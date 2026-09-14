use super::WorkerExchange;
use anyhow::{Context, Result, bail};
use baselineops_domain::PlanV3;
use baselineops_engine::{InstalledPackageExpectation, PackageError, verify_installed_package};
use baselineops_windows::ipc::{ProcessTokenIdentity, inspect_process};
use baselineops_windows::{
    ElevatedLaunchPolicy, ElevatedLaunchResult, InstallationTrustPolicy, PeerIdentity,
    ReplayNonceCache, TrustedInstallation, launch_elevated, verify_protected_install,
};
use std::{path::Path, sync::Arc, thread, time::Duration};

pub(super) fn start_worker(plan: &PlanV3) -> Result<WorkerExchange> {
    let (signer, installation) = authenticated_installation(plan)?;
    let cli_identity = inspect_process(std::process::id())?;
    let session = uuid::Uuid::new_v4();
    let pipe_name = session.as_simple().to_string();
    let launch = launch_worker(Arc::clone(&installation), session);
    let (client, launch) = super::connect(&pipe_name, launch)?;
    authenticate_worker_server(
        &client.server_peer_identity()?,
        &cli_identity,
        &installation,
        &signer,
    )?;
    Ok(WorkerExchange {
        client,
        replays: ReplayNonceCache::new(Duration::from_mins(2), 4)?,
        pipe_name,
        launch,
    })
}

fn authenticated_installation(
    plan: &PlanV3,
) -> Result<(crate::ReleaseSignerIdentity, Arc<TrustedInstallation>)> {
    let signer = crate::release_signer_identity()?;
    let installation = verified_installation(plan, &signer)?;
    Ok((signer, installation))
}

fn launch_worker(
    installation: Arc<TrustedInstallation>,
    session: uuid::Uuid,
) -> thread::JoinHandle<Result<ElevatedLaunchResult, baselineops_windows::PlatformError>> {
    let arguments = worker_arguments(session);
    thread::spawn(move || {
        launch_elevated(
            installation.as_ref(),
            &ElevatedLaunchPolicy {
                arguments,
                timeout: Duration::from_mins(2),
            },
        )
    })
}

fn worker_arguments(session: uuid::Uuid) -> Vec<String> {
    vec![
        "--session".into(),
        session.to_string(),
        "--client-pid".into(),
        std::process::id().to_string(),
    ]
}

fn verified_installation(
    plan: &PlanV3,
    signer: &crate::ReleaseSignerIdentity,
) -> Result<Arc<TrustedInstallation>> {
    let installation = Arc::new(verify_worker_install(signer)?);
    let installed_package = verify_installed_package(
        installation.root(),
        installed_expectation(signer),
        &crate::PlatformDetachedSignatureVerifier::new(signer),
        &crate::PlatformSignatureVerifier::new(signer),
    )?;
    verify_package_digest(plan, installed_package.binding_digest())?;
    Ok(installation)
}

fn verify_package_digest(
    plan: &PlanV3,
    installed_digest: baselineops_domain::Sha256Digest,
) -> Result<()> {
    if plan.package_digest != installed_digest {
        return Err(PackageError::Signature(
            "plan package digest does not match the authenticated installed manifest".into(),
        )
        .into());
    }
    Ok(())
}

fn verify_worker_install(signer: &crate::ReleaseSignerIdentity) -> Result<TrustedInstallation> {
    let executable = std::env::current_exe()?;
    let bin = executable
        .parent()
        .context("CLI executable has no bin directory")?;
    let root = bin
        .parent()
        .context("CLI executable has no installation root")?;
    verify_protected_install(
        &installation_policy(root, signer),
        bin.join("baselineops-worker.exe"),
    )
    .map_err(Into::into)
}

fn authenticate_worker_server(
    peer: &PeerIdentity,
    cli: &ProcessTokenIdentity,
    expected: &TrustedInstallation,
    signer: &crate::ReleaseSignerIdentity,
) -> Result<()> {
    let server = inspect_process(peer.process_id)?;
    verify_server_identity(peer, cli, &server, expected)?;
    let verified = verify_protected_install(
        &installation_policy(expected.root(), signer),
        &server.image_path,
    )?;
    if !same_windows_path(verified.executable(), expected.executable()) {
        bail!("named-pipe server final handle identity differs from trusted worker");
    }
    Ok(())
}

fn verify_server_identity(
    peer: &PeerIdentity,
    cli: &ProcessTokenIdentity,
    server: &ProcessTokenIdentity,
    expected: &TrustedInstallation,
) -> Result<()> {
    if server.session_id != cli.session_id
        || peer.session_id != cli.session_id
        || server.user_sid != cli.user_sid
        || server.logon_sid != cli.logon_sid
        || server.integrity_rid < 0x3000
    {
        bail!("named-pipe server token is not the expected elevated logon identity");
    }
    if !same_windows_path(&server.image_path, expected.executable()) {
        bail!("named-pipe server image is not the expected protected worker");
    }
    Ok(())
}

fn installation_policy(
    root: &Path,
    signer: &crate::ReleaseSignerIdentity,
) -> InstallationTrustPolicy {
    InstallationTrustPolicy {
        root: root.to_path_buf(),
        publisher_subject: signer.subject.clone(),
        publisher_spki_sha256: signer.spki_sha256.clone(),
        validate_ancestors: true,
    }
}

fn installed_expectation(signer: &crate::ReleaseSignerIdentity) -> InstalledPackageExpectation<'_> {
    InstalledPackageExpectation {
        product: "BaselineOps for Windows",
        package_version: env!("CARGO_PKG_VERSION"),
        target: "x86_64-pc-windows-msvc",
        signer_subject: &signer.subject,
    }
}

fn same_windows_path(actual: &Path, expected: &Path) -> bool {
    actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
}
