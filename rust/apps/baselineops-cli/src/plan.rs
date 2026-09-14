//! Worker-plan-only proposal composition. Current registry entries reject mutations.

use crate::{Selection, resolve_selection, unsupported_response};
use anyhow::{Context, Result, anyhow, bail};
use baselineops_domain::{
    ExecutionIntent, ExitCode, InputIdentityV3, JsonLoadLimits, ObservedStateV3, ProfileV3,
    SourceIdentityV3, SourceKind, ToolIdentityV3,
};
use baselineops_engine::{InstalledPackageExpectation, verify_installed_package};
use baselineops_engine::{PlanBuildContext, RegistryActionDeriver, build_plan};
use chrono::{Duration, Utc};
use std::path::Path;

pub(crate) fn run(selection: &Selection, output: &Path) -> Result<ExitCode> {
    require_output(output)?;
    if !cfg!(windows) {
        return unsupported_response("plan", &["Windows protected worker"]);
    }
    let (profile_path, bytes, profile) = load_profile(selection)?;
    let (descriptors, _) = resolve_selection(selection)?;
    let context = build_context(selection, &profile_path, &bytes, &profile, &descriptors)?;
    persist_or_report(
        build_plan(&profile, context, &RegistryActionDeriver, Utc::now()),
        output,
        &descriptors,
    )
}

fn require_output(output: &Path) -> Result<()> {
    if output.as_os_str().is_empty() {
        bail!("plan output path is empty");
    }
    Ok(())
}

fn load_profile(selection: &Selection) -> Result<(std::path::PathBuf, Vec<u8>, ProfileV3)> {
    let path = selection.profile.as_ref().ok_or_else(|| {
        anyhow!("plan requires a profile so source and input bindings can be retained")
    })?;
    let path = crate::resources::resolve_input_file(path)?;
    let bytes = baselineops_windows::read_bounded_utf8_no_follow(
        &path,
        baselineops_windows::MAX_INPUT_BYTES,
    )?
    .into_bytes();
    let profile: ProfileV3 = baselineops_domain::load_json(&bytes, JsonLoadLimits::default())?;
    profile.validate()?;
    Ok((path, bytes, profile))
}

fn build_context(
    selection: &Selection,
    path: &Path,
    bytes: &[u8],
    profile: &ProfileV3,
    descriptors: &[&'static baselineops_capabilities::CapabilityDescriptor],
) -> Result<PlanBuildContext> {
    let digest = baselineops_domain::Sha256Digest::of_bytes(bytes);
    let resources = crate::resources::bind_selection(selection)?;
    let observed_state = observe(profile, descriptors)?;
    let package_digest = current_package_digest()?;
    Ok(PlanBuildContext {
        intent: ExecutionIntent::Apply,
        host: baselineops_windows::collect_host_identity()?,
        tool: ToolIdentityV3 {
            name: "baselineops".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            build_digest: Some(package_digest),
        },
        package_digest,
        source: SourceIdentityV3 {
            kind: SourceKind::LocalFile,
            locator: path.display().to_string(),
            digest,
        },
        input: InputIdentityV3::from_resources(digest, u64::try_from(bytes.len())?, &resources)?,
        resources,
        observed_state,
        lifetime: Duration::minutes(5),
    })
}

fn current_package_digest() -> Result<baselineops_domain::Sha256Digest> {
    installed_package_digest(&std::env::current_exe()?)
}

fn persist_or_report(
    plan: Result<baselineops_engine::WorkerPlan, baselineops_engine::PlanningError>,
    output: &Path,
    descriptors: &[&'static baselineops_capabilities::CapabilityDescriptor],
) -> Result<ExitCode> {
    match plan {
        Ok(worker_plan) => {
            let body = serde_json::to_vec_pretty(worker_plan.proposal())?;
            baselineops_windows::atomic_write(output, &body)?;
            crate::print_json(
                &serde_json::json!({"status":"proposed","digest":worker_plan.digest().to_hex(),"plan":worker_plan.proposal()}),
            )?;
            Ok(ExitCode::Completed)
        }
        Err(baselineops_engine::PlanningError::Derivation(_)) => unsupported_response(
            "plan",
            &descriptors
                .iter()
                .map(|descriptor| descriptor.id)
                .collect::<Vec<_>>(),
        ),
        Err(error) => Err(error.into()),
    }
}

fn installed_package_digest(executable: &Path) -> Result<baselineops_domain::Sha256Digest> {
    let bin = executable
        .parent()
        .context("CLI executable has no package bin directory")?;
    let root = bin
        .parent()
        .context("CLI executable has no installation root")?;
    let signer = crate::release_signer_identity()?;
    let installation = baselineops_windows::verify_protected_install(
        &baselineops_windows::InstallationTrustPolicy {
            root: root.to_path_buf(),
            publisher_subject: signer.subject.clone(),
            publisher_spki_sha256: signer.spki_sha256.clone(),
            validate_ancestors: true,
        },
        executable,
    )?;
    Ok(verify_installed_package(
        installation.root(),
        InstalledPackageExpectation {
            product: "BaselineOps for Windows",
            package_version: env!("CARGO_PKG_VERSION"),
            target: "x86_64-pc-windows-msvc",
            signer_subject: &signer.subject,
        },
        &crate::PlatformDetachedSignatureVerifier::new(&signer),
        &crate::PlatformSignatureVerifier::new(&signer),
    )?
    .binding_digest())
}

fn observe(
    profile: &ProfileV3,
    _descriptors: &[&'static baselineops_capabilities::CapabilityDescriptor],
) -> Result<ObservedStateV3> {
    baselineops_engine::reobserve_profile(
        profile,
        &baselineops_engine::NativeObservationSource,
        Utc::now(),
    )
    .map_err(|error| anyhow!(error))
}
