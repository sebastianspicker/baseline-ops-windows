//! Protected-install and authenticated client trust checks for the worker.

use anyhow::{Context, Result, anyhow};
#[cfg(windows)]
use baselineops_engine::{
    DetachedSignatureVerifier, InstalledPackageExpectation, PackageError, SignatureVerifier,
    verify_installed_package,
};
use baselineops_windows::{InstallationTrustPolicy, verify_protected_install};
use std::path::Path;

#[derive(Clone)]
pub(crate) struct ReleaseSignerIdentity {
    pub(crate) subject: String,
    pub(crate) spki_sha256: baselineops_windows::SignerSpkiSha256,
}

pub(crate) fn release_signer_identity() -> Result<ReleaseSignerIdentity> {
    let subject = option_env!("BASELINEOPS_EXPECTED_SIGNER_SUBJECT")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("worker build does not embed the release signer subject"))?;
    let spki_sha256 = option_env!("BASELINEOPS_EXPECTED_SIGNER_SPKI_SHA256")
        .ok_or_else(|| anyhow!("worker build does not embed the release signer SPKI pin"))
        .and_then(|value| {
            baselineops_windows::SignerSpkiSha256::from_hex(value).map_err(|error| anyhow!(error))
        })?;
    Ok(ReleaseSignerIdentity {
        subject: subject.into(),
        spki_sha256,
    })
}

pub(crate) fn verify_current_worker(
    signer: &ReleaseSignerIdentity,
) -> Result<baselineops_windows::TrustedInstallation> {
    let executable = std::env::current_exe().context("resolve worker executable")?;
    let bin = executable
        .parent()
        .context("worker executable has no package bin directory")?;
    let root = bin
        .parent()
        .context("worker package has no protected root")?;
    verify_protected_install(&installation_policy(root, signer), &executable).map_err(Into::into)
}

#[cfg(windows)]
pub(crate) fn verify_current_installed_package(
    trust: &baselineops_windows::TrustedInstallation,
    signer: &ReleaseSignerIdentity,
) -> Result<baselineops_engine::InstalledPackageIdentity> {
    Ok(verify_installed_package(
        trust.root(),
        InstalledPackageExpectation {
            product: "BaselineOps for Windows",
            package_version: env!("CARGO_PKG_VERSION"),
            target: "x86_64-pc-windows-msvc",
            signer_subject: &signer.subject,
        },
        &PlatformDetachedSignatureVerifier::new(signer),
        &PlatformSignatureVerifier::new(signer),
    )?)
}

fn installation_policy(root: &Path, signer: &ReleaseSignerIdentity) -> InstallationTrustPolicy {
    InstallationTrustPolicy {
        root: root.to_path_buf(),
        publisher_subject: signer.subject.clone(),
        publisher_spki_sha256: signer.spki_sha256.clone(),
        validate_ancestors: true,
    }
}

#[cfg(windows)]
struct PlatformDetachedSignatureVerifier {
    signer: ReleaseSignerIdentity,
}

#[cfg(windows)]
impl PlatformDetachedSignatureVerifier {
    fn new(signer: &ReleaseSignerIdentity) -> Self {
        Self {
            signer: signer.clone(),
        }
    }
}

#[cfg(windows)]
impl DetachedSignatureVerifier for PlatformDetachedSignatureVerifier {
    fn verify(&self, signed: &[u8], signature: &[u8], subject: &str) -> Result<(), PackageError> {
        if subject != self.signer.subject {
            return Err(PackageError::Signature(
                "package verifier received an untrusted signer subject".into(),
            ));
        }
        baselineops_windows::verify_detached_manifest(
            signed,
            signature,
            &self.signer.subject,
            &self.signer.spki_sha256,
        )
        .map_err(|error| PackageError::Signature(error.to_string()))
    }
}

#[cfg(windows)]
struct PlatformSignatureVerifier {
    signer: ReleaseSignerIdentity,
}

#[cfg(windows)]
impl PlatformSignatureVerifier {
    fn new(signer: &ReleaseSignerIdentity) -> Self {
        Self {
            signer: signer.clone(),
        }
    }
}

#[cfg(windows)]
impl SignatureVerifier for PlatformSignatureVerifier {
    fn verify(&self, executable: &Path, subject: &str) -> Result<(), PackageError> {
        if subject != self.signer.subject {
            return Err(PackageError::Signature(
                "package verifier received an untrusted signer subject".into(),
            ));
        }
        baselineops_windows::verify_authenticode(
            executable,
            &self.signer.subject,
            &self.signer.spki_sha256,
        )
        .map_err(|error| PackageError::Signature(error.to_string()))
    }
}

#[cfg(windows)]
pub(crate) struct StrictClientVerifier {
    expected_pid: u32,
    expected_session: u32,
    expected_image: std::path::PathBuf,
    expected_user_sid: String,
    expected_logon_sid: String,
    installation_root: std::path::PathBuf,
    publisher_subject: String,
    publisher_spki_sha256: baselineops_windows::SignerSpkiSha256,
}

#[cfg(windows)]
impl StrictClientVerifier {
    pub(crate) fn new(
        client_pid: u32,
        trust: &baselineops_windows::TrustedInstallation,
        signer: &ReleaseSignerIdentity,
    ) -> Result<Self> {
        let identity = baselineops_windows::ipc::inspect_process(client_pid)?;
        let bin = trust
            .executable()
            .parent()
            .context("trusted worker lacks bin directory")?;
        let expected_image = verify_protected_install(
            &installation_policy(trust.root(), signer),
            bin.join("baselineops.exe"),
        )?
        .executable()
        .to_path_buf();
        Ok(Self {
            expected_pid: client_pid,
            expected_session: identity.session_id,
            expected_image,
            expected_user_sid: identity.user_sid,
            expected_logon_sid: identity.logon_sid,
            installation_root: trust.root().to_path_buf(),
            publisher_subject: signer.subject.clone(),
            publisher_spki_sha256: signer.spki_sha256.clone(),
        })
    }

    pub(crate) fn expected_logon_sid(&self) -> &str {
        &self.expected_logon_sid
    }
}

#[cfg(windows)]
impl baselineops_windows::ipc::PipePeerVerifier for StrictClientVerifier {
    fn verify(
        &self,
        peer: &baselineops_windows::PeerIdentity,
    ) -> Result<(), baselineops_windows::PlatformError> {
        verify_peer_binding(self, peer)?;
        let identity = baselineops_windows::ipc::inspect_process(peer.process_id)?;
        verify_client_identity(self, &identity)?;
        let verified = verify_protected_install(
            &InstallationTrustPolicy {
                root: self.installation_root.clone(),
                publisher_subject: self.publisher_subject.clone(),
                publisher_spki_sha256: self.publisher_spki_sha256.clone(),
                validate_ancestors: true,
            },
            &identity.image_path,
        )?;
        if !same_windows_path(verified.executable(), &self.expected_image) {
            return Err(protocol(
                "pipe client final image does not match protected CLI",
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
fn verify_peer_binding(
    verifier: &StrictClientVerifier,
    peer: &baselineops_windows::PeerIdentity,
) -> Result<(), baselineops_windows::PlatformError> {
    if peer.process_id != verifier.expected_pid || peer.session_id != verifier.expected_session {
        return Err(protocol(
            "pipe PID or session does not match the UAC launch binding",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn verify_client_identity(
    verifier: &StrictClientVerifier,
    identity: &baselineops_windows::ipc::ProcessTokenIdentity,
) -> Result<(), baselineops_windows::PlatformError> {
    if identity.user_sid != verifier.expected_user_sid
        || identity.logon_sid != verifier.expected_logon_sid
        || identity.integrity_rid < 0x2000
    {
        return Err(protocol(
            "pipe client token does not match the launched standard-user logon identity",
        ));
    }
    if !same_windows_path(&identity.image_path, &verifier.expected_image) {
        return Err(protocol(
            "pipe client image is not the protected BaselineOps CLI",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn protocol(message: &str) -> baselineops_windows::PlatformError {
    baselineops_windows::PlatformError::ProtocolRejected(message.into())
}

#[cfg(windows)]
fn same_windows_path(actual: &Path, expected: &Path) -> bool {
    actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
}
