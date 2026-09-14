use crate::PlatformError;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(windows)]
mod detached;
#[cfg(windows)]
mod windows;

/// Expected SHA-256 digest for immutable input bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileDigest([u8; 32]);

impl FileDigest {
    /// Parse a 64-character hexadecimal SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not exactly 32 hexadecimal bytes.
    pub fn from_hex(value: &str) -> Result<Self, PlatformError> {
        let bytes = hex::decode(value)
            .map_err(|error| PlatformError::TrustFailure(format!("invalid SHA-256: {error}")))?;
        let value: [u8; 32] = bytes.try_into().map_err(|_| {
            PlatformError::TrustFailure("SHA-256 must contain exactly 32 bytes".into())
        })?;
        Ok(Self(value))
    }

    /// Return lowercase hexadecimal text.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// SHA-256 pin for the canonical DER `SubjectPublicKeyInfo` of a release signer.
///
/// This deliberately accepts only lowercase hexadecimal input so release identity
/// configuration is byte-exact and has a single canonical textual form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerSpkiSha256([u8; 32]);

impl SignerSpkiSha256 {
    /// Parse exactly 64 lowercase hexadecimal characters.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not the canonical lowercase encoding
    /// of a 32-byte SHA-256 digest.
    pub fn from_hex(value: &str) -> Result<Self, PlatformError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PlatformError::TrustFailure(
                "signer SPKI SHA-256 must be 64 lowercase hexadecimal characters".into(),
            ));
        }
        let bytes = hex::decode(value).map_err(|error| {
            PlatformError::TrustFailure(format!("invalid signer SPKI SHA-256: {error}"))
        })?;
        let value: [u8; 32] = bytes.try_into().map_err(|_| {
            PlatformError::TrustFailure("signer SPKI SHA-256 must contain exactly 32 bytes".into())
        })?;
        Ok(Self(value))
    }

    /// Return lowercase hexadecimal text.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    #[cfg(any(windows, test))]
    pub(crate) fn matches_digest(&self, candidate: &[u8; 32]) -> bool {
        let mut difference = 0_u8;
        for (left, right) in self.0.iter().zip(candidate) {
            difference |= left ^ right;
        }
        difference == 0
    }
}

/// Trust requirements independently enforced by the elevated worker.
#[derive(Clone, Debug)]
pub struct InstallationTrustPolicy {
    /// Protected installation root containing the worker and product files.
    pub root: PathBuf,
    /// Canonical X.500 subject of the required Authenticode signer.
    pub publisher_subject: String,
    /// SHA-256 pin for the signer's canonical DER `SubjectPublicKeyInfo`.
    pub publisher_spki_sha256: SignerSpkiSha256,
    /// Whether every non-volume-root ancestor must reject untrusted replacement rights.
    pub validate_ancestors: bool,
}

/// Proof that the current worker executable passed protected-install checks.
///
/// The fields are private so callers cannot manufacture execution authority.
pub struct TrustedInstallation {
    executable: PathBuf,
    root: PathBuf,
    #[cfg(windows)]
    _retained_paths: windows::VerifiedInstallPaths,
}

impl std::fmt::Debug for TrustedInstallation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustedInstallation")
            .field("executable", &self.executable)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl TrustedInstallation {
    /// Verified worker executable path.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Verified protected installation root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Hash a regular file and compare it in constant work with the expected digest.
///
/// # Errors
///
/// Returns an error when the target is not a readable regular file or its digest
/// does not match.
pub fn verify_file_digest(
    path: impl AsRef<Path>,
    expected: &FileDigest,
) -> Result<(), PlatformError> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(PlatformError::TrustFailure(
            "digest target is not a regular file".into(),
        ));
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let actual = hash.finalize();
    if !digest_matches(actual.as_slice(), &expected.0) {
        return Err(PlatformError::TrustFailure(
            "file SHA-256 does not match the trusted manifest".into(),
        ));
    }
    Ok(())
}

fn digest_matches(actual: &[u8], expected: &[u8; 32]) -> bool {
    actual
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

/// Verify an executable's Authenticode chain and exact canonical X.500 subject.
///
/// Windows performs a no-UI full-chain revocation check. Other platforms do not
/// emulate Authenticode and return [`PlatformError::UnsupportedPlatform`].
///
/// # Errors
///
/// Returns an error when the subject is malformed, the path is not a regular
/// non-reparse file, or Windows cannot validate its signature and signer.
pub fn verify_authenticode_subject(
    executable: impl AsRef<Path>,
    expected_subject: &str,
) -> Result<(), PlatformError> {
    validate_subject(expected_subject)?;
    #[cfg(windows)]
    {
        windows::verify_authenticode_subject(executable.as_ref(), expected_subject)
    }
    #[cfg(not(windows))]
    {
        let _ = executable;
        Err(PlatformError::UnsupportedPlatform)
    }
}

/// Verify an executable's Authenticode chain and full external signer identity.
///
/// Production callers must use this function rather than the subject-only
/// compatibility verifier.
///
/// # Errors
///
/// Returns an error when the executable signature, canonical subject, or
/// canonical DER `SubjectPublicKeyInfo` pin cannot be verified.
pub fn verify_authenticode(
    executable: impl AsRef<Path>,
    expected_subject: &str,
    expected_spki_sha256: &SignerSpkiSha256,
) -> Result<(), PlatformError> {
    validate_subject(expected_subject)?;
    #[cfg(windows)]
    {
        windows::verify_authenticode(executable.as_ref(), expected_subject, expected_spki_sha256)
    }
    #[cfg(not(windows))]
    {
        let _ = (executable, expected_spki_sha256);
        Err(PlatformError::UnsupportedPlatform)
    }
}

/// Verify a detached PKCS#7 signature over exact manifest bytes and its signer.
///
/// Windows validates the detached signature, code-signing EKU, current-time
/// certificate chain, cached offline revocation state, and Authenticode chain
/// policy. This intentionally does not apply timestamp-based post-expiry
/// lifetime validation. Other platforms fail closed.
///
/// # Errors
///
/// Returns an error when the signature does not cover the supplied bytes or
/// the signer cannot satisfy the exact external trust policy.
pub fn verify_detached_manifest_signature(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    expected_subject: &str,
) -> Result<(), PlatformError> {
    prepare_detached_verification(manifest_bytes, signature_bytes, expected_subject)?;
    #[cfg(windows)]
    {
        detached::verify_subject(manifest_bytes, signature_bytes, expected_subject)
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

/// Verify a detached PKCS#7 manifest signature against a full external signer identity.
///
/// Production package verification must use this function rather than the
/// subject-only compatibility verifier.
///
/// # Errors
///
/// Returns an error when the detached signature, canonical subject, or
/// canonical DER `SubjectPublicKeyInfo` pin cannot be verified.
pub fn verify_detached_manifest(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    expected_subject: &str,
    expected_spki_sha256: &SignerSpkiSha256,
) -> Result<(), PlatformError> {
    prepare_detached_verification(manifest_bytes, signature_bytes, expected_subject)?;
    #[cfg(windows)]
    {
        detached::verify(
            manifest_bytes,
            signature_bytes,
            expected_subject,
            expected_spki_sha256,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = expected_spki_sha256;
        Err(PlatformError::UnsupportedPlatform)
    }
}

/// Validate containment, Authenticode, ownership, and ACL controls for an install.
///
/// Windows uses opened handles throughout the check and returns the final handle
/// path. Unsupported hosts fail closed.
///
/// # Errors
///
/// Returns an error when any path, handle identity, signer, owner, DACL, or
/// ancestor replacement-right check cannot be proved.
pub fn verify_protected_install(
    policy: &InstallationTrustPolicy,
    executable: impl AsRef<Path>,
) -> Result<TrustedInstallation, PlatformError> {
    validate_subject(&policy.publisher_subject)?;
    #[cfg(windows)]
    {
        let verified = windows::verify_protected_install(policy, executable.as_ref())?;
        let executable = verified.executable().to_path_buf();
        let root = verified.root().to_path_buf();
        Ok(TrustedInstallation {
            executable,
            root,
            _retained_paths: verified,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = executable;
        Err(PlatformError::UnsupportedPlatform)
    }
}

pub(crate) fn verify_windows_system_executable(path: &Path) -> Result<PathBuf, PlatformError> {
    #[cfg(windows)]
    {
        windows::verify_windows_system_executable(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(PlatformError::UnsupportedPlatform)
    }
}

pub(crate) fn resolve_regular_executable(path: &Path) -> Result<PathBuf, PlatformError> {
    #[cfg(windows)]
    {
        windows::resolve_regular_executable(path)
    }
    #[cfg(not(windows))]
    {
        let canonical = std::fs::canonicalize(path)?;
        if !canonical.is_file() {
            return Err(PlatformError::TrustFailure(
                "native executable is not a regular file".into(),
            ));
        }
        Ok(canonical)
    }
}

#[cfg(windows)]
pub(crate) use windows::{ProtectedRunDirectory, ProtectedRunLease};

#[cfg(windows)]
pub(crate) use windows::read_protected_run_artifacts;

#[cfg(windows)]
pub(crate) fn create_protected_run_directory(
    run_id: baselineops_domain::RunId,
) -> Result<ProtectedRunDirectory, PlatformError> {
    windows::create_protected_run_directory(run_id)
}

pub(crate) fn windows_system32_file(file_name: &str) -> Result<PathBuf, PlatformError> {
    if !is_simple_executable_name(file_name) {
        return Err(PlatformError::ProcessRejected(
            "System32 executable name is not a simple .exe file name".into(),
        ));
    }
    #[cfg(windows)]
    {
        Ok(windows::system32_directory()?.join(file_name))
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

fn is_simple_executable_name(file_name: &str) -> bool {
    !file_name.is_empty()
        && file_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        && file_name
            .get(file_name.len().saturating_sub(4)..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".exe"))
}

fn validate_subject(subject: &str) -> Result<(), PlatformError> {
    if subject.trim().is_empty() || subject.contains('\0') {
        return Err(PlatformError::TrustFailure(
            "a non-empty canonical X.500 signer subject is required".into(),
        ));
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn is_forbidden_protected_path_namespace(path: &Path) -> bool {
    let value = path.as_os_str().to_string_lossy();
    let bytes = value.as_bytes();
    if value.starts_with("//") {
        return true;
    }
    if !value.starts_with("\\\\") {
        return false;
    }
    // GetFinalPathNameByHandleW returns local drive paths as `\\?\C:\...`.
    // Accept only that extended local form; UNC, device, volume-GUID, and
    // GLOBALROOT namespaces remain outside protected-install policy.
    !(bytes.len() >= 7
        && bytes[..4] == *b"\\\\?\\"
        && bytes[4].is_ascii_alphabetic()
        && bytes[5] == b':'
        && matches!(bytes[6], b'\\' | b'/'))
}

#[cfg(any(windows, test))]
fn protected_descendant_directories(root: &Path, executable: &Path) -> Option<Vec<PathBuf>> {
    let relative_parent = executable.strip_prefix(root).ok()?.parent()?;
    let mut current = root.to_path_buf();
    let mut directories = Vec::new();
    for component in relative_parent.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return None;
        }
        current.push(component.as_os_str());
        directories.push(current.clone());
    }
    Some(directories)
}

fn prepare_detached_verification(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    expected_subject: &str,
) -> Result<(), PlatformError> {
    validate_subject(expected_subject)?;
    if manifest_bytes.is_empty() || signature_bytes.is_empty() {
        return Err(PlatformError::TrustFailure(
            "detached manifest bytes and signature must be non-empty".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_round_trip_is_stable() {
        let digest = FileDigest::from_hex(&"ab".repeat(32)).expect("digest");
        assert_eq!(digest.to_hex(), "ab".repeat(32));
    }

    #[test]
    fn malformed_digest_fails_closed() {
        assert!(FileDigest::from_hex("f00d").is_err());
        assert!(FileDigest::from_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn signer_pin_requires_canonical_lowercase_hex() {
        let pin = SignerSpkiSha256::from_hex(&"ab".repeat(32)).expect("pin");
        assert_eq!(pin.to_hex(), "ab".repeat(32));
        assert!(SignerSpkiSha256::from_hex(&"AB".repeat(32)).is_err());
        assert!(SignerSpkiSha256::from_hex("f00d").is_err());
    }

    #[test]
    fn signer_pin_comparison_rejects_mismatch() {
        let pin = SignerSpkiSha256::from_hex(&"00".repeat(32)).expect("pin");
        assert!(pin.matches_digest(&[0; 32]));
        assert!(!pin.matches_digest(&[1; 32]));
    }

    #[test]
    fn protected_path_namespace_accepts_final_local_drive_paths_only() {
        assert!(!is_forbidden_protected_path_namespace(Path::new(
            r"\\?\C:\Program Files\BaselineOps"
        )));
        assert!(is_forbidden_protected_path_namespace(Path::new(
            r"\\?\UNC\server\share\BaselineOps"
        )));
        assert!(is_forbidden_protected_path_namespace(Path::new(
            r"\\.\GLOBALROOT\Device\HarddiskVolumeShadowCopy1"
        )));
        assert!(is_forbidden_protected_path_namespace(Path::new(
            r"\\server\share\BaselineOps"
        )));
    }

    #[test]
    fn protected_directory_walk_includes_executable_parent() {
        let root = Path::new("/protected/BaselineOps");
        assert_eq!(
            protected_descendant_directories(root, &root.join("bin/worker.exe")),
            Some(vec![root.join("bin")])
        );
        assert_eq!(
            protected_descendant_directories(root, &root.join("worker.exe")),
            Some(Vec::new())
        );
    }

    #[test]
    fn protected_directory_walk_includes_every_nested_acl_candidate() {
        let root = Path::new("/protected/BaselineOps");
        assert_eq!(
            protected_descendant_directories(root, &root.join("bin/writable/worker.exe")),
            Some(vec![root.join("bin"), root.join("bin/writable")])
        );
        assert_eq!(
            protected_descendant_directories(root, Path::new("/elsewhere/worker.exe")),
            None
        );
    }

    #[test]
    fn mismatched_digest_fails_closed() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("binary.exe");
        std::fs::write(&path, b"bytes").expect("write");
        let digest = FileDigest::from_hex(&"00".repeat(32)).expect("digest");
        assert!(matches!(
            verify_file_digest(path, &digest),
            Err(PlatformError::TrustFailure(_))
        ));
    }

    #[test]
    fn blank_or_nul_subject_is_rejected_before_platform_dispatch() {
        assert!(validate_subject(" \t").is_err());
        assert!(validate_subject("CN=Vendor\0,O=Example").is_err());
    }

    #[test]
    fn system32_tool_names_are_single_executable_components() {
        for value in ["", "tool", r"..\tool.exe", "tool.exe/other", "tool.exe\0"] {
            assert!(windows_system32_file(value).is_err());
        }
        #[cfg(not(windows))]
        assert!(matches!(
            windows_system32_file("w32tm.exe"),
            Err(PlatformError::UnsupportedPlatform)
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_authenticode_fails_closed() {
        assert!(matches!(
            verify_authenticode_subject("missing.exe", "CN=Vendor"),
            Err(PlatformError::UnsupportedPlatform)
        ));
    }
}
