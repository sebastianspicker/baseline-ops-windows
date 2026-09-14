use super::*;

pub(super) struct CountingVerifier(pub(super) AtomicUsize);
impl SignatureVerifier for CountingVerifier {
    fn verify(&self, executable: &Path, expected_subject: &str) -> Result<(), PackageError> {
        assert!(executable.is_file());
        assert_eq!(expected_subject, "CN=BaselineOps Test");
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
pub(super) struct DetachedFixtureVerifier {
    pub(super) calls: AtomicUsize,
    pub(super) subject: &'static str,
}
impl DetachedSignatureVerifier for DetachedFixtureVerifier {
    fn verify(&self, signed: &[u8], signature: &[u8], subject: &str) -> Result<(), PackageError> {
        if subject != self.subject
            || signature != b"fixture detached signature"
            || !signed.starts_with(b"{\"schema_version\"")
        {
            return Err(PackageError::Signature(
                "fixture rejected detached signature bytes or signer".into(),
            ));
        }
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
pub(super) struct RejectingDetachedVerifier(pub(super) AtomicUsize);
impl DetachedSignatureVerifier for RejectingDetachedVerifier {
    fn verify(&self, _: &[u8], _: &[u8], _: &str) -> Result<(), PackageError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(PackageError::Signature(
            "fixture rejected detached signature".into(),
        ))
    }
}

type FixturePayload = (&'static str, &'static [u8]);

const FIXTURE_PAYLOADS: [FixturePayload; 4] = [
    ("bin/baselineops.exe", b"cli"),
    ("bin/baselineops-gui.exe", b"gui"),
    ("bin/baselineops-worker.exe", b"worker"),
    ("schemas/profile-v3.schema.json", b"{}"),
];

pub(super) fn write_fixture_package(
    tamper: bool,
    include_signature: bool,
    signer: &str,
    signature: &[u8],
) -> tempfile::NamedTempFile {
    let manifest = fixture_manifest(tamper, signer);
    let output = tempfile::NamedTempFile::new().expect("package");
    let mut zip = zip::ZipWriter::new(output.reopen().expect("package writer"));
    write_payloads(&mut zip);
    write_manifest(&mut zip, &manifest, include_signature, signature);
    zip.finish().expect("finish ZIP");
    output
}

fn fixture_manifest(tamper: bool, signer: &str) -> PackageManifestV1 {
    let mut files = FIXTURE_PAYLOADS
        .iter()
        .map(|(path, bytes)| ManifestFile {
            path: (*path).into(),
            size_bytes: u64::try_from(bytes.len()).expect("fixture size"),
            sha256: Sha256Digest::of_bytes(bytes),
        })
        .collect::<Vec<_>>();
    if tamper {
        files[0].sha256 = Sha256Digest::of_bytes(b"different");
    }
    PackageManifestV1 {
        schema_version: "1.0".into(),
        product: "BaselineOps for Windows".into(),
        package_version: "3.0.0-alpha.1".into(),
        target: "x86_64-pc-windows-msvc".into(),
        signer_subject: signer.into(),
        files,
    }
}

fn write_payloads(zip: &mut zip::ZipWriter<std::fs::File>) {
    for (path, bytes) in FIXTURE_PAYLOADS {
        zip.start_file(path, zip::write::SimpleFileOptions::default())
            .expect("payload member");
        zip.write_all(bytes).expect("payload bytes");
    }
}

fn write_manifest(
    zip: &mut zip::ZipWriter<std::fs::File>,
    manifest: &PackageManifestV1,
    include_signature: bool,
    signature: &[u8],
) {
    zip.start_file(MANIFEST_PATH, zip::write::SimpleFileOptions::default())
        .expect("manifest member");
    zip.write_all(&serde_json::to_vec(&manifest).expect("manifest JSON"))
        .expect("manifest bytes");
    if include_signature {
        zip.start_file(
            MANIFEST_SIGNATURE_PATH,
            zip::write::SimpleFileOptions::default(),
        )
        .expect("signature member");
        zip.write_all(signature).expect("signature bytes");
    }
}
