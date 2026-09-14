//! Opt-in portable I/O costs. Fixture trust ports do not measure Windows security APIs.

use crate::*;
use baselineops_domain::{ActionStatus, ArtifactKind, JsonMap, PlanId, ResultId, Sha256Digest};
use chrono::Utc;
use std::{fs::File, io::Write, path::Path, sync::Arc, time::Instant};

const SAMPLES: usize = 25;

struct FixtureTrust;

impl EvidenceProtection for FixtureTrust {
    fn protect(&self, _: &Path) -> Result<(), EvidenceError> {
        Ok(())
    }
    fn verify(&self, _: &Path) -> Result<(), EvidenceError> {
        Ok(())
    }
}

impl SignatureVerifier for FixtureTrust {
    fn verify(&self, _: &Path, subject: &str) -> Result<(), PackageError> {
        assert_eq!(subject, "portable fixture");
        Ok(())
    }
}

impl DetachedSignatureVerifier for FixtureTrust {
    fn verify(&self, bytes: &[u8], signature: &[u8], subject: &str) -> Result<(), PackageError> {
        assert_eq!(subject, "portable fixture");
        assert_eq!(Sha256Digest::of_bytes(bytes).to_hex().as_bytes(), signature);
        Ok(())
    }
}

fn measure(name: &str, size: usize, mut workload: impl FnMut()) {
    for _ in 0..3 {
        workload();
    }
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        workload();
        samples.push(start.elapsed().as_nanos());
    }
    samples.sort_unstable();
    println!(
        "boundary_io,{name},{size},samples={SAMPLES},p50_ns={},p95_ns={},p99_ns={}",
        samples[12], samples[23], samples[24]
    );
}

#[test]
#[ignore = "portable cost harness; run --release --ignored --nocapture"]
fn journal_io_distribution() {
    measure("journal_32_actions", 66, || {
        let root = tempfile::tempdir().unwrap();
        let mut journal = Journal::create(root.path().join("journal")).unwrap();
        let digest = Sha256Digest::of_bytes(b"fixture");
        journal
            .append(
                Utc::now(),
                JournalEvent::PlanApproved {
                    plan_id: PlanId::new(),
                    plan_digest: digest,
                },
            )
            .unwrap();
        for index in 0..32 {
            journal
                .append(
                    Utc::now(),
                    JournalEvent::ActionStarted {
                        action_id: index.to_string(),
                        pre_state_digest: digest,
                    },
                )
                .unwrap();
            journal
                .append(
                    Utc::now(),
                    JournalEvent::ActionFinished {
                        action_id: index.to_string(),
                        status: ActionStatus::Succeeded,
                        receipt_digest: digest,
                    },
                )
                .unwrap();
        }
        journal
            .append(
                Utc::now(),
                JournalEvent::RunFinished {
                    result_id: ResultId::new(),
                    result_digest: digest,
                },
            )
            .unwrap();
        let snapshot = Journal::verify(journal.path(), journal.terminal_hash()).unwrap();
        assert_eq!(snapshot.records.len(), 66);
    });
}

#[test]
#[ignore = "portable cost harness; run --release --ignored --nocapture"]
fn evidence_io_distribution() {
    for size in [4096, 1024 * 1024, 16 * 1024 * 1024] {
        let bytes = payload(size);
        measure("evidence_bytes", size, || evidence_roundtrip(&bytes));
    }
}

fn evidence_roundtrip(bytes: &[u8]) {
    let root = tempfile::tempdir().unwrap();
    let limits = EvidenceLimits {
        max_file_bytes: 32 * 1024 * 1024,
        max_total_bytes: 32 * 1024 * 1024,
        max_artifacts: 1,
    };
    let mut store = EvidenceStore::create(root.path(), limits, Arc::new(FixtureTrust)).unwrap();
    let artifact = store
        .write(
            EvidenceWrite {
                locator: "evidence.bin",
                kind: ArtifactKind::Evidence,
                media_type: "application/octet-stream",
                created_at: Utc::now(),
                metadata: JsonMap::new(),
            },
            bytes,
        )
        .unwrap();
    assert_eq!(artifact.digest, Sha256Digest::of_bytes(bytes));
    EvidenceStore::open(root.path(), limits, Arc::new(FixtureTrust)).unwrap();
}

#[test]
#[ignore = "portable cost harness; run --release --ignored --nocapture"]
fn package_io_distribution() {
    for size in [4096, 1024 * 1024, 16 * 1024 * 1024] {
        let root = tempfile::tempdir().unwrap();
        let package = root.path().join("fixture.zip");
        create_package(&package, &payload(size));
        measure("package_payload_bytes", size, || {
            let result =
                verify_package(&package, "portable fixture", &FixtureTrust, &FixtureTrust).unwrap();
            assert_eq!(result.verified_files, 4);
            assert_eq!(result.verified_signatures, 3);
        });
    }
}

fn payload(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect()
}

fn create_package(path: &Path, bytes: &[u8]) {
    let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
    let mut files = Vec::new();
    for name in crate::package::REQUIRED_EXECUTABLES {
        add_file(&mut zip, name, b"inert executable fixture");
        files.push(manifest_file(name, b"inert executable fixture"));
    }
    add_file(&mut zip, "data/evidence.bin", bytes);
    files.push(manifest_file("data/evidence.bin", bytes));
    let manifest = PackageManifestV1 {
        schema_version: "1.0".into(),
        product: "BaselineOps for Windows".into(),
        package_version: env!("CARGO_PKG_VERSION").into(),
        target: "x86_64-pc-windows-msvc".into(),
        signer_subject: "portable fixture".into(),
        files,
    };
    let encoded = baselineops_domain::canonical_json_bytes(&manifest).unwrap();
    add_file(&mut zip, crate::package::MANIFEST_PATH, &encoded);
    add_file(
        &mut zip,
        crate::package::MANIFEST_SIGNATURE_PATH,
        Sha256Digest::of_bytes(&encoded).to_hex().as_bytes(),
    );
    zip.finish().unwrap().sync_all().unwrap();
}

fn manifest_file(name: &str, bytes: &[u8]) -> ManifestFile {
    ManifestFile {
        path: name.into(),
        size_bytes: bytes.len() as u64,
        sha256: Sha256Digest::of_bytes(bytes),
    }
}

fn add_file(zip: &mut zip::ZipWriter<File>, name: &str, bytes: &[u8]) {
    zip.start_file(
        name,
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )
    .unwrap();
    zip.write_all(bytes).unwrap();
}
