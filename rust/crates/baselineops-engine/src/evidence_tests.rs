use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[derive(Default)]
struct Protection;

impl EvidenceProtection for Protection {
    fn protect(&self, _root: &Path) -> Result<(), EvidenceError> {
        Ok(())
    }

    fn verify(&self, _root: &Path) -> Result<(), EvidenceError> {
        Ok(())
    }
}

struct FailOnVerify {
    calls: AtomicUsize,
    failure_call: AtomicUsize,
}

impl FailOnVerify {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            failure_call: AtomicUsize::new(usize::MAX),
        }
    }

    fn fail_on_next_persist(&self) {
        self.failure_call
            .store(self.calls.load(Ordering::SeqCst) + 2, Ordering::SeqCst);
    }

    fn fail_on_rollback_after_next_persist(&self) {
        self.failure_call
            .store(self.calls.load(Ordering::SeqCst) + 3, Ordering::SeqCst);
    }
}

impl EvidenceProtection for FailOnVerify {
    fn protect(&self, _root: &Path) -> Result<(), EvidenceError> {
        Ok(())
    }

    fn verify(&self, _root: &Path) -> Result<(), EvidenceError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.failure_call.load(Ordering::SeqCst) {
            return Err(EvidenceError::Protection("injected failure".into()));
        }
        Ok(())
    }
}

fn limits() -> EvidenceLimits {
    EvidenceLimits {
        max_file_bytes: 8,
        max_total_bytes: 10,
        max_artifacts: 2,
    }
}

fn roomy_limits() -> EvidenceLimits {
    EvidenceLimits {
        max_file_bytes: 1024,
        max_total_bytes: 4096,
        max_artifacts: 16,
    }
}

fn request(locator: &str) -> EvidenceWrite<'_> {
    EvidenceWrite {
        locator,
        kind: ArtifactKind::Evidence,
        media_type: "text/plain",
        created_at: Utc::now(),
        metadata: JsonMap::new(),
    }
}

#[test]
fn store_rejects_traversal_and_enforces_quotas() {
    let root = tempfile::tempdir().expect("root");
    let mut store =
        EvidenceStore::create(root.path().join("evidence"), limits(), Arc::new(Protection))
            .expect("store");

    assert!(matches!(
        store.write(request("../outside"), b"x"),
        Err(EvidenceError::UnsafeLocator(_))
    ));
    store
        .write(request("first.txt"), b"12345678")
        .expect("first");
    assert!(matches!(
        store.write(request("second.txt"), b"123"),
        Err(EvidenceError::QuotaExceeded)
    ));
}

#[test]
fn insertion_keeps_manifest_sorted_and_reopen_verified() {
    let root = tempfile::tempdir().expect("root");
    let evidence_root = root.path().join("evidence");
    let protection = Arc::new(Protection);
    let mut store =
        EvidenceStore::create(&evidence_root, roomy_limits(), protection.clone()).expect("store");
    for locator in ["z.txt", "a.txt", "middle.txt"] {
        store
            .write(request(locator), locator.as_bytes())
            .expect("write");
    }

    let locators = store
        .manifest()
        .artifacts
        .iter()
        .map(|artifact| artifact.locator.as_str())
        .collect::<Vec<_>>();
    assert_eq!(locators, ["a.txt", "middle.txt", "z.txt"]);
    let reopened = EvidenceStore::open(evidence_root, roomy_limits(), protection).expect("reopen");
    assert_eq!(reopened.manifest(), store.manifest());
}

#[test]
fn persistence_failure_restores_manifest_exactly_and_removes_artifact() {
    let root = tempfile::tempdir().expect("root");
    let evidence_root = root.path().join("evidence");
    let protection = Arc::new(FailOnVerify::new());
    let mut store =
        EvidenceStore::create(&evidence_root, roomy_limits(), protection.clone()).expect("store");
    store
        .write(request("middle.txt"), b"middle")
        .expect("initial artifact");
    let before = store.manifest().clone();
    let manifest_bytes = fs::read(evidence_root.join(MANIFEST_NAME)).expect("manifest bytes");
    protection.fail_on_next_persist();

    let error = store
        .write(request("first.txt"), b"first")
        .expect_err("manifest persistence must fail");

    assert!(matches!(error, EvidenceError::Protection(_)));
    assert_eq!(store.manifest(), &before);
    assert_eq!(
        fs::read(evidence_root.join(MANIFEST_NAME)).expect("manifest bytes"),
        manifest_bytes
    );
    assert!(!evidence_root.join("first.txt").exists());
}

#[test]
fn post_replacement_failure_restores_prior_canonical_manifest() {
    let root = tempfile::tempdir().expect("root");
    let evidence_root = root.path().join("evidence");
    let protection = Arc::new(Protection);
    let mut store =
        EvidenceStore::create(&evidence_root, roomy_limits(), protection.clone()).expect("store");
    store
        .write(request("middle.txt"), b"middle")
        .expect("initial artifact");
    let before = store.manifest().clone();
    let manifest_bytes = fs::read(evidence_root.join(MANIFEST_NAME)).expect("manifest bytes");
    store.fail_next_persist_after_replace();

    let error = store
        .write(request("first.txt"), b"first")
        .expect_err("injected post-replacement failure");

    assert!(matches!(error, EvidenceError::Protection(_)));
    assert_eq!(store.manifest(), &before);
    assert_eq!(
        fs::read(evidence_root.join(MANIFEST_NAME)).expect("manifest bytes"),
        manifest_bytes
    );
    assert!(!evidence_root.join("first.txt").exists());
    let reopened = EvidenceStore::open(evidence_root, roomy_limits(), protection).expect("reopen");
    assert_eq!(reopened.manifest(), &before);
}

#[test]
fn rollback_failure_makes_handle_unusable_until_reopened() {
    let root = tempfile::tempdir().expect("root");
    let evidence_root = root.path().join("evidence");
    let protection = Arc::new(FailOnVerify::new());
    let mut store =
        EvidenceStore::create(&evidence_root, roomy_limits(), protection.clone()).expect("store");
    store
        .write(request("middle.txt"), b"middle")
        .expect("initial artifact");
    store.fail_next_persist_after_replace();
    protection.fail_on_rollback_after_next_persist();

    let error = store
        .write(request("first.txt"), b"first")
        .expect_err("rollback must fail");

    assert!(matches!(error, EvidenceError::PersistenceRollback { .. }));
    assert!(matches!(
        store.read("middle.txt"),
        Err(EvidenceError::Unusable)
    ));
    let reopened = EvidenceStore::open(evidence_root, roomy_limits(), protection).expect("reopen");
    assert_eq!(reopened.manifest().artifacts.len(), 2);
    assert_eq!(reopened.read("first.txt").expect("artifact"), b"first");
}

#[test]
fn store_detects_tampered_artifacts_when_reopened() {
    let root = tempfile::tempdir().expect("root");
    let evidence_root = root.path().join("evidence");
    let mut store =
        EvidenceStore::create(&evidence_root, limits(), Arc::new(Protection)).expect("store");
    store
        .write(request("nested/receipt.txt"), b"original")
        .expect("write");
    fs::write(evidence_root.join("nested/receipt.txt"), b"edited").expect("tamper");

    assert!(matches!(
        EvidenceStore::open(evidence_root, limits(), Arc::new(Protection)),
        Err(EvidenceError::IntegrityMismatch(_))
    ));
}

#[test]
fn noncanonical_manifest_is_rejected() {
    let root = tempfile::tempdir().expect("root");
    let evidence_root = root.path().join("evidence");
    let _store =
        EvidenceStore::create(&evidence_root, limits(), Arc::new(Protection)).expect("store");
    let manifest = fs::read(evidence_root.join(MANIFEST_NAME)).expect("manifest");
    let value = serde_json::from_slice::<serde_json::Value>(&manifest).expect("json");
    fs::write(
        evidence_root.join(MANIFEST_NAME),
        serde_json::to_vec_pretty(&value).expect("pretty json"),
    )
    .expect("tamper");

    assert!(matches!(
        EvidenceStore::open(evidence_root, limits(), Arc::new(Protection)),
        Err(EvidenceError::NonCanonicalManifest)
    ));
}
