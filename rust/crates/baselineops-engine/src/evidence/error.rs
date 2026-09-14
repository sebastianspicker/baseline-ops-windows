use std::io;

/// Evidence retention failures. Protection failures deliberately reject use.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    /// File operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Canonical serialization failed.
    #[error(transparent)]
    Domain(#[from] baselineops_domain::DomainError),
    /// Strict manifest decoding failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Atomic manifest replacement failed.
    #[error(transparent)]
    Platform(#[from] baselineops_windows::PlatformError),
    /// Protection establishment or verification failed.
    #[error("evidence protection failed: {0}")]
    Protection(String),
    /// Limits are empty or internally inconsistent.
    #[error("evidence limits are invalid")]
    InvalidLimits,
    /// A new store would replace an existing manifest.
    #[error("evidence manifest already exists")]
    AlreadyExists,
    /// A locator is absolute, traversal-like, or platform-ambiguous.
    #[error("unsafe evidence locator: {0}")]
    UnsafeLocator(String),
    /// A quota would be exceeded.
    #[error("evidence quota exceeded")]
    QuotaExceeded,
    /// Manifest fields or retained inventory are inconsistent.
    #[error("evidence manifest is invalid")]
    InvalidManifest,
    /// The on-disk manifest is not its canonical serialization.
    #[error("evidence manifest is not canonical")]
    NonCanonicalManifest,
    /// A retained artifact changed after its digest was recorded.
    #[error("evidence integrity mismatch: {0}")]
    IntegrityMismatch(String),
    /// The requested locator does not appear in the manifest.
    #[error("unknown evidence artifact")]
    UnknownArtifact,
    /// Manifest persistence failed and the prior manifest could not be restored durably.
    #[error("evidence manifest persistence failed ({persistence}); rollback failed ({rollback})")]
    PersistenceRollback {
        /// Original persistence failure.
        persistence: Box<EvidenceError>,
        /// Failure while restoring the prior canonical manifest.
        rollback: Box<EvidenceError>,
    },
    /// A failed persistence rollback left this store handle unusable until reopened.
    #[error("evidence store is unusable after an incomplete persistence rollback")]
    Unusable,
}
