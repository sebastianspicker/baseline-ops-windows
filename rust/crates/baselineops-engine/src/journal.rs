use baselineops_domain::{ActionStatus, PlanId, ResultId, Sha256Digest, canonical_json_bytes};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

mod lifecycle;
mod reader;
mod storage;

use lifecycle::Lifecycle;

use reader::parse_journal;

const JOURNAL_MAGIC: &[u8] = b"BASELINEOPS-JOURNAL-V2\n";
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_RECORDS: usize = 4096;

/// Resource limits applied while creating, appending, reading, and recovering a journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalLimits {
    /// Maximum complete file size, including the journal marker and frame prefixes.
    pub max_bytes: u64,
    /// Maximum number of complete records.
    pub max_records: usize,
}

impl JournalLimits {
    /// Constructs explicit journal limits for a trusted caller.
    #[must_use]
    pub const fn new(max_bytes: u64, max_records: usize) -> Self {
        Self {
            max_bytes,
            max_records,
        }
    }
}

impl Default for JournalLimits {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_BYTES, DEFAULT_MAX_RECORDS)
    }
}

/// Mutation-boundary event retained in the protected worker run directory.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum JournalEvent {
    /// Operator approved the exact plan digest.
    PlanApproved {
        /// Plan identity.
        plan_id: PlanId,
        /// Canonical approved plan digest.
        plan_digest: Sha256Digest,
    },
    /// An action is about to mutate state after precondition revalidation.
    ActionStarted {
        /// Stable action identifier.
        action_id: String,
        /// Digest of pre-state captured before mutation.
        pre_state_digest: Sha256Digest,
    },
    /// An action reached a terminal boundary.
    ActionFinished {
        /// Stable action identifier.
        action_id: String,
        /// Typed terminal status; only success permits another action.
        status: ActionStatus,
        /// Digest of post-state or action receipt.
        receipt_digest: Sha256Digest,
    },
    /// Worker finalized the result and artifact manifest.
    RunFinished {
        /// Result identity.
        result_id: ResultId,
        /// Digest of the retained result document, before adding this terminal journal anchor
        /// and the document's own artifact reference to the broker envelope.
        result_digest: Sha256Digest,
    },
}

/// One hash-chained journal record.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct JournalRecord {
    /// Monotonic record sequence.
    pub sequence: u64,
    /// Worker-trusted timestamp.
    pub timestamp: DateTime<Utc>,
    /// Previous record hash, or all zeros for the first record.
    pub previous_hash: Sha256Digest,
    /// Event payload.
    pub payload: JournalEvent,
    /// Hash of sequence, timestamp, previous hash, and payload.
    pub record_hash: Sha256Digest,
}

/// Append-only writer for a tamper-evident journal.
pub struct Journal {
    path: PathBuf,
    file: storage::Storage,
    next_sequence: u64,
    previous_hash: Sha256Digest,
    current_bytes: u64,
    limits: JournalLimits,
    lifecycle: Lifecycle,
    write_failed: bool,
}

/// Verified journal contents and the chain anchor needed to detect truncation.
#[derive(Clone, Debug)]
pub struct JournalSnapshot {
    /// Records in their file order after hash-chain verification.
    pub records: Vec<JournalRecord>,
    /// Digest of the final retained record, or the empty-chain digest.
    pub terminal_hash: Sha256Digest,
}

/// Recovery result for a journal that ended in an interrupted frame write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalRecovery {
    /// Number of incomplete trailing bytes removed. Complete invalid records are never removed.
    pub truncated_bytes: u64,
}

impl Journal {
    /// Create a journal through a worker-owned directory capability.
    ///
    /// The sink retains its directory protection for the writer's lifetime and enforces
    /// the platform's byte quota. No caller-provided path is opened by this constructor.
    /// This creates output storage only; it does not grant capability execution authority.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported platforms, failed protection/creation, or durability.
    pub fn create_protected(
        run: &mut baselineops_windows::ProtectedRunDirectory,
    ) -> Result<Self, JournalError> {
        let file = run.create_journal()?;
        let path = file.path().to_path_buf();
        Self::initialize(
            path,
            storage::Storage::Protected(file),
            JournalLimits::new(
                baselineops_windows::MAX_JOURNAL_BYTES as u64,
                DEFAULT_MAX_RECORDS,
            ),
        )
    }

    /// Create a local journal using the default limits.
    ///
    /// This path-based API provides integrity and durability, not Windows output authority.
    /// Production worker creation must use [`Self::create_protected`].
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the journal cannot be created, written, or synced.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::create_with_limits(path, JournalLimits::default()).map_err(JournalError::into_io)
    }

    /// Create a new journal with caller-selected resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error before creating the file if its marker exceeds `limits`.
    pub fn create_with_limits(
        path: impl AsRef<Path>,
        limits: JournalLimits,
    ) -> Result<Self, JournalError> {
        ensure_size_limit(JOURNAL_MAGIC.len() as u64, limits)?;
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Self::initialize(path, file.into(), limits)
    }

    fn initialize(
        path: PathBuf,
        mut file: storage::Storage,
        limits: JournalLimits,
    ) -> Result<Self, JournalError> {
        file.write_all(JOURNAL_MAGIC)?;
        file.synchronize()?;
        Ok(Self {
            path,
            file,
            next_sequence: 0,
            previous_hash: Sha256Digest::of_bytes([]),
            current_bytes: JOURNAL_MAGIC.len() as u64,
            limits,
            lifecycle: Lifecycle::default(),
            write_failed: false,
        })
    }

    /// Open an existing local journal after validating complete records with default limits.
    ///
    /// This verifies content integrity, not the path's Windows protection. It is not an
    /// execution-recovery authority and cannot reopen an interrupted action for retry.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid framing, chain integrity, lifecycle, limits, or file access.
    /// An unmatched action start requires explicit action recovery and cannot be reopened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        Self::open_with_limits(path, JournalLimits::default())
    }

    /// Open an existing journal after validating every complete record with explicit limits.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid framing, chain integrity, lifecycle, limits, or file access.
    /// An unmatched action start requires explicit action recovery and cannot be reopened.
    pub fn open_with_limits(
        path: impl AsRef<Path>,
        limits: JournalLimits,
    ) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let parsed = complete_parse(&path, limits)?;
        let lifecycle = Lifecycle::from_snapshot(&parsed.snapshot)?;
        lifecycle.require_resumable()?;
        let file = OpenOptions::new().append(true).open(&path)?;
        Ok(Self {
            path,
            file: file.into(),
            next_sequence: parsed.next_sequence,
            previous_hash: parsed.snapshot.terminal_hash,
            current_bytes: parsed.valid_bytes,
            limits,
            lifecycle,
            write_failed: false,
        })
    }

    /// Read and verify a complete journal with default resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid framing, chain integrity, limits, or file access.
    pub fn read(path: impl AsRef<Path>) -> Result<JournalSnapshot, JournalError> {
        Self::read_with_limits(path, JournalLimits::default())
    }

    /// Read and verify a complete journal with caller-selected resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid framing, chain integrity, limits, or file access.
    pub fn read_with_limits(
        path: impl AsRef<Path>,
        limits: JournalLimits,
    ) -> Result<JournalSnapshot, JournalError> {
        Ok(complete_parse(path.as_ref(), limits)?.snapshot)
    }

    /// Verify a journal against a terminal hash using default resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error when parsing fails or the terminal hash differs.
    pub fn verify(
        path: impl AsRef<Path>,
        expected_terminal_hash: Sha256Digest,
    ) -> Result<JournalSnapshot, JournalError> {
        Self::verify_with_limits(path, expected_terminal_hash, JournalLimits::default())
    }

    /// Verify a journal against a terminal hash using caller-selected resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error when parsing fails or the terminal hash differs.
    pub fn verify_with_limits(
        path: impl AsRef<Path>,
        expected_terminal_hash: Sha256Digest,
        limits: JournalLimits,
    ) -> Result<JournalSnapshot, JournalError> {
        let snapshot = Self::read_with_limits(path, limits)?;
        if snapshot.terminal_hash != expected_terminal_hash {
            return Err(JournalError::TerminalHashMismatch);
        }
        Ok(snapshot)
    }

    /// Recover an incomplete final frame using default resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid complete frame, file failure, or interrupted action.
    /// Frame repair does not authorize retrying or rolling back a mutation.
    pub fn recover(path: impl AsRef<Path>) -> Result<(Self, JournalRecovery), JournalError> {
        Self::recover_with_limits(path, JournalLimits::default())
    }

    /// Recover an incomplete final frame using caller-selected resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid complete frame, exceeded limit, file failure, or
    /// interrupted action. An unmatched action start prevents truncation and reopening.
    pub fn recover_with_limits(
        path: impl AsRef<Path>,
        limits: JournalLimits,
    ) -> Result<(Self, JournalRecovery), JournalError> {
        let path = path.as_ref().to_path_buf();
        let parsed = parse_journal(&path, limits)?;
        Lifecycle::from_snapshot(&parsed.snapshot)?.validate_recovery(parsed.trailing_bytes)?;
        truncate_incomplete_frame(&path, parsed.valid_bytes, parsed.trailing_bytes)?;
        let recovery = JournalRecovery {
            truncated_bytes: parsed.trailing_bytes,
        };
        let journal = Self::open_with_limits(path, limits)?;
        Ok((journal, recovery))
    }

    /// Append, flush, and sync one mutation-boundary record.
    ///
    /// # Errors
    ///
    /// Returns an error before writing when a limit would be exceeded, or on serialization,
    /// writing, or durable synchronization failure.
    pub fn append(
        &mut self,
        timestamp: DateTime<Utc>,
        payload: JournalEvent,
    ) -> Result<JournalRecord, JournalError> {
        if self.write_failed {
            return Err(JournalError::WriteFailed);
        }
        ensure_record_limit(self.next_sequence, self.limits)?;
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
        let record = journal_record(self.next_sequence, self.previous_hash, timestamp, payload)?;
        let next_bytes = self.write_next_record(&record)?;
        self.lifecycle.accept(&record.payload);
        self.previous_hash = record.record_hash;
        self.next_sequence = next_sequence;
        self.current_bytes = next_bytes;
        Ok(record)
    }

    fn write_next_record(&mut self, record: &JournalRecord) -> Result<u64, JournalError> {
        let bytes = canonical_json_bytes(record)?;
        let next_bytes = self.next_frame_end(bytes.len())?;
        self.lifecycle.validate(&record.payload)?;
        write_durable_record(&mut self.file, &mut self.write_failed, &bytes)?;
        Ok(next_bytes)
    }

    fn next_frame_end(&self, length: usize) -> Result<u64, JournalError> {
        let frame_bytes = frame_size(length)?;
        let next_bytes = self.current_bytes.checked_add(frame_bytes).ok_or(
            JournalError::JournalSizeLimitExceeded {
                limit: self.limits.max_bytes,
            },
        )?;
        ensure_size_limit(next_bytes, self.limits)?;
        Ok(next_bytes)
    }

    /// Terminal chain hash. It is meaningful only when retained independently.
    pub const fn terminal_hash(&self) -> Sha256Digest {
        self.previous_hash
    }

    /// Journal path beneath the worker-controlled protected run directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn complete_parse(
    path: &Path,
    limits: JournalLimits,
) -> Result<reader::ParsedJournal, JournalError> {
    let parsed = parse_journal(path, limits)?;
    if parsed.trailing_bytes != 0 {
        return Err(JournalError::IncompleteFrame);
    }
    Ok(parsed)
}

fn ensure_size_limit(bytes: u64, limits: JournalLimits) -> Result<(), JournalError> {
    if bytes > limits.max_bytes {
        return Err(JournalError::JournalSizeLimitExceeded {
            limit: limits.max_bytes,
        });
    }
    Ok(())
}

fn ensure_record_limit(sequence: u64, limits: JournalLimits) -> Result<(), JournalError> {
    let count = usize::try_from(sequence).map_err(|_| JournalError::SequenceOverflow)?;
    if count >= limits.max_records {
        return Err(JournalError::JournalRecordLimitExceeded {
            limit: limits.max_records,
        });
    }
    Ok(())
}

fn frame_size(record_bytes: usize) -> Result<u64, JournalError> {
    if record_bytes == 0 || record_bytes > MAX_RECORD_BYTES {
        return Err(JournalError::RecordTooLarge);
    }
    u64::try_from(4 + record_bytes).map_err(|_| JournalError::RecordTooLarge)
}

fn truncate_incomplete_frame(
    path: &Path,
    valid_bytes: u64,
    trailing_bytes: u64,
) -> Result<(), JournalError> {
    if trailing_bytes == 0 {
        return Ok(());
    }
    let file = OpenOptions::new().write(true).open(path)?;
    file.set_len(valid_bytes)?;
    file.sync_all()?;
    Ok(())
}

fn journal_record(
    sequence: u64,
    previous_hash: Sha256Digest,
    timestamp: DateTime<Utc>,
    payload: JournalEvent,
) -> Result<JournalRecord, JournalError> {
    let record_hash = Sha256Digest::of_bytes(canonical_json_bytes(&(
        sequence,
        timestamp,
        previous_hash,
        &payload,
    ))?);
    Ok(JournalRecord {
        sequence,
        timestamp,
        previous_hash,
        payload,
        record_hash,
    })
}

trait DurableWrite: Write {
    fn synchronize(&mut self) -> io::Result<()>;
}

impl DurableWrite for File {
    fn synchronize(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

fn write_durable_record(
    file: &mut impl DurableWrite,
    write_failed: &mut bool,
    bytes: &[u8],
) -> Result<(), JournalError> {
    if *write_failed {
        return Err(JournalError::WriteFailed);
    }
    *write_failed = true;
    write_record(file, bytes)?;
    *write_failed = false;
    Ok(())
}

fn write_record(file: &mut impl DurableWrite, bytes: &[u8]) -> Result<(), JournalError> {
    let length = u32::try_from(bytes.len()).map_err(|_| JournalError::RecordTooLarge)?;
    file.write_all(&length.to_le_bytes())?;
    file.write_all(bytes)?;
    file.flush()?;
    file.synchronize()?;
    Ok(())
}

fn validate_record(
    record: &JournalRecord,
    sequence: u64,
    previous_hash: Sha256Digest,
) -> Result<(), JournalError> {
    if record.sequence != sequence {
        return Err(JournalError::SequenceMismatch);
    }
    if record.previous_hash != previous_hash {
        return Err(JournalError::PreviousHashMismatch);
    }
    let hash_payload = (
        record.sequence,
        record.timestamp,
        record.previous_hash,
        &record.payload,
    );
    if Sha256Digest::of_bytes(canonical_json_bytes(&hash_payload)?) != record.record_hash {
        return Err(JournalError::RecordHashMismatch);
    }
    Ok(())
}

/// Journal append and verification failures.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The Windows protected-output boundary failed closed.
    #[error(transparent)]
    Protection(#[from] baselineops_windows::PlatformError),
    /// File operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Canonical serialization failed.
    #[error(transparent)]
    Domain(#[from] baselineops_domain::DomainError),
    /// An earlier write or durability operation failed; this writer cannot be reused.
    #[error("journal writer is unusable after a write or synchronization failure")]
    WriteFailed,
    /// A correctly hashed record violates sequential execution boundaries.
    #[error("journal execution lifecycle is invalid: {0}")]
    InvalidLifecycle(&'static str),
    /// A durable action start has no terminal receipt; reopening cannot retry it.
    #[error("journal contains interrupted action {0}; explicit action recovery is required")]
    ActionRecoveryRequired(String),
    /// A frame exceeded the fixed 4 MiB record limit or its framing range.
    #[error("journal record exceeded the framing limit")]
    RecordTooLarge,
    /// The journal exceeds its configured byte quota.
    #[error("journal exceeds the configured byte limit of {limit}")]
    JournalSizeLimitExceeded {
        /// Configured maximum file size.
        limit: u64,
    },
    /// The journal exceeds its configured record quota.
    #[error("journal exceeds the configured record limit of {limit}")]
    JournalRecordLimitExceeded {
        /// Configured maximum record count.
        limit: usize,
    },
    /// The file did not begin with the exact journal marker.
    #[error(
        "journal marker is invalid or unsupported; preserve older journals for manual recovery"
    )]
    BadMagic,
    /// The final frame is incomplete and must be recovered explicitly.
    #[error("journal ends with an incomplete frame")]
    IncompleteFrame,
    /// A frame used an alternate encoding that the canonical writer never emits.
    #[error("journal record encoding is not canonical")]
    NonCanonicalRecord,
    /// A complete frame could not be parsed as a strict journal record.
    #[error("journal record is invalid: {0}")]
    InvalidRecord(serde_json::Error),
    /// A record's sequence was not monotonic.
    #[error("journal record sequence is invalid")]
    SequenceMismatch,
    /// The sequence could not be advanced.
    #[error("journal record sequence overflowed")]
    SequenceOverflow,
    /// A record was not bound to the prior chain hash.
    #[error("journal previous hash does not match")]
    PreviousHashMismatch,
    /// A record's canonical payload hash changed.
    #[error("journal record hash does not match")]
    RecordHashMismatch,
    /// The chain is a valid prefix but not the independently retained terminal chain.
    #[error("journal terminal hash does not match")]
    TerminalHashMismatch,
}

impl JournalError {
    fn into_io(self) -> io::Error {
        match self {
            Self::Io(error) => error,
            other => io::Error::new(io::ErrorKind::InvalidInput, other),
        }
    }
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
