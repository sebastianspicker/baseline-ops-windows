use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use baselineops_domain::{Sha256Digest, canonical_json_bytes};

use super::{
    JOURNAL_MAGIC, JournalError, JournalLimits, JournalRecord, JournalSnapshot, Lifecycle,
    MAX_RECORD_BYTES, ensure_record_limit, ensure_size_limit, validate_record,
};

impl super::Journal {
    /// Verify already retained journal bytes without reopening a path.
    ///
    /// This validates integrity and lifecycle only; callers must independently establish
    /// the source's protection and compare an authenticated terminal anchor.
    ///
    /// # Errors
    /// Returns an error for invalid framing, lifecycle, chain integrity, or limits.
    pub fn read_bytes(
        bytes: &[u8],
        limits: JournalLimits,
    ) -> Result<JournalSnapshot, JournalError> {
        let parsed = parse_bytes(bytes, limits)?;
        if parsed.trailing_bytes != 0 {
            return Err(JournalError::IncompleteFrame);
        }
        Ok(parsed.snapshot)
    }
}

pub(super) struct ParsedJournal {
    pub(super) snapshot: JournalSnapshot,
    pub(super) next_sequence: u64,
    pub(super) valid_bytes: u64,
    pub(super) trailing_bytes: u64,
}

pub(super) fn parse_journal(
    path: &Path,
    limits: JournalLimits,
) -> Result<ParsedJournal, JournalError> {
    let file = File::open(path)?;
    ensure_size_limit(file.metadata()?.len(), limits)?;
    let mut reader = BufReader::new(file);
    read_magic(&mut reader)?;
    parse_records(&mut reader, limits)
}

pub(super) fn parse_bytes(
    bytes: &[u8],
    limits: JournalLimits,
) -> Result<ParsedJournal, JournalError> {
    ensure_size_limit(bytes.len() as u64, limits)?;
    let mut reader = bytes;
    read_magic(&mut reader)?;
    parse_records(&mut reader, limits)
}

fn parse_records(
    reader: &mut impl Read,
    limits: JournalLimits,
) -> Result<ParsedJournal, JournalError> {
    let mut state = ParseState::new();
    let mut frame = Vec::new();
    while let Some(prefix_end) = state.read_prefix(reader, limits)? {
        if !state.read_frame(reader, &mut frame, prefix_end, limits)? {
            break;
        }
        state.accept_frame(&frame, limits)?;
    }
    Ok(state.finish())
}

struct ParseState {
    prefix: [u8; 4],
    records: Vec<JournalRecord>,
    previous_hash: Sha256Digest,
    next_sequence: u64,
    valid_bytes: u64,
    trailing_bytes: u64,
    lifecycle: Lifecycle,
}

impl ParseState {
    fn new() -> Self {
        Self {
            prefix: [0; 4],
            records: Vec::new(),
            previous_hash: Sha256Digest::of_bytes([]),
            next_sequence: 0,
            valid_bytes: JOURNAL_MAGIC.len() as u64,
            trailing_bytes: 0,
            lifecycle: Lifecycle::default(),
        }
    }

    fn read_prefix(
        &mut self,
        reader: &mut impl Read,
        limits: JournalLimits,
    ) -> Result<Option<u64>, JournalError> {
        let prefix_bytes = read_available(reader, &mut self.prefix)?;
        if prefix_bytes == 0 {
            return Ok(None);
        }
        let prefix_end = ensure_observed_size(self.valid_bytes, prefix_bytes, limits)?;
        if prefix_bytes < self.prefix.len() {
            self.trailing_bytes = prefix_bytes as u64;
            return Ok(None);
        }
        Ok(Some(prefix_end))
    }

    fn read_frame(
        &mut self,
        reader: &mut impl Read,
        frame: &mut Vec<u8>,
        prefix_end: u64,
        limits: JournalLimits,
    ) -> Result<bool, JournalError> {
        let length = frame_length(self.prefix)?;
        let remaining = limits.max_bytes - prefix_end;
        let maximum_read = usize::try_from(remaining.saturating_add(1)).unwrap_or(usize::MAX);
        frame.resize(length.min(maximum_read), 0);
        let frame_bytes = read_available(reader, frame)?;
        ensure_observed_size(prefix_end, frame_bytes, limits)?;
        if frame_bytes < length {
            self.trailing_bytes = 4 + frame_bytes as u64;
            return Ok(false);
        }
        Ok(true)
    }

    fn accept_frame(&mut self, frame: &[u8], limits: JournalLimits) -> Result<(), JournalError> {
        ensure_record_limit(self.next_sequence, limits)?;
        self.push_record(parse_record(frame)?, frame.len())
    }

    fn push_record(&mut self, record: JournalRecord, length: usize) -> Result<(), JournalError> {
        validate_record(&record, self.next_sequence, self.previous_hash)?;
        self.lifecycle.validate(&record.payload)?;
        self.lifecycle.accept(&record.payload);
        self.valid_bytes += 4 + length as u64;
        self.previous_hash = record.record_hash;
        self.records.push(record);
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
        Ok(())
    }

    fn finish(self) -> ParsedJournal {
        ParsedJournal {
            snapshot: JournalSnapshot {
                records: self.records,
                terminal_hash: self.previous_hash,
            },
            next_sequence: self.next_sequence,
            valid_bytes: self.valid_bytes,
            trailing_bytes: self.trailing_bytes,
        }
    }
}

fn read_magic(reader: &mut impl Read) -> Result<(), JournalError> {
    let mut magic = [0_u8; JOURNAL_MAGIC.len()];
    if read_available(reader, &mut magic)? != magic.len() || magic != JOURNAL_MAGIC {
        return Err(JournalError::BadMagic);
    }
    Ok(())
}

fn read_available(reader: &mut impl Read, destination: &mut [u8]) -> io::Result<usize> {
    let mut read = 0;
    while read < destination.len() {
        match reader.read(&mut destination[read..]) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(read)
}

fn frame_length(prefix: [u8; 4]) -> Result<usize, JournalError> {
    let length =
        usize::try_from(u32::from_le_bytes(prefix)).map_err(|_| JournalError::RecordTooLarge)?;
    if length == 0 || length > MAX_RECORD_BYTES {
        return Err(JournalError::RecordTooLarge);
    }
    Ok(length)
}

fn ensure_observed_size(
    valid_bytes: u64,
    observed_bytes: usize,
    limits: JournalLimits,
) -> Result<u64, JournalError> {
    let observed_bytes =
        u64::try_from(observed_bytes).map_err(|_| JournalError::JournalSizeLimitExceeded {
            limit: limits.max_bytes,
        })?;
    let observed_end =
        valid_bytes
            .checked_add(observed_bytes)
            .ok_or(JournalError::JournalSizeLimitExceeded {
                limit: limits.max_bytes,
            })?;
    ensure_size_limit(observed_end, limits)?;
    Ok(observed_end)
}

fn parse_record(frame: &[u8]) -> Result<JournalRecord, JournalError> {
    let record: JournalRecord =
        serde_json::from_slice(frame).map_err(JournalError::InvalidRecord)?;
    if canonical_json_bytes(&record)? != frame {
        return Err(JournalError::NonCanonicalRecord);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn prefix_growth_after_metadata_check_enforces_actual_bytes() {
        let mut reader = Cursor::new([1_u8]);
        let limits = JournalLimits::new(JOURNAL_MAGIC.len() as u64, 1);

        assert!(matches!(
            parse_records(&mut reader, limits),
            Err(JournalError::JournalSizeLimitExceeded { .. })
        ));
    }
}
