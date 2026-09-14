use super::{BrokerBinding, MAX_KIND_BYTES, PROTOCOL_VERSION, valid_nonce};
use crate::PlatformError;
use serde::{Deserialize, Serialize};

/// Versioned broker envelope carried inside a bounded frame.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerMessage {
    /// Fixed protocol revision; peers with another revision are rejected.
    pub version: u16,
    /// Immutable plan/session binding for this message.
    pub binding: BrokerBinding,
    /// Cryptographically random, single-use request nonce encoded as lowercase hex.
    pub nonce: String,
    /// Bounded operation discriminator selected by the trusted client.
    pub kind: String,
    /// Capability-specific canonical JSON payload.
    pub payload: serde_json::Value,
}

impl BrokerMessage {
    /// Validate envelope fields independently of the payload schema.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid envelope or binding.
    pub fn validate(&self) -> Result<(), PlatformError> {
        validate_version(self.version)?;
        validate_nonce(&self.nonce)?;
        validate_kind(&self.kind)?;
        if !self.payload.is_object() {
            return Err(rejected("payload must be a JSON object"));
        }
        self.binding.validate()
    }
}

fn validate_version(version: u16) -> Result<(), PlatformError> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(rejected("unsupported protocol version"))
    }
}
fn validate_nonce(nonce: &str) -> Result<(), PlatformError> {
    if valid_nonce(nonce) {
        Ok(())
    } else {
        Err(rejected("nonce is not bounded hexadecimal"))
    }
}
fn validate_kind(kind: &str) -> Result<(), PlatformError> {
    if !kind.is_empty()
        && kind.len() <= MAX_KIND_BYTES
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(rejected("operation kind is invalid"))
    }
}
fn rejected(message: &str) -> PlatformError {
    PlatformError::ProtocolRejected(message.into())
}
