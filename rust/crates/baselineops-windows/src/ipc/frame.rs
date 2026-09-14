use super::MAX_FRAME_BYTES;
use crate::PlatformError;
use serde::{Serialize, de::DeserializeOwned};

/// Exact wire bytes for a broker frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerFrame(pub Vec<u8>);

/// Four-byte big-endian length framing with explicit JSON limits.
pub struct FrameCodec;

impl FrameCodec {
    /// Encode one serializable value as a bounded length-prefixed frame.
    ///
    /// # Errors
    ///
    /// Returns an error for serialization or frame-size failure.
    pub fn encode<T: Serialize>(value: &T) -> Result<BrokerFrame, PlatformError> {
        let body = serde_json::to_vec(value).map_err(|error| rejected("encode", &error))?;
        if body.len() > MAX_FRAME_BYTES {
            return Err(PlatformError::ProtocolRejected(
                "frame exceeds maximum size".into(),
            ));
        }
        let length = u32::try_from(body.len())
            .map_err(|_| PlatformError::ProtocolRejected("frame length overflow".into()))?;
        let mut frame = Vec::with_capacity(body.len().saturating_add(4));
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&body);
        Ok(BrokerFrame(frame))
    }

    /// Decode exactly one length-prefixed frame and reject trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed framing or JSON input.
    pub fn decode<T: DeserializeOwned>(frame: &[u8]) -> Result<T, PlatformError> {
        serde_json::from_slice(bounded_body(frame)?).map_err(|error| rejected("decode", &error))
    }
}

fn bounded_body(frame: &[u8]) -> Result<&[u8], PlatformError> {
    let prefix = frame.get(..4).ok_or_else(|| {
        PlatformError::ProtocolRejected("frame is missing a length prefix".into())
    })?;
    let length: [u8; 4] = prefix
        .try_into()
        .map_err(|_| PlatformError::ProtocolRejected("frame prefix is invalid".into()))?;
    let expected = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| PlatformError::ProtocolRejected("frame length is invalid".into()))?;
    if expected > MAX_FRAME_BYTES || frame.len() != expected.saturating_add(4) {
        return Err(PlatformError::ProtocolRejected(
            "frame length does not match bytes".into(),
        ));
    }
    Ok(&frame[4..])
}

fn rejected(operation: &str, error: &serde_json::Error) -> PlatformError {
    PlatformError::ProtocolRejected(format!("JSON {operation} failed: {error}"))
}
