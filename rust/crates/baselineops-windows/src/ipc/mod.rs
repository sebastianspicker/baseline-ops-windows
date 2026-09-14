//! Bounded, versioned framing for the local elevated-worker broker.
//!
//! The types in this module are transport-neutral so framing, binding, and
//! replay handling remain portable and independently testable.

mod binding;
mod control;
mod frame;
mod message;
mod replay;
#[cfg(all(test, not(windows)))]
#[path = "windows/transfer.rs"]
mod transfer_tests;
#[cfg(windows)]
mod validation;

#[cfg(windows)]
mod auth;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use auth::{ProcessTokenIdentity, inspect_process};
pub use binding::BrokerBinding;
pub use control::{ApprovalControl, ProgressPhase, WorkerProgress};
pub use frame::{BrokerFrame, FrameCodec};
pub use message::BrokerMessage;
pub use replay::ReplayNonceCache;
#[cfg(windows)]
pub use windows::{NamedPipeClient, NamedPipeServer, PipePeerVerifier};

/// Largest allowed encoded broker frame, excluding its four-byte length field.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Only protocol revision understood by this boundary slice.
pub const PROTOCOL_VERSION: u16 = 2;
pub(crate) const MAX_NONCE_BYTES: usize = 96;
pub(crate) const MAX_KIND_BYTES: usize = 64;
pub(crate) const MAX_SESSION_BYTES: usize = 64;
pub(crate) const MAX_PLAN_ID_BYTES: usize = 128;
pub(crate) const SHA256_HEX_BYTES: usize = 64;

/// Authenticated peer facts supplied by the Windows named-pipe adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    /// OS-assigned client process identifier.
    pub process_id: u32,
    /// Logon session ID bound to the interactive caller.
    pub session_id: u32,
    /// Canonical caller SID string.
    pub user_sid: String,
    /// Token integrity RID; lower values are rejected by a policy hook.
    pub integrity_rid: u32,
    /// Canonical image path resolved from an opened process handle.
    pub image_path: String,
}

pub(crate) fn valid_nonce(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NONCE_BYTES
        && value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PlatformError;
    use std::time::{Duration, Instant};

    fn message() -> BrokerMessage {
        BrokerMessage {
            version: PROTOCOL_VERSION,
            binding: BrokerBinding {
                session_id: "a1b2".into(),
                plan_id: "plan-1".into(),
                plan_digest: "ab".repeat(32),
                reply_to: None,
            },
            nonce: "a1b2".into(),
            kind: "plan.apply".into(),
            payload: serde_json::json!({"id": "x"}),
        }
    }

    #[test]
    fn frame_round_trip_is_exact() {
        let frame = FrameCodec::encode(&message()).expect("encode");
        assert_eq!(
            FrameCodec::decode::<BrokerMessage>(&frame.0).expect("decode"),
            message()
        );
    }

    #[test]
    fn malformed_lengths_and_unknown_fields_fail_closed() {
        assert!(FrameCodec::decode::<BrokerMessage>(&[0, 0, 0, 3, b'{', b'}']).is_err());
        let frame = FrameCodec::encode(&serde_json::json!({"version":1,"binding":{"sessionId":"a1","planId":"p","planDigest":"abababababababababababababababababababababababababababababababab","replyTo":null},"nonce":"a1","kind":"x","payload":{},"extra":true})).expect("frame");
        assert!(FrameCodec::decode::<BrokerMessage>(&frame.0).is_err());
    }

    #[test]
    fn envelope_and_replay_bounds_are_enforced() {
        let mut invalid = message();
        invalid.nonce = "not hex".into();
        assert!(invalid.validate().is_err());
        let now = Instant::now();
        let mut cache = ReplayNonceCache::new(Duration::from_secs(1), 1).expect("cache");
        cache.accept("a1", now).expect("first use");
        assert!(matches!(
            cache.accept("a1", now),
            Err(PlatformError::ReplayDetected)
        ));
        cache.accept("b2", now).expect("capacity evicts old value");
        cache.accept("a1", now).expect("evicted nonce is accepted");
    }

    #[test]
    fn reply_binding_cannot_cross_sessions_plans_or_nonces() {
        let request = message();
        let mut reply = message();
        reply.binding.reply_to = Some(request.nonce.clone());
        reply.binding.plan_digest = "cd".repeat(32);
        assert!(
            reply
                .binding
                .require_reply_to("a1b2", "plan-1", &"cd".repeat(32), &request.nonce)
                .is_ok()
        );
        reply.binding.reply_to = Some("ffff".into());
        assert!(
            reply
                .binding
                .require_reply_to("a1b2", "plan-1", &"cd".repeat(32), &request.nonce)
                .is_err()
        );
    }
}
