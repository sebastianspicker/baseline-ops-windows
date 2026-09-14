use super::{MAX_PLAN_ID_BYTES, MAX_SESSION_BYTES, SHA256_HEX_BYTES, valid_hex, valid_nonce};
use crate::PlatformError;
use serde::{Deserialize, Serialize};

/// Values that bind every broker message to one reviewed plan exchange.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerBinding {
    /// Session token passed directly from the CLI to the elevated worker.
    pub session_id: String,
    /// Stable identifier of the reviewed plan.
    pub plan_id: String,
    /// Canonical SHA-256 digest of the exact plan relevant to this message.
    pub plan_digest: String,
    /// Nonce of the message to which this message is replying, if any.
    pub reply_to: Option<String>,
}

impl BrokerBinding {
    /// Validate the stable exchange binding independently of the payload schema.
    ///
    /// # Errors
    ///
    /// Returns an error when a binding component is malformed.
    pub fn validate(&self) -> Result<(), PlatformError> {
        validate_session_id(&self.session_id)?;
        validate_plan_id(&self.plan_id)?;
        if !valid_hex(&self.plan_digest, SHA256_HEX_BYTES) {
            return Err(rejected("plan digest is not SHA-256 hex"));
        }
        if self
            .reply_to
            .as_deref()
            .is_some_and(|nonce| !valid_nonce(nonce))
        {
            return Err(rejected("reply nonce is invalid"));
        }
        Ok(())
    }

    /// Reject a reply that is not tied to the expected exchange state.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, exchange comparison, or reply nonce binding fails.
    pub fn require_reply_to(
        &self,
        session_id: &str,
        plan_id: &str,
        plan_digest: &str,
        request_nonce: &str,
    ) -> Result<(), PlatformError> {
        self.validate()?;
        if !self.matches_active_exchange(session_id, plan_id, plan_digest)
            || self.reply_to.as_deref() != Some(request_nonce)
        {
            return Err(rejected("reply binding does not match the active exchange"));
        }
        Ok(())
    }

    /// Reject an initiating request that is not bound to the expected plan/session.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, exchange comparison, or reply absence checks fail.
    pub fn require_request(
        &self,
        session_id: &str,
        plan_id: &str,
        plan_digest: &str,
    ) -> Result<(), PlatformError> {
        self.validate()?;
        if !self.matches_active_exchange(session_id, plan_id, plan_digest)
            || self.reply_to.is_some()
        {
            return Err(rejected(
                "request binding does not match the active exchange",
            ));
        }
        Ok(())
    }

    fn matches_active_exchange(&self, session_id: &str, plan_id: &str, plan_digest: &str) -> bool {
        self.session_id == session_id && self.plan_id == plan_id && self.plan_digest == plan_digest
    }
}

fn validate_session_id(value: &str) -> Result<(), PlatformError> {
    if value.is_empty()
        || value.len() > MAX_SESSION_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(rejected("session identifier is invalid"));
    }
    Ok(())
}

fn validate_plan_id(value: &str) -> Result<(), PlatformError> {
    if value.is_empty()
        || value.len() > MAX_PLAN_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(rejected("plan identifier is invalid"));
    }
    Ok(())
}

fn rejected(message: &str) -> PlatformError {
    PlatformError::ProtocolRejected(message.into())
}
