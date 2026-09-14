//! Finite post-approval messages; none carry executable intent.

use super::{BrokerBinding, BrokerMessage, PROTOCOL_VERSION, ReplayNonceCache};
use crate::PlatformError;
use baselineops_domain::ActionId;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Last durable stage reported by the native executor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressPhase {
    /// The worker is revalidating approval and preparing protected output.
    Preparing,
    /// The action start is durable; cancellation waits for the next action boundary.
    ActionStarted,
    /// A terminal action receipt is durable.
    ActionFinished,
    /// Cancellation was accepted; an action already in progress may still finish.
    CancellationPending,
}

/// Bounded progress evidence without registry values, paths, or authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerProgress {
    /// Finite lifecycle stage.
    pub phase: ProgressPhase,
    /// Exact proposed action for action stages; absent for run stages.
    pub action_id: Option<ActionId>,
}

impl WorkerProgress {
    /// Validate stage/action consistency.
    ///
    /// # Errors
    /// Rejects absent action identifiers on action stages or identifiers on run stages.
    pub fn validate(&self) -> Result<(), PlatformError> {
        let action_stage = matches!(
            self.phase,
            ProgressPhase::ActionStarted | ProgressPhase::ActionFinished
        );
        if action_stage != self.action_id.is_some() {
            return Err(rejected("progress stage and action identifier disagree"));
        }
        Ok(())
    }
}

/// Immutable binding and bounded replay state for one authenticated approval exchange.
/// Authentication of the OS peer is a transport prerequisite, not established by this type.
pub struct ApprovalControl {
    binding: BrokerBinding,
    seen: ReplayNonceCache,
    deadline: Instant,
    received: usize,
    cancellation_seen: bool,
    terminal_seen: bool,
}

impl ApprovalControl {
    /// Retain the authenticated approval envelope and a two-minute control-message lifetime.
    ///
    /// # Errors
    /// Rejects invalid envelopes or a message other than `plan.approve`.
    pub fn new(approval: &BrokerMessage, now: Instant) -> Result<Self, PlatformError> {
        approval.validate()?;
        if approval.kind != "plan.approve" {
            return Err(rejected(
                "control session requires an authenticated approval",
            ));
        }
        let mut binding = approval.binding.clone();
        binding.reply_to = Some(approval.nonce.clone());
        let mut seen = ReplayNonceCache::new(Duration::from_mins(2), 128)?;
        seen.accept(&approval.nonce, now)?;
        Ok(Self {
            binding,
            seen,
            deadline: now + Duration::from_mins(2),
            received: 0,
            cancellation_seen: false,
            terminal_seen: false,
        })
    }

    /// Form an empty cancellation request bound to the exact approval.
    ///
    /// # Errors
    /// Rejects invalid caller-generated nonces.
    pub fn cancellation(&self, nonce: String) -> Result<BrokerMessage, PlatformError> {
        self.message("plan.cancel", serde_json::json!({}), nonce)
    }

    /// Form validated finite progress bound to the approval.
    ///
    /// # Errors
    /// Rejects malformed progress or nonces.
    pub fn progress(
        &self,
        progress: WorkerProgress,
        nonce: String,
    ) -> Result<BrokerMessage, PlatformError> {
        progress.validate()?;
        let payload =
            serde_json::to_value(progress).map_err(|error| rejected(&error.to_string()))?;
        self.message("plan.progress", payload, nonce)
    }

    /// Accept one empty, bound, unreplayed cancellation message.
    ///
    /// # Errors
    /// Rejects unexpected payloads, wrong bindings, replays, expiry, or a second cancellation.
    pub fn accept_cancellation(
        &mut self,
        message: &BrokerMessage,
        now: Instant,
    ) -> Result<(), PlatformError> {
        self.accept_envelope(message, now)?;
        if message.kind != "plan.cancel"
            || message.payload != serde_json::json!({})
            || self.cancellation_seen
        {
            return Err(rejected(
                "worker accepts exactly one empty cancellation request",
            ));
        }
        self.cancellation_seen = true;
        Ok(())
    }

    /// Accept a bound progress or final result envelope; progress never replaces the final result.
    ///
    /// # Errors
    /// Rejects unexpected kinds, payloads, bindings, replay, expiry, or excess messages.
    pub fn accept_worker_message(
        &mut self,
        message: &BrokerMessage,
        now: Instant,
    ) -> Result<Option<WorkerProgress>, PlatformError> {
        self.accept_envelope(message, now)?;
        match message.kind.as_str() {
            "plan.progress" => {
                let progress: WorkerProgress = serde_json::from_value(message.payload.clone())
                    .map_err(|error| rejected(&error.to_string()))?;
                progress.validate()?;
                Ok(Some(progress))
            }
            "plan.result" => {
                self.terminal_seen = true;
                Ok(None)
            }
            _ => Err(rejected("expected worker progress or terminal result")),
        }
    }

    fn accept_envelope(
        &mut self,
        message: &BrokerMessage,
        now: Instant,
    ) -> Result<(), PlatformError> {
        message.validate()?;
        message.binding.require_reply_to(
            &self.binding.session_id,
            &self.binding.plan_id,
            &self.binding.plan_digest,
            self.binding.reply_to.as_deref().expect("approval nonce"),
        )?;
        if self.terminal_seen || now >= self.deadline || self.received >= 127 {
            return Err(rejected(
                "control session expired or exceeded its message quota",
            ));
        }
        self.seen.accept(&message.nonce, now)?;
        self.received += 1;
        Ok(())
    }

    fn message(
        &self,
        kind: &str,
        payload: serde_json::Value,
        nonce: String,
    ) -> Result<BrokerMessage, PlatformError> {
        let message = BrokerMessage {
            version: PROTOCOL_VERSION,
            binding: self.binding.clone(),
            nonce,
            kind: kind.into(),
            payload,
        };
        message.validate()?;
        Ok(message)
    }
}

fn rejected(reason: &str) -> PlatformError {
    PlatformError::ProtocolRejected(reason.into())
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
