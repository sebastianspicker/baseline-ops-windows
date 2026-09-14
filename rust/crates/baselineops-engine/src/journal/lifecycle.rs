use std::collections::BTreeSet;

use super::{ActionStatus, JournalError, JournalEvent, JournalSnapshot};

#[derive(Default)]
pub(super) struct Lifecycle {
    approved: bool,
    finished: bool,
    stopped: bool,
    active: Option<String>,
    completed: BTreeSet<String>,
}

impl Lifecycle {
    pub(super) fn from_snapshot(snapshot: &JournalSnapshot) -> Result<Self, JournalError> {
        let mut state = Self::default();
        for record in &snapshot.records {
            state.validate(&record.payload)?;
            state.accept(&record.payload);
        }
        Ok(state)
    }

    pub(super) fn require_resumable(&self) -> Result<(), JournalError> {
        if let Some(action) = &self.active {
            return Err(JournalError::ActionRecoveryRequired(action.clone()));
        }
        Ok(())
    }

    pub(super) fn validate_recovery(&self, trailing_bytes: u64) -> Result<(), JournalError> {
        if self.finished && trailing_bytes != 0 {
            return Err(invalid("bytes cannot follow run completion"));
        }
        self.require_resumable()
    }

    pub(super) fn validate(&self, event: &JournalEvent) -> Result<(), JournalError> {
        if self.finished {
            return Err(invalid("events cannot follow run completion"));
        }
        match event {
            JournalEvent::PlanApproved { .. } => self.validate_approval(),
            JournalEvent::ActionStarted { action_id, .. } => self.validate_start(action_id),
            JournalEvent::ActionFinished { action_id, .. } => self.validate_finish(action_id),
            JournalEvent::RunFinished { .. } => self.validate_run_finish(),
        }
    }

    fn validate_approval(&self) -> Result<(), JournalError> {
        if self.approved {
            return Err(invalid("approval must occur exactly once"));
        }
        Ok(())
    }

    fn validate_start(&self, action_id: &str) -> Result<(), JournalError> {
        if !self.approved || self.active.is_some() || self.stopped {
            return Err(invalid(
                "action start requires approval, no active action, and no failure",
            ));
        }
        if action_id.is_empty() || self.completed.contains(action_id) {
            return Err(invalid("action identity is empty or already completed"));
        }
        Ok(())
    }

    fn validate_finish(&self, action_id: &str) -> Result<(), JournalError> {
        if self.active.as_deref() != Some(action_id) {
            return Err(invalid(
                "action completion does not match the active action",
            ));
        }
        Ok(())
    }

    fn validate_run_finish(&self) -> Result<(), JournalError> {
        if !self.approved || self.active.is_some() {
            return Err(invalid(
                "run completion requires approval and no active action",
            ));
        }
        Ok(())
    }

    pub(super) fn accept(&mut self, event: &JournalEvent) {
        match event {
            JournalEvent::PlanApproved { .. } => self.approved = true,
            JournalEvent::ActionStarted { action_id, .. } => {
                self.active = Some(action_id.clone());
            }
            JournalEvent::ActionFinished {
                action_id, status, ..
            } => {
                self.stopped = *status != ActionStatus::Succeeded;
                self.completed.insert(action_id.clone());
                self.active = None;
            }
            JournalEvent::RunFinished { .. } => self.finished = true,
        }
    }
}

const fn invalid(reason: &'static str) -> JournalError {
    JournalError::InvalidLifecycle(reason)
}
