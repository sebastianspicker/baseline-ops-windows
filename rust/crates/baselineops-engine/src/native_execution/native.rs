use super::{
    NativeActionPhase, NativeActionProgress, NativeExecutionError, action::ActionPort,
    bounded_detail,
};
use crate::{Journal, JournalEvent, VerifiedPlan};
use baselineops_capabilities::{PolicyValueSnapshot, WindowsUpdateField, WindowsUpdateObservation};
use baselineops_domain::{
    ActionId, ArtifactId, ArtifactKind, ArtifactV3, ExitCode, JsonMap, PlanId, ResultId,
    ResultStatus, Sha256Digest, WorkerResultV3, canonical_json_bytes,
};
use baselineops_windows::{ProtectedRunArtifactKind, ProtectedRunDirectory};
use chrono::{DateTime, Utc};
use serde::Serialize;

mod finalization;

use finalization::{FinalizationPort, append_run_finished, finalize_result};

pub(super) struct NativeActionPort {
    run: ProtectedRunDirectory,
    journal: Journal,
    plan_id: PlanId,
    plan_digest: Sha256Digest,
    expires_at: DateTime<Utc>,
    action_started: bool,
    action_id: ActionId,
    progress: Option<std::sync::mpsc::SyncSender<NativeActionProgress>>,
    artifacts: Vec<ArtifactV3>,
}

impl NativeActionPort {
    pub(super) fn create(
        verified: &VerifiedPlan,
        progress: Option<std::sync::mpsc::SyncSender<NativeActionProgress>>,
    ) -> Result<Self, NativeExecutionError> {
        let mut run = baselineops_windows::create_protected_run_directory()?;
        let mut journal = Journal::create_protected(&mut run)?;
        journal.append(
            Utc::now(),
            JournalEvent::PlanApproved {
                plan_id: verified.plan().id,
                plan_digest: verified.digest(),
            },
        )?;
        Ok(Self {
            run,
            journal,
            plan_id: verified.plan().id,
            plan_digest: verified.digest(),
            expires_at: verified.plan().expires_at,
            action_started: false,
            action_id: verified.plan().actions[0].id,
            progress,
            artifacts: Vec::new(),
        })
    }

    pub(super) fn finish(
        mut self,
        mut result: WorkerResultV3,
        may_finish_run: bool,
        reboot_possible: bool,
    ) -> Result<WorkerResultV3, NativeExecutionError> {
        if may_finish_run && let Err(error) = self.finalize_document(&result, reboot_possible) {
            result.final_status = ResultStatus::ExecutionFailed;
            result.exit_code = ExitCode::ExecutionFailure.as_i32();
            result.reason = Some(format!(
                "Result finalization failed: {}. Preserve the run for manual recovery; no further action was attempted.",
                bounded_detail(&error.to_string())
            ));
        }
        result.artifact_manifest = self.artifacts;
        result.journal_terminal_hash = Some(self.journal.terminal_hash());
        result.validate()?;
        Ok(result)
    }

    fn finalize_document(
        &mut self,
        result: &WorkerResultV3,
        reboot_possible: bool,
    ) -> Result<(), NativeExecutionError> {
        let result_id = ResultId::new();
        // The document binds the confirmed prefix, not its own future RunFinished hash.
        // Its artifact reference is added to the broker result after the document is written.
        let document = crate::committed_result::ResultDocument {
            schema_version: "1.0".into(),
            result_id,
            plan_id: result.plan_id,
            run_id: result.run_id,
            plan_digest: result.plan_digest,
            journal_prefix_hash: self.journal.terminal_hash(),
            receipts: result.receipts.clone(),
            status: result.final_status,
            reason: result.reason.clone(),
            reboot_possible,
            artifacts: self.artifacts.clone(),
        };
        let bytes = canonical_json_bytes(&document)?;
        let artifact = finalize_result(self, result_id, &bytes)?;
        self.artifacts.push(artifact);
        Ok(())
    }

    fn retain_artifact(
        &mut self,
        kind: ProtectedRunArtifactKind,
        artifact_kind: ArtifactKind,
        bytes: &[u8],
    ) -> Result<(), NativeExecutionError> {
        let artifact = self.write_artifact(kind, artifact_kind, bytes)?;
        self.artifacts.push(artifact);
        Ok(())
    }

    fn write_artifact(
        &mut self,
        kind: ProtectedRunArtifactKind,
        artifact_kind: ArtifactKind,
        bytes: &[u8],
    ) -> Result<ArtifactV3, NativeExecutionError> {
        let path = self.run.write_artifact(kind, bytes)?;
        let name = path.file_name().and_then(|value| value.to_str()).ok_or(
            NativeExecutionError::Rejected("protected artifact has no finite filename"),
        )?;
        Ok(ArtifactV3 {
            id: ArtifactId::new(),
            kind: artifact_kind,
            media_type: "application/json".into(),
            locator: format!("{}/{name}", self.run.run_id()),
            digest: Sha256Digest::of_bytes(bytes),
            size_bytes: bytes.len() as u64,
            created_at: Utc::now(),
            metadata: JsonMap::new(),
        })
    }

    fn require_fresh(&self) -> Result<(), String> {
        if Utc::now() >= self.expires_at {
            return Err("approval expired before the next native boundary".into());
        }
        Ok(())
    }
}

impl ActionPort for NativeActionPort {
    fn observe(&mut self) -> Result<WindowsUpdateObservation, String> {
        if !self.action_started {
            self.require_fresh()?;
        }
        baselineops_windows::observe_windows_update_policy().map_err(|error| error.to_string())
    }

    fn persist_recovery(
        &mut self,
        action_id: ActionId,
        pre: &WindowsUpdateObservation,
        expected_post: &WindowsUpdateObservation,
    ) -> Result<(), String> {
        #[derive(Serialize)]
        struct Recovery<'a> {
            schema_version: &'static str,
            plan_id: PlanId,
            plan_digest: Sha256Digest,
            action_id: ActionId,
            before: &'a WindowsUpdateObservation,
            expected_after: &'a WindowsUpdateObservation,
            #[serde(rename = "recovery")]
            instructions: &'static str,
        }
        let recovery = Recovery {
            schema_version: "1.0",
            plan_id: self.plan_id,
            plan_digest: self.plan_digest,
            action_id,
            before: pre,
            expected_after: expected_post,
            instructions: "manual: independently inspect current policy before restoring captured values; this document grants no execution authority",
        };
        let bytes = canonical_json_bytes(&recovery).map_err(|error| error.to_string())?;
        self.retain_artifact(
            ProtectedRunArtifactKind::RecoverySnapshot,
            ArtifactKind::RollbackState,
            &bytes,
        )
        .map_err(|error| error.to_string())
    }

    fn append(&mut self, event: JournalEvent) -> Result<(), String> {
        let phase = match &event {
            JournalEvent::ActionStarted { .. } => Some(NativeActionPhase::Started),
            JournalEvent::ActionFinished { .. } => Some(NativeActionPhase::Finished),
            _ => None,
        };
        self.journal
            .append(Utc::now(), event)
            .map_err(|error| error.to_string())?;
        self.action_started |= phase == Some(NativeActionPhase::Started);
        if let (Some(sender), Some(phase)) = (&self.progress, phase) {
            let _ = sender.try_send(NativeActionProgress {
                action_id: self.action_id,
                phase,
            });
        }
        Ok(())
    }

    fn mutate(
        &mut self,
        field: WindowsUpdateField,
        expected: &PolicyValueSnapshot,
        desired: &PolicyValueSnapshot,
    ) -> Result<PolicyValueSnapshot, String> {
        self.require_fresh()?;
        baselineops_windows::apply_windows_update_mutation(field, expected, desired)
            .map_err(|error| error.to_string())
    }
}

impl FinalizationPort for NativeActionPort {
    fn write_pending_result(&mut self, bytes: &[u8]) -> Result<ArtifactV3, NativeExecutionError> {
        self.write_artifact(
            ProtectedRunArtifactKind::Result,
            ArtifactKind::Report,
            bytes,
        )
    }

    fn commit_result(
        &mut self,
        result_id: ResultId,
        digest: Sha256Digest,
    ) -> Result<(), NativeExecutionError> {
        append_run_finished(&mut self.journal, result_id, digest)
    }
}
