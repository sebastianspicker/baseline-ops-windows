//! Result assembly bound exclusively to the retained worker proposal.

use anyhow::{Result, bail};
use baselineops_domain::{
    ExitCode, PlanId, ResultStatus, RunId, SchemaVersion, Sha256Digest, WorkerResultV3,
};
use baselineops_windows::{BrokerBinding, BrokerMessage, PROTOCOL_VERSION};

#[derive(Clone, Copy)]
pub(super) struct ResultBinding {
    plan_id: PlanId,
    run_id: RunId,
    digest: Sha256Digest,
}

impl ResultBinding {
    pub(super) const fn new(plan_id: PlanId, run_id: RunId, digest: Sha256Digest) -> Self {
        Self {
            plan_id,
            run_id,
            digest,
        }
    }

    pub(super) fn failure(self, status: ResultStatus, reason: &str) -> Result<WorkerResultV3> {
        let result = WorkerResultV3 {
            schema_version: SchemaVersion::V3,
            plan_id: self.plan_id,
            run_id: self.run_id,
            plan_digest: self.digest,
            journal_terminal_hash: None,
            receipts: Vec::new(),
            artifact_manifest: Vec::new(),
            final_status: status,
            reason: Some(reason.chars().take(768).collect()),
            exit_code: ExitCode::for_status(status).as_i32(),
        };
        result.validate()?;
        Ok(result)
    }

    pub(super) fn after_revalidation<T>(
        self,
        reload: impl FnOnce() -> Result<T>,
        execute: impl FnOnce(T) -> Result<WorkerResultV3>,
    ) -> Result<WorkerResultV3> {
        match reload() {
            Ok(live) => execute(live),
            Err(error) => self.failure(
                ResultStatus::Rejected,
                &format!("Live approval revalidation failed: {error}"),
            ),
        }
    }
}

pub(super) fn result_message(
    proposal: &BrokerMessage,
    approval_nonce: String,
    result: WorkerResultV3,
) -> Result<BrokerMessage> {
    result.validate()?;
    if proposal.binding.plan_id != result.plan_id.to_string()
        || proposal.binding.plan_digest != result.plan_digest.to_hex()
    {
        bail!("result does not match the retained worker proposal");
    }
    let reply = BrokerMessage {
        version: PROTOCOL_VERSION,
        binding: BrokerBinding {
            session_id: proposal.binding.session_id.clone(),
            plan_id: proposal.binding.plan_id.clone(),
            plan_digest: proposal.binding.plan_digest.clone(),
            reply_to: Some(approval_nonce),
        },
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        kind: "plan.result".into(),
        payload: serde_json::to_value(result)?,
    };
    reply.validate()?;
    Ok(reply)
}

#[cfg(test)]
#[path = "responses_tests.rs"]
mod tests;
