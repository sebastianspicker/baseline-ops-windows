use super::*;

fn fixture() -> (ResultBinding, BrokerMessage) {
    let binding = ResultBinding::new(
        PlanId::new(),
        RunId::new(),
        Sha256Digest::of_bytes(b"worker proposal"),
    );
    let proposal = BrokerMessage {
        version: PROTOCOL_VERSION,
        binding: BrokerBinding {
            session_id: "11".repeat(16),
            plan_id: binding.plan_id.to_string(),
            plan_digest: binding.digest.to_hex(),
            reply_to: Some("22".repeat(16)),
        },
        nonce: "33".repeat(16),
        kind: "plan.proposal".into(),
        payload: serde_json::json!({}),
    };
    (binding, proposal)
}

#[test]
fn second_reload_failure_returns_bound_reply_without_execution() {
    let (binding, proposal) = fixture();
    let result = binding
        .after_revalidation(
            || -> Result<()> { bail!("installed package changed after proposal") },
            |()| panic!("rejected revalidation must not reach approval or dispatch"),
        )
        .unwrap();
    assert_eq!(result.run_id, binding.run_id);
    assert_eq!(result.final_status, ResultStatus::Rejected);
    assert_eq!(result.exit_code, ExitCode::Rejected.as_i32());
    let approval_nonce = "44".repeat(16);
    let reply = result_message(&proposal, approval_nonce.clone(), result).unwrap();
    reply
        .binding
        .require_reply_to(
            &proposal.binding.session_id,
            &binding.plan_id.to_string(),
            &binding.digest.to_hex(),
            &approval_nonce,
        )
        .unwrap();
    let decoded: WorkerResultV3 = serde_json::from_value(reply.payload).unwrap();
    assert_eq!(decoded.plan_digest, binding.digest);
    assert_eq!(decoded.plan_id, binding.plan_id);
    assert_eq!(decoded.run_id, binding.run_id);
}

#[test]
fn mismatched_approval_payload_cannot_replace_result_digest() {
    let (binding, proposal) = fixture();
    let untrusted_digest = Sha256Digest::of_bytes(b"different approved payload");
    let result = binding
        .after_revalidation(
            || Ok(untrusted_digest),
            |submitted| {
                assert_ne!(submitted, binding.digest);
                binding.failure(
                    ResultStatus::Rejected,
                    "approved digest differs from worker proposal",
                )
            },
        )
        .unwrap();
    assert_eq!(result.plan_digest, binding.digest);
    let mut tampered = result.clone();
    tampered.plan_digest = untrusted_digest;
    assert!(result_message(&proposal, "44".repeat(16), tampered).is_err());
    assert!(result_message(&proposal, "44".repeat(16), result).is_ok());
}

#[test]
fn failure_details_remain_bounded_for_multibyte_input() {
    let (binding, _) = fixture();
    let result = binding
        .failure(ResultStatus::ExecutionFailed, &"🦀".repeat(4096))
        .unwrap();
    assert_eq!(result.reason.unwrap().len(), 768 * 4);
}
