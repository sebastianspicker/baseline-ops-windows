use super::*;

fn approval() -> BrokerMessage {
    BrokerMessage {
        version: PROTOCOL_VERSION,
        binding: BrokerBinding {
            session_id: "11".repeat(16),
            plan_id: "plan".into(),
            plan_digest: "22".repeat(32),
            reply_to: Some("33".repeat(16)),
        },
        nonce: "44".repeat(16),
        kind: "plan.approve".into(),
        payload: serde_json::json!({"approvedDigest":"22".repeat(32)}),
    }
}

#[test]
fn only_empty_exactly_bound_cancellation_can_signal_once() {
    let now = Instant::now();
    for field in ["session", "digest", "reply", "kind", "payload", "nonce"] {
        let mut session = ApprovalControl::new(&approval(), now).unwrap();
        let mut message = session.cancellation("55".repeat(16)).unwrap();
        match field {
            "session" => message.binding.session_id = "66".repeat(16),
            "digest" => message.binding.plan_digest = "66".repeat(32),
            "reply" => message.binding.reply_to = Some("66".repeat(16)),
            "kind" => message.kind = "plan.approve".into(),
            "payload" => message.payload = serde_json::json!({"command":"anything"}),
            "nonce" => message.nonce = approval().nonce,
            _ => unreachable!(),
        }
        assert!(
            session.accept_cancellation(&message, now).is_err(),
            "{field}"
        );
        assert!(!session.cancellation_seen);
    }
    let mut session = ApprovalControl::new(&approval(), now).unwrap();
    let message = session.cancellation("55".repeat(16)).unwrap();
    session.accept_cancellation(&message, now).unwrap();
    assert!(session.accept_cancellation(&message, now).is_err());
    let second = session.cancellation("66".repeat(16)).unwrap();
    assert!(session.accept_cancellation(&second, now).is_err());
}

#[test]
fn progress_is_finite_and_cannot_substitute_for_terminal_result() {
    let now = Instant::now();
    let mut session = ApprovalControl::new(&approval(), now).unwrap();
    let progress = WorkerProgress {
        phase: ProgressPhase::Preparing,
        action_id: None,
    };
    let message = session.progress(progress.clone(), "55".repeat(16)).unwrap();
    assert_eq!(
        session.accept_worker_message(&message, now).unwrap(),
        Some(progress)
    );
    assert!(session.accept_worker_message(&message, now).is_err());
    let terminal = session
        .message("plan.result", serde_json::json!({}), "66".repeat(16))
        .unwrap();
    assert!(
        session
            .accept_worker_message(&terminal, now)
            .unwrap()
            .is_none()
    );
    assert!(session.accept_worker_message(&terminal, now).is_err());
}

#[test]
fn malformed_progress_and_expired_session_fail_closed() {
    let now = Instant::now();
    let mut session = ApprovalControl::new(&approval(), now).unwrap();
    for phase in [ProgressPhase::ActionStarted, ProgressPhase::ActionFinished] {
        assert!(
            session
                .progress(
                    WorkerProgress {
                        phase,
                        action_id: None
                    },
                    "55".repeat(16)
                )
                .is_err()
        );
    }
    let mut message = session
        .progress(
            WorkerProgress {
                phase: ProgressPhase::Preparing,
                action_id: None,
            },
            "55".repeat(16),
        )
        .unwrap();
    message.payload["extra"] = serde_json::json!(true);
    assert!(session.accept_worker_message(&message, now).is_err());
    let cancel = session.cancellation("66".repeat(16)).unwrap();
    assert!(
        session
            .accept_cancellation(&cancel, now + Duration::from_mins(2))
            .is_err()
    );
}

#[test]
fn quota_prevents_nonce_eviction_from_reopening_replay_window() {
    let now = Instant::now();
    let mut session = ApprovalControl::new(&approval(), now).unwrap();
    for index in 0..127 {
        let message = session
            .progress(
                WorkerProgress {
                    phase: ProgressPhase::Preparing,
                    action_id: None,
                },
                format!("{index:032x}"),
            )
            .unwrap();
        session.accept_worker_message(&message, now).unwrap();
    }
    let message = session
        .progress(
            WorkerProgress {
                phase: ProgressPhase::Preparing,
                action_id: None,
            },
            "ff".repeat(16),
        )
        .unwrap();
    assert!(session.accept_worker_message(&message, now).is_err());
}
