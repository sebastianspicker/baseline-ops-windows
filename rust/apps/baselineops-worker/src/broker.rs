mod session;
use super::responses::ResultBinding;
use super::{Arguments, ProposalRequest, parse_approval_request, parse_proposal_request, trust};
use anyhow::{Result, anyhow, bail};
use baselineops_domain::{
    ExecutionIntent, ExitCode, InputIdentityV3, JsonLoadLimits, PlanValidationContext, ProfileV3,
    ResultStatus, Sha256Digest, SourceIdentityV3, SourceKind, ToolIdentityV3, WorkerResultV3,
    load_profile_json,
};
use baselineops_engine::{
    NativeObservationSource, PlanBuildContext, WorkerApplyAuthority, prepare_worker_apply,
    reobserve_profile,
};
use baselineops_windows::ipc::{NamedPipeClient, NamedPipeServer};
use baselineops_windows::{
    BrokerBinding, BrokerMessage, FrameCodec, PROTOCOL_VERSION, ReplayNonceCache,
    TrustedInstallation,
};
use session::{execute_session, send_result};
use std::time::{Duration, Instant};
use uuid::Uuid;

pub(super) fn run_windows(
    arguments: &Arguments,
    trust: &TrustedInstallation,
    signer: &trust::ReleaseSignerIdentity,
) -> Result<ExitCode> {
    let pipe_name = arguments.session.as_simple().to_string();
    let (mut client, mut replays) = accept_client(arguments, trust, signer, &pipe_name)?;
    let (request, request_message) =
        receive_proposal_request(&mut client, &mut replays, &pipe_name)?;
    let prepared = prepare_proposal(&request, trust, signer, &pipe_name, &request_message)?;
    let approval = exchange_proposal(&mut client, &mut replays, &pipe_name, &prepared.message)?;
    let deadline = Instant::now() + Duration::from_mins(2);
    let result = execute_session(
        &mut client,
        prepared.authority,
        &request,
        &approval,
        trust,
        signer,
        deadline,
    )?;
    let exit_code = ExitCode::for_status(result.final_status);
    send_result(
        &mut client,
        &prepared.message,
        approval.nonce,
        result,
        deadline,
    )?;
    Ok(exit_code)
}

fn exchange_proposal(
    client: &mut NamedPipeClient,
    replays: &mut ReplayNonceCache,
    pipe_name: &str,
    proposal: &BrokerMessage,
) -> Result<BrokerMessage> {
    send_message(client, proposal)?;
    receive_approval(client, replays, pipe_name, proposal)
}

struct PreparedProposal {
    authority: WorkerApplyAuthority,
    message: BrokerMessage,
}

fn accept_client(
    arguments: &Arguments,
    trust: &TrustedInstallation,
    signer: &trust::ReleaseSignerIdentity,
    pipe_name: &str,
) -> Result<(NamedPipeClient, ReplayNonceCache)> {
    let verifier = trust::StrictClientVerifier::new(arguments.client_pid, trust, signer)?;
    let server = NamedPipeServer::bind(pipe_name, verifier.expected_logon_sid())?;
    let client = server.accept(&verifier)?;
    let replays = ReplayNonceCache::new(Duration::from_mins(2), 8)?;
    Ok((client, replays))
}

fn receive_proposal_request(
    client: &mut NamedPipeClient,
    replays: &mut ReplayNonceCache,
    pipe_name: &str,
) -> Result<(ProposalRequest, BrokerMessage)> {
    let message = receive_message(client, replays)?;
    let request = parse_proposal_request(&message)?;
    validate_request_binding(&message, &request, pipe_name)?;
    Ok((request, message))
}

fn receive_message(
    client: &mut NamedPipeClient,
    replays: &mut ReplayNonceCache,
) -> Result<BrokerMessage> {
    let frame = client.receive()?;
    let message: BrokerMessage = FrameCodec::decode(&frame.0)?;
    message.validate()?;
    replays.accept(&message.nonce, Instant::now())?;
    Ok(message)
}

fn validate_request_binding(
    message: &BrokerMessage,
    request: &ProposalRequest,
    pipe_name: &str,
) -> Result<()> {
    let submitted_digest = baselineops_domain::canonical_json_digest(&request.plan)?;
    message.binding.require_request(
        pipe_name,
        &request.plan.id.to_string(),
        &submitted_digest.to_hex(),
    )?;
    Ok(())
}

fn prepare_proposal(
    request: &ProposalRequest,
    trust: &TrustedInstallation,
    signer: &trust::ReleaseSignerIdentity,
    pipe_name: &str,
    request_message: &BrokerMessage,
) -> Result<PreparedProposal> {
    let (profile, context) = reload_context(request, trust, signer)?;
    let authority = prepare_worker_apply(&request.plan, &profile, context)?;
    let message = proposal_message(&authority, pipe_name, &request_message.nonce)?;
    Ok(PreparedProposal { authority, message })
}

fn proposal_message(
    authority: &WorkerApplyAuthority,
    pipe_name: &str,
    request_nonce: &str,
) -> Result<BrokerMessage> {
    let proposal = BrokerMessage {
        version: PROTOCOL_VERSION,
        binding: BrokerBinding {
            session_id: pipe_name.into(),
            plan_id: authority.proposal().id.to_string(),
            plan_digest: authority.digest().to_hex(),
            reply_to: Some(request_nonce.into()),
        },
        nonce: Uuid::new_v4().simple().to_string(),
        kind: "plan.proposal".into(),
        payload: serde_json::json!({"plan":authority.proposal(),"digest":authority.digest().to_hex()}),
    };
    proposal.validate()?;
    Ok(proposal)
}

fn send_message(client: &mut NamedPipeClient, message: &BrokerMessage) -> Result<()> {
    client.send(&FrameCodec::encode(message)?)?;
    Ok(())
}

fn receive_approval(
    client: &mut NamedPipeClient,
    replays: &mut ReplayNonceCache,
    pipe_name: &str,
    proposal: &BrokerMessage,
) -> Result<BrokerMessage> {
    let approval = receive_message(client, replays)?;
    approval.binding.require_reply_to(
        pipe_name,
        &proposal.binding.plan_id,
        &proposal.binding.plan_digest,
        &proposal.nonce,
    )?;
    parse_approval_request(&approval)?;
    Ok(approval)
}

fn apply_result(
    authority: WorkerApplyAuthority,
    request: &ProposalRequest,
    approval: &BrokerMessage,
    trust: &TrustedInstallation,
    signer: &trust::ReleaseSignerIdentity,
    cancellation: &baselineops_engine::CancellationToken,
    progress: std::sync::mpsc::SyncSender<baselineops_engine::NativeActionProgress>,
) -> Result<WorkerResultV3> {
    let binding = ResultBinding::new(
        authority.proposal().id,
        authority.proposal().run_id,
        authority.digest(),
    );
    binding.after_revalidation(
        || {
            Ok((
                approval_digest(approval)?,
                live_context(reload_context(request, trust, signer)?.1),
            ))
        },
        |(approved_digest, live)| {
            execution_result(
                authority.approve(approved_digest, &live, trust),
                binding,
                cancellation,
                progress,
            )
        },
    )
}

fn approval_digest(approval: &BrokerMessage) -> Result<Sha256Digest> {
    parse_approval_request(approval)?
        .approved_digest
        .parse::<Sha256Digest>()
        .map_err(|error| anyhow!(error))
}

fn reload_context(
    request: &ProposalRequest,
    trust: &TrustedInstallation,
    signer: &trust::ReleaseSignerIdentity,
) -> Result<(ProfileV3, PlanBuildContext)> {
    let (profile, mut context) =
        reload_apply_inputs(&request.plan.source, &request.profile_source, trust, signer)?;
    super::validate_worker_resources(&request.plan.resources)?;
    // Until retained handles are transferred and independently verified, no resource
    // metadata from the client can become a fresh worker binding.
    context.input = InputIdentityV3::from_resources(
        context.source.digest,
        context.input.size_bytes,
        &context.resources,
    )?;
    Ok((profile, context))
}

fn live_context(context: PlanBuildContext) -> PlanValidationContext {
    PlanValidationContext {
        now: chrono::Utc::now(),
        intent: context.intent,
        host: context.host,
        tool: context.tool,
        package_digest: context.package_digest,
        source: context.source,
        input: context.input,
        observed_state_digest: context.observed_state.digest,
    }
}

fn execution_result(
    approval: Result<
        baselineops_engine::ApprovedWorkerApply<'_>,
        baselineops_engine::ApprovalError,
    >,
    binding: ResultBinding,
    cancellation: &baselineops_engine::CancellationToken,
    progress: std::sync::mpsc::SyncSender<baselineops_engine::NativeActionProgress>,
) -> Result<WorkerResultV3> {
    let (status, reason) = match approval {
        Ok(verified) => match baselineops_engine::execute_approved_worker_apply_with_progress(
            verified,
            cancellation,
            progress,
        ) {
            Ok(result) => return Ok(result),
            Err(error) => (
                error.result_status(),
                format!(
                    "Native dispatch did not produce a trustworthy result: {error}. Preserve any protected run for manual review."
                ),
            ),
        },
        Err(baselineops_engine::ApprovalError::ApplyIneligible { reason, .. }) => {
            (ResultStatus::Unsupported, reason.to_owned())
        }
        Err(error) => (ResultStatus::Rejected, error.to_string()),
    };
    binding.failure(status, &reason)
}

fn reload_apply_inputs(
    reviewed: &SourceIdentityV3,
    profile_source: &str,
    trust: &TrustedInstallation,
    signer: &trust::ReleaseSignerIdentity,
) -> Result<(ProfileV3, PlanBuildContext)> {
    let loaded = load_brokered_profile(reviewed, profile_source)?;
    let package_digest = trust::verify_current_installed_package(trust, signer)?.binding_digest();
    let observed_state = observe_profile(&loaded.profile)?;
    let context = apply_context(reviewed, loaded, package_digest, observed_state)?;
    Ok((context.0, context.1))
}

struct LoadedProfile {
    profile: ProfileV3,
    source_digest: Sha256Digest,
    size_bytes: u64,
}

fn load_brokered_profile(
    reviewed: &SourceIdentityV3,
    profile_source: &str,
) -> Result<LoadedProfile> {
    if reviewed.kind != SourceKind::LocalFile {
        bail!("apply accepts only a locally validated profile source");
    }
    let source_bytes = profile_source.as_bytes();
    let size_bytes = u64::try_from(source_bytes.len())?;
    if size_bytes > baselineops_windows::MAX_INPUT_BYTES {
        bail!("brokered profile source exceeds the worker input bound");
    }
    let profile = load_profile_json(source_bytes, JsonLoadLimits::default())?;
    let source_digest = Sha256Digest::of_bytes(source_bytes);
    if source_digest != reviewed.digest {
        bail!("brokered profile source digest does not match the reviewed source binding");
    }
    Ok(LoadedProfile {
        profile,
        source_digest,
        size_bytes,
    })
}

fn observe_profile(profile: &ProfileV3) -> Result<baselineops_domain::ObservedStateV3> {
    reobserve_profile(profile, &NativeObservationSource, chrono::Utc::now())
        .map_err(|error| anyhow!(error))
}

fn apply_context(
    reviewed: &SourceIdentityV3,
    loaded: LoadedProfile,
    package_digest: Sha256Digest,
    observed_state: baselineops_domain::ObservedStateV3,
) -> Result<(ProfileV3, PlanBuildContext)> {
    let context = PlanBuildContext {
        intent: ExecutionIntent::Apply,
        host: baselineops_windows::collect_host_identity()?,
        tool: ToolIdentityV3 {
            name: "baselineops".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            build_digest: Some(package_digest),
        },
        package_digest,
        source: reviewed.clone(),
        input: InputIdentityV3 {
            digest: loaded.source_digest,
            size_bytes: loaded.size_bytes,
        },
        resources: Vec::new(),
        observed_state,
        lifetime: chrono::Duration::minutes(5),
    };
    Ok((loaded.profile, context))
}
