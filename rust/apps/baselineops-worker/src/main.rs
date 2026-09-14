//! Short-lived elevated `BaselineOps` v3 worker entry point.

#![cfg_attr(windows, allow(unsafe_code))]

use anyhow::{Context, Result, bail};
use baselineops_domain::{ExitCode, PlanV3};
#[cfg(windows)]
mod broker;
#[cfg(any(windows, test))]
mod control;
#[cfg(any(windows, test))]
mod responses;
mod trust;
use clap::Parser;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "baselineops-worker", version)]
struct Arguments {
    /// Random local named-pipe session identifier supplied as a direct UAC token.
    #[arg(long, value_parser = parse_session)]
    session: Uuid,
    /// Exact standard-user CLI process that must own the pipe client endpoint.
    #[arg(long, value_parser = parse_process_id)]
    client_pid: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(not(windows), allow(dead_code))]
struct ProposalRequest {
    plan: PlanV3,
    profile_source: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(not(windows), allow(dead_code))]
struct ApprovalRequest {
    approved_digest: String,
}

fn main() {
    #[cfg(windows)]
    sanitize_environment();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let exit = match run(&Arguments::parse()) {
        Ok(exit) => exit,
        Err(error) => {
            eprintln!("baselineops-worker: {error:#}");
            ExitCode::Rejected
        }
    };
    std::process::exit(exit.as_i32());
}

/// Retain only a bounded diagnostic filter before tracing or worker setup reads env.
#[cfg(windows)]
fn sanitize_environment() {
    let rust_log = std::env::var_os("RUST_LOG").filter(|value| safe_log_filter(value));
    let keys = std::env::vars_os().map(|(key, _)| key).collect::<Vec<_>>();
    for key in keys {
        // The worker must not inherit loader, path, proxy, or application configuration.
        unsafe { std::env::remove_var(key) };
    }
    if let Some(rust_log) = rust_log {
        unsafe { std::env::set_var("RUST_LOG", rust_log) };
    }
}

#[cfg(any(windows, test))]
fn safe_log_filter(value: &std::ffi::OsStr) -> bool {
    let value = value.to_string_lossy();
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}

fn run(arguments: &Arguments) -> Result<ExitCode> {
    #[cfg(windows)]
    baselineops_windows::wait_for_worker_containment(std::time::Duration::from_secs(30))?;
    let signer = trust::release_signer_identity()?;
    let trust = trust::verify_current_worker(&signer)?;
    #[cfg(windows)]
    {
        let _installed_package = trust::verify_current_installed_package(&trust, &signer)?;
        broker::run_windows(arguments, &trust, &signer)
    }
    #[cfg(not(windows))]
    {
        let _ = (arguments, trust);
        bail!("protected UAC worker is only available on Windows");
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn parse_proposal_request(message: &baselineops_windows::BrokerMessage) -> Result<ProposalRequest> {
    if message.kind != "plan.propose" {
        bail!("worker only accepts plan.propose messages");
    }
    let request: ProposalRequest = serde_json::from_value(message.payload.clone())
        .context("invalid bounded proposal request")?;
    validate_worker_resources(&request.plan.resources)?;
    Ok(request)
}

fn validate_worker_resources(resources: &[baselineops_domain::ResourceBindingV3]) -> Result<()> {
    if !resources.is_empty() {
        bail!(
            "resource-dependent Apply requires authenticated retained-handle transfer; resource metadata alone is not worker authority"
        );
    }
    Ok(())
}

#[cfg_attr(not(windows), allow(dead_code))]
fn parse_approval_request(message: &baselineops_windows::BrokerMessage) -> Result<ApprovalRequest> {
    if message.kind != "plan.approve" {
        bail!("worker only accepts plan.approve messages");
    }
    let request: ApprovalRequest = serde_json::from_value(message.payload.clone())
        .context("invalid bounded approval request")?;
    if request.approved_digest.len() != 64
        || !request
            .approved_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("approved digest must be lowercase SHA-256 hex");
    }
    Ok(request)
}

fn parse_session(value: &str) -> Result<Uuid, String> {
    let session = Uuid::parse_str(value).map_err(|error| error.to_string())?;
    if session.is_nil() {
        return Err("session identifier may not be nil".into());
    }
    Ok(session)
}

fn parse_process_id(value: &str) -> Result<u32, String> {
    let pid = value.parse::<u32>().map_err(|error| error.to_string())?;
    if pid == 0 {
        return Err("client process identifier may not be zero".into());
    }
    Ok(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_and_session_inputs_are_strict() {
        assert!(parse_session("00000000-0000-0000-0000-000000000000").is_err());
        assert!(parse_process_id("0").is_err());
    }
    #[test]
    fn two_phase_request_kinds_are_checked() {
        let message = baselineops_windows::BrokerMessage {
            version: baselineops_windows::PROTOCOL_VERSION,
            binding: baselineops_windows::BrokerBinding {
                session_id: "aa".into(),
                plan_id: "plan".into(),
                plan_digest: "ab".repeat(32),
                reply_to: None,
            },
            nonce: "aa".into(),
            kind: "wrong".into(),
            payload: serde_json::json!({}),
        };
        assert!(parse_proposal_request(&message).is_err());
        assert!(parse_approval_request(&message).is_err());
    }

    #[test]
    fn resource_metadata_cannot_grant_worker_authority() {
        let resource = baselineops_domain::ResourceBindingV3 {
            logical_id: baselineops_domain::LogicalResourceId::new("catalog").unwrap(),
            kind: baselineops_domain::ResourceKind::File,
            digest: baselineops_domain::Sha256Digest::of_bytes(b"unverified"),
            size_bytes: 10,
        };
        assert!(validate_worker_resources(&[resource]).is_err());
        assert!(validate_worker_resources(&[]).is_ok());
    }

    #[test]
    fn diagnostic_environment_allowlist_is_bounded() {
        assert!(safe_log_filter(std::ffi::OsStr::new("info,worker=debug")));
        assert!(!safe_log_filter(std::ffi::OsStr::new("")));
        assert!(!safe_log_filter(std::ffi::OsStr::new("info\nworker=debug")));
    }
}
