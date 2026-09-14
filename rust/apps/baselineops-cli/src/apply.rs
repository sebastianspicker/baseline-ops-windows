//! Mutually authenticated elevated apply broker.

mod input;
mod protocol;
mod trust;

use anyhow::{Result, anyhow, bail};
use baselineops_domain::{ExitCode, PlanV3};
use baselineops_windows::ipc::NamedPipeClient;
use baselineops_windows::{ElevatedLaunchResult, PlatformError, ReplayNonceCache};
use std::{
    io::{BufRead as _, Write as _},
    thread,
    time::{Duration, Instant},
};

pub(super) fn run(plan: &PlanV3, preapproved_digest: Option<&str>) -> Result<ExitCode> {
    let mut exchange = trust::start_worker(plan)?;
    let (response, proposal_nonce) = protocol::propose(&mut exchange, plan)?;
    super::print_json(
        &serde_json::json!({"status":"proposal","digest":response.digest,"plan":response.plan}),
    )?;
    let approval = protocol::approval_request(
        &exchange.pipe_name,
        &response,
        proposal_nonce,
        &approval_digest(preapproved_digest)?,
    )?;
    protocol::finish(exchange, &response, &approval)
}

pub(super) struct WorkerExchange {
    pub(super) client: NamedPipeClient,
    pub(super) replays: ReplayNonceCache,
    pub(super) pipe_name: String,
    pub(super) launch: WorkerLaunch,
}

pub(super) type WorkerLaunch = thread::JoinHandle<Result<ElevatedLaunchResult, PlatformError>>;

impl WorkerExchange {
    fn worker_exit(self) -> Result<ExitCode> {
        let launched = self
            .launch
            .join()
            .map_err(|_| anyhow!("elevation launcher panicked"))??;
        Ok(crate::protocol::map_worker_exit_status(&launched.status))
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WorkerProposal {
    pub(super) plan: PlanV3,
    pub(super) digest: String,
}

fn connect(name: &str, launch: WorkerLaunch) -> Result<(NamedPipeClient, WorkerLaunch)> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let selected = crate::protocol::select_startup_poll(
            NamedPipeClient::connect(name),
            launch.is_finished(),
            Instant::now() < deadline,
        );
        match selected {
            crate::protocol::StartupPoll::Connected(client) => return Ok((client, launch)),
            crate::protocol::StartupPoll::LauncherFinished => {
                return Err(crate::protocol::early_worker_completion_error(
                    launch.join(),
                ));
            }
            crate::protocol::StartupPoll::Retry => thread::sleep(Duration::from_millis(50)),
            crate::protocol::StartupPoll::ConnectionFailed(error) => {
                return Err(anyhow!(error));
            }
        }
    }
}

fn approval_digest(provided: Option<&str>) -> Result<String> {
    if let Some(value) = provided {
        return Ok(value.to_owned());
    }
    eprint!("Approve this exact worker digest to continue (leave blank to cancel): ");
    std::io::stderr().flush()?;
    let mut value = String::new();
    std::io::stdin().lock().read_line(&mut value)?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        bail!("worker proposal was not approved");
    }
    Ok(value)
}
