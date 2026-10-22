//! `kr workflow`: giving a causal chain whose budget ran out a new one.
//!
//! A chain of workflows that trigger one another has one budget, and when it runs out the chain is
//! paused and one attention item says so. Only an explicit, authorised rearm gives it a new
//! budget, and `kr workflow rearm` is that request: it names the chain, the grant it is made under
//! and the budget generation it leaves, and the control daemon decides every refusal. The command
//! sends one request and prints what the daemon answered.

use kr_client::shown;
use kr_protocol::automation::{
    WorkflowReadParams, WorkflowReadResult, WorkflowRearmParams, WorkflowRearmResult,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{CausalRootId, GrantId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64};

use crate::cli::{WorkflowCommand, WorkflowRearmArguments};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::output::{self, closed_word};
use crate::{answer, stdout_line};

/// Runs one `kr workflow` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the daemon's refusal, or a transport failure.
pub async fn run(
    paths: &kr_ipc::paths::HostPaths,
    command: WorkflowCommand,
    json: bool,
) -> Result<()> {
    match command {
        WorkflowCommand::Rearm(arguments) => rearm(paths, &arguments, json).await,
    }
}

/// `kr workflow rearm`.
async fn rearm(
    paths: &kr_ipc::paths::HostPaths,
    arguments: &WorkflowRearmArguments,
    json: bool,
) -> Result<()> {
    let root: CausalRootId = identifier(&arguments.causal_root, "a causal root")?;
    let grant: GrantId = identifier(&arguments.grant, "a grant")?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let generation = match arguments.generation {
        Some(named) => named,
        None => current_generation(&mut daemon, root).await?,
    };
    let rearmed: WorkflowRearmResult = daemon
        .mutate(
            Method::WorkflowRearm,
            &WorkflowRearmParams {
                causal_root_id: root,
                grant_reference: grant,
                generation: U64::new(generation),
            },
        )
        .await?;
    if json {
        output::document(&answer::workflow_rearm_result(&rearmed));
    } else {
        output::line(&stdout_line!(
            "Rearmed chain {}: its budget is on generation {}.",
            closed_word(&rearmed.causal_root_id),
            rearmed.generation.get()
        ));
    }
    Ok(())
}

/// The budget generation the daemon says a chain is on.
async fn current_generation(daemon: &mut Daemon, root: CausalRootId) -> Result<u64> {
    let read: WorkflowReadResult = daemon
        .read(
            Method::WorkflowRead,
            &WorkflowReadParams {
                causal_root_id: Nullable::some(root),
                ..WorkflowReadParams::default()
            },
        )
        .await?;
    read.remaining_causal_budget
        .0
        .map(|budget| budget.generation.get())
        .ok_or_else(|| {
            CliError::Refused(kr_client::error::refusal(
                ErrorCode::InvalidArgument,
                shown!("this environment holds no budget for that chain"),
            ))
        })
}
