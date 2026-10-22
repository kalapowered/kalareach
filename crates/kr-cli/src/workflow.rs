//! `kr workflow`: giving a causal chain whose budget ran out a new one.
//!
//! A chain of workflows that trigger one another has one budget, and when it runs out the chain is
//! paused and one attention item says so. Only an explicit, authorised rearm gives it a new
//! budget, and `kr workflow rearm` is that request: it names the chain, the grant it is made under
//! and the budget generation it leaves, and the control daemon decides whether it is allowed.
//! Without a generation the command reads the one the chain is on, and says so; it refuses a chain
//! the daemon holds no budget for itself, and sends one request, whose answer it prints.

use kr_client::shown;
use kr_client::shown::Shown;
use kr_protocol::automation::{
    WorkflowReadParams, WorkflowReadResult, WorkflowRearmParams, WorkflowRearmResult,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{CausalRootId, GrantId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64};

use crate::cli::{EnvironmentSelector, WorkflowCommand, WorkflowRearmArguments};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::output::{self, closed_word};
use crate::{answer, report, stdout_line};

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
    // Said before the request is sent: a reply that is lost leaves a person with no other way to
    // know which generation to name, and a repeat that names it gives no second budget.
    let environment = environment_flag(&daemon, &arguments.selector);
    report::say(&shown!(
        "Rearming chain {} from budget generation {}. {}",
        closed_word(&root),
        generation,
        repeat_with(root, grant, generation, &environment)
    ));
    let rearmed: WorkflowRearmResult = match daemon
        .mutate(
            Method::WorkflowRearm,
            &WorkflowRearmParams {
                causal_root_id: root,
                grant_reference: grant,
                generation: U64::new(generation),
            },
        )
        .await
    {
        Ok(rearmed) => rearmed,
        // A refusal says what is wrong. Anything else may have followed a rearm that was made.
        Err(error) => {
            if !matches!(&error, CliError::Refused(refusal) if refusal.code != ErrorCode::OutcomeUnknown)
            {
                report::say(&repeat_with(root, grant, generation, &environment));
            }
            return Err(error);
        }
    };
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

/// What a person does when the reply to a rearm may not have reached them: the command that
/// names the generation, which a chain already on the generation after it answers without giving a
/// second budget. It names the environment the rearm was sent to when this command was given one.
fn repeat_with(root: CausalRootId, grant: GrantId, generation: u64, environment: &Shown) -> Shown {
    shown!(
        "If the reply does not arrive, run: kr workflow rearm {} --grant {} --generation {}{}",
        closed_word(&root),
        closed_word(&grant),
        generation,
        *environment
    )
}

/// What `--environment` says in a command printed for a person to run: nothing when this command
/// was not given one, since the default is the same for the person's next command.
fn environment_flag(daemon: &Daemon, selector: &EnvironmentSelector) -> Shown {
    if selector.environment.is_some() {
        shown!(" --environment {}", daemon.environment_id())
    } else {
        Shown::said("")
    }
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
