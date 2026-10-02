//! `kr host machine`: the machine group an environment records for itself, and the steps that
//! change it.
//!
//! A machine group is a random grouping of environments that the owner approves. It grants nothing,
//! and each environment records its own and changes it only by its own owner-approved step: a
//! step is one environment's, taken over that environment's own connection, against the group and
//! the revision the owner saw. This command is the owner at their own command line, so a step is
//! the owner's own on this host's socket, or on the process bridge of an environment this host
//! reaches that way. An enrolled environment's group is what that environment reports about itself
//! through its bridge, never what its enrolment records.
//!
//! **One step here.** `join`, `merge` and `split` take one step on one environment, under an action
//! identity this command makes and prints.
//!
//! **A merge over independent environments** is a plan this command keeps. Each environment that
//! reports the group being merged away takes its own step, so the plan holds, for each selected
//! environment, the step's precondition (the record the environment reported when the plan was
//! made), the identity of its action, the step as it was composed once it was first sent, and what
//! it has come to. A step is composed on the connection that first sends it, because the action
//! window it quotes belongs to that connection. The plan is a file only the owner reads, in this
//! user's own state directory and never in an environment's, written before the first step is sent
//! and rewritten as each answer arrives, and it is deleted when every step has a result. One
//! command at a time works on it: `merge --from`, `finish` and `undo` each hold a lock on it for as
//! long as they run, and refuse while another holds it.
//!
//! - `finish` sends each step that has no result: a step never sent is composed and sent under its
//!   identity, and a step already sent is sent again as it was composed, so an environment that took
//!   it answers from its receipt. A step the environment refuses without a receipt is read against
//!   what the environment reports: at the precondition nothing was applied, and the step is
//!   composed again under a new action identity (unless its first action is still running, in which
//!   case it waits for that); one step on, the record shows it was taken; and anywhere else it can
//!   never apply and is given its refusal. A step whose outcome the environment does not know, or
//!   could not confirm, or could not write, is not given a result it was not given: it stays sent.
//!   An environment that cannot be reached stays pending.
//! - `undo` moves each environment the plan moved back into the group it left, by a step of its own
//!   against the record the first one left, sent by the next `finish` or at once. A step that was
//!   never sent is given up. One that may or may not have been taken has to be finished first,
//!   because undoing an environment that may still move would leave it moved.
//! - A lost plan is not rebuilt from what environments report: the owner selects the environments
//!   again, and a merge that finds a plan kept says so rather than starting another.

use std::path::PathBuf;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_controller::bridge::invoke::{self, Invocation, Refusal};
use kr_ipc::client::LocalClient;
use kr_ipc::paths::HostPaths;
use kr_protocol::envelope::{ActionTarget, MutationRequest, Outcome, ParamsValue, Request};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::hello::ActionWindow;
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::identity::{
    BridgeTarget, EnvironmentEnrolment, EnvironmentInventoryParams, EnvironmentInventoryResult,
};
use kr_protocol::ids::{
    ActionId, ActorId, ConnectionId, ControllerGeneration, EnvironmentId, MachineId, RequestId,
};
use kr_protocol::machine::{
    MachineChange, MachineExpected, MachineGroup, MachineJoinParams, MachineMergeParams,
    MachineSplitParams, MachineStepResult,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{DurationMs, Nullable, U64};
use serde::{Deserialize, Serialize};

use crate::cli::{
    EnvironmentSelector, MachineArguments, MachineCommand, MachineJoinArguments,
    MachineMergeArguments, MachineSplitArguments,
};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::output::{self, Document, Line};
use crate::report::Completion;
use crate::stdout_line;

/// The file the plan is kept in, in this user's own state directory.
const PLAN_FILE: &str = "machine-merge-plan";

/// The file the lock on the plan is taken on, beside the plan.
const PLAN_LOCK_FILE: &str = "machine-merge-plan.lock";

/// The largest plan this command reads: a step is a few hundred bytes.
const PLAN_LIMIT: u64 = 1 << 20;

/// Runs one `kr host machine` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the environment's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, arguments: MachineArguments, json: bool) -> Result<Completion> {
    let MachineArguments {
        command,
        environment,
    } = arguments;
    if matches!(
        command,
        Some(MachineCommand::Plan | MachineCommand::Finish | MachineCommand::Undo)
    ) && !environment.is_empty()
    {
        return Err(CliError::Usage(Shown::said(
            "plan, finish and undo act on the merge plan this client keeps, which names its own \
             environments: --environment names one only for a step or when a merge plan is made",
        )));
    }
    match command {
        None => show(paths, &environment, json)
            .await
            .map(|()| Completion::Done),
        Some(MachineCommand::Join(arguments)) => join(paths, &environment, &arguments, json).await,
        Some(MachineCommand::Merge(arguments)) => {
            merge(paths, &environment, &arguments, json).await
        }
        Some(MachineCommand::Split(arguments)) => {
            split(paths, &environment, &arguments, json).await
        }
        Some(MachineCommand::Plan) => plan_shown(paths, json).map(|()| Completion::Done),
        Some(MachineCommand::Finish) => finish(paths, json).await,
        Some(MachineCommand::Undo) => undo(paths, json).await,
    }
}

/* -------------------------------------------------------------------------------------------- */
/* Reaching one environment                                                                     */
/* -------------------------------------------------------------------------------------------- */

/// How this host reaches an environment, which a plan keeps for each of its steps.
#[derive(Clone, Debug, Serialize, Deserialize)]
enum Reach {
    /// One of this host's own environments, over its own socket.
    Own,
    /// An environment enrolled for a process bridge, over that bridge.
    Enrolled(EnvironmentEnrolment),
}

/// One environment's connection.
struct Reached {
    environment_id: EnvironmentId,
    channel: Channel,
    next_request: u64,
}

enum Channel {
    Local(Box<LocalClient>),
    Bridged {
        invocation: Box<Invocation>,
        window: ActionWindow,
    },
}

/// Chooses the one environment a command acts in.
async fn select_one(paths: &HostPaths, named: &[String]) -> Result<(EnvironmentId, Reach)> {
    match named {
        [] => {
            let known = crate::resolve::select(paths, None)?;
            Ok((known.environment_id, Reach::Own))
        }
        [one] => select(paths, one).await,
        _ => Err(CliError::Usage(Shown::said(
            "one step changes one environment: name one with --environment",
        ))),
    }
}

/// Finds the environment `text` names: one of this host's own by identifier, or an enrolled one by
/// identifier or label.
async fn select(paths: &HostPaths, text: &str) -> Result<(EnvironmentId, Reach)> {
    if let Ok(wanted) = text.parse::<EnvironmentId>()
        && crate::resolve::environments(paths)?
            .iter()
            .any(|known| known.environment_id == wanted)
    {
        return Ok((wanted, Reach::Own));
    }
    let mut daemon = Daemon::open(paths, &EnvironmentSelector { environment: None }).await?;
    let inventory: EnvironmentInventoryResult = daemon
        .read(
            Method::EnvironmentInventory,
            &EnvironmentInventoryParams {
                access: Nullable::null(),
            },
        )
        .await?;
    let mut found = inventory.rows.into_iter().filter(|row| {
        row.enrolment.environment_id.to_string() == text || row.enrolment.selected_by(text)
    });
    let Some(row) = found.next() else {
        return Err(CliError::HostUnavailable(Shown::said(
            "this host has no such environment of its own, and none enrolled by that identifier \
             or label",
        )));
    };
    if found.next().is_some() {
        return Err(CliError::Usage(Shown::said(
            "that label names more than one enrolled environment; give the environment identifier",
        )));
    }
    if !row.enrolment.access.is_process_bridge() {
        return Err(CliError::Usage(Shown::said(
            "this command reaches an enrolled environment over its process bridge, and that \
             environment is reached another way: run it from inside that environment",
        )));
    }
    Ok((row.enrolment.environment_id, Reach::Enrolled(row.enrolment)))
}

/// Opens the connection `reach` names.
async fn reach_environment(
    paths: &HostPaths,
    environment_id: EnvironmentId,
    reach: &Reach,
) -> Result<Reached> {
    let channel = match reach {
        Reach::Own => {
            let known = crate::resolve::environments(paths)?
                .into_iter()
                .find(|known| known.environment_id == environment_id)
                .ok_or_else(|| {
                    CliError::HostUnavailable(Shown::said(
                        "this host has no longer an environment of that identifier",
                    ))
                })?;
            Channel::Local(Box::new(
                crate::resolve::open_controller(&known.paths, crate::build_id()).await?,
            ))
        }
        Reach::Enrolled(enrolment) => {
            // This command is the owner at their own command line: the one ingress a bridge
            // carries.
            let actor = kr_controller::service::local_actor(
                ActorId::new(format!("local:{}", kr_ipc::paths::current_uid())).map_err(|_| {
                    CliError::Other(Shown::said("this user has no principal a bridge can carry"))
                })?,
                ConnectionId::new(kr_ipc::new_uuid()),
                ControllerGeneration::new(0),
            );
            let opening = invoke::open(
                &actor,
                false,
                enrolment,
                paths.open_environment_id()?,
                crate::build_id(),
                BridgeTarget::Controller,
            )
            .map_err(bridge_failure)?;
            let invocation = opening.launch().await.map_err(bridge_failure)?;
            let window = invocation.acknowledgement().action_window.clone();
            Channel::Bridged {
                invocation: Box::new(invocation),
                window,
            }
        }
    };
    Ok(Reached {
        environment_id,
        channel,
        next_request: 1,
    })
}

/// What a bridge that could not be used says, without repeating what the destination wrote.
fn bridge_failure(refusal: Refusal) -> CliError {
    match refusal {
        Refusal::NotStarted { .. } | Refusal::Stream { .. } | Refusal::Silent { .. } => {
            CliError::HostUnavailable(Shown::said(
                "the process bridge to that environment could not be opened, so it was not \
                 asked: start the environment and try again",
            ))
        }
        Refusal::IdentityMismatch { .. } => CliError::Other(Shown::said(
            "that environment answered as another installation than the one enrolled, so it \
             was not asked",
        )),
        Refusal::Destination(error) => CliError::Refused(error),
        _ => CliError::Other(Shown::said(
            "the process bridge to that environment could not be used, so it was not asked",
        )),
    }
}

/// What a step whose answer did not arrive is told, with the action it was sent under.
fn answer_lost(action_id: ActionId) -> CliError {
    CliError::Unfinished {
        code: ErrorCode::OutcomeUnknown,
        message: shown!(
            "the connection failed after the step was sent, so whether the environment took it is \
             not known: kr host machine shows its record, and the step was sent under action {}",
            action_id
        ),
    }
}

impl Reached {
    /// Reads the environment's own `host.info`.
    async fn host_info(&mut self) -> Result<HostInfoResult> {
        match &mut self.channel {
            Channel::Local(client) => crate::bind::read(client, Method::HostInfo, &()).await,
            Channel::Bridged { invocation, .. } => {
                let request_id = RequestId::new(self.next_request);
                self.next_request += 1;
                let answer = invocation
                    .request(Request {
                        request_id,
                        method: Method::HostInfo.into(),
                        method_version: MethodVersion::V1,
                        params: ParamsValue::from_typed(&()).map_err(|_| {
                            CliError::Other(Shown::said("the request could not be encoded"))
                        })?,
                    })
                    .await
                    .map_err(bridge_failure)?;
                match answer.outcome {
                    Outcome::Ok(value) => value.to_typed().map_err(|_| {
                        CliError::Other(Shown::said(
                            "the environment's answer could not be read as host information",
                        ))
                    }),
                    Outcome::Error(error) => Err(CliError::Refused(error)),
                }
            }
        }
    }

    /// Composes one mutation on this environment, quoting the action window of this connection.
    async fn compose<P: Serialize + ?Sized>(
        &mut self,
        method: Method,
        action_id: ActionId,
        params: &P,
    ) -> Result<MutationRequest> {
        let target = ActionTarget::environment(self.environment_id);
        match &mut self.channel {
            Channel::Local(client) => Ok(client.compose(method, action_id, target, params).await?),
            Channel::Bridged { window, .. } => {
                let request_id = RequestId::new(self.next_request);
                self.next_request += 1;
                Ok(MutationRequest {
                    request_id,
                    method: method.into(),
                    method_version: MethodVersion::V1,
                    action_id,
                    grant_id: Nullable::null(),
                    target,
                    expected: ParamsValue::empty(),
                    action_window_id: window.action_window_id.clone(),
                    requested_ttl_ms: DurationMs::new(
                        kr_protocol::limits::DEFAULT_MUTATION_TTL.get(),
                    ),
                    params: ParamsValue::from_typed(params).map_err(|_| {
                        CliError::Other(Shown::said("the parameters could not be encoded"))
                    })?,
                })
            }
        }
    }

    /// Sends a mutation exactly as it was composed, and returns what the environment answered.
    ///
    /// An environment that already holds the action answers from its receipt, whatever window the
    /// mutation quotes and on whatever connection it arrives. A connection that fails here may have
    /// failed after the environment took the step, and says so, with the action's identity.
    async fn send(
        &mut self,
        mutation: &MutationRequest,
    ) -> Result<std::result::Result<ParamsValue, ProtocolError>> {
        let action_id = mutation.action_id;
        match &mut self.channel {
            Channel::Local(client) => client
                .repeat(mutation)
                .await
                .map_err(|_| answer_lost(action_id)),
            Channel::Bridged { invocation, .. } => {
                let mut mutation = mutation.clone();
                mutation.request_id = RequestId::new(self.next_request);
                self.next_request += 1;
                let answer =
                    invocation
                        .mutate(mutation)
                        .await
                        .map_err(|refusal| match refusal {
                            Refusal::IdentityMismatch { .. } | Refusal::Destination(_) => {
                                bridge_failure(refusal)
                            }
                            _ => answer_lost(action_id),
                        })?;
                Ok(match answer.outcome {
                    Outcome::Ok(value) => Ok(value),
                    Outcome::Error(error) => Err(error),
                })
            }
        }
    }

    /// Ends the connection. A bridge's helper is ended with it.
    async fn close(self) {
        if let Channel::Bridged { invocation, .. } = self.channel {
            let _ = invocation.close().await;
        }
    }
}

/* -------------------------------------------------------------------------------------------- */
/* Showing a group, and one step                                                                */
/* -------------------------------------------------------------------------------------------- */

/// `kr host machine`.
async fn show(paths: &HostPaths, named: &[String], json: bool) -> Result<()> {
    let (environment_id, reach) = select_one(paths, named).await?;
    let mut reached = reach_environment(paths, environment_id, &reach).await?;
    let info = reached.host_info().await;
    reached.close().await;
    let info = info?;
    if json {
        output::document(&group_document(environment_id, info.machine.as_ref()));
    } else {
        output::lines(&group_lines(environment_id, info.machine.as_ref()));
    }
    Ok(())
}

/// The group an environment reports, as lines for a person.
fn group_lines(environment_id: EnvironmentId, machine: Option<&MachineGroup>) -> Vec<Line> {
    let Some(group) = machine else {
        return vec![stdout_line!(
            "Environment {} reports no machine group: it is an older host, or its record cannot \
             be used, and kr doctor, run in that environment, says what to do.",
            environment_id
        )];
    };
    let mut lines = vec![
        stdout_line!(
            "Environment {} is in machine group {}, at revision {}.",
            environment_id,
            group.machine_id.get(),
            group.revision
        ),
        stdout_line!("Last change: {}.", change_words(group.change)),
    ];
    if let Some(previous) = group.previous.as_ref() {
        lines.push(stdout_line!("Before that: group {}.", previous.get()));
    }
    lines.push(stdout_line!(
        "To change it, name this record: --expect {}@{}",
        group.machine_id.get(),
        group.revision
    ));
    lines
}

/// What wrote a record, in words.
const fn change_words(change: MachineChange) -> &'static str {
    match change {
        MachineChange::Created => "the environment's first start minted this group",
        MachineChange::Joined => "the owner moved the environment into this group",
        MachineChange::Merged => "the owner merged the environment's group into this one",
        MachineChange::Split => "the owner moved the environment into this fresh group of its own",
    }
}

/// The group an environment reports, for a script.
fn group_document(environment_id: EnvironmentId, machine: Option<&MachineGroup>) -> Document {
    Document::new()
        .with("ok", true)
        .with("environment_id", output::closed(&environment_id))
        .with("machine", machine.map(group_value))
}

/// One group, for a script.
fn group_value(group: &MachineGroup) -> Document {
    Document::new()
        .with("machine_id", shown!("{}", group.machine_id.get()))
        .with("revision", output::closed(&group.revision))
        .with("change", Shown::said(group.change.as_str()))
        .with(
            "previous",
            group
                .previous
                .as_ref()
                .map(|previous| shown!("{}", previous.get())),
        )
}

/// Reads `<group>@<revision>`.
fn expectation(text: &str) -> Result<MachineExpected> {
    let malformed = || {
        CliError::Usage(Shown::said(
            "--expect names the record the step is approved against, written <group>@<revision>, \
             as kr host machine shows it",
        ))
    };
    let (group, revision) = text.split_once('@').ok_or_else(malformed)?;
    Ok(MachineExpected {
        machine_id: group.parse().map_err(|_| malformed())?,
        revision: U64::new(revision.parse().map_err(|_| malformed())?),
    })
}

/// `kr host machine join`.
async fn join(
    paths: &HostPaths,
    named: &[String],
    arguments: &MachineJoinArguments,
    json: bool,
) -> Result<Completion> {
    let machine_id: MachineId = identifier(&arguments.group, "a machine group")?;
    let params = MachineJoinParams {
        machine_id,
        expected: expectation(&arguments.expect)?,
    };
    one_step(paths, named, Method::MachineJoin, &params, json).await
}

/// `kr host machine split`.
async fn split(
    paths: &HostPaths,
    named: &[String],
    arguments: &MachineSplitArguments,
    json: bool,
) -> Result<Completion> {
    let params = MachineSplitParams {
        expected: expectation(&arguments.expect)?,
    };
    one_step(paths, named, Method::MachineSplit, &params, json).await
}

/// `kr host machine merge`: one step here, or a plan over several environments.
async fn merge(
    paths: &HostPaths,
    named: &[String],
    arguments: &MachineMergeArguments,
    json: bool,
) -> Result<Completion> {
    let into: MachineId = identifier(&arguments.into, "a machine group")?;
    match (&arguments.expect, &arguments.from) {
        (Some(expect), None) => {
            let params = MachineMergeParams {
                machine_id: into,
                expected: expectation(expect)?,
            };
            one_step(paths, named, Method::MachineMerge, &params, json).await
        }
        (None, Some(from)) => {
            let from: MachineId = identifier(from, "a machine group")?;
            if from == into {
                return Err(CliError::Usage(Shown::said(
                    "a merge moves environments out of one group into another: --from names a \
                     group other than the one being merged into",
                )));
            }
            plan_made(paths, named, into, from, json).await
        }
        _ => Err(CliError::Usage(Shown::said(
            "a merge names the record one environment's step is approved against with --expect, \
             or the group several environments are in with --from and each of them with \
             --environment",
        ))),
    }
}

/// Takes one step on one environment and prints what it came to.
async fn one_step<P: Serialize + ?Sized>(
    paths: &HostPaths,
    named: &[String],
    method: Method,
    params: &P,
    json: bool,
) -> Result<Completion> {
    let (environment_id, reach) = select_one(paths, named).await?;
    let mut reached = reach_environment(paths, environment_id, &reach).await?;
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let answered = async {
        let mutation = reached.compose(method, action_id, params).await?;
        reached.send(&mutation).await
    }
    .await;
    reached.close().await;
    match answered? {
        Ok(value) => {
            let result: MachineStepResult = value.to_typed().map_err(|_| {
                CliError::Other(Shown::said(
                    "the environment's answer could not be read as a machine group step",
                ))
            })?;
            if json {
                output::document(
                    &group_document(result.environment_id, Some(&result.machine))
                        .with("action_id", output::closed(&action_id)),
                );
            } else {
                let mut lines = group_lines(result.environment_id, Some(&result.machine));
                lines.push(stdout_line!("Action {}.", action_id));
                output::lines(&lines);
            }
            Ok(Completion::Done)
        }
        Err(error) => Err(CliError::Refused(error)),
    }
}

/* -------------------------------------------------------------------------------------------- */
/* The plan                                                                                     */
/* -------------------------------------------------------------------------------------------- */

/// A merge over independent environments, kept by this client until each step has its result.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Plan {
    /// The group the environments are merged into.
    into: MachineId,
    /// The group they are in now, and are moved out of.
    from: MachineId,
    /// One step for each environment the owner selected.
    steps: Vec<PlannedStep>,
    /// The steps that put moved environments back, once the owner asked for that.
    undo: Vec<PlannedStep>,
    /// Whether the owner asked for the merge to be undone.
    undoing: bool,
}

/// One environment's step.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PlannedStep {
    environment_id: EnvironmentId,
    reach: Reach,
    /// The record the step is approved against.
    expected: MachineExpected,
    /// The group the step takes the environment into.
    into: MachineId,
    /// The identity of the step's action: the one it is first sent under, and after a refusal the
    /// environment kept for that action, the one of the step composed again.
    action_id: ActionId,
    /// The step as it was composed on the connection that sent it, which is sent again exactly as
    /// it is. None until a connection has composed it, which is why an unsent step is one no
    /// environment has been sent.
    mutation: Option<MutationRequest>,
    state: StepState,
}

/// What one step has come to.
#[derive(Clone, Debug, Serialize, Deserialize)]
enum StepState {
    /// Not sent: no environment has been sent it, under any identity.
    Unsent,
    /// Sent, and what the environment did with it is not known yet.
    Sent,
    /// The environment took it, and records this.
    Done(MachineGroup),
    /// It will not be taken, and why.
    Refused(ErrorCode, Why),
}

/// Where a refusal came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Why {
    /// The environment refused it.
    Environment,
    /// The environment's record moved on from the one the step was approved against.
    Moved,
    /// The owner gave it up before it was sent.
    GivenUp,
}

impl StepState {
    const fn has_result(&self) -> bool {
        matches!(self, Self::Done(_) | Self::Refused(..))
    }
}

impl Plan {
    /// Whether every step the plan holds has a result, so that nothing is owed.
    fn complete(&self) -> bool {
        let forward = self.steps.iter().all(|step| step.state.has_result());
        let undone = !self.undoing || self.missing_undo().is_empty();
        forward && undone && self.undo.iter().all(|step| step.state.has_result())
    }

    /// The environments the merge moved that have no step putting them back, once the owner has
    /// asked for the merge to be undone.
    fn missing_undo(&self) -> Vec<usize> {
        if !self.undoing {
            return Vec::new();
        }
        self.steps
            .iter()
            .enumerate()
            .filter(|(_, step)| {
                matches!(step.state, StepState::Done(_))
                    && !self
                        .undo
                        .iter()
                        .any(|undo| undo.environment_id == step.environment_id)
            })
            .map(|(index, _)| index)
            .collect()
    }

    /// Gives each environment the merge moved a step that puts it back into the group it left,
    /// against the record its own step left. Nothing is sent: the steps are composed by the
    /// connection that sends them.
    fn with_the_missing_undo(&mut self) {
        for index in self.missing_undo() {
            let step = &self.steps[index];
            let StepState::Done(group) = &step.state else {
                continue;
            };
            let undo = PlannedStep {
                environment_id: step.environment_id,
                reach: step.reach.clone(),
                expected: MachineExpected {
                    machine_id: group.machine_id,
                    revision: group.revision,
                },
                into: self.from,
                action_id: ActionId::new(kr_ipc::new_uuid()),
                mutation: None,
                state: StepState::Unsent,
            };
            self.undo.push(undo);
        }
    }
}

fn plan_path(paths: &HostPaths) -> PathBuf {
    paths.state_root().join(PLAN_FILE)
}

/// The lock one command holds on the plan for as long as it works on it.
///
/// An exclusive advisory lock on a file of its own, because the plan is replaced by renaming a new
/// file over it each time it is saved, which no lock on the plan itself could outlast. The file is
/// never removed: removing a lock file lets a second command lock the one that is gone.
struct PlanLock {
    /// Held open: the lock is released when the file is closed.
    _file: std::fs::File,
}

/// Takes the plan's lock, or says that another command holds it.
fn lock_plan(paths: &HostPaths) -> Result<PlanLock> {
    let path = paths.state_root().join(PLAN_LOCK_FILE);
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(kr_ipc::paths::OWNER_ONLY_FILE_MODE);
    }
    let unusable = |_| {
        CliError::Other(Shown::said(
            "the lock on the merge plan could not be taken in this user's state directory",
        ))
    };
    let file = options.open(&path).map_err(unusable)?;
    match file.try_lock() {
        Ok(()) => Ok(PlanLock { _file: file }),
        Err(std::fs::TryLockError::WouldBlock) => Err(CliError::Other(Shown::said(
            "another kr host machine command is working on the merge plan: run this one again \
             once it has ended",
        ))),
        Err(std::fs::TryLockError::Error(error)) => Err(unusable(error)),
    }
}

/// Reads the plan this client keeps, if it keeps one.
fn load(paths: &HostPaths) -> Result<Option<Plan>> {
    let path = plan_path(paths);
    let Some(bytes) = kr_ipc::paths::read_owner_only_file(&path, PLAN_LIMIT)? else {
        return Ok(None);
    };
    let limits = kr_cbor::Limits {
        max_message_len: bytes.len(),
        max_items: bytes.len(),
        max_collection_len: bytes.len(),
        ..kr_cbor::Limits::DEFAULT
    };
    kr_cbor::from_canonical_slice(&bytes, &limits)
        .map(Some)
        .map_err(|_| {
            CliError::Other(Shown::said(
                "the merge plan this client keeps cannot be read; it is in this user's state \
                 directory as machine-merge-plan, and the owner selects the environments again \
                 once it is moved aside",
            ))
        })
}

fn encoded(plan: &Plan) -> Result<Vec<u8>> {
    kr_cbor::to_canonical_vec(plan)
        .map_err(|_| CliError::Other(Shown::said("the merge plan could not be encoded")))
}

/// Keeps the plan, replacing what was kept.
fn save(paths: &HostPaths, plan: &Plan) -> Result<()> {
    kr_ipc::paths::write_owner_only_file(&plan_path(paths), &encoded(plan)?)?;
    Ok(())
}

/// Removes the plan once nothing is owed.
fn finished(paths: &HostPaths) -> Result<()> {
    match std::fs::remove_file(plan_path(paths)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CliError::Other(Shown::said(
            "the merge plan is complete and could not be removed from this user's state directory",
        ))),
    }
}

/// `kr host machine merge --from`: records the plan, keeps it, and takes each step.
async fn plan_made(
    paths: &HostPaths,
    named: &[String],
    into: MachineId,
    from: MachineId,
    json: bool,
) -> Result<Completion> {
    let _lock = lock_plan(paths)?;
    if load(paths)?.is_some() {
        return Err(CliError::Usage(Shown::said(
            "a merge plan is kept already: kr host machine plan shows it, and finish or undo \
             takes it to its results",
        )));
    }
    if named.is_empty() {
        return Err(CliError::Usage(Shown::said(
            "a merge plan names the environments it moves with --environment, once for each",
        )));
    }
    // What each environment reports of itself is what its step is approved against: read when the
    // plan is made, from the environment's own record. Nothing is composed or sent yet.
    let mut steps = Vec::new();
    for text in named {
        let (environment_id, reach) = select(paths, text).await?;
        if steps
            .iter()
            .any(|step: &PlannedStep| step.environment_id == environment_id)
        {
            return Err(CliError::Usage(Shown::said(
                "an environment is named twice in one merge plan",
            )));
        }
        let mut reached = reach_environment(paths, environment_id, &reach).await?;
        let reported = reached.host_info().await;
        reached.close().await;
        let group = reported?.machine.ok_or_else(|| {
            CliError::Usage(Shown::said(
                "an environment named in the plan reports no machine group, so there is nothing \
                 to merge it out of",
            ))
        })?;
        if group.machine_id != from {
            return Err(CliError::Usage(Shown::said(
                "an environment named in the plan reports another group than the one being merged \
                 away: kr host machine shows each environment's",
            )));
        }
        steps.push(PlannedStep {
            environment_id,
            reach,
            expected: MachineExpected {
                machine_id: group.machine_id,
                revision: group.revision,
            },
            into,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            mutation: None,
            state: StepState::Unsent,
        });
    }
    let plan = Plan {
        into,
        from,
        steps,
        undo: Vec::new(),
        undoing: false,
    };
    // Written before anything is sent, and never replaced by another: a second plan would be a
    // second set of steps for the same environments.
    kr_ipc::paths::create_new_owner_only_file(&plan_path(paths), &encoded(&plan)?)?;
    take_steps(paths, plan, json).await
}

/// `kr host machine plan`.
fn plan_shown(paths: &HostPaths, json: bool) -> Result<()> {
    match load(paths)? {
        None => {
            if json {
                output::document(&Document::new().with("ok", true).with("plan", None::<bool>));
            } else {
                output::say(&Shown::said("no merge plan is kept"));
            }
        }
        Some(plan) => {
            if json {
                output::document(&plan_document(&plan, true));
            } else {
                output::lines(&plan_lines(&plan));
            }
        }
    }
    Ok(())
}

/// `kr host machine finish`.
async fn finish(paths: &HostPaths, json: bool) -> Result<Completion> {
    // The plan is read under the lock, never before it: another command may be taking it to its
    // results, or may have.
    let _lock = lock_plan(paths)?;
    let Some(plan) = load(paths)? else {
        return Err(CliError::Usage(Shown::said("no merge plan is kept")));
    };
    take_steps(paths, plan, json).await
}

/// `kr host machine undo`.
async fn undo(paths: &HostPaths, json: bool) -> Result<Completion> {
    let _lock = lock_plan(paths)?;
    let Some(mut plan) = load(paths)? else {
        return Err(CliError::Usage(Shown::said("no merge plan is kept")));
    };
    // A step that may or may not have been taken has to be finished before the merge is undone:
    // undoing the environments that moved, and leaving this one to move later, would leave the
    // owner with the merge half done the other way round.
    if plan
        .steps
        .iter()
        .any(|step| matches!(step.state, StepState::Sent))
    {
        return Err(CliError::Usage(Shown::said(
            "a step was sent and what the environment did with it is not known: kr host machine \
             finish asks it again and says, and the merge is undone after that",
        )));
    }
    plan.undoing = true;
    for step in &mut plan.steps {
        if matches!(step.state, StepState::Unsent) {
            step.state = StepState::Refused(ErrorCode::InvalidArgument, Why::GivenUp);
        }
    }
    // Each moved environment gets a step that goes back, against the record the first one left. They
    // are kept in the same save as the owner's asking, so that no plan kept asks for an undo and
    // lacks a step.
    plan.with_the_missing_undo();
    save(paths, &plan)?;
    take_steps(paths, plan, json).await
}

/// Takes each step of the plan that has no result, in order, keeping the plan as each answer
/// arrives, and removes the plan once nothing is owed.
async fn take_steps(paths: &HostPaths, mut plan: Plan, json: bool) -> Result<Completion> {
    for index in 0..plan.steps.len() {
        advance(paths, &mut plan, Which::Forward, index).await?;
    }
    for index in 0..plan.undo.len() {
        advance(paths, &mut plan, Which::Undo, index).await?;
    }
    let complete = plan.complete();
    let pending = plan
        .steps
        .iter()
        .chain(plan.undo.iter())
        .any(|step| !step.state.has_result());
    let refused = plan.steps.iter().chain(plan.undo.iter()).any(|step| {
        matches!(
            step.state,
            StepState::Refused(_, Why::Environment | Why::Moved)
        )
    });
    // What the plan came to is said whether or not the file could be removed.
    let removal = if complete { finished(paths) } else { Ok(()) };
    let failure = if pending {
        Some(CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: Shown::said(
                "a step has no result yet: kr host machine finish takes it again once its \
                 environment can be reached and can answer",
            ),
        })
    } else if refused {
        Some(CliError::Unfinished {
            code: ErrorCode::DraftConflict,
            message: Shown::said(
                "a step was refused, so the merge is not whole: each environment reports its own \
                 group, and kr host machine join puts one back where it was",
            ),
        })
    } else {
        None
    };
    report_plan(&plan, !complete, failure.as_ref(), json);
    removal?;
    Ok(failure.map_or(Completion::Done, Completion::Reported))
}

/// Writes what the plan has come to, with the failure beside it where there is one.
fn report_plan(plan: &Plan, kept: bool, failure: Option<&CliError>, json: bool) {
    if json {
        let document = plan_document(plan, kept);
        output::document(&match failure {
            Some(error) => crate::report::with_failure(document, error),
            None => document,
        });
        return;
    }
    output::lines(&plan_lines(plan));
    if !kept {
        output::say(&Shown::said(
            "every step has a result, so the plan is no longer kept",
        ));
        if failure.is_some() {
            output::lines(&put_back_lines(plan));
        }
    }
    if let Some(error) = failure {
        crate::report::failed(error);
    }
}

#[derive(Clone, Copy)]
enum Which {
    Forward,
    Undo,
}

fn step_mut(plan: &mut Plan, which: Which, index: usize) -> &mut PlannedStep {
    match which {
        Which::Forward => &mut plan.steps[index],
        Which::Undo => &mut plan.undo[index],
    }
}

/// Takes one step to its result, or leaves it pending where its environment cannot be reached.
async fn advance(paths: &HostPaths, plan: &mut Plan, which: Which, index: usize) -> Result<()> {
    let (environment_id, reach, state) = {
        let step = step_mut(plan, which, index);
        (step.environment_id, step.reach.clone(), step.state.clone())
    };
    if state.has_result() {
        return Ok(());
    }
    let Ok(mut reached) = reach_environment(paths, environment_id, &reach).await else {
        return Ok(());
    };
    let outcome = attempt(paths, plan, which, index, &mut reached).await;
    reached.close().await;
    outcome
}

/// The mutation a step sends, composed on `reached` under `action_id`: this connection's window.
async fn compose_step(
    reached: &mut Reached,
    which: Which,
    step: &PlannedStep,
    action_id: ActionId,
) -> Result<MutationRequest> {
    match which {
        Which::Forward => {
            reached
                .compose(
                    Method::MachineMerge,
                    action_id,
                    &MachineMergeParams {
                        machine_id: step.into,
                        expected: step.expected.clone(),
                    },
                )
                .await
        }
        Which::Undo => {
            reached
                .compose(
                    Method::MachineJoin,
                    action_id,
                    &MachineJoinParams {
                        machine_id: step.into,
                        expected: step.expected.clone(),
                    },
                )
                .await
        }
    }
}

/// Records what a step came to.
fn conclude(
    paths: &HostPaths,
    plan: &mut Plan,
    which: Which,
    index: usize,
    state: StepState,
) -> Result<()> {
    step_mut(plan, which, index).state = state;
    save(paths, plan)
}

/// What a step came to on one connection.
async fn attempt(
    paths: &HostPaths,
    plan: &mut Plan,
    which: Which,
    index: usize,
    reached: &mut Reached,
) -> Result<()> {
    let stored = step_mut(plan, which, index).mutation.clone();
    // A step no environment was sent is composed here, under its own identity, on this connection:
    // the window it quotes is this connection's, so nothing but a refusal the environment decides
    // can stop it.
    let fresh = stored.is_none();
    let mutation = match stored {
        Some(mutation) => mutation,
        None => {
            let step = step_mut(plan, which, index).clone();
            match compose_step(reached, which, &step, step.action_id).await {
                Ok(mutation) => mutation,
                // Not composed, so not sent: the step stays unsent.
                Err(_) => return Ok(()),
            }
        }
    };
    // The state is written before the step is sent: a step that is sent and not kept as sent is a
    // step this client would take for unsent, and give up.
    {
        let step = step_mut(plan, which, index);
        step.mutation = Some(mutation.clone());
        step.state = StepState::Sent;
    }
    save(paths, plan)?;
    let answered = match reached.send(&mutation).await {
        Ok(answered) => answered,
        // The connection failed after the step may have been sent: it stays sent, and pending.
        Err(_) => return Ok(()),
    };
    match answered {
        Ok(value) => taken(paths, plan, which, index, &value),
        // No receipt answered it. What the environment reports says what it came to.
        Err(error) => settle(paths, plan, which, index, reached, error, fresh).await,
    }
}

/// Records the result an environment answered a step with.
fn taken(
    paths: &HostPaths,
    plan: &mut Plan,
    which: Which,
    index: usize,
    value: &ParamsValue,
) -> Result<()> {
    let result: MachineStepResult = value.to_typed().map_err(|_| {
        CliError::Other(Shown::said(
            "the environment's answer could not be read as a machine group step",
        ))
    })?;
    conclude(paths, plan, which, index, StepState::Done(result.machine))
}

/// What reading an environment says about a step it refused or could not answer.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The environment took it, and records this.
    Done(MachineGroup),
    /// It will not be taken.
    Refused(ErrorCode, Why),
    /// It may still be taken, or answered, and nothing more is done now: it stays sent.
    Pending,
    /// Nothing was applied and the action cannot be asked again: the step is composed again under a
    /// new action, against the same record.
    AskAgain,
}

/// Decides what a step an environment refused, or could not answer, has come to, from what the
/// environment reports now.
///
/// Every action a step is sent under carries the same record as its precondition, so at most one of
/// them applies. `fresh` says the refused mutation was composed on the connection that sent it, and
/// so was not refused for the window it quotes.
fn judge(
    step: &PlannedStep,
    record: Option<&MachineGroup>,
    code: ErrorCode,
    fresh: bool,
) -> Verdict {
    let Some(group) = record else {
        // An environment with no usable record takes no step.
        return Verdict::Refused(ErrorCode::StorageUnavailable, Why::Environment);
    };
    if group.machine_id == step.expected.machine_id && group.revision == step.expected.revision {
        // Nothing was applied.
        return match (fresh, code) {
            // The first action is still running in the environment, and may yet apply.
            (false, ErrorCode::ResourceUnavailable) => Verdict::Pending,
            // A mutation sent again was refused for its window, or an action the environment kept
            // a refusal for, or one it cannot finish: it is composed again under a new action.
            (false, _) => Verdict::AskAgain,
            // A step composed here and refused as the owner's authority is not the owner's.
            (true, ErrorCode::PermissionDenied) => {
                Verdict::Refused(ErrorCode::PermissionDenied, Why::Environment)
            }
            // A step the environment could not write, or answer, or is still running, may be taken
            // later: it stays sent.
            (
                true,
                ErrorCode::ResourceUnavailable
                | ErrorCode::StorageUnavailable
                | ErrorCode::OutcomeUnknown
                | ErrorCode::DraftConflict,
            ) => Verdict::Pending,
            (true, other) => Verdict::Refused(other, Why::Environment),
        };
    }
    if group.machine_id == step.into
        && group.revision == U64::new(step.expected.revision.get().saturating_add(1))
        && group.previous.as_ref() == Some(&step.expected.machine_id)
        && matches!(group.change, MachineChange::Merged | MachineChange::Joined)
    {
        // The record shows the step was taken. An environment that could not say whether its
        // change survives a crash has not said it was taken: that stays to be answered.
        return if code == ErrorCode::OutcomeUnknown {
            Verdict::Pending
        } else {
            Verdict::Done(group.clone())
        };
    }
    Verdict::Refused(ErrorCode::DraftConflict, Why::Moved)
}

/// Reads an environment that refused a step, or could not answer it, and decides what the step came
/// to. A step composed again is taken once, and what the environment answers it is read the same
/// way.
async fn settle(
    paths: &HostPaths,
    plan: &mut Plan,
    which: Which,
    index: usize,
    reached: &mut Reached,
    mut error: ProtocolError,
    mut fresh: bool,
) -> Result<()> {
    loop {
        // A refusal the environment decides against the request, such as a join into the group it
        // is in, is final whatever it holds.
        if error.code == ErrorCode::InvalidArgument {
            return conclude(
                paths,
                plan,
                which,
                index,
                StepState::Refused(error.code, Why::Environment),
            );
        }
        let Ok(info) = reached.host_info().await else {
            // What the environment holds is not known, and the step stays sent.
            return Ok(());
        };
        let step = step_mut(plan, which, index).clone();
        match judge(&step, info.machine.as_ref(), error.code, fresh) {
            Verdict::Done(group) => {
                return conclude(paths, plan, which, index, StepState::Done(group));
            }
            Verdict::Refused(code, why) => {
                return conclude(paths, plan, which, index, StepState::Refused(code, why));
            }
            Verdict::Pending => return Ok(()),
            Verdict::AskAgain => {
                let action_id = ActionId::new(kr_ipc::new_uuid());
                let Ok(mutation) = compose_step(reached, which, &step, action_id).await else {
                    return Ok(());
                };
                {
                    let step = step_mut(plan, which, index);
                    step.action_id = action_id;
                    step.mutation = Some(mutation.clone());
                    step.state = StepState::Sent;
                }
                save(paths, plan)?;
                match reached.send(&mutation).await {
                    Ok(Ok(value)) => return taken(paths, plan, which, index, &value),
                    Ok(Err(refused)) => {
                        error = refused;
                        fresh = true;
                    }
                    // Sent, and not known: it stays sent.
                    Err(_) => return Ok(()),
                }
            }
        }
    }
}

/* -------------------------------------------------------------------------------------------- */
/* What a plan says                                                                             */
/* -------------------------------------------------------------------------------------------- */

fn state_words(state: &StepState) -> Shown {
    match state {
        StepState::Unsent => Shown::said("not sent"),
        StepState::Sent => Shown::said("sent, and what the environment did is not known yet"),
        StepState::Done(group) => shown!(
            "taken: it records group {} at revision {}",
            group.machine_id.get(),
            group.revision
        ),
        StepState::Refused(code, Why::Environment) => {
            shown!("refused by the environment ({})", *code)
        }
        StepState::Refused(code, Why::Moved) => shown!(
            "not taken: the environment's record is no longer the one it was approved against \
             ({})",
            *code
        ),
        StepState::Refused(_, Why::GivenUp) => Shown::said("given up before it was sent"),
    }
}

fn plan_lines(plan: &Plan) -> Vec<Line> {
    let mut lines = vec![stdout_line!(
        "Merging group {} into group {}.",
        plan.from.get(),
        plan.into.get()
    )];
    for step in &plan.steps {
        lines.push(stdout_line!(
            "  Environment {}: {}.",
            step.environment_id,
            state_words(&step.state)
        ));
    }
    for step in &plan.undo {
        lines.push(stdout_line!(
            "  Putting environment {} back: {}.",
            step.environment_id,
            state_words(&step.state)
        ));
    }
    lines
}

/// What a person types to put back each environment a finished plan left moved, where some other
/// step of it was refused and the plan, with every step resulted, is no longer kept.
fn put_back_lines(plan: &Plan) -> Vec<Line> {
    plan.steps
        .iter()
        .filter_map(|step| match &step.state {
            StepState::Done(group)
                if !plan
                    .undo
                    .iter()
                    .any(|undo| undo.environment_id == step.environment_id) =>
            {
                Some(stdout_line!(
                    "To put environment {} back: kr host machine join {} --expect {}@{} \
                     --environment {}",
                    step.environment_id,
                    plan.from.get(),
                    group.machine_id.get(),
                    group.revision,
                    step.environment_id
                ))
            }
            _ => None,
        })
        .collect()
}

fn step_document(step: &PlannedStep) -> Document {
    let (state, machine) = match &step.state {
        StepState::Unsent => (Shown::said("unsent"), None),
        StepState::Sent => (Shown::said("sent"), None),
        StepState::Done(group) => (Shown::said("done"), Some(group_value(group))),
        StepState::Refused(..) => (Shown::said("refused"), None),
    };
    let document = Document::new()
        .with("environment_id", output::closed(&step.environment_id))
        .with("action_id", output::closed(&step.action_id))
        .with("state", state)
        .with("machine", machine);
    match &step.state {
        StepState::Refused(code, why) => document.with("code", Shown::said(code.as_str())).with(
            "reason",
            Shown::said(match why {
                Why::Environment => "environment",
                Why::Moved => "moved",
                Why::GivenUp => "given_up",
            }),
        ),
        _ => document,
    }
}

fn plan_document(plan: &Plan, kept: bool) -> Document {
    Document::new()
        .with("ok", true)
        .with("kept", kept)
        .with("into", shown!("{}", plan.into.get()))
        .with("from", shown!("{}", plan.from.get()))
        .with(
            "steps",
            plan.steps.iter().map(step_document).collect::<Vec<_>>(),
        )
        .with(
            "undo",
            plan.undo.iter().map(step_document).collect::<Vec<_>>(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(
        machine_id: u8,
        revision: u64,
        change: MachineChange,
        previous: Option<u8>,
    ) -> MachineGroup {
        MachineGroup {
            machine_id: MachineId::new(kr_protocol::scalars::Uuid::from_bytes([machine_id; 16])),
            revision: U64::new(revision),
            change,
            previous: previous.map_or_else(Nullable::null, |previous| {
                Nullable::some(MachineId::new(kr_protocol::scalars::Uuid::from_bytes(
                    [previous; 16],
                )))
            }),
        }
    }

    /// A merge step approved against group 1 at revision 3, into group 2.
    fn step() -> PlannedStep {
        let mutation = None;
        PlannedStep {
            environment_id: EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16])),
            reach: Reach::Own,
            expected: MachineExpected {
                machine_id: MachineId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
                revision: U64::new(3),
            },
            into: MachineId::new(kr_protocol::scalars::Uuid::from_bytes([2; 16])),
            action_id: ActionId::new(kr_ipc::new_uuid()),
            mutation,
            state: StepState::Sent,
        }
    }

    fn at_the_precondition() -> MachineGroup {
        group(1, 3, MachineChange::Joined, Some(7))
    }
    fn one_step_on() -> MachineGroup {
        group(2, 4, MachineChange::Merged, Some(1))
    }
    fn elsewhere() -> MachineGroup {
        group(5, 9, MachineChange::Split, Some(1))
    }

    /// KR-REQ-03.07: an environment that took the step another way, or whose record shows it, has
    /// the step taken; one that moved elsewhere has it refused for good; one with no record has
    /// it refused; and no answer that leaves it unknown whether the step was taken is called taken.
    #[test]
    fn what_an_environment_reports_decides_what_a_refused_step_has_come_to() {
        let step = step();
        let taken = one_step_on();
        for code in [
            ErrorCode::PermissionDenied,
            ErrorCode::DraftConflict,
            ErrorCode::StorageUnavailable,
            ErrorCode::ResourceUnavailable,
        ] {
            for fresh in [false, true] {
                assert_eq!(
                    judge(&step, Some(&taken), code, fresh),
                    Verdict::Done(taken.clone()),
                    "{code:?}, fresh {fresh}: the record shows the step was taken"
                );
            }
        }
        // A step the environment could not say it took is not called taken from its record alone.
        for fresh in [false, true] {
            assert_eq!(
                judge(&step, Some(&taken), ErrorCode::OutcomeUnknown, fresh),
                Verdict::Pending,
                "fresh {fresh}"
            );
        }
        // Another change at another revision, or another group, can never apply.
        let elsewhere = elsewhere();
        let one_on_into_another_group = group(5, 4, MachineChange::Merged, Some(1));
        let two_on = group(2, 5, MachineChange::Merged, Some(1));
        let one_on_from_another = group(2, 4, MachineChange::Merged, Some(8));
        for moved in [
            &elsewhere,
            &one_on_into_another_group,
            &two_on,
            &one_on_from_another,
        ] {
            assert_eq!(
                judge(&step, Some(moved), ErrorCode::DraftConflict, false),
                Verdict::Refused(ErrorCode::DraftConflict, Why::Moved),
                "{moved:?}"
            );
        }
        // An environment with no usable record takes no step.
        assert_eq!(
            judge(&step, None, ErrorCode::PermissionDenied, false),
            Verdict::Refused(ErrorCode::StorageUnavailable, Why::Environment)
        );
    }

    /// KR-REQ-03.07: at the record the step was approved against, nothing was applied. A mutation
    /// sent again that is refused is composed again under a new action, unless its first action is
    /// still running; one composed on the connection that sent it is not given up for an answer
    /// that says it may yet be taken, and a refusal of the owner's authority is final.
    #[test]
    fn at_the_precondition_a_step_is_asked_again_once_and_never_while_it_may_still_be_taken() {
        let step = step();
        let at = at_the_precondition();
        for code in [
            ErrorCode::PermissionDenied,
            ErrorCode::DraftConflict,
            ErrorCode::StorageUnavailable,
            ErrorCode::OutcomeUnknown,
            ErrorCode::IdConflict,
        ] {
            assert_eq!(
                judge(&step, Some(&at), code, false),
                Verdict::AskAgain,
                "{code:?}: a mutation sent again"
            );
        }
        assert_eq!(
            judge(&step, Some(&at), ErrorCode::ResourceUnavailable, false),
            Verdict::Pending,
            "the first action is still running, and a second identity would race it"
        );
        for code in [
            ErrorCode::ResourceUnavailable,
            ErrorCode::StorageUnavailable,
            ErrorCode::OutcomeUnknown,
            ErrorCode::DraftConflict,
        ] {
            assert_eq!(
                judge(&step, Some(&at), code, true),
                Verdict::Pending,
                "{code:?}: a step composed here that may be taken later"
            );
        }
        assert_eq!(
            judge(&step, Some(&at), ErrorCode::PermissionDenied, true),
            Verdict::Refused(ErrorCode::PermissionDenied, Why::Environment)
        );
        assert_eq!(
            judge(&step, Some(&at), ErrorCode::IdConflict, true),
            Verdict::Refused(ErrorCode::IdConflict, Why::Environment)
        );
    }

    /// KR-REQ-03.07: a plan that asks for an undo has a step for each environment its merge moved,
    /// whichever command made them, and is not complete without them.
    #[test]
    fn a_plan_that_asks_for_an_undo_has_a_step_for_each_environment_it_moved() {
        let mut moved = step();
        moved.state = StepState::Done(one_step_on());
        let mut never_sent = step();
        never_sent.environment_id =
            EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([8; 16]));
        never_sent.state = StepState::Refused(ErrorCode::InvalidArgument, Why::GivenUp);
        let mut plan = Plan {
            into: moved.into,
            from: moved.expected.machine_id,
            steps: vec![moved, never_sent],
            undo: Vec::new(),
            undoing: false,
        };
        assert!(plan.missing_undo().is_empty(), "nothing asked for an undo");
        assert!(plan.complete());

        plan.undoing = true;
        assert_eq!(plan.missing_undo(), vec![0], "the environment that moved");
        assert!(!plan.complete(), "an undo is owed");

        plan.with_the_missing_undo();
        assert!(plan.missing_undo().is_empty());
        assert_eq!(plan.undo.len(), 1);
        assert_eq!(plan.undo[0].environment_id, plan.steps[0].environment_id);
        assert_eq!(
            plan.undo[0].into, plan.from,
            "it goes back to the group it left"
        );
        assert_eq!(
            plan.undo[0].expected,
            MachineExpected {
                machine_id: one_step_on().machine_id,
                revision: one_step_on().revision,
            },
            "against the record its own step left"
        );
        assert!(plan.undo[0].mutation.is_none(), "nothing was sent");
        assert!(!plan.complete(), "the undo step has no result");
        plan.undo[0].state = StepState::Refused(ErrorCode::DraftConflict, Why::Moved);
        assert!(plan.complete());
    }
}
