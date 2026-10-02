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
//! environment, the step as it was composed (its precondition, its own action identity and the
//! action window it quotes) and what it has come to. The plan is a file only the owner reads, in
//! this user's own state directory and never in an environment's, written before the first step is
//! sent and rewritten as each answer arrives, and it is deleted when every step has a result.
//!
//! - `finish` sends each step that has no result again exactly as it was composed. An environment
//!   that took it answers from its receipt, and one that did not takes it now. A step the
//!   environment refuses without a receipt (its window is gone, or it never saw it) is read against
//!   what the environment reports: at the precondition nothing was applied, and the step is
//!   composed again under a new action identity; one step on, the record shows it was taken; and
//!   anywhere else it can never apply and is given its refusal. An environment that cannot be
//!   reached stays pending.
//! - `undo` moves each environment the plan moved back into the group it left, by a step of its own
//!   against the record the first one left. A step that was never sent is given up. One that may or
//!   may not have been taken has to be finished first, because undoing an environment that may
//!   still move would leave it moved.
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
    /// mutation quotes and on whatever connection it arrives.
    async fn send(
        &mut self,
        mutation: &MutationRequest,
    ) -> Result<std::result::Result<ParamsValue, ProtocolError>> {
        match &mut self.channel {
            Channel::Local(client) => Ok(client.repeat(mutation).await?),
            Channel::Bridged { invocation, .. } => {
                let mut mutation = mutation.clone();
                mutation.request_id = RequestId::new(self.next_request);
                self.next_request += 1;
                let answer = invocation.mutate(mutation).await.map_err(bridge_failure)?;
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
             be used and kr doctor says what to do.",
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
    /// The step as it was composed, which is sent again exactly as it is.
    mutation: MutationRequest,
    state: StepState,
}

/// What one step has come to.
#[derive(Clone, Debug, Serialize, Deserialize)]
enum StepState {
    /// Composed and not sent.
    Unsent,
    /// Sent, and what the environment did with it is not known yet.
    Sent,
    /// The environment took it, and records this.
    Done(MachineGroup),
    /// It will not be taken, and why.
    Refused(ErrorCode, Why),
}

/// Where a refusal came from.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
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
        let undone = !self.undoing
            || self.steps.iter().all(|step| match step.state {
                StepState::Done(_) => self.undo.iter().any(|undo| {
                    undo.environment_id == step.environment_id && undo.state.has_result()
                }),
                _ => true,
            });
        forward && undone && self.undo.iter().all(|step| step.state.has_result())
    }
}

fn plan_path(paths: &HostPaths) -> PathBuf {
    paths.state_root().join(PLAN_FILE)
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

/// `kr host machine merge --from`: composes the plan, keeps it, and takes each step.
async fn plan_made(
    paths: &HostPaths,
    named: &[String],
    into: MachineId,
    from: MachineId,
    json: bool,
) -> Result<Completion> {
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
    // plan is made, from the environment's own record.
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
        let composed = async {
            let group = reached.host_info().await?.machine.ok_or_else(|| {
                CliError::Usage(Shown::said(
                    "an environment named in the plan reports no machine group, so there is \
                     nothing to merge it out of",
                ))
            })?;
            if group.machine_id != from {
                return Err(CliError::Usage(Shown::said(
                    "an environment named in the plan reports another group than the one being \
                     merged away: kr host machine shows each environment's",
                )));
            }
            let expected = MachineExpected {
                machine_id: group.machine_id,
                revision: group.revision,
            };
            let mutation = reached
                .compose(
                    Method::MachineMerge,
                    ActionId::new(kr_ipc::new_uuid()),
                    &MachineMergeParams {
                        machine_id: into,
                        expected: expected.clone(),
                    },
                )
                .await?;
            Ok(PlannedStep {
                environment_id,
                reach,
                expected,
                into,
                mutation,
                state: StepState::Unsent,
            })
        }
        .await;
        reached.close().await;
        steps.push(composed?);
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
    take_steps(paths, plan, json, None).await
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
    let Some(plan) = load(paths)? else {
        return Err(CliError::Usage(Shown::said("no merge plan is kept")));
    };
    take_steps(paths, plan, json, None).await
}

/// `kr host machine undo`.
async fn undo(paths: &HostPaths, json: bool) -> Result<Completion> {
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
    save(paths, &plan)?;
    // Each moved environment gets a step that goes back, against the record the first one left.
    let moved: Vec<(EnvironmentId, Reach, MachineGroup)> = plan
        .steps
        .iter()
        .filter_map(|step| match &step.state {
            StepState::Done(group)
                if !plan
                    .undo
                    .iter()
                    .any(|undo| undo.environment_id == step.environment_id) =>
            {
                Some((step.environment_id, step.reach.clone(), group.clone()))
            }
            _ => None,
        })
        .collect();
    let mut unreachable = false;
    for (environment_id, reach, group) in moved {
        let mut reached = match reach_environment(paths, environment_id, &reach).await {
            Ok(reached) => reached,
            Err(_) => {
                unreachable = true;
                continue;
            }
        };
        let expected = MachineExpected {
            machine_id: group.machine_id,
            revision: group.revision,
        };
        let composed = reached
            .compose(
                Method::MachineJoin,
                ActionId::new(kr_ipc::new_uuid()),
                &MachineJoinParams {
                    machine_id: plan.from,
                    expected: expected.clone(),
                },
            )
            .await;
        reached.close().await;
        match composed {
            Ok(mutation) => {
                plan.undo.push(PlannedStep {
                    environment_id,
                    reach,
                    expected,
                    into: plan.from,
                    mutation,
                    state: StepState::Unsent,
                });
                save(paths, &plan)?;
            }
            Err(_) => unreachable = true,
        }
    }
    let owed = unreachable.then(|| CliError::Unfinished {
        code: ErrorCode::EnvironmentUnavailable,
        message: Shown::said(
            "an environment the merge moved could not be reached to put it back: run kr host \
             machine undo again once it can be",
        ),
    });
    take_steps(paths, plan, json, owed).await
}

/// Takes each step of the plan that has no result, in order, keeping the plan as each answer
/// arrives, and removes the plan once nothing is owed.
async fn take_steps(
    paths: &HostPaths,
    mut plan: Plan,
    json: bool,
    owed: Option<CliError>,
) -> Result<Completion> {
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
    if complete {
        finished(paths)?;
    }
    let failure = if pending {
        Some(CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: Shown::said(
                "a step has no result yet: kr host machine finish takes it again once its \
                 environment can be reached",
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
        owed
    };
    report_plan(&plan, !complete, failure.as_ref(), json);
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

/// What a step came to on one connection.
async fn attempt(
    paths: &HostPaths,
    plan: &mut Plan,
    which: Which,
    index: usize,
    reached: &mut Reached,
) -> Result<()> {
    // The state is written before the step is sent: a step that is sent and not kept as sent is a
    // step this client would take for unsent, and give up.
    step_mut(plan, which, index).state = StepState::Sent;
    save(paths, plan)?;
    let mutation = step_mut(plan, which, index).mutation.clone();
    let answered = match reached.send(&mutation).await {
        Ok(answered) => answered,
        // The connection failed after the step may have been sent: it stays sent, and pending.
        Err(_) => return Ok(()),
    };
    match answered {
        Ok(value) => {
            let taken: MachineStepResult = value.to_typed().map_err(|_| {
                CliError::Other(Shown::said(
                    "the environment's answer could not be read as a machine group step",
                ))
            })?;
            step_mut(plan, which, index).state = StepState::Done(taken.machine);
            save(paths, plan)
        }
        // No receipt answered it. What the environment reports says whether it was taken.
        Err(error) => resolve(paths, plan, which, index, reached, error).await,
    }
}

/// Reads an environment that gave no receipt for a step, and decides what the step came to.
async fn resolve(
    paths: &HostPaths,
    plan: &mut Plan,
    which: Which,
    index: usize,
    reached: &mut Reached,
    error: ProtocolError,
) -> Result<()> {
    let Ok(info) = reached.host_info().await else {
        // What the environment holds is not known, and the step stays sent.
        return Ok(());
    };
    let (expected, into, forward) = {
        let step = step_mut(plan, which, index);
        (
            step.expected.clone(),
            step.into,
            matches!(which, Which::Forward),
        )
    };
    let now = info.machine;
    let state = match now {
        None => StepState::Refused(error.code, Why::Environment),
        Some(group)
            if group.machine_id == expected.machine_id && group.revision == expected.revision =>
        {
            // Nothing was applied. The step is composed again under a new action, and taken once:
            // what it answers is its result.
            let params_method = if forward {
                Method::MachineMerge
            } else {
                Method::MachineJoin
            };
            let action_id = ActionId::new(kr_ipc::new_uuid());
            let fresh = if forward {
                reached
                    .compose(
                        params_method,
                        action_id,
                        &MachineMergeParams {
                            machine_id: into,
                            expected: expected.clone(),
                        },
                    )
                    .await?
            } else {
                reached
                    .compose(
                        params_method,
                        action_id,
                        &MachineJoinParams {
                            machine_id: into,
                            expected: expected.clone(),
                        },
                    )
                    .await?
            };
            step_mut(plan, which, index).mutation = fresh.clone();
            save(paths, plan)?;
            match reached.send(&fresh).await {
                Ok(Ok(value)) => {
                    let taken: MachineStepResult = value.to_typed().map_err(|_| {
                        CliError::Other(Shown::said(
                            "the environment's answer could not be read as a machine group step",
                        ))
                    })?;
                    StepState::Done(taken.machine)
                }
                Ok(Err(refused)) => StepState::Refused(refused.code, Why::Environment),
                // Sent, and not known: it stays sent.
                Err(_) => return Ok(()),
            }
        }
        Some(group)
            if group.machine_id == into
                && group.revision == U64::new(expected.revision.get().saturating_add(1))
                && group.previous.as_ref() == Some(&expected.machine_id)
                && matches!(group.change, MachineChange::Merged | MachineChange::Joined) =>
        {
            // The record shows the step was taken, and its receipt is not here to say so.
            StepState::Done(group)
        }
        Some(_) => StepState::Refused(ErrorCode::DraftConflict, Why::Moved),
    };
    step_mut(plan, which, index).state = state;
    save(paths, plan)
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
        .with("action_id", output::closed(&step.mutation.action_id))
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
