//! `kr share`: sharing a session with a paired device, seeing who holds a share, taking one back,
//! and handing a session's control to another device.
//!
//! Every effect here is one of the host's sharing methods over this user's own local socket. The
//! person at this machine is the host's owner, so `grant.create` and `grant.revoke` are theirs to
//! send, and `grant.transfer` is theirs alone: an owner device confirms it.
//!
//! **What a share carries is shown before it exists.** `kr share invite` prints the role in words,
//! the rights it compiles to, when it ends, what the device sees of the session and the host's
//! sentence for each consequence of the rights, and with `--live` the lines on the session's screen
//! now. A share that carries a consequence, or the live screen, is issued only after `share` is
//! typed at the controlling terminal, which has to be outside every KalaReach session: no flag
//! skips that. The preview is the screen as it is when read. It does not bind what the device is
//! drawn when it opens the session, and the command says so. After the host writes the invitation
//! the command compares the lines the host kept with the lines it showed, and prints the revoke
//! command if they differ.
//!
//! **A lost reply is asked about, never answered by guessing.** Each of the four mutations is
//! composed once, and sent as that request. When the reply is lost, the command asks again with
//! exactly that request on a connection of its own, which the host can answer only from the record
//! of the action; a refusal to that question closes nothing. When it cannot be answered, the command
//! reads the host's state, and says an action did not happen only once nothing more of it can,
//! measured on a clock the wall clock cannot move (`kr_client::attempt`). This command keeps no
//! record across a restart: if it ends, `kr share list` shows what the host holds.

use std::time::Duration;

use kr_client::attempt::{Armed, Attempt, Found, Kind, Next, Outcome, REPEAT_DELAYS, Reply};
use kr_client::session::ComposedMutation;
use kr_client::shown;
use kr_client::shown::Shown;
use kr_client::transport::Reach;
use kr_ipc::client::LocalClient;
use kr_ipc::paths::HostPaths;
use kr_protocol::confirmation::{
    ConfirmationSubject, OwnerConfirmationPendingParams, OwnerConfirmationPendingResult,
    OwnerConfirmationRequestParams, OwnerConfirmationRequestResult, TransferControlSubject,
};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, BuildId, DeviceId, GrantId, InvitationId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};
use kr_protocol::sharing::{
    AuthorityNotice, DeviceListParams, DeviceListResult, DeviceSummary, GrantCreateParams,
    GrantCreateResult, GrantListParams, GrantListResult, GrantRevokeParams, GrantState,
    GrantSummary, GrantTransferParams, GrantTransferResult, RevocationResult, RoleSelection,
    SessionRole, SessionScreenPreviewParams, SessionScreenPreviewResult, local_actor,
    share_identities, transfer_identity,
};
use kr_protocol::worker::WorkerDescriptor;

use crate::cli::{
    EnvironmentSelector, ShareCommand, ShareInviteArguments, ShareListArguments,
    ShareRevokeArguments, ShareTransferArguments,
};
use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Line, Request, closed};
use crate::pair::{self, OWNER_DEVICE_POLL};
use crate::report::{self, Completion};
use crate::resolve::{self, KnownEnvironment, SessionSelector};
use crate::stdout_line;

/// What a person types to issue a share that carries a consequence or the live screen.
pub const SHARE_WORD: &str = "share";

/// How long a share lasts when the person names nothing and the device's pairing allows it.
const DEFAULT_LIFETIME_MS: u64 = 60 * 60_000;

/// The shortest share the host is asked for: a pairing with less left than this is paired again.
const MIN_LIFETIME_MS: u64 = 60_000;

/// What is left of a pairing's end for the host to claim the share in: the host dates a share when
/// it accepts the action, a moment after the person pressed enter.
const CLAIM_MARGIN_MS: u64 = 10_000;

/// How often the host's state is read while an attempt waits for the time after which an absent
/// grant counts.
const CHECK_EVERY: Duration = Duration::from_secs(5);

/// How often a reply that is not an answer is asked for again while a transfer's confirmation is
/// waited for.
const POLL_EVERY: Duration = OWNER_DEVICE_POLL;

/// How long one read of the host, with the connection it is made on, is given before it counts as
/// a read that failed.
const READ_WITHIN: Duration = Duration::from_secs(10);

/// How long one send of a request to the host, or one question about it, is given before the
/// answer counts as lost: a host that keeps a connection open and says nothing is a host that did
/// not answer, which a repeat on a connection of its own settles.
const SEND_WITHIN: Duration = Duration::from_secs(30);

/// How long past the time an absent grant counts a command goes on reading a host it cannot read.
/// A read that reaches the host decides at once once the bound has passed, so only a host that
/// cannot be read keeps a command waiting, and for this long at the most.
const READ_PATIENCE: Duration = Duration::from_secs(60);

/// Runs one `kr share` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the host's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, command: ShareCommand, json: bool) -> Result<Completion> {
    let build_id = crate::build_id();
    match command {
        ShareCommand::Invite(arguments) => invite(paths, &arguments, json, &build_id).await,
        ShareCommand::List(arguments) => list(paths, &arguments, json, &build_id)
            .await
            .map(|()| Completion::Done),
        ShareCommand::Revoke(arguments) => revoke(paths, &arguments, json, &build_id).await,
        ShareCommand::Transfer(arguments) => transfer(paths, &arguments, json, &build_id).await,
    }
}

// ---------------------------------------------------------------------------------------------
// What a share is, from what was typed
// ---------------------------------------------------------------------------------------------

/// Reads `--role`.
///
/// # Errors
///
/// Returns a usage mistake for a word that is not a role this command shares as. Reviewer is not
/// one of them: the host decides a reviewer's diffs and change sets under the device's pairing,
/// which a guest does not have.
fn parse_role(text: &str) -> Result<SessionRole> {
    match text {
        "viewer" => Ok(SessionRole::Viewer),
        "controller" => Ok(SessionRole::Controller),
        "owner" => Ok(SessionRole::Owner),
        _ => Err(CliError::Usage(Shown::said(
            "--role is viewer, controller or owner",
        ))),
    }
}

/// Reads `--history` as the cursor the share's earlier activity starts at: none for "from the
/// moment of the invitation", a time before `now_ms` for an hour or a day, and the start of time
/// for everything the host retains.
fn parse_history(text: &str, now_ms: u64) -> Result<Nullable<TimestampMs>> {
    let back = |ms: u64| Nullable::some(TimestampMs::new(now_ms.saturating_sub(ms)));
    match text {
        "none" => Ok(Nullable::null()),
        "1h" => Ok(back(60 * 60_000)),
        "1d" => Ok(back(24 * 60 * 60_000)),
        "all" => Ok(Nullable::some(TimestampMs::new(0))),
        _ => Err(CliError::Usage(Shown::said(
            "--history is none, 1h, 1d or all",
        ))),
    }
}

/// How long a share is asked to last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lasts {
    /// This many milliseconds from when it is issued.
    For(u64),
    /// As long as the device's pairing.
    Pairing,
}

/// Reads `--for`.
fn parse_lasts(text: &str) -> Result<Lasts> {
    match text {
        "15m" => Ok(Lasts::For(15 * 60_000)),
        "1h" => Ok(Lasts::For(60 * 60_000)),
        "1d" => Ok(Lasts::For(24 * 60 * 60_000)),
        "7d" => Ok(Lasts::For(7 * 24 * 60 * 60_000)),
        "30d" => Ok(Lasts::For(30 * 24 * 60 * 60_000)),
        "pairing" => Ok(Lasts::Pairing),
        _ => Err(CliError::Usage(Shown::said(
            "--for is 15m, 1h, 1d, 7d, 30d or pairing",
        ))),
    }
}

/// How long the share lasts, in milliseconds, given what was asked and when the device's pairing
/// ends.
///
/// The share has to end before the pairing does, with room for the host to date it, and the host
/// refuses one that does not; this refuses it before anything is asked. With nothing asked, an hour
/// when it fits, else until the pairing ends.
fn lifetime(asked: Option<Lasts>, pairing_ends_at_ms: Option<u64>, now_ms: u64) -> Result<u64> {
    let room =
        pairing_ends_at_ms.map(|ends| ends.saturating_sub(now_ms).saturating_sub(CLAIM_MARGIN_MS));
    let milliseconds = match (asked, room) {
        (Some(Lasts::For(wanted)), Some(room)) if wanted > room => {
            return Err(CliError::Usage(Shown::said(
                "that is longer than the device's pairing lasts; name a shorter time, or `pairing` \
                 for as long as it does",
            )));
        }
        (Some(Lasts::For(wanted)), _) => wanted,
        (Some(Lasts::Pairing), Some(room)) => room,
        (Some(Lasts::Pairing), None) => {
            return Err(CliError::Usage(Shown::said(
                "that device's pairing does not end, so `pairing` names no time; name one",
            )));
        }
        (None, Some(room)) => room.min(DEFAULT_LIFETIME_MS),
        (None, None) => DEFAULT_LIFETIME_MS,
    };
    if milliseconds < MIN_LIFETIME_MS {
        return Err(CliError::Usage(Shown::said(
            "that device's pairing ends in less than a minute, so a share to it would hardly \
             begin; pair the device again first",
        )));
    }
    Ok(milliseconds)
}

/// The device a person means by `text`: an identifier, or a name exactly one device has.
///
/// # Errors
///
/// Returns a usage mistake when none is meant or several are, and says why a device that cannot
/// take a share cannot: it manages this host, its pairing already opens every session, its pairing
/// has run out, or it was revoked.
fn pick_device<'a>(
    listed: &'a [DeviceSummary],
    text: &str,
    environment: &Shown,
) -> Result<&'a DeviceSummary> {
    let device = match text.parse::<DeviceId>() {
        Ok(device_id) => listed.iter().find(|device| device.device_id == device_id),
        Err(_) => {
            let named: Vec<&DeviceSummary> = listed
                .iter()
                .filter(|device| !device.revoked && device.display_name == text)
                .collect();
            match named.as_slice() {
                [only] => Some(*only),
                [] => None,
                several => {
                    let identifiers = Shown::joined(
                        several.iter().map(|device| shown!("{}", device.device_id)),
                        ", ",
                    );
                    return Err(CliError::Usage(shown!(
                        "more than one device has that name; give the identifier of one of {}",
                        identifiers
                    )));
                }
            }
        }
    };
    let Some(device) = device else {
        return Err(CliError::Usage(shown!(
            "no paired device has that identifier or name; `kr device list{}` shows them",
            environment.clone()
        )));
    };
    if device.revoked {
        return Err(CliError::Usage(Shown::said("that device was revoked")));
    }
    if device.manages_host {
        return Err(CliError::Usage(Shown::said(
            "that device manages this host as an owner and keeps its own access whatever is shared",
        )));
    }
    if device.all_sessions {
        return Err(CliError::Usage(shown!(
            "that device's pairing already opens every session, so a share to it adds nothing the \
             connection can use; pair it as a guest (`kr pair invite --guest{}`) to share one \
             session",
            environment.clone()
        )));
    }
    if device.grant_expired {
        return Err(CliError::Usage(Shown::said(
            "that device's pairing has run out; pair it again before sharing a session with it",
        )));
    }
    Ok(device)
}

/// Text a program wrote, with everything a terminal would act on or hide written out.
///
/// It is the lines of the session's screen, and the name of a program in a session's foreground,
/// which is whatever a program in the session wrote or was named.
pub(crate) fn visibly(line: &str) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(line.len());
    for character in line.chars() {
        if character.is_control() || crate::doctor::content::hides(character) {
            let _ = write!(out, "\\u{{{:04x}}}", u32::from(character));
        } else {
            out.push(character);
        }
    }
    out
}

/// What a role lets a device do, in words, for a share with or without the live screen. Without
/// the live screen a device is given no terminal and no stream of events, whatever its role.
const fn role_words(role: SessionRole, live: bool) -> &'static str {
    match (role, live) {
        (SessionRole::Viewer, true) => "watch the session and what the agent does",
        (SessionRole::Viewer, false) => {
            "see the agent's conversation and questions, with no terminal and no live stream"
        }
        (SessionRole::Reviewer, _) => "watch the session and read files",
        (SessionRole::Controller, true) => {
            "watch the session, type in its terminal, resize it, prompt the agent and answer it"
        }
        (SessionRole::Controller, false) => {
            "prompt the agent and answer it, and see its conversation, but see no terminal and \
             no live stream"
        }
        (SessionRole::Owner, true) => {
            "watch the session, type in its terminal, resize it, prompt the agent and answer it, \
             manage sharing and close the session"
        }
        (SessionRole::Owner, false) => {
            "prompt the agent and answer it, manage sharing and close the session, and see the \
             agent's conversation, but see no terminal and no live stream"
        }
    }
}

/// The rights a selection compiles to, as the protocol names them.
fn rights_line(actions: &CanonicalSet<ActionRight>) -> Shown {
    Shown::joined(
        actions.iter().map(|right| Shown::said(right.as_str())),
        ", ",
    )
}

// ---------------------------------------------------------------------------------------------
// The host, reached
// ---------------------------------------------------------------------------------------------

/// The control daemon of one environment, and what is needed to reach it again.
struct Host {
    environment: KnownEnvironment,
    build_id: BuildId,
    client: LocalClient,
}

impl Host {
    /// Reaches the daemon of the environment `selector` names.
    async fn open(
        paths: &HostPaths,
        selector: &EnvironmentSelector,
        build_id: &BuildId,
    ) -> Result<Self> {
        let environment = resolve::select(paths, selector.environment.as_deref())?;
        let client = resolve::open_controller(&environment.paths, build_id.clone()).await?;
        Ok(Self {
            environment,
            build_id: build_id.clone(),
            client,
        })
    }

    /// A target that names this environment alone.
    fn on_the_host(&self) -> ActionTarget {
        ActionTarget::environment(self.environment.environment_id)
    }

    /// Calls a read.
    async fn read<P: serde::Serialize + ?Sized, T: kr_protocol::wire::WireMessage>(
        &mut self,
        method: Method,
        params: &P,
    ) -> Result<T> {
        crate::bind::read(&mut self.client, method, params).await
    }

    /// Opens a connection of its own to the same daemon.
    async fn another(&self) -> Result<LocalClient> {
        resolve::open_controller(&self.environment.paths, self.build_id.clone()).await
    }

    /// The devices paired with this host, the revoked ones too.
    async fn devices(&mut self) -> Result<DeviceListResult> {
        self.read(
            Method::DeviceList,
            &DeviceListParams {
                include_revoked: true,
            },
        )
        .await
    }

    /// The grants of one session, or of every session, the resolved ones included when asked.
    async fn grants(
        &mut self,
        session_id: Option<SessionId>,
        include_resolved: bool,
    ) -> Result<GrantListResult> {
        self.read(
            Method::GrantList,
            &GrantListParams {
                session_id: Nullable(session_id),
                include_resolved,
            },
        )
        .await
    }
}

/// The live session a selector names, with its worker's descriptor.
fn session_of(paths: &HostPaths, host: &Host, text: &str) -> Result<WorkerDescriptor> {
    let selector = SessionSelector::parse(text)?;
    let (_, descriptor) = resolve::find(paths, &selector, Some(host.environment.environment_id))?;
    Ok(descriptor)
}

/// Maps what the local socket said to a send, to what the attempt makes of it.
fn reply_of(sent: &Sent) -> Reply {
    match sent {
        Ok(Ok(_)) => Reply::Result,
        Ok(Err(refusal)) => Reply::Refused(refusal.retry),
        // A connection that went after the request was composed may have carried it or not, which
        // is what asking again is for.
        Err(_) => Reply::Lost,
    }
}

/// What the host answered to a request, or what stopped it answering.
type Sent = std::result::Result<std::result::Result<ParamsValue, ProtocolError>, kr_ipc::IpcError>;

/// The first send of a request, which counts as lost when the host has not answered in time.
async fn sent_within(send: impl std::future::Future<Output = Sent>) -> Sent {
    tokio::time::timeout(SEND_WITHIN, send).await.unwrap_or(Err(
        kr_ipc::IpcError::UnexpectedMessage("the host did not answer in time"),
    ))
}

/// Asks about a request again, with exactly that request, on a connection opened for it; the
/// connection is given back with the answer so a caller that goes on can go on there. A host that
/// cannot be reached, or does not answer in time, is an answer lost.
async fn ask_again(
    host: &Host,
    request: &kr_protocol::envelope::MutationRequest,
) -> (Sent, Option<LocalClient>) {
    let asked = async {
        match host.another().await {
            Ok(mut second) => {
                let sent = second.repeat(request).await;
                (sent, Some(second))
            }
            Err(CliError::Ipc(error)) => (Err(error), None),
            Err(_) => (
                Err(kr_ipc::IpcError::UnexpectedMessage(
                    "the daemon could not be reached",
                )),
                None,
            ),
        }
    };
    tokio::time::timeout(SEND_WITHIN, asked).await.unwrap_or((
        Err(kr_ipc::IpcError::UnexpectedMessage(
            "the host did not answer in time",
        )),
        None,
    ))
}

// ---------------------------------------------------------------------------------------------
// One mutation, sent once and asked about
// ---------------------------------------------------------------------------------------------

/// What came of one mutation.
struct Performed {
    outcome: Outcome,
    /// The host's result, when this command was given it.
    value: Option<ParamsValue>,
    /// The host's refusal, when the first send was refused and the host kept the refusal.
    refusal: Option<ProtocolError>,
}

/// What a state check looks for.
struct Watch {
    /// The session the grant belongs to.
    session_id: Option<SessionId>,
    /// The grant the action would write, or revoke.
    grant_id: GrantId,
    /// The command that shows what the host holds, for a person whose command ends before it knows.
    list_command: Shown,
}

/// What `--environment` says in a command printed for a person to run: nothing when this command
/// was not given one, since the default is the same for the person's next command.
fn environment_flag(host: &Host, selector: &EnvironmentSelector) -> Shown {
    if selector.environment.is_some() {
        shown!(" --environment {}", host.environment.environment_id)
    } else {
        Shown::said("")
    }
}

/// `kr share list` for one session, or for every session, with every grant the host wrote and the
/// environment this command was given.
fn list_command(session: Option<Shown>, environment: Shown) -> Shown {
    let session = session.map_or_else(|| Shown::said(""), |session| shown!(" {}", session));
    shown!("kr share list{} --all{}", session, environment)
}

/// `kr share revoke` for one grant, in the environment this command was given.
fn revoke_command(grant_id: GrantId, environment: Shown) -> Shown {
    shown!("kr share revoke {}{}", grant_id, environment)
}

/// Whether a command that has waited `elapsed` for the host to show what became of an action, which
/// it counts as not done only after `bound`, has waited as long as it will.
fn has_waited_enough(elapsed: Duration, bound: Duration) -> bool {
    elapsed >= bound.saturating_add(READ_PATIENCE)
}

/// Sends one mutation and, when its reply is lost, asks the host what became of it.
///
/// The request is composed once and sent as that request. A lost reply is asked about by repeating
/// it exactly, on a connection of its own, a few times; whatever those answer other than the result
/// leads to reading the host's state, which counts as "not done" only after the bound
/// ([`Attempt::bound`]) has passed on a clock that cannot be stepped. Nothing here sends the action
/// as a new one.
#[allow(clippy::too_many_arguments)]
async fn perform(
    host: &mut Host,
    kind: Kind,
    method: Method,
    target: ActionTarget,
    action_id: ActionId,
    params: &(impl serde::Serialize + ?Sized),
    watch: &Watch,
    challenge: Option<Armed>,
) -> Result<Performed> {
    let request = host
        .client
        .compose(method, action_id, target, params)
        .await
        .map_err(CliError::Ipc)?;
    let window = host.client.action_window().clone();
    // The host keeps its record of an action under the user it authenticated, and states that user
    // in its acknowledgement.
    let reach = Reach {
        host: host.environment.environment_id.to_string(),
        actor: format!("local:{}", host.client.acknowledgement().peer.uid.get()),
    };
    let composed = ComposedMutation::restored(
        request.clone(),
        window.issued_at_ms.get(),
        window.valid_for_ms.get(),
        Some(reach),
    );
    let mut attempt = Attempt::new(
        kind,
        &composed,
        Some(watch.grant_id),
        kr_ipc::now_ms().get(),
        "kr share",
    );
    if let Some(answered) = challenge {
        attempt.bound_by_challenge(answered);
    }
    let armed = Armed::now();
    // Said before anything is sent: a command that ends here has no record of its own, and this is
    // what a person has to go on. The bound is shown as a moment for the person; the decision is
    // made on the clock that cannot be stepped.
    report::say(&shown!(
        "The grant this {} is {}. If this command is interrupted, `{}` shows what the host holds. \
         The host can still act on this until {}: {}.",
        if kind == Kind::Revoke {
            "revokes"
        } else {
            "writes"
        },
        watch.grant_id,
        watch.list_command.clone(),
        crate::shown::utc_moment(
            kr_ipc::now_ms()
                .get()
                .saturating_add(u64::try_from(attempt.bound().as_millis()).unwrap_or(u64::MAX))
        ),
        Shown::said(if kind == Kind::Revoke {
            "a grant still listed as active before then can still be revoked by it"
        } else {
            "a grant missing from the list before then does not mean it will not appear"
        })
    ));

    let first = sent_within(host.client.repeat(&request)).await;
    let mut performed = Performed {
        outcome: Outcome::Unknown,
        value: None,
        refusal: None,
    };
    take(&mut performed, &first);
    let mut next = attempt.after_first_send(reply_of(&first));
    let mut waited_notice = false;
    let mut unreadable_said = false;
    loop {
        match next {
            Next::Closed(outcome) => {
                performed.outcome = outcome;
                return Ok(performed);
            }
            Next::NotSent => {
                return Err(CliError::Other(Shown::said("the request was not sent")));
            }
            Next::Repeat => {
                let index = usize::from(attempt.repeats).min(REPEAT_DELAYS.len() - 1);
                tokio::time::sleep(REPEAT_DELAYS[index]).await;
                let (sent, _) = ask_again(host, &request).await;
                take(&mut performed, &sent);
                next = attempt.after_repeat(reply_of(&sent));
            }
            Next::Check | Next::Wait => {
                if !waited_notice {
                    waited_notice = true;
                    // A refusal that is not the host's last word is shown, so the person is not
                    // told that nothing was heard when something was.
                    match &performed.refusal {
                        Some(refusal) => report::say(&shown!(
                            "The host said: {}. That does not say that nothing was done, so its \
                             state is read until it shows what became of this; nothing counts as \
                             not done before {} seconds from the first send.",
                            Shown::protocol(refusal),
                            attempt.bound().as_secs()
                        )),
                        None => report::say(&shown!(
                            "The host did not answer, so its state is read until it shows what \
                             became of this; nothing counts as not done before {} seconds from \
                             the first send.",
                            attempt.bound().as_secs()
                        )),
                    }
                }
                tokio::time::sleep(CHECK_EVERY).await;
                // The moment the read begins is what decides whether it counts.
                let began = armed.read_begins();
                let read = tokio::time::timeout(READ_WITHIN, found(host, kind, watch)).await;
                next = match read {
                    Ok(Some(found)) => attempt.after_read(found, began),
                    // A read that fails or does not finish leaves the attempt as it was.
                    Ok(None) | Err(_) => {
                        if !unreadable_said {
                            unreadable_said = true;
                            report::say(&Shown::said(
                                "The host could not be read just now; trying again.",
                            ));
                        }
                        Next::Wait
                    }
                };
                // Once the bound has passed every read that reaches the host decides, so a command
                // still waiting is waiting on a host it cannot read.
                if matches!(next, Next::Wait | Next::Check)
                    && has_waited_enough(armed.elapsed(), attempt.bound())
                {
                    performed.outcome = Outcome::Unknown;
                    return Ok(performed);
                }
            }
        }
    }
}

/// Keeps what the host said, when it said the result or a refusal.
fn take(performed: &mut Performed, sent: &Sent) {
    match sent {
        Ok(Ok(value)) => performed.value = Some(value.clone()),
        Ok(Err(refusal)) if performed.refusal.is_none() => {
            performed.refusal = Some(refusal.clone());
        }
        _ => {}
    }
}

/// Reads the host's state for an attempt of this kind, or none when it could not be read.
async fn found(host: &Host, kind: Kind, watch: &Watch) -> Option<Found> {
    let mut client = host.another().await.ok()?;
    let listed: GrantListResult = crate::bind::read(
        &mut client,
        Method::GrantList,
        &GrantListParams {
            session_id: Nullable(watch.session_id),
            include_resolved: true,
        },
    )
    .await
    .ok()?;
    let entry = listed
        .grants
        .iter()
        .find(|summary| summary.grant.grant_id == watch.grant_id);
    Some(match (kind, entry) {
        (Kind::Revoke, Some(summary)) => {
            Found::Grant(summary.state, summary.revoked_at_ms.is_present())
        }
        (Kind::Revoke, None) => Found::Gone,
        (_, Some(_)) => Found::Present,
        (_, None) => Found::Absent,
    })
}

/// What a person is told of an attempt that did not end in the result.
fn unfinished(outcome: Outcome, what: &'static str, list_command: &Shown) -> CliError {
    let list = shown!("`{}` shows what the host holds.", list_command.clone());
    let message = match outcome {
        Outcome::NotDone | Outcome::NotAccepted => shown!(
            "{} did not happen, as far as the host shows, and nothing more of it can; it is safe \
             to run the command again. {}",
            what,
            list.clone()
        ),
        Outcome::HadEnded => shown!(
            "the grant has ended and {} did not revoke it. {}",
            what,
            list.clone()
        ),
        Outcome::Unknown | Outcome::Happened | Outcome::Refused => shown!(
            "what became of {} is not known: the host did not answer, and its state could not be \
             read or does not settle it. {}",
            what,
            list.clone()
        ),
    };
    CliError::Unfinished {
        code: ErrorCode::OutcomeUnknown,
        message,
    }
}

// ---------------------------------------------------------------------------------------------
// kr share invite
// ---------------------------------------------------------------------------------------------

/// `kr share invite`.
async fn invite(
    paths: &HostPaths,
    arguments: &ShareInviteArguments,
    json: bool,
    build_id: &BuildId,
) -> Result<Completion> {
    let role = parse_role(&arguments.role)?;
    let now_ms = kr_ipc::now_ms().get();
    let history = parse_history(&arguments.history, now_ms)?;
    let asked_lasts = arguments.lasts.as_deref().map(parse_lasts).transpose()?;
    let mut host = Host::open(paths, &arguments.selector, build_id).await?;
    let descriptor = session_of(paths, &host, &arguments.session)?;
    let session_id = descriptor.session_id;
    let devices = host.devices().await?;
    let environment = environment_flag(&host, &arguments.selector);
    let device = pick_device(&devices.devices, &arguments.to, &environment)?.clone();
    let pairing_ends = device.grant_expires_at_ms.as_ref().map(|ends| ends.get());
    // The end the person is shown is the end the host is asked for: it is fixed here, and what the
    // person's time at the question takes comes out of the share, not out of what was shown.
    let ends_at_ms = now_ms.saturating_add(lifetime(asked_lasts, pairing_ends, now_ms)?);

    let selection = RoleSelection {
        role,
        history_from_cursor_ms: history,
        include_live_screen: arguments.live,
        include_question_respond: arguments.answer_questions,
        named_questions: CanonicalSet::new(),
        named_approvals: CanonicalSet::new(),
    };
    let actions = selection.actions();
    let notices = AuthorityNotice::for_actions(&actions);

    // The lines on the screen now, which the share would include.
    let shown_lines = if arguments.live {
        let preview = preview_of(&descriptor, &selection, build_id).await?;
        Some(preview)
    } else {
        None
    };

    let consequential = !notices.is_empty() || arguments.live;
    if arguments.yes && consequential {
        return Err(CliError::Usage(Shown::said(
            "--yes does not skip the question for a share that carries a consequence or the live \
             screen; leave it out and type `share` at the terminal",
        )));
    }
    // What this device already holds of the session: a second share to it is not a replacement.
    let held_already = device_shares(&mut host, session_id, device.device_id).await?;
    let summary = summary_of(
        &descriptor,
        &device,
        &selection,
        &notices,
        ends_at_ms,
        pairing_ends.is_some(),
        shown_lines.as_deref(),
        &held_already,
    );
    if arguments.yes {
        // Standard error carries nothing but this program's own words and an export's preview, so
        // the summary is read on standard output, and not at all when that is a document.
        if !json {
            output::lines(&summary);
        }
    } else {
        pair::guard(
            build_id,
            "a share is issued at a terminal outside every session",
        )
        .await?;
        let mut terminal = pair::Terminal::open()?;
        for line in &summary {
            terminal.say(line)?;
        }
        let typed = terminal.ask(&stdout_line!(
            "Type {} to issue this invitation: ",
            SHARE_WORD
        ))?;
        if typed.trim() != SHARE_WORD {
            return Err(CliError::refused_in_its_own_words(
                ErrorCode::OwnerConfirmationRequired,
                Shown::said("that is not what the question asked for, so nothing was shared"),
            ));
        }
    }

    // The host dates the share when it accepts the action, so it is asked for what is left of the
    // time that was shown.
    let lifetime_ms = remaining_lifetime(ends_at_ms, kr_ipc::now_ms().get())?;
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let uid = host.client.acknowledgement().peer.uid.get();
    let (grant_id, invitation_id) = share_identities(&local_actor(uid), action_id.get());
    let params = GrantCreateParams {
        session_id,
        recipient_device_id: device.device_id,
        parent_grant_id: Nullable::null(),
        accepted_notices: notices,
        selection,
        lifetime_ms: Nullable::some(kr_protocol::scalars::DurationMs::new(lifetime_ms)),
        owner_confirmation: Nullable::null(),
    };
    let target = crate::attach::target(&descriptor);
    let watch = Watch {
        session_id: Some(session_id),
        grant_id,
        // The session's identifier, which names it when its display number is gone with it.
        list_command: list_command(Some(shown!("{}", session_id)), environment.clone()),
    };
    let performed = perform(
        &mut host,
        Kind::Invite,
        Method::GrantCreate,
        target,
        action_id,
        &params,
        &watch,
        None,
    )
    .await?;
    match performed.outcome {
        Outcome::Refused => {
            return Err(performed.refusal.map_or_else(
                || CliError::Other(Shown::said("the host refused the share")),
                CliError::Refused,
            ));
        }
        Outcome::Happened => {}
        other => {
            // What the host shows now of this device's shares of the session, so a person who
            // runs the command again sees what is already there.
            say_device_shares(&host, session_id, device.device_id).await;
            return Err(unfinished(other, "the invitation", &watch.list_command));
        }
    }
    let created: Option<GrantCreateResult> = performed
        .value
        .as_ref()
        .and_then(|value| value.to_typed().ok());
    let changed = match (&created, &shown_lines) {
        (Some(created), Some(lines)) => Some(
            created
                .preview
                .live_screen
                .as_ref()
                .map(|screen| &screen.lines)
                != Some(lines),
        ),
        _ => None,
    };
    let revoke = revoke_command(grant_id, environment);
    if json {
        output::document(&invite_document(&Issued {
            grant_id,
            invitation_id,
            session_id,
            device: &device,
            role,
            created: created.as_ref(),
            screen_changed: changed,
            revoke: revoke.clone(),
        }));
    } else {
        output::lines(&invited_lines(
            &descriptor,
            &device,
            grant_id,
            invitation_id,
            created.as_ref(),
        ));
        if let (Some(true), Some(created)) = (changed, &created) {
            output::lines(&screen_changed_lines(created));
        }
    }
    // For the person, in both forms: the document of a script holds the same facts.
    match (changed, &created) {
        (Some(true), Some(_)) => report::say(&shown!(
            "The screen changed before the invitation was written. Withdraw it with `{}`.",
            revoke
        )),
        (None, _) if arguments.live => report::say(&shown!(
            "The host's answer was not read here, so the lines it kept could not be compared with \
             the ones shown. Withdraw the invitation with `{}` if the screen has changed.",
            revoke
        )),
        _ => {}
    }
    Ok(Completion::Done)
}

/// What the end the person was shown leaves to ask the host for, now that the question is over.
///
/// # Errors
///
/// Returns a usage mistake when too little is left for a share to begin: the person took so long
/// at the question that what they were shown has nearly passed.
fn remaining_lifetime(ends_at_ms: u64, now_ms: u64) -> Result<u64> {
    let left = ends_at_ms.saturating_sub(now_ms);
    if left < MIN_LIFETIME_MS {
        return Err(CliError::Usage(Shown::said(
            "the end shown for this share has nearly passed while the question was open, so \
             nothing was shared; ask again",
        )));
    }
    Ok(left)
}

/// What a device holds, or is offered, of one session: the grants the host lists for it that have
/// not ended or been revoked.
async fn device_shares(
    host: &mut Host,
    session_id: SessionId,
    device_id: DeviceId,
) -> Result<Vec<GrantSummary>> {
    Ok(host
        .grants(Some(session_id), false)
        .await?
        .grants
        .into_iter()
        .filter(|summary| summary.grant.recipient_device_id == device_id)
        .collect())
}

/// Says what the host shows of a device's shares of a session, on a connection of its own: for a
/// command that could not tell what became of its invitation. A host that cannot be read says so.
async fn say_device_shares(host: &Host, session_id: SessionId, device_id: DeviceId) {
    let read = async {
        let mut client = host.another().await?;
        let listed: GrantListResult = crate::bind::read(
            &mut client,
            Method::GrantList,
            &GrantListParams {
                session_id: Nullable::some(session_id),
                include_resolved: false,
            },
        )
        .await?;
        Ok::<_, CliError>(listed)
    };
    match tokio::time::timeout(READ_WITHIN, read).await {
        Ok(Ok(listed)) => {
            let held: Vec<&GrantSummary> = listed
                .grants
                .iter()
                .filter(|summary| summary.grant.recipient_device_id == device_id)
                .collect();
            if held.is_empty() {
                report::say(&Shown::said(
                    "The host shows no open share of this session for that device.",
                ));
            }
            for summary in held {
                report::say(&shown!(
                    "The host shows grant {} of this session for that device: {}.",
                    summary.grant.grant_id,
                    state_words(summary.state)
                ));
            }
        }
        _ => report::say(&Shown::said(
            "The host could not be read, so what it holds of this device's shares is not known.",
        )),
    }
}

/// Reads the lines on the session's screen now, as the share would include them.
///
/// # Errors
///
/// Returns the worker's refusal, and refuses a screen that was cut: the host refuses a share whose
/// issuer was not shown all of it.
async fn preview_of(
    descriptor: &WorkerDescriptor,
    selection: &RoleSelection,
    build_id: &BuildId,
) -> Result<Vec<String>> {
    let mut worker = resolve::open_worker(descriptor, build_id.clone()).await?;
    crate::helper::read_only_same(
        worker.acknowledgement().build.as_ref(),
        descriptor.display_number.get(),
        "share",
    )?;
    let result: SessionScreenPreviewResult = crate::bind::read(
        &mut worker,
        Method::SessionScreenPreview,
        &SessionScreenPreviewParams {
            session_id: descriptor.session_id,
            history: selection.history(),
        },
    )
    .await?;
    let Some(screen) = result.screen.0 else {
        return Err(CliError::Other(Shown::said(
            "the session returned no screen to preview",
        )));
    };
    if screen.truncated {
        return Err(CliError::refused_in_its_own_words(
            ErrorCode::InvalidArgument,
            Shown::said(
                "the screen is larger than a preview shows, so its issuer would not be shown all \
                 of it; make the session's terminal smaller, or share without the live screen",
            ),
        ));
    }
    Ok(screen.lines)
}

/// The lines a person reads before they decide.
#[allow(clippy::too_many_arguments)]
fn summary_of(
    descriptor: &WorkerDescriptor,
    device: &DeviceSummary,
    selection: &RoleSelection,
    notices: &CanonicalSet<AuthorityNotice>,
    ends_at_ms: u64,
    ends_with_pairing: bool,
    screen: Option<&[String]>,
    held_already: &[GrantSummary],
) -> Vec<Line> {
    // The name is whatever the device called itself, so it is written out as a screen line is.
    let name = Asked::text(Request::Devices, &visibly(&device.display_name));
    let mut lines = vec![
        stdout_line!(
            "Share session {} with {} ({}, device {}).",
            descriptor.display_number.get(),
            name,
            crate::output::closed_word(&device.platform),
            device.device_id
        ),
        stdout_line!(
            "  Role: {}, which lets it {}.",
            selection.role.as_str(),
            role_words(selection.role, selection.include_live_screen)
        ),
        stdout_line!("  Rights: {}.", rights_line(&selection.actions())),
        stdout_line!(
            "  Until {}, used once.{}",
            crate::shown::utc_moment(ends_at_ms),
            if ends_with_pairing {
                " The share ends no later than the device's pairing."
            } else {
                ""
            }
        ),
    ];
    lines.push(match selection.history_from_cursor_ms.as_ref() {
        None => stdout_line!(
            "  Earlier activity: none; it sees what happens from the moment you invite."
        ),
        Some(from) => {
            let scope = if selection.include_live_screen {
                "the agent's conversation, questions and events"
            } else {
                "the agent's conversation and questions"
            };
            let never = if selection.include_live_screen {
                " Never the terminal's scrollback."
            } else {
                ""
            };
            if from.get() == 0 {
                stdout_line!(
                    "  Earlier activity: {} from before, everything the host keeps.{}",
                    scope,
                    Shown::said(never)
                )
            } else {
                stdout_line!(
                    "  Earlier activity: {} from {}.{}",
                    scope,
                    crate::shown::utc_moment(from.get()),
                    Shown::said(never)
                )
            }
        }
    });
    if selection.include_live_screen {
        lines.push(stdout_line!("  The live screen is included."));
    } else {
        lines.push(stdout_line!(
            "  No terminal and no live stream: the device does not see the screen."
        ));
    }
    for notice in notices.iter() {
        lines.push(stdout_line!(
            "  Consequence: {}",
            Shown::said(notice.sentence())
        ));
    }
    if !held_already.is_empty() {
        lines.push(stdout_line!(
            "That device already has {} open share{} of this session; this one is another, not a \
             replacement:",
            held_already.len(),
            if held_already.len() == 1 { "" } else { "s" }
        ));
        for summary in held_already {
            lines.push(stdout_line!(
                "  grant {}, {}",
                summary.grant.grant_id,
                Shown::said(state_words(summary.state))
            ));
        }
    }
    if let Some(screen) = screen {
        lines.push(stdout_line!(
            "The screen now ({} line{}):",
            screen.len(),
            if screen.len() == 1 { "" } else { "s" }
        ));
        for line in screen {
            lines.push(stdout_line!(
                "  | {}",
                Asked::text(Request::Screen, &visibly(line))
            ));
        }
        lines.push(stdout_line!(
            "They see the screen as it is when they open it, and what follows. A resize can bring \
             earlier lines into view, and a program that switches screens can show older text. \
             This preview shows neither."
        ));
    }
    lines
}

/// What a person is told once the invitation is written.
fn invited_lines(
    descriptor: &WorkerDescriptor,
    device: &DeviceSummary,
    grant_id: GrantId,
    invitation_id: InvitationId,
    created: Option<&GrantCreateResult>,
) -> Vec<Line> {
    let name = Asked::text(Request::Devices, &device.display_name);
    let mut lines = vec![stdout_line!(
        "Invited {} to session {}. They accept it on their device.",
        name,
        descriptor.display_number.get()
    )];
    lines.push(stdout_line!(
        "  Grant {}, invitation {}.",
        grant_id,
        invitation_id
    ));
    if let Some(created) = created
        && let kr_protocol::grant::GrantExpiry::At { expires_at_ms } = created.grant.expiry
    {
        lines.push(stdout_line!(
            "  The invitation ends {}.",
            crate::shown::utc_moment(expires_at_ms.get())
        ));
    }
    lines
}

/// The lines the host kept as the screen of a share whose screen changed before it was written.
fn screen_changed_lines(created: &GrantCreateResult) -> Vec<Line> {
    let mut lines = vec![stdout_line!(
        "The screen changed before the invitation was written. The host kept these lines:"
    )];
    if let Some(screen) = created.preview.live_screen.as_ref() {
        for line in &screen.lines {
            lines.push(stdout_line!(
                "  | {}",
                Asked::text(Request::Screen, &visibly(line))
            ));
        }
    }
    lines
}

/// What an invitation is, as the command that wrote it knows it.
struct Issued<'a> {
    grant_id: GrantId,
    invitation_id: InvitationId,
    session_id: SessionId,
    device: &'a DeviceSummary,
    role: SessionRole,
    /// The host's answer, when this command was given it.
    created: Option<&'a GrantCreateResult>,
    /// Whether the lines the host kept are the ones that were shown, when that could be told.
    screen_changed: Option<bool>,
    /// The command that withdraws it.
    revoke: Shown,
}

/// The invitation, for a script.
fn invite_document(issued: &Issued<'_>) -> Document {
    let Issued {
        grant_id,
        invitation_id,
        session_id,
        device,
        role,
        created,
        screen_changed,
        revoke,
    } = issued;
    let (created, screen_changed) = (*created, *screen_changed);
    Document::new()
        .with("grant_id", closed(grant_id))
        .with("invitation_id", closed(invitation_id))
        .with("session_id", closed(session_id))
        .with("device_id", closed(&device.device_id))
        .with(
            "device_name",
            Asked::text(Request::Devices, &device.display_name),
        )
        .with("role", closed(role))
        .with(
            "actions",
            created.map(|created| closed(&created.grant.actions)),
        )
        .with(
            "ends_at_ms",
            created.and_then(|created| match created.grant.expiry {
                kr_protocol::grant::GrantExpiry::At { expires_at_ms } => {
                    Some(closed(&expires_at_ms))
                }
                kr_protocol::grant::GrantExpiry::Never => None,
            }),
        )
        .with("screen_changed", screen_changed)
        .with(
            "kept_screen",
            (screen_changed == Some(true))
                .then(|| created.and_then(|created| created.preview.live_screen.as_ref()))
                .flatten()
                .map(|screen| {
                    screen
                        .lines
                        .iter()
                        .map(|line| Asked::text(Request::Screen, &visibly(line)))
                        .collect::<Vec<_>>()
                }),
        )
        .with("revoke_command", revoke.clone())
        .with("ok", true)
}

// ---------------------------------------------------------------------------------------------
// kr share list
// ---------------------------------------------------------------------------------------------

/// `kr share list`.
async fn list(
    paths: &HostPaths,
    arguments: &ShareListArguments,
    json: bool,
    build_id: &BuildId,
) -> Result<()> {
    let mut host = Host::open(paths, &arguments.selector, build_id).await?;
    let session_id = match arguments.session.as_deref() {
        None => None,
        Some(text) => Some(match SessionSelector::parse(text)? {
            SessionSelector::Identifier(session_id) => session_id,
            display @ SessionSelector::Display(_) => {
                resolve::find(paths, &display, Some(host.environment.environment_id))?
                    .1
                    .session_id
            }
        }),
    };
    let listed = host.grants(session_id, arguments.all).await?;
    let devices = host.devices().await?;
    if json {
        output::document(&list_document(&listed, &devices));
        return Ok(());
    }
    if listed.grants.is_empty() {
        output::say(&Shown::said("no shares"));
    }
    for summary in &listed.grants {
        output::line(&list_line(summary, &devices));
    }
    Ok(())
}

/// The name a device gave itself, for a grant that goes to it.
fn name_of(devices: &DeviceListResult, device_id: DeviceId) -> Option<&str> {
    devices
        .devices
        .iter()
        .find(|device| device.device_id == device_id)
        .map(|device| device.display_name.as_str())
}

/// The state of a share, in the words a person reads.
const fn state_words(state: GrantState) -> &'static str {
    match state {
        GrantState::Pending => "waiting to be accepted",
        GrantState::Active => "active",
        GrantState::Expired => "ended",
        GrantState::Revoked => "revoked",
    }
}

/// What a share allows, as a list prints it: the widest role whose rights the share carries in
/// full, and every right the role does not cover named beside it. A viewer who may answer the
/// agent's questions is `viewer plus question.respond`, never a plain viewer; a share that carries
/// no role in full, because every role includes `session.view` and it has none, is `custom` with
/// each right named. The role is a label for the person reading the line: the host decides from
/// the rights.
fn access_words(actions: &CanonicalSet<ActionRight>) -> Shown {
    let role = kr_controller::sharing::roles::describes(actions);
    let beyond: Vec<Shown> = actions
        .iter()
        .filter(|right| role.is_none_or(|role| !role.default_actions().contains(right)))
        .map(|right| Shown::said(right.as_str()))
        .collect();
    match (role, beyond.is_empty()) {
        (Some(role), true) => Shown::said(role.as_str()),
        (Some(role), false) => shown!(
            "{} plus {}",
            Shown::said(role.as_str()),
            Shown::joined(beyond, ", ")
        ),
        (None, true) => Shown::said("custom"),
        (None, false) => shown!("custom: {}", Shown::joined(beyond, ", ")),
    }
}

/// One share as a line.
fn list_line(summary: &GrantSummary, devices: &DeviceListResult) -> Line {
    let access = access_words(&summary.grant.actions);
    let session = match &summary.grant.session_selector {
        kr_protocol::grant::SessionSelector::These { session_ids } => session_ids.iter().next(),
        _ => None,
    };
    let device = name_of(devices, summary.grant.recipient_device_id)
        .map(|name| Asked::text(Request::Devices, name));
    let ends = summary.ends_at_ms.as_ref().map_or_else(
        || Shown::said("no end"),
        |ends| shown!("until {}", crate::shown::utc_moment(ends.get())),
    );
    stdout_line!(
        "{}  {}  {} {}  session {}  {}{}  {}",
        summary.grant.grant_id,
        output::left(24, &Shown::said(state_words(summary.state))),
        summary.grant.recipient_device_id,
        device.unwrap_or_else(|| Asked::text(Request::Devices, "")),
        session.map_or_else(|| Shown::said("none"), |session| shown!("{}", *session)),
        access,
        Shown::said(if summary.grant.history.include_live_screen {
            " with the live screen"
        } else {
            ""
        }),
        ends
    )
}

/// The shares, for a script, in the shape the protocol answers them, with the name each device gave
/// itself beside its identifier.
fn list_document(listed: &GrantListResult, devices: &DeviceListResult) -> Document {
    Document::new()
        .with(
            "grants",
            listed
                .grants
                .iter()
                .map(|summary| {
                    Document::new()
                        .with("grant_id", closed(&summary.grant.grant_id))
                        .with("state", closed(&summary.state))
                        .with(
                            "recipient_device_id",
                            closed(&summary.grant.recipient_device_id),
                        )
                        .with(
                            "recipient_name",
                            name_of(devices, summary.grant.recipient_device_id)
                                .map(|name| Asked::text(Request::Devices, name)),
                        )
                        .with("session_selector", closed(&summary.grant.session_selector))
                        .with("actions", closed(&summary.grant.actions))
                        .with("live_screen", summary.grant.history.include_live_screen)
                        .with(
                            "history_from_ms",
                            closed(&summary.grant.history.lower_bound_ms),
                        )
                        .with("ends_at_ms", closed(&summary.ends_at_ms))
                        .with("revoked_at_ms", closed(&summary.revoked_at_ms))
                        .with("revoked_by_parent", closed(&summary.revoked_by_parent))
                })
                .collect::<Vec<_>>(),
        )
        .with("ok", true)
}

// ---------------------------------------------------------------------------------------------
// kr share revoke
// ---------------------------------------------------------------------------------------------

/// `kr share revoke`.
///
/// A revocation is complete only once every affected session's worker has fenced it. Until then it
/// is pending, never a success: the command prints what it did and which workers it waits for, and
/// fails. Asking again is a new revocation, and tells each worker the revision again.
async fn revoke(
    paths: &HostPaths,
    arguments: &ShareRevokeArguments,
    json: bool,
    build_id: &BuildId,
) -> Result<Completion> {
    let grant_id: GrantId = crate::daemon::identifier(&arguments.grant, "a grant")?;
    let mut host = Host::open(paths, &arguments.selector, build_id).await?;
    let known = host.grants(None, true).await?;
    let Some(entry) = known
        .grants
        .iter()
        .find(|summary| summary.grant.grant_id == grant_id)
    else {
        return Err(CliError::refused_in_its_own_words(
            ErrorCode::ResourceUnavailable,
            Shown::said("the host holds no such share, so nothing was revoked"),
        ));
    };
    let session_id = match &entry.grant.session_selector {
        kr_protocol::grant::SessionSelector::These { session_ids } => {
            session_ids.iter().next().copied()
        }
        _ => None,
    };
    let target = host.on_the_host();
    let watch = Watch {
        session_id,
        grant_id,
        list_command: list_command(
            session_id.map(|session_id| shown!("{}", session_id)),
            environment_flag(&host, &arguments.selector),
        ),
    };
    let performed = perform(
        &mut host,
        Kind::Revoke,
        Method::GrantRevoke,
        target,
        ActionId::new(kr_ipc::new_uuid()),
        &GrantRevokeParams { grant_id },
        &watch,
        None,
    )
    .await?;
    match performed.outcome {
        Outcome::Refused => Err(performed.refusal.map_or_else(
            || CliError::Other(Shown::said("the host refused the revocation")),
            CliError::Refused,
        )),
        Outcome::Happened => {
            let revoked: Option<RevocationResult> = performed
                .value
                .as_ref()
                .and_then(|value| value.to_typed().ok());
            finish_revocation(
                grant_id,
                revoked.as_ref(),
                &revoke_command(grant_id, environment_flag(&host, &arguments.selector)),
                json,
            )
        }
        other => Err(unfinished(other, "the revocation", &watch.list_command)),
    }
}

/// Prints a revocation and fails while a worker has not fenced it.
fn finish_revocation(
    grant_id: GrantId,
    revoked: Option<&RevocationResult>,
    revoke: &Shown,
    json: bool,
) -> Result<Completion> {
    let Some(revoked) = revoked else {
        // The host's state shows the grant revoked, and its answer was not read here, so the
        // barrier is not known and is not claimed.
        let error = CliError::Unfinished {
            code: ErrorCode::ResourceUnavailable,
            message: shown!(
                "grant {} is revoked, and whether each session's worker has fenced it is not \
                 known: the host's answer was not read; run `{}` again to ask each worker",
                grant_id,
                revoke.clone()
            ),
        };
        if json {
            output::document(&report::with_failure(
                Document::new().with("grant_id", closed(&grant_id)),
                &error,
            ));
        } else {
            report::failed(&error);
        }
        return Ok(Completion::Reported(error));
    };
    let pending = revoked.barrier.pending();
    let error = (!pending.is_empty()).then(|| CliError::Unfinished {
        code: ErrorCode::ResourceUnavailable,
        message: shown!(
            "the revocation of grant {} is recorded and still pending: {}{} session worker{} {} \
             not fenced it yet, and `{}` again reports how far it has got",
            grant_id,
            // A cut list names the workers still waiting first, so its count is a floor.
            if crate::device::unlisted_workers(&revoked.barrier) > 0 {
                "at least "
            } else {
                ""
            },
            pending.len(),
            if pending.len() == 1 { "" } else { "s" },
            if pending.len() == 1 { "has" } else { "have" },
            revoke.clone()
        ),
    });
    if json {
        let mut document = Document::new().with("grant_id", closed(&grant_id));
        document.merge(crate::device::revocation_document(revoked));
        // The member this document carried before it listed each worker. A script written against
        // it keeps reading it until a release that changes the command line's JSON removes it;
        // `ok` and `barrier.workers[].state` say the same.
        document.set("barrier_holds", revoked.barrier.holds());
        match &error {
            None => output::document(&document),
            Some(error) => output::document(&report::with_failure(document, error)),
        }
    } else {
        output::lines(&revocation_lines(grant_id, revoked));
        if let Some(error) = &error {
            report::failed(error);
        }
    }
    Ok(error.map_or(Completion::Done, Completion::Reported))
}

/// What a revocation did, as lines for a person: the grants it took, and how far each affected
/// session's worker has got in fencing it. A revocation some worker has not fenced is said to be
/// pending, not done.
fn revocation_lines(grant_id: GrantId, revoked: &RevocationResult) -> Vec<Line> {
    let grants = usize::try_from(revoked.revoked_grants_total.get()).unwrap_or(usize::MAX);
    let first = if revoked.barrier.holds() {
        stdout_line!(
            "Revoked grant {} and {} grant{} in all, at authority revision {}. What the device \
             already saw stays with it.",
            grant_id,
            grants,
            if grants == 1 { "" } else { "s" },
            revoked.authority_revision
        )
    } else {
        stdout_line!(
            "The revocation of grant {} is pending, at authority revision {}: {} grant{} \
             revoked, and it is complete only when these sessions' workers fence it.",
            grant_id,
            revoked.authority_revision,
            grants,
            if grants == 1 { "" } else { "s" }
        )
    };
    crate::device::barrier_lines(first, &revoked.barrier)
}

// ---------------------------------------------------------------------------------------------
// kr share transfer
// ---------------------------------------------------------------------------------------------

/// `kr share transfer`.
///
/// The host describes the transfer from its own records, an owner device confirms exactly that
/// plan, and `grant.transfer` spends the confirmation once. The command asks for the confirmation
/// under a fresh action, waits for an owner device to answer it, then sends the transfer under
/// that action.
async fn transfer(
    paths: &HostPaths,
    arguments: &ShareTransferArguments,
    json: bool,
    build_id: &BuildId,
) -> Result<Completion> {
    let from: GrantId = crate::daemon::identifier(&arguments.from, "a grant")?;
    let mut host = Host::open(paths, &arguments.selector, build_id).await?;
    let descriptor = session_of(paths, &host, &arguments.session)?;
    let session_id = descriptor.session_id;
    let devices = host.devices().await?;
    let environment = environment_flag(&host, &arguments.selector);
    let receiver = pick_device(&devices.devices, &arguments.to, &environment)?.clone();
    if !devices
        .devices
        .iter()
        .any(|device| device.manages_host && !device.revoked && !device.grant_expired)
    {
        return Err(CliError::refused_in_its_own_words(
            ErrorCode::OwnerConfirmationRequired,
            shown!(
                "no owner device is paired with this host, so nobody can confirm a transfer of \
                 control; pair one with `kr pair invite --owner{}`",
                environment.clone()
            ),
        ));
    }
    let held = host.grants(Some(session_id), false).await?;
    let Some(giving) = held
        .grants
        .iter()
        .find(|summary| summary.grant.grant_id == from)
    else {
        return Err(CliError::refused_in_its_own_words(
            ErrorCode::ResourceUnavailable,
            Shown::said("the host holds no such share of that session"),
        ));
    };
    if giving.state != GrantState::Active {
        return Err(CliError::refused_in_its_own_words(
            ErrorCode::PermissionDenied,
            Shown::said(
                "only a share its device has accepted, and that still stands, can be handed over",
            ),
        ));
    }
    if !json {
        output::line(&stdout_line!(
            "{} gets the access {} has now. {} loses it. An owner device must confirm.",
            Asked::text(Request::Devices, &receiver.display_name),
            Asked::text(
                Request::Devices,
                name_of(&devices, giving.grant.recipient_device_id).unwrap_or("")
            ),
            Asked::text(
                Request::Devices,
                name_of(&devices, giving.grant.recipient_device_id).unwrap_or("")
            )
        ));
    }
    let params = GrantTransferParams {
        session_id,
        from_grant_id: from,
        to_device_id: receiver.device_id,
    };
    let transfer_action = ActionId::new(kr_ipc::new_uuid());

    // Ask for the confirmation under its own action. A lost reply is asked about again with the
    // same request: the host keeps its answer, and an owner device then shows one request.
    let challenge = ask_for_confirmation(&mut host, &params, transfer_action).await?;
    let expires_at_ms = challenge.request.expires_at_ms.get();
    if challenge.initial_bootstrap {
        return Err(CliError::refused_in_its_own_words(
            ErrorCode::OwnerConfirmationRequired,
            Shown::said("this host has no owner device yet, so nobody can confirm a transfer"),
        ));
    }
    let received = Armed::now();
    report::say(&shown!(
        "Waiting for an owner device to confirm this plan. It expires {}.",
        crate::shown::utc_moment(expires_at_ms)
    ));
    // The wait ends at the host's own expiry, measured once on this process's monotonic clock.
    let deadline = tokio::time::Instant::now()
        + crate::plugin::time_left(expires_at_ms, kr_ipc::now_ms().get());
    answered_by_an_owner_device(deadline, POLL_EVERY, &challenge.request, async || {
        host.read(
            Method::OwnerConfirmationPending,
            &OwnerConfirmationPendingParams {},
        )
        .await
    })
    .await?;

    let uid = host.client.acknowledgement().peer.uid.get();
    let new_grant_id = transfer_identity(&local_actor(uid), transfer_action);
    let target = crate::attach::target(&descriptor);
    let watch = Watch {
        session_id: Some(session_id),
        grant_id: new_grant_id,
        list_command: list_command(Some(shown!("{}", session_id)), environment.clone()),
    };
    let performed = perform(
        &mut host,
        Kind::Transfer,
        Method::GrantTransfer,
        target,
        transfer_action,
        &params,
        &watch,
        Some(received),
    )
    .await?;
    match performed.outcome {
        Outcome::Refused => Err(performed.refusal.map_or_else(
            || CliError::Other(Shown::said("the host refused the transfer")),
            CliError::Refused,
        )),
        Outcome::Happened => {
            let result: Option<GrantTransferResult> = performed
                .value
                .as_ref()
                .and_then(|value| value.to_typed().ok());
            finish_transfer(
                &descriptor,
                &receiver,
                (from, new_grant_id),
                &revoke_command(from, environment.clone()),
                result.as_ref(),
                json,
            )
        }
        other => Err(unfinished(other, "the transfer", &watch.list_command)),
    }
}

/// Reads the host's list of pending challenges every `every` until an owner device has answered
/// `request`, and ends the command when the challenge has run out or been taken, when `deadline`
/// passes, or when the list cannot be read: each read is given the time any request that changes
/// nothing is given and never past `deadline`, as the other owner-device commands give it, and
/// each ends the command with nothing changed and the reason it ended. A read that `deadline` cut
/// short is the challenge running out, and so is the pause between two reads, which ends at
/// `deadline` when it would run past it.
///
/// `deadline` is a point on this process's own monotonic clock, fixed when the challenge arrived,
/// so nothing that happens to the wall clock afterwards moves it.
async fn answered_by_an_owner_device(
    deadline: tokio::time::Instant,
    every: Duration,
    request: &kr_protocol::pairing::OwnerConfirmationRequest,
    mut pending: impl AsyncFnMut() -> Result<OwnerConfirmationPendingResult>,
) -> Result<()> {
    let ran_out = || {
        CliError::refused_in_its_own_words(
            ErrorCode::OwnerConfirmationRequired,
            Shown::said(
                "the confirmation ran out or was taken before an owner device answered it, so \
                 nothing was handed over; ask again",
            ),
        )
    };
    loop {
        // A read the challenge's end cut short is the challenge running out, not a host that did
        // not answer: the host is asked about it every poll until then.
        let listed = match crate::plugin::ask_before(
            deadline,
            crate::plugin::ListRead::TheAnswer,
            pending(),
        )
        .await
        {
            Ok(listed) => listed?,
            Err(_) if tokio::time::Instant::now() >= deadline => return Err(ran_out()),
            Err(ended) => return Err(ended),
        };
        match listed
            .pending
            .iter()
            .find(|waiting| waiting.request == *request)
        {
            Some(waiting) if waiting.answered => return Ok(()),
            // The wait ends where the challenge does, so the last sleep is cut short at its end.
            Some(_) => {
                tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + every)).await;
            }
            None => return Err(ran_out()),
        }
    }
}

/// Asks the host to describe the transfer and obtain an owner device's confirmation of it.
async fn ask_for_confirmation(
    host: &mut Host,
    params: &GrantTransferParams,
    transfer_action: ActionId,
) -> Result<OwnerConfirmationRequestResult> {
    let ask = OwnerConfirmationRequestParams {
        subject: ConfirmationSubject::TransferControl(Box::new(TransferControlSubject {
            params: params.clone(),
            action_id: transfer_action,
        })),
    };
    let target = host.on_the_host();
    let request = host
        .client
        .compose(
            Method::OwnerConfirmationRequest,
            ActionId::new(kr_ipc::new_uuid()),
            target,
            &ask,
        )
        .await
        .map_err(CliError::Ipc)?;
    let mut sent = sent_within(host.client.repeat(&request)).await;
    let mut asked_again = 0;
    // The connection a repeat was answered on, which the first one no longer is when its reply was
    // lost: the command goes on on it.
    let mut answered_on: Option<LocalClient> = None;
    loop {
        match sent {
            Ok(Ok(value)) => {
                if let Some(connection) = answered_on {
                    host.client = connection;
                }
                return value.to_typed().map_err(|error| {
                    CliError::Other(shown!(
                        "the host's answer could not be read: {}",
                        Shown::cbor(&error)
                    ))
                });
            }
            // The host's own answer to the request, which only the first send is: a refusal to a
            // repeat can be the host saying it has no record of an action it never read.
            Ok(Err(refusal)) if asked_again == 0 => return Err(CliError::Refused(refusal)),
            _ if asked_again < REPEAT_DELAYS.len() => {
                tokio::time::sleep(REPEAT_DELAYS[asked_again]).await;
                asked_again += 1;
                (sent, answered_on) = ask_again(host, &request).await;
            }
            _ => {
                return Err(CliError::Unfinished {
                    code: ErrorCode::OutcomeUnknown,
                    message: Shown::said(
                        "the host did not answer, so nothing was handed over; an owner device can \
                         still be shown the request for up to two minutes, and will do nothing \
                         with it that this command sends",
                    ),
                });
            }
        }
    }
}

/// Prints a transfer and fails while a worker has not fenced what it took from the giver.
fn finish_transfer(
    descriptor: &WorkerDescriptor,
    receiver: &DeviceSummary,
    (from, new_grant_id): (GrantId, GrantId),
    revoke: &Shown,
    result: Option<&GrantTransferResult>,
    json: bool,
) -> Result<Completion> {
    let pending = result.map(|result| result.revoked.barrier.pending().len());
    let error = match pending {
        Some(0) => None,
        Some(waiting) => Some(CliError::Unfinished {
            code: ErrorCode::ResourceUnavailable,
            message: shown!(
                "the transfer is recorded and the revocation of the giving device's grant is \
                 pending: {} session worker{} {} not fenced it yet; `{}` again reports how far it \
                 has got",
                waiting,
                if waiting == 1 { "" } else { "s" },
                if waiting == 1 { "has" } else { "have" },
                revoke.clone()
            ),
        }),
        None => Some(CliError::Unfinished {
            code: ErrorCode::ResourceUnavailable,
            message: shown!(
                "the transfer happened, and whether each session's worker has fenced the giving \
                 device's grant is not known: the host's answer was not read; `{}` again asks \
                 each worker",
                revoke.clone()
            ),
        }),
    };
    if json {
        let mut document = Document::new()
            .with("session_id", closed(&descriptor.session_id))
            .with("from_grant_id", closed(&from))
            .with("new_grant_id", closed(&new_grant_id))
            .with("to_device_id", closed(&receiver.device_id))
            .with(
                "barrier_holds",
                result.map(|result| result.revoked.barrier.holds()),
            );
        // The revocation of the giving device's grant, in the shape a revocation is answered in.
        if let Some(result) = result {
            document.merge(crate::device::revocation_document(&result.revoked));
        } else {
            document.set("ok", true);
        }
        match &error {
            None => output::document(&document),
            Some(error) => output::document(&report::with_failure(document, error)),
        }
    } else {
        output::lines(&transfer_lines(
            descriptor.display_number.get(),
            &receiver.display_name,
            (from, new_grant_id),
            result.map(|result| &result.revoked),
        ));
        if let Some(error) = &error {
            report::failed(error);
        }
    }
    Ok(error.map_or(Completion::Done, Completion::Reported))
}

/// What a transfer did, as lines for a person: where the session went, and how far each affected
/// session's worker has got in fencing the giving device's grant. A grant some worker has not
/// fenced, or whose result was not read, is not said to be revoked.
fn transfer_lines(
    session_number: u64,
    receiver_name: &str,
    (from, new_grant_id): (GrantId, GrantId),
    revoked: Option<&RevocationResult>,
) -> Vec<Line> {
    let Some(revoked) = revoked else {
        return vec![stdout_line!(
            "Session {} was handed to {}. Grant {} holds it. Whether grant {}, the giving \
             device's, is revoked and fenced is not known: the host's answer was not read.",
            session_number,
            Asked::text(Request::Devices, receiver_name),
            new_grant_id,
            from
        )];
    };
    let first = if revoked.barrier.holds() {
        stdout_line!(
            "Session {} is now with {}. Grant {} holds it; grant {} was revoked, at authority \
             revision {}.",
            session_number,
            Asked::text(Request::Devices, receiver_name),
            new_grant_id,
            from,
            revoked.authority_revision
        )
    } else {
        stdout_line!(
            "Session {} is now with {}. Grant {} holds it. The revocation of grant {} is \
             pending, at authority revision {}: it is complete only when these sessions' workers \
             fence it.",
            session_number,
            Asked::text(Request::Devices, receiver_name),
            new_grant_id,
            from,
            revoked.authority_revision
        )
    };
    crate::device::barrier_lines(first, &revoked.barrier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::pairing::DevicePlatform;
    use kr_protocol::scalars::Uuid;

    const NOW: u64 = 1_764_000_000_000;

    fn device(seed: u8, name: &str) -> DeviceSummary {
        DeviceSummary {
            device_id: DeviceId::new(Uuid::from_bytes([seed; 16])),
            display_name: name.to_owned(),
            grant_id: GrantId::new(Uuid::from_bytes([seed; 16])),
            paired_at_ms: TimestampMs::new(1),
            revoked: false,
            keys: Nullable::null(),
            manages_host: false,
            platform: DevicePlatform::Ios,
            grant_expires_at_ms: Nullable::null(),
            grant_expired: false,
            all_sessions: false,
        }
    }

    /// A share lasts an hour when the device's pairing has room for it, until the pairing's end
    /// less the host's room to date it when it does not, and is refused when it cannot fit or
    /// would hardly begin.
    #[test]
    fn a_share_lasts_as_long_as_the_pairing_allows() {
        let room = |ends_in: u64| Some(NOW + ends_in);
        assert_eq!(
            lifetime(None, None, NOW).expect("an hour"),
            DEFAULT_LIFETIME_MS
        );
        assert_eq!(
            lifetime(None, room(2 * 60 * 60_000), NOW).expect("an hour"),
            DEFAULT_LIFETIME_MS
        );
        assert_eq!(
            lifetime(None, room(30 * 60_000), NOW).expect("until the pairing ends"),
            30 * 60_000 - CLAIM_MARGIN_MS
        );
        assert_eq!(
            lifetime(Some(Lasts::Pairing), room(30 * 60_000), NOW).expect("the pairing's room"),
            30 * 60_000 - CLAIM_MARGIN_MS
        );
        assert_eq!(
            lifetime(Some(Lasts::For(15 * 60_000)), room(30 * 60_000), NOW).expect("fits"),
            15 * 60_000
        );
        for refused in [
            lifetime(Some(Lasts::For(60 * 60_000)), room(30 * 60_000), NOW),
            lifetime(Some(Lasts::Pairing), None, NOW),
            lifetime(None, room(30_000), NOW),
            lifetime(Some(Lasts::For(30 * 60_000)), room(30 * 60_000), NOW),
        ] {
            assert!(matches!(refused, Err(CliError::Usage(_))), "{refused:?}");
        }
    }

    /// A share is asked for what is left of the end the person was shown, so the time spent at the
    /// question comes out of the share and not out of what was shown; and too little left to begin
    /// is refused.
    #[test]
    fn a_share_is_asked_for_what_is_left_of_the_end_that_was_shown() {
        let ends = NOW + 15 * 60_000;
        assert_eq!(
            remaining_lifetime(ends, NOW).expect("all of it"),
            15 * 60_000
        );
        assert_eq!(
            remaining_lifetime(ends, NOW + 40_000).expect("less the time at the question"),
            15 * 60_000 - 40_000
        );
        for now in [ends - 30_000, ends, ends + 1] {
            assert!(
                matches!(remaining_lifetime(ends, now), Err(CliError::Usage(_))),
                "{now}"
            );
        }
    }

    /// A command that cannot read the host stops waiting a set time after the bound it was waiting
    /// for, and not before: until the bound nothing it reads counts, and every read that reaches
    /// the host decides after it.
    #[test]
    fn a_command_waits_for_a_host_it_cannot_read_only_so_long() {
        let bound = Duration::from_secs(330);
        assert!(!has_waited_enough(Duration::ZERO, bound));
        assert!(!has_waited_enough(bound, bound));
        assert!(!has_waited_enough(
            bound + READ_PATIENCE - Duration::from_millis(1),
            bound
        ));
        assert!(has_waited_enough(bound + READ_PATIENCE, bound));
    }

    /// The words of `--role`, `--for` and `--history` are the ones the help names, and Reviewer is
    /// not among the roles.
    #[test]
    fn the_arguments_are_the_words_the_help_names() {
        assert_eq!(parse_role("viewer").expect("a role"), SessionRole::Viewer);
        assert_eq!(parse_role("owner").expect("a role"), SessionRole::Owner);
        assert!(parse_role("reviewer").is_err());
        assert_eq!(parse_lasts("pairing").expect("a time"), Lasts::Pairing);
        assert_eq!(
            parse_lasts("7d").expect("a time"),
            Lasts::For(7 * 24 * 60 * 60_000)
        );
        assert!(parse_lasts("forever").is_err());
        assert_eq!(
            parse_history("none", NOW).expect("a cursor"),
            Nullable::null()
        );
        assert_eq!(
            parse_history("1h", NOW).expect("a cursor"),
            Nullable::some(TimestampMs::new(NOW - 60 * 60_000))
        );
        assert_eq!(
            parse_history("all", NOW).expect("a cursor"),
            Nullable::some(TimestampMs::new(0))
        );
        assert!(parse_history("last year", NOW).is_err());
    }

    /// A device is named by identifier or by a name exactly one has, and a device that cannot take
    /// a share is refused with the reason: it manages the host, its pairing already opens every
    /// session, its pairing ran out, or it was revoked.
    #[test]
    fn a_device_is_named_by_identifier_or_by_a_name_one_device_has() {
        let mut owner = device(1, "laptop");
        owner.manages_host = true;
        let mut wide = device(2, "tablet");
        wide.all_sessions = true;
        let mut ran_out = device(3, "old phone");
        ran_out.grant_expired = true;
        let mut revoked = device(4, "lost phone");
        revoked.revoked = true;
        let phone = device(5, "phone");
        let twin_a = device(6, "twin");
        let twin_b = device(7, "twin");
        let devices = [owner, wide, ran_out, revoked, phone.clone(), twin_a, twin_b];

        assert_eq!(
            pick_device(&devices, "phone", &Shown::said(""))
                .expect("by name")
                .device_id,
            phone.device_id
        );
        assert_eq!(
            pick_device(&devices, &phone.device_id.to_string(), &Shown::said(""))
                .expect("by identifier")
                .device_id,
            phone.device_id
        );
        for refused in [
            "laptop",
            "tablet",
            "old phone",
            "lost phone",
            "nobody",
            "twin",
        ] {
            assert!(
                matches!(
                    pick_device(&devices, refused, &Shown::said("")),
                    Err(CliError::Usage(_))
                ),
                "{refused}"
            );
        }
        let by_identifier = devices[3].device_id.to_string();
        assert!(
            matches!(
                pick_device(&devices, &by_identifier, &Shown::said("")),
                Err(CliError::Usage(_))
            ),
            "a revoked device is refused even by identifier"
        );
    }

    /// The lines of a screen are shown with what a terminal would act on or hide written out, so
    /// the text on the page is the text the session printed.
    #[test]
    fn a_screen_line_shows_its_control_and_hidden_characters() {
        let line = visibly("ok\u{1b}[31m red \u{202e}gnp.exe\u{7}\u{200b}");
        assert_eq!(
            line,
            "ok\\u{001b}[31m red \\u{202e}gnp.exe\\u{0007}\\u{200b}"
        );
        assert_eq!(visibly("plain text ünï"), "plain text ünï");
    }

    /// A share to a device, as the host lists it, carrying exactly these rights.
    fn share_with(seed: u8, rights: &[ActionRight]) -> GrantSummary {
        use kr_protocol::grant::{
            EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector,
        };
        use kr_protocol::ids::AuthorityRevision;

        GrantSummary {
            grant: Grant {
                grant_id: GrantId::new(Uuid::from_bytes([seed; 16])),
                parent_grant_id: Nullable::null(),
                issuer_device_id: DeviceId::new(Uuid::from_bytes([200; 16])),
                recipient_device_id: DeviceId::new(Uuid::from_bytes([seed; 16])),
                authority_revision: AuthorityRevision::new(1),
                environment_selector: EnvironmentSelector::Any,
                session_selector: SessionSelector::None,
                actions: rights.iter().copied().collect(),
                history: HistoryScope {
                    lower_bound_ms: Nullable::null(),
                    include_live_screen: false,
                    named_questions: CanonicalSet::new(),
                    named_approvals: CanonicalSet::new(),
                },
                expiry: GrantExpiry::At {
                    expires_at_ms: TimestampMs::new(NOW),
                },
                organisation: Nullable::null(),
            },
            state: GrantState::Active,
            revoked_at_ms: Nullable::null(),
            revoked_by_parent: Nullable::null(),
            ends_at_ms: Nullable::some(TimestampMs::new(NOW)),
        }
    }

    /// The text of the line `kr share list` prints for a share.
    fn listed(rights: &[ActionRight]) -> String {
        let devices = DeviceListResult {
            devices: Vec::new(),
            authority_revision: kr_protocol::ids::AuthorityRevision::new(1),
            feed_synchronised_at_ms: Nullable::null(),
            feed_stale: false,
            feed_removed: false,
        };
        list_line(&share_with(1, rights), &devices)
            .text()
            .to_owned()
    }

    /// KR-REQ-10.42: a viewer who may answer the agent's questions is not listed as a plain
    /// viewer. The role is the widest one whose rights the share carries in full, and each right
    /// beyond it is named beside it.
    #[test]
    fn a_viewer_who_may_answer_is_listed_with_the_answer() {
        let answering = listed(&[ActionRight::SessionView, ActionRight::QuestionRespond]);
        assert!(answering.contains("viewer"), "{answering}");
        assert!(answering.contains("question.respond"), "{answering}");
    }

    /// KR-REQ-10.42: the grant of a voice call in the default scope, with prompt submission added,
    /// carries `session.view`, `agent.prompt` and `voice.use`, so it is a viewer with the other two
    /// rights named, not a plain viewer.
    #[test]
    fn a_voice_calls_grant_is_listed_with_its_rights() {
        let call = listed(&[
            ActionRight::SessionView,
            ActionRight::AgentPrompt,
            ActionRight::VoiceUse,
        ]);
        assert!(call.contains("viewer"), "{call}");
        for right in ["agent.prompt", "voice.use"] {
            assert!(call.contains(right), "{call}");
        }
    }

    /// KR-REQ-10.42: every role includes the view of the session, so a share without it has no
    /// role. It is not called a viewer; each right it carries is named.
    #[test]
    fn a_share_with_no_view_of_the_session_is_listed_with_its_rights() {
        let blind = listed(&[ActionRight::AgentApprovalRespond, ActionRight::AgentPrompt]);
        assert!(!blind.contains("viewer"), "{blind}");
        for right in ["agent.approval.respond", "agent.prompt"] {
            assert!(blind.contains(right), "{blind}");
        }
    }

    /// A share that carries exactly a role's rights says the role and no right: nothing is left
    /// unnamed, and nothing is said twice.
    #[test]
    fn a_share_that_carries_exactly_a_role_is_listed_by_the_role_alone() {
        for role in SessionRole::ALL {
            let line = listed(role.default_actions());
            assert!(line.contains(role.as_str()), "{line}");
            for right in role.default_actions() {
                assert!(!line.contains(right.as_str()), "{role}: {line}");
            }
        }
    }

    /// A revocation one session's worker has not fenced, in an answer where the host counted
    /// `total` workers and listed that one.
    fn waiting_on_one_of(total: u64) -> RevocationResult {
        use kr_protocol::action::{BarrierState, RevocationBarrier, WorkerBarrier};
        use kr_protocol::ids::AuthorityRevision;
        use kr_protocol::scalars::U64;

        let worker = WorkerBarrier {
            session_id: SessionId::new(Uuid::from_bytes([2; 16])),
            state: BarrierState::Pending,
            acknowledged_revision: Nullable::null(),
            rejected_actions: Vec::new(),
            rejected_actions_total: U64::new(0),
            possibly_executed: Vec::new(),
            possibly_executed_total: U64::new(0),
            omitted_actions: U64::new(0),
            names_pending: U64::new(0),
            detail: String::new(),
        };
        let mut barrier = RevocationBarrier::new(AuthorityRevision::new(4), vec![worker]);
        barrier.workers_total = U64::new(total);
        RevocationResult {
            authority_revision: AuthorityRevision::new(4),
            revoked_grants: CanonicalSet::new(),
            revoked_grants_total: U64::new(0),
            barrier,
        }
    }

    /// KR-REQ-18.14, a transfer: the giving device's grant is revoked with the transfer, so what the
    /// command says of it is a revocation's. It states the authority revision, names each worker the
    /// host listed with its state, says it is pending while a worker has not fenced it, and says the
    /// grant is revoked only when every worker has, or nothing of it when the host's answer was not
    /// read.
    #[test]
    fn a_transfer_states_the_revision_and_each_worker_and_says_revoked_only_when_fenced() {
        let written = |lines: Vec<Line>| -> String {
            lines
                .iter()
                .map(|line| format!("{}\n", line.text()))
                .collect()
        };
        let from = GrantId::new(Uuid::from_bytes([7; 16]));
        let new = GrantId::new(Uuid::from_bytes([8; 16]));
        let waiting = waiting_on_one_of(1);
        let text = written(transfer_lines(3, "Sam", (from, new), Some(&waiting)));
        assert!(text.contains("authority revision 4"), "{text}");
        assert!(text.contains("pending"), "{text}");
        assert!(
            text.contains(&format!(
                "session {}: pending",
                SessionId::new(Uuid::from_bytes([2; 16]))
            )),
            "{text}"
        );
        assert!(
            !text.contains("was revoked"),
            "a grant a worker has not fenced is not called revoked: {text}"
        );

        let mut fenced = waiting_on_one_of(1);
        fenced.barrier.workers[0].state = kr_protocol::action::BarrierState::Acknowledged;
        let text = written(transfer_lines(3, "Sam", (from, new), Some(&fenced)));
        assert!(
            text.contains("was revoked, at authority revision 4"),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "session {}: acknowledged",
                SessionId::new(Uuid::from_bytes([2; 16]))
            )),
            "a grant every worker has fenced still names each worker and its state: {text}"
        );

        let text = written(transfer_lines(3, "Sam", (from, new), None));
        assert!(
            !text.contains("was revoked") && text.contains("not known"),
            "an unread answer claims nothing of the grant: {text}"
        );
    }

    /// When the host cut its list of workers it named those still waiting first, so how many it
    /// names is a floor, and the failure says "at least"; a whole list gives the count.
    #[test]
    fn a_revocation_whose_list_the_host_cut_is_pending_for_at_least_the_workers_it_names() {
        let reported = |total| {
            let revoke = Shown::said("kr share revoke");
            let grant = GrantId::new(Uuid::from_bytes([9; 16]));
            match finish_revocation(grant, Some(&waiting_on_one_of(total)), &revoke, false) {
                Ok(Completion::Reported(error)) => error.to_string(),
                _ => panic!("a pending revocation is a reported failure"),
            }
        };
        assert!(
            reported(5_000).contains("at least 1 session worker has not fenced it"),
            "{}",
            reported(5_000)
        );
        assert!(!reported(1).contains("at least"), "{}", reported(1));
    }

    /// The list document carries the device's own name only as asked-for text, and every other leaf
    /// as the protocol encodes it.
    #[test]
    fn planted_text_in_the_shares_shows_only_the_name_a_device_gave_itself() {
        use crate::output::planted::{only_asked, planted};

        let mut shown = std::collections::BTreeSet::new();
        for listed in planted::<GrantListResult>() {
            for devices in planted::<DeviceListResult>() {
                let document = list_document(&listed, &devices);
                shown.extend(only_asked("kr share list", &document));
            }
        }
        assert!(
            shown.iter().all(|path| path.ends_with("recipient_name")),
            "{shown:?}"
        );
    }

    fn a_challenge() -> kr_protocol::pairing::OwnerConfirmationRequest {
        use kr_protocol::ids::{ConfirmationId, DeviceId};
        use kr_protocol::pairing::SensitiveAction;
        use kr_protocol::scalars::{Digest256, EndpointKey, Nonce256};
        kr_protocol::pairing::OwnerConfirmationRequest {
            confirmation_id: ConfirmationId::new(Uuid::from_bytes([1; 16])),
            action: SensitiveAction::TrustRepositoryRoot,
            action_digest: Digest256::from_bytes([1; 32]),
            destination_keys: Nullable::null(),
            destination_rights: CanonicalSet::new(),
            host_device_id: DeviceId::new(Uuid::from_bytes([3; 16])),
            host_endpoint_id: EndpointKey::from_bytes([5; 32]),
            nonce: Nonce256::from_bytes([4; 32]),
            expires_at_ms: TimestampMs::new(1),
        }
    }

    /// KR-REQ-07.47: the wait for an owner device to answer a transfer's confirmation reads the
    /// host's list as the other owner-device commands do. It ends with the challenge, on this
    /// process's own clock, and not after the time any read is given: a host that does not answer,
    /// or a connection that fails, ends the command with nothing changed and the reason, with the
    /// status of a host that is not there; a challenge the host stops listing, or lists to its
    /// end unanswered, is one that ran out, and so is a read the challenge's end cuts short; the
    /// wait ends at the challenge's end and not a pause later. A request the host's release cannot
    /// read was not sent, and the wait ends with the host's own code and says which request it
    /// was. The controls are a challenge an owner device has answered and a refusal of the host's,
    /// which is its own.
    #[tokio::test(start_paused = true)]
    async fn the_wait_for_an_owner_device_to_confirm_a_transfer_ends_with_the_challenge_and_says_why()
     {
        use kr_protocol::confirmation::{ConfirmationDisplay, PendingConfirmation};
        use std::sync::atomic::{AtomicUsize, Ordering};

        // The outer bound is the test's own: a wait that is never given up never ends.
        let outer = Duration::from_secs(3600);
        let request = a_challenge();
        let listing = |answered: bool| OwnerConfirmationPendingResult {
            pending: vec![PendingConfirmation {
                request: request.clone(),
                display: ConfirmationDisplay::EstablishClock,
                answered,
            }],
        };
        let nothing_changed = |error: &CliError| error.to_string().contains("Nothing was changed");

        // A host that does not answer the read is given the time any request is given, and not
        // the ten seconds a read of the list was once given: on the paused clock, thirty.
        let started = tokio::time::Instant::now();
        let silent = tokio::time::timeout(
            outer,
            answered_by_an_owner_device(
                started + Duration::from_secs(600),
                POLL_EVERY,
                &request,
                async || std::future::pending::<Result<OwnerConfirmationPendingResult>>().await,
            ),
        )
        .await
        .expect("the wait was given up when the host did not answer");
        let Err(unanswered @ CliError::HostUnavailable(_)) = silent else {
            panic!("the host did not answer");
        };
        assert_eq!(unanswered.exit_code(), 3);
        assert!(nothing_changed(&unanswered), "{unanswered}");
        assert_eq!(started.elapsed(), Duration::from_secs(30));

        // A read the challenge's end cuts short, five seconds on, is the challenge running out, and
        // is given up there.
        let started = tokio::time::Instant::now();
        let cut = tokio::time::timeout(
            outer,
            answered_by_an_owner_device(
                started + Duration::from_secs(5),
                POLL_EVERY,
                &request,
                async || std::future::pending::<Result<OwnerConfirmationPendingResult>>().await,
            ),
        )
        .await
        .expect("the wait was given up at the challenge's end");
        let Err(cut @ CliError::ServiceRefused { .. }) = cut else {
            panic!("the challenge ran out");
        };
        assert_eq!(cut.code(), ErrorCode::OwnerConfirmationRequired);
        assert_eq!(started.elapsed(), Duration::from_secs(5));

        // A connection that fails before the host answers.
        let lost = answered_by_an_owner_device(
            tokio::time::Instant::now() + Duration::from_secs(60),
            POLL_EVERY,
            &request,
            async || Err(CliError::Ipc(kr_ipc::IpcError::PeerClosed)),
        )
        .await;
        let Err(lost @ CliError::HostUnavailable(_)) = lost else {
            panic!("the connection failed");
        };
        assert!(nothing_changed(&lost), "{lost}");

        // A challenge listed to its end, unanswered, is asked about every poll until then and ends
        // the wait there; one the host stops listing ends it at once.
        let reads = AtomicUsize::new(0);
        let ran_out = tokio::time::timeout(
            outer,
            answered_by_an_owner_device(
                tokio::time::Instant::now() + Duration::from_secs(5),
                POLL_EVERY,
                &request,
                async || {
                    reads.fetch_add(1, Ordering::SeqCst);
                    Ok(listing(false))
                },
            ),
        )
        .await
        .expect("the wait ended with the challenge");
        let Err(ran_out @ CliError::ServiceRefused { .. }) = ran_out else {
            panic!("the challenge ran out");
        };
        assert_eq!(ran_out.code(), ErrorCode::OwnerConfirmationRequired);
        assert!(
            reads.load(Ordering::SeqCst) > 1,
            "the host's list is read again until the challenge ends"
        );
        // The wait ends where the challenge does, and not up to one poll later: a deadline that is
        // not a whole number of polls cuts the last sleep short.
        let started = tokio::time::Instant::now();
        let part_way = tokio::time::timeout(
            outer,
            answered_by_an_owner_device(
                started + POLL_EVERY * 5 + POLL_EVERY / 4,
                POLL_EVERY,
                &request,
                async || Ok(listing(false)),
            ),
        )
        .await
        .expect("the wait ended with the challenge");
        let Err(part_way @ CliError::ServiceRefused { .. }) = part_way else {
            panic!("the challenge ran out");
        };
        assert_eq!(part_way.code(), ErrorCode::OwnerConfirmationRequired);
        assert_eq!(started.elapsed(), POLL_EVERY * 5 + POLL_EVERY / 4);
        let reads = AtomicUsize::new(0);
        let unlisted = answered_by_an_owner_device(
            tokio::time::Instant::now() + Duration::from_secs(60),
            POLL_EVERY,
            &request,
            async || {
                reads.fetch_add(1, Ordering::SeqCst);
                Ok(OwnerConfirmationPendingResult { pending: vec![] })
            },
        )
        .await;
        let Err(unlisted @ CliError::ServiceRefused { .. }) = unlisted else {
            panic!("the challenge is not listed");
        };
        assert_eq!(unlisted.code(), ErrorCode::OwnerConfirmationRequired);
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        // A request the host's release cannot read is not written, and the connection stands: the
        // wait ends with the host's own code, and says which request it was.
        let unread = answered_by_an_owner_device(
            tokio::time::Instant::now() + Duration::from_secs(60),
            POLL_EVERY,
            &request,
            async || {
                Err(CliError::Ipc(kr_ipc::IpcError::NotInLevel(
                    "a request the level cannot read".to_owned(),
                )))
            },
        )
        .await;
        let Err(unread) = unread else {
            panic!("the request was not written");
        };
        assert_eq!(unread.code(), ErrorCode::UnsupportedCapability);
        assert!(nothing_changed(&unread), "{unread}");
        assert!(
            unread.to_string().contains("the request for the list"),
            "{unread}"
        );

        // The controls.
        let live = tokio::time::Instant::now() + Duration::from_secs(60);
        answered_by_an_owner_device(live, POLL_EVERY, &request, async || Ok(listing(true)))
            .await
            .expect("an owner device has answered");
        let refused = answered_by_an_owner_device(live, POLL_EVERY, &request, async || {
            Err(CliError::Refused(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "no",
            )))
        })
        .await;
        assert!(matches!(refused, Err(CliError::Refused(_))));
    }
}
