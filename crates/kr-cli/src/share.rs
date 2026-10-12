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
fn pick_device<'a>(listed: &'a [DeviceSummary], text: &str) -> Result<&'a DeviceSummary> {
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
        return Err(CliError::Usage(Shown::said(
            "no paired device has that identifier or name; `kr device list` shows them",
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
        return Err(CliError::Usage(Shown::said(
            "that device's pairing already opens every session, so a share to it adds nothing the \
             connection can use; pair it as a guest (`kr pair invite --guest`) to share one session",
        )));
    }
    if device.grant_expired {
        return Err(CliError::Usage(Shown::said(
            "that device's pairing has run out; pair it again before sharing a session with it",
        )));
    }
    Ok(device)
}

/// A line of the session's screen, with everything a terminal would act on or hide written out.
///
/// The lines are what the session printed, which is whatever a program in it wrote.
fn visibly(line: &str) -> String {
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

/// The words for a role, in the order the share form gives them.
const fn role_words(role: SessionRole) -> &'static str {
    match role {
        SessionRole::Viewer => "watch the session",
        SessionRole::Reviewer => "watch the session and read files",
        SessionRole::Controller => {
            "watch the session, type in its terminal, resize it, prompt the agent and answer"
        }
        SessionRole::Owner => "do all of that, and also manage sharing and close the session",
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
fn reply_of(
    sent: &std::result::Result<std::result::Result<ParamsValue, ProtocolError>, kr_ipc::IpcError>,
) -> Reply {
    match sent {
        Ok(Ok(_)) => Reply::Result,
        Ok(Err(refusal)) => Reply::Refused(refusal.retry),
        // A connection that went after the request was composed may have carried it or not, which
        // is what asking again is for.
        Err(_) => Reply::Lost,
    }
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
    challenge: Option<Duration>,
) -> Result<Performed> {
    let request = host
        .client
        .compose(method, action_id, target, params)
        .await
        .map_err(CliError::Ipc)?;
    let window = host.client.action_window().clone();
    let composed = ComposedMutation::restored(
        request.clone(),
        window.issued_at_ms.get(),
        window.valid_for_ms.get(),
    );
    let mut attempt = Attempt::new(
        kind,
        &composed,
        host.environment.environment_id.to_string(),
        "local",
        Some(watch.grant_id),
        kr_ipc::now_ms().get(),
        "kr share",
    );
    if let Some(lifetime) = challenge {
        attempt.bound_by_challenge(lifetime);
    }
    let armed = Armed::now();
    report::say(&shown!(
        "The grant this writes is {}. If this command is interrupted, `kr share list` shows it \
         once the host has written it.",
        watch.grant_id
    ));

    let first = host.client.repeat(&request).await;
    let mut performed = Performed {
        outcome: Outcome::Unknown,
        value: None,
        refusal: None,
    };
    take(&mut performed, &first);
    let mut next = attempt.after_first_send(reply_of(&first));
    let mut waited_notice = false;
    loop {
        match next {
            Next::Closed(outcome) => {
                performed.outcome = outcome;
                return Ok(performed);
            }
            Next::NotSent => {
                return Err(CliError::Other(Shown::said(
                    "the request was not sent, so nothing happened",
                )));
            }
            Next::Repeat => {
                let index = usize::from(attempt.repeats).min(REPEAT_DELAYS.len() - 1);
                tokio::time::sleep(REPEAT_DELAYS[index]).await;
                let reply = match host.another().await {
                    Ok(mut second) => {
                        let sent = second.repeat(&request).await;
                        take(&mut performed, &sent);
                        reply_of(&sent)
                    }
                    Err(_) => Reply::Lost,
                };
                next = attempt.after_repeat(reply);
            }
            Next::Check | Next::Wait => {
                if !waited_notice {
                    waited_notice = true;
                    report::say(&shown!(
                        "The host did not answer, so its state is read until it shows what \
                         became of this; an absent grant counts only after {} seconds from the \
                         first send.",
                        attempt.bound().as_secs()
                    ));
                }
                tokio::time::sleep(CHECK_EVERY).await;
                let found = found(host, kind, watch).await;
                next = match found {
                    Some(found) => attempt.after_read(found, armed.elapsed()),
                    // A read that fails leaves the attempt as it was.
                    None => Next::Wait,
                };
            }
        }
    }
}

/// Keeps what the host said, when it said the result or a refusal.
fn take(
    performed: &mut Performed,
    sent: &std::result::Result<std::result::Result<ParamsValue, ProtocolError>, kr_ipc::IpcError>,
) {
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
fn unfinished(outcome: Outcome, what: &'static str, list: &Shown) -> CliError {
    let message = match outcome {
        Outcome::NotDone | Outcome::NotAccepted => shown!(
            "{} did not happen, as far as the host shows, and nothing more of it can; it is safe \
             to run the command again. {}",
            what,
            list.clone()
        ),
        Outcome::HadEnded => shown!(
            "the grant had already ended when {} was asked, so this did nothing to it. {}",
            what,
            list.clone()
        ),
        Outcome::Unknown | Outcome::Happened | Outcome::Refused => shown!(
            "what became of {} is not known: the host did not answer and its state does not \
             show. {}",
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
    let device = pick_device(&devices.devices, &arguments.to)?.clone();
    let pairing_ends = device.grant_expires_at_ms.as_ref().map(|ends| ends.get());
    lifetime(asked_lasts, pairing_ends, now_ms)?;

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
    let summary = summary_of(
        &descriptor,
        &device,
        &selection,
        &notices,
        asked_lasts,
        now_ms,
        shown_lines.as_deref(),
    )?;
    if arguments.yes {
        for line in &summary {
            let _ = output::write_line(&mut std::io::stderr(), line);
        }
    } else {
        pair::guard(build_id).await?;
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

    // Decided now, after the question: the host dates the share when it accepts the action.
    let now_ms = kr_ipc::now_ms().get();
    let lifetime_ms = lifetime(asked_lasts, pairing_ends, now_ms)?;
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
    let performed = perform(
        &mut host,
        Kind::Invite,
        Method::GrantCreate,
        target,
        action_id,
        &params,
        &Watch {
            session_id: Some(session_id),
            grant_id,
        },
        None,
    )
    .await?;
    let list = shown!(
        "`kr share list {} --all` shows what the host holds.",
        descriptor.display_number.get()
    );
    match performed.outcome {
        Outcome::Refused => {
            return Err(performed.refusal.map_or_else(
                || CliError::Other(Shown::said("the host refused the share")),
                CliError::Refused,
            ));
        }
        Outcome::Happened => {}
        other => return Err(unfinished(other, "the invitation", &list)),
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
    if json {
        output::document(&invite_document(
            grant_id,
            invitation_id,
            session_id,
            &device,
            role,
            created.as_ref(),
            changed,
        ));
    } else {
        output::lines(&invited_lines(
            &descriptor,
            &device,
            grant_id,
            invitation_id,
            created.as_ref(),
        ));
        match (changed, &created) {
            (Some(true), Some(created)) => {
                output::lines(&screen_changed_lines(created));
                report::say(&shown!(
                    "The screen changed before the invitation was written. Withdraw it with `kr \
                     share revoke {}`.",
                    grant_id
                ));
            }
            (None, _) if arguments.live => {
                report::say(&shown!(
                    "The host's answer was not read here, so the lines it kept could not be \
                     compared with the ones shown. Withdraw the invitation with `kr share revoke \
                     {}` if the screen has changed.",
                    grant_id
                ));
            }
            _ => {}
        }
    }
    Ok(Completion::Done)
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
fn summary_of(
    descriptor: &WorkerDescriptor,
    device: &DeviceSummary,
    selection: &RoleSelection,
    notices: &CanonicalSet<AuthorityNotice>,
    asked_lasts: Option<Lasts>,
    now_ms: u64,
    screen: Option<&[String]>,
) -> Result<Vec<Line>> {
    let pairing_ends = device.grant_expires_at_ms.as_ref().map(|ends| ends.get());
    let lasts = lifetime(asked_lasts, pairing_ends, now_ms)?;
    let name = Asked::text(Request::Devices, &device.display_name);
    let mut lines = vec![
        stdout_line!(
            "Share session {} with {} ({}).",
            descriptor.display_number.get(),
            name,
            crate::output::closed_word(&device.platform)
        ),
        stdout_line!(
            "  Role: {}, which lets it {}.",
            selection.role.as_str(),
            role_words(selection.role)
        ),
        stdout_line!("  Rights: {}.", rights_line(&selection.actions())),
        stdout_line!(
            "  Until {}, used once.{}",
            crate::shown::utc_moment(now_ms.saturating_add(lasts)),
            if pairing_ends.is_some() {
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
        Some(from) => stdout_line!(
            "  Earlier activity: the agent's conversation, questions and events from {}.",
            crate::shown::utc_moment(from.get())
        ),
    });
    if selection.include_live_screen {
        lines.push(stdout_line!(
            "  The live screen is included. It never shows the terminal's scrollback."
        ));
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
    Ok(lines)
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

/// The invitation, for a script.
fn invite_document(
    grant_id: GrantId,
    invitation_id: InvitationId,
    session_id: SessionId,
    device: &DeviceSummary,
    role: SessionRole,
    created: Option<&GrantCreateResult>,
    screen_changed: Option<bool>,
) -> Document {
    Document::new()
        .with("grant_id", closed(&grant_id))
        .with("invitation_id", closed(&invitation_id))
        .with("session_id", closed(&session_id))
        .with("device_id", closed(&device.device_id))
        .with(
            "device_name",
            Asked::text(Request::Devices, &device.display_name),
        )
        .with("role", closed(&role))
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

/// One share as a line.
fn list_line(summary: &GrantSummary, devices: &DeviceListResult) -> Line {
    let role = kr_controller::sharing::roles::describes(&summary.grant.actions)
        .map_or("custom", SessionRole::as_str);
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
        "{}  {}  {} {}  session {}  {}  {}",
        summary.grant.grant_id,
        output::left(24, &Shown::said(state_words(summary.state))),
        summary.grant.recipient_device_id,
        device.unwrap_or_else(|| Asked::text(Request::Devices, "")),
        session.map_or_else(|| Shown::said("none"), |session| shown!("{}", *session)),
        Shown::said(role),
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
    let performed = perform(
        &mut host,
        Kind::Revoke,
        Method::GrantRevoke,
        target,
        ActionId::new(kr_ipc::new_uuid()),
        &GrantRevokeParams { grant_id },
        &Watch {
            session_id,
            grant_id,
        },
        None,
    )
    .await?;
    let list = Shown::said("`kr share list --all` shows what the host holds.");
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
            finish_revocation(grant_id, revoked.as_ref(), json)
        }
        other => Err(unfinished(other, "the revocation", &list)),
    }
}

/// Prints a revocation and fails while a worker has not fenced it.
fn finish_revocation(
    grant_id: GrantId,
    revoked: Option<&RevocationResult>,
    json: bool,
) -> Result<Completion> {
    let Some(revoked) = revoked else {
        // The host's state shows the grant revoked, and its answer was not read here, so the
        // barrier is not known and is not claimed.
        let error = CliError::Unfinished {
            code: ErrorCode::ResourceUnavailable,
            message: shown!(
                "grant {} is revoked, and whether each session's worker has fenced it is not \
                 known: the host's answer was not read; run `kr share revoke {}` again to ask \
                 each worker",
                grant_id,
                grant_id
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
            "the revocation of grant {} is recorded and still pending: {} session worker{} {} \
             not fenced it yet, and `kr share revoke {}` again reports how far it has got",
            grant_id,
            pending.len(),
            if pending.len() == 1 { "" } else { "s" },
            if pending.len() == 1 { "has" } else { "have" },
            grant_id
        ),
    });
    if json {
        let document = Document::new()
            .with("grant_id", closed(&grant_id))
            .with("authority_revision", closed(&revoked.authority_revision))
            .with("revoked_grants", closed(&revoked.revoked_grants))
            .with(
                "revoked_grants_total",
                closed(&revoked.revoked_grants_total),
            )
            .with("barrier_holds", revoked.barrier.holds())
            .with("ok", true);
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

/// What a revocation did, as lines for a person.
fn revocation_lines(grant_id: GrantId, revoked: &RevocationResult) -> Vec<Line> {
    let grants = usize::try_from(revoked.revoked_grants_total.get()).unwrap_or(usize::MAX);
    let mut lines = vec![if revoked.barrier.holds() {
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
    }];
    for worker in &revoked.barrier.workers {
        if !worker.state.holds() {
            lines.push(stdout_line!(
                "  session {}: {}",
                worker.session_id,
                worker.state.as_str()
            ));
        }
    }
    lines
}

// ---------------------------------------------------------------------------------------------
// kr share transfer
// ---------------------------------------------------------------------------------------------

/// How long a confirmation's challenge lasts, which the host's reply bounds the transfer by.
const CHALLENGE_LIFETIME: Duration = Duration::from_secs(120);

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
    let receiver = pick_device(&devices.devices, &arguments.to)?.clone();
    if !devices
        .devices
        .iter()
        .any(|device| device.manages_host && !device.revoked && !device.grant_expired)
    {
        return Err(CliError::refused_in_its_own_words(
            ErrorCode::OwnerConfirmationRequired,
            Shown::said(
                "no owner device is paired with this host, so nobody can confirm a transfer of \
                 control; pair one with `kr pair invite --owner`",
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
    loop {
        let pending: OwnerConfirmationPendingResult = host
            .read(
                Method::OwnerConfirmationPending,
                &OwnerConfirmationPendingParams {},
            )
            .await?;
        match pending
            .pending
            .iter()
            .find(|waiting| waiting.request == challenge.request)
        {
            Some(waiting) if waiting.answered => break,
            Some(_) if kr_ipc::now_ms().get() < expires_at_ms => {
                tokio::time::sleep(POLL_EVERY).await;
            }
            _ => {
                return Err(CliError::refused_in_its_own_words(
                    ErrorCode::OwnerConfirmationRequired,
                    Shown::said(
                        "the confirmation ran out or was taken before an owner device answered \
                         it, so nothing was handed over; ask again",
                    ),
                ));
            }
        }
    }

    let uid = host.client.acknowledgement().peer.uid.get();
    let new_grant_id = transfer_identity(&local_actor(uid), transfer_action);
    let lifetime = CHALLENGE_LIFETIME.saturating_sub(received.elapsed());
    let target = crate::attach::target(&descriptor);
    let performed = perform(
        &mut host,
        Kind::Transfer,
        Method::GrantTransfer,
        target,
        transfer_action,
        &params,
        &Watch {
            session_id: Some(session_id),
            grant_id: new_grant_id,
        },
        Some(CHALLENGE_LIFETIME.min(lifetime.max(Duration::from_secs(1)))),
    )
    .await?;
    let list = shown!(
        "`kr share list {} --all` shows what the host holds.",
        descriptor.display_number.get()
    );
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
                from,
                new_grant_id,
                result.as_ref(),
                json,
            )
        }
        other => Err(unfinished(other, "the transfer", &list)),
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
    let mut sent = host.client.repeat(&request).await;
    let mut asked_again = 0;
    loop {
        match sent {
            Ok(Ok(value)) => {
                return value.to_typed().map_err(|error| {
                    CliError::Other(shown!(
                        "the host's answer could not be read: {}",
                        Shown::cbor(&error)
                    ))
                });
            }
            Ok(Err(refusal)) => return Err(CliError::Refused(refusal)),
            Err(_) if asked_again < REPEAT_DELAYS.len() => {
                tokio::time::sleep(REPEAT_DELAYS[asked_again]).await;
                asked_again += 1;
                sent = match host.another().await {
                    Ok(mut second) => second.repeat(&request).await,
                    Err(error) => Err(match error {
                        CliError::Ipc(error) => error,
                        _ => kr_ipc::IpcError::UnexpectedMessage("the daemon could not be reached"),
                    }),
                };
            }
            Err(error) => return Err(CliError::Ipc(error)),
        }
    }
}

/// Prints a transfer and fails while a worker has not fenced what it took from the giver.
fn finish_transfer(
    descriptor: &WorkerDescriptor,
    receiver: &DeviceSummary,
    from: GrantId,
    new_grant_id: GrantId,
    result: Option<&GrantTransferResult>,
    json: bool,
) -> Result<Completion> {
    let pending = result.map(|result| result.revoked.barrier.pending().len());
    let error = match pending {
        Some(0) => None,
        Some(waiting) => Some(CliError::Unfinished {
            code: ErrorCode::ResourceUnavailable,
            message: shown!(
                "the transfer is recorded and the giving device's grant is revoked, and {} \
                 session worker{} {} not fenced it yet; `kr share revoke {}` again reports how \
                 far it has got",
                waiting,
                if waiting == 1 { "" } else { "s" },
                if waiting == 1 { "has" } else { "have" },
                from
            ),
        }),
        None => Some(CliError::Unfinished {
            code: ErrorCode::ResourceUnavailable,
            message: shown!(
                "the transfer happened, and whether each session's worker has fenced the giving \
                 device's grant is not known: the host's answer was not read; `kr share revoke \
                 {}` again asks each worker",
                from
            ),
        }),
    };
    if json {
        let document = Document::new()
            .with("session_id", closed(&descriptor.session_id))
            .with("from_grant_id", closed(&from))
            .with("new_grant_id", closed(&new_grant_id))
            .with("to_device_id", closed(&receiver.device_id))
            .with(
                "barrier_holds",
                result.map(|result| result.revoked.barrier.holds()),
            )
            .with("ok", true);
        match &error {
            None => output::document(&document),
            Some(error) => output::document(&report::with_failure(document, error)),
        }
    } else {
        output::line(&stdout_line!(
            "Session {} is now with {}. Grant {} holds it; grant {} was revoked.",
            descriptor.display_number.get(),
            Asked::text(Request::Devices, &receiver.display_name),
            new_grant_id,
            from
        ));
        if let Some(error) = &error {
            report::failed(error);
        }
    }
    Ok(error.map_or(Completion::Done, Completion::Reported))
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
            acknowledged_revision: Nullable::null(),
            acknowledged_at_ms: Nullable::null(),
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
            pick_device(&devices, "phone").expect("by name").device_id,
            phone.device_id
        );
        assert_eq!(
            pick_device(&devices, &phone.device_id.to_string())
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
                matches!(pick_device(&devices, refused), Err(CliError::Usage(_))),
                "{refused}"
            );
        }
        let by_identifier = devices[3].device_id.to_string();
        assert!(
            matches!(
                pick_device(&devices, &by_identifier),
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
}
