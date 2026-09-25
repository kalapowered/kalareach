//! `kr pair`: issuing an invitation, approving the device that answers it, and withdrawing or
//! reading one.
//!
//! Every effect here is one of the host's pairing methods over this user's own local socket, and
//! issuing an invitation and approving a device each need a fresh owner confirmation naming
//! exactly that action. The command asks the host for the confirmation's challenge first, and the
//! host's answer says who can confirm it:
//!
//! * **A host with an owner.** An owner device confirms, in its own ceremony. The command says so
//!   and asks for the effect again every second until the host spends that confirmation, or until
//!   the challenge runs out.
//! * **A host with no owner yet.** The first owner is established here, at this terminal. The
//!   person confirms at the controlling terminal, typing `pair` to issue the owner invitation and,
//!   to approve the device that answers it, the verification value that device shows. The command
//!   then answers the challenge on the `local_bootstrap_terminal` channel with a key it makes for
//!   that one answer. The host takes that channel only while it has no owner, and only for issuing
//!   a personal owner invitation and approving the device that answers it; the pairing that
//!   commits ends it for good.
//!
//! Answering on the terminal channel is guarded against starting by accident from inside a
//! KalaReach session, which is where an agent runs. Standard input and output must be terminals,
//! the controlling terminal must open, neither `KR_SESSION` nor `KR_ATTACHMENT` may be set, and
//! every live session's worker must say this process is not one of its own (see
//! [`crate::bind::membership`]); anything that cannot be established refuses. The guard protects
//! against an agent starting the ceremony by accident. It is not isolation from other code running
//! as the same user, which can do anything this command does.

use kr_client::shown;
use kr_client::shown::Shown;
use std::fs::File;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::time::Duration;

use kr_crypto::keys::AuthorisationKeyPair;
use kr_ipc::client::LocalClient;
use kr_ipc::paths::HostPaths;
use kr_pairing::confirm::sign_confirmation;
use kr_pairing::grants::{personal_owner_grant, session_invitation_grant};
use kr_protocol::confirmation::{
    ConfirmationSubject, OwnerConfirmationCompleteParams, OwnerConfirmationCompleteResult,
    OwnerConfirmationRequestParams, OwnerConfirmationRequestResult,
};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::HistoryScope;
use kr_protocol::ids::{ActionId, BuildId, InvitationId};
use kr_protocol::invitation::{
    InviteEntry, InviteGrantKind, InviteMode, InviteModeKind, PairCancelParams, PairCandidateView,
    PairConfirmParams, PairConfirmResult, PairInviteParams, PairInviteResult,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    ConfirmationChannel, DevicePlatform, PairStatus, PairingConsumedReason, ProposedGrant,
    RendezvousOrigin, group_verification_value,
};
use kr_protocol::preauth::{PairStatusParams, PairStatusResult};
use kr_protocol::scalars::{CanonicalSet, Nullable};

use crate::bind::{self, Membership};
use crate::cli::{PairCancelArguments, PairCommand, PairInvitationArguments, PairInviteArguments};
use crate::error::{CliError, Result};
use crate::resolve::{self, ATTACHMENT_VARIABLE, SESSION_VARIABLE};

/// How often the command asks again while an owner device has not confirmed yet.
pub const OWNER_DEVICE_POLL: Duration = Duration::from_secs(1);

/// What a person types to issue a host's first owner invitation.
pub const ISSUE_WORD: &str = "pair";

/// The most of one typed line the command reads.
const MAX_TYPED_LINE: u64 = 256;

/// The modules of blank space around a QR code, which a reader needs to find it.
const QUIET_ZONE: i32 = 4;

/// Black on white, whatever the terminal's own colours are.
const BLACK_ON_WHITE: &str = "\x1b[30;47m";

/// Back to the terminal's own colours.
const RESET: &str = "\x1b[0m";

/// Runs one `kr pair` command and prints its result.
///
/// # Errors
///
/// Returns the host's refusal, a refusal of the first-owner guard, or a transport failure.
pub async fn run(paths: &HostPaths, command: PairCommand, json: bool) -> Result<()> {
    let build_id = crate::build_id();
    match command {
        PairCommand::Invite(arguments) => invite(paths, &arguments, json, &build_id).await,
        PairCommand::Confirm(arguments) => approve(paths, &arguments, json, &build_id).await,
        PairCommand::Cancel(arguments) => cancel(paths, &arguments, json, &build_id).await,
        PairCommand::Status(arguments) => status(paths, &arguments, json, &build_id).await,
    }
}

/// `kr pair invite`.
async fn invite(
    paths: &HostPaths,
    arguments: &PairInviteArguments,
    json: bool,
    build_id: &BuildId,
) -> Result<()> {
    let (grant_kind, proposed_grant) = proposal(arguments, kr_ipc::now_ms().get())?;
    let (mode, mode_kind, origin) = offer(arguments)?;
    let environment = resolve::select(paths, arguments.environment.as_deref())?;
    let target = ActionTarget::environment(environment.environment_id);
    let mut client = resolve::open_controller(&environment.paths, build_id.clone()).await?;
    let subject = ConfirmationSubject::IssueInvitation {
        mode: mode_kind,
        rendezvous_origin: origin.map_or_else(Nullable::null, Nullable::some),
        grant_kind,
        proposed_grant: proposed_grant.clone(),
    };
    let effect = Effect::Invite(PairInviteParams {
        mode,
        grant_kind,
        proposed_grant,
    });
    let ceremony = Ceremony::Issue {
        owner: grant_kind == InviteGrantKind::PersonalOwner,
    };
    let answer = confirmed(&mut client, target, subject, &ceremony, &effect, build_id).await?;
    let invited: PairInviteResult = decode(&answer)?;
    if json {
        print_json(&invitation_document(&invited));
    } else {
        print!(
            "{}",
            describe_invitation(&invited, kr_ipc::now_ms().get(), true)?
        );
    }
    Ok(())
}

/// `kr pair confirm`.
async fn approve(
    paths: &HostPaths,
    arguments: &PairInvitationArguments,
    json: bool,
    build_id: &BuildId,
) -> Result<()> {
    let invitation_id = invitation(&arguments.invitation)?;
    let environment = resolve::select(paths, arguments.environment.as_deref())?;
    let target = ActionTarget::environment(environment.environment_id);
    let mut client = resolve::open_controller(&environment.paths, build_id.clone()).await?;
    let status: PairStatusResult = bind::read(
        &mut client,
        Method::PairStatus,
        &PairStatusParams { invitation_id },
    )
    .await?;
    let view = status.owner.0.ok_or_else(|| {
        refused(
            ErrorCode::PermissionDenied,
            "only the owner who issued this invitation approves the device that answers it",
        )
    })?;
    let (Some(candidate), Some(approval)) = (view.candidate.0, view.approval.0) else {
        return Err(refused(
            ErrorCode::PermissionDenied,
            "no device has answered this invitation yet: approve it once the new device shows \
             its verification value",
        ));
    };
    let effect = Effect::Confirm(PairConfirmParams {
        invitation_id,
        approval,
    });
    let ceremony = Ceremony::Approve {
        candidate: &candidate,
    };
    let answer = confirmed(
        &mut client,
        target,
        ConfirmationSubject::ConfirmDevice { invitation_id },
        &ceremony,
        &effect,
        build_id,
    )
    .await?;
    let paired: PairConfirmResult = decode(&answer)?;
    if json {
        print_json(&serde_json::json!({
            "ok": true,
            "invitation_id": invitation_id.to_string(),
            "device_id": paired.device_id.to_string(),
            "grant_id": paired.grant_id.to_string(),
            "device_name": candidate.device_name.as_str(),
            "platform": platform_name(&candidate),
        }));
    } else {
        println!(
            "Paired {} ({}) as device {}, with grant {}.",
            candidate.device_name.as_str(),
            platform_name(&candidate),
            paired.device_id,
            paired.grant_id
        );
    }
    Ok(())
}

/// `kr pair cancel`.
async fn cancel(
    paths: &HostPaths,
    arguments: &PairCancelArguments,
    json: bool,
    build_id: &BuildId,
) -> Result<()> {
    let invitation_id = invitation(&arguments.invitation)?;
    let environment = resolve::select(paths, arguments.environment.as_deref())?;
    let target = ActionTarget::environment(environment.environment_id);
    let mut client = resolve::open_controller(&environment.paths, build_id.clone()).await?;
    let result: PairStatusResult = bind::mutate(
        &mut client,
        Method::PairCancel,
        target,
        &PairCancelParams {
            invitation_id,
            deny: arguments.deny,
        },
    )
    .await?;
    report_status(invitation_id, &result, json)
}

/// `kr pair status`.
async fn status(
    paths: &HostPaths,
    arguments: &PairInvitationArguments,
    json: bool,
    build_id: &BuildId,
) -> Result<()> {
    let invitation_id = invitation(&arguments.invitation)?;
    let environment = resolve::select(paths, arguments.environment.as_deref())?;
    let mut client = resolve::open_controller(&environment.paths, build_id.clone()).await?;
    let result: PairStatusResult = bind::read(
        &mut client,
        Method::PairStatus,
        &PairStatusParams { invitation_id },
    )
    .await?;
    report_status(invitation_id, &result, json)
}

fn report_status(invitation_id: InvitationId, result: &PairStatusResult, json: bool) -> Result<()> {
    if json {
        let mut document = serde_json::to_value(result).map_err(|error| {
            CliError::Other(shown!(
                "the status could not be written: {}",
                Shown::json(&error)
            ))
        })?;
        document["ok"] = serde_json::json!(true);
        document["invitation_id"] = serde_json::json!(invitation_id.to_string());
        print_json(&document);
    } else {
        print!(
            "{}",
            describe_status(invitation_id, result, kr_ipc::now_ms().get())
        );
    }
    Ok(())
}

/// The effect an owner confirmation is obtained for.
enum Effect {
    Invite(PairInviteParams),
    Confirm(PairConfirmParams),
}

/// What the person at this terminal confirms, when the host has no owner yet.
enum Ceremony<'a> {
    /// Issuing an invitation; `owner` when it proposes a personal owner grant.
    Issue { owner: bool },
    /// Approving the device that answered an invitation.
    Approve { candidate: &'a PairCandidateView },
}

impl Ceremony<'_> {
    /// Refuses what a host with no owner yet cannot confirm at a terminal, before anything is
    /// asked of the person.
    fn bootstrap_permits(&self) -> Result<()> {
        match self {
            Self::Issue { owner: false } => Err(refused(
                ErrorCode::PermissionDenied,
                "this host has no owner yet: pair its first owner with `kr pair invite --owner`",
            )),
            Self::Issue { owner: true } | Self::Approve { .. } => Ok(()),
        }
    }

    /// What the person at this terminal is told while an owner device confirms.
    ///
    /// The owner device shows the new device's verification value in its own prompt; saying it
    /// here too, grouped the same way, lets the person at the host check both screens against it.
    fn owner_device_note(&self) -> Option<Shown> {
        match self {
            Self::Issue { .. } => None,
            Self::Approve { candidate } => Some(owner_device_note(
                candidate.platform,
                &candidate.verification_value,
            )),
        }
    }

    /// Asks the person at the controlling terminal to confirm, and refuses unless they do.
    fn confirm_at(&self, terminal: &mut Terminal) -> Result<()> {
        match self {
            Self::Issue { .. } => {
                terminal.say(
                    "This host has no owner yet. The device that answers this invitation becomes \
                     its first owner, with every right over this host until it is revoked.\n",
                )?;
                let typed =
                    terminal.ask(&format!("Type {ISSUE_WORD} to issue the invitation: "))?;
                if typed.trim() != ISSUE_WORD {
                    return Err(not_confirmed("the invitation was not issued"));
                }
            }
            Self::Approve { candidate } => {
                terminal.say(&format!(
                    "{} ({}) answered this invitation, and becomes this host's first owner if you \
                     approve it.\n",
                    candidate.device_name.as_str(),
                    platform_name(candidate)
                ))?;
                let typed = terminal.ask("Type the verification value the new device shows: ")?;
                if !same_value(&typed, &candidate.verification_value) {
                    return Err(not_confirmed(
                        "that is not the verification value this host sees, so the device was not \
                         approved",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Obtains a fresh owner confirmation for `subject`, then performs the effect it confirms.
async fn confirmed(
    client: &mut LocalClient,
    target: ActionTarget,
    subject: ConfirmationSubject,
    ceremony: &Ceremony<'_>,
    effect: &Effect,
    build_id: &BuildId,
) -> Result<ParamsValue> {
    let challenge: OwnerConfirmationRequestResult = bind::mutate(
        client,
        Method::OwnerConfirmationRequest,
        target.clone(),
        &OwnerConfirmationRequestParams { subject },
    )
    .await?;
    if challenge.initial_bootstrap {
        ceremony.bootstrap_permits()?;
        guard(build_id).await?;
        let mut terminal = Terminal::open()?;
        ceremony.confirm_at(&mut terminal)?;
        let key = AuthorisationKeyPair::generate().map_err(|error| {
            CliError::Other(shown!("no key could be made: {}", Shown::crypto(&error)))
        })?;
        let proof = sign_confirmation(
            &key,
            &challenge.request,
            ConfirmationChannel::LocalBootstrapTerminal,
        )
        .map_err(|error| {
            CliError::Other(shown!(
                "the confirmation could not be signed: {}",
                Shown::pairing(&error)
            ))
        })?;
        let _: OwnerConfirmationCompleteResult = bind::mutate(
            client,
            Method::OwnerConfirmationComplete,
            target.clone(),
            &OwnerConfirmationCompleteParams {
                proof,
                bootstrap_signer: Nullable::some(*key.public()),
            },
        )
        .await?;
        return perform(client, target, effect)
            .await?
            .map_err(CliError::Refused);
    }
    let expires_at_ms = challenge.request.expires_at_ms.get();
    if let Some(note) = ceremony.owner_device_note() {
        crate::report::say(&note);
    }
    crate::report::say(&shown!(
        "Confirm this on an owner device. Waiting {}.",
        remaining(expires_at_ms, kr_ipc::now_ms().get())
    ));
    loop {
        match perform(client, target.clone(), effect).await? {
            Ok(answer) => return Ok(answer),
            Err(error)
                if error.code == ErrorCode::OwnerConfirmationRequired
                    && kr_ipc::now_ms().get() < expires_at_ms =>
            {
                tokio::time::sleep(OWNER_DEVICE_POLL).await;
            }
            Err(error) => return Err(CliError::Refused(error)),
        }
    }
}

/// Asks for the effect once, under an action identity of its own.
async fn perform(
    client: &mut LocalClient,
    target: ActionTarget,
    effect: &Effect,
) -> Result<std::result::Result<ParamsValue, ProtocolError>> {
    let action = ActionId::new(kr_ipc::new_uuid());
    Ok(match effect {
        Effect::Invite(params) => {
            client
                .mutate(Method::PairInvite, action, target, params)
                .await?
        }
        Effect::Confirm(params) => {
            client
                .mutate(Method::PairConfirm, action, target, params)
                .await?
        }
    })
}

/// Refuses unless this is where a host's first owner may be confirmed: at an interactive
/// terminal, outside every KalaReach session.
async fn guard(build_id: &BuildId) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(CliError::NotATerminal);
    }
    for variable in [SESSION_VARIABLE, ATTACHMENT_VARIABLE] {
        if std::env::var_os(variable).is_some() {
            return Err(refused(
                ErrorCode::PermissionDenied,
                shown!(
                    "{} is set, so this is inside a KalaReach session; a host's first owner is \
                     confirmed at a terminal outside every session",
                    variable
                ),
            ));
        }
    }
    match bind::membership(build_id).await {
        Membership::Outside => Ok(()),
        Membership::Inside(session_id) => Err(refused(
            ErrorCode::PermissionDenied,
            shown!(
                "this process is inside session {}; a host's first owner is confirmed at a \
                 terminal outside every session",
                session_id
            ),
        )),
        Membership::Unknown(why) => Err(refused(
            ErrorCode::PermissionDenied,
            shown!(
                "whether this process is inside a KalaReach session cannot be established ({}); a \
                 host's first owner is confirmed only where it can",
                why
            ),
        )),
    }
}

/// The terminal the person types at, opened as itself rather than through this command's
/// standard streams.
struct Terminal {
    input: BufReader<File>,
    output: File,
}

impl Terminal {
    /// Opens the controlling terminal.
    fn open() -> Result<Self> {
        #[cfg(unix)]
        let (input, output) = (
            File::options().read(true).open("/dev/tty"),
            File::options().write(true).open("/dev/tty"),
        );
        #[cfg(windows)]
        let (input, output) = (
            File::options().read(true).write(true).open("CONIN$"),
            File::options().read(true).write(true).open("CONOUT$"),
        );
        let (Ok(input), Ok(output)) = (input, output) else {
            return Err(CliError::NotATerminal);
        };
        Ok(Self {
            input: BufReader::new(input),
            output,
        })
    }

    fn say(&mut self, text: &str) -> Result<()> {
        self.output
            .write_all(text.as_bytes())
            .and_then(|()| self.output.flush())
            .map_err(|error| {
                CliError::Terminal(shown!(
                    "the terminal could not be written: {}",
                    Shown::io(&error)
                ))
            })
    }

    /// Writes `prompt` and reads one line.
    fn ask(&mut self, prompt: &str) -> Result<String> {
        self.say(prompt)?;
        let mut line = String::new();
        (&mut self.input)
            .take(MAX_TYPED_LINE)
            .read_line(&mut line)
            .map_err(|error| {
                CliError::Terminal(shown!(
                    "the terminal could not be read: {}",
                    Shown::io(&error)
                ))
            })?;
        Ok(line)
    }
}

/// Returns the grant an invitation proposes, and its kind.
fn proposal(
    arguments: &PairInviteArguments,
    now_ms: u64,
) -> Result<(InviteGrantKind, ProposedGrant)> {
    match (arguments.owner, arguments.view) {
        (true, None) => Ok((InviteGrantKind::PersonalOwner, personal_owner_grant())),
        (false, Some(minutes)) => {
            let history = HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: true,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            };
            let grant = session_invitation_grant(now_ms, minutes.saturating_mul(60_000), history)
                .map_err(|error| {
                CliError::Usage(shown!("--view {}: {}", minutes, Shown::pairing(&error)))
            })?;
            Ok((InviteGrantKind::SessionInvitation, grant))
        }
        _ => Err(CliError::Usage(Shown::said(
            "say what the new device may do: --owner, or --view with the minutes it may view \
             sessions for",
        ))),
    }
}

/// Returns how the invitation is offered.
fn offer(
    arguments: &PairInviteArguments,
) -> Result<(InviteMode, InviteModeKind, Option<RendezvousOrigin>)> {
    if arguments.direct {
        if arguments.origin.is_some() {
            return Err(CliError::Usage(Shown::said(
                "a direct invitation is scanned on this network and contacts no rendezvous \
                 service, so it takes no --origin",
            )));
        }
        return Ok((InviteMode::Direct, InviteModeKind::Direct, None));
    }
    let origin = arguments
        .origin
        .as_deref()
        .map(|text| {
            RendezvousOrigin::new(text).map_err(|error| {
                CliError::Usage(shown!(
                    "--origin {} is not a rendezvous origin: {}",
                    Shown::address(text),
                    error
                ))
            })
        })
        .transpose()?;
    Ok((
        InviteMode::Code {
            rendezvous_origin: origin.clone().map_or_else(Nullable::null, Nullable::some),
        },
        InviteModeKind::Code,
        origin,
    ))
}

fn invitation(text: &str) -> Result<InvitationId> {
    text.parse().map_err(|_| {
        CliError::Usage(Shown::said(
            "the text given is not an invitation identifier",
        ))
    })
}

/// Says which value the new device should show, grouped as both devices show it.
///
/// The device is named by its platform. The name it gave itself is text it chose, which the owner
/// device that confirms shows in its own prompt.
fn owner_device_note(platform: DevicePlatform, verification_value: &str) -> Shown {
    shown!(
        "The new device ({}) should show {}. Confirm on an owner device only if it does.",
        crate::shown::platform(platform),
        crate::shown::verification_value(verification_value)
    )
}

/// Compares a typed verification value with the host's, ignoring case, spaces and hyphens.
fn same_value(typed: &str, expected: &str) -> bool {
    let normal = |text: &str| {
        text.chars()
            .filter(|character| !character.is_whitespace() && *character != '-')
            .flat_map(char::to_lowercase)
            .collect::<String>()
    };
    let typed = normal(typed);
    !typed.is_empty() && typed == normal(expected)
}

/// Says how long is left until `until_ms`, in words.
fn remaining(until_ms: u64, now_ms: u64) -> Shown {
    let seconds = until_ms.saturating_sub(now_ms) / 1000;
    match seconds {
        0 => Shown::said("no longer"),
        1..=59 => shown!("for {} seconds", seconds),
        _ => {
            let minutes = seconds / 60;
            let unit = if minutes == 1 { "minute" } else { "minutes" };
            shown!("for {} {}", minutes, unit)
        }
    }
}

fn platform_name(candidate: &PairCandidateView) -> String {
    serde_json::to_value(candidate.platform)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Describes an issued invitation for a person, with its QR code when `draw` says to.
///
/// # Errors
///
/// Returns an error when the invitation's QR text is too long for a QR code.
pub fn describe_invitation(invited: &PairInviteResult, now_ms: u64, draw: bool) -> Result<String> {
    let mut text = format!(
        "Invitation {}, open {}.\n",
        invited.invitation_id,
        remaining(invited.expires_at_ms.get(), now_ms)
    );
    let qr = match &invited.entry {
        InviteEntry::Code {
            rendezvous_origin,
            code,
            qr_text,
        } => {
            text.push_str(&format!(
                "Code: {}  at {}\nEnter the code on the new device, or scan this QR code with it:\n",
                code.as_str(),
                rendezvous_origin.as_str()
            ));
            qr_text
        }
        InviteEntry::Direct { qr_text } => {
            text.push_str("Scan this QR code with the new device, on this network:\n");
            qr_text
        }
    };
    if draw {
        for line in qr_lines(qr.as_str())? {
            text.push_str(&line);
            text.push('\n');
        }
    }
    text.push_str(&format!(
        "When the new device shows its verification value, approve it with:\n  kr pair confirm {}\n",
        invited.invitation_id
    ));
    Ok(text)
}

fn invitation_document(invited: &PairInviteResult) -> serde_json::Value {
    let mut document = serde_json::json!({
        "ok": true,
        "invitation_id": invited.invitation_id.to_string(),
        "expires_at_ms": invited.expires_at_ms.get(),
    });
    match &invited.entry {
        InviteEntry::Code {
            rendezvous_origin,
            code,
            qr_text,
        } => {
            document["mode"] = serde_json::json!("code");
            document["code"] = serde_json::json!(code.as_str());
            document["rendezvous_origin"] = serde_json::json!(rendezvous_origin.as_str());
            document["qr_text"] = serde_json::json!(qr_text.as_str());
        }
        InviteEntry::Direct { qr_text } => {
            document["mode"] = serde_json::json!("direct");
            document["qr_text"] = serde_json::json!(qr_text.as_str());
        }
    }
    document
}

/// Describes where an invitation has reached, for a person.
fn describe_status(invitation_id: InvitationId, result: &PairStatusResult, now_ms: u64) -> String {
    let state = match &result.status {
        PairStatus::Open {
            remaining_confirmations,
            expires_at_ms,
        } => {
            let open = format!("open {}", remaining(expires_at_ms.get(), now_ms));
            // Only a code can be guessed at, so only a code invitation has an allowance to show.
            let code = result
                .owner
                .0
                .as_ref()
                .is_none_or(|view| view.mode == InviteModeKind::Code);
            if code {
                format!(
                    "{open}, with {remaining_confirmations} wrong codes allowed before it closes"
                )
            } else {
                open
            }
        }
        PairStatus::Locked { expires_at_ms, .. } => format!(
            "a device has proved the code and is finishing, open {}",
            remaining(expires_at_ms.get(), now_ms)
        ),
        PairStatus::AwaitingApproval {
            verification_value,
            expires_at_ms,
            ..
        } => format!(
            "a device is waiting for approval, open {}; its verification value is {}",
            remaining(expires_at_ms.get(), now_ms),
            group_verification_value(verification_value)
        ),
        PairStatus::Committed {
            device_id,
            grant_id,
        } => format!("paired as device {device_id}, with grant {grant_id}"),
        PairStatus::Consumed { reason } => format!("ended: {}", ended_because(*reason)),
    };
    let mut text = format!("Invitation {invitation_id}: {state}.\n");
    if let Some(candidate) = result
        .owner
        .0
        .as_ref()
        .and_then(|view| view.candidate.0.as_ref())
    {
        text.push_str(&format!(
            "The device is {} ({}).\n",
            candidate.device_name.as_str(),
            platform_name(candidate)
        ));
    }
    if matches!(result.status, PairStatus::AwaitingApproval { .. }) {
        text.push_str(&format!(
            "Check the new device shows the same value, then approve it with:\n  kr pair confirm \
             {invitation_id}\n"
        ));
    }
    text
}

const fn ended_because(reason: PairingConsumedReason) -> &'static str {
    match reason {
        PairingConsumedReason::Denied => "the device was denied",
        PairingConsumedReason::Expired => "the invitation ran out of time",
        PairingConsumedReason::Cancelled => "the invitation was withdrawn",
        PairingConsumedReason::AttemptsExhausted => "too many wrong codes were tried",
        PairingConsumedReason::HostRestarted => "the host restarted before it finished",
    }
}

/// Draws `text` as a QR code in terminal cells: one module to a cell's width and two to its
/// height, black on white whatever the terminal's own colours are, inside the quiet zone a reader
/// needs.
///
/// # Errors
///
/// Returns an error when `text` is too long for a QR code.
pub fn qr_lines(text: &str) -> Result<Vec<String>> {
    let code = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Low)
        .map_err(|_| CliError::Other(Shown::said("the invitation is too long for a QR code")))?;
    let edge = code.size() + 2 * QUIET_ZONE;
    let dark = |x: i32, y: i32| code.get_module(x - QUIET_ZONE, y - QUIET_ZONE);
    Ok((0..edge)
        .step_by(2)
        .map(|y| {
            let mut line = String::from(BLACK_ON_WHITE);
            for x in 0..edge {
                line.push(match (dark(x, y), dark(x, y + 1)) {
                    (true, true) => '\u{2588}',
                    (true, false) => '\u{2580}',
                    (false, true) => '\u{2584}',
                    (false, false) => ' ',
                });
            }
            line.push_str(RESET);
            line
        })
        .collect())
}

fn decode<T: kr_protocol::wire::WireMessage>(value: &ParamsValue) -> Result<T> {
    value.to_typed().map_err(|error| {
        CliError::Other(shown!(
            "the host's answer could not be read: {}",
            Shown::cbor(&error)
        ))
    })
}

fn refused(code: ErrorCode, message: impl Into<Shown>) -> CliError {
    CliError::Refused(kr_client::error::refusal(code, message.into()))
}

fn not_confirmed(message: &'static str) -> CliError {
    refused(ErrorCode::OwnerConfirmationRequired, Shown::said(message))
}

fn print_json(value: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_owned())
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::invitation::QrText;
    use kr_protocol::pairing::{CodeQrPayload, QrPayload, ShortCode};
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{TimestampMs, Uuid};

    fn arguments(owner: bool, view: Option<u64>) -> PairInviteArguments {
        PairInviteArguments {
            owner,
            view,
            direct: false,
            origin: None,
            environment: None,
        }
    }

    /// KR-REQ-10.04: an invitation says what the new device may do, and nothing chooses that for
    /// the owner: an owner device gets the personal owner grant, a viewer `session.view` for the
    /// minutes named, and a command that names neither is a usage mistake.
    #[test]
    fn an_invitation_names_what_the_device_may_do() {
        let now = 1_764_000_000_000;
        let (kind, grant) = proposal(&arguments(true, None), now).expect("an owner invitation");
        assert_eq!(kind, InviteGrantKind::PersonalOwner);
        assert_eq!(grant, personal_owner_grant());

        let (kind, grant) = proposal(&arguments(false, Some(30)), now).expect("a viewer");
        assert_eq!(kind, InviteGrantKind::SessionInvitation);
        assert_eq!(
            grant.actions.iter().copied().collect::<Vec<_>>(),
            vec![ActionRight::SessionView]
        );
        assert_eq!(
            grant.expiry,
            kr_protocol::grant::GrantExpiry::At {
                expires_at_ms: TimestampMs::new(now + 30 * 60_000)
            }
        );

        for (owner, view) in [(false, None), (false, Some(0)), (false, Some(60 * 24 * 31))] {
            assert!(matches!(
                proposal(&arguments(owner, view), now),
                Err(CliError::Usage(_))
            ));
        }
    }

    /// A direct invitation contacts no rendezvous service, so it takes no origin, and a code
    /// invitation's origin is a canonical one.
    #[test]
    fn an_origin_is_named_only_for_a_code_and_only_canonically() {
        let mut direct = arguments(true, None);
        direct.direct = true;
        let (mode, kind, origin) = offer(&direct).expect("a direct offer");
        assert_eq!(mode, InviteMode::Direct);
        assert_eq!(kind, InviteModeKind::Direct);
        assert!(origin.is_none());
        direct.origin = Some("https://rendezvous.example".to_owned());
        assert!(matches!(offer(&direct), Err(CliError::Usage(_))));

        let mut code = arguments(true, None);
        code.origin = Some("https://rendezvous.example".to_owned());
        let (_, kind, origin) = offer(&code).expect("a code offer");
        assert_eq!(kind, InviteModeKind::Code);
        assert_eq!(
            origin.map(|origin| origin.as_str().to_owned()),
            Some("https://rendezvous.example".to_owned())
        );
        code.origin = Some("https://Rendezvous.example/".to_owned());
        assert!(matches!(offer(&code), Err(CliError::Usage(_))));
    }

    /// KR-REQ-10.04: a code invitation is shown as its code beside the origin it is reserved at,
    /// with a QR code that carries both, and the command that approves the device that answers.
    #[test]
    fn a_code_invitation_is_shown_with_its_origin_and_a_qr_code() {
        let now = 1_764_000_000_000;
        let origin = RendezvousOrigin::new("https://reach.kala.to").expect("an origin");
        let code = ShortCode::new("4XkP-Qm7-Zr2").expect("a code");
        let payload = QrPayload::Code(CodeQrPayload {
            rendezvous_origin: origin.clone(),
            code: code.clone(),
        });
        let text = payload.to_text().expect("the payload's text");
        let invited = PairInviteResult {
            invitation_id: InvitationId::new(Uuid::from_bytes([9; 16])),
            expires_at_ms: TimestampMs::new(now + 5 * 60_000),
            entry: InviteEntry::Code {
                rendezvous_origin: origin,
                code,
                qr_text: QrText::new(text.as_str()).expect("QR text"),
            },
        };
        let shown = describe_invitation(&invited, now, true).expect("a description");
        assert!(
            shown.contains("Code: 4XkP-Qm7-Zr2  at https://reach.kala.to"),
            "{shown}"
        );
        assert!(shown.contains("open for 5 minutes"), "{shown}");
        assert!(
            shown.contains(&format!("kr pair confirm {}", invited.invitation_id)),
            "{shown}"
        );
        let drawn = qr_lines(text.as_str()).expect("a QR code");
        assert!(drawn.iter().all(|line| shown.contains(line.as_str())));
        let document = invitation_document(&invited);
        assert_eq!(document["mode"], "code");
        assert_eq!(document["code"], "4XkP-Qm7-Zr2");
        assert_eq!(document["rendezvous_origin"], "https://reach.kala.to");
    }

    /// A QR code is drawn square, black on white, inside its quiet zone: every line is as wide as
    /// the code and the zone around it, the zone's rows are blank, and the top-left finder
    /// pattern's corner is dark where it belongs.
    #[test]
    fn a_qr_code_is_drawn_square_inside_its_quiet_zone() {
        let text = "kr-pair:a test payload";
        let code = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Low).expect("a code");
        let edge = usize::try_from(code.size() + 2 * QUIET_ZONE).expect("a size");
        let lines = qr_lines(text).expect("drawn");
        assert_eq!(lines.len(), edge.div_ceil(2));
        let cells: Vec<Vec<char>> = lines
            .iter()
            .map(|line| {
                let inner = line
                    .strip_prefix(BLACK_ON_WHITE)
                    .and_then(|rest| rest.strip_suffix(RESET))
                    .expect("black on white");
                inner.chars().collect()
            })
            .collect();
        assert!(cells.iter().all(|row| row.len() == edge));
        assert!(cells[0].iter().all(|cell| *cell == ' '), "the quiet zone");
        assert!(cells[1].iter().all(|cell| *cell == ' '), "the quiet zone");
        // Module (0, 0) is the finder pattern's corner, at cell row 2 (modules 4 and 5) and
        // column 4: dark above, dark below.
        assert_eq!(cells[2][4], '\u{2588}');
    }

    /// KR-REQ-10.37: the verification value is printed in the same two groups of four the new
    /// device shows, never as eight characters run together.
    #[test]
    fn a_verification_value_is_printed_grouped() {
        let now = 1_764_000_000_000;
        let invitation_id = InvitationId::new(Uuid::from_bytes([9; 16]));
        let waiting = PairStatusResult {
            status: PairStatus::AwaitingApproval {
                attempt_id: kr_protocol::ids::AttemptId::new(Uuid::from_bytes([3; 16])),
                verification_value: "f3c146fd".to_owned(),
                expires_at_ms: TimestampMs::new(now + 60_000),
            },
            owner: kr_protocol::scalars::Nullable::null(),
        };
        let shown = describe_status(invitation_id, &waiting, now);
        assert!(shown.contains("f3c1 46fd"), "{shown}");
        assert!(!shown.contains("f3c146fd"), "{shown}");
        assert_eq!(
            owner_device_note(DevicePlatform::Android, "f3c146fd").as_str(),
            "The new device (android) should show f3c1 46fd. Confirm on an owner device only if \
             it does."
        );
        // A value the host sent in any other shape is not repeated.
        let marked = owner_device_note(DevicePlatform::Android, crate::shown::marker::MARKER);
        crate::shown::marker::assert_unmarked(
            "the owner device note",
            &[marked.as_str().to_owned()],
        );
    }

    /// The value a person types is compared with the host's without regard to case, spaces or
    /// hyphens, and nothing typed is never a match.
    #[test]
    fn a_typed_verification_value_is_compared_as_a_person_types_it() {
        assert!(same_value("1A2B 3C4D\n", "1a2b3c4d"));
        assert!(same_value("1a2b-3c4d", "1a2b3c4d"));
        assert!(!same_value("1a2b3c4e", "1a2b3c4d"));
        assert!(!same_value("\n", ""));
        assert!(!same_value("", "1a2b3c4d"));
    }
}
