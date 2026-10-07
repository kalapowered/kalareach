//! `kr pair`: issuing an invitation, approving the device that answers it, and withdrawing or
//! reading one; and `kr host clock --establish`, which is the owner's confirmation of the host's
//! clock and is obtained the same way.
//!
//! Every effect here is one of the host's pairing methods over this user's own local socket, and
//! issuing an invitation, approving a device and establishing the host's clock each need a fresh
//! owner confirmation naming exactly that action. The command asks the host for the confirmation's
//! challenge first, and the host's answer says who can confirm it:
//!
//! * **A host with an owner.** An owner device confirms, in its own ceremony. The command says so
//!   and asks for the effect again every second until the host spends that confirmation, or until
//!   the challenge runs out.
//! * **A host with no owner yet.** The first owner is established here, at this terminal. The
//!   person confirms at the controlling terminal, typing `pair` to issue the owner invitation and,
//!   to approve the device that answers it, the verification value that device shows; to establish
//!   the host's clock the person reads the time the host gives and types `clock`. The command
//!   then answers the challenge on the `local_bootstrap_terminal` channel with a key it makes for
//!   that one answer. The host takes that channel only while it has no owner, and only for issuing
//!   a personal owner invitation, approving the device that answers it and establishing its
//!   clock; the pairing that commits ends it for good.
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
    ConfirmationSubject, HostClockEstablishParams, HostClockEstablishResult,
    OwnerConfirmationCompleteParams, OwnerConfirmationCompleteResult,
    OwnerConfirmationRequestParams, OwnerConfirmationRequestResult,
};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::HistoryScope;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, InvitationId};
use kr_protocol::invitation::{
    InviteEntry, InviteGrantKind, InviteMode, InviteModeKind, PairCancelParams, PairCandidateView,
    PairConfirmParams, PairConfirmResult, PairInviteParams, PairInviteResult,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    ConfirmationChannel, DevicePlatform, PairStatus, PairingConsumedReason, ProposedGrant,
    RendezvousOrigin,
};
use kr_protocol::preauth::{PairStatusParams, PairStatusResult};
use kr_protocol::scalars::{CanonicalSet, Nullable};

use crate::bind::{self, Membership};
use crate::cli::{
    ClockArguments, PairCancelArguments, PairCommand, PairInvitationArguments, PairInviteArguments,
};
use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Line, Request, closed};
use crate::resolve::{self, ATTACHMENT_VARIABLE, SESSION_VARIABLE};
use crate::stdout_line;

/// How often the command asks again while an owner device has not confirmed yet.
pub const OWNER_DEVICE_POLL: Duration = Duration::from_secs(1);

/// What a person types to issue a host's first owner invitation.
pub const ISSUE_WORD: &str = "pair";

/// What a person types to establish the host's clock again.
pub const CLOCK_WORD: &str = "clock";

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
        output::document(&invitation_document(&invited));
    } else {
        output::lines(&describe_invitation(
            &invited,
            kr_ipc::now_ms().get(),
            true,
            arguments
                .environment
                .is_some()
                .then_some(environment.environment_id),
        )?);
    }
    Ok(())
}

/// `kr host clock --establish`: the owner trusts this host's clock again.
///
/// The host's clock is what an expiring grant, a retention period and the attention store's
/// forgetting are measured on, and a host that found it going backwards decides none of them
/// from it until its owner says it is right. The person is told the time this host reads, and
/// confirms it at the terminal when the host has no owner, or on an owner device when it has one.
///
/// # Errors
///
/// Returns the host's refusal, a refusal of the first-owner guard, or a transport failure.
pub async fn establish_clock(
    paths: &HostPaths,
    arguments: &ClockArguments,
    json: bool,
) -> Result<()> {
    let build_id = crate::build_id();
    let environment = resolve::select(paths, arguments.selector.environment.as_deref())?;
    let target = ActionTarget::environment(environment.environment_id);
    let mut client = resolve::open_controller(&environment.paths, build_id.clone()).await?;
    let ceremony = Ceremony::EstablishClock {
        reading_ms: kr_ipc::now_ms().get(),
    };
    let effect = Effect::EstablishClock(HostClockEstablishParams {});
    let answer = confirmed(
        &mut client,
        target,
        ConfirmationSubject::EstablishClock,
        &ceremony,
        &effect,
        &build_id,
    )
    .await?;
    let established: HostClockEstablishResult = decode(&answer)?;
    if json {
        output::document(
            &Document::new()
                .with("ok", true)
                .with("confirmation_id", closed(&established.confirmation_id)),
        );
    } else {
        output::line(&stdout_line!("This host's owner trusts its clock again."));
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
        output::document(
            &Document::new()
                .with("ok", true)
                .with("invitation_id", output::said(&invitation_id))
                .with("device_id", closed(&paired.device_id))
                .with("grant_id", closed(&paired.grant_id))
                .with("device_name", device_name(&candidate))
                .with("platform", crate::shown::platform(candidate.platform)),
        );
    } else {
        output::line(&stdout_line!(
            "Paired {} ({}) as device {}, with grant {}.",
            device_name(&candidate),
            crate::shown::platform(candidate.platform),
            paired.device_id,
            paired.grant_id
        ));
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
        output::document(&status_document(invitation_id, result));
    } else {
        output::lines(&describe_status(
            invitation_id,
            result,
            kr_ipc::now_ms().get(),
        ));
    }
    Ok(())
}

/// The effect an owner confirmation is obtained for.
enum Effect {
    Invite(PairInviteParams),
    Confirm(PairConfirmParams),
    EstablishClock(HostClockEstablishParams),
}

/// What the person at this terminal confirms, when the host has no owner yet.
enum Ceremony<'a> {
    /// Issuing an invitation; `owner` when it proposes a personal owner grant.
    Issue { owner: bool },
    /// Approving the device that answered an invitation.
    Approve { candidate: &'a PairCandidateView },
    /// Trusting this host's clock again, which reads `reading_ms` now.
    EstablishClock { reading_ms: u64 },
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
            Self::Issue { owner: true } | Self::Approve { .. } | Self::EstablishClock { .. } => {
                Ok(())
            }
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
            Self::EstablishClock { reading_ms } => Some(shown!(
                "This host's clock reads {}. Confirm on an owner device only if that is the time \
                 now.",
                crate::shown::utc_moment(*reading_ms)
            )),
        }
    }

    /// Asks the person at the controlling terminal to confirm, and refuses unless they do.
    fn confirm_at(&self, terminal: &mut Terminal) -> Result<()> {
        match self {
            Self::Issue { .. } => {
                terminal.say(&stdout_line!(
                    "This host has no owner yet. The device that answers this invitation becomes \
                     its first owner, with every right over this host until it is revoked."
                ))?;
                let typed = terminal.ask(&stdout_line!(
                    "Type {} to issue the invitation: ",
                    ISSUE_WORD
                ))?;
                if typed.trim() != ISSUE_WORD {
                    return Err(not_confirmed("the invitation was not issued"));
                }
            }
            Self::Approve { candidate } => {
                terminal.say(&stdout_line!(
                    "{} ({}) answered this invitation, and becomes this host's first owner if you \
                     approve it.",
                    device_name(candidate),
                    crate::shown::platform(candidate.platform)
                ))?;
                let typed = terminal.ask(&stdout_line!(
                    "Type the verification value the new device shows: "
                ))?;
                if !same_value(&typed, &candidate.verification_value) {
                    return Err(not_confirmed(
                        "that is not the verification value this host sees, so the device was not \
                         approved",
                    ));
                }
            }
            Self::EstablishClock { reading_ms } => {
                terminal.say(&stdout_line!(
                    "This host's clock reads {}. If that is the time now, trusting it again lets \
                     the host go on forgetting what has grown old by it and decide expiring \
                     grants against it.",
                    crate::shown::utc_moment(*reading_ms)
                ))?;
                let typed = terminal.ask(&stdout_line!(
                    "Type {} to trust this host's clock: ",
                    CLOCK_WORD
                ))?;
                if typed.trim() != CLOCK_WORD {
                    return Err(not_confirmed("the clock was not established"));
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
        Effect::EstablishClock(params) => {
            client
                .mutate(Method::HostClockEstablish, action, target, params)
                .await?
        }
    })
}

/// Refuses unless this is where a host with no owner may be confirmed at a terminal: at an
/// interactive terminal, outside every KalaReach session.
async fn guard(build_id: &BuildId) -> Result<()> {
    if !std::io::stdin().is_terminal() || !output::is_terminal() {
        return Err(CliError::NotATerminal);
    }
    for variable in [SESSION_VARIABLE, ATTACHMENT_VARIABLE] {
        if std::env::var_os(variable).is_some() {
            return Err(refused(
                ErrorCode::PermissionDenied,
                shown!(
                    "{} is set, so this is inside a KalaReach session; what a host with no owner \
                     confirms is confirmed at a terminal outside every session",
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
                "this process is inside session {}; what a host with no owner confirms is \
                 confirmed at a terminal outside every session",
                session_id
            ),
        )),
        Membership::Unknown(why) => Err(refused(
            ErrorCode::PermissionDenied,
            shown!(
                "whether this process is inside a KalaReach session cannot be established ({}); \
                 what a host with no owner confirms is confirmed only where it can",
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

    /// Writes one line.
    fn say(&mut self, line: &Line) -> Result<()> {
        output::write_line(&mut self.output, line)
            .and_then(|()| self.output.flush())
            .map_err(|error| {
                CliError::Terminal(shown!(
                    "the terminal could not be written: {}",
                    Shown::io(&error)
                ))
            })
    }

    /// Writes `prompt` and reads one line.
    fn ask(&mut self, prompt: &Line) -> Result<String> {
        output::write_prompt(&mut self.output, prompt)
            .and_then(|()| self.output.flush())
            .map_err(|error| {
                CliError::Terminal(shown!(
                    "the terminal could not be written: {}",
                    Shown::io(&error)
                ))
            })?;
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

/// The name a device gave itself, which the person pairing it is shown.
fn device_name(candidate: &PairCandidateView) -> Asked {
    Asked::text(Request::Devices, candidate.device_name.as_str())
}

/// Describes an issued invitation for a person, with its QR code when `draw` says to.
///
/// The code, the QR text and the QR code drawn from it are the invitation the person asked for.
/// `environment` is the environment the person named when they issued it, and the commands the
/// text offers name it too: without it they would act in this installation's own.
///
/// # Errors
///
/// Returns an error when the invitation's QR text is too long for a QR code.
pub fn describe_invitation(
    invited: &PairInviteResult,
    now_ms: u64,
    draw: bool,
    environment: Option<EnvironmentId>,
) -> Result<Vec<Line>> {
    let mut lines = vec![stdout_line!(
        "Invitation {}, open {}.",
        invited.invitation_id,
        remaining(invited.expires_at_ms.get(), now_ms)
    )];
    let qr = match &invited.entry {
        InviteEntry::Code {
            rendezvous_origin,
            code,
            qr_text,
        } => {
            lines.push(stdout_line!(
                "Code: {}  at {}",
                Asked::text(Request::Invitation, code.as_str()),
                Shown::address(rendezvous_origin.as_str())
            ));
            lines.push(match environment {
                Some(environment) => stdout_line!(
                    "To reserve a code at another rendezvous origin, cancel this invitation with \
                     kr pair cancel {} --environment {}, then run kr pair invite again with \
                     --origin <address> --environment {}.",
                    invited.invitation_id,
                    environment,
                    environment
                ),
                None => stdout_line!(
                    "To reserve a code at another rendezvous origin, cancel this invitation with \
                     kr pair cancel {}, then run kr pair invite again with --origin <address>.",
                    invited.invitation_id
                ),
            });
            lines.push(stdout_line!(
                "Enter the code on the new device, or scan this QR code with it:"
            ));
            qr_text
        }
        InviteEntry::Direct { qr_text } => {
            lines.push(stdout_line!(
                "Scan this QR code with the new device, on this network:"
            ));
            qr_text
        }
    };
    if draw {
        for line in qr_lines(qr.as_str())? {
            lines.push(stdout_line!("{}", Asked::text(Request::Invitation, &line)));
        }
    }
    lines.push(stdout_line!(
        "When the new device shows its verification value, approve it with:"
    ));
    lines.push(match environment {
        Some(environment) => stdout_line!(
            "  kr pair confirm {} --environment {}",
            invited.invitation_id,
            environment
        ),
        None => stdout_line!("  kr pair confirm {}", invited.invitation_id),
    });
    Ok(lines)
}

/// An issued invitation, for a script: its code and its QR text are the invitation the person
/// asked for, and the origin it is reserved at is said as an address.
fn invitation_document(invited: &PairInviteResult) -> Document {
    let document = Document::new()
        .with("ok", true)
        .with("invitation_id", output::said(&invited.invitation_id))
        .with("expires_at_ms", invited.expires_at_ms.get());
    match &invited.entry {
        InviteEntry::Code {
            rendezvous_origin,
            code,
            qr_text,
        } => document
            .with("mode", "code")
            .with("code", Asked::text(Request::Invitation, code.as_str()))
            .with(
                "rendezvous_origin",
                Shown::address(rendezvous_origin.as_str()),
            )
            .with(
                "qr_text",
                Asked::text(Request::Invitation, qr_text.as_str()),
            ),
        InviteEntry::Direct { qr_text } => document.with("mode", "direct").with(
            "qr_text",
            Asked::text(Request::Invitation, qr_text.as_str()),
        ),
    }
}

/// An invitation's status, for a script, in the shape the protocol answers it: the name a device
/// gave itself is shown to the person pairing it, an origin is said as an address, and a
/// verification value is said only when it is one.
fn status_document(invitation_id: InvitationId, result: &PairStatusResult) -> Document {
    let status = match &result.status {
        PairStatus::Open {
            remaining_confirmations,
            expires_at_ms,
        } => Document::new().with(
            "open",
            Document::new()
                .with("remaining_confirmations", *remaining_confirmations)
                .with("expires_at_ms", closed(expires_at_ms)),
        ),
        PairStatus::Locked {
            attempt_id,
            expires_at_ms,
        } => Document::new().with(
            "locked",
            Document::new()
                .with("attempt_id", closed(attempt_id))
                .with("expires_at_ms", closed(expires_at_ms)),
        ),
        PairStatus::AwaitingApproval {
            attempt_id,
            verification_value,
            expires_at_ms,
        } => Document::new().with(
            "awaiting_approval",
            Document::new()
                .with("attempt_id", closed(attempt_id))
                .with(
                    "verification_value",
                    crate::shown::verification_digits(verification_value),
                )
                .with("expires_at_ms", closed(expires_at_ms)),
        ),
        PairStatus::Committed {
            device_id,
            grant_id,
        } => Document::new().with(
            "committed",
            Document::new()
                .with("device_id", closed(device_id))
                .with("grant_id", closed(grant_id)),
        ),
        PairStatus::Consumed { reason } => {
            Document::new().with("consumed", Document::new().with("reason", closed(reason)))
        }
    };
    let owner = result.owner.0.as_ref().map(|view| {
        Document::new()
            .with("mode", closed(&view.mode))
            .with(
                "rendezvous_origin",
                view.rendezvous_origin
                    .as_ref()
                    .map(|origin| Shown::address(origin.as_str())),
            )
            .with("remaining_confirmations", view.remaining_confirmations)
            .with("grant_kind", closed(&view.grant_kind))
            .with("proposed_grant", closed(&view.proposed_grant))
            .with(
                "candidate",
                view.candidate.as_ref().map(|candidate| {
                    Document::new()
                        .with("device_name", device_name(candidate))
                        .with("platform", closed(&candidate.platform))
                        .with("keys", closed(&candidate.keys))
                        .with(
                            "verification_value",
                            crate::shown::verification_digits(&candidate.verification_value),
                        )
                }),
            )
            .with("approval", closed(&view.approval))
            .with(
                "event",
                view.event.as_ref().map(|event| {
                    Document::new()
                        .with("sequence", closed(&event.sequence))
                        .with("invitation_id", closed(&event.invitation_id))
                        .with("mode", closed(&event.mode))
                        .with("device_id", closed(&event.device_id))
                        .with("grant_id", closed(&event.grant_id))
                        .with("grant_kind", closed(&event.grant_kind))
                        .with(
                            "device_name",
                            Asked::text(Request::Devices, event.device_name.as_str()),
                        )
                        .with("platform", closed(&event.platform))
                        .with(
                            "verification_value",
                            crate::shown::verification_digits(&event.verification_value),
                        )
                        .with("confirmation_id", closed(&event.confirmation_id))
                        .with("channel", closed(&event.channel))
                        .with("signer_key_id", closed(&event.signer_key_id))
                        .with("first_owner", event.first_owner)
                        .with("committed_at_ms", closed(&event.committed_at_ms))
                }),
            )
    });
    Document::new()
        .with("status", status)
        .with("owner", owner)
        .with("ok", true)
        .with("invitation_id", output::said(&invitation_id))
}

/// Describes where an invitation has reached, for a person.
fn describe_status(
    invitation_id: InvitationId,
    result: &PairStatusResult,
    now_ms: u64,
) -> Vec<Line> {
    let state = match &result.status {
        PairStatus::Open {
            remaining_confirmations,
            expires_at_ms,
        } => {
            let open = remaining(expires_at_ms.get(), now_ms);
            // Only a code can be guessed at, so only a code invitation has an allowance to show.
            let code = result
                .owner
                .0
                .as_ref()
                .is_none_or(|view| view.mode == InviteModeKind::Code);
            if code {
                shown!(
                    "open {}, with {} wrong codes allowed before it closes",
                    open,
                    *remaining_confirmations
                )
            } else {
                shown!("open {}", open)
            }
        }
        PairStatus::Locked { expires_at_ms, .. } => shown!(
            "a device has proved the code and is finishing, open {}",
            remaining(expires_at_ms.get(), now_ms)
        ),
        PairStatus::AwaitingApproval {
            verification_value,
            expires_at_ms,
            ..
        } => shown!(
            "a device is waiting for approval, open {}; its verification value is {}",
            remaining(expires_at_ms.get(), now_ms),
            crate::shown::verification_value(verification_value)
        ),
        PairStatus::Committed {
            device_id,
            grant_id,
        } => shown!("paired as device {}, with grant {}", *device_id, *grant_id),
        PairStatus::Consumed { reason } => shown!("ended: {}", ended_because(*reason)),
    };
    let mut lines = vec![stdout_line!("Invitation {}: {}.", invitation_id, state)];
    if let Some(candidate) = result
        .owner
        .0
        .as_ref()
        .and_then(|view| view.candidate.0.as_ref())
    {
        lines.push(stdout_line!(
            "The device is {} ({}).",
            device_name(candidate),
            crate::shown::platform(candidate.platform)
        ));
    }
    if matches!(result.status, PairStatus::AwaitingApproval { .. }) {
        lines.push(stdout_line!(
            "Check the new device shows the same value, then approve it with:"
        ));
        lines.push(stdout_line!("  kr pair confirm {}", invitation_id));
    }
    lines
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
    CliError::refused_in_its_own_words(code, message)
}

fn not_confirmed(message: &'static str) -> CliError {
    refused(ErrorCode::OwnerConfirmationRequired, Shown::said(message))
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
    ///
    /// KR-REQ-10.18: the issuing owner chooses the rendezvous origin a code invitation goes through
    /// before it is issued.
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
    ///
    /// KR-REQ-10.18: the issuing screen names the rendezvous origin beside the code, the default
    /// origin included.
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
        let shown = describe_invitation(&invited, now, true, None)
            .expect("a description")
            .iter()
            .map(|line| line.text().to_owned())
            .collect::<Vec<_>>()
            .join("\n");
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
        let document = invitation_document(&invited).json();
        assert_eq!(document["mode"], "code");
        assert_eq!(document["code"], "4XkP-Qm7-Zr2");
        assert_eq!(document["rendezvous_origin"], "https://reach.kala.to");
    }

    /// KR-REQ-10.18: the issuing text shows the rendezvous origin with the action that changes it.
    #[test]
    fn the_issuing_text_names_the_action_that_changes_the_origin() {
        let now = 1_764_000_000_000;
        let origin = RendezvousOrigin::new("https://reach.kala.to").expect("an origin");
        let code = ShortCode::new("4XkP-Qm7-Zr2").expect("a code");
        let text = QrPayload::Code(CodeQrPayload {
            rendezvous_origin: origin.clone(),
            code: code.clone(),
        })
        .to_text()
        .expect("the payload's text");
        let invited = PairInviteResult {
            invitation_id: InvitationId::new(Uuid::from_bytes([9; 16])),
            expires_at_ms: TimestampMs::new(now + 5 * 60_000),
            entry: InviteEntry::Code {
                rendezvous_origin: origin,
                code,
                qr_text: QrText::new(text.as_str()).expect("QR text"),
            },
        };
        let shown = describe_invitation(&invited, now, false, None)
            .expect("a description")
            .iter()
            .map(|line| line.text().to_owned())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(shown.contains("--origin"), "{shown}");
        // The invitation stays open for five minutes, so a second `kr pair invite` is refused
        // until this one is cancelled: the text says to cancel it, by the identifier it was given.
        assert!(
            shown.contains(&format!("kr pair cancel {}", invited.invitation_id)),
            "{shown}"
        );
        assert!(
            !shown.contains("--environment"),
            "an environment nobody named is not named: {shown}"
        );
        // Issued in an environment the person named, the commands the text offers name it too: a
        // cancel or a confirm without it would look in this installation's own.
        let environment = EnvironmentId::new(Uuid::from_bytes([7; 16]));
        let named = describe_invitation(&invited, now, false, Some(environment))
            .expect("a description")
            .iter()
            .map(|line| line.text().to_owned())
            .collect::<Vec<_>>()
            .join("\n");
        for command in [
            format!(
                "kr pair cancel {} --environment {environment}",
                invited.invitation_id
            ),
            format!(
                "kr pair confirm {} --environment {environment}",
                invited.invitation_id
            ),
            format!("--origin <address> --environment {environment}"),
        ] {
            assert!(named.contains(&command), "{command}: {named}");
        }
    }

    /// KR-REQ-23.25: text planted in every leaf of an invitation's status that can hold free text
    /// reaches its document and its lines only as the name a device gave itself; an origin is
    /// said as an address and a verification value only when it is one. Every other leaf is what
    /// the protocol encodes.
    #[test]
    fn planted_text_in_a_status_shows_only_as_a_device_name() {
        use crate::output::planted::{only_asked, only_asked_lines, planted, same_encoding};

        let invitation_id = InvitationId::new(Uuid::from_bytes([9; 16]));
        let mut shown = std::collections::BTreeSet::new();
        for result in planted::<PairStatusResult>() {
            let document = status_document(invitation_id, &result);
            shown.extend(only_asked("kr pair status", &document));
            same_encoding(
                "kr pair status",
                &document,
                &serde_json::to_value(&result).expect("the status encodes"),
                &[
                    "status.awaiting_approval.verification_value",
                    "owner.rendezvous_origin",
                    "owner.candidate.verification_value",
                    "owner.event.verification_value",
                ],
                &["ok", "invitation_id"],
            );
            only_asked_lines(
                "kr pair status",
                &describe_status(invitation_id, &result, 0),
            );
        }
        for asked in ["owner.candidate.device_name", "owner.event.device_name"] {
            assert!(shown.contains(asked), "{asked} shows what was asked for");
        }
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
        let shown = describe_status(invitation_id, &waiting, now)
            .iter()
            .map(|line| line.text().to_owned())
            .collect::<Vec<_>>()
            .join("\n");
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
