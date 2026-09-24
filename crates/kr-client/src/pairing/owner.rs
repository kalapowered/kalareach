//! An owner device answering the owner-confirmation challenges its hosts issue.
//!
//! Section 10 has six actions need a fresh owner confirmation bound to the exact action digest,
//! destination keys and rights, host, nonce and a short expiry, and prefers a protected native
//! ceremony on the unlocked owner device. A caller on the host (`kr pair invite`, `kr pair
//! confirm`, the project service) asks the host for a challenge; this device reads it from
//! `owner.confirmation.pending`, runs its platform's ceremony, signs the challenge with its
//! authorisation key on the `owner_device_presence` channel, and sends the proof with
//! `owner.confirmation.complete`.
//!
//! # Before anything is signed
//!
//! A challenge is signed only when what the person is shown is bound to what is signed. Matching
//! the action's name and rights is not enough, because two invitations with the same rights can
//! differ in origin, expiry or scope, so wherever this device can recompute the digest from what
//! it shows, it does ([`check`]). A challenge that fails any check is listed as one that cannot be
//! checked, and is never signed.
//!
//! # What this does not protect
//!
//! The authorisation key also signs every connection handshake, silently, so it is not held behind
//! the ceremony; the ceremony guards the signing path. A process that already controls the
//! device's files and keys can sign without it, as section 10 says of any software-only account.

use std::sync::Arc;
use std::time::Duration;

use kr_crypto::keys::AuthorisationKeyPair;
use kr_pairing::platform::PairingClock;
use kr_protocol::confirmation::{
    CLOCK_PURPOSE, ConfirmationDisplay, DescribedAction, OwnerConfirmationCompleteParams,
    OwnerConfirmationPendingParams, OwnerConfirmationPendingResult, PendingConfirmation,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::GrantExpiry;
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::ids::EnvironmentId;
use kr_protocol::invitation::{
    InviteGrantKind, InviteModeKind, PairCandidateView, issuance_digest,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    ConfirmationChannel, DevicePlatform, OwnerConfirmationRequest, ProposedGrant, RendezvousOrigin,
    SensitiveAction, group_verification_value,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{DurationMs, Nullable};
use serde::Serialize;

use super::BoxFuture;
use super::invitation::origin_host;
use super::paired::PairedHost;
use crate::error::ClientError;
use crate::session::Session;

/// How long a completion may stay acceptable to the host. A challenge lives two minutes; its
/// answer is sent at once or not at all.
const COMPLETION_TTL: DurationMs = DurationMs::new(60_000);

/// The longest reason a ceremony is given. The platforms' dialogs show one short line.
pub const MAX_REASON_CHARS: usize = 200;

/// How a device reaches its host's owner-confirmation methods.
///
/// [`SessionChannel`] is the product's: the device's own authorised session. A test puts a layer
/// that alters what the host listed, or counts what is sent, in its place.
pub trait OwnerChannel: Send + Sync {
    /// Reads the challenges the host holds open.
    fn pending(&self) -> BoxFuture<'_, Result<OwnerConfirmationPendingResult, ClientError>>;

    /// Sends one answer.
    fn complete<'a>(
        &'a self,
        params: &'a OwnerConfirmationCompleteParams,
    ) -> BoxFuture<'a, Result<(), ClientError>>;
}

/// A method that takes no parameters, as the empty map the protocol expects.
#[derive(Serialize)]
struct NoParams {}

/// The owner-confirmation methods over this device's authorised session with a host.
#[derive(Debug)]
pub struct SessionChannel {
    session: Arc<Session>,
    environment: EnvironmentId,
}

impl SessionChannel {
    /// The channel over `session`, targeting the host's environment.
    ///
    /// # Errors
    ///
    /// Returns the session's failure when the host cannot say which environment it is.
    pub async fn open(session: Arc<Session>) -> Result<Self, ClientError> {
        let info: HostInfoResult = session.read(Method::HostInfo, &NoParams {}).await?;
        Ok(Self {
            session,
            environment: info.environment_id,
        })
    }

    /// The session the channel uses.
    #[must_use]
    pub const fn session(&self) -> &Arc<Session> {
        &self.session
    }
}

impl OwnerChannel for SessionChannel {
    fn pending(&self) -> BoxFuture<'_, Result<OwnerConfirmationPendingResult, ClientError>> {
        Box::pin(async move {
            self.session
                .read(
                    Method::OwnerConfirmationPending,
                    &OwnerConfirmationPendingParams {},
                )
                .await
        })
    }

    fn complete<'a>(
        &'a self,
        params: &'a OwnerConfirmationCompleteParams,
    ) -> BoxFuture<'a, Result<(), ClientError>> {
        Box::pin(async move {
            self.session
                .mutate(
                    Method::OwnerConfirmationComplete,
                    ActionTarget::environment(self.environment),
                    None,
                    &NoParams {},
                    params,
                    COMPLETION_TTL,
                )
                .await
                .map(|_| ())
        })
    }
}

/// Which ceremony a device offers, so an interface can name its button.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyKind {
    /// Touch ID, with the password as its fallback.
    TouchId,
    /// The device password, on a Mac without Touch ID.
    Password,
    /// Windows Hello.
    WindowsHello,
    /// None: this device cannot check that it is its owner in front of it.
    None,
}

/// What a ceremony answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyOutcome {
    /// The person completed it.
    Confirmed,
    /// The person declined, cancelled or failed it, or it was not answered in time.
    NotConfirmed,
    /// The device has no ceremony to run.
    Unavailable,
}

/// The platform's user-verification ceremony.
///
/// It is the operating system's own dialog, which is where the evidence of presence comes from: a
/// click the page or desktop automation can synthesise can open it, and cannot complete it.
pub trait Ceremony: Send + Sync {
    /// Which ceremony this is.
    fn kind(&self) -> CeremonyKind;

    /// Runs the ceremony for `reason`, and ends it when `within` passes.
    fn verify<'a>(&'a self, reason: &'a str, within: Duration) -> BoxFuture<'a, CeremonyOutcome>;
}

/// What a checked challenge approves, as the person is shown it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subject {
    /// Issuing an invitation.
    IssueInvitation {
        /// How it will be offered.
        mode: InviteModeKind,
        /// The origin a code invitation reserves at.
        origin: Option<RendezvousOrigin>,
        /// Which rules the proposal is checked against.
        grant_kind: InviteGrantKind,
        /// The exact proposal.
        proposed_grant: ProposedGrant,
    },
    /// Adding a device.
    ConfirmDevice {
        /// The device, its keys and the value both devices display.
        candidate: PairCandidateView,
        /// The grant it would receive.
        proposed_grant: ProposedGrant,
    },
    /// Trusting the host's clock again.
    EstablishClock,
    /// An action its caller described by class, rights and digest only.
    Described(DescribedAction),
}

/// Why a challenge could not be checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CannotCheck {
    /// It names another host than the one this device paired with.
    AnotherHost,
    /// What it shows is another kind of action than the one it would authorise.
    ActionMismatch,
    /// What it shows is not what its digest covers.
    DigestMismatch,
    /// It sends authority to keys the action does not name, or names none where it should.
    Destination,
    /// Its rights are not the rights it shows.
    Rights,
    /// What it shows could not be encoded to check.
    Unreadable,
    /// What it would authorise cannot be said in one line of the platform's prompt.
    CannotShow,
}

/// Checks that what a challenge shows is what it would authorise, on the host it is for.
///
/// # Errors
///
/// Returns why the challenge cannot be checked.
pub fn check(pending: &PendingConfirmation, host: &PairedHost) -> Result<Subject, CannotCheck> {
    let request = &pending.request;
    if request.host_device_id != host.host_device_id
        || request.host_endpoint_id != host.host_endpoint_id
    {
        return Err(CannotCheck::AnotherHost);
    }
    let expect = |action: SensitiveAction| {
        if request.action == action {
            Ok(())
        } else {
            Err(CannotCheck::ActionMismatch)
        }
    };
    let rights = |shown: &kr_protocol::scalars::CanonicalSet<ActionRight>| {
        if &request.destination_rights == shown {
            Ok(())
        } else {
            Err(CannotCheck::Rights)
        }
    };
    let no_destination = || {
        if request.destination_keys.is_present() {
            Err(CannotCheck::Destination)
        } else {
            Ok(())
        }
    };
    match &pending.display {
        ConfirmationDisplay::IssueInvitation {
            mode,
            rendezvous_origin,
            grant_kind,
            proposed_grant,
        } => {
            expect(SensitiveAction::IssueInvitation)?;
            let digest = issuance_digest(
                *mode,
                rendezvous_origin.as_ref(),
                *grant_kind,
                proposed_grant,
            )
            .map_err(|_| CannotCheck::Unreadable)?;
            if digest != request.action_digest {
                return Err(CannotCheck::DigestMismatch);
            }
            no_destination()?;
            rights(&proposed_grant.actions)?;
            Ok(Subject::IssueInvitation {
                mode: *mode,
                origin: rendezvous_origin.as_ref().cloned(),
                grant_kind: *grant_kind,
                proposed_grant: proposed_grant.clone(),
            })
        }
        ConfirmationDisplay::ConfirmDevice {
            candidate,
            proposed_grant,
            ..
        } => {
            expect(SensitiveAction::ConfirmDevice)?;
            // The digest binds the host's transcript and the candidate's key digest, which no owner
            // device can recompute; the value both devices show is the person's check that the
            // candidate is the device in front of them.
            if request.destination_keys.as_ref() != Some(&candidate.keys) {
                return Err(CannotCheck::Destination);
            }
            rights(&proposed_grant.actions)?;
            Ok(Subject::ConfirmDevice {
                candidate: candidate.clone(),
                proposed_grant: proposed_grant.clone(),
            })
        }
        ConfirmationDisplay::EstablishClock => {
            expect(SensitiveAction::ChangeHostAuthority)?;
            let digest = kr_pairing::confirm::action_digest(&CLOCK_PURPOSE)
                .map_err(|_| CannotCheck::Unreadable)?;
            if digest != request.action_digest {
                return Err(CannotCheck::DigestMismatch);
            }
            no_destination()?;
            if !request.destination_rights.is_empty() {
                return Err(CannotCheck::Rights);
            }
            Ok(Subject::EstablishClock)
        }
        ConfirmationDisplay::Described(described) => {
            expect(described.action)?;
            if described.action_digest != request.action_digest {
                return Err(CannotCheck::DigestMismatch);
            }
            if described.destination_keys != request.destination_keys {
                return Err(CannotCheck::Destination);
            }
            rights(&described.destination_rights)?;
            Ok(Subject::Described(described.clone()))
        }
    }
}

/// The kinds of action a grant can let a device take, strongest first, as a prompt names them.
///
/// Every right belongs to exactly one kind, and a prompt names every kind a grant holds, so an
/// authority larger than viewing is never shown as viewing. Host management is the owner's and is
/// named on its own.
const KINDS: [(&str, &[ActionRight]); 9] = [
    ("type in terminals", &[ActionRight::TerminalInput]),
    (
        "direct agents",
        &[
            ActionRight::AgentPrompt,
            ActionRight::AgentCancel,
            ActionRight::AgentApprovalRespond,
            ActionRight::QuestionRespond,
        ],
    ),
    (
        "change files",
        &[
            ActionRight::FilesRead,
            ActionRight::FilesUpload,
            ActionRight::FilesApplyDiff,
            ActionRight::ChangesetCreate,
        ],
    ),
    ("run automations", &[ActionRight::AutomationManage]),
    (
        "manage projects",
        &[ActionRight::ProjectCreate, ActionRight::WorkspaceManage],
    ),
    (
        "manage sessions",
        &[
            ActionRight::SessionCreate,
            ActionRight::SessionRename,
            ActionRight::SessionClose,
            ActionRight::SessionShare,
        ],
    ),
    ("use voice", &[ActionRight::VoiceUse]),
    (
        "resize terminals",
        &[
            ActionRight::TerminalGeometry,
            ActionRight::TerminalGeometryTransfer,
            ActionRight::TerminalPalette,
        ],
    ),
    ("view sessions", &[ActionRight::SessionView]),
];

/// What `rights` let a device do, in words, or `None` when a right has no words here.
fn authority(rights: &kr_protocol::scalars::CanonicalSet<ActionRight>) -> Option<String> {
    if rights.contains(&ActionRight::HostManage) {
        return Some("manage the host as an owner".to_owned());
    }
    let named = rights
        .iter()
        .all(|right| KINDS.iter().any(|(_, kind)| kind.contains(right)));
    if !named {
        return None;
    }
    let kinds: Vec<&str> = KINDS
        .iter()
        .filter(|(_, kind)| kind.iter().any(|right| rights.contains(right)))
        .map(|(phrase, _)| *phrase)
        .collect();
    Some(match kinds.as_slice() {
        [] => "do nothing".to_owned(),
        [one] => (*one).to_owned(),
        [first @ .., last] => format!("{} and {last}", first.join(", ")),
    })
}

/// How long a grant lasts, from `now_ms`, in words.
fn duration(expiry: &GrantExpiry, now_ms: u64) -> String {
    let GrantExpiry::At { expires_at_ms } = expiry else {
        return "until it is revoked".to_owned();
    };
    let minutes = expires_at_ms.get().saturating_sub(now_ms).div_ceil(60_000);
    match minutes {
        0 => "for no time at all".to_owned(),
        1 => "for 1 minute".to_owned(),
        2..=119 => format!("for {minutes} minutes"),
        120..=2879 => format!("for {} hours", minutes / 60),
        _ => format!("for {} days", minutes / (60 * 24)),
    }
}

/// The first eight hexadecimal characters of a digest, grouped as a value is.
fn digest_prefix(digest: &kr_protocol::scalars::Digest256) -> String {
    let hex: String = digest.as_bytes()[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    group_verification_value(&hex)
}

/// The one line a platform's dialog shows for a subject, completing "KalaReach is trying to ...".
///
/// It names everything the confirmation would authorise: every kind of action the rights allow,
/// for how long, and to which device. Names a candidate or a host chose are display text: they are
/// shortened, and stripped of control characters, line separators and the characters that reorder
/// text, before they are shown. When what the challenge authorises cannot be said in one line of
/// at most [`MAX_REASON_CHARS`] characters, even with the names shortened, there is no line: a
/// prompt that left authority out would be asking the person to approve what it did not show.
///
/// # Errors
///
/// Returns [`CannotCheck::CannotShow`] when no line can say it all.
pub fn reason(subject: &Subject, host_name: &str, now_ms: u64) -> Result<String, CannotCheck> {
    for names in [40, 24, 16] {
        let host = shown(host_name, names);
        let text = match subject {
            Subject::IssueInvitation {
                mode,
                origin,
                proposed_grant,
                ..
            } => {
                let offered = match (mode, origin) {
                    (InviteModeKind::Code, Some(origin)) => {
                        format!("a code at {}", shown(origin_host(origin), names + 20))
                    }
                    (InviteModeKind::Code, None) => "a code".to_owned(),
                    (InviteModeKind::Direct, _) => "a QR code on this network".to_owned(),
                };
                format!(
                    "issue an invitation from {host}: {offered}, for a device that may {} {}",
                    authority(&proposed_grant.actions).ok_or(CannotCheck::CannotShow)?,
                    duration(&proposed_grant.expiry, now_ms)
                )
            }
            Subject::ConfirmDevice {
                candidate,
                proposed_grant,
            } => format!(
                "confirm adding {} ({}) to {host}, which may {} {}. It shows {}.",
                shown(candidate.device_name.as_str(), names),
                platform(candidate.platform),
                authority(&proposed_grant.actions).ok_or(CannotCheck::CannotShow)?,
                duration(&proposed_grant.expiry, now_ms),
                group_verification_value(&candidate.verification_value)
            ),
            Subject::EstablishClock => format!("trust the clock of {host} again"),
            Subject::Described(described) => {
                let action = match described.action {
                    SensitiveAction::EnlargeGrant => "widen what devices may do",
                    SensitiveAction::TrustRepositoryRoot => "trust a plugin repository",
                    SensitiveAction::GrantExecutableCapability => {
                        "let a plugin use new capabilities"
                    }
                    SensitiveAction::IssueInvitation => "issue an invitation",
                    SensitiveAction::ConfirmDevice => "add a device",
                    SensitiveAction::ChangeHostAuthority => "change who manages the host",
                };
                let rights = if described.destination_rights.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", so that a device may {}",
                        authority(&described.destination_rights).ok_or(CannotCheck::CannotShow)?
                    )
                };
                format!(
                    "{action} on {host}{rights}. The host did not say which location or package; \
                     its digest starts {}",
                    digest_prefix(&described.action_digest)
                )
            }
        };
        if text.chars().count() <= MAX_REASON_CHARS {
            return Ok(text);
        }
    }
    Err(CannotCheck::CannotShow)
}

/// A platform's name as people know it.
const fn platform(platform: DevicePlatform) -> &'static str {
    match platform {
        DevicePlatform::Macos => "macOS",
        DevicePlatform::Windows => "Windows",
        DevicePlatform::Linux => "Linux",
        DevicePlatform::Ios => "iOS",
        DevicePlatform::Android => "Android",
    }
}

/// True for a character that reorders or hides text, which a dialog's line leaves out.
const fn invisible(character: char) -> bool {
    matches!(
        character,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
    )
}

/// True for a character that breaks a line, which a dialog's line shows as a space.
const fn breaking(character: char) -> bool {
    character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
}

/// Display text as a dialog may show it: on one line, with the characters that reorder or hide
/// text left out, runs of space as one, and at most `limit` characters.
fn shown(text: &str, limit: usize) -> String {
    let spaced: String = text
        .chars()
        .filter(|character| !invisible(*character))
        .map(|character| if breaking(character) { ' ' } else { character })
        .collect();
    let clean = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.chars().count() <= limit {
        return clean;
    }
    let mut shortened: String = clean.chars().take(limit.saturating_sub(1)).collect();
    shortened.push('\u{2026}');
    shortened
}

/// One challenge the host holds open, as this device checked it.
#[derive(Clone, Debug)]
pub struct Listed {
    /// The challenge, exactly as a proof must answer it.
    pub request: OwnerConfirmationRequest,
    /// What it approves, or why it cannot be checked.
    pub subject: Result<Subject, CannotCheck>,
    /// True once a proof has answered it and it waits for its action.
    pub answered: bool,
}

/// How a review ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewOutcome {
    /// The person completed the ceremony and the host has the proof.
    Confirmed,
    /// The person did not complete the ceremony, or the host could not take the proof.
    NotConfirmed,
    /// The challenge expired first.
    Expired,
    /// The challenge could not be checked, so it was not offered to the ceremony.
    CannotCheck,
    /// This device has no ceremony, so it signs nothing.
    NoCeremony,
}

/// One paired host's owner confirmations, answered by this device.
pub struct OwnerConfirmations {
    host: PairedHost,
    authorisation: AuthorisationKeyPair,
    channel: Arc<dyn OwnerChannel>,
    clock: Arc<dyn PairingClock + Send + Sync>,
}

impl std::fmt::Debug for OwnerConfirmations {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnerConfirmations")
            .field("host", &self.host.host_device_id)
            .finish_non_exhaustive()
    }
}

impl OwnerConfirmations {
    /// The confirmations of `host`, answered with `authorisation` over `channel`.
    #[must_use]
    pub fn new(
        host: PairedHost,
        authorisation: AuthorisationKeyPair,
        channel: Arc<dyn OwnerChannel>,
        clock: Arc<dyn PairingClock + Send + Sync>,
    ) -> Self {
        Self {
            host,
            authorisation,
            channel,
            clock,
        }
    }

    /// The host these confirmations are for.
    #[must_use]
    pub const fn host(&self) -> &PairedHost {
        &self.host
    }

    /// Reads and checks the challenges the host holds open.
    ///
    /// # Errors
    ///
    /// Returns the channel's failure.
    pub async fn pending(&self) -> Result<Vec<Listed>, ClientError> {
        let listed = self.channel.pending().await?;
        Ok(listed
            .pending
            .iter()
            .map(|pending| Listed {
                request: pending.request.clone(),
                subject: check(pending, &self.host),
                answered: pending.answered,
            })
            .collect())
    }

    /// Runs the ceremony for one listed challenge and, when the person completes it in time, signs
    /// the challenge on `owner_device_presence` and sends the proof.
    pub async fn review(&self, listed: &Listed, ceremony: &dyn Ceremony) -> ReviewOutcome {
        let Ok(subject) = &listed.subject else {
            return ReviewOutcome::CannotCheck;
        };
        if listed.answered {
            return ReviewOutcome::Confirmed;
        }
        let expires_at_ms = listed.request.expires_at_ms.get();
        let now = self.clock.wall_clock_ms();
        if now >= expires_at_ms {
            return ReviewOutcome::Expired;
        }
        if ceremony.kind() == CeremonyKind::None {
            return ReviewOutcome::NoCeremony;
        }
        let host_name = self.host.name.as_deref().unwrap_or("your host");
        let Ok(reason) = reason(subject, host_name, now) else {
            return ReviewOutcome::CannotCheck;
        };
        let within = Duration::from_millis(expires_at_ms - now);
        match ceremony.verify(&reason, within).await {
            CeremonyOutcome::Unavailable => return ReviewOutcome::NoCeremony,
            CeremonyOutcome::NotConfirmed => return ReviewOutcome::NotConfirmed,
            CeremonyOutcome::Confirmed => {}
        }
        // A ceremony answered after the challenge expired confirms nothing, whatever it says.
        if self.clock.wall_clock_ms() >= expires_at_ms {
            return ReviewOutcome::Expired;
        }
        let Ok(proof) = kr_pairing::confirm::sign_confirmation(
            &self.authorisation,
            &listed.request,
            ConfirmationChannel::OwnerDevicePresence,
        ) else {
            return ReviewOutcome::NotConfirmed;
        };
        let sent = self
            .channel
            .complete(&OwnerConfirmationCompleteParams {
                proof,
                bootstrap_signer: Nullable::null(),
            })
            .await;
        match sent {
            Ok(()) => ReviewOutcome::Confirmed,
            Err(ClientError::Host(error) | ClientError::Refused { error, .. })
                if error.code == ErrorCode::OwnerConfirmationRequired
                    && self.clock.wall_clock_ms() >= expires_at_ms =>
            {
                ReviewOutcome::Expired
            }
            Err(_) => ReviewOutcome::NotConfirmed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kr_crypto::keys::DeviceKeys;
    use kr_protocol::grant::{EnvironmentSelector, HistoryScope, SessionSelector};
    use kr_protocol::ids::{ConfirmationId, DeviceId, DeviceKeyRevision, GrantId, InvitationId};
    use kr_protocol::invitation::PairCandidateView;
    use kr_protocol::pairing::{DeviceName, NetworkConfig};
    use kr_protocol::scalars::{CanonicalSet, Digest256, Nonce256, TimestampMs, Uuid};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NOW: u64 = 1_764_000_000_000;

    fn grant(rights: &[ActionRight], expiry: GrantExpiry) -> ProposedGrant {
        ProposedGrant {
            parent_grant_id: Nullable::null(),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: rights.iter().copied().collect::<CanonicalSet<_>>(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: true,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry,
            organisation: Nullable::null(),
        }
    }

    fn an_hour() -> GrantExpiry {
        GrantExpiry::At {
            expires_at_ms: TimestampMs::new(NOW + 60 * 60_000),
        }
    }

    fn candidate(name: &str) -> PairCandidateView {
        PairCandidateView {
            device_name: DeviceName::new(name).expect("a name"),
            platform: DevicePlatform::Android,
            keys: DeviceKeys::generate().expect("keys").public_keys(),
            verification_value: "f3c146fd".to_owned(),
        }
    }

    /// KR-REQ-10.06: every kind of action a grant allows is named, for how long, and a grant that
    /// lets a device type in terminals is never shown as one that lets it view sessions.
    #[test]
    fn a_reason_names_all_the_authority_it_would_confirm() {
        let broad = Subject::ConfirmDevice {
            candidate: candidate("Pixel 8"),
            proposed_grant: grant(
                &[ActionRight::SessionView, ActionRight::TerminalInput],
                an_hour(),
            ),
        };
        let line = reason(&broad, "studio", NOW).expect("a line");
        assert_eq!(
            line,
            "confirm adding Pixel 8 (Android) to studio, which may type in terminals and view \
             sessions for 60 minutes. It shows f3c1 46fd."
        );

        let owner = Subject::IssueInvitation {
            mode: InviteModeKind::Code,
            origin: Some(RendezvousOrigin::new("https://reach.kala.to").expect("an origin")),
            grant_kind: InviteGrantKind::PersonalOwner,
            proposed_grant: grant(&[ActionRight::HostManage], GrantExpiry::Never),
        };
        assert_eq!(
            reason(&owner, "studio", NOW).expect("a line"),
            "issue an invitation from studio: a code at reach.kala.to, for a device that may \
             manage the host as an owner until it is revoked"
        );

        let described = Subject::Described(DescribedAction {
            action: SensitiveAction::EnlargeGrant,
            action_digest: Digest256::from_bytes([0xf3; 32]),
            destination_keys: Nullable::null(),
            destination_rights: [ActionRight::FilesApplyDiff].into_iter().collect(),
        });
        assert_eq!(
            reason(&described, "studio", NOW).expect("a line"),
            "widen what devices may do on studio, so that a device may change files. The host did \
             not say which location or package; its digest starts f3f3 f3f3"
        );
    }

    /// Every right has words, so no right can be left out of a prompt for want of them.
    #[test]
    fn every_right_has_words() {
        for right in ActionRight::ALL {
            let rights = [*right].into_iter().collect::<CanonicalSet<_>>();
            assert!(authority(&rights).is_some(), "{right}");
        }
    }

    /// KR-REQ-10.06: a dialog's line is one line whatever a candidate or a host calls itself: no
    /// control character, line or paragraph separator or reordering character survives, and the
    /// names are shortened before any authority is left out. A device name already refuses control
    /// characters; a host's name is whatever its owner typed.
    #[test]
    fn a_reason_is_one_line_whatever_the_names() {
        let subject = Subject::ConfirmDevice {
            candidate: candidate("Pixel\u{2028}8\u{2029}Pro\u{202E}\u{2066}droid\u{FEFF}"),
            proposed_grant: grant(&[ActionRight::SessionView], an_hour()),
        };
        let line = reason(&subject, "stu\u{2028}di\no\r", NOW).expect("a line");
        for hidden_character in [
            '\n', '\r', '\u{2028}', '\u{2029}', '\u{202E}', '\u{2066}', '\u{FEFF}',
        ] {
            assert!(!line.contains(hidden_character), "{line:?}");
        }
        assert!(
            line.starts_with("confirm adding Pixel 8 Prodroid (Android) to stu di o,"),
            "{line}"
        );

        let long = Subject::ConfirmDevice {
            candidate: candidate(&"a".repeat(120)),
            proposed_grant: grant(
                &[ActionRight::SessionView, ActionRight::TerminalInput],
                an_hour(),
            ),
        };
        let line = reason(&long, &"h".repeat(120), NOW).expect("a line");
        assert!(line.chars().count() <= MAX_REASON_CHARS, "{line}");
        assert!(
            line.contains("type in terminals and view sessions"),
            "{line}"
        );
    }

    /// An owner channel over a listing a test writes, which counts what is sent.
    struct Listing {
        pending: Mutex<Vec<PendingConfirmation>>,
        completions: AtomicUsize,
    }

    impl OwnerChannel for Listing {
        fn pending(&self) -> BoxFuture<'_, Result<OwnerConfirmationPendingResult, ClientError>> {
            let pending = self.pending.lock().expect("the listing").clone();
            Box::pin(async move { Ok(OwnerConfirmationPendingResult { pending }) })
        }

        fn complete<'a>(
            &'a self,
            _params: &'a OwnerConfirmationCompleteParams,
        ) -> BoxFuture<'a, Result<(), ClientError>> {
            self.completions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    struct Asked(Mutex<Vec<String>>);

    impl Ceremony for Asked {
        fn kind(&self) -> CeremonyKind {
            CeremonyKind::TouchId
        }

        fn verify<'a>(
            &'a self,
            reason: &'a str,
            _within: Duration,
        ) -> BoxFuture<'a, CeremonyOutcome> {
            self.0.lock().expect("the record").push(reason.to_owned());
            Box::pin(async { CeremonyOutcome::Confirmed })
        }
    }

    struct Fixed(u64);

    impl PairingClock for Fixed {
        fn monotonic_ms(&self) -> u64 {
            0
        }

        fn boot_identity(&self) -> kr_pairing::platform::BootIdentity {
            kr_pairing::platform::BootIdentity([0; 32])
        }

        fn wall_clock_ms(&self) -> u64 {
            self.0
        }
    }

    /// KR-REQ-10.06: a challenge whose authority no line of the prompt can show is never offered
    /// to the ceremony, and nothing is signed or sent.
    #[tokio::test]
    async fn authority_no_line_can_show_is_not_offered_to_the_ceremony() {
        let host_keys = DeviceKeys::generate().expect("keys").public_keys();
        let host = PairedHost {
            host_device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
            host_key_revision: DeviceKeyRevision::new(1),
            host_endpoint_id: host_keys.transport,
            host_keys,
            network_config: NetworkConfig::empty(),
            device_id: DeviceId::new(Uuid::from_bytes([2; 16])),
            grant_id: GrantId::new(Uuid::from_bytes([3; 16])),
            proposed_grant: grant(&[ActionRight::HostManage], GrantExpiry::Never),
            name: Some("studio".to_owned()),
            paired_at_ms: NOW,
        };
        let everything_but_the_host: Vec<ActionRight> = ActionRight::ALL
            .iter()
            .copied()
            .filter(|right| *right != ActionRight::HostManage)
            .collect();
        let shown_candidate = candidate("Pixel 8");
        let proposed = grant(&everything_but_the_host, an_hour());
        let request = OwnerConfirmationRequest {
            confirmation_id: ConfirmationId::new(Uuid::from_bytes([4; 16])),
            action: SensitiveAction::ConfirmDevice,
            action_digest: Digest256::from_bytes([5; 32]),
            destination_keys: Nullable::some(shown_candidate.keys),
            destination_rights: proposed.actions.clone(),
            host_device_id: host.host_device_id,
            host_endpoint_id: host.host_endpoint_id,
            nonce: Nonce256::from_bytes([6; 32]),
            expires_at_ms: TimestampMs::new(NOW + 60_000),
        };
        let listing = Arc::new(Listing {
            pending: Mutex::new(vec![PendingConfirmation {
                request,
                display: ConfirmationDisplay::ConfirmDevice {
                    invitation_id: InvitationId::new(Uuid::from_bytes([7; 16])),
                    candidate: shown_candidate,
                    proposed_grant: proposed,
                },
                answered: false,
            }]),
            completions: AtomicUsize::new(0),
        });
        let confirmations = OwnerConfirmations::new(
            host,
            DeviceKeys::generate().expect("keys").authorisation,
            listing.clone(),
            Arc::new(Fixed(NOW)),
        );
        let listed = confirmations.pending().await.expect("the listing");
        assert!(listed[0].subject.is_ok(), "the challenge itself checks");
        let asked = Asked(Mutex::new(Vec::new()));
        assert_eq!(
            confirmations.review(&listed[0], &asked).await,
            ReviewOutcome::CannotCheck
        );
        assert!(asked.0.lock().expect("the record").is_empty());
        assert_eq!(listing.completions.load(Ordering::SeqCst), 0);
    }
}
