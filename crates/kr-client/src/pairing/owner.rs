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
    CLOCK_PURPOSE, CatalogueTrustPlan, ConfirmationDisplay, DescribedAction,
    OwnerConfirmationCompleteParams, OwnerConfirmationPendingParams,
    OwnerConfirmationPendingResult, PendingConfirmation, PluginInstallPlan,
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

/// How long a host may take to take an answer. A host that holds its connection open and answers
/// nothing ends the review not confirmed at this bound, rather than holding the review, and
/// whatever waits on it, for as long as the connection stays open.
pub const ANSWER_WITHIN: Duration = Duration::from_secs(10);

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
#[derive(Clone, PartialEq, Eq)]
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
    /// Adopting a repository's trust root, as the host's catalogue described the enrolment: the
    /// plan whose digest this device recomputed from what it shows.
    CatalogueAdd(CatalogueTrustPlan),
    /// Installing a release with a grant, as the host's catalogue described the installation: the
    /// plan whose digest this device recomputed from what it shows.
    PluginInstall(PluginInstallPlan),
    /// An action its caller described by class, rights and digest only.
    Described(DescribedAction),
}

impl std::fmt::Debug for Subject {
    /// Which action it is, and an invitation's mode and kind of grant. Never an origin, a grant's
    /// scopes, a candidate's description or an action's words, which are what a person typed or a
    /// device sent.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IssueInvitation {
                mode, grant_kind, ..
            } => formatter
                .debug_struct("IssueInvitation")
                .field("mode", mode)
                .field("grant_kind", grant_kind)
                .finish_non_exhaustive(),
            Self::ConfirmDevice { .. } => formatter
                .debug_struct("ConfirmDevice")
                .finish_non_exhaustive(),
            Self::EstablishClock => formatter.write_str("EstablishClock"),
            Self::CatalogueAdd(_) => formatter.write_str("CatalogueAdd(..)"),
            Self::PluginInstall(_) => formatter.write_str("PluginInstall(..)"),
            Self::Described(_) => formatter.write_str("Described(..)"),
        }
    }
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
    /// The value it shows is not a verification value.
    Value,
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
            // The value goes into the platform's own dialog as it is, so it has to be the value a
            // host computes and nothing else.
            if !is_verification_value(&candidate.verification_value) {
                return Err(CannotCheck::Value);
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
        ConfirmationDisplay::CatalogueAdd { .. } => {
            expect(SensitiveAction::TrustRepositoryRoot)?;
            // The plan is built again from what the person is shown, so a host that shows one
            // enrolment and asks for the confirmation of another is found here.
            let plan =
                CatalogueTrustPlan::of_display(&pending.display).ok_or(CannotCheck::Unreadable)?;
            let digest = plan.action_digest().map_err(|_| CannotCheck::Unreadable)?;
            if digest != request.action_digest {
                return Err(CannotCheck::DigestMismatch);
            }
            no_destination()?;
            rights(&kr_protocol::scalars::CanonicalSet::new())?;
            Ok(Subject::CatalogueAdd(plan))
        }
        ConfirmationDisplay::PluginInstall { .. } => {
            expect(SensitiveAction::GrantExecutableCapability)?;
            let plan =
                PluginInstallPlan::of_display(&pending.display).ok_or(CannotCheck::Unreadable)?;
            let digest = plan.action_digest().map_err(|_| CannotCheck::Unreadable)?;
            if digest != request.action_digest {
                return Err(CannotCheck::DigestMismatch);
            }
            no_destination()?;
            rights(&kr_protocol::scalars::CanonicalSet::new())?;
            Ok(Subject::PluginInstall(plan))
        }
    }
}

/// The kinds of action a grant can let a device take, strongest first, as a prompt names them.
///
/// Every right belongs to exactly one kind, and a prompt names every kind a grant holds, each in
/// words that cover everything its rights allow, so no authority is shown as a smaller one. Host
/// management is the owner's and is named on its own.
const KINDS: [(&str, &[ActionRight]); 15] = [
    ("type in terminals", &[ActionRight::TerminalInput]),
    (
        "install, enable, pause and run automations",
        &[ActionRight::AutomationManage],
    ),
    (
        "change files",
        &[ActionRight::FilesUpload, ActionRight::FilesApplyDiff],
    ),
    (
        "direct agents",
        &[ActionRight::AgentPrompt, ActionRight::AgentCancel],
    ),
    (
        "answer agents' approval requests and questions",
        &[
            ActionRight::AgentApprovalRespond,
            ActionRight::QuestionRespond,
        ],
    ),
    ("share sessions with others", &[ActionRight::SessionShare]),
    (
        "create projects from repositories",
        &[ActionRight::ProjectCreate],
    ),
    (
        "create and remove workspaces",
        &[ActionRight::WorkspaceManage],
    ),
    (
        "create, rename and close sessions",
        &[
            ActionRight::SessionCreate,
            ActionRight::SessionRename,
            ActionRight::SessionClose,
        ],
    ),
    ("capture change sets", &[ActionRight::ChangesetCreate]),
    ("read files", &[ActionRight::FilesRead]),
    ("use voice", &[ActionRight::VoiceUse]),
    (
        "resize terminals",
        &[
            ActionRight::TerminalGeometry,
            ActionRight::TerminalGeometryTransfer,
        ],
    ),
    ("change terminal colours", &[ActionRight::TerminalPalette]),
    ("view sessions", &[ActionRight::SessionView]),
];

/// What `rights` let a device do, in the words a person is shown on every surface: the owner's
/// prompt, the pairing screen and the list of paired hosts.
#[must_use]
pub fn describe_rights(rights: &kr_protocol::scalars::CanonicalSet<ActionRight>) -> String {
    authority(rights).unwrap_or_else(|| "do what the host allows".to_owned())
}

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

/// How long a grant lasts, from `now_ms`, in words. Each unit is rounded up, so the words never
/// say a grant ends sooner than it does: 71 hours is "for 3 days".
fn duration(expiry: &GrantExpiry, now_ms: u64) -> String {
    const MINUTE_MS: u64 = 60_000;
    const HOUR_MS: u64 = 60 * MINUTE_MS;
    const DAY_MS: u64 = 24 * HOUR_MS;
    let GrantExpiry::At { expires_at_ms } = expiry else {
        return "until it is revoked".to_owned();
    };
    let left = expires_at_ms.get().saturating_sub(now_ms);
    let minutes = left.div_ceil(MINUTE_MS);
    let hours = left.div_ceil(HOUR_MS);
    match (minutes, hours) {
        (0, _) => "for no time at all".to_owned(),
        (1, _) => "for 1 minute".to_owned(),
        (2..=119, _) => format!("for {minutes} minutes"),
        (_, ..=47) => format!("for {hours} hours"),
        _ => format!("for {} days", left.div_ceil(DAY_MS)),
    }
}

/// Where a repository's metadata is served from.
enum Location {
    /// A named host.
    Host(String),
    /// A folder on the host's own machine.
    Folder,
    /// An address this prompt cannot name.
    Unknown,
}

/// Where the repository at `metadata_url` is served from, in the words a prompt uses.
fn location(metadata_url: &str) -> Location {
    match url::Url::parse(metadata_url) {
        Ok(url) if url.scheme() == "file" => Location::Folder,
        Ok(url) => url
            .host_str()
            .map_or(Location::Unknown, |name| Location::Host(name.to_owned())),
        Err(_) => Location::Unknown,
    }
}

/// The first eight characters of a hash a host reports, grouped as a verification value is, or
/// `None` when it is not a hash as a host writes one: sixty-four lower-case hexadecimal
/// characters.
fn hash_start(hash: &str) -> Option<String> {
    (hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| group_verification_value(&hash[..8]))
}

/// True for a verification value as a host computes it: eight lower-case hexadecimal characters.
fn is_verification_value(value: &str) -> bool {
    value.len() == kr_protocol::pairing::VERIFICATION_VALUE_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    if !is_showable(subject) {
        return Err(CannotCheck::CannotShow);
    }
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
                "confirm adding {} ({}) to {host}, which may {} {}. {}",
                shown(candidate.device_name.as_str(), names),
                platform(candidate.platform),
                authority(&proposed_grant.actions).ok_or(CannotCheck::CannotShow)?,
                duration(&proposed_grant.expiry, now_ms),
                shows_value(&group_verification_value(&candidate.verification_value))
            ),
            Subject::EstablishClock => format!("trust the clock of {host} again"),
            Subject::CatalogueAdd(plan) => {
                let served = match location(&plan.metadata_url) {
                    Location::Host(name) => shown(&name, names + 20),
                    Location::Folder => "a folder on that host".to_owned(),
                    Location::Unknown => return Err(CannotCheck::CannotShow),
                };
                let root = hash_start(&plan.root_digest).ok_or(CannotCheck::CannotShow)?;
                let may = match plan.ceiling.len() {
                    0 => "its packages may hold nothing beyond the default".to_owned(),
                    1 => "its packages may hold 1 capability beyond the default".to_owned(),
                    more => format!("its packages may hold {more} capabilities beyond the default"),
                };
                format!(
                    "trust the plugin repository {} on {host}, served from {served}: its root \
                     starts {root}, and {may}",
                    shown(&plan.catalogue_id, names)
                )
            }
            Subject::PluginInstall(plan) => {
                let package = hash_start(&plan.package_digest).ok_or(CannotCheck::CannotShow)?;
                let bridge = plan.grant_statement.is_some()
                    || plan.grant.contains(&"native_bridge.install".to_owned());
                let granting = match (plan.grant.len(), bridge) {
                    (0, false) => "nothing beyond what the repository allows".to_owned(),
                    (0, true) => "a native bridge that runs outside the plugin sandbox".to_owned(),
                    (1, false) => "1 capability".to_owned(),
                    (more, false) => format!("{more} capabilities"),
                    (1, true) => {
                        "1 capability, a native bridge that runs outside the plugin sandbox"
                            .to_owned()
                    }
                    (more, true) => format!(
                        "{more} capabilities, among them a native bridge that runs outside the \
                         plugin sandbox"
                    ),
                };
                format!(
                    "install {} {} from {} on {host}, granting {granting}; package starts \
                     {package}",
                    shown(plan.plugin_id.as_str(), names),
                    shown(&plan.version, names),
                    shown(&plan.catalogue_id, names)
                )
            }
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
        // Every part of the line is fixed text, a checked value or a name `shown` cleaned, so a
        // character a dialog must not show here is a fault: no line is better than a wrong one.
        if !is_plain_text(&text) {
            return Err(CannotCheck::CannotShow);
        }
        if text.chars().count() <= MAX_REASON_CHARS {
            return Ok(text);
        }
    }
    Err(CannotCheck::CannotShow)
}

/// The sentence a device confirmation's reason ends with: the value, grouped, that the device being
/// added shows. An interface that shows the value in a place of its own leaves this sentence out
/// of the line it shows beside it.
#[must_use]
pub fn shows_value(grouped: &str) -> String {
    format!("It shows {grouped}.")
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

/// The longest address, name or identifier an enrolment or an installation shows whole.
pub const FIELD_CHARS: usize = 2048;

/// The longest statement a publisher's manifest may carry, and so the longest shown whole.
pub const STATEMENT_CHARS: usize = 1000;

/// True when `text` is one line a person reads as it is written: no control character, no
/// character that reorders or hides text, and no white space but the space.
///
/// What a host or a publisher wrote is shown as it is or not at all, never cleaned into words it
/// did not write.
#[must_use]
pub fn is_plain_text(text: &str) -> bool {
    !text
        .chars()
        .any(|character| character.is_control() || invisible(character))
        && !text
            .chars()
            .any(|character| character.is_whitespace() && character != ' ')
}

/// True when every word an enrolment or an installation shows can be shown exactly as written:
/// each is one plain line within its bound. A request with a word that cannot be is not offered
/// to anybody to confirm, because what it shows would not be what its digest covers.
fn is_showable(subject: &Subject) -> bool {
    let line =
        |text: &str| !text.is_empty() && text.chars().count() <= FIELD_CHARS && is_plain_text(text);
    match subject {
        Subject::CatalogueAdd(plan) => {
            line(&plan.catalogue_id)
                && line(&plan.metadata_url)
                && line(&plan.targets_url)
                && line(&plan.root_digest)
                && plan.root_key_ids.iter().all(|key| line(key))
                && plan.ceiling.iter().all(|capability| line(capability))
        }
        Subject::PluginInstall(plan) => {
            line(plan.plugin_id.as_str())
                && line(&plan.version)
                && line(&plan.catalogue_id)
                && line(&plan.package_digest)
                && plan.ceiling.iter().all(|capability| line(capability))
                && plan.grant.iter().all(|capability| line(capability))
                && plan.grant_statement.as_ref().is_none_or(|statement| {
                    !statement.is_empty()
                        && statement.chars().count() <= STATEMENT_CHARS
                        && is_plain_text(statement)
                })
        }
        _ => true,
    }
}

/// True for a character that reorders or hides text, which a dialog's line leaves out: the
/// characters every package's own text is held to, apart from the control characters, which a
/// line turns into spaces.
fn invisible(character: char) -> bool {
    kr_plugin_sdk::text::is_forbidden_text_char(character)
        && !character.is_control()
        && !character.is_whitespace()
}

/// Display text as a dialog may show it: on one line, with the characters that reorder or hide
/// text left out, runs of space as one, and at most `limit` characters.
///
/// A control character becomes a space, and splitting on Unicode white space turns every other
/// break, the line and paragraph separators U+2028 and U+2029 among them, into single spaces.
/// What an interface shows of a name a host or a person chose goes through this too, so that it
/// reads as the dialog's line does.
#[must_use]
pub fn shown(text: &str, limit: usize) -> String {
    let spaced: String = text
        .chars()
        .filter(|character| !invisible(*character))
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
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
#[derive(Clone)]
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
    /// The person did not complete the ceremony, or the host refused the proof.
    NotConfirmed,
    /// The challenge expired first.
    Expired,
    /// The challenge could not be checked, so it was not offered to the ceremony.
    CannotCheck,
    /// This device has no ceremony, so it signs nothing.
    NoCeremony,
    /// The answer was sent, and the host has not said whether it took it: it did not reply in
    /// time, or the connection ended first. What the host lists next shows whether it did.
    Unknown,
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
        let params = OwnerConfirmationCompleteParams {
            proof,
            bootstrap_signer: Nullable::null(),
        };
        let sent = tokio::time::timeout(ANSWER_WITHIN, self.channel.complete(&params)).await;
        match sent {
            Ok(Ok(())) => ReviewOutcome::Confirmed,
            // The host's own refusal: it did not take the answer. A host that says it does not
            // know what came of the answer has refused nothing.
            Ok(Err(ClientError::Host(error) | ClientError::Refused { error, .. }))
                if error.code != ErrorCode::OutcomeUnknown =>
            {
                if error.code == ErrorCode::OwnerConfirmationRequired
                    && self.clock.wall_clock_ms() >= expires_at_ms
                {
                    ReviewOutcome::Expired
                } else {
                    ReviewOutcome::NotConfirmed
                }
            }
            // No reply, one that does not know, or none from the host: it may have taken the
            // answer all the same.
            Ok(Err(_)) | Err(_) => self.settled(&listed.request).await,
        }
    }

    /// Whether the host took an answer it gave no reply to, from what it lists now: a challenge it
    /// lists as answered was taken, and anything else leaves the outcome unknown.
    async fn settled(&self, request: &OwnerConfirmationRequest) -> ReviewOutcome {
        match tokio::time::timeout(ANSWER_WITHIN, self.channel.pending()).await {
            Ok(Ok(listed))
                if listed.pending.iter().any(|pending| {
                    pending.answered && pending.request.confirmation_id == request.confirmation_id
                }) =>
            {
                ReviewOutcome::Confirmed
            }
            _ => ReviewOutcome::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kr_crypto::keys::DeviceKeys;
    use kr_protocol::error::ProtocolError;
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

    /// Every right but the owner's belongs to exactly one kind, so no right can be left out of a
    /// prompt for want of words, or be described twice.
    #[test]
    fn every_right_has_words() {
        for right in ActionRight::ALL {
            let kinds = KINDS
                .iter()
                .filter(|(_, kind)| kind.contains(right))
                .count();
            let expected = usize::from(*right != ActionRight::HostManage);
            assert_eq!(kinds, expected, "{right}");
            let rights = [*right].into_iter().collect::<CanonicalSet<_>>();
            assert!(authority(&rights).is_some(), "{right}");
        }
    }

    /// KR-REQ-10.06: a right on its own is named for everything it allows, never for less.
    #[test]
    fn each_right_is_named_for_what_it_allows() {
        for (right, words) in [
            (ActionRight::FilesRead, "read files"),
            (ActionRight::FilesApplyDiff, "change files"),
            (
                ActionRight::AutomationManage,
                "install, enable, pause and run automations",
            ),
            (ActionRight::TerminalPalette, "change terminal colours"),
            (ActionRight::TerminalGeometry, "resize terminals"),
            (ActionRight::SessionShare, "share sessions with others"),
            (
                ActionRight::AgentApprovalRespond,
                "answer agents' approval requests and questions",
            ),
            (ActionRight::HostManage, "manage the host as an owner"),
        ] {
            let rights = [right].into_iter().collect::<CanonicalSet<_>>();
            assert_eq!(authority(&rights).as_deref(), Some(words), "{right}");
        }
    }

    /// KR-REQ-10.06: a grant's duration is rounded up in every unit, so the prompt never says it
    /// ends sooner than it does.
    #[test]
    fn a_duration_is_never_shorter_than_the_grant() {
        const MINUTE: u64 = 60_000;
        const HOUR: u64 = 60 * MINUTE;
        for (left, words) in [
            (1, "for 1 minute"),
            (61 * MINUTE, "for 61 minutes"),
            (119 * MINUTE + 30_000, "for 2 hours"),
            (24 * HOUR, "for 24 hours"),
            (47 * HOUR + 30 * MINUTE, "for 2 days"),
            (71 * HOUR, "for 3 days"),
        ] {
            let expiry = GrantExpiry::At {
                expires_at_ms: TimestampMs::new(NOW + left),
            };
            assert_eq!(duration(&expiry, NOW), words, "{left} ms");
        }
        assert_eq!(duration(&GrantExpiry::Never, NOW), "until it is revoked");
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
        let line = reason(&subject, "stu\u{2028}di\no\r\u{1b}", NOW).expect("a line");
        for hidden_character in [
            '\n', '\r', '\u{1b}', '\u{2028}', '\u{2029}', '\u{202E}', '\u{2066}', '\u{FEFF}',
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

    /// The host a device is paired with.
    fn paired_host() -> PairedHost {
        let host_keys = DeviceKeys::generate().expect("keys").public_keys();
        PairedHost {
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
        }
    }

    /// The challenge a host issues for an action with `digest`: no destination, no rights.
    fn challenge_for(
        host: &PairedHost,
        action: SensitiveAction,
        digest: Digest256,
    ) -> OwnerConfirmationRequest {
        OwnerConfirmationRequest {
            confirmation_id: ConfirmationId::new(Uuid::from_bytes([4; 16])),
            action,
            action_digest: digest,
            destination_keys: Nullable::null(),
            destination_rights: CanonicalSet::new(),
            host_device_id: host.host_device_id,
            host_endpoint_id: host.host_endpoint_id,
            nonce: Nonce256::from_bytes([6; 32]),
            expires_at_ms: TimestampMs::new(NOW + 60_000),
        }
    }

    fn environment() -> kr_protocol::ids::EnvironmentId {
        kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([8; 16]))
    }

    /// The enrolment a host describes: a community repository, its root and what it may do.
    fn trust_plan() -> CatalogueTrustPlan {
        use kr_protocol::catalogue::{CatalogueAddParams, CatalogueBudgets, CatalogueKind};
        use kr_protocol::scalars::U64;
        let params = CatalogueAddParams {
            environment_id: environment(),
            catalogue_id: "community".to_owned(),
            kind: CatalogueKind::Community,
            metadata_url: "https://repo.example/metadata/".to_owned(),
            targets_url: "https://repo.example/targets/".to_owned(),
            root: "cm9vdA==".to_owned(),
            budgets: CatalogueBudgets {
                metadata_bytes: U64::new(67_108_864),
                metadata_entries: U64::new(100_000),
                retained_generations: U64::new(2),
                retained_metadata_bytes: U64::new(268_435_456),
                payload_cache_bytes: U64::new(2_147_483_648),
                full_offline_mirror: false,
            },
            ceiling: vec!["terminal.stream".to_owned()],
            owner_confirmation: Nullable::null(),
        };
        CatalogueTrustPlan::of_request(
            &params,
            "1a2b3c4d".repeat(8),
            ["key-one".to_owned(), "key-two".to_owned()]
                .into_iter()
                .collect(),
        )
    }

    /// The installation a host describes: a release with a native bridge and what it grants.
    fn install_plan() -> PluginInstallPlan {
        PluginInstallPlan {
            environment_id: environment(),
            catalogue_id: "community".to_owned(),
            ceiling: ["metadata.match".to_owned()].into_iter().collect(),
            plugin_id: kr_protocol::ids::PluginId::new("kalareach/claude-code")
                .expect("a plugin identifier"),
            version: "0.3.0".to_owned(),
            package_digest: "e5f60718".repeat(8),
            grant: [
                "approval.respond".to_owned(),
                "native_bridge.install".to_owned(),
            ]
            .into_iter()
            .collect(),
            grant_statement: Some(
                "Adds one registration file in Claude Code's directory.".to_owned(),
            ),
        }
    }

    fn pending_for(
        host: &PairedHost,
        action: SensitiveAction,
        digest: Digest256,
        display: ConfirmationDisplay,
    ) -> PendingConfirmation {
        PendingConfirmation {
            request: challenge_for(host, action, digest),
            display,
            answered: false,
        }
    }

    /// KR-REQ-11.42, KR-REQ-10.05: an owner device shows what a host describes of an enrolment or
    /// an installation, builds the plan again from it, and takes the challenge only when the
    /// digest it recomputes is the one the host issued: what the person is shown is what the
    /// confirmation covers.
    #[test]
    fn what_a_host_describes_of_an_enrolment_and_an_installation_is_checked_against_its_digest() {
        let host = paired_host();
        let trust = trust_plan();
        let pending = pending_for(
            &host,
            SensitiveAction::TrustRepositoryRoot,
            trust.action_digest().expect("a digest"),
            trust.display(),
        );
        assert_eq!(
            check(&pending, &host),
            Ok(Subject::CatalogueAdd(trust.clone())),
            "an enrolment the host describes"
        );

        let install = install_plan();
        let pending = pending_for(
            &host,
            SensitiveAction::GrantExecutableCapability,
            install.action_digest().expect("a digest"),
            install.display(),
        );
        assert_eq!(
            check(&pending, &host),
            Ok(Subject::PluginInstall(install)),
            "an installation the host describes"
        );
    }

    /// A change to one member of a plan, named for what it changes.
    type Edits<P> = Vec<(&'static str, Box<dyn Fn(&mut P)>)>;

    /// KR-REQ-11.42, KR-REQ-10.05: a challenge whose digest covers something other than what the
    /// display shows is refused, whichever member of the display differs. The control is the
    /// display the digest covers.
    #[test]
    fn a_display_that_differs_from_its_digest_in_any_member_is_refused() {
        let host = paired_host();
        let trust = trust_plan();
        let confirmed = trust.action_digest().expect("a digest");
        let edits: Edits<CatalogueTrustPlan> = vec![
            (
                "the environment",
                Box::new(|plan| {
                    plan.environment_id =
                        kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([9; 16]))
                }),
            ),
            (
                "the name",
                Box::new(|plan| "elsewhere".clone_into(&mut plan.catalogue_id)),
            ),
            (
                "the kind",
                Box::new(|plan| plan.kind = kr_protocol::catalogue::CatalogueKind::Official),
            ),
            (
                "the metadata location",
                Box::new(|plan| {
                    "https://other.example/metadata/".clone_into(&mut plan.metadata_url)
                }),
            ),
            (
                "the targets location",
                Box::new(|plan| "https://other.example/targets/".clone_into(&mut plan.targets_url)),
            ),
            (
                "the root",
                Box::new(|plan| plan.root_digest = "ffff0000".repeat(8)),
            ),
            (
                "the root's keys",
                Box::new(|plan| {
                    plan.root_key_ids.insert("key-three".to_owned());
                }),
            ),
            (
                "the metadata budget",
                Box::new(|plan| plan.budgets.metadata_bytes = kr_protocol::scalars::U64::new(1)),
            ),
            (
                "the entry budget",
                Box::new(|plan| plan.budgets.metadata_entries = kr_protocol::scalars::U64::new(1)),
            ),
            (
                "the generations kept",
                Box::new(|plan| {
                    plan.budgets.retained_generations = kr_protocol::scalars::U64::new(9)
                }),
            ),
            (
                "the metadata kept",
                Box::new(|plan| {
                    plan.budgets.retained_metadata_bytes = kr_protocol::scalars::U64::new(1)
                }),
            ),
            (
                "the package cache",
                Box::new(|plan| {
                    plan.budgets.payload_cache_bytes = kr_protocol::scalars::U64::new(1)
                }),
            ),
            (
                "the offline mirror",
                Box::new(|plan| plan.budgets.full_offline_mirror = true),
            ),
            (
                "the ceiling",
                Box::new(|plan| {
                    plan.ceiling.insert("native_bridge.install".to_owned());
                }),
            ),
        ];
        for (name, edit) in &edits {
            let mut shown = trust.clone();
            edit(&mut shown);
            assert_ne!(shown, trust, "{name}: the edit changes the plan");
            let pending = pending_for(
                &host,
                SensitiveAction::TrustRepositoryRoot,
                confirmed,
                shown.display(),
            );
            assert_eq!(
                check(&pending, &host),
                Err(CannotCheck::DigestMismatch),
                "{name}"
            );
        }

        let install = install_plan();
        let confirmed = install.action_digest().expect("a digest");
        let edits: Edits<PluginInstallPlan> = vec![
            (
                "the environment",
                Box::new(|plan| {
                    plan.environment_id =
                        kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([9; 16]))
                }),
            ),
            (
                "the repository",
                Box::new(|plan| "wide".clone_into(&mut plan.catalogue_id)),
            ),
            (
                "the repository's ceiling",
                Box::new(|plan| {
                    plan.ceiling.insert("terminal.stream".to_owned());
                }),
            ),
            (
                "the package",
                Box::new(|plan| {
                    plan.plugin_id =
                        kr_protocol::ids::PluginId::new("kalareach/other").expect("an identifier")
                }),
            ),
            (
                "the release",
                Box::new(|plan| "0.4.0".clone_into(&mut plan.version)),
            ),
            (
                "the package hash",
                Box::new(|plan| plan.package_digest = "00000000".repeat(8)),
            ),
            (
                "the grant",
                Box::new(|plan| {
                    plan.grant.insert("upstream.action".to_owned());
                }),
            ),
            (
                "the publisher's statement",
                Box::new(|plan| plan.grant_statement = Some("Does something else.".to_owned())),
            ),
            ("no statement", Box::new(|plan| plan.grant_statement = None)),
        ];
        for (name, edit) in &edits {
            let mut shown = install.clone();
            edit(&mut shown);
            assert_ne!(shown, install, "{name}: the edit changes the plan");
            let pending = pending_for(
                &host,
                SensitiveAction::GrantExecutableCapability,
                confirmed,
                shown.display(),
            );
            assert_eq!(
                check(&pending, &host),
                Err(CannotCheck::DigestMismatch),
                "{name}"
            );
        }
    }

    /// KR-REQ-10.05: a display is checked against the kind of action it would authorise, the host
    /// it is for, and the destination and rights the challenge carries, which an enrolment and an
    /// installation have none of.
    #[test]
    fn an_enrolment_or_an_installation_is_refused_for_another_action_host_destination_or_rights() {
        let host = paired_host();
        let trust = trust_plan();
        let digest = trust.action_digest().expect("a digest");
        let asked = |action, edit: &dyn Fn(&mut PendingConfirmation)| {
            let mut pending = pending_for(&host, action, digest, trust.display());
            edit(&mut pending);
            check(&pending, &host)
        };
        assert!(matches!(
            asked(SensitiveAction::TrustRepositoryRoot, &|_| {}),
            Ok(Subject::CatalogueAdd(_))
        ));
        assert_eq!(
            asked(SensitiveAction::GrantExecutableCapability, &|_| {}),
            Err(CannotCheck::ActionMismatch),
            "an enrolment is not an installation"
        );
        assert_eq!(
            asked(SensitiveAction::TrustRepositoryRoot, &|pending| {
                pending.request.host_device_id = DeviceId::new(Uuid::from_bytes([42; 16]));
            }),
            Err(CannotCheck::AnotherHost)
        );
        assert_eq!(
            asked(SensitiveAction::TrustRepositoryRoot, &|pending| {
                pending.request.destination_keys =
                    Nullable::some(DeviceKeys::generate().expect("keys").public_keys());
            }),
            Err(CannotCheck::Destination)
        );
        assert_eq!(
            asked(SensitiveAction::TrustRepositoryRoot, &|pending| {
                pending.request.destination_rights =
                    [ActionRight::SessionView].into_iter().collect();
            }),
            Err(CannotCheck::Rights)
        );

        // A host that lists a set out of its canonical order has not followed the definition.
        let install = install_plan();
        let mut display = install.display();
        if let ConfirmationDisplay::PluginInstall { grant, .. } = &mut display {
            grant.reverse();
        }
        let pending = pending_for(
            &host,
            SensitiveAction::GrantExecutableCapability,
            install.action_digest().expect("a digest"),
            display,
        );
        assert_eq!(check(&pending, &host), Err(CannotCheck::Unreadable));
    }

    /// KR-REQ-11.42: the dialog's line names what an enrolment and an installation authorise: the
    /// repository and where it is served from, the first characters of the root or package hash
    /// the page shows in full, the capabilities, and for a native bridge that it runs outside the
    /// plugin sandbox. It is one line whatever the names, and a hash that is not a hash has no
    /// line.
    #[test]
    fn a_reason_for_an_enrolment_and_an_installation_names_what_each_authorises() {
        let trust = Subject::CatalogueAdd(trust_plan());
        assert_eq!(
            reason(&trust, "studio", NOW).expect("a line"),
            "trust the plugin repository community on studio, served from repo.example: its \
             root starts 1a2b 3c4d, and its packages may hold 1 capability beyond the default"
        );
        let nothing_more = Subject::CatalogueAdd(CatalogueTrustPlan {
            ceiling: CanonicalSet::new(),
            metadata_url: "file:///srv/community/metadata/".to_owned(),
            ..trust_plan()
        });
        assert_eq!(
            reason(&nothing_more, "studio", NOW).expect("a line"),
            "trust the plugin repository community on studio, served from a folder on that \
             host: its root starts 1a2b 3c4d, and its packages may hold nothing beyond the \
             default"
        );

        let install = Subject::PluginInstall(install_plan());
        assert_eq!(
            reason(&install, "studio", NOW).expect("a line"),
            "install kalareach/claude-code 0.3.0 from community on studio, granting 2 \
             capabilities, among them a native bridge that runs outside the plugin sandbox; \
             package starts e5f6 0718"
        );
        let plain = Subject::PluginInstall(PluginInstallPlan {
            grant: CanonicalSet::new(),
            grant_statement: None,
            ..install_plan()
        });
        assert_eq!(
            reason(&plain, "studio", NOW).expect("a line"),
            "install kalareach/claude-code 0.3.0 from community on studio, granting nothing \
             beyond what the repository allows; package starts e5f6 0718"
        );

        let long = Subject::PluginInstall(PluginInstallPlan {
            catalogue_id: "community".repeat(30),
            ..install_plan()
        });
        let line = reason(&long, &"h".repeat(120), NOW).expect("a line");
        assert!(line.chars().count() <= MAX_REASON_CHARS, "{line}");
        assert!(
            line.contains("runs outside the plugin sandbox"),
            "authority is never shortened away: {line}"
        );

        // Words that cannot be shown as written are not cleaned into words the host did not
        // write: there is no line.
        for hidden in [
            "com\u{2028}munity",
            "com\u{202E}munity",
            "com\nmunity",
            "com\u{00AD}munity",
        ] {
            let hostile = Subject::PluginInstall(PluginInstallPlan {
                catalogue_id: hidden.to_owned(),
                ..install_plan()
            });
            assert_eq!(
                reason(&hostile, "studio", NOW),
                Err(CannotCheck::CannotShow),
                "{hidden:?}"
            );
        }

        for broken in ["", "not a hash", &"G".repeat(64), &"a".repeat(63)] {
            let subject = Subject::CatalogueAdd(CatalogueTrustPlan {
                root_digest: (*broken).to_owned(),
                ..trust_plan()
            });
            assert_eq!(
                reason(&subject, "studio", NOW),
                Err(CannotCheck::CannotShow),
                "{broken:?}"
            );
        }
    }

    /// KR-REQ-11.42: a character that hides or reorders text is never shown: U+00AD and U+061C are
    /// not control characters or white space and are in the policy every package's own text is held
    /// to. A host's name, an address with one in its path or a publisher's statement that carries
    /// one is a line no dialog is given, so the confirmation is not offered to the ceremony.
    #[test]
    fn text_that_hides_or_reorders_characters_is_never_shown() {
        for hidden in [
            '\u{00AD}', '\u{061C}', '\u{200B}', '\u{202E}', '\u{FFF9}', '\u{FEFF}',
        ] {
            assert!(
                !is_plain_text(&format!("a{hidden}b")),
                "U+{:04X}",
                hidden as u32
            );
        }
        assert!(is_plain_text(
            "an ordinary line, with spaces and https://repo.example/a-b_c/"
        ));
        assert!(!is_plain_text("two\nlines"));
        assert!(!is_plain_text("tab\there"));

        let mut subjects = Vec::new();
        for text in [
            "https://repo.example/me\u{00AD}tadata/",
            "https://repo.example/me\u{061C}tadata/",
        ] {
            subjects.push(Subject::CatalogueAdd(CatalogueTrustPlan {
                metadata_url: text.to_owned(),
                ..trust_plan()
            }));
            subjects.push(Subject::CatalogueAdd(CatalogueTrustPlan {
                targets_url: text.to_owned(),
                ..trust_plan()
            }));
        }
        subjects.push(Subject::CatalogueAdd(CatalogueTrustPlan {
            targets_url: format!("https://repo.example/{}", "a".repeat(5000)),
            ..trust_plan()
        }));
        subjects.push(Subject::PluginInstall(PluginInstallPlan {
            grant_statement: Some("it\u{00AD}s fine".to_owned()),
            ..install_plan()
        }));
        subjects.push(Subject::PluginInstall(PluginInstallPlan {
            grant_statement: Some("x".repeat(kr_plugin_sdk::text::Summary::LIMIT + 1)),
            ..install_plan()
        }));
        subjects.push(Subject::PluginInstall(PluginInstallPlan {
            version: "0.3\u{061C}.0".to_owned(),
            ..install_plan()
        }));
        for subject in &subjects {
            assert_eq!(
                reason(subject, "studio", NOW),
                Err(CannotCheck::CannotShow),
                "{subject:?}"
            );
        }
        // The control: the same plans with the text as written.
        assert!(reason(&Subject::CatalogueAdd(trust_plan()), "studio", NOW).is_ok());
        assert!(reason(&Subject::PluginInstall(install_plan()), "studio", NOW).is_ok());
    }

    /// A review of one listed challenge on a listing of its own, and what the person was asked and
    /// what was sent.
    async fn reviewed(
        host: &PairedHost,
        pending: PendingConfirmation,
    ) -> (ReviewOutcome, usize, usize) {
        let listing = Arc::new(Listing {
            pending: Mutex::new(vec![pending]),
            completions: AtomicUsize::new(0),
            takes: std::sync::atomic::AtomicBool::new(true),
            reply: Mutex::new(Reply::Took),
        });
        let confirmations = OwnerConfirmations::new(
            host.clone(),
            DeviceKeys::generate().expect("keys").authorisation,
            listing.clone(),
            Arc::new(Fixed(NOW)),
        );
        let listed = confirmations.pending().await.expect("the listing");
        assert!(listed[0].subject.is_ok(), "the challenge itself checks");
        let asked = Asked(Mutex::new(Vec::new()));
        let outcome = confirmations.review(&listed[0], &asked).await;
        let asked = asked.0.lock().expect("the record").len();
        (outcome, asked, listing.completions.load(Ordering::SeqCst))
    }

    /// KR-REQ-11.42: a request whose text cannot be shown as written never reaches the ceremony,
    /// whoever asks for the review: the review runs the same check before it asks the person, so
    /// a signature is never given for facts a page withheld. Nothing is signed or sent. The
    /// control is the same challenge with its text as written, which the person is asked about.
    #[tokio::test]
    async fn a_request_whose_text_cannot_be_shown_is_not_offered_to_the_ceremony() {
        let host = paired_host();
        for unshowable in [
            CatalogueTrustPlan {
                targets_url: format!("https://repo.example/{}", "a".repeat(5000)),
                ..trust_plan()
            },
            CatalogueTrustPlan {
                metadata_url: "https://repo.example/me\u{00AD}tadata/".to_owned(),
                ..trust_plan()
            },
        ] {
            let pending = pending_for(
                &host,
                SensitiveAction::TrustRepositoryRoot,
                unshowable.action_digest().expect("a digest"),
                unshowable.display(),
            );
            assert_eq!(
                reviewed(&host, pending).await,
                (ReviewOutcome::CannotCheck, 0, 0),
                "{unshowable:?}"
            );
        }
        let trust = trust_plan();
        let pending = pending_for(
            &host,
            SensitiveAction::TrustRepositoryRoot,
            trust.action_digest().expect("a digest"),
            trust.display(),
        );
        assert_eq!(
            reviewed(&host, pending).await,
            (ReviewOutcome::Confirmed, 1, 1)
        );
    }

    /// An owner channel over a listing a test writes, which counts what is sent.
    struct Listing {
        pending: Mutex<Vec<PendingConfirmation>>,
        completions: AtomicUsize,
        /// Lists a challenge as answered once an answer to it arrives.
        takes: std::sync::atomic::AtomicBool,
        /// What the host replies to an answer.
        reply: Mutex<Reply>,
    }

    /// What a host replies to an answer.
    #[derive(Clone, Copy)]
    enum Reply {
        /// That it took it.
        Took,
        /// Nothing, ever.
        Nothing,
        /// That it does not know what came of it.
        OutcomeUnknown,
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
            if self.takes.load(Ordering::SeqCst) {
                for pending in self.pending.lock().expect("the listing").iter_mut() {
                    pending.answered = true;
                }
            }
            let reply = *self.reply.lock().expect("the reply");
            Box::pin(async move {
                match reply {
                    Reply::Took => Ok(()),
                    Reply::Nothing => std::future::pending().await,
                    Reply::OutcomeUnknown => Err(ClientError::Host(ProtocolError::new(
                        ErrorCode::OutcomeUnknown,
                        "the host could not tell whether the answer took effect",
                    ))),
                }
            })
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

    /// A device confirmation for `shown` with `proposed`, as a host this device owns lists it, and
    /// the service that reviews it.
    fn listed_device(
        shown: PairCandidateView,
        proposed: ProposedGrant,
    ) -> (OwnerConfirmations, Arc<Listing>) {
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
        let request = OwnerConfirmationRequest {
            confirmation_id: ConfirmationId::new(Uuid::from_bytes([4; 16])),
            action: SensitiveAction::ConfirmDevice,
            action_digest: Digest256::from_bytes([5; 32]),
            destination_keys: Nullable::some(shown.keys),
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
                    candidate: shown,
                    proposed_grant: proposed,
                },
                answered: false,
            }]),
            completions: AtomicUsize::new(0),
            takes: std::sync::atomic::AtomicBool::new(true),
            reply: Mutex::new(Reply::Took),
        });
        let confirmations = OwnerConfirmations::new(
            host,
            DeviceKeys::generate().expect("keys").authorisation,
            listing.clone(),
            Arc::new(Fixed(NOW)),
        );
        (confirmations, listing)
    }

    /// KR-REQ-10.06: a challenge whose authority no line of the prompt can show is never offered
    /// to the ceremony, and nothing is signed or sent.
    #[tokio::test]
    async fn authority_no_line_can_show_is_not_offered_to_the_ceremony() {
        let everything_but_the_host: Vec<ActionRight> = ActionRight::ALL
            .iter()
            .copied()
            .filter(|right| *right != ActionRight::HostManage)
            .collect();
        let (confirmations, listing) = listed_device(
            candidate("Pixel 8"),
            grant(&everything_but_the_host, an_hour()),
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

    /// KR-REQ-10.06: a device confirmation whose value is not a verification value as a host
    /// computes it, eight lower-case hexadecimal characters, cannot be checked: it never reaches the
    /// ceremony's dialog, and nothing is signed or sent.
    #[tokio::test]
    async fn a_value_that_is_not_a_verification_value_is_not_offered_to_the_ceremony() {
        for value in [
            "f3c1\n46f",
            "f3c146f\u{202E}",
            "f3c1 46fd",
            "F3C146FD",
            "f3c146fd0",
            "",
        ] {
            let mut shown = candidate("Pixel 8");
            shown.verification_value = value.to_owned();
            let (confirmations, listing) =
                listed_device(shown, grant(&[ActionRight::SessionView], an_hour()));
            let listed = confirmations.pending().await.expect("the listing");
            assert_eq!(
                listed[0].subject.clone().err(),
                Some(CannotCheck::Value),
                "{value:?}"
            );
            let asked = Asked(Mutex::new(Vec::new()));
            assert_eq!(
                confirmations.review(&listed[0], &asked).await,
                ReviewOutcome::CannotCheck,
                "{value:?}"
            );
            assert!(asked.0.lock().expect("the record").is_empty(), "{value:?}");
            assert_eq!(listing.completions.load(Ordering::SeqCst), 0, "{value:?}");
        }
    }

    /// KR-REQ-10.06: a host that takes an answer and says nothing holds the review for
    /// [`ANSWER_WITHIN`] and no longer. The answer was sent once. The host may have taken it, and
    /// what it lists afterwards does not show that it did, so the review ends as unknown, never as
    /// not confirmed, rather than holding its connection, and the page that asked, for as long as
    /// the host keeps the connection open.
    #[tokio::test(start_paused = true)]
    async fn a_host_that_never_answers_a_completion_holds_the_review_for_a_bound() {
        let (confirmations, listing) = listed_device(
            candidate("Pixel 8"),
            grant(&[ActionRight::SessionView], an_hour()),
        );
        listing.takes.store(false, Ordering::SeqCst);
        *listing.reply.lock().expect("the reply") = Reply::Nothing;
        let listed = confirmations.pending().await.expect("the listing");
        let asked = Asked(Mutex::new(Vec::new()));
        let started = tokio::time::Instant::now();
        let outcome =
            tokio::time::timeout(ANSWER_WITHIN * 3, confirmations.review(&listed[0], &asked))
                .await
                .expect("the review ends");
        assert_eq!(outcome, ReviewOutcome::Unknown);
        let took = started.elapsed();
        assert!(
            took >= ANSWER_WITHIN && took < ANSWER_WITHIN + Duration::from_secs(1),
            "{took:?}"
        );
        assert_eq!(listing.completions.load(Ordering::SeqCst), 1);
    }

    /// KR-REQ-10.06: a host that takes the proof and withholds its reply has still taken it. The
    /// review asks the host what it holds once the reply is overdue, finds the challenge answered,
    /// and says the confirmation went through.
    #[tokio::test(start_paused = true)]
    async fn a_proof_the_host_took_without_replying_is_confirmed_from_what_it_lists() {
        let (confirmations, listing) = listed_device(
            candidate("Pixel 8"),
            grant(&[ActionRight::SessionView], an_hour()),
        );
        *listing.reply.lock().expect("the reply") = Reply::Nothing;
        let listed = confirmations.pending().await.expect("the listing");
        let asked = Asked(Mutex::new(Vec::new()));
        let outcome =
            tokio::time::timeout(ANSWER_WITHIN * 3, confirmations.review(&listed[0], &asked))
                .await
                .expect("the review ends");
        assert_eq!(outcome, ReviewOutcome::Confirmed);
        assert_eq!(listing.completions.load(Ordering::SeqCst), 1);
    }

    /// KR-REQ-10.06: a host that replies that it does not know what came of an answer has not
    /// refused it. The review asks what the host lists: a challenge listed as answered was taken,
    /// and one listed unanswered leaves the outcome unknown, never "not confirmed".
    #[tokio::test]
    async fn an_answer_whose_outcome_the_host_does_not_know_is_settled_from_what_it_lists() {
        for (takes, settled) in [
            (true, ReviewOutcome::Confirmed),
            (false, ReviewOutcome::Unknown),
        ] {
            let (confirmations, listing) = listed_device(
                candidate("Pixel 8"),
                grant(&[ActionRight::SessionView], an_hour()),
            );
            listing.takes.store(takes, Ordering::SeqCst);
            *listing.reply.lock().expect("the reply") = Reply::OutcomeUnknown;
            let listed = confirmations.pending().await.expect("the listing");
            let asked = Asked(Mutex::new(Vec::new()));
            assert_eq!(
                confirmations.review(&listed[0], &asked).await,
                settled,
                "the host took it: {takes}"
            );
        }
    }
}
