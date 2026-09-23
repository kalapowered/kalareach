//! Sharing: the four default roles, what an invitation previews, and the notices a grant carries.
//!
//! Section 25 fixes the shape of this module. Roles are a *composition* aid: viewer, reviewer,
//! controller and owner each name a set of actions, and issuing under a role writes those actions
//! into the grant. Nothing here ever reaches an authorisation decision, because the host never
//! authorises from a role label: [`Grant`](crate::grant::Grant) carries no role, and a request is
//! decided against the actions it carries and nothing else.
//!
//! Three things a role does not decide on its own, because section 25 makes each an explicit
//! choice the issuer has to take:
//!
//! * **Earlier history.** A viewer sees the selected live screen and future events. Anything older
//!   is opt-in through [`RoleSelection::history_from_cursor_ms`].
//! * **`question.respond` for a viewer or reviewer.** Only controller and owner carry it by
//!   default. A viewer or reviewer receives it through [`RoleSelection::include_question_respond`],
//!   which carries [`AuthorityNotice::AgentPermissions`] with it.
//! * **Named current questions and approvals.** An invitation may name exact current decisions
//!   that were created before the history cursor. That permits those decisions, not the
//!   conversation they came from.
//!
//! An issuer sees [`InvitationPreview`] before the invitation exists: the actions the role
//! compiled to, the history the recipient will reach, the live screen as it stands right now, each
//! named question and approval, and every notice the actions carry. A shared live screen can
//! contain text printed before the invitation, so the preview shows what is being shared rather
//! than describing it.

use core::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::action::RevocationBarrier;
use crate::grant::{Grant, HistoryScope};
use crate::ids::{
    ApprovalRequestId, AuthorityRevision, DeviceId, DeviceKeyRevision, EnvironmentId, GrantId,
    InvitationId, QuestionId, QuestionRevision, SessionId,
};
use crate::pairing::OwnerConfirmationProof;
use crate::rights::ActionRight;
use crate::scalars::{CanonicalSet, DurationMs, Nullable, TimestampMs};

/// How long a session invitation lasts when the issuer chooses nothing, in milliseconds.
///
/// Section 10: session invitations default to view-only for one hour.
pub const DEFAULT_INVITATION_LIFETIME_MS: u64 = 60 * 60 * 1000;

/// The longest a session invitation may last, in milliseconds.
///
/// Section 10: the issuer may shorten it or extend it to at most 30 days. Persistent co-owner
/// access is a separate owner pairing, not a longer invitation.
pub const MAX_INVITATION_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// The most lines of the live screen a preview carries.
pub const MAX_PREVIEW_LINES: usize = 256;

/// The most characters one preview line carries.
pub const MAX_PREVIEW_LINE_CHARS: usize = 512;

/// The most named questions or approvals one invitation previews.
pub const MAX_NAMED_RESOURCES: usize = 32;

/// One of the four default roles.
///
/// The order is the order of increasing authority, so a comparison reads the way a person expects.
/// It is a display and composition order only: no check anywhere compares two roles to decide a
/// request.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SessionRole {
    /// Sees the selected live screen and future events.
    Viewer,
    /// A viewer that also sees selected diffs and files.
    Reviewer,
    /// A reviewer that also holds terminal input, prompts and `question.respond`.
    Controller,
    /// A controller that can also manage grants and close the session.
    Owner,
}

impl SessionRole {
    /// Every role, in order of increasing authority.
    pub const ALL: [Self; 4] = [Self::Viewer, Self::Reviewer, Self::Controller, Self::Owner];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Reviewer => "reviewer",
            Self::Controller => "controller",
            Self::Owner => "owner",
        }
    }

    /// Returns the role for a wire string.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "viewer" => Some(Self::Viewer),
            "reviewer" => Some(Self::Reviewer),
            "controller" => Some(Self::Controller),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }

    /// The actions this role carries by default.
    ///
    /// This is the whole of what a role means. It is read once, when a grant is written, and never
    /// again: an authorisation decision reads the grant's actions.
    ///
    /// `question.respond` appears in controller and owner only. Section 25 makes it an explicit
    /// invitation option for the two roles below them, because an answer, including free text, is
    /// input the receiving agent may act on under its own host permissions.
    #[must_use]
    pub const fn default_actions(self) -> &'static [ActionRight] {
        match self {
            Self::Viewer => &[ActionRight::SessionView],
            Self::Reviewer => &[ActionRight::SessionView, ActionRight::FilesRead],
            Self::Controller => &[
                ActionRight::SessionView,
                ActionRight::FilesRead,
                ActionRight::TerminalInput,
                ActionRight::TerminalGeometry,
                ActionRight::AgentPrompt,
                ActionRight::AgentCancel,
                ActionRight::AgentApprovalRespond,
                ActionRight::QuestionRespond,
            ],
            Self::Owner => &[
                ActionRight::SessionView,
                ActionRight::FilesRead,
                ActionRight::TerminalInput,
                ActionRight::TerminalGeometry,
                ActionRight::TerminalGeometryTransfer,
                ActionRight::TerminalPalette,
                ActionRight::AgentPrompt,
                ActionRight::AgentCancel,
                ActionRight::AgentApprovalRespond,
                ActionRight::QuestionRespond,
                ActionRight::SessionRename,
                ActionRight::SessionClose,
                ActionRight::SessionShare,
            ],
        }
    }

    /// Returns true when this role carries `question.respond` without an explicit option.
    #[must_use]
    pub const fn responds_to_questions_by_default(self) -> bool {
        matches!(self, Self::Controller | Self::Owner)
    }
}

impl fmt::Display for SessionRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What the issuer chose, on top of the role, before the grant was written.
///
/// Every field here is an explicit choice. A default-constructed selection adds nothing to the
/// role, which is what section 25 requires: earlier history, the live screen, `question.respond`
/// below controller, and named pre-cutoff resources are each opted into or absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleSelection {
    /// The role the issuer chose.
    pub role: SessionRole,
    /// Earlier history, from this cursor. Null keeps the recipient to the live screen and what
    /// follows it.
    pub history_from_cursor_ms: Nullable<TimestampMs>,
    /// Whether the currently visible screen is included, previewed to the issuer.
    ///
    /// The exception never reaches inactive screen buffers, scrollback or the backing transcript.
    pub include_live_screen: bool,
    /// Whether a viewer or reviewer also receives `question.respond`.
    ///
    /// Ignored for controller and owner, which carry it already.
    pub include_question_respond: bool,
    /// Current questions this invitation names explicitly.
    pub named_questions: CanonicalSet<QuestionId>,
    /// Current approval requests this invitation names explicitly.
    pub named_approvals: CanonicalSet<ApprovalRequestId>,
}

impl RoleSelection {
    /// A selection that adds nothing to the role.
    #[must_use]
    pub fn plain(role: SessionRole) -> Self {
        Self {
            role,
            history_from_cursor_ms: Nullable::null(),
            include_live_screen: false,
            include_question_respond: false,
            named_questions: CanonicalSet::from_iter([]),
            named_approvals: CanonicalSet::from_iter([]),
        }
    }

    /// The actions this selection compiles to.
    ///
    /// The role's defaults, plus `question.respond` when the issuer opted into it for a role that
    /// does not carry it. Nothing else is added, and nothing is added implicitly.
    #[must_use]
    pub fn actions(&self) -> CanonicalSet<ActionRight> {
        let mut actions: CanonicalSet<ActionRight> =
            self.role.default_actions().iter().copied().collect();
        if self.include_question_respond {
            actions.insert(ActionRight::QuestionRespond);
        }
        actions
    }

    /// The history scope this selection compiles to.
    #[must_use]
    pub fn history(&self) -> HistoryScope {
        HistoryScope {
            lower_bound_ms: self.history_from_cursor_ms,
            include_live_screen: self.include_live_screen,
            named_questions: self.named_questions.clone(),
            named_approvals: self.named_approvals.clone(),
        }
    }
}

/// One consequence of a grant that the issuer is shown before the grant exists.
///
/// Section 10 forbids a label that implies a restrictive sandbox the upstream does not enforce, so
/// the host decides which notices a set of actions carries and states each one in fixed words.
/// A surface may translate [`Self::sentence`]; it may not soften it, and it may not decide for
/// itself that an action is harmless.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityNotice {
    /// `terminal.input`: the recipient types as the shell user.
    AccountAccess,
    /// `agent.prompt`, `agent.approval.respond` or `question.respond`: what the recipient sends is
    /// input the agent may act on under the agent's own permissions.
    AgentPermissions,
    /// `files.upload`, `files.apply_diff`, `project.create`, `workspace.manage` or
    /// `changeset.create`: the recipient changes files in this environment.
    EnvironmentWrites,
    /// `session.share`: the recipient can delegate what it holds to somebody else.
    Delegation,
}

impl AuthorityNotice {
    /// Every notice, in wire order.
    pub const ALL: [Self; 4] = [
        Self::AccountAccess,
        Self::AgentPermissions,
        Self::EnvironmentWrites,
        Self::Delegation,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountAccess => "account_access",
            Self::AgentPermissions => "agent_permissions",
            Self::EnvironmentWrites => "environment_writes",
            Self::Delegation => "delegation",
        }
    }

    /// The sentence a surface shows for this notice.
    ///
    /// Each one states what the upstream actually permits. None of them promises a boundary this
    /// host does not enforce.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::AccountAccess => {
                "Terminal input runs as your account. Anything this recipient types can do what \
                 you can do on this machine."
            }
            Self::AgentPermissions => {
                "Prompts, approvals and answers, including free text, are input the agent may act \
                 on under its own permissions on this machine. This is not a restricted sandbox."
            }
            Self::EnvironmentWrites => {
                "This recipient can change files and repositories in this environment."
            }
            Self::Delegation => {
                "This recipient can pass on what it holds, narrowed but never enlarged, to \
                 somebody else."
            }
        }
    }

    /// Returns the notices a set of actions carries.
    #[must_use]
    pub fn for_actions<'a>(
        actions: impl IntoIterator<Item = &'a ActionRight>,
    ) -> CanonicalSet<Self> {
        let mut notices = CanonicalSet::from_iter([]);
        for action in actions {
            match action {
                ActionRight::TerminalInput => {
                    notices.insert(Self::AccountAccess);
                }
                ActionRight::AgentPrompt
                | ActionRight::AgentApprovalRespond
                | ActionRight::QuestionRespond => {
                    notices.insert(Self::AgentPermissions);
                }
                ActionRight::FilesUpload
                | ActionRight::FilesApplyDiff
                | ActionRight::ProjectCreate
                | ActionRight::WorkspaceManage
                | ActionRight::ChangesetCreate => {
                    notices.insert(Self::EnvironmentWrites);
                }
                ActionRight::SessionShare => {
                    notices.insert(Self::Delegation);
                }
                _ => {}
            }
        }
        notices
    }
}

impl fmt::Display for AuthorityNotice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The live screen as it stands, shown to the issuer before the invitation exists.
///
/// A shared live screen can contain text printed long before the invitation, so the preview shows
/// the text rather than promising it is recent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveScreenPreview {
    /// The visible lines, top to bottom, as the recipient would first see them.
    pub lines: Vec<String>,
    /// True when the preview was cut to [`MAX_PREVIEW_LINES`] or [`MAX_PREVIEW_LINE_CHARS`].
    pub truncated: bool,
}

/// One current question an invitation names explicitly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NamedQuestionPreview {
    /// The question.
    pub question_id: QuestionId,
    /// The revision the issuer was shown.
    pub revision: QuestionRevision,
    /// The question itself.
    pub question: String,
    /// When it was created, which may be before the history cursor.
    pub created_at_ms: TimestampMs,
}

/// One current approval request an invitation names explicitly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NamedApprovalPreview {
    /// The approval request.
    pub approval_request_id: ApprovalRequestId,
    /// What the upstream is asking to do.
    pub summary: String,
    /// When it was created, which may be before the history cursor.
    pub created_at_ms: TimestampMs,
}

/// What an invitation will share, shown to its issuer before it exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InvitationPreview {
    /// The invitation this preview belongs to.
    pub invitation_id: InvitationId,
    /// The session it shares.
    pub session_id: SessionId,
    /// The environment that session lives in.
    pub environment_id: EnvironmentId,
    /// The role the issuer chose.
    pub role: SessionRole,
    /// The actions the role compiled to. The host authorises from these, never from the role.
    pub actions: CanonicalSet<ActionRight>,
    /// The history the recipient will reach.
    pub history: HistoryScope,
    /// When the invitation expires.
    pub expires_at_ms: TimestampMs,
    /// The live screen as it stands, when the issuer included it.
    pub live_screen: Nullable<LiveScreenPreview>,
    /// The current questions this invitation names.
    pub named_questions: Vec<NamedQuestionPreview>,
    /// The current approval requests this invitation names.
    pub named_approvals: Vec<NamedApprovalPreview>,
    /// The notices the actions carry.
    pub notices: CanonicalSet<AuthorityNotice>,
    /// Always false. A new recipient receives no historical attachment keys.
    pub historical_attachment_keys: bool,
    /// Always true. An invitation is redeemed once.
    pub single_use: bool,
}

/// Where an invitation is in its life.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InvitationState {
    /// Issued and not yet redeemed.
    Open,
    /// Redeemed. An invitation is single use, so nothing further can redeem it.
    Redeemed,
    /// Withdrawn by its issuer before anybody redeemed it.
    Cancelled,
    /// Its deadline passed.
    Expired,
}

impl InvitationState {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Redeemed => "redeemed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

impl fmt::Display for InvitationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Where a grant is in its life.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    /// Written down and checked, and authorising nothing until its invitation is redeemed.
    Pending,
    /// Valid now.
    Active,
    /// Its expiry passed. It never revives.
    Expired,
    /// Revoked, on its own or as the descendant of a revoked parent.
    Revoked,
}

impl GrantState {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

impl fmt::Display for GrantState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One grant as `grant.list` reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantSummary {
    /// The grant itself.
    pub grant: Grant,
    /// Where it stands now.
    pub state: GrantState,
    /// When it was revoked, when it was.
    pub revoked_at_ms: Nullable<TimestampMs>,
    /// The grant whose revocation revoked this one, when it was a descendant.
    pub revoked_by_parent: Nullable<GrantId>,
}

/// Parameters of `grant.create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantCreateParams {
    /// The session being shared.
    pub session_id: SessionId,
    /// The device the grant is issued to.
    pub recipient_device_id: DeviceId,
    /// The grant this one is delegated from. Null issues from the issuer's own authority.
    pub parent_grant_id: Nullable<GrantId>,
    /// The role and the explicit choices on top of it.
    pub selection: RoleSelection,
    /// How long the invitation lasts. Null takes [`DEFAULT_INVITATION_LIFETIME_MS`].
    pub lifetime_ms: Nullable<DurationMs>,
    /// The notices the issuer states it was shown and accepted.
    ///
    /// The host computes the notices the grant actually carries and refuses the request when the
    /// two sets differ. Section 25 makes a controller's terminal input conditional on the issuer
    /// accepting its account-level implications, and a surface that showed a softer set than the
    /// grant carries therefore cannot get the grant written.
    pub accepted_notices: CanonicalSet<AuthorityNotice>,
    /// The owner's confirmation, when the request enlarges persistent authority.
    pub owner_confirmation: Nullable<OwnerConfirmationProof>,
}

/// The result of `grant.create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantCreateResult {
    /// The grant that was written.
    pub grant: Grant,
    /// What the issuer was shown before it was written.
    pub preview: InvitationPreview,
    /// The authority revision it was issued under.
    pub authority_revision: AuthorityRevision,
}

/// Parameters of `grant.revoke`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantRevokeParams {
    /// The grant to revoke. Its descendants go with it.
    pub grant_id: GrantId,
}

/// The result of `grant.revoke` and `device.revoke`.
///
/// A revocation is not complete when the host records it. It is complete for a worker once that
/// worker has acknowledged the revision and fenced the undispatched actions it affects, or once
/// the worker is confirmed ended, so the barrier travels with the answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationResult {
    /// The revision this revocation advanced to.
    pub authority_revision: AuthorityRevision,
    /// Every grant it revoked: the named one and its descendants.
    pub revoked_grants: CanonicalSet<GrantId>,
    /// The per-worker completion status.
    pub barrier: RevocationBarrier,
}

/// Parameters of `grant.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantListParams {
    /// One session, or null for every session the caller may see.
    pub session_id: Nullable<SessionId>,
    /// Whether expired and revoked grants are included.
    pub include_resolved: bool,
}

/// The result of `grant.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantListResult {
    /// The grants, ordered by identity.
    pub grants: Vec<GrantSummary>,
}

/// Parameters of `device.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceListParams {
    /// Whether revoked devices are included.
    pub include_revoked: bool,
}

/// One paired device as `device.list` reports it.
///
/// Section 10 puts each host's last acknowledgement in the device list, because an offline host
/// cannot apply a revocation it has not received and the person has to be able to see that.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceSummary {
    /// The device.
    pub device_id: DeviceId,
    /// The name it was paired under.
    pub display_name: String,
    /// The grant it holds.
    pub grant_id: GrantId,
    /// When it was paired.
    pub paired_at_ms: TimestampMs,
    /// The last authority revision this device acknowledged.
    pub acknowledged_revision: Nullable<AuthorityRevision>,
    /// When that acknowledgement arrived.
    pub acknowledged_at_ms: Nullable<TimestampMs>,
    /// Whether the device has been revoked.
    pub revoked: bool,
    /// The device's four purpose-separated public keys, as its pairing bound them.
    ///
    /// Null for a device paired before this host kept all four, until it declares the rest through
    /// `device.keys.complete`. Another device seals to a device's stored-envelope key only when this
    /// host reports it, because the pairing the owner approved is what binds it to the device.
    pub keys: Nullable<crate::pairing::DevicePublicKeys>,
    /// Whether the device's grant lets it manage this host, which is what an owner's device holds.
    pub manages_host: bool,
}

/// The result of `device.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceListResult {
    /// The devices, ordered by identity.
    pub devices: Vec<DeviceSummary>,
    /// The revision in force when the list was taken.
    pub authority_revision: AuthorityRevision,
    /// The last time this host synchronised the remote authority feed, when it has.
    pub feed_synchronised_at_ms: Nullable<TimestampMs>,
    /// True when the feed is unreachable, so the revocation status shown is stale.
    pub feed_stale: bool,
}

/// Parameters of `device.revoke`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceRevokeParams {
    /// The device to revoke. Every grant it holds goes with it.
    pub device_id: DeviceId,
}

/// Parameters of `device.preview_key.update`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DevicePreviewKeyUpdateParams {
    /// The device rotating its key. A device may rotate only its own.
    pub device_id: DeviceId,
    /// The new notification-preview public key.
    pub notification_preview: crate::scalars::NotificationPreviewKey,
    /// The key revision.
    #[serde(default)]
    pub revision: DeviceKeyRevision,
}

/// The result of `device.preview_key.update`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DevicePreviewKeyUpdateResult {
    /// The device whose key changed.
    pub device_id: DeviceId,
    /// The key revision now on record.
    #[serde(default)]
    pub revision: DeviceKeyRevision,
    /// The key now on record.
    pub notification_preview: crate::scalars::NotificationPreviewKey,
}

/// The domain a device's declaration of its own public keys is signed under.
pub const DEVICE_KEYS_DOMAIN: &str = "kr-device-keys/1";

/// What a device signs to declare its four public keys to a host that recorded only two of them.
///
/// A device paired before its host kept every key declares the rest once. The declaration names
/// the device and all four keys, and it is signed by the authorisation key the host recorded at
/// pairing, which is what binds the new keys to the device the owner approved: the same binding the
/// signed bundle gave the keys the host did record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceKeysDeclaration {
    /// The device, as the host named it when it committed the pairing.
    pub device_id: DeviceId,
    /// All four of the device's public keys.
    pub keys: crate::pairing::DevicePublicKeys,
}

impl DeviceKeysDeclaration {
    /// Builds the canonical bytes the signature covers: `CBOR(["kr-device-keys/1", declaration])`.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the declaration cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, kr_cbor::CborError> {
        Ok(kr_cbor::encode(&kr_cbor::signing_value(
            DEVICE_KEYS_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }
}

/// Parameters of `device.keys.complete`.
///
/// The device is the one the connection authenticated as; the parameters name nothing else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceKeysCompleteParams {
    /// All four of the device's public keys. The two the host recorded at pairing must be among
    /// them unchanged.
    pub keys: crate::pairing::DevicePublicKeys,
    /// The Ed25519 signature over [`DeviceKeysDeclaration::signing_input`], by the authorisation
    /// key the host recorded for this device.
    pub signature: crate::scalars::Signature64,
}

/// The result of `device.keys.complete`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceKeysCompleteResult {
    /// The device whose keys are on record.
    pub device_id: DeviceId,
    /// The four keys now on record.
    pub keys: crate::pairing::DevicePublicKeys,
}

/// Why a host would not answer under an organisation's authority.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MembershipRefusal {
    /// The host holds no lease for that organisation at all.
    NoLease,
    /// The lease this host holds has expired. A connected transport does not extend it.
    LeaseExpired,
    /// The lease is for another organisation, or was signed under a policy revision this host has
    /// not pinned.
    WrongAuthority,
}

impl MembershipRefusal {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoLease => "no_lease",
            Self::LeaseExpired => "lease_expired",
            Self::WrongAuthority => "wrong_authority",
        }
    }
}

impl fmt::Display for MembershipRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A host owner's bounded offline-validity policy for personal remote access.
///
/// Section 10 makes this optional and explicit. The default personal owner grant stays
/// account-free and non-expiring, so independent operation never depends on a cloud lease; an
/// owner who wants a bound chooses one, and the host shows the feed status and the last successful
/// synchronisation beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfflineValidityPolicy {
    /// How long personal remote access stays valid without a successful authority-feed
    /// synchronisation.
    pub maximum_offline_ms: DurationMs,
    /// The last successful synchronisation, when there has been one.
    pub last_synchronised_at_ms: Nullable<TimestampMs>,
}

impl OfflineValidityPolicy {
    /// Returns true when personal remote access is still inside the bound at `now_ms`.
    ///
    /// A policy that has never synchronised is outside its bound from the moment it is chosen:
    /// there is no successful synchronisation to measure from, and treating that as unlimited
    /// would make the policy mean nothing.
    #[must_use]
    pub fn is_inside_bound(&self, now_ms: u64) -> bool {
        self.last_synchronised_at_ms
            .as_ref()
            .is_some_and(|last| now_ms <= last.get().saturating_add(self.maximum_offline_ms.get()))
    }
}

/// What this host shows about the remote authority feed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorityFeedStatus {
    /// The latest revision this host has accepted. It never goes backwards.
    pub accepted_revision: AuthorityRevision,
    /// The last successful synchronisation, when there has been one.
    pub last_synchronised_at_ms: Nullable<TimestampMs>,
    /// True when the feed could not be reached, so what is shown is stale.
    pub stale: bool,
    /// How many retained revocation records have not yet been acknowledged by every enrolled host.
    pub unacknowledged_records: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_controller_and_owner_answer_questions_by_default() {
        for role in SessionRole::ALL {
            let carries = role
                .default_actions()
                .contains(&ActionRight::QuestionRespond);
            assert_eq!(
                carries,
                role.responds_to_questions_by_default(),
                "{role} disagrees with its own default action list"
            );
        }
        assert!(!SessionRole::Viewer.responds_to_questions_by_default());
        assert!(!SessionRole::Reviewer.responds_to_questions_by_default());
        assert!(SessionRole::Controller.responds_to_questions_by_default());
        assert!(SessionRole::Owner.responds_to_questions_by_default());
    }

    #[test]
    fn each_role_carries_everything_the_role_below_it_carries() {
        for pair in SessionRole::ALL.windows(2) {
            let (lower, higher) = (pair[0], pair[1]);
            for right in lower.default_actions() {
                assert!(
                    higher.default_actions().contains(right),
                    "{higher} drops {right}, which {lower} carries"
                );
            }
        }
    }

    #[test]
    fn a_viewer_receives_question_respond_only_when_the_issuer_asks_for_it() {
        let plain = RoleSelection::plain(SessionRole::Viewer);
        assert!(!plain.actions().contains(&ActionRight::QuestionRespond));

        let opted = RoleSelection {
            include_question_respond: true,
            ..RoleSelection::plain(SessionRole::Viewer)
        };
        assert!(opted.actions().contains(&ActionRight::QuestionRespond));
        assert!(
            AuthorityNotice::for_actions(&opted.actions())
                .contains(&AuthorityNotice::AgentPermissions),
            "the option carries the notice that explains what an answer is"
        );
    }

    #[test]
    fn a_plain_selection_adds_no_history_and_no_live_screen() {
        let history = RoleSelection::plain(SessionRole::Reviewer).history();
        assert!(!history.include_live_screen);
        assert!(history.lower_bound_ms.as_ref().is_none());
        assert!(history.named_questions.is_empty());
        assert!(history.named_approvals.is_empty());
    }

    #[test]
    fn terminal_input_always_carries_the_account_notice() {
        let notices = AuthorityNotice::for_actions(&[ActionRight::TerminalInput]);
        assert!(notices.contains(&AuthorityNotice::AccountAccess));
        assert!(
            AuthorityNotice::AccountAccess
                .sentence()
                .contains("runs as your account")
        );
    }

    #[test]
    fn an_offline_policy_that_never_synchronised_is_outside_its_bound() {
        let policy = OfflineValidityPolicy {
            maximum_offline_ms: DurationMs::new(1_000),
            last_synchronised_at_ms: Nullable::null(),
        };
        assert!(!policy.is_inside_bound(0));

        let synchronised = OfflineValidityPolicy {
            maximum_offline_ms: DurationMs::new(1_000),
            last_synchronised_at_ms: Nullable::some(TimestampMs::new(10_000)),
        };
        assert!(synchronised.is_inside_bound(11_000));
        assert!(!synchronised.is_inside_bound(11_001));
    }

    #[test]
    fn every_role_and_notice_resolves_from_its_own_wire_string() {
        for role in SessionRole::ALL {
            assert_eq!(SessionRole::from_wire(role.as_str()), Some(role));
        }
        for notice in AuthorityNotice::ALL {
            assert_eq!(
                serde_json::to_value(notice).expect("a notice encodes"),
                serde_json::Value::String(notice.as_str().to_owned())
            );
        }
    }
}
