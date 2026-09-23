//! Voice: the six method shapes, the voice grant's vocabulary and the voice confirmation.
//!
//! Section 15 puts the coordinator on the host. The native client owns capture and playback, the
//! managed broker owns the provider session and the money, and what travels between them is the
//! six methods this module gives shapes to.
//!
//! Three rules decide nearly everything here.
//!
//! * **Content is never authority** (section 19). A provider delegation identifier is correlation
//!   data, a transcript is data, and a model statement that somebody agreed to something is data
//!   too. [`VoiceDelegateParams`] therefore carries an identifier and a timeline offset and has no
//!   field for task text, and [`VoiceConfirmationProof`] is a signature by the paired device's
//!   identity key, which no amount of provider text can produce.
//! * **A voice session is not a terminal session.** [`VoiceSessionId`] is its own identity, and
//!   stopping one leaves the terminal sessions it reached running.
//!
//!   [`VoiceSessionId`]: crate::ids::VoiceSessionId
//! * **`creation_unknown` is a resource state, not an error spelling** (section 23). A start that
//!   the broker could not resolve answers [`VoiceStartResult`] with
//!   [`VoiceStartOutcome::CreationUnknown`], which carries the attempt the host may ask about
//!   later. Nothing retries it.
//!
//! # The voice grant
//!
//! [`VoiceAction`] is the vocabulary section 15 ¶13 states: what the default grant permits, what
//! needs a spoken confirmation naming the destination session, and what needs a confirmation on an
//! unlocked screen. Each action names the ordinary [`ActionRight`] the host already checks for the
//! same effect, so speaking never reaches an effect typing could not.
//!
//! The grant itself is an ordinary [`Grant`](crate::grant::Grant) in the host's one authority
//! store. There is no second store, and no state in this module is authority.

use core::fmt;
use core::str::FromStr;

use kr_cbor::CborError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{
    ActionId, AgentTurnId, ApprovalRequestId, ConfirmationId, DeviceId, GrantId, SessionId,
    VoiceSessionId,
};
use crate::rights::ActionRight;
use crate::scalars::{
    CanonicalSet, Digest256, KeyId, Nonce256, Nullable, Signature64, TimestampMs, U64,
};

/// The domain a voice confirmation's signature covers.
pub const VOICE_CONFIRM_DOMAIN: &str = "kr-voice/confirm/1";

/// The domain a voice action digest covers.
pub const VOICE_ACTION_DOMAIN: &str = "kr-voice/action/1";

/// Largest number of text tokens the default context may carry (section 15 ¶12).
pub const VOICE_CONTEXT_TOKEN_CAP: u32 = 8_000;

/// How many semantic messages the default context carries (section 15 ¶12).
pub const VOICE_CONTEXT_MESSAGE_COUNT: u32 = 20;

/// Largest append, in UTF-8 bytes, the managed broker carries in one context request.
///
/// The broker counts bytes because it cannot count the provider's tokens, and section 15 ¶9 bounds
/// an append at 500 provider tokens. Under a byte-level encoder a string of this many bytes is at
/// most that many tokens. The bound is stated here so a host result is cut to something the broker
/// will carry rather than being refused after it was built.
pub const VOICE_APPEND_BYTES: usize = 500;

/// How long a voice confirmation challenge stays open, in milliseconds.
///
/// The same two minutes the owner-confirmation ceremony uses: long enough for a ceremony on an
/// unlocked device, short enough that a challenge captured now is useless later.
pub const VOICE_CONFIRMATION_LIFETIME_MS: u64 = 2 * 60 * 1000;

/* -------------------------------------------------------------------------- */
/* What a voice grant permits                                                  */
/* -------------------------------------------------------------------------- */

/// One thing a voice session may ask the host to do.
///
/// Section 15 ¶13 divides these three ways, and the divisions are the methods on this type rather
/// than rules restated at each call site:
///
/// * the default grant permits session navigation, status queries, briefing and prompt
///   composition, and nothing else ([`Self::in_default_scope`]);
/// * submitting a prompt requires a clear spoken confirmation naming the destination session
///   ([`Self::needs_spoken_destination`]), and an approval decision requires the verified
///   request's details and an explicit answer ([`Self::needs_verified_request`]);
/// * session closure, grant changes, arbitrary shell input, diff application and external
///   delivery require a confirmation on an unlocked screen ([`Self::needs_unlocked_screen`]).
///
/// [`Self::required_right`] is the other half: every voice action names the ordinary right the
/// host already checks for the same effect, so a voice grant can never reach an effect the device
/// could not reach by typing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VoiceAction {
    /// Move between the sessions the grant covers.
    Navigate,
    /// Read a session's current status.
    Status,
    /// Hear a briefing built from the selected context.
    Brief,
    /// Compose a prompt without submitting it.
    ComposePrompt,
    /// Submit a composed prompt to a named session.
    SubmitPrompt,
    /// Answer an approval request the host has verified and read out.
    AnswerApproval,
    /// Cancel the upstream agent's current turn.
    CancelTurn,
    /// Close a session.
    CloseSession,
    /// Create or change a grant.
    ChangeGrant,
    /// Send arbitrary bytes to a terminal.
    ShellInput,
    /// Apply or revert a diff.
    ApplyDiff,
    /// Deliver content to an external destination.
    DeliverExternally,
}

impl VoiceAction {
    /// Every voice action, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Navigate,
        Self::Status,
        Self::Brief,
        Self::ComposePrompt,
        Self::SubmitPrompt,
        Self::AnswerApproval,
        Self::CancelTurn,
        Self::CloseSession,
        Self::ChangeGrant,
        Self::ShellInput,
        Self::ApplyDiff,
        Self::DeliverExternally,
    ];

    /// The five classes section 15 ¶13 puts behind a confirmation on an unlocked screen.
    pub const UNLOCKED_SCREEN: &'static [Self] = &[
        Self::CloseSession,
        Self::ChangeGrant,
        Self::ShellInput,
        Self::ApplyDiff,
        Self::DeliverExternally,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Navigate => "navigate",
            Self::Status => "status",
            Self::Brief => "brief",
            Self::ComposePrompt => "compose_prompt",
            Self::SubmitPrompt => "submit_prompt",
            Self::AnswerApproval => "answer_approval",
            Self::CancelTurn => "cancel_turn",
            Self::CloseSession => "close_session",
            Self::ChangeGrant => "change_grant",
            Self::ShellInput => "shell_input",
            Self::ApplyDiff => "apply_diff",
            Self::DeliverExternally => "deliver_externally",
        }
    }

    /// Returns the action for a wire string.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|action| action.as_str() == value)
    }

    /// Returns true when the default voice grant permits this action.
    ///
    /// Section 15 ¶13's four, and nothing else. Anything further is something a person chooses in
    /// settings, and the change states which actions it permits.
    #[must_use]
    pub const fn in_default_scope(self) -> bool {
        matches!(
            self,
            Self::Navigate | Self::Status | Self::Brief | Self::ComposePrompt
        )
    }

    /// The ordinary action right the host checks for the same effect.
    ///
    /// `None` means this release has no host method that carries the effect, so no grant can
    /// carry it either. External delivery is that case: section 15 ¶13 names it among the actions
    /// that need a confirmation on an unlocked screen, so it is in this vocabulary rather than
    /// absent from it, and a coordinator that can name a class is a coordinator that cannot let
    /// the class arrive under a neighbouring name.
    #[must_use]
    pub const fn required_right(self) -> Option<ActionRight> {
        match self {
            // Navigating, reading status, hearing a briefing and composing a draft are all reads
            // of a session the grant already covers.
            Self::Navigate | Self::Status | Self::Brief | Self::ComposePrompt => {
                Some(ActionRight::SessionView)
            }
            Self::SubmitPrompt => Some(ActionRight::AgentPrompt),
            Self::AnswerApproval => Some(ActionRight::AgentApprovalRespond),
            Self::CancelTurn => Some(ActionRight::AgentCancel),
            Self::CloseSession => Some(ActionRight::SessionClose),
            Self::ChangeGrant => Some(ActionRight::SessionShare),
            Self::ShellInput => Some(ActionRight::TerminalInput),
            Self::ApplyDiff => Some(ActionRight::FilesApplyDiff),
            Self::DeliverExternally => None,
        }
    }

    /// Returns true when section 15 ¶13 requires a confirmation on an unlocked screen.
    #[must_use]
    pub const fn needs_unlocked_screen(self) -> bool {
        matches!(
            self,
            Self::CloseSession
                | Self::ChangeGrant
                | Self::ShellInput
                | Self::ApplyDiff
                | Self::DeliverExternally
        )
    }

    /// Returns true when section 15 ¶13 requires a clear spoken confirmation naming the
    /// destination session.
    #[must_use]
    pub const fn needs_spoken_destination(self) -> bool {
        matches!(self, Self::SubmitPrompt)
    }

    /// Returns true when section 15 ¶13 requires the verified request's details and an explicit
    /// answer.
    #[must_use]
    pub const fn needs_verified_request(self) -> bool {
        matches!(self, Self::AnswerApproval)
    }

    /// The sentence a grant change states about this action.
    ///
    /// Section 15 ¶13: a person broadening their own voice grant is told which actions it permits,
    /// so the sentences live beside the vocabulary rather than in whichever surface writes them.
    #[must_use]
    pub const fn statement(self) -> &'static str {
        match self {
            Self::Navigate => "Move between the sessions this grant covers.",
            Self::Status => "Read what a session is doing.",
            Self::Brief => "Hear a briefing built from the selected context.",
            Self::ComposePrompt => "Compose a prompt without submitting it.",
            Self::SubmitPrompt => {
                "Submit a composed prompt, after a spoken confirmation that names the destination \
                 session."
            }
            Self::AnswerApproval => {
                "Answer an approval request, after its verified details and an explicit answer."
            }
            Self::CancelTurn => "Cancel the agent's current turn. It does not stop playback.",
            Self::CloseSession => "Close a session, after a confirmation on an unlocked screen.",
            Self::ChangeGrant => "Change a grant, after a confirmation on an unlocked screen.",
            Self::ShellInput => {
                "Send arbitrary input to a terminal, after a confirmation on an unlocked screen."
            }
            Self::ApplyDiff => "Apply a diff, after a confirmation on an unlocked screen.",
            Self::DeliverExternally => {
                "Deliver content outside this host, after a confirmation on an unlocked screen."
            }
        }
    }

    /// The default voice scope of section 15 ¶13.
    #[must_use]
    pub fn default_scope() -> CanonicalSet<Self> {
        Self::ALL
            .iter()
            .copied()
            .filter(|action| action.in_default_scope())
            .collect()
    }

    /// The rights a grant permitting `actions` has to carry, beside [`ActionRight::VoiceUse`].
    #[must_use]
    pub fn rights_for(actions: &CanonicalSet<Self>) -> CanonicalSet<ActionRight> {
        let mut rights: CanonicalSet<ActionRight> =
            core::iter::once(ActionRight::VoiceUse).collect();
        for action in actions.iter() {
            if let Some(right) = action.required_right() {
                rights.insert(right);
            }
        }
        rights
    }
}

/// Ordered by the wire string, so a set of actions encodes in an order a reader can verify from
/// the encoded values alone rather than from this file's declaration order.
impl Ord for VoiceAction {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for VoiceAction {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for VoiceAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A wire string that is not a voice action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownVoiceAction;

impl fmt::Display for UnknownVoiceAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown voice action")
    }
}

impl std::error::Error for UnknownVoiceAction {}

impl FromStr for VoiceAction {
    type Err = UnknownVoiceAction;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_wire(value).ok_or(UnknownVoiceAction)
    }
}

/// What a voice grant permits, as the person who chose it is told.
///
/// Section 15 ¶13: "the change must state which actions it permits". The statement is computed
/// from the action set rather than written beside it, so a grant and its description cannot drift.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceGrantStatement {
    /// The actions the grant permits.
    pub actions: CanonicalSet<VoiceAction>,
    /// One sentence per action, in the order the actions are listed.
    pub statements: Vec<String>,
    /// The actions that still need a confirmation on an unlocked screen every time they are used.
    ///
    /// Holding the action in the grant is not holding the confirmation. Section 15 ¶8 makes them
    /// two separate things, and this field says so where the person reads the grant.
    pub unlocked_screen_actions: CanonicalSet<VoiceAction>,
}

impl VoiceGrantStatement {
    /// Builds the statement for one action set.
    #[must_use]
    pub fn of(actions: &CanonicalSet<VoiceAction>) -> Self {
        Self {
            actions: actions.clone(),
            statements: actions
                .iter()
                .map(|action| action.statement().to_owned())
                .collect(),
            unlocked_screen_actions: actions
                .iter()
                .copied()
                .filter(|action| action.needs_unlocked_screen())
                .collect(),
        }
    }
}

/* -------------------------------------------------------------------------- */
/* The confirmation                                                            */
/* -------------------------------------------------------------------------- */

/// A host-issued challenge for one voice action that needs an unlocked screen.
///
/// This is not a [`SensitiveAction`](crate::pairing::SensitiveAction). The owner-confirmation
/// ceremony of section 10 confirms a change to persistent authority; this confirms one action of
/// one voice session, and binding it to the exact action hash and the current request is what
/// stops a confirmation for one action authorising another.
///
/// Everything the host relies on is inside the signed bytes. A field beside an unsigned signature
/// would be the signer's unauthenticated claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceConfirmationRequest {
    /// The challenge identity. Single use.
    pub confirmation_id: ConfirmationId,
    /// The voice session the action belongs to.
    pub voice_session_id: VoiceSessionId,
    /// The class of action being confirmed.
    pub action: VoiceAction,
    /// The digest of the exact action. One confirmation authorises one digest.
    pub action_digest: Digest256,
    /// The request this confirmation is for. One confirmation authorises one request.
    pub action_id: ActionId,
    /// The host that issued the challenge.
    pub host_device_id: DeviceId,
    /// The paired device that must sign it, with the identity key that signs its
    /// authority-bearing requests. Never a session key.
    pub device_id: DeviceId,
    /// The host's fresh challenge nonce.
    pub nonce: Nonce256,
    /// The short expiry, in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
}

impl VoiceConfirmationRequest {
    /// Builds the canonical bytes a voice confirmation proof signs.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the request cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&kr_cbor::signing_value(
            VOICE_CONFIRM_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }
}

/// The paired device's answer to a voice confirmation challenge.
///
/// The ceremony that produces it is the native client's: device-owner authentication on an
/// unlocked screen. What the host verifies is this object, and a model statement that the user
/// agreed to something cannot produce one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceConfirmationProof {
    /// The challenge this proof answers, byte for byte.
    pub request: VoiceConfirmationRequest,
    /// The key identifier of the device identity key that produced it.
    pub signer_key_id: KeyId,
    /// The Ed25519 signature over `CBOR(["kr-voice/confirm/1", request])`.
    pub signature: Signature64,
}

/// What a voice action is hashed over, so one confirmation authorises one action.
///
/// The digest is built from the plan rather than from the challenge: a challenge that carried the
/// only copy of what was agreed to would be a challenge an attacker could rewrite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceActionPlan {
    /// The voice session proposing it.
    pub voice_session_id: VoiceSessionId,
    /// The class of action.
    pub action: VoiceAction,
    /// The session it acts on, when it acts on one.
    pub session_id: Nullable<SessionId>,
    /// The delegation it was interpreted from, when a delegation caused it.
    pub delegation_id: Nullable<VoiceDelegationId>,
    /// The exact parameters, canonically encoded by the caller that proposes them.
    ///
    /// Opaque bytes here: this module hashes what the host will perform rather than restating each
    /// method's shape a second time.
    pub payload_digest: Digest256,
}

impl VoiceActionPlan {
    /// The digest a confirmation binds to.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the plan cannot be represented in KR-CBOR-1.
    pub fn digest(&self) -> Result<Digest256, CborError> {
        Ok(Digest256::from_bytes(kr_cbor::sha256(&kr_cbor::encode(
            &kr_cbor::signing_value(
                VOICE_ACTION_DOMAIN,
                vec![kr_cbor::to_canonical_value(self)?],
            ),
        ))))
    }
}

/* -------------------------------------------------------------------------- */
/* Delegation                                                                  */
/* -------------------------------------------------------------------------- */

/// Largest length, in bytes, of a provider delegation identifier this host will hold.
pub const MAX_DELEGATION_ID_LEN: usize = 128;

/// A provider delegation identifier, exactly as the provider wrote it.
///
/// Correlation data and nothing else. It is returned unchanged and never parsed: the provider
/// profile records an `item_` prefix and says to return it unchanged, and a host that read meaning
/// out of it would be reading a value the provider chose. It is bounded so a peer cannot force an
/// unbounded allocation through a field that means nothing to this host.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct VoiceDelegationId(String);

impl VoiceDelegationId {
    /// Wraps a provider identifier, rejecting an empty, over-long or control-bearing value.
    ///
    /// # Errors
    ///
    /// Returns [`DelegationIdError`] when the text is empty, longer than
    /// [`MAX_DELEGATION_ID_LEN`] bytes or contains a control character.
    pub fn new(value: impl Into<String>) -> Result<Self, DelegationIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DelegationIdError(
                "a delegation identifier must not be empty",
            ));
        }
        if value.len() > MAX_DELEGATION_ID_LEN {
            return Err(DelegationIdError(
                "a delegation identifier is at most 128 bytes",
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(DelegationIdError(
                "a delegation identifier must not contain control characters",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the identifier exactly as the provider wrote it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VoiceDelegationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A delegation identifier that is empty, too long or carries a control character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationIdError(&'static str);

impl fmt::Display for DelegationIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for DelegationIdError {}

impl FromStr for VoiceDelegationId {
    type Err = DelegationIdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

impl<'de> Deserialize<'de> for VoiceDelegationId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for VoiceDelegationId {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "VoiceDelegationId".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::VoiceDelegationId".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_DELEGATION_ID_LEN,
            "description": "An opaque provider delegation identifier. Correlation data, never authority."
        })
    }
}

/* -------------------------------------------------------------------------- */
/* voice.grant                                                                 */
/* -------------------------------------------------------------------------- */

/// Parameters of `voice.grant`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceGrantParams {
    /// The device whose voice grant this is. A device broadening its own names itself; naming
    /// another device is a host-management change.
    pub device_id: DeviceId,
    /// The sessions the grant covers. Empty covers every session the device's own grant covers.
    pub session_ids: CanonicalSet<SessionId>,
    /// The actions to permit. Absent takes the default scope of section 15 ¶13.
    pub actions: Nullable<CanonicalSet<VoiceAction>>,
}

/// The result of `voice.grant`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceGrantResult {
    /// The grant that was written, in the host's one authority store.
    pub grant_id: GrantId,
    /// The device it was issued to.
    pub device_id: DeviceId,
    /// What it permits, stated action by action.
    pub statement: VoiceGrantStatement,
    /// Actions the request asked for that the device's own grant does not carry.
    ///
    /// A voice grant is intersected with the device's ordinary grant, so asking for more than the
    /// device holds narrows rather than enlarges. Naming what was dropped is what stops a person
    /// believing they granted something they did not.
    pub not_held_by_device: CanonicalSet<VoiceAction>,
}

/* -------------------------------------------------------------------------- */
/* voice.prepare                                                               */
/* -------------------------------------------------------------------------- */

/// Parameters of `voice.prepare`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoicePrepareParams {
    /// The sessions a call would be asked to reach. Empty asks about every session the grant
    /// covers.
    pub session_ids: CanonicalSet<SessionId>,
    /// Content classes the person has selected on top of the default, as they would be at start.
    pub selected: CanonicalSet<VoiceContextClass>,
}

/// What `voice.prepare` answered: what a call started now would be, before one exists.
///
/// Section 15 ¶12 asks for the provider and the selected context scope to be shown **before**
/// voice starts. The only other read of the voice surface, [`VoiceContextParams`], names a voice
/// session, and `voice.start` has already created the metered provider session by the time its
/// descriptor carries this. So the answer a person reads before deciding has to come from
/// somewhere that creates nothing, and this is it: no provider session, no reservation, no grant
/// and no context leaves the host for this read.
///
/// Two sources, kept apart. The scope is this host's: its grants, its selection and its cap. What
/// the managed service would do with a call is the service's, read from it for this answer and
/// carried in [`Self::managed`] in its own words, so a person is shown the model, the disclosure,
/// the rate and the limits the deployment publishes rather than a copy this host keeps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoicePrepareResult {
    /// The sessions a call started now could reach.
    ///
    /// The intersection of what was asked for with what the voice grant and the device's own grant
    /// carry, so a person reads the scope they would get rather than the one they requested.
    pub session_ids: CanonicalSet<SessionId>,
    /// What a call started now would be permitted to do, action by action.
    pub statement: VoiceGrantStatement,
    /// Classes the default context leaves out unless the person selects them (section 15 ¶12).
    pub excluded: CanonicalSet<VoiceContextClass>,
    /// Classes from the request that would actually be carried.
    ///
    /// A selection the grant does not reach is absent here rather than refused, because this read
    /// exists to show a person what a call would be before they make one.
    pub selected: CanonicalSet<VoiceContextClass>,
    /// The host's cap on selected context, in text tokens.
    pub token_cap: u32,
    /// How many semantic messages the default context carries.
    pub message_count: u32,
    /// The origin of the managed service a call would be brokered through.
    pub broker_origin: String,
    /// A digest of what a call started now would be bound to: the sessions it would reach, what
    /// it would be permitted to do, and the provider that would carry it.
    ///
    /// A start names it. When what a start would be bound to is no longer what this digest
    /// describes, because a grant changed or another provider was attached, the start is refused
    /// as [`VoiceStartOutcome::PreparationChanged`] before anything is created, so a call never
    /// reaches further than what the person was shown.
    pub prepared: Digest256,
    /// What the managed service answered about a call started now.
    ///
    /// Null for a provider that is not the managed service, and when this host could not read the
    /// service's terms; [`Self::managed_unavailable`] then says which. A managed call is not
    /// offered without these terms, because a start names the rate version a person was shown
    /// and a person shown no rate has accepted none.
    pub managed: Nullable<VoiceManagedTerms>,
    /// Why a managed call cannot start from here, in words a person can act on.
    ///
    /// Present exactly when [`Self::managed`] is null.
    pub managed_unavailable: Nullable<String>,
}

/// What the managed service publishes about a call started now, carried in its own words.
///
/// The service answers this without creating anything, and every value in it is the deployment's
/// own configuration or a constant of its contract. The wordings are carried verbatim: the
/// disclosure a person reads is the list the deployment publishes, not a second list this host
/// keeps beside it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceManagedTerms {
    /// Whether an operator has managed voice open.
    ///
    /// False is the operator's circuit breaker: a call started now would be refused, and
    /// [`Self::alternatives`] is what still works.
    pub enabled: bool,
    /// The model a call started now would be asked for.
    pub model: String,
    /// What the provider and the managed service can see, stated where the choice is made.
    pub disclosure: Vec<String>,
    /// What an append acknowledgement establishes, and what it does not (section 15 ¶10).
    pub admission_note: String,
    /// What a provider delegation identifier is, and what it is not.
    pub delegation_note: String,
    /// Paths that cost no managed credit.
    pub alternatives: Vec<String>,
    /// The rate a call started now would be quoted under.
    pub rate: VoiceRate,
    /// The longest call the service authorises, in seconds.
    pub maximum_session_seconds: u32,
    /// The shortest call a start may ask for, in seconds.
    pub minimum_request_seconds: u32,
    /// Seconds between heartbeats on the control socket.
    pub heartbeat_seconds: u32,
    /// The largest context append the service carries, in UTF-8 bytes.
    pub context_bytes: u32,
}

/// The managed rate, as the service quoted it.
///
/// A start names [`Self::version`], and the service compares it with the rate it would charge: a
/// version that is no longer current is refused as [`VoiceStartOutcome::RateChanged`] with the
/// rate as it is now, before anything is held or charged. So a call runs under the terms the
/// person was shown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRate {
    /// The version of the rate table the quote is made under. Opaque, and compared exactly.
    pub version: String,
    /// Minor units of [`Self::currency`] charged per second of call.
    pub minor_units_per_second: U64,
    /// The shortest duration the provider sells, charged whatever the call did, in seconds.
    pub minimum_seconds: u32,
    /// The ISO 4217 code the amounts are in, as the service wrote it.
    pub currency: String,
}

/* -------------------------------------------------------------------------- */
/* voice.start                                                                 */
/* -------------------------------------------------------------------------- */

/// Parameters of `voice.start`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceStartParams {
    /// The sessions this voice session may reach. Empty takes every session the voice grant covers.
    pub session_ids: CanonicalSet<SessionId>,
    /// The caller's own SDP offer, as its WebRTC stack produced it.
    ///
    /// The host forwards it to the managed broker unchanged and terminates no media: audio flows
    /// between the device and the provider. The host never generates an offer of its own.
    pub offer_sdp: String,
    /// Seconds of call the caller is asking to be authorised for.
    pub duration_seconds: u32,
    /// Minor units to hold for reasoning and tools, held separately from the call.
    pub reasoning_budget_minor: Nullable<U64>,
    /// The preparation the person was shown, as `voice.prepare` answered it.
    ///
    /// The host refuses a start whose preparation no longer describes what it would be bound to,
    /// before the provider is asked for anything.
    pub prepared: Digest256,
    /// The version of the managed rate the person was shown, as `voice.prepare` answered it.
    ///
    /// A managed call names it, and the host passes it on unchanged. A version that is no longer
    /// current is refused as [`VoiceStartOutcome::RateChanged`] with the rate as it is now, so a
    /// call never runs under terms the person was not shown. A provider that is not the managed
    /// service quotes no rate, and a start through one names none.
    pub expected_rate_version: Nullable<String>,
}

/// What `voice.start` answered.
///
/// Three outcomes, because three things can be true and only one of them is a running call.
/// Section 23 makes `creation_unknown` a typed resource state with its own result schema rather
/// than an error-code spelling, and this is that schema.
///
/// The outcome names itself the way every other variant union in this protocol does: the name is
/// the key and the payload is under it. A tag inside the payload would be read by buffering the
/// whole value first, and a buffered value loses the binary form every identifier in this protocol
/// travels as, so an answer carrying one could be written and never read back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum VoiceStartOutcome {
    /// A call is running.
    Started {
        /// Everything the device needs to use it.
        session: Box<VoiceSessionDescriptor>,
    },
    /// The broker could not tell whether the provider created a session.
    ///
    /// No SDP answer exists for that attempt, nothing is retried, and the reservation is the
    /// broker's to reconcile. The voice session and its grant are not created.
    CreationUnknown {
        /// The creation attempt, for a later reconciliation to name.
        attempt_id: String,
        /// What a person is told. Never a provider credential and never a blame of the host.
        message: String,
    },
    /// Managed voice could not be started, and what still works.
    Unavailable {
        /// The broker's own reason, in its vocabulary.
        reason: String,
        /// What a person is told.
        message: String,
        /// Paths that still work. A voice session stopping leaves the agent running.
        alternatives: Vec<String>,
    },
    /// What the call would be bound to is no longer what the preparation the start named described.
    ///
    /// A grant changed, or another provider was attached, after the person was shown the
    /// preparation. Nothing was created or asked of the provider; the person reads the preparation
    /// again before starting.
    PreparationChanged {
        /// What a person is told.
        message: String,
    },
    /// The managed rate is no longer the version the start named.
    ///
    /// Nothing was created, held or charged, and the voice session and its grant do not exist.
    /// `rate` is the rate a call started now would run under: a person who accepts it starts again
    /// naming its version.
    RateChanged {
        /// The rate as the service quotes it now.
        rate: VoiceRate,
        /// What a person is told, in the service's words.
        message: String,
    },
}

/// The result of `voice.start`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceStartResult {
    /// Which of the three outcomes happened.
    pub outcome: VoiceStartOutcome,
}

/// A running voice session, as the paired device needs to see it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceSessionDescriptor {
    /// The host's identity for this voice session.
    pub voice_session_id: VoiceSessionId,
    /// The session-bound voice grant this session runs under. Stopping revokes it.
    pub grant_id: GrantId,
    /// What that grant permits, stated action by action.
    pub statement: VoiceGrantStatement,
    /// The sessions this voice session may reach.
    pub session_ids: CanonicalSet<SessionId>,
    /// The broker's identifier for the call. The control socket is addressed by it.
    pub call_id: String,
    /// The provider's own session identifier. Opaque; never parsed or constructed.
    pub provider_session_id: String,
    /// The provider's SDP answer, to be applied to the caller's own connection.
    pub answer_sdp: String,
    /// The model the call is running on.
    pub model: String,
    /// Path on the broker's origin the control socket is opened on.
    pub control_path: String,
    /// The broker's origin, so the device does not have to be configured with it separately.
    pub broker_origin: String,
    /// Seconds between heartbeats the device is expected to send.
    pub heartbeat_seconds: u32,
    /// When the broker closes the call, whatever else happens, in UTC milliseconds.
    pub closes_at_ms: TimestampMs,
    /// What the provider and the managed service can see, in the words the service's answer to
    /// this start gave.
    pub disclosure: Vec<String>,
}

/* -------------------------------------------------------------------------- */
/* voice.stop                                                                  */
/* -------------------------------------------------------------------------- */

/// Parameters of `voice.stop`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceStopParams {
    /// The voice session to end.
    pub voice_session_id: VoiceSessionId,
}

/// The result of `voice.stop`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceStopResult {
    /// The voice session that ended.
    pub voice_session_id: VoiceSessionId,
    /// The grant that was revoked with it.
    pub revoked_grant_id: GrantId,
    /// When the grant was revoked, in UTC milliseconds.
    ///
    /// Section 15 ¶8: ending the native voice session revokes its voice grant immediately,
    /// independently of provider billing finalisation. This moment is the host's own.
    pub revoked_at_ms: TimestampMs,
    /// Whether the broker was told to finalise the call.
    ///
    /// False is not a failure of the stop. The grant is gone either way; what the broker does with
    /// the money is settled on its own schedule, and a host that waited for it would be holding a
    /// revocation open for a reason that has nothing to do with authority.
    pub broker_notified: bool,
    /// The terminal sessions this voice session reached, which keep running.
    ///
    /// Section 15 ¶1: a voice session is not a shell session, and voice can stop while the agent
    /// continues.
    pub sessions_left_running: CanonicalSet<SessionId>,
}

/* -------------------------------------------------------------------------- */
/* voice.delegate                                                              */
/* -------------------------------------------------------------------------- */

/// Parameters of `voice.delegate`.
///
/// Section 15 ¶7: the delegation event supplies an identifier and a timeline offset, not task
/// text. There is deliberately no field for what the model said the user wants; the coordinator
/// uses the accumulated transcripts and current host state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceDelegateParams {
    /// The voice session the delegation belongs to.
    pub voice_session_id: VoiceSessionId,
    /// The provider's delegation identifier, as the device received it on the data channel.
    pub delegation_id: VoiceDelegationId,
    /// Where in the call it happened, in milliseconds from the start.
    pub offset_ms: U64,
    /// The action the device asks the coordinator to propose.
    pub action: VoiceAction,
    /// The session it acts on, when it acts on one.
    pub session_id: Nullable<SessionId>,
    /// The spoken confirmation naming the destination session, when the action needs one.
    pub spoken_destination: Nullable<SpokenDestination>,
    /// The approval the answer belongs to, when the action answers one.
    pub approval: Nullable<VerifiedApprovalAnswer>,
    /// The turn being cancelled, when the action cancels one.
    pub turn_id: Nullable<AgentTurnId>,
    /// The confirmation from the device's unlocked screen, when the action needs one.
    pub confirmation: Nullable<VoiceConfirmationProof>,
}

/// A spoken confirmation that names the destination session.
///
/// Section 15 ¶13 requires the confirmation to name the destination, so the host checks the name
/// against the session it is about to submit to rather than accepting that one was given.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpokenDestination {
    /// The session the speaker named.
    pub session_id: SessionId,
    /// The words the speaker used, as the transcript recorded them. Data, never authority.
    pub spoken_text: String,
}

/// An approval answer, with the details of the request it answers.
///
/// Section 15 ¶13: an approval decision requires the verified request's details and an explicit
/// answer. The host compares the details against the approval it holds, so a model that invented
/// them is refused rather than believed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifiedApprovalAnswer {
    /// The approval being answered.
    pub approval_request_id: ApprovalRequestId,
    /// The digest of the request's details as the host read them out.
    pub details_digest: Digest256,
    /// The explicit answer. Nothing is inferred from a transcript.
    pub approved: bool,
}

/// The result of `voice.delegate`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceDelegateResult {
    /// The delegation this answers.
    pub delegation_id: VoiceDelegationId,
    /// What the coordinator proposed and what the host did about it.
    pub outcome: VoiceDelegationOutcome,
}

/// What one delegation became.
///
/// Named the way [`VoiceStartOutcome`] is named, and for the same reason: an identifier inside a
/// payload the format has to buffer first cannot be read back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum VoiceDelegationOutcome {
    /// The host performed it, and its receipt is the authority for that.
    Performed {
        /// The action identifier of the host action. Its receipt is read the ordinary way.
        action_id: ActionId,
        /// What the coordinator may say about it, bounded to what a context request carries.
        summary: String,
    },
    /// The host accepted the proposal and its effect is not established.
    ///
    /// Section 15 ¶10: an acknowledgement proves admission, not execution, and host action
    /// receipts remain authoritative. A result that was admitted and not performed is reported as
    /// admitted only; nothing reads it as evidence that anything ran.
    Admitted {
        /// The action identifier to read the receipt under.
        action_id: ActionId,
        /// What admission does not establish.
        note: String,
    },
    /// The action needs a confirmation on the device's unlocked screen, and here is the challenge.
    ///
    /// Section 15 ¶13 puts five classes of action behind a confirmation on an unlocked screen, and
    /// section 15 ¶8 makes that confirmation a signature over the exact action rather than a
    /// statement in the conversation. This is how the device gets the challenge to sign: the
    /// delegation is not spent, so the same delegation comes back with the proof on it and becomes
    /// one action. Nothing has been admitted at this point, and the challenge carries no authority
    /// of its own: it is single use, short-lived, and bound to this action and this request.
    ConfirmationRequired {
        /// The challenge the device's ceremony signs.
        request: Box<VoiceConfirmationRequest>,
        /// What a person is told, and what is missing.
        message: String,
    },
    /// The host refused it, and why.
    ///
    /// A refusal is an answer, not a failure: the delegation arrived, the check ran and the answer
    /// was no. A caller that treated it as a transport failure would retry something that was
    /// decided.
    Refused {
        /// Which rule refused it.
        reason: VoiceRefusal,
        /// What a person is told, and what is missing.
        message: String,
    },
}

/// Why a delegation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VoiceRefusal {
    /// The voice session does not exist, or is not this device's.
    UnknownVoiceSession,
    /// The provider never announced this delegation identifier to this call.
    UnannouncedDelegation,
    /// The voice grant does not permit this action.
    OutsideVoiceGrant,
    /// The device's own grant does not carry the right this action needs.
    OutsideDeviceGrant,
    /// This release has no host effect for the action.
    NoSuchEffect,
    /// The action needs a confirmation on an unlocked screen and none was presented.
    ConfirmationRequired,
    /// A confirmation was presented and does not authorise this action or this request.
    ConfirmationMismatch,
    /// A confirmation was presented and has expired or was already used.
    ConfirmationSpent,
    /// Submitting a prompt needs a spoken confirmation naming the destination session.
    DestinationNotNamed,
    /// An approval decision needs the verified request's details and an explicit answer.
    ApprovalNotVerified,
    /// Cancelling a turn needs the typed request and the current turn identifier.
    TurnNotNamed,
    /// The session named is not one this voice session may reach.
    SessionOutsideVoiceSession,
}

impl VoiceRefusal {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownVoiceSession => "unknown_voice_session",
            Self::UnannouncedDelegation => "unannounced_delegation",
            Self::OutsideVoiceGrant => "outside_voice_grant",
            Self::OutsideDeviceGrant => "outside_device_grant",
            Self::NoSuchEffect => "no_such_effect",
            Self::ConfirmationRequired => "confirmation_required",
            Self::ConfirmationMismatch => "confirmation_mismatch",
            Self::ConfirmationSpent => "confirmation_spent",
            Self::DestinationNotNamed => "destination_not_named",
            Self::ApprovalNotVerified => "approval_not_verified",
            Self::TurnNotNamed => "turn_not_named",
            Self::SessionOutsideVoiceSession => "session_outside_voice_session",
        }
    }
}

impl fmt::Display for VoiceRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/* -------------------------------------------------------------------------- */
/* voice.context                                                               */
/* -------------------------------------------------------------------------- */

/// Parameters of `voice.context`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceContextParams {
    /// The voice session asking.
    pub voice_session_id: VoiceSessionId,
    /// The session the context is about.
    pub session_id: SessionId,
    /// Content classes the person has selected on top of the default.
    ///
    /// Section 15 ¶12 excludes file contents, environment variables, raw terminal scrollback and
    /// attachment bytes unless the user selects them, so selecting one is a field rather than a
    /// setting somewhere else.
    pub selected: CanonicalSet<VoiceContextClass>,
    /// The delegation this context belongs to, or null for context that belongs to the call.
    pub delegation_id: Nullable<VoiceDelegationId>,
}

/// A class of content the default context excludes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VoiceContextClass {
    /// The contents of files.
    FileContents,
    /// Environment variables.
    EnvironmentVariables,
    /// Raw terminal scrollback.
    TerminalScrollback,
    /// The bytes of an attachment.
    AttachmentBytes,
}

impl VoiceContextClass {
    /// Every excluded class, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::FileContents,
        Self::EnvironmentVariables,
        Self::TerminalScrollback,
        Self::AttachmentBytes,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileContents => "file_contents",
            Self::EnvironmentVariables => "environment_variables",
            Self::TerminalScrollback => "terminal_scrollback",
            Self::AttachmentBytes => "attachment_bytes",
        }
    }

    /// The right a grant needs before content of this class is read at all, on top of the history
    /// bound every item is held to.
    ///
    /// Selecting a class is a person saying they want it, not authority to read it. File contents
    /// and attachment bytes are file reads, so they need the grant's own file right. The host's
    /// context filter and the preparation that describes a call both ask this, so what a person is
    /// told a call would carry is what the filter would let it carry.
    #[must_use]
    pub const fn required_right(self) -> Option<ActionRight> {
        match self {
            Self::FileContents | Self::AttachmentBytes => Some(ActionRight::FilesRead),
            Self::EnvironmentVariables | Self::TerminalScrollback => None,
        }
    }
}

/// Ordered by the wire string, for the same reason [`VoiceAction`] is.
impl Ord for VoiceContextClass {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for VoiceContextClass {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for VoiceContextClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The result of `voice.context`.
///
/// Section 15 ¶9: selected context and host results return from the paired client to the managed
/// broker as bounded context requests. This is what the host hands back to the paired client; the
/// host never sends it to the broker itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceContextResult {
    /// The voice session it was selected for.
    pub voice_session_id: VoiceSessionId,
    /// The session it is about.
    pub session_id: SessionId,
    /// What the coordinator selected, as project text.
    pub selection: VoiceContextSelection,
    /// The interval and resources the selection was built from.
    ///
    /// Section 10: derived data identifies its source interval and resources.
    pub provenance: VoiceContextProvenance,
    /// What the grant's history bound kept out, so a gap is visible rather than silent.
    pub withheld: Vec<VoiceWithheld>,
    /// What the provider and the managed service can see of what is sent, in the words the
    /// service gave this call when it started.
    pub disclosure: Vec<String>,
}

/// The default context of section 15 ¶12, bounded and separated from coordinator instructions.
///
/// Every field here is **project text**: data the coordinator submits, never instructions it
/// follows. The separation is in the types rather than in a comment — nothing in this structure
/// can become an instruction, because the instruction side is [`VoiceInstructions`] and the two
/// never share a field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceContextSelection {
    /// The session's description.
    pub session_description: String,
    /// The current working directory.
    pub working_directory: String,
    /// The active application.
    pub active_application: String,
    /// Summaries of the decisions waiting on a person.
    pub pending_decisions: Vec<String>,
    /// The last semantic messages, oldest first, at most
    /// [`VOICE_CONTEXT_MESSAGE_COUNT`] of them.
    pub recent_messages: Vec<String>,
    /// Content classes the person selected, with what each contributed.
    pub selected: Vec<VoiceSelectedContent>,
    /// The upper bound on the text tokens this selection costs, counted against
    /// [`VOICE_CONTEXT_TOKEN_CAP`].
    ///
    /// A bound rather than a measurement: the host cannot run the provider's encoder, so it counts
    /// something no byte-level tokenizer can exceed. The selection is therefore never larger than
    /// the cap and is often smaller than the figure suggests.
    pub text_tokens: u32,
    /// True when the cap cut the selection short.
    pub truncated: bool,
    /// How many secret-looking runs were replaced.
    ///
    /// Section 15 ¶12: stripping configured secret patterns is a secondary measure. A count above
    /// zero says something was replaced; a count of zero says nothing was matched, and neither says
    /// the remainder holds no secrets.
    pub secrets_stripped: u32,
    /// What stripping does and does not establish, carried with every selection.
    pub stripping_note: String,
}

/// One class of content the person selected, and what it contributed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceSelectedContent {
    /// Which class.
    pub class: VoiceContextClass,
    /// The text it contributed, already filtered, capped and stripped.
    pub text: String,
}

/// Where a selection's content came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceContextProvenance {
    /// The earliest source read, in UTC milliseconds.
    pub from_ms: TimestampMs,
    /// The latest source read, in UTC milliseconds.
    pub to_ms: TimestampMs,
    /// The resources read, as the host names them.
    pub resources: Vec<String>,
}

/// A run of content the history filter kept out of a selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceWithheld {
    /// Why it was kept out.
    pub reason: String,
    /// How many items.
    pub count: U64,
}

/// Application-authored instructions, which are never project text.
///
/// Section 15 ¶9 and ¶12 both ask for this separation. It is a separate type with a separate field
/// on the wire so a coordinator cannot accidentally put a session's text where its own
/// instructions go, and a reader can tell which is which without knowing where the value came
/// from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceInstructions {
    /// The instruction text the application wrote.
    pub text: String,
}

/* -------------------------------------------------------------------------- */
/* What an append acknowledgement does not mean                                */
/* -------------------------------------------------------------------------- */

/// What a provider append acknowledgement establishes, and what it does not.
///
/// Section 15 ¶10: append acknowledgements prove context admission, not host execution or audio
/// playback, and host action receipts remain authoritative. The sentence lives here so every
/// surface that reports an admission says the same thing.
pub const VOICE_ADMISSION_NOTE: &str = "The model received this context. It is not evidence that a host action ran or that audio was \
     played; host action receipts are the authority for that.";

/// What a provider delegation identifier is, carried with every delegation the host accepts.
pub const VOICE_DELEGATION_NOTE: &str = "A provider delegation identifier is correlation data. It carries no authority and no task \
     text; the host decides what a delegation becomes from its own state.";

/// What secret-pattern stripping does and does not establish.
pub const VOICE_STRIPPING_NOTE: &str = "Configured secret patterns were replaced as a secondary measure. Filtering does not prove \
     the remaining content contains no secrets.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalars::Uuid;

    #[test]
    fn the_default_scope_is_section_fifteens_four_actions() {
        let default = VoiceAction::default_scope();
        let names: Vec<&str> = default.iter().map(|action| action.as_str()).collect();
        assert_eq!(
            names,
            vec!["brief", "compose_prompt", "navigate", "status"],
            "the default scope is navigation, status, briefing and prompt composition"
        );
        for action in VoiceAction::ALL {
            assert_eq!(
                default.contains(action),
                action.in_default_scope(),
                "{action} disagrees with the default scope"
            );
        }
    }

    /// Every answer a voice method gives travels as KR-CBOR-1 and is read back by the device that
    /// asked, so every one of them has to survive the round trip. The identifiers inside them are
    /// binary on the wire, and a shape that made the format buffer the value before reading it
    /// would lose that: this is the test that would have caught it.
    #[test]
    fn every_voice_answer_survives_the_wire() {
        fn round_trip<T>(value: &T)
        where
            T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
        {
            let encoded =
                kr_cbor::encode(&kr_cbor::to_canonical_value(value).expect("the answer encodes"));
            let decoded: T = kr_cbor::from_canonical_value(
                &kr_cbor::decode(&encoded, &kr_cbor::Limits::DEFAULT).expect("the answer decodes"),
            )
            .expect("the answer reads back");
            assert_eq!(&decoded, value);
        }

        let voice_session_id = VoiceSessionId::new(Uuid::from_bytes([0xa0; 16]));
        let disclosure = vec![
            "Audio travels directly between this device and the provider.".to_owned(),
            "The provider and this service can process the speech.".to_owned(),
        ];
        let rate = VoiceRate {
            version: "2026-09-a".to_owned(),
            minor_units_per_second: U64::new(2),
            minimum_seconds: 15,
            currency: "usd".to_owned(),
        };
        let descriptor = VoiceSessionDescriptor {
            voice_session_id,
            grant_id: GrantId::new(Uuid::from_bytes([0xb0; 16])),
            statement: VoiceGrantStatement::of(&VoiceAction::default_scope()),
            session_ids: [SessionId::new(Uuid::from_bytes([0xc0; 16]))]
                .into_iter()
                .collect(),
            call_id: "call-1".to_owned(),
            provider_session_id: "sess_1".to_owned(),
            answer_sdp: "v=0\r\n".to_owned(),
            model: "gpt-live-1".to_owned(),
            control_path: "/api/voice/sessions/call-1/control".to_owned(),
            broker_origin: "https://reach.example".to_owned(),
            heartbeat_seconds: 20,
            closes_at_ms: TimestampMs::new(1_700_000_000_000),
            disclosure: disclosure.clone(),
        };
        round_trip(&VoiceStartResult {
            outcome: VoiceStartOutcome::Started {
                session: Box::new(descriptor),
            },
        });
        round_trip(&VoiceStartResult {
            outcome: VoiceStartOutcome::RateChanged {
                rate: rate.clone(),
                message: "The rate changed after it was shown.".to_owned(),
            },
        });
        round_trip(&VoiceStartResult {
            outcome: VoiceStartOutcome::PreparationChanged {
                message: "What this call would reach changed after it was shown.".to_owned(),
            },
        });
        round_trip(&VoiceStartResult {
            outcome: VoiceStartOutcome::CreationUnknown {
                attempt_id: "attempt-1".to_owned(),
                message: "The provider may hold a session for that attempt.".to_owned(),
            },
        });
        round_trip(&VoiceDelegateResult {
            delegation_id: VoiceDelegationId::new("item_one").expect("an identifier"),
            outcome: VoiceDelegationOutcome::Performed {
                action_id: ActionId::new(Uuid::from_bytes([0xd0; 16])),
                summary: "session 3 is live".to_owned(),
            },
        });
        round_trip(&VoiceDelegateResult {
            delegation_id: VoiceDelegationId::new("item_two").expect("an identifier"),
            outcome: VoiceDelegationOutcome::ConfirmationRequired {
                request: Box::new(VoiceConfirmationRequest {
                    confirmation_id: ConfirmationId::new(Uuid::from_bytes([0xe0; 16])),
                    voice_session_id,
                    action: VoiceAction::ApplyDiff,
                    action_digest: Digest256::from_bytes([7; 32]),
                    action_id: ActionId::new(Uuid::from_bytes([0xd1; 16])),
                    host_device_id: DeviceId::new(Uuid::from_bytes([0xf0; 16])),
                    device_id: DeviceId::new(Uuid::from_bytes([0xf1; 16])),
                    nonce: Nonce256::from_bytes([9; 32]),
                    expires_at_ms: TimestampMs::new(1_700_000_120_000),
                }),
                message: "sign this on the unlocked screen".to_owned(),
            },
        });
        round_trip(&VoicePrepareResult {
            session_ids: [SessionId::new(Uuid::from_bytes([0xc0; 16]))]
                .into_iter()
                .collect(),
            statement: VoiceGrantStatement::of(&VoiceAction::default_scope()),
            excluded: VoiceContextClass::ALL.iter().copied().collect(),
            selected: [VoiceContextClass::FileContents].into_iter().collect(),
            token_cap: VOICE_CONTEXT_TOKEN_CAP,
            message_count: VOICE_CONTEXT_MESSAGE_COUNT,
            broker_origin: "https://reach.example".to_owned(),
            prepared: Digest256::from_bytes([4; 32]),
            managed: Nullable::some(VoiceManagedTerms {
                enabled: true,
                model: "gpt-live-1".to_owned(),
                disclosure,
                admission_note: "The model received this context.".to_owned(),
                delegation_note: "A delegation identifier is correlation data.".to_owned(),
                alternatives: vec!["Type to the agent instead.".to_owned()],
                rate,
                maximum_session_seconds: 1_800,
                minimum_request_seconds: 60,
                heartbeat_seconds: 20,
                context_bytes: 500,
            }),
            managed_unavailable: Nullable::null(),
        });
        round_trip(&VoicePrepareResult {
            session_ids: CanonicalSet::from_iter([]),
            statement: VoiceGrantStatement::of(&VoiceAction::default_scope()),
            excluded: VoiceContextClass::ALL.iter().copied().collect(),
            selected: CanonicalSet::from_iter([]),
            token_cap: VOICE_CONTEXT_TOKEN_CAP,
            message_count: VOICE_CONTEXT_MESSAGE_COUNT,
            broker_origin: String::new(),
            prepared: Digest256::from_bytes([5; 32]),
            managed: Nullable::null(),
            managed_unavailable: Nullable::some("This host has no voice service.".to_owned()),
        });
    }

    #[test]
    fn the_five_unlocked_screen_classes_are_the_ones_section_fifteen_names() {
        let named: Vec<&str> = VoiceAction::UNLOCKED_SCREEN
            .iter()
            .map(|action| action.as_str())
            .collect();
        assert_eq!(
            named,
            vec![
                "close_session",
                "change_grant",
                "shell_input",
                "apply_diff",
                "deliver_externally"
            ]
        );
        for action in VoiceAction::ALL {
            assert_eq!(
                VoiceAction::UNLOCKED_SCREEN.contains(action),
                action.needs_unlocked_screen(),
                "{action} disagrees with the unlocked-screen list"
            );
        }
    }

    #[test]
    fn no_action_in_the_default_scope_needs_a_confirmation() {
        for action in VoiceAction::ALL.iter().filter(|a| a.in_default_scope()) {
            assert!(!action.needs_unlocked_screen());
            assert!(!action.needs_spoken_destination());
            assert!(!action.needs_verified_request());
            assert_eq!(action.required_right(), Some(ActionRight::SessionView));
        }
    }

    #[test]
    fn a_voice_grant_carries_the_rights_its_actions_need() {
        let rights = VoiceAction::rights_for(&VoiceAction::default_scope());
        assert!(rights.contains(&ActionRight::VoiceUse));
        assert!(rights.contains(&ActionRight::SessionView));
        assert!(!rights.contains(&ActionRight::AgentPrompt));

        let broadened: CanonicalSet<VoiceAction> =
            [VoiceAction::Navigate, VoiceAction::SubmitPrompt]
                .into_iter()
                .collect();
        let rights = VoiceAction::rights_for(&broadened);
        assert!(rights.contains(&ActionRight::AgentPrompt));
    }

    #[test]
    fn external_delivery_has_no_right_and_therefore_no_grant() {
        // Named because section 15 ¶13 names it. No grant can carry it, because this release has
        // no host effect that delivers outside the host.
        assert_eq!(VoiceAction::DeliverExternally.required_right(), None);
        let rights =
            VoiceAction::rights_for(&[VoiceAction::DeliverExternally].into_iter().collect());
        assert_eq!(rights.len(), 1);
        assert!(rights.contains(&ActionRight::VoiceUse));
    }

    #[test]
    fn a_statement_names_every_action_the_grant_permits() {
        let actions: CanonicalSet<VoiceAction> = [VoiceAction::Navigate, VoiceAction::ShellInput]
            .into_iter()
            .collect();
        let statement = VoiceGrantStatement::of(&actions);
        assert_eq!(statement.statements.len(), 2);
        assert!(
            statement
                .unlocked_screen_actions
                .contains(&VoiceAction::ShellInput)
        );
        assert!(
            !statement
                .unlocked_screen_actions
                .contains(&VoiceAction::Navigate)
        );
    }

    #[test]
    fn every_action_round_trips_through_its_wire_string() {
        for action in VoiceAction::ALL {
            assert_eq!(VoiceAction::from_wire(action.as_str()), Some(*action));
            assert_eq!(action.as_str().parse::<VoiceAction>(), Ok(*action));
        }
        assert_eq!(VoiceAction::from_wire("submit"), None);
        assert_eq!(VoiceAction::from_wire(""), None);
    }

    #[test]
    fn a_delegation_identifier_is_returned_unchanged_and_never_parsed() {
        let provider = "item_9fA-_.42";
        let id = VoiceDelegationId::new(provider).expect("an opaque identifier");
        assert_eq!(id.as_str(), provider);
        // Nothing reads a prefix out of it.
        assert!(VoiceDelegationId::new("").is_err());
    }

    #[test]
    fn a_confirmation_binds_to_one_action_and_one_request() {
        use crate::scalars::Uuid;

        let plan = VoiceActionPlan {
            voice_session_id: VoiceSessionId::new(Uuid::from_bytes([1; 16])),
            action: VoiceAction::ShellInput,
            session_id: Nullable::some(SessionId::new(Uuid::from_bytes([2; 16]))),
            delegation_id: Nullable::null(),
            payload_digest: Digest256::from_bytes([3; 32]),
        };
        let other = VoiceActionPlan {
            action: VoiceAction::ApplyDiff,
            ..plan.clone()
        };
        assert_ne!(
            plan.digest().expect("a digest"),
            other.digest().expect("a digest"),
            "two different actions hash differently"
        );
    }
}
