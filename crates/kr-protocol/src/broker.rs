//! The trusted broker's vocabulary: grants, decoding trust, action tokens, launch profiles and
//! the capability map.
//!
//! Section 11 puts the broker between an upstream application and everything that wants to say
//! what the application is doing. The broker owns the processes it launched, their credentials,
//! the immutable source frames they produced, the pending resources those frames imply and the
//! arbitration that resolves them. A component supplies meaning; it never supplies authority.
//!
//! Four rules shape every type here.
//!
//! * **The three grants are separate.** Observation lets a component say what it thinks is
//!   happening. Upstream action lets it prepare a declared operation against the bound execution.
//!   Approval interpretation lets it read a native request and encode an answer. Holding one is
//!   never holding another, which is why [`BrokerGrants`] is a set of three independent flags and
//!   not a level.
//! * **Decoding trust is explicit and recorded.** A component that turns vendor bytes into a
//!   pending approval is a semantic trust boundary. [`DecodingTrust`] names the publisher, the
//!   package and the exact upstream methods the trust covers, and a component without it cannot
//!   create an approval resource however convincing its output is.
//! * **A token is the authority for one invocation.** [`ActionToken`] binds the verified actor,
//!   which of the three grants authorised the call, the application and thread revision it was
//!   issued against, the declared action and the hash of the parameters. A callback can do what
//!   that invocation permits and nothing else, and the token is spent once.
//! * **Evidence is not permission.** A [`InstanceCapabilityRecord`] says what is known to work here, at
//!   which exact identity, and what makes that knowledge stale. Every action rechecks its
//!   capability revision and its grant separately, because one answers "can this be done" and the
//!   other answers "may this actor do it".

use core::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{
    ActionTokenId, ActorId, AgentBindingRevision, ApplicationInstanceId, BrokerBindingId,
    CapabilityId, CapabilityRevision, EnvironmentId, GrantId, LaunchProfileId, PluginId,
    PublisherId, SourceGeneration, UpstreamMethod, UpstreamRequestId,
};
use crate::scalars::{Bytes, CanonicalSet, Digest256, Nullable, TimestampMs, U64};

/// Maximum length in bytes of a declared action name.
pub const MAX_ACTION_NAME_LEN: usize = 96;

/// Maximum length in bytes of a free-text reason a person reads.
pub const MAX_BROKER_REASON_LEN: usize = 512;

/// How many upstream methods one decoding-trust record may cover.
///
/// A record that covered everything would not be a boundary. The bound is generous enough for a
/// real connector's approval surface and small enough that the list is readable.
pub const MAX_TRUSTED_METHODS: usize = 64;

/// How many decisions one decoded projection may offer.
///
/// A person chooses one of these. A list longer than this is not a decision, and a decoder that
/// produced one has misread the request.
pub const MAX_OFFERED_DECISIONS: usize = 16;

/// Maximum length in bytes of one decision identifier or label.
pub const MAX_DECISION_TEXT_LEN: usize = 256;

/// Maximum bytes of original source one decoded request may carry.
///
/// Section 11 requires the ledger to retain the original source, and a partial copy is not the
/// original. A request whose frame is larger than this is therefore never turned into an
/// actionable approval: it is forwarded opaquely on the native path, where nothing depends on
/// this host being able to reproduce it. The bound leaves room inside one canonical record for
/// the projection and the record's own fields.
pub const MAX_RETAINED_SOURCE_BYTES: usize = 512 * 1024;

/// Maximum length in bytes of the summary a decoder writes for a person.
pub const MAX_PROJECTION_SUMMARY_LEN: usize = 4096;

// ---------------------------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------------------------

/// One of the three broker grants a binding can hold.
///
/// Section 11 keeps them apart on purpose: "Observation callbacks cannot submit input merely
/// because they can read output."
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BrokerGrant {
    /// Semantic presentation and inferred status from scoped source events.
    Observation,
    /// Preparing declared prompts, commands, attachments or cancellation against the bound
    /// execution.
    UpstreamAction,
    /// Interpreting native requests from the bound upstream and encoding answers to them.
    ApprovalInterpreter,
}

impl BrokerGrant {
    /// Every grant, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Observation,
        Self::UpstreamAction,
        Self::ApprovalInterpreter,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::UpstreamAction => "upstream_action",
            Self::ApprovalInterpreter => "approval_interpreter",
        }
    }

    /// Returns true when this grant permits creating a pending approval resource.
    ///
    /// Only the approval interpreter does. A display-only component holds observation alone, and
    /// a scraped screen is not approval authority however accurate it is.
    #[must_use]
    pub const fn may_create_approval(self) -> bool {
        matches!(self, Self::ApprovalInterpreter)
    }

    /// Returns true when this grant permits preparing an effect against the upstream.
    #[must_use]
    pub const fn may_prepare_effect(self) -> bool {
        matches!(self, Self::UpstreamAction)
    }
}

impl fmt::Display for BrokerGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The grants one binding holds, each independently.
///
/// The type is a set rather than a rank because there is no ordering between them: a connector
/// that answers approvals need not be permitted to submit prompts, and one that presents a
/// conversation need not be permitted to do either.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct BrokerGrants(CanonicalSet<BrokerGrant>);

impl Default for BrokerGrants {
    fn default() -> Self {
        Self::none()
    }
}

impl BrokerGrants {
    /// A binding that holds nothing.
    #[must_use]
    pub const fn none() -> Self {
        Self(CanonicalSet::new())
    }

    /// Builds a set from the grants a binding was given.
    #[must_use]
    pub fn granted(granted: impl IntoIterator<Item = BrokerGrant>) -> Self {
        Self(granted.into_iter().collect())
    }

    /// Returns true when the binding holds this grant.
    #[must_use]
    pub fn holds(&self, grant: BrokerGrant) -> bool {
        self.0.contains(&grant)
    }

    /// Returns the grants held, in declaration order.
    pub fn iter(&self) -> impl Iterator<Item = BrokerGrant> + '_ {
        self.0.iter().copied()
    }

    /// Returns true when the binding holds no grant at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns true when the binding may observe and nothing more.
    ///
    /// This is the display-only case section 11 singles out: it can present, and it cannot create
    /// an approval resource or send anything upstream.
    #[must_use]
    pub fn is_display_only(&self) -> bool {
        self.holds(BrokerGrant::Observation)
            && !self.holds(BrokerGrant::UpstreamAction)
            && !self.holds(BrokerGrant::ApprovalInterpreter)
    }

    /// Adds one grant.
    pub fn insert(&mut self, grant: BrokerGrant) {
        self.0.insert(grant);
    }

    /// Removes one grant.
    ///
    /// Withdrawing one grant never touches the others, which is the whole point of holding them
    /// as three independent flags.
    pub fn remove(&mut self, grant: BrokerGrant) {
        self.0 = self.iter().filter(|held| *held != grant).collect();
    }

    /// Checks that the binding holds the grant an operation needs.
    ///
    /// # Errors
    ///
    /// Returns [`GrantError::NotHeld`] when it does not.
    pub fn require(&self, grant: BrokerGrant) -> Result<(), GrantError> {
        if self.holds(grant) {
            Ok(())
        } else {
            Err(GrantError::NotHeld { grant })
        }
    }
}

/// A binding asked to do something no grant of its permits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// The binding does not hold the named grant.
    #[error("this binding does not hold the {grant} grant")]
    NotHeld {
        /// The grant the operation needed.
        grant: BrokerGrant,
    },
}

// ---------------------------------------------------------------------------------------------
// Decoding trust
// ---------------------------------------------------------------------------------------------

/// What a component is trusted to interpret, and whose interpretation it is.
///
/// Section 11: "Trust to classify or encode native mutations must be explicit, with the publisher
/// and methods recorded." Authenticated wire provenance proves which connection supplied bytes; it
/// does not prove that this decoder read them correctly, so the record exists to be shown to a
/// person beside the pending resource it produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DecodingTrust {
    /// The package whose component holds the trust.
    pub plugin_id: PluginId,
    /// The publisher that signed that package.
    pub publisher_id: PublisherId,
    /// The digest of the exact component bytes the trust was granted to.
    pub package_digest: Digest256,
    /// The upstream methods this component may decode into a pending resource.
    ///
    /// A method outside this list is forwarded opaquely and produces no rich approval, whatever
    /// the component reports about it.
    pub methods: CanonicalSet<UpstreamMethod>,
    /// The projection schema versions this trust covers.
    ///
    /// This is the schema policy the broker checks before a decoded projection becomes an
    /// actionable approval. A projection that names a version outside this set is not one this
    /// trust was granted for, whatever it contains.
    pub schema_versions: CanonicalSet<String>,
    /// The most decisions a projection under this trust may offer.
    pub max_decisions: U64,
    /// Whether the component may also encode an answer to those requests.
    ///
    /// Decoding and answering are separate capabilities in the package contract, and they stay
    /// separate here.
    pub may_encode_response: bool,
    /// When the trust was recorded.
    pub granted_at: TimestampMs,
}

impl DecodingTrust {
    /// Returns true when this record covers the named upstream method.
    #[must_use]
    pub fn covers(&self, method: &UpstreamMethod) -> bool {
        self.methods.contains(method)
    }

    /// Returns true when the record was granted to exactly this package.
    ///
    /// Trust is granted to a publisher's package at a digest. A binding that runs different bytes
    /// is a different decoder, and one package's trust is never another's.
    #[must_use]
    pub fn belongs_to(
        &self,
        plugin_id: &PluginId,
        publisher_id: &PublisherId,
        package_digest: &Digest256,
    ) -> bool {
        &self.plugin_id == plugin_id
            && &self.publisher_id == publisher_id
            && &self.package_digest == package_digest
    }

    /// Checks a decoded projection against this trust's schema policy.
    ///
    /// Section 11 lists schema policy among the things the broker checks before it believes a
    /// decoder, and this is that check: the projection names a schema version the trust covers,
    /// it offers at least one decision and no more than the trust permits, and its decision
    /// identifiers are unique and bounded. Only a projection that passes becomes an actionable
    /// approval.
    ///
    /// # Errors
    ///
    /// Returns the first rule the projection breaks.
    pub fn check_projection(&self, projection: &DecodedProjection) -> Result<(), TrustError> {
        if !self.schema_versions.contains(&projection.schema_version) {
            return Err(TrustError::SchemaNotCovered);
        }
        if projection.schema_version.is_empty()
            || projection.schema_version.len() > MAX_DECISION_TEXT_LEN
        {
            return Err(TrustError::SchemaNotCovered);
        }
        if projection.summary.len() > MAX_PROJECTION_SUMMARY_LEN {
            return Err(TrustError::SummaryTooLong {
                length: projection.summary.len(),
                limit: MAX_PROJECTION_SUMMARY_LEN,
            });
        }
        if projection.decisions.is_empty() {
            return Err(TrustError::NoDecisions);
        }
        let permitted = usize::try_from(self.max_decisions.get())
            .unwrap_or(MAX_OFFERED_DECISIONS)
            .min(MAX_OFFERED_DECISIONS);
        if projection.decisions.len() > permitted {
            return Err(TrustError::TooManyDecisions {
                decisions: projection.decisions.len(),
                limit: permitted,
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for decision in &projection.decisions {
            if decision.option_id.is_empty()
                || decision.option_id.len() > MAX_DECISION_TEXT_LEN
                || decision.label.len() > MAX_DECISION_TEXT_LEN
            {
                return Err(TrustError::DecisionText);
            }
            if !seen.insert(decision.option_id.as_str()) {
                return Err(TrustError::DuplicateDecision);
            }
        }
        Ok(())
    }

    /// Checks that the record is one the broker can act on.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::TooManyMethods`] when the list exceeds [`MAX_TRUSTED_METHODS`], and
    /// [`TrustError::NoMethods`] when it is empty, because a trust record that covers nothing is a
    /// record that should not have been written.
    pub fn validate(&self) -> Result<(), TrustError> {
        if self.methods.is_empty() {
            return Err(TrustError::NoMethods);
        }
        if self.methods.len() > MAX_TRUSTED_METHODS {
            return Err(TrustError::TooManyMethods {
                methods: self.methods.len(),
                limit: MAX_TRUSTED_METHODS,
            });
        }
        if self.schema_versions.is_empty() {
            return Err(TrustError::NoSchemaVersions);
        }
        if self.max_decisions.get() == 0 {
            return Err(TrustError::NoDecisions);
        }
        Ok(())
    }
}

/// One decision a decoder offers a person.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct OfferedDecision {
    /// The identifier the upstream expects back. Answering is choosing one of these.
    pub option_id: String,
    /// What the decision says, for a person.
    pub label: String,
}

/// What a decoder made of one native request.
///
/// It is a proposal. The broker checks it against the trust's schema policy before any of it
/// becomes an approval a person can answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DecodedProjection {
    /// The projection schema the decoder wrote this against.
    pub schema_version: String,
    /// What the request is asking, for a person.
    pub summary: String,
    /// The decisions offered, in the order the upstream offered them.
    pub decisions: Vec<OfferedDecision>,
}

/// A decoding-trust record, or a projection under it, the broker will not act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// The record named no method.
    #[error("a decoding trust record must name at least one upstream method")]
    NoMethods,
    /// The record named no projection schema version.
    #[error("a decoding trust record must name at least one projection schema version")]
    NoSchemaVersions,
    /// The projection names a schema version this trust does not cover.
    #[error("this decoding trust does not cover the projection's schema version")]
    SchemaNotCovered,
    /// The projection offered nothing to choose between.
    #[error("a decoded projection must offer at least one decision")]
    NoDecisions,
    /// The projection offered more decisions than the trust permits.
    #[error("this decoding trust permits {limit} decisions and the projection offered {decisions}")]
    TooManyDecisions {
        /// How many it offered.
        decisions: usize,
        /// The limit.
        limit: usize,
    },
    /// A decision identifier or label was empty or too long.
    #[error("a decision identifier is 1 to 256 bytes and a label is at most 256 bytes")]
    DecisionText,
    /// Two decisions shared one identifier.
    #[error("a decoded projection's decision identifiers must be unique")]
    DuplicateDecision,
    /// The summary was longer than a record can carry.
    #[error("a decoded projection's summary is at most {limit} bytes, and this one is {length}")]
    SummaryTooLong {
        /// How long it was.
        length: usize,
        /// The limit.
        limit: usize,
    },
    /// The record named more methods than one record may cover.
    #[error(
        "a decoding trust record covers at most {limit} methods, and this one covers {methods}"
    )]
    TooManyMethods {
        /// How many the record named.
        methods: usize,
        /// The limit.
        limit: usize,
    },
}

/// What a decoder offered, and every check the broker made before believing it.
///
/// This is the ledger row section 11 requires the broker to retain: "the decoder/package hash,
/// original source, native request ID, offered decisions, deadline and resolution state". It
/// outlives the plugin process, because a plugin-process failure cannot destroy the approval
/// ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DecoderLedgerEntry {
    /// The binding whose component decoded the request.
    pub binding_id: BrokerBindingId,
    /// The package that binding runs.
    pub plugin_id: PluginId,
    /// The publisher of that package, for a person reading the pending resource.
    pub publisher_id: PublisherId,
    /// The digest of the exact component bytes.
    pub package_digest: Digest256,
    /// The upstream method the original request named.
    pub method: UpstreamMethod,
    /// The native request identifier, exactly as the upstream wrote it.
    pub upstream_request_id: UpstreamRequestId,
    /// The generation of the source frame the decoder read.
    pub source_generation: SourceGeneration,
    /// The digest of those immutable source bytes.
    pub source_digest: Digest256,
    /// The original source bytes, whole.
    ///
    /// A digest proves which bytes these are; it cannot reproduce them, and section 11 requires
    /// the original source to be retained rather than merely identified. A request too large to
    /// retain whole never becomes an approval, so this is never a partial copy.
    pub source_bytes: Bytes,
    /// The projection the decoder produced, with the exact decisions it offered.
    pub projection: DecodedProjection,
    /// The deadline the upstream put on its request, where it stated one.
    pub deadline_ms: Nullable<TimestampMs>,
    /// When the entry was written.
    pub decoded_at: TimestampMs,
}

impl DecoderLedgerEntry {
    /// Returns true when the named decision is one this request actually offered.
    ///
    /// Answering is choosing from what the upstream offered, so an identifier that is not in the
    /// retained list is not an answer this host will encode.
    #[must_use]
    pub fn offers(&self, option_id: &str) -> bool {
        self.projection
            .decisions
            .iter()
            .any(|decision| decision.option_id == option_id)
    }
}

// ---------------------------------------------------------------------------------------------
// Action tokens
// ---------------------------------------------------------------------------------------------

/// The authority for exactly one action callback.
///
/// Section 11: "Every action callback receives a token bound to actor, grant, application/thread
/// revision, declared action and parameter hash. Its effect plan can use only resources and
/// operations permitted by that invocation."
///
/// All five bindings are checked together when the effect plan comes back. Checking the handle
/// alone would make the token a bearer secret; checking the bindings alone would let a component
/// replay one invocation's token against a later one. The broker does both, and spends the handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ActionToken {
    /// The record the broker consumes when the effect plan arrives.
    pub token_id: ActionTokenId,
    /// The verified actor whose action this is. A component never asserts it.
    pub actor_id: ActorId,
    /// Which of the three grants authorised this invocation.
    pub grant: BrokerGrant,
    /// The grant record that authority came from, when one does.
    ///
    /// A local operating-system caller has none: its authority is the identity the listener
    /// authenticated rather than a grant, and section 23 leaves the field null for it.
    pub grant_id: Nullable<GrantId>,
    /// The application instance the action runs against.
    pub application_instance_id: ApplicationInstanceId,
    /// The binding revision in force when the token was issued.
    ///
    /// A native `/new`, `/resume` or thread selection advances it, so a token issued before the
    /// switch cannot act on the conversation after it.
    pub binding_revision: AgentBindingRevision,
    /// The declared action, as the package's manifest names it.
    pub action: ActionName,
    /// The hash of the parameters the action was invoked with.
    pub parameter_hash: Digest256,
    /// The draft the invocation acts on, where it acts on one.
    ///
    /// Section 11 binds a token to the invocation it was issued for, and a draft-dependent action
    /// acts on a specific draft. Without this the token would authorise the same action against
    /// whatever draft the effect plan happened to name.
    pub draft_id: Nullable<crate::ids::DraftId>,
    /// When the token was issued.
    pub issued_at: TimestampMs,
}

impl ActionToken {
    /// Checks a returned effect plan against every binding of the token.
    ///
    /// # Errors
    ///
    /// Returns the first binding that disagrees. The order is deliberate: the actor first,
    /// because presenting another actor's token is the most serious thing a component can try;
    /// then the grant, the instance, the revision, the action and finally the parameters.
    pub fn check(&self, presented: &ActionTokenClaim) -> Result<(), TokenError> {
        if presented.token_id != self.token_id {
            return Err(TokenError::UnknownToken);
        }
        if presented.actor_id != self.actor_id {
            return Err(TokenError::Mismatch { field: "actor_id" });
        }
        if presented.grant != self.grant {
            return Err(TokenError::Mismatch { field: "grant" });
        }
        if presented.grant_id != self.grant_id {
            return Err(TokenError::Mismatch { field: "grant_id" });
        }
        if presented.application_instance_id != self.application_instance_id {
            return Err(TokenError::Mismatch {
                field: "application_instance_id",
            });
        }
        if presented.binding_revision != self.binding_revision {
            return Err(TokenError::StaleBinding {
                issued_at_revision: self.binding_revision,
                presented_revision: presented.binding_revision,
            });
        }
        if presented.action != self.action {
            return Err(TokenError::Mismatch { field: "action" });
        }
        if presented.parameter_hash != self.parameter_hash {
            return Err(TokenError::Mismatch {
                field: "parameter_hash",
            });
        }
        Ok(())
    }

    /// Checks the token against the binding revision the broker holds *now*.
    ///
    /// A token that was valid when it was issued is not authority after the upstream owner or
    /// thread changed underneath it, and this is asked again at dispatch rather than only at
    /// issue.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::StaleBinding`] when the current revision has moved on.
    pub const fn check_current_revision(
        &self,
        current: AgentBindingRevision,
    ) -> Result<(), TokenError> {
        if current.get() == self.binding_revision.get() {
            Ok(())
        } else {
            Err(TokenError::StaleBinding {
                issued_at_revision: self.binding_revision,
                presented_revision: current,
            })
        }
    }
}

/// What one operation a prepared effect asks for.
///
/// The vocabulary is the component interface's, narrowed to what the broker has to decide about:
/// which grant the operation needs, whether it acts on a draft, and whether the action's declared
/// effect class agrees with it. The arguments themselves are the connector's.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PreparedOperation {
    /// Submit or queue a prompt against the bound execution.
    UpstreamSubmit,
    /// Cancel the running turn.
    UpstreamCancel,
    /// Contribute a completed attachment to the upstream draft.
    UpstreamAttachment,
    /// Write text into the terminal.
    TerminalText,
}

impl PreparedOperation {
    /// Every operation, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::UpstreamSubmit,
        Self::UpstreamCancel,
        Self::UpstreamAttachment,
        Self::TerminalText,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UpstreamSubmit => "upstream_submit",
            Self::UpstreamCancel => "upstream_cancel",
            Self::UpstreamAttachment => "upstream_attachment",
            Self::TerminalText => "terminal_text",
        }
    }

    /// Returns the grant this operation needs, where one of the broker's three covers it.
    ///
    /// Terminal text is deliberately absent. Section 11 keeps method classification, input leases,
    /// file grants and native approval rights distinct, and writing into the terminal is the input
    /// lease's, not the upstream-action grant's. An effect plan that asks for it is asking for
    /// something no plugin grant carries.
    #[must_use]
    pub const fn grant(self) -> Option<BrokerGrant> {
        match self {
            Self::UpstreamSubmit | Self::UpstreamCancel | Self::UpstreamAttachment => {
                Some(BrokerGrant::UpstreamAction)
            }
            Self::TerminalText => None,
        }
    }

    /// Returns true when this operation can act on a draft at all.
    ///
    /// Whether a given action *must* is the manifest's own declaration, because a prompt can
    /// carry its text inline as well as live in a draft. This is the weaker fact: an operation
    /// that cannot touch a draft is one no plan may name a draft for.
    #[must_use]
    pub const fn may_act_on_a_draft(self) -> bool {
        matches!(self, Self::UpstreamSubmit | Self::UpstreamAttachment)
    }

    /// Returns true when performing this operation changes the upstream.
    #[must_use]
    pub const fn writes(self) -> bool {
        true
    }
}

impl core::fmt::Display for PreparedOperation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The effect one component prepared, as the broker receives it.
///
/// Proposing is not doing. Section 11: "Its effect plan can use only resources and operations
/// permitted by that invocation." What arrives here is a proposal, and the broker compares it with
/// the token it was prepared under before anything is dispatched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreparedEffect {
    /// The action the component says it prepared.
    pub action: ActionName,
    /// The effect class it says the operation has.
    pub class: crate::authority::EffectClass,
    /// What it asks the host to perform.
    pub operation: PreparedOperation,
    /// The draft it acts on, where it acts on one.
    pub draft_id: Nullable<crate::ids::DraftId>,
    /// The hash of the arguments it filled in.
    pub argument_hash: Digest256,
}

/// What a component presents when it returns an effect plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ActionTokenClaim {
    /// The handle the broker issued.
    pub token_id: ActionTokenId,
    /// The actor the component believes it is acting for.
    pub actor_id: ActorId,
    /// The grant it believes authorised the call.
    pub grant: BrokerGrant,
    /// The grant record it names, when the actor acts under one.
    pub grant_id: Nullable<GrantId>,
    /// The application instance it acted against.
    pub application_instance_id: ApplicationInstanceId,
    /// The binding revision it acted under.
    pub binding_revision: AgentBindingRevision,
    /// The action it declares it performed.
    pub action: ActionName,
    /// The hash of the parameters it used.
    pub parameter_hash: Digest256,
}

impl From<&ActionToken> for ActionTokenClaim {
    fn from(token: &ActionToken) -> Self {
        Self {
            token_id: token.token_id.clone(),
            actor_id: token.actor_id.clone(),
            grant: token.grant,
            grant_id: token.grant_id,
            application_instance_id: token.application_instance_id,
            binding_revision: token.binding_revision,
            action: token.action.clone(),
            parameter_hash: token.parameter_hash,
        }
    }
}

/// A token that does not authorise what was presented with it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// No live token has this handle: it was never issued, or it has already been spent.
    #[error("no unspent action token has this handle")]
    UnknownToken,
    /// One of the token's bindings disagrees with what was presented.
    #[error("the action token was issued for a different {field}")]
    Mismatch {
        /// Which binding disagreed.
        field: &'static str,
    },
    /// The application or thread binding moved after the token was issued.
    #[error(
        "the action token was issued at binding revision {issued_at_revision} and the binding is at {presented_revision}"
    )]
    StaleBinding {
        /// The revision the token was issued at.
        issued_at_revision: AgentBindingRevision,
        /// The revision presented, or the one currently in force.
        presented_revision: AgentBindingRevision,
    },
}

/// A declared action name from a package manifest.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ActionName(String);

/// An action name that is empty, too long or not in the permitted shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("an action name is 1 to 96 bytes of lower-case ASCII letters, digits, '_' and '.'")]
pub struct ActionNameError;

impl ActionName {
    /// Validates and wraps an action name.
    ///
    /// # Errors
    ///
    /// Returns [`ActionNameError`] when the name is empty, longer than [`MAX_ACTION_NAME_LEN`]
    /// bytes or contains a character outside `[a-z0-9_.]`.
    pub fn new(value: impl Into<String>) -> Result<Self, ActionNameError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_ACTION_NAME_LEN {
            return Err(ActionNameError);
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
        }) {
            return Err(ActionNameError);
        }
        Ok(Self(value))
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ActionName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl core::str::FromStr for ActionName {
    type Err = ActionNameError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

impl<'de> Deserialize<'de> for ActionName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for ActionName {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ActionName".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::ActionName".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_ACTION_NAME_LEN,
            "description": "A declared plugin action name from a package manifest."
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------------------------

/// How one action actually reached the upstream application.
///
/// Section 12 requires every action to record this, and forbids reporting an authoritative typed
/// approval or an accepted media upload from screen text alone. The app may offer a terminal
/// action as a convenience; it says so.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ActionProvenance {
    /// A typed remote procedure call the upstream answered.
    UpstreamTypedRpc,
    /// An authenticated response from an installed native hook or bridge.
    AuthenticatedHookResponse,
    /// Bytes written into the terminal. Convenience, never a typed result.
    TerminalInput,
}

impl ActionProvenance {
    /// Every provenance, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::UpstreamTypedRpc,
        Self::AuthenticatedHookResponse,
        Self::TerminalInput,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UpstreamTypedRpc => "upstream_typed_rpc",
            Self::AuthenticatedHookResponse => "authenticated_hook_response",
            Self::TerminalInput => "terminal_input",
        }
    }

    /// Returns true when this provenance can carry an authoritative typed result.
    ///
    /// Terminal input cannot: writing an answer into a terminal proves the bytes were written, not
    /// that the upstream accepted them as an approval.
    #[must_use]
    pub const fn is_authoritative(self) -> bool {
        matches!(
            self,
            Self::UpstreamTypedRpc | Self::AuthenticatedHookResponse
        )
    }
}

impl fmt::Display for ActionProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------------------------
// Launch profiles
// ---------------------------------------------------------------------------------------------

/// How a launched application is integrated.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationMode {
    /// The ordinary native terminal path and nothing else.
    NativeTerminal,
    /// The worker-owned gateway is established before the native terminal starts.
    Gateway,
    /// A native bridge installed beside an unchanged terminal.
    NativeBridge,
}

impl IntegrationMode {
    /// Every mode, in declaration order.
    pub const ALL: &'static [Self] = &[Self::NativeTerminal, Self::Gateway, Self::NativeBridge];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeTerminal => "native_terminal",
            Self::Gateway => "gateway",
            Self::NativeBridge => "native_bridge",
        }
    }

    /// Returns true when this mode routes rich traffic through the gateway.
    #[must_use]
    pub const fn uses_gateway(self) -> bool {
        matches!(self, Self::Gateway)
    }
}

impl fmt::Display for IntegrationMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What is known about the upstream's authentication at launch time.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationState {
    /// The application reports a usable credential.
    Authenticated,
    /// The application reports that it needs the user to sign in.
    SignInRequired,
    /// The host has not established which it is.
    Unknown,
}

impl AuthenticationState {
    /// Every state, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Authenticated, Self::SignInRequired, Self::Unknown];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authenticated => "authenticated",
            Self::SignInRequired => "sign_in_required",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for AuthenticationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The identity of one executable, as it was resolved.
///
/// An installed upgrade replaces the file; it does not replace the identity a running process was
/// bound to. Section 12: "An agent executable upgrade affects new launches; existing bindings
/// retain their original binary identity, schema and adapter version."
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BinaryIdentity {
    /// The absolute path the launch resolved to.
    pub resolved_path: String,
    /// The digest of the bytes at that path when it was resolved.
    pub digest: Digest256,
    /// The version the application reported.
    pub version: String,
    /// How the application was distributed: a package manager, an installer, a build.
    pub distribution: String,
}

/// One resolved launch profile.
///
/// Section 12 fixes the contents: "Each launch profile records the resolved executable,
/// distribution, version, argument vector, supported authentication state, and integration mode."
/// It is written before the launch, so a launch that is refused still leaves a record of what was
/// going to be run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LaunchProfile {
    /// This profile's identity.
    pub profile_id: LaunchProfileId,
    /// The environment the launch happens in.
    pub environment_id: EnvironmentId,
    /// The executable, its digest, its version and how it was distributed.
    pub binary: BinaryIdentity,
    /// The argument vector, exactly as it will be passed. Never a shell string.
    pub arguments: Vec<String>,
    /// What is known about the application's authentication.
    pub authentication: AuthenticationState,
    /// How the launch will be integrated.
    pub mode: IntegrationMode,
    /// When the profile was resolved.
    pub resolved_at: TimestampMs,
}

/// Why a launch intent was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LaunchRefusal {
    /// An application took the foreground between the intent and its execution.
    ///
    /// The refusal is the whole answer. Section 12 forbids the alternative outright: "It must
    /// never paste a launch command into that application's input."
    #[error("an application took the foreground after this launch was prepared")]
    ForegroundChanged,
    /// The idle-shell boundary the intent was prepared against has moved.
    #[error("the prompt has moved since this launch was prepared")]
    PromptMoved,
    /// A live execution already owns the saved conversation this launch would resume.
    ///
    /// Section 12: "An adapter must not start a second agent process against the same saved
    /// conversation to obtain a remote interface."
    #[error("{application_instance_id} is already running against this saved conversation")]
    ConversationAlreadyLive {
        /// The instance that owns it.
        application_instance_id: ApplicationInstanceId,
    },
}

// ---------------------------------------------------------------------------------------------
// The capability map
// ---------------------------------------------------------------------------------------------

/// What is currently known about one capability on this host.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InstanceCapabilityState {
    /// Qualified here and available now.
    QualifiedAvailable,
    /// This version was qualified, and nothing has established that this host can use it.
    ///
    /// A signed compatibility record establishes this and never [`InstanceCapabilityState::QualifiedAvailable`]:
    /// it is evidence about a version, not about this host's permission or live binding.
    VersionQualified,
    /// The software that would provide it is not installed.
    MissingInstallation,
    /// An operating-system permission is needed first.
    PermissionRequired,
    /// The installed version cannot provide it.
    Incompatible,
    /// It normally works here and does not at the moment.
    TemporarilyUnavailable,
    /// Nothing has established either way.
    NotTested,
}

impl InstanceCapabilityState {
    /// Every state, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::QualifiedAvailable,
        Self::VersionQualified,
        Self::MissingInstallation,
        Self::PermissionRequired,
        Self::Incompatible,
        Self::TemporarilyUnavailable,
        Self::NotTested,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QualifiedAvailable => "qualified_available",
            Self::VersionQualified => "version_qualified",
            Self::MissingInstallation => "missing_installation",
            Self::PermissionRequired => "permission_required",
            Self::Incompatible => "incompatible",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::NotTested => "not_tested",
        }
    }

    /// Returns true when an action bound to this capability may be dispatched.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::QualifiedAvailable)
    }
}

impl fmt::Display for InstanceCapabilityState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Where a capability record came from.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InstanceEvidenceSource {
    /// A bounded, disclosed probe with declared effects, run by the host.
    HostProbe,
    /// A live binding that performed the operation here.
    LiveBinding,
    /// A signed compatibility record shipped in a catalogue.
    ///
    /// Evidence about a version. Never proof that this host has permission or a live binding.
    SignedRecord,
    /// The package's own declaration, believed only for a negative state.
    PackageDeclaration,
}

impl InstanceEvidenceSource {
    /// Every source, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::HostProbe,
        Self::LiveBinding,
        Self::SignedRecord,
        Self::PackageDeclaration,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostProbe => "host_probe",
            Self::LiveBinding => "live_binding",
            Self::SignedRecord => "signed_record",
            Self::PackageDeclaration => "package_declaration",
        }
    }

    /// Returns true when this source can establish that a capability works on this host.
    #[must_use]
    pub const fn can_establish_qualified(self) -> bool {
        matches!(self, Self::HostProbe | Self::LiveBinding)
    }

    /// Returns true when this source can establish that a version was qualified.
    ///
    /// A package's own declaration cannot: a package saying its capabilities work is the claim
    /// under review, not evidence for it.
    #[must_use]
    pub const fn can_establish_version_qualified(self) -> bool {
        matches!(
            self,
            Self::HostProbe | Self::LiveBinding | Self::SignedRecord
        )
    }
}

impl fmt::Display for InstanceEvidenceSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What makes a capability record stale.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InstanceInvalidation {
    /// The tested binary changed.
    BinaryChanged,
    /// The active binding changed.
    BindingChanged,
    /// The upstream schema or protocol version changed.
    SchemaChanged,
    /// An operating-system permission changed.
    OsPermissionChanged,
    /// The desktop session generation changed.
    DesktopGenerationChanged,
    /// The signed qualification profile in the catalogue changed.
    QualificationProfileChanged,
    /// The host's own launch profile changed.
    ///
    /// Separate from the catalogue's qualification profile, because a record gathered under one
    /// argument vector says nothing about another and neither implies the other changed.
    LaunchProfileChanged,
}

impl InstanceInvalidation {
    /// Every trigger, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::BinaryChanged,
        Self::BindingChanged,
        Self::SchemaChanged,
        Self::OsPermissionChanged,
        Self::DesktopGenerationChanged,
        Self::QualificationProfileChanged,
        Self::LaunchProfileChanged,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BinaryChanged => "binary_changed",
            Self::BindingChanged => "binding_changed",
            Self::SchemaChanged => "schema_changed",
            Self::OsPermissionChanged => "os_permission_changed",
            Self::DesktopGenerationChanged => "desktop_generation_changed",
            Self::QualificationProfileChanged => "qualification_profile_changed",
            Self::LaunchProfileChanged => "launch_profile_changed",
        }
    }
}

impl fmt::Display for InstanceInvalidation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The exact identity one capability record was gathered against.
///
/// Naming the identity rather than the product is what lets an installed upgrade leave a running
/// process's pinned evidence alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InstanceCapabilityIdentity {
    /// The digest of the tested binary.
    pub binary_digest: Nullable<Digest256>,
    /// The upstream schema or protocol version the evidence is about.
    pub schema_version: Nullable<MethodTableVersionText>,
    /// The package the evidence is about, where it is about one.
    pub plugin_id: Nullable<PluginId>,
    /// The digest of that package's bytes.
    pub package_digest: Nullable<Digest256>,
    /// The publisher whose signed record supplied the evidence, where one did.
    pub publisher_id: Nullable<PublisherId>,
    /// The digest of the signed qualification profile the evidence came from, where one did.
    pub qualification_profile_digest: Nullable<Digest256>,
    /// The host's launch profile the evidence was gathered under.
    pub profile_id: Nullable<LaunchProfileId>,
    /// The binding the evidence was gathered through.
    pub binding_id: Nullable<BrokerBindingId>,
    /// The agent binding revision it was gathered at.
    ///
    /// A binding identifier alone names the binding, not the conversation it was bound to when the
    /// evidence was taken, and a thread selection changes what the upstream can do.
    pub binding_revision: Nullable<AgentBindingRevision>,
    /// The desktop session generation the evidence is bound to.
    pub desktop_generation: Nullable<U64>,
    /// Whether the operating-system permission the capability needs was held.
    pub os_permission_held: Nullable<bool>,
}

impl Default for InstanceCapabilityIdentity {
    fn default() -> Self {
        Self {
            binary_digest: Nullable::null(),
            schema_version: Nullable::null(),
            plugin_id: Nullable::null(),
            package_digest: Nullable::null(),
            publisher_id: Nullable::null(),
            qualification_profile_digest: Nullable::null(),
            profile_id: Nullable::null(),
            binding_id: Nullable::null(),
            binding_revision: Nullable::null(),
            desktop_generation: Nullable::null(),
            os_permission_held: Nullable::null(),
        }
    }
}

/// A schema or protocol version as text, so a record survives a vendor's own numbering.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct MethodTableVersionText(pub String);

/// One capability record the worker keeps for dispatch.
///
/// The host owns the current evidence; a worker keeps the subset its dispatch decisions need. The
/// record carries its own invalidation triggers so a worker can decide staleness without asking.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InstanceCapabilityRecord {
    /// The versioned capability this record is about.
    pub capability_id: CapabilityId,
    /// The version of that capability the record is about.
    pub capability_version: String,
    /// The application instance the record is about.
    pub application_instance_id: ApplicationInstanceId,
    /// The exact identity the evidence was gathered against.
    pub identity: InstanceCapabilityIdentity,
    /// The current revision of this record. Every action rechecks it.
    pub revision: CapabilityRevision,
    /// The current state.
    pub state: InstanceCapabilityState,
    /// Where the record came from.
    pub source: InstanceEvidenceSource,
    /// What makes it stale.
    pub invalidated_by: CanonicalSet<InstanceInvalidation>,
    /// The user-facing reason, required whenever the state is not usable.
    pub disabled_reason: Nullable<String>,
    /// When the record was gathered.
    pub observed_at: TimestampMs,
}

impl InstanceCapabilityRecord {
    /// Checks the two rules a record must satisfy before the host stores it.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::UnqualifiedSource`] when a source that cannot establish a
    /// working capability claims one, and [`CapabilityError::MissingReason`] when an unusable
    /// state carries no reason for a person to read.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.state.is_usable() && !self.source.can_establish_qualified() {
            return Err(CapabilityError::UnqualifiedSource {
                evidence_source: self.source,
            });
        }
        if self.state == InstanceCapabilityState::VersionQualified
            && !self.source.can_establish_version_qualified()
        {
            return Err(CapabilityError::DeclaredQualification);
        }
        // A record nothing can make stale is a record that never becomes stale, which is how
        // evidence outlives the thing it was about.
        if self.invalidated_by.is_empty() {
            return Err(CapabilityError::NoInvalidation);
        }
        // A record that a changed qualification profile invalidates has to name the profile it
        // came from, whatever produced it: without that name there is nothing to compare a new
        // profile against, and the trigger could never fire.
        if (self.source == InstanceEvidenceSource::SignedRecord
            || self
                .invalidated_by
                .contains(&InstanceInvalidation::QualificationProfileChanged))
            && !self.identity.qualification_profile_digest.is_present()
        {
            return Err(CapabilityError::MissingProfileIdentity);
        }
        if !self.state.is_usable() && self.disabled_reason.as_ref().is_none() {
            return Err(CapabilityError::MissingReason { state: self.state });
        }
        if let Some(reason) = self.disabled_reason.as_ref()
            && reason.len() > MAX_BROKER_REASON_LEN
        {
            return Err(CapabilityError::ReasonTooLong {
                length: reason.len(),
                limit: MAX_BROKER_REASON_LEN,
            });
        }
        Ok(())
    }

    /// Returns true when this change invalidates the record.
    #[must_use]
    pub fn invalidated_by(&self, change: InstanceInvalidation) -> bool {
        self.invalidated_by.contains(&change)
    }
}

/// A capability record that breaks one of section 11's rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityError {
    /// A source that cannot establish a working capability claimed one.
    #[error(
        "{evidence_source} evidence cannot establish that a capability is qualified on this host"
    )]
    UnqualifiedSource {
        /// The source that overreached.
        evidence_source: InstanceEvidenceSource,
    },
    /// An unusable state carried no reason.
    #[error("state {state} needs a user-facing disabled reason")]
    MissingReason {
        /// The state that carried none.
        state: InstanceCapabilityState,
    },
    /// A package declaration claimed a version had been qualified.
    #[error("a package declaration cannot establish that a capability version was qualified")]
    DeclaredQualification,
    /// The record named nothing that would make it stale.
    #[error("a capability record must name at least one change that invalidates it")]
    NoInvalidation,
    /// A record from a signed profile did not name the profile it came from.
    #[error("a record from a signed profile must name that profile's digest")]
    MissingProfileIdentity,
    /// An update carried a revision that is not newer than the record it would replace.
    #[error("a capability record at revision {held} is not replaced by one at {offered}")]
    StaleUpdate {
        /// The revision the map holds.
        held: CapabilityRevision,
        /// The revision the update offered.
        offered: CapabilityRevision,
    },
    /// The reason was longer than a person will read.
    #[error("a disabled reason is at most {limit} bytes, and this one is {length}")]
    ReasonTooLong {
        /// How long it was.
        length: usize,
        /// The limit.
        limit: usize,
    },
}

/// Everything one installation of one application can currently do.
///
/// Section 12: "The feature set is a per-installation capability map, not a single label assigned
/// to an agent name." Two installations of the same agent, at different versions or with different
/// permissions, have different maps.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CapabilityMap {
    /// The records, ordered by capability so the map encodes deterministically.
    pub records: Vec<InstanceCapabilityRecord>,
}

impl CapabilityMap {
    /// Returns the record for one capability, if the map holds one.
    #[must_use]
    pub fn record(&self, capability: &CapabilityId) -> Option<&InstanceCapabilityRecord> {
        self.records
            .iter()
            .find(|record| &record.capability_id == capability)
    }

    /// Returns the capabilities that are usable now.
    pub fn usable(&self) -> impl Iterator<Item = &InstanceCapabilityRecord> {
        self.records
            .iter()
            .filter(|record| record.state.is_usable())
    }

    /// Adds or replaces one record, keeping the map ordered by capability.
    ///
    /// A record only moves forward. An update at a revision the map has already passed is refused
    /// rather than applied: a late answer from a probe that started before an invalidation would
    /// otherwise restore availability the host had already withdrawn.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::StaleUpdate`] when the offered revision is not newer than the
    /// one held, and whatever [`InstanceCapabilityRecord::validate`] refuses.
    pub fn upsert(&mut self, record: InstanceCapabilityRecord) -> Result<(), CapabilityError> {
        record.validate()?;
        match self
            .records
            .binary_search_by(|held| held.capability_id.cmp(&record.capability_id))
        {
            Ok(position) => {
                let held = &self.records[position];
                if record.revision.get() <= held.revision.get() {
                    return Err(CapabilityError::StaleUpdate {
                        held: held.revision,
                        offered: record.revision,
                    });
                }
                self.records[position] = record;
            }
            Err(position) => self.records.insert(position, record),
        }
        Ok(())
    }

    /// Invalidates every record the change makes stale, returning how many were affected.
    ///
    /// A record whose triggers do not name the change is left exactly as it was. That is what
    /// keeps an installed upgrade from invalidating an old running process's pinned evidence: the
    /// running binding's record names the binding, and the change names the binary.
    pub fn invalidate(
        &mut self,
        change: InstanceInvalidation,
        reason: &str,
        now: TimestampMs,
    ) -> usize {
        let mut affected = 0;
        for record in &mut self.records {
            if record.invalidated_by.contains(&change)
                && record.state != InstanceCapabilityState::NotTested
            {
                record.state = InstanceCapabilityState::NotTested;
                record.source = InstanceEvidenceSource::HostProbe;
                record.disabled_reason = Nullable::some(reason.to_owned());
                record.revision = CapabilityRevision::new(record.revision.get().saturating_add(1));
                record.observed_at = now;
                affected += 1;
            }
        }
        affected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalars::Uuid;

    fn actor(name: &str) -> ActorId {
        ActorId::new(name).expect("a short actor principal is valid")
    }

    fn token() -> ActionToken {
        ActionToken {
            token_id: ActionTokenId::new("token-1").expect("a short handle is valid"),
            actor_id: actor("device-1"),
            grant: BrokerGrant::UpstreamAction,
            grant_id: Nullable::some(GrantId::new(Uuid::from_bytes([7; 16]))),
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
            binding_revision: AgentBindingRevision::new(4),
            action: ActionName::new("prompt.submit").expect("a valid action name"),
            parameter_hash: Digest256::from_bytes([1; 32]),
            draft_id: Nullable::null(),
            issued_at: TimestampMs::new(1_000),
        }
    }

    #[test]
    fn the_three_grants_are_independent() {
        let mut grants = BrokerGrants::granted([BrokerGrant::Observation]);
        assert!(grants.is_display_only());
        assert!(grants.require(BrokerGrant::UpstreamAction).is_err());
        assert!(grants.require(BrokerGrant::ApprovalInterpreter).is_err());
        grants.insert(BrokerGrant::UpstreamAction);
        assert!(!grants.is_display_only());
        assert!(grants.require(BrokerGrant::UpstreamAction).is_ok());
        assert!(grants.require(BrokerGrant::ApprovalInterpreter).is_err());
    }

    #[test]
    fn only_the_approval_interpreter_may_create_an_approval() {
        assert!(!BrokerGrant::Observation.may_create_approval());
        assert!(!BrokerGrant::UpstreamAction.may_create_approval());
        assert!(BrokerGrant::ApprovalInterpreter.may_create_approval());
    }

    #[test]
    fn a_token_binds_all_five_of_its_subjects() {
        let issued = token();
        let claim = ActionTokenClaim::from(&issued);
        assert!(issued.check(&claim).is_ok());

        for (field, mutate) in [
            (
                "actor_id",
                (|claim: &mut ActionTokenClaim| {
                    claim.actor_id = actor("device-2");
                }) as fn(&mut ActionTokenClaim),
            ),
            ("grant", |claim| claim.grant = BrokerGrant::Observation),
            ("action", |claim| {
                claim.action = ActionName::new("turn.cancel").expect("valid");
            }),
            ("parameter_hash", |claim| {
                claim.parameter_hash = Digest256::from_bytes([2; 32]);
            }),
        ] {
            let mut tampered = ActionTokenClaim::from(&issued);
            mutate(&mut tampered);
            assert_eq!(
                issued.check(&tampered),
                Err(TokenError::Mismatch { field }),
                "{field} was not checked"
            );
        }

        let mut moved = ActionTokenClaim::from(&issued);
        moved.binding_revision = AgentBindingRevision::new(5);
        assert!(matches!(
            issued.check(&moved),
            Err(TokenError::StaleBinding { .. })
        ));
    }

    #[test]
    fn a_token_is_rechecked_against_the_revision_in_force() {
        let issued = token();
        assert!(
            issued
                .check_current_revision(AgentBindingRevision::new(4))
                .is_ok()
        );
        assert!(matches!(
            issued.check_current_revision(AgentBindingRevision::new(5)),
            Err(TokenError::StaleBinding { .. })
        ));
    }

    #[test]
    fn terminal_input_is_never_an_authoritative_result() {
        assert!(!ActionProvenance::TerminalInput.is_authoritative());
        assert!(ActionProvenance::UpstreamTypedRpc.is_authoritative());
        assert!(ActionProvenance::AuthenticatedHookResponse.is_authoritative());
    }

    #[test]
    fn a_signed_record_cannot_say_a_capability_works_here() {
        let mut record = InstanceCapabilityRecord {
            capability_id: CapabilityId::new("agent.prompt").expect("valid"),
            capability_version: "1".to_owned(),
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
            identity: InstanceCapabilityIdentity::default(),
            revision: CapabilityRevision::new(1),
            state: InstanceCapabilityState::QualifiedAvailable,
            source: InstanceEvidenceSource::SignedRecord,
            invalidated_by: [InstanceInvalidation::BinaryChanged].into_iter().collect(),
            disabled_reason: Nullable::null(),
            observed_at: TimestampMs::new(1),
        };
        assert!(matches!(
            record.validate(),
            Err(CapabilityError::UnqualifiedSource { .. })
        ));
        record.source = InstanceEvidenceSource::HostProbe;
        assert!(record.validate().is_ok());
        record.state = InstanceCapabilityState::PermissionRequired;
        assert!(matches!(
            record.validate(),
            Err(CapabilityError::MissingReason { .. })
        ));
    }

    #[test]
    fn an_upgrade_leaves_a_pinned_running_binding_alone() {
        let mut map = CapabilityMap::default();
        map.upsert(InstanceCapabilityRecord {
            capability_id: CapabilityId::new("agent.prompt").expect("valid"),
            capability_version: "1".to_owned(),
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
            identity: InstanceCapabilityIdentity {
                binding_id: Nullable::some(BrokerBindingId::new(Uuid::from_bytes([9; 16]))),
                ..InstanceCapabilityIdentity::default()
            },
            revision: CapabilityRevision::new(1),
            state: InstanceCapabilityState::QualifiedAvailable,
            source: InstanceEvidenceSource::LiveBinding,
            invalidated_by: [InstanceInvalidation::BindingChanged].into_iter().collect(),
            disabled_reason: Nullable::null(),
            observed_at: TimestampMs::new(1),
        })
        .expect("a fresh record is accepted");
        map.upsert(InstanceCapabilityRecord {
            capability_id: CapabilityId::new("agent.commands").expect("valid"),
            capability_version: "1".to_owned(),
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
            identity: InstanceCapabilityIdentity {
                binary_digest: Nullable::some(Digest256::from_bytes([4; 32])),
                ..InstanceCapabilityIdentity::default()
            },
            revision: CapabilityRevision::new(1),
            state: InstanceCapabilityState::QualifiedAvailable,
            source: InstanceEvidenceSource::HostProbe,
            invalidated_by: [InstanceInvalidation::BinaryChanged].into_iter().collect(),
            disabled_reason: Nullable::null(),
            observed_at: TimestampMs::new(1),
        })
        .expect("a fresh record is accepted");

        let affected = map.invalidate(
            InstanceInvalidation::BinaryChanged,
            "the executable was upgraded",
            TimestampMs::new(2),
        );
        assert_eq!(affected, 1);
        let pinned = map
            .record(&CapabilityId::new("agent.prompt").expect("valid"))
            .expect("the running binding's record is still there");
        assert_eq!(pinned.state, InstanceCapabilityState::QualifiedAvailable);
        assert_eq!(pinned.revision, CapabilityRevision::new(1));
        let upgraded = map
            .record(&CapabilityId::new("agent.commands").expect("valid"))
            .expect("the probed record is still there");
        assert_eq!(upgraded.state, InstanceCapabilityState::NotTested);
        assert_eq!(upgraded.revision, CapabilityRevision::new(2));
    }

    #[test]
    fn a_trust_record_names_the_methods_it_covers() {
        let trust = DecodingTrust {
            plugin_id: PluginId::new("kalareach.codex").expect("valid"),
            publisher_id: PublisherId::new("kalareach").expect("valid"),
            package_digest: Digest256::from_bytes([5; 32]),
            methods: [UpstreamMethod::new("session/request_permission").expect("valid")]
                .into_iter()
                .collect(),
            schema_versions: ["kr-approval/1".to_owned()].into_iter().collect(),
            max_decisions: U64::new(4),
            may_encode_response: true,
            granted_at: TimestampMs::new(1),
        };
        assert!(trust.validate().is_ok());
        assert!(trust.covers(&UpstreamMethod::new("session/request_permission").expect("valid")));
        assert!(!trust.covers(&UpstreamMethod::new("fs/write_text_file").expect("valid")));

        let empty = DecodingTrust {
            methods: CanonicalSet::new(),
            ..trust
        };
        assert_eq!(empty.validate(), Err(TrustError::NoMethods));
    }

    fn decoding_trust() -> DecodingTrust {
        DecodingTrust {
            plugin_id: PluginId::new("kalareach.codex").expect("valid"),
            publisher_id: PublisherId::new("kalareach").expect("valid"),
            package_digest: Digest256::from_bytes([5; 32]),
            methods: [UpstreamMethod::new("session/request_permission").expect("valid")]
                .into_iter()
                .collect(),
            schema_versions: ["kr-approval/1".to_owned()].into_iter().collect(),
            max_decisions: U64::new(3),
            may_encode_response: true,
            granted_at: TimestampMs::new(1),
        }
    }

    fn projection(schema: &str, ids: &[&str]) -> DecodedProjection {
        DecodedProjection {
            schema_version: schema.to_owned(),
            summary: "the agent wants to write a file".to_owned(),
            decisions: ids
                .iter()
                .map(|option_id| OfferedDecision {
                    option_id: (*option_id).to_owned(),
                    label: format!("choose {option_id}"),
                })
                .collect(),
        }
    }

    #[test]
    fn trust_belongs_to_one_package_at_one_digest() {
        let trust = decoding_trust();
        assert!(trust.belongs_to(
            &PluginId::new("kalareach.codex").expect("valid"),
            &PublisherId::new("kalareach").expect("valid"),
            &Digest256::from_bytes([5; 32])
        ));
        assert!(
            !trust.belongs_to(
                &PluginId::new("someone.else").expect("valid"),
                &PublisherId::new("kalareach").expect("valid"),
                &Digest256::from_bytes([5; 32])
            ),
            "one package's trust is never another's"
        );
        assert!(
            !trust.belongs_to(
                &PluginId::new("kalareach.codex").expect("valid"),
                &PublisherId::new("kalareach").expect("valid"),
                &Digest256::from_bytes([6; 32])
            ),
            "different bytes are a different decoder"
        );
    }

    #[test]
    fn a_projection_is_checked_against_the_schema_policy_it_was_granted() {
        let trust = decoding_trust();
        trust
            .check_projection(&projection("kr-approval/1", &["allow", "deny"]))
            .expect("a projection under the covered schema is accepted");
        assert_eq!(
            trust.check_projection(&projection("kr-approval/2", &["allow"])),
            Err(TrustError::SchemaNotCovered)
        );
        assert_eq!(
            trust.check_projection(&projection("kr-approval/1", &[])),
            Err(TrustError::NoDecisions)
        );
        assert!(matches!(
            trust.check_projection(&projection("kr-approval/1", &["a", "b", "c", "d"])),
            Err(TrustError::TooManyDecisions { .. })
        ));
        assert_eq!(
            trust.check_projection(&projection("kr-approval/1", &["allow", "allow"])),
            Err(TrustError::DuplicateDecision)
        );
        assert_eq!(
            trust.check_projection(&projection("kr-approval/1", &[""])),
            Err(TrustError::DecisionText)
        );
        let mut verbose = projection("kr-approval/1", &["allow"]);
        verbose.summary = "a".repeat(MAX_PROJECTION_SUMMARY_LEN + 1);
        assert!(matches!(
            trust.check_projection(&verbose),
            Err(TrustError::SummaryTooLong { .. })
        ));
    }

    #[test]
    fn a_ledger_entry_answers_only_what_the_request_offered() {
        let entry = DecoderLedgerEntry {
            binding_id: BrokerBindingId::new(Uuid::from_bytes([9; 16])),
            plugin_id: PluginId::new("kalareach.codex").expect("valid"),
            publisher_id: PublisherId::new("kalareach").expect("valid"),
            package_digest: Digest256::from_bytes([5; 32]),
            method: UpstreamMethod::new("session/request_permission").expect("valid"),
            upstream_request_id: UpstreamRequestId::new("11").expect("valid"),
            source_generation: SourceGeneration::new(1),
            source_digest: Digest256::from_bytes([6; 32]),
            source_bytes: Bytes::from(b"{\"id\":11}".to_vec()),
            projection: projection("kr-approval/1", &["allow", "deny"]),
            deadline_ms: Nullable::null(),
            decoded_at: TimestampMs::new(2),
        };
        assert!(entry.offers("allow"));
        assert!(entry.offers("deny"));
        assert!(
            !entry.offers("allow_always"),
            "an identifier the request never offered is not an answer this host encodes"
        );
        assert_eq!(entry.source_bytes.as_slice(), b"{\"id\":11}");
    }

    #[test]
    fn a_record_that_nothing_invalidates_is_refused() {
        let record = InstanceCapabilityRecord {
            capability_id: CapabilityId::new("agent.prompt").expect("valid"),
            capability_version: "1".to_owned(),
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
            identity: InstanceCapabilityIdentity::default(),
            revision: CapabilityRevision::new(1),
            state: InstanceCapabilityState::QualifiedAvailable,
            source: InstanceEvidenceSource::HostProbe,
            invalidated_by: CanonicalSet::new(),
            disabled_reason: Nullable::null(),
            observed_at: TimestampMs::new(1),
        };
        assert_eq!(record.validate(), Err(CapabilityError::NoInvalidation));
    }

    #[test]
    fn a_signed_record_names_the_profile_it_came_from() {
        let record = InstanceCapabilityRecord {
            capability_id: CapabilityId::new("agent.prompt").expect("valid"),
            capability_version: "1".to_owned(),
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
            identity: InstanceCapabilityIdentity::default(),
            revision: CapabilityRevision::new(1),
            state: InstanceCapabilityState::VersionQualified,
            source: InstanceEvidenceSource::SignedRecord,
            invalidated_by: [InstanceInvalidation::QualificationProfileChanged]
                .into_iter()
                .collect(),
            disabled_reason: Nullable::some("not tried on this host".to_owned()),
            observed_at: TimestampMs::new(1),
        };
        assert_eq!(
            record.validate(),
            Err(CapabilityError::MissingProfileIdentity)
        );
        let named = InstanceCapabilityRecord {
            identity: InstanceCapabilityIdentity {
                qualification_profile_digest: Nullable::some(Digest256::from_bytes([8; 32])),
                ..InstanceCapabilityIdentity::default()
            },
            ..record
        };
        named.validate().expect("a named profile is accepted");
    }

    #[test]
    fn a_late_answer_never_restores_evidence_the_host_withdrew() {
        let mut map = CapabilityMap::default();
        let qualified = InstanceCapabilityRecord {
            capability_id: CapabilityId::new("agent.prompt").expect("valid"),
            capability_version: "1".to_owned(),
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
            identity: InstanceCapabilityIdentity::default(),
            revision: CapabilityRevision::new(1),
            state: InstanceCapabilityState::QualifiedAvailable,
            source: InstanceEvidenceSource::HostProbe,
            invalidated_by: [InstanceInvalidation::BinaryChanged].into_iter().collect(),
            disabled_reason: Nullable::null(),
            observed_at: TimestampMs::new(1),
        };
        map.upsert(qualified.clone()).expect("the first record");
        map.invalidate(
            InstanceInvalidation::BinaryChanged,
            "the executable was upgraded",
            TimestampMs::new(2),
        );
        assert!(matches!(
            map.upsert(qualified),
            Err(CapabilityError::StaleUpdate { .. })
        ));
        assert_eq!(
            map.record(&CapabilityId::new("agent.prompt").expect("valid"))
                .expect("still recorded")
                .state,
            InstanceCapabilityState::NotTested
        );
    }
}
