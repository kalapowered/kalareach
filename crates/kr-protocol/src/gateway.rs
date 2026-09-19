//! The native proxy contract: the declarative table, the closed rich method table, namespaced
//! request identifiers, the pending-resource transition and volatile-native mode.
//!
//! Section 11 draws a line through the gateway. On one side is the **core-declarative** path: a
//! connector supplies a qualified table that says how its protocol frames, where its request
//! identifiers live, how responses correlate and what each method does, and core code interprets
//! that table without calling a component. On the other side is **rich** meaning: a component
//! decodes a request into something a person can answer and encodes the answer back. The first
//! path must keep working when the second one does not.
//!
//! Three rules follow from that, and they are what this module enforces.
//!
//! * **Unclassified is mutating.** [`DeclarativeTable::classify`] answers
//!   [`NativeMethodClass::Mutation`] for a method the table does not list, and says the answer was
//!   presumed rather than declared. A request nobody classified is the one most likely to change
//!   rich state, so it suspends rich mutations while its opaque forwarding continues.
//! * **The rich table is closed.** [`RichMethodTable::admit`] rejects an unknown rich mutation
//!   outright. A gateway that guessed would be inventing an effect under an audited name.
//! * **One resolution per resource.** [`PendingState`] permits exactly one transition out of
//!   `Claimed`, and reconnect reconciles what happened rather than sending a second answer. An
//!   uncertain outcome stays uncertain; it is never resolved by repeating the request.

use core::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::broker::ActionProvenance;
use crate::ids::{
    ApplicationInstanceId, GatewayConnectionId, MethodTableVersion, PendingResourceId, PluginId,
    PublisherId, SourceGeneration, UpstreamMethod, UpstreamRequestId,
};
use crate::rights::ActionRight;
use crate::scalars::{Digest256, Nullable, TimestampMs, U64};
use crate::session::Durability;

/// How many methods one declarative or rich table may classify.
///
/// A table is a contract a person can read, not a dump of a vendor's surface.
pub const MAX_TABLE_METHODS: usize = 256;

/// The domain a declarative table's content digest is separated by.
pub const DECLARATIVE_TABLE_DOMAIN: &str = "kr-declarative-table/1";

// ---------------------------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------------------------

/// What one upstream method does.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum NativeMethodClass {
    /// It reports state and changes none.
    Observation,
    /// It changes upstream state.
    Mutation,
    /// It reads or writes credentials or configuration.
    ///
    /// Separate from a mutation because a write grant is not a provider-credential grant.
    CredentialOrConfiguration,
    /// This build does not support it.
    Unsupported,
}

impl NativeMethodClass {
    /// Every class, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Observation,
        Self::Mutation,
        Self::CredentialOrConfiguration,
        Self::Unsupported,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Mutation => "mutation",
            Self::CredentialOrConfiguration => "credential_or_configuration",
            Self::Unsupported => "unsupported",
        }
    }

    /// Returns true when a request of this class can change what a rich client is showing.
    #[must_use]
    pub const fn affects_rich_state(self) -> bool {
        matches!(self, Self::Mutation | Self::CredentialOrConfiguration)
    }
}

impl fmt::Display for NativeMethodClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A classification, and whether the table actually said so.
///
/// The distinction is the whole of section 11's safety rule for the native path. A declared
/// mutation is forwarded and its rich effects are known. An *undeclared* one is forwarded exactly
/// the same way and suspends rich mutations until the binding is reconciled, because the host does
/// not know what it did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NativeClassification {
    /// What the request is taken to do.
    pub class: NativeMethodClass,
    /// True when the table listed the method; false when the class was presumed.
    pub declared: bool,
}

impl NativeClassification {
    /// A class the table stated.
    #[must_use]
    pub const fn declared(class: NativeMethodClass) -> Self {
        Self {
            class,
            declared: true,
        }
    }

    /// The presumption for a method the table does not list.
    #[must_use]
    pub const fn presumed_mutation() -> Self {
        Self {
            class: NativeMethodClass::Mutation,
            declared: false,
        }
    }

    /// Returns true when this request must suspend rich mutations until reconciliation.
    #[must_use]
    pub const fn suspends_rich_mutations(&self) -> bool {
        !self.declared
    }
}

// ---------------------------------------------------------------------------------------------
// The declarative table
// ---------------------------------------------------------------------------------------------

/// How a connector's protocol frames on the wire.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum NativeFraming {
    /// One JSON object per line.
    JsonLines,
    /// A decimal byte length, a newline, then that many bytes.
    LengthPrefixed,
    /// Header lines, a blank line, then a body of the declared length.
    ContentLength,
}

impl NativeFraming {
    /// Every framing, in declaration order.
    pub const ALL: &'static [Self] = &[Self::JsonLines, Self::LengthPrefixed, Self::ContentLength];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JsonLines => "json_lines",
            Self::LengthPrefixed => "length_prefixed",
            Self::ContentLength => "content_length",
        }
    }
}

impl fmt::Display for NativeFraming {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One entry of a connector's declarative table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DeclarativeEntry {
    /// The upstream method this entry classifies.
    pub method: UpstreamMethod,
    /// What it does.
    pub class: NativeMethodClass,
    /// True when the upstream sends this as a request that expects a response.
    ///
    /// A reverse request creates a pending resource; a notification does not.
    pub expects_response: bool,
    /// What this method asks the host to perform, when it asks for anything.
    ///
    /// Section 12 has the upstream ask this host for filesystem and terminal operations, and they
    /// run in the agent's own host environment. Which of its methods ask for that is a fact about
    /// the protocol, so the qualified table states it rather than leaving the core to guess from a
    /// method name.
    pub reverse: Nullable<ReverseOperation>,
    /// The member of a response's result that carries the decision, for a method a person answers.
    ///
    /// An approval's answer is written by the core, so the core has to know the shape the upstream
    /// reads. Protocols disagree about it: one wants `{"option_id": "allow"}` and the next wants
    /// `{"behavior": "allow"}`. The qualified table states the member name, and a method that
    /// names none is one this host will not write an answer for.
    pub approval_option_field: Nullable<String>,
}

/// A connector's qualified declarative table.
///
/// Core code interprets this without calling Wasm, which is what makes the forwarding path
/// independent of the component runtime. The table is pinned to one upstream protocol version and
/// carries the publisher whose semantic trust grant qualifies it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DeclarativeTable {
    /// The package that supplied the table.
    pub plugin_id: PluginId,
    /// The publisher whose semantic trust grant qualifies it.
    pub publisher_id: PublisherId,
    /// The version of the table itself.
    pub table_version: MethodTableVersion,
    /// The upstream protocol version the table is pinned to.
    pub upstream_protocol_version: String,
    /// The digest of the exact table bytes, so a qualification names what was qualified.
    pub digest: Digest256,
    /// How the protocol frames.
    pub framing: NativeFraming,
    /// The member of a frame that carries its request identifier.
    pub request_id_field: String,
    /// The member of a frame that carries the identifier a response correlates to.
    pub response_id_field: String,
    /// The member of a frame that carries its method name.
    pub method_field: String,
    /// The member a request carries its parameters in.
    ///
    /// Core code encodes a rich mutation into this member. Without it the core would know where to
    /// read an identifier and a method and would still have nowhere to put what the operation
    /// actually asks for.
    pub params_field: String,
    /// The member a successful response carries its result in.
    pub result_field: String,
    /// The member a failed response carries its error in.
    ///
    /// A response names exactly one of these two. A frame that names both, or neither, is not a
    /// response this host will correlate: it would otherwise resolve a pending resource on the
    /// strength of nothing but a matching identifier.
    pub error_field: String,
    /// The entries, ordered by method so the table encodes deterministically.
    pub entries: Vec<DeclarativeEntry>,
}

impl DeclarativeTable {
    /// Returns one of the members a frame is read by, named as `validate` names it.
    fn member(&self, field: &str) -> &str {
        match field {
            "request_id_field" => &self.request_id_field,
            "response_id_field" => &self.response_id_field,
            "method_field" => &self.method_field,
            "params_field" => &self.params_field,
            "result_field" => &self.result_field,
            "error_field" => &self.error_field,
            _ => "",
        }
    }

    /// Returns what one method asks this host to perform, when it asks for anything.
    #[must_use]
    pub fn reverse_of(&self, method: &UpstreamMethod) -> Option<ReverseOperation> {
        self.entries
            .iter()
            .find(|entry| &entry.method == method)
            .and_then(|entry| entry.reverse.as_ref().copied())
    }

    /// Returns the member an answer to one method carries the decision in.
    #[must_use]
    pub fn approval_option_field(&self, method: &UpstreamMethod) -> Option<&str> {
        self.entries
            .iter()
            .find(|entry| &entry.method == method)
            .and_then(|entry| entry.approval_option_field.as_ref())
            .map(String::as_str)
    }

    /// Returns the digest of everything this table says about the protocol.
    ///
    /// It covers every semantic field: the framing, the member names the core reads a frame by,
    /// and each entry's method, class, response expectation, reverse operation and answer shape.
    /// It does not cover the [`digest`](Self::digest) member itself, which is where this value is
    /// recorded.
    ///
    /// The reason it exists is the one section 11 states: a table is qualified under the
    /// publisher's semantic trust grant, and a qualification has to name what was qualified.
    /// A digest over labels alone would let a package keep the digest of a qualified table while
    /// changing what the core does with its frames.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when a field cannot be represented in KR-CBOR-1.
    pub fn canonical_digest(&self) -> Result<Digest256, kr_cbor::CborError> {
        let mut covered = kr_cbor::CanonicalMap::new();
        covered.insert(
            "entries".to_owned(),
            kr_cbor::to_canonical_value(&self.entries)?,
        )?;
        covered.insert(
            "error_field".to_owned(),
            kr_cbor::to_canonical_value(&self.error_field)?,
        )?;
        covered.insert(
            "framing".to_owned(),
            kr_cbor::to_canonical_value(&self.framing)?,
        )?;
        covered.insert(
            "method_field".to_owned(),
            kr_cbor::to_canonical_value(&self.method_field)?,
        )?;
        covered.insert(
            "params_field".to_owned(),
            kr_cbor::to_canonical_value(&self.params_field)?,
        )?;
        covered.insert(
            "plugin_id".to_owned(),
            kr_cbor::to_canonical_value(&self.plugin_id)?,
        )?;
        covered.insert(
            "publisher_id".to_owned(),
            kr_cbor::to_canonical_value(&self.publisher_id)?,
        )?;
        covered.insert(
            "request_id_field".to_owned(),
            kr_cbor::to_canonical_value(&self.request_id_field)?,
        )?;
        covered.insert(
            "response_id_field".to_owned(),
            kr_cbor::to_canonical_value(&self.response_id_field)?,
        )?;
        covered.insert(
            "result_field".to_owned(),
            kr_cbor::to_canonical_value(&self.result_field)?,
        )?;
        covered.insert(
            "table_version".to_owned(),
            kr_cbor::to_canonical_value(&self.table_version)?,
        )?;
        covered.insert(
            "upstream_protocol_version".to_owned(),
            kr_cbor::to_canonical_value(&self.upstream_protocol_version)?,
        )?;
        Ok(Digest256::from_bytes(kr_cbor::sha256(&kr_cbor::encode(
            &kr_cbor::signing_value(
                DECLARATIVE_TABLE_DOMAIN,
                vec![kr_cbor::CanonicalValue::Map(covered)],
            ),
        ))))
    }

    /// Classifies one upstream method.
    ///
    /// A method the table does not list is presumed mutation-capable. That is the conservative
    /// direction and the one section 11 fixes: "Any unclassified native request is presumed
    /// mutation-capable for rich-state safety."
    #[must_use]
    pub fn classify(&self, method: &UpstreamMethod) -> NativeClassification {
        self.entries
            .iter()
            .find(|entry| &entry.method == method)
            .map_or_else(NativeClassification::presumed_mutation, |entry| {
                NativeClassification::declared(entry.class)
            })
    }

    /// Returns true when the upstream expects a response to this method.
    ///
    /// An unlisted method is treated as one that does, so a reverse request the table does not
    /// describe still becomes a pending resource rather than being silently dropped.
    #[must_use]
    pub fn expects_response(&self, method: &UpstreamMethod) -> bool {
        self.entries
            .iter()
            .find(|entry| &entry.method == method)
            .is_none_or(|entry| entry.expects_response)
    }

    /// Checks that the table is one the core can interpret.
    ///
    /// # Errors
    ///
    /// Returns [`TableError`] for an empty or over-long table, an unnamed field, or entries that
    /// are not in ascending method order, because an unordered table would encode differently on
    /// each pass and its digest would not identify it.
    pub fn validate(&self) -> Result<(), TableError> {
        if self.entries.is_empty() {
            return Err(TableError::Empty);
        }
        if self.entries.len() > MAX_TABLE_METHODS {
            return Err(TableError::TooManyMethods {
                methods: self.entries.len(),
                limit: MAX_TABLE_METHODS,
            });
        }
        for (field, value) in [
            ("request_id_field", &self.request_id_field),
            ("response_id_field", &self.response_id_field),
            ("method_field", &self.method_field),
            ("params_field", &self.params_field),
            ("result_field", &self.result_field),
            ("error_field", &self.error_field),
            ("upstream_protocol_version", &self.upstream_protocol_version),
        ] {
            if value.is_empty() {
                return Err(TableError::MissingField { field });
            }
        }
        // A request and a response may name their identifier the same way, as JSON-RPC does. The
        // other four say different things about a frame, so sharing a name would make one frame
        // two things at once: a table whose result member is also its identifier member turns
        // every bare identifier into a successful answer.
        for (first, second) in [
            ("response_id_field", "method_field"),
            ("response_id_field", "params_field"),
            ("response_id_field", "result_field"),
            ("response_id_field", "error_field"),
            ("method_field", "params_field"),
            ("method_field", "result_field"),
            ("method_field", "error_field"),
            ("params_field", "result_field"),
            ("params_field", "error_field"),
            ("result_field", "error_field"),
        ] {
            if self.member(first) == self.member(second) {
                return Err(TableError::RepeatedField { first, second });
            }
        }
        if !self
            .entries
            .windows(2)
            .all(|pair| pair[0].method < pair[1].method)
        {
            return Err(TableError::Unordered);
        }
        for entry in &self.entries {
            if entry
                .approval_option_field
                .as_ref()
                .is_some_and(String::is_empty)
            {
                return Err(TableError::MissingField {
                    field: "approval_option_field",
                });
            }
        }
        // And the digest names this table's own content. Without this the digest is a label a
        // package chooses, and every later comparison of it says only that the label is unchanged.
        let computed = self
            .canonical_digest()
            .map_err(|_| TableError::Unrepresentable)?;
        if computed != self.digest {
            return Err(TableError::DigestMismatch);
        }
        Ok(())
    }

    /// Checks that this table qualifies against the upstream version actually in use.
    ///
    /// # Errors
    ///
    /// Returns [`TableError::VersionMismatch`] when the pinned version is not the installed one.
    /// A table built for another version is not interpreted "close enough": a field that moved
    /// would make the core correlate the wrong response to a pending approval.
    pub fn qualify(&self, installed_protocol_version: &str) -> Result<(), TableError> {
        self.validate()?;
        if self.upstream_protocol_version == installed_protocol_version {
            Ok(())
        } else {
            Err(TableError::VersionMismatch {
                pinned: self.upstream_protocol_version.clone(),
                installed: installed_protocol_version.to_owned(),
            })
        }
    }
}

/// A declarative or rich table the core will not interpret.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TableError {
    /// The table classified nothing.
    #[error("a declarative table must classify at least one method")]
    Empty,
    /// The table classified more methods than one table may.
    #[error("a table classifies at most {limit} methods, and this one classifies {methods}")]
    TooManyMethods {
        /// How many it classified.
        methods: usize,
        /// The limit.
        limit: usize,
    },
    /// A field the core needs to read a frame was not named.
    #[error("a declarative table must name its {field}")]
    MissingField {
        /// Which field was missing.
        field: &'static str,
    },
    /// Two members that say different things about a frame were given one name.
    #[error("a table's {first} and {second} must name different members")]
    RepeatedField {
        /// The first of the pair.
        first: &'static str,
        /// The second.
        second: &'static str,
    },
    /// The entries were not in ascending method order.
    #[error("a table's entries must be in ascending method order")]
    Unordered,
    /// The recorded digest is not the digest of what the table says.
    #[error("this table's digest is not the digest of the protocol semantics it declares")]
    DigestMismatch,
    /// A field of the table cannot be represented canonically, so it cannot be digested.
    #[error("this table carries a field that cannot be encoded canonically")]
    Unrepresentable,
    /// Two methods claimed one of the core's own operations.
    #[error("a table names one method for {operation} and this one names several")]
    RepeatedOperation {
        /// The operation that was claimed twice.
        operation: RichOperation,
    },
    /// The table is pinned to another upstream version.
    #[error("this table is pinned to upstream protocol {pinned} and {installed} is installed")]
    VersionMismatch {
        /// The version the table names.
        pinned: String,
        /// The version actually installed.
        installed: String,
    },
}

// ---------------------------------------------------------------------------------------------
// The closed rich method table
// ---------------------------------------------------------------------------------------------

/// One operation the core carries to an upstream on a person's behalf.
///
/// Section 23 gives the five agent mutations five separate rights, and two of them share one:
/// submitting a prompt, queueing one and steering a turn all need `agent.prompt`. The right is
/// therefore not what names the upstream method, and this is: a table says which of its methods
/// each operation is, so submitting a prompt cannot encode as steering a turn.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RichOperation {
    /// Submit a prompt now.
    PromptSubmit,
    /// Queue a prompt behind the current turn.
    PromptQueue,
    /// Steer the turn that is running.
    TurnSteer,
    /// Cancel the turn that is running.
    TurnCancel,
    /// Answer a pending approval.
    ApprovalRespond,
    /// Invoke a registered plugin action.
    ///
    /// This one is named by the action the package declared rather than by the table, because the
    /// action *is* the method. The table still has to list it, so an unknown rich mutation is
    /// rejected rather than guessed at.
    PluginAction,
}

impl RichOperation {
    /// Every operation.
    pub const ALL: &'static [Self] = &[
        Self::PromptSubmit,
        Self::PromptQueue,
        Self::TurnSteer,
        Self::TurnCancel,
        Self::ApprovalRespond,
        Self::PluginAction,
    ];

    /// Returns the stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PromptSubmit => "prompt.submit",
            Self::PromptQueue => "prompt.queue",
            Self::TurnSteer => "turn.steer",
            Self::TurnCancel => "turn.cancel",
            Self::ApprovalRespond => "approval.respond",
            Self::PluginAction => "plugin.action",
        }
    }

    /// Returns true when a table entry names this operation.
    ///
    /// A plugin action is named by its own action name, so no entry claims it as an operation.
    #[must_use]
    pub const fn is_named_by_the_table(self) -> bool {
        !matches!(self, Self::PluginAction)
    }
}

impl fmt::Display for RichOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One entry of the closed rich method table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RichMethodEntry {
    /// The upstream method.
    pub method: UpstreamMethod,
    /// What it does.
    pub class: NativeMethodClass,
    /// The right an actor must hold to invoke it through the gateway.
    pub required_right: ActionRight,
    /// The operation this method is, where it is one of the core's own.
    ///
    /// A table may also list a method that no core operation encodes, which is why this is
    /// optional: it is listed so the method is admissible, not so the core will send it.
    pub operation: Nullable<RichOperation>,
    /// How a successful invocation's provenance is recorded.
    pub provenance: ActionProvenance,
}

/// The closed, versioned method table for rich actions.
///
/// Section 12: "The gateway has a closed, versioned method table for rich/API actions... Reject
/// unknown rich/API mutations." Closed means exactly that: a method with no entry is refused, and
/// a method classified as unsupported is refused with its own reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RichMethodTable {
    /// The version of this table.
    pub table_version: MethodTableVersion,
    /// The upstream protocol version it is pinned to.
    pub upstream_protocol_version: String,
    /// The entries, ordered by method.
    pub entries: Vec<RichMethodEntry>,
}

impl RichMethodTable {
    /// Returns the entry for one method, if the table lists it.
    #[must_use]
    pub fn entry(&self, method: &UpstreamMethod) -> Option<&RichMethodEntry> {
        self.entries.iter().find(|entry| &entry.method == method)
    }

    /// Admits one rich invocation, or refuses it.
    ///
    /// # Errors
    ///
    /// Returns [`RichRejection::Unknown`] for a method with no entry and
    /// [`RichRejection::Unsupported`] for one this build classifies as unsupported. Neither is
    /// approximated under a neighbouring name.
    pub fn admit(&self, method: &UpstreamMethod) -> Result<&RichMethodEntry, RichRejection> {
        let Some(entry) = self.entry(method) else {
            return Err(RichRejection::Unknown {
                method: method.clone(),
            });
        };
        if entry.class == NativeMethodClass::Unsupported {
            return Err(RichRejection::Unsupported {
                method: method.clone(),
            });
        }
        Ok(entry)
    }

    /// Returns the admitted entry for one core operation.
    ///
    /// This is the only way the core chooses what to send. It is by operation rather than by the
    /// right the operation needs, because three operations share one right and sending any of the
    /// three as another is sending something nobody asked for.
    ///
    /// # Errors
    ///
    /// Returns [`RichRejection::NoOperation`] when the table names no method for the operation or
    /// names more than one, and whatever [`RichMethodTable::admit`] refuses for the method found.
    pub fn for_operation(
        &self,
        operation: RichOperation,
    ) -> Result<&RichMethodEntry, RichRejection> {
        let mut found = self
            .entries
            .iter()
            .filter(|entry| entry.operation.as_ref() == Some(&operation));
        let entry = found
            .next()
            .ok_or(RichRejection::NoOperation { operation })?;
        // Two methods for one operation is a table that does not say what to send, and picking
        // the first would make the answer depend on the order somebody wrote it in.
        if found.next().is_some() {
            return Err(RichRejection::NoOperation { operation });
        }
        self.admit(&entry.method)
    }

    /// Checks that the table is well formed and pinned to the installed upstream version.
    ///
    /// # Errors
    ///
    /// Returns the same [`TableError`] values a declarative table does.
    pub fn qualify(&self, installed_protocol_version: &str) -> Result<(), TableError> {
        if self.entries.is_empty() {
            return Err(TableError::Empty);
        }
        if self.entries.len() > MAX_TABLE_METHODS {
            return Err(TableError::TooManyMethods {
                methods: self.entries.len(),
                limit: MAX_TABLE_METHODS,
            });
        }
        if !self
            .entries
            .windows(2)
            .all(|pair| pair[0].method < pair[1].method)
        {
            return Err(TableError::Unordered);
        }
        // One operation, one method. A table that names two methods for submitting a prompt does
        // not say which one to send, and the core will not choose for it.
        for operation in RichOperation::ALL
            .iter()
            .filter(|operation| operation.is_named_by_the_table())
        {
            let named = self
                .entries
                .iter()
                .filter(|entry| entry.operation.as_ref() == Some(operation))
                .count();
            if named > 1 {
                return Err(TableError::RepeatedOperation {
                    operation: *operation,
                });
            }
        }
        if self.upstream_protocol_version == installed_protocol_version {
            Ok(())
        } else {
            Err(TableError::VersionMismatch {
                pinned: self.upstream_protocol_version.clone(),
                installed: installed_protocol_version.to_owned(),
            })
        }
    }
}

/// A rich invocation the closed table refuses.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RichRejection {
    /// The method has no entry in the closed table.
    #[error("{method} is not in this build's rich method table")]
    Unknown {
        /// The method that was named.
        method: UpstreamMethod,
    },
    /// The method is listed and this build does not support it.
    #[error("{method} is listed as unsupported in this build")]
    Unsupported {
        /// The method that was named.
        method: UpstreamMethod,
    },
    /// The table names no single method for one of the core's own operations.
    #[error("this upstream's rich table names no one method for {operation}")]
    NoOperation {
        /// The operation the core was asked to encode.
        operation: RichOperation,
    },
}

// ---------------------------------------------------------------------------------------------
// Namespaced identifiers
// ---------------------------------------------------------------------------------------------

/// One downstream JSON-RPC identifier, namespaced by the connection that chose it.
///
/// Section 12: "Namespace downstream JSON-RPC IDs by connection." Two connections that both call
/// their first request `1` are two different pending resources, and nothing in the gateway can
/// confuse one for the other.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DownstreamRequestId {
    /// The connection the identifier belongs to.
    pub connection: GatewayConnectionId,
    /// The identifier exactly as the upstream wrote it.
    pub upstream: UpstreamRequestId,
}

impl DownstreamRequestId {
    /// Namespaces one upstream identifier.
    #[must_use]
    pub const fn new(connection: GatewayConnectionId, upstream: UpstreamRequestId) -> Self {
        Self {
            connection,
            upstream,
        }
    }
}

impl fmt::Display for DownstreamRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.connection, self.upstream)
    }
}

// ---------------------------------------------------------------------------------------------
// Pending resources
// ---------------------------------------------------------------------------------------------

/// What a pending resource is doing.
///
/// The state machine is small because the contract is small: a resource is offered once, claimed
/// once, and reaches exactly one terminal state. There is no edge back out of a terminal state,
/// so a reconnect cannot revive a resolved resource and answer it again.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PendingState {
    /// Recorded and waiting for an answer.
    Pending,
    /// One actor's answer is encoding. No other answer may claim it.
    Claimed,
    /// The answer reached the upstream.
    Resolved,
    /// The upstream withdrew or cancelled the request.
    Cancelled,
    /// The deadline passed without an answer.
    Expired,
    /// An answer was dispatched and its outcome cannot be established.
    ///
    /// Reconnect reconciles this; it never reissues. Section 11: it "does not reissue an uncertain
    /// response".
    Uncertain,
}

impl PendingState {
    /// Every state, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Pending,
        Self::Claimed,
        Self::Resolved,
        Self::Cancelled,
        Self::Expired,
        Self::Uncertain,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Claimed => "claimed",
            Self::Resolved => "resolved",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Uncertain => "uncertain",
        }
    }

    /// Returns true when nothing further can happen to a resource in this state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Resolved | Self::Cancelled | Self::Expired | Self::Uncertain
        )
    }

    /// The states this one may move to.
    #[must_use]
    pub const fn permitted_transitions(self) -> &'static [Self] {
        match self {
            // A pending request can be claimed by an answer, withdrawn by its upstream, or run
            // out of time. It cannot go straight to resolved: an answer is always claimed first,
            // which is what makes one answer win.
            Self::Pending => &[Self::Claimed, Self::Cancelled, Self::Expired],
            // A claim ends in one of three ways, or is given up. `Cancelled` is there because a
            // native answer arriving during encoding wins, and the claim it beat is released as
            // the upstream's own resolution rather than as a second dispatch. `Pending` is there
            // because a claim that never dispatched anything can be handed back: what stops a
            // second answer is the dispatch marker, not the claim, and a resource nobody answered
            // is one somebody should still be able to.
            Self::Claimed => &[
                Self::Resolved,
                Self::Uncertain,
                Self::Cancelled,
                Self::Pending,
            ],
            Self::Resolved | Self::Cancelled | Self::Expired | Self::Uncertain => &[],
        }
    }

    /// Returns true when this transition is one the contract permits.
    #[must_use]
    pub fn may_become(self, next: Self) -> bool {
        self.permitted_transitions().contains(&next)
    }
}

impl fmt::Display for PendingState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What kind of thing is pending.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PendingKind {
    /// An upstream approval request.
    Approval,
    /// A reverse remote procedure call for a filesystem or terminal operation.
    ReverseRpc,
    /// An action this host prepared against the upstream.
    UpstreamAction,
}

impl PendingKind {
    /// Every kind, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Approval, Self::ReverseRpc, Self::UpstreamAction];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::ReverseRpc => "reverse_rpc",
            Self::UpstreamAction => "upstream_action",
        }
    }
}

impl fmt::Display for PendingKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One pending resource, as the broker publishes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PendingResource {
    /// This resource's identity.
    pub resource_id: PendingResourceId,
    /// The application instance the request came from.
    pub application_instance_id: ApplicationInstanceId,
    /// The namespaced downstream identifier the upstream used.
    pub request: DownstreamRequestId,
    /// What kind of thing it is.
    pub kind: PendingKind,
    /// The upstream method that produced it.
    pub method: UpstreamMethod,
    /// How the table classified that method, and whether it said so.
    pub classification: NativeClassification,
    /// The source frame generation the request arrived in.
    pub source_generation: SourceGeneration,
    /// Its current state.
    pub state: PendingState,
    /// Whether the record of this resource is durable or only in memory.
    pub durability: Durability,
    /// The upstream's own deadline, where it stated one.
    pub deadline_ms: Nullable<TimestampMs>,
    /// When the broker recorded it.
    pub recorded_at: TimestampMs,
    /// True when its interpretation has been verified under a granted decoder.
    ///
    /// Section 11: "A pending opaque request is not an actionable approval UI until its
    /// interpretation is verified under the granted decoder."
    pub interpretation_verified: bool,
}

impl PendingResource {
    /// Returns true when a client may offer this as an approval a person can answer.
    #[must_use]
    pub const fn is_actionable(&self) -> bool {
        self.interpretation_verified && matches!(self.state, PendingState::Pending)
    }
}

/// A transition a pending resource cannot make.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArbitrationError {
    /// The transition is not one the contract permits.
    #[error("a pending resource cannot go from {from} to {to}")]
    ForbiddenTransition {
        /// The state it is in.
        from: PendingState,
        /// The state that was asked for.
        to: PendingState,
    },
    /// Another answer already holds the claim.
    #[error("this pending resource is already claimed")]
    AlreadyClaimed,
    /// The resource has already reached a terminal state.
    #[error("this pending resource is already {state}")]
    AlreadyResolved {
        /// The terminal state it reached.
        state: PendingState,
    },
}

/// Checks one transition of a pending resource.
///
/// # Errors
///
/// Returns [`ArbitrationError::AlreadyResolved`] when the resource is terminal,
/// [`ArbitrationError::AlreadyClaimed`] when a second claim arrives, and
/// [`ArbitrationError::ForbiddenTransition`] for anything else the contract forbids.
pub fn check_transition(from: PendingState, to: PendingState) -> Result<(), ArbitrationError> {
    if from.is_terminal() {
        return Err(ArbitrationError::AlreadyResolved { state: from });
    }
    if from == PendingState::Claimed && to == PendingState::Claimed {
        return Err(ArbitrationError::AlreadyClaimed);
    }
    if from.may_become(to) {
        Ok(())
    } else {
        Err(ArbitrationError::ForbiddenTransition { from, to })
    }
}

// ---------------------------------------------------------------------------------------------
// Volatile-native mode
// ---------------------------------------------------------------------------------------------

/// What the gateway is currently able to do.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GatewayMode {
    /// Everything works and every record is durable.
    Normal,
    /// The journal faulted: rich work is fenced and native arbitration continues in memory.
    NativeOnlyVolatile,
    /// Storage is back and the gap is being committed before rich work resumes.
    Recovering,
}

impl GatewayMode {
    /// Every mode, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Normal, Self::NativeOnlyVolatile, Self::Recovering];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::NativeOnlyVolatile => "native_only_volatile",
            Self::Recovering => "recovering",
        }
    }

    /// Returns true when a new rich mutation or rich approval may be admitted.
    ///
    /// Recovering is still no: the gap has to be committed and the pending identifiers reconciled
    /// with the same upstream before rich mutation comes back.
    #[must_use]
    pub const fn admits_rich_work(self) -> bool {
        matches!(self, Self::Normal)
    }

    /// Returns the durability a record written in this mode has.
    #[must_use]
    pub const fn durability(self) -> Durability {
        match self {
            Self::Normal => Durability::Durable,
            Self::NativeOnlyVolatile | Self::Recovering => Durability::Volatile,
        }
    }

    /// The modes this one may move to.
    #[must_use]
    pub const fn permitted_transitions(self) -> &'static [Self] {
        match self {
            Self::Normal => &[Self::NativeOnlyVolatile],
            // Storage can fail again while the gap is being committed, so recovery can fall back.
            Self::NativeOnlyVolatile => &[Self::Recovering],
            Self::Recovering => &[Self::Normal, Self::NativeOnlyVolatile],
        }
    }

    /// Returns true when this transition is one the contract permits.
    #[must_use]
    pub fn may_become(self, next: Self) -> bool {
        self.permitted_transitions().contains(&next)
    }
}

impl fmt::Display for GatewayMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The evidence gap a spell of volatile operation leaves behind.
///
/// It is exposed while it is open and committed when storage returns. Section 11 forbids the
/// alternative: "Never replay volatile operations to manufacture durable history." What is
/// committed is the fact that the gap happened and what was in it, not the operations themselves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EvidenceGap {
    /// When the journal faulted.
    pub opened_at: TimestampMs,
    /// When storage returned, while the gap is still open.
    pub closed_at: Nullable<TimestampMs>,
    /// Why the journal faulted, for a person to read.
    pub reason: String,
    /// Native requests forwarded while the gap was open.
    pub native_requests: U64,
    /// Native responses arbitrated in memory while the gap was open.
    pub native_responses: U64,
    /// Rich mutations and rich approvals refused because of the gap.
    pub fenced_rich_operations: U64,
    /// Pending identifiers that were already claimed when the gap opened.
    ///
    /// These are the ones a second response must never be emitted for, so they are carried across
    /// the gap rather than forgotten.
    pub carried_pending: U64,
}

impl EvidenceGap {
    /// Opens a gap.
    #[must_use]
    pub fn open(reason: impl Into<String>, at: TimestampMs, carried_pending: u64) -> Self {
        Self {
            opened_at: at,
            closed_at: Nullable::null(),
            reason: reason.into(),
            native_requests: U64::new(0),
            native_responses: U64::new(0),
            fenced_rich_operations: U64::new(0),
            carried_pending: U64::new(carried_pending),
        }
    }

    /// Returns true when the gap is still open.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        !self.closed_at.is_present()
    }
}

// ---------------------------------------------------------------------------------------------
// Reverse remote procedure calls
// ---------------------------------------------------------------------------------------------

/// What an upstream reverse request asks the host to do.
///
/// Section 12: KalaReach executes these "in the agent's host environment with its existing user
/// identity, not accidentally in the phone or another desktop client's filesystem". The type
/// exists so that the execution site is part of the contract rather than an implementation
/// accident.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ReverseOperation {
    /// Read a file.
    FilesystemRead,
    /// Write a file.
    FilesystemWrite,
    /// Run something in the session's terminal environment.
    Terminal,
}

impl ReverseOperation {
    /// Every operation, in declaration order.
    pub const ALL: &'static [Self] = &[Self::FilesystemRead, Self::FilesystemWrite, Self::Terminal];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemRead => "filesystem_read",
            Self::FilesystemWrite => "filesystem_write",
            Self::Terminal => "terminal",
        }
    }

    /// Returns the class a reverse operation of this kind has.
    #[must_use]
    pub const fn class(self) -> NativeMethodClass {
        match self {
            Self::FilesystemRead => NativeMethodClass::Observation,
            Self::FilesystemWrite | Self::Terminal => NativeMethodClass::Mutation,
        }
    }
}

impl fmt::Display for ReverseOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Where one reverse request is executed.
///
/// There is one correct answer and it is named here so a client cannot supply another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReverseExecutionSite {
    /// The environment the agent process runs in.
    pub environment_id: crate::ids::EnvironmentId,
    /// The application instance whose upstream asked.
    pub application_instance_id: ApplicationInstanceId,
    /// The operating-system user the agent runs as, as the host resolved it.
    pub os_user: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method(name: &str) -> UpstreamMethod {
        UpstreamMethod::new(name).expect("a short method name is valid")
    }

    fn table() -> DeclarativeTable {
        let mut table = DeclarativeTable {
            plugin_id: PluginId::new("kalareach.codex").expect("valid"),
            publisher_id: PublisherId::new("kalareach").expect("valid"),
            table_version: MethodTableVersion::new(1),
            upstream_protocol_version: "1".to_owned(),
            digest: Digest256::from_bytes([1; 32]),
            framing: NativeFraming::JsonLines,
            request_id_field: "id".to_owned(),
            response_id_field: "id".to_owned(),
            method_field: "method".to_owned(),
            params_field: "params".to_owned(),
            result_field: "result".to_owned(),
            error_field: "error".to_owned(),
            entries: vec![
                DeclarativeEntry {
                    method: method("session/request_permission"),
                    class: NativeMethodClass::Mutation,
                    expects_response: true,
                    reverse: Nullable::null(),
                    approval_option_field: Nullable::some("option_id".to_owned()),
                },
                DeclarativeEntry {
                    method: method("session/update"),
                    class: NativeMethodClass::Observation,
                    expects_response: false,
                    reverse: Nullable::null(),
                    approval_option_field: Nullable::null(),
                },
            ],
        };
        table.digest = table.canonical_digest().expect("encodable");
        table
    }

    #[test]
    fn an_unclassified_request_is_presumed_mutating() {
        let table = table();
        let known = table.classify(&method("session/update"));
        assert_eq!(known.class, NativeMethodClass::Observation);
        assert!(known.declared);
        assert!(!known.suspends_rich_mutations());

        let unknown = table.classify(&method("vendor/undocumented"));
        assert_eq!(unknown.class, NativeMethodClass::Mutation);
        assert!(!unknown.declared);
        assert!(unknown.suspends_rich_mutations());
        assert!(table.expects_response(&method("vendor/undocumented")));
    }

    #[test]
    fn a_table_is_qualified_against_the_installed_version() {
        let table = table();
        assert!(table.qualify("1").is_ok());
        assert!(matches!(
            table.qualify("2"),
            Err(TableError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn an_unordered_table_is_refused() {
        let mut table = table();
        table.entries.reverse();
        assert_eq!(table.validate(), Err(TableError::Unordered));
    }

    #[test]
    fn a_table_whose_members_collide_is_refused() {
        // A request and a response may name their identifier the same way; JSON-RPC does.
        let shared = table();
        assert_eq!(shared.request_id_field, shared.response_id_field);
        assert!(shared.validate().is_ok());

        // The rest say different things about a frame, and one name for two of them makes one
        // frame two things at once.
        for (field, value) in [
            ("result_field", "id"),
            ("error_field", "method"),
            ("method_field", "result"),
        ] {
            let mut collided = table();
            match field {
                "result_field" => collided.result_field = value.to_owned(),
                "error_field" => collided.error_field = value.to_owned(),
                _ => collided.method_field = value.to_owned(),
            }
            assert!(
                matches!(collided.validate(), Err(TableError::RepeatedField { .. })),
                "{field} named {value} collides"
            );
        }
    }

    #[test]
    fn the_rich_table_is_closed() {
        let rich = RichMethodTable {
            table_version: MethodTableVersion::new(1),
            upstream_protocol_version: "1".to_owned(),
            entries: vec![
                RichMethodEntry {
                    method: method("session/cancel"),
                    class: NativeMethodClass::Mutation,
                    required_right: ActionRight::AgentCancel,
                    operation: Nullable::some(RichOperation::TurnCancel),
                    provenance: ActionProvenance::UpstreamTypedRpc,
                },
                RichMethodEntry {
                    method: method("session/set_provider_key"),
                    class: NativeMethodClass::Unsupported,
                    required_right: ActionRight::AgentPrompt,
                    operation: Nullable::some(RichOperation::PromptSubmit),
                    provenance: ActionProvenance::UpstreamTypedRpc,
                },
            ],
        };
        assert!(rich.qualify("1").is_ok());
        assert!(rich.admit(&method("session/cancel")).is_ok());
        assert!(matches!(
            rich.admit(&method("session/set_provider_key")),
            Err(RichRejection::Unsupported { .. })
        ));
        assert!(matches!(
            rich.admit(&method("vendor/undocumented")),
            Err(RichRejection::Unknown { .. })
        ));
    }

    #[test]
    fn one_resource_resolves_once() {
        assert!(check_transition(PendingState::Pending, PendingState::Claimed).is_ok());
        assert!(check_transition(PendingState::Claimed, PendingState::Resolved).is_ok());
        assert_eq!(
            check_transition(PendingState::Claimed, PendingState::Claimed),
            Err(ArbitrationError::AlreadyClaimed)
        );
        assert_eq!(
            check_transition(PendingState::Resolved, PendingState::Resolved),
            Err(ArbitrationError::AlreadyResolved {
                state: PendingState::Resolved
            })
        );
        assert_eq!(
            check_transition(PendingState::Pending, PendingState::Resolved),
            Err(ArbitrationError::ForbiddenTransition {
                from: PendingState::Pending,
                to: PendingState::Resolved
            })
        );
        for state in PendingState::ALL {
            if state.is_terminal() {
                assert!(
                    state.permitted_transitions().is_empty(),
                    "{state} is not terminal"
                );
            }
        }
    }

    #[test]
    fn a_native_answer_during_encoding_releases_the_claim() {
        assert!(check_transition(PendingState::Claimed, PendingState::Cancelled).is_ok());
    }

    #[test]
    fn a_claim_that_dispatched_nothing_can_be_given_back() {
        assert!(check_transition(PendingState::Claimed, PendingState::Pending).is_ok());
        assert_eq!(
            check_transition(PendingState::Resolved, PendingState::Pending),
            Err(ArbitrationError::AlreadyResolved {
                state: PendingState::Resolved
            })
        );
    }

    #[test]
    fn volatile_mode_admits_no_rich_work_until_the_gap_is_committed() {
        assert!(GatewayMode::Normal.admits_rich_work());
        assert!(!GatewayMode::NativeOnlyVolatile.admits_rich_work());
        assert!(!GatewayMode::Recovering.admits_rich_work());
        assert_eq!(GatewayMode::Normal.durability(), Durability::Durable);
        assert_eq!(
            GatewayMode::NativeOnlyVolatile.durability(),
            Durability::Volatile
        );
        assert!(GatewayMode::Normal.may_become(GatewayMode::NativeOnlyVolatile));
        assert!(!GatewayMode::NativeOnlyVolatile.may_become(GatewayMode::Normal));
        assert!(GatewayMode::NativeOnlyVolatile.may_become(GatewayMode::Recovering));
        assert!(GatewayMode::Recovering.may_become(GatewayMode::Normal));
        assert!(GatewayMode::Recovering.may_become(GatewayMode::NativeOnlyVolatile));
    }

    #[test]
    fn a_downstream_identifier_is_namespaced_by_its_connection() {
        let first = DownstreamRequestId::new(
            GatewayConnectionId::new(1),
            UpstreamRequestId::new("1").expect("valid"),
        );
        let second = DownstreamRequestId::new(
            GatewayConnectionId::new(2),
            UpstreamRequestId::new("1").expect("valid"),
        );
        assert_ne!(first, second);
        assert_eq!(first.to_string(), "1:1");
    }

    #[test]
    fn a_reverse_write_is_a_mutation_and_a_read_is_not() {
        assert_eq!(
            ReverseOperation::FilesystemRead.class(),
            NativeMethodClass::Observation
        );
        assert_eq!(
            ReverseOperation::FilesystemWrite.class(),
            NativeMethodClass::Mutation
        );
        assert_eq!(
            ReverseOperation::Terminal.class(),
            NativeMethodClass::Mutation
        );
    }
}
