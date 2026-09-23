//! The identity and object model of section 6.
//!
//! Each row of the section 6 table has a type here. Identifiers that are 128-bit values are
//! [`Uuid`] newtypes; counters and revisions are [`U64`] newtypes; identifiers that originate
//! upstream or in the operating system are bounded opaque text.
//!
//! The newtypes are not interchangeable. A session identifier cannot be passed where an
//! environment identifier is expected, and the JSON Schema names each one separately.

use core::fmt;
use core::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize};

use crate::scalars::{U64, Uuid, UuidParseError};

/// Maximum length in bytes of a bounded opaque identifier.
///
/// Opaque identifiers come from an upstream agent, the operating system or a service. They are
/// correlation data, never authority, and they are bounded so a peer cannot force an unbounded
/// allocation through an identifier field.
pub const MAX_OPAQUE_ID_LEN: usize = 256;

/// The longest an upstream request identifier may be, in bytes of its JSON form.
///
/// An upstream identifier is carried as JSON, so its value is bounded by [`MAX_OPAQUE_ID_LEN`] and
/// its text by what encoding that value can cost. The worst case is a control character, which
/// costs six bytes as `\u0000`; a multi-byte character costs only its own bytes, because the
/// encoder copies it. Two quotes are added. The gateway checks the value against
/// [`MAX_OPAQUE_ID_LEN`] before it encodes, so this bound is never what refuses an identifier a
/// person chose.
pub const MAX_UPSTREAM_REQUEST_ID_LEN: usize = 6 * MAX_OPAQUE_ID_LEN + 2;

macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident, $description:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Wraps a raw identifier.
            #[must_use]
            pub const fn new(value: Uuid) -> Self {
                Self(value)
            }

            /// Returns the raw identifier.
            #[must_use]
            pub const fn get(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, formatter)
            }
        }

        impl FromStr for $name {
            type Err = UuidParseError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                text.parse().map(Self)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> std::borrow::Cow<'static, str> {
                concat!("kalareach::", stringify!($name)).into()
            }

            fn json_schema(generator: &mut SchemaGenerator) -> Schema {
                // The scalar's schema is written out rather than referenced. A definition that is
                // only a reference to another definition is an alias of an alias, and a generator
                // that flattens one drops the named type, which is the whole point of this type.
                let mut schema = Uuid::json_schema(generator);
                schema.insert("description".to_owned(), $description.into());
                schema
            }
        }
    };
}

macro_rules! counter_id {
    ($(#[$meta:meta])* $name:ident, $description:literal) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub U64);

        impl $name {
            /// Wraps a raw counter.
            #[must_use]
            pub const fn new(value: u64) -> Self {
                Self(U64::new(value))
            }

            /// Returns the raw counter.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, formatter)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> std::borrow::Cow<'static, str> {
                concat!("kalareach::", stringify!($name)).into()
            }

            fn json_schema(generator: &mut SchemaGenerator) -> Schema {
                // See the note on the UUID identifiers above.
                let mut schema = U64::json_schema(generator);
                schema.insert("description".to_owned(), $description.into());
                schema
            }
        }
    };
}

macro_rules! opaque_id {
    ($(#[$meta:meta])* $name:ident, $description:literal) => {
        opaque_id!($(#[$meta])* $name, $description, MAX_OPAQUE_ID_LEN);
    };
    ($(#[$meta:meta])* $name:ident, $description:literal, $limit:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wraps text, rejecting an empty or over-long identifier.
            ///
            /// # Errors
            ///
            /// Returns [`OpaqueIdError`] when the text is empty, longer than this
            /// identifier's own limit, or contains a control character.
            pub fn new(value: impl Into<String>) -> Result<Self, OpaqueIdError> {
                let value = value.into();
                validate_opaque_id(&value, $limit)?;
                Ok(Self(value))
            }

            /// Returns the identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = OpaqueIdError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::new(text)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Self::new(text).map_err(serde::de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> std::borrow::Cow<'static, str> {
                concat!("kalareach::", stringify!($name)).into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "minLength": 1,
                    "maxLength": $limit,
                    "description": $description
                })
            }
        }
    };
}

/// An opaque identifier that is empty, too long or contains a control character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueIdError(&'static str);

impl fmt::Display for OpaqueIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for OpaqueIdError {}

fn validate_opaque_id(value: &str, limit: usize) -> Result<(), OpaqueIdError> {
    if value.is_empty() {
        return Err(OpaqueIdError("identifier must not be empty"));
    }
    if value.len() > limit {
        return Err(OpaqueIdError("identifier is longer than its limit"));
    }
    if value.chars().any(char::is_control) {
        return Err(OpaqueIdError(
            "identifier must not contain control characters",
        ));
    }
    Ok(())
}

uuid_id!(
    /// One relay lease: one endpoint pair, one payer.
    RelayLeaseId,
    "One relay lease, covering one endpoint pair for one payer."
);
uuid_id!(
    /// One reserved block of relay bytes. Consumption is reported against it.
    RelayReservationId,
    "One reserved block of relay bytes. Consumption receipts are keyed by it."
);
uuid_id!(
    /// One relay instance. Stable across rotation of the key it signs receipts with.
    RelayInstanceId,
    "One relay instance. Stable across rotation of the key it signs receipts with."
);

counter_id!(
    /// The revision of one relay lease. Only the issuing service advances it.
    RelayLeaseRevision,
    "The revision of one relay lease. Only the issuing service advances it."
);
counter_id!(
    /// The position of one consumption receipt inside its reservation's sequence.
    RelayReceiptSequence,
    "The position of one consumption receipt inside its reservation's sequence."
);
counter_id!(
    /// The revision of one relay instance's registration. Only the instance advances it.
    RelayRegistrationRevision,
    "The revision of one relay instance's registration. Only the instance advances it."
);

uuid_id!(
    /// A random owner-approved logical grouping of environments. Not a hardware identity.
    MachineId,
    "A logical machine group. Not a hardware identity."
);
uuid_id!(
    /// One installed operating-system environment and operating-system user.
    EnvironmentId,
    "One installed OS, distribution or container environment and OS user."
);
uuid_id!(
    /// One KalaReach terminal session.
    SessionId,
    "One KalaReach terminal session."
);
uuid_id!(
    /// One CLI or application attachment, independently of its device.
    AttachmentId,
    "One CLI or application attachment, independently of its device."
);
uuid_id!(
    /// One foreground application inside a terminal session.
    ApplicationInstanceId,
    "One foreground application within a terminal session."
);
uuid_id!(
    /// One submitted intent and its receipt. Generated as a UUIDv4.
    ActionId,
    "One submitted intent and its receipt, generated as a UUIDv4."
);
uuid_id!(
    /// One paired device.
    DeviceId,
    "One paired device."
);
uuid_id!(
    /// One host-issued authority object.
    GrantId,
    "One host-issued authority object."
);
uuid_id!(
    /// One agent-to-user question.
    QuestionId,
    "One agent-to-user question."
);
uuid_id!(
    /// One durable device-owned draft.
    DraftId,
    "One durable device-owned draft, independent of an attachment."
);
uuid_id!(
    /// One environment-bound source repository.
    ProjectRepositoryId,
    "One environment-bound source repository."
);
uuid_id!(
    /// One selected working copy of a repository.
    WorkspaceId,
    "One selected working copy and its policy."
);
uuid_id!(
    /// One immutable captured change set.
    ChangeSetId,
    "One immutable captured change set."
);
uuid_id!(
    /// One independent materialisation of one exact change-set version.
    MaterialisationId,
    "One independent materialisation of one exact change-set version."
);
uuid_id!(
    /// One automation definition.
    WorkflowId,
    "One automation definition."
);
uuid_id!(
    /// One automation run.
    WorkflowRunId,
    "One automation run."
);
uuid_id!(
    /// The root of a bounded cross-run causal chain.
    CausalRootId,
    "The root of a bounded cross-run causal chain."
);
uuid_id!(
    /// One remote dispatch lease issued by the current controller generation.
    RemoteDispatchLeaseId,
    "One remote dispatch lease from the current controller generation."
);
uuid_id!(
    /// One transport connection, allocated by the host during `hello`.
    ConnectionId,
    "One transport connection, allocated by the host during hello."
);
uuid_id!(
    /// One pairing invitation. 128 random bits, not necessarily a UUIDv4.
    InvitationId,
    "One pairing invitation: 128 random bits, not necessarily a UUIDv4."
);
uuid_id!(
    /// One pairing attempt by one candidate. 128 random bits.
    AttemptId,
    "One pairing attempt by one candidate: 128 random bits."
);
uuid_id!(
    /// One upload or download transfer.
    TransferId,
    "One upload or download transfer."
);

uuid_id!(
    /// One stored mailbox envelope. 128 random bits.
    EnvelopeId,
    "One stored mailbox envelope: 128 random bits."
);
uuid_id!(
    /// One backup archive. The service sees only this opaque identifier.
    ArchiveId,
    "One backup archive. The service sees only this opaque identifier."
);
uuid_id!(
    /// One encrypted object inside a backup archive.
    BackupObjectId,
    "One encrypted object inside a backup archive."
);
uuid_id!(
    /// One signed revocation request published by a remote owner.
    RevocationRequestId,
    "One signed revocation request published by a remote owner."
);
uuid_id!(
    /// One owner-confirmation challenge. Single use, bound to one action digest.
    ConfirmationId,
    "One owner-confirmation challenge: single use and bound to one action digest."
);
uuid_id!(
    /// One voice session, which is not a terminal session and does not end one.
    ///
    /// A voice session has its own life: it carries the voice grant the host created for it, and
    /// ending it revokes that grant. The terminal sessions it may reach keep running.
    VoiceSessionId,
    "One voice session, independent of the terminal sessions it may reach."
);
uuid_id!(
    /// One native application installation registered with a push gateway.
    InstallationId,
    "One native application installation registered with a push gateway."
);
uuid_id!(
    /// One organisation whose policy a host has opted into (section 17).
    OrganisationId,
    "One organisation whose signed policy a host has opted into."
);
uuid_id!(
    /// One notification, as the host that produced it names it. 128 random bits.
    ///
    /// The gateway deduplicates by this value and never reads it. It travels to a provider in the
    /// clear, so the producer generates it at random rather than deriving it from anything about
    /// the work. Being 128 bits rather than text leaves no room for a name that reads as one; it
    /// does not stop a producer encoding something into the bits, which is the producer's own rule
    /// to keep.
    NotificationId,
    "One notification, named by the host that produced it. 128 random bits, opaque to the gateway and the provider."
);
uuid_id!(
    /// The group a notification replaces others in on the device.
    ///
    /// A host derives it from its own secret and whatever it wants to group by, so two notifications
    /// about one thing collapse into one and the value tells a provider nothing about what that
    /// thing is. Like the notification identifier it reaches the provider in the clear, and like it
    /// the producer is the one that keeps it meaningless.
    CollapseId,
    "The group a notification replaces others in on the device. 128 bits a host derives from its own secret."
);
uuid_id!(
    /// One attempt to bind a push token to an installation. 128 random bits.
    ///
    /// It names the attempt, not the token: a challenge answered for one attempt says nothing
    /// about another, so a pending registration cannot be completed with the answer to an earlier
    /// one.
    PushRegistrationId,
    "One attempt to bind a push token to an installation. 128 random bits."
);
uuid_id!(
    /// One installation's authorisation of one paired host to send it notifications.
    PushSenderRecordId,
    "One installation's authorisation of one paired host to send it notifications."
);
uuid_id!(
    /// The group repeated state notifications coalesce in inside one mailbox.
    ///
    /// The sender derives it from its own secret and whatever the notifications are about, so the
    /// newest of a run replaces the older unread one without the service learning what the run is
    /// about. Section 9 coalesces by this value and keeps the authoritative events on the host.
    MailboxThreadId,
    "The group repeated state notifications coalesce in. The sender derives it; the service only compares it."
);
uuid_id!(
    /// One synchronised collection of encrypted settings, drafts and client positions.
    SyncCollectionId,
    "One synchronised collection of encrypted settings, drafts and client positions."
);
uuid_id!(
    /// One synchronised object inside a collection.
    SyncObjectId,
    "One synchronised object inside a collection."
);
uuid_id!(
    /// One revision of one synchronised object, issued by the service on every accepted write.
    ///
    /// It is a fresh 128-bit value rather than a counter, so a revision an object once had cannot
    /// be reached again by removing that object and writing a new one in its place.
    SyncRevisionId,
    "One revision of one synchronised object. A fresh 128-bit value per accepted write."
);
uuid_id!(
    /// One retained conflict copy of a rejected synchronised write.
    SyncConflictId,
    "One retained conflict copy of a rejected synchronised write."
);
uuid_id!(
    /// One component bound to one application instance inside the broker.
    ///
    /// A binding is what a grant, a decoding trust record and a capability evidence record all
    /// hang from. It is not the package: reinstalling a package does not revive the grants of a
    /// binding that has gone.
    BrokerBindingId,
    "One component bound to one application instance inside the broker."
);
uuid_id!(
    /// One pending resource the broker arbitrates: an approval, a question or an upstream action.
    ///
    /// Exactly one resolution reaches the upstream for each of these, whatever reconnects.
    PendingResourceId,
    "One pending resource the broker arbitrates and resolves exactly once."
);

counter_id!(
    /// The session epoch. Fixed at 1 in version 1 of the protocol.
    SessionEpoch,
    "The session epoch, fixed at 1 in protocol version 1."
);
counter_id!(
    /// Monotonic join order of an attachment, used for deterministic size-owner succession.
    AttachmentOrdinal,
    "Monotonic attachment join order, used for deterministic geometry-owner succession."
);
counter_id!(
    /// Changes when the active upstream execution owner or selected thread changes.
    AgentBindingRevision,
    "Changes when the active upstream execution owner or selected thread changes."
);
counter_id!(
    /// A position in one event stream.
    StreamCursor,
    "A position in one event stream."
);
counter_id!(
    /// The catalogue generation a plugin package was resolved against.
    RepositoryGeneration,
    "The catalogue generation a plugin package was resolved against."
);
counter_id!(
    /// The exact version of a question that a person answers.
    QuestionRevision,
    "The exact version of a question that a person answers."
);
counter_id!(
    /// The exact version of a draft.
    DraftRevision,
    "The exact version of a draft."
);
counter_id!(
    /// The exact version of a change set that was tested or reviewed.
    ChangeSetVersion,
    "The exact version of a change set that was tested or reviewed."
);
counter_id!(
    /// Current evidence for a versioned capability. Never permission.
    CapabilityRevision,
    "Current evidence for a versioned capability. Never permission."
);
counter_id!(
    /// The controller's persistent generation, advanced on every controller start.
    ControllerGeneration,
    "The controller's persistent generation, advanced on every controller start."
);
counter_id!(
    /// The host's ordered authority revision. Only the host issues it.
    AuthorityRevision,
    "The host's ordered authority revision. Only the host issues its own revisions."
);
counter_id!(
    /// The revision of a device's purpose-separated public keys.
    DeviceKeyRevision,
    "The revision of a device's purpose-separated public keys."
);
counter_id!(
    /// The revision of an organisation's policy-signing key.
    ///
    /// The policy-signing authority advances it on every rotation, and a host follows the signed
    /// chain from the revision it pinned to the revision signing now.
    PolicyKeyRevision,
    "The revision of an organisation's policy-signing key, advanced on every rotation."
);
counter_id!(
    /// The revision of one push sender record. Only the gateway advances it.
    ///
    /// Every renewal advances it, so a captured renewal cannot be replayed to reinstate a
    /// credential that a later renewal or a revocation has already replaced.
    PushSenderRevision,
    "The revision of one push sender record, advanced by the gateway on every renewal."
);

counter_id!(
    /// The backup generation an archive belongs to. Only its producer advances it.
    BackupGeneration,
    "The backup generation an archive belongs to. Only its producer advances it."
);
counter_id!(
    /// The revision of one collection's enrolled backup writer. Only its owner advances it.
    BackupWriterRevision,
    "The revision of one collection's enrolled backup writer. Only the collection's owner advances it."
);
counter_id!(
    /// Which key a synchronised collection is sealed under.
    ///
    /// It starts at zero and moves on by one whenever the key changes, which removing a member
    /// always requires: a device that has left must not hold the key the others write with next.
    SyncKeyEpoch,
    "Which key a synchronised collection is sealed under. It moves on by one whenever the key changes."
);
counter_id!(
    /// The revision of one synchronised collection's key record. Every accepted record is the next.
    SyncKeyRecordRevision,
    "The revision of one synchronised collection's key record. Every accepted record is the next one."
);
counter_id!(
    /// The revision of one organisation's signed policy. Only its administrators advance it.
    OrganisationPolicyRevision,
    "The revision of one organisation's signed policy, advanced on every policy change."
);
counter_id!(
    /// The sequence number of one message inside a pairing bundle exchange.
    PairingSequence,
    "The sequence number of one message inside a pairing bundle exchange."
);
counter_id!(
    /// The current input lease epoch.
    InputLeaseEpoch,
    "The current input lease epoch."
);
counter_id!(
    /// The current geometry-owner epoch, separate from the input lease.
    GeometryEpoch,
    "The current geometry-owner epoch, separate from the input lease."
);
counter_id!(
    /// A request identifier, unique for the lifetime of one connection.
    RequestId,
    "A request identifier, unique for the lifetime of one connection."
);
counter_id!(
    /// A position in one notification stream.
    EventSequence,
    "A position in one notification stream."
);
counter_id!(
    /// An increasing sequence number inside one raw input stream.
    InputSequence,
    "An increasing sequence number inside one raw input stream."
);
counter_id!(
    /// The host's boot epoch, used to bind continuous-time deadlines to one boot.
    BootEpoch,
    "The host boot epoch, which binds continuous-time deadlines to one boot."
);
counter_id!(
    /// The host's clock epoch, advanced when wall-clock trust changes.
    ClockEpoch,
    "The host clock epoch, advanced when wall-clock trust changes."
);
counter_id!(
    /// One connection into the worker-owned gateway.
    ///
    /// Downstream JSON-RPC identifiers are namespaced by it, so two connections that both choose
    /// the identifier `1` name two different pending resources.
    GatewayConnectionId,
    "One connection into the worker-owned gateway. Downstream request identifiers are namespaced by it."
);
counter_id!(
    /// The generation of one immutable source frame stream.
    ///
    /// It advances whenever the bound upstream execution owner changes, so a decoder cannot offer
    /// a resource from a frame an earlier execution produced.
    SourceGeneration,
    "The generation of one immutable source frame stream. It advances when the bound execution owner changes."
);
counter_id!(
    /// The version of a connector's declarative or rich method table.
    ///
    /// Tables are pinned and qualified against the installed protocol version, so a table built
    /// for one upstream version is never interpreted against another.
    MethodTableVersion,
    "The version of a connector's declarative or rich method table."
);

opaque_id!(
    /// Binds the operating-system user, boot identity and login-session generation.
    ///
    /// The host derives this value; it is not a reusable login-session number.
    DesktopSessionId,
    "A host-derived desktop session identity binding OS user, boot identity and login-session generation."
);
opaque_id!(
    /// The upstream agent's conversation identifier, where the agent exposes one.
    AgentThreadId,
    "The upstream agent's conversation identifier, where available. Correlation data, not authority."
);
opaque_id!(
    /// The upstream agent's current turn identifier, where the agent exposes one.
    AgentTurnId,
    "The upstream agent's current turn identifier, where available."
);
opaque_id!(
    /// An upstream approval request identifier.
    ApprovalRequestId,
    "An upstream approval request identifier. Opaque to KalaReach."
);
opaque_id!(
    /// A private broker handle for immutable upstream bytes and their execution provenance.
    SourceEventHandle,
    "A private broker handle for immutable upstream bytes and their execution provenance."
);
opaque_id!(
    /// A plugin identifier from its manifest.
    PluginId,
    "A plugin identifier from its manifest."
);
opaque_id!(
    /// A versioned capability name. Capabilities describe feasibility, never authority.
    CapabilityId,
    "A versioned capability name. Capabilities describe feasibility, never authority."
);
opaque_id!(
    /// A host-issued action window identifier, bound to one connection and host boot.
    ActionWindowId,
    "A host-issued action window identifier, bound to one authenticated connection and host boot."
);
opaque_id!(
    /// A stable host-issued principal for one verified actor.
    ///
    /// A paired device uses its device principal; a local operating-system caller or an
    /// authorised workflow uses a principal scoped to that environment, user or workflow grant.
    /// A caller cannot assert its own principal.
    ActorId,
    "A stable host-issued principal for one verified actor. The caller cannot assert it."
);
opaque_id!(
    /// The name of one event stream.
    StreamId,
    "The name of one event stream."
);
opaque_id!(
    /// The type of one notification event.
    EventType,
    "The type of one notification event."
);
opaque_id!(
    /// A build identifier reported in `hello`.
    BuildId,
    "A build identifier reported in hello."
);
opaque_id!(
    /// A managed account, as the service names it.
    ///
    /// It names who is billed. Authority to bill them comes from the issuer's signature over the
    /// object carrying it, never from the identifier.
    AccountId,
    "A managed account identifier minted by the service. It names the payer; it is not authority."
);
opaque_id!(
    /// The record that authorised one principal to pay for another's relay traffic.
    PayerAuthorisationId,
    "The service record that authorised one principal to pay for another's relay traffic."
);
opaque_id!(
    /// The deployment region one relay instance serves.
    RelayRegion,
    "The deployment region one relay instance serves."
);
opaque_id!(
    /// An opaque diagnostic identifier attached to an error.
    DiagnosticId,
    "An opaque diagnostic identifier. It carries no protocol meaning."
);
opaque_id!(
    /// A package publisher identity, as its manifest states it.
    ///
    /// Decoding trust is recorded against it, so a person inspecting a pending approval can see
    /// whose interpretation produced it.
    PublisherId,
    "A package publisher identity from its manifest. Decoding trust is recorded against it."
);
opaque_id!(
    /// A single-use broker handle for one issued action token.
    ///
    /// The token's bindings are the authority; this names the record the broker consumes, so one
    /// invocation cannot be spent twice.
    ActionTokenId,
    "A single-use broker handle for one issued action token."
);
opaque_id!(
    /// An upstream JSON-RPC request identifier, in this host's JSON encoding of it.
    ///
    /// A JSON-RPC identifier is a string or a number, and the two are different identifiers, so
    /// what is carried is the member's JSON form: the string eleven is `"11"` and the number
    /// eleven is `11`. The form is this host's own encoding of the value, not the upstream's own
    /// spelling of it, so `"a"` and `"\u0061"` are one identifier, which is what a correlation key
    /// has to be. The value keeps the [`MAX_OPAQUE_ID_LEN`] bound every opaque identifier has, and
    /// [`MAX_UPSTREAM_REQUEST_ID_LEN`] is what encoding that value can cost. It is correlation
    /// data. An upstream identifier never becomes a KalaReach identifier.
    UpstreamRequestId,
    "An upstream JSON-RPC request identifier, in its JSON form: a string identifier keeps its quotes, so a string and a number never collide. Correlation data, not authority.",
    MAX_UPSTREAM_REQUEST_ID_LEN
);
opaque_id!(
    /// An upstream method name, as a connector's table names it.
    UpstreamMethod,
    "An upstream method name, as a connector's declarative or rich table names it."
);
opaque_id!(
    /// One resolved launch profile.
    LaunchProfileId,
    "One resolved launch profile: its executable, distribution, version, arguments, authentication state and mode."
);

impl SessionEpoch {
    /// The only session epoch defined in version 1.
    ///
    /// Section 6 fixes the epoch at 1 and reserves it for an explicitly specified future
    /// replacement operation. A new execution always gets a new session UUID.
    pub const V1: Self = Self::new(1);
}

/// A session and the epoch it was addressed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionRef {
    /// The session identifier.
    pub session_id: SessionId,
    /// The session epoch. Version 1 always uses [`SessionEpoch::V1`].
    pub session_epoch: SessionEpoch,
}
