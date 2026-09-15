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
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wraps text, rejecting an empty or over-long identifier.
            ///
            /// # Errors
            ///
            /// Returns [`OpaqueIdError`] when the text is empty, longer than
            /// [`MAX_OPAQUE_ID_LEN`] bytes or contains a control character.
            pub fn new(value: impl Into<String>) -> Result<Self, OpaqueIdError> {
                let value = value.into();
                validate_opaque_id(&value)?;
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
                    "maxLength": MAX_OPAQUE_ID_LEN,
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

fn validate_opaque_id(value: &str) -> Result<(), OpaqueIdError> {
    if value.is_empty() {
        return Err(OpaqueIdError("identifier must not be empty"));
    }
    if value.len() > MAX_OPAQUE_ID_LEN {
        return Err(OpaqueIdError("identifier is longer than 256 bytes"));
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
    /// One native application installation registered with a push gateway.
    InstallationId,
    "One native application installation registered with a push gateway."
);
uuid_id!(
    /// One organisation whose policy a host has opted into (section 17).
    OrganisationId,
    "One organisation whose signed policy a host has opted into."
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
    /// The backup generation an archive belongs to. Only its producer advances it.
    BackupGeneration,
    "The backup generation an archive belongs to. Only its producer advances it."
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
