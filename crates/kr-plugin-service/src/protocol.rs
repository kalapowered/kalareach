//! The frames a worker and the plugin host exchange.
//!
//! One closed union in each direction, carried as KR-CBOR-1 objects in the host's own
//! length-delimited frames. A frame that does not belong on the connection it arrived on is a
//! refusal rather than a parse failure, which is what a closed union buys.
//!
//! # Correlation
//!
//! Every request carries a number the response echoes, because the connection is not
//! request-and-response only: the host also sends document nodes, gaps, faults and disabled notices
//! as they happen. A frame with a `reply_to` is somebody's answer; a frame without one is news.
//!
//! # Why the component travels as a path
//!
//! A control frame is bounded at 1 MiB and a component may be sixteen times that. The worker has
//! already verified the package the payload came from, so it sends the payload's location and the
//! digest it verified, and the host reads the file and checks the digest before compiling anything.
//! Nothing is trusted because it was on disk: the digest is the same one the catalogue signed, and
//! the path has to be inside the packages directory the host was started with.

use kr_protocol::identity::{BootIdentity, ProcessStartIdentity};
use kr_protocol::ids::EnvironmentId;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, Nonce256, Signature64};
use kr_protocol::worker::ReservationId;
use serde::{Deserialize, Serialize};

use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::identity::PluginIdentity;

/// The domain separating the plugin host's startup claim.
pub const RENDEZVOUS_DOMAIN: &str = "kr-plugin-host/1/rendezvous";

/// The domain separating the plugin host's answer to a verification challenge.
pub const VERIFY_DOMAIN: &str = "kr-plugin-host/1/verify";

/// One plugin host protocol, and where a host that speaks it is found.
///
/// A host process speaks one protocol, fixed by the program it runs, and each protocol has an
/// endpoint and a descriptor of its own inside the environment runtime directory, so a host of one
/// protocol is never published over a host of another and a client of one never reaches the other.
/// The first protocol keeps the names it has always had; a later protocol `/N` uses `p<N>.sock`
/// and `plugin-host-<N>.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostProtocol {
    /// The protocol's name, as a host's `Hello` answers it and a descriptor records it.
    pub name: &'static str,
    /// The name of the host's endpoint inside the environment runtime directory.
    pub endpoint: &'static str,
    /// The file the host's descriptor is published as, inside the environment runtime directory.
    pub descriptor: &'static str,
}

impl HostProtocol {
    /// The protocol this build's plugin host and client speak.
    pub const THIS: Self = Self {
        name: kr_protocol::retained::PLUGIN_HOST_PROTOCOL,
        endpoint: "p3.sock",
        descriptor: "plugin-host-3.json",
    };

    /// The protocol of the plugin host a retained level's workers speak: a host of the release
    /// before, adopted when it runs and otherwise started from that release's own program.
    ///
    /// The 0.78 cut removes this protocol, its route in the control daemon, `retained_host` and its
    /// entry in [`kr_protocol::retained::RETAINED_PLUGIN_HOST_PROTOCOLS`].
    pub const SECOND: Self = Self {
        name: "kr-plugin-host/2",
        endpoint: "p.sock",
        descriptor: "plugin-host.json",
    };

    /// Every protocol a route exists for: this build's and each retained one.
    pub const ALL: [Self; 2] = [Self::THIS, Self::SECOND];

    /// The protocol a name stands for, where a route exists for it.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|protocol| protocol.name == name)
    }
}

/// The prefix of the rendezvous endpoint a launcher listens on for one plugin host.
///
/// One endpoint per reservation rather than one for the environment. A shared address would be
/// rebound for every launch, and a launch that reused an address a previous one had just given up
/// would be answering on a name two launches had meant. The reservation is what makes each launch
/// its own, so it names the address as well.
pub const RENDEZVOUS_PREFIX: &str = "pr-";

/// The plugin host's startup claim.
///
/// The same shape the worker's rendezvous has, and for the same reason: the launcher recorded the
/// process identity it was told about before this process connected, and this claim is what ties
/// that record to a key it can challenge later. A second claim against one reservation is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRendezvous {
    /// The reservation this process was started for.
    pub reservation_id: ReservationId,
    /// The environment it serves.
    pub environment_id: EnvironmentId,
    /// The public half of the key it generated at startup.
    pub host_public_key: AuthorisationKey,
    /// The boot it started in.
    pub boot_identity: BootIdentity,
    /// Its own process identity, which the launcher compares with what the launcher was told and
    /// with the connecting peer.
    pub process_start_identity: ProcessStartIdentity,
    /// The endpoint it is serving workers on.
    pub endpoint: String,
    /// The signature over [`rendezvous_elements`].
    pub signature: Signature64,
}

/// Builds the transcript a rendezvous signature covers.
///
/// `CBOR(["kr-plugin-host/1/rendezvous", reservation_id, environment_id, host_public_key,
/// boot_identity, process_start_identity, endpoint])`.
///
/// # Errors
///
/// Returns a CBOR error when a field cannot be represented in KR-CBOR-1.
pub fn rendezvous_elements(
    reservation_id: ReservationId,
    environment_id: EnvironmentId,
    host_public_key: &AuthorisationKey,
    boot_identity: &BootIdentity,
    process_start_identity: &ProcessStartIdentity,
    endpoint: &str,
) -> Result<Vec<kr_cbor::CanonicalValue>, kr_cbor::CborError> {
    Ok(vec![
        kr_cbor::to_canonical_value(&reservation_id)?,
        kr_cbor::to_canonical_value(&environment_id)?,
        kr_cbor::to_canonical_value(host_public_key)?,
        kr_cbor::to_canonical_value(boot_identity)?,
        kr_cbor::to_canonical_value(process_start_identity)?,
        kr_cbor::to_canonical_value(endpoint)?,
    ])
}

/// What a launcher sends back once it has accepted a claim and published the descriptor.
///
/// It carries no signature and needs none. The rendezvous endpoint is inside the owner-only runtime
/// directory and the host checked the peer's credentials before it wrote its claim, so the only
/// process that can answer on that connection is one running as this user with a descriptor of the
/// launcher's own. What the acknowledgement settles is ordering, not identity: a host that starts
/// serving before the launcher has accepted it would be answering workers as a process the daemon
/// may still refuse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RendezvousAccepted {
    /// The reservation the claim was accepted for.
    pub reservation_id: ReservationId,
    /// The environment it serves.
    pub environment_id: EnvironmentId,
    /// The endpoint the launcher published for it.
    pub endpoint: String,
}

/// The plugin host's answer to a verification challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostVerifyProof {
    /// The environment the host serves.
    pub environment_id: EnvironmentId,
    /// The boot it is running in.
    pub boot_identity: BootIdentity,
    /// Its process identity.
    pub process_start_identity: ProcessStartIdentity,
    /// The endpoint it answered on.
    pub endpoint: String,
    /// The signature over [`verify_elements`].
    pub signature: Signature64,
}

/// Builds the transcript a verification signature covers.
///
/// `CBOR(["kr-plugin-host/1/verify", environment_id, boot_identity, process_start_identity,
/// endpoint, nonce])`.
///
/// # Errors
///
/// Returns a CBOR error when a field cannot be represented in KR-CBOR-1.
pub fn verify_elements(
    environment_id: EnvironmentId,
    boot_identity: &BootIdentity,
    process_start_identity: &ProcessStartIdentity,
    endpoint: &str,
    nonce: &Nonce256,
) -> Result<Vec<kr_cbor::CanonicalValue>, kr_cbor::CborError> {
    Ok(vec![
        kr_cbor::to_canonical_value(&environment_id)?,
        kr_cbor::to_canonical_value(boot_identity)?,
        kr_cbor::to_canonical_value(process_start_identity)?,
        kr_cbor::to_canonical_value(endpoint)?,
        kr_cbor::to_canonical_value(nonce)?,
    ])
}

/// What a worker reads out of the published plugin-host descriptor.
///
/// It carries no secret. Nothing in it is acted on until the process behind the endpoint has
/// answered a challenge against the public key recorded here, which is the same rule the worker
/// descriptors follow: a filename and a process identifier are hints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDescriptor {
    /// The protocol the host speaks.
    pub protocol: String,
    /// The environment it serves.
    pub environment_id: EnvironmentId,
    /// The reservation it was started for.
    pub reservation_id: ReservationId,
    /// The endpoint workers connect to.
    pub endpoint: String,
    /// The boot it started in.
    pub boot_identity: BootIdentity,
    /// Its process identity.
    pub process_start_identity: ProcessStartIdentity,
    /// The public half of its per-process key.
    pub host_public_key: AuthorisationKey,
}

/// Where a component's bytes are, and which bytes they must be.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentSource {
    /// The payload's path, which has to be inside the host's packages directory.
    pub path: String,
    /// The digest the worker verified against the catalogue.
    pub digest: PayloadDigest,
    /// The length the worker verified.
    pub bytes: u64,
}

/// The facts a component may read about its binding, as they travel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireFacts {
    /// The plugin this instance serves.
    pub plugin_id: String,
    /// The binding revision.
    pub binding_revision: u64,
    /// What the bound execution is doing.
    pub activity: String,
    /// The upstream thread, where the application exposes one.
    pub thread_id: Option<String>,
    /// The upstream turn, where the application exposes one.
    pub turn_id: Option<String>,
    /// When these facts were last true.
    pub updated_at_ms: u64,
    /// The rights the current actor holds.
    pub held_rights: Vec<ActionRight>,
}

/// One immutable source event, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireSourceEvent {
    /// The private broker handle.
    pub handle: kr_protocol::ids::SourceEventHandle,
    /// What produced the bytes.
    pub provenance: String,
    /// When the host observed them.
    pub observed_at_ms: u64,
    /// The native request identifier, where the event is a native request.
    pub request_id: Option<String>,
    /// The bytes.
    #[serde(with = "serde_bytes_vec")]
    pub bytes: Vec<u8>,
}

/// One document node, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireNode {
    /// The node's stable identifier.
    pub node_id: String,
    /// The node's revision.
    pub node_revision: u64,
    /// The node body, as canonical JSON for that node kind.
    pub body_json: String,
}

/// Everything one registration names.
///
/// A record rather than a handful of fields on the request, because it is the largest thing this
/// protocol carries and a union whose variants differ wildly in size costs every frame the size of
/// the biggest one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingRegistration {
    /// The binding this instance serves.
    pub binding_id: kr_protocol::scalars::Uuid,
    /// Which package, which bytes and which catalogue generation.
    pub identity: PluginIdentity,
    /// The facts the component may read.
    pub facts: WireFacts,
    /// The executable the host matched.
    pub executable: String,
    /// Where the component's bytes are.
    pub component: ComponentSource,
}

/// One value of an action's argument, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireArgument {
    /// Text.
    Text(String),
    /// A whole number.
    Integer(i64),
    /// A decision.
    Boolean(bool),
    /// A chosen identifier.
    Choice(String),
    /// A completed attachment handle.
    AttachmentHandle(String),
    /// A node of the package's presentation document.
    NodeRef(String),
}

/// One named argument of an action, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireNamedArgument {
    /// The parameter's name.
    pub name: String,
    /// Its value.
    pub value: WireArgument,
}

/// The authority of one invocation, as a component reads it.
///
/// The host issues it and the component only reads it; nothing in it is a handle the component
/// could present to anybody. The broker's own token, with its handle, is issued separately and
/// never leaves the worker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireToken {
    /// The verified actor the action is for.
    pub actor_id: String,
    /// The grant record the actor acts under, empty for the local owner, who has none.
    pub grant_id: String,
    /// The binding revision the invocation was admitted at.
    pub binding_revision: u64,
    /// The thread revision, where the application has one apart from the binding's.
    pub thread_revision: Option<u64>,
    /// The declared action.
    pub action_id: String,
    /// The SHA-256 of exactly the parameters a person saw.
    #[serde(with = "serde_bytes_vec")]
    pub parameter_hash: Vec<u8>,
    /// When the token stops being one a plan should be prepared under, in milliseconds since the
    /// Unix epoch.
    pub expires_at_ms: u64,
}

/// One step of a path into an upstream request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireSegment {
    /// A member name.
    Member(String),
    /// An array index.
    Index(u32),
}

/// One field of an upstream request and the value that goes in it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireField {
    /// The path into the request, from its root.
    pub path: Vec<WireSegment>,
    /// The value.
    pub value: WireArgument,
}

/// What a component says the broker should do, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireOperation {
    /// Redraw the component's own document.
    Present,
    /// Send one routed upstream method with its fields filled in.
    UpstreamMethod {
        /// The method.
        method: String,
        /// The fields.
        fields: Vec<WireField>,
    },
    /// Cancel the bound execution's current turn.
    UpstreamCancel,
    /// Contribute a completed attachment to the upstream draft.
    UpstreamAttachment {
        /// The attachment the component names.
        attachment_id: String,
    },
    /// Write text into the terminal.
    TerminalText(String),
}

/// The effect a component proposes, as it travels.
///
/// A proposal and nothing more: the worker compares every part of it with the invocation and the
/// declaration before anything is dispatched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WirePlan {
    /// The action the component says it prepared.
    pub action_id: String,
    /// The effect class it says the action has.
    pub class: kr_plugin_sdk::effect::EffectClass,
    /// What it asks the broker to do.
    pub operation: WireOperation,
    /// The arguments it says it filled in.
    pub arguments: Vec<WireNamedArgument>,
}

/// What a worker asks the plugin host to do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Request {
    /// The number the response echoes.
    pub request_id: u64,
    /// What is being asked.
    pub body: RequestBody,
}

/// The closed set of things a worker may ask for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestBody {
    /// Opens the connection and names the protocol.
    Hello {
        /// The protocol the caller speaks.
        protocol: String,
    },
    /// Asks the host to prove which process it is.
    Verify {
        /// A fresh 32-byte challenge.
        nonce: Nonce256,
    },
    /// Registers a binding: compile the component, instantiate it and bind it.
    RegisterBinding(Box<BindingRegistration>),
    /// Delivers one scoped source event to a binding's observation queue.
    Event {
        /// The binding.
        binding_id: kr_protocol::scalars::Uuid,
        /// The event.
        event: WireSourceEvent,
    },
    /// Asks a binding for a fresh document.
    Snapshot {
        /// The binding.
        binding_id: kr_protocol::scalars::Uuid,
        /// The caller's own deadline.
        deadline_ms: u64,
    },
    /// Asks a binding's component to turn an invoked control into a proposed effect.
    PrepareAction(Box<PrepareActionCall>),
    /// Takes a binding's resumable state.
    Checkpoint {
        /// The binding.
        binding_id: kr_protocol::scalars::Uuid,
        /// The caller's own deadline.
        deadline_ms: u64,
    },
    /// Restores a binding from a checkpoint.
    Restore {
        /// The binding.
        binding_id: kr_protocol::scalars::Uuid,
        /// The state a checkpoint produced.
        #[serde(with = "serde_bytes_vec")]
        state: Vec<u8>,
        /// The caller's own deadline.
        deadline_ms: u64,
    },
    /// Removes a binding and its instance.
    Unbind {
        /// The binding.
        binding_id: kr_protocol::scalars::Uuid,
    },
    /// Asks what the host is doing.
    Health,
    /// Asks a binding's component to interpret one native request.
    ///
    /// The answer is a proposal. The worker compares every part of it with the request it holds
    /// before anything becomes an approval.
    Decode(Box<DecodeCall>),
    /// Asks a binding's component to encode a validated decision as the bytes of a response.
    ///
    /// The answer is bytes and nothing has been sent: the host has no way to send them.
    Encode(Box<EncodeCall>),
    /// Replaces the facts a binding's component reads about its bound execution.
    ///
    /// Answered on acceptance. A revision replaces an earlier one no call has yet seen, and the
    /// binding's next call is the first to see it.
    ReviseFacts {
        /// The binding.
        binding_id: kr_protocol::scalars::Uuid,
        /// The facts, whole.
        facts: WireFacts,
    },
    /// Replaces the attachments a binding's component reads the current draft as holding.
    ///
    /// Answered and applied as [`Self::ReviseFacts`] is.
    ReviseAttachments {
        /// The binding.
        binding_id: kr_protocol::scalars::Uuid,
        /// The attachments, whole.
        attachments: Vec<WireAttachment>,
    },
    /// Tells the host whether privacy mode stands for the worker this connection serves.
    ///
    /// While it does, the host writes no document of this connection and sends the presentation of
    /// a decoded request empty. Answered once that holds.
    Privacy {
        /// Whether privacy mode stands.
        private: bool,
    },
}

/// Everything a `decode-request` call carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodeCall {
    /// The binding.
    pub binding_id: kr_protocol::scalars::Uuid,
    /// The native request, as the broker retained it.
    pub event: WireSourceEvent,
    /// The caller's own deadline.
    pub deadline_ms: u64,
}

/// Everything an `encode-response` call carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncodeCall {
    /// The binding.
    pub binding_id: kr_protocol::scalars::Uuid,
    /// The broker's own record of the pending request.
    pub request: WireRequestSnapshot,
    /// The decision the broker validated, one of the request's offered decisions.
    pub decision: String,
    /// The request's source event, where the broker still holds it.
    pub event: Option<WireSourceEvent>,
    /// The caller's own deadline.
    pub deadline_ms: u64,
}

/// The broker's own record of one pending native request, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRequestSnapshot {
    /// The identifier the upstream gave the request.
    pub request_id: String,
    /// The source event the request arrived as.
    pub handle: kr_protocol::ids::SourceEventHandle,
    /// The method the request named.
    pub method: String,
    /// How the method is classified.
    pub class: WireMethodClass,
    /// When the broker received the request, in milliseconds since the Unix epoch.
    pub received_at_ms: u64,
    /// When the upstream stops waiting for an answer, where it says.
    pub deadline_at_ms: Option<u64>,
    /// The decisions the upstream offers, as stable identifiers.
    pub offered_decisions: Vec<String>,
    /// The binding revision the request was recorded at.
    pub binding_revision: u64,
}

/// How a native method is classified, as it travels.
///
/// The protocol's own closed set rather than another crate's, so that a change to that type is not
/// a change to a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireMethodClass {
    /// The method reads.
    Observation,
    /// The method changes something.
    Mutation,
    /// The method carries a credential or a configuration.
    Credential,
    /// The method is not one the connector supports.
    Unsupported,
}

/// A native request a component decoded, as it travels.
///
/// All of the contract's record. The worker uses the identifier, the summary and the decisions and
/// believes none of them as they stand.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireDecoded {
    /// The identifier the component says the request has.
    pub request_id: String,
    /// How the component says its method is classified.
    pub class: WireMethodClass,
    /// A one-line summary of what answering yes would do.
    pub summary: String,
    /// The decisions the component says the upstream offers, as stable identifiers.
    pub decisions: Vec<String>,
    /// The document nodes that present the request, as canonical JSON.
    ///
    /// Empty while privacy mode stands on the connection.
    pub presentation: Vec<String>,
}

/// A response a component encoded, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEncoded {
    /// The identifier of the request the component says it answers.
    pub request_id: String,
    /// The bytes. Nothing has sent them.
    #[serde(with = "serde_bytes_vec")]
    pub bytes: Vec<u8>,
}

/// One completed attachment of the current draft, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireAttachment {
    /// The attachment's identifier.
    pub attachment_id: String,
    /// Its name.
    pub name: String,
    /// Its media type.
    pub media_type: String,
    /// Its size in bytes.
    pub size_bytes: u64,
    /// When its transfer completed, in milliseconds since the Unix epoch.
    pub completed_at_ms: u64,
}

/// Everything a `prepare-action` call carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareActionCall {
    /// The binding.
    pub binding_id: kr_protocol::scalars::Uuid,
    /// The invocation's authority, as the component reads it.
    pub token: WireToken,
    /// The arguments the action was invoked with, in the declaration's order.
    pub arguments: Vec<WireNamedArgument>,
    /// The caller's own deadline.
    pub deadline_ms: u64,
}

impl RequestBody {
    /// Returns the binding this request concerns, where it concerns one.
    #[must_use]
    pub const fn binding_id(&self) -> Option<kr_protocol::scalars::Uuid> {
        match self {
            Self::RegisterBinding(registration) => Some(registration.binding_id),
            Self::PrepareAction(call) => Some(call.binding_id),
            Self::Decode(call) => Some(call.binding_id),
            Self::Encode(call) => Some(call.binding_id),
            Self::Event { binding_id, .. }
            | Self::Snapshot { binding_id, .. }
            | Self::Checkpoint { binding_id, .. }
            | Self::Restore { binding_id, .. }
            | Self::ReviseFacts { binding_id, .. }
            | Self::ReviseAttachments { binding_id, .. }
            | Self::Unbind { binding_id } => Some(*binding_id),
            Self::Hello { .. } | Self::Verify { .. } | Self::Health | Self::Privacy { .. } => None,
        }
    }

    /// Returns the name used in a refusal and in the host's own records.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "hello",
            Self::Verify { .. } => "verify",
            Self::RegisterBinding(_) => "register_binding",
            Self::Event { .. } => "event",
            Self::Snapshot { .. } => "snapshot",
            Self::PrepareAction(_) => "prepare_action",
            Self::Checkpoint { .. } => "checkpoint",
            Self::Restore { .. } => "restore",
            Self::Unbind { .. } => "unbind",
            Self::Health => "health",
            Self::Decode(_) => "decode",
            Self::Encode(_) => "encode",
            Self::ReviseFacts { .. } => "revise_facts",
            Self::ReviseAttachments { .. } => "revise_attachments",
            Self::Privacy { .. } => "privacy",
        }
    }
}

/// What the plugin host sends back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frame {
    /// An answer to a request.
    Response {
        /// The request this answers.
        reply_to: u64,
        /// The answer.
        body: ResponseBody,
    },
    /// Something a binding produced without being asked.
    Notice(Notice),
}

/// The closed set of answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBody {
    /// The connection is open.
    Hello {
        /// The protocol the host speaks.
        protocol: String,
        /// The host's descriptor, so a caller that read a stale one can compare.
        descriptor: Box<HostDescriptor>,
    },
    /// The host's answer to a challenge.
    Verified(Box<HostVerifyProof>),
    /// The binding is registered and bound.
    Registered {
        /// Whether the component was compiled or loaded from the cache.
        origin: String,
        /// How long obtaining the compiled component took.
        elapsed_ms: u64,
    },
    /// The event was offered to the queue.
    Admitted {
        /// What happened to it.
        admission: String,
        /// How many observations were lost to make room, where any were.
        lost_events: u32,
        /// How many bytes they held.
        lost_bytes: u64,
    },
    /// A call answered.
    ///
    /// The document the call drew is not here. Nodes travel as [`Notice::Document`] frames, chunked
    /// so each fits one frame, because one call may draw a mebibyte and a control frame carries a
    /// mebibyte including its envelope. A caller reads the notices for the document and this for
    /// the answer.
    Called {
        /// The component's answer, where it answered.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<CallValue>,
        /// The fault the component declared, where it declared one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fault: Option<String>,
        /// Which of this binding's documents the call drew, where it drew one.
        ///
        /// Nothing means the call drew nothing, which is how a caller tells an empty document from
        /// one whose notices have not arrived yet.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        document: Option<u64>,
    },
    /// The binding is gone.
    Unbound {
        /// Whether there was one to remove.
        existed: bool,
    },
    /// A revision of a binding's facts or attachments was accepted.
    Revised,
    /// Privacy mode is as the worker said, for the rest of this connection until it says otherwise.
    ///
    /// Every document frame of the connection is before this answer in the stream, or is never
    /// written.
    PrivacySet {
        /// Whether privacy mode stands.
        private: bool,
    },
    /// What the host is doing.
    Health(Box<HostHealth>),
    /// The request was refused.
    Refused {
        /// Which request.
        request: String,
        /// Why.
        detail: String,
        /// Whether the binding is now disabled.
        disabled: bool,
    },
}

/// A value a call returned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallValue {
    /// Nothing but the document.
    Document,
    /// The effect a component proposed.
    Plan(Box<WirePlan>),
    /// A component's own resumable state.
    State(#[serde(with = "serde_bytes_vec")] Vec<u8>),
    /// A native request a component decoded.
    Decoded(Box<WireDecoded>),
    /// A response a component encoded.
    Encoded(Box<WireEncoded>),
}

/// What the host reports about itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHealth {
    /// How many bindings are live, across every connection.
    pub live_bindings: u64,
    /// How many bindings this connection holds.
    pub connection_bindings: u64,
    /// How many one connection may hold.
    pub binding_bound: u64,
    /// How many calls into a component this connection's bindings have finished.
    ///
    /// A count that grew between two health reports is a component that was running between them,
    /// which is what tells a caller that its own progress happened alongside one rather than after
    /// it.
    pub component_calls: u64,
    /// How many compiled components the cache is holding in memory.
    pub resident_components: u64,
    /// How many compiled bytes those components were made from.
    pub resident_bytes: u64,
    /// How many bytes of notices this connection has waiting to be written.
    pub queued_notice_bytes: u64,
    /// How many documents this connection has dropped for want of room.
    pub dropped_documents: u64,
    /// The engine version.
    pub engine_version: String,
    /// The target it compiles machine code for.
    pub target: String,
    /// The engine's compatibility identity, which is part of every cache key.
    pub engine_compatibility: String,
    /// How long the host has been running.
    pub uptime_ms: u64,
    /// Whether the epoch ticker is running, and therefore whether elapsed deadlines are enforced.
    pub deadlines_enforceable: bool,
}

/// Something a binding produced without being asked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Notice {
    /// A component emitted document nodes.
    ///
    /// One call's document may take more than one of these: a call may draw a mebibyte and a frame
    /// carries a mebibyte including its envelope. `document` is the number that call's output
    /// carries, counted per binding, and `last` marks the final piece, so a reader knows which
    /// notices belong together and when it has all of them.
    Document {
        /// The binding.
        binding_id: kr_protocol::scalars::Uuid,
        /// Which export emitted them.
        call: String,
        /// Which of this binding's documents these nodes belong to.
        document: u64,
        /// Whether this is the last piece of that document.
        last: bool,
        /// The nodes.
        nodes: Vec<WireNode>,
    },
    /// Something was lost, and a fresh snapshot follows.
    ///
    /// The two kinds of loss are counted apart because they mean different things. Lost
    /// observations are events the component never saw. Lost documents are drawings the reader
    /// never saw; the component has been asked to draw again.
    Gap {
        /// The binding.
        binding_id: kr_protocol::scalars::Uuid,
        /// How many observations were lost.
        events: u32,
        /// How many bytes they held.
        bytes: u64,
        /// How many documents the reader never received.
        documents: u64,
    },
    /// A call failed and the binding survived it.
    Fault {
        /// The binding.
        binding_id: kr_protocol::scalars::Uuid,
        /// Which export failed.
        call: String,
        /// The failure.
        detail: String,
        /// How many faults are inside the window now.
        faults_in_window: u32,
    },
    /// The binding is disabled and will run nothing more.
    Disabled {
        /// The binding.
        binding_id: kr_protocol::scalars::Uuid,
        /// Why, in the words a person is shown.
        reason: String,
    },
}

impl Notice {
    /// Returns the binding this notice concerns.
    #[must_use]
    pub const fn binding_id(&self) -> kr_protocol::scalars::Uuid {
        match self {
            Self::Document { binding_id, .. }
            | Self::Gap { binding_id, .. }
            | Self::Fault { binding_id, .. }
            | Self::Disabled { binding_id, .. } => *binding_id,
        }
    }
}

/// Byte strings, as CBOR byte strings rather than as arrays of numbers.
mod serde_bytes_vec {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        kr_protocol::scalars::Bytes::deserialize(deserializer)
            .map(kr_protocol::scalars::Bytes::into_vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + core::fmt::Debug,
    {
        let bytes = kr_cbor::to_canonical_vec(value).expect("the frame encodes");
        let decoded: T = kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
            .expect("the frame decodes");
        assert_eq!(&decoded, value);
        decoded
    }

    #[test]
    fn every_request_round_trips_through_canonical_cbor() {
        let binding_id = kr_protocol::scalars::Uuid::from_bytes([3; 16]);
        for body in [
            RequestBody::Hello {
                protocol: kr_protocol::retained::PLUGIN_HOST_PROTOCOL.to_owned(),
            },
            RequestBody::Verify {
                nonce: Nonce256::from_bytes([4; 32]),
            },
            RequestBody::Event {
                binding_id,
                event: WireSourceEvent {
                    handle: kr_protocol::ids::SourceEventHandle::new("se-1")
                        .expect("a bounded handle"),
                    provenance: "native_protocol".to_owned(),
                    observed_at_ms: 7,
                    request_id: Some("req-1".to_owned()),
                    bytes: b"{}".to_vec(),
                },
            },
            RequestBody::Snapshot {
                binding_id,
                deadline_ms: 200,
            },
            RequestBody::PrepareAction(Box::new(PrepareActionCall {
                binding_id,
                token: WireToken {
                    actor_id: "local:501".to_owned(),
                    grant_id: String::new(),
                    binding_revision: 3,
                    thread_revision: None,
                    action_id: "turn.cancel".to_owned(),
                    parameter_hash: vec![7; 32],
                    expires_at_ms: 1_700_000_005_000,
                },
                arguments: vec![WireNamedArgument {
                    name: "reason".to_owned(),
                    value: WireArgument::Text("because".to_owned()),
                }],
                deadline_ms: 500,
            })),
            RequestBody::Checkpoint {
                binding_id,
                deadline_ms: 200,
            },
            RequestBody::Restore {
                binding_id,
                state: b"state".to_vec(),
                deadline_ms: 200,
            },
            RequestBody::Unbind { binding_id },
            RequestBody::Health,
        ] {
            round_trip(&Request {
                request_id: 9,
                body: body.clone(),
            });
        }
    }

    #[test]
    fn a_request_names_itself_and_the_binding_it_concerns() {
        let binding_id = kr_protocol::scalars::Uuid::from_bytes([3; 16]);
        assert_eq!(
            RequestBody::Unbind { binding_id }.binding_id(),
            Some(binding_id)
        );
        assert_eq!(RequestBody::Health.binding_id(), None);
        assert_eq!(RequestBody::Health.name(), "health");
        assert_eq!(
            RequestBody::Event {
                binding_id,
                event: WireSourceEvent {
                    handle: kr_protocol::ids::SourceEventHandle::new("se-1")
                        .expect("a bounded handle"),
                    provenance: "terminal_scrape".to_owned(),
                    observed_at_ms: 0,
                    request_id: None,
                    bytes: Vec::new(),
                },
            }
            .name(),
            "event"
        );
    }

    #[test]
    fn a_notice_round_trips_and_names_its_binding() {
        let binding_id = kr_protocol::scalars::Uuid::from_bytes([5; 16]);
        let notice = Notice::Gap {
            binding_id,
            events: 4,
            bytes: 8192,
            documents: 1,
        };
        assert_eq!(notice.binding_id(), binding_id);
        round_trip(&Frame::Notice(notice));
    }

    #[test]
    fn a_response_round_trips_through_canonical_cbor() {
        round_trip(&Frame::Response {
            reply_to: 1,
            body: ResponseBody::Called {
                value: Some(CallValue::State(b"resumable".to_vec())),
                fault: None,
                document: Some(3),
            },
        });
        round_trip(&Frame::Response {
            reply_to: 4,
            body: ResponseBody::Called {
                value: Some(CallValue::Plan(Box::new(WirePlan {
                    action_id: "attach".to_owned(),
                    class: kr_plugin_sdk::effect::EffectClass::UpstreamAttachment,
                    operation: WireOperation::UpstreamAttachment {
                        attachment_id: "t-1".to_owned(),
                    },
                    arguments: Vec::new(),
                }))),
                fault: None,
                document: None,
            },
        });
        // The document a call drew travels as its own frames, so a caller reads it from the
        // notices rather than from the answer.
        round_trip(&Frame::Notice(Notice::Document {
            binding_id: kr_protocol::scalars::Uuid::from_bytes([7; 16]),
            call: "snapshot".to_owned(),
            document: 3,
            last: true,
            nodes: vec![WireNode {
                node_id: "n0".to_owned(),
                node_revision: 2,
                body_json: "{}".to_owned(),
            }],
        }));
        round_trip(&Frame::Response {
            reply_to: 2,
            body: ResponseBody::Refused {
                request: "register_binding".to_owned(),
                detail: "the component imports wasi:filesystem/types@0.2.9".to_owned(),
                disabled: false,
            },
        });
    }

    #[test]
    fn an_unknown_request_is_refused_rather_than_ignored() {
        // A closed union is what makes an unrecognised frame a refusal. The encoding is an
        // externally tagged map, so a variant nobody defined simply does not decode.
        let bytes =
            kr_cbor::to_canonical_vec(&serde_json::json!({"request_id": 1, "body": {"drain": {}}}))
                .expect("the document encodes");
        assert!(
            kr_cbor::from_canonical_slice::<Request>(&bytes, &kr_cbor::Limits::DEFAULT).is_err()
        );
    }

    #[test]
    fn the_transcripts_cover_every_field_they_name() {
        let environment_id = EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16]));
        let reservation_id = ReservationId::new(kr_protocol::scalars::Uuid::from_bytes([2; 16]));
        let key = AuthorisationKey::from_bytes([3; 32]);
        let boot = BootIdentity {
            source: kr_protocol::identity::BootIdentitySource::LinuxBootId,
            value: kr_protocol::scalars::Bytes::new(vec![4; 16]),
        };
        let start = ProcessStartIdentity::new(
            42,
            kr_protocol::identity::ProcessStartSource::LinuxProcStat,
            99,
        );

        let rendezvous = rendezvous_elements(
            reservation_id,
            environment_id,
            &key,
            &boot,
            &start,
            "/run/kr/p.sock",
        )
        .expect("the transcript encodes");
        assert_eq!(rendezvous.len(), 6);

        let verify = verify_elements(
            environment_id,
            &boot,
            &start,
            "/run/kr/p.sock",
            &Nonce256::from_bytes([5; 32]),
        )
        .expect("the transcript encodes");
        assert_eq!(verify.len(), 5);

        // Two different endpoints produce two different transcripts, so a proof for one endpoint
        // cannot be replayed on another.
        let other = rendezvous_elements(
            reservation_id,
            environment_id,
            &key,
            &boot,
            &start,
            "/run/kr/other.sock",
        )
        .expect("the transcript encodes");
        assert_ne!(rendezvous, other);
    }

    #[test]
    fn a_launcher_acknowledges_the_claim_it_accepted() {
        let accepted = RendezvousAccepted {
            reservation_id: ReservationId::new(kr_protocol::scalars::Uuid::from_bytes([8; 16])),
            environment_id: EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16])),
            endpoint: "/run/kr/p.sock".to_owned(),
        };
        assert_eq!(round_trip(&accepted), accepted);
    }

    #[test]
    fn the_domains_and_names_are_the_ones_this_protocol_publishes() {
        assert_eq!(RENDEZVOUS_DOMAIN, "kr-plugin-host/1/rendezvous");
        assert_eq!(VERIFY_DOMAIN, "kr-plugin-host/1/verify");
        assert_ne!(RENDEZVOUS_DOMAIN, VERIFY_DOMAIN);
        assert_eq!(RENDEZVOUS_PREFIX, "pr-");
    }

    #[test]
    fn each_protocol_has_a_name_an_endpoint_and_a_descriptor_no_other_shares() {
        use std::collections::BTreeSet;

        let protocols = HostProtocol::ALL;
        for field in [
            protocols.map(|protocol| protocol.name),
            protocols.map(|protocol| protocol.endpoint),
            protocols.map(|protocol| protocol.descriptor),
        ] {
            assert_eq!(
                field.into_iter().collect::<BTreeSet<_>>().len(),
                protocols.len(),
                "{field:?}"
            );
        }
        assert_eq!(HostProtocol::THIS.name, "kr-plugin-host/3");
        // The first protocol keeps its names, which a host of the release before still publishes.
        assert_eq!(HostProtocol::SECOND.endpoint, "p.sock");
        assert_eq!(HostProtocol::SECOND.descriptor, "plugin-host.json");
        assert_eq!(
            HostProtocol::named("kr-plugin-host/2"),
            Some(HostProtocol::SECOND)
        );
        assert_eq!(HostProtocol::named("kr-plugin-host/9"), None);
    }

    #[test]
    fn every_retained_protocol_has_a_route_and_every_route_but_this_builds_is_retained() {
        for level in &kr_protocol::retained::RETAINED {
            let recorded = level.plugin_host.trim();
            assert!(
                recorded == HostProtocol::THIS.name || HostProtocol::named(recorded).is_some(),
                "level {} recorded {recorded}, which has no route",
                level.level
            );
        }
        for protocol in HostProtocol::ALL {
            if protocol == HostProtocol::THIS {
                continue;
            }
            assert!(
                kr_protocol::retained::RETAINED_PLUGIN_HOST_PROTOCOLS.contains(&protocol.name),
                "{} is not listed as a retained protocol",
                protocol.name
            );
            assert!(
                kr_protocol::retained::RETAINED
                    .iter()
                    .any(|level| level.plugin_host.trim() == protocol.name),
                "no retained level records {}: remove its route",
                protocol.name
            );
        }
    }
}
