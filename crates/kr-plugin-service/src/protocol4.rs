//! The frames of the plugin host protocol `kr-plugin-host/4`.
//!
//! The same conversation as [`crate::protocol`] holds for `kr-plugin-host/3`, in a second closed
//! set of frames: a request or a response names the registration it belongs to, a checkpoint says
//! which events the instance has consumed, a restore says which events its state covers, an
//! admission says how much room the host's queue has left, and a notice names the registration it
//! is about. A binding's registration is a number the worker mints for each `RegisterBinding`; the
//! host echoes it and never reads it as anything else.
//!
//! Each endpoint speaks one protocol. A frame of this set is never written on the `/3` endpoint and
//! a `/3` frame is never written here, so nothing in `/3` changes. The leaf records the two sets
//! share (a node, a source event, a plan, a decoded request) are the `/3` types: a change to one of
//! them changes both protocols, and the recorded frames of each protocol hold both.
//!
//! Every frame and member below is closed at the release that first carries this protocol. A member
//! added to any of them afterwards is a new protocol.
//!
//! # What a host writes
//!
//! A host writes `consumed`, `Consumed` notices and the loss positions only when its writer is open
//! (`kr_protocol::retained::replay_writer_open`). A host with its writer closed still reads every
//! member and writes none of them. A worker reads every member whatever its own gate says.

use kr_protocol::identity::{BootIdentity, ProcessStartIdentity};
use kr_protocol::ids::{EnvironmentId, SourceEventHandle};
use kr_protocol::local::LocalBuild;
use kr_protocol::scalars::{AuthorisationKey, Nonce256, Uuid};
use kr_protocol::worker::ReservationId;
use serde::{Deserialize, Serialize};

use crate::protocol::{
    BindingRegistration, DecodeCall, EncodeCall, HostHealth, HostVerifyProof, PrepareActionCall,
    WireAttachment, WireDecoded, WireEncoded, WireFacts, WireNode, WirePlan, WireSourceEvent,
    serde_bytes_vec,
};

/// What the plugin host of this protocol publishes about itself.
///
/// The members of the `/3` descriptor, and the build of the program that answers. Like the other
/// members it is a hint: what settles which process answers is the challenge, and a wrong `build`
/// can at worst make a daemon replace a host it could have kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDescriptor4 {
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
    /// The build of the program: its build identifier and the protocol package it was built from.
    pub build: LocalBuild,
}

/// What a worker asks the plugin host to do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request4 {
    /// The number the response echoes.
    pub request_id: u64,
    /// What is being asked.
    pub body: RequestBody4,
}

/// A registration and the number the worker gave this attempt at it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingRegistration4 {
    /// One attempt to run one instance, minted by the worker. The host echoes it in the answer and
    /// in every notice of the binding, so a worker drops what belongs to an attempt it gave up.
    pub registration: u64,
    /// The registration of `/3`, unchanged.
    pub binding: BindingRegistration,
}

/// The last event of each source that a restored state covers.
///
/// A handle is the worker's own name for an event, as the host's queue carries it. The host holds
/// handles as opaque text and checks only their form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Through {
    /// The last native event the state covers, where it covers one.
    pub native: Option<SourceEventHandle>,
    /// The last terminal event the state covers, where it covers one.
    pub terminal: Option<SourceEventHandle>,
}

/// The closed set of things a worker may ask for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestBody4 {
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
    RegisterBinding(Box<BindingRegistration4>),
    /// Delivers one scoped source event to a binding's observation queue.
    Event {
        /// The binding.
        binding_id: Uuid,
        /// The event.
        event: WireSourceEvent,
    },
    /// Asks a binding for a fresh document.
    Snapshot {
        /// The binding.
        binding_id: Uuid,
        /// The caller's own deadline.
        deadline_ms: u64,
    },
    /// Asks a binding's component to turn an invoked control into a proposed effect.
    PrepareAction(Box<PrepareActionCall>),
    /// Takes a binding's resumable state and what the instance has consumed.
    Checkpoint {
        /// The binding.
        binding_id: Uuid,
        /// The caller's own deadline.
        deadline_ms: u64,
    },
    /// Restores a binding from a checkpoint.
    Restore {
        /// The binding.
        binding_id: Uuid,
        /// The registration this restore is for, which is the one the instance was registered under.
        registration: u64,
        /// The state a checkpoint produced.
        #[serde(with = "serde_bytes_vec")]
        state: Vec<u8>,
        /// The events the state covers, where the worker holds a cursor for it.
        through: Option<Through>,
        /// The caller's own deadline.
        deadline_ms: u64,
    },
    /// Removes a binding and its instance.
    Unbind {
        /// The binding.
        binding_id: Uuid,
    },
    /// Asks what the host is doing.
    Health,
    /// Asks a binding's component to interpret one native request.
    Decode(Box<DecodeCall>),
    /// Asks a binding's component to encode a validated decision as the bytes of a response.
    Encode(Box<EncodeCall>),
    /// Replaces the facts a binding's component reads about its bound execution.
    ReviseFacts {
        /// The binding.
        binding_id: Uuid,
        /// The facts, whole.
        facts: WireFacts,
    },
    /// Replaces the attachments a binding's component reads the current draft as holding.
    ReviseAttachments {
        /// The binding.
        binding_id: Uuid,
        /// The attachments, whole.
        attachments: Vec<WireAttachment>,
    },
    /// Tells the host whether privacy mode stands for the worker this connection serves.
    Privacy {
        /// Whether privacy mode stands.
        private: bool,
    },
}

impl RequestBody4 {
    /// Returns the binding this request concerns, where it concerns one.
    #[must_use]
    pub const fn binding_id(&self) -> Option<Uuid> {
        match self {
            Self::RegisterBinding(registration) => Some(registration.binding.binding_id),
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

    /// Returns the name used in a refusal and in the host's own records, the same as `/3`'s.
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

/// What a plugin host sends back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frame4 {
    /// An answer to a request.
    Response {
        /// The request this answers.
        reply_to: u64,
        /// The answer.
        body: ResponseBody4,
    },
    /// Something a binding produced without being asked.
    Notice(Notice4),
}

/// What an instance has consumed, as a checkpoint states it.
///
/// An event is consumed when its `observe` call returned, whether the component accepted it or
/// declined it. An event that trapped, that the queue dropped or that was refused before it ran is
/// not consumed, and the cursor is then not a prefix of what was observed: `clean` says so for the
/// rest of the instance's life, or until a restore the host accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consumed {
    /// The registration the instance was registered under.
    pub registration: u64,
    /// How many times the instance has been replaced since the registration.
    pub generation: u32,
    /// Whether the cursor is a prefix: no event was dropped, trapped or refused since the state it
    /// describes.
    pub clean: bool,
    /// The last native event whose `observe` returned, where one has.
    pub native: Option<SourceEventHandle>,
    /// The last terminal event whose `observe` returned, where one has.
    pub terminal: Option<SourceEventHandle>,
}

/// A checkpoint: the component's own resumable state and what it has consumed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpointed {
    /// The component's own state.
    #[serde(with = "serde_bytes_vec")]
    pub state: Vec<u8>,
    /// What it has consumed. None from a host whose writer is closed.
    pub consumed: Option<Consumed>,
}

/// A value a call returned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallValue4 {
    /// Nothing but the document.
    Document,
    /// The effect a component proposed.
    Plan(Box<WirePlan>),
    /// A component's own resumable state, and what it has consumed.
    Checkpointed(Box<Checkpointed>),
    /// A native request a component decoded.
    Decoded(Box<WireDecoded>),
    /// A response a component encoded.
    Encoded(Box<WireEncoded>),
}

/// Whether the host set the instance's record of what it has consumed from a restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordState {
    /// The host's writer is open and the restore carried a `through`: the record now holds it, at
    /// the instance's own registration and generation, and is `clean`.
    Set,
    /// The record is as it was. A restore with no `through` restores the state plainly. A host with
    /// its writer closed answers `NotSet` to a restore that carries a `through` and leaves the
    /// instance as it was.
    NotSet,
}

/// The closed set of answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBody4 {
    /// The connection is open.
    Hello {
        /// The protocol the host speaks.
        protocol: String,
        /// The host's descriptor, so a caller that read a stale one can compare.
        descriptor: Box<HostDescriptor4>,
    },
    /// The host's answer to a challenge.
    Verified(Box<HostVerifyProof>),
    /// The binding is registered and bound.
    Registered {
        /// The registration of the request, echoed.
        registration: u64,
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
        /// The bytes the queue can still take after this admission.
        free_bytes: u64,
    },
    /// A call answered.
    Called {
        /// The component's answer, where it answered.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<CallValue4>,
        /// The fault the component declared, where it declared one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fault: Option<String>,
        /// Which of this binding's documents the call drew, where it drew one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        document: Option<u64>,
        /// For the answer to a restore: whether the host set its record.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        record: Option<RecordState>,
    },
    /// The binding is gone.
    Unbound {
        /// Whether this request is the one that ended the connection's registration of the
        /// binding.
        existed: bool,
    },
    /// A revision of a binding's facts or attachments was accepted.
    Revised,
    /// Privacy mode is as the worker said, for the rest of this connection until it says otherwise.
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

/// Something a binding produced without being asked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Notice4 {
    /// A component emitted document nodes.
    Document {
        /// The binding.
        binding_id: Uuid,
        /// The registration the binding runs under.
        registration: u64,
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
    Gap {
        /// The binding.
        binding_id: Uuid,
        /// The registration the binding runs under.
        registration: u64,
        /// How many observations were lost.
        events: u32,
        /// How many bytes they held.
        bytes: u64,
        /// How many documents the reader never received.
        documents: u64,
        /// The first lost event in the order the queue admitted them, where the host's writer is
        /// open and the loss was of events.
        first: Option<SourceEventHandle>,
        /// The last lost event in that order.
        last: Option<SourceEventHandle>,
    },
    /// A call failed and the binding survived it.
    Fault {
        /// The binding.
        binding_id: Uuid,
        /// The registration the binding runs under.
        registration: u64,
        /// Which export failed.
        call: String,
        /// The failure.
        detail: String,
        /// How many faults are inside the window now.
        faults_in_window: u32,
        /// The event whose `observe` trapped, where the call was one and the host's writer is open.
        event: Option<SourceEventHandle>,
        /// The generation the next call runs under: the replacements so far, and one for the
        /// replacement that call makes first.
        generation: u32,
    },
    /// The binding is disabled and will run nothing more.
    Disabled {
        /// The binding.
        binding_id: Uuid,
        /// The registration the binding runs under.
        registration: u64,
        /// Why, in the words a person is shown.
        reason: String,
    },
    /// The instance has consumed events: sent at the end of a pass that returned at least one,
    /// after any gap or fault that pass raised, and coalesced to one pending for each binding. A
    /// host with its writer closed never sends it.
    Consumed {
        /// The binding.
        binding_id: Uuid,
        /// The registration the binding runs under.
        registration: u64,
        /// How many times the instance has been replaced since the registration.
        generation: u32,
        /// Whether the cursor is a prefix.
        clean: bool,
        /// The last native event whose `observe` returned.
        native: Option<SourceEventHandle>,
        /// The last terminal event whose `observe` returned.
        terminal: Option<SourceEventHandle>,
    },
}

impl Notice4 {
    /// Returns the binding this notice concerns.
    #[must_use]
    pub const fn binding_id(&self) -> Uuid {
        match self {
            Self::Document { binding_id, .. }
            | Self::Gap { binding_id, .. }
            | Self::Fault { binding_id, .. }
            | Self::Disabled { binding_id, .. }
            | Self::Consumed { binding_id, .. } => *binding_id,
        }
    }

    /// Returns the registration this notice is about.
    #[must_use]
    pub const fn registration(&self) -> u64 {
        match self {
            Self::Document { registration, .. }
            | Self::Gap { registration, .. }
            | Self::Fault { registration, .. }
            | Self::Disabled { registration, .. }
            | Self::Consumed { registration, .. } => *registration,
        }
    }
}
