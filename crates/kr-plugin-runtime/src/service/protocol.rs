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

/// The protocol a worker and the plugin host speak.
pub const PROTOCOL: &str = "kr-plugin-host/1";

/// The domain separating the plugin host's startup claim.
pub const RENDEZVOUS_DOMAIN: &str = "kr-plugin-host/1/rendezvous";

/// The domain separating the plugin host's answer to a verification challenge.
pub const VERIFY_DOMAIN: &str = "kr-plugin-host/1/verify";

/// The file the plugin host's descriptor is published as, inside the environment runtime directory.
pub const DESCRIPTOR_FILE: &str = "plugin-host.json";

/// The name of the plugin host's endpoint inside the environment runtime directory.
pub const ENDPOINT_NAME: &str = "p.sock";

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
}

impl RequestBody {
    /// Returns the binding this request concerns, where it concerns one.
    #[must_use]
    pub const fn binding_id(&self) -> Option<kr_protocol::scalars::Uuid> {
        match self {
            Self::RegisterBinding(registration) => Some(registration.binding_id),
            Self::Event { binding_id, .. }
            | Self::Snapshot { binding_id, .. }
            | Self::Checkpoint { binding_id, .. }
            | Self::Restore { binding_id, .. }
            | Self::Unbind { binding_id } => Some(*binding_id),
            Self::Hello { .. } | Self::Verify { .. } | Self::Health => None,
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
            Self::Checkpoint { .. } => "checkpoint",
            Self::Restore { .. } => "restore",
            Self::Unbind { .. } => "unbind",
            Self::Health => "health",
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
    },
    /// The binding is gone.
    Unbound {
        /// Whether there was one to remove.
        existed: bool,
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
    /// A component's own resumable state.
    State(#[serde(with = "serde_bytes_vec")] Vec<u8>),
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
    /// How many compiled components the cache is holding in memory.
    pub resident_components: u64,
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
    Document {
        /// The binding.
        binding_id: kr_protocol::scalars::Uuid,
        /// Which export emitted them.
        call: String,
        /// The nodes.
        nodes: Vec<WireNode>,
    },
    /// The observation stream has a gap, and a fresh snapshot follows.
    Gap {
        /// The binding.
        binding_id: kr_protocol::scalars::Uuid,
        /// How many observations were lost.
        events: u32,
        /// How many bytes they held.
        bytes: u64,
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
                protocol: PROTOCOL.to_owned(),
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
            },
        });
        // The document a call drew travels as its own frames, so a caller reads it from the
        // notices rather than from the answer.
        round_trip(&Frame::Notice(Notice::Document {
            binding_id: kr_protocol::scalars::Uuid::from_bytes([7; 16]),
            call: "snapshot".to_owned(),
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
        assert_eq!(PROTOCOL, "kr-plugin-host/1");
        assert_eq!(RENDEZVOUS_DOMAIN, "kr-plugin-host/1/rendezvous");
        assert_eq!(VERIFY_DOMAIN, "kr-plugin-host/1/verify");
        assert_ne!(RENDEZVOUS_DOMAIN, VERIFY_DOMAIN);
        assert_eq!(ENDPOINT_NAME, "p.sock");
        assert_eq!(RENDEZVOUS_PREFIX, "pr-");
    }
}
