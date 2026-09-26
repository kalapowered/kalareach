//! The local IPC handshake.
//!
//! Local sockets and named pipes carry the same typed frames as the network transport: one
//! [`crate::envelope::ControlFrame`] union serves both. What differs is authentication. There is no
//! paired device and no endpoint proof, so the host authenticates the operating-system caller
//! through peer credentials and then issues the action window itself. A local caller never
//! pretends to be a paired network device and never supplies its own window.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::{MutationRequest, Request};
use crate::hello::{ActionWindow, ProtocolVersion, ReceiveLimits};
use crate::identity::BootIdentity;
use crate::ids::{BuildId, CapabilityId, ConnectionId, EnvironmentId};
use crate::scalars::{CanonicalSet, Nullable, U64};

/// Which host process a local endpoint belongs to.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LocalRole {
    /// The per-environment control daemon.
    Controller,
    /// One session worker's private endpoint.
    Worker,
    /// The controller's owner-only rendezvous socket, which accepts only a worker's startup
    /// handshake.
    Rendezvous,
}

impl LocalRole {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Controller => "controller",
            Self::Worker => "worker",
            Self::Rendezvous => "rendezvous",
        }
    }
}

/// What kind of client opened a local connection.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LocalClientKind {
    /// The `kr` command-line client.
    Cli,
    /// The control daemon connecting to a worker.
    Controller,
    /// A worker connecting to the control daemon.
    Worker,
}

/// The authenticated operating-system caller.
///
/// The host stamps this from the socket's peer credentials. It proves an OS identity, not human
/// intent: rights-enlarging owner operations still require the owner-confirmation contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalPeer {
    /// The caller's user identifier.
    pub uid: U64,
    /// The caller's primary group identifier.
    pub gid: U64,
    /// The caller's process identifier, where the platform reports one. A hint for diagnostics,
    /// never authority on its own.
    pub pid: Nullable<U64>,
}

/// The first frame a local client sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalHello {
    /// Every protocol version the client offers.
    pub offered_versions: Vec<ProtocolVersion>,
    /// The client build.
    pub build_id: BuildId,
    /// What kind of client this is. It says how to frame the conversation; it confers nothing.
    pub client: LocalClientKind,
    /// The capabilities the client offers.
    pub capabilities: CanonicalSet<CapabilityId>,
    /// The client's own receive limits.
    pub max_receive: ReceiveLimits,
}

/// The first frame the host sends back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalHelloAck {
    /// The version both sides will use.
    pub selected_version: ProtocolVersion,
    /// Which host process answered.
    pub role: LocalRole,
    /// The connection identity the host assigned.
    pub connection_id: ConnectionId,
    /// The environment this endpoint belongs to.
    pub environment_id: EnvironmentId,
    /// The boot the host is running.
    pub boot_identity: BootIdentity,
    /// The caller the host authenticated.
    pub peer: LocalPeer,
    /// The first action window of this connection.
    ///
    /// It carries a validity *duration*, not a deadline: the authoritative deadline lives on the
    /// host's suspend-aware continuous clock, and the host renews the window on this connection
    /// without being asked. A client schedules its own expectations from the duration and never
    /// computes an expiry the host will honour.
    pub action_window: ActionWindow,
    /// The capabilities both sides will use.
    pub capabilities: CanonicalSet<CapabilityId>,
    /// The limits both sides will use.
    pub max_receive: ReceiveLimits,
}

/// The capability a worker states when it reads the UTC deadline beside each forwarded copy's
/// continuous one, and a control daemon offers when it writes it.
///
/// A worker survives an upgrade of the daemon, and the forwarded frames are closed schemas, so a
/// worker of an earlier build refuses a frame with a field it does not know. The daemon reads this
/// in the worker's answer to its hello before it sends such a frame.
pub const FORWARDED_UTC_DEADLINE: &str = "forwarded.utc-deadline/1";

/// The capability a worker states when it reads the history scope a forwarded read carries
/// ([`ForwardedRequest::history`]), and a control daemon reads before it sends one.
///
/// A worker survives an upgrade of the daemon, the forwarded frames are closed schemas, and a
/// worker ends the connection a frame it cannot read arrived on, so a worker of an earlier build is
/// sent no scope at all. It refuses the reads a scope narrows by itself, as it always did. The
/// version is the second: a scope names approvals by the broker's resource identity, and a worker
/// that states only the first read them as an upstream's text, so it is sent none either.
pub const FORWARDED_HISTORY_SCOPE: &str = "forwarded.history-scope/2";

/// Returns true when a worker's statement says it reads a forwarded read's history scope
/// ([`FORWARDED_HISTORY_SCOPE`]).
#[must_use]
pub fn reads_history_scopes(capabilities: &CanonicalSet<CapabilityId>) -> bool {
    capabilities
        .iter()
        .any(|capability| capability.as_str() == FORWARDED_HISTORY_SCOPE)
}

/// What a worker's statement of the clock floor it maps starts with. The rest is the floor's
/// identity, as 32 lowercase hexadecimal digits.
pub const UTC_FLOOR_PREFIX: &str = "utc-floor/";

/// The capability that states the clock floor a worker maps, by the floor's identity.
///
/// # Panics
///
/// Never: the statement is 42 characters, well inside what a capability identifier holds.
#[must_use]
pub fn utc_floor_capability(identity: &[u8; 16]) -> CapabilityId {
    let mut text = String::with_capacity(UTC_FLOOR_PREFIX.len() + 32);
    text.push_str(UTC_FLOOR_PREFIX);
    for byte in identity {
        text.push_str(&format!("{byte:02x}"));
    }
    CapabilityId::new(text).expect("a clock floor statement fits a capability identifier")
}

/// The identity of the clock floor a set of capabilities states, when it states exactly one.
///
/// A statement that is not 32 lowercase hexadecimal digits states nothing, and neither do two.
#[must_use]
pub fn stated_utc_floor(capabilities: &CanonicalSet<CapabilityId>) -> Option<[u8; 16]> {
    let mut stated = capabilities
        .iter()
        .filter_map(|capability| capability.as_str().strip_prefix(UTC_FLOOR_PREFIX));
    let digits = stated.next()?;
    if stated.next().is_some() || digits.len() != 32 {
        return None;
    }
    let mut identity = [0_u8; 16];
    for (index, pair) in digits.as_bytes().chunks_exact(2).enumerate() {
        let value = |digit: u8| match digit {
            b'0'..=b'9' => Some(digit - b'0'),
            b'a'..=b'f' => Some(digit - b'a' + 10),
            _ => None,
        };
        identity[index] = (value(pair[0])? << 4) | value(pair[1])?;
    }
    Some(identity)
}

/// Whether a set of capabilities states the forwarded frames' UTC deadlines
/// ([`FORWARDED_UTC_DEADLINE`]).
#[must_use]
pub fn states_utc_deadlines(capabilities: &CanonicalSet<CapabilityId>) -> bool {
    capabilities
        .iter()
        .any(|capability| capability.as_str() == FORWARDED_UTC_DEADLINE)
}

/// Whether a set of rights may travel to a worker beside a [`ForwardedMutation`]: never with
/// `voice.use` in it.
///
/// A voice grant is decided only inside the control daemon. The device door decides a forwarded
/// method under the pairing grant with `voice.use` taken out, the methods that need it are the
/// daemon's own voice methods, and the voice module performs its one effect as the daemon's own
/// request, which carries no rights. So no worker holds work under a voice grant, and withdrawing
/// one owes no fence. A forwarded mutation whose rights this answers false for is neither encoded
/// nor decoded, and both builders of one refuse such a set before anything is sent.
#[must_use]
pub fn may_travel_to_a_worker(
    rights: &crate::scalars::CanonicalSet<crate::rights::ActionRight>,
) -> bool {
    !rights.contains(&crate::rights::ActionRight::VoiceUse)
}

/// A mutation the host admitted for a caller, passed to the component that owns its subject.
///
/// The control daemon owns admission: it authenticates the caller, stamps the freshness window,
/// checks the envelope and derives the accepted deadline. The worker owns the subject. Forwarding
/// carries the caller's mutation to the worker **unchanged**, because the mutation is what the
/// payload digest covers and what the caller will retry with: rewriting any of it would give the
/// worker a different action from the one the caller asked for.
///
/// What travels beside it is what the worker cannot establish for itself: which principal the host
/// verified, the rights the grant it was checked against carries, and the deadline the host
/// accepted. The worker performs the action under all three.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForwardedMutation {
    /// The caller's mutation, exactly as it arrived at the host.
    pub mutation: MutationRequest,
    /// The actor the host verified, with the ingress it arrived on.
    pub actor: crate::actor::ActorEnvelope,
    /// The rights the grant named in the envelope carries, as the host resolved them.
    ///
    /// Section 8 makes an attachment's granted capabilities the requested ones intersected with
    /// the actor's rights, and the worker is where an attachment is admitted. It holds no grants,
    /// so the rights travel with the mutation that needs them rather than being asked for again.
    ///
    /// Empty when the envelope names no grant, which is what a locally authenticated caller's
    /// operating-system identity is. The worker narrows nothing for such a caller: there is no
    /// grant to narrow by, and its peer credentials already proved it is this user.
    #[serde(with = "worker_rights")]
    #[schemars(with = "CanonicalSet<crate::rights::ActionRight>")]
    pub grant_rights: CanonicalSet<crate::rights::ActionRight>,
    /// The deadline the host derived at first admission, on the machine's own continuous clock.
    ///
    /// Milliseconds since this boot, from the clock the operating system keeps for the whole
    /// machine: `CLOCK_BOOTTIME` on Linux and `CLOCK_MONOTONIC` on Apple. Two processes on one boot
    /// read the same clock, so this is the same instant on both sides of the socket and nothing has
    /// to guess at what the journey cost.
    ///
    /// Not a wall-clock time and not a process-anchored one. A wall-clock instant would be
    /// comparable and also steppable, which is the one property a deadline cannot have; a
    /// process-anchored instant is not comparable at all. A deadline from a previous boot reads as
    /// long past, because the clock restarts at the boot, so a stale one expires rather than being
    /// honoured.
    pub accepted_deadline_boot_ms: U64,
}

/// The rights beside a forwarded mutation, as they are encoded and decoded: a set that holds
/// `voice.use` is refused both ways ([`may_travel_to_a_worker`]), so no frame carries it, whoever
/// builds it and however it is sent.
mod worker_rights {
    use serde::{Deserialize as _, Serialize as _};

    use crate::rights::ActionRight;
    use crate::scalars::CanonicalSet;

    /// Why a set is refused.
    const REFUSED: &str = "voice.use never travels to a worker";

    pub fn serialize<S: serde::Serializer>(
        rights: &CanonicalSet<ActionRight>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if !super::may_travel_to_a_worker(rights) {
            return Err(serde::ser::Error::custom(REFUSED));
        }
        rights.serialize(serializer)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<CanonicalSet<ActionRight>, D::Error> {
        let rights = CanonicalSet::<ActionRight>::deserialize(deserializer)?;
        if !super::may_travel_to_a_worker(&rights) {
            return Err(serde::de::Error::custom(REFUSED));
        }
        Ok(rights)
    }
}

/// What one of the control daemon's connections to a worker is for.
///
/// A daemon needs more than one connection to a worker, because a worker's attachments,
/// subscriptions and input lane belong to the connection that created them: a device's attachment
/// cannot share a connection with the daemon's own housekeeping. Only one of those connections
/// carries the environment's authority, and a connection says which it is *before* it presents a
/// generation token, so the worker never has to guess and a proxy never displaces the authority.
///
/// It confers nothing on its own. Every one of these connections still proves which generation it
/// speaks for, and only the holder of the environment's signing key can produce that proof.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ControllerConnectionRole {
    /// The connection that speaks for the environment's authority. It announces authority
    /// revisions, and presenting a generation on it fences whatever held that authority before.
    #[default]
    Authority,
    /// A connection the daemon opened on behalf of one caller it authenticated elsewhere.
    ///
    /// It forwards that caller's admitted reads and mutations and owns their attachment, and it
    /// announces nothing. A replacement generation fences it along with the authority itself.
    Proxy,
    /// The connection the daemon reads this session's attention sources over.
    ///
    /// It carries the attention source and text requests and nothing else. A newer one replaces
    /// it, and a replacement generation fences it along with the authority itself.
    Attention,
}

impl ControllerConnectionRole {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::Proxy => "proxy",
            Self::Attention => "attention",
        }
    }
}

/// A read the host admitted for a caller, passed to the component that owns its subject.
///
/// A read needs forwarding for the same reason a mutation does, and for one reason more. The
/// subject is the worker's, and the daemon owns admission; but a read is also *attributed*: the
/// de-duplication key of a retained receipt is the verified actor and the action together, so a
/// read that asks about an action has to ask as the caller rather than as the proxy. A plain
/// request carries no actor, and serving one on the proxy's own principal would answer about the
/// proxy's actions instead of the caller's.
///
/// What travels beside the request is the actor the host verified, including the ingress it
/// arrived on. The worker checks the method against *that* ingress, so a method the registry keeps
/// to private IPC stays unreachable for a paired device even though the frame arrived on a socket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForwardedRequest {
    /// The caller's request, exactly as it arrived at the host.
    pub request: Request,
    /// The actor the host verified, with the ingress it arrived on.
    pub actor: crate::actor::ActorEnvelope,
    /// When the authority behind this request runs out, on the machine's own continuous clock.
    ///
    /// A read is not a mutation and carries no accepted deadline, but the authority behind it
    /// still ends: a grant expires while the request is in the worker's queue, and raw input is a
    /// request. The worker compares this inside the boundary that decides what reaches the
    /// application, so bytes admitted a moment before an expiry are not written after it. Null
    /// when the caller's authority is not something that expires, which is what a locally
    /// authenticated caller's operating-system identity is.
    pub authority_deadline_boot_ms: crate::scalars::Nullable<crate::scalars::U64>,
    /// The history scope of the grant the host decided this read under.
    ///
    /// Section 10 narrows a grant's history in one place, the shared host-side filter, and the
    /// worker applies that filter to what it retains: an agent's semantic history and an
    /// approval's record. The worker holds no grants, so the scope travels with the read. It is
    /// absent for a caller acting under no grant. Absence never widens what a caller reads: a
    /// worker serves retained history without a scope only to a caller it can see is the local
    /// owner, and refuses anybody else.
    ///
    /// It is absent from the wire when it is absent, so a read without one is byte for byte what a
    /// worker built before scopes travelled reads. A daemon sends one only to a worker that states
    /// [`FORWARDED_HISTORY_SCOPE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<crate::grant::HistoryScope>,
}

#[cfg(test)]
mod tests {
    use crate::envelope::{ControlFrame, ParamsValue, Request};
    use crate::ids::RequestId;
    use crate::method::{Method, MethodVersion};

    #[test]
    fn a_worker_states_the_clock_floor_it_maps_by_its_identity() {
        use crate::ids::CapabilityId;
        use crate::scalars::CanonicalSet;

        let identity = [0xa5_u8; 16];
        let stated = super::utc_floor_capability(&identity);
        assert_eq!(
            stated.as_str(),
            "utc-floor/a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"
        );
        let frame_shape =
            CapabilityId::new(super::FORWARDED_UTC_DEADLINE).expect("a capability identifier");
        let capabilities: CanonicalSet<CapabilityId> =
            [stated.clone(), frame_shape].into_iter().collect();
        assert_eq!(super::stated_utc_floor(&capabilities), Some(identity));
        assert!(super::states_utc_deadlines(&capabilities));

        // A worker of an earlier build states nothing, and a statement this build cannot read
        // states no floor.
        assert_eq!(super::stated_utc_floor(&CanonicalSet::new()), None);
        assert!(!super::states_utc_deadlines(&CanonicalSet::new()));
        let upper: CanonicalSet<CapabilityId> =
            [CapabilityId::new("utc-floor/A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5").expect("text")]
                .into_iter()
                .collect();
        assert_eq!(super::stated_utc_floor(&upper), None);
        let two: CanonicalSet<CapabilityId> = [stated, super::utc_floor_capability(&[1_u8; 16])]
            .into_iter()
            .collect();
        assert_eq!(super::stated_utc_floor(&two), None, "two floors state none");
    }

    /// A forwarded mutation that carries `voice.use` is neither encoded nor decoded, however it is
    /// built; one that does not round-trips.
    #[test]
    fn a_forwarded_mutation_never_carries_a_voice_right_in_either_direction() {
        use crate::actor::{ActorEnvelope, ActorIngress};
        use crate::envelope::{ActionTarget, MutationRequest};
        use crate::ids::{
            ActionId, ActionWindowId, ActorId, ConnectionId, ControllerGeneration, EnvironmentId,
        };
        use crate::local::ForwardedMutation as Built;
        use crate::rights::ActionRight;
        use crate::scalars::{DurationMs, Nullable, U64, Uuid};

        let frame = |rights: &[ActionRight]| {
            ControlFrame::Forwarded(Box::new(Built {
                mutation: MutationRequest {
                    request_id: RequestId::new(1),
                    method: Method::SessionClose.into(),
                    method_version: MethodVersion::V1,
                    action_id: ActionId::new(Uuid::from_bytes([1; 16])),
                    grant_id: Nullable::null(),
                    target: ActionTarget {
                        environment_id: EnvironmentId::new(Uuid::from_bytes([2; 16])),
                        session_id: Nullable::null(),
                        session_epoch: Nullable::null(),
                        application_instance_id: Nullable::null(),
                        agent_binding_revision: Nullable::null(),
                    },
                    expected: ParamsValue::empty(),
                    action_window_id: ActionWindowId::new("device:test").expect("a window"),
                    requested_ttl_ms: DurationMs::new(30_000),
                    params: ParamsValue::empty(),
                },
                actor: ActorEnvelope {
                    actor_id: ActorId::new("device:test").expect("a principal"),
                    ingress: ActorIngress::PairedDevice,
                    device_id: Nullable::null(),
                    grant_id: Nullable::null(),
                    grant_revision: Nullable::null(),
                    controller_generation: ControllerGeneration::new(1),
                    connection_id: ConnectionId::new(Uuid::from_bytes([3; 16])),
                },
                grant_rights: rights.iter().copied().collect(),
                accepted_deadline_boot_ms: U64::new(5),
            }))
        };

        let allowed = frame(&[ActionRight::SessionView]);
        let bytes = kr_cbor::to_canonical_vec(&allowed).expect("encodes");
        let decoded: ControlFrame =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(decoded, allowed);

        let refused =
            kr_cbor::to_canonical_vec(&frame(&[ActionRight::SessionView, ActionRight::VoiceUse]))
                .expect_err("a frame carrying voice.use is not encoded");
        // The refusal's reason is kept in the failure's own field; what the failure says is its
        // rule.
        let reason = match &refused {
            kr_cbor::CborError::Serialize { message } => message.as_str(),
            other => panic!("a refusal to write the frame, not {other}"),
        };
        assert!(reason.contains("never travels to a worker"), "{reason}");

        // Decoding refuses it too, whatever wrote it.
        let read = |rights: &[&'static str]| {
            super::worker_rights::deserialize(serde::de::value::SeqDeserializer::<
                _,
                serde::de::value::Error,
            >::new(rights.iter().copied()))
        };
        assert_eq!(
            read(&["session.view"]).expect("decodes"),
            [ActionRight::SessionView].into_iter().collect()
        );
        let undecoded = read(&["session.view", "voice.use"])
            .expect_err("a set carrying voice.use is not decoded");
        assert!(
            undecoded.to_string().contains("never travels to a worker"),
            "{undecoded}"
        );
    }

    /// A forwarded read without a history scope is the frame a worker of an earlier build reads,
    /// member for member, and a frame such a daemon wrote reads as one without a scope. A scope
    /// round-trips, and an earlier worker could not read it, which is why a daemon asks first.
    #[test]
    fn a_forwarded_read_without_a_scope_is_the_frame_an_earlier_worker_reads() {
        use crate::actor::{ActorEnvelope, ActorIngress};
        use crate::grant::HistoryScope;
        use crate::ids::{ActorId, ControllerGeneration};
        use crate::scalars::{CanonicalSet, Nullable, TimestampMs, U64, Uuid};

        /// The frame as a worker built before scopes travelled declares it.
        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Earlier {
            request: Request,
            actor: ActorEnvelope,
            authority_deadline_boot_ms: Nullable<U64>,
        }

        let read = |history: Option<HistoryScope>| super::ForwardedRequest {
            request: Request {
                request_id: RequestId::new(3),
                method: Method::AgentSnapshot.into(),
                method_version: MethodVersion::V1,
                params: ParamsValue::empty(),
            },
            actor: ActorEnvelope {
                actor_id: ActorId::new("device:test").expect("a principal"),
                ingress: ActorIngress::PairedDevice,
                device_id: Nullable::null(),
                grant_id: Nullable::null(),
                grant_revision: Nullable::null(),
                controller_generation: ControllerGeneration::new(1),
                connection_id: crate::ids::ConnectionId::new(Uuid::from_bytes([3; 16])),
            },
            authority_deadline_boot_ms: Nullable::some(U64::new(9)),
            history,
        };
        let limits = kr_cbor::Limits::DEFAULT;

        let unscoped = read(None);
        let bytes = kr_cbor::to_canonical_vec(&unscoped).expect("encodes");
        let earlier: Earlier =
            kr_cbor::from_canonical_slice(&bytes, &limits).expect("an earlier worker reads it");
        assert_eq!(
            kr_cbor::to_canonical_vec(&earlier).expect("encodes"),
            bytes,
            "no scope, no member"
        );
        let decoded: super::ForwardedRequest =
            kr_cbor::from_canonical_slice(&bytes, &limits).expect("decodes");
        assert_eq!(
            decoded, unscoped,
            "an earlier daemon's frame reads as unscoped"
        );

        let scoped = read(Some(HistoryScope {
            lower_bound_ms: Nullable::some(TimestampMs::new(2_000)),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        }));
        let bytes = kr_cbor::to_canonical_vec(&scoped).expect("encodes");
        let decoded: super::ForwardedRequest =
            kr_cbor::from_canonical_slice(&bytes, &limits).expect("decodes");
        assert_eq!(decoded, scoped);
        assert!(
            kr_cbor::from_canonical_slice::<Earlier>(&bytes, &limits).is_err(),
            "an earlier worker cannot read a scope"
        );
    }

    #[test]
    fn a_worker_states_that_it_reads_a_forwarded_scope() {
        use crate::ids::CapabilityId;
        use crate::scalars::CanonicalSet;

        let stated: CanonicalSet<CapabilityId> =
            [CapabilityId::new(super::FORWARDED_HISTORY_SCOPE).expect("a capability identifier")]
                .into_iter()
                .collect();
        assert!(super::reads_history_scopes(&stated));
        assert!(!super::reads_history_scopes(&CanonicalSet::new()));
        let other: CanonicalSet<CapabilityId> =
            [CapabilityId::new(super::FORWARDED_UTC_DEADLINE).expect("a capability identifier")]
                .into_iter()
                .collect();
        assert!(!super::reads_history_scopes(&other));

        // A worker that read scopes naming approvals by an upstream's text says so with the first
        // version alone, and is sent no scope; the version that names them by resource is read.
        let statement = |capability: &str| -> CanonicalSet<CapabilityId> {
            [CapabilityId::new(capability).expect("a capability identifier")]
                .into_iter()
                .collect()
        };
        assert!(!super::reads_history_scopes(&statement(
            "forwarded.history-scope/1"
        )));
        assert!(super::reads_history_scopes(&statement(
            "forwarded.history-scope/2"
        )));
    }

    #[test]
    fn a_local_control_frame_round_trips_through_the_canonical_encoding() {
        let frame = ControlFrame::Request(Request {
            request_id: RequestId::new(7),
            method: Method::SessionList.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::empty(),
        });
        let bytes = kr_cbor::to_canonical_vec(&frame).expect("encodes");
        let decoded: ControlFrame =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(decoded, frame);
    }
}
