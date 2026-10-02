//! The local IPC handshake.
//!
//! Local sockets and named pipes carry the same typed frames as the network transport: one
//! [`crate::envelope::ControlFrame`] union serves both. What differs is authentication. There is no
//! paired device and no endpoint proof, so the host authenticates the operating-system caller
//! through peer credentials and then issues the action window itself. A local caller never
//! pretends to be a paired network device and never supplies its own window.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::actor::ActorIngress;
use crate::envelope::{MutationRequest, Request};
use crate::hello::{ActionWindow, PACKAGE_VERSION, PackageVersion, ProtocolVersion, ReceiveLimits};
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

/// Where a request that crossed a process bridge first entered, as the invoker declares it.
///
/// Section 3 has a request record the ingress it *originally* arrived on, `local_peer` or
/// `network_device`, and not merely the local IPC hop the bridge's helper makes at the destination.
/// A process bridge carries locally authenticated command-line invocations only, so the one
/// ingress a destination admits here is [`ActorIngress::LocalIpc`] (`local_peer`); a declaration of
/// any other is refused at the hello.
///
/// This is a record and a restriction, never authority. The destination authenticates the helper by
/// its own operating-system credentials and issues its own action window and generation, and
/// nothing in a declared origin widens what that connection may do. What it does is let the
/// destination know that the connection arrived over a bridge, so that a rule only a destination
/// can keep, such as a request crossing at most one bridge, is kept there and not left to the
/// helper alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeOrigin {
    /// The environment the invoker ran in.
    pub environment_id: EnvironmentId,
    /// The ingress the request originally arrived on.
    pub ingress: ActorIngress,
}

impl BridgeOrigin {
    /// Whether a destination admits a connection that declares this origin.
    #[must_use]
    pub const fn is_admissible(&self) -> bool {
        self.ingress.may_cross_process_bridge()
    }
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
    /// Where this connection's requests originally entered, when it is a process bridge's helper
    /// connecting on an invoker's behalf.
    ///
    /// Absent for every other client, and then omitted from the frame, so a hello that declares no
    /// origin is the frame it always was and a process that outlived an upgrade still reads it. A
    /// host or worker of a build before this member refuses a hello that carries one, which fails
    /// closed. Absence is not a shape to be read two ways: it means the connection is not bridged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<BridgeOrigin>,
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
    /// The build of the process that answered: its build identifier, and the version of the
    /// protocol package it was built from.
    ///
    /// A client that attaches a terminal refuses a worker on this before it asks the worker for
    /// anything, when the two versions do not share a compatibility level
    /// ([`PackageVersion::shares_frames_with`]), rather than meet a frame it cannot read. A
    /// process of a build before this member states none. Its answer is still read, by a daemon
    /// that goes on speaking to the workers that outlived its upgrade and by every client, and a
    /// client that attaches takes it for an earlier build.
    ///
    /// Remove the default and the omission once no process of a build before this member can
    /// still be running, which is when every session that was live across the upgrade has closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<LocalBuild>,
}

/// The build of a local host process, as it states it in its answer to a hello.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalBuild {
    /// The process's build identifier: its program name and its release.
    pub build_id: BuildId,
    /// The version of the protocol package the process was built from.
    pub protocol_version: PackageVersion,
}

impl LocalBuild {
    /// This build, as the process whose build identifier is `build_id` states it.
    #[must_use]
    pub fn this(build_id: BuildId) -> Self {
        Self {
            build_id,
            protocol_version: PACKAGE_VERSION,
        }
    }
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
/// sent no scope at all. It refuses the agent reads a scope narrows by itself, as it always did.
/// The version is the second: a scope names approvals by the broker's resource identity, and a
/// worker that states only the first read them as an upstream's text, so it is sent none either. A
/// question read is decided by [`FORWARDED_QUESTION_SCOPE`] as well.
pub const FORWARDED_HISTORY_SCOPE: &str = "forwarded.history-scope/2";

/// Returns true when a worker's statement says it reads a forwarded read's history scope
/// ([`FORWARDED_HISTORY_SCOPE`]).
#[must_use]
pub fn reads_history_scopes(capabilities: &CanonicalSet<CapabilityId>) -> bool {
    capabilities
        .iter()
        .any(|capability| capability.as_str() == FORWARDED_HISTORY_SCOPE)
}

/// The capability a worker states when it holds a forwarded `question.read` to the history scope
/// the read carries, and a control daemon reads before it sends a question read with a scope.
///
/// A worker of an earlier build reads a scope ([`FORWARDED_HISTORY_SCOPE`]) and still answers a
/// question read with every question it holds, because the daemon of its build narrowed a paired
/// device's answer itself. The narrowing is the worker's now, so a daemon sends a question read
/// that carries a scope only to a worker that states this, and refuses it for any other rather
/// than pass on what nothing narrowed. It stands beside [`FORWARDED_HISTORY_SCOPE`], which keeps
/// its meaning: a worker that states only that is still sent its scope with every other read.
pub const FORWARDED_QUESTION_SCOPE: &str = "forwarded.question-scope/1";

/// Returns true when a worker's statement says it holds a forwarded question read to the read's
/// history scope ([`FORWARDED_QUESTION_SCOPE`]).
#[must_use]
pub fn holds_question_reads_to_scopes(capabilities: &CanonicalSet<CapabilityId>) -> bool {
    capabilities
        .iter()
        .any(|capability| capability.as_str() == FORWARDED_QUESTION_SCOPE)
}

/// The capability a worker states when it holds what it retains to the history scope a forwarded
/// frame carries: the first answer to a `question.answer` or `question.cancel`, the answer to a
/// duplicate of any mutation, and the answer to an `action.read`. A control daemon reads it before
/// it sends a mutation's scope ([`ForwardedMutation::history`]) or a `question.answer`,
/// `question.cancel` or `action.read` that carries one.
///
/// A worker of an earlier build keeps a retained answer whole, so a daemon never passes one of its
/// retained answers to a paired device. It also ends the link a frame with a member it does not
/// know arrived on, which is why the member is sent only to a worker that states this.
pub const FORWARDED_RESULT_SCOPE: &str = "forwarded.result-scope/1";

/// Returns true when a worker's statement says it holds what it retains to a forwarded frame's
/// history scope ([`FORWARDED_RESULT_SCOPE`]).
#[must_use]
pub fn holds_results_to_scopes(capabilities: &CanonicalSet<CapabilityId>) -> bool {
    capabilities
        .iter()
        .any(|capability| capability.as_str() == FORWARDED_RESULT_SCOPE)
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
    /// The history scope of the grant the host decided this mutation under.
    ///
    /// Section 10 narrows a grant's history in one place, the shared host-side filter, and the
    /// worker applies it to the answer it gives the caller: the first answer to a question, and
    /// the retained answer to a duplicate. The worker holds no grants, so the scope travels with
    /// the mutation. It is absent for a caller acting under no grant. Absence never widens what a
    /// caller is shown: a worker shows retained content without a scope only to a caller it can
    /// see is the local owner.
    ///
    /// It is absent from the wire when it is absent, so a mutation without one is byte for byte
    /// what a worker built before scopes travelled with mutations reads, and the daemon's own link
    /// for a local caller's action never writes one. A daemon sends one only to a worker that states
    /// [`FORWARDED_RESULT_SCOPE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<crate::grant::HistoryScope>,
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
    /// worker applies that filter to what it retains: an agent's semantic history, an approval's
    /// record and the session's questions. The worker holds no grants, so the scope travels with
    /// the read. It is absent for a caller acting under no grant. Absence never widens what a
    /// caller reads: a worker serves retained history without a scope only to a caller it can see
    /// is the local owner, and refuses anybody else.
    ///
    /// It is absent from the wire when it is absent, so a read without one is byte for byte what a
    /// worker built before scopes travelled reads. A daemon sends one only to a worker that states
    /// [`FORWARDED_HISTORY_SCOPE`], and a question read with one only to a worker that also states
    /// [`FORWARDED_QUESTION_SCOPE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<crate::grant::HistoryScope>,
}

#[cfg(test)]
mod tests {
    use super::{BridgeOrigin, LocalClientKind, LocalHello};
    use crate::actor::ActorIngress;
    use crate::envelope::{ControlFrame, ParamsValue, Request};
    use crate::hello::{PROTOCOL_VERSION, ReceiveLimits};
    use crate::ids::{BuildId, EnvironmentId, RequestId};
    use crate::method::{Method, MethodVersion};
    use crate::scalars::CanonicalSet;

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
                history: None,
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

    /// A forwarded mutation without a history scope is the frame a worker of an earlier build
    /// reads, member for member, and a frame such a daemon wrote reads as one without a scope. A
    /// scope round-trips, and an earlier worker could not read it, which is why a daemon sends one
    /// only to a worker that states it holds results to a scope.
    #[test]
    fn a_forwarded_mutation_without_a_scope_is_the_frame_an_earlier_worker_reads() {
        use crate::actor::{ActorEnvelope, ActorIngress};
        use crate::envelope::{ActionTarget, MutationRequest};
        use crate::grant::HistoryScope;
        use crate::ids::{
            ActionId, ActionWindowId, ActorId, ConnectionId, ControllerGeneration, EnvironmentId,
        };
        use crate::scalars::{CanonicalSet, DurationMs, Nullable, TimestampMs, U64, Uuid};

        /// The frame as a worker built before scopes travelled with mutations declares it.
        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Earlier {
            mutation: MutationRequest,
            actor: ActorEnvelope,
            #[serde(with = "super::worker_rights")]
            grant_rights: CanonicalSet<crate::rights::ActionRight>,
            accepted_deadline_boot_ms: U64,
        }

        let mutation = |history: Option<HistoryScope>| super::ForwardedMutation {
            mutation: MutationRequest {
                request_id: RequestId::new(1),
                method: Method::QuestionAnswer.into(),
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
            grant_rights: CanonicalSet::new(),
            accepted_deadline_boot_ms: U64::new(5),
            history,
        };
        let limits = kr_cbor::Limits::DEFAULT;

        let unscoped = mutation(None);
        let bytes = kr_cbor::to_canonical_vec(&unscoped).expect("encodes");
        let earlier: Earlier =
            kr_cbor::from_canonical_slice(&bytes, &limits).expect("an earlier worker reads it");
        assert_eq!(
            kr_cbor::to_canonical_vec(&earlier).expect("encodes"),
            bytes,
            "no scope, no member"
        );
        let decoded: super::ForwardedMutation =
            kr_cbor::from_canonical_slice(&bytes, &limits).expect("decodes");
        assert_eq!(
            decoded, unscoped,
            "an earlier daemon's frame reads as unscoped"
        );

        let scoped = mutation(Some(HistoryScope {
            lower_bound_ms: Nullable::some(TimestampMs::new(2_000)),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        }));
        let bytes = kr_cbor::to_canonical_vec(&scoped).expect("encodes");
        let decoded: super::ForwardedMutation =
            kr_cbor::from_canonical_slice(&bytes, &limits).expect("decodes");
        assert_eq!(decoded, scoped);
        assert!(
            kr_cbor::from_canonical_slice::<Earlier>(&bytes, &limits).is_err(),
            "an earlier worker cannot read a scope"
        );
    }

    #[test]
    fn a_worker_states_that_it_holds_results_to_a_scope() {
        use crate::ids::CapabilityId;
        use crate::scalars::CanonicalSet;

        let statement = |capabilities: &[&str]| -> CanonicalSet<CapabilityId> {
            capabilities
                .iter()
                .map(|capability| CapabilityId::new(*capability).expect("a capability identifier"))
                .collect()
        };
        assert_eq!(super::FORWARDED_RESULT_SCOPE, "forwarded.result-scope/1");
        assert!(super::holds_results_to_scopes(&statement(&[
            super::FORWARDED_RESULT_SCOPE
        ])));
        // A worker that reads a scope and holds its question reads to it still keeps a retained
        // answer whole, and a worker that states nothing at all is the same.
        assert!(!super::holds_results_to_scopes(&statement(&[
            super::FORWARDED_HISTORY_SCOPE,
            super::FORWARDED_QUESTION_SCOPE,
        ])));
        assert!(!super::holds_results_to_scopes(&CanonicalSet::new()));
        // The statements are read apart.
        assert!(!super::reads_history_scopes(&statement(&[
            super::FORWARDED_RESULT_SCOPE
        ])));
        assert!(!super::holds_question_reads_to_scopes(&statement(&[
            super::FORWARDED_RESULT_SCOPE
        ])));
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
    fn a_worker_states_that_it_holds_a_question_read_to_its_scope() {
        use crate::ids::CapabilityId;
        use crate::scalars::CanonicalSet;

        let statement = |capabilities: &[&str]| -> CanonicalSet<CapabilityId> {
            capabilities
                .iter()
                .map(|capability| CapabilityId::new(*capability).expect("a capability identifier"))
                .collect()
        };
        assert_eq!(
            super::FORWARDED_QUESTION_SCOPE,
            "forwarded.question-scope/1"
        );
        assert!(super::holds_question_reads_to_scopes(&statement(&[
            super::FORWARDED_HISTORY_SCOPE,
            super::FORWARDED_QUESTION_SCOPE,
        ])));
        // A worker that reads a scope and says nothing of its question reads answers them with
        // every question it holds, and a worker that states nothing at all is the same.
        assert!(!super::holds_question_reads_to_scopes(&statement(&[
            super::FORWARDED_HISTORY_SCOPE
        ])));
        assert!(!super::holds_question_reads_to_scopes(&CanonicalSet::new()));
        // The two statements are read apart: the new one alone says nothing about the scope's
        // other reads.
        assert!(!super::reads_history_scopes(&statement(&[
            super::FORWARDED_QUESTION_SCOPE
        ])));
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

    /// The version a build states is the one `packages/protocol/package.json` states, read here as
    /// the JSON document it is rather than as the text the compile-time reading scans.
    #[test]
    fn the_package_version_is_the_one_the_protocol_package_states() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../../packages/protocol/package.json"))
                .expect("the manifest is a document");
        let stated = manifest["version"]
            .as_str()
            .expect("the manifest states a version");
        assert_eq!(crate::hello::PACKAGE_VERSION.to_string(), stated);
    }

    /// Below 1.0.0 the minor number is the compatibility level, and from 1.0.0 the major number
    /// is. The patch number never decides, and the answer is the same whichever build asks.
    #[test]
    fn below_one_the_minor_number_is_the_compatibility_level_and_the_patch_never_decides() {
        use crate::hello::PackageVersion as Version;

        let pairs = [
            (Version::new(0, 46, 0), Version::new(0, 46, 3), true),
            (Version::new(0, 46, 2), Version::new(0, 46, 2), true),
            (Version::new(0, 46, 0), Version::new(0, 45, 0), false),
            (Version::new(0, 46, 0), Version::new(0, 47, 0), false),
            (Version::new(1, 2, 0), Version::new(1, 9, 4), true),
            (Version::new(1, 0, 0), Version::new(2, 0, 0), false),
            (Version::new(0, 1, 0), Version::new(1, 1, 0), false),
        ];
        for (one, other, shared) in pairs {
            assert_eq!(one.shares_frames_with(other), shared, "{one} and {other}");
            assert_eq!(other.shares_frames_with(one), shared, "{other} and {one}");
        }
    }

    /// A process states its build in its answer to a hello. The answer of a process of an earlier
    /// build has no such member, and it is read, with no build.
    #[test]
    fn an_answer_to_a_hello_states_the_build_and_an_earlier_build_s_answer_is_read_without_one() {
        use crate::hello::{ActionWindow, ReceiveLimits};
        use crate::identity::{BootIdentity, BootIdentitySource};
        use crate::ids::{ActionWindowId, BootEpoch, BuildId, ConnectionId, EnvironmentId};
        use crate::scalars::{Bytes, CanonicalSet, DurationMs, Nullable, TimestampMs, U64, Uuid};

        let connection_id = ConnectionId::new(Uuid::from_bytes([4; 16]));
        let answer = |build: Option<super::LocalBuild>| {
            ControlFrame::HelloAck(Box::new(super::LocalHelloAck {
                selected_version: crate::hello::PROTOCOL_VERSION,
                role: super::LocalRole::Worker,
                connection_id,
                environment_id: EnvironmentId::new(Uuid::from_bytes([5; 16])),
                boot_identity: BootIdentity {
                    source: BootIdentitySource::LinuxBootId,
                    value: Bytes::new(b"a boot".to_vec()),
                },
                peer: super::LocalPeer {
                    uid: U64::new(501),
                    gid: U64::new(20),
                    pid: Nullable::null(),
                },
                action_window: ActionWindow {
                    action_window_id: ActionWindowId::new("worker:test").expect("a window"),
                    connection_id,
                    boot_epoch: BootEpoch::new(1),
                    issued_at_ms: TimestampMs::new(0),
                    valid_for_ms: DurationMs::new(60_000),
                },
                capabilities: CanonicalSet::new(),
                max_receive: ReceiveLimits::default(),
                build,
            }))
        };
        let read = |frame: &ControlFrame| -> ControlFrame {
            let bytes = kr_cbor::to_canonical_vec(frame).expect("encodes");
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes")
        };

        let stated = answer(Some(super::LocalBuild::this(
            BuildId::new("kr-worker/0.1.0").expect("a build identifier"),
        )));
        assert_eq!(read(&stated), stated);
        let ControlFrame::HelloAck(stated) = stated else {
            unreachable!("built as an answer to a hello");
        };
        assert_eq!(
            stated.build.as_ref().map(|build| build.protocol_version),
            Some(crate::hello::PACKAGE_VERSION)
        );

        // An answer without the member is what a build before it wrote, byte for byte, and it is
        // read with no build.
        let earlier = answer(None);
        let ControlFrame::HelloAck(written) = &earlier else {
            unreachable!("built as an answer to a hello");
        };
        let document = serde_json::to_value(written).expect("a document");
        assert!(document.get("build").is_none(), "{document}");
        let ControlFrame::HelloAck(read_back) = read(&earlier) else {
            panic!("an answer to a hello is read as one");
        };
        assert_eq!(read_back.build, None);
    }

    fn a_hello(origin: Option<BridgeOrigin>) -> LocalHello {
        LocalHello {
            offered_versions: vec![PROTOCOL_VERSION],
            build_id: BuildId::new("kr/0.1.0").expect("a build identifier"),
            client: LocalClientKind::Cli,
            capabilities: CanonicalSet::new(),
            max_receive: ReceiveLimits::default(),
            origin,
        }
    }

    /// KR-REQ-03.13: a hello that declares no origin is the frame it always was, and one that
    /// declares an origin carries it and reads back as it was written.
    #[test]
    fn a_hello_without_an_origin_omits_it_and_one_with_an_origin_round_trips() {
        let plain = a_hello(None);
        let document = serde_json::to_value(&plain).expect("a document");
        assert!(document.get("origin").is_none(), "{document}");

        let bridged = a_hello(Some(BridgeOrigin {
            environment_id: EnvironmentId::new(crate::scalars::Uuid::from_bytes([6; 16])),
            ingress: ActorIngress::LocalIpc,
        }));
        let frame = ControlFrame::Hello(bridged.clone());
        let bytes = kr_cbor::to_canonical_vec(&frame).expect("encodes");
        let read: ControlFrame =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(read, frame);
        let plain_bytes = kr_cbor::to_canonical_vec(&ControlFrame::Hello(plain)).expect("encodes");
        assert!(bytes.len() > plain_bytes.len(), "the origin is on the wire");
    }

    /// KR-REQ-03.13: a hello as a host or worker built before the origin member declares it, member
    /// for member. What an earlier client writes reads here as one that declares no origin; what
    /// this build writes without an origin is the earlier frame, byte for byte; and a hello that
    /// declares one is refused by the earlier build, which is what makes the helper's report of it
    /// necessary.
    #[test]
    fn a_hello_is_read_both_ways_between_a_build_with_an_origin_member_and_one_without() {
        use crate::hello::{ProtocolVersion, ReceiveLimits as Limits};

        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Earlier {
            offered_versions: Vec<ProtocolVersion>,
            build_id: BuildId,
            client: LocalClientKind,
            capabilities: CanonicalSet<crate::ids::CapabilityId>,
            max_receive: Limits,
        }

        let limits = kr_cbor::Limits::DEFAULT;
        let earlier = Earlier {
            offered_versions: vec![PROTOCOL_VERSION],
            build_id: BuildId::new("kr/0.1.0").expect("a build identifier"),
            client: LocalClientKind::Cli,
            capabilities: CanonicalSet::new(),
            max_receive: ReceiveLimits::default(),
        };
        let written = kr_cbor::to_canonical_vec(&earlier).expect("encodes");
        let read: LocalHello =
            kr_cbor::from_canonical_slice(&written, &limits).expect("this build reads it");
        assert_eq!(read, a_hello(None), "an earlier client declares no origin");

        let plain = kr_cbor::to_canonical_vec(&a_hello(None)).expect("encodes");
        assert_eq!(plain, written, "no origin, no member: the earlier frame");
        assert_eq!(
            kr_cbor::from_canonical_slice::<Earlier>(&plain, &limits).expect("an earlier build"),
            earlier
        );

        let bridged = kr_cbor::to_canonical_vec(&a_hello(Some(BridgeOrigin {
            environment_id: EnvironmentId::new(crate::scalars::Uuid::from_bytes([6; 16])),
            ingress: ActorIngress::LocalIpc,
        })))
        .expect("encodes");
        assert!(
            kr_cbor::from_canonical_slice::<Earlier>(&bridged, &limits).is_err(),
            "an earlier build cannot read a hello that declares an origin"
        );
    }

    /// KR-REQ-03.13, KR-ACC-021: the one ingress a destination admits an origin for is the locally
    /// authenticated one; every network ingress, a workflow and a plugin are refused.
    #[test]
    fn only_a_local_peer_is_an_admissible_origin() {
        for ingress in ActorIngress::ALL.iter().copied() {
            let origin = BridgeOrigin {
                environment_id: EnvironmentId::new(crate::scalars::Uuid::from_bytes([6; 16])),
                ingress,
            };
            assert_eq!(
                origin.is_admissible(),
                ingress == ActorIngress::LocalIpc,
                "{}",
                ingress.as_str()
            );
        }
    }
}
