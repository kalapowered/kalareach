//! Keys of a device that go ahead of its own pending request.
//!
//! A device sends its keys, its viewport reports and its reads on one control stream, and the loop
//! that serves the stream answers one frame before it reads the next. A request that waits for the
//! worker (a mutation's commits, or a read waiting for the session) therefore held back a key sent
//! behind it, for as long as the request waited. While such a request is answered, the stream is
//! read ahead here and each key found is answered at once, over the same worker link, which carries
//! every call by its own request identifier. The request is answered on a task of its own, so that
//! what it does without awaiting, a commit to the device directory among it, does not hold the key
//! back. What is read and not served goes back to the loop in the order it was sent. Which
//! requests a key may go ahead of is [`kr_protocol::ordering`]'s, narrowed here by what this host
//! decides a frame over.
//!
//! # When it applies
//!
//! Only once the connection's link to its worker is open and the grant it acts under is fixed
//! ([`RemoteConnection::fixed_route`]). Until then a read or a geometry mutation can be the frame
//! that opens the link and fixes the grant, and a key served ahead of it would fix a different one.
//! A real device attaches first, so it is in that state for every report it sends.
//!
//! # What a frame is decided over
//!
//! A frame is decided under one grant, and a frame decided under a share notes that share on the
//! connection's registration and holds its end as a bound of the connection, so that the share's
//! revocation ends the connection. That is a change a key could land ahead of. A frame therefore
//! goes ahead of keys, or is a key served ahead of one, only when it is decided over the session
//! and the grant the connection already acts under, or over none: [`RemoteConnection::order_kind`]
//! reads them from the fields the decision reads. Any other frame keeps its place, so what ends the
//! connection, and when, is what it was in order.
//!
//! # Limits
//!
//! At most [`kr_protocol::ordering::MOST_HELD`] frames that cannot be served are read ahead, a key
//! that is not read before the reading stops waits for the request that is running, and one key is
//! answered at a time. A key arriving while the loop writes a large answer waits for the write. The
//! relay's end is seen at the next frame, as it is without this.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, PoisonError};

use kr_protocol::envelope::ControlFrame;
use kr_protocol::ids::{GrantId, SessionId};
use kr_protocol::ordering::{self, Judgement, Kind, Sorting};
use kr_transport::listener::ControlChannel;

use super::RemoteConnection;
use super::decision::Answered;
use super::decision::mutation_subject;

/// The session a connection's link to its worker serves and the grant it acts under for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Route {
    session: SessionId,
    grant: GrantId,
}

/// A key being answered: its answer is made and written, and says whether the connection goes on.
type KeyAnswering<'a> = Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

/// What a task of the loop reads: the frame that came next, or `None` for the end of the stream.
type Read = Option<ControlFrame>;

/// A frame being answered on a task of its own, which ends when this is dropped.
///
/// The loop that serves a connection is dropped when the control stream ends, and what it was
/// awaiting stops with it. A task that is spawned for the answer would outlive that, so dropping
/// this aborts it. It stops when it next yields to the runtime, which can be after the step it is
/// running, as dropping the answer's future would have stopped it at its next await.
struct Answering(tokio::task::JoinHandle<Option<Answered>>);

impl Drop for Answering {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl RemoteConnection {
    /// The link and the grant this connection acts under, once both are fixed.
    pub(super) async fn fixed_route(&self) -> Option<Route> {
        let open = self
            .proxy
            .lock()
            .await
            .as_ref()
            .is_some_and(|proxy| proxy.is_open());
        if !open {
            return None;
        }
        let (session, grant) = (*self.fixed.lock().unwrap_or_else(PoisonError::into_inner))?;
        Some(Route { session, grant })
    }

    /// What `frame` is to the order a key keeps on a connection with this route.
    ///
    /// The method rule is [`kr_protocol::ordering`]'s. A frame this host decides over a session
    /// other than the route's, or a mutation that names no session or a grant other than the
    /// route's, is `Blocking` whatever its method: deciding it can note another share on the
    /// registration, and the daemon refuses a mutation that names no session before the worker. A
    /// key naming another session is `Blocking` for the same reason, and the link refuses it
    /// anyway. An `action.read` that names no session is decided over the session its recorded
    /// route names, and one whose route names none, or that has no route yet, is `Blocking`:
    /// another connection of the device can claim the route first. A voice read is `Blocking` too.
    /// Any other read that names no session is decided under the pairing grant, which notes no
    /// share, and goes ahead.
    pub(super) fn order_kind(&self, frame: &ControlFrame, route: Route) -> Kind {
        match frame {
            ControlFrame::Request(request) => {
                let Ok(entry) = self.admit(request.method.as_str(), request.method_version) else {
                    return Kind::Blocking;
                };
                let kind = ordering::request_kind(Some(entry.method));
                // A voice read is decided under the pairing grant whatever session it names, so it
                // keeps its place and the rule below holds as stated.
                if kind == Kind::Blocking || crate::voice::VoiceModule::serves(entry.method) {
                    return Kind::Blocking;
                }
                let session = self.read_session(request, entry);
                let by_action_alone =
                    entry.method == kr_protocol::method::Method::ActionRead && session.is_none();
                if by_action_alone || session.is_some_and(|named| named != route.session) {
                    return Kind::Blocking;
                }
                kind
            }
            ControlFrame::Mutation(mutation) => {
                let Ok(entry) = self.admit(mutation.method.as_str(), mutation.method_version)
                else {
                    return Kind::Blocking;
                };
                let kind = ordering::mutation_kind(Some(entry.method));
                let (session, grant) = mutation_subject(mutation);
                if session.is_none_or(|named| named != route.session)
                    || grant.is_some_and(|named| named != route.grant)
                {
                    return Kind::Blocking;
                }
                kind
            }
            _ => Kind::Blocking,
        }
    }

    /// Serves one frame of the connection, and says whether the connection goes on.
    ///
    /// The frame is answered and its answer written, as the loop does for every frame. When the
    /// frame is one keys go ahead of ([`Self::order_kind`]), the stream is read ahead meanwhile
    /// and each key found is answered at once; what else was read is put back at the front of
    /// `backlog`, in the order it was sent, before the frame's own answer is written.
    pub(crate) async fn serve_frame(
        self: &Arc<Self>,
        control: &mut ControlChannel,
        backlog: &mut VecDeque<Read>,
        frame: ControlFrame,
    ) -> bool {
        let route = self.fixed_route().await;
        let overtaken =
            route.is_some_and(|route| self.order_kind(&frame, route) == Kind::Independent);
        let Some(route) = route.filter(|_| overtaken) else {
            let Some(answer) = self.answer(frame).await else {
                return false;
            };
            return self.write_answer(answer).await;
        };

        let mut ordered = Answering(tokio::spawn({
            let connection = Arc::clone(self);
            async move { connection.answer(frame).await }
        }));
        let mut sorting = Sorting::default();
        let mut held: VecDeque<Read> = VecDeque::new();
        let mut key: Option<KeyAnswering<'_>> = None;
        let answered = loop {
            // The frame's own answer first, so a long run of keys cannot delay its end; then the
            // key being answered; then the stream, only while no key is being answered and a key
            // could still be served.
            tokio::select! {
                biased;
                answered = &mut ordered.0 => match answered {
                    Ok(answered) => break answered,
                    // The task panicked: the connection ends, as it did when the answer panicked
                    // in the loop's own task.
                    Err(_) => return false,
                },
                went_on = async { key.as_mut().expect("a key is being answered").await },
                    if key.is_some() => {
                    key = None;
                    if !went_on {
                        return false;
                    }
                }
                next = async {
                    match backlog.pop_front() {
                        Some(queued) => queued,
                        None => control.recv().await,
                    }
                }, if key.is_none() && sorting.may_read() => {
                    let kind = next.as_ref().map(|frame| self.order_kind(frame, route));
                    match (sorting.judge(kind), next) {
                        (Judgement::Serve, Some(frame)) => {
                            key = Some(Box::pin(self.answer_and_write(frame)));
                        }
                        (_, next) => held.push_back(next),
                    }
                }
            }
        };
        // The key in flight finishes before the answer it went ahead of is written.
        if let Some(key) = key.take()
            && !key.await
        {
            return false;
        }
        // What was held goes back in front of what was never looked at.
        held.extend(backlog.drain(..));
        *backlog = held;
        let Some(answer) = answered else {
            return false;
        };
        self.write_answer(answer).await
    }

    /// Answers one frame and writes the answer, and says whether the connection goes on.
    async fn answer_and_write(&self, frame: ControlFrame) -> bool {
        match self.answer(frame).await {
            Some(answer) => self.write_answer(answer).await,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue, Request};
    use kr_protocol::grant::SessionSelector;
    use kr_protocol::ids::{
        ActionId, ActionWindowId, ApplicationInstanceId, AttachmentId, AuthorityRevision,
        EnvironmentId, GrantId, InputLeaseEpoch, InputSequence, RequestId, SessionEpoch, SessionId,
    };
    use kr_protocol::method::{Method, MethodVersion};
    use kr_protocol::scalars::{Bytes, Digest256, Nullable, TimestampMs, Uuid};

    use super::super::a_share_that_names_a_current_decision::{
        Holding, device_read, holding_grant, holds_question_reads, world,
    };
    use super::*;

    fn session(byte: u8) -> SessionId {
        SessionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn grant(byte: u8) -> GrantId {
        GrantId::new(Uuid::from_bytes([byte; 16]))
    }

    fn read<P: serde::Serialize>(method: Method, params: &P) -> ControlFrame {
        ControlFrame::Request(device_read(7, method, params))
    }

    fn key(session_id: SessionId) -> ControlFrame {
        read(
            Method::InputWrite,
            &kr_protocol::input::InputWriteParams {
                session_id,
                attachment_id: AttachmentId::new(Uuid::from_bytes([9; 16])),
                epoch: InputLeaseEpoch::new(1),
                sequence: InputSequence::new(0),
                bytes: Bytes::new(b"x".to_vec()),
            },
        )
    }

    fn mutation(
        method: Method,
        session_id: Option<SessionId>,
        grant_id: Option<GrantId>,
    ) -> ControlFrame {
        ControlFrame::Mutation(Box::new(MutationRequest {
            request_id: RequestId::new(8),
            method: method.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(Uuid::from_bytes([10; 16])),
            grant_id: Nullable(grant_id),
            target: ActionTarget {
                environment_id: EnvironmentId::new(Uuid::from_bytes([11; 16])),
                session_id: Nullable(session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            expected: ParamsValue::empty(),
            action_window_id: ActionWindowId::new("window").expect("an id"),
            requested_ttl_ms: kr_protocol::scalars::DurationMs::new(1),
            params: ParamsValue::empty(),
        }))
    }

    /// KR-PERF-002: the frames a device's key goes ahead of, and the keys that go ahead, are those
    /// this host decides over the session and the grant its connection already acts under, or over
    /// none. Any other frame keeps its place, because deciding it can note another share on the
    /// connection and a key must not land ahead of that.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn only_a_frame_decided_over_the_route_the_connection_acts_under_goes_ahead_of_keys() {
        let (world, _) = world(Holding::default(), holds_question_reads()).await;
        let (pairing, _) = crate::service::net::tests::granted(
            kr_protocol::grant::GrantExpiry::Never,
            world.controller.policy().authority_revision(),
        );
        let mut pairing = pairing;
        pairing.session_selector = SessionSelector::Any;
        let device = holding_grant(&world.controller, 0x21, pairing);
        let connection = RemoteConnection::for_test(&world.controller, device.clone());
        let (here, elsewhere) = (session(0x31), session(0x32));
        let route = Route {
            session: here,
            grant: device.grant.grant_id,
        };
        let kind = |frame: &ControlFrame| connection.order_kind(frame, route);

        // A key is served ahead only when it names the session the connection acts for.
        assert_eq!(kind(&key(here)), Kind::Key);
        assert_eq!(kind(&key(elsewhere)), Kind::Blocking);

        // A read goes ahead of keys when it is decided over that session or over none.
        let of = |session_id| kr_protocol::session::SessionReadParams { session_id };
        assert_eq!(
            kind(&read(Method::SessionRead, &of(here))),
            Kind::Independent
        );
        assert_eq!(
            kind(&read(Method::SessionRead, &of(elsewhere))),
            Kind::Blocking
        );
        assert_eq!(
            kind(&read(Method::HostInfo, &ParamsValue::empty())),
            Kind::Independent,
            "a read that names no session is decided under the pairing grant"
        );
        // A session named inside the subject is the session the decision reads.
        let subject = |session_id| kr_protocol::agent::AgentSnapshotParams {
            subject: kr_protocol::agent::AgentSubject {
                session_id,
                application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([12; 16])),
            },
            from_node: Nullable::null(),
        };
        assert_eq!(
            kind(&read(Method::AgentSnapshot, &subject(here))),
            Kind::Independent
        );
        assert_eq!(
            kind(&read(Method::AgentSnapshot, &subject(elsewhere))),
            Kind::Blocking
        );
        // `session.open` scopes the connection, and a request for a write is not a read.
        assert_eq!(
            kind(&read(Method::SessionOpen, &ParamsValue::empty())),
            Kind::Blocking
        );
        assert_eq!(
            kind(&read(Method::SessionDetach, &ParamsValue::empty())),
            Kind::Blocking
        );

        // A read of an action alone is decided over the session its recorded route names, and
        // one with no route is not yet decided over any. A voice read keeps its place whatever
        // session it names, and a route that names no session decides none.
        let voice_context = read(
            Method::VoiceContext,
            &kr_protocol::voice::VoiceContextParams {
                voice_session_id: kr_protocol::ids::VoiceSessionId::new(Uuid::from_bytes([16; 16])),
                session_id: here,
                selected: kr_protocol::scalars::CanonicalSet::new(),
                delegation_id: Nullable::null(),
            },
        );
        assert_eq!(kind(&voice_context), Kind::Blocking);
        assert_eq!(
            kind(&read(
                Method::VoicePrepare,
                &kr_protocol::voice::VoicePrepareParams {
                    session_ids: [here].into_iter().collect(),
                    selected: kr_protocol::scalars::CanonicalSet::new(),
                },
            )),
            Kind::Blocking
        );
        let action = ActionId::new(Uuid::from_bytes([13; 16]));
        let by_action = read(
            Method::ActionRead,
            &kr_protocol::receipt::ActionReadParams {
                action_id: action,
                session_id: None,
            },
        );
        assert_eq!(kind(&by_action), Kind::Blocking, "no route is recorded");
        connection
            .devices
            .claim_action_route(
                &connection.device.principal(),
                action,
                Some(here),
                Digest256::from_bytes([1; 32]),
                TimestampMs::new(1),
            )
            .expect("the route is recorded");
        assert_eq!(kind(&by_action), Kind::Independent, "it names this session");
        let routed_to_none = ActionId::new(Uuid::from_bytes([15; 16]));
        connection
            .devices
            .claim_action_route(
                &connection.device.principal(),
                routed_to_none,
                None,
                Digest256::from_bytes([3; 32]),
                TimestampMs::new(1),
            )
            .expect("the route is recorded");
        assert_eq!(
            kind(&read(
                Method::ActionRead,
                &kr_protocol::receipt::ActionReadParams {
                    action_id: routed_to_none,
                    session_id: None,
                },
            )),
            Kind::Blocking,
            "a host effect's route names no session"
        );
        assert_eq!(
            kind(&read(
                Method::ActionRead,
                &kr_protocol::receipt::ActionReadParams {
                    action_id: routed_to_none,
                    session_id: Some(here),
                },
            )),
            Kind::Independent,
            "an action read that names the session itself is decided over it"
        );
        let routed_elsewhere = ActionId::new(Uuid::from_bytes([14; 16]));
        connection
            .devices
            .claim_action_route(
                &connection.device.principal(),
                routed_elsewhere,
                Some(elsewhere),
                Digest256::from_bytes([2; 32]),
                TimestampMs::new(1),
            )
            .expect("the route is recorded");
        assert_eq!(
            kind(&read(
                Method::ActionRead,
                &kr_protocol::receipt::ActionReadParams {
                    action_id: routed_elsewhere,
                    session_id: None,
                },
            )),
            Kind::Blocking,
            "it names another session"
        );

        // A mutation is decided over the target it names and the grant it names, and nothing in
        // its parameters.
        let own = Some(device.grant.grant_id);
        assert_eq!(
            kind(&mutation(Method::AttachmentViewport, Some(here), None)),
            Kind::Independent
        );
        assert_eq!(
            kind(&mutation(Method::AttachmentViewport, Some(here), own)),
            Kind::Independent
        );
        assert_eq!(
            kind(&mutation(Method::TerminalResize, None, None)),
            Kind::Blocking,
            "a mutation that names no session is refused before the worker, and keeps its place"
        );
        assert_eq!(
            kind(&mutation(Method::AttachmentViewport, Some(elsewhere), None)),
            Kind::Blocking
        );
        assert_eq!(
            kind(&mutation(
                Method::AttachmentViewport,
                Some(here),
                Some(grant(0x41))
            )),
            Kind::Blocking
        );
        assert_eq!(
            kind(&mutation(Method::SessionDetach, Some(here), None)),
            Kind::Blocking
        );

        // Nothing that is not a request or a mutation is read ahead of, a device's own forwarded
        // frames among them: the host refuses those and ends the connection.
        assert_eq!(
            kind(&ControlFrame::Event(
                kr_protocol::envelope::ControlEvent::Keepalive
            )),
            Kind::Blocking
        );
        let forwarded =
            ControlFrame::ForwardedRead(Box::new(kr_protocol::local::ForwardedRequest {
                request: Request {
                    request_id: RequestId::new(9),
                    method: Method::InputWrite.into(),
                    method_version: MethodVersion::V1,
                    params: ParamsValue::empty(),
                },
                actor: connection.envelope(device.grant.grant_id, AuthorityRevision::default()),
                authority_deadline_boot_ms: Nullable::null(),
                history: None,
            }));
        assert_eq!(kind(&forwarded), Kind::Blocking);
    }
}
