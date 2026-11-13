//! Serving a local client: its hello, its window, its keepalive and the mutation it performs.

use std::sync::Arc;

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::split;
use kr_ipc::peer::PeerIdentity;
use kr_protocol::authority::EffectClass;
use kr_protocol::envelope::{ControlEvent, ControlFrame, MutationRequest};
use kr_protocol::error::ErrorCode;
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, ProtocolVersion, ReceiveLimits};
use kr_protocol::ids::{ActorId, ConnectionId, RequestId};
use kr_protocol::local::{LocalHelloAck, LocalPeer, LocalRole};
use kr_protocol::method::Method;
use kr_protocol::scalars::{CanonicalSet, Nullable, U64};
use kr_transport::window::MAX_WINDOW_VALIDITY;

use crate::error::{ControllerError, Result};
use crate::given::local_door::{Declined, DoorReply, ReplySink, Standing, declined, told};
use crate::given::{Given, Recorded, Settled};

use super::identifiers::{Arrival, SpendError};
use super::{Controller, error_reply, net, respond};

/// How often the daemon replaces a live connection's action window.
///
/// Half the window's validity, which is the schedule the transport uses: a client is never left
/// holding a window that expired while a renewal was still in flight, and a connection that is
/// about to submit a mutation does not have to ask for one.
pub const WINDOW_RENEWAL: std::time::Duration =
    std::time::Duration::from_millis(MAX_WINDOW_VALIDITY.as_millis() as u64 / 2);

/// How often a local connection sends a keepalive.
///
/// Section 23 puts it at ten seconds while the connection is active. A network connection has the
/// transport's own keepalive underneath it; a Unix socket or a named pipe has nothing equivalent,
/// so the control stream carries one itself.
pub const LOCAL_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(10);

/// How long the loop that serves a local connection waits for the peer to take one frame it
/// writes without being asked: a keepalive or a replacement window.
///
/// The loop writes them between reads, so while it waits for the peer it reads nothing, and a
/// peer that has stopped reading would hold the connection for ever. Past this the connection
/// ends, as a failed write ends it. The same bound the daemon gives a worker's answer.
pub const LOCAL_WRITE_BOUND: std::time::Duration = super::workers::WORKER_EXCHANGE;

/// How often the loop that serves a local connection writes unasked, and how long it waits for the
/// peer to take what it writes.
#[derive(Clone, Copy, Debug)]
pub(super) struct LocalPace {
    renewal: std::time::Duration,
    keepalive: std::time::Duration,
    write_bound: std::time::Duration,
}

impl Default for LocalPace {
    fn default() -> Self {
        Self {
            renewal: WINDOW_RENEWAL,
            keepalive: LOCAL_KEEPALIVE,
            write_bound: LOCAL_WRITE_BOUND,
        }
    }
}

/// The methods whose answer the registry keeps under the actor's action, in its receipts, and that
/// both routes look up before they admit a call (`Controller::retained`, which the local route and
/// a paired device's route each make first), so that a repeat is answered from the record, on a
/// later connection and after the window it was sent in has closed. The stored-formats table pairs
/// each with the type of the answer it keeps, so an answer kept here whose type the table does not
/// name fails the lock's checks. A method only a paired device sends, such as
/// `device.push.register`, is refused to a local caller before it can claim, so the lookup finds no
/// record for it there.
pub const RETAINED_AUTHORITY_ANSWERS: [Method; 25] = [
    Method::GrantCreate,
    Method::GrantRedeem,
    Method::GrantRevoke,
    Method::GrantTransfer,
    Method::DeviceRevoke,
    Method::DevicePreviewKeyUpdate,
    Method::DeliveryDestinationConfigure,
    Method::DeliveryDestinationRemove,
    Method::DeliveryDestinationSecretSet,
    Method::DevicePushRegister,
    Method::OrganisationEnrol,
    Method::OrganisationExclusiveSet,
    Method::OrganisationWithdraw,
    Method::PrivacySet,
    Method::AccountSignIn,
    Method::AccountSignOut,
    Method::AccountStorageSignIn,
    Method::AccountStorageSignOut,
    Method::SessionRename,
    Method::DescriptionConfigure,
    Method::DescriptionDownload,
    Method::EnvironmentEnrol,
    Method::EnvironmentForget,
    Method::EnvironmentRefresh,
    Method::HostUpdateHandover,
];

/// The methods whose answer the machine group's record keeps, in the same store, and answers again to
/// a repeat.
pub const RETAINED_MACHINE_ANSWERS: [Method; 3] = [
    Method::MachineJoin,
    Method::MachineMerge,
    Method::MachineSplit,
];

/// Serves each connection `listener` accepts on a task of its own, until accepting fails or `serve`
/// declines a connection by answering `None`.
///
/// The tasks belong to this future and not to the runtime: when it ends, or is dropped because its
/// owner stopped the daemon, every connection it is serving ends with it, and its peer sees the
/// connection close. A task left to run alone would keep what it holds, the daemon among it, for as
/// long as its peer stayed connected.
pub(crate) async fn serve_each<S, T>(listener: &Listener, mut serve: S) -> Result<()>
where
    S: FnMut(Connection, PeerIdentity) -> Option<T>,
    T: std::future::Future<Output = ()> + Send + 'static,
{
    let mut serving = tokio::task::JoinSet::new();
    loop {
        let (connection, peer) = listener.accept().await?;
        // Connections that have ended are collected as the next one arrives, so the set holds no
        // more than those being served and those that ended since the last arrival.
        while serving.try_join_next().is_some() {}
        let Some(task) = serve(connection, peer) else {
            return Ok(());
        };
        serving.spawn(task);
    }
}

/// Takes a connection's authority away when its task ends, however it ends.
///
/// The task of a connection is cancelled, not finished, when the loop that serves it is ended, and
/// code after its last await does not run then. A window that outlived its connection could
/// first-admit a request through a connection that no longer exists, and a registration that
/// outlived it would be an authority nothing can revoke, so both go from a destructor, which runs
/// wherever the task is.
pub(super) struct EndsConnection<'a> {
    controller: &'a Controller,
    connection_id: ConnectionId,
    /// Whether the connection was registered in the authority store, which only a client
    /// connection is: a rendezvous exchange holds a window and nothing else.
    registered: bool,
}

impl<'a> EndsConnection<'a> {
    /// A client connection, whose windows and registration go with it.
    pub(super) const fn client(controller: &'a Controller, connection_id: ConnectionId) -> Self {
        Self {
            controller,
            connection_id,
            registered: true,
        }
    }

    /// A rendezvous exchange, whose windows go with it.
    pub(super) const fn exchange(controller: &'a Controller, connection_id: ConnectionId) -> Self {
        Self {
            controller,
            connection_id,
            registered: false,
        }
    }
}

impl Drop for EndsConnection<'_> {
    fn drop(&mut self) {
        self.controller
            .windows
            .retire_connection(self.connection_id);
        if self.registered {
            self.controller.deregister(self.connection_id);
        }
    }
}

/// Ends the daemon's network connections when the loop that serves its clients ends.
struct StopsTheNetwork(Arc<Controller>);

impl Drop for StopsTheNetwork {
    fn drop(&mut self) {
        self.0.end_network_connections();
    }
}

impl Controller {
    /// Makes this daemon's local connections write unasked at the pace given, and wait for their
    /// peer for `write_bound`, from the next connection on.
    #[cfg(feature = "testing")]
    pub fn pace_local_connections(
        &self,
        renewal: std::time::Duration,
        keepalive: std::time::Duration,
        write_bound: std::time::Duration,
    ) {
        *self
            .local_pace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = LocalPace {
            renewal,
            keepalive,
            write_bound,
        };
    }

    /// How many writes of a local connection's loop have had to wait for their peer.
    #[cfg(feature = "testing")]
    pub fn local_writes_blocked(&self) -> usize {
        self.local_writes_blocked
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The pace local connections write unasked at.
    fn local_pace(&self) -> LocalPace {
        #[cfg(feature = "testing")]
        {
            *self
                .local_pace
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
        #[cfg(not(feature = "testing"))]
        {
            LocalPace::default()
        }
    }

    /// Writes one frame the loop was not asked for, and says whether the connection goes on.
    ///
    /// The write waits for the peer for at most `bound`: a peer that has stopped reading is a
    /// connection that ends rather than one that holds its loop, and the frame it was part way
    /// through is not continued, because the connection goes with it. The wait is the one
    /// [`kr_ipc::framed::Writable`] gives a caller whose peer may stall, under a deadline of its
    /// own.
    async fn write_within(
        &self,
        writer: &mut kr_ipc::framed::FrameWriter,
        kind: StreamKind,
        frame: &ControlFrame,
        bound: std::time::Duration,
    ) -> bool {
        use kr_ipc::framed::{FrameWriter, Wrote};

        let Ok(bytes) = FrameWriter::encode(kind, frame) else {
            return false;
        };
        let written = async {
            let mut outcome = writer.begin_frame(&bytes)?;
            let mut waited = false;
            while outcome == Wrote::Blocked {
                if !waited {
                    waited = true;
                    #[cfg(feature = "testing")]
                    self.local_writes_blocked
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                writer.writable().ready().await?;
                outcome = writer.resume_frame()?;
            }
            kr_ipc::Result::Ok(())
        };
        matches!(tokio::time::timeout(bound, written).await, Ok(Ok(())))
    }

    /// What a local caller is told when the local owner's lease ended while its answer was being
    /// written.
    ///
    /// A write's answer is withheld after its effect ran, so the caller is told its outcome is
    /// unknown: a refusal of any other kind says nothing was done, which is false here. A read has
    /// no effect to be unsure of and is refused.
    pub(super) fn lease_ended_reply(
        &self,
        request_id: RequestId,
        method: Option<Method>,
    ) -> ControlFrame {
        let code = match method.map(|method| method.entry().effect) {
            Some(EffectClass::Write) => ErrorCode::OutcomeUnknown,
            Some(EffectClass::Read) | None => ErrorCode::PermissionDenied,
        };
        error_reply(
            request_id,
            code,
            "this host is exclusively organisation-managed and its local owner's membership lease \
             ended before this result could be sent, so the result is withheld; if the request \
             changed anything the change stands, and the request is not to be repeated under a new \
             identifier. Present a new lease with `kr organisation present`.",
        )
    }

    /// Writes the answer to a local caller's request for `method`, and says whether the
    /// connection goes on.
    ///
    /// The answer of a method that is held to the local owner's lease is written only while the
    /// lease holds. The lease is asked again before every transport write, and while the peer has
    /// no room it is asked again each time the peer reads, so an answer that waited for a peer is
    /// not finished under a lease that ended meanwhile: one none of which has gone is taken back
    /// and its refusal written, and one the peer has part of ends the connection.
    pub(crate) async fn write_answer(
        &self,
        writer: &mut kr_ipc::framed::FrameWriter,
        kind: StreamKind,
        answer: &ControlFrame,
        method: Option<Method>,
        request_id: RequestId,
    ) -> bool {
        use kr_ipc::framed::CheckedWrite;

        let Some(method) = method.filter(|method| {
            kr_protocol::method::local_hold(*method) == kr_protocol::method::LocalHold::Held
        }) else {
            return writer.write_message(answer).await.is_ok();
        };
        let Ok(bytes) = kr_ipc::framed::FrameWriter::encode(kind, answer) else {
            return false;
        };
        let permitted = || self.local_hold(method).is_ok();
        let mut begun = false;
        loop {
            let attempt = if begun {
                writer.resume_frame_checked(&permitted)
            } else {
                begun = true;
                writer.begin_frame_checked(&bytes, &permitted)
            };
            match attempt {
                Ok(CheckedWrite::Complete) => return true,
                Ok(CheckedWrite::Blocked) => {
                    if writer.writable().ready().await.is_err() {
                        return false;
                    }
                }
                Ok(CheckedWrite::Refused) => {
                    if !writer.withdraw_unstarted() {
                        return false;
                    }
                    if self.local_hold(method).is_ok() {
                        // The lease was presented again meanwhile: offered afresh.
                        begun = false;
                        continue;
                    }
                    return writer
                        .write_message(&self.lease_ended_reply(request_id, Some(method)))
                        .await
                        .is_ok();
                }
                Err(_) => return false,
            }
        }
    }

    /// Arms the pause the next call stops at once it has looked for a retained answer, whether or
    /// not it found one, before the admission it arrived under is asked again. Returns the end that
    /// says the call has arrived, and the end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_retained_lookup(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.after_the_retained_lookup.arm()
    }

    /// Arms the pause the next first admission at this door stops at once its effect is spawned,
    /// before the service that performs it is asked and so before its action has written a claim.
    /// Returns the end that says the effect has arrived, and the end that lets it go. The pause
    /// fires once.
    #[cfg(feature = "testing")]
    pub fn pause_before_a_door_effect(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.before_a_door_effect.arm()
    }

    /// Arms the pause the next local write stops at once the route that performs it has answered,
    /// before the answer is told, so that a connection can be withdrawn or a fence set where the
    /// answer is asked what it stands on. Returns the end that says the route has answered, and the
    /// end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_after_a_route_answers(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.after_a_route_answers.arm()
    }

    /// Arms the pause the next answer the local door tells stops at as it begins to tell it, so
    /// that authority can change after the route's own work and before the check that decides what
    /// is shown. Returns the end that says the door has arrived, and the end that lets it go. The
    /// pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_before_a_reply_is_told(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.before_a_reply_is_told.arm()
    }

    /// Every reply the local door's sink has consumed so far, with the request it answers.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn replies_written(&self) -> Vec<(RequestId, ControlFrame)> {
        self.replies_written
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Every reply `told` or `declined` has made so far, with the request it answers and whether
    /// it was told (and not declined).
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn replies_made(&self) -> Vec<(RequestId, bool, ControlFrame)> {
        self.replies_made
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Notes a reply `told` or `declined` made, where it is made.
    #[cfg(feature = "testing")]
    pub(crate) fn note_a_reply_made(
        &self,
        request_id: RequestId,
        told: bool,
        frame: &ControlFrame,
    ) {
        self.replies_made
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((request_id, told, frame.clone()));
    }

    /// Notes a reply the sink consumed.
    #[cfg(feature = "testing")]
    pub(crate) fn note_a_reply_written(&self, request_id: RequestId, frame: &ControlFrame) {
        self.replies_written
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((request_id, frame.clone()));
    }

    /// Stops here while the pause before a reply is told is armed ([`Self::pause_before_a_reply_is_told`]).
    #[cfg(feature = "testing")]
    pub(crate) async fn stop_before_a_reply_is_told(&self) {
        self.before_a_reply_is_told.wait().await;
    }

    /// Arms the pause the next copy of an action stops at once its window has refused it and it has
    /// looked for the claim of its action and found none while another arrival may carry the action
    /// out, before it asks again whether that arrival still may. Returns the end that says the copy
    /// has arrived, and the end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_after_a_copy_looked_for_a_claim(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.after_a_copy_looked_for_a_claim.arm()
    }

    /// Arms the signal that the next copy of an action to wait, because its window is refused and
    /// an arrival under the same identifier has not decided what it is doing, gives. Returns the end
    /// that says the copy is waiting. It fires once.
    #[cfg(feature = "testing")]
    pub fn notify_when_a_copy_waits(&self) -> tokio::sync::oneshot::Receiver<()> {
        self.identifiers_performing.notify_when_a_copy_waits()
    }

    /// Arms the pause the next mutation of a paired device stops at once its worker has answered,
    /// before the answer is checked against the device's authority. Returns the end that says the
    /// call has arrived, and the end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_after_the_worker_answered(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.after_the_worker_answered.arm()
    }

    /// Arms the pause the connection of a paired device stops at once it has answered its next
    /// frame, before it goes on to the one after. A connection the authority feed's refusal has
    /// cut from its worker ends there, and closes under an answer the device has not yet read;
    /// held at the pause, it ends only when the pause is let go. Returns the end that says the
    /// answer has been written, and the end that lets the connection go on. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_after_a_frame_is_answered(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.after_a_frame_is_answered.arm()
    }

    /// Arms the pause the next key registration of a paired device stops at once its first lookup
    /// for a retained answer has found none, before it looks again. Returns the end that says the
    /// registration has arrived, and the end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_before_the_second_retained_lookup(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.before_the_second_retained_lookup.arm()
    }

    /// Arms the pause the next automation mutation stops at once the admission it arrived under
    /// has been asked, before the workflow journal's transaction asks it again. Returns the end
    /// that says the mutation has arrived, and the end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_after_the_automation_admission(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.after_the_automation_admission.arm()
    }

    /// Arms the pause the next network connection stops at once the transport has authorised it,
    /// before this host registers it. Returns the end that says the connection has arrived, and
    /// the end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_connection_registration(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.before_a_connection_is_registered.arm()
    }

    /// Holds the withdrawal of every network connection that ends from now on, whether its control
    /// stream is lost or its handler is dropped, before its registration goes. Returns the end that
    /// says the first withdrawal has arrived, and the end that lets them all go when it is set to
    /// `true` or dropped.
    #[cfg(feature = "testing")]
    pub fn pause_connection_deregistration(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::watch::Sender<bool>,
    ) {
        self.before_a_connection_is_deregistered.arm()
    }

    /// Answers an action this daemon has already admitted for this caller, if it has.
    ///
    /// The de-duplication key is the actor and the action together, and the payload digest decides
    /// whether it is the same action or a reused identifier. Only `session.create` has a retained
    /// record here; a close is retained by the worker that owns the session, which answers its own
    /// duplicates.
    pub(super) async fn retained(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Option<Recorded<ControlFrame>> {
        if matches!(method, Method::AgentToolsInstall | Method::AgentToolsRemove) {
            return self.retained_installation(actor_id, mutation).await;
        }
        self.retained_by_store(actor_id, mutation, method).await
    }

    async fn retained_by_store(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Option<Recorded<ControlFrame>> {
        // An authority change this host already holds a claim on is answered from it, here, before
        // freshness is asked for: its result, its refusal, that it is still running, or what this
        // host's records prove an attempt that ended unrecorded did. Section 9 keeps a receipt
        // readable after the window that admitted it has expired, and a retry of a revocation that
        // cannot reach its result would otherwise be told its window is gone rather than what
        // happened.
        if RETAINED_AUTHORITY_ANSWERS.contains(&method) {
            return self.retained_authority_answer(actor_id, mutation).await;
        }
        // The request for the disclosed checks is answered the same way from the record of what
        // this host answered, on a later connection, after its window has closed and after a
        // restart. The record is not in the registry; what the run found lives only as long as
        // this daemon, and the record holds only where the checks stood when it was answered.
        if method == Method::EnvironmentCapabilitiesCheck {
            return self.kept_capability_checks(actor_id, mutation);
        }
        // A machine group step is claimed in the same store and answered from it the same way, and
        // from the machine group record where an attempt ended without recording what it did.
        if RETAINED_MACHINE_ANSWERS.contains(&method) {
            return self.machine_retained(actor_id, mutation).await;
        }
        // A declaration of a device's keys is answered the same way, from the outcome the device
        // directory recorded beside the keys: a completion or a refusal alike, so a retry whose
        // reply was lost is told what happened rather than that its window is gone.
        if method == Method::DeviceKeysComplete {
            return self.retained_declaration(actor_id, mutation);
        }
        // A voice change is claimed in the same store and answered the same way: section 9 keeps
        // a receipt readable after the window that admitted it has expired, and a retry that
        // cannot reach its result would otherwise be told its window is gone rather than what
        // happened. A delegation is answered from it too, under the authority it is owed now.
        if crate::voice::VoiceModule::serves(method) {
            return self
                .voice_answered(actor_id, mutation)
                .await
                .present()
                .map(|found| found.respond(mutation.request_id));
        }

        if method != Method::SessionCreate {
            return None;
        }
        self.retained_create(actor_id, mutation).await
    }

    /// Serves the client endpoint.
    ///
    /// A daemon is stopped by ending its serving loops, as every suite does by aborting them and
    /// the binary does when its process ends and its runtime drops them: this one,
    /// [`Self::serve_rendezvous`] and `transfer::serve_chunks`. Each loop ends the connections it
    /// serves with it, and each peer sees its connection close. This loop also ends the network
    /// connections: a connection holds the daemon for as long as it lasts, and the daemon owns the
    /// network listener whose tasks serve the network ones, so dropping the daemon's last handle
    /// while a loop runs cannot release it.
    ///
    /// Once the loops are ended the daemon is released at the next turns of the runtime, when the
    /// tasks they ended have dropped their holds, and every other holder has let go. An operation
    /// that has already started (a request's effect, the watch on a session's closure) keeps the
    /// daemon until it ends, and the network listener, which this ends the connections of, is
    /// ended once for good: a second loop on the same daemon would find its network gone.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting fails.
    pub async fn serve_clients(self: Arc<Self>, listener: Listener) -> Result<()> {
        let _stops = StopsTheNetwork(Arc::clone(&self));
        serve_each(&listener, |connection, peer| {
            let controller = Arc::clone(&self);
            Some(async move {
                let _ = controller
                    .client(connection, peer, StreamKind::Control)
                    .await;
            })
        })
        .await
    }

    /// Ends every connection the daemon's network listener is serving, and stops it accepting.
    fn end_network_connections(&self) {
        if let Some(network) = self.network.get() {
            network.end_connections();
        }
    }

    pub(super) fn acknowledgement(
        &self,
        selected_version: ProtocolVersion,
        role: LocalRole,
        action_window: ActionWindow,
        peer: &PeerIdentity,
    ) -> Box<LocalHelloAck> {
        Box::new(LocalHelloAck {
            selected_version,
            role,
            connection_id: action_window.connection_id,
            environment_id: self.paths.environment_id(),
            boot_identity: self.boot_identity.clone(),
            peer: LocalPeer {
                uid: U64::new(u64::from(peer.uid)),
                gid: U64::new(u64::from(peer.gid)),
                pid: Nullable(peer.pid.map(|pid| U64::new(u64::from(pid)))),
            },
            action_window,
            capabilities: CanonicalSet::new(),
            max_receive: ReceiveLimits::default(),
            build: Some(kr_protocol::local::LocalBuild::this(self.build_id.clone())),
        })
    }

    pub(crate) async fn client(
        self: &Arc<Self>,
        connection: Connection,
        peer: PeerIdentity,
        kind: StreamKind,
    ) -> Result<()> {
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        // A connection that ends takes its windows and its registration with it, whether its loop
        // finishes or its task is cancelled.
        let _ends = EndsConnection::client(self, connection_id);
        let (mut reader, mut writer) = split(connection, kind);
        self.serve_client(&mut reader, &mut writer, connection_id, &peer, kind)
            .await
    }

    async fn serve_client(
        self: &Arc<Self>,
        reader: &mut kr_ipc::framed::FrameReader,
        writer: &mut kr_ipc::framed::FrameWriter,
        connection_id: ConnectionId,
        peer: &PeerIdentity,
        kind: StreamKind,
    ) -> Result<()> {
        let actor_id = kr_protocol::sharing::local_actor(u64::from(peer.uid));
        let mut negotiated = false;
        // Where this connection's requests originally entered, when it is a process bridge's
        // helper and said so in its hello. Kept for the life of the connection and never replaced:
        // a connection says hello once.
        let mut origin: Option<kr_protocol::local::BridgeOrigin> = None;
        // Both timers fire once immediately; that first tick is consumed here so a connection is
        // not handed a replacement window before it has read the first one.
        let pace = self.local_pace();
        let mut renewal = tokio::time::interval(pace.renewal);
        renewal.tick().await;
        let mut keepalive = tokio::time::interval(pace.keepalive);
        keepalive.tick().await;
        loop {
            let frame = tokio::select! {
                frame = reader.read_message::<ControlFrame>() => match frame {
                    Ok(frame) => frame,
                    Err(_) => break,
                },
                // The window is replaced without being asked for, at half its validity. A client
                // never has to renew before a mutation, and never holds a window that expired
                // while its renewal was in flight.
                _ = renewal.tick(), if negotiated => {
                    let Ok(window) = self.issue_window(connection_id) else {
                        break;
                    };
                    let renewed = ControlFrame::Event(ControlEvent::ActionWindowRenewed(window));
                    if !self.write_within(writer, kind, &renewed, pace.write_bound).await {
                        break;
                    }
                    continue;
                }
                _ = keepalive.tick(), if negotiated => {
                    let beat = ControlFrame::Event(ControlEvent::Keepalive);
                    if !self.write_within(writer, kind, &beat, pace.write_bound).await {
                        break;
                    }
                    continue;
                }
            };
            let reply = match frame {
                // A connection says hello once. Admitting it again would let a connection that
                // was admitted as a bridge's helper take its origin off, or a controller's
                // registration be replaced by a client's, so a second hello is answered and
                // changes nothing.
                ControlFrame::Hello(_) if negotiated => error_reply(
                    RequestId::new(0),
                    ErrorCode::UnsupportedSchema,
                    "this connection has already negotiated; open another one to change client",
                ),
                ControlFrame::Hello(hello) => {
                    // An origin is something only a bridge's helper has, and only for an
                    // invocation that was locally authenticated where it started. Anything else is
                    // refused here, on this side, whatever the helper checked before connecting.
                    if let Some(declared) = hello.origin.as_ref()
                        && (hello.client != kr_protocol::local::LocalClientKind::Cli
                            || !declared.is_admissible())
                    {
                        let refusal = error_reply(
                            RequestId::new(0),
                            ErrorCode::PermissionDenied,
                            "a process bridge carries locally authenticated invocations only, \
                             and only a command-line client may declare where one began",
                        );
                        let _ = writer.write_message(&refusal).await;
                        break;
                    }
                    // A peer that says it can hold no outstanding mutation at all is refused
                    // rather than quietly read as one. The worker's endpoint refuses the same
                    // offer, and a limit this host would then ignore is worse than a refusal.
                    if hello.max_receive.max_outstanding_mutations.get() == 0 {
                        let refusal = error_reply(
                            RequestId::new(0),
                            ErrorCode::InvalidArgument,
                            "a connection holds at least one outstanding mutation; offering none \
                             is not a limit this host serves",
                        );
                        let _ = writer.write_message(&refusal).await;
                        break;
                    }
                    // The protocol this daemon states, which a client of the same major offers.
                    let stated = kr_protocol::retained::stated_protocol();
                    if hello
                        .offered_versions
                        .iter()
                        .any(|offered| offered.major == stated.major)
                    {
                        // Validating the caller's record and registering the connection in the
                        // authority store happen together, under the store's own lock, so a
                        // revocation cannot land between the two and leave a connection admitted
                        // under authority that has already been withdrawn.
                        match self
                            .admit_connection(connection_id, &actor_id, peer, hello.client)
                            .await
                        {
                            Ok(()) => {}
                            Err(error) => {
                                let refusal = error_reply(
                                    RequestId::new(0),
                                    ErrorCode::PermissionDenied,
                                    error.to_string(),
                                );
                                let _ = writer.write_message(&refusal).await;
                                break;
                            }
                        }
                        negotiated = true;
                        origin = hello.origin;
                        let Ok(window) = self.issue_window(connection_id) else {
                            break;
                        };
                        ControlFrame::HelloAck(self.acknowledgement(
                            stated,
                            LocalRole::Controller,
                            window,
                            peer,
                        ))
                    } else {
                        error_reply(
                            RequestId::new(0),
                            ErrorCode::UnsupportedSchema,
                            format!("this host speaks protocol {stated}"),
                        )
                    }
                }
                ControlFrame::Request(request)
                    if negotiated && !crate::transfer::carries(kind, request.method.method()) =>
                {
                    error_reply(
                        request.request_id,
                        ErrorCode::PermissionDenied,
                        crate::transfer::WRONG_ENDPOINT,
                    )
                }
                ControlFrame::Request(request) if negotiated && Self::releases(&request) => {
                    // The attention store's reads carry session text and a session's description
                    // carries what a model wrote. Neither leaves this daemon except under the
                    // privacy fence it was read under: its ticket is checked before every write.
                    match self.authorised(connection_id) {
                        Ok(_) => match self.read_refused(&request) {
                            Some(refused) => refused,
                            None => {
                                let released = self.read_released(&actor_id, &request).await;
                                match self.authorised(connection_id) {
                                    Ok(_) => match self.read_refused(&request) {
                                        Some(refused) => refused,
                                        None => {
                                            // Held to the local owner's lease at every transport
                                            // write, as to the privacy fence.
                                            let method = request.method.method();
                                            let permitted = || {
                                                method.is_none_or(|method| {
                                                    self.local_hold(method).is_ok()
                                                })
                                            };
                                            let lease = crate::attention::LeaseHold {
                                                permitted: &permitted,
                                                refusal: self
                                                    .lease_ended_reply(request.request_id, method),
                                            };
                                            if self
                                                .attention
                                                .write_released_held(
                                                    writer,
                                                    kind,
                                                    released,
                                                    Some(&lease),
                                                )
                                                .await
                                                .is_err()
                                            {
                                                break;
                                            }
                                            continue;
                                        }
                                    },
                                    Err(error) => error_reply(
                                        request.request_id,
                                        ErrorCode::PermissionDenied,
                                        error.to_string(),
                                    ),
                                }
                            }
                        },
                        Err(error) => error_reply(
                            request.request_id,
                            ErrorCode::PermissionDenied,
                            error.to_string(),
                        ),
                    }
                }
                ControlFrame::Request(request) if negotiated => {
                    match self.authorised(connection_id) {
                        Ok(_) => match self.read_refused(&request) {
                            Some(refused) => refused,
                            None => {
                                let answer = self.read_method(&actor_id, &request, false).await;
                                // Checked again now the read has finished. A read that passed its
                                // check and then waited for the registry can complete after the
                                // authority behind it was withdrawn, and what the contract forbids
                                // is *serving* that state rather than reading it.
                                match self.authorised(connection_id) {
                                    Ok(_) => match self.read_refused(&request) {
                                        Some(refused) => refused,
                                        None => {
                                            if !self
                                                .write_answer(
                                                    writer,
                                                    kind,
                                                    &answer,
                                                    request.method.method(),
                                                    request.request_id,
                                                )
                                                .await
                                            {
                                                break;
                                            }
                                            continue;
                                        }
                                    },
                                    Err(error) => error_reply(
                                        request.request_id,
                                        ErrorCode::PermissionDenied,
                                        error.to_string(),
                                    ),
                                }
                            }
                        },
                        Err(error) => error_reply(
                            request.request_id,
                            ErrorCode::PermissionDenied,
                            error.to_string(),
                        ),
                    }
                }
                ControlFrame::Mutation(mutation) if negotiated => {
                    // The reply is written only by the sink, which this arm hands the connection's
                    // writer to for the one request.
                    if !self
                        .serve_mutation(
                            ReplySink::new(writer, kind),
                            &actor_id,
                            connection_id,
                            origin,
                            *mutation,
                        )
                        .await
                    {
                        break;
                    }
                    continue;
                }
                _ => error_reply(
                    RequestId::new(0),
                    ErrorCode::UnsupportedSchema,
                    "a local connection negotiates its version before anything else",
                ),
            };
            if writer.write_message(&reply).await.is_err() {
                break;
            }
        }
        Ok(())
    }

    /// Performs one mutation that arrived on a local connection and writes its reply, and says
    /// whether the connection goes on.
    ///
    /// The reply is written only by `sink`, which consumes it: a mutation on a stream of the wrong
    /// kind is declined, and every other reply is the one [`Self::perform_at`] made. The loop that
    /// serves the connection holds no writer for this request and no reply of its own.
    pub(super) async fn serve_mutation(
        self: &Arc<Self>,
        sink: ReplySink<'_>,
        actor_id: &ActorId,
        connection_id: ConnectionId,
        origin: Option<kr_protocol::local::BridgeOrigin>,
        mutation: MutationRequest,
    ) -> bool {
        let confirm = mutation.action_id;
        let request_id = mutation.request_id;
        let method = mutation.method.method();
        if !crate::transfer::carries(sink.kind(), method) {
            let reply = declined(self, Declined::WrongEndpoint, request_id);
            return sink.write(self, reply, method).await;
        }
        // Receipt time, before anything this daemon waits for.
        let received_at = self.clock.now();
        let reply = self
            .perform_at(actor_id, connection_id, origin, mutation, received_at)
            .await;
        // The acceptance reaches the caller here. A worker that is holding a close for this action
        // learns that it has, and only then starts signalling. A refusal made before anything ran
        // carries no result and is written as it is; the answer of a held method is written only
        // while the lease holds, asked again before every transport write, and a result that
        // waited for a worker or a store is withheld once the lease has ended.
        if !sink.write(self, reply, method).await {
            return false;
        }
        self.confirm_delivery(confirm).await;
        true
    }

    /// Admits one mutation as [`Self::perform_at`] does, for a request that has just arrived, for
    /// the tests that call the door without a connection.
    #[cfg(test)]
    pub(super) async fn perform(
        self: &Arc<Self>,
        actor_id: &ActorId,
        connection_id: ConnectionId,
        origin: Option<kr_protocol::local::BridgeOrigin>,
        mutation: MutationRequest,
    ) -> ControlFrame {
        // Receipt time, recorded before anything this daemon then waits for. Section 9 measures a
        // requested lifetime from when the request arrived, and the retained lookup below takes
        // the registry lock: sampling the clock after it would hand the request its whole lifetime
        // back after the wait.
        let received_at = self.clock.now();
        self.perform_at(actor_id, connection_id, origin, mutation, received_at)
            .await
            .into_frame()
    }

    /// Admits one mutation that arrived at `received_at` and performs it on an owner that outlives
    /// this connection.
    ///
    /// This door awaits the call in line, so the end of the control stream does not cancel it: the
    /// connection, and its registration, are retired only after the call has ended. A stop of the
    /// daemon does cancel it: the loop that serves the connection ends its task at this wait, and
    /// the connection's windows and registration are withdrawn at once, so an effect that has not
    /// yet committed is refused at its next check of the registration. The effect runs in its own
    /// task all the same, because dropping a future is a cancellation, destructors run and nothing
    /// after an outstanding `await` finishes, and a durable commit cannot be left half done by a
    /// task that is dropped. Dropping the handle this awaits does not stop that task; it only stops
    /// this connection hearing the answer.
    ///
    /// The reply says which it is: a refusal made before anything ran, which carries no result, or
    /// an answer, which does.
    pub(super) async fn perform_at(
        self: &Arc<Self>,
        actor_id: &ActorId,
        connection_id: ConnectionId,
        origin: Option<kr_protocol::local::BridgeOrigin>,
        mutation: MutationRequest,
        received_at: kr_transport::clock::ContinuousInstant,
    ) -> DoorReply {
        let request_id = mutation.request_id;
        if let Err(refusal) = self.authorised(connection_id) {
            return declined(self, Declined::Unauthorised(refusal), request_id);
        }
        let Some(method) = mutation.method.method() else {
            return declined(self, Declined::NotInRegistry, request_id);
        };
        // On a host that is exclusively organisation-managed the local owner answers to a
        // membership lease like a member, so a held method is refused here, before a retained
        // answer is looked for, once no lease is live.
        if let Err(refusal) = self.local_hold(method) {
            return declined(self, Declined::Lease(refusal), request_id);
        }
        // The arrival is recorded as soon as the door has the mutation, so that a copy that arrives
        // on another connection while this arrival looks for a retained answer, or reads the other
        // stores, knows that this one is there: it may be the first attempt, and about to write the
        // claim of its action. It is held until this arrival has ended, whatever it comes to.
        let mut arrival = self.arrive(actor_id, &mutation, method);
        // A retained action is answered before anything about a first admission is considered.
        // Section 9 makes the freshness window the thing that admits a *new* action; applying it to
        // a retry would refuse a caller its own completed result because its window has since been
        // replaced, and replacing the window of an action already submitted is not allowed either.
        //
        // Every store that retains an action here is asked in turn, and whichever answers, the
        // answer passes through the same guard. Finding a retained action takes a lock and can
        // wait for a blocking thread; what the contract forbids is *disclosing* a retained result
        // under authority that has since been withdrawn, so the check belongs where the answer is
        // about to be written rather than only where the lookup began.
        // The authority revision this mutation is admitted under, read here: beside the
        // registration check above and before the first thing this daemon waits for. The network
        // ingress reads its own in the same critical section as that check, and the two doors have
        // to agree. A revocation of somebody else's device advances the revision and leaves every
        // surviving registration stamped with the new one, so a door that read the revision after
        // a retained lookup, a lock or a task being scheduled would admit a mutation under an
        // authority the other door refuses the same mutation under. A retained answer is checked
        // against it, and so is every effect this door performs.
        let admitted = self.admitted_revision(connection_id).ok();
        // What every reply is told under: the connection the request arrived on and the revision it
        // was admitted under.
        let standing = Standing::new(self, connection_id, admitted, request_id);
        let mut retained = self.retained(actor_id, &mutation, method).await;
        if retained.is_none() && crate::transfer::TransferModule::serves(method) {
            retained = self.transfer.retained(actor_id, &mutation, method).await;
        }
        if retained.is_none() && crate::project::ProjectModule::serves(method) {
            retained = self.project.retained(actor_id, &mutation, method).await;
        }
        if retained.is_none() && crate::catalogue::CatalogueModule::serves(method) {
            retained = self.catalogue.retained(actor_id, &mutation, method).await;
        }
        if retained.is_none() && crate::changeset::ChangeSetModule::serves(method) {
            retained = self.changesets.retained(actor_id, &mutation, method).await;
        }
        if retained.is_none() && crate::automation::AutomationModule::serves(method) {
            retained = self
                .automation
                .retained(actor_id, &mutation, method, None)
                .await;
        }
        if retained.is_none() && crate::attention::AttentionModule::serves(method) {
            retained = self.attention.retained(
                &crate::attention::Caller::Owner,
                actor_id,
                &mutation,
                method,
            );
        }
        if retained.is_none() && net::methods::serves(method) {
            retained = self
                .pairing_retained(self.local_caller(actor_id), method, &mutation)
                .await
                .map(|outcome| outcome.respond(mutation.request_id));
        }
        #[cfg(feature = "testing")]
        self.after_the_retained_lookup.wait().await;
        if let Some(retained) = retained {
            return told(Settled::of(retained.copied()), &standing).await;
        }
        // A first admission spends an identifier no other method of this actor has spent, and holds
        // it until its effect has ended.
        let spending = match self.spend_the_identifier(actor_id, &mutation, method).await {
            Ok(spending) => spending,
            // The conflict says that another request spent the identifier, which is another
            // attempt's word. The search waited for a blocking task, so it is told only under the
            // authority this arrival still has, asked with the conflict in hand.
            Err(SpendError::Conflict(error)) => {
                let conflict = Given::fresh(respond(request_id, Err(error)));
                return told(Settled::of(conflict), &standing).await;
            }
            Err(SpendError::Failed(failed)) => {
                return declined(self, Declined::Spend(failed), request_id);
            }
        };
        let accepted = match self.check_envelope(connection_id, &mutation, method, received_at) {
            Ok(accepted) => Some(accepted),
            // A window that admits nothing says nothing about an action the host may already
            // hold. Section 9 keeps a receipt readable after the freshness that admitted it is
            // gone, and for a mutation this daemon forwards, the worker that owns the session is
            // the only thing that knows whether it holds one. So the mutation goes on with no
            // freshness at all: a retry finds its receipt there, and a first admission is refused
            // there for the same reason it would have been refused here.
            Err(error) if error.is_window_expired() && forwarded_to_worker(method) => None,
            // The same holds for an exact repeat of a transfer action that claimed an effect and
            // was interrupted before it settled. The repeat is the original request, window
            // included, and on a connection that did not issue that window, or on one where it has
            // expired, it admits nothing. The service finishes what the claim began and begins
            // nothing.
            Err(error)
                if error.is_window_expired() && crate::transfer::TransferModule::serves(method) =>
            {
                // Asked before the claim is, so that a first attempt that writes its claim and ends
                // between the two is read as its claim and not missed as an absent one.
                let another_holds = another_may_carry_it_out(&mut arrival).await;
                let mut settling = self.transfer.settles(actor_id, &mutation, method).await;
                // No claim while another arrival may carry the action out: that arrival may since
                // have been refused before it did anything, or have written its claim and ended.
                // Asked again, and the claim read again if it has gone, in that order, because a
                // claim only moves from absent to open to settled: an arrival that is gone has
                // left its claim, if it left one, where the second reading finds it.
                if matches!(settling, crate::transfer::Settling::No) && another_holds {
                    #[cfg(feature = "testing")]
                    self.after_a_copy_looked_for_a_claim.wait().await;
                    if another_may_carry_it_out(&mut arrival).await {
                        return the_attempt_that_holds_the_action(&standing, request_id).await;
                    }
                    settling = self.transfer.settles(actor_id, &mutation, method).await;
                }
                match settling {
                    crate::transfer::Settling::Open => None,
                    // The claim was settled between the lookup above and this one, by another copy
                    // of the action or by the sweep: what it recorded is the answer, under the
                    // check any retained answer is owed.
                    crate::transfer::Settling::Answered(answer) => {
                        return told(Settled::of(answer.copied()), &standing).await;
                    }
                    // No claim, and no arrival that may carry the action out: a first admission,
                    // which has no window.
                    crate::transfer::Settling::No => {
                        return declined(self, Declined::Envelope(error), request_id);
                    }
                }
            }
            // And for an exact repeat of a project action whose claim is open: its first attempt
            // may still be carrying the action out, and a refusal about a window says nothing was
            // done. The repeat is told what the service holds for its action, which for an open
            // claim is that what became of the action is not known. An action with no claim is a
            // first admission, and is refused for its window, unless another arrival may carry
            // the action out: a copy that arrives before the first attempt has written its claim
            // is told that what became of the action is not known.
            Err(error)
                if error.is_window_expired() && crate::project::ProjectModule::serves(method) =>
            {
                // Asked before the claim is, as for a transfer action above.
                let another_holds = another_may_carry_it_out(&mut arrival).await;
                let mut held = self.project.held_answer(actor_id, &mutation, method).await;
                // No claim while another arrival may carry the action out: asked again, and the
                // claim read again if it has gone, as for a transfer action above.
                if held.is_none() && another_holds {
                    #[cfg(feature = "testing")]
                    self.after_a_copy_looked_for_a_claim.wait().await;
                    if another_may_carry_it_out(&mut arrival).await {
                        return the_attempt_that_holds_the_action(&standing, request_id).await;
                    }
                    held = self.project.held_answer(actor_id, &mutation, method).await;
                }
                let Some(held) = held else {
                    return declined(self, Declined::Envelope(error), request_id);
                };
                return told(Settled::of(held.copied()), &standing).await;
            }
            Err(error) => return declined(self, Declined::Envelope(error), request_id),
        };
        // From here this arrival carries the action out, and a copy that finds no claim yet asks
        // whether it may.
        if let Some(arrival) = arrival.as_mut() {
            arrival.runs();
        }
        let controller = Arc::clone(self);
        let actor_id = actor_id.clone();
        let effect = tokio::spawn(async move {
            let _arrival = arrival;
            let _spending = spending;
            #[cfg(feature = "testing")]
            controller.before_a_door_effect.wait().await;
            controller
                .write_method(
                    &actor_id,
                    &mutation,
                    method,
                    connection_id,
                    origin,
                    accepted,
                    admitted,
                )
                .await
        });
        // The join error is the daemon's own word, and may follow an effect that ran.
        let settled = effect.await.unwrap_or_else(|_| {
            Settled::of(Given::fresh(error_reply(
                request_id,
                ErrorCode::OutcomeUnknown,
                "the daemon could not report what happened to this action",
            )))
        });
        told(settled, &standing).await
    }

    /// Returns the answer a retained installation action is owed.
    ///
    /// It runs before first-admission freshness, like every other retained action: a caller that
    /// reconnects and asks again about work it already submitted must get its own result rather
    /// than a refusal about a window that has since been replaced.
    async fn retained_installation(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Option<Recorded<ControlFrame>> {
        let installer = self.installer().ok()?;
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
        // Waiting for the lock takes time, and a retained result is a read of somebody's action:
        // the door asks the authority the caller still has once the lookups have ended.
        let _admission = self.agent_tools.lock().await;
        installer
            .retained(actor_id, mutation.action_id, &digest)
            .present()
            .map(|found| found.respond(mutation.request_id))
    }
}

/// The answer to a copy of an action that no claim answers while another arrival may carry the
/// action out: its first attempt has not written the claim and goes on to carry the action out, so
/// it may have been done by the time the copy asks again. It is a record of that attempt's claim,
/// and is told under the check any such answer is owed.
async fn the_attempt_that_holds_the_action(
    standing: &Standing<'_>,
    request_id: RequestId,
) -> DoorReply {
    let answer = respond(request_id, Err(ControllerError::attempt_still_running()));
    told(Settled::of(Given::copied(answer)), standing).await
}

/// Whether another arrival under the identifier may carry the action out, asked by a copy that is
/// refused for its window ([`Arrival::another_may_carry_it_out`]). A method that records no arrival
/// has no other.
async fn another_may_carry_it_out(arrival: &mut Option<Arrival>) -> bool {
    match arrival.as_mut() {
        Some(arrival) => arrival.another_may_carry_it_out().await,
        None => false,
    }
}

/// Returns whether this daemon forwards the method to the worker that owns the session.
///
/// It decides what a window refusal means. A mutation this daemon performs itself has its
/// retained action here, and a window that admits nothing has already been past it; one it
/// forwards has its retained action in the worker's journal, which only the worker can read.
const fn forwarded_to_worker(method: Method) -> bool {
    matches!(
        method,
        Method::SessionClose | Method::AgentPromptSubmit | Method::AgentPromptQueue
    )
}
