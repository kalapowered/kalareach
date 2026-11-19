//! This device's half of a call the host controls.
//!
//! A call on the host owner's own OpenAI key has no socket for this device to open: the host holds
//! the provider's side of the call, and this device reaches it through the host's own methods,
//! `voice.control` and `voice.context.send`. The device keeps the same state machine it keeps for a
//! managed call; what changes is how its words reach the model and how the host's news reaches it.
//!
//! # The heartbeat
//!
//! A heartbeat goes to the host every `beat`, the first at once, each under an action identifier of
//! its own: a repeat of an old one would be answered from nothing and prove nothing. The answer
//! carries the call's state and the news since the last item this device acknowledged, and the next
//! heartbeat acknowledges what arrived. A beat that is not answered within `miss_after`, or that
//! comes back as an error, is a miss. Two misses in a row are told to the person; an answer after
//! them takes the notice back. With no answer for `silent_after` the device ends its media, because
//! the host began to close the call when it stopped hearing from this device.
//!
//! # What the device sends
//!
//! The device decides which sentence goes to the model and when; the host writes the words. A
//! `note` names a [`VoiceNote`] and the delegation it is about, and `mute` carries the person's
//! microphone state. `heard` asks whether the host's own side channel heard a delegation that this
//! device's data channel delivered, and what offset it heard it at.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use kr_client::{ClientError, Session, Settled};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{ActionId, EnvironmentId, SessionId, VoiceSessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{CanonicalSet, Nullable, U64};
use kr_protocol::voice::VoiceDelegationId;
use kr_protocol::voice_host::{
    VoiceContextSendParams, VoiceContextSendResult, VoiceContextState, VoiceControlArm,
    VoiceControlParams, VoiceControlResult, VoiceEndReason, VoiceHostCallState, VoiceHostRefusal,
    VoiceNewsItem, VoiceNote,
};
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;

use crate::commands::{MUTATION_TTL, NoPreconditions};

/// How many news items wait for the owner to read them.
const NEWS_QUEUE: usize = 128;

/// The bounds a host control keeps.
#[derive(Clone, Copy, Debug)]
pub(super) struct HostLimits {
    /// Between heartbeats.
    pub beat: Duration,
    /// How long a heartbeat is given before it counts as a miss.
    pub miss_after: Duration,
    /// How long without an answer before the device ends its media.
    pub silent_after: Duration,
    /// How long a note, a mute, a question about a delegation or a context send is given.
    pub within: Duration,
}

/// Why a write to the host did not go through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum LinkError {
    /// Nothing was written: the request was not composed, or no window admitted it.
    NotSent,
    /// The request may have been written, and no answer of the method's shape came back.
    Unknown,
    /// The host answered with an error, in these words.
    Refused(String),
}

/// The pending answer of a write to the host.
pub(super) type LinkFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, LinkError>> + Send + 'a>>;

/// How the two host methods are written to the host: over the call's connection, or, for a case,
/// by a stand-in.
pub(super) trait HostLink: Send + Sync + 'static {
    /// Writes a `voice.control` under `action_id` and returns the host's answer.
    fn control<'a>(
        &'a self,
        action_id: ActionId,
        params: &'a VoiceControlParams,
    ) -> LinkFuture<'a, VoiceControlResult>;

    /// Writes a `voice.context.send` under `action_id` and returns the host's answer.
    fn send_context<'a>(
        &'a self,
        action_id: ActionId,
        params: &'a VoiceContextSendParams,
    ) -> LinkFuture<'a, VoiceContextSendResult>;
}

/// An action this device holds the book of until it settles it: dropped before it was settled, it
/// is settled on a task of its own, so that a write that was cut short leaves nothing unresolved
/// on the connection.
struct Settling {
    session: Arc<Session>,
    action_id: ActionId,
    settled: bool,
}

impl Settling {
    const fn new(session: Arc<Session>, action_id: ActionId) -> Self {
        Self {
            session,
            action_id,
            settled: false,
        }
    }

    async fn settle(&mut self) {
        self.session.settle(self.action_id).await;
        self.settled = true;
    }
}

impl Drop for Settling {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let (session, action_id) = (Arc::clone(&self.session), self.action_id);
            runtime.spawn(async move { session.settle(action_id).await });
        }
    }
}

/// The host's connection, written to as a paired device writes any action. The connection can be
/// replaced while the call runs, and the next write goes over the one that reaches the host.
pub(super) struct SessionLink {
    session: std::sync::Mutex<Arc<Session>>,
    environment_id: EnvironmentId,
}

impl SessionLink {
    pub(super) fn new(session: Arc<Session>, environment_id: EnvironmentId) -> Self {
        Self {
            session: std::sync::Mutex::new(session),
            environment_id,
        }
    }

    /// Writes over `session` from now on.
    pub(super) fn use_session(&self, session: Arc<Session>) {
        *self
            .session
            .lock()
            .expect("the session lock is not poisoned") = session;
    }

    async fn write<P, T>(
        &self,
        method: Method,
        action_id: ActionId,
        params: &P,
    ) -> std::result::Result<T, LinkError>
    where
        P: serde::Serialize + Sync,
        T: kr_protocol::wire::WireMessage,
    {
        let session = Arc::clone(
            &self
                .session
                .lock()
                .expect("the session lock is not poisoned"),
        );
        let composed = session
            .compose(
                method,
                action_id,
                ActionTarget::environment(self.environment_id),
                None,
                &NoPreconditions {},
                params,
                MUTATION_TTL,
            )
            .await
            .map_err(|_| LinkError::NotSent)?;
        // The device never repeats one of these under the same action, and an action it keeps
        // unsettled is counted against it: it is settled whatever the host answered, and also
        // when a time-out drops this write before the host answers.
        let mut settling = Settling::new(Arc::clone(&session), action_id);
        let sent = session.send(&composed).await;
        settling.settle().await;
        match sent {
            Ok(Settled::Result(value)) => value.to_typed::<T>().map_err(|_| LinkError::Unknown),
            // A receipt shows that the host holds the action, never what became of it.
            Ok(Settled::Receipt(_)) => Err(LinkError::Unknown),
            Err(ClientError::Host(error)) => Err(LinkError::Refused(error.message)),
            Err(
                ClientError::Cbor(_)
                | ClientError::NoActionWindow
                | ClientError::Misdirected { .. }
                | ClientError::StillAccounting
                | ClientError::TooManyOutstandingMutations { .. }
                | ClientError::TooManyUnresolvedActions { .. },
            ) => Err(LinkError::NotSent),
            Err(_) => Err(LinkError::Unknown),
        }
    }
}

impl HostLink for SessionLink {
    fn control<'a>(
        &'a self,
        action_id: ActionId,
        params: &'a VoiceControlParams,
    ) -> LinkFuture<'a, VoiceControlResult> {
        Box::pin(self.write(Method::VoiceControl, action_id, params))
    }

    fn send_context<'a>(
        &'a self,
        action_id: ActionId,
        params: &'a VoiceContextSendParams,
    ) -> LinkFuture<'a, VoiceContextSendResult> {
        Box::pin(self.write(Method::VoiceContextSend, action_id, params))
    }
}

/// What a host control tells its owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum HostNews {
    /// The host answered a heartbeat. The first time, and after every outage.
    Attached {
        /// True when an earlier answer was followed by a silence.
        reattached: bool,
    },
    /// Two heartbeats in a row were not answered.
    Detached,
    /// The host's own side channel heard a delegation.
    Delegation {
        delegation_id: String,
        offset_ms: u64,
    },
    /// The provider refused a write the host had admitted.
    LateRefusal {
        action_id: ActionId,
        reason: VoiceHostRefusal,
    },
    /// Where a context send stands.
    Context {
        action_id: ActionId,
        appended: u32,
        of: u32,
        unconfirmed: u32,
        state: VoiceContextState,
    },
    /// The host's news queue overflowed: what the call did is not all known.
    Dropped,
    /// The control is over. Nothing follows.
    Ended(HostEnding),
}

/// How a host control ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostEnding {
    /// The host said the call is over, and why.
    Reason(VoiceEndReason),
    /// The host does not know the call for this device: it was restarted, or the call is another
    /// device's.
    NotKnown(VoiceHostRefusal),
    /// No heartbeat was answered for as long as the host waits before it begins to close the call.
    Silent,
}

/// What a host control tells, read by its owner.
pub(super) struct HostEvents {
    news: mpsc::Receiver<HostNews>,
}

impl HostEvents {
    /// The next piece of news, or nothing once the control is over and everything it told has been
    /// read.
    pub(super) async fn next(&mut self) -> Option<HostNews> {
        self.news.recv().await
    }
}

/// Why a write the owner asked of the host did not go through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HostSendError {
    /// Nothing reached the host.
    NotSent,
    /// The write may have reached the host, and no answer came.
    Unanswered,
    /// The host took no part of it, for this reason when it gave one.
    Refused(Option<VoiceHostRefusal>),
}

/// What the host's sender took of a context send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ContextQueued {
    /// The send's identity, which the news about it names.
    pub action_id: ActionId,
    /// How many appends the host's sender will write.
    pub appends: u32,
}

/// A call's control at the host, from the side that uses it. Cheap to clone.
#[derive(Clone)]
pub(super) struct HostControl {
    link: Arc<dyn HostLink>,
    voice_session_id: VoiceSessionId,
    within: Duration,
    stop: Arc<Notify>,
}

impl std::fmt::Debug for HostControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostControl")
            .finish_non_exhaustive()
    }
}

impl HostControl {
    /// Opens a call's control at the host: the first heartbeat goes at once. Must be called inside
    /// a Tokio runtime.
    pub(super) fn open(
        link: Arc<dyn HostLink>,
        voice_session_id: VoiceSessionId,
        limits: HostLimits,
    ) -> (Self, HostEvents) {
        let (told, news) = mpsc::channel(NEWS_QUEUE);
        let stop = Arc::new(Notify::new());
        tokio::spawn(heartbeats(
            Arc::clone(&link),
            voice_session_id,
            limits,
            told,
            Arc::clone(&stop),
        ));
        (
            Self {
                link,
                voice_session_id,
                within: limits.within,
                stop,
            },
            HostEvents { news },
        )
    }

    /// Ends the control. Nothing more is told and no heartbeat is sent; the call is ended by the
    /// stop the owner sends the host.
    pub(super) fn stop(&self) {
        self.stop.notify_one();
    }

    async fn ask(
        &self,
        arm: VoiceControlArm,
    ) -> std::result::Result<VoiceControlResult, HostSendError> {
        let params = VoiceControlParams {
            voice_session_id: self.voice_session_id,
            arm,
        };
        let action_id = ActionId::new(kr_ipc::new_uuid());
        match tokio::time::timeout(self.within, self.link.control(action_id, &params)).await {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(LinkError::NotSent)) => Err(HostSendError::NotSent),
            Ok(Err(LinkError::Refused(_))) => Err(HostSendError::Refused(None)),
            Ok(Err(LinkError::Unknown)) | Err(_) => Err(HostSendError::Unanswered),
        }
    }

    /// Tells the model the fixed sentence `note` names, about `delegation` for a note that is about
    /// one. The host writes the words.
    pub(super) async fn note(
        &self,
        note: VoiceNote,
        delegation: Option<&str>,
    ) -> std::result::Result<(), HostSendError> {
        let delegation_id = match delegation {
            Some(id) => {
                Nullable::some(VoiceDelegationId::new(id).map_err(|_| HostSendError::NotSent)?)
            }
            None => Nullable::null(),
        };
        match self
            .ask(VoiceControlArm::Note {
                note,
                delegation_id,
            })
            .await?
        {
            VoiceControlResult::Admitted { .. } => Ok(()),
            VoiceControlResult::Refused { reason } => Err(HostSendError::Refused(Some(reason))),
            _ => Err(HostSendError::Unanswered),
        }
    }

    /// Tells the host the person's microphone state, which it writes to the provider as advice.
    pub(super) async fn mute(&self, muted: bool) -> std::result::Result<(), HostSendError> {
        match self.ask(VoiceControlArm::Mute { muted }).await? {
            VoiceControlResult::Admitted { .. } => Ok(()),
            VoiceControlResult::Refused { reason } => Err(HostSendError::Refused(Some(reason))),
            _ => Err(HostSendError::Unanswered),
        }
    }

    /// Asks whether the host's own side channel heard the delegation, and where: `Some(offset)` when
    /// it did and none when it did not (asking again is a new question).
    pub(super) async fn heard(
        &self,
        delegation: &str,
    ) -> std::result::Result<Option<u64>, HostSendError> {
        let delegation_id =
            VoiceDelegationId::new(delegation).map_err(|_| HostSendError::NotSent)?;
        match self.ask(VoiceControlArm::Heard { delegation_id }).await? {
            VoiceControlResult::Heard { offset_ms } => Ok(Some(offset_ms.get())),
            VoiceControlResult::NotHeard => Ok(None),
            VoiceControlResult::Refused { reason } => Err(HostSendError::Refused(Some(reason))),
            _ => Err(HostSendError::Unanswered),
        }
    }

    /// Asks the host to send the call the context of `session_id`, which it selects, caps and
    /// writes at its own pace, under `action_id`, which the caller made. The answer is given at
    /// once; progress arrives as news naming the action, and applies whether or not the answer
    /// does.
    pub(super) async fn send_context(
        &self,
        action_id: ActionId,
        session_id: SessionId,
        delegation: Option<&str>,
    ) -> std::result::Result<ContextQueued, HostSendError> {
        let delegation_id = match delegation {
            Some(id) => {
                Nullable::some(VoiceDelegationId::new(id).map_err(|_| HostSendError::NotSent)?)
            }
            None => Nullable::null(),
        };
        let params = VoiceContextSendParams {
            voice_session_id: self.voice_session_id,
            session_id,
            selected: CanonicalSet::new(),
            delegation_id,
        };
        match tokio::time::timeout(self.within, self.link.send_context(action_id, &params)).await {
            Ok(Ok(VoiceContextSendResult::Queued { appends })) => {
                Ok(ContextQueued { action_id, appends })
            }
            Ok(Ok(VoiceContextSendResult::Refused { reason })) => {
                Err(HostSendError::Refused(Some(reason)))
            }
            Ok(Err(LinkError::NotSent)) => Err(HostSendError::NotSent),
            Ok(Err(LinkError::Refused(_))) => Err(HostSendError::Refused(None)),
            Ok(Err(LinkError::Unknown)) | Err(_) => Err(HostSendError::Unanswered),
        }
    }
}

/// Sends the heartbeats of one call, and tells what the host answered, until the call is over.
async fn heartbeats(
    link: Arc<dyn HostLink>,
    voice_session_id: VoiceSessionId,
    limits: HostLimits,
    told: mpsc::Sender<HostNews>,
    stop: Arc<Notify>,
) {
    // The last news item this device received, which each heartbeat acknowledges.
    let mut after_seq = 0_u64;
    let mut missed = 0_u32;
    let mut answered_before = false;
    let mut detached = false;
    let mut last_heard = Instant::now();
    loop {
        let began = Instant::now();
        let params = VoiceControlParams {
            voice_session_id,
            arm: VoiceControlArm::Heartbeat {
                after_seq: U64::new(after_seq),
            },
        };
        let action_id = ActionId::new(kr_ipc::new_uuid());
        let answer = tokio::select! {
            () = stop.notified() => return,
            () = tokio::time::sleep_until(last_heard + limits.silent_after) => {
                let _ = told.send(HostNews::Ended(HostEnding::Silent)).await;
                return;
            }
            answer = tokio::time::timeout(limits.miss_after, link.control(action_id, &params)) => answer,
        };
        match answer {
            Ok(Ok(VoiceControlResult::Heartbeat {
                state,
                news,
                dropped,
                ..
            })) => {
                missed = 0;
                last_heard = Instant::now();
                if !answered_before || detached {
                    let reattached = answered_before;
                    answered_before = true;
                    detached = false;
                    if told.send(HostNews::Attached { reattached }).await.is_err() {
                        return;
                    }
                }
                if dropped && told.send(HostNews::Dropped).await.is_err() {
                    return;
                }
                let mut ended = false;
                for item in news {
                    let seq = item.seq.get();
                    // News the device already has is not told twice.
                    if seq <= after_seq {
                        continue;
                    }
                    after_seq = seq;
                    let item = match item.item {
                        VoiceNewsItem::Delegation {
                            delegation_id,
                            offset_ms,
                        } => HostNews::Delegation {
                            delegation_id: delegation_id.as_str().to_owned(),
                            offset_ms: offset_ms.get(),
                        },
                        VoiceNewsItem::LateRefusal { action_id, reason } => {
                            HostNews::LateRefusal { action_id, reason }
                        }
                        VoiceNewsItem::Context {
                            action_id,
                            appended,
                            of,
                            unconfirmed,
                            state,
                        } => HostNews::Context {
                            action_id,
                            appended,
                            of,
                            unconfirmed,
                            state,
                        },
                        VoiceNewsItem::Ended { reason } => {
                            ended = true;
                            HostNews::Ended(HostEnding::Reason(reason))
                        }
                    };
                    if told.send(item).await.is_err() {
                        return;
                    }
                }
                if let VoiceHostCallState::Closed { reason } = state
                    && !ended
                {
                    let _ = told.send(HostNews::Ended(HostEnding::Reason(reason))).await;
                    return;
                }
                if ended {
                    return;
                }
            }
            // The host does not know the call for this device: nothing more will be answered.
            Ok(Ok(VoiceControlResult::Refused { reason })) => {
                let _ = told
                    .send(HostNews::Ended(HostEnding::NotKnown(reason)))
                    .await;
                return;
            }
            // An error, an answer of another shape and no answer in time are all a miss.
            Ok(Ok(_) | Err(_)) | Err(_) => {
                missed += 1;
                if missed >= 2 && !detached {
                    detached = true;
                    if told.send(HostNews::Detached).await.is_err() {
                        return;
                    }
                }
            }
        }
        tokio::select! {
            () = stop.notified() => return,
            () = tokio::time::sleep_until(last_heard + limits.silent_after) => {
                let _ = told.send(HostNews::Ended(HostEnding::Silent)).await;
                return;
            }
            () = tokio::time::sleep_until(began + limits.beat) => {}
        }
    }
}

#[cfg(test)]
mod tests;
