//! The host's call object for a call on the owner's own provider account.
//!
//! The provider's side channel belongs to the provider's tasks; this is what the host decides on
//! top of it. A paired device reaches a call here through `voice.control`: its heartbeat, its mute,
//! the fixed sentences it owes the model and its question whether a delegation was heard. The
//! device decides which sentence goes and when. The host checks that the sentence is true by its
//! own record, writes the words, and keeps the news the device missed until the device says it has
//! it.
//!
//! Nothing here reads a clock or waits on a timer: every call takes the time it is asked at, so a
//! case that judges a delay moves time itself.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use kr_client::services::host_call::HostFuture;
use kr_client::services::host_call::{
    HostCallControl, HostCallEvent, SidebandEnd, SidebandState, WriteRefusal,
};
use kr_client::services::voice::{VoiceCommand, VoiceContextFrame};
use kr_client::services::voice_pacing::{MAX_START_APPENDS, call_start_appends};
use kr_protocol::ids::{ActionId, DeviceId, VoiceSessionId};
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::voice::{
    VoiceContextSelection, VoiceDelegateParams, VoiceDelegateResult, VoiceDelegationOutcome,
};
use kr_protocol::voice_host::{
    HOST_CLIENT_ABSENT_SECONDS, HOST_HEARD_WAIT_MS, HOST_HEARTBEAT_SECONDS, HOST_NEWS_LIMIT,
    HOST_PERFORMED_WORDS_BYTES, HostNote, NotePhase, VoiceContextSendParams,
    VoiceContextSendResult, VoiceContextState, VoiceContextStop, VoiceControlResult,
    VoiceEndReason, VoiceHostCallState, VoiceHostRefusal, VoiceNews, VoiceNewsItem, VoiceNote,
    VoiceProviderClose,
};
use tokio::time::Instant;

/// The most calls whose final status the host keeps after they end.
pub const FINAL_STATUS_RECORDS: usize = 16;

/// How long the host keeps a call's final status after it ends, unless the device acknowledges it.
pub const FINAL_STATUS_KEEP_MS: u64 = 10 * 60 * 1_000;

/// How long a call whose end is recorded waits for its side channel to report the close before the
/// host tells the end as it stands, with the close not confirmed. A threshold, not a deadline: the
/// next tick or heartbeat after it applies it. The longest close the client runs on its own takes
/// about 35.5 seconds, so a close that is still unreported after this long is one the host could
/// not confirm.
pub const FINAL_STATUS_CLOSE_WAIT_MS: u64 = 60_000;

/// The most delegations a call remembers.
const DELEGATIONS_KEPT: usize = 64;

/// The most writes a call remembers having admitted, so a late refusal can name its action.
const WRITES_KEPT: usize = 64;

/// Missed heartbeats after which the model is told the phone has gone quiet: two beats and a
/// margin for the one in flight.
const SILENT_AFTER_MS: u64 = 2 * HOST_HEARTBEAT_SECONDS as u64 * 1_000 + 5_000;

/// What a call kept for a device that comes back after it ended. States, offsets and counts, and
/// no content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalStatus {
    /// The call it is about.
    pub voice_session_id: VoiceSessionId,
    /// The one device it is answered to.
    pub device_id: DeviceId,
    /// What ended the call.
    pub reason: VoiceEndReason,
    /// Whether the provider's close of the call was confirmed.
    pub provider_close: VoiceProviderClose,
    /// The news the device had not acknowledged, at most [`HOST_NEWS_LIMIT`].
    pub news: Vec<VoiceNews>,
    /// The sequence number of the last item, including the `ended` one.
    pub last_seq: u64,
}

/// What the host's record says one delegation became.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelegationKind {
    /// The host performed it.
    Performed,
    /// The host admitted it and did not say it ran.
    Admitted,
    /// The host refused it.
    Refused,
}

/// What the host recorded when `voice.delegate` answered: the request, in memory, and the answer.
///
/// The request is kept so that a note about a performed delegation can read the result again under
/// the grants as they stand then. It holds what the person said and is never written to disk or
/// to the provider; the host keeps at most [`DELEGATIONS_KEPT`] of them for the life of the call.
#[derive(Clone, Debug)]
pub struct DelegationRecord {
    /// The action the delegation was submitted under.
    pub delegate_action_id: ActionId,
    /// What the device submitted.
    pub params: VoiceDelegateParams,
    /// What the host answered.
    pub kept: VoiceDelegateResult,
}

impl DelegationRecord {
    /// What the delegation became, as far as a note about its outcome is concerned.
    #[must_use]
    pub const fn kind(&self) -> DelegationKind {
        match self.kept.outcome {
            VoiceDelegationOutcome::Performed { .. } => DelegationKind::Performed,
            VoiceDelegationOutcome::Admitted { .. } => DelegationKind::Admitted,
            VoiceDelegationOutcome::ConfirmationRequired { .. }
            | VoiceDelegationOutcome::Refused { .. } => DelegationKind::Refused,
        }
    }
}

/// What a note about a performed delegation needs from outside the call: the summary, read again
/// under the grants, the history bound and privacy mode as they stand now.
pub trait NoteSupport: Send + Sync {
    /// The host's clock now, in milliseconds, which the call's deadline is decided on.
    fn now_ms(&self) -> u64;

    /// Reads the performed delegation's summary again.
    ///
    /// # Errors
    ///
    /// Returns [`VoiceHostRefusal::OutsideGrant`] when a grant or the history bound no longer
    /// allows the read, and [`VoiceHostRefusal::Privacy`] when privacy mode moved.
    fn fresh_summary<'a>(
        &'a self,
        record: &'a DelegationRecord,
    ) -> kr_client::services::host_call::HostFuture<'a, Result<String, VoiceHostRefusal>>;

    /// Checks again, just before the words are written, that the grants, the history bound and
    /// privacy mode still allow what [`Self::fresh_summary`] read. Reads nothing.
    ///
    /// # Errors
    ///
    /// The same refusals as [`Self::fresh_summary`].
    fn allowed_now<'a>(
        &'a self,
        record: &'a DelegationRecord,
    ) -> kr_client::services::host_call::HostFuture<'a, Result<(), VoiceHostRefusal>>;
}

/// How long a context send waits for the provider to acknowledge one append before it stops.
pub const SEND_ACKNOWLEDGEMENT_WAIT: Duration = Duration::from_secs(15);

/// A selection of context, and what it was selected under.
#[derive(Clone, Debug)]
pub struct ContextSelected {
    /// The selection the send carries.
    pub selection: VoiceContextSelection,
    /// The history bound the two grants allowed when it was selected, in UTC milliseconds.
    pub lower_bound_ms: Option<u64>,
    /// Privacy mode as it stood when the read began.
    pub decided: crate::privacy::Published,
}

/// What the sender of a call's context needs from outside the call.
pub trait SendSupport: Send + Sync {
    /// The time the send's own decisions are made on.
    fn now_ms(&self) -> u64;

    /// Selects what the send carries, under the device's own scope, so that privacy mode did not
    /// move during the read.
    ///
    /// # Errors
    ///
    /// The refusal a device is told: a grant that no longer reaches the session is
    /// [`VoiceHostRefusal::OutsideGrant`] and privacy mode that kept moving is
    /// [`VoiceHostRefusal::Privacy`].
    fn select<'a>(
        &'a self,
        params: &'a VoiceContextSendParams,
    ) -> HostFuture<'a, Result<ContextSelected, VoiceHostRefusal>>;

    /// Looks again, before one append, at what allows the send: the voice session still reaches
    /// the session, both grants permit a briefing, the history bound has not narrowed and privacy
    /// mode has not moved. Reads nothing.
    ///
    /// # Errors
    ///
    /// What stopped the send.
    fn still_allowed<'a>(
        &'a self,
        params: &'a VoiceContextSendParams,
        selected: &'a ContextSelected,
    ) -> HostFuture<'a, Result<(), VoiceContextStop>>;
}

/// Where a provider's answer to one write stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ack {
    Waiting,
    Acknowledged,
    Refused,
}

/// How far the one send of a call has come.
#[derive(Clone, Copy, Debug)]
struct SendProgress {
    action_id: ActionId,
    of: u32,
    appended: u32,
    unconfirmed: u32,
    /// Whether an append is written and not yet answered.
    in_flight: bool,
}

/// What a side channel's own end says: the reason, and whether the provider's close is confirmed.
/// The provider's own word that the call closed, and a hang-up the provider confirmed, are
/// confirmations; a channel that was lost and then hung up is not.
const fn closing_of(end: SidebandEnd) -> (VoiceEndReason, VoiceProviderClose) {
    match end {
        SidebandEnd::ProviderClosed => (
            VoiceEndReason::ProviderClosed,
            VoiceProviderClose::Confirmed,
        ),
        SidebandEnd::HostClosed => (VoiceEndReason::Stop, VoiceProviderClose::Confirmed),
        SidebandEnd::Lost => (
            VoiceEndReason::SidebandLost,
            VoiceProviderClose::Unconfirmed,
        ),
    }
}

/// The stop a call's end is for a send that was still running.
const fn stop_of(reason: VoiceEndReason) -> VoiceContextStop {
    match reason {
        VoiceEndReason::Stop | VoiceEndReason::Silence => VoiceContextStop::Stop,
        VoiceEndReason::Deadline => VoiceContextStop::Deadline,
        VoiceEndReason::Revocation | VoiceEndReason::CredentialRemoved => {
            VoiceContextStop::Revocation
        }
        VoiceEndReason::ProviderClosed | VoiceEndReason::SidebandLost => {
            VoiceContextStop::SidebandLost
        }
    }
}

/// What one delegation has been told to the model.
#[derive(Debug, Default)]
struct Told {
    sentences: BTreeSet<VoiceNote>,
    finished: bool,
}

/// An end the host recorded, and when.
#[derive(Clone, Copy, Debug)]
struct RecordedEnd {
    reason: VoiceEndReason,
    at_ms: u64,
}

#[derive(Debug)]
struct CallState {
    next_seq: u64,
    news: VecDeque<VoiceNews>,
    dropped_through: u64,
    last_beat_ms: u64,
    /// Whether the model was told, and the write was accepted, that the phone is silent.
    silent_told: bool,
    /// Whether the model is owed the note that the phone is back, because it was told the phone
    /// was silent and the note that it is back is not yet written. A writer claims it under the
    /// lock before its write awaits, and sets it again when the write is not done with.
    back_owed: bool,
    delegations: BTreeMap<String, DelegationRecord>,
    told: BTreeMap<Option<String>, Told>,
    call_notes: BTreeSet<VoiceNote>,
    writes: VecDeque<(String, ActionId)>,
    write_count: u64,
    /// The end the host recorded, from the first request to end the call or the first report of
    /// the side channel. The first one stands.
    ended: Option<RecordedEnd>,
    /// The call's final status, built in the locked step that settles the call: the call is
    /// settled once its side channel has reported the close, or the wait for the report is over.
    /// It is kept here until the registry holds it, so a heartbeat that meets the settlement
    /// answers from it.
    settled: Option<Kept>,
    /// The send of context that runs now, at most one.
    sending: Option<SendProgress>,
    /// What the provider said of the appends of that send.
    acks: BTreeMap<String, Ack>,
}

/// One call on the owner's own key, as the host holds it.
pub struct HostCall {
    voice_session_id: VoiceSessionId,
    device_id: DeviceId,
    closes_at_ms: u64,
    control: Arc<dyn HostCallControl>,
    state: Mutex<CallState>,
    /// Told when the provider answers a write, when the channel changes state and when the call
    /// ends, so the sender looks again.
    progress: tokio::sync::Notify,
    calls: Weak<Shared>,
    /// Where this module's own tests stop a settlement after the call's own record is made and
    /// before the registry takes the status.
    #[cfg(test)]
    between_the_locks: crate::attention::Pause,
}

impl std::fmt::Debug for HostCall {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostCall")
            .field("voice_session_id", &self.voice_session_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
struct Kept {
    status: FinalStatus,
    ended_ms: u64,
}

/// What a call answers to a heartbeat, and whether the answer took the last of its final status.
struct Answer {
    result: VoiceControlResult,
    /// Whether the call is settled and the device has acknowledged its last item.
    final_acknowledged: bool,
}

#[derive(Default)]
struct Registry {
    calls: BTreeMap<VoiceSessionId, Arc<HostCall>>,
    finals: VecDeque<Kept>,
}

struct Shared {
    registry: Mutex<Registry>,
}

/// The calls the host holds on the owner's own key, and what it kept of the ones that ended.
#[derive(Clone)]
pub struct HostCalls {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for HostCalls {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HostCalls")
    }
}

impl Default for HostCalls {
    fn default() -> Self {
        Self::new()
    }
}

impl HostCalls {
    /// A registry that holds no call.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                registry: Mutex::new(Registry::default()),
            }),
        }
    }

    fn registry(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.shared.registry.lock().expect("the host call registry")
    }

    /// Takes a call the provider started into this registry and listens to its side channel.
    pub fn register(
        &self,
        voice_session_id: VoiceSessionId,
        device_id: DeviceId,
        started_ms: u64,
        closes_at_ms: u64,
        control: Arc<dyn HostCallControl>,
    ) -> Arc<HostCall> {
        let call = Arc::new(HostCall {
            voice_session_id,
            device_id,
            closes_at_ms,
            control: Arc::clone(&control),
            state: Mutex::new(CallState {
                next_seq: 1,
                news: VecDeque::new(),
                dropped_through: 0,
                last_beat_ms: started_ms,
                silent_told: false,
                back_owed: false,
                delegations: BTreeMap::new(),
                told: BTreeMap::new(),
                call_notes: BTreeSet::new(),
                writes: VecDeque::new(),
                write_count: 0,
                ended: None,
                settled: None,
                sending: None,
                acks: BTreeMap::new(),
            }),
            progress: tokio::sync::Notify::new(),
            calls: Arc::downgrade(&self.shared),
            #[cfg(test)]
            between_the_locks: crate::attention::Pause::default(),
        });
        self.registry()
            .calls
            .insert(voice_session_id, Arc::clone(&call));
        let weak = Arc::downgrade(&call);
        control.listen(Arc::new(move |event| {
            if let Some(call) = weak.upgrade() {
                call.on_event(event);
            }
        }));
        // A channel that closed before the listener was set told nobody: look once.
        call.settle_if_due(started_ms);
        call
    }

    /// The call a device controls, or why it may not.
    ///
    /// # Errors
    ///
    /// [`VoiceHostRefusal::UnknownCall`] when the host holds no such call and kept no final status
    /// for it, [`VoiceHostRefusal::NotThisDevice`] when it is another device's, and
    /// [`VoiceHostRefusal::Closing`] when the host recorded the call's end and its close is not
    /// settled yet: such a call answers a heartbeat and nothing else.
    pub fn of_device(
        &self,
        voice_session_id: VoiceSessionId,
        device_id: DeviceId,
    ) -> Result<Arc<HostCall>, VoiceHostRefusal> {
        let call = {
            let registry = self.registry();
            match registry.calls.get(&voice_session_id) {
                Some(call) if call.device_id == device_id => Arc::clone(call),
                Some(_) => return Err(VoiceHostRefusal::NotThisDevice),
                None => return Err(VoiceHostRefusal::UnknownCall),
            }
        };
        if call.state().ended.is_some() {
            return Err(VoiceHostRefusal::Closing);
        }
        Ok(call)
    }

    /// Records that a call is ending, and why. The first reason stands: a call ends once.
    ///
    /// The call stays held, and answers `closing`, until its side channel reports the close. Its
    /// final status is then built and kept for [`FINAL_STATUS_KEEP_MS`], with the close confirmed
    /// or not as the channel reported it. A close the channel has not reported
    /// [`FINAL_STATUS_CLOSE_WAIT_MS`] after the end is told as it stands at the next tick or
    /// heartbeat. Called before the call's grant is revoked.
    pub fn end(&self, voice_session_id: VoiceSessionId, reason: VoiceEndReason, now_ms: u64) {
        let call = self.registry().calls.get(&voice_session_id).cloned();
        if let Some(call) = call {
            call.record_end(reason, now_ms);
            call.settle_if_due(now_ms);
        }
    }

    /// Answers a heartbeat.
    ///
    /// A call that is held answers its state and its news. A call whose end is recorded answers
    /// `closing` until its close settles, and the heartbeat that finds it settled answers
    /// `closed`, with the matching `ended` item, in the same reply. A call that ended answers
    /// `closed` from the final status, to its own device alone, until the device acknowledges the
    /// `ended` item or the record is [`FINAL_STATUS_KEEP_MS`] old. After that it is unknown.
    #[must_use]
    pub fn heartbeat(
        &self,
        voice_session_id: VoiceSessionId,
        device_id: DeviceId,
        after_seq: u64,
        now_ms: u64,
    ) -> VoiceControlResult {
        {
            let mut registry = self.registry();
            registry
                .finals
                .retain(|kept| now_ms.saturating_sub(kept.ended_ms) < FINAL_STATUS_KEEP_MS);
            if let Some(call) = registry.calls.get(&voice_session_id) {
                if call.device_id != device_id {
                    return refused(VoiceHostRefusal::NotThisDevice);
                }
                let call = Arc::clone(call);
                drop(registry);
                call.settle_if_due(now_ms);
                let answer = call.heartbeat(after_seq, now_ms);
                if answer.final_acknowledged {
                    // The status may not be in the registry yet, when the settling thread has not
                    // handed it over: it is then kept until its time is up.
                    self.registry()
                        .finals
                        .retain(|kept| kept.status.voice_session_id != voice_session_id);
                }
                return answer.result;
            }
            let Some(at) = registry
                .finals
                .iter()
                .position(|kept| kept.status.voice_session_id == voice_session_id)
            else {
                return refused(VoiceHostRefusal::UnknownCall);
            };
            if registry.finals[at].status.device_id != device_id {
                return refused(VoiceHostRefusal::NotThisDevice);
            }
            let status = registry.finals[at].status.clone();
            let news: Vec<VoiceNews> = status
                .news
                .iter()
                .filter(|item| item.seq.get() > after_seq)
                .cloned()
                .collect();
            if after_seq >= status.last_seq {
                registry.finals.remove(at);
            }
            VoiceControlResult::Heartbeat {
                state: VoiceHostCallState::Closed {
                    reason: status.reason,
                    provider_close: status.provider_close,
                },
                remaining_seconds: 0,
                news,
                dropped: false,
            }
        }
    }

    /// The calls whose phone has not been heard from for [`HOST_CLIENT_ABSENT_SECONDS`]: the
    /// caller begins their closure. A phone silent for two beats is told to the model, once. A
    /// call whose side channel reported its close, or whose wait for the report is over, is
    /// settled first.
    pub async fn tick(&self, now_ms: u64) -> Vec<VoiceSessionId> {
        let calls: Vec<Arc<HostCall>> = self.registry().calls.values().cloned().collect();
        // Settles every call whose close is reported or whose wait is over, before any await.
        for call in &calls {
            call.settle_if_due(now_ms);
        }
        let mut absent = Vec::new();
        for call in calls {
            if call.tick(now_ms).await {
                absent.push(call.voice_session_id);
            }
        }
        absent
    }

    /// How many calls the host holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.registry().calls.len()
    }

    /// The voice session of each call the host holds.
    #[must_use]
    pub fn voice_session_ids(&self) -> Vec<VoiceSessionId> {
        self.registry().calls.keys().copied().collect()
    }

    /// Whether the host holds no call.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many final statuses the host keeps.
    #[must_use]
    pub fn kept_final_statuses(&self) -> usize {
        self.registry().finals.len()
    }
}

fn refused(reason: VoiceHostRefusal) -> VoiceControlResult {
    VoiceControlResult::Refused { reason }
}

impl HostCall {
    fn state(&self) -> std::sync::MutexGuard<'_, CallState> {
        self.state.lock().expect("the host call's state")
    }

    /// The device the call belongs to.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The call's own deadline, in milliseconds since the epoch.
    #[must_use]
    pub const fn closes_at_ms(&self) -> u64 {
        self.closes_at_ms
    }

    fn push_news(state: &mut CallState, item: VoiceNewsItem) {
        let seq = state.next_seq;
        state.next_seq += 1;
        if state.news.len() >= HOST_NEWS_LIMIT
            && let Some(lost) = state.news.pop_front()
        {
            state.dropped_through = lost.seq.get();
        }
        state.news.push_back(VoiceNews {
            seq: U64::new(seq),
            item,
        });
    }

    fn on_event(&self, event: HostCallEvent) {
        match event {
            HostCallEvent::DelegationHeard {
                delegation_id,
                offset_ms,
            } => {
                let Ok(delegation_id) = kr_protocol::voice::VoiceDelegationId::new(delegation_id)
                else {
                    return;
                };
                Self::push_news(
                    &mut self.state(),
                    VoiceNewsItem::Delegation {
                        delegation_id,
                        offset_ms: U64::new(offset_ms),
                    },
                );
            }
            HostCallEvent::WriteRefused { write_id } => {
                let mut state = self.state();
                if let Some(ack) = state.acks.get_mut(&write_id) {
                    *ack = Ack::Refused;
                    drop(state);
                    self.progress.notify_one();
                    return;
                }
                if let Some(at) = state.writes.iter().position(|(id, _)| *id == write_id) {
                    let (_, action_id) = state.writes.remove(at).expect("a write at a position");
                    Self::push_news(
                        &mut state,
                        VoiceNewsItem::LateRefusal {
                            action_id,
                            reason: VoiceHostRefusal::ProviderRefused,
                        },
                    );
                }
            }
            HostCallEvent::WriteAcknowledged { write_id } => {
                let mut state = self.state();
                if let Some(ack) = state.acks.get_mut(&write_id) {
                    *ack = Ack::Acknowledged;
                    drop(state);
                    self.progress.notify_one();
                    return;
                }
                if let Some(at) = state.writes.iter().position(|(id, _)| *id == write_id) {
                    state.writes.remove(at);
                }
            }
            HostCallEvent::State(SidebandState::Closed(end)) => self.settle(Some(end)),
            HostCallEvent::State(_) => self.progress.notify_one(),
        }
    }

    /// Records the end of the call: the running send is stopped, and counted as unconfirmed when
    /// an append of it was written and not answered, as it is when the channel is lost. The
    /// caller wakes the sender after it has dropped the lock.
    fn note_end(state: &mut CallState, reason: VoiceEndReason, at_ms: u64) {
        state.ended = Some(RecordedEnd { reason, at_ms });
        if let Some(mut send) = state.sending.take() {
            if send.in_flight {
                send.unconfirmed += 1;
            }
            Self::upsert_context(
                state,
                send,
                VoiceContextState::Stopped {
                    stopped_by: stop_of(reason),
                },
            );
        }
    }

    /// Records that the host ends the call. The first end stands, and the call stays held: its
    /// final status is built when the side channel reports the close, or when the wait for it is
    /// over.
    fn record_end(&self, reason: VoiceEndReason, now_ms: u64) {
        {
            let mut state = self.state();
            if state.ended.is_some() {
                return;
            }
            Self::note_end(&mut state, reason, now_ms);
        }
        self.progress.notify_one();
    }

    /// Settles the call when its side channel reports the close, or when its end is recorded and
    /// [`FINAL_STATUS_CLOSE_WAIT_MS`] has passed without a report. Reads the channel outside the
    /// call's lock.
    fn settle_if_due(&self, now_ms: u64) {
        if let SidebandState::Closed(end) = self.control.state() {
            self.settle(Some(end));
            return;
        }
        let due = self.state().ended.is_some_and(|recorded| {
            now_ms >= recorded.at_ms.saturating_add(FINAL_STATUS_CLOSE_WAIT_MS)
        });
        if due {
            self.settle(None);
        }
    }

    /// Builds the call's final status and hands it to the registry, once. `end` is how the side
    /// channel closed, or `None` when the wait for the close is over. A call whose end was not
    /// recorded ends by the channel alone. The first reason stands, except that an end the
    /// coordinator recorded for a provider that closed the call is only an inference, and the
    /// channel's own end gives the reason.
    ///
    /// The status is built and kept on the call in the one locked step that settles it, so a
    /// heartbeat that meets the settlement answers from it; the registry takes it after.
    fn settle(&self, end: Option<SidebandEnd>) {
        let (kept, wake) = {
            let mut state = self.state();
            if state.settled.is_some() {
                return;
            }
            let mut wake = false;
            let (reason, provider_close) = match (state.ended, end) {
                (Some(recorded), Some(end))
                    if recorded.reason == VoiceEndReason::ProviderClosed =>
                {
                    closing_of(end)
                }
                (Some(recorded), Some(end)) => (recorded.reason, closing_of(end).1),
                (Some(recorded), None) => (recorded.reason, VoiceProviderClose::Unconfirmed),
                (None, Some(end)) => {
                    let closing = closing_of(end);
                    let at_ms = state.last_beat_ms;
                    Self::note_end(&mut state, closing.0, at_ms);
                    wake = true;
                    closing
                }
                (None, None) => return,
            };
            let at_ms = state.ended.map_or(0, |recorded| recorded.at_ms);
            Self::push_news(
                &mut state,
                VoiceNewsItem::Ended {
                    reason,
                    provider_close,
                },
            );
            let kept = Kept {
                status: FinalStatus {
                    voice_session_id: self.voice_session_id,
                    device_id: self.device_id,
                    reason,
                    provider_close,
                    news: state.news.iter().cloned().collect(),
                    last_seq: state.next_seq - 1,
                },
                ended_ms: at_ms,
            };
            state.settled = Some(kept.clone());
            (kept, wake)
        };
        if wake {
            self.progress.notify_one();
        }
        #[cfg(test)]
        self.between_the_locks.wait();
        let Some(shared) = self.calls.upgrade() else {
            return;
        };
        let mut registry = shared.registry.lock().expect("the host call registry");
        registry.calls.remove(&self.voice_session_id);
        registry.finals.push_back(kept);
        while registry.finals.len() > FINAL_STATUS_RECORDS {
            registry.finals.pop_front();
        }
    }

    /// The state the call answers: `closing` once its end is recorded, whatever the channel says,
    /// then the channel's own. A channel that is closed is read as closing here, because the
    /// callers settle a closed channel first, and `closed` is only answered from a final status.
    fn state_of(&self, ended: bool, channel: SidebandState, now_ms: u64) -> VoiceHostCallState {
        if ended {
            return VoiceHostCallState::Closing;
        }
        match channel {
            SidebandState::Ready if now_ms < self.closes_at_ms => VoiceHostCallState::Open,
            SidebandState::Ready | SidebandState::Closing | SidebandState::Closed(_) => {
                VoiceHostCallState::Closing
            }
            SidebandState::Recovering => VoiceHostCallState::Recovering,
        }
    }

    fn call_state(&self, now_ms: u64) -> VoiceHostCallState {
        let channel = self.control.state();
        let ended = self.state().ended.is_some();
        self.state_of(ended, channel, now_ms)
    }

    /// Answers a heartbeat. A call that is settled answers `closed` from its final status. Any
    /// other call answers its state and its news from one look at its record: it stamps the
    /// phone's liveness while the call is open or recovering and its end is not recorded, drops
    /// the news the device acknowledged and returns the rest.
    fn heartbeat(&self, after_seq: u64, now_ms: u64) -> Answer {
        let channel = self.control.state();
        let mut state = self.state();
        if let Some(kept) = &state.settled {
            let status = &kept.status;
            return Answer {
                result: VoiceControlResult::Heartbeat {
                    state: VoiceHostCallState::Closed {
                        reason: status.reason,
                        provider_close: status.provider_close,
                    },
                    remaining_seconds: 0,
                    news: status
                        .news
                        .iter()
                        .filter(|item| item.seq.get() > after_seq)
                        .cloned()
                        .collect(),
                    dropped: false,
                },
                final_acknowledged: after_seq >= status.last_seq,
            };
        }
        let call_state = self.state_of(state.ended.is_some(), channel, now_ms);
        if matches!(
            call_state,
            VoiceHostCallState::Open | VoiceHostCallState::Recovering
        ) {
            state.last_beat_ms = now_ms;
        }
        while state
            .news
            .front()
            .is_some_and(|item| item.seq.get() <= after_seq)
        {
            state.news.pop_front();
        }
        let news: Vec<VoiceNews> = state.news.iter().cloned().collect();
        let dropped = after_seq < state.dropped_through;
        Answer {
            result: VoiceControlResult::Heartbeat {
                state: call_state,
                remaining_seconds: u32::try_from(self.closes_at_ms.saturating_sub(now_ms) / 1_000)
                    .unwrap_or(u32::MAX),
                news,
                dropped,
            },
            final_acknowledged: false,
        }
    }

    /// Runs the phone-absence rules. Returns true when the phone has been silent long enough that
    /// the caller begins closing the call.
    ///
    /// A note counts as told when it was written, or refused for a reason a later try would not
    /// change (too large, or refused by the provider). Any other refusal keeps it owed: the call's
    /// pace, a side channel that is not ready or was lost. It is written on a later pass.
    async fn tick(&self, now_ms: u64) -> bool {
        let (silent_for, beat, back, tell) = {
            let mut state = self.state();
            if state.ended.is_some() {
                return false;
            }
            let silent_for = now_ms.saturating_sub(state.last_beat_ms);
            let tell = silent_for >= SILENT_AFTER_MS && !state.silent_told;
            // An owed back note is claimed here, under the lock, so that a request that comes
            // while it is written does not write it too.
            (
                silent_for,
                state.last_beat_ms,
                std::mem::take(&mut state.back_owed),
                tell,
            )
        };
        if back {
            self.tell_that_the_phone_is_back().await;
        } else if tell && self.write_automatic_note(HostNote::PhoneSilent).await {
            let mut state = self.state();
            if state.last_beat_ms == beat {
                state.silent_told = true;
            } else {
                // The phone was heard while the note was being written: the model was told it
                // is silent and is owed that it is back.
                state.back_owed = true;
            }
        }
        silent_for >= u64::from(HOST_CLIENT_ABSENT_SECONDS) * 1_000
    }

    /// Writes one automatic note. Says whether the note is done with: written, or refused for a
    /// reason a later try would not change (too large, or refused by the provider). A refusal that
    /// a later try can change (the call's pace, a side channel that is not ready, one that was
    /// lost) leaves the note owed. A call whose end is recorded takes no note, and owes none.
    async fn write_automatic_note(&self, note: HostNote) -> bool {
        if self.state().ended.is_some() {
            return true;
        }
        let id = self.next_write_id(None);
        let Ok(frame) = VoiceContextFrame::new(
            id,
            VoiceCommand::Instructions,
            None,
            Some(note.words().to_owned()),
        ) else {
            return true;
        };
        matches!(
            self.control.write(self.control.revision(), frame).await,
            Ok(()) | Err(WriteRefusal::TooLarge | WriteRefusal::ProviderRefused)
        )
    }

    /// Writes the back note that the caller claimed from `back_owed`, and owes it again when it
    /// is not done with.
    async fn tell_that_the_phone_is_back(&self) {
        if !self.write_automatic_note(HostNote::PhoneBack).await {
            self.state().back_owed = true;
        }
    }

    fn next_write_id(&self, action_id: Option<ActionId>) -> String {
        let mut state = self.state();
        state.write_count += 1;
        let id = format!("host-{}", state.write_count);
        if let Some(action_id) = action_id {
            if state.writes.len() >= WRITES_KEPT {
                state.writes.pop_front();
            }
            state.writes.push_back((id.clone(), action_id));
        }
        id
    }

    /// Notes that the next request after a silence is the phone coming back, and tells the model
    /// once. Every control arm calls it, the heartbeat among them, and the request's answer waits
    /// for the write of the note, which is bounded by the side channel's own write bound. A note
    /// that is not done with is owed, and written by the next request or the next pass of the
    /// tick. The owed note is claimed under the lock before the write awaits, so a request and a
    /// pass that meet write it once between them.
    pub async fn phone_is_back(&self, now_ms: u64) {
        let owed = {
            let mut state = self.state();
            // A call whose end is recorded is not the phone's to wake: no stamp, no note.
            if state.ended.is_some() {
                return;
            }
            if state.silent_told {
                state.silent_told = false;
                state.back_owed = true;
            }
            state.last_beat_ms = now_ms;
            std::mem::take(&mut state.back_owed)
        };
        if owed {
            self.tell_that_the_phone_is_back().await;
        }
    }

    fn writable(&self, now_ms: u64) -> Result<u64, VoiceHostRefusal> {
        match self.call_state(now_ms) {
            VoiceHostCallState::Open => Ok(self.control.revision()),
            VoiceHostCallState::Recovering => Err(VoiceHostRefusal::NotReady),
            VoiceHostCallState::Closing | VoiceHostCallState::Closed { .. } => {
                Err(VoiceHostRefusal::Closing)
            }
        }
    }

    async fn write(
        &self,
        revision: u64,
        action_id: ActionId,
        command: VoiceCommand,
        delegation_id: Option<String>,
        content: Option<String>,
    ) -> Result<(), VoiceHostRefusal> {
        let id = self.next_write_id(Some(action_id));
        let frame = VoiceContextFrame::new(id, command, delegation_id, content)
            .map_err(|_| VoiceHostRefusal::TooLarge)?;
        self.control
            .write(revision, frame)
            .await
            .map_err(|refusal| match refusal {
                WriteRefusal::NotReady | WriteRefusal::Stale => VoiceHostRefusal::NotReady,
                WriteRefusal::ProviderRefused => VoiceHostRefusal::ProviderRefused,
                WriteRefusal::Lost => VoiceHostRefusal::SidebandLost,
                WriteRefusal::Rate => VoiceHostRefusal::Rate,
                WriteRefusal::TooLarge => VoiceHostRefusal::TooLarge,
            })
    }

    /// Writes the mute or the unmute.
    pub async fn mute(&self, action_id: ActionId, muted: bool, now_ms: u64) -> VoiceControlResult {
        self.phone_is_back(now_ms).await;
        let revision = match self.writable(now_ms) {
            Ok(revision) => revision,
            Err(reason) => return refused(reason),
        };
        let command = if muted {
            VoiceCommand::Mute
        } else {
            VoiceCommand::Unmute
        };
        match self.write(revision, action_id, command, None, None).await {
            Ok(()) => VoiceControlResult::Admitted {
                note: Nullable(None),
            },
            Err(reason) => refused(reason),
        }
    }

    /// Records what `voice.delegate` answered for a delegation, so a note about its outcome can be
    /// checked against it.
    pub fn record_delegation(&self, delegation_id: &str, record: DelegationRecord) {
        let mut state = self.state();
        if state.delegations.len() >= DELEGATIONS_KEPT
            && !state.delegations.contains_key(delegation_id)
            && let Some(oldest) = state.delegations.keys().next().cloned()
        {
            state.delegations.remove(&oldest);
        }
        state.delegations.insert(delegation_id.to_owned(), record);
    }

    /// Whether the host's own side channel heard the delegation, waiting at most five seconds for
    /// it. A delegation the provider never announced to this call is not one the host acts on.
    pub async fn announced(&self, delegation_id: &str) -> bool {
        self.control
            .heard_within(delegation_id, Duration::from_millis(HOST_HEARD_WAIT_MS))
            .await
            .is_some()
    }

    /// Answers `heard`: where the host's own side channel heard the delegation, within five
    /// seconds, or that it has not.
    pub async fn heard(&self, delegation_id: &str, now_ms: u64) -> VoiceControlResult {
        self.phone_is_back(now_ms).await;
        // Bound to a call that is ready and within its deadline, as a write is.
        if let Err(reason) = self.writable(now_ms) {
            return refused(reason);
        }
        match self
            .control
            .heard_within(delegation_id, Duration::from_millis(HOST_HEARD_WAIT_MS))
            .await
        {
            Some(offset_ms) => VoiceControlResult::Heard {
                offset_ms: U64::new(offset_ms),
            },
            None => VoiceControlResult::NotHeard,
        }
    }

    /// Checks a note against the host's record and writes its words.
    ///
    /// The checks, in order: the call is writable; the note is one a device may ask for here; a note
    /// about a delegation names one the host's side channel heard; an outcome the host recorded
    /// agrees with the note's kind; the note was not told before; nothing follows a final note.
    /// Only then are the words written, as instructions without a delegation and as commentary
    /// with one. `DelegationPerformed` carries the host's own summary, read again just now.
    pub async fn note(
        &self,
        action_id: ActionId,
        note: VoiceNote,
        delegation_id: Option<&str>,
        support: &dyn NoteSupport,
        now_ms: u64,
    ) -> VoiceControlResult {
        self.phone_is_back(now_ms).await;
        let revision = match self.writable(now_ms) {
            Ok(revision) => revision,
            Err(reason) => return refused(reason),
        };
        if note.is_for_the_managed_control_only() {
            return refused(VoiceHostRefusal::NotSupportedByRecord);
        }
        if note.is_about_a_delegation() != delegation_id.is_some() {
            return refused(if delegation_id.is_some() {
                VoiceHostRefusal::NotSupportedByRecord
            } else {
                VoiceHostRefusal::UnknownDelegation
            });
        }
        let record = match delegation_id {
            Some(id) => {
                if self.control.heard(id).is_none() {
                    return refused(VoiceHostRefusal::UnknownDelegation);
                }
                let record = self.state().delegations.get(id).cloned();
                match (note, &record) {
                    (VoiceNote::DelegationPerformed, Some(r))
                        if r.kind() == DelegationKind::Performed => {}
                    (VoiceNote::DelegationAdmitted, Some(r))
                        if r.kind() == DelegationKind::Admitted => {}
                    (VoiceNote::DelegationPerformed | VoiceNote::DelegationAdmitted, _) => {
                        return refused(if record.is_some() {
                            VoiceHostRefusal::NotSupportedByRecord
                        } else {
                            VoiceHostRefusal::UnknownDelegation
                        });
                    }
                    // A refusal that came before the coordinator's handler leaves no record: the
                    // note is the device's truth. A recorded delegation that was not refused is
                    // not supported by the record.
                    (VoiceNote::DelegationHostRefused, Some(r))
                        if r.kind() != DelegationKind::Refused =>
                    {
                        return refused(VoiceHostRefusal::NotSupportedByRecord);
                    }
                    _ => {}
                }
                record
            }
            None => None,
        };
        // The words, with the host's own fresh summary when the delegation was performed.
        let words = if note == VoiceNote::DelegationPerformed {
            let Some(record) = &record else {
                return refused(VoiceHostRefusal::UnknownDelegation);
            };
            let summary = match support.fresh_summary(record).await {
                Ok(summary) => summary,
                Err(reason) => return refused(reason),
            };
            // Between the read and the write the grants, the history bound, privacy mode, the
            // call's deadline and the side channel's revision are looked at again, so a change in
            // that interval writes nothing.
            if let Err(reason) = support.allowed_now(record).await {
                return refused(reason);
            }
            // Asked again at the time it is now, not the time the note came: the read and the
            // check before this each waited.
            match self.writable(support.now_ms()) {
                Ok(current) if current == revision => {}
                Ok(_) => return refused(VoiceHostRefusal::NotReady),
                Err(reason) => return refused(reason),
            }
            performed_words(&summary)
        } else {
            note.words().to_owned()
        };
        // Told at most once; one final per delegation; nothing after a final.
        {
            let mut state = self.state();
            let key = delegation_id.map(str::to_owned);
            let CallState {
                told, call_notes, ..
            } = &mut *state;
            if key.is_none() {
                if !call_notes.insert(note) {
                    return refused(VoiceHostRefusal::AlreadyTold);
                }
            } else {
                let told = told.entry(key).or_default();
                if told.finished || told.sentences.contains(&note) {
                    return refused(VoiceHostRefusal::AlreadyTold);
                }
                told.sentences.insert(note);
                if note.phase() == NotePhase::Final {
                    told.finished = true;
                }
            }
        }
        let outcome = self
            .write_note(
                revision,
                action_id,
                note,
                delegation_id.map(str::to_owned),
                words,
            )
            .await;
        match outcome {
            Ok(()) => VoiceControlResult::Admitted {
                note: Nullable(Some(note)),
            },
            Err(reason) => {
                // Nothing reached the model, so the note is still owed: it was not told.
                let mut state = self.state();
                let key = delegation_id.map(str::to_owned);
                if key.is_none() {
                    state.call_notes.remove(&note);
                } else if let Some(told) = state.told.get_mut(&key) {
                    told.sentences.remove(&note);
                    told.finished = false;
                }
                refused(reason)
            }
        }
    }

    /// Puts the progress of a send in the news: the one item of that send, which a newer one
    /// replaces, so a send of many appends never fills the queue.
    fn upsert_context(state: &mut CallState, send: SendProgress, now: VoiceContextState) {
        state.news.retain(|item| {
            !matches!(&item.item, VoiceNewsItem::Context { action_id, .. } if *action_id == send.action_id)
        });
        Self::push_news(
            state,
            VoiceNewsItem::Context {
                action_id: send.action_id,
                appended: send.appended,
                of: send.of,
                unconfirmed: send.unconfirmed,
                state: now,
            },
        );
    }

    /// Takes a selection of context for the model and answers at once: the sender is a task of this
    /// call, one at a time, and its progress arrives as news naming `action_id`.
    ///
    /// An answer of `queued` proves the sender took the selection, not that the provider acted on
    /// it.
    pub async fn send_context(
        self: &Arc<Self>,
        action_id: ActionId,
        params: VoiceContextSendParams,
        support: Arc<dyn SendSupport>,
        now_ms: u64,
    ) -> VoiceContextSendResult {
        let refused = |reason| VoiceContextSendResult::Refused { reason };
        self.phone_is_back(now_ms).await;
        let revision = match self.writable(now_ms) {
            Ok(revision) => revision,
            Err(reason) => return refused(reason),
        };
        if let Some(id) = params.delegation_id.0.as_ref()
            && self.control.heard(id.as_str()).is_none()
        {
            return refused(VoiceHostRefusal::UnknownDelegation);
        }
        {
            let mut state = self.state();
            if state.sending.is_some() {
                return refused(VoiceHostRefusal::Busy);
            }
            state.sending = Some(SendProgress {
                action_id,
                of: 0,
                appended: 0,
                unconfirmed: 0,
                in_flight: false,
            });
        }
        let selected = match support.select(&params).await {
            Ok(selected) => selected,
            Err(reason) => {
                self.give_up_send(action_id);
                return refused(reason);
            }
        };
        let appends = call_start_appends(&selected.selection);
        if appends.len() > MAX_START_APPENDS {
            self.give_up_send(action_id);
            return refused(VoiceHostRefusal::TooLarge);
        }
        let of = u32::try_from(appends.len()).unwrap_or(u32::MAX);
        {
            let mut state = self.state();
            // The call may have ended while the selection was read: its end took the send.
            let Some(send) = state
                .sending
                .as_mut()
                .filter(|send| send.action_id == action_id)
            else {
                return refused(VoiceHostRefusal::Closing);
            };
            send.of = of;
            let send = *send;
            Self::upsert_context(&mut state, send, VoiceContextState::Sending);
        }
        let call = Arc::clone(self);
        tokio::spawn(async move {
            call.run_sender(action_id, params, selected, appends, support, revision)
                .await;
        });
        VoiceContextSendResult::Queued { appends: of }
    }

    fn give_up_send(&self, action_id: ActionId) {
        let mut state = self.state();
        if state
            .sending
            .is_some_and(|send| send.action_id == action_id)
        {
            state.sending = None;
        }
    }

    /// Why a running send must stop now, when it must: the call ended, its deadline passed, or the
    /// side channel is not the one the send began on.
    fn send_stop(&self, revision: u64, now_ms: u64) -> Option<VoiceContextStop> {
        if let Some(recorded) = self.state().ended {
            return Some(stop_of(recorded.reason));
        }
        if now_ms >= self.closes_at_ms {
            return Some(VoiceContextStop::Deadline);
        }
        match self.control.state() {
            SidebandState::Ready => {}
            SidebandState::Closing => return Some(VoiceContextStop::Stop),
            SidebandState::Recovering | SidebandState::Closed(_) => {
                return Some(VoiceContextStop::SidebandLost);
            }
        }
        (self.control.revision() != revision).then_some(VoiceContextStop::SidebandLost)
    }

    /// Waits for the provider to acknowledge the write `id`, and stops where the send must stop.
    async fn acknowledged(
        &self,
        id: &str,
        revision: u64,
        support: &dyn SendSupport,
    ) -> Result<(), VoiceContextStop> {
        let deadline = Instant::now() + SEND_ACKNOWLEDGEMENT_WAIT;
        loop {
            {
                let mut state = self.state();
                match state.acks.get(id).copied() {
                    Some(Ack::Acknowledged) => {
                        state.acks.remove(id);
                        return Ok(());
                    }
                    // The provider took a frame it then refused.
                    Some(Ack::Refused) => {
                        state.acks.remove(id);
                        return Err(VoiceContextStop::ProviderRefused);
                    }
                    _ => {}
                }
            }
            if let Some(stop) = self.send_stop(revision, support.now_ms()) {
                return Err(stop);
            }
            tokio::select! {
                () = self.progress.notified() => {}
                () = tokio::time::sleep_until(deadline) => return Err(VoiceContextStop::SidebandLost),
            }
        }
    }

    /// The sender: writes each append under the pacing of the managed control, looking again at
    /// what allows the send before every one, and stops at the first change.
    async fn run_sender(
        self: Arc<Self>,
        action_id: ActionId,
        params: VoiceContextSendParams,
        selected: ContextSelected,
        appends: Vec<String>,
        support: Arc<dyn SendSupport>,
        revision: u64,
    ) {
        let delegation_id = params
            .delegation_id
            .0
            .as_ref()
            .map(|id| id.as_str().to_owned());
        let mut stopped = None;
        let mut next = 0;
        while let Some(text) = appends.get(next) {
            loop {
                if let Some(stop) = self.send_stop(revision, support.now_ms()) {
                    stopped = Some(stop);
                    break;
                }
                let Some(at) = self.control.next_write_at() else {
                    break;
                };
                tokio::select! {
                    () = tokio::time::sleep_until(at) => {}
                    () = self.progress.notified() => {}
                }
            }
            if stopped.is_none()
                && let Err(stop) = support.still_allowed(&params, &selected).await
            {
                stopped = Some(stop);
            }
            if stopped.is_some() {
                break;
            }
            let id = self.next_write_id(None);
            // A frame that cannot be built is refused before anything is written.
            let Ok(frame) = VoiceContextFrame::new(
                id.clone(),
                VoiceCommand::Thinking,
                delegation_id.clone(),
                Some(text.clone()),
            ) else {
                stopped = Some(VoiceContextStop::SidebandLost);
                break;
            };
            {
                // The append counts as written from the step that may write it, in the lock that
                // makes it wait for its answer: the provider's closure can be read and the call
                // ended before this task has the write's result back, and the final status then
                // still counts it.
                let mut state = self.state();
                state.acks.insert(id.clone(), Ack::Waiting);
                if let Some(send) = state
                    .sending
                    .as_mut()
                    .filter(|send| send.action_id == action_id)
                {
                    send.in_flight = true;
                }
            }
            let written = self.control.write(revision, frame).await;
            if let Err(refusal) = written {
                {
                    let mut state = self.state();
                    state.acks.remove(&id);
                    if let Some(send) = state
                        .sending
                        .as_mut()
                        .filter(|send| send.action_id == action_id)
                    {
                        // A refusal before anything was sent leaves no append unanswered. A write
                        // that did not finish (`Lost`) may have been read by the provider: it is
                        // counted here, once, and the flag is cleared so that the call's end does
                        // not count it again. When the call ended first, the end took the send
                        // and counted it, and nothing is left here to count.
                        if refusal == WriteRefusal::Lost && send.in_flight {
                            send.unconfirmed += 1;
                        }
                        send.in_flight = false;
                    }
                }
                stopped = Some(match refusal {
                    // Another command of the call took the pace first: the append waits for it
                    // again, and everything that allows it is looked at again.
                    WriteRefusal::Rate => continue,
                    WriteRefusal::ProviderRefused | WriteRefusal::TooLarge => {
                        VoiceContextStop::ProviderRefused
                    }
                    WriteRefusal::NotReady | WriteRefusal::Stale | WriteRefusal::Lost => {
                        VoiceContextStop::SidebandLost
                    }
                });
                break;
            }
            next += 1;
            let answer = self.acknowledged(&id, revision, &*support).await;
            let mut state = self.state();
            state.acks.remove(&id);
            let Some(send) = state
                .sending
                .as_mut()
                .filter(|send| send.action_id == action_id)
            else {
                return;
            };
            send.in_flight = false;
            match answer {
                Ok(()) => {
                    send.appended += 1;
                    let send = *send;
                    Self::upsert_context(&mut state, send, VoiceContextState::Sending);
                }
                Err(stop) => {
                    // Written, and never answered: counted, and never written again.
                    send.unconfirmed += 1;
                    stopped = Some(stop);
                    break;
                }
            }
        }
        let mut state = self.state();
        if let Some(send) = state.sending.filter(|send| send.action_id == action_id) {
            state.sending = None;
            let end = stopped.map_or(VoiceContextState::Done, |stopped_by| {
                VoiceContextState::Stopped { stopped_by }
            });
            Self::upsert_context(&mut state, send, end);
        }
    }

    async fn write_note(
        &self,
        revision: u64,
        action_id: ActionId,
        note: VoiceNote,
        delegation_id: Option<String>,
        words: String,
    ) -> Result<(), VoiceHostRefusal> {
        let command = if delegation_id.is_some() {
            VoiceCommand::Commentary
        } else {
            VoiceCommand::Instructions
        };
        self.write(
            revision,
            action_id,
            command,
            delegation_id.clone(),
            Some(words.clone()),
        )
        .await?;
        if note.goes_both_ways() {
            self.write(
                revision,
                action_id,
                VoiceCommand::Commentary,
                None,
                Some(words),
            )
            .await?;
        }
        Ok(())
    }
}

/// The words the model is told of a performed delegation: the lead-in and the host's own summary,
/// together at most [`HOST_PERFORMED_WORDS_BYTES`] bytes, cut at a character boundary.
#[must_use]
pub fn performed_words(summary: &str) -> String {
    let lead = VoiceNote::DelegationPerformed.words();
    let mut words = format!("{lead} {summary}");
    if words.len() > HOST_PERFORMED_WORDS_BYTES {
        let mut end = HOST_PERFORMED_WORDS_BYTES;
        while !words.is_char_boundary(end) {
            end -= 1;
        }
        words.truncate(end);
    }
    words
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use kr_client::services::host_call::{HostCallListener, HostFuture};
    use kr_client::services::voice_control::ControlTimings;
    use kr_client::services::voice_pacing::Pacer;
    use kr_protocol::voice::VoiceDelegationId;

    use super::*;

    /// What was written: the command, the delegation it named and its text.
    type Written = Vec<(VoiceCommand, Option<String>, Option<String>)>;

    /// A side channel the test steers: its state, what it has heard and what was written to it.
    struct Sideband {
        state: Mutex<SidebandState>,
        heard: Mutex<BTreeMap<String, u64>>,
        written: Mutex<Written>,
        ids: Mutex<Vec<String>>,
        acknowledged: AtomicU64,
        listener: Mutex<Option<HostCallListener>>,
        /// A close the channel tells the listener the moment it is set.
        tells_on_listen: Mutex<Option<SidebandEnd>>,
        revision: AtomicU64,
        refuses: std::sync::atomic::AtomicBool,
        /// Whether the provider's closure is read as soon as a write is taken, before the write's
        /// caller has its result.
        closes_with_the_write: std::sync::atomic::AtomicBool,
        /// Whether every write is refused by the call's pace.
        rate_refuses: std::sync::atomic::AtomicBool,
        /// Whether a write is taken and then reported as not finished: the provider may have read
        /// it, and the writer cannot say.
        loses_the_write: std::sync::atomic::AtomicBool,
        /// A gate every write waits at, until the test lets the writes through.
        gate: Mutex<Option<Arc<tokio::sync::Notify>>>,
        pacer: Mutex<Pacer>,
    }

    impl Sideband {
        fn new() -> Arc<Self> {
            let timings = ControlTimings::default();
            Arc::new(Self {
                state: Mutex::new(SidebandState::Ready),
                heard: Mutex::new(BTreeMap::new()),
                written: Mutex::new(Vec::new()),
                ids: Mutex::new(Vec::new()),
                acknowledged: AtomicU64::new(0),
                listener: Mutex::new(None),
                tells_on_listen: Mutex::new(None),
                revision: AtomicU64::new(1),
                refuses: std::sync::atomic::AtomicBool::new(false),
                closes_with_the_write: std::sync::atomic::AtomicBool::new(false),
                rate_refuses: std::sync::atomic::AtomicBool::new(false),
                loses_the_write: std::sync::atomic::AtomicBool::new(false),
                gate: Mutex::new(None),
                pacer: Mutex::new(Pacer::new(timings.burst_window, timings.minute_window)),
            })
        }

        fn set(&self, state: SidebandState) {
            *self.state.lock().expect("the state") = state;
        }

        fn hear(&self, id: &str, offset_ms: u64) {
            self.heard
                .lock()
                .expect("heard")
                .insert(id.to_owned(), offset_ms);
            self.tell(HostCallEvent::DelegationHeard {
                delegation_id: id.to_owned(),
                offset_ms,
            });
        }

        fn tell(&self, event: HostCallEvent) {
            let listener = self.listener.lock().expect("the listener").clone();
            listener.expect("a listener")(event);
        }

        fn written(&self) -> Written {
            self.written.lock().expect("written").clone()
        }

        /// Tells the call that the provider acknowledged every write it has not yet acknowledged.
        fn acknowledge_all(&self) {
            let ids = self.ids.lock().expect("ids").clone();
            let from = usize::try_from(self.acknowledged.swap(ids.len() as u64, Ordering::SeqCst))
                .expect("a count");
            for id in &ids[from..] {
                self.pacer
                    .lock()
                    .expect("the pacer")
                    .acknowledged(id, Instant::now());
                self.tell(HostCallEvent::WriteAcknowledged {
                    write_id: id.clone(),
                });
            }
        }
    }

    impl std::fmt::Debug for Sideband {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("Sideband")
        }
    }

    impl HostCallControl for Sideband {
        fn state(&self) -> SidebandState {
            *self.state.lock().expect("the state")
        }

        fn revision(&self) -> u64 {
            self.revision.load(Ordering::SeqCst)
        }

        fn write<'a>(
            &'a self,
            revision: u64,
            frame: VoiceContextFrame,
        ) -> HostFuture<'a, Result<(), WriteRefusal>> {
            Box::pin(async move {
                if revision != self.revision() {
                    return Err(WriteRefusal::Stale);
                }
                if self.state() != SidebandState::Ready {
                    return Err(WriteRefusal::NotReady);
                }
                if self.refuses.load(Ordering::SeqCst) {
                    return Err(WriteRefusal::ProviderRefused);
                }
                if self.rate_refuses.load(Ordering::SeqCst) || self.next_write_at().is_some() {
                    return Err(WriteRefusal::Rate);
                }
                let gate = self.gate.lock().expect("the gate").clone();
                if let Some(gate) = gate {
                    gate.notified().await;
                }
                self.pacer
                    .lock()
                    .expect("the pacer")
                    .record(&frame.id, Instant::now());
                self.ids.lock().expect("ids").push(frame.id.clone());
                self.written.lock().expect("written").push((
                    frame.command,
                    frame.delegation_id.clone(),
                    frame.content.clone(),
                ));
                if self.closes_with_the_write.load(Ordering::SeqCst) {
                    self.set(SidebandState::Closed(SidebandEnd::ProviderClosed));
                    self.tell(HostCallEvent::State(SidebandState::Closed(
                        SidebandEnd::ProviderClosed,
                    )));
                }
                if self.loses_the_write.load(Ordering::SeqCst) {
                    return Err(WriteRefusal::Lost);
                }
                Ok(())
            })
        }

        fn next_write_at(&self) -> Option<Instant> {
            self.pacer
                .lock()
                .expect("the pacer")
                .next_at(Instant::now())
        }

        fn heard(&self, delegation_id: &str) -> Option<u64> {
            self.heard
                .lock()
                .expect("heard")
                .get(delegation_id)
                .copied()
        }

        fn heard_within<'a>(
            &'a self,
            delegation_id: &'a str,
            _within: Duration,
        ) -> HostFuture<'a, Option<u64>> {
            Box::pin(async move { self.heard(delegation_id) })
        }

        fn listen(&self, listener: HostCallListener) {
            *self.listener.lock().expect("the listener") = Some(Arc::clone(&listener));
            let told = *self.tells_on_listen.lock().expect("the end");
            if let Some(end) = told {
                listener(HostCallEvent::State(SidebandState::Closed(end)));
            }
        }
    }

    /// What a performed delegation's summary reads as now, or why it cannot be read.
    struct Reads(Result<String, VoiceHostRefusal>);

    impl NoteSupport for Reads {
        fn now_ms(&self) -> u64 {
            OPENED + 1_000
        }

        fn fresh_summary<'a>(
            &'a self,
            _record: &'a DelegationRecord,
        ) -> HostFuture<'a, Result<String, VoiceHostRefusal>> {
            let answer = self.0.clone();
            Box::pin(async move { answer })
        }

        fn allowed_now<'a>(
            &'a self,
            _record: &'a DelegationRecord,
        ) -> HostFuture<'a, Result<(), VoiceHostRefusal>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// A read that passes and ends after the call's deadline.
    struct ReadsPastTheDeadline;

    impl NoteSupport for ReadsPastTheDeadline {
        fn now_ms(&self) -> u64 {
            CLOSES + 1
        }

        fn fresh_summary<'a>(
            &'a self,
            _record: &'a DelegationRecord,
        ) -> HostFuture<'a, Result<String, VoiceHostRefusal>> {
            Box::pin(async { Ok("fresh".to_owned()) })
        }

        fn allowed_now<'a>(
            &'a self,
            _record: &'a DelegationRecord,
        ) -> HostFuture<'a, Result<(), VoiceHostRefusal>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// A read that passes, and a check just before the write that does not: a grant, the history
    /// bound or privacy mode moved in between.
    struct MovesBeforeTheWrite(VoiceHostRefusal);

    impl NoteSupport for MovesBeforeTheWrite {
        fn now_ms(&self) -> u64 {
            OPENED + 1_000
        }

        fn fresh_summary<'a>(
            &'a self,
            _record: &'a DelegationRecord,
        ) -> HostFuture<'a, Result<String, VoiceHostRefusal>> {
            Box::pin(async { Ok("fresh".to_owned()) })
        }

        fn allowed_now<'a>(
            &'a self,
            _record: &'a DelegationRecord,
        ) -> HostFuture<'a, Result<(), VoiceHostRefusal>> {
            let refusal = self.0;
            Box::pin(async move { Err(refusal) })
        }
    }

    fn voice_session(byte: u8) -> VoiceSessionId {
        VoiceSessionId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16]))
    }

    fn device(byte: u8) -> DeviceId {
        DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16]))
    }

    fn action(byte: u8) -> ActionId {
        ActionId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16]))
    }

    fn delegation(name: &str) -> VoiceDelegationId {
        VoiceDelegationId::new(name).expect("a delegation id")
    }

    const OPENED: u64 = 1_000;
    const CLOSES: u64 = 601_000;

    fn held() -> (HostCalls, Arc<HostCall>, Arc<Sideband>) {
        let calls = HostCalls::new();
        let sideband = Sideband::new();
        let call = calls.register(
            voice_session(1),
            device(7),
            OPENED,
            CLOSES,
            Arc::clone(&sideband) as Arc<dyn HostCallControl>,
        );
        (calls, call, sideband)
    }

    fn heartbeat(
        calls: &HostCalls,
        after_seq: u64,
        now_ms: u64,
    ) -> (VoiceHostCallState, u32, Vec<VoiceNews>, bool) {
        match calls.heartbeat(voice_session(1), device(7), after_seq, now_ms) {
            VoiceControlResult::Heartbeat {
                state,
                remaining_seconds,
                news,
                dropped,
            } => (state, remaining_seconds, news, dropped),
            other => panic!("a heartbeat answer: {other:?}"),
        }
    }

    fn performed(summary: &str) -> VoiceDelegateResult {
        VoiceDelegateResult {
            delegation_id: delegation("d1"),
            action: Nullable::null(),
            session_id: Nullable::null(),
            outcome: VoiceDelegationOutcome::Performed {
                action_id: action(9),
                summary: summary.to_owned(),
            },
        }
    }

    fn recorded(call: &HostCall, id: &str, kept: VoiceDelegateResult) {
        call.record_delegation(
            id,
            DelegationRecord {
                delegate_action_id: action(9),
                params: VoiceDelegateParams {
                    voice_session_id: voice_session(1),
                    delegation_id: delegation(id),
                    offset_ms: U64::new(0),
                    fragments: Vec::new(),
                    confirmation: Nullable::null(),
                },
                kept,
            },
        );
    }

    fn admitted_note(result: &VoiceControlResult) -> Option<VoiceNote> {
        match result {
            VoiceControlResult::Admitted { note } => note.0,
            other => panic!("not admitted: {other:?}"),
        }
    }

    /// What the sender of a call's context reads of the host, as the test steers it.
    struct Support {
        selection: VoiceContextSelection,
        verdict: Mutex<Result<(), VoiceContextStop>>,
        rechecks: AtomicU64,
    }

    impl Support {
        fn of(messages: usize) -> Arc<Self> {
            Arc::new(Self {
                selection: selection_of(messages),
                verdict: Mutex::new(Ok(())),
                rechecks: AtomicU64::new(0),
            })
        }

        fn change(&self, to: VoiceContextStop) {
            *self.verdict.lock().expect("the verdict") = Err(to);
        }
    }

    impl SendSupport for Support {
        fn now_ms(&self) -> u64 {
            OPENED + 1_000
        }

        fn select<'a>(
            &'a self,
            _params: &'a VoiceContextSendParams,
        ) -> HostFuture<'a, Result<ContextSelected, VoiceHostRefusal>> {
            Box::pin(async move {
                Ok(ContextSelected {
                    selection: self.selection.clone(),
                    lower_bound_ms: None,
                    decided: crate::privacy::Published::default(),
                })
            })
        }

        fn still_allowed<'a>(
            &'a self,
            _params: &'a VoiceContextSendParams,
            _selected: &'a ContextSelected,
        ) -> HostFuture<'a, Result<(), VoiceContextStop>> {
            self.rechecks.fetch_add(1, Ordering::SeqCst);
            let verdict = *self.verdict.lock().expect("the verdict");
            Box::pin(async move { verdict })
        }
    }

    /// A selection whose opening is the header and `messages` messages of 400 bytes, which pack
    /// into one append each.
    fn selection_of(messages: usize) -> VoiceContextSelection {
        VoiceContextSelection {
            session_description: String::new(),
            working_directory: String::new(),
            active_application: String::new(),
            pending_decisions: Vec::new(),
            recent_messages: (0..messages).map(|n| format!("{n:0>400}")).collect(),
            selected: Vec::new(),
            text_tokens: 0,
            truncated: false,
            secrets_stripped: 0,
            stripping_note: String::new(),
        }
    }

    fn send_params() -> VoiceContextSendParams {
        VoiceContextSendParams {
            voice_session_id: voice_session(1),
            session_id: kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes(
                [3; 16],
            )),
            selected: kr_protocol::scalars::CanonicalSet::from_iter([]),
            delegation_id: Nullable::null(),
        }
    }

    /// Lets the tasks of the test's runtime run until they wait.
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    fn context_news(calls: &HostCalls) -> Vec<VoiceNewsItem> {
        let (_, _, news, _) = heartbeat(calls, 0, OPENED + 2_000);
        news.into_iter()
            .map(|item| item.item)
            .filter(|item| matches!(item, VoiceNewsItem::Context { .. }))
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn a_context_send_is_queued_at_once_its_progress_is_one_news_item_naming_its_action_and_a_second_send_is_busy()
     {
        let (calls, call, sideband) = held();
        let support = Support::of(3);
        let appends = u32::try_from(call_start_appends(&support.selection).len()).expect("a count");
        assert_eq!(appends, 4, "the header and three messages");
        assert_eq!(
            call.send_context(action(5), send_params(), support.clone(), OPENED + 1_000)
                .await,
            VoiceContextSendResult::Queued { appends }
        );
        assert_eq!(
            call.send_context(action(6), send_params(), support.clone(), OPENED + 1_000)
                .await,
            VoiceContextSendResult::Refused {
                reason: VoiceHostRefusal::Busy
            }
        );
        for written in 1..=4 {
            settle().await;
            assert_eq!(sideband.written().len(), written);
            assert!(
                sideband
                    .written()
                    .iter()
                    .all(|(command, _, _)| *command == VoiceCommand::Thinking)
            );
            sideband.acknowledge_all();
        }
        settle().await;
        assert_eq!(
            context_news(&calls),
            [VoiceNewsItem::Context {
                action_id: action(5),
                appended: 4,
                of: 4,
                unconfirmed: 0,
                state: VoiceContextState::Done
            }]
        );
        // A send that is done lets the next begin.
        assert!(matches!(
            call.send_context(action(7), send_params(), support, OPENED + 1_500)
                .await,
            VoiceContextSendResult::Queued { .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_context_send_looks_again_before_every_append_and_a_change_stops_it_with_no_further_write()
     {
        for change in [
            VoiceContextStop::History,
            VoiceContextStop::Privacy,
            VoiceContextStop::Grant,
        ] {
            let (calls, call, sideband) = held();
            let support = Support::of(3);
            let _ = call
                .send_context(action(5), send_params(), support.clone(), OPENED + 1_000)
                .await;
            settle().await;
            assert_eq!(sideband.written().len(), 1);
            support.change(change);
            sideband.acknowledge_all();
            settle().await;
            assert_eq!(
                sideband.written().len(),
                1,
                "nothing is written after {change:?}"
            );
            assert_eq!(
                context_news(&calls),
                [VoiceNewsItem::Context {
                    action_id: action(5),
                    appended: 1,
                    of: 4,
                    unconfirmed: 0,
                    state: VoiceContextState::Stopped { stopped_by: change }
                }]
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_append_without_its_acknowledgement_before_a_sideband_loss_is_unconfirmed_and_never_written_again()
     {
        let (calls, call, sideband) = held();
        let support = Support::of(2);
        let _ = call
            .send_context(action(5), send_params(), support, OPENED + 1_000)
            .await;
        settle().await;
        assert_eq!(sideband.written().len(), 1);
        // The channel is lost before the provider answered the append.
        sideband.set(SidebandState::Recovering);
        sideband.tell(HostCallEvent::State(SidebandState::Recovering));
        settle().await;
        sideband.set(SidebandState::Ready);
        sideband.tell(HostCallEvent::State(SidebandState::Ready));
        sideband.acknowledge_all();
        settle().await;
        assert_eq!(
            sideband.written().len(),
            1,
            "an append is never written again"
        );
        assert_eq!(
            context_news(&calls),
            [VoiceNewsItem::Context {
                action_id: action(5),
                appended: 0,
                of: 3,
                unconfirmed: 1,
                state: VoiceContextState::Stopped {
                    stopped_by: VoiceContextStop::SidebandLost
                }
            }]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_append_without_its_acknowledgement_when_the_provider_closes_the_call_is_unconfirmed()
     {
        let (calls, call, sideband) = held();
        let support = Support::of(2);
        let _ = call
            .send_context(action(5), send_params(), support, OPENED + 1_000)
            .await;
        settle().await;
        assert_eq!(sideband.written().len(), 1);
        // The provider closes the call before it answered the append.
        sideband.set(SidebandState::Closed(SidebandEnd::ProviderClosed));
        sideband.tell(HostCallEvent::State(SidebandState::Closed(
            SidebandEnd::ProviderClosed,
        )));
        settle().await;
        assert_eq!(
            context_news(&calls),
            [VoiceNewsItem::Context {
                action_id: action(5),
                appended: 0,
                of: 3,
                unconfirmed: 1,
                state: VoiceContextState::Stopped {
                    stopped_by: stop_of(VoiceEndReason::ProviderClosed)
                }
            }]
        );
    }

    /// The provider's closure can be read before the sender has the result of the write it took:
    /// the append is counted all the same, in the one final status.
    #[tokio::test(start_paused = true)]
    async fn an_append_whose_closure_is_read_before_its_write_returns_is_counted_unconfirmed() {
        let (calls, call, sideband) = held();
        sideband.closes_with_the_write.store(true, Ordering::SeqCst);
        let _ = call
            .send_context(action(5), send_params(), Support::of(2), OPENED + 1_000)
            .await;
        settle().await;
        assert_eq!(sideband.written().len(), 1);
        assert_eq!(
            context_news(&calls),
            [VoiceNewsItem::Context {
                action_id: action(5),
                appended: 0,
                of: 3,
                unconfirmed: 1,
                state: VoiceContextState::Stopped {
                    stopped_by: stop_of(VoiceEndReason::ProviderClosed)
                }
            }]
        );
    }

    /// A write that did not finish may have been read by the provider: the append is counted as
    /// unconfirmed once, whether the sender hears of the loss before the provider's closure comes
    /// or the closure is read before the write's result is back.
    #[tokio::test(start_paused = true)]
    async fn an_append_whose_write_is_lost_is_counted_unconfirmed_once_in_either_order() {
        // The write returns `Lost` first, and the closure comes after.
        let (calls, call, sideband) = held();
        sideband.loses_the_write.store(true, Ordering::SeqCst);
        let _ = call
            .send_context(action(5), send_params(), Support::of(2), OPENED + 1_000)
            .await;
        settle().await;
        assert_eq!(sideband.written().len(), 1);
        sideband.set(SidebandState::Closed(SidebandEnd::ProviderClosed));
        sideband.tell(HostCallEvent::State(SidebandState::Closed(
            SidebandEnd::ProviderClosed,
        )));
        settle().await;
        assert_eq!(
            context_news(&calls),
            [VoiceNewsItem::Context {
                action_id: action(5),
                appended: 0,
                of: 3,
                unconfirmed: 1,
                state: VoiceContextState::Stopped {
                    stopped_by: VoiceContextStop::SidebandLost
                }
            }]
        );

        // The closure is read before the write returns `Lost`.
        let (calls, call, sideband) = held();
        sideband.loses_the_write.store(true, Ordering::SeqCst);
        sideband.closes_with_the_write.store(true, Ordering::SeqCst);
        let _ = call
            .send_context(action(6), send_params(), Support::of(2), OPENED + 1_000)
            .await;
        settle().await;
        assert_eq!(sideband.written().len(), 1);
        assert_eq!(
            context_news(&calls),
            [VoiceNewsItem::Context {
                action_id: action(6),
                appended: 0,
                of: 3,
                unconfirmed: 1,
                state: VoiceContextState::Stopped {
                    stopped_by: VoiceContextStop::SidebandLost
                }
            }]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_append_the_provider_refuses_stops_the_send_as_provider_refused_not_as_a_lost_channel()
     {
        // Refused when it was written.
        let (calls, call, sideband) = held();
        sideband.refuses.store(true, Ordering::SeqCst);
        let _ = call
            .send_context(action(5), send_params(), Support::of(2), OPENED + 1_000)
            .await;
        settle().await;
        assert!(sideband.written().is_empty());
        assert_eq!(
            context_news(&calls),
            [VoiceNewsItem::Context {
                action_id: action(5),
                appended: 0,
                of: 3,
                unconfirmed: 0,
                state: VoiceContextState::Stopped {
                    stopped_by: VoiceContextStop::ProviderRefused
                }
            }]
        );

        // Refused after the provider had taken it.
        let (calls, call, sideband) = held();
        let _ = call
            .send_context(action(6), send_params(), Support::of(2), OPENED + 1_000)
            .await;
        settle().await;
        assert_eq!(sideband.written().len(), 1);
        let id = sideband.ids.lock().expect("ids")[0].clone();
        sideband.tell(HostCallEvent::WriteRefused { write_id: id });
        settle().await;
        assert_eq!(
            sideband.written().len(),
            1,
            "nothing is written after the refusal"
        );
        assert_eq!(
            context_news(&calls),
            [VoiceNewsItem::Context {
                action_id: action(6),
                appended: 0,
                of: 3,
                unconfirmed: 1,
                state: VoiceContextState::Stopped {
                    stopped_by: VoiceContextStop::ProviderRefused
                }
            }]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_send_that_waits_for_its_pace_delays_neither_a_heartbeat_nor_the_end_of_the_call() {
        let (calls, call, sideband) = held();
        let support = Support::of(14);
        let _ = call
            .send_context(action(5), send_params(), support, OPENED + 1_000)
            .await;
        // Ten appends are the burst; the eleventh waits for its window.
        for _ in 0..10 {
            settle().await;
            sideband.acknowledge_all();
        }
        settle().await;
        assert_eq!(
            sideband.written().len(),
            10,
            "the burst, and the pace holds the rest"
        );
        let (state, _, _, _) = heartbeat(&calls, 0, OPENED + 2_000);
        assert_eq!(
            state,
            VoiceHostCallState::Open,
            "a heartbeat is answered while the sender waits"
        );
        calls.end(voice_session(1), VoiceEndReason::Stop, OPENED + 3_000);
        tokio::time::advance(Duration::from_secs(12)).await;
        settle().await;
        assert_eq!(
            sideband.written().len(),
            10,
            "nothing is written after the call ended"
        );
        let (_, _, news, _) = heartbeat(&calls, 0, OPENED + 4_000);
        assert!(news.iter().any(|item| matches!(
            item.item,
            VoiceNewsItem::Context {
                state: VoiceContextState::Stopped {
                    stopped_by: VoiceContextStop::Stop
                },
                ..
            }
        )));
    }

    #[tokio::test(start_paused = true)]
    async fn a_selection_that_needs_more_than_64_appends_is_refused_whole_and_writes_nothing() {
        let (_calls, call, sideband) = held();
        let support = Support::of(70);
        assert_eq!(
            call.send_context(action(5), send_params(), support, OPENED + 1_000)
                .await,
            VoiceContextSendResult::Refused {
                reason: VoiceHostRefusal::TooLarge
            }
        );
        settle().await;
        assert!(sideband.written().is_empty());
        // The refusal left no send behind.
        assert!(matches!(
            call.send_context(action(6), send_params(), Support::of(1), OPENED + 1_100)
                .await,
            VoiceContextSendResult::Queued { .. }
        ));
    }

    #[test]
    fn a_heartbeat_answers_the_state_and_the_news_after_its_cursor_and_drops_what_it_acknowledged()
    {
        let (calls, _call, sideband) = held();
        sideband.hear("d1", 1_500);
        sideband.hear("d2", 2_500);

        let (state, remaining, news, dropped) = heartbeat(&calls, 0, 11_000);
        assert_eq!(state, VoiceHostCallState::Open);
        assert_eq!(remaining, 590);
        assert!(!dropped);
        assert_eq!(news.len(), 2);
        assert_eq!(news[0].seq.get(), 1);
        assert_eq!(news[1].seq.get(), 2);

        // The device acknowledges the first: only the second is sent again.
        let (_, _, news, _) = heartbeat(&calls, 1, 31_000);
        assert_eq!(news.len(), 1);
        assert_eq!(news[0].seq.get(), 2);
        // A device that never received the answer asks with the old cursor and is told the news
        // again: the cursor only moves when an answer arrived.
        let (_, _, again, _) = heartbeat(&calls, 1, 31_500);
        assert_eq!(again, news);
        let (_, _, none, _) = heartbeat(&calls, 2, 51_000);
        assert!(none.is_empty());
    }

    #[test]
    fn a_news_queue_that_overflowed_says_dropped_until_the_device_has_caught_up() {
        let (calls, _call, sideband) = held();
        for index in 0..=HOST_NEWS_LIMIT {
            sideband.hear(&format!("d{index}"), 100);
        }
        // 65 items into a queue of 64: the first was lost.
        let (_, _, news, dropped) = heartbeat(&calls, 0, 11_000);
        assert_eq!(news.len(), HOST_NEWS_LIMIT);
        assert_eq!(news[0].seq.get(), 2);
        assert!(dropped, "the device never saw the first item");
        let (_, _, _, dropped) = heartbeat(&calls, 1, 31_000);
        assert!(
            !dropped,
            "a device that has item 1 knows it lost nothing past it"
        );
    }

    #[test]
    fn a_heartbeat_after_the_call_ended_is_answered_from_the_final_status_to_its_own_device_only() {
        let (calls, _call, sideband) = held();
        calls.end(voice_session(1), VoiceEndReason::Deadline, 601_000);
        close(&sideband, SidebandEnd::HostClosed);
        assert!(calls.is_empty());
        assert_eq!(calls.kept_final_statuses(), 1);

        // Another device is not told how the call ended, and does not cause the record to go.
        assert_eq!(
            calls.heartbeat(voice_session(1), device(8), 0, 602_000),
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::NotThisDevice
            }
        );
        let VoiceControlResult::Heartbeat {
            state,
            news,
            remaining_seconds,
            ..
        } = calls.heartbeat(voice_session(1), device(7), 0, 602_000)
        else {
            panic!("a closed answer");
        };
        assert_eq!(
            state,
            VoiceHostCallState::Closed {
                reason: VoiceEndReason::Deadline,
                provider_close: VoiceProviderClose::Confirmed
            }
        );
        assert_eq!(remaining_seconds, 0);
        assert_eq!(
            news.last().map(|item| item.item.clone()),
            Some(VoiceNewsItem::Ended {
                reason: VoiceEndReason::Deadline,
                provider_close: VoiceProviderClose::Confirmed
            })
        );
        // Acknowledging the ended item is the last the host keeps of the call.
        let last = news.last().expect("the ended item").seq.get();
        let _ = calls.heartbeat(voice_session(1), device(7), last, 603_000);
        assert_eq!(calls.kept_final_statuses(), 0);
        assert_eq!(
            calls.heartbeat(voice_session(1), device(7), last, 604_000),
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::UnknownCall
            }
        );
    }

    #[test]
    fn a_final_status_is_forgotten_after_ten_minutes_and_after_sixteen_calls() {
        let calls = HostCalls::new();
        for byte in 0..17u8 {
            let sideband = Sideband::new();
            calls.register(
                voice_session(byte),
                device(7),
                OPENED,
                CLOSES,
                Arc::clone(&sideband) as Arc<dyn HostCallControl>,
            );
            calls.end(voice_session(byte), VoiceEndReason::Stop, 10_000);
            close(&sideband, SidebandEnd::HostClosed);
        }
        assert_eq!(calls.kept_final_statuses(), FINAL_STATUS_RECORDS);
        assert_eq!(
            calls.heartbeat(voice_session(0), device(7), 0, 10_001),
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::UnknownCall
            },
            "the oldest was pushed out"
        );
        assert!(matches!(
            calls.heartbeat(
                voice_session(16),
                device(7),
                0,
                10_000 + FINAL_STATUS_KEEP_MS - 1
            ),
            VoiceControlResult::Heartbeat { .. }
        ));
        assert_eq!(
            calls.heartbeat(
                voice_session(15),
                device(7),
                0,
                10_000 + FINAL_STATUS_KEEP_MS
            ),
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::UnknownCall
            },
            "ten minutes after the end the record is gone"
        );
    }

    #[test]
    fn a_call_ends_once_and_the_first_reason_stands() {
        let (calls, _call, sideband) = held();
        sideband.tell(HostCallEvent::State(SidebandState::Closed(
            SidebandEnd::ProviderClosed,
        )));
        calls.end(voice_session(1), VoiceEndReason::Stop, 5_000);
        let VoiceControlResult::Heartbeat { state, .. } =
            calls.heartbeat(voice_session(1), device(7), 0, 6_000)
        else {
            panic!("a closed answer");
        };
        assert_eq!(
            state,
            VoiceHostCallState::Closed {
                reason: VoiceEndReason::ProviderClosed,
                provider_close: VoiceProviderClose::Confirmed
            }
        );
        assert_eq!(calls.kept_final_statuses(), 1);
    }

    #[test]
    fn a_heartbeat_is_answered_in_every_state_of_the_side_channel() {
        let (calls, _call, sideband) = held();
        sideband.set(SidebandState::Recovering);
        assert_eq!(
            heartbeat(&calls, 0, 11_000).0,
            VoiceHostCallState::Recovering
        );
        sideband.set(SidebandState::Closing);
        assert_eq!(heartbeat(&calls, 0, 12_000).0, VoiceHostCallState::Closing);
        sideband.set(SidebandState::Ready);
        assert_eq!(
            heartbeat(&calls, 0, CLOSES).0,
            VoiceHostCallState::Closing,
            "a call past its deadline is closing, not open"
        );
    }

    #[tokio::test]
    async fn a_mute_is_written_only_while_the_side_channel_is_ready_and_the_call_is_within_its_deadline()
     {
        let (_calls, call, sideband) = held();
        assert!(matches!(
            call.mute(action(1), true, 5_000).await,
            VoiceControlResult::Admitted { .. }
        ));
        assert!(matches!(
            call.mute(action(2), false, 6_000).await,
            VoiceControlResult::Admitted { .. }
        ));
        assert_eq!(
            sideband
                .written()
                .iter()
                .map(|(command, _, _)| *command)
                .collect::<Vec<_>>(),
            [VoiceCommand::Mute, VoiceCommand::Unmute]
        );
        sideband.set(SidebandState::Recovering);
        assert_eq!(
            call.mute(action(3), true, 7_000).await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::NotReady
            }
        );
        sideband.set(SidebandState::Ready);
        assert_eq!(
            call.mute(action(4), true, CLOSES).await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::Closing
            }
        );
        assert_eq!(
            sideband.written().len(),
            2,
            "nothing was written after the refusals"
        );
    }

    #[tokio::test]
    async fn a_note_is_written_by_its_table_once_and_never_after_a_final_for_its_delegation() {
        let (_calls, call, sideband) = held();
        let support = Reads(Ok(String::new()));
        sideband.hear("d1", 100);

        // A call note without a delegation goes as instructions, once.
        let told = call
            .note(
                action(1),
                VoiceNote::HostActionsAvailable,
                None,
                &support,
                5_000,
            )
            .await;
        assert_eq!(admitted_note(&told), Some(VoiceNote::HostActionsAvailable));
        assert_eq!(
            call.note(
                action(2),
                VoiceNote::HostActionsAvailable,
                None,
                &support,
                5_001
            )
            .await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::AlreadyTold
            }
        );
        // A note about a delegation names one the side channel heard, and goes as commentary.
        assert_eq!(
            call.note(
                action(3),
                VoiceNote::DelegationUnknown,
                Some("never"),
                &support,
                5_002
            )
            .await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::UnknownDelegation
            }
        );
        assert_eq!(
            call.note(
                action(4),
                VoiceNote::DelegationUnknown,
                None,
                &support,
                5_003
            )
            .await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::UnknownDelegation
            },
            "a delegation note without a delegation"
        );
        assert_eq!(
            call.note(
                action(5),
                VoiceNote::HostActionsUnavailable,
                Some("d1"),
                &support,
                5_004
            )
            .await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::NotSupportedByRecord
            },
            "a call note that names a delegation"
        );
        // A non-final note, then a final one, then nothing.
        assert!(matches!(
            call.note(
                action(6),
                VoiceNote::DelegationUnknown,
                Some("d1"),
                &support,
                5_005
            )
            .await,
            VoiceControlResult::Admitted { .. }
        ));
        assert!(matches!(
            call.note(
                action(7),
                VoiceNote::DelegationRefused,
                Some("d1"),
                &support,
                5_006
            )
            .await,
            VoiceControlResult::Admitted { .. }
        ));
        for note in [VoiceNote::DelegationNotSent, VoiceNote::DelegationRefused] {
            assert_eq!(
                call.note(action(8), note, Some("d1"), &support, 5_007)
                    .await,
                VoiceControlResult::Refused {
                    reason: VoiceHostRefusal::AlreadyTold
                }
            );
        }
        let written = sideband.written();
        assert_eq!(written.len(), 3);
        assert_eq!(
            written[0],
            (
                VoiceCommand::Instructions,
                None,
                Some(VoiceNote::HostActionsAvailable.words().to_owned())
            )
        );
        assert_eq!(
            written[1],
            (
                VoiceCommand::Commentary,
                Some("d1".to_owned()),
                Some(VoiceNote::DelegationUnknown.words().to_owned())
            )
        );
        // The three notes about the phone's contact with the host are the managed control's.
        assert_eq!(
            call.note(action(9), VoiceNote::HostLost, None, &support, 5_008)
                .await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::NotSupportedByRecord
            }
        );
    }

    #[tokio::test]
    async fn a_note_whose_words_are_both_instructions_and_commentary_writes_both() {
        let (_calls, call, sideband) = held();
        let support = Reads(Ok(String::new()));
        call.note(action(1), VoiceNote::SpeechTainted, None, &support, 5_000)
            .await;
        let commands: Vec<VoiceCommand> = sideband
            .written()
            .iter()
            .map(|(command, _, _)| *command)
            .collect();
        assert_eq!(
            commands,
            [VoiceCommand::Instructions, VoiceCommand::Commentary]
        );
    }

    #[tokio::test]
    async fn an_outcome_note_the_hosts_record_does_not_support_is_refused_and_a_performed_one_carries_a_fresh_summary_within_500_bytes()
     {
        let (_calls, call, sideband) = held();
        sideband.hear("d1", 100);
        sideband.hear("d2", 200);
        let support = Reads(Ok("one file changed".to_owned()));

        // No record of a performed delegation: nothing to say it was performed.
        assert_eq!(
            call.note(
                action(1),
                VoiceNote::DelegationPerformed,
                Some("d1"),
                &support,
                5_000
            )
            .await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::UnknownDelegation
            }
        );
        // A record of an admission does not support "performed".
        recorded(
            &call,
            "d1",
            VoiceDelegateResult {
                outcome: VoiceDelegationOutcome::Admitted {
                    action_id: action(9),
                    note: "admitted".to_owned(),
                },
                ..performed("")
            },
        );
        assert_eq!(
            call.note(
                action(2),
                VoiceNote::DelegationPerformed,
                Some("d1"),
                &support,
                5_001
            )
            .await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::NotSupportedByRecord
            }
        );
        // A record of a performed delegation does.
        recorded(&call, "d2", performed("old summary"));
        let told = call
            .note(
                action(3),
                VoiceNote::DelegationPerformed,
                Some("d2"),
                &support,
                5_002,
            )
            .await;
        assert_eq!(admitted_note(&told), Some(VoiceNote::DelegationPerformed));
        let written = sideband.written();
        let words = written[0].2.clone().expect("words");
        assert_eq!(
            words,
            format!(
                "{} one file changed",
                VoiceNote::DelegationPerformed.words()
            ),
            "the summary is the fresh one, not the one recorded"
        );
        assert_eq!(written[0].1.as_deref(), Some("d2"));

        // A long summary is cut at a character boundary, so the words are at most 500 bytes.
        let long = "é".repeat(400);
        let words = performed_words(&long);
        assert!(words.len() <= HOST_PERFORMED_WORDS_BYTES);
        assert!(words.starts_with(VoiceNote::DelegationPerformed.words()));
        assert!(std::str::from_utf8(words.as_bytes()).is_ok());
    }

    #[tokio::test]
    async fn a_performed_note_after_the_grants_narrowed_writes_nothing_and_stays_owed() {
        let (_calls, call, sideband) = held();
        sideband.hear("d1", 100);
        recorded(&call, "d1", performed("old summary"));
        let narrowed = Reads(Err(VoiceHostRefusal::OutsideGrant));
        assert_eq!(
            call.note(
                action(1),
                VoiceNote::DelegationPerformed,
                Some("d1"),
                &narrowed,
                5_000
            )
            .await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::OutsideGrant
            }
        );
        assert!(sideband.written().is_empty());
        // The refusal did not use up the note: the device may try again when the read works.
        let reads = Reads(Ok("fresh".to_owned()));
        assert!(matches!(
            call.note(
                action(2),
                VoiceNote::DelegationPerformed,
                Some("d1"),
                &reads,
                5_001
            )
            .await,
            VoiceControlResult::Admitted { .. }
        ));
    }

    #[tokio::test]
    async fn a_grant_the_history_bound_or_privacy_moved_between_the_read_and_the_write_writes_nothing_and_stays_owed()
     {
        for moved in [VoiceHostRefusal::OutsideGrant, VoiceHostRefusal::Privacy] {
            let (_calls, call, sideband) = held();
            sideband.hear("d1", 100);
            recorded(&call, "d1", performed("old summary"));
            assert_eq!(
                call.note(
                    action(1),
                    VoiceNote::DelegationPerformed,
                    Some("d1"),
                    &MovesBeforeTheWrite(moved),
                    5_000
                )
                .await,
                VoiceControlResult::Refused { reason: moved }
            );
            assert!(
                sideband.written().is_empty(),
                "nothing was written for {moved:?}"
            );
            // The note was not used up: it is told once the checks pass.
            let reads = Reads(Ok("fresh".to_owned()));
            assert!(matches!(
                call.note(
                    action(2),
                    VoiceNote::DelegationPerformed,
                    Some("d1"),
                    &reads,
                    5_001
                )
                .await,
                VoiceControlResult::Admitted { .. }
            ));
        }
    }

    /// The call's deadline is read when the write is about to go, not when the note came: a read
    /// that ends after the deadline writes nothing.
    #[tokio::test]
    async fn a_performed_note_whose_read_ends_after_the_calls_deadline_is_not_written() {
        let (_calls, call, sideband) = held();
        sideband.hear("d1", 100);
        recorded(&call, "d1", performed("old summary"));
        assert_eq!(
            call.note(
                action(1),
                VoiceNote::DelegationPerformed,
                Some("d1"),
                &ReadsPastTheDeadline,
                5_000
            )
            .await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::Closing
            }
        );
        assert!(sideband.written().is_empty());
    }

    /// The pace refuses the note that the phone is silent: it is kept, written on a later pass
    /// once the pace allows it, and told once.
    #[tokio::test]
    async fn a_silent_note_the_pace_refuses_is_kept_and_written_once_the_pace_allows_it() {
        let (calls, _call, sideband) = held();
        sideband.rate_refuses.store(true, Ordering::SeqCst);
        assert!(calls.tick(OPENED + 45_000).await.is_empty());
        assert!(sideband.written().is_empty(), "the pace refused the note");
        sideband.rate_refuses.store(false, Ordering::SeqCst);
        assert!(calls.tick(OPENED + 50_000).await.is_empty());
        let written = sideband.written();
        assert_eq!(
            written.len(),
            1,
            "the kept note is written on the next pass"
        );
        assert_eq!(written[0].2.as_deref(), Some(HostNote::PhoneSilent.words()));
        assert!(calls.tick(OPENED + 55_000).await.is_empty());
        assert_eq!(sideband.written().len(), 1, "told once");
    }

    /// The pace refuses the note that the phone is back: it is owed, and the next request or the
    /// next pass of the tick writes it, once.
    #[tokio::test]
    async fn a_back_note_the_pace_refuses_is_owed_and_written_by_the_next_request_or_pass_once() {
        let owed_then_paid = |by_the_tick: bool| async move {
            let (calls, call, sideband) = held();
            assert!(calls.tick(OPENED + 45_000).await.is_empty());
            assert_eq!(sideband.written().len(), 1, "the silent note");
            sideband.rate_refuses.store(true, Ordering::SeqCst);
            call.phone_is_back(OPENED + 70_000).await;
            assert_eq!(
                sideband.written().len(),
                1,
                "the pace refused the back note"
            );
            sideband.rate_refuses.store(false, Ordering::SeqCst);
            if by_the_tick {
                assert!(calls.tick(OPENED + 75_000).await.is_empty());
            } else {
                call.phone_is_back(OPENED + 71_000).await;
            }
            let written = sideband.written();
            assert_eq!(written.len(), 2);
            assert_eq!(written[1].2.as_deref(), Some(HostNote::PhoneBack.words()));
            call.phone_is_back(OPENED + 76_000).await;
            assert!(calls.tick(OPENED + 77_000).await.is_empty());
            assert_eq!(sideband.written().len(), 2, "told once");
        };
        owed_then_paid(false).await;
        owed_then_paid(true).await;
    }

    /// A note refused while the side channel recovers is not counted as told: it is kept, and
    /// written once the channel is ready again.
    #[tokio::test]
    async fn a_note_refused_while_the_channel_recovers_is_kept_and_written_when_it_is_back() {
        let (calls, call, sideband) = held();
        // The silent note meets a channel that is not ready.
        sideband.set(SidebandState::Recovering);
        assert!(calls.tick(OPENED + 45_000).await.is_empty());
        assert!(sideband.written().is_empty(), "the channel was not ready");
        sideband.set(SidebandState::Ready);
        assert!(calls.tick(OPENED + 50_000).await.is_empty());
        let written = sideband.written();
        assert_eq!(
            written.len(),
            1,
            "the kept note is written once the channel is ready"
        );
        assert_eq!(written[0].2.as_deref(), Some(HostNote::PhoneSilent.words()));
        // The back note meets a channel that is not ready.
        sideband.set(SidebandState::Recovering);
        call.phone_is_back(OPENED + 70_000).await;
        assert_eq!(sideband.written().len(), 1, "the channel was not ready");
        sideband.set(SidebandState::Ready);
        call.phone_is_back(OPENED + 71_000).await;
        let written = sideband.written();
        assert_eq!(written.len(), 2);
        assert_eq!(written[1].2.as_deref(), Some(HostNote::PhoneBack.words()));
        assert!(calls.tick(OPENED + 72_000).await.is_empty());
        call.phone_is_back(OPENED + 73_000).await;
        assert_eq!(sideband.written().len(), 2, "told once");
    }

    /// A request and a pass of the tick that meet while the owed back note is written write it
    /// once between them.
    #[tokio::test]
    async fn a_tick_and_a_request_that_meet_write_the_owed_back_note_once() {
        let (calls, call, sideband) = held();
        assert!(calls.tick(OPENED + 45_000).await.is_empty());
        assert_eq!(sideband.written().len(), 1, "the silent note");
        sideband.rate_refuses.store(true, Ordering::SeqCst);
        call.phone_is_back(OPENED + 70_000).await;
        assert_eq!(
            sideband.written().len(),
            1,
            "the pace refused the back note"
        );
        sideband.rate_refuses.store(false, Ordering::SeqCst);
        // Both reach the side channel before either write is let through.
        let gate = Arc::new(tokio::sync::Notify::new());
        *sideband.gate.lock().expect("the gate") = Some(Arc::clone(&gate));
        let pass = calls.tick(OPENED + 75_000);
        let request = call.phone_is_back(OPENED + 76_000);
        let open = async {
            settle().await;
            gate.notify_waiters();
        };
        let (_, (), ()) = tokio::join!(pass, request, open);
        let backs = sideband
            .written()
            .iter()
            .filter(|(_, _, words)| words.as_deref() == Some(HostNote::PhoneBack.words()))
            .count();
        assert_eq!(backs, 1, "the owed note is written once");

        // The same on a fresh call, with the request first: it is the request that claims the
        // owed note, and the pass that finds it claimed.
        let (calls, call, sideband) = held();
        assert!(calls.tick(OPENED + 45_000).await.is_empty());
        assert_eq!(sideband.written().len(), 1, "the silent note");
        sideband.rate_refuses.store(true, Ordering::SeqCst);
        call.phone_is_back(OPENED + 70_000).await;
        assert_eq!(
            sideband.written().len(),
            1,
            "the pace refused the back note"
        );
        sideband.rate_refuses.store(false, Ordering::SeqCst);
        let gate = Arc::new(tokio::sync::Notify::new());
        *sideband.gate.lock().expect("the gate") = Some(Arc::clone(&gate));
        let request = call.phone_is_back(OPENED + 76_000);
        let pass = calls.tick(OPENED + 75_000);
        let open = async {
            settle().await;
            gate.notify_waiters();
        };
        let ((), _, ()) = tokio::join!(request, pass, open);
        let backs = sideband
            .written()
            .iter()
            .filter(|(_, _, words)| words.as_deref() == Some(HostNote::PhoneBack.words()))
            .count();
        assert_eq!(
            backs, 1,
            "the owed note is written once when the request is first"
        );
    }

    #[tokio::test]
    async fn a_delegation_is_announced_only_when_the_side_channel_heard_it() {
        let (_calls, call, sideband) = held();
        assert!(!call.announced("d1").await);
        sideband.hear("d1", 100);
        assert!(call.announced("d1").await);
        assert!(!call.announced("d2").await);
    }

    #[tokio::test]
    async fn a_note_the_provider_refused_to_take_is_still_owed() {
        let (_calls, call, sideband) = held();
        let support = Reads(Ok(String::new()));
        sideband.refuses.store(true, Ordering::SeqCst);
        assert_eq!(
            call.note(
                action(1),
                VoiceNote::HostActionsAvailable,
                None,
                &support,
                5_000
            )
            .await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::ProviderRefused
            }
        );
        // Nothing reached the model, so the note was not told: asking again is not a repeat.
        sideband.refuses.store(false, Ordering::SeqCst);
        assert_eq!(
            admitted_note(
                &call
                    .note(
                        action(2),
                        VoiceNote::HostActionsAvailable,
                        None,
                        &support,
                        5_001
                    )
                    .await
            ),
            Some(VoiceNote::HostActionsAvailable)
        );
        assert_eq!(sideband.written().len(), 1);
    }

    #[tokio::test]
    async fn a_phone_silent_for_two_heartbeats_is_told_to_the_model_once_and_a_request_after_it_tells_it_back()
     {
        let (calls, call, sideband) = held();
        // Nothing yet: the first heartbeat is not due.
        assert!(calls.tick(OPENED + 44_000).await.is_empty());
        assert!(sideband.written().is_empty());
        // Two beats and the margin: told once, and not again.
        assert!(calls.tick(OPENED + 45_000).await.is_empty());
        assert!(calls.tick(OPENED + 60_000).await.is_empty());
        let written = sideband.written();
        assert_eq!(written.len(), 1);
        assert_eq!(
            written[0],
            (
                VoiceCommand::Instructions,
                None,
                Some(HostNote::PhoneSilent.words().to_owned())
            )
        );
        // A request from the phone tells the model it is back, and only once.
        call.phone_is_back(OPENED + 70_000).await;
        call.phone_is_back(OPENED + 71_000).await;
        let written = sideband.written();
        assert_eq!(written.len(), 2);
        assert_eq!(written[1].2.as_deref(), Some(HostNote::PhoneBack.words()));
        // A phone not heard from for 120 seconds is one the caller begins closing.
        assert_eq!(
            calls.tick(OPENED + 71_000 + 120_000).await,
            vec![voice_session(1)]
        );
    }

    #[test]
    fn a_late_provider_refusal_reaches_the_device_as_news_naming_its_action() {
        let (calls, call, sideband) = held();
        let write_id = call.next_write_id(Some(action(5)));
        sideband.tell(HostCallEvent::WriteRefused {
            write_id: write_id.clone(),
        });
        // A refusal of a write the host never admitted names nothing.
        sideband.tell(HostCallEvent::WriteRefused {
            write_id: "host-99".to_owned(),
        });
        let (_, _, news, _) = heartbeat(&calls, 0, 11_000);
        assert_eq!(news.len(), 1);
        assert_eq!(
            news[0].item,
            VoiceNewsItem::LateRefusal {
                action_id: action(5),
                reason: VoiceHostRefusal::ProviderRefused
            }
        );
        // An acknowledged write is not refused later.
        let acknowledged = call.next_write_id(Some(action(6)));
        sideband.tell(HostCallEvent::WriteAcknowledged {
            write_id: acknowledged.clone(),
        });
        sideband.tell(HostCallEvent::WriteRefused {
            write_id: acknowledged,
        });
        assert_eq!(heartbeat(&calls, 1, 12_000).2.len(), 0);
    }

    /// `heard` is bound to a call that is ready and within its deadline, as a write is: a call that
    /// is recovering or past its deadline answers a refusal, not what it heard.
    #[tokio::test]
    async fn heard_is_refused_unless_the_call_is_ready_and_within_its_deadline() {
        let (_calls, call, sideband) = held();
        sideband.hear("d1", 1_234);
        sideband.set(SidebandState::Recovering);
        assert_eq!(
            call.heard("d1", 5_000).await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::NotReady
            }
        );
        sideband.set(SidebandState::Ready);
        assert_eq!(
            call.heard("d1", CLOSES).await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::Closing
            }
        );
        assert_eq!(
            call.heard("d1", 5_000).await,
            VoiceControlResult::Heard {
                offset_ms: U64::new(1_234)
            }
        );
    }

    /// A mute meets the pace the context send holds the call to, because the call keeps one
    /// history for every command the provider counts.
    #[tokio::test(start_paused = true)]
    async fn a_mute_meets_the_pace_the_context_send_holds_the_call_to() {
        let (_calls, call, sideband) = held();
        let _ = call
            .send_context(action(5), send_params(), Support::of(14), OPENED + 1_000)
            .await;
        for _ in 0..10 {
            settle().await;
            sideband.acknowledge_all();
        }
        settle().await;
        assert_eq!(sideband.written().len(), 10, "the burst");
        assert_eq!(
            call.mute(action(6), true, OPENED + 2_000).await,
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::Rate
            }
        );
        assert_eq!(sideband.written().len(), 10, "the mute was not written");
    }

    #[tokio::test]
    async fn heard_answers_the_offset_or_not_heard() {
        let (_calls, call, sideband) = held();
        assert_eq!(call.heard("d1", 5_000).await, VoiceControlResult::NotHeard);
        sideband.hear("d1", 1_234);
        assert_eq!(
            call.heard("d1", 5_001).await,
            VoiceControlResult::Heard {
                offset_ms: U64::new(1_234)
            }
        );
    }

    #[test]
    fn a_call_the_host_does_not_hold_is_unknown_and_another_devices_is_not_this_one() {
        let (calls, _call, _sideband) = held();
        assert!(calls.of_device(voice_session(1), device(7)).is_ok());
        assert_eq!(
            calls.of_device(voice_session(1), device(8)).unwrap_err(),
            VoiceHostRefusal::NotThisDevice
        );
        assert_eq!(
            calls.of_device(voice_session(2), device(7)).unwrap_err(),
            VoiceHostRefusal::UnknownCall
        );
    }

    /// The channel closes, as the side channel tells it.
    fn close(sideband: &Sideband, end: SidebandEnd) {
        sideband.set(SidebandState::Closed(end));
        sideband.tell(HostCallEvent::State(SidebandState::Closed(end)));
    }

    fn ended_item(
        reason: VoiceEndReason,
        provider_close: VoiceProviderClose,
        seq: u64,
    ) -> VoiceNews {
        VoiceNews {
            seq: U64::new(seq),
            item: VoiceNewsItem::Ended {
                reason,
                provider_close,
            },
        }
    }

    fn closing() -> VoiceControlResult {
        VoiceControlResult::Refused {
            reason: VoiceHostRefusal::Closing,
        }
    }

    /// A call whose end is recorded is held until its side channel reports the close: it answers
    /// `closing`, tells no `ended` item, and the phone's liveness is not stamped.
    #[test]
    fn a_host_end_inside_the_deadline_is_closing_until_the_side_channel_reports_the_close() {
        let (calls, call, _sideband) = held();
        calls.end(voice_session(1), VoiceEndReason::Silence, OPENED + 3_000);
        let (state, remaining, news, _) = heartbeat(&calls, 0, OPENED + 4_000);
        assert_eq!(state, VoiceHostCallState::Closing);
        assert!(remaining > 0, "the call is inside its deadline");
        assert!(
            !news
                .iter()
                .any(|item| matches!(item.item, VoiceNewsItem::Ended { .. })),
            "no ended item before the close is reported"
        );
        assert_eq!(calls.kept_final_statuses(), 0);
        assert_eq!(calls.len(), 1);
        assert_eq!(call.state().last_beat_ms, OPENED, "no liveness stamped");
    }

    #[test]
    fn a_call_whose_end_is_recorded_is_refused_as_closing_to_its_device() {
        let (calls, _call, _sideband) = held();
        calls.end(voice_session(1), VoiceEndReason::Silence, OPENED + 3_000);
        assert_eq!(
            calls.of_device(voice_session(1), device(7)).unwrap_err(),
            VoiceHostRefusal::Closing
        );
        assert_eq!(
            calls.of_device(voice_session(1), device(8)).unwrap_err(),
            VoiceHostRefusal::NotThisDevice
        );
    }

    /// A caller that held the call before its end was recorded writes nothing after it, and the
    /// phone is not woken: no stamp and no note, whatever the channel reads.
    #[tokio::test]
    async fn a_held_call_refuses_every_write_once_its_end_is_recorded() {
        for channel in [SidebandState::Ready, SidebandState::Recovering] {
            let (calls, call, sideband) = held();
            // The model was told that the phone is silent before the end.
            assert!(calls.tick(OPENED + 45_000).await.is_empty());
            let written = sideband.written();
            assert_eq!(written.len(), 1, "the silence note");
            calls.end(voice_session(1), VoiceEndReason::Silence, OPENED + 46_000);
            sideband.set(channel);
            let beat = call.state().last_beat_ms;
            let support = Reads(Ok("a summary".to_owned()));
            assert_eq!(
                call.mute(action(1), true, OPENED + 47_000).await,
                closing(),
                "{channel:?}"
            );
            assert_eq!(
                call.note(
                    action(2),
                    VoiceNote::HostActionsAvailable,
                    None,
                    &support,
                    OPENED + 47_001
                )
                .await,
                closing(),
                "{channel:?}"
            );
            assert_eq!(
                call.send_context(action(3), send_params(), Support::of(1), OPENED + 47_002)
                    .await,
                VoiceContextSendResult::Refused {
                    reason: VoiceHostRefusal::Closing
                },
                "{channel:?}"
            );
            assert_eq!(
                call.heard("d1", OPENED + 47_003).await,
                closing(),
                "{channel:?}"
            );
            assert_eq!(
                sideband.written(),
                written,
                "nothing was written after the end, the back note included ({channel:?})"
            );
            assert_eq!(
                call.state().last_beat_ms,
                beat,
                "no liveness stamped ({channel:?})"
            );
        }
        // A channel that closed whose event was not told yet: the call is closing, not unknown.
        let (_calls, call, sideband) = held();
        sideband.set(SidebandState::Closed(SidebandEnd::Lost));
        assert_eq!(call.mute(action(1), true, OPENED + 2_000).await, closing());
        assert!(sideband.written().is_empty());
    }

    #[test]
    fn a_recovering_channel_with_a_recorded_end_answers_closing_and_stamps_no_liveness() {
        let (calls, call, sideband) = held();
        sideband.set(SidebandState::Recovering);
        calls.end(voice_session(1), VoiceEndReason::Revocation, OPENED + 3_000);
        let (state, _, _, _) = heartbeat(&calls, 0, OPENED + 4_000);
        assert_eq!(state, VoiceHostCallState::Closing);
        assert_eq!(call.state().last_beat_ms, OPENED, "no liveness stamped");
    }

    /// The wait for a close that is never reported is one minute from the end, and a tick that
    /// finds it over tells the end as it stands.
    #[tokio::test]
    async fn an_end_whose_close_never_reports_settles_after_the_wait() {
        let (calls, _call, sideband) = held();
        let t0 = OPENED + 3_000;
        calls.end(voice_session(1), VoiceEndReason::Revocation, t0);
        assert!(calls.tick(t0 + 59_999).await.is_empty());
        assert_eq!((calls.len(), calls.kept_final_statuses()), (1, 0));
        assert!(calls.tick(t0 + 60_000).await.is_empty());
        assert_eq!((calls.len(), calls.kept_final_statuses()), (0, 1));
        // A close that is reported after the wait changes nothing.
        close(&sideband, SidebandEnd::HostClosed);
        assert_eq!(calls.kept_final_statuses(), 1);
        let (state, ..) = heartbeat(&calls, 0, t0 + 60_001);
        assert_eq!(
            state,
            VoiceHostCallState::Closed {
                reason: VoiceEndReason::Revocation,
                provider_close: VoiceProviderClose::Unconfirmed
            }
        );
        assert_eq!(FINAL_STATUS_CLOSE_WAIT_MS, 60_000);
    }

    /// A heartbeat that finds the channel closed settles the call and answers `closed` with the
    /// matching `ended` item in the same reply, though the close was never told.
    #[test]
    fn a_heartbeat_settles_a_call_whose_close_event_was_missed_and_answers_closed_in_the_same_reply()
     {
        let (calls, _call, sideband) = held();
        sideband.set(SidebandState::Closed(SidebandEnd::HostClosed));
        assert_eq!(
            calls.heartbeat(voice_session(1), device(7), 0, OPENED + 2_000),
            VoiceControlResult::Heartbeat {
                state: VoiceHostCallState::Closed {
                    reason: VoiceEndReason::Stop,
                    provider_close: VoiceProviderClose::Confirmed
                },
                remaining_seconds: 0,
                news: vec![ended_item(
                    VoiceEndReason::Stop,
                    VoiceProviderClose::Confirmed,
                    1
                )],
                dropped: false,
            }
        );
        assert_eq!(calls.len(), 0);
        assert_eq!(calls.kept_final_statuses(), 1);
        // The device's acknowledgement of that reply is the last the host keeps of the call.
        let _ = calls.heartbeat(voice_session(1), device(7), 1, OPENED + 3_000);
        assert_eq!(calls.kept_final_statuses(), 0);
    }

    /// The same for a wait that ran out: the heartbeat that finds it over answers `closed`.
    #[test]
    fn a_heartbeat_settles_an_expired_wait_and_answers_closed_in_the_same_reply() {
        let calls = HostCalls::new();
        for byte in [1u8, 2] {
            calls.register(
                voice_session(byte),
                device(7),
                OPENED,
                CLOSES,
                Sideband::new(),
            );
        }
        let t0 = OPENED + 3_000;
        for byte in [1u8, 2] {
            calls.end(voice_session(byte), VoiceEndReason::Revocation, t0);
        }
        let beat = |byte: u8, at: u64| calls.heartbeat(voice_session(byte), device(7), 0, at);
        assert!(matches!(
            beat(1, t0 + 59_999),
            VoiceControlResult::Heartbeat {
                state: VoiceHostCallState::Closing,
                ..
            }
        ));
        assert_eq!(
            beat(2, t0 + 60_000),
            VoiceControlResult::Heartbeat {
                state: VoiceHostCallState::Closed {
                    reason: VoiceEndReason::Revocation,
                    provider_close: VoiceProviderClose::Unconfirmed
                },
                remaining_seconds: 0,
                news: vec![ended_item(
                    VoiceEndReason::Revocation,
                    VoiceProviderClose::Unconfirmed,
                    1
                )],
                dropped: false,
            }
        );
        assert_eq!(calls.len(), 1, "the other call is still held");
    }

    #[test]
    fn a_channel_that_closed_before_registration_is_settled_by_registration() {
        let calls = HostCalls::new();
        let sideband = Sideband::new();
        sideband.set(SidebandState::Closed(SidebandEnd::Lost));
        calls.register(
            voice_session(1),
            device(7),
            OPENED,
            CLOSES,
            Arc::clone(&sideband) as Arc<dyn HostCallControl>,
        );
        assert_eq!(calls.len(), 0);
        assert_eq!(calls.kept_final_statuses(), 1);
        let (state, ..) = heartbeat(&calls, 0, OPENED + 1_000);
        assert_eq!(
            state,
            VoiceHostCallState::Closed {
                reason: VoiceEndReason::SidebandLost,
                provider_close: VoiceProviderClose::Unconfirmed
            }
        );
    }

    /// A channel that tells its close to the listener the moment it is set, and whose state the
    /// registration then reads closed, gives one status and one `ended` item.
    #[test]
    fn a_close_told_by_listen_and_seen_by_the_registration_snapshot_gives_one_status() {
        let calls = HostCalls::new();
        let sideband = Sideband::new();
        sideband.set(SidebandState::Closed(SidebandEnd::Lost));
        *sideband.tells_on_listen.lock().expect("the end") = Some(SidebandEnd::Lost);
        calls.register(
            voice_session(1),
            device(7),
            OPENED,
            CLOSES,
            Arc::clone(&sideband) as Arc<dyn HostCallControl>,
        );
        assert_eq!(calls.len(), 0);
        assert_eq!(calls.kept_final_statuses(), 1);
        let (_, _, news, _) = heartbeat(&calls, 0, OPENED + 1_000);
        assert_eq!(
            news,
            vec![ended_item(
                VoiceEndReason::SidebandLost,
                VoiceProviderClose::Unconfirmed,
                1
            )]
        );
    }

    #[tokio::test]
    async fn a_closed_channel_whose_event_was_never_told_settles_on_the_next_tick() {
        let (calls, _call, sideband) = held();
        sideband.set(SidebandState::Closed(SidebandEnd::HostClosed));
        assert!(calls.tick(OPENED + 2_000).await.is_empty());
        assert_eq!(calls.len(), 0);
        assert_eq!(calls.kept_final_statuses(), 1);
    }

    #[test]
    fn an_end_decided_after_the_channel_closed_settles_at_once() {
        let (calls, _call, sideband) = held();
        sideband.set(SidebandState::Closed(SidebandEnd::HostClosed));
        calls.end(voice_session(1), VoiceEndReason::Deadline, OPENED + 3_000);
        assert_eq!(calls.len(), 0);
        assert_eq!(calls.kept_final_statuses(), 1);
        let (state, ..) = heartbeat(&calls, 0, OPENED + 4_000);
        assert_eq!(
            state,
            VoiceHostCallState::Closed {
                reason: VoiceEndReason::Deadline,
                provider_close: VoiceProviderClose::Confirmed
            }
        );
    }

    /// A second end changes neither the reason nor the time the status is kept from.
    #[tokio::test]
    async fn a_second_end_with_another_reason_changes_neither_the_reason_nor_the_time() {
        let (calls, _call, _sideband) = held();
        let t0 = OPENED + 3_000;
        calls.end(voice_session(1), VoiceEndReason::Deadline, t0);
        calls.end(voice_session(1), VoiceEndReason::Revocation, t0 + 10_000);
        assert!(calls.tick(t0 + 60_000).await.is_empty());
        let (state, ..) = heartbeat(&calls, 0, t0 + FINAL_STATUS_KEEP_MS - 1);
        assert_eq!(
            state,
            VoiceHostCallState::Closed {
                reason: VoiceEndReason::Deadline,
                provider_close: VoiceProviderClose::Unconfirmed
            }
        );
        assert_eq!(
            calls.heartbeat(voice_session(1), device(7), 0, t0 + FINAL_STATUS_KEEP_MS),
            VoiceControlResult::Refused {
                reason: VoiceHostRefusal::UnknownCall
            },
            "kept from the first end, not from the second or from the settlement"
        );
    }

    /// The end wakes a sender that waits for its pace, and the sender stops before the channel
    /// reports anything: the clock does not move, so only the wake can have stopped it.
    #[tokio::test(start_paused = true)]
    async fn a_recorded_end_wakes_a_waiting_sender_and_stops_it_before_the_channel_reports() {
        let (calls, call, sideband) = held();
        let _ = call
            .send_context(action(5), send_params(), Support::of(14), OPENED + 1_000)
            .await;
        for _ in 0..10 {
            settle().await;
            sideband.acknowledge_all();
        }
        settle().await;
        assert_eq!(sideband.written().len(), 10, "the burst");
        let holders = Arc::strong_count(&call);
        calls.end(voice_session(1), VoiceEndReason::Stop, OPENED + 3_000);
        settle().await;
        assert_eq!(
            Arc::strong_count(&call),
            holders - 1,
            "the sender task ended with no step of the clock"
        );
        let (state, _, news, _) = heartbeat(&calls, 0, OPENED + 4_000);
        assert_eq!(state, VoiceHostCallState::Closing);
        assert!(news.iter().any(|item| matches!(
            item.item,
            VoiceNewsItem::Context {
                state: VoiceContextState::Stopped {
                    stopped_by: VoiceContextStop::Stop
                },
                ..
            }
        )));
    }

    /// A recorded end with an append written and not answered, and the channel's close after it:
    /// one unconfirmed append, and the stop is the recorded reason's.
    #[tokio::test(start_paused = true)]
    async fn a_recorded_end_with_an_append_in_flight_then_the_channels_close_counts_one_unconfirmed_and_stops_with_the_recorded_reason()
     {
        let (calls, call, sideband) = held();
        let _ = call
            .send_context(action(5), send_params(), Support::of(2), OPENED + 1_000)
            .await;
        settle().await;
        assert_eq!(sideband.written().len(), 1);
        calls.end(voice_session(1), VoiceEndReason::Stop, OPENED + 1_500);
        settle().await;
        close(&sideband, SidebandEnd::HostClosed);
        settle().await;
        assert_eq!(
            context_news(&calls),
            [VoiceNewsItem::Context {
                action_id: action(5),
                appended: 0,
                of: 3,
                unconfirmed: 1,
                state: VoiceContextState::Stopped {
                    stopped_by: VoiceContextStop::Stop
                }
            }]
        );
    }

    /// A channel that ended the call alone, found by a heartbeat that no event announced, counts
    /// the append it never answered once.
    #[tokio::test(start_paused = true)]
    async fn a_channel_only_end_found_by_a_heartbeat_counts_an_unanswered_append_once() {
        let (calls, call, sideband) = held();
        let _ = call
            .send_context(action(5), send_params(), Support::of(2), OPENED + 1_000)
            .await;
        settle().await;
        assert_eq!(sideband.written().len(), 1);
        sideband.set(SidebandState::Closed(SidebandEnd::Lost));
        let _ = calls.heartbeat(voice_session(1), device(7), 0, OPENED + 1_500);
        settle().await;
        assert_eq!(
            context_news(&calls),
            [VoiceNewsItem::Context {
                action_id: action(5),
                appended: 0,
                of: 3,
                unconfirmed: 1,
                state: VoiceContextState::Stopped {
                    stopped_by: VoiceContextStop::SidebandLost
                }
            }]
        );
    }

    /// An end the coordinator recorded as the provider's close is its inference: the channel's own
    /// end gives the reason.
    #[test]
    fn a_recorded_provider_closed_takes_its_reason_from_the_channel() {
        let (calls, _call, sideband) = held();
        sideband.set(SidebandState::Closed(SidebandEnd::Lost));
        calls.end(
            voice_session(1),
            VoiceEndReason::ProviderClosed,
            OPENED + 3_000,
        );
        let (state, ..) = heartbeat(&calls, 0, OPENED + 4_000);
        assert_eq!(
            state,
            VoiceHostCallState::Closed {
                reason: VoiceEndReason::SidebandLost,
                provider_close: VoiceProviderClose::Unconfirmed
            }
        );
    }

    /// A heartbeat that meets another thread's settlement between its two locks, when the call is
    /// settled and the registry does not hold the status yet, answers `closed` with zero time left
    /// and the matching `ended` item.
    #[test]
    fn a_heartbeat_that_meets_a_settlement_between_its_two_locks_answers_closed_with_the_matching_ended_item()
     {
        let (calls, call, sideband) = held();
        sideband.set(SidebandState::Closed(SidebandEnd::HostClosed));
        let (arrived, go) = call.between_the_locks.arm();
        let settler = {
            let call = Arc::clone(&call);
            std::thread::spawn(move || call.settle(Some(SidebandEnd::HostClosed)))
        };
        arrived
            .recv()
            .expect("the settling thread reached the pause");
        assert_eq!(calls.len(), 1, "the registry has not taken the call out");
        assert_eq!(calls.kept_final_statuses(), 0, "nor taken the status in");
        assert_eq!(
            calls.heartbeat(voice_session(1), device(7), 0, OPENED + 2_000),
            VoiceControlResult::Heartbeat {
                state: VoiceHostCallState::Closed {
                    reason: VoiceEndReason::Stop,
                    provider_close: VoiceProviderClose::Confirmed
                },
                remaining_seconds: 0,
                news: vec![ended_item(
                    VoiceEndReason::Stop,
                    VoiceProviderClose::Confirmed,
                    1
                )],
                dropped: false,
            }
        );
        go.send(()).expect("the settling thread waits");
        settler.join().expect("the settling thread");
        assert_eq!(calls.len(), 0);
        assert_eq!(calls.kept_final_statuses(), 1);
    }

    /// The call answers `closed` from the status it kept itself when the registry cannot take it.
    #[test]
    fn a_settled_call_answers_closed_from_its_own_copy_when_the_registry_is_gone() {
        let (calls, call, sideband) = held();
        drop(calls);
        close(&sideband, SidebandEnd::Lost);
        assert_eq!(
            call.heartbeat(0, OPENED + 2_000).result,
            VoiceControlResult::Heartbeat {
                state: VoiceHostCallState::Closed {
                    reason: VoiceEndReason::SidebandLost,
                    provider_close: VoiceProviderClose::Unconfirmed
                },
                remaining_seconds: 0,
                news: vec![ended_item(
                    VoiceEndReason::SidebandLost,
                    VoiceProviderClose::Unconfirmed,
                    1
                )],
                dropped: false,
            }
        );
    }

    /// A back note that was claimed before the end is recorded is not written after it.
    #[tokio::test]
    async fn a_back_note_claimed_before_the_end_is_not_written_after_it() {
        let (calls, call, sideband) = held();
        assert!(calls.tick(OPENED + 45_000).await.is_empty());
        let written = sideband.written();
        assert_eq!(written.len(), 1, "the silence note");
        calls.end(voice_session(1), VoiceEndReason::Silence, OPENED + 46_000);
        call.tell_that_the_phone_is_back().await;
        assert_eq!(sideband.written(), written);
        assert!(
            !call.state().back_owed,
            "nothing is owed to a call that ended"
        );
    }

    /// Every `provider_close` word a result carries, read from its wire form, in the order the
    /// wire form lists its members.
    fn provider_closes(result: &VoiceControlResult) -> Vec<String> {
        fn walk(value: &serde_json::Value, found: &mut Vec<String>) {
            match value {
                serde_json::Value::Object(members) => {
                    for (name, member) in members {
                        match (name.as_str(), member) {
                            ("provider_close", serde_json::Value::String(word)) => {
                                found.push(word.clone());
                            }
                            _ => walk(member, found),
                        }
                    }
                }
                serde_json::Value::Array(items) => items.iter().for_each(|item| walk(item, found)),
                _ => {}
            }
        }
        let mut found = Vec::new();
        walk(
            &serde_json::to_value(result).expect("a result serialises"),
            &mut found,
        );
        found
    }

    /// Both places that carry the word, the `ended` item and the `closed` state, carry the same.
    fn the_word_of(result: &VoiceControlResult) -> String {
        let words = provider_closes(result);
        assert_eq!(
            words.len(),
            2,
            "the ended item and the closed state: {words:?}"
        );
        assert_eq!(words[0], words[1]);
        words[0].clone()
    }

    #[test]
    fn every_end_reason_is_told_with_the_confirmation_of_the_close() {
        for reason in [
            VoiceEndReason::Stop,
            VoiceEndReason::Deadline,
            VoiceEndReason::Revocation,
            VoiceEndReason::Silence,
            VoiceEndReason::CredentialRemoved,
        ] {
            for (end, word) in [
                (SidebandEnd::HostClosed, "confirmed"),
                (SidebandEnd::Lost, "unconfirmed"),
            ] {
                let (calls, _call, sideband) = held();
                calls.end(voice_session(1), reason, OPENED + 3_000);
                close(&sideband, end);
                let answer = calls.heartbeat(voice_session(1), device(7), 0, OPENED + 4_000);
                let (state, ..) = match &answer {
                    VoiceControlResult::Heartbeat { state, .. } => (*state, ()),
                    other => panic!("a heartbeat answer: {other:?}"),
                };
                assert!(
                    matches!(state, VoiceHostCallState::Closed { reason: told, .. } if told == reason),
                    "{reason:?} {end:?}: {state:?}"
                );
                assert_eq!(the_word_of(&answer), word, "{reason:?} {end:?}");
            }
        }
    }

    #[test]
    fn a_channel_that_ends_the_call_alone_tells_its_own_confirmation() {
        for (end, reason, word) in [
            (
                SidebandEnd::ProviderClosed,
                VoiceEndReason::ProviderClosed,
                "confirmed",
            ),
            (SidebandEnd::HostClosed, VoiceEndReason::Stop, "confirmed"),
            (
                SidebandEnd::Lost,
                VoiceEndReason::SidebandLost,
                "unconfirmed",
            ),
        ] {
            let (calls, _call, sideband) = held();
            close(&sideband, end);
            let answer = calls.heartbeat(voice_session(1), device(7), 0, OPENED + 2_000);
            assert!(
                matches!(&answer, VoiceControlResult::Heartbeat { state: VoiceHostCallState::Closed { reason: told, .. }, .. } if *told == reason),
                "{end:?}: {answer:?}"
            );
            assert_eq!(the_word_of(&answer), word, "{end:?}");
        }
        // An end the coordinator recorded as the provider's close takes the channel's word.
        let (calls, _call, sideband) = held();
        sideband.set(SidebandState::Closed(SidebandEnd::Lost));
        calls.end(
            voice_session(1),
            VoiceEndReason::ProviderClosed,
            OPENED + 3_000,
        );
        let answer = calls.heartbeat(voice_session(1), device(7), 0, OPENED + 4_000);
        assert_eq!(the_word_of(&answer), "unconfirmed");
    }

    /// A close that is never reported is told as not confirmed, whatever the reason.
    #[tokio::test]
    async fn a_timed_out_close_is_told_unconfirmed() {
        for reason in [VoiceEndReason::Revocation, VoiceEndReason::ProviderClosed] {
            let (calls, _call, _sideband) = held();
            let t0 = OPENED + 3_000;
            calls.end(voice_session(1), reason, t0);
            assert!(calls.tick(t0 + 60_000).await.is_empty());
            let answer = calls.heartbeat(voice_session(1), device(7), 0, t0 + 60_001);
            assert!(
                matches!(&answer, VoiceControlResult::Heartbeat { state: VoiceHostCallState::Closed { reason: told, .. }, .. } if *told == reason),
                "{answer:?}"
            );
            assert_eq!(the_word_of(&answer), "unconfirmed", "{reason:?}");
        }
    }
}
