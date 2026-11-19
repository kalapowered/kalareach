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

use kr_client::services::host_call::{
    HostCallControl, HostCallEvent, SidebandEnd, SidebandState, WriteRefusal,
};
use kr_client::services::voice::{VoiceCommand, VoiceContextFrame};
use kr_protocol::ids::{ActionId, DeviceId, VoiceSessionId};
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::voice::{VoiceDelegateParams, VoiceDelegateResult, VoiceDelegationOutcome};
use kr_protocol::voice_host::{
    HOST_CLIENT_ABSENT_SECONDS, HOST_HEARD_WAIT_MS, HOST_HEARTBEAT_SECONDS, HOST_NEWS_LIMIT,
    HOST_PERFORMED_WORDS_BYTES, HostNote, NotePhase, VoiceControlResult, VoiceEndReason,
    VoiceHostCallState, VoiceHostRefusal, VoiceNews, VoiceNewsItem, VoiceNote,
};

/// The most calls whose final status the host keeps after they end.
pub const FINAL_STATUS_RECORDS: usize = 16;

/// How long the host keeps a call's final status after it ends, unless the device acknowledges it.
pub const FINAL_STATUS_KEEP_MS: u64 = 10 * 60 * 1_000;

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
}

/// What one delegation has been told to the model.
#[derive(Debug, Default)]
struct Told {
    sentences: BTreeSet<VoiceNote>,
    finished: bool,
}

#[derive(Debug)]
struct CallState {
    next_seq: u64,
    news: VecDeque<VoiceNews>,
    dropped_through: u64,
    last_beat_ms: u64,
    silent_told: bool,
    delegations: BTreeMap<String, DelegationRecord>,
    told: BTreeMap<Option<String>, Told>,
    call_notes: BTreeSet<VoiceNote>,
    writes: VecDeque<(String, ActionId)>,
    write_count: u64,
    ended: Option<VoiceEndReason>,
}

/// One call on the owner's own key, as the host holds it.
pub struct HostCall {
    voice_session_id: VoiceSessionId,
    device_id: DeviceId,
    closes_at_ms: u64,
    control: Arc<dyn HostCallControl>,
    state: Mutex<CallState>,
    calls: Weak<Shared>,
}

impl std::fmt::Debug for HostCall {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostCall")
            .field("voice_session_id", &self.voice_session_id)
            .finish_non_exhaustive()
    }
}

struct Kept {
    status: FinalStatus,
    ended_ms: u64,
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
                delegations: BTreeMap::new(),
                told: BTreeMap::new(),
                call_notes: BTreeSet::new(),
                writes: VecDeque::new(),
                write_count: 0,
                ended: None,
            }),
            calls: Arc::downgrade(&self.shared),
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
        call
    }

    /// The call a device controls, or why it may not.
    ///
    /// # Errors
    ///
    /// [`VoiceHostRefusal::UnknownCall`] when the host holds no such call and kept no final status
    /// for it, and [`VoiceHostRefusal::NotThisDevice`] when it is another device's.
    pub fn of_device(
        &self,
        voice_session_id: VoiceSessionId,
        device_id: DeviceId,
    ) -> Result<Arc<HostCall>, VoiceHostRefusal> {
        let registry = self.registry();
        match registry.calls.get(&voice_session_id) {
            Some(call) if call.device_id == device_id => Ok(Arc::clone(call)),
            Some(_) => Err(VoiceHostRefusal::NotThisDevice),
            None => Err(VoiceHostRefusal::UnknownCall),
        }
    }

    /// Ends a call: its final status is kept, in memory, for [`FINAL_STATUS_KEEP_MS`], and the call
    /// is no longer one the host holds. Called before the call's grant is revoked.
    pub fn end(&self, voice_session_id: VoiceSessionId, reason: VoiceEndReason, now_ms: u64) {
        let call = self.registry().calls.get(&voice_session_id).cloned();
        if let Some(call) = call {
            call.finish(reason, now_ms);
        }
    }

    /// Answers a heartbeat.
    ///
    /// A call that is held answers its state and its news. A call that ended answers `closed` from
    /// the final status, to its own device alone, until the device acknowledges the `ended` item or
    /// the record is [`FINAL_STATUS_KEEP_MS`] old. After that it is unknown.
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
                return call.heartbeat(after_seq, now_ms);
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
                },
                remaining_seconds: 0,
                news,
                dropped: false,
            }
        }
    }

    /// The calls whose phone has not been heard from for [`HOST_CLIENT_ABSENT_SECONDS`]: the
    /// caller begins their closure. A phone silent for two beats is told to the model, once.
    pub async fn tick(&self, now_ms: u64) -> Vec<VoiceSessionId> {
        let calls: Vec<Arc<HostCall>> = self.registry().calls.values().cloned().collect();
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
                if let Some(at) = state.writes.iter().position(|(id, _)| *id == write_id) {
                    state.writes.remove(at);
                }
            }
            HostCallEvent::State(SidebandState::Closed(end)) => {
                let reason = match end {
                    SidebandEnd::ProviderClosed => VoiceEndReason::ProviderClosed,
                    SidebandEnd::HostClosed => VoiceEndReason::Stop,
                    SidebandEnd::Lost => VoiceEndReason::SidebandLost,
                };
                self.finish(reason, self.last_seen_ms());
            }
            HostCallEvent::State(_) => {}
        }
    }

    fn last_seen_ms(&self) -> u64 {
        self.state().last_beat_ms
    }

    /// Records the end of the call and hands its final status to the registry. The first reason
    /// stands: a call ends once.
    fn finish(&self, reason: VoiceEndReason, now_ms: u64) {
        let status = {
            let mut state = self.state();
            if state.ended.is_some() {
                return;
            }
            state.ended = Some(reason);
            Self::push_news(&mut state, VoiceNewsItem::Ended { reason });
            FinalStatus {
                voice_session_id: self.voice_session_id,
                device_id: self.device_id,
                reason,
                news: state.news.iter().cloned().collect(),
                last_seq: state.next_seq - 1,
            }
        };
        let Some(shared) = self.calls.upgrade() else {
            return;
        };
        let mut registry = shared.registry.lock().expect("the host call registry");
        registry.calls.remove(&self.voice_session_id);
        registry.finals.push_back(Kept {
            status,
            ended_ms: now_ms,
        });
        while registry.finals.len() > FINAL_STATUS_RECORDS {
            registry.finals.pop_front();
        }
    }

    fn call_state(&self, now_ms: u64) -> VoiceHostCallState {
        match self.control.state() {
            SidebandState::Ready if now_ms < self.closes_at_ms => VoiceHostCallState::Open,
            SidebandState::Ready | SidebandState::Closing => VoiceHostCallState::Closing,
            SidebandState::Recovering => VoiceHostCallState::Recovering,
            SidebandState::Closed(end) => VoiceHostCallState::Closed {
                reason: match end {
                    SidebandEnd::ProviderClosed => VoiceEndReason::ProviderClosed,
                    SidebandEnd::HostClosed => VoiceEndReason::Stop,
                    SidebandEnd::Lost => VoiceEndReason::SidebandLost,
                },
            },
        }
    }

    /// Answers a heartbeat: stamps the phone's liveness while the call is open or recovering,
    /// drops the news the device acknowledged and returns the rest.
    fn heartbeat(&self, after_seq: u64, now_ms: u64) -> VoiceControlResult {
        let call_state = self.call_state(now_ms);
        let mut state = self.state();
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
        VoiceControlResult::Heartbeat {
            state: call_state,
            remaining_seconds: u32::try_from(self.closes_at_ms.saturating_sub(now_ms) / 1_000)
                .unwrap_or(u32::MAX),
            news,
            dropped,
        }
    }

    /// Runs the phone-absence rules. Returns true when the phone has been silent long enough that
    /// the caller begins closing the call.
    async fn tick(&self, now_ms: u64) -> bool {
        let (silent_for, tell) = {
            let mut state = self.state();
            if state.ended.is_some() {
                return false;
            }
            let silent_for = now_ms.saturating_sub(state.last_beat_ms);
            let tell = silent_for >= SILENT_AFTER_MS && !state.silent_told;
            if tell {
                state.silent_told = true;
            }
            (silent_for, tell)
        };
        if tell {
            let id = self.next_write_id(None);
            if let Ok(frame) = VoiceContextFrame::new(
                id,
                VoiceCommand::Instructions,
                None,
                Some(HostNote::PhoneSilent.words().to_owned()),
            ) {
                let _ = self.control.write(self.control.revision(), frame).await;
            }
        }
        silent_for >= u64::from(HOST_CLIENT_ABSENT_SECONDS) * 1_000
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
    /// once. Every control arm but the heartbeat calls it, as does the heartbeat itself.
    pub async fn phone_is_back(&self, now_ms: u64) {
        let was_silent = {
            let mut state = self.state();
            let was = state.silent_told;
            state.silent_told = false;
            state.last_beat_ms = now_ms;
            was
        };
        if was_silent {
            let id = self.next_write_id(None);
            if let Ok(frame) = VoiceContextFrame::new(
                id,
                VoiceCommand::Instructions,
                None,
                Some(HostNote::PhoneBack.words().to_owned()),
            ) {
                let _ = self.control.write(self.control.revision(), frame).await;
            }
        }
    }

    fn writable(&self, now_ms: u64) -> Result<u64, VoiceHostRefusal> {
        match self.call_state(now_ms) {
            VoiceHostCallState::Open => Ok(self.control.revision()),
            VoiceHostCallState::Recovering => Err(VoiceHostRefusal::NotReady),
            VoiceHostCallState::Closing => Err(VoiceHostRefusal::Closing),
            VoiceHostCallState::Closed { .. } => Err(VoiceHostRefusal::UnknownCall),
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

    /// Answers `heard`: where the host's own side channel heard the delegation, within five
    /// seconds, or that it has not.
    pub async fn heard(&self, delegation_id: &str, now_ms: u64) -> VoiceControlResult {
        self.phone_is_back(now_ms).await;
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
            match support.fresh_summary(record).await {
                Ok(summary) => performed_words(&summary),
                Err(reason) => return refused(reason),
            }
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
    use kr_protocol::voice::VoiceDelegationId;

    use super::*;

    /// What was written: the command, the delegation it named and its text.
    type Written = Vec<(VoiceCommand, Option<String>, Option<String>)>;

    /// A side channel the test steers: its state, what it has heard and what was written to it.
    struct Sideband {
        state: Mutex<SidebandState>,
        heard: Mutex<BTreeMap<String, u64>>,
        written: Mutex<Written>,
        listener: Mutex<Option<HostCallListener>>,
        revision: AtomicU64,
        refuses: std::sync::atomic::AtomicBool,
    }

    impl Sideband {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(SidebandState::Ready),
                heard: Mutex::new(BTreeMap::new()),
                written: Mutex::new(Vec::new()),
                listener: Mutex::new(None),
                revision: AtomicU64::new(1),
                refuses: std::sync::atomic::AtomicBool::new(false),
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
                self.written.lock().expect("written").push((
                    frame.command,
                    frame.delegation_id.clone(),
                    frame.content.clone(),
                ));
                Ok(())
            })
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
            *self.listener.lock().expect("the listener") = Some(listener);
        }
    }

    /// What a performed delegation's summary reads as now, or why it cannot be read.
    struct Reads(Result<String, VoiceHostRefusal>);

    impl NoteSupport for Reads {
        fn fresh_summary<'a>(
            &'a self,
            _record: &'a DelegationRecord,
        ) -> HostFuture<'a, Result<String, VoiceHostRefusal>> {
            let answer = self.0.clone();
            Box::pin(async move { answer })
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
        let (calls, _call, _sideband) = held();
        calls.end(voice_session(1), VoiceEndReason::Deadline, 601_000);
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
                reason: VoiceEndReason::Deadline
            }
        );
        assert_eq!(remaining_seconds, 0);
        assert_eq!(
            news.last().map(|item| item.item.clone()),
            Some(VoiceNewsItem::Ended {
                reason: VoiceEndReason::Deadline
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
            calls.register(voice_session(byte), device(7), OPENED, CLOSES, sideband);
            calls.end(voice_session(byte), VoiceEndReason::Stop, 10_000);
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
                reason: VoiceEndReason::ProviderClosed
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
}
