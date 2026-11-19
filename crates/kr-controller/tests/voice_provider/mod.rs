//! A managed voice service that answers without a network call, for the suites that drive the
//! daemon's own voice service. It quotes no terms, creates calls it never meters, and records the
//! calls it was told to close.

#![allow(
    dead_code,
    reason = "each suite that includes this module uses the part of it that it needs"
)]

use kr_client::services::ServiceFuture;
use kr_client::services::voice::{
    VoiceClosure, VoiceHold, VoiceProviderService, VoiceProviderTerms, VoiceRateQuote,
    VoiceSession, VoiceSessionRequest, VoiceStart, VoiceStartLatency,
};

/// A provider that answers without a network call.
#[derive(Debug, Default)]
pub struct OfflineProvider {
    closed: std::sync::Mutex<Vec<String>>,
    /// How many calls it has created, each of which a managed service would meter.
    started: std::sync::atomic::AtomicUsize,
    /// Where a start waits before it answers, for a provider that holds its starts.
    gate: Option<BrokerGate>,
}

/// Where a held start waits: it says it has arrived, then waits to be let go.
#[derive(Debug, Default)]
pub struct BrokerGate {
    reached: tokio::sync::Notify,
    released: tokio::sync::Notify,
}

impl OfflineProvider {
    /// A provider that holds every start until the test lets it answer, the way a broker that is
    /// slow to create a call holds the start waiting for it.
    pub fn holding() -> Self {
        Self {
            gate: Some(BrokerGate::default()),
            ..Self::default()
        }
    }

    /// The calls this provider was told to close.
    pub fn closed(&self) -> Vec<String> {
        self.closed.lock().expect("what was closed").clone()
    }

    /// How many calls this provider has created.
    pub fn started(&self) -> usize {
        self.started.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Waits until a start has arrived and is being held.
    pub async fn reached(&self) {
        self.gate
            .as_ref()
            .expect("a provider that holds its starts")
            .reached
            .notified()
            .await;
    }

    /// Lets the start being held answer.
    pub fn release(&self) {
        self.gate
            .as_ref()
            .expect("a provider that holds its starts")
            .released
            .notify_one();
    }
}

impl VoiceProviderService for OfflineProvider {
    fn terms(&self) -> ServiceFuture<'_, VoiceProviderTerms> {
        // This stand-in quotes nothing. The test that needs the service's terms scripts the
        // service's own wire instead, so what it proves is what a real answer does.
        Box::pin(async move { Ok(VoiceProviderTerms::Unquoted) })
    }

    fn account_bound(&self) -> bool {
        true
    }

    fn call_is_open<'a>(&'a self, _call_id: &'a str) -> ServiceFuture<'a, bool> {
        // Nothing here can say, so the call is held open until its own deadline.
        Box::pin(async move { Ok(true) })
    }

    fn provider(&self) -> String {
        "the offline provider".to_owned()
    }

    fn begin<'a>(
        &'a self,
        _request: &'a VoiceSessionRequest,
    ) -> ServiceFuture<'a, kr_client::services::StartAttempt> {
        Box::pin(async { Ok(kr_client::services::StartAttempt::none()) })
    }

    fn abandon<'a>(&'a self, _attempt: kr_client::services::StartAttempt) -> ServiceFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn dispatch<'a>(
        &'a self,
        _attempt: kr_client::services::StartAttempt,
        _request: &'a VoiceSessionRequest,
    ) -> ServiceFuture<'a, VoiceStart> {
        Box::pin(async move {
            if let Some(gate) = &self.gate {
                gate.reached.notify_one();
                gate.released.notified().await;
            }
            self.started
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(VoiceStart::Started(Box::new(VoiceSession {
                call_id: "call-1".to_owned(),
                attempt_id: "attempt-1".to_owned(),
                provider_session_id: "sess_1".to_owned(),
                answer_sdp: "v=0\r\n".to_owned(),
                model: "gpt-live-1".to_owned(),
                closes_at: "2026-09-20T01:00:00Z".to_owned(),
                reservation_ends_at: "2026-09-20T01:00:15Z".to_owned(),
                control_path: "/api/voice/sessions/call-1/control".to_owned(),
                heartbeat_seconds: 20,
                sideband_ready: true,
                hold: VoiceHold {
                    reservation_id: "hold-1".to_owned(),
                    reserved: "600".to_owned(),
                    ceiling: "500".to_owned(),
                    deadline: "2026-09-20T01:00:15Z".to_owned(),
                },
                reasoning_hold: None,
                rate: VoiceRateQuote {
                    version: "2026-09".to_owned(),
                    minor_units_per_second: "1".to_owned(),
                    minimum_seconds: 15,
                    currency: "USD".to_owned(),
                },
                latency: VoiceStartLatency {
                    creation_to_answer_ms: 10,
                    sideband_ready_ms: 5,
                },
                replayed: false,
                disclosure: Vec::new(),
            })))
        })
    }

    fn close<'a>(&'a self, call_id: &'a str) -> ServiceFuture<'a, VoiceClosure> {
        self.closed
            .lock()
            .expect("what was closed")
            .push(call_id.to_owned());
        let call_id = call_id.to_owned();
        Box::pin(async move {
            Ok(VoiceClosure {
                call_id,
                state: "finalised".to_owned(),
                usage_seconds: 0,
                usage_provisional: true,
            })
        })
    }
}

/// What the host wrote to a side channel: the command's wire word, the delegation it named and its
/// text.
pub type Written = Vec<(String, Option<String>, Option<String>)>;

/// A side channel the test steers: what the host wrote to it, what it says it has heard, and
/// where it stands. It tells the host's listener when it closes.
pub struct StandInSideband {
    written: std::sync::Mutex<Written>,
    heard: std::sync::Mutex<std::collections::BTreeMap<String, u64>>,
    state: std::sync::Mutex<kr_client::services::host_call::SidebandState>,
    listener: std::sync::Mutex<Option<kr_client::services::host_call::HostCallListener>>,
}

impl Default for StandInSideband {
    fn default() -> Self {
        Self {
            written: std::sync::Mutex::default(),
            heard: std::sync::Mutex::default(),
            state: std::sync::Mutex::new(kr_client::services::host_call::SidebandState::Ready),
            listener: std::sync::Mutex::new(None),
        }
    }
}

impl std::fmt::Debug for StandInSideband {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StandInSideband")
    }
}

impl StandInSideband {
    /// Closes the channel as `end` and tells the host's listener, as the provider's side channel
    /// does when the call's close is reported.
    pub fn close(&self, end: kr_client::services::host_call::SidebandEnd) {
        use kr_client::services::host_call::{HostCallEvent, SidebandState};
        *self.state.lock().expect("the state") = SidebandState::Closed(end);
        let listener = self.listener.lock().expect("the listener").clone();
        if let Some(listener) = listener {
            listener(HostCallEvent::State(SidebandState::Closed(end)));
        }
    }

    /// Makes the side channel say it heard `delegation_id`, `offset_ms` into the call.
    pub fn hear(&self, delegation_id: &str, offset_ms: u64) {
        self.heard
            .lock()
            .expect("what was heard")
            .insert(delegation_id.to_owned(), offset_ms);
    }

    /// What the host wrote: the command's wire word, the delegation it named and its text.
    pub fn written(&self) -> Written {
        self.written.lock().expect("what was written").clone()
    }
}

impl kr_client::services::host_call::HostCallControl for StandInSideband {
    fn state(&self) -> kr_client::services::host_call::SidebandState {
        *self.state.lock().expect("the state")
    }

    fn revision(&self) -> u64 {
        1
    }

    fn write<'a>(
        &'a self,
        _revision: u64,
        frame: kr_client::services::voice::VoiceContextFrame,
    ) -> kr_client::services::host_call::HostFuture<
        'a,
        Result<(), kr_client::services::host_call::WriteRefusal>,
    > {
        self.written.lock().expect("what was written").push((
            frame.command.as_str().to_owned(),
            frame.delegation_id.clone(),
            frame.content.clone(),
        ));
        Box::pin(async { Ok(()) })
    }

    fn next_write_at(&self) -> Option<tokio::time::Instant> {
        None
    }

    fn heard(&self, delegation_id: &str) -> Option<u64> {
        self.heard
            .lock()
            .expect("what was heard")
            .get(delegation_id)
            .copied()
    }

    fn heard_within<'a>(
        &'a self,
        delegation_id: &'a str,
        _within: std::time::Duration,
    ) -> kr_client::services::host_call::HostFuture<'a, Option<u64>> {
        let heard = self.heard(delegation_id);
        Box::pin(async move { heard })
    }

    fn listen(&self, listener: kr_client::services::host_call::HostCallListener) {
        *self.listener.lock().expect("the listener") = Some(listener);
    }
}

/// What the stand-in's side channel reports when its provider is told to close a call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CloseReport {
    /// The close is confirmed: the channel closes as the host's own close.
    #[default]
    Confirmed,
    /// The channel is lost: it closes unconfirmed.
    Lost,
    /// The channel reports nothing.
    Nothing,
}

/// A provider for a call on the owner's own key: it quotes a held key, spends it, answers a start
/// with a call the host controls, and shows one side channel for each call, which reports the
/// call's close as the test scripts it.
#[derive(Debug, Default)]
pub struct OwnKeyStandIn {
    closed: std::sync::Mutex<Vec<String>>,
    sidebands:
        std::sync::Mutex<std::collections::BTreeMap<String, std::sync::Arc<StandInSideband>>>,
    started: std::sync::atomic::AtomicUsize,
    report: std::sync::Mutex<CloseReport>,
}

impl OwnKeyStandIn {
    /// The calls this provider was told to close.
    pub fn closed(&self) -> Vec<String> {
        self.closed.lock().expect("what was closed").clone()
    }

    /// The side channel of the call it started last.
    pub fn sideband(&self) -> std::sync::Arc<StandInSideband> {
        let sidebands = self.sidebands.lock().expect("the side channels");
        std::sync::Arc::clone(
            sidebands
                .values()
                .next_back()
                .expect("a call was started, so a side channel is shown"),
        )
    }

    /// What the side channels report from now on when their call is closed.
    pub fn reports(&self, report: CloseReport) {
        *self.report.lock().expect("the report") = report;
    }
}

impl VoiceProviderService for OwnKeyStandIn {
    fn terms(&self) -> ServiceFuture<'_, VoiceProviderTerms> {
        Box::pin(async move {
            Ok(VoiceProviderTerms::OwnKey(
                kr_client::services::voice::VoiceOwnKeyTerms {
                    model: "gpt-live-1".to_owned(),
                    disclosure: vec![
                        "This call runs on the OpenAI key set on this host.".to_owned(),
                    ],
                    held: true,
                },
            ))
        })
    }

    fn account_bound(&self) -> bool {
        false
    }

    fn spends_the_owners_key(&self) -> bool {
        true
    }

    fn call_is_open<'a>(&'a self, _call_id: &'a str) -> ServiceFuture<'a, bool> {
        Box::pin(async move { Ok(true) })
    }

    fn provider(&self) -> String {
        "openai_live".to_owned()
    }

    fn host_control(
        &self,
        call_id: &str,
    ) -> Option<std::sync::Arc<dyn kr_client::services::host_call::HostCallControl>> {
        let sideband = self
            .sidebands
            .lock()
            .expect("the side channels")
            .get(call_id)
            .cloned()?;
        Some(sideband as std::sync::Arc<dyn kr_client::services::host_call::HostCallControl>)
    }

    fn begin<'a>(
        &'a self,
        _request: &'a VoiceSessionRequest,
    ) -> ServiceFuture<'a, kr_client::services::StartAttempt> {
        Box::pin(async { Ok(kr_client::services::StartAttempt::none()) })
    }

    fn abandon<'a>(&'a self, _attempt: kr_client::services::StartAttempt) -> ServiceFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn dispatch<'a>(
        &'a self,
        _attempt: kr_client::services::StartAttempt,
        request: &'a VoiceSessionRequest,
    ) -> ServiceFuture<'a, VoiceStart> {
        let closes_at_ms = kr_ipc::now_ms().get() + u64::from(request.duration_seconds) * 1_000;
        // Every call has its own identifier and its own side channel.
        let number = self
            .started
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let call_id = format!("own-{number}");
        self.sidebands
            .lock()
            .expect("the side channels")
            .insert(call_id.clone(), std::sync::Arc::default());
        Box::pin(async move {
            Ok(VoiceStart::StartedOwn(Box::new(
                kr_client::services::voice::OwnSession {
                    call_id,
                    provider_session_id: "sess_own_1".to_owned(),
                    answer_sdp: "v=0\r\n".to_owned(),
                    model: "gpt-live-1".to_owned(),
                    closes_at_ms,
                    disclosure: Vec::new(),
                },
            )))
        })
    }

    fn close<'a>(&'a self, call_id: &'a str) -> ServiceFuture<'a, VoiceClosure> {
        self.closed
            .lock()
            .expect("what was closed")
            .push(call_id.to_owned());
        // The provider reports the close to the call's side channel before it answers.
        let sideband = self
            .sidebands
            .lock()
            .expect("the side channels")
            .get(call_id)
            .cloned();
        let report = *self.report.lock().expect("the report");
        if let Some(sideband) = sideband {
            use kr_client::services::host_call::SidebandEnd;
            match report {
                CloseReport::Confirmed => sideband.close(SidebandEnd::HostClosed),
                CloseReport::Lost => sideband.close(SidebandEnd::Lost),
                CloseReport::Nothing => {}
            }
        }
        let call_id = call_id.to_owned();
        Box::pin(async move {
            Ok(VoiceClosure {
                call_id,
                state: "closed".to_owned(),
                usage_seconds: 0,
                usage_provisional: false,
            })
        })
    }
}
