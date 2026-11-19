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

/// A side channel the test steers: what the host wrote to it, and what it says it has heard.
#[derive(Debug, Default)]
pub struct StandInSideband {
    written: std::sync::Mutex<Written>,
}

impl StandInSideband {
    /// What the host wrote: the command's wire word, the delegation it named and its text.
    pub fn written(&self) -> Written {
        self.written.lock().expect("what was written").clone()
    }
}

impl kr_client::services::host_call::HostCallControl for StandInSideband {
    fn state(&self) -> kr_client::services::host_call::SidebandState {
        kr_client::services::host_call::SidebandState::Ready
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

    fn heard(&self, _delegation_id: &str) -> Option<u64> {
        None
    }

    fn heard_within<'a>(
        &'a self,
        _delegation_id: &'a str,
        _within: std::time::Duration,
    ) -> kr_client::services::host_call::HostFuture<'a, Option<u64>> {
        Box::pin(async { None })
    }

    fn listen(&self, _listener: kr_client::services::host_call::HostCallListener) {}
}

/// A provider for a call on the owner's own key: it quotes a held key, spends it, answers a start
/// with a call the host controls, and shows one side channel for it.
#[derive(Debug, Default)]
pub struct OwnKeyStandIn {
    closed: std::sync::Mutex<Vec<String>>,
    sideband: std::sync::Arc<StandInSideband>,
}

impl OwnKeyStandIn {
    /// The calls this provider was told to close.
    pub fn closed(&self) -> Vec<String> {
        self.closed.lock().expect("what was closed").clone()
    }

    /// The side channel it shows for its call.
    pub fn sideband(&self) -> std::sync::Arc<StandInSideband> {
        std::sync::Arc::clone(&self.sideband)
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
        _call_id: &str,
    ) -> Option<std::sync::Arc<dyn kr_client::services::host_call::HostCallControl>> {
        Some(self.sideband() as std::sync::Arc<dyn kr_client::services::host_call::HostCallControl>)
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
        Box::pin(async move {
            Ok(VoiceStart::StartedOwn(Box::new(
                kr_client::services::voice::OwnSession {
                    call_id: "own-1".to_owned(),
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
