//! A managed voice service that answers without a network call, for the suites that drive the
//! daemon's own voice service. It quotes no terms, creates calls it never meters, and records the
//! calls it was told to close.

#![allow(
    dead_code,
    reason = "each suite that includes this module uses the part of it that it needs"
)]

use kr_client::services::ServiceFuture;
use kr_client::services::voice::{
    ManagedVoiceService, VoiceClosure, VoiceHold, VoiceMetadata, VoiceRateQuote, VoiceSession,
    VoiceSessionRequest, VoiceStart, VoiceStartLatency,
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

impl ManagedVoiceService for OfflineProvider {
    fn metadata(&self) -> ServiceFuture<'_, Option<VoiceMetadata>> {
        // This stand-in quotes nothing. The test that needs the service's terms scripts the
        // service's own wire instead, so what it proves is what a real answer does.
        Box::pin(async move { Ok(None) })
    }

    fn call_is_open<'a>(&'a self, _call_id: &'a str) -> ServiceFuture<'a, bool> {
        // Nothing here can say, so the call is held open until its own deadline.
        Box::pin(async move { Ok(true) })
    }

    fn provider(&self) -> String {
        "the offline provider".to_owned()
    }

    fn start<'a>(&'a self, _request: &'a VoiceSessionRequest) -> ServiceFuture<'a, VoiceStart> {
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
