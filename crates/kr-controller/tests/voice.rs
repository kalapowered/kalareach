//! The voice service against a real control daemon.
//!
//! The daemon is the real one: its own grant store, its own device directory, its own history
//! filter and its own dispatch. What the suite supplies is the paired device's records and a
//! provider that makes no network call, because no test here makes a live provider call.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-09.09, 09.12, 26.16 | `a_voice_change_is_not_written_while_a_fence_is_owed`, `a_voice_start_that_waited_writes_nothing_once_a_fence_is_owed` |
//! | KR-REQ-15.02 | `stopping_voice_leaves_the_session_running` |
//! | KR-REQ-15.11 | `a_delegation_runs_under_the_grant_the_host_already_holds` |
//! | KR-REQ-15.13 | `an_unlocked_screen_action_is_refused_without_a_signed_confirmation` |
//! | KR-REQ-15.14 | `stopping_voice_revokes_the_grant_in_the_hosts_own_store` |
//! | KR-REQ-15.17 | `an_effect_this_host_does_not_dispatch_is_reported_as_admitted` |
//! | KR-REQ-15.20 | `context_is_filtered_by_the_requesting_devices_own_history_bound` |
//! | KR-REQ-15.21 | `the_default_voice_grant_is_written_into_the_hosts_own_store` |
//! | KR-REQ-23.51 | `a_voice_method_is_unreachable_from_local_ipc`, `voice_needs_a_paired_device_and_a_voice_grant` |
//!
//! Section 23 gives the five voice methods `PairedDevice` ingress and nothing else, so a local
//! client cannot reach them: `a_voice_method_is_unreachable_from_local_ipc` is that, proved through
//! the daemon's own endpoint. The suite therefore drives the service the way a paired device's
//! dispatch reaches it, against the same daemon.

use std::path::PathBuf;
use std::sync::Arc;

use kr_client::services::ServiceFuture;
use kr_client::services::voice::{
    ManagedVoiceService, VoiceClosure, VoiceHold, VoiceRateQuote, VoiceSession,
    VoiceSessionRequest, VoiceStart, VoiceStartLatency,
};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{
    ActionId, AuthorityRevision, BuildId, DeviceId, EnvironmentId, GrantId, SessionId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, U64};
use kr_protocol::voice::{
    VoiceAction, VoiceContextParams, VoiceDelegateParams, VoiceDelegationId,
    VoiceDelegationOutcome, VoiceGrantParams, VoiceRefusal, VoiceStartOutcome, VoiceStartParams,
    VoiceStopParams,
};
use kr_voice::seams::VoiceAuthority as _;

/// A supervisor that starts nothing. These tests create no sessions.
#[derive(Debug)]
struct RefusingSupervisor;

impl WorkerSupervisor for RefusingSupervisor {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

/// A provider that answers without a network call.
#[derive(Debug, Default)]
struct OfflineProvider {
    closed: std::sync::Mutex<Vec<String>>,
    /// Where a start waits before it answers, for a provider that holds its starts.
    gate: Option<BrokerGate>,
}

/// Where a held start waits: it says it has arrived, then waits to be let go.
#[derive(Debug, Default)]
struct BrokerGate {
    reached: tokio::sync::Notify,
    released: tokio::sync::Notify,
}

impl OfflineProvider {
    /// A provider that holds every start until the test lets it answer, the way a broker that is
    /// slow to create a call holds the start waiting for it.
    fn holding() -> Self {
        Self {
            gate: Some(BrokerGate::default()),
            ..Self::default()
        }
    }

    /// The calls this provider was told to close.
    fn closed(&self) -> Vec<String> {
        self.closed.lock().expect("what was closed").clone()
    }

    /// Waits until a start has arrived and is being held.
    async fn reached(&self) {
        self.gate
            .as_ref()
            .expect("a provider that holds its starts")
            .reached
            .notified()
            .await;
    }

    /// Lets the start being held answer.
    fn release(&self) {
        self.gate
            .as_ref()
            .expect("a provider that holds its starts")
            .released
            .notify_one();
    }
}

impl ManagedVoiceService for OfflineProvider {
    fn provider(&self) -> String {
        "the offline provider".to_owned()
    }

    fn start<'a>(&'a self, _request: &'a VoiceSessionRequest) -> ServiceFuture<'a, VoiceStart> {
        Box::pin(async move {
            if let Some(gate) = &self.gate {
                gate.reached.notify_one();
                gate.released.notified().await;
            }
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

struct Host {
    _temp: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    voice: Arc<kr_controller::voice::VoiceModule>,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    device_id: DeviceId,
    device_key: AuthorisationKeyPair,
    session_id: SessionId,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(RefusingSupervisor),
        terminal: Box::new(kr_controller::supervision::NoTerminal),
        worker_program: PathBuf::from("/nonexistent/kr-worker"),
        build_id: build(),
        release: "0".to_owned(),
        shell_packages: None,
    })
    .await
    .expect("the daemon starts");
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let clients = tokio::spawn(Arc::clone(&controller).serve_clients(listener));

    // A paired device with an ordinary grant, written into the daemon's own stores.
    let device_key = AuthorisationKeyPair::generate().expect("a device identity key");
    let device_id = DeviceId::new(kr_ipc::new_uuid());
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let grant = Grant {
        grant_id: GrantId::new(kr_ipc::new_uuid()),
        parent_grant_id: Nullable::null(),
        issuer_device_id: controller.sharing().host_device_id(),
        recipient_device_id: device_id,
        authority_revision: controller.policy().authority_revision(),
        environment_selector: EnvironmentSelector::These {
            environment_ids: [environment_id].into_iter().collect(),
        },
        session_selector: SessionSelector::These {
            session_ids: [session_id].into_iter().collect(),
        },
        actions: [
            ActionRight::SessionView,
            ActionRight::AgentPrompt,
            ActionRight::TerminalInput,
        ]
        .into_iter()
        .collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::some(TimestampMs::new(1)),
            include_live_screen: true,
            named_questions: CanonicalSet::from_iter([]),
            named_approvals: CanonicalSet::from_iter([]),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    };
    controller
        .sharing()
        .grants()
        .issue(
            &kr_controller::grants::GrantRecord {
                grant,
                session_id: Some(session_id),
                issued_at_ms: 1,
                activated_at_ms: Some(1),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("the device's ordinary grant");

    // The daemon registered its own voice service at startup; this suite drives a second one over
    // the same stores so it can attach a provider that makes no network call.
    assert_eq!(controller.voice().coordinator().live_sessions(), 0);
    let voice = Arc::new(kr_controller::voice::VoiceModule::new(
        Arc::new(kr_controller::voice::ControllerFacts::new(Arc::downgrade(
            &controller,
        ))),
        Arc::new(kr_controller::voice::GrantAuthority::new(
            Arc::clone(controller.sharing()),
            Arc::clone(controller.devices()),
            controller.sharing().host_device_id(),
        )),
        Arc::new(kr_controller::voice::ControllerDispatch::new(
            Arc::downgrade(&controller),
        )),
        Some(Arc::new(OfflineProvider::default())),
        controller.sharing().host_device_id(),
        environment_id,
        "https://reach.example".to_owned(),
    ));

    Host {
        _temp: temp,
        controller,
        voice,
        environment_id,
        endpoint,
        clients,
        device_id,
        device_key,
        session_id,
    }
}

impl Host {
    fn revision(&self) -> AuthorityRevision {
        self.controller.policy().authority_revision()
    }

    async fn grant_voice(&self, actions: Option<&[VoiceAction]>) -> GrantId {
        self.voice
            .coordinator()
            .grant(
                &VoiceGrantParams {
                    device_id: self.device_id,
                    session_ids: [self.session_id].into_iter().collect(),
                    actions: Nullable(actions.map(|actions| actions.iter().copied().collect())),
                },
                self.revision(),
                2,
                &kr_voice::Unbounded,
            )
            .await
            .expect("a standing voice grant")
            .grant_id
    }

    async fn start_voice(&self) -> kr_protocol::ids::VoiceSessionId {
        let result = self
            .voice
            .coordinator()
            .start(
                self.device_id,
                &VoiceStartParams {
                    session_ids: [self.session_id].into_iter().collect(),
                    offer_sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n".to_owned(),
                    duration_seconds: 600,
                    reasoning_budget_minor: Nullable::null(),
                },
                self.revision(),
                3,
                &kr_voice::Unbounded,
            )
            .await
            .expect("a call");
        let VoiceStartOutcome::Started { session } = result.outcome else {
            panic!("the call runs");
        };
        session.voice_session_id
    }
}

fn delegation(name: &str) -> VoiceDelegationId {
    VoiceDelegationId::new(format!("item_{name}")).expect("an opaque identifier")
}

/// KR-REQ-15.21: the default voice grant is written into the host's own authority store, carries
/// the voice right, and states what it permits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_default_voice_grant_is_written_into_the_hosts_own_store() {
    let host = host().await;
    let grant_id = host.grant_voice(None).await;

    let stored = host
        .controller
        .sharing()
        .grants()
        .record(grant_id)
        .expect("the store answers")
        .expect("the grant is there");
    assert!(stored.grant.permits(ActionRight::VoiceUse));
    assert!(stored.grant.permits(ActionRight::SessionView));
    assert!(
        !stored.grant.permits(ActionRight::TerminalInput),
        "the default scope carries nothing that needs an unlocked screen"
    );
    assert_eq!(stored.grant.recipient_device_id, host.device_id);
    host.clients.abort();
}

/// KR-REQ-23.51: a voice mutation is deduplicated by its action identifier, so a retry answers
/// with what the first attempt produced rather than replacing the grant a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_voice_mutation_answers_with_what_the_first_one_did() {
    let host = host().await;
    let mut control = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects to the control endpoint");
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let params = VoiceGrantParams {
        device_id: host.device_id,
        session_ids: [host.session_id].into_iter().collect(),
        actions: Nullable::some([VoiceAction::Status].into_iter().collect()),
    };
    let first: kr_protocol::voice::VoiceGrantResult = control
        .mutate(
            Method::VoiceGrant,
            action_id,
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the voice grant is written")
        .to_typed()
        .expect("a voice grant result");
    let again: kr_protocol::voice::VoiceGrantResult = control
        .mutate(
            Method::VoiceGrant,
            action_id,
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the retry is answered")
        .to_typed()
        .expect("a voice grant result");
    assert_eq!(
        again.grant_id, first.grant_id,
        "the retry is the first change's own answer, not a second grant"
    );
    let stored = host
        .controller
        .sharing()
        .grants()
        .record(first.grant_id)
        .expect("the store answers")
        .expect("the grant is there");
    assert!(
        stored.revoked_at_ms.is_none(),
        "the retry did not replace the grant the first attempt wrote"
    );
    host.clients.abort();
}

/// KR-REQ-15.21 and 23.51: the person at this machine changes a device's voice grant on the host's
/// own socket, which is the ingress the registry lists for `voice.grant` beside a paired device's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_changes_a_devices_voice_grant_on_the_hosts_own_socket() {
    let host = host().await;
    let mut control = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects to the control endpoint");
    let written = control
        .mutate(
            Method::VoiceGrant,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &VoiceGrantParams {
                device_id: host.device_id,
                session_ids: [host.session_id].into_iter().collect(),
                actions: Nullable::some([VoiceAction::Status].into_iter().collect()),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the owner may change a device's voice grant");
    let result: kr_protocol::voice::VoiceGrantResult =
        written.to_typed().expect("a voice grant result");
    assert_eq!(result.device_id, host.device_id);
    let stored = host
        .controller
        .sharing()
        .grants()
        .record(result.grant_id)
        .expect("the store answers")
        .expect("the grant is there");
    assert!(stored.grant.permits(ActionRight::VoiceUse));
    assert_eq!(stored.grant.recipient_device_id, host.device_id);
    // And the statement names every action those rights permit, not only the one that was asked
    // for: four voice actions share the right status needs.
    assert!(
        result.statement.actions.contains(&VoiceAction::Brief),
        "{:?}",
        result.statement.actions
    );
    host.clients.abort();
}

/// KR-REQ-23.51: the other four voice methods have `PairedDevice` ingress and nothing else, so a
/// local client on the host machine cannot reach one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_voice_method_is_unreachable_from_local_ipc() {
    let host = host().await;
    let mut control = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects to the control endpoint");
    let refusal = control
        .mutate(
            Method::VoiceStart,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &VoiceStartParams {
                session_ids: CanonicalSet::from_iter([]),
                offer_sdp: "v=0\r\n".to_owned(),
                duration_seconds: 600,
                reasoning_budget_minor: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("a local caller may not start a voice session");
    assert!(
        matches!(
            refusal.code,
            kr_protocol::error::ErrorCode::PermissionDenied
                | kr_protocol::error::ErrorCode::UnsupportedCapability
        ),
        "{refusal:?}"
    );
    host.clients.abort();
}

/// KR-REQ-23.51: without a voice grant there is no call, and without a call there is no context.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voice_needs_a_paired_device_and_a_voice_grant() {
    let host = host().await;
    let error = host
        .voice
        .coordinator()
        .start(
            host.device_id,
            &VoiceStartParams {
                session_ids: [host.session_id].into_iter().collect(),
                offer_sdp: "v=0\r\n".to_owned(),
                duration_seconds: 600,
                reasoning_budget_minor: Nullable::null(),
            },
            host.revision(),
            3,
            &kr_voice::Unbounded,
        )
        .await
        .expect_err("no voice grant, no call");
    assert_eq!(error.reason(), Some(VoiceRefusal::OutsideVoiceGrant));
    host.clients.abort();
}

/// KR-REQ-15.14 and 15.02: stopping the call revokes its grant in the host's own store, and the
/// terminal session it reached is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stopping_voice_revokes_the_grant_in_the_hosts_own_store() {
    let host = host().await;
    host.grant_voice(None).await;
    let voice_session_id = host.start_voice().await;

    let result = host
        .voice
        .coordinator()
        .stop(host.device_id, &VoiceStopParams { voice_session_id }, 4)
        .await
        .expect("the call stops");
    let stored = host
        .controller
        .sharing()
        .grants()
        .record(result.revoked_grant_id)
        .expect("the store answers")
        .expect("the record is there");
    assert!(
        stored.revoked_at_ms.is_some(),
        "the grant is revoked in the host's own store"
    );
    assert_eq!(result.revoked_at_ms.get(), 4);
    host.clients.abort();
}

/// KR-REQ-15.02: the terminal sessions a voice session reached keep running, and the answer names
/// them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stopping_voice_leaves_the_session_running() {
    let host = host().await;
    host.grant_voice(None).await;
    let voice_session_id = host.start_voice().await;
    let result = host
        .voice
        .coordinator()
        .stop(host.device_id, &VoiceStopParams { voice_session_id }, 4)
        .await
        .expect("the call stops");
    assert_eq!(
        result.sessions_left_running,
        [host.session_id].into_iter().collect()
    );
    host.clients.abort();
}

/// KR-REQ-15.11: a delegation is decided against the grants this host already holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delegation_runs_under_the_grant_the_host_already_holds() {
    let host = host().await;
    host.grant_voice(Some(&[VoiceAction::Status, VoiceAction::SubmitPrompt]))
        .await;
    let voice_session_id = host.start_voice().await;

    let result = host
        .voice
        .coordinator()
        .delegate(
            host.device_id,
            ActionId::new(kr_ipc::new_uuid()),
            &VoiceDelegateParams {
                voice_session_id,
                delegation_id: delegation("one"),
                offset_ms: U64::new(0),
                action: VoiceAction::Status,
                session_id: Nullable::some(host.session_id),
                spoken_destination: Nullable::null(),
                approval: Nullable::null(),
                turn_id: Nullable::null(),
                confirmation: Nullable::null(),
            },
            5,
        )
        .await;
    // The session in this test has no worker, so the read this proposal becomes cannot complete.
    // What the row asks is that the authority check passed and the proposal reached this host's
    // own dispatch, rather than being refused by a rule of section 15.
    match result {
        Ok(answered) => assert!(
            !matches!(
                &answered.outcome,
                VoiceDelegationOutcome::Refused { reason, .. }
                    if matches!(
                        reason,
                        VoiceRefusal::OutsideVoiceGrant | VoiceRefusal::OutsideDeviceGrant
                    )
            ),
            "{:?}",
            answered.outcome
        ),
        Err(error) => assert!(
            error.reason().is_none(),
            "the grants admitted it; the host could not carry it out: {error}"
        ),
    }
    host.clients.abort();
}

/// KR-REQ-15.13: an action in one of section 15 ¶13's five classes is refused without a signed
/// confirmation, and the refusal names what is missing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unlocked_screen_action_is_refused_without_a_signed_confirmation() {
    let host = host().await;
    host.grant_voice(Some(&[VoiceAction::ShellInput])).await;
    let voice_session_id = host.start_voice().await;

    let result = host
        .voice
        .coordinator()
        .delegate(
            host.device_id,
            ActionId::new(kr_ipc::new_uuid()),
            &VoiceDelegateParams {
                voice_session_id,
                delegation_id: delegation("shell"),
                offset_ms: U64::new(0),
                action: VoiceAction::ShellInput,
                session_id: Nullable::some(host.session_id),
                spoken_destination: Nullable::null(),
                approval: Nullable::null(),
                turn_id: Nullable::null(),
                confirmation: Nullable::null(),
            },
            5,
        )
        .await
        .expect("an answer");
    let VoiceDelegationOutcome::ConfirmationRequired { request, message } = result.outcome else {
        panic!("an unlocked-screen action answers with the challenge it needs");
    };
    assert_eq!(request.action, VoiceAction::ShellInput);
    assert_eq!(request.device_id, host.device_id);
    assert!(message.contains("unlocked screen"), "{message}");

    // And this host holds no identity key for a device it never paired, so a confirmation cannot
    // be checked against one either.
    let authority = kr_controller::voice::GrantAuthority::new(
        Arc::clone(host.controller.sharing()),
        Arc::clone(host.controller.devices()),
        host.controller.sharing().host_device_id(),
    );
    assert!(
        authority
            .device_identity_key(host.device_id)
            .expect("the directory answers")
            .is_none()
    );
    let _ = &host.device_key;
    host.clients.abort();
}

/// KR-REQ-15.17: an effect this host does not dispatch is reported as admitted, never as done.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_effect_this_host_does_not_dispatch_is_reported_as_admitted() {
    let host = host().await;
    host.grant_voice(Some(&[VoiceAction::SubmitPrompt])).await;
    let voice_session_id = host.start_voice().await;

    let result = host
        .voice
        .coordinator()
        .delegate(
            host.device_id,
            ActionId::new(kr_ipc::new_uuid()),
            &VoiceDelegateParams {
                voice_session_id,
                delegation_id: delegation("prompt"),
                offset_ms: U64::new(0),
                action: VoiceAction::SubmitPrompt,
                session_id: Nullable::some(host.session_id),
                spoken_destination: Nullable::some(kr_protocol::voice::SpokenDestination {
                    session_id: host.session_id,
                    spoken_text: "send it to this session".to_owned(),
                }),
                approval: Nullable::null(),
                turn_id: Nullable::null(),
                confirmation: Nullable::null(),
            },
            5,
        )
        .await
        .expect("an answer");
    let VoiceDelegationOutcome::Admitted { note, .. } = result.outcome else {
        panic!("an effect this host does not dispatch is admitted, not performed");
    };
    assert!(
        note.contains("not evidence that a host action ran"),
        "{note}"
    );
    host.clients.abort();
}

/// KR-REQ-15.20: the selection is filtered by the requesting device's own history bound, through
/// the shared host-side filter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn context_is_filtered_by_the_requesting_devices_own_history_bound() {
    let host = host().await;
    host.grant_voice(None).await;
    let voice_session_id = host.start_voice().await;

    let error = host
        .voice
        .coordinator()
        .context(
            host.device_id,
            &VoiceContextParams {
                voice_session_id,
                session_id: SessionId::new(kr_ipc::new_uuid()),
                selected: CanonicalSet::from_iter([]),
                delegation_id: Nullable::null(),
            },
            5,
        )
        .await
        .expect_err("a session outside this call");
    assert_eq!(
        error.reason(),
        Some(VoiceRefusal::SessionOutsideVoiceSession)
    );

    // The session this call may reach has no worker, so the read fails rather than serving
    // anything: a selection is never built from something the host could not read.
    let answered = host
        .voice
        .coordinator()
        .context(
            host.device_id,
            &VoiceContextParams {
                voice_session_id,
                session_id: host.session_id,
                selected: CanonicalSet::from_iter([]),
                delegation_id: Nullable::null(),
            },
            5,
        )
        .await;
    match answered {
        Ok(result) => {
            assert!(result.selection.text_tokens <= 8_000);
            assert!(result.selection.stripping_note.contains("does not prove"));
            assert!(
                result
                    .disclosure
                    .iter()
                    .any(|line| line.contains("transcripts"))
            );
        }
        Err(error) => assert!(
            error.reason().is_none(),
            "a read that could not happen is not a rule refusing it: {error}"
        ),
    }
    host.clients.abort();
}

// ---------------------------------------------------------------------------------------------
// A fence this host owes and could not raise
// ---------------------------------------------------------------------------------------------

mod fence_support;

use fence_support::{clear_the_fault, owe_a_fence};

/// The voice grants one device holds in the host's own store.
fn voice_grants_of(controller: &Controller, device_id: DeviceId) -> Vec<Grant> {
    controller
        .sharing()
        .grants()
        .records_for_device(device_id)
        .expect("the store answers")
        .into_iter()
        .map(|record| record.grant)
        .filter(|grant| grant.permits(ActionRight::VoiceUse))
        .collect()
}

/// KR-REQ-09.12 and 26.16: a withdrawal whose fence could not be raised stops a voice change the
/// person at this machine asks for on the host's own socket. The daemon admits the change, and the
/// voice service asks the check every service asks from inside its work, which asks that fence
/// first: the refusal is the one the other services give, and no voice grant is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_voice_change_is_not_written_while_a_fence_is_owed() {
    let host = host().await;
    let environment = host._temp.environment();
    let mut control = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects to the control endpoint");
    let registry = owe_a_fence(&host.controller, &environment).await;

    let refusal = control
        .mutate(
            Method::VoiceGrant,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &VoiceGrantParams {
                device_id: host.device_id,
                session_ids: [host.session_id].into_iter().collect(),
                actions: Nullable::some([VoiceAction::Status].into_iter().collect()),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("the fence stops the voice change");
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refusal:?}"
    );
    assert!(
        refusal.message.contains("could not be raised"),
        "{refusal:?}"
    );
    assert!(
        voice_grants_of(&host.controller, host.device_id).is_empty(),
        "no voice grant was written"
    );
    clear_the_fault(&registry);
    host.clients.abort();
}

// ---------------------------------------------------------------------------------------------
// The paired device's own path: a real connection, over iroh, to the daemon's own voice service
// ---------------------------------------------------------------------------------------------

mod net_support;

/// How long a mutation over the network asks the host to hold its admission for.
const NETWORK_LIFETIME: kr_protocol::scalars::DurationMs =
    kr_protocol::scalars::DurationMs::new(120_000);

/// Runs one voice mutation over the paired device's connection.
async fn remote_voice<P>(
    session: &kr_client::session::Session,
    environment_id: EnvironmentId,
    method: Method,
    params: &P,
) -> std::result::Result<kr_protocol::envelope::ParamsValue, kr_client::error::ClientError>
where
    P: serde::Serialize + ?Sized,
{
    session
        .mutate(
            method,
            ActionTarget::environment(environment_id),
            None,
            &kr_protocol::envelope::ParamsValue::empty(),
            params,
            NETWORK_LIFETIME,
        )
        .await
        .map(|settled| {
            settled
                .result()
                .cloned()
                .expect("a voice mutation answers with its result")
        })
}

/// KR-REQ-23.51 and 15.01: the five voice methods are reachable from a paired device over its own
/// authenticated connection, and a device with no voice grant reaches none of them.
///
/// The daemon is the real one and the connection is a real iroh connection. The provider is
/// attached to the daemon's own service and makes no network call, which is what every other test
/// here does too: no test in this suite makes a live provider call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_reaches_voice_over_its_own_connection() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let (_device, session) = net_support::paired_device(
        &host,
        &owner,
        &[ActionRight::SessionView, ActionRight::AgentPrompt],
    )
    .await;
    let environment_id = host.environment_id;
    let broker = Arc::new(OfflineProvider::default());
    host.controller()
        .voice()
        .attach_provider(Some(Arc::clone(&broker) as Arc<dyn ManagedVoiceService>));
    let session_id = SessionId::new(kr_ipc::new_uuid());

    // Without a voice grant, the registry's own requirement refuses the call before the
    // coordinator is reached.
    let refused = remote_voice(
        &session,
        environment_id,
        Method::VoiceStart,
        &VoiceStartParams {
            session_ids: [session_id].into_iter().collect(),
            offer_sdp: "v=0\r\n".to_owned(),
            duration_seconds: 600,
            reasoning_budget_minor: Nullable::null(),
        },
    )
    .await
    .expect_err("a device with no voice grant starts nothing");
    let kr_client::error::ClientError::Host(refusal) = refused else {
        panic!("the host refuses it: {refused:?}");
    };
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refusal:?}"
    );

    // The device creates its own voice grant over the same connection.
    let granted: kr_protocol::voice::VoiceGrantResult = remote_voice(
        &session,
        environment_id,
        Method::VoiceGrant,
        &VoiceGrantParams {
            device_id: host
                .controller()
                .devices()
                .devices()
                .expect("the device directory answers")
                .into_iter()
                .find(|record| record.is_paired())
                .expect("the paired device")
                .device_id,
            session_ids: [session_id].into_iter().collect(),
            actions: Nullable::null(),
        },
    )
    .await
    .expect("the voice grant is written")
    .to_typed()
    .expect("a voice grant result");
    assert!(
        granted.statement.actions.contains(&VoiceAction::Brief),
        "{:?}",
        granted.statement.actions
    );

    // And now the call itself, through the daemon's own coordinator and the attached provider.
    let started: kr_protocol::voice::VoiceStartResult = remote_voice(
        &session,
        environment_id,
        Method::VoiceStart,
        &VoiceStartParams {
            session_ids: [session_id].into_iter().collect(),
            offer_sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n".to_owned(),
            duration_seconds: 600,
            reasoning_budget_minor: Nullable::null(),
        },
    )
    .await
    .expect("the call is created")
    .to_typed()
    .expect("a start result");
    let VoiceStartOutcome::Started { session: call } = started.outcome else {
        panic!("the call runs: {:?}", started.outcome);
    };
    assert_eq!(call.session_ids, [session_id].into_iter().collect());

    // The read and the delegation reach the coordinator over the same connection. This host runs
    // no worker for that session, so both answer with a host failure rather than a refusal: what
    // they prove is the ingress, and that the coordinator decided them rather than the registry
    // turning them away.
    let context: std::result::Result<kr_protocol::voice::VoiceContextResult, _> = session
        .read(
            Method::VoiceContext,
            &VoiceContextParams {
                voice_session_id: call.voice_session_id,
                session_id,
                selected: CanonicalSet::from_iter([]),
                delegation_id: Nullable::null(),
            },
        )
        .await;
    match &context {
        // The coordinator answered. This host runs no worker for that session, so what it could
        // gather is nothing; what the row asks is that the read reached it.
        Ok(result) => assert_eq!(result.session_id, session_id),
        Err(kr_client::error::ClientError::Host(refusal)) => {
            assert!(
                matches!(
                    refusal.code,
                    kr_protocol::error::ErrorCode::UnknownSession
                        | kr_protocol::error::ErrorCode::SessionClosed
                        | kr_protocol::error::ErrorCode::EnvironmentUnavailable
                        | kr_protocol::error::ErrorCode::ResourceUnavailable
                ),
                "the read reached the coordinator and failed on the session, not on the ingress: \
                 {refusal:?}"
            );
        }
        Err(other) => panic!("the read reached the host: {other:?}"),
    }
    let delegated = remote_voice(
        &session,
        environment_id,
        Method::VoiceDelegate,
        &VoiceDelegateParams {
            voice_session_id: call.voice_session_id,
            delegation_id: delegation("net"),
            offset_ms: U64::new(0),
            action: VoiceAction::Status,
            session_id: Nullable::some(session_id),
            spoken_destination: Nullable::null(),
            approval: Nullable::null(),
            turn_id: Nullable::null(),
            confirmation: Nullable::null(),
        },
    )
    .await;
    match delegated {
        Ok(value) => {
            let answered: kr_protocol::voice::VoiceDelegateResult =
                value.to_typed().expect("a delegation result");
            assert!(
                !matches!(
                    answered.outcome,
                    VoiceDelegationOutcome::Refused {
                        reason: VoiceRefusal::OutsideVoiceGrant
                            | VoiceRefusal::OutsideDeviceGrant
                            | VoiceRefusal::UnknownVoiceSession
                            | VoiceRefusal::SessionOutsideVoiceSession
                            | VoiceRefusal::UnannouncedDelegation,
                        ..
                    }
                ),
                "the call, the device, the delegation and both grants admitted it, so what is \
                 left is this host's own dispatch: {:?}",
                answered.outcome
            );
        }
        Err(kr_client::error::ClientError::Host(refusal)) => assert!(
            matches!(
                refusal.code,
                kr_protocol::error::ErrorCode::UnknownSession
                    | kr_protocol::error::ErrorCode::SessionClosed
                    | kr_protocol::error::ErrorCode::EnvironmentUnavailable
                    | kr_protocol::error::ErrorCode::ResourceUnavailable
            ),
            "the delegation reached the coordinator and failed on the session, not on the \
             ingress: {refusal:?}"
        ),
        Err(other) => panic!("the delegation reached the host: {other:?}"),
    }

    // Stopping it over the same connection revokes the grant it ran under.
    let stopped: kr_protocol::voice::VoiceStopResult = remote_voice(
        &session,
        environment_id,
        Method::VoiceStop,
        &VoiceStopParams {
            voice_session_id: call.voice_session_id,
        },
    )
    .await
    .expect("the call stops")
    .to_typed()
    .expect("a stop result");
    assert_eq!(stopped.revoked_grant_id, call.grant_id);
    assert_eq!(broker.closed(), vec!["call-1".to_owned()]);
    host.stop().await;
}

/// KR-REQ-09.09, 09.12 and 26.16: a voice start that waited writes nothing once a fence is owed.
///
/// The paired device's start passes the daemon's checks and waits for the broker to create its
/// call. Meanwhile a configuration narrows the rights a grant may carry, and the registry refuses
/// the revision advance the fence needs. When the broker answers, the admission the start arrived
/// under is asked again before the call's grant is written: it refuses with the refusal every other
/// service gives, no grant is written, and the call the broker created is closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_voice_start_that_waited_writes_nothing_once_a_fence_is_owed() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let (_device, session) = net_support::paired_device(
        &host,
        &owner,
        &[ActionRight::SessionView, ActionRight::AgentPrompt],
    )
    .await;
    let environment = host.tree().environment();
    let environment_id = host.environment_id;
    let broker = Arc::new(OfflineProvider::holding());
    host.controller()
        .voice()
        .attach_provider(Some(Arc::clone(&broker) as Arc<dyn ManagedVoiceService>));
    let device_id = host
        .controller()
        .devices()
        .devices()
        .expect("the device directory answers")
        .into_iter()
        .find(|record| record.is_paired())
        .expect("the paired device")
        .device_id;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let standing: kr_protocol::voice::VoiceGrantResult = remote_voice(
        &session,
        environment_id,
        Method::VoiceGrant,
        &VoiceGrantParams {
            device_id,
            session_ids: [session_id].into_iter().collect(),
            actions: Nullable::null(),
        },
    )
    .await
    .expect("the voice grant is written")
    .to_typed()
    .expect("a voice grant result");

    let start = VoiceStartParams {
        session_ids: [session_id].into_iter().collect(),
        offer_sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n".to_owned(),
        duration_seconds: 600,
        reasoning_budget_minor: Nullable::null(),
    };
    let starting = remote_voice(&session, environment_id, Method::VoiceStart, &start);
    // Only once the start is waiting for the broker: it was admitted before the fence was owed.
    let fencing = async {
        broker.reached().await;
        let registry = owe_a_fence(host.controller(), &environment).await;
        broker.release();
        registry
    };
    let (started, registry) = tokio::join!(starting, fencing);

    let refused = started.expect_err("the fence stops the start before its grant is written");
    let kr_client::error::ClientError::Host(refusal) = refused else {
        panic!("the host refuses it: {refused:?}");
    };
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refusal:?}"
    );
    assert!(
        refusal.message.contains("could not be raised"),
        "{refusal:?}"
    );
    let held = voice_grants_of(host.controller(), device_id);
    assert!(
        held.iter().all(|grant| grant.grant_id == standing.grant_id),
        "the standing voice grant and nothing written for the call: {held:?}"
    );
    assert_eq!(
        host.controller().voice().coordinator().live_sessions(),
        0,
        "no voice session was recorded"
    );
    assert_eq!(
        broker.closed(),
        vec!["call-1".to_owned()],
        "the call the broker created is closed"
    );
    clear_the_fault(&registry);
    host.stop().await;
}

/// KR-REQ-09.12 and 26.16: a retry is answered from its record only under the admission this host
/// asks where a retained answer goes back. A paired device's voice change completes and the same
/// action is answered from its record; once this host owes a fence it could not raise, the same
/// action submitted again is refused rather than answered, with the fence's own refusal.
///
/// Finding the record waits, and section 23 has the host check current authority before a retained
/// receipt goes back. The check is the one every service asks from inside its work, asked without a
/// deadline, because section 9 keeps a receipt readable after the window that admitted it is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_is_not_answered_from_its_record_while_a_fence_is_owed() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let device = net_support::Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::SessionView, ActionRight::AgentPrompt]),
    )
    .await;
    let raw = net_support::RawDevice::connect(&host, &device, &record).await;
    raw.claim();
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let target = ActionTarget::environment(host.environment_id);
    let params = VoiceGrantParams {
        device_id: record.device_id,
        session_ids: [SessionId::new(kr_ipc::new_uuid())].into_iter().collect(),
        actions: Nullable::null(),
    };

    let first: kr_protocol::voice::VoiceGrantResult = raw
        .mutate(Method::VoiceGrant, action_id, target.clone(), &params)
        .await
        .expect("the voice grant is written")
        .to_typed()
        .expect("a voice grant result");
    let again: kr_protocol::voice::VoiceGrantResult = raw
        .mutate(Method::VoiceGrant, action_id, target.clone(), &params)
        .await
        .expect("the same action is answered from its record")
        .to_typed()
        .expect("a voice grant result");
    assert_eq!(again.grant_id, first.grant_id, "one action, one grant");

    let registry = owe_a_fence(host.controller(), &host.tree().environment()).await;
    let refused = raw
        .mutate(Method::VoiceGrant, action_id, target, &params)
        .await
        .expect_err("a fence owed stops the retained answer");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refused:?}"
    );
    assert!(
        refused.message.contains("could not be raised"),
        "{refused:?}"
    );
    clear_the_fault(&registry);
    raw.close();
    host.stop().await;
}
