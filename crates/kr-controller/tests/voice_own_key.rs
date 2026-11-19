//! Calls on the owner's own OpenAI key against a real control daemon.
//!
//! The daemon is the real one: its own grant store, device directory, secret store and record of
//! calls, with the own-key provider selected by its configuration document. What the suite
//! supplies is the paired devices and the stand-in that takes the place of OpenAI, placed under the
//! daemon by its state directory. No provider is contacted and no real key is used.

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_client::services::own_voice::stand_in::{CreateScript, StandIn, created_body};
use kr_client::services::own_voice::words;
use kr_client::services::{OwnCallLedger, RegistryState};
use kr_controller::voice::own_key_calls::OwnKeyCalls;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::open_store_in;
use kr_ipc::client::LocalClient;
use kr_protocol::delivery::SecretText;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::voice::{
    VoiceGrantParams, VoicePrepareParams, VoicePrepareProvider, VoicePrepareResult,
    VoiceStartOutcome, VoiceStartParams, VoiceStartResult,
};
use kr_protocol::voice_credential::{
    VoiceCredentialForgetCallsParams, VoiceCredentialForgetCallsResult, VoiceCredentialKind,
    VoiceCredentialRemoveParams, VoiceCredentialRemoveResult, VoiceCredentialSetParams,
    VoiceLateStart,
};

const HELD_KEY: &str = "kr-test-voice-key-held-01234567890";
const OTHER_KEY: &str = "kr-test-voice-key-other-0123456789";

/// A daemon that holds a key and reaches OpenAI only by its stand-in.
struct Daemon {
    host: net_support::Host,
    owner: DeviceKeys,
    stand_in: StandIn,
    control: LocalClient,
    // Held while the daemon runs, and across its restart.
    placed: kr_controller::voice::own_key_hooks::Placed,
}

/// A paired device with a standing voice grant over one session and the preparation a start is
/// bound to.
struct Phone {
    device_id: kr_protocol::ids::DeviceId,
    raw: net_support::RawDevice,
    target: ActionTarget,
    prepared: VoicePrepareResult,
    session_id: SessionId,
    // Declared last: the endpoint is let go after the connection on it.
    _device: net_support::Device,
}

async fn daemon() -> Daemon {
    let owner = DeviceKeys::generate().expect("owner keys");
    let stand_in = StandIn::new();
    let (host, placed) =
        net_support::Host::start_with_own_voice(&owner, Arc::new(stand_in.clone())).await;
    let mut control = host.client().await;
    set_key(&mut control, &host, HELD_KEY)
        .await
        .expect("the key is held");
    Daemon {
        host,
        owner,
        stand_in,
        control,
        placed,
    }
}

async fn set_key(
    control: &mut LocalClient,
    host: &net_support::Host,
    key: &str,
) -> Result<ParamsValue, ProtocolError> {
    control
        .mutate(
            Method::VoiceCredentialSet,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &VoiceCredentialSetParams {
                kind: VoiceCredentialKind::OpenaiLive,
                key: SecretText::new(key).expect("a key"),
            },
        )
        .await
        .expect("the call reaches the daemon")
}

async fn forget_calls(
    control: &mut LocalClient,
    host: &net_support::Host,
) -> Result<VoiceCredentialForgetCallsResult, ProtocolError> {
    control
        .mutate(
            Method::VoiceCredentialForgetCalls,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &VoiceCredentialForgetCallsParams {
                kind: VoiceCredentialKind::OpenaiLive,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .map(|answer| answer.to_typed().expect("the result decodes"))
}

async fn remove_key(
    control: &mut LocalClient,
    host: &net_support::Host,
) -> Result<VoiceCredentialRemoveResult, ProtocolError> {
    control
        .mutate(
            Method::VoiceCredentialRemove,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &VoiceCredentialRemoveParams {
                kind: VoiceCredentialKind::OpenaiLive,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .map(|answer| answer.to_typed().expect("the result decodes"))
}

/// The key the daemon's secret store holds, read from its own files.
fn held_key(host: &net_support::Host) -> Option<String> {
    let store = open_store_in(&host.tree().environment().secrets_dir())
        .expect("the store the daemon keeps its secrets in");
    kr_controller::voice::VoiceCredentials::new(Arc::from(store.store), host.environment_id)
        .get(VoiceCredentialKind::OpenaiLive)
        .expect("the store reads")
        .map(|item| item.expose().to_owned())
}

async fn phone(daemon: &Daemon, rights: &[ActionRight]) -> Phone {
    let device = net_support::Device::create().await;
    let record = net_support::pair_with(
        &daemon.host,
        &device,
        &daemon.owner,
        net_support::proposal(rights),
    )
    .await;
    let raw = net_support::RawDevice::connect(&daemon.host, &device, &record).await;
    raw.claim();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let target = ActionTarget::environment(daemon.host.environment_id);
    raw.mutate(
        Method::VoiceGrant,
        ActionId::new(kr_ipc::new_uuid()),
        target.clone(),
        &VoiceGrantParams {
            device_id: record.device_id,
            session_ids: [session_id].into_iter().collect(),
            actions: Nullable::null(),
        },
    )
    .await
    .expect("the voice grant is written");
    let prepared: VoicePrepareResult = raw
        .read(
            Method::VoicePrepare,
            &VoicePrepareParams {
                session_ids: [session_id].into_iter().collect(),
                selected: CanonicalSet::from_iter([]),
            },
        )
        .await
        .expect("the host answers what a call would be")
        .to_typed()
        .expect("a preparation");
    Phone {
        device_id: record.device_id,
        raw,
        target,
        prepared,
        session_id,
        _device: device,
    }
}

const MANAGER: [ActionRight; 3] = [
    ActionRight::SessionView,
    ActionRight::AgentPrompt,
    ActionRight::HostManage,
];

impl Phone {
    fn start_params(&self) -> VoiceStartParams {
        VoiceStartParams {
            session_ids: [self.session_id].into_iter().collect(),
            offer_sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n".to_owned(),
            duration_seconds: 600,
            reasoning_budget_minor: Nullable::null(),
            prepared: self.prepared.prepared,
            expected_rate_version: Nullable::null(),
        }
    }

    async fn start_as(&self, action_id: ActionId) -> Result<VoiceStartResult, ProtocolError> {
        self.raw
            .mutate(
                Method::VoiceStart,
                action_id,
                self.target.clone(),
                &self.start_params(),
            )
            .await
            .map(|answer| answer.to_typed().expect("a start result"))
    }

    async fn start(&self) -> Result<VoiceStartResult, ProtocolError> {
        self.start_as(ActionId::new(kr_ipc::new_uuid())).await
    }
}

fn rows_of(daemon: &Daemon) -> Vec<kr_client::services::CallRow> {
    OwnKeyCalls::open(daemon.host.tree().environment().state_dir())
        .expect("the record of calls opens beside the daemon")
        .rows()
        .expect("rows")
}

/// Waits, within a bound, until `ready` holds.
async fn until(what: &str, mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(60), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

fn started(
    result: Result<VoiceStartResult, ProtocolError>,
) -> Box<kr_protocol::voice::VoiceSessionDescriptor> {
    match result.expect("the start is answered").outcome {
        VoiceStartOutcome::Started { session } => session,
        other => panic!("the call runs: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_action_id_and_a_device_id_reach_the_row_from_the_envelope() {
    let daemon = daemon().await;
    let phone = phone(&daemon, &MANAGER).await;
    assert!(
        matches!(
            phone.prepared.provider,
            VoicePrepareProvider::OwnKey { held: true, .. }
        ),
        "a manager is offered the call on the held key: {:?}",
        phone.prepared.provider
    );
    let action = ActionId::new(kr_ipc::new_uuid());
    let session = started(phone.start_as(action).await);
    assert!(matches!(
        session.control,
        kr_protocol::voice::VoiceSessionControl::Host { .. }
    ));
    let rows = rows_of(&daemon);
    assert_eq!(rows.len(), 1, "one row stands for the running call");
    assert_eq!(rows[0].call.action_id, action);
    assert_eq!(rows[0].call.device_id, phone.device_id.to_string());
    let seen = daemon.stand_in.recorded();
    assert_eq!(seen.creates.len(), 1);
    assert_eq!(
        seen.creates[0].0, HELD_KEY,
        "the key is read from the store"
    );
    daemon.host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_start_from_any_device_is_refused_with_draft_conflict_naming_the_earlier_action_and_device_and_closes_nothing()
 {
    let daemon = daemon().await;
    let first = phone(&daemon, &MANAGER).await;
    let second = phone(&daemon, &MANAGER).await;
    let action = ActionId::new(kr_ipc::new_uuid());
    let _ = started(first.start_as(action).await);

    let refused = second
        .start()
        .await
        .expect_err("a second call on the key is refused");
    assert_eq!(refused.code, ErrorCode::DraftConflict);
    assert!(refused.message.contains("not confirmed closed (action"));
    assert!(refused.message.contains(&action.to_string()));
    assert!(refused.message.contains(&first.device_id.to_string()));

    let seen = daemon.stand_in.recorded();
    assert_eq!(
        seen.creates.len(),
        1,
        "the second start asked OpenAI nothing"
    );
    assert!(seen.hangups.is_empty(), "the first call is not closed");
    assert_eq!(rows_of(&daemon).len(), 1);
    assert_eq!(
        daemon.host.controller().own_key_registry_state(),
        RegistryState::Running
    );
    daemon.host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_whose_own_grant_is_view_only_cannot_start_a_call_on_the_hosts_key_and_a_device_with_host_management_can()
 {
    let daemon = daemon().await;
    let viewer = phone(&daemon, &[ActionRight::SessionView]).await;
    assert!(
        matches!(
            viewer.prepared.provider,
            VoicePrepareProvider::Unavailable { .. }
        ),
        "a viewer is not offered the call: {:?}",
        viewer.prepared.provider
    );
    let refused = viewer.start().await.expect("the start is answered").outcome;
    match refused {
        VoiceStartOutcome::Unavailable { reason, .. } => {
            assert_eq!(reason, "host_management_required");
        }
        other => panic!("a viewer cannot spend the key: {other:?}"),
    }
    let seen = daemon.stand_in.recorded();
    assert!(seen.creates.is_empty(), "nothing was asked of OpenAI");
    assert!(rows_of(&daemon).is_empty(), "nothing was written down");

    let manager = phone(&daemon, &MANAGER).await;
    let _ = started(manager.start().await);
    assert_eq!(daemon.stand_in.recorded().creates.len(), 1);
    daemon.host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_closes_the_open_row_with_the_key_and_deletes_the_closed_row_without_a_provider_request()
 {
    let daemon = daemon().await;
    let Daemon {
        host,
        stand_in,
        placed,
        control,
        owner: _,
    } = daemon;
    drop(control);
    let stopped = host.shut_down().await;
    let state_dir = stopped.tree().environment().state_dir().to_path_buf();
    {
        use kr_client::services::NewCall;
        let calls = OwnKeyCalls::open(&state_dir).expect("the record opens");
        for (byte, session, closed) in [(1_u8, "live_open", false), (2, "live_done", true)] {
            let call = NewCall {
                call_id: format!("call-{byte}"),
                attempt_id: format!("attempt-{byte}"),
                action_id: ActionId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16])),
                device_id: "device-1".to_owned(),
                asked_ms: 1_700_000_000_000,
                closes_at_ms: 1_700_000_300_000,
            };
            calls.begin(&call).expect("a row is written");
            calls
                .record_id(&call.call_id, session, None)
                .expect("its id is written");
            if closed {
                calls
                    .record_closed(&call.call_id, 1_700_000_100_000)
                    .expect("the closure is written");
            }
        }
    }
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    until("the start-time reconcile deleted both rows", || {
        OwnKeyCalls::open(&state_dir)
            .ok()
            .and_then(|calls| calls.rows().ok())
            .is_some_and(|rows| rows.is_empty())
    })
    .await;
    let seen = stand_in.recorded();
    assert_eq!(
        seen.hangups,
        vec![(HELD_KEY.to_owned(), "live_open".to_owned())],
        "only the open row is hung up, with the held key; the closed row asks nothing"
    );
    assert_eq!(held_key(&host).as_deref(), Some(HELD_KEY));
    host.stop().await;
    drop(placed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clean_stop_closes_the_calls_the_host_controls_at_the_provider_and_leaves_no_row() {
    let daemon = daemon().await;
    let phone = phone(&daemon, &MANAGER).await;
    let _ = started(phone.start().await);
    assert_eq!(rows_of(&daemon).len(), 1);

    daemon.host.controller().close_host_calls_for_stop().await;

    until("the stopped call's row is gone", || {
        rows_of(&daemon).is_empty()
    })
    .await;
    let seen = daemon.stand_in.recorded();
    assert!(
        seen.commands
            .iter()
            .any(|command| command["type"] == "session.close"),
        "the host asked the provider to close the session: {:?}",
        seen.commands
    );
    assert_eq!(
        daemon.host.controller().own_key_registry_state(),
        RegistryState::Idle
    );
    daemon.host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_doctor_names_each_call_that_is_not_confirmed_closed_and_the_command_that_clears_it() {
    let daemon = daemon().await;
    {
        use kr_client::services::NewCall;
        let calls = OwnKeyCalls::open(daemon.host.tree().environment().state_dir())
            .expect("the record opens");
        for (byte, closed) in [(1_u8, false), (2, true)] {
            let call = NewCall {
                call_id: format!("call-{byte}"),
                attempt_id: format!("attempt-{byte}"),
                action_id: ActionId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16])),
                device_id: "device-1".to_owned(),
                asked_ms: 1_700_000_000_000,
                closes_at_ms: 1_700_000_300_000,
            };
            calls.begin(&call).expect("a row is written");
            calls
                .record_id(&call.call_id, "live_standing", None)
                .expect("its id is written");
            if closed {
                calls
                    .record_closed(&call.call_id, 1_700_000_100_000)
                    .expect("the closure is written");
            }
        }
    }
    let mut client = daemon.host.client().await;
    let doctor: kr_protocol::hostinfo::HostDoctorResult = client
        .request(Method::HostDoctor, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.doctor is served on the local socket")
        .to_typed()
        .expect("a doctor result");
    let lines: Vec<&str> = doctor
        .checks
        .iter()
        .filter(|check| check.id() == "voice-own-key-call")
        .map(kr_protocol::hostinfo::DoctorCheck::detail)
        .collect();
    let first = ActionId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16]));
    assert_eq!(
        lines,
        vec![format!(
            "own-key voice call {first}: not confirmed closed since {} UTC; if it has ended, run \
             kr voice credential forget-calls",
            kr_client::services::own_voice::utc(1_700_000_000_000)
        )],
        "one line for the open row and none for the closed one"
    );
    daemon.host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forget_calls_during_a_creation_settles_the_start_task_before_the_item_goes_and_a_late_creation_reply_is_hung_up_with_the_original_key_and_not_adopted()
 {
    let mut daemon = daemon().await;
    let phone = Arc::new(phone(&daemon, &MANAGER).await);
    let release = Arc::new(tokio::sync::Notify::new());
    daemon.stand_in.script_create(CreateScript::Held(
        Arc::clone(&release),
        Box::new(CreateScript::Answer(
            201,
            Some(created_body("live_late_session")),
        )),
    ));
    let starting = {
        let phone = Arc::clone(&phone);
        tokio::spawn(async move { phone.start().await })
    };
    until("the creation reached the stand-in", || {
        daemon.stand_in.recorded().creates.len() == 1
    })
    .await;

    let forgetting = {
        let host_client = daemon.host.client().await;
        let environment = daemon.host.environment_id;
        tokio::spawn(async move {
            let mut client = host_client;
            let target = ActionTarget::environment(environment);
            client
                .mutate(
                    Method::VoiceCredentialForgetCalls,
                    ActionId::new(kr_ipc::new_uuid()),
                    target,
                    &VoiceCredentialForgetCallsParams {
                        kind: VoiceCredentialKind::OpenaiLive,
                    },
                )
                .await
                .expect("the call reaches the daemon")
                .map(|answer| {
                    answer
                        .to_typed::<VoiceCredentialForgetCallsResult>()
                        .expect("the result decodes")
                })
        })
    };
    until("the registry is settling", || {
        daemon.host.controller().own_key_registry_state() == RegistryState::Settling
    })
    .await;

    let replaced = set_key(&mut daemon.control, &daemon.host, OTHER_KEY).await;
    assert!(
        replaced
            .expect_err("a key is not replaced during a settle")
            .message
            .contains("A call is using this key; replace it after the call has ended"),
    );

    release.notify_one();
    let forgotten = forgetting
        .await
        .expect("the task ends")
        .expect("forgetting is answered");
    assert_eq!(forgotten.late_start, VoiceLateStart::Closed);
    let refused = starting.await.expect("the task ends");
    assert!(
        !matches!(
            refused.map(|result| result.outcome),
            Ok(VoiceStartOutcome::Started { .. })
        ),
        "the fenced start does not become a call"
    );

    let seen = daemon.stand_in.recorded();
    assert_eq!(
        seen.hangups,
        vec![(HELD_KEY.to_owned(), "live_late_session".to_owned())],
        "the late session is hung up with the original key"
    );
    assert!(
        rows_of(&daemon).is_empty(),
        "no row is kept for the late session"
    );
    assert_eq!(
        held_key(&daemon.host).as_deref(),
        Some(HELD_KEY),
        "the key is kept"
    );
    let again = forget_calls(&mut daemon.control, &daemon.host)
        .await
        .expect("forgetting again is answered");
    assert_eq!(again.late_start, VoiceLateStart::None);
    let _ = &daemon.placed;
    daemon.host.stop().await;
}

/// A creation held at the stand-in, and a forget-calls that holds the host's fence while it waits
/// for that creation: the host is settling.
struct Settling {
    release: Arc<tokio::sync::Notify>,
    starting: tokio::task::JoinHandle<Result<VoiceStartResult, ProtocolError>>,
    forgetting: tokio::task::JoinHandle<Result<VoiceCredentialForgetCallsResult, ProtocolError>>,
}

async fn settling(daemon: &Daemon, phone: &Arc<Phone>) -> Settling {
    let release = Arc::new(tokio::sync::Notify::new());
    daemon.stand_in.script_create(CreateScript::Held(
        Arc::clone(&release),
        Box::new(CreateScript::Answer(
            201,
            Some(created_body("live_late_session")),
        )),
    ));
    let starting = {
        let phone = Arc::clone(phone);
        tokio::spawn(async move { phone.start().await })
    };
    until("the creation reached the stand-in", || {
        daemon.stand_in.recorded().creates.len() == 1
    })
    .await;
    let forgetting = {
        let mut client = daemon.host.client().await;
        let environment = daemon.host.environment_id;
        tokio::spawn(async move { forget_calls_of(&mut client, environment).await })
    };
    until("the registry is settling", || {
        daemon.host.controller().own_key_registry_state() == RegistryState::Settling
    })
    .await;
    Settling {
        release,
        starting,
        forgetting,
    }
}

async fn forget_calls_of(
    control: &mut LocalClient,
    environment: kr_protocol::ids::EnvironmentId,
) -> Result<VoiceCredentialForgetCallsResult, ProtocolError> {
    control
        .mutate(
            Method::VoiceCredentialForgetCalls,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment),
            &VoiceCredentialForgetCallsParams {
                kind: VoiceCredentialKind::OpenaiLive,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .map(|answer| answer.to_typed().expect("the result decodes"))
}

/// A removal that meets the fence another removal or forget-calls holds is told, in its own
/// words and not the start's, that the host changes neither the key nor its record now; it
/// changes nothing, and run again after the earlier command has finished it removes the key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_that_meets_the_held_fence_changes_neither_the_key_nor_the_record_and_says_so() {
    let mut daemon = daemon().await;
    let phone = Arc::new(phone(&daemon, &MANAGER).await);
    let held = settling(&daemon, &phone).await;
    let rows_before = rows_of(&daemon);
    assert_eq!(rows_before.len(), 1, "the held creation has its row");

    let refused = remove_key(&mut daemon.control, &daemon.host)
        .await
        .expect_err("a removal does not pass the held fence");
    assert_eq!(refused.message, words::STILL_CLOSING);
    assert_ne!(refused.message, words::SETTLING, "not the start's sentence");
    assert_eq!(held_key(&daemon.host).as_deref(), Some(HELD_KEY));
    assert!(rows_of(&daemon) == rows_before, "the record is as it was");
    assert!(daemon.stand_in.recorded().hangups.is_empty());

    held.release.notify_one();
    let forgotten = held
        .forgetting
        .await
        .expect("the task ends")
        .expect("forgetting is answered");
    assert_eq!(forgotten.late_start, VoiceLateStart::Closed);
    let _ = held.starting.await.expect("the task ends");
    let removed = remove_key(&mut daemon.control, &daemon.host)
        .await
        .expect("after the earlier command the removal is answered");
    assert!(removed.removed);
    assert_eq!(
        held_key(&daemon.host),
        None,
        "the removal then removes the key"
    );
    let _ = &daemon.placed;
    daemon.host.stop().await;
}

/// The same for a forget-calls: it changes nothing while the fence is held, and its words are the
/// ones of the command, not the start's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forget_calls_that_meets_the_held_fence_changes_neither_the_key_nor_the_record_and_says_so()
 {
    let mut daemon = daemon().await;
    let phone = Arc::new(phone(&daemon, &MANAGER).await);
    let held = settling(&daemon, &phone).await;
    let rows_before = rows_of(&daemon);
    assert_eq!(rows_before.len(), 1, "the held creation has its row");

    let refused = forget_calls(&mut daemon.control, &daemon.host)
        .await
        .expect_err("a forget-calls does not pass the held fence");
    assert_eq!(refused.message, words::STILL_CLOSING);
    assert_ne!(refused.message, words::SETTLING, "not the start's sentence");
    assert_eq!(held_key(&daemon.host).as_deref(), Some(HELD_KEY));
    assert!(rows_of(&daemon) == rows_before, "the record is as it was");

    held.release.notify_one();
    held.forgetting
        .await
        .expect("the task ends")
        .expect("forgetting is answered");
    let _ = held.starting.await.expect("the task ends");
    let again = forget_calls(&mut daemon.control, &daemon.host)
        .await
        .expect("after the earlier command it is answered");
    assert_eq!(again.late_start, VoiceLateStart::None);
    let _ = &daemon.placed;
    daemon.host.stop().await;
}

/// The record of calls refuses a forget part of the way through (a trigger that another
/// connection added to the daemon's own file): the host says it could not forget, in the approved
/// words, and every row is as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forget_calls_the_record_refuses_leaves_the_record_as_it_was_and_says_so() {
    let mut daemon = daemon().await;
    let state_dir = daemon.host.tree().environment().state_dir().to_path_buf();
    let record = OwnKeyCalls::open(&state_dir).expect("the record opens beside the daemon");
    for byte in [1_u8, 2] {
        record
            .begin(&kr_client::services::NewCall {
                call_id: format!("call-{byte}"),
                attempt_id: format!("attempt-{byte}"),
                action_id: ActionId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16])),
                device_id: "device".to_owned(),
                asked_ms: 1_000,
                closes_at_ms: 2_000,
            })
            .expect("a row is written");
    }
    rusqlite::Connection::open(
        state_dir.join(kr_controller::voice::own_key_calls::OWN_KEY_CALLS_RECORD),
    )
    .expect("a second connection to the daemon's record")
    .execute_batch(
        "CREATE TRIGGER refuse_the_last BEFORE DELETE ON own_key_calls
             WHEN old.call_id = 'call-2'
             BEGIN SELECT RAISE(ABORT, 'refused'); END;",
    )
    .expect("the record is made to refuse");
    let before = rows_of(&daemon);

    let refused = forget_calls(&mut daemon.control, &daemon.host)
        .await
        .expect_err("the forget is refused");
    assert_eq!(refused.message, words::NOT_FORGOTTEN);
    assert!(rows_of(&daemon) == before, "the record stays as it was");
    assert_eq!(held_key(&daemon.host).as_deref(), Some(HELD_KEY));
    let _ = &daemon.placed;
    daemon.host.stop().await;
}

/// A key is not replaced while a start waits on its creation or while the call it made runs, and
/// the replacement goes through once the calls are forgotten, with every later request made under
/// the new key. (A guard for the held write: the race itself is the registry's case
/// `a_change_runs_only_while_idle_and_a_start_cannot_pass_it`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_is_not_replaced_while_a_creation_is_held_or_a_call_runs_and_is_after_the_calls_are_forgotten()
 {
    let mut daemon = daemon().await;
    let phone = Arc::new(phone(&daemon, &MANAGER).await);
    let release = Arc::new(tokio::sync::Notify::new());
    daemon.stand_in.script_create(CreateScript::Held(
        Arc::clone(&release),
        Box::new(CreateScript::Answer(201, Some(created_body("live_held")))),
    ));
    let starting = {
        let phone = Arc::clone(&phone);
        tokio::spawn(async move { phone.start().await })
    };
    until("the creation reached the stand-in", || {
        daemon.stand_in.recorded().creates.len() == 1
    })
    .await;
    let refusal = |result: Result<ParamsValue, ProtocolError>| {
        result
            .expect_err("a key is not replaced now")
            .message
            .contains("A call is using this key; replace it after the call has ended")
    };
    assert!(refusal(
        set_key(&mut daemon.control, &daemon.host, OTHER_KEY).await
    ));
    assert_eq!(held_key(&daemon.host).as_deref(), Some(HELD_KEY));

    release.notify_one();
    let _call = started(starting.await.expect("the task ends"));
    assert!(refusal(
        set_key(&mut daemon.control, &daemon.host, OTHER_KEY).await
    ));
    assert_eq!(held_key(&daemon.host).as_deref(), Some(HELD_KEY));

    forget_calls(&mut daemon.control, &daemon.host)
        .await
        .expect("the calls are forgotten");
    set_key(&mut daemon.control, &daemon.host, OTHER_KEY)
        .await
        .expect("the key is replaced once nothing uses it");
    assert_eq!(held_key(&daemon.host).as_deref(), Some(OTHER_KEY));
    let _ = &daemon.placed;
    daemon.host.stop().await;
}
