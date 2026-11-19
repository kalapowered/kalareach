//! Calls on the owner's own OpenAI key against a real control daemon.
//!
//! The daemon is the real one: its own grant store, device directory, secret store and record of
//! calls, with the own-key provider selected by its configuration document. What the suite
//! supplies is the paired devices and the stand-in that takes the place of OpenAI, placed under the
//! daemon by its state directory. No provider is contacted and no real key is used.

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_client::services::own_voice::stand_in::{
    CreateScript, HangupScript, StandIn, TESTING_REFUSALS, closed_event, created_body,
};
use kr_client::services::own_voice::words;
use kr_client::services::{CallState, OwnCallLedger, RegistryState};
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
    record: kr_controller::service::net::devices::DeviceRecord,
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
    phone_on(&daemon.host, &daemon.owner, rights).await
}

async fn phone_on(host: &net_support::Host, owner: &DeviceKeys, rights: &[ActionRight]) -> Phone {
    let device = net_support::Device::create().await;
    let record = net_support::pair_with(host, &device, owner, net_support::proposal(rights)).await;
    let raw = net_support::RawDevice::connect(host, &device, &record).await;
    raw.claim();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let target = ActionTarget::environment(host.environment_id);
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
        record,
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

type Forgetting = tokio::task::JoinHandle<Result<VoiceCredentialForgetCallsResult, ProtocolError>>;
type Removing = tokio::task::JoinHandle<Result<VoiceCredentialRemoveResult, ProtocolError>>;

async fn forgetting_in_background(daemon: &Daemon) -> Forgetting {
    let mut client = daemon.host.client().await;
    let environment = daemon.host.environment_id;
    tokio::spawn(async move { forget_calls_of(&mut client, environment).await })
}

async fn removing_in_background(daemon: &Daemon) -> Removing {
    let mut client = daemon.host.client().await;
    let environment = daemon.host.environment_id;
    tokio::spawn(async move {
        client
            .mutate(
                Method::VoiceCredentialRemove,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(environment),
                &VoiceCredentialRemoveParams {
                    kind: VoiceCredentialKind::OpenaiLive,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .map(|answer| answer.to_typed().expect("the result decodes"))
    })
}

fn starting_in_background(
    phone: &Arc<Phone>,
) -> tokio::task::JoinHandle<Result<VoiceStartResult, ProtocolError>> {
    let phone = Arc::clone(phone);
    tokio::spawn(async move { phone.start().await })
}

fn creates_seen(daemon: &Daemon) -> usize {
    daemon.stand_in.recorded().creates.len()
}

fn the_registry_is(daemon: &Daemon, state: RegistryState) -> bool {
    daemon.host.controller().own_key_registry_state() == state
}

/// The live voice grants a device holds in the host's own store.
fn live_voice_grants(daemon: &Daemon, phone: &Phone) -> usize {
    daemon
        .host
        .controller()
        .sharing()
        .grants()
        .records_for_device(phone.device_id)
        .expect("the store answers")
        .into_iter()
        .filter(|record| record.is_active() && record.revoked_at_ms.is_none())
        .filter(|record| record.grant.permits(ActionRight::VoiceUse))
        .count()
}

/// A start whose caller goes away while OpenAI has not yet answered is not dropped with it: the
/// start runs on a task of its own, so the answer that comes later is adopted, found no longer
/// admitted because its link is gone, and the call it created is closed: no row stays, the
/// registry is idle and the coordinator holds nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_whose_caller_goes_away_during_the_creation_is_carried_to_its_end_and_the_call_it_created_is_closed()
 {
    let daemon = daemon().await;
    let phone = Arc::new(phone(&daemon, &MANAGER).await);
    let release = Arc::new(tokio::sync::Notify::new());
    daemon.stand_in.script_create(CreateScript::Held(
        Arc::clone(&release),
        Box::new(CreateScript::Answer(
            201,
            Some(created_body("live_carried")),
        )),
    ));
    let starting = starting_in_background(&phone);
    until("the creation reached the stand-in", || {
        creates_seen(&daemon) == 1
    })
    .await;
    assert!(the_registry_is(&daemon, RegistryState::Starting));

    phone.raw.close();
    until("the daemon has let the link go", || {
        daemon.host.connections_of(&phone.record) == 0
    })
    .await;
    release.notify_one();
    until("the start ended though its caller was gone", || {
        the_registry_is(&daemon, RegistryState::Idle)
    })
    .await;
    assert!(
        rows_of(&daemon).is_empty(),
        "the start ran to its end: the row of the call it created is closed and deleted"
    );

    let seen = daemon.stand_in.recorded();
    assert_eq!(seen.creates.len(), 1);
    let closed_by_command = seen
        .commands
        .iter()
        .any(|command| command["type"] == "session.close");
    let hung_up = seen
        .hangups
        .iter()
        .any(|(key, session)| key == HELD_KEY && session == "live_carried");
    assert!(
        closed_by_command || hung_up,
        "the session the creation gave is closed at the provider: {:?} {:?}",
        seen.commands,
        seen.hangups
    );
    assert_eq!(
        daemon
            .host
            .controller()
            .voice()
            .coordinator()
            .live_sessions(),
        0,
        "the coordinator holds no call its caller never saw"
    );
    let _ = starting.await;
    daemon.host.stop().await;
}

/// A reattachment that a fence overtakes while its attach is awaited writes nothing to the channel
/// it was given: the call is hung up with the key still held and no probe goes out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reattachment_that_a_fence_overtakes_sends_no_probe_and_the_call_is_hung_up_with_the_held_key()
 {
    let daemon = daemon().await;
    let phone = phone(&daemon, &MANAGER).await;
    let _ = started(phone.start().await);
    let asked_before = daemon.stand_in.recorded().attaches_asked;
    let release = Arc::new(tokio::sync::Notify::new());
    daemon.stand_in.hold_attach(Arc::clone(&release));
    daemon.stand_in.drop_socket();
    until("the reattachment reached the stand-in", || {
        daemon.stand_in.recorded().attaches_asked == asked_before + 1
    })
    .await;
    let commands_before = daemon.stand_in.recorded().commands.len();

    let forgetting = forgetting_in_background(&daemon).await;
    until("the registry is settling", || {
        the_registry_is(&daemon, RegistryState::Settling)
    })
    .await;
    release.notify_one();
    forgetting
        .await
        .expect("the task ends")
        .expect("forgetting is answered");

    let seen = daemon.stand_in.recorded();
    assert_eq!(
        seen.commands.len(),
        commands_before,
        "no probe and no close was written to the channel an older epoch attached: {:?}",
        &seen.commands[commands_before..]
    );
    assert!(
        !seen.hangups.is_empty() && seen.hangups.iter().all(|(key, _)| key == HELD_KEY),
        "the call is hung up with the key that is still held: {:?}",
        seen.hangups
    );
    assert!(rows_of(&daemon).is_empty());
    assert!(the_registry_is(&daemon, RegistryState::Idle));
    assert_eq!(held_key(&daemon.host).as_deref(), Some(HELD_KEY));
    daemon.host.stop().await;
}

/// A call that OpenAI closes leaves nothing of the host's authority behind: the host call is gone
/// at once, and the coordinator's own pass then ends the voice session and revokes the call's
/// grant, though no host call is left to prompt it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_the_provider_closes_is_ended_in_the_coordinator_with_its_grant_revoked_though_no_host_call_is_left()
 {
    let daemon = daemon().await;
    let phone = phone(&daemon, &MANAGER).await;
    let before = live_voice_grants(&daemon, &phone);
    let _ = started(phone.start().await);
    let coordinator = daemon.host.controller().voice().coordinator();
    assert_eq!(coordinator.live_sessions(), 1);
    assert!(
        live_voice_grants(&daemon, &phone) > before,
        "the call has a grant of its own"
    );

    daemon.stand_in.event(&closed_event("expired", None));
    until("the host call left with the closed session", || {
        daemon.host.controller().voice().host_calls().is_empty()
    })
    .await;
    until("the coordinator ended the call it still held", || {
        coordinator.live_sessions() == 0
    })
    .await;
    assert_eq!(
        live_voice_grants(&daemon, &phone),
        before,
        "the call's grant is revoked"
    );
    assert!(
        rows_of(&daemon).is_empty(),
        "the closure was marked and the row deleted"
    );
    assert!(the_registry_is(&daemon, RegistryState::Idle));
    assert!(
        daemon.stand_in.recorded().hangups.is_empty(),
        "a closure OpenAI told is not hung up again"
    );
    daemon.host.stop().await;
}

/// A `session.closed` that comes while the call is not yet ready is a recognised closure: the row
/// is marked and deleted, nothing is hung up, and the registry is free for the next start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_closed_during_readiness_marks_the_row_closed_sends_no_hangup_and_frees_the_next_start()
 {
    let daemon = daemon().await;
    let phone = phone(&daemon, &MANAGER).await;
    daemon.stand_in.close_at_attach(true);
    let outcome = phone.start().await.expect("the start is answered").outcome;
    assert!(
        !matches!(outcome, VoiceStartOutcome::Started { .. }),
        "a call that closed before it was ready does not run: {outcome:?}"
    );
    let seen = daemon.stand_in.recorded();
    assert_eq!(seen.creates.len(), 1);
    assert!(
        seen.hangups.is_empty(),
        "a closure the provider told is not hung up again: {:?}",
        seen.hangups
    );
    assert!(
        rows_of(&daemon).is_empty(),
        "the row was marked and deleted"
    );
    assert!(the_registry_is(&daemon, RegistryState::Idle));

    daemon.stand_in.close_at_attach(false);
    let _ = started(phone.start().await);
    daemon.host.stop().await;
}

/// A removal that fences after the session id is written and before the call is ready hangs that
/// session up with the key still held, and deletes the key after the closure is recognised.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_after_the_id_is_written_and_before_the_call_is_ready_hangs_that_session_up_with_the_held_key_and_deletes_the_item_after_the_recognised_closure()
 {
    let daemon = daemon().await;
    let phone = Arc::new(phone(&daemon, &MANAGER).await);
    daemon.stand_in.script_create(CreateScript::Answer(
        201,
        Some(created_body("live_not_ready")),
    ));
    let release = Arc::new(tokio::sync::Notify::new());
    daemon.stand_in.hold_attach(Arc::clone(&release));
    let starting = starting_in_background(&phone);
    until("the session id is written and the attach is asked", || {
        daemon.stand_in.recorded().attaches_asked == 1
            && rows_of(&daemon)
                .first()
                .is_some_and(|row| row.provider_session_id.as_deref() == Some("live_not_ready"))
    })
    .await;

    let removing = removing_in_background(&daemon).await;
    until("the registry is settling", || {
        the_registry_is(&daemon, RegistryState::Settling)
    })
    .await;
    release.notify_one();
    let removed = removing
        .await
        .expect("the task ends")
        .expect("the removal is answered");
    assert!(removed.removed);
    assert_eq!(removed.late_start, VoiceLateStart::Closed);
    assert_eq!(
        held_key(&daemon.host),
        None,
        "the item goes after the closure"
    );
    assert_eq!(
        daemon.stand_in.recorded().hangups,
        vec![(HELD_KEY.to_owned(), "live_not_ready".to_owned())],
        "the session was hung up with the key that was held then"
    );
    assert!(rows_of(&daemon).is_empty());
    let _ = starting.await;
    daemon.host.stop().await;
}

/// A removal that finds only a row with no id keeps the key and says the creation was not learned;
/// forget-calls then deletes the record and keeps the key, and the key can be removed after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remove_with_only_a_creating_row_keeps_the_item_and_forget_calls_deletes_it() {
    let mut daemon = daemon().await;
    let phone = phone(&daemon, &MANAGER).await;
    daemon.stand_in.script_create(CreateScript::Lost);
    let outcome = phone.start().await.expect("the start is answered").outcome;
    assert!(
        matches!(outcome, VoiceStartOutcome::CreationUnknown { .. }),
        "{outcome:?}"
    );
    assert_eq!(rows_of(&daemon).len(), 1);
    assert_eq!(rows_of(&daemon)[0].state, CallState::Creating);

    let refused = remove_key(&mut daemon.control, &daemon.host)
        .await
        .expect_err("a creating row keeps the key");
    assert_eq!(refused.message, words::CREATION_NOT_LEARNED);
    assert_eq!(held_key(&daemon.host).as_deref(), Some(HELD_KEY));
    assert_eq!(rows_of(&daemon).len(), 1, "the record is as it was");

    let forgotten = forget_calls(&mut daemon.control, &daemon.host)
        .await
        .expect("forgetting is answered");
    assert_eq!(forgotten.calls_forgotten, 1);
    assert!(rows_of(&daemon).is_empty());
    assert_eq!(held_key(&daemon.host).as_deref(), Some(HELD_KEY));
    let removed = remove_key(&mut daemon.control, &daemon.host)
        .await
        .expect("the removal is answered");
    assert!(removed.removed);
    assert_eq!(held_key(&daemon.host), None);
    let _ = &daemon.placed;
    daemon.host.stop().await;
}

/// A plain removal that meets a late creation whose hangup is not confirmed keeps the key and the
/// row with the late session's id, and says the call could not be confirmed closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plain_removal_that_cannot_confirm_the_late_session_closed_keeps_the_key_and_the_row_with_its_id()
 {
    let daemon = daemon().await;
    let phone = Arc::new(phone(&daemon, &MANAGER).await);
    let release = Arc::new(tokio::sync::Notify::new());
    daemon.stand_in.script_create(CreateScript::Held(
        Arc::clone(&release),
        Box::new(CreateScript::Answer(
            201,
            Some(created_body("live_late_session")),
        )),
    ));
    // The late hangup and the removal's own hangup of the stored row are both lost.
    daemon.stand_in.script_hangup(HangupScript::Lost);
    daemon.stand_in.script_hangup(HangupScript::Lost);
    let starting = starting_in_background(&phone);
    until("the creation reached the stand-in", || {
        creates_seen(&daemon) == 1
    })
    .await;
    let removing = removing_in_background(&daemon).await;
    until("the registry is settling", || {
        the_registry_is(&daemon, RegistryState::Settling)
    })
    .await;
    release.notify_one();
    let refused = removing
        .await
        .expect("the task ends")
        .expect_err("the removal could not confirm the call closed");
    assert_eq!(refused.message, words::NOT_CONFIRMED_CLOSED);
    assert_eq!(
        held_key(&daemon.host).as_deref(),
        Some(HELD_KEY),
        "the key stays so that the host can try again"
    );
    let rows = rows_of(&daemon);
    assert_eq!(rows.len(), 1, "the late session keeps its row");
    assert_eq!(rows[0].state, CallState::Unresolved);
    assert_eq!(
        rows[0].provider_session_id.as_deref(),
        Some("live_late_session")
    );
    assert!(
        daemon
            .stand_in
            .recorded()
            .hangups
            .iter()
            .all(|(key, session)| key == HELD_KEY && session == "live_late_session")
    );
    let _ = starting.await;
    daemon.host.stop().await;
}

/// A removal that cannot wait out the task of a call it ended keeps the key, the record and the
/// fence: no start is admitted and no key is put until that task has ended, and then the registry
/// is free again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_that_cannot_wait_out_a_calls_task_keeps_the_fence_until_that_task_ends() {
    let mut daemon = daemon().await;
    let phone = phone(&daemon, &MANAGER).await;
    let _ = started(phone.start().await);
    // The call's own task has ended in the host; what stays is a task that still holds the key.
    let task = daemon.host.controller().own_key_task_token();
    let refused = remove_key(&mut daemon.control, &daemon.host)
        .await
        .expect_err("the removal could not wait out the task");
    assert_eq!(refused.message, words::STILL_CLOSING);
    assert_eq!(held_key(&daemon.host).as_deref(), Some(HELD_KEY));
    assert!(
        the_registry_is(&daemon, RegistryState::Settling),
        "the fence is kept while a task that may read the key still runs"
    );
    let replaced = set_key(&mut daemon.control, &daemon.host, OTHER_KEY)
        .await
        .expect_err("the key is not replaced while the task runs");
    assert_eq!(replaced.message, words::KEY_IN_USE);
    assert_eq!(held_key(&daemon.host).as_deref(), Some(HELD_KEY));
    let refused_start = phone
        .start()
        .await
        .expect_err("no start is admitted while the fence is kept");
    assert_eq!(refused_start.code, ErrorCode::ResourceUnavailable);
    assert_eq!(refused_start.message, words::SETTLING);

    drop(task);
    assert!(the_registry_is(&daemon, RegistryState::Idle));
    set_key(&mut daemon.control, &daemon.host, OTHER_KEY)
        .await
        .expect("the key is replaced once the task has ended");
    assert_eq!(held_key(&daemon.host).as_deref(), Some(OTHER_KEY));
    daemon.host.stop().await;
}

/// A forget-calls that cannot wait out the task of a call it ended forgets nothing and keeps the
/// fence until that task has ended, so that the task never finds its record or its key gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forget_calls_that_cannot_wait_out_a_calls_task_keeps_the_record_and_the_fence() {
    let mut daemon = daemon().await;
    let phone = phone(&daemon, &MANAGER).await;
    let _ = started(phone.start().await);
    let task = daemon.host.controller().own_key_task_token();
    let rows_before = rows_of(&daemon).len();
    let refused = forget_calls(&mut daemon.control, &daemon.host)
        .await
        .expect_err("forgetting could not wait out the task");
    assert_eq!(refused.message, words::STILL_CLOSING);
    assert_eq!(
        rows_of(&daemon).len(),
        rows_before,
        "the record is kept while a task may still write to it"
    );
    assert!(
        the_registry_is(&daemon, RegistryState::Settling),
        "the fence is kept while the task runs"
    );
    drop(task);
    assert!(the_registry_is(&daemon, RegistryState::Idle));
    forget_calls(&mut daemon.control, &daemon.host)
        .await
        .expect("forgetting is answered once the task has ended");
    assert!(rows_of(&daemon).is_empty());
    daemon.host.stop().await;
}

/// A clean stop takes the fence first and keeps it: the serving tasks still run while the daemon
/// stops, so no start is admitted from then on, and the calls the host controls are ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clean_stop_fences_the_registry_before_it_ends_the_calls_and_admits_no_start_after() {
    let daemon = daemon().await;
    let phone = phone(&daemon, &MANAGER).await;
    let _ = started(phone.start().await);
    daemon.host.controller().close_host_calls_for_stop().await;
    assert!(
        the_registry_is(&daemon, RegistryState::Settling),
        "the fence taken by the stop is kept"
    );
    let refused = phone
        .start()
        .await
        .expect_err("no start is admitted while the daemon stops");
    assert_eq!(refused.message, words::SETTLING);
    assert!(rows_of(&daemon).is_empty(), "the call was closed");
    daemon.host.stop().await;
}

/// A forget-calls hangs a live call up once, and only when its close did not hear `session.closed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forget_calls_hangs_a_live_call_up_once_and_only_when_its_close_heard_no_closing_event() {
    for answer_close in [true, false] {
        let mut daemon = daemon().await;
        daemon.stand_in.answer_close(answer_close);
        let phone = phone(&daemon, &MANAGER).await;
        let _ = started(phone.start().await);

        let forgotten = forget_calls(&mut daemon.control, &daemon.host)
            .await
            .expect("forgetting is answered");
        assert_eq!(forgotten.late_start, VoiceLateStart::None);
        let seen = daemon.stand_in.recorded();
        let closes = seen
            .commands
            .iter()
            .filter(|command| command["type"] == "session.close")
            .count();
        assert_eq!(closes, 1, "the close protocol ran once");
        if answer_close {
            assert!(
                seen.hangups.is_empty(),
                "the close heard session.closed, so nothing is hung up: {:?}",
                seen.hangups
            );
        } else {
            assert_eq!(
                seen.hangups,
                vec![(HELD_KEY.to_owned(), "live_u1_stand_in".to_owned())],
                "one hangup with the held key, and no second one from the forget"
            );
        }
        assert!(rows_of(&daemon).is_empty());
        assert_eq!(held_key(&daemon.host).as_deref(), Some(HELD_KEY));
        daemon.host.stop().await;
    }
}

/// A forget-calls that comes while the start-time reconcile hangs a stored call up waits for it:
/// it is not refused, it hangs nothing up a second time, and it finds the record as the reconcile
/// left it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forget_calls_fences_a_running_reconcile_and_waits_for_its_hangup() {
    let daemon = daemon().await;
    let Daemon {
        host,
        stand_in,
        placed,
        control,
        owner,
    } = daemon;
    drop(control);
    let stopped = host.shut_down().await;
    let state_dir = stopped.tree().environment().state_dir().to_path_buf();
    {
        use kr_client::services::NewCall;
        let calls = OwnKeyCalls::open(&state_dir).expect("the record opens");
        let call = NewCall {
            call_id: "call-1".to_owned(),
            attempt_id: "attempt-1".to_owned(),
            action_id: ActionId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
            device_id: "device-1".to_owned(),
            asked_ms: 1_700_000_000_000,
            closes_at_ms: 1_700_000_300_000,
        };
        calls.begin(&call).expect("a row is written");
        calls
            .record_id(&call.call_id, "live_open", None)
            .expect("its id is written");
    }
    let release = Arc::new(tokio::sync::Notify::new());
    stand_in.script_hangup(HangupScript::Held(
        Arc::clone(&release),
        Box::new(HangupScript::Answer(200, Some(Vec::new()))),
    ));
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    until("the reconcile's hangup reached the stand-in", || {
        stand_in.recorded().hangups.len() == 1
    })
    .await;

    let mut client = host.client().await;
    let environment = host.environment_id;
    let mut forgetting =
        tokio::spawn(async move { forget_calls_of(&mut client, environment).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(500), &mut forgetting)
            .await
            .is_err(),
        "the forget waits for the reconcile and is not refused"
    );
    release.notify_one();
    let forgotten = forgetting
        .await
        .expect("the task ends")
        .expect("forgetting is answered after the reconcile");
    assert_eq!(forgotten.late_start, VoiceLateStart::None);
    assert_eq!(
        stand_in.recorded().hangups,
        vec![(HELD_KEY.to_owned(), "live_open".to_owned())],
        "the stored call is hung up once, by the reconcile"
    );
    assert!(
        OwnKeyCalls::open(&state_dir)
            .expect("the record opens")
            .rows()
            .expect("rows")
            .is_empty()
    );
    assert_eq!(held_key(&host).as_deref(), Some(HELD_KEY));
    let _ = owner;
    host.stop().await;
    drop(placed);
}

/// A host that holds the owner's key and no account is a host that needs no account, and it does
/// not report the managed inference service as configured, before a call and while one runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_own_voice_host_passes_assert_it_needs_no_account_and_does_not_report_managed_inference()
{
    let daemon = daemon().await;
    let not_configured = format!(
        "{}: not configured",
        kr_client::services::ManagedService::ManagedInference.as_str()
    );
    daemon.host.assert_it_needs_no_account().await;
    let before = daemon.host.managed_services().await;
    assert!(
        before.detail().contains(&not_configured),
        "managed inference is not configured before a call: {}",
        before.detail()
    );
    let phone = phone(&daemon, &MANAGER).await;
    let _ = started(phone.start().await);
    daemon.host.assert_it_needs_no_account().await;
    let during = daemon.host.managed_services().await;
    assert!(
        during.detail().contains(&not_configured),
        "managed inference is not configured while an own-key call runs: {}",
        during.detail()
    );
    daemon.host.stop().await;
}

/// A daemon of the testing build that has no stand-in under it asks the production connector once
/// at startup and is refused by it, and an own-key start on it never becomes a call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_testing_daemon_refuses_an_own_key_start_without_a_stand_in_transport_and_makes_no_connection()
 {
    use std::sync::atomic::Ordering;
    let owner = DeviceKeys::generate().expect("owner keys");
    let before = TESTING_REFUSALS.load(Ordering::Relaxed);
    let host = net_support::Host::start_with_own_voice_unplaced(&owner).await;
    assert_eq!(
        TESTING_REFUSALS.load(Ordering::Relaxed),
        before + 1,
        "the daemon asked the production connector once and the testing build refused it"
    );
    let mut control = host.client().await;
    set_key(&mut control, &host, HELD_KEY)
        .await
        .expect("the key is held");
    let phone = phone_on(&host, &owner, &MANAGER).await;
    let outcome = phone.start().await.expect("the start is answered").outcome;
    assert!(
        !matches!(outcome, VoiceStartOutcome::Started { .. }),
        "no call runs on a daemon that reaches nothing: {outcome:?}"
    );
    assert_eq!(
        TESTING_REFUSALS.load(Ordering::Relaxed),
        before + 1,
        "no second connection was asked for"
    );
    host.stop().await;
}

/// A document edited by hand to name both voice providers is refused at load with its sentence,
/// which the diagnostics show, and the daemon starts neither provider: a device is offered no call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_edited_document_naming_both_providers_is_refused_at_load_with_its_sentence_and_starts_no_provider()
 {
    const SENTENCE: &str = "voice: name either broker_origin or own_voice.provider, not both.";
    let daemon = daemon().await;
    let Daemon {
        host,
        placed,
        control,
        owner,
        ..
    } = daemon;
    drop(control);
    let stopped = host.shut_down().await;
    net_support::write_document_text(
        stopped.tree(),
        r#"{"version": 3, "level": 8, "voice": {"broker_origin": "https://broker.example.com"}, "own_voice": {"provider": "openai_live"}}"#,
    );
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    let doctor = host.doctor().await;
    let shown = format!("{:?}", doctor.configuration);
    assert!(
        shown.contains(SENTENCE),
        "the diagnostics carry the refusal: {shown}"
    );
    let phone = phone_on(&host, &owner, &MANAGER).await;
    assert!(
        matches!(
            phone.prepared.provider,
            VoicePrepareProvider::Unavailable { .. }
        ),
        "neither provider is started: {:?}",
        phone.prepared.provider
    );
    host.stop().await;
    drop(placed);
}
