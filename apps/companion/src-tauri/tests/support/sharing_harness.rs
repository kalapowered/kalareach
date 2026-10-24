// The person's computer and a device a session is shared with, against one daemon: the scene and
// the transport that loses what the host answers, which the sharing suites include. Included by
// each suite's root file, which declares `net_support`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use companion_tauri::AppState;
use companion_tauri::agent::WorkerLinks;
use companion_tauri::connection::{Connection, Reopen, Standing};
use companion_tauri::sharing::Pace;
use kr_client::Session;
use kr_client::error::ClientError;
use kr_client::ipc::IpcTransport;
use kr_client::pairing::paired::PairedHost;
use kr_client::transport::{ControlTransport, Reach, TransportFuture};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::hello::{ActionWindow, ReceiveLimits};
use kr_protocol::ids::{
    ActionId, ConnectionId, DeviceId, DeviceKeyRevision, GrantId, InvitationId, RequestId,
    SessionId,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{NetworkConfig, ProposedGrant};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::sharing::{
    AuthorityNotice, GrantCreateParams, GrantCreateResult, GrantHeldResult, GrantListParams,
    GrantListResult, GrantRedeemParams, GrantRedeemResult, GrantRevokeParams, GrantState,
    GrantTransferParams, GrantTransferResult, RevocationResult, RoleSelection, SessionRole,
    SessionScreenPreviewResult, local_actor, share_identities,
};
use net_support::worker::{Adopted, type_into};
use net_support::{Device, Host, RawDevice, an_open_session, on_the_host, owned_by, recipient};
use serde_json::{Value, json};
use tauri::Manager as _;
use tauri::test::MockRuntime;
use tokio::sync::Notify;

/// Where the bundle's pages are served from.
const BUNDLE: &str = "tauri://localhost";

/// How long one command, or one wait for a background step, may take before the test calls it hung.
const WATCHDOG: Duration = Duration::from_secs(60);

/// What the host's answer may be made to do on one connection.
#[derive(Debug, Default)]
struct Faults {
    /// Lose the host's answer to the next mutation sent: it is read and dropped, and the
    /// connection ends, as a connection does that the person's computer lost.
    answer: AtomicBool,
    /// Lose the next mutation before it leaves: the host never sees it.
    request: AtomicBool,
    /// Lose the connection as the read numbered so is about to leave, counting from one for the next
    /// read sent: the host never sees it. Zero is off.
    cut_at_read: AtomicUsize,
    /// Hold the next mutation before it leaves: it says it is held through the first, and leaves
    /// when the second is told. The host sees nothing until then.
    hold_next: Mutex<Option<(Arc<Notify>, Arc<Notify>)>>,
    watching: Mutex<Option<RequestId>>,
}

/// A transport that does what its [`Faults`] say and otherwise carries every frame as it is.
#[derive(Debug)]
struct Lossy {
    inner: Arc<dyn ControlTransport>,
    faults: Arc<Faults>,
}

impl ControlTransport for Lossy {
    fn connection_id(&self) -> ConnectionId {
        self.inner.connection_id()
    }

    fn limits(&self) -> ReceiveLimits {
        self.inner.limits()
    }

    fn initial_action_window(&self) -> ActionWindow {
        self.inner.initial_action_window()
    }

    fn reach(&self) -> Option<Reach> {
        self.inner.reach()
    }

    fn ended_by_this_device(&self) -> Option<kr_protocol::error::ProtocolError> {
        self.inner.ended_by_this_device()
    }

    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        Box::pin(async move {
            if let ControlFrame::Request(_) = frame {
                let counting = self.faults.cut_at_read.load(Ordering::SeqCst);
                if counting == 1 {
                    self.faults.cut_at_read.store(0, Ordering::SeqCst);
                    self.inner.close();
                    return Err(ClientError::ConnectionEnded);
                }
                if counting > 1 {
                    self.faults
                        .cut_at_read
                        .store(counting - 1, Ordering::SeqCst);
                }
            }
            if let ControlFrame::Mutation(_) = frame {
                let held = self
                    .faults
                    .hold_next
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                if let Some((parked, release)) = held {
                    parked.notify_one();
                    release.notified().await;
                }
            }
            if let ControlFrame::Mutation(request) = frame {
                if self.faults.request.swap(false, Ordering::SeqCst) {
                    self.inner.close();
                    return Err(ClientError::ConnectionEnded);
                }
                if self.faults.answer.swap(false, Ordering::SeqCst) {
                    *self
                        .faults
                        .watching
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) = Some(request.request_id);
                }
            }
            self.inner.send(frame).await
        })
    }

    fn claim_receiver(&self) -> kr_client::Result<()> {
        self.inner.claim_receiver()
    }

    fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
        Box::pin(async move {
            let frame = self.inner.recv().await?;
            if let Some(ControlFrame::Response(response)) = &frame {
                let mut watching = self
                    .faults
                    .watching
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if *watching == Some(response.request_id) {
                    watching.take();
                    self.inner.close();
                    return Ok(None);
                }
            }
            Ok(frame)
        })
    }

    fn revoke_streams(&self) {
        self.inner.revoke_streams();
    }

    fn close(&self) {
        self.inner.close();
    }
}

fn lossy(inner: Arc<dyn ControlTransport>, faults: &Arc<Faults>) -> Arc<dyn ControlTransport> {
    Arc::new(Lossy {
        inner,
        faults: Arc::clone(faults),
    })
}

/// A connection to the person's own host over its socket, as the application makes one, with the
/// way to open another.
async fn local_connection(host: &Host, faults: Option<&Arc<Faults>>) -> Connection {
    let endpoint = host.endpoint().clone();
    let transport = IpcTransport::connect_app(
        &endpoint,
        companion_tauri::connection::build_id().expect("a build identity"),
    )
    .await
    .expect("connects to the control endpoint");
    let environment_id = transport.context().environment_id;
    let uid = transport.context().peer.uid.get();
    let shared = transport.shared();
    let session = Session::start(match faults {
        Some(faults) => lossy(shared, faults),
        None => shared,
    })
    .expect("a session");
    let reopen: Reopen = Arc::new(move || {
        let endpoint = endpoint.clone();
        Box::pin(async move {
            let transport = IpcTransport::connect_app(
                &endpoint,
                companion_tauri::connection::build_id().expect("a build identity"),
            )
            .await
            .map_err(companion_tauri::CommandError::from)?;
            Connection::over(transport)
        })
    });
    Connection::assembled(
        session,
        environment_id,
        Standing::Owner,
        Some(uid),
        Some(reopen),
    )
}

/// The record a paired device keeps of its host, for a connection these suites assemble by hand.
/// They open no session of their own, so nothing but its shape is read.
fn host_record(device_id: DeviceId) -> Box<PairedHost> {
    let keys = DeviceKeys::generate().expect("keys").public_keys();
    Box::new(PairedHost {
        host_device_id: DeviceId::new(kr_ipc::new_uuid()),
        host_key_revision: DeviceKeyRevision::new(1),
        host_endpoint_id: keys.transport,
        host_keys: keys,
        network_config: NetworkConfig::empty(),
        device_id,
        grant_id: GrantId::new(kr_ipc::new_uuid()),
        proposed_grant: ProposedGrant {
            parent_grant_id: Nullable::null(),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: CanonicalSet::new(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: true,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry: GrantExpiry::Never,
            organisation: Nullable::null(),
        },
        name: None,
        paired_at_ms: 0,
        device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(1),
    })
}

/// Opens a paired connection for the host alone, as the application does when it connects to a host
/// it is paired with: the host then serves its own reads and the sharing commands on it, and refuses
/// it every decision under a share and every route to a session's worker.
///
/// A host that does not answer ends the test at the watchdog, and a refusal is the connection's
/// failure, as it is for the application.
async fn open_for_the_host(session: &Session) -> Result<(), companion_tauri::CommandError> {
    tokio::time::timeout(
        WATCHDOG,
        session.read::<_, kr_protocol::session::SessionOpenResult>(
            kr_protocol::method::Method::SessionOpen,
            &kr_protocol::session::SessionOpenParams {
                session_id: Nullable::null(),
                grant_id: Nullable::null(),
            },
        ),
    )
    .await
    .map_err(|_| {
        companion_tauri::CommandError::unavailable("the host did not open the connection")
    })?
    .map(|_| ())
    .map_err(companion_tauri::CommandError::from)
}

/// A connection of a paired device to the host it is paired with, as the application makes one.
async fn paired_connection(
    host: &Host,
    device: &Device,
    record: &kr_controller::service::net::devices::DeviceRecord,
    faults: Option<&Arc<Faults>>,
) -> Connection {
    let dial = net_support::paired_dial(host, device, record);
    let shared: Arc<dyn ControlTransport> = Arc::new(dial.dial().await);
    let session = Session::start(match faults {
        Some(faults) => lossy(shared, faults),
        None => shared,
    })
    .expect("a session");
    open_for_the_host(&session)
        .await
        .expect("the host opens the connection for itself");
    let reopen: Reopen = Arc::new(move || {
        let dial = dial.clone();
        Box::pin(async move {
            let session = Session::start(Arc::new(dial.dial().await)).expect("a session");
            open_for_the_host(&session).await?;
            Ok(Connection::assembled(
                session,
                // The environment of a connection that is only read from or repeated on is not
                // asked of it.
                kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()),
                {
                    let device_id = DeviceId::new(kr_ipc::new_uuid());
                    Standing::Paired {
                        device_id,
                        rights: Vec::new(),
                        host: host_record(device_id),
                    }
                },
                None,
                None,
            ))
        })
    });
    Connection::assembled(
        session,
        host.environment_id,
        Standing::Paired {
            device_id: record.device_id,
            rights: Vec::new(),
            host: host_record(record.device_id),
        },
        None,
        Some(reopen),
    )
}

/// The application's backend on the mock runtime, called through the invoke path.
struct Page {
    app: tauri::App<MockRuntime>,
    window: tauri::WebviewWindow<MockRuntime>,
    /// Where the application keeps what it keeps on this computer. A restart keeps it.
    data: Arc<tempfile::TempDir>,
}

impl Page {
    fn start(connection: Connection, data: Arc<tempfile::TempDir>, links: WorkerLinks) -> Self {
        let state = AppState::new();
        state.keep_under(data.path());
        state.connected(connection);
        let app = tauri::test::mock_builder()
            .manage(state)
            .manage(links)
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::device_list,
                companion_tauri::commands::grant_list,
                companion_tauri::commands::grant_create,
                companion_tauri::commands::grant_revoke,
                companion_tauri::commands::grant_redeem,
                companion_tauri::commands::grant_held,
                companion_tauri::commands::session_screen_preview,
                companion_tauri::commands::transfer_ask,
                companion_tauri::commands::transfer_answered,
                companion_tauri::commands::transfer_finish,
                companion_tauri::commands::transfer_cancel,
                companion_tauri::commands::attempts_list,
                companion_tauri::commands::attempt_ask,
                companion_tauri::commands::attempt_set_hidden,
                companion_tauri::commands::attempt_remove,
                companion_tauri::commands::attention_read,
                companion_tauri::commands::session_list,
                companion_tauri::commands::session_read,
            ])
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("an application");
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("a window");
        Self { app, window, data }
    }

    fn state(&self) -> tauri::State<'_, AppState> {
        self.app.state::<AppState>()
    }

    /// Calls `command` as the page does and waits for its answer.
    async fn call(&self, command: &'static str, body: Value) -> Result<Value, Value> {
        assert!(
            companion_tauri::commands::NAMED_COMMANDS
                .iter()
                .any(|(name, _)| *name == command),
            "{command} is a command the application registers"
        );
        let window = self.window.clone();
        let answer = tokio::task::spawn_blocking(move || {
            tauri::test::get_ipc_response(
                &window,
                tauri::webview::InvokeRequest {
                    cmd: command.into(),
                    callback: tauri::ipc::CallbackFn(0),
                    error: tauri::ipc::CallbackFn(1),
                    url: BUNDLE.parse().expect("the bundle's address"),
                    body: tauri::ipc::InvokeBody::Json(body),
                    headers: Default::default(),
                    invoke_key: tauri::test::INVOKE_KEY.to_owned(),
                },
            )
            .map(|answer| {
                answer
                    .deserialize::<Value>()
                    .expect("an answer the page reads")
            })
        });
        tokio::time::timeout(WATCHDOG, answer)
            .await
            .expect("the command answered within the watchdog")
            .expect("the command's thread finished")
    }

    /// What the application keeps for the host it is connected to, as the page reads it.
    async fn attempts(&self) -> Vec<Value> {
        let listed = self
            .call("attempts_list", json!({}))
            .await
            .expect("the attempts are listed");
        listed["attempts"].as_array().expect("a list").clone()
    }

    /// Waits until the attempts listed hold one `matching` accepts, and returns it.
    async fn attempt_where(&self, matching: impl Fn(&Value) -> bool) -> Value {
        tokio::time::timeout(WATCHDOG, async {
            loop {
                if let Some(found) = self.attempts().await.into_iter().find(&matching) {
                    return found;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("an attempt gets there")
    }
}

/// The person's computer and a device a session is shared with, against one daemon.
struct Scene {
    host: Host,
    owner: DeviceKeys,
    session_id: SessionId,
    device: Device,
    record: kr_controller::service::net::devices::DeviceRecord,
    issuer_faults: Arc<Faults>,
    phone_faults: Arc<Faults>,
    issuer: Page,
    phone: Page,
}

/// The pace at which a background step goes: at once.
const AT_ONCE: Pace = Pace {
    repeats: [Duration::ZERO; 3],
    check_every: Duration::from_millis(20),
};

/// The pace of an application that is left for a long time before it asks again, which a test uses
/// to stop its background step from recovering before the application is restarted.
const FOR_A_WHILE: Pace = Pace {
    repeats: [Duration::from_secs(3600); 3],
    check_every: Duration::from_secs(3600),
};

impl Scene {
    async fn start() -> Self {
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start(&owner).await;
        Self::around(owner, host).await
    }

    async fn around(owner: DeviceKeys, host: Host) -> Self {
        let (device, record) = recipient(&host, &owner).await;
        let (session_id, _) = an_open_session(&host);
        let issuer_faults = Arc::new(Faults::default());
        let phone_faults = Arc::new(Faults::default());
        let environment = host.tree().environment();
        let issuer = Page::start(
            local_connection(&host, Some(&issuer_faults)).await,
            Arc::new(tempfile::tempdir().expect("a data directory")),
            WorkerLinks::at(environment.clone()),
        );
        let phone = Page::start(
            paired_connection(&host, &device, &record, Some(&phone_faults)).await,
            Arc::new(tempfile::tempdir().expect("a data directory")),
            WorkerLinks::at(environment),
        );
        issuer.state().shares().pace_at(AT_ONCE);
        phone.state().shares().pace_at(AT_ONCE);
        Self {
            host,
            owner,
            session_id,
            device,
            record,
            issuer_faults,
            phone_faults,
            issuer,
            phone,
        }
    }

    /// The person's computer, started again over the same data directory: a new backend and a new
    /// connection that loses nothing.
    async fn restart_issuer(&mut self) {
        let data = Arc::clone(&self.issuer.data);
        let faults = Arc::new(Faults::default());
        self.issuer = Page::start(
            local_connection(&self.host, Some(&faults)).await,
            data,
            WorkerLinks::at(self.host.tree().environment()),
        );
        self.issuer_faults = faults;
        self.issuer.state().shares().pace_at(AT_ONCE);
    }

    /// The device, started again over the same data directory.
    async fn restart_phone(&mut self) {
        let data = Arc::clone(&self.phone.data);
        let faults = Arc::new(Faults::default());
        self.phone = Page::start(
            paired_connection(&self.host, &self.device, &self.record, Some(&faults)).await,
            data,
            WorkerLinks::at(self.host.tree().environment()),
        );
        self.phone_faults = faults;
        self.phone.state().shares().pace_at(AT_ONCE);
    }

    /// The application's connection taken up again, as it does when one ends: the backend and what
    /// it keeps stay, and the connection is a new one that loses nothing.
    async fn reconnect_issuer(&mut self) {
        let faults = Arc::new(Faults::default());
        self.issuer
            .state()
            .connected(local_connection(&self.host, Some(&faults)).await);
        self.issuer_faults = faults;
    }

    /// As [`Self::reconnect_issuer`], for the device.
    async fn reconnect_phone(&mut self) {
        let faults = Arc::new(Faults::default());
        self.phone.state().connected(
            paired_connection(&self.host, &self.device, &self.record, Some(&faults)).await,
        );
        self.phone_faults = faults;
    }

    /// The choices of an invitation to the device as a viewer, and the subject the page names.
    fn invitation(&self, role: SessionRole) -> Value {
        self.invitation_lasting(role, None)
    }

    /// As [`Self::invitation`], for `lifetime_ms` when it names one.
    fn invitation_lasting(&self, role: SessionRole, lifetime_ms: Option<u64>) -> Value {
        let selection = RoleSelection::plain(role);
        let params = GrantCreateParams {
            session_id: self.session_id,
            recipient_device_id: self.record.device_id,
            parent_grant_id: Nullable::null(),
            accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
            selection,
            lifetime_ms: Nullable(lifetime_ms.map(kr_protocol::scalars::DurationMs::new)),
            owner_confirmation: Nullable::null(),
        };
        json!({
            "params": serde_json::to_value(&params).expect("encodes"),
            "subject": { "sessionId": self.session_id.to_string(), "sessionEpoch": "1" },
        })
    }

    /// What the host lists for the session, resolved grants included.
    async fn listed(&self) -> GrantListResult {
        net_support::pairing::read(
            &mut self.host.client().await,
            kr_protocol::method::Method::GrantList,
            &GrantListParams {
                session_id: Nullable::some(self.session_id),
                include_resolved: true,
            },
        )
        .await
        .expect("the list is read")
    }

    /// A hand-over of the session from the device, which holds it as an owner of it, to another
    /// device, asked for through the page and confirmed by the owner device: ready to be sent.
    async fn confirmed_hand_over(&self) -> HandOver {
        use net_support::pairing::{self as calls, Signer};

        let (_share, giving) =
            owned_by(&self.host, self.session_id, &self.device, &self.record).await;
        let (taker, taker_record) = recipient(&self.host, &self.owner).await;
        let from = self
            .listed()
            .await
            .grants
            .iter()
            .find(|summary| {
                summary.state == GrantState::Active
                    && summary.grant.recipient_device_id == self.record.device_id
            })
            .expect("the device's share")
            .grant
            .grant_id;
        let asked = self
            .issuer
            .call(
                "transfer_ask",
                json!({
                    "params": serde_json::to_value(&GrantTransferParams {
                        session_id: self.session_id,
                        from_grant_id: from,
                        to_device_id: taker_record.device_id,
                    }).expect("encodes"),
                    "subject": {
                        "sessionId": self.session_id.to_string(), "sessionEpoch": "1",
                    },
                }),
            )
            .await
            .expect("the owner devices are asked");
        let reference = asked["reference"].as_str().expect("a reference").to_owned();
        let mut client = self.host.client().await;
        let pending = calls::pending(&mut client).await.expect("readable").pending;
        let (proof, presented) =
            calls::sign(&pending[0].request, &Signer::OwnerDevice(&self.owner));
        calls::complete(self.host.environment_id, &mut client, proof, presented)
            .await
            .expect("the owner answers");
        let answered = self
            .issuer
            .call("transfer_answered", json!({ "reference": reference }))
            .await
            .expect("read");
        assert_eq!(answered["state"], "answered");
        HandOver {
            reference,
            from,
            taker,
            taker_record,
            giving,
        }
    }

    /// The body of a request to hand the session over from the device, which holds it as an owner
    /// of it, to another paired device, and the connection that keeps the device's share alive.
    async fn hand_over_body(&self) -> (Value, net_support::RawDevice) {
        let (_share, giving) =
            owned_by(&self.host, self.session_id, &self.device, &self.record).await;
        let (_taker, taker_record) = recipient(&self.host, &self.owner).await;
        let from = self
            .listed()
            .await
            .grants
            .iter()
            .find(|summary| summary.state == GrantState::Active)
            .expect("the device's share")
            .grant
            .grant_id;
        let body = json!({
            "params": serde_json::to_value(&GrantTransferParams {
                session_id: self.session_id,
                from_grant_id: from,
                to_device_id: taker_record.device_id,
            }).expect("encodes"),
            "subject": { "sessionId": self.session_id.to_string(), "sessionEpoch": "1" },
        });
        (body, giving)
    }

    async fn stop(self) {
        self.issuer
            .state()
            .connection()
            .expect("connected")
            .session()
            .close();
        self.phone
            .state()
            .connection()
            .expect("connected")
            .session()
            .close();
        drop(self.issuer);
        drop(self.phone);
        self.host.stop().await;
    }
}

/// A hand-over an owner device confirmed and the page has not sent.
struct HandOver {
    reference: String,
    from: GrantId,
    #[allow(
        dead_code,
        reason = "held so the device stays paired for the test's length"
    )]
    taker: Device,
    taker_record: kr_controller::service::net::devices::DeviceRecord,
    giving: net_support::RawDevice,
}

fn typed<T: serde::de::DeserializeOwned>(value: &Value) -> T {
    serde_json::from_value(value.clone()).expect("the answer is the method's own result")
}

/// What `grant_held` answered, as the protocol's own result.
fn held_of(answer: &Value) -> GrantHeldResult {
    typed(&json!({
        "offers": answer["offers"], "offers_more": false,
        "shares": answer["shares"], "shares_more": false,
    }))
}

/// What the person at the machine is told by the host's own words when the attempt was refused.
fn code_of(refusal: &Value) -> &str {
    refusal["code"].as_str().unwrap_or_default()
}
