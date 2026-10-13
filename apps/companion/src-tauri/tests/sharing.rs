//! Sharing a session from the companion, and accepting a share on a device it is shared with,
//! called the way the page calls it.
//!
//! The daemon is kr-controller's in-process host with its test support included by path. The
//! person's computer is this crate's backend on the mock runtime, connected to the daemon's own
//! socket; the device the session is shared with is a second backend on a paired connection of its
//! own. What a test puts of its own between a backend and the daemon is a transport that loses what
//! the host answers to one mutation, or the mutation before it leaves: the daemon, its store and
//! its answers are the product's.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-18.12 | `the_typed_result_reaches_the_page_and_a_share_is_accepted_and_taken_back` |
//! | KR-REQ-18.14 | `a_lost_reply_is_asked_about_again_and_answered_from_the_hosts_record` |
//! | KR-REQ-18.13 | `an_accepted_invitation_whose_reply_was_lost_is_found_accepted` |
//! | KR-REQ-18.15 | `a_hand_over_asks_an_owner_device_and_sends_only_what_it_confirmed` |
//! | KR-REQ-18.15 | `a_hand_over_whose_challenge_the_host_lost_is_ended_and_can_be_asked_again` |
//! | KR-REQ-23.49 | `an_application_restarted_after_the_host_committed_asks_the_host_and_is_answered` |
//! | KR-REQ-23.49 | `a_second_invitation_is_not_started_while_the_first_can_still_happen` |
//! | KR-REQ-23.49 | `an_action_the_host_never_saw_is_not_done_only_after_the_bound` |

#![cfg(unix)]

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use companion_tauri::AppState;
use companion_tauri::agent::WorkerLinks;
use companion_tauri::connection::{Connection, Reopen, Standing};
use companion_tauri::sharing::Pace;
use kr_client::Session;
use kr_client::error::ClientError;
use kr_client::ipc::IpcTransport;
use kr_client::transport::{ControlTransport, Reach, TransportFuture};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::hello::{ActionWindow, ReceiveLimits};
use kr_protocol::ids::{ConnectionId, DeviceId, GrantId, InvitationId, RequestId, SessionId};
use kr_protocol::scalars::Nullable;
use kr_protocol::sharing::{
    AuthorityNotice, GrantCreateParams, GrantCreateResult, GrantHeldResult, GrantListParams,
    GrantListResult, GrantRedeemParams, GrantRedeemResult, GrantRevokeParams, GrantState,
    GrantTransferParams, GrantTransferResult, RevocationResult, RoleSelection, SessionRole,
    local_actor, share_identities,
};
use net_support::{Device, Host, an_open_session, owned_by, recipient};
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

    fn send<'a>(&'a self, frame: &'a ControlFrame) -> TransportFuture<'a, ()> {
        Box::pin(async move {
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
    let reopen: Reopen = Arc::new(move || {
        let dial = dial.clone();
        Box::pin(async move {
            let session = Session::start(Arc::new(dial.dial().await)).expect("a session");
            Ok(Connection::assembled(
                session,
                // The environment of a connection that is only read from or repeated on is not
                // asked of it.
                kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()),
                Standing::Paired {
                    device_id: DeviceId::new(kr_ipc::new_uuid()),
                    rights: Vec::new(),
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
        let selection = RoleSelection::plain(role);
        let params = GrantCreateParams {
            session_id: self.session_id,
            recipient_device_id: self.record.device_id,
            parent_grant_id: Nullable::null(),
            accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
            selection,
            lifetime_ms: Nullable::null(),
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

/// What the person at the machine is told by the host's own words when the attempt was refused.
fn code_of(refusal: &Value) -> &str {
    refusal["code"].as_str().unwrap_or_default()
}

/// KR-REQ-18.12, KR-REQ-18.13, KR-REQ-18.14: the invitation, its acceptance and its withdrawal reach
/// the page as the methods' own results, in shapes the protocol defines, and the device sees only
/// what the host tells it. An invitation the host answers at once leaves no record behind. The
/// person's computer issues and the device holds, and neither does the other's part.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_typed_result_reaches_the_page_and_a_share_is_accepted_and_taken_back() {
    let scene = Scene::start().await;

    let made = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("the invitation is issued");
    assert_eq!(made["attempt"]["phase"], "closed");
    assert_eq!(made["attempt"]["outcome"], "happened");
    let created: GrantCreateResult = typed(&made["value"]);
    assert_eq!(created.grant.recipient_device_id, scene.record.device_id);
    assert!(created.preview.single_use);
    assert!(
        scene.issuer.attempts().await.is_empty(),
        "an answer the host gave at once leaves no record"
    );
    assert_eq!(
        scene
            .issuer
            .state()
            .connection()
            .expect("connected")
            .session()
            .submitted_actions()
            .await
            .len(),
        0,
        "and the action is settled in the connection's book"
    );

    // The device is told what it is offered, and nothing of the text its issuer was shown.
    let held = scene
        .phone
        .call("grant_held", json!({}))
        .await
        .expect("held");
    let offers: GrantHeldResult = typed(&json!({
        "offers": held["offers"], "offers_more": false,
        "shares": held["shares"], "shares_more": false,
    }));
    assert_eq!(offers.offers.len(), 1);
    assert_eq!(
        offers.offers[0].invitation_id,
        created.preview.invitation_id
    );
    assert!(offers.shares.is_empty());

    let accepted = scene
        .phone
        .call(
            "grant_redeem",
            json!({ "params": serde_json::to_value(&GrantRedeemParams {
                invitation_id: created.preview.invitation_id,
            }).expect("encodes") }),
        )
        .await
        .expect("the invitation is accepted");
    assert_eq!(accepted["attempt"]["outcome"], "happened");
    let redeemed: GrantRedeemResult = typed(&accepted["value"]);
    assert_eq!(redeemed.grant.grant_id, created.grant.grant_id);
    let held = scene
        .phone
        .call("grant_held", json!({}))
        .await
        .expect("held");
    assert_eq!(held["offers"].as_array().expect("offers").len(), 0);
    assert_eq!(held["shares"].as_array().expect("shares").len(), 1);

    let revoked = scene
        .issuer
        .call(
            "grant_revoke",
            json!({ "params": serde_json::to_value(&GrantRevokeParams {
                grant_id: created.grant.grant_id,
            }).expect("encodes") }),
        )
        .await
        .expect("the share is taken back");
    let result: RevocationResult = typed(&revoked["value"]);
    assert!(result.barrier.holds(), "no worker owes a fence here");
    let held = scene
        .phone
        .call("grant_held", json!({}))
        .await
        .expect("held");
    assert_eq!(held["shares"].as_array().expect("shares").len(), 0);

    // Each side does its own part and not the other's.
    let refused = scene
        .phone
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect_err("a device it is paired with does not issue from here");
    assert_eq!(code_of(&refused), "PERMISSION_DENIED", "{refused}");
    let refused = scene
        .issuer
        .call("grant_held", json!({}))
        .await
        .expect_err("the host's own computer holds no share of it");
    assert_eq!(code_of(&refused), "PERMISSION_DENIED", "{refused}");
    scene.stop().await;
}

/// KR-REQ-18.14: the host's answer to an invitation is lost, and the application, which kept the
/// request before it sent it, asks the host again with the same request on a connection opened for
/// it. The host answers from the record it kept, so the invitation exists once, and the page reads
/// the host's own result from the attempt. The record stays until the page removes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_reply_is_asked_about_again_and_answered_from_the_hosts_record() {
    let scene = Scene::start().await;
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);

    let sent = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("the application answers though the host's answer was lost");
    assert_ne!(
        sent["attempt"]["phase"], "closed",
        "the answer was lost, so nothing is known yet"
    );
    assert_eq!(sent["value"], Value::Null);

    let done = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(done["outcome"], "happened");
    let created: GrantCreateResult = typed(&done["result"]);
    assert_eq!(created.grant.recipient_device_id, scene.record.device_id);
    let listed = scene.listed().await;
    assert_eq!(
        listed.grants.len(),
        1,
        "the host performed it once, however often it was asked"
    );
    assert_eq!(listed.grants[0].grant.grant_id, created.grant.grant_id);

    // The grant the application would have looked for is the one the host wrote.
    let uid = scene
        .issuer
        .state()
        .connection()
        .expect("connected")
        .actor()
        .expect("an actor");
    let (grant_id, _) = share_identities(&uid, uuid_of(&done["action_id"]));
    assert_eq!(grant_id, created.grant.grant_id);

    scene
        .issuer
        .call(
            "attempt_remove",
            json!({ "actionId": done["action_id"].as_str().expect("an action") }),
        )
        .await
        .expect("the record is removed once the page has read it");
    assert!(scene.issuer.attempts().await.is_empty());
    assert_eq!(
        scene
            .issuer
            .state()
            .connection()
            .expect("connected")
            .session()
            .submitted_actions()
            .await
            .len(),
        0,
        "the lost action is settled in the book once the attempt is over"
    );
    scene.stop().await;
}

fn uuid_of(value: &Value) -> kr_protocol::scalars::Uuid {
    value
        .as_str()
        .expect("a uuid")
        .parse::<kr_protocol::ids::ActionId>()
        .expect("an action identifier")
        .get()
}

/// KR-REQ-18.13: the device's acceptance is committed by the host and its answer is lost; the
/// application finds it accepted by asking again, and the share is held once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_accepted_invitation_whose_reply_was_lost_is_found_accepted() {
    let mut scene = Scene::start().await;
    let made = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("issued");
    let created: GrantCreateResult = typed(&made["value"]);
    scene.phone_faults.answer.store(true, Ordering::SeqCst);

    let sent = scene
        .phone
        .call(
            "grant_redeem",
            json!({ "params": serde_json::to_value(&GrantRedeemParams {
                invitation_id: created.preview.invitation_id,
            }).expect("encodes") }),
        )
        .await
        .expect("answered");
    assert_ne!(sent["attempt"]["phase"], "closed");

    let done = scene
        .phone
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(done["outcome"], "happened");
    let redeemed: GrantRedeemResult = typed(&done["result"]);
    assert_eq!(redeemed.grant.grant_id, created.grant.grant_id);
    // The connection that lost the answer is gone, and the application takes one up again.
    scene.reconnect_phone().await;
    let held = scene
        .phone
        .call("grant_held", json!({}))
        .await
        .expect("held");
    assert_eq!(held["shares"].as_array().expect("shares").len(), 1);
    scene.stop().await;
}

/// KR-REQ-23.49: the application is stopped after the host committed and before the answer
/// arrived. Started again, it reads the attempt back from what it kept, shows it as unfinished and
/// sends nothing by itself; *Ask the host* is the person's choice, and it is answered from the host's
/// record. That holds for each of the four actions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_application_restarted_after_the_host_committed_asks_the_host_and_is_answered() {
    let mut scene = Scene::start().await;

    // An invitation.
    scene.issuer.state().shares().pace_at(FOR_A_WHILE);
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);
    let sent = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("answered");
    assert_ne!(sent["attempt"]["phase"], "closed");
    let action = sent["attempt"]["action_id"]
        .as_str()
        .expect("an action")
        .to_owned();
    scene.restart_issuer().await;
    let back = scene.issuer.attempts().await;
    assert_eq!(back.len(), 1, "the attempt is read back");
    assert_eq!(back[0]["action_id"], action.as_str());
    assert_eq!(back[0]["kind"], "invite");
    assert_ne!(back[0]["phase"], "closed");
    assert_eq!(
        scene.listed().await.grants.len(),
        1,
        "the host committed it"
    );
    let asked = scene
        .issuer
        .call("attempt_ask", json!({ "actionId": action }))
        .await
        .expect("the host answers from its record");
    let created: GrantCreateResult = typed(&asked["value"]);
    assert!(
        scene.issuer.attempts().await.is_empty(),
        "the result is the page's, so there is no record of it"
    );
    assert_eq!(scene.listed().await.grants.len(), 1);

    // Its acceptance, on the device.
    scene.phone.state().shares().pace_at(FOR_A_WHILE);
    scene.phone_faults.answer.store(true, Ordering::SeqCst);
    let sent = scene
        .phone
        .call(
            "grant_redeem",
            json!({ "params": serde_json::to_value(&GrantRedeemParams {
                invitation_id: created.preview.invitation_id,
            }).expect("encodes") }),
        )
        .await
        .expect("answered");
    let action = sent["attempt"]["action_id"]
        .as_str()
        .expect("an action")
        .to_owned();
    scene.restart_phone().await;
    let back = scene.phone.attempts().await;
    assert_eq!(back.len(), 1);
    assert_eq!(back[0]["kind"], "redeem");
    let asked = scene
        .phone
        .call("attempt_ask", json!({ "actionId": action }))
        .await
        .expect("answered from the host's record");
    let redeemed: GrantRedeemResult = typed(&asked["value"]);
    assert_eq!(redeemed.grant.grant_id, created.grant.grant_id);

    // Its withdrawal.
    scene.issuer.state().shares().pace_at(FOR_A_WHILE);
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);
    let sent = scene
        .issuer
        .call(
            "grant_revoke",
            json!({ "params": serde_json::to_value(&GrantRevokeParams {
                grant_id: created.grant.grant_id,
            }).expect("encodes") }),
        )
        .await
        .expect("answered");
    let action = sent["attempt"]["action_id"]
        .as_str()
        .expect("an action")
        .to_owned();
    scene.restart_issuer().await;
    let back = scene.issuer.attempts().await;
    assert_eq!(back.len(), 1);
    assert_eq!(back[0]["kind"], "revoke");
    let asked = scene
        .issuer
        .call("attempt_ask", json!({ "actionId": action }))
        .await
        .expect("answered from the host's record");
    let revoked: RevocationResult = typed(&asked["value"]);
    assert!(revoked.barrier.holds());
    assert!(
        scene
            .listed()
            .await
            .grants
            .iter()
            .any(|summary| summary.grant.grant_id == created.grant.grant_id
                && summary.state == GrantState::Revoked)
    );
    scene.stop().await;
}

/// KR-REQ-23.49: a second invitation of the same session to the same device is not started while
/// the first can still happen, whatever the person did to the row: hiding it takes it out of view
/// and releases nothing, and a restart keeps it. The host performed the first once, and the person
/// who asks about it gets its result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_invitation_is_not_started_while_the_first_can_still_happen() {
    let mut scene = Scene::start().await;
    scene.issuer.state().shares().pace_at(FOR_A_WHILE);
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);
    let first = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("answered");
    let action = first["attempt"]["action_id"]
        .as_str()
        .expect("an action")
        .to_owned();
    scene.reconnect_issuer().await;

    let refused = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect_err("the first can still happen");
    assert_eq!(code_of(&refused), "PERMISSION_DENIED", "{refused}");
    assert_eq!(
        scene.listed().await.grants.len(),
        1,
        "and nothing else was written"
    );

    let hidden = scene
        .issuer
        .call(
            "attempt_set_hidden",
            json!({ "actionId": action, "hidden": true }),
        )
        .await
        .expect("hidden");
    assert_eq!(hidden["hidden"], true);
    let refused = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect_err("hiding it releases nothing");
    assert_eq!(code_of(&refused), "PERMISSION_DENIED");

    scene.restart_issuer().await;
    let refused = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect_err("a restart keeps the gate");
    assert_eq!(code_of(&refused), "PERMISSION_DENIED");

    // A record that can still happen is not removed either.
    let kept = scene
        .issuer
        .call("attempt_remove", json!({ "actionId": action }))
        .await
        .expect_err("it can still happen");
    assert_eq!(code_of(&kept), "PERMISSION_DENIED");

    // The host's answer closes it, and a closed attempt gates nothing.
    scene
        .issuer
        .call("attempt_ask", json!({ "actionId": action }))
        .await
        .expect("answered");
    let again = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Controller))
        .await;
    assert!(again.is_ok(), "{again:?}");
    scene.stop().await;
}

/// KR-REQ-23.49: an action the host never saw is not reported as not done before the bound the
/// window sets has passed, however often the host is asked and however often a read finds nothing;
/// after it, the application says it did not happen as far as the host shows, and nothing is
/// written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_action_the_host_never_saw_is_not_done_only_after_the_bound() {
    let scene = Scene::start().await;
    scene.issuer_faults.request.store(true, Ordering::SeqCst);
    let sent = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("answered");
    assert_ne!(sent["attempt"]["phase"], "closed");
    let action = sent["attempt"]["action_id"]
        .as_str()
        .expect("an action")
        .to_owned();

    // It is asked about, finds nothing, and keeps reading: the host's window for it has not ended.
    let checking = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "checking")
        .await;
    assert_eq!(checking["action_id"], action.as_str());
    tokio::time::sleep(Duration::from_millis(400)).await;
    let still = scene.issuer.attempts().await;
    assert_eq!(still.len(), 1);
    assert_eq!(
        still[0]["phase"], "checking",
        "an absent grant proves nothing before the bound: {still:?}"
    );
    assert!(still[0]["can_happen_until_ms"].is_string());

    // The clock that counts the bound passes it.
    scene
        .issuer
        .state()
        .shares()
        .advance(Duration::from_secs(3600));
    let closed = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(closed["outcome"], "not_done");
    assert_eq!(closed["result"], Value::Null);
    assert!(
        scene.listed().await.grants.is_empty(),
        "and nothing was written"
    );
    scene.stop().await;
}

/// KR-REQ-18.15: handing a session over asks an owner device to confirm exactly the plan the host
/// describes, and the transfer is sent only after it answered. The giving device loses the session,
/// the receiving device holds it, and the page is answered with the host's result. Cancelling
/// before the owner answers sends nothing, and a reference is spent by the one transfer it sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_over_asks_an_owner_device_and_sends_only_what_it_confirmed() {
    use kr_protocol::confirmation::{ConfirmationDisplay, TransferControlPlan};
    use net_support::pairing::{self as calls, Signer};

    let scene = Scene::start().await;
    // The device holds the session as an owner of it, and another device is to receive it.
    let (_share, giving) =
        owned_by(&scene.host, scene.session_id, &scene.device, &scene.record).await;
    let (_taker, taker_record) = recipient(&scene.host, &scene.owner).await;
    let held: GrantListResult = scene.listed().await;
    let from = held
        .grants
        .iter()
        .find(|summary| summary.state == GrantState::Active)
        .expect("the device's share")
        .grant
        .grant_id;
    let params = GrantTransferParams {
        session_id: scene.session_id,
        from_grant_id: from,
        to_device_id: taker_record.device_id,
    };
    let body = json!({
        "params": serde_json::to_value(&params).expect("encodes"),
        "subject": { "sessionId": scene.session_id.to_string(), "sessionEpoch": "1" },
    });

    let asked = scene
        .issuer
        .call("transfer_ask", body.clone())
        .await
        .expect("the owner devices are asked");
    let reference = asked["reference"].as_str().expect("a reference").to_owned();
    assert_eq!(asked["attempt"]["phase"], "asking");
    let waiting = scene
        .issuer
        .call("transfer_answered", json!({ "reference": reference }))
        .await
        .expect("read");
    assert_eq!(waiting["state"], "waiting");
    assert_eq!(
        waiting["plan"]["to_device_name"], asked["to_device_name"],
        "the plan the host describes is the sheet's"
    );
    let early = scene
        .issuer
        .call("transfer_finish", json!({ "reference": reference }))
        .await
        .expect_err("nothing is sent before an owner device answered");
    assert_eq!(code_of(&early), "OWNER_CONFIRMATION_REQUIRED", "{early}");
    assert_eq!(
        scene.listed().await.grants.len(),
        1,
        "and nothing was written"
    );

    // The owner device shows what the host described, and answers it.
    let mut client = scene.host.client().await;
    let pending = calls::pending(&mut client).await.expect("readable").pending;
    assert_eq!(pending.len(), 1);
    let ConfirmationDisplay::TransferControl(plan) = &pending[0].display else {
        panic!("the owner device is shown a transfer of control");
    };
    let plan: &TransferControlPlan = plan;
    assert_eq!(plan.source_grant_id, from);
    assert_eq!(plan.to_device_id, taker_record.device_id);
    let (proof, presented) = calls::sign(&pending[0].request, &Signer::OwnerDevice(&scene.owner));
    calls::complete(scene.host.environment_id, &mut client, proof, presented)
        .await
        .expect("the owner answers");

    let answered = scene
        .issuer
        .call("transfer_answered", json!({ "reference": reference }))
        .await
        .expect("read");
    assert_eq!(answered["state"], "answered");
    let done = scene
        .issuer
        .call("transfer_finish", json!({ "reference": reference }))
        .await
        .expect("the confirmed transfer is sent");
    assert_eq!(done["attempt"]["outcome"], "happened");
    let result: GrantTransferResult = typed(&done["value"]);
    assert_eq!(
        result.replacement.recipient_device_id,
        taker_record.device_id
    );
    assert!(net_support::holds(&scene.host, result.replacement.grant_id));
    assert!(
        !net_support::holds(&scene.host, from),
        "the giving device no longer holds the session"
    );
    assert!(scene.issuer.attempts().await.is_empty());

    // The reference is spent: it sends nothing again, and cancelling it undoes nothing.
    let again = scene
        .issuer
        .call("transfer_finish", json!({ "reference": reference }))
        .await
        .expect_err("a hand-over is sent once");
    assert_eq!(code_of(&again), "INVALID_ARGUMENT", "{again}");
    let cancelled = scene
        .issuer
        .call("transfer_cancel", json!({ "reference": reference }))
        .await
        .expect_err("a hand-over that was sent is not cancelled");
    assert_eq!(code_of(&cancelled), "INVALID_ARGUMENT", "{cancelled}");
    assert!(net_support::holds(&scene.host, result.replacement.grant_id));
    giving.close();
    scene.stop().await;
}

/// KR-REQ-18.15, KR-REQ-23.49: the host's answer to the transfer is lost. The application asks
/// again with the same request, on a connection opened for it, and the host answers from its record,
/// so the session changes hands once. While the transfer can still happen no second hand-over of the
/// session is started, and the application, stopped and started again, asks and is answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_reply_to_a_hand_over_is_answered_from_the_hosts_record_and_gates_a_second() {
    let mut scene = Scene::start().await;
    let hand_over = scene.confirmed_hand_over().await;
    scene.issuer.state().shares().pace_at(FOR_A_WHILE);
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);
    let sent = scene
        .issuer
        .call(
            "transfer_finish",
            json!({ "reference": hand_over.reference }),
        )
        .await
        .expect("answered");
    assert_ne!(sent["attempt"]["phase"], "closed");
    let action = sent["attempt"]["action_id"]
        .as_str()
        .expect("an action")
        .to_owned();
    assert!(
        net_support::holds(&scene.host, hand_over.from)
            || !net_support::holds(&scene.host, hand_over.from),
        "the host committed it or not; either way the record is kept"
    );

    // No second hand-over of the session while this one can still happen.
    scene.reconnect_issuer().await;
    let asked = scene
        .issuer
        .call(
            "transfer_ask",
            json!({
                "params": serde_json::to_value(&GrantTransferParams {
                    session_id: scene.session_id,
                    from_grant_id: hand_over.from,
                    to_device_id: hand_over.taker_record.device_id,
                }).expect("encodes"),
                "subject": {
                    "sessionId": scene.session_id.to_string(), "sessionEpoch": "1",
                },
            }),
        )
        .await
        .expect_err("a hand-over of this session can still happen");
    assert_eq!(code_of(&asked), "PERMISSION_DENIED", "{asked}");

    scene.restart_issuer().await;
    let back = scene.issuer.attempts().await;
    assert_eq!(back.len(), 1);
    assert_eq!(back[0]["kind"], "transfer");
    assert_ne!(back[0]["phase"], "closed");
    let done = scene
        .issuer
        .call("attempt_ask", json!({ "actionId": action }))
        .await
        .expect("answered from the host's record");
    let result: GrantTransferResult = typed(&done["value"]);
    assert_eq!(
        result.replacement.recipient_device_id,
        hand_over.taker_record.device_id
    );
    assert!(net_support::holds(&scene.host, result.replacement.grant_id));
    assert!(!net_support::holds(&scene.host, hand_over.from));
    hand_over.giving.close();
    scene.stop().await;
}

/// KR-REQ-18.15, KR-REQ-23.49: a transfer the host never saw is not reported as a hand-over because
/// the receiving device already holds another grant of the session: the state check looks for the
/// grant the plan names, not for any grant of the receiver's. Before the bound it is unfinished;
/// after it, the application says it did not happen, and the giving device still holds the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_over_the_host_never_saw_is_not_done_though_the_receiver_holds_another_grant() {
    let scene = Scene::start().await;
    let hand_over = scene.confirmed_hand_over().await;
    // The receiving device holds a grant of the session of its own.
    let (_other, _held) = owned_by(
        &scene.host,
        scene.session_id,
        &hand_over.taker,
        &hand_over.taker_record,
    )
    .await;
    scene.issuer_faults.request.store(true, Ordering::SeqCst);
    let sent = scene
        .issuer
        .call(
            "transfer_finish",
            json!({ "reference": hand_over.reference }),
        )
        .await
        .expect("answered");
    assert_ne!(sent["attempt"]["phase"], "closed");

    let checking = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "checking")
        .await;
    assert_eq!(checking["kind"], "transfer");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        scene.issuer.attempts().await[0]["phase"],
        "checking",
        "the receiver's other grant is not the transfer, and the bound has not passed"
    );
    scene
        .issuer
        .state()
        .shares()
        .advance(Duration::from_secs(3600));
    let closed = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(closed["outcome"], "not_done");
    assert!(
        net_support::holds(&scene.host, hand_over.from),
        "the giving device still holds the session"
    );
    hand_over.giving.close();
    scene.stop().await;
}

/// KR-REQ-18.15: cancelling a hand-over before an owner device answers sends nothing, forgets the
/// reference, and leaves no record that gates the next.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_a_hand_over_sends_nothing_and_leaves_no_record() {
    let scene = Scene::start().await;
    let (_share, giving) =
        owned_by(&scene.host, scene.session_id, &scene.device, &scene.record).await;
    let (_taker, taker_record) = recipient(&scene.host, &scene.owner).await;
    let from = scene
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
            session_id: scene.session_id,
            from_grant_id: from,
            to_device_id: taker_record.device_id,
        }).expect("encodes"),
        "subject": { "sessionId": scene.session_id.to_string(), "sessionEpoch": "1" },
    });
    let asked = scene
        .issuer
        .call("transfer_ask", body.clone())
        .await
        .expect("asked");
    let reference = asked["reference"].as_str().expect("a reference").to_owned();
    assert_eq!(
        scene.issuer.attempts().await.len(),
        1,
        "the hand-over holds its place"
    );
    scene
        .issuer
        .call("transfer_cancel", json!({ "reference": reference }))
        .await
        .expect("cancelled");
    assert!(scene.issuer.attempts().await.is_empty());
    let spent = scene
        .issuer
        .call("transfer_answered", json!({ "reference": reference }))
        .await
        .expect_err("the reference is forgotten");
    assert_eq!(code_of(&spent), "INVALID_ARGUMENT", "{spent}");
    assert!(
        net_support::holds(&scene.host, from),
        "and the giving device still holds the session"
    );
    // The next hand-over is not gated by the one cancelled.
    scene
        .issuer
        .call("transfer_ask", body)
        .await
        .expect("asked again");
    giving.close();
    scene.stop().await;
}

/// KR-REQ-18.15: a hand-over whose challenge the host no longer has, because the host restarted
/// while the owner devices were being asked, is ended when the page next reads it. The page is told
/// it is gone, the record that held the session's place goes with it, and the next hand-over of the
/// session is not refused as still under way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_over_whose_challenge_the_host_lost_is_ended_and_can_be_asked_again() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = recipient(&host, &owner).await;
    let (session_id, _) = an_open_session(&host);
    let (_share, giving) = owned_by(&host, session_id, &device, &record).await;
    let (_taker, taker_record) = recipient(&host, &owner).await;
    let held: GrantListResult = net_support::pairing::read(
        &mut host.client().await,
        kr_protocol::method::Method::GrantList,
        &GrantListParams {
            session_id: Nullable::some(session_id),
            include_resolved: true,
        },
    )
    .await
    .expect("the list is read");
    let from = held
        .grants
        .iter()
        .find(|summary| summary.state == GrantState::Active)
        .expect("the device's share")
        .grant
        .grant_id;
    let issuer = Page::start(
        local_connection(&host, None).await,
        Arc::new(tempfile::tempdir().expect("a data directory")),
        WorkerLinks::at(host.tree().environment()),
    );
    issuer.state().shares().pace_at(AT_ONCE);
    let body = json!({
        "params": serde_json::to_value(&GrantTransferParams {
            session_id,
            from_grant_id: from,
            to_device_id: taker_record.device_id,
        }).expect("encodes"),
        "subject": { "sessionId": session_id.to_string(), "sessionEpoch": "1" },
    });
    let asked = issuer
        .call("transfer_ask", body.clone())
        .await
        .expect("the owner devices are asked");
    let reference = asked["reference"].as_str().expect("a reference").to_owned();
    assert_eq!(issuer.attempts().await.len(), 1, "it holds its place");

    // The challenge lives in the host's memory alone, so a restart ends it.
    issuer
        .state()
        .connection()
        .expect("connected")
        .session()
        .close();
    giving.close();
    let host = host.restart().await;
    issuer
        .state()
        .connected(local_connection(&host, None).await);
    let read = issuer
        .call("transfer_answered", json!({ "reference": reference }))
        .await
        .expect("read");
    assert_eq!(read["state"], "gone");
    assert!(
        issuer.attempts().await.is_empty(),
        "the record that held the session's place is gone with the hand-over"
    );
    issuer
        .call("transfer_ask", body)
        .await
        .expect("a hand-over of the session is not refused as still under way");

    issuer
        .state()
        .connection()
        .expect("connected")
        .session()
        .close();
    drop(issuer);
    host.stop().await;
}

/// KR-REQ-23.49: an invitation whose answer was lost and which the host is never asked about again,
/// because no connection can be opened for it, is found by reading the host's state, and the
/// application says it happened without the host's result: the grant is there, so it is not done
/// again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invitation_found_by_a_read_closes_as_happened_without_the_hosts_result() {
    let mut scene = Scene::start().await;
    // The first three connections the application opens for an exact repeat fail; the next, which
    // reads the host's state, is made.
    let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reopen: Reopen = {
        let host_endpoint = scene.host.endpoint().clone();
        let opened = Arc::clone(&opened);
        Arc::new(move || {
            let endpoint = host_endpoint.clone();
            let opened = Arc::clone(&opened);
            Box::pin(async move {
                if opened.fetch_add(1, Ordering::SeqCst) < 3 {
                    return Err(companion_tauri::CommandError::unavailable("no connection"));
                }
                let transport = IpcTransport::connect_app(
                    &endpoint,
                    companion_tauri::connection::build_id().expect("a build identity"),
                )
                .await
                .map_err(companion_tauri::CommandError::from)?;
                Connection::over(transport)
            })
        })
    };
    let faults = Arc::new(Faults::default());
    let inner = local_connection(&scene.host, Some(&faults)).await;
    scene.issuer.state().connected(inner.reopening(reopen));
    scene.issuer_faults = faults;
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);

    let sent = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("answered");
    assert_ne!(sent["attempt"]["phase"], "closed");
    let done = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(
        done["outcome"], "happened",
        "the grant is on the host's list"
    );
    assert_eq!(
        done["result"],
        Value::Null,
        "and the host's result was never read"
    );
    assert_eq!(
        done["follow_up"], false,
        "an invitation without the live view needs none"
    );
    assert_eq!(scene.listed().await.grants.len(), 1);
    assert_eq!(
        opened.load(Ordering::SeqCst),
        4,
        "three repeats could not be made"
    );
    scene
        .issuer
        .call(
            "attempt_remove",
            json!({ "actionId": done["action_id"].as_str().expect("an action") }),
        )
        .await
        .expect("removed");
    scene.stop().await;
}

/// KR-REQ-23.49: the attention read of a device paired as a guest is refused by the host as it
/// refuses everything a guest has no right to, so a page can treat it as nothing of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_guests_attention_read_is_the_hosts_refusal() {
    let scene = Scene::start().await;
    let refused = scene
        .phone
        .call("attention_read", json!({ "params": {} }))
        .await;
    assert!(
        refused.is_err(),
        "a guest has no attention inbox of its own: {refused:?}"
    );
    scene.stop().await;
}

/// KR-REQ-18.15, KR-REQ-23.49: an application stopped while an owner device was being asked to
/// confirm a hand-over starts with the record of it and none of the reference the page held. The
/// record holds the session's place, is not something the host can be asked about, and cannot be
/// hidden away: the person cancels it, and the next hand-over of the session is not refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_over_being_confirmed_when_the_application_stopped_is_cancelled_from_its_record() {
    let mut scene = Scene::start().await;
    let (body, giving) = scene.hand_over_body().await;
    scene
        .issuer
        .call("transfer_ask", body.clone())
        .await
        .expect("the owner devices are asked");

    scene.restart_issuer().await;
    let back = scene.issuer.attempts().await;
    assert_eq!(back.len(), 1, "the record is read back");
    assert_eq!(back[0]["phase"], "asking");
    let action = back[0]["action_id"].as_str().expect("an action").to_owned();

    let asked = scene
        .issuer
        .call("attempt_ask", json!({ "actionId": action }))
        .await
        .expect_err("a hand-over still being confirmed is not asked about");
    assert_eq!(code_of(&asked), "INVALID_ARGUMENT", "{asked}");
    let hidden = scene
        .issuer
        .call(
            "attempt_set_hidden",
            json!({ "actionId": action, "hidden": true }),
        )
        .await
        .expect_err("it is cancelled, not hidden away with its place held");
    assert_eq!(code_of(&hidden), "INVALID_ARGUMENT", "{hidden}");
    let held = scene
        .issuer
        .call("transfer_ask", body.clone())
        .await
        .expect_err("it still holds the session's place");
    assert_eq!(code_of(&held), "PERMISSION_DENIED", "{held}");

    scene
        .issuer
        .call("attempt_remove", json!({ "actionId": action }))
        .await
        .expect("the person cancels it");
    assert!(scene.issuer.attempts().await.is_empty());
    scene
        .issuer
        .call("transfer_ask", body)
        .await
        .expect("and the session can be handed over again");
    assert!(
        net_support::holds(&scene.host, giving_grant(&scene).await),
        "and the giving device still holds the session"
    );
    giving.close();
    scene.stop().await;
}

/// The grant the device's share of the session is held under.
async fn giving_grant(scene: &Scene) -> GrantId {
    scene
        .listed()
        .await
        .grants
        .iter()
        .find(|summary| {
            summary.state == GrantState::Active
                && summary.grant.recipient_device_id == scene.record.device_id
        })
        .expect("the device's share")
        .grant
        .grant_id
}

/// KR-REQ-23.49: what a person does to an attempt, hiding it or showing it, is theirs, and the task
/// carrying the attempt on does not undo it by writing the copy of the record it began with. An
/// attempt that ends is shown whatever was done to it, since its end is what the person is owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attempt_is_hidden_and_shown_by_the_person_and_not_undone_by_the_task_carrying_it_on() {
    let mut scene = Scene::start().await;
    // The first connection the application opens for a repeat waits for the test; every one after
    // it fails until the test lets one be made.
    let parked = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let open = Arc::new(AtomicBool::new(false));
    let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reopen: Reopen = {
        let endpoint = scene.host.endpoint().clone();
        let (parked, release, open, opened) = (
            Arc::clone(&parked),
            Arc::clone(&release),
            Arc::clone(&open),
            Arc::clone(&opened),
        );
        Arc::new(move || {
            let endpoint = endpoint.clone();
            let (parked, release, open, opened) = (
                Arc::clone(&parked),
                Arc::clone(&release),
                Arc::clone(&open),
                Arc::clone(&opened),
            );
            Box::pin(async move {
                if opened.fetch_add(1, Ordering::SeqCst) == 0 {
                    parked.notify_one();
                    release.notified().await;
                }
                if !open.load(Ordering::SeqCst) {
                    return Err(companion_tauri::CommandError::unavailable("no connection"));
                }
                let transport = IpcTransport::connect_app(
                    &endpoint,
                    companion_tauri::connection::build_id().expect("a build identity"),
                )
                .await
                .map_err(companion_tauri::CommandError::from)?;
                Connection::over(transport)
            })
        })
    };
    let faults = Arc::new(Faults::default());
    let inner = local_connection(&scene.host, Some(&faults)).await;
    scene.issuer.state().connected(inner.reopening(reopen));
    scene.issuer_faults = faults;
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);

    let sent = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("answered");
    assert_ne!(sent["attempt"]["phase"], "closed");
    let action = sent["attempt"]["action_id"]
        .as_str()
        .expect("an action")
        .to_owned();
    // The task is waiting to repeat the request, with the record as it was when it began.
    parked.notified().await;
    let hidden = scene
        .issuer
        .call(
            "attempt_set_hidden",
            json!({ "actionId": action, "hidden": true }),
        )
        .await
        .expect("hidden");
    assert_eq!(hidden["hidden"], true);

    // It goes on, and writes what it learns: the person's choice stands.
    release.notify_one();
    let after = scene
        .issuer
        .attempt_where(|attempt| attempt["repeats"].as_u64() >= Some(1))
        .await;
    assert_eq!(
        after["hidden"], true,
        "the task's write left the person's choice alone: {after}"
    );

    // Showing it is as much theirs, and the task's next writes leave that alone too.
    let shown = scene
        .issuer
        .call(
            "attempt_set_hidden",
            json!({ "actionId": action, "hidden": false }),
        )
        .await
        .expect("shown");
    assert_eq!(shown["hidden"], false);
    let later = scene
        .issuer
        .attempt_where(|attempt| attempt["repeats"].as_u64() >= Some(3))
        .await;
    assert_eq!(later["hidden"], false);

    // Hidden again, and then it ends: the end is shown.
    scene
        .issuer
        .call(
            "attempt_set_hidden",
            json!({ "actionId": action, "hidden": true }),
        )
        .await
        .expect("hidden again");
    open.store(true, Ordering::SeqCst);
    let done = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(done["hidden"], false, "an attempt that is over is shown");
    let refused = scene
        .issuer
        .call(
            "attempt_set_hidden",
            json!({ "actionId": action, "hidden": true }),
        )
        .await
        .expect_err("an attempt that is over is removed, not hidden");
    assert_eq!(code_of(&refused), "INVALID_ARGUMENT", "{refused}");
    scene.stop().await;
}

/// KR-REQ-23.49: what the host's result carries, which the end of an attempt does not say, is owed
/// to the person until the page has taken it. A revocation whose result was recovered in the
/// background and held in memory is still one the host can be asked for when the application
/// stops before the page read it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_result_recovered_in_the_background_can_still_be_asked_for_after_a_restart() {
    let mut scene = Scene::start().await;
    let made = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("issued");
    let created: GrantCreateResult = typed(&made["value"]);
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);
    scene
        .issuer
        .call(
            "grant_revoke",
            json!({ "params": serde_json::to_value(&GrantRevokeParams {
                grant_id: created.grant.grant_id,
            }).expect("encodes") }),
        )
        .await
        .expect("answered though the host's answer was lost");
    let done = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(done["outcome"], "happened");
    let in_memory: RevocationResult = typed(&done["result"]);
    assert!(in_memory.barrier.holds());
    assert_eq!(
        done["follow_up"], true,
        "the page has not taken the result, so the host can still be asked for it"
    );

    scene.restart_issuer().await;
    let back = scene.issuer.attempts().await;
    assert_eq!(back.len(), 1);
    assert_eq!(
        back[0]["result"],
        Value::Null,
        "the result in memory is gone"
    );
    assert_eq!(back[0]["follow_up"], true);
    let asked = scene
        .issuer
        .call(
            "attempt_ask",
            json!({ "actionId": back[0]["action_id"].as_str().expect("an action") }),
        )
        .await
        .expect("the host answers from its record");
    let result: RevocationResult = typed(&asked["value"]);
    assert!(result.barrier.holds());
    assert!(
        scene.issuer.attempts().await.is_empty(),
        "and the record goes once the result is the page's"
    );
    scene.stop().await;
}

/// KR-REQ-18.15: a refusal is the host's answer to the confirmation request only when it answers
/// the first send. The request never reached the host, so every repeat is a first admission on a
/// connection the window does not belong to and is refused; that is not the host saying no owner
/// device was asked, and when the repeats are used up nothing is known of it. The record that held
/// the session's place goes, since nothing was or will be sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_to_a_repeat_of_the_confirmation_request_is_not_the_hosts_answer() {
    let mut scene = Scene::start().await;
    let (body, giving) = scene.hand_over_body().await;
    scene.issuer_faults.request.store(true, Ordering::SeqCst);
    let unknown = scene
        .issuer
        .call("transfer_ask", body.clone())
        .await
        .expect_err("nothing is known of the request");
    assert_eq!(code_of(&unknown), "RESOURCE_UNAVAILABLE", "{unknown}");
    assert!(
        unknown["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not known whether an owner device was asked"),
        "{unknown}"
    );
    assert!(scene.issuer.attempts().await.is_empty());
    scene.reconnect_issuer().await;
    scene
        .issuer
        .call("transfer_ask", body)
        .await
        .expect("and the session can be handed over again");
    giving.close();
    scene.stop().await;
}

#[allow(dead_code, reason = "the types a page's parameters are written from")]
const _: fn(&GrantId, &InvitationId, &GrantCreateParams) = |_, _, _| {};
#[allow(dead_code, reason = "the actor a local caller is")]
const _: fn(u64) -> kr_protocol::ids::ActorId = local_actor;
