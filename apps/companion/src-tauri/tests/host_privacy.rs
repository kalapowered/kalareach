//! A paired device reads where its host's privacy mode stands, for the drafts it keeps for that host.
//!
//! The daemon is kr-controller's in-process host with its test support included by path. The device
//! is this crate's backend on the mock runtime, on a paired connection it holds as the application
//! holds one, and the seam under test is the one settings sync asks: `ConnectedHosts::privacy`. A
//! host of an earlier build is the real daemon's answer with the member it does not send taken out,
//! by a transport the test puts between the device and the daemon; the daemon, its answers and
//! `privacy.status` are the product's.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-24.28 | `a_device_that_does_not_manage_the_host_reads_where_its_privacy_mode_stands` |
//! | KR-REQ-24.28 | `a_host_of_an_earlier_build_is_asked_for_its_report_by_a_device_that_manages_it` |
//! | KR-REQ-24.28 | `a_host_of_an_earlier_build_is_unread_by_a_device_that_does_not_manage_it` |

#![cfg(unix)]

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use companion_tauri::AppState;
use companion_tauri::connection::{Connection, Standing};
use companion_tauri::settings::HostPrivacy;
use companion_tauri::settings::Hosts as _;
use companion_tauri::settings::connected::ConnectedHosts;
use kr_cbor::{CanonicalMap, CanonicalValue};
use kr_client::Session;
use kr_client::pairing::paired::PairedHost;
use kr_client::transport::{ControlTransport, Reach, TransportFuture};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue};
use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::hello::{ActionWindow, ReceiveLimits};
use kr_protocol::ids::{ConnectionId, DeviceId, DeviceKeyRevision, GrantId, RequestId};
use kr_protocol::method::Method;
use kr_protocol::pairing::{NetworkConfig, ProposedGrant};
use kr_protocol::privacy::{
    PrivacyCompletion, PrivacyReport, PrivacySetParams, PrivacyStatusParams,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use net_support::{Device, Host, pair_with, paired_dial, proposal};
use tauri::test::MockRuntime;

/// How long a step of the daemon's may take before the test calls it hung.
const WATCHDOG: Duration = Duration::from_secs(60);

/// A transport that carries every frame as it is, and takes the `privacy` member out of the
/// answers to `host.info` when it is told to: what a host of an earlier build answers.
#[derive(Debug)]
struct EarlierBuild {
    inner: Arc<dyn ControlTransport>,
    /// Whether the answers to `host.info` lose the member.
    strip: AtomicBool,
    /// The requests for `host.info` that were sent. A read that is sent again after a refusal is
    /// sent under a new identity, so each is kept.
    asked: Mutex<BTreeSet<RequestId>>,
}

impl ControlTransport for EarlierBuild {
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
        if let ControlFrame::Request(request) = frame
            && request.method.as_str() == Method::HostInfo.as_str()
        {
            self.asked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(request.request_id);
        }
        self.inner.send(frame)
    }

    fn claim_receiver(&self) -> kr_client::Result<()> {
        self.inner.claim_receiver()
    }

    fn recv(&self) -> TransportFuture<'_, Option<ControlFrame>> {
        Box::pin(async move {
            let frame = self.inner.recv().await?;
            let Some(ControlFrame::Response(mut response)) = frame else {
                return Ok(frame);
            };
            let asked = self
                .asked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&response.request_id);
            if asked
                && self.strip.load(Ordering::SeqCst)
                && let Outcome::Ok(value) = &response.outcome
                && let CanonicalValue::Map(fields) = value.as_value()
            {
                let kept = fields
                    .entries()
                    .iter()
                    .filter(|(key, _)| key != "privacy")
                    .cloned();
                let fields = CanonicalMap::from_entries(kept).expect("the keys stay distinct");
                response.outcome = Outcome::Ok(ParamsValue::new(CanonicalValue::Map(fields)));
            }
            Ok(Some(ControlFrame::Response(response)))
        })
    }

    fn revoke_streams(&self) {
        self.inner.revoke_streams();
    }

    fn close(&self) {
        self.inner.close();
    }
}

/// The record a paired device keeps of its host, for a connection this suite assembles by hand. It
/// opens no session of its own, so nothing but its shape is read.
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

/// A host, its owner at its own socket, and a device paired with it, read through the seam.
struct Scene {
    host: Host,
    seam: ConnectedHosts<MockRuntime>,
    transport: Arc<EarlierBuild>,
    _app: tauri::App<MockRuntime>,
    _device: Device,
}

impl Scene {
    /// Pairs a device that holds `rights` with a new host, connects it as the application does, and
    /// takes the seam on that connection. `earlier` makes the host answer `host.info` as a host of
    /// an earlier build does.
    async fn start(rights: &[ActionRight], earlier: bool) -> Self {
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start(&owner).await;
        let device = Device::create().await;
        let record = pair_with(&host, &device, &owner, proposal(rights)).await;
        let dial = paired_dial(&host, &device, &record);
        let shared: Arc<dyn ControlTransport> = Arc::new(dial.dial().await);
        let transport = Arc::new(EarlierBuild {
            inner: shared,
            strip: AtomicBool::new(earlier),
            asked: Mutex::new(BTreeSet::new()),
        });
        let session =
            Session::start(Arc::clone(&transport) as Arc<dyn ControlTransport>).expect("a session");
        tokio::time::timeout(
            WATCHDOG,
            session.read::<_, kr_protocol::session::SessionOpenResult>(
                Method::SessionOpen,
                &kr_protocol::session::SessionOpenParams {
                    session_id: Nullable::null(),
                    grant_id: Nullable::null(),
                },
            ),
        )
        .await
        .expect("the host opens the connection for itself")
        .expect("the host opens the connection for itself");
        // What the application holds of a connection it opened: the rights the host decided the
        // open with, which are the rights of the grant.
        let connection = Connection::assembled(
            session,
            host.environment_id,
            Standing::Paired {
                device_id: record.device_id,
                rights: rights.to_vec(),
                host: host_record(record.device_id),
            },
            None,
            None,
        );
        let state = AppState::new();
        state.connected(connection);
        let app = tauri::test::mock_builder()
            .manage(state)
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("an application");
        let seam = ConnectedHosts::new(app.handle().clone());
        Self {
            host,
            seam,
            transport,
            _app: app,
            _device: device,
        }
    }

    /// What the seam reads of the host's privacy mode now.
    async fn reads(&self) -> HostPrivacy {
        tokio::time::timeout(WATCHDOG, self.seam.privacy(self.host.environment_id))
            .await
            .expect("the seam answers")
    }

    /// Turns privacy mode on or off at the host's own socket.
    async fn turn(&self, enabled: bool) {
        let mut client = self.host.client().await;
        let _: PrivacyReport = net_support::pairing::mutate(
            self.host.environment_id,
            &mut client,
            Method::PrivacySet,
            &PrivacySetParams { enabled },
        )
        .await
        .expect("privacy mode is turned");
    }

    /// Waits until the host has finished the change, which turning privacy mode off needs.
    async fn until_complete(&self) {
        tokio::time::timeout(WATCHDOG, async {
            loop {
                let mut client = self.host.client().await;
                let report: PrivacyReport = client
                    .request(Method::PrivacyStatus, &PrivacyStatusParams {})
                    .await
                    .expect("the call reaches the daemon")
                    .expect("privacy mode's report")
                    .to_typed()
                    .expect("decodes");
                if report.completion == PrivacyCompletion::Complete {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the host finishes the change");
    }

    /// How many requests for `host.info` the device has sent.
    fn asked_the_host(&self) -> usize {
        self.transport
            .asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// KR-REQ-24.28: a device that holds no right to manage the host reads where its privacy mode
/// stands from `host.info`, at each generation, so that its drafts for that host follow it. The
/// device holds `session.view` only, and is refused `privacy.status`, so before the host told it in
/// `host.info` it could read nothing of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_does_not_manage_the_host_reads_where_its_privacy_mode_stands() {
    let scene = Scene::start(&[ActionRight::SessionView], false).await;
    assert_eq!(scene.reads().await, HostPrivacy::Off { generation: 0 });
    assert!(scene.asked_the_host() >= 1, "the device asked the host");

    scene.turn(true).await;
    assert_eq!(scene.reads().await, HostPrivacy::On { generation: 1 });

    scene.until_complete().await;
    scene.turn(false).await;
    assert_eq!(scene.reads().await, HostPrivacy::Off { generation: 2 });
}

/// KR-REQ-24.28: a host of an earlier build says nothing of its privacy mode in `host.info`, so a
/// device that manages it asks `privacy.status`, and reads the report the host gives it. The host's
/// answer is the daemon's own with the member taken out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_of_an_earlier_build_is_asked_for_its_report_by_a_device_that_manages_it() {
    let scene = Scene::start(&[ActionRight::HostManage, ActionRight::SessionView], true).await;
    assert_eq!(scene.reads().await, HostPrivacy::Off { generation: 0 });

    scene.turn(true).await;
    assert_eq!(scene.reads().await, HostPrivacy::On { generation: 1 });

    scene.until_complete().await;
    scene.turn(false).await;
    assert_eq!(scene.reads().await, HostPrivacy::Off { generation: 2 });
}

/// KR-REQ-24.28: a host of an earlier build tells nothing in `host.info` to a device that does not
/// manage it, and a device is not read as off where it cannot be told: the host is unread, whether
/// its privacy mode is off or on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_of_an_earlier_build_is_unread_by_a_device_that_does_not_manage_it() {
    let scene = Scene::start(&[ActionRight::SessionView], true).await;
    assert!(
        matches!(scene.reads().await, HostPrivacy::Unreadable { .. }),
        "off, and not told"
    );
    scene.turn(true).await;
    assert!(
        matches!(scene.reads().await, HostPrivacy::Unreadable { .. }),
        "on, and not told"
    );
}
