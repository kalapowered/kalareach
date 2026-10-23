//! A member's device gets the lease its organisation signs for it, presents it to the host it is
//! paired with, and keeps it.
//!
//! The host is kr-controller's in-process daemon, enrolled in an organisation on clocks the test
//! moves, and the device is this crate's own backend on the mock runtime, paired under a grant that
//! answers to the organisation. The organisation's service is the stand-in on loopback: it checks
//! the account's bearer token and signs with the test's organisation, which holds real keys. The
//! account is signed in on the device before it connects. The one thing the test holds is the
//! device's waits: a refresh asks to wait the interval the service advised, and the test says when
//! that interval has passed.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-17.53 | `a_member_connects_by_presenting_its_lease_first_and_keeps_it_on_the_advised_interval` |
//! | KR-REQ-17.53 | `a_member_whose_host_restarted_presents_first_again_and_is_served` |
//! | KR-REQ-17.53 | `a_lease_signed_by_a_key_the_host_has_not_followed_travels_with_the_chain` |
//! | KR-REQ-17.53 | `a_member_the_organisation_removes_is_told_so` |

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
#[path = "../../../../crates/kr-controller/tests/organisation_fixture/mod.rs"]
mod organisation_fixture;
#[path = "../../../../crates/kr-controller/tests/organisation_support/mod.rs"]
mod organisation_support;
mod support;

use std::collections::{BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use companion_tauri::account::carrier::{Boxed, Carrier, Ending, Plan, Unavailable};
use companion_tauri::account::{Account, AccountSlot};
use companion_tauri::lease::LeaseDesk;
use kr_client::organisation::LeaseTimer;
use kr_client::services::NullService;
use kr_client::services::account::{
    AccountService, AccountToken, Client, IssuedGrant, PendingAuthorisation, RefreshToken,
    SignedInAccount,
};
use kr_crypto::store::MemoryStore;
use kr_protocol::account::{MembershipLease, PolicyAuthority};
use kr_protocol::grant::OrganisationRequirement;
use kr_protocol::pairing::ProposedGrant;
use kr_protocol::scalars::{AuthorisationKey, Nullable};
use kr_service_stand_in::{OrganisationAuthority, Served, serve};
use net_support::proposal;
use organisation_fixture::{Fixture, SERVED};
use organisation_support::{MINUTE_MS, Organisation, member};
use serde_json::json;
use support::{Companion, NoOwner, Phone, StubIntake, WATCHDOG, pair_under, parts};
use tokio::sync::{oneshot, watch};

/// The account the device is signed in as, and the token it holds for the organisation's service.
const ACCOUNT: &str = "ada";
const TOKEN: &str = "ada-access-token";

/// A device that carries no sign-in: the account is signed in before the test begins.
struct NoCarrier;

impl Carrier for NoCarrier {
    fn plan(&self) -> Boxed<'_, Result<Plan, Unavailable>> {
        Box::pin(async { Err(Unavailable::NoReturningBrowser) })
    }

    fn carry<'a>(
        &'a self,
        _plan: &'a Plan,
        _url: String,
        _pending: &'a mut PendingAuthorisation,
        _cancel: watch::Receiver<bool>,
    ) -> Boxed<'a, Ending> {
        Box::pin(async { Ending::Cancelled })
    }
}

/// What the organisation signs: its keys, the members it has, and every lease it has issued.
///
/// The leases are issued on the host's wall clock, which the test moves, so what a lease says of
/// when it was issued is what the host reads.
struct Signing {
    organisation: Mutex<Organisation>,
    moved: Arc<AtomicI64>,
    members: Mutex<BTreeSet<String>>,
    issued: Mutex<Vec<MembershipLease>>,
}

impl std::fmt::Debug for Signing {
    /// What the organisation has done, and none of its keys.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Signing")
            .field("issued", &self.issued().len())
            .finish_non_exhaustive()
    }
}

impl Signing {
    fn now(&self) -> u64 {
        kr_ipc::now_ms()
            .get()
            .saturating_add_signed(self.moved.load(Ordering::SeqCst))
    }

    fn issued(&self) -> Vec<MembershipLease> {
        self.issued
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The organisation rotates its policy-signing key, which takes over now.
    fn rotates(&self) -> u64 {
        self.organisation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .rotate(self.now())
    }

    /// The directory removes the member.
    fn removes(&self, account: &str) {
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(account);
    }
}

impl OrganisationAuthority for Signing {
    fn lease(&self, account: &str, device_key: &AuthorisationKey) -> Option<MembershipLease> {
        if !self.is_member(account) {
            return None;
        }
        let organisation = self
            .organisation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let lease = organisation.lease(
            organisation.current(),
            &member(account),
            *device_key,
            self.now(),
            SERVED,
        );
        self.issued
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(lease.clone());
        Some(lease)
    }

    fn authority(&self) -> PolicyAuthority {
        self.organisation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .authority(self.now() - 1_000)
    }

    fn is_member(&self, account: &str) -> bool {
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(account)
    }
}

/// The waits the device asks for, held until the test says they have passed.
#[derive(Debug)]
struct HeldWaits {
    held: Mutex<(Vec<Duration>, VecDeque<oneshot::Sender<()>>)>,
    asked: watch::Sender<usize>,
}

impl HeldWaits {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            held: Mutex::default(),
            asked: watch::channel(0).0,
        })
    }

    /// Returns when the device has asked for `count` waits in all.
    async fn until_asked(&self, count: usize) {
        let mut asked = self.asked.subscribe();
        tokio::time::timeout(WATCHDOG, asked.wait_for(|asked| *asked >= count))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the device asked for {} waits, not {count}",
                    *self.asked.borrow()
                )
            })
            .expect("the waits are still counted");
    }

    fn asked_for(&self) -> Vec<Duration> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .0
            .clone()
    }

    /// The oldest wait the device holds has passed.
    fn passes(&self) {
        let oldest = self
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .1
            .pop_front();
        if let Some(oldest) = oldest {
            let _ = oldest.send(());
        }
    }
}

impl LeaseTimer for HeldWaits {
    fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let (passed, waiting) = oneshot::channel();
        {
            let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
            held.0.push(duration);
            held.1.push_back(passed);
        }
        self.asked.send_modify(|asked| *asked += 1);
        Box::pin(async move {
            let _ = waiting.await;
        })
    }
}

/// Everything one test holds.
struct Rig {
    fixture: Fixture,
    served: Served,
    signing: Arc<Signing>,
    waits: Arc<HeldWaits>,
    phone: Phone,
}

/// The path the device asks the organisation's service for a lease on.
fn lease_path(fixture: &Fixture) -> String {
    format!(
        "/api/account/organisations/{}/lease",
        fixture.organisation.organisation_id
    )
}

impl Rig {
    /// A host enrolled in an organisation, the organisation's service, and a device signed in as a
    /// member that has paired with the host under a grant that answers to the organisation.
    async fn start() -> Self {
        let port = {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("a port");
            socket.local_addr().expect("an address").port()
        };
        let mut settings = kr_controller::service::net::config::NetworkSettings::default();
        settings.endpoint.bind_addr =
            Some(format!("127.0.0.1:{port}").parse().expect("an address"));
        let fixture = Fixture::start_on(settings).await;
        let served = serve().await;
        served
            .web()
            .issue_token(TOKEN, ACCOUNT, &["openid", "organisation.lease"]);
        let signing = Arc::new(Signing {
            organisation: Mutex::new(fixture.organisation.clone()),
            moved: Arc::clone(&fixture.moved),
            members: Mutex::new(BTreeSet::from([ACCOUNT.to_owned()])),
            issued: Mutex::default(),
        });
        served.web().serve_organisation(
            &fixture.organisation.organisation_id.to_string(),
            Arc::clone(&signing) as Arc<dyn OrganisationAuthority>,
        );
        let waits = HeldWaits::new();
        let phone = signed_in_phone(&fixture, &served, &waits).await;
        let grant = ProposedGrant {
            organisation: Nullable::some(OrganisationRequirement {
                organisation_id: fixture.organisation.organisation_id,
                policy_revision: fixture.revision,
            }),
            ..proposal(SERVED)
        };
        pair_under(&phone, &fixture.host, &fixture.owner, grant).await;
        Self {
            fixture,
            served,
            signing,
            waits,
            phone,
        }
    }

    fn companion(&self) -> &Companion {
        &self.phone.companion
    }

    /// Waits until `connection_state` says `connected`, and returns it.
    async fn connection(&self, connected: bool) -> serde_json::Value {
        tokio::time::timeout(WATCHDOG, async {
            loop {
                let state = self
                    .companion()
                    .call("connection_state", json!({}))
                    .expect("the connection's state");
                if state["connected"] == connected {
                    return state;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the connection did not come to be {connected}"))
    }

    /// The host's own reading of the lease it holds for the member, from the owner's list.
    async fn host_holds(&self) -> Option<(u64, u64)> {
        let listed = self.fixture.listed().await;
        let member = listed.enrolments.first()?.members.first()?;
        let lease = member.lease.as_ref()?;
        Some((lease.issued_at_ms.get(), lease.expires_at_ms.get()))
    }

    /// How many lease requests have reached the organisation's service.
    fn lease_requests(&self) -> usize {
        self.served.web().requests_to(&lease_path(&self.fixture))
    }

    /// The device reads the host, as a page does.
    fn reads(&self) -> Result<serde_json::Value, serde_json::Value> {
        self.companion().call("host_info", json!({}))
    }

    /// The host stops and starts again on its tree, where it was.
    async fn restarted(self) -> Self {
        Self {
            fixture: self.fixture.restart().await,
            ..self
        }
    }
}

/// A device that is signed in as the account `ACCOUNT`, whose waits are held.
async fn signed_in_phone(fixture: &Fixture, served: &Served, waits: &Arc<HeldWaits>) -> Phone {
    let service: Arc<dyn AccountService> = Arc::new(NullService);
    let tokens = Arc::new(SignedInAccount::new(
        Arc::clone(&service),
        Arc::new(MemoryStore::new()),
        Client::Mobile,
    ));
    tokens
        .keep(
            IssuedGrant {
                access_token: AccountToken::new(TOKEN).expect("a token"),
                expires_in_seconds: 3600,
                refresh_token: RefreshToken::new("ada-refresh-token").expect("a token"),
                scopes: ["openid", "organisation.lease"].map(str::to_owned).to_vec(),
                subject: ACCOUNT.to_owned(),
            },
            "a-nonce",
        )
        .await
        .expect("the device signs in");
    let account = Arc::new(Account::new(
        tokens,
        service,
        kr_protocol::service::GatewayOrigin::new(served.origin()).expect("an origin"),
        Arc::new(NoCarrier),
        Arc::new(|_| {}),
    ));
    let desk = {
        let account = Arc::clone(&account);
        LeaseDesk::new(
            Arc::new(move || {
                let account = Arc::clone(&account);
                Box::pin(async move { Some(account) })
            }),
            Arc::clone(waits) as Arc<dyn LeaseTimer>,
        )
    };
    let data = tempfile::tempdir().expect("a directory");
    let secrets: Arc<dyn kr_crypto::store::SecretStore> = Arc::new(MemoryStore::new());
    let room: Arc<dyn kr_client::pairing::candidate::CandidateRoom> =
        Arc::new(fixture.host.room.clone());
    let paste = StubIntake::holding("", false);
    let mut device = parts(Arc::clone(&secrets), Arc::clone(&room));
    device.leases = Some(desk);
    let companion = Companion::start_with_voice(
        data.path(),
        device,
        Arc::new(NoOwner),
        Arc::clone(&paste) as Arc<dyn companion_tauri::pairing::IntakePlatform>,
        companion_tauri::voice::Calls::absent(),
        AccountSlot::ready(account),
    );
    Phone {
        companion,
        paste,
        secrets,
        room,
        data,
    }
}

/// KR-REQ-17.53: a device whose grant answers to an organisation is refused everything until the
/// host holds the lease its organisation signed for it, so it presents the lease before it reads
/// anything of the host, and the host then serves it. It asks for the next lease on the interval
/// the service advised, five minutes, and the host holds the newer one each time, so the device is
/// served for longer than any one lease lasts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_connects_by_presenting_its_lease_first_and_keeps_it_on_the_advised_interval() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.reads()
        .expect("the host serves the device under its lease");

    // The device presented a lease to confirm its pairing and another to open its connection, each
    // before it asked the host anything, and the host holds the newest.
    let connected = rig.signing.issued();
    let newest = connected.last().expect("a lease was asked for to connect");
    assert_eq!(
        rig.host_holds().await,
        Some((
            newest.payload.issued_at_ms.get(),
            newest.payload.expires_at_ms.get()
        )),
        "the host holds the lease the organisation signed"
    );

    // The device asks to wait the interval the service advised before it asks again.
    rig.waits.until_asked(1).await;
    assert_eq!(rig.waits.asked_for(), [Duration::from_secs(300)]);

    // Four intervals of five minutes pass. Each time the wait is over, the device has asked again
    // and the host holds a lease issued after the one before it.
    for round in 1..=4_usize {
        rig.fixture.pass_wall(Duration::from_millis(5 * MINUTE_MS));
        rig.waits.passes();
        rig.waits.until_asked(round + 1).await;
        let issued = rig.signing.issued();
        assert_eq!(issued.len(), connected.len() + round, "round {round}");
        let newest = issued.last().expect("a lease");
        assert_eq!(
            rig.host_holds().await,
            Some((
                newest.payload.issued_at_ms.get(),
                newest.payload.expires_at_ms.get()
            )),
            "round {round}: the host holds the newest lease"
        );
    }
    assert_eq!(rig.lease_requests(), connected.len() + 4);
    assert!(
        newest_of(&connected) < rig.fixture.now(),
        "the lease the device connected with ended on the host's clock long ago"
    );
    rig.reads()
        .expect("the device is served after the lease it connected with ended");
}

/// When the newest of these leases ends, in UTC milliseconds.
fn newest_of(leases: &[MembershipLease]) -> u64 {
    leases
        .iter()
        .map(|lease| lease.payload.expires_at_ms.get())
        .max()
        .expect("a lease")
}

/// KR-REQ-17.53: no lease survives a host's restart, so a device that connects again presents
/// first, before the host will say anything to it, and is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_whose_host_restarted_presents_first_again_and_is_served() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    let before = rig.signing.issued().len();

    let rig = rig.restarted().await;
    tokio::time::timeout(WATCHDOG, async {
        while rig.signing.issued().len() == before {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the device asks for a lease on the new connection");
    rig.connection(true).await;
    rig.reads().expect("the restarted host serves the device");
    let issued = rig.signing.issued();
    let newest = issued.last().expect("a lease");
    assert_eq!(
        rig.host_holds().await,
        Some((
            newest.payload.issued_at_ms.get(),
            newest.payload.expires_at_ms.get()
        )),
        "the restarted host holds the lease the device presented"
    );
}

/// KR-REQ-17.53: a lease signed by a key revision the host has not followed is accepted with the
/// chain that brings the revision in, so the device carries the chain beside the lease when the
/// organisation rotated its key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_signed_by_a_key_the_host_has_not_followed_travels_with_the_chain() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;
    let before = rig.signing.issued().len();

    // The organisation rotates after the lease the host holds was issued, so nothing the host
    // holds is signed by a key that has been retired.
    rig.fixture.pass_wall(Duration::from_millis(MINUTE_MS));
    assert_eq!(rig.signing.rotates(), 3);
    rig.fixture.pass_wall(Duration::from_millis(MINUTE_MS));
    rig.waits.passes();
    rig.waits.until_asked(2).await;

    let issued = rig.signing.issued();
    assert_eq!(issued.len(), before + 1);
    let newest = issued.last().expect("a lease");
    assert_eq!(newest.payload.key_revision.get(), 3);
    assert_eq!(
        rig.host_holds().await,
        Some((
            newest.payload.issued_at_ms.get(),
            newest.payload.expires_at_ms.get()
        )),
        "the host holds a lease signed by a key it learned of from the chain beside it"
    );
    rig.reads().expect("the device is served under the new key");
}

/// KR-REQ-17.53: an organisation that removes a member issues it no more leases, and the device is
/// told that its account is not a member rather than retried at the service for ever: the
/// connection ends with that reason, and the host answers nothing once the last lease has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_the_organisation_removes_is_told_so() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;

    rig.signing.removes(ACCOUNT);
    rig.fixture.pass_wall(Duration::from_millis(5 * MINUTE_MS));
    rig.waits.passes();
    let ended = rig.connection(false).await;
    assert!(
        ended["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("not a member")),
        "the device says why: {ended}"
    );
    let refused = rig
        .reads()
        .expect_err("a connection that ended answers nothing");
    assert_eq!(refused["code"], "HOST_NOT_CONFIGURED", "{refused}");
}
