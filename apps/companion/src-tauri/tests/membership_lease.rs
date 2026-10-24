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
//! | KR-REQ-17.53 | `a_host_the_person_forgets_is_no_longer_kept` |
//! | KR-REQ-17.53 | `a_device_that_is_signed_out_is_told_to_sign_in` |
//! | KR-REQ-17.53 | `a_stop_that_needs_a_person_is_not_asked_again_by_every_connection` |
//! | KR-REQ-17.53 | `a_service_that_asks_for_a_long_wait_is_not_waited_out_in_a_connection` |
//! | KR-REQ-17.53 | `a_lease_is_asked_for_no_oftener_than_the_shortest_refresh` |
//! | KR-REQ-17.53 | `a_chain_the_host_will_not_take_ends_the_keeper_after_a_few_tries` |
//! | KR-REQ-17.53 | `a_second_connection_presents_the_lease_the_device_holds_and_asks_only_when_the_host_refuses_it` |
//! | KR-REQ-17.53 | `a_visit_to_a_host_that_holds_no_lease_presents_one_first` |
//! | KR-REQ-17.53 | `a_token_the_service_turns_back_is_replaced_once_and_the_keeper_goes_on` |
//! | KR-REQ-17.53 | `a_lease_and_a_stop_belong_to_the_account_that_asked` |
//! | KR-REQ-17.53 | `a_delay_the_service_names_binds_every_connection_until_it_is_over` |
//! | KR-REQ-17.53 | `a_lease_the_host_refuses_as_ended_the_moment_it_is_signed_is_not_asked_for_again_and_again` |
//! | KR-REQ-17.53 | `a_lease_that_arrives_after_the_account_changed_is_not_presented` |
//! | KR-REQ-17.53 | `a_sign_out_ends_the_member_connection_at_once` |
//! | KR-REQ-17.53 | `a_kept_visit_is_given_the_lease_again_when_the_one_it_holds_has_ended` |
//! | KR-REQ-17.53 | `a_visit_that_cannot_get_a_lease_says_why_and_is_not_out_of_contact` |
//! | KR-REQ-17.53 | `a_sign_in_made_since_clears_what_was_held_against_the_account` |
//! | KR-REQ-17.53 | `a_visit_does_not_ask_for_the_chain_of_keys_while_the_service_asks_for_a_wait` |
//! | KR-REQ-17.53 | `a_reused_lease_lasts_until_the_first_refresh_of_the_connection_that_keeps_it` |
//! | KR-REQ-17.53 | `a_presentation_its_caller_cuts_off_while_the_service_is_silent_holds_the_service_off` |

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
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use companion_tauri::account::carrier::{Boxed, Carrier, Ending, Plan, Unavailable};
use companion_tauri::account::{Account, AccountSlot};
use companion_tauri::connection::CONNECTION_EVENT;
use companion_tauri::inbox::{HostInbox, HostInboxState, InboxDesk};
use companion_tauri::lease::LeaseDesk;
use kr_client::Session;
use kr_client::organisation::LeaseTimer;
use kr_client::pairing::link::LinkError;
use kr_client::services::account::{
    AccountService, AccountToken, Client, IssuedGrant, PendingAuthorisation, RefreshToken,
    SignedInAccount,
};
use kr_client::services::{
    HttpDeadlines, HttpService, ManagedAccountService, managed_response_limits,
};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::MemoryStore;
use kr_protocol::account::{MembershipLease, PolicyAuthority};
use kr_protocol::grant::OrganisationRequirement;
use kr_protocol::pairing::ProposedGrant;
use kr_protocol::scalars::{AuthorisationKey, Nullable};
use kr_service_stand_in::{Moment, OrganisationAuthority, Served, serve};
use net_support::{Host, proposal};
use organisation_fixture::{Fixture, SERVED};
use organisation_support::{MINUTE_MS, Organisation, member};
use serde_json::json;
use support::{
    Companion, LinkControl, NoOwner, Phone, StubIntake, WATCHDOG, govern, pair_under, parts,
};
use tauri::Listener as _;
use tokio::sync::{oneshot, watch};

/// The account the device is signed in as, and the token it holds for the organisation's service.
const ACCOUNT: &str = "ada";
const TOKEN: &str = "ada-access-token";
const SCOPES: [&str; 2] = ["openid", "organisation.lease"];

/// The sign-in grant of `account` in the account system, and the tokens it holds for it.
fn grant_of(account: &str) -> IssuedGrant {
    IssuedGrant {
        access_token: AccountToken::new(format!("{account}-access-token")).expect("a token"),
        expires_in_seconds: 3600,
        refresh_token: RefreshToken::new(format!("{account}-refresh-token")).expect("a token"),
        scopes: SCOPES.map(str::to_owned).to_vec(),
        subject: account.to_owned(),
    }
}

/// The account system knows `account`'s grant: its token, and the refresh token that replaces it.
fn account_system_knows(served: &Served, account: &str) {
    let grant = format!("{account}-grant");
    served
        .web()
        .issue_grant_token(&format!("{account}-access-token"), account, &grant, &SCOPES);
    served
        .web()
        .issue_grant_refresh(&format!("{account}-refresh-token"), &grant);
}

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
    /// Another organisation, whose chain the service hands out in place of this one's while
    /// `foreign_chain` is set: a chain the host cannot take beside this organisation's lease.
    other: Organisation,
    foreign_chain: AtomicBool,
    /// How far behind the host's wall clock the service's runs, in milliseconds.
    behind_ms: AtomicU64,
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
            .saturating_sub(self.behind_ms.load(Ordering::SeqCst))
    }

    /// From now on the service's clock is `by` behind the host's.
    fn runs_behind(&self, by: Duration) {
        self.behind_ms.store(
            u64::try_from(by.as_millis()).expect("a short time"),
            Ordering::SeqCst,
        );
    }

    /// The directory has `account` as a member.
    fn admits(&self, account: &str) {
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(account.to_owned());
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

    /// From now on the service gives out another organisation's chain as this one's.
    fn gives_a_chain_the_host_cannot_take(&self) {
        self.foreign_chain.store(true, Ordering::SeqCst);
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
        if self.foreign_chain.load(Ordering::SeqCst) {
            return self.other.authority(self.now() - 1_000);
        }
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

/// A wait the device asked for: how long, and the end that lets it go.
type Wait = (Duration, oneshot::Sender<()>);

/// The time the device keeps: its waits, held until the test says they have passed, and the clock
/// that moves on as each does.
#[derive(Debug)]
struct HeldWaits {
    held: Mutex<(Vec<Duration>, VecDeque<Wait>)>,
    asked: watch::Sender<usize>,
    /// How many waits were dropped before they passed.
    abandoned: watch::Sender<usize>,
    /// What the device reads as the time, in UTC milliseconds.
    now_ms: AtomicU64,
}

/// Counts a wait that is dropped before it has passed.
struct Abandoning<'a>(Option<&'a watch::Sender<usize>>);

impl Drop for Abandoning<'_> {
    fn drop(&mut self) {
        if let Some(abandoned) = self.0 {
            abandoned.send_modify(|count| *count += 1);
        }
    }
}

impl HeldWaits {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            held: Mutex::default(),
            asked: watch::channel(0).0,
            abandoned: watch::channel(0).0,
            now_ms: AtomicU64::new(kr_ipc::now_ms().get()),
        })
    }

    /// Returns when `count` waits in all have been dropped before they passed: whatever was
    /// waiting on them is gone.
    async fn until_abandoned(&self, count: usize) {
        let mut abandoned = self.abandoned.subscribe();
        tokio::time::timeout(
            WATCHDOG,
            abandoned.wait_for(|abandoned| *abandoned >= count),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{} waits were dropped, not {count}",
                *self.abandoned.borrow()
            )
        })
        .expect("the drops are still counted");
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

    /// Time passes for the device, though none of its waits is over.
    fn time_passes(&self, by: Duration) {
        self.now_ms.fetch_add(
            u64::try_from(by.as_millis()).expect("a short time"),
            Ordering::SeqCst,
        );
    }

    /// The oldest wait the device still holds has passed, and the device's clock is that much
    /// later. A wait whose connection ended is not one the device holds.
    fn passes(&self) {
        loop {
            let oldest = self
                .held
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .1
                .pop_front();
            let Some((waited, oldest)) = oldest else {
                return;
            };
            if oldest.is_closed() {
                continue;
            }
            self.now_ms.fetch_add(
                u64::try_from(waited.as_millis()).expect("a short wait"),
                Ordering::SeqCst,
            );
            let _ = oldest.send(());
            return;
        }
    }
}

impl LeaseTimer for HeldWaits {
    fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let (passed, waiting) = oneshot::channel();
        {
            let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
            held.0.push(duration);
            held.1.push_back((duration, passed));
        }
        self.asked.send_modify(|asked| *asked += 1);
        Box::pin(async move {
            let mut abandoning = Abandoning(Some(&self.abandoned));
            let _ = waiting.await;
            abandoning.0 = None;
        })
    }

    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}

/// Everything one test holds.
struct Rig {
    fixture: Fixture,
    served: Served,
    signing: Arc<Signing>,
    waits: Arc<HeldWaits>,
    phone: Phone,
    /// The account the device is signed in as.
    tokens: Arc<SignedInAccount>,
    /// Counts each time the application tells the page where its connection stands.
    changes: watch::Receiver<u64>,
    /// What the test does to the application's connections to the host.
    control: Arc<LinkControl>,
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
        account_system_knows(&served, ACCOUNT);
        let signing = Arc::new(Signing {
            organisation: Mutex::new(fixture.organisation.clone()),
            moved: Arc::clone(&fixture.moved),
            members: Mutex::new(BTreeSet::from([ACCOUNT.to_owned()])),
            issued: Mutex::default(),
            other: Organisation::new(0x66, kr_ipc::now_ms().get()),
            foreign_chain: AtomicBool::new(false),
            behind_ms: AtomicU64::new(0),
        });
        served.web().serve_organisation(
            &fixture.organisation.organisation_id.to_string(),
            Arc::clone(&signing) as Arc<dyn OrganisationAuthority>,
        );
        let waits = HeldWaits::new();
        let control = LinkControl::new();
        let (phone, tokens) = signed_in_phone(&fixture, &served, &waits, &control).await;
        let changes = {
            let (heard, changes) = watch::channel(0_u64);
            phone.companion.app.listen_any(CONNECTION_EVENT, move |_| {
                heard.send_modify(|count| *count += 1);
            });
            changes
        };
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
            tokens,
            changes,
            control,
        }
    }

    fn companion(&self) -> &Companion {
        &self.phone.companion
    }

    /// Waits until the application's connection state is one `wanted` accepts, and returns it.
    async fn connection_where(
        &self,
        wanted: impl Fn(&serde_json::Value) -> bool,
    ) -> serde_json::Value {
        let mut changes = self.changes.clone();
        tokio::time::timeout(WATCHDOG, async {
            loop {
                let state = self
                    .companion()
                    .call("connection_state", json!({}))
                    .expect("the connection's state");
                if wanted(&state) {
                    return state;
                }
                changes
                    .changed()
                    .await
                    .expect("the application goes on telling the page");
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the connection did not come to be what was waited for"))
    }

    /// Waits until `connection_state` says `connected`, and returns it.
    async fn connection(&self, connected: bool) -> serde_json::Value {
        self.connection_where(|state| state["connected"] == connected)
            .await
    }

    /// Waits until the connection is down and says why in words that include `said`.
    async fn down_because(&self, said: &str) -> serde_json::Value {
        self.connection_where(|state| {
            state["connected"] == false
                && state["reason"]
                    .as_str()
                    .is_some_and(|reason| reason.contains(said))
        })
        .await
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

    /// How many reads of the organisation's chain of keys have reached the service.
    fn authority_requests(&self) -> usize {
        self.served.web().requests_to(&format!(
            "/api/account/organisations/{}/policy-authority",
            self.fixture.organisation.organisation_id
        ))
    }

    /// Returns when the organisation's service has had `count` lease requests in all.
    async fn until_lease_requests(&self, count: usize) {
        tokio::time::timeout(
            WATCHDOG,
            self.served
                .web()
                .requests_reach(&lease_path(&self.fixture), count),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the service had {} lease requests, not {count}",
                self.lease_requests()
            )
        });
    }

    /// The next lease request the service gets is refused as `moment` says.
    fn refuses_the_next_lease(&self, moment: Moment) {
        let path: &'static str = Box::leak(lease_path(&self.fixture).into_boxed_str());
        self.served.web().fail(path, 1, moment);
    }

    /// The next read of the organisation's chain of keys the service gets is refused as `moment`
    /// says.
    fn refuses_the_next_chain(&self, moment: Moment) {
        let path: &'static str = Box::leak(
            format!(
                "/api/account/organisations/{}/policy-authority",
                self.fixture.organisation.organisation_id
            )
            .into_boxed_str(),
        );
        self.served.web().fail(path, 1, moment);
    }

    /// The application is told to use another host, a plain one this device pairs with now, so that
    /// the member host is one it only visits. The other host is returned to be kept running.
    async fn uses_another_host(&self) -> Host {
        let owner = DeviceKeys::generate().expect("keys");
        let other = Host::start(&owner).await;
        pair_under(&self.phone, &other, &owner, proposal(SERVED)).await;
        let listed = self
            .companion()
            .call("pairing_view", json!({}))
            .expect("the pairing screen");
        let environment = other.environment_id.to_string();
        // The rows carry no environment, so the other host is found by choosing each and asking
        // where the connection went.
        for row in listed["hosts"].as_array().expect("the paired hosts") {
            let used = self
                .companion()
                .call(
                    "hosts_use",
                    json!({ "reference": row["reference"].as_str().expect("a reference") }),
                )
                .expect("the application uses the host");
            if used["environment_id"] == environment.as_str() {
                assert_eq!(used["connected"], true, "{used}");
                return other;
            }
        }
        panic!("the other host is among the hosts paired");
    }

    /// The row the inbox shows for the member host when the device visits it, as it does a host it
    /// is not using.
    async fn inbox_of(&self, desk: &Arc<InboxDesk>) -> HostInbox {
        let device = self.companion().device();
        let mut rows = desk.visit(&device).await;
        assert_eq!(rows.len(), 1, "the member host is the one host visited");
        rows.remove(0)
    }

    /// The device reads the host, as a page does.
    fn reads(&self) -> Result<serde_json::Value, serde_json::Value> {
        self.companion().call("host_info", json!({}))
    }

    /// The device makes a connection to the host of its own, beside the application's, as the
    /// settings listing and the owner's confirmations do.
    async fn dials(&self) -> Result<Session, LinkError> {
        let device = self.companion().device();
        let pairing = device.pairing();
        let host = pairing
            .hosts
            .list()
            .expect("the paired hosts")
            .into_iter()
            .next()
            .expect("a paired host");
        let identity = pairing.candidate.paired_identity(host.device_id);
        tokio::time::timeout(WATCHDOG, pairing.link.connect_paired(&host, &identity))
            .await
            .expect("the connection ends one way or the other")
    }

    /// The device visits the host, as it does a host it is not using: a connection of its own that
    /// never closes the endpoint of the host in use, of which there is none here.
    async fn visits(&self) -> Result<Session, LinkError> {
        let device = self.companion().device();
        let pairing = device.pairing();
        let host = pairing
            .hosts
            .list()
            .expect("the paired hosts")
            .into_iter()
            .next()
            .expect("a paired host");
        let identity = pairing.candidate.paired_identity(host.device_id);
        tokio::time::timeout(
            WATCHDOG,
            pairing.link.visit_paired(&host, &identity, &|| None),
        )
        .await
        .expect("the visit ends one way or the other")
    }

    /// The reference the pairing screen lists the host under.
    fn the_host(&self) -> String {
        self.companion()
            .call("pairing_view", json!({}))
            .expect("the pairing screen")["hosts"][0]["reference"]
            .as_str()
            .expect("a reference to the host")
            .to_owned()
    }

    /// The person signs out and signs in as `account`, a member the account system knows.
    async fn signs_in_as(&self, account: &str) {
        account_system_knows(&self.served, account);
        self.signing.admits(account);
        let _ = self.tokens.sign_out().await;
        self.tokens
            .keep(grant_of(account), "a-nonce")
            .await
            .expect("the person signs in");
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
async fn signed_in_phone(
    fixture: &Fixture,
    served: &Served,
    waits: &Arc<HeldWaits>,
    control: &Arc<LinkControl>,
) -> (Phone, Arc<SignedInAccount>) {
    let origin = kr_protocol::service::GatewayOrigin::new(served.origin()).expect("an origin");
    let http = HttpService::with(
        origin.clone(),
        HttpDeadlines::default(),
        managed_response_limits(),
    )
    .expect("a transport to the account system");
    let service: Arc<dyn AccountService> = Arc::new(ManagedAccountService::at_origin(
        served.origin(),
        Arc::new(http),
        Client::Mobile,
    ));
    let tokens = Arc::new(SignedInAccount::new(
        Arc::clone(&service),
        Arc::new(MemoryStore::new()),
        Client::Mobile,
    ));
    tokens
        .keep(grant_of(ACCOUNT), "a-nonce")
        .await
        .expect("the device signs in");
    let account = Arc::new(Account::new(
        Arc::clone(&tokens),
        service,
        origin,
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
    govern(&mut device, control);
    let companion = Companion::start_with_voice(
        data.path(),
        device,
        Arc::new(NoOwner),
        Arc::clone(&paste) as Arc<dyn companion_tauri::pairing::IntakePlatform>,
        companion_tauri::voice::Calls::absent(),
        AccountSlot::ready(account),
    );
    let phone = Phone {
        companion,
        paste,
        secrets,
        room,
        data,
    };
    (phone, tokens)
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

    // The device presented a lease to confirm its pairing and presented it again to open its
    // connection, each before it asked the host anything, and the host holds the newest.
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
    rig.until_lease_requests(before + 1).await;
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
/// told that its account is not a member rather than retried at the service: the connection ends
/// with that reason, and the application then reaches nothing of the host.
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
    assert_eq!(
        refused["code"], "HOST_NOT_CONFIGURED",
        "the application has no connection to read the host through: {refused}"
    );
}

/// KR-REQ-17.53: the lease is kept for as long as the application's connection to the host is, and
/// no longer. A person who forgets the host, or chooses another, ends the connection, and the
/// device then asks the organisation's service for nothing more for that host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_the_person_forgets_is_no_longer_kept() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;
    let requests = rig.lease_requests();

    rig.companion()
        .call("hosts_forget", json!({ "reference": rig.the_host() }))
        .expect("the person forgets the host");
    rig.waits.until_abandoned(1).await;

    assert_eq!(
        rig.lease_requests(),
        requests,
        "nothing asks for a lease for a host the person forgot"
    );
}

/// KR-REQ-17.53: a device that is not signed in cannot ask for a lease, and the person is told to
/// sign in, not that the app will try again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_is_signed_out_is_told_to_sign_in() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;

    let _ = rig.tokens.sign_out().await;
    rig.waits.passes();

    let ended = rig.down_because("sign in").await;
    assert!(
        ended["reason"]
            .as_str()
            .is_some_and(|reason| !reason.contains("asks again")),
        "the device does not promise to try again: {ended}"
    );
}

/// KR-REQ-17.53: a stop that only a person or an administrator can mend is not asked about again by
/// every connection the device makes, until the time it is held for has passed. The application reconnects every few seconds, and the
/// organisation's service allows an account a hundred and twenty lease requests an hour, so a
/// device the organisation removed would otherwise use the allowance of its account's other
/// devices.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_that_needs_a_person_is_not_asked_again_by_every_connection() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;

    rig.signing.removes(ACCOUNT);
    rig.fixture.pass_wall(Duration::from_millis(5 * MINUTE_MS));
    rig.waits.passes();
    rig.down_because("not a member").await;
    let requests = rig.lease_requests();

    let mut said = Vec::new();
    for _ in 0..3 {
        let refused = rig
            .dials()
            .await
            .expect_err("a device the organisation removed gets no connection");
        said.push(refused.to_string());
    }
    assert_eq!(
        rig.lease_requests(),
        requests,
        "no connection asks the service again after it said the account is not a member"
    );
    for said in said {
        assert!(said.contains("not a member"), "{said}");
        assert!(
            !said.contains("the host refused"),
            "the organisation's word is not the host's: {said}"
        );
    }

    // Once the time it is held for has passed, a connection asks again, in case the organisation
    // took the member back.
    rig.signing.admits(ACCOUNT);
    rig.waits.time_passes(Duration::from_secs(5 * 60 + 1));
    rig.dials().await.expect("the member is a member again");
    assert!(rig.lease_requests() > requests, "the service was asked");
}

/// KR-REQ-17.53: a service that asks the device to wait an hour is not waited out inside a
/// connection that is given twenty seconds: the connection says what the service asked for, at
/// once, and the device asks no sooner than it was told.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_that_asks_for_a_long_wait_is_not_waited_out_in_a_connection() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;
    // The host forgets the lease when it restarts, so the next connection needs the service, which
    // asks for an hour.
    rig.refuses_the_next_lease(Moment::Refuse {
        status: 429,
        code: "RATE_LIMITED",
        retry_after_seconds: Some(3600),
    });
    let rig = rig.restarted().await;

    let told = rig.down_because("wait").await;
    let requests = rig.lease_requests();
    let refused = rig.dials().await.expect_err("no connection is made");
    assert!(refused.to_string().contains("wait"), "{told}");
    assert_eq!(
        rig.lease_requests(),
        requests,
        "no connection asks before the hour is over"
    );
    assert_eq!(
        rig.waits.asked_for(),
        [Duration::from_secs(300)],
        "no connection holds an hour-long wait"
    );
}

/// KR-REQ-17.53: whatever a failure is, the device asks for a lease no oftener than once a minute
/// while it keeps one: a service that names no delay, or names none worth waiting, does not make
/// the device a loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_is_asked_for_no_oftener_than_the_shortest_refresh() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;

    rig.refuses_the_next_lease(Moment::Refuse {
        status: 429,
        code: "RATE_LIMITED",
        retry_after_seconds: Some(0),
    });
    rig.fixture.pass_wall(Duration::from_millis(5 * MINUTE_MS));
    rig.waits.passes();
    rig.waits.until_asked(2).await;
    rig.refuses_the_next_lease(Moment::Refuse {
        status: 503,
        code: "SERVICE_UNAVAILABLE",
        retry_after_seconds: None,
    });
    rig.waits.passes();
    rig.waits.until_asked(3).await;
    rig.waits.passes();
    rig.waits.until_asked(4).await;

    let asked = rig.waits.asked_for();
    for (round, wait) in asked[1..3].iter().enumerate() {
        assert!(
            *wait >= Duration::from_secs(60),
            "wait {} was {wait:?}",
            round + 1
        );
    }
    assert_eq!(
        asked[3],
        Duration::from_secs(300),
        "a lease was got in the end"
    );
}

/// KR-REQ-17.53: a chain the host will not take is not asked about for ever. The device tries a few
/// times, in case the cause is time, and then stops and says the host refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_the_host_will_not_take_ends_the_keeper_after_a_few_tries() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;
    let requests = rig.lease_requests();
    let chains = rig.authority_requests();

    // A newer key makes the next lease travel with the chain, and the chain is not this
    // organisation's.
    rig.fixture.pass_wall(Duration::from_millis(MINUTE_MS));
    assert_eq!(rig.signing.rotates(), 3);
    rig.signing.gives_a_chain_the_host_cannot_take();
    rig.fixture.pass_wall(Duration::from_millis(MINUTE_MS));
    rig.waits.passes();
    for tried in 2..=3 {
        rig.waits.until_asked(tried).await;
        rig.waits.passes();
    }

    rig.down_because("refused").await;
    assert_eq!(
        rig.lease_requests(),
        requests + 1,
        "the lease the host would not take with that chain was presented again, not asked for again"
    );
    assert_eq!(
        rig.authority_requests(),
        chains + 3,
        "the device read the chain three times and stopped"
    );
}

/// KR-REQ-17.53: a connection made beside the application's own presents the lease the device
/// already holds, and the device asks the organisation's service for another only when the host
/// refuses the one it holds, as it does once the lease has ended on the host's clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_connection_presents_the_lease_the_device_holds_and_asks_only_when_the_host_refuses_it()
 {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;
    let requests = rig.lease_requests();

    let beside = rig
        .dials()
        .await
        .expect("a connection beside the application's");
    read_host_info(&beside)
        .await
        .expect("the host serves the connection under the lease the device holds");
    assert_eq!(
        rig.lease_requests(),
        requests,
        "the lease it holds is presented again"
    );

    // The lease ends on the host's clock while the application's refresh is still waiting.
    rig.fixture.pass_wall(Duration::from_millis(20 * MINUTE_MS));
    let after = rig
        .dials()
        .await
        .expect("a connection once the lease has ended");
    read_host_info(&after)
        .await
        .expect("the host serves the connection under the lease it was given in its place");
    assert!(rig.lease_requests() > requests, "a new lease was asked for");
}

/// KR-REQ-17.53: the service can turn back a token the device thinks is good, since a token ends in
/// transit or on a clock that runs behind, and the person has done nothing wrong. The device
/// replaces the token once and asks again, and goes on keeping the lease without a word to anyone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_the_service_turns_back_is_replaced_once_and_the_keeper_goes_on() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;
    let refreshed = rig.served.web().token_refreshes();

    rig.served.web().expire_token(TOKEN);
    rig.fixture.pass_wall(Duration::from_millis(5 * MINUTE_MS));
    rig.waits.passes();
    rig.waits.until_asked(2).await;

    assert_eq!(rig.served.web().token_refreshes(), refreshed + 1);
    assert_eq!(
        rig.waits.asked_for()[1],
        Duration::from_secs(300),
        "the lease was got and the next refresh is five minutes off"
    );
    rig.connection(true).await;
    rig.reads().expect("the host serves the device");
}

/// KR-REQ-17.53: the lease the device holds, and a stop it remembers, are the account's that asked.
/// The application keeps one account object, whoever is signed in to it, so a person who signs in
/// as another member is not served under the lease of the one before, and is not told what the one
/// before was told.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_and_a_stop_belong_to_the_account_that_asked() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;

    // The first account is removed: its stop is remembered.
    rig.signing.removes(ACCOUNT);
    rig.fixture.pass_wall(Duration::from_millis(5 * MINUTE_MS));
    rig.waits.passes();
    rig.down_because("not a member").await;
    let removed = rig
        .dials()
        .await
        .expect_err("the removed account is not served");
    assert!(removed.to_string().contains("not a member"), "{removed}");
    let requests = rig.lease_requests();

    // Another member signs in. The host has bound this device to the first account, and says so.
    rig.signs_in_as("bea").await;
    let other = rig
        .dials()
        .await
        .expect_err("the host binds the device to the first");
    assert!(
        other.to_string().contains("account_mismatch"),
        "the second account was asked about afresh, and the host's rule is named: {other}"
    );
    assert_eq!(rig.lease_requests(), requests + 1);
}

/// KR-REQ-17.53: a delay the service names holds every connection, the application's own refresh
/// and the ones made beside it, until it is over. A lease the host refuses after a restart is not
/// asked for in the meantime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delay_the_service_names_binds_every_connection_until_it_is_over() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;

    // The refresh is told to wait an hour.
    rig.refuses_the_next_lease(Moment::Refuse {
        status: 429,
        code: "RATE_LIMITED",
        retry_after_seconds: Some(3600),
    });
    rig.fixture.pass_wall(Duration::from_millis(5 * MINUTE_MS));
    rig.waits.passes();
    rig.waits.until_asked(2).await;
    let requests = rig.lease_requests();

    // The host restarts and forgets the lease it held; a connection beside the application's needs
    // a new one, and the service has said when it may be asked.
    let rig = rig.restarted().await;
    let told = rig
        .dials()
        .await
        .expect_err("the service asked this device to wait");
    assert!(told.to_string().contains("wait"), "{told}");
    assert_eq!(
        rig.lease_requests(),
        requests,
        "nothing was sent before the hour was over"
    );
}

/// KR-REQ-17.53: a lease the service has just signed that the host refuses as ended is not a lease
/// to ask for again at once: the host's clock and the service's differ, and every new lease is
/// refused the same way. The device tries a few times, says which rule the host named, and sends the
/// service nothing more for a while, however many connections ask.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_the_host_refuses_as_ended_the_moment_it_is_signed_is_not_asked_for_again_and_again()
 {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;
    let requests = rig.lease_requests();

    rig.signing
        .runs_behind(Duration::from_millis(30 * MINUTE_MS));
    let rig = rig.restarted().await;
    for tried in 2..=3 {
        rig.waits.until_asked(tried).await;
        rig.waits.passes();
    }
    rig.down_because("expired").await;
    assert_eq!(
        rig.lease_requests(),
        requests + 3,
        "three leases were asked for, each refused, and the device stopped"
    );

    let refused = rig.dials().await.expect_err("the host refuses every lease");
    assert!(refused.to_string().contains("expired"), "{refused}");
    assert_eq!(
        rig.lease_requests(),
        requests + 3,
        "a stop that is held sends nothing"
    );
}

/// KR-REQ-17.53: a visit to a paired host, which the application makes to read a host it is not
/// using, is a connection of the device like any other, and the host refuses it every method until
/// it holds the device's lease. So a visit presents the lease first, and is served. The
/// application's own connections to the host are held, so that nothing but the visit can have
/// presented one after the host restarted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_visit_to_a_host_that_holds_no_lease_presents_one_first() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;
    let requests = rig.lease_requests();

    rig.control.hold_own();
    let rig = rig.restarted().await;

    let visit = rig.visits().await.expect("a visit to the host");
    read_host_info(&visit)
        .await
        .expect("the host serves a visit that presented the device's lease");
    assert_eq!(
        rig.lease_requests(),
        requests + 1,
        "the visit asked for the lease the host had forgotten"
    );
}

/// KR-REQ-17.53: a lease the service signs for one account is not presented for another. A lease
/// that arrives after another member signed in on the device is the first member's, and the host
/// binds the device to the first member and would take it: it is not presented, and the connection
/// asks again as the member who is signed in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_that_arrives_after_the_account_changed_is_not_presented() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;
    let requests = rig.lease_requests();

    // The host forgets its lease when it restarts, so the application asks the organisation's
    // service for one as it reconnects, and the service takes its time over the answer.
    let held_before = rig.host_holds().await;
    rig.refuses_the_next_lease(Moment::Gate);
    let rig = rig.restarted().await;
    rig.until_lease_requests(requests + 1).await;
    rig.signs_in_as("bea").await;
    rig.served.web().release_held();

    // The device is Ada's to the host, which refuses Bea's lease by name, and that is what is told.
    let told = rig.down_because("account_mismatch").await;
    assert_eq!(told["connected"], false, "{told}");
    assert_eq!(
        rig.host_holds().await,
        held_before,
        "the lease that arrived was Ada's, and nothing presented it"
    );
}

/// KR-REQ-17.53: a member who signs out is out of the host at once. The connection that keeps the
/// member's lease ends when the account signs out, whatever the keeper is doing, and says why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_out_ends_the_member_connection_at_once() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;
    let requests = rig.lease_requests();

    // The refresh asks the service for a lease, which takes its time.
    rig.refuses_the_next_lease(Moment::Gate);
    rig.fixture.pass_wall(Duration::from_millis(5 * MINUTE_MS));
    rig.waits.passes();
    rig.until_lease_requests(requests + 1).await;

    let _ = rig.tokens.sign_out().await;
    let ended = rig.down_because("sign in").await;
    assert_eq!(ended["connected"], false, "{ended}");
    rig.served.web().release_held();
}

/// KR-REQ-17.53: the inbox keeps its connection to a host that is not in use between passes, and
/// nothing keeps the lease of that host fresh. When the lease the host holds has ended, the next
/// pass presents the device's lease again over the connection it kept, asks the organisation's
/// service for a new one when the host refuses it, and reads the inbox, instead of showing a host
/// that is reachable as having refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_visit_is_given_the_lease_again_when_the_one_it_holds_has_ended() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    let _elsewhere = rig.uses_another_host().await;
    let desk = Arc::new(InboxDesk::default());
    let first = rig.inbox_of(&desk).await;
    assert_eq!(first.state, HostInboxState::Read, "{:?}", first.refusal);
    let requests = rig.lease_requests();

    // The lease the host holds ends on its clock, long before anything asks for another.
    rig.fixture.pass_wall(Duration::from_millis(20 * MINUTE_MS));
    let again = rig.inbox_of(&desk).await;
    assert_eq!(again.state, HostInboxState::Read, "{:?}", again.refusal);
    assert!(rig.lease_requests() > requests, "a new lease was asked for");
}

/// KR-REQ-17.53: a visit that cannot give the host the device's lease says why. A host that is
/// reachable is not out of contact because this device is signed out: the row shows the reason in
/// words, and no loss of contact is noted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_visit_that_cannot_get_a_lease_says_why_and_is_not_out_of_contact() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    let _elsewhere = rig.uses_another_host().await;
    let _ = rig.tokens.sign_out().await;

    let row = rig.inbox_of(&Arc::new(InboxDesk::default())).await;
    assert_eq!(row.state, HostInboxState::Refused, "{row:?}");
    assert_eq!(row.lost_since_ms, None);
    let said = row.refusal.expect("the reason").message;
    assert!(said.contains("sign in"), "{said}");
}

/// KR-REQ-17.53: what was held against a sign-in is not held against the next one. The service
/// turns the device's sign-in back, which the device is told to mend and is not asked about again
/// meanwhile; the person signs in again, as the same account, and the next visit asks and is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_made_since_clears_what_was_held_against_the_account() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    let _elsewhere = rig.uses_another_host().await;
    let desk = Arc::new(InboxDesk::default());
    let first = rig.inbox_of(&desk).await;
    assert_eq!(first.state, HostInboxState::Read, "{:?}", first.refusal);

    // The lease the device holds is about to end by its own clock, and the service turns its token
    // back, even renewed.
    rig.waits.time_passes(Duration::from_secs(14 * 60));
    rig.refuses_the_next_lease(Moment::Refuse {
        status: 403,
        code: "REAUTHENTICATION_REQUIRED",
        retry_after_seconds: None,
    });
    let turned_back = rig.inbox_of(&desk).await;
    assert_eq!(turned_back.state, HostInboxState::Refused);
    let said = turned_back.refusal.expect("the reason").message;
    assert!(said.contains("does not take the sign-in"), "{said}");
    let requests = rig.lease_requests();
    let held = rig.inbox_of(&desk).await;
    assert_eq!(held.state, HostInboxState::Refused);
    assert_eq!(
        rig.lease_requests(),
        requests,
        "a stop that is held asks nothing"
    );

    rig.signs_in_as(ACCOUNT).await;
    let served = rig.inbox_of(&desk).await;
    assert_eq!(served.state, HostInboxState::Read, "{:?}", served.refusal);
    assert!(rig.lease_requests() > requests, "the new sign-in asked");
}

/// KR-REQ-17.53: the service's delay binds the request for the chain of keys as it binds the request
/// for a lease. A refresh that got a new lease and was told to wait an hour for the chain leaves
/// the lease cached, and a connection that reuses it asks the service for the chain no sooner.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_visit_does_not_ask_for_the_chain_of_keys_while_the_service_asks_for_a_wait() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;
    let chains = rig.authority_requests();

    // The organisation rotates its key, so the next lease needs the chain, and the service refuses
    // the chain for an hour.
    rig.fixture.pass_wall(Duration::from_millis(MINUTE_MS));
    assert_eq!(rig.signing.rotates(), 3);
    rig.fixture.pass_wall(Duration::from_millis(MINUTE_MS));
    rig.refuses_the_next_chain(Moment::Refuse {
        status: 429,
        code: "RATE_LIMITED",
        retry_after_seconds: Some(3600),
    });
    rig.waits.passes();
    rig.waits.until_asked(2).await;
    assert_eq!(
        rig.authority_requests(),
        chains + 1,
        "the chain was refused"
    );

    let told = rig.dials().await.expect_err("the service asked for a wait");
    assert!(told.to_string().contains("wait"), "{told}");
    assert_eq!(
        rig.authority_requests(),
        chains + 1,
        "nothing asked for the chain while the hour ran"
    );
}

/// KR-REQ-17.53: a lease that is reused lasts until the first refresh of the connection that keeps
/// it. One with less left than that, and the margin, is replaced, so that a connection that
/// presents it is not left without a lease between its presentation and its first refresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reused_lease_lasts_until_the_first_refresh_of_the_connection_that_keeps_it() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;
    let requests = rig.lease_requests();

    // By the device's clock the lease it holds has a minute left, which is the shortest a refresh
    // waits and so too little.
    rig.waits.time_passes(Duration::from_secs(14 * 60));
    let session = rig
        .dials()
        .await
        .expect("a connection beside the application's");
    read_host_info(&session)
        .await
        .expect("the host serves the connection");
    assert_eq!(
        rig.lease_requests(),
        requests + 1,
        "a new lease was asked for"
    );
}

/// KR-REQ-17.53: a caller that cuts a presentation off while the service has not answered has not
/// been answered either, and the next presentation does not ask again at once: a service that
/// answers nothing is not sent a request from every pass of every caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_presentation_its_caller_cuts_off_while_the_service_is_silent_holds_the_service_off() {
    let rig = Rig::start().await;
    rig.connection(true).await;
    rig.waits.until_asked(1).await;
    let requests = rig.lease_requests();

    // The lease the device holds is too short to present again, so a lease is asked for, and the
    // service answers nothing. The caller gives up on it the moment the request has arrived.
    rig.waits.time_passes(Duration::from_secs(14 * 60 + 30));
    rig.refuses_the_next_lease(Moment::Hold);
    tokio::select! {
        _ = rig.dials() => panic!("the service answered nothing"),
        () = rig.until_lease_requests(requests + 1) => {}
    }

    let told = rig.dials().await.expect_err("the service is held off");
    assert!(
        told.to_string().contains("did not give this device"),
        "{told}"
    );
    assert_eq!(rig.lease_requests(), requests + 1, "nothing asked again");
    rig.served.web().release_held();
}

/// The host answers what it is, to a connection that holds a lease.
async fn read_host_info(session: &Session) -> Result<(), kr_client::ClientError> {
    session
        .read::<_, kr_protocol::hostinfo::HostInfoResult>(
            kr_protocol::method::Method::HostInfo,
            &json!({}),
        )
        .await
        .map(|_| ())
}
