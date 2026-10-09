//! A member's device presents the lease its organisation signed for it, on its own connection to a
//! real daemon, and is answered for exactly as long as the lease lasts.
//!
//! The organisation is a stand-in that signs with real keys: it issues the leases and publishes the
//! chain, which is all the managed service does for the host. The daemon runs on a continuous
//! clock and a wall clock the suite moves by hand, so a lease ends when the suite says it does and
//! never because a runner was slow. A device's connection stays up throughout; what ends is the
//! lease, and with it the daemon's answers.

#![cfg(unix)]

mod net_support;
mod organisation_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use kr_controller::grants::LeaseRefused;
use kr_controller::service::{Clocks, WallClock};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::account::{MembershipLease, PolicyAuthority, TeamRole};
use kr_protocol::confirmation::{ConfirmationSubject, OrganisationEnrolPlan};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::OrganisationRequirement;
use kr_protocol::ids::{AccountId, ActionId, AuthorityRevision, SessionId};
use kr_protocol::method::Method;
use kr_protocol::organisation::{
    MembershipPresentParams, MembershipPresentResult, OrganisationEnrolParams,
    OrganisationEnrolResult, OrganisationListParams, OrganisationListResult,
};
use kr_protocol::pairing::ProposedGrant;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, Nullable, Uuid};
use kr_protocol::session::SessionCloseParams;
use kr_transport::clock::ManualClock;
use net_support::pairing::{self as calls, Signer};
use net_support::{Device, Host, RawDevice, connect, pair_with, proposal};
use organisation_support::{LEASE_MS, MINUTE_MS, Organisation, member};

const DAY_MS: u64 = 24 * 60 * MINUTE_MS;
const SERVED: &[ActionRight] = &[ActionRight::SessionView, ActionRight::SessionClose];
const VIEW_ONLY: &[ActionRight] = &[ActionRight::SessionView];

/// A daemon enrolled in an organisation, on clocks the suite moves.
struct Fixture {
    host: Host,
    owner: DeviceKeys,
    organisation: Organisation,
    revision: AuthorityRevision,
    continuous: ManualClock,
    moved: Arc<AtomicI64>,
}

impl Fixture {
    /// Starts a daemon with an owner device and enrols it through the owner's confirmation, the
    /// way a person does.
    async fn start() -> Self {
        let owner = DeviceKeys::generate().expect("keys");
        let continuous = ManualClock::new();
        let moved = Arc::new(AtomicI64::new(0));
        let read = Arc::clone(&moved);
        let clocks = Clocks {
            continuous: Arc::new(continuous.clone()),
            wall: WallClock::from_fn(move || {
                kr_ipc::now_ms()
                    .get()
                    .saturating_add_signed(read.load(Ordering::SeqCst))
            }),
        };
        let host = Host::start_on_clocks(&owner, clocks).await;
        let now = kr_ipc::now_ms().get();
        let mut organisation = Organisation::new(0x21, now - 2 * DAY_MS);
        organisation.rotate(now - DAY_MS);
        let params = OrganisationEnrolParams {
            authority: organisation.authority(now - 1_000),
        };
        let mut client = host.client().await;
        calls::confirm_subject(
            host.environment_id,
            &mut client,
            ConfirmationSubject::EnrolOrganisation(Box::new(params.clone())),
            &Signer::OwnerDevice(&owner),
        )
        .await
        .expect("the owner confirms the chain");
        let enrolled: OrganisationEnrolResult = calls::mutate_as(
            host.environment_id,
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            Method::OrganisationEnrol,
            &params,
        )
        .await
        .expect("the host enrols");
        assert!(OrganisationEnrolPlan::of_authority(&params.authority).is_some());
        drop(client);
        Self {
            host,
            owner,
            organisation,
            revision: enrolled.enrolment_revision,
            continuous,
            moved,
        }
    }

    /// The daemon's wall clock now, in UTC milliseconds.
    fn now(&self) -> u64 {
        kr_ipc::now_ms()
            .get()
            .saturating_add_signed(self.moved.load(Ordering::SeqCst))
    }

    /// Both clocks pass `by`, as time does.
    fn pass(&self, by: Duration) {
        self.pass_continuous(by);
        self.pass_wall(by);
    }

    /// Only the continuous clock passes `by`: a host that slept with its wall clock held.
    fn pass_continuous(&self, by: Duration) {
        self.continuous.advance(by);
    }

    /// Only the wall clock passes `by`: a clock set forward.
    fn pass_wall(&self, by: Duration) {
        self.moved.fetch_add(
            i64::try_from(by.as_millis()).expect("a short time"),
            Ordering::SeqCst,
        );
    }

    /// Pairs a device whose grant answers to the organisation, with the rights named.
    async fn member(&self, name: &str, rights: &[ActionRight]) -> Member {
        let device = Device::create().await;
        let grant = ProposedGrant {
            organisation: Nullable::some(OrganisationRequirement {
                organisation_id: self.organisation.organisation_id,
                policy_revision: self.revision,
            }),
            ..proposal(rights)
        };
        let record = pair_with(&self.host, &device, &self.owner, grant).await;
        Member {
            device,
            record,
            account: member(name),
        }
    }

    /// A lease signed by `revision` for `member`, issued now.
    fn lease(&self, revision: u64, member: &Member, rights: &[ActionRight]) -> MembershipLease {
        self.organisation
            .lease(revision, &member.account, member.key(), self.now(), rights)
    }

    /// Waits until the host owes no fence: the debt pass has retired what a restriction owed.
    async fn until_the_fence_is_retired(&self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while !self
            .host
            .controller()
            .sharing()
            .grants()
            .fence_owed()
            .expect("readable")
            .is_empty()
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the fence the host owes was not retired"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The owner reads what the host holds, on the owner's own local socket.
    async fn listed(&self) -> OrganisationListResult {
        let mut client = self.host.client().await;
        calls::read(
            &mut client,
            Method::OrganisationList,
            &OrganisationListParams::default(),
        )
        .await
        .expect("the owner reads the list")
    }
}

/// A member's device: its keys, its pairing and the account it works as.
struct Member {
    device: Device,
    record: kr_controller::service::net::devices::DeviceRecord,
    account: AccountId,
}

impl Member {
    /// The authorisation key the device proves, which a lease for it names.
    fn key(&self) -> AuthorisationKey {
        *self.device.keys().authorisation.public()
    }

    /// A new connection of the device, with a fresh action window.
    async fn connect(&self, fixture: &Fixture) -> RawDevice {
        let raw = RawDevice::connect(&fixture.host, &self.device, &self.record).await;
        raw.claim();
        raw
    }

    /// Presents `lease`, and a chain when there is one, under a new action.
    async fn present(
        &self,
        fixture: &Fixture,
        raw: &RawDevice,
        lease: MembershipLease,
        authority: Option<PolicyAuthority>,
    ) -> Result<MembershipPresentResult, ProtocolError> {
        let value = raw
            .mutate(
                Method::MembershipPresent,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(fixture.host.environment_id),
                &MembershipPresentParams {
                    lease,
                    authority: authority.map_or_else(Nullable::null, Nullable::some),
                },
            )
            .await?;
        Ok(value.to_typed().expect("the answer of the method"))
    }
}

/// Reads the host's identity, which every member with a lease may.
async fn read_host_info(raw: &RawDevice) -> Result<(), ProtocolError> {
    raw.read(Method::HostInfo, &()).await.map(|_| ())
}

/// Closes a session that does not exist, which only a device with `session.close` under a lease
/// gets as far as asking. It is refused for what is wrong with it, never for want of authority.
async fn close_a_session(fixture: &Fixture, raw: &RawDevice) -> ProtocolError {
    let session_id = SessionId::new(Uuid::from_bytes([0x5e; 16]));
    let target = ActionTarget {
        session_id: Nullable::some(session_id),
        ..ActionTarget::environment(fixture.host.environment_id)
    };
    net_support::refusal(
        raw.mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            target,
            &SessionCloseParams { session_id },
        )
        .await,
    )
}

fn denied(error: &ProtocolError) -> bool {
    error.code == ErrorCode::PermissionDenied
}

/// KR-REQ-17.53, KR-REQ-17.54: a member's device whose grant answers to an organisation is refused
/// every read and mutation until it presents a lease, and served once the host has installed one.
/// What the host tells the device is what it installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_device_is_refused_before_it_presents_and_served_after() {
    let fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let raw = ada.connect(&fixture).await;
    assert!(
        denied(&net_support::refusal(read_host_info(&raw).await)),
        "a read before a lease"
    );
    assert!(denied(&close_a_session(&fixture, &raw).await));

    let lease = fixture.lease(2, &ada, SERVED);
    let expires_at_ms = lease.payload.expires_at_ms;
    let answer = ada
        .present(&fixture, &raw, lease, None)
        .await
        .expect("the host installs the lease");
    assert_eq!(answer.organisation_id, fixture.organisation.organisation_id);
    assert_eq!(answer.account_id, ada.account);
    assert_eq!(answer.key_revision.get(), 2);
    assert_eq!(answer.expires_at_ms, expires_at_ms);
    assert!(!answer.exclusive);
    assert!(answer.exclusive_ended_at_terminal_ms.0.is_none());

    read_host_info(&raw).await.expect("a read under the lease");
    let error = close_a_session(&fixture, &raw).await;
    assert!(
        !denied(&error),
        "a mutation under the lease gets as far as its session: {error:?}"
    );

    // The device is bound to the account and key of its first lease, durably and where the owner
    // reads it.
    let listed = fixture.listed().await;
    let members = &listed.enrolments[0].members;
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].account_id, ada.account);
    assert_eq!(members[0].device_id, ada.record.device_id);
    assert_eq!(
        members[0].lease.as_ref().map(|lease| lease.expires_at_ms),
        Some(expires_at_ms)
    );
    raw.close();
    fixture.host.stop().await;
}

/// KR-REQ-17.53: a device that presents a fresh lease every five minutes of the continuous clock is
/// served throughout, for longer than any one lease lasts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_who_presents_every_five_minutes_is_served_throughout() {
    let fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let first = ada.connect(&fixture).await;
    ada.present(&fixture, &first, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("the first lease");
    first.close();
    for round in 1..=6 {
        fixture.pass(Duration::from_millis(5 * MINUTE_MS));
        // A window lasts five minutes of the continuous clock, so each presentation is made on a
        // connection that was just given one.
        let raw = ada.connect(&fixture).await;
        read_host_info(&raw).await.unwrap_or_else(|error| {
            panic!("round {round}: still served before it renews: {error:?}")
        });
        ada.present(&fixture, &raw, fixture.lease(2, &ada, SERVED), None)
            .await
            .unwrap_or_else(|error| panic!("round {round}: the renewal: {error:?}"));
        read_host_info(&raw)
            .await
            .unwrap_or_else(|error| panic!("round {round}: served after it renews: {error:?}"));
        raw.close();
    }
    fixture.host.stop().await;
}

/// KR-REQ-17.54: a member whose organisation stops issuing leases is served until the last one runs
/// out and refused after, a read and a mutation both, while the connection stays up. A lease that
/// arrives after the end serves the device again on the same connection, and the owner's own
/// device is served throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_whose_lease_runs_out_is_refused_on_the_same_connection_and_served_again_by_a_new_one()
 {
    let fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let owner_device = fixture
        .host
        .owner_device
        .as_ref()
        .expect("the owner device");
    let owner_record = fixture.host.owner.as_ref().expect("the owner's record");
    let owner = connect(&fixture.host, owner_device, owner_record).await;
    let owner_list = || async {
        owner
            .read::<_, OrganisationListResult>(
                Method::OrganisationList,
                &OrganisationListParams::default(),
            )
            .await
            .expect("the owner's device is served")
    };

    let raw = ada.connect(&fixture).await;
    let first = fixture.lease(2, &ada, SERVED);
    ada.present(&fixture, &raw, first.clone(), None)
        .await
        .expect("the lease");
    owner_list().await;

    fixture.pass(Duration::from_millis(14 * MINUTE_MS));
    read_host_info(&raw)
        .await
        .expect("served a minute before the end");
    let fresh = ada.connect(&fixture).await;
    assert!(!denied(&close_a_session(&fixture, &fresh).await));
    fresh.close();

    fixture.pass(Duration::from_millis(MINUTE_MS + 1_000));
    assert!(
        denied(&net_support::refusal(read_host_info(&raw).await)),
        "a read after the end, on the connection that stayed up"
    );
    let fresh = ada.connect(&fixture).await;
    assert!(
        denied(&close_a_session(&fixture, &fresh).await),
        "a mutation after the end"
    );
    owner_list().await;

    // A lease that arrives late is refused as ended, and one issued now serves the device again,
    // on the connection that never closed.
    let late = ada
        .present(&fixture, &fresh, first, None)
        .await
        .expect_err("the lease that ran out");
    assert!(denied(&late), "{late:?}");
    assert!(
        late.message.contains(LeaseRefused::Expired.name()),
        "{late:?}"
    );
    ada.present(&fixture, &fresh, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("a new lease");
    read_host_info(&raw)
        .await
        .expect("served again on the old connection");
    owner_list().await;
    raw.close();
    fresh.close();
    fixture.host.stop().await;
}

/// KR-REQ-17.54: a lease ends on the continuous clock with the wall clock held, and on the wall
/// clock with the continuous clock held. Waking from sleep is the first: the continuous clock counts
/// the sleep, and the wall clock is whatever it says.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_ends_on_either_clock_alone() {
    let fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let raw = ada.connect(&fixture).await;
    ada.present(&fixture, &raw, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("the lease");
    read_host_info(&raw).await.expect("served");

    // The wall clock set forward alone ends it. A new lease serves the device again.
    fixture.pass_wall(Duration::from_millis(LEASE_MS));
    assert!(
        denied(&net_support::refusal(read_host_info(&raw).await)),
        "the wall clock alone ended it"
    );
    ada.present(&fixture, &raw, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("a new lease");
    read_host_info(&raw).await.expect("served again");

    // The continuous clock alone ends it too: a host that slept with its wall clock held. That host
    // also finds its wall clock behind the time it has lived through, and trusts it no more, which
    // is why this is last.
    fixture.pass_continuous(Duration::from_millis(LEASE_MS));
    assert!(
        denied(&net_support::refusal(read_host_info(&raw).await)),
        "the continuous clock alone ended it"
    );
    raw.close();
    fixture.host.stop().await;
}

/// KR-REQ-17.54: a lease that narrows what the device may do narrows what it is served, and fences
/// the device: the host owes a barrier for it, and a device whose connection the barrier withdrew
/// connects again and presents the same lease under a new action, which the host answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_narrower_renewal_narrows_what_is_served_and_the_presenter_reconnects() {
    let fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let raw = ada.connect(&fixture).await;
    ada.present(&fixture, &raw, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("the wide lease");
    assert!(!denied(&close_a_session(&fixture, &raw).await));

    // The next lease is newer and says less: no right to close a session.
    fixture.pass(Duration::from_secs(1));
    let narrow = fixture.lease(2, &ada, VIEW_ONLY);
    ada.present(&fixture, &raw, narrow.clone(), None)
        .await
        .expect("the narrower lease installs");
    fixture.until_the_fence_is_retired().await;
    // The fence the narrowing owed withdrew the presenter's registration: the connection it was
    // made on stays up and is served nothing more, though the lease still allows reads.
    assert!(
        denied(&net_support::refusal(read_host_info(&raw).await)),
        "the connection the narrowing was presented on is withdrawn"
    );

    let again = ada.connect(&fixture).await;
    read_host_info(&again)
        .await
        .expect("still served what the lease allows");
    assert!(
        denied(&close_a_session(&fixture, &again).await),
        "no longer served what the lease dropped"
    );
    let repeat = ada
        .present(&fixture, &again, narrow, None)
        .await
        .expect("the same lease again, under a new action, is answered");
    assert_eq!(repeat.account_id, ada.account);
    raw.close();
    again.close();
    fixture.host.stop().await;
}

/// KR-REQ-17.53: a lease some rule refuses installs nothing, the refusal names the rule, and what
/// the device was served under its earlier lease goes on. A host that distrusts its clock installs
/// no lease at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_a_rule_refuses_installs_nothing_and_names_the_rule() {
    let fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let bea = fixture.member("bea", SERVED).await;
    let raw = ada.connect(&fixture).await;
    let organisation = &fixture.organisation;

    let good = fixture.lease(2, &ada, SERVED);
    let issued = good.payload.issued_at_ms.get();
    ada.present(&fixture, &raw, good.clone(), None)
        .await
        .expect("the first lease installs");

    let mut tampered = fixture.lease(2, &ada, SERVED);
    tampered.payload.maximum_grants = [ActionRight::SessionView, ActionRight::TerminalInput]
        .into_iter()
        .collect();
    let too_long = organisation.sign(
        2,
        organisation.payload(
            2,
            &ada.account,
            ada.key(),
            issued + 1_000,
            LEASE_MS + 1_000,
            SERVED,
        ),
    );
    let mut above_ceiling_payload =
        organisation.payload(2, &ada.account, ada.key(), issued + 2_000, LEASE_MS, SERVED);
    above_ceiling_payload.role = TeamRole::Viewer;
    above_ceiling_payload.maximum_grants = [ActionRight::SessionView, ActionRight::TerminalInput]
        .into_iter()
        .collect();
    let above_ceiling = organisation.sign(2, above_ceiling_payload);
    let from_the_future = organisation.lease(
        2,
        &ada.account.clone().into(),
        ada.key(),
        issued + 60_000,
        SERVED,
    );
    let for_another_device = fixture.lease(2, &bea, SERVED);
    let another_member = organisation.lease(2, &member("cai"), ada.key(), issued + 3_000, SERVED);
    let unknown_revision = {
        let mut unknown = Organisation::new(0x21, issued - 2 * DAY_MS);
        unknown.rotate(issued - DAY_MS);
        unknown.rotate(issued - 1_000);
        unknown.lease(3, &ada.account, ada.key(), issued + 4_000, SERVED)
    };
    let older = organisation.lease(2, &ada.account, ada.key(), issued - 1_000, SERVED);

    for (name, lease, rule) in [
        (
            "a signature that is not the revision's",
            tampered,
            LeaseRefused::BadSignature,
        ),
        (
            "a lease longer than fifteen minutes",
            too_long,
            LeaseRefused::TooLong,
        ),
        (
            "a lease above its role's ceiling",
            above_ceiling,
            LeaseRefused::AboveRoleCeiling,
        ),
        (
            "a lease from the host's future",
            from_the_future,
            LeaseRefused::NotYetValid,
        ),
        (
            "a lease for another device's key",
            for_another_device,
            LeaseRefused::DeviceMismatch,
        ),
        (
            "a lease for another member on a bound device",
            another_member,
            LeaseRefused::AccountMismatch,
        ),
        (
            "a revision the host has not authenticated",
            unknown_revision,
            LeaseRefused::UnauthenticatedRevision,
        ),
        (
            "a lease older than the newest",
            older,
            LeaseRefused::Superseded,
        ),
    ] {
        let error = ada
            .present(&fixture, &raw, lease, None)
            .await
            .expect_err(name);
        assert!(denied(&error), "{name}: {error:?}");
        assert!(error.message.contains(rule.name()), "{name}: {error:?}");
    }
    read_host_info(&raw)
        .await
        .expect("what was served under the first lease goes on");
    assert_eq!(fixture.listed().await.enrolments[0].members.len(), 1);

    // A host that distrusts its clock installs no lease.
    fixture.pass_wall(Duration::from_secs(0));
    fixture.moved.fetch_sub(
        i64::try_from(10 * MINUTE_MS).expect("fits"),
        Ordering::SeqCst,
    );
    assert!(
        !fixture.listed().await.clock_trusted,
        "the host found the wall clock going backwards"
    );
    let error = ada
        .present(&fixture, &raw, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect_err("the host trusts no reading of UTC");
    assert_eq!(error.code, ErrorCode::ClockUntrusted, "{error:?}");
    raw.close();
    fixture.host.stop().await;
}

/// KR-REQ-17.53, KR-REQ-24.15: the leases a daemon held are not held by the next one. A lease it
/// installed before it restarted is refused as installed earlier, whatever its time says, and a
/// newer one installs, with the binding the first one made read back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_installed_before_a_restart_is_refused_after_it_and_a_newer_one_installs() {
    let fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let raw = ada.connect(&fixture).await;
    let first = fixture.lease(2, &ada, SERVED);
    ada.present(&fixture, &raw, first.clone(), None)
        .await
        .expect("the lease");
    raw.close();

    let Fixture {
        host,
        owner,
        organisation,
        revision,
        continuous,
        moved,
    } = fixture;
    let host = host.restart().await;
    let fixture = Fixture {
        host,
        owner,
        organisation,
        revision,
        continuous,
        moved,
    };
    let raw = ada.connect(&fixture).await;
    assert!(
        denied(&net_support::refusal(read_host_info(&raw).await)),
        "no lease is held after a restart"
    );
    let error = ada
        .present(&fixture, &raw, first, None)
        .await
        .expect_err("the lease of the earlier run");
    assert!(
        error
            .message
            .contains(LeaseRefused::InstalledEarlier.name()),
        "{error:?}"
    );
    assert_eq!(
        fixture.listed().await.enrolments[0].members.len(),
        1,
        "the binding survived"
    );
    fixture.pass(Duration::from_secs(1));
    let answered = ada
        .present(&fixture, &raw, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("a newer lease installs");
    assert_eq!(answered.account_id, ada.account);
    read_host_info(&raw).await.expect("served again");
    raw.close();
    fixture.host.stop().await;
}

/// KR-REQ-17.53: a chain presented beside a lease is followed before the lease is judged. A lease
/// signed by a revision the host has not heard of is refused alone and accepted with the chain that
/// brings the revision in; a chain that is not newer changes nothing and does not refuse the lease
/// beside it; a newer chain beside a lease already installed is followed; a chain that does not
/// carry the host's anchor, or is another organisation's, refuses the presentation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_beside_a_lease_is_followed_before_the_lease_is_judged() {
    let mut fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let raw = ada.connect(&fixture).await;
    let now = fixture.now();
    let third = fixture.organisation.rotate(now - 60_000);
    assert_eq!(third, 3);

    let lease = fixture.lease(3, &ada, SERVED);
    let error = ada
        .present(&fixture, &raw, lease.clone(), None)
        .await
        .expect_err("the host has not heard of revision 3");
    assert!(
        error
            .message
            .contains(LeaseRefused::UnauthenticatedRevision.name()),
        "{error:?}"
    );

    // A forked history and another organisation's chain are refused, and install nothing.
    let mut fork = Organisation::new(0x21, now - 2 * DAY_MS);
    fork.rotate(now - DAY_MS);
    fork.rotate(now - 60_000);
    let error = ada
        .present(&fixture, &raw, lease.clone(), Some(fork.authority(now)))
        .await
        .expect_err("a chain without this host's anchor");
    assert_eq!(error.code, ErrorCode::InvalidArgument, "{error:?}");
    let mut elsewhere = Organisation::new(0x22, now - 2 * DAY_MS);
    elsewhere.rotate(now - DAY_MS);
    let error = ada
        .present(
            &fixture,
            &raw,
            lease.clone(),
            Some(elsewhere.authority(now)),
        )
        .await
        .expect_err("another organisation's chain");
    assert_eq!(error.code, ErrorCode::InvalidArgument, "{error:?}");
    assert_eq!(fixture.listed().await.enrolments[0].accepted_head.get(), 2);

    // The chain that brings revision 3 in is followed, and the lease is judged against it.
    let answered = ada
        .present(
            &fixture,
            &raw,
            lease.clone(),
            Some(fixture.organisation.authority(now)),
        )
        .await
        .expect("the lease signed by revision 3, with the chain that brings it in");
    assert_eq!(answered.key_revision.get(), 3);
    assert_eq!(fixture.listed().await.enrolments[0].accepted_head.get(), 3);
    read_host_info(&raw).await.expect("served");

    // A chain that is not newer does not refuse the lease beside it.
    fixture.pass(Duration::from_secs(1));
    ada.present(
        &fixture,
        &raw,
        fixture.lease(3, &ada, SERVED),
        Some(fixture.organisation.authority_at(2, now)),
    )
    .await
    .expect("a stale chain is not a reason to refuse a valid lease");
    assert_eq!(fixture.listed().await.enrolments[0].accepted_head.get(), 3);

    // A newer chain beside a lease already installed is followed, though the lease binds nothing.
    let installed = fixture.lease(3, &ada, SERVED);
    ada.present(&fixture, &raw, installed.clone(), None)
        .await
        .expect("installed");
    // Revision 4 takes over a moment after that lease was issued, so the lease is not signed
    // after its revision was succeeded.
    let issued = installed.payload.issued_at_ms.get();
    let fourth = fixture.organisation.rotate(issued + 500);
    assert_eq!(fourth, 4);
    fixture.pass(Duration::from_secs(2));
    ada.present(
        &fixture,
        &raw,
        installed,
        Some(fixture.organisation.authority(fixture.now())),
    )
    .await
    .expect("the same lease, with a newer chain");
    assert_eq!(fixture.listed().await.enrolments[0].accepted_head.get(), 4);
    raw.close();
    fixture.host.stop().await;
}

/// KR-REQ-17.53: a chain that shows another device's lease was signed after its revision was
/// succeeded drops that lease and fences the host. The other device is refused from then on, and
/// the host's barrier retires.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_that_drops_another_devices_lease_fences_the_host() {
    let mut fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let bea = fixture.member("bea", SERVED).await;
    let now = fixture.now();
    // Revision 3 took over a minute ago, and the host has not heard.
    fixture.organisation.rotate(now - 60_000);
    let ada_raw = ada.connect(&fixture).await;
    let bea_raw = bea.connect(&fixture).await;

    // Bea's lease, signed by revision 2 after revision 3 took over, installs: nothing this host
    // knows shows revision 2 was succeeded.
    ada.present(&fixture, &ada_raw, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("ada's lease");
    bea.present(&fixture, &bea_raw, fixture.lease(2, &bea, SERVED), None)
        .await
        .expect("bea's lease");
    read_host_info(&bea_raw).await.expect("bea is served");

    // Ada presents revision 3's chain. Both leases were issued after it took over, so both go.
    fixture.pass(Duration::from_secs(1));
    let outcome = ada
        .present(
            &fixture,
            &ada_raw,
            fixture.lease(3, &ada, SERVED),
            Some(fixture.organisation.authority(fixture.now())),
        )
        .await;
    // The barrier may withdraw the connection the answer was on; the lease is installed either way.
    drop(outcome);
    fixture.until_the_fence_is_retired().await;
    let fresh = bea.connect(&fixture).await;
    assert!(
        denied(&net_support::refusal(read_host_info(&fresh).await)),
        "bea's lease went with the chain"
    );
    let ada_fresh = ada.connect(&fixture).await;
    read_host_info(&ada_fresh)
        .await
        .expect("ada's new lease, signed by the new revision, serves her");
    fresh.close();
    ada_fresh.close();
    fixture.host.stop().await;
}

/// KR-REQ-17.53: an admission that lapses while a presentation waits for the store is asked again
/// where the policy is written, and nothing is written: the device is not bound, no lease is held,
/// and the owner's list shows no member.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_presentation_whose_deadline_passes_while_it_waits_for_the_store_writes_nothing() {
    let fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let raw = ada.connect(&fixture).await;
    let (arrived, go) = fixture
        .host
        .controller()
        .sharing()
        .grants()
        .pause_before_effect();

    let lease = fixture.lease(2, &ada, SERVED);
    let attempt = {
        let params = MembershipPresentParams {
            lease,
            authority: Nullable::null(),
        };
        let environment = fixture.host.environment_id;
        tokio::spawn(async move {
            let answered = raw
                .mutate(
                    Method::MembershipPresent,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget::environment(environment),
                    &params,
                )
                .await;
            (raw, answered)
        })
    };
    // Thirty seconds is how long the test waits for a presentation that never gets as far as the
    // store, so that it fails rather than hangs.
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the wait ends")
        .expect("the presentation reaches the store");
    // The mutation was admitted for a bounded time on the continuous clock.
    fixture.pass(Duration::from_secs(10 * 60));
    go.send(()).expect("the presentation waits");
    let (raw, answered) = attempt.await.expect("the presentation ends");
    let error = answered.expect_err("the deadline passed before the policy was written");
    assert!(error.code == ErrorCode::PermissionDenied, "{error:?}");
    assert!(
        fixture.listed().await.enrolments[0].members.is_empty(),
        "no member was bound"
    );
    let fresh = ada.connect(&fixture).await;
    assert!(
        denied(&net_support::refusal(read_host_info(&fresh).await)),
        "no lease is held"
    );
    // The control: the same lease, presented in time, installs.
    ada.present(&fixture, &fresh, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("presented in time");
    raw.close();
    fresh.close();
    fixture.host.stop().await;
}
