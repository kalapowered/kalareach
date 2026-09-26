//! The host side of organisation policy: the chain a host pins when it enrols, the rotations it
//! follows, the membership leases it verifies before it stores them, and what survives a restart.
//!
//! The policy-level tests drive a manual continuous clock and hand the policy its reading of UTC,
//! so every deadline is decided at a moment the test chose.

mod organisation_support;

use std::path::PathBuf;
use std::sync::Arc;

use kr_controller::grants::policy::UtcFloor;
use std::time::Duration;

use kr_controller::grants::organisation::{
    ChainOutcome, ChainRefused, LeaseChange, LeasePresentation,
};
use kr_controller::grants::store::BindingEvent;
use kr_controller::grants::{
    AccessRequest, GrantDirectory, GrantRecord, HostPolicy, LeaseRefused, Refusal, decide,
};
use kr_controller::service::net::devices::{DeviceDirectory, DeviceRecord};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::account::{ChainError, POLICY_AUTHORITY_DOMAIN, POLICY_AUTHORITY_HEAD_DOMAIN};
use kr_protocol::actor::ActorIngress;
use kr_protocol::grant::{
    EnvironmentSelector, Grant, GrantExpiry, HistoryScope, OrganisationRequirement, SessionSelector,
};
use kr_protocol::ids::{
    AuthorityRevision, BuildId, DeviceId, DeviceKeyRevision, EnvironmentId, GrantId,
    OrganisationId, PolicyKeyRevision,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{DeviceName, DevicePlatform};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{
    AuthorisationKey, CanonicalSet, EndpointKey, Nullable, Signature64, TimestampMs, Uuid,
};
use kr_protocol::sharing::{MembershipRefusal, OfflineValidityPolicy};
use kr_transport::clock::{ContinuousClock as _, ManualClock};

use organisation_support::{
    LEASE_MS, MINUTE_MS, Organisation, T, device, generation, member, presented, reading, sign,
};

const DAY_MS: u64 = 24 * 60 * MINUTE_MS;
const VIEW: &[ActionRight] = &[ActionRight::SessionView];

fn policy() -> HostPolicy {
    HostPolicy::personal(AuthorityRevision::new(1))
}

/// An organisation whose second revision took over a day before `T`, enrolled in `host` at `T`.
fn enrolled(host: &mut HostPolicy) -> Organisation {
    let mut organisation = Organisation::new(0x21, T - 2 * DAY_MS);
    organisation.rotate(T - DAY_MS);
    organisation.enrol(host, T);
    organisation
}

// ---------------------------------------------------------------------------------------------
// Enrolment and rotation (KR-REQ-17.53, section 25's signed rotation chain)
// ---------------------------------------------------------------------------------------------

/// A host pins an organisation only from a chain that verifies whole: the first link under its
/// own key, every later link under its predecessor's, and a current head under the key of the
/// revision it names. The pin is the key signing now, not a number.
#[test]
fn a_chain_that_does_not_verify_is_not_pinned() {
    let mut organisation = Organisation::new(0x21, T - 2 * DAY_MS);
    organisation.rotate(T - DAY_MS);
    let host = policy();
    let at = Some(reading(T));

    let mut foreign_root = organisation.authority(T);
    foreign_root.chain[0].signature = sign(
        organisation.key(2),
        POLICY_AUTHORITY_DOMAIN,
        foreign_root.chain[0].payload.signing_input(),
    );
    assert_eq!(
        host.verify_enrolment(&foreign_root, at.as_ref()),
        Err(ChainRefused::LinkSignature {
            revision: PolicyKeyRevision::new(1)
        }),
        "the first revision signs itself"
    );

    let mut self_signed_step = organisation.authority(T);
    self_signed_step.chain[1].signature = sign(
        organisation.key(2),
        POLICY_AUTHORITY_DOMAIN,
        self_signed_step.chain[1].payload.signing_input(),
    );
    assert_eq!(
        host.verify_enrolment(&self_signed_step, at.as_ref()),
        Err(ChainRefused::LinkSignature {
            revision: PolicyKeyRevision::new(2)
        }),
        "a later revision is signed by the one before it, never by itself"
    );

    let mut reparented = organisation.authority(T);
    reparented.chain[1].payload.previous_key_revision = Nullable::some(PolicyKeyRevision::new(2));
    assert_eq!(
        host.verify_enrolment(&reparented, at.as_ref()),
        Err(ChainRefused::Structure(ChainError::BrokenSuccession {
            index: 1
        })),
        "a broken succession is refused before any signature is read"
    );

    let mut foreign_head = organisation.authority(T);
    foreign_head.head.signature = sign(
        organisation.key(1),
        POLICY_AUTHORITY_HEAD_DOMAIN,
        foreign_head.head.payload.signing_input(),
    );
    assert_eq!(
        host.verify_enrolment(&foreign_head, at.as_ref()),
        Err(ChainRefused::HeadSignature),
        "the head is signed by the revision it names"
    );

    let authority = organisation.authority(T);
    assert_eq!(
        host.verify_enrolment(&authority, Some(&reading(T + 16 * MINUTE_MS))),
        Err(ChainRefused::HeadNotCurrent),
        "an expired head says nothing about now"
    );
    assert_eq!(
        host.verify_enrolment(&authority, None),
        Err(ChainRefused::ClockUntrusted),
        "a clock this host does not trust verifies nothing"
    );

    // The control: the intact chain enrols, and what is pinned is the key signing now.
    let mut host = policy();
    let verified = host
        .verify_enrolment(&authority, at.as_ref())
        .expect("the intact chain verifies");
    assert_eq!(verified.root(), organisation.link(1));
    assert_eq!(verified.anchor(), organisation.link(2));
    host.enrol(verified).expect("the host enrols");
    let enrolment = host
        .enrolment(organisation.organisation_id)
        .expect("enrolled");
    assert_eq!(enrolment.anchor(), organisation.link(2));
    assert_eq!(enrolment.accepted_head(), PolicyKeyRevision::new(2));
    assert_eq!(
        enrolment.links(),
        std::slice::from_ref(organisation.link(2)),
        "the chain authenticates forward from the anchor, not backward"
    );
    assert_eq!(enrolment.enrolment_revision(), AuthorityRevision::new(1));
    assert_eq!(
        host.verify_enrolment(&authority, at.as_ref()),
        Err(ChainRefused::AlreadyEnrolled),
        "an enrolment is replaced only by withdrawing it first"
    );
}

/// A rotation is followed only through links the anchor's key signed. A forged successor and a
/// chain without the anchor change nothing; the genuine rotation moves the anchor and drops an
/// installed lease its signing revision issued after it was succeeded; the same head again does no
/// signature work; an older head is stale, and the lease beside it is still judged.
#[test]
fn rotation_is_followed_only_through_links_the_anchor_signed() {
    let mut host = policy();
    let mut organisation = enrolled(&mut host);
    let organisation_id = organisation.organisation_id;
    let clock = ManualClock::new();
    let (ada, phone) = (member("ada"), device());

    // Revision 3 takes over a minute after T. Before this host hears of it, it installs a lease
    // revision 2 issued after that: only a key that outlived its rotation could have signed it.
    organisation.rotate(T + MINUTE_MS);
    let late = organisation.lease(2, &ada, *phone.public(), T + 90_000, VIEW);
    host.install_lease(presented(&late, phone.public(), T + 90_000, clock.now(), 1))
        .expect("nothing this host knows shows revision 2 was succeeded");
    let at = T + 2 * MINUTE_MS;
    let anchor = |host: &HostPolicy| {
        host.enrolment(organisation_id)
            .expect("enrolled")
            .anchor()
            .clone()
    };

    let mut forged = organisation.authority(at);
    forged.chain[2].signature = sign(
        organisation.key(3),
        POLICY_AUTHORITY_DOMAIN,
        forged.chain[2].payload.signing_input(),
    );
    assert_eq!(
        host.accept_chain(&forged, Some(&reading(at))),
        Err(ChainRefused::LinkSignature {
            revision: PolicyKeyRevision::new(3)
        })
    );
    assert_eq!(
        anchor(&host),
        *organisation.link(2),
        "the anchor has not moved"
    );

    // Another history under the same organisation's name, which does not carry this host's anchor.
    let mut fork = Organisation::new(0x21, T - 2 * DAY_MS);
    fork.rotate(T - DAY_MS);
    fork.rotate(T + MINUTE_MS);
    assert_eq!(
        host.accept_chain(&fork.authority(at), Some(&reading(at))),
        Err(ChainRefused::AnchorMissing)
    );
    assert_eq!(
        anchor(&host),
        *organisation.link(2),
        "the anchor has not moved"
    );

    // The control: the genuine rotation ratchets, and the late lease goes with it.
    assert_eq!(
        host.accept_chain(&organisation.authority(at), Some(&reading(at))),
        Ok(ChainOutcome::Advanced {
            to: PolicyKeyRevision::new(3),
            dropped: vec![(ada.clone(), *phone.public())],
        })
    );
    let enrolment = host.enrolment(organisation_id).expect("enrolled");
    assert_eq!(enrolment.anchor(), organisation.link(3));
    assert_eq!(
        enrolment.links(),
        &[organisation.link(2).clone(), organisation.link(3).clone()],
        "revision 2 may still have signed a live lease before it was succeeded"
    );
    assert_eq!(
        host.lease_in_force(organisation_id, &ada, phone.public(), clock.now(), at),
        Err(MembershipRefusal::NoLease)
    );

    let mut same = organisation.authority(at);
    same.head.signature = Signature64::from_bytes([0; 64]);
    assert_eq!(
        host.accept_chain(&same, Some(&reading(at))),
        Ok(ChainOutcome::Unchanged),
        "the head this host already accepted is not read again"
    );

    assert_eq!(
        host.accept_chain(&organisation.authority_at(2, T), Some(&reading(at))),
        Ok(ChainOutcome::Stale {
            held: PolicyKeyRevision::new(3)
        })
    );
    let current = organisation.lease(3, &ada, *phone.public(), at, VIEW);
    host.install_lease(presented(&current, phone.public(), at, clock.now(), 1))
        .expect("the lease beside a stale chain is judged against the host's own links");
}

/// Section 24: the anchor and the lease records survive a restart, and no lease is installed. The
/// lease the host held is refused afterwards as one installed in an earlier run.
#[test]
fn the_anchor_and_lease_records_survive_a_restart_and_no_lease_is_installed() {
    let directory = tempfile::TempDir::new().expect("a directory on the internal disk");
    let path = directory.path().join("registry.db");
    let store = GrantDirectory::open(&path).expect("the store opens");
    let mut host = policy();
    let organisation = enrolled(&mut host);
    let organisation_id = organisation.organisation_id;
    let clock = ManualClock::new();
    let (ada, phone) = (member("ada"), device());
    let lease = organisation.lease(2, &ada, *phone.public(), T, VIEW);
    host.install_lease(presented(&lease, phone.public(), T, clock.now(), 1))
        .expect("installed");
    // The control: before the restart the lease answers.
    host.lease_in_force(organisation_id, &ada, phone.public(), clock.now(), T)
        .expect("in force before the restart");
    store
        .store_policy(&host.snapshot())
        .expect("the policy is written down");
    drop(store);

    let stored = GrantDirectory::open(&path)
        .expect("the store opens again")
        .stored_policy()
        .expect("readable")
        .expect("present");
    let mut restored = HostPolicy::restore(
        &stored,
        AuthorityRevision::new(1),
        Arc::new(UtcFloor::at(stored.utc_floor_ms.get())),
    );
    let enrolment = restored
        .enrolment(organisation_id)
        .expect("the enrolment survives");
    assert_eq!(enrolment.root(), organisation.link(1));
    assert_eq!(enrolment.anchor(), organisation.link(2));
    assert_eq!(enrolment.accepted_head(), PolicyKeyRevision::new(2));
    let record = *restored
        .lease_record(organisation_id, &ada, phone.public())
        .expect("the record survives");
    assert_eq!(record.issued_at_ms, T);
    assert_eq!(record.installed_in, generation(1));
    assert_eq!(
        restored.lease_in_force(organisation_id, &ada, phone.public(), clock.now(), T),
        Err(MembershipRefusal::NoLease),
        "no lease is installed after a restart"
    );
    assert_eq!(
        restored.install_lease(presented(
            &lease,
            phone.public(),
            T + MINUTE_MS,
            clock.now(),
            2
        )),
        Err(LeaseRefused::InstalledEarlier)
    );
}

/// Section 25: a chain longer than any fixed cap is followed from the anchor, and only the links
/// after the anchor are verified. A forged link after the anchor is refused.
#[test]
fn a_chain_longer_than_any_fixed_cap_is_followed_from_the_anchor() {
    let start = T - 200 * MINUTE_MS;
    let activation = |revision: u64| start + (revision - 1) * MINUTE_MS;
    let mut organisation = Organisation::new(0x31, start);
    for revision in 2..=98 {
        organisation.rotate(activation(revision));
    }
    let mut host = policy();
    organisation.enrol(&mut host, activation(98) + 30_000);
    organisation.rotate(activation(99));
    organisation.rotate(activation(100));
    let at = activation(100) + 30_000;
    let anchor = |host: &HostPolicy| {
        host.enrolment(organisation.organisation_id)
            .expect("enrolled")
            .anchor()
            .payload
            .key_revision
    };

    let mut forged = organisation.authority(at);
    forged.chain[99].signature = sign(
        organisation.key(100),
        POLICY_AUTHORITY_DOMAIN,
        forged.chain[99].payload.signing_input(),
    );
    assert_eq!(
        host.accept_chain(&forged, Some(&reading(at))),
        Err(ChainRefused::LinkSignature {
            revision: PolicyKeyRevision::new(100)
        })
    );
    assert_eq!(anchor(&host), PolicyKeyRevision::new(98));

    assert_eq!(
        host.accept_chain(&organisation.authority(at), Some(&reading(at))),
        Ok(ChainOutcome::Advanced {
            to: PolicyKeyRevision::new(100),
            dropped: Vec::new(),
        })
    );
    assert_eq!(anchor(&host), PolicyKeyRevision::new(100));
}

// ---------------------------------------------------------------------------------------------
// Verifying a lease before it is stored (section 4)
// ---------------------------------------------------------------------------------------------

/// An organisation whose second revision takes over at `T`, enrolled a minute later.
fn rotated_at_t(host: &mut HostPolicy) -> Organisation {
    let mut organisation = Organisation::new(0x41, T - DAY_MS);
    organisation.rotate(T);
    organisation.enrol(host, T + MINUTE_MS);
    organisation
}

/// A lease issued before its signing revision took over is refused.
#[test]
fn a_lease_issued_before_its_revision_took_over_is_refused() {
    let mut host = policy();
    let organisation = rotated_at_t(&mut host);
    let clock = ManualClock::new();
    let (ada, phone) = (member("ada"), device());
    let early = organisation.lease(2, &ada, *phone.public(), T - 30_000, VIEW);
    assert_eq!(
        host.install_lease(presented(
            &early,
            phone.public(),
            T + MINUTE_MS,
            clock.now(),
            1
        )),
        Err(LeaseRefused::IssuedBeforeActivation)
    );
    // The control: the same revision's lease issued after it took over installs.
    let lease = organisation.lease(2, &ada, *phone.public(), T + 30_000, VIEW);
    host.install_lease(presented(
        &lease,
        phone.public(),
        T + MINUTE_MS,
        clock.now(),
        1,
    ))
    .expect("issued while its revision was signing");
}

/// A lease by a revision before the enrolment anchor is refused: the chain authenticates forward.
#[test]
fn a_lease_by_a_revision_before_the_enrolment_anchor_is_refused() {
    let mut host = policy();
    let organisation = rotated_at_t(&mut host);
    let clock = ManualClock::new();
    let (ada, phone) = (member("ada"), device());
    let before_anchor = organisation.lease(1, &ada, *phone.public(), T - MINUTE_MS, VIEW);
    assert_eq!(
        host.install_lease(presented(
            &before_anchor,
            phone.public(),
            T + MINUTE_MS,
            clock.now(),
            1
        )),
        Err(LeaseRefused::UnauthenticatedRevision),
        "revision 1 signed it while it was signing, but nothing this host holds authenticates it"
    );
    // The control: the anchor's own lease installs.
    let lease = organisation.lease(2, &ada, *phone.public(), T + 30_000, VIEW);
    host.install_lease(presented(
        &lease,
        phone.public(),
        T + MINUTE_MS,
        clock.now(),
        1,
    ))
    .expect("signed by the anchor");
}

/// A lease issued after its signing revision was succeeded is refused; one that revision issued
/// before the rotation, still live, installs.
#[test]
fn a_lease_issued_after_its_revisions_successor_took_over_is_refused() {
    let mut host = policy();
    let mut organisation = rotated_at_t(&mut host);
    organisation.rotate(T + 2 * MINUTE_MS);
    let at = T + 3 * MINUTE_MS;
    host.accept_chain(&organisation.authority(at), Some(&reading(at)))
        .expect("the rotation is accepted");
    let clock = ManualClock::new();
    let (ada, phone) = (member("ada"), device());
    let after = organisation.lease(2, &ada, *phone.public(), T + 150_000, VIEW);
    assert_eq!(
        host.install_lease(presented(&after, phone.public(), at, clock.now(), 1)),
        Err(LeaseRefused::SignedAfterSuccessor)
    );
    // The control: revision 2's lease from before the rotation is still live and installs.
    let before = organisation.lease(2, &ada, *phone.public(), T + 90_000, VIEW);
    host.install_lease(presented(&before, phone.public(), at, clock.now(), 1))
        .expect("issued while revision 2 was the signing revision");
}

/// Of two leases for one member's device, the older never replaces the newer, and a second lease
/// with the same issue time is refused as ambiguous rather than guessed at.
#[test]
fn an_older_or_ambiguous_lease_never_replaces_the_newest() {
    let mut host = policy();
    let organisation = enrolled(&mut host);
    let clock = ManualClock::new();
    let (ada, phone) = (member("ada"), device());
    let newest = organisation.lease(2, &ada, *phone.public(), T, VIEW);
    host.install_lease(presented(&newest, phone.public(), T, clock.now(), 1))
        .expect("installed");

    let older = organisation.lease(2, &ada, *phone.public(), T - MINUTE_MS, VIEW);
    assert_eq!(
        host.install_lease(presented(&older, phone.public(), T, clock.now(), 1)),
        Err(LeaseRefused::Superseded)
    );
    let twin = organisation.lease(
        2,
        &ada,
        *phone.public(),
        T,
        &[ActionRight::SessionView, ActionRight::FilesRead],
    );
    assert_eq!(
        host.install_lease(presented(&twin, phone.public(), T, clock.now(), 1)),
        Err(LeaseRefused::AmbiguousIssue)
    );
    let record = host
        .lease_record(organisation.organisation_id, &ada, phone.public())
        .expect("recorded");
    assert_eq!(record.issued_at_ms, T, "the newest stays recorded");

    // The control: a newer lease replaces it.
    let next = organisation.lease(2, &ada, *phone.public(), T + MINUTE_MS, VIEW);
    let installed = host
        .install_lease(presented(
            &next,
            phone.public(),
            T + MINUTE_MS,
            clock.now(),
            1,
        ))
        .expect("a newer lease replaces the newest");
    assert_eq!(installed.change, LeaseChange::Installed { narrowed: false });
}

/// A lease is taken only from the connection that proves the key it names, so a host that
/// receives a member's lease for one device cannot present it for another.
#[test]
fn a_lease_naming_another_devices_key_is_refused_on_this_connection() {
    let mut host = policy();
    let organisation = enrolled(&mut host);
    let clock = ManualClock::new();
    let (ada, phone, relay) = (member("ada"), device(), device());
    let for_phone = organisation.lease(2, &ada, *phone.public(), T, VIEW);
    assert_eq!(
        host.install_lease(presented(&for_phone, relay.public(), T, clock.now(), 1)),
        Err(LeaseRefused::DeviceMismatch)
    );
    assert!(
        host.lease_record(organisation.organisation_id, &ada, phone.public())
            .is_none(),
        "nothing is recorded"
    );
    // The control: the same account's lease naming the presenting device's own key installs.
    let for_relay = organisation.lease(2, &ada, *relay.public(), T, VIEW);
    host.install_lease(presented(&for_relay, relay.public(), T, clock.now(), 1))
        .expect("the lease names the key this connection proved");
}

/// Each device of a member holds its own lease: one device's refresh neither supersedes the
/// other's nor answers for it.
#[test]
fn each_device_of_a_member_holds_its_own_lease() {
    let mut host = policy();
    let organisation = enrolled(&mut host);
    let organisation_id = organisation.organisation_id;
    let clock = ManualClock::new();
    let (ada, phone, laptop) = (member("ada"), device(), device());
    let phone_lease = organisation.lease(2, &ada, *phone.public(), T, VIEW);
    host.install_lease(presented(&phone_lease, phone.public(), T, clock.now(), 1))
        .expect("the phone's lease");
    let laptop_lease = organisation.lease(2, &ada, *laptop.public(), T + MINUTE_MS, VIEW);
    host.install_lease(presented(
        &laptop_lease,
        laptop.public(),
        T + MINUTE_MS,
        clock.now(),
        1,
    ))
    .expect("the laptop's own lease is not superseded by the phone's");
    let refresh = organisation.lease(2, &ada, *phone.public(), T + 2 * MINUTE_MS, VIEW);
    host.install_lease(presented(
        &refresh,
        phone.public(),
        T + 2 * MINUTE_MS,
        clock.now(),
        1,
    ))
    .expect("the phone's refresh");
    assert_eq!(
        host.lease_record(organisation_id, &ada, laptop.public())
            .expect("the laptop's record")
            .issued_at_ms,
        T + MINUTE_MS,
        "the phone's refresh does not touch the laptop's record"
    );

    // The control: each device's own lease answers for it.
    let at = T + 2 * MINUTE_MS;
    assert_eq!(
        host.lease_in_force(organisation_id, &ada, phone.public(), clock.now(), at),
        Ok(&refresh)
    );
    assert_eq!(
        host.lease_in_force(organisation_id, &ada, laptop.public(), clock.now(), at),
        Ok(&laptop_lease)
    );
    // And the laptop's lease does not answer for the phone: ten minutes on the laptop renews,
    // and once the phone's lease has run out the phone is refused while the laptop is not.
    clock.advance(Duration::from_millis(10 * MINUTE_MS));
    let renewed_at = T + 12 * MINUTE_MS;
    let laptop_renewal = organisation.lease(2, &ada, *laptop.public(), renewed_at, VIEW);
    host.install_lease(presented(
        &laptop_renewal,
        laptop.public(),
        renewed_at,
        clock.now(),
        1,
    ))
    .expect("the laptop renews");
    clock.advance(Duration::from_millis(6 * MINUTE_MS));
    let late = T + 16 * MINUTE_MS;
    assert_eq!(
        host.lease_in_force(organisation_id, &ada, phone.public(), clock.now(), late),
        Err(MembershipRefusal::LeaseExpired)
    );
    assert_eq!(
        host.lease_in_force(organisation_id, &ada, laptop.public(), clock.now(), late),
        Ok(&laptop_renewal)
    );
}

/// A wall clock wound back does not lengthen a lease: its continuous deadline, fixed when it was
/// installed, ends it while UTC still reads inside it.
#[test]
fn a_wall_clock_wound_back_does_not_lengthen_a_lease() {
    let mut host = policy();
    let organisation = enrolled(&mut host);
    let organisation_id = organisation.organisation_id;
    let clock = ManualClock::new();
    let (ada, phone) = (member("ada"), device());
    let lease = organisation.lease(2, &ada, *phone.public(), T, VIEW);
    let installed = host
        .install_lease(presented(&lease, phone.public(), T, clock.now(), 1))
        .expect("installed");
    assert_eq!(
        installed.continuous_deadline,
        clock
            .now()
            .checked_add(Duration::from_millis(LEASE_MS - 5_000))
            .expect("a deadline"),
        "fifteen minutes less the five-second margin"
    );

    // The wall clock is wound back a minute; this host reads UTC through its floor, which the
    // installation raised to T, so UTC stays inside the lease throughout.
    let wound_back = T - MINUTE_MS;
    let settled = host.settled_now(wound_back);
    assert_eq!(settled, T);

    // The control: before the continuous deadline it answers.
    clock.advance(Duration::from_millis(LEASE_MS - 10_000));
    host.lease_in_force(organisation_id, &ada, phone.public(), clock.now(), settled)
        .expect("inside both deadlines");

    // Past it, the lease has ended however far back the wall clock reads.
    clock.advance(Duration::from_millis(5_000));
    assert_eq!(
        host.lease_in_force(organisation_id, &ada, phone.public(), clock.now(), settled),
        Err(MembershipRefusal::LeaseExpired)
    );
    assert_eq!(
        host.install_lease(presented(
            &lease,
            phone.public(),
            wound_back,
            clock.now(),
            1
        )),
        Err(LeaseRefused::Expired),
        "presented again, it is refused as ended"
    );
}

/// A lease the host's clock places more than five seconds in the future is refused; one four
/// seconds ahead installs, ending on the continuous clock fifteen minutes less the margin later.
/// Once installed it is in force at once, and answered as a repeat at once, although this host's
/// clock has not reached its issue time; it ends at its continuous deadline, or at its signed
/// expiry on UTC, whichever comes first.
#[test]
fn a_lease_from_the_hosts_future_is_refused_beyond_five_seconds() {
    let mut host = policy();
    let organisation = enrolled(&mut host);
    let organisation_id = organisation.organisation_id;
    let clock = ManualClock::new();
    let (ada, phone) = (member("ada"), device());
    let ahead = organisation.lease(2, &ada, *phone.public(), T + 6_000, VIEW);
    assert_eq!(
        host.install_lease(presented(&ahead, phone.public(), T, clock.now(), 1)),
        Err(LeaseRefused::NotYetValid)
    );
    let near = organisation.lease(2, &ada, *phone.public(), T + 4_000, VIEW);
    let installed = host
        .install_lease(presented(&near, phone.public(), T, clock.now(), 1))
        .expect("inside the five seconds");
    assert_eq!(
        installed.continuous_deadline,
        clock
            .now()
            .checked_add(Duration::from_millis(LEASE_MS - 5_000))
            .expect("a deadline")
    );

    // In force at once, before this host's clock reaches the issue time.
    assert_eq!(
        host.lease_in_force(organisation_id, &ada, phone.public(), clock.now(), T),
        Ok(&near)
    );
    let repeat = host
        .install_lease(presented(&near, phone.public(), T, clock.now(), 1))
        .expect("presented again at once, it is answered from its installation");
    assert_eq!(repeat.change, LeaseChange::Repeat);

    // It ends at its continuous deadline...
    clock.advance(Duration::from_millis(LEASE_MS - 5_000));
    assert_eq!(
        host.lease_in_force(
            organisation_id,
            &ada,
            phone.public(),
            clock.now(),
            T + 60_000
        ),
        Err(MembershipRefusal::LeaseExpired)
    );
    // ...or at its signed expiry on UTC, if that comes first.
    let mut other = policy();
    organisation.enrol(&mut other, T);
    let early_clock = ManualClock::new();
    other
        .install_lease(presented(&near, phone.public(), T, early_clock.now(), 1))
        .expect("installed on another host");
    let expiry = near.payload.expires_at_ms.get();
    assert_eq!(
        other.lease_in_force(
            organisation.organisation_id,
            &ada,
            phone.public(),
            early_clock.now(),
            expiry
        ),
        Err(MembershipRefusal::LeaseExpired)
    );
    other
        .lease_in_force(
            organisation.organisation_id,
            &ada,
            phone.public(),
            early_clock.now(),
            expiry - 1,
        )
        .expect("the control: a millisecond before its signed expiry it is in force");
}

/// Nothing that reads the clock is decided while the floor it would stand on is owed its record:
/// not an enrolment, not a rotation, not a lease. Once the record lands, each is decided.
#[test]
fn nothing_that_reads_the_clock_is_decided_while_the_floor_is_owed_its_record() {
    let mut organisation = Organisation::new(0x61, T - 2 * DAY_MS);
    organisation.rotate(T - DAY_MS);
    let mut host = policy();
    // A decision stood on the floor at T, and its record has not landed.
    host.utc_floor().owe(T);
    let authority = organisation.authority(T);
    assert_eq!(
        host.verify_enrolment(&authority, Some(&reading(T))),
        Err(ChainRefused::FloorUnrecorded)
    );
    host.utc_floor().wrote(T);
    organisation.enrol(&mut host, T);

    organisation.rotate(T + MINUTE_MS);
    let at = T + 2 * MINUTE_MS;
    host.utc_floor().owe(at);
    assert_eq!(
        host.accept_chain(&organisation.authority(at), Some(&reading(at))),
        Err(ChainRefused::FloorUnrecorded)
    );
    let clock = ManualClock::new();
    let (ada, phone) = (member("ada"), device());
    let lease = organisation.lease(2, &ada, *phone.public(), T + 30_000, VIEW);
    assert_eq!(
        host.install_lease(presented(&lease, phone.public(), at, clock.now(), 1)),
        Err(LeaseRefused::FloorUnrecorded)
    );
    assert!(
        host.lease_record(organisation.organisation_id, &ada, phone.public())
            .is_none(),
        "nothing is recorded while the floor is owed"
    );

    // The control: once the record lands, both are decided.
    host.utc_floor().wrote(at);
    assert_eq!(
        host.accept_chain(&organisation.authority(at), Some(&reading(at))),
        Ok(ChainOutcome::Advanced {
            to: PolicyKeyRevision::new(3),
            dropped: Vec::new(),
        })
    );
    host.install_lease(presented(&lease, phone.public(), at, clock.now(), 1))
        .expect("revision 2 signed it before it was succeeded");
}

/// A lease record is let go of only in a write whose floor is past its issue time plus the longest
/// lease: every lease it could stand for has expired by then, and stays refused afterwards.
#[test]
fn a_record_is_let_go_only_once_the_floor_shows_its_leases_expired() {
    let mut host = policy();
    let organisation = enrolled(&mut host);
    let organisation_id = organisation.organisation_id;
    let clock = ManualClock::new();
    let (ada, phone) = (member("ada"), device());
    let lease = organisation.lease(2, &ada, *phone.public(), T, VIEW);
    host.install_lease(presented(&lease, phone.public(), T, clock.now(), 1))
        .expect("installed");

    // The control: with the floor at the last moment a lease it names could be live, the record
    // is written down.
    host.observe_utc(T + LEASE_MS);
    assert_eq!(host.snapshot().lease_records.len(), 1);

    host.observe_utc(T + LEASE_MS + 1);
    let snapshot = host.snapshot();
    assert!(
        snapshot.lease_records.is_empty(),
        "a floor past the lease's life lets the record go"
    );
    assert_eq!(snapshot.utc_floor_ms, TimestampMs::new(T + LEASE_MS + 1));

    // Restored without the record, the lease is still refused: the floor written beside the
    // pruning has passed its expiry, whatever the wall clock reads.
    let mut restored = HostPolicy::restore(
        &snapshot,
        AuthorityRevision::new(1),
        Arc::new(UtcFloor::at(snapshot.utc_floor_ms.get())),
    );
    assert_eq!(
        restored.install_lease(presented(
            &lease,
            phone.public(),
            T + MINUTE_MS,
            clock.now(),
            2
        )),
        Err(LeaseRefused::Expired)
    );
    assert!(
        restored
            .lease_record(organisation_id, &ada, phone.public())
            .is_none()
    );
}

/// A link older than the anchor is let go of only once its successor has been signing for longer
/// than any lease it signed can last, with the clock margin.
#[test]
fn a_link_is_let_go_only_once_no_lease_it_signed_can_be_live() {
    let mut host = policy();
    let mut organisation = enrolled(&mut host);
    let organisation_id = organisation.organisation_id;
    organisation.rotate(T + MINUTE_MS);
    let first = T + 2 * MINUTE_MS;
    host.accept_chain(&organisation.authority(first), Some(&reading(first)))
        .expect("revision 3 is accepted");
    organisation.rotate(T + 20 * MINUTE_MS);
    let links = |host: &HostPolicy| {
        host.enrolment(organisation_id)
            .expect("enrolled")
            .links()
            .iter()
            .map(|link| link.payload.key_revision.get())
            .collect::<Vec<_>>()
    };
    // The control: two minutes after revision 3 took over, revision 2 is still kept.
    assert_eq!(links(&host), vec![2, 3]);

    // Revision 3 has signed for nineteen minutes when revision 4 is accepted: revision 2 can have
    // signed no lease that is still live, and is let go of; revision 3 is kept.
    let later = T + 20 * MINUTE_MS + 30_000;
    host.accept_chain(&organisation.authority(later), Some(&reading(later)))
        .expect("revision 4 is accepted");
    assert_eq!(links(&host), vec![3, 4]);
}

/// Rule A: a lease digest is installed at most once on a host. A repeat in the run that installed
/// it is answered from that installation; once it has ended, and after a withdrawal and a new
/// enrolment, it is refused. A newer lease installs each time.
#[test]
fn a_lease_digest_is_installed_at_most_once() {
    let mut host = policy();
    let organisation = enrolled(&mut host);
    let organisation_id = organisation.organisation_id;
    let clock = ManualClock::new();
    let (ada, phone) = (member("ada"), device());
    let lease = organisation.lease(2, &ada, *phone.public(), T, VIEW);
    let first = host
        .install_lease(presented(&lease, phone.public(), T, clock.now(), 1))
        .expect("installed");
    let record = *host
        .lease_record(organisation_id, &ada, phone.public())
        .expect("recorded");

    // (a) A repeat in the installing run: answered from the installation, nothing recorded anew,
    // and the same deadline.
    clock.advance(Duration::from_millis(MINUTE_MS));
    let repeat = host
        .install_lease(presented(
            &lease,
            phone.public(),
            T + MINUTE_MS,
            clock.now(),
            1,
        ))
        .expect("answered from its installation");
    assert_eq!(repeat.change, LeaseChange::Repeat);
    assert_eq!(repeat.continuous_deadline, first.continuous_deadline);
    assert_eq!(
        host.lease_record(organisation_id, &ada, phone.public()),
        Some(&record)
    );

    // (b) Once it has ended it is refused, while its signed window still has time on UTC.
    clock.advance(Duration::from_millis(LEASE_MS));
    assert_eq!(
        host.install_lease(presented(
            &lease,
            phone.public(),
            T + 2 * MINUTE_MS,
            clock.now(),
            1
        )),
        Err(LeaseRefused::Expired)
    );
    let second = organisation.lease(2, &ada, *phone.public(), T + 2 * MINUTE_MS, VIEW);
    host.install_lease(presented(
        &second,
        phone.public(),
        T + 2 * MINUTE_MS,
        clock.now(),
        1,
    ))
    .expect("the control: a newer lease installs");

    // (d) A withdrawal ends it and keeps its record; after a new enrolment it is refused.
    assert!(host.withdraw(organisation_id));
    organisation.enrol(&mut host, T + 3 * MINUTE_MS);
    assert_eq!(
        host.install_lease(presented(
            &second,
            phone.public(),
            T + 3 * MINUTE_MS,
            clock.now(),
            1
        )),
        Err(LeaseRefused::Expired),
        "a lease installed before the withdrawal is an ended one"
    );
    let third = organisation.lease(2, &ada, *phone.public(), T + 3 * MINUTE_MS, VIEW);
    host.install_lease(presented(
        &third,
        phone.public(),
        T + 3 * MINUTE_MS,
        clock.now(),
        1,
    ))
    .expect("the control: a newer lease installs under the new enrolment");
}

// ---------------------------------------------------------------------------------------------
// The stored policy's upgrade, through a daemon start (section 24: no restored old policy revives
// authority)
// ---------------------------------------------------------------------------------------------

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

async fn start_daemon(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: EnvironmentId,
) -> Arc<Controller> {
    start_daemon_on(
        environment,
        environment_id,
        kr_controller::service::Clocks::system(),
    )
    .await
}

/// Starts a daemon on the clocks the test gives it.
async fn start_daemon_on(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: EnvironmentId,
    clocks: kr_controller::service::Clocks,
) -> Arc<Controller> {
    let secrets = environment.secrets_dir();
    Controller::start_on_clocks(
        ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store =
                    open_store_in(&secrets).expect("a secret store for the test environment");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(RefusingSupervisor),
            worker_program: PathBuf::from("/nonexistent/kr-worker"),
            build_id: BuildId::new("kr-test/0").expect("a build identifier"),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        },
        clocks,
    )
    .await
    .unwrap_or_else(|error| panic!("the daemon starts: {error}"))
}

/// The stored policy in the shape earlier builds wrote: two floors, the host's restrictions and
/// enrolments of two numbers each, and no lease records.
#[derive(serde::Serialize)]
struct EarlierPolicy {
    accepted_floor: AuthorityRevision,
    utc_floor_ms: TimestampMs,
    exclusively_managed: bool,
    offline: Nullable<OfflineValidityPolicy>,
    enrolments: Vec<EarlierEnrolment>,
}

#[derive(serde::Serialize)]
struct EarlierEnrolment {
    organisation_id: OrganisationId,
    pinned_key_revision: PolicyKeyRevision,
    pinned_policy_revision: AuthorityRevision,
}

/// A grant held by another device, expiring at `expires_at_ms`.
fn stored_grant(byte: u8, expires_at_ms: u64) -> GrantRecord {
    GrantRecord {
        grant: Grant {
            grant_id: GrantId::new(Uuid::from_bytes([byte; 16])),
            parent_grant_id: Nullable::null(),
            issuer_device_id: DeviceId::new(Uuid::from_bytes([0xf0; 16])),
            recipient_device_id: DeviceId::new(Uuid::from_bytes([0xf1; 16])),
            authority_revision: AuthorityRevision::new(1),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: [ActionRight::ChangesetCreate].into_iter().collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: false,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry: GrantExpiry::At {
                expires_at_ms: TimestampMs::new(expires_at_ms),
            },
            organisation: Nullable::null(),
        },
        session_id: None,
        issued_at_ms: 1_000,
        activated_at_ms: Some(1_000),
        revoked_at_ms: None,
        revoked_by_parent: None,
    }
}

/// KR-REQ-24.15: a daemon started on a policy row an earlier build wrote upgrades it and keeps its
/// clock floor, so a grant whose expiry lies between the wall clock and that floor stays refused.
/// The control: a grant expiring after the floor is permitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_existing_policy_row_is_upgraded_once_and_keeps_its_floors() {
    use kr_automation::AuthoritySource as _;
    use kr_controller::automation::HostGrants;

    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    environment.create().expect("the environment's directories");
    let now_ms = kr_ipc::now_ms().get();
    let floor_ms = now_ms + 60 * MINUTE_MS;
    let earlier = kr_cbor::to_canonical_vec(&EarlierPolicy {
        accepted_floor: AuthorityRevision::new(1),
        utc_floor_ms: TimestampMs::new(floor_ms),
        exclusively_managed: false,
        offline: Nullable::null(),
        enrolments: vec![EarlierEnrolment {
            organisation_id: OrganisationId::new(Uuid::from_bytes([0x21; 16])),
            pinned_key_revision: PolicyKeyRevision::new(4),
            pinned_policy_revision: AuthorityRevision::new(1),
        }],
    })
    .expect("the earlier shape encodes");
    drop(GrantDirectory::open(environment.registry_database()).expect("the store is created"));
    rusqlite::Connection::open(environment.registry_database())
        .expect("the registry opens")
        .execute(
            "INSERT OR REPLACE INTO host_authority (key, value) VALUES ('policy', ?1)",
            rusqlite::params![earlier],
        )
        .expect("the earlier row is written");

    let controller = start_daemon(&environment, environment_id).await;
    let floor = controller
        .update_policy(|policy| policy.utc_floor_ms())
        .expect("the policy is written down");
    assert!(floor >= floor_ms, "the floor survives the upgrade");
    let between = stored_grant(0x51, now_ms + 30 * MINUTE_MS);
    let after = stored_grant(0x52, floor_ms + 60 * MINUTE_MS);
    for record in [&between, &after] {
        controller
            .sharing()
            .grants()
            .issue(record, || Ok(()))
            .expect("the grant is written");
    }
    let grants = HostGrants::for_daemon(&controller);
    let refused = grants
        .grant(between.grant.grant_id, kr_ipc::now_ms().get())
        .expect_err("a grant the floor has already passed stays expired");
    assert!(
        refused.to_string().contains("expired"),
        "refused as expired: {refused}"
    );
    grants
        .grant(after.grant.grant_id, kr_ipc::now_ms().get())
        .expect("the control: a grant expiring after the floor is permitted");
}

// ---------------------------------------------------------------------------------------------
// The member behind a grant: bindings (section 5)
// ---------------------------------------------------------------------------------------------

/// A pairing record for the device holding `key`, whose grant requires `requirement`'s
/// organisation at its enrolment revision when there is one.
fn member_device(
    byte: u8,
    key: AuthorisationKey,
    requirement: Option<(OrganisationId, AuthorityRevision)>,
) -> DeviceRecord {
    let device_id = DeviceId::new(Uuid::from_bytes([byte; 16]));
    DeviceRecord {
        device_id,
        endpoint_id: EndpointKey::from_bytes([byte; 32]),
        device_key_revision: DeviceKeyRevision::new(1),
        authorisation: key,
        stored_envelope: None,
        notification_preview: None,
        device_name: DeviceName::new("A phone").expect("a name"),
        platform: DevicePlatform::Ios,
        grant: Grant {
            grant_id: GrantId::new(Uuid::from_bytes([byte; 16])),
            parent_grant_id: Nullable::null(),
            issuer_device_id: DeviceId::new(Uuid::from_bytes([0xf0; 16])),
            recipient_device_id: device_id,
            authority_revision: AuthorityRevision::new(1),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: VIEW.iter().copied().collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: false,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry: GrantExpiry::Never,
            organisation: Nullable(requirement.map(|(organisation_id, policy_revision)| {
                OrganisationRequirement {
                    organisation_id,
                    policy_revision,
                }
            })),
        },
        paired_at_ms: TimestampMs::new(1_000),
        revoked_at_ms: None,
        expired_at_ms: None,
        committed_invitation_id: None,
    }
}

/// A daemon enrolled, at the wall clock now, in an organisation named by `byte`. Returns the
/// organisation, the enrolment revision and the moment it enrolled.
async fn enrolled_daemon(
    temp: &kr_ipc::testing::TempHost,
    byte: u8,
) -> (Arc<Controller>, Organisation, AuthorityRevision, u64) {
    let controller = start_daemon(&temp.environment(), temp.environment_id()).await;
    let now = kr_ipc::now_ms().get();
    let mut organisation = Organisation::new(byte, now - 2 * DAY_MS);
    organisation.rotate(now - DAY_MS);
    let revision = controller.policy().authority_revision();
    controller
        .update_policy(|policy| organisation.enrol(policy, now))
        .expect("the enrolment is written down");
    (controller, organisation, revision, now)
}

/// The binding `device_id` holds in `organisation_id`, as the daemon's policy stands.
fn binding_of(
    controller: &Controller,
    organisation_id: OrganisationId,
    device_id: DeviceId,
) -> Option<kr_controller::grants::organisation::Binding> {
    controller
        .policy()
        .enrolment(organisation_id)
        .and_then(|enrolment| enrolment.binding(device_id).cloned())
}

/// KR-REQ-17.53 (the member behind a grant): the first verified lease a device presents binds it
/// to that lease's account and key, durably and with a retained event; a later lease for another
/// account on that device is refused. The control: the same member's next lease installs and binds
/// nothing new.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_is_bound_to_the_account_and_key_of_its_first_verified_lease_and_no_other() {
    let temp = kr_ipc::testing::TempHost::create();
    let (controller, organisation, revision, now) = enrolled_daemon(&temp, 0x31).await;
    let organisation_id = organisation.organisation_id;
    let phone = device();
    let paired = member_device(0x41, *phone.public(), Some((organisation_id, revision)));
    controller.devices().commit(&paired).expect("paired");
    let (ada, bea) = (member("ada"), member("bea"));

    let first = organisation.lease(2, &ada, *phone.public(), now, VIEW);
    let installed = controller
        .present_membership_lease(paired.device_id, phone.public(), &first)
        .expect("storage")
        .expect("the first verified lease installs");
    assert!(installed.bound, "and binds the device");
    let binding = binding_of(&controller, organisation_id, paired.device_id).expect("bound");
    assert_eq!(
        (&binding.account_id, &binding.device_key),
        (&ada, phone.public())
    );
    let stored = controller
        .sharing()
        .grants()
        .stored_policy()
        .expect("readable")
        .expect("written");
    assert_eq!(
        stored.enrolments[0].members.len(),
        1,
        "the binding is in the stored enrolment"
    );
    assert_eq!(
        controller
            .sharing()
            .grants()
            .organisation_events()
            .expect("readable"),
        vec![BindingEvent {
            organisation_id,
            device_id: paired.device_id,
            account_id: ada.clone(),
            device_key: *phone.public(),
            lease_digest: binding.lease_digest,
            bound_at_ms: binding.bound_at_ms,
        }],
        "and its event is retained"
    );

    let another = organisation.lease(2, &bea, *phone.public(), now + 1_000, VIEW);
    assert_eq!(
        controller
            .present_membership_lease(paired.device_id, phone.public(), &another)
            .expect("storage"),
        Err(LeaseRefused::AccountMismatch),
        "a lease for another member on a bound device is refused"
    );
    assert_eq!(
        binding_of(&controller, organisation_id, paired.device_id).as_ref(),
        Some(&binding)
    );

    // The control: the same member's next lease installs, and binds nothing new.
    let next = organisation.lease(2, &ada, *phone.public(), now + 2_000, VIEW);
    let renewed = controller
        .present_membership_lease(paired.device_id, phone.public(), &next)
        .expect("storage")
        .expect("the same member's next lease installs");
    assert!(!renewed.bound);
    assert_eq!(
        controller
            .sharing()
            .grants()
            .organisation_events()
            .expect("readable")
            .len(),
        1
    );
}

/// A device that holds no grant requiring the organisation cannot bind, whatever lease it holds.
/// The control: a device whose grant requires the organisation binds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_without_an_organisation_grant_cannot_bind() {
    let temp = kr_ipc::testing::TempHost::create();
    let (controller, organisation, revision, now) = enrolled_daemon(&temp, 0x32).await;
    let organisation_id = organisation.organisation_id;
    let (laptop, phone) = (device(), device());
    let personal = member_device(0x42, *laptop.public(), None);
    let paired = member_device(0x43, *phone.public(), Some((organisation_id, revision)));
    controller.devices().commit(&personal).expect("paired");
    controller.devices().commit(&paired).expect("paired");

    let lease = organisation.lease(2, &member("ada"), *laptop.public(), now, VIEW);
    assert_eq!(
        controller
            .present_membership_lease(personal.device_id, laptop.public(), &lease)
            .expect("storage"),
        Err(LeaseRefused::NoOrganisationGrant)
    );
    assert!(binding_of(&controller, organisation_id, personal.device_id).is_none());
    assert!(
        controller
            .sharing()
            .grants()
            .organisation_events()
            .expect("readable")
            .is_empty()
    );

    // Nor can a device whose organisation grant has run out, although no expiry is recorded yet.
    let tablet = device();
    let mut lapsed = member_device(0x47, *tablet.public(), Some((organisation_id, revision)));
    lapsed.grant.expiry = GrantExpiry::At {
        expires_at_ms: TimestampMs::new(now - 1_000),
    };
    controller.devices().commit(&lapsed).expect("paired");
    assert!(lapsed.expired_at_ms.is_none(), "no expiry is recorded");
    let lease = organisation.lease(2, &member("ada"), *tablet.public(), now, VIEW);
    assert_eq!(
        controller
            .present_membership_lease(lapsed.device_id, tablet.public(), &lease)
            .expect("storage"),
        Err(LeaseRefused::NoOrganisationGrant)
    );
    assert!(binding_of(&controller, organisation_id, lapsed.device_id).is_none());

    let lease = organisation.lease(2, &member("ada"), *phone.public(), now, VIEW);
    let installed = controller
        .present_membership_lease(paired.device_id, phone.public(), &lease)
        .expect("storage")
        .expect("the control: the device with one binds");
    assert!(installed.bound);
}

/// A lease is judged at a reading no older than the policy's lock its presentation is decided
/// under. A presentation that read the clock before the lease ran out, and waited for the lock
/// while it did, is refused as expired. The control: with the clock short of the lease's expiry,
/// it installs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lease_that_runs_out_while_its_presentation_waits_is_refused() {
    use std::sync::atomic::{AtomicU64, Ordering};

    for runs_out in [false, true] {
        let temp = kr_ipc::testing::TempHost::create();
        let wall = Arc::new(AtomicU64::new(kr_ipc::now_ms().get()));
        let clocks = kr_controller::service::Clocks {
            continuous: Arc::new(ManualClock::new()),
            wall: kr_controller::service::WallClock::from_fn({
                let wall = Arc::clone(&wall);
                move || wall.load(Ordering::SeqCst)
            }),
        };
        let controller = start_daemon_on(&temp.environment(), temp.environment_id(), clocks).await;
        let now = wall.load(Ordering::SeqCst);
        let mut organisation = Organisation::new(0x35, now - 2 * DAY_MS);
        organisation.rotate(now - DAY_MS);
        let revision = controller.policy().authority_revision();
        controller
            .update_policy(|policy| organisation.enrol(policy, now))
            .expect("the enrolment is written down");
        let phone = device();
        let key = *phone.public();
        let paired = member_device(0x4a, key, Some((organisation.organisation_id, revision)));
        let device_id = paired.device_id;
        controller.devices().commit(&paired).expect("paired");
        // Issued fourteen minutes ago, so it runs out a minute from now.
        let lease = organisation.lease(2, &member("ada"), key, now - 14 * 60 * 1000, VIEW);
        let expires_at_ms = lease.payload.expires_at_ms.get();

        let (arrived, go) = controller.pause_presentation_before_lock();
        let presenting = {
            let controller = Arc::clone(&controller);
            tokio::task::spawn_blocking(move || {
                controller
                    .present_membership_lease(device_id, &key, &lease)
                    .expect("storage")
            })
        };
        tokio::task::spawn_blocking(move || arrived.recv())
            .await
            .expect("the wait ends")
            .expect("the presentation read the clock and reached the lock");
        if runs_out {
            wall.store(expires_at_ms, Ordering::SeqCst);
        }
        go.send(()).expect("the presentation waits");
        let outcome = presenting.await.expect("presented");
        if runs_out {
            assert_eq!(
                outcome,
                Err(LeaseRefused::Expired),
                "judged at the reading taken under the lock"
            );
            assert!(binding_of(&controller, organisation.organisation_id, device_id).is_none());
        } else {
            assert!(outcome.expect("the control: the lease installs").bound);
        }
    }
}

/// A presentation and a revocation of its device cannot interleave so that the revoked device
/// ends up bound: the presentation decides the device's standing under the policy's lock and
/// holds it until the binding is published, so a revocation recorded while the presentation waited
/// for that lock is seen. The presentation is stopped at the lock, so the order is exact. The
/// control: the same wait with no revocation binds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_revoked_while_its_presentation_waits_is_not_bound() {
    let temp = kr_ipc::testing::TempHost::create();
    let (controller, organisation, revision, now) = enrolled_daemon(&temp, 0x34).await;
    let organisation_id = organisation.organisation_id;

    for (byte, revoked) in [(0x48, true), (0x49, false)] {
        let phone = device();
        let key = *phone.public();
        let paired = member_device(byte, key, Some((organisation_id, revision)));
        let device_id = paired.device_id;
        controller.devices().commit(&paired).expect("paired");
        let lease = organisation.lease(2, &member("ada"), key, now, VIEW);

        // Another change of the policy holds its lock while the presentation starts.
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = {
            let controller = Arc::clone(&controller);
            tokio::task::spawn_blocking(move || {
                controller
                    .update_policy(|_| {
                        held_tx.send(()).expect("the test waits");
                        release_rx.recv().expect("the test releases");
                    })
                    .expect("the policy is written down");
            })
        };
        held_rx.recv().expect("the lock is held");
        // The presentation stops once it has read the clock, before it waits for the lock, so the
        // revocation below lands while it waits.
        let (arrived, go) = controller.pause_presentation_before_lock();
        let presenting = {
            let controller = Arc::clone(&controller);
            tokio::task::spawn_blocking(move || {
                controller
                    .present_membership_lease(device_id, &key, &lease)
                    .expect("storage")
            })
        };
        tokio::task::spawn_blocking(move || arrived.recv())
            .await
            .expect("the wait ends")
            .expect("the presentation reaches the lock");
        if revoked {
            assert!(
                controller
                    .devices()
                    .revoke(device_id, TimestampMs::new(now))
                    .expect("the record is written"),
                "the device is revoked"
            );
        }
        go.send(()).expect("the presentation waits");
        release_tx.send(()).expect("the holder waits");
        holder.await.expect("the holder ends");
        let outcome = presenting.await.expect("presented");
        if revoked {
            assert_eq!(
                outcome,
                Err(LeaseRefused::NoOrganisationGrant),
                "the revocation is seen"
            );
            assert!(
                binding_of(&controller, organisation_id, device_id).is_none(),
                "and nothing is bound"
            );
        } else {
            assert!(outcome.expect("the control: the device binds").bound);
        }
    }
}

/// One device presenting two members' leases at once is bound to exactly one of them. The
/// control: one member's leases presented one after the other both install.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_device_racing_two_accounts_binds_exactly_one() {
    let temp = kr_ipc::testing::TempHost::create();
    let (controller, organisation, revision, now) = enrolled_daemon(&temp, 0x33).await;
    let organisation_id = organisation.organisation_id;
    let phone = device();
    let key = *phone.public();
    let paired = member_device(0x44, key, Some((organisation_id, revision)));
    controller.devices().commit(&paired).expect("paired");
    let device_id = paired.device_id;

    let present = |name: &str| {
        let controller = Arc::clone(&controller);
        let lease = organisation.lease(2, &member(name), key, now, VIEW);
        tokio::task::spawn_blocking(move || {
            controller
                .present_membership_lease(device_id, &key, &lease)
                .expect("storage")
        })
    };
    let (ada, bea) = tokio::join!(present("ada"), present("bea"));
    let outcomes = [ada.expect("presented"), bea.expect("presented")];
    let bound: Vec<_> = outcomes
        .iter()
        .filter_map(|outcome| outcome.as_ref().ok())
        .collect();
    assert_eq!(bound.len(), 1, "exactly one binds: {outcomes:?}");
    assert!(bound[0].bound);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Err(LeaseRefused::AccountMismatch))
            .count(),
        1,
        "the other is refused: {outcomes:?}"
    );
    assert_eq!(
        binding_of(&controller, organisation_id, device_id).map(|binding| binding.account_id),
        Some(bound[0].account_id.clone())
    );
    assert_eq!(
        controller
            .sharing()
            .grants()
            .organisation_events()
            .expect("readable")
            .len(),
        1
    );

    // The control: one member's two leases, one after the other, both install.
    let laptop = device();
    let second = member_device(0x45, *laptop.public(), Some((organisation_id, revision)));
    controller.devices().commit(&second).expect("paired");
    let first = organisation.lease(2, &member("cai"), *laptop.public(), now, VIEW);
    let next = organisation.lease(2, &member("cai"), *laptop.public(), now + 1_000, VIEW);
    assert!(
        controller
            .present_membership_lease(second.device_id, laptop.public(), &first)
            .expect("storage")
            .expect("the first installs")
            .bound
    );
    assert!(
        !controller
            .present_membership_lease(second.device_id, laptop.public(), &next)
            .expect("storage")
            .expect("the next installs too")
            .bound
    );
}

/// A pairing record written with an organisation requirement before this host enrolled still
/// reads, and its grant answers only once an enrolment records exactly its revision and the device
/// is bound on its own lease.
#[test]
fn a_stored_grant_with_an_earlier_organisation_requirement_still_reads() {
    let directory = DeviceDirectory::in_memory().expect("a directory");
    let mut organisation = Organisation::new(0x21, T - 2 * DAY_MS);
    organisation.rotate(T - DAY_MS);
    let phone = device();
    let paired = member_device(
        0x46,
        *phone.public(),
        Some((organisation.organisation_id, AuthorityRevision::new(1))),
    );
    directory
        .commit(&paired)
        .expect("the row is written before any enrolment");
    let read = directory
        .record_for_device(paired.device_id)
        .expect("readable")
        .expect("the row still reads");
    assert_eq!(read.grant, paired.grant);
    let record = GrantRecord {
        grant: read.grant.clone(),
        session_id: None,
        issued_at_ms: 1_000,
        activated_at_ms: Some(1_000),
        revoked_at_ms: None,
        revoked_by_parent: None,
    };
    let request = || AccessRequest {
        method: Method::SessionRead,
        ingress: ActorIngress::PairedDevice,
        environment_id: EnvironmentId::new(Uuid::from_bytes([0xe0; 16])),
        session_id: None,
        claims_geometry: false,
        own_subject: None,
        now_ms: T + MINUTE_MS,
        continuous_now: ManualClock::new().now(),
    };

    let mut host = policy();
    assert_eq!(
        decide(&read.grant, &record, &mut host, request()),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::NoLease
        }),
        "no enrolment records its revision yet"
    );
    let mut elsewhere = HostPolicy::personal(AuthorityRevision::new(2));
    organisation.enrol(&mut elsewhere, T);
    assert_eq!(
        decide(&read.grant, &record, &mut elsewhere, request()),
        Err(Refusal::MembershipUnusable {
            refusal: MembershipRefusal::WrongAuthority
        }),
        "an enrolment at another revision does not answer for it"
    );

    // The control: enrolled at exactly its revision, with the device bound on its own lease.
    organisation.enrol(&mut host, T);
    let lease = organisation.lease(2, &member("ada"), *phone.public(), T, VIEW);
    host.install_lease(LeasePresentation {
        device_id: paired.device_id,
        ..presented(&lease, phone.public(), T, ManualClock::new().now(), 1)
    })
    .expect("installed");
    decide(&read.grant, &record, &mut host, request())
        .expect("it answers once an enrolment records its revision");
}

/// A grant in the grant store answers for a presentation only while it is in force on both clocks
/// and has no end on record. A device whose pairing grant is personal presents under a stored
/// organisation grant whose anchor has run out on the continuous clock, and another under one whose
/// end is on record, both with UTC still before their expiry: neither binds. The control: a device
/// under a live stored organisation grant binds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stored_organisation_grant_that_ran_out_admits_no_lease() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let temp = kr_ipc::testing::TempHost::create();
    let continuous = ManualClock::new();
    let wall = Arc::new(AtomicU64::new(T));
    let controller = start_daemon_on(
        &temp.environment(),
        temp.environment_id(),
        kr_controller::service::Clocks {
            continuous: Arc::new(continuous.clone()),
            wall: kr_controller::service::WallClock::from_fn({
                let wall = Arc::clone(&wall);
                move || wall.load(Ordering::SeqCst)
            }),
        },
    )
    .await;
    let mut organisation = Organisation::new(0x35, T - 2 * DAY_MS);
    organisation.rotate(T - DAY_MS);
    let revision = controller.policy().authority_revision();
    controller
        .update_policy(|policy| organisation.enrol(policy, T))
        .expect("the enrolment is written down");
    let organisation_id = organisation.organisation_id;
    let grants = controller.sharing().grants();

    // Three devices paired under personal grants, each named by a stored organisation grant.
    let mut presenting = Vec::new();
    for (byte, lifetime_ms) in [
        (0x4a, MINUTE_MS),
        (0x4b, 60 * MINUTE_MS),
        (0x4c, 60 * MINUTE_MS),
    ] {
        let key = device();
        let paired = member_device(byte, *key.public(), None);
        controller.devices().commit(&paired).expect("paired");
        let stored = GrantRecord {
            grant: Grant {
                grant_id: GrantId::new(Uuid::from_bytes([byte ^ 0x80; 16])),
                expiry: GrantExpiry::At {
                    expires_at_ms: TimestampMs::new(T + lifetime_ms),
                },
                organisation: Nullable::some(OrganisationRequirement {
                    organisation_id,
                    policy_revision: revision,
                }),
                ..paired.grant.clone()
            },
            session_id: None,
            issued_at_ms: T,
            activated_at_ms: Some(T),
            revoked_at_ms: None,
            revoked_by_parent: None,
        };
        grants
            .issue(&stored, || Ok(()))
            .expect("the grant is written");
        presenting.push((paired, key, stored));
    }

    // The first grant is anchored in this boot, and its anchor runs out on the continuous clock
    // while UTC stays before its expiry.
    assert!(
        !grants.lapsed(&presenting[0].2, T).expect("decided"),
        "anchored in this boot"
    );
    continuous.advance(std::time::Duration::from_millis(MINUTE_MS + 1_000));
    // The second grant's end is on record from an earlier reader, before anything in this daemon
    // anchored it.
    grants
        .record_grant_expiry(presenting[1].2.grant.grant_id, T)
        .expect("the end is written down");

    for (index, (paired, key, _)) in presenting.iter().enumerate() {
        let lease = organisation.lease(2, &member("ada"), *key.public(), T, VIEW);
        let outcome = controller
            .present_membership_lease(paired.device_id, key.public(), &lease)
            .expect("storage");
        if index < 2 {
            assert_eq!(
                outcome,
                Err(LeaseRefused::NoOrganisationGrant),
                "device {index}: a grant out of force answers for no presentation"
            );
            assert!(binding_of(&controller, organisation_id, paired.device_id).is_none());
        } else {
            assert!(
                outcome
                    .expect("the control: a live stored grant answers")
                    .bound,
                "and the device binds"
            );
        }
    }
}
