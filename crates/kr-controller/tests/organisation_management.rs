//! An owner leaves an organisation's policy, and makes the host exclusively organisation-managed or
//! ends that, through the methods the daemon serves.
//!
//! Everything here goes through the owner's local socket, an owner device's own proofs and a
//! member's device on its own connection, on clocks the suite moves, the way a person manages a
//! host. The organisation is a stand-in that signs with real keys.

#![cfg(unix)]

mod fence_support;
mod net_support;
mod organisation_fixture;
mod organisation_support;

use std::time::Duration;

use kr_protocol::confirmation::ConfirmationSubject;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::OrganisationRequirement;
use kr_protocol::ids::ActionId;
use kr_protocol::invitation::InviteGrantKind;
use kr_protocol::method::Method;
use kr_protocol::organisation::{
    MembershipPresentParams, OrganisationEnrolParams, OrganisationEnrolResult,
    OrganisationExclusiveSetParams, OrganisationExclusiveSetResult, OrganisationWithdrawParams,
};
use kr_protocol::pairing::ProposedGrant;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use kr_protocol::sharing::RevocationResult;
use net_support::pairing::{self as calls, Signer};
use net_support::{Device, RawDevice};
use organisation_fixture::*;

/// KR-REQ-17.53: withdrawing from an organisation ends what answered to it. The list no longer
/// shows the enrolment, a member's lease serves nothing on the connection it was presented on or
/// on a new one, a lease cannot be presented again, and the host was fenced for it: the revision
/// advanced and the answer carries the barrier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawal_ends_what_answered_to_the_organisation_and_fences_the_host() {
    let fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let raw = ada.connect(&fixture).await;
    ada.present(&fixture, &raw, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("the lease");
    read_host_info(&raw).await.expect("served under the lease");
    let organisation_id = fixture.organisation.organisation_id;
    let before = fixture.authority_revision();

    let mut client = fixture.host.client().await;
    let answered = fixture
        .withdraw(
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            organisation_id,
        )
        .await
        .expect("the owner withdraws the host");
    assert!(
        answered.authority_revision.get() > before.get(),
        "the host was fenced: the revision advanced from {before:?} to {:?}",
        answered.authority_revision
    );
    assert_eq!(
        answered.barrier.authority_revision,
        answered.authority_revision
    );
    assert!(answered.revoked_grants.is_empty(), "no grant was revoked");
    assert!(fixture.listed().await.enrolments.is_empty());

    // The connection the lease was presented on was admitted under what the withdrawal ended.
    match raw.try_read(Method::HostInfo, &()).await {
        None => {}
        Some(answer) => assert!(
            denied(&net_support::refusal(answer)),
            "a connection admitted before the withdrawal is served nothing"
        ),
    }
    let fresh = ada.connect(&fixture).await;
    assert!(
        denied(&net_support::refusal(read_host_info(&fresh).await)),
        "a new connection is served nothing"
    );
    let refused = net_support::refusal(
        ada.present(&fixture, &fresh, fixture.lease(2, &ada, SERVED), None)
            .await,
    );
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");

    // The host is enrolled in nothing now, so a second withdrawal is refused, and fences nothing.
    // The owner's first connection was admitted under what the fence ended, so it opens a new one.
    let after = fixture.authority_revision();
    let mut client = fixture.host.client().await;
    let again = fixture
        .withdraw(
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            organisation_id,
        )
        .await
        .expect_err("the host is not enrolled any more");
    assert_eq!(again.code, ErrorCode::InvalidArgument, "{again:?}");
    assert_eq!(
        fixture.authority_revision(),
        after,
        "a refusal fences nothing"
    );
    fresh.close();
    raw.close();
    fixture.host.stop().await;
}

/// KR-REQ-17.53: a repeat of a withdrawal that committed is answered from its record, with the
/// fence as it stands, whether the repeat arrives on the same daemon or after a restart; it does
/// not withdraw again or fence the host again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_of_a_withdrawal_is_answered_from_its_record_and_fences_nothing_more() {
    let fixture = Fixture::start().await;
    let organisation_id = fixture.organisation.organisation_id;
    let mut client = fixture.host.client().await;
    // The exact request, window and all, which is what a caller whose answer never arrived sends
    // again over a new connection.
    let request = client
        .compose(
            Method::OrganisationWithdraw,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(fixture.host.environment_id),
            &OrganisationWithdrawParams { organisation_id },
        )
        .await
        .expect("the request");
    let first: RevocationResult = client
        .repeat(&request)
        .await
        .expect("the daemon answers")
        .expect("the owner withdraws the host")
        .to_typed()
        .expect("a revocation result");
    let revision = fixture.authority_revision();
    assert_eq!(first.authority_revision, revision);
    drop(client);

    let mut client = fixture.host.client().await;
    let repeat: RevocationResult = client
        .repeat(&request)
        .await
        .expect("the daemon answers")
        .expect("the same action is answered from its record")
        .to_typed()
        .expect("a revocation result");
    assert_eq!(repeat.authority_revision, first.authority_revision);
    assert_eq!(
        fixture.authority_revision(),
        revision,
        "nothing was fenced again"
    );
    drop(client);

    let fixture = fixture.restart().await;
    let mut client = fixture.host.client().await;
    let after_a_restart: RevocationResult = client
        .repeat(&request)
        .await
        .expect("the daemon answers")
        .expect("and after a restart")
        .to_typed()
        .expect("a revocation result");
    assert_eq!(after_a_restart.authority_revision, first.authority_revision);
    assert_eq!(fixture.authority_revision(), revision);
    assert!(fixture.listed().await.enrolments.is_empty());
    drop(client);
    fixture.host.stop().await;
}

/// KR-REQ-17.53: a later enrolment in the same organisation takes a higher revision and does not
/// bring back what answered to the earlier one. A grant that required the earlier enrolment stays
/// unserved although the organisation signs a lease for its device, and so does one whose
/// invitation had not been redeemed when the host left.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_later_enrolment_takes_a_higher_revision_and_revives_nothing_of_the_earlier_one() {
    let mut fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let organisation_id = fixture.organisation.organisation_id;
    let first_revision = fixture.revision;

    // An invitation of the first enrolment that nobody redeems before the host leaves.
    let mut client = fixture.host.client().await;
    let pending_grant = ProposedGrant {
        organisation: Nullable::some(OrganisationRequirement {
            organisation_id,
            policy_revision: first_revision,
        }),
        ..net_support::proposal(SERVED)
    };
    let invited = calls::invite_direct(
        fixture.host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &pending_grant,
        &Signer::OwnerDevice(&fixture.owner),
    )
    .await
    .expect("an invitation of the first enrolment");
    drop(client);

    let mut client = fixture.host.client().await;
    fixture
        .withdraw(
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            organisation_id,
        )
        .await
        .expect("the owner withdraws the host");
    drop(client);
    let enrolled = fixture.enrol().await;
    assert!(
        enrolled.enrolment_revision.get() > first_revision.get(),
        "the second enrolment took {:?} after the first took {first_revision:?}",
        enrolled.enrolment_revision
    );

    // Ada's grant requires the first enrolment. The organisation signs her a lease, and she is
    // refused for presenting it.
    let raw = ada.connect(&fixture).await;
    let refused = net_support::refusal(
        ada.present(&fixture, &raw, fixture.lease(2, &ada, SERVED), None)
            .await,
    );
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(denied(&net_support::refusal(read_host_info(&raw).await)));
    raw.close();

    // A device that redeems the first enrolment's invitation holds a grant that requires the
    // first enrolment. It is paired, or refused pairing, and either way it is served nothing.
    let bea = Device::create().await;
    let (connection, _candidate, _value) = calls::redeem(&bea.candidate(), &invited).await;
    let mut client = fixture.host.client().await;
    let confirmed = calls::confirm_candidate(
        fixture.host.environment_id,
        &mut client,
        invited.invitation_id,
        &Signer::OwnerDevice(&fixture.owner),
    )
    .await;
    connection.close(0u32.into(), b"paired");
    if let Ok(confirmed) = confirmed {
        let record = fixture
            .host
            .network()
            .devices()
            .record_for_device(confirmed.device_id)
            .expect("readable")
            .expect("the device's record");
        let raw = RawDevice::connect(&fixture.host, &bea, &record).await;
        raw.claim();
        let bea_key = *bea.keys().authorisation.public();
        let lease = fixture.organisation.lease(
            2,
            &organisation_support::member("bea"),
            bea_key,
            fixture.now(),
            SERVED,
        );
        let refused = net_support::refusal(
            raw.mutate(
                Method::MembershipPresent,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(fixture.host.environment_id),
                &MembershipPresentParams {
                    lease,
                    authority: Nullable::null(),
                },
            )
            .await,
        );
        assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
        raw.close();
    }

    // A member paired under the second enrolment is served.
    let cara = fixture.member("cara", SERVED).await;
    let raw = cara.connect(&fixture).await;
    cara.present(&fixture, &raw, fixture.lease(2, &cara, SERVED), None)
        .await
        .expect("the second enrolment's member presents");
    read_host_info(&raw).await.expect("and is served");
    raw.close();
    fixture.host.stop().await;
}

/// KR-REQ-17.53: the grants of an organisation are refused as soon as the withdrawal is written,
/// before its fence is raised. A fence the registry cannot raise stays owed, the host admits
/// nobody while it does, and a restart finishes it: the repeat of the withdrawal is then answered
/// from its record with the revision the fence reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawal_whose_fence_fails_stays_owed_and_a_restart_finishes_it() {
    let fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let raw = ada.connect(&fixture).await;
    ada.present(&fixture, &raw, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("the lease");
    let organisation_id = fixture.organisation.organisation_id;
    let before = fixture.authority_revision();
    let mut client = fixture.host.client().await;
    let request = client
        .compose(
            Method::OrganisationWithdraw,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(fixture.host.environment_id),
            &OrganisationWithdrawParams { organisation_id },
        )
        .await
        .expect("the request");

    // The registry refuses the revision a fence advances, as a full disk would.
    let fault = fence_support::refuse_fences(&fixture.host.tree().environment());
    let failed = client
        .repeat(&request)
        .await
        .expect("the daemon answers")
        .expect_err("the fence could not be raised");
    assert_ne!(failed.code, ErrorCode::InvalidArgument, "{failed:?}");
    assert_eq!(
        fixture.authority_revision(),
        before,
        "the revision did not advance"
    );

    // The withdrawal is written all the same: the enrolment is gone and the member is served
    // nothing, and the host owes a fence it admits nobody under.
    assert!(fixture.listed().await.enrolments.is_empty());
    match raw.try_read(Method::HostInfo, &()).await {
        None => {}
        Some(answer) => assert!(denied(&net_support::refusal(answer))),
    }
    assert!(
        !fixture
            .host
            .controller()
            .sharing()
            .grants()
            .fence_owed()
            .expect("readable")
            .is_empty(),
        "the fence is owed"
    );
    raw.close();
    drop(client);

    // The fault clears and the host restarts: the start publishes the debt and a barrier retires it.
    fence_support::clear_the_fault(&fault);
    drop(fault);
    let fixture = fixture.restart().await;
    fixture.until_the_fence_is_retired().await;
    assert!(fixture.authority_revision().get() > before.get());

    let mut client = fixture.host.client().await;
    let answered: RevocationResult = client
        .repeat(&request)
        .await
        .expect("the daemon answers")
        .expect("the repeat is answered from the record")
        .to_typed()
        .expect("a revocation result");
    assert_eq!(answered.authority_revision, fixture.authority_revision());
    drop(client);
    fixture.host.stop().await;
}

/// KR-REQ-17.53: an enrolment that arrives between a withdrawal's write and the publication of its
/// fence cannot take the revision the fence is about to replace, because the withdrawal holds the
/// registry from its admission through that publication.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrolment_racing_a_withdrawal_cannot_take_the_revision_the_fence_replaces() {
    let mut fixture = Fixture::start().await;
    let organisation_id = fixture.organisation.organisation_id;
    let first_revision = fixture.revision;
    // The owner's second connection is opened now: while the withdrawal holds the registry, a new
    // connection cannot be admitted.
    let mut second = fixture.host.client().await;
    let (arrived, go) = fixture
        .host
        .controller()
        .pause_organisation_restriction_after_commit();

    let withdrawal = {
        let mut client = fixture.host.client().await;
        let environment = fixture.host.environment_id;
        tokio::spawn(async move {
            let answered = calls::mutate_as::<_, RevocationResult>(
                environment,
                &mut client,
                ActionId::new(kr_ipc::new_uuid()),
                Method::OrganisationWithdraw,
                &OrganisationWithdrawParams { organisation_id },
            )
            .await;
            (client, answered)
        })
    };
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the wait ends")
        .expect("the withdrawal reaches its write");

    // The policy no longer holds the enrolment, so an owner can ask to enrol again, and does:
    // confirm the chain, then enrol. Nothing here waits for the withdrawal, which holds the
    // registry, except what needs it.
    let params = OrganisationEnrolParams {
        authority: fixture.organisation.authority(fixture.now() - 1_000),
    };
    let environment = fixture.host.environment_id;
    let owner = fixture.owner.clone();
    let enrolment = tokio::spawn(async move {
        calls::confirm_subject(
            environment,
            &mut second,
            ConfirmationSubject::EnrolOrganisation(Box::new(params.clone())),
            &Signer::OwnerDevice(&owner),
        )
        .await?;
        let enrolled: OrganisationEnrolResult = calls::mutate_as(
            environment,
            &mut second,
            ActionId::new(kr_ipc::new_uuid()),
            Method::OrganisationEnrol,
            &params,
        )
        .await?;
        Ok::<_, kr_protocol::error::ProtocolError>(enrolled)
    });
    // An implementation that let the registry go before it published its fence would let this
    // finish at the old revision. This one cannot, so the wait below ends only by its bound; the
    // bound decides nothing for an implementation that is right.
    let mut enrolment = enrolment;
    let early = tokio::time::timeout(Duration::from_secs(3), &mut enrolment).await;
    go.send(()).expect("the withdrawal waits");
    let (client, answered) = withdrawal.await.expect("the withdrawal ends");
    let answered = answered.expect("the withdrawal is answered");
    drop(client);
    let outcome = match early {
        Ok(joined) => joined.expect("the enrolment ends"),
        Err(_) => enrolment.await.expect("the enrolment ends"),
    };
    if let Ok(enrolled) = outcome {
        assert!(
            enrolled.enrolment_revision.get() > first_revision.get(),
            "an enrolment took {:?}, the revision the fence at {:?} replaced",
            enrolled.enrolment_revision,
            answered.authority_revision
        );
    }
    assert!(answered.authority_revision.get() > first_revision.get());

    // Enrolling again once the fence has held takes a later revision in any case.
    let enrolled = fixture.enrol().await;
    assert!(enrolled.enrolment_revision.get() > first_revision.get());
    fixture.host.stop().await;
}

/// The owner's own device, on a connection of its own, and the lease the organisation signs for it
/// once the host is exclusively managed.
struct OwnerDevice<'a> {
    fixture: &'a Fixture,
}

impl OwnerDevice<'_> {
    async fn connect(&self) -> RawDevice {
        let device = self
            .fixture
            .host
            .owner_device
            .as_ref()
            .expect("the owner device");
        let record = self
            .fixture
            .host
            .owner
            .as_ref()
            .expect("the owner's record");
        let raw = RawDevice::connect(&self.fixture.host, device, record).await;
        raw.claim();
        raw
    }

    fn lease(&self) -> kr_protocol::account::MembershipLease {
        let device = self
            .fixture
            .host
            .owner_device
            .as_ref()
            .expect("the owner device");
        self.fixture.organisation.lease(
            2,
            &organisation_support::member("owner"),
            *device.keys().authorisation.public(),
            self.fixture.now(),
            &[ActionRight::SessionView],
        )
    }

    async fn present(&self, raw: &RawDevice) -> Result<(), kr_protocol::error::ProtocolError> {
        raw.mutate(
            Method::MembershipPresent,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(self.fixture.host.environment_id),
            &MembershipPresentParams {
                lease: self.lease(),
                authority: Nullable::null(),
            },
        )
        .await
        .map(|_| ())
    }
}

/// KR-REQ-17.54: the owner's own device keeps its access when the organisation's leases stop, until
/// the host is made exclusively organisation-managed. Then its access answers to a lease like a
/// member's: refused without one, served while the lease the organisation signs for it lasts, and
/// refused when that ends. Turning it on fences the host, as a restriction does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owners_device_keeps_its_access_until_the_host_is_made_exclusive_and_then_answers_to_a_lease()
 {
    let fixture = Fixture::start().await;
    let owner = OwnerDevice { fixture: &fixture };
    let raw = owner.connect().await;
    read_host_info(&raw).await.expect("served on its own grant");
    let before = fixture.authority_revision();

    let mut client = fixture.host.client().await;
    let on = fixture
        .set_exclusive(&mut client, ActionId::new(kr_ipc::new_uuid()), true)
        .await
        .expect("the owner makes the host exclusive");
    assert!(on.exclusive);
    assert!(
        on.authority_revision.get() > before.get(),
        "the host was fenced"
    );
    assert!(on.barrier.0.is_some(), "the answer carries the barrier");
    assert!(fixture.listed().await.exclusive);
    drop(client);

    // The connection admitted before the fence is served nothing more; a new one is refused for
    // want of a lease, and served once the organisation's lease for the device is presented.
    match raw.try_read(Method::HostInfo, &()).await {
        None => {}
        Some(answer) => assert!(denied(&net_support::refusal(answer))),
    }
    raw.close();
    let raw = owner.connect().await;
    assert!(
        denied(&net_support::refusal(read_host_info(&raw).await)),
        "the owner's device is refused without a lease"
    );
    owner
        .present(&raw)
        .await
        .expect("the owner's lease installs");
    read_host_info(&raw).await.expect("served under the lease");

    fixture.pass(Duration::from_millis(
        organisation_support::LEASE_MS + 1_000,
    ));
    assert!(
        denied(&net_support::refusal(read_host_info(&raw).await)),
        "and refused again once it ends"
    );
    raw.close();
    fixture.host.stop().await;
}

/// KR-REQ-17.54: a change the host would refuse is not put to the owner, and nothing is kept for
/// it: exclusive management needs an enrolment and a device that can recover the host, and ending
/// it needs it to be on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exclusive_management_is_refused_without_an_enrolment_and_without_a_device_that_can_recover_the_host()
 {
    // No enrolment: there is nothing to manage the host.
    let fixture = Fixture::start_unenrolled().await;
    let mut client = fixture.host.client().await;
    let refused = calls::request(
        fixture.host.environment_id,
        &mut client,
        ConfirmationSubject::SetExclusiveManagement { exclusive: true },
    )
    .await
    .expect_err("the host is enrolled in nothing");
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    let refused = calls::request(
        fixture.host.environment_id,
        &mut client,
        ConfirmationSubject::SetExclusiveManagement { exclusive: false },
    )
    .await
    .expect_err("the host is not exclusive");
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    drop(client);
    fixture.host.stop().await;

    // The owner's one device does not qualify when its grant ends: nothing that never ends can
    // confirm for the host once its leases do.
    let fixture = Fixture::start().await;
    let helper = Device::create().await;
    let helper_record = net_support::pair_with(
        &fixture.host,
        &helper,
        &fixture.owner,
        net_support::proposal(&[ActionRight::HostManage]),
    )
    .await;
    assert!(helper_record.grant.expiry != kr_protocol::grant::GrantExpiry::Never);
    // Only the helper's device remains; the first owner's is revoked.
    let owner_id = fixture
        .host
        .owner
        .as_ref()
        .expect("the owner's record")
        .device_id;
    let mut client = fixture.host.client().await;
    calls::mutate::<_, kr_protocol::sharing::RevocationResult>(
        fixture.host.environment_id,
        &mut client,
        Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: owner_id,
        },
    )
    .await
    .expect("the owner's device is revoked");
    drop(client);
    let mut client = fixture.host.client().await;
    let refused = calls::request(
        fixture.host.environment_id,
        &mut client,
        ConfirmationSubject::SetExclusiveManagement { exclusive: true },
    )
    .await
    .expect_err("no device that never expires can recover the host");
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    drop(client);
    fixture.host.stop().await;
}

/// KR-REQ-17.54: an owner device ends exclusive management, which enlarges nothing the host
/// refuses and fences nothing. The turning off is recorded with how it was confirmed, the record is
/// read by `organisation.list`, and a repeat of the action is answered from the record without a
/// second record. Leaving the last organisation is refused while it is on and allowed after.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_device_ends_exclusive_management_and_the_host_records_how_it_was_confirmed() {
    let fixture = Fixture::start().await;
    let organisation_id = fixture.organisation.organisation_id;
    let mut client = fixture.host.client().await;
    fixture
        .set_exclusive(&mut client, ActionId::new(kr_ipc::new_uuid()), true)
        .await
        .expect("the owner makes the host exclusive");
    assert!(fixture.listed().await.exclusive_events.is_empty());

    // The host's last organisation cannot be left while the host is exclusive: nothing would
    // answer for it.
    let mut client = fixture.host.client().await;
    let refused = fixture
        .withdraw(
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            organisation_id,
        )
        .await
        .expect_err("the last organisation of an exclusive host");
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    let revision = fixture.authority_revision();

    let mut client = fixture.host.client().await;
    calls::confirm_subject(
        fixture.host.environment_id,
        &mut client,
        ConfirmationSubject::SetExclusiveManagement { exclusive: false },
        &Signer::OwnerDevice(&fixture.owner),
    )
    .await
    .expect("the owner device confirms ending it");
    let request = client
        .compose(
            Method::OrganisationExclusiveSet,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(fixture.host.environment_id),
            &OrganisationExclusiveSetParams { exclusive: false },
        )
        .await
        .expect("the request");
    let off: OrganisationExclusiveSetResult = client
        .repeat(&request)
        .await
        .expect("the daemon answers")
        .expect("the owner ends exclusive management")
        .to_typed()
        .expect("a result");
    assert!(!off.exclusive);
    assert!(
        off.barrier.0.is_none(),
        "ending it restricts nothing, so it fences nothing"
    );
    assert_eq!(fixture.authority_revision(), revision);

    let listed = fixture.listed().await;
    assert!(!listed.exclusive);
    assert_eq!(
        listed.exclusive_events.len(),
        1,
        "the turning off is on record"
    );
    let event = &listed.exclusive_events[0];
    assert_eq!(
        event.channel,
        kr_protocol::pairing::ConfirmationChannel::OwnerDevicePresence
    );
    assert_eq!(
        event.organisation_ids.iter().copied().collect::<Vec<_>>(),
        vec![organisation_id]
    );

    // A repeat is answered from the record and records nothing more.
    drop(client);
    let mut client = fixture.host.client().await;
    let again: OrganisationExclusiveSetResult = client
        .repeat(&request)
        .await
        .expect("the daemon answers")
        .expect("answered from the record")
        .to_typed()
        .expect("a result");
    assert_eq!(again, off);
    assert_eq!(fixture.listed().await.exclusive_events.len(), 1);

    // And the host may leave its last organisation now.
    drop(client);
    let mut client = fixture.host.client().await;
    fixture
        .withdraw(
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            organisation_id,
        )
        .await
        .expect("the host is not exclusive any more");
    drop(client);
    fixture.host.stop().await;
}

/// KR-REQ-17.54: making the host exclusive whose fence the registry cannot raise leaves the fence
/// owed; a restart finishes it and the repeat of the action is answered from its record, built from
/// the barrier as it stands, and not again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn making_the_host_exclusive_when_its_fence_fails_stays_owed_and_a_restart_finishes_it() {
    let fixture = Fixture::start().await;
    let before = fixture.authority_revision();
    let mut client = fixture.host.client().await;
    calls::confirm_subject(
        fixture.host.environment_id,
        &mut client,
        ConfirmationSubject::SetExclusiveManagement { exclusive: true },
        &Signer::OwnerDevice(&fixture.owner),
    )
    .await
    .expect("the owner device confirms");
    let request = client
        .compose(
            Method::OrganisationExclusiveSet,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(fixture.host.environment_id),
            &OrganisationExclusiveSetParams { exclusive: true },
        )
        .await
        .expect("the request");

    let fault = fence_support::refuse_fences(&fixture.host.tree().environment());
    let failed = client
        .repeat(&request)
        .await
        .expect("the daemon answers")
        .expect_err("the fence could not be raised");
    assert_ne!(failed.code, ErrorCode::InvalidArgument, "{failed:?}");
    assert_eq!(fixture.authority_revision(), before);
    assert!(
        fixture.listed().await.exclusive,
        "the host is exclusive as soon as the change is written"
    );
    assert!(
        !fixture
            .host
            .controller()
            .sharing()
            .grants()
            .fence_owed()
            .expect("readable")
            .is_empty(),
        "the fence is owed"
    );
    drop(client);
    fence_support::clear_the_fault(&fault);
    drop(fault);

    let fixture = fixture.restart().await;
    fixture.until_the_fence_is_retired().await;
    assert!(fixture.authority_revision().get() > before.get());
    assert!(
        fixture.listed().await.exclusive,
        "the flag survives a restart"
    );
    let mut client = fixture.host.client().await;
    let answered: OrganisationExclusiveSetResult = client
        .repeat(&request)
        .await
        .expect("the daemon answers")
        .expect("answered from the record")
        .to_typed()
        .expect("a result");
    assert!(answered.exclusive);
    assert_eq!(answered.authority_revision, fixture.authority_revision());
    assert!(answered.barrier.0.is_some());
    drop(client);
    fixture.host.stop().await;
}
