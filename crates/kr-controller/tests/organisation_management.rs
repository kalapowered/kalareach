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

use kr_crypto::keys::DeviceKeys;
use kr_protocol::confirmation::{
    ConfirmationSubject, OwnerConfirmationCompleteParams, OwnerConfirmationPendingParams,
    OwnerConfirmationPendingResult, OwnerConfirmationRequestParams, OwnerConfirmationRequestResult,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::OrganisationRequirement;
use kr_protocol::ids::ActionId;
use kr_protocol::invitation::InviteGrantKind;
use kr_protocol::method::Method;
use kr_protocol::organisation::{
    MembershipPresentParams, OrganisationEnrolParams, OrganisationEnrolResult,
    OrganisationExclusiveSetParams, OrganisationExclusiveSetResult, OrganisationListParams,
    OrganisationListResult, OrganisationWithdrawParams,
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
///
/// It is rebuilt from the owner's keys, so it stays the same device across a restart of the host.
struct OwnerDevice<'a> {
    fixture: &'a Fixture,
    device: Device,
}

impl<'a> OwnerDevice<'a> {
    async fn of(fixture: &'a Fixture) -> Self {
        Self {
            fixture,
            device: Device::with_keys(fixture.owner.clone()).await,
        }
    }

    async fn connect(&self) -> RawDevice {
        let record = self
            .fixture
            .host
            .owner
            .as_ref()
            .expect("the owner's record");
        let raw = RawDevice::connect(&self.fixture.host, &self.device, record).await;
        raw.claim();
        raw
    }

    fn lease(&self) -> kr_protocol::account::MembershipLease {
        self.fixture.organisation.lease(
            2,
            &organisation_support::member("owner"),
            *self.device.keys().authorisation.public(),
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
    let owner = OwnerDevice::of(&fixture).await;
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

/// Recovers an exclusively organisation-managed host whose owner's device no lease serves: the
/// device reads what the host holds, asks for the confirmation of ending exclusive management and
/// answers it, all over its own connection, and the owner at the host's own socket spends the
/// answer. Everything else the device asks is refused for want of a lease.
async fn recover_by_a_confirmed_ending(fixture: &Fixture) {
    let owner = OwnerDevice::of(fixture).await;
    let raw = owner.connect().await;
    assert!(
        denied(&net_support::refusal(read_host_info(&raw).await)),
        "an ordinary read is refused for want of a lease"
    );
    let listed: OrganisationListResult = raw
        .read(Method::OrganisationList, &OrganisationListParams::default())
        .await
        .expect("the host's organisations are read without a lease")
        .to_typed()
        .expect("a list");
    assert!(listed.exclusive);

    // A confirmation of anything but the clock and the end of exclusive management is refused.
    let environment = ActionTarget::environment(fixture.host.environment_id);
    let refused = net_support::refusal(
        raw.mutate(
            Method::OwnerConfirmationRequest,
            ActionId::new(kr_ipc::new_uuid()),
            environment.clone(),
            &OwnerConfirmationRequestParams {
                subject: ConfirmationSubject::SetExclusiveManagement { exclusive: true },
            },
        )
        .await,
    );
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");

    let challenge: OwnerConfirmationRequestResult = raw
        .mutate(
            Method::OwnerConfirmationRequest,
            ActionId::new(kr_ipc::new_uuid()),
            environment.clone(),
            &OwnerConfirmationRequestParams {
                subject: ConfirmationSubject::SetExclusiveManagement { exclusive: false },
            },
        )
        .await
        .expect("the confirmation of ending it is asked for")
        .to_typed()
        .expect("a challenge");
    let pending: OwnerConfirmationPendingResult = raw
        .read(
            Method::OwnerConfirmationPending,
            &OwnerConfirmationPendingParams {},
        )
        .await
        .expect("the challenge is listed")
        .to_typed()
        .expect("a list");
    assert!(
        pending
            .pending
            .iter()
            .any(|shown| shown.request == challenge.request),
        "the owner device is shown what it is asked to confirm"
    );
    let (proof, _) = calls::sign(&challenge.request, &Signer::OwnerDevice(&fixture.owner));
    raw.mutate(
        Method::OwnerConfirmationComplete,
        ActionId::new(kr_ipc::new_uuid()),
        environment,
        &OwnerConfirmationCompleteParams {
            proof,
            bootstrap_signer: Nullable::null(),
        },
    )
    .await
    .expect("the owner device answers its own ceremony");
    raw.close();

    // The owner at the host spends the answer: exclusive management ends, with the event.
    let mut client = fixture.host.client().await;
    let off: OrganisationExclusiveSetResult = calls::mutate(
        fixture.host.environment_id,
        &mut client,
        Method::OrganisationExclusiveSet,
        &OrganisationExclusiveSetParams { exclusive: false },
    )
    .await
    .expect("the host spends the answered confirmation");
    assert!(!off.exclusive);
    let listed = fixture.listed().await;
    assert!(!listed.exclusive);
    assert_eq!(listed.exclusive_events.len(), 1);

    // And the owner's device is served on its own grant again, and reads the event at its own door.
    let raw = owner.connect().await;
    read_host_info(&raw).await.expect("served on its own grant");
    let listed: OrganisationListResult = raw
        .read(Method::OrganisationList, &OrganisationListParams::default())
        .await
        .expect("the owner device reads the list")
        .to_typed()
        .expect("a list");
    assert!(!listed.exclusive);
    assert_eq!(
        listed.exclusive_events.len(),
        1,
        "the paired door shows the record of the ending"
    );
    raw.close();
}

/// KR-REQ-17.54: a host made exclusive recovers at once, with no lease ever presented, by the
/// confirmed ending of exclusive management over the owner's device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exclusive_host_recovers_by_a_confirmed_ending_right_after_it_was_made_exclusive() {
    let fixture = Fixture::start().await;
    let mut client = fixture.host.client().await;
    fixture
        .set_exclusive(&mut client, ActionId::new(kr_ipc::new_uuid()), true)
        .await
        .expect("the owner makes the host exclusive");
    drop(client);
    recover_by_a_confirmed_ending(&fixture).await;
    fixture.host.stop().await;
}

/// KR-REQ-17.54: and after the leases it had ended, and after a restart that took them all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exclusive_host_recovers_after_its_leases_ended_and_after_a_restart() {
    let fixture = Fixture::start().await;
    let mut client = fixture.host.client().await;
    fixture
        .set_exclusive(&mut client, ActionId::new(kr_ipc::new_uuid()), true)
        .await
        .expect("the owner makes the host exclusive");
    drop(client);
    let owner = OwnerDevice::of(&fixture).await;
    let raw = owner.connect().await;
    owner.present(&raw).await.expect("the owner's lease");
    read_host_info(&raw).await.expect("served under the lease");
    fixture.pass(Duration::from_millis(
        organisation_support::LEASE_MS + 1_000,
    ));
    assert!(denied(&net_support::refusal(read_host_info(&raw).await)));
    raw.close();

    // After a restart no lease is held either.
    let fixture = fixture.restart().await;
    recover_by_a_confirmed_ending(&fixture).await;
    fixture.host.stop().await;
}

/// KR-REQ-17.54: what recovers the host is for the device that can recover it. An owner's device
/// whose grant ends is refused on a lapsed exclusive host, a leased owner device keeps every
/// confirmation, and the confirmation of ending exclusive management is not carried by a device
/// that no lease serves to a change it cannot see.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_device_that_can_recover_the_host_reaches_what_recovers_it_and_a_leased_one_confirms_everything()
 {
    let fixture = Fixture::start().await;
    let mut client = fixture.host.client().await;
    fixture
        .set_exclusive(&mut client, ActionId::new(kr_ipc::new_uuid()), true)
        .await
        .expect("the owner makes the host exclusive");
    drop(client);
    // The host's local owner answers to a lease as a member does, and asks for what follows.
    fixture.lease_the_local_owner().await;

    // A device with host management whose grant expires does not qualify.
    let helper = Device::create().await;
    let helper_record = net_support::pair_with(
        &fixture.host,
        &helper,
        &fixture.owner,
        net_support::proposal(&[ActionRight::HostManage]),
    )
    .await;
    let helper_raw = RawDevice::connect(&fixture.host, &helper, &helper_record).await;
    helper_raw.claim();
    let refused = net_support::refusal(
        helper_raw
            .read(Method::OrganisationList, &OrganisationListParams::default())
            .await,
    );
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    helper_raw.close();

    // A leased owner device is asked for any confirmation: the request reaches the host's own
    // check and is refused for what is wrong with it, not for want of a lease.
    let owner = OwnerDevice::of(&fixture).await;
    let raw = owner.connect().await;
    let environment = ActionTarget::environment(fixture.host.environment_id);
    let without_a_lease = net_support::refusal(
        raw.mutate(
            Method::OwnerConfirmationRequest,
            ActionId::new(kr_ipc::new_uuid()),
            environment.clone(),
            &OwnerConfirmationRequestParams {
                subject: ConfirmationSubject::SetExclusiveManagement { exclusive: true },
            },
        )
        .await,
    );
    assert_eq!(without_a_lease.code, ErrorCode::PermissionDenied);
    owner.present(&raw).await.expect("the owner's lease");
    let with_a_lease = net_support::refusal(
        raw.mutate(
            Method::OwnerConfirmationRequest,
            ActionId::new(kr_ipc::new_uuid()),
            environment,
            &OwnerConfirmationRequestParams {
                subject: ConfirmationSubject::SetExclusiveManagement { exclusive: true },
            },
        )
        .await,
    );
    assert_eq!(
        with_a_lease.code,
        ErrorCode::InvalidArgument,
        "the host is exclusive already: {with_a_lease:?}"
    );
    raw.close();
    fixture.host.stop().await;
}

/// The owner at the host's terminal answers `subject` with a key made for that one answer, which is
/// what `kr` does when the host says the terminal can confirm it, and returns whether the host
/// said so.
async fn at_the_terminal(
    fixture: &Fixture,
    client: &mut kr_ipc::client::LocalClient,
    subject: ConfirmationSubject,
) -> (bool, Result<(), kr_protocol::error::ProtocolError>) {
    let challenge = match calls::request(fixture.host.environment_id, client, subject).await {
        Ok(challenge) => challenge,
        // The host refuses to issue it at all.
        Err(refused) => return (false, Err(refused)),
    };
    let key = DeviceKeys::generate().expect("a key for this one answer");
    let (proof, presented) =
        calls::sign(&challenge.request, &Signer::Bootstrap(&key.authorisation));
    let answered = calls::complete(fixture.host.environment_id, client, proof, presented)
        .await
        .map(|_| ());
    (challenge.initial_bootstrap, answered)
}

/// KR-REQ-17.54: when exclusive management is on and no device is left that can confirm for the
/// host, its owner at the host's terminal ends it, and nothing else. The host says the terminal can
/// confirm it only in that state; while a device that can confirm exists, or for any other subject,
/// the terminal's proof is refused. The turning off is on record as the terminal's, and the
/// organisation hears of it with the next lease it asks the host about.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_terminal_confirms_the_end_of_exclusive_management_when_no_device_can_and_nothing_else()
{
    let fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let organisation_id = fixture.organisation.organisation_id;
    let mut client = fixture.host.client().await;
    fixture
        .set_exclusive(&mut client, ActionId::new(kr_ipc::new_uuid()), true)
        .await
        .expect("the owner makes the host exclusive");
    drop(client);

    // While an owner device that can confirm exists, the terminal confirms nothing.
    let mut client = fixture.host.client().await;
    let (offered, answered) = at_the_terminal(
        &fixture,
        &mut client,
        ConfirmationSubject::SetExclusiveManagement { exclusive: false },
    )
    .await;
    assert!(
        !offered,
        "the host does not offer the terminal while a device can confirm"
    );
    let refused = answered.expect_err("the terminal's proof is refused");
    assert_eq!(
        refused.code,
        ErrorCode::OwnerConfirmationRequired,
        "{refused:?}"
    );
    drop(client);

    // The owner's one device is revoked, which no rule refuses.
    let owner_id = fixture
        .host
        .owner
        .as_ref()
        .expect("the owner's record")
        .device_id;
    let mut client = fixture.host.client().await;
    calls::mutate::<_, RevocationResult>(
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

    // Nothing but the end of exclusive management is confirmed at the terminal.
    let mut client = fixture.host.client().await;
    let (offered, answered) =
        at_the_terminal(&fixture, &mut client, ConfirmationSubject::EstablishClock).await;
    assert!(!offered, "the clock is not the terminal's here");
    let refused = answered.expect_err("the terminal's proof for the clock is refused");
    assert_eq!(
        refused.code,
        ErrorCode::OwnerConfirmationRequired,
        "{refused:?}"
    );
    let (_, answered) = at_the_terminal(
        &fixture,
        &mut client,
        ConfirmationSubject::IssueInvitation {
            mode: kr_protocol::invitation::InviteModeKind::Direct,
            rendezvous_origin: Nullable::null(),
            grant_kind: InviteGrantKind::PersonalOwner,
            proposed_grant: kr_pairing::grants::personal_owner_grant(),
        },
    )
    .await;
    let refused = answered.expect_err("an owner invitation is not the terminal's either");
    assert_eq!(
        refused.code,
        ErrorCode::PermissionDenied,
        "the host's local owner holds no lease, so the host does not issue the challenge: \
         {refused:?}"
    );

    // The end of exclusive management is.
    let (offered, answered) = at_the_terminal(
        &fixture,
        &mut client,
        ConfirmationSubject::SetExclusiveManagement { exclusive: false },
    )
    .await;
    assert!(
        offered,
        "the host offers the terminal when no device can confirm"
    );
    answered.expect("the terminal confirms the end of exclusive management");
    let off: OrganisationExclusiveSetResult = calls::mutate(
        fixture.host.environment_id,
        &mut client,
        Method::OrganisationExclusiveSet,
        &OrganisationExclusiveSetParams { exclusive: false },
    )
    .await
    .expect("the host spends the terminal's answer");
    assert!(!off.exclusive);
    drop(client);

    let listed = fixture.listed().await;
    assert!(!listed.exclusive);
    assert_eq!(listed.exclusive_events.len(), 1);
    let event = &listed.exclusive_events[0];
    assert_eq!(
        event.channel,
        kr_protocol::pairing::ConfirmationChannel::LocalBootstrapTerminal
    );
    assert_eq!(
        event.organisation_ids.iter().copied().collect::<Vec<_>>(),
        vec![organisation_id]
    );

    // A member's next presentation carries the time to the organisation.
    let raw = ada.connect(&fixture).await;
    let presented = ada
        .present(&fixture, &raw, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("the member's lease");
    assert!(!presented.exclusive);
    assert_eq!(
        presented.exclusive_ended_at_terminal_ms.0,
        Some(event.at_ms),
        "the organisation is told when the terminal ended it"
    );
    raw.close();
    fixture.host.stop().await;
}

/// KR-REQ-17.54: the terminal's answer is good only while the host is in the state that offered it.
/// A device that can confirm appears after the terminal answered, and the host refuses to spend
/// the answer: the device is the one to ask.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_can_confirm_appearing_after_the_terminal_answered_stops_the_terminal() {
    let fixture = Fixture::start().await;
    let mut client = fixture.host.client().await;
    fixture
        .set_exclusive(&mut client, ActionId::new(kr_ipc::new_uuid()), true)
        .await
        .expect("the owner makes the host exclusive");
    drop(client);
    // The host's local owner answers to a lease as a member does, and asks for what follows.
    fixture.lease_the_local_owner().await;

    // A device whose grant ends can still confirm a pairing, which a lasting one can then make.
    let helper = Device::create().await;
    net_support::pair_with(
        &fixture.host,
        &helper,
        &fixture.owner,
        net_support::proposal(&[ActionRight::HostManage]),
    )
    .await;
    let owner_id = fixture
        .host
        .owner
        .as_ref()
        .expect("the owner's record")
        .device_id;
    let mut client = fixture.host.client().await;
    calls::mutate::<_, RevocationResult>(
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
    let (offered, answered) = at_the_terminal(
        &fixture,
        &mut client,
        ConfirmationSubject::SetExclusiveManagement { exclusive: false },
    )
    .await;
    assert!(offered);
    answered.expect("the terminal answers");

    // The helper confirms a new owner device's pairing.
    let successor = Device::create().await;
    let signer = Signer::OwnerDevice(helper.keys());
    let invited = calls::invite_direct(
        fixture.host.environment_id,
        &mut client,
        InviteGrantKind::PersonalOwner,
        &kr_pairing::grants::personal_owner_grant(),
        &signer,
    )
    .await
    .expect("the helper confirms an owner invitation");
    let (connection, _candidate, _value) = calls::redeem(&successor.candidate(), &invited).await;
    calls::confirm_candidate(
        fixture.host.environment_id,
        &mut client,
        invited.invitation_id,
        &signer,
    )
    .await
    .expect("the helper confirms the new owner device");
    connection.close(0u32.into(), b"paired");
    drop(client);

    // The answer the terminal gave belonged to a host that nothing else could confirm for.
    let mut client = fixture.host.client().await;
    let refused = calls::mutate::<_, OrganisationExclusiveSetResult>(
        fixture.host.environment_id,
        &mut client,
        Method::OrganisationExclusiveSet,
        &OrganisationExclusiveSetParams { exclusive: false },
    )
    .await
    .expect_err("the terminal's answer is not spent");
    assert_eq!(
        refused.code,
        ErrorCode::OwnerConfirmationRequired,
        "{refused:?}"
    );
    assert!(fixture.listed().await.exclusive);
    assert!(fixture.listed().await.exclusive_events.is_empty());
    drop(client);
    fixture.host.stop().await;
}

/// The number of actions this host holds a claim on: the rows a request that is asked again for a
/// confirmation not yet given must not leave behind.
fn claims(fixture: &Fixture) -> i64 {
    rusqlite::Connection::open(fixture.host.registry_database())
        .expect("the registry opens")
        .query_row("SELECT COUNT(*) FROM authority_receipts", [], |row| {
            row.get(0)
        })
        .expect("counts the claims")
}

/// KR-REQ-17.54: a request to change exclusive management that finds no answered confirmation of
/// exactly that change is refused before anything is claimed, so an owner's client that asks again
/// with a new identifier for each poll leaves no row behind per attempt, and a confirmation of the
/// other change is neither spent nor accepted for this one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_of_exclusive_management_with_no_answer_yet_leaves_no_claim_and_spends_nothing_else()
 {
    let fixture = Fixture::start().await;
    let before = claims(&fixture);
    let mut client = fixture.host.client().await;
    for _ in 0..3 {
        let refused = calls::mutate::<_, OrganisationExclusiveSetResult>(
            fixture.host.environment_id,
            &mut client,
            Method::OrganisationExclusiveSet,
            &OrganisationExclusiveSetParams { exclusive: true },
        )
        .await
        .expect_err("no confirmation has been given");
        assert_eq!(
            refused.code,
            ErrorCode::OwnerConfirmationRequired,
            "{refused:?}"
        );
    }
    assert_eq!(claims(&fixture), before, "a poll leaves nothing behind");

    // A confirmation of the end of exclusive management is not one for making the host exclusive.
    // The host is not exclusive, so the end cannot be asked for; the confirmation of making it
    // exclusive is for another host's state once an organisation is withdrawn.
    calls::confirm_subject(
        fixture.host.environment_id,
        &mut client,
        ConfirmationSubject::SetExclusiveManagement { exclusive: true },
        &Signer::OwnerDevice(&fixture.owner),
    )
    .await
    .expect("the owner device confirms making the host exclusive");
    drop(client);
    let mut client = fixture.host.client().await;
    let organisation_id = fixture.organisation.organisation_id;
    fixture
        .withdraw(
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            organisation_id,
        )
        .await
        .expect("the host leaves the organisation");
    drop(client);
    let mut client = fixture.host.client().await;
    let refused = calls::mutate::<_, OrganisationExclusiveSetResult>(
        fixture.host.environment_id,
        &mut client,
        Method::OrganisationExclusiveSet,
        &OrganisationExclusiveSetParams { exclusive: true },
    )
    .await
    .expect_err("the confirmation was for a host enrolled in the organisation");
    assert_eq!(
        refused.code,
        ErrorCode::OwnerConfirmationRequired,
        "{refused:?}"
    );
    assert!(!fixture.listed().await.exclusive);
    drop(client);
    fixture.host.stop().await;
}

/// KR-REQ-17.54: leaving an organisation and changing exclusive management are the owner's at the
/// host: a paired device, an owner device included, does not reach either over its own connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_does_not_reach_withdrawal_or_exclusive_management() {
    let fixture = Fixture::start().await;
    let owner = OwnerDevice::of(&fixture).await;
    let raw = owner.connect().await;
    let environment = ActionTarget::environment(fixture.host.environment_id);
    let organisation_id = fixture.organisation.organisation_id;
    let withdrawn = net_support::refusal(
        raw.mutate(
            Method::OrganisationWithdraw,
            ActionId::new(kr_ipc::new_uuid()),
            environment.clone(),
            &OrganisationWithdrawParams { organisation_id },
        )
        .await,
    );
    assert_eq!(withdrawn.code, ErrorCode::PermissionDenied, "{withdrawn:?}");
    let exclusive = net_support::refusal(
        raw.mutate(
            Method::OrganisationExclusiveSet,
            ActionId::new(kr_ipc::new_uuid()),
            environment,
            &OrganisationExclusiveSetParams { exclusive: true },
        )
        .await,
    );
    assert_eq!(exclusive.code, ErrorCode::PermissionDenied, "{exclusive:?}");
    raw.close();
    assert_eq!(
        fixture.listed().await.enrolments.len(),
        1,
        "nothing was withdrawn"
    );
    assert!(!fixture.listed().await.exclusive);
    fixture.host.stop().await;
}

/// What the host lists as outstanding for the device on `raw`.
async fn pending_on(raw: &RawDevice) -> OwnerConfirmationPendingResult {
    raw.read(
        Method::OwnerConfirmationPending,
        &OwnerConfirmationPendingParams {},
    )
    .await
    .expect("the list of challenges is read")
    .to_typed()
    .expect("a list")
}

/// KR-REQ-17.54: on a lapsed exclusive host the owner's device is shown, and may answer, only the
/// challenges that recover the host. A challenge for a member's invitation, asked for at the host,
/// is neither listed for it nor accepted from it; once a lease serves the device it is both, and
/// the answer is spent at the host to issue the invitation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lapsed_owner_device_is_neither_shown_nor_allowed_to_answer_a_members_invitation_and_a_leased_one_is()
 {
    let fixture = Fixture::start().await;
    let mut client = fixture.host.client().await;
    fixture
        .set_exclusive(&mut client, ActionId::new(kr_ipc::new_uuid()), true)
        .await
        .expect("the owner makes the host exclusive");
    // Making the host exclusive fences it, which withdraws the connection it was asked on.
    drop(client);
    // The host's local owner answers to a lease as a member does, and asks for what follows.
    fixture.lease_the_local_owner().await;
    let mut client = fixture.host.client().await;
    let proposed = ProposedGrant {
        organisation: Nullable::some(OrganisationRequirement {
            organisation_id: fixture.organisation.organisation_id,
            policy_revision: fixture.revision,
        }),
        ..net_support::proposal(&[ActionRight::SessionView])
    };
    let challenge = calls::request(
        fixture.host.environment_id,
        &mut client,
        ConfirmationSubject::IssueInvitation {
            mode: kr_protocol::invitation::InviteModeKind::Direct,
            rendezvous_origin: Nullable::null(),
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: proposed.clone(),
        },
    )
    .await
    .expect("the owner at the host asks for the member's invitation to be confirmed");

    let owner = OwnerDevice::of(&fixture).await;
    let raw = owner.connect().await;
    let environment = ActionTarget::environment(fixture.host.environment_id);
    let (proof, _) = calls::sign(&challenge.request, &Signer::OwnerDevice(&fixture.owner));
    let complete = || OwnerConfirmationCompleteParams {
        proof: proof.clone(),
        bootstrap_signer: Nullable::null(),
    };
    assert!(
        !pending_on(&raw)
            .await
            .pending
            .iter()
            .any(|shown| shown.request == challenge.request),
        "no lease serves the device, so it is not shown the invitation's challenge"
    );
    let refused = net_support::refusal(
        raw.mutate(
            Method::OwnerConfirmationComplete,
            ActionId::new(kr_ipc::new_uuid()),
            environment.clone(),
            &complete(),
        )
        .await,
    );
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");

    // Served by a lease, the same device is shown the challenge, answers it, and the owner at the
    // host issues the invitation on that answer.
    owner.present(&raw).await.expect("the owner's lease");
    assert!(
        pending_on(&raw)
            .await
            .pending
            .iter()
            .any(|shown| shown.request == challenge.request),
        "a leased device is shown the challenge"
    );
    raw.mutate(
        Method::OwnerConfirmationComplete,
        ActionId::new(kr_ipc::new_uuid()),
        environment,
        &complete(),
    )
    .await
    .expect("a leased owner device answers a member's invitation");
    raw.close();
    calls::mutate::<_, kr_protocol::invitation::PairInviteResult>(
        fixture.host.environment_id,
        &mut client,
        Method::PairInvite,
        &kr_protocol::invitation::PairInviteParams {
            mode: kr_protocol::invitation::InviteMode::Direct,
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: proposed,
        },
    )
    .await
    .expect("the host issues the invitation on the device's answer");
    drop(client);
    fixture.host.stop().await;
}

/// KR-REQ-17.54: what recovers an exclusive host is a device whose host management the
/// configuration leaves it. A rights ceiling that removes `host.manage` leaves no device that can
/// recover the host, so making the host exclusive is refused; one that keeps it allows that.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rights_ceiling_that_removes_host_management_leaves_no_device_that_can_recover_the_host()
{
    let ceiling_naming = |rights: &[ActionRight]| {
        let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
        document.ceilings.grant_rights = Nullable::some(
            rights
                .iter()
                .map(|right| right.as_str().to_owned())
                .collect(),
        );
        document
    };

    let fixture = Fixture::start_under(&ceiling_naming(&[ActionRight::SessionView])).await;
    let mut client = fixture.host.client().await;
    let refused = fixture
        .set_exclusive(&mut client, ActionId::new(kr_ipc::new_uuid()), true)
        .await
        .expect_err("the configuration removes host management from the owner's device");
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    assert!(!fixture.listed().await.exclusive);
    drop(client);
    fixture.host.stop().await;

    let fixture = Fixture::start_under(&ceiling_naming(&[
        ActionRight::SessionView,
        ActionRight::HostManage,
    ]))
    .await;
    let mut client = fixture.host.client().await;
    fixture
        .set_exclusive(&mut client, ActionId::new(kr_ipc::new_uuid()), true)
        .await
        .expect("a ceiling that keeps host management leaves a device that can recover the host");
    assert!(fixture.listed().await.exclusive);
    drop(client);
    fixture.host.stop().await;
}

/// KR-REQ-17.54: a change of exclusive management is written whole or not at all. When the store
/// refuses the record of the ending, the policy that went into the same transaction is not kept;
/// when it refuses the policy, no record is kept; each attempt spent its confirmation, and a stop
/// of the host after either leaves the host exclusive and its ending to be confirmed again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_write_ends_exclusive_management_in_neither_the_policy_nor_the_record_and_spends_the_confirmation()
 {
    let fixture = Fixture::start().await;
    let mut client = fixture.host.client().await;
    fixture
        .set_exclusive(&mut client, ActionId::new(kr_ipc::new_uuid()), true)
        .await
        .expect("the owner makes the host exclusive");
    // Making the host exclusive fences it, which withdraws the connection it was asked on.
    drop(client);
    let mut client = fixture.host.client().await;

    let end = async |client: &mut kr_ipc::client::LocalClient| {
        calls::mutate::<_, OrganisationExclusiveSetResult>(
            fixture.host.environment_id,
            client,
            Method::OrganisationExclusiveSet,
            &OrganisationExclusiveSetParams { exclusive: false },
        )
        .await
    };
    let confirm_ending = async |client: &mut kr_ipc::client::LocalClient| {
        calls::confirm_subject(
            fixture.host.environment_id,
            client,
            ConfirmationSubject::SetExclusiveManagement { exclusive: false },
            &Signer::OwnerDevice(&fixture.owner),
        )
        .await
        .expect("the owner device confirms ending it");
    };
    let refusing = |trigger: &str| {
        let blocker = rusqlite::Connection::open(fixture.host.registry_database())
            .expect("the registry opens");
        blocker
            .execute_batch(trigger)
            .expect("the fault is in place");
        blocker
    };

    // The record of the ending is refused.
    confirm_ending(&mut client).await;
    let blocker = refusing(
        "CREATE TRIGGER refuse_record BEFORE INSERT ON exclusive_management_events
         BEGIN SELECT RAISE(ABORT, 'no room'); END;",
    );
    end(&mut client)
        .await
        .expect_err("the store refuses the record");
    blocker
        .execute_batch("DROP TRIGGER refuse_record;")
        .expect("the fault is cleared");
    drop(blocker);
    let listed = fixture.listed().await;
    assert!(listed.exclusive, "the policy went with the record");
    assert!(listed.exclusive_events.is_empty());
    let refused = end(&mut client)
        .await
        .expect_err("the failed attempt spent the confirmation");
    assert_eq!(
        refused.code,
        ErrorCode::OwnerConfirmationRequired,
        "{refused:?}"
    );

    // The policy is refused.
    confirm_ending(&mut client).await;
    let blocker = refusing(
        "CREATE TRIGGER refuse_policy BEFORE INSERT ON host_authority
         WHEN NEW.key = 'policy'
         BEGIN SELECT RAISE(ABORT, 'no room'); END;",
    );
    end(&mut client)
        .await
        .expect_err("the store refuses the policy");
    blocker
        .execute_batch("DROP TRIGGER refuse_policy;")
        .expect("the fault is cleared");
    drop(blocker);
    let listed = fixture.listed().await;
    assert!(listed.exclusive);
    assert!(
        listed.exclusive_events.is_empty(),
        "no record without the policy"
    );
    drop(client);

    // A stop of the host after the spent confirmation turns nothing off.
    let fixture = fixture.restart().await;
    let listed = fixture.listed().await;
    assert!(
        listed.exclusive,
        "the host is still exclusive after a restart"
    );
    assert!(listed.exclusive_events.is_empty());
    let mut client = fixture.host.client().await;

    // Confirmed again, it ends, with its record.
    calls::confirm_subject(
        fixture.host.environment_id,
        &mut client,
        ConfirmationSubject::SetExclusiveManagement { exclusive: false },
        &Signer::OwnerDevice(&fixture.owner),
    )
    .await
    .expect("the owner device confirms again");
    let off: OrganisationExclusiveSetResult = calls::mutate(
        fixture.host.environment_id,
        &mut client,
        Method::OrganisationExclusiveSet,
        &OrganisationExclusiveSetParams { exclusive: false },
    )
    .await
    .expect("and the host ends it");
    assert!(!off.exclusive);
    let listed = fixture.listed().await;
    assert!(!listed.exclusive);
    assert_eq!(listed.exclusive_events.len(), 1);
    drop(client);
    fixture.host.stop().await;
}

/// KR-REQ-17.54: making the host exclusive never commits after the last device that could recover
/// it was revoked. The revocation lands while the change waits for the store; the change is
/// refused and the host stays as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn making_the_host_exclusive_never_commits_after_the_last_device_that_could_recover_it_was_revoked()
 {
    let fixture = Fixture::start().await;
    let mut client = fixture.host.client().await;
    calls::confirm_subject(
        fixture.host.environment_id,
        &mut client,
        ConfirmationSubject::SetExclusiveManagement { exclusive: true },
        &Signer::OwnerDevice(&fixture.owner),
    )
    .await
    .expect("the owner device confirms making the host exclusive");
    let (arrived, go) = fixture
        .host
        .controller()
        .sharing()
        .grants()
        .pause_before_effect();
    let environment = fixture.host.environment_id;
    let enabling = tokio::spawn(async move {
        let answer = calls::mutate::<_, OrganisationExclusiveSetResult>(
            environment,
            &mut client,
            Method::OrganisationExclusiveSet,
            &OrganisationExclusiveSetParams { exclusive: true },
        )
        .await;
        (client, answer)
    });
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the wait ends")
        .expect("the change reaches the store");

    // The revocation is written where the store reads it, as the host's own revocation does, while
    // the change waits. The pairing path would wait on the registry the change holds.
    rusqlite::Connection::open(fixture.host.registry_database())
        .expect("the registry opens")
        .execute(
            "UPDATE network_devices SET revoked_at_ms = ?1 WHERE revoked_at_ms IS NULL",
            [i64::try_from(kr_ipc::now_ms().get()).expect("a time")],
        )
        .expect("the last owner device is revoked");
    go.send(()).expect("the change waits");
    let (client, answer) = enabling.await.expect("the change ends");
    drop(client);
    let refused = answer.expect_err("no device is left that could recover the host");
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    assert!(!fixture.listed().await.exclusive);
    fixture.host.stop().await;
}

/// KR-REQ-17.54: exclusive management refuses no revocation. The fence that making the host
/// exclusive owes can stop a revocation admitted while it is owed; once it is retired the same
/// revocation, asked again at the host's socket, succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_stopped_by_the_fence_of_making_the_host_exclusive_succeeds_once_it_is_retired()
 {
    let fixture = Fixture::start().await;
    let helper = Device::create().await;
    let helper_record = net_support::pair_with(
        &fixture.host,
        &helper,
        &fixture.owner,
        net_support::proposal(&[ActionRight::SessionView]),
    )
    .await;
    let mut client = fixture.host.client().await;
    calls::confirm_subject(
        fixture.host.environment_id,
        &mut client,
        ConfirmationSubject::SetExclusiveManagement { exclusive: true },
        &Signer::OwnerDevice(&fixture.owner),
    )
    .await
    .expect("the owner device confirms");
    let fault = fence_support::refuse_fences(&fixture.host.tree().environment());
    calls::mutate::<_, OrganisationExclusiveSetResult>(
        fixture.host.environment_id,
        &mut client,
        Method::OrganisationExclusiveSet,
        &OrganisationExclusiveSetParams { exclusive: true },
    )
    .await
    .expect_err("the fence could not be raised");
    drop(client);

    // The fence is owed: the revocation is not admitted, and nothing about exclusive management
    // is what stopped it.
    let revoke = kr_protocol::sharing::DeviceRevokeParams {
        device_id: helper_record.device_id,
    };
    let mut client = fixture.host.client().await;
    calls::mutate::<_, RevocationResult>(
        fixture.host.environment_id,
        &mut client,
        Method::DeviceRevoke,
        &revoke,
    )
    .await
    .expect_err("the fence the change owes stops the revocation");
    drop(client);
    fence_support::clear_the_fault(&fault);
    drop(fault);

    let fixture = fixture.restart().await;
    fixture.until_the_fence_is_retired().await;
    let mut client = fixture.host.client().await;
    calls::mutate::<_, RevocationResult>(
        fixture.host.environment_id,
        &mut client,
        Method::DeviceRevoke,
        &revoke,
    )
    .await
    .expect("asked again at the host's socket, the revocation succeeds");
    assert!(fixture.listed().await.exclusive);
    drop(client);
    fixture.host.stop().await;
}
