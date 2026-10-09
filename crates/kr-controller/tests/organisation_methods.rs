//! Enrolling a host in an organisation's policy, through the methods the daemon serves.
//!
//! An owner opts the host in by pinning the chain of keys that signs an organisation's policy. The
//! chain is verified before anything is shown, an owner device confirms exactly that chain, and the
//! host writes the enrolment with the action's answer in one transaction. Everything here goes
//! through the owner's local socket and an owner device's own proofs, the way a person enrols; the
//! organisation is a stand-in that signs with real keys.

#![cfg(unix)]

mod net_support;
mod organisation_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use kr_client::pairing::paired::PairedHost;
use kr_controller::service::{Clocks, WallClock};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::account::PolicyAuthorityHead;
use kr_protocol::confirmation::{
    ConfirmationDisplay, ConfirmationSubject, OrganisationEnrolPlan, OwnerConfirmationRequestParams,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::OrganisationRequirement;
use kr_protocol::ids::{ActionId, AuthorityRevision, DeviceKeyRevision, PolicyKeyRevision};
use kr_protocol::invitation::{InviteGrantKind, InviteMode, PairInviteParams};
use kr_protocol::method::Method;
use kr_protocol::organisation::{
    OrganisationEnrolParams, OrganisationEnrolResult, OrganisationListParams,
    OrganisationListResult,
};
use kr_protocol::pairing::{KeyPurpose, NetworkConfig, ProposedGrant, SensitiveAction, key_id};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, Signature64, TimestampMs};
use net_support::pairing::{self as calls, Signer};
use net_support::{Device, Host, RawDevice, connect, pair_with, proposal};
use organisation_support::Organisation;

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

fn keys() -> DeviceKeys {
    DeviceKeys::generate().expect("keys")
}

/// An organisation whose second revision took over a day ago, and the chain it publishes now.
fn organisation(byte: u8) -> (Organisation, u64) {
    let now = kr_ipc::now_ms().get();
    let mut organisation = Organisation::new(byte, now - 2 * DAY_MS);
    organisation.rotate(now - DAY_MS);
    (organisation, now)
}

fn enrol_params(organisation: &Organisation, now: u64) -> OrganisationEnrolParams {
    OrganisationEnrolParams {
        authority: organisation.authority(now - 1_000),
    }
}

fn subject(params: &OrganisationEnrolParams) -> ConfirmationSubject {
    ConfirmationSubject::EnrolOrganisation(Box::new(params.clone()))
}

/// The record an owner's device keeps of `host`, from what the host says of itself.
fn paired_host(host: &Host) -> PairedHost {
    let owner = host.owner.clone().expect("the owner device");
    let identity = host.network().pairing().identity();
    PairedHost {
        host_device_id: identity.device_id,
        host_key_revision: DeviceKeyRevision::new(1),
        host_keys: identity.keys,
        host_endpoint_id: host.network().endpoint_id(),
        network_config: NetworkConfig::empty(),
        device_id: owner.device_id,
        grant_id: owner.grant.grant_id,
        proposed_grant: kr_pairing::grants::personal_owner_grant(),
        name: Some("studio".to_owned()),
        paired_at_ms: owner.paired_at_ms.get(),
    }
}

async fn list(client: &mut kr_ipc::client::LocalClient) -> OrganisationListResult {
    calls::read(
        client,
        Method::OrganisationList,
        &OrganisationListParams::default(),
    )
    .await
    .expect("the owner reads the list")
}

async fn enrol(
    host: &Host,
    client: &mut kr_ipc::client::LocalClient,
    action: ActionId,
    params: &OrganisationEnrolParams,
) -> Result<OrganisationEnrolResult, kr_protocol::error::ProtocolError> {
    calls::mutate_as(
        host.environment_id,
        client,
        action,
        Method::OrganisationEnrol,
        params,
    )
    .await
}

/// The number of actions this host holds a claim on: the rows a refused or unanswered request must
/// not leave behind.
fn claims(host: &Host) -> i64 {
    rusqlite::Connection::open(host.registry_database())
        .expect("the registry opens")
        .query_row("SELECT COUNT(*) FROM authority_receipts", [], |row| {
            row.get(0)
        })
        .expect("counts the claims")
}

/// KR-REQ-17.53: a daemon is enrolled from a signed chain. The owner asks for a confirmation of
/// the chain, an owner device is shown the keys and builds the digest from them, signs it, and the
/// host enrols; the list reports the enrolment at the first key and the key signing now, at both
/// doors, and the enrolment survives a restart of the daemon.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_is_enrolled_from_a_signed_chain_on_an_owner_devices_confirmation() {
    let owner = keys();
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let (organisation, now) = organisation(0x21);
    let params = enrol_params(&organisation, now);
    assert!(
        list(&mut client).await.enrolments.is_empty(),
        "a new host is enrolled in nothing"
    );

    let challenge = calls::request(host.environment_id, &mut client, subject(&params))
        .await
        .expect("the host verifies the chain and issues a challenge");
    assert_eq!(
        challenge.request.action,
        SensitiveAction::ChangeHostAuthority
    );
    // What an owner device is shown is the plan its digest covers, and the device rebuilds it.
    let pending = calls::pending(&mut client).await.expect("pending");
    let shown = pending
        .pending
        .iter()
        .find(|held| held.request.confirmation_id == challenge.request.confirmation_id)
        .expect("the challenge is listed for an owner to answer");
    let plan = OrganisationEnrolPlan::of_display(&shown.display).expect("an enrolment display");
    assert_eq!(
        plan,
        OrganisationEnrolPlan::of_authority(&params.authority).expect("a chain")
    );
    assert_eq!(
        plan.action_digest().expect("encodes"),
        challenge.request.action_digest,
        "the digest the owner device builds from what it is shown is the one it signs"
    );
    assert!(
        matches!(shown.display, ConfirmationDisplay::EnrolOrganisation { .. }),
        "{:?}",
        shown.display
    );
    // The owner's client checks what it is shown against the digest it is asked to sign, on the
    // host it knows, before it signs: a display that differs in any member, an activation time
    // included, is refused, and the line its platform's dialog shows names both keys.
    let paired = paired_host(&host);
    let subject_checked = kr_client::pairing::owner::check(shown, &paired)
        .expect("the owner's client takes the challenge the host issued");
    assert_eq!(
        subject_checked,
        kr_client::pairing::owner::Subject::EnrolOrganisation(plan)
    );
    let line = kr_client::pairing::owner::reason(&subject_checked, "studio", now)
        .expect("a line for the dialog");
    assert!(line.contains(" on studio"), "{line}");
    let mut altered = plan;
    altered.anchor.not_before_ms = TimestampMs::new(plan.anchor.not_before_ms.get() + 1);
    let swapped = kr_protocol::confirmation::PendingConfirmation {
        display: altered.display(),
        ..shown.clone()
    };
    assert_eq!(
        kr_client::pairing::owner::check(&swapped, &paired),
        Err(kr_client::pairing::owner::CannotCheck::DigestMismatch),
        "a display that differs from what the digest covers is not signed"
    );
    let elsewhere = PairedHost {
        host_endpoint_id: DeviceKeys::generate()
            .expect("keys")
            .public_keys()
            .transport,
        ..paired.clone()
    };
    assert_eq!(
        kr_client::pairing::owner::check(shown, &elsewhere),
        Err(kr_client::pairing::owner::CannotCheck::AnotherHost),
        "and neither is a challenge of another host"
    );

    let (proof, bootstrap) = calls::sign(&challenge.request, &Signer::OwnerDevice(&owner));
    calls::complete(host.environment_id, &mut client, proof, bootstrap)
        .await
        .expect("the owner device's proof answers the challenge");

    let action = ActionId::new(kr_ipc::new_uuid());
    let enrolled = enrol(&host, &mut client, action, &params)
        .await
        .expect("the host enrols");
    assert_eq!(enrolled.organisation_id, organisation.organisation_id);
    assert_eq!(enrolled.accepted_head, PolicyKeyRevision::new(2));
    assert_eq!(
        enrolled.root_key_id,
        key_id(
            KeyPurpose::Authorisation,
            organisation.link(1).payload.public_key.as_bytes()
        )
    );
    let revision = enrolled.enrolment_revision;

    let listed = list(&mut client).await;
    assert_eq!(listed.enrolments.len(), 1);
    let view = &listed.enrolments[0];
    assert_eq!(view.organisation_id, organisation.organisation_id);
    assert_eq!(view.root_key_id, enrolled.root_key_id);
    assert_eq!(view.anchor_revision, PolicyKeyRevision::new(2));
    assert_eq!(
        view.anchor_key_id,
        key_id(
            KeyPurpose::Authorisation,
            organisation.link(2).payload.public_key.as_bytes()
        )
    );
    assert_eq!(view.accepted_head, PolicyKeyRevision::new(2));
    assert_eq!(view.enrolment_revision, revision);
    assert!(view.members.is_empty());
    assert!(!listed.exclusive && listed.clock_trusted);
    assert!(listed.exclusive_events.is_empty());

    // An owner device reads the same list at the paired door, and a device that does not manage the
    // host is refused it.
    let owner_device = host.owner_device.as_ref().expect("the owner device");
    let owner_record = host.owner.as_ref().expect("the owner device's record");
    let session = connect(&host, owner_device, owner_record).await;
    let at_the_door: OrganisationListResult = session
        .read(Method::OrganisationList, &OrganisationListParams::default())
        .await
        .expect("an owner device reads the list");
    assert_eq!(at_the_door, listed);
    let (_viewer, viewer_session) =
        net_support::paired_device(&host, &owner, &[ActionRight::SessionView]).await;
    let refused = viewer_session
        .read::<_, OrganisationListResult>(
            Method::OrganisationList,
            &OrganisationListParams::default(),
        )
        .await
        .expect_err("a device that does not manage the host reads nothing of it");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);

    // A repeat of the action is answered from the record, and asks for no new confirmation.
    let again = enrol(&host, &mut client, action, &params)
        .await
        .expect("a repeat of the action is answered");
    assert_eq!(again, enrolled);

    // The enrolment is written down: a restarted daemon holds it, with no lease. Every client is
    // closed first, since each holds the daemon until it is.
    session.close();
    viewer_session.close();
    drop(client);
    let host = host.restart().await;
    let mut client = host.client().await;
    let after = list(&mut client).await;
    assert_eq!(after.enrolments, listed.enrolments);
    host.stop().await;
}

/// KR-REQ-17.53: nothing enrols without the owner's confirmation of exactly this chain, and what
/// is refused leaves nothing behind: no enrolment, no claim on the action, and a confirmation for
/// another chain still unspent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrolment_needs_the_owners_confirmation_of_exactly_this_chain() {
    let owner = keys();
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let (organisation, now) = organisation(0x21);
    let params = enrol_params(&organisation, now);
    let (other, _) = self::organisation(0x22);
    let other_params = enrol_params(&other, now);
    let baseline = claims(&host);

    // No confirmation: refused, and polling for one leaves no claim row per attempt.
    for _ in 0..3 {
        let refused = enrol(
            &host,
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            &params,
        )
        .await
        .expect_err("an unconfirmed enrolment is refused");
        assert_eq!(refused.code, ErrorCode::OwnerConfirmationRequired);
    }
    assert_eq!(claims(&host), baseline, "a poll claims nothing");

    // A confirmation for another organisation's chain does not enrol this one, and is left
    // unspent: it still enrols the chain it names.
    calls::confirm_subject(
        host.environment_id,
        &mut client,
        subject(&other_params),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("the owner confirms another chain");
    let refused = enrol(
        &host,
        &mut client,
        ActionId::new(kr_ipc::new_uuid()),
        &params,
    )
    .await
    .expect_err("a confirmation of another chain is not this chain's");
    assert_eq!(refused.code, ErrorCode::OwnerConfirmationRequired);
    assert!(list(&mut client).await.enrolments.is_empty());
    enrol(
        &host,
        &mut client,
        ActionId::new(kr_ipc::new_uuid()),
        &other_params,
    )
    .await
    .expect("the confirmation still enrols the chain it named");
    assert_eq!(list(&mut client).await.enrolments.len(), 1);

    // The same action with other parameters is a conflict, not a second enrolment. The parameters
    // are checked before a confirmation is looked for, so the conflict is the answer even though
    // no confirmation stands for them.
    let action = ActionId::new(kr_ipc::new_uuid());
    calls::confirm_subject(
        host.environment_id,
        &mut client,
        subject(&params),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("the owner confirms the first chain");
    enrol(&host, &mut client, action, &params)
        .await
        .expect("the first chain enrols under the action");
    let third = self::organisation(0x23).0;
    let conflict = enrol(&host, &mut client, action, &enrol_params(&third, now))
        .await
        .expect_err("the action is taken by other parameters");
    assert_eq!(conflict.code, ErrorCode::IdConflict, "{conflict:?}");
    assert_eq!(list(&mut client).await.enrolments.len(), 2);
    host.stop().await;
}

/// KR-REQ-17.53: a chain that does not verify is not shown to an owner at all. The host checks the
/// whole chain first, so no challenge is issued for a link signed by the wrong key, a head by
/// another key, a head that is not current, or an organisation the host is enrolled in already.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_that_does_not_verify_is_not_shown_to_an_owner() {
    let owner = keys();
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let (organisation, now) = organisation(0x21);
    let good = enrol_params(&organisation, now);

    let mut forged_link = good.clone();
    forged_link.authority.chain[1].signature = Signature64::from_bytes([7; 64]);
    let mut forged_head = good.clone();
    forged_head.authority.head = PolicyAuthorityHead {
        signature: Signature64::from_bytes([9; 64]),
        ..forged_head.authority.head
    };
    let stale = OrganisationEnrolParams {
        authority: organisation.authority(now - 3_600_000),
    };
    let foreign_head = {
        let (other, _) = self::organisation(0x22);
        let mut params = good.clone();
        params.authority.head = other.authority(now - 1_000).head;
        params
    };
    for (name, params) in [
        ("a link signed by another key", &forged_link),
        ("a head signed by another key", &forged_head),
        ("a head that is not current", &stale),
        ("a head of another organisation", &foreign_head),
    ] {
        let refused = calls::request(host.environment_id, &mut client, subject(params))
            .await
            .expect_err(name);
        assert_eq!(
            refused.code,
            ErrorCode::InvalidArgument,
            "{name}: {refused:?}"
        );
    }
    // A change of exclusive management is described by this host's policy and not by the caller,
    // so a caller cannot obtain a confirmation of one by naming it.
    let refused = calls::request(
        host.environment_id,
        &mut client,
        ConfirmationSubject::SetExclusiveManagement { exclusive: true },
    )
    .await
    .expect_err("this host describes no change of exclusive management to an owner");
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    assert!(
        calls::pending(&mut client)
            .await
            .expect("pending")
            .pending
            .is_empty(),
        "no challenge was issued for a chain that does not verify"
    );

    // The control: the intact chain is shown, confirmed and enrolled.
    calls::confirm_subject(
        host.environment_id,
        &mut client,
        subject(&good),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("the intact chain is shown");
    enrol(&host, &mut client, ActionId::new(kr_ipc::new_uuid()), &good)
        .await
        .expect("and enrols");
    let again = calls::request(host.environment_id, &mut client, subject(&good))
        .await
        .expect_err("a host enrolled in an organisation withdraws before it enrols again");
    assert_eq!(again.code, ErrorCode::InvalidArgument);
    host.stop().await;
}

/// KR-REQ-17.53: enrolment is the owner's. A paired device does not reach it, and one that does not
/// manage the host cannot ask for the confirmation either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_owner_enrols_and_a_device_does_not_reach_enrolment() {
    let owner = keys();
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let (organisation, now) = organisation(0x21);
    let params = enrol_params(&organisation, now);
    calls::confirm_subject(
        host.environment_id,
        &mut client,
        subject(&params),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("the owner confirms the chain");

    let device = Device::create().await;
    let record = pair_with(
        &host,
        &device,
        &owner,
        proposal(&[ActionRight::HostManage, ActionRight::SessionView]),
    )
    .await;
    let raw = RawDevice::connect(&host, &device, &record).await;
    raw.claim();
    let refused = net_support::refusal(
        raw.mutate(
            Method::OrganisationEnrol,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await,
    );
    assert_eq!(
        refused.code,
        ErrorCode::PermissionDenied,
        "a device that manages the host does not reach enrolment either"
    );
    raw.close();

    let viewer = Device::create().await;
    let viewer_record = pair_with(
        &host,
        &viewer,
        &owner,
        proposal(&[ActionRight::SessionView]),
    )
    .await;
    let raw = RawDevice::connect(&host, &viewer, &viewer_record).await;
    raw.claim();
    let refused = net_support::refusal(
        raw.mutate(
            Method::OwnerConfirmationRequest,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &OwnerConfirmationRequestParams {
                subject: subject(&params),
            },
        )
        .await,
    );
    assert_eq!(refused.code, ErrorCode::PermissionDenied);
    raw.close();
    assert!(list(&mut client).await.enrolments.is_empty());
    host.stop().await;
}

/// KR-REQ-17.53: a write the store refuses enrols nothing. The confirmation was spent before the
/// write, so the owner confirms again, and what the failed attempt claimed is never performed
/// again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_policy_write_the_store_refuses_enrols_nothing_and_spends_the_confirmation() {
    let owner = keys();
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let (organisation, now) = organisation(0x21);
    let params = enrol_params(&organisation, now);
    calls::confirm_subject(
        host.environment_id,
        &mut client,
        subject(&params),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("the owner confirms the chain");

    let blocker = rusqlite::Connection::open(host.registry_database()).expect("the registry opens");
    blocker
        .execute_batch(
            "CREATE TRIGGER refuse_policy BEFORE INSERT ON host_authority
             WHEN NEW.key = 'policy'
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the policy's write is refused");
    let action = ActionId::new(kr_ipc::new_uuid());
    enrol(&host, &mut client, action, &params)
        .await
        .expect_err("the store refuses the write");
    blocker
        .execute_batch("DROP TRIGGER refuse_policy;")
        .expect("the write is taken again");
    drop(blocker);
    assert!(
        list(&mut client).await.enrolments.is_empty(),
        "nothing was enrolled"
    );

    // The confirmation went with the attempt.
    let refused = enrol(
        &host,
        &mut client,
        ActionId::new(kr_ipc::new_uuid()),
        &params,
    )
    .await
    .expect_err("the confirmation was spent");
    assert_eq!(refused.code, ErrorCode::OwnerConfirmationRequired);
    // And the failed attempt's action is not performed again: its claim has no outcome.
    let unknown = enrol(&host, &mut client, action, &params)
        .await
        .expect_err("the outcome of that attempt is not known");
    assert_eq!(unknown.code, ErrorCode::OutcomeUnknown, "{unknown:?}");
    assert!(list(&mut client).await.enrolments.is_empty());

    // Confirmed again, the chain enrols.
    calls::confirm_subject(
        host.environment_id,
        &mut client,
        subject(&params),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("the owner confirms again");
    enrol(
        &host,
        &mut client,
        ActionId::new(kr_ipc::new_uuid()),
        &params,
    )
    .await
    .expect("and the host enrols");
    assert_eq!(list(&mut client).await.enrolments.len(), 1);
    host.stop().await;
}

/// KR-REQ-17.53: the enrolment and the answer to the action that asked for it are written together
/// or not at all. When the store refuses the answer, the enrolment that went into the same
/// transaction is not kept, the confirmation is spent, and the action's outcome is not known.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_the_store_refuses_takes_the_enrolment_with_it() {
    let owner = keys();
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let (organisation, now) = organisation(0x21);
    let params = enrol_params(&organisation, now);
    let signer = Signer::OwnerDevice(&owner);
    calls::confirm_subject(host.environment_id, &mut client, subject(&params), &signer)
        .await
        .expect("the owner confirms the chain");

    let blocker = rusqlite::Connection::open(host.registry_database()).expect("the registry opens");
    blocker
        .execute_batch(
            "CREATE TRIGGER refuse_answer BEFORE UPDATE OF result ON authority_receipts
             WHEN NEW.result IS NOT NULL
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the answer's write is refused");
    let action = ActionId::new(kr_ipc::new_uuid());
    enrol(&host, &mut client, action, &params)
        .await
        .expect_err("the store refuses the answer");
    blocker
        .execute_batch("DROP TRIGGER refuse_answer;")
        .expect("the write is taken again");
    drop(blocker);
    assert!(
        list(&mut client).await.enrolments.is_empty(),
        "the policy that went with the answer was not kept"
    );
    let unknown = enrol(&host, &mut client, action, &params)
        .await
        .expect_err("the outcome of that attempt is not known");
    assert_eq!(unknown.code, ErrorCode::OutcomeUnknown, "{unknown:?}");

    calls::confirm_subject(host.environment_id, &mut client, subject(&params), &signer)
        .await
        .expect("the owner confirms again");
    enrol(
        &host,
        &mut client,
        ActionId::new(kr_ipc::new_uuid()),
        &params,
    )
    .await
    .expect("and the host enrols");
    assert_eq!(list(&mut client).await.enrolments.len(), 1);
    host.stop().await;
}

/// The requirement a member's grant names, at the revision the host enrolled at.
fn member_grant(
    organisation: &Organisation,
    policy_revision: AuthorityRevision,
    rights: &[ActionRight],
) -> ProposedGrant {
    ProposedGrant {
        organisation: Nullable::some(OrganisationRequirement {
            organisation_id: organisation.organisation_id,
            policy_revision,
        }),
        ..proposal(rights)
    }
}

/// KR-REQ-17.53: an invitation proposes only access the host can answer for. A proposal that
/// requires an organisation the host is not enrolled in, names another enrolment revision, or
/// carries a right above what the owner role may hold is refused before it is confirmed or issued,
/// and a conforming one pairs a member device whose grant keeps its requirement.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invitation_proposes_only_an_organisation_this_host_is_enrolled_in() {
    let owner = keys();
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let (organisation, now) = organisation(0x21);
    let params = enrol_params(&organisation, now);
    let signer = Signer::OwnerDevice(&owner);

    // Before the enrolment nothing requires this organisation.
    let proposed = member_grant(
        &organisation,
        AuthorityRevision::new(1),
        &[ActionRight::SessionView],
    );
    let refused = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &proposed,
        &signer,
    )
    .await
    .expect_err("the host is enrolled in no organisation");
    assert_eq!(refused.code, ErrorCode::InvalidArgument);

    calls::confirm_subject(host.environment_id, &mut client, subject(&params), &signer)
        .await
        .expect("the owner confirms the chain");
    let enrolled = enrol(
        &host,
        &mut client,
        ActionId::new(kr_ipc::new_uuid()),
        &params,
    )
    .await
    .expect("the host enrols");
    let revision = enrolled.enrolment_revision;

    for (name, grant) in [
        (
            "another enrolment revision",
            member_grant(
                &organisation,
                AuthorityRevision::new(revision.get() + 1),
                &[ActionRight::SessionView],
            ),
        ),
        (
            "a right above the owner role",
            member_grant(&organisation, revision, &[ActionRight::HostManage]),
        ),
        (
            "another organisation",
            member_grant(
                &self::organisation(0x22).0,
                revision,
                &[ActionRight::SessionView],
            ),
        ),
    ] {
        let refused = calls::invite_direct(
            host.environment_id,
            &mut client,
            InviteGrantKind::SessionInvitation,
            &grant,
            &signer,
        )
        .await
        .expect_err(name);
        assert_eq!(
            refused.code,
            ErrorCode::InvalidArgument,
            "{name}: {refused:?}"
        );
        // The invitation's own check does not depend on the request for a confirmation having
        // refused first: with no confirmation at all, the proposal is refused for what it
        // requires, and a conforming one is asked for its confirmation instead.
        let refused = calls::mutate::<_, kr_protocol::invitation::PairInviteResult>(
            host.environment_id,
            &mut client,
            Method::PairInvite,
            &PairInviteParams {
                mode: InviteMode::Direct,
                grant_kind: InviteGrantKind::SessionInvitation,
                proposed_grant: grant,
            },
        )
        .await
        .expect_err(name);
        assert_eq!(
            refused.code,
            ErrorCode::InvalidArgument,
            "{name} at the invitation: {refused:?}"
        );
    }
    let unconfirmed = calls::mutate::<_, kr_protocol::invitation::PairInviteResult>(
        host.environment_id,
        &mut client,
        Method::PairInvite,
        &PairInviteParams {
            mode: InviteMode::Direct,
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: member_grant(&organisation, revision, &[ActionRight::SessionView]),
        },
    )
    .await
    .expect_err("a conforming proposal still needs the owner's confirmation");
    assert_eq!(unconfirmed.code, ErrorCode::OwnerConfirmationRequired);

    // The control: a proposal that conforms pairs a member device whose grant keeps the
    // requirement it was issued with.
    let device = Device::create().await;
    let record = pair_with(
        &host,
        &device,
        &owner,
        member_grant(&organisation, revision, &[ActionRight::SessionView]),
    )
    .await;
    let requirement = record
        .grant
        .organisation
        .as_ref()
        .expect("the member's grant requires the organisation");
    assert_eq!(requirement.organisation_id, organisation.organisation_id);
    assert_eq!(requirement.policy_revision, revision);
    host.stop().await;
}

/// A wall clock the suite moves by hand, in milliseconds either way from the machine's own, and
/// the clocks a daemon runs on with it.
fn moved_clocks() -> (Arc<AtomicI64>, Clocks) {
    let moved = Arc::new(AtomicI64::new(0));
    let read = Arc::clone(&moved);
    let wall = WallClock::from_fn(move || {
        kr_ipc::now_ms()
            .get()
            .saturating_add_signed(read.load(Ordering::SeqCst))
    });
    (
        moved,
        Clocks {
            wall,
            ..Clocks::system()
        },
    )
}

/// Asks for the enrolment under `action`, as the owner's client does, stops it where it has
/// done everything but take the store's transaction, runs `meanwhile`, and lets it go.
async fn enrol_while_it_waits(
    host: &Host,
    client: kr_ipc::client::LocalClient,
    params: &OrganisationEnrolParams,
    meanwhile: impl AsyncFnOnce(),
) -> (
    kr_ipc::client::LocalClient,
    Result<OrganisationEnrolResult, kr_protocol::error::ProtocolError>,
) {
    let (arrived, go) = host.controller().sharing().grants().pause_before_effect();
    let environment_id = host.environment_id;
    let params = params.clone();
    let enrolment = tokio::spawn(async move {
        let mut client = client;
        let answer = calls::mutate_as(
            environment_id,
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            Method::OrganisationEnrol,
            &params,
        )
        .await;
        (client, answer)
    });
    tokio::task::spawn_blocking(move || arrived.recv())
        .await
        .expect("the wait ends")
        .expect("the enrolment reaches the store");
    meanwhile().await;
    go.send(()).expect("the enrolment waits");
    enrolment.await.expect("the enrolment ends")
}

/// KR-REQ-17.53: a chain is enrolled only while its head is current, to the moment the policy is
/// written. The head is judged before the enrolment waits for the locks it writes under, and its
/// lifetime is a bound that can pass during the wait: an enrolment that waits past it enrols
/// nothing, and the same enrolment that does not wait past it enrols.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_head_that_runs_out_while_the_enrolment_waits_for_the_store_enrols_nothing() {
    let owner = keys();
    let (moved, clocks) = moved_clocks();
    let host = Host::start_on_clocks(&owner, clocks).await;
    let mut client = host.client().await;
    let signer = Signer::OwnerDevice(&owner);

    // The control: the pause alone, with the head current when the transaction opens, enrols.
    let (organisation, now) = organisation(0x21);
    let params = enrol_params(&organisation, now);
    calls::confirm_subject(host.environment_id, &mut client, subject(&params), &signer)
        .await
        .expect("the owner confirms the chain");
    let (mut client, answer) = enrol_while_it_waits(&host, client, &params, async || {}).await;
    answer.expect("a head that is current when the policy is written enrols");
    assert_eq!(list(&mut client).await.enrolments.len(), 1);

    // The head ends during the wait. The owner's confirmation is still inside its own deadline.
    let (late, now) = self::organisation(0x22);
    let params = enrol_params(&late, now);
    calls::confirm_subject(host.environment_id, &mut client, subject(&params), &signer)
        .await
        .expect("the owner confirms the second chain");
    let passed = i64::try_from(2 * 60 * 60 * 1000).expect("fits");
    let (mut client, answer) = enrol_while_it_waits(&host, client, &params, async || {
        moved.fetch_add(passed, Ordering::SeqCst);
    })
    .await;
    let refused = answer.expect_err("the head ran out before the policy was written");
    assert!(
        matches!(
            refused.code,
            ErrorCode::InvalidArgument | ErrorCode::StorageUnavailable
        ),
        "{refused:?}"
    );
    let listed = list(&mut client).await;
    assert_eq!(
        listed.enrolments.len(),
        1,
        "only the first chain is enrolled"
    );
    assert_ne!(listed.enrolments[0].organisation_id, late.organisation_id);
    host.stop().await;
}

/// KR-REQ-17.53: the owner's confirmation is a decision made now, and the enrolment asks whether
/// it still is where it writes the policy. A confirmation whose short life passes while the
/// enrolment waits for the store enrols nothing and is spent; the owner confirms the chain again,
/// and the same enrolment then goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_confirmation_that_runs_out_while_the_enrolment_waits_for_the_store_enrols_nothing() {
    let owner = keys();
    let host = Host::start(&owner).await;
    let client = host.client().await;
    let (organisation, now) = organisation(0x21);
    let params = enrol_params(&organisation, now);
    let signer = Signer::OwnerDevice(&owner);
    let mut client = client;
    calls::confirm_subject(host.environment_id, &mut client, subject(&params), &signer)
        .await
        .expect("the owner confirms the chain");

    let owner_authority = Arc::clone(host.controller().owner_authority());
    let (mut client, answer) = enrol_while_it_waits(&host, client, &params, async || {
        owner_authority.pass(std::time::Duration::from_secs(10 * 60));
    })
    .await;
    let refused = answer.expect_err("the confirmation ran out before the policy was written");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        list(&mut client).await.enrolments.is_empty(),
        "nothing was enrolled"
    );

    // The control: a confirmation inside its life enrols the same chain.
    calls::confirm_subject(host.environment_id, &mut client, subject(&params), &signer)
        .await
        .expect("the owner confirms the chain again");
    enrol(
        &host,
        &mut client,
        ActionId::new(kr_ipc::new_uuid()),
        &params,
    )
    .await
    .expect("and the host enrols");
    assert_eq!(list(&mut client).await.enrolments.len(), 1);
    host.stop().await;
}

/// KR-REQ-17.53: a host that distrusts its clock shows an owner no chain and enrols nothing: a
/// head is current only against a clock the host trusts, and an owner establishes the clock again
/// before any chain is judged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_distrusts_its_clock_shows_an_owner_no_chain() {
    let owner = keys();
    let (moved, clocks) = moved_clocks();
    let host = Host::start_on_clocks(&owner, clocks).await;
    let mut client = host.client().await;
    let (organisation, now) = organisation(0x21);
    let params = enrol_params(&organisation, now);
    assert!(list(&mut client).await.clock_trusted);

    // The wall clock steps back by more than the host forgives, and the next reading finds it.
    let back = i64::try_from(kr_controller::service::net::devices::CLOCK_TOLERANCE_MS + 60_000)
        .expect("fits");
    moved.fetch_sub(back, Ordering::SeqCst);
    assert!(
        !list(&mut client).await.clock_trusted,
        "the host finds the step back"
    );
    let refused = calls::request(host.environment_id, &mut client, subject(&params))
        .await
        .expect_err("no chain is judged at a clock that is not trusted");
    assert_eq!(refused.code, ErrorCode::ClockUntrusted, "{refused:?}");
    let refused = enrol(
        &host,
        &mut client,
        ActionId::new(kr_ipc::new_uuid()),
        &params,
    )
    .await
    .expect_err("and none is enrolled");
    assert!(
        matches!(
            refused.code,
            ErrorCode::ClockUntrusted | ErrorCode::OwnerConfirmationRequired
        ),
        "{refused:?}"
    );
    assert!(list(&mut client).await.enrolments.is_empty());
    host.stop().await;
}
