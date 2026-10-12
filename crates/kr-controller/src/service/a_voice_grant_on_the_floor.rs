//! The voice coordinator's reads of a grant, decided on this host's clock floor.
//!
//! A voice call asks the host four things about authority: the device's ordinary grant, its
//! standing voice grant, one grant by identity, and, when an effect is about to run, whether the
//! grant the call was admitted under still stands. Each is a decision about a time bound, and every
//! decision about one on this host is taken the same way: on the continuous clock the grant was
//! anchored on and on UTC read through the clock floor, which a reading raises and which is written
//! down. A wall clock wound back does not bring a grant that ran out back to life, and a grant whose
//! end is found while the floor cannot be written is not stated to have ended: it is refused with the
//! host's own reason, because a daemon started in a new boot could decide the other way.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{AuthorityRevision, DeviceId, GrantId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};
use kr_voice::seams::VoiceAuthority as _;

use crate::grants::GrantRecord;
use crate::service::Controller;
use crate::service::net::devices::DeviceRecord;
use crate::service::net::tests::{daemon_on, manual_clocks};
use crate::voice::GrantAuthority;

/// A grant to `device_id` carrying `actions`, which stands until `expires_at_ms` in UTC.
fn grant(
    device_id: DeviceId,
    actions: &[ActionRight],
    expires_at_ms: Option<u64>,
    revision: AuthorityRevision,
) -> Grant {
    Grant {
        grant_id: GrantId::new(kr_ipc::new_uuid()),
        parent_grant_id: Nullable::null(),
        issuer_device_id: device_id,
        recipient_device_id: device_id,
        authority_revision: revision,
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: actions.iter().copied().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: expires_at_ms.map_or(GrantExpiry::Never, |expires_at_ms| GrantExpiry::At {
            expires_at_ms: TimestampMs::new(expires_at_ms),
        }),
        organisation: Nullable::null(),
    }
}

/// A device committed to `controller`'s records, paired under a grant that carries viewing and
/// stands until `expires_at_ms`, or for ever.
pub(super) fn paired(
    controller: &Controller,
    byte: u8,
    expires_at_ms: Option<u64>,
) -> DeviceRecord {
    paired_holding(controller, byte, &[ActionRight::SessionView], expires_at_ms)
}

/// As [`paired`], under a grant that carries `rights`.
pub(super) fn paired_holding(
    controller: &Controller,
    byte: u8,
    rights: &[ActionRight],
    expires_at_ms: Option<u64>,
) -> DeviceRecord {
    paired_signing_as(
        controller,
        byte,
        kr_protocol::scalars::AuthorisationKey::from_bytes([byte; 32]),
        rights,
        expires_at_ms,
    )
}

/// As [`paired_holding`], for a device whose identity key is `authorisation`, so that what it
/// signs is checked against the key this host holds for it.
pub(super) fn paired_signing_as(
    controller: &Controller,
    byte: u8,
    authorisation: kr_protocol::scalars::AuthorisationKey,
    rights: &[ActionRight],
    expires_at_ms: Option<u64>,
) -> DeviceRecord {
    paired_on(
        controller,
        byte,
        authorisation,
        rights,
        expires_at_ms,
        Nullable::null(),
    )
}

/// As [`paired_holding`], for a device whose grant requires membership of an organisation this host
/// is not enrolled in, so that no lease answers for it.
pub(super) fn paired_needing_a_lease(
    controller: &Controller,
    byte: u8,
    rights: &[ActionRight],
) -> DeviceRecord {
    paired_on(
        controller,
        byte,
        kr_protocol::scalars::AuthorisationKey::from_bytes([byte; 32]),
        rights,
        None,
        Nullable::some(kr_protocol::grant::OrganisationRequirement {
            organisation_id: kr_protocol::ids::OrganisationId::new(kr_ipc::new_uuid()),
            policy_revision: controller.policy().authority_revision(),
        }),
    )
}

fn paired_on(
    controller: &Controller,
    byte: u8,
    authorisation: kr_protocol::scalars::AuthorisationKey,
    rights: &[ActionRight],
    expires_at_ms: Option<u64>,
    organisation: Nullable<kr_protocol::grant::OrganisationRequirement>,
) -> DeviceRecord {
    let revision = controller.policy().authority_revision();
    let device_id = DeviceId::new(kr_ipc::new_uuid());
    let device = DeviceRecord {
        device_id,
        endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes([byte; 32]),
        device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(1),
        authorisation,
        stored_envelope: None,
        notification_preview: None,
        device_name: kr_protocol::pairing::DeviceName::new("A phone").expect("a name"),
        platform: kr_protocol::pairing::DevicePlatform::Ios,
        grant: Grant {
            organisation,
            ..grant(device_id, rights, expires_at_ms, revision)
        },
        paired_at_ms: TimestampMs::new(1),
        revoked_at_ms: None,
        committed_invitation_id: None,
        expired_at_ms: None,
    };
    controller.devices().commit(&device).expect("paired");
    device
}

/// A voice grant `device` holds in the grant store, which stands until `expires_at_ms`.
fn voice_grant(controller: &Controller, device: &DeviceRecord, expires_at_ms: u64) -> Grant {
    let voice = Grant {
        issuer_device_id: controller.sharing().host_device_id(),
        ..grant(
            device.device_id,
            &[ActionRight::VoiceUse, ActionRight::SessionView],
            Some(expires_at_ms),
            controller.policy().authority_revision(),
        )
    };
    controller
        .sharing()
        .grants()
        .issue(
            &GrantRecord {
                grant: voice.clone(),
                session_id: None,
                issued_at_ms: 1,
                activated_at_ms: Some(1),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("a live voice grant");
    voice
}

/// The seam the coordinator reads this host's grants through, over the stores a daemon keeps.
pub(super) fn authority(controller: &Arc<Controller>) -> GrantAuthority {
    GrantAuthority::new(
        Arc::clone(controller.sharing()),
        Arc::clone(controller.devices()),
        controller.sharing().host_device_id(),
        Arc::downgrade(controller),
    )
}

/// The store takes no record of an expiry, as on a full disk: for the grant store, or for the
/// table of paired devices.
fn refuse_expiry_records(temp: &kr_ipc::testing::TempHost, table: &str) -> rusqlite::Connection {
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("opens the registry");
    registry
        .execute_batch(&format!(
            "CREATE TRIGGER refuse_expiry BEFORE UPDATE ON {table}
             WHEN NEW.expired_at_ms IS NOT NULL
             BEGIN SELECT RAISE(ABORT, 'no room'); END;"
        ))
        .expect("the fault is in place");
    registry
}

/// A grant shared with `device`, which requires membership of an organisation this host is not
/// enrolled in when `needs_a_lease`.
fn shared_with(
    controller: &Controller,
    device: &DeviceRecord,
    rights: &[ActionRight],
    needs_a_lease: bool,
) -> Grant {
    let shared = Grant {
        issuer_device_id: controller.sharing().host_device_id(),
        organisation: if needs_a_lease {
            Nullable::some(kr_protocol::grant::OrganisationRequirement {
                organisation_id: kr_protocol::ids::OrganisationId::new(kr_ipc::new_uuid()),
                policy_revision: controller.policy().authority_revision(),
            })
        } else {
            Nullable::null()
        },
        ..grant(
            device.device_id,
            rights,
            None,
            controller.policy().authority_revision(),
        )
    };
    controller
        .sharing()
        .grants()
        .issue(
            &GrantRecord {
                grant: shared.clone(),
                session_id: None,
                issued_at_ms: 1,
                activated_at_ms: Some(1),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("a grant shared with the device");
    shared
}

/// KR-REQ-26.16: a share that needs a lease this host holds none for does not stand in the way of the
/// grant the device was paired under, even where the share carries more rights. The share is refused
/// as a typed request under it would be, and the pairing grant answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_share_the_host_refuses_does_not_stand_in_the_way_of_the_pairing_grant() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, _wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let device = paired_holding(&controller, 64, &[ActionRight::SessionView], None);
    shared_with(
        &controller,
        &device,
        &[ActionRight::SessionView, ActionRight::SessionClose],
        true,
    );

    let read = authority(&controller)
        .device_grant(device.device_id, None)
        .expect("the host answers")
        .expect("a grant the host lets be used");

    assert_eq!(read.grant_id, device.grant.grant_id);
    assert!(!read.permits(ActionRight::SessionClose));
}

/// KR-REQ-26.16: a request under a share needs the grant the device was paired under to stand under
/// the host's policy, so a pairing grant the host refuses leaves no share to answer for the device.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pairing_grant_the_host_refuses_leaves_no_share_to_answer() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, _wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let device = paired_needing_a_lease(
        &controller,
        65,
        &[ActionRight::SessionView, ActionRight::SessionClose],
    );
    shared_with(&controller, &device, &[ActionRight::SessionView], false);

    let refused = authority(&controller)
        .device_grant(device.device_id, None)
        .expect_err("the pairing grant needs a lease this host holds none for");

    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refused}"
    );
}

/// KR-REQ-15.11: a device paired as an owner, with every right the voice right included, is given
/// a voice grant over its ordinary grant. The voice right in the grant it was paired under is not
/// what makes a grant a voice grant, and the ordinary grant a call narrows carries the rights it
/// does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_paired_with_every_right_is_read_without_the_voice_right() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, _wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let owner = paired_holding(&controller, 67, ActionRight::ALL, None);

    let read = authority(&controller)
        .device_grant(owner.device_id, None)
        .expect("the host answers")
        .expect("the pairing grant is the device's ordinary grant");

    assert_eq!(read.grant_id, owner.grant.grant_id);
    assert!(read.permits(ActionRight::SessionClose));
    assert!(!read.permits(ActionRight::VoiceUse));
}

/// KR-REQ-26.16 and 09.16: a pairing grant that has run out leaves no share to answer for the
/// device, as a typed request under a share is refused when the grant it was paired under does not
/// stand.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pairing_grant_that_has_run_out_leaves_no_share_to_answer() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let now = wall.load(Ordering::SeqCst);
    let device = paired_holding(
        &controller,
        68,
        &[ActionRight::SessionView],
        Some(now + 60_000),
    );
    shared_with(&controller, &device, &[ActionRight::SessionView], false);
    assert!(
        authority(&controller)
            .device_grant(device.device_id, None)
            .expect("the host answers")
            .is_some(),
        "the control: while the pairing grant stands, the device has a grant"
    );

    wall.store(now + 120_000, Ordering::SeqCst);

    // The read that finds the pairing grant out of force writes its end down; the reads after it
    // find a device recorded as having expired. Neither is answered by the share.
    for read in ["the first", "the next", "and the one after it"] {
        assert!(
            authority(&controller)
                .device_grant(device.device_id, None)
                .expect("the host answers")
                .is_none(),
            "the share does not answer for a device whose pairing grant has run out: {read}"
        );
    }
}

/// KR-REQ-26.16: a share does not answer for a device that has been revoked, whatever the share
/// still carries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_device_is_given_no_grant_by_a_share_that_remains() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let device = paired_holding(&controller, 69, &[ActionRight::SessionView], None);
    shared_with(&controller, &device, &[ActionRight::SessionView], false);
    assert!(
        authority(&controller)
            .device_grant(device.device_id, None)
            .expect("the host answers")
            .is_some(),
        "the control: before the revocation the device has a grant"
    );
    controller
        .devices()
        .revoke(
            device.device_id,
            TimestampMs::new(wall.load(Ordering::SeqCst) + 1),
        )
        .expect("the device is revoked");

    assert!(
        authority(&controller)
            .device_grant(device.device_id, None)
            .expect("the host answers")
            .is_none(),
        "the share does not answer for a revoked device"
    );
}

/// KR-REQ-26.16 and 09.16: a share the host cannot yet decide on, because the clock it reads is not
/// proven, does not take a pairing grant that reads no clock from the device. Section 9 keeps usable
/// what does not depend on the clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_share_the_host_cannot_yet_decide_on_does_not_stand_in_the_way_of_the_pairing_grant() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, _wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let device = paired_holding(
        &controller,
        66,
        &[ActionRight::SessionView, ActionRight::SessionClose],
        None,
    );
    shared_with(&controller, &device, &[ActionRight::SessionView], true);
    controller
        .policy
        .lock()
        .expect("the policy")
        .utc_floor()
        .lose_continuity();

    let read = authority(&controller)
        .device_grant(device.device_id, None)
        .expect("the host answers")
        .expect("a grant that reads no clock");

    assert_eq!(read.grant_id, device.grant.grant_id);
}

/// A voice grant that ran out stays out when this host's wall clock is wound back, for the grant
/// asked for by identity and for the device's standing one: the lapse is decided on the reading
/// this host's floor holds and not on the raw clock. The control is the same grant before it ran
/// out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_voice_grant_that_ran_out_does_not_come_back_when_the_wall_clock_is_wound_back() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let now = wall.load(Ordering::SeqCst);
    let device = paired(&controller, 41, None);
    let voice = voice_grant(&controller, &device, now + 60_000);
    let authority = authority(&controller);

    assert_eq!(
        authority
            .standing_voice_grant(device.device_id)
            .expect("the store answers")
            .map(|held| held.grant_id),
        Some(voice.grant_id),
        "the voice grant stands until it expires"
    );
    assert!(
        authority
            .grant(voice.grant_id)
            .expect("the store answers")
            .is_some()
    );

    // Past its expiry: this host's reading raises the floor, and the grant is out.
    wall.store(now + 120_000, Ordering::SeqCst);
    assert!(
        authority
            .standing_voice_grant(device.device_id)
            .expect("the store answers")
            .is_none()
    );
    assert!(
        authority
            .grant(voice.grant_id)
            .expect("the store answers")
            .is_none()
    );

    // Wound back to before the expiry: the floor holds the reading, so it stays out.
    wall.store(now + 10_000, Ordering::SeqCst);
    assert!(
        authority
            .standing_voice_grant(device.device_id)
            .expect("the store answers")
            .is_none(),
        "a clock wound back does not lend it a life"
    );
    assert!(
        authority
            .grant(voice.grant_id)
            .expect("the store answers")
            .is_none()
    );
}

/// The ordinary grant a device was paired under is decided the same way: once it ran out, no
/// wall clock brings it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pairing_grant_that_ran_out_does_not_come_back_when_the_wall_clock_is_wound_back() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let now = wall.load(Ordering::SeqCst);
    let device = paired(&controller, 42, Some(now + 60_000));
    let authority = authority(&controller);

    assert!(
        authority
            .device_grant(device.device_id, None)
            .expect("the directory answers")
            .is_some(),
        "the grant a device was paired under stands until it expires"
    );
    wall.store(now + 120_000, Ordering::SeqCst);
    assert!(
        authority
            .device_grant(device.device_id, None)
            .expect("the directory answers")
            .is_none()
    );
    wall.store(now + 10_000, Ordering::SeqCst);
    assert!(
        authority
            .device_grant(device.device_id, None)
            .expect("the directory answers")
            .is_none(),
        "a clock wound back does not lend it a life"
    );
}

/// While the floor an end of the voice grant was found on is not on record, the three reads refuse
/// with the host's own reason and not as a device that holds nothing: a daemon started in a new boot
/// could decide the other way. Once the floor can be written, the same reads answer that none
/// stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_voice_grant_whose_end_is_not_on_record_is_refused_with_the_hosts_reason() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let now = wall.load(Ordering::SeqCst);
    let device = paired(&controller, 43, None);
    let voice = voice_grant(&controller, &device, now + 60_000);
    let authority = authority(&controller);
    authority
        .standing_voice_grant(device.device_id)
        .expect("the voice grant stands until it expires")
        .expect("held");

    let faulted = refuse_expiry_records(&temp, "grants");
    wall.store(now + 120_000, Ordering::SeqCst);
    for refused in [
        authority
            .standing_voice_grant(device.device_id)
            .map(|held| held.map(|grant| grant.grant_id)),
        authority
            .grant(voice.grant_id)
            .map(|held| held.map(|grant| grant.grant_id)),
    ] {
        let error = refused.expect_err("a lapse this host cannot record is not stated");
        assert_eq!(
            error.code(),
            kr_protocol::error::ErrorCode::StorageUnavailable
        );
    }

    faulted
        .execute_batch("DROP TRIGGER refuse_expiry;")
        .expect("the fault is cleared");
    assert!(
        authority
            .standing_voice_grant(device.device_id)
            .expect("the end is on record now")
            .is_none()
    );
    assert!(
        authority
            .grant(voice.grant_id)
            .expect("the end is on record now")
            .is_none()
    );
}

/// The same refusal for the grant a device was paired under, whose end is written in the table of
/// paired devices.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pairing_grant_whose_end_is_not_on_record_is_refused_with_the_hosts_reason() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let now = wall.load(Ordering::SeqCst);
    let device = paired(&controller, 44, Some(now + 60_000));
    let authority = authority(&controller);
    authority
        .device_grant(device.device_id, None)
        .expect("the grant stands until it expires")
        .expect("held");

    let faulted = refuse_expiry_records(&temp, "network_devices");
    wall.store(now + 120_000, Ordering::SeqCst);
    let error = authority
        .device_grant(device.device_id, None)
        .expect_err("a lapse this host cannot record is not stated");
    assert_eq!(
        error.code(),
        kr_protocol::error::ErrorCode::StorageUnavailable
    );
    faulted
        .execute_batch("DROP TRIGGER refuse_expiry;")
        .expect("the fault is cleared");
    assert!(
        authority
            .device_grant(device.device_id, None)
            .expect("the end is on record now")
            .is_none()
    );
}

/// The check a voice effect takes at the moment it runs, on the grant the call was admitted under,
/// reads the same decision: a grant that ran out is not given back, whatever the wall clock says
/// afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_effect_is_checked_against_the_grant_on_the_floor() {
    use kr_protocol::ids::{EnvironmentId, VoiceSessionId};
    use kr_protocol::voice::{VoiceAction, VoiceActionPlan, VoiceDelegationId};

    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let now = wall.load(Ordering::SeqCst);
    let device = paired(&controller, 45, None);
    let voice = voice_grant(&controller, &device, now + 60_000);
    let session_id = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
    let voice_session_id = VoiceSessionId::new(kr_ipc::new_uuid());
    let delegation_id = VoiceDelegationId::new("delegation-one").expect("a delegation");
    let proposal = kr_voice::Proposal {
        voice_session_id,
        device_id: device.device_id,
        voice_grant_id: voice.grant_id,
        environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
        action: VoiceAction::Status,
        action_id: kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
        session_id: Some(session_id),
        delegation_id: delegation_id.clone(),
        plan: VoiceActionPlan {
            voice_session_id,
            action: VoiceAction::Status,
            session_id: Nullable::some(session_id),
            delegation_id: Nullable::some(delegation_id),
            payload_digest: kr_protocol::scalars::Digest256::from_bytes([3; 32]),
        },
        approval: None,
        turn_id: None,
        destination: None,
    };
    controller
        .voice_authority_now(&proposal, session_id)
        .expect("the voice grant the action was admitted under stands");

    wall.store(now + 120_000, Ordering::SeqCst);
    controller
        .voice_authority_now(&proposal, session_id)
        .expect_err("a grant that ran out is not given back");
    wall.store(now + 10_000, Ordering::SeqCst);
    controller
        .voice_authority_now(&proposal, session_id)
        .expect_err("a clock wound back does not bring it back");
}

/// The reading a voice change is dated and its call is timed from is this host's reading through
/// the floor, and not the raw wall clock: with the wall clock wound back after the floor was raised,
/// the grant a change replaces is withdrawn at the floor's reading. The control is the same change
/// with the clock where it was, which dates it at the clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_voice_change_is_dated_on_the_floor_and_not_the_wound_back_wall_clock() {
    use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
    use kr_protocol::ids::{ActionId, ActionWindowId, ActorId, RequestId};
    use kr_protocol::method::{Method, MethodVersion};
    use kr_protocol::scalars::DurationMs;
    use kr_transport::window::{AcceptedDeadline, DeadlineBound};

    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let now = wall.load(Ordering::SeqCst);
    let device = paired(&controller, 46, None);
    let actor_id = ActorId::new("local:test").expect("a principal");

    let change = |controller: Arc<Controller>| {
        let device_id = device.device_id;
        let actor_id = actor_id.clone();
        let environment_id = temp.environment_id();
        async move {
            let accepted = AcceptedDeadline {
                deadline: controller
                    .clock
                    .now()
                    .checked_add(std::time::Duration::from_secs(300))
                    .expect("a deadline five minutes out"),
                bound: DeadlineBound::RequestedTtl,
            };
            let carried =
                crate::service::a_close_a_worker_never_answers::admission(&controller, accepted)
                    .await;
            let params = kr_protocol::voice::VoiceGrantParams {
                device_id,
                session_ids: CanonicalSet::new(),
                actions: Nullable::null(),
            };
            let mutation = MutationRequest {
                request_id: RequestId::new(1),
                method: Method::VoiceGrant.into(),
                method_version: MethodVersion::V1,
                action_id: ActionId::new(kr_ipc::new_uuid()),
                grant_id: Nullable::null(),
                target: ActionTarget {
                    environment_id,
                    session_id: Nullable::null(),
                    session_epoch: Nullable::null(),
                    application_instance_id: Nullable::null(),
                    agent_binding_revision: Nullable::null(),
                },
                expected: ParamsValue::empty(),
                action_window_id: ActionWindowId::new("local:test").expect("a window"),
                requested_ttl_ms: DurationMs::new(30_000),
                params: ParamsValue::from_typed(&params).expect("encodes"),
            };
            let revision = controller.policy().authority_revision();
            controller
                .voice_mutation(
                    crate::service::voice_actions::VoiceIngress {
                        actor_id: actor_id.clone(),
                        actor: crate::voice::VoiceActor::Device(device_id),
                        route: None,
                    },
                    &mutation,
                    Method::VoiceGrant,
                    revision,
                    carried,
                )
                .await
                .expect("the voice grant is written");
        }
    };

    // The control: the clock where it was, so the floor and the clock agree.
    change(Arc::clone(&controller)).await;
    let first = controller
        .sharing()
        .grants()
        .records_for_device(device.device_id)
        .expect("the store answers")
        .into_iter()
        .find(|record| record.grant.permits(ActionRight::VoiceUse))
        .expect("a standing voice grant");
    change(Arc::clone(&controller)).await;
    let revoked = controller
        .sharing()
        .grants()
        .record(first.grant.grant_id)
        .expect("the store answers")
        .expect("the record")
        .revoked_at_ms
        .expect("the replaced grant was withdrawn");
    assert!(
        (now..now + 5_000).contains(&revoked),
        "dated at the clock: {revoked}"
    );

    // The floor is raised, and the wall clock is wound back below it.
    wall.store(now + 120_000, Ordering::SeqCst);
    let raised = controller.settled_utc_now();
    assert_eq!(raised, now + 120_000);
    wall.store(now + 10_000, Ordering::SeqCst);
    let second = controller
        .sharing()
        .grants()
        .records_for_device(device.device_id)
        .expect("the store answers")
        .into_iter()
        .find(|record| {
            record.grant.permits(ActionRight::VoiceUse) && record.revoked_at_ms.is_none()
        })
        .expect("a standing voice grant");
    change(Arc::clone(&controller)).await;
    let revoked = controller
        .sharing()
        .grants()
        .record(second.grant.grant_id)
        .expect("the store answers")
        .expect("the record")
        .revoked_at_ms
        .expect("the replaced grant was withdrawn");
    assert!(
        revoked >= now + 120_000,
        "dated on the floor, not on the wound-back clock: {revoked}"
    );
}

/// A delegation identifier is forgotten once its retention has run out, and only on a clock this
/// host can prove: while this boot's clock continuity is lost, and while the wall clock has gone
/// backwards and an owner has not established it again, nothing that can expire is decided, so a
/// spend that cannot be shown to have outlived its retention stays spent, and the same delegation
/// is not a new action. The controls are the same waits with the clock established, and a wait
/// that stops one moment short of the retention.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spent_delegation_is_forgotten_only_on_a_clock_this_host_can_prove() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let authority = authority(&controller);
    let device_id = DeviceId::new(kr_ipc::new_uuid());
    let delegation = kr_protocol::voice::VoiceDelegationId::new("item_one").expect("an identifier");
    let spend = || {
        authority
            .spend_delegation(
                device_id,
                &delegation,
                kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
                controller.settled_now_ms(),
            )
            .expect("asked")
    };
    let retention = kr_protocol::limits::DEDUPLICATION_RETENTION.get();
    let day = 86_400_000;
    let start = wall.load(Ordering::SeqCst);

    assert!(spend(), "a first spend");
    wall.store(start + retention, Ordering::SeqCst);
    assert!(
        !spend(),
        "one moment short of the retention it is still spent"
    );

    // The retention has run out by the clock, and this boot's clock continuity is lost.
    wall.store(start + retention + day, Ordering::SeqCst);
    controller.utc_floor().lose_continuity();
    assert!(!spend(), "a clock that is not proven forgets nothing");
    controller.utc_floor().establish_continuity();
    let spent_again_at = wall.load(Ordering::SeqCst);
    assert!(spend(), "a proven clock has outlived the retention");

    // The wall clock goes back by more than the tolerance and then steps forward past the
    // retention. The floor only moves forward and is written down, so the floor alone would let
    // the forward step forget the spend; the host has found its clock going backwards and has not
    // established it again, so it does not.
    assert!(!spend(), "spent again, and a moment later still");
    wall.store(spent_again_at - 60_000, Ordering::SeqCst);
    let _ = spend();
    wall.store(spent_again_at + retention + day, Ordering::SeqCst);
    assert!(
        !spend(),
        "a clock that went backwards and was not established again forgets nothing"
    );
    super::an_owner_establishes_the_clock::the_owner_establishes(&temp, &controller).await;
    assert!(spend(), "an established clock has outlived the retention");
}

/// A spend is forgotten on the reading the retention is counted from, which is the one the floor on
/// disk covers, and not on a later one: another reader of the shared floor can raise it past that
/// reading with nothing written down, and a spend whose retention ran out only on that later
/// reading is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spent_delegation_is_not_forgotten_on_a_reading_the_floor_on_disk_does_not_cover() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let authority = authority(&controller);
    let device_id = DeviceId::new(kr_ipc::new_uuid());
    let delegation = kr_protocol::voice::VoiceDelegationId::new("item_one").expect("an identifier");
    let spend = |now_ms: u64| {
        authority
            .spend_delegation(
                device_id,
                &delegation,
                kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
                now_ms,
            )
            .expect("asked")
    };
    let retention = kr_protocol::limits::DEDUPLICATION_RETENTION.get();
    let day = 86_400_000;
    let start = wall.load(Ordering::SeqCst);

    assert!(spend(controller.settled_now_ms()), "a first spend");
    // The reading a spend is asked at, written down, one moment short of the retention.
    wall.store(start + retention - 1, Ordering::SeqCst);
    let asked_at = controller.settled_now_ms();
    // Another reader raises the shared floor a day past it, and nothing is written.
    controller.utc_floor().observe(start + retention + day);
    assert!(
        !spend(asked_at),
        "the retention had not run out at the reading the floor on disk covers"
    );
}
