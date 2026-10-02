//! The machine group each environment records for itself, minted, reported and changed by the
//! daemon: at its own socket, from a paired device that manages the host, and across restarts.
//!
//! A group is a random, owner-approved grouping and grants nothing by itself. These tests start
//! real daemons, each with an environment tree of its own, and read the group the way a client
//! does: through `host.info` and `environment.list`. A step is taken at both doors, under the
//! action identity a client chose, and an exact duplicate is the original request, window and all.
//! The daemon starts no worker, so every answer here is one it gives itself.

mod net_support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_controller::machine::RECORD_FILE;
use kr_crypto::keys::DeviceKeys;
use kr_ipc::client::LocalClient;
use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::hostinfo::{
    DoctorStatus, EnvironmentListResult, HostDoctorResult, HostInfoResult,
};
use kr_protocol::ids::{ActionId, EnvironmentId, MachineId};
use kr_protocol::machine::{
    MachineChange, MachineExpected, MachineGroup, MachineJoinParams, MachineMergeParams,
    MachineSplitParams, MachineStepResult,
};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, U64, Uuid};
use net_support::{Device, Host, RawDevice};

fn typed<T: kr_protocol::wire::WireMessage>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

fn action() -> ActionId {
    ActionId::new(kr_ipc::new_uuid())
}

fn some_group(byte: u8) -> MachineId {
    MachineId::new(Uuid::from_bytes([byte; 16]))
}

fn target(host: &Host) -> ActionTarget {
    ActionTarget::environment(host.environment_id)
}

/// A target that names a session of the environment, with the epoch a session target carries.
fn a_session_target(host: &Host) -> ActionTarget {
    ActionTarget {
        session_id: Nullable::some(kr_protocol::ids::SessionId::new(Uuid::from_bytes([5; 16]))),
        session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
        ..target(host)
    }
}

fn expecting(group: &MachineGroup) -> MachineExpected {
    MachineExpected {
        machine_id: group.machine_id,
        revision: group.revision,
    }
}

/// What the owner at the daemon's own socket reads of the group, from `host.info`.
async fn group_of(client: &mut LocalClient) -> MachineGroup {
    let info: HostInfoResult = typed(
        &client
            .request(Method::HostInfo, &())
            .await
            .expect("the call reaches the daemon")
            .expect("host.info is served"),
    );
    info.machine.expect("the daemon reports a group")
}

async fn info_of(client: &mut LocalClient) -> HostInfoResult {
    typed(
        &client
            .request(Method::HostInfo, &())
            .await
            .expect("the call reaches the daemon")
            .expect("host.info is served"),
    )
}

/// One step at the local socket, under the action given.
async fn local_step<P: serde::Serialize>(
    host: &Host,
    client: &mut LocalClient,
    method: Method,
    action_id: ActionId,
    params: &P,
) -> std::result::Result<MachineStepResult, ProtocolError> {
    client
        .mutate(method, action_id, target(host), params)
        .await
        .expect("the call reaches the daemon")
        .map(|value| typed(&value))
}

async fn join(
    host: &Host,
    client: &mut LocalClient,
    into: MachineId,
    expected: &MachineGroup,
) -> std::result::Result<MachineStepResult, ProtocolError> {
    local_step(
        host,
        client,
        Method::MachineJoin,
        action(),
        &MachineJoinParams {
            machine_id: into,
            expected: expecting(expected),
        },
    )
    .await
}

/// The doctor's check of the record, as the owner reads it.
async fn doctor_check(client: &mut LocalClient) -> (DoctorStatus, String) {
    let report: HostDoctorResult = typed(
        &client
            .request(Method::HostDoctor, &())
            .await
            .expect("the call reaches the daemon")
            .expect("host.doctor is served"),
    );
    let check = report
        .checks
        .iter()
        .find(|check| check.id() == "machine-group")
        .expect("the doctor checks the machine group");
    (
        check.status,
        format!("{} {}", check.detail(), check.remedy().unwrap_or_default()),
    )
}

/// KR-REQ-03.07: a daemon's first start mints a group of one from the secure random source alone,
/// and reports it through `host.info` and `environment.list`. Two environments never share a group
/// because of what they have in common: one whose record is gone and which starts again, as an
/// environment created again over the same paths does, gets another, and an ordinary restart keeps
/// the group it recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_start_mints_a_group_of_one_that_a_restart_keeps_and_a_new_environment_never_shares()
 {
    let first = Host::start_unowned().await;
    let mut client = first.client().await;
    let minted = group_of(&mut client).await;
    assert_eq!(minted.revision, U64::new(1));
    assert_eq!(minted.change, MachineChange::Created);
    assert!(
        !minted.previous.is_present(),
        "the first record left no group"
    );
    assert_ne!(
        minted.machine_id.get().as_bytes(),
        first.environment_id.get().as_bytes(),
        "the group is not the environment's identity or computed from it"
    );

    // The same group in the environment list, which names this environment.
    let list: EnvironmentListResult = typed(
        &client
            .request(Method::EnvironmentList, &())
            .await
            .expect("the call reaches the daemon")
            .expect("environment.list is served"),
    );
    assert_eq!(list.environments.len(), 1);
    assert_eq!(list.environments[0].environment_id, first.environment_id);
    assert_eq!(list.environments[0].machine.as_ref(), Some(&minted));

    // A restart keeps it.
    drop(client);
    let stopped = first.shut_down().await;
    let settings = stopped.settings().clone();
    let restarted = stopped.start(settings).await;
    let mut client = restarted.client().await;
    assert_eq!(
        group_of(&mut client).await,
        minted,
        "a restart keeps the group"
    );

    // Another environment on the same machine, with the same user and the same kind of paths,
    // gets another group.
    let other = Host::start_unowned().await;
    let mut other_client = other.client().await;
    let other_group = group_of(&mut other_client).await;
    assert_ne!(other_group.machine_id, minted.machine_id);

    // An environment whose record is gone starts as a first start does, and mints anew rather
    // than finding its old group from what it shares with itself.
    drop(client);
    let stopped = restarted.shut_down().await;
    std::fs::remove_file(stopped.tree().environment().state_dir().join(RECORD_FILE))
        .expect("removes the record");
    let settings = stopped.settings().clone();
    let again = stopped.start(settings).await;
    let mut client = again.client().await;
    let created_again = group_of(&mut client).await;
    assert_eq!(created_again.revision, U64::new(1));
    assert_eq!(created_again.change, MachineChange::Created);
    assert_ne!(created_again.machine_id, minted.machine_id);
    assert_ne!(created_again.machine_id, other_group.machine_id);

    drop(client);
    drop(other_client);
    again.stop().await;
    other.stop().await;
}

/// KR-REQ-03.07: the owner at the daemon's own socket joins a group, takes a merge's part and
/// splits, each against the record it saw. A step against any other record changes nothing, joining
/// the group the environment is already in is refused, a step that names a session is refused, and
/// every step's result is what `host.info` reports next.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_at_the_local_socket_joins_merges_and_splits_against_the_record_they_saw() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let minted = group_of(&mut client).await;

    // Join a group the owner names.
    let into = some_group(0x41);
    let joined = join(&host, &mut client, into, &minted)
        .await
        .expect("joins");
    assert_eq!(joined.environment_id, host.environment_id);
    assert_eq!(joined.machine.machine_id, into);
    assert_eq!(joined.machine.revision, U64::new(2));
    assert_eq!(joined.machine.change, MachineChange::Joined);
    assert_eq!(joined.machine.previous, Nullable::some(minted.machine_id));
    assert_eq!(group_of(&mut client).await, joined.machine);

    // A step approved against the record the environment had before is refused, and writes nothing.
    let stale = join(&host, &mut client, some_group(0x42), &minted)
        .await
        .expect_err("a stale precondition");
    assert_eq!(stale.code, ErrorCode::DraftConflict);
    assert_eq!(group_of(&mut client).await, joined.machine);

    // The group it is already in is not a move.
    let same = join(&host, &mut client, into, &joined.machine)
        .await
        .expect_err("the group it is in");
    assert_eq!(same.code, ErrorCode::InvalidArgument);
    assert_eq!(group_of(&mut client).await, joined.machine);

    // A target that names a session is refused: a group belongs to the environment.
    let session_target = a_session_target(&host);
    let named = client
        .mutate(
            Method::MachineSplit,
            action(),
            session_target,
            &MachineSplitParams {
                expected: expecting(&joined.machine),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("a session is not a machine group's subject");
    assert_eq!(named.code, ErrorCode::InvalidArgument);
    assert_eq!(group_of(&mut client).await, joined.machine);

    // This environment's part in a merge of its group into another.
    let merged_into = some_group(0x43);
    let merged = local_step(
        &host,
        &mut client,
        Method::MachineMerge,
        action(),
        &MachineMergeParams {
            machine_id: merged_into,
            expected: expecting(&joined.machine),
        },
    )
    .await
    .expect("merges");
    assert_eq!(merged.machine.machine_id, merged_into);
    assert_eq!(merged.machine.revision, U64::new(3));
    assert_eq!(merged.machine.change, MachineChange::Merged);
    assert_eq!(merged.machine.previous, Nullable::some(into));

    // A split leaves into a fresh group the environment mints, and keeps the one it left.
    let split = local_step(
        &host,
        &mut client,
        Method::MachineSplit,
        action(),
        &MachineSplitParams {
            expected: expecting(&merged.machine),
        },
    )
    .await
    .expect("splits");
    assert_eq!(split.machine.revision, U64::new(4));
    assert_eq!(split.machine.change, MachineChange::Split);
    assert_eq!(split.machine.previous, Nullable::some(merged_into));
    assert_ne!(split.machine.machine_id, merged_into);
    assert_ne!(split.machine.machine_id, minted.machine_id);

    // A step is undone by joining the group it left, against its own result.
    let undone = join(&host, &mut client, merged_into, &split.machine)
        .await
        .expect("goes back");
    assert_eq!(undone.machine.machine_id, merged_into);
    assert_eq!(undone.machine.revision, U64::new(5));
    assert_eq!(undone.machine.change, MachineChange::Joined);

    drop(client);
    host.stop().await;
}

/// KR-REQ-03.07: a paired device whose grant carries `host.manage` takes a step on the environment
/// it is paired with, and reads the group through the export form of `host.info` and
/// `environment.list`; a device whose grant does not carry it is refused every step and the record
/// is as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_changes_the_group_only_where_its_grant_carries_host_manage() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut local = host.client().await;
    let minted = group_of(&mut local).await;

    let managing = Device::create().await;
    let managing_record = net_support::pair_with(
        &host,
        &managing,
        &owner,
        net_support::proposal(&[ActionRight::SessionView, ActionRight::HostManage]),
    )
    .await;
    let managing = RawDevice::connect(&host, &managing, &managing_record).await;

    // The device reads the group.
    let info: HostInfoResult = typed(
        &managing
            .read(Method::HostInfo, &())
            .await
            .expect("host.info is served to the device"),
    );
    assert_eq!(info.machine.as_ref(), Some(&minted));
    let list: EnvironmentListResult = typed(
        &managing
            .read(Method::EnvironmentList, &())
            .await
            .expect("environment.list is served to the device"),
    );
    assert_eq!(list.environments[0].machine.as_ref(), Some(&minted));

    // And takes a step, which is recorded as the device's own.
    let into = some_group(0x51);
    let joined: MachineStepResult = typed(
        &managing
            .mutate(
                Method::MachineJoin,
                action(),
                target(&host),
                &MachineJoinParams {
                    machine_id: into,
                    expected: expecting(&minted),
                },
            )
            .await
            .expect("a device that manages the host joins a group"),
    );
    assert_eq!(joined.machine.machine_id, into);
    assert_eq!(group_of(&mut local).await, joined.machine);

    // A device whose grant does not carry host.manage is refused, whatever it asks.
    let viewing = Device::create().await;
    let viewing_record = net_support::pair_with(
        &host,
        &viewing,
        &owner,
        net_support::proposal(&[ActionRight::SessionView]),
    )
    .await;
    let viewing = RawDevice::connect(&host, &viewing, &viewing_record).await;
    for (method, params) in [
        (
            Method::MachineJoin,
            ParamsValue::from_typed(&MachineJoinParams {
                machine_id: some_group(0x52),
                expected: expecting(&joined.machine),
            })
            .expect("encodes"),
        ),
        (
            Method::MachineSplit,
            ParamsValue::from_typed(&MachineSplitParams {
                expected: expecting(&joined.machine),
            })
            .expect("encodes"),
        ),
    ] {
        let refused = viewing
            .mutate(method, action(), target(&host), &params)
            .await
            .expect_err("a device without host.manage");
        assert_eq!(refused.code, ErrorCode::PermissionDenied, "{method:?}");
    }
    assert_eq!(group_of(&mut local).await, joined.machine);

    // A device that manages the host is still refused a step that names a session, and one that
    // is about another environment.
    let named = managing
        .mutate(
            Method::MachineSplit,
            action(),
            a_session_target(&host),
            &MachineSplitParams {
                expected: expecting(&joined.machine),
            },
        )
        .await
        .expect_err("a session is not a machine group's subject");
    assert_eq!(named.code, ErrorCode::InvalidArgument);
    let elsewhere = managing
        .mutate(
            Method::MachineSplit,
            action(),
            ActionTarget::environment(EnvironmentId::new(Uuid::from_bytes([7; 16]))),
            &MachineSplitParams {
                expected: expecting(&joined.machine),
            },
        )
        .await
        .expect_err("no environment takes a step for another");
    assert_eq!(elsewhere.code, ErrorCode::InvalidArgument);
    assert_eq!(group_of(&mut local).await, joined.machine);

    managing.close();
    viewing.close();
    drop(local);
    host.stop().await;
}

/// The original request of one step, as a client keeps it to send again.
async fn composed_join(
    host: &Host,
    client: &mut LocalClient,
    into: MachineId,
    expected: &MachineGroup,
) -> MutationRequest {
    client
        .compose(
            Method::MachineJoin,
            action(),
            target(host),
            &MachineJoinParams {
                machine_id: into,
                expected: expecting(expected),
            },
        )
        .await
        .expect("composes")
}

/// KR-REQ-03.07: a step is performed once per actor's action. A retry is answered from the receipt
/// the first attempt left, after another step has changed the record and over a new connection; a
/// reused action with another payload is `ID_CONFLICT` and changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_is_performed_once_and_a_retry_is_answered_from_its_receipt() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let minted = group_of(&mut client).await;

    // A: joins a group.
    let first_into = some_group(0x61);
    let a = composed_join(&host, &mut client, first_into, &minted).await;
    let answered = client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect("joins");
    let a_result: MachineStepResult = typed(&answered);
    assert_eq!(a_result.machine.machine_id, first_into);
    assert_eq!(a_result.machine.revision, U64::new(2));

    // B: another action moves the record on.
    let b_into = some_group(0x62);
    let b = join(&host, &mut client, b_into, &a_result.machine)
        .await
        .expect("joins again");
    assert_eq!(b.machine.revision, U64::new(3));

    // A again, over a connection of its own: the receipt, not the record as it stands now.
    drop(client);
    let mut client = host.client().await;
    let again = client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect("is answered from its receipt");
    assert_eq!(typed::<MachineStepResult>(&again), a_result);
    assert_eq!(
        group_of(&mut client).await,
        b.machine,
        "a retry changes nothing"
    );

    // A with a changed payload is a reused identifier.
    let mut changed = a.clone();
    changed.params = ParamsValue::from_typed(&MachineJoinParams {
        machine_id: some_group(0x63),
        expected: expecting(&minted),
    })
    .expect("encodes");
    let conflict = client
        .repeat(&changed)
        .await
        .expect("reaches the daemon")
        .expect_err("a reused action with another payload");
    assert_eq!(conflict.code, ErrorCode::IdConflict);
    assert_eq!(group_of(&mut client).await, b.machine);

    drop(client);
    host.stop().await;
}

/// KR-REQ-03.07: the same holds at the device door, which answers an exact duplicate from the
/// receipt on a connection of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_repeats_a_step_is_answered_from_the_receipt_and_a_changed_payload_conflicts()
{
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut local = host.client().await;
    let minted = group_of(&mut local).await;
    let device = Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::HostManage]),
    )
    .await;
    let connection = RawDevice::connect(&host, &device, &record).await;

    let a = action();
    let first = MachineJoinParams {
        machine_id: some_group(0x71),
        expected: expecting(&minted),
    };
    let a_result: MachineStepResult = typed(
        &connection
            .mutate(Method::MachineJoin, a, target(&host), &first)
            .await
            .expect("joins"),
    );
    let b_result: MachineStepResult = typed(
        &connection
            .mutate(
                Method::MachineJoin,
                action(),
                target(&host),
                &MachineJoinParams {
                    machine_id: some_group(0x72),
                    expected: expecting(&a_result.machine),
                },
            )
            .await
            .expect("joins again"),
    );
    // A again: the same action, the same payload, the same window.
    let again: MachineStepResult = typed(
        &connection
            .mutate(Method::MachineJoin, a, target(&host), &first)
            .await
            .expect("is answered from its receipt"),
    );
    assert_eq!(again, a_result);
    assert_eq!(group_of(&mut local).await, b_result.machine);
    // A with a changed payload.
    let conflict = connection
        .mutate(
            Method::MachineJoin,
            a,
            target(&host),
            &MachineJoinParams {
                machine_id: some_group(0x73),
                expected: expecting(&minted),
            },
        )
        .await
        .expect_err("a reused action with another payload");
    assert_eq!(conflict.code, ErrorCode::IdConflict);
    assert_eq!(group_of(&mut local).await, b_result.machine);

    connection.close();
    drop(local);
    host.stop().await;
}

/// KR-REQ-03.07: a step whose attempt ended after it wrote the record and before it kept its
/// receipt is answered from the record while the record still names it, and never performed again.
/// Another step does not take the answer with it: the claim the record names is settled before the
/// next step is taken, and again at start before anything is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_that_ended_between_its_write_and_its_receipt_keeps_its_answer() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let minted = group_of(&mut client).await;

    // A writes the record, and the daemon stops it before its receipt.
    host.controller().lose_the_next_machine_receipt();
    let a = composed_join(&host, &mut client, some_group(0x81), &minted).await;
    let lost = client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect_err("the attempt ended before it answered");
    assert_eq!(lost.code, ErrorCode::OutcomeUnknown);
    let written = group_of(&mut client).await;
    assert_eq!(
        written.machine_id,
        some_group(0x81),
        "the record was written"
    );

    // The record names the step, so a retry is told what it did, and nothing is written twice.
    let retried = client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect("is answered from the record");
    let a_result: MachineStepResult = typed(&retried);
    assert_eq!(a_result.machine, written);
    assert_eq!(group_of(&mut client).await, written);

    // Another step moves the record on; the first step's answer was kept first.
    let b = join(&host, &mut client, some_group(0x82), &written)
        .await
        .expect("takes the next step");
    let still = client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect("is answered from its receipt");
    assert_eq!(typed::<MachineStepResult>(&still), a_result);
    assert_eq!(group_of(&mut client).await, b.machine);

    drop(client);
    host.stop().await;
}

/// KR-REQ-03.07: the claim of a step that wrote the record and stopped with the daemon is settled
/// from the record at start, before anything can change it, so the answer survives the steps taken
/// after the restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_that_stopped_between_a_write_and_its_receipt_settles_it_at_start() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let minted = group_of(&mut client).await;
    host.controller().lose_the_next_machine_receipt();
    let a = composed_join(&host, &mut client, some_group(0x91), &minted).await;
    client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect_err("the attempt ended before it answered");
    let written = group_of(&mut client).await;
    drop(client);

    let stopped = host.shut_down().await;
    let settings = stopped.settings().clone();
    let restarted = stopped.start(settings).await;
    let mut client = restarted.client().await;
    assert_eq!(group_of(&mut client).await, written);
    // Before any step is taken, the claim holds the answer: the daemon settled it at start from the
    // record, and a retry does not depend on the record staying as it is.
    let actor = kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
        .expect("the local principal");
    let digest = kr_protocol::digest::mutation_digest(&a, &actor).expect("a digest");
    let kept = restarted
        .controller()
        .sharing()
        .grants()
        .recorded_action(&actor, a.action_id, &digest)
        .expect("readable")
        .expect("the step was claimed");
    assert!(
        matches!(kept, kr_controller::grants::ActionRecord::Answered { .. }),
        "the claim was settled at start: {kept:?}"
    );
    // A step after the restart changes the record; the earlier step is still answered.
    let b = join(&restarted, &mut client, some_group(0x92), &written)
        .await
        .expect("takes the next step");
    let answered = client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect("is answered from its receipt");
    assert_eq!(typed::<MachineStepResult>(&answered).machine, written);
    assert_eq!(group_of(&mut client).await, b.machine);

    drop(client);
    restarted.stop().await;
}

/// KR-REQ-03.07: a claim whose attempt ended before it recorded anything, for an action the record
/// does not name, is an outcome nobody knows, and is never performed: the record's last change is
/// another step's, and answering this action with it would tell the owner a step happened that did
/// not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_nobody_finished_that_the_record_does_not_name_is_an_outcome_nobody_knows() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let minted = group_of(&mut client).await;
    // The record's last change is this owner's step under another action.
    let earlier = join(&host, &mut client, some_group(0xe1), &minted)
        .await
        .expect("takes a step");

    // A step claimed by an attempt that ended before it wrote anything.
    let unfinished = composed_join(&host, &mut client, some_group(0xe2), &earlier.machine).await;
    let actor = kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
        .expect("the local principal");
    let digest = kr_protocol::digest::mutation_digest(&unfinished, &actor).expect("a digest");
    let claimed = host
        .controller()
        .sharing()
        .grants()
        .claim_action(&actor, unfinished.action_id, &digest, 1_000)
        .expect("claims the action");
    let kr_controller::grants::ActionClaim::Claimed { hold } = claimed else {
        panic!("nothing held this action before");
    };
    drop(hold);

    let answer = client
        .repeat(&unfinished)
        .await
        .expect("reaches the daemon")
        .expect_err("the record does not name this action");
    assert_eq!(answer.code, ErrorCode::OutcomeUnknown);
    assert_eq!(
        group_of(&mut client).await,
        earlier.machine,
        "it was not performed"
    );

    drop(client);
    host.stop().await;
}

/// The local owner's identity, as the daemon names it in its own records.
fn local_owner() -> kr_protocol::ids::ActorId {
    kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
        .expect("the local principal")
}

/// What the daemon's records hold of a step's action, or `None` where it never claimed it.
fn claim_of(host: &Host, step: &MutationRequest) -> Option<kr_controller::grants::ActionRecord> {
    let actor = local_owner();
    let digest = kr_protocol::digest::mutation_digest(step, &actor).expect("a digest");
    host.controller()
        .sharing()
        .grants()
        .recorded_action(&actor, step.action_id, &digest)
        .expect("the registry reads")
}

/// The refusals and the unknown outcomes a step is answered with carry no path of this host's
/// state: an answer can reach a paired device.
fn assert_names_no_path(host: &Host, answer: &ProtocolError) {
    let state = host.tree().environment().state_dir().display().to_string();
    assert!(
        !answer.message.contains(&state) && !answer.message.contains(RECORD_FILE_PATH_MARKER),
        "the answer names the state directory: {}",
        answer.message
    );
}

/// What a path of the machine group record would show in a message.
const RECORD_FILE_PATH_MARKER: &str = "/machine-group";

/// KR-REQ-03.07: a step is not taken while the change an earlier step made cannot be confirmed to
/// survive a crash. A wrote the record and its attempt ended before its receipt; the flush that
/// settles A before the next step fails. B is refused before it claims anything, the record is still
/// A's, and a retry of A is an outcome nobody knows, with no path in the answer, instead of a result
/// the record cannot yet vouch for. Once the flush works, A is answered from the record and B goes
/// through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_is_not_taken_while_the_change_before_it_cannot_be_confirmed() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let minted = group_of(&mut client).await;

    host.controller().lose_the_next_machine_receipt();
    let a = composed_join(&host, &mut client, some_group(0xa1), &minted).await;
    let lost = client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect_err("the attempt ended before it answered");
    assert_eq!(lost.code, ErrorCode::OutcomeUnknown);
    let written = group_of(&mut client).await;
    assert_eq!(
        written.machine_id,
        some_group(0xa1),
        "the record was written"
    );

    host.controller().fail_the_machine_recovery_flush(true);
    let b = composed_join(&host, &mut client, some_group(0xa2), &written).await;
    let refused = client
        .repeat(&b)
        .await
        .expect("reaches the daemon")
        .expect_err("a change nobody can confirm blocks the next step");
    assert_eq!(refused.code, ErrorCode::StorageUnavailable);
    assert_names_no_path(&host, &refused);
    assert_eq!(
        group_of(&mut client).await,
        written,
        "the next step replaced a record whose change was not confirmed"
    );
    assert!(
        claim_of(&host, &b).is_none(),
        "a step that was refused before anything changed claimed its action"
    );

    // A retry of A is not answered from a record that cannot be vouched for.
    let unknown = client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect_err("what the record shows cannot be confirmed yet");
    assert_eq!(unknown.code, ErrorCode::OutcomeUnknown);
    assert_names_no_path(&host, &unknown);

    // The flush works again: A is answered from the record, and B, under a new action, goes
    // through and does not take A's answer with it.
    host.controller().fail_the_machine_recovery_flush(false);
    let answered = client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect("is answered from the record once it can be confirmed");
    assert_eq!(typed::<MachineStepResult>(&answered).machine, written);
    let next = join(&host, &mut client, some_group(0xa2), &written)
        .await
        .expect("the next step goes through");
    let still = client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect("is answered from its receipt");
    assert_eq!(typed::<MachineStepResult>(&still).machine, written);
    assert_eq!(group_of(&mut client).await, next.machine);

    drop(client);
    host.stop().await;
}

/// KR-REQ-03.07: a retry of an unfinished step is answered from what the claim holds once it has its
/// turn, not from what the record showed when it first looked. A wrote the record and its attempt
/// ended before its receipt. A's retry finds the claim unfinished and is stopped before it takes its
/// turn; B, under another action, settles A's claim from the record and moves the record on; the
/// retry then goes on, and is answered with A's result, where an answer read from the record as it
/// stands now would be an outcome nobody knows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_that_looked_before_another_step_settled_its_claim_is_answered_from_it() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let minted = group_of(&mut client).await;
    let mut other = host.client().await;

    host.controller().lose_the_next_machine_receipt();
    let a = composed_join(&host, &mut client, some_group(0xa7), &minted).await;
    client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect_err("the attempt ended before it answered");
    let written = group_of(&mut other).await;
    assert!(
        matches!(
            claim_of(&host, &a),
            Some(kr_controller::grants::ActionRecord::Unfinished)
        ),
        "A's claim is unfinished: {:?}",
        claim_of(&host, &a)
    );

    let answer = held(
        host.controller(),
        Point::Retry,
        async move {
            let answer = client.repeat(&a).await.expect("reaches the daemon");
            (client, answer)
        },
        async {
            join(&host, &mut other, some_group(0xa8), &written)
                .await
                .expect("B settles A's claim and moves the record on");
        },
    )
    .await
    .expect("the retry's connection stands");
    let result: MachineStepResult = typed(&answer.1.expect("answered from A's claim"));
    assert_eq!(
        result.machine, written,
        "the retry was answered with a record that was not A's"
    );

    drop(answer.0);
    drop(other);
    host.stop().await;
}

/// KR-REQ-03.07: a step that wrote the record and could not confirm that its directory survives a
/// crash is an outcome nobody knows, at either door, and its answer names no path: a paired device
/// is given it. The record shows the change, so asking again under the same action is answered from
/// the record once the flush works, and the step is never performed twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_whose_directory_could_not_be_flushed_is_an_outcome_nobody_knows_that_names_no_path()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut local = host.client().await;
    let minted = group_of(&mut local).await;
    let device = Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::HostManage]),
    )
    .await;
    let connection = RawDevice::connect(&host, &device, &record).await;

    // At the device door.
    host.controller()
        .report_the_next_machine_write_as_unconfirmed();
    let a = action();
    let first = joining(some_group(0xa3), &minted);
    let unknown = connection
        .mutate(Method::MachineJoin, a, target(&host), &first)
        .await
        .expect_err("whether the change survives a crash is not known");
    assert_eq!(unknown.code, ErrorCode::OutcomeUnknown);
    assert_names_no_path(&host, &unknown);
    let written = group_of(&mut local).await;
    assert_eq!(
        written.machine_id,
        some_group(0xa3),
        "the record shows the change"
    );
    // The same action again, over the same connection: answered from the record, not performed.
    let again: MachineStepResult = typed(
        &connection
            .mutate(Method::MachineJoin, a, target(&host), &first)
            .await
            .expect("is answered from the record"),
    );
    assert_eq!(again.machine, written);
    assert_eq!(group_of(&mut local).await, written);

    // At the daemon's own socket.
    host.controller()
        .report_the_next_machine_write_as_unconfirmed();
    let b = composed_join(&host, &mut local, some_group(0xa4), &written).await;
    let unknown = local
        .repeat(&b)
        .await
        .expect("reaches the daemon")
        .expect_err("whether the change survives a crash is not known");
    assert_eq!(unknown.code, ErrorCode::OutcomeUnknown);
    assert_names_no_path(&host, &unknown);
    let answered = local
        .repeat(&b)
        .await
        .expect("reaches the daemon")
        .expect("is answered from the record");
    let b_group = group_of(&mut local).await;
    assert_eq!(b_group.machine_id, some_group(0xa4));
    assert_eq!(typed::<MachineStepResult>(&answered).machine, b_group);

    connection.close();
    drop(local);
    host.stop().await;
}

/// KR-REQ-03.07: a step that wrote the record is answered with its result even when its receipt
/// cannot be kept: the answer never says a change did not happen after it did. The claim stays
/// unfinished, and the record, which names the step, answers a retry, at either door, with the same
/// result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_whose_receipt_cannot_be_kept_is_answered_with_its_result() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut local = host.client().await;
    let minted = group_of(&mut local).await;
    let device = Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::HostManage]),
    )
    .await;
    let connection = RawDevice::connect(&host, &device, &record).await;

    // At the daemon's own socket.
    host.controller().make_the_next_machine_receipt_unwritable();
    let a = composed_join(&host, &mut local, some_group(0xa5), &minted).await;
    let result: MachineStepResult = typed(
        &local
            .repeat(&a)
            .await
            .expect("reaches the daemon")
            .expect("the record was written, so the step is answered with its result"),
    );
    assert_eq!(result.machine.machine_id, some_group(0xa5));
    assert!(
        matches!(
            claim_of(&host, &a),
            Some(kr_controller::grants::ActionRecord::Unfinished)
        ),
        "the receipt was not kept: {:?}",
        claim_of(&host, &a)
    );
    let retried: MachineStepResult = typed(
        &local
            .repeat(&a)
            .await
            .expect("reaches the daemon")
            .expect("is answered from the record"),
    );
    assert_eq!(retried, result);
    assert!(
        matches!(
            claim_of(&host, &a),
            Some(kr_controller::grants::ActionRecord::Answered { .. })
        ),
        "the retry kept the answer"
    );

    // At the device door.
    host.controller().make_the_next_machine_receipt_unwritable();
    let b = action();
    let params = joining(some_group(0xa6), &result.machine);
    let device_result: MachineStepResult = typed(
        &connection
            .mutate(Method::MachineJoin, b, target(&host), &params)
            .await
            .expect("the record was written, so the step is answered with its result"),
    );
    assert_eq!(device_result.machine.machine_id, some_group(0xa6));
    let retried: MachineStepResult = typed(
        &connection
            .mutate(Method::MachineJoin, b, target(&host), &params)
            .await
            .expect("is answered from the record"),
    );
    assert_eq!(retried, device_result);
    assert_eq!(group_of(&mut local).await, device_result.machine);

    connection.close();
    drop(local);
    host.stop().await;
}

/// What a file holds and what its metadata says: a rewrite with equal bytes, a replaced file and a
/// changed mode each change one of these.
#[derive(Debug, PartialEq, Eq)]
struct Kept {
    bytes: Vec<u8>,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    inode: u64,
}

impl Kept {
    fn of(path: &Path) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        let metadata = std::fs::symlink_metadata(path).ok()?;
        Some(Self {
            bytes,
            modified: metadata.modified().ok()?,
            #[cfg(unix)]
            mode: std::os::unix::fs::MetadataExt::mode(&metadata),
            #[cfg(unix)]
            inode: std::os::unix::fs::MetadataExt::ino(&metadata),
        })
    }
}

/// Every file of the host's own that a step must leave alone: the host's identity file, the
/// environment's markers, its secret store, and everything else in its state directory but the
/// machine group record, which the step writes, and the registry, which is compared by its rows.
fn untouched_files(host: &Host) -> BTreeMap<PathBuf, Kept> {
    let paths = host.tree().paths();
    let environment = host.tree().environment();
    let registry = environment.registry_database();
    let registry_name = registry
        .file_name()
        .expect("the registry has a name")
        .to_string_lossy()
        .into_owned();
    let mut found = BTreeMap::new();
    let mut take = |path: &Path| {
        if let Some(kept) = Kept::of(path) {
            found.insert(path.to_path_buf(), kept);
        }
    };
    take(&paths.environment_id_file());
    take(&environment.runtime_dir().join("environment"));
    fn walk(directory: &Path, skip: &dyn Fn(&Path) -> bool, take: &mut impl FnMut(&Path)) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if skip(&path) {
                continue;
            }
            if path.is_dir() {
                walk(&path, skip, take);
            } else {
                take(&path);
            }
        }
    }
    walk(&environment.secrets_dir(), &|_| false, &mut take);
    walk(
        environment.state_dir(),
        &|path| {
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            name == RECORD_FILE
                || name.starts_with(&registry_name)
                || name.starts_with(".machine-group.")
        },
        &mut take,
    );
    found
}

/// Every row of every table of the registry but the tables named, each rendered as text, so that a
/// row written, changed or removed shows. The registry holds the daemon's grants, devices,
/// reservations, workers and tombstones, which are the sessions and the people it knows.
fn registry_rows(host: &Host, except: &[&str]) -> BTreeMap<String, Vec<String>> {
    let connection = rusqlite::Connection::open_with_flags(
        host.registry_database(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("opens the registry");
    let tables: Vec<String> = connection
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
             ORDER BY name",
        )
        .expect("lists the tables")
        .query_map([], |row| row.get(0))
        .expect("reads the tables")
        .collect::<std::result::Result<_, _>>()
        .expect("table names");
    let mut found = BTreeMap::new();
    for table in tables {
        if except.contains(&table.as_str()) {
            continue;
        }
        let mut statement = connection
            .prepare(&format!("SELECT * FROM \"{table}\""))
            .expect("reads the table");
        let columns = statement.column_count();
        let mut rows: Vec<String> = statement
            .query_map([], |row| {
                let mut values = Vec::new();
                for column in 0..columns {
                    values.push(format!("{:?}", row.get_ref(column)?));
                }
                Ok(values.join(" | "))
            })
            .expect("reads the rows")
            .collect::<std::result::Result<_, _>>()
            .expect("rows");
        rows.sort();
        found.insert(table, rows);
    }
    found
}

/// Gives the registry a closed session and a fenced reservation, so that what a step must leave
/// alone includes session identifiers and the rows that hold them.
fn hold_sessions(host: &Host, byte: u8) {
    let connection =
        rusqlite::Connection::open(host.registry_database()).expect("opens the registry");
    connection
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    connection
        .execute(
            "INSERT INTO tombstones (session_id, record, closed_at_ms) VALUES (?1, ?2, ?3)",
            rusqlite::params![vec![byte; 16], vec![byte, 1, 2, 3], 1_i64],
        )
        .expect("a closed session");
    connection
        .execute(
            "INSERT INTO reservations (reservation_id, actor_id, create_token, payload_digest, \
             create_intent, session_id, display_number, phase, created_at_ms) \
             VALUES (?1, 'local:1', ?2, ?3, NULL, ?4, ?5, 'fenced', 1)",
            rusqlite::params![
                vec![byte.wrapping_add(1); 16],
                vec![byte.wrapping_add(2); 16],
                vec![byte.wrapping_add(3); 32],
                vec![byte.wrapping_add(4); 16],
                i64::from(byte),
            ],
        )
        .expect("a fenced reservation");
}

/// What the registry holds of the people the daemon knows, through its own interfaces: the devices
/// and the grants.
fn rows_of_authority(host: &Host) -> String {
    let devices = host.controller().devices().devices().expect("devices");
    let grants = host
        .controller()
        .sharing()
        .grants()
        .records()
        .expect("grants");
    format!("{devices:#?}\n{grants:#?}")
}

/// Whether `host` lets `device`, which presents the identity `record` gave it, in and answer it.
async fn lets_in(
    host: &Host,
    device: &Device,
    record: &kr_controller::service::net::devices::DeviceRecord,
) -> bool {
    match RawDevice::try_connect(host, device, record).await {
        Ok(connection) => {
            let answered = connection.read(Method::HostInfo, &()).await.is_ok();
            connection.close();
            answered
        }
        Err(_) => false,
    }
}

/// The enrolments the daemon holds, as `environment.inventory` reads them from its store.
async fn enrolments_of(
    client: &mut LocalClient,
) -> Vec<kr_protocol::identity::EnvironmentEnrolment> {
    let inventory: kr_protocol::identity::EnvironmentInventoryResult = typed(
        &client
            .request(
                Method::EnvironmentInventory,
                &kr_protocol::identity::EnvironmentInventoryParams {
                    access: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("environment.inventory is served"),
    );
    inventory
        .rows
        .into_iter()
        .map(|row| row.enrolment)
        .collect()
}

/// The groups `environment.list` reports, which is this environment's own and no other's.
async fn listed_groups(client: &mut LocalClient) -> Vec<(EnvironmentId, Option<MachineGroup>)> {
    let list: EnvironmentListResult = typed(
        &client
            .request(Method::EnvironmentList, &())
            .await
            .expect("the call reaches the daemon")
            .expect("environment.list is served"),
    );
    list.environments
        .into_iter()
        .map(|row| (row.environment_id, row.machine))
        .collect()
}

/// KR-REQ-03.11: grouping grants nothing. A device paired with one environment of a group gains
/// nothing on the other: no grant, no visibility, no route and no pairing there. A step that
/// changes an environment's group leaves its keys, its grants, its devices, its session identifiers,
/// its enrolments and its identity file as they were, bytes, mode, modification time and file
/// identity included, and every row of its registry but the step's own receipt, and an environment's
/// group is not what a bridge enrolment changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grouping_grants_nothing_to_a_device_paired_with_another_environment_of_the_group() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let mut first_client = first.client().await;
    let mut second_client = second.client().await;

    // A device paired with the first environment alone, which can manage it.
    let device = Device::create().await;
    let record = net_support::pair_with(
        &first,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::SessionView, ActionRight::HostManage]),
    )
    .await;
    let connection = RawDevice::connect(&first, &device, &record).await;

    // The second environment enrols another environment before its group changes, and both
    // registries hold a closed session and a fenced reservation.
    let enrolled_id = EnvironmentId::new(Uuid::from_bytes([9; 16]));
    let enrolment = kr_protocol::identity::EnvironmentEnrolment {
        environment_id: enrolled_id,
        access: kr_protocol::identity::EnvironmentAccess::SshHost,
        label: "elsewhere".to_owned(),
        target: "elsewhere.example".to_owned(),
        os_user: "kala".to_owned(),
        helper_path: "/usr/local/bin/kr".to_owned(),
        clipboard_destination: Nullable::null(),
        approved_at_ms: kr_protocol::scalars::TimestampMs::new(1),
    };
    second_client
        .mutate(
            Method::EnvironmentEnrol,
            action(),
            target(&second),
            &kr_protocol::identity::EnvironmentEnrolParams { enrolment },
        )
        .await
        .expect("reaches the daemon")
        .expect("enrols an environment");
    hold_sessions(&first, 0x30);
    hold_sessions(&second, 0x50);

    let first_before = group_of(&mut first_client).await;
    let second_before = group_of(&mut second_client).await;
    assert_ne!(first_before.machine_id, second_before.machine_id);
    let second_enrolments = enrolments_of(&mut second_client).await;
    assert_eq!(second_enrolments.len(), 1, "the enrolment is in the store");
    assert_eq!(
        listed_groups(&mut second_client)
            .await
            .iter()
            .map(|(environment, _)| *environment)
            .collect::<Vec<_>>(),
        vec![second.environment_id],
        "an enrolled environment's group is read from itself, never from the enrolment: the list \
         holds this environment alone"
    );
    let first_files = untouched_files(&first);
    let first_authority = rows_of_authority(&first);
    let first_rows = registry_rows(&first, &["authority_receipts", "network_actions"]);
    let second_files = untouched_files(&second);
    let second_authority = rows_of_authority(&second);
    let second_rows = registry_rows(&second, &["authority_receipts"]);
    assert!(
        second_files.len() > 3
            && second_rows["tombstones"].len() == 1
            && second_rows["reservations"].len() == 1,
        "the comparison holds files and session rows to compare"
    );
    assert!(
        !second_authority.contains(&format!("{:?}", record.device_id)),
        "the second environment knows nothing of the device before the group"
    );
    // No visibility, no route and no pairing: the device is not let in to the second environment.
    assert!(
        !lets_in(&second, &device, &record).await,
        "the device reached the second environment before any group"
    );

    // The owner puts both environments in one group, each by its own step.
    let shared = first_before.machine_id;
    let joined = join(&second, &mut second_client, shared, &second_before)
        .await
        .expect("the second environment joins the first's group");
    assert_eq!(joined.machine.machine_id, shared);
    assert_eq!(group_of(&mut first_client).await, first_before);

    // The device now sees the same group where it is paired, and nothing new anywhere else.
    let info: HostInfoResult = typed(
        &connection
            .read(Method::HostInfo, &())
            .await
            .expect("the device reads its own environment"),
    );
    assert_eq!(
        info.machine.as_ref().map(|group| group.machine_id),
        Some(shared)
    );
    assert_eq!(
        second_authority,
        rows_of_authority(&second),
        "no grant, device or pairing appeared on the second environment"
    );
    assert_eq!(
        second_rows,
        registry_rows(&second, &["authority_receipts"]),
        "the join changed a row of the second environment's registry"
    );
    assert!(
        second
            .controller()
            .devices()
            .record_for_device(record.device_id)
            .expect("readable")
            .is_none(),
        "the device is not paired with the second environment"
    );
    assert!(
        !lets_in(&second, &device, &record).await,
        "the group let the device into the second environment"
    );
    // Nothing of what it took to change the group touched the second environment's own files, its
    // enrolments included, and the enrolment still names no group.
    assert_eq!(second_files, untouched_files(&second));
    assert_eq!(
        enrolments_of(&mut second_client).await,
        second_enrolments,
        "the group change touched the enrolment"
    );
    assert_eq!(
        listed_groups(&mut second_client).await,
        vec![(second.environment_id, Some(joined.machine.clone()))],
        "the list reports the new group for this environment and no other"
    );

    // A step on the first environment, taken by the device that manages it, changes only the
    // record there, and the receipt and the route its own door keeps.
    let moved: MachineStepResult = typed(
        &connection
            .mutate(
                Method::MachineSplit,
                action(),
                target(&first),
                &MachineSplitParams {
                    expected: expecting(&first_before),
                },
            )
            .await
            .expect("the device splits the first environment"),
    );
    assert_ne!(moved.machine.machine_id, shared);
    assert_eq!(
        group_of(&mut second_client).await,
        joined.machine,
        "a step on one environment changes no other"
    );
    assert_eq!(first_files, untouched_files(&first));
    assert_eq!(
        first_authority,
        rows_of_authority(&first),
        "a step leaves the grants and the devices as they were"
    );
    assert_eq!(
        first_rows,
        registry_rows(&first, &["authority_receipts", "network_actions"]),
        "a step changed a row of the registry other than its own receipt and route"
    );

    // The controls: the comparisons above do detect what they claim to. The same device paired with
    // the second environment on purpose, by that environment's own owner, changes its rows, makes it
    // known there and lets it in; and a file rewritten with the bytes it already held is a change
    // the file comparison sees. What held before was the absence of a pairing and of a change, and
    // not a blind check.
    let second_record = net_support::pair_with(
        &second,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::SessionView]),
    )
    .await;
    assert_ne!(
        second_authority,
        rows_of_authority(&second),
        "an explicit pairing is a change the comparison sees"
    );
    assert_ne!(
        second_rows,
        registry_rows(&second, &["authority_receipts"]),
        "an explicit pairing is a change the registry comparison sees"
    );
    assert!(
        second
            .controller()
            .devices()
            .devices()
            .expect("readable")
            .iter()
            .any(|known| known.endpoint_id == record.endpoint_id),
        "the device is known to the second environment once it is paired with it"
    );
    assert!(
        lets_in(&second, &device, &second_record).await,
        "the device is let in where it is paired"
    );
    let marker = second.tree().environment().state_dir().join("environment");
    let held = std::fs::read(&marker).expect("the environment marker");
    std::fs::write(&marker, &held).expect("rewrites the marker with the bytes it held");
    assert_ne!(
        second_files,
        untouched_files(&second),
        "a rewrite with equal bytes is a change the file comparison sees"
    );

    // An environment's group is not what a bridge enrolment changes, on the first environment too.
    let enrolled_before = group_of(&mut first_client).await;
    let other = kr_protocol::identity::EnvironmentEnrolment {
        environment_id: EnvironmentId::new(Uuid::from_bytes([10; 16])),
        access: kr_protocol::identity::EnvironmentAccess::SshHost,
        label: "another".to_owned(),
        target: "another.example".to_owned(),
        os_user: "kala".to_owned(),
        helper_path: "/usr/local/bin/kr".to_owned(),
        clipboard_destination: Nullable::null(),
        approved_at_ms: kr_protocol::scalars::TimestampMs::new(1),
    };
    first_client
        .mutate(
            Method::EnvironmentEnrol,
            action(),
            target(&first),
            &kr_protocol::identity::EnvironmentEnrolParams { enrolment: other },
        )
        .await
        .expect("reaches the daemon")
        .expect("enrols an environment");
    assert_eq!(
        group_of(&mut first_client).await,
        enrolled_before,
        "an enrolment changes no group"
    );

    connection.close();
    drop(first_client);
    drop(second_client);
    first.stop().await;
    second.stop().await;
}

/// KR-REQ-03.07: a step that wrote nothing is answered as refused, and asked again under the same
/// action it is answered the same way, never as an outcome nobody knows. A record that became
/// unreadable while the daemon ran makes the step fail before it claims anything, so the action is
/// not spent: asked again it gets the same refusal, and the owner's step goes through once the
/// record is whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_that_wrote_nothing_is_answered_as_refused_every_time_it_is_asked() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let minted = group_of(&mut client).await;
    let record = host.tree().environment().state_dir().join(RECORD_FILE);
    let whole = std::fs::read(&record).expect("the record");
    kr_ipc::paths::write_owner_only_file(&record, b"damaged while the daemon ran")
        .expect("damages the record");

    let a = composed_join(&host, &mut client, some_group(0xd1), &minted).await;
    let first = client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect_err("the record cannot be read");
    assert_eq!(first.code, ErrorCode::StorageUnavailable);
    assert!(
        claim_of(&host, &a).is_none(),
        "a step that could not read the record claimed its action"
    );
    for _ in 0..2 {
        let again = client
            .repeat(&a)
            .await
            .expect("reaches the daemon")
            .expect_err("the same refusal");
        assert_eq!(
            again.code,
            ErrorCode::StorageUnavailable,
            "a step that wrote nothing is never an outcome nobody knows"
        );
    }

    // The record is whole again; a new action takes the step.
    kr_ipc::paths::write_owner_only_file(&record, &whole).expect("restores the record");
    let joined = join(&host, &mut client, some_group(0xd2), &minted)
        .await
        .expect("takes the step under a new action");
    assert_eq!(joined.machine.machine_id, some_group(0xd2));

    drop(client);
    host.stop().await;
}

/// KR-REQ-03.07: a step that claimed its action and then could not write the record is a refusal
/// the claim keeps: it changed nothing, so asked again under the same action it is answered the same
/// way and never as an outcome nobody knows, and its answer names no path. A new action takes the
/// step once the disk can be written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_that_claimed_its_action_and_could_not_write_keeps_its_refusal() {
    let host = Host::start_unowned().await;
    let mut client = host.client().await;
    let minted = group_of(&mut client).await;

    host.controller().fail_the_next_machine_write();
    let a = composed_join(&host, &mut client, some_group(0xd3), &minted).await;
    let first = client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect_err("the record cannot be written");
    assert_eq!(first.code, ErrorCode::StorageUnavailable);
    assert_names_no_path(&host, &first);
    assert!(
        matches!(
            claim_of(&host, &a),
            Some(kr_controller::grants::ActionRecord::Refused { .. })
        ),
        "the refusal was kept under the claim: {:?}",
        claim_of(&host, &a)
    );
    let again = client
        .repeat(&a)
        .await
        .expect("reaches the daemon")
        .expect_err("the same refusal");
    assert_eq!(again.code, ErrorCode::StorageUnavailable);
    assert_eq!(group_of(&mut client).await, minted, "nothing was written");

    let joined = join(&host, &mut client, some_group(0xd4), &minted)
        .await
        .expect("a new action takes the step");
    assert_eq!(joined.machine.machine_id, some_group(0xd4));

    drop(client);
    host.stop().await;
}

/// KR-REQ-03.07: a record this daemon cannot use is refused and left exactly as it is. The daemon
/// serves with no group, `host.doctor` fails a check that says what to do, every step is refused
/// without a claim, and nothing is minted over the record. Moving the file aside and restarting is
/// the repair: a missing record is a first start and mints a group of one, and the file moved
/// aside is still there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_or_foreign_record_is_refused_and_kept_and_moving_it_aside_repairs_it() {
    for foreign in [false, true] {
        let host = Host::start_unowned().await;
        let environment = host.tree().environment();
        let record = environment.state_dir().join(RECORD_FILE);
        let stopped = host.shut_down().await;
        let contents: Vec<u8> = if foreign {
            // A well-formed record of another environment.
            let text = std::fs::read_to_string(&record).expect("the record");
            text.replace(
                &stopped.tree().environment_id().to_string(),
                &EnvironmentId::new(Uuid::from_bytes([0x0f; 16])).to_string(),
            )
            .into_bytes()
        } else {
            b"this is not a machine group record".to_vec()
        };
        kr_ipc::paths::write_owner_only_file(&record, &contents).expect("writes the record");
        let settings = stopped.settings().clone();
        let host = stopped.start(settings).await;
        let mut client = host.client().await;

        // No group is reported, and the doctor says why and what to do.
        assert!(info_of(&mut client).await.machine.is_none());
        let (status, text) = doctor_check(&mut client).await;
        assert_eq!(status, DoctorStatus::Failed);
        assert!(text.contains("machine-group"), "{text}");
        assert!(text.contains("move"), "{text}");
        assert!(text.contains("restart"), "{text}");
        assert!(text.contains("kr host machine join"), "{text}");

        // A step is refused, writes nothing and claims nothing, however often it is asked.
        let step = client
            .compose(
                Method::MachineSplit,
                action(),
                target(&host),
                &MachineSplitParams {
                    expected: MachineExpected {
                        machine_id: some_group(1),
                        revision: U64::new(1),
                    },
                },
            )
            .await
            .expect("composes");
        let refused = client
            .repeat(&step)
            .await
            .expect("reaches the daemon")
            .expect_err("a daemon with no group takes no step");
        assert_eq!(refused.code, ErrorCode::StorageUnavailable);
        assert!(
            claim_of(&host, &step).is_none(),
            "a daemon with no group claimed the step's action, which would turn the next answer \
             into an outcome nobody knows"
        );
        let again = client
            .repeat(&step)
            .await
            .expect("reaches the daemon")
            .expect_err("the same refusal");
        assert_eq!(again.code, ErrorCode::StorageUnavailable);
        assert!(
            !refused
                .message
                .contains(&environment.state_dir().display().to_string()),
            "the refusal names no path: {}",
            refused.message
        );
        assert_eq!(
            std::fs::read(&record).expect("the record"),
            contents,
            "the record is left exactly as it was"
        );
        drop(client);

        // Moving the file aside and restarting mints a group of one, and keeps the file.
        let stopped = host.shut_down().await;
        let aside = environment.state_dir().join("machine-group.damaged");
        std::fs::rename(&record, &aside).expect("moves the record aside");
        let settings = stopped.settings().clone();
        let host = stopped.start(settings).await;
        let mut client = host.client().await;
        let minted = group_of(&mut client).await;
        assert_eq!(minted.revision, U64::new(1));
        assert_eq!(minted.change, MachineChange::Created);
        assert_eq!(
            std::fs::read(&aside).expect("the file moved aside"),
            contents
        );
        let (status, _) = doctor_check(&mut client).await;
        assert_eq!(status, DoctorStatus::Ok);
        // And the owner joins a known group, which is the other half of the repair.
        let joined = join(&host, &mut client, some_group(0xaa), &minted)
            .await
            .expect("joins a known group");
        assert_eq!(joined.machine.machine_id, some_group(0xaa));

        drop(client);
        host.stop().await;
    }
}

/// Where this suite stops a step on its way to the record.
#[derive(Clone, Copy, Debug)]
enum Point {
    /// Once the step has claimed its action, before its authority is asked about again and the
    /// record is read.
    BeforeTheWrite,
    /// Once its new record is written and flushed, before the record is replaced and the authority
    /// is asked about for the last time.
    AtTheReplacement,
    /// For a retry: once it has found its action's claim unfinished, before it takes its turn.
    Retry,
}

/// Runs `step`, stops it at `point` while `between` runs, and then lets it go. Returns what the step
/// came to, or `None` where its task ended without an answer, as one does when the host ends the
/// connection of a device it has revoked.
async fn held<S, B>(
    controller: &std::sync::Arc<kr_controller::service::Controller>,
    point: Point,
    step: S,
    between: B,
) -> Option<S::Output>
where
    S: std::future::Future + Send + 'static,
    S::Output: Send + 'static,
    B: std::future::Future<Output = ()>,
{
    let (arrived, go): (_, Box<dyn FnOnce() + Send>) = match point {
        Point::BeforeTheWrite => {
            let (arrived, go) = controller.hold_the_next_machine_step();
            (
                arrived,
                Box::new(move || go.send(()).expect("lets the step go")),
            )
        }
        Point::AtTheReplacement => {
            let (arrived, go) = controller.hold_the_next_machine_publication();
            (
                arrived,
                Box::new(move || go.send(()).expect("lets the step go")),
            )
        }
        Point::Retry => {
            let (arrived, go) = controller.hold_the_next_machine_retry();
            (
                arrived,
                Box::new(move || go.send(()).expect("lets the retry go")),
            )
        }
    };
    let step = tokio::spawn(step);
    arrived.await.expect("the step reached its hold");
    between.await;
    go();
    step.await.ok()
}

/// The join a step takes, as the parameters carry it.
fn joining(into: MachineId, expected: &MachineGroup) -> MachineJoinParams {
    MachineJoinParams {
        machine_id: into,
        expected: expecting(expected),
    }
}

/// KR-REQ-03.07: the authority a step was admitted under is checked again where it counts, at
/// both points a step can be stopped at: before its record is read, and at the moment its record is
/// replaced. Another device's revocation, which withdraws that device alone and moves the host's
/// authority on, makes the step refused at either door and at either point, with the refusal
/// itself and not a connection that went away; the device's own revocation ends its connection;
/// and in every case the record is as it was, so the owner's next step, approved against the record
/// the step saw, still finds it. A caller that has lost its authority is told that, and nothing of
/// the record. The control is the same step with nothing withdrawn, which writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_authority_a_step_was_admitted_under_is_checked_again_at_the_write() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut local = host.client().await;
    let mut current = group_of(&mut local).await;
    let controller = host.controller().clone();

    let pair = |rights: Vec<ActionRight>| {
        let host = &host;
        let owner = &owner;
        async move {
            let device = Device::create().await;
            let record =
                net_support::pair_with(host, &device, owner, net_support::proposal(&rights)).await;
            (device, record)
        }
    };
    // The owner's step, approved against the record the withdrawn step saw: it finds that record
    // unchanged, so nothing was written, and it also leaves nothing on its way to the record.
    // Another device's revocation leaves the owner's connection standing, and a device's own
    // revocation withdraws every registration, so the owner connects again before each one.
    let mut next = 0xc0_u8;
    macro_rules! unchanged_and_moved_on {
        () => {{
            drop(local);
            local = host.client().await;
            assert_eq!(
                group_of(&mut local).await,
                current,
                "the withdrawn step wrote"
            );
            next += 1;
            current = join(&host, &mut local, some_group(next), &current)
                .await
                .expect("the owner's step finds the record as the withdrawn step saw it")
                .machine;
        }};
    }

    for (point, first) in [
        (Point::BeforeTheWrite, 0xb0_u8),
        (Point::AtTheReplacement, 0xb8),
    ] {
        // Another device is revoked after the step was admitted: a device's step.
        let (managing, managing_record) = pair(vec![ActionRight::HostManage]).await;
        let (_other, other_record) = pair(vec![ActionRight::SessionView]).await;
        let connection = RawDevice::connect(&host, &managing, &managing_record).await;
        let params = joining(some_group(first), &current);
        let environment = target(&host);
        let revoked = other_record.device_id;
        let answer = held(
            &controller,
            point,
            async move {
                connection
                    .mutate(Method::MachineJoin, action(), environment, &params)
                    .await
            },
            async {
                host.network()
                    .revoke_device(revoked)
                    .await
                    .expect("revokes the other device");
            },
        )
        .await
        .expect("another device's revocation does not end this device's connection")
        .expect_err("admitted under an authority since replaced");
        assert_eq!(
            answer.code,
            ErrorCode::PermissionDenied,
            "{point:?}, device door"
        );
        assert!(
            answer.message.contains("withdrawn"),
            "{point:?}, device door: {}",
            answer.message
        );
        assert_eq!(
            group_of(&mut local).await,
            current,
            "the withdrawn step wrote"
        );

        // The same revocation, and a step at the daemon's own socket.
        let (_another, another_record) = pair(vec![ActionRight::SessionView]).await;
        let params = joining(some_group(first + 1), &current);
        let environment = target(&host);
        let revoked = another_record.device_id;
        let (returned, answer) = held(
            &controller,
            point,
            async move {
                let answer = local
                    .mutate(Method::MachineJoin, action(), environment, &params)
                    .await
                    .expect("the call reaches the daemon");
                (local, answer)
            },
            async {
                host.network()
                    .revoke_device(revoked)
                    .await
                    .expect("revokes the other device");
            },
        )
        .await
        .expect("the owner's connection stands");
        local = returned;
        let answer = answer.expect_err("admitted under an authority since replaced");
        assert_eq!(
            answer.code,
            ErrorCode::PermissionDenied,
            "{point:?}, local door"
        );
        assert!(
            answer.message.contains("withdrawn"),
            "{point:?}, local door: {}",
            answer.message
        );
        unchanged_and_moved_on!();

        // The stepping device's own registration is withdrawn: its connection ends, and it may be
        // answered or not.
        let (managing_two, managing_two_record) = pair(vec![ActionRight::HostManage]).await;
        let connection = RawDevice::connect(&host, &managing_two, &managing_two_record).await;
        let params = joining(some_group(first + 2), &current);
        let environment = target(&host);
        let device_id = managing_two_record.device_id;
        let host_ref = &host;
        let answer = held(
            &controller,
            point,
            async move {
                connection
                    .mutate(Method::MachineJoin, action(), environment, &params)
                    .await
            },
            async move {
                host_ref
                    .client()
                    .await
                    .mutate(
                        Method::DeviceRevoke,
                        action(),
                        target(host_ref),
                        &kr_protocol::sharing::DeviceRevokeParams { device_id },
                    )
                    .await
                    .expect("reaches the daemon")
                    .expect("revokes the device");
            },
        )
        .await;
        if let Some(answer) = answer {
            assert_eq!(
                answer.expect_err("withdrawn before the write").code,
                ErrorCode::PermissionDenied
            );
        }
        unchanged_and_moved_on!();

        // A caller whose authority is gone is told that and nothing of the record: its
        // precondition is stale as well, and the answer is still the refusal.
        if matches!(point, Point::BeforeTheWrite) {
            let (managing_three, managing_three_record) = pair(vec![ActionRight::HostManage]).await;
            let (_third, third_record) = pair(vec![ActionRight::SessionView]).await;
            let connection =
                RawDevice::connect(&host, &managing_three, &managing_three_record).await;
            let seen = current.clone();
            let moved = join(&host, &mut local, some_group(first + 3), &current)
                .await
                .expect("the owner moves the record on");
            current = moved.machine;
            let params = joining(some_group(first + 4), &seen);
            let environment = target(&host);
            let revoked = third_record.device_id;
            let answer = held(
                &controller,
                point,
                async move {
                    connection
                        .mutate(Method::MachineJoin, action(), environment, &params)
                        .await
                },
                async {
                    host.network()
                        .revoke_device(revoked)
                        .await
                        .expect("revokes the other device");
                },
            )
            .await
            .expect("another device's revocation does not end this device's connection")
            .expect_err("a withdrawn caller is refused");
            assert_eq!(
                answer.code,
                ErrorCode::PermissionDenied,
                "a caller with no authority is told that, and nothing of the record: {}",
                answer.message
            );
            unchanged_and_moved_on!();
        }

        // The control: a device whose authority nothing withdrew, held at the same point.
        let (controlled, controlled_record) = pair(vec![ActionRight::HostManage]).await;
        let connection = RawDevice::connect(&host, &controlled, &controlled_record).await;
        let params = joining(some_group(first + 5), &current);
        let environment = target(&host);
        let answer = held(
            &controller,
            point,
            async move {
                connection
                    .mutate(Method::MachineJoin, action(), environment, &params)
                    .await
            },
            async {},
        )
        .await
        .expect("the device is still connected")
        .expect("nothing withdrawn, so it writes");
        let written: MachineStepResult = typed(&answer);
        assert_eq!(written.machine.machine_id, some_group(first + 5));
        assert_eq!(group_of(&mut local).await, written.machine);
        current = written.machine;

        // And the owner's own step, held at the same point.
        let params = joining(some_group(first + 6), &current);
        let environment = target(&host);
        let (returned, answer) = held(
            &controller,
            point,
            async move {
                let answer = local
                    .mutate(Method::MachineJoin, action(), environment, &params)
                    .await
                    .expect("the call reaches the daemon");
                (local, answer)
            },
            async {},
        )
        .await
        .expect("the owner's connection stands");
        local = returned;
        let written: MachineStepResult = typed(&answer.expect("nothing withdrawn, so it writes"));
        assert_eq!(written.machine.machine_id, some_group(first + 6));
        current = written.machine;
    }

    drop(local);
    host.stop().await;
}

/// A daemon that serves its own socket on a continuous clock this suite moves by hand, so that a
/// deadline passes by a condition and never by waiting.
struct ClockedHost {
    temp: kr_ipc::testing::TempHost,
    controller: std::sync::Arc<kr_controller::service::Controller>,
    endpoint: kr_ipc::paths::Endpoint,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
}

impl ClockedHost {
    async fn start(clocks: kr_controller::service::Clocks) -> Self {
        use kr_controller::service::{Controller, ControllerSetup};
        use kr_crypto::store::{StoreSelection, open_store_in};
        use kr_ipc::verify::ControllerIdentity;

        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let controller = kr_controller::testing::taken_over(|| {
            let secrets = environment.secrets_dir();
            Controller::start_on_clocks(
                ControllerSetup {
                    paths: environment.clone(),
                    environment_id,
                    identity: Box::new(move || {
                        let store = open_store_in(&secrets)
                            .expect("a secret store for the test environment");
                        Ok(
                            ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                                .expect("an identity"),
                        )
                    }),
                    secret_store: StoreSelection::File,
                    boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
                    supervisor: Box::new(net_support::RefusingSupervisor),
                    worker_program: PathBuf::from("/nonexistent/kr-worker"),
                    build_id: net_support::build(),
                    release: "0".to_owned(),
                    shell_packages: None,
                    terminal: Box::new(kr_controller::supervision::NoTerminal),
                },
                clocks.clone(),
            )
        })
        .await
        .unwrap_or_else(|error| panic!("the daemon starts: {error}"));
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
        let clients = tokio::spawn(std::sync::Arc::clone(&controller).serve_clients(listener));
        Self {
            temp,
            controller,
            endpoint,
            clients,
        }
    }

    async fn client(&self) -> LocalClient {
        LocalClient::connect(
            &self.endpoint,
            kr_protocol::local::LocalClientKind::Cli,
            net_support::build(),
        )
        .await
        .expect("connects to the control endpoint")
    }

    fn environment(&self) -> ActionTarget {
        ActionTarget::environment(self.temp.environment_id())
    }

    async fn stop(self) {
        self.clients.abort();
        let _ = self.clients.await;
        drop(self.controller);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// KR-REQ-03.07: the deadline a step was admitted under is checked at the moment its record is
/// replaced, not only before the record is written: the new record is written and flushed first, and
/// a deadline that passes meanwhile leaves the old record. The daemon runs on a clock this test
/// moves by hand: the step is stopped once its new record is written, the clock is moved past the
/// deadline, and the step goes on. Stopped before it reads the record, the same step is refused as
/// well, and the control, the clock where it was, writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_whose_deadline_passes_while_its_record_is_written_leaves_the_old_record() {
    let clock = kr_transport::clock::ManualClock::new();
    let host = ClockedHost::start(kr_controller::service::Clocks {
        continuous: std::sync::Arc::new(clock.clone()),
        wall: kr_controller::service::WallClock::system(),
    })
    .await;
    let controller = host.controller.clone();
    let mut client = host.client().await;
    let mut current = group_of(&mut client).await;
    let past_the_deadline =
        std::time::Duration::from_millis(kr_protocol::limits::MAX_MUTATION_TTL.get() + 1_000);

    // The control: held at the replacement with the clock where it was, the step writes.
    let params = joining(some_group(0xf0), &current);
    let environment = host.environment();
    let (returned, answer) = held(
        &controller,
        Point::AtTheReplacement,
        async move {
            let answer = client
                .mutate(Method::MachineJoin, action(), environment, &params)
                .await
                .expect("the call reaches the daemon");
            (client, answer)
        },
        async {},
    )
    .await
    .expect("the connection stands");
    client = returned;
    let written: MachineStepResult = typed(&answer.expect("the deadline stands, so it writes"));
    assert_eq!(written.machine.machine_id, some_group(0xf0));
    current = written.machine;
    assert_eq!(group_of(&mut client).await, current);

    for (point, into) in [
        (Point::AtTheReplacement, 0xe1_u8),
        (Point::BeforeTheWrite, 0xe2),
    ] {
        let record = host.temp.environment().state_dir().join(RECORD_FILE);
        let on_disk = std::fs::read(&record).expect("the record");
        let params = joining(some_group(into), &current);
        let environment = host.environment();
        let (returned, answer) = held(
            &controller,
            point,
            async move {
                let answer = client
                    .mutate(Method::MachineJoin, action(), environment, &params)
                    .await
                    .expect("the call reaches the daemon");
                (client, answer)
            },
            async {
                clock.advance(past_the_deadline);
            },
        )
        .await
        .expect("the connection stands");
        client = returned;
        let refused = answer.expect_err("the deadline passed before the record was replaced");
        assert_eq!(refused.code, ErrorCode::PermissionDenied, "{point:?}");
        assert!(
            refused.message.contains("deadline"),
            "{point:?}: {}",
            refused.message
        );
        assert_eq!(
            std::fs::read(&record).expect("the record"),
            on_disk,
            "{point:?}: a step whose deadline had passed wrote"
        );
        assert_eq!(group_of(&mut client).await, current);
        let leftovers: Vec<_> = std::fs::read_dir(host.temp.environment().state_dir())
            .expect("reads the state directory")
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".machine-group.")
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "{point:?}: a refused step left its file"
        );
        // The owner's next step finds the record, over a connection whose action window the moved
        // clock has not outlived.
        drop(client);
        client = host.client().await;
        current = {
            let params = joining(some_group(into + 0x10), &current);
            let moved = client
                .mutate(Method::MachineJoin, action(), host.environment(), &params)
                .await
                .expect("the call reaches the daemon")
                .expect("a step under a deadline that stands writes");
            typed::<MachineStepResult>(&moved).machine
        };
    }

    drop(client);
    host.stop().await;
}
