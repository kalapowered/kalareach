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

async fn join<'a>(
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
    let session_target = kr_protocol::envelope::ActionTarget {
        session_id: Nullable::some(kr_protocol::ids::SessionId::new(Uuid::from_bytes([5; 16]))),
        ..target(&host)
    };
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
            kr_protocol::envelope::ActionTarget {
                session_id: Nullable::some(kr_protocol::ids::SessionId::new(Uuid::from_bytes(
                    [6; 16],
                ))),
                ..target(&host)
            },
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

/// The bytes and metadata of the files that a step must leave alone: the host's identity file, the
/// environment's markers and the secret store.
fn untouched_files(host: &Host) -> BTreeMap<PathBuf, (Vec<u8>, u64)> {
    let paths = host.tree().paths();
    let environment = host.tree().environment();
    let mut found = BTreeMap::new();
    let mut take = |path: &Path| {
        if let Ok(bytes) = std::fs::read(path) {
            let length = std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
            found.insert(path.to_path_buf(), (bytes, length));
        }
    };
    take(&paths.environment_id_file());
    take(&environment.state_dir().join("environment"));
    take(&environment.runtime_dir().join("environment"));
    fn walk(directory: &Path, take: &mut impl FnMut(&Path)) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, take);
            } else {
                take(&path);
            }
        }
    }
    walk(&environment.secrets_dir(), &mut take);
    found
}

/// What the registry holds of the people and the sessions, as rows: the devices, the grants, and
/// the sessions the daemon knows.
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

/// KR-REQ-03.11: grouping grants nothing. A device paired with one environment of a group gains
/// nothing on the other: no grant, no visibility, no route and no pairing there. A step that
/// changes an environment's group leaves its keys, its grants, its devices and its identity file as
/// they were, and an environment's group is not what a bridge enrolment changes.
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

    let first_before = group_of(&mut first_client).await;
    let second_before = group_of(&mut second_client).await;
    assert_ne!(first_before.machine_id, second_before.machine_id);
    let first_files = untouched_files(&first);
    let first_rows = rows_of_authority(&first);
    let second_files = untouched_files(&second);
    let second_rows = rows_of_authority(&second);
    assert!(
        !second_rows.contains(&format!("{:?}", record.device_id)),
        "the second environment knows nothing of the device before the group"
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
        second_rows,
        rows_of_authority(&second),
        "no grant, device or pairing appeared on the second environment"
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
        second
            .controller()
            .devices()
            .action_route(&device_principal(&record), action())
            .expect("readable")
            .is_none(),
        "no route to the second environment was made for the device"
    );
    // Nothing of what it took to change the group touched the second environment's own files.
    assert_eq!(second_files, untouched_files(&second));

    // A step on the first environment, taken by the device that manages it, changes only the
    // record there.
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
        first_rows,
        rows_of_authority(&first),
        "a step leaves the grants and the devices as they were"
    );

    // The control: the comparisons above do detect a pairing. The same device paired with the
    // second environment on purpose, by that environment's own owner, changes its rows and makes
    // it known there, so what held before was the absence of a pairing and not a blind check.
    net_support::pair_with(
        &second,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::SessionView]),
    )
    .await;
    assert_ne!(
        second_rows,
        rows_of_authority(&second),
        "an explicit pairing is a change the comparison sees"
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

    // An environment's group is not what a bridge enrolment changes.
    let enrolled_before = group_of(&mut first_client).await;
    let enrolment = kr_protocol::identity::EnvironmentEnrolment {
        environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
        access: kr_protocol::identity::EnvironmentAccess::SshHost,
        label: "elsewhere".to_owned(),
        target: "elsewhere.example".to_owned(),
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
            &kr_protocol::identity::EnvironmentEnrolParams { enrolment },
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

fn device_principal(
    record: &kr_controller::service::net::devices::DeviceRecord,
) -> kr_protocol::ids::ActorId {
    record.principal()
}

/// KR-REQ-03.07: a step that wrote nothing is answered as refused, and asked again under the same
/// action it is answered the same way, never as an outcome nobody knows. A record that became
/// unreadable while the daemon ran makes the step fail before it writes; the action is spent, and
/// the owner asks again under a new one once the record is whole.
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

        // A step is refused, writes nothing and claims nothing.
        let refused = local_step(
            &host,
            &mut client,
            Method::MachineSplit,
            action(),
            &MachineSplitParams {
                expected: MachineExpected {
                    machine_id: some_group(1),
                    revision: U64::new(1),
                },
            },
        )
        .await
        .expect_err("a daemon with no group takes no step");
        assert_eq!(refused.code, ErrorCode::StorageUnavailable);
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

/// One step a device takes while this suite holds it between its admission and its write: the
/// step arrives, `between` runs while it is held, and the step is let go. A host ends a revoked
/// device's connection, so the step may be answered with a refusal or not at all.
async fn held_step<F, Fut>(
    host: &Host,
    connection: RawDevice,
    params: MachineJoinParams,
    between: F,
) -> Option<std::result::Result<ParamsValue, ProtocolError>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let (arrived, go) = host.controller().hold_the_next_machine_step();
    let environment = target(host);
    let step = tokio::spawn(async move {
        connection
            .mutate(Method::MachineJoin, action(), environment, &params)
            .await
    });
    arrived.await.expect("the step reached its write");
    between().await;
    go.send(()).expect("lets the step go");
    step.await.ok()
}

/// KR-REQ-03.07: the authority a step was admitted under is checked again at the write. A device
/// whose registration is withdrawn after its step was admitted and before it is written has that
/// step refused, so does one whose host's authority moved on under it, because another device was
/// revoked meanwhile and the step was admitted under the authority that replaced, and the record is
/// as it was either way: the owner's next step, approved against the record the device saw, still
/// finds it. The control is the same step with nothing withdrawn, which writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_authority_a_step_was_admitted_under_is_checked_again_at_the_write() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut local = host.client().await;
    let minted = group_of(&mut local).await;

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
    let revoke = |device_id| {
        let host = &host;
        let client = host.client();
        async move {
            client
                .await
                .mutate(
                    Method::DeviceRevoke,
                    action(),
                    target(host),
                    &kr_protocol::sharing::DeviceRevokeParams { device_id },
                )
                .await
                .expect("reaches the daemon")
                .expect("revokes the device");
        }
    };

    // Another device is revoked after the step was admitted and before it is written.
    let (managing, managing_record) = pair(vec![ActionRight::HostManage]).await;
    let (_other, other_record) = pair(vec![ActionRight::SessionView]).await;
    let connection = RawDevice::connect(&host, &managing, &managing_record).await;
    let answer = held_step(
        &host,
        connection,
        MachineJoinParams {
            machine_id: some_group(0xb1),
            expected: expecting(&minted),
        },
        || revoke(other_record.device_id),
    )
    .await;
    if let Some(answer) = answer {
        assert_eq!(
            answer
                .expect_err("admitted under an authority since replaced")
                .code,
            ErrorCode::PermissionDenied
        );
    }
    // The owner's step, approved against the record the device saw, finds it unchanged. It also
    // waits behind the held step, so nothing is still on its way to the record. A revocation
    // withdraws every connection's registration, so the owner connects again.
    drop(local);
    let mut local = host.client().await;
    let after_first = join(&host, &mut local, some_group(0xc1), &minted)
        .await
        .expect("the record was not written by the withdrawn step");

    // The device's own registration is withdrawn after the step was admitted and before it is
    // written.
    let (managing_two, managing_two_record) = pair(vec![ActionRight::HostManage]).await;
    let connection = RawDevice::connect(&host, &managing_two, &managing_two_record).await;
    let answer = held_step(
        &host,
        connection,
        MachineJoinParams {
            machine_id: some_group(0xb2),
            expected: expecting(&after_first.machine),
        },
        || revoke(managing_two_record.device_id),
    )
    .await;
    if let Some(answer) = answer {
        assert_eq!(
            answer.expect_err("withdrawn before the write").code,
            ErrorCode::PermissionDenied
        );
    }
    drop(local);
    let mut local = host.client().await;
    let after_second = join(&host, &mut local, some_group(0xc2), &after_first.machine)
        .await
        .expect("the record was not written by the withdrawn step");

    // The control: a device whose authority nothing withdrew, held at the same point.
    let (controlled, controlled_record) = pair(vec![ActionRight::HostManage]).await;
    let connection = RawDevice::connect(&host, &controlled, &controlled_record).await;
    let answer = held_step(
        &host,
        connection,
        MachineJoinParams {
            machine_id: some_group(0xb3),
            expected: expecting(&after_second.machine),
        },
        || async {},
    )
    .await
    .expect("the device is still connected")
    .expect("nothing withdrawn, so it writes");
    let written: MachineStepResult = typed(&answer);
    assert_eq!(written.machine.machine_id, some_group(0xb3));
    assert_eq!(group_of(&mut local).await, written.machine);

    drop(local);
    host.stop().await;
}
