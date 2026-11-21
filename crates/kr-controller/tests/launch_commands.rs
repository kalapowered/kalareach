//! The saved launch commands through a real daemon: what the owner at the machine may do, and what
//! a paired device may not.
//!
//! The daemon runs on the loopback network as a host starts one. The owner reads, saves and removes
//! on the local socket; a paired device speaks to the same daemon over an authorised connection. A
//! refusal is asserted by its kind, never by its words.

mod net_support;

use kr_controller::service::net::devices::DeviceRecord;
use kr_crypto::keys::DeviceKeys;
use kr_ipc::client::LocalClient;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::ActionId;
use kr_protocol::launch_commands::{
    NamedLaunch, ShellLaunchCommandsListParams, ShellLaunchCommandsListResult,
    ShellLaunchCommandsRemoveParams, ShellLaunchCommandsRemoveResult,
    ShellLaunchCommandsSaveParams, ShellLaunchCommandsSaveResult,
};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::U64;
use kr_protocol::sharing::{RoleSelection, SessionRole};
use net_support::worker::{Adopted, share};
use net_support::{Device, Host, RawDevice, on_the_host, pair_with, proposal, recipient};

fn command(label: &str, arguments: &[&str]) -> NamedLaunch {
    NamedLaunch {
        label: label.to_owned(),
        program: "claude".to_owned(),
        arguments: arguments.iter().map(|word| (*word).to_owned()).collect(),
    }
}

async fn listed(client: &mut LocalClient) -> ShellLaunchCommandsListResult {
    client
        .request(
            Method::ShellLaunchCommandsList,
            &ShellLaunchCommandsListParams {},
        )
        .await
        .expect("the daemon answers")
        .expect("the list is read")
        .to_typed()
        .expect("decodes")
}

async fn saved(
    host: &Host,
    client: &mut LocalClient,
    expected: U64,
    command: NamedLaunch,
) -> ShellLaunchCommandsSaveResult {
    net_support::pairing::mutate(
        host.environment_id,
        client,
        Method::ShellLaunchCommandsSave,
        &ShellLaunchCommandsSaveParams {
            expected_revision: expected,
            command,
        },
    )
    .await
    .expect("the save is answered")
}

fn code<T>(outcome: Result<T, ProtocolError>) -> ErrorCode {
    match outcome {
        Ok(_) => panic!("this call is refused"),
        Err(error) => error.code,
    }
}

async fn read_by(connection: &RawDevice) -> Result<ShellLaunchCommandsListResult, ProtocolError> {
    connection
        .read(
            Method::ShellLaunchCommandsList,
            &ShellLaunchCommandsListParams {},
        )
        .await
        .map(|value| value.to_typed().expect("decodes"))
}

/// A device paired under `rights`, connected to the host.
async fn device_with(
    host: &Host,
    owner: &DeviceKeys,
    rights: &[ActionRight],
) -> (Device, DeviceRecord, RawDevice) {
    let device = Device::create().await;
    let record = pair_with(host, &device, owner, proposal(rights)).await;
    let connection = RawDevice::connect(host, &device, &record).await;
    (device, record, connection)
}

/// KR-REQ-13.11: the owner at the machine saves, replaces and removes launch commands on the local
/// socket and reads them back in order with every argument exact, and a restart of the daemon keeps
/// the list and its revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_local_owner_saves_changes_and_removes_launch_commands_and_a_restart_keeps_them() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let none = listed(&mut client).await;
    assert_eq!(none.revision, U64::ZERO);
    assert!(none.commands.is_empty());

    let first = saved(
        &host,
        &mut client,
        none.revision,
        command(
            "Claude Code",
            &["--resume", "two words", "", "C:\\tools\\agent.exe"],
        ),
    )
    .await;
    assert!(first.applied && first.changed && !first.replaced);
    let second = saved(&host, &mut client, first.revision, command("Codex", &[])).await;
    let replaced = saved(
        &host,
        &mut client,
        second.revision,
        command("CLAUDE code", &["--continue"]),
    )
    .await;
    assert!(replaced.changed && replaced.replaced);
    let labels = |list: &[NamedLaunch]| -> Vec<String> {
        list.iter().map(|held| held.label.clone()).collect()
    };
    assert_eq!(labels(&replaced.commands), ["CLAUDE code", "Codex"]);

    let removed: ShellLaunchCommandsRemoveResult = net_support::pairing::mutate(
        host.environment_id,
        &mut client,
        Method::ShellLaunchCommandsRemove,
        &ShellLaunchCommandsRemoveParams {
            expected_revision: replaced.revision,
            label: "codex".to_owned(),
        },
    )
    .await
    .expect("the removal is answered");
    assert!(removed.applied && removed.removed);
    let held = listed(&mut client).await;
    assert_eq!(held.revision, removed.revision);
    assert_eq!(labels(&held.commands), ["CLAUDE code"]);
    assert_eq!(held.commands[0].arguments, ["--continue"]);

    let stopped = host.shut_down().await;
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    let mut client = host.client().await;
    assert_eq!(
        listed(&mut client).await,
        held,
        "a restart keeps the list and its revision"
    );
    host.shut_down().await;
}

/// KR-REQ-13.11: a paired device that holds `host.manage` reads the list and is refused a save and
/// a removal by the ingress of those methods, which is the local door alone, even though it holds
/// the right.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_with_host_manage_lists_and_is_refused_a_save_and_a_remove_by_ingress() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut local = host.client().await;
    let kept = saved(
        &host,
        &mut local,
        U64::ZERO,
        command("Claude", &["--resume"]),
    )
    .await;

    let (_device, _record, connection) =
        device_with(&host, &owner, &[ActionRight::HostManage]).await;
    let read = read_by(&connection)
        .await
        .expect("a device that may manage the host lists");
    assert_eq!(read.revision, kept.revision);
    assert_eq!(read.commands, kept.commands, "the exact command lines");

    let save = connection
        .mutate(
            Method::ShellLaunchCommandsSave,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &ShellLaunchCommandsSaveParams {
                expected_revision: kept.revision,
                command: command("Other", &[]),
            },
        )
        .await;
    assert_eq!(code(save), ErrorCode::PermissionDenied);
    let remove = connection
        .mutate(
            Method::ShellLaunchCommandsRemove,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &ShellLaunchCommandsRemoveParams {
                expected_revision: kept.revision,
                label: "Claude".to_owned(),
            },
        )
        .await;
    assert_eq!(code(remove), ErrorCode::PermissionDenied);
    assert_eq!(
        listed(&mut local).await.commands,
        kept.commands,
        "nothing changed"
    );
    connection.close();
    host.shut_down().await;
}

/// KR-REQ-13.11: a paired device with `session.view` and no `host.manage` is refused the list by
/// its kind, and so is one whose pairing was revoked.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_with_session_view_and_no_host_manage_is_refused_the_list() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, _record, connection) =
        device_with(&host, &owner, &[ActionRight::SessionView]).await;
    assert_eq!(
        code(read_by(&connection).await),
        ErrorCode::PermissionDenied
    );
    connection.close();
    host.shut_down().await;
}

/// KR-REQ-13.11: a device that holds `session.view` only through a share of a session is refused
/// the list: no share role carries `host.manage`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_with_session_view_only_through_a_share_is_refused_the_list() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let (device, record) = recipient(&adopted.host, &adopted.owner).await;
    let grant = share(
        &adopted.host,
        worker.session_id,
        &device,
        &record,
        RoleSelection {
            include_live_screen: true,
            ..RoleSelection::plain(SessionRole::Viewer)
        },
    )
    .await;
    let connection = RawDevice::connect(&adopted.host, &device, &record).await;
    connection
        .read(
            Method::SessionOpen,
            &kr_protocol::session::SessionOpenParams {
                session_id: kr_protocol::scalars::Nullable::some(worker.session_id),
                grant_id: kr_protocol::scalars::Nullable::some(grant.grant_id),
            },
        )
        .await
        .expect("the share opens");
    assert_eq!(
        code(read_by(&connection).await),
        ErrorCode::PermissionDenied
    );
    connection.close();
    adopted.stop().await;
}

/// KR-REQ-13.11: a device whose pairing the owner revoked is refused the list: it is not admitted
/// again, and the connection it held answers nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_revoked_pairing_is_refused_the_list() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record, connection) = device_with(&host, &owner, &[ActionRight::HostManage]).await;
    assert!(
        read_by(&connection).await.is_ok(),
        "the device lists before it is revoked"
    );

    let mut local = host.client().await;
    let _: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
        host.environment_id,
        &mut local,
        Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: record.device_id,
        },
    )
    .await
    .expect("the owner revokes the device");
    assert!(
        RawDevice::admitted(&host, &device, &record).await.is_err(),
        "a revoked device is not admitted again"
    );
    connection.close();
    host.shut_down().await;
}
