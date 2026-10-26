//! A policy the host found restored waits for the person at this machine, through a real daemon.
//!
//! When a host finds the registry it holds put back to an earlier state, it writes that down in a
//! store of its own and refuses every grant but the owner's at this machine until the person at
//! this machine confirms the policy it holds. The record is read at a start, and the wait outlives
//! it. These cases place the record the way the finding writes it, and hold what a start makes of
//! each thing it can find, and what the confirmation does; the finding itself, through a feed that
//! is ahead of the registry, is held with the feed's own cases.

mod net_support;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_controller::grants::mirror;
use kr_controller::grants::restored::{self, Found, Record};
use kr_controller::quiet::Timer;
use kr_controller::service::net::devices::DeviceRecord;
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_controller::testing::HeldTimer;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::hostinfo::{DoctorStatus, HostDoctorResult};
use kr_protocol::ids::BuildId;
use kr_protocol::invitation::InviteGrantKind;
use kr_protocol::method::Method;
use kr_protocol::organisation::{HostPolicyConfirmParams, HostPolicyConfirmResult};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Digest256, TimestampMs};
use net_support::{Device, Host, connect, pair_with, proposal};

/// A host whose daemon started on a tree that holds a record of a restore, with a device paired
/// before the record was placed.
struct Restored {
    host: Host,
    owner: DeviceKeys,
    device: Device,
    record: DeviceRecord,
}

/// The file the record is kept in.
fn the_file(host: &Host) -> PathBuf {
    restored::file_beside(&host.tree().environment().registry_database())
}

/// A record naming a row no host holds.
fn a_record() -> Record {
    Record::of(Digest256::from_bytes([1; 32]), TimestampMs::new(1))
}

/// Pairs a device, stops the daemon, lets `place` change what the tree holds, and starts it again.
async fn a_host_started_on(place: impl FnOnce(&Path)) -> Restored {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = Device::create().await;
    let record = pair_with(
        &host,
        &device,
        &owner,
        proposal(&[ActionRight::SessionView]),
    )
    .await;
    let stopped = host.shut_down().await;
    place(stopped.tree().environment().registry_database().as_path());
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    Restored {
        host,
        owner,
        device,
        record,
    }
}

/// What the doctor says to a paired device, and whether it is served at all.
async fn doctor_as_the_device(
    host: &Host,
    device: &Device,
    record: &DeviceRecord,
) -> Result<HostDoctorResult, kr_client::ClientError> {
    let session = connect(host, device, record).await;
    session.read(Method::HostDoctor, &()).await
}

/// What the doctor says at this machine.
async fn doctor_at_the_machine(host: &Host) -> HostDoctorResult {
    let mut local = host.client().await;
    net_support::pairing::read(&mut local, Method::HostDoctor, &())
        .await
        .expect("the person at this machine is never refused")
}

/// The person at this machine confirms.
async fn confirms(host: &Host) -> HostPolicyConfirmResult {
    let mut local = host.client().await;
    net_support::pairing::mutate(
        host.environment_id,
        &mut local,
        Method::HostPolicyConfirm,
        &HostPolicyConfirmParams {},
    )
    .await
    .expect("the person at this machine confirms")
}

fn is_refused_for_the_restored_policy<T: std::fmt::Debug>(
    outcome: &Result<T, kr_client::ClientError>,
) -> bool {
    outcome
        .as_ref()
        .err()
        .is_some_and(|error| error.to_string().contains("restored from an earlier state"))
}

/// KR-REQ-24.15: a host that finds the record of a restored policy refuses every device until the
/// person at this machine confirms the policy it holds, serves that person all the while, says so
/// in its doctor, and serves the device again once confirmed, across a restart too. The
/// confirmation changes none of the policy and is not asked for twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_policy_the_host_found_restored_waits_until_the_person_at_the_machine_confirms_it() {
    let Restored {
        host,
        device,
        record,
        ..
    } = a_host_started_on(|registry| {
        restored::write(&restored::file_beside(registry), &a_record()).expect("a record")
    })
    .await;
    let file = the_file(&host);

    let refused = doctor_as_the_device(&host, &device, &record).await;
    assert!(
        is_refused_for_the_restored_policy(&refused),
        "a device is refused, and told why, while the policy waits: {refused:?}"
    );
    let check = doctor_at_the_machine(&host)
        .await
        .checks
        .into_iter()
        .find(|check| check.id() == "restored-policy")
        .expect("the doctor says the policy waits");
    assert_eq!(check.status, DoctorStatus::Warning);
    assert!(
        check
            .remedy()
            .is_some_and(|remedy| remedy.contains("kr host policy --confirm")),
        "and says how it ends: {:?}",
        check.remedy()
    );
    assert!(
        matches!(restored::read(&file), Found::Record(_)),
        "the record stands"
    );

    assert!(confirms(&host).await.lifted, "the wait was ended");
    assert_eq!(restored::read(&file), Found::Missing, "the record is gone");
    doctor_as_the_device(&host, &device, &record)
        .await
        .expect("the device is served once the person at this machine has confirmed");
    assert!(
        doctor_at_the_machine(&host)
            .await
            .checks
            .iter()
            .all(|check| check.id() != "restored-policy"),
        "and the doctor no longer says the policy waits"
    );
    assert!(
        !confirms(&host).await.lifted,
        "nothing waits, so a second confirmation lifts nothing"
    );

    let host = host.restart().await;
    doctor_as_the_device(&host, &device, &record)
        .await
        .expect("a restart finds no record and waits for nothing");
}

/// KR-REQ-24.15: a record that cannot be read gives the closed side. The host waits, the doctor
/// says the record cannot be read, and the confirmation removes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_of_a_restore_that_cannot_be_read_is_a_wait_and_the_confirmation_removes_it() {
    let Restored {
        host,
        device,
        record,
        ..
    } = a_host_started_on(|registry| {
        std::fs::write(restored::file_beside(registry), b"not a record").expect("junk")
    })
    .await;
    let file = the_file(&host);

    let refused = doctor_as_the_device(&host, &device, &record).await;
    assert!(
        is_refused_for_the_restored_policy(&refused),
        "a record that cannot be read is no reason to serve: {refused:?}"
    );
    let check = doctor_at_the_machine(&host)
        .await
        .checks
        .into_iter()
        .find(|check| check.id() == "restored-policy")
        .expect("the doctor says the policy waits");
    assert!(
        check.detail().contains("cannot be read"),
        "and says the record cannot be read: {}",
        check.detail()
    );
    assert!(file.is_file(), "the host does not repair the file");

    assert!(confirms(&host).await.lifted);
    assert_eq!(restored::read(&file), Found::Missing, "the record is gone");
    doctor_as_the_device(&host, &device, &record)
        .await
        .expect("the device is served once the person at this machine has confirmed");
}

/// KR-REQ-24.15: a record of another format is no record this build reads, and waits the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_of_another_format_is_a_wait() {
    let Restored {
        host,
        device,
        record,
        ..
    } = a_host_started_on(|registry| {
        let other = Record {
            version: restored::RECORD_VERSION + 1,
            ..a_record()
        };
        std::fs::write(
            restored::file_beside(registry),
            kr_cbor::to_canonical_vec(&other).expect("encodes"),
        )
        .expect("a record of another format");
    })
    .await;
    assert!(
        is_refused_for_the_restored_policy(&doctor_as_the_device(&host, &device, &record).await),
        "a later release wrote what this one cannot vouch for"
    );
}

/// KR-REQ-24.15: a record describes a policy row, so a host that holds no policy row, and whose
/// mirror holds none, removes it and waits for nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_that_describes_no_policy_is_removed() {
    let Restored {
        host,
        device,
        record,
        ..
    } = a_host_started_on(|registry| {
        rusqlite::Connection::open(registry)
            .expect("the registry opens")
            .execute(
                "DELETE FROM host_authority WHERE key IN ('policy', 'policy_sequence')",
                [],
            )
            .expect("the policy row is gone");
        let _ = std::fs::remove_file(registry.with_file_name("policy-mirror.cbor"));
        restored::write(&restored::file_beside(registry), &a_record()).expect("a record");
    })
    .await;
    assert_eq!(
        restored::read(&the_file(&host)),
        Found::Missing,
        "a record that names no policy is removed"
    );
    doctor_as_the_device(&host, &device, &record)
        .await
        .expect("and nothing waits");
}

/// KR-REQ-24.15: a record naming a row other than the one the host holds (an earlier release
/// rewrote it, or it was changed while the wait stood) is a wait too, and the file is rewritten to
/// name the row now held. Nobody confirmed that row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_naming_another_row_is_a_wait_and_is_rewritten_to_name_the_row_held() {
    let Restored {
        host,
        device,
        record,
        ..
    } = a_host_started_on(|registry| {
        restored::write(&restored::file_beside(registry), &a_record()).expect("a record")
    })
    .await;
    assert!(
        is_refused_for_the_restored_policy(&doctor_as_the_device(&host, &device, &record).await),
        "a stale record waits"
    );
    let Found::Record(named) = restored::read(&the_file(&host)) else {
        panic!("the record stands");
    };
    assert_ne!(
        named.subject,
        a_record().subject,
        "it names the row now held"
    );
    assert_eq!(
        named.found_at_ms,
        a_record().found_at_ms,
        "and the moment the restore was found stays"
    );
    let host = host.restart().await;
    assert!(
        is_refused_for_the_restored_policy(&doctor_as_the_device(&host, &device, &record).await),
        "and a record that names the row held waits as well"
    );
}

/// The owner device signs the confirmation for issuing a session invitation, and the host is asked
/// to issue it.
async fn invites(
    host: &Host,
    owner: &DeviceKeys,
    local: &mut kr_ipc::client::LocalClient,
) -> Result<kr_protocol::invitation::PairInviteResult, kr_protocol::error::ProtocolError> {
    net_support::pairing::invite_direct(
        host.environment_id,
        local,
        InviteGrantKind::SessionInvitation,
        &proposal(&[ActionRight::SessionView]),
        &net_support::pairing::Signer::OwnerDevice(owner),
    )
    .await
}

/// KR-REQ-24.15: an owner device's confirmation is not spent while the policy waits. The wait takes
/// every remote device's standing away, an owner's too, so only the person at this machine can end
/// it; a confirmation signed after it has ended is spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_devices_confirmation_is_not_spent_while_the_policy_waits() {
    let Restored { host, owner, .. } = a_host_started_on(|registry| {
        restored::write(&restored::file_beside(registry), &a_record()).expect("a record")
    })
    .await;
    let mut local = host.client().await;
    let refused = invites(&host, &owner, &mut local)
        .await
        .expect_err("a remote owner device's confirmation is not spent while the policy waits");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refused:?}"
    );
    assert!(
        refused.message.contains("restored from an earlier state"),
        "refused for the wait and in its words: {refused:?}"
    );
    assert!(confirms(&host).await.lifted);
    invites(&host, &owner, &mut local)
        .await
        .expect("a confirmation signed once the wait has ended is spent");
}

/// KR-REQ-24.15: a copy of the policy that is there and cannot be read could have shown that the
/// registry was put back to an earlier state, and the host cannot tell now. The start writes the
/// record naming the row it holds before it replaces the copy, and the host waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_of_the_policy_that_cannot_be_read_is_a_wait_recorded_before_the_copy_is_replaced() {
    let Restored {
        host,
        device,
        record,
        ..
    } = a_host_started_on(|registry| {
        std::fs::write(mirror::file_beside(registry), b"not a copy").expect("junk")
    })
    .await;

    let refused = doctor_as_the_device(&host, &device, &record).await;
    assert!(
        is_refused_for_the_restored_policy(&refused),
        "a copy that cannot be read is no reason to serve: {refused:?}"
    );
    let Found::Record(named) = restored::read(&the_file(&host)) else {
        panic!("the record stands");
    };
    assert_eq!(
        named.subject,
        restored::subject_of(&host.controller().policy().snapshot()),
        "and names the row the host holds"
    );
    assert!(
        matches!(
            mirror::read(&mirror::file_beside(
                &host.tree().environment().registry_database()
            )),
            Ok(Some(_))
        ),
        "the start replaced the copy with one it reads"
    );
    assert!(confirms(&host).await.lifted);
    doctor_as_the_device(&host, &device, &record)
        .await
        .expect("the device is served once the person at this machine has confirmed");
}

struct NoWorkers;

impl WorkerSupervisor for NoWorkers {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

/// Starts a daemon on `host`, or says why it does not.
async fn try_to_start(host: &kr_ipc::testing::TempHost) -> kr_controller::Result<Arc<Controller>> {
    let environment = host.environment();
    let environment_id = host.environment_id();
    environment.create().expect("the environment's directories");
    let secrets = environment.secrets_dir();
    kr_controller::testing::taken_over(|| {
        let secrets = secrets.clone();
        kr_controller::testing::with_account_origin(
            None,
            Controller::start_on_timer(
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
                    supervisor: Box::new(NoWorkers),
                    worker_program: PathBuf::from("/nonexistent/kr-worker"),
                    build_id: BuildId::new("kr-test/0").expect("a build identifier"),
                    release: "0".to_owned(),
                    shell_packages: None,
                    terminal: Box::new(kr_controller::supervision::NoTerminal),
                },
                HeldTimer::held() as Arc<dyn Timer>,
            ),
        )
    })
    .await
}

/// KR-REQ-24.15: a start that cannot write the record of a copy it cannot read stops, and leaves the
/// copy as it was. Going on would replace the copy and lose the only evidence of what it held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_that_cannot_write_the_record_leaves_a_copy_it_cannot_read_as_it_was() {
    let host = kr_ipc::testing::TempHost::create();
    drop(try_to_start(&host).await.expect("a first start"));
    let registry = host.environment().registry_database();
    let copy = mirror::file_beside(&registry);
    std::fs::write(&copy, b"not a copy").expect("junk");
    std::fs::create_dir(restored::file_beside(&registry))
        .expect("something that is no file is in the record's place");

    let error = try_to_start(&host)
        .await
        .expect_err("the start stops where the record cannot be written");
    assert!(
        error.to_string().contains("restored-policy.cbor"),
        "and names the file: {error}"
    );
    assert_eq!(
        std::fs::read(&copy).expect("the copy is still there"),
        b"not a copy",
        "the copy it could not read is as it was"
    );
}
