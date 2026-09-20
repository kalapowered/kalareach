//! The enrolled environments this host reaches, and the gate in front of the process bridge.
//!
//! Section 3 puts three separate promises here, and each has its own test below.
//!
//! * **The bridges serve locally authenticated command-line invocations only.** A paired device
//!   never reaches one, and a network actor cannot be relabelled a local owner by crossing one.
//! * **A listing starts nothing.** Stopped distributions come from an owner-approved cached
//!   inventory carrying `last_observed_at`, the environment identity and an explicit status, and a
//!   cached row is not evidence that a process is live.
//! * **Each installation is its own environment authority.** Enrolling one here grants this host
//!   nothing inside it, and a grouped listing keeps every identity distinct.
//!
//! The daemon these run against starts no workers, so nothing here needs a session. The
//! environment tree is a temporary one on the internal disk and goes when the test does.

#![cfg(unix)]

mod net_support;

use kr_protocol::actor::ActorIngress;
use kr_protocol::authority::AuthorityDecision;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::identity::{
    EnvironmentAccess, EnvironmentEnrolParams, EnvironmentEnrolResult, EnvironmentEnrolment,
    EnvironmentForgetParams, EnvironmentForgetResult, EnvironmentInventoryParams,
    EnvironmentInventoryResult, EnvironmentPresence, EnvironmentRefreshParams,
    EnvironmentRefreshResult, ObservationSource,
};
use kr_protocol::ids::{ActionId, EnvironmentId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

use net_support::{Host, build};

fn enrolment(byte: u8, label: &str, access: EnvironmentAccess) -> EnvironmentEnrolment {
    let target = match access {
        EnvironmentAccess::Container => format!("{byte:02x}").repeat(32),
        _ => format!("{label}-target"),
    };
    EnvironmentEnrolment {
        environment_id: EnvironmentId::new(Uuid::from_bytes([byte; 16])),
        access,
        label: label.to_owned(),
        target,
        os_user: "kala".to_owned(),
        helper_path: "/usr/local/bin/kr".to_owned(),
        clipboard_destination: Nullable::null(),
        approved_at_ms: TimestampMs::new(0),
    }
}

async fn enrol(
    client: &mut kr_ipc::client::LocalClient,
    host: &Host,
    record: EnvironmentEnrolment,
) -> EnvironmentEnrolResult {
    client
        .mutate(
            Method::EnvironmentEnrol,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &EnvironmentEnrolParams { enrolment: record },
        )
        .await
        .expect("the daemon answers")
        .expect("the owner may enrol an environment")
        .to_typed()
        .expect("an enrolment result")
}

async fn inventory(client: &mut kr_ipc::client::LocalClient) -> EnvironmentInventoryResult {
    client
        .request(
            Method::EnvironmentInventory,
            &EnvironmentInventoryParams {
                access: Nullable::null(),
            },
        )
        .await
        .expect("the daemon answers")
        .expect("the owner may read the inventory")
        .to_typed()
        .expect("an inventory")
}

#[tokio::test]
async fn an_enrolment_records_the_identity_the_user_and_the_absolute_helper_path() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;

    let record = enrolment(1, "ubuntu", EnvironmentAccess::WslDistribution);
    let enrolled = enrol(&mut client, &host, record.clone()).await;
    assert_eq!(enrolled.row.enrolment.target, "ubuntu-target");
    assert_eq!(enrolled.row.enrolment.os_user, "kala");
    assert_eq!(enrolled.row.enrolment.helper_path, "/usr/local/bin/kr");
    assert_eq!(enrolled.row.enrolment.environment_id, record.environment_id);

    let rows = inventory(&mut client).await.rows;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].enrolment, enrolled.row.enrolment);
    host.stop().await;
}

#[tokio::test]
async fn a_record_without_an_absolute_helper_path_is_refused() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;

    let mut incomplete = enrolment(1, "ubuntu", EnvironmentAccess::WslDistribution);
    incomplete.helper_path = "kr".to_owned();
    let error = client
        .mutate(
            Method::EnvironmentEnrol,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &EnvironmentEnrolParams {
                enrolment: incomplete,
            },
        )
        .await
        .expect("the daemon answers")
        .expect_err("an incomplete record is refused");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(inventory(&mut client).await.rows.is_empty());
    host.stop().await;
}

#[tokio::test]
async fn a_listing_reports_cached_rows_and_starts_nothing() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;

    // The target names a distribution that does not exist on this machine, and `wsl.exe` does not
    // exist here at all. A listing that asked the platform anything would fail; it answers.
    enrol(
        &mut client,
        &host,
        enrolment(1, "ubuntu", EnvironmentAccess::WslDistribution),
    )
    .await;
    let rows = inventory(&mut client).await.rows;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].observation, ObservationSource::Cache);
    assert_eq!(rows[0].status, EnvironmentPresence::Stale);
    assert!(!rows[0].is_evidence_of_a_live_process());
    // The row carries the three things section 3 names.
    assert_eq!(
        rows[0].enrolment.environment_id,
        rows[0].enrolment.environment_id
    );
    assert!(rows[0].last_observed_at_ms.get() > 0);
    host.stop().await;
}

#[tokio::test]
async fn a_cached_row_is_never_evidence_of_a_live_process() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    enrol(
        &mut client,
        &host,
        enrolment(1, "ubuntu", EnvironmentAccess::WslDistribution),
    )
    .await;
    for row in inventory(&mut client).await.rows {
        assert!(!row.is_evidence_of_a_live_process());
    }
    host.stop().await;
}

#[tokio::test]
async fn a_refresh_of_an_environment_this_machine_does_not_have_says_so_rather_than_inventing_one()
{
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let record = enrolment(1, "ubuntu", EnvironmentAccess::WslDistribution);
    enrol(&mut client, &host, record.clone()).await;

    // `wsl.exe` is not on this machine, so the refresh cannot observe anything. What it must not
    // do is report the environment running, and what it must not leave behind is a row that says
    // it was observed.
    let answered = client
        .mutate(
            Method::EnvironmentRefresh,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &EnvironmentRefreshParams {
                environment_id: record.environment_id,
                start: false,
            },
        )
        .await
        .expect("the daemon answers");
    match answered {
        Ok(value) => {
            let refreshed: EnvironmentRefreshResult = value.to_typed().expect("a refresh result");
            assert!(!refreshed.started);
            assert_ne!(refreshed.row.status, EnvironmentPresence::Running);
        }
        Err(error) => assert_eq!(error.code, ErrorCode::ResourceUnavailable, "{error}"),
    }
    for row in inventory(&mut client).await.rows {
        assert!(!row.is_evidence_of_a_live_process());
    }
    host.stop().await;
}

#[tokio::test]
async fn forgetting_removes_the_row_and_says_whether_there_was_one() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let record = enrolment(1, "ubuntu", EnvironmentAccess::WslDistribution);
    enrol(&mut client, &host, record.clone()).await;

    let forget = |environment_id: EnvironmentId| EnvironmentForgetParams { environment_id };
    let first: EnvironmentForgetResult = client
        .mutate(
            Method::EnvironmentForget,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &forget(record.environment_id),
        )
        .await
        .expect("the daemon answers")
        .expect("the owner may forget an environment")
        .to_typed()
        .expect("a removal");
    assert!(first.forgotten);
    assert!(inventory(&mut client).await.rows.is_empty());

    let second: EnvironmentForgetResult = client
        .mutate(
            Method::EnvironmentForget,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &forget(record.environment_id),
        )
        .await
        .expect("the daemon answers")
        .expect("forgetting twice is not a failure")
        .to_typed()
        .expect("a removal");
    assert!(!second.forgotten);
    host.stop().await;
}

#[tokio::test]
async fn a_grouped_listing_keeps_every_environment_identity_distinct() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;

    // Two enrolments that share a label, as a container destroyed and recreated under the same
    // human name would. The identity is what separates them; the label does not.
    let first = enrolment(1, "build", EnvironmentAccess::Container);
    let mut second = enrolment(2, "build", EnvironmentAccess::Container);
    second.target = "03".repeat(32);
    enrol(&mut client, &host, first.clone()).await;
    enrol(&mut client, &host, second.clone()).await;

    let rows = inventory(&mut client).await.rows;
    assert_eq!(rows.len(), 2);
    assert_ne!(
        rows[0].enrolment.environment_id,
        rows[1].enrolment.environment_id
    );
    assert_ne!(rows[0].enrolment.target, rows[1].enrolment.target);
    // Neither of them is this host's own environment. Grouping them for a person to look at does
    // not merge them with the environment the daemon owns.
    for row in &rows {
        assert_ne!(row.enrolment.environment_id, host.environment_id);
    }
    host.stop().await;
}

#[tokio::test]
async fn a_paired_device_never_reaches_the_bridge_or_the_inventory() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = net_support::Device::create().await;
    // The widest set of rights this suite can give a device. None of them opens a bridge, because
    // the registry refuses the ingress before a right is read.
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::HostManage, ActionRight::SessionView]),
    )
    .await;
    let raw = net_support::RawDevice::connect(&host, &device, &record).await;
    raw.claim();

    for method in [
        Method::EnvironmentEnrol,
        Method::EnvironmentForget,
        Method::EnvironmentRefresh,
    ] {
        let error = net_support::refusal(
            raw.mutate(
                method,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &EnvironmentForgetParams {
                    environment_id: host.environment_id,
                },
            )
            .await,
        );
        assert_eq!(
            error.code,
            ErrorCode::PermissionDenied,
            "{} must not be reachable from a device",
            method.as_str()
        );
    }
    raw.close();
    host.stop().await;
}

#[test]
fn the_registry_refuses_every_remote_ingress_on_every_environment_method() {
    // The refusal is the authority table's, not a check restated in the daemon. A method that is
    // local only is unreachable from the network whatever rights the caller holds.
    for method in [
        Method::EnvironmentEnrol,
        Method::EnvironmentForget,
        Method::EnvironmentInventory,
        Method::EnvironmentRefresh,
    ] {
        assert_eq!(
            method.entry().ingress,
            &[ActorIngress::LocalIpc],
            "{}",
            method.as_str()
        );
        for ingress in ActorIngress::ALL
            .iter()
            .copied()
            .filter(|ingress| *ingress != ActorIngress::LocalIpc)
        {
            let decision = kr_protocol::method::decide(method.as_str(), MethodVersion::V1, ingress);
            assert!(
                matches!(decision, AuthorityDecision::Denied(_)),
                "{} from {}",
                method.as_str(),
                ingress.as_str()
            );
        }
    }
}

#[test]
fn a_network_actor_is_refused_a_bridge_before_a_process_exists() {
    use kr_controller::bridge::invoke::{self, Refusal};
    use kr_protocol::actor::ActorEnvelope;
    use kr_protocol::identity::BridgeTarget;
    use kr_protocol::ids::{ActorId, ConnectionId, ControllerGeneration};

    let record = enrolment(1, "ubuntu", EnvironmentAccess::WslDistribution);
    for ingress in ActorIngress::ALL.iter().copied() {
        let actor = ActorEnvelope {
            actor_id: ActorId::new("device:1").expect("a principal"),
            ingress,
            device_id: Nullable::null(),
            grant_id: Nullable::null(),
            grant_revision: Nullable::null(),
            controller_generation: ControllerGeneration::new(1),
            connection_id: ConnectionId::new(Uuid::from_bytes([1; 16])),
        };
        let outcome = invoke::open(
            &actor,
            false,
            &record,
            EnvironmentId::new(Uuid::from_bytes([9; 16])),
            build(),
            BridgeTarget::Controller,
        );
        if ingress == ActorIngress::LocalIpc {
            let opening = outcome.expect("a local invocation opens a bridge");
            // The frame carries the ingress the request arrived on, so the far side records that
            // rather than the local IPC hop the helper makes there.
            assert_eq!(opening.hello.origin_ingress, ActorIngress::LocalIpc);
        } else {
            assert_eq!(
                outcome.expect_err("a refusal"),
                Refusal::NetworkActor { ingress }
            );
        }
    }
}

#[test]
fn a_wsl_environment_works_with_no_native_installation_of_this_product() {
    // Section 3: a WSL installation must work without a native Windows installation, and a native
    // bridge must not become a hidden dependency. Taking the bridge away is what shows it: the
    // Linux side is an ordinary environment with its own daemon, its own endpoint and its own
    // command line, and none of the things it needs to run is in this module.
    let tree = kr_ipc::testing::TempHost::create();
    let environment = tree.environment();
    // Its own endpoint, in its own runtime directory, under its own environment identity.
    let endpoint = environment
        .controller_endpoint()
        .expect("the distribution's own control endpoint");
    assert!(endpoint.as_path().starts_with(environment.runtime_root()));
    assert_eq!(
        kr_ipc::paths::read_environment_marker(environment.state_dir())
            .expect("its own environment identity"),
        tree.environment_id()
    );
    // And nothing in the enrolment record is needed to reach it: the record is what a *Windows*
    // host keeps so it can find the distribution, and this side has none.
    let store_path = environment.state_dir().join("environments.json");
    assert!(!store_path.exists());
}
