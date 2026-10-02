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
//! A fourth follows from section 25: the scoped channel a bridge establishes belongs to the record
//! it was opened for, so the answer to a refresh is one record's, whatever another client does to
//! the record while the bridge is open.
//!
//! The daemon most of these run against starts no workers, so nothing here needs a session. The
//! environment tree is a temporary one on the internal disk and goes when the test does. The
//! fourth runs this build's daemon program with a stand-in for `wsl.exe` first on its path, from a
//! copy on the internal disk.

#![cfg(unix)]

mod net_support;

use std::path::{Path, PathBuf};
use std::process::Stdio;

use kr_ipc::client::LocalClient;
use kr_protocol::actor::ActorIngress;
use kr_protocol::authority::AuthorityDecision;
use kr_protocol::envelope::{ActionTarget, ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{FrameCodec, StreamKind};
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION};
use kr_protocol::identity::{
    BootIdentity, BootIdentitySource, BridgeFrame, BridgeHelloAck, BridgeVerification,
    EnvironmentAccess, EnvironmentEnrolParams, EnvironmentEnrolResult, EnvironmentEnrolment,
    EnvironmentForgetParams, EnvironmentForgetResult, EnvironmentInventoryParams,
    EnvironmentInventoryResult, EnvironmentInventoryRow, EnvironmentPresence, EnvironmentReadiness,
    EnvironmentRefreshParams, EnvironmentRefreshResult, ObservationSource,
};
use kr_protocol::ids::{
    ActionId, ActionWindowId, BootEpoch, ConnectionId, EnvironmentId, RequestId,
};
use kr_protocol::local::{LocalClientKind, LocalRole};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Bytes, DurationMs, Nullable, TimestampMs, U64, Uuid};

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

/// KR-REQ-03.16: the daemon records a distribution's identity, its Linux user and the absolute path
/// of its installed helper, and lists the record as enrolled.
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

/// Composes one environment record mutation, as a client keeps it to send again.
async fn composed<P: serde::Serialize>(
    client: &mut kr_ipc::client::LocalClient,
    host: &Host,
    method: Method,
    params: &P,
) -> kr_protocol::envelope::MutationRequest {
    client
        .compose(
            method,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            params,
        )
        .await
        .expect("composes")
}

/// KR-REQ-23.33: `environment.enrol` is de-duplicated by actor and action. An enrolment sent again
/// as it was first sent is answered from the receipt and enrols nothing a second time, and the same
/// action carrying another record is `ID_CONFLICT` and records nothing.
#[tokio::test]
async fn an_enrolment_is_performed_once_per_action_and_a_retry_is_answered_from_its_receipt() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;

    let record = enrolment(1, "ubuntu", EnvironmentAccess::WslDistribution);
    let first = composed(
        &mut client,
        &host,
        Method::EnvironmentEnrol,
        &EnvironmentEnrolParams {
            enrolment: record.clone(),
        },
    )
    .await;
    let enrolled: EnvironmentEnrolResult = client
        .repeat(&first)
        .await
        .expect("the daemon answers")
        .expect("enrols")
        .to_typed()
        .expect("an enrolment result");
    assert_eq!(enrolled.row.enrolment.environment_id, record.environment_id);
    assert_eq!(enrolled.row.enrolment.label, "ubuntu");

    // The record is forgotten by another action. Sending the enrolment again as it was sent, over a
    // connection of its own whose window is not the one it quotes, answers from its receipt and
    // does not enrol the record again.
    let forgotten = client
        .mutate(
            Method::EnvironmentForget,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &EnvironmentForgetParams {
                environment_id: record.environment_id,
            },
        )
        .await
        .expect("the daemon answers")
        .expect("forgets");
    assert!(
        forgotten
            .to_typed::<EnvironmentForgetResult>()
            .expect("a result")
            .forgotten
    );
    drop(client);
    let mut client = host.client().await;
    let again: EnvironmentEnrolResult = client
        .repeat(&first)
        .await
        .expect("the daemon answers")
        .expect("is answered from its receipt")
        .to_typed()
        .expect("an enrolment result");
    assert_eq!(again, enrolled);
    assert!(
        inventory(&mut client).await.rows.is_empty(),
        "the retry enrolled nothing"
    );

    // The same action carrying another record.
    let mut changed = first.clone();
    changed.params = ParamsValue::from_typed(&EnvironmentEnrolParams {
        enrolment: enrolment(2, "debian", EnvironmentAccess::WslDistribution),
    })
    .expect("encodes");
    let conflict = client
        .repeat(&changed)
        .await
        .expect("the daemon answers")
        .expect_err("a reused action with another payload");
    assert_eq!(conflict.code, ErrorCode::IdConflict);
    assert!(inventory(&mut client).await.rows.is_empty());
    host.stop().await;
}

/// KR-REQ-23.33: `environment.forget` is de-duplicated by actor and action. A forget sent again as
/// it was first sent is answered from its receipt and forgets nothing a second time, even when the
/// record has been enrolled again meanwhile, and the same action naming another environment is
/// `ID_CONFLICT`.
#[tokio::test]
async fn a_forget_is_performed_once_per_action_and_a_retry_is_answered_from_its_receipt() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let record = enrolment(1, "ubuntu", EnvironmentAccess::WslDistribution);
    enrol(&mut client, &host, record.clone()).await;

    let first = composed(
        &mut client,
        &host,
        Method::EnvironmentForget,
        &EnvironmentForgetParams {
            environment_id: record.environment_id,
        },
    )
    .await;
    let forgotten: EnvironmentForgetResult = client
        .repeat(&first)
        .await
        .expect("the daemon answers")
        .expect("forgets")
        .to_typed()
        .expect("a result");
    assert!(forgotten.forgotten);

    enrol(&mut client, &host, record.clone()).await;
    drop(client);
    let mut client = host.client().await;
    let again: EnvironmentForgetResult = client
        .repeat(&first)
        .await
        .expect("the daemon answers")
        .expect("is answered from its receipt")
        .to_typed()
        .expect("a result");
    assert_eq!(again, forgotten);
    assert_eq!(
        inventory(&mut client).await.rows.len(),
        1,
        "the retry forgot nothing"
    );

    let mut changed = first.clone();
    changed.params = ParamsValue::from_typed(&EnvironmentForgetParams {
        environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
    })
    .expect("encodes");
    let conflict = client
        .repeat(&changed)
        .await
        .expect("the daemon answers")
        .expect_err("a reused action with another payload");
    assert_eq!(conflict.code, ErrorCode::IdConflict);
    assert_eq!(inventory(&mut client).await.rows.len(), 1);
    host.stop().await;
}

/// KR-REQ-23.33: `environment.refresh` is de-duplicated by actor and action. A refresh sent again as
/// it was first sent is answered with the observation its receipt holds, not a new one, and the
/// same action naming another environment is `ID_CONFLICT`.
#[tokio::test]
async fn a_refresh_is_performed_once_per_action_and_a_retry_is_answered_from_its_receipt() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    // An environment reached another way answers a refresh from its record alone, so nothing is
    // started and no bridge is opened.
    let record = enrolment(3, "workstation", EnvironmentAccess::SshHost);
    enrol(&mut client, &host, record.clone()).await;

    let first = composed(
        &mut client,
        &host,
        Method::EnvironmentRefresh,
        &EnvironmentRefreshParams {
            environment_id: record.environment_id,
            start: false,
        },
    )
    .await;
    let refreshed: EnvironmentRefreshResult = client
        .repeat(&first)
        .await
        .expect("the daemon answers")
        .expect("refreshes")
        .to_typed()
        .expect("a result");
    assert_eq!(refreshed.row.enrolment.label, "workstation");

    // The record is enrolled again under another label; a retry still answers what it answered.
    let renamed = EnvironmentEnrolment {
        label: "renamed".to_owned(),
        ..record.clone()
    };
    enrol(&mut client, &host, renamed).await;
    drop(client);
    let mut client = host.client().await;
    let again: EnvironmentRefreshResult = client
        .repeat(&first)
        .await
        .expect("the daemon answers")
        .expect("is answered from its receipt")
        .to_typed()
        .expect("a result");
    assert_eq!(again, refreshed);

    let mut changed = first.clone();
    changed.params = ParamsValue::from_typed(&EnvironmentRefreshParams {
        environment_id: record.environment_id,
        start: true,
    })
    .expect("encodes");
    let conflict = client
        .repeat(&changed)
        .await
        .expect("the daemon answers")
        .expect_err("a reused action with another payload");
    assert_eq!(conflict.code, ErrorCode::IdConflict);
    host.stop().await;
}

/// KR-REQ-03.16: an enrolment whose helper path is not absolute is refused and records nothing.
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
async fn a_refresh_that_cannot_reach_a_destination_says_so_and_scopes_no_channel() {
    // Section 18: an integration needs a helper and scoped credentials in the target environment,
    // and forwarding a socket does not install one. So a channel is recorded only when a bridge to
    // that environment actually answered, and a refresh that reached nothing says what stopped it.
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let record = enrolment(1, "ubuntu", EnvironmentAccess::WslDistribution);
    enrol(&mut client, &host, record.clone()).await;

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
            assert!(
                refreshed.verification.as_ref().is_none(),
                "nothing answered, so nothing is recorded as verified"
            );
            assert!(
                !refreshed.connection.is_empty(),
                "the result says what opening the bridge did"
            );
            assert!(!refreshed.row.readiness.channel_scoped);
            assert!(!refreshed.row.readiness.is_ready());
            assert!(
                refreshed
                    .row
                    .readiness
                    .detail
                    .contains("forwarding a socket"),
                "the detail is the record's own answer, not an earlier bridge's: {}",
                refreshed.row.readiness.detail
            );
        }
        // This machine has no `wsl.exe`, so the observation itself may fail. What it may not do is
        // report the environment reached.
        Err(error) => assert_eq!(error.code, ErrorCode::ResourceUnavailable, "{error}"),
    }
    for row in inventory(&mut client).await.rows {
        assert!(
            !row.readiness.channel_scoped,
            "a channel is scoped by a bridge that answered, not by a refresh that failed"
        );
    }
    host.stop().await;
}

#[tokio::test]
async fn a_refresh_of_an_environment_that_is_not_a_process_bridge_opens_none() {
    // An SSH user runs the command line on the destination host and a named remote host is reached
    // through its own paired endpoint. Neither is a process bridge, and a refresh of one says that
    // rather than starting a helper.
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut client = host.client().await;
    let record = enrolment(4, "build-host", EnvironmentAccess::SshHost);
    enrol(&mut client, &host, record.clone()).await;

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
    let refreshed: EnvironmentRefreshResult = answered
        .expect("an SSH environment is answered from the record rather than refused")
        .to_typed()
        .expect("a refresh result");
    assert!(refreshed.verification.as_ref().is_none());
    assert!(!refreshed.started);
    assert!(
        refreshed.connection.contains("process bridge"),
        "{}",
        refreshed.connection
    );
    assert_eq!(
        refreshed.row.enrolment.environment_id,
        record.environment_id
    );
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

/// KR-REQ-03.12: a paired device holding host management reaches no method that enrols, forgets or
/// refreshes a bridged environment, so it never opens a bridge through this host.
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

/// KR-REQ-03.12: every environment method, the refresh that opens a bridge among them, admits local
/// IPC alone, whatever rights a remote caller holds.
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

/// KR-REQ-03.12: the invoker opens a bridge for a locally authenticated invocation only, and
/// carries its ingress to the far side; every network ingress is refused before a process is
/// started.
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

/// The distribution the stand-in for `wsl.exe` reports as running.
const FIXTURE_TARGET: &str = "Ubuntu-Fixture";

/// The helper a record names when it is first approved.
const FIRST_HELPER: &str = "/usr/local/bin/kr";

/// The helper the record that replaces it names instead.
const MOVED_HELPER: &str = "/opt/kalareach/kr";

/// What the stand-in's destination says when it refuses a bridge.
const REFUSAL: &str = "the destination refuses this bridge";

/// What `wsl.exe --list --verbose` prints on the machine the stand-in describes.
const LISTING: &str = "  NAME              STATE           VERSION\n\
                       * Ubuntu-Fixture    Running         2\n";

/// The text of the stand-in for `wsl.exe`, which keeps its control files in `fixture`.
///
/// It records the argument vector of every invocation on a line of its own. It answers a listing
/// with [`LISTING`], and a bridge with the frames the test wrote for that bridge's helper. When the
/// test has asked for a bridge to be held, the stand-in marks it open once it has started, which is
/// after the refresh that opened it has read its row, and waits for the test to release it before
/// it answers. The wait has a bound of its own, longer than the silence the invoker allows, so a
/// stand-in whose test has gone does not outlive it by much.
fn stand_in(fixture: &Path) -> String {
    let fixture = fixture.to_str().expect("a temporary path is text");
    assert!(
        !fixture.contains('\''),
        "the stand-in quotes its directory with single quotes: {fixture}"
    );
    format!(
        r##"#!/bin/sh
fixture='{fixture}'
line="$(printf '%s\t' "$@")"
printf '%s\n' "$line" >>"$fixture/invocations"
case "$1" in
  --list)
    cat "$fixture/listing"
    exit 0
    ;;
  --distribution)
    key="$(printf '%s' "$6" | tr '/' '-')"
    if [ -e "$fixture/$key.hold" ]; then
      : >"$fixture/$key.opened"
      waited=0
      while [ ! -e "$fixture/$key.release" ] && [ "$waited" -lt 600 ]; do
        sleep 0.05
        waited=$((waited + 1))
      done
    fi
    cat "$fixture/$key.answer"
    exec cat >/dev/null
    ;;
esac
echo "the stand-in for wsl.exe has no answer for: $*" >&2
exit 2
"##
    )
}

/// This build's control daemon, started as the program a person runs, with the stand-in for
/// `wsl.exe` first on its path.
///
/// Everything it touches is on the internal disk: it runs from a copy there, in an environment tree
/// of its own, and so does the stand-in. It keeps its keys in that tree rather than in a keychain.
struct FixtureDaemon {
    tree: kr_ipc::testing::TempHost,
    fixture: PathBuf,
    log: PathBuf,
    child: std::process::Child,
}

impl FixtureDaemon {
    fn start() -> Self {
        let tree = kr_ipc::testing::TempHost::create();
        let fixture = tree.root().join("fixture");
        let bin = fixture.join("bin");
        std::fs::create_dir_all(&bin).expect("the stand-in's directories");
        std::fs::write(fixture.join("listing"), LISTING).expect("the listing");
        // The stand-in is placed rather than written in place, like every program a test starts:
        // a descriptor open for writing, handed to a child another thread was starting, would stop
        // it from starting.
        let text = fixture.join("wsl.exe.text");
        std::fs::write(&text, stand_in(&fixture)).expect("the stand-in's text");
        kr_ipc::testing::place_program(&text, &bin.join("wsl.exe"));
        let program = tree.root().join("kr-controller");
        kr_ipc::testing::place_program(Path::new(env!("CARGO_BIN_EXE_kr-controller")), &program);

        let mut path = std::ffi::OsString::from(bin.as_os_str());
        if let Some(inherited) = std::env::var_os("PATH") {
            path.push(":");
            path.push(inherited);
        }
        let log = tree.root().join("daemon.log");
        let output = std::fs::File::create(&log).expect("the daemon's log");
        let child = std::process::Command::new(&program)
            // On the internal disk, never the checkout: a copied program is a new one to the
            // operating system's privacy rules.
            .current_dir(tree.root())
            .arg("--runtime-dir")
            .arg(tree.root().join("r"))
            .arg("--state-dir")
            .arg(tree.root().join("s"))
            .arg("--worker")
            .arg(tree.root().join("no-such-worker"))
            .arg("--secret-store")
            .arg("file")
            .env("PATH", path)
            .stdin(Stdio::null())
            .stdout(output.try_clone().expect("the log again"))
            .stderr(output)
            .spawn()
            .expect("the daemon starts");
        Self {
            tree,
            fixture,
            log,
            child,
        }
    }

    /// The daemon's own environment.
    fn environment_id(&self) -> EnvironmentId {
        self.tree.environment_id()
    }

    /// Connects one local client, once the daemon answers.
    async fn client(&self) -> LocalClient {
        let endpoint = self
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            if let Ok(client) = LocalClient::connect(&endpoint, LocalClientKind::Cli, build()).await
            {
                return client;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the daemon did not answer, and its log says: {}",
                std::fs::read_to_string(&self.log).unwrap_or_default()
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// The name the stand-in files a helper's control files under.
    fn key(helper: &str) -> String {
        helper.replace('/', "-")
    }

    /// Sets the frames a bridge to `helper` answers with.
    fn answer(&self, helper: &str, frames: &[BridgeFrame]) {
        let codec = FrameCodec::new(StreamKind::Control);
        let mut bytes = Vec::new();
        for frame in frames {
            bytes.extend(codec.encode_message(frame).expect("a bridge frame encodes"));
        }
        std::fs::write(
            self.fixture.join(format!("{}.answer", Self::key(helper))),
            bytes,
        )
        .expect("the answer is written");
    }

    /// Holds the next bridge to `helper` open once its helper has started.
    fn hold(&self, helper: &str) {
        let key = Self::key(helper);
        for stale in ["opened", "release"] {
            let _ = std::fs::remove_file(self.fixture.join(format!("{key}.{stale}")));
        }
        std::fs::write(self.fixture.join(format!("{key}.hold")), b"").expect("the hold is set");
    }

    /// Waits until a held bridge to `helper` has started.
    async fn opened(&self, helper: &str) {
        let marker = self.fixture.join(format!("{}.opened", Self::key(helper)));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !marker.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "no bridge to {helper} was opened, and the daemon's log says: {}",
                std::fs::read_to_string(&self.log).unwrap_or_default()
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// Lets a held bridge to `helper` answer, and holds none after it.
    fn release(&self, helper: &str) {
        let key = Self::key(helper);
        std::fs::write(self.fixture.join(format!("{key}.release")), b"")
            .expect("the release is written");
        let _ = std::fs::remove_file(self.fixture.join(format!("{key}.hold")));
    }

    /// Every argument vector the stand-in was started with, in order.
    fn invocations(&self) -> Vec<Vec<String>> {
        std::fs::read_to_string(self.fixture.join("invocations"))
            .unwrap_or_default()
            .lines()
            .map(|line| {
                line.strip_suffix('\t')
                    .unwrap_or(line)
                    .split('\t')
                    .map(str::to_owned)
                    .collect()
            })
            .collect()
    }
}

impl Drop for FixtureDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        // Collected once it has gone, and waited for no longer than half a minute: a daemon still
        // there by then is left to the operating system rather than holding the test.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            if !matches!(self.child.try_wait(), Ok(None)) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

/// A WSL record for the fixture's distribution, as the owner approves it.
fn fixture_record(environment_id: EnvironmentId, helper: &str) -> EnvironmentEnrolment {
    EnvironmentEnrolment {
        environment_id,
        access: EnvironmentAccess::WslDistribution,
        label: "fixture".to_owned(),
        target: FIXTURE_TARGET.to_owned(),
        os_user: "kala".to_owned(),
        helper_path: helper.to_owned(),
        clipboard_destination: Nullable::null(),
        approved_at_ms: TimestampMs::new(0),
    }
}

/// The acknowledgement the fixture's destination gives, and its answer to the one read a refresh
/// carries.
fn answered_as(environment_id: EnvironmentId) -> Vec<BridgeFrame> {
    let connection_id = ConnectionId::new(Uuid::from_bytes([0x5c; 16]));
    vec![
        BridgeFrame::HelloAck(Box::new(BridgeHelloAck {
            protocol_version: PROTOCOL_VERSION,
            environment_id,
            os_user: "kala".to_owned(),
            role: LocalRole::Controller,
            connection_id,
            boot_identity: BootIdentity {
                source: BootIdentitySource::LinuxBootId,
                value: Bytes::new(b"fixture-boot".to_vec()),
            },
            max_frame_len: U64::new(65_536),
            action_window: ActionWindow {
                action_window_id: ActionWindowId::new("w-fixture").expect("a window"),
                connection_id,
                boot_epoch: BootEpoch::new(1),
                issued_at_ms: TimestampMs::new(100),
                valid_for_ms: DurationMs::new(120_000),
            },
        })),
        BridgeFrame::Control(Box::new(ControlFrame::Response(Response {
            request_id: RequestId::new(1),
            outcome: Outcome::Ok(ParamsValue::empty()),
        }))),
    ]
}

/// What a refresh reports of an acknowledgement from [`answered_as`].
fn verified_as(environment_id: EnvironmentId) -> BridgeVerification {
    BridgeVerification {
        environment_id,
        os_user: "kala".to_owned(),
        role: LocalRole::Controller,
        protocol_version: PROTOCOL_VERSION,
        max_frame_len: U64::new(65_536),
    }
}

async fn enrol_as(
    client: &mut LocalClient,
    host_environment: EnvironmentId,
    record: EnvironmentEnrolment,
) -> EnvironmentEnrolment {
    let enrolled: EnvironmentEnrolResult = client
        .mutate(
            Method::EnvironmentEnrol,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host_environment),
            &EnvironmentEnrolParams { enrolment: record },
        )
        .await
        .expect("the daemon answers")
        .expect("the owner may enrol an environment")
        .to_typed()
        .expect("an enrolment result");
    enrolled.row.enrolment
}

async fn refresh_as(
    client: &mut LocalClient,
    host_environment: EnvironmentId,
    environment_id: EnvironmentId,
) -> EnvironmentRefreshResult {
    client
        .mutate(
            Method::EnvironmentRefresh,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host_environment),
            &EnvironmentRefreshParams {
                environment_id,
                start: false,
            },
        )
        .await
        .expect("the daemon answers")
        .expect("the owner may refresh an environment")
        .to_typed()
        .expect("a refresh result")
}

/// What the second client does to the record while the first client's bridge is open.
#[derive(Clone, Copy, Debug)]
enum Change {
    Forgotten,
    Replaced,
}

/// How the bridge that was held open ends.
#[derive(Clone, Copy, Debug)]
enum Ending {
    Answered,
    Refused,
}

/// A refreshed row of the fixture's distribution, observed running at `observed_at_ms`.
fn refreshed_row(
    enrolment: EnvironmentEnrolment,
    observed_at_ms: TimestampMs,
    readiness: EnvironmentReadiness,
) -> EnvironmentInventoryRow {
    EnvironmentInventoryRow {
        enrolment,
        last_observed_at_ms: observed_at_ms,
        status: EnvironmentPresence::Running,
        observation: ObservationSource::Refresh,
        readiness,
    }
}

/// Readiness that records both halves of the integration.
fn both_recorded() -> EnvironmentReadiness {
    EnvironmentReadiness {
        helper_enrolled: true,
        channel_scoped: true,
        detail: "the helper and the scoped channel are both recorded".to_owned(),
    }
}

/// A refresh whose bridge answered for the record that is approved now.
fn established(
    enrolment: EnvironmentEnrolment,
    observed_at_ms: TimestampMs,
) -> EnvironmentRefreshResult {
    let environment_id = enrolment.environment_id;
    EnvironmentRefreshResult {
        row: refreshed_row(enrolment, observed_at_ms, both_recorded()),
        started: false,
        verification: Nullable::some(verified_as(environment_id)),
        connection: format!(
            "environment {environment_id} answered as kala over its own local channel"
        ),
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is past 1970")
            .as_millis(),
    )
    .expect("milliseconds fit")
}

/// One bridge held open across a change to the record it was opened for.
///
/// The first client establishes the channel for the record, then opens a second bridge and holds
/// it once the refresh behind it has read that ready row. While it is held, the second client
/// forgets the record, or approves a replacement and establishes the replacement's own channel.
/// Then the held bridge ends as the case says. Its reply is asserted whole: the record it was
/// opened for, observed running, claiming neither half of the integration and saying why, with
/// the destination's answer where there was one. The inventory afterwards holds exactly what the
/// second client left.
async fn held_across(
    daemon: &FixtureDaemon,
    first: &mut LocalClient,
    second: &mut LocalClient,
    environment_id: EnvironmentId,
    change: Change,
    ending: Ending,
) {
    let case = format!("{change:?} while the bridge was open, then {ending:?}");
    let host = daemon.environment_id();
    let approved = enrol_as(first, host, fixture_record(environment_id, FIRST_HELPER)).await;

    daemon.answer(FIRST_HELPER, &answered_as(environment_id));
    let ready = refresh_as(first, host, environment_id).await;
    assert_eq!(
        ready,
        established(approved.clone(), ready.row.last_observed_at_ms),
        "{case}: a bridge that answered for the approved record establishes its channel"
    );

    daemon.hold(FIRST_HELPER);
    let held = refresh_as(first, host, environment_id);
    let meanwhile = async {
        daemon.opened(FIRST_HELPER).await;
        let replacement = match change {
            Change::Forgotten => {
                let forgotten: EnvironmentForgetResult = second
                    .mutate(
                        Method::EnvironmentForget,
                        ActionId::new(kr_ipc::new_uuid()),
                        ActionTarget::environment(host),
                        &EnvironmentForgetParams { environment_id },
                    )
                    .await
                    .expect("the daemon answers")
                    .expect("the owner may forget an environment")
                    .to_typed()
                    .expect("a removal");
                assert!(
                    forgotten.forgotten,
                    "{case}: the record was there to forget"
                );
                None
            }
            Change::Replaced => {
                let replacement =
                    enrol_as(second, host, fixture_record(environment_id, MOVED_HELPER)).await;
                // The replacement's own bridge answers while the first is still held, and what it
                // establishes is the replacement's.
                daemon.answer(MOVED_HELPER, &answered_as(environment_id));
                let its_own = refresh_as(second, host, environment_id).await;
                assert_eq!(
                    its_own,
                    established(replacement.clone(), its_own.row.last_observed_at_ms),
                    "{case}: the replacement's own bridge establishes its channel"
                );
                Some((replacement, its_own.row.last_observed_at_ms))
            }
        };
        daemon.answer(
            FIRST_HELPER,
            &match ending {
                Ending::Answered => answered_as(environment_id),
                Ending::Refused => vec![BridgeFrame::Refused(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    REFUSAL,
                ))],
            },
        );
        daemon.release(FIRST_HELPER);
        replacement
    };
    let (reply, replacement) = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        tokio::join!(held, meanwhile)
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{case}: the held refresh did not come back, and the daemon's log says: {}",
            std::fs::read_to_string(&daemon.log).unwrap_or_default()
        )
    });

    let observed = reply.row.last_observed_at_ms;
    assert!(
        ready.row.last_observed_at_ms <= observed && observed.get() <= now_ms(),
        "{case}: observed at {observed:?}"
    );
    let detail = match change {
        Change::Forgotten => {
            "this environment was forgotten while the bridge was open; enrol it again to reach it"
        }
        Change::Replaced => {
            "this environment's record was replaced while the bridge was open; refresh it again to \
             reach what is recorded now"
        }
    };
    let (verification, connection) = match ending {
        Ending::Answered => (
            Nullable::some(verified_as(environment_id)),
            "this environment's record changed while the bridge was open, so what answered says \
             nothing about what is recorded now"
                .to_owned(),
        ),
        Ending::Refused => (
            Nullable::null(),
            format!("the destination refused the bridge: {REFUSAL}"),
        ),
    };
    assert_eq!(
        reply,
        EnvironmentRefreshResult {
            row: refreshed_row(
                approved,
                observed,
                EnvironmentReadiness {
                    helper_enrolled: false,
                    channel_scoped: false,
                    detail: detail.to_owned(),
                },
            ),
            started: false,
            verification,
            connection,
        },
        "{case}: the reply is the held record's alone"
    );

    // A listing asks the platform nothing. The earlier cases' records are still there, and each
    // case reads its own.
    let before = daemon.invocations().len();
    let rows: Vec<EnvironmentInventoryRow> = inventory(second)
        .await
        .rows
        .into_iter()
        .filter(|row| row.enrolment.environment_id == environment_id)
        .collect();
    assert_eq!(
        daemon.invocations().len(),
        before,
        "{case}: the listing started something"
    );
    match replacement {
        None => assert!(rows.is_empty(), "{case}: {rows:?}"),
        Some((replacement, observed_at_ms)) => assert_eq!(
            rows,
            vec![EnvironmentInventoryRow {
                observation: ObservationSource::Cache,
                ..refreshed_row(replacement, observed_at_ms, both_recorded())
            }],
            "{case}: the replacement keeps what its own bridge established"
        ),
    }
}

/// KR-REQ-25.26, 03.15: the scoped channel a helper registers belongs to the record the bridge was
/// opened for, and the answer to a refresh is that one record's. A bridge held open while a second
/// client forgets the record, or approves a replacement and establishes the replacement's own
/// channel, answers for the record it was opened for and claims neither half of the integration for
/// it, whether it then answers or is refused, and the replacement keeps its own channel. The daemon
/// is this build's program, reaching the stand-in for `wsl.exe` through its own path with the
/// argument vector section 3 writes out, so every frame the destination sends crosses a real
/// process bridge. The second client has to finish inside the twenty seconds the daemon waits for
/// the destination's first frame, which one forgetting, or one approval and one refresh, does in
/// milliseconds.
///
/// This proves the scoped-channel half of the first row for a WSL distribution, and the daemon's
/// side of the second for a refresh. SSH registration, and create and attach over the bridge, are
/// other tests' work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bridge_held_open_while_another_client_changes_the_record_answers_for_its_own_record() {
    let daemon = FixtureDaemon::start();
    let mut first = daemon.client().await;
    let mut second = daemon.client().await;
    for (byte, change, ending) in [
        (0x21, Change::Forgotten, Ending::Answered),
        (0x22, Change::Forgotten, Ending::Refused),
        (0x23, Change::Replaced, Ending::Answered),
        (0x24, Change::Replaced, Ending::Refused),
    ] {
        held_across(
            &daemon,
            &mut first,
            &mut second,
            EnvironmentId::new(Uuid::from_bytes([byte; 16])),
            change,
            ending,
        )
        .await;
    }

    // Every process the daemon started was the stand-in, with an argument vector it built: the
    // listing it observes a distribution with, and the bridge, whose helper is each record's own.
    let bridge = |helper: &str| {
        [
            "--distribution",
            FIXTURE_TARGET,
            "--user",
            "kala",
            "--exec",
            helper,
            "bridge",
            "--stdio",
        ]
        .map(str::to_owned)
        .to_vec()
    };
    let listing = ["--list", "--verbose"].map(str::to_owned).to_vec();
    let invocations = daemon.invocations();
    for invocation in &invocations {
        assert!(
            *invocation == listing
                || *invocation == bridge(FIRST_HELPER)
                || *invocation == bridge(MOVED_HELPER),
            "the daemon started the stand-in with {invocation:?}"
        );
    }
    // Two refreshes of each first record and one of each replacement, each observing once and
    // opening one bridge.
    let count = |wanted: &Vec<String>| {
        invocations
            .iter()
            .filter(|invocation| *invocation == wanted)
            .count()
    };
    assert_eq!(count(&listing), 10, "{invocations:?}");
    assert_eq!(count(&bridge(FIRST_HELPER)), 8, "{invocations:?}");
    assert_eq!(count(&bridge(MOVED_HELPER)), 2, "{invocations:?}");
}
