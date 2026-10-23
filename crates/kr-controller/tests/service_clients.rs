//! The managed services a host holds, as `kr doctor` says them.
//!
//! A real daemon, started from a configuration document that selects services at the stand-in or
//! selects none, answers `host.doctor`. The `managed-services` check says, for each service a host
//! can hold, whether the daemon holds a client of it, and what to do instead when it does not.
//! Section 17 has the check explain availability and nothing more: it is never a warning or a
//! failure, because a host without a managed service is a complete host.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-17.14 | the `kr_req_17_14_` tests here, and the spent allowance in `relay_leases.rs` |

mod net_support;

use kr_client::services::ManagedService;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus, HostDoctorResult};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_service_stand_in::serve;
use net_support::{AccountAt, Host};

/// The services a host can hold. Push registration is a phone's.
const A_HOST_HOLDS: [ManagedService; 4] = [
    ManagedService::AccountLogin,
    ManagedService::RelayLeases,
    ManagedService::SyncBackup,
    ManagedService::ManagedInference,
];

/// What the daemon says of its managed services.
async fn managed_services(host: &Host) -> DoctorCheck {
    let mut local = host.client().await;
    let doctor: HostDoctorResult = net_support::pairing::read(&mut local, Method::HostDoctor, &())
        .await
        .expect("the host's diagnostics");
    doctor
        .checks
        .into_iter()
        .find(|check| check.id() == "managed-services")
        .expect("the managed-services check")
}

/// Whether the check says `service` is configured.
fn says_configured(check: &DoctorCheck, service: ManagedService) -> bool {
    check
        .detail()
        .contains(&format!("{}: configured", service.as_str()))
}

/// Whether the check says `service` is not configured, and what to do instead.
fn says_what_to_do_instead(check: &DoctorCheck, service: ManagedService) -> bool {
    let detail = check.detail();
    detail.contains(&format!("{}: not configured", service.as_str()))
        && detail.contains(service.alternative())
}

/// KR-REQ-17.14: a host whose configuration selects a relay lease service, a storage service and a
/// voice broker, all at the account service, holds a client for each of the four services a host
/// can hold, and says so. Nothing in the check is a warning.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_17_14_a_host_that_selects_every_service_says_each_is_configured() {
    let served = serve().await;
    let origin = served.origin().to_owned();
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.relay.origin = Nullable::some(origin.clone());
    document.storage.origin = Nullable::some(origin.clone());
    document.voice.broker_origin = Nullable::some(origin.clone());
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_with_document_at(&owner, &document, AccountAt::Origin(origin)).await;

    let check = managed_services(&host).await;
    assert_eq!(check.status, DoctorStatus::Ok, "{}", check.detail());
    for service in A_HOST_HOLDS {
        assert!(
            says_configured(&check, service),
            "{}: {}",
            service.as_str(),
            check.detail()
        );
    }
    host.stop().await;
}

/// KR-REQ-17.14: a host that selects nothing holds no managed client, says so for each service with
/// what to do instead, and the check is not a warning or a failure: the host is complete without
/// them. A host that cannot sign in anywhere has no account login to name either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_17_14_a_host_that_selects_nothing_says_what_to_do_instead() {
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_with_document(&owner, &document).await;

    let check = managed_services(&host).await;
    assert_eq!(
        check.status,
        DoctorStatus::NotApplicable,
        "{}",
        check.detail()
    );
    for service in A_HOST_HOLDS {
        assert!(
            says_what_to_do_instead(&check, service),
            "{}: {}",
            service.as_str(),
            check.detail()
        );
    }
    host.stop().await;
}

/// KR-REQ-17.14: a host that selects only a relay lease service at the account service holds the
/// account login it signs in at and the lease client, and says the other two are not configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_17_14_a_host_that_selects_one_service_says_which_it_holds() {
    let served = serve().await;
    let origin = served.origin().to_owned();
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.relay.origin = Nullable::some(origin.clone());
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_with_document_at(&owner, &document, AccountAt::Origin(origin)).await;

    let check = managed_services(&host).await;
    assert_eq!(
        check.status,
        DoctorStatus::NotApplicable,
        "{}",
        check.detail()
    );
    assert!(says_configured(&check, ManagedService::AccountLogin));
    assert!(says_configured(&check, ManagedService::RelayLeases));
    assert!(says_what_to_do_instead(&check, ManagedService::SyncBackup));
    assert!(says_what_to_do_instead(
        &check,
        ManagedService::ManagedInference
    ));
    host.stop().await;
}
