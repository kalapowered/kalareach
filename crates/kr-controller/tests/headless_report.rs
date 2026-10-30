//! What a daemon reports about a headless worker's logout behaviour, through both of its reports.
//!
//! KR-REQ-03.24: the answer for a headless worker is about the supervisor the daemon selected when
//! it started, because that is what a logout acts on. `host.doctor` and `environment.capabilities`
//! each build it at a call site of their own, so each is read here, on a daemon that started a
//! detached process and on one that started anything else, whatever service manager the machine
//! the test runs on offers. A call site that asked the platform at the time of the question would
//! name the machine's mechanism on one of them and not the daemon's.

#![cfg(unix)]

use std::sync::Arc;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{
    DETACHED_DESCRIPTION, DetachedSupervisor, LaunchOutcome, WorkerLaunch, WorkerSupervisor,
};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::desktop::{
    EnvironmentCapabilitiesParams, EnvironmentCapabilitiesResult, ProfilePersistence,
};
use kr_protocol::hostinfo::HostDoctorResult;
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::BuildId;
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;

/// The description of the supervisor that is not a detached process.
const OWN: &str = "a service manager of this test's own";

/// A supervisor that starts nothing and is not a detached process.
#[derive(Debug)]
struct Own;

impl WorkerSupervisor for Own {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        OWN
    }
}

/// What a daemon says about logout, read through each of its two reports.
struct Reports {
    /// The `host.doctor` check about a desktop-bound session, and the one about a headless one.
    doctor: (String, String),
    /// The two profiles as `environment.capabilities` lists them.
    capabilities: Vec<ProfilePersistence>,
}

/// Starts a daemon that selected `supervisor`, and reads both of its reports at its own socket.
async fn reports_of(supervisor: Box<dyn WorkerSupervisor>) -> Reports {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor,
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: BuildId::new("kr-test/0").expect("a build identifier"),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
    .expect("the daemon starts");
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let serving = tokio::spawn(
        Arc::clone(&controller)
            .serve_clients(Listener::bind(&endpoint).expect("binds the client endpoint")),
    );
    let mut client = LocalClient::connect(
        &endpoint,
        LocalClientKind::Cli,
        BuildId::new("kr-test/0").expect("a build identifier"),
    )
    .await
    .expect("connects to the control endpoint");

    let doctor: HostDoctorResult = client
        .request(Method::HostDoctor, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.doctor is served on the local socket")
        .to_typed()
        .expect("a result of the declared shape");
    let detail = |id: &str| {
        doctor
            .checks
            .iter()
            .find(|check| check.id() == id)
            .unwrap_or_else(|| panic!("host.doctor has a {id} check"))
            .detail()
            .to_owned()
    };
    let doctor = (
        detail("logout-desktop_bound"),
        detail("logout-headless_user"),
    );

    let capabilities: EnvironmentCapabilitiesResult = client
        .request(
            Method::EnvironmentCapabilities,
            &EnvironmentCapabilitiesParams { environment_id },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("environment.capabilities succeeds")
        .to_typed()
        .expect("a result of the declared shape");

    serving.abort();
    Reports {
        doctor,
        capabilities: capabilities.persistence,
    }
}

/// KR-REQ-03.24: a daemon that selected a detached process reports that for a headless worker in
/// both reports, and one that selected anything else reports that and not a detached process, in
/// both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_reports_are_about_the_supervisor_the_daemon_selected() {
    for (supervisor, description, detached) in [
        (
            Box::new(DetachedSupervisor::new()) as Box<dyn WorkerSupervisor>,
            DETACHED_DESCRIPTION,
            true,
        ),
        (Box::new(Own), OWN, false),
    ] {
        let reports = reports_of(supervisor).await;

        let (bound, headless) = &reports.doctor;
        assert!(
            bound.contains(description),
            "host.doctor names the daemon's supervisor for a desktop-bound session, {description}: \
             {bound}"
        );
        assert_eq!(
            headless.contains("detached process"),
            detached,
            "host.doctor's headless answer is about the daemon's supervisor, {description}: \
             {headless}"
        );

        let [bound, headless] = &reports.capabilities[..] else {
            panic!(
                "both profiles are reported: {:?}",
                reports.capabilities.len()
            );
        };
        assert_eq!(bound.profile, WorkerProfile::DesktopBound);
        assert_eq!(
            bound.mechanism().as_str(),
            description,
            "environment.capabilities names the daemon's supervisor for a desktop-bound session"
        );
        assert_eq!(headless.profile, WorkerProfile::HeadlessUser);
        assert_eq!(
            headless.mechanism().as_str().contains("detached process"),
            detached,
            "environment.capabilities' headless answer is about the daemon's supervisor, \
             {description}: {}",
            headless.mechanism()
        );
    }
}
