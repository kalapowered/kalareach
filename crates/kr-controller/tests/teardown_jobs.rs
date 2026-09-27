//! A test's host tree takes every job registered for it with it.
//!
//! A job its service manager keeps outlives the test that registered it, and once the tree is gone
//! the job names a program nothing can find. Each case here registers a real job through the
//! platform's own supervisor, drops the tree, and asks the service manager what it still has. The
//! job's program is the system's own, and everything it is given is inside the tree, on the
//! internal disk.
//!
//! Every job a case registers is removed again when the case ends, however it ends, so a case that
//! fails leaves nothing registered either.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod teardown;

use std::path::PathBuf;
use std::process::{Command, Stdio};

use kr_controller::supervision::{LaunchOutcome, WorkerSupervisor};
use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::ids::EnvironmentId;

/// A job a case registered, removed from the service manager when the case ends, however it ends.
struct Registered(String);

impl Drop for Registered {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        for domain in ["gui", "user"] {
            let _ = Command::new("/bin/launchctl")
                .arg("bootout")
                .arg(format!(
                    "{domain}/{}/{}",
                    kr_ipc::paths::current_uid(),
                    self.0
                ))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        #[cfg(target_os = "linux")]
        for verb in ["stop", "reset-failed"] {
            let _ = Command::new("systemctl")
                .args(["--user", verb, &format!("{}.service", self.0)])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// Whether this user's launchd still has the job `label` loaded, in either of the user's domains.
#[cfg(target_os = "macos")]
fn registered(label: &str) -> bool {
    let uid = kr_ipc::paths::current_uid();
    ["gui", "user"].into_iter().any(|domain| {
        let target = format!("{domain}/{uid}/{label}");
        let status = Command::new("/bin/launchctl")
            .arg("print")
            .arg(&target)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("launchctl runs");
        // 113 is a job the domain does not have, and 112 a domain that is not there.
        match status.code() {
            Some(0) => true,
            Some(112 | 113) => false,
            _ => panic!("launchctl could not say whether {target} is loaded: {status}"),
        }
    })
}

/// Whether this user's service manager still has the unit of the job `label`.
#[cfg(target_os = "linux")]
fn registered(label: &str) -> bool {
    let unit = format!("{label}.service");
    let output = Command::new("systemctl")
        .args(["--user", "show", "--property=LoadState", "--value", &unit])
        .output()
        .expect("systemctl runs");
    assert!(
        output.status.success(),
        "the user manager could not say whether it has {unit}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim() != "not-found"
}

/// Registers a headless worker's job for `environment`, as a daemon of that environment would, and
/// returns the guard that removes it when the case ends.
///
/// Its definition is written into the environment's jobs directory and it is started in this
/// user's background domain. The program is the system's own and ends at once, which leaves the job
/// loaded with no process in it: what a worker's job is once its worker has ended.
#[cfg(target_os = "macos")]
fn register(environment: &EnvironmentPaths) -> Registered {
    use kr_controller::supervision::{LaunchdSupervisor, WorkerLaunch};
    use kr_protocol::identity::WorkerProfile;
    use kr_protocol::ids::SessionId;
    use kr_protocol::session::DisplayNumber;
    use kr_protocol::worker::ReservationId;

    assert!(
        LaunchdSupervisor::available(),
        "this user has no graphical launchd domain on this host, so no job can be registered and \
         this check cannot run"
    );
    let launch = WorkerLaunch {
        reservation_id: ReservationId::new(kr_ipc::new_uuid()),
        session_id: SessionId::new(kr_ipc::new_uuid()),
        environment_id: environment.environment_id(),
        display_number: DisplayNumber::new(1),
        program: PathBuf::from("/usr/bin/true"),
        rendezvous: environment.state_dir().join("rendezvous"),
        runtime_directory: environment.runtime_dir().to_path_buf(),
        state_directory: environment.state_dir().to_path_buf(),
        jobs_directory: environment.jobs_dir(),
        working_directory: environment.state_dir().to_path_buf(),
        desktop_environment: Vec::new(),
        profile: WorkerProfile::HeadlessUser,
    };
    let job = Registered(launch.label());
    let outcome = LaunchdSupervisor::new().start(&launch);
    assert!(
        !matches!(outcome, LaunchOutcome::NotStarted { .. }),
        "the job was registered: {outcome:?}"
    );
    job
}

/// Registers a service for `environment` as a transient user unit, as a daemon of that environment
/// would, and returns the guard that removes it when the case ends.
///
/// It runs in the environment's state directory. The program is the system's own and keeps running
/// for five minutes, which keeps its unit: a unit whose process has ended is collected by itself.
#[cfg(target_os = "linux")]
fn register(environment: &EnvironmentPaths) -> Registered {
    use kr_controller::supervision::{ServiceLaunch, SystemdSupervisor};

    assert!(
        SystemdSupervisor::available(),
        "this account has no user service manager to ask, so no unit can be registered and this \
         check cannot run here"
    );
    let label = format!("kr-worker-{}", kr_ipc::new_uuid());
    let job = Registered(label.clone());
    let outcome = SystemdSupervisor::new().start_service(&ServiceLaunch {
        label,
        program: PathBuf::from("/bin/sleep"),
        arguments: vec!["300".to_owned()],
        jobs_directory: environment.jobs_dir(),
        working_directory: environment.state_dir().to_path_buf(),
    });
    assert!(
        !matches!(outcome, LaunchOutcome::NotStarted { .. }),
        "the unit was registered: {outcome:?}"
    );
    job
}

/// A job registered for the environment a tree was created with goes when the tree does.
#[test]
#[cfg_attr(
    target_os = "linux",
    ignore = "needs a user service manager for this account (`systemctl --user`), which a hosted CI \
              runner's account does not have; it runs with --ignored on a Linux host whose account \
              has one"
)]
fn a_job_registered_for_a_tree_goes_with_it() {
    let tree = teardown::Tree::create();
    let job = register(&tree.environment());
    assert!(registered(&job.0), "{} was registered", job.0);

    drop(tree);
    assert!(
        !registered(&job.0),
        "{} is still registered after the tree it was registered for has gone",
        job.0
    );
}

/// A job registered for another environment in the same tree goes with the tree as well: a tree
/// holds every environment in it, not only the one it was created with.
#[test]
#[cfg_attr(
    target_os = "linux",
    ignore = "needs a user service manager for this account (`systemctl --user`), which a hosted CI \
              runner's account does not have; it runs with --ignored on a Linux host whose account \
              has one"
)]
fn a_job_registered_for_another_environment_of_a_tree_goes_with_it() {
    let tree = teardown::Tree::create();
    let other = tree
        .paths()
        .environment(EnvironmentId::new(kr_ipc::new_uuid()));
    other.create().expect("a second environment in the tree");
    let job = register(&other);
    assert!(registered(&job.0), "{} was registered", job.0);

    drop(tree);
    assert!(
        !registered(&job.0),
        "{} is still registered after the tree it was registered for has gone",
        job.0
    );
}

/// A job the tree's test did not register is never touched: one registered for another tree stays
/// registered when this one goes.
#[test]
#[cfg_attr(
    target_os = "linux",
    ignore = "needs a user service manager for this account (`systemctl --user`), which a hosted CI \
              runner's account does not have; it runs with --ignored on a Linux host whose account \
              has one"
)]
fn a_job_registered_for_another_tree_is_left_alone() {
    let other = kr_ipc::testing::TempHost::create();
    let job = register(&other.environment());
    assert!(registered(&job.0), "{} was registered", job.0);

    drop(teardown::Tree::create());
    assert!(
        registered(&job.0),
        "{} was taken away by a tree it was not registered for",
        job.0
    );
}
