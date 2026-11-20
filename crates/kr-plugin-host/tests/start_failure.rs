//! A real plugin host process that cannot start tells the launcher that started it why.
//!
//! The host here is the program itself, run as a plain child by cargo's own path with an empty
//! home and the plain path, and the launcher is this test's `HostReservation` in the role the
//! control daemon has. The case takes the child's own process identity as the one the service
//! manager reported, which is what the launcher compares the connecting process with. No job is
//! registered and no service manager is called.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::framed::split;
use kr_ipc::paths::{Endpoint, EnvironmentPaths, HostPaths, MAX_SOCKET_PATH_LEN};
use kr_ipc::testing::{PrivateTempDir, TempHost};
use kr_plugin_service::launcher::{HostReservation, LaunchError, host_endpoint};
use kr_plugin_service::protocol::{HostProtocol, MAX_FAILURE_REASON_BYTES};
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::EnvironmentId;
use kr_protocol::scalars::Uuid;

/// A host process, ended when the case ends, however it ends.
struct Running {
    child: Child,
    /// Where its home is, kept until the process is gone.
    _home: PrivateTempDir,
}

impl Running {
    fn start(arguments: &[String]) -> Self {
        let home = PrivateTempDir::create();
        let child = Command::new(env!("CARGO_BIN_EXE_kr-plugin-host"))
            .args(arguments)
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the plugin host starts");
        Self { child, _home: home }
    }

    fn identity(&self) -> kr_protocol::identity::ProcessStartIdentity {
        kr_ipc::identity::process_start_identity(self.child.id()).expect("the host's identity")
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _killed = self.child.kill();
        let _collected = self.child.wait();
    }
}

/// One environment on a private tree, and the packages folder a host is told about.
struct Setup {
    tree: TempHost,
    environment: EnvironmentPaths,
}

impl Setup {
    fn new() -> Self {
        let tree = TempHost::create();
        let environment = tree.environment();
        environment.create().expect("the environment's folders");
        Self { tree, environment }
    }

    /// Where the host binds the endpoint workers use.
    fn endpoint(&self) -> Endpoint {
        host_endpoint(&self.environment, &HostProtocol::THIS).expect("the host's endpoint")
    }

    fn path(&self) -> PathBuf {
        self.endpoint().as_path().to_path_buf()
    }

    fn arguments(&self, reservation: &HostReservation) -> Vec<String> {
        let packages = self.environment.state_dir().join("packages");
        std::fs::create_dir_all(&packages).expect("a packages folder");
        reservation.arguments(&self.environment, &packages)
    }

    /// What the launcher hears from a host started with `arguments`, `delay` after the host was
    /// started and before the launcher accepts.
    async fn heard_after(
        &self,
        reservation: HostReservation,
        arguments: &[String],
        delay: Duration,
    ) -> LaunchError {
        let host = Running::start(arguments);
        tokio::time::sleep(delay).await;
        reservation
            .accept(&self.environment, &host.identity(), Duration::from_secs(20))
            .await
            .expect_err("a host that cannot start does not report in")
    }

    async fn failure_of(&self, delay: Duration) -> String {
        let reservation =
            HostReservation::open(&self.environment, HostProtocol::THIS).expect("a reservation");
        let arguments = self.arguments(&reservation);
        match self.heard_after(reservation, &arguments, delay).await {
            LaunchError::HostFailed { reason } => reason,
            other => panic!("the host's reason, not {other:?}"),
        }
    }
}

/// The arguments with `value` in place of the one after `flag`.
fn with_argument(arguments: &[String], flag: &str, value: &str) -> Vec<String> {
    let mut changed = arguments.to_vec();
    let at = changed
        .iter()
        .position(|argument| argument == flag)
        .expect("the flag is among the arguments");
    changed[at + 1] = value.to_owned();
    changed
}

/// A file at the host's endpoint is named, and the launcher is told so.
#[tokio::test]
async fn a_host_whose_endpoint_has_a_file_on_it_tells_the_launcher_why() {
    let setup = Setup::new();
    let path = setup.path();
    std::fs::write(&path, b"mine").expect("a file at the endpoint");
    let reason = setup.failure_of(Duration::ZERO).await;
    assert!(
        reason.starts_with("the plugin host could not listen on ")
            && reason.contains(&path.display().to_string())
            && reason.contains("a file")
            && reason.contains("kr does not remove what it did not make"),
        "{reason}"
    );
    assert_eq!(std::fs::read(&path).expect("the file"), b"mine");
}

/// A live listener at the host's endpoint is named by the process that holds it, and the words do
/// not tell the person to remove anything.
#[tokio::test]
async fn a_host_whose_endpoint_is_held_by_a_live_listener_tells_the_launcher_why() {
    let setup = Setup::new();
    let _held = Listener::bind(&setup.endpoint()).expect("a live listener of this process");
    let reason = setup.failure_of(Duration::ZERO).await;
    assert!(
        reason.contains(&format!("process {} started", std::process::id())),
        "{reason}"
    );
    assert!(!reason.contains("remove"), "{reason}");
}

/// The host that fails first is still heard by a launcher that accepts a second and a half late,
/// because it waits for the launcher to close before it ends.
#[tokio::test]
async fn a_failure_is_heard_when_the_launcher_accepts_a_second_late() {
    let setup = Setup::new();
    std::fs::write(setup.path(), b"mine").expect("a file at the endpoint");
    let reason = setup.failure_of(Duration::from_millis(1500)).await;
    assert!(reason.contains("could not listen on"), "{reason}");
}

/// A step before the endpoint exists says the host could not start, and never says "listen".
#[tokio::test]
async fn a_step_before_the_endpoint_exists_says_it_could_not_start() {
    let setup = Setup::new();
    let reservation =
        HostReservation::open(&setup.environment, HostProtocol::THIS).expect("a reservation");
    let blocker = setup.tree.root().join("blocker");
    std::fs::write(&blocker, b"a file where a folder is wanted").expect("a file");
    let arguments = with_argument(
        &setup.arguments(&reservation),
        "--runtime-dir",
        &blocker.join("run").display().to_string(),
    );
    match setup
        .heard_after(reservation, &arguments, Duration::ZERO)
        .await
    {
        LaunchError::HostFailed { reason } => assert!(
            reason.starts_with("the plugin host could not start: ") && !reason.contains("listen"),
            "{reason}"
        ),
        other => panic!("the host's reason, not {other:?}"),
    }
}

/// A host whose launcher's rendezvous path is as long as a socket path can be still sends its
/// whole reason, within the bound.
#[tokio::test]
async fn a_reason_from_the_longest_rendezvous_path_arrives_whole_and_within_its_bound() {
    let root = PrivateTempDir::create();
    let state = PrivateTempDir::create();
    let environment_id = EnvironmentId::new(Uuid::from_bytes([7; 16]));
    let paths_at = |runtime: &Path| {
        let paths = HostPaths::new(runtime, state.path()).expect("paths");
        let environment = paths.environment(environment_id);
        environment.create().expect("the environment's folders");
        environment
    };
    // The rendezvous endpoint's length with no padding, then the padding that makes it exactly the
    // longest a socket path may be.
    let unpadded = {
        let environment = paths_at(root.path());
        let reservation =
            HostReservation::open(&environment, HostProtocol::THIS).expect("a reservation");
        reservation.endpoint().as_path().as_os_str().len()
    };
    let padding = MAX_SOCKET_PATH_LEN - unpadded;
    assert!(padding >= 2, "the temporary folder is already too long");
    let padded = root.path().join("p".repeat(padding - 1));
    kr_ipc::paths::create_dir_all_owner_only(&padded).expect("the padded folder");
    let environment = paths_at(&padded);
    let reservation =
        HostReservation::open(&environment, HostProtocol::THIS).expect("a reservation");
    assert_eq!(
        reservation.endpoint().as_path().as_os_str().len(),
        MAX_SOCKET_PATH_LEN
    );
    let endpoint = host_endpoint(&environment, &HostProtocol::THIS).expect("the host's endpoint");
    std::fs::write(endpoint.as_path(), b"mine").expect("a file at the endpoint");
    let packages = state.path().join("packages");
    std::fs::create_dir_all(&packages).expect("a packages folder");
    let arguments = reservation.arguments(&environment, &packages);
    let host = Running::start(&arguments);
    let heard = reservation
        .accept(&environment, &host.identity(), Duration::from_secs(20))
        .await
        .expect_err("a host that cannot start does not report in");
    let LaunchError::HostFailed { reason } = heard else {
        panic!("the host's reason, not {heard:?}");
    };
    assert!(reason.len() <= MAX_FAILURE_REASON_BYTES, "{reason}");
    assert!(
        reason.ends_with("if you do not need it, move it away"),
        "{reason}"
    );
}

/// The host holds its endpoint from the bind until the daemon accepts: a daemon that has read the
/// claim and not answered leaves the endpoint taken.
#[tokio::test]
async fn the_endpoint_stays_held_from_the_bind_until_the_daemon_accepts() {
    let setup = Setup::new();
    let rendezvous_path = setup.environment.runtime_dir().join("raw.sock");
    let rendezvous = Endpoint::from_path(&rendezvous_path).expect("a rendezvous endpoint");
    let daemon = Listener::bind(&rendezvous).expect("a raw listener");
    let reservation =
        HostReservation::open(&setup.environment, HostProtocol::THIS).expect("a reservation");
    let arguments = with_argument(
        &setup.arguments(&reservation),
        "--rendezvous",
        &rendezvous.as_text(),
    );
    let _host = Running::start(&arguments);
    let (connection, _peer) = tokio::time::timeout(Duration::from_secs(20), daemon.accept())
        .await
        .expect("the host connects")
        .expect("an accepted connection");
    let (mut reader, _writer) = split(connection, StreamKind::Control);
    // The claim is read and no answer is given.
    reader.read_payload().await.expect("the host's claim");
    assert!(
        Listener::bind(&setup.endpoint()).is_err(),
        "a second bind of the host's endpoint is refused while the host holds it"
    );
}

/// A host whose launcher takes its failure and never closes the connection ends by itself.
#[tokio::test]
async fn a_host_waits_for_the_launcher_to_close_and_then_ends_by_itself() {
    let setup = Setup::new();
    std::fs::write(setup.path(), b"mine").expect("a file at the endpoint");
    let rendezvous_path = setup.environment.runtime_dir().join("raw.sock");
    let rendezvous = Endpoint::from_path(&rendezvous_path).expect("a rendezvous endpoint");
    let daemon = Listener::bind(&rendezvous).expect("a raw listener");
    let reservation =
        HostReservation::open(&setup.environment, HostProtocol::THIS).expect("a reservation");
    let arguments = with_argument(
        &setup.arguments(&reservation),
        "--rendezvous",
        &rendezvous.as_text(),
    );
    let mut host = Running::start(&arguments);
    // The connection is accepted and held open: nothing is read from it and nothing is closed.
    let _held = tokio::time::timeout(Duration::from_secs(20), daemon.accept())
        .await
        .expect("the host connects")
        .expect("an accepted connection");
    let ended = tokio::task::spawn_blocking(move || {
        let until = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = host.child.try_wait().expect("the host's state") {
                return Some(status);
            }
            if std::time::Instant::now() > until {
                return None;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    })
    .await
    .expect("the wait");
    let status = ended.expect("the host ends by itself");
    assert!(!status.success(), "{status}");
}

/// The connection the host holds to the launcher is the one it connects first: a host with nowhere
/// to report in has bound nothing.
#[tokio::test]
async fn a_host_that_cannot_connect_binds_nothing() {
    let setup = Setup::new();
    let reservation =
        HostReservation::open(&setup.environment, HostProtocol::THIS).expect("a reservation");
    let arguments = with_argument(
        &setup.arguments(&reservation),
        "--rendezvous",
        &setup
            .environment
            .runtime_dir()
            .join("absent.sock")
            .display()
            .to_string(),
    );
    let mut host = Running::start(&arguments);
    let status = tokio::task::spawn_blocking(move || host.child.wait().expect("the host ends"))
        .await
        .expect("the wait");
    assert!(!status.success(), "{status}");
    assert!(!setup.path().exists(), "the host bound its endpoint");
}
