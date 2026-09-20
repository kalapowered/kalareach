//! The container half of the local process bridge, against a real container runtime.
//!
//! Everything here needs a container runtime on the machine. Where there is none the suite says so
//! by name and stops: a machine without one has not disproved anything, and reporting these as
//! passed would be a claim nothing made.
//!
//! What they establish is the part of section 3 that only a real runtime can show: an enrolled
//! container is reached by the identifier the runtime issued, a human name that is reused is not
//! that identity, and the argument vector arrives inside the container exactly as it was built.

#![cfg(unix)]

mod net_support;

use std::process::{Command, Stdio};

use kr_controller::bridge::launch;
use kr_controller::bridge::platform::{PlatformObserver, container_runtime_present};
use kr_controller::bridge::store::Observer;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::identity::{
    EnvironmentAccess, EnvironmentEnrolParams, EnvironmentEnrolResult, EnvironmentEnrolment,
    EnvironmentInventoryParams, EnvironmentInventoryResult, EnvironmentPresence,
    EnvironmentRefreshParams, EnvironmentRefreshResult,
};
use kr_protocol::ids::{ActionId, EnvironmentId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

/// A small image with a shell, which every one of these starts a sleeping process in.
const IMAGE: &str = "docker.io/library/alpine:3.20";

/// Returns false and says why when this machine has no container runtime.
fn runtime_available(suite: &str) -> bool {
    if container_runtime_present() {
        return true;
    }
    eprintln!(
        "{suite}: skipped, because {} is not installed on this machine",
        launch::CONTAINER_RUNTIME
    );
    false
}

fn podman(arguments: &[&str]) -> (bool, String) {
    let output = Command::new(launch::CONTAINER_RUNTIME)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .expect("the container runtime runs");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), text)
}

/// A container this test made, removed when the test ends however it ends.
struct Container {
    name: String,
    id: String,
}

impl Container {
    /// Starts a container that does nothing but stay alive.
    fn start(name: &str) -> Self {
        let (started, text) = podman(&[
            "run", "--detach", "--name", name, "--", IMAGE, "sleep", "600",
        ]);
        assert!(started, "the container starts: {text}");
        let id = text.trim().lines().last().unwrap_or_default().to_owned();
        assert!(!id.is_empty(), "the runtime names the container it made");
        Self {
            name: name.to_owned(),
            id,
        }
    }

    fn enrolment(&self, byte: u8, helper: &str) -> EnvironmentEnrolment {
        EnvironmentEnrolment {
            environment_id: EnvironmentId::new(Uuid::from_bytes([byte; 16])),
            access: EnvironmentAccess::Container,
            // The label is the human name. The identity is the identifier the runtime issued.
            label: self.name.clone(),
            target: self.id.clone(),
            os_user: "root".to_owned(),
            helper_path: helper.to_owned(),
            clipboard_destination: Nullable::null(),
            approved_at_ms: TimestampMs::new(0),
        }
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // Only what this test made, and by the identifier it recorded rather than by a name
        // somebody else might now hold.
        let _ = podman(&["rm", "--force", "--", &self.id]);
    }
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", &kr_ipc::new_uuid().to_string()[..8])
}

#[test]
fn a_running_container_is_observed_as_running_and_a_stopped_one_as_stopped() {
    if !runtime_available("a_running_container_is_observed") {
        return;
    }
    let container = Container::start(&unique("kr-t025-state"));
    let enrolment = container.enrolment(1, "/bin/echo");
    let observer = PlatformObserver;
    assert_eq!(
        observer.observe(&enrolment).expect("an observation"),
        EnvironmentPresence::Running
    );

    let (stopped, text) = podman(&["stop", "--time", "1", "--", &container.id]);
    assert!(stopped, "the container stops: {text}");
    assert_eq!(
        observer.observe(&enrolment).expect("an observation"),
        EnvironmentPresence::EnvironmentStopped
    );

    // And a refresh that was told to may start it again. This is the one path section 3 allows to.
    observer.start(&enrolment).expect("the container starts");
    assert_eq!(
        observer.observe(&enrolment).expect("an observation"),
        EnvironmentPresence::Running
    );
}

#[test]
fn a_reused_container_name_is_not_the_identity_that_was_enrolled() {
    if !runtime_available("a_reused_container_name") {
        return;
    }
    let name = unique("kr-t025-name");
    let first = Container::start(&name);
    let enrolled = first.enrolment(2, "/bin/echo");
    let observer = PlatformObserver;
    assert_eq!(
        observer.observe(&enrolled).expect("an observation"),
        EnvironmentPresence::Running
    );

    // The container is destroyed and another is created under the same human name.
    let (removed, text) = podman(&["rm", "--force", "--", &first.id]);
    assert!(removed, "the container is removed: {text}");
    let second = Container::start(&name);
    assert_ne!(second.id, first.id, "a new container has a new identity");

    // The enrolment still names the identifier it recorded, and that identifier is gone. This host
    // has therefore observed nothing about it, which is stale rather than running.
    assert_eq!(
        observer.observe(&enrolled).expect("an observation"),
        EnvironmentPresence::Stale
    );
    // The new container answers under its own identity, and only under it.
    assert_eq!(
        observer
            .observe(&second.enrolment(3, "/bin/echo"))
            .expect("an observation"),
        EnvironmentPresence::Running
    );
}

#[test]
fn the_argument_vector_reaches_the_container_exactly_as_it_was_built() {
    if !runtime_available("the_argument_vector_reaches_the_container") {
        return;
    }
    let container = Container::start(&unique("kr-t025-exec"));
    // `/bin/echo` stands in for the helper: it prints the arguments it was given, which is what
    // says whether `bridge` and `--stdio` arrived as two separate values or as one string somebody
    // parsed again.
    let command = launch::command(&container.enrolment(4, "/bin/echo")).expect("an exec command");
    assert_eq!(command.program, launch::CONTAINER_RUNTIME);
    let arguments: Vec<&str> = command.arguments.iter().map(String::as_str).collect();
    let (ran, text) = podman(&arguments);
    assert!(ran, "the helper runs inside the container: {text}");
    assert_eq!(text.trim_end(), "bridge --stdio");
}

#[test]
fn a_helper_path_with_a_space_in_it_is_one_argument_inside_the_container() {
    if !runtime_available("a_helper_path_with_a_space") {
        return;
    }
    let container = Container::start(&unique("kr-t025-space"));
    // A small script at a path a command line would split in two. If any layer between here
    // and the container parsed the vector again, this would be "no such file" twice over.
    let (created, text) = podman(&[
        "exec",
        "--",
        &container.id,
        "/bin/sh",
        "-c",
        "printf '#!/bin/sh\\necho \"$@\"\\n' > '/tmp/an echo' && chmod +x '/tmp/an echo'",
    ]);
    assert!(
        created,
        "the helper is placed at a path with a space: {text}"
    );

    let command =
        launch::command(&container.enrolment(5, "/tmp/an echo")).expect("an exec command");
    let arguments: Vec<&str> = command.arguments.iter().map(String::as_str).collect();
    let (ran, output) = podman(&arguments);
    assert!(ran, "the helper at that path runs: {output}");
    assert_eq!(output.trim_end(), "bridge --stdio");
}

#[tokio::test]
async fn a_refresh_that_reached_a_running_environment_without_a_helper_scopes_no_channel() {
    // The one path through the daemon that reaches a bridge and is refused by it. A distribution
    // cannot do this on a machine that has no `wsl.exe`, and a running container can: the
    // environment is observed running, so the refresh opens a bridge, and what is at the helper
    // path is `/bin/echo`, which answers with something that is not an opening frame.
    //
    // What that has to leave behind is one thing said in one place: the readiness in the answer is
    // the record's own, so it cannot report a channel while saying none is scoped.
    if !runtime_available("a_refresh_that_reached_a_running_environment") {
        return;
    }
    let container = Container::start(&unique("kr-t025-refresh"));
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let mut client = host.client().await;
    let record = container.enrolment(6, "/bin/echo");
    let enrolled: EnvironmentEnrolResult = client
        .mutate(
            Method::EnvironmentEnrol,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &EnvironmentEnrolParams {
                enrolment: record.clone(),
            },
        )
        .await
        .expect("the daemon answers")
        .expect("the owner may enrol an environment")
        .to_typed()
        .expect("an enrolment result");
    assert!(!enrolled.row.readiness.channel_scoped);

    let refreshed: EnvironmentRefreshResult = client
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
        .expect("the daemon answers")
        .expect("a running container is refreshed rather than refused")
        .to_typed()
        .expect("a refresh result");
    assert_eq!(
        refreshed.row.status,
        EnvironmentPresence::Running,
        "the container this test started is running"
    );
    assert!(
        refreshed.verification.as_ref().is_none(),
        "what is not a helper verifies nothing: {}",
        refreshed.connection
    );
    assert!(!refreshed.row.readiness.channel_scoped);
    assert!(
        refreshed
            .row
            .readiness
            .detail
            .contains("forwarding a socket"),
        "the detail says what is still needed rather than what an earlier bridge found: {}",
        refreshed.row.readiness.detail
    );

    let inventory: EnvironmentInventoryResult = client
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
        .expect("an inventory");
    for row in inventory.rows {
        assert!(
            !row.readiness.channel_scoped,
            "a channel is scoped by a bridge that answered, not by one that was refused"
        );
        assert!(
            !row.readiness.detail.contains("both recorded"),
            "{}",
            row.readiness.detail
        );
    }
    host.stop().await;
}
