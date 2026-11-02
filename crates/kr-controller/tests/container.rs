//! The container half of the local process bridge, against a real container runtime.
//!
//! Everything here but the reading of what a start prints needs a container runtime on the machine.
//! Where there is none the suite says so by name and stops: a machine without one has not disproved
//! anything, and reporting these as passed would be a claim nothing made.
//!
//! What they establish is the part of section 3 that only a real runtime can show: an enrolled
//! container is reached by the identifier the runtime issued, a human name that is reused is not
//! that identity, and the argument vector arrives inside the container exactly as it was built.

#![cfg(unix)]

mod net_support;

use std::io::Write as _;
use std::process::Output;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use kr_controller::bridge::launch;
use kr_controller::bridge::platform::{CallFailure, PLATFORM_LIMIT, PlatformObserver, run_bounded};
use kr_controller::bridge::store::Observer;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::identity::{
    CONTAINER_IDENTIFIER_LEN, EnvironmentAccess, EnvironmentEnrolParams, EnvironmentEnrolResult,
    EnvironmentEnrolment, EnvironmentInventoryParams, EnvironmentInventoryResult,
    EnvironmentPresence, EnvironmentRefreshParams, EnvironmentRefreshResult,
};
use kr_protocol::ids::{ActionId, EnvironmentId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

/// A small image with a shell, which every one of these starts a sleeping process in.
const IMAGE: &str = "docker.io/library/alpine:3.20";

/// The container runtime a case drives, and how long it gives each call and the removal of what it
/// made. A call that never answers fails the case that made it, with the call named.
#[derive(Clone)]
struct Runtime {
    program: String,
    /// How long one ordinary call is given.
    quick: Duration,
    /// How long a removal that gives no answer is asked again.
    removal: Duration,
}

impl Runtime {
    /// The runtime of this machine.
    fn podman() -> Self {
        Self {
            program: launch::CONTAINER_RUNTIME.to_owned(),
            quick: PLATFORM_LIMIT,
            removal: REMOVAL_WITHIN,
        }
    }

    /// Runs the runtime once, with nothing on its standard input, within `bound`.
    fn run(&self, arguments: &[&str], bound: Duration) -> Result<Output, CallFailure> {
        let arguments: Vec<String> = arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect();
        run_bounded(&self.program, &arguments, bound)
    }

    /// [`Runtime::run`], saying what went wrong with the call named.
    fn within(&self, arguments: &[&str], bound: Duration) -> Result<Output, String> {
        self.run(arguments, bound)
            .map_err(|failure| failure.to_string())
    }

    /// Why a case that needs this runtime cannot run on this machine, or nothing where it can.
    /// Only a program that is not there is a reason: one that is there and fails its `--version`
    /// is a broken install, and one that does not answer it is a stall. Both fail the case, with
    /// the call named, where a skip would pass every case that needs the runtime.
    fn why_unavailable(&self) -> Option<String> {
        match self.run(&["--version"], self.quick) {
            Ok(output) if output.status.success() => None,
            Ok(output) => panic!(
                "{} is installed and `--version` ended with {}",
                self.program, output.status
            ),
            Err(CallFailure::NotRun { error, .. })
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                Some(format!("{} is not installed on this machine", self.program))
            }
            Err(failure) => panic!("{failure}"),
        }
    }
}

/// Returns false and says why when this machine has no container runtime.
fn runtime_available(suite: &str) -> bool {
    available_through(&Runtime::podman(), suite)
}

/// [`runtime_available`], for `runtime`. A machine without one has not disproved anything, and
/// reporting these as passed would be a claim nothing made.
fn available_through(runtime: &Runtime, suite: &str) -> bool {
    match runtime.why_unavailable() {
        None => true,
        Some(why) => {
            eprintln!("{suite}: skipped, because {why}");
            false
        }
    }
}

/// How long a call that fetches an image is given. Any other call is given [`PLATFORM_LIMIT`].
const PULL_BOUND: Duration = Duration::from_secs(300);

/// Runs the container runtime once, with nothing on its standard input, within `bound`, or says
/// what went wrong with the call named.
fn runtime_within(arguments: &[&str], bound: Duration) -> Result<Output, String> {
    Runtime::podman().within(arguments, bound)
}

/// Runs the container runtime once, and fails the case if the call does not end.
fn runtime(arguments: &[&str]) -> Output {
    runtime_within(arguments, PLATFORM_LIMIT).unwrap_or_else(|why| panic!("{why}"))
}

/// Both of the runtime's streams, standard output first, for a message about what it did.
fn printed(output: &Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

fn podman(arguments: &[&str]) -> (bool, String) {
    let output = runtime(arguments);
    (output.status.success(), printed(&output))
}

/// Puts the image in the runtime's store, once per run of this suite, before any container starts.
///
/// A start that has to pull the image first prints the pull's progress while it works. The pull is
/// therefore a step of its own, and every start after it is told never to pull, so no start is ever
/// also a pull.
fn image_present() {
    static PRESENT: OnceLock<()> = OnceLock::new();
    PRESENT.get_or_init(|| {
        if podman(&["image", "exists", "--", IMAGE]).0 {
            return;
        }
        let pulled = runtime_within(&["pull", "--quiet", "--", IMAGE], PULL_BOUND)
            .unwrap_or_else(|why| panic!("{why}"));
        assert!(
            pulled.status.success(),
            "the runtime pulls {IMAGE}: {}",
            printed(&pulled)
        );
    });
}

/// The identifier a detached start printed for the container it made.
///
/// Only standard output is read: the runtime writes its progress and its warnings to standard error,
/// and neither is an identifier. The last line there that is not empty is the answer, and it is
/// refused unless it is what the runtime issues, the whole identifier in lowercase hexadecimal.
fn container_identifier(stdout: &[u8]) -> Result<String, String> {
    let text = String::from_utf8_lossy(stdout);
    let last = text
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .unwrap_or_default();
    let whole = last.len() == CONTAINER_IDENTIFIER_LEN
        && last
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if whole {
        Ok(last.to_owned())
    } else {
        Err(format!(
            "the runtime's standard output does not end in the identifier of the container it \
             made: {text:?}"
        ))
    }
}

/// How long a removal that does not end is asked again: far longer than a call that answers takes,
/// and short of a runtime that has stopped answering.
const REMOVAL_WITHIN: Duration = Duration::from_secs(300);

/// A container this test made, removed when the test ends by any way that runs destructors. A test
/// binary that is killed runs none, and leaves the container.
struct Container {
    runtime: Runtime,
    name: String,
    /// The identifier the runtime issued, empty until it has issued one.
    id: String,
}

impl Container {
    /// Starts a container that does nothing but stay alive.
    fn start(name: &str) -> Self {
        image_present();
        // The guard exists before the call that can make the container: a call that makes it and
        // then stalls, or prints no identifier, still leaves a guard that removes it by the name
        // given here.
        let mut container = Self {
            runtime: Runtime::podman(),
            name: name.to_owned(),
            id: String::new(),
        };
        let output = runtime(&[
            "run",
            "--detach",
            "--pull=never",
            "--name",
            name,
            "--",
            IMAGE,
            "sleep",
            "600",
        ]);
        assert!(
            output.status.success(),
            "the container starts: {}",
            printed(&output)
        );
        container.id =
            container_identifier(&output.stdout).unwrap_or_else(|refusal| panic!("{refusal}"));
        container
    }

    /// What names the container to the runtime: the identifier it issued, and until it has issued
    /// one, the name this test gave it.
    fn target(&self) -> &str {
        if self.id.is_empty() {
            &self.name
        } else {
            &self.id
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

    /// Removes the container, or says why it could not. A removal can be asked again and a loaded
    /// machine's runtime can take longer than one call is given, so a call that gave no answer is
    /// asked again until [`REMOVAL_WITHIN`] has passed, each call given no more than what is left;
    /// a refusal is not asked again. The first call is always made and is given the whole time for
    /// removals, whatever has gone by since that time was set.
    fn remove(&self) -> Result<(), String> {
        self.remove_telling(&mut std::io::stderr())
    }

    /// [`Container::remove`], writing the line for a call that gave no answer to `told`.
    fn remove_telling(&self, told: &mut dyn std::io::Write) -> Result<(), String> {
        let until = Instant::now() + self.runtime.removal;
        let mut last: String;
        let mut left = self.runtime.removal;
        loop {
            match self.runtime.within(
                &[
                    "rm",
                    "--force",
                    "--ignore",
                    "--time",
                    "0",
                    "--",
                    self.target(),
                ],
                self.runtime.quick.min(left),
            ) {
                Ok(output) if output.status.success() => return Ok(()),
                Ok(output) => return Err(printed(&output)),
                Err(why) => {
                    // A call that stalls and is answered the next time leaves no other trace, and
                    // a stall of the runtime is what this evidence is for.
                    let _ = writeln!(
                        told,
                        "the removal of the container {} did not answer ({why}); asking again",
                        self.name
                    );
                    last = why;
                }
            }
            std::thread::sleep(Duration::from_millis(200));
            left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(last);
            }
        }
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // A container the case itself removed is not one to complain of. A removal that fails is
        // recorded, and fails a case that passed; a case that is already failing has said so, and
        // a second panic would end the whole test binary.
        let Err(why) = self.remove() else {
            return;
        };
        let record = format!(
            "the container {} ({}) was not removed and may still be running: {why}",
            self.name,
            self.target()
        );
        let _ = writeln!(std::io::stderr(), "{record}");
        if !std::thread::panicking() {
            panic!("{record}");
        }
    }
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", &kr_ipc::new_uuid().to_string()[..8])
}

#[test]
fn a_started_container_is_named_only_by_a_whole_identifier_on_standard_output() {
    // Needs no runtime: this is the reading every start above relies on.
    let issued = "0123456789abcdef".repeat(4);
    assert_eq!(
        container_identifier(format!("{issued}\n").as_bytes()),
        Ok(issued.clone())
    );
    assert_eq!(
        container_identifier(format!("a notice\n{issued}\n\n").as_bytes()),
        Ok(issued.clone()),
        "the last line that is not empty is the identifier"
    );
    // What a pull prints is not an identifier, and neither is a prefix of one or one in capitals.
    for answer in [
        "Writing manifest to image destination\n".to_owned(),
        format!("{issued}\nWriting manifest to image destination\n"),
        issued[..12].to_owned(),
        issued.to_uppercase(),
        String::new(),
    ] {
        let refusal = container_identifier(answer.as_bytes()).expect_err("refused");
        assert!(
            refusal.contains(&format!("{answer:?}")),
            "the refusal quotes what the runtime printed: {refusal}"
        );
    }
}

#[test]
fn a_running_container_is_observed_as_running_and_a_stopped_one_as_stopped() {
    if !runtime_available("a_running_container_is_observed") {
        return;
    }
    let container = Container::start(&unique("kr-bridge-state"));
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
    let name = unique("kr-bridge-name");
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
    let container = Container::start(&unique("kr-bridge-exec"));
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
    let container = Container::start(&unique("kr-bridge-space"));
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
    let container = Container::start(&unique("kr-bridge-refresh"));
    // A busy machine makes the runtime slow to answer the daemon, which says nothing about what the
    // refresh leaves behind. The daemon waits for the runtime as long as the runtime needs and ends
    // it only if it has hung.
    let _platform_commands =
        kr_controller::testing::hold_platform_commands_to(std::time::Duration::from_secs(600));
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

/// A runtime of this test's own: a program in `directory` that records each call's arguments, one
/// line to a call, in `calls`, and then runs `body`, answering with success where `body` says
/// nothing. A call is given ten seconds, which a call that answers does not come near, and a stalled
/// one lasts forty; a removal that gives no answer is asked again for a minute.
fn a_runtime_that(directory: &std::path::Path, body: &str) -> Runtime {
    let text = directory.join("runtime.text");
    std::fs::write(
        &text,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >>'{calls}'\n{body}\nexit 0\n",
            calls = directory.join("calls").display()
        ),
    )
    .expect("the stand-in runtime");
    let program = directory.join("podman");
    kr_ipc::testing::place_program(&text, &program);
    Runtime {
        program: program.display().to_string(),
        quick: Duration::from_secs(10),
        removal: Duration::from_secs(60),
    }
}

/// The calls a stand-in runtime was given, one line of arguments each.
fn recorded_calls(directory: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(directory.join("calls"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The removals among them.
fn removals(directory: &std::path::Path) -> Vec<String> {
    recorded_calls(directory)
        .into_iter()
        .filter(|call| call.starts_with("rm "))
        .collect()
}

/// The identifier the stand-in runtime issued for the container the cases below hold.
const STAND_IN_ID: &str = "3f1a9c0d5e7b2468a1c3e5f7092b4d6e8a0c2e4f61738495a6b7c8d9e0f1a2b3";

/// A container held by the identifier a stand-in runtime issued.
fn held_in(runtime: Runtime) -> Container {
    Container {
        runtime,
        name: "kr-stand-in".to_owned(),
        id: STAND_IN_ID.to_owned(),
    }
}

/// What a panic said.
fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_default()
}

/// A removal that never answers is, when the time for removals has passed, an error that names the
/// call and does not panic; each call is given no more than what is left of that time (the first,
/// the whole of it, whatever has gone by since it was set), and each that gave no answer leaves a
/// line for whoever reads the run.
#[test]
fn a_removal_that_never_answers_is_reported_with_the_call_named() {
    let directory = tempfile::tempdir().expect("a directory");
    // A call is given far more than the time for removals, so that a call given more than that time
    // shows in the bound it is told it had.
    let container = held_in(Runtime {
        quick: Duration::from_secs(30),
        removal: Duration::from_secs(3),
        ..a_runtime_that(directory.path(), "case \"$1\" in rm) exec sleep 40 ;; esac")
    });
    let mut told = Vec::new();
    let why = container
        .remove_telling(&mut told)
        .expect_err("a removal that never ends is an error and not a panic");
    assert!(
        why.contains(" rm did not end within"),
        "the call is named: {why}"
    );
    // The first call was given the whole time for removals, which is less than a whole call.
    assert!(
        why.contains("within 3 seconds"),
        "the call was given the time for removals and no more: {why}"
    );
    let told = String::from_utf8_lossy(&told);
    assert!(
        told.contains("did not answer") && told.contains("asking again"),
        "{told}"
    );
    // The runtime answers no removal, and the guard would ask again for as long as it is given and
    // fail this case for what it was written to show.
    std::mem::forget(container);
}

/// A call after the first is given no more than what is left of the time for removals. A call is
/// given two seconds here and the time for removals is three, so a second call, begun with less than
/// a second left, cannot be told it has two. A machine that stood still through the first call
/// leaves no time for a second, and then there is nothing to read.
#[test]
fn a_later_removal_call_is_given_no_more_than_what_is_left_of_the_time_for_removals() {
    let directory = tempfile::tempdir().expect("a directory");
    let container = held_in(Runtime {
        quick: Duration::from_secs(2),
        removal: Duration::from_secs(3),
        ..a_runtime_that(directory.path(), "case \"$1\" in rm) exec sleep 40 ;; esac")
    });
    let why = container
        .remove_telling(&mut std::io::sink())
        .expect_err("a removal that never ends is an error and not a panic");
    assert!(
        why.contains(" rm did not end within"),
        "the call is named: {why}"
    );
    if removals(directory.path()).len() >= 2 {
        assert!(
            !why.contains("within 2 seconds"),
            "the last call was given a whole call's time and not what was left: {why}"
        );
    }
    // The runtime answers no removal, and the guard would ask again and fail this case for what it
    // was written to show.
    std::mem::forget(container);
}

/// A removal that stalls once and is answered the next time succeeds, after a line that says it was
/// asked again.
#[test]
fn a_removal_that_stalls_once_is_asked_again_and_answered() {
    let directory = tempfile::tempdir().expect("a directory");
    let calls = directory.path().join("calls");
    let container = held_in(a_runtime_that(
        directory.path(),
        &format!(
            "case \"$1\" in rm) if [ \"$(grep -c '^rm ' '{}')\" -le 1 ]; then exec sleep 40; fi ;; esac",
            calls.display()
        ),
    ));
    let mut told = Vec::new();
    container
        .remove_telling(&mut told)
        .expect("the second asking is answered");
    assert!(removals(directory.path()).len() >= 2);
    assert!(
        String::from_utf8_lossy(&told).contains("asking again"),
        "{}",
        String::from_utf8_lossy(&told)
    );
}

/// A removal the runtime refuses is not asked again: it would be refused again.
#[test]
fn a_removal_the_runtime_refuses_is_not_asked_again() {
    let directory = tempfile::tempdir().expect("a directory");
    let container = held_in(a_runtime_that(
        directory.path(),
        "case \"$1\" in rm) echo 'Error: the stand-in refuses this call' >&2; exit 125 ;; esac",
    ));
    let why = container
        .remove()
        .expect_err("a refusal is an error and not a panic");
    assert!(why.contains("the stand-in refuses this call"), "{why}");
    // The runtime is told to remove it by force, whether or not it is running, at once, and to
    // say nothing of a container that is not there; and the refusal is asked once.
    assert_eq!(
        removals(directory.path()),
        [format!("rm --force --ignore --time 0 -- {STAND_IN_ID}")]
    );
    // The runtime refuses every removal, and the guard would ask again and fail this case for what
    // it was written to show.
    std::mem::forget(container);
}

/// A case that passes while its container could not be removed fails: the container is still
/// there, running a process, on a machine that other cases and other people share.
#[test]
fn a_case_that_passes_fails_when_its_container_could_not_be_removed() {
    let directory = tempfile::tempdir().expect("a directory");
    let container = held_in(a_runtime_that(
        directory.path(),
        "case \"$1\" in rm) echo 'Error: the stand-in refuses this call' >&2; exit 125 ;; esac",
    ));
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _held = container;
    }));
    let said = panic_message(failed.expect_err("a container left behind fails the case"));
    assert!(
        said.contains("was not removed and may still be running"),
        "{said}"
    );
}

/// Only a runtime that is not there is a reason to leave out the cases that need one. One that is
/// there and fails its `--version` is a broken install, and fails the case that asks.
#[test]
fn only_a_runtime_that_is_not_there_is_a_reason_to_skip() {
    let missing = Runtime {
        program: "/nonexistent-runtime/podman".to_owned(),
        ..Runtime::podman()
    };
    assert!(
        missing
            .why_unavailable()
            .is_some_and(|why| why.contains("is not installed")),
    );
    assert!(!available_through(
        &missing,
        "the_cases_of_a_machine_with_none"
    ));

    let working_directory = tempfile::tempdir().expect("a directory");
    let working = a_runtime_that(
        working_directory.path(),
        "case \"$1\" in --version) echo 'podman version 5.0.0' ;; esac",
    );
    assert!(working.why_unavailable().is_none());

    let broken_directory = tempfile::tempdir().expect("a directory");
    let broken = a_runtime_that(
        broken_directory.path(),
        "case \"$1\" in --version) exit 1 ;; esac",
    );
    let failed =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| broken.why_unavailable()));
    let said = panic_message(failed.expect_err("a runtime that fails its version fails the case"));
    assert!(
        said.contains("is installed and `--version` ended with"),
        "{said}"
    );
}
