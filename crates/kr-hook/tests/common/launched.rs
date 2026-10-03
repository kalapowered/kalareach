//! A launch of a stand-in application by the worker's own gateway, with its bridge installed.
//!
//! The application is `/bin/sh` running a loop that stands in for the application the bridge was
//! installed for: for every request path a test writes to its input it runs
//! `kr-hook <application> hook` with that request as the hook's input, as the application runs a
//! hook for an event, and writes the hook's output, diagnostics and exit code beside the request.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kr_protocol::broker::{AuthenticationState, BinaryIdentity, IntegrationMode, LaunchProfile};
use kr_protocol::gateway::NativeFraming;
use kr_protocol::ids::{
    ApplicationInstanceId, EnvironmentId, LaunchProfileId, PluginId, SessionId,
};
use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};
use kr_worker::broker::{
    AdmittedBridge, BridgeSurface, Broker, BrokerError, ForegroundMark, Framing, InstalledBridge,
    NativeGateway, NativeLaunch,
};

use super::{LIVENESS, Placed};

/// The package whose bridge these launches were installed with, unless a test names another.
pub fn plugin() -> PluginId {
    plugin_of("claude-code")
}

/// The connector package for an application.
pub fn plugin_of(application: &str) -> PluginId {
    PluginId::new(format!("kalareach/{application}")).expect("valid")
}

pub fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

/// The installation: Claude Code's two registrations, pointing at `forwarder`.
pub fn installed(forwarder: &Path, surfaces: &[BridgeSurface]) -> InstalledBridge {
    installed_for("claude-code", forwarder, surfaces)
}

/// The installation of an application's registrations, from its connector package, pointing at
/// `forwarder`.
pub fn installed_for(
    application: &str,
    forwarder: &Path,
    surfaces: &[BridgeSurface],
) -> InstalledBridge {
    InstalledBridge {
        plugin_id: plugin_of(application),
        application: application.to_owned(),
        surfaces: surfaces.iter().copied().collect(),
        forwarder: forwarder.to_path_buf(),
    }
}

/// The stand-in application: it reads one request path per line and runs a hook for each,
/// as the application does for each event, with the request as the hook's input and the hook's
/// output, diagnostics and exit code written beside it. `$2` is the application name its
/// registration invokes the forwarder with.
const APPLICATION: &str = r#"
while IFS= read -r request; do
  "$1" "$2" hook < "$request" > "$request.out" 2> "$request.err"
  echo $? > "$request.tmp"
  mv "$request.tmp" "$request.code"
done
"#;

/// The stand-in application for a channel: the channel server runs as its child, on its standard
/// streams, and the application ends with the server's exit code, which it writes to `$3` first.
const CHANNEL_APPLICATION: &str = r#"
"$1" claude-code channel
code=$?
echo "$code" > "$3.tmp"
mv "$3.tmp" "$3"
exit "$code"
"#;

/// What the application runs first: it makes itself the leader of a process group of its own and
/// then runs the stand-in `$4`, with the program, the application's name and the file its exit
/// code goes to as `$1` to `$3`.
///
/// Everything it starts is then in that group, wherever the kernel puts the process afterwards: a
/// process that outlives the application is adopted by another parent and stays in the group. A
/// shell has no way to lead a group of its own without job control, which takes the terminal from
/// whatever holds it, so the one step is Perl's `setpgrp`.
const LEADER: &str = r#"exec /usr/bin/perl -e 'setpgrp(0, 0) or die "setpgrp: $!\n"; exec @ARGV or die "exec: $!\n"' /bin/sh -c "$4" application "$1" "$2" "$3""#;

/// One launch this host made of the stand-in application, with its bridge installed.
pub struct Launch {
    pub broker: Arc<Broker>,
    pub gateway: NativeGateway,
    pub application: Application,
    /// The application's input, until a test closes it.
    pub requests: Option<std::process::ChildStdin>,
    pub runtime: PathBuf,
    pub inbox: PathBuf,
    next: u32,
}

/// The stand-in application one launch started, which that launch alone ends and collects.
///
/// It leads a process group of its own, and it is collected only once the group has been ended:
/// until then its identifier, and with it the group's, can name no other process. So ending the
/// group reaches exactly what the application started, however long ago the application itself
/// ended and whoever ended it.
pub struct Application {
    child: std::process::Child,
    /// The application's output, until a test takes it.
    pub stdout: Option<std::process::ChildStdout>,
    /// The file the channel's stand-in writes the code it ends with to.
    code: PathBuf,
}

impl Application {
    /// The application's process identifier.
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// The code the channel's stand-in ended with, read from what it wrote rather than by
    /// collecting it, once it has ended within the liveness bound.
    pub fn exit_code(&self) -> Option<i32> {
        let deadline = std::time::Instant::now() + LIVENESS;
        loop {
            if let Ok(code) = std::fs::read_to_string(&self.code) {
                return code.trim().parse().ok();
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Ends the application and everything it started, and collects it.
    ///
    /// The application is ended by its identifier, which is still its own because nothing else
    /// collects it, and its end is waited for without collecting it. Its group is then ended:
    /// nothing in the group can start anything more by then, and while the application is not
    /// collected its group's identifier can name no other group. Then the application is
    /// collected.
    ///
    /// Every answer the kernel gives is looked at, and the only refusals taken as done are the
    /// ones this ownership makes certain: a process that had already ended, and a group that does
    /// not exist because the application ended before it made one, so it started nothing. What
    /// macOS answers for a group holding only processes that have ended is taken as done once a
    /// query shows no process of the group still running.
    ///
    /// # Errors
    ///
    /// Returns what went wrong when the application could not be ended, its end could not be
    /// waited for, its group could not be ended or it could not be collected.
    fn end(&mut self) -> Result<(), String> {
        use rustix::io::Errno;
        use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};

        let pid = Pid::from_child(&self.child);
        match self.child.kill() {
            Ok(()) => {}
            // It had ended already and waits to be collected, which the wait below establishes.
            Err(error) if error.raw_os_error() == Some(Errno::SRCH.raw_os_error()) => {}
            // It may still be running, so nothing below would return: say so and leave it.
            Err(error) => return Err(format!("the application could not be ended: {error}")),
        }
        let ended = loop {
            match waitid(
                WaitId::Pid(pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
            ) {
                Err(Errno::INTR) => {}
                ended => break ended,
            }
        };
        let group = match ended {
            Ok(_) => match kill_process_group(pid, Signal::KILL) {
                Ok(()) | Err(Errno::SRCH) => Ok(()),
                #[cfg(target_os = "macos")]
                Err(Errno::PERM) => nothing_running_in_group(pid.as_raw_pid()),
                Err(error) => Err(format!(
                    "the application's group could not be ended: {error}"
                )),
            },
            Err(error) => Err(format!(
                "the application's end could not be waited for: {error}"
            )),
        };
        let collected = self
            .child
            .wait()
            .map(|_| ())
            .map_err(|error| format!("the application could not be collected: {error}"));
        match (group, collected) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(failure), Ok(())) | (Ok(()), Err(failure)) => Err(failure),
            (Err(group), Err(collected)) => Err(format!("{group}, and {collected}")),
        }
    }
}

/// Says whether `ps` shows no process of the group `group` still running, as a check of what a
/// refused group signal means on macOS: there, a group whose processes have all ended refuses the
/// signal. A query that fails is a failure, never an empty group.
#[cfg(target_os = "macos")]
fn nothing_running_in_group(group: i32) -> Result<(), String> {
    let listed = std::process::Command::new("ps")
        .args(["-A", "-o", "pgid=,stat="])
        .output()
        .map_err(|error| format!("ps could not be run: {error}"))?;
    if !listed.status.success() {
        return Err(format!(
            "ps failed ({}): {}",
            listed.status,
            String::from_utf8_lossy(&listed.stderr)
        ));
    }
    let text = String::from_utf8(listed.stdout).map_err(|error| format!("ps printed: {error}"))?;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(member), Some(state)) = (fields.next(), fields.next()) else {
            return Err(format!(
                "ps printed a line with no group and state: {line:?}"
            ));
        };
        let member: i32 = member.parse().map_err(|error| {
            format!("ps printed a group that is not a number, {line:?}: {error}")
        })?;
        if member == group && !state.starts_with('Z') {
            return Err(format!(
                "the signal to group {group} was refused and one of its processes still runs: \
                 {line:?}"
            ));
        }
    }
    Ok(())
}

impl Launch {
    /// Launches the stand-in application, whose hooks run `hook_program` for the application
    /// the installation names, against an installation of `installed`.
    pub fn start(placed: &Placed, hook_program: &Path, installed: InstalledBridge) -> Self {
        let invoked = installed.application.clone();
        Self::start_as(placed, hook_program, &invoked, installed)
    }

    /// Launches the stand-in application, whose hooks run `hook_program <invoked> hook`, against
    /// an installation of `installed`, which may be another application's.
    pub fn start_as(
        placed: &Placed,
        hook_program: &Path,
        invoked: &str,
        installed: InstalledBridge,
    ) -> Self {
        Self::start_running(placed, APPLICATION, hook_program, invoked, installed)
    }

    /// Launches a stand-in application that starts `kr-hook claude-code channel` over its own
    /// standard input and output, as Claude Code starts a channel server, and ends with its code.
    pub fn channel(placed: &Placed, installed: InstalledBridge) -> Self {
        Self::start_running(
            placed,
            CHANNEL_APPLICATION,
            &placed.forwarder,
            "claude-code",
            installed,
        )
    }

    fn start_running(
        placed: &Placed,
        script: &str,
        program: &Path,
        invoked: &str,
        installed: InstalledBridge,
    ) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let runtime = placed.host.root().join("l");
        let inbox = placed.host.root().join("h");
        for directory in [&runtime, &inbox] {
            std::fs::create_dir_all(directory).expect("a directory");
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .expect("made private");
        }
        let code = inbox.join("application.code");
        let broker = Arc::new(
            Broker::open(
                None,
                SessionId::new(Uuid::from_bytes([1; 16])),
                kr_worker::persistence::JournalHealth::shared(),
            )
            .expect("a broker"),
        );
        let mut gateway = NativeGateway::bind(
            Arc::clone(&broker),
            &runtime,
            NativeLaunch {
                profile_id: LaunchProfileId::new("lp-claude").expect("valid"),
                expected_process: None,
                native_terminal: None,
                application_instance_id: instance(),
                plugin_id: installed.plugin_id.clone(),
                installed_protocol_version: "2.1.278".to_owned(),
                framing: Framing::new(NativeFraming::JsonLines),
                site: EnvironmentId::new(Uuid::from_bytes([4; 16])),
                os_user: "agent-user".to_owned(),
                working_directory: runtime.clone(),
            },
        )
        .expect("the endpoint binds")
        .with_bridge(installed)
        .expect("the bridge is this launch's connector's");
        let profile = LaunchProfile {
            profile_id: LaunchProfileId::new("lp-claude").expect("valid"),
            environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
            binary: BinaryIdentity {
                resolved_path: "/bin/sh".to_owned(),
                digest: Digest256::from_bytes([3; 32]),
                version: "2.1.278".to_owned(),
                distribution: "npm".to_owned(),
            },
            arguments: vec![
                "-c".to_owned(),
                LEADER.to_owned(),
                "application".to_owned(),
                program.to_string_lossy().into_owned(),
                invoked.to_owned(),
                code.to_string_lossy().into_owned(),
                script.to_owned(),
            ],
            authentication: AuthenticationState::Authenticated,
            mode: IntegrationMode::NativeBridge,
            resolved_at: TimestampMs::new(1),
        };
        let intent = broker
            .prepare_launch(profile, ForegroundMark::idle(4), None)
            .expect("the launch is prepared");
        let mut launched = gateway
            .launch(
                &intent,
                &ForegroundMark::idle(4),
                IntegrationMode::NativeBridge,
                TimestampMs::new(1),
            )
            .expect("the application is started");
        let requests = launched
            .child
            .stdin
            .take()
            .expect("the application reads requests");
        let stdout = launched.child.stdout.take();
        Self {
            broker,
            gateway,
            application: Application {
                child: launched.child,
                stdout,
                code,
            },
            requests: Some(requests),
            runtime,
            inbox,
            next: 0,
        }
    }

    /// Has the application run one hook with `payload` as its input, and returns the request's
    /// path, beside which the hook's output lands.
    pub fn hook(&mut self, payload: &[u8]) -> PathBuf {
        use std::io::Write as _;
        self.next += 1;
        let request = self.inbox.join(format!("r{}", self.next));
        std::fs::write(&request, payload).expect("the request is written");
        let requests = self
            .requests
            .as_mut()
            .expect("the application's input is open");
        writeln!(requests, "{}", request.display()).expect("the application is asked");
        requests.flush().expect("and it goes");
        request
    }

    /// Accepts one bridge connection, within the liveness bound.
    pub async fn accept(&self) -> Result<AdmittedBridge, BrokerError> {
        tokio::time::timeout(LIVENESS, self.gateway.accept_bridge())
            .await
            .expect("a bridge reached the endpoint")
    }

    /// The owner-only file the launch's private exchange was written to.
    pub fn credential_file(&self) -> PathBuf {
        self.runtime.join("credential")
    }
}

impl Drop for Launch {
    /// Ends the application and everything it started, the channel server it runs or a hook it is
    /// running, before anything else of the launch goes.
    ///
    /// # Panics
    ///
    /// When that cannot be done, unless a panic is already unwinding, which is told what went
    /// wrong instead: a cleanup that did not happen fails the test rather than leaving a process
    /// behind unsaid.
    fn drop(&mut self) {
        if let Err(failure) = self.application.end() {
            if std::thread::panicking() {
                eprintln!("the launch could not end what its application started: {failure}");
            } else {
                panic!("the launch could not end what its application started: {failure}");
            }
        }
    }
}

/// What one hook the application ran produced, once it has ended.
pub struct Outcome {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

/// Waits for the hook run for `request` to end, and reads what it produced.
pub fn outcome(request: &Path) -> Outcome {
    let code_file = request.with_extension("code");
    let deadline = std::time::Instant::now() + LIVENESS;
    let code = loop {
        if let Ok(code) = std::fs::read_to_string(&code_file) {
            break code.trim().parse::<i32>().expect("an exit code");
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the hook for {} did not end",
            request.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    Outcome {
        code,
        stdout: std::fs::read(request.with_extension("out")).expect("its output"),
        stderr: std::fs::read_to_string(request.with_extension("err")).expect("its diagnostics"),
    }
}
