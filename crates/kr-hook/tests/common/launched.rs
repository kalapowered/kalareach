//! A launch of a stand-in application by the worker's own gateway, with its bridge installed.
//!
//! The application is a shell running a loop that stands in for the application the bridge was
//! installed for: `/bin/sh` on Unix, and on Windows a copy of `cmd.exe` running a batch file, which
//! every Windows machine has. For every request path a test writes to its input it runs
//! `kr-hook <application> hook` with that request as the hook's input, as the application runs a
//! hook for an event, and writes the hook's output, diagnostics and exit code beside the request.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kr_protocol::broker::{AuthenticationState, BinaryIdentity, IntegrationMode, LaunchProfile};
use kr_protocol::gateway::NativeFraming;
#[cfg(windows)]
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    ApplicationInstanceId, EnvironmentId, LaunchProfileId, PluginId, SessionId,
};
use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};
use kr_worker::broker::{
    AdmittedBridge, AgentChild, BridgeSurface, Broker, BrokerError, ForegroundMark, Framing,
    InstalledBridge, NativeGateway, NativeLaunch,
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
#[cfg(unix)]
const APPLICATION: &str = r#"
while IFS= read -r request; do
  "$1" "$2" hook < "$request" > "$request.out" 2> "$request.err"
  echo $? > "$request.tmp"
  mv "$request.tmp" "$request.code"
done
"#;

/// The stand-in application for a channel: the channel server runs as its child, on its standard
/// streams, and the application ends with the server's exit code, which it writes to `$3` first.
#[cfg(unix)]
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
#[cfg(unix)]
const LEADER: &str = r#"exec /usr/bin/perl -e 'setpgrp(0, 0) or die "setpgrp: $!\n"; exec @ARGV or die "exec: $!\n"' /bin/sh -c "$4" application "$1" "$2" "$3""#;

/// The stand-in application on Windows: it reads one request path per line and runs a hook for
/// each, as [`APPLICATION`] does. A batch file reads a line of its input with `set /p`, which
/// leaves the variable as it was at the end of the input, so the variable is cleared first and an
/// empty one ends the application. `{program}` and `{invoked}` are the program and the application
/// name its registration invokes the forwarder with.
#[cfg(windows)]
const APPLICATION: &str = "@echo off\r\n\
:next\r\n\
set \"request=\"\r\n\
set /p request=\r\n\
if not defined request exit /b 0\r\n\
\"{program}\" {invoked} hook < \"%request%\" > \"%request%.out\" 2> \"%request%.err\"\r\n\
> \"%request%.tmp\" echo %errorlevel%\r\n\
move /y \"%request%.tmp\" \"%request%.code\" > NUL\r\n\
goto next\r\n";

/// The stand-in application for a channel on Windows: the channel server runs as its child, on
/// its standard streams, and the application ends with the server's exit code, which it writes to
/// `{code}` first.
#[cfg(windows)]
const CHANNEL_APPLICATION: &str = "@echo off\r\n\
\"{program}\" claude-code channel\r\n\
set code=%errorlevel%\r\n\
> \"{code}.tmp\" echo %code%\r\n\
move /y \"{code}.tmp\" \"{code}\" > NUL\r\n\
exit /b %code%\r\n";

/// What a test writes a stand-in application's requests to.
#[cfg(unix)]
pub type Input = std::process::ChildStdin;
/// What a test writes a stand-in application's requests to.
#[cfg(windows)]
pub type Input = kr_worker::windows::launch::StdinPipe;

/// What a stand-in application writes to its output.
#[cfg(unix)]
pub type Output = std::process::ChildStdout;
/// What a stand-in application writes to its output.
#[cfg(windows)]
pub type Output = std::fs::File;

/// One launch this host made of the stand-in application, with its bridge installed.
pub struct Launch {
    pub broker: Arc<Broker>,
    pub gateway: NativeGateway,
    pub application: Application,
    /// The application's input, until a test closes it.
    pub requests: Option<Input>,
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
    child: AgentChild,
    /// The application's output, until a test takes it.
    pub stdout: Option<Output>,
    /// The file the channel's stand-in writes the code it ends with to.
    code: PathBuf,
    /// What the kernel says the application is, which names the job that holds what it started.
    #[cfg(windows)]
    process: ProcessStartIdentity,
    /// The session's job, which a launch on Windows is held by and which ends all of it when it
    /// closes.
    #[cfg(windows)]
    session: Arc<kr_worker::windows::job::SessionJob>,
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
    #[cfg(unix)]
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

    /// Ends the application and everything it started, and collects it.
    ///
    /// The application's own job lists what it started, wherever those processes are in the tree
    /// below it, so ending the job reaches all of it, including a process whose parent went long
    /// ago. The session's job is let go of last, which ends whatever the first missed.
    ///
    /// # Errors
    ///
    /// Returns what went wrong when the job could not be ended, the application could not be
    /// ended or it could not be collected.
    #[cfg(windows)]
    fn end(&mut self) -> Result<(), String> {
        let job = kr_worker::windows::job::agent_job(&self.process);
        // The application first, which a process the job ended already would refuse to be ended
        // again; the job then ends what the application started.
        let ended = self
            .child
            .kill()
            .map_err(|error| format!("the application could not be ended: {error}"));
        let job_ended = job.as_ref().map_or(Ok(()), |job| {
            job.terminate(1)
                .map_err(|error| format!("the application's job could not be ended: {error}"))
        });
        let collected = self
            .child
            .wait()
            .map(|_| ())
            .map_err(|error| format!("the application could not be collected: {error}"));
        kr_worker::windows::job::release_agent(&self.process);
        // A process the job ended is listed until the system has finished with it, so the job is
        // read until it lists nothing, within the liveness bound.
        let listed = job.as_ref().map_or(Ok(()), |job| {
            let deadline = std::time::Instant::now() + LIVENESS;
            loop {
                match job.process_ids() {
                    Ok(left) if left.is_empty() => break Ok(()),
                    Ok(left) if std::time::Instant::now() >= deadline => {
                        break Err(format!("the application's job still holds {left:?}"));
                    }
                    Ok(_) => std::thread::sleep(Duration::from_millis(10)),
                    Err(error) => {
                        break Err(format!("the application's job could not be read: {error}"));
                    }
                }
            }
        });
        [job_ended, ended, collected, listed]
            .into_iter()
            .filter_map(Result::err)
            .reduce(|first, next| format!("{first}, and {next}"))
            .map_or(Ok(()), Err)
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

/// Makes a directory only this account may use.
#[cfg(unix)]
fn private(directory: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(directory).expect("a directory");
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        .expect("made private");
}

/// Makes a directory only this account may use.
#[cfg(windows)]
fn private(directory: &Path) {
    kr_ipc::paths::create_private_directory(directory).expect("a private directory");
}

/// The directory the launched application works in: the launch's own, on Unix, and one beside it
/// on Windows, where the backend never works in the directory its files are published in.
#[cfg(unix)]
fn working_directory(_placed: &Placed, runtime: &Path) -> PathBuf {
    runtime.to_path_buf()
}

/// The directory the launched application works in.
#[cfg(windows)]
fn working_directory(placed: &Placed, _runtime: &Path) -> PathBuf {
    let directory = placed.host.root().join("w");
    std::fs::create_dir_all(&directory).expect("a working directory");
    directory
}

/// The program a launch starts for the stand-in application `script` stands for, and its
/// arguments: `/bin/sh` running the script under a leader of a process group of its own, the
/// program, the application's name and the file its exit code goes to.
#[cfg(unix)]
fn application(
    _placed: &Placed,
    script: &str,
    program: &Path,
    invoked: &str,
    code: &Path,
) -> (String, Vec<String>) {
    (
        "/bin/sh".to_owned(),
        vec![
            "-c".to_owned(),
            LEADER.to_owned(),
            "application".to_owned(),
            program.to_string_lossy().into_owned(),
            invoked.to_owned(),
            code.to_string_lossy().into_owned(),
            script.to_owned(),
        ],
    )
}

/// The program a launch starts for the stand-in application `script` stands for, and its
/// arguments: a copy of `cmd.exe` of this launch's own running a batch file written for it, which
/// names the program, the application and the file its exit code goes to. The launch's own jobs
/// hold what it starts, so nothing leads a group.
#[cfg(windows)]
fn application(
    placed: &Placed,
    script: &str,
    program: &Path,
    invoked: &str,
    code: &Path,
) -> (String, Vec<String>) {
    let text = placed.host.root().join("application.cmd");
    std::fs::write(
        &text,
        script
            .replace("{program}", &program.to_string_lossy())
            .replace("{invoked}", invoked)
            .replace("{code}", &code.to_string_lossy()),
    )
    .expect("the stand-in application is written");
    let shell = placed.host.root().join("bin").join("application.exe");
    let system = std::env::var_os("SystemRoot").expect("a system directory");
    kr_ipc::testing::place_program(&Path::new(&system).join("System32").join("cmd.exe"), &shell);
    (
        shell.to_string_lossy().into_owned(),
        vec![
            "/d".to_owned(),
            "/q".to_owned(),
            "/c".to_owned(),
            text.to_string_lossy().into_owned(),
        ],
    )
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
        let runtime = placed.host.root().join("l");
        let inbox = placed.host.root().join("h");
        for directory in [&runtime, &inbox] {
            private(directory);
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
        let gateway = NativeGateway::bind(
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
                working_directory: working_directory(placed, &runtime),
            },
        )
        .expect("the endpoint binds")
        .with_bridge(installed)
        .expect("the bridge is this launch's connector's");
        // A launch on Windows is held by the session's job, which ends all of it when it closes.
        #[cfg(windows)]
        let session = Arc::new(kr_worker::windows::job::SessionJob::create().expect("a job"));
        #[cfg(windows)]
        let gateway = gateway.in_session(Arc::clone(&session));
        let mut gateway = gateway;
        let (resolved_path, arguments) = application(placed, script, program, invoked, &code);
        let profile = LaunchProfile {
            profile_id: LaunchProfileId::new("lp-claude").expect("valid"),
            environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
            binary: BinaryIdentity {
                resolved_path,
                digest: Digest256::from_bytes([3; 32]),
                version: "2.1.278".to_owned(),
                distribution: "npm".to_owned(),
            },
            arguments,
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
                #[cfg(windows)]
                process: launched.process,
                #[cfg(windows)]
                session,
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
        // One write, so that the line is never read as two: a batch file's `set /p` that reads
        // between a path and its line break takes the path as the line and the break as the next.
        requests
            .write_all(format!("{}\n", request.display()).as_bytes())
            .expect("the application is asked");
        requests.flush().expect("and it goes");
        request
    }

    /// Closes the application's input, as the application's own end of a connection closes when it
    /// goes: what reads it then reads the end.
    ///
    /// On Windows the host keeps a handle on the pipe for the agent's stop, so a test that only
    /// dropped its own would leave the pipe open.
    pub fn close_input(&mut self) {
        let Some(input) = self.requests.take() else {
            return;
        };
        #[cfg(windows)]
        input.close().expect("the application's input is closed");
        drop(input);
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
