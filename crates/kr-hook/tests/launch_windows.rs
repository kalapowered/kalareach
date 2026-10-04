//! `kr-hook launch` on Windows, against the worker's own command backends.
//!
//! This test process plays the root shell: it establishes a backend the way the session does when the
//! shell asks to resolve an integrated invocation, and starts the launcher as its own child, in a job
//! of its own the way a session's shell runs everything it starts. The program is a copy of
//! `cmd.exe` named `gemini.exe`, running a short batch file that writes down what it found the moment
//! it started: the registration, the variable the package declares and the directory it works in.
//! `cmd.exe` and `ping.exe` are on every Windows machine; nothing else is needed.
//!
//! The launcher creates its program before it tells the backend, and starts it only when the backend
//! has committed, so what is checked here is the order as much as the outcome: the backend names the
//! program and not the launcher, in a job of its own, and a launch that goes wrong leaves a program
//! that never ran.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.02 | a launch records and commits the program the launcher created, never the launcher; the program's exit code is the launcher's, whole, whether the launch was committed or the program ran as typed; a launch the backend refuses or does not commit, one a launcher declines, one whose launcher goes before the program is shown and one before it is confirmed, and one that is never started leave nothing running; a program that was started outlives the launcher |
//! | KR-REQ-12.07 | a refused invocation runs as typed |
//! | KR-REQ-05.09 | a program the kernel shows was not made from the hashed file, or was not started by the launcher, is not committed; the hold on the hashed file ends with the commit; a launcher the root shell did not start, or one started before the backend was established, is not admitted |
//! | KR-REQ-07.61 | the committed program is held by a job of its own, which lists what it starts |

#![cfg(windows)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{LIVENESS, Placed};
use kr_protocol::ids::{ApplicationInstanceId, EnvironmentId, SessionId};
use kr_protocol::root::{CommandBackend, CwdRevision, PromptGeneration};
use kr_protocol::scalars::Uuid;
use kr_protocol::session::CommandIntegration;
use kr_worker::broker::Broker;
use kr_worker::broker::commands::{
    BackendState, CommandBackends, CommandBackendsConfig, EstablishRequest,
};
use kr_worker::broker::connectors::{ConnectorSources, fixture};
use kr_worker::persistence::JournalHealth;
use kr_worker::windows::job::{AgentJob, SessionJob};
use kr_worker::windows::launch::{Child, Spec};

/// What the program writes the moment it starts, and what it does next. It waits far longer than
/// any test takes unless a test tells it to end.
const SCRIPT: &str = "@echo off\r\n\
(\r\n\
echo variable=%KR_REGISTRATION%\r\n\
echo relaunch=%GEMINI_CLI_NO_RELAUNCH%\r\n\
echo cwd=%CD%\r\n\
) > \"%REPORT%.part\"\r\n\
move /y \"%REPORT%.part\" \"%REPORT%\" > NUL\r\n\
if defined EXIT_WITH exit /b %EXIT_WITH%\r\n\
if defined AFTER_GONE call :after\r\n\
ping -n 600 127.0.0.1 > NUL\r\n\
exit /b 0\r\n\
:after\r\n\
if not exist \"%AFTER_GONE%\" ping -n 2 127.0.0.1 > NUL & goto after\r\n\
echo survived > \"%AFTER_DONE%\"\r\n\
exit /b 0\r\n";

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

/// A program in the system directory, which every Windows machine has.
fn system_program(name: &str) -> PathBuf {
    Path::new(&std::env::var_os("SystemRoot").expect("a system directory"))
        .join("System32")
        .join(name)
}

/// Waits until a condition holds, within the liveness bound.
fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(started.elapsed() < LIVENESS, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// What a program wrote, one `name=value` to a line. A value that still reads as the name of a
/// variable the batch file asked for is one that was not set.
fn parsed(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.trim_end().split_once('='))
        .map(|(name, value)| {
            let value = if value.starts_with('%') && value.ends_with('%') {
                "unset"
            } else {
                value
            };
            (name.to_owned(), value.to_owned())
        })
        .collect()
}

/// This test process, the root shell of every launch it starts.
struct Shell {
    placed: Placed,
    runtime: tokio::runtime::Runtime,
    broker: Arc<Broker>,
    backends: Arc<CommandBackends>,
    /// The program every case runs: a copy of `cmd.exe` under the name the package integrates.
    executable: PathBuf,
    reports: PathBuf,
    script: PathBuf,
    generation: std::sync::atomic::AtomicU64,
    /// The job everything this shell starts runs in, which ends all of it when the test does.
    job: SessionJob,
    /// A file the launchers it starts wait for before they start their program, where it is set.
    barrier: std::sync::Mutex<Option<PathBuf>>,
}

impl Shell {
    fn new() -> Self {
        Self::build(|source| source, 0)
    }

    /// A shell whose program is `bytes` long, written new so that the system has not seen it: the
    /// size of the largest agent this platform runs, whose first start is scanned as it is read.
    fn large(bytes: u64) -> Self {
        Self::build(|source| source, bytes)
    }

    /// A shell whose connector's installation is granted to read files as well.
    fn reading() -> Self {
        Self::build(fixture::reading, 0)
    }

    fn build(
        installed: impl FnOnce(
            kr_worker::broker::connectors::ConnectorSource,
        ) -> kr_worker::broker::connectors::ConnectorSource,
        padding: u64,
    ) -> Self {
        let placed = Placed::new();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        let bin = placed.host.root().join("bin");
        let executable = bin.join("gemini.exe");
        kr_ipc::testing::place_program(&system_program("cmd.exe"), &executable);
        if padding > 0 {
            // Zeros after the image: the file still runs, and it is as large as an agent is.
            std::fs::OpenOptions::new()
                .write(true)
                .open(&executable)
                .and_then(|file| file.set_len(padding))
                .expect("the program is made as large as an agent");
        }
        let store = placed.host.root().join("store");
        std::fs::create_dir_all(&store).expect("a store");
        let sources = Arc::new(ConnectorSources::new());
        let source = installed(
            fixture::package(&store, &placed.forwarder, &fixture::Shape::gemini_cli(&[]))
                .expect("the package is written"),
        );
        let broker = Arc::new(
            Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens"),
        );
        // The connector is admitted, as the control daemon hands it over, and a launch binds it.
        let admissions = kr_worker::broker::catalogue::Admissions::new();
        let _ = kr_worker::broker::catalogue::testing::admit(
            &admissions,
            &sources,
            &broker,
            vec![kr_worker::broker::catalogue::testing::admitted(&source)],
            1,
        );
        assert!(sources.for_command("gemini").is_some());
        let backends = Arc::new(CommandBackends::new(
            Arc::clone(&broker),
            CommandBackendsConfig {
                session_id: session(),
                environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
                os_user: "someone".to_owned(),
                runtime_dir: placed.host.root().to_path_buf(),
                sources: Arc::clone(&sources),
                launcher: Some(placed.forwarder.clone()),
                registered_forwarder: Some(placed.forwarder.clone()),
            },
            runtime.handle().clone(),
        ));
        let reports = placed.host.root().join("reports");
        std::fs::create_dir_all(&reports).expect("a directory for reports");
        let script = reports.join("report.cmd");
        std::fs::write(&script, SCRIPT).expect("the program's batch file");
        Self {
            placed,
            runtime,
            broker,
            backends,
            executable,
            reports,
            script,
            generation: std::sync::atomic::AtomicU64::new(1),
            job: SessionJob::create().expect("a job for what this shell starts"),
            barrier: std::sync::Mutex::new(None),
        }
    }

    fn integration() -> CommandIntegration {
        CommandIntegration {
            plugin_id: kr_protocol::ids::PluginId::new("kalareach/gemini-cli")
                .expect("a plugin identifier"),
            command: "gemini".to_owned(),
            flags: Vec::new(),
            enabled: true,
        }
    }

    /// The vector every case types, which the integration answers unchanged: the program's name
    /// and the batch file `cmd.exe` runs.
    fn typed(&self) -> Vec<String> {
        vec![
            "gemini".to_owned(),
            "/d".to_owned(),
            "/c".to_owned(),
            self.script.display().to_string(),
        ]
    }

    /// Establishes a backend for the next line, as the session does for an integrated resolve, for
    /// an invocation the shell reported running in `cwd`.
    fn establish_in(&self, cwd: &Path) -> CommandBackend {
        let typed = self.typed();
        let generation = self
            .generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _entered = self.runtime.enter();
        self.backends
            .establish(&EstablishRequest {
                prompt_generation: PromptGeneration::new(generation),
                typed: &typed,
                arguments: &typed,
                added: &[],
                integration: &Self::integration(),
                executable: self.executable.to_str().expect("a text path"),
                cwd: cwd.to_str().expect("a text path"),
                cwd_revision: CwdRevision::new(1),
                root_shell: kr_ipc::identity::current_process_start_identity()
                    .expect("this process"),
            })
            .expect("a backend is established")
    }

    fn establish(&self) -> CommandBackend {
        self.establish_in(self.placed.host.root())
    }

    /// Starts the launcher for `vector` as the shell's executor does: with the answer's variable, a
    /// report to write and the variables of `env`, in `cwd`, in this shell's job. Where the shell
    /// holds its launchers at a barrier, none starts its program until that file exists.
    fn launcher(
        &self,
        executable: &Path,
        vector: &[String],
        answer: &CommandBackend,
        name: &str,
        env: &[(&str, &str)],
        cwd: &Path,
    ) -> Child {
        let mut arguments = vec!["launch".to_owned()];
        if let Some(barrier) = self.barrier.lock().expect("the barrier").as_ref() {
            arguments.push("--hold-before-exec".to_owned());
            arguments.push(barrier.display().to_string());
        }
        arguments.push("--".to_owned());
        arguments.push(executable.display().to_string());
        arguments.extend(vector.iter().cloned());
        let report = self.reports.join(name);
        let mut variables: Vec<(&str, std::ffi::OsString)> = answer
            .environment
            .iter()
            .map(|variable| (variable.name.as_str(), variable.value.clone().into()))
            .collect();
        variables.push(("REPORT", report.into_os_string()));
        for (name, value) in env {
            variables.push((name, (*value).into()));
        }
        let variables: Vec<(&str, &std::ffi::OsStr)> = variables
            .iter()
            .map(|(name, value)| (*name, value.as_os_str()))
            .collect();
        let agent = AgentJob::create().expect("a job for the launcher's own children");
        kr_worker::windows::launch::start(&Spec {
            program: &self.placed.forwarder,
            arguments: &arguments,
            directory: cwd,
            environment: &variables,
            session: Some(&self.job),
            agent: &agent,
            pipe_input: false,
            pipe_output: false,
        })
        .expect("the launcher starts")
    }

    /// Starts the launcher for the vector every case types, in the tree's root.
    fn launch(&self, answer: &CommandBackend, name: &str, env: &[(&str, &str)]) -> Child {
        self.launcher(
            &self.executable,
            &self.typed(),
            answer,
            name,
            env,
            self.placed.host.root(),
        )
    }

    /// Waits for the report a launched program writes, and says what became of the launcher when
    /// none comes.
    fn report_from(&self, name: &str, launcher: &mut Child) -> BTreeMap<String, String> {
        let path = self.reports.join(name);
        let started = Instant::now();
        loop {
            if let Ok(text) = std::fs::read_to_string(&path) {
                return parsed(&text);
            }
            if let Ok(Some(status)) = launcher.try_wait() {
                // A program that has written its report and gone is read once more.
                std::thread::sleep(Duration::from_millis(200));
                if let Ok(text) = std::fs::read_to_string(&path) {
                    return parsed(&text);
                }
                panic!("the launcher ended with {status} and the program reported nothing");
            }
            assert!(
                started.elapsed() < LIVENESS,
                "the program reported by now: the launcher is still running"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn registration(answer: &CommandBackend) -> PathBuf {
        PathBuf::from(&answer.environment[0].value)
    }

    /// What a published registration says, one `name=value` to a line.
    fn registered(answer: &CommandBackend) -> BTreeMap<String, String> {
        std::fs::read_to_string(Self::registration(answer))
            .expect("the registration")
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect()
    }

    fn instance_of(answer: &CommandBackend) -> ApplicationInstanceId {
        Self::registered(answer)["instance"]
            .parse()
            .expect("the registration names an instance")
    }

    fn state_of(&self, instance: ApplicationInstanceId) -> Option<BackendState> {
        self.backends.state_of(instance)
    }
}

impl Drop for Shell {
    fn drop(&mut self) {
        let _ = self.job.terminate(1);
        let _ = self.backends.close();
    }
}

/// KR-REQ-12.02, KR-REQ-05.09 and KR-REQ-07.61: a launch is committed for the program the launcher
/// created and not for the launcher, which is that program's parent; the program runs in a job of
/// its own, with the variable its package declares, and in the directory the launcher worked in.
#[test]
fn kr_req_12_02_a_launch_commits_the_program_the_launcher_created() {
    let shell = Shell::new();
    let answer = shell.establish();
    let mut launcher = shell.launch(&answer, "committed", &[]);
    let report = shell.report_from("committed", &mut launcher);
    assert_eq!(report["relaunch"], "true", "the declared variable is set");
    assert_eq!(
        PathBuf::from(&report["variable"]),
        Shell::registration(&answer),
        "and the registration the shell exported is there"
    );
    let registered = Shell::registered(&answer);
    let program: u32 = registered["pid"].parse().expect("a process identifier");
    assert_ne!(
        program,
        launcher.id(),
        "the registration names the program and not the launcher"
    );
    let program_identity = kr_ipc::identity::process_start_identity(program).expect("the program");
    assert_eq!(
        registered["start"],
        program_identity.start_value.get().to_string(),
        "by its start as well"
    );
    let launcher_identity =
        kr_ipc::identity::process_start_identity(launcher.id()).expect("the launcher");
    assert_eq!(
        kr_worker::windows::lineage::parent_of(&program_identity),
        Ok(launcher_identity),
        "the launcher is the program's parent"
    );
    let instance = Shell::instance_of(&answer);
    assert!(matches!(
        shell.state_of(instance),
        Some(BackendState::Committed(_))
    ));
    assert!(
        shell.broker.holds_process(&program_identity),
        "the broker's instance is the program's"
    );
    let job = kr_worker::windows::job::agent_job(&program_identity)
        .expect("the program is held by a job of its own");
    assert!(
        job.process_ids()
            .expect("the job lists its processes")
            .contains(&program),
        "which holds it"
    );
    assert!(
        PathBuf::from(&report["cwd"])
            .to_string_lossy()
            .eq_ignore_ascii_case(&shell.placed.host.root().to_string_lossy()),
        "the program works where the launcher did: {}",
        report["cwd"]
    );
}

/// KR-REQ-12.02: the launcher ends with the whole exit code of its program, which is 32 bits on this
/// platform. Control: a small code reaches the shell as it is.
#[test]
fn kr_req_12_02_the_launcher_returns_the_programs_whole_exit_code() {
    let shell = Shell::new();
    for (code, name) in [("305419896", "whole"), ("3", "small")] {
        let answer = shell.establish();
        let mut launcher = shell.launch(&answer, name, &[("EXIT_WITH", code)]);
        let report = shell.report_from(name, &mut launcher);
        assert_eq!(report["relaunch"], "true", "{name}: it was launched");
        let status = launcher.wait().expect("the launcher ends with the program");
        assert_eq!(
            status.code(),
            Some(code.parse::<i32>().expect("a code")),
            "{name}: the program's code, whole"
        );
    }
}

/// KR-REQ-12.02: a program run as typed, because the backend refused the launch, also ends the
/// launcher with its whole 32-bit exit code and not with that code cut to a byte. Control: a small
/// code reaches the shell as it is (`kr_req_12_07_a_launch_the_backend_refuses_runs_as_typed`).
#[test]
fn kr_req_12_02_a_program_run_as_typed_returns_its_whole_exit_code() {
    let shell = Shell::new();
    let answer = shell.establish();
    let mut launcher = shell.launcher(
        &shell.executable.clone(),
        &[
            "gemini".to_owned(),
            "/d".to_owned(),
            "/c".to_owned(),
            "exit /b 305419896".to_owned(),
        ],
        &answer,
        "typed-whole",
        &[],
        shell.placed.host.root(),
    );
    let status = launcher.wait().expect("the launcher ends with the program");
    assert_eq!(
        status.code(),
        Some(305_419_896),
        "the typed program's code, whole"
    );
}

/// KR-REQ-12.07: a launch the backend refuses runs as typed: the program runs without the declared
/// variable and without the registration, and ends with its own exit code. Here the argument vector
/// the launcher presents is not the one the backend answered. Control: the vector it answered is
/// committed.
#[test]
fn kr_req_12_07_a_launch_the_backend_refuses_runs_as_typed() {
    let shell = Shell::new();
    let answer = shell.establish();
    let mut launcher = shell.launcher(
        &shell.executable.clone(),
        &[
            "gemini".to_owned(),
            "/d".to_owned(),
            "/c".to_owned(),
            "exit /b 7".to_owned(),
        ],
        &answer,
        "typed",
        &[],
        shell.placed.host.root(),
    );
    let status = launcher.wait().expect("the launcher ends with the program");
    assert_eq!(status.code(), Some(7), "the typed program ran and ended");
    assert!(
        !Shell::registration(&answer).exists(),
        "and nothing was registered for it"
    );
    // Control: the same invocation as it was established is committed.
    let mut again = shell.launch(&answer, "again", &[]);
    let report = shell.report_from("again", &mut again);
    assert_eq!(report["relaunch"], "true");
}

/// The launcher played by a process of its own, which this test controls over its standard input
/// and output: it says to the backend what a real launcher says, and can say what no real one
/// does, so the checks a real launcher can never fail are shown to fail. It is a child of this
/// process, started after the backend was established, as the shell's own children are.
///
/// The process is this test binary running [`scripted_launcher_helper`]: each command is one line of
/// JSON on its standard input, and each answer is one line that begins `KR>`.
struct Scripted {
    child: Child,
    answers: std::io::BufReader<std::fs::File>,
}

impl Scripted {
    fn start(shell: &Shell) -> Self {
        Self::started(shell, false)
    }

    /// Starts the scripted launcher as the child of a `cmd.exe` that is the shell's own child, so
    /// that the shell is the launcher's grandparent.
    fn start_beneath(shell: &Shell) -> Self {
        Self::started(shell, true)
    }

    fn started(shell: &Shell, beneath: bool) -> Self {
        let agent = AgentJob::create().expect("a job for the helper's own children");
        let this = std::env::current_exe().expect("this test's executable");
        let mut arguments = vec![
            "--ignored".to_owned(),
            "--exact".to_owned(),
            "scripted_launcher_helper".to_owned(),
            "--nocapture".to_owned(),
        ];
        let program = if beneath {
            let mut through = vec!["/d".to_owned(), "/c".to_owned(), this.display().to_string()];
            through.append(&mut arguments);
            arguments = through;
            system_program("cmd.exe")
        } else {
            this
        };
        let mut child = kr_worker::windows::launch::start(&Spec {
            program: &program,
            arguments: &arguments,
            directory: shell.placed.host.root(),
            environment: &[],
            session: Some(&shell.job),
            agent: &agent,
            pipe_input: true,
            pipe_output: true,
        })
        .expect("the scripted launcher starts");
        let answers = std::io::BufReader::new(child.stdout.take().expect("its output"));
        Self { child, answers }
    }

    /// Sends one command and returns the answer it gives.
    fn ask(&mut self, command: &serde_json::Value) -> serde_json::Value {
        use std::io::{BufRead as _, Write as _};
        let input = self.child.stdin.as_mut().expect("its input");
        writeln!(input, "{command}").expect("the command is written");
        loop {
            let mut line = String::new();
            let read = self
                .answers
                .read_line(&mut line)
                .expect("an answer is read");
            assert_ne!(read, 0, "the scripted launcher ended before it answered");
            if let Some(answer) = line.trim_end().strip_prefix("KR>") {
                return serde_json::from_str(answer).expect("an answer is JSON");
            }
        }
    }

    /// Presents the helper to the backend as a launcher for `executable` and `arguments`, and
    /// returns the backend's answer to it: a line, or `None` where the connection was closed.
    fn present(
        &mut self,
        answer: &CommandBackend,
        executable: &Path,
        arguments: &[String],
    ) -> Option<String> {
        let directory = Shell::registration(answer)
            .parent()
            .expect("the backend's directory")
            .to_path_buf();
        self.ask(&serde_json::json!({ "present": {
            "directory": directory,
            "executable": executable,
            "arguments": arguments,
        }}))["line"]
            .as_str()
            .map(str::to_owned)
    }

    /// The next line the backend writes, or `None` where it closed the connection.
    fn read(&mut self) -> Option<String> {
        self.ask(&serde_json::json!({ "read": true }))["line"]
            .as_str()
            .map(str::to_owned)
    }

    fn write(&mut self, frame: &serde_json::Value) {
        self.ask(&serde_json::json!({ "write": frame }));
    }

    /// Creates a program suspended from `executable`, as a launcher does, and returns it.
    fn create(&mut self, executable: &Path, arguments: &[String]) -> u32 {
        self.ask(&serde_json::json!({ "create": {
            "executable": executable,
            "arguments": arguments,
        }}))["pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok())
            .expect("a process identifier")
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Scripted {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The scripted launcher's process: it does what it is told on its standard input.
#[test]
#[ignore = "a process the tests below start as a launcher"]
fn scripted_launcher_helper() {
    use std::io::{BufRead as _, Write as _};
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let mut connection: Option<(
        tokio::io::BufReader<tokio::io::ReadHalf<kr_ipc::endpoint::Connection>>,
        tokio::io::WriteHalf<kr_ipc::endpoint::Connection>,
    )> = None;
    let mut created: Vec<std::process::Child> = Vec::new();
    let reply = |value: serde_json::Value| {
        let mut out = std::io::stdout().lock();
        writeln!(out, "KR>{value}").expect("the answer is written");
        out.flush().expect("and flushed");
    };
    let read_line = |connection: &mut Option<(
        tokio::io::BufReader<tokio::io::ReadHalf<kr_ipc::endpoint::Connection>>,
        tokio::io::WriteHalf<kr_ipc::endpoint::Connection>,
    )>| {
        let (reader, _) = connection.as_mut().expect("a connection");
        let mut line = String::new();
        let read = runtime
            .block_on(async { tokio::time::timeout(LIVENESS, reader.read_line(&mut line)).await })
            .expect("the backend answers or closes in time");
        match read {
            Ok(0) | Err(_) => serde_json::json!({ "line": null }),
            Ok(_) => serde_json::json!({ "line": line.trim_end() }),
        }
    };
    for command in std::io::stdin().lock().lines() {
        let command: serde_json::Value =
            serde_json::from_str(&command.expect("a line")).expect("a command is JSON");
        if let Some(present) = command.get("present") {
            let directory = PathBuf::from(present["directory"].as_str().expect("a directory"));
            let record: serde_json::Value = serde_json::from_slice(
                &std::fs::read(directory.join("launch")).expect("the launch record"),
            )
            .expect("a record");
            let name = record["endpoint"]
                .as_str()
                .and_then(|text| text.strip_prefix(r"\\.\pipe\"))
                .expect("a local pipe")
                .to_owned();
            let credential = std::fs::read_to_string(directory.join("credential"))
                .expect("the credential")
                .trim()
                .to_owned();
            let identity =
                kr_ipc::identity::current_process_start_identity().expect("this process");
            let address = kr_ipc::paths::Endpoint::from_name(name).expect("an endpoint");
            let opened = runtime
                .block_on(kr_ipc::endpoint::Connection::connect(&address))
                .expect("the endpoint is reached");
            let (reader, mut writer) = tokio::io::split(opened);
            let line = serde_json::json!({ "kr_launch": {
                "credential": credential,
                "pid": identity.pid.get(),
                "start": identity.start_value.get(),
                "executable": present["executable"],
                "arguments": present["arguments"],
            }})
            .to_string();
            runtime
                .block_on(async {
                    writer.write_all(line.as_bytes()).await?;
                    writer.write_all(b"\n").await?;
                    writer.flush().await
                })
                .expect("the presentation is written");
            connection = Some((tokio::io::BufReader::new(reader), writer));
            reply(read_line(&mut connection));
        } else if command.get("read").is_some() {
            reply(read_line(&mut connection));
        } else if let Some(frame) = command.get("write") {
            let (_, writer) = connection.as_mut().expect("a connection");
            let line = format!("{frame}\n");
            runtime
                .block_on(async {
                    writer.write_all(line.as_bytes()).await?;
                    writer.flush().await
                })
                .expect("the frame is written");
            reply(serde_json::json!({ "written": true }));
        } else if let Some(create) = command.get("create") {
            use std::os::windows::process::CommandExt as _;
            let arguments: Vec<String> = create["arguments"]
                .as_array()
                .expect("arguments")
                .iter()
                .map(|argument| argument.as_str().expect("text").to_owned())
                .collect();
            let child = std::process::Command::new(create["executable"].as_str().expect("a path"))
                .args(arguments)
                .creation_flags(0x0000_0004)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("a suspended program");
            reply(serde_json::json!({ "pid": child.id() }));
            created.push(child);
        }
    }
    for mut child in created {
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Shell {
    /// The prompt generation of the line the last backend was established for.
    fn last_generation(&self) -> PromptGeneration {
        PromptGeneration::new(self.generation.load(std::sync::atomic::Ordering::SeqCst) - 1)
    }

    /// A copy of `cmd.exe` that is not the program every case runs.
    fn another_program(&self) -> PathBuf {
        let another = self.placed.host.root().join("bin").join("another.exe");
        kr_ipc::testing::place_program(&system_program("cmd.exe"), &another);
        another
    }

    /// The frame a launcher says it is going in, naming `program` and the directory it works in.
    fn going(program: u32) -> serde_json::Value {
        serde_json::json!({ "kr_launch": { "going": true, "program": program } })
    }

    /// Starts a scripted launcher and presents it for the vector every case types.
    fn admitted_launcher(&self, answer: &CommandBackend) -> Scripted {
        let mut scripted = Scripted::start(self);
        let admitted = scripted.present(answer, &self.executable, &self.typed());
        assert!(
            admitted
                .as_deref()
                .is_some_and(|line| line.contains("\"admitted\":true")),
            "the backend admits the launch: {admitted:?}"
        );
        scripted
    }

    /// Shows that a refused launch gave everything back: the same invocation, launched again, is
    /// admitted and committed.
    fn commits_after_a_refusal(&self, answer: &CommandBackend) {
        let mut scripted = self.admitted_launcher(answer);
        let program = scripted.create(&self.executable, &self.typed()[1..]);
        scripted.write(&Self::going(program));
        let committed = scripted.read();
        assert!(
            committed
                .as_deref()
                .is_some_and(|line| line.contains("\"committed\":true")),
            "a retry of the invocation is committed: {committed:?}"
        );
    }
}

/// KR-REQ-05.09: a program created from another file than the one the backend hashed is not
/// committed, and the launch gives back what it took. Control: a program created from the hashed
/// file is.
#[test]
fn kr_req_05_09_a_program_created_from_another_file_is_not_committed() {
    let shell = Shell::new();
    let answer = shell.establish();
    let mut scripted = shell.admitted_launcher(&answer);
    let program = scripted.create(&shell.another_program(), &shell.typed()[1..]);
    scripted.write(&Shell::going(program));
    assert_eq!(
        scripted.read(),
        None,
        "the connection is closed, uncommitted"
    );
    let why = shell
        .backends
        .launch_failure_of(shell.last_generation())
        .expect("the backend says why");
    assert!(why.contains("another file"), "{why}");
    assert!(
        !Shell::registration(&answer).exists(),
        "and nothing was published"
    );
    shell.commits_after_a_refusal(&answer);
}

/// KR-REQ-05.09: a process the launcher did not start is not the program it says it created: here
/// the launcher names itself, and its own parent is not it. Control: its own child is.
#[test]
fn kr_req_05_09_a_process_the_launcher_did_not_create_is_not_committed() {
    let shell = Shell::new();
    let answer = shell.establish();
    let mut scripted = shell.admitted_launcher(&answer);
    scripted.write(&Shell::going(scripted.pid()));
    assert_eq!(scripted.read(), None, "uncommitted");
    let why = shell
        .backends
        .launch_failure_of(shell.last_generation())
        .expect("the backend says why");
    assert!(why.contains("not started by the launcher"), "{why}");
    shell.commits_after_a_refusal(&answer);
}

/// KR-REQ-05.09: a launcher the root shell did not start is not admitted, whatever it presents: here
/// the shell started a `cmd.exe` and that started the launcher. Control: the shell's own child, the
/// same presentation, is admitted and committed.
#[test]
fn kr_req_05_09_a_launcher_the_root_shell_did_not_start_is_not_admitted() {
    let shell = Shell::new();
    let answer = shell.establish();
    let mut beneath = Scripted::start_beneath(&shell);
    assert_eq!(
        beneath.present(&answer, &shell.executable, &shell.typed()),
        None,
        "the connection is closed without a word"
    );
    shell.commits_after_a_refusal(&answer);
}

/// KR-REQ-05.09: a launcher that was started before the backend was established is not admitted: it
/// cannot have been started for the invocation the backend answered. Control: one started after
/// the establish, the same presentation, is admitted and committed.
#[test]
fn kr_req_05_09_a_launcher_started_before_the_backend_was_established_is_not_admitted() {
    let shell = Shell::new();
    let mut early = Scripted::start(&shell);
    // Longer than a tick of the kernel's clock, so that the launcher is strictly the older.
    std::thread::sleep(Duration::from_millis(100));
    let answer = shell.establish();
    assert_eq!(
        early.present(&answer, &shell.executable, &shell.typed()),
        None,
        "the connection is closed without a word"
    );
    shell.commits_after_a_refusal(&answer);
}

/// KR-REQ-12.02: a launcher that cannot create its program says so, the backend records why on the
/// launch attempt, and the invocation can be launched again.
#[test]
fn kr_req_12_02_a_launcher_that_declines_leaves_its_reason_and_no_instance() {
    let shell = Shell::new();
    let answer = shell.establish();
    let mut scripted = shell.admitted_launcher(&answer);
    scripted.write(&serde_json::json!({ "kr_launch": {
        "going": false,
        "declined": "the job limits the desktop",
    }}));
    assert_eq!(scripted.read(), None, "uncommitted");
    let why = shell
        .backends
        .launch_failure_of(shell.last_generation())
        .expect("the reason is kept on the backend");
    assert!(why.contains("the job limits the desktop"), "{why}");
    assert!(!Shell::registration(&answer).exists());
    shell.commits_after_a_refusal(&answer);
}

/// KR-REQ-12.02: a launch the backend does not commit leaves nothing of the launcher's running: the
/// program it created was never started and it is ended before the typed command runs. Here the
/// line ends while the launch waits at its commit, so the backend is retired and the commit is
/// refused. Control: the same launch, committed, is the program the other tests run.
#[test]
fn kr_req_12_02_a_program_the_backend_does_not_commit_is_ended_and_the_typed_command_runs() {
    let shell = Shell::new();
    let answer = shell.establish();
    let (arrived, release) = shell.backends.pause_before_committing();
    // The typed program ends at once, so that what the shell's job holds afterwards is what the
    // launcher left behind.
    let mut launcher = shell.launch(&answer, "uncommitted", &[("EXIT_WITH", "7")]);
    shell
        .runtime
        .block_on(async { tokio::time::timeout(LIVENESS, arrived).await })
        .expect("the launch arrives at the commit")
        .expect("and waits there");
    // Retiring the backend ends the admission where it waits, so there may be nobody to release.
    let _ = shell.backends.close();
    let _ = release.send(());
    let status = launcher
        .wait()
        .expect("the launcher ends with the typed program");
    assert_eq!(status.code(), Some(7), "the typed command ran");
    eventually("the program the launcher created is ended", || {
        shell.job.process_ids().is_ok_and(|held| held.is_empty())
    });
}

/// KR-REQ-12.02: a launcher that is gone between the commit and the confirmation leaves no program
/// suspended: the worker ends the program it was shown when the confirmation cannot be written.
/// Control: a launcher that is not gone is confirmed, and its program runs (every other test here).
#[test]
fn kr_req_12_02_a_launcher_gone_before_it_is_confirmed_leaves_no_suspended_program() {
    let shell = Shell::new();
    let answer = shell.establish();
    let (arrived, release) = shell.backends.pause_before_confirming();
    let mut scripted = shell.admitted_launcher(&answer);
    let program = scripted.create(&shell.executable, &shell.typed()[1..]);
    let identity = kr_ipc::identity::process_start_identity(program).expect("an identity");
    scripted.write(&Shell::going(program));
    shell
        .runtime
        .block_on(async { tokio::time::timeout(LIVENESS, arrived).await })
        .expect("the launch arrives at its confirmation")
        .expect("and waits there");
    let _ = scripted.child.kill();
    let _ = scripted.child.wait();
    let _ = release.send(());
    eventually("the program nobody can start is ended", || {
        matches!(
            kr_ipc::identity::process_state(&identity),
            kr_ipc::identity::ProcessState::Ended
        )
    });
}

/// KR-REQ-12.02: a launcher that stops after it created its program and before the backend has
/// looked at it leaves no program suspended: the program ends with the launcher, whatever the
/// backend does or does not do next. The backend is held where it has been told the program's name
/// and not yet shown it, so nothing of the host can end the program for it. Control: the next case,
/// in which a launcher that is not stopped has its program started and that program outlives it.
#[test]
fn kr_req_12_02_a_launcher_gone_before_its_program_is_shown_leaves_no_suspended_program() {
    let shell = Shell::new();
    let answer = shell.establish();
    let (arrived, release) = shell.backends.pause_before_showing();
    let mut launcher = shell.launch(&answer, "unshown", &[]);
    shell
        .runtime
        .block_on(async { tokio::time::timeout(LIVENESS, arrived).await })
        .expect("the launch arrives before its program is shown")
        .expect("and waits there");
    // The program is the process of the shell's job that runs from the file the launcher was asked
    // to run, which is what it has created and named.
    let wanted = kr_worker::windows::file::object_of(
        &std::fs::File::open(&shell.executable).expect("the program's file opens"),
    )
    .expect("the program's file has an id");
    let program = shell
        .job
        .process_ids()
        .expect("the shell's job lists its processes")
        .into_iter()
        .find(|member| {
            kr_worker::windows::file::image_of(*member)
                .and_then(|image| {
                    kr_worker::windows::file::object_of(&image).map_err(|error| error.to_string())
                })
                .is_ok_and(|object| object == wanted)
        })
        .expect("the launcher has created its program, suspended, in the shell's job");
    let identity = kr_ipc::identity::process_start_identity(program).expect("an identity");
    launcher.kill().expect("the launcher is ended");
    let _ = launcher.wait();
    eventually(
        "the program nobody can start is ended with the launcher",
        || kr_ipc::identity::process_state(&identity) == kr_ipc::identity::ProcessState::Ended,
    );
    let _ = release.send(());
}

/// KR-REQ-12.02, the control of the case above: a program a launcher started is not ended with the
/// launcher. Once the worker has read that the launcher started the program, the launcher is ended
/// from outside, and the program, which waits for that, still writes what it was waiting to write.
/// The program is started after the launcher has let go of its job; a launcher that is gone before
/// it has said so is the worker's to answer by ending the program, which is not this case.
#[test]
fn kr_req_12_02_a_program_that_is_started_outlives_the_launcher_that_started_it() {
    let shell = Shell::new();
    let answer = shell.establish();
    let gone = shell.reports.join("launcher.gone");
    let survived = shell.reports.join("survived");
    let started = shell.backends.notify_when_started();
    let mut launcher = shell.launch(
        &answer,
        "outlives",
        &[
            ("AFTER_GONE", &gone.display().to_string()),
            ("AFTER_DONE", &survived.display().to_string()),
        ],
    );
    let report = shell.report_from("outlives", &mut launcher);
    assert_eq!(report["relaunch"], "true", "the launch was committed");
    // The launch is complete once the worker has read that the launcher started the program. A
    // launcher that is ended before it has said so is one whose program the worker ends, which is
    // another case; the program's report can come before the launcher's word, so it is waited for.
    shell
        .runtime
        .block_on(async { tokio::time::timeout(LIVENESS, started).await })
        .expect("the launcher says it started the program")
        .expect("and the worker reads it");
    launcher.kill().expect("the launcher is ended");
    let _ = launcher.wait();
    std::fs::write(&gone, b"gone").expect("the program is told the launcher is gone");
    eventually("the program wrote after the launcher was gone", || {
        survived.exists()
    });
}

/// KR-REQ-05.09: the hold on the file a launch hashed lasts to the commit and ends with it: the file
/// cannot be renamed while the launch is being committed, and can once it is, so a program that
/// updates itself while it runs is not held to its old file. Control: before the commit the rename
/// is refused with a sharing violation.
#[test]
fn kr_req_05_09_the_hold_on_a_launchs_file_ends_with_its_commit() {
    let shell = Shell::new();
    let answer = shell.establish();
    let moved = shell.executable.with_extension("moved");
    let (arrived, release) = shell.backends.pause_before_committing();
    let mut launcher = shell.launch(&answer, "held", &[]);
    shell
        .runtime
        .block_on(async { tokio::time::timeout(LIVENESS, arrived).await })
        .expect("the launch arrives at the commit")
        .expect("and waits there");
    let refused = std::fs::rename(&shell.executable, &moved)
        .expect_err("the file is held until the launch is committed");
    assert_eq!(
        refused.raw_os_error(),
        Some(32),
        "by a sharing violation: {refused}"
    );
    release.send(()).expect("the commit goes on");
    let report = shell.report_from("held", &mut launcher);
    assert_eq!(report["relaunch"], "true", "the launch was committed");
    std::fs::rename(&shell.executable, &moved).expect("the file is let go of with the commit");
    assert!(matches!(
        shell.state_of(Shell::instance_of(&answer)),
        Some(BackendState::Committed(_))
    ));
}

/// KR-REQ-12.02: a program that has run and ended before the worker has heard that the launcher
/// started it does not take what it started with it: the program's end retires its backend and ends
/// the worker's wait, and what the program started is still running. Here the test plays the
/// program: it puts a helper in the program's job and ends the program while the launcher holds it,
/// committed, before it starts it. Control: the same wait, with the launcher saying nothing,
/// ends at its deadline and ends the job (`kr_req_12_02_a_program_that_is_never_started_is_ended`).
#[test]
fn kr_req_12_02_a_program_that_ends_before_the_launcher_is_heard_leaves_what_it_started() {
    let shell = Shell::new();
    let answer = shell.establish();
    *shell.barrier.lock().expect("the barrier") = Some(shell.reports.join("barrier"));
    let launcher = shell.launch(&answer, "heard", &[]);
    eventually("the launch is committed", || {
        std::fs::read_to_string(Shell::registration(&answer)).is_ok()
            && matches!(
                shell.state_of(Shell::instance_of(&answer)),
                Some(BackendState::Committed(_))
            )
    });
    let instance = Shell::instance_of(&answer);
    let program: u32 = Shell::registered(&answer)["pid"]
        .parse()
        .expect("a process identifier");
    let identity = kr_ipc::identity::process_start_identity(program).expect("the program");
    let job = kr_worker::windows::job::agent_job(&identity).expect("the program's job");
    let mut helper = std::process::Command::new(system_program("ping.exe"))
        .args(["-n", "600", "127.0.0.1"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the helper starts");
    job.assign(helper.id())
        .expect("the helper joins the program's job");
    let ended = std::process::Command::new(system_program("taskkill.exe"))
        .args(["/F", "/PID", &program.to_string()])
        .output()
        .expect("taskkill runs");
    assert!(ended.status.success(), "the program is ended");
    eventually("the backend retires with the program's end", || {
        !matches!(shell.state_of(instance), Some(BackendState::Committed(_)))
    });
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        helper.try_wait().expect("the helper is asked").is_none(),
        "what the program started is still running"
    );
    let _ = helper.kill();
    let _ = helper.wait();
    drop(launcher);
}

/// KR-REQ-12.02: a program that was committed and never started is ended with everything in its job
/// when the launcher says nothing within its deadline, and its instance ends with it.
#[test]
fn kr_req_12_02_a_program_that_is_never_started_is_ended() {
    let shell = Shell::new();
    let answer = shell.establish();
    let mut scripted = shell.admitted_launcher(&answer);
    let program = scripted.create(&shell.executable, &shell.typed()[1..]);
    let identity = kr_ipc::identity::process_start_identity(program).expect("an identity");
    scripted.write(&Shell::going(program));
    let committed = scripted.read();
    assert!(
        committed
            .as_deref()
            .is_some_and(|line| line.contains("\"committed\":true"))
    );
    let instance = Shell::instance_of(&answer);
    assert!(matches!(
        shell.state_of(instance),
        Some(BackendState::Committed(_))
    ));
    // The launcher goes quiet and keeps the connection open: the program is ended by the backend.
    eventually("the program that never started is ended", || {
        matches!(
            kr_ipc::identity::process_state(&identity),
            kr_ipc::identity::ProcessState::Ended
        )
    });
    eventually("and its instance ends with it", || {
        !matches!(
            shell.state_of(instance),
            Some(BackendState::Committed(_) | BackendState::Launching)
        )
    });
    drop(scripted);
}

/// Turns an empty directory into a junction to `target` in place, as a principal that may write to
/// the directory can whatever is held on it: the conversion changes what the path reaches and not
/// the object a handle holds.
#[expect(
    unsafe_code,
    reason = "setting a reparse point is a device control with a buffer only the caller can lay out"
)]
fn convert_to_a_junction(directory: &Path, target: &Path) {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_WRITE_ATTRIBUTES,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
    let opened = std::fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .share_mode(7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory)
        .expect("the directory opens for its attributes");
    let substitute: Vec<u16> = std::ffi::OsString::from(format!(r"\??\{}", target.display()))
        .encode_wide()
        .collect();
    let printed: Vec<u16> = target.as_os_str().encode_wide().collect();
    let substitute_bytes = u16::try_from(substitute.len() * 2).expect("short");
    let printed_bytes = u16::try_from(printed.len() * 2).expect("short");
    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend(IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    let data_length = 8 + usize::from(substitute_bytes) + 2 + usize::from(printed_bytes) + 2;
    buffer.extend(u16::try_from(data_length).expect("short").to_le_bytes());
    buffer.extend(0_u16.to_le_bytes());
    buffer.extend(0_u16.to_le_bytes());
    buffer.extend(substitute_bytes.to_le_bytes());
    buffer.extend((substitute_bytes + 2).to_le_bytes());
    buffer.extend(printed_bytes.to_le_bytes());
    for unit in &substitute {
        buffer.extend(unit.to_le_bytes());
    }
    buffer.extend(0_u16.to_le_bytes());
    for unit in &printed {
        buffer.extend(unit.to_le_bytes());
    }
    buffer.extend(0_u16.to_le_bytes());
    let mut returned = 0_u32;
    // SAFETY: the handle is open for the call, the buffer is a local laid out as the control
    // documents, and the count is another local.
    let set = unsafe {
        DeviceIoControl(
            opened.as_raw_handle().cast(),
            FSCTL_SET_REPARSE_POINT,
            buffer.as_ptr().cast(),
            u32::try_from(buffer.len()).expect("short"),
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(
        set,
        0,
        "the directory becomes a junction: {}",
        std::io::Error::last_os_error()
    );
}

/// What a failed rename of a path says when the path is held: a sharing violation.
fn held(result: std::io::Result<()>) -> bool {
    result.is_err_and(|error| error.raw_os_error() == Some(32))
}

/// A directory three levels down in the tree, so that its ancestors can be renamed too.
fn nested(shell: &Shell, name: &str) -> PathBuf {
    let directory = shell.placed.host.root().join(name).join("b").join("work");
    std::fs::create_dir_all(&directory).expect("a nested directory");
    directory
}

/// KR-REQ-12.16: a launch is granted the directory its program inherits, which was held from the
/// drive's root when the backend was established: nothing can rename, replace or delete it or its
/// ancestors while the program runs, and the hold is let go of when the program ends. Control: once
/// it has, the same directory renames.
#[test]
fn kr_req_12_16_a_launch_is_granted_the_directory_the_program_inherits_and_it_is_held() {
    let shell = Shell::reading();
    let work = nested(&shell, "grant");
    let answer = shell.establish_in(&work);
    let mut launcher = shell.launcher(
        &shell.executable.clone(),
        &shell.typed(),
        &answer,
        "granted",
        &[],
        &work,
    );
    let report = shell.report_from("granted", &mut launcher);
    assert_eq!(report["relaunch"], "true", "committed");
    let instance = Shell::instance_of(&answer);
    assert!(
        shell.broker.host_files(instance).is_some(),
        "the directory is granted"
    );
    let ancestor = work
        .parent()
        .expect("b")
        .parent()
        .expect("grant")
        .to_path_buf();
    assert!(
        held(std::fs::rename(&work, ancestor.join("moved"))),
        "the directory cannot be renamed while the program runs"
    );
    assert!(
        held(std::fs::rename(
            &ancestor,
            ancestor.with_file_name("grant-moved")
        )),
        "nor can an ancestor"
    );
    assert!(held(std::fs::remove_dir(&work)), "nor deleted");
    // The program ends, and the backend with it: the hold is let go of once the line is over, which
    // is when the shell's command block finishes and the backend is forgotten.
    shell.job.terminate(1).expect("the job ends");
    eventually("the backend retires with its program", || {
        matches!(shell.state_of(instance), Some(BackendState::Retired))
    });
    shell.backends.line_ended(shell.last_generation());
    let ended = Instant::now();
    let moved = loop {
        match std::fs::rename(&work, ancestor.join("moved")) {
            Ok(()) => break Ok(()),
            Err(error) if ended.elapsed() >= LIVENESS => break Err(error),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    assert!(
        moved.is_ok(),
        "the directory is let go of once the program has ended: {moved:?}"
    );
}

/// KR-REQ-12.16: a launcher started in another directory than the one the shell reported grants
/// nothing. Control: the directory it was reported in is granted.
#[test]
fn kr_req_12_16_a_launcher_started_in_another_directory_grants_nothing() {
    let shell = Shell::reading();
    let work = nested(&shell, "reported");
    let elsewhere = nested(&shell, "elsewhere");
    let answer = shell.establish_in(&work);
    let mut launcher = shell.launcher(
        &shell.executable.clone(),
        &shell.typed(),
        &answer,
        "elsewhere",
        &[],
        &elsewhere,
    );
    let report = shell.report_from("elsewhere", &mut launcher);
    assert_eq!(report["relaunch"], "true", "the launch itself goes through");
    let instance = Shell::instance_of(&answer);
    assert!(
        shell.broker.host_files(instance).is_none(),
        "and the directory is not granted"
    );
    let same = shell.establish_in(&work);
    let mut again = shell.launcher(
        &shell.executable.clone(),
        &shell.typed(),
        &same,
        "same",
        &[],
        &work,
    );
    shell.report_from("same", &mut again);
    assert!(shell.broker.host_files(Shell::instance_of(&same)).is_some());
}

/// KR-REQ-12.16: a directory converted to a junction after the launcher's path was held and before
/// the commit is granted nothing: the commit reads the held directory's attributes again. The
/// conversion is what a principal that may write to an empty directory can make whatever is held.
#[test]
fn kr_req_12_16_a_directory_converted_to_a_link_before_the_commit_grants_nothing() {
    let shell = Shell::reading();
    let work = nested(&shell, "converted");
    let target = nested(&shell, "target");
    let answer = shell.establish_in(&work);
    let (arrived, release) = shell.backends.pause_before_committing();
    let mut launcher = shell.launcher(
        &shell.executable.clone(),
        &shell.typed(),
        &answer,
        "converted",
        &[],
        &work,
    );
    shell
        .runtime
        .block_on(async { tokio::time::timeout(LIVENESS, arrived).await })
        .expect("the launch arrives at the commit")
        .expect("and waits there");
    let instance = Shell::instance_of(&answer);
    assert!(
        shell.broker.host_files(instance).is_some(),
        "the directory was granted when its path was walked"
    );
    convert_to_a_junction(&work, &target);
    release.send(()).expect("the commit goes on");
    let report = shell.report_from("converted", &mut launcher);
    assert_eq!(report["relaunch"], "true", "the launch itself goes through");
    assert!(
        shell.broker.host_files(instance).is_none(),
        "and the grant was withdrawn at the commit"
    );
}

/// KR-REQ-12.02: a launch of a program as large as the largest agent, written new and so not yet
/// seen by the system, is committed within the launcher's deadlines and the worker's, which are
/// measured together here: the backend hashes 300 MB while the launcher waits, the program is
/// created from the file the worker holds, and the commit follows. The time each step takes is
/// printed, so the evidence names what the deadlines were set against. Control: the launch of a
/// small file is committed by the same run.
#[test]
fn kr_req_12_02_a_cold_copy_of_the_largest_agent_is_launched_within_the_deadlines() {
    let shell = Shell::large(300 * 1024 * 1024);
    let answer = shell.establish();
    let started = Instant::now();
    let mut launcher = shell.launch(&answer, "cold", &[]);
    let report = shell.report_from("cold", &mut launcher);
    let program_ran = started.elapsed();
    assert_eq!(
        report["relaunch"], "true",
        "the launch was committed and not run as typed: {report:?}"
    );
    eprintln!("cold 300 MB launch: the program ran {program_ran:?} after the launcher started");
    // One placed program is held at a time, so the cold copy is let go of before the control's.
    drop(shell);
    let small = Shell::new();
    let answer = small.establish();
    let started = Instant::now();
    let mut launcher = small.launch(&answer, "warm", &[]);
    let report = small.report_from("warm", &mut launcher);
    assert_eq!(report["relaunch"], "true");
    eprintln!(
        "small launch: the program ran {:?} after the launcher started",
        started.elapsed()
    );
}
