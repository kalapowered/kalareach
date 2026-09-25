//! `kr-hook launch`, against the worker's own command backends.
//!
//! This test process plays the root shell: it establishes a backend the way the session does when
//! the shell asks to resolve an integrated invocation, and starts the launcher as its own child,
//! as the shell's executor does, with the answer's variable in that child only. The program is the
//! system's bash, reached through a link named `claude` as an installed agent often is, running a
//! short script that writes down what it found the moment it started: the registration, the
//! variable and its argument vector. It is bash itself rather than a copy, because macOS stops a
//! copy of a system program from running, and rather than `/bin/sh`, which on macOS starts another
//! shell in its place.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.07 | the backend and its registration exist before the program runs; a refused, timed-out, uncommitted or orphaned invocation runs as typed |
//! | KR-REQ-05.09 | a launch is admitted by the kernel's account of its process, its parent and its start, and the backend's credential; the program's bridges only when it executes what was hashed |
//! | KR-REQ-11.34 | the launched program's hooks are admitted against the registration the launch published |

#![cfg(unix)]

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
use kr_protocol::session::EnvironmentVariable;
use kr_worker::broker::Broker;
use kr_worker::broker::commands::{CommandBackends, CommandBackendsConfig, EstablishRequest};
use kr_worker::broker::connectors::{ConnectorSources, fixture};
use kr_worker::persistence::JournalHealth;

/// What the program writes the moment it starts, and whether it runs a hook.
const SCRIPT: &str = r#"report="$REPORT"
{
  echo "pid=$$"
  if [ -n "$KR_REGISTRATION" ] && [ -f "$KR_REGISTRATION" ]; then
    echo "registered=yes"
    sed 's/^/registration./' "$KR_REGISTRATION"
  else
    echo "registered=no"
  fi
  echo "variable=${KR_REGISTRATION:-none}"
  echo "args=$0|$*"
} > "$report.part" && mv "$report.part" "$report"
if [ -n "$HOOK" ]; then
  if [ -n "$WAIT_FOR" ]; then while [ ! -f "$WAIT_FOR" ]; do sleep 0.02; done; fi
  printf '%s' "$HOOK_EVENT" | "$HOOK" claude-code hook > "$report.hook" 2>&1
  echo done > "$report.hooked"
  if [ -n "$THEN_EXEC" ]; then
    exec "$THEN_EXEC" -c 'printf "%s" "$HOOK_EVENT_2" | "$HOOK" claude-code hook > "$REPORT.hook2" 2>&1; echo done > "$REPORT.hooked2"; sleep 1; exit 0'
  fi
fi
sleep "${LINGER:-0}"
exit 0
"#;

/// A hook's report that a session started, which selects its thread.
const SESSION_START: &str = r#"{"session_id":"4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11","transcript_path":"/tmp/t.jsonl","cwd":"/tmp","hook_event_name":"SessionStart","source":"startup"}"#;

/// The thread that report selects.
const THREAD: &str = "4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11";

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn words(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

/// The program every case runs, and another program that is not it.
fn shells() -> (&'static Path, &'static Path) {
    let bash = Path::new("/bin/bash");
    let another = ["/bin/dash", "/usr/bin/dash", "/bin/zsh", "/usr/bin/zsh"]
        .into_iter()
        .map(Path::new)
        .find(|candidate| {
            std::fs::metadata(candidate).is_ok_and(|metadata| {
                use std::os::unix::fs::MetadataExt as _;
                let bash = std::fs::metadata(bash).expect("bash");
                (metadata.dev(), metadata.ino()) != (bash.dev(), bash.ino())
            })
        })
        .expect("a second shell");
    (bash, another)
}

/// Points `link` at `target` in one step, as an upgrade that replaces a link does.
fn retarget(link: &Path, target: &Path) {
    let staged = link.with_extension("next");
    let _ = std::fs::remove_file(&staged);
    std::os::unix::fs::symlink(target, &staged).expect("the new link");
    std::fs::rename(&staged, link).expect("the link is replaced");
}

/// A POSIX shell running `script`, with nothing of a surrounding session in its environment.
fn sh(script: &str) -> std::process::Command {
    let mut command = std::process::Command::new("/bin/sh");
    command.arg("-c").arg(script);
    for variable in common::FORWARDER_VARIABLES {
        command.env_remove(variable);
    }
    command
}

/// Waits until a process is stopped.
fn wait_stopped(pid: u32) {
    eventually("the process stopped itself", || {
        std::process::Command::new("ps")
            .args(["-o", "state=", "-p", &pid.to_string()])
            .output()
            .is_ok_and(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .trim_start()
                    .starts_with('T')
            })
    });
}

/// The instance a program's report names.
fn instance_of(report: &BTreeMap<String, String>) -> ApplicationInstanceId {
    report["registration.instance"]
        .parse()
        .expect("the registration names an instance")
}

/// This test process, the root shell of every launch it starts.
struct Shell {
    placed: Placed,
    runtime: tokio::runtime::Runtime,
    broker: Arc<Broker>,
    backends: CommandBackends,
    executable: PathBuf,
    other: PathBuf,
    reports: PathBuf,
    generation: std::sync::atomic::AtomicU64,
}

impl Shell {
    fn new() -> Self {
        let placed = Placed::new();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        let bin = placed.host.root().join("bin");
        let executable = bin.join("claude");
        let other = bin.join("other");
        let (program, another) = shells();
        std::os::unix::fs::symlink(program, &executable).expect("the program stands in");
        std::os::unix::fs::symlink(another, &other).expect("another program");
        let store = placed.host.root().join("store");
        std::fs::create_dir_all(&store).expect("a store");
        let sources = Arc::new(ConnectorSources::new());
        let source = fixture::claude_code_package(&store, &placed.forwarder)
            .expect("the package is written");
        assert!(sources.replace(vec![source]).is_empty());
        let broker = Arc::new(
            Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens"),
        );
        // The host tree itself, so a backend's socket path stays inside the bound it has on macOS.
        let runtime_dir = placed.host.root().to_path_buf();
        let backends = CommandBackends::new(
            Arc::clone(&broker),
            CommandBackendsConfig {
                session_id: session(),
                environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
                os_user: "someone".to_owned(),
                runtime_dir,
                sources,
                launcher: Some(placed.forwarder.clone()),
            },
            runtime.handle().clone(),
        );
        let reports = placed.host.root().join("reports");
        std::fs::create_dir_all(&reports).expect("a directory for reports");
        Self {
            placed,
            runtime,
            broker,
            backends,
            executable,
            other,
            reports,
            generation: std::sync::atomic::AtomicU64::new(1),
        }
    }

    fn integration() -> CommandIntegration {
        CommandIntegration {
            command: fixture::COMMAND.to_owned(),
            flags: words(&fixture::FLAGS),
            enabled: true,
        }
    }

    /// The typed vector every case runs: the program's name and its script.
    fn typed() -> Vec<String> {
        vec!["claude".to_owned(), "-c".to_owned(), SCRIPT.to_owned()]
    }

    /// The answered vector: the typed one with the integration's flags added.
    fn answered() -> Vec<String> {
        Self::answered_for(&Self::typed())
    }

    fn answered_for(typed: &[String]) -> Vec<String> {
        let mut answered = typed.to_vec();
        answered.extend(words(&fixture::FLAGS));
        answered
    }

    /// Establishes a backend for the next line, as the session does for an integrated resolve.
    fn establish(&self) -> CommandBackend {
        self.establish_for(&self.executable)
    }

    fn establish_for(&self, executable: &Path) -> CommandBackend {
        self.establish_with(executable, &Self::typed())
    }

    fn establish_with(&self, executable: &Path, typed: &[String]) -> CommandBackend {
        let generation = self
            .generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let integration = Self::integration();
        let typed = typed.to_vec();
        let answered = Self::answered_for(&typed);
        let added = words(&fixture::FLAGS);
        let _entered = self.runtime.enter();
        self.backends
            .establish(&EstablishRequest {
                prompt_generation: PromptGeneration::new(generation),
                typed: &typed,
                arguments: &answered,
                added: &added,
                integration: &integration,
                executable: executable.to_str().expect("a text path"),
                cwd: self.placed.host.root().to_str().expect("a text path"),
                cwd_revision: CwdRevision::new(1),
                root_shell: kr_ipc::identity::current_process_start_identity()
                    .expect("this process"),
            })
            .expect("a backend is established")
    }

    /// The launcher's command line for an answer: `launch -- <executable> <vector>`.
    fn launcher(
        &self,
        executable: &Path,
        vector: &[String],
        hold: Option<u64>,
    ) -> std::process::Command {
        let mut arguments = vec!["launch".to_owned()];
        if let Some(hold) = hold {
            arguments.push("--hold-after-admission".to_owned());
            arguments.push(hold.to_string());
        }
        arguments.push("--".to_owned());
        arguments.push(executable.display().to_string());
        arguments.extend(vector.iter().cloned());
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        self.placed.command(&arguments)
    }

    /// Starts the launcher for an answer, with its variable, writing its report under `name`.
    fn launch(
        &self,
        answer: &CommandBackend,
        name: &str,
        env: &[(&str, &str)],
    ) -> std::process::Child {
        let mut command = self.launcher(&self.executable, &Self::answered(), None);
        self.prepare(&mut command, Some(answer), name, env);
        command.spawn().expect("the launcher starts")
    }

    fn prepare(
        &self,
        command: &mut std::process::Command,
        answer: Option<&CommandBackend>,
        name: &str,
        env: &[(&str, &str)],
    ) {
        if let Some(answer) = answer {
            for variable in &answer.environment {
                command.env(&variable.name, &variable.value);
            }
        }
        command
            .env("REPORT", self.reports.join(name))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        for (name, value) in env {
            command.env(name, value);
        }
    }

    /// Waits for the report the program writes when it starts.
    fn report(&self, name: &str) -> BTreeMap<String, String> {
        let path = self.reports.join(name);
        let started = Instant::now();
        loop {
            if let Ok(text) = std::fs::read_to_string(&path) {
                return text
                    .lines()
                    .filter_map(|line| line.split_once('='))
                    .map(|(name, value)| (name.to_owned(), value.to_owned()))
                    .collect();
            }
            assert!(started.elapsed() < LIVENESS, "the program reported by now");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn registration(answer: &CommandBackend) -> PathBuf {
        PathBuf::from(&answer.environment[0].value)
    }

    fn directory(answer: &CommandBackend) -> PathBuf {
        Self::registration(answer)
            .parent()
            .expect("the backend's directory")
            .to_path_buf()
    }

    /// The instance a published registration names.
    fn registered_instance(answer: &CommandBackend) -> ApplicationInstanceId {
        std::fs::read_to_string(Self::registration(answer))
            .expect("the registration")
            .lines()
            .find_map(|line| line.strip_prefix("instance="))
            .expect("it names an instance")
            .parse()
            .expect("an instance")
    }
}

impl Drop for Shell {
    fn drop(&mut self) {
        self.backends.close();
    }
}

/// Waits for a process to end, within the liveness bound.
fn finish(mut child: std::process::Child) -> (std::process::ExitStatus, String) {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("readable") {
            let mut said = String::new();
            if let Some(stderr) = child.stderr.as_mut() {
                let _ = std::io::Read::read_to_string(stderr, &mut said);
            }
            return (status, said);
        }
        if started.elapsed() > LIVENESS {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the launch did not finish");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Waits for a condition, within the liveness bound.
fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(started.elapsed() < LIVENESS, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A report of a program that ran as typed: no registration, no variable, no added flag.
fn assert_typed(report: &BTreeMap<String, String>, what: &str) {
    assert_eq!(report["registered"], "no", "{what}: no registration");
    assert_eq!(report["variable"], "none", "{what}: no variable");
    assert!(
        !report["args"].contains("--dangerously-load-development-channels"),
        "{what}: the added flags were taken out: {}",
        report["args"]
    );
}

/// KR-REQ-12.07, KR-REQ-05.09: the root shell's own child, started after the establish, with the
/// backend's credential and the answered invocation, is admitted, and its registration exists
/// when the program first runs and names the program. When the program ends, so do the instance,
/// the endpoint, the credential, the registration and the launch record.
#[test]
fn kr_req_12_07_a_launch_is_published_before_the_program_runs() {
    let shell = Shell::new();
    let answer = shell.establish();
    let directory = Shell::directory(&answer);
    let registration = Shell::registration(&answer);
    let child = shell.launch(&answer, "first", &[("LINGER", "1")]);
    let report = shell.report("first");
    assert_eq!(
        report["registered"], "yes",
        "the registration was there first"
    );
    assert_eq!(
        report["registration.pid"], report["pid"],
        "and it names the program, which kept the launcher's process"
    );
    assert_eq!(report["variable"], answer.environment[0].value);
    assert!(
        report["args"].contains(
            "--dangerously-load-development-channels|plugin:kalareach-channels@skills-dir"
        ),
        "the program runs the answered vector: {}",
        report["args"]
    );
    let instance = instance_of(&report);
    assert_eq!(
        shell
            .broker
            .binding_state(instance)
            .expect("the launched instance is live")
            .mode,
        kr_protocol::broker::IntegrationMode::NativeBridge
    );
    assert!(
        shell.broker.profile_of(instance).is_some(),
        "its profile was recorded when it presented itself"
    );
    let (status, said) = finish(child);
    assert!(status.success(), "{said}");
    eventually("the instance ends with its program", || {
        shell.broker.binding_state(instance).is_err()
    });
    eventually(
        "its endpoint, credential, registration and record go",
        || {
            !directory.join("credential").exists()
                && !registration.exists()
                && !directory.join("launch").exists()
        },
    );
}

/// KR-REQ-05.09, KR-REQ-12.07: a launch the backend refuses runs as typed, without the flags and
/// without the variable, whichever check refused it.
#[test]
fn kr_req_05_09_a_refused_launch_runs_the_invocation_as_typed() {
    let shell = Shell::new();
    let launch_line = r#""$LAUNCHER" launch -- "$PROGRAM" claude -c "$SCRIPT" "$FLAG" "$VALUE""#;
    let with_launch = |command: &mut std::process::Command| {
        command
            .env("LAUNCHER", &shell.placed.forwarder)
            .env("PROGRAM", &shell.executable)
            .env("SCRIPT", SCRIPT)
            .env("FLAG", fixture::FLAGS[0])
            .env("VALUE", fixture::FLAGS[1]);
    };

    // Not the root shell's own child: a process the child started.
    let answer = shell.establish();
    let mut nested = sh(&format!("{launch_line}; true"));
    shell.prepare(&mut nested, Some(&answer), "nested", &[]);
    with_launch(&mut nested);
    let _ = finish(nested.spawn().expect("the nested launch starts"));
    assert_typed(
        &shell.report("nested"),
        "a process the root shell's child started",
    );

    // The root shell's own child, but one that started before the backend was established.
    let go = shell.placed.host.root().join("go");
    let mut older = sh(&format!(
        r#"while [ ! -f "$GO" ]; do sleep 0.02; done; export KR_REGISTRATION="$(cat "$GO")"; exec {launch_line}"#
    ));
    shell.prepare(&mut older, None, "older", &[]);
    with_launch(&mut older);
    older.env("GO", &go);
    let waiting = older.spawn().expect("an older child starts");
    std::thread::sleep(Duration::from_millis(50));
    let answer = shell.establish();
    std::fs::write(&go, &answer.environment[0].value).expect("the path is handed over");
    let _ = finish(waiting);
    let report = shell.report("older");
    assert_typed(&report, "a child older than the backend");

    // The wrong credential.
    let answer = shell.establish();
    std::fs::write(
        Shell::directory(&answer).join("credential"),
        "05".repeat(32),
    )
    .expect("the credential is replaced");
    let _ = finish(shell.launch(&answer, "credential", &[]));
    assert_typed(&shell.report("credential"), "another credential");

    // Another executable than the one the backend was established for.
    let answer = shell.establish();
    let mut foreign = shell.launcher(&shell.other, &Shell::answered(), None);
    shell.prepare(&mut foreign, Some(&answer), "foreign", &[]);
    let _ = finish(foreign.spawn().expect("the launcher starts"));
    assert_typed(&shell.report("foreign"), "another executable");

    // Another argument vector than the one the backend answered.
    let answer = shell.establish();
    let mut extended = Shell::answered();
    extended.push("more".to_owned());
    let mut arguments = shell.launcher(&shell.executable, &extended, None);
    shell.prepare(&mut arguments, Some(&answer), "arguments", &[]);
    let _ = finish(arguments.spawn().expect("the launcher starts"));
    assert_typed(&shell.report("arguments"), "another vector");

    // An executable that is a script.
    let script = shell.placed.host.root().join("bin").join("script");
    std::fs::write(&script, "#!/bin/sh\nexec /bin/sh \"$@\"\n").expect("a script");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("executable");
    }
    let answer = shell.establish_for(&script);
    let mut scripted = shell.launcher(&script, &Shell::answered(), None);
    shell.prepare(&mut scripted, Some(&answer), "script", &[]);
    let _ = finish(scripted.spawn().expect("the launcher starts"));
    assert_typed(&shell.report("script"), "a script");
}

/// KR-REQ-12.07: a backend that does not answer within the launcher's two seconds: the program runs
/// as typed, without the flags and without the variable.
#[test]
fn kr_req_12_07_a_backend_that_does_not_answer_leaves_the_invocation_as_typed() {
    let shell = Shell::new();
    let quiet = private(&shell, "q");
    let endpoint = quiet.join("e.sock");
    // Listening, so the launcher connects, and never accepting, so nothing answers it.
    let listener = std::os::unix::net::UnixListener::bind(&endpoint).expect("a quiet endpoint");
    let answer = hand_made_backend(&shell, &quiet, &endpoint);
    let started = Instant::now();
    let (_, said) = finish(shell.launch(&answer, "quiet", &[]));
    assert!(
        started.elapsed() >= kr_hook::launch::ADMISSION_DEADLINE,
        "it waited for its deadline: {said}"
    );
    assert_typed(&shell.report("quiet"), "a backend that does not answer");
    drop(listener);
}

/// KR-REQ-12.07: a launcher that goes away after its admission and before it says it is going
/// leaves nothing: the registration is taken back and the instance given back, and a retry of the
/// same invocation is admitted.
#[test]
fn kr_req_12_07_a_launch_that_never_goes_is_rolled_back() {
    let shell = Shell::new();
    let answer = shell.establish();
    let registration = Shell::registration(&answer);
    let mut held = shell.launcher(&shell.executable, &Shell::answered(), Some(20_000));
    shell.prepare(&mut held, Some(&answer), "held", &[]);
    let mut held = held.spawn().expect("the launcher starts");
    eventually("the registration is published on the admission", || {
        registration.exists()
    });
    let _ = held.kill();
    let _ = held.wait();
    eventually("and taken back when the launch does not go", || {
        !registration.exists()
    });

    let child = shell.launch(&answer, "retry", &[]);
    let report = shell.report("retry");
    assert_eq!(report["registered"], "yes", "the retry is admitted");
    let _ = finish(child);
}

/// KR-REQ-12.07: a launcher stopped before it looked, whose line then ended, still runs the
/// invocation as typed when it is resumed: what was typed is in its variable's file name.
#[test]
fn kr_req_12_07_a_launcher_resumed_after_its_line_ended_runs_as_typed() {
    let shell = Shell::new();
    let answer = shell.establish();
    let mut stopped = sh(
        r#"kill -STOP $$; exec "$LAUNCHER" launch -- "$PROGRAM" claude -c "$SCRIPT" "$FLAG" "$VALUE""#,
    );
    shell.prepare(&mut stopped, Some(&answer), "resumed", &[]);
    stopped
        .env("LAUNCHER", &shell.placed.forwarder)
        .env("PROGRAM", &shell.executable)
        .env("SCRIPT", SCRIPT)
        .env("FLAG", fixture::FLAGS[0])
        .env("VALUE", fixture::FLAGS[1]);
    let child = stopped.spawn().expect("the shell starts");
    wait_stopped(child.id());
    shell.backends.line_ended(answer.prompt_generation);
    let resumed = std::process::Command::new("kill")
        .arg("-CONT")
        .arg(child.id().to_string())
        .status()
        .expect("the launcher is resumed");
    assert!(resumed.success());
    let _ = finish(child);
    assert_typed(
        &shell.report("resumed"),
        "a launcher resumed after its line ended",
    );
}

/// Waits until the program's hook has run and its report was applied or refused.
fn hooked(shell: &Shell, name: &str) {
    eventually("the program's hook has run", || {
        shell.reports.join(format!("{name}.hooked")).exists()
    });
}

/// The thread one instance has selected, where it has one.
fn selected(shell: &Shell, instance: ApplicationInstanceId) -> Option<String> {
    shell
        .broker
        .binding_state(instance)
        .ok()
        .and_then(|state| state.thread_id.0.map(|thread| thread.to_string()))
}

/// KR-REQ-11.34, KR-REQ-05.09: the program's own hook is admitted against the registration its
/// launch published, and its report selects the thread. A program replaced between its admission
/// and its exec, whose path is put back before its first hook, has every bridge refused: the
/// kernel's record of what the process runs decides, not the path.
#[test]
fn kr_req_11_34_the_launched_program_s_hook_moves_the_binding_and_a_replaced_one_is_refused() {
    let shell = Shell::new();
    let hook = shell.placed.forwarder.display().to_string();
    let answer = shell.establish();
    let child = shell.launch(
        &answer,
        "hooked",
        &[
            ("HOOK", hook.as_str()),
            ("HOOK_EVENT", SESSION_START),
            ("LINGER", "3"),
        ],
    );
    let instance = instance_of(&shell.report("hooked"));
    hooked(&shell, "hooked");
    eventually("the hook's report selects the thread", || {
        selected(&shell, instance).as_deref() == Some(THREAD)
    });
    let _ = finish(child);

    // Replaced while the launcher holds after its admission, and put back once it runs.
    let (program, another) = shells();
    let swapped = shell.placed.host.root().join("bin").join("swapped");
    std::os::unix::fs::symlink(program, &swapped).expect("the program");
    let answer = shell.establish_for(&swapped);
    let go = shell.placed.host.root().join("go-swapped");
    let go_text = go.display().to_string();
    let mut held = shell.launcher(&swapped, &Shell::answered(), Some(1000));
    shell.prepare(
        &mut held,
        Some(&answer),
        "swapped",
        &[
            ("HOOK", hook.as_str()),
            ("HOOK_EVENT", SESSION_START),
            ("WAIT_FOR", go_text.as_str()),
            ("LINGER", "2"),
        ],
    );
    let held = held.spawn().expect("the launcher starts");
    let registration = Shell::registration(&answer);
    eventually("the launch is admitted", || registration.exists());
    retarget(&swapped, another);
    let report = shell.report("swapped");
    assert_eq!(report["registered"], "yes", "the launch went ahead");
    retarget(&swapped, program);
    std::fs::write(&go, "").expect("the hook may run");
    let instance = instance_of(&report);
    hooked(&shell, "swapped");
    assert_eq!(
        selected(&shell, instance),
        None,
        "the hook of a program that is not the one hashed moves nothing"
    );
    let _ = finish(held);
}

/// KR-REQ-05.09: a connection that says nothing holds only its own admission: the program's hook
/// is admitted meanwhile. Beyond the bound a connection is closed unread.
#[test]
fn kr_req_05_09_admissions_run_beside_each_other_up_to_their_bound() {
    let shell = Shell::new();
    let hook = shell.placed.forwarder.display().to_string();
    let endpoint_of = |answer: &CommandBackend| {
        let record: serde_json::Value = serde_json::from_slice(
            &std::fs::read(Shell::directory(answer).join("launch")).expect("the record"),
        )
        .expect("JSON");
        PathBuf::from(record["endpoint"].as_str().expect("an endpoint"))
    };
    let answer = shell.establish();
    let silent =
        std::os::unix::net::UnixStream::connect(endpoint_of(&answer)).expect("a silent connection");
    let child = shell.launch(
        &answer,
        "beside",
        &[
            ("HOOK", hook.as_str()),
            ("HOOK_EVENT", SESSION_START),
            ("LINGER", "2"),
        ],
    );
    let instance = instance_of(&shell.report("beside"));
    hooked(&shell, "beside");
    assert_eq!(
        selected(&shell, instance).as_deref(),
        Some(THREAD),
        "the hook was admitted while the silent connection waited"
    );
    let _ = finish(child);
    drop(silent);

    let answer = shell.establish();
    let endpoint = endpoint_of(&answer);
    let held: Vec<_> = (0..kr_worker::broker::commands::MAX_CONCURRENT_ADMISSIONS)
        .map(|_| std::os::unix::net::UnixStream::connect(&endpoint).expect("a connection"))
        .collect();
    std::thread::sleep(Duration::from_millis(200));
    let beyond = std::os::unix::net::UnixStream::connect(&endpoint).expect("one more");
    beyond
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bounded");
    let mut byte = [0_u8; 1];
    let read = std::io::Read::read(&mut &beyond, &mut byte);
    assert!(
        matches!(read, Ok(0)),
        "the connection beyond the bound is closed unread, well before a first frame is due: \
         {read:?}"
    );
    drop(held);
}

/// A backend directory made by hand around `endpoint`: its credential, its launch record, and an
/// answer naming a registration whose file name places the two added flags after the typed vector.
fn hand_made_backend(shell: &Shell, directory: &Path, endpoint: &Path) -> CommandBackend {
    hand_made_backend_at(shell, directory, endpoint, Shell::typed().len())
}

/// The same, for a typed vector of `typed` arguments.
fn hand_made_backend_at(
    shell: &Shell,
    directory: &Path,
    endpoint: &Path,
    typed: usize,
) -> CommandBackend {
    kr_ipc::paths::create_new_owner_only_file(
        &directory.join("credential"),
        "09".repeat(32).as_bytes(),
    )
    .expect("a credential");
    let record = serde_json::json!({
        "endpoint": endpoint.display().to_string(),
        "credential": directory.join("credential").display().to_string(),
    });
    kr_ipc::paths::write_owner_only_file(&directory.join("launch"), record.to_string().as_bytes())
        .expect("a launch record");
    CommandBackend {
        session_id: session(),
        prompt_generation: PromptGeneration::new(1),
        environment: vec![EnvironmentVariable {
            name: "KR_REGISTRATION".to_owned(),
            value: directory
                .join(format!("registration.{typed}.2"))
                .display()
                .to_string(),
        }],
        launcher: shell.placed.forwarder.display().to_string(),
    }
}

/// A private directory for a backend made by hand.
fn private(shell: &Shell, name: &str) -> PathBuf {
    let directory = shell.placed.host.root().join(name);
    std::fs::create_dir_all(&directory).expect("a directory");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("private");
    }
    directory
}

/// KR-REQ-12.07: the session closed after the launch was admitted and before it went: the
/// admission ends with the backend at once, its guard giving the instance back, and the launcher,
/// which is never told its launch is committed, runs what was typed.
#[test]
fn kr_req_12_07_a_launch_whose_session_closed_before_it_went_runs_as_typed() {
    let shell = Shell::new();
    let answer = shell.establish();
    let registration = Shell::registration(&answer);
    // Held past the backend's going deadline, so an admission that outlived its backend would give
    // the instance back only when that deadline fired.
    let mut held = shell.launcher(&shell.executable, &Shell::answered(), Some(3000));
    shell.prepare(&mut held, Some(&answer), "closed", &[]);
    let held = held.spawn().expect("the launcher starts");
    eventually("the launch is admitted", || registration.exists());
    let admitted_at = Instant::now();
    let instance = Shell::registered_instance(&answer);
    shell.backends.close();
    eventually("the admission ends with its backend", || {
        shell.broker.binding_state(instance).is_err()
    });
    assert!(
        admitted_at.elapsed() < kr_worker::broker::commands::GOING_DEADLINE,
        "the instance was given back when the backend was retired, not when the launch timed out: \
         {:?}",
        admitted_at.elapsed()
    );
    let _ = finish(held);
    assert_typed(
        &shell.report("closed"),
        "a launch whose session closed before it went",
    );
}

/// KR-REQ-12.07: the session closed after the launch was committed and before the launcher was told:
/// the launcher, which execs with the integration's flags only when it is told, runs what was typed.
#[test]
fn kr_req_12_07_a_launch_whose_session_closed_before_it_was_confirmed_runs_as_typed() {
    let shell = Shell::new();
    let (arrived, _release) = shell.backends.pause_before_confirming();
    let answer = shell.establish();
    let child = shell.launch(&answer, "unconfirmed", &[]);
    shell
        .runtime
        .block_on(async { tokio::time::timeout(LIVENESS, arrived).await })
        .expect("the launch is committed")
        .expect("and paused before the launcher is told");
    shell.backends.close();
    let _ = finish(child);
    assert_typed(
        &shell.report("unconfirmed"),
        "a launch whose session closed before it was confirmed",
    );
}

/// KR-REQ-12.07: a backend being launched when its line ends, or when a later line is resolved, is
/// retired by its rollback rather than handed back unbound, so a retry of the old answer runs as
/// typed.
#[test]
fn kr_req_12_07_a_launch_rolled_back_after_its_line_ended_retires_its_backend() {
    let shell = Shell::new();
    for (case, end) in [
        (
            "line",
            Box::new(|shell: &Shell, answer: &CommandBackend| {
                shell.backends.line_ended(answer.prompt_generation);
            }) as Box<dyn Fn(&Shell, &CommandBackend)>,
        ),
        (
            "later",
            Box::new(|shell: &Shell, _: &CommandBackend| {
                let _ = shell.establish();
            }),
        ),
    ] {
        let answer = shell.establish();
        let registration = Shell::registration(&answer);
        let mut held = shell.launcher(&shell.executable, &Shell::answered(), Some(20_000));
        shell.prepare(&mut held, Some(&answer), &format!("{case}-held"), &[]);
        let mut held = held.spawn().expect("the launcher starts");
        eventually("the launch is admitted", || registration.exists());
        end(&shell, &answer);
        let _ = held.kill();
        let _ = held.wait();
        eventually("the launch is rolled back", || !registration.exists());
        let retry = format!("{case}-retry");
        let _ = finish(shell.launch(&answer, &retry, &[]));
        assert_typed(
            &shell.report(&retry),
            &format!("a retry after its {case} ended"),
        );
        assert!(
            !Shell::directory(&answer).join("credential").exists(),
            "{case}: the backend was retired"
        );
    }
}

/// KR-REQ-05.09: a hello from a process the program did not start, waiting while the launch is
/// committed and the process still runs the launcher, cannot decide whether the program executes
/// what was hashed: it is refused before that is asked, and the program's own hook is admitted.
#[test]
fn kr_req_05_09_a_hello_that_is_not_the_program_s_own_decides_nothing() {
    let shell = Shell::new();
    let hook = shell.placed.forwarder.display().to_string();
    let (arrived, release) = shell.backends.pause_before_confirming();
    let answer = shell.establish();
    let registration = Shell::registration(&answer);
    let child = shell.launch(
        &answer,
        "own",
        &[
            ("HOOK", hook.as_str()),
            ("HOOK_EVENT", SESSION_START),
            ("LINGER", "2"),
        ],
    );
    shell
        .runtime
        .block_on(async { tokio::time::timeout(LIVENESS, arrived).await })
        .expect("the launch is committed")
        .expect("and paused before the launcher is told");
    // This test's own forwarder: the session's user, with the registration and its credential, and
    // not started by the program.
    let mut stranger = shell.placed.command(&["claude-code", "hook"]);
    stranger.env("KR_REGISTRATION", &registration);
    let ran = common::run_with_input(stranger, SESSION_START.as_bytes());
    assert_eq!(
        ran.code,
        Some(0),
        "a refused hook answers neutrally: {}",
        ran.stderr
    );
    let _ = release.send(());
    let report = shell.report("own");
    assert_eq!(report["registered"], "yes", "the launch went ahead");
    let instance = instance_of(&report);
    hooked(&shell, "own");
    assert_eq!(
        selected(&shell, instance).as_deref(),
        Some(THREAD),
        "the program's own hook is admitted"
    );
    let _ = finish(child);
}

/// KR-REQ-12.07: an endpoint whose queue is full cannot hold the launcher past its deadline: it runs
/// what was typed. On Linux a blocking connect would wait for room that never comes; macOS refuses
/// such a connect at once.
#[test]
fn kr_req_12_07_a_full_endpoint_queue_cannot_hold_the_launcher() {
    let shell = Shell::new();
    let directory = private(&shell, "f");
    let endpoint = directory.join("e.sock");
    let listener = std::os::unix::net::UnixListener::bind(&endpoint).expect("an endpoint");
    rustix::net::listen(&listener, 0).expect("its queue holds one connection");
    let _queued = std::os::unix::net::UnixStream::connect(&endpoint).expect("which this takes");
    let answer = hand_made_backend(&shell, &directory, &endpoint);
    let started = Instant::now();
    let (_, said) = finish(shell.launch(&answer, "full", &[]));
    assert!(
        started.elapsed() < kr_hook::launch::ADMISSION_DEADLINE + Duration::from_secs(3),
        "it gave up by its deadline: {:?}, {said}",
        started.elapsed()
    );
    assert_typed(&shell.report("full"), "an endpoint whose queue is full");
    drop(listener);
}

/// KR-REQ-12.07: an admission that trickles in a byte at a time cannot hold the launcher past its
/// deadline: each read is given only the time left, and the launcher runs what was typed.
#[test]
fn kr_req_12_07_an_admission_that_trickles_in_cannot_hold_the_launcher() {
    use std::io::{Read as _, Write as _};
    let shell = Shell::new();
    let directory = private(&shell, "t");
    let endpoint = directory.join("e.sock");
    let listener = std::os::unix::net::UnixListener::bind(&endpoint).expect("an endpoint");
    let serving = std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut byte = [0_u8; 1];
        while matches!(stream.read(&mut byte), Ok(1)) && byte[0] != b'\n' {}
        for byte in b"{\"kr_launch\":{\"admitted\":true}}\n" {
            if stream.write_all(&[*byte]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        std::thread::sleep(Duration::from_secs(2));
    });
    let answer = hand_made_backend(&shell, &directory, &endpoint);
    let started = Instant::now();
    let (_, said) = finish(shell.launch(&answer, "trickle", &[]));
    let took = started.elapsed();
    assert!(
        took < kr_hook::launch::ADMISSION_DEADLINE + Duration::from_secs(3),
        "it gave up by its deadline, not when the answer was whole: {took:?}, {said}"
    );
    assert_typed(&shell.report("trickle"), "an admission that trickled in");
    let _ = serving.join();
}

/// KR-REQ-12.07: a launcher stopped before it looked, whose session then closed, runs what was
/// typed when it is resumed: nothing of the backend is left, and the variable's file name says what
/// was typed.
#[test]
fn kr_req_12_07_a_launcher_resumed_after_its_session_closed_runs_as_typed() {
    let shell = Shell::new();
    let answer = shell.establish();
    let mut stopped = sh(
        r#"kill -STOP $$; exec "$LAUNCHER" launch -- "$PROGRAM" claude -c "$SCRIPT" "$FLAG" "$VALUE""#,
    );
    shell.prepare(&mut stopped, Some(&answer), "orphaned", &[]);
    stopped
        .env("LAUNCHER", &shell.placed.forwarder)
        .env("PROGRAM", &shell.executable)
        .env("SCRIPT", SCRIPT)
        .env("FLAG", fixture::FLAGS[0])
        .env("VALUE", fixture::FLAGS[1]);
    let child = stopped.spawn().expect("the shell starts");
    wait_stopped(child.id());
    shell.backends.close();
    assert!(
        !Shell::directory(&answer).exists(),
        "the session's backends are gone"
    );
    let resumed = std::process::Command::new("kill")
        .arg("-CONT")
        .arg(child.id().to_string())
        .status()
        .expect("the launcher is resumed");
    assert!(resumed.success());
    let _ = finish(child);
    assert_typed(
        &shell.report("orphaned"),
        "a launcher resumed after its session closed",
    );
}

/// The program for the mapping case: python, which writes the same report as the shell script, maps
/// the file `MAP_FILE` names read-only, and runs its hook while the mapping is there.
const MAPPING_PROGRAM: &str = r#"import mmap, os, subprocess, sys, time
report = os.environ["REPORT"]
mapped = open(os.environ["MAP_FILE"], "rb")
view = mmap.mmap(mapped.fileno(), 0, access=mmap.ACCESS_READ)
registration = os.environ.get("KR_REGISTRATION", "")
lines = ["pid=%d" % os.getpid()]
if registration and os.path.isfile(registration):
    lines.append("registered=yes")
    lines += ["registration." + line for line in open(registration).read().splitlines()]
else:
    lines.append("registered=no")
lines.append("variable=" + (registration or "none"))
lines.append("args=" + "|".join(sys.argv))
with open(report + ".part", "w") as out:
    out.write("\n".join(lines) + "\n")
os.rename(report + ".part", report)
with open(report + ".hook", "w") as out:
    subprocess.run([os.environ["HOOK"], "claude-code", "hook"], input=os.environ["HOOK_EVENT"].encode(), stdout=out, stderr=out)
with open(report + ".hooked", "w") as out:
    out.write("done\n")
time.sleep(float(os.environ.get("LINGER", "0")))
"#;

/// The python3 interpreter itself, not a command that finds one: macOS's `/usr/bin/python3` picks
/// its tool by the name it was run as, which a link named otherwise does not carry.
fn python3() -> PathBuf {
    let command = [
        "/usr/bin/python3",
        "/usr/local/bin/python3",
        "/opt/homebrew/bin/python3",
    ]
    .into_iter()
    .find(|candidate| Path::new(candidate).exists())
    .expect("a python3 for the mapping case");
    let found = std::process::Command::new(command)
        .args([
            "-c",
            "import os, sys; print(os.path.realpath(sys.executable))",
        ])
        .output()
        .expect("python3 runs");
    PathBuf::from(String::from_utf8_lossy(&found.stdout).trim())
}

/// KR-REQ-05.09: a program replaced between its admission and its exec by one that maps the hashed
/// program as data, and runs its hook while it does, is refused: the kernel's record of what the
/// process executes decides, not what it maps.
#[test]
fn kr_req_05_09_a_replacement_that_maps_the_hashed_program_is_refused() {
    let shell = Shell::new();
    let hook = shell.placed.forwarder.display().to_string();
    let (program, _) = shells();
    let path = shell.placed.host.root().join("bin").join("mapped");
    std::os::unix::fs::symlink(program, &path).expect("the program");
    let typed = vec![
        "claude".to_owned(),
        "-c".to_owned(),
        MAPPING_PROGRAM.to_owned(),
    ];
    let answer = shell.establish_with(&path, &typed);
    let registration = Shell::registration(&answer);
    let mut held = shell.launcher(&path, &Shell::answered_for(&typed), Some(1000));
    let mapped = program.display().to_string();
    shell.prepare(
        &mut held,
        Some(&answer),
        "mapped",
        &[
            ("HOOK", hook.as_str()),
            ("HOOK_EVENT", SESSION_START),
            ("MAP_FILE", mapped.as_str()),
            ("LINGER", "2"),
        ],
    );
    let held = held.spawn().expect("the launcher starts");
    eventually("the launch is admitted", || registration.exists());
    retarget(&path, &python3());
    let report = shell.report("mapped");
    assert_eq!(report["registered"], "yes", "the launch went ahead");
    let instance = instance_of(&report);
    hooked(&shell, "mapped");
    assert_eq!(
        selected(&shell, instance),
        None,
        "the hook of a program that only maps the hashed one moves nothing"
    );
    let _ = finish(held);
}

/// KR-REQ-05.09: on Linux, the program rewritten in place with its own bytes after it was hashed,
/// its modification time put back, is refused: its change time says it was written since.
#[cfg(target_os = "linux")]
#[test]
fn kr_req_05_09_a_program_rewritten_in_place_after_it_was_hashed_is_refused() {
    use std::io::Write as _;
    let shell = Shell::new();
    let hook = shell.placed.forwarder.display().to_string();
    let program = shell.placed.host.root().join("bin").join("rewritten");
    std::fs::copy("/bin/bash", &program).expect("a copy of the program, which Linux runs anywhere");
    let answer = shell.establish_for(&program);
    let registration = Shell::registration(&answer);
    let mut held = shell.launcher(&program, &Shell::answered(), Some(1000));
    shell.prepare(
        &mut held,
        Some(&answer),
        "rewritten",
        &[
            ("HOOK", hook.as_str()),
            ("HOOK_EVENT", SESSION_START),
            ("LINGER", "2"),
        ],
    );
    let held = held.spawn().expect("the launcher starts");
    eventually("the launch is admitted", || registration.exists());
    let bytes = std::fs::read(&program).expect("the program's bytes");
    let modified = std::fs::metadata(&program)
        .and_then(|metadata| metadata.modified())
        .expect("its modification time");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&program)
            .expect("the same inode, opened to write");
        file.write_all(&bytes).expect("its own bytes written back");
        file.set_modified(modified)
            .expect("its modification time put back");
        file.sync_all().expect("written");
    }
    let report = shell.report("rewritten");
    assert_eq!(report["registered"], "yes", "the launch went ahead");
    let instance = instance_of(&report);
    hooked(&shell, "rewritten");
    assert_eq!(
        selected(&shell, instance),
        None,
        "the hook of a program written since it was hashed moves nothing"
    );
    let _ = finish(held);
}

/// A thread a program starts a new session with after it execs another program.
const SECOND_THREAD: &str = "9b2e6f10-7c4d-4e8a-a1f3-2d5c8b0e4f22";

/// KR-REQ-05.09: a program whose first hook was admitted, and which then execs another program in
/// its own process, gets no bridge for the other: every bridge is checked against the kernel's
/// record of what the process executes now.
#[test]
fn kr_req_05_09_a_program_that_execs_another_gets_no_bridge_for_it() {
    let shell = Shell::new();
    let hook = shell.placed.forwarder.display().to_string();
    let (_, another) = shells();
    let second = SESSION_START.replace(THREAD, SECOND_THREAD);
    let then_exec = another.display().to_string();
    let answer = shell.establish();
    let child = shell.launch(
        &answer,
        "execs",
        &[
            ("HOOK", hook.as_str()),
            ("HOOK_EVENT", SESSION_START),
            ("HOOK_EVENT_2", second.as_str()),
            ("THEN_EXEC", then_exec.as_str()),
        ],
    );
    let instance = instance_of(&shell.report("execs"));
    hooked(&shell, "execs");
    assert_eq!(
        selected(&shell, instance).as_deref(),
        Some(THREAD),
        "the program's own hook is admitted"
    );
    eventually("the other program's hook has run", || {
        shell.reports.join("execs.hooked2").exists()
    });
    assert_eq!(
        selected(&shell, instance).as_deref(),
        Some(THREAD),
        "the hook of the program it execed moves nothing"
    );
    let _ = finish(child);
}

/// KR-REQ-12.07: a backend that drains the launcher's presentation a byte at a time cannot hold it
/// past its deadline, however large the presentation: every write waits for readiness only as long
/// as is left.
#[test]
fn kr_req_12_07_a_slowly_drained_presentation_cannot_hold_the_launcher() {
    use std::io::Read as _;
    let shell = Shell::new();
    let directory = private(&shell, "d");
    let endpoint = directory.join("e.sock");
    let listener = std::os::unix::net::UnixListener::bind(&endpoint).expect("an endpoint");
    let serving = std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut byte = [0_u8; 1];
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(20) && matches!(stream.read(&mut byte), Ok(1))
        {
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    // Six arguments of 96 KiB each: more than any socket buffer holds, and inside every
    // platform's bound on one argument and on all of them.
    let mut typed = Shell::typed();
    typed.extend((0..6).map(|index| format!("{index}{}", "x".repeat(96 * 1024))));
    let answer = hand_made_backend_at(&shell, &directory, &endpoint, typed.len());
    let mut command = shell.launcher(&shell.executable, &Shell::answered_for(&typed), None);
    shell.prepare(&mut command, Some(&answer), "drained", &[]);
    let started = Instant::now();
    let (_, said) = finish(command.spawn().expect("the launcher starts"));
    let took = started.elapsed();
    assert!(
        took < kr_hook::launch::ADMISSION_DEADLINE + Duration::from_secs(3),
        "it gave up by its deadline: {took:?}, {}",
        said.lines().last().unwrap_or_default()
    );
    let report = shell.report("drained");
    assert_eq!(report["registered"], "no", "not admitted");
    assert_eq!(report["variable"], "none", "without the variable");
    assert!(
        !report["args"].contains("--dangerously-load-development-channels"),
        "and without the added flags"
    );
    let _ = serving.join();
}

/// KR-REQ-12.07: a launch record replaced by a FIFO cannot hold the launcher: it is opened without
/// waiting, refused for not being a regular file, and the launcher runs what was typed.
#[test]
fn kr_req_12_07_a_fifo_in_place_of_the_launch_record_cannot_hold_the_launcher() {
    let shell = Shell::new();
    let answer = shell.establish();
    let record = Shell::directory(&answer).join("launch");
    std::fs::remove_file(&record).expect("the record goes");
    let made = std::process::Command::new("mkfifo")
        .arg(&record)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "a FIFO in its place");
    let started = Instant::now();
    let (_, said) = finish(shell.launch(&answer, "fifo", &[]));
    assert!(
        started.elapsed() < kr_hook::launch::ADMISSION_DEADLINE + Duration::from_secs(3),
        "it did not wait on the FIFO: {:?}, {said}",
        started.elapsed()
    );
    assert_typed(&shell.report("fifo"), "a launch record that is a FIFO");
}

/// KR-REQ-05.09: on macOS, a file whose code was changed and which kept another file's code
/// directory, established and then replaced by that other file before the exec, is refused: a code
/// directory is kept only when its pages match the file that was hashed.
#[cfg(target_os = "macos")]
#[test]
fn kr_req_05_09_a_code_directory_copied_into_changed_code_vouches_for_nothing() {
    let shell = Shell::new();
    let hook = shell.placed.forwarder.display().to_string();
    let (program, _) = shells();
    // Bash, with one byte of its arm64 slice's first page changed and its signature left as it was.
    let mut bytes = std::fs::read(program).expect("the program's bytes");
    let count = usize::try_from(u32::from_be_bytes(bytes[4..8].try_into().expect("four")))
        .expect("a slice count");
    let record = (0..count)
        .map(|slice| 8 + slice * 20)
        .find(|at| u32::from_be_bytes(bytes[*at..*at + 4].try_into().expect("four")) == 0x0100_000c)
        .expect("an arm64 slice");
    let offset = usize::try_from(u32::from_be_bytes(
        bytes[record + 8..record + 12].try_into().expect("four"),
    ))
    .expect("an offset");
    bytes[offset + 40] ^= 0xff;
    let changed = shell.placed.host.root().join("bin").join("changed");
    std::fs::write(&changed, &bytes).expect("the changed copy, which is hashed and never run");
    let path = shell.placed.host.root().join("bin").join("stale");
    std::os::unix::fs::symlink(&changed, &path).expect("the program");
    let answer = shell.establish_for(&path);
    let registration = Shell::registration(&answer);
    let mut held = shell.launcher(&path, &Shell::answered(), Some(1000));
    shell.prepare(
        &mut held,
        Some(&answer),
        "stale",
        &[
            ("HOOK", hook.as_str()),
            ("HOOK_EVENT", SESSION_START),
            ("LINGER", "2"),
        ],
    );
    let held = held.spawn().expect("the launcher starts");
    eventually("the launch is admitted", || registration.exists());
    retarget(&path, program);
    let report = shell.report("stale");
    assert_eq!(report["registered"], "yes", "the launch went ahead");
    let instance = instance_of(&report);
    hooked(&shell, "stale");
    assert_eq!(
        selected(&shell, instance),
        None,
        "the hook of a program only a copied directory vouched for moves nothing"
    );
    let _ = finish(held);
}
