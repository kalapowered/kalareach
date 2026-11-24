//! The stand-in service manager, run as `kr` and the daemon run it: by its program, in a test tree of
//! its own, with the state directory the caller names. The cases read the process list and the
//! system's own programs as macOS prints and protects them, which is where the stand-in is used.
#![cfg(target_os = "macos")]

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_ipc::identity::{ProcessState, Stop, process_state, started_process_identity, stop_process};
use kr_ipc::testing::PrivateTempDir;
use kr_ipc::testing::manager_stand_in::{PROGRAM_NAME, place_installation};
use kr_protocol::identity::ProcessStartIdentity;

/// A test tree and an installation beside it, both of this case's own.
///
/// When the fixture is dropped, which is when a case ends whether it passed or failed, it ends every
/// process the case started, each by the identity it was recorded with: those the case started
/// itself through [`Fixture::detached`] and the daemons the stand-in recorded in its jobs.
struct Fixture {
    tree: PrivateTempDir,
    installation: PrivateTempDir,
    program: PathBuf,
    uid: u32,
    /// The processes the case started itself.
    started: Mutex<Vec<ProcessStartIdentity>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let mut identities = std::mem::take(
            self.started
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner),
        );
        identities.extend(self.recorded_daemons());
        for identity in &identities {
            let _ = stop_process(identity, Stop::Kill);
        }
        for identity in &identities {
            let _ = ended(identity);
        }
    }
}

impl Fixture {
    fn new() -> Self {
        let tree = PrivateTempDir::create();
        std::fs::create_dir_all(tree.path().join("state")).expect("a state directory");
        std::fs::create_dir_all(tree.path().join("home/Library/LaunchAgents")).expect("a home");
        let installation = PrivateTempDir::create();
        let _ = place_installation(installation.path());
        let program = installation.path().join(PROGRAM_NAME);
        kr_ipc::testing::place_program(
            Path::new(env!("CARGO_BIN_EXE_kr-manager-stand-in")),
            &program,
        );
        let uid = std::fs::metadata(installation.path())
            .expect("a folder")
            .uid();
        Self {
            tree,
            installation,
            program,
            uid,
            started: Mutex::new(Vec::new()),
        }
    }

    /// The processes the stand-in recorded as the daemons of its jobs.
    fn recorded_daemons(&self) -> Vec<ProcessStartIdentity> {
        let Ok(entries) = std::fs::read_dir(self.tree.path().join("state/manager-stand-in/jobs"))
        else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
            .filter_map(|record| serde_json::from_str::<kr_manager_stand_in::Job>(&record).ok())
            .filter_map(|job| job.identity)
            .collect()
    }

    /// The stand-in run with `arguments`, from a caller that names this tree's state directory.
    fn call(&self, arguments: &[&str]) -> Output {
        run(Command::new(&self.program)
            .args(arguments)
            .env_clear()
            .env("HOME", self.tree.path().join("home"))
            .env("TMPDIR", self.tree.path())
            .env(
                kr_ipc::paths::STATE_DIR_VARIABLE,
                self.tree.path().join("state"),
            ))
    }

    fn domain(&self) -> String {
        format!("user/{}", self.uid)
    }

    /// The calls it recorded, as the lines of its log.
    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.tree.path().join("state/manager-stand-in/calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The definition `kr` writes for a daemon `program` run in `directory`, as its `render` writes
    /// it: the same keys in the same order.
    fn plist(&self, label: &str, program: &Path, directory: &Path, extra: &str) -> String {
        let arguments = [
            program.display().to_string(),
            "--runtime-dir".to_owned(),
            self.tree.path().join("r").display().to_string(),
            "--state-dir".to_owned(),
            self.tree.path().join("state").display().to_string(),
        ];
        self.plist_of(label, &arguments, directory, extra)
    }

    /// The same definition with the program and the arguments `arguments`, the program first.
    fn plist_of(&self, label: &str, arguments: &[String], directory: &Path, extra: &str) -> String {
        let log = directory.join("daemon.log");
        let arguments: String = arguments
            .iter()
            .map(|argument| format!("\t\t<string>{argument}</string>\n"))
            .collect();
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <!-- The KalaReach control daemon. -->\n\
             <plist version=\"1.0\">\n<dict>\n\
             \t<key>Label</key>\n\t<string>{label}</string>\n\
             \t<key>ProgramArguments</key>\n\t<array>\n{arguments}\t</array>\n\
             \t<key>RunAtLoad</key>\n\t<false/>\n\t<key>KeepAlive</key>\n\t<false/>\n\
             \t<key>LimitLoadToSessionType</key>\n\t<string>Background</string>\n\
             \t<key>ProcessType</key>\n\t<string>Interactive</string>\n\
             \t<key>WorkingDirectory</key>\n\t<string>{}</string>\n\
             \t<key>Umask</key>\n\t<integer>63</integer>\n{extra}\
             \t<key>StandardOutPath</key>\n\t<string>{}</string>\n\
             \t<key>StandardErrorPath</key>\n\t<string>{}</string>\n</dict>\n</plist>\n",
            directory.display(),
            log.display(),
            log.display(),
        )
    }

    /// Writes a definition for a daemon made of `script` and loads it.
    fn load(&self, label: &str, script: &str, extra: &str) -> (PathBuf, Output) {
        let program = self.installation.path().join("kr-daemon");
        kr_ipc::testing::place_script(&program, script);
        let directory = self.tree.path().join("state");
        let plist = self
            .tree
            .path()
            .join(format!("home/Library/LaunchAgents/{label}.plist"));
        std::fs::write(&plist, self.plist(label, &program, &directory, extra)).expect("a plist");
        let loaded = self.call(&["bootstrap", &self.domain(), plist.to_str().expect("text")]);
        (plist, loaded)
    }

    /// The record of the job `label`, which a start that was never recorded leaves behind: the job is
    /// loaded and marked as a start that began.
    fn mark_pending(&self, label: &str) {
        let record = self
            .tree
            .path()
            .join(format!("state/manager-stand-in/jobs/{label}.json"));
        let mut job: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&record).expect("the record"))
                .expect("json");
        job["pending"] = serde_json::Value::Bool(true);
        std::fs::write(&record, job.to_string()).expect("a pending record");
    }

    /// Starts the shell command `line` in `directory` with the variables `environment` added, as the
    /// system's first process holds a daemon whose starter has gone, and returns its identity. The
    /// fixture ends the process when the case ends.
    fn detached(
        &self,
        line: &str,
        directory: &Path,
        environment: &[(&str, &str)],
    ) -> ProcessStartIdentity {
        let started = run(Command::new("/bin/sh")
            .args([
                "-c",
                &format!("{line} </dev/null >/dev/null 2>&1 & echo $!"),
            ])
            .current_dir(directory)
            .envs(environment.iter().copied()));
        let pid: u32 = text(&started.stdout)
            .trim()
            .parse()
            .expect("a process number");
        let identity = started_process_identity(pid).expect("the process is there");
        self.track(&identity);
        identity
    }

    /// Has the fixture end the process `identity` when the case ends.
    fn track(&self, identity: &ProcessStartIdentity) {
        self.started
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(identity.clone());
    }
}

/// Whether the process `identity` has ended within ten seconds.
fn ended(identity: &ProcessStartIdentity) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if process_state(identity) == ProcessState::Ended {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    process_state(identity) == ProcessState::Ended
}

/// How long a command of a case is given to end.
const CASE_BOUND: Duration = Duration::from_secs(120);

/// Runs `command` as the cases need it: with no input, for at most [`CASE_BOUND`], and returns what
/// it printed. A command that outlasts the bound is ended and fails the case.
fn run(command: &mut Command) -> Output {
    kr_manager_stand_in::bounded_output(command, CASE_BOUND).unwrap_or_else(|why| panic!("{why}"))
}

/// No command of the cases is waited for without a bound: each one goes through `run`.
#[test]
fn no_command_of_the_cases_is_waited_for_without_a_bound() {
    let source = include_str!("stand_in.rs");
    for call in [
        [".out", "put()"].concat(),
        [".sta", "tus()"].concat(),
        [".wa", "it()"].concat(),
    ] {
        assert!(
            !source.contains(&call),
            "a case waits for a command with {call}, and no bound"
        );
    }
}

fn text(output: &[u8]) -> String {
    String::from_utf8_lossy(output).into_owned()
}

/// What the stand-in answers to the questions `kr` puts: the graphical domain is absent in the
/// words the reader of the desktop knows, the background domain is there, and a job that was never
/// loaded is not.
#[test]
fn the_stand_in_answers_the_reads_of_kr_as_launchd_does() {
    let fixture = Fixture::new();
    let gui = fixture.call(&["print", &format!("gui/{}", fixture.uid)]);
    assert_eq!(gui.status.code(), Some(112));
    assert!(
        text(&gui.stderr)
            .to_lowercase()
            .contains("could not find domain")
    );
    let user = fixture.call(&["print", &fixture.domain()]);
    assert_eq!(user.status.code(), Some(0));
    let absent = fixture.call(&["print", &format!("{}/kr-controller-x", fixture.domain())]);
    assert_eq!(absent.status.code(), Some(113));
    let unknown = fixture.call(&["bootstrap", "system", "/x"]);
    assert_ne!(unknown.status.code(), Some(0));
    let verb = fixture.call(&["remove", "x"]);
    assert_eq!(verb.status.code(), Some(64), "an unknown verb is refused");
    let calls = fixture.calls();
    assert_eq!(calls.len(), 5, "{calls:?}");
    assert!(
        calls[4].contains("\"status\":64") && calls[4].contains("remove"),
        "{calls:?}"
    );
}

/// A job loaded in the background domain is not there for the graphical domain: `print`,
/// `kickstart` and `bootout` answer 113, as launchd does for a job that a domain does not have,
/// and the job stays loaded in its own domain.
#[test]
fn a_job_loaded_in_the_background_domain_is_not_found_in_the_graphical_domain() {
    let fixture = Fixture::new();
    let (_, loaded) = fixture.load("kr-controller-x", "#!/bin/sh\nexit 0\n", "");
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    let graphical = format!("gui/{}/kr-controller-x", fixture.uid);
    for arguments in [
        vec!["print", &graphical],
        vec!["kickstart", "-p", &graphical],
        vec!["bootout", &graphical],
    ] {
        let answered = fixture.call(&arguments);
        assert_eq!(
            answered.status.code(),
            Some(113),
            "{arguments:?}: {}",
            text(&answered.stderr)
        );
    }
    let background = format!("{}/kr-controller-x", fixture.domain());
    let described = fixture.call(&["print", &background]);
    assert_eq!(
        described.status.code(),
        Some(0),
        "the job is still loaded in its own domain"
    );
}

/// A definition is loaded as written, once; what the description says is what `kr` reads; and
/// everything the stand-in does not apply is refused and never loaded.
#[test]
fn a_definition_is_loaded_as_written_and_what_it_does_not_apply_is_refused() {
    let fixture = Fixture::new();
    let (plist, loaded) = fixture.load("kr-controller-a", "#!/bin/sh\nexit 0\n", "");
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    let target = format!("{}/kr-controller-a", fixture.domain());
    let described = text(&fixture.call(&["print", &target]).stdout);
    assert!(
        described.contains(&format!(
            "\tpath = {}\n",
            plist.canonicalize().unwrap().display()
        )),
        "{described}"
    );
    assert!(described.contains("\targuments = {\n\t\t"), "{described}");
    assert!(
        !described.contains("keepalive") && !described.contains("pid ="),
        "{described}"
    );
    let again = fixture.call(&[
        "bootstrap",
        &fixture.domain(),
        plist.to_str().expect("text"),
    ]);
    assert_eq!(again.status.code(), Some(5), "a label that is loaded");

    for (name, extra, why) in [
        (
            "kr-controller-b",
            "\t<key>KeepAlive2</key>\n\t<true/>\n",
            "a key it does not apply",
        ),
        (
            "kr-controller-c",
            "\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>KR_ALLOW_ACCOUNT_LAUNCHD</key>\n\t\t<string>1</string>\n\t</dict>\n",
            "the ask",
        ),
        (
            "kr-controller-d",
            "\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>HOME</key>\n\t\t<string>/x</string>\n\t</dict>\n",
            "a variable of the harness",
        ),
    ] {
        let (_, refused) = fixture.load(name, "#!/bin/sh\nexit 0\n", extra);
        assert_eq!(
            refused.status.code(),
            Some(64),
            "{why}: {}",
            text(&refused.stderr)
        );
        let listed = fixture.call(&["print", &format!("{}/{name}", fixture.domain())]);
        assert_eq!(listed.status.code(), Some(113), "{why} is not loaded");
    }
    let outside = fixture
        .tree
        .path()
        .join("home/Library/LaunchAgents/kr-controller-e.plist");
    std::fs::write(
        &outside,
        fixture.plist(
            "kr-controller-e",
            Path::new("/usr/bin/true"),
            Path::new("/tmp"),
            "",
        ),
    )
    .expect("a plist");
    let refused = fixture.call(&[
        "bootstrap",
        &fixture.domain(),
        outside.to_str().expect("text"),
    ]);
    assert_eq!(
        refused.status.code(),
        Some(64),
        "a program outside the test's folders"
    );
    let aqua = fixture
        .plist(
            "kr-controller-f",
            &fixture.installation.path().join("kr-daemon"),
            &fixture.tree.path().join("state"),
            "",
        )
        .replace("Background", "Aqua");
    let path = fixture
        .tree
        .path()
        .join("home/Library/LaunchAgents/kr-controller-f.plist");
    std::fs::write(&path, aqua).expect("a plist");
    let refused = fixture.call(&["bootstrap", &fixture.domain(), path.to_str().expect("text")]);
    assert_eq!(
        refused.status.code(),
        Some(64),
        "a session type that is not the domain's"
    );
    let program = fixture.installation.path().join("kr-daemon");
    let state = fixture.tree.path().join("state");
    for (name, from, to, why) in [
        (
            "kr-controller-g",
            "\t<string>Interactive</string>\n",
            "\t<string>Background</string>\n",
            "a process type that is not the one `kr` writes",
        ),
        (
            "kr-controller-h",
            "\t<key>ProcessType</key>\n\t<string>Interactive</string>\n",
            "",
            "no process type",
        ),
    ] {
        let written = fixture.plist(name, &program, &state, "");
        assert!(
            written.contains(from),
            "the definition holds the text this case changes"
        );
        let path = fixture
            .tree
            .path()
            .join(format!("home/Library/LaunchAgents/{name}.plist"));
        std::fs::write(&path, written.replace(from, to)).expect("a plist");
        let refused = fixture.call(&["bootstrap", &fixture.domain(), path.to_str().expect("text")]);
        assert_eq!(
            refused.status.code(),
            Some(64),
            "{why}: {}",
            text(&refused.stderr)
        );
        let listed = fixture.call(&["print", &format!("{}/{name}", fixture.domain())]);
        assert_eq!(listed.status.code(), Some(113), "{why} is not loaded");
    }
}

/// The daemon starts as the definition says: its arguments, directory, mask and log, the harness's
/// own environment and the definition's entry with its value, no ask, and a session of its own. Its
/// process survives the script's `exec`, a job that runs is not started again, and `bootout` ends
/// it by its recorded identity and unloads the job.
#[test]
fn the_daemon_starts_as_the_definition_says_survives_its_exec_and_ends_by_identity() {
    let fixture = Fixture::new();
    let out = fixture.tree.path().join("seen");
    let script = format!(
        "#!/bin/sh\n{{ echo \"cwd=$(pwd -P)\"; echo \"mask=$(umask)\"; echo \"args=$*\"; \
         echo \"home=$HOME\"; echo \"path=$PATH\"; echo \"harmless=$HARMLESS\"; \
         echo \"ask=$KR_ALLOW_ACCOUNT_LAUNCHD\"; echo \"stand_in=$KR_MANAGER_STAND_IN\"; \
         echo \"pgid=$(ps -o pgid= -p $$ | tr -d ' ')\"; echo \"pid=$$\"; \
         echo \"tmp=$TMPDIR\"; echo \"tty=$(ps -o tty= -p $$ | tr -d ' ')\"; }} > {}\n\
         exec /bin/sleep 120\n",
        out.display()
    );
    let extra = "\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>HARMLESS</key>\n\t\t<string>a value 1</string>\n\t</dict>\n";
    let (_, loaded) = fixture.load("kr-controller-g", &script, extra);
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    let target = format!("{}/kr-controller-g", fixture.domain());
    let started = fixture.call(&["kickstart", "-p", &target]);
    assert_eq!(started.status.code(), Some(0), "{}", text(&started.stderr));
    let pid: u32 = text(&started.stdout)
        .trim()
        .parse()
        .expect("a process number");
    let deadline = Instant::now() + Duration::from_secs(20);
    // The last line the script writes, so that what is read is all of what it saw.
    while !std::fs::read_to_string(&out).is_ok_and(|seen| seen.contains("tty="))
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(50));
    }
    let seen = std::fs::read_to_string(&out).expect("the daemon wrote what it saw");
    assert!(
        seen.contains(&format!(
            "cwd={}",
            fixture
                .tree
                .path()
                .join("state")
                .canonicalize()
                .unwrap()
                .display()
        )),
        "{seen}"
    );
    assert!(seen.contains("mask=0077"), "{seen}");
    assert!(seen.contains("--runtime-dir"), "{seen}");
    assert!(
        seen.contains("path=/usr/bin:/bin:/usr/sbin:/sbin"),
        "{seen}"
    );
    assert!(seen.contains("harmless=a value 1"), "{seen}");
    assert!(seen.contains("ask=\n"), "no ask reaches the daemon: {seen}");
    assert!(
        seen.contains(&format!(
            "stand_in={}",
            fixture.program.canonicalize().unwrap().display()
        )),
        "{seen}"
    );
    assert!(
        seen.contains(&format!("pid={pid}")),
        "the process is the one the manager recorded: {seen}"
    );
    assert!(
        seen.contains("tty=??") || seen.contains("tty=\n"),
        "no controlling terminal: {seen}"
    );
    assert!(
        seen.contains(&format!("pgid={pid}")),
        "a process group of its own: {seen}"
    );
    assert!(
        seen.contains(&format!(
            "home={}",
            fixture.tree.path().join("home").display()
        )),
        "the case's own home, kept apart from the definition's entries: {seen}"
    );
    assert!(
        seen.contains(&format!("tmp={}", fixture.tree.path().display())),
        "the case's own temporary directory: {seen}"
    );
    // A session of its own whatever started the test, which a terminal's absence does not show.
    let session_of = |pid: u32| {
        rustix::process::getsid(rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()))
            .expect("a session")
    };
    assert_ne!(
        session_of(pid),
        session_of(std::process::id()),
        "the daemon is in the session of the test, not a session of its own"
    );
    let described = text(&fixture.call(&["print", &target]).stdout);
    assert!(
        described.contains(&format!("\tpid = {pid}\n")),
        "{described}"
    );
    let again = fixture.call(&["kickstart", "-p", &target]);
    assert_eq!(
        text(&again.stdout).trim(),
        pid.to_string(),
        "a job that runs is not started again"
    );
    let job = std::fs::read_to_string(
        fixture
            .tree
            .path()
            .join("state/manager-stand-in/jobs/kr-controller-g.json"),
    )
    .expect("the record");
    assert!(job.contains("\"starts\": 1"), "{job}");
    let ended = fixture.call(&["bootout", &target]);
    assert_eq!(ended.status.code(), Some(0), "{}", text(&ended.stderr));
    let gone = run(Command::new("/bin/ps").args(["-o", "pid=", "-p", &pid.to_string()]));
    assert!(text(&gone.stdout).trim().is_empty(), "the daemon was ended");
    assert_eq!(
        fixture.call(&["print", &target]).status.code(),
        Some(113),
        "the job is unloaded"
    );
}

/// A start that was never recorded is found by proof that it is the job's and ended: its arguments
/// end with the definition's, whole word for whole word, it runs a program inside the test's
/// folders, and its working directory is the definition's. The process is the wrapper as the system's
/// shell reads it, which `ps` shows as the interpreter, the program and the arguments.
#[test]
fn a_start_that_was_never_recorded_is_found_by_its_arguments_program_and_directory_and_ended() {
    let fixture = Fixture::new();
    let script = "#!/bin/sh\nwhile :; do sleep 1; done\n";
    let (_, loaded) = fixture.load("kr-controller-i", script, "");
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    fixture.mark_pending("kr-controller-i");
    let state = fixture.tree.path().join("state");
    let program = fixture.installation.path().join("kr-daemon");
    let wrapper = fixture.detached(
        &format!(
            "{} --runtime-dir {} --state-dir {}",
            program.display(),
            fixture.tree.path().join("r").display(),
            state.display()
        ),
        &state,
        &[],
    );
    let target = format!("{}/kr-controller-i", fixture.domain());
    let ended_job = fixture.call(&["bootout", &target]);
    assert_eq!(
        ended_job.status.code(),
        Some(0),
        "{}",
        text(&ended_job.stderr)
    );
    assert!(
        ended(&wrapper),
        "the wrapper was found by its arguments, program and directory, and ended"
    );
}

/// A start that was never recorded is not confused with any other process, whatever text the other
/// holds: a program outside the test's folders, a program inside them in another directory, a
/// program inside them in the right directory whose last argument only starts with the definition's,
/// and a program outside them that is given a path inside them as data, in the right directory with
/// the definition's last argument, are all left running, though every one of them holds the
/// definition's arguments in its own arguments or its environment.
#[test]
fn a_start_that_was_never_recorded_is_not_confused_with_processes_that_only_hold_the_same_text() {
    let fixture = Fixture::new();
    let program = fixture.installation.path().join("kr-daemon");
    kr_ipc::testing::place_script(&program, "#!/bin/sh\nexit 0\n");
    let state = fixture.tree.path().join("state");
    let arguments = [program.display().to_string(), "30".to_owned()];
    let plist = fixture
        .tree
        .path()
        .join("home/Library/LaunchAgents/kr-controller-n.plist");
    std::fs::write(
        &plist,
        fixture.plist_of("kr-controller-n", &arguments, &state, ""),
    )
    .expect("a plist");
    let loaded = fixture.call(&[
        "bootstrap",
        &fixture.domain(),
        plist.to_str().expect("text"),
    ]);
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    fixture.mark_pending("kr-controller-n");
    // A program of the installation that waits as long as its first argument says. The system shows
    // it as the shell, the script and the argument.
    let idle = fixture.installation.path().join("idle");
    kr_ipc::testing::place_script(&idle, "#!/bin/sh\nsleep \"$1\"\n");
    // A file that a reader of it waits at, so that a program outside the folders is given a path
    // inside them as an argument and stays running.
    let waited_at = fixture.tree.path().join("waited-at");
    let made = run(Command::new("/usr/bin/mkfifo").arg(&waited_at));
    assert!(made.status.success(), "{}", text(&made.stderr));
    let same_text = format!("{} 30", program.display());
    let environment = [("SAME_TEXT", same_text.as_str())];
    let others = [
        (
            "a program outside the folders, in the right directory",
            fixture.detached("/bin/sleep 30", &state, &environment),
        ),
        (
            "a program inside the folders, in another directory",
            fixture.detached(
                &format!("{} 30", idle.display()),
                fixture.tree.path(),
                &environment,
            ),
        ),
        (
            "a program inside the folders and the right directory whose last argument only starts \
             with the definition's",
            fixture.detached(&format!("{} 300", idle.display()), &state, &environment),
        ),
        (
            "a program outside the folders that is given a path inside them as data, in the right \
             directory with the definition's last argument",
            fixture.detached(
                &format!("/bin/cat {} 30", waited_at.display()),
                &state,
                &environment,
            ),
        ),
    ];
    let target = format!("{}/kr-controller-n", fixture.domain());
    let ended_job = fixture.call(&["bootout", &target]);
    assert_eq!(
        ended_job.status.code(),
        Some(0),
        "{}",
        text(&ended_job.stderr)
    );
    for (what, identity) in &others {
        assert_eq!(
            process_state(identity),
            ProcessState::Running,
            "{what} was taken for the job's and ended"
        );
    }
}

/// `bootout` ends the daemon and the group it leads: a process the daemon started and left running
/// ends with it, and the job is unloaded.
#[test]
fn bootout_ends_the_processes_the_daemon_started_with_it() {
    let fixture = Fixture::new();
    let child_file = fixture.tree.path().join("child.pid");
    let script = format!(
        "#!/bin/sh\nsleep 60 &\necho $! > {}\nwait\n",
        child_file.display()
    );
    let (_, loaded) = fixture.load("kr-controller-r", &script, "");
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    let target = format!("{}/kr-controller-r", fixture.domain());
    let started = fixture.call(&["kickstart", "-p", &target]);
    assert_eq!(started.status.code(), Some(0), "{}", text(&started.stderr));
    let deadline = Instant::now() + Duration::from_secs(20);
    let child = loop {
        if let Some(pid) = std::fs::read_to_string(&child_file)
            .ok()
            .and_then(|written| written.trim().parse::<u32>().ok())
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "the daemon started no process");
        std::thread::sleep(Duration::from_millis(50));
    };
    let child = started_process_identity(child).expect("the process the daemon started");
    fixture.track(&child);
    assert_eq!(process_state(&child), ProcessState::Running);
    let ended_job = fixture.call(&["bootout", &target]);
    assert_eq!(
        ended_job.status.code(),
        Some(0),
        "{}",
        text(&ended_job.stderr)
    );
    assert!(
        ended(&child),
        "the process the daemon started ended with the daemon"
    );
}

/// A label is checked before any path is made of it: a label that is an absolute path, one with a
/// parent component and one with a separator are refused, however the command names it, and no
/// record is made at the place the label points to.
#[test]
fn a_label_that_is_a_path_is_refused_and_no_record_is_made_where_it_points() {
    let fixture = Fixture::new();
    let tree = fixture.tree.path();
    let program = fixture.installation.path().join("kr-daemon");
    kr_ipc::testing::place_script(&program, "#!/bin/sh\nexit 0\n");
    let arguments = [program.display().to_string(), "30".to_owned()];
    let absolute = tree.join("escaped").display().to_string();
    for (label, made) in [
        (absolute.as_str(), tree.join("escaped.json")),
        (
            "../escaped-up",
            tree.join("state/manager-stand-in/escaped-up.json"),
        ),
        ("a/b", tree.join("state/manager-stand-in/jobs/a/b.json")),
    ] {
        let plist = tree.join("home/Library/LaunchAgents/kr-controller-label.plist");
        std::fs::write(
            &plist,
            fixture.plist_of(label, &arguments, &tree.join("state"), ""),
        )
        .expect("a plist");
        let loaded = fixture.call(&[
            "bootstrap",
            &fixture.domain(),
            plist.to_str().expect("text"),
        ]);
        assert_eq!(loaded.status.code(), Some(64), "the label {label}");
        assert!(!made.exists(), "the label {label} made {}", made.display());
        let read = fixture.call(&["print", &format!("{}/{label}", fixture.domain())]);
        assert_eq!(read.status.code(), Some(64), "a read of the label {label}");
    }
}

/// A path argument is bounded or refused in every form the definition can give it: the value of
/// `--state-dir` as a separate argument or after an equals sign, inside the test's folders or
/// outside, and any other argument that may name a path.
#[test]
fn a_path_argument_in_every_form_is_bounded_or_refused_when_a_definition_is_loaded() {
    let fixture = Fixture::new();
    let tree = fixture.tree.path();
    let program = fixture.installation.path().join("kr-daemon");
    kr_ipc::testing::place_script(&program, "#!/bin/sh\nexit 0\n");
    let state = tree.join("state");
    let load = |label: &str, extra: &[String]| {
        let mut arguments = vec![program.display().to_string()];
        arguments.extend_from_slice(extra);
        let plist = tree.join(format!("home/Library/LaunchAgents/{label}.plist"));
        std::fs::write(&plist, fixture.plist_of(label, &arguments, &state, "")).expect("a plist");
        fixture.call(&[
            "bootstrap",
            &fixture.domain(),
            plist.to_str().expect("text"),
        ])
    };
    let inside = format!("--state-dir={}", state.display());
    let loaded = load("kr-controller-s0", &[inside]);
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    for (index, refused) in [
        vec!["--state-dir=/outside"],
        vec!["--runtime-dir=/outside"],
        vec!["--state-dir", "/outside"],
        vec!["--secret-store=/outside"],
        vec!["../escape"],
    ]
    .into_iter()
    .enumerate()
    {
        let label = format!("kr-controller-s{}", index + 1);
        let extra: Vec<String> = refused
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect();
        let answered = load(&label, &extra);
        assert_eq!(answered.status.code(), Some(64), "{refused:?}");
        let listed = fixture.call(&["print", &format!("{}/{label}", fixture.domain())]);
        assert_eq!(listed.status.code(), Some(113), "{refused:?} is not loaded");
    }
}

/// The store's own folders, files and links are bounded as a definition's are: a link in the
/// place of the store, of its folder of jobs, of its lock or of its log that leads out of the
/// test's folders is refused, and nothing is made outside.
#[test]
fn a_link_in_the_place_of_the_stores_own_paths_is_refused_and_nothing_is_made_outside() {
    for place in ["", "jobs", "lock", "calls.jsonl"] {
        let fixture = Fixture::new();
        let outside = PrivateTempDir::create();
        let store = fixture.tree.path().join("state/manager-stand-in");
        // The link takes the place of the store, of its folder of jobs (which leads to a folder
        // outside), or of its lock or log (which lead to a file outside that is not there yet).
        let (at, led_to) = match place {
            "" => (store.clone(), outside.path().to_path_buf()),
            "jobs" => {
                std::fs::create_dir_all(&store).expect("a store");
                (store.join("jobs"), outside.path().to_path_buf())
            }
            file => {
                std::fs::create_dir_all(store.join("jobs")).expect("a store");
                (store.join(file), outside.path().join(file))
            }
        };
        std::os::unix::fs::symlink(&led_to, &at).expect("a link");
        let answered = fixture.call(&["print", &format!("gui/{}", fixture.uid)]);
        assert_eq!(
            answered.status.code(),
            Some(64),
            "a link in the place of {place:?}: {}",
            text(&answered.stderr)
        );
        let made: Vec<_> = std::fs::read_dir(outside.path())
            .expect("the folder outside")
            .filter_map(Result::ok)
            .collect();
        assert!(
            made.is_empty(),
            "a link in the place of {place:?} let something be made outside: {made:?}"
        );
    }
}

/// Ends the processes it holds when it is dropped, by their identities, independently of the fixture.
struct Leftovers(Vec<ProcessStartIdentity>);

impl Drop for Leftovers {
    fn drop(&mut self) {
        for leftover in &self.0 {
            let _ = stop_process(leftover, Stop::Kill);
        }
    }
}

/// The variable that names the file in which the case that fails on purpose lists what it started.
const LIST_VARIABLE: &str = "KR_STAND_IN_TEST_STARTED_LIST";

/// A case that fails before its own cleanup leaves nothing it started alive: the fixture ends every
/// process of the case, as it does when the case passes. The case that fails on purpose runs in a
/// child test process, and lists the processes it started (its own unbounded loop and the daemon
/// the stand-in started) before it fails.
#[test]
fn a_case_that_fails_before_its_own_cleanup_leaves_nothing_alive() {
    let folder = PrivateTempDir::create();
    let list = folder.path().join("started.json");
    let child = run(
        Command::new(std::env::current_exe().expect("this test program"))
            .args([
                "--ignored",
                "--exact",
                "a_case_that_fails_on_purpose_before_its_own_cleanup",
                "--test-threads=1",
            ])
            .env(LIST_VARIABLE, &list),
    );
    let said = text(&child.stdout);
    let started: Vec<ProcessStartIdentity> =
        serde_json::from_str(&std::fs::read_to_string(&list).expect("the list of what it started"))
            .expect("a list");
    // Whatever the fixture did, no process of the failed case outlives this one.
    let leftovers = Leftovers(started.clone());
    assert!(
        said.contains("this case fails on purpose") && child.status.code() == Some(101),
        "the child case fails on purpose and for no other reason: {said}"
    );
    assert_eq!(started.len(), 2, "the loop and the daemon: {started:?}");
    for identity in &started {
        assert!(
            ended(identity),
            "a process the failed case started is still alive: {identity:?}"
        );
    }
    drop(leftovers);
}

/// Run by the case above, in a child test process: it starts an unbounded loop and a daemon, lists
/// them, and fails before it ends either.
#[test]
#[ignore = "run by the case that shows a failed case leaves nothing alive"]
fn a_case_that_fails_on_purpose_before_its_own_cleanup() {
    let Some(list) = std::env::var_os(LIST_VARIABLE) else {
        return;
    };
    let fixture = Fixture::new();
    let script = "#!/bin/sh\nwhile :; do sleep 1; done\n";
    let (_, loaded) = fixture.load("kr-controller-q", script, "");
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    let target = format!("{}/kr-controller-q", fixture.domain());
    let started = fixture.call(&["kickstart", "-p", &target]);
    assert_eq!(started.status.code(), Some(0), "{}", text(&started.stderr));
    let state = fixture.tree.path().join("state");
    let own_loop = fixture.detached(
        &format!(
            "/bin/sh -c 'while :; do sleep 1; done' x {}",
            state.display()
        ),
        &state,
        &[],
    );
    let mut identities = fixture.recorded_daemons();
    identities.push(own_loop);
    std::fs::write(
        list,
        serde_json::to_string(&identities).expect("the identities as text"),
    )
    .expect("the list is written");
    panic!("this case fails on purpose, before it ends anything it started");
}

/// What a definition may name is bounded after every link is resolved: a plist, a log or a working
/// directory behind a link that leads outside the test's folders, or a link that leads nowhere, is
/// refused.
#[test]
fn a_link_that_leads_out_of_the_test_is_refused() {
    let fixture = Fixture::new();
    let outside = PrivateTempDir::create();
    let tree = fixture.tree.path();
    let program = fixture.installation.path().join("kr-daemon");
    kr_ipc::testing::place_script(&program, "#!/bin/sh\nexit 0\n");
    let loaded_from = |label: &str, plist: &Path| {
        std::fs::write(
            plist,
            fixture.plist(label, &program, &tree.join("state"), ""),
        )
        .expect("a plist");
        fixture.call(&[
            "bootstrap",
            &fixture.domain(),
            plist.to_str().expect("text"),
        ])
    };

    // A folder that is a link to a folder outside holds the working directory and the log.
    std::os::unix::fs::symlink(outside.path(), tree.join("out")).expect("a link");
    let behind = tree.join("home/Library/LaunchAgents/kr-controller-j.plist");
    std::fs::write(
        &behind,
        fixture.plist("kr-controller-j", &program, &tree.join("out"), ""),
    )
    .expect("a plist");
    let refused = fixture.call(&[
        "bootstrap",
        &fixture.domain(),
        behind.to_str().expect("text"),
    ]);
    assert_eq!(refused.status.code(), Some(64), "a folder behind a link");

    // A log that is a link to a file that does not exist would be made outside by a start.
    std::os::unix::fs::symlink(outside.path().join("never"), tree.join("state/daemon.log"))
        .expect("a link");
    let dangling = loaded_from(
        "kr-controller-k",
        &tree.join("home/Library/LaunchAgents/kr-controller-k.plist"),
    );
    assert_eq!(
        dangling.status.code(),
        Some(64),
        "a link that leads nowhere"
    );
    assert!(!outside.path().join("never").exists());
    std::fs::remove_file(tree.join("state/daemon.log")).expect("the link is removed");

    // A plist that is a link to a file outside is refused before it is read.
    let real = outside.path().join("kr-controller-l.plist");
    std::fs::write(
        &real,
        fixture.plist("kr-controller-l", &program, &tree.join("state"), ""),
    )
    .expect("a plist");
    let linked = tree.join("home/Library/LaunchAgents/kr-controller-l.plist");
    std::os::unix::fs::symlink(&real, &linked).expect("a link");
    let refused = fixture.call(&[
        "bootstrap",
        &fixture.domain(),
        linked.to_str().expect("text"),
    ]);
    assert_eq!(refused.status.code(), Some(64), "a plist behind a link");
    assert!(
        text(&refused.stderr).contains("outside the folders"),
        "{}",
        text(&refused.stderr)
    );
}

/// A definition cannot set a variable the harness owns: the home, the temporary directory, the
/// path, and every variable of the product's own prefix, among them the state and runtime
/// directories the daemon finds this test's record by. The definition is refused and never loaded.
#[test]
fn a_definition_that_sets_a_variable_the_harness_owns_is_refused_and_not_loaded() {
    let fixture = Fixture::new();
    for (index, name) in [
        "HOME",
        "TMPDIR",
        "PATH",
        "KR_STATE_DIR",
        "KR_RUNTIME_DIR",
        "KR_MANAGER_STAND_IN",
        "KR_MANAGER_STAND_IN_JOB",
        "KR_SOMETHING_ELSE",
    ]
    .into_iter()
    .enumerate()
    {
        let extra = format!(
            "\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>{name}</key>\n\t\t<string>/x</string>\n\t</dict>\n"
        );
        let label = format!("kr-controller-m{index}");
        let (_, refused) = fixture.load(&label, "#!/bin/sh\nexit 0\n", &extra);
        assert_eq!(refused.status.code(), Some(64), "{name}");
        assert!(text(&refused.stderr).contains(name), "{name}");
        let listed = fixture.call(&["print", &format!("{}/{label}", fixture.domain())]);
        assert_eq!(listed.status.code(), Some(113), "{name} is not loaded");
    }
}

/// Every call is one whole line of the log, numbered once, whatever the calls' timing.
#[test]
fn calls_made_together_are_logged_as_whole_lines_each_with_its_own_number() {
    let fixture = Fixture::new();
    let gui = format!("gui/{}", fixture.uid);
    std::thread::scope(|scope| {
        for _ in 0..12 {
            scope.spawn(|| {
                let answered = fixture.call(&["print", &gui]);
                assert_eq!(answered.status.code(), Some(112));
            });
        }
    });
    let mut numbers: Vec<u64> = fixture
        .calls()
        .iter()
        .map(|line| {
            let value: serde_json::Value =
                serde_json::from_str(line).unwrap_or_else(|error| panic!("{line}: {error}"));
            value["number"].as_u64().expect("a number")
        })
        .collect();
    numbers.sort_unstable();
    assert_eq!(numbers, (1..=12).collect::<Vec<u64>>());
}
