//! The stand-in service manager, run as `kr` and the daemon run it: by its program, in a test tree of
//! its own, with the state directory the caller names. The cases read the process list and the
//! system's own programs as macOS prints and protects them, which is where the stand-in is used.
#![cfg(target_os = "macos")]

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_ipc::identity::{
    ProcessState, Stop, children_of, process_state, processes_in_group, started_process_identity,
    stop_process,
};
use kr_ipc::testing::PrivateTempDir;
use kr_ipc::testing::manager_stand_in::{PROGRAM_NAME, place_installation};
use kr_protocol::identity::ProcessStartIdentity;

/// A test tree and an installation beside it, both of this case's own.
///
/// When the fixture is dropped, which is when a case ends whether it passed or failed, it ends every
/// process the case or the stand-in started for it, each by identity: those the case started itself
/// through [`Fixture::detached`] and tracked, every process the stand-in wrote down as it started
/// it (which holds whatever came of the record of its job), the daemons of the jobs' records, and
/// the members of the groups those lead, read as the stand-in reads a group. A process it cannot
/// show to have ended, a group or a record it cannot read, and a line of the file of starts that is
/// not a start fail the case.
///
/// Six readings are single, with no second reading to show that the process is the same one: the
/// identity [`Fixture::detached`] reads of the process its shell started; the identity of each
/// `sleep` that `idle` starts, which the one case that tracks them reads once; the identity of the
/// process a daemon's script started, which three cases read once from the number the script wrote;
/// and the identity of the `sleep` that the case of an unreadable group starts through a shell.
/// Each is read just after its process starts, and all but the `sleep`s of `idle`, which end within
/// a second, run for as long as their case lets them. A number that passes to another process
/// between the start of a process and its one reading is not guarded against.
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
        let mut known = std::mem::take(
            self.started
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner),
        );
        let mut problems = Vec::new();
        match self.recorded_daemons() {
            Ok(daemons) => known.extend(daemons),
            Err(why) => problems.push(why),
        }
        match kr_manager_stand_in::read_started(&self.started_file()) {
            Ok(starts) => known.extend(starts.into_iter().map(|start| start.identity)),
            Err(why) => problems.push(why),
        }
        known.sort();
        known.dedup();
        problems.extend(end_everything(
            &known,
            &kr_manager_stand_in::members_of_group,
        ));
        if !problems.is_empty() {
            let said = format!("the fixture could not end every process of the case: {problems:?}");
            if std::thread::panicking() {
                eprintln!("{said}");
            } else {
                panic!("{said}");
            }
        }
    }
}

/// Ends every process of `known` and of the groups they lead, each by identity, and says what it
/// could not do: a group that `members` cannot read, and a process that is not shown to have ended.
fn end_everything(
    known: &[ProcessStartIdentity],
    members: &dyn Fn(&ProcessStartIdentity) -> Result<Vec<ProcessStartIdentity>, String>,
) -> Vec<String> {
    let mut problems = Vec::new();
    let mut everything = known.to_vec();
    // A member started while the others were being ended is found by the next pass.
    for _ in 0..5 {
        for leader in known {
            match members(leader) {
                Ok(found) => everything.extend(found),
                Err(why) => problems.push(format!(
                    "the group of the process {} cannot be read: {why}",
                    leader.pid.get()
                )),
            }
        }
        everything.sort();
        everything.dedup();
        for identity in &everything {
            let _ = stop_process(identity, Stop::Kill);
        }
    }
    problems.sort();
    problems.dedup();
    let alive: Vec<_> = everything
        .iter()
        .filter(|identity| !ended(identity))
        .collect();
    if !alive.is_empty() {
        problems.push(format!("not shown to have ended: {alive:?}"));
    }
    problems
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

    /// The processes the stand-in recorded as the daemons of its jobs. A record that cannot be read
    /// is an error.
    fn recorded_daemons(&self) -> Result<Vec<ProcessStartIdentity>, String> {
        let folder = self.tree.path().join("state/manager-stand-in/jobs");
        let entries = match std::fs::read_dir(&folder) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("{} cannot be read: {error}", folder.display())),
        };
        let mut daemons = Vec::new();
        for entry in entries {
            let path = entry
                .map_err(|error| format!("{} cannot be read: {error}", folder.display()))?
                .path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let job: kr_manager_stand_in::Job = std::fs::read_to_string(&path)
                .map_err(|error| error.to_string())
                .and_then(|record| serde_json::from_str(&record).map_err(|error| error.to_string()))
                .map_err(|why| format!("the record {} cannot be read: {why}", path.display()))?;
            daemons.extend(job.identity);
        }
        Ok(daemons)
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

    /// The file in which the stand-in writes down each process it starts.
    fn started_file(&self) -> PathBuf {
        self.tree
            .path()
            .join("state/manager-stand-in")
            .join(kr_manager_stand_in::STARTED_FILE)
    }

    /// The processes the stand-in wrote down as it started them, whatever came of their jobs'
    /// records. A line that is not a start fails the case.
    fn written_down(&self) -> Vec<kr_manager_stand_in::Started> {
        kr_manager_stand_in::read_started(&self.started_file())
            .unwrap_or_else(|why| panic!("the starts the stand-in wrote down: {why}"))
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

    /// The record of the job `label` as a start whose process was never kept leaves it: the job is
    /// loaded and names no process.
    fn lose_identity(&self, label: &str) {
        let record = self
            .tree
            .path()
            .join(format!("state/manager-stand-in/jobs/{label}.json"));
        let mut job: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&record).expect("the record"))
                .expect("json");
        job["identity"] = serde_json::Value::Null;
        std::fs::write(&record, job.to_string()).expect("a record that names no process");
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

/// Places the program `idle` at `path`: it waits as many seconds as its first argument says, a
/// second at a time.
fn place_idle(path: &Path) {
    kr_ipc::testing::place_script(
        path,
        "#!/bin/sh\ni=0\nwhile [ \"$i\" -lt \"$1\" ]; do sleep 1; i=$((i + 1)); done\n",
    );
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
        [".wait_with_", "output()"].concat(),
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

/// The graphical domain is one the user does not have, whatever is loaded in the background domain:
/// `print`, `kickstart` and `bootout` of a job in it answer 112 and name the domain, as `print` does
/// for the domain itself, and the job stays loaded in its own domain.
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
            Some(112),
            "{arguments:?}: {}",
            text(&answered.stderr)
        );
        assert!(
            text(&answered.stderr)
                .contains(&format!("Could not find domain for gui/{}", fixture.uid)),
            "{arguments:?} names the absent domain: {}",
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

/// A daemon that handed over by `exec` to a second program of the installation is ended by `bootout`
/// though its record names no process: the stand-in wrote the process down with the job's label as it
/// started it, and an `exec` leaves the identity of a process as it was.
#[test]
fn bootout_ends_a_daemon_that_handed_over_by_exec_though_its_record_names_no_process() {
    let fixture = Fixture::new();
    let second = fixture.installation.path().join("second");
    let flag = fixture.tree.path().join("handed-over");
    kr_ipc::testing::place_script(
        &second,
        format!(
            "#!/bin/sh\necho up > {}\nwhile :; do sleep 1; done\n",
            flag.display()
        ),
    );
    let (_, loaded) = fixture.load(
        "kr-controller-e",
        &format!("#!/bin/sh\nexec {} \"$@\"\n", second.display()),
        "",
    );
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    let target = format!("{}/kr-controller-e", fixture.domain());
    let started = fixture.call(&["kickstart", "-p", &target]);
    assert_eq!(started.status.code(), Some(0), "{}", text(&started.stderr));
    let deadline = Instant::now() + Duration::from_secs(20);
    while !flag.exists() {
        assert!(
            Instant::now() < deadline,
            "the job's program never handed over to the second program"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let written = fixture.written_down();
    assert_eq!(written.len(), 1, "one start, written down: {written:?}");
    assert_eq!(written[0].label, "kr-controller-e");
    let daemon = written[0].identity.clone();
    fixture.lose_identity("kr-controller-e");
    assert_eq!(process_state(&daemon), ProcessState::Running);
    let ended_job = fixture.call(&["bootout", &target]);
    assert_eq!(
        ended_job.status.code(),
        Some(0),
        "{}",
        text(&ended_job.stderr)
    );
    assert!(
        ended(&daemon),
        "the daemon that handed over by exec was left running when its record named no process"
    );
}

/// `bootout` ends the processes written down for its own job and for no other job.
#[test]
fn bootout_ends_the_processes_written_down_for_its_job_and_for_no_other_job() {
    let fixture = Fixture::new();
    let script = "#!/bin/sh\nwhile :; do sleep 1; done\n";
    let mut daemons = Vec::new();
    for label in ["kr-controller-a", "kr-controller-b"] {
        let (_, loaded) = fixture.load(label, script, "");
        assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
        let target = format!("{}/{label}", fixture.domain());
        let started = fixture.call(&["kickstart", "-p", &target]);
        assert_eq!(started.status.code(), Some(0), "{}", text(&started.stderr));
        let daemon = fixture
            .written_down()
            .into_iter()
            .find(|started| started.label == label)
            .expect("the start of the job, written down")
            .identity;
        daemons.push(daemon);
    }
    let target = format!("{}/kr-controller-a", fixture.domain());
    let ended_job = fixture.call(&["bootout", &target]);
    assert_eq!(
        ended_job.status.code(),
        Some(0),
        "{}",
        text(&ended_job.stderr)
    );
    assert!(ended(&daemons[0]), "the daemon of the job was ended");
    assert_eq!(
        process_state(&daemons[1]),
        ProcessState::Running,
        "the daemon of another job was ended with it"
    );
    let target = format!("{}/kr-controller-b", fixture.domain());
    let ended_job = fixture.call(&["bootout", &target]);
    assert_eq!(
        ended_job.status.code(),
        Some(0),
        "{}",
        text(&ended_job.stderr)
    );
    assert!(ended(&daemons[1]), "the daemon of the other job was ended");
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

/// `bootout` ends what a daemon left when it ended: a wrapper that exits at once and leaves a child
/// running in its group does not end the job's duty to that child, and the job is unloaded only
/// once the child has ended.
#[test]
fn bootout_ends_the_processes_a_daemon_left_behind_when_it_ended() {
    let fixture = Fixture::new();
    let child_file = fixture.tree.path().join("child.pid");
    let script = format!(
        "#!/bin/sh\nsleep 60 &\necho $! > {}\nexit 0\n",
        child_file.display()
    );
    let (_, loaded) = fixture.load("kr-controller-w", &script, "");
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    let target = format!("{}/kr-controller-w", fixture.domain());
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
    let wrapper = fixture
        .recorded_daemons()
        .expect("the records of the jobs")
        .pop()
        .expect("the daemon the stand-in recorded");
    assert!(ended(&wrapper), "the wrapper exits and leaves its child");
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
        "the process the daemon left when it ended was left running and the job was unloaded"
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
    let mut identities = fixture.recorded_daemons().expect("the records of the jobs");
    identities.push(own_loop);
    std::fs::write(
        list,
        serde_json::to_string(&identities).expect("the identities as text"),
    )
    .expect("the list is written");
    panic!("this case fails on purpose, before it ends anything it started");
}

/// A daemon whose record never reached its job is ended with the case, and so is what it started
/// and what the case's own `idle` program started: the stand-in wrote the daemon down as it started
/// it, and the fixture ends the members of its group. The case that loses the record runs in a child
/// test process, and lists the processes before it fails.
#[test]
fn a_daemon_whose_record_was_lost_and_what_it_started_are_ended_with_the_case() {
    let folder = PrivateTempDir::create();
    let list = folder.path().join("started.json");
    let child = run(
        Command::new(std::env::current_exe().expect("this test program"))
            .args([
                "--ignored",
                "--exact",
                "a_case_that_loses_a_daemons_record_and_fails",
                "--test-threads=1",
            ])
            .env(LIST_VARIABLE, &list),
    );
    let said = text(&child.stdout);
    let started: Vec<ProcessStartIdentity> =
        serde_json::from_str(&std::fs::read_to_string(&list).expect("the list of what it started"))
            .expect("a list");
    let leftovers = Leftovers(started.clone());
    assert!(
        said.contains("this case fails on purpose") && child.status.code() == Some(101),
        "the child case fails on purpose and for no other reason: {said}"
    );
    assert!(
        started.len() >= 3,
        "the daemon, what it started and what idle started: {started:?}"
    );
    for identity in &started {
        assert!(
            ended(identity),
            "a process of the case is still alive after its record was lost: {identity:?}"
        );
    }
    drop(leftovers);
}

/// Run by the case above, in a child test process: it starts a daemon that starts a long-lived
/// process of its own, loses the daemon's record, starts the `idle` program, lists what it started
/// and fails before it ends any of it.
#[test]
#[ignore = "run by the case that shows a lost record leaves nothing alive"]
fn a_case_that_loses_a_daemons_record_and_fails() {
    let Some(list) = std::env::var_os(LIST_VARIABLE) else {
        return;
    };
    let fixture = Fixture::new();
    let child_file = fixture.tree.path().join("child.pid");
    let script = format!(
        "#!/bin/sh\nsleep 7300 &\necho $! > {}\nwhile :; do sleep 1; done\n",
        child_file.display()
    );
    let (_, loaded) = fixture.load("kr-controller-l", &script, "");
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    let target = format!("{}/kr-controller-l", fixture.domain());
    let started = fixture.call(&["kickstart", "-p", &target]);
    assert_eq!(started.status.code(), Some(0), "{}", text(&started.stderr));
    let daemon = fixture
        .recorded_daemons()
        .expect("the records of the jobs")
        .pop()
        .expect("the daemon the stand-in recorded");
    let deadline = Instant::now() + Duration::from_secs(20);
    let descendant = loop {
        if let Some(pid) = std::fs::read_to_string(&child_file)
            .ok()
            .and_then(|written| written.trim().parse::<u32>().ok())
        {
            break started_process_identity(pid).expect("the process the daemon started");
        }
        assert!(Instant::now() < deadline, "the daemon started no process");
        std::thread::sleep(Duration::from_millis(50));
    };
    // The record the case failed to publish: the job has none that names the daemon.
    std::fs::remove_file(
        fixture
            .tree
            .path()
            .join("state/manager-stand-in/jobs/kr-controller-l.json"),
    )
    .expect("the record is removed");
    assert!(
        fixture
            .recorded_daemons()
            .expect("the records of the jobs")
            .is_empty()
    );
    let idle = fixture.installation.path().join("idle");
    place_idle(&idle);
    let state = fixture.tree.path().join("state");
    let waiting = fixture.detached(&format!("{} 7301", idle.display()), &state, &[]);
    let pid = u32::try_from(waiting.pid.get()).expect("a number");
    let mut listed = vec![daemon, descendant, waiting];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let children: Vec<ProcessStartIdentity> = children_of(pid)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|child| started_process_identity(child).ok())
            .collect();
        if !children.is_empty() {
            listed.extend(children);
            break;
        }
        assert!(Instant::now() < deadline, "idle started no process");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::fs::write(
        list,
        serde_json::to_string(&listed).expect("the identities as text"),
    )
    .expect("the list is written");
    panic!("this case fails on purpose, after its daemon's record was lost");
}

/// The variable that tells a case that fails on purpose that another case has run it, in a child
/// test process.
const CHILD_VARIABLE: &str = "KR_STAND_IN_TEST_AS_CHILD";

/// Runs the case `name`, which does nothing unless another case runs it, in a child test process.
fn run_as_child(name: &str) -> Output {
    run(
        Command::new(std::env::current_exe().expect("this test program"))
            .args(["--ignored", "--exact", name, "--test-threads=1"])
            .env(CHILD_VARIABLE, "1"),
    )
}

/// A line of the file of starts that is not a start fails the case: the fixture does not end the
/// case as if it had ended every process when it cannot read which processes the stand-in started.
#[test]
fn a_line_of_the_file_of_starts_that_is_not_a_start_fails_the_case() {
    let child = run_as_child("a_case_that_leaves_a_line_that_is_not_a_start");
    let said = text(&child.stdout);
    assert_eq!(
        child.status.code(),
        Some(101),
        "the child case does not fail: {said}"
    );
    assert!(
        said.contains("the fixture could not end every process of the case")
            && said.contains("is not a start"),
        "the child case fails for another reason: {said}"
    );
}

/// Run by the case above, in a child test process: it leaves a line that is not a start in the file
/// of starts and ends.
#[test]
#[ignore = "run by the case that shows a line that is not a start fails the case"]
fn a_case_that_leaves_a_line_that_is_not_a_start() {
    if std::env::var_os(CHILD_VARIABLE).is_none() {
        return;
    }
    let fixture = Fixture::new();
    let file = fixture.started_file();
    std::fs::create_dir_all(file.parent().expect("a folder")).expect("the stand-in's folder");
    std::fs::write(&file, "this is not a start\n").expect("a line that is not a start");
}

/// A process the fixture cannot end fails the case: the fixture does not end the case as if it had
/// ended every process when one is still there.
#[test]
fn a_process_the_fixture_cannot_end_fails_the_case() {
    let child = run_as_child("a_case_that_leaves_a_process_the_fixture_cannot_end");
    let said = text(&child.stdout);
    assert_eq!(
        child.status.code(),
        Some(101),
        "the child case does not fail: {said}"
    );
    assert!(
        said.contains("the fixture could not end every process of the case")
            && said.contains("not shown to have ended"),
        "the child case fails for another reason: {said}"
    );
}

/// Run by the case above, in a child test process: its fixture is told to end the test process
/// itself, which nothing may end, and the case ends.
#[test]
#[ignore = "run by the case that shows a process the fixture cannot end fails the case"]
fn a_case_that_leaves_a_process_the_fixture_cannot_end() {
    if std::env::var_os(CHILD_VARIABLE).is_none() {
        return;
    }
    let fixture = Fixture::new();
    fixture.track(&started_process_identity(std::process::id()).expect("this process"));
}

/// A group the fixture cannot read is a problem of the case and not an empty group, and the
/// processes it did find are ended all the same.
#[test]
fn a_group_the_fixture_cannot_read_is_a_problem_and_not_an_empty_group() {
    let started =
        run(Command::new("/bin/sh")
            .args(["-c", "/bin/sleep 30 </dev/null >/dev/null 2>&1 & echo $!"]));
    let pid: u32 = text(&started.stdout)
        .trim()
        .parse()
        .expect("a process number");
    let sleeping = started_process_identity(pid).expect("the process is there");
    let leftovers = Leftovers(vec![sleeping.clone()]);
    let problems = end_everything(std::slice::from_ref(&sleeping), &|_| {
        Err("the system would not list the group".to_owned())
    });
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("cannot be read")
                && problem.contains("the system would not list the group")),
        "a group that cannot be read was taken for an empty one: {problems:?}"
    );
    assert!(ended(&sleeping), "the process that was found was not ended");
    drop(leftovers);
}

/// A `bootout` that fails keeps the job: a line of the file of starts that cannot be read leaves it
/// not known whose the line is, so the answer is a failure, and the job is still loaded.
#[test]
fn a_bootout_that_fails_keeps_the_job_loaded() {
    let fixture = Fixture::new();
    let (_, loaded) = fixture.load("kr-controller-f", "#!/bin/sh\nexit 0\n", "");
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    let file = fixture.started_file();
    std::fs::write(&file, "this is not a start\n").expect("a line that is not a start");
    let target = format!("{}/kr-controller-f", fixture.domain());
    let failed = fixture.call(&["bootout", &target]);
    assert_eq!(
        failed.status.code(),
        Some(64),
        "a bootout that cannot read the starts fails: {}",
        text(&failed.stderr)
    );
    assert!(
        text(&failed.stderr).contains("is not a start"),
        "{}",
        text(&failed.stderr)
    );
    let listed = fixture.call(&["print", &target]);
    assert_eq!(
        listed.status.code(),
        Some(0),
        "the job of a bootout that failed is still loaded: {}",
        text(&listed.stderr)
    );
    // The fixture reads the file when the case ends, and holds no line that is not a start.
    std::fs::remove_file(&file).expect("the file is removed");
}

/// A start that cannot be written down fails the call and ends the process it began and the group
/// that process leads: with a folder in the place of the file of starts, no process of the daemon is
/// left in the group it led.
#[test]
fn a_start_that_cannot_be_written_down_ends_the_process_and_its_group() {
    let fixture = Fixture::new();
    let (_, loaded) = fixture.load("kr-controller-w", "#!/bin/sh\nsleep 5 &\nwait\n", "");
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    let file = fixture.started_file();
    std::fs::create_dir_all(&file).expect("a folder in the place of the file of starts");
    let target = format!("{}/kr-controller-w", fixture.domain());
    let failed = fixture.call(&["kickstart", "-p", &target]);
    let said = text(&failed.stderr);
    assert_eq!(
        failed.status.code(),
        Some(64),
        "a start that cannot be written down fails: {said}"
    );
    assert!(
        said.contains("cannot be written down") && said.contains("it and its group were ended"),
        "the start does not say that the process and its group were ended: {said}"
    );
    let pid: u32 = said
        .split("the start of the process ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|number| number.parse().ok())
        .expect("the number of the process in the answer");
    assert!(
        processes_in_group(pid).expect("the group").is_empty(),
        "a process of the group the daemon led is still there"
    );
    // The fixture reads the file of starts when the case ends, so the folder goes first.
    std::fs::remove_dir(&file).expect("the folder is removed");
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
