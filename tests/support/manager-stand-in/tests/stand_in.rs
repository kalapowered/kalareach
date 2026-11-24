//! The stand-in service manager, run as `kr` and the daemon run it: by its program, in a test tree of
//! its own, with the state directory the caller names. The cases read the process list and the
//! system's own programs as macOS prints and protects them, which is where the stand-in is used.
#![cfg(target_os = "macos")]

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use kr_ipc::testing::PrivateTempDir;
use kr_ipc::testing::manager_stand_in::{PROGRAM_NAME, place_installation};

/// A test tree and an installation beside it, both of this case's own.
struct Fixture {
    tree: PrivateTempDir,
    installation: PrivateTempDir,
    program: PathBuf,
    uid: u32,
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
        }
    }

    /// The stand-in run with `arguments`, from a caller that names this tree's state directory.
    fn call(&self, arguments: &[&str]) -> Output {
        Command::new(&self.program)
            .args(arguments)
            .env_clear()
            .env("HOME", self.tree.path().join("home"))
            .env("TMPDIR", self.tree.path())
            .env(
                kr_ipc::paths::STATE_DIR_VARIABLE,
                self.tree.path().join("state"),
            )
            .stdin(Stdio::null())
            .output()
            .expect("the stand-in runs")
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
        let log = directory.join("daemon.log");
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <!-- The KalaReach control daemon. -->\n\
             <plist version=\"1.0\">\n<dict>\n\
             \t<key>Label</key>\n\t<string>{label}</string>\n\
             \t<key>ProgramArguments</key>\n\t<array>\n\
             \t\t<string>{}</string>\n\t\t<string>--runtime-dir</string>\n\t\t<string>{}</string>\n\
             \t\t<string>--state-dir</string>\n\t\t<string>{}</string>\n\t</array>\n\
             \t<key>RunAtLoad</key>\n\t<false/>\n\t<key>KeepAlive</key>\n\t<false/>\n\
             \t<key>LimitLoadToSessionType</key>\n\t<string>Background</string>\n\
             \t<key>ProcessType</key>\n\t<string>Interactive</string>\n\
             \t<key>WorkingDirectory</key>\n\t<string>{}</string>\n\
             \t<key>Umask</key>\n\t<integer>63</integer>\n{extra}\
             \t<key>StandardOutPath</key>\n\t<string>{}</string>\n\
             \t<key>StandardErrorPath</key>\n\t<string>{}</string>\n</dict>\n</plist>\n",
            program.display(),
            self.tree.path().join("r").display(),
            self.tree.path().join("state").display(),
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
    let gone = Command::new("/bin/ps")
        .args(["-o", "pid=", "-p", &pid.to_string()])
        .output()
        .expect("ps runs");
    assert!(text(&gone.stdout).trim().is_empty(), "the daemon was ended");
    assert_eq!(
        fixture.call(&["print", &target]).status.code(),
        Some(113),
        "the job is unloaded"
    );
}

/// A start that was never recorded is found by the token in its environment and ended: the stand-in
/// or the test died between the start and the record.
#[test]
fn a_start_that_was_never_recorded_is_found_by_its_token_and_ended() {
    let fixture = Fixture::new();
    let (_, loaded) = fixture.load("kr-controller-h", "#!/bin/sh\nexit 0\n", "");
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    let record = fixture
        .tree
        .path()
        .join("state/manager-stand-in/jobs/kr-controller-h.json");
    let mut job: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&record).expect("the record")).expect("json");
    job["pending"] = serde_json::Value::String("00ff00ff".to_owned());
    std::fs::write(&record, job.to_string()).expect("a pending record");
    // The shell ends at once, so the process it started belongs to the system's own first process,
    // which collects it, as it would a daemon the stand-in started. A copy of the program is
    // started, since the system shows no environment of a program of its own.
    let own_sleep = fixture.installation.path().join("sleep");
    kr_ipc::testing::place_program(Path::new("/bin/sleep"), &own_sleep);
    let started = Command::new("/bin/sh")
        .args([
            "-c",
            &format!(
                "{} 120 </dev/null >/dev/null 2>&1 & echo $!",
                own_sleep.display()
            ),
        ])
        .env("KR_MANAGER_STAND_IN_JOB", "kr-controller-h/00ff00ff")
        .stdin(Stdio::null())
        .output()
        .expect("a process of the start");
    let pid = text(&started.stdout).trim().to_owned();
    let target = format!("{}/kr-controller-h", fixture.domain());
    let ended = fixture.call(&["bootout", &target]);
    assert_eq!(ended.status.code(), Some(0), "{}", text(&ended.stderr));
    let gone = Command::new("/bin/ps")
        .args(["-o", "pid=", "-p", &pid])
        .output()
        .expect("ps runs");
    assert!(
        text(&gone.stdout).trim().is_empty(),
        "the process {pid} was found by its token and ended"
    );
}

/// A start whose process still shows the arguments of the definition and no token, as the wrapper
/// does while the system's shell reads it, is found by those arguments and ended.
#[test]
fn a_start_that_was_never_recorded_is_found_by_its_arguments_and_ended() {
    let fixture = Fixture::new();
    let script = "#!/bin/sh\nwhile :; do sleep 1; done\n";
    let (_, loaded) = fixture.load("kr-controller-i", script, "");
    assert_eq!(loaded.status.code(), Some(0), "{}", text(&loaded.stderr));
    let record = fixture
        .tree
        .path()
        .join("state/manager-stand-in/jobs/kr-controller-i.json");
    let mut job: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&record).expect("the record")).expect("json");
    job["pending"] = serde_json::Value::String("00ff00fe".to_owned());
    std::fs::write(&record, job.to_string()).expect("a pending record");
    let program = fixture.installation.path().join("kr-daemon");
    let started = Command::new("/bin/sh")
        .args([
            "-c",
            &format!(
                "{} --runtime-dir {} --state-dir {} </dev/null >/dev/null 2>&1 & echo $!",
                program.display(),
                fixture.tree.path().join("r").display(),
                fixture.tree.path().join("state").display()
            ),
        ])
        .stdin(Stdio::null())
        .output()
        .expect("a process of the start");
    let pid = text(&started.stdout).trim().to_owned();
    let target = format!("{}/kr-controller-i", fixture.domain());
    let ended = fixture.call(&["bootout", &target]);
    assert_eq!(ended.status.code(), Some(0), "{}", text(&ended.stderr));
    let gone = Command::new("/bin/ps")
        .args(["-o", "pid=", "-p", &pid])
        .output()
        .expect("ps runs");
    assert!(
        text(&gone.stdout).trim().is_empty(),
        "the process {pid} was found by its arguments and ended"
    );
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
