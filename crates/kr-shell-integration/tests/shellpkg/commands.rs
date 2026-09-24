//! The commands a line runs: the question in front of each, the launcher an answer can name, the
//! block each line reports and the capability it holds.
//!
//! Section 12 has an opt-in command integration establish the worker's backend before the program
//! starts, keep the command name and the argument vector the person typed, and leave scripts alone.
//! Section 25 has the shell report each command block with its status, duration and directory.
//! Each case below drives one of those through the built shell, with the worker's side of the
//! session played here: the answers are the worker's own decision, a backend it established, or
//! silence.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_protocol::root::{
    CommandBypassReason, DETACH_HINT, LAUNCH_READER_BUDGET, LaunchCommand, RootCommandResolveParams,
};
use kr_protocol::session::{CommandIntegration, EnvironmentVariable};
use kr_shell_integration::contract::events::ConsumeReason;
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::contract::requests::{
    LaunchMailboxRequest, LaunchRejectionReason, LaunchTransactionId,
};

use super::*;

/// How long a shell waits for an answer before it runs a command as it was typed.
///
/// The packages' own constant, restated so a package that waited less, or not at all, fails here.
pub const ANSWER_WAIT: Duration = Duration::from_millis(1000);

/// Programs a case runs, in a directory of the case's own on the internal disk, and what each
/// recorded about how it was started.
pub struct Probes {
    _directory: tempfile::TempDir,
    root: PathBuf,
}

/// One start of a recording program: the arguments after its own name, and the reserved variables
/// it was started with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeRun {
    pub arguments: Vec<String>,
    pub environment: BTreeMap<String, String>,
}

impl ProbeRun {
    /// The reserved variables this start saw, by name.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.environment.keys().map(String::as_str).collect()
    }
}

/// Writes a program that records its arguments and every reserved variable it was started with,
/// then prints a word it puts together from two pieces.
fn write_recorder(path: &Path, record: &Path, head: &str, tail: &str) {
    let script = format!(
        "#!/bin/sh\n\
         {{\n\
         printf 'run\\n'\n\
         for word in \"$@\"; do printf 'arg %s\\n' \"$word\"; done\n\
         env | LC_ALL=C sort | while IFS= read -r line; do\n\
         case $line in KR_*) printf 'env %s\\n' \"$line\" ;; esac\n\
         done\n\
         printf 'end\\n'\n\
         }} >> '{record}'\n\
         printf '%s%s\\n' '{head}' '{tail}'\n",
        record = record.display()
    );
    std::fs::write(path, script).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    run_once(path, record);
}

/// Starts a program that has just been written once, here, and forgets what it recorded.
///
/// Some systems check a program the first time anything starts it, and on a busy machine that
/// check can outlast a reply window. It is paid here, outside every timed wait, rather than by the
/// shell a case is timing.
pub fn run_once(path: &Path, record: &Path) {
    let status = std::process::Command::new(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap_or_else(|error| panic!("{} does not start: {error}", path.display()));
    assert!(
        status.success(),
        "{} failed its first start",
        path.display()
    );
    let _ = std::fs::remove_file(record);
}

/// Reads what a recording program wrote, one start at a time.
///
/// An argument need not be text, so a byte that is not part of one reads as U+FFFD.
fn read_runs(record: &Path) -> Vec<ProbeRun> {
    let Ok(bytes) = std::fs::read(record) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut runs = Vec::new();
    let mut current: Option<ProbeRun> = None;
    for line in text.lines() {
        match line {
            "run" => {
                current = Some(ProbeRun {
                    arguments: Vec::new(),
                    environment: BTreeMap::new(),
                });
            }
            "end" => runs.extend(current.take()),
            _ => {
                let Some(run) = current.as_mut() else {
                    continue;
                };
                if let Some(argument) = line.strip_prefix("arg ") {
                    run.arguments.push(argument.to_owned());
                } else if let Some((name, value)) = line
                    .strip_prefix("env ")
                    .and_then(|pair| pair.split_once('='))
                {
                    run.environment.insert(name.to_owned(), value.to_owned());
                }
            }
        }
    }
    runs
}

impl Probes {
    /// Makes the directory, the recording program on the path, a stand-in for the launcher off the
    /// path, a script that runs the program, and a directory to move to.
    ///
    /// # Panics
    ///
    /// Panics when the directory cannot be made on the internal disk.
    #[must_use]
    pub fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("kr-probes-")
            .tempdir()
            .expect("a directory on the internal disk");
        // The name the kernel gives it, which is the one a shell reports.
        let root = std::fs::canonicalize(directory.path()).expect("the directory resolves");
        for sub in ["bin", "other", "launcher", "elsewhere"] {
            std::fs::create_dir(root.join(sub)).expect("a directory for the probes");
        }
        write_recorder(
            &root.join("bin").join("kr-probe"),
            &root.join("probe.record"),
            "probe-",
            "ran",
        );
        write_recorder(
            &root.join("launcher").join("kr-hook"),
            &root.join("launcher.record"),
            "launcher-",
            "ran",
        );
        // The same name in another directory, for a command whose own search path finds it.
        write_recorder(
            &root.join("other").join("kr-probe"),
            &root.join("other.record"),
            "other-",
            "ran",
        );
        // A launcher that is an executable file the system cannot start.
        let broken = root.join("launcher").join("kr-hook-broken");
        std::fs::write(&broken, [0u8, 1, 2, 3]).expect("a launcher that cannot start");
        std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o755))
            .expect("an executable file");
        std::fs::write(root.join("script.sh"), "kr-probe from-a-script\n").expect("a script");
        Self {
            _directory: directory,
            root,
        }
    }

    /// What a shell is started with so that the program is found on its search path.
    #[must_use]
    pub fn environment(&self) -> Vec<(String, String)> {
        let inherited = std::env::var("PATH").unwrap_or_default();
        vec![(
            "PATH".to_owned(),
            format!("{}:{inherited}", self.root.join("bin").display()),
        )]
    }

    /// The recording program, where the search finds it.
    #[must_use]
    pub fn probe(&self) -> PathBuf {
        self.root.join("bin").join("kr-probe")
    }

    /// The stand-in for the launcher, which no search finds.
    #[must_use]
    pub fn launcher(&self) -> PathBuf {
        self.root.join("launcher").join("kr-hook")
    }

    /// A launcher that is an executable file the system cannot start.
    #[must_use]
    pub fn broken_launcher(&self) -> PathBuf {
        self.root.join("launcher").join("kr-hook-broken")
    }

    /// Another directory holding a program of the same name.
    #[must_use]
    pub fn other_directory(&self) -> PathBuf {
        self.root.join("other")
    }

    /// Every start of the program of the same name in the other directory.
    #[must_use]
    pub fn other_runs(&self) -> Vec<ProbeRun> {
        read_runs(&self.root.join("other.record"))
    }

    /// A path in the probes' directory, for a case that needs a file of its own there.
    #[must_use]
    pub fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// A script that runs the program.
    #[must_use]
    pub fn script(&self) -> PathBuf {
        self.root.join("script.sh")
    }

    /// A directory a line can move to.
    #[must_use]
    pub fn elsewhere(&self) -> PathBuf {
        self.root.join("elsewhere")
    }

    /// Every start of the program so far.
    #[must_use]
    pub fn runs(&self) -> Vec<ProbeRun> {
        read_runs(&self.root.join("probe.record"))
    }

    /// Every start of the launcher's stand-in so far.
    #[must_use]
    pub fn launches(&self) -> Vec<ProbeRun> {
        read_runs(&self.root.join("launcher.record"))
    }
}

impl Default for Probes {
    fn default() -> Self {
        Self::new()
    }
}

/// A session of this package's own with the probes on its search path, at an answering prompt.
fn a_session_with_probes(package: &Package, probes: &Probes) -> Session {
    let mut session = Session::start_with(package, &probes.environment());
    session.first_prompt();
    session.forget_events();
    assert!(
        session.answered("kr-ready"),
        "the shell did not answer:\n{}",
        session.terminal_output()
    );
    session
}

impl Session {
    /// Reads what the bridge sends until `ready` holds for what it reported about the commands.
    ///
    /// # Panics
    ///
    /// Panics when it does not hold inside the reply window.
    pub fn until(&mut self, what: &str, ready: impl Fn(&Commands) -> bool) {
        let deadline = Deadline::after(REPLY);
        while !ready(&self.commands) {
            assert!(
                !deadline.passed(),
                "{what} did not arrive; the terminal showed:\n{}",
                self.terminal_output()
            );
            self.pump(Duration::from_millis(25));
        }
    }

    /// Runs `command`, waits for `marker`, and returns the resolves the line asked.
    ///
    /// # Panics
    ///
    /// Panics when the marker does not appear.
    pub fn run_asking(&mut self, command: &str, marker: &str) -> Vec<RootCommandResolveParams> {
        let before = self.commands.resolves.len();
        assert!(
            self.run(command, marker),
            "{command:?} did not print {marker:?}:\n{}",
            self.terminal_output()
        );
        self.commands.resolves[before..].to_vec()
    }
}

/// The last start of the program, which a case has just waited for.
fn last_run(probes: &Probes) -> ProbeRun {
    probes
        .runs()
        .last()
        .cloned()
        .expect("the program recorded its start")
}

/// KR-REQ-12.07, KR-REQ-07.45: an interactive command asks once, before it starts, and a bypass
/// runs it exactly as it was typed.
pub fn an_interactive_command_asks_once_and_runs_as_typed(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);

    // The control: the same program in a pipeline runs in a child the shell forks, and asks
    // nothing. What it was started with is what the shell passes a command it does not ask about.
    let asked = session.run_asking("kr-probe control | cat", "probe-ran");
    assert!(asked.is_empty(), "a pipeline asked: {asked:?}");
    let control = last_run(&probes);

    let asked = session.run_asking("kr-probe one 'two words'", "probe-ran");
    assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
    let request = &asked[0];
    let entry = session.commands.last_line_reader().clone();
    assert_eq!(request.session_id, session.session_id);
    assert_eq!(request.argv, ["kr-probe", "one", "two words"]);
    assert!(request.interactive);
    // What the shell's own search found and where the command runs, at the revision the reader
    // reported for this prompt.
    assert_eq!(request.executable, probes.probe().display().to_string());
    assert_eq!(request.cwd, session.home().display().to_string());
    assert_eq!(request.cwd_revision, entry.cwd_revision);
    assert_eq!(request.prompt_generation, entry.prompt_generation);
    assert_eq!(
        worker_decision(&[], request).bypass.0,
        Some(CommandBypassReason::NotIntegrated)
    );
    let ran = last_run(&probes);
    assert_eq!(
        ran.arguments,
        ["one", "two words"],
        "the vector as it was typed"
    );
    assert_eq!(
        ran.names(),
        control.names(),
        "a bypassed command is started with the shell's own environment and nothing added"
    );

    // A directory the line itself moved to is the one named, at the revision after the move.
    let elsewhere = probes.elsewhere();
    let asked = session.run_asking(
        &format!("cd '{}' && kr-probe moved", elsewhere.display()),
        "probe-ran",
    );
    assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
    let entry = session.commands.last_line_reader().clone();
    assert_eq!(asked[0].prompt_generation, entry.prompt_generation);
    assert_eq!(asked[0].cwd, elsewhere.display().to_string());
    assert_eq!(asked[0].cwd_revision.get(), entry.cwd_revision.get() + 1);

    // A session created with an integration for the name, and no backend behind it, is answered
    // as the worker answers it, and the command still runs as it was typed: no flag, no variable.
    session.commands.policy = ResolvePolicy::Decide(vec![CommandIntegration {
        command: "kr-probe".to_owned(),
        flags: vec!["--kr-integrated".to_owned()],
        enabled: true,
    }]);
    let asked = session.run_asking("kr-probe integrated", "probe-ran");
    assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
    let ResolvePolicy::Decide(integrations) = &session.commands.policy else {
        unreachable!()
    };
    assert_eq!(
        worker_decision(integrations, &asked[0]).bypass.0,
        Some(CommandBypassReason::BackendUnavailable)
    );
    let ran = last_run(&probes);
    assert_eq!(ran.arguments, ["integrated"]);
    assert_eq!(ran.names(), control.names());

    // An argument that is not text cannot be named exactly in a request, so the command runs as
    // it was typed without a question.
    let asked = session.run_asking("kr-probe $'\\xff'", "probe-ran");
    assert!(
        asked.is_empty(),
        "an argument that is not text was asked about: {asked:?}"
    );
    assert_eq!(last_run(&probes).arguments, ["\u{fffd}"]);
}

/// KR-REQ-12.07: only the root shell's own top-level commands ask. A pipeline, a subshell, a
/// command substitution, a background job, a sourced script, a function and an eval run as typed
/// and ask nothing; a script is a process of its own, whose commands ask nothing.
pub fn forms_the_root_shell_does_not_start_itself_never_ask(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);
    let script = probes.script();

    let forms = [
        ("a pipeline", "kr-probe in-a-pipeline | cat".to_owned()),
        ("a subshell", "(kr-probe in-a-subshell)".to_owned()),
        (
            "a command substitution",
            "printf '%s\\n' \"$(kr-probe in-a-substitution)\"".to_owned(),
        ),
        (
            "a background job",
            "kr-probe in-the-background & wait".to_owned(),
        ),
        ("a sourced script", format!(". '{}'", script.display())),
        (
            "a function",
            "kr_probe_function() { kr-probe in-a-function; }; kr_probe_function".to_owned(),
        ),
        ("an eval", "eval 'kr-probe in-an-eval'".to_owned()),
        // The last part of a pipeline can run in the root shell itself: zsh runs a group there,
        // and a redirection of the group's own does not make it any less part of the pipeline.
        (
            "a group at the end of a pipeline",
            "printf x | { kr-probe in-a-group; }".to_owned(),
        ),
        (
            "a redirected group at the end of a pipeline",
            "printf x | { kr-probe in-a-redirected-group; } </dev/null".to_owned(),
        ),
    ];
    let mut forms = forms.to_vec();
    if kind == ShellKind::Bash {
        // Bash runs the last part of a pipeline itself when job control is off and lastpipe is on.
        forms.push((
            "the last part of a pipeline the shell runs itself",
            "set +m; shopt -s lastpipe; printf x | kr-probe in-the-last-part; shopt -u lastpipe; \
             set -m"
                .to_owned(),
        ));
        forms.push((
            "a redirected group as the last part of a pipeline the shell runs itself",
            "set +m; shopt -s lastpipe; printf x | { kr-probe in-the-last-group; } </dev/null; \
             shopt -u lastpipe; set -m"
                .to_owned(),
        ));
    }
    for (form, command) in forms {
        let runs = probes.runs().len();
        let asked = session.run_asking(&command, "probe-ran");
        assert!(asked.is_empty(), "{form} asked: {asked:?}");
        assert_eq!(probes.runs().len(), runs + 1, "{form} ran the program once");
    }

    // A group reading a string is no pipeline, however the shell carries the string to it: it
    // asks.
    let asked = session.run_asking("{ kr-probe from-a-string; } <<<x", "probe-ran");
    assert_eq!(
        asked.len(),
        1,
        "a group reading a string asks once: {asked:?}"
    );
    assert_eq!(last_run(&probes).arguments, ["from-a-string"]);

    // The interpreter a script is started with is a command of the line, so it asks; nothing
    // the script runs does.
    let asked = session.run_asking(&format!("sh '{}'", script.display()), "probe-ran");
    assert_eq!(asked.len(), 1, "only the interpreter asks: {asked:?}");
    assert_eq!(asked[0].argv[0], "sh");
    assert_eq!(last_run(&probes).arguments, ["from-a-script"]);
}

/// KR-REQ-12.07: a command runs the file and the vector its shell would run. Assignments in front
/// of it can change both, so the question names what they select, or is not asked.
///
/// Bash searches with a `PATH` placed in front of the command, and asks about the file that search
/// finds. Zsh applies those assignments only in the child it forks, so it does not ask about such
/// a command at all; `STTY` in front of one runs a command in that child before it starts.
pub fn assignments_in_front_of_a_command_run_what_they_select(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);
    // A backend for whatever is asked about, so a question that named the wrong file would start
    // the launcher in the command's place.
    session.commands.policy = ResolvePolicy::Backend {
        launcher: probes.launcher().display().to_string(),
        environment: Vec::new(),
        added: Vec::new(),
    };
    let other = probes.other_directory();

    let launches = probes.launches().len();
    let asked = session.run_asking(
        &format!(
            "PATH='{}':\"$PATH\" kr-probe from-the-other",
            other.display()
        ),
        match kind {
            ShellKind::Bash => "launcher-ran",
            _ => "other-ran",
        },
    );
    match kind {
        ShellKind::Bash => {
            assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
            assert_eq!(
                asked[0].executable,
                other.join("kr-probe").display().to_string(),
                "the question names the file the command's own search path finds"
            );
            let launched = probes.launches().last().cloned().expect("the launcher ran");
            assert_eq!(
                launched.arguments[2],
                other.join("kr-probe").display().to_string()
            );
        }
        _ => {
            assert!(
                asked.is_empty(),
                "a command with assignments asked: {asked:?}"
            );
            assert_eq!(probes.launches().len(), launches, "the launcher started");
            assert_eq!(
                probes.other_runs().last().map(|run| run.arguments.clone()),
                Some(vec!["from-the-other".to_owned()]),
                "the file the command's own search path finds ran as typed"
            );
        }
    }

    if kind == ShellKind::Zsh {
        for command in [
            "ARGV0=renamed kr-probe with-argv0",
            "STTY=sane kr-probe with-stty",
        ] {
            let launches = probes.launches().len();
            let asked = session.run_asking(command, "probe-ran");
            assert!(asked.is_empty(), "{command:?} asked: {asked:?}");
            assert_eq!(
                probes.launches().len(),
                launches,
                "{command:?} started the launcher"
            );
        }
        assert_eq!(last_run(&probes).arguments, ["with-stty"]);
    }
}

/// KR-REQ-07.44: diagnostics the session names a path for never hold a command up, whatever is at
/// that path.
pub fn diagnostics_that_cannot_be_written_never_hold_a_command_up(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let probes = Probes::new();
    // A pipe that nothing reads, where an ordinary open for writing would wait for a reader.
    let fifo = probes.path("trace.fifo");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo starts");
    assert!(made.success(), "a pipe for the diagnostics");
    let mut environment = probes.environment();
    environment.push((
        "KR_SHELL_BRIDGE_TRACE".to_owned(),
        fifo.display().to_string(),
    ));
    let mut session = Session::start_with(&package, &environment);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));
    let asked = session.run_asking("kr-probe traced", "probe-ran");
    assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
    assert_eq!(last_run(&probes).arguments, ["traced"]);
}

/// KR-REQ-12.07: an absolute-path invocation asks, is answered with the documented bypass, and
/// runs as it was typed.
pub fn an_absolute_path_invocation_runs_as_typed(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);
    let probe = probes.probe().display().to_string();

    let asked = session.run_asking(&format!("'{probe}' by-path"), "probe-ran");
    assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
    assert_eq!(asked[0].argv, [probe.clone(), "by-path".to_owned()]);
    assert_eq!(asked[0].executable, probe);
    assert_eq!(
        worker_decision(&[], &asked[0]).bypass.0,
        Some(CommandBypassReason::AbsolutePath)
    );
    assert_eq!(last_run(&probes).arguments, ["by-path"]);
}

/// KR-REQ-12.07: a worker that does not answer leaves the command running as typed once the
/// deadline has passed, and a worker that has stopped answering is not asked again.
pub fn an_unanswered_question_runs_the_command_as_typed_after_the_deadline(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);

    session.commands.policy = ResolvePolicy::Silent;
    let started = Instant::now();
    let asked = session.run_asking("kr-probe unanswered", "probe-ran");
    let waited = started.elapsed();
    assert_eq!(asked.len(), 1, "the command asked: {asked:?}");
    assert!(
        waited >= ANSWER_WAIT,
        "the command started after {waited:?}, before the answer's deadline"
    );
    // The deadline, and time for a busy machine to schedule the command after it, but no second
    // wait of the same length.
    assert!(
        waited < ANSWER_WAIT * 2 + Duration::from_secs(4),
        "the command started after {waited:?}, long after the answer's deadline"
    );
    assert_eq!(last_run(&probes).arguments, ["unanswered"]);

    // A worker that answers what came after the unanswered question has caught up, so the next
    // command asks again.
    session.commands.policy = ResolvePolicy::default();
    let asked = session.run_asking("kr-probe caught-up", "probe-ran");
    assert_eq!(
        asked.len(),
        1,
        "a worker that has caught up is asked again: {asked:?}"
    );
    assert_eq!(last_run(&probes).arguments, ["caught-up"]);

    // A refusal answers the question it names and nothing else: the command runs as it was typed,
    // and no detach is taken to have been refused.
    session.commands.policy = ResolvePolicy::Refuse;
    let before = session.written();
    let asked = session.run_asking("kr-probe refused", "probe-ran");
    assert_eq!(asked.len(), 1, "the command asked: {asked:?}");
    assert_eq!(last_run(&probes).arguments, ["refused"]);
    assert!(
        !session
            .drew_after(before, DETACH_HINT, Duration::from_millis(500))
            .was_drawn(),
        "a refused question was taken for a refused detach:\n{}",
        session.terminal_output()
    );
    assert!(
        !session.saw_event(Duration::from_millis(200), |event| matches!(
            event,
            kr_shell_integration::contract::events::BridgeEvent::PreEofConsumed(_)
        )),
        "a refused question consumed a gesture"
    );
    session.commands.policy = ResolvePolicy::default();

    // A worker that answers nothing at all is not asked again while an answer is owed: the
    // commands after it run as they were typed without a question.
    session.commands.stuck = true;
    for word in ["after", "and-after"] {
        let asked = session.run_asking(&format!("kr-probe {word}"), "probe-ran");
        assert!(
            asked.is_empty(),
            "a question went to a worker that owes an answer: {asked:?}"
        );
        assert_eq!(last_run(&probes).arguments, [word]);
    }
}

/// KR-REQ-12.07, KR-REQ-07.45: a backend the worker established runs the command through the
/// launcher it names, with the answer's variables and flags and the executable the shell found;
/// a launcher that is not an absolute path to a program leaves the command as it was typed.
pub fn a_backend_runs_the_command_through_the_launcher_it_names(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);
    let asked = session.run_asking("kr-probe control | cat", "probe-ran");
    assert!(asked.is_empty(), "a pipeline asked: {asked:?}");
    let control = last_run(&probes);

    let environment = vec![
        EnvironmentVariable {
            name: "KR_REGISTRATION".to_owned(),
            value: "/run/kr/launch/registration".to_owned(),
        },
        EnvironmentVariable {
            name: "KR_SESSION".to_owned(),
            value: session.session_id.to_string(),
        },
    ];
    let backend = |launcher: String| ResolvePolicy::Backend {
        launcher,
        environment: environment.clone(),
        added: vec!["--kr-integrated".to_owned()],
    };

    session.commands.policy = backend(probes.launcher().display().to_string());
    let runs = probes.runs().len();
    let asked = session.run_asking("kr-probe one 'two words'", "launcher-ran");
    assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
    let launched = probes
        .launches()
        .last()
        .cloned()
        .expect("the launcher recorded its start");
    let probe = probes.probe().display().to_string();
    assert_eq!(
        launched.arguments,
        [
            "launch",
            "--",
            probe.as_str(),
            "kr-probe",
            "one",
            "two words",
            "--kr-integrated"
        ],
        "the launcher is given the executable the shell found and the answer's vector"
    );
    assert_eq!(
        launched
            .environment
            .get("KR_REGISTRATION")
            .map(String::as_str),
        Some("/run/kr/launch/registration")
    );
    assert_eq!(
        launched.environment.get("KR_SESSION"),
        Some(&session.session_id.to_string())
    );
    assert_eq!(
        probes.runs().len(),
        runs,
        "the launcher runs in the program's place"
    );

    // A launcher named by a relative path, or one that is not there, is refused, and the
    // command runs exactly as it was typed.
    for launcher in [
        "kr-hook".to_owned(),
        probes.elsewhere().join("kr-hook").display().to_string(),
    ] {
        session.commands.policy = backend(launcher.clone());
        let launches = probes.launches().len();
        let asked = session.run_asking("kr-probe refused", "probe-ran");
        assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
        assert_eq!(probes.launches().len(), launches, "{launcher} was started");
        let ran = last_run(&probes);
        assert_eq!(ran.arguments, ["refused"], "{launcher}");
        assert_eq!(ran.names(), control.names(), "{launcher}");
    }

    // A launcher that is an executable file the system cannot start leaves the command as it was
    // typed, with the shell's own environment.
    session.commands.policy = backend(probes.broken_launcher().display().to_string());
    let asked = session.run_asking("kr-probe unstartable", "probe-ran");
    assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
    let ran = last_run(&probes);
    assert_eq!(ran.arguments, ["unstartable"]);
    assert_eq!(ran.names(), control.names());
    assert!(!ran.environment.contains_key("KR_REGISTRATION"));

    // The backend's variables were that one child's: the shell exports none of them.
    session.commands.policy = ResolvePolicy::default();
    let asked = session.run_asking("kr-probe afterwards", "probe-ran");
    assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
    let ran = last_run(&probes);
    assert_eq!(ran.arguments, ["afterwards"]);
    assert_eq!(ran.names(), control.names());
    assert!(!ran.environment.contains_key("KR_REGISTRATION"));
}

/// The shell's own `read` reading a line through the editor.
fn reading_through_the_editor(kind: ShellKind) -> &'static str {
    match kind {
        ShellKind::Zsh => "vared -c kr_reply",
        _ => "read -e -r kr_reply",
    }
}

/// KR-REQ-25.05: each line reports one command block when it starts and again when it has
/// finished, with the shell's own status for it, its duration and the directory it ran in. An
/// empty line and the input a running command reads report none.
pub fn each_line_reports_its_block_with_status_duration_and_directory(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);

    let reported = session.commands.blocks.len();
    let command = "kr-probe block; sh -c 'exit 3'";
    assert!(session.run(command, "probe-ran"));
    let entry = session.commands.last_line_reader().clone();
    session.until("the line's finished block", |commands| {
        commands.blocks[reported..]
            .iter()
            .any(|block| block.exit_status.0.is_some())
    });
    let blocks = session.commands.blocks[reported..].to_vec();
    assert_eq!(
        blocks.len(),
        2,
        "one block when the line started and one when it finished: {blocks:?}"
    );
    let (started, finished) = (&blocks[0], &blocks[1]);
    assert_eq!(started.session_id, session.session_id);
    assert_eq!(started.command, command);
    assert_eq!(started.prompt_generation, entry.prompt_generation);
    assert_eq!(started.cwd, session.home().display().to_string());
    assert_eq!(started.cwd_revision, entry.cwd_revision);
    assert!(
        started.exit_status.0.is_none() && started.duration_ms.0.is_none(),
        "a block that has just started has no status and no duration: {started:?}"
    );
    assert_eq!(finished.command, started.command);
    assert_eq!(finished.prompt_generation, started.prompt_generation);
    assert_eq!(finished.started_at_ms, started.started_at_ms);
    assert_eq!(
        finished.exit_status.0.map(|status| status.get()),
        Some(3),
        "the status the shell itself holds for the line"
    );
    assert!(finished.duration_ms.0.is_some(), "{finished:?}");
    assert!(finished.completed_nonzero());

    // A line that succeeds reports that it did.
    let reported = session.commands.blocks.len();
    assert!(session.run("kr-probe fine", "probe-ran"));
    session.until("the line's finished block", |commands| {
        commands.blocks[reported..]
            .iter()
            .any(|block| block.exit_status.0.is_some())
    });
    let blocks = session.commands.blocks[reported..].to_vec();
    assert_eq!(blocks.len(), 2, "{blocks:?}");
    assert_eq!(blocks[1].exit_status.0.map(|status| status.get()), Some(0));

    // A continuation line is part of the line it continues: one block holds both.
    let reported = session.commands.blocks.len();
    session.type_line("kr-probe joined \\");
    assert!(session.run("continued", "probe-ran"));
    session.until("the joined line's finished block", |commands| {
        commands.blocks[reported..]
            .iter()
            .any(|block| block.exit_status.0.is_some())
    });
    let finished = session.commands.blocks[reported..]
        .iter()
        .rev()
        .find(|block| block.exit_status.0.is_some())
        .cloned()
        .expect("a finished block");
    assert_eq!(finished.command, "kr-probe joined \\\ncontinued");
    assert_eq!(last_run(&probes).arguments, ["joined", "continued"]);

    // An empty line runs nothing and reports nothing: the next block is the next command's.
    let reported = session.commands.blocks.len();
    session.type_line("");
    let marker_command = print_assembled(kind, "kr-after-empty");
    assert!(session.run(&marker_command, "kr-after-empty"));
    session.until("the next command's finished block", |commands| {
        commands.blocks[reported..]
            .iter()
            .any(|block| block.exit_status.0.is_some())
    });
    let blocks = session.commands.blocks[reported..].to_vec();
    assert!(
        blocks.iter().all(|block| block.command == marker_command),
        "an empty line reported a block: {blocks:?}"
    );

    // Input a running command reads through the editor is that command's, not a line of its
    // own: the line that asked for it is the one block.
    let reported = session.commands.blocks.len();
    let reading = reading_through_the_editor(kind);
    session.type_line(reading);
    session.type_line("kr-typed-input");
    session.until("the reading line's finished block", |commands| {
        commands.blocks[reported..]
            .iter()
            .any(|block| block.command == reading && block.exit_status.0.is_some())
    });
    let commands: Vec<String> = session.commands.blocks[reported..]
        .iter()
        .map(|block| block.command.clone())
        .collect();
    assert!(
        commands
            .iter()
            .all(|command| !command.contains("kr-typed-input")),
        "the input a command read was reported as a line: {commands:?}"
    );
    assert!(
        commands.iter().all(|command| command == reading),
        "only the line that read the input is reported: {commands:?}"
    );
}

/// KR-REQ-07.84: the commands a line runs are started with the capability the worker minted for
/// that line and no other, which is what `kr detach` with no attachment presents, and a line the
/// worker minted none for has none.
pub fn a_line_exports_the_capability_minted_for_it(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);

    let mut seen = Vec::new();
    for word in ["first", "second"] {
        assert!(session.run(&format!("kr-probe {word}"), "probe-ran"));
        let minted = session
            .commands
            .tokens
            .last()
            .cloned()
            .flatten()
            .expect("the line was answered with a capability");
        let ran = last_run(&probes);
        assert_eq!(
            ran.environment.get("KR_DETACH_TOKEN"),
            Some(&minted),
            "the command was started with its own line's capability"
        );
        seen.push(minted);
    }
    assert_ne!(seen[0], seen[1], "each line holds a capability of its own");

    // A line the worker minted nothing for runs with nothing, not with the last line's.
    session.commands.withhold_tokens = true;
    assert!(session.run("kr-probe none", "probe-ran"));
    let ran = last_run(&probes);
    assert!(
        !ran.environment.contains_key("KR_DETACH_TOKEN"),
        "a line with no capability ran with one: {ran:?}"
    );

    // A bridge that goes while its line runs leaves nothing the next line could present: the
    // capability leaves the environment with its line, bridge or no bridge.
    session.commands.withhold_tokens = false;
    session.commands.policy = ResolvePolicy::CloseEndpoint;
    assert!(session.run("kr-probe as-the-bridge-goes", "probe-ran"));
    assert!(
        last_run(&probes)
            .environment
            .contains_key("KR_DETACH_TOKEN"),
        "the line was answered with its capability before the bridge went"
    );
    assert!(session.run("kr-probe after-the-bridge", "probe-ran"));
    let ran = last_run(&probes);
    assert!(
        !ran.environment.contains_key("KR_DETACH_TOKEN"),
        "a line after the bridge went ran with the last line's capability: {ran:?}"
    );
}

/// KR-REQ-07.34, KR-REQ-07.35: what the worker sends while a shell waits for an answer before a
/// command starts reaches the next reader in the order it came, each frame once, and with nothing
/// more from the worker.
///
/// Launches that cannot install anything are the probes: the reader refuses each one, and it
/// refuses one as `fence_invalid` exactly when the fence the probe names is not the one it holds
/// at that point. A probe between each pair of frames reads the fence at that point, so a frame
/// that was lost, applied early, applied twice or taken out of order shows as a probe answered
/// the other way.
pub fn frames_that_arrive_while_a_command_waits_reach_the_reader_once(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);

    // A gesture at a fenced prompt leaves a detach waiting for the worker's answer, which comes
    // only after the next line has been typed. The fence stays held until the answer arrives.
    let (reader, held) = session.fenced_prompt(4);
    session.type_bytes(CTRL_D);
    let (detach, _) = session.expect_event("eof_detach", |event| {
        matches!(event, BridgeEvent::EofDetach(_))
    });

    let published = fence_for(&reader, fence_id(9), attachment_id(9), epoch(1));
    let probe = |session: &mut Session, fence: FenceId, index: u8| {
        let id = RequestId::new(session.next_request);
        session.next_request += 1;
        let request = BridgeFrame::Request {
            id,
            request: WorkerRequest::Launch(LaunchMailboxRequest {
                session_id: session.session_id,
                transaction: LaunchTransactionId::new(Uuid::from_bytes([0x90 + index; 16])),
                fence_id: fence,
                command: LaunchCommand::Arguments(vec![
                    "echo".to_owned(),
                    "kr-never-installed".to_owned(),
                ]),
                // The prompt the line was typed at, which is never the reader's by the time the
                // probe is read: whatever else holds, nothing is installed.
                expected_prompt_generation: reader.prompt_generation,
                expected_buffer_revision: reader.editor.buffer_revision,
                expected_cwd_revision: reader.cwd_revision,
                deadline_ms: LAUNCH_READER_BUDGET,
            }),
        };
        (id, request)
    };
    // Ahead of the acceptance's answer: the held fence probed, the detach's refusal, the held
    // fence probed again. Ahead of the resolve's: another fence published, probed, withdrawn and
    // probed again.
    let (before_refusal, first) = probe(&mut session, held.fence_id, 1);
    let (after_refusal, second) = probe(&mut session, held.fence_id, 2);
    session.commands.before_acceptance_answer = vec![
        first,
        BridgeFrame::EventResult {
            id: detach,
            result: detach_refusal(),
        },
        second,
    ];
    let (after_publication, third) = probe(&mut session, published.fence_id, 3);
    let (after_withdrawal, fourth) = probe(&mut session, published.fence_id, 4);
    session.commands.before_resolve_answer = vec![
        BridgeFrame::FencePublished(FencePublication::Published(published.clone())),
        third,
        BridgeFrame::FencePublished(FencePublication::Invalidated {
            fence_id: published.fence_id,
            reason: WithheldReason::ReaderMoved,
            state: FenceState::Unfenced,
        }),
        fourth,
    ];
    // Nothing is answered after the resolve, so what the next reader does with those frames
    // depends on nothing more arriving.
    session.commands.silent_after_resolve = true;

    let asked = session.run_asking("kr-probe amid-traffic", "probe-ran");
    assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
    assert_eq!(last_run(&probes).arguments, ["amid-traffic"]);

    // Each probe reads the fence as the frames before it, and only those, left it.
    for (id, fence_held, point) in [
        (before_refusal, true, "before the detach's refusal"),
        (after_refusal, false, "after the detach's refusal"),
        (after_publication, true, "after the publication"),
        (after_withdrawal, false, "after the withdrawal"),
    ] {
        let BridgeAnswer::Launch(decision) = session.answer(id) else {
            panic!("the reader answered a launch with something else")
        };
        let reason = decision
            .rejection()
            .unwrap_or_else(|| panic!("a probe {point} installed a command"));
        assert_eq!(
            reason != LaunchRejectionReason::FenceInvalid,
            fence_held,
            "{point}, the fence probed was {} held: {reason:?}",
            if fence_held { "still" } else { "no longer" }
        );
    }

    // The refused detach is consumed with the hint, once, by the reader that took the refusal.
    let (_, refused) = session.expect_event("the refused detach consumed", |event| {
        matches!(event, BridgeEvent::PreEofConsumed(_))
    });
    let BridgeEvent::PreEofConsumed(refused) = refused else {
        unreachable!()
    };
    assert!(refused.hint_printed, "a refused detach printed no hint");
    assert!(
        !session.saw_event(Duration::from_millis(300), |event| matches!(
            event,
            BridgeEvent::PreEofConsumed(_)
        )),
        "a refused detach was acted on more than once"
    );

    // The last of those frames was the withdrawal, so a gesture now finds no fence at all.
    session.type_bytes(CTRL_D);
    let (_, consumed) = session.expect_event("pre_eof_consumed", |event| {
        matches!(event, BridgeEvent::PreEofConsumed(_))
    });
    let BridgeEvent::PreEofConsumed(consumed) = consumed else {
        unreachable!()
    };
    assert_eq!(consumed.reason, ConsumeReason::FenceMissing);

    session.commands.stuck = false;
    assert!(session.answered("kr-after-traffic"));
    let probed = [
        before_refusal,
        after_refusal,
        after_publication,
        after_withdrawal,
    ];
    let answered: Vec<RequestId> = session
        .commands
        .answer_ids
        .iter()
        .copied()
        .filter(|id| probed.contains(id))
        .collect();
    assert_eq!(
        answered, probed,
        "each request the reader held was answered once, in the order it came"
    );
}
