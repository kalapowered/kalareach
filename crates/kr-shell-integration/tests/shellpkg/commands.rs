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
use std::path::{Path, PathBuf};

use kr_protocol::root::{
    CommandBypassReason, DETACH_HINT, FENCE_EXCHANGE_TIMEOUT, FenceCause, LAUNCH_READER_BUDGET,
    LaunchCommand, ReaderContext, RootCommandResolveParams, RootEditorFenceParams,
};
use kr_protocol::session::{CommandIntegration, EnvironmentVariable};
use kr_shell_integration::contract::events::ConsumeReason;
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::contract::requests::{
    LaunchDecision, LaunchMailboxRequest, LaunchRejectionReason, LaunchTransactionId,
};

use super::*;

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

/// Places a program whose contents are `bytes` at `path`.
///
/// The bytes are written beside it and placed by a process of its own, so this process never holds
/// the program open for writing, and a child another test starts is never handed a descriptor that
/// would keep the program from starting.
fn place(path: &Path, bytes: &[u8]) {
    let mut name = path.file_name().expect("a program has a name").to_owned();
    name.push(".text");
    let text = path.with_file_name(name);
    std::fs::write(&text, bytes).unwrap_or_else(|error| panic!("{}: {error}", text.display()));
    kr_ipc::testing::place_program(&text, path);
    std::fs::remove_file(&text).unwrap_or_else(|error| panic!("{}: {error}", text.display()));
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
        record = told(record)
    );
    place(path, script.as_bytes());
    run_once(path, record);
}

/// Starts a program that has just been placed once, here, and forgets what it recorded.
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
        place(&root.join("launcher").join("kr-hook-broken"), &[0, 1, 2, 3]);
        std::fs::write(root.join("script.sh"), "kr-probe from-a-script\n").expect("a script");
        std::fs::write(root.join("script.ps1"), "kr-probe from-a-script\n").expect("a script");
        Self {
            _directory: directory,
            root,
        }
    }

    /// What a shell is started with so that the program is found on its search path.
    #[must_use]
    pub fn environment(&self) -> Vec<(String, String)> {
        // The search path is told to the shell as text, like every path here: one that is not
        // text is refused rather than dropped.
        let inherited = match std::env::var("PATH") {
            Ok(inherited) => inherited,
            Err(std::env::VarError::NotPresent) => String::new(),
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("this test's PATH is not UTF-8, so no shell can be told it")
            }
        };
        vec![(
            "PATH".to_owned(),
            format!("{}:{inherited}", told(&self.root.join("bin"))),
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
pub(super) fn a_session_with_probes(package: &Package, probes: &Probes) -> Session {
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
pub(super) fn last_run(probes: &Probes) -> ProbeRun {
    probes
        .runs()
        .last()
        .cloned()
        .expect("the program recorded its start")
}

/// KR-REQ-12.07, KR-REQ-07.45: an interactive command asks once, before it starts, and a bypass
/// runs it exactly as it was typed.
pub fn an_interactive_command_asks_once_and_runs_as_typed(kind: ShellKind) {
    let package = Package::built(kind);
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
    assert_eq!(request.executable, told(&probes.probe()));
    assert_eq!(request.cwd, told(&session.home()));
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
        &format!("cd '{}' && kr-probe moved", told(&elsewhere)),
        "probe-ran",
    );
    assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
    let entry = session.commands.last_line_reader().clone();
    assert_eq!(asked[0].prompt_generation, entry.prompt_generation);
    assert_eq!(asked[0].cwd, told(&elsewhere));
    assert_eq!(asked[0].cwd_revision.get(), entry.cwd_revision.get() + 1);

    // A session created with an integration for the name, and no backend behind it, is answered
    // as the worker answers it, and the command still runs as it was typed: no flag, no variable.
    session.commands.policy = ResolvePolicy::Decide(vec![CommandIntegration {
        plugin_id: kr_protocol::ids::PluginId::new("kalareach/probe").expect("a plugin identifier"),
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
    let not_text = if kind == ShellKind::Fish {
        "kr-probe \\xff"
    } else {
        "kr-probe $'\\xff'"
    };
    let asked = session.run_asking(not_text, "probe-ran");
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
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);
    let script = probes.script();

    let mut forms = if kind == ShellKind::Fish {
        fish_forms_that_never_ask(&script)
    } else {
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
            ("a sourced script", format!(". '{}'", told(&script))),
            (
                "a function",
                "kr_probe_function() { kr-probe in-a-function; }; kr_probe_function".to_owned(),
            ),
            ("an eval", "eval 'kr-probe in-an-eval'".to_owned()),
            // The last part of a pipeline can run in the root shell itself: zsh runs a group
            // there, and a redirection of the group's own does not make it any less part of the
            // pipeline.
            (
                "a group at the end of a pipeline",
                "printf x | { kr-probe in-a-group; }".to_owned(),
            ),
            (
                "a redirected group at the end of a pipeline",
                "printf x | { kr-probe in-a-redirected-group; } </dev/null".to_owned(),
            ),
        ];
        forms.to_vec()
    };
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
    if kind == ShellKind::Zsh {
        // With MULTIOS, zsh's default, a pipe and a redirection of the same descriptor are joined
        // through a copier, so the group still reads a pipe. Without it the redirection replaces
        // the pipe, and the group's command reads a file while it is still part of the pipeline.
        forms.push((
            "a redirected group at the end of a pipeline, without MULTIOS",
            "setopt nomultios; printf x | { kr-probe in-a-plain-redirected-group; } </dev/null; \
             setopt multios"
                .to_owned(),
        ));
    }
    for (form, command) in forms {
        let runs = probes.runs().len();
        let asked = session.run_asking(&command, "probe-ran");
        assert!(asked.is_empty(), "{form} asked: {asked:?}");
        assert_eq!(probes.runs().len(), runs + 1, "{form} ran the program once");
    }

    if kind == ShellKind::Fish {
        fish_handlers_never_ask(&mut session, &probes);
        // A group with a redirection of its own is a block the shell runs itself, in the foreground
        // and in no pipeline: its command is the line's own, and it asks.
        let asked = session.run_asking(
            "begin; kr-probe from-a-redirected-block; end </dev/null",
            "probe-ran",
        );
        assert_eq!(asked.len(), 1, "a redirected block asks once: {asked:?}");
        assert_eq!(last_run(&probes).arguments, ["from-a-redirected-block"]);
        // The same block, now with a pipe in front of its command, is part of the pipeline.
        let asked = session.run_asking(
            "printf x | begin; kr-probe from-a-piped-block; end",
            "probe-ran",
        );
        assert!(asked.is_empty(), "a piped block asked: {asked:?}");
    } else {
        // A group reading a string is no pipeline, however the shell carries the string to it: it
        // asks.
        let asked = session.run_asking("{ kr-probe from-a-string; } <<<x", "probe-ran");
        assert_eq!(
            asked.len(),
            1,
            "a group reading a string asks once: {asked:?}"
        );
        assert_eq!(last_run(&probes).arguments, ["from-a-string"]);
    }

    // The interpreter a script is started with is a command of the line, so it asks; nothing
    // the script runs does.
    let asked = session.run_asking(&format!("sh '{}'", told(&script)), "probe-ran");
    assert_eq!(asked.len(), 1, "only the interpreter asks: {asked:?}");
    assert_eq!(asked[0].argv[0], "sh");
    assert_eq!(last_run(&probes).arguments, ["from-a-script"]);
}

/// The forms of a fish line whose commands the root shell does not start itself.
///
/// Fish runs a group, a function, an `eval`, a substitution, a sourced file and an event handler
/// inside its own blocks, and a command in any of them is not one of the line's own.
fn fish_forms_that_never_ask(script: &Path) -> Vec<(&'static str, String)> {
    vec![
        ("a pipeline", "kr-probe in-a-pipeline | cat".to_owned()),
        (
            "a command substitution",
            "printf '%s\\n' (kr-probe in-a-substitution)".to_owned(),
        ),
        (
            "a background job",
            "kr-probe in-the-background & wait".to_owned(),
        ),
        ("a sourced script", format!("source '{}'", told(script))),
        (
            "a function",
            "function kr_probe_function; kr-probe in-a-function; end; kr_probe_function".to_owned(),
        ),
        ("an eval", "eval 'kr-probe in-an-eval'".to_owned()),
        // A redirection on `eval` is the shell's own and changes nothing about the command it
        // evaluates.
        (
            "an eval with a redirection",
            "eval 'kr-probe in-a-redirected-eval' </dev/null".to_owned(),
        ),
        (
            "a group at the end of a pipeline",
            "printf x | begin; kr-probe in-a-group; end".to_owned(),
        ),
        (
            "an event the line emits",
            "function kr_on_event --on-event kr_event; kr-probe in-an-event; end; emit kr_event"
                .to_owned(),
        ),
    ]
}

/// Handlers fish runs around a line: the one for `fish_preexec` and the prompt function. Their
/// commands are the shell's own, not the line's, and ask nothing.
fn fish_handlers_never_ask(session: &mut Session, probes: &Probes) {
    let asked_before = session.commands.resolves.len();
    let started = |probes: &Probes, word: &str| {
        probes
            .runs()
            .iter()
            .filter(|run| run.arguments == [word])
            .count()
    };

    // A `fish_preexec` handler is defined by one line and runs at the start of the next, before
    // that line's own commands.
    let defined = format!(
        "function kr_preexec --on-event fish_preexec; kr-probe in-preexec; end; {}",
        print_assembled(ShellKind::Fish, "kr-preexec-defined")
    );
    assert!(session.run(&defined, "kr-preexec-defined"));
    assert_eq!(started(probes, "in-preexec"), 0, "the handler ran early");
    let erased = format!(
        "functions -e kr_preexec; {}",
        print_assembled(ShellKind::Fish, "kr-preexec-erased")
    );
    assert!(session.run(&erased, "kr-preexec-erased"));
    assert_eq!(
        started(probes, "in-preexec"),
        1,
        "the handler ran once, for the line after it"
    );

    // The prompt function runs before every prompt it draws, so a probe it starts has run by the
    // time a line typed at that prompt does.
    let prompt = session.prompt.clone();
    let redefined = format!(
        "function fish_prompt; kr-probe in-the-prompt >/dev/null; printf '%s' '{prompt}'; end; {}",
        print_assembled(ShellKind::Fish, "kr-prompt-defined")
    );
    assert!(session.run(&redefined, "kr-prompt-defined"));
    assert!(session.answered("kr-prompt-drawn"));
    assert!(
        started(probes, "in-the-prompt") >= 1,
        "the prompt function's command did not run"
    );
    let restored = format!(
        "function fish_prompt; printf '%s' '{prompt}'; end; {}",
        print_assembled(ShellKind::Fish, "kr-prompt-restored")
    );
    assert!(session.run(&restored, "kr-prompt-restored"));

    assert_eq!(
        session.commands.resolves.len(),
        asked_before,
        "a handler's command asked: {:?}",
        &session.commands.resolves[asked_before..]
    );
}

/// KR-REQ-12.07: a command runs the file and the vector its shell would run. Assignments in front
/// of it can change both, so the question names what they select, or is not asked.
///
/// Bash searches with a `PATH` placed in front of the command, and asks about the file that search
/// finds. Zsh applies those assignments only in the child it forks, so it does not ask about such
/// a command at all; `STTY` in front of one runs a command in that child before it starts.
pub fn assignments_in_front_of_a_command_run_what_they_select(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);
    // A backend for whatever is asked about, so a question that named the wrong file would start
    // the launcher in the command's place.
    session.commands.policy = ResolvePolicy::Backend {
        launcher: told(&probes.launcher()),
        environment: Vec::new(),
        added: Vec::new(),
    };
    let other = probes.other_directory();

    if kind == ShellKind::Fish {
        // Fish applies the assignments in front of a command in a block of its own, so the command
        // is not one of the line's own: it asks nothing and runs with the assignment. The same
        // command without it is asked about, and goes through the launcher.
        let launches = probes.launches().len();
        let asked = session.run_asking("KR_MARK=1 kr-probe assigned", "probe-ran");
        assert!(
            asked.is_empty(),
            "a command with an assignment asked: {asked:?}"
        );
        assert_eq!(probes.launches().len(), launches, "the launcher started");
        let ran = last_run(&probes);
        assert_eq!(ran.arguments, ["assigned"]);
        assert_eq!(
            ran.environment.get("KR_MARK").map(String::as_str),
            Some("1"),
            "the command ran with its assignment"
        );
        let asked = session.run_asking("kr-probe unassigned", "launcher-ran");
        assert_eq!(asked.len(), 1, "the same command asks: {asked:?}");
        assert_eq!(probes.launches().len(), launches + 1);
        return;
    }

    let launches = probes.launches().len();
    let asked = session.run_asking(
        &format!("PATH='{}':\"$PATH\" kr-probe from-the-other", told(&other)),
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
                told(&other.join("kr-probe")),
                "the question names the file the command's own search path finds"
            );
            let launched = probes.launches().last().cloned().expect("the launcher ran");
            assert_eq!(launched.arguments[2], told(&other.join("kr-probe")));
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
    let package = Package::built(kind);
    let probes = Probes::new();
    // A pipe that nothing reads, where an ordinary open for writing would wait for a reader.
    let fifo = probes.path("trace.fifo");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo starts");
    assert!(made.success(), "a pipe for the diagnostics");
    let mut environment = probes.environment();
    environment.push(("KR_SHELL_BRIDGE_TRACE".to_owned(), told(&fifo)));
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
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);
    let probe = told(&probes.probe());

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
///
/// Nothing here times anything. The command is asked about once and then runs as typed, and every
/// absence is decided by order: a command the shell ran after the refusal proves the refusal had
/// been taken, and an answer to a request the reader was asked afterwards proves everything the
/// reader sent before it has been read.
pub fn an_unanswered_question_runs_the_command_as_typed_after_the_deadline(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);

    session.commands.policy = ResolvePolicy::Silent;
    let asked = session.run_asking("kr-probe unanswered", "probe-ran");
    assert_eq!(asked.len(), 1, "the command asked: {asked:?}");
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
    // and no detach is taken to have been refused. What a refusal taken for a detach's would do is
    // draw the hint and report a consumed gesture, at the next reader the shell enters, so a
    // command that runs after that reader has entered finds both already there.
    session.commands.policy = ResolvePolicy::Refuse;
    let before = session.written();
    let decisions = session.events.managed_decisions();
    let asked = session.run_asking("kr-probe refused", "probe-ran");
    assert_eq!(asked.len(), 1, "the command asked: {asked:?}");
    assert_eq!(last_run(&probes).arguments, ["refused"]);
    session.commands.policy = ResolvePolicy::default();
    assert!(session.answered("kr-after-refusal"));
    session.barrier();
    let shown = session.shown_before(before, "kr-after-refusal");
    assert!(
        !shown.contains(DETACH_HINT),
        "a refused question was taken for a refused detach:\n{}",
        session.terminal_output()
    );
    assert_eq!(
        session.events.managed_decisions(),
        decisions,
        "a refused question consumed a gesture"
    );

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

impl Session {
    /// Asks the reader something and waits for its answer.
    ///
    /// The reader writes what it has to say in order, so when the answer is here everything it
    /// sent before answering has been read too, whichever way it answered. This is the barrier
    /// that stands in for a wait of a chosen length where a check needs to say that nothing else
    /// came.
    ///
    /// # Panics
    ///
    /// Panics when the reader does not answer inside the reply window.
    pub fn barrier(&mut self) {
        let (generation, revision) = self.last_entry.as_ref().map_or_else(
            || {
                (
                    kr_protocol::root::PromptGeneration::new(0),
                    kr_protocol::root::ReaderRevision::new(0),
                )
            },
            |entry| (entry.prompt_generation, entry.reader_revision),
        );
        let id = self.ask(WorkerRequest::Fence(RootEditorFenceParams {
            session_id: self.session_id,
            fence_id: fence_id(201),
            prompt_generation: generation,
            reader_revision: revision,
            deadline_ms: FENCE_EXCHANGE_TIMEOUT,
            cause: FenceCause::Retry,
        }));
        let _ = self.answer(id);
    }

    /// What the terminal showed after `start` and before the first copy of `marker` that follows,
    /// where the marker is something a command printed.
    #[must_use]
    pub fn shown_before(&self, start: usize, marker: &str) -> String {
        let output = self.output.lock().expect("the output lock");
        let from = start.min(output.len());
        let end = output[from..]
            .windows(marker.len())
            .position(|window| window == marker.as_bytes())
            .map_or(output.len(), |at| from + at);
        String::from_utf8_lossy(&output[from..end]).into_owned()
    }
}

/// KR-REQ-12.07, KR-REQ-07.45: a backend the worker established runs the command through the
/// launcher it names, with the answer's variables and flags and the executable the shell found;
/// a launcher that is not an absolute path to a program leaves the command as it was typed.
pub fn a_backend_runs_the_command_through_the_launcher_it_names(kind: ShellKind) {
    let package = Package::built(kind);
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

    session.commands.policy = backend(told(&probes.launcher()));
    let runs = probes.runs().len();
    let asked = session.run_asking("kr-probe one 'two words'", "launcher-ran");
    assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
    let launched = probes
        .launches()
        .last()
        .cloned()
        .expect("the launcher recorded its start");
    let probe = told(&probes.probe());
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
        told(&probes.elsewhere().join("kr-hook")),
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
    session.commands.policy = backend(told(&probes.broken_launcher()));
    let asked = session.run_asking("kr-probe unstartable", "probe-ran");
    assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
    let ran = last_run(&probes);
    assert_eq!(ran.arguments, ["unstartable"]);
    assert_eq!(ran.names(), control.names());
    assert!(!ran.environment.contains_key("KR_REGISTRATION"));

    if kind == ShellKind::Fish {
        // Fish starts a command that needs no terminal with `posix_spawn`, which under
        // `status job-control none` is every command. The launcher is started all the same.
        session.commands.policy = backend(told(&probes.launcher()));
        let launches = probes.launches().len();
        let asked = session.run_asking(
            "status job-control none; kr-probe without-job-control; status job-control full",
            "launcher-ran",
        );
        assert_eq!(asked.len(), 1, "one command asks once: {asked:?}");
        assert_eq!(
            probes.launches().len(),
            launches + 1,
            "the launcher did not run without job control"
        );
    }

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
        // Fish's `read` reads through its own editor whenever its input is a terminal.
        ShellKind::Fish => "read -l kr_reply",
        _ => "read -e -r kr_reply",
    }
}

/// KR-REQ-25.05: each line reports one command block when it starts and again when it has
/// finished, with the shell's own status for it, its duration and the directory it ran in. An
/// empty line and the input a running command reads report none.
pub fn each_line_reports_its_block_with_status_duration_and_directory(kind: ShellKind) {
    let package = Package::built(kind);
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
    assert_eq!(started.cwd, told(&session.home()));
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

    // What the shell cannot see into is still part of its line: a function, a pipeline, an `eval`
    // and a sourced file each report the one block of the line that ran them.
    for (what, line) in lines_the_shell_cannot_see_into(kind, &probes) {
        let reported = session.commands.blocks.len();
        assert!(session.run(&line, "probe-ran"), "{what}");
        session.until(&format!("{what}'s finished block"), |commands| {
            commands.blocks[reported..]
                .iter()
                .any(|block| block.exit_status.0.is_some())
        });
        let blocks = session.commands.blocks[reported..].to_vec();
        assert_eq!(
            blocks.len(),
            2,
            "{what} reported one block when it started and one when it finished: {blocks:?}"
        );
        assert!(
            blocks.iter().all(|block| block.command == line),
            "{what} reported another command than the line: {blocks:?}"
        );
        assert_eq!(blocks[1].exit_status.0.map(|status| status.get()), Some(0));
    }
}

/// Lines whose program runs where the shell cannot see it from the line: inside a function, a
/// pipeline, an `eval` and a sourced file. Each prints `probe-ran` and succeeds.
fn lines_the_shell_cannot_see_into(
    kind: ShellKind,
    probes: &Probes,
) -> Vec<(&'static str, String)> {
    let script = told(&probes.script());
    match kind {
        ShellKind::Fish => vec![
            (
                "a function",
                "function kr_probe_function; kr-probe in-a-function; end; kr_probe_function"
                    .to_owned(),
            ),
            ("a pipeline", "kr-probe in-a-pipeline | cat".to_owned()),
            ("an eval", "eval 'kr-probe in-an-eval'".to_owned()),
            ("a sourced file", format!("source '{script}'")),
        ],
        ShellKind::PowerShell => vec![
            (
                "a function",
                "function Invoke-KrProbe { kr-probe in-a-function }; Invoke-KrProbe".to_owned(),
            ),
            (
                "a pipeline",
                "kr-probe in-a-pipeline | Out-String".to_owned(),
            ),
            (
                "an expression",
                "Invoke-Expression 'kr-probe in-an-eval'".to_owned(),
            ),
            (
                "a sourced file",
                format!(". '{}'", told(&probes.path("script.ps1"))),
            ),
        ],
        ShellKind::Zsh | ShellKind::Bash => vec![
            (
                "a function",
                "kr_probe_function() { kr-probe in-a-function; }; kr_probe_function".to_owned(),
            ),
            ("a pipeline", "kr-probe in-a-pipeline | cat".to_owned()),
            ("an eval", "eval 'kr-probe in-an-eval'".to_owned()),
            ("a sourced file", format!(". '{script}'")),
        ],
    }
}

/// KR-REQ-07.84: the commands a line runs are started with the capability the worker minted for
/// that line and no other, which is what `kr detach` with no attachment presents, and a line the
/// worker minted none for has none.
pub fn a_line_exports_the_capability_minted_for_it(kind: ShellKind) {
    let package = Package::built(kind);
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
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);

    // A gesture at a fenced prompt leaves a detach waiting for the worker's answer, which comes
    // only after the next line has been typed. The fence stays held until the answer arrives.
    let decisions_before = session.events.managed_decisions();
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

    // Each probe reads the fence as the frames before it, and only those, left it, and it is the
    // next reader that reads it: a wait that took the frames itself would answer at the prompt
    // the line was typed at.
    let mut next_prompt = None;
    for (id, fence_held, point) in [
        (before_refusal, true, "before the detach's refusal"),
        (after_refusal, false, "after the detach's refusal"),
        (after_publication, true, "after the publication"),
        (after_withdrawal, false, "after the withdrawal"),
    ] {
        let BridgeAnswer::Launch(decision) = session.answer(id) else {
            panic!("the reader answered a launch with something else")
        };
        let LaunchDecision::Rejected(rejection) = decision else {
            panic!("a probe {point} installed a command")
        };
        assert_eq!(
            rejection.reason != LaunchRejectionReason::FenceInvalid,
            fence_held,
            "{point}, the fence probed was {} held: {:?}",
            if fence_held { "still" } else { "no longer" },
            rejection.reason
        );
        let next = *next_prompt.get_or_insert_with(|| {
            session
                .commands
                .entries
                .iter()
                .rev()
                .find(|entry| entry.reader_context == ReaderContext::Primary)
                .expect("the next reader entered")
                .prompt_generation
        });
        assert!(
            next > reader.prompt_generation,
            "no reader had entered after the line"
        );
        assert_eq!(
            rejection.prompt_generation, next,
            "the probe {point} was read at another prompt than the next reader's"
        );
    }
    let next_prompt = next_prompt.expect("the probes were answered");

    // The refused detach is consumed with the hint, once, by the reader that took the refusal, and
    // between the two probes on either side of it.
    let (_, refused) = session.expect_event("the refused detach consumed", |event| {
        matches!(event, BridgeEvent::PreEofConsumed(_))
    });
    let BridgeEvent::PreEofConsumed(refused) = refused else {
        unreachable!()
    };
    assert!(refused.hint_printed, "a refused detach printed no hint");
    assert_eq!(refused.prompt_generation, next_prompt);
    let arrivals = &session.commands.arrivals;
    let at = |wanted: Arrival| {
        arrivals
            .iter()
            .position(|arrival| *arrival == wanted)
            .unwrap_or_else(|| panic!("{wanted:?} did not arrive"))
    };
    let (first_answer, second_answer) = (
        at(Arrival::Answer(before_refusal)),
        at(Arrival::Answer(after_refusal)),
    );
    let consumed_between = arrivals[first_answer..second_answer]
        .iter()
        .filter(|arrival| **arrival == Arrival::Event("pre_eof_consumed"))
        .count();
    assert_eq!(
        consumed_between, 1,
        "the refusal was not taken between the probes on either side of it: {arrivals:?}"
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
    session.barrier();
    // The decisions the worker was told of since the case began are the gesture's detach, the
    // refusal's consumption and the second gesture's: a refused detach acted on more than once
    // would be a fourth.
    assert_eq!(
        session.events.managed_decisions() - decisions_before,
        3,
        "the refused detach was not acted on exactly once"
    );
    let probed = [
        before_refusal,
        after_refusal,
        after_publication,
        after_withdrawal,
    ];
    let answered: Vec<RequestId> = session
        .commands
        .arrivals
        .iter()
        .filter_map(|arrival| match arrival {
            Arrival::Answer(id) if probed.contains(id) => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(
        answered, probed,
        "each request the reader held was answered once, in the order it came"
    );
}

// --------------------------------------------------------------------------------------------
// KR-REQ-01.06: ordinary commands and agent names run in a managed session as they do in the
// same shell without KalaReach.
// --------------------------------------------------------------------------------------------

/// The six agents the bundled adapters cover, by the command a person types for each.
const AGENT_NAMES: [&str; 6] = ["codex", "claude", "opencode", "gemini", "kimi", "qodercli"];

/// The marker each line of the corpus ends by printing, put together by the shell from two pieces
/// so a terminal echoing the line cannot produce it.
const ITEM_DONE: &str = "kr-item-done";

/// What a comparison between a managed shell and an ordinary one runs against: programs on the
/// search path, a script and directories the two share, and a place of its own for each shell to
/// leave what it saw.
struct Corpus {
    _directory: tempfile::TempDir,
    root: PathBuf,
}

/// The reserved variables a managed shell may export to what it starts and an ordinary one does not,
/// by name. Any other `KR_` variable an agent sees is one both shells were given, and is compared
/// like every other.
const DECLARED_RESERVED: &[&str] = &["KR_SESSION", "KR_DETACH_TOKEN"];

/// What one shell left behind: the files its corpus wrote, and every start of each agent.
struct Observed {
    files: BTreeMap<String, String>,
    starts: BTreeMap<String, Vec<ProbeRun>>,
    /// The reserved variables (`KR_`) any agent was started with, by name: the one declared
    /// difference between a managed shell and an ordinary one, kept so a case can say which of
    /// them may be there and that the bridge's own never are.
    reserved: std::collections::BTreeSet<String>,
}

impl Corpus {
    /// Makes the directory, one recording program per agent name on its search path, a script that
    /// runs one of them and a directory to move to.
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("kr-corpus-")
            .tempdir()
            .expect("a directory on the internal disk");
        let root = std::fs::canonicalize(directory.path()).expect("the directory resolves");
        std::fs::create_dir_all(root.join("bin")).expect("a directory for the programs");
        std::fs::create_dir_all(root.join("dirs").join("one")).expect("a directory to move to");
        for name in AGENT_NAMES {
            // Every variable it was started with, so an environment that differs anywhere shows.
            let script = format!(
                "#!/bin/sh\n\
                 {{\n\
                 printf 'run\\n'\n\
                 for word in \"$@\"; do printf 'arg %s\\n' \"$word\"; done\n\
                 env | LC_ALL=C sort | while IFS= read -r line; do printf 'env %s\\n' \"$line\"; done\n\
                 printf 'end\\n'\n\
                 }} >> \"$CASE_RECORD/{name}.record\"\n\
                 printf '%s%s\\n' '{name}-' 'ran'\n"
            );
            let program = root.join("bin").join(name);
            place(&program, script.as_bytes());
            // Started once here, outside every timed wait, with somewhere to record.
            let scratch = root.join("scratch");
            std::fs::create_dir_all(&scratch).expect("a scratch directory");
            let status = std::process::Command::new(&program)
                .env("CASE_RECORD", &scratch)
                .stdout(std::process::Stdio::null())
                .status()
                .expect("the program starts");
            assert!(status.success());
        }
        std::fs::write(root.join("script.sh"), "claude from-a-script\n").expect("a script");
        Self {
            _directory: directory,
            root,
        }
    }

    /// What a shell is started with: the search path with the agents' stand-ins first, and where
    /// this shell leaves what it saw. The names carry no `KR_` prefix, so a comparison that
    /// leaves out the reserved variables leaves out none of these.
    fn environment(&self, arena: &Path) -> Vec<(String, String)> {
        std::fs::create_dir_all(arena.join("out")).expect("somewhere to leave files");
        std::fs::create_dir_all(arena.join("records")).expect("somewhere to record starts");
        let inherited = std::env::var("PATH").expect("a search path that is text");
        vec![
            (
                "PATH".to_owned(),
                format!("{}:{inherited}", told(&self.root.join("bin"))),
            ),
            ("CASE_OUT".to_owned(), told(&arena.join("out"))),
            ("CASE_RECORD".to_owned(), told(&arena.join("records"))),
            ("CASE_DIRS".to_owned(), told(&self.root.join("dirs"))),
            ("CASE_BIN".to_owned(), told(&self.root.join("bin"))),
            ("CASE_SCRIPT".to_owned(), told(&self.root.join("script.sh"))),
        ]
    }
}

/// One thing the corpus does, in one shell's words. Every line leaves what it saw in a file of its
/// own under `$CASE_OUT` rather than on the terminal, where the editor's drawing would be part of
/// what is compared.
struct Item {
    name: &'static str,
    lines: Vec<String>,
}

fn item(name: &'static str, lines: &[&str]) -> Item {
    Item {
        name,
        lines: lines.iter().map(|line| (*line).to_owned()).collect(),
    }
}

/// The ordinary commands: pipes, redirects, moving about, aliases, functions, `exec`, exit
/// statuses and signals, and what the shell says about itself.
fn ordinary_items(kind: ShellKind) -> Vec<Item> {
    match kind {
        ShellKind::Zsh | ShellKind::Bash => vec![
            item(
                "pipe",
                &["printf 'a\\nb\\nc\\n' | tr a-c A-C | sort -r > \"$CASE_OUT/pipe\""],
            ),
            item(
                "redirect",
                &[
                    "{ printf x; printf y; } > \"$CASE_OUT/redirect\" 2> \"$CASE_OUT/redirect.err\"; printf z >> \"$CASE_OUT/redirect\"; ls /kr-no-such-path 2>> \"$CASE_OUT/redirect.err\"; printf 'ls=%s' $? >> \"$CASE_OUT/redirect\"",
                ],
            ),
            item(
                "cd",
                &[
                    "cd \"$CASE_DIRS/one\" && pwd -P > \"$CASE_OUT/cd\"; cd \"$CASE_DIRS\" && pwd -P >> \"$CASE_OUT/cd\"; cd \"$HOME\"",
                ],
            ),
            item(
                "alias",
                &[
                    "alias kr_alias='printf alias-%s'",
                    "kr_alias ran > \"$CASE_OUT/alias\"; type kr_alias >> \"$CASE_OUT/alias\" 2>&1; unalias kr_alias",
                ],
            ),
            item(
                "function",
                &[
                    "kr_fn() { printf 'fn-%s' \"$1\"; }",
                    "kr_fn arg > \"$CASE_OUT/function\"; type kr_fn >> \"$CASE_OUT/function\" 2>&1; unset -f kr_fn",
                ],
            ),
            item(
                "exec",
                &[
                    "(exec printf 'exec-%s' ran) > \"$CASE_OUT/exec\"; printf ' status=%s' $? >> \"$CASE_OUT/exec\"",
                ],
            ),
            item(
                "status",
                &[
                    "(exit 3); printf 'a=%s ' $? > \"$CASE_OUT/status\"; false; printf 'b=%s ' $? >> \"$CASE_OUT/status\"; sh -c 'exit 7'; printf 'c=%s ' $? >> \"$CASE_OUT/status\"; true; printf 'd=%s' $? >> \"$CASE_OUT/status\"",
                ],
            ),
            item(
                "signals",
                &[
                    "sh -c 'kill -TERM $$'; printf 'term=%s ' $? > \"$CASE_OUT/signals\"; sh -c 'kill -HUP $$'; printf 'hup=%s ' $? >> \"$CASE_OUT/signals\"; sh -c 'kill -KILL $$'; printf 'kill=%s' $? >> \"$CASE_OUT/signals\"",
                ],
            ),
            item(
                "self",
                &[
                    "{ printf '%s\\n' \"$0\"; command -v ls; command -v sh; command -v kr-no-such; printf 'st=%s\\n' $?; } > \"$CASE_OUT/self\" 2>&1",
                ],
            ),
        ],
        ShellKind::Fish => vec![
            item(
                "pipe",
                &["printf 'a\\nb\\nc\\n' | tr a-c A-C | sort -r > $CASE_OUT/pipe"],
            ),
            item(
                "redirect",
                &[
                    "begin; printf x; printf y; end > $CASE_OUT/redirect 2> $CASE_OUT/redirect.err; printf z >> $CASE_OUT/redirect; ls /kr-no-such-path 2>> $CASE_OUT/redirect.err; printf 'ls=%s' $status >> $CASE_OUT/redirect",
                ],
            ),
            item(
                "cd",
                &[
                    "cd $CASE_DIRS/one; and pwd -P > $CASE_OUT/cd; cd $CASE_DIRS; and pwd -P >> $CASE_OUT/cd; cd $HOME",
                ],
            ),
            item(
                "alias",
                &[
                    "alias kr_alias 'printf alias-%s'",
                    "kr_alias ran > $CASE_OUT/alias; type kr_alias >> $CASE_OUT/alias 2>&1; functions -e kr_alias",
                ],
            ),
            item(
                "function",
                &[
                    "function kr_fn; printf 'fn-%s' $argv[1]; end",
                    "kr_fn arg > $CASE_OUT/function; type kr_fn >> $CASE_OUT/function 2>&1; functions -e kr_fn",
                ],
            ),
            item(
                "exec",
                &[
                    "sh -c 'exec printf exec-%s ran' > $CASE_OUT/exec; printf ' status=%s' $status >> $CASE_OUT/exec",
                ],
            ),
            item(
                "status",
                &[
                    "sh -c 'exit 3'; printf 'a=%s ' $status > $CASE_OUT/status; false; printf 'b=%s ' $status >> $CASE_OUT/status; sh -c 'exit 7'; printf 'c=%s ' $status >> $CASE_OUT/status; true; printf 'd=%s' $status >> $CASE_OUT/status",
                ],
            ),
            item(
                "signals",
                &[
                    "sh -c 'kill -TERM $$'; printf 'term=%s ' $status > $CASE_OUT/signals; sh -c 'kill -HUP $$'; printf 'hup=%s ' $status >> $CASE_OUT/signals; sh -c 'kill -KILL $$'; printf 'kill=%s' $status >> $CASE_OUT/signals",
                ],
            ),
            item(
                "self",
                &[
                    "begin; status is-interactive; printf 'interactive=%s\\n' $status; command -v ls; command -v sh; command -v kr-no-such; printf 'st=%s\\n' $status; end > $CASE_OUT/self 2>&1",
                ],
            ),
        ],
        ShellKind::PowerShell => vec![
            item(
                "pipe",
                &[
                    "'a','b','c' | ForEach-Object { $_.ToUpper() } | Sort-Object -Descending | Set-Content \"$env:CASE_OUT/pipe\"",
                ],
            ),
            item(
                "redirect",
                &[
                    "'x' | Out-File \"$env:CASE_OUT/redirect\"; 'y' | Out-File -Append \"$env:CASE_OUT/redirect\"; Get-Item /kr-no-such-path 2> \"$env:CASE_OUT/redirect.err\"; \"ls=$($?)\" | Out-File -Append \"$env:CASE_OUT/redirect\"",
                ],
            ),
            item(
                "cd",
                &[
                    "Set-Location \"$env:CASE_DIRS/one\"; (Get-Location).Path | Out-File \"$env:CASE_OUT/cd\"; Set-Location \"$env:CASE_DIRS\"; (Get-Location).Path | Out-File -Append \"$env:CASE_OUT/cd\"; Set-Location $HOME",
                ],
            ),
            item(
                "alias",
                &[
                    "Set-Alias kr_alias Write-Output",
                    "kr_alias alias-ran | Out-File \"$env:CASE_OUT/alias\"; (Get-Command kr_alias).Definition | Out-File -Append \"$env:CASE_OUT/alias\"; Remove-Item alias:kr_alias",
                ],
            ),
            item(
                "function",
                &[
                    "function kr_fn { 'fn-' + $args[0] }",
                    "kr_fn arg | Out-File \"$env:CASE_OUT/function\"; (Get-Command kr_fn).CommandType | Out-File -Append \"$env:CASE_OUT/function\"; Remove-Item function:kr_fn",
                ],
            ),
            item(
                "exec",
                &[
                    "& sh -c 'exec printf exec-%s ran' | Out-File \"$env:CASE_OUT/exec\"; \"status=$LASTEXITCODE\" | Out-File -Append \"$env:CASE_OUT/exec\"",
                ],
            ),
            item(
                "status",
                &[
                    "& sh -c 'exit 3'; \"a=$LASTEXITCODE\" | Out-File \"$env:CASE_OUT/status\"; & sh -c 'exit 7'; \"c=$LASTEXITCODE\" | Out-File -Append \"$env:CASE_OUT/status\"; & true; \"d=$LASTEXITCODE\" | Out-File -Append \"$env:CASE_OUT/status\"",
                ],
            ),
            item(
                "signals",
                &[
                    "& sh -c 'kill -TERM $$'; \"term=$LASTEXITCODE\" | Out-File \"$env:CASE_OUT/signals\"; & sh -c 'kill -HUP $$'; \"hup=$LASTEXITCODE\" | Out-File -Append \"$env:CASE_OUT/signals\"; & sh -c 'kill -KILL $$'; \"kill=$LASTEXITCODE\" | Out-File -Append \"$env:CASE_OUT/signals\"",
                ],
            ),
            // `?` is `Where-Object`, and a character that goes into the line like any other.
            item(
                "question-mark",
                &["1..3 | ? { $_ -gt 1 } | Out-File \"$env:CASE_OUT/question-mark\""],
            ),
            item(
                "self",
                &[
                    "$PSVersionTable.PSEdition | Out-File \"$env:CASE_OUT/self\"; (Get-Command ls).Source | Out-File -Append \"$env:CASE_OUT/self\"; (Get-Command sh).Source | Out-File -Append \"$env:CASE_OUT/self\"; [bool](Get-Command kr-no-such -ErrorAction SilentlyContinue) | Out-File -Append \"$env:CASE_OUT/self\"",
                ],
            ),
        ],
    }
}

/// The agent names typed the way a person types them, an absolute path and a script.
fn agent_items(kind: ShellKind) -> Vec<Item> {
    let mut items = Vec::new();
    for name in AGENT_NAMES {
        let line = match kind {
            ShellKind::Zsh | ShellKind::Bash => format!(
                "command -v {name} > \"$CASE_OUT/{name}.path\"; {name} 'two words' -- last > \"$CASE_OUT/{name}.out\""
            ),
            ShellKind::Fish => format!(
                "command -v {name} > $CASE_OUT/{name}.path; {name} 'two words' -- last > $CASE_OUT/{name}.out"
            ),
            ShellKind::PowerShell => format!(
                "(Get-Command {name}).Source | Out-File \"$env:CASE_OUT/{name}.path\"; & {name} 'two words' -- last | Out-File \"$env:CASE_OUT/{name}.out\""
            ),
        };
        items.push(Item {
            name: Box::leak(format!("agent-{name}").into_boxed_str()),
            lines: vec![line],
        });
    }
    let (absolute, script) = match kind {
        ShellKind::Zsh | ShellKind::Bash => (
            "\"$CASE_BIN/claude\" absolute > \"$CASE_OUT/absolute.out\"".to_owned(),
            "sh \"$CASE_SCRIPT\" > \"$CASE_OUT/script.out\"".to_owned(),
        ),
        ShellKind::Fish => (
            "$CASE_BIN/claude absolute > $CASE_OUT/absolute.out".to_owned(),
            "sh $CASE_SCRIPT > $CASE_OUT/script.out".to_owned(),
        ),
        ShellKind::PowerShell => (
            "& \"$env:CASE_BIN/claude\" absolute | Out-File \"$env:CASE_OUT/absolute.out\""
                .to_owned(),
            "& sh $env:CASE_SCRIPT | Out-File \"$env:CASE_OUT/script.out\"".to_owned(),
        ),
    };
    items.push(Item {
        name: "absolute",
        lines: vec![absolute],
    });
    items.push(Item {
        name: "script",
        lines: vec![script],
    });
    items
}

/// Runs one item's lines at a shell's prompt, each to its end.
fn run_item(session: &mut Session, kind: ShellKind, item: &Item) {
    let done = print_assembled(kind, ITEM_DONE);
    for line in &item.lines {
        assert!(
            session.run(&format!("{line}; {done}"), ITEM_DONE),
            "{}: {line:?} did not finish:\n{}",
            item.name,
            session.terminal_output()
        );
    }
}

/// What a shell left behind, with the places that differ between two shells named the same way.
fn observe(arena: &Path, replacing: &[(String, &'static str)]) -> Observed {
    let normalise = |text: &str| {
        let mut text = text.to_owned();
        for (from, to) in replacing {
            text = text.replace(from.as_str(), to);
        }
        text
    };
    let mut files = BTreeMap::new();
    for entry in std::fs::read_dir(arena.join("out")).expect("the files it left") {
        let path = entry.expect("an entry").path();
        let name = path
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .into_owned();
        let text = String::from_utf8_lossy(&std::fs::read(&path).expect("a file")).into_owned();
        files.insert(name, normalise(&text));
    }
    let mut starts: BTreeMap<String, Vec<ProbeRun>> = BTreeMap::new();
    let mut reserved = std::collections::BTreeSet::new();
    for name in AGENT_NAMES {
        let runs = read_runs(&arena.join("records").join(format!("{name}.record")))
            .into_iter()
            .inspect(|run| {
                reserved.extend(
                    run.environment
                        .keys()
                        .filter(|name| name.starts_with("KR_"))
                        .cloned(),
                );
            })
            .map(|run| ProbeRun {
                arguments: run.arguments.iter().map(|word| normalise(word)).collect(),
                // The reserved variables are the one declared difference between a managed shell
                // and an ordinary one.
                environment: run
                    .environment
                    .into_iter()
                    .filter(|(name, _)| !DECLARED_RESERVED.contains(&name.as_str()))
                    .map(|(name, value)| (name, normalise(&value)))
                    .collect(),
            })
            .collect();
        starts.insert(name.to_owned(), runs);
    }
    Observed {
        files,
        starts,
        reserved,
    }
}

/// Every place two shells' observations differ, each named by the file or the agent it is about.
fn differences(managed: &Observed, ordinary: &Observed) -> Vec<String> {
    let mut found = Vec::new();
    let names: std::collections::BTreeSet<_> = managed
        .files
        .keys()
        .chain(ordinary.files.keys())
        .cloned()
        .collect();
    for name in names {
        if managed.files.get(&name) != ordinary.files.get(&name) {
            found.push(format!(
                "{name}: the managed shell left {:?} and the ordinary one {:?}",
                managed.files.get(&name),
                ordinary.files.get(&name)
            ));
        }
    }
    for (name, runs) in &managed.starts {
        let others = &ordinary.starts[name];
        if runs.len() != others.len() {
            found.push(format!(
                "{name}: the managed shell started it {} times and the ordinary one {}",
                runs.len(),
                others.len()
            ));
            continue;
        }
        for (index, (ours, theirs)) in runs.iter().zip(others).enumerate() {
            if ours.arguments != theirs.arguments {
                found.push(format!(
                    "{name}, start {index}: the arguments were {:?} and {:?}",
                    ours.arguments, theirs.arguments
                ));
            }
            let variables: std::collections::BTreeSet<_> = ours
                .environment
                .keys()
                .chain(theirs.environment.keys())
                .collect();
            for variable in variables {
                if ours.environment.get(variable) != theirs.environment.get(variable) {
                    found.push(format!(
                        "{name}, start {index}: {variable} was {:?} and {:?}",
                        ours.environment.get(variable),
                        theirs.environment.get(variable)
                    ));
                }
            }
        }
    }
    found
}

/// One managed shell and one ordinary shell of the same package, having run the same items.
struct Pair {
    managed: Session,
    ordinary: Session,
    corpus: Corpus,
    arenas: (tempfile::TempDir, tempfile::TempDir),
}

impl Pair {
    fn start(package: &Package) -> Self {
        let corpus = Corpus::new();
        let arenas = (
            tempfile::Builder::new()
                .prefix("kr-managed-")
                .tempdir()
                .expect("a directory"),
            tempfile::Builder::new()
                .prefix("kr-ordinary-")
                .tempdir()
                .expect("a directory"),
        );
        let managed_arena = std::fs::canonicalize(arenas.0.path()).expect("resolves");
        let ordinary_arena = std::fs::canonicalize(arenas.1.path()).expect("resolves");
        let mut managed = Session::start_with(package, &corpus.environment(&managed_arena));
        managed.first_prompt();
        managed.forget_events();
        assert!(
            managed.answered("kr-ready"),
            "the managed shell did not answer:\n{}",
            managed.terminal_output()
        );
        // The same binary, the same configuration and no entry: what the person has without us.
        let mut ordinary = Session::start_unmanaged(
            package,
            &corpus.environment(&ordinary_arena),
            Profile {
                entry: false,
                ..Profile::ORDINARY
            },
        );
        assert!(
            ordinary.answered("kr-ready"),
            "the ordinary shell did not answer:\n{}",
            ordinary.terminal_output()
        );
        Self {
            managed,
            ordinary,
            corpus,
            arenas: (arenas.0, arenas.1),
        }
    }

    fn run(&mut self, kind: ShellKind, items: &[Item]) {
        for item in items {
            run_item(&mut self.managed, kind, item);
            run_item(&mut self.ordinary, kind, item);
        }
    }

    fn observed(&self) -> (Observed, Observed) {
        let managed = std::fs::canonicalize(self.arenas.0.path()).expect("resolves");
        let ordinary = std::fs::canonicalize(self.arenas.1.path()).expect("resolves");
        // The place a shell was given as its home and the place the kernel names it by, which are
        // two spellings on a platform whose temporary directory is a link.
        let names = |arena: &Path, session: &Session| {
            vec![
                (told(arena), "<arena>"),
                (told(&session._directory.path().join("home")), "<home>"),
                (told(&session.home()), "<home>"),
            ]
        };
        (
            observe(&managed, &names(&managed, &self.managed)),
            observe(&ordinary, &names(&ordinary, &self.ordinary)),
        )
    }
}

/// KR-REQ-01.06: with command integration off, ordinary commands and the six agent names resolve
/// and run in a managed session as they do in the same shell without KalaReach.
///
/// The same package's shell is started twice, once as a session's root shell and once as a person's
/// own, with the same configuration, the same search path and the same files to leave things in.
/// Both run the same corpus: pipes, redirects, moving about, aliases, functions, `exec`, exit
/// statuses, signals and what the shell says about itself, then each agent name, an absolute path
/// and a script. What each saw is compared: what `command -v` names, `$0`, the argument vector each
/// program started with, its environment other than the reserved variables, and the status.
pub fn ordinary_commands_and_agent_names_run_as_in_an_unmanaged_shell(kind: ShellKind) {
    let package = Package::built(kind);
    let mut pair = Pair::start(&package);
    let mut items = ordinary_items(kind);
    items.extend(agent_items(kind));
    pair.run(kind, &items);
    let (managed, ordinary) = pair.observed();
    // Something was observed, or two empty results would agree.
    assert!(
        managed.files.len() >= items.len(),
        "{:?}",
        managed.files.keys()
    );
    for name in AGENT_NAMES {
        assert_eq!(
            ordinary.starts[name].len(),
            if name == "claude" { 3 } else { 1 },
            "{name}: the corpus started it the same number of times in the ordinary shell"
        );
    }
    // The bridge's own variables leave the environment once the handshake is done, so no agent is
    // started with the endpoint or the secret, whatever else a session exports. What a managed
    // shell may export to an agent is the declared set and nothing else: a name outside it is a
    // difference the comparison would otherwise have filtered away.
    let undeclared: Vec<_> = managed
        .reserved
        .iter()
        .filter(|name| {
            !DECLARED_RESERVED.contains(&name.as_str()) && !ordinary.reserved.contains(*name)
        })
        .collect();
    assert!(
        undeclared.is_empty(),
        "an agent was started with reserved variables a managed shell does not declare: {undeclared:?}"
    );
    let differences = differences(&managed, &ordinary);
    assert!(
        differences.is_empty(),
        "a managed session ran something differently from the same shell without KalaReach:\n{}\n\
         the managed terminal:\n{}\nthe ordinary terminal:\n{}",
        differences.join("\n"),
        pair.managed.terminal_output(),
        pair.ordinary.terminal_output()
    );
}

/// The control for the case above: an alias planted in the managed shell alone, which changes what
/// an agent name runs, is reported by the comparison and not hidden by it.
pub fn a_planted_alias_that_changes_an_agent_name_is_reported_not_hidden(kind: ShellKind) {
    let package = Package::built(kind);
    let mut pair = Pair::start(&package);
    let plant = match kind {
        ShellKind::Zsh | ShellKind::Bash => "alias claude=codex",
        ShellKind::Fish => "alias claude codex",
        ShellKind::PowerShell => "Set-Alias claude codex",
    };
    let done = print_assembled(kind, ITEM_DONE);
    assert!(
        pair.managed.run(&format!("{plant}; {done}"), ITEM_DONE),
        "{}",
        pair.managed.terminal_output()
    );
    let items = agent_items(kind)
        .into_iter()
        .filter(|item| item.name == "agent-claude" || item.name == "agent-codex")
        .collect::<Vec<_>>();
    pair.run(kind, &items);
    let (managed, ordinary) = pair.observed();
    let found = differences(&managed, &ordinary);
    assert!(
        found
            .iter()
            .any(|difference| difference.starts_with("claude")),
        "an alias that made `claude` start another program went unreported:\n{found:?}"
    );
    // The program the alias names is the one that ran, in the shell that has the alias.
    assert_eq!(
        managed.starts["codex"].len(),
        2,
        "the alias made `claude` start codex as well as codex's own start"
    );
    assert_eq!(ordinary.starts["codex"].len(), 1);
}

/// KR-REQ-01.06, KR-REQ-12.07: with the integration for one agent enabled, its flags are added to
/// that agent's interactive invocation and to nothing else.
///
/// The worker's own decision is played with a backend it can establish. `claude` is enabled with a
/// flag; a typed `claude` runs through the launcher with the flag, and then each of these runs as
/// typed: an absolute path to the same program, another agent, the same name inside a script, and
/// in a pipeline. An alias planted for the name changes what the shell asks about, and the
/// request says so: it names the program the alias makes it run, which is not the enabled one, so
/// it gets no flag either.
///
/// Zsh and Bash only: those are the packages whose executor asks the worker before a command
/// starts.
pub fn an_enabled_integration_adds_its_flags_only_to_the_agents_interactive_invocation(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let corpus = Corpus::new();
    let probes = Probes::new();
    let arena = tempfile::Builder::new()
        .prefix("kr-enabled-")
        .tempdir()
        .expect("a directory");
    let arena_path = std::fs::canonicalize(arena.path()).expect("resolves");
    let mut session = Session::start_with(&package, &corpus.environment(&arena_path));
    session.first_prompt();
    session.forget_events();
    assert!(
        session.answered("kr-ready"),
        "{}",
        session.terminal_output()
    );
    let integrations = vec![CommandIntegration {
        plugin_id: kr_protocol::ids::PluginId::new("kalareach/claude-code")
            .expect("a plugin identifier"),
        command: "claude".to_owned(),
        flags: vec!["--kr-flag".to_owned()],
        enabled: true,
    }];
    session.commands.policy = ResolvePolicy::Establishing {
        integrations: integrations.clone(),
        launcher: told(&probes.launcher()),
        environment: Vec::new(),
    };
    let starts = |name: &str| read_runs(&arena_path.join("records").join(format!("{name}.record")));
    let run = |session: &mut Session, line: &str| {
        let done = print_assembled(kind, ITEM_DONE);
        session.run_asking(&format!("{line}; {done}"), ITEM_DONE)
    };

    // The named agent, typed at the prompt: asked once, and run through the launcher in the
    // program's place with the flag added after what was typed.
    let asked = run(&mut session, "claude one 'two words' > /dev/null");
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0].argv, ["claude", "one", "two words"]);
    let launches = probes.launches();
    assert_eq!(launches.len(), 1, "the launcher started once: {launches:?}");
    assert_eq!(
        launches[0].arguments,
        [
            "launch",
            "--",
            told(&corpus.root.join("bin").join("claude")).as_str(),
            "claude",
            "one",
            "two words",
            "--kr-flag"
        ],
        "the flag is added to the interactive invocation of the named agent"
    );
    assert!(
        starts("claude").is_empty(),
        "the launcher runs in its place"
    );

    // Everything below runs as typed, and none of it gets the flag.
    let asked = run(&mut session, "\"$CASE_BIN/claude\" absolute > /dev/null");
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(
        worker_decision(&integrations, &asked[0]).bypass.0,
        Some(CommandBypassReason::AbsolutePath),
        "the name is the enabled one, and a path is the documented bypass"
    );
    let asked = run(&mut session, "codex other > /dev/null");
    assert_eq!(asked.len(), 1, "{asked:?}");
    let asked = run(&mut session, "sh \"$CASE_SCRIPT\" > /dev/null");
    assert_eq!(
        asked
            .iter()
            .map(|request| request.argv[0].as_str())
            .collect::<Vec<_>>(),
        ["sh"],
        "the script is asked about as the command it is, and nothing its own commands do"
    );
    let asked = run(&mut session, "claude piped | cat > /dev/null");
    assert!(asked.is_empty(), "a pipeline asked: {asked:?}");
    let claude = starts("claude");
    assert_eq!(
        claude
            .iter()
            .map(|run| run.arguments.clone())
            .collect::<Vec<_>>(),
        [
            vec!["absolute".to_owned()],
            vec!["from-a-script".to_owned()],
            vec!["piped".to_owned()]
        ],
        "an absolute path, a script and a pipeline run claude exactly as typed"
    );
    assert_eq!(starts("codex")[0].arguments, ["other"]);
    assert_eq!(
        probes.launches().len(),
        1,
        "no other launch: {:?}",
        probes.launches()
    );

    // The control: an alias that makes `claude` run another program is what the shell asks about,
    // and the enabled agent's flag stays with the enabled agent.
    let planted = run(&mut session, "alias claude=codex");
    assert!(planted.is_empty(), "{planted:?}");
    let asked = run(&mut session, "claude via-alias > /dev/null");
    if kind == ShellKind::Fish {
        // An alias is a function in fish, and a command a function runs is none of the line's
        // own: nothing is asked, and nothing is added.
        assert!(asked.is_empty(), "an alias asked: {asked:?}");
    } else {
        assert_eq!(asked.len(), 1, "{asked:?}");
        assert_eq!(
            asked[0].argv,
            ["codex", "via-alias"],
            "the request reports what the alias makes the shell run"
        );
    }
    assert_eq!(
        probes.launches().len(),
        1,
        "no flag went to the aliased command"
    );
    assert_eq!(
        starts("codex").last().map(|run| run.arguments.clone()),
        Some(vec!["via-alias".to_owned()])
    );
}
