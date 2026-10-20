//! What a launch runs: the argument vector the caller named, in each shell.
//!
//! The reader installs a line, and the shell reads that line again before it runs anything. A word
//! the shell treats as more than itself would reach the program as something else, or not reach it
//! at all, so each case here launches a program that prints each argument it receives between
//! angle brackets and reads the terminal for exactly that text. The echo of the installed line
//! carries no angle brackets, so it cannot produce it.

use kr_protocol::root::{EditorFence, LaunchCommand, RootEditorEnterParams};
use kr_protocol::scalars::Uuid;
use kr_shell_integration::contract::events::BridgeEvent;
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::contract::requests::{
    BridgeAnswer, LaunchDecision, LaunchMailboxRequest, LaunchRejectionReason, LaunchTransactionId,
    WorkerRequest,
};

use super::commands::{Probes, a_session_with_probes};
use super::*;

/// Writes a program into the session's home that prints each argument it was given between angle
/// brackets, and returns its path.
fn argument_printer(session: &Session) -> PathBuf {
    let program = session.home().join("show-arguments");
    std::fs::write(
        &program,
        "#!/bin/sh\nfor argument in \"$@\"; do printf '<%s>' \"$argument\"; done\nprintf '\\n'\n",
    )
    .expect("a program that prints its arguments");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
        .expect("the program can be run");
    program
}

/// Launches `vector` at the fenced prompt `enter` opened, and returns the reader's decision.
fn launch_vector_at(
    session: &mut Session,
    enter: &RootEditorEnterParams,
    fence: &EditorFence,
    vector: Vec<String>,
    transaction_seed: u8,
) -> LaunchDecision {
    let id = session.ask(WorkerRequest::Launch(LaunchMailboxRequest {
        session_id: session.session_id,
        transaction: LaunchTransactionId::new(Uuid::from_bytes([transaction_seed; 16])),
        fence_id: fence.fence_id,
        command: LaunchCommand::Arguments(vector),
        expected_prompt_generation: enter.prompt_generation,
        expected_buffer_revision: enter.editor.buffer_revision,
        expected_cwd_revision: enter.cwd_revision,
        deadline_ms: LAUNCH_BUDGET_NOT_UNDER_TEST,
    }));
    let BridgeAnswer::Launch(decision) = session.answer(id) else {
        panic!("the reader answered a launch with something else")
    };
    decision
}

/// Launches `vector` at the next fenced prompt, and returns the reader's decision.
fn launch_vector(
    session: &mut Session,
    vector: Vec<String>,
    prompt_seed: u8,
    transaction_seed: u8,
) -> LaunchDecision {
    let (enter, fence) = session.fenced_prompt(prompt_seed);
    launch_vector_at(session, &enter, &fence, vector, transaction_seed)
}

/// Installs `program` with `words` as its arguments through a launch, and says that the terminal
/// shows the program printing exactly those words.
fn launch_prints_what_was_named(
    session: &mut Session,
    program: &Path,
    words: &[&str],
    prompt_seed: u8,
    transaction_seed: u8,
) {
    let expected: String = words.iter().map(|word| format!("<{word}>")).collect();
    let mut vector = vec![told(program)];
    vector.extend(words.iter().map(|word| (*word).to_owned()));
    let before_install = session.written();
    let decision = launch_vector(session, vector, prompt_seed, transaction_seed);
    assert!(
        matches!(decision, LaunchDecision::Accepted(_)),
        "an empty fenced prompt refused a launch: {decision:?}"
    );
    session.nudge();
    session.expect_event("command_accepted", |event| {
        matches!(event, BridgeEvent::CommandAccepted(_))
    });
    assert!(
        session
            .drew_after(before_install, &expected, REPLY)
            .was_drawn(),
        "the arguments that ran are not the arguments the caller named; wanted {expected}:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-23.54: every word of the vector reaches the program, whatever the shell makes of it
/// when it reads a line.
///
/// PowerShell reads a word that is exactly `--%` as the token that stops its own parsing, and
/// leaves it out of the arguments of a native program. The words around it are ones a shell might
/// also take for an option or a marker, which a launch has to pass on as they are.
pub fn a_launch_passes_every_word_it_is_given(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));

    let program = argument_printer(&session);
    launch_prints_what_was_named(&mut session, &program, &["--%"], 40, 0x81);
    launch_prints_what_was_named(
        &mut session,
        &program,
        &["a", "--%", "b", "--", "-", "-x:y", "--%x"],
        41,
        0x82,
    );
}

/// Words that name a function and an alias of this shell's own, each shadowing a program the
/// system has: `printf` is a function, and `uname` is an alias of that function. Either prints
/// the marker, so a line that ran one of them shows it.
const SHADOWS: &str = "function printf { Write-Output ('kr-shadow-' + 'ran') }; \
    Set-Alias -Name uname -Value printf; \
    function kr-only-a-function { Write-Output ('kr-function-' + 'ran') }; \
    Write-Output ('kr-shadows-' + 'defined')";

/// Defines [`SHADOWS`] in the session, as its first command, so the prompt that follows is the one
/// the launch is made at.
fn define_shadows(session: &mut Session) {
    assert!(
        session.run(SHADOWS, "kr-shadows-defined"),
        "the shell did not take the function and the alias:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-23.54: a launch runs the application its first word names, and a function or an alias
/// of that name stands in for it nowhere.
///
/// A quoted word at command position is still looked up as a command, so a function or an alias
/// of the same name would run in the program's place. The line shows what runs: the application's
/// own path.
pub fn a_launch_runs_the_application_and_not_a_function_or_alias_of_its_name(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    define_shadows(&mut session);

    let uname = std::process::Command::new("uname")
        .arg("-s")
        .output()
        .expect("the system's uname");
    let system = String::from_utf8_lossy(&uname.stdout).trim().to_owned();
    assert!(!system.is_empty(), "the system's uname printed nothing");

    for (vector, expected, prompt_seed, transaction_seed) in [
        (
            vec!["printf", "%s|", "one", "two"],
            "one|two|".to_owned(),
            50,
            0x91,
        ),
        (vec!["uname", "-s"], system, 51, 0x92),
    ] {
        let before_install = session.written();
        let decision = launch_vector(
            &mut session,
            vector.iter().map(|word| (*word).to_owned()).collect(),
            prompt_seed,
            transaction_seed,
        );
        assert!(
            matches!(decision, LaunchDecision::Accepted(_)),
            "an empty fenced prompt refused a launch of {vector:?}: {decision:?}"
        );
        session.nudge();
        session.expect_event("command_accepted", |event| {
            matches!(event, BridgeEvent::CommandAccepted(_))
        });
        assert!(
            session
                .drew_after(before_install, &expected, REPLY)
                .was_drawn(),
            "{vector:?} did not run the application of that name; wanted {expected}:\n{}",
            session.terminal_output()
        );
    }
    assert!(
        !session.terminal_output().contains("kr-shadow-ran"),
        "a function or an alias ran in the place of the program:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-23.54: a first word that names no application is refused, and installs nothing.
///
/// The refusal is the reader's own for a vector it cannot build a line from. A name that is only a
/// function of this shell's own is such a name: the launch asked for a program.
pub fn a_launch_of_a_name_that_is_no_application_is_refused_and_installs_nothing(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    define_shadows(&mut session);

    let (enter, fence) = session.fenced_prompt(52);
    for (name, transaction_seed) in [("kr-only-a-function", 0x93), ("kr-no-such-program", 0x94)] {
        let decision = launch_vector_at(
            &mut session,
            &enter,
            &fence,
            vec![name.to_owned()],
            transaction_seed,
        );
        assert_eq!(
            decision.rejection(),
            Some(LaunchRejectionReason::BufferNotEmpty),
            "{name} is no application, so nothing should have been installed: {decision:?}"
        );
    }

    // Nothing was installed, so the same prompt takes the next launch.
    let before_install = session.written();
    let decision = launch_vector_at(
        &mut session,
        &enter,
        &fence,
        ["printf", "%s|", "three", "four"]
            .map(str::to_owned)
            .to_vec(),
        0x95,
    );
    assert!(
        matches!(decision, LaunchDecision::Accepted(_)),
        "the refusals left something behind: {decision:?}"
    );
    session.nudge();
    session.expect_event("command_accepted", |event| {
        matches!(event, BridgeEvent::CommandAccepted(_))
    });
    assert!(
        session
            .drew_after(before_install, "three|four|", REPLY)
            .was_drawn(),
        "the launch after the refusals did not run:\n{}",
        session.terminal_output()
    );
    assert!(
        !session.terminal_output().contains("kr-function-ran"),
        "a function ran in the place of a program:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-12.07: a launch of a command the host's lookup handler asks the worker about is asked
/// about, as the same command typed at the prompt is.
///
/// The handler answers for a command typed by its name, and runs a path as typed. A launch whose
/// line carried the program's path would start it with none of what an enabled integration adds,
/// so the case launches a program found on the search path and reads what the handler asked.
pub fn a_launch_of_a_command_the_lookup_handler_asks_about_is_asked_about(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);

    let before = session.written();
    let decision = launch_vector(
        &mut session,
        ["kr-probe", "one", "two words"].map(str::to_owned).to_vec(),
        60,
        0xa1,
    );
    assert!(
        matches!(decision, LaunchDecision::Accepted(_)),
        "an empty fenced prompt refused a launch: {decision:?}"
    );
    session.nudge();
    session.expect_event("command_accepted", |event| {
        matches!(event, BridgeEvent::CommandAccepted(_))
    });
    assert!(
        session.drew_after(before, "probe-ran", REPLY).was_drawn(),
        "the program did not run:\n{}",
        session.terminal_output()
    );
    let asked = &session.commands.resolves;
    assert_eq!(
        asked.len(),
        1,
        "a launch of a command the handler answers for was asked about {} times: {asked:?}",
        asked.len()
    );
    assert_eq!(asked[0].argv, ["kr-probe", "one", "two words"]);
    assert_eq!(asked[0].executable, told(&probes.probe()));
}
