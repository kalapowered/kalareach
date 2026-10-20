//! What a launch runs: the argument vector the caller named, in each shell.
//!
//! The reader installs a line, and the shell reads that line again before it runs anything. A word
//! the shell treats as more than itself would reach the program as something else, or not reach it
//! at all, so each case here launches a program that prints each argument it receives between
//! angle brackets and reads the terminal for exactly that text. The echo of the installed line
//! carries no angle brackets, so it cannot produce it.

use kr_protocol::root::LaunchCommand;
use kr_protocol::scalars::Uuid;
use kr_shell_integration::contract::events::BridgeEvent;
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::contract::requests::{
    BridgeAnswer, LaunchDecision, LaunchMailboxRequest, LaunchTransactionId, WorkerRequest,
};

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

/// Launches `vector` at the next fenced prompt, and returns the reader's decision.
fn launch_vector(
    session: &mut Session,
    vector: Vec<String>,
    prompt_seed: u8,
    transaction_seed: u8,
) -> LaunchDecision {
    let (enter, fence) = session.fenced_prompt(prompt_seed);
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
