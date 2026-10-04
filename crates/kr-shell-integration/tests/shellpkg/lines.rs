//! What the root shell's own line does when something interrupts it, and what runs inside it.
//!
//! A line the person accepted is reported to the worker, which answers with the capability minted
//! for it, and its commands are asked about before they start. Each case here is one way that
//! goes differently from the plain run: a cancellation or an exit signal while the worker is
//! being told, a cancellation left over from before the line, a reader a running line starts
//! itself, and the commands that run around a line rather than in it.

use kr_protocol::root::ReaderContext;
use kr_shell_integration::contract::events::BridgeEvent;
use kr_shell_integration::contract::qualification::ShellKind;

use super::commands::{a_session_with_probes, after_the_first_line, last_run};
use super::*;

/// The status a line ended by a signal leaves: 128 plus the signal.
const INTERRUPTED: u64 = 130;
const TERMINATED: u64 = 143;

impl Session {
    /// Waits for the finished block of the line whose command is `command`, and returns its
    /// status.
    ///
    /// # Panics
    ///
    /// Panics when no such block arrives inside the reply window.
    fn status_of(&mut self, command: &str) -> Option<u64> {
        let wanted = command.to_owned();
        self.until(&format!("the finished block of {command:?}"), |commands| {
            commands
                .blocks
                .iter()
                .any(|block| block.command == wanted && block.exit_status.0.is_some())
        });
        self.commands
            .blocks
            .iter()
            .find(|block| block.command == command && block.exit_status.0.is_some())
            .and_then(|block| block.exit_status.0.map(|status| status.get()))
    }
}

/// KR-REQ-12.07, KR-REQ-25.05: a cancellation that arrives while the worker is being told of a
/// line, or asked about its command, ends that line before the command starts: nothing runs, the
/// block finishes with the status a cancelled line leaves, and the next prompt works.
pub fn a_cancellation_while_the_worker_is_told_starts_nothing(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);

    // The worker never answers the question in front of the command.
    session.commands.policy = ResolvePolicy::Silent;
    let asked = session.commands.resolves.len();
    let _ = session.submit("kr-probe cancelled-in-the-question", "probe-ran");
    session.until("the question", |commands| commands.resolves.len() > asked);
    session.type_bytes(CTRL_C);
    assert_eq!(
        session.status_of("kr-probe cancelled-in-the-question"),
        Some(INTERRUPTED),
        "the line did not report the status of a cancelled line"
    );
    assert!(
        probes.runs().is_empty(),
        "a cancelled command started: {:?}",
        probes.runs()
    );
    session.commands.policy = ResolvePolicy::default();
    assert!(session.answered("kr-after-the-question"));

    // The worker never answers the line's own acceptance.
    session.commands.silent_acceptance = true;
    let accepted = session.commands.accepted.len();
    let _ = session.submit("kr-probe cancelled-in-the-acceptance", "probe-ran");
    session.until("the acceptance", |commands| {
        commands.accepted.len() > accepted
    });
    session.type_bytes(CTRL_C);
    assert_eq!(
        session.status_of("kr-probe cancelled-in-the-acceptance"),
        Some(INTERRUPTED)
    );
    assert!(
        probes.runs().is_empty(),
        "a cancelled line ran its command: {:?}",
        probes.runs()
    );
    session.commands.silent_acceptance = false;
    assert!(session.answered("kr-after-the-acceptance"));

    // The control: a line nobody cancels runs, so the two above were ended by the cancellation.
    assert!(session.run("kr-probe not-cancelled", "probe-ran"));
    assert_eq!(last_run(&probes).arguments, ["not-cancelled"]);
}

/// KR-REQ-12.07, KR-REQ-25.05: a shell that is told to end while the worker is asked about a
/// command starts no command, finishes the line's block with the status of that signal, and ends.
pub fn a_termination_while_the_worker_is_asked_starts_nothing_and_ends_the_shell(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);

    session.commands.policy = ResolvePolicy::Silent;
    let asked = session.commands.resolves.len();
    let _ = session.submit("kr-probe terminated", "probe-ran");
    session.until("the question", |commands| commands.resolves.len() > asked);
    let pid = session.child_pid().expect("the shell's process identifier");
    let sent = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("kill starts");
    assert!(sent.success());
    // The block is decided by the status the shell itself holds for the line: it is sent after
    // any foreground child ends and before the shell's own exit check, so a command that had been
    // started would show as a different status, or as a program that ran.
    let status = session.expecting_the_bridge_to_go(|session| {
        let status = session.status_of("kr-probe terminated");
        assert!(
            session.ended_within(REPLY),
            "the shell did not end:\n{}",
            session.terminal_output()
        );
        status
    });
    assert_eq!(status, Some(TERMINATED));
    assert!(
        probes.runs().is_empty(),
        "a command started after the shell was told to end: {:?}",
        probes.runs()
    );
}

/// KR-REQ-25.05: a cancellation left over at the prompt, by a key binding a Ctrl-C ended, is not
/// the next line's: that line runs.
pub fn a_cancellation_left_at_the_prompt_skips_no_line(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);
    // The binding sends this shell the cancellation signal, and the shell is at its prompt when
    // the key that runs it is typed.
    let bound = format!(
        "bind ctrl-x 'kill -INT $fish_pid'; {}",
        print_assembled(kind, "kr-bound")
    );
    assert!(session.run(&bound, "kr-bound"));
    session.type_bytes(&[0x18]);
    assert!(session.run("kr-probe after-the-binding", "probe-ran"));
    assert_eq!(last_run(&probes).arguments, ["after-the-binding"]);
    assert_eq!(
        session.status_of("kr-probe after-the-binding"),
        Some(0),
        "the line a left-over cancellation preceded did not run to its own status"
    );
}

/// KR-REQ-25.05: a line that ends the shell reports its block with the status it ended with.
pub fn a_line_that_ends_the_shell_finishes_its_block(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);
    let _ = session.submit("exit 3", "never-printed-by-the-line");
    let status = session.expecting_the_bridge_to_go(|session| {
        let status = session.status_of("exit 3");
        assert!(session.ended_within(REPLY));
        status
    });
    assert_eq!(status, Some(3));
}

/// KR-REQ-07.84: the capability is the line's own commands' and nothing around the line's: the
/// handler a line runs after itself and the prompt that follows hold none, a shell the line starts
/// keeps it for its own commands, and the next line is not given this one's.
pub fn the_capability_reaches_a_lines_commands_and_nothing_around_them(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);
    let started = |probes: &Probes, word: &str| {
        probes
            .runs()
            .into_iter()
            .filter(|run| run.arguments == [word])
            .collect::<Vec<_>>()
    };

    let defined = format!(
        "function kr_post --on-event fish_postexec; kr-probe in-postexec >/dev/null; end; {}",
        print_assembled(kind, "kr-post-defined")
    );
    assert!(session.run(&defined, "kr-post-defined"));
    assert!(session.run("kr-probe the-lines-own", "probe-ran"));
    let minted = session
        .commands
        .tokens
        .last()
        .cloned()
        .flatten()
        .expect("the line was answered with a capability");
    assert_eq!(
        last_run(&probes).environment.get("KR_DETACH_TOKEN"),
        Some(&minted),
        "the line's own command did not carry its capability"
    );
    let erased = format!(
        "functions -e kr_post; {}",
        print_assembled(kind, "kr-post-erased")
    );
    assert!(session.run(&erased, "kr-post-erased"));
    let post = started(&probes, "in-postexec");
    assert!(!post.is_empty(), "the handler did not run");
    assert!(
        post.iter()
            .all(|run| !run.environment.contains_key("KR_DETACH_TOKEN")),
        "a handler that runs after the line held its capability: {post:?}"
    );

    // The prompt that follows a line draws before the next line is accepted, so it holds none
    // either, whatever it runs.
    let prompt = session.prompt.clone();
    let redefined = format!(
        "function fish_prompt; kr-probe in-the-prompt >/dev/null; printf '%s' '{prompt}'; end; {}",
        print_assembled(kind, "kr-prompt-defined")
    );
    assert!(session.run(&redefined, "kr-prompt-defined"));
    assert!(session.answered("kr-prompt-drawn"));
    let drawn = started(&probes, "in-the-prompt");
    assert!(!drawn.is_empty(), "the prompt did not run its command");
    assert!(
        drawn
            .iter()
            .all(|run| !run.environment.contains_key("KR_DETACH_TOKEN")),
        "the prompt held a capability: {drawn:?}"
    );
    let restored = format!(
        "function fish_prompt; printf '%s' '{prompt}'; end; {}",
        print_assembled(kind, "kr-prompt-restored")
    );
    assert!(session.run(&restored, "kr-prompt-restored"));

    // A shell the line starts is not the root shell: it takes no part in the capability, and its
    // own commands keep the one it inherited, for as many commands as it runs.
    let executable = told(&package.executable);
    let child = format!("'{executable}' -i -c 'kr-probe child-one; kr-probe child-two'");
    let lines = session.commands.tokens.len();
    assert!(session.run(&child, "probe-ran"));
    let minted = session.commands.tokens[lines]
        .clone()
        .expect("the line was answered with a capability");
    // The next command can only run once the child shell has ended, which is after both probes.
    assert!(session.answered("kr-after-the-child"));
    for word in ["child-one", "child-two"] {
        let runs = started(&probes, word);
        assert_eq!(runs.len(), 1, "{word} ran {} times", runs.len());
        assert_eq!(
            runs[0].environment.get("KR_DETACH_TOKEN"),
            Some(&minted),
            "{word}: the child shell lost the line's capability"
        );
    }
}

/// KR-REQ-07.84, KR-REQ-25.05: a reader a running line starts itself (a breakpoint) is not a new
/// prompt. It reports as the line's, at the line's prompt generation, so the worker keeps the
/// line and the capability it has; a command typed at it asks nothing and carries the line's
/// capability; the line reports one block; and the empty-prompt gesture there is the shell's own.
pub fn a_reader_a_line_starts_keeps_the_lines_block_and_capability(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);

    let line = "begin; breakpoint; end; kr-probe outer";
    let reported = session.commands.blocks.len();
    let entries = session.commands.entries.len();
    let _ = session.submit(line, "never-printed-by-the-line");
    session.until("the nested reader's entry", |commands| {
        commands.entries[entries..]
            .iter()
            .any(|entry| entry.reader_context == ReaderContext::ReadBuiltin)
    });
    let outer = session.commands.last_line_reader().clone();
    let outer_token = session
        .commands
        .tokens
        .last()
        .cloned()
        .flatten()
        .expect("the line was answered with a capability");
    let nested = session.commands.entries[entries..]
        .iter()
        .find(|entry| entry.reader_context == ReaderContext::ReadBuiltin)
        .cloned()
        .expect("the nested reader entered");
    assert_eq!(
        nested.prompt_generation, outer.prompt_generation,
        "a reader the line started advanced the prompt generation"
    );
    let (_, idle) = session.expect_event("the nested reader's idle report", |event| {
        matches!(
            event,
            BridgeEvent::ReaderIdle(idle) if idle.reader_context == ReaderContext::ReadBuiltin
        )
    });
    let BridgeEvent::ReaderIdle(idle) = idle else {
        unreachable!()
    };
    assert_eq!(idle.prompt_generation, outer.prompt_generation);

    // A command typed at the nested prompt asks nothing and carries the outer line's capability.
    let asked = session.commands.resolves.len();
    assert!(session.run("kr-probe nested", "probe-ran"));
    assert_eq!(
        session.commands.resolves.len(),
        asked,
        "a command typed at a reader the line started asked"
    );
    assert_eq!(
        last_run(&probes).environment.get("KR_DETACH_TOKEN"),
        Some(&outer_token)
    );

    // Leaving it, the outer line goes on: its own command asks once, at the line's generation,
    // with the line's capability.
    let asked = session.commands.resolves.len();
    session.type_line("exit");
    session.until("the outer line's command", |commands| {
        commands.resolves.len() > asked
    });
    let outer_ask = session.commands.resolves[asked].clone();
    assert_eq!(outer_ask.argv, ["kr-probe", "outer"]);
    assert_eq!(outer_ask.prompt_generation, outer.prompt_generation);
    assert!(session.answered("kr-after-the-outer-line"));
    assert_eq!(
        last_run(&probes).environment.get("KR_DETACH_TOKEN"),
        Some(&outer_token)
    );
    assert_eq!(last_run(&probes).arguments, ["outer"]);
    let blocks: Vec<_> = session.commands.blocks[reported..]
        .iter()
        .filter(|block| block.command == line)
        .collect();
    assert_eq!(
        blocks.len(),
        2,
        "the line reported one block started and one finished, and its nested lines none: {blocks:?}"
    );

    // The gesture at the empty nested prompt is the shell's own end of file, which leaves that
    // reader, and no detach is taken from it.
    let decisions = session.events.managed_decisions();
    let _ = session.submit("begin; breakpoint; end", "never-printed-by-the-line");
    let entries = session.commands.entries.len();
    session.until("the second nested reader", |commands| {
        commands.entries[entries.saturating_sub(1)..]
            .iter()
            .any(|entry| entry.reader_context == ReaderContext::ReadBuiltin)
    });
    session.type_bytes(CTRL_D);
    assert!(session.answered("kr-after-the-gesture"));
    session.barrier();
    assert_eq!(
        session.events.managed_decisions(),
        decisions,
        "the gesture at a reader the line started was taken as a detach"
    );
    assert!(session.alive(), "the gesture ended the shell");
}

// --------------------------------------------------------------------------------------------
// PowerShell: what the module reports of a line, and the entry points a lookup handler calls.
// --------------------------------------------------------------------------------------------

/// KR-REQ-12.07: the entry points answer for the origin the lookup names and nothing else, and no
/// argument makes them fail: a value of the wrong kind is an answer of nothing.
pub fn the_entry_points_answer_by_origin_and_never_fail(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);

    // The same line, with the origin the only difference: the line is the command it asks about.
    assert!(session.run(
        "Test-KalaReachCommand -Origin Internal -Name Test-KalaReachCommand",
        "False"
    ));
    assert!(session.run(
        "Test-KalaReachCommand -Origin Runspace -Name Test-KalaReachCommand",
        "True"
    ));
    // The name is compared as typed, ignoring case, and is a command name and not a path.
    assert!(session.run(
        "Test-KalaReachCommand -Origin Runspace -Name test-kalareachcommand",
        "True"
    ));
    assert!(session.run(
        "Test-KalaReachCommand -Origin Runspace -Name Test-KalaReachCommand.exe",
        "False"
    ));
    assert!(session.run(
        "Test-KalaReachCommand -Origin Runspace -Name ./Test-KalaReachCommand",
        "False"
    ));

    // A value of the wrong kind is no answer and no failure.
    for line in [
        "Test-KalaReachCommand -Origin 1 -Name @(1,2)",
        "Test-KalaReachCommand -Origin $null -Name $null",
        "Test-KalaReachCommand -Origin @{a=1} -Name (Get-Date)",
    ] {
        let before = session.written();
        assert!(session.run(line, "False"), "{line}");
        assert!(
            !session
                .shown_before(before, "False")
                .to_lowercase()
                .contains("exception"),
            "{line} failed"
        );
    }
    // Asking about a command with arguments that are not text is an answer of nothing, and the
    // line still ends.
    assert!(session.answered("kr-after-the-wrong-kinds"));
}

/// KR-REQ-25.05: a line's status is the one the shell would show for it, read before anything of
/// the module's own can change it.
pub fn a_line_reports_the_status_the_shell_would_show(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);
    let exits = format!("& '{}'", told(&probes.path("exits.ps1")));
    let cases: Vec<(&str, String, u64)> = vec![
        // A native command that fails is its exit code, and one that succeeds is nothing.
        ("a native failure", "sh -c 'exit 5'".to_owned(), 5),
        ("a native success", "sh -c 'exit 0'".to_owned(), 0),
        // The last native command of a pipeline decides.
        (
            "a failing last stage",
            "kr-probe one | sh -c 'exit 3'".to_owned(),
            3,
        ),
        // A negative code is the unsigned 32-bit value it is on the wire.
        ("a negative exit code", exits, 4_294_967_295),
        // A failure of another kind after a native failure is not about the exit code.
        (
            "a failing cmdlet after a native failure",
            "sh -c 'exit 3'; Get-Item /kr-no-such-item".to_owned(),
            1,
        ),
        (
            "a failing cmdlet",
            "Get-Item /kr-no-such-item".to_owned(),
            1,
        ),
        // A native failure the shell raises as an error of its own is its exit code too.
        (
            "a native failure raised as an error",
            "$PSNativeCommandUseErrorActionPreference = $true; sh -c 'exit 5'".to_owned(),
            5,
        ),
    ];
    for (what, line, status) in cases {
        let _ = session.submit(&line, "never-printed-by-the-line");
        assert_eq!(
            session.status_of(&line),
            Some(status),
            "{what}: the status of {line:?}"
        );
    }
}

/// KR-REQ-25.05: the directory a block reports is the file system's, where a native command
/// starts, and not the location of another provider the person has moved to.
pub fn a_block_reports_the_file_system_directory(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);
    assert!(session.run(
        &format!("Set-Location Env:; {}", print_assembled(kind, "kr-moved")),
        "kr-moved"
    ));
    let reported = session.commands.blocks.len();
    assert!(session.run("kr-probe in-another-provider", "probe-ran"));
    session.until("the line's block", |commands| {
        commands.blocks[reported..]
            .iter()
            .any(|block| block.command == "kr-probe in-another-provider")
    });
    let block = session.commands.blocks[reported..]
        .iter()
        .find(|block| block.command == "kr-probe in-another-provider")
        .cloned()
        .expect("the line's block");
    assert_eq!(block.cwd, told(&session.home()));
}

/// KR-REQ-12.07: a line the lookup handler substituted a script block for has the status of the
/// launcher it ran, which is what the program would have left.
pub fn a_launcher_leaves_its_exit_status_as_the_lines(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);
    session.commands.policy = ResolvePolicy::Backend {
        launcher: told(&probes.failing_launcher()),
        environment: Vec::new(),
        added: Vec::new(),
    };
    let _ = session.submit(
        "kr-probe through-a-failing-launcher",
        "never-printed-by-the-line",
    );
    assert_eq!(
        session.status_of("kr-probe through-a-failing-launcher"),
        Some(7)
    );
    session.commands.policy = ResolvePolicy::default();
    let _ = session.submit("kr-probe as-typed", "never-printed-by-the-line");
    assert_eq!(session.status_of("kr-probe as-typed"), Some(0));
}

/// KR-REQ-07.84, KR-REQ-25.05: a prompt a running line opens ($Host.EnterNestedPrompt()) is not a
/// new prompt of the root editor. It reports as the line's, at the line's prompt generation; a
/// command typed at it asks nothing and carries the line's capability; and the line reports the
/// one block.
pub fn a_prompt_a_line_opens_keeps_the_lines_block_and_capability(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);

    after_the_first_line(&mut session, kind);
    let line = "$Host.EnterNestedPrompt()";
    let reported = session.commands.blocks.len();
    let entries = session.commands.entries.len();
    let _ = session.submit(line, "never-printed-by-the-line");
    session.until("the nested prompt's entry", |commands| {
        commands.entries[entries..]
            .iter()
            .any(|entry| entry.reader_context == ReaderContext::ReadBuiltin)
    });
    let outer = session.commands.last_line_reader().clone();
    let outer_token = session
        .commands
        .tokens
        .last()
        .cloned()
        .flatten()
        .expect("the line was answered with a capability");
    let nested = session.commands.entries[entries..]
        .iter()
        .find(|entry| entry.reader_context == ReaderContext::ReadBuiltin)
        .cloned()
        .expect("the nested reader entered");
    assert_eq!(
        nested.prompt_generation, outer.prompt_generation,
        "a prompt the line opened advanced the prompt generation"
    );
    let (_, idle) = session.expect_event("the nested prompt's idle report", |event| {
        matches!(
            event,
            BridgeEvent::ReaderIdle(idle) if idle.reader_context == ReaderContext::ReadBuiltin
        )
    });
    let BridgeEvent::ReaderIdle(idle) = idle else {
        unreachable!()
    };
    assert_eq!(idle.prompt_generation, outer.prompt_generation);

    // A command typed at the nested prompt asks nothing and carries the outer line's capability.
    let asked = session.commands.resolves.len();
    assert!(session.run("kr-probe nested", "probe-ran"));
    assert_eq!(
        session.commands.resolves.len(),
        asked,
        "a command typed at a prompt the line opened asked"
    );
    assert_eq!(
        last_run(&probes).environment.get("KR_DETACH_TOKEN"),
        Some(&outer_token)
    );

    // Leaving it, the outer line ends with one block reported for it, and no nested line has one.
    session.type_line("exit");
    assert!(session.answered("kr-after-the-outer-line"));
    session.until("the outer line's finished block", |commands| {
        commands.blocks[reported..]
            .iter()
            .any(|block| block.command == line && block.exit_status.0.is_some())
    });
    let blocks: Vec<_> = session.commands.blocks[reported..]
        .iter()
        .filter(|block| block.command == line)
        .collect();
    assert_eq!(
        blocks.len(),
        2,
        "the line reported one block started and one finished: {blocks:?}"
    );
    assert!(
        session.commands.blocks[reported..]
            .iter()
            .all(|block| block.command == line
                || block.command == print_assembled(kind, "kr-after-the-outer-line")),
        "a line typed at the nested prompt reported a block: {:?}",
        session.commands.blocks[reported..]
            .iter()
            .map(|block| (
                &block.command,
                block.exit_status.0.map(|status| status.get())
            ))
            .collect::<Vec<_>>()
    );
}

/// KR-REQ-07.84: a Ctrl-C that arrives while the worker has not answered a line's acceptance is
/// not taken by the module, and the prompt after the line reads through the editor as it did.
///
/// What the console does with the key while the module waits is not something this package can
/// prove, so this case records what the line did and requires what the module owes: the line's
/// block and a prompt that works.
pub fn a_cancellation_during_an_unanswered_acceptance_leaves_the_prompt_working(kind: ShellKind) {
    let package = Package::built(kind);
    let probes = Probes::new();
    let mut session = a_session_with_probes(&package, &probes);
    session.commands.silent_acceptance = true;
    let accepted = session.commands.accepted.len();
    let line = "kr-probe cancelled-in-the-acceptance";
    let _ = session.submit(line, "probe-ran");
    session.until("the acceptance", |commands| {
        commands.accepted.len() > accepted
    });
    session.type_bytes(CTRL_C);
    let status = session.status_of(line);
    session.commands.silent_acceptance = false;
    assert!(session.answered("kr-after-the-acceptance"));
    println!(
        "a Ctrl-C during an unanswered acceptance: the line ran {} time(s) and its block finished with {status:?}",
        probes.runs().len()
    );
}
