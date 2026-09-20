//! What both managed packages have to reproduce, driven through the built shell.
//!
//! Every expectation here comes from the committed scenarios under `fixtures/shell-bridge/` or
//! from the contract's own constants, so these tests and the worker are checked against one
//! corpus. Each case names the requirement rows it closes.

use std::time::Duration;

use kr_protocol::root::{
    AcceptedOrigin, DETACH_HINT, EditorBufferRevision, EditorLeaveReason, FENCE_EXCHANGE_TIMEOUT,
    FenceCause, LAUNCH_READER_BUDGET, LaunchCommand, PromptGeneration, RootEditorFenceParams,
    RootEditorFenceResult,
};
use kr_protocol::scalars::{DurationMs, U64, Uuid};
use kr_shell_integration::contract::events::{
    BridgeEvent, ConsumeReason, EofGesture, NativeReason, PreEofDecision,
};
use kr_shell_integration::contract::fixtures::{PreEofStep, Script};
use kr_shell_integration::contract::qualification::{BridgeAbi, DetachExclusion, ShellKind};
use kr_shell_integration::contract::requests::{
    BridgeAnswer, CancelKeyWait, LaunchDecision, LaunchMailboxRequest, LaunchRejectionReason,
    LaunchTransactionId, WorkerRequest,
};

use super::*;

impl Session {
    /// Waits for the hooks the guarded startup entry activates and the first primary reader.
    ///
    /// # Panics
    ///
    /// Panics when either does not arrive, which means the startup entry did not run or the reader
    /// did not report itself.
    pub fn first_prompt(&mut self) -> RootEditorEnterParams {
        self.expect_event("hooks_activated", |event| {
            matches!(event, BridgeEvent::HooksActivated(_))
        });
        let (_, event) = self.expect_event("the first editor entry", |event| {
            matches!(event, BridgeEvent::EditorEnter(_))
        });
        // From here the shell has a reader, so a key typed at it is a step it takes.
        self.reading = true;
        let entry = as_enter(&event).clone();
        self.last_entry = Some(entry.clone());
        entry
    }

    /// Waits for the next primary reader.
    pub fn next_prompt(&mut self) -> RootEditorEnterParams {
        let (_, event) = self.expect_event("an editor entry", |event| {
            matches!(
                event,
                BridgeEvent::EditorEnter(params)
                    if params.reader_context == kr_protocol::root::ReaderContext::Primary
            )
        });
        let entry = as_enter(&event).clone();
        self.last_entry = Some(entry.clone());
        entry
    }

    /// Runs one fence exchange against the reader and returns what it acknowledged.
    ///
    /// # Panics
    ///
    /// Panics when the reader refuses a fence for the reader it is actually running.
    pub fn fence_exchange(
        &mut self,
        enter: &RootEditorEnterParams,
        fence: FenceId,
    ) -> kr_protocol::root::FenceAcknowledgement {
        self.fence_exchange_before(enter, fence, Instant::now() + REPLY)
    }

    /// Runs one fence exchange the reader has until `deadline` to answer.
    ///
    /// A caller that exchanges more than once while it waits for the reader's state to settle
    /// passes every exchange the same instant, so the settlement is bounded by that one instant
    /// instead of by a reply window each time it asks.
    ///
    /// # Panics
    ///
    /// Panics when the reader refuses a fence for the reader it is actually running, and when it
    /// has not answered by `deadline`.
    pub fn fence_exchange_before(
        &mut self,
        enter: &RootEditorEnterParams,
        fence: FenceId,
        deadline: Instant,
    ) -> kr_protocol::root::FenceAcknowledgement {
        let id = self.ask(WorkerRequest::Fence(RootEditorFenceParams {
            session_id: self.session_id,
            fence_id: fence,
            prompt_generation: enter.prompt_generation,
            reader_revision: enter.reader_revision,
            deadline_ms: FENCE_EXCHANGE_TIMEOUT,
            cause: FenceCause::EditorEntry,
        }));
        match self.answer_before(id, deadline) {
            BridgeAnswer::Fence(RootEditorFenceResult::Acknowledged(acknowledgement)) => {
                acknowledgement
            }
            BridgeAnswer::Fence(RootEditorFenceResult::Refused(refusal)) => {
                panic!("the reader refused its own fence: {:?}", refusal.reason)
            }
            other => panic!("the reader answered a fence with {other:?}"),
        }
    }

    /// Takes the reader to a fenced empty prompt and returns the entry and the fence.
    pub fn fenced_prompt(&mut self, index: u8) -> (RootEditorEnterParams, EditorFence) {
        let enter = self.next_prompt();
        let fence = fence_for(&enter, fence_id(index), attachment_id(1), epoch(4));
        // One deadline covers the exchanges and the waits between them, so asking the reader again
        // never buys it another reply window.
        let deadline = Instant::now() + REPLY;
        let mut acknowledgement = self.fence_exchange_before(&enter, fence.fence_id, deadline);
        while !(acknowledgement.queues.tty_typeahead_drained
            && acknowledgement.queues.macro_input_drained
            && acknowledgement.queues.partial_key_drained)
            && Instant::now() < deadline
        {
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(20)),
            );
            if Instant::now() >= deadline {
                break;
            }
            acknowledgement = self.fence_exchange_before(&enter, fence.fence_id, deadline);
        }
        assert!(
            acknowledgement.queues.tty_typeahead_drained
                && acknowledgement.queues.macro_input_drained
                && acknowledgement.queues.partial_key_drained,
            "an idle reader reported a queue still holding input: {:?}",
            acknowledgement.queues
        );
        self.publish(&fence);
        (enter, fence)
    }

    /// Clears whatever is in the edit buffer.
    pub fn clear_line(&mut self) {
        self.type_bytes(CTRL_U);
        std::thread::sleep(Duration::from_millis(60));
    }
}

/// KR-REQ-07.34, KR-REQ-07.35, KR-REQ-07.85, and `handshake-accept`.
pub fn the_handshake_declares_the_packaged_reader(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let mut session = Session::start(&package);
    let hello = session.hello.clone();

    assert_eq!(hello.protocol, BRIDGE_PROTOCOL);
    assert_eq!(hello.session_id, session.session_id);
    assert_eq!(hello.shell.kind, kind);
    // The declaration is exactly this shell's own reader, which is what `qualify` admits.
    assert_eq!(hello.abi, BridgeAbi::qualified(kind));
    assert_eq!(
        hello.shell.executable,
        package.executable.to_string_lossy(),
        "the package names the executable it was launched as"
    );
    assert_eq!(
        hello.shell.integration_version,
        package.record["shell"]["integration_version"]
            .as_str()
            .expect("the record names an integration version")
    );
    assert_eq!(
        hello.shell.editor_abi,
        package.record["shell"]["editor_abi"]
            .as_str()
            .expect("the record names an editor ABI")
    );
    let declared: Vec<String> = hello
        .shell
        .patches
        .iter()
        .map(|patch| patch.name.clone())
        .collect();
    assert_eq!(
        declared,
        package.patch_names(),
        "every published patch is named in the handshake"
    );
    if package.record["build"]["upstream"]["sha256"]
        .as_str()
        .is_some_and(|digest| !digest.is_empty())
    {
        assert!(
            !hello.shell.patches.is_empty(),
            "a package built from a patched release declares the patches behind it"
        );
    } else {
        // A package that builds no shell patches nothing, so what it declares instead is the
        // module tree it binds into, with the ABI each module was built against.
        assert!(
            hello.shell.patches.is_empty(),
            "a package that patches no source declared a patch"
        );
        assert!(
            !hello.shell.modules.is_empty(),
            "a qualified module package declares the module tree it binds into"
        );
    }
    for module in &hello.shell.modules {
        assert_eq!(
            module.editor_abi, hello.shell.editor_abi,
            "a module in the tree was built against another editor ABI"
        );
    }

    // The process the kernel sees is the process the declaration names.
    assert_eq!(
        u64::from(session.child_pid().expect("a running shell")),
        hello.shell_process.pid.get(),
        "the handshake binds this shell's own process"
    );
    assert!(
        hello.shell_process.start_value.get() > 0,
        "the kernel's start value is part of what the worker compares"
    );
    if cfg!(target_os = "linux") {
        assert_eq!(
            hello.shell_process.source,
            kr_protocol::identity::ProcessStartSource::LinuxProcStat
        );
        let recorded = linux_start_value(hello.shell_process.pid.get());
        assert_eq!(
            Some(hello.shell_process.start_value.get()),
            recorded,
            "the package reports the value the host reads for the same process"
        );
    }

    // The accept is the contract's, including the hint an unattributable gesture prints.
    assert_eq!(session.accepted.hold_ms, FENCE_EXCHANGE_TIMEOUT);
    assert_eq!(session.accepted.hint, DETACH_HINT);
    assert_eq!(
        session.accepted.unexport,
        vec![
            "KR_SHELL_BRIDGE".to_owned(),
            "KR_SHELL_BRIDGE_SECRET".to_owned()
        ]
    );

    session.first_prompt();

    // The bootstrap values have left the exported environment, so nothing a child starts inherits
    // them and the user's own startup file never saw the secret.
    let speech = dialect(kind);
    assert!(
        session.run(speech.bootstrap_probe, speech.bootstrap_gone),
        "the bootstrap values are still exported:\n{}",
        session.terminal_output()
    );
    assert!(
        session.run(speech.user_configuration_probe, "kr-config=1"),
        "the person's own startup configuration did not survive:\n{}",
        session.terminal_output()
    );
}

/// `handshake-reject`: a child shell has nothing to activate from.
pub fn a_child_shell_has_nothing_to_activate_from(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();

    // The same packaged shell, started as a child of the managed root: it inherits neither value,
    // so it attempts no handshake at all and the endpoint sees nothing.
    let command = child_probe(kind, &package.executable);
    assert!(
        session.run(&command, "kr-child=[unset]"),
        "a child inherited the endpoint:\n{}",
        session.terminal_output()
    );
    assert!(
        session.alive(),
        "the root shell did not survive starting a child"
    );
}

/// KR-REQ-07.34, KR-REQ-07.35: the reader's own boundaries, and the fence its state proves.
pub fn the_reader_reports_its_boundaries_and_proves_its_own_state(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let mut session = Session::start(&package);
    let first = session.first_prompt();
    assert_eq!(
        first.reader_context,
        kr_protocol::root::ReaderContext::Primary
    );
    assert!(first.editor.buffer_empty, "a new prompt starts empty");
    assert!(
        first.editor.pending.is_idle(),
        "nothing is pending at entry"
    );

    // The fence rests on the reader's own atomic read: the queues, the buffer and the invoking
    // sequence together, at one instant. The reader reaches that instant once the bytes its own
    // startup left behind have drained, so this asks again until the state it reports has settled.
    // One deadline covers every exchange and every wait between them.
    let deadline = Instant::now() + REPLY;
    let mut acknowledgement = session.fence_exchange_before(&first, fence_id(1), deadline);
    while Instant::now() < deadline
        && (!acknowledgement.editor.buffer_empty
            || acknowledgement.snapshot.queued_keys != U64::new(0)
            || acknowledgement.snapshot.pending_bytes != U64::new(0))
    {
        std::thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(10)),
        );
        if Instant::now() >= deadline {
            break;
        }
        acknowledgement = session.fence_exchange_before(&first, fence_id(1), deadline);
    }
    assert_eq!(acknowledgement.fence_id, fence_id(1));
    assert_eq!(acknowledgement.prompt_generation, first.prompt_generation);
    assert_eq!(acknowledgement.reader_revision, first.reader_revision);
    assert_eq!(acknowledgement.cwd_revision, first.cwd_revision);
    assert!(acknowledgement.editor.buffer_empty);
    assert_eq!(acknowledgement.snapshot.queued_keys, U64::new(0));
    assert_eq!(acknowledgement.snapshot.pending_bytes, U64::new(0));

    // A request naming a reader that is not the one running says nothing about the one that is.
    let stale = session.ask(WorkerRequest::Fence(RootEditorFenceParams {
        session_id: session.session_id,
        fence_id: fence_id(2),
        prompt_generation: first.prompt_generation,
        reader_revision: kr_protocol::root::ReaderRevision::new(first.reader_revision.get() + 9),
        deadline_ms: FENCE_EXCHANGE_TIMEOUT,
        cause: FenceCause::Retry,
    }));
    match session.answer(stale) {
        BridgeAnswer::Fence(RootEditorFenceResult::Refused(refusal)) => assert_eq!(
            refusal.reason,
            kr_protocol::root::FenceRefusalReason::ReaderMoved
        ),
        other => panic!("a moved reader acknowledged a fence: {other:?}"),
    }

    // Acceptance is reported from the reader, before the leave, and the next prompt is a new
    // reader with its own generation.
    session.type_line("echo kr-boundary-ok");
    let (_, accepted) = session.expect_event("command_accepted", |event| {
        matches!(event, BridgeEvent::CommandAccepted(_))
    });
    let BridgeEvent::CommandAccepted(accepted) = accepted else {
        unreachable!()
    };
    assert_eq!(accepted.prompt_generation, first.prompt_generation);
    assert_eq!(
        accepted.origin,
        AcceptedOrigin::Unverifiable,
        "with no fence published the reader cannot attribute the line"
    );
    let (_, left) = session.expect_event("editor_leave", |event| {
        matches!(event, BridgeEvent::EditorLeave(_))
    });
    let BridgeEvent::EditorLeave(left) = left else {
        unreachable!()
    };
    assert_eq!(left.reason, EditorLeaveReason::CommandAccepted);
    assert_eq!(left.prompt_generation, first.prompt_generation);
    assert!(session.wait_for_output("kr-boundary-ok", REPLY));

    let second = session.next_prompt();
    assert!(
        second.prompt_generation.get() > first.prompt_generation.get(),
        "a new primary reader is a new prompt generation"
    );

    // A continuation line is its own reader context, and it is not the root editor's prompt.
    if let Some((open, close)) = dialect(kind).continuation {
        session.type_line(open);
        let (_, event) = session.expect_event("a continuation reader", |event| {
            matches!(
                event,
                BridgeEvent::EditorEnter(params)
                    if params.reader_context == kr_protocol::root::ReaderContext::Continuation
            )
        });
        let _ = as_enter(&event);
        session.type_line(close);
        assert!(session.wait_for_output("kr-continuation-ok", REPLY));
    }
}

/// KR-REQ-07.71, KR-REQ-07.72, and `enter-fence-acknowledge-detach`.
pub fn an_eligible_gesture_under_a_fence_is_an_attributable_detach(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    session.type_line("echo kr-ready");
    assert!(session.wait_for_output("kr-ready", REPLY));

    let (enter, fence) = session.fenced_prompt(1);
    session.type_bytes(CTRL_D);

    let (id, event) = session.expect_event("eof_detach", |event| {
        matches!(event, BridgeEvent::EofDetach(_))
    });
    let BridgeEvent::EofDetach(detach) = event else {
        unreachable!()
    };
    assert_eq!(detach.fence_id, fence.fence_id);
    assert_eq!(detach.prompt_generation, enter.prompt_generation);
    assert_eq!(detach.input_epoch, fence.input_epoch);
    session.answer_event(id, detached(attachment_id(1)));

    assert!(
        !session.saw_event(Duration::from_millis(400), |event| matches!(
            event,
            BridgeEvent::PreEofConsumed(_)
        )),
        "an attributable gesture is submitted, not consumed"
    );
    assert!(
        session.alive(),
        "the gesture ended the shell instead of detaching an attachment"
    );

    // After a successful detach the bridge drops its fence, so a repeated gesture cannot take on
    // the next attachment's identity.
    session.type_bytes(CTRL_D);
    let (_, repeated) = session.expect_event("pre_eof_consumed", |event| {
        matches!(event, BridgeEvent::PreEofConsumed(_))
    });
    let BridgeEvent::PreEofConsumed(repeated) = repeated else {
        unreachable!()
    };
    assert_eq!(repeated.reason, ConsumeReason::FenceMissing);
    assert!(session.alive());
}

/// KR-REQ-07.71, KR-REQ-07.72, and `eof-missing-fence`, `eof-stale-fence`, `eof-repeated-after-detach`.
pub fn an_unattributable_gesture_is_consumed_with_one_hint_per_prompt(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    session.type_line("echo kr-ready");
    assert!(session.wait_for_output("kr-ready", REPLY));
    let enter = session.next_prompt();

    session.type_bytes(CTRL_D);
    let (_, first) = session.expect_event("pre_eof_consumed", |event| {
        matches!(event, BridgeEvent::PreEofConsumed(_))
    });
    let BridgeEvent::PreEofConsumed(first) = first else {
        unreachable!()
    };
    assert_eq!(first.reason, ConsumeReason::FenceMissing);
    assert!(first.hint_printed);
    assert_eq!(first.prompt_generation, enter.prompt_generation);
    assert!(
        session.wait_for_output(DETACH_HINT, REPLY),
        "the hint was not printed:\n{}",
        session.terminal_output()
    );
    let after_first = session.terminal_output().matches(DETACH_HINT).count();
    if kind == ShellKind::Fish {
        let hint_pos = session.terminal_output().rfind(DETACH_HINT).unwrap();
        let prompt = session.prompt.clone();
        assert!(
            session.wait_for_output_after(hint_pos, &prompt, REPLY),
            "the prompt was not redrawn after the hint:\n{}",
            session.terminal_output()
        );
    }

    session.type_bytes(CTRL_D);
    let (_, second) = session.expect_event("a second pre_eof_consumed", |event| {
        matches!(event, BridgeEvent::PreEofConsumed(_))
    });
    let BridgeEvent::PreEofConsumed(second) = second else {
        unreachable!()
    };
    assert!(
        !second.hint_printed,
        "the hint is printed at most once per prompt"
    );
    assert_eq!(
        session.terminal_output().matches(DETACH_HINT).count(),
        after_first,
        "a second gesture at one prompt printed the hint again"
    );
    assert!(session.alive(), "an unattributable gesture ended the shell");

    // A fence from an earlier prompt is as stale as none at all.
    let stale = fence_for(&enter, fence_id(3), attachment_id(2), epoch(6));
    session.publish(&stale);
    session.type_line("echo kr-next-prompt");
    assert!(session.wait_for_output("kr-next-prompt", REPLY));
    let _ = session.next_prompt();
    session.type_bytes(CTRL_D);
    let (_, third) = session.expect_event("a stale-fence consume", |event| {
        matches!(event, BridgeEvent::PreEofConsumed(_))
    });
    let BridgeEvent::PreEofConsumed(third) = third else {
        unreachable!()
    };
    assert_eq!(third.reason, ConsumeReason::FenceStale);
    assert!(third.hint_printed, "a new prompt prints the hint again");
}

/// `eof-repeated-after-detach`: a detach the worker refuses is consumed with the hint.
pub fn a_refused_detach_is_consumed_with_the_hint(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    session.type_line("echo kr-ready");
    assert!(session.wait_for_output("kr-ready", REPLY));

    let (_, fence) = session.fenced_prompt(4);
    session.type_bytes(CTRL_D);
    let (id, event) = session.expect_event("eof_detach", |event| {
        matches!(event, BridgeEvent::EofDetach(_))
    });
    let BridgeEvent::EofDetach(detach) = event else {
        unreachable!()
    };
    assert_eq!(detach.fence_id, fence.fence_id);
    session.answer_event(id, detach_refusal());

    let (_, consumed) = session.expect_event("pre_eof_consumed", |event| {
        matches!(event, BridgeEvent::PreEofConsumed(_))
    });
    let BridgeEvent::PreEofConsumed(consumed) = consumed else {
        unreachable!()
    };
    assert!(consumed.hint_printed);
    assert!(
        session.wait_for_output(DETACH_HINT, REPLY),
        "a refused detach printed no hint"
    );
    assert!(session.alive());
}

/// `detach-condition-exclusions`: outside the condition the editor keeps the key.
pub fn the_detach_condition_excludes_what_the_corpus_names(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let named = excluded_states();
    let speech = dialect(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    // Outside the detach condition the key is the editor's own, and at an empty prompt the
    // editor's own answer can be to end the shell. Where the shell has a setting of its own for
    // that, the person's setting is what makes the answer observable without ending this session,
    // and it is left exactly as they set it; where it has none, the buffer is not empty, so the
    // editor's own answer is to delete a character.
    session.type_line(speech.ignore_eof_on.unwrap_or("echo kr-ready"));
    assert!(session.wait_for_output("kr-ready", REPLY));
    let (_, _fence) = session.fenced_prompt(5);

    // Each of these puts the reader into one excluded state and offers it the gesture. The
    // contract's answer is native, so the reader keeps the key: no detach, no consume, and the
    // shell carries on.
    let mut driven: Vec<DetachExclusion> = Vec::new();
    for drive in exclusion_drives(kind) {
        if let Some((command, marker)) = drive.prepare {
            session.type_line(command);
            assert!(
                session.wait_for_output(marker, REPLY),
                "{} could not be prepared:\n{}",
                drive.exclusion.as_str(),
                session.terminal_output()
            );
            std::thread::sleep(Duration::from_millis(200));
            session.forget_events();
        }
        for bytes in drive.setup {
            session.type_bytes(bytes);
            std::thread::sleep(Duration::from_millis(80));
        }
        session.type_bytes(CTRL_D);
        assert!(
            !session.saw_event(Duration::from_millis(500), |event| matches!(
                event,
                BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
            )),
            "{} did not exclude the gesture:\n{}",
            drive.exclusion.as_str(),
            session.terminal_output()
        );
        for bytes in drive.teardown {
            session.type_bytes(bytes);
            std::thread::sleep(Duration::from_millis(80));
        }
        session.clear_line();
        assert!(
            session.alive(),
            "{} ended the shell",
            drive.exclusion.as_str()
        );
        driven.push(drive.exclusion);
    }

    // The reader the shell's own `read` starts is not the root editor's prompt.
    if let Some(command) = read_builtin_command(kind) {
        session.type_line(command);
        std::thread::sleep(Duration::from_millis(500));
        session.forget_events();
        session.type_bytes(CTRL_D);
        assert!(
            !session.saw_event(Duration::from_millis(600), |event| matches!(
                event,
                BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
            )),
            "a gesture inside the read builtin was treated as the root editor's"
        );
        assert!(
            session.alive(),
            "the read builtin's gesture ended the shell"
        );
        driven.push(DetachExclusion::ReadBuiltin);
        session.type_line("echo kr-read-done");
        assert!(session.wait_for_output("kr-read-done", REPLY));
    }

    // A vi motion waits for its target, and the gesture belongs to that wait. It needs the vi
    // keymap, which is the person's own setting, so it is put back afterwards.
    if let Some((vi_mode, emacs_mode)) = vi_keymap_commands(kind) {
        session.clear_line();
        session.forget_events();
        session.type_line(vi_mode);
        assert!(session.wait_for_output("kr-vi-on", REPLY));
        let vi_prompt = session.next_prompt();
        std::thread::sleep(Duration::from_millis(300));
        session.forget_events();
        session.type_bytes(ESCAPE);
        std::thread::sleep(Duration::from_millis(120));
        session.type_bytes(b"d");
        std::thread::sleep(Duration::from_millis(120));
        session.type_bytes(CTRL_D);
        assert!(
            !session.saw_event(Duration::from_millis(600), |event| matches!(
                event,
                BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
            )),
            "a gesture a vi motion was waiting for was treated as a detach"
        );
        assert!(session.alive(), "a vi motion's gesture ended the shell");
        driven.push(DetachExclusion::ViMotion);
        session.type_bytes(CTRL_C);
        std::thread::sleep(Duration::from_millis(150));

        // A count being accumulated for the command that follows it is the same kind of state.
        // The editor's own answer to the gesture in this keymap is to end the shell, which is
        // exactly what the contract says it may do outside the detach condition, so what is
        // asserted here is the state the reader reports rather than what the key would do: the
        // condition is evaluated against that state, and the corpus says what it decides.
        if speech.vi_counts {
            session.type_bytes(ESCAPE);
            std::thread::sleep(Duration::from_millis(120));
            session.type_bytes(b"2");
            std::thread::sleep(Duration::from_millis(200));
            let held = session.fence_exchange(&vi_prompt, fence_id(22));
            assert!(
                held.editor.pending.numeric_argument,
                "a reader accumulating a count reported nothing pending: {:?}",
                held.editor.pending
            );
            assert!(
                !held.queues.partial_key_drained,
                "a reader accumulating a count reported its partial-key queue clear"
            );
            driven.push(DetachExclusion::NumericArgument);
            session.type_bytes(ESCAPE);
            std::thread::sleep(Duration::from_millis(120));
            session.type_bytes(b"i");
            std::thread::sleep(Duration::from_millis(150));
        }
        session.type_line(emacs_mode);
        assert!(session.wait_for_output("kr-vi-off", REPLY));
    }

    // A macro the reader is replaying is the reader's own input, not a gesture a person made, and
    // a binding that feeds the gesture itself proves the source is what excludes it.
    if let Some(bind_macro) = macro_binding(kind) {
        session.clear_line();
        session.type_line(bind_macro);
        assert!(session.wait_for_output("kr-macro-bound", REPLY));
        std::thread::sleep(Duration::from_millis(300));
        session.forget_events();
        session.type_bytes(CTRL_T);
        assert!(
            !session.saw_event(Duration::from_millis(600), |event| matches!(
                event,
                BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
            )),
            "a gesture a macro produced was treated as one a person made"
        );
        assert!(session.alive(), "macro input ended the shell");
        driven.push(DetachExclusion::MacroInput);
        session.clear_line();
    }

    // A continuation line is a different reader, so the gesture is the editor's there too.
    if let Some((open, close)) = speech.continuation {
        session.clear_line();
        session.type_line(open);
        session.expect_event("a continuation reader", |event| {
            matches!(
                event,
                BridgeEvent::EditorEnter(params)
                    if params.reader_context == kr_protocol::root::ReaderContext::Continuation
            )
        });
        session.type_bytes(CTRL_D);
        assert!(
            !session.saw_event(Duration::from_millis(500), |event| matches!(
                event,
                BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
            )),
            "a continuation line did not exclude the gesture"
        );
        driven.push(DetachExclusion::ContinuationInput);
        session.type_line(close);
        assert!(
            session.wait_for_output("kr-continuation-ok", REPLY),
            "the continuation did not close:\n{}",
            session.terminal_output()
        );
    }

    for exclusion in &named {
        assert!(
            driven.contains(exclusion) || not_constructible_here(kind, *exclusion).is_some(),
            "{} is in the corpus and neither driven nor accounted for",
            exclusion.as_str()
        );
    }
    assert!(
        driven.len() >= speech.driven_exclusions,
        "only {} of {}'s exclusions were driven; this test has stopped proving anything",
        driven.len(),
        kind.as_str()
    );
}

/// The shell's own `read`, reading a line through the editor.
fn read_builtin_command(kind: ShellKind) -> Option<&'static str> {
    match kind {
        ShellKind::Bash => Some("read -e -t 5 kr_read_var"),
        ShellKind::Fish => Some("read -l kr_read_var"),
        _ => None,
    }
}

/// Switching the editor to vi bindings and back, where a motion waits for its target there.
fn vi_keymap_commands(kind: ShellKind) -> Option<(&'static str, &'static str)> {
    match kind {
        ShellKind::Zsh => Some(("bindkey -v; echo kr-vi-on", "bindkey -e; echo kr-vi-off")),
        ShellKind::Bash => Some(("set -o vi; echo kr-vi-on", "set -o emacs; echo kr-vi-off")),
        ShellKind::Fish => Some((
            "fish_vi_key_bindings; echo kr-vi-on",
            "fish_default_key_bindings; echo kr-vi-off",
        )),
        // This editor's vi mode is the host's own and its operators take their keys themselves.
        ShellKind::PowerShell => None,
    }
}

/// A binding that feeds the gesture back as the reader's own input.
fn macro_binding(kind: ShellKind) -> Option<&'static str> {
    match kind {
        ShellKind::Zsh => Some("bindkey -s '^T' $'\\x04'; echo kr-macro-bound"),
        ShellKind::Bash => Some("bind '\"\\C-t\": \"\\C-d\"' ; echo kr-macro-bound"),
        _ => None,
    }
}

/// The exclusions the committed corpus names, read from the scenario rather than restated.
fn excluded_states() -> Vec<DetachExclusion> {
    let scenario = scenarios()
        .into_iter()
        .find(|scenario| scenario.id == "detach-condition-exclusions")
        .expect("the exclusion scenario is committed");
    let Script::PreEof(script) = scenario.script else {
        panic!("the exclusion scenario drives the pre-EOF decision");
    };
    script
        .steps
        .iter()
        .filter_map(|step| match step {
            PreEofStep::Offer {
                expect:
                    PreEofDecision::Native {
                        reason: NativeReason::Excluded(exclusion),
                    },
                ..
            } => Some(*exclusion),
            _ => None,
        })
        .collect()
}

/// KR-REQ-07.73's package half, and `veof-change`, `veof-disabled`.
pub fn the_gesture_follows_the_line_discipline(kind: ShellKind) {
    let speech = dialect(kind);
    let (Some(change), Some(disable)) = (speech.veof_change, speech.veof_disable) else {
        // This editor's gesture is a chord the worker configures rather than the line discipline's
        // own character, which `psreadline-chord-gesture` is the scenario for.
        println!("skipped: {} follows a configured chord", kind.as_str());
        return;
    };
    let Some(package) = Package::found(kind) else {
        return;
    };
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    // A character that is not the gesture is the editor's own, and at an empty prompt the editor's
    // own answer can be to end the shell. The person's ignoreeof setting makes that answer
    // observable without ending this session; an editor with no such setting keeps something in
    // the buffer instead.
    if let Some(command) = speech.ignore_eof_on {
        session.type_line(command);
        assert!(session.wait_for_output("kr-ready", REPLY));
    }

    // A VEOF reassignment is a user change to the gesture, and it takes effect at a prompt rather
    // than in the middle of a read.
    session.type_line(change);
    assert!(session.wait_for_output("kr-veof-set", REPLY));
    let (_, changed) = session.expect_event("gesture_changed", |event| {
        matches!(event, BridgeEvent::GestureChanged(_))
    });
    let BridgeEvent::GestureChanged(changed) = changed else {
        unreachable!()
    };
    assert_eq!(
        changed.gesture,
        EofGesture::TerminalEof {
            byte: U64::new(0x07)
        }
    );

    let (_, fence) = session.fenced_prompt(6);
    if speech.ignore_eof_on.is_none() {
        // Nothing of the editor's own ends a shell whose buffer is not empty.
        session.type_bytes(b"kr");
        std::thread::sleep(Duration::from_millis(80));
    }
    session.type_bytes(CTRL_D);
    assert!(
        !session.saw_event(Duration::from_millis(500), |event| matches!(
            event,
            BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
        )),
        "a character that is no longer the gesture was treated as one"
    );
    session.clear_line();
    session.type_bytes(CTRL_G);
    let (id, event) = session.expect_event("eof_detach", |event| {
        matches!(event, BridgeEvent::EofDetach(_))
    });
    let BridgeEvent::EofDetach(detach) = event else {
        unreachable!()
    };
    assert_eq!(detach.fence_id, fence.fence_id);
    session.answer_event(id, detached(attachment_id(1)));

    // A terminal with no end-of-file character has no gesture, so no character is one.
    session.clear_line();
    session.type_line(disable);
    assert!(session.wait_for_output("kr-veof-undef", REPLY));
    let (_, disabled) = session.expect_event("a disabled gesture", |event| {
        matches!(
            event,
            BridgeEvent::GestureChanged(change) if change.gesture == EofGesture::Disabled
        )
    });
    let BridgeEvent::GestureChanged(_) = disabled else {
        unreachable!()
    };
    let (enter, _) = session.fenced_prompt(7);
    let _ = enter;
    session.type_bytes(CTRL_G);
    assert!(
        !session.saw_event(Duration::from_millis(500), |event| matches!(
            event,
            BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
        )),
        "a terminal with no gesture still produced one"
    );
    assert!(session.alive());
}

/// KR-REQ-07.34, KR-REQ-07.35, and `launch-installed`.
pub fn a_launch_is_installed_and_accepted_on_the_reader_thread(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    session.type_line("echo kr-ready");
    assert!(session.wait_for_output("kr-ready", REPLY));

    let (enter, fence) = session.fenced_prompt(8);
    let transaction = LaunchTransactionId::new(Uuid::from_bytes([0x71; 16]));
    // An argument vector no interpolation could survive: a word with a space in it, which a split
    // would break into two, and a word that is a command substitution, which an unquoted install
    // would run. `printf` prints each argument followed by a bar, so the exact vector that ran is
    // visible in the output.
    let substitution = match kind {
        // Each shell's own way of writing a command substitution, so an unquoted install would run
        // something rather than print it.
        ShellKind::Fish => "(echo substituted)".to_owned(),
        _ => "$(echo substituted)".to_owned(),
    };
    let command = LaunchCommand::Arguments(vec![
        "printf".to_owned(),
        "%s|".to_owned(),
        "kr launch ok".to_owned(),
        substitution,
    ]);
    let id = session.ask(WorkerRequest::Launch(LaunchMailboxRequest {
        session_id: session.session_id,
        transaction,
        fence_id: fence.fence_id,
        command: command.clone(),
        expected_prompt_generation: enter.prompt_generation,
        expected_buffer_revision: enter.editor.buffer_revision,
        expected_cwd_revision: enter.cwd_revision,
        deadline_ms: LAUNCH_READER_BUDGET,
    }));

    let BridgeAnswer::Launch(decision) = session.answer(id) else {
        panic!("the reader answered a launch with something else")
    };
    let accepted = match decision {
        LaunchDecision::Accepted(accepted) => accepted,
        LaunchDecision::Rejected(rejected) => {
            panic!(
                "an empty fenced prompt refused a launch: {:?}",
                rejected.reason
            )
        }
    };
    assert_eq!(accepted.transaction, transaction);
    assert_eq!(accepted.fence_id, fence.fence_id);
    assert_eq!(
        accepted.installed, command,
        "the caller's own arguments went in"
    );
    assert_eq!(
        accepted.buffer_revision,
        next_revision(enter.editor.buffer_revision),
        "installing the command changes the buffer once"
    );
    assert_eq!(accepted.prompt_generation, enter.prompt_generation);

    // This editor completes an acceptance at its own next step, so the session gives it one. The
    // acceptance is already in the editor's own queue, which is drained before anything the
    // terminal has, so it is the installed line that runs.
    session.nudge();

    // The accepted line is reported from the reader, inside the fence, before the leave.
    let (_, recorded) = session.expect_event("command_accepted", |event| {
        matches!(event, BridgeEvent::CommandAccepted(_))
    });
    let BridgeEvent::CommandAccepted(recorded) = recorded else {
        unreachable!()
    };
    assert_eq!(recorded.fence_id.as_ref(), Some(&fence.fence_id));
    assert_eq!(
        recorded.origin,
        AcceptedOrigin::Fenced {
            attachment_id: fence.originating_attachment,
            input_epoch: fence.input_epoch,
        }
    );
    let (_, left) = session.expect_event("editor_leave", |event| {
        matches!(event, BridgeEvent::EditorLeave(_))
    });
    let BridgeEvent::EditorLeave(left) = left else {
        unreachable!()
    };
    assert_eq!(left.reason, EditorLeaveReason::CommandAccepted);

    assert!(
        session.wait_for_output(dialect(kind).launch_expectation, REPLY),
        "the arguments that ran are not the arguments the caller named:\n{}",
        session.terminal_output()
    );
    assert!(
        !session.terminal_output().contains("substituted|"),
        "an argument was expanded rather than installed literally:\n{}",
        session.terminal_output()
    );
}

/// `launch-reader-decisions`: the reader's own check, one case per reason it can produce here.
pub fn the_reader_refuses_a_launch_its_own_state_does_not_match(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let wait = pending_wait(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    // Whatever the wait below needs runs before the reader the launches are checked against.
    let ready = wait
        .as_ref()
        .and_then(|wait| wait.prepare)
        .unwrap_or(("echo kr-ready", "kr-ready"));
    session.type_line(ready.0);
    assert!(session.wait_for_output(ready.1, REPLY));

    let (enter, fence) = session.fenced_prompt(9);
    let base = LaunchMailboxRequest {
        session_id: session.session_id,
        transaction: LaunchTransactionId::new(Uuid::from_bytes([0x72; 16])),
        fence_id: fence.fence_id,
        command: LaunchCommand::Arguments(vec!["true".to_owned()]),
        expected_prompt_generation: enter.prompt_generation,
        expected_buffer_revision: enter.editor.buffer_revision,
        expected_cwd_revision: enter.cwd_revision,
        deadline_ms: LAUNCH_READER_BUDGET,
    };

    let refuse =
        |session: &mut Session, request: LaunchMailboxRequest, expected: LaunchRejectionReason| {
            let id = session.ask(WorkerRequest::Launch(request));
            let BridgeAnswer::Launch(decision) = session.answer(id) else {
                panic!("the reader answered a launch with something else")
            };
            assert_eq!(
                decision.rejection(),
                Some(expected),
                "the reader named a different reason"
            );
        };

    refuse(
        &mut session,
        LaunchMailboxRequest {
            fence_id: fence_id(10),
            ..base.clone()
        },
        LaunchRejectionReason::FenceInvalid,
    );
    refuse(
        &mut session,
        LaunchMailboxRequest {
            deadline_ms: DurationMs::new(0),
            ..base.clone()
        },
        LaunchRejectionReason::Timeout,
    );
    refuse(
        &mut session,
        LaunchMailboxRequest {
            expected_prompt_generation: PromptGeneration::new(enter.prompt_generation.get() + 7),
            ..base.clone()
        },
        LaunchRejectionReason::PromptGenerationMismatch,
    );
    refuse(
        &mut session,
        LaunchMailboxRequest {
            expected_cwd_revision: kr_protocol::root::CwdRevision::new(
                enter.cwd_revision.get() + 7,
            ),
            ..base.clone()
        },
        LaunchRejectionReason::CwdRevisionMismatch,
    );
    refuse(
        &mut session,
        LaunchMailboxRequest {
            expected_buffer_revision: EditorBufferRevision::new(
                enter.editor.buffer_revision.get() + 7,
            ),
            ..base.clone()
        },
        LaunchRejectionReason::BufferRevisionMismatch,
    );

    // Something the person typed is theirs and goes first.
    if !dialect(kind).answers_at_the_next_step {
        session.type_bytes(b"x");
        std::thread::sleep(Duration::from_millis(150));
        refuse(
            &mut session,
            base.clone(),
            LaunchRejectionReason::BufferNotEmpty,
        );
        session.clear_line();
    }

    // Something the person had half-typed is theirs too: the reader is waiting for another key,
    // so the launch waits behind it.
    if let Some(wait) = wait {
        session.type_bytes(wait.enter);
        std::thread::sleep(Duration::from_millis(150));
        refuse(
            &mut session,
            base.clone(),
            LaunchRejectionReason::QueuedPriorInput,
        );
        let cancel = session.ask(WorkerRequest::Cancel(CancelKeyWait {
            session_id: session.session_id,
            sequence: U64::new(2),
            epoch: epoch(4),
            prompt_generation: enter.prompt_generation,
            reader_revision: enter.reader_revision,
        }));
        let _ = session.answer(cancel);
    }

    // Every reason the corpus names is driven above, or is one the worker decides rather than the
    // reader, or needs a reader this session cannot reach.
    for reason in launch_rejection_reasons() {
        assert!(
            driven_here(kind, reason)
                || worker_side(reason)
                || not_reachable_here(kind, reason).is_some(),
            "{} is in the corpus and neither driven nor accounted for",
            reason.as_str()
        );
    }
}

/// Whether the reader raised the flag this wait is supposed to raise.
fn pending_flag_is_set(pending: &kr_protocol::root::PendingReaderInput, flag: PendingFlag) -> bool {
    match flag {
        PendingFlag::MultikeySequence => pending.multikey_sequence,
        PendingFlag::ViMotion => pending.vi_motion,
        PendingFlag::QuotedInsertion => pending.quoted_insertion,
    }
}

/// The reasons the cases above put a real reader into.
fn driven_here(kind: ShellKind, reason: LaunchRejectionReason) -> bool {
    if not_reachable_here(kind, reason).is_some() {
        return false;
    }
    matches!(
        reason,
        LaunchRejectionReason::FenceInvalid
            | LaunchRejectionReason::Timeout
            | LaunchRejectionReason::PromptGenerationMismatch
            | LaunchRejectionReason::CwdRevisionMismatch
            | LaunchRejectionReason::BufferRevisionMismatch
            | LaunchRejectionReason::BufferNotEmpty
            | LaunchRejectionReason::QueuedPriorInput
    )
}

/// The rejections that need a reader state this session cannot put this editor into, with why.
fn not_reachable_here(kind: ShellKind, reason: LaunchRejectionReason) -> Option<&'static str> {
    match reason {
        // Input of the person's waiting ahead of a launch is a state this session can only reach
        // through a reader that waits for another key, which not every editor has.
        LaunchRejectionReason::QueuedPriorInput if pending_wait(kind).is_none() => {
            Some("this editor has no key wait to leave input in")
        }
        // Once the person has typed, this editor's host stops offering the module's signal to the
        // reader until the reader reaches a boundary of its own, so a launch asked for at a buffer
        // the person has started is answered there rather than while they are still typing.
        LaunchRejectionReason::BufferNotEmpty if dialect(kind).answers_at_the_next_step => {
            Some("this editor answers at its next boundary once the person has typed")
        }
        _ => None,
    }
}

/// The reasons that are the worker's own answer rather than the reader's, or that name a reader a
/// session cannot be driven into from the terminal.
fn worker_side(reason: LaunchRejectionReason) -> bool {
    matches!(
        reason,
        // `revoked` has its own case; the rest are the worker's answers when the reader is gone,
        // has left, or is not the one the transaction was reserved against.
        LaunchRejectionReason::Revoked
            | LaunchRejectionReason::ConfirmationLost
            | LaunchRejectionReason::SessionClosing
            | LaunchRejectionReason::EditorLeft
            | LaunchRejectionReason::LeaseChanged
            | LaunchRejectionReason::NotPrimaryReader
    )
}

/// The rejection reasons the committed corpus states, read from the scenario.
fn launch_rejection_reasons() -> Vec<LaunchRejectionReason> {
    let scenario = scenarios()
        .into_iter()
        .find(|scenario| scenario.id == "launch-reader-decisions")
        .expect("the launch scenario is committed");
    let Script::Launch(script) = scenario.script else {
        panic!("the launch scenario drives the reader's decision");
    };
    script
        .cases
        .iter()
        .filter_map(|case| match &case.expect {
            kr_shell_integration::contract::fixtures::LaunchExpectation::Rejected {
                reason,
                ..
            } => Some(*reason),
            kr_shell_integration::contract::fixtures::LaunchExpectation::Installed { .. } => None,
        })
        .collect()
}

/// A-17 and `timeout-launch`: a revoked launch installs nothing and says so.
pub fn a_revoked_launch_installs_nothing(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    session.type_line("echo kr-ready");
    assert!(session.wait_for_output("kr-ready", REPLY));

    let (enter, fence) = session.fenced_prompt(11);
    let transaction = LaunchTransactionId::new(Uuid::from_bytes([0x73; 16]));

    // The endpoint delivers frames in order, so a revocation the worker sent before the reader's
    // atomic step is one that step sees.
    session.write_frame(&BridgeFrame::LaunchRevoked {
        transaction,
        reason: LaunchRejectionReason::Timeout,
    });
    let id = session.ask(WorkerRequest::Launch(LaunchMailboxRequest {
        session_id: session.session_id,
        transaction,
        fence_id: fence.fence_id,
        command: LaunchCommand::Arguments(vec!["echo".to_owned(), "kr-revoked".to_owned()]),
        expected_prompt_generation: enter.prompt_generation,
        expected_buffer_revision: enter.editor.buffer_revision,
        expected_cwd_revision: enter.cwd_revision,
        deadline_ms: LAUNCH_READER_BUDGET,
    }));
    let BridgeAnswer::Launch(decision) = session.answer(id) else {
        panic!("the reader answered a launch with something else")
    };
    assert_eq!(decision.rejection(), Some(LaunchRejectionReason::Revoked));

    // Nothing was installed, and the reader's own state says so.
    let acknowledgement = session.fence_exchange(&enter, fence_id(12));
    assert!(
        acknowledgement.editor.buffer_empty,
        "a revoked launch left text in the editor"
    );
    assert!(
        !session.saw_event(Duration::from_millis(400), |event| matches!(
            event,
            BridgeEvent::CommandAccepted(_)
        )),
        "a revoked launch accepted a line"
    );
    assert!(!session.terminal_output().contains("kr-revoked"));
}

/// A revocation in the same read binds the launch, in whichever order the two frames arrive.
///
/// `ReaderLaunchState::revoked` is "a revocation for this transaction was in the frames this step
/// read", so a worker that dispatched a launch and revoked it in the same breath has revoked it.
pub fn a_revocation_in_the_same_read_binds_the_launch(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    session.type_line("echo kr-ready");
    assert!(session.wait_for_output("kr-ready", REPLY));

    let (enter, fence) = session.fenced_prompt(15);
    let transaction = LaunchTransactionId::new(Uuid::from_bytes([0x74; 16]));
    let id = RequestId::new(9001);

    // The launch first, its revocation second, in one write.
    session.write_frames(&[
        BridgeFrame::Request {
            id,
            request: WorkerRequest::Launch(LaunchMailboxRequest {
                session_id: session.session_id,
                transaction,
                fence_id: fence.fence_id,
                command: LaunchCommand::Arguments(vec![
                    "echo".to_owned(),
                    "kr-late-revoked".to_owned(),
                ]),
                expected_prompt_generation: enter.prompt_generation,
                expected_buffer_revision: enter.editor.buffer_revision,
                expected_cwd_revision: enter.cwd_revision,
                deadline_ms: LAUNCH_READER_BUDGET,
            }),
        },
        BridgeFrame::LaunchRevoked {
            transaction,
            reason: LaunchRejectionReason::Timeout,
        },
    ]);

    let BridgeAnswer::Launch(decision) = session.answer(id) else {
        panic!("the reader answered a launch with something else")
    };
    assert_eq!(
        decision.rejection(),
        Some(LaunchRejectionReason::Revoked),
        "a revocation the reader had already read did not bind its launch"
    );

    let acknowledgement = session.fence_exchange(&enter, fence_id(16));
    assert!(
        acknowledgement.editor.buffer_empty,
        "a revoked launch left its text in the editor"
    );
    assert!(
        !session.terminal_output().contains("kr-late-revoked"),
        "a revoked launch ran anyway:\n{}",
        session.terminal_output()
    );

    // A revocation for a transaction that is long over touches nothing.
    session.write_frame(&BridgeFrame::LaunchRevoked {
        transaction,
        reason: LaunchRejectionReason::Timeout,
    });
    std::thread::sleep(Duration::from_millis(200));
    session.type_bytes(b"kr-typed");
    std::thread::sleep(Duration::from_millis(200));
    session.write_frame(&BridgeFrame::LaunchRevoked {
        transaction,
        reason: LaunchRejectionReason::Timeout,
    });
    std::thread::sleep(Duration::from_millis(200));
    session.type_line("");
    assert!(
        session.wait_for_output("kr-typed", REPLY),
        "a revocation for a finished transaction took the person's own text out:\n{}",
        session.terminal_output()
    );
    assert!(session.alive());
}

/// The reader reports itself idle, which is one of the three points a withheld fence is retried at.
pub fn the_reader_reports_itself_idle(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let mut session = Session::start(&package);
    session.first_prompt();
    let (_, event) = session.expect_event("reader_idle", |event| {
        matches!(event, BridgeEvent::ReaderIdle(_))
    });
    let BridgeEvent::ReaderIdle(idle) = event else {
        unreachable!()
    };
    assert_eq!(
        idle.reader_context,
        kr_protocol::root::ReaderContext::Primary
    );
    assert!(
        idle.editor.buffer_empty,
        "an idle empty prompt has no buffer"
    );
    assert!(
        idle.snapshot.queued_keys == U64::new(0) && idle.snapshot.pending_bytes == U64::new(0),
        "an idle reader reported input it has not read: {:?}",
        idle.snapshot
    );
}

/// A session that loses its bridge keeps the fail-safe answer to an eligible gesture.
pub fn a_lost_bridge_does_not_restore_a_native_empty_prompt_end_of_file(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    session.type_line("echo kr-ready");
    assert!(session.wait_for_output("kr-ready", REPLY));
    let before = session.terminal_output().matches(DETACH_HINT).count();

    // The worker goes. Nothing can attribute a gesture any more, which is exactly when turning one
    // into a native end of file would close somebody's shell.
    session.close_endpoint();
    std::thread::sleep(Duration::from_millis(300));

    session.type_bytes(CTRL_D);
    assert!(
        session.wait_for_output(DETACH_HINT, REPLY),
        "a shell whose bridge has gone printed no hint:\n{}",
        session.terminal_output()
    );
    assert!(
        session.terminal_output().matches(DETACH_HINT).count() > before,
        "the hint was the one from before the bridge went"
    );
    assert!(
        session.alive(),
        "an eligible gesture ended a shell whose bridge had gone"
    );
}

/// `takeover-partial-escape` and `takeover-quoted-insertion`: the cancellation the contract needs.
pub fn a_takeover_ends_a_pending_key_wait_and_keeps_the_buffer(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let Some(wait) = pending_wait(kind) else {
        println!(
            "skipped: {} has no key wait a takeover can end",
            kind.as_str()
        );
        return;
    };
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    // Whatever the wait needs runs before the reader it is measured against starts.
    let ready = wait.prepare.unwrap_or(("echo kr-ready", "kr-ready"));
    session.type_line(ready.0);
    assert!(session.wait_for_output(ready.1, REPLY));
    let enter = session.next_prompt();

    // The reader is left waiting for another key, with text already typed.
    session.type_bytes(b"echo kr-");
    std::thread::sleep(Duration::from_millis(120));
    session.type_bytes(wait.enter);
    std::thread::sleep(Duration::from_millis(150));

    // A reader in that state says so: a queue of its own still holds input, and the fence the
    // worker asked for is one it will withhold until that queue drains.
    let waiting = session.fence_exchange(&enter, fence_id(14));
    assert!(
        !waiting.queues.partial_key_drained || !waiting.snapshot.is_drained(),
        "a reader waiting for another key reported every queue clear: {:?} {:?}",
        waiting.queues,
        waiting.snapshot
    );
    if wait.partial_key_queue {
        assert!(
            !waiting.queues.partial_key_drained,
            "a reader waiting for the rest of a sequence reported its partial-key queue clear"
        );
    }
    assert!(
        pending_flag_is_set(&waiting.editor.pending, wait.flag),
        "a reader waiting for another key reported nothing pending: {:?}",
        waiting.editor.pending
    );
    assert!(
        !waiting.editor.buffer_empty,
        "the text typed before the sequence is still in the buffer"
    );

    // Everything the reader said before this point is dropped, so the idle report asserted below
    // is the one the cancellation produced rather than one from the entry.
    session.forget_events();
    let id = session.ask(WorkerRequest::Cancel(CancelKeyWait {
        session_id: session.session_id,
        sequence: U64::new(1),
        epoch: epoch(4),
        prompt_generation: enter.prompt_generation,
        reader_revision: enter.reader_revision,
    }));
    let BridgeAnswer::Cancel(report) = session.answer(id) else {
        panic!("the reader answered a cancellation with something else")
    };
    assert_eq!(report.sequence, U64::new(1));
    assert_eq!(report.epoch, epoch(4));
    assert_eq!(report.prompt_generation, enter.prompt_generation);
    assert_eq!(report.reader_revision, enter.reader_revision);
    assert!(
        report.buffer_preserved,
        "the cancellation lost what the person had typed"
    );
    assert!(
        report.cancelled.any(),
        "the cancellation reported that it ended nothing: {:?}",
        report.cancelled
    );
    if let Some(discarded) = wait.discarded_bytes {
        assert_eq!(
            report.discarded_bytes.get(),
            u64::from(discarded),
            "the cancellation did not count the bytes it dropped for {:?}",
            wait.enter
        );
    }

    // And the reader recovers at the same prompt: it reports itself idle again, which is the
    // retry point a withheld fence needs, and its queues are clear.
    assert!(
        session.saw_event(REPLY, |event| matches!(
            event,
            BridgeEvent::ReaderIdle(idle)
                if idle.prompt_generation == enter.prompt_generation
                    && idle.reader_revision == enter.reader_revision
        )),
        "the reader did not report itself idle again after the cancellation"
    );
    let recovered = session.fence_exchange(&enter, fence_id(17));
    assert!(
        recovered.queues.partial_key_drained
            && recovered.queues.tty_typeahead_drained
            && recovered.queues.macro_input_drained,
        "the reader's queues did not come back after the cancellation: {:?}",
        recovered.queues
    );

    // A quoted insertion waits for its character in the same way, and ends the same way.
    if let Some(quoted_insertion) = quoted_wait(kind) {
        if let Some((command, marker)) = quoted_insertion.prepare {
            session.type_line(command);
            assert!(session.wait_for_output(marker, REPLY));
            std::thread::sleep(Duration::from_millis(200));
        }
        session.type_bytes(quoted_insertion.enter);
        std::thread::sleep(Duration::from_millis(150));
        let quoted = session.ask(WorkerRequest::Cancel(CancelKeyWait {
            session_id: session.session_id,
            sequence: U64::new(2),
            epoch: epoch(4),
            prompt_generation: enter.prompt_generation,
            reader_revision: enter.reader_revision,
        }));
        let BridgeAnswer::Cancel(report) = session.answer(quoted) else {
            panic!("the reader answered a cancellation with something else")
        };
        assert!(report.buffer_preserved);
        assert!(
            report.cancelled.quoted_insertion,
            "the cancellation did not name the quoted insertion it ended: {:?}",
            report.cancelled
        );
    }

    // A cancellation for a reader the worker is not looking at ends nothing.
    let stale = session.ask(WorkerRequest::Cancel(CancelKeyWait {
        session_id: session.session_id,
        sequence: U64::new(3),
        epoch: epoch(4),
        prompt_generation: PromptGeneration::new(enter.prompt_generation.get() + 9),
        reader_revision: enter.reader_revision,
    }));
    let BridgeAnswer::Cancel(report) = session.answer(stale) else {
        panic!("the reader answered a cancellation with something else")
    };
    assert!(
        !report.cancelled.any(),
        "a cancellation for another reader ended this one's work: {:?}",
        report.cancelled
    );

    // The buffer survived all of it: the rest of the line is typed and the whole command runs.
    session.type_line("takeover-ok");
    assert!(
        session.wait_for_output("kr-takeover-ok", REPLY),
        "the edit buffer did not survive the cancellation:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-07.34 and KR-REQ-07.35: a cancellation ends what it found, and nothing else.
pub fn a_cancellation_that_ends_nothing_leaves_the_next_sequence_alone(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let wait = pending_wait(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    // Whatever the wait needs runs before the reader it is measured against starts.
    let ready = wait
        .as_ref()
        .and_then(|wait| wait.prepare)
        .unwrap_or(("echo kr-ready", "kr-ready"));
    session.type_line(ready.0);
    assert!(session.wait_for_output(ready.1, REPLY));
    let enter = session.next_prompt();

    // The reader is waiting for a key with nothing in progress, so there is nothing of the old
    // lease's for this cancellation to end and nothing for it to throw away.
    session.type_bytes(dialect(kind).arithmetic.0.as_bytes());
    std::thread::sleep(Duration::from_millis(120));
    session.forget_events();
    let idle = session.ask(WorkerRequest::Cancel(CancelKeyWait {
        session_id: session.session_id,
        sequence: U64::new(1),
        epoch: epoch(4),
        prompt_generation: enter.prompt_generation,
        reader_revision: enter.reader_revision,
    }));
    let BridgeAnswer::Cancel(report) = session.answer(idle) else {
        panic!("the reader answered a cancellation with something else")
    };
    assert!(
        !report.cancelled.any(),
        "a cancellation at a reader with nothing in progress ended something: {:?}",
        report.cancelled
    );
    assert_eq!(
        report.discarded_bytes,
        U64::new(0),
        "a cancellation that ended nothing reported input it had discarded"
    );
    // A reader that came out of its wait would report itself idle on the way back in. This one
    // never left it, so there is nothing new to report. A reader that answers only when it steps
    // was given a step to answer with, so the step is what it reports rather than the
    // cancellation.
    if !dialect(kind).answers_at_the_next_step {
        assert!(
            !session.saw_event(Duration::from_millis(600), |event| matches!(
                event,
                BridgeEvent::ReaderIdle(_)
            )),
            "the reader left a wait that the cancellation had nothing to end"
        );
    }

    // The person then starts a sequence of their own, and the mailbox is read while it is
    // part-read. The cancellation before it is over, so the sequence is still the reader's to
    // finish rather than something that cancellation takes away.
    let Some(wait) = wait else {
        // Nothing of this package's runs on this reader's thread while the editor is inside one of
        // its own nested reads, so there is no part-read sequence to leave alone.
        println!("skipped: {} has no key wait to leave alone", kind.as_str());
        return;
    };
    session.type_bytes(wait.enter);
    std::thread::sleep(Duration::from_millis(150));
    for fence in [fence_id(20), fence_id(21)] {
        let held = session.fence_exchange(&enter, fence);
        assert!(
            pending_flag_is_set(&held.editor.pending, wait.flag)
                && (!held.queues.partial_key_drained || !held.snapshot.is_drained()),
            "the reader lost the sequence the person had started: {:?} {:?}",
            held.editor.pending,
            held.queues
        );
    }

    // A cancellation now does end that sequence, and the typed text is still there afterwards.
    let ends = session.ask(WorkerRequest::Cancel(CancelKeyWait {
        session_id: session.session_id,
        sequence: U64::new(2),
        epoch: epoch(4),
        prompt_generation: enter.prompt_generation,
        reader_revision: enter.reader_revision,
    }));
    let BridgeAnswer::Cancel(report) = session.answer(ends) else {
        panic!("the reader answered a cancellation with something else")
    };
    assert!(
        report.cancelled.any() && report.buffer_preserved,
        "the cancellation did not end the sequence it found: {:?}",
        report.cancelled
    );
    // The rest of the line is typed and the whole command runs: the shell's own answer, which is
    // in none of the keystrokes, is what proves it ran rather than an echo of the typing.
    session.type_line(dialect(kind).arithmetic.1);
    assert!(
        session.wait_for_output(dialect(kind).arithmetic.2, REPLY),
        "the edit buffer did not survive the cancellations:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-07.72: the person's own IGNORE_EOF setting is left as they set it.
pub fn the_ignore_eof_setting_is_left_as_the_person_set_it(kind: ShellKind) {
    if dialect(kind).ignore_eof_on.is_none() {
        println!(
            "skipped: {} has no end-of-file setting of its own",
            kind.as_str()
        );
        return;
    }
    let Some(package) = Package::found(kind) else {
        return;
    };
    let (turn_on, report) = match kind {
        ShellKind::Zsh => (
            "setopt ignoreeof; echo kr-ignoreeof-set",
            "[[ -o ignoreeof ]] && echo kr-ignoreeof=on",
        ),
        ShellKind::Bash => (
            "set -o ignoreeof; echo kr-ignoreeof-set",
            "[[ -o ignoreeof ]] && echo kr-ignoreeof=on",
        ),
        _ => {
            println!(
                "skipped: {} has no end-of-file setting of its own",
                kind.as_str()
            );
            return;
        }
    };
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    session.type_line(turn_on);
    assert!(session.wait_for_output("kr-ignoreeof-set", REPLY));

    // Inside the detach condition the decision is taken before either end-of-file branch, so the
    // shell's own message never appears and the setting is untouched.
    let (_, fence) = session.fenced_prompt(13);
    session.type_bytes(CTRL_D);
    let (id, event) = session.expect_event("eof_detach", |event| {
        matches!(event, BridgeEvent::EofDetach(_))
    });
    let BridgeEvent::EofDetach(detach) = event else {
        unreachable!()
    };
    assert_eq!(detach.fence_id, fence.fence_id);
    session.answer_event(id, detached(attachment_id(1)));
    assert!(
        !session.terminal_output().contains("use 'exit' to exit"),
        "the shell's own end-of-file branch ran"
    );

    session.clear_line();
    session.type_line(report);
    assert!(
        session.wait_for_output("kr-ignoreeof=on", REPLY),
        "the person's ignoreeof setting did not survive:\n{}",
        session.terminal_output()
    );
    assert!(session.alive());
}

/// KR-REQ-07.85: the package declares the baseline the specification names.
pub fn the_package_declares_the_baseline_the_specification_names(kind: ShellKind) {
    let Some(package) = Package::found(kind) else {
        return;
    };
    let record = &package.record;
    let version = record["shell"]["upstream_version"]
        .as_str()
        .expect("the record names an upstream version");
    let (major, minor) = version_pair(version);
    match kind {
        ShellKind::Zsh => assert!(
            (major, minor) >= (5, 9),
            "the managed Zsh baseline is 5.9 and this package is {version}"
        ),
        ShellKind::Bash => assert!(
            (major, minor) >= (5, 2),
            "the managed Bash baseline is 5.2 and this package is {version}"
        ),
        ShellKind::Fish => assert!(
            major >= 4,
            "the managed fish baseline is 4.x and this package is {version}"
        ),
        ShellKind::PowerShell => {
            assert!(
                (major, minor) >= (7, 4),
                "the PowerShell baseline is 7.4 and this package is {version}"
            );
            let qualified = &record["qualified"];
            assert_eq!(
                qualified["psreadline_from"], "2.3.4",
                "the package names the PSReadLine range it was qualified against"
            );
            let found = qualified["psreadline_found"]
                .as_str()
                .expect("the record names the PSReadLine it found");
            let (psrl_major, psrl_minor) = version_pair(found);
            assert!(
                (psrl_major, psrl_minor) >= (2, 3),
                "a qualified PSReadLine is 2.3.4 or later and this one is {found}"
            );
        }
    }

    let abi = &record["abi"];
    assert_eq!(abi["fence_proof"], "atomic_reader_state");
    assert_eq!(abi["cancellation"], "non_destructive_key_wait");
    assert_eq!(abi["launch_delivery"], "reader_mailbox");
    assert_eq!(
        abi["mailbox"].as_str().expect("a mailbox mechanism"),
        kr_shell_integration::contract::qualification::MailboxMechanism::for_shell(kind).as_str()
    );
    assert_eq!(
        abi["pre_eof"].as_str().expect("a pre-EOF mechanism"),
        kr_shell_integration::contract::qualification::PreEofMechanism::for_shell(kind).as_str()
    );

    // A rebuild from the same inputs lands in the same place, and the binary is outside the
    // workspace so nothing a service manager starts has to reach it.
    assert_eq!(
        record["build"]["inputs_sha256"]
            .as_str()
            .expect("the record names its inputs")[..16]
            .to_owned(),
        package.identity
    );
    assert!(
        outside_workspace(&package.executable),
        "the package is installed inside the workspace: {}",
        package.executable.display()
    );
    record_evidence(kind, &package);
}

fn version_pair(version: &str) -> (u32, u32) {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    (major, minor)
}

fn record_evidence(kind: ShellKind, package: &Package) {
    record(
        &format!("kr-shell-package-{}.json", kind.as_str()),
        &serde_json::to_string_pretty(&package.record).unwrap_or_default(),
    );
}

/// The corpus this package's own cases take their expectations from is itself sound.
///
/// This replays the committed scenarios against the contract, which is the worker's side; the
/// cases above are what drives the package. Both read the same files, which is the point.
pub fn every_scenario_naming_this_shell_holds(kind: ShellKind) {
    let named = scenarios_for(kind);
    // Every scenario but the ones that name another editor's own gesture.
    let expected = scenarios().len() - 2;
    assert!(
        named.len() >= expected,
        "only {} of {} scenarios name {}",
        named.len(),
        expected,
        kind.as_str()
    );
    let mut failures = Vec::new();
    for scenario in &named {
        failures.extend(contract_failures(scenario));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The shell-independent half of the bridge is the same source in every package that compiles it.
///
/// Each package is self-contained because each patch set is published against its own upstream
/// project under that project's licence. That is a decision, not a licence for the copies to
/// drift, so it is checked here.
pub fn the_bridge_core_is_identical_in_both_packages() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("shells");
    for name in [
        "kr_bridge.h",
        "kr_bridge.c",
        "kr_bridge_cbor.h",
        "kr_bridge_cbor.c",
        "kr_bridge_crypto.h",
        "kr_bridge_crypto.c",
    ] {
        let zsh = std::fs::read_to_string(root.join("zsh/src").join(name))
            .unwrap_or_else(|error| panic!("shells/zsh/src/{name}: {error}"));
        for other in ["bash", "fish"] {
            let theirs = std::fs::read_to_string(root.join(other).join("src").join(name))
                .unwrap_or_else(|error| panic!("shells/{other}/src/{name}: {error}"));
            assert_eq!(
                strip_licence_note(&zsh),
                strip_licence_note(&theirs),
                "shells/zsh/src/{name} and shells/{other}/src/{name} have drifted apart"
            );
        }
    }
}

/// Removes the per-package licence paragraph, which is the one part that differs on purpose.
fn strip_licence_note(source: &str) -> String {
    source
        .lines()
        .filter(|line| {
            let line = line.trim_start_matches(" *").trim();
            !(line.starts_with("This file is added to")
                || line.starts_with("licence that governs")
                || line.starts_with("distributed under the GNU")
                || line.starts_with("the package; see shells/"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The start value the host reads for one process, where the platform keeps it in a file.
fn linux_start_value(pid: u64) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = text.rsplit_once(')')?.1;
    tail.split_whitespace().nth(19)?.parse().ok()
}
