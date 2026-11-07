//! What both managed packages have to reproduce, driven through the built shell.
//!
//! Every expectation here comes from the committed scenarios under `fixtures/shell-bridge/` or
//! from the contract's own constants, so these tests and the worker are checked against one
//! corpus. Each case names the requirement rows it closes.

use std::time::Duration;

use kr_protocol::root::{
    AcceptedOrigin, DETACH_HINT, EditorBufferRevision, EditorLeaveReason, EditorState,
    FENCE_EXCHANGE_TIMEOUT, FenceCause, LAUNCH_READER_BUDGET, LaunchCommand, PromptGeneration,
    RootEditorFenceParams, RootEditorFenceResult, WithheldReason,
};
use kr_protocol::scalars::{DurationMs, U64, Uuid};
use kr_shell_integration::contract::events::{
    BridgeEvent, ConsumeReason, DEFAULT_EOF_BYTE, EofGesture, NativeReason, PreEofDecision,
    PressedKey,
};
use kr_shell_integration::contract::fixtures::{PreEofStep, Script};
use kr_shell_integration::contract::qualification::{
    BridgeAbi, DetachExclusion, IntegrationLoss, ShellKind,
};
use kr_shell_integration::contract::requests::{
    BridgeAnswer, CancelKeyWait, LaunchDecision, LaunchMailboxRequest, LaunchRejectionReason,
    LaunchTransactionId, WorkerRequest,
};
use kr_shell_integration::host::phase::PhaseGate;

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
    /// Panics when the exchange could not be settled, which is the caller's own decision put in
    /// one place: every case here needs the reader's state and none of them can carry on without
    /// it.
    pub fn fence_exchange(
        &mut self,
        enter: &RootEditorEnterParams,
        fence: FenceId,
    ) -> kr_protocol::root::FenceAcknowledgement {
        let deadline = self.deadline_for(REPLY);
        self.fence_exchange_before(enter, fence, deadline.0)
    }

    /// Runs one fence exchange, asked, answered and settled by `deadline`.
    ///
    /// A caller that exchanges more than once while it waits for the reader's state to settle
    /// passes every exchange the same instant, so the settlement is bounded by that one instant
    /// instead of by a reply window each time it asks. The instant covers the whole exchange: the
    /// endpoint's backpressure and the step the reader is given on the way out, the wait for the
    /// answer, and the asking again that a reader which has moved calls for.
    ///
    /// # Panics
    ///
    /// Panics when the exchange could not be settled by `deadline`, which is the caller's own
    /// decision put in one place, as [`Session::fence_exchange`] says.
    pub fn fence_exchange_before(
        &mut self,
        enter: &RootEditorEnterParams,
        fence: FenceId,
        deadline: Instant,
    ) -> kr_protocol::root::FenceAcknowledgement {
        let settled = self.settled_fence_exchange(enter, fence, deadline);
        settled.unwrap_or_else(|why| {
            if Instant::now() >= deadline {
                note_that_a_wait_gave_up();
            }
            panic!("{why}:\n{}", self.terminal_output())
        })
    }

    /// Runs the exchange against the reader `enter` names, and against the reader its own next
    /// report names where that one has moved, all of it by `deadline`.
    ///
    /// An exchange is about one reader identity, and a refusal that says the reader moved is the
    /// bridge answering honestly rather than failing: this is not the reader you asked about. The
    /// one that is there now is the one the reader's own next report names, which is where this
    /// asks next. It never waits for a fresh prompt: an editor can take a new revision at the
    /// prompt it is already at, and no entry is owed for that.
    ///
    /// # Errors
    ///
    /// Returns why no reader answered, which is a reader that kept moving, one that refused for
    /// another reason, and one that said nothing at all inside the deadline.
    pub fn settled_fence_exchange(
        &mut self,
        enter: &RootEditorEnterParams,
        fence: FenceId,
        deadline: Instant,
    ) -> Result<kr_protocol::root::FenceAcknowledgement, String> {
        // The deadline is put in force for the whole exchange rather than handed to the waits
        // this names, so the ones below them answer to it too: the pumps that read a moved
        // reader's next report, and the acknowledgements and steps those pumps write.
        self.within_budget(Deadline::at(deadline), |session| {
            session.settle_the_exchange(enter, fence)
        })
    }

    /// The exchange [`Session::settled_fence_exchange`] runs, under the budget it puts in force.
    fn settle_the_exchange(
        &mut self,
        enter: &RootEditorEnterParams,
        fence: FenceId,
    ) -> Result<kr_protocol::root::FenceAcknowledgement, String> {
        let deadline = self.deadline_for(REPLY);
        let mut asked = (enter.prompt_generation, enter.reader_revision);
        let mut attempts = 0;
        loop {
            attempts += 1;
            let Ok(id) = self.try_ask_before(
                WorkerRequest::Fence(RootEditorFenceParams {
                    session_id: self.session_id,
                    fence_id: fence,
                    prompt_generation: asked.0,
                    reader_revision: asked.1,
                    deadline_ms: FENCE_EXCHANGE_TIMEOUT,
                    cause: FenceCause::EditorEntry,
                }),
                deadline.0,
            ) else {
                return Err(format!(
                    "the shell stopped reading its end of the endpoint while fence {attempts} \
                     was written, and the deadline of this wait passed"
                ));
            };
            match self.answer_by(id, deadline) {
                Some(BridgeAnswer::Fence(RootEditorFenceResult::Acknowledged(acknowledgement))) => {
                    return Ok(acknowledgement);
                }
                Some(BridgeAnswer::Fence(RootEditorFenceResult::Refused(refusal)))
                    if refusal.reason == kr_protocol::root::FenceRefusalReason::ReaderMoved =>
                {
                    let Some(report) = self.next_reader_report(deadline, |_| true) else {
                        return Err(format!(
                            "the reader moved under every one of {attempts} fences and reported \
                             no reader to ask instead"
                        ));
                    };
                    asked = (report.idle.prompt_generation, report.idle.reader_revision);
                }
                Some(BridgeAnswer::Fence(RootEditorFenceResult::Refused(refusal))) => {
                    return Err(format!(
                        "the reader refused its own fence: {:?}",
                        refusal.reason
                    ));
                }
                None => {
                    return Err(format!(
                        "the reader did not answer fence {attempts} before the deadline of this \
                         wait"
                    ));
                }
                other => {
                    return Err(format!("the reader answered a fence with {other:?}"));
                }
            }
        }
    }

    /// Takes the reader to a fenced empty prompt and returns the entry and the fence.
    ///
    /// The publication is whole on the endpoint before this returns, so a reader that takes its
    /// mailbox before it acts on a key judges a key typed afterwards against the fence, whichever
    /// of the endpoint and the terminal it notices first. Zsh and Fish read the mailbox at every
    /// key-sequence boundary, before that sequence's binding runs. Bash's reader reads it before
    /// its next ordinary read from the terminal and whenever the endpoint becomes ready while it
    /// waits, which at this drained prompt comes before any key typed afterwards. So on those
    /// three it holds for any key. The PowerShell editor reads it after a key's operation has
    /// run, so there it holds only for the end-of-file gesture, whose decision reads the mailbox
    /// first.
    ///
    /// A reader that reports the terminal's or the macro queue as still holding input may not have
    /// taken it yet: it is asked again about the same prompt until it reports them taken or the
    /// reply window ends. A reader that reports a partial key sequence is not asked again, since no
    /// key typed here leaves one: that report is the one that counts.
    ///
    /// # Panics
    ///
    /// Panics when the reader still reports a queue holding input at the empty prompt, as its last
    /// report or after the window for asking again, whether the window ends between the exchanges
    /// or inside one.
    pub fn fenced_prompt(&mut self, index: u8) -> (RootEditorEnterParams, EditorFence) {
        let mut entry = self.next_prompt();
        // One deadline covers the exchanges and the waits between them, so asking the reader again
        // never buys it another reply window.
        let deadline = self.deadline_for(REPLY);
        let mut acknowledgement = self.fence_exchange_before(&entry, fence_id(index), deadline.0);
        while Self::input_not_yet_taken(acknowledgement.queues) && !deadline.passed() {
            std::thread::sleep(deadline.left().min(Duration::from_millis(20)));
            if deadline.passed() {
                break;
            }
            // The exchange before settled on the reader that is running, so the next one asks
            // that reader rather than one a redraw has since replaced.
            entry.prompt_generation = acknowledgement.prompt_generation;
            entry.reader_revision = acknowledgement.reader_revision;
            // A window that ends inside the exchange ends the case with the report that was being
            // asked about again, which is what failed, and says how the exchange ended after it.
            acknowledgement = match self.settled_fence_exchange(&entry, fence_id(index), deadline.0)
            {
                Ok(next) => next,
                Err(why) => {
                    // A window that ran out notes the give-up when it is asked.
                    let _ = deadline.passed();
                    panic!(
                        "an idle reader reported a queue still holding input: {:?}; asked again, \
                         {why}:\n{}",
                        acknowledgement.queues,
                        self.terminal_output()
                    );
                }
            };
        }
        assert!(
            acknowledgement.queues.tty_typeahead_drained
                && acknowledgement.queues.macro_input_drained
                && acknowledgement.queues.partial_key_drained,
            "an idle reader reported a queue still holding input: {:?}",
            acknowledgement.queues
        );
        // The exchange settles on the reader that is running, which a redraw can make a different
        // one from the entry above. Everything handed back names that reader, so nothing after
        // this publishes a fence for, or asks about, a reader that has gone.
        entry.prompt_generation = acknowledgement.prompt_generation;
        entry.reader_revision = acknowledgement.reader_revision;
        let fence = fence_for(&entry, fence_id(index), attachment_id(1), epoch(4));
        self.publish(&fence);
        (entry, fence)
    }

    /// Clears whatever is in the edit buffer, and returns once the reader has said it is empty.
    ///
    /// The reader reports what it holds each time it comes to wait for a key, so the first report
    /// that arrives after the key was typed is about a reader that has dealt with it.
    ///
    /// # Panics
    ///
    /// Panics when no such report arrives inside the reply window.
    pub fn clear_line(&mut self) {
        // What the reader sent before this point is read first, so that it is not taken for what
        // the key brings.
        self.pump(Duration::ZERO);
        let reports = self.idle_reports;
        self.type_bytes(CTRL_U);
        let deadline = self.deadline_for(REPLY);
        while !(self.idle_reports > reports && self.last_idle_empty) {
            assert!(
                !deadline.passed(),
                "the reader did not report an empty buffer after the line was cleared:\n{}",
                self.terminal_output()
            );
            self.pump(Duration::from_millis(10));
        }
    }

    /// Types `text` and returns once the reader has reported a buffer that is not empty.
    ///
    /// The reader reports what it holds each time it comes to wait for a key, so the first report
    /// that arrives after the key was typed is about a reader that has dealt with it.
    ///
    /// # Panics
    ///
    /// Panics when no such report arrives inside the reply window.
    pub fn type_text(&mut self, text: &[u8]) {
        self.pump(Duration::ZERO);
        let reports = self.idle_reports;
        self.type_bytes(text);
        let deadline = self.deadline_for(REPLY);
        while !(self.idle_reports > reports && !self.last_idle_empty) {
            assert!(
                !deadline.passed(),
                "the reader did not report the text it was typed:\n{}",
                self.terminal_output()
            );
            self.pump(Duration::from_millis(10));
        }
    }
}

/// KR-REQ-07.34, KR-REQ-07.35, KR-REQ-07.85, and `handshake-accept`.
pub fn the_handshake_declares_the_packaged_reader(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    let hello = session.hello.clone();

    assert_eq!(hello.protocol, BRIDGE_PROTOCOL);
    assert_eq!(hello.session_id, session.session_id);
    assert_eq!(hello.shell.kind, kind);
    // The declaration is exactly this shell's own reader, which is what `qualify` admits.
    assert_eq!(hello.abi, BridgeAbi::qualified(kind));
    assert_eq!(
        hello.shell.executable,
        told(&package.executable),
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
    let package = Package::built(kind);
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

/// Stops or continues the shell a session started, by the process identifier the session holds.
///
/// A stop is over when the shell is stopped, not when `kill` has sent the signal: a shell that has
/// not stopped yet reads what is typed at it and runs its keys before the request that was meant
/// to be waiting for them is sent. The kernel tells a parent that its child has stopped only once
/// every thread of it has, so the wait is on that report; on Linux the state `ps` shows is the
/// main thread's alone.
///
/// # Panics
///
/// Panics when the session has no process, `kill` cannot signal it, or a shell that was sent the
/// stop has not stopped inside [`REPLY`].
#[cfg(unix)]
fn signal_the_shell(session: &Session, signal: &str) {
    use rustix::process::{Pid, WaitOptions, waitpid};

    let pid = session
        .child_pid()
        .expect("the shell's process has an identifier");
    let status = std::process::Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .status()
        .expect("kill runs");
    assert!(status.success(), "kill -{signal} {pid} failed");
    if signal == "STOP" {
        let shell = i32::try_from(pid)
            .ok()
            .and_then(Pid::from_raw)
            .expect("the shell's process identifier is a process");
        let deadline = session.deadline_for(REPLY);
        loop {
            match waitpid(Some(shell), WaitOptions::UNTRACED | WaitOptions::NOHANG) {
                Ok(Some((_, status))) if status.stopped() => break,
                Ok(Some((_, status))) => {
                    panic!("the shell {pid} ended when it was sent the stop: {status:?}")
                }
                Ok(None) => {}
                Err(error) => panic!("waiting for the shell {pid} to stop: {error}"),
            }
            assert!(
                !deadline.passed(),
                "the shell {pid} was sent the stop and is not stopped"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// KR-REQ-08.49: bytes the host put into the terminal that no one typed are input the reader has
/// not taken, so a reader that is asked for its queues says they are not drained.
///
/// The bridge cannot tell what a byte is: a host's answer to a query the application made reaches
/// the shell as input like any other, and the fence rests on the reader saying it has none left.
/// The case stops an idle reader, puts three answers a terminal gives to a device-attributes query
/// into its terminal, asks for the fence and lets the reader go, so the answers are waiting when
/// the reader meets the request. A reader takes its input a byte at a time and meets its mailbox
/// at the first point it is free to, which is before the first byte or after the first whole key
/// sequence, so more than one answer is waiting whichever it is, and what it reports then has to
/// count the bytes it has not read. A reader that reaches its mailbox only at a step a person gives
/// it by typing is given that step first, so the answers are behind it. Once it has taken them a
/// later exchange says the queues are drained, so a reader that counts bytes it no longer holds is
/// not the one that passes. A reader of Zsh or Bash takes a whole answer out of its keys in one
/// step, so for those two the answers have three plain keys behind them, and it is the keys that
/// are waiting when it meets the request.
///
/// PSReadLine is given two more steps and half a character instead, and what the case shows for it
/// is the count of the bytes the decoder holds. It draws every printable key it takes, and a draw
/// after it was continued asks the terminal where the cursor is, from the same input its key thread
/// is reading: the key thread takes the reply for keys, and the draw waits for good, or the draw
/// takes keys ahead of the reply for part of it, and three device-attributes answers ahead of the
/// reply give .NET a column of 226222621 and the editor an exception. Its key thread also queues every
/// key that is waiting in the first two milliseconds, so whether the editor is at a step with
/// input left to read depends on how fast that went. A step draws nothing, and half a character is
/// no key at all, so it stays unread whatever the timing: the editor meets the request at a step
/// with a byte it has not read, and nothing is drawn before the character is whole. The bytes of a
/// host's answer that the runtime has read and not handed on are counted from its buffer, which
/// [`bytes_the_runtime_has_read_from_the_terminal_are_input_the_reader_has_not_taken`] shows
/// without an editor.
///
/// # Panics
///
/// Panics when the reader says its terminal's typeahead is drained with the answer unread, or says
/// it is not after it has taken the answer.
#[cfg(unix)]
pub fn bytes_the_host_put_into_the_terminal_are_input_the_reader_has_not_taken(kind: ShellKind) {
    if kind == ShellKind::PowerShell {
        // Two steps, and the first byte of "\u{e9}" in UTF-8 with its second to follow.
        unread_input_is_not_drained(kind, b"\x06\x06\xc3", b"\xa9");
    } else {
        // Three answers a terminal gives to a primary device-attributes query, and three keys behind
        // them. A reader of Zsh or Bash takes whole answers out of its keys as it reads them, so the
        // answers are never what it is holding unread when it answers the fence; the keys behind
        // them are, and it counts them until it has read them.
        unread_input_is_not_drained(kind, b"\x1b[?62;22c\x1b[?62;22c\x1b[?62;22cabc", b"");
    }
}

/// Three answers a terminal gives to a device-attributes query, alone in a Fish reader's terminal,
/// are input the reader has not taken.
///
/// The case for every reader but PowerShell puts three plain keys behind the answers, because a
/// reader of Zsh or Bash takes a whole answer out of its keys as it reads them and it is the keys
/// that are waiting when that reader meets the request. A Fish reader that counted the keys and
/// nothing else would pass that case, so this one puts the answers into the terminal with nothing
/// behind them, and what the reader reports on meeting the request is a count of the answers
/// themselves. Once it has read them a later exchange says the queues are drained, and the editor's
/// buffer in that answer is empty and at the revision the reader's idle report gave it: taken as
/// the host's answers, they never reached the command line.
///
/// KR-REQ-08.49, the last clause for a Fish reader only: the shell bridge accounts for bytes the
/// host delivered that are not a person's keys. Not shown here: the other readers, which the case
/// above shows with keys behind the answers, and the clause's other parts (the replies' deadlines
/// and queue limits, source loss closing paste framing, and what a reply that does alter reader
/// state does to the fence's proof).
///
/// # Panics
///
/// Panics when the reader says its terminal's typeahead is drained with the answers unread, says
/// it is not after it has taken them, or has put them into its edit buffer.
#[cfg(unix)]
pub fn three_answers_alone_in_the_terminal_are_input_the_fish_reader_has_not_taken() {
    let (before, after) = unread_input_is_not_drained(
        ShellKind::Fish,
        b"\x1b[?62;22c\x1b[?62;22c\x1b[?62;22c",
        b"",
    );
    // Counted as input the reader has not taken is not the same as taken as the person's keys: an
    // editor that put the answers into the command line would also have them unread until it did.
    assert!(
        before.buffer_empty,
        "the buffer was empty before the answers: {before:?}"
    );
    assert!(
        after.buffer_empty,
        "the answers the reader took were put into the command line: {after:?}"
    );
    assert_eq!(
        after.buffer_revision, before.buffer_revision,
        "and the reader's edit buffer was not changed by them"
    );
}

/// KR-REQ-08.49: the first byte of a character the terminal delivered in two parts is input the
/// reader has not taken, although it has read it.
///
/// A runtime that reads its terminal in chunks keeps the first byte of a multibyte character in its
/// decoder until the rest arrives. That byte is no longer in the terminal's queue or in a buffer of
/// bytes, and the reader that counts only those says its queues are drained with a character half
/// delivered. The case types the step a reader at a step takes and the first byte of a two-byte
/// character in one go, asks for the fence, and lets the reader go; it then types the second byte
/// and expects the queues drained once the reader has the whole character.
///
/// # Panics
///
/// Panics when the reader says its terminal's typeahead is drained with the first byte unread, or
/// says it is not after it has the whole character.
#[cfg(unix)]
pub fn half_a_character_the_terminal_delivered_is_input_the_reader_has_not_taken(kind: ShellKind) {
    // The first byte of "\u{e9}" in UTF-8, and its second.
    unread_input_is_not_drained(kind, b"\xc3", b"\xa9");
}

/// KR-REQ-08.49: a byte waiting in the terminal's queue, which the runtime has not read, is input
/// the reader has not taken.
///
/// The runtime reads its terminal when the editor asks for a key, so a byte that arrives between
/// two keys is in the terminal's queue and in none of the runtime's. The reader counts it by asking
/// the runtime whether the terminal has input, and that is the whole of the count here: the runtime
/// holds nothing of it, and the editor's queue is empty. The case runs the module's count on a
/// terminal nobody reads, before a line is typed at it and after, and expects none and then the
/// line. The second count is taken once the harness has typed the line and said so by making a
/// file, so no length of time stands between the line and the count.
///
/// # Panics
///
/// Panics when the count is not nothing at first, or does not see the line.
#[cfg(unix)]
pub fn a_byte_waiting_in_the_terminals_queue_is_input_the_reader_has_not_taken(kind: ShellKind) {
    let package = Package::built(kind);
    let module = package
        .directory()
        .join("modules/KalaReach.ShellBridge/KalaReach.ShellBridge.psd1")
        .display()
        .to_string();
    let script = |typed: &Path| {
        let typed = typed.display();
        let seconds = REPLY.as_secs();
        format!(
            "Import-Module '{module}'; $module = Get-Module KalaReach.ShellBridge; \
             Write-Output (('kr-be' + 'fore=[') + (& $module {{ Read-KrRuntimeUnread }}) + ']'); \
             $until = [DateTime]::UtcNow.AddSeconds({seconds}); \
             while (-not (Test-Path -LiteralPath '{typed}') -and [DateTime]::UtcNow -lt $until) \
             {{ Start-Sleep -Milliseconds 20 }}; \
             Write-Output (('kr-af' + 'ter=[') + (& $module {{ Read-KrRuntimeUnread }}) + ']')"
        )
    };
    let shown = package.ask_with_input_typed_after(script, "kr-before=[", b"x\n");
    assert!(
        shown.contains("kr-before=[0]"),
        "a terminal nobody typed at has nothing unread: {shown:?}"
    );
    assert!(
        shown.contains("kr-after=[1]"),
        "a line waiting in the terminal's queue is input the runtime has not read: {shown:?}"
    );
}

/// KR-REQ-08.49: bytes the runtime has read from the terminal and has not handed on are input the
/// reader has not taken.
///
/// The runtime reads its terminal in chunks, everything a host put there at once, and hands out
/// one key at a time. What is left of a chunk is in the terminal's queue no more, in the decoder
/// only when it is half a character, and in the editor's queue only when the editor has taken it
/// from the runtime; the reader counts it from the runtime's buffer. This case has no editor and no
/// key thread, so no timing decides what has been read. It types a key, a whole answer to a
/// device-attributes query and a line end in one write, takes one key with
/// `[Console]::ReadKey($true)`, and runs the module's count, which has to see the rest.
///
/// # Panics
///
/// Panics when the count after the key is no more than the terminal's queue alone gives, or the
/// terminal shows no count.
#[cfg(unix)]
pub fn bytes_the_runtime_has_read_from_the_terminal_are_input_the_reader_has_not_taken(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let module = package
        .directory()
        .join("modules/KalaReach.ShellBridge/KalaReach.ShellBridge.psd1")
        .display()
        .to_string();
    let script = format!(
        "Import-Module '{module}'; $module = Get-Module KalaReach.ShellBridge; \
         Write-Output (('kr-be' + 'fore=[') + (& $module {{ Read-KrRuntimeUnread }}) + ']'); \
         $key = [Console]::ReadKey($true); \
         Write-Output (('kr-af' + 'ter=[') + (& $module {{ Read-KrRuntimeUnread }}) + ']')"
    );
    // The key, an answer to a primary device-attributes query, and the end of the line that makes
    // all of it readable at once.
    let shown = package.ask_with_input_typed_after(|_| script, "kr-before=[", b"x\x1b[?62;22c\n");
    let count = shown
        .split("kr-after=[")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .and_then(|count| count.parse::<u64>().ok());
    // The terminal's queue is one of the counts and gives at most one, so more than one is the
    // runtime's buffer: the case fails when the reader leaves that out.
    assert!(
        count.is_some_and(|count| count > 1),
        "the answer and the line end the runtime read and has not handed on are input the reader \
         has not taken: {shown:?}"
    );
}

/// KR-REQ-08.48, KR-REQ-08.49: the host's answer to a terminal query, reaching the terminal of an
/// idle reader, never reaches the line the reader edits.
///
/// An application asked the terminal something and ended before the answer came, so the host's
/// answer lands in the terminal of a shell that is at its prompt with nothing typed. The answer is
/// not the person's input, and a line editor that takes its bytes as keys puts part of them in the
/// line and draws what it put there. The case writes a primary device-attributes answer into the
/// terminal in one piece, as the host does, and asks the reader for its state until the terminal
/// holds nothing it has not taken. It expects the line empty, a line typed afterwards to run, a
/// return that follows an Escape and a bracket in one write to end the line, as it does for a person,
/// and a letter typed behind the start of an answer to be in the line.
///
/// # Panics
///
/// Panics when the reader's line has anything in it once it has taken the answer, when the reader
/// stops answering, or when a line typed afterwards does not run.
#[cfg(unix)]
pub fn a_hosts_answer_to_a_terminal_query_never_reaches_the_line_the_editor_reads(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    let first = session.first_prompt();
    session.expect_event(
        "an idle report from this reader with its queues clear",
        |event| {
            matches!(
                event,
                BridgeEvent::ReaderIdle(idle)
                    if idle.prompt_generation == first.prompt_generation
                        && idle.reader_revision == first.reader_revision
                        && idle.editor.buffer_empty
                        && idle.snapshot.queued_keys == U64::new(0)
                        && idle.snapshot.pending_bytes == U64::new(0)
            )
        },
    );
    // An editor that asks where the cursor is once its prompt is drawn reads the answer from the
    // same input as its keys, and the answer under test is behind that reply, as a person's keys
    // are.
    if dialect(kind).types_at_the_prompt {
        assert!(
            session.wait_for_prompt(),
            "the shell drew no prompt to put the host's answer behind:\n{}",
            session.terminal_output()
        );
        assert!(
            session.wait_for_editor_reading(),
            "the editor never asked where the cursor was after the prompt:\n{}",
            session.terminal_output()
        );
    }

    session.type_bytes(b"\x1b[?62;22c");

    let latest = the_reader_once_it_has_taken_what_the_terminal_holds(&mut session, first);
    assert!(
        latest.queues.tty_typeahead_drained,
        "the reader still reports typeahead after it has had the answer: {:?}\n{}",
        latest.queues,
        session.terminal_output()
    );
    assert!(
        latest.editor.buffer_empty,
        "the host's answer is in the line the reader edits:\n{}",
        session.terminal_output()
    );
    assert_eq!(latest.snapshot.queued_keys, U64::new(0));

    let marker = "kr-answer-ok";
    assert!(
        session.run(&print_assembled(kind, marker), marker),
        "a line typed after the host's answer did not run:\n{}",
        session.terminal_output()
    );

    // What begins like an answer and is not one is the person's: an Escape, a bracket and a return
    // in one write end no sequence, so the return goes back to the editor and ends the line, and
    // the shell draws its next prompt. An editor that took the return as part of an answer would
    // draw none.
    assert!(
        session.wait_for_prompt() && session.wait_for_editor_reading(),
        "the shell drew no prompt to type behind:\n{}",
        session.terminal_output()
    );
    // From here to the last exchange the reader is given no step. A step is a key: it would end the
    // wait of a read that waited for the rest of an answer, and it makes the reader report idle
    // again, which the report the case waits for after the start of an answer could not then be
    // told from.
    session.stepping = false;
    session.forget_events();
    session.mark = session.written();
    session.type_bytes(b"\x1b[\r");
    assert!(
        session.wait_for_prompt(),
        "a return typed behind an Escape and a bracket was taken for part of an answer:\n{}",
        session.terminal_output()
    );

    // An answer the terminal has delivered only the start of is not waited for. The editor reads
    // the keys of an answer only while the terminal has delivered them, so an Escape, a bracket and
    // a semicolon end with the reader idle again, and the next key the person types is theirs: a
    // letter typed behind them is in the line. A read that waited for the final character of the
    // answer would report nothing until a key came, and would take that key for the answer's end.
    let entry = session.next_prompt();
    assert!(
        session.wait_for_prompt() && session.wait_for_editor_reading(),
        "the shell drew no prompt to type an unfinished answer behind:\n{}",
        session.terminal_output()
    );
    session.expect_event(
        "the idle report of the read the answer is typed into",
        |event| {
            matches!(
                event,
                BridgeEvent::ReaderIdle(idle) if idle.prompt_generation == entry.prompt_generation
            )
        },
    );
    session.type_bytes(b"\x1b[;");
    session.expect_event(
        "an idle report once the editor has taken the start of an answer",
        |event| {
            matches!(
                event,
                BridgeEvent::ReaderIdle(idle)
                    if idle.prompt_generation == entry.prompt_generation
                        && idle.editor.buffer_empty
            )
        },
    );
    session.type_bytes(b"x");
    session.stepping = true;
    let latest = the_reader_once_it_has_taken_what_the_terminal_holds(&mut session, entry);
    assert!(
        !latest.editor.buffer_empty,
        "a letter typed behind the start of an answer was taken for its end:\n{}",
        session.terminal_output()
    );
}

/// One answer of each shape the host's query broker writes to the terminal for a program that
/// asked: device attributes, statuses, cursor positions, mode and window reports, the terminal's
/// version, the keyboard protocol, a setting, a capability, colours and the clipboard. They are
/// in the words the broker uses, ending as it ends them.
#[cfg(unix)]
const HOST_ANSWERS: &[&str] = &[
    "\x1b[?62;22c",
    "\x1b[>41;1;0c",
    "\x1bP!|4B520001\x1b\\",
    "\x1b[0n",
    "\x1b[24;80R",
    "\x1b[?24;80;1R",
    "\x1b[?13n",
    "\x1b[?25;1$y",
    "\x1b[4;2$y",
    "\x1b[8;24;80t",
    "\x1bP>|KalaReach(kr-vt/1)\x1b\\",
    "\x1b[?0u",
    "\x1b[>4;0m",
    "\x1bP1$r0;1m\x1b\\",
    "\x1bP1+r544e=4b52\x1b\\",
    "\x1b]11;rgb:0000/0000/0000\x07",
    "\x1b]4;1;rgb:cdcd/0000/0000\x1b\\",
    "\x1b]52;c;\x1b\\",
];

/// KR-REQ-08.48: the host's answers to a program's questions, written into the terminal in the
/// middle of what a person types, leave what the person typed whole and in order.
///
/// A program asked the terminal something and ended, and the answers reach a prompt where the
/// person is typing, so the keys and the answers arrive in one write. The case types a line that
/// prints a word from its arguments, each argument followed by one answer, the answers in turn each
/// of a shape the broker writes. A reader that types an answer into the line puts its characters in
/// the arguments, and a reader that loses a key loses a letter: either way the word the line prints
/// is not the word the keys spell. The arguments are separated by spaces, so the line the reader
/// draws never holds the word, and only the command having run puts it on the screen.
///
/// # Panics
///
/// Panics when the line does not print the word the keys spell.
#[cfg(unix)]
pub fn the_keys_a_person_types_around_a_hosts_answers_arrive_whole_and_in_order(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    let letters = "abcdefghijklmnopqrstuvwxyz";
    let count = HOST_ANSWERS.len();
    let mut line = format!("printf '{}\\n' kr-", "%s".repeat(count + 1));
    let mut word = String::from("kr-");
    for (index, answer) in HOST_ANSWERS.iter().enumerate() {
        line.push_str(answer);
        let letter = &letters[index..=index];
        line.push(' ');
        line.push_str(letter);
        word.push_str(letter);
    }
    assert!(
        session.run(&line, &word),
        "the keys typed around the host's answers did not spell {word:?}:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-08.48: the byte behind the start of a device control string that is not one the reader
/// skips stays the person's.
///
/// A reader that reads a device control string to its end decides from its first bytes which string
/// it is. The tertiary device attributes begin with `!` and the report of a setting with `1$`, and
/// the byte behind such a header says whether the string is one: a person who presses Alt+Shift+p
/// and then types `!` or `1$` and a command has typed no string, and the first letter of the
/// command is theirs. The case types each header and a command that prints a word, with no
/// terminal answer anywhere in the line: a reader that took the letter for the string's next byte
/// runs a command with a letter missing, and the word is not printed.
///
/// # Panics
///
/// Panics when a line does not print its word.
#[cfg(unix)]
pub fn the_byte_behind_a_device_control_header_the_reader_does_not_skip_stays_the_persons(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    for (header, marker) in DEVICE_CONTROL_HEADERS_NOT_SKIPPED {
        let line = format!("{header}{}", print_assembled(kind, marker));
        assert!(
            session.run(&line, marker),
            "the line typed behind {header:?} did not print {marker:?}:\n{}",
            session.terminal_output()
        );
    }
}

/// The starts of the device control strings a reader skips to their end, each with the word a line
/// typed behind it prints. The strings are the tertiary device attributes (`ESC P !`) and the
/// reports of a setting (`ESC P 1 $` and `ESC P 0 $`); the header is all the reader has to go on
/// until the byte behind it says whether it is one.
#[cfg(unix)]
const DEVICE_CONTROL_HEADERS_NOT_SKIPPED: [(&str, &str); 3] = [
    ("\x1bP!", "kr-dcs-a"),
    ("\x1bP1$", "kr-dcs-b"),
    ("\x1bP0$", "kr-dcs-c"),
];

/// KR-REQ-08.48: a cursor key behind the start of a device control string that is not one the
/// reader skips is still the cursor key.
///
/// The reader tells the string from text by the byte behind its header, and an Escape there begins
/// a sequence of its own. A person who presses Alt+Shift+p, types `!` (or `1$` or `0$`) and moves
/// the cursor with an arrow key inside the wait for the next byte of a sequence has typed no
/// string, and the arrow key is theirs whole. The case types a line that prints a word from two
/// arguments, each header, the left arrow and one letter: the word is printed only if the arrow
/// moved the cursor before the last letter of the second argument. A reader that takes the Escape
/// for a key of its own and the rest for text puts `[D` into the line.
///
/// # Panics
///
/// Panics when a line does not print its word.
#[cfg(unix)]
pub fn a_cursor_key_behind_a_device_control_header_the_reader_does_not_skip_still_moves_the_cursor(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    for (header, _) in DEVICE_CONTROL_HEADERS_NOT_SKIPPED {
        let word = "kr-curexd";
        let line = format!("printf '%s%s\\n' kr-cur ed{header}\x1b[Dx");
        assert!(
            session.run(&line, word),
            "the arrow key typed behind {header:?} did not move the cursor:\n{}",
            session.terminal_output()
        );
    }
}

/// KR-REQ-08.48: a long run of Escape pairs, each ahead of the start of a device control string that
/// is not one the reader skips, is read to its end and leaves the shell running.
///
/// The Escape that comes before an `ESC P !` header is a key of the person's own, and the reader
/// owes one for each pair it reads again after dropping the header. A reader that counts them in a
/// byte stops at the 256th, and a shell built with overflow checks ends on it: the host's shell
/// session goes with it. The case types three hundred pairs, each with the header, and a
/// control character that clears the line, then runs a command that prints a word: the word is
/// printed only if the shell took them all and went on.
///
/// # Panics
///
/// Panics when the shell does not print the word.
#[cfg(unix)]
pub fn a_long_run_of_escape_pairs_before_a_device_control_header_leaves_the_shell_running(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    let mut keys = "\x1b\x1bP!".repeat(300);
    keys.push('\x15');
    session.type_bytes(keys.as_bytes());
    assert!(
        session.answered("kr-esc-run"),
        "the shell did not go on after three hundred pairs of Escapes and headers:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-08.48: the Escape that comes before a device control string that is not one the reader
/// skips stays ahead of the key behind the string while the reader waits for the terminal's answer.
///
/// While a query of the terminal is unanswered the reader sets the keys typed aside at the back of
/// its queue, and otherwise it puts a key it has decoded at the front. The Escape of an
/// `ESC ESC P !` is owed to the person ahead of the key that is read again, in both. The case sets
/// the editor to its vi keys, takes the terminal's answers away so that the next prompt's query
/// stays open, types a line with a word that ends in a letter, the Escapes with the header and an
/// `x`, and a return, then gives the answers back. The Escape comes out ahead of the `x`, and an
/// Escape followed at once by a key is read by the editor as the two of them together, which leave
/// the word as it was, so the line prints the whole word and a dash. With the two the other way
/// round the `x` is typed into the word and the Escape ends up beside the return, so the line
/// does not print that word. The dash is what the case waits for with the word, so that a word with
/// anything after its last letter is not taken for the one that was asked for.
///
/// # Panics
///
/// Panics when the line does not print its word.
#[cfg(unix)]
pub fn the_keys_around_a_device_control_header_keep_their_order_while_the_terminal_is_asked(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    let (vi_mode, _) = vi_keymap_commands(kind).expect("this editor has vi keys");
    assert!(session.run(vi_mode, "kr-vi-on"));
    let _ = session.next_prompt();
    session.hold_terminal_answers();
    assert!(session.answered("kr-held"));
    let _ = session.next_prompt();
    let start = session.written();
    session.type_bytes(b"printf '%s%s-\\n' kr-ord ered\x1b\x1bP!x\r");
    session.release_terminal_answers();
    let deadline = session.deadline_for(REPLY);
    assert!(
        session.wait_for_output_after_by(start, "kr-ordered-", deadline),
        "the Escape did not stay ahead of the key behind the header:\n{}",
        shown_since(&session, start)
    );
}

/// KR-REQ-08.48: a bracketed paste with an unfinished device control string in its text still
/// ends, and the key typed behind it reaches the line.
///
/// The reader reads a tertiary device attributes string or a report of a setting to its terminator,
/// and a terminal sends one only as an answer, never inside a paste. A reader that reads one inside
/// a paste takes the end of the paste for part of the string when the text has the string's start
/// and no terminator, and stays in the paste: every key typed afterwards is held with it. The case
/// pastes a command with each of the strings' starts (`ESC P ! |`, `ESC P 1 $ r`, `ESC P 0 $ r`)
/// and no terminator in the middle of a quoted word, types the rest of the word and a last word
/// behind the paste, and returns: the word is printed only if the paste ended and the typed keys
/// reached the line, with the byte behind the start among the pasted text.
///
/// # Panics
///
/// Panics when a line does not print its word.
#[cfg(unix)]
pub fn a_paste_with_an_unfinished_device_control_string_in_it_still_ends(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    for (start, kept) in [("\x1bP!|", '|'), ("\x1bP1$r", 'r'), ("\x1bP0$r", 'r')] {
        let line = format!("\x1b[200~printf '%s%s\\n' 'kr-pa{start}\x1b[201~' ted");
        let word = format!("kr-pa{kept}ted");
        assert!(
            session.run(&line, &word),
            "the keys typed behind the paste with {start:?} in it did not reach the line:\n{}",
            session.terminal_output()
        );
    }
}

/// KR-REQ-08.48: a bracketed paste with the start of a device control string that is not one the
/// reader skips in its text still ends, and the text behind the start is pasted.
///
/// The paste ends with a sequence of the terminal's own, and the Escape that begins it comes
/// right behind the text. When the text ends in the header of a string the reader skips (`ESC P !`,
/// `ESC P 1 $`, `ESC P 0 $`) that Escape is the byte the reader reads to tell the string from
/// text, and a reader that does not read it again as the start of the paste's end takes the rest
/// of the end for pasted text: the paste never ends and every key typed after it is held with the
/// paste. A letter behind the header inside the paste is the byte read to tell, too, and belongs
/// to the paste, not to the keys typed. The case pastes a command with each header at its end,
/// types the last word of the command behind the paste and returns, and pastes a command with
/// each header before its last word: the word is printed only if the paste ended, the typed word
/// came after it and the pasted word reached the line in its place.
///
/// # Panics
///
/// Panics when a line does not print its word.
#[cfg(unix)]
pub fn a_paste_with_a_device_control_header_the_reader_does_not_skip_in_its_text_is_pasted_whole(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    for (header, _) in DEVICE_CONTROL_HEADERS_NOT_SKIPPED {
        let line = format!("\x1b[200~printf '%s%s\\n' kr-pas{header}\x1b[201~ ed");
        assert!(
            session.run(&line, "kr-pased"),
            "the keys typed behind the paste ending in {header:?} did not reach the line:\n{}",
            session.terminal_output()
        );
        let line = format!("\x1b[200~printf '%s%s\\n' kr-pa{header}sted\x1b[201~");
        assert!(
            session.run(&line, "kr-pasted"),
            "the text pasted behind {header:?} did not reach the line:\n{}",
            session.terminal_output()
        );
    }
}

/// KR-REQ-08.48: the host's answer between the cursor keys a person presses leaves the cursor keys
/// working.
///
/// A cursor key begins with an Escape and a bracket as an answer does, and the reader has to tell
/// them apart without holding a key back. The case types a line that prints a word from two
/// arguments with a letter missing from the second, presses the left arrow twice, takes in an
/// answer, presses it twice more and types the letter: the line prints the word only if the
/// cursor stood at the start of the second argument.
///
/// # Panics
///
/// Panics when the line does not print the word.
#[cfg(unix)]
pub fn a_hosts_answer_between_cursor_keys_leaves_the_cursor_keys_working(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    let left = "\x1b[D";
    let line = format!(
        "printf '%s%s\\n' kr-ans ered{left}{left}{}{left}{left}w",
        HOST_ANSWERS[0]
    );
    assert!(
        session.run(&line, "kr-answered"),
        "the cursor keys around the host's answer did not move the cursor to the letter:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-08.48: a run of bytes shaped like the host's answer inside a bracketed paste is the text
/// the person pasted, and reaches the line whole.
///
/// The reader takes an answer out of the keys, and a paste is not keys: its bytes are data, whatever
/// they look like, and a log or a capture pasted into a prompt can hold any escape sequence. The
/// case pastes a line that prints a string with an answer in the middle of it, through `od` and `tr`
/// (some `od` pad their columns), so the bytes the shell was given show as hex that no echo of the
/// typed line can draw.
///
/// # Panics
///
/// Panics when the line does not print the string with the answer in it.
#[cfg(unix)]
pub fn a_reply_shaped_run_inside_a_bracketed_paste_is_pasted_whole(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    let line = format!(
        "\x1b[200~printf '%s' 'x{}y' | od -An -tx1 | tr -s ' '\x1b[201~",
        HOST_ANSWERS[0]
    );
    assert!(
        session.run(&line, "78 1b 5b 3f 36 32 3b 32 32 63 79"),
        "the answer inside the paste did not reach the line:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-08.48: the host's answer behind text a person has typed leaves the text on the screen.
///
/// An answer left over from a program that ended arrives in the same delivery as the keys, behind
/// them, and the person has not pressed return. The reader takes the answer out of the keys, and
/// the editor has to go on and draw what was typed: a reader that waits for another key after it
/// has taken the answer leaves the line in memory and the screen as it was. The editor draws a line
/// only once it has the keys, and the terminal does not echo while it reads, so the text on the
/// screen after the keys went in is the editor's drawing.
///
/// # Panics
///
/// Panics when the typed text is not drawn.
#[cfg(unix)]
pub fn a_hosts_answer_behind_typed_text_leaves_the_text_drawn(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));
    let _ = session.next_prompt();
    let start = session.written();
    let keys = format!("echo ab{}", HOST_ANSWERS[0]);
    session.type_bytes(keys.as_bytes());
    assert!(
        session.drew_after(start, "echo ab", REPLY).was_drawn(),
        "the text typed in front of the host's answer was not drawn:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-08.48: an Escape a person presses, with a host's answer behind it in the same delivery,
/// is still the person's Escape.
///
/// The Escape begins a key with the key that follows it, and the answer begins with an Escape of its
/// own, so the reader that looks at what follows the first Escape finds the second. The case types a
/// line that prints a word from two arguments with a letter missing from the second, presses
/// Escape, takes in an answer and presses `b` in the same write: the editor's backward-word. The
/// letter then goes in front of the second argument only if the Escape and the `b` made the key.
///
/// # Panics
///
/// Panics when the line does not print the word.
#[cfg(unix)]
pub fn an_escape_and_a_hosts_answer_in_one_delivery_leave_the_escape_a_key(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    let line = format!("printf '%s%s\\n' kr-ans ered\x1b{}bw", HOST_ANSWERS[0]);
    assert!(
        session.run(&line, "kr-answered"),
        "the Escape in front of the host's answer was not the Escape of the key that followed:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-08.48: in vi insert mode, an Escape a person presses with a host's answer behind it in
/// one delivery leaves insert mode at once, without another key.
///
/// The editor decides whether an Escape is a lone key or the start of a key sequence by looking at
/// what has arrived behind it. An answer behind it is not part of any key, so the editor has to
/// take it out of the way and treat the Escape as the key that ends insert mode; a reader that
/// takes the answer and then waits for another key leaves the line in insert mode. The case turns
/// on the editor's mode indicator, types a word, an Escape and an answer in one write, waits for
/// the indicator to say command mode, and then appends a second word with `A` and runs the line.
/// The indicator is the editor's own drawing, which nothing the person typed can put on the screen.
///
/// # Panics
///
/// Panics when the indicator does not change, or the line does not print the word.
#[cfg(unix)]
pub fn an_escape_and_a_hosts_answer_in_one_delivery_leave_vi_insert_mode(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    assert!(
        session.run(
            "set -o vi; bind 'set show-mode-in-prompt on'; printf '%s%s\\n' kr-vi- on",
            "kr-vi-on"
        ),
        "the editor did not switch to vi bindings:\n{}",
        session.terminal_output()
    );
    let _ = session.next_prompt();
    let start = session.written();
    let keys = format!("printf '%s%s\\n' kr-\x1b{}", HOST_ANSWERS[0]);
    session.type_bytes(keys.as_bytes());
    assert!(
        session.drew_after(start, "(cmd)", REPLY).was_drawn(),
        "the editor stayed in insert mode after an Escape with an answer behind it:\n{}",
        session.terminal_output()
    );
    assert!(
        session.finish_line(&keys, "A ab", "kr-ab"),
        "the line appended in command mode did not run:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-08.48: text pasted in vi replace mode, which Readline reads again key by key, reaches
/// the line whole, a run shaped like the host's answer inside it included.
///
/// A bracketed paste is data, and the reader leaves its bytes alone while Readline collects it.
/// In vi replace mode Readline puts the collected text back among its keys and reads it again, so
/// the bytes are read a second time as keys, and the reader must not take an answer-shaped run of
/// them for an answer then either. The case switches to vi bindings, presses Escape and `R`, and
/// pastes a line that prints a string with an answer in the middle of it, through `od` and `tr`
/// (some `od` pad their columns), so the bytes the shell was given show as hex that no echo of the
/// typed line can draw.
///
/// # Panics
///
/// Panics when the line does not print the string with the answer in it.
#[cfg(unix)]
pub fn a_paste_read_again_in_vi_replace_mode_reaches_the_line_whole(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    assert!(
        session.run(
            "set -o vi; printf '%s%s\\n' kr-vi- replace",
            "kr-vi-replace"
        ),
        "the editor did not switch to vi bindings:\n{}",
        session.terminal_output()
    );
    let _ = session.next_prompt();
    let line = format!(
        "\x1bR\x1b[200~printf '%s' 'x{}y' | od -An -tx1 | tr -s ' '\x1b[201~",
        HOST_ANSWERS[0]
    );
    assert!(
        session.run(&line, "78 1b 5b 3f 36 32 3b 32 32 63 79"),
        "the answer inside the text pasted in replace mode did not reach the line:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-08.48: the rest of a paste whose first byte Readline takes as a search target reaches the
/// editor's keys whole, a run shaped like the host's answer inside it included.
///
/// A character search reads the target from the keys, and when the target is the start of a
/// bracketed paste Readline takes the paste's first byte for it and puts the rest back among its
/// keys. Those bytes are the person's paste and not the host's, so the reader must not take a run
/// of them for an answer. The case binds, to a command that prints a word, the key sequence that is
/// the shape of an answer, presses the editor's character-search key, and pastes a letter followed
/// by that sequence: the bytes behind the letter are keys, and the word is printed only if the
/// sequence reached the editor whole.
///
/// # Panics
///
/// Panics when the bound command does not run.
#[cfg(unix)]
pub fn the_rest_of_a_paste_read_as_a_search_target_reaches_the_keys_whole(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    let binding = format!(
        "bind -x '\"\\e[?62;22c\": printf \"%s%s\\n\" kr-ke ys'; {}",
        print_assembled(kind, "kr-bound")
    );
    assert!(
        session.run(&binding, "kr-bound"),
        "the line that binds the key sequence did not run:\n{}",
        session.terminal_output()
    );
    let _ = session.next_prompt();
    let start = session.written();
    // The search key, then a paste of a letter and the sequence.
    session.type_bytes(b"\x1d\x1b[200~x\x1b[?62;22c\x1b[201~");
    let deadline = session.deadline_for(REPLY);
    assert!(
        session.wait_for_output_after_by(start, "kr-keys", deadline),
        "the bytes of the paste behind its first byte did not reach the editor's keys whole:\n{}",
        shown_since(&session, start)
    );
}

/// KR-REQ-08.48: pasted bytes that Readline gives back after a key sequence fails are still pasted.
///
/// A key sequence that is a prefix of a longer binding is read on until a key fails it, and
/// Readline then gives every key it read back, the last first. When the first key is a letter that
/// a character search took the rest of a paste for, the bytes behind it are pasted text, and so are
/// the bytes it gives back; the keys that failed the sequence are not, and a reader that gave the
/// bytes the marks of those keys, or lost the marks of the oldest of a long sequence, would take an
/// answer-shaped run among them for the host's. The case binds the answer-shaped run to a command
/// that prints a word, and a longer sequence that begins with a letter, holds the run and ends in
/// a hundred and forty keys and a last one. It presses the editor's character-search key and
/// pastes a letter, the letter that begins the longer sequence, the run and a hundred and thirty of
/// the keys, then types the other ten and a key that is not the sequence's last. The sequence fails
/// at the last key: the word is printed only if the run reached the editor's keys whole after the
/// hundred and fifty keys were given back.
///
/// # Panics
///
/// Panics when the bound command does not run.
#[cfg(unix)]
pub fn a_key_sequence_that_fails_behind_pasted_bytes_gives_them_back_as_pasted(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    let sequence_end = "z".repeat(140);
    let binding = format!(
        "bind -x '\"\\e[?62;22c\": printf \"%s%s\\n\" kr-ke ys'; \
         bind -x '\"x\\e[?62;22c{sequence_end}q\": printf \"%s%s\\n\" kr-ot her'; {}",
        print_assembled(kind, "kr-bound")
    );
    assert!(
        session.run(&binding, "kr-bound"),
        "the line that binds the key sequences did not run:\n{}",
        session.terminal_output()
    );
    let _ = session.next_prompt();
    let start = session.written();
    // The search key, then a paste of the search target, the sequence and most of its end, then
    // the rest of its end and a key that is not the sequence's last, typed behind the paste.
    let mut keys = b"\x1d\x1b[200~ax\x1b[?62;22c".to_vec();
    keys.extend(std::iter::repeat_n(b'z', 130));
    keys.extend_from_slice(b"\x1b[201~");
    keys.extend(std::iter::repeat_n(b'z', 10));
    keys.push(b'y');
    session.type_bytes(&keys);
    let deadline = session.deadline_for(REPLY);
    assert!(
        session.wait_for_output_after_by(start, "kr-keys", deadline),
        "the pasted bytes a failed key sequence gave back did not reach the editor's keys whole:\n{}",
        shown_since(&session, start)
    );
}

/// KR-REQ-08.48: a byte of a paste that Readline reads again as a key is not the end-of-input
/// gesture.
///
/// A character search takes the first byte of a paste for its target and reads the rest again as
/// keys. They are pasted text, whatever they are: a person who pastes a letter and an end-of-input
/// character has not pressed the gesture, as they have not when the paste reaches the line the usual
/// way. The case sets the shell to keep the end-of-input character from ending it, presses the
/// character-search key at an empty prompt under a fence and pastes a letter with the character
/// behind it: the reader sends no decision about it, and the shell goes on.
///
/// # Panics
///
/// Panics when a decision is sent for the character, or the shell stops answering.
#[cfg(unix)]
pub fn a_byte_of_a_paste_read_again_as_a_key_is_not_the_gesture(kind: ShellKind) {
    let package = Package::built(kind);
    let speech = dialect(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    // The editor's own answer to the character at an empty prompt can be to end the shell, so the
    // person's setting that keeps it is on, as it is in the drives of the detach condition.
    let ready = speech
        .ignore_eof_on
        .map_or_else(|| print_assembled(kind, "kr-ready"), ToOwned::to_owned);
    assert!(session.run(&ready, "kr-ready"));
    let (_enter, _fence) = session.fenced_prompt(5);
    session.ensure_reading();
    session.forget_events();
    session.type_bytes(b"\x1d\x1b[200~x\x04\x1b[201~");
    session
        .serving_after_teardown(&[], "kr-paste-gesture-served")
        .unwrap_or_else(|why| {
            panic!(
                "after the paste with the character: {why}:\n{}",
                session.terminal_output()
            )
        });
    session
        .ended_whole_with_no_decision()
        .unwrap_or_else(|why| {
            panic!(
                "at the end of the paste with the character: {why}:\n{}",
                session.terminal_output()
            )
        });
}

/// KR-REQ-08.48: the end-of-input gesture a person types behind pasted bytes that a failed key
/// sequence gave back is still the gesture.
///
/// Readline gives the keys of a sequence that fails back to its typeahead, the last first, and the
/// key that failed it is one the person typed. A reader that took the marks of the bytes from the
/// wrong places would call that key pasted, and the gesture would be taken for a letter of the
/// paste. The case binds the shape of an answer to a command that does nothing, and a longer
/// sequence that begins with a control character and holds it, sets the shell to keep the
/// end-of-input character from ending it, and at an empty prompt under a fence presses the
/// character-search key, pastes a letter, the control character and the answer's shape, and
/// types the end-of-input character behind the paste: it fails the longer sequence, the keys it
/// gave back run, and the character is read again as typed and is the gesture.
///
/// # Panics
///
/// Panics when no detach is asked for, or the shell stops.
#[cfg(unix)]
pub fn a_gesture_typed_behind_bytes_a_failed_key_sequence_gave_back_is_still_the_gesture(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    let setup = format!(
        "set -o ignoreeof; bind -x '\"\\C-a\\e[?62;22cq\": :'; bind -x '\"\\e[?62;22c\": :'; {}",
        print_assembled(kind, "kr-ready")
    );
    assert!(
        session.run(&setup, "kr-ready"),
        "the line that sets the shell up did not run:\n{}",
        session.terminal_output()
    );
    let (_enter, _fence) = session.fenced_prompt(5);
    session.ensure_reading();
    session.forget_events();
    session.type_bytes(b"\x1d\x1b[200~a\x01\x1b[?62;22c\x1b[201~\x04");
    let (id, event) = session.expect_event("eof_detach", |event| {
        matches!(event, BridgeEvent::EofDetach(_))
    });
    assert!(matches!(event, BridgeEvent::EofDetach(_)));
    session.answer_event(id, detached(attachment_id(1)));
    assert!(
        session.alive(),
        "the gesture typed behind the pasted bytes ended the shell"
    );
}

/// KR-REQ-08.48: the end-of-input gesture a person makes after an Escape sequence the editor does
/// not know is still the gesture.
///
/// The reader looks at what follows an Escape, and it gives back what is no answer for the editor to
/// decode. What it gave back came from the person, so the gesture that was among it is the person's
/// gesture, as it is when the editor reads the same keys from the terminal itself: the reader
/// consumes it with the hint and the shell stays, where a gesture taken for something the editor
/// pushed back would reach the shell as an end of file and end it. The case presses Escape, a
/// closing bracket, which no key sequence of the editors begins with, and the gesture in one write.
///
/// # Panics
///
/// Panics when the reader does not decide the gesture, or the shell ends.
#[cfg(unix)]
pub fn a_gesture_after_an_unknown_escape_sequence_is_still_the_gesture(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));
    let enter = session.next_prompt();
    session.type_bytes(b"\x1b]\x04");
    let (_, consumed) = session.expect_event("pre_eof_consumed", |event| {
        matches!(event, BridgeEvent::PreEofConsumed(_))
    });
    let BridgeEvent::PreEofConsumed(consumed) = consumed else {
        unreachable!()
    };
    assert_eq!(consumed.prompt_generation, enter.prompt_generation);
    assert!(
        session.alive(),
        "the gesture after an unknown Escape sequence ended the shell"
    );
}

/// KR-REQ-08.48: a bracketed paste into a search or a command name a person is typing reaches that
/// text whole, and nothing in it runs.
///
/// A paste begins with an Escape and a bracket, as an answer does, and the editor reads it in a
/// minibuffer of its own: an incremental search, a search by prefix, a named command. The reader
/// looks at what follows the Escape and gives it back, and the minibuffer has to find the paste's
/// opening where it was given back. The case opens each, pastes two lines of which the second prints
/// a word, ends the search with the abort key and runs a line of its own. The word is printed from
/// two pieces, so only a command that ran puts it on the screen, and it never is.
///
/// # Panics
///
/// Panics when a pasted line ran, or the line after them does not run.
#[cfg(unix)]
pub fn a_bracketed_paste_inside_a_minibuffer_is_pasted_whole(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    assert!(session.answered("kr-ready"));
    let _ = session.next_prompt();
    for opening in [&b"\x12"[..], b"\x1bp", b"\x1bx"] {
        let mut keys = opening.to_vec();
        keys.extend_from_slice(b"\x1b[200~true\nprintf '%s%s\\n' kr-ne ver\n\x1b[201~\x07");
        session.type_bytes(&keys);
    }
    assert!(
        session.run("printf '%s%s\\n' kr-after pastes", "kr-afterpastes"),
        "the line typed after the pastes did not run:\n{}",
        session.terminal_output()
    );
    assert!(
        !session.terminal_output().contains("kr-never"),
        "a line pasted into a minibuffer ran:\n{}",
        session.terminal_output()
    );
}

/// Asks the reader for its state until the terminal holds nothing it has not taken, and returns
/// the last answer.
///
/// The reader answers at its next boundary, which is after it has acted on what it was given, and
/// the exchange gives it the step that reaches one. The loop asks again while the terminal still
/// holds what the reader has not taken.
#[cfg(unix)]
fn the_reader_once_it_has_taken_what_the_terminal_holds(
    session: &mut Session,
    mut entry: RootEditorEnterParams,
) -> kr_protocol::root::FenceAcknowledgement {
    let deadline = session.deadline_for(REPLY);
    let mut latest = session.fence_exchange_before(&entry, fence_id(41), deadline.0);
    while !latest.queues.tty_typeahead_drained && !deadline.passed() {
        std::thread::sleep(Duration::from_millis(20));
        entry.prompt_generation = latest.prompt_generation;
        entry.reader_revision = latest.reader_revision;
        latest = session.fence_exchange_before(&entry, fence_id(42), deadline.0);
    }
    latest
}

/// KR-REQ-08.49: a reader whose editor has not yet asked the terminal where the cursor is has not
/// reported itself idle, and does once the terminal has answered and the editor has started.
///
/// The first idle report with clear queues is where a worker proves a fence, and what the host
/// writes behind a fence is behind the reader's claim. The editor reads the reply to its question
/// about the cursor from the same input as every other byte, so an answer written behind a fence
/// proved before the question is read as part of the reply. The terminal here is made slow to
/// answer, so that at the prompt after an empty line the editor is waiting for its reply, and the
/// bridge is read for everything the reader has sent: a report of the reader being idle is the
/// reader claiming the editor is clear when it has not started. The terminal then answers, and the
/// report comes with the editor's line empty.
///
/// How long the editor waits for a held reply is the runtime's to say, and it may give up and start
/// without the reply. A harness that is slow between the question and the check can then see the
/// reader report idle while the answers are still held, and the case fails. So the case can fail for
/// want of speed, and it cannot pass for want of it.
///
/// # Panics
///
/// Panics when the reader has reported itself idle at a prompt whose editor is still waiting for
/// the terminal, or when it never reports once the editor has the answer.
#[cfg(unix)]
pub fn a_reader_reports_itself_idle_only_once_its_editor_has_the_cursors_reply(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    // The first prompt's editor asks where the cursor is once its prompt is drawn. The answers are
    // held below, so the case waits until that question has its answer: the hold then catches the
    // question of the prompt after the empty line and no other.
    assert!(
        session.wait_for_prompt() && session.wait_for_editor_reading(),
        "the shell drew no first prompt to type an empty line at:\n{}",
        session.terminal_output()
    );
    session.forget_events();

    session.hold_terminal_answers();
    session.type_line("");
    let enter = session.next_prompt();
    assert!(
        session.wait_for_prompt() && session.wait_for_editor_reading(),
        "the editor asked the terminal nothing at its next prompt:\n{}",
        session.terminal_output()
    );

    // A frame the reader wrote before the question is on the endpoint already.
    session.take_in_what_has_arrived();
    assert!(
        !session.events.waiting().contains(&"reader_idle"),
        "the reader reported itself idle while its editor waited for the terminal to say where the \
         cursor was: {:?}\n{}",
        session.events.waiting(),
        session.terminal_output()
    );

    session.release_terminal_answers();
    session.expect_event(
        "an idle report from this reader once its editor has the reply",
        |event| {
            matches!(
                event,
                BridgeEvent::ReaderIdle(idle)
                    if idle.prompt_generation == enter.prompt_generation
                        && idle.reader_revision == enter.reader_revision
                        && idle.editor.buffer_empty
            )
        },
    );
}

/// What the module's trace says so far, or nothing when it has written none.
#[cfg(unix)]
fn the_trace(trace: &Path) -> String {
    std::fs::read_to_string(trace).unwrap_or_default()
}

/// KR-REQ-08.48, KR-REQ-08.49: the editor does not start its read until the worker has answered the
/// entry of the read.
///
/// The worker holds every answer it writes for the terminal back from the moment it has applied the
/// entry until it has written the reply to the editor's question about the cursor. It applies the
/// entry on one path and reads the terminal's output on another, in no fixed order, so a read that
/// began before the entry was answered could ask its question first and have it let go by. The case
/// leaves the entry unanswered. The module says in its trace that it is waiting for the answer, and
/// the editor has not asked where the cursor is when it has: a module that started its read at once
/// says nothing of waiting, and its editor asks within moments. The case then answers the entry and
/// expects the editor to ask and the reader to report itself idle over an empty line.
///
/// # Panics
///
/// Panics when the editor asks where the cursor is before the entry is answered, when the module
/// does not say it waits, or when the read does not go on once the entry is answered.
#[cfg(unix)]
pub fn the_editor_does_not_start_its_read_until_the_worker_has_answered_its_entry(kind: ShellKind) {
    let package = Package::built(kind);
    let directory = tempfile::Builder::new()
        .prefix("kr-entry-trace-")
        .tempdir()
        .expect("a directory for the module's trace");
    let trace = directory.path().join("trace");
    let mut session = Session::start_with(
        &package,
        &[("KR_SHELL_BRIDGE_TRACE".to_owned(), told(&trace))],
    );
    session.commands.hold_entries = true;
    session.stepping = false;
    let entry = session.first_prompt();
    assert!(
        session.wait_for_prompt(),
        "the shell drew no prompt:\n{}",
        session.terminal_output()
    );
    // The module has sent the entry. Either it says it waits for the answer, or its editor has
    // begun and asks where the cursor is.
    let deadline = session.deadline_for(REPLY);
    while !the_trace(&trace).contains("waiting for the worker's answer")
        && !session.editor_has_asked_where_the_cursor_is()
        && !deadline.passed()
    {
        session.pump(Duration::from_millis(10));
    }
    assert!(
        !session.editor_has_asked_where_the_cursor_is(),
        "the editor began its read and asked where the cursor is before the worker had answered \
         the entry of the read:\n{}",
        session.terminal_output()
    );
    assert!(
        the_trace(&trace).contains("waiting for the worker's answer"),
        "the module did not say it was waiting for the worker's answer to the entry:\n{}",
        the_trace(&trace)
    );

    session.answer_held_entries();
    assert!(
        session.wait_for_editor_reading(),
        "the editor never began its read once the worker had answered the entry:\n{}",
        session.terminal_output()
    );
    assert!(
        the_trace(&trace).contains(": answered"),
        "the module did not say the worker's answer came:\n{}",
        the_trace(&trace)
    );
    session.stepping = true;
    session.expect_event(
        "an idle report over an empty line from the read that began once its entry was answered",
        |event| {
            matches!(
                event,
                BridgeEvent::ReaderIdle(idle)
                    if idle.prompt_generation == entry.prompt_generation
                        && idle.reader_revision == entry.reader_revision
                        && idle.editor.buffer_empty
            )
        },
    );
}

/// KR-REQ-08.48, KR-REQ-08.49: the host's answers that are already in the terminal's input when a
/// read begins are taken out of it before the editor asks where the cursor is.
///
/// The editor reads the reply to that question from the same input as every other byte, and joins
/// into it every digit that comes ahead of it, so an answer the host wrote before the question is
/// read as part of the reply and leaves the editor with a cursor that is not where it is. The worker
/// holds back every answer it writes after it has applied the entry, but one it had already handed
/// to its writer is on its way to the terminal, and no hold reaches it. The case leaves the entry
/// unanswered, as the case above does, and types two answers into the terminal in the meantime, so
/// they are in the terminal's input before the editor has begun. It then answers the entry and
/// expects the editor to begin, ask and be answered, the reader to report itself idle over a line
/// that is empty, and a line typed afterwards to run as typed. A module that does not wait for the
/// entry's answer begins its editor with the answers still in the input, and the answers are read
/// as part of the reply or typed into the line.
///
/// # Panics
///
/// Panics when the reader does not report itself idle over an empty line, or when a line typed
/// afterwards does not run.
#[cfg(unix)]
pub fn host_answers_in_the_terminal_when_a_read_begins_are_taken_out_before_the_editor_asks(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let directory = tempfile::Builder::new()
        .prefix("kr-stale-trace-")
        .tempdir()
        .expect("a directory for the module's trace");
    let trace = directory.path().join("trace");
    let mut session = Session::start_with(
        &package,
        &[("KR_SHELL_BRIDGE_TRACE".to_owned(), told(&trace))],
    );
    session.commands.hold_entries = true;
    session.stepping = false;
    // The terminal keeps the reply to the editor's question until the case lets it go, so the reply
    // is written after the two answers whenever the editor asks, and a module that starts its
    // editor at once cannot ask before they are in the input and be answered ahead of them.
    session.hold_terminal_answers_after_the_shells_own_cursor_question();
    let entry = session.first_prompt();
    assert!(
        session.wait_for_prompt(),
        "the shell drew no prompt:\n{}",
        session.terminal_output()
    );
    session.type_bytes(b"\x1b[?62;22c\x1b]11;rgb:0000/0000/0000\x07");
    session.answer_held_entries();
    assert!(
        session.wait_for_editor_reading(),
        "the editor never asked where the cursor was once the entry was answered:\n{}",
        session.terminal_output()
    );
    session.release_terminal_answers();
    session.stepping = true;
    session.expect_event(
        "an idle report over an empty line from the read the answers were in the terminal for",
        |event| {
            matches!(
                event,
                BridgeEvent::ReaderIdle(idle)
                    if idle.prompt_generation == entry.prompt_generation
                        && idle.reader_revision == entry.reader_revision
                        && idle.editor.buffer_empty
            )
        },
    );
    let marker = "kr-stale-ok";
    assert!(
        session.run(&print_assembled(kind, marker), marker),
        "a line typed after the answers did not run:\n{}",
        session.terminal_output()
    );
    assert!(
        the_trace(&trace).contains("2 host answers were in the terminal's input"),
        "the module did not take the two answers out of the terminal's input:\n{}",
        the_trace(&trace)
    );
}

/// KR-REQ-08.48: the keys a person typed ahead of a read reach the editor whole and in order, with the
/// host's answers among them taken out.
///
/// Before the editor starts, the module reads what the terminal has delivered, drops the host's
/// answers and gives every other key to the editor's queue, so a read must not lose, reorder or change
/// a key that was typed ahead. The case leaves the entry unanswered and types a line in one write with
/// answers among its keys: one first, one behind the Escape of Alt+b (which starts again at the later
/// Escape), and one behind the End key. The line puts a letter after a word with Alt+b and the End key
/// and runs; it prints the word only if every key reached the editor, in its place.
///
/// # Panics
///
/// Panics when the line does not print the word the keys spell.
#[cfg(unix)]
pub fn keys_typed_ahead_of_a_read_reach_the_editor_whole_and_in_order_among_the_hosts_answers(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.commands.hold_entries = true;
    session.stepping = false;
    session.first_prompt();
    assert!(
        session.wait_for_prompt(),
        "the shell drew no prompt:\n{}",
        session.terminal_output()
    );
    let typed = [
        "\x1b[?62;22c",
        "Write-Output ('kr-ahead-' + '",
        "z",
        "\x1b",
        "\x1b[?62;22c",
        "b",
        "y",
        "\x1b[F",
        "\x1b]11;rgb:0000/0000/0000\x07",
        "')",
        "\r",
    ]
    .concat();
    let start = session.written();
    session.type_bytes(typed.as_bytes());
    session.answer_held_entries();
    let deadline = session.deadline_for(REPLY);
    assert!(
        session.wait_for_output_after_by(start, "kr-ahead-yz", deadline),
        "the keys typed ahead of the read did not spell \"kr-ahead-yz\":\n{}",
        shown_since(&session, start)
    );
}

/// KR-REQ-08.48: the keys of an answer the module was reading when its read failed reach the
/// editor, and the answer is still taken out.
///
/// Before the editor starts, the module reads the keys the terminal has delivered, and it takes an
/// Escape and the introducer behind it before it reads the rest of the answer. A read that fails
/// part way must not lose the keys it has already taken: they are the person's, as far as the
/// module can tell. The case replaces the module's reader of the rest of an answer with one that
/// fails on its first call and then does what it did, leaves the entry unanswered, and types a line
/// with an answer in the middle of it. The first read fails, so the answer reaches the editor with
/// its Escape and its bracket, and the module's chord for the bracket takes it out as the editor
/// meets it; the line prints its word only if that happened and no key was lost. A module that
/// loses the two keys leaves the rest of the answer in the line.
///
/// # Panics
///
/// Panics when the line does not print the word the keys spell.
#[cfg(unix)]
pub fn the_keys_of_an_answer_the_drain_was_reading_when_it_failed_reach_the_editor(
    kind: ShellKind,
) {
    // Runs after the package's entry: the first call of the module's reader of an answer fails,
    // the others are the module's own.
    const FAILING_ONCE: &str = r#"& (Get-Module KalaReach.ShellBridge) {
    $script:RealSkipReply = (Get-Command Skip-KrReply -CommandType Function).ScriptBlock
    $script:SkipReplyFailures = 1
    Set-Item function:script:Skip-KrReply -Value {
        param([char]$Introducer, [scriptblock]$Waiting, [scriptblock]$Read, [scriptblock]$Restore)
        if ($script:SkipReplyFailures -gt 0) {
            $script:SkipReplyFailures--
            throw 'the read of the answer failed'
        }
        & $script:RealSkipReply @PSBoundParameters
    }
}
"#;
    let package = Package::built(kind);
    let mut session = Session::start_with_profile(
        &package,
        Profile {
            after_entry: FAILING_ONCE,
            ..Profile::ORDINARY
        },
    );
    session.commands.hold_entries = true;
    session.stepping = false;
    session.first_prompt();
    assert!(
        session.wait_for_prompt(),
        "the shell drew no prompt:\n{}",
        session.terminal_output()
    );
    let typed = ["Write-Output ('kr-lost-' + 'a", "\x1b[?62;22c", "b')", "\r"].concat();
    let start = session.written();
    session.type_bytes(typed.as_bytes());
    session.answer_held_entries();
    let deadline = session.deadline_for(REPLY);
    assert!(
        session.wait_for_output_after_by(start, "kr-lost-ab", deadline),
        "the keys typed ahead of the read did not spell \"kr-lost-ab\":\n{}",
        shown_since(&session, start)
    );
}

/// KR-REQ-08.48: an answer behind one that was cut short is taken out before the editor starts.
///
/// The module reads the keys the terminal has delivered, and a run that turns out to be no answer
/// gives its Escape and its bracket to the editor. The keys it read after them are looked at again
/// from the first, because one of them may be the Escape of an answer of its own: a control
/// sequence cut short by the Escape of the next one is the case. The case types a line in which a
/// control sequence is cut short by an answer, and expects the module to say in its trace that it
/// took one answer out of the input, and the line to print the word the other keys spell.
///
/// # Panics
///
/// Panics when the module does not take the second answer out or the line does not print its word.
#[cfg(unix)]
pub fn an_answer_behind_one_that_was_cut_short_is_taken_out_before_the_editor_starts(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let directory = tempfile::Builder::new()
        .prefix("kr-cut-trace-")
        .tempdir()
        .expect("a directory for the module's trace");
    let trace = directory.path().join("trace");
    let mut session = Session::start_with(
        &package,
        &[("KR_SHELL_BRIDGE_TRACE".to_owned(), told(&trace))],
    );
    session.commands.hold_entries = true;
    session.stepping = false;
    session.first_prompt();
    assert!(
        session.wait_for_prompt(),
        "the shell drew no prompt:\n{}",
        session.terminal_output()
    );
    let typed = [
        "Write-Output ('kr-cut-' + 'a",
        "\x1b[?",
        "\x1b[?62;22c",
        "~b')",
        "\r",
    ]
    .concat();
    let start = session.written();
    session.type_bytes(typed.as_bytes());
    session.answer_held_entries();
    let deadline = session.deadline_for(REPLY);
    assert!(
        session.wait_for_output_after_by(start, "kr-cut-ab", deadline),
        "the keys typed ahead of the read did not spell \"kr-cut-ab\":\n{}",
        shown_since(&session, start)
    );
    assert!(
        the_trace(&trace).contains("1 host answers were in the terminal's input"),
        "the module did not take the answer behind the one that was cut short out of the terminal's \
         input:\n{}",
        the_trace(&trace)
    );
}

/// KR-REQ-08.48: a chord the person bound on an Escape runs when its keys were typed ahead of a read.
///
/// The module takes an Escape and the key behind it for a host's answer only where the chord is its
/// own: it binds `Escape,[`, `Escape,]` and `Escape,P` where nothing is bound, and a person's binding
/// of one of them is theirs. The case binds `Escape,P` to a handler that inserts a line ending in a
/// comment, leaves the entry unanswered, types the chord, a backslash (which ends a device control
/// string, so the three keys are a whole answer by their shape) and a return, and expects the line to
/// run: a module that took the Escape and the P for the start of an answer would drop the chord and
/// run an empty line.
///
/// # Panics
///
/// Panics when the person's handler does not run.
#[cfg(unix)]
pub fn a_chord_the_person_bound_on_an_escape_runs_when_it_was_typed_ahead_of_a_read(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let mut session = Session::start_with_profile(
        &package,
        Profile {
            after_configuration: "Set-PSReadLineKeyHandler -Chord 'Escape,P' -ScriptBlock { \
                [Microsoft.PowerShell.PSConsoleReadLine]::Insert(\
                'Write-Output (''kr-cho'' + ''rd'') # ') }\n",
            ..Profile::ORDINARY
        },
    );
    session.commands.hold_entries = true;
    session.stepping = false;
    session.first_prompt();
    assert!(
        session.wait_for_prompt(),
        "the shell drew no prompt:\n{}",
        session.terminal_output()
    );
    let start = session.written();
    session.type_bytes(b"\x1bP\\\r");
    session.answer_held_entries();
    let deadline = session.deadline_for(REPLY);
    assert!(
        session.wait_for_output_after_by(start, "kr-chord", deadline),
        "the person's handler on Escape,P did not run when its keys were typed ahead:\n{}",
        shown_since(&session, start)
    );
}

/// KR-REQ-08.48: a chord the person bound behind another key runs when its keys were typed ahead of
/// a read.
///
/// The key behind the first key of a chord is the chord's second key, whatever it is, and the
/// editor's: an Escape there is not the start of a host's answer. The case binds `Ctrl+x,Escape` to
/// a handler that inserts a line ending in a comment, leaves the entry unanswered, types `Ctrl+x`,
/// an Escape, a `P`, a backslash (which ends a device control string, so the three keys behind the
/// first are a whole answer by their shape) and a return, and expects the line to run: a module that
/// took the Escape for the start of an answer would drop it, and the chord with it.
///
/// # Panics
///
/// Panics when the person's handler does not run.
#[cfg(unix)]
pub fn a_chord_the_person_bound_behind_another_key_runs_when_it_was_typed_ahead_of_a_read(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let mut session = Session::start_with_profile(
        &package,
        Profile {
            after_configuration: "Set-PSReadLineKeyHandler -Chord 'Ctrl+x,Escape' -ScriptBlock { \
                [Microsoft.PowerShell.PSConsoleReadLine]::Insert(\
                'Write-Output (''kr-cho'' + ''rd'') # ') }\n",
            ..Profile::ORDINARY
        },
    );
    session.commands.hold_entries = true;
    session.stepping = false;
    session.first_prompt();
    assert!(
        session.wait_for_prompt(),
        "the shell drew no prompt:\n{}",
        session.terminal_output()
    );
    let start = session.written();
    session.type_bytes(b"\x18\x1bP\\\r");
    session.answer_held_entries();
    let deadline = session.deadline_for(REPLY);
    assert!(
        session.wait_for_output_after_by(start, "kr-chord", deadline),
        "the person's handler on Ctrl+x,Escape did not run when its keys were typed ahead:\n{}",
        shown_since(&session, start)
    );
}

/// KR-REQ-08.48: a chord the person binds after the module has bound its own runs when its keys were
/// typed ahead of a read.
///
/// The module binds `Escape,[`, `Escape,]` and `Escape,P` where nothing is bound when it starts, and
/// takes a host's answer out of the keys typed ahead only where those chords are still its own. A
/// person can bind a chord later, at the prompt, and the module reads the editor's tables at each
/// read for that reason. The case runs a line that binds `Escape,P` to a handler of the person's
/// own, leaves the entry of the next read unanswered, types the chord, a backslash (which ends a
/// device control string, so the three keys are a whole answer by their shape) and a return, and
/// expects the handler to have run: a module that went by the chords it bound at the start would
/// drop the three keys and run an empty line.
///
/// # Panics
///
/// Panics when the person's handler does not run.
#[cfg(unix)]
pub fn a_chord_the_person_binds_after_the_first_prompt_runs_when_it_was_typed_ahead_of_a_read(
    kind: ShellKind,
) {
    let handler = "Set-PSReadLineKeyHandler -Chord 'Escape,P' -ScriptBlock { \
        [Microsoft.PowerShell.PSConsoleReadLine]::Insert('Write-Output (''kr-lat'' + ''e'') # ') }";
    keys_typed_ahead_of_a_read_after_a_binding_made_at_the_prompt(
        kind,
        handler,
        "kr-late",
        "the person's handler on Escape,P, bound after the first prompt, did not run when its keys \
         were typed ahead",
    );
}

/// KR-REQ-08.48: an Escape the person binds alone after the module has bound its chords is theirs,
/// and the keys typed ahead of a read after it are the line they spell.
///
/// The chords the module binds stand behind the Escape key, which the editor keeps as the first key
/// of a chord. A person who binds the Escape key to an operation of their own at the prompt makes
/// the keys behind it a new line, as the Windows edit mode does, and the module reads the editor's
/// tables at each read for that reason. The case binds the Escape key to reverting the line, leaves
/// the entry of the next read unanswered and types an Escape, a `P`, a backslash and a return; the
/// editor has to meet the `P` and the backslash as the line it runs, which the shell says it does
/// not know as a command, where a module that went by the chords it bound at the start would take
/// the three keys for an answer and run an empty line.
///
/// # Panics
///
/// Panics when the shell does not run the line the keys spell.
#[cfg(unix)]
pub fn an_escape_the_person_binds_after_the_first_prompt_leaves_the_keys_behind_it_theirs(
    kind: ShellKind,
) {
    keys_typed_ahead_of_a_read_after_a_binding_made_at_the_prompt(
        kind,
        "Set-PSReadLineKeyHandler -Chord 'Escape' -Function RevertLine",
        "The term 'P\\' is not recognized",
        "the keys typed behind an Escape the person bound after the first prompt did not run as the \
         line they spell",
    );
}

/// Binds with `binding` in a line the person runs at the prompt, then types an Escape, a `P`, a
/// backslash and a return into the read that follows the next one, whose entry is left unanswered,
/// and waits for `expected` to be shown.
#[cfg(unix)]
fn keys_typed_ahead_of_a_read_after_a_binding_made_at_the_prompt(
    kind: ShellKind,
    binding: &str,
    expected: &str,
    complaint: &str,
) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.stepping = false;
    let bound = format!("{binding}; {}", print_assembled(kind, "kr-bound"));
    assert!(
        session.run(&bound, "kr-bound"),
        "the line that binds did not run:\n{}",
        session.terminal_output()
    );
    // The read that follows the binding has started and been answered before the next entry is
    // left unanswered, so that it is the entry of the read after it that is.
    assert!(
        session.wait_for_prompt() && session.wait_for_editor_reading(),
        "the editor did not start the read after the binding:\n{}",
        session.terminal_output()
    );
    session.commands.hold_entries = true;
    let entries = session.commands.entries.len();
    assert!(
        session.answered("kr-after"),
        "a line did not run after the binding:\n{}",
        session.terminal_output()
    );
    assert!(
        session.wait_for_prompt(),
        "the shell drew no prompt after the line:\n{}",
        session.terminal_output()
    );
    // The prompt is drawn before the module sends the read's entry, and the module does some work
    // of its own in between. The keys are typed ahead of a read the module holds at its entry,
    // so they are typed once that entry has arrived.
    session.until("the entry of the read after the line", |commands| {
        commands.entries.len() > entries
    });
    let start = session.written();
    session.type_bytes(b"\x1bP\\\r");
    session.answer_held_entries();
    let deadline = session.deadline_for(REPLY);
    assert!(
        session.wait_for_output_after_by(start, expected, deadline),
        "{complaint}:\n{}",
        shown_since(&session, start)
    );
}

/// A `stty` that, once, says what mode the terminal is in while it runs, waits until the case lets
/// it go, then does what `stty` does. The case puts the directory it lives in first on the shell's path
/// and arms it with a file; the pipe is what it waits on, so no time is measured.
#[cfg(unix)]
const HELD_STTY: &str = "#!/bin/sh\n\
    if [ -e \"$KR_STTY_HOLD/armed\" ] && mv \"$KR_STTY_HOLD/armed\" \"$KR_STTY_HOLD/used\" 2>/dev/null; then\n\
    settings=$(stty -a </dev/tty 2>/dev/null | tr '\\n' ' ')\n\
    case \" $settings \" in *\" -icanon \"*) mode=raw ;; *) mode=line ;; esac\n\
    printf 'kr-stty-held-%s\\n' \"$mode\" > /dev/tty\n\
    read -r _ < \"$KR_STTY_HOLD/release\"\n\
    fi\n\
    PATH=${PATH#*:}\n\
    exec stty \"$@\"\n";

/// KR-REQ-08.48: the keys a person types while the module asks the terminal for its settings are
/// theirs, whole, and a return among them is accepted.
///
/// Between drawing the prompt and sending the read's entry the module runs `stty` once, to learn
/// the terminal's end-of-file character. The runtime puts the terminal in line mode for as long as
/// a program runs that has the terminal for any of its three standard streams, and a terminal in
/// line mode shows every key itself and hands the editor a line feed where the return was, which
/// the editor does not take for Enter. The case puts a `stty` first on the shell's path that
/// says what mode the terminal is in while it runs and waits, runs a line so that the next read is
/// the one it waits in, expects the terminal to be raw, types a line and a return while it waits,
/// lets it go, and expects the line to run.
///
/// # Panics
///
/// Panics when the line the keys spell does not run.
#[cfg(unix)]
pub fn keys_typed_while_the_module_asks_the_terminal_for_its_settings_are_the_persons_own(
    kind: ShellKind,
) {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = tempfile::Builder::new()
        .prefix("kr-stty-")
        .tempdir()
        .expect("a directory for the held program");
    let programs = fixture.path().join("bin");
    let hold = fixture.path().join("hold");
    std::fs::create_dir(&programs).expect("a directory for the held program's path");
    std::fs::create_dir(&hold).expect("a directory for the held program's state");
    let release = hold.join("release");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&release)
            .status()
            .expect("mkfifo starts")
            .success(),
        "no pipe to let the held program go on"
    );
    // Opened for reading and writing here, before the program is started, so that neither side
    // waits for the other to open it: the program opens it to read, and a byte written here waits
    // in it until the program reads.
    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&release)
        .expect("the pipe opens");
    let program = programs.join("stty");
    std::fs::write(&program, HELD_STTY).expect("the held program");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
        .expect("an executable held program");

    let package = Package::built(kind);
    let path = format!(
        "{}:{}",
        programs.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut session = Session::start_with(
        &package,
        &[
            ("PATH".to_owned(), path),
            ("KR_STTY_HOLD".to_owned(), hold.display().to_string()),
        ],
    );
    session.first_prompt();
    session.stepping = false;
    // The program waits in the read that follows the next line.
    std::fs::write(hold.join("armed"), b"").expect("the file that arms the held program");
    // Counted from before the line runs: the program can say it is running before the line's own
    // check has returned.
    let waiting = session.written();
    assert!(
        session.answered("kr-armed"),
        "a line did not run:\n{}",
        session.terminal_output()
    );
    let deadline = session.deadline_for(REPLY);
    assert!(
        session.wait_for_output_after_by(waiting, "kr-stty-held-", deadline),
        "the module never asked the terminal for its settings:\n{}",
        shown_since(&session, waiting)
    );
    assert!(
        shown_since(&session, waiting).contains("kr-stty-held-raw"),
        "the terminal was in line mode while the module asked it for its settings:\n{}",
        shown_since(&session, waiting)
    );

    let start = session.written();
    session.type_bytes(format!("{}\r", print_assembled(kind, "kr-held")).as_bytes());
    pipe.write_all(b"\n").expect("the held program is let go");
    let deadline = session.deadline_for(REPLY);
    assert!(
        session.wait_for_output_after_by(start, "kr-held", deadline),
        "the line typed while the module asked the terminal for its settings did not run:\n{}",
        shown_since(&session, start)
    );
}

/// A `stty` for a case that must never run it: it leaves a file where the case looks, then does
/// what `stty` does.
#[cfg(unix)]
const MARKING_STTY: &str = "#!/bin/sh\n\
    : > \"$KR_STTY_RAN\"\n\
    if [ -x /bin/stty ]; then exec /bin/stty \"$@\"; fi\n\
    exec /usr/bin/stty \"$@\"\n";

/// KR-REQ-07.73: the module never runs a program of the shell's current directory to read the
/// terminal's settings, whatever the path holds.
///
/// An empty entry of the path (a leading or a trailing colon, or two together) is the current
/// directory to a POSIX shell, and a lookup that skips it is the one a command line here makes.
/// The case puts a `stty` that leaves a file where the case looks in the directory the shell is
/// in, gives the shell a path with an empty entry at each end, lets the module read the terminal's
/// settings for the read that follows, and expects the file not to be there.
///
/// # Panics
///
/// Panics when the program of the current directory ran.
#[cfg(unix)]
pub fn a_program_of_the_current_directory_is_not_run_for_an_empty_entry_of_the_path(
    kind: ShellKind,
) {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = tempfile::Builder::new()
        .prefix("kr-stty-")
        .tempdir()
        .expect("a directory for the program");
    let here = fixture.path().join("here");
    std::fs::create_dir(&here).expect("a directory for the shell to stand in");
    let ran = fixture.path().join("ran");
    let program = here.join("stty");
    std::fs::write(&program, MARKING_STTY).expect("the program of the current directory");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
        .expect("an executable program");

    let package = Package::built(kind);
    let path = format!(":{}:", std::env::var("PATH").unwrap_or_default());
    let mut session = Session::start_with(
        &package,
        &[
            ("PATH".to_owned(), path),
            ("KR_STTY_RAN".to_owned(), ran.display().to_string()),
        ],
    );
    session.first_prompt();
    session.stepping = false;
    let entries = session.commands.entries.len();
    let moving = format!(
        "Set-Location '{}'; {}",
        here.display(),
        print_assembled(kind, "kr-moved")
    );
    assert!(
        session.run(&moving, "kr-moved"),
        "the line that moves the shell did not run:\n{}",
        session.terminal_output()
    );
    // The entry of the read that follows is sent after the module has read the settings.
    session.until("the entry of the read after the line", |commands| {
        commands.entries.len() > entries
    });
    assert!(
        !ran.exists(),
        "the module ran the program of the shell's current directory for an empty entry of the path"
    );
}

/// KR-REQ-08.48: in the Windows edit mode the keys typed ahead of a read are the person's, whatever
/// follows an Escape in them.
///
/// The module binds the chords that drop a host's answer only in the Emacs edit mode, where an Escape
/// begins a chord. In the Windows edit mode an Escape reverts the line, and the keys behind it are a
/// new line. The case sets that mode, leaves the entry unanswered and types an Escape, a `P`, a
/// backslash (`ESC P \` is a whole device control string by its shape) and a return. The editor has
/// to meet the `P` and the backslash as the line it runs, which the shell says it does not know as a
/// command; a module that took the three keys for an answer would run an empty line and say nothing.
/// (A control sequence cannot stand in for the answer here: the runtime reads one that has no
/// parameters as a function key of the terminal before any editor or module meets it.)
///
/// # Panics
///
/// Panics when the shell does not run the line the keys spell.
#[cfg(unix)]
pub fn keys_typed_ahead_of_a_read_in_the_windows_edit_mode_are_the_persons_own(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start_with_profile(
        &package,
        Profile {
            after_configuration: "Set-PSReadLineOption -EditMode Windows\n",
            ..Profile::ORDINARY
        },
    );
    session.commands.hold_entries = true;
    session.stepping = false;
    session.first_prompt();
    assert!(
        session.wait_for_prompt(),
        "the shell drew no prompt:\n{}",
        session.terminal_output()
    );
    let start = session.written();
    session.type_bytes(b"\x1bP\\\r");
    session.answer_held_entries();
    let deadline = session.deadline_for(REPLY);
    assert!(
        session.wait_for_output_after_by(start, "The term 'P\\' is not recognized", deadline),
        "the keys typed behind an Escape in the Windows edit mode did not run as the line they spell:\n{}",
        shown_since(&session, start)
    );
}

/// KR-REQ-08.49: a read that the module queues no key for reports itself idle only once its editor
/// has the cursor's reply.
///
/// The module queues a key of its own at the start of a read, and the reader reports itself idle
/// from that key's handler, which runs after the editor has asked where the cursor is and been
/// answered. It queues none where that would change what the person's keys do: one is the read
/// after a line accepted with accept-and-get-next, where the editor loads the next history entry and
/// carries the person's search over, and any key it runs ahead of the person's ends the search. A
/// report from such a read before the editor has the reply ends the worker's hold on the answers it
/// writes for the terminal early, and lets a fence be proved before the editor has asked. The case
/// accepts a recalled line with accept-and-get-next, waits for the editor of the next prompt to have
/// asked and been answered, and expects the reader to have reported nothing: its entry's report
/// would have been on the endpoint before the editor asked. It then types a key, as a person does,
/// and expects the report from that key.
///
/// # Panics
///
/// Panics when the reader has reported itself idle before any key has run in such a read, or when it
/// never reports once a key has run.
#[cfg(unix)]
pub fn a_read_with_no_key_of_the_modules_own_reports_idle_only_once_its_editor_has_the_cursors_reply(
    kind: ShellKind,
) {
    // Control characters, which no runtime splits or reads as the start of a sequence.
    const PREVIOUS_HISTORY: &[u8] = b"\x10";
    const ACCEPT_AND_GET_NEXT: &[u8] = b"\x0f";
    const FORWARD_CHARACTER: &[u8] = b"\x06";
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.stepping = false;
    for entry in ["aaa1", "bbb2"] {
        let marker = format!("kr-idle-{entry}");
        assert!(
            session.run(&print_assembled(kind, &marker), &marker),
            "a line of the history did not run:\n{}",
            session.terminal_output()
        );
    }
    assert!(
        session.wait_for_prompt() && session.wait_for_editor_reading(),
        "the shell drew no prompt to recall a line at:\n{}",
        session.terminal_output()
    );
    // Two steps back in the history recall the first line, and accepting it with accept-and-get-next
    // loads the second at the next prompt.
    let recalled = session.written();
    session.type_bytes(PREVIOUS_HISTORY);
    session.type_bytes(PREVIOUS_HISTORY);
    // The editor draws a line in colours, so the recalled line is not one run of text: the end of
    // its first entry is.
    assert!(
        session.drew_after(recalled, "aa1'", REPLY).was_drawn(),
        "the history did not recall the first line:\n{}",
        shown_since(&session, recalled)
    );
    session.forget_events();
    session.mark = session.written();
    session.type_bytes(ACCEPT_AND_GET_NEXT);
    let enter = session.next_prompt();
    assert!(
        session.wait_for_prompt() && session.wait_for_editor_reading(),
        "the editor asked the terminal nothing at the prompt after the recalled line:\n{}",
        session.terminal_output()
    );
    // A report from the read's entry comes before the editor asks, so it is on the endpoint by now.
    session.take_in_what_has_arrived();
    assert!(
        !session.events.waiting().contains(&"reader_idle"),
        "the reader reported itself idle before any key had run in a read the module queued no key \
         for, which is before its editor had the reply to its question about the cursor: \
         {:?}\n{}",
        session.events.waiting(),
        session.terminal_output()
    );

    session.type_bytes(FORWARD_CHARACTER);
    session.expect_event(
        "an idle report from the key the person pressed once the editor has the reply",
        |event| {
            matches!(
                event,
                BridgeEvent::ReaderIdle(idle)
                    if idle.prompt_generation == enter.prompt_generation
                        && idle.reader_revision == enter.reader_revision
            )
        },
    );
}

/// KR-REQ-08.48, KR-REQ-08.49: taking a host's answer out of the editor's keys never waits for the
/// terminal to send more, so half a character behind the start of an answer does not hold the
/// reader.
///
/// The runtime reads the terminal in chunks and keeps the first byte of a character that a chunk
/// ends inside until the rest of it comes. That byte is no key, and a read of the next key waits
/// for the rest of the character. The case types an Escape, a capital P and a letter, which begin a
/// device control string, and the first byte of a two-byte character behind them, and expects the
/// reader to report itself idle with nothing more sent: it gives the reader no step, because a step
/// is a key and would end a wait. It then types the rest of the character and expects it in the line,
/// since nothing took it for part of the answer.
///
/// # Panics
///
/// Panics when the reader reports nothing once the terminal has delivered the half character, or
/// when the character the person finishes is not in the line.
#[cfg(unix)]
pub fn a_dropped_answer_does_not_wait_for_the_rest_of_a_character_the_terminal_has_half_delivered(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    let first = session.first_prompt();
    // No step is given until the last exchange: a step is a key, and it would end the wait of a
    // drop that waited for the rest of the character.
    session.stepping = false;
    assert!(
        session.wait_for_prompt() && session.wait_for_editor_reading(),
        "the shell drew no prompt to type behind:\n{}",
        session.terminal_output()
    );
    session.expect_event(
        "the idle report of the read the answer is typed into",
        |event| {
            matches!(
                event,
                BridgeEvent::ReaderIdle(idle) if idle.prompt_generation == first.prompt_generation
            )
        },
    );
    session.type_bytes(b"\x1bPx\xc3");
    session.expect_event(
        "an idle report once the editor has taken what the terminal delivered",
        |event| {
            matches!(
                event,
                BridgeEvent::ReaderIdle(idle)
                    if idle.prompt_generation == first.prompt_generation
                        && idle.editor.buffer_empty
            )
        },
    );
    session.type_bytes(b"\xa9");
    session.stepping = true;
    let latest = the_reader_once_it_has_taken_what_the_terminal_holds(&mut session, first);
    assert!(
        !latest.editor.buffer_empty,
        "the end of a character the person typed was taken for the end of an answer:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-07.37: a history search the person is in the middle of goes on at the next prompt after
/// the line it recalled is accepted with the editor's accept-and-get-next, as it does without the
/// package.
///
/// The editor loads the history entry after the one it ran and keeps the search's chain from the
/// line that ran, and only then: the next search key continues from the loaded entry. Any key the
/// editor runs ahead of the person's ends the chain, so a package that queues a key of its own at the
/// start of a read must queue none where the chain is carried. The case recalls an older line with
/// a search from a typed prefix, accepts it with Ctrl+o, and presses the search key at the next
/// prompt. The chain takes it back to the older line; a chain that was ended searches again from the
/// line the editor loaded, which is the one after it.
///
/// # Panics
///
/// Panics when a line does not run, or when the search at the second prompt does not go back to the
/// older line.
#[cfg(unix)]
pub fn a_history_search_goes_on_across_a_line_accepted_with_accept_and_get_next(kind: ShellKind) {
    // Control characters, which no runtime splits or reads as the start of a sequence.
    const SEARCH_BACKWARD: &[u8] = b"\x0c";
    const ACCEPT_AND_GET_NEXT: &[u8] = b"\x0f";
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    // The case gives the reader no step. A step is a key, and any key the editor runs between the
    // search and the acceptance, or ahead of the next search, ends the very thing the case looks
    // at: the editor forgets the recalled line's place in the history after the first, and the
    // search chain after the second.
    session.stepping = false;
    let bound = "kr-chain-bound";
    assert!(
        session.run(
            &format!(
                "Set-PSReadLineKeyHandler -Chord Ctrl+l -Function HistorySearchBackward; {}",
                print_assembled(kind, bound)
            ),
            bound
        ),
        "the search key was not bound:\n{}",
        session.terminal_output()
    );
    for entry in ["aaa1", "bbb2", "aaa3", "ccc4"] {
        let marker = format!("kr-chain-{entry}");
        assert!(
            session.run(&print_assembled(kind, &marker), &marker),
            "a line of the history did not run:\n{}",
            session.terminal_output()
        );
    }

    // The first and the third entry begin with the prefix typed here, and the search recalls the
    // later of them, the third.
    assert!(
        session.wait_for_prompt() && session.wait_for_editor_reading(),
        "the shell drew no prompt to search at:\n{}",
        session.terminal_output()
    );
    let searched = session.written();
    session.type_bytes(b"Write-Output ('kr-chain-' + 'a");
    session.type_bytes(SEARCH_BACKWARD);
    // The editor draws the prefix a search started from in a colour of its own, so the recalled
    // line is not one run of text: the end of its third entry is.
    assert!(
        session.drew_after(searched, "aa3'", REPLY).was_drawn(),
        "the search did not recall the third entry:\n{}",
        shown_since(&session, searched)
    );

    // Accepting it loads the entry after it, the fourth, at the next prompt.
    session.mark = session.written();
    let accepted = session.written();
    session.type_bytes(ACCEPT_AND_GET_NEXT);
    let deadline = session.deadline_for(REPLY);
    assert!(
        session.wait_for_output_after_by(accepted, "kr-chain-aaa3", deadline),
        "the recalled line did not run:\n{}",
        session.terminal_output()
    );
    assert!(
        session.wait_for_prompt() && session.wait_for_editor_reading(),
        "the shell drew no prompt after the recalled line:\n{}",
        session.terminal_output()
    );

    assert!(
        session.drew_after(accepted, "ccc4", REPLY).was_drawn(),
        "the editor did not load the entry after the accepted line at the next prompt:\n{}",
        shown_since(&session, accepted)
    );
    session.mark = session.written();
    let continued = session.written();
    session.type_bytes(SEARCH_BACKWARD);
    session.type_bytes(b"\r");
    assert!(
        session.wait_for_prompt(),
        "the line the search recalled did not run:\n{}",
        session.terminal_output()
    );
    let shown = shown_since(&session, continued);
    assert!(
        shown.contains("kr-chain-aaa3") && !shown.contains("kr-chain-ccc4"),
        "the search at the next prompt began again from the line the editor loaded, so something \
         ended the chain the accepted line left:\n{shown}"
    );
}

/// What the terminal has shown since `start`.
#[cfg(unix)]
fn shown_since(session: &Session, start: usize) -> String {
    let output = session.output.lock().expect("the output lock");
    String::from_utf8_lossy(&output[start.min(output.len())..]).into_owned()
}

/// Types `unread` into the terminal of an idle reader that is stopped, asks it for its queues, and
/// expects it to say they are not drained. Then types `completion`, which the reader needs to take
/// what it has, and expects it to say they are.
///
/// Returns the editor's state in the reader's idle report before anything was typed and in the
/// last answer, which is the one that says the queues are drained, so a case whose bytes should
/// never reach the buffer can say what the buffer held.
#[cfg(unix)]
fn unread_input_is_not_drained(
    kind: ShellKind,
    unread: &[u8],
    completion: &[u8],
) -> (EditorState, EditorState) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    let first = session.first_prompt();
    let (_, idle) = session.expect_event(
        "an idle report from this reader with its queues clear",
        |event| {
            matches!(
                event,
                BridgeEvent::ReaderIdle(idle)
                    if idle.prompt_generation == first.prompt_generation
                        && idle.reader_revision == first.reader_revision
                        && idle.editor.buffer_empty
                        && idle.snapshot.queued_keys == U64::new(0)
                        && idle.snapshot.pending_bytes == U64::new(0)
            )
        },
    );

    // An editor that asks where the cursor is once its prompt is drawn reads the reply from the
    // same input as its keys, a byte at a time. What is typed before it has the reply is taken for
    // part of it, or the reply is taken for keys. A person types after the reply, as `type_line`
    // does, and so does this.
    if dialect(kind).types_at_the_prompt {
        assert!(
            session.wait_for_prompt(),
            "the shell drew no prompt to put {unread:?} behind:\n{}",
            session.terminal_output()
        );
        assert!(
            session.wait_for_editor_reading(),
            "the editor never asked where the cursor was after the prompt, to put {unread:?} \
             behind:\n{}",
            session.terminal_output()
        );
    }

    signal_the_shell(&session, "STOP");
    // A reader that answers only when it steps meets its mailbox at the step a person gives it by
    // typing, so the answers wait behind that step and not ahead of it.
    session.type_behind_the_step(unread);
    let id = session.ask_after_the_step(WorkerRequest::Fence(RootEditorFenceParams {
        session_id: session.session_id,
        fence_id: fence_id(31),
        prompt_generation: first.prompt_generation,
        reader_revision: first.reader_revision,
        deadline_ms: FENCE_EXCHANGE_TIMEOUT,
        cause: FenceCause::EditorEntry,
    }));
    signal_the_shell(&session, "CONT");
    let BridgeAnswer::Fence(RootEditorFenceResult::Acknowledged(asked)) =
        session.answer_after_the_step(id)
    else {
        panic!("the reader did not acknowledge the fence it was asked for")
    };
    assert!(
        !asked.queues.tty_typeahead_drained,
        "the reader said its terminal's typeahead was drained with {unread:?} unread: {:?}",
        asked.queues
    );
    session.type_bytes(completion);

    // Taken, the answer is no longer typeahead: the reader that reported it unread reports the
    // queues drained once it has read it.
    let deadline = session.deadline_for(REPLY);
    let mut entry = first;
    let mut latest = asked;
    while !latest.queues.tty_typeahead_drained && !deadline.passed() {
        std::thread::sleep(Duration::from_millis(20));
        entry.prompt_generation = latest.prompt_generation;
        entry.reader_revision = latest.reader_revision;
        latest = session.fence_exchange_before(&entry, fence_id(32), deadline.0);
    }
    assert!(
        latest.queues.tty_typeahead_drained,
        "the reader still reports typeahead after it has had the answer: {:?}\n{}",
        latest.queues,
        session.terminal_output()
    );
    let BridgeEvent::ReaderIdle(idle) = idle else {
        unreachable!("the event was accepted as an idle report")
    };
    (idle.editor, latest.editor)
}

/// KR-REQ-07.34, KR-REQ-07.35: the reader's own boundaries, and the fence its state proves.
pub fn the_reader_reports_its_boundaries_and_proves_its_own_state(kind: ShellKind) {
    let package = Package::built(kind);
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

    // Startup drawing and terminal queries must settle before the reader's key wait is idle, and
    // what says they have is the reader's own report rather than a clock: the bridge writes one
    // when the reader has nothing left to read, so the report that names this reader with its
    // queues clear is the drain finishing. Polling the exchange instead would settle by wall time
    // and a loaded host would run out of it while the reader was still honestly reporting bytes
    // the startup entry had left.
    session.expect_event(
        "an idle report from this reader with its queues clear",
        |event| {
            matches!(
                event,
                BridgeEvent::ReaderIdle(idle)
                    if idle.prompt_generation == first.prompt_generation
                        && idle.reader_revision == first.reader_revision
                        && idle.editor.buffer_empty
                        && idle.snapshot.queued_keys == U64::new(0)
                        && idle.snapshot.pending_bytes == U64::new(0)
            )
        },
    );

    // The fence rests on the reader's own atomic read: the queues, the buffer and the invoking
    // sequence together, at one instant. The reader reaches that instant once the bytes its own
    // startup left behind have drained, so this asks again until the state it reports has settled.
    // One deadline covers every exchange and every wait between them.
    let deadline = session.deadline_for(REPLY);
    let mut acknowledgement = session.fence_exchange_before(&first, fence_id(1), deadline.0);
    while (!acknowledgement.editor.buffer_empty
        || acknowledgement.snapshot.queued_keys != U64::new(0)
        || acknowledgement.snapshot.pending_bytes != U64::new(0))
        && !deadline.passed()
    {
        std::thread::sleep(deadline.left().min(Duration::from_millis(10)));
        if deadline.passed() {
            break;
        }
        acknowledgement = session.fence_exchange_before(&first, fence_id(1), deadline.0);
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
    let running = session.submit(&print_assembled(kind, "kr-boundary-ok"), "kr-boundary-ok");
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
    assert!(session.finished(&running));

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
        assert!(session.run(close, "kr-continuation-ok"));
    }
}

/// KR-REQ-07.71, KR-REQ-07.72, and `enter-fence-acknowledge-detach`.
pub fn an_eligible_gesture_under_a_fence_is_an_attributable_detach(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));

    let (enter, fence) = session.fenced_prompt(1);
    // The decisions the reader reports from here are the gesture's and the repeated gesture's, and
    // no other: they are counted as they arrive, whatever the waits below take off the queue.
    let decisions_before = session.events.managed_decisions();
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
    // The reader reports in the order it acts, and a line it runs next is accepted after both
    // gestures were decided, so the harness has read every decision by the time the line has run.
    // The detach and the repeated gesture's consumption are two; a third is a consumption of the
    // gesture that was submitted, which an attributable gesture is not.
    assert!(session.answered("kr-after-the-gestures"));
    // The shell wrote both decisions before it ran the line, so they are on the endpoint when the
    // marker is on the screen, whether or not it waited for the acceptance's answer: they are read
    // here rather than assumed to have been read.
    session.take_in_what_has_arrived();
    assert_eq!(
        session.events.managed_decisions(),
        decisions_before + 2,
        "an attributable gesture is submitted, not consumed"
    );
    assert!(session.alive());
}

/// KR-REQ-07.71, KR-REQ-07.72, and `eof-missing-fence`, `eof-stale-fence`, `eof-repeated-after-detach`.
pub fn an_unattributable_gesture_is_consumed_with_one_hint_per_prompt(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));
    let enter = session.next_prompt();

    // What the hint is, is what the screen shows, so this is a display observation and carries no
    // claim that anything ran. The boundary is taken before the key, so a hint an earlier prompt
    // printed is not this one's.
    let before_first = session.written();
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
        session
            .drew_after(before_first, DETACH_HINT, REPLY)
            .was_drawn(),
        "the hint was not printed:\n{}",
        session.terminal_output()
    );
    let after_first = session.terminal_output().matches(DETACH_HINT).count();
    if kind == ShellKind::Fish {
        // Counted in the terminal's own bytes, which is what the wait below counts in.
        let hint_pos = session
            .last_shown(DETACH_HINT)
            .expect("the hint the check above saw drawn");
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
    assert!(session.answered("kr-next-prompt"));
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
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));

    let (_, fence) = session.fenced_prompt(4);
    let before_key = session.written();
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
        session
            .drew_after(before_key, DETACH_HINT, REPLY)
            .was_drawn(),
        "a refused detach printed no hint"
    );
    session
        .still_serving("kr-hint-served")
        .unwrap_or_else(|why| panic!("a refused detach left nothing working: {why}"));
}

/// A cancellation is not the gesture again: a read that ends with no key resolved leaves the key
/// before it as the last one, and a decision taken on that key would detach the next attachment.
pub fn a_cancellation_after_a_detach_does_not_detach_the_next_attachment(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));

    let (enter, fence) = session.fenced_prompt(1);
    session.type_bytes(CTRL_D);
    let (id, event) = session.expect_event("eof_detach", |event| {
        matches!(event, BridgeEvent::EofDetach(_))
    });
    let BridgeEvent::EofDetach(detach) = event else {
        unreachable!()
    };
    assert_eq!(detach.fence_id, fence.fence_id);
    session.answer_event(id, detached(attachment_id(1)));

    // A second attachment takes the input at the same prompt, and the worker fences the reader for
    // it. The exchange after the publication is answered only once the reader has read both.
    let second = fence_for(&enter, fence_id(2), attachment_id(2), epoch(5));
    session.publish(&second);
    let _ = session.fence_exchange(&enter, fence_id(3));

    // The second attachment cancels the line. That is its own key, and it ends this reader. The
    // events are in the order the reader sent them, so a decision taken on the cancellation is
    // counted before the next prompt's entry, which is what this waits for.
    let decisions = session.events.managed_decisions();
    session.type_bytes(CTRL_C);
    let _ = session.next_prompt();
    assert_eq!(
        session.events.managed_decisions(),
        decisions,
        "a cancellation was decided as the end-of-file gesture the attachment before it made"
    );
    assert!(
        session.alive(),
        "the cancellation ended the shell instead of the line"
    );
}

/// A key sequence a cancellation cut short is no key at all, and the value the reader holds for it
/// is not the gesture on a terminal whose end-of-file character is the byte 0xff.
///
/// An escape starts a sequence the editor waits to see finished, and the cancellation ends the
/// wait with nothing selected. What the reader is left holding is the end of the input, which is
/// not a byte, and reading it as the byte 0xff would make it the gesture. The editor's wait for
/// the rest of a sequence is made long, so that it is the cancellation that ends it and not the
/// wait.
pub fn a_cancelled_key_sequence_is_not_the_gesture_on_a_terminal_whose_eof_byte_is_0xff(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let mut session = Session::start_with_profile(
        &package,
        Profile {
            after_configuration: "KEYTIMEOUT=6000\n",
            ..Profile::ORDINARY
        },
    );
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));
    assert!(session.run(
        "stty eof 0xff; printf '%s%s\\n' kr-veof- set",
        "kr-veof-set"
    ));
    let (_, changed) = session.expect_event("gesture_changed", |event| {
        matches!(event, BridgeEvent::GestureChanged(_))
    });
    let BridgeEvent::GestureChanged(changed) = changed else {
        unreachable!()
    };
    assert_eq!(
        changed.gesture,
        EofGesture::TerminalEof {
            byte: U64::new(0xff)
        }
    );

    let (enter, _fence) = session.fenced_prompt(1);
    session.type_bytes(ESCAPE);
    // The editor has taken the escape and waits for the rest of the sequence, which is the reader's
    // own report of it: the cancellation that follows is then one that cuts a sequence short.
    session.until_the_reader_shows(&enter, fence_id(2), "the escape waiting", |held| {
        held.pending.multikey_sequence
    });
    let decisions = session.events.managed_decisions();
    session.type_bytes(CTRL_C);
    let _ = session.next_prompt();
    assert_eq!(
        session.events.managed_decisions(),
        decisions,
        "a cancelled key sequence was decided as the end-of-file gesture"
    );
    assert!(
        session.alive(),
        "the cancellation ended the shell instead of the line"
    );
}

/// The person's function for the cases below, which says how long the text it was given is.
///
/// The words it prints are put together by the shell, so the screen showing the line a person
/// typed cannot produce them.
const LENGTH_FUNCTION: &str =
    "function global:kr-length { Write-Output ('kr-' + 'length-' + $args[0].Length) }\n";

/// KR-REQ-07.73: a key the editor binds nothing to is left to the editor when the gesture sits on
/// it, and what the editor does with such a key is to put the character it carries in the line.
///
/// PSReadLine's Windows edit mode binds no end-of-file chord, which is the platform's; here the
/// person has taken the binding off the key the terminal names, which leaves the editor with no
/// operation for it. The module's decision is on that key all the same, and a key outside the
/// detach condition (here a line with text in it) is what it passes on.
pub fn an_unbound_gesture_key_does_what_the_editor_does_with_an_unbound_key(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start_with_profile(
        &package,
        Profile {
            after_configuration: &format!(
                "Remove-PSReadLineKeyHandler -Chord Ctrl+d\n{LENGTH_FUNCTION}"
            ),
            ..Profile::ORDINARY
        },
    );
    session.first_prompt();
    session.forget_events();
    assert!(
        session.answered("kr-ready"),
        "the shell did not answer:\n{}",
        session.terminal_output()
    );

    assert!(session.wait_for_prompt());
    assert!(session.wait_for_editor_reading());
    let start = session.written();
    session.type_bytes(b"kr-length abc");
    assert!(session.wait_for_editor(start));
    // The cursor goes back one place, in front of the last character.
    session.type_bytes(b"\x1b[D");
    session.type_bytes(CTRL_D);
    let before_return = session.written();
    session.type_bytes(b"\r");
    // What the editor does with an unbound key is to insert the character the key carries, so the
    // line runs with four characters. The operation the module used to run in its place deleted
    // the last one, which left two.
    assert!(
        session
            .drew_after(before_return, "kr-length-4", REPLY)
            .was_drawn(),
        "the gesture key did not do what the editor does with an unbound key:\n{}",
        session.terminal_output()
    );
    assert!(session.alive());
}

/// KR-REQ-07.73: the key that moves the gesture still does what it was bound to.
///
/// A person whose terminal has another end-of-file character than the worker was told of has
/// changed the gesture before the first prompt, and the change takes effect at the first key the
/// module's decision sees afterwards, which is the old one. The decision moves to the new key
/// before the old key's press has run, and the press runs what stood on the old key, whatever
/// stood on the new one.
pub fn the_key_that_promotes_a_changed_gesture_runs_what_was_bound_to_it(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start_with_profile(
        &package,
        Profile {
            after_configuration: LENGTH_FUNCTION,
            terminal_eof: Some("^e"),
            ..Profile::ORDINARY
        },
    );
    session.first_prompt();

    // No command runs before the key itself: the change takes effect at the first gesture key the
    // prompt sees, and a command run first would have the next prompt take it on entry.
    assert!(session.wait_for_prompt());
    assert!(session.wait_for_editor_reading());
    let start = session.written();
    session.type_bytes(b"kr-length abc");
    assert!(session.wait_for_editor(start));
    session.type_bytes(b"\x1b[D");
    // The old gesture key, which the editor binds to deleting the character under the cursor, so
    // the line runs with two characters. The new one is bound to going to the end of the line,
    // which would leave three.
    session.type_bytes(CTRL_D);
    let before_return = session.written();
    session.type_bytes(b"\r");
    assert!(
        session
            .drew_after(before_return, "kr-length-2", REPLY)
            .was_drawn(),
        "the key that moved the gesture did not run what stood on it:\n{}",
        session.terminal_output()
    );
    assert!(session.alive());
}

/// `detach-condition-exclusions`: outside the condition the editor keeps the key.
pub fn the_detach_condition_excludes_what_the_corpus_names(kind: ShellKind) {
    let package = Package::built(kind);
    let named = excluded_states();
    let speech = dialect(kind);

    // Each of these puts the reader into one excluded state and offers it the gesture, in a shell
    // of its own. The contract's answer is native, so the reader keeps the key: no detach, no
    // consume, and the shell and the bridge are both still working afterwards.
    let mut driven: Vec<DetachExclusion> = Vec::new();
    // States a drive put the reader into and the reader reported nothing of its own about. The
    // corpus accounts for them by what was observed rather than counting them as driven.
    let mut narrowed: Vec<DetachExclusion> = Vec::new();
    for drive in exclusion_drives(kind) {
        one_excluded_state_keeps_the_key(kind, &package, &drive);
        driven.push(drive.exclusion);
    }

    // The reader the shell's own `read` starts is not the root editor's prompt.
    if let Some(command) = read_builtin_command(kind) {
        let mut session = a_shell_of_its_own(kind, &package);
        session.type_line(command);
        std::thread::sleep(Duration::from_millis(500));
        session.forget_events();
        let decisions = session.events.managed_decisions();
        session.type_bytes(CTRL_D);
        // The read ends on the key, and the shell comes back to its prompt and runs a command of
        // this session's own. The root editor reads the keys in the order they were typed, so a
        // decision for the key was sent before that command was accepted, and it is on the endpoint
        // once the command has answered.
        assert!(
            session.answered("kr-read-done"),
            "the shell did not come back from the read builtin after the gesture:\n{}",
            session.terminal_output()
        );
        session.take_in_what_has_arrived();
        assert_eq!(
            session.events.managed_decisions(),
            decisions,
            "a gesture inside the read builtin was treated as the root editor's"
        );
        assert!(
            session.alive(),
            "the read builtin's gesture ended the shell"
        );
        driven.push(DetachExclusion::ReadBuiltin);
    }

    // A vi motion waits for its target, and the gesture belongs to that wait. It needs the vi
    // keymap, which is the person's own setting, so it is put back afterwards.
    if let Some((vi_mode, emacs_mode)) = vi_keymap_commands(kind) {
        let mut session = a_shell_of_its_own(kind, &package);
        session.clear_line();
        session.forget_events();
        assert!(session.run(vi_mode, "kr-vi-on"));
        let vi_prompt = session.next_prompt();
        std::thread::sleep(Duration::from_millis(300));
        session.forget_events();
        if kind == ShellKind::Fish {
            // This reader resolves a lone escape on a timer of its own, and a key that is already
            // there when the timer is read goes with the escape as the sequence it began (the
            // escape and a d are alt-d, and no operator waits for anything). On a machine that
            // stalls the shell for a moment the delay a drive allows is the whole of what the
            // next key arrives in, so each key goes in once the reader has said the one before
            // it took effect: the escape once the reader is in the command keymap, and the
            // operator once the reader is waiting behind it, which it holds back as the first key
            // of the sequences that begin with it and reports as a sequence in progress.
            session.type_bytes(ESCAPE);
            session.until_the_reader_shows(
                &vi_prompt,
                fence_id(20),
                "the command keymap",
                |held| held.keymap == kr_protocol::root::EditorKeymap::ViCommand,
            );
            session.type_bytes(b"d");
            session.until_the_reader_shows(
                &vi_prompt,
                fence_id(21),
                "the operator waiting",
                |held| held.pending.vi_motion || held.pending.multikey_sequence,
            );
        } else {
            // Zsh waits out a lone escape in its own poll and is not asked while it does, since a
            // question restarts the wait and an escape that is asked about never ends. Its drive
            // and bash's keep the delays, which decide nothing here.
            session.type_bytes(ESCAPE);
            std::thread::sleep(Duration::from_millis(120));
            session.type_bytes(b"d");
            std::thread::sleep(Duration::from_millis(120));
        }
        let decisions = session.events.managed_decisions();
        session.type_bytes(CTRL_D);
        // The window is the key's own room before the interrupt: an interrupt typed at once behind
        // it ended the shell in Fish. What decides the verdict is the count at the end of the
        // block, which a command of this session's own has run behind.
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
        assert!(session.run(emacs_mode, "kr-vi-off"));
        session.take_in_what_has_arrived();
        assert_eq!(
            session.events.managed_decisions(),
            decisions,
            "a gesture a vi motion was waiting for was treated as a detach, late"
        );
    }

    // A macro the reader is replaying is the reader's own input, not a gesture a person made, and
    // a binding that feeds the gesture itself proves the source is what excludes it.
    if let Some(bind_macro) = macro_binding(kind) {
        let mut session = a_shell_of_its_own(kind, &package);
        session.clear_line();
        assert!(session.run(bind_macro, "kr-macro-bound"));
        let bound = session.latest_prompt();
        std::thread::sleep(Duration::from_millis(300));
        session.forget_events();
        let decisions = session.events.managed_decisions();
        session.type_bytes(CTRL_T);
        // Whether the reader replayed anything is the reader's own answer. A binding that did
        // nothing looks exactly like one whose replay the worker refused: both are silence and a
        // live shell. So the state is asked for, and where the reader does not report a replay the
        // drive keeps what it saw and claims no more.
        let replayed = session.reader_replaying(&bound, fence_id(23));
        // The replay is the reader's own input, read before it says it has read what was typed.
        session.until_the_reader_has_acted_on_what_was_typed(&bound);
        assert_eq!(
            session.events.managed_decisions(),
            decisions,
            "a gesture a macro produced was treated as one a person made"
        );
        assert!(session.alive(), "macro input ended the shell");
        if replayed {
            driven.push(DetachExclusion::MacroInput);
        } else {
            narrowed.push(DetachExclusion::MacroInput);
            println!(
                "macro_input: unobserved, the reader reported no replay of its own, so this case \
                 claims the key it typed and the editor's answer to it and nothing about the state"
            );
        }
        session.clear_line();
    }

    // A continuation line is a different reader, so the gesture is the editor's there too.
    if let Some((open, _close)) = speech.continuation {
        let mut session = a_shell_of_its_own(kind, &package);
        session.clear_line();
        session.type_line(open);
        let (_, continuation) = session.expect_event("a continuation reader", |event| {
            matches!(
                event,
                BridgeEvent::EditorEnter(params)
                    if params.reader_context == kr_protocol::root::ReaderContext::Continuation
            )
        });
        let decisions = session.events.managed_decisions();
        session.type_bytes(CTRL_D);
        session.until_the_reader_has_acted_on_what_was_typed(as_enter(&continuation));
        assert_eq!(
            session.events.managed_decisions(),
            decisions,
            "a continuation line did not exclude the gesture"
        );
        assert!(
            session.alive(),
            "a gesture in a continuation reader ended the shell"
        );
        driven.push(DetachExclusion::ContinuationInput);
        // The session ends here rather than closing the continuation. The gesture this drive just
        // offered makes the shell abandon the unfinished command, so the line that would have
        // closed the continuation opens another one and nothing after it is at the prompt it was
        // written for. What this drive proves, it has proved.
        drop(session);
        return;
    }

    for exclusion in &named {
        assert!(
            driven.contains(exclusion)
                || narrowed.contains(exclusion)
                || not_constructible_here(kind, *exclusion).is_some(),
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

/// One excluded state, in a shell of its own, from the state the reader reports to what the
/// editor does with the key.
///
/// A shell of its own for each, because a drive that ran where another had already been would be
/// measuring what that one left behind: a search leaves the editor in a listing, a paste leaves it
/// mid-paste, and a recovery gesture between the two would stand where the evidence should be.
///
/// Silence is not the answer either. A reader that had died, one that had been replaced and one
/// that never took the key are equally silent, so three things are asked for: the reader says, in
/// its own answer to a fence, that it is in the state this drive names; neither managed event
/// arrives; and afterwards the shell runs a command of this session's own while the bridge reports
/// its reader coming and going.
/// A shell of this package's own, at a fenced empty prompt, for one drive to use.
///
/// Every drive gets one. A drive that ran in a shell another drive had already used would be
/// measuring what that one left behind: a macro binding stays bound, a keymap one drive changed is
/// the keymap the next starts in, a search leaves the editor in a listing, and a gesture inside a
/// continuation reader leaves the shell part way through a command it could not parse.
fn a_shell_of_its_own(kind: ShellKind, package: &Package) -> Session {
    let mut session = Session::start(package);
    session.first_prompt();
    session.forget_events();
    // Outside the detach condition the key is the editor's own, and at an empty prompt the
    // editor's own answer can be to end the shell. Where the shell has a setting of its own for
    // that, the person's setting is what makes the answer observable without ending this session,
    // and it is left exactly as they set it; where it has none, the buffer is not empty, so the
    // editor's own answer is to delete a character.
    let ready = dialect(kind)
        .ignore_eof_on
        .map_or_else(|| print_assembled(kind, "kr-ready"), ToOwned::to_owned);
    assert!(session.run(&ready, "kr-ready"));
    let (_, _fence) = session.fenced_prompt(5);
    session
}

fn one_excluded_state_keeps_the_key(kind: ShellKind, package: &Package, drive: &ExclusionDrive) {
    let speech = dialect(kind);
    let named = drive.exclusion.as_str();
    let mut session = Session::start(package);
    session.first_prompt();
    session.forget_events();
    // Outside the detach condition the key is the editor's own, and at an empty prompt the
    // editor's own answer can be to end the shell. Where the shell has a setting of its own for
    // that, the person's setting is what makes the answer observable without ending this session,
    // and it is left exactly as they set it.
    let ready = speech
        .ignore_eof_on
        .map_or_else(|| print_assembled(kind, "kr-ready"), ToOwned::to_owned);
    assert!(session.run(&ready, "kr-ready"));
    if let Some((command, marker)) = drive.prepare {
        assert!(
            session.run(command, marker),
            "{named} could not be prepared:\n{}",
            session.terminal_output()
        );
    }
    let (enter, _fence) = session.fenced_prompt(5);
    session.ensure_reading();
    let offered_to = session.reading_reader();
    session.forget_events();

    for bytes in drive.setup {
        session.type_bytes(bytes);
        std::thread::sleep(Duration::from_millis(80));
    }
    // This suite runs the package on its own, with no startup customisation of the person's to put
    // a widget of its own on the key that was just typed, so the reader here owes an answer.
    let read = session.reader_state_now(&enter, fence_id(6));
    let held = read.unwrap_or_else(|why| {
        panic!(
            "{named} was driven and the reader's state could not be read: {why}:\n{}",
            session.terminal_output()
        )
    });
    assert!(
        offered_to.same_reader(&held),
        "the reader changed while {named} was being set up"
    );
    // What the reader reports is what this claims. A reader that answers the keys with no state of
    // its own leaves the drive with the keys it typed and the editor's own answer to the gesture,
    // and the line below says so rather than the claim being made anyway: an editor with no
    // observable of its own for a state is a gap in what this suite can prove, not a pass.
    if held.shows(drive.exclusion) == Some(true) {
        println!("{named}: the reader reported {}", held.doing());
    } else {
        println!(
            "{named}: unobserved, the reader reported {} instead, so this case claims the keys it \
             typed and the editor's answer to the gesture and nothing about the state",
            held.doing()
        );
    }

    // A decision for the key is judged at the end of the drive, when a command of this session's
    // own has run behind it: the count the end reads is of everything since the boundary above.
    session.type_bytes(CTRL_D);
    // The keys that end the state come before the shell is asked to run anything, and nothing is
    // typed until the reader says they worked: a reader left where a typed line is motions
    // swallows the command, and the silence would read as the gesture having ended the shell.
    session
        .serving_after_teardown(drive.teardown, "kr-exclusion-served")
        .unwrap_or_else(|why| panic!("after {named}: {why}:\n{}", session.terminal_output()));
    // The rejection covers the whole drive, not the moment after the key: a decision that arrived
    // while the drive was ending the state is still one the key reached, and the inbox counted it.
    // It is judged with the endpoint and the shell, on the drive's last read.
    session
        .ended_whole_with_no_decision()
        .unwrap_or_else(|why| {
            panic!(
                "at the end of the drive after {named}: {why}:\n{}",
                session.terminal_output()
            )
        });
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
        ShellKind::Zsh => Some((
            "bindkey -v; printf '%s%s\\n' kr-vi- on",
            "bindkey -e; printf '%s%s\\n' kr-vi- off",
        )),
        ShellKind::Bash => Some((
            "set -o vi; printf '%s%s\\n' kr-vi- on",
            "set -o emacs; printf '%s%s\\n' kr-vi- off",
        )),
        ShellKind::Fish => Some((
            "fish_vi_key_bindings; printf '%s%s\\n' kr-vi- on",
            "fish_default_key_bindings; printf '%s%s\\n' kr-vi- off",
        )),
        // This editor's vi mode is the host's own and its operators take their keys themselves.
        ShellKind::PowerShell => None,
    }
}

/// A binding that feeds the gesture back as the reader's own input.
fn macro_binding(kind: ShellKind) -> Option<&'static str> {
    match kind {
        ShellKind::Zsh => Some("bindkey -s '^T' $'\\x04'; printf '%s%s\\n' kr-macro- bound"),
        ShellKind::Bash => Some("bind '\"\\C-t\": \"\\C-d\"' ; printf '%s%s\\n' kr-macro- bound"),
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
    // An editor whose host puts the terminal's settings back after every command cannot be told a
    // new character from inside the shell, and one whose gesture is a chord the worker configures
    // does not follow the character at all. Neither is one this case is for: the first is driven
    // by `the_gesture_a_terminal_starts_with_is_the_one_the_reader_announces` and the second by
    // `psreadline-chord-gesture`, and a suite that named this case for such an editor would pass it
    // without a check.
    let (Some(change), Some(disable)) = (speech.veof_change, speech.veof_disable) else {
        panic!(
            "{} keeps no end-of-file character changed inside the shell, or follows a configured \
             chord rather than the terminal's character, so this case is not one of its",
            kind.as_str()
        );
    };
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    // A character that is not the gesture is the editor's own, and at an empty prompt the editor's
    // own answer can be to end the shell. The person's ignoreeof setting makes that answer
    // observable without ending this session; an editor with no such setting keeps something in
    // the buffer instead.
    if let Some(command) = speech.ignore_eof_on {
        assert!(session.run(command, "kr-ready"));
    }
    // And the editor's own answer to the old character must end by itself: one that asks the person
    // a question is a key sequence still being read, which no fence asked behind it can drain past.
    if let Some(command) = speech.quiet_own_key {
        assert!(session.run(command, "kr-quiet-set"));
    }

    // A VEOF reassignment is a user change to the gesture, and it takes effect at a prompt rather
    // than in the middle of a read.
    assert!(session.run(change, "kr-veof-set"));
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

    let (entry, fence) = session.fenced_prompt(6);
    if speech.ignore_eof_on.is_none() {
        // Nothing of the editor's own ends a shell whose buffer is not empty.
        session.type_bytes(b"kr");
        std::thread::sleep(Duration::from_millis(80));
    }
    let decisions = session.events.managed_decisions();
    session.type_bytes(CTRL_D);
    session.until_the_reader_has_acted_on_what_was_typed(&entry);
    assert_eq!(
        session.events.managed_decisions(),
        decisions,
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
    assert!(session.run(disable, "kr-veof-undef"));
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
    let decisions = session.events.managed_decisions();
    session.type_bytes(CTRL_G);
    session.until_the_reader_has_acted_on_what_was_typed(&enter);
    assert_eq!(
        session.events.managed_decisions(),
        decisions,
        "a terminal with no gesture still produced one"
    );
    assert!(session.alive());
}

/// KR-REQ-07.73's package half for an editor whose host puts a terminal setting back after every
/// command, and `veof-change`, `veof-disabled`.
///
/// A person who changes the end-of-file character from inside such a shell loses the change when
/// the command ends, so the character the shell finds is the one the terminal had when the shell
/// started. The terminal is set up first, and the reader announces what it found at the first
/// prompt: a gesture that moved, or none at all. Each key is pressed at an empty fenced prompt,
/// where the gesture detaches and any other key is the editor's own; the editor's own answer to the
/// terminal's usual character at an empty prompt is to end the shell, which is what shows that no
/// managed decision stood in its way.
pub fn the_gesture_a_terminal_starts_with_is_the_one_the_reader_announces(kind: ShellKind) {
    let package = Package::built(kind);
    let started_with = |eof: &'static str| {
        let mut session = Session::start_with_profile(
            &package,
            Profile {
                terminal_eof: Some(eof),
                ..Profile::ORDINARY
            },
        );
        // The gesture is announced before the first entry, so the entry is waited for after it.
        session.expect_event("hooks_activated", |event| {
            matches!(event, BridgeEvent::HooksActivated(_))
        });
        let (_, event) = session.expect_event("the gesture the terminal started with", |event| {
            matches!(event, BridgeEvent::GestureChanged(_))
        });
        let BridgeEvent::GestureChanged(announced) = event else {
            unreachable!()
        };
        let (_, event) = session.expect_event("the first editor entry", |event| {
            matches!(event, BridgeEvent::EditorEnter(_))
        });
        session.reading = true;
        session.last_entry = Some(as_enter(&event).clone());
        session.forget_events();
        assert!(session.answered("kr-ready"));
        (session, announced.gesture)
    };
    let moved = EofGesture::TerminalEof {
        byte: U64::new(0x07),
    };

    // The terminal's character moved: the key it names detaches at an empty prompt.
    let (mut session, gesture) = started_with("^g");
    assert_eq!(
        gesture, moved,
        "the gesture the terminal started with was announced as another"
    );
    let (_, fence) = session.fenced_prompt(6);
    session.type_bytes(CTRL_G);
    let (id, event) = session.expect_event("eof_detach", |event| {
        matches!(event, BridgeEvent::EofDetach(_))
    });
    let BridgeEvent::EofDetach(detach) = event else {
        unreachable!()
    };
    assert_eq!(detach.fence_id, fence.fence_id);
    session.answer_event(id, detached(attachment_id(1)));
    assert!(session.alive());
    drop(session);

    // And the default key is no longer the gesture: the editor's own answer to it at an empty
    // prompt, which is to end the shell, is the answer, and nothing decided before it.
    let (mut session, _) = started_with("^g");
    let (_enter, _fence) = session.fenced_prompt(7);
    session.type_bytes(CTRL_D);
    assert!(
        session.ended_within(REPLY),
        "the terminal's old character was kept as if it were still the gesture:\n{}",
        session.terminal_output()
    );
    assert!(
        session.no_managed_decision_before(0),
        "the terminal's old character was decided on as the gesture"
    );
    drop(session);

    // The terminal started with no end-of-file character: no key is the gesture. Ctrl+G stays the
    // editor's own and changes nothing, and Ctrl+D, the editor's own exit at an empty prompt, ends
    // the shell.
    let (mut session, gesture) = started_with("undef");
    assert_eq!(
        gesture,
        EofGesture::Disabled,
        "a terminal with no end-of-file character was announced as having a gesture"
    );
    let (_enter, _fence) = session.fenced_prompt(8);
    session.type_bytes(CTRL_G);
    session.type_bytes(CTRL_D);
    assert!(
        session.ended_within(REPLY),
        "a terminal with no end-of-file character kept a key as the gesture:\n{}",
        session.terminal_output()
    );
    assert!(
        session.no_managed_decision_before(0),
        "a terminal with no end-of-file character still produced a gesture"
    );
}

/// The budget a case gives a launch whose subject is not the deadline.
///
/// The product's budget is 200 ms of the reader's own clock, from reading the request to deciding
/// it, and a reader that the scheduler has not run for that long answers `timeout` to every
/// request that passes the checks before it (a launch not revoked, a fence still live, a primary
/// reader). A case about what the reader installs, or about why it refuses a request, would then
/// pass or fail by the load of the machine. A day is a budget no run reaches, and the
/// deadline itself is decided by a request whose budget is none, which is over on arrival.
pub const LAUNCH_BUDGET_NOT_UNDER_TEST: DurationMs = DurationMs::new(86_400_000);

/// KR-REQ-07.34, KR-REQ-07.35, and `launch-installed`.
pub fn a_launch_is_installed_and_accepted_on_the_reader_thread(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));

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
    let before_install = session.written();
    let decision = session.launched(LaunchMailboxRequest {
        session_id: session.session_id,
        transaction,
        fence_id: fence.fence_id,
        command: command.clone(),
        expected_prompt_generation: enter.prompt_generation,
        expected_buffer_revision: enter.editor.buffer_revision,
        expected_cwd_revision: enter.cwd_revision,
        deadline_ms: LAUNCH_BUDGET_NOT_UNDER_TEST,
    });
    let accepted = match decision {
        LaunchDecision::Accepted(accepted) => accepted,
        LaunchDecision::Rejected(rejected) => {
            panic!(
                "an empty fenced prompt refused a launch: {:?}",
                rejected.reason
            )
        }
    };
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
        session
            .drew_after(before_install, dialect(kind).launch_expectation, REPLY)
            .was_drawn(),
        "the arguments that ran are not the arguments the caller named:\n{}",
        session.terminal_output()
    );
    assert!(
        !session.terminal_output().contains("substituted|"),
        "an argument was expanded rather than installed literally:\n{}",
        session.terminal_output()
    );
}

/// A command the caller already quoted for the target shell, which the reader installs as it was
/// given, and what it prints.
///
/// A pipeline is the plainest text that only means something to a shell: the reader that installed
/// it as one word, or quoted it again, would print nothing of this.
fn pipeline_for(kind: ShellKind) -> (&'static str, &'static str) {
    match kind {
        ShellKind::PowerShell => ("'abc' | ForEach-Object { $_.ToUpper() }", "ABC"),
        _ => ("printf '%s\\n' abc | tr a-c X-Z", "XYZ"),
    }
}

/// Installs `program` with `words` as its arguments through a launch, and says that the terminal
/// shows the program printing exactly those words.
fn launch_prints_what_was_named(
    session: &mut Session,
    program: &std::path::Path,
    words: &[&str],
    prompt_seed: u8,
    transaction_seed: u8,
) {
    let expected: String = words.iter().map(|word| format!("<{word}>")).collect();
    let mut vector = vec![told(program)];
    vector.extend(words.iter().map(|word| (*word).to_owned()));
    let (enter, fence) = session.fenced_prompt(prompt_seed);
    let before_install = session.written();
    let decision = session.launched(LaunchMailboxRequest {
        session_id: session.session_id,
        transaction: LaunchTransactionId::new(Uuid::from_bytes([transaction_seed; 16])),
        fence_id: fence.fence_id,
        command: LaunchCommand::Arguments(vector),
        expected_prompt_generation: enter.prompt_generation,
        expected_buffer_revision: enter.editor.buffer_revision,
        expected_cwd_revision: enter.cwd_revision,
        deadline_ms: LAUNCH_BUDGET_NOT_UNDER_TEST,
    });
    assert!(
        matches!(decision, LaunchDecision::Accepted(_)),
        "an empty fenced prompt refused a launch: {decision:?}"
    );
    session.nudge();
    session.expect_event("command_accepted", |event| {
        matches!(event, BridgeEvent::CommandAccepted(_))
    });
    session.expect_event("editor_leave", |event| {
        matches!(event, BridgeEvent::EditorLeave(_))
    });
    assert!(
        session
            .drew_after(before_install, &expected, REPLY)
            .was_drawn(),
        "the arguments that ran are not the arguments the caller named; wanted {expected}:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-23.54: a launch is quoted for the shell that reads it and is never evaluated.
///
/// The first launch is an executable whose path has a space in it, with one hostile word: for
/// PowerShell, a word that ends its string at a typographic quote and then names a command of its
/// own. The second has an argument vector that holds every quote character PowerShell reads, an
/// embedded quote, a backslash, an empty word, a glob, a tilde, a variable, a splatting word, two
/// separators and a command substitution. The executable prints each argument it was given between
/// angle brackets, so the line that appears is the argument vector that arrived, and the echo of
/// the installed line, which carries quotes and no brackets, cannot produce it. The last launch is
/// a pipeline the caller quoted for the shell itself, which runs as written.
pub fn a_launch_is_quoted_for_its_own_shell_and_never_evaluated(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));

    let directory = session.home().join("kr launch directory");
    std::fs::create_dir_all(&directory).expect("a directory with a space in its name");
    let program = directory.join("show arguments");
    kr_ipc::testing::place_script(
        &program,
        "#!/bin/sh\nfor argument in \"$@\"; do printf '<%s>' \"$argument\"; done\nprintf '\\n'\n",
    );

    let substitution = match kind {
        ShellKind::Fish => "(echo substituted)",
        _ => "$(echo substituted)",
    };
    // PowerShell reads five characters as a single quote: the ASCII one and the four typographic
    // ones, so a word holding any of them must keep it inside the string. The first launch is one
    // word that ends its string early in a reader that doubles only the ASCII quote, and what
    // follows the word then runs as a command of its own. The second holds every quote character,
    // and every other character a shell treats as more than itself.
    let injected = "x\u{2019}; Write-Output kr-injected; \u{2019}";
    launch_prints_what_was_named(&mut session, &program, &[injected], 19, 0x74);
    launch_prints_what_was_named(
        &mut session,
        &program,
        &[
            "it's",
            "it\u{2019}s",
            "\u{2018}",
            "\u{2019}",
            "\u{201A}",
            "\u{201B}",
            r"a\b",
            "",
            "*",
            "~",
            "$HOME",
            "@payload",
            "a;b",
            "a|b",
            substitution,
        ],
        20,
        0x75,
    );

    let (pipeline, printed) = pipeline_for(kind);
    let (enter, fence) = session.fenced_prompt(21);
    let before_install = session.written();
    let decision = session.launched(LaunchMailboxRequest {
        session_id: session.session_id,
        transaction: LaunchTransactionId::new(Uuid::from_bytes([0x76; 16])),
        fence_id: fence.fence_id,
        command: LaunchCommand::QuotedCommand(pipeline.to_owned()),
        expected_prompt_generation: enter.prompt_generation,
        expected_buffer_revision: enter.editor.buffer_revision,
        expected_cwd_revision: enter.cwd_revision,
        deadline_ms: LAUNCH_BUDGET_NOT_UNDER_TEST,
    });
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
            .drew_after(before_install, printed, REPLY)
            .was_drawn(),
        "a command the caller quoted was not run as written:\n{}",
        session.terminal_output()
    );
}

/// The reader's own check, one case per reason it can produce here.
pub fn the_reader_refuses_a_launch_its_own_state_does_not_match(kind: ShellKind) {
    let package = Package::built(kind);
    let wait = pending_wait(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    // Whatever the wait below needs runs before the reader the launches are checked against.
    let fallback = print_assembled(kind, "kr-ready");
    let ready = wait
        .as_ref()
        .and_then(|wait| wait.prepare)
        .unwrap_or((&fallback, "kr-ready"));
    assert!(session.run(ready.0, ready.1));

    let (enter, fence) = session.fenced_prompt(9);
    let base = LaunchMailboxRequest {
        session_id: session.session_id,
        transaction: LaunchTransactionId::new(Uuid::from_bytes([0x72; 16])),
        fence_id: fence.fence_id,
        command: LaunchCommand::Arguments(vec!["true".to_owned()]),
        expected_prompt_generation: enter.prompt_generation,
        expected_buffer_revision: enter.editor.buffer_revision,
        expected_cwd_revision: enter.cwd_revision,
        deadline_ms: LAUNCH_BUDGET_NOT_UNDER_TEST,
    };

    let refuse =
        |session: &mut Session, request: LaunchMailboxRequest, expected: LaunchRejectionReason| {
            // The refusal for queued input is the point of the case that asks for it, so that
            // one is taken as it comes.
            let decision = if expected == LaunchRejectionReason::QueuedPriorInput {
                let id = session.ask(WorkerRequest::Launch(request));
                let BridgeAnswer::Launch(decision) = session.answer(id) else {
                    panic!("the reader answered a launch with something else")
                };
                decision
            } else {
                session.launched(request)
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

    // Every reason is driven above, or is one the worker decides rather than the reader, or needs
    // a reader this session cannot reach.
    for reason in LaunchRejectionReason::ALL.iter().copied() {
        assert!(
            driven_here(kind, reason)
                || worker_side(reason)
                || not_reachable_here(kind, reason).is_some(),
            "{} is neither driven nor accounted for",
            reason.as_str()
        );
    }
}

/// A launch of the argument vector `launch_expectation` expects, for the prompt `enter` opened and
/// the fence `fence` the worker published at it.
fn launch_at(
    session: &Session,
    transaction: u8,
    enter: &RootEditorEnterParams,
    fence: &kr_protocol::root::EditorFence,
    substitution: &str,
) -> LaunchMailboxRequest {
    LaunchMailboxRequest {
        session_id: session.session_id,
        transaction: LaunchTransactionId::new(Uuid::from_bytes([transaction; 16])),
        fence_id: fence.fence_id,
        command: LaunchCommand::Arguments(vec![
            "printf".to_owned(),
            "%s|".to_owned(),
            "kr launch ok".to_owned(),
            substitution.to_owned(),
        ]),
        expected_prompt_generation: enter.prompt_generation,
        expected_buffer_revision: enter.editor.buffer_revision,
        expected_cwd_revision: enter.cwd_revision,
        deadline_ms: LAUNCH_BUDGET_NOT_UNDER_TEST,
    }
}

/// KR-REQ-23.38: a launch whose working-directory revision is not the shell's own is refused by
/// the reader as a draft conflict. A refused launch installs nothing: the same launch at the
/// shell's own revision, at the same prompt, is then installed and runs, which a reader whose
/// buffer the first had changed would have refused.
pub fn a_launch_for_another_working_directory_is_a_conflict_and_installs_nothing(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));

    let (enter, fence) = session.fenced_prompt(8);
    let substitution = match kind {
        ShellKind::Fish => "(echo substituted)",
        _ => "$(echo substituted)",
    };
    let mut stale = launch_at(&session, 0x73, &enter, &fence, substitution);
    stale.expected_cwd_revision = kr_protocol::root::CwdRevision::new(enter.cwd_revision.get() + 7);
    let before = session.written();
    let decision = session.launched(stale);
    let refusal = decision
        .rejection()
        .expect("the reader refused a launch for another working directory");
    assert_eq!(refusal, LaunchRejectionReason::CwdRevisionMismatch);
    assert_eq!(refusal.code(), kr_protocol::error::ErrorCode::DraftConflict);

    // At the shell's own revision the same launch installs and runs.
    let request = launch_at(&session, 0x74, &enter, &fence, substitution);
    let decision = session.launched(request);
    assert!(
        matches!(decision, LaunchDecision::Accepted(_)),
        "the launch at the shell's own revision was refused: {:?}",
        decision.rejection()
    );
    session.nudge();
    assert!(
        session
            .drew_after(before, dialect(kind).launch_expectation, REPLY)
            .was_drawn(),
        "the launch the reader accepted did not run:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-23.38: a launch over text the person has typed is refused by the reader as a draft
/// conflict: the prompt has to be empty. The refusal leaves the buffer as the person made it: a
/// second launch is refused for the same reason at the same buffer revision. This case is for the
/// editors whose reader answers while the person types; one that answers at its next boundary is
/// not driven into it from here.
pub fn a_launch_over_typed_text_is_a_conflict_and_installs_nothing(kind: ShellKind) {
    assert!(
        !dialect(kind).answers_at_the_next_step,
        "{} answers a launch at its next boundary once the person has typed, so this case does \
         not reach it",
        kind.as_str()
    );
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));

    let (enter, fence) = session.fenced_prompt(8);
    let substitution = match kind {
        ShellKind::Fish => "(echo substituted)",
        _ => "$(echo substituted)",
    };
    session.type_text(b"x");
    let mut refusals = Vec::new();
    for transaction in [0x75, 0x76] {
        let request = launch_at(&session, transaction, &enter, &fence, substitution);
        let LaunchDecision::Rejected(refusal) = session.launched(request) else {
            panic!("the reader did not refuse a launch over typed text")
        };
        assert_eq!(refusal.reason, LaunchRejectionReason::BufferNotEmpty);
        assert_eq!(
            refusal.reason.code(),
            kr_protocol::error::ErrorCode::DraftConflict
        );
        refusals.push(refusal.buffer_revision);
    }
    assert_eq!(
        refusals[0], refusals[1],
        "the refused launch changed the buffer the person typed in"
    );
    session.clear_line();
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
        // has left, or is not the one the transaction was reserved against. The PowerShell reader
        // also gives `editor_left`, for a launch it reads while its editor is not reading, and that
        // has a case of its own.
        LaunchRejectionReason::Revoked
            | LaunchRejectionReason::ConfirmationLost
            | LaunchRejectionReason::SessionClosing
            | LaunchRejectionReason::EditorLeft
            | LaunchRejectionReason::LeaseChanged
            | LaunchRejectionReason::NotPrimaryReader
    )
}

/// A-17 and `timeout-launch`: a revoked launch installs nothing and says so.
pub fn a_revoked_launch_installs_nothing(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));

    let (enter, fence) = session.fenced_prompt(11);
    let accepted = session.commands.accepted.len();
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
    // Nothing happened is only an answer where something was there for it to happen to. The
    // command of this session's own runs behind anything the revoked launch would have run, and
    // the terminal shows them in the order they ran.
    session
        .still_serving("kr-after-the-revocation")
        .unwrap_or_else(|why| panic!("a revoked launch left nothing working: {why}"));
    assert!(
        !session.terminal_output().contains("kr-revoked"),
        "a revoked launch accepted a line and ran it:\n{}",
        session.terminal_output()
    );
    // The acceptances the session was told of since the launch are the served command's alone.
    session.take_in_what_has_arrived();
    assert_eq!(
        session.commands.accepted.len(),
        accepted + 1,
        "a revoked launch accepted a line"
    );
}

/// A revocation in the same read binds the launch, in whichever order the two frames arrive.
///
/// A revocation for this transaction in the frames the reader's step read binds the launch, so a
/// worker that dispatched a launch and revoked it in the same breath has revoked it.
pub fn a_revocation_in_the_same_read_binds_the_launch(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));

    let (enter, fence) = session.fenced_prompt(15);
    let transaction = LaunchTransactionId::new(Uuid::from_bytes([0x74; 16]));
    let id = RequestId::new(9001);

    // The launch first, its revocation second, in one write, which has to reach the bridge: a
    // write that found it gone would leave this check asserting nothing at all.
    let delivery = session.write_frames(&[
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
    assert_eq!(
        delivery,
        Delivery::Delivered,
        "the bridge was gone before the launch and its revocation were sent"
    );

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
    let before_typing = session.written();
    session.type_bytes(b"kr-typed");
    std::thread::sleep(Duration::from_millis(200));
    session.write_frame(&BridgeFrame::LaunchRevoked {
        transaction,
        reason: LaunchRejectionReason::Timeout,
    });
    std::thread::sleep(Duration::from_millis(200));
    session.type_line("");
    // The editor drawing the person's text is what says it survived, which is a display
    // observation: nothing here claims a command ran.
    assert!(
        session
            .drew_after(before_typing, "kr-typed", REPLY)
            .was_drawn(),
        "a revocation for a finished transaction took the person's own text out:\n{}",
        session.terminal_output()
    );
    session
        .still_serving("kr-revocation-served")
        .unwrap_or_else(|why| panic!("a stale revocation left nothing working: {why}"));
}

/// The reader reports itself idle, which is one of the three points a withheld fence is retried at.
pub fn the_reader_reports_itself_idle(kind: ShellKind) {
    let package = Package::built(kind);
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

/// A reader that has already reported itself idle reports again once the worker has ended an
/// exchange with no fence, because the worker retries at the reader's next idle report and drops
/// one that arrives while its exchange is still open.
///
/// The worker's exchange for a prompt can still be open when the reader first reports idle (the
/// terminal's answers to the prompt's own questions are what the reader reads first), and the
/// acknowledgement that closes it is then withheld. The reader that does not report again leaves
/// the editor unfenced for as long as it stays at that prompt.
pub fn a_reader_reports_itself_idle_again_when_the_worker_withholds_a_fence(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    let (_, event) = session.expect_event("reader_idle", |event| {
        matches!(event, BridgeEvent::ReaderIdle(_))
    });
    let BridgeEvent::ReaderIdle(first) = event else {
        unreachable!()
    };
    // Whatever else the first prompt's start-up reported is behind this point, so the report
    // looked for below can only be one the withheld exchange asked for.
    session.forget_events();

    session.withhold(WithheldReason::QueuesNotDrained);
    let (_, event) = session.expect_event(
        "a second reader_idle after the withheld exchange",
        |event| {
            matches!(
                event,
                BridgeEvent::ReaderIdle(idle)
                    if idle.prompt_generation == first.prompt_generation
                        && idle.reader_revision == first.reader_revision
            )
        },
    );
    let BridgeEvent::ReaderIdle(again) = event else {
        unreachable!()
    };
    assert!(
        again.editor.buffer_empty
            && again.snapshot.queued_keys == U64::new(0)
            && again.snapshot.pending_bytes == U64::new(0),
        "the report after a withheld exchange was not an idle reader's: {again:?}"
    );
}

/// A reader that still holds input it has taken does not report itself idle again when the worker
/// withholds a fence, because the exchange that report starts would be withheld too, and that sends
/// the frame which asks for the report again.
///
/// The reader is left partway through something its acknowledgement reports as input not yet
/// acted on: the start of an escape sequence in Zsh and Bash, and a paste in fish, where an escape
/// is resolved on a timer. The order of the endpoint decides the absence: the reader reads the
/// withheld frame before it reads the exchange sent after it, so a report that frame brought would
/// arrive before that exchange's answer. Once the reader lets go of what it held, the retry the
/// withheld frame left owed is taken and it reports itself idle.
pub fn a_reader_that_holds_input_does_not_report_idle_again_when_the_worker_withholds_a_fence(
    kind: ShellKind,
) {
    let (setup, teardown): (&[&[u8]], &[&[u8]]) = match kind {
        ShellKind::Fish => (&[b"\x1b[200~"], &[b"\x1b[201~"]),
        ShellKind::Zsh | ShellKind::Bash => (&[ESCAPE], &[b"b"]),
        ShellKind::PowerShell => panic!(
            "this editor is not left holding input a handler can see, so this case is not one of \
             its"
        ),
    };
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    let enter = session.first_prompt();
    for bytes in setup {
        session.type_bytes(bytes);
    }
    // The reader is holding input once an exchange finds it so, and every report it made on the way
    // there was sent before the answer that says so.
    let deadline = session.deadline_for(REPLY);
    let mut held = session.fence_exchange_before(&enter, fence_id(30), deadline.0);
    while held.queues.partial_key_drained && !deadline.passed() {
        held = session.fence_exchange_before(&enter, fence_id(30), deadline.0);
    }
    assert!(
        !held.queues.partial_key_drained,
        "a reader holding the start of something reported its partial-key queue clear: {:?}",
        held.queues
    );
    session.forget_events();

    session.withhold(WithheldReason::QueuesNotDrained);
    // The reader answers what it reads in the order it read it, and takes the retry after it has
    // answered, so a report the withheld frame brought is sent before the answer to an exchange
    // that is asked after the first one's answer has come.
    let after = session.fence_exchange_before(&enter, fence_id(31), deadline.0);
    assert!(
        !after.queues.partial_key_drained,
        "what the reader was holding ended on its own: {:?}",
        after.queues
    );
    let _ = session.fence_exchange_before(&enter, fence_id(32), deadline.0);
    assert!(
        !session.saw_event(Duration::ZERO, |event| matches!(
            event,
            BridgeEvent::ReaderIdle(idle)
                if idle.prompt_generation == enter.prompt_generation
                    && idle.reader_revision == enter.reader_revision
        )),
        "a reader that still held input reported itself idle when the worker withheld its fence"
    );

    // Once the reader has let go of what it held, the retry the withheld frame left owed is taken:
    // it reports itself idle, which is the point the worker asks again at, and its next exchange is
    // acknowledged with every queue clear.
    for bytes in teardown {
        session.type_bytes(bytes);
    }
    let (_, event) = session.expect_event("an idle report once the reader let go", |event| {
        matches!(
            event,
            BridgeEvent::ReaderIdle(idle)
                if idle.prompt_generation == enter.prompt_generation
                    && idle.reader_revision == enter.reader_revision
        )
    });
    let BridgeEvent::ReaderIdle(idle) = event else {
        unreachable!()
    };
    assert!(
        idle.snapshot.queued_keys == U64::new(0) && idle.snapshot.pending_bytes == U64::new(0),
        "the report after the reader let go was not an idle reader's: {idle:?}"
    );
    let recovered = session.fence_exchange_before(&enter, fence_id(33), deadline.0);
    assert!(
        recovered.queues.all_drained() && recovered.snapshot.is_drained(),
        "the reader did not clear its queues once it let go of what it held: {:?} {:?}",
        recovered.queues,
        recovered.snapshot
    );
}

/// A session that loses its bridge keeps the fail-safe answer to an eligible gesture.
pub fn a_lost_bridge_does_not_restore_a_native_empty_prompt_end_of_file(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));
    let before = session.terminal_output().matches(DETACH_HINT).count();

    // The worker goes. Nothing can attribute a gesture any more, which is exactly when turning one
    // into a native end of file would close somebody's shell.
    session.close_endpoint();
    std::thread::sleep(Duration::from_millis(300));

    let before_key = session.written();
    session.type_bytes(CTRL_D);
    assert!(
        session
            .drew_after(before_key, DETACH_HINT, REPLY)
            .was_drawn(),
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

/// A gesture typed while the editor waits for the terminal's answer to a question of its own is
/// the person's gesture: it is consumed like any other that no fence attributes, not left to end
/// the shell as a native end of file.
///
/// An editor that has asked the terminal something does not act on keys until the answer comes, so
/// it keeps what the person types in its own queue meanwhile. The terminal here is made slow to
/// answer, and the key is typed once the editor has taken it, so the editor is waiting whatever
/// the speed of the machine.
pub fn a_gesture_typed_while_the_editor_waits_for_the_terminal_is_still_a_gesture(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();

    session.hold_terminal_answers();
    let before_command = session.written();
    assert!(session.answered("kr-ready"));
    let enter = session.next_prompt();
    // The prompt after the command asks the terminal where the cursor is and what it is, and the
    // editor waits for the answer to the last of those.
    assert!(
        session
            .drew_after(before_command, "\x1b[0c", REPLY)
            .was_drawn(),
        "the editor asked the terminal nothing at its next prompt:\n{}",
        session.terminal_output()
    );

    let before_key = session.written();
    session.type_bytes(CTRL_D);
    // The editor's own report of its queue says when it has the key: asking is an exchange the
    // editor answers while it waits for the terminal.
    let deadline = session.deadline_for(REPLY);
    loop {
        let held = session.fence_exchange_before(&enter, fence_id(41), deadline.0);
        if held.snapshot.queued_keys > U64::new(0) {
            break;
        }
        assert!(
            !deadline.passed(),
            "the editor never took the key it was typed:\n{}",
            session.terminal_output()
        );
    }

    session.release_terminal_answers();
    assert!(
        session
            .drew_after(before_key, DETACH_HINT, REPLY)
            .was_drawn(),
        "a gesture typed while the editor waited for the terminal printed no hint:\n{}",
        session.terminal_output()
    );
    assert!(
        session.alive(),
        "a gesture typed while the editor waited for the terminal ended the shell"
    );
}

/// A key a binding hands back to the editor is the editor's own input, even when the person typed
/// it while the editor waited for the terminal's answer: the gesture is only what the person's own
/// key press is, so this one is the editor's to deal with and not a hint's.
///
/// `self-insert` bound to a sequence that ends in the gesture replays the whole sequence, and the
/// terminal is made slow to answer so that both keys are set aside first.
pub fn a_gesture_a_binding_hands_back_is_the_editors_own_input(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start_with_profile(
        &package,
        Profile {
            after_configuration: "bind ctrl-x,ctrl-d self-insert\n",
            ..Profile::ORDINARY
        },
    );
    session.first_prompt();
    session.forget_events();

    session.hold_terminal_answers();
    let before_command = session.written();
    assert!(session.answered("kr-ready"));
    let enter = session.next_prompt();
    assert!(
        session
            .drew_after(before_command, "\x1b[0c", REPLY)
            .was_drawn(),
        "the editor asked the terminal nothing at its next prompt:\n{}",
        session.terminal_output()
    );

    let before_keys = session.written();
    session.type_bytes(b"\x18\x04");
    let deadline = session.deadline_for(REPLY);
    loop {
        let held = session.fence_exchange_before(&enter, fence_id(42), deadline.0);
        if held.snapshot.queued_keys >= U64::new(2) {
            break;
        }
        assert!(
            !deadline.passed(),
            "the editor never took both keys it was typed:\n{}",
            session.terminal_output()
        );
    }

    // From here the editor either consumes the replayed gesture and says so with its hint, or
    // leaves it to its own handling, which at an empty prompt ends the shell: the first of the two
    // to happen is the answer.
    session.release_terminal_answers();
    let deadline = session.deadline_for(REPLY);
    let hinted = session.expecting_the_bridge_to_go(|session| {
        loop {
            if !session.alive() {
                break false;
            }
            if session
                .drew_after(before_keys, DETACH_HINT, Duration::ZERO)
                .was_drawn()
            {
                break true;
            }
            assert!(
                !deadline.passed(),
                "the editor neither hinted nor ended:\n{}",
                session.terminal_output()
            );
            session.pump(Duration::from_millis(25));
        }
    });
    assert!(
        !hinted,
        "a gesture a binding handed back was taken for one the person made:\n{}",
        session.terminal_output()
    );
}

/// `takeover-partial-escape` and `takeover-quoted-insertion`: the cancellation the contract needs.
pub fn a_takeover_ends_a_pending_key_wait_and_keeps_the_buffer(kind: ShellKind) {
    // A reader with no key wait a takeover can end is not one this case is for, and a suite that
    // named it for one would pass it without a check.
    let wait = pending_wait(kind).unwrap_or_else(|| {
        panic!(
            "{} has no key wait a takeover can end, so this case is not one of its",
            kind.as_str()
        )
    });
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    // Whatever the wait needs runs before the reader it is measured against starts.
    let fallback = print_assembled(kind, "kr-ready");
    let ready = wait.prepare.unwrap_or((&fallback, "kr-ready"));
    assert!(session.run(ready.0, ready.1));
    let enter = session.next_prompt();

    // The reader is left waiting for another key, with text already typed.
    session.type_bytes(dialect(kind).arithmetic.0.as_bytes());
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
            assert!(session.run(command, marker));
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
    let line = dialect(kind).arithmetic;
    assert!(
        session.finish_line(line.0, line.1, line.2),
        "the edit buffer did not survive the cancellation:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-07.34 and KR-REQ-07.35: a cancellation ends what it found, and nothing else.
pub fn a_cancellation_that_ends_nothing_leaves_the_next_sequence_alone(kind: ShellKind) {
    let package = Package::built(kind);
    let wait = pending_wait(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    // Whatever the wait needs runs before the reader it is measured against starts.
    let fallback = print_assembled(kind, "kr-ready");
    let ready = wait
        .as_ref()
        .and_then(|wait| wait.prepare)
        .unwrap_or((&fallback, "kr-ready"));
    assert!(session.run(ready.0, ready.1));
    let enter = session.next_prompt();

    // The reader is waiting for a key with nothing in progress, so there is nothing of the old
    // lease's for this cancellation to end and nothing for it to throw away.
    if dialect(kind).answers_at_the_next_step {
        session.type_bytes(dialect(kind).arithmetic.0.as_bytes());
        std::thread::sleep(Duration::from_millis(120));
    } else {
        // The reader's own report that it holds the text is the proof that it has dealt with the
        // keys, so no report of theirs is still to come when the count below is first read.
        session.type_text(dialect(kind).arithmetic.0.as_bytes());
    }
    session.forget_events();
    let reports = session.idle_reports;
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
        // A reader that left its wait for a pass boundary reads the endpoint there before it is
        // back in the wait and reports itself idle: twice in Zsh, once in Fish, not at all in Bash.
        // So the third exchange is the first one that is read in the wait, after the report, and
        // the count of reports the session was told of, which a wait taking events off the queue
        // does not lower, is read once it has been answered.
        let _ = session.fence_exchange(&enter, fence_id(19));
        let _ = session.fence_exchange(&enter, fence_id(18));
        let _ = session.fence_exchange(&enter, fence_id(17));
        assert_eq!(
            session.idle_reports, reports,
            "the reader left a wait that the cancellation had nothing to end"
        );
    }

    // The person then starts a sequence of their own, and the mailbox is read while it is
    // part-read. The cancellation before it is over, so the sequence is still the reader's to
    // finish rather than something that cancellation takes away.
    let Some(wait) = wait else {
        // Nothing of this package's runs on this reader's thread while the editor is inside one of
        // its own nested reads, so there is no part-read sequence to leave alone, and the half
        // above is the whole of this case for it.
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
    let line = dialect(kind).arithmetic;
    assert!(
        session.finish_line(line.0, line.1, line.2),
        "the edit buffer did not survive the cancellations:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-07.72: the person's own IGNORE_EOF setting is left as they set it.
pub fn the_ignore_eof_setting_is_left_as_the_person_set_it(kind: ShellKind) {
    // The report puts its answer together out of pieces, so the word appears on the screen because
    // the setting was still on and not because the line that asked was echoed back. A shell with no
    // end-of-file setting of its own is not one this case is for, and a suite that named it for one
    // would pass it without a check.
    let (turn_on, report) = match kind {
        ShellKind::Zsh => (
            "setopt ignoreeof; printf '%s%s\\n' kr-ignoreeof- set",
            "[[ -o ignoreeof ]] && printf '%s%s\\n' kr-ignoreeof= on",
        ),
        ShellKind::Bash => (
            "set -o ignoreeof; printf '%s%s\\n' kr-ignoreeof- set",
            "[[ -o ignoreeof ]] && printf '%s%s\\n' kr-ignoreeof= on",
        ),
        ShellKind::Fish | ShellKind::PowerShell => panic!(
            "{} has no end-of-file setting of its own, so this case is not one of its",
            kind.as_str()
        ),
    };
    let package = Package::built(kind);
    let mut session = Session::start(&package);
    session.first_prompt();
    session.forget_events();
    assert!(session.run(turn_on, "kr-ignoreeof-set"));

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
    assert!(
        session.run(report, "kr-ignoreeof=on"),
        "the person's ignoreeof setting did not survive:\n{}",
        session.terminal_output()
    );
    assert!(session.alive());
}

/// KR-REQ-07.85: the package declares the baseline the specification names.
pub fn the_package_declares_the_baseline_the_specification_names(kind: ShellKind) {
    let package = Package::built(kind);
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
    // The two packages whose editors read the terminal's bytes as keys share the classifier of the
    // host's answers; fish's reader drops them itself.
    for name in ["kr_bridge_reply.h", "kr_bridge_reply.c"] {
        let zsh = std::fs::read_to_string(root.join("zsh/src").join(name))
            .unwrap_or_else(|error| panic!("shells/zsh/src/{name}: {error}"));
        let bash = std::fs::read_to_string(root.join("bash/src").join(name))
            .unwrap_or_else(|error| panic!("shells/bash/src/{name}: {error}"));
        assert_eq!(
            strip_licence_note(&zsh),
            strip_licence_note(&bash),
            "shells/zsh/src/{name} and shells/bash/src/{name} have drifted apart"
        );
    }
}

/// The chords the committed `psreadline-chord-gesture` scenario offers: the configured one and the
/// other one it says is the editor's own, and how many offers there are and of what kind.
///
/// Read from the scenario rather than restated, so a scenario that changes fails the drive that
/// stands for it. The third offer is a terminal byte handed to a chord configuration, which is the
/// contract's own case of an input the reader reports by a different kind of name.
fn chord_scenario() -> (String, String) {
    let scenario = scenarios()
        .into_iter()
        .find(|scenario| scenario.id == "psreadline-chord-gesture")
        .expect("the chord scenario is committed");
    let Script::PreEof(script) = scenario.script else {
        panic!("the chord scenario drives the pre-EOF decision");
    };
    let EofGesture::Chord { keys: configured } = script.view.gesture.clone() else {
        panic!("the chord scenario configures a chord");
    };
    let offers: Vec<_> = script
        .steps
        .iter()
        .filter_map(|step| match step {
            PreEofStep::Offer {
                context, expect, ..
            } => Some((context.key.clone(), expect.clone())),
            _ => None,
        })
        .collect();
    let [
        (first, PreEofDecision::SubmitDetach(_)),
        (second, PreEofDecision::Native { .. }),
        (third, PreEofDecision::Native { .. }),
    ] = offers.as_slice()
    else {
        panic!(
            "the chord scenario offers the configured chord, another chord and a byte: {offers:?}"
        );
    };
    assert_eq!(
        first,
        &PressedKey::chord(configured.clone()),
        "the first offer is the configured chord"
    );
    let PressedKey::Chord { keys: other } = second else {
        panic!("the second offer is another chord");
    };
    assert_ne!(other, &configured);
    assert_eq!(
        third,
        &PressedKey::byte(DEFAULT_EOF_BYTE),
        "the third offer is the terminal's byte"
    );
    (configured, other.clone())
}

/// The bytes a terminal sends for `Ctrl+<letter>`.
fn control_bytes(chord: &str) -> Vec<u8> {
    let letter = chord
        .strip_prefix("Ctrl+")
        .and_then(|rest| rest.chars().next())
        .filter(char::is_ascii_lowercase)
        .unwrap_or_else(|| panic!("{chord} is not a control chord this drive can type"));
    vec![letter as u8 - b'a' + 1]
}

/// KR-REQ-07.73, and `psreadline-chord-gesture`: the configured chord carries the detach, and any
/// other key, the terminal's end-of-file byte included, is the editor's own.
///
/// The scenario offers three inputs to a session whose gesture is a chord: the chord, another chord
/// and the terminal's byte. Through a pseudo-terminal the editor reports every key as a chord, so
/// the terminal's byte is one chord among the others and the scenario's chord `Ctrl+d` is that byte
/// too. The offers are therefore driven in two sessions, each a real key press: with the scenario's
/// chord configured, the other chord is the editor's own and the configured one detaches; with the
/// other chord configured, the terminal's byte is not the gesture and the editor does what it does
/// with it, which at an empty prompt is to end the shell.
pub fn the_configured_chord_carries_the_detach_and_any_other_key_is_the_editors_own(
    kind: ShellKind,
) {
    let (configured, other) = chord_scenario();
    let package = Package::built(kind);

    // The scenario's own configuration. Another chord goes first and the configured one after it,
    // on the one reader thread, so the detach arriving with no decision before it is the other
    // chord having decided nothing.
    let mut session = Session::start_with_gesture(
        &package,
        EofGesture::Chord {
            keys: configured.clone(),
        },
    );
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));
    let (enter, fence) = session.fenced_prompt(1);
    session.type_bytes(&control_bytes(&other));
    session.type_bytes(&control_bytes(&configured));
    let (id, event) = session.expect_event("eof_detach", |event| {
        matches!(event, BridgeEvent::EofDetach(_))
    });
    let BridgeEvent::EofDetach(detach) = event else {
        unreachable!()
    };
    assert_eq!(detach.fence_id, fence.fence_id);
    assert_eq!(detach.prompt_generation, enter.prompt_generation);
    assert!(
        session.no_managed_decision_before(1),
        "{other} is not the configured chord and decided something before {configured} did"
    );
    session.answer_event(id, detached(attachment_id(1)));
    assert!(
        session.alive(),
        "the configured chord ended the shell instead of detaching an attachment"
    );
    drop(session);

    // The other chord configured, so the terminal's byte is not the gesture.
    let mut session = Session::start_with_gesture(
        &package,
        EofGesture::Chord {
            keys: other.clone(),
        },
    );
    session.first_prompt();
    session.forget_events();
    assert!(session.answered("kr-ready"));
    let (_enter, _fence) = session.fenced_prompt(1);
    session.type_bytes(&[DEFAULT_EOF_BYTE]);
    assert!(
        session.ended_within(REPLY),
        "the editor kept the terminal's byte, which is not the configured chord, instead of doing \
         what it does with it at an empty prompt:\n{}",
        session.terminal_output()
    );
    assert!(
        session.no_managed_decision_before(0),
        "the terminal's byte was decided on as if it were the configured chord {other}"
    );
}

/// The question a person's own startup asks before anything of the package's entry has run, in the
/// shell's own words for reading a line, and the words it prints once it has an answer.
///
/// `read` in Bash and Fish, `vared` in Zsh, whose line editor is what a startup prompt would use,
/// and `Read-Host` in PowerShell. The marker is put together by the shell from what it read, so
/// the terminal echoing the answer cannot make it appear.
fn startup_question(kind: ShellKind) -> &'static str {
    match kind {
        ShellKind::Zsh => {
            "kr_answer=\nvared -p 'ASK> ' kr_answer\nprint -r -- \"kr-answer-<${kr_answer}>\"\n"
        }
        ShellKind::Bash => {
            "read -r -p 'ASK> ' kr_answer\nprintf 'kr-answer-<%s>\\n' \"$kr_answer\"\n"
        }
        ShellKind::Fish => "read -P 'ASK> ' kr_answer\nprintf 'kr-answer-<%s>\\n' $kr_answer\n",
        ShellKind::PowerShell => {
            "$kr_answer = Read-Host 'ASK>'\nWrite-Host \"kr-answer-<$kr_answer>\"\n"
        }
    }
}

/// KR-REQ-07.23: a startup prompt reads its answer once the bridge is authenticated, and the
/// session reports ready only after the profile that asked has finished.
///
/// Section 7 lets a native startup prompt receive normal input in its own non-primary context
/// while the profiles run, and forbids the deadlock a worker would make of a profile that asks a
/// question: rich launch and a ready session wait for full qualification after the profile. Here
/// the person's startup asks before the package's entry has run. The bridge must already be
/// connected and its handshake accepted, or nothing here could type the answer; the phase the
/// worker holds is then authenticated, which takes input and neither launches nor reports ready;
/// the answer reaches the prompt; and the entry's activation, which is the profile having
/// finished, is what qualifies the session.
pub fn a_startup_prompt_reads_its_answer_and_readiness_waits_for_the_profile(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start_with_profile(
        &package,
        Profile {
            after_configuration: startup_question(kind),
            ..Profile::ORDINARY
        },
    );
    // Authenticated and ABI-checked: the handshake this returns from is the worker's own decision
    // over the hello, and the reader it declared is the one the package's record names.
    assert_eq!(
        session.hello.shell.editor_abi,
        package.record["shell"]["editor_abi"]
            .as_str()
            .expect("the package records its editor ABI"),
        "the bridge declared a reader other than the one the package was built as"
    );
    let mut phase = PhaseGate::unauthenticated();
    assert!(
        !phase.accepts_external_input(),
        "input is refused before the bridge has authenticated"
    );
    assert!(phase.authenticated(kind));
    assert!(phase.accepts_external_input());
    assert!(!phase.reports_ready());
    assert!(!phase.permits_launch());

    // The prompt is on the terminal, waiting, and the profile that asked has not finished, so the
    // activation that follows it cannot have come.
    assert!(
        session.drew_after(0, "ASK>", REPLY).was_drawn(),
        "the startup prompt was not drawn:\n{}",
        session.terminal_output()
    );
    assert!(
        !session.saw_event(Duration::from_millis(500), |event| matches!(
            event,
            BridgeEvent::HooksActivated(_)
        )),
        "the hooks were reported live while the profile was still waiting for its answer"
    );
    assert!(!phase.reports_ready());

    session.type_bytes(b"the-answer\r");
    assert!(
        session
            .drew_after(0, "kr-answer-<the-answer>", REPLY)
            .was_drawn(),
        "the answer did not reach the startup prompt:\n{}",
        session.terminal_output()
    );

    // The profile has finished, so the activation comes, and then the first reader of the shell.
    let entry = session.first_prompt();
    assert!(
        phase.qualified(),
        "the activation qualifies an authenticated session"
    );
    assert!(phase.reports_ready());
    assert!(phase.permits_launch());
    assert_eq!(
        entry.reader_context,
        kr_protocol::root::ReaderContext::Primary
    );
    assert!(session.alive());
}

/// KR-REQ-07.23: a profile that asks and is never answered leaves the session authenticated and
/// not ready, and the shell can be ended within its bound rather than left hanging.
///
/// Nothing here decides by how long the shell was left. The prompt is drawn, so the profile is
/// waiting for its answer, and a shell waiting for input cannot go on to activate anything: what is
/// asserted is that the phase is what it was and the shell ends when asked.
pub fn a_startup_prompt_nobody_answers_holds_readiness_and_does_not_hang_the_shell(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let mut session = Session::start_with_profile(
        &package,
        Profile {
            after_configuration: startup_question(kind),
            ..Profile::ORDINARY
        },
    );
    let mut phase = PhaseGate::unauthenticated();
    assert!(phase.authenticated(kind));
    assert!(session.drew_after(0, "ASK>", REPLY).was_drawn());
    assert!(
        !session.saw_event(Duration::from_millis(500), |event| matches!(
            event,
            BridgeEvent::HooksActivated(_)
        )),
        "a profile nobody answered went on to report the hooks live"
    );
    assert!(
        !phase.reports_ready(),
        "an unanswered profile reported ready"
    );
    assert!(!phase.permits_launch());
    assert!(
        phase.accepts_external_input(),
        "and it still takes the answer"
    );
    assert!(session.alive());

    // The shell ends when asked, inside the harness's own bound for a shell to stop.
    let ending = Deadline::after(REPLY);
    drop(session);
    assert!(
        !ending.passed(),
        "the shell that was waiting for an answer did not stop within its bound"
    );
}

/// The report a profile makes when it fails after the startup files, in the shell's own words: the
/// package's own report, which is what its entry makes when the integration cannot go on.
fn failing_after_startup(kind: ShellKind) -> Profile<'static> {
    match kind {
        ShellKind::Zsh | ShellKind::Bash => Profile {
            after_configuration: "builtin kr-bridge lost post-startup-failure 'the profile failed after its startup files'\n",
            entry: false,
            after_entry: "",
            all_hosts: "",
            terminal_eof: None,
        },
        // The fish reader is only there once the first prompt is, and the entry waits for it.
        ShellKind::Fish => Profile {
            after_configuration: "function __kr_fail --on-event fish_prompt\n    functions --erase __kr_fail\n    builtin kr-bridge lost post-startup-failure 'the profile failed after its startup files'\nend\n",
            entry: false,
            after_entry: "",
            all_hosts: "",
            terminal_eof: None,
        },
        // The module is loaded by the entry, so the report follows it.
        ShellKind::PowerShell => Profile {
            after_configuration: "",
            entry: true,
            after_entry: "Write-KalaReachLoss -Loss post_startup_failure -Detail 'the profile failed after its startup files'\n",
            all_hosts: "",
            terminal_eof: None,
        },
    }
}

/// KR-REQ-07.23, KR-REQ-07.22: a profile that fails after the startup files closes the session that
/// was being created, and carries its diagnostics.
pub fn a_profile_that_fails_after_startup_closes_the_creating_session_with_its_diagnostics(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let mut session = Session::start_with_profile(&package, failing_after_startup(kind));
    let mut phase = PhaseGate::unauthenticated();
    assert!(phase.authenticated(kind));
    let (_, event) = session.expect_event("integration_lost", |event| {
        matches!(event, BridgeEvent::IntegrationLost(_))
    });
    let BridgeEvent::IntegrationLost(lost) = event else {
        unreachable!()
    };
    assert_eq!(lost.loss, IntegrationLoss::PostStartupFailure);
    assert_eq!(
        lost.detail, "the profile failed after its startup files",
        "the diagnostics the session closes with"
    );
    let decision = phase.lost(lost.loss);
    assert!(
        decision.closes_session,
        "a loss before the session qualified must close the session that was being created"
    );
    assert!(!phase.reports_ready());
}

/// KR-REQ-07.23, KR-REQ-07.85: an editor that is no longer the qualified one when the profile has
/// finished is diagnosed at activation, rather than reported live on the strength of the editor the
/// module found when it loaded.
///
/// The module loads first in the profile so that the bridge is open before the profile asks
/// anything, which leaves the profile free to change the editor afterwards. The profile here does:
/// it puts an editor in the module's place that keeps no key queue the module can read, and the
/// session says the integration failed after the startup files instead of activating.
pub fn an_editor_the_profile_replaced_is_diagnosed_when_the_hooks_activate(kind: ShellKind) {
    let package = Package::built(kind);
    let mut session = Session::start_with_profile(
        &package,
        Profile {
            after_configuration: "",
            entry: true,
            after_entry: "Add-Type -IgnoreWarnings -WarningAction SilentlyContinue -TypeDefinition 'public class KrEditorGone { }'\n\
                          & (Get-Module KalaReach.ShellBridge) { param($editor) $script:SingletonField = $null; $script:QueuedKeysField = $null; $script:Rl = $editor } ([KrEditorGone])\n",
            all_hosts: "",
            terminal_eof: None,
        },
    );
    let mut phase = PhaseGate::unauthenticated();
    assert!(phase.authenticated(kind));
    let (_, event) = session.expect_event("integration_lost", |event| {
        matches!(event, BridgeEvent::IntegrationLost(_))
    });
    let BridgeEvent::IntegrationLost(lost) = event else {
        unreachable!()
    };
    assert_eq!(lost.loss, IntegrationLoss::PostStartupFailure);
    assert!(
        lost.detail.contains("keeps no reader queue"),
        "the diagnostics name what changed: {}",
        lost.detail
    );
    assert!(phase.lost(lost.loss).closes_session);
    // The loss closes the session that was being created, so nothing the reader says after it
    // claims the hooks are live. What it sent before its first step is what the session was told
    // after the loss.
    let hooks = std::cell::Cell::new(false);
    session.expect_event("the first editor entry", |event| {
        hooks.set(hooks.get() || matches!(event, BridgeEvent::HooksActivated(_)));
        matches!(event, BridgeEvent::EditorEnter(_))
    });
    assert!(
        !hooks.get(),
        "the hooks were reported live after a loss that closes the session"
    );
}

/// KR-REQ-07.23: a question the profile every host reads asks takes its answer through the worker,
/// which is the first profile PowerShell runs of the person's own.
///
/// The bridge has to be open before anything in that profile asks, and the entry that opens it is
/// the first thing in it, below what PowerShell requires to come first. The question is the person's
/// own, asked before the profile of the host the shell runs in has been read, and the answer has to
/// reach it while the session is authenticated and not yet ready.
pub fn a_question_in_the_profile_every_host_reads_takes_its_answer_through_the_worker(
    kind: ShellKind,
) {
    let package = Package::built(kind);
    let mut session = Session::start_with_profile(
        &package,
        Profile {
            all_hosts: startup_question(kind),
            ..Profile::ORDINARY
        },
    );
    let mut phase = PhaseGate::unauthenticated();
    assert!(
        phase.authenticated(kind),
        "the bridge authenticated while the first profile was waiting for its answer"
    );
    assert!(
        session.drew_after(0, "ASK>", REPLY).was_drawn(),
        "the question was not drawn:\n{}",
        session.terminal_output()
    );
    assert!(
        !phase.reports_ready(),
        "a session whose profile is waiting for an answer reported ready"
    );
    session.type_bytes(b"the-answer\r");
    assert!(
        session
            .drew_after(0, "kr-answer-<the-answer>", REPLY)
            .was_drawn(),
        "the answer did not reach the question the first profile asked:\n{}",
        session.terminal_output()
    );
    // Both profiles have finished, so the hooks activate and the reader is the first one.
    session.first_prompt();
    assert!(phase.qualified());
    assert!(phase.reports_ready());
}

/// The profile text that changes what the host calls to read a line, in each shape a person writes
/// it in, and the shapes that leave the editor's own function in front of the module.
#[derive(Clone, Copy)]
pub enum ReadLineChange {
    /// The profile leaves the host's entry point alone.
    None,
    /// A function of the same name that reads a line some other way.
    Replaced,
    /// A function of the same name that calls what was there before it.
    Wrapped,
    /// A function of the same name that calls the editor directly, which is what a wrapper some
    /// tool's setup adds does.
    CallsTheEditor,
    /// An alias of the same name, which the host resolves ahead of a function.
    Aliased,
    /// The editor imported again, which puts its own function back in front of the module.
    EditorImportedAgain,
    /// A function defined inside the editor's own module scope, which reports the editor as the
    /// module it belongs to and is not the editor's function.
    InsideTheEditorsModule,
    /// The editor's own function replaced where it lives, inside its module scope, and the module
    /// imported again so that the replacement is what it exports. It is the very object the editor
    /// exports and it is not the editor's function.
    ReplacedInsideTheEditorsModule,
    /// The editor imported again so that it brings in no function of the host's entry point and
    /// takes none of the module's, which leaves the module in front of the editor's own function.
    ImportedAgainBesideTheModule,
}

impl ReadLineChange {
    fn profile(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Replaced => "function PSConsoleHostReadLine { [Console]::ReadLine() }\n",
            Self::Wrapped => {
                "$kr_inner = ${function:PSConsoleHostReadLine}\n\
                 function PSConsoleHostReadLine { & $kr_inner }\n"
            }
            Self::CallsTheEditor => {
                "function PSConsoleHostReadLine { [Microsoft.PowerShell.PSConsoleReadLine]::ReadLine($host.Runspace, $ExecutionContext, $?) }\n"
            }
            Self::Aliased => "Set-Alias PSConsoleHostReadLine Get-Date -Scope Global\n",
            Self::EditorImportedAgain => "Import-Module PSReadLine -Force\n",
            Self::InsideTheEditorsModule => {
                "& (Get-Module PSReadLine) { function global:PSConsoleHostReadLine { [Console]::ReadLine() } }\n"
            }
            Self::ReplacedInsideTheEditorsModule => {
                "& (Get-Module PSReadLine) { Set-Item function:script:PSConsoleHostReadLine -Value { [Console]::ReadLine() } }\n\
                 Import-Module PSReadLine\n"
            }
            Self::ImportedAgainBesideTheModule => "Import-Module PSReadLine -Force -NoClobber\n",
        }
    }

    /// Whether the module's own function still runs after this, inside the profile's.
    fn reader_still_runs(self) -> bool {
        matches!(self, Self::Wrapped)
    }

    /// Whether the reader is still the qualified editor's after this, so the session carries on.
    fn leaves_the_qualified_reader(self) -> bool {
        matches!(
            self,
            Self::None | Self::EditorImportedAgain | Self::ImportedAgainBesideTheModule
        )
    }
}

/// KR-REQ-07.23, KR-REQ-07.85: a profile that changes the host's read-line entry point is diagnosed
/// by name at the end of the last profile, and one that leaves the qualified reader in front of the
/// host is not.
///
/// The module goes in front of the entry point when it loads, first in the first profile, so a
/// function of the same name that a later profile defines takes the host's calls away from it and
/// the reader never runs: nothing would say so, and the session would stay authenticated and not
/// ready. The entry at the end of the last profile asks the module whether its own function is still
/// the one the host calls. What decides is whether it is the editor's own function, not what its text or its module's name says: a
/// function that replaces the entry point, one that wraps the one before it, one that calls the
/// editor directly and an alias are all the host's reader being somebody else's rather than the
/// editor the package was qualified against, and each is refused by the name the integration loss
/// carries. The session that was being created closes with it, and is never reported to have its
/// hooks live afterwards. The editor imported again puts its own function back, which is the
/// qualified reader, so the module goes back in front of it and the session carries on. So does the
/// editor imported again beside the module, which brings in nothing the module's function stands in
/// front of. The editor's own function replaced where it lives, in its module scope, and imported
/// again is the very object the editor exports and is not the editor's function, so it is refused.
pub fn a_profile_that_changes_the_read_line_entry_point_is_diagnosed_by_name(kind: ShellKind) {
    let package = Package::built(kind);

    for change in [
        ReadLineChange::None,
        ReadLineChange::EditorImportedAgain,
        ReadLineChange::ImportedAgainBesideTheModule,
        ReadLineChange::Replaced,
        ReadLineChange::Wrapped,
        ReadLineChange::CallsTheEditor,
        ReadLineChange::Aliased,
        ReadLineChange::InsideTheEditorsModule,
        ReadLineChange::ReplacedInsideTheEditorsModule,
    ] {
        let mut session = Session::start_with_profile(
            &package,
            Profile {
                after_entry: change.profile(),
                ..Profile::ORDINARY
            },
        );
        let mut phase = PhaseGate::unauthenticated();
        assert!(phase.authenticated(kind));
        if change.leaves_the_qualified_reader() {
            // The control: nothing is lost, the hooks go live, and the first reader is the module's.
            let lost = std::cell::Cell::new(false);
            session.expect_event("hooks_activated", |event| {
                lost.set(lost.get() || matches!(event, BridgeEvent::IntegrationLost(_)));
                matches!(event, BridgeEvent::HooksActivated(_))
            });
            assert!(
                !lost.get(),
                "a profile that left the qualified reader in front of the host was diagnosed"
            );
            session.expect_event("the first editor entry", |event| {
                matches!(event, BridgeEvent::EditorEnter(_))
            });
            continue;
        }
        let (_, event) = session.expect_event("integration_lost", |event| {
            matches!(event, BridgeEvent::IntegrationLost(_))
        });
        let BridgeEvent::IntegrationLost(lost) = event else {
            unreachable!()
        };
        assert_eq!(lost.loss, IntegrationLoss::PostStartupFailure);
        assert!(
            lost.detail.starts_with("reader_replaced: ")
                && lost.detail.contains("read-line entry point"),
            "the diagnostics carry the name and say what changed: {}",
            lost.detail
        );
        assert!(
            phase.lost(lost.loss).closes_session,
            "a loss before the session qualified closes the session that was being created"
        );
        // Where the module's own function still runs, inside the profile's, its reader goes on to
        // its first step. What it sends before that is what the session was told after the loss, and
        // none of it says the hooks are live.
        if change.reader_still_runs() {
            let hooks = std::cell::Cell::new(false);
            session.expect_event("the first editor entry", |event| {
                hooks.set(hooks.get() || matches!(event, BridgeEvent::HooksActivated(_)));
                matches!(event, BridgeEvent::EditorEnter(_))
            });
            assert!(
                !hooks.get(),
                "the hooks were reported live after a loss that closes the session"
            );
        }
    }
}

/// A writer that keeps what it is given, for a case that reads what the terminal answered.
struct Recorded(Arc<Mutex<Vec<u8>>>);

impl Write for Recorded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the record is not poisoned")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A query the editor sends that reaches the terminal in two reads is answered once, and the same
/// query sent twice is answered twice.
///
/// A pseudo-terminal hands over what has arrived, and on a loaded machine that can be the first
/// bytes of a query and then the rest of it. An editor that asked where the cursor is waits for the
/// reply before it reads a key, so a query the terminal did not recognise because it came in pieces
/// left the editor waiting for ever, and the line typed at it was never drawn.
pub fn a_terminal_query_the_output_splits_across_reads_is_answered_once(
    whole: &[u8],
    reply: &[u8],
) {
    for cut in 1..whole.len() {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let terminal = TerminalInput::of(Box::new(Recorded(Arc::clone(&kept))));
        let mut queries = TerminalQueries::new(Arc::new(AtomicUsize::new(0)));
        queries.answer(&[b"prompt> ", &whole[..cut]].concat(), &terminal);
        queries.answer(&[&whole[cut..], b" and more"].concat(), &terminal);
        assert_eq!(
            *kept.lock().expect("the record is not poisoned"),
            reply,
            "the query {whole:?} cut after {cut} bytes was not answered exactly once"
        );
    }
    // The control: a query that is not cut is answered once, and one that came in a read of its own
    // after another is answered again.
    let kept = Arc::new(Mutex::new(Vec::new()));
    let terminal = TerminalInput::of(Box::new(Recorded(Arc::clone(&kept))));
    let answered_to = Arc::new(AtomicUsize::new(0));
    let mut queries = TerminalQueries::new(Arc::clone(&answered_to));
    queries.answer(whole, &terminal);
    queries.answer(b"nothing asked", &terminal);
    queries.answer(whole, &terminal);
    assert_eq!(
        *kept.lock().expect("the record is not poisoned"),
        [reply, reply].concat(),
        "two queries, each in one read, are two answers and text that asks nothing is none"
    );
    // Where the last answered cursor query ends is where it ended in the whole of the output.
    if whole == b"\x1b[6n" {
        assert_eq!(
            answered_to.load(Ordering::Acquire),
            whole.len() + b"nothing asked".len() + whole.len(),
            "the editor is known to have been answered after everything the terminal showed before it"
        );
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

/// What one scan of a process's writable memory found.
#[cfg(target_os = "linux")]
struct Scan {
    /// The lines of the memory map whose mapping holds the bytes looked for.
    copies: Vec<String>,
    /// The lines of the mappings the scan could not read to their end.
    unread: Vec<String>,
    /// How many bytes were read.
    bytes: u64,
    /// How many pages the kernel refused to read that hold nothing: guard pages, and pages of a
    /// region that was unmapped after the scan listed it.
    guards: u64,
}

/// The size of a page on this machine, from the kernel's own report on a mapping of this process.
///
/// # Panics
///
/// Panics when the report cannot be read, because a scan that does not know its pages cannot step
/// over one.
#[cfg(target_os = "linux")]
fn page_size() -> u64 {
    std::fs::read_to_string("/proc/self/smaps")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("KernelPageSize:"))
                .and_then(|rest| rest.split_whitespace().next()?.parse::<u64>().ok())
        })
        .map(|kilobytes| kilobytes * 1024)
        .expect("the kernel reports its page size in /proc/self/smaps")
}

/// The kernel's entry for the page at `address` in `/proc/<pid>/pagemap`, the file `pagemap` is
/// open on, or nothing when the entry cannot be read.
#[cfg(target_os = "linux")]
fn page_entry(pagemap: &mut std::fs::File, address: u64, page: u64) -> Option<u64> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut entry = [0u8; 8];
    pagemap
        .seek(SeekFrom::Start(address / page * 8))
        .and_then(|_| pagemap.read_exact(&mut entry))
        .ok()
        .map(|()| u64::from_le_bytes(entry))
}

/// Whether a page's entry in `/proc/<pid>/pagemap` says the page can hold nothing a process wrote.
///
/// That is a page the kernel marks as a guard (bit 58, Linux 6.15 and later, for a guard installed
/// with `MADV_GUARD_INSTALL`), and a page that is neither in memory (bit 63) nor swapped out
/// (bit 62): a process that wrote to a page leaves it in one of the two, so such a page holds no
/// copy of anything. The second is also what an address that is no longer mapped looks like.
///
/// Linux 6.13 and 6.14 can install a guard and have no bit for it, and report one as swapped out
/// (bit 62), which this takes for memory that holds data. Nothing in the entry or in the mapping's
/// `Swap` figure tells a guard from a page whose swap entry is a migration, a device page or a
/// poisoned one, so the page is left unread and [`unread_note`] says why when it matters. A guard
/// is installed in a thread stack by glibc 2.42 and later, so the pair that fails a correct
/// package is those kernels with that library.
#[cfg(target_os = "linux")]
fn entry_holds_nothing(entry: u64) -> bool {
    (entry >> 58) & 1 == 1 || (entry >> 62) & 0b11 == 0
}

/// What to add to a report of unread memory when the kernel is one that cannot tell a guard page
/// from swapped memory: Linux 6.13 and 6.14 install guards and report them as swapped out. Nothing
/// when the kernel is another, or its release cannot be read.
#[cfg(target_os = "linux")]
fn unread_note() -> String {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut numbers = release
        .trim()
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<u32>().ok());
    match (numbers.next(), numbers.next()) {
        (Some(6), Some(13 | 14)) => format!(
            "\nthis kernel ({}) can install a guard page and reports it as swapped-out memory, so the scan cannot tell it from memory it must read; the case needs Linux 6.15 or later to separate them",
            release.trim()
        ),
        _ => String::new(),
    }
}

/// Looks for `needle` in every mapping of a running process that is both readable and writable,
/// which is where a static buffer, the heap and the stack are.
///
/// A Linux process can be read through `/proc/<pid>/mem` by the process that started it. A mapping
/// that cannot be read to its end is reported and not skipped, because a scan that stopped early
/// finds nothing and proves nothing.
///
/// # Panics
///
/// Panics when the process's memory map or memory cannot be opened.
#[cfg(target_os = "linux")]
fn scan_memory(pid: u32, needle: &[u8]) -> Scan {
    scan_memory_listing(pid, needle, "")
}

/// [`scan_memory`] over the process's memory map with `extra` lines added to it. A process that is
/// running changes its map between the reading of the map and the reading of its memory, and a
/// line for a region that is not mapped is how a case makes the scan meet that on purpose.
#[cfg(target_os = "linux")]
fn scan_memory_listing(pid: u32, needle: &[u8], extra: &str) -> Scan {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .unwrap_or_else(|error| panic!("the memory map of process {pid} cannot be read: {error}"))
        + extra;
    let mut memory = std::fs::File::open(format!("/proc/{pid}/mem"))
        .unwrap_or_else(|error| panic!("the memory of process {pid} cannot be opened: {error}"));
    let mut pagemap = std::fs::File::open(format!("/proc/{pid}/pagemap"))
        .unwrap_or_else(|error| panic!("the page map of process {pid} cannot be opened: {error}"));
    let page = page_size();
    let mut scan = Scan {
        copies: Vec::new(),
        unread: Vec::new(),
        bytes: 0,
        guards: 0,
    };
    let mut chunk = vec![0u8; 1 << 20];
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (Some(range), Some(permissions)) = (fields.next(), fields.next()) else {
            continue;
        };
        if !permissions.starts_with("rw") {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        let mut offset = start;
        let mut carried: Vec<u8> = Vec::new();
        let mut found = false;
        let mut refused = String::new();
        while offset < end {
            let want =
                usize::try_from(end - offset).map_or(chunk.len(), |left| left.min(chunk.len()));
            let outcome = memory
                .seek(SeekFrom::Start(offset))
                .and_then(|_| memory.read(&mut chunk[..want]));
            let read = match outcome {
                Ok(read) => read,
                // A guard page of a thread's stack stays inside a mapping that reads as writable,
                // a mapping can be unmapped between the listing and the read, and the kernel
                // answers both with an input/output error, as it does a page it cannot read.
                // A page is stepped over only when the kernel's page map says it holds nothing a
                // process wrote, and any other refusal ends the mapping unread.
                Err(error)
                    if error.raw_os_error() == Some(5)
                        && page_entry(&mut pagemap, offset, page)
                            .is_some_and(entry_holds_nothing) =>
                {
                    scan.guards += 1;
                    offset += page;
                    carried.clear();
                    continue;
                }
                Err(error) => {
                    refused = format!(" (at {offset:x}: {error})");
                    0
                }
            };
            if read == 0 {
                break;
            }
            scan.bytes += read as u64;
            carried.extend_from_slice(&chunk[..read]);
            if carried.windows(needle.len()).any(|window| window == needle) {
                scan.copies.push(line.to_owned());
                found = true;
                break;
            }
            let keep = needle.len().saturating_sub(1).min(carried.len());
            carried.drain(..carried.len() - keep);
            offset += read as u64;
        }
        if !found && offset < end {
            scan.unread.push(format!("{line}{refused}"));
        }
    }
    scan
}

/// KR-REQ-07.40: a compiled bridge holds no copy of the bootstrap secret once the handshake is
/// accepted.
///
/// The secret is decoded into the bridge's own buffer, used once for the proof and read by nothing
/// afterwards. The case starts a shell with a secret it knows, waits for the first prompt (which
/// follows the acceptance and the wipe, by a condition and not by a delay) and looks for the
/// secret's 32 bytes in every writable mapping of the shell's process. The scan is wider than the
/// bridge's buffer, so a copy anywhere else in the process fails the case too. It must read every
/// mapping to its end with the shell still running, so a shell that has gone, or memory that could
/// not be read, fails the case instead of passing it. Reading another process's memory is a Linux
/// facility, so the case is a stated skip elsewhere. The first thing it does is look for the same
/// bytes in its own process, so a scan that cannot find a secret fails the case too.
///
/// # Panics
///
/// Panics when the scan cannot find the bytes where they are known to be, cannot read the shell,
/// or finds them in the shell.
pub fn the_bootstrap_secret_does_not_outlive_the_accepted_handshake(kind: ShellKind) {
    #[cfg(target_os = "linux")]
    {
        let secret = bootstrap_secret();
        assert!(
            !scan_memory(std::process::id(), &secret).copies.is_empty(),
            "the memory scan cannot find a secret it is given, so it proves nothing about a shell"
        );
        let package = Package::built(kind);
        let mut session = Session::start(&package);
        session.first_prompt();
        let pid = session
            .child_pid()
            .expect("the shell's process has an identifier");
        assert!(
            session.alive(),
            "the shell had gone before its memory was read"
        );
        let scan = scan_memory(pid, &secret);
        assert!(
            session.alive(),
            "the shell went while its memory was read, so the scan may have read nothing"
        );
        assert!(
            scan.unread.is_empty() && scan.bytes > 0,
            "{} bytes of the {} shell's memory were read ({} pages that hold nothing stepped over), and these writable mappings were not read to their end:\n{}{}",
            scan.bytes,
            kind.as_str(),
            scan.guards,
            scan.unread.join("\n"),
            unread_note()
        );
        assert!(
            scan.copies.is_empty(),
            "the {} bridge still holds the bootstrap secret after the handshake was accepted, in:\n{}",
            kind.as_str(),
            scan.copies.join("\n")
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = kind;
        record(
            "bootstrap-secret-scan-skipped.txt",
            "another process's memory is read through /proc on Linux; this host is not Linux\n",
        );
    }
}

/// KR-REQ-07.40: the PowerShell bridge holds no secret bytes once the handshake is accepted.
///
/// The module's array is cleared in place and replaced with an empty one, and the case reads the
/// length the module is left with after the first prompt. The runtime's own copies of the
/// environment variable's text and of the key an HMAC object held are outside what the module can
/// reach, and outside what this case reads.
///
/// # Panics
///
/// Panics when the module still holds bytes.
pub fn the_powershell_bootstrap_secret_is_cleared_once_the_handshake_is_accepted() {
    let package = Package::built(ShellKind::PowerShell);
    let mut session = Session::start(&package);
    session.first_prompt();
    let probe = "Write-Output ('kr-secret-length=' + (& (Get-Module KalaReach.ShellBridge) { $script:Kr.Secret.Length }))";
    assert!(
        session.run(probe, "kr-secret-length=0"),
        "the module still holds secret bytes after the handshake was accepted:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-07.40: a mapping that goes while the scan is reading is not memory the scan left unread.
///
/// A shell that runs threads maps and unmaps small regions, such as the alternate signal stack of
/// a thread that ends, and the scan reads the process's map before it reads the memory it lists.
/// A region listed and gone by then answers the read with an input/output error, as a page the
/// kernel guards does, and the scan has to tell the two apart from memory it truly cannot read: a
/// region that is no longer mapped holds nothing a process could have written. The case adds a
/// line to the map for a region that is not mapped, as one unmapped after the listing is, and asks
/// that the scan does not report it.
///
/// # Panics
///
/// Panics when the scan reports the unmapped region as unread.
#[cfg(target_os = "linux")]
pub fn a_mapping_that_goes_while_the_scan_reads_is_not_memory_left_unread() {
    // A region the map lists and the process no longer has: nothing is mapped at this address,
    // which is what a region unmapped after the listing looks like to the read. The address is
    // below the lowest one a process may map, so it is inside every address space, the small ones
    // of some Arm kernels included, and no thread of the test can come to map it.
    let gone = "10000-12000 rw-p 00000000 00:00 0\n";
    let scan = scan_memory_listing(std::process::id(), b"a needle of no consequence", gone);
    assert!(
        !scan.unread.iter().any(|line| line.starts_with("10000-")),
        "the scan reports a region that was unmapped before it was read as unread memory: {:?}",
        scan.unread
    );
}

/// KR-REQ-07.40: the PowerShell bridge decodes the secret into one byte array and clears that
/// array.
///
/// A function's output is enumerated into the pipeline, so a byte array returned bare reaches its
/// caller as an array of boxed bytes and the buffer the decoder made is left uncleared behind it.
/// The case decodes a known secret in the module's own scope, puts the result where the module
/// keeps its secret, clears it as the module does, and reads the result it decoded: it has to be
/// the byte array itself, and every byte of it has to be gone.
///
/// # Panics
///
/// Panics when the decoder returns anything but a byte array, or the clear leaves a byte.
pub fn the_powershell_secret_is_decoded_into_one_byte_array_that_is_cleared() {
    let package = Package::built(ShellKind::PowerShell);
    let module = package
        .directory()
        .join("modules/KalaReach.ShellBridge/KalaReach.ShellBridge.psd1")
        .display()
        .to_string();
    let script = format!(
        "$ErrorActionPreference = 'Stop'; Import-Module '{module}'; \
         & (Get-Module KalaReach.ShellBridge) {{ \
           $decoded = ConvertFrom-KrBase64Url 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'; \
           $script:Kr.Secret = $decoded; \
           $type = $decoded.GetType().FullName; $length = $decoded.Length; \
           Clear-KrSecret; \
           $left = @($decoded | Where-Object {{ $_ -ne 0 }}).Count; \
           Write-Output \"kr-decoded=[$type|$length|$left]\" }}"
    );
    let asked = package.ask(&script);
    let said = String::from_utf8_lossy(&asked.stdout).into_owned();
    assert!(
        said.lines()
            .any(|line| line == "kr-decoded=[System.Byte[]|32|0]"),
        "the decoded secret is not one byte array of 32 bytes with none left after the clear:\n{said}\n{}",
        String::from_utf8_lossy(&asked.stderr)
    );
}

/// KR-REQ-07.16: a case that asks the package's host something starts it as a session does, with
/// the launch environment the package's record holds.
///
/// A package that builds no shell names the host the person has, and the record holds what that
/// host needs in its environment: a host that is framework-dependent does not start without the
/// location of its runtime. The host here is a stand-in outside the package that answers with the
/// location it was started with, and the record gives it one that nothing else in the environment
/// could.
///
/// # Panics
///
/// Panics when the stand-in is not started with the record's location.
pub fn the_packages_host_is_started_with_the_launch_environment_its_record_holds() {
    let root = tempfile::tempdir().expect("a directory");
    let directory = root.path().join("powershell/identity-1");
    let modules = directory.join("modules");
    std::fs::create_dir_all(&modules).expect("the package's modules");
    std::fs::create_dir_all(directory.join("startup")).expect("the package's startup entry");
    std::fs::write(directory.join("startup/kr-profile.ps1"), b"# entry\n").expect("the entry");
    let host = root.path().join("host/PowerShell/7/pwsh");
    std::fs::create_dir_all(host.parent().expect("a directory")).expect("the host's directory");
    let text = host.with_file_name("pwsh.text");
    std::fs::write(
        &text,
        b"#!/bin/sh\nprintf 'kr-runtime=[%s]\\n' \"$DOTNET_ROOT\"\n",
    )
    .expect("the stand-in host");
    kr_ipc::testing::place_program(&text, &host);
    let record = serde_json::json!({
        "identity": "identity-1",
        "shell": {
            "kind": "powershell",
            "executable": host,
            "upstream_version": "7.6.7",
            "editor_abi": "psreadline-2.4",
            "integration_version": "1",
            "patches": [],
            "modules": [{
                "name": "KalaReach.ShellBridge",
                "search_path": modules,
                "editor_abi": "psreadline-2.4",
            }],
        },
        "startup_entry": { "file": "startup/kr-profile.ps1" },
        "launch": {
            "environment": { "DOTNET_ROOT": "/opt/dotnet-the-record-holds" },
            "search_paths": { "PSModulePath": [modules] },
        },
    });
    std::fs::write(directory.join("kr-shell-identity.json"), record.to_string())
        .expect("the record");
    let package = Package {
        kind: ShellKind::PowerShell,
        identity: "identity-1".to_owned(),
        executable: host,
        startup_entry: directory.join("startup/kr-profile.ps1"),
        module_directory: modules,
        record,
    };

    let asked = package.ask("the stand-in answers whatever it is asked");
    let said = String::from_utf8_lossy(&asked.stdout);
    assert!(
        said.contains("kr-runtime=[/opt/dotnet-the-record-holds]"),
        "the host was not started with the location of the runtime its record holds: {said:?}"
    );
}

/// KR-REQ-07.37: an error in the PowerShell handshake leaves the bridge unregistered, with no
/// secret and no connection.
///
/// A worker's answer that does not decode is an error inside the handshake, and the host's error
/// preference decides whether the code after it runs. Whatever runs, a bridge the worker never
/// accepted must not be marked registered or managed, because the reader then acts as a managed
/// shell for a worker that has not admitted it. The case answers the bridge's opening frame with
/// one that cannot be decoded and reads the module's state once the shell is answering.
///
/// # Panics
///
/// Panics when the module is registered or managed, keeps a connection, or holds secret bytes.
pub fn an_error_in_the_powershell_handshake_leaves_the_bridge_unregistered() {
    let package = Package::built(ShellKind::PowerShell);
    let mut session = Session::start_answered_with_a_frame_that_does_not_decode(&package);
    let probe = "Write-Output ('kr-bridge=' + (& (Get-Module KalaReach.ShellBridge) { '{0}/{1}/{2}/{3}' -f $script:Kr.Registered, $script:Kr.Managed, ($null -eq $script:Kr.Socket), $script:Kr.Secret.Length }))";
    assert!(
        session.run(probe, "kr-bridge=False/False/True/0"),
        "the module is registered or managed, keeps its connection or holds secret bytes after an \
         answer it could not decode:\n{}",
        session.terminal_output()
    );
}

/// KR-REQ-07.37: a hello the worker refuses is reported to the person, with the reason the worker
/// gave, and the shell goes on without the integration.
///
/// A worker that refuses a shell's hello writes the refusal and ends the connection. A module that
/// takes the end for the whole answer starts the person's shell with no integration and says
/// nothing of why, which the person cannot tell from an installation that was never set up. The
/// case answers the opening frame of a PowerShell with the worker's own refusal of a shell whose
/// start time it reads a unit away from the one the shell named, which is a process mismatch, and
/// ends the connection behind it as the worker does. The shell then runs a command of the person's,
/// and the terminal has to show the reason by its name.
///
/// # Panics
///
/// Panics when the reason is not shown, or the shell does not answer.
pub fn a_hello_the_worker_refuses_is_reported_to_the_person() {
    let package = Package::built(ShellKind::PowerShell);
    let mut session = Session::start_refused(&package);
    assert!(
        session.answered("kr-after-refusal"),
        "the shell did not answer after the worker refused its hello:\n{}",
        session.terminal_output()
    );
    assert!(
        session.terminal_output().contains("process_mismatch"),
        "the person was not told why the worker refused the shell's hello:\n{}",
        session.terminal_output()
    );
}

/// The libraries a native file asks the loader for, by the name or path the file records.
///
/// On macOS they are the load commands that name a library the file needs, read with `otool -l`:
/// the listing `otool -L` prints starts with the install name of a dynamic library, which is the
/// file's own name and no dependency, so a loadable module would be taken for needing itself. On
/// Linux they are the `NEEDED` entries of the dynamic section.
///
/// # Panics
///
/// Panics when the platform's tool for reading them is missing or fails, because a list that
/// could not be read proves nothing.
fn linked_libraries(file: &Path) -> Vec<String> {
    if cfg!(target_os = "macos") {
        // Every architecture of a universal file, not the one the host would run.
        let output = std::process::Command::new("otool")
            .args(["-arch", "all", "-l"])
            .arg(file)
            .output()
            .expect("otool to run");
        assert!(
            output.status.success(),
            "otool could not read {}",
            file.display()
        );
        let mut needed = false;
        let mut libraries = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let mut words = line.split_whitespace();
            match (words.next(), words.next()) {
                (Some("cmd"), Some(command)) => {
                    needed = [
                        "LC_LOAD_DYLIB",
                        "LC_LOAD_WEAK_DYLIB",
                        "LC_REEXPORT_DYLIB",
                        "LC_LOAD_UPWARD_DYLIB",
                        "LC_LAZY_LOAD_DYLIB",
                    ]
                    .contains(&command);
                }
                (Some("name"), Some(path)) if needed => {
                    libraries.push(path.to_owned());
                    needed = false;
                }
                _ => {}
            }
        }
        libraries
    } else {
        let output = std::process::Command::new("readelf")
            .arg("-d")
            .arg(file)
            .output()
            .expect("readelf to run");
        assert!(
            output.status.success(),
            "readelf could not read {}",
            file.display()
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.contains("(NEEDED)"))
            .filter_map(|line| line.split('[').nth(1))
            .filter_map(|rest| rest.split(']').next())
            .map(str::to_owned)
            .collect()
    }
}

/// Every Mach-O or ELF file under a package, found by its magic number and not by its name: a
/// zsh module is a `.so`, a bash loadable has no extension, and a text file beside them is none.
/// A link is not followed, so a file is read once under the name it is installed by.
fn native_files(directory: &Path) -> Vec<std::path::PathBuf> {
    use std::io::Read as _;

    let mut found = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(next) = pending.pop() {
        let entries = std::fs::read_dir(&next)
            .unwrap_or_else(|error| panic!("{} cannot be listed: {error}", next.display()));
        for entry in entries {
            let entry = entry.expect("a directory entry");
            let kind = entry.file_type().expect("a file type");
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                let mut magic = [0u8; 4];
                let read = std::fs::File::open(entry.path())
                    .and_then(|mut file| file.read_exact(&mut magic))
                    .is_ok();
                let native = read
                    && (magic == *b"\x7fELF"
                        || matches!(
                            u32::from_be_bytes(magic),
                            0xfeed_face
                                | 0xfeed_facf
                                | 0xcefa_edfe
                                | 0xcffa_edfe
                                | 0xcafe_babe
                                | 0xcafe_babf
                        ));
                if native {
                    found.push(entry.path());
                }
            }
        }
    }
    found.sort();
    found
}

/// The directories a native file asks the loader to search besides the system's: the `LC_RPATH`
/// commands of a Mach-O file and the `RPATH` and `RUNPATH` entries of an ELF file, one per path.
///
/// # Panics
///
/// Panics when the platform's tool for reading them is missing or fails.
fn search_paths(file: &Path) -> Vec<String> {
    if cfg!(target_os = "macos") {
        let output = std::process::Command::new("otool")
            .args(["-arch", "all", "-l"])
            .arg(file)
            .output()
            .expect("otool to run");
        assert!(
            output.status.success(),
            "otool could not read {}",
            file.display()
        );
        let mut rpath = false;
        let mut paths = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let line = line.trim();
            if let Some(command) = line.strip_prefix("cmd ") {
                rpath = command == "LC_RPATH";
            } else if let (true, Some(path)) = (rpath, line.strip_prefix("path ")) {
                paths.push(path.split(" (offset").next().unwrap_or(path).to_owned());
                rpath = false;
            }
        }
        paths
    } else {
        let output = std::process::Command::new("readelf")
            .arg("-d")
            .arg(file)
            .output()
            .expect("readelf to run");
        assert!(
            output.status.success(),
            "readelf could not read {}",
            file.display()
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.contains("(RPATH)") || line.contains("(RUNPATH)"))
            .filter_map(|line| line.split('[').nth(1))
            .filter_map(|rest| rest.split(']').next())
            .flat_map(|list| list.split(':'))
            .map(str::to_owned)
            .collect()
    }
}

/// The dynamic loader an ELF file asks for, which is a path and not a library name, or nothing for
/// a Mach-O file and for an ELF file that asks for none.
///
/// # Panics
///
/// Panics when `readelf` is missing or fails.
fn interpreter(file: &Path) -> Option<String> {
    if cfg!(target_os = "macos") {
        return None;
    }
    let output = std::process::Command::new("readelf")
        .arg("-l")
        .arg(file)
        .output()
        .expect("readelf to run");
    assert!(
        output.status.success(),
        "readelf could not read {}",
        file.display()
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.split("Requesting program interpreter: ").nth(1))
        .and_then(|rest| rest.split(']').next())
        .map(str::to_owned)
}

/// Whether a path has a `..` in it, which leaves the directory it starts in.
fn leaves_its_directory(path: &str) -> bool {
    path.split('/').any(|part| part == "..")
}

/// Whether a macOS library name is the system's own: under `/usr/lib` or `/System/Library`, with no
/// `..` in it. `/System/Volumes/Data` is where the firmlinks of `/opt` and `/usr/local` lead, so a
/// name under it is a library of the build machine's own volume.
fn is_a_macos_system_library(name: &str) -> bool {
    (name.starts_with("/usr/lib/") || name.starts_with("/System/Library/"))
        && !leaves_its_directory(name)
}

/// Whether a search path stays in the package: it is relative to the file that names it.
fn is_relative_to_the_file(path: &str) -> bool {
    ["$ORIGIN", "${ORIGIN}", "@loader_path", "@executable_path"]
        .iter()
        .any(|base| path == *base || path.starts_with(&format!("{base}/")))
        && !leaves_its_directory(path)
}

/// The dynamic loaders a Linux package may ask for: the standard path of the C library's loader on
/// x86-64 and on Arm.
const LINUX_INTERPRETERS: [&str; 2] = ["/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1"];

/// The libraries a Linux package may need of the machine it runs on: the C library and its
/// companions, the compiler's runtime and the terminal-information library. A shell is built where
/// it is built and run where it is installed, so a name outside this list is a library the build
/// machine happened to have, and the feature that asked for it is switched off in the manifest.
const LINUX_LIBRARIES: [&str; 12] = [
    "libc.so.6",
    "libm.so.6",
    "libdl.so.2",
    "libpthread.so.0",
    "librt.so.1",
    "libutil.so.1",
    "libgcc_s.so.1",
    "libtinfo.so.6",
    "libncurses.so.6",
    "libncursesw.so.6",
    "ld-linux-x86-64.so.2",
    "ld-linux-aarch64.so.1",
];

/// KR-REQ-07.88: a built shell depends on no library that the machine which built it happened to
/// have.
///
/// A package is requalified once and distributed to machines that are not the builder. A build
/// that asks the machine for a library (the PCRE2 of the Fish build, the message-catalogue library
/// of Bash on a runner whose package manager keeps it beside the compiler's default paths) names
/// it in the executable or in a module, and the package then fails to start, or to load a module,
/// where there is none. The case reads the load commands or dynamic section of every native file
/// of the package: on macOS each library is one of the system's (`/usr/lib` or `/System/Library`,
/// with no `..`), and on Linux each is one of a short list of names. A directory the loader is
/// asked to search is relative to the file, and the dynamic loader of a Linux file is the standard
/// one.
///
/// # Panics
///
/// Panics when the executable names no library at all, or when a native file of the package names
/// a library of the build machine.
pub fn the_shell_links_no_library_of_the_machine_that_built_it(kind: ShellKind) {
    let package = Package::built(kind);
    let directory = package.directory();
    assert!(
        !linked_libraries(&package.executable).is_empty(),
        "no dependency was read from {}",
        package.executable.display()
    );
    let files = native_files(directory);
    assert!(
        files.contains(&package.executable),
        "the package's executable {} was not found among its native files {files:?}",
        package.executable.display()
    );
    for file in files {
        for library in linked_libraries(&file) {
            let system = if cfg!(target_os = "macos") {
                is_a_macos_system_library(&library)
            } else {
                LINUX_LIBRARIES.contains(&library.as_str())
            };
            assert!(
                system,
                "{} depends on {library}, a library the build machine had and the machine the \
                 package is installed on may not",
                file.display()
            );
        }
        for path in search_paths(&file) {
            assert!(
                is_relative_to_the_file(&path),
                "{} asks the loader to search {path}, a directory of the build machine",
                file.display()
            );
        }
        if let Some(loader) = interpreter(&file) {
            assert!(
                LINUX_INTERPRETERS.contains(&loader.as_str()),
                "{} asks for the loader {loader}, which is not the standard one of the C library",
                file.display()
            );
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod pages {
    use super::entry_holds_nothing;

    /// KR-REQ-07.40: the scan steps over a page only when the kernel says nothing was ever written
    /// to it, and never over a page that is in memory or swapped out.
    #[test]
    fn a_page_holds_nothing_only_when_it_is_a_guard_or_neither_in_memory_nor_swapped() {
        assert!(
            entry_holds_nothing(1 << 58),
            "a page the kernel marks as a guard"
        );
        assert!(
            entry_holds_nothing(0),
            "a page that is neither in memory nor swapped out"
        );
        assert!(
            entry_holds_nothing(1 << 55),
            "a page with only its soft-dirty bit set is still neither in memory nor swapped out"
        );
        assert!(!entry_holds_nothing(1 << 63), "a page that is in memory");
        assert!(!entry_holds_nothing(1 << 62), "a page that is swapped out");
        assert!(
            !entry_holds_nothing((1 << 63) | (1 << 61)),
            "a page that is in memory and file-backed or shared"
        );
    }
}

#[cfg(test)]
mod dependency_guards {
    use super::{is_a_macos_system_library, is_relative_to_the_file};

    /// KR-REQ-07.88: the names the dependency case lets through are the system's alone, and the
    /// ways round it that a path allows are refused.
    #[test]
    fn the_dependency_case_refuses_a_path_into_the_build_machines_volume_or_out_of_the_package() {
        for name in [
            "/usr/lib/libSystem.B.dylib",
            "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
        ] {
            assert!(is_a_macos_system_library(name), "{name} is the system's");
        }
        for name in [
            "/usr/local/opt/gettext/lib/libintl.8.dylib",
            "/System/Volumes/Data/opt/homebrew/opt/gettext/lib/libintl.8.dylib",
            "/usr/lib/../local/lib/libintl.8.dylib",
            "@rpath/libintl.8.dylib",
        ] {
            assert!(
                !is_a_macos_system_library(name),
                "{name} is not the system's"
            );
        }
        for path in [
            "$ORIGIN",
            "$ORIGIN/lib",
            "@loader_path/lib",
            "@executable_path/../lib",
        ] {
            let expected = !path.contains("..");
            assert_eq!(is_relative_to_the_file(path), expected, "{path}");
        }
        for path in [
            "/opt/homebrew/lib",
            "/usr/local/lib",
            "lib",
            "$ORIGINAL/lib",
        ] {
            assert!(
                !is_relative_to_the_file(path),
                "{path} is a directory of the build machine"
            );
        }
    }
}
