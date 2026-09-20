//! The cross-shell scenarios under `fixtures/shell-bridge/`.
//!
//! Each scenario is one JSON file: a named script, the requirement rows it demonstrates, the shell
//! packages that must reproduce it, and the exact outcome of every step. The expectations are
//! written from section 7 rather than captured from a run, so replaying them checks the contract
//! instead of recording whatever the code happened to do. Error codes and the hint text are written
//! out as literals for the same reason.
//!
//! Four kinds of script, because the contract has four decision points:
//!
//! * A **handshake** script drives [`decide_handshake`](crate::contract::transport::decide_handshake)
//!   and [`decide_activation`](crate::contract::transport::decide_activation): who is admitted, who
//!   is refused and with which named reason, and what a shell that inherited nothing does.
//! * A **fence** script drives [`FenceMachine`]: one stimulus per step at a stated clock reading,
//!   with the state, the fence, the held batches in order and the actions in order.
//! * A **pre-EOF** script drives [`BridgeFenceView`]: the detach condition, the gesture, the one
//!   hint per prompt, and what the bridge does when the worker refuses a submitted detach.
//! * A **launch** script drives [`decide_launch`]: the reader thread's own check of its buffer, its
//!   revisions and its deadline before anything is installed.
//!
//! [`replay`] runs one scenario and returns what did not match. The harness runs every committed
//! file through it, and each shell package's own tests run the same files against its bridge, so
//! "the packages agree with the worker" is a fact about one corpus rather than four opinions.

use kr_protocol::error::ErrorCode;
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{AttachmentId, InputLeaseEpoch, SessionId};
use kr_protocol::input::InterruptAction;
use kr_protocol::root::{
    AcceptedOrigin, CwdRevision, EditorBufferRevision, EditorBusyReason, EditorFence, EditorKeymap,
    EditorLeaveReason, EditorState, FenceAcknowledgement, FenceCause, FenceId, FenceState,
    KeyQueueSnapshot, LAUNCH_READER_BUDGET, LaunchCommand, PendingReaderInput, PromptGeneration,
    QueueDrainReport, ReaderContext, ReaderRevision, RootCommandAcceptedParams,
    RootEditorEnterParams, RootEditorLeaveParams, RootEofDetachParams, ShellLaunchParams,
    WithheldReason,
};
use kr_protocol::scalars::{Bytes, DurationMs, Nullable, U64, Uuid};
use serde::{Deserialize, Serialize};

use crate::contract::events::{
    BridgeFenceView, ConsumeReason, DEFAULT_EOF_BYTE, EofGesture, EofGestureChange, NativeReason,
    PreEofContext, PreEofDecision, PressedKey, ReaderIdle,
};
use crate::contract::fence::{
    ActionShape, AmbiguityReason, ContinuousMs, DetachRejection, DetachTarget, DiscardReason,
    EditorEntered, FenceInvalidation, FenceMachine, InputArrived, InputRef, InputRefusal,
    InterruptRequested, LaunchRequested, LeaseChanged, LeaseFault, LeaseView, ReaderIdled,
    StaleMessage, Stimulus,
};
use crate::contract::qualification::{
    BridgeAbi, CancellationMechanism, DetachCondition, DetachExclusion, FenceProofMechanism,
    InputSource, IntegrationLoss, LaunchDelivery, MailboxMechanism, PreEofMechanism,
    QualificationReason, ShellKind,
};
use crate::contract::requests::{
    CancellationReport, CancelledOperations, LaunchAccepted, LaunchDecision, LaunchMailboxRequest,
    LaunchRejection, LaunchRejectionReason, LaunchTransactionId, ReaderLaunchState, decide_launch,
};
use crate::contract::transport::{
    Activation, ActivationInputs, BridgeHello, HandshakeOutcome, ModuleEntry, ObservedPeer,
    PatchRevision, ProofVerdict, SecretLocation, ShellIdentity, SkipReason, WorkerExpectation,
    decide_activation, decide_handshake,
};

/// Where the committed scenarios live, relative to the repository root.
pub const FIXTURES_DIRECTORY: &str = "fixtures/shell-bridge";

/// One scenario.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// The scenario's name, which is also its file name without the extension.
    pub id: String,
    /// What it demonstrates, in one sentence.
    pub purpose: String,
    /// The requirement rows it covers.
    pub covers: Vec<String>,
    /// The shell packages that must reproduce it.
    pub shells: Vec<ShellKind>,
    /// The script.
    pub script: Script,
}

impl Scenario {
    /// Returns the file this scenario is committed as.
    #[must_use]
    pub fn file_name(&self) -> String {
        format!("{}.json", self.id)
    }
}

/// What a scenario drives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Script {
    /// The handshake and the activation decision.
    Handshake(HandshakeScript),
    /// The fence and detach state machine.
    Fence(FenceScript),
    /// The pre-EOF decision inside the bridge.
    PreEof(PreEofScript),
    /// The reader thread's launch decision.
    Launch(LaunchScript),
}

/// A handshake script.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeScript {
    /// What the worker knows before the first frame.
    pub expectation: WorkerExpectation,
    /// The hellos, each with the connection's own identity, the worker's verdict on the proof and
    /// the expected outcome.
    pub cases: Vec<HandshakeCase>,
    /// What a starting shell does before it opens a connection at all.
    pub activation: Vec<ActivationCase>,
}

/// One hello and what it should produce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeCase {
    /// The case's name.
    pub name: String,
    /// Who the kernel says is on the other end.
    pub peer: ObservedPeer,
    /// The hello.
    pub hello: BridgeHello,
    /// Whether the worker's own comparison of the proof succeeded.
    pub proof: ProofVerdict,
    /// What the worker knows, when this case needs something other than the script's.
    pub expectation: Option<WorkerExpectation>,
    /// The expected outcome.
    pub expect: HandshakeExpectation,
}

/// What an accepted handshake must carry back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedHandshake {
    /// The editor ABI the worker took.
    pub editor_abi: String,
    /// The hold the worker will apply to a reader transition or a launch.
    pub hold_ms: DurationMs,
    /// The gesture in force at acceptance.
    pub gesture: EofGesture,
    /// The hint an unattributable gesture prints, exactly as written.
    pub hint: String,
    /// Where the bridge keeps the bootstrap secret from now on.
    pub secret_location: SecretLocation,
    /// The variables it removes from the exported environment before it returns.
    pub unexport: Vec<String>,
}

/// What a handshake should produce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeExpectation {
    /// Registered as the session's root integration, with this acceptance.
    Accepted(AcceptedHandshake),
    /// Refused, with this reason and this error code.
    Refused {
        /// Why.
        reason: QualificationReason,
        /// The code the session reports.
        code: ErrorCode,
    },
}

/// One activation decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationCase {
    /// The case's name.
    pub name: String,
    /// What the starting shell can see.
    pub inputs: ActivationInputs,
    /// What it should do.
    pub expect: Activation,
}

/// A state-machine script.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceScript {
    /// The session.
    pub session_id: SessionId,
    /// The lease the machine starts with.
    pub lease: LeaseView,
    /// The steps, in order.
    pub steps: Vec<FenceStep>,
}

/// One step of a state-machine script.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceStep {
    /// The clock reading the stimulus arrives at.
    pub at_ms: ContinuousMs,
    /// What happened.
    pub stimulus: Stimulus,
    /// What must come of it.
    pub expect: Expect,
}

/// What a step must produce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    /// The state afterwards.
    pub state: FenceState,
    /// The fence afterwards.
    pub fence: Option<FenceId>,
    /// The batches still held, in arrival order.
    pub held: Vec<InputRef>,
    /// The actions, in order.
    pub actions: Vec<ActionShape>,
    /// What `kr detach` without an identifier resolves to, when the step asserts it.
    pub detach_target: Option<DetachTarget>,
}

/// A pre-EOF script.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreEofScript {
    /// The bridge's view of the fence at the start.
    pub view: BridgeFenceView,
    /// The steps, in order, against that one view.
    pub steps: Vec<PreEofStep>,
}

/// One step of a pre-EOF script.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreEofStep {
    /// The worker published a fence.
    Publish(EditorFence),
    /// The worker withheld or invalidated one.
    Invalidate,
    /// The line discipline's gesture changed.
    Gesture(EofGestureChange),
    /// The native hook offered a character.
    Offer {
        /// The case's name.
        name: String,
        /// What the hook was handed.
        context: PreEofContext,
        /// What the integration must decide.
        expect: PreEofDecision,
    },
    /// The worker refused a detach the bridge had submitted.
    DetachRefused {
        /// The case's name.
        name: String,
        /// The prompt the gesture belonged to.
        prompt_generation: PromptGeneration,
        /// The hint the bridge must print, if any.
        expect_hint: Option<String>,
    },
}

/// A reader-thread launch script.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchScript {
    /// The request in the mailbox.
    pub request: LaunchMailboxRequest,
    /// The reader states it is decided against.
    pub cases: Vec<LaunchCase>,
}

/// One reader state and the decision it must produce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchCase {
    /// The case's name.
    pub name: String,
    /// What the reader knows.
    pub state: ReaderLaunchState,
    /// What it must decide.
    pub expect: LaunchExpectation,
}

/// What a reader must decide.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchExpectation {
    /// Installed and submitted, leaving the buffer at this revision.
    Installed {
        /// What the reader installed, which must be the caller's own arguments: nothing quoted,
        /// joined or re-split on the way.
        installed: LaunchCommand,
        /// The buffer revision after the install.
        buffer_revision: EditorBufferRevision,
    },
    /// Refused, with nothing installed.
    Rejected {
        /// Why.
        reason: LaunchRejectionReason,
        /// The error the `shell.launch` caller receives.
        code: ErrorCode,
    },
}

/// What a replay found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Replay {
    /// How many expectations were compared.
    pub checks: usize,
    /// Every expectation that did not hold, named by scenario, step and field.
    pub failures: Vec<String>,
}

impl Replay {
    /// Returns true when every expectation held.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }

    fn check<T: PartialEq + core::fmt::Debug>(
        &mut self,
        scenario: &str,
        step: &str,
        field: &str,
        actual: &T,
        expected: &T,
    ) {
        self.checks += 1;
        if actual != expected {
            self.failures.push(format!(
                "{scenario} / {step}: {field} is {actual:?}, the scenario expects {expected:?}"
            ));
        }
    }
}

/// Replays one scenario and returns what did not match.
#[must_use]
pub fn replay(scenario: &Scenario) -> Replay {
    let mut replay = Replay::default();
    match &scenario.script {
        Script::Handshake(script) => replay_handshake(&scenario.id, script, &mut replay),
        Script::Fence(script) => replay_fence(&scenario.id, script, &mut replay),
        Script::PreEof(script) => replay_pre_eof(&scenario.id, script, &mut replay),
        Script::Launch(script) => replay_launch(&scenario.id, script, &mut replay),
    }
    replay
}

fn replay_handshake(id: &str, script: &HandshakeScript, replay: &mut Replay) {
    for case in &script.cases {
        let expectation = case.expectation.as_ref().unwrap_or(&script.expectation);
        let outcome = decide_handshake(expectation, &case.peer, &case.hello, case.proof);
        let actual = match &outcome {
            HandshakeOutcome::Accepted(accepted) => {
                HandshakeExpectation::Accepted(AcceptedHandshake {
                    editor_abi: accepted.editor_abi.clone(),
                    hold_ms: accepted.hold_ms,
                    gesture: accepted.gesture.clone(),
                    hint: accepted.hint.clone(),
                    secret_location: accepted.secret_location,
                    unexport: accepted.unexport.clone(),
                })
            }
            HandshakeOutcome::Refused(refused) => HandshakeExpectation::Refused {
                reason: refused.reason,
                code: refused.code(),
            },
        };
        replay.check(id, &case.name, "outcome", &actual, &case.expect);
    }
    for case in &script.activation {
        let actual = decide_activation(&case.inputs);
        replay.check(id, &case.name, "activation", &actual, &case.expect);
    }
}

fn replay_fence(id: &str, script: &FenceScript, replay: &mut Replay) {
    let mut machine = FenceMachine::new(script.session_id, script.lease);
    for (index, step) in script.steps.iter().enumerate() {
        let name = format!("step {}", index + 1);
        let outcome = machine.apply(step.at_ms, &step.stimulus);
        replay.check(id, &name, "state", &outcome.state, &step.expect.state);
        replay.check(id, &name, "fence", &outcome.fence, &step.expect.fence);
        replay.check(id, &name, "held", &outcome.held, &step.expect.held);
        replay.check(
            id,
            &name,
            "actions",
            &outcome.shapes(),
            &step.expect.actions,
        );
        if let Some(expected) = step.expect.detach_target {
            replay.check(
                id,
                &name,
                "detach target",
                &machine.detach_target(),
                &expected,
            );
        }
    }
}

fn replay_pre_eof(id: &str, script: &PreEofScript, replay: &mut Replay) {
    let mut view = script.view.clone();
    for step in &script.steps {
        match step {
            PreEofStep::Publish(fence) => view.publish(fence.clone()),
            PreEofStep::Invalidate => view.invalidate(),
            PreEofStep::Gesture(change) => view.observe_gesture(change),
            PreEofStep::Offer {
                name,
                context,
                expect,
            } => {
                let decision = view.decide(context);
                replay.check(id, name, "decision", &decision, expect);
            }
            PreEofStep::DetachRefused {
                name,
                prompt_generation,
                expect_hint,
            } => {
                let hint = view.detach_refused(*prompt_generation);
                replay.check(id, name, "hint", &hint, expect_hint);
            }
        }
    }
}

fn replay_launch(id: &str, script: &LaunchScript, replay: &mut Replay) {
    for case in &script.cases {
        let actual = match decide_launch(&script.request, &case.state) {
            LaunchDecision::Accepted(accepted) => LaunchExpectation::Installed {
                installed: accepted.installed.clone(),
                buffer_revision: accepted.buffer_revision,
            },
            LaunchDecision::Rejected(rejected) => LaunchExpectation::Rejected {
                reason: rejected.reason,
                code: rejected.reason.code(),
            },
        };
        replay.check(id, &case.name, "decision", &actual, &case.expect);
    }
}

/// Returns every committed scenario, in file-name order.
#[must_use]
pub fn scenarios() -> Vec<Scenario> {
    let mut scenarios = vec![
        handshake_accept(),
        handshake_reject(),
        enter_fence_acknowledge_detach(),
        detach_condition_exclusions(),
        takeover_partial_escape(),
        takeover_quoted_insertion(),
        takeover_vi_motion(),
        takeover_incomplete_chord(),
        takeover_macro(),
        takeover_destructive_cancellation(),
        attachment_removed_during_exchange(),
        deadline_meets_departure(),
        detach_at_the_launch_deadline(),
        integration_lost(),
        launch_confirmation_lost(),
        takeover_receipt_superseded(),
        two_outstanding_confirmations(),
        timeout_editor_entry(),
        timeout_takeover(),
        timeout_launch(),
        launch_installed(),
        launch_reader_decisions(),
        launch_cancelled_by_leave(),
        launch_cancelled_by_prior_input(),
        launch_cancelled_by_lease_change(),
        launch_cancelled_by_buffer_revision(),
        detach_during_launch(),
        eof_stale_fence(),
        eof_missing_fence(),
        eof_repeated_after_detach(),
        eof_after_detach_succession(),
        veof_change(),
        veof_disabled(),
        psreadline_chord_gesture(),
        acceptance_mixed_context(),
        acceptance_read_builtin(),
        editor_leave_boundaries(),
        retry_at_entry_and_leave(),
        interrupt_bypasses_the_hold(),
        outside_state_bypass(),
        closing_rejects_input(),
    ];
    scenarios.sort_by(|left, right| left.id.cmp(&right.id));
    scenarios
}

/// Returns every scenario as the file name and the exact bytes it is committed as.
#[must_use]
pub fn rendered_files() -> Vec<(String, String)> {
    scenarios()
        .iter()
        .map(|scenario| (scenario.file_name(), render(scenario)))
        .collect()
}

/// Renders one scenario exactly as it is committed.
///
/// # Panics
///
/// Panics when a scenario cannot be serialised, which would mean one of its own types is malformed
/// rather than a runtime condition.
#[must_use]
pub fn render(scenario: &Scenario) -> String {
    let mut text = serde_json::to_string_pretty(scenario).expect("a scenario is serialisable");
    text.push('\n');
    text
}

// ----- identities and builders the scenarios share ---------------------------------------------

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([0x11; 16]))
}

fn attachment_a() -> AttachmentId {
    AttachmentId::new(Uuid::from_bytes([0xA1; 16]))
}

fn attachment_b() -> AttachmentId {
    AttachmentId::new(Uuid::from_bytes([0xB2; 16]))
}

fn fence(index: u8) -> FenceId {
    FenceId::new(Uuid::from_bytes([0xF0 + index; 16]))
}

fn transaction(index: u8) -> LaunchTransactionId {
    LaunchTransactionId::new(Uuid::from_bytes([0x70 + index; 16]))
}

fn root_process() -> ProcessStartIdentity {
    ProcessStartIdentity::new(4242, ProcessStartSource::MacosProcBsdInfo, 900)
}

fn child_process() -> ProcessStartIdentity {
    ProcessStartIdentity::new(4243, ProcessStartSource::MacosProcBsdInfo, 901)
}

fn every_shell() -> Vec<ShellKind> {
    ShellKind::ALL.to_vec()
}

fn unix_shells() -> Vec<ShellKind> {
    vec![ShellKind::Zsh, ShellKind::Bash, ShellKind::Fish]
}

fn covers(rows: &[&str]) -> Vec<String> {
    rows.iter().map(|row| (*row).to_owned()).collect()
}

fn editor(
    revision: u64,
    empty: bool,
    pending: PendingReaderInput,
    keymap: EditorKeymap,
) -> EditorState {
    EditorState {
        buffer_revision: EditorBufferRevision::new(revision),
        buffer_empty: empty,
        keymap,
        pending,
    }
}

fn empty_editor(revision: u64) -> EditorState {
    editor(
        revision,
        true,
        PendingReaderInput::NONE,
        EditorKeymap::Emacs,
    )
}

fn typed_editor(revision: u64) -> EditorState {
    editor(
        revision,
        false,
        PendingReaderInput::NONE,
        EditorKeymap::Emacs,
    )
}

fn enter(prompt: u64, revision: u64, candidate: u8) -> Stimulus {
    enter_in(prompt, revision, candidate, ReaderContext::Primary)
}

fn enter_in(prompt: u64, revision: u64, candidate: u8, context: ReaderContext) -> Stimulus {
    Stimulus::EditorEntered(EditorEntered {
        params: RootEditorEnterParams {
            session_id: session(),
            root_process: root_process(),
            prompt_generation: PromptGeneration::new(prompt),
            reader_revision: ReaderRevision::new(revision),
            reader_context: context,
            editor: empty_editor(1),
            cwd_revision: CwdRevision::new(2),
        },
        candidate_fence: fence(candidate),
    })
}

fn leave(prompt: u64, revision: u64, reason: EditorLeaveReason) -> Stimulus {
    Stimulus::EditorLeft(RootEditorLeaveParams {
        session_id: session(),
        prompt_generation: PromptGeneration::new(prompt),
        reader_revision: ReaderRevision::new(revision),
        reason,
    })
}

fn acknowledgement(
    candidate: u8,
    prompt: u64,
    revision: u64,
    queues: QueueDrainReport,
    snapshot: KeyQueueSnapshot,
    state: EditorState,
) -> Stimulus {
    Stimulus::FenceAcknowledged(FenceAcknowledgement {
        fence_id: fence(candidate),
        reader_context: ReaderContext::Primary,
        prompt_generation: PromptGeneration::new(prompt),
        reader_revision: ReaderRevision::new(revision),
        queues,
        snapshot,
        editor: state,
        cwd_revision: CwdRevision::new(2),
    })
}

fn drained(candidate: u8, prompt: u64, revision: u64, state: EditorState) -> Stimulus {
    acknowledgement(
        candidate,
        prompt,
        revision,
        QueueDrainReport::CLEAR,
        KeyQueueSnapshot::drained(),
        state,
    )
}

/// A drained acknowledgement from a reader that says which context it is reading in.
fn drained_in(
    candidate: u8,
    prompt: u64,
    revision: u64,
    state: EditorState,
    context: ReaderContext,
) -> Stimulus {
    let Stimulus::FenceAcknowledged(mut acknowledgement) =
        drained(candidate, prompt, revision, state)
    else {
        unreachable!("a drained acknowledgement is one")
    };
    acknowledgement.reader_context = context;
    Stimulus::FenceAcknowledged(acknowledgement)
}

fn idle(prompt: u64, revision: u64, candidate: u8) -> Stimulus {
    Stimulus::ReaderIdled(ReaderIdled {
        idle: ReaderIdle {
            session_id: session(),
            prompt_generation: PromptGeneration::new(prompt),
            reader_revision: ReaderRevision::new(revision),
            reader_context: ReaderContext::Primary,
            snapshot: KeyQueueSnapshot::drained(),
            editor: empty_editor(1),
            cwd_revision: CwdRevision::new(2),
        },
        candidate_fence: fence(candidate),
    })
}

fn input(label: &str, attachment: AttachmentId, epoch: u64, bytes: u64) -> Stimulus {
    Stimulus::InputArrived(InputArrived {
        input: InputRef::new(label),
        attachment_id: attachment,
        epoch: InputLeaseEpoch::new(epoch),
        bytes: U64::new(bytes),
    })
}

fn lease_change(
    epoch: u64,
    holder: Option<AttachmentId>,
    candidate: u8,
    discarded: u64,
) -> Stimulus {
    Stimulus::LeaseChanged(LeaseChanged {
        lease: LeaseView {
            epoch: InputLeaseEpoch::new(epoch),
            holder,
        },
        discarded_bytes: U64::new(discarded),
        candidate_fence: fence(candidate),
    })
}

fn detach(candidate: u8, prompt: u64, epoch: u64) -> Stimulus {
    Stimulus::DetachSubmitted(RootEofDetachParams {
        session_id: session(),
        fence_id: fence(candidate),
        prompt_generation: PromptGeneration::new(prompt),
        input_epoch: InputLeaseEpoch::new(epoch),
    })
}

fn interrupt(attachment: AttachmentId, epoch: u64) -> Stimulus {
    Stimulus::InterruptRequested(InterruptRequested {
        attachment_id: attachment,
        epoch: InputLeaseEpoch::new(epoch),
        action: InterruptAction::NativeInterrupt,
    })
}

fn launch(prompt: u64, buffer: u64, requester: AttachmentId, index: u8) -> Stimulus {
    Stimulus::LaunchRequested(LaunchRequested {
        params: ShellLaunchParams {
            session_id: session(),
            command: LaunchCommand::Arguments(vec!["codex".to_owned(), "--resume".to_owned()]),
            expected_prompt_generation: PromptGeneration::new(prompt),
            expected_buffer_revision: EditorBufferRevision::new(buffer),
        },
        requester,
        transaction: transaction(index),
    })
}

fn launched_command() -> LaunchCommand {
    LaunchCommand::Arguments(vec!["codex".to_owned(), "--resume".to_owned()])
}

/// An argument vector no interpolation could survive.
///
/// A space, a quotation mark, a dollar and a semicolon inside one argument. What the reader installs
/// must be these three strings, not a line assembled from them and split again.
fn quote_sensitive_command() -> LaunchCommand {
    LaunchCommand::Arguments(vec![
        "codex".to_owned(),
        "--message".to_owned(),
        "fix \"$HOME\"; rm -rf /".to_owned(),
    ])
}

fn launch_accepted(index: u8, candidate: u8, prompt: u64, buffer: u64) -> Stimulus {
    Stimulus::LaunchDecided(LaunchDecision::Accepted(LaunchAccepted {
        transaction: transaction(index),
        installed: launched_command(),
        fence_id: fence(candidate),
        prompt_generation: PromptGeneration::new(prompt),
        buffer_revision: EditorBufferRevision::new(buffer),
        reader_revision: ReaderRevision::new(1),
    }))
}

fn launch_rejected(
    index: u8,
    candidate: u8,
    reason: LaunchRejectionReason,
    prompt: u64,
    buffer: u64,
) -> Stimulus {
    Stimulus::LaunchDecided(LaunchDecision::Rejected(LaunchRejection {
        transaction: transaction(index),
        fence_id: fence(candidate),
        reason,
        prompt_generation: PromptGeneration::new(prompt),
        buffer_revision: EditorBufferRevision::new(buffer),
    }))
}

fn cancellation(
    sequence: u64,
    epoch: u64,
    prompt: u64,
    revision: u64,
    cancelled: CancelledOperations,
    buffer_preserved: bool,
    discarded: u64,
) -> Stimulus {
    Stimulus::CancellationReported(CancellationReport {
        sequence: U64::new(sequence),
        epoch: InputLeaseEpoch::new(epoch),
        prompt_generation: PromptGeneration::new(prompt),
        reader_revision: ReaderRevision::new(revision),
        cancelled,
        buffer_preserved,
        discarded_bytes: U64::new(discarded),
    })
}

fn accepted_command(candidate: Option<u8>, prompt: u64, origin: AcceptedOrigin) -> Stimulus {
    Stimulus::CommandAccepted(RootCommandAcceptedParams {
        session_id: session(),
        fence_id: Nullable(candidate.map(fence)),
        prompt_generation: PromptGeneration::new(prompt),
        origin,
    })
}

fn fenced_origin(attachment: AttachmentId, epoch: u64) -> AcceptedOrigin {
    AcceptedOrigin::Fenced {
        attachment_id: attachment,
        input_epoch: InputLeaseEpoch::new(epoch),
    }
}

fn step(at: u64, stimulus: Stimulus, expect: Expect) -> FenceStep {
    FenceStep {
        at_ms: ContinuousMs::new(at),
        stimulus,
        expect,
    }
}

fn expect(
    state: FenceState,
    fenced: Option<u8>,
    held: &[&str],
    actions: Vec<ActionShape>,
) -> Expect {
    Expect {
        state,
        fence: fenced.map(fence),
        held: refs(held),
        actions,
        detach_target: None,
    }
}

fn with_target(mut expect: Expect, target: DetachTarget) -> Expect {
    expect.detach_target = Some(target);
    expect
}

fn refs(labels: &[&str]) -> Vec<InputRef> {
    labels.iter().map(|label| InputRef::new(*label)).collect()
}

fn ask(candidate: u8, prompt: u64, revision: u64, cause: FenceCause) -> ActionShape {
    ask_within(candidate, prompt, revision, cause, 250)
}

fn ask_within(
    candidate: u8,
    prompt: u64,
    revision: u64,
    cause: FenceCause,
    remaining: u64,
) -> ActionShape {
    ActionShape::AskFence {
        fence_id: fence(candidate),
        prompt_generation: PromptGeneration::new(prompt),
        reader_revision: ReaderRevision::new(revision),
        deadline_ms: DurationMs::new(remaining),
        cause,
    }
}

fn proof(
    candidate: u8,
    prompt: u64,
    revision: u64,
    epoch: u64,
    origin: AttachmentId,
) -> EditorFence {
    EditorFence {
        fence_id: fence(candidate),
        root_process: root_process(),
        prompt_generation: PromptGeneration::new(prompt),
        reader_revision: ReaderRevision::new(revision),
        input_epoch: InputLeaseEpoch::new(epoch),
        originating_attachment: origin,
    }
}

fn publish(
    candidate: u8,
    prompt: u64,
    revision: u64,
    epoch: u64,
    origin: AttachmentId,
) -> ActionShape {
    ActionShape::PublishFence(proof(candidate, prompt, revision, epoch, origin))
}

fn withhold(reason: WithheldReason) -> ActionShape {
    ActionShape::WithholdFence(reason)
}

fn invalidate(reason: FenceInvalidation) -> ActionShape {
    ActionShape::InvalidateFence(reason)
}

fn busy(
    reason: EditorBusyReason,
    attachment: AttachmentId,
    epoch: u64,
    released: u64,
) -> ActionShape {
    busy_in(reason, attachment, epoch, released, FenceState::Unfenced)
}

fn busy_in(
    reason: EditorBusyReason,
    attachment: AttachmentId,
    epoch: u64,
    released: u64,
    state: FenceState,
) -> ActionShape {
    ActionShape::EmitEditorBusy {
        reason,
        attachment_id: attachment,
        input_epoch: InputLeaseEpoch::new(epoch),
        released_input_bytes: U64::new(released),
        state,
    }
}

fn lease_ack(
    epoch: u64,
    holder: Option<AttachmentId>,
    discarded: u64,
    input: &[&str],
) -> ActionShape {
    lease_ack_pending(epoch, holder, discarded, input, false)
}

fn lease_ack_pending(
    epoch: u64,
    holder: Option<AttachmentId>,
    discarded: u64,
    input: &[&str],
    reader_discards_pending: bool,
) -> ActionShape {
    ActionShape::AcknowledgeLeaseChange {
        lease: LeaseView {
            epoch: InputLeaseEpoch::new(epoch),
            holder,
        },
        discarded_bytes: U64::new(discarded),
        discarded_input: refs(input),
        reader_discards_pending,
    }
}

fn cancel_at(sequence: u64, epoch: u64, prompt: u64, revision: u64) -> ActionShape {
    ActionShape::CancelNativeOperations {
        sequence: U64::new(sequence),
        epoch: InputLeaseEpoch::new(epoch),
        prompt_generation: PromptGeneration::new(prompt),
        reader_revision: ReaderRevision::new(revision),
    }
}

fn detach_ack(attachment: AttachmentId, discarded: u64) -> ActionShape {
    ActionShape::AcknowledgeDetach {
        detached_attachment: attachment,
        state: FenceState::Unfenced,
        discarded_input_bytes: U64::new(discarded),
    }
}

fn send_launch(index: u8, candidate: u8, prompt: u64, buffer: u64) -> ActionShape {
    ActionShape::SendLaunch {
        transaction: transaction(index),
        command: launched_command(),
        fence_id: fence(candidate),
        expected_prompt_generation: PromptGeneration::new(prompt),
        expected_buffer_revision: EditorBufferRevision::new(buffer),
        expected_cwd_revision: CwdRevision::new(2),
        // The reader's own budget, which ends before the worker gives up.
        deadline_ms: DurationMs::new(200),
    }
}

fn close_receipt(epoch: u64, reader_discards: Option<u64>) -> ActionShape {
    ActionShape::CloseTakeoverReceipt {
        epoch: InputLeaseEpoch::new(epoch),
        reader_discards: reader_discards.map(U64::new),
    }
}

fn late_installation(candidate: u8, prompt: u64) -> ActionShape {
    ActionShape::LateInstallation {
        fence_id: fence(candidate),
        prompt_generation: PromptGeneration::new(prompt),
    }
}

fn revoke(index: u8, reason: LaunchRejectionReason) -> ActionShape {
    ActionShape::RevokeLaunch {
        transaction: transaction(index),
        reason,
    }
}

fn install(candidate: u8, prompt: u64, buffer: u64) -> ActionShape {
    ActionShape::InstallLaunch {
        fence_id: fence(candidate),
        prompt_generation: PromptGeneration::new(prompt),
        buffer_revision: EditorBufferRevision::new(buffer),
    }
}

fn reject_launch(reason: LaunchRejectionReason, code: ErrorCode) -> ActionShape {
    ActionShape::RejectLaunch { reason, code }
}

fn shell(kind: ShellKind, abi: &str, version: &str) -> ShellIdentity {
    ShellIdentity {
        kind,
        executable: format!("/opt/kalareach/shells/{}/bin/{}", abi, kind.as_str()),
        upstream_version: match kind {
            ShellKind::Zsh => "5.9",
            ShellKind::Bash => "5.2.37",
            ShellKind::Fish => "4.0.2",
            ShellKind::PowerShell => "7.4.6",
        }
        .to_owned(),
        editor_abi: abi.to_owned(),
        integration_version: version.to_owned(),
        patches: vec![PatchRevision {
            name: format!("{}-reader-bridge", kind.as_str()),
            upstream_revision: abi.to_owned(),
            revision: "1".to_owned(),
        }],
        modules: vec![ModuleEntry {
            name: format!("{}/kr-bridge", kind.as_str()),
            search_path: format!("/opt/kalareach/shells/{abi}/lib"),
            editor_abi: abi.to_owned(),
        }],
    }
}

fn hello(kind: ShellKind, abi: &str, version: &str) -> BridgeHello {
    BridgeHello {
        protocol: crate::contract::transport::BRIDGE_PROTOCOL.to_owned(),
        session_id: session(),
        shell_process: root_process(),
        shell: shell(kind, abi, version),
        abi: BridgeAbi::qualified(kind),
        proof: Bytes::new(vec![7; crate::contract::transport::BOOTSTRAP_PROOF_LEN]),
    }
}

fn zsh_hello() -> BridgeHello {
    hello(ShellKind::Zsh, "zle-5.9", "1")
}

fn root_peer() -> ObservedPeer {
    ObservedPeer {
        uid: 501,
        process: Some(root_process()),
    }
}

fn child_peer() -> ObservedPeer {
    ObservedPeer {
        uid: 501,
        process: Some(child_process()),
    }
}

fn expectation() -> WorkerExpectation {
    WorkerExpectation {
        session_id: session(),
        root_process: root_process(),
        supported_editor_abis: vec![
            "zle-5.9".to_owned(),
            "readline-8.2".to_owned(),
            "fish-reader-4.0".to_owned(),
            "psreadline-2.3".to_owned(),
        ],
        supported_integration_versions: vec!["1".to_owned()],
        launched_package: None,
        already_registered: false,
        gesture: EofGesture::default(),
    }
}

fn accepted_case(name: &str, hello: BridgeHello, abi: &str) -> HandshakeCase {
    HandshakeCase {
        name: name.to_owned(),
        peer: root_peer(),
        hello,
        proof: ProofVerdict::Verified,
        expectation: None,
        expect: HandshakeExpectation::Accepted(AcceptedHandshake {
            editor_abi: abi.to_owned(),
            hold_ms: DurationMs::new(250),
            gesture: EofGesture::TerminalEof { byte: U64::new(4) },
            hint: "Use kr detach --attachment <id> to detach.".to_owned(),
            secret_location: SecretLocation::PrivateIntegrationState,
            unexport: vec![
                "KR_SHELL_BRIDGE".to_owned(),
                "KR_SHELL_BRIDGE_SECRET".to_owned(),
            ],
        }),
    }
}

fn refused_case(
    name: &str,
    peer: ObservedPeer,
    hello: BridgeHello,
    proof: ProofVerdict,
    reason: QualificationReason,
    code: ErrorCode,
) -> HandshakeCase {
    HandshakeCase {
        name: name.to_owned(),
        peer,
        hello,
        proof,
        expectation: None,
        expect: HandshakeExpectation::Refused { reason, code },
    }
}

// ----- the handshake scenarios -----------------------------------------------------------------

fn handshake_accept() -> Scenario {
    Scenario {
        id: "handshake-accept".to_owned(),
        purpose: "Each package's own reader mechanisms register it as the session's root \
                  integration, and the accept carries the hold, the configured gesture, the hint \
                  and the instruction to take the bootstrap values out of the exported environment."
            .to_owned(),
        covers: covers(&[
            "KR-REQ-07.39",
            "KR-REQ-07.70",
            "KR-REQ-07.89",
            "KR-REQ-07.40",
        ]),
        shells: every_shell(),
        script: Script::Handshake(HandshakeScript {
            expectation: expectation(),
            cases: vec![
                accepted_case(
                    "patched-zsh-reader-mailbox-and-native-hook",
                    zsh_hello(),
                    "zle-5.9",
                ),
                accepted_case(
                    "patched-bash-idle-mailbox-and-native-hook",
                    hello(ShellKind::Bash, "readline-8.2", "1"),
                    "readline-8.2",
                ),
                accepted_case(
                    "fish-reader-event-bridge-and-named-binding",
                    hello(ShellKind::Fish, "fish-reader-4.0", "1"),
                    "fish-reader-4.0",
                ),
                accepted_case(
                    "psreadline-reader-thread-queue-and-state-handler",
                    hello(ShellKind::PowerShell, "psreadline-2.3", "1"),
                    "psreadline-2.3",
                ),
            ],
            activation: vec![ActivationCase {
                name: "the-root-shell-has-both-bootstrap-values".to_owned(),
                inputs: ActivationInputs {
                    exported_endpoint: Some("/tmp/kalareach/s/shell-bridge".to_owned()),
                    exported_secret: true,
                },
                expect: Activation::Attempt,
            }],
        }),
    }
}

fn handshake_reject() -> Scenario {
    let mut cases = vec![
        refused_case(
            "another-protocol",
            root_peer(),
            BridgeHello {
                protocol: "kr-shell-bridge/0".to_owned(),
                ..zsh_hello()
            },
            ProofVerdict::Verified,
            QualificationReason::ProtocolMismatch,
            ErrorCode::UnsupportedSchema,
        ),
        refused_case(
            "a-stale-inherited-session",
            root_peer(),
            BridgeHello {
                session_id: SessionId::new(Uuid::from_bytes([0x22; 16])),
                ..zsh_hello()
            },
            ProofVerdict::Verified,
            QualificationReason::SessionMismatch,
            ErrorCode::PermissionDenied,
        ),
        refused_case(
            "a-child-shell-of-the-root-shell",
            child_peer(),
            BridgeHello {
                shell_process: child_process(),
                ..zsh_hello()
            },
            ProofVerdict::Verified,
            QualificationReason::ProcessMismatch,
            ErrorCode::PermissionDenied,
        ),
        refused_case(
            "a-child-shell-claiming-its-parents-identity-with-a-valid-proof",
            child_peer(),
            zsh_hello(),
            ProofVerdict::Verified,
            QualificationReason::ProcessMismatch,
            ErrorCode::PermissionDenied,
        ),
        refused_case(
            "a-connection-the-platform-cannot-identify",
            ObservedPeer {
                uid: 501,
                process: None,
            },
            zsh_hello(),
            ProofVerdict::Verified,
            QualificationReason::PeerUnidentified,
            ErrorCode::PermissionDenied,
        ),
        refused_case(
            "a-proof-that-does-not-verify",
            root_peer(),
            zsh_hello(),
            ProofVerdict::Failed,
            QualificationReason::ProofMismatch,
            ErrorCode::PermissionDenied,
        ),
        refused_case(
            "a-file-descriptor-watcher-instead-of-a-mailbox",
            root_peer(),
            BridgeHello {
                abi: BridgeAbi {
                    mailbox: MailboxMechanism::FileDescriptorWatcher,
                    ..BridgeAbi::qualified(ShellKind::Zsh)
                },
                ..zsh_hello()
            },
            ProofVerdict::Verified,
            QualificationReason::UnqualifiedMailbox,
            ErrorCode::ShellIntegrationUnsupported,
        ),
        refused_case(
            "another-readers-mailbox",
            root_peer(),
            BridgeHello {
                abi: BridgeAbi {
                    mailbox: MailboxMechanism::ReaderThreadQueue,
                    ..BridgeAbi::qualified(ShellKind::Zsh)
                },
                ..zsh_hello()
            },
            ProofVerdict::Verified,
            QualificationReason::MailboxNotForShell,
            ErrorCode::ShellIntegrationUnsupported,
        ),
        refused_case(
            "a-key-binding-wrapper-instead-of-the-readers-own-hook",
            root_peer(),
            BridgeHello {
                abi: BridgeAbi {
                    pre_eof: PreEofMechanism::KeyBindingWrapper,
                    ..BridgeAbi::qualified(ShellKind::Zsh)
                },
                ..zsh_hello()
            },
            ProofVerdict::Verified,
            QualificationReason::KeyBindingPreEof,
            ErrorCode::ShellIntegrationUnsupported,
        ),
        refused_case(
            "another-readers-pre-eof-mechanism",
            root_peer(),
            BridgeHello {
                abi: BridgeAbi {
                    pre_eof: PreEofMechanism::ReaderStateHandler,
                    ..BridgeAbi::qualified(ShellKind::Zsh)
                },
                ..zsh_hello()
            },
            ProofVerdict::Verified,
            QualificationReason::PreEofNotForShell,
            ErrorCode::ShellIntegrationUnsupported,
        ),
        refused_case(
            "a-prompt-hook-as-the-fence-proof",
            root_peer(),
            BridgeHello {
                abi: BridgeAbi {
                    fence_proof: FenceProofMechanism::PromptHook,
                    ..BridgeAbi::qualified(ShellKind::Zsh)
                },
                ..zsh_hello()
            },
            ProofVerdict::Verified,
            QualificationReason::UnprovableFence,
            ErrorCode::ShellIntegrationUnsupported,
        ),
        refused_case(
            "an-empty-kernel-queue-as-the-fence-proof",
            root_peer(),
            BridgeHello {
                abi: BridgeAbi {
                    fence_proof: FenceProofMechanism::EmptyKernelQueue,
                    ..BridgeAbi::qualified(ShellKind::Zsh)
                },
                ..zsh_hello()
            },
            ProofVerdict::Verified,
            QualificationReason::UnprovableFence,
            ErrorCode::ShellIntegrationUnsupported,
        ),
        refused_case(
            "a-foreground-process-group-as-the-fence-proof",
            root_peer(),
            BridgeHello {
                abi: BridgeAbi {
                    fence_proof: FenceProofMechanism::ForegroundProcessGroup,
                    ..BridgeAbi::qualified(ShellKind::Zsh)
                },
                ..zsh_hello()
            },
            ProofVerdict::Verified,
            QualificationReason::UnprovableFence,
            ErrorCode::ShellIntegrationUnsupported,
        ),
        refused_case(
            "screen-coordinates-as-the-fence-proof",
            root_peer(),
            BridgeHello {
                abi: BridgeAbi {
                    fence_proof: FenceProofMechanism::ScreenCoordinates,
                    ..BridgeAbi::qualified(ShellKind::Zsh)
                },
                ..zsh_hello()
            },
            ProofVerdict::Verified,
            QualificationReason::UnprovableFence,
            ErrorCode::ShellIntegrationUnsupported,
        ),
        refused_case(
            "no-non-destructive-cancellation",
            root_peer(),
            BridgeHello {
                abi: BridgeAbi {
                    cancellation: CancellationMechanism::Unavailable,
                    ..BridgeAbi::qualified(ShellKind::Zsh)
                },
                ..zsh_hello()
            },
            ProofVerdict::Verified,
            QualificationReason::NoCancellationPath,
            ErrorCode::ShellIntegrationUnsupported,
        ),
        refused_case(
            "key-injection-into-the-terminal-as-the-launch-path",
            root_peer(),
            BridgeHello {
                abi: BridgeAbi {
                    launch_delivery: LaunchDelivery::PseudoTerminalKeyInjection,
                    ..BridgeAbi::qualified(ShellKind::Zsh)
                },
                ..zsh_hello()
            },
            ProofVerdict::Verified,
            QualificationReason::KeyInjectionForbidden,
            ErrorCode::ShellIntegrationUnsupported,
        ),
        refused_case(
            "an-integration-version-this-build-does-not-support",
            root_peer(),
            hello(ShellKind::Zsh, "zle-5.9", "2"),
            ProofVerdict::Verified,
            QualificationReason::IntegrationVersionUnsupported,
            ErrorCode::ShellIntegrationUnsupported,
        ),
        refused_case(
            "an-editor-abi-this-build-was-not-qualified-against",
            root_peer(),
            hello(ShellKind::Zsh, "zle-5.8", "1"),
            ProofVerdict::Verified,
            QualificationReason::EditorAbiUnsupported,
            ErrorCode::ShellIntegrationUnsupported,
        ),
    ];
    let mut incompatible = zsh_hello();
    incompatible.shell.modules.push(ModuleEntry {
        name: "zsh/user-native-module".to_owned(),
        search_path: "/usr/local/lib/zsh/5.8".to_owned(),
        editor_abi: "zle-5.8".to_owned(),
    });
    cases.push(refused_case(
        "an-abi-incompatible-user-native-module",
        root_peer(),
        incompatible,
        ProofVerdict::Verified,
        QualificationReason::ModuleTreeUnsupported,
        ErrorCode::ShellIntegrationUnsupported,
    ));
    // A build of the same shell this session did not launch: the same editor ABI and the same
    // integration version, and a different binary behind them.
    let mut another_build = refused_case(
        "a-declaration-of-another-build-of-the-same-shell",
        root_peer(),
        zsh_hello(),
        ProofVerdict::Verified,
        QualificationReason::PackageMismatch,
        ErrorCode::PermissionDenied,
    );
    another_build.expectation = Some(WorkerExpectation {
        launched_package: Some(crate::contract::transport::PackageDeclaration {
            kind: ShellKind::Zsh,
            executable: "/opt/kalareach/shells/zsh/other-build/bin/zsh".to_owned(),
            upstream_version: "5.9".to_owned(),
            editor_abi: "zle-5.9".to_owned(),
            integration_version: "1".to_owned(),
            patches: zsh_hello().shell.patches,
            modules: zsh_hello().shell.modules,
        }),
        ..expectation()
    });
    cases.push(another_build);
    let mut second = refused_case(
        "a-second-root-integration-for-one-session",
        root_peer(),
        zsh_hello(),
        ProofVerdict::Verified,
        QualificationReason::AlreadyRegistered,
        ErrorCode::PermissionDenied,
    );
    // Every other case is refused before registration is considered at all, so they share one
    // worker expectation. This one needs a worker that already has a root integration.
    second.expectation = Some(WorkerExpectation {
        launched_package: None,
        already_registered: true,
        ..expectation()
    });
    cases.push(second);
    Scenario {
        id: "handshake-reject".to_owned(),
        purpose: "Every named qualification error, including a child that claims its parent's \
                  identity with a valid proof, and the two reasons a starting shell does not \
                  attempt the handshake at all."
            .to_owned(),
        covers: covers(&[
            "KR-REQ-07.39",
            "KR-REQ-07.70",
            "KR-REQ-07.89",
            "KR-REQ-07.40",
        ]),
        shells: every_shell(),
        script: Script::Handshake(HandshakeScript {
            expectation: expectation(),
            cases,
            activation: vec![
                ActivationCase {
                    name: "a-child-shell-inherits-no-bootstrap-values".to_owned(),
                    inputs: ActivationInputs {
                        exported_endpoint: None,
                        exported_secret: false,
                    },
                    expect: Activation::Skip(SkipReason::NoEndpoint),
                },
                ActivationCase {
                    name: "an-endpoint-without-its-secret".to_owned(),
                    inputs: ActivationInputs {
                        exported_endpoint: Some("/tmp/kalareach/s/shell-bridge".to_owned()),
                        exported_secret: false,
                    },
                    expect: Activation::Skip(SkipReason::NoSecret),
                },
            ],
        }),
    }
}

// ----- the state-machine scenarios -------------------------------------------------------------

fn fence_scenario(
    id: &str,
    purpose: &str,
    rows: &[&str],
    shells: Vec<ShellKind>,
    lease: LeaseView,
    steps: Vec<FenceStep>,
) -> Scenario {
    Scenario {
        id: id.to_owned(),
        purpose: purpose.to_owned(),
        covers: covers(rows),
        shells,
        script: Script::Fence(FenceScript {
            session_id: session(),
            lease,
            steps,
        }),
    }
}

fn held_by_a() -> LeaseView {
    LeaseView::held(InputLeaseEpoch::new(3), attachment_a())
}

fn entered(candidate: u8) -> FenceStep {
    step(
        0,
        enter(1, 1, candidate),
        expect(
            FenceState::Unfenced,
            None,
            &[],
            vec![ask(candidate, 1, 1, FenceCause::EditorEntry)],
        ),
    )
}

fn fenced_at(at: u64, candidate: u8) -> FenceStep {
    step(
        at,
        drained(candidate, 1, 1, empty_editor(1)),
        expect(
            FenceState::Fenced,
            Some(candidate),
            &[],
            vec![publish(candidate, 1, 1, 3, attachment_a())],
        ),
    )
}

fn enter_fence_acknowledge_detach() -> Scenario {
    fence_scenario(
        "enter-fence-acknowledge-detach",
        "The whole path: the reader starts, the worker holds input while the bridge resolves the \
         old queues, the fence publishes with its complete proof, and an empty-prompt gesture \
         removes the attachment the fence names.",
        &[
            "KR-REQ-07.75",
            "KR-REQ-07.76",
            "KR-REQ-07.79",
            "KR-REQ-07.81",
            "KR-REQ-07.82",
        ],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            step(
                10,
                input("typed-ls", attachment_a(), 3, 3),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["typed-ls"],
                    vec![ActionShape::Hold(InputRef::new("typed-ls"))],
                ),
            ),
            step(
                20,
                drained(1, 1, 1, empty_editor(1)),
                expect(
                    FenceState::Fenced,
                    Some(1),
                    &[],
                    vec![
                        publish(1, 1, 1, 3, attachment_a()),
                        ActionShape::Release(refs(&["typed-ls"])),
                    ],
                ),
            ),
            step(
                30,
                detach(1, 1, 3),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        invalidate(FenceInvalidation::DetachAccepted),
                        cancel_at(1, 3, 1, 1),
                        ActionShape::RemoveAttachment(attachment_a()),
                        detach_ack(attachment_a(), 0),
                    ],
                ),
            ),
            step(
                40,
                detach(1, 1, 3),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ActionShape::RejectDetach(DetachRejection::FenceMissing)],
                ),
            ),
        ],
    )
}

fn takeover(
    id: &str,
    purpose: &str,
    queues: QueueDrainReport,
    snapshot: KeyQueueSnapshot,
    pending: PendingReaderInput,
    keymap: EditorKeymap,
    cancelled: CancelledOperations,
) -> Scenario {
    fence_scenario(
        id,
        purpose,
        &["KR-REQ-07.77", "KR-REQ-07.78", "KR-REQ-07.79"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            fenced_at(5, 1),
            step(
                10,
                input("typed-half-a-word", attachment_a(), 3, 4),
                expect(
                    FenceState::Fenced,
                    Some(1),
                    &[],
                    vec![ActionShape::Forward(InputRef::new("typed-half-a-word"))],
                ),
            ),
            step(
                20,
                lease_change(4, Some(attachment_b()), 2, 0),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        invalidate(FenceInvalidation::LeaseChanged),
                        cancel_at(1, 4, 1, 1),
                        lease_ack_pending(4, Some(attachment_b()), 0, &[], true),
                        ask(2, 1, 1, FenceCause::LeaseChange),
                    ],
                ),
            ),
            step(
                22,
                cancellation(1, 4, 1, 1, cancelled, true, 2),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![close_receipt(4, Some(2))],
                ),
            ),
            step(
                25,
                input("second-client-types", attachment_b(), 4, 3),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["second-client-types"],
                    vec![ActionShape::Hold(InputRef::new("second-client-types"))],
                ),
            ),
            step(
                30,
                acknowledgement(2, 1, 1, queues, snapshot, editor(2, false, pending, keymap)),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        withhold(WithheldReason::QueuesNotDrained),
                        ActionShape::Release(refs(&["second-client-types"])),
                        busy(EditorBusyReason::QueuesNotDrained, attachment_b(), 4, 3),
                    ],
                ),
            ),
            step(
                40,
                idle(1, 1, 3),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ask(3, 1, 1, FenceCause::Retry)],
                ),
            ),
            step(
                45,
                drained(3, 1, 1, typed_editor(2)),
                expect(
                    FenceState::Fenced,
                    Some(3),
                    &[],
                    vec![publish(3, 1, 1, 4, attachment_b())],
                ),
            ),
        ],
    )
}

fn takeover_partial_escape() -> Scenario {
    takeover(
        "takeover-partial-escape",
        "A takeover while a lone Escape is still in the decoder: the cancellation ends the wait and \
         keeps the buffer, the fence is withheld until the queue is clear, and the retry at the idle \
         callback publishes with the edit buffer intact.",
        QueueDrainReport {
            partial_key_drained: false,
            ..QueueDrainReport::CLEAR
        },
        KeyQueueSnapshot {
            keys: Bytes::new(vec![0x1b]),
            pending_bytes: U64::new(1),
            queued_keys: U64::ZERO,
        },
        PendingReaderInput::NONE,
        EditorKeymap::Emacs,
        CancelledOperations {
            partial_escape: true,
            ..CancelledOperations::NONE
        },
    )
}

fn takeover_quoted_insertion() -> Scenario {
    takeover(
        "takeover-quoted-insertion",
        "A takeover while a quoted insertion waits for the character to insert literally.",
        QueueDrainReport {
            partial_key_drained: false,
            ..QueueDrainReport::CLEAR
        },
        KeyQueueSnapshot {
            keys: Bytes::new(vec![0x16]),
            pending_bytes: U64::ZERO,
            queued_keys: U64::new(1),
        },
        PendingReaderInput {
            quoted_insertion: true,
            ..PendingReaderInput::NONE
        },
        EditorKeymap::Emacs,
        CancelledOperations {
            quoted_insertion: true,
            ..CancelledOperations::NONE
        },
    )
}

fn takeover_vi_motion() -> Scenario {
    takeover(
        "takeover-vi-motion",
        "A takeover while a vi motion waits for its target, in a keymap the integration never \
         changes.",
        QueueDrainReport {
            partial_key_drained: false,
            ..QueueDrainReport::CLEAR
        },
        KeyQueueSnapshot {
            keys: Bytes::new(vec![b'd']),
            pending_bytes: U64::ZERO,
            queued_keys: U64::new(1),
        },
        PendingReaderInput {
            vi_motion: true,
            ..PendingReaderInput::NONE
        },
        EditorKeymap::ViCommand,
        CancelledOperations {
            vi_motion: true,
            ..CancelledOperations::NONE
        },
    )
}

fn takeover_incomplete_chord() -> Scenario {
    takeover(
        "takeover-incomplete-chord",
        "A takeover in the middle of a multikey sequence that would otherwise wait for a key that \
         is never coming.",
        QueueDrainReport {
            partial_key_drained: false,
            ..QueueDrainReport::CLEAR
        },
        KeyQueueSnapshot {
            keys: Bytes::new(vec![0x18]),
            pending_bytes: U64::ZERO,
            queued_keys: U64::new(1),
        },
        PendingReaderInput {
            multikey_sequence: true,
            ..PendingReaderInput::NONE
        },
        EditorKeymap::Emacs,
        CancelledOperations {
            multikey_sequence: true,
            ..CancelledOperations::NONE
        },
    )
}

fn takeover_macro() -> Scenario {
    takeover(
        "takeover-macro",
        "A takeover while a macro is still feeding the reader: the macro queue is what is not \
         drained, and no new fence publishes until it is.",
        QueueDrainReport {
            macro_input_drained: false,
            ..QueueDrainReport::CLEAR
        },
        KeyQueueSnapshot {
            keys: Bytes::new(Vec::new()),
            pending_bytes: U64::ZERO,
            queued_keys: U64::new(3),
        },
        PendingReaderInput {
            macro_input: true,
            ..PendingReaderInput::NONE
        },
        EditorKeymap::Emacs,
        CancelledOperations {
            macro_input: true,
            ..CancelledOperations::NONE
        },
    )
}

fn takeover_destructive_cancellation() -> Scenario {
    fence_scenario(
        "takeover-destructive-cancellation",
        "A cancellation that could only end the key wait by losing the edit buffer is not the \
         non-destructive path this contract requires: the fence is withheld rather than published \
         over a reader state nobody can attribute input through, and a report from another reader \
         is ignored.",
        &["KR-REQ-07.78", "KR-REQ-07.39"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            fenced_at(5, 1),
            step(
                10,
                lease_change(4, Some(attachment_b()), 2, 0),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        invalidate(FenceInvalidation::LeaseChanged),
                        cancel_at(1, 4, 1, 1),
                        lease_ack_pending(4, Some(attachment_b()), 0, &[], true),
                        ask(2, 1, 1, FenceCause::LeaseChange),
                    ],
                ),
            ),
            step(
                15,
                input("new-holder-types", attachment_b(), 4, 4),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["new-holder-types"],
                    vec![ActionShape::Hold(InputRef::new("new-holder-types"))],
                ),
            ),
            step(
                18,
                cancellation(
                    9,
                    4,
                    9,
                    9,
                    CancelledOperations {
                        multikey_sequence: true,
                        ..CancelledOperations::NONE
                    },
                    false,
                    0,
                ),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["new-holder-types"],
                    vec![ActionShape::IgnoreStale(StaleMessage::ReaderEvent)],
                ),
            ),
            step(
                20,
                cancellation(
                    1,
                    4,
                    1,
                    1,
                    CancelledOperations {
                        multikey_sequence: true,
                        ..CancelledOperations::NONE
                    },
                    false,
                    0,
                ),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        // The receipt closes with what the reader did discard, even though what it
                        // did to the buffer means no fence can publish over it.
                        close_receipt(4, Some(0)),
                        withhold(WithheldReason::Refused),
                        ActionShape::Release(refs(&["new-holder-types"])),
                        busy(EditorBusyReason::FenceRefused, attachment_b(), 4, 4),
                    ],
                ),
            ),
            step(
                30,
                drained(2, 1, 1, empty_editor(1)),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ActionShape::IgnoreStale(StaleMessage::FenceAcknowledgement)],
                ),
            ),
        ],
    )
}

fn attachment_removed_during_exchange() -> Scenario {
    fence_scenario(
        "attachment-removed-during-exchange",
        "An attachment that goes away during its own fence exchange takes the exchange with it: \
         there is no origin left for a fence to name, its undelivered input is discarded and the \
         held input of whoever is left is released.",
        &["KR-REQ-07.82", "KR-REQ-07.80"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            step(
                5,
                input("first-client-types", attachment_a(), 3, 4),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["first-client-types"],
                    vec![ActionShape::Hold(InputRef::new("first-client-types"))],
                ),
            ),
            step(
                10,
                Stimulus::AttachmentRemoved(attachment_a()),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        ActionShape::Discard {
                            input: refs(&["first-client-types"]),
                            reason: DiscardReason::AttachmentRemoved,
                        },
                        withhold(WithheldReason::LeaseChanged),
                        cancel_at(1, 3, 1, 1),
                    ],
                ),
            ),
            step(
                20,
                drained(1, 1, 1, empty_editor(1)),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ActionShape::IgnoreStale(StaleMessage::FenceAcknowledgement)],
                ),
            ),
            step(
                30,
                idle(1, 1, 2),
                expect(FenceState::Unfenced, None, &[], Vec::new()),
            ),
            step(
                40,
                lease_change(4, Some(attachment_b()), 3, 0),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        lease_ack(4, Some(attachment_b()), 0, &[]),
                        ask(3, 1, 1, FenceCause::LeaseChange),
                    ],
                ),
            ),
            step(
                45,
                drained(3, 1, 1, empty_editor(1)),
                expect(
                    FenceState::Fenced,
                    Some(3),
                    &[],
                    vec![publish(3, 1, 1, 4, attachment_b())],
                ),
            ),
        ],
    )
}

fn takeover_receipt_superseded() -> Scenario {
    fence_scenario(
        "takeover-receipt-superseded",
        "A takeover's receipt belongs to the cancellation that opened it: a departure supersedes \
         that cancellation, so the receipt closes saying the reader's own discards are unknown \
         rather than taking the departure's count, and the superseded report is ignored.",
        &["KR-REQ-07.78", "KR-REQ-07.82"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            fenced_at(5, 1),
            step(
                10,
                lease_change(4, Some(attachment_b()), 2, 0),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        invalidate(FenceInvalidation::LeaseChanged),
                        cancel_at(1, 4, 1, 1),
                        lease_ack_pending(4, Some(attachment_b()), 0, &[], true),
                        ask(2, 1, 1, FenceCause::LeaseChange),
                    ],
                ),
            ),
            // The new holder goes away before it answered. Its cancellation supersedes the
            // takeover's, and the receipt closes with the takeover's discards unknown.
            step(
                20,
                Stimulus::AttachmentRemoved(attachment_b()),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        withhold(WithheldReason::LeaseChanged),
                        close_receipt(4, None),
                        cancel_at(2, 4, 1, 1),
                    ],
                ),
            ),
            // The takeover's own answer arrives at last. It belongs to a cancellation nobody is
            // waiting on any more, and it fills nothing.
            step(
                30,
                cancellation(
                    1,
                    4,
                    1,
                    1,
                    CancelledOperations {
                        partial_escape: true,
                        ..CancelledOperations::NONE
                    },
                    true,
                    2,
                ),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ActionShape::IgnoreStale(StaleMessage::ReaderEvent)],
                ),
            ),
            // The departure's own answer fills nothing either: a departure asked for no takeover.
            step(
                40,
                cancellation(2, 4, 1, 1, CancelledOperations::NONE, true, 5),
                expect(FenceState::Unfenced, None, &[], Vec::new()),
            ),
        ],
    )
}

fn timeout_editor_entry() -> Scenario {
    fence_scenario(
        "timeout-editor-entry",
        "A bridge that does not answer within 250 ms of plain editor entry: the held input is \
         released in its original order, the editor stays unfenced, an EDITOR_BUSY attachment event \
         says so, and an acknowledgement that arrives afterwards publishes nothing whether or not a \
         timer fired first.",
        &["KR-REQ-07.79", "KR-REQ-07.80"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            step(
                10,
                input("first", attachment_a(), 3, 4),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["first"],
                    vec![ActionShape::Hold(InputRef::new("first"))],
                ),
            ),
            step(
                100,
                input("second", attachment_a(), 3, 2),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["first", "second"],
                    vec![ActionShape::Hold(InputRef::new("second"))],
                ),
            ),
            step(
                249,
                Stimulus::HoldExpired,
                expect(FenceState::Unfenced, None, &["first", "second"], Vec::new()),
            ),
            step(
                250,
                Stimulus::HoldExpired,
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        withhold(WithheldReason::ExchangeTimedOut),
                        ActionShape::Release(refs(&["first", "second"])),
                        busy(
                            EditorBusyReason::FenceExchangeTimedOut,
                            attachment_a(),
                            3,
                            6,
                        ),
                    ],
                ),
            ),
            step(
                260,
                drained(1, 1, 1, empty_editor(1)),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ActionShape::IgnoreStale(StaleMessage::FenceAcknowledgement)],
                ),
            ),
            step(
                300,
                idle(1, 1, 2),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ask(2, 1, 1, FenceCause::Retry)],
                ),
            ),
            // The second exchange is never answered either, and this acknowledgement arrives after
            // its deadline with no timer stimulus in between. The clock decides, not the order the
            // messages happen to arrive in.
            step(
                560,
                drained(2, 1, 1, empty_editor(1)),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        withhold(WithheldReason::ExchangeTimedOut),
                        busy(
                            EditorBusyReason::FenceExchangeTimedOut,
                            attachment_a(),
                            3,
                            0,
                        ),
                        ActionShape::IgnoreStale(StaleMessage::FenceAcknowledgement),
                    ],
                ),
            ),
            step(
                600,
                idle(1, 1, 3),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ask(3, 1, 1, FenceCause::Retry)],
                ),
            ),
            step(
                610,
                drained(3, 1, 1, empty_editor(1)),
                expect(
                    FenceState::Fenced,
                    Some(3),
                    &[],
                    vec![publish(3, 1, 1, 3, attachment_a())],
                ),
            ),
        ],
    )
}

fn timeout_takeover() -> Scenario {
    fence_scenario(
        "timeout-takeover",
        "A bridge that does not answer a takeover within 250 ms: the lease change still stands, the \
         new holder's input is released in order and the event is an editor event rather than a \
         failed input.acquire.",
        &["KR-REQ-07.77", "KR-REQ-07.79"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            fenced_at(5, 1),
            step(
                10,
                lease_change(4, Some(attachment_b()), 2, 12),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        invalidate(FenceInvalidation::LeaseChanged),
                        cancel_at(1, 4, 1, 1),
                        lease_ack_pending(4, Some(attachment_b()), 12, &[], true),
                        ask(2, 1, 1, FenceCause::LeaseChange),
                    ],
                ),
            ),
            step(
                20,
                input("new-holder-types", attachment_b(), 4, 5),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["new-holder-types"],
                    vec![ActionShape::Hold(InputRef::new("new-holder-types"))],
                ),
            ),
            step(
                260,
                Stimulus::HoldExpired,
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        // Neither the cancellation nor the fence was answered inside the hold,
                        // so the receipt closes saying the reader's own discards are unknown.
                        close_receipt(4, None),
                        withhold(WithheldReason::ExchangeTimedOut),
                        ActionShape::Release(refs(&["new-holder-types"])),
                        busy(
                            EditorBusyReason::FenceExchangeTimedOut,
                            attachment_b(),
                            4,
                            5,
                        ),
                    ],
                ),
            ),
            step(
                270,
                input("new-holder-types-more", attachment_b(), 4, 2),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ActionShape::Forward(InputRef::new("new-holder-types-more"))],
                ),
            ),
        ],
    )
}

fn timeout_launch() -> Scenario {
    fence_scenario(
        "timeout-launch",
        "A launch transaction the reader does not answer within 250 ms: the reader is told the \
         transaction is over, the caller gets EDITOR_BUSY, the held input is released in order, and \
         an acceptance that arrives afterwards is a qualification breach rather than an install.",
        &["KR-REQ-07.83", "KR-REQ-07.33"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            fenced_at(5, 1),
            step(
                10,
                launch(1, 1, attachment_a(), 1),
                expect(
                    FenceState::LaunchReserved,
                    Some(1),
                    &[],
                    vec![send_launch(1, 1, 1, 1)],
                ),
            ),
            step(
                20,
                input("typed-during-the-transaction", attachment_a(), 3, 2),
                expect(
                    FenceState::LaunchReserved,
                    Some(1),
                    &["typed-during-the-transaction"],
                    vec![ActionShape::Hold(InputRef::new(
                        "typed-during-the-transaction",
                    ))],
                ),
            ),
            step(
                260,
                Stimulus::HoldExpired,
                expect(
                    FenceState::Fenced,
                    Some(1),
                    &[],
                    vec![
                        revoke(1, LaunchRejectionReason::Timeout),
                        // The input hold is over, so the batches go to the terminal. The caller's
                        // answer is not: only the reader knows whether it installed anything.
                        ActionShape::Release(refs(&["typed-during-the-transaction"])),
                        busy_in(
                            EditorBusyReason::LaunchReservationTimedOut,
                            attachment_a(),
                            3,
                            2,
                            FenceState::Fenced,
                        ),
                    ],
                ),
            ),
            // The reader had already installed it when the revocation arrived. The command is in
            // the editor, so the caller is told what happened rather than told it failed, and the
            // session records the late installation.
            step(
                270,
                launch_accepted(1, 1, 1, 2),
                expect(
                    FenceState::Fenced,
                    Some(1),
                    &[],
                    vec![late_installation(1, 1), install(1, 1, 2)],
                ),
            ),
        ],
    )
}

fn launch_installed() -> Scenario {
    fence_scenario(
        "launch-installed",
        "A launch the reader installs: the caller is told what was installed and at which revision, \
         and the line it accepts belongs to the client that asked for it rather than to whoever \
         holds the lease when the command starts.",
        &["KR-REQ-07.83", "KR-REQ-07.84"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            fenced_at(5, 1),
            step(
                10,
                launch(1, 1, attachment_b(), 1),
                expect(
                    FenceState::LaunchReserved,
                    Some(1),
                    &[],
                    vec![send_launch(1, 1, 1, 1)],
                ),
            ),
            step(
                20,
                launch_accepted(1, 1, 1, 2),
                expect(FenceState::Fenced, Some(1), &[], vec![install(1, 1, 2)]),
            ),
            step(
                30,
                accepted_command(Some(1), 1, fenced_origin(attachment_a(), 3)),
                with_target(
                    expect(
                        FenceState::Fenced,
                        Some(1),
                        &[],
                        vec![ActionShape::RecordAcceptance(fenced_origin(
                            attachment_b(),
                            3,
                        ))],
                    ),
                    DetachTarget::Attachment(attachment_b()),
                ),
            ),
        ],
    )
}

fn launch_reader_decisions() -> Scenario {
    let request = LaunchMailboxRequest {
        session_id: session(),
        transaction: transaction(1),
        fence_id: fence(1),
        command: quote_sensitive_command(),
        expected_prompt_generation: PromptGeneration::new(4),
        expected_buffer_revision: EditorBufferRevision::new(9),
        expected_cwd_revision: CwdRevision::new(2),
        deadline_ms: LAUNCH_READER_BUDGET,
    };
    let ready = ReaderLaunchState {
        prompt_generation: PromptGeneration::new(4),
        reader_revision: ReaderRevision::new(1),
        reader_context: ReaderContext::Primary,
        editor: empty_editor(9),
        snapshot: KeyQueueSnapshot::drained(),
        cwd_revision: CwdRevision::new(2),
        fence_live: true,
        revoked: false,
        waited_ms: DurationMs::new(3),
    };
    let case = |name: &str, state: ReaderLaunchState, expect: LaunchExpectation| LaunchCase {
        name: name.to_owned(),
        state,
        expect,
    };
    let rejected = |reason: LaunchRejectionReason, code: ErrorCode| LaunchExpectation::Rejected {
        reason,
        code,
    };
    Scenario {
        id: "launch-reader-decisions".to_owned(),
        purpose: "The reader thread's own check before anything is installed: this reader, this \
                  fence, inside its deadline, with no input of the person's waiting and the prompt, \
                  directory and buffer the caller expected."
            .to_owned(),
        covers: covers(&["KR-REQ-07.83", "KR-REQ-07.32", "KR-REQ-07.33"]),
        shells: every_shell(),
        script: Script::Launch(LaunchScript {
            request,
            cases: vec![
                case(
                    "an-empty-primary-prompt-at-the-expected-revisions",
                    ready.clone(),
                    LaunchExpectation::Installed {
                        installed: quote_sensitive_command(),
                        buffer_revision: EditorBufferRevision::new(10),
                    },
                ),
                case(
                    "a-revocation-the-reader-saw-in-the-same-step",
                    ReaderLaunchState {
                        revoked: true,
                        ..ready.clone()
                    },
                    rejected(LaunchRejectionReason::Revoked, ErrorCode::EditorBusy),
                ),
                case(
                    "a-fence-the-reader-no-longer-holds",
                    ReaderLaunchState {
                        fence_live: false,
                        ..ready.clone()
                    },
                    rejected(LaunchRejectionReason::FenceInvalid, ErrorCode::EditorBusy),
                ),
                case(
                    "a-continuation-line",
                    ReaderLaunchState {
                        reader_context: ReaderContext::Continuation,
                        ..ready.clone()
                    },
                    rejected(LaunchRejectionReason::NotPrimaryReader, ErrorCode::EditorBusy),
                ),
                case(
                    "the-readers-own-deadline-has-passed",
                    ReaderLaunchState {
                        waited_ms: DurationMs::new(250),
                        ..ready.clone()
                    },
                    rejected(LaunchRejectionReason::Timeout, ErrorCode::EditorBusy),
                ),
                case(
                    "input-the-person-typed-first",
                    ReaderLaunchState {
                        snapshot: KeyQueueSnapshot {
                            keys: Bytes::new(Vec::new()),
                            pending_bytes: U64::new(3),
                            queued_keys: U64::ZERO,
                        },
                        ..ready.clone()
                    },
                    rejected(
                        LaunchRejectionReason::QueuedPriorInput,
                        ErrorCode::EditorBusy,
                    ),
                ),
                case(
                    "a-macro-still-feeding-the-reader",
                    ReaderLaunchState {
                        editor: editor(
                            9,
                            true,
                            PendingReaderInput {
                                macro_input: true,
                                ..PendingReaderInput::NONE
                            },
                            EditorKeymap::Emacs,
                        ),
                        ..ready.clone()
                    },
                    rejected(
                        LaunchRejectionReason::QueuedPriorInput,
                        ErrorCode::EditorBusy,
                    ),
                ),
                case(
                    "another-prompt-than-the-caller-expected",
                    ReaderLaunchState {
                        prompt_generation: PromptGeneration::new(5),
                        ..ready.clone()
                    },
                    rejected(
                        LaunchRejectionReason::PromptGenerationMismatch,
                        ErrorCode::DraftConflict,
                    ),
                ),
                case(
                    "another-working-directory",
                    ReaderLaunchState {
                        cwd_revision: CwdRevision::new(3),
                        ..ready.clone()
                    },
                    rejected(
                        LaunchRejectionReason::CwdRevisionMismatch,
                        ErrorCode::DraftConflict,
                    ),
                ),
                case(
                    "something-typed-into-the-buffer",
                    ReaderLaunchState {
                        editor: typed_editor(9),
                        ..ready.clone()
                    },
                    rejected(
                        LaunchRejectionReason::BufferNotEmpty,
                        ErrorCode::DraftConflict,
                    ),
                ),
                case(
                    "a-buffer-revision-that-has-moved",
                    ReaderLaunchState {
                        editor: empty_editor(11),
                        ..ready
                    },
                    rejected(
                        LaunchRejectionReason::BufferRevisionMismatch,
                        ErrorCode::DraftConflict,
                    ),
                ),
            ],
        }),
    }
}

fn launch_prelude() -> Vec<FenceStep> {
    vec![
        entered(1),
        fenced_at(5, 1),
        step(
            10,
            launch(1, 1, attachment_a(), 1),
            expect(
                FenceState::LaunchReserved,
                Some(1),
                &[],
                vec![send_launch(1, 1, 1, 1)],
            ),
        ),
    ]
}

fn launch_cancelled_by_leave() -> Scenario {
    let mut steps = launch_prelude();
    steps.push(step(
        15,
        input("typed-during-the-transaction", attachment_a(), 3, 3),
        expect(
            FenceState::LaunchReserved,
            Some(1),
            &["typed-during-the-transaction"],
            vec![ActionShape::Hold(InputRef::new(
                "typed-during-the-transaction",
            ))],
        ),
    ));
    steps.push(step(
        20,
        leave(1, 1, EditorLeaveReason::CommandAccepted),
        expect(
            FenceState::Outside,
            None,
            &[],
            vec![
                revoke(1, LaunchRejectionReason::EditorLeft),
                invalidate(FenceInvalidation::EditorLeft),
                ActionShape::Release(refs(&["typed-during-the-transaction"])),
            ],
        ),
    ));
    steps.push(step(
        25,
        input("straight-to-the-application", attachment_a(), 3, 2),
        expect(
            FenceState::Outside,
            None,
            &[],
            vec![ActionShape::Forward(InputRef::new(
                "straight-to-the-application",
            ))],
        ),
    ));
    steps.push(step(
        30,
        launch_accepted(1, 1, 1, 2),
        expect(
            FenceState::Outside,
            None,
            &[],
            vec![late_installation(1, 1), install(1, 1, 2)],
        ),
    ));
    fence_scenario(
        "launch-cancelled-by-leave",
        "The reader leaves while the launch is in its mailbox: the reader is told, the caller gets \
         EDITOR_BUSY, the fence is invalidated, and the input held for the transaction goes to \
         whatever is reading the terminal now rather than waiting for a reader that has gone.",
        &["KR-REQ-07.83", "KR-REQ-07.33"],
        every_shell(),
        held_by_a(),
        steps,
    )
}

fn launch_cancelled_by_prior_input() -> Scenario {
    let mut steps = launch_prelude();
    steps.push(step(
        20,
        launch_rejected(1, 1, LaunchRejectionReason::QueuedPriorInput, 1, 1),
        expect(
            FenceState::Fenced,
            Some(1),
            &[],
            vec![reject_launch(
                LaunchRejectionReason::QueuedPriorInput,
                ErrorCode::EditorBusy,
            )],
        ),
    ));
    fence_scenario(
        "launch-cancelled-by-prior-input",
        "The reader finds input the person typed before the launch arrived and rejects it on its own \
         thread, installing nothing.",
        &["KR-REQ-07.83", "KR-REQ-07.33"],
        every_shell(),
        held_by_a(),
        steps,
    )
}

fn launch_cancelled_by_lease_change() -> Scenario {
    let mut steps = launch_prelude();
    steps.push(step(
        20,
        lease_change(4, Some(attachment_b()), 2, 0),
        expect(
            FenceState::Unfenced,
            None,
            &[],
            vec![
                revoke(1, LaunchRejectionReason::LeaseChanged),
                invalidate(FenceInvalidation::LeaseChanged),
                cancel_at(1, 4, 1, 1),
                lease_ack_pending(4, Some(attachment_b()), 0, &[], true),
                ask(2, 1, 1, FenceCause::LeaseChange),
            ],
        ),
    ));
    steps.push(step(
        30,
        launch_accepted(1, 1, 1, 2),
        expect(
            FenceState::Unfenced,
            None,
            &[],
            vec![late_installation(1, 1), install(1, 1, 2)],
        ),
    ));
    fence_scenario(
        "launch-cancelled-by-lease-change",
        "The input lease changes during the transaction: the reader is told to install nothing, the \
         fence is invalidated before the lease change is acknowledged, and a late acceptance is a \
         qualification breach rather than an install.",
        &["KR-REQ-07.83", "KR-REQ-07.33"],
        every_shell(),
        held_by_a(),
        steps,
    )
}

fn launch_cancelled_by_buffer_revision() -> Scenario {
    let mut steps = launch_prelude();
    steps.push(step(
        20,
        launch_rejected(1, 1, LaunchRejectionReason::BufferRevisionMismatch, 1, 4),
        expect(
            FenceState::Fenced,
            Some(1),
            &[],
            vec![reject_launch(
                LaunchRejectionReason::BufferRevisionMismatch,
                ErrorCode::DraftConflict,
            )],
        ),
    ));
    steps.push(step(
        30,
        launch(9, 1, attachment_a(), 2),
        expect(
            FenceState::Fenced,
            Some(1),
            &[],
            vec![reject_launch(
                LaunchRejectionReason::PromptGenerationMismatch,
                ErrorCode::DraftConflict,
            )],
        ),
    ));
    fence_scenario(
        "launch-cancelled-by-buffer-revision",
        "The reader's own buffer revision is not the one the caller expected, so the launch is a \
         draft conflict rather than a busy editor; a launch against the wrong prompt generation \
         never reaches the mailbox at all.",
        &["KR-REQ-07.83", "KR-REQ-07.33"],
        every_shell(),
        held_by_a(),
        steps,
    )
}

fn detach_during_launch() -> Scenario {
    let mut steps = launch_prelude();
    steps.push(step(
        20,
        detach(1, 1, 3),
        expect(
            FenceState::Unfenced,
            None,
            &[],
            vec![
                // The request is already with the reader, so the revocation goes out and the
                // caller's answer waits for the reader's word.
                revoke(1, LaunchRejectionReason::FenceInvalid),
                invalidate(FenceInvalidation::DetachAccepted),
                cancel_at(1, 3, 1, 1),
                ActionShape::RemoveAttachment(attachment_a()),
                detach_ack(attachment_a(), 0),
            ],
        ),
    ));
    // The reader had already installed it when the revocation arrived: the command is in the
    // editor, so the caller is told that rather than told it failed.
    steps.push(step(
        30,
        launch_accepted(1, 1, 1, 2),
        expect(
            FenceState::Unfenced,
            None,
            &[],
            vec![late_installation(1, 1), install(1, 1, 2)],
        ),
    ));
    fence_scenario(
        "detach-during-launch",
        "An eligible gesture arrives while a launch holds the fence: the attachment the fence names \
         is going away, so the transaction loses its fence and the detach is validated and \
         acknowledged rather than refused.",
        &["KR-REQ-07.81", "KR-REQ-07.83"],
        every_shell(),
        held_by_a(),
        steps,
    )
}

fn deadline_meets_departure() -> Scenario {
    fence_scenario(
        "deadline-meets-departure",
        "A hold that expires at the same moment as a removal, a detach or a closure: the input the \
         stimulus is about to discard is not delivered on its way to being thrown away, and the \
         event that discards it says so.",
        &["KR-REQ-07.79", "KR-REQ-07.82"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            step(
                10,
                input("typed-before-the-timeout", attachment_a(), 3, 4),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["typed-before-the-timeout"],
                    vec![ActionShape::Hold(InputRef::new("typed-before-the-timeout"))],
                ),
            ),
            // The attachment goes away exactly at the deadline. The hold is its own, and it is
            // discarded rather than released: nothing of a client that is gone reaches the terminal.
            step(
                250,
                Stimulus::AttachmentRemoved(attachment_a()),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        withhold(WithheldReason::ExchangeTimedOut),
                        busy(
                            EditorBusyReason::FenceExchangeTimedOut,
                            attachment_a(),
                            3,
                            0,
                        ),
                        ActionShape::Discard {
                            input: refs(&["typed-before-the-timeout"]),
                            reason: DiscardReason::AttachmentRemoved,
                        },
                        cancel_at(1, 3, 1, 1),
                    ],
                ),
            ),
            // Its epoch has not advanced yet, and its keystrokes still go nowhere.
            step(
                260,
                input("after-it-went-away", attachment_a(), 3, 2),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ActionShape::Discard {
                        input: refs(&["after-it-went-away"]),
                        reason: DiscardReason::OldLease,
                    }],
                ),
            ),
            step(
                270,
                lease_change(4, Some(attachment_b()), 2, 0),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        lease_ack(4, Some(attachment_b()), 0, &[]),
                        ask(2, 1, 1, FenceCause::LeaseChange),
                    ],
                ),
            ),
            step(
                280,
                input("the-new-holder-types", attachment_b(), 4, 3),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["the-new-holder-types"],
                    vec![ActionShape::Hold(InputRef::new("the-new-holder-types"))],
                ),
            ),
            // Closing at the deadline discards what was held rather than releasing it into a
            // session that no longer accepts input.
            step(
                520,
                Stimulus::SessionClosing,
                expect(
                    FenceState::Closing,
                    None,
                    &[],
                    vec![
                        withhold(WithheldReason::ExchangeTimedOut),
                        busy(
                            EditorBusyReason::FenceExchangeTimedOut,
                            attachment_b(),
                            4,
                            0,
                        ),
                        ActionShape::Discard {
                            input: refs(&["the-new-holder-types"]),
                            reason: DiscardReason::SessionClosing,
                        },
                    ],
                ),
            ),
        ],
    )
}

fn detach_at_the_launch_deadline() -> Scenario {
    let mut steps = launch_prelude();
    steps.push(step(
        15,
        input("typed-during-the-transaction", attachment_a(), 3, 3),
        expect(
            FenceState::LaunchReserved,
            Some(1),
            &["typed-during-the-transaction"],
            vec![ActionShape::Hold(InputRef::new(
                "typed-during-the-transaction",
            ))],
        ),
    ));
    steps.push(step(
        260,
        detach(1, 1, 3),
        expect(
            FenceState::Unfenced,
            None,
            &[],
            vec![
                revoke(1, LaunchRejectionReason::Timeout),
                // No answer to the caller yet: only the reader knows whether it installed
                // anything, and its confirmation is what the answer rests on.
                busy_in(
                    EditorBusyReason::LaunchReservationTimedOut,
                    attachment_a(),
                    3,
                    0,
                    FenceState::Fenced,
                ),
                invalidate(FenceInvalidation::DetachAccepted),
                ActionShape::Discard {
                    input: refs(&["typed-during-the-transaction"]),
                    reason: DiscardReason::AttachmentRemoved,
                },
                cancel_at(1, 3, 1, 1),
                ActionShape::RemoveAttachment(attachment_a()),
                detach_ack(attachment_a(), 3),
            ],
        ),
    ));
    // The reader saw the revocation in the same step it would have installed, and says so. That
    // confirmation is what the caller's EDITOR_BUSY rests on.
    steps.push(step(
        270,
        launch_rejected(1, 1, LaunchRejectionReason::Revoked, 1, 1),
        expect(
            FenceState::Unfenced,
            None,
            &[],
            vec![reject_launch(
                LaunchRejectionReason::Revoked,
                ErrorCode::EditorBusy,
            )],
        ),
    ));
    fence_scenario(
        "detach-at-the-launch-deadline",
        "A gesture that arrives exactly as the launch hold expires: the transaction is refused, and \
         the detaching attachment's own held input is discarded and counted in the detach rather \
         than released to the terminal first.",
        &["KR-REQ-07.82", "KR-REQ-07.83"],
        every_shell(),
        held_by_a(),
        steps,
    )
}

fn launch_confirmation_lost() -> Scenario {
    let mut steps = launch_prelude();
    steps.push(step(
        260,
        Stimulus::HoldExpired,
        expect(
            FenceState::Fenced,
            Some(1),
            &[],
            vec![
                revoke(1, LaunchRejectionReason::Timeout),
                busy_in(
                    EditorBusyReason::LaunchReservationTimedOut,
                    attachment_a(),
                    3,
                    0,
                    FenceState::Fenced,
                ),
            ],
        ),
    ));
    steps.push(step(
        300,
        Stimulus::IntegrationLost(IntegrationLoss::BridgeDisconnected),
        expect(
            FenceState::Unfenced,
            None,
            &[],
            vec![
                reject_launch(
                    LaunchRejectionReason::ConfirmationLost,
                    ErrorCode::OutcomeUnknown,
                ),
                invalidate(FenceInvalidation::IntegrationLost),
            ],
        ),
    ));
    fence_scenario(
        "launch-confirmation-lost",
        "The bridge ends before it says what it did with a revoked transaction: the command may or \
         may not be in the editor, nothing left can say which, and the caller is told exactly that \
         rather than being told it failed.",
        &["KR-REQ-07.83"],
        every_shell(),
        held_by_a(),
        steps,
    )
}

fn two_outstanding_confirmations() -> Scenario {
    let mut steps = launch_prelude();
    steps.push(step(
        260,
        Stimulus::HoldExpired,
        expect(
            FenceState::Fenced,
            Some(1),
            &[],
            vec![
                revoke(1, LaunchRejectionReason::Timeout),
                busy_in(
                    EditorBusyReason::LaunchReservationTimedOut,
                    attachment_a(),
                    3,
                    0,
                    FenceState::Fenced,
                ),
            ],
        ),
    ));
    // A second launch while the first is still unresolved. Each transaction keeps its own answer.
    steps.push(step(
        270,
        launch(1, 1, attachment_a(), 2),
        expect(
            FenceState::LaunchReserved,
            Some(1),
            &[],
            vec![send_launch(2, 1, 1, 1)],
        ),
    ));
    steps.push(step(
        520,
        Stimulus::HoldExpired,
        expect(
            FenceState::Fenced,
            Some(1),
            &[],
            vec![
                revoke(2, LaunchRejectionReason::Timeout),
                busy_in(
                    EditorBusyReason::LaunchReservationTimedOut,
                    attachment_a(),
                    3,
                    0,
                    FenceState::Fenced,
                ),
            ],
        ),
    ));
    // The first reader answer arrives after the second transaction was revoked, and it still
    // answers the first caller rather than being lost.
    steps.push(step(
        530,
        launch_rejected(1, 1, LaunchRejectionReason::Revoked, 1, 1),
        expect(
            FenceState::Fenced,
            Some(1),
            &[],
            vec![reject_launch(
                LaunchRejectionReason::Revoked,
                ErrorCode::EditorBusy,
            )],
        ),
    ));
    // The bridge then ends, and the second caller is told nothing can say what happened.
    steps.push(step(
        540,
        Stimulus::IntegrationLost(IntegrationLoss::BridgeDisconnected),
        expect(
            FenceState::Unfenced,
            None,
            &[],
            vec![
                reject_launch(
                    LaunchRejectionReason::ConfirmationLost,
                    ErrorCode::OutcomeUnknown,
                ),
                invalidate(FenceInvalidation::IntegrationLost),
            ],
        ),
    ));
    fence_scenario(
        "two-outstanding-confirmations",
        "Two transactions can be unresolved at once, and each keeps its own answer: the first \
         caller hears the reader's confirmation, and the second hears that nothing can say what \
         happened to it.",
        &["KR-REQ-07.83"],
        every_shell(),
        held_by_a(),
        steps,
    )
}

fn integration_lost() -> Scenario {
    fence_scenario(
        "integration-lost",
        "Losing the semantic hooks takes the fence and any transaction with them, because both rest \
         on a reader the session can no longer speak for; an unqualified root replacement leaves \
         nothing registered at all.",
        &["KR-REQ-07.39", "KR-REQ-07.75"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            fenced_at(5, 1),
            step(
                10,
                launch(1, 1, attachment_a(), 1),
                expect(
                    FenceState::LaunchReserved,
                    Some(1),
                    &[],
                    vec![send_launch(1, 1, 1, 1)],
                ),
            ),
            step(
                15,
                input("typed-before-the-loss", attachment_a(), 3, 3),
                expect(
                    FenceState::LaunchReserved,
                    Some(1),
                    &["typed-before-the-loss"],
                    vec![ActionShape::Hold(InputRef::new("typed-before-the-loss"))],
                ),
            ),
            step(
                20,
                Stimulus::IntegrationLost(IntegrationLoss::SemanticHookLoss),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        // The semantic hooks are gone but the bridge may still answer, so the
                        // caller's answer waits for it.
                        revoke(1, LaunchRejectionReason::FenceInvalid),
                        invalidate(FenceInvalidation::IntegrationLost),
                        ActionShape::Release(refs(&["typed-before-the-loss"])),
                    ],
                ),
            ),
            step(
                30,
                detach(1, 1, 3),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ActionShape::RejectDetach(DetachRejection::FenceMissing)],
                ),
            ),
            step(
                40,
                launch(1, 1, attachment_a(), 2),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![reject_launch(
                        LaunchRejectionReason::FenceInvalid,
                        ErrorCode::EditorBusy,
                    )],
                ),
            ),
            // The root shell is gone, so nothing will ever say what happened to the transaction the
            // hook loss revoked. Its caller is told exactly that.
            step(
                50,
                Stimulus::IntegrationLost(IntegrationLoss::UnqualifiedRootReplacement),
                expect(
                    FenceState::Outside,
                    None,
                    &[],
                    vec![reject_launch(
                        LaunchRejectionReason::ConfirmationLost,
                        ErrorCode::OutcomeUnknown,
                    )],
                ),
            ),
            step(
                60,
                input("straight-to-whatever-is-reading", attachment_a(), 3, 2),
                expect(
                    FenceState::Outside,
                    None,
                    &[],
                    vec![ActionShape::Forward(InputRef::new(
                        "straight-to-whatever-is-reading",
                    ))],
                ),
            ),
        ],
    )
}

// ----- the pre-EOF scenarios -------------------------------------------------------------------

fn condition(source: InputSource, context: ReaderContext, state: EditorState) -> DetachCondition {
    DetachCondition {
        managed_root_editor: true,
        reader_context: context,
        source,
        editor: state,
    }
}

fn eof_context(prompt: u64) -> PreEofContext {
    PreEofContext {
        prompt_generation: PromptGeneration::new(prompt),
        reader_revision: ReaderRevision::new(1),
        key: PressedKey::byte(DEFAULT_EOF_BYTE),
        condition: condition(
            InputSource::Terminal,
            ReaderContext::Primary,
            empty_editor(1),
        ),
    }
}

fn published_fence(candidate: u8, prompt: u64, epoch: u64, origin: AttachmentId) -> EditorFence {
    proof(candidate, prompt, 1, epoch, origin)
}

fn submitted(candidate: u8, prompt: u64, epoch: u64) -> PreEofDecision {
    PreEofDecision::SubmitDetach(RootEofDetachParams {
        session_id: session(),
        fence_id: fence(candidate),
        prompt_generation: PromptGeneration::new(prompt),
        input_epoch: InputLeaseEpoch::new(epoch),
    })
}

fn hinted(reason: ConsumeReason) -> PreEofDecision {
    PreEofDecision::Consume {
        hint: Some("Use kr detach --attachment <id> to detach.".to_owned()),
        reason,
    }
}

fn silent(reason: ConsumeReason) -> PreEofDecision {
    PreEofDecision::Consume { hint: None, reason }
}

fn native(reason: NativeReason) -> PreEofDecision {
    PreEofDecision::Native { reason }
}

fn offer(name: &str, context: PreEofContext, expect: PreEofDecision) -> PreEofStep {
    PreEofStep::Offer {
        name: name.to_owned(),
        context,
        expect,
    }
}

fn pre_eof_scenario(
    id: &str,
    purpose: &str,
    rows: &[&str],
    shells: Vec<ShellKind>,
    steps: Vec<PreEofStep>,
) -> Scenario {
    Scenario {
        id: id.to_owned(),
        purpose: purpose.to_owned(),
        covers: covers(rows),
        shells,
        script: Script::PreEof(PreEofScript {
            view: BridgeFenceView::new(session()),
            steps,
        }),
    }
}

fn detach_condition_exclusions() -> Scenario {
    let pending = |pending: PendingReaderInput, keymap: EditorKeymap| {
        condition(
            InputSource::Terminal,
            ReaderContext::Primary,
            editor(1, true, pending, keymap),
        )
    };
    let excluded = |name: &str, condition: DetachCondition, exclusion: DetachExclusion| {
        offer(
            name,
            PreEofContext {
                condition,
                ..eof_context(1)
            },
            native(NativeReason::Excluded(exclusion)),
        )
    };
    pre_eof_scenario(
        "detach-condition-exclusions",
        "The detach condition needs the managed root editor, the primary prompt and an empty \
         buffer, and the ten states in which the next character belongs to something already in \
         progress, or came from somewhere other than the person at the keyboard, give it back to \
         the editor.",
        &["KR-REQ-07.74", "KR-REQ-07.70"],
        every_shell(),
        vec![
            PreEofStep::Publish(published_fence(1, 1, 3, attachment_a())),
            offer(
                "an-empty-primary-prompt-is-eligible",
                eof_context(1),
                submitted(1, 1, 3),
            ),
            excluded(
                "not-the-managed-root-editor",
                DetachCondition {
                    managed_root_editor: false,
                    ..eof_context(1).condition
                },
                DetachExclusion::NotManagedRootEditor,
            ),
            excluded(
                "continuation-input",
                condition(
                    InputSource::Terminal,
                    ReaderContext::Continuation,
                    empty_editor(1),
                ),
                DetachExclusion::ContinuationInput,
            ),
            excluded(
                "the-read-builtin",
                condition(
                    InputSource::Terminal,
                    ReaderContext::ReadBuiltin,
                    empty_editor(1),
                ),
                DetachExclusion::ReadBuiltin,
            ),
            excluded(
                "a-buffer-with-something-in-it",
                condition(
                    InputSource::Terminal,
                    ReaderContext::Primary,
                    typed_editor(2),
                ),
                DetachExclusion::BufferNotEmpty,
            ),
            excluded(
                "quoted-insertion",
                pending(
                    PendingReaderInput {
                        quoted_insertion: true,
                        ..PendingReaderInput::NONE
                    },
                    EditorKeymap::Emacs,
                ),
                DetachExclusion::QuotedInsertion,
            ),
            excluded(
                "macro-input-in-progress",
                pending(
                    PendingReaderInput {
                        macro_input: true,
                        ..PendingReaderInput::NONE
                    },
                    EditorKeymap::Emacs,
                ),
                DetachExclusion::MacroInput,
            ),
            excluded(
                "the-last-character-of-a-macro",
                condition(InputSource::Macro, ReaderContext::Primary, empty_editor(1)),
                DetachExclusion::MacroInput,
            ),
            excluded(
                "a-key-a-widget-pushed-back",
                condition(
                    InputSource::PushedBack,
                    ReaderContext::Primary,
                    empty_editor(1),
                ),
                DetachExclusion::MacroInput,
            ),
            excluded(
                "search",
                pending(
                    PendingReaderInput {
                        search: true,
                        ..PendingReaderInput::NONE
                    },
                    EditorKeymap::Emacs,
                ),
                DetachExclusion::Search,
            ),
            excluded(
                "a-numeric-argument",
                pending(
                    PendingReaderInput {
                        numeric_argument: true,
                        ..PendingReaderInput::NONE
                    },
                    EditorKeymap::Emacs,
                ),
                DetachExclusion::NumericArgument,
            ),
            excluded(
                "a-pending-multikey-sequence",
                pending(
                    PendingReaderInput {
                        multikey_sequence: true,
                        ..PendingReaderInput::NONE
                    },
                    EditorKeymap::Emacs,
                ),
                DetachExclusion::MultikeySequence,
            ),
            excluded(
                "a-vi-motion",
                pending(
                    PendingReaderInput {
                        vi_motion: true,
                        ..PendingReaderInput::NONE
                    },
                    EditorKeymap::ViCommand,
                ),
                DetachExclusion::ViMotion,
            ),
            excluded(
                "an-open-paste",
                pending(
                    PendingReaderInput {
                        paste: true,
                        ..PendingReaderInput::NONE
                    },
                    EditorKeymap::Emacs,
                ),
                DetachExclusion::Paste,
            ),
            excluded(
                "the-last-character-of-a-paste",
                condition(InputSource::Paste, ReaderContext::Primary, empty_editor(1)),
                DetachExclusion::Paste,
            ),
        ],
    )
}

fn eof_missing_fence() -> Scenario {
    pre_eof_scenario(
        "eof-missing-fence",
        "With no fence the gesture is consumed rather than turned into an empty-prompt end of file, \
         and the hint appears once per prompt.",
        &["KR-REQ-07.81", "KR-REQ-07.74"],
        every_shell(),
        vec![
            offer(
                "the-first-gesture-at-this-prompt-prints-the-hint",
                eof_context(1),
                hinted(ConsumeReason::FenceMissing),
            ),
            offer(
                "the-second-at-the-same-prompt-is-silent",
                eof_context(1),
                silent(ConsumeReason::FenceMissing),
            ),
            offer(
                "the-next-prompt-may-hint-again",
                eof_context(2),
                hinted(ConsumeReason::FenceMissing),
            ),
            PreEofStep::Publish(published_fence(1, 2, 3, attachment_a())),
            offer(
                "a-fence-from-an-earlier-prompt-is-stale",
                eof_context(3),
                hinted(ConsumeReason::FenceStale),
            ),
            PreEofStep::Publish(published_fence(2, 3, 3, attachment_a())),
            offer(
                "a-fence-from-a-reader-this-one-replaced-is-stale-too",
                PreEofContext {
                    reader_revision: ReaderRevision::new(2),
                    ..eof_context(3)
                },
                silent(ConsumeReason::FenceStale),
            ),
        ],
    )
}

fn eof_stale_fence() -> Scenario {
    fence_scenario(
        "eof-stale-fence",
        "The worker refuses a detach that names a fence it no longer holds, whether the identity, \
         the prompt generation or the epoch is the stale part.",
        &["KR-REQ-07.81", "KR-REQ-07.82"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            fenced_at(5, 1),
            step(
                10,
                detach(2, 1, 3),
                expect(
                    FenceState::Fenced,
                    Some(1),
                    &[],
                    vec![ActionShape::RejectDetach(DetachRejection::FenceStale)],
                ),
            ),
            step(
                20,
                detach(1, 2, 3),
                expect(
                    FenceState::Fenced,
                    Some(1),
                    &[],
                    vec![ActionShape::RejectDetach(DetachRejection::FenceStale)],
                ),
            ),
            step(
                30,
                detach(1, 1, 4),
                expect(
                    FenceState::Fenced,
                    Some(1),
                    &[],
                    vec![ActionShape::RejectDetach(DetachRejection::FenceStale)],
                ),
            ),
        ],
    )
}

fn eof_repeated_after_detach() -> Scenario {
    pre_eof_scenario(
        "eof-repeated-after-detach",
        "A gesture that has already been delivered is consumed while the reader is unfenced, and a \
         detach the worker refuses is consumed the same way: the character has already left the \
         reader, so the hint is the only honest answer left.",
        &["KR-REQ-07.82", "KR-REQ-07.81"],
        every_shell(),
        vec![
            PreEofStep::Publish(published_fence(1, 1, 3, attachment_a())),
            offer(
                "the-fenced-gesture-detaches-its-own-attachment",
                eof_context(1),
                submitted(1, 1, 3),
            ),
            PreEofStep::Invalidate,
            offer(
                "the-repeat-after-the-detach-is-consumed",
                eof_context(1),
                hinted(ConsumeReason::FenceMissing),
            ),
            offer(
                "and-cannot-adopt-whatever-arrives-next",
                eof_context(1),
                silent(ConsumeReason::FenceMissing),
            ),
            PreEofStep::Publish(published_fence(2, 2, 4, attachment_b())),
            offer(
                "the-next-attachments-fence-detaches-the-next-attachment",
                eof_context(2),
                submitted(2, 2, 4),
            ),
            PreEofStep::DetachRefused {
                name: "a-detach-the-worker-refuses-prints-the-hint".to_owned(),
                prompt_generation: PromptGeneration::new(2),
                expect_hint: Some("Use kr detach --attachment <id> to detach.".to_owned()),
            },
            PreEofStep::DetachRefused {
                name: "and-only-once-for-that-prompt".to_owned(),
                prompt_generation: PromptGeneration::new(2),
                expect_hint: None,
            },
        ],
    )
}

fn eof_after_detach_succession() -> Scenario {
    fence_scenario(
        "eof-after-detach-succession",
        "After a detach no new fence publishes until the old queues drain, and a gesture that names \
         the departed attachment's fence cannot borrow the next attachment's identity.",
        &["KR-REQ-07.82", "KR-REQ-07.79"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            fenced_at(5, 1),
            step(
                10,
                detach(1, 1, 3),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        invalidate(FenceInvalidation::DetachAccepted),
                        cancel_at(1, 3, 1, 1),
                        ActionShape::RemoveAttachment(attachment_a()),
                        detach_ack(attachment_a(), 0),
                    ],
                ),
            ),
            step(
                20,
                lease_change(4, Some(attachment_b()), 2, 0),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        lease_ack(4, Some(attachment_b()), 0, &[]),
                        ask(2, 1, 1, FenceCause::LeaseChange),
                    ],
                ),
            ),
            step(
                30,
                acknowledgement(
                    2,
                    1,
                    1,
                    QueueDrainReport {
                        tty_typeahead_drained: false,
                        ..QueueDrainReport::CLEAR
                    },
                    KeyQueueSnapshot {
                        keys: Bytes::new(Vec::new()),
                        pending_bytes: U64::new(2),
                        queued_keys: U64::ZERO,
                    },
                    empty_editor(1),
                ),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        withhold(WithheldReason::QueuesNotDrained),
                        busy(EditorBusyReason::QueuesNotDrained, attachment_b(), 4, 0),
                    ],
                ),
            ),
            step(
                40,
                detach(1, 1, 3),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ActionShape::RejectDetach(DetachRejection::FenceMissing)],
                ),
            ),
            step(
                50,
                idle(1, 1, 3),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ask(3, 1, 1, FenceCause::Retry)],
                ),
            ),
            step(
                55,
                drained(3, 1, 1, empty_editor(1)),
                expect(
                    FenceState::Fenced,
                    Some(3),
                    &[],
                    vec![publish(3, 1, 1, 4, attachment_b())],
                ),
            ),
            step(
                60,
                detach(3, 1, 4),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        invalidate(FenceInvalidation::DetachAccepted),
                        // The second cancellation of this session, and a departure's: it ends the
                        // reader's wait and opens no takeover receipt, because nothing asked for a
                        // takeover.
                        cancel_at(2, 4, 1, 1),
                        ActionShape::RemoveAttachment(attachment_b()),
                        detach_ack(attachment_b(), 0),
                    ],
                ),
            ),
        ],
    )
}

fn veof_change() -> Scenario {
    pre_eof_scenario(
        "veof-change",
        "A reassigned VEOF is a user change to the gesture and takes effect at the next prompt: the \
         character typed at this prompt is still judged by the gesture that was in force when it \
         was typed.",
        &["KR-REQ-07.73", "KR-REQ-07.74"],
        unix_shells(),
        vec![
            PreEofStep::Publish(published_fence(1, 1, 3, attachment_a())),
            offer(
                "the-default-gesture-detaches",
                eof_context(1),
                submitted(1, 1, 3),
            ),
            PreEofStep::Gesture(EofGestureChange {
                session_id: session(),
                gesture: EofGesture::TerminalEof {
                    byte: U64::new(u64::from(b'q')),
                },
                effective_at: PromptGeneration::new(2),
            }),
            offer(
                "the-old-byte-still-detaches-at-the-prompt-it-was-typed-at",
                eof_context(1),
                submitted(1, 1, 3),
            ),
            PreEofStep::Publish(published_fence(2, 2, 3, attachment_a())),
            offer(
                "at-the-next-prompt-the-old-byte-is-ordinary-input",
                eof_context(2),
                native(NativeReason::NotTheGesture),
            ),
            offer(
                "and-the-new-byte-carries-the-detach",
                PreEofContext {
                    key: PressedKey::byte(b'q'),
                    ..eof_context(2)
                },
                submitted(2, 2, 3),
            ),
        ],
    )
}

fn veof_disabled() -> Scenario {
    pre_eof_scenario(
        "veof-disabled",
        "A terminal with VEOF disabled has no end-of-file gesture from the next prompt on, so no \
         character is one and nothing is consumed.",
        &["KR-REQ-07.73"],
        unix_shells(),
        vec![
            PreEofStep::Publish(published_fence(1, 1, 3, attachment_a())),
            PreEofStep::Gesture(EofGestureChange {
                session_id: session(),
                gesture: EofGesture::Disabled,
                effective_at: PromptGeneration::new(2),
            }),
            offer(
                "the-gesture-typed-before-the-change-still-detaches",
                eof_context(1),
                submitted(1, 1, 3),
            ),
            PreEofStep::Publish(published_fence(2, 2, 3, attachment_a())),
            offer(
                "with-veof-disabled-the-byte-is-the-editors",
                eof_context(2),
                native(NativeReason::GestureDisabled),
            ),
            PreEofStep::Gesture(EofGestureChange {
                session_id: session(),
                gesture: EofGesture::default(),
                effective_at: PromptGeneration::new(3),
            }),
            PreEofStep::Publish(published_fence(3, 3, 3, attachment_a())),
            offer(
                "restoring-a-gesture-restores-the-detach",
                eof_context(3),
                submitted(3, 3, 3),
            ),
        ],
    )
}

fn psreadline_chord_gesture() -> Scenario {
    let chord = |keys: &str, prompt: u64| PreEofContext {
        key: PressedKey::chord(keys),
        ..eof_context(prompt)
    };
    Scenario {
        id: "psreadline-chord-gesture".to_owned(),
        purpose: "Windows uses the configured PSReadLine gesture, which is a chord rather than a \
                  byte: the configured chord carries the detach and any other chord is the \
                  editor's own."
            .to_owned(),
        covers: covers(&["KR-REQ-07.73", "KR-REQ-07.74"]),
        shells: vec![ShellKind::PowerShell],
        script: Script::PreEof(PreEofScript {
            view: BridgeFenceView {
                session_id: session(),
                fence: None,
                gesture: EofGesture::Chord {
                    keys: "Ctrl+d".to_owned(),
                },
                pending_gesture: None,
                hinted_for: None,
            },
            steps: vec![
                PreEofStep::Publish(published_fence(1, 1, 3, attachment_a())),
                offer(
                    "the-configured-chord-detaches",
                    chord("Ctrl+d", 1),
                    submitted(1, 1, 3),
                ),
                offer(
                    "another-chord-is-the-editors-own",
                    chord("Ctrl+k", 1),
                    native(NativeReason::NotTheGesture),
                ),
                offer(
                    "and-so-is-the-unix-byte",
                    eof_context(1),
                    native(NativeReason::NotTheGesture),
                ),
            ],
        }),
    }
}

// ----- acceptance, leave boundaries, retries and the remaining machine rules -------------------

fn acceptance_read_builtin() -> Scenario {
    fence_scenario(
        "acceptance-read-builtin",
        "Input a running command reads through the line editor is accepted like a line and is not \
         one. The record stays with the line that started the command, whoever answers the read \
         and whatever fence that reader is given, so an unqualified kr detach still belongs to the \
         terminal the command was typed in.",
        &["KR-REQ-07.84"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            step(
                5,
                drained(1, 1, 1, empty_editor(1)),
                expect(
                    FenceState::Fenced,
                    Some(1),
                    &[],
                    vec![publish(1, 1, 1, 3, attachment_a())],
                ),
            ),
            // A types the line, which is the record every later detach resolves against.
            step(
                10,
                accepted_command(Some(1), 1, fenced_origin(attachment_a(), 3)),
                with_target(
                    expect(
                        FenceState::Fenced,
                        Some(1),
                        &[],
                        vec![ActionShape::RecordAcceptance(fenced_origin(
                            attachment_a(),
                            3,
                        ))],
                    ),
                    DetachTarget::Attachment(attachment_a()),
                ),
            ),
            step(
                15,
                leave(1, 1, EditorLeaveReason::CommandAccepted),
                with_target(
                    expect(
                        FenceState::Outside,
                        None,
                        &[],
                        vec![invalidate(FenceInvalidation::EditorLeft)],
                    ),
                    DetachTarget::Attachment(attachment_a()),
                ),
            ),
            // The command it started asks a question, and B has the keys by the time it does.
            step(
                20,
                lease_change(4, Some(attachment_b()), 2, 0),
                with_target(
                    expect(
                        FenceState::Outside,
                        None,
                        &[],
                        vec![lease_ack(4, Some(attachment_b()), 0, &[])],
                    ),
                    DetachTarget::Attachment(attachment_a()),
                ),
            ),
            step(
                25,
                enter_in(1, 2, 2, ReaderContext::ReadBuiltin),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ask(2, 1, 2, FenceCause::EditorEntry)],
                ),
            ),
            step(
                30,
                drained_in(2, 1, 2, empty_editor(1), ReaderContext::ReadBuiltin),
                expect(
                    FenceState::Fenced,
                    Some(2),
                    &[],
                    vec![publish(2, 1, 2, 4, attachment_b())],
                ),
            ),
            // B answers the question. It is B's input, under B's fence, and it is not a line: the
            // command A typed is still the one running and still the one a detach is about.
            step(
                35,
                accepted_command(Some(2), 1, fenced_origin(attachment_b(), 4)),
                with_target(
                    expect(
                        FenceState::Fenced,
                        Some(2),
                        &[],
                        vec![ActionShape::RetainAcceptance(Some(fenced_origin(
                            attachment_a(),
                            3,
                        )))],
                    ),
                    DetachTarget::Attachment(attachment_a()),
                ),
            ),
        ],
    )
}

fn acceptance_mixed_context() -> Scenario {
    fence_scenario(
        "acceptance-mixed-context",
        "An accepted line records the attachment and epoch it came from through the fenced context. \
         A mixed or unverifiable context makes an unqualified kr detach AMBIGUOUS_ATTACHMENT rather \
         than a guess, and a lease change afterwards never moves the recorded origin.",
        &["KR-REQ-07.84"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            step(
                5,
                drained(1, 1, 1, empty_editor(1)),
                with_target(
                    expect(
                        FenceState::Fenced,
                        Some(1),
                        &[],
                        vec![publish(1, 1, 1, 3, attachment_a())],
                    ),
                    DetachTarget::Ambiguous(AmbiguityReason::NoAcceptedCommand),
                ),
            ),
            step(
                10,
                accepted_command(Some(1), 1, fenced_origin(attachment_a(), 3)),
                with_target(
                    expect(
                        FenceState::Fenced,
                        Some(1),
                        &[],
                        vec![ActionShape::RecordAcceptance(fenced_origin(
                            attachment_a(),
                            3,
                        ))],
                    ),
                    DetachTarget::Attachment(attachment_a()),
                ),
            ),
            step(
                15,
                leave(1, 1, EditorLeaveReason::CommandAccepted),
                with_target(
                    expect(
                        FenceState::Outside,
                        None,
                        &[],
                        vec![invalidate(FenceInvalidation::EditorLeft)],
                    ),
                    DetachTarget::Attachment(attachment_a()),
                ),
            ),
            // The child command is running and another client takes the lease. The recorded origin
            // is still the attachment that typed the line.
            step(
                20,
                lease_change(4, Some(attachment_b()), 2, 0),
                with_target(
                    expect(
                        FenceState::Outside,
                        None,
                        &[],
                        vec![lease_ack(4, Some(attachment_b()), 0, &[])],
                    ),
                    DetachTarget::Attachment(attachment_a()),
                ),
            ),
            step(
                30,
                enter(2, 1, 2),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ask(2, 2, 1, FenceCause::EditorEntry)],
                ),
            ),
            step(
                35,
                drained(2, 2, 1, empty_editor(1)),
                expect(
                    FenceState::Fenced,
                    Some(2),
                    &[],
                    vec![publish(2, 2, 1, 4, attachment_b())],
                ),
            ),
            step(
                40,
                accepted_command(Some(2), 2, AcceptedOrigin::Mixed),
                with_target(
                    expect(
                        FenceState::Fenced,
                        Some(2),
                        &[],
                        vec![ActionShape::RecordAcceptance(AcceptedOrigin::Mixed)],
                    ),
                    DetachTarget::Ambiguous(AmbiguityReason::MixedContext),
                ),
            ),
            step(
                45,
                accepted_command(Some(2), 2, fenced_origin(attachment_a(), 4)),
                with_target(
                    expect(
                        FenceState::Fenced,
                        Some(2),
                        &[],
                        vec![ActionShape::RecordAcceptance(AcceptedOrigin::Mixed)],
                    ),
                    DetachTarget::Ambiguous(AmbiguityReason::MixedContext),
                ),
            ),
            step(
                50,
                leave(2, 1, EditorLeaveReason::Preexec),
                expect(
                    FenceState::Outside,
                    None,
                    &[],
                    vec![invalidate(FenceInvalidation::EditorLeft)],
                ),
            ),
            step(
                55,
                accepted_command(None, 3, fenced_origin(attachment_b(), 4)),
                with_target(
                    expect(
                        FenceState::Outside,
                        None,
                        &[],
                        vec![ActionShape::RecordAcceptance(AcceptedOrigin::Unverifiable)],
                    ),
                    DetachTarget::Ambiguous(AmbiguityReason::Unverifiable),
                ),
            ),
        ],
    )
}

fn editor_leave_boundaries() -> Scenario {
    let boundary = |at: u64, prompt: u64, candidate: u8, reason: EditorLeaveReason| {
        vec![
            step(
                at,
                enter(prompt, 1, candidate),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ask(candidate, prompt, 1, FenceCause::EditorEntry)],
                ),
            ),
            step(
                at + 2,
                drained(candidate, prompt, 1, empty_editor(1)),
                expect(
                    FenceState::Fenced,
                    Some(candidate),
                    &[],
                    vec![publish(candidate, prompt, 1, 3, attachment_a())],
                ),
            ),
            step(
                at + 4,
                leave(prompt, 1, reason),
                expect(
                    FenceState::Outside,
                    None,
                    &[],
                    vec![invalidate(FenceInvalidation::EditorLeft)],
                ),
            ),
        ]
    };
    let mut steps = Vec::new();
    steps.extend(boundary(0, 1, 1, EditorLeaveReason::CommandAccepted));
    steps.extend(boundary(10, 2, 2, EditorLeaveReason::Preexec));
    steps.extend(boundary(20, 3, 3, EditorLeaveReason::ReaderTakeover));
    steps.extend(boundary(30, 4, 4, EditorLeaveReason::Cancellation));
    // A leave from a reader this one has already replaced must not deregister the reader running
    // now.
    steps.push(step(
        40,
        enter(5, 2, 5),
        expect(
            FenceState::Unfenced,
            None,
            &[],
            vec![ask(5, 5, 2, FenceCause::EditorEntry)],
        ),
    ));
    steps.push(step(
        42,
        leave(4, 1, EditorLeaveReason::Cancellation),
        expect(
            FenceState::Unfenced,
            None,
            &[],
            vec![ActionShape::IgnoreStale(StaleMessage::ReaderEvent)],
        ),
    ));
    steps.push(step(
        44,
        leave(5, 2, EditorLeaveReason::RootExit),
        expect(
            FenceState::Outside,
            None,
            &[],
            vec![withhold(WithheldReason::EditorLeft)],
        ),
    ));
    fence_scenario(
        "editor-leave-boundaries",
        "The reader reports leaving at each of the five boundaries, and each one invalidates the \
         fence. A leave from a reader that has already been replaced is ignored instead of \
         deregistering the one running now.",
        &["KR-REQ-07.76", "KR-REQ-07.75"],
        every_shell(),
        held_by_a(),
        steps,
    )
}

fn retry_at_entry_and_leave() -> Scenario {
    fence_scenario(
        "retry-at-entry-and-leave",
        "A withheld fence is retried at the reader's next entry as well as at its idle callback, a \
         replacement entry withholds the exchange the previous reader was to answer without \
         discarding what is held, and a leave releases it because nothing outside a registered root \
         editor waits for a fence.",
        &["KR-REQ-07.79", "KR-REQ-07.77"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            step(
                10,
                input("typed-before-the-retry", attachment_a(), 3, 4),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["typed-before-the-retry"],
                    vec![ActionShape::Hold(InputRef::new("typed-before-the-retry"))],
                ),
            ),
            // The reader restarts inside the same prompt before the hold expires. The exchange it
            // was to answer dies with it; the held batch stays, because a retry waits for the mixed
            // queues rather than discarding them.
            step(
                20,
                enter(1, 2, 2),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["typed-before-the-retry"],
                    vec![
                        withhold(WithheldReason::ReaderMoved),
                        // What is left of the original hold, not a fresh one: the hold belongs to
                        // the input this client has already sent.
                        ask_within(2, 1, 2, FenceCause::EditorEntry, 230),
                    ],
                ),
            ),
            step(
                30,
                acknowledgement(
                    2,
                    1,
                    2,
                    QueueDrainReport {
                        macro_input_drained: false,
                        ..QueueDrainReport::CLEAR
                    },
                    KeyQueueSnapshot {
                        keys: Bytes::new(Vec::new()),
                        pending_bytes: U64::ZERO,
                        queued_keys: U64::new(2),
                    },
                    empty_editor(1),
                ),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![
                        withhold(WithheldReason::QueuesNotDrained),
                        ActionShape::Release(refs(&["typed-before-the-retry"])),
                        busy(EditorBusyReason::QueuesNotDrained, attachment_a(), 3, 4),
                    ],
                ),
            ),
            step(
                40,
                enter(1, 3, 3),
                expect(
                    FenceState::Unfenced,
                    None,
                    &[],
                    vec![ask(3, 1, 3, FenceCause::EditorEntry)],
                ),
            ),
            step(
                50,
                input("typed-during-the-second-retry", attachment_a(), 3, 2),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["typed-during-the-second-retry"],
                    vec![ActionShape::Hold(InputRef::new(
                        "typed-during-the-second-retry",
                    ))],
                ),
            ),
            // The old command has reached a foreground application: the reader leaves, and the held
            // input goes to whatever is reading the terminal now rather than waiting for a prompt
            // that is not coming.
            step(
                60,
                leave(1, 3, EditorLeaveReason::Preexec),
                expect(
                    FenceState::Outside,
                    None,
                    &[],
                    vec![
                        withhold(WithheldReason::EditorLeft),
                        ActionShape::Release(refs(&["typed-during-the-second-retry"])),
                    ],
                ),
            ),
            step(
                70,
                input("straight-to-the-application", attachment_a(), 3, 1),
                expect(
                    FenceState::Outside,
                    None,
                    &[],
                    vec![ActionShape::Forward(InputRef::new(
                        "straight-to-the-application",
                    ))],
                ),
            ),
        ],
    )
}

fn interrupt_bypasses_the_hold() -> Scenario {
    fence_scenario(
        "interrupt-bypasses-the-hold",
        "An interrupt is not held for a reader transition, needs the current epoch and the lease, \
         and carries only the configured native action.",
        &["KR-REQ-07.80"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            step(
                10,
                input("held-while-fencing", attachment_a(), 3, 4),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["held-while-fencing"],
                    vec![ActionShape::Hold(InputRef::new("held-while-fencing"))],
                ),
            ),
            step(
                20,
                interrupt(attachment_a(), 3),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["held-while-fencing"],
                    vec![ActionShape::Interrupt(InterruptAction::NativeInterrupt)],
                ),
            ),
            step(
                30,
                interrupt(attachment_a(), 2),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["held-while-fencing"],
                    vec![ActionShape::RefuseInterrupt(LeaseFault::LeaseLost)],
                ),
            ),
            step(
                40,
                interrupt(attachment_b(), 3),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["held-while-fencing"],
                    vec![ActionShape::RefuseInterrupt(LeaseFault::NotHolder)],
                ),
            ),
        ],
    )
}

fn outside_state_bypass() -> Scenario {
    fence_scenario(
        "outside-state-bypass",
        "Outside a registered root editor the lease changes and input forwards immediately: an \
         application does not have a reader bridge, and no end-of-file candidate queue delays \
         anything.",
        &["KR-REQ-07.77", "KR-REQ-07.76"],
        every_shell(),
        held_by_a(),
        vec![
            step(
                0,
                lease_change(4, Some(attachment_b()), 1, 7),
                expect(
                    FenceState::Outside,
                    None,
                    &[],
                    vec![lease_ack(4, Some(attachment_b()), 7, &[])],
                ),
            ),
            step(
                10,
                input("straight-to-the-application", attachment_b(), 4, 6),
                expect(
                    FenceState::Outside,
                    None,
                    &[],
                    vec![ActionShape::Forward(InputRef::new(
                        "straight-to-the-application",
                    ))],
                ),
            ),
            step(
                20,
                input("from-a-lease-that-is-gone", attachment_a(), 3, 2),
                expect(
                    FenceState::Outside,
                    None,
                    &[],
                    vec![ActionShape::Discard {
                        input: refs(&["from-a-lease-that-is-gone"]),
                        reason: DiscardReason::StaleEpoch,
                    }],
                ),
            ),
            step(
                30,
                detach(1, 1, 4),
                expect(
                    FenceState::Outside,
                    None,
                    &[],
                    vec![ActionShape::RejectDetach(DetachRejection::FenceMissing)],
                ),
            ),
            step(
                40,
                idle(1, 1, 2),
                expect(
                    FenceState::Outside,
                    None,
                    &[],
                    vec![ActionShape::IgnoreStale(StaleMessage::ReaderEvent)],
                ),
            ),
        ],
    )
}

fn closing_rejects_input() -> Scenario {
    fence_scenario(
        "closing-rejects-input",
        "Closing invalidates the fence, discards what was held and refuses input, a detach and an \
         interrupt alike.",
        &["KR-REQ-07.75", "KR-REQ-07.80"],
        every_shell(),
        held_by_a(),
        vec![
            entered(1),
            step(
                5,
                input("held-when-the-session-closed", attachment_a(), 3, 4),
                expect(
                    FenceState::Unfenced,
                    None,
                    &["held-when-the-session-closed"],
                    vec![ActionShape::Hold(InputRef::new(
                        "held-when-the-session-closed",
                    ))],
                ),
            ),
            step(
                10,
                Stimulus::SessionClosing,
                expect(
                    FenceState::Closing,
                    None,
                    &[],
                    vec![
                        withhold(WithheldReason::SessionClosing),
                        ActionShape::Discard {
                            input: refs(&["held-when-the-session-closed"]),
                            reason: DiscardReason::SessionClosing,
                        },
                    ],
                ),
            ),
            step(
                20,
                input("after-closing", attachment_a(), 3, 1),
                expect(
                    FenceState::Closing,
                    None,
                    &[],
                    vec![ActionShape::RefuseInput(InputRefusal::SessionClosing)],
                ),
            ),
            step(
                30,
                detach(1, 1, 3),
                expect(
                    FenceState::Closing,
                    None,
                    &[],
                    vec![ActionShape::RejectDetach(DetachRejection::SessionClosing)],
                ),
            ),
            step(
                40,
                interrupt(attachment_a(), 3),
                expect(
                    FenceState::Closing,
                    None,
                    &[],
                    vec![ActionShape::RefuseInterrupt(LeaseFault::SessionClosing)],
                ),
            ),
            step(
                50,
                launch(1, 1, attachment_a(), 1),
                expect(
                    FenceState::Closing,
                    None,
                    &[],
                    vec![reject_launch(
                        LaunchRejectionReason::SessionClosing,
                        ErrorCode::SessionClosed,
                    )],
                ),
            ),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scenario_replays_against_the_contract() {
        for scenario in scenarios() {
            let replay = replay(&scenario);
            assert!(
                replay.passed(),
                "{} does not hold:\n{}",
                scenario.id,
                replay.failures.join("\n")
            );
            assert!(replay.checks > 0, "{} asserts nothing", scenario.id);
        }
    }

    #[test]
    fn every_scenario_has_a_distinct_name_and_names_its_requirements() {
        let scenarios = scenarios();
        let mut ids: Vec<&str> = scenarios
            .iter()
            .map(|scenario| scenario.id.as_str())
            .collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count);
        for scenario in &scenarios {
            assert!(
                !scenario.covers.is_empty(),
                "{} covers nothing",
                scenario.id
            );
            assert!(
                !scenario.shells.is_empty(),
                "{} is for no shell",
                scenario.id
            );
            assert!(
                !scenario.purpose.is_empty(),
                "{} says nothing about itself",
                scenario.id
            );
        }
    }

    #[test]
    fn the_handshake_scenarios_name_every_qualification_reason() {
        let mut named = Vec::new();
        for scenario in scenarios() {
            if let Script::Handshake(script) = &scenario.script {
                for case in &script.cases {
                    if let HandshakeExpectation::Refused { reason, .. } = case.expect {
                        named.push(reason);
                    }
                }
            }
        }
        for reason in QualificationReason::ALL {
            assert!(
                named.contains(reason),
                "no scenario produces {}",
                reason.as_str()
            );
        }
    }

    #[test]
    fn the_launch_scenarios_name_every_rejection_reason() {
        let mut named = Vec::new();
        for scenario in scenarios() {
            match &scenario.script {
                Script::Launch(script) => {
                    for case in &script.cases {
                        if let LaunchExpectation::Rejected { reason, .. } = case.expect {
                            named.push(reason);
                        }
                    }
                }
                Script::Fence(script) => {
                    for step in &script.steps {
                        for action in &step.expect.actions {
                            // A reason reaches the caller as a rejection and the reader as a
                            // revocation, and the corpus must show it doing both.
                            match action {
                                ActionShape::RejectLaunch { reason, .. }
                                | ActionShape::RevokeLaunch { reason, .. } => named.push(*reason),
                                _ => {}
                            }
                        }
                    }
                }
                Script::Handshake(_) | Script::PreEof(_) => {}
            }
        }
        for reason in LaunchRejectionReason::ALL {
            assert!(
                named.contains(reason),
                "no scenario produces {}",
                reason.as_str()
            );
        }
    }

    #[test]
    fn every_scenario_round_trips_through_its_committed_form() {
        for scenario in scenarios() {
            let rendered = render(&scenario);
            let decoded: Scenario = serde_json::from_str(&rendered).expect("a scenario decodes");
            assert_eq!(decoded, scenario);
        }
    }
}
