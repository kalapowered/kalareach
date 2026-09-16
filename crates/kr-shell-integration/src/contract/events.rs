//! What the bridge reports, and the pre-EOF decision it takes.
//!
//! Every event here comes from the reader itself, at the moment the reader does the thing. That is
//! the whole point of a patched reader rather than a prompt hook: `root.editor.enter` means the
//! primary reader has started, not that a prompt has been printed, and `root.editor.leave` arrives
//! before the reader returns rather than after the next prompt appears.
//!
//! # The pre-EOF decision
//!
//! Readline and ZLE recognise an empty-line end of file before an ordinary binding runs, so each
//! managed package's native hook is called immediately before that branch, after the next character
//! has been selected from the reader's input sources. The hook is handed the actual character, which
//! input source it came from, the reader's state and which reader is asking, and it answers
//! [`PatchAnswer::Native`] or [`PatchAnswer::Consume`] without replacing the user's binding.
//!
//! [`BridgeFenceView::decide`] is that answer. It is a pure function of the reader's state and the
//! fence the worker last published, which is what keeps three rules together:
//!
//! * Outside the detach condition the character is the editor's own, so the answer is `native`.
//! * With a fence for this exact reader, the gesture becomes an attributable `root.eof.detach`.
//! * Without one, the gesture is consumed with at most one hint per prompt, and never converted
//!   into a native empty-prompt end of file.
//! * A detach the worker then refuses is consumed the same way, through
//!   [`BridgeFenceView::detach_refused`]. The character has already left the reader, so the only
//!   honest answer left is the hint.

use kr_protocol::ids::SessionId;
use kr_protocol::root::{
    CwdRevision, DETACH_HINT, EditorFence, EditorState, KeyQueueSnapshot, PromptGeneration,
    ReaderContext, ReaderRevision, RootCommandAcceptedParams, RootEditorEnterParams,
    RootEditorLeaveParams, RootEofDetachParams,
};
use kr_protocol::scalars::U64;
use serde::{Deserialize, Serialize};

use crate::contract::qualification::{
    DetachCondition, DetachEligibility, DetachExclusion, IntegrationLoss,
};

/// The byte a terminal's `VEOF` carries by default.
pub const DEFAULT_EOF_BYTE: u8 = 0x04;

/// The key that ends input.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EofGesture {
    /// The terminal's `VEOF` byte, which the integration reads from the line discipline rather than
    /// assuming. A user who reassigns `VEOF` has changed the gesture, and the new byte takes effect
    /// at the next prompt.
    TerminalEof {
        /// The byte value, 0 to 255.
        byte: U64,
    },
    /// `VEOF` is disabled, so this terminal has no end-of-file gesture and no character can be one.
    Disabled,
    /// The configured PSReadLine gesture, which is a chord rather than a byte.
    Chord {
        /// The chord as PSReadLine names it.
        keys: String,
    },
}

impl Default for EofGesture {
    fn default() -> Self {
        Self::TerminalEof {
            byte: U64::new(u64::from(DEFAULT_EOF_BYTE)),
        }
    }
}

impl EofGesture {
    /// Returns true when `key` is this gesture.
    #[must_use]
    pub fn matches(&self, key: &PressedKey) -> bool {
        match (self, key) {
            (Self::TerminalEof { byte }, PressedKey::Byte { byte: pressed }) => byte == pressed,
            (Self::Chord { keys }, PressedKey::Chord { keys: pressed }) => keys == pressed,
            (Self::Disabled, _) | (Self::TerminalEof { .. } | Self::Chord { .. }, _) => false,
        }
    }
}

/// The key the reader selected.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressedKey {
    /// One byte, as a Unix reader sees it.
    Byte {
        /// The byte value, 0 to 255.
        byte: U64,
    },
    /// A chord, as PSReadLine reports it.
    Chord {
        /// The chord.
        keys: String,
    },
}

impl PressedKey {
    /// Names a byte.
    #[must_use]
    pub const fn byte(value: u8) -> Self {
        Self::Byte {
            byte: U64::new(value as u64),
        }
    }

    /// Names a chord.
    #[must_use]
    pub fn chord(keys: impl Into<String>) -> Self {
        Self::Chord { keys: keys.into() }
    }
}

/// What the native pre-EOF hook hands the integration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreEofContext {
    /// The prompt the reader is at.
    pub prompt_generation: PromptGeneration,
    /// The revision of the reader.
    pub reader_revision: ReaderRevision,
    /// The character the reader selected.
    pub key: PressedKey,
    /// The detach condition as the reader itself reports it, including where the character came
    /// from.
    pub condition: DetachCondition,
}

/// What the native hook returns.
///
/// The published patches return exactly these two values, and neither replaces the user's saved
/// binding. `consume` continues the same reader call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchAnswer {
    /// Let the reader take its own end-of-file branch.
    Native,
    /// Consume the character and continue the same reader.
    Consume,
}

impl PatchAnswer {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Consume => "consume",
        }
    }
}

/// Why a character is the editor's own to handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeReason {
    /// The character is not the configured end-of-file gesture.
    NotTheGesture,
    /// This terminal has no end-of-file gesture, because `VEOF` is disabled.
    GestureDisabled,
    /// The detach condition does not hold.
    Excluded(DetachExclusion),
}

/// Why an eligible gesture was consumed instead of submitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumeReason {
    /// No fence has been published, so nothing can say whose gesture this is.
    FenceMissing,
    /// The published fence belongs to an earlier prompt.
    FenceStale,
}

impl ConsumeReason {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FenceMissing => "fence_missing",
            Self::FenceStale => "fence_stale",
        }
    }
}

/// What the integration does with the character.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreEofDecision {
    /// The editor or the application handles it normally.
    Native {
        /// Why it is theirs.
        reason: NativeReason,
    },
    /// Submit an attributable detach for the fence this gesture arrived under.
    SubmitDetach(RootEofDetachParams),
    /// Consume the gesture and continue the same reader.
    Consume {
        /// The hint to print, at most once per prompt.
        hint: Option<String>,
        /// Why the gesture could not be submitted.
        reason: ConsumeReason,
    },
}

impl PreEofDecision {
    /// Returns what the native hook is told.
    ///
    /// A submitted detach consumes the character as well: the reader continues, the attachment goes
    /// away, and the shell keeps running. Only [`Self::Native`] gives the character back.
    #[must_use]
    pub const fn patch_answer(&self) -> PatchAnswer {
        match self {
            Self::Native { .. } => PatchAnswer::Native,
            Self::SubmitDetach(_) | Self::Consume { .. } => PatchAnswer::Consume,
        }
    }
}

/// The bridge's own view of the fence, and what it has already printed.
///
/// A bridge cannot infer that its acknowledgement published a fence, so this holds only what the
/// worker has told it: [`Self::publish`] on a published fence, [`Self::invalidate`] when the worker
/// withholds one, when the reader leaves, when the lease changes and after a successful detach.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeFenceView {
    /// The session.
    pub session_id: SessionId,
    /// The fence the worker last published, if it is still valid.
    pub fence: Option<EditorFence>,
    /// The gesture in force now.
    pub gesture: EofGesture,
    /// A gesture the line discipline has changed to, which takes effect at its prompt.
    pub pending_gesture: Option<PendingGesture>,
    /// The prompt a hint has already been printed for.
    pub hinted_for: Option<PromptGeneration>,
}

/// A gesture change that has been observed but is not in force yet.
///
/// A `VEOF` reassignment is a user change to the gesture, and it takes effect at the next prompt
/// rather than in the middle of a read: the character the reader is holding was typed under the old
/// gesture.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingGesture {
    /// The gesture from `effective_at` onwards.
    pub gesture: EofGesture,
    /// The prompt it takes effect at.
    pub effective_at: PromptGeneration,
}

impl BridgeFenceView {
    /// Builds a view with no fence and the default gesture.
    #[must_use]
    pub fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            fence: None,
            gesture: EofGesture::default(),
            pending_gesture: None,
            hinted_for: None,
        }
    }

    /// Records a fence the worker published.
    pub fn publish(&mut self, fence: EditorFence) {
        self.fence = Some(fence);
    }

    /// Drops the fence.
    ///
    /// After this, a repeated gesture is consumed rather than submitted, and its hint names no
    /// attachment: a gesture that was already delivered cannot take on the identity of whichever
    /// attachment arrives next.
    pub fn invalidate(&mut self) {
        self.fence = None;
    }

    /// Records a gesture change, to take effect at the prompt the change names.
    ///
    /// The character the reader is holding now was typed under the gesture in force when it was
    /// typed, so nothing changes mid-read.
    pub fn observe_gesture(&mut self, change: &EofGestureChange) {
        self.pending_gesture = Some(PendingGesture {
            gesture: change.gesture.clone(),
            effective_at: change.effective_at,
        });
    }

    /// Consumes the gesture the worker refused a detach for.
    ///
    /// The gesture has already been taken from the reader, so it cannot be given back. The bridge
    /// drops its fence, consumes the character and prints the hint, at most once per prompt.
    pub fn detach_refused(&mut self, prompt: PromptGeneration) -> Option<String> {
        self.fence = None;
        match self.consume(prompt, ConsumeReason::FenceStale) {
            PreEofDecision::Consume { hint, .. } => hint,
            PreEofDecision::Native { .. } | PreEofDecision::SubmitDetach(_) => None,
        }
    }

    /// Decides what to do with a character the native hook offered.
    pub fn decide(&mut self, context: &PreEofContext) -> PreEofDecision {
        self.promote_gesture(context.prompt_generation);
        if self.gesture == EofGesture::Disabled {
            return PreEofDecision::Native {
                reason: NativeReason::GestureDisabled,
            };
        }
        if !self.gesture.matches(&context.key) {
            return PreEofDecision::Native {
                reason: NativeReason::NotTheGesture,
            };
        }
        if let DetachEligibility::Excluded(exclusion) =
            crate::contract::qualification::detach_eligibility(&context.condition)
        {
            return PreEofDecision::Native {
                reason: NativeReason::Excluded(exclusion),
            };
        }
        match &self.fence {
            // The reader revision is part of the fence's proof, so a fence taken before a plugin
            // restarted the reader inside this prompt is as stale as one from an earlier prompt.
            Some(fence)
                if fence.prompt_generation == context.prompt_generation
                    && fence.reader_revision == context.reader_revision =>
            {
                PreEofDecision::SubmitDetach(RootEofDetachParams {
                    session_id: self.session_id,
                    fence_id: fence.fence_id,
                    prompt_generation: fence.prompt_generation,
                    input_epoch: fence.input_epoch,
                })
            }
            Some(_) => self.consume(context.prompt_generation, ConsumeReason::FenceStale),
            None => self.consume(context.prompt_generation, ConsumeReason::FenceMissing),
        }
    }

    fn promote_gesture(&mut self, prompt: PromptGeneration) {
        let Some(pending) = self.pending_gesture.as_ref() else {
            return;
        };
        if prompt >= pending.effective_at {
            self.gesture = pending.gesture.clone();
            self.pending_gesture = None;
        }
    }

    fn consume(&mut self, prompt: PromptGeneration, reason: ConsumeReason) -> PreEofDecision {
        let hint = if self.hinted_for == Some(prompt) {
            None
        } else {
            self.hinted_for = Some(prompt);
            Some(DETACH_HINT.to_owned())
        };
        PreEofDecision::Consume { hint, reason }
    }
}

/// The reader reporting that it is idle with nothing left to read.
///
/// One of the three points a withheld fence is retried at. The snapshot is the same atomic read a
/// fence acknowledgement carries, so a retry starts from evidence rather than from a hope that the
/// queues have drained by now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderIdle {
    /// The session.
    pub session_id: SessionId,
    /// The prompt the reader is at.
    pub prompt_generation: PromptGeneration,
    /// The reader's revision.
    pub reader_revision: ReaderRevision,
    /// Which reader is idle.
    pub reader_context: ReaderContext,
    /// Its key queues at this instant.
    pub snapshot: KeyQueueSnapshot,
    /// Its buffer state at the same instant.
    pub editor: EditorState,
    /// The shell's working-directory revision at the same instant.
    pub cwd_revision: CwdRevision,
}

/// The end-of-file gesture changed.
///
/// A `VEOF` reassignment is a user change to the gesture, and it takes effect at the next prompt
/// rather than mid-reader. Disabling `VEOF` leaves the terminal with no gesture at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EofGestureChange {
    /// The session.
    pub session_id: SessionId,
    /// The gesture from now on.
    pub gesture: EofGesture,
    /// The prompt it takes effect at.
    pub effective_at: PromptGeneration,
}

/// The bridge consumed an eligible gesture it could not attribute.
///
/// Reported so the session can say why a Ctrl-D did nothing, and so a hint is counted rather than
/// repeated: at most one per prompt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreEofConsumed {
    /// The session.
    pub session_id: SessionId,
    /// The prompt it happened at.
    pub prompt_generation: PromptGeneration,
    /// Why the gesture could not be submitted.
    pub reason: ConsumeReason,
    /// Whether this one printed the hint.
    pub hint_printed: bool,
}

/// The integration's user-facing hooks are live.
///
/// Sent once, after the user's startup files have run and before the first primary reader the
/// session will report. It is what moves a session from authenticated to qualified: until it
/// arrives, rich launch and a ready or create success stay disabled, because a startup file could
/// still replace the reader or fail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksActivated {
    /// The session.
    pub session_id: SessionId,
    /// The prompt generation the first primary reader will start at.
    pub prompt_generation: PromptGeneration,
}

/// The integration lost the ground it stood on.
///
/// Reported by the bridge for what it can see, and inferred by the worker when the bridge's
/// connection ends. What each loss does to the session is
/// [`phase_after`](crate::contract::qualification::phase_after); what it does to a live fence and a
/// pending launch is the state machine's `integration_lost` stimulus.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationLostReport {
    /// The session.
    pub session_id: SessionId,
    /// What was lost.
    pub loss: IntegrationLoss,
    /// What the session can say about it, for its diagnostics. Never a command line and never a
    /// credential.
    pub detail: String,
}

/// Something the reader did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeEvent {
    /// `root.editor.enter`: the actual primary reader started.
    EditorEnter(RootEditorEnterParams),
    /// `root.editor.leave`: it stopped, with the reason.
    EditorLeave(RootEditorLeaveParams),
    /// The reader is idle with nothing left to read.
    ReaderIdle(ReaderIdle),
    /// `root.eof.detach`: an eligible gesture at an empty primary prompt, under a fence.
    EofDetach(RootEofDetachParams),
    /// `root.command.accepted`: the accepted line and where it came from.
    CommandAccepted(RootCommandAcceptedParams),
    /// The end-of-file gesture changed.
    GestureChanged(EofGestureChange),
    /// An eligible gesture was consumed because it could not be attributed.
    PreEofConsumed(PreEofConsumed),
    /// The integration's user-facing hooks are live after the startup files.
    HooksActivated(HooksActivated),
    /// The integration lost its hooks, its reader or its root shell.
    IntegrationLost(IntegrationLostReport),
}

#[cfg(test)]
mod tests {
    use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
    use kr_protocol::ids::{AttachmentId, InputLeaseEpoch};
    use kr_protocol::root::{EditorBufferRevision, EditorKeymap, FenceId, PendingReaderInput};

    use crate::contract::qualification::InputSource;
    use kr_protocol::scalars::Uuid;

    use super::*;

    fn session() -> SessionId {
        SessionId::new(Uuid::from_bytes([0x11; 16]))
    }

    fn fence(prompt: u64) -> EditorFence {
        EditorFence {
            fence_id: FenceId::new(Uuid::from_bytes([0xF1; 16])),
            root_process: ProcessStartIdentity::new(
                4242,
                ProcessStartSource::MacosProcBsdInfo,
                900,
            ),
            prompt_generation: PromptGeneration::new(prompt),
            reader_revision: ReaderRevision::new(1),
            input_epoch: InputLeaseEpoch::new(3),
            originating_attachment: AttachmentId::new(Uuid::from_bytes([0xA1; 16])),
        }
    }

    fn context(prompt: u64) -> PreEofContext {
        PreEofContext {
            prompt_generation: PromptGeneration::new(prompt),
            reader_revision: ReaderRevision::new(1),
            key: PressedKey::byte(DEFAULT_EOF_BYTE),
            condition: DetachCondition {
                managed_root_editor: true,
                reader_context: ReaderContext::Primary,
                source: InputSource::Terminal,
                editor: EditorState {
                    buffer_revision: EditorBufferRevision::new(1),
                    buffer_empty: true,
                    keymap: EditorKeymap::Emacs,
                    pending: PendingReaderInput::NONE,
                },
            },
        }
    }

    #[test]
    fn a_fenced_gesture_becomes_an_attributable_detach() {
        let mut view = BridgeFenceView::new(session());
        view.publish(fence(7));
        let decision = view.decide(&context(7));
        assert_eq!(decision.patch_answer(), PatchAnswer::Consume);
        let PreEofDecision::SubmitDetach(params) = decision else {
            panic!("a fenced gesture submits");
        };
        assert_eq!(params.fence_id, fence(7).fence_id);
        assert_eq!(params.prompt_generation, PromptGeneration::new(7));
        assert_eq!(params.input_epoch, InputLeaseEpoch::new(3));
    }

    #[test]
    fn a_missing_fence_consumes_the_gesture_and_hints_once_per_prompt() {
        let mut view = BridgeFenceView::new(session());
        let first = view.decide(&context(7));
        assert_eq!(
            first,
            PreEofDecision::Consume {
                hint: Some(DETACH_HINT.to_owned()),
                reason: ConsumeReason::FenceMissing,
            }
        );
        let second = view.decide(&context(7));
        assert_eq!(
            second,
            PreEofDecision::Consume {
                hint: None,
                reason: ConsumeReason::FenceMissing,
            }
        );
        let next_prompt = view.decide(&context(8));
        assert_eq!(
            next_prompt,
            PreEofDecision::Consume {
                hint: Some(DETACH_HINT.to_owned()),
                reason: ConsumeReason::FenceMissing,
            }
        );
    }

    #[test]
    fn a_fence_from_an_earlier_prompt_is_stale() {
        let mut view = BridgeFenceView::new(session());
        view.publish(fence(7));
        assert_eq!(
            view.decide(&context(8)),
            PreEofDecision::Consume {
                hint: Some(DETACH_HINT.to_owned()),
                reason: ConsumeReason::FenceStale,
            }
        );
    }

    #[test]
    fn a_repeated_gesture_after_a_detach_cannot_take_the_next_attachments_identity() {
        let mut view = BridgeFenceView::new(session());
        view.publish(fence(7));
        assert!(matches!(
            view.decide(&context(7)),
            PreEofDecision::SubmitDetach(_)
        ));
        view.invalidate();
        let repeated = view.decide(&context(7));
        assert_eq!(
            repeated,
            PreEofDecision::Consume {
                hint: Some(DETACH_HINT.to_owned()),
                reason: ConsumeReason::FenceMissing,
            }
        );
    }

    #[test]
    fn a_character_that_is_not_the_gesture_stays_the_editors_own() {
        let mut view = BridgeFenceView::new(session());
        view.publish(fence(7));
        let ordinary = PreEofContext {
            key: PressedKey::byte(b'a'),
            ..context(7)
        };
        assert_eq!(
            view.decide(&ordinary),
            PreEofDecision::Native {
                reason: NativeReason::NotTheGesture
            }
        );
        assert_eq!(view.decide(&ordinary).patch_answer(), PatchAnswer::Native);
    }

    #[test]
    fn a_disabled_veof_leaves_the_terminal_without_a_gesture() {
        let mut view = BridgeFenceView::new(session());
        view.publish(fence(7));
        view.observe_gesture(&EofGestureChange {
            session_id: session(),
            gesture: EofGesture::Disabled,
            effective_at: PromptGeneration::new(7),
        });
        assert_eq!(
            view.decide(&context(7)),
            PreEofDecision::Native {
                reason: NativeReason::GestureDisabled
            }
        );
    }

    #[test]
    fn a_reassigned_veof_becomes_the_gesture() {
        let mut view = BridgeFenceView::new(session());
        view.publish(fence(7));
        view.observe_gesture(&EofGestureChange {
            session_id: session(),
            gesture: EofGesture::TerminalEof {
                byte: U64::new(u64::from(b'q')),
            },
            effective_at: PromptGeneration::new(7),
        });
        assert_eq!(
            view.decide(&context(7)),
            PreEofDecision::Native {
                reason: NativeReason::NotTheGesture
            }
        );
        let reassigned = PreEofContext {
            key: PressedKey::byte(b'q'),
            ..context(7)
        };
        assert!(matches!(
            view.decide(&reassigned),
            PreEofDecision::SubmitDetach(_)
        ));
    }

    #[test]
    fn a_configured_chord_is_the_gesture_on_windows() {
        let mut view = BridgeFenceView::new(session());
        view.publish(fence(7));
        view.observe_gesture(&EofGestureChange {
            session_id: session(),
            gesture: EofGesture::Chord {
                keys: "Ctrl+d".to_owned(),
            },
            effective_at: PromptGeneration::new(7),
        });
        let chord = PreEofContext {
            key: PressedKey::chord("Ctrl+d"),
            ..context(7)
        };
        assert!(matches!(
            view.decide(&chord),
            PreEofDecision::SubmitDetach(_)
        ));
    }

    #[test]
    fn a_gesture_change_takes_effect_at_the_prompt_it_names() {
        let mut view = BridgeFenceView::new(session());
        view.publish(fence(7));
        view.observe_gesture(&EofGestureChange {
            session_id: session(),
            gesture: EofGesture::TerminalEof {
                byte: U64::new(u64::from(b'q')),
            },
            effective_at: PromptGeneration::new(8),
        });
        // Still the old gesture at the prompt the character was typed at.
        assert!(matches!(
            view.decide(&context(7)),
            PreEofDecision::SubmitDetach(_)
        ));
        view.publish(fence(8));
        let at_the_next_prompt = PreEofContext {
            prompt_generation: PromptGeneration::new(8),
            ..context(8)
        };
        assert_eq!(
            view.decide(&at_the_next_prompt),
            PreEofDecision::Native {
                reason: NativeReason::NotTheGesture
            }
        );
        let reassigned = PreEofContext {
            key: PressedKey::byte(b'q'),
            ..at_the_next_prompt
        };
        assert!(matches!(
            view.decide(&reassigned),
            PreEofDecision::SubmitDetach(_)
        ));
    }

    #[test]
    fn a_refused_detach_is_consumed_with_the_hint_once_per_prompt() {
        let mut view = BridgeFenceView::new(session());
        view.publish(fence(7));
        assert!(matches!(
            view.decide(&context(7)),
            PreEofDecision::SubmitDetach(_)
        ));
        assert_eq!(
            view.detach_refused(PromptGeneration::new(7)),
            Some(DETACH_HINT.to_owned())
        );
        assert_eq!(view.detach_refused(PromptGeneration::new(7)), None);
        assert_eq!(
            view.decide(&context(7)),
            PreEofDecision::Consume {
                hint: None,
                reason: ConsumeReason::FenceMissing,
            }
        );
    }

    #[test]
    fn a_fence_from_another_reader_at_the_same_prompt_is_stale() {
        let mut view = BridgeFenceView::new(session());
        view.publish(fence(7));
        let restarted = PreEofContext {
            reader_revision: ReaderRevision::new(2),
            ..context(7)
        };
        assert_eq!(
            view.decide(&restarted),
            PreEofDecision::Consume {
                hint: Some(DETACH_HINT.to_owned()),
                reason: ConsumeReason::FenceStale,
            }
        );
    }

    #[test]
    fn an_excluded_state_gives_the_character_back_to_the_editor() {
        let mut view = BridgeFenceView::new(session());
        view.publish(fence(7));
        let searching = PreEofContext {
            condition: DetachCondition {
                editor: EditorState {
                    pending: PendingReaderInput {
                        search: true,
                        ..PendingReaderInput::NONE
                    },
                    ..context(7).condition.editor
                },
                ..context(7).condition
            },
            ..context(7)
        };
        assert_eq!(
            view.decide(&searching),
            PreEofDecision::Native {
                reason: NativeReason::Excluded(DetachExclusion::Search)
            }
        );
    }
}
