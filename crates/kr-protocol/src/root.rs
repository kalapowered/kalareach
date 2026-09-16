//! The trusted root integration: editor registration, the delivery fence and the launch
//! transaction.
//!
//! Section 7 gives the managed root shell one job the rest of the protocol cannot do for it: say
//! which client's keystrokes reached the line editor, and say it with proof rather than with a
//! timestamp. That proof is the fence in [`EditorFence`]: the root process the shell is actually
//! running as, the prompt it is at, the revision of the reader inside that prompt, the input-lease
//! epoch the bytes arrived under, and exactly one originating attachment.
//!
//! Everything else here exists to keep that proof honest:
//!
//! * A fence is published only after the bridge has acknowledged that the old typeahead, macro and
//!   partial-key queues are clear ([`FenceAcknowledgement`]), and withheld when they are not
//!   ([`FencePublication`]). A prompt hook or a kernel byte count is not a substitute.
//! * A detach names the fence it belongs to ([`RootEofDetachParams`]), so an empty-prompt Ctrl-D
//!   removes the attachment that typed it and never the one that happens to hold the lease now.
//! * A launch is installed through the reader's own mailbox against an expected prompt generation
//!   and buffer revision ([`ShellLaunchParams`]), so a command cannot land in an application that
//!   took the terminal in the meantime.
//!
//! The types are the wire half of that contract. The state machine every managed shell package and
//! the worker drive them through lives in the `kr-shell-integration` crate.

use core::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

use crate::identity::ProcessStartIdentity;
use crate::ids::{AttachmentId, InputLeaseEpoch, SessionId};
use crate::scalars::{Bytes, DurationMs, Nullable, U64, Uuid};

/// How long the worker holds new input while a reader transition resolves.
///
/// Section 7 fixes it at 250 ms for the fence exchange, for plain editor entry and for a launch
/// transaction alike. On expiry the lease change still stands: the held input is released in its
/// original order and the editor stays unfenced. A reader that replaces another inside the same
/// hold does not restart it: the hold belongs to the input, not to the reader.
pub const FENCE_EXCHANGE_TIMEOUT: DurationMs = DurationMs::new(250);

/// How long the reader has to decide a launch, measured from when it receives the request.
///
/// Shorter than the worker's hold on purpose. The two sides measure on their own clocks, so the
/// only way "on timeout, install no command" can be a fact rather than a hope is for the reader's
/// own budget to end before the worker gives up, with the difference covering one local frame each
/// way. A worker that has already spent part of its hold sends what is left of this budget rather
/// than the whole of it, so queueing shortens the reader's window and never extends it.
pub const LAUNCH_READER_BUDGET: DurationMs = DurationMs::new(200);

/// The hint a bridge prints when it consumes an end-of-file gesture it cannot attribute.
///
/// It is printed exactly as written, `<id>` included. The hint appears only when no fence can name
/// an attachment, so there is nothing to substitute: an identifier guessed from the current lease
/// would be the uncertain attribution the gesture was consumed to avoid. The person names one.
pub const DETACH_HINT: &str = "Use kr detach --attachment <id> to detach.";

/// The event type an `EDITOR_BUSY` notice carries on the attachments stream.
pub const EDITOR_BUSY_EVENT: &str = "editor_busy";

/// One published fence.
///
/// The identity is allocated by the worker when it starts a fence exchange and becomes meaningful
/// only when that exchange is acknowledged; an identity from an exchange that timed out never names
/// a fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FenceId(pub Uuid);

impl FenceId {
    /// Wraps a raw identifier.
    #[must_use]
    pub const fn new(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the raw identifier.
    #[must_use]
    pub const fn get(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for FenceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl JsonSchema for FenceId {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "FenceId".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::FenceId".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let mut schema = Uuid::json_schema(generator);
        schema.insert(
            "description".to_owned(),
            "One published editor fence. An identity from an unacknowledged exchange names no fence."
                .into(),
        );
        schema
    }
}

/// The prompt the root editor is at.
///
/// It advances at every primary prompt, so a decision taken at one prompt cannot be replayed at the
/// next.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct PromptGeneration(pub U64);

/// The revision of the reader inside one prompt.
///
/// It advances whenever the reader restarts or is replaced within the same prompt, which is how a
/// fence taken before a plugin restarted the reader is recognised as stale.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ReaderRevision(pub U64);

/// The revision of the editor's edit buffer.
///
/// Every change to the buffer advances it, including one made by a completion widget or a
/// highlighting plugin, so a launch that expected an empty buffer can tell that something has been
/// typed since.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct EditorBufferRevision(pub U64);

/// The revision of the root shell's working directory.
///
/// The shell reports it at every reader boundary, so a launch can be refused when the directory has
/// changed since the caller decided what to run. Section 23 lists it among the preconditions of
/// `shell.launch`.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct CwdRevision(pub U64);

macro_rules! counter {
    ($name:ident, $description:literal) => {
        impl $name {
            /// Wraps a raw counter.
            #[must_use]
            pub const fn new(value: u64) -> Self {
                Self(U64::new(value))
            }

            /// Returns the raw counter.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, formatter)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> std::borrow::Cow<'static, str> {
                concat!("kalareach::", stringify!($name)).into()
            }

            fn json_schema(generator: &mut SchemaGenerator) -> Schema {
                // The scalar's schema is written out rather than referenced, so the named type
                // survives a generator that flattens an alias of an alias.
                let mut schema = U64::json_schema(generator);
                schema.insert("description".to_owned(), $description.into());
                schema
            }
        }
    };
}

counter!(
    PromptGeneration,
    "The prompt the root editor is at. It advances at every primary prompt."
);
counter!(
    ReaderRevision,
    "The revision of the reader inside one prompt. It advances whenever the reader restarts or is replaced."
);
counter!(
    EditorBufferRevision,
    "The revision of the editor's edit buffer. Every change to the buffer advances it."
);
counter!(
    CwdRevision,
    "The revision of the root shell's working directory. It advances whenever the directory changes."
);

/// Which reader a root editor event belongs to.
///
/// The three are what a pre-EOF decision and a fence acknowledgement have to distinguish. Only the
/// primary reader can carry the empty-prompt detach; a continuation line and the `read` builtin are
/// ordinary input even when the buffer looks empty.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ReaderContext {
    /// The primary prompt of the managed root editor.
    Primary,
    /// A continuation line of an unfinished command.
    Continuation,
    /// The shell's `read` builtin reading through the line editor.
    ReadBuiltin,
}

impl ReaderContext {
    /// Every context, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Primary, Self::Continuation, Self::ReadBuiltin];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Continuation => "continuation",
            Self::ReadBuiltin => "read_builtin",
        }
    }

    /// Returns true when this is the primary prompt.
    #[must_use]
    pub const fn is_primary(self) -> bool {
        matches!(self, Self::Primary)
    }
}

/// The keymap the reader is in.
///
/// It is reported rather than imposed: the integration never changes a user's keymap, and a vi
/// command-mode motion in progress is one of the states that excludes the detach condition.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EditorKeymap {
    /// The emacs-style keymap.
    Emacs,
    /// Vi insert mode.
    ViInsert,
    /// Vi command mode.
    ViCommand,
    /// A keymap the user selected that is none of the above.
    Custom,
}

impl EditorKeymap {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Emacs => "emacs",
            Self::ViInsert => "vi_insert",
            Self::ViCommand => "vi_command",
            Self::Custom => "custom",
        }
    }
}

/// What the reader is in the middle of.
///
/// Each field names an operation that is waiting for another key or is mid-way through a sequence.
/// Any of them excludes the detach condition, because the next character belongs to that operation
/// rather than to an empty prompt, and all of them are read from the reader's own state rather than
/// guessed from the terminal.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct PendingReaderInput {
    /// A quoted insertion is waiting for the character to insert literally.
    pub quoted_insertion: bool,
    /// The reader is consuming a macro rather than the terminal.
    pub macro_input: bool,
    /// An incremental or non-incremental search is active.
    pub search: bool,
    /// A numeric argument is being accumulated.
    pub numeric_argument: bool,
    /// A multikey sequence has begun and is waiting for its remaining keys.
    pub multikey_sequence: bool,
    /// A vi motion is waiting for its target.
    pub vi_motion: bool,
    /// A bracketed paste is open.
    pub paste: bool,
}

impl PendingReaderInput {
    /// Nothing pending.
    pub const NONE: Self = Self {
        quoted_insertion: false,
        macro_input: false,
        search: false,
        numeric_argument: false,
        multikey_sequence: false,
        vi_motion: false,
        paste: false,
    };

    /// Returns true when the reader is between operations and the next key starts a new one.
    #[must_use]
    pub const fn is_idle(self) -> bool {
        !(self.quoted_insertion
            || self.macro_input
            || self.search
            || self.numeric_argument
            || self.multikey_sequence
            || self.vi_motion
            || self.paste)
    }
}

/// The reader's own view of its edit buffer.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct EditorState {
    /// The buffer revision this state was read at.
    pub buffer_revision: EditorBufferRevision,
    /// True when the buffer holds nothing, as the reader itself reports it.
    pub buffer_empty: bool,
    /// The keymap in force.
    pub keymap: EditorKeymap,
    /// What the reader is in the middle of.
    pub pending: PendingReaderInput,
}

/// The reader's key queues at one instant, snapshotted atomically.
///
/// These are the native equivalents of Zsh's `$KEYS`, `$PENDING` and `$KEYS_QUEUED_COUNT`, and
/// every managed package supplies them from the reader's own state under its own lock. Two reads
/// taken a moment apart would describe two different instants, which is exactly the ambiguity a
/// fence exists to remove.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct KeyQueueSnapshot {
    /// The key sequence that invoked the reader's current operation. Empty between operations.
    pub keys: Bytes,
    /// Bytes still unread in the reader's own input queue.
    pub pending_bytes: U64,
    /// Keys still queued ahead of the terminal, including pushed-back and macro keys.
    pub queued_keys: U64,
}

impl KeyQueueSnapshot {
    /// An empty snapshot: nothing invoked, nothing pending, nothing queued.
    #[must_use]
    pub fn drained() -> Self {
        Self {
            keys: Bytes::new(Vec::new()),
            pending_bytes: U64::ZERO,
            queued_keys: U64::ZERO,
        }
    }

    /// Returns true when the reader has no unread input of its own.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.pending_bytes == U64::ZERO && self.queued_keys == U64::ZERO
    }
}

/// Which of the reader's input queues the bridge has cleared.
///
/// A fence publishes only when all three are clear. Reporting them separately is what makes a
/// retry possible: the worker learns which queue is still holding input rather than only that the
/// transition failed.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct QueueDrainReport {
    /// The terminal's typeahead has been consumed by this reader.
    pub tty_typeahead_drained: bool,
    /// No macro input remains.
    pub macro_input_drained: bool,
    /// No partial key sequence remains.
    pub partial_key_drained: bool,
}

impl QueueDrainReport {
    /// Every queue clear.
    pub const CLEAR: Self = Self {
        tty_typeahead_drained: true,
        macro_input_drained: true,
        partial_key_drained: true,
    };

    /// Returns true when every queue is clear.
    #[must_use]
    pub const fn all_drained(self) -> bool {
        self.tty_typeahead_drained && self.macro_input_drained && self.partial_key_drained
    }
}

/// The ownership proof for the input delivered during one editor epoch.
///
/// Every field is evidence rather than inference. The root process says which shell this is, the
/// prompt generation and reader revision say which reader instance, the lease epoch says which
/// client's bytes could have reached it, and the single originating attachment is the one a detach
/// or an accepted line belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EditorFence {
    /// The fence identity.
    pub fence_id: FenceId,
    /// The root shell process, with the kernel's record of when it started.
    pub root_process: ProcessStartIdentity,
    /// The prompt the reader is at.
    pub prompt_generation: PromptGeneration,
    /// The reader revision inside that prompt.
    pub reader_revision: ReaderRevision,
    /// The input-lease epoch the fenced input belongs to.
    pub input_epoch: InputLeaseEpoch,
    /// The one attachment whose input this fence covers.
    pub originating_attachment: AttachmentId,
}

/// What the worker knows about the root editor.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FenceState {
    /// No root editor is registered. Input forwards immediately and a lease change waits for
    /// nothing: an application does not have a reader bridge.
    Outside,
    /// A root editor is registered and no fence is valid.
    Unfenced,
    /// A root editor is registered and its fence is valid.
    Fenced,
    /// A launch transaction holds the current fence while the reader's mailbox decides.
    LaunchReserved,
    /// The session is closing. Input is rejected; interruption, attachment removal and closure
    /// remain available.
    Closing,
}

impl FenceState {
    /// Every state, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Outside,
        Self::Unfenced,
        Self::Fenced,
        Self::LaunchReserved,
        Self::Closing,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Outside => "outside",
            Self::Unfenced => "unfenced",
            Self::Fenced => "fenced",
            Self::LaunchReserved => "launch_reserved",
            Self::Closing => "closing",
        }
    }

    /// Returns true when a valid fence exists in this state.
    #[must_use]
    pub const fn holds_fence(self) -> bool {
        matches!(self, Self::Fenced | Self::LaunchReserved)
    }

    /// Returns true when a reader transition in this state uses the hold and fence exchange.
    ///
    /// Only a registered root editor does. Outside one, and while closing, input never waits for a
    /// reader bridge.
    #[must_use]
    pub const fn uses_hold_exchange(self) -> bool {
        matches!(self, Self::Unfenced | Self::Fenced | Self::LaunchReserved)
    }
}

impl fmt::Display for FenceState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Parameters of `root.editor.enter`.
///
/// Sent when the actual primary reader starts, not when a prompt is printed. A prompt hook runs
/// before the reader exists and cannot stand in for this.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootEditorEnterParams {
    /// The session.
    pub session_id: SessionId,
    /// The root shell process and the kernel's record of when it started.
    pub root_process: ProcessStartIdentity,
    /// The prompt the reader is starting at.
    pub prompt_generation: PromptGeneration,
    /// The revision of this reader inside that prompt.
    pub reader_revision: ReaderRevision,
    /// Which reader started.
    pub reader_context: ReaderContext,
    /// The reader's own initial state, including its keymap.
    pub editor: EditorState,
    /// The shell's working-directory revision at this boundary.
    pub cwd_revision: CwdRevision,
}

/// The result of `root.editor.enter`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootEditorEnterResult {
    /// The state after registration. Entry always invalidates the previous fence, so this is
    /// `unfenced` until an exchange is acknowledged.
    pub state: FenceState,
    /// The fence exchange the worker started, when it started one.
    pub fence_exchange: Nullable<FenceId>,
}

/// Why a root editor stopped.
///
/// The bridge reports one of these before the reader returns, so the fence cannot outlive the
/// reader it proves something about.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EditorLeaveReason {
    /// The line was accepted and the reader is returning it.
    CommandAccepted,
    /// The shell is about to run a command and its pre-execution hook has run.
    Preexec,
    /// Another reader took over, such as a nested reader or a pager inside the shell.
    ReaderTakeover,
    /// The reader was cancelled.
    Cancellation,
    /// The root shell is exiting.
    RootExit,
}

impl EditorLeaveReason {
    /// Every reason, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::CommandAccepted,
        Self::Preexec,
        Self::ReaderTakeover,
        Self::Cancellation,
        Self::RootExit,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommandAccepted => "command_accepted",
            Self::Preexec => "preexec",
            Self::ReaderTakeover => "reader_takeover",
            Self::Cancellation => "cancellation",
            Self::RootExit => "root_exit",
        }
    }
}

/// Parameters of `root.editor.leave`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootEditorLeaveParams {
    /// The session.
    pub session_id: SessionId,
    /// The prompt the reader was at.
    pub prompt_generation: PromptGeneration,
    /// The revision of the reader that is leaving.
    pub reader_revision: ReaderRevision,
    /// Why it stopped.
    pub reason: EditorLeaveReason,
}

/// The result of `root.editor.leave`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootEditorLeaveResult {
    /// The state after the reader left. Leaving invalidates the fence.
    pub state: FenceState,
}

/// Parameters of `root.editor.fence`: the worker asking the bridge to resolve prior input.
///
/// The identity travels with the question so the acknowledgement can be matched to it. An
/// acknowledgement that arrives after the deadline names an exchange that no longer exists and
/// publishes nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootEditorFenceParams {
    /// The session.
    pub session_id: SessionId,
    /// The identity the fence will have if this exchange is acknowledged in time.
    pub fence_id: FenceId,
    /// The prompt generation the worker believes the reader is at.
    pub prompt_generation: PromptGeneration,
    /// The reader revision the worker believes is current.
    pub reader_revision: ReaderRevision,
    /// How long the worker will hold input for this exchange.
    pub deadline_ms: DurationMs,
    /// Why the worker is asking.
    pub cause: FenceCause,
}

/// Why the worker started a fence exchange.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FenceCause {
    /// A root editor was registered.
    EditorEntry,
    /// The input lease changed while a root editor was registered.
    LeaseChange,
    /// An earlier exchange did not complete and this is the retry.
    Retry,
}

impl FenceCause {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EditorEntry => "editor_entry",
            Self::LeaseChange => "lease_change",
            Self::Retry => "retry",
        }
    }
}

/// The bridge's answer that prior input is resolved.
///
/// It is evidence, not agreement: the drain report and the snapshot are what the worker checks
/// before it publishes anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FenceAcknowledgement {
    /// The exchange being answered.
    pub fence_id: FenceId,
    /// The reader the bridge is answering from.
    pub reader_context: ReaderContext,
    /// The prompt generation at the moment of the snapshot.
    pub prompt_generation: PromptGeneration,
    /// The reader revision at the moment of the snapshot.
    pub reader_revision: ReaderRevision,
    /// Which queues the bridge has cleared.
    pub queues: QueueDrainReport,
    /// The atomically read key queues behind that report.
    pub snapshot: KeyQueueSnapshot,
    /// The reader's edit-buffer state at the same instant.
    pub editor: EditorState,
    /// The shell's working-directory revision at the same instant.
    pub cwd_revision: CwdRevision,
}

/// Why a bridge could not resolve prior input.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FenceRefusalReason {
    /// The reader is inside an operation it cannot be interrupted out of.
    ReaderBusy,
    /// Input remains in one of the reader's queues.
    QueuesNotDrained,
    /// The reader is not the one the worker asked about.
    ReaderMoved,
    /// The non-destructive cancellation path is unavailable, so an incomplete operation cannot be
    /// ended without losing the edit buffer.
    CancellationUnavailable,
}

impl FenceRefusalReason {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReaderBusy => "reader_busy",
            Self::QueuesNotDrained => "queues_not_drained",
            Self::ReaderMoved => "reader_moved",
            Self::CancellationUnavailable => "cancellation_unavailable",
        }
    }
}

/// A bridge's refusal to resolve prior input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FenceRefusal {
    /// The exchange being refused.
    pub fence_id: FenceId,
    /// Why.
    pub reason: FenceRefusalReason,
    /// The reader the refusal came from.
    pub reader_context: ReaderContext,
    /// What was still in the reader's queues.
    pub snapshot: KeyQueueSnapshot,
}

/// The result of `root.editor.fence`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RootEditorFenceResult {
    /// Prior input is resolved and here is the evidence.
    Acknowledged(FenceAcknowledgement),
    /// It is not, and here is why.
    Refused(FenceRefusal),
}

/// Why a fence was not published after an exchange.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WithheldReason {
    /// The bridge did not answer within the hold.
    ExchangeTimedOut,
    /// A root editor was registered, which invalidates the previous fence.
    EditorEntered,
    /// A detach was accepted and its attachment removed.
    DetachAccepted,
    /// The fence's own attachment was removed.
    AttachmentRemoved,
    /// The integration lost the ground this fence stood on.
    IntegrationLost,
    /// The acknowledgement did not report every queue clear.
    QueuesNotDrained,
    /// The bridge refused.
    Refused,
    /// The reader moved on between the question and the answer.
    ReaderMoved,
    /// The input lease changed again.
    LeaseChanged,
    /// The reader left.
    EditorLeft,
    /// The session is closing.
    SessionClosing,
}

impl WithheldReason {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExchangeTimedOut => "exchange_timed_out",
            Self::EditorEntered => "editor_entered",
            Self::DetachAccepted => "detach_accepted",
            Self::AttachmentRemoved => "attachment_removed",
            Self::IntegrationLost => "integration_lost",
            Self::QueuesNotDrained => "queues_not_drained",
            Self::Refused => "refused",
            Self::ReaderMoved => "reader_moved",
            Self::LeaseChanged => "lease_changed",
            Self::EditorLeft => "editor_left",
            Self::SessionClosing => "session_closing",
        }
    }
}

/// What the worker tells the bridge about the fence.
///
/// The bridge cannot conclude that its acknowledgement published a fence: the hold may have expired
/// while the answer was in flight, and a fence the worker never published must not be quoted in a
/// detach. Nor can it conclude that a fence it was given is still live. So all three are stated
/// rather than inferred, and a bridge holds a fence only between a [`Self::Published`] and the
/// [`Self::Invalidated`] that ends it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FencePublication {
    /// The fence is live and its full proof is here.
    Published(EditorFence),
    /// No fence was published.
    Withheld {
        /// Why not.
        reason: WithheldReason,
        /// The state the editor is in now.
        state: FenceState,
    },
    /// A fence that was live is not any more.
    Invalidated {
        /// The fence that has gone.
        fence_id: FenceId,
        /// Why.
        reason: WithheldReason,
        /// The state the editor is in now.
        state: FenceState,
    },
}

/// Parameters of `root.eof.detach`.
///
/// The bridge submits this at an eligible empty primary prompt. Naming the fence, the prompt and
/// the epoch is what makes the request attributable: the worker removes the attachment the fence
/// names, never whichever one holds the lease when the request arrives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootEofDetachParams {
    /// The session.
    pub session_id: SessionId,
    /// The fence the gesture belongs to.
    pub fence_id: FenceId,
    /// The prompt generation the gesture arrived at.
    pub prompt_generation: PromptGeneration,
    /// The input-lease epoch it arrived under.
    pub input_epoch: InputLeaseEpoch,
}

/// The result of `root.eof.detach`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootEofDetachResult {
    /// The attachment that was removed.
    pub detached_attachment: AttachmentId,
    /// The state after the detach. The fence is invalidated before this answer is sent.
    pub state: FenceState,
    /// Undelivered bytes of the removed attachment that were discarded.
    pub discarded_input_bytes: U64,
}

/// Where an accepted line came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AcceptedOrigin {
    /// One attachment's input, under one epoch, through a valid fence.
    Fenced {
        /// The attachment that typed it.
        attachment_id: AttachmentId,
        /// The epoch its bytes arrived under.
        input_epoch: InputLeaseEpoch,
    },
    /// Input from more than one epoch or attachment reached this line.
    Mixed,
    /// There was no valid fence, so the origin cannot be established at all.
    Unverifiable,
}

impl AcceptedOrigin {
    /// Returns the attachment a detach without an explicit identifier targets.
    ///
    /// A mixed or unverifiable origin returns `None`, which is what makes an unqualified
    /// `kr detach` an `AMBIGUOUS_ATTACHMENT` error rather than a guess.
    #[must_use]
    pub const fn target(&self) -> Option<AttachmentId> {
        match self {
            Self::Fenced { attachment_id, .. } => Some(*attachment_id),
            Self::Mixed | Self::Unverifiable => None,
        }
    }
}

/// Parameters of `root.command.accepted`.
///
/// Sent from the reader at acceptance, inside the fenced context, before the reader leaves. The
/// order matters: a record sent after the leave would arrive with the fence already invalidated and
/// could only ever say `unverifiable`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootCommandAcceptedParams {
    /// The session.
    pub session_id: SessionId,
    /// The fence the acceptance happened under, when one was live.
    pub fence_id: Nullable<FenceId>,
    /// The prompt generation of the accepted line.
    pub prompt_generation: PromptGeneration,
    /// The origin the bridge can prove from its own reader state.
    pub origin: AcceptedOrigin,
}

/// The result of `root.command.accepted`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootCommandAcceptedResult {
    /// The origin the worker recorded, which is what a later unqualified detach resolves against.
    pub origin: AcceptedOrigin,
    /// The state after acceptance.
    pub state: FenceState,
}

/// What a launch installs in the editor.
///
/// An argument vector is the safe form: the integration quotes it for its own shell. A quoted
/// command is already the exact text to run, and neither form is assembled by interpolation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LaunchCommand {
    /// An argument vector, quoted by the integration for its own shell.
    Arguments(Vec<String>),
    /// A command already quoted for the target shell.
    QuotedCommand(String),
}

/// Parameters of `shell.launch`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShellLaunchParams {
    /// The session.
    pub session_id: SessionId,
    /// What to install.
    pub command: LaunchCommand,
    /// The prompt generation the caller expects the root editor to be at.
    pub expected_prompt_generation: PromptGeneration,
    /// The buffer revision the caller expects an empty buffer to be at.
    pub expected_buffer_revision: EditorBufferRevision,
}

/// The result of a `shell.launch` that was installed and submitted.
///
/// A launch that was not installed is an error rather than a result: `EDITOR_BUSY` when the
/// transaction could not be held, `DRAFT_CONFLICT` when the editor's own state had moved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShellLaunchResult {
    /// The fence the launch was installed under.
    pub fence_id: FenceId,
    /// The prompt generation it was accepted at.
    pub prompt_generation: PromptGeneration,
    /// The buffer revision after the command was installed.
    pub buffer_revision: EditorBufferRevision,
}

/// Why the editor could not be fenced or reserved.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EditorBusyReason {
    /// The fence exchange did not complete within the hold.
    FenceExchangeTimedOut,
    /// The bridge refused the exchange.
    FenceRefused,
    /// The reader's queues still held input.
    QueuesNotDrained,
    /// A launch transaction was not answered within the hold.
    LaunchReservationTimedOut,
}

impl EditorBusyReason {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FenceExchangeTimedOut => "fence_exchange_timed_out",
            Self::FenceRefused => "fence_refused",
            Self::QueuesNotDrained => "queues_not_drained",
            Self::LaunchReservationTimedOut => "launch_reservation_timed_out",
        }
    }
}

/// The `EDITOR_BUSY` attachment event.
///
/// It is an event about the editor, not a failed `input.acquire`: the lease change it follows
/// stands, the epoch below is the one that now holds input, and the released bytes went to the
/// terminal in the order they arrived. The worker retries the fence at the reader's next entry,
/// leave or idle callback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EditorBusyEvent {
    /// The session.
    pub session_id: SessionId,
    /// The attachment the event is delivered to, which is the one that now holds input.
    pub attachment_id: AttachmentId,
    /// The lease epoch that stands.
    pub input_epoch: InputLeaseEpoch,
    /// Why the editor could not be fenced.
    pub reason: EditorBusyReason,
    /// How many held bytes were released in their original order.
    pub released_input_bytes: U64,
    /// The state the editor is in now.
    pub state: FenceState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;
    use crate::identity::ProcessStartSource;
    use crate::scalars::Uuid;

    fn fence() -> EditorFence {
        EditorFence {
            fence_id: FenceId::new(Uuid::from_bytes([7; 16])),
            root_process: ProcessStartIdentity::new(4242, ProcessStartSource::MacosProcBsdInfo, 99),
            prompt_generation: PromptGeneration::new(3),
            reader_revision: ReaderRevision::new(1),
            input_epoch: InputLeaseEpoch::new(5),
            originating_attachment: AttachmentId::new(Uuid::from_bytes([9; 16])),
        }
    }

    #[test]
    fn the_readers_budget_ends_before_the_workers_hold() {
        assert_eq!(FENCE_EXCHANGE_TIMEOUT.get(), 250);
        assert!(LAUNCH_READER_BUDGET.get() < FENCE_EXCHANGE_TIMEOUT.get());
    }

    #[test]
    fn a_fence_round_trips_through_the_canonical_encoding() {
        let original = fence();
        let bytes = kr_cbor::to_canonical_vec(&original).expect("encodes");
        let decoded: EditorFence =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(decoded, original);
    }

    #[test]
    fn only_a_fenced_origin_names_a_detach_target() {
        let attachment = AttachmentId::new(Uuid::from_bytes([9; 16]));
        let fenced = AcceptedOrigin::Fenced {
            attachment_id: attachment,
            input_epoch: InputLeaseEpoch::new(5),
        };
        assert_eq!(fenced.target(), Some(attachment));
        assert_eq!(AcceptedOrigin::Mixed.target(), None);
        assert_eq!(AcceptedOrigin::Unverifiable.target(), None);
    }

    #[test]
    fn a_fence_publishes_only_from_a_drained_reader() {
        assert!(QueueDrainReport::CLEAR.all_drained());
        assert!(
            !QueueDrainReport {
                macro_input_drained: false,
                ..QueueDrainReport::CLEAR
            }
            .all_drained()
        );
        assert!(KeyQueueSnapshot::drained().is_drained());
        assert!(
            !KeyQueueSnapshot {
                queued_keys: U64::new(2),
                ..KeyQueueSnapshot::drained()
            }
            .is_drained()
        );
    }

    #[test]
    fn a_pending_operation_means_the_reader_is_not_idle() {
        assert!(PendingReaderInput::NONE.is_idle());
        for pending in [
            PendingReaderInput {
                quoted_insertion: true,
                ..PendingReaderInput::NONE
            },
            PendingReaderInput {
                macro_input: true,
                ..PendingReaderInput::NONE
            },
            PendingReaderInput {
                search: true,
                ..PendingReaderInput::NONE
            },
            PendingReaderInput {
                numeric_argument: true,
                ..PendingReaderInput::NONE
            },
            PendingReaderInput {
                multikey_sequence: true,
                ..PendingReaderInput::NONE
            },
            PendingReaderInput {
                vi_motion: true,
                ..PendingReaderInput::NONE
            },
            PendingReaderInput {
                paste: true,
                ..PendingReaderInput::NONE
            },
        ] {
            assert!(!pending.is_idle());
        }
    }

    #[test]
    fn only_a_registered_root_editor_holds_input_for_a_transition() {
        assert!(!FenceState::Outside.uses_hold_exchange());
        assert!(!FenceState::Closing.uses_hold_exchange());
        assert!(FenceState::Unfenced.uses_hold_exchange());
        assert!(FenceState::Fenced.uses_hold_exchange());
        assert!(FenceState::LaunchReserved.uses_hold_exchange());
        assert!(FenceState::Fenced.holds_fence());
        assert!(FenceState::LaunchReserved.holds_fence());
        assert!(!FenceState::Unfenced.holds_fence());
    }

    #[test]
    fn the_editor_busy_event_names_the_two_codes_the_contract_uses() {
        assert_eq!(
            ErrorCode::from_wire("EDITOR_BUSY"),
            Some(ErrorCode::EditorBusy)
        );
        assert_eq!(
            ErrorCode::from_wire("AMBIGUOUS_ATTACHMENT"),
            Some(ErrorCode::AmbiguousAttachment)
        );
    }

    #[test]
    fn every_state_and_reason_has_a_distinct_wire_string() {
        let mut names: Vec<&str> = FenceState::ALL.iter().map(|state| state.as_str()).collect();
        names.extend(EditorLeaveReason::ALL.iter().map(|reason| reason.as_str()));
        names.extend(ReaderContext::ALL.iter().map(|context| context.as_str()));
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
    }
}
