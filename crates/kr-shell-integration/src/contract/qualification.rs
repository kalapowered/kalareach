//! Which mechanisms qualify a bridge, and the exact detach condition.
//!
//! Section 7 is specific about two kinds of shortcut, and both are refused here rather than
//! diagnosed later:
//!
//! * **A bridge that cannot prove its delivery fence is unqualified.** A prompt hook, the
//!   foreground process group, the cursor position and an empty kernel queue each describe
//!   something adjacent to the reader, and none of them says that the reader has no input of its
//!   own, no plugin-mutated buffer and no imminent transition. Only the reader's own atomically
//!   read state does. An unqualified bridge must not fall back to injecting a private key into the
//!   pseudo-terminal, so that fallback is not a variant a qualified declaration can hold.
//! * **The end-of-file decision belongs to a native pre-EOF hook**, not to a key-binding wrapper.
//!   Readline and ZLE recognise an empty-line end of file before an ordinary binding runs, so a
//!   wrapper is downstream of the decision it claims to make.
//!
//! The detach condition is the other half. It requires the managed root editor, the primary prompt
//! and an empty buffer, and it excludes ten states in which the next character belongs to something
//! already in progress or came from somewhere other than the person at the keyboard.
//!
//! Qualification is per package. Each shell's reader has its own mailbox and its own place to take
//! the end-of-file decision, so a declaration naming another shell's mechanism describes a reader
//! the package does not have. [`IntegrationPhase`] holds the other half of the lifecycle: what a
//! session permits before qualification completes, and what it keeps when a live session loses its
//! hooks, its bridge or its root shell. The phases advance on what the bridge reports, never on a
//! guess: the handshake authenticates it, `hooks_activated` says its user-facing hooks are live
//! after the startup files, and `integration_lost` says the ground has gone.

use core::fmt;

use kr_protocol::error::ErrorCode;
use kr_protocol::root::{EditorState, ReaderContext};
use serde::{Deserialize, Serialize};

/// Which managed shell a root integration belongs to.
///
/// Each one is a qualified package with its own reader bridge. An unqualified system shell of the
/// same family is a child application or an explicitly selected compatibility shell; it is not one
/// of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellKind {
    /// The packaged Zsh with the published ZLE reader and pre-EOF patch.
    Zsh,
    /// The packaged Bash with the published bundled-Readline patch.
    Bash,
    /// The qualified Fish 4.x package with its reader-event bridge.
    Fish,
    /// PowerShell 7 with the qualified PSReadLine module.
    #[serde(rename = "powershell")]
    PowerShell,
}

impl ShellKind {
    /// Every managed shell, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Zsh, Self::Bash, Self::Fish, Self::PowerShell];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Zsh => "zsh",
            Self::Bash => "bash",
            Self::Fish => "fish",
            Self::PowerShell => "powershell",
        }
    }
}

impl fmt::Display for ShellKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How a bridge delivers a request to the reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxMechanism {
    /// A mailbox the patched ZLE reader checks at key-sequence boundaries, with immediate line
    /// acceptance and non-destructive cancellation.
    KeySequenceBoundaryMailbox,
    /// The patched Readline idle-reader callback, which runs after buffered input is consumed.
    IdleReaderMailbox,
    /// The Fish 4.x reader-event bridge against its own reader implementation.
    ReaderEventBridge,
    /// The qualified PSReadLine module's reader-thread request queue and signal.
    ReaderThreadQueue,
    /// A file-descriptor watcher such as stock `zle -F`, including its `-w` form.
    ///
    /// Not qualified: its callback can run inside a multikey wait, and it can guarantee neither
    /// immediate acceptance nor cancellation.
    FileDescriptorWatcher,
}

impl MailboxMechanism {
    /// Every mechanism, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::KeySequenceBoundaryMailbox,
        Self::IdleReaderMailbox,
        Self::ReaderEventBridge,
        Self::ReaderThreadQueue,
        Self::FileDescriptorWatcher,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeySequenceBoundaryMailbox => "key_sequence_boundary_mailbox",
            Self::IdleReaderMailbox => "idle_reader_mailbox",
            Self::ReaderEventBridge => "reader_event_bridge",
            Self::ReaderThreadQueue => "reader_thread_queue",
            Self::FileDescriptorWatcher => "file_descriptor_watcher",
        }
    }

    /// Returns true when the mechanism can carry a fenced request to the reader.
    #[must_use]
    pub const fn is_qualified(self) -> bool {
        !matches!(self, Self::FileDescriptorWatcher)
    }

    /// Returns the mechanism this shell's qualified package implements.
    ///
    /// Each package's mailbox is its own reader's: a declaration naming another shell's mechanism
    /// describes a reader this package does not have, which is a qualification failure rather than
    /// a detail.
    #[must_use]
    pub const fn for_shell(kind: ShellKind) -> Self {
        match kind {
            ShellKind::Zsh => Self::KeySequenceBoundaryMailbox,
            ShellKind::Bash => Self::IdleReaderMailbox,
            ShellKind::Fish => Self::ReaderEventBridge,
            ShellKind::PowerShell => Self::ReaderThreadQueue,
        }
    }
}

/// Where the end-of-file decision is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreEofMechanism {
    /// A native hook immediately before the reader's own end-of-file branch, after the next
    /// character has been selected from its input sources. This is what the published Zsh and Bash
    /// patches add, because those readers decide before an ordinary binding runs.
    NativeHook,
    /// A named binding that receives the actual reader context, which is how the Fish 4.x package
    /// reaches the same decision point in a reader that has no equivalent branch to patch.
    NamedReaderBinding,
    /// A handler over the reader's own buffer and invocation state, which is what PSReadLine
    /// exposes under the configured gesture.
    ReaderStateHandler,
    /// A wrapper around a key binding, which runs after the decision has already been made.
    KeyBindingWrapper,
}

impl PreEofMechanism {
    /// Every mechanism, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::NativeHook,
        Self::NamedReaderBinding,
        Self::ReaderStateHandler,
        Self::KeyBindingWrapper,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeHook => "native_hook",
            Self::NamedReaderBinding => "named_reader_binding",
            Self::ReaderStateHandler => "reader_state_handler",
            Self::KeyBindingWrapper => "key_binding_wrapper",
        }
    }

    /// Returns true when the mechanism sees the character before the reader's own decision.
    #[must_use]
    pub const fn is_qualified(self) -> bool {
        !matches!(self, Self::KeyBindingWrapper)
    }

    /// Returns the mechanism this shell's qualified package implements.
    #[must_use]
    pub const fn for_shell(kind: ShellKind) -> Self {
        match kind {
            ShellKind::Zsh | ShellKind::Bash => Self::NativeHook,
            ShellKind::Fish => Self::NamedReaderBinding,
            ShellKind::PowerShell => Self::ReaderStateHandler,
        }
    }
}

/// What a bridge offers as evidence that prior input is resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceProofMechanism {
    /// The reader's own key queues and buffer state, read atomically under the reader's lock.
    AtomicReaderState,
    /// A prompt hook firing.
    PromptHook,
    /// The terminal's foreground process group.
    ForegroundProcessGroup,
    /// Where the cursor is on the screen.
    ScreenCoordinates,
    /// The kernel reporting no readable bytes on the terminal.
    EmptyKernelQueue,
}

impl FenceProofMechanism {
    /// Every mechanism, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::AtomicReaderState,
        Self::PromptHook,
        Self::ForegroundProcessGroup,
        Self::ScreenCoordinates,
        Self::EmptyKernelQueue,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AtomicReaderState => "atomic_reader_state",
            Self::PromptHook => "prompt_hook",
            Self::ForegroundProcessGroup => "foreground_process_group",
            Self::ScreenCoordinates => "screen_coordinates",
            Self::EmptyKernelQueue => "empty_kernel_queue",
        }
    }

    /// Returns true when the mechanism proves a delivery fence.
    #[must_use]
    pub const fn is_proof(self) -> bool {
        matches!(self, Self::AtomicReaderState)
    }

    /// Returns what the mechanism cannot establish, for the diagnostic a refusal carries.
    #[must_use]
    pub const fn shortfall(self) -> &'static str {
        match self {
            Self::AtomicReaderState => "nothing: the reader's own state is the proof",
            Self::PromptHook => {
                "a prompt event runs before the reader exists and says nothing \
                                 about its queues"
            }
            Self::ForegroundProcessGroup => {
                "the foreground process group names a process, not the \
                                             state of a reader inside it"
            }
            Self::ScreenCoordinates => {
                "the cursor position describes what was drawn, not what is \
                                        waiting to be read"
            }
            Self::EmptyKernelQueue => {
                "an empty kernel queue says nothing about input the reader \
                                       has already taken, a plugin-mutated buffer or an imminent \
                                       reader transition"
            }
        }
    }
}

/// How a bridge ends an operation that is waiting for another key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationMechanism {
    /// A native cancellation that ends the pending key wait and preserves the edit buffer.
    NonDestructiveKeyWait,
    /// No cancellation path, so a partial sequence can only be ended by losing the buffer or by
    /// waiting for a key that may never come.
    Unavailable,
}

impl CancellationMechanism {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NonDestructiveKeyWait => "non_destructive_key_wait",
            Self::Unavailable => "unavailable",
        }
    }

    /// Returns true when a takeover can cancel an incomplete operation without destroying the
    /// buffer.
    #[must_use]
    pub const fn is_qualified(self) -> bool {
        matches!(self, Self::NonDestructiveKeyWait)
    }
}

/// How a launch reaches the editor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchDelivery {
    /// Through the reader's private mailbox, installed and accepted on the reader thread.
    ReaderMailbox,
    /// By writing a key sequence into the pseudo-terminal and hoping the reader is the one that
    /// reads it.
    ///
    /// Section 7 forbids this outright, as a fallback as well as a design. A declaration naming it
    /// is refused rather than accepted with a reduced contract.
    PseudoTerminalKeyInjection,
}

impl LaunchDelivery {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReaderMailbox => "reader_mailbox",
            Self::PseudoTerminalKeyInjection => "pseudo_terminal_key_injection",
        }
    }

    /// Returns true when the delivery path is the reader's own mailbox.
    #[must_use]
    pub const fn is_qualified(self) -> bool {
        matches!(self, Self::ReaderMailbox)
    }
}

/// The five mechanisms a bridge declares in its handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeAbi {
    /// How a request reaches the reader.
    pub mailbox: MailboxMechanism,
    /// Where the end-of-file decision is taken.
    pub pre_eof: PreEofMechanism,
    /// What the bridge offers as fence evidence.
    pub fence_proof: FenceProofMechanism,
    /// How an incomplete operation is ended.
    pub cancellation: CancellationMechanism,
    /// How a launch reaches the editor.
    pub launch_delivery: LaunchDelivery,
}

impl BridgeAbi {
    /// The declaration this shell's qualified package makes.
    ///
    /// The mailbox and the pre-EOF mechanism are the package's own; the fence proof, the
    /// cancellation path and the launch path are the same for all four.
    #[must_use]
    pub const fn qualified(kind: ShellKind) -> Self {
        Self {
            mailbox: MailboxMechanism::for_shell(kind),
            pre_eof: PreEofMechanism::for_shell(kind),
            fence_proof: FenceProofMechanism::AtomicReaderState,
            cancellation: CancellationMechanism::NonDestructiveKeyWait,
            launch_delivery: LaunchDelivery::ReaderMailbox,
        }
    }
}

/// Why a bridge is not qualified, or not who it says it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationReason {
    /// The bridge offered a protocol this worker does not speak.
    ProtocolMismatch,
    /// The bridge named a different session, which is what a stale inherited environment looks
    /// like.
    SessionMismatch,
    /// The connecting process is not the root shell the worker started.
    ProcessMismatch,
    /// The proof over the bootstrap secret does not verify.
    ProofMismatch,
    /// This session already has a registered root integration.
    AlreadyRegistered,
    /// The connection's own process could not be identified, so nothing binds the declaration to
    /// the root shell.
    PeerUnidentified,
    /// The mailbox mechanism cannot carry a fenced request.
    UnqualifiedMailbox,
    /// The mailbox named belongs to another shell's reader.
    MailboxNotForShell,
    /// The end-of-file decision would be taken by a key-binding wrapper.
    KeyBindingPreEof,
    /// The pre-EOF mechanism named belongs to another shell's reader.
    PreEofNotForShell,
    /// The offered fence evidence does not prove a delivery fence.
    UnprovableFence,
    /// There is no non-destructive cancellation path.
    NoCancellationPath,
    /// The declaration named pseudo-terminal key injection as its launch path.
    KeyInjectionForbidden,
    /// The editor ABI revision is not one this worker was qualified against.
    EditorAbiUnsupported,
    /// The integration version is not one this worker supports.
    IntegrationVersionUnsupported,
    /// A loadable module in the shell's module tree is ABI-incompatible with the packaged reader.
    ModuleTreeUnsupported,
}

impl QualificationReason {
    /// Every reason, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::ProtocolMismatch,
        Self::SessionMismatch,
        Self::ProcessMismatch,
        Self::ProofMismatch,
        Self::AlreadyRegistered,
        Self::PeerUnidentified,
        Self::UnqualifiedMailbox,
        Self::MailboxNotForShell,
        Self::KeyBindingPreEof,
        Self::PreEofNotForShell,
        Self::UnprovableFence,
        Self::NoCancellationPath,
        Self::KeyInjectionForbidden,
        Self::EditorAbiUnsupported,
        Self::IntegrationVersionUnsupported,
        Self::ModuleTreeUnsupported,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolMismatch => "protocol_mismatch",
            Self::SessionMismatch => "session_mismatch",
            Self::ProcessMismatch => "process_mismatch",
            Self::ProofMismatch => "proof_mismatch",
            Self::AlreadyRegistered => "already_registered",
            Self::PeerUnidentified => "peer_unidentified",
            Self::UnqualifiedMailbox => "unqualified_mailbox",
            Self::MailboxNotForShell => "mailbox_not_for_shell",
            Self::KeyBindingPreEof => "key_binding_pre_eof",
            Self::PreEofNotForShell => "pre_eof_not_for_shell",
            Self::UnprovableFence => "unprovable_fence",
            Self::NoCancellationPath => "no_cancellation_path",
            Self::KeyInjectionForbidden => "key_injection_forbidden",
            Self::EditorAbiUnsupported => "editor_abi_unsupported",
            Self::IntegrationVersionUnsupported => "integration_version_unsupported",
            Self::ModuleTreeUnsupported => "module_tree_unsupported",
        }
    }

    /// Returns the error code the refusal carries.
    ///
    /// An identity failure is a permission answer: the caller is not the root shell of this
    /// session, whatever it declares. A capability failure is a configuration answer, and the
    /// session reports it with the named choices rather than substituting a shell.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::ProtocolMismatch => ErrorCode::UnsupportedSchema,
            Self::SessionMismatch
            | Self::ProcessMismatch
            | Self::ProofMismatch
            | Self::PeerUnidentified
            | Self::AlreadyRegistered => ErrorCode::PermissionDenied,
            Self::UnqualifiedMailbox
            | Self::MailboxNotForShell
            | Self::KeyBindingPreEof
            | Self::PreEofNotForShell
            | Self::UnprovableFence
            | Self::NoCancellationPath
            | Self::KeyInjectionForbidden
            | Self::EditorAbiUnsupported
            | Self::IntegrationVersionUnsupported
            | Self::ModuleTreeUnsupported => ErrorCode::ShellIntegrationUnsupported,
        }
    }
}

/// Checks a declaration against the mechanisms section 7 requires of this shell's package.
///
/// The order is the order a reader meets the mechanisms: how a request arrives, where the
/// end-of-file decision is taken, what proves the fence, how an incomplete operation ends, and how
/// a launch is delivered.
///
/// # Errors
///
/// Returns the first unqualified mechanism's reason.
pub const fn qualify(kind: ShellKind, abi: &BridgeAbi) -> Result<(), QualificationReason> {
    if !abi.mailbox.is_qualified() {
        return Err(QualificationReason::UnqualifiedMailbox);
    }
    if abi.mailbox as u8 != MailboxMechanism::for_shell(kind) as u8 {
        return Err(QualificationReason::MailboxNotForShell);
    }
    if !abi.pre_eof.is_qualified() {
        return Err(QualificationReason::KeyBindingPreEof);
    }
    if abi.pre_eof as u8 != PreEofMechanism::for_shell(kind) as u8 {
        return Err(QualificationReason::PreEofNotForShell);
    }
    if !abi.fence_proof.is_proof() {
        return Err(QualificationReason::UnprovableFence);
    }
    if !abi.cancellation.is_qualified() {
        return Err(QualificationReason::NoCancellationPath);
    }
    if !abi.launch_delivery.is_qualified() {
        return Err(QualificationReason::KeyInjectionForbidden);
    }
    Ok(())
}

/// Where the reader took the character from.
///
/// It matters because Readline returns pending and macro input without consulting the character
/// callback at all, and because a character that came from a macro or a paste is not a gesture a
/// person just made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputSource {
    /// Read from the terminal.
    Terminal,
    /// Taken from the reader's own typeahead buffer.
    Typeahead,
    /// Produced by a macro.
    Macro,
    /// Pushed back by a widget or a plugin.
    PushedBack,
    /// Inside a bracketed paste.
    Paste,
}

impl InputSource {
    /// Every source, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Terminal,
        Self::Typeahead,
        Self::Macro,
        Self::PushedBack,
        Self::Paste,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
            Self::Typeahead => "typeahead",
            Self::Macro => "macro",
            Self::PushedBack => "pushed_back",
            Self::Paste => "paste",
        }
    }
}

/// What the detach condition is evaluated against.
///
/// Every field is read from the reader's own state at the moment the character was selected. None
/// of it is inferred from the terminal, the screen or the process group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachCondition {
    /// True when this reader is the managed root editor of this session.
    pub managed_root_editor: bool,
    /// Which reader is asking.
    pub reader_context: ReaderContext,
    /// Where the reader took this character from.
    ///
    /// The pending flags below describe an operation that is still in progress; the source
    /// describes where this character came from, which is a different question. The last character
    /// of a macro or a paste arrives with the flags already clear, and it is still not a gesture a
    /// person just made.
    pub source: InputSource,
    /// The reader's buffer and pending operation.
    pub editor: EditorState,
}

/// Why an end-of-file gesture is not an empty-prompt detach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetachExclusion {
    /// This is not the managed root editor, so the contract does not apply to it at all.
    NotManagedRootEditor,
    /// A continuation line of an unfinished command.
    ContinuationInput,
    /// The `read` builtin reading through the editor.
    ReadBuiltin,
    /// The buffer is not empty.
    BufferNotEmpty,
    /// A quoted insertion is waiting for its character.
    QuotedInsertion,
    /// The reader is consuming a macro.
    MacroInput,
    /// A search is active.
    Search,
    /// A numeric argument is being accumulated.
    NumericArgument,
    /// A multikey sequence is waiting for its remaining keys.
    MultikeySequence,
    /// A vi motion is waiting for its target.
    ViMotion,
    /// A bracketed paste is open.
    Paste,
}

impl DetachExclusion {
    /// The ten states that exclude the detach condition, in evaluation order.
    ///
    /// [`Self::NotManagedRootEditor`] is not among them: it is the requirement that the contract
    /// applies at all, and a reader that fails it is not a managed root editor being excluded.
    pub const ALL: &'static [Self] = &[
        Self::ContinuationInput,
        Self::ReadBuiltin,
        Self::BufferNotEmpty,
        Self::QuotedInsertion,
        Self::MacroInput,
        Self::Search,
        Self::NumericArgument,
        Self::MultikeySequence,
        Self::ViMotion,
        Self::Paste,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotManagedRootEditor => "not_managed_root_editor",
            Self::ContinuationInput => "continuation_input",
            Self::ReadBuiltin => "read_builtin",
            Self::BufferNotEmpty => "buffer_not_empty",
            Self::QuotedInsertion => "quoted_insertion",
            Self::MacroInput => "macro_input",
            Self::Search => "search",
            Self::NumericArgument => "numeric_argument",
            Self::MultikeySequence => "multikey_sequence",
            Self::ViMotion => "vi_motion",
            Self::Paste => "paste",
        }
    }
}

/// How far the root integration has got, and what that permits.
///
/// Section 7 separates authentication from qualification: the private reader and pre-EOF bridge are
/// authenticated and ABI-checked before external input is accepted, while rich launch and a ready
/// or create success stay disabled until qualification completes after the user's startup files
/// have run. A live session can also lose ground afterwards, and what it keeps when it does is part
/// of the contract rather than a matter of taste.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationPhase {
    /// The bridge has not been authenticated and ABI-checked. External input is not accepted.
    Unauthenticated,
    /// The bridge is authenticated and ABI-checked, and the user's startup files are still running.
    /// A native startup prompt may read input in its own non-primary context; nothing else is on.
    Authenticated,
    /// Qualification completed after the startup files. Everything in this contract applies.
    Qualified,
    /// The session lost its semantic hooks or its bridge. Rich launch and attribution are off; the
    /// pre-EOF hook stays fail-safe and consumes an eligible gesture with the hint.
    Degraded,
    /// The root shell was replaced by something unqualified. The session is visibly terminal-only
    /// and claims none of this contract.
    TerminalOnly,
}

impl IntegrationPhase {
    /// Every phase, in order of how far it has got.
    pub const ALL: &'static [Self] = &[
        Self::Unauthenticated,
        Self::Authenticated,
        Self::Qualified,
        Self::Degraded,
        Self::TerminalOnly,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::Authenticated => "authenticated",
            Self::Qualified => "qualified",
            Self::Degraded => "degraded",
            Self::TerminalOnly => "terminal_only",
        }
    }

    /// Returns true when a client's input may reach the terminal.
    #[must_use]
    pub const fn accepts_external_input(self) -> bool {
        !matches!(self, Self::Unauthenticated)
    }

    /// Returns true when the session may report itself ready and a create may succeed.
    #[must_use]
    pub const fn reports_ready(self) -> bool {
        matches!(self, Self::Qualified)
    }

    /// Returns true when a launch may be installed through the reader.
    #[must_use]
    pub const fn permits_launch(self) -> bool {
        matches!(self, Self::Qualified)
    }

    /// Returns true when an accepted line may be attributed to an attachment.
    #[must_use]
    pub const fn permits_attribution(self) -> bool {
        matches!(self, Self::Qualified)
    }

    /// Returns true when an eligible end-of-file gesture is still consumed with the hint.
    ///
    /// True wherever a hook can run at all. The gesture is consumed rather than acted on, which is
    /// the fail-safe answer: a session that cannot prove whose gesture it was must not turn it into
    /// a native empty-prompt end of file.
    #[must_use]
    pub const fn consumes_eligible_eof(self) -> bool {
        !matches!(self, Self::TerminalOnly)
    }

    /// Returns true when a fence may be held in this phase.
    ///
    /// Only a qualified session. Leaving that phase invalidates the fence and cancels a launch
    /// transaction, because both rest on a reader the session can no longer speak for. The worker
    /// drives that through the state machine's `integration_lost` stimulus.
    #[must_use]
    pub const fn retains_fence(self) -> bool {
        matches!(self, Self::Qualified)
    }
}

/// What a live session lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationLoss {
    /// The integration failed after the startup files ran.
    PostStartupFailure,
    /// The semantic hooks stopped reporting.
    SemanticHookLoss,
    /// The bridge connection ended.
    BridgeDisconnected,
    /// The root shell was replaced by something this build cannot qualify.
    UnqualifiedRootReplacement,
}

impl IntegrationLoss {
    /// Every loss, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::PostStartupFailure,
        Self::SemanticHookLoss,
        Self::BridgeDisconnected,
        Self::UnqualifiedRootReplacement,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PostStartupFailure => "post_startup_failure",
            Self::SemanticHookLoss => "semantic_hook_loss",
            Self::BridgeDisconnected => "bridge_disconnected",
            Self::UnqualifiedRootReplacement => "unqualified_root_replacement",
        }
    }
}

/// What a session does about a loss.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LossOutcome {
    /// Carry on in this phase.
    Phase(IntegrationPhase),
    /// Close the session and record the diagnostics. An explicit compatibility retry is a new
    /// create request, never a silent substitution.
    CloseSession,
}

/// Returns what a loss does to a session in this phase.
///
/// Before qualification a session is still being created, and a create that cannot deliver the
/// managed contract fails rather than succeeding with less: every loss closes it, and none of them
/// promotes it into the phase meant for a live session that has lost ground. An explicit
/// compatibility retry is a new create request.
#[must_use]
pub const fn phase_after(phase: IntegrationPhase, loss: IntegrationLoss) -> LossOutcome {
    match phase {
        IntegrationPhase::Unauthenticated | IntegrationPhase::Authenticated => {
            LossOutcome::CloseSession
        }
        IntegrationPhase::TerminalOnly => LossOutcome::Phase(IntegrationPhase::TerminalOnly),
        IntegrationPhase::Qualified | IntegrationPhase::Degraded => match loss {
            IntegrationLoss::UnqualifiedRootReplacement => {
                LossOutcome::Phase(IntegrationPhase::TerminalOnly)
            }
            IntegrationLoss::PostStartupFailure
            | IntegrationLoss::SemanticHookLoss
            | IntegrationLoss::BridgeDisconnected => LossOutcome::Phase(IntegrationPhase::Degraded),
        },
    }
}

/// Whether an end-of-file gesture is an empty-prompt detach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetachEligibility {
    /// The managed root editor, at its primary prompt, with an empty buffer and nothing pending.
    Eligible,
    /// One of the excluded states holds.
    Excluded(DetachExclusion),
}

impl DetachEligibility {
    /// Returns true when the gesture may be submitted as a detach.
    #[must_use]
    pub const fn is_eligible(self) -> bool {
        matches!(self, Self::Eligible)
    }
}

/// Evaluates the detach condition.
///
/// Outside this condition the original editor or application handles the key normally: an excluded
/// gesture is not consumed, not converted into an empty-prompt end of file, and not reported.
#[must_use]
pub const fn detach_eligibility(condition: &DetachCondition) -> DetachEligibility {
    use DetachExclusion as Excluded;

    if !condition.managed_root_editor {
        return DetachEligibility::Excluded(Excluded::NotManagedRootEditor);
    }
    match condition.reader_context {
        ReaderContext::Continuation => {
            return DetachEligibility::Excluded(Excluded::ContinuationInput);
        }
        ReaderContext::ReadBuiltin => return DetachEligibility::Excluded(Excluded::ReadBuiltin),
        ReaderContext::Primary => {}
    }
    match condition.source {
        // Input the reader produced rather than the person. The specification names macro input as
        // the exclusion for that class, and a key a widget pushed back belongs to it.
        InputSource::Macro | InputSource::PushedBack => {
            return DetachEligibility::Excluded(Excluded::MacroInput);
        }
        InputSource::Paste => return DetachEligibility::Excluded(Excluded::Paste),
        InputSource::Terminal | InputSource::Typeahead => {}
    }
    if !condition.editor.buffer_empty {
        return DetachEligibility::Excluded(Excluded::BufferNotEmpty);
    }
    let pending = condition.editor.pending;
    if pending.quoted_insertion {
        return DetachEligibility::Excluded(Excluded::QuotedInsertion);
    }
    if pending.macro_input {
        return DetachEligibility::Excluded(Excluded::MacroInput);
    }
    if pending.search {
        return DetachEligibility::Excluded(Excluded::Search);
    }
    if pending.numeric_argument {
        return DetachEligibility::Excluded(Excluded::NumericArgument);
    }
    if pending.multikey_sequence {
        return DetachEligibility::Excluded(Excluded::MultikeySequence);
    }
    if pending.vi_motion {
        return DetachEligibility::Excluded(Excluded::ViMotion);
    }
    if pending.paste {
        return DetachEligibility::Excluded(Excluded::Paste);
    }
    DetachEligibility::Eligible
}

#[cfg(test)]
mod tests {
    use kr_protocol::root::{EditorBufferRevision, EditorKeymap, PendingReaderInput};

    use super::*;

    fn condition() -> DetachCondition {
        DetachCondition {
            managed_root_editor: true,
            reader_context: ReaderContext::Primary,
            source: InputSource::Terminal,
            editor: EditorState {
                buffer_revision: EditorBufferRevision::new(4),
                buffer_empty: true,
                keymap: EditorKeymap::Emacs,
                pending: PendingReaderInput::NONE,
            },
        }
    }

    #[test]
    fn an_empty_primary_prompt_in_the_managed_editor_is_eligible() {
        assert!(detach_eligibility(&condition()).is_eligible());
    }

    #[test]
    fn every_excluded_state_is_named() {
        let cases: Vec<(DetachExclusion, DetachCondition)> = vec![
            (
                DetachExclusion::NotManagedRootEditor,
                DetachCondition {
                    managed_root_editor: false,
                    ..condition()
                },
            ),
            (
                DetachExclusion::ContinuationInput,
                DetachCondition {
                    reader_context: ReaderContext::Continuation,
                    ..condition()
                },
            ),
            (
                DetachExclusion::ReadBuiltin,
                DetachCondition {
                    reader_context: ReaderContext::ReadBuiltin,
                    ..condition()
                },
            ),
            (
                DetachExclusion::BufferNotEmpty,
                DetachCondition {
                    editor: EditorState {
                        buffer_empty: false,
                        ..condition().editor
                    },
                    ..condition()
                },
            ),
            (
                DetachExclusion::MacroInput,
                DetachCondition {
                    source: InputSource::Macro,
                    ..condition()
                },
            ),
            (
                DetachExclusion::MacroInput,
                DetachCondition {
                    source: InputSource::PushedBack,
                    ..condition()
                },
            ),
            (
                DetachExclusion::Paste,
                DetachCondition {
                    source: InputSource::Paste,
                    ..condition()
                },
            ),
            (
                DetachExclusion::QuotedInsertion,
                pending(PendingReaderInput {
                    quoted_insertion: true,
                    ..PendingReaderInput::NONE
                }),
            ),
            (
                DetachExclusion::MacroInput,
                pending(PendingReaderInput {
                    macro_input: true,
                    ..PendingReaderInput::NONE
                }),
            ),
            (
                DetachExclusion::Search,
                pending(PendingReaderInput {
                    search: true,
                    ..PendingReaderInput::NONE
                }),
            ),
            (
                DetachExclusion::NumericArgument,
                pending(PendingReaderInput {
                    numeric_argument: true,
                    ..PendingReaderInput::NONE
                }),
            ),
            (
                DetachExclusion::MultikeySequence,
                pending(PendingReaderInput {
                    multikey_sequence: true,
                    ..PendingReaderInput::NONE
                }),
            ),
            (
                DetachExclusion::ViMotion,
                pending(PendingReaderInput {
                    vi_motion: true,
                    ..PendingReaderInput::NONE
                }),
            ),
            (
                DetachExclusion::Paste,
                pending(PendingReaderInput {
                    paste: true,
                    ..PendingReaderInput::NONE
                }),
            ),
        ];
        for (expected, condition) in cases {
            assert_eq!(
                detach_eligibility(&condition),
                DetachEligibility::Excluded(expected),
                "{}",
                expected.as_str()
            );
        }
    }

    fn pending(pending: PendingReaderInput) -> DetachCondition {
        let base = condition();
        DetachCondition {
            editor: EditorState {
                pending,
                ..base.editor
            },
            ..base
        }
    }

    #[test]
    fn the_exclusion_list_has_the_ten_states_the_condition_excludes() {
        assert_eq!(DetachExclusion::ALL.len(), 10);
        assert!(!DetachExclusion::ALL.contains(&DetachExclusion::NotManagedRootEditor));
    }

    #[test]
    fn only_the_readers_own_state_proves_a_fence() {
        for mechanism in FenceProofMechanism::ALL {
            assert_eq!(
                mechanism.is_proof(),
                *mechanism == FenceProofMechanism::AtomicReaderState,
                "{}",
                mechanism.as_str()
            );
        }
    }

    #[test]
    fn an_unqualified_declaration_names_its_first_failure() {
        let zsh = BridgeAbi::qualified(ShellKind::Zsh);
        assert_eq!(qualify(ShellKind::Zsh, &zsh), Ok(()));
        assert_eq!(
            qualify(
                ShellKind::Zsh,
                &BridgeAbi {
                    mailbox: MailboxMechanism::FileDescriptorWatcher,
                    ..zsh
                }
            ),
            Err(QualificationReason::UnqualifiedMailbox)
        );
        assert_eq!(
            qualify(
                ShellKind::Zsh,
                &BridgeAbi {
                    pre_eof: PreEofMechanism::KeyBindingWrapper,
                    ..zsh
                }
            ),
            Err(QualificationReason::KeyBindingPreEof)
        );
        assert_eq!(
            qualify(
                ShellKind::Zsh,
                &BridgeAbi {
                    fence_proof: FenceProofMechanism::EmptyKernelQueue,
                    ..zsh
                }
            ),
            Err(QualificationReason::UnprovableFence)
        );
        assert_eq!(
            qualify(
                ShellKind::Zsh,
                &BridgeAbi {
                    cancellation: CancellationMechanism::Unavailable,
                    ..zsh
                }
            ),
            Err(QualificationReason::NoCancellationPath)
        );
        assert_eq!(
            qualify(
                ShellKind::Zsh,
                &BridgeAbi {
                    launch_delivery: LaunchDelivery::PseudoTerminalKeyInjection,
                    ..zsh
                }
            ),
            Err(QualificationReason::KeyInjectionForbidden)
        );
    }

    #[test]
    fn each_package_declares_its_own_readers_mechanisms() {
        for kind in ShellKind::ALL {
            assert_eq!(qualify(*kind, &BridgeAbi::qualified(*kind)), Ok(()));
        }
        assert_eq!(
            qualify(ShellKind::Bash, &BridgeAbi::qualified(ShellKind::Zsh)),
            Err(QualificationReason::MailboxNotForShell)
        );
        assert_eq!(
            qualify(
                ShellKind::Fish,
                &BridgeAbi {
                    mailbox: MailboxMechanism::for_shell(ShellKind::Fish),
                    ..BridgeAbi::qualified(ShellKind::Zsh)
                }
            ),
            Err(QualificationReason::PreEofNotForShell)
        );
    }

    #[test]
    fn a_session_keeps_the_fail_safe_gesture_and_loses_the_rest() {
        assert!(!IntegrationPhase::Unauthenticated.accepts_external_input());
        assert!(IntegrationPhase::Authenticated.accepts_external_input());
        assert!(!IntegrationPhase::Authenticated.reports_ready());
        assert!(!IntegrationPhase::Authenticated.permits_launch());
        assert!(IntegrationPhase::Qualified.reports_ready());
        assert!(IntegrationPhase::Qualified.permits_launch());
        assert!(IntegrationPhase::Qualified.permits_attribution());
        assert!(!IntegrationPhase::Degraded.permits_launch());
        assert!(!IntegrationPhase::Degraded.permits_attribution());
        assert!(IntegrationPhase::Degraded.consumes_eligible_eof());
        assert!(!IntegrationPhase::TerminalOnly.consumes_eligible_eof());
        for phase in IntegrationPhase::ALL {
            assert_eq!(
                phase.retains_fence(),
                *phase == IntegrationPhase::Qualified,
                "{}",
                phase.as_str()
            );
        }
    }

    #[test]
    fn a_failure_before_qualification_closes_the_creating_session() {
        for phase in [
            IntegrationPhase::Unauthenticated,
            IntegrationPhase::Authenticated,
        ] {
            for loss in IntegrationLoss::ALL {
                assert_eq!(
                    phase_after(phase, *loss),
                    LossOutcome::CloseSession,
                    "{} after {}",
                    phase.as_str(),
                    loss.as_str()
                );
            }
        }
        assert_eq!(
            phase_after(
                IntegrationPhase::Authenticated,
                IntegrationLoss::PostStartupFailure
            ),
            LossOutcome::CloseSession
        );
        assert_eq!(
            phase_after(
                IntegrationPhase::Qualified,
                IntegrationLoss::SemanticHookLoss
            ),
            LossOutcome::Phase(IntegrationPhase::Degraded)
        );
        assert_eq!(
            phase_after(
                IntegrationPhase::Qualified,
                IntegrationLoss::BridgeDisconnected
            ),
            LossOutcome::Phase(IntegrationPhase::Degraded)
        );
        assert_eq!(
            phase_after(
                IntegrationPhase::Qualified,
                IntegrationLoss::UnqualifiedRootReplacement
            ),
            LossOutcome::Phase(IntegrationPhase::TerminalOnly)
        );
    }

    #[test]
    fn a_character_the_reader_produced_is_not_a_gesture() {
        for source in [InputSource::Macro, InputSource::PushedBack] {
            assert_eq!(
                detach_eligibility(&DetachCondition {
                    source,
                    ..condition()
                }),
                DetachEligibility::Excluded(DetachExclusion::MacroInput)
            );
        }
        assert_eq!(
            detach_eligibility(&DetachCondition {
                source: InputSource::Paste,
                ..condition()
            }),
            DetachEligibility::Excluded(DetachExclusion::Paste)
        );
        for source in [InputSource::Terminal, InputSource::Typeahead] {
            assert!(
                detach_eligibility(&DetachCondition {
                    source,
                    ..condition()
                })
                .is_eligible()
            );
        }
    }

    #[test]
    fn an_identity_failure_is_a_permission_answer_and_a_capability_failure_a_configuration_one() {
        assert_eq!(
            QualificationReason::ProofMismatch.code(),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            QualificationReason::UnprovableFence.code(),
            ErrorCode::ShellIntegrationUnsupported
        );
        assert_eq!(
            QualificationReason::ProtocolMismatch.code(),
            ErrorCode::UnsupportedSchema
        );
    }
}
