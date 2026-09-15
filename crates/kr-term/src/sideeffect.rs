//! Side effects and where they go.
//!
//! A terminal side effect leaves the terminal: it writes a clipboard, rings a bell, raises a
//! notification. Section 8 forbids a broadcast, because a broadcast output stream would copy a
//! secret into every attached device's clipboard. So every side effect names one destination, and
//! the default destination is the specific attachment that currently holds the input lease.
//!
//! With no lease there is no destination. That is not a licence to pick one: the effect becomes a
//! durable host event instead, which a person can see later without anything having been written to
//! a device they were not using.

use kr_protocol::ids::{AttachmentId, InputLeaseEpoch};

/// Which clipboard an OSC 52 operation addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardSelection {
    /// The system clipboard, `c`.
    Clipboard,
    /// The primary selection, `p`.
    Primary,
}

impl ClipboardSelection {
    /// Reads the selection character an OSC 52 request carries.
    ///
    /// The request may list several; kr-vt/1 takes the first it recognises, and treats the empty
    /// list as the clipboard, which is what the sequence's own default says.
    #[must_use]
    pub fn parse(spec: &[u8]) -> Option<Self> {
        if spec.is_empty() {
            return Some(Self::Clipboard);
        }
        spec.iter().find_map(|byte| match byte {
            b'c' | b's' => Some(Self::Clipboard),
            b'p' => Some(Self::Primary),
            _ => None,
        })
    }

    /// The character used in a reply.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Clipboard => b'c',
            Self::Primary => b'p',
        }
    }
}

/// How far along a progress report is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// No progress is being reported.
    None,
    /// A determinate percentage.
    Percent(u8),
    /// An error state, carrying the last percentage.
    Error(u8),
    /// Work is happening but its extent is unknown.
    Indeterminate,
    /// Work is paused.
    Paused(u8),
}

/// What a side effect asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideEffectKind {
    /// One bell. Never replayed from history and never broadcast.
    Bell,
    /// A desktop notification.
    Notification {
        /// The title, when the sequence carried one.
        title: Option<String>,
        /// The body.
        body: String,
        /// The application's own identifier for it, when it gave one.
        ///
        /// It groups the parts of one notification and lets a later one replace an earlier one, so
        /// it travels with the effect rather than being dropped at the boundary.
        id: Option<String>,
        /// How urgent the application says it is.
        urgency: NotificationUrgency,
        /// When the application asks for it to be shown.
        display: NotificationDisplay,
    },
    /// A progress report.
    Progress {
        /// The reported state.
        progress: Progress,
    },
    /// A clipboard write that policy accepted.
    ClipboardWrite {
        /// Which clipboard.
        selection: ClipboardSelection,
        /// The decoded content.
        content: Vec<u8>,
    },
    /// A clipboard read request.
    ///
    /// kr-vt/1 answers it with an empty response by default; the record exists so a policy that
    /// allows reads has something to act on and so the attempt is visible either way.
    ClipboardRead {
        /// Which clipboard.
        selection: ClipboardSelection,
    },
}

/// How urgent an application says its notification is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NotificationUrgency {
    /// The application asked for the lowest urgency.
    Low,
    /// The default.
    #[default]
    Normal,
    /// The application asked for the highest urgency.
    Critical,
}

/// When an application asks for its notification to be shown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NotificationDisplay {
    /// Always.
    #[default]
    Always,
    /// Only when the session is not focused.
    Unfocused,
    /// Only when the session is not visible.
    Invisible,
}

/// Where a side effect goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SideEffectDestination {
    /// One specific attachment: the current input-lease holder.
    Attachment {
        /// The attachment.
        id: AttachmentId,
        /// The lease epoch that made it the destination. A later epoch invalidates the routing.
        epoch: InputLeaseEpoch,
    },
    /// No attachment holds the lease, so the effect becomes a durable host event.
    HostEvent,
}

/// One routed side effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SideEffect {
    /// What is being asked for.
    pub kind: SideEffectKind,
    /// Where it goes.
    pub destination: SideEffectDestination,
    /// The output-stream offset of the sequence that caused it.
    pub at: u64,
}

/// Why a side effect was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideEffectRefusal {
    /// Host policy denies this operation.
    PolicyDenied,
    /// The encoded payload passed its bound; the write is rejected whole.
    TooLarge {
        /// Encoded length that arrived.
        encoded_len: usize,
        /// The bound.
        limit: usize,
    },
    /// The payload was not valid for its sequence.
    Malformed,
}

/// What a clipboard write may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardWritePolicy {
    /// Refuse every write.
    Deny,
    /// Deliver the write to the current input-lease attachment, which may still refuse locally.
    LeaseHolder,
}

/// What a clipboard read may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardReadPolicy {
    /// Answer with an empty response without consulting any client. This is the default.
    EmptyResponse,
    /// Ask the current input-lease attachment, which may still refuse locally.
    LeaseHolder,
}

/// The host policy the worker enforces for side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SideEffectPolicy {
    /// What a clipboard write may do.
    pub clipboard_write: ClipboardWritePolicy,
    /// What a clipboard read may do.
    pub clipboard_read: ClipboardReadPolicy,
    /// Whether notifications are delivered.
    pub notifications: bool,
    /// Whether progress reports are delivered.
    pub progress: bool,
    /// Whether the bell is delivered.
    pub bell: bool,
    /// Bound on the encoded OSC 52 string.
    pub max_clipboard_encoded: usize,
}

impl SideEffectPolicy {
    /// The kr-vt/1 defaults: the bell, notifications and progress go to the lease holder, a
    /// clipboard write goes to the lease holder under its own local policy, and a clipboard read
    /// gets an empty answer.
    pub const DEFAULT: Self = Self {
        clipboard_write: ClipboardWritePolicy::LeaseHolder,
        clipboard_read: ClipboardReadPolicy::EmptyResponse,
        notifications: true,
        progress: true,
        bell: true,
        max_clipboard_encoded: 1024 * 1024,
    };
}

impl Default for SideEffectPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Who currently holds the input lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeaseHolder {
    /// The attachment, when one holds the lease.
    pub attachment: Option<AttachmentId>,
    /// The epoch of that lease.
    pub epoch: Option<InputLeaseEpoch>,
}

impl LeaseHolder {
    /// Nobody holds the lease.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            attachment: None,
            epoch: None,
        }
    }

    /// One attachment holds the lease at `epoch`.
    #[must_use]
    pub const fn new(attachment: AttachmentId, epoch: InputLeaseEpoch) -> Self {
        Self {
            attachment: Some(attachment),
            epoch: Some(epoch),
        }
    }

    /// The destination a side effect takes right now.
    #[must_use]
    pub const fn destination(self) -> SideEffectDestination {
        match (self.attachment, self.epoch) {
            (Some(id), Some(epoch)) => SideEffectDestination::Attachment { id, epoch },
            _ => SideEffectDestination::HostEvent,
        }
    }
}
