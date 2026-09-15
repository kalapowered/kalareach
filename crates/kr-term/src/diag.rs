//! Out-of-band diagnostics.
//!
//! Section 8 is explicit that diagnostics are status and events, never bytes injected into the
//! application's PTY output and never painted over a running full-screen program. Nothing in this
//! module writes anywhere near the output stream; it produces records the worker publishes as
//! status.
//!
//! An `X`-class sequence in a tight loop would otherwise produce one diagnostic per iteration, so
//! each kind is rate limited and the suppressed count is reported with the next one that gets
//! through. A suppressed diagnostic is still counted, because "this happened 40,000 times" is the
//! interesting part.

use std::collections::BTreeMap;

/// What a diagnostic is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiagnosticKind {
    /// A sequence with no class in this profile revision was consumed.
    UnclassifiedSequence,
    /// A control string passed its bound and was discarded whole.
    OversizedControlString,
    /// A control string was abandoned before its terminator.
    AbandonedControlString,
    /// Malformed UTF-8 was replaced with U+FFFD.
    MalformedUtf8,
    /// A raw 8-bit C1 control was recognised and handled without being forwarded.
    RawC1Control,
    /// A tmux passthrough envelope nested deeper than the profile allows.
    PassthroughTooDeep,
    /// An image or raster-graphics sequence was consumed; kr-vt/1 has no raster graphics.
    ImageSequenceDisabled,
    /// A request to change the physical window or its columns was consumed.
    PhysicalWindowRequest,
    /// A query was answered from the profile in place of a physical terminal.
    QueryAnswered,
    /// The response lane is shedding load.
    ResponseLaneDegraded,
    /// A side effect had no destination and became a durable host event instead.
    SideEffectWithoutDestination,
    /// A clipboard write was rejected whole.
    ClipboardWriteRejected,
    /// A title stack pop found the stack empty.
    TitleStackUnderflow,
    /// Content was truncated to stay inside a resident-state bound.
    ResidentStateTruncated,
}

impl DiagnosticKind {
    /// The stable identifier fixtures and status records use.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::UnclassifiedSequence => "unclassified-sequence",
            Self::OversizedControlString => "oversized-control-string",
            Self::AbandonedControlString => "abandoned-control-string",
            Self::MalformedUtf8 => "malformed-utf8",
            Self::RawC1Control => "raw-c1-control",
            Self::PassthroughTooDeep => "passthrough-too-deep",
            Self::ImageSequenceDisabled => "image-sequence-disabled",
            Self::PhysicalWindowRequest => "physical-window-request",
            Self::QueryAnswered => "query-answered",
            Self::ResponseLaneDegraded => "response-lane-degraded",
            Self::SideEffectWithoutDestination => "side-effect-without-destination",
            Self::ClipboardWriteRejected => "clipboard-write-rejected",
            Self::TitleStackUnderflow => "title-stack-underflow",
            Self::ResidentStateTruncated => "resident-state-truncated",
        }
    }
}

/// One out-of-band diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// What happened.
    pub kind: DiagnosticKind,
    /// A short, bounded description of the specific occurrence.
    pub detail: String,
    /// Output-stream offset where it happened.
    pub at: u64,
    /// How many occurrences of this kind were suppressed since the last one that got through.
    pub suppressed: u64,
}

/// Maximum length of a diagnostic detail, in bytes.
pub const MAX_DETAIL: usize = 120;

/// Collects diagnostics and rate limits them per kind.
#[derive(Debug, Clone)]
pub struct DiagnosticSink {
    interval_ms: u64,
    last: BTreeMap<DiagnosticKind, u64>,
    suppressed: BTreeMap<DiagnosticKind, u64>,
    totals: BTreeMap<DiagnosticKind, u64>,
    pending: Vec<Diagnostic>,
}

impl DiagnosticSink {
    /// One diagnostic per kind per second.
    pub const DEFAULT_INTERVAL_MS: u64 = 1_000;

    /// Builds a sink with the default interval.
    #[must_use]
    pub fn new() -> Self {
        Self::with_interval(Self::DEFAULT_INTERVAL_MS)
    }

    /// Builds a sink with an explicit interval.
    #[must_use]
    pub fn with_interval(interval_ms: u64) -> Self {
        Self {
            interval_ms,
            last: BTreeMap::new(),
            suppressed: BTreeMap::new(),
            totals: BTreeMap::new(),
            pending: Vec::new(),
        }
    }

    /// Records one occurrence. `now_ms` is a monotonic millisecond clock.
    pub fn record(
        &mut self,
        kind: DiagnosticKind,
        at: u64,
        now_ms: u64,
        detail: impl Into<String>,
    ) {
        *self.totals.entry(kind).or_insert(0) += 1;
        let allowed = match self.last.get(&kind) {
            None => true,
            Some(last) => now_ms.saturating_sub(*last) >= self.interval_ms,
        };
        if !allowed {
            *self.suppressed.entry(kind).or_insert(0) += 1;
            return;
        }
        self.last.insert(kind, now_ms);
        let suppressed = self.suppressed.remove(&kind).unwrap_or(0);
        let mut detail = detail.into();
        if detail.len() > MAX_DETAIL {
            let mut end = MAX_DETAIL;
            while end > 0 && !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail.truncate(end);
        }
        self.pending.push(Diagnostic {
            kind,
            detail,
            at,
            suppressed,
        });
    }

    /// Takes the diagnostics that are ready to publish.
    pub fn drain(&mut self) -> Vec<Diagnostic> {
        core::mem::take(&mut self.pending)
    }

    /// How many occurrences of `kind` have been recorded, published or not.
    #[must_use]
    pub fn total(&self, kind: DiagnosticKind) -> u64 {
        self.totals.get(&kind).copied().unwrap_or(0)
    }

    /// Every kind that has occurred, with its count.
    #[must_use]
    pub fn totals(&self) -> Vec<(DiagnosticKind, u64)> {
        self.totals.iter().map(|(k, v)| (*k, *v)).collect()
    }
}

impl Default for DiagnosticSink {
    fn default() -> Self {
        Self::new()
    }
}
