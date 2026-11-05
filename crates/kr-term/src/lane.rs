//! The trusted terminal-response lane.
//!
//! A reply the engine writes back to the application is not input. It needs no human lease, it
//! never acquires one, and it never looks like a device, a paste or a root command. Only the query
//! broker can put anything here, and the lane keeps replies in the order their queries arrived,
//! except that a cursor report goes ahead of the others while the root editor is owed one.
//!
//! The lane is bounded four ways at once, because a query flood is an ordinary thing for a
//! misbehaving program to do: one reply has a maximum size, the queue has a maximum size, there is
//! a refill budget per second, and a reply that has waited too long is dropped rather than written
//! into a conversation that has moved on. When any of them binds, the lane says so out of band and
//! sheds load in a stated order. It never grows without bound, never starves human input and never
//! forwards a query onwards as a way of avoiding the work.
//!
//! The lane holds replies; the session loop delivers them. [`LaneGate`] carries what the loop knows
//! about the write it is about to make, so a reply cannot land inside an unfinished bracketed paste
//! or split a recognised human input frame.
//!
//! Nothing here is history. A reply that was never drained is dropped when the lane resets, and a
//! reconnecting client is never sent a reply or a probe answer from before it arrived.
//!
//! The lane reads no clock. Every call that has a deadline or a refill in it is handed a reading of
//! one, in milliseconds, and the readings a lane is handed all come from one continuous clock: a
//! deadline offered on one clock and read on another is dropped at once or kept for ever, and a
//! wall clock that is set moves a window it has no business moving.

use std::collections::VecDeque;

/// Which query a reply answers, and about what.
///
/// The subject is part of the kind because the lane coalesces while it is shedding load. Two
/// answers about the same subject carry the same information, so keeping the newer one loses
/// nothing; two answers about different modes, or two cursor reports, are different answers and are
/// never collapsed into each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResponseKind {
    /// Primary device attributes.
    DeviceAttributes1,
    /// Secondary device attributes.
    DeviceAttributes2,
    /// Tertiary device attributes.
    DeviceAttributes3,
    /// A device status report, identified by the status it reports on.
    DeviceStatus(u16),
    /// A cursor position report.
    CursorPosition,
    /// A mode report, identified by the spelling and the mode.
    ///
    /// The spelling is part of the subject: ANSI mode 4 and DEC private mode 4 are different modes,
    /// and an answer about one must never stand in for an answer about the other.
    ModeReport(crate::modes::ModeKind, u16),
    /// A window or geometry report, identified by the window operation.
    GeometryReport(u16),
    /// A setting report, identified by the setting name.
    SettingReport(SubjectName),
    /// A terminfo capability report, identified by the capability name.
    Capability(SubjectName),
    /// A colour report, identified by its selector: an OSC number, or `0x1000 + index`.
    Colour(u32),
    /// The keyboard protocol state, identified by the protocol asked about.
    KeyboardProtocol(u8),
    /// The terminal identity.
    Version,
    /// A clipboard answer.
    Clipboard,
}

/// The name a capability or setting report is about.
///
/// The name itself is the subject rather than a hash of it. A hash has collisions, and a collision
/// here is not a slow lookup: it lets one capability's answer stand in for a different capability's
/// answer while the lane is shedding load, so the application reads a reply to a question it never
/// asked. Both kinds of name are short and bounded before a reply is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SubjectName {
    bytes: [u8; Self::MAX],
    len: u8,
}

impl SubjectName {
    /// The longest name a subject holds. Longer names are refused before a reply is built.
    pub const MAX: usize = 32;

    /// Builds a subject from a name, keeping at most [`Self::MAX`] bytes.
    #[must_use]
    pub fn new(name: &[u8]) -> Self {
        let len = name.len().min(Self::MAX);
        let mut bytes = [0u8; Self::MAX];
        bytes[..len].copy_from_slice(&name[..len]);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the length was just bounded by MAX, which is far below u8::MAX"
        )]
        Self {
            bytes,
            len: len as u8,
        }
    }

    /// The name.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl ResponseKind {
    /// Whether two pending answers of this kind may be collapsed into the newer one.
    ///
    /// A cursor report is a sequence rather than a fact, and a clipboard answer belongs to the
    /// request that asked for it, so neither is ever collapsed.
    #[must_use]
    pub const fn coalescable(self) -> bool {
        !matches!(self, Self::CursorPosition | Self::Clipboard)
    }
}

/// One reply waiting to go to the application.
///
/// Replies are built inside this crate, by the query broker. Anything outside it can read a reply
/// and write it, and cannot invent one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    bytes: Vec<u8>,
    kind: ResponseKind,
    query_at: u64,
    expires_at_ms: u64,
    /// When a drain first kept this reply behind a cursor report, while it is being kept.
    held_since: Option<u64>,
}

impl Response {
    /// Builds a reply. Only the query broker calls this.
    pub(crate) const fn new(kind: ResponseKind, query_at: u64, bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            kind,
            query_at,
            expires_at_ms: 0,
            held_since: None,
        }
    }

    /// Whether this reply has waited past its deadline at `now_ms`.
    const fn lapsed(&self, now_ms: u64) -> bool {
        self.expires_at_ms != 0 && now_ms > self.expires_at_ms
    }

    /// The exact bytes to write.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Which query this answers.
    #[must_use]
    pub const fn kind(&self) -> ResponseKind {
        self.kind
    }

    /// Output-stream offset of the query that caused it, so the ordering is checkable.
    #[must_use]
    pub const fn query_at(&self) -> u64 {
        self.query_at
    }

    /// When this reply stops being worth writing.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

/// How the lane is shedding load.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LaneDegradation {
    /// Replies collapsed into a later reply about the same subject.
    pub coalesced: u64,
    /// Replies dropped because the queue was full.
    pub dropped: u64,
    /// Replies refused because the per-second budget was spent.
    pub over_budget: u64,
    /// Replies refused because they were larger than one reply may be.
    pub oversized: u64,
    /// Replies dropped because they waited past their deadline.
    pub expired: u64,
}

impl LaneDegradation {
    /// Whether anything has actually been shed.
    #[must_use]
    pub const fn is_degraded(self) -> bool {
        self.coalesced > 0
            || self.dropped > 0
            || self.over_budget > 0
            || self.oversized > 0
            || self.expired > 0
    }
}

/// What the session loop knows about the write it is about to make.
///
/// The loop owns delivery; the lane owns the bounds. These flags are how the loop says that this is
/// not a moment when a reply may be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LaneGate {
    /// Whether a bracketed paste is open and unterminated.
    pub paste_open: bool,
    /// Whether the backend is qualified to take a reply inside an open paste.
    pub backend_handles_paste_interleave: bool,
    /// Whether a recognised human input frame is part way through being delivered.
    pub human_frame_open: bool,
    /// Whether the root editor is owed the reply to its cursor question.
    ///
    /// The editor reads that reply from the same input as everything else the terminal sends, and
    /// bytes that come ahead of it are read as part of it. While this is set a cursor report goes
    /// out ahead of every other reply, and no other reply goes out until one has.
    pub cursor_report_first: bool,
}

impl LaneGate {
    /// Whether a reply may be written right now.
    #[must_use]
    pub const fn allows_write(self) -> bool {
        if self.human_frame_open {
            return false;
        }
        !self.paste_open || self.backend_handles_paste_interleave
    }
}

/// Bounds the lane applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneLimits {
    /// The largest one reply may be.
    pub max_response_bytes: usize,
    /// The largest the queue may grow.
    pub max_queue_bytes: usize,
    /// Replies per second, which is also the burst size.
    pub responses_per_second: u32,
    /// How long a reply may wait before it stops being worth writing.
    pub reply_deadline_ms: u64,
}

impl LaneLimits {
    /// The kr-vt/1 bounds: a 128 KiB queue and 256 replies per second.
    ///
    /// The per-reply bound is 8 KiB. The largest reply the broker can build is an XTGETTCAP answer
    /// for a long capability list, and the terminfo responder bounds that list well below this.
    ///
    /// The deadline is two seconds. An application that asked a question and has not had the answer
    /// in two seconds has either given up or moved on, and writing then is worse than not writing.
    pub const DEFAULT: Self = Self {
        max_response_bytes: 8 * 1024,
        max_queue_bytes: 128 * 1024,
        responses_per_second: 256,
        reply_deadline_ms: 2_000,
    };
}

impl Default for LaneLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The trusted response lane.
#[derive(Debug, Clone)]
pub struct ResponseLane {
    limits: LaneLimits,
    queue: VecDeque<Response>,
    queued_bytes: usize,
    tokens: u32,
    last_refill_ms: u64,
    degradation: LaneDegradation,
    delivered: u64,
    /// Whether any waiting reply carries a `held_since`.
    holding: bool,
}

impl ResponseLane {
    /// Builds a lane with the kr-vt/1 bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(LaneLimits::DEFAULT)
    }

    /// Builds a lane with explicit bounds.
    #[must_use]
    pub fn with_limits(limits: LaneLimits) -> Self {
        Self {
            queue: VecDeque::new(),
            queued_bytes: 0,
            tokens: limits.responses_per_second,
            last_refill_ms: 0,
            limits,
            degradation: LaneDegradation::default(),
            delivered: 0,
            holding: false,
        }
    }

    /// The bounds in force.
    #[must_use]
    pub const fn limits(&self) -> LaneLimits {
        self.limits
    }

    /// How the lane is currently shedding load.
    #[must_use]
    pub const fn degradation(&self) -> LaneDegradation {
        self.degradation
    }

    /// How many replies have been handed to the session loop.
    #[must_use]
    pub const fn delivered(&self) -> u64 {
        self.delivered
    }

    /// Replies waiting to be written.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.queue.len()
    }

    /// Bytes waiting to be written.
    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Offers a reply to the lane. Returns whether it was accepted.
    ///
    /// This is the only way anything reaches the lane, and the broker is the only caller. `now_ms` is
    /// a reading of the continuous clock the lane is driven by, which the deadline and the refill are
    /// measured from.
    pub(crate) fn offer(&mut self, mut response: Response, now_ms: u64) -> bool {
        if response.bytes.len() > self.limits.max_response_bytes {
            self.degradation.oversized += 1;
            return false;
        }
        self.refill(now_ms);
        if self.tokens == 0 {
            self.degradation.over_budget += 1;
            return false;
        }
        if self.queued_bytes + response.bytes.len() > self.limits.max_queue_bytes {
            self.shed_for(&response);
            if self.queued_bytes + response.bytes.len() > self.limits.max_queue_bytes {
                self.degradation.dropped += 1;
                return false;
            }
        }
        response.expires_at_ms = now_ms.saturating_add(self.limits.reply_deadline_ms);
        self.tokens -= 1;
        self.queued_bytes += response.bytes.len();
        self.queue.push_back(response);
        true
    }

    /// Takes replies to write, up to `max_bytes`.
    ///
    /// The caller passes its own byte budget so that draining the lane can never crowd out the
    /// human input the same loop is delivering. A reply that does not fit the remaining budget
    /// stays where it is, including the first one: a budget of zero takes nothing.
    ///
    /// A reply that has waited past its deadline is dropped here rather than written, and the drop
    /// shows up in the degradation record. `now_ms` is a reading of the same continuous clock the
    /// replies were offered on.
    ///
    /// With [`LaneGate::cursor_report_first`] set, the cursor reports go first, in their order, and
    /// nothing else is taken until one has been: the other replies are held, not dropped. A reply
    /// the hold kept does not age while it is kept, so when a cursor report ends the hold each of
    /// them has the time it had left when it was first kept. When the hold ends any other way the
    /// flag is simply not set again, no time is given back, and a reply that has by then waited
    /// past its deadline is dropped as it would be behind a paste: an answer that old would reach
    /// whatever reads next, which did not ask.
    pub fn drain(&mut self, gate: LaneGate, max_bytes: usize, now_ms: u64) -> Vec<Response> {
        if !gate.allows_write() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut taken = 0usize;
        if gate.cursor_report_first {
            self.hold_behind_cursor_report(now_ms);
            self.take_cursor_reports(max_bytes, now_ms, &mut taken, &mut out);
            if out.is_empty() {
                return out;
            }
            self.release_held(now_ms, true);
        } else if self.holding {
            self.release_held(now_ms, false);
        }
        while let Some(front) = self.queue.front() {
            if front.lapsed(now_ms) {
                let Some(expired) = self.queue.pop_front() else {
                    break;
                };
                self.queued_bytes -= expired.bytes.len();
                self.degradation.expired += 1;
                continue;
            }
            if taken + front.bytes.len() > max_bytes {
                break;
            }
            let Some(response) = self.queue.pop_front() else {
                break;
            };
            self.queued_bytes -= response.bytes.len();
            taken += response.bytes.len();
            self.delivered += 1;
            out.push(response);
        }
        out
    }

    /// Marks the replies that wait behind a cursor report, from now on, and drops one that had
    /// already waited past its deadline before it was first kept.
    fn hold_behind_cursor_report(&mut self, now_ms: u64) {
        self.holding = true;
        let mut index = 0;
        while index < self.queue.len() {
            let reply = &mut self.queue[index];
            if matches!(reply.kind, ResponseKind::CursorPosition) || reply.held_since.is_some() {
                index += 1;
            } else if reply.lapsed(now_ms) {
                if let Some(expired) = self.queue.remove(index) {
                    self.queued_bytes -= expired.bytes.len();
                    self.degradation.expired += 1;
                }
            } else {
                reply.held_since = Some(now_ms);
                index += 1;
            }
        }
    }

    /// Takes the cursor reports in the order they were offered.
    fn take_cursor_reports(
        &mut self,
        max_bytes: usize,
        now_ms: u64,
        taken: &mut usize,
        out: &mut Vec<Response>,
    ) {
        let mut index = 0;
        while index < self.queue.len() {
            let reply = &self.queue[index];
            if !matches!(reply.kind, ResponseKind::CursorPosition) {
                index += 1;
            } else if reply.lapsed(now_ms) {
                if let Some(expired) = self.queue.remove(index) {
                    self.queued_bytes -= expired.bytes.len();
                    self.degradation.expired += 1;
                }
            } else if *taken + reply.bytes.len() > max_bytes {
                break;
            } else if let Some(report) = self.queue.remove(index) {
                self.queued_bytes -= report.bytes.len();
                *taken += report.bytes.len();
                self.delivered += 1;
                out.push(report);
            }
        }
    }

    /// Ends the hold on the replies it kept. `given_back` says whether the time they were kept is
    /// added to their deadlines, which is so only when a cursor report ended the hold.
    fn release_held(&mut self, now_ms: u64, given_back: bool) {
        self.holding = false;
        for reply in &mut self.queue {
            if let Some(since) = reply.held_since.take()
                && given_back
            {
                reply.expires_at_ms = reply
                    .expires_at_ms
                    .saturating_add(now_ms.saturating_sub(since));
            }
        }
    }

    /// Drops everything waiting.
    ///
    /// Source loss and reconnection both use this: an undelivered reply from before a disconnect is
    /// not replayed to whoever attaches next.
    pub fn reset(&mut self) {
        self.queue.clear();
        self.queued_bytes = 0;
        self.holding = false;
    }

    /// Clears the recorded degradation once the status has been published.
    pub const fn clear_degradation(&mut self) {
        self.degradation = LaneDegradation {
            coalesced: 0,
            dropped: 0,
            over_budget: 0,
            oversized: 0,
            expired: 0,
        };
    }

    /// Adds whole tokens for the time that has passed.
    ///
    /// The baseline only moves when at least one token was earned, so a caller that polls faster
    /// than the token interval still accumulates instead of losing the remainder every time. A
    /// clock that goes backwards resets the baseline rather than granting a free burst.
    fn refill(&mut self, now_ms: u64) {
        if now_ms < self.last_refill_ms {
            self.last_refill_ms = now_ms;
            return;
        }
        let elapsed = now_ms - self.last_refill_ms;
        let gained = u64::from(self.limits.responses_per_second).saturating_mul(elapsed) / 1_000;
        if gained == 0 {
            return;
        }
        let capacity = u64::from(self.limits.responses_per_second);
        let tokens = u64::from(self.tokens).saturating_add(gained).min(capacity);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "tokens is clamped to responses_per_second, which is a u32"
        )]
        {
            self.tokens = tokens as u32;
        }
        self.last_refill_ms = now_ms;
    }

    /// Collapses an earlier pending reply about the same subject.
    fn shed_for(&mut self, incoming: &Response) {
        if !incoming.kind.coalescable() {
            return;
        }
        if let Some(index) = self.queue.iter().position(|r| r.kind == incoming.kind)
            && let Some(existing) = self.queue.remove(index)
        {
            self.queued_bytes -= existing.bytes.len();
            self.degradation.coalesced += 1;
        }
    }
}

impl Default for ResponseLane {
    fn default() -> Self {
        Self::new()
    }
}
