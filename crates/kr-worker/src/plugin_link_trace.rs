//! The link to the plugin runtime's account of its own work, for the cases that look into it.
//!
//! The link makes every call to the plugin runtime one after another, so what a binding is shown
//! while a call is out depends on what the link is doing. A case that waits for a binding's report
//! and finds it never came can say what it saw of the report but not what the link was doing. This
//! is the link's own record of that: each pass, each call with its name, its limit and how it
//! ended, each loss with its kind, each wait before the next try, and each report it made to a
//! binding. The broker's own part in what the link is given is in it too: each instance adopted
//! or ended, and each binding made, refused or forgotten, with the last six digits of the
//! identifiers and the process identifier of an adopted program.
//!
//! It exists only where the `testing` feature is on, and then it does nothing unless a file named
//! by [`switch_beside`] lies next to the worker's program, which only the cases that look into the
//! link make. A file is the switch because a service manager decides the environment a worker is
//! started with, and one of them gives it none of the launch's own variables. A worker that has it
//! on adds the last entries of its record to the reason of each component report it sends, after
//! [`MARKER`]; the reason before the marker is exactly what the worker sends without it.
//!
//! A record is a ring of [`ENTRIES`] entries in memory and is written nowhere. An entry holds a
//! time on the monotonic clock, fixed words, counts, the last six digits of an identifier, a
//! process identifier and a time limit: no error text, no path, no payload and no value of the
//! environment.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use kr_plugin_service::error::ServiceError;
use kr_protocol::admission::{ComponentReport, ComponentState};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ApplicationInstanceId, BrokerBindingId};
use kr_protocol::limits::MAX_REPORT_DETAIL_BYTES;
use kr_protocol::scalars::{Nullable, Uuid};

/// What is added to a worker's program file name to name the file that turns the record on.
const SWITCH_SUFFIX: &str = ".link-trace";

/// The file that turns the record on in the worker that runs `program`: a file beside it, named
/// like it with a suffix. It is asked for by its presence, and what it holds is not read.
#[must_use]
pub fn switch_beside(program: &Path) -> PathBuf {
    let mut name = program.file_name().unwrap_or_default().to_owned();
    name.push(SWITCH_SUFFIX);
    program.with_file_name(name)
}

/// What starts the record's tail in a reason. A reason is text a person reads, and the two
/// separators in it are control characters no reason holds.
pub const MARKER: &str = "\u{1f}link trace\u{1f}";

/// How many entries a record holds before the oldest goes.
pub const ENTRIES: usize = 64;

/// A call the link makes to the plugin runtime, or to the control daemon for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    /// The request to the control daemon for the runtime.
    Ask,
    /// The connection to the runtime and its handshake, whose requests are each given the limit.
    Connect,
    /// Telling the runtime whether privacy mode stands.
    Privacy,
    /// Registering one binding's component.
    Register,
    /// Removing one binding's registration.
    Unbind,
    /// Giving a component its held state back.
    Restore,
    /// Taking a component's state.
    Checkpoint,
    /// Asking the runtime what it is doing.
    Health,
    /// Telling a component what its binding is bound to now.
    ReviseFacts,
}

impl Call {
    const fn word(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Connect => "connect (each request)",
            Self::Privacy => "privacy",
            Self::Register => "register",
            Self::Unbind => "unbind",
            Self::Restore => "restore",
            Self::Checkpoint => "checkpoint",
            Self::Health => "health",
            Self::ReviseFacts => "revise",
        }
    }
}

/// How a call ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// It was answered.
    Answered,
    /// The runtime refused it, or the binding is disabled.
    Refused,
    /// The runtime could not be reached or closed the connection.
    Unavailable,
    /// Its limit passed before an answer came.
    Limit,
    /// It was given up before an answer came, because its binding went.
    Gone,
    /// The runtime answered, and the component declared a fault of its own.
    Faulted,
    /// It came to no answer that could be used: the other end was not reached, its limit passed,
    /// or what came back was of the wrong kind. Which of them is not told.
    Failed,
}

impl Outcome {
    const fn word(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::Refused => "refused",
            Self::Unavailable => "unavailable",
            Self::Limit => "limit",
            Self::Gone => "gone",
            Self::Faulted => "faulted",
            Self::Failed => "failed",
        }
    }

    /// What a call's result came to.
    #[must_use]
    pub const fn of<T>(result: &Result<T, ServiceError>) -> Self {
        match result {
            Ok(_) => Self::Answered,
            Err(ServiceError::Unavailable { .. }) => Self::Unavailable,
            Err(ServiceError::CallerDeadline { .. }) => Self::Limit,
            Err(_) => Self::Refused,
        }
    }
}

/// Why the link took the runtime to be lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A call's limit passed.
    Limit,
    /// A call found the runtime unreachable.
    Unavailable,
    /// A call was refused where the runtime cannot refuse.
    Refused,
    /// The health call went unanswered as many times in a row as the link allows.
    StoppedAnswering,
    /// The runtime ended its connection.
    Ended,
}

impl Why {
    const fn word(self) -> &'static str {
        match self {
            Self::Limit => "limit",
            Self::Unavailable => "unavailable",
            Self::Refused => "refused",
            Self::StoppedAnswering => "stopped-answering",
            Self::Ended => "ended",
        }
    }

    /// The loss a failed call is.
    #[must_use]
    pub const fn of(error: &ServiceError) -> Self {
        match error {
            ServiceError::Unavailable { .. } => Self::Unavailable,
            ServiceError::CallerDeadline { .. } => Self::Limit,
            _ => Self::Refused,
        }
    }
}

/// What a report to a binding said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Asking the control daemon for the runtime.
    Asking,
    /// Connecting to the runtime.
    Connecting,
    /// Registering with it.
    Registering,
    /// Registered.
    Registered,
    /// Unavailable.
    Unavailable,
    /// Anything else.
    Other,
}

impl Step {
    const fn word(self) -> &'static str {
        match self {
            Self::Asking => "asking",
            Self::Connecting => "connecting",
            Self::Registering => "registering",
            Self::Registered => "registered",
            Self::Unavailable => "unavailable",
            Self::Other => "other",
        }
    }

    /// The step a state and its reason come to, by the words the link reports.
    #[must_use]
    pub fn of(state: ComponentState, reason: Option<&str>) -> Self {
        match (state, reason) {
            (ComponentState::Registered, _) => Self::Registered,
            (ComponentState::Unavailable, _) => Self::Unavailable,
            (ComponentState::Pending, Some(reason)) if reason.starts_with("asking") => Self::Asking,
            (ComponentState::Pending, Some(reason)) if reason.starts_with("connecting") => {
                Self::Connecting
            }
            (ComponentState::Pending, Some(reason)) if reason.starts_with("registering") => {
                Self::Registering
            }
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Pass {
        wants: usize,
    },
    Began {
        call: Call,
        binding: Option<u32>,
        limit_ms: u64,
    },
    Ended {
        call: Call,
        binding: Option<u32>,
        outcome: Outcome,
        took_ms: u64,
    },
    Lost {
        why: Why,
    },
    Retry {
        in_ms: u64,
    },
    Reported {
        step: Step,
        binding: u32,
    },
    /// A program found running was recorded as an instance.
    Adopted {
        instance: u32,
        pid: u64,
    },
    /// A binding was made for an instance.
    Bound {
        binding: u32,
        instance: u32,
    },
    /// An instance nothing had bound is being bound to the package that now recognises its
    /// program.
    BindingTheUnbound {
        instance: u32,
    },
    /// A request to bind an instance was refused.
    BindRefused {
        instance: u32,
    },
    /// A binding left the broker.
    Forgot {
        binding: u32,
        instance: u32,
    },
    /// An instance ended, or was given back.
    InstanceEnded {
        instance: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    /// Which entry this is in the order they were noted, from zero, so that tails taken at
    /// different times can be put together and a gap between them seen.
    seq: u64,
    at_ms: u64,
    event: Event,
}

#[derive(Debug)]
struct Ring {
    entries: VecDeque<Entry>,
    next: u64,
}

/// A call that has begun, to be ended with its outcome.
#[derive(Clone, Copy, Debug)]
pub struct Began {
    call: Call,
    binding: Option<u32>,
    at: Instant,
}

/// The last six hexadecimal digits of an identifier, which is how the cases name a binding and
/// an instance.
const fn label(id: Uuid) -> u32 {
    let bytes = id.as_bytes();
    let last = bytes.len() - 1;
    u32::from_be_bytes([0, bytes[last - 2], bytes[last - 1], bytes[last]])
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// One worker's record.
#[derive(Debug)]
pub struct LinkTrace {
    origin: Instant,
    ring: Mutex<Ring>,
}

impl Default for LinkTrace {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkTrace {
    /// An empty record whose times count from now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
            ring: Mutex::new(Ring {
                entries: VecDeque::with_capacity(ENTRIES),
                next: 0,
            }),
        }
    }

    fn ring(&self) -> MutexGuard<'_, Ring> {
        self.ring.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn push(&self, event: Event) {
        let at_ms = millis(self.origin.elapsed());
        let mut ring = self.ring();
        if ring.entries.len() == ENTRIES {
            ring.entries.pop_front();
        }
        let seq = ring.next;
        ring.next += 1;
        ring.entries.push_back(Entry { seq, at_ms, event });
    }

    /// Notes that a pass began with this many bindings wanting a component.
    pub fn pass(&self, wants: usize) {
        self.push(Event::Pass { wants });
    }

    /// Notes that a call began, with the limit it is given.
    pub fn began(&self, call: Call, binding: Option<BrokerBindingId>, limit: Duration) -> Began {
        let binding = binding.map(|binding| label(binding.get()));
        self.push(Event::Began {
            call,
            binding,
            limit_ms: millis(limit),
        });
        Began {
            call,
            binding,
            at: Instant::now(),
        }
    }

    /// Notes how a call that began ended.
    pub fn ended(&self, began: Began, outcome: Outcome) {
        self.push(Event::Ended {
            call: began.call,
            binding: began.binding,
            outcome,
            took_ms: millis(began.at.elapsed()),
        });
    }

    /// Notes that the runtime was taken to be lost.
    pub fn lost(&self, why: Why) {
        self.push(Event::Lost { why });
    }

    /// Notes how long the link leaves before it tries the runtime again.
    pub fn retry(&self, wait: Duration) {
        self.push(Event::Retry {
            in_ms: millis(wait),
        });
    }

    /// Notes a report made to a binding.
    pub fn reported(&self, binding: BrokerBindingId, step: Step) {
        self.push(Event::Reported {
            step,
            binding: label(binding.get()),
        });
    }

    /// Notes that a program found running was recorded as an instance.
    pub fn adopted(&self, instance: ApplicationInstanceId, process: &ProcessStartIdentity) {
        self.push(Event::Adopted {
            instance: label(instance.get()),
            pid: process.pid.get(),
        });
    }

    /// Notes that a binding was made for an instance.
    pub fn bound(&self, binding: BrokerBindingId, instance: ApplicationInstanceId) {
        self.push(Event::Bound {
            binding: label(binding.get()),
            instance: label(instance.get()),
        });
    }

    /// Notes that an instance nothing had bound is being bound.
    pub fn binding_the_unbound(&self, instance: ApplicationInstanceId) {
        self.push(Event::BindingTheUnbound {
            instance: label(instance.get()),
        });
    }

    /// Notes that a request to bind an instance was refused.
    pub fn bind_refused(&self, instance: ApplicationInstanceId) {
        self.push(Event::BindRefused {
            instance: label(instance.get()),
        });
    }

    /// Notes that a binding left the broker.
    pub fn forgot(&self, binding: BrokerBindingId, instance: ApplicationInstanceId) {
        self.push(Event::Forgot {
            binding: label(binding.get()),
            instance: label(instance.get()),
        });
    }

    /// Notes that an instance ended, or was given back.
    pub fn instance_ended(&self, instance: ApplicationInstanceId) {
        self.push(Event::InstanceEnded {
            instance: label(instance.get()),
        });
    }

    /// How many entries the record holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ring().entries.len()
    }

    /// Returns true when nothing has been noted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ring().entries.is_empty()
    }

    /// The newest entries that fit in `budget` bytes, oldest first, one phrase each.
    #[must_use]
    pub fn tail(&self, budget: usize) -> String {
        let ring = self.ring();
        let mut phrases: Vec<String> = Vec::new();
        let mut used = 0usize;
        for entry in ring.entries.iter().rev() {
            let phrase = phrase(entry);
            let cost = phrase.len()
                + if phrases.is_empty() {
                    0
                } else {
                    SEPARATOR.len()
                };
            if used + cost > budget {
                break;
            }
            used += cost;
            phrases.push(phrase);
        }
        phrases.reverse();
        phrases.join(SEPARATOR)
    }

    /// The report with the record's tail after its reason, within the bound a report carries. The
    /// tail is cut to what room is left and never the reason; a reason that already holds the
    /// marker, or that leaves no room, is sent as it is. A report that has no reason is sent with
    /// the marker and the tail as its reason, so what comes before the marker is empty then.
    #[must_use]
    pub fn with_tail(&self, mut report: ComponentReport) -> ComponentReport {
        let original = report.reason.0.clone().unwrap_or_default();
        if original.contains(MARKER) {
            return report;
        }
        let room = MAX_REPORT_DETAIL_BYTES.saturating_sub(original.len() + MARKER.len());
        let tail = self.tail(room);
        if tail.is_empty() {
            return report;
        }
        report.reason = Nullable::some(format!("{original}{MARKER}{tail}"));
        report
    }
}

const SEPARATOR: &str = "; ";

fn phrase(entry: &Entry) -> String {
    let at = format!(
        "#{} {}.{:03}",
        entry.seq,
        entry.at_ms / 1000,
        entry.at_ms % 1000
    );
    let named = |binding: Option<u32>| binding.map_or_else(String::new, |id| format!(" {id:06x}"));
    match entry.event {
        Event::Pass { wants } => format!("{at} pass wants {wants}"),
        Event::Began {
            call,
            binding,
            limit_ms,
        } => format!(
            "{at} began {}{} limit {limit_ms}",
            call.word(),
            named(binding)
        ),
        Event::Ended {
            call,
            binding,
            outcome,
            took_ms,
        } => format!(
            "{at} ended {}{} {} after {took_ms}",
            call.word(),
            named(binding),
            outcome.word()
        ),
        Event::Lost { why } => format!("{at} lost {}", why.word()),
        Event::Retry { in_ms } => format!("{at} retry in {in_ms}"),
        Event::Reported { step, binding } => {
            format!("{at} reported {} {binding:06x}", step.word())
        }
        Event::Adopted { instance, pid } => {
            format!("{at} adopted instance {instance:06x} process {pid}")
        }
        Event::Bound { binding, instance } => {
            format!("{at} bound {binding:06x} to instance {instance:06x}")
        }
        Event::BindingTheUnbound { instance } => {
            format!("{at} binding the unbound instance {instance:06x}")
        }
        Event::BindRefused { instance } => {
            format!("{at} bind refused for instance {instance:06x}")
        }
        Event::Forgot { binding, instance } => {
            format!("{at} forgot {binding:06x} of instance {instance:06x}")
        }
        Event::InstanceEnded { instance } => format!("{at} ended instance {instance:06x}"),
    }
}

/// The reason without the record's tail: what the worker sends with the record off.
#[must_use]
pub fn plain(reason: &str) -> &str {
    reason.split_once(MARKER).map_or(reason, |(plain, _)| plain)
}

/// The record's tail a reason carries, where it carries one.
#[must_use]
pub fn tail_of(reason: &str) -> Option<&str> {
    reason.split_once(MARKER).map(|(_, tail)| tail)
}

/// How many entries a [`History`] keeps. Past it, the oldest entries after the first half go.
const HISTORY_ENTRIES: usize = 4096;

/// The tails of one worker's record taken at different times, put together: each entry once, in
/// the order it was noted, with a note where entries were noted that no tail held.
///
/// A tail holds only the newest entries that fit a report, so one taken when a long wait ends has
/// lost what happened early in it. A reader that takes a tail with each look keeps all of it, in
/// whatever order the tails come. It takes a worker's record to be one: entries of a record that
/// began again carry numbers the history holds already, and are dropped until they pass them.
#[derive(Debug, Default)]
pub struct History {
    entries: BTreeMap<u64, String>,
    last_new: Option<Instant>,
}

impl History {
    /// Adds the entries of a tail that this history does not hold yet.
    pub fn add(&mut self, tail: &str) {
        for phrase in tail.split(SEPARATOR) {
            let Some(seq) = numbered(phrase) else {
                continue;
            };
            if self.entries.contains_key(&seq) {
                continue;
            }
            self.entries.insert(seq, phrase.to_owned());
            self.last_new = Some(Instant::now());
            if self.entries.len() > HISTORY_ENTRIES {
                // The first half stays, since it holds how a wait began; the oldest of the rest
                // goes, and shows as a gap.
                if let Some(&oldest) = self.entries.keys().nth(HISTORY_ENTRIES / 2) {
                    self.entries.remove(&oldest);
                }
            }
        }
    }

    /// Every entry held, oldest first, one phrase each, a note where entries are missing between
    /// two of them or before the first, and how long ago the newest was taken.
    #[must_use]
    pub fn in_words(&self) -> String {
        let mut words: Vec<String> = Vec::new();
        let mut expected = 0;
        for (seq, phrase) in &self.entries {
            if *seq > expected {
                words.push(format!("[{} entries not held]", seq - expected));
            }
            words.push(phrase.clone());
            expected = seq + 1;
        }
        if let Some(taken) = self.last_new {
            words.push(format!(
                "[the newest entry was taken {} ms before this]",
                millis(taken.elapsed())
            ));
        }
        words.join(SEPARATOR)
    }
}

/// The number an entry's phrase starts with.
fn numbered(phrase: &str) -> Option<u64> {
    phrase.strip_prefix('#')?.split_once(' ')?.0.parse().ok()
}

/// This worker's record, once the link has found the file of [`switch_beside`] beside its program.
static ON: OnceLock<LinkTrace> = OnceLock::new();

/// Whether the file that asks for the record lies beside `program`: a regular file, taken as it
/// is where it is found and not by a link that leads to one.
fn asked(program: &Path) -> bool {
    std::fs::symlink_metadata(switch_beside(program)).is_ok_and(|found| found.file_type().is_file())
}

/// Starts this worker's record where the file that asks for it lies beside this worker's program.
pub fn start_if_asked() {
    if std::env::current_exe().is_ok_and(|program| asked(&program)) {
        start();
    }
}

/// Starts this worker's record now, for a case of the broker that wants the account of what the
/// broker did to say what it saw.
pub fn start() {
    let _ = ON.set(LinkTrace::new());
}

/// The whole record, oldest entry first, where it is on.
#[must_use]
pub fn account() -> Option<String> {
    ON.get().map(|trace| trace.tail(usize::MAX))
}

/// Notes the start of a pass of the link.
pub fn pass(wants: usize) {
    if let Some(trace) = ON.get() {
        trace.pass(wants);
    }
}

/// Notes the start of a call, where the record is on.
#[must_use]
pub fn began(call: Call, binding: Option<BrokerBindingId>, limit: Duration) -> Option<Began> {
    ON.get().map(|trace| trace.began(call, binding, limit))
}

/// Notes the end of a call noted by [`began`].
pub fn ended(began: Option<Began>, outcome: Outcome) {
    if let (Some(trace), Some(began)) = (ON.get(), began) {
        trace.ended(began, outcome);
    }
}

/// Notes that the runtime was taken to be lost.
pub fn lost(why: Why) {
    if let Some(trace) = ON.get() {
        trace.lost(why);
    }
}

/// Notes how long the link leaves before it tries the runtime again.
pub fn retry(wait: Duration) {
    if let Some(trace) = ON.get() {
        trace.retry(wait);
    }
}

/// Notes a report made to a binding.
pub fn reported(binding: BrokerBindingId, state: ComponentState, reason: Option<&str>) {
    if let Some(trace) = ON.get() {
        trace.reported(binding, Step::of(state, reason));
    }
}

/// Notes that a program found running was recorded as an instance.
pub fn adopted(instance: ApplicationInstanceId, process: &ProcessStartIdentity) {
    if let Some(trace) = ON.get() {
        trace.adopted(instance, process);
    }
}

/// Notes that a binding was made for an instance.
pub fn bound(binding: BrokerBindingId, instance: ApplicationInstanceId) {
    if let Some(trace) = ON.get() {
        trace.bound(binding, instance);
    }
}

/// Notes that an instance nothing had bound is being bound.
pub fn binding_the_unbound(instance: ApplicationInstanceId) {
    if let Some(trace) = ON.get() {
        trace.binding_the_unbound(instance);
    }
}

/// Notes that a request to bind an instance was refused.
pub fn bind_refused(instance: ApplicationInstanceId) {
    if let Some(trace) = ON.get() {
        trace.bind_refused(instance);
    }
}

/// Notes that a binding left the broker.
pub fn forgot(binding: BrokerBindingId, instance: ApplicationInstanceId) {
    if let Some(trace) = ON.get() {
        trace.forgot(binding, instance);
    }
}

/// Notes that an instance ended, or was given back.
pub fn instance_ended(instance: ApplicationInstanceId) {
    if let Some(trace) = ON.get() {
        trace.instance_ended(instance);
    }
}

/// A component report with this worker's tail after its reason where the record is on, and as it
/// is where it is not.
#[must_use]
pub fn with_tail(report: Option<ComponentReport>) -> Option<ComponentReport> {
    match (ON.get(), report) {
        (Some(trace), Some(report)) => Some(trace.with_tail(report)),
        (_, report) => report,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(state: ComponentState, reason: Option<&str>) -> ComponentReport {
        ComponentReport {
            state,
            reason: reason.map_or_else(Nullable::null, |text| Nullable::some(text.to_owned())),
            reason_cut: false,
        }
    }

    #[test]
    fn a_record_keeps_the_newest_entries_in_order_and_no_more_than_its_bound() {
        let trace = LinkTrace::new();
        for wants in 0..ENTRIES + 10 {
            trace.pass(wants);
        }
        assert_eq!(trace.len(), ENTRIES);
        let tail = trace.tail(usize::MAX);
        let numbers: Vec<usize> = tail
            .split(SEPARATOR)
            .map(|phrase| {
                phrase
                    .rsplit(' ')
                    .next()
                    .and_then(|last| last.parse().ok())
                    .expect("each phrase ends in its count")
            })
            .collect();
        assert_eq!(numbers, (10..ENTRIES + 10).collect::<Vec<_>>());
    }

    #[test]
    fn tails_taken_over_a_long_wait_are_put_together_with_each_entry_once_and_the_gaps_told() {
        let trace = LinkTrace::new();
        let binding = "00000000-0000-0000-0000-000000123456"
            .parse::<BrokerBindingId>()
            .expect("an identifier");
        let mut history = History::default();
        // The call that is never answered is in the first tail taken, and what follows it fills the
        // record many times over while the tails taken are each far shorter than the record.
        let _began = trace.began(Call::Register, Some(binding), Duration::from_secs(35));
        history.add(&trace.tail(usize::MAX));
        for wants in 0..ENTRIES * 3 {
            trace.pass(wants);
            history.add(&trace.tail(120));
        }
        let words = history.in_words();
        assert!(words.starts_with("#0 "), "{words}");
        assert!(
            words.contains("began register 123456 limit 35000"),
            "{words}"
        );
        assert!(!words.contains("not held"), "{words}");
        let numbers: Vec<u64> = words.split(SEPARATOR).filter_map(numbered).collect();
        assert_eq!(
            numbers,
            (0..=u64::try_from(ENTRIES * 3).expect("a count")).collect::<Vec<_>>(),
            "each entry once, in order"
        );
        assert!(words.contains("the newest entry was taken"), "{words}");
        // Entries noted between two tails that neither held are told, and the same tail twice adds
        // nothing.
        for wants in 0..=ENTRIES {
            trace.pass(wants);
        }
        history.add(&trace.tail(usize::MAX));
        history.add(&trace.tail(usize::MAX));
        let words = history.in_words();
        assert_eq!(words.matches("entries not held]").count(), 1, "{words}");
        assert!(words.contains("[1 entries not held]"), "{words}");
        // A history that starts from the middle of a record says what came before it.
        let mut later = History::default();
        later.add(&trace.tail(200));
        assert!(later.in_words().starts_with('[') && later.in_words().contains("not held]"));
    }

    #[test]
    fn a_tail_that_comes_after_a_later_one_fills_the_gap_between_what_was_held() {
        let entry = |seq: u64| format!("#{seq} 0.000 pass wants {seq}");
        let tail = |from: u64, to: u64| (from..=to).map(entry).collect::<Vec<_>>().join(SEPARATOR);
        let mut history = History::default();
        history.add(&tail(0, 1));
        history.add(&tail(9, 9));
        history.add(&tail(4, 5));
        let held: Vec<String> = history
            .in_words()
            .split(SEPARATOR)
            .take_while(|phrase| !phrase.contains("the newest"))
            .map(str::to_owned)
            .collect();
        assert_eq!(
            held,
            [
                entry(0),
                entry(1),
                "[2 entries not held]".to_owned(),
                entry(4),
                entry(5),
                "[3 entries not held]".to_owned(),
                entry(9),
            ]
        );
        history.add(&tail(2, 8));
        let words = history.in_words();
        assert!(!words.contains("not held"), "{words}");
    }

    #[test]
    fn a_history_that_outgrows_its_bound_keeps_how_a_wait_began_and_its_newest_entries() {
        let mut history = History::default();
        for seq in 0..u64::try_from(HISTORY_ENTRIES * 2).expect("a count") {
            history.add(&format!("#{seq} 0.000 pass wants 0"));
        }
        let words = history.in_words();
        assert!(words.starts_with("#0 "), "{words}");
        assert!(
            words.contains(&format!("#{} ", HISTORY_ENTRIES * 2 - 1)),
            "{words}"
        );
        assert!(words.contains("entries not held]"), "{words}");
        assert_eq!(history.entries.len(), HISTORY_ENTRIES);
    }

    #[test]
    fn a_tail_names_a_call_with_its_limit_and_how_it_ended() {
        let trace = LinkTrace::new();
        let binding = "00000000-0000-0000-0000-000000123456"
            .parse::<BrokerBindingId>()
            .expect("an identifier");
        let began = trace.began(Call::Register, Some(binding), Duration::from_secs(35));
        let tail = trace.tail(usize::MAX);
        assert!(
            tail.ends_with("began register 123456 limit 35000"),
            "{tail}"
        );
        trace.ended(began, Outcome::Limit);
        trace.lost(Why::Limit);
        trace.retry(Duration::from_millis(500));
        let tail = trace.tail(usize::MAX);
        assert!(tail.contains("ended register 123456 limit after"), "{tail}");
        assert!(
            tail.ends_with("lost limit; ") || tail.contains("lost limit; "),
            "{tail}"
        );
        assert!(
            tail.ends_with("retry in 500") || tail.contains("retry in 500"),
            "{tail}"
        );
    }

    #[test]
    fn a_tail_names_what_the_broker_did_to_an_instance_and_its_bindings_by_their_last_six_digits() {
        let trace = LinkTrace::new();
        let binding = "00000000-0000-0000-0000-000000abcdef"
            .parse::<BrokerBindingId>()
            .expect("an identifier");
        let instance = "00000000-0000-0000-0000-000000123456"
            .parse::<ApplicationInstanceId>()
            .expect("an identifier");
        let process = ProcessStartIdentity::new(
            4242,
            kr_protocol::identity::ProcessStartSource::LinuxProcStat,
            7,
        );
        trace.adopted(instance, &process);
        trace.binding_the_unbound(instance);
        trace.bound(binding, instance);
        trace.bind_refused(instance);
        trace.forgot(binding, instance);
        trace.instance_ended(instance);
        let tail = trace.tail(usize::MAX);
        for phrase in [
            "adopted instance 123456 process 4242",
            "binding the unbound instance 123456",
            "bound abcdef to instance 123456",
            "bind refused for instance 123456",
            "forgot abcdef of instance 123456",
            "ended instance 123456",
        ] {
            assert!(tail.contains(phrase), "{phrase} is not in {tail}");
        }
    }

    #[test]
    fn a_reason_with_the_tail_removed_is_what_is_sent_without_it_and_stays_within_the_bound() {
        let trace = LinkTrace::new();
        for wants in 0..ENTRIES {
            trace.pass(wants);
        }
        let long = "r".repeat(MAX_REPORT_DETAIL_BYTES - 40);
        let full = "r".repeat(MAX_REPORT_DETAIL_BYTES);
        for original in [
            None,
            Some(""),
            Some("registering with the plugin runtime"),
            Some(long.as_str()),
            Some(full.as_str()),
        ] {
            let sent = trace.with_tail(report(ComponentState::Pending, original));
            let reason = sent.reason.0.clone();
            assert!(
                reason
                    .as_ref()
                    .is_none_or(|text| text.len() <= MAX_REPORT_DETAIL_BYTES),
                "the reason stays within the bound"
            );
            assert_eq!(
                plain(reason.as_deref().unwrap_or("")),
                original.unwrap_or(""),
                "the reason before the marker is untouched"
            );
            assert_eq!(sent.state, ComponentState::Pending);
            assert!(!sent.reason_cut);
        }
        // A reason with no room left for the marker and one entry is sent as it is.
        let sent = trace.with_tail(report(ComponentState::Pending, Some(full.as_str())));
        assert_eq!(sent.reason.0.as_deref(), Some(full.as_str()));
        // And so is one that holds the marker already.
        let marked = format!("a{MARKER}b");
        let sent = trace.with_tail(report(ComponentState::Pending, Some(marked.as_str())));
        assert_eq!(sent.reason.0.as_deref(), Some(marked.as_str()));
    }

    #[test]
    fn a_record_that_is_empty_changes_no_reason() {
        let trace = LinkTrace::new();
        for original in [None, Some("unavailable")] {
            let before = report(ComponentState::Unavailable, original);
            assert_eq!(trace.with_tail(before.clone()), before);
        }
    }

    #[test]
    fn only_a_file_beside_the_program_with_its_name_asks_for_the_record() {
        let directory = tempfile::tempdir().expect("a directory");
        let program = directory.path().join("kr-worker");
        assert!(!asked(&program));
        std::fs::write(directory.path().join("kr-worker-other.link-trace"), "").expect("a file");
        std::fs::write(directory.path().join("kr-worker.link"), "").expect("a file");
        assert!(!asked(&program));
        std::fs::write(switch_beside(&program), "").expect("a file");
        assert!(asked(&program));
        assert_eq!(
            switch_beside(&program)
                .file_name()
                .and_then(|name| name.to_str()),
            Some("kr-worker.link-trace")
        );
        // A file of the program's own name in another directory is not beside this one.
        let elsewhere = tempfile::tempdir().expect("a directory");
        assert!(!asked(&elsewhere.path().join("kr-worker")));
    }

    #[test]
    fn a_directory_or_a_link_in_the_place_of_the_file_does_not_ask_for_the_record() {
        let directory = tempfile::tempdir().expect("a directory");
        let program = directory.path().join("kr-worker");
        std::fs::create_dir(switch_beside(&program)).expect("a directory");
        assert!(!asked(&program));
        std::fs::remove_dir(switch_beside(&program)).expect("the directory removed");
        #[cfg(unix)]
        {
            let real = directory.path().join("real");
            std::fs::write(&real, "").expect("a file");
            std::os::unix::fs::symlink(&real, switch_beside(&program)).expect("a link");
            assert!(!asked(&program));
        }
    }

    #[test]
    fn a_worker_with_no_file_beside_its_program_sends_its_reports_as_they_are() {
        // Nothing beside this test program asks for the record, and nothing here makes it.
        start_if_asked();
        assert!(ON.get().is_none());
        for original in [None, Some("registering with the plugin runtime")] {
            let sent = report(ComponentState::Pending, original);
            assert_eq!(with_tail(Some(sent.clone())), Some(sent));
        }
        assert_eq!(with_tail(None), None);
        pass(3);
        lost(Why::Limit);
        assert!(ON.get().is_none());
    }

    #[test]
    fn a_tail_holds_only_fixed_words_counts_and_times() {
        let trace = LinkTrace::new();
        let binding = "00000000-0000-0000-0000-000000000007"
            .parse::<BrokerBindingId>()
            .expect("an identifier");
        trace.reported(
            binding,
            Step::of(
                ComponentState::Pending,
                Some("registering with the plugin runtime"),
            ),
        );
        let began = trace.began(Call::Health, None, Duration::from_secs(5));
        trace.ended(
            began,
            Outcome::of::<()>(&Err(ServiceError::Unavailable {
                detail: "/a/path/of/a/person's/file".to_owned(),
            })),
        );
        trace.lost(Why::of(&ServiceError::Unavailable {
            detail: "/a/path/of/a/person's/file".to_owned(),
        }));
        let tail = trace.tail(usize::MAX);
        assert!(!tail.contains('/') && !tail.contains("person"), "{tail}");
        assert!(tail.contains("ended health unavailable after"), "{tail}");
    }
}
