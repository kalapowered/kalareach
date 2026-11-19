//! One observing hook, for every application whose registration starts the forwarder as one.
//!
//! A hook here observes. Whatever happens, the forwarder writes exactly `{}` to standard output and
//! exits 0, promptly: a JSON object with no members is the neutral answer on every event of every
//! application this serves, and exit 0 is the code that neither blocks nor reports an error. It
//! never answers with a decision, never prints anything a hook's output could be read as, and
//! never waits for a person.
//!
//! What differs between applications is the name the bridge declares, which an [`Application`]
//! holds, and how the application writes a hook's input: the names of its events and the places in
//! the input of the members a report carries. The package declares those as hook events in its
//! connector table, the worker publishes them for the launch and the registration names them; a
//! package that declares none gets Claude Code's, which [`HookEvents::claude_code`] holds. What a
//! hook can report is five things, whatever the package says. The deadline, the input bound, the
//! exchange with the worker and the answer are this module's, the same for all of them.
//!
//! Every run waits for its observation for at most [`HOOK_DEADLINE`] from its start, well inside the
//! shortest timeout any registration names (one second, for a session ending). When that passes,
//! the answer is written and the process ends, whatever is still in flight. The answer goes before
//! anything the run says about itself: a diagnostic goes to standard error after it, and is waited
//! for until the same deadline or [`DIAGNOSTIC_ALLOWANCE`] after the answer, whichever is later, so
//! a standard error nobody reads can hold neither the answer nor, past that, the end. The waits a
//! run asks for therefore add up to 600 ms on Windows at the most: the deadline and the allowance
//! after it. On Unix a hook that is handing its launch over to the forwarder of the worker's own
//! release holds its answer, after the wait for its work and before the answer, for at most
//! `helper::CLAIM_WAIT` (100 ms) while that forwarder starts in its place, and the allowance counts
//! from the answer, so the waits add up to 700 ms there. Both sums are inside the one second, by
//! 400 ms and 300 ms. They are sums of what a run asks to wait, held by cases on a clock that the
//! cases move; on the system's clock a loaded machine adds its own delay to each wake-up (a hosted
//! Windows run read 1.13 seconds for a run of this shape). The diagnostic says how long the run
//! had run, on its own clock, when its answer was written
//! ([`answered_after`]), which is the figure to hold against an application's timeout: how long the
//! machine took to start the process and to let it end lies outside the run.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::Duration;

use kr_plugin_sdk::hook_events::{CONTACT_REQUEST_MEMBER, HookEvent, HookEvents, HookReport};
use serde::de::{DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::exchange::Exchange;
use crate::registration::{Bridge, Paths, Registration};

/// The surface every hook declares itself to the worker as.
pub const SURFACE: &str = "hook";

/// How long a hook waits for its observation, from its start, before it answers anyway. A
/// diagnostic written after the answer is waited for until the same moment, or for
/// [`DIAGNOSTIC_ALLOWANCE`] after the answer when that is later.
///
/// Every registration gives a session ending one second and every other event five. An
/// application cancels a hook that reaches its timeout and discards its output, and Gemini CLI
/// also warns the person, so the deadline sits well inside the shorter one.
pub const HOOK_DEADLINE: Duration = Duration::from_millis(500);

/// How long a diagnostic written after the answer is waited for at the least.
///
/// A run that spent all of [`HOOK_DEADLINE`] waiting for its worker still says why, on a standard
/// error that takes the line, and one that does not take it holds the hook this much longer at
/// most, which keeps the end well inside the shortest timeout any registration names.
pub const DIAGNOSTIC_ALLOWANCE: Duration = Duration::from_millis(100);

/// The most of a hook's input this forwarder reads.
///
/// A finished tool's event carries the tool's whole response, which can be large. It is read to
/// its end so the application's write completes, and past this bound it is left unread.
pub const MAX_HOOK_INPUT_BYTES: u64 = 64 * 1024 * 1024;

/// The answer every hook run writes: a JSON object that sets nothing.
pub const NEUTRAL_ANSWER: &str = "{}";

/// How soon after it started a hook that reported a thread starting, going on or ending answers,
/// at the earliest.
///
/// The worker places those reports by the kernel's record of when each hook started, which counts
/// ten-millisecond ticks on Linux, and it does not place two from one tick against each other.
/// Answering two ticks after the start means a hook the application starts only once this one has
/// answered, as Claude Code does after a session ends, falls in a later tick.
pub const THREAD_REPORT_LINGER: Duration = Duration::from_millis(20);

/// How long a hook waits for the worker to finish publishing its launch.
///
/// The worker writes the registration as soon as it knows which process it started, long before
/// the application runs its first hook, so this only covers a hook that races the launch itself.
pub const REGISTRATION_WAIT: Duration = Duration::from_millis(250);

/// The longest detail an observation carries, which is the host's own bound.
pub const MAX_DETAIL_BYTES: usize = 256;

/// The longest text an observation carries, which is the host's own bound.
pub const MAX_TEXT_BYTES: usize = 4096;

/// The longest contact request identifier, which is the longest a question's own may be.
pub const MAX_CONTACT_REQUEST_BYTES: usize = 256;

/// One application's hooks, as the runner serves them.
#[derive(Debug)]
pub struct Application {
    /// The application name its registration invokes the forwarder with, which is also the
    /// application its bridge declares to the worker.
    pub name: Cow<'static, str>,
}

impl Application {
    /// The hooks of the application a registration names by `word`.
    #[must_use]
    pub fn for_word(word: &str) -> Self {
        Self {
            name: Cow::Owned(word.to_owned()),
        }
    }

    /// The bridge a hook of this application declares.
    #[must_use]
    pub fn bridge(&self) -> Bridge {
        Bridge {
            application: self.name.clone(),
            surface: SURFACE,
        }
    }
}

/// Runs one hook of `application`, which started at `started`, and answers neutrally.
///
/// The run's clock is the process's: what a hook waits for before it reads its input, taking the
/// hold on its release included, counts against its deadline.
#[must_use]
pub fn run(application: Application, started: std::time::Instant) -> std::process::ExitCode {
    // A hook started in place of another has the rest of the deadline the application gave that
    // one, which may have ended before it began.
    #[cfg(unix)]
    let started = match resumed(started) {
        Resumed::Passed => {
            answer();
            return std::process::ExitCode::SUCCESS;
        }
        Resumed::At(started) => started,
    };
    run_with(
        started,
        move |started| observe(&application, started),
        claim_answer,
        answer,
        |bytes| {
            use std::io::Write as _;
            let _ = std::io::stderr().lock().write_all(bytes);
        },
        std::time::Instant::now,
        crate::wait_by,
    );
    std::process::ExitCode::SUCCESS
}

/// What a hook does before it writes its answer so that no forwarder is started in its place
/// afterwards.
fn claim_answer() {
    #[cfg(unix)]
    crate::helper::claim_answer();
}

/// Where a hook stands when it was started in place of another.
#[cfg(unix)]
enum Resumed {
    /// The deadline of the hook it replaced ended before it began.
    Passed,
    /// The hook began at this moment, as far as its deadline goes.
    At(std::time::Instant),
}

/// The moment this hook began as far as its deadline goes: `started`, or the moment the hook it
/// replaced began when it was started in place of one.
#[cfg(unix)]
fn resumed(started: std::time::Instant) -> Resumed {
    resumed_by(
        started,
        crate::helper::Marker::of_this_process(),
        std::time::Instant::now,
        kr_ipc::clock::boot_elapsed_ms,
    )
}

/// [`resumed`] given the marker and the two clocks: this process's own, and the machine's
/// continuous one that the marker's deadline is kept on.
///
/// Neither is read when there is no marker. This process's clock is read first and the machine's
/// second, so that a pause between the two readings shortens what is left instead of lengthening
/// it.
#[cfg(unix)]
fn resumed_by(
    started: std::time::Instant,
    marker: Option<crate::helper::Marker>,
    own_now: impl FnOnce() -> std::time::Instant,
    machine_now: impl FnOnce() -> u64,
) -> Resumed {
    use crate::helper::Standing;

    let Some(marker) = marker else {
        return Resumed::At(started);
    };
    let now = own_now();
    match marker.standing(machine_now()) {
        None => Resumed::At(started),
        Some(Standing::Passed) => Resumed::Passed,
        Some(Standing::Left(left)) => {
            let spent = HOOK_DEADLINE.saturating_sub(left);
            Resumed::At(now.checked_sub(spent).unwrap_or(started))
        }
    }
}

/// One run: the work, the answer, and the diagnostic, with what writes each given.
///
/// The work runs on its own thread so the deadline is kept whatever it is waiting on. When the
/// deadline passes the answer is written and the process ends, which ends that thread too. The
/// wait ends the deadline after the hook's own start, not after the thread started. A system that
/// will not start the thread is a run that could not do its work: it is answered at once.
///
/// The application waits for the answer, and a standard error nobody reads can hold a write to it
/// for as long as nobody reads it. So the answer goes first, and the diagnostic, if there is one,
/// gets what remains of the deadline, and at least [`DIAGNOSTIC_ALLOWANCE`] after the answer
/// ([`diagnostic_bound`]). A run whose work finished says nothing. `claim` is what a run does first
/// of all to be the one that answers, `answer` and `write` are what writes each, and `run` passes
/// the real ones. `now` is the clock that the moment of the answer is read from, and `wait` waits
/// for a message until the moment it is given: `run` passes the system's. The work and the claim
/// read their own clocks.
fn run_with(
    started: std::time::Instant,
    work: impl FnOnce(std::time::Instant) -> Result<(), String> + Send + 'static,
    claim: impl FnOnce(),
    answer: impl FnOnce(),
    write: impl FnOnce(&[u8]) + Send + 'static,
    now: impl Fn() -> std::time::Instant,
    wait: impl Fn(
        &std::sync::mpsc::Receiver<crate::Done>,
        std::time::Instant,
    ) -> Result<crate::Done, std::sync::mpsc::RecvTimeoutError>,
) {
    let (finished, outcome) = std::sync::mpsc::channel();
    let working = std::thread::Builder::new().spawn(move || {
        let _ = finished.send(work(started));
    });
    let failure = match working {
        Err(error) => Some(format!("the hook's work could not be started: {error}")),
        Ok(_) => match wait(&outcome, started + HOOK_DEADLINE) {
            Ok(Ok(())) => None,
            Ok(Err(failure)) => Some(failure),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Some(deadline_diagnostic()),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Some("the hook's work ended without saying how".to_owned())
            }
        },
    };
    // A forwarder being started in this one's place is waited for, and one not yet started is not
    // started once the answer is out: only one process answers.
    claim();
    answer();
    let answered = now();
    if let Some(failure) = failure {
        let answered_after = answered.saturating_duration_since(started);
        crate::report_with(
            &format!(
                "{failure} (answered after {} ms)",
                answered_after.as_millis()
            ),
            diagnostic_bound(started, answered),
            write,
            wait,
        );
    }
}

/// The moment a run stops waiting for its diagnostic to be written, given when it started and when
/// its answer was written: the deadline, or the allowance after the answer when that is later.
///
/// The run ends no later than this, whatever standard error does, so it is also the latest a run
/// that answered no later than its deadline ends: [`HOOK_DEADLINE`] plus [`DIAGNOSTIC_ALLOWANCE`]
/// after its start.
#[must_use]
pub fn diagnostic_bound(
    started: std::time::Instant,
    answered: std::time::Instant,
) -> std::time::Instant {
    (started + HOOK_DEADLINE).max(answered + DIAGNOSTIC_ALLOWANCE)
}

/// What a run says when it answered because [`HOOK_DEADLINE`] passed before its observation was
/// through.
///
/// It is the one place the words are written, so that a reader of a run's standard error asks
/// [`ran_out_of_its_deadline`] and is never left to match them.
#[must_use]
pub fn deadline_diagnostic() -> String {
    format!(
        "the hook did not finish within {} ms, and answered anyway",
        HOOK_DEADLINE.as_millis()
    )
}

/// Whether `diagnostic`, what a run wrote to standard error, says that the run answered because
/// its time ran out, and not because of anything else that went wrong: its deadline passed before
/// its observation was through, or the worker did not admit it inside the same length of time.
/// Which of the two ends a run whose worker is silent is up to which clock is read first.
#[must_use]
pub fn ran_out_of_its_deadline(diagnostic: &str) -> bool {
    [
        deadline_diagnostic(),
        crate::exchange::ExchangeError::TimedOut.to_string(),
    ]
    .iter()
    .any(|words| diagnostic.contains(words.as_str()))
}

/// How long a run says it had run, on its own clock from its start, when its answer was written,
/// if `diagnostic` is what a run writes to standard error about why it answered as it did, and
/// `None` for anything else.
///
/// A run that needed nothing from its deadline and had nothing to say writes no diagnostic.
#[must_use]
pub fn answered_after(diagnostic: &str) -> Option<Duration> {
    let (_, after) = diagnostic.trim_end().rsplit_once(" (answered after ")?;
    let milliseconds = after.strip_suffix(" ms)")?.parse().ok()?;
    Some(Duration::from_millis(milliseconds))
}

/// Takes the hold on the hook's release, then reads the event the application wrote and, inside a
/// launch, reaches the worker with it.
///
/// The hold is taken here, inside the deadline. An update that moves the release holds its manifest
/// for as long as half a minute, and a program of the release waits for it, which no application
/// gives a hook: past the deadline the answer is written without the hold, and the process ends. A
/// hook of a release that is being removed does none of its work and says why on standard error.
///
/// The observation goes straight behind the hello. The worker reads nothing past the hello until
/// it has admitted the connection, and then reads the observation, applies it and closes the
/// connection. This waits for that close, so an observation that selects a thread has been applied
/// before the hook returns to the application, which may hold a session's first response until
/// its session-start hooks have finished. A thread's report is then held until
/// [`THREAD_REPORT_LINGER`] after `started`.
fn observe(application: &Application, started: std::time::Instant) -> Result<(), String> {
    let held = kr_ipc::install::this_process()
        .map(|_| ())
        .map_err(|error| error.to_string());
    // Before the input is read: the forwarder of the worker's own release is given it. It is a
    // reason to go on directly when that one cannot be started.
    #[cfg(unix)]
    if held.is_ok() {
        let _ = crate::helper::hand_over(REGISTRATION_WAIT, Some((started, HOOK_DEADLINE)));
    }
    // However the run ends from here on, the application's write of its input completes: what
    // ends the run without a report reads the input to its end first.
    let mut stdin = std::io::stdin().lock();
    if let Err(error) = held {
        return end_unreported(&mut stdin, error);
    }
    // Outside a launch there is nobody to tell, and the answer is the same neutral one.
    let Some(paths) = Paths::from_environment() else {
        return drain_input(&mut stdin);
    };
    // The registration comes first: the events the launch's package declares decide how the input
    // is read.
    let registration = match Registration::read(&paths, REGISTRATION_WAIT) {
        Ok(registration) => registration,
        Err(error) => return end_unreported(&mut stdin, error.to_string()),
    };
    let Some(input) = read_input(&mut stdin, &registration.events)? else {
        return Ok(());
    };
    let Some(observation) = observation(&registration.events, &input) else {
        return Ok(());
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("the hook could not start: {error}"))?;
    runtime
        .block_on(async {
            let mut exchange = Exchange::open(&registration, application.bridge()).await?;
            deliver(&mut exchange, &observation).await
        })
        .map_err(|error| error.to_string())?;
    if reports_thread(&registration.events, &input) {
        std::thread::sleep(THREAD_REPORT_LINGER.saturating_sub(started.elapsed()));
    }
    Ok(())
}

/// Reads a hook's input to its end, bounded by [`MAX_HOOK_INPUT_BYTES`], and parses none of it.
///
/// A run that reports nothing says nothing about its input either, however the application wrote
/// it, and an application's write of a large input does not complete until it is read.
///
/// # Errors
///
/// Returns what went wrong reading standard input.
fn drain_input(input: impl std::io::Read) -> Result<(), String> {
    std::io::copy(&mut input.take(MAX_HOOK_INPUT_BYTES), &mut std::io::sink())
        .map(|_| ())
        .map_err(|error| format!("the hook's input could not be read: {error}"))
}

/// Ends a run that reports nothing and says `why`, once the input is read to its end.
///
/// What went wrong is what the run says; a failure to read the rest of the input has nothing to add
/// to it.
fn end_unreported(input: impl std::io::Read, why: String) -> Result<(), String> {
    let _ = drain_input(input);
    Err(why)
}

/// Delivers one observation over an exchange whose hello has just been written, and waits until the
/// worker has applied it.
///
/// The observation goes straight behind the hello. A worker that refuses the hello closes the
/// connection without reading anything past it, and that close can land before the observation is
/// written, so the write then finds the connection gone. That is the refusal arriving first, not a
/// failure of the write's own: what the worker answered is read before the write's outcome counts,
/// so a refusal is reported as one, and a write that failed on a connection the worker admitted is
/// still reported as the failure it is.
async fn deliver(
    exchange: &mut Exchange,
    observation: &serde_json::Value,
) -> Result<(), crate::exchange::ExchangeError> {
    let sent = exchange.send(observation).await;
    exchange.admitted(HOOK_DEADLINE).await?;
    sent?;
    // The worker closes the connection once it has applied the observation.
    while exchange.receive().await?.is_some() {}
    Ok(())
}

/// Whether the event is one the worker decides the thread by: a session starting or ending.
fn reports_thread(events: &HookEvents, input: &Observed) -> bool {
    events.events.iter().any(|event| {
        event.name == input.event
            && matches!(
                event.report,
                HookReport::SessionStarted | HookReport::SessionEnded
            )
    })
}

/// The name of the contact skill's tool on its server.
const CONTACT_TOOL: &str = "ask_user";

/// What this forwarder read of a hook's input, at the places the launch's hook events name.
///
/// Every application names the session and the event; the rest is read where the event carries
/// it. Everything else in the payload, a tool's whole response included, is skipped as it is read
/// and never held.
#[derive(Debug, Default)]
pub struct Observed {
    /// The session the event happened in, which is the thread KalaReach binds to.
    pub thread: String,
    /// Which event this is.
    pub event: String,
    /// How a session started.
    pub start_source: Option<String>,
    /// Why a session ended.
    pub end_reason: Option<String>,
    /// The tool that ran.
    pub tool_name: Option<String>,
    /// The `request_id` member of the tool's input, where it has a string one.
    pub tool_request_id: Option<String>,
    /// Which notification this is.
    pub notification_kind: Option<String>,
    /// The notification's text.
    pub notification_text: Option<String>,
    /// What each member the contact is named by held, in the order the events declare them.
    pub agreeing: Vec<Option<String>>,
}

/// What one place of a hook's input is read as.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Slot {
    Event,
    Thread,
    StartSource,
    EndReason,
    ToolName,
    NotificationKind,
    NotificationText,
    Agreeing(usize),
    RequestId,
}

/// One member of the input on the way to the places the events name, and what each member below it
/// is.
#[derive(Debug, Default)]
struct Node {
    children: BTreeMap<String, Node>,
    /// What a string at this member is read as; a member that has some has no children.
    slots: Vec<Slot>,
    /// Whether this is the contact tool's input, which is read for one member and skipped when it
    /// is not an object.
    contact_input: bool,
}

impl Node {
    fn insert(&mut self, names: &[&str], slot: Slot) -> &mut Self {
        let mut node = self;
        for name in names {
            node = node.children.entry((*name).to_owned()).or_default();
        }
        node.slots.push(slot);
        node
    }

    /// Whether this member is read only as the contact's request identifier, which is a string
    /// where the tool's input has one and nothing otherwise, never an error, and may be held
    /// twice. A member that the events also read as the event, the session or any other value is
    /// held to that stricter role: what it may hold is what that role takes.
    fn lenient(&self) -> bool {
        !self.slots.is_empty() && self.slots.iter().all(|slot| *slot == Slot::RequestId)
    }

    /// Whether the event is read at this member or below it.
    fn reaches_event(&self) -> bool {
        self.slots.contains(&Slot::Event) || self.children.values().any(Self::reaches_event)
    }

    fn at(&mut self, names: &[&str]) -> &mut Self {
        let mut node = self;
        for name in names {
            node = node.children.entry((*name).to_owned()).or_default();
        }
        node
    }

    /// The tree of the places `events` names. Each place passed the check every reader makes, so
    /// one that holds an index segment is left out.
    fn of(events: &HookEvents) -> Self {
        let mut root = Self::default();
        let mut add = |place: &kr_plugin_sdk::connector::FieldPath, slot| {
            if let Some(names) = place.member_names() {
                root.insert(&names, slot);
            }
        };
        add(&events.event, Slot::Event);
        add(&events.thread, Slot::Thread);
        let details = &events.details;
        for (place, slot) in [
            (&details.start_source, Slot::StartSource),
            (&details.end_reason, Slot::EndReason),
            (&details.tool_name, Slot::ToolName),
            (&details.notification_kind, Slot::NotificationKind),
            (&details.notification_text, Slot::NotificationText),
        ] {
            if let Some(place) = place {
                add(place, slot);
            }
        }
        if let Some(contact) = &events.contact {
            for (index, agreement) in contact.agreeing.iter().enumerate() {
                add(&agreement.place, Slot::Agreeing(index));
            }
            if let Some(mut names) = contact.tool_input.member_names() {
                root.at(&names).contact_input = true;
                names.push(CONTACT_REQUEST_MEMBER);
                root.insert(&names, Slot::RequestId);
            }
        }
        root
    }
}

/// What the read of one input has found.
#[derive(Default)]
struct Reading {
    /// The strings at the places the events name.
    found: BTreeMap<Slot, String>,
    /// The first fault of a member, kept and not raised: an event the map does not name is no
    /// concern of the map's, whatever else its input holds.
    fault: Option<String>,
}

impl Reading {
    fn fault(&mut self, fault: String) {
        self.fault.get_or_insert(fault);
    }
}

/// Reads a hook's input along the tree, holding the strings at the places it names and skipping
/// everything else.
struct Descend<'a> {
    node: &'a Node,
    reading: &'a mut Reading,
}

impl Descend<'_> {
    /// What this member is read as, for what is said of one that holds something else.
    fn expected(&self) -> &'static str {
        if self.node.children.is_empty() {
            "a string"
        } else {
            "a hook's input"
        }
    }

    /// A member that holds `held`, where `self.expected()` is read.
    fn wrong(&mut self, held: &str) {
        let fault = format!("a member holds {held}, where {} is read", self.expected());
        self.reading.fault(fault);
    }

    /// A value that is not a string. A member that is only the contact's request identifier takes
    /// it as no value, and so does the contact tool's input, which is read for one member and
    /// skipped when it is not an object; every other place the events name refuses it.
    fn not_a_string(mut self, held: &str) {
        if self.node.lenient() {
            self.reading.found.remove(&Slot::RequestId);
        } else if !self.node.contact_input {
            self.wrong(held);
        }
    }
}

impl<'de> DeserializeSeed<'de> for Descend<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Descend<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.expected())
    }

    fn visit_map<A>(mut self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.node.children.is_empty() {
            // A member read as a string, holding an object.
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            self.not_a_string("an object");
            return Ok(());
        }
        let mut seen: Vec<String> = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            let Some(child) = self.node.children.get(&key) else {
                map.next_value::<IgnoredAny>()?;
                continue;
            };
            if !child.lenient() && seen.contains(&key) {
                let fault = format!("`{key}` is held twice");
                // Which of two events the input names cannot be told.
                if child.reaches_event() {
                    return Err(A::Error::custom(fault));
                }
                self.reading.fault(fault);
            }
            seen.push(key);
            map.next_value_seed(Descend {
                node: child,
                reading: &mut *self.reading,
            })?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        self.not_a_string("an array");
        Ok(())
    }

    fn visit_str<E>(mut self, value: &str) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        if self.node.slots.is_empty() {
            // A member the events read below it, holding a string.
            if !self.node.contact_input {
                self.wrong("a string");
            }
            return Ok(());
        }
        for slot in &self.node.slots {
            self.reading.found.insert(*slot, value.to_owned());
        }
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        self.not_a_string("a boolean");
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        self.not_a_string("a number");
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        self.not_a_string("a number");
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        self.not_a_string("a number");
        Ok(())
    }

    fn visit_unit<E>(mut self) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        if self
            .node
            .slots
            .iter()
            .any(|slot| matches!(slot, Slot::Event | Slot::Thread))
        {
            self.wrong("null");
        } else if self.node.lenient() {
            self.reading.found.remove(&Slot::RequestId);
        }
        Ok(())
    }
}

/// Reads and parses one hook's input at the places `events` names, bounded by
/// [`MAX_HOOK_INPUT_BYTES`], and reads the rest of it however the read ends, so an application's
/// write of a large input completes.
///
/// A member the events do not name is skipped as it is read. A member they name is a string, or
/// null where it is optional, or absent. `None` is an event the events do not name: it reports
/// nothing and is no fault, whatever else its input holds. An input that is not JSON, an event
/// that is absent, null, not a string or named twice, and, for an event the events name, a session
/// that is absent, null or not a string, a named member of the wrong type or held twice and a
/// named object that is not one are not an event this bridge reads.
///
/// # Errors
///
/// Returns what went wrong for a payload that is not a hook's input or is past the bound.
pub fn read_input(
    input: impl std::io::Read,
    events: &HookEvents,
) -> Result<Option<Observed>, String> {
    let tree = Node::of(events);
    let mut reading = Reading::default();
    let mut reader = std::io::BufReader::new(input.take(MAX_HOOK_INPUT_BYTES));
    let parsed = {
        let mut deserializer = serde_json::Deserializer::from_reader(&mut reader);
        Descend {
            node: &tree,
            reading: &mut reading,
        }
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end())
    };
    let drained = drain_input(&mut reader);
    let refused = |why: &str| format!("the hook's input is not an event this bridge reads: {why}");
    parsed.map_err(|error| refused(&error.to_string()))?;
    drained?;
    let Some(event) = reading.found.remove(&Slot::Event) else {
        return Err(refused(
            reading.fault.as_deref().unwrap_or("it names no event"),
        ));
    };
    if !events.events.iter().any(|named| named.name == event) {
        return Ok(None);
    }
    if let Some(fault) = &reading.fault {
        return Err(refused(fault));
    }
    let Some(thread) = reading.found.remove(&Slot::Thread) else {
        return Err(refused("it names no session"));
    };
    let mut take = |slot| reading.found.remove(&slot);
    Ok(Some(Observed {
        thread,
        event,
        start_source: take(Slot::StartSource),
        end_reason: take(Slot::EndReason),
        tool_name: take(Slot::ToolName),
        tool_request_id: take(Slot::RequestId),
        notification_kind: take(Slot::NotificationKind),
        notification_text: take(Slot::NotificationText),
        agreeing: (0..events
            .contact
            .as_ref()
            .map_or(0, |contact| contact.agreeing.len()))
            .map(|index| take(Slot::Agreeing(index)))
            .collect(),
    }))
}

/// Translates one hook's input into the observation the worker reads, or `None` for an event
/// outside the events' vocabulary, or input that names no thread.
///
/// A session starting or ending selects or ends the thread, and a start the events mark as a
/// continuation goes on in it; a tool finishing or failing and a notification are recorded as
/// observed history. A finished call of the contact skill's `ask_user` also names the request it
/// asked, so the worker learns which thread the question was asked in.
#[must_use]
pub fn observation(events: &HookEvents, input: &Observed) -> Option<serde_json::Value> {
    let event: &HookEvent = events
        .events
        .iter()
        .find(|event| event.name == input.event)?;
    let thread = kr_protocol::ids::AgentThreadId::new(input.thread.clone()).ok()?;
    let (word, detail) = match event.report {
        HookReport::SessionStarted
            if event.continued_by.is_some()
                && event.continued_by.as_deref() == input.start_source.as_deref() =>
        {
            ("thread_continued", input.start_source.as_deref())
        }
        HookReport::SessionStarted => ("thread_started", input.start_source.as_deref()),
        HookReport::SessionEnded => ("thread_ended", input.end_reason.as_deref()),
        HookReport::ToolFinished => ("tool_finished", input.tool_name.as_deref()),
        HookReport::ToolFailed => ("tool_failed", input.tool_name.as_deref()),
        HookReport::Notification => ("notification", input.notification_kind.as_deref()),
    };
    let mut reported = serde_json::Map::new();
    reported.insert("event".to_owned(), serde_json::json!(word));
    reported.insert("thread".to_owned(), serde_json::json!(thread.as_str()));
    if let Some(detail) = detail {
        reported.insert(
            "detail".to_owned(),
            serde_json::json!(bounded(detail, MAX_DETAIL_BYTES)),
        );
    }
    if event.report == HookReport::Notification
        && let Some(message) = &input.notification_text
    {
        reported.insert(
            "text".to_owned(),
            serde_json::json!(bounded(message, MAX_TEXT_BYTES)),
        );
    }
    if event.report == HookReport::ToolFinished
        && let Some(request) = contact_request(events, input)
    {
        reported.insert("contact_request".to_owned(), serde_json::json!(request));
    }
    Some(serde_json::json!({ "kr_observation": reported }))
}

/// The request identifier of the contact skill's `ask_user` call, when this finished tool call was
/// one.
///
/// The events say how the application spells the tool's name, over the two words the host expands:
/// the contact skill's server is registered as [`kr_protocol::skill::SERVER_NAME`]. Where the
/// application also names the server, or the tool on it, every name it gives must agree.
fn contact_request<'a>(events: &HookEvents, input: &'a Observed) -> Option<&'a str> {
    let contact = events.contact.as_ref()?;
    let server = kr_protocol::skill::SERVER_NAME;
    let expected = contact
        .tool_name
        .replace("{server}", server)
        .replace("{tool}", CONTACT_TOOL);
    if input.tool_name.as_deref() != Some(expected.as_str()) {
        return None;
    }
    for (agreement, named) in contact.agreeing.iter().zip(&input.agreeing) {
        let own = match agreement.names {
            kr_plugin_sdk::hook_events::HookAgreed::Server => server,
            kr_plugin_sdk::hook_events::HookAgreed::Tool => CONTACT_TOOL,
        };
        if named.as_deref().is_some_and(|name| name != own) {
            return None;
        }
    }
    input
        .tool_request_id
        .as_deref()
        .filter(|request| !request.trim().is_empty() && request.len() <= MAX_CONTACT_REQUEST_BYTES)
}

/// Cuts text to at most `limit` bytes, at a character boundary.
fn bounded(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Writes the neutral answer and flushes it, so the application has it before anything else the
/// run does.
fn answer() {
    use std::io::Write as _;
    let mut output = std::io::stdout().lock();
    let _ = writeln!(output, "{NEUTRAL_ANSWER}");
    let _ = output.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hook started in place of another has the deadline the application gave the first, counted
    /// on the continuous clock the marker names: what is left of it when it begins is what its own
    /// run is given, a deadline that has ended is passed, and a hook started on its own has all of
    /// it. The clock reading is supplied, so nothing here waits.
    #[cfg(unix)]
    #[test]
    fn a_hook_started_in_place_of_another_has_what_is_left_of_the_deadline() {
        use crate::helper::Marker;

        let started = std::time::Instant::now();
        let marker = |deadline_ms| {
            Some(Marker {
                from: "0.1.0+aaaaaaaaaaaa".to_owned(),
                deadline_ms: Some(deadline_ms),
            })
        };
        // On its own: the whole deadline, from its own start.
        let Resumed::At(own) = resumed_by(started, None, std::time::Instant::now, || 10_000) else {
            panic!("a hook on its own is given its deadline");
        };
        assert_eq!(own, started);
        // A hundred and fifty milliseconds left of five hundred: three hundred and fifty spent.
        let Resumed::At(began) =
            resumed_by(started, marker(10_150), std::time::Instant::now, || 10_000)
        else {
            panic!("a hook with time left is given it");
        };
        let spent = std::time::Instant::now().saturating_duration_since(began);
        assert!(
            spent >= HOOK_DEADLINE - Duration::from_millis(150),
            "{spent:?} of the deadline counts as spent"
        );
        assert!(HOOK_DEADLINE.saturating_sub(spent) <= Duration::from_millis(150));
        // The deadline ended, exactly and before.
        assert!(matches!(
            resumed_by(started, marker(10_000), std::time::Instant::now, || 10_000),
            Resumed::Passed
        ));
        assert!(matches!(
            resumed_by(started, marker(9_000), std::time::Instant::now, || 10_000),
            Resumed::Passed
        ));
        // A marker with no deadline, as a channel's, leaves the hook's own start.
        let channel = Some(Marker {
            from: "0.1.0+aaaaaaaaaaaa".to_owned(),
            deadline_ms: None,
        });
        assert!(matches!(
            resumed_by(started, channel, std::time::Instant::now, || 10_000),
            Resumed::At(at) if at == started
        ));
    }

    /// A run claims its answer before it writes it, so a forwarder that has not yet been started in
    /// its place is not started afterwards.
    #[cfg(unix)]
    #[test]
    fn a_run_claims_its_answer_before_it_writes_it() {
        let order = std::cell::RefCell::new(Vec::new());
        run_with(
            std::time::Instant::now(),
            |_| Ok(()),
            || order.borrow_mut().push("claimed"),
            || order.borrow_mut().push("answered"),
            |_| {},
            std::time::Instant::now,
            crate::wait_by,
        );
        assert_eq!(*order.borrow(), ["claimed", "answered"]);
    }

    /// The hook's own clock is read before the machine's, so a pause between the two readings
    /// shortens what a hook started in place of another is given, and neither is read for a hook
    /// started on its own.
    #[cfg(unix)]
    #[test]
    fn a_hook_started_in_place_of_another_reads_its_own_clock_before_the_machines() {
        use crate::helper::Marker;
        use std::cell::RefCell;

        let started = std::time::Instant::now();
        let readings = RefCell::new(Vec::new());
        let marker = Some(Marker {
            from: "0.1.0+aaaaaaaaaaaa".to_owned(),
            deadline_ms: Some(10_150),
        });
        let _ = resumed_by(
            started,
            marker,
            || {
                readings.borrow_mut().push("own");
                std::time::Instant::now()
            },
            || {
                readings.borrow_mut().push("machine");
                10_000
            },
        );
        assert_eq!(*readings.borrow(), ["own", "machine"]);

        readings.borrow_mut().clear();
        let _ = resumed_by(
            started,
            None,
            || {
                readings.borrow_mut().push("own");
                std::time::Instant::now()
            },
            || {
                readings.borrow_mut().push("machine");
                10_000
            },
        );
        assert!(readings.borrow().is_empty());
    }

    /// A run waits for its diagnostic no later than its deadline, or the allowance after an answer
    /// that came later, and in either case no later than the deadline and the allowance after the
    /// run's start: the whole of what a standard error nobody reads could hold it.
    #[test]
    fn a_run_waits_for_its_diagnostic_no_later_than_the_deadline_and_the_allowance_after_its_start()
    {
        let started = std::time::Instant::now();
        for after in [0, 1, 250, 499, 500].map(Duration::from_millis) {
            let bound = diagnostic_bound(started, started + after);
            assert!(bound >= started + HOOK_DEADLINE);
            assert!(bound >= started + after + DIAGNOSTIC_ALLOWANCE);
            assert!(
                bound <= started + HOOK_DEADLINE + DIAGNOSTIC_ALLOWANCE,
                "answered after {after:?}: {:?}",
                bound.duration_since(started)
            );
        }
    }

    /// The timeout a session ending is given, the shortest any registration names.
    const SESSION_END_TIMEOUT: Duration = Duration::from_secs(1);

    /// How many runs a test starts, one after another, to have one whose work reported before the
    /// deadline.
    const ATTEMPTS: usize = 30;

    /// How long a test waits for the writer of a line a run handed it. The run does not wait that
    /// long: the figure only ends a writer that never finishes.
    const HUNG_WRITER: Duration = Duration::from_secs(30);

    /// What one run did when its work reported at once.
    struct Immediate {
        answered: bool,
        /// The whole of what the run handed its writer for standard error, as text, however late
        /// that writer ran: empty when the run handed it nothing.
        said: String,
        /// How long the call took, from the run's start to its return.
        ran_for: Duration,
    }

    /// Runs `run_with` once with work that reports `outcome` at once, and returns what it did.
    ///
    /// The work is on a thread of its own, as in a run, and a machine that keeps it off the
    /// processor past the deadline makes the run answer at its deadline instead: such a run says
    /// so, and shows nothing about the branch the caller is after. A run does not wait for its
    /// writer past its bound, so the writer says when it has written: the line is read once it
    /// has, and a run that handed the writer nothing is the one whose writer was never given a
    /// line.
    fn immediate(outcome: Result<(), String>) -> Immediate {
        let said = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let into = std::sync::Arc::clone(&said);
        let (written, line) = std::sync::mpsc::channel::<()>();
        let started = std::time::Instant::now();
        let mut answered = false;
        run_with(
            started,
            move |_| outcome,
            || {},
            || answered = true,
            move |bytes| {
                into.lock().expect("the line").extend_from_slice(bytes);
                let _ = written.send(());
            },
            std::time::Instant::now,
            crate::wait_by,
        );
        let ran_for = started.elapsed();
        assert!(
            line.recv_timeout(HUNG_WRITER) != Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            "the writer of the line the run handed it never finished"
        );
        let said = String::from_utf8_lossy(&said.lock().expect("the line")).into_owned();
        Immediate {
            answered,
            said,
            ran_for,
        }
    }

    /// A run that finishes its work answers and says nothing, inside the one-second timeout a
    /// session ending is given, by the run's own clock: from its start to the end of the call, so
    /// what the machine takes to start the process and to let it end is not in it.
    #[test]
    fn a_run_whose_work_finishes_answers_inside_the_session_end_timeout_and_says_nothing() {
        let mut last = String::new();
        for _ in 0..ATTEMPTS {
            let ran = immediate(Ok(()));
            assert!(ran.answered, "the answer is written");
            if ran_out_of_its_deadline(&ran.said) {
                // The work thread was kept off the processor for the whole deadline.
                last = ran.said;
                continue;
            }
            assert_eq!(ran.said, "", "a diagnostic was written");
            assert!(
                ran.ran_for < SESSION_END_TIMEOUT,
                "a run whose work finished was through inside the one-second timeout: {:?}",
                ran.ran_for
            );
            return;
        }
        panic!(
            "no run of {ATTEMPTS} had its work report before its deadline; the last said {last:?}"
        );
    }

    /// A run whose work never finishes, with a standard error nobody reads, is held by neither,
    /// on the system's clock and with the system's wait: the work waits for ever, the diagnostic's
    /// write stalls, and the run answers no earlier than the deadline, waits at least the allowance
    /// after its answer for the line, and is through while the work and the write are both still
    /// stalled. That the waits it asks for end by its bound and no later is held by the cases that
    /// give it a clock of their own and, for the system's wait, by the text of `wait_by`. The bound
    /// the run sets itself, the deadline and the allowance after
    /// the run's start, is inside the one-second timeout a session ending is given. How soon after
    /// its bound the machine lets a run end is the machine's: it is not held against the run.
    #[test]
    fn a_run_that_waits_for_ever_and_whose_diagnostic_nobody_reads_is_through_while_both_still_wait()
     {
        let (release_work, stalled_work) = std::sync::mpsc::channel::<()>();
        let (release_write, stalled_write) = std::sync::mpsc::channel::<()>();
        let work_ended = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let write_ended = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let work_ends = std::sync::Arc::clone(&work_ended);
        let write_ends = std::sync::Arc::clone(&write_ended);
        let started = std::time::Instant::now();
        let mut answered_at = None;
        run_with(
            started,
            move |_| {
                // Waits until the test lets it go, which is after the run is through.
                let _ = stalled_work.recv_timeout(HUNG_WRITER);
                work_ends.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
            || {},
            || answered_at = Some(std::time::Instant::now()),
            move |_| {
                // The write stalls too, until the test lets it go.
                let _ = stalled_write.recv_timeout(HUNG_WRITER);
                write_ends.store(true, std::sync::atomic::Ordering::SeqCst);
            },
            std::time::Instant::now,
            crate::wait_by,
        );
        let through = std::time::Instant::now();
        let work_had_ended = work_ended.load(std::sync::atomic::Ordering::SeqCst);
        let write_had_ended = write_ended.load(std::sync::atomic::Ordering::SeqCst);
        drop(release_work);
        drop(release_write);
        let answered_at = answered_at.expect("the answer is written");
        assert!(
            answered_at >= started + HOOK_DEADLINE,
            "work that never finishes is answered no earlier than the deadline"
        );
        assert!(
            through >= answered_at + DIAGNOSTIC_ALLOWANCE,
            "it waited the allowance for the line"
        );
        assert!(
            !work_had_ended,
            "it was through while its work was stalled, not when the work ended"
        );
        assert!(
            !write_had_ended,
            "it was through while the write was stalled, not when the write ended"
        );
        assert!(
            HOOK_DEADLINE + DIAGNOSTIC_ALLOWANCE < SESSION_END_TIMEOUT,
            "the bound is inside the one-second timeout of a session ending"
        );
    }

    /// How a run's work goes, for the cases that give a run a clock of their own.
    #[derive(Clone, Copy)]
    enum Work {
        /// It never says anything: the run waits for it until its deadline.
        NeverAnswers,
        /// It fails at once.
        FailsAtOnce,
    }

    /// How the write of a run's diagnostic goes.
    #[derive(Clone, Copy)]
    enum Write {
        /// It never finishes.
        Stalls,
        /// It finishes at once.
        Finishes,
    }

    /// What takes time on the made clock besides the waits of a run.
    #[derive(Clone, Copy, Default)]
    struct Takes {
        /// How far the clock has moved before the run begins to wait, as when the arguments are
        /// parsed or the deadline of a hook that was replaced is read.
        before: Duration,
        /// The claim.
        claim: Duration,
        /// The write of the answer.
        answer: Duration,
    }

    /// What one run did on a clock that a case moves, as how long after the run's start.
    struct OnMade {
        ended: Duration,
        answered: Duration,
        /// Every moment its waits were asked to wait until.
        asked: Vec<Duration>,
        work_ended: bool,
        write_ended: bool,
    }

    /// Runs `run_with` once on a clock that stands still until a wait runs out or something in
    /// `takes` passes time, with `work` and `write` going as given. A wait that is not given a
    /// message moves the clock to the moment it was asked to wait until, so what a run waits is
    /// read off the clock; a stalled thread waits for the case to let it go, which is after the run.
    /// The real waits are the receive of a wait that is given a message, which ends when the message
    /// comes, and the guards that end a stalled thread of a case that has a fault.
    fn on_made_clock(work: Work, write: Write, takes: Takes) -> OnMade {
        use crate::made::{Made, Wait};
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        use std::sync::{Arc, mpsc};

        let made = Made::new([
            match work {
                Work::NeverAnswers => Wait::RunsOut,
                Work::FailsAtOnce => Wait::Message,
            },
            match write {
                Write::Stalls => Wait::RunsOut,
                Write::Finishes => Wait::Message,
            },
        ]);
        let (release_work, stalled_work) = mpsc::channel::<()>();
        let (release_write, stalled_write) = mpsc::channel::<()>();
        let work_ended = Arc::new(AtomicBool::new(false));
        let write_ended = Arc::new(AtomicBool::new(false));
        let (work_ends, write_ends) = (Arc::clone(&work_ended), Arc::clone(&write_ended));
        let answered = std::cell::Cell::new(None);
        made.pass(takes.before);
        run_with(
            made.start(),
            move |_| match work {
                Work::NeverAnswers => {
                    // Waits until the case lets it go, which is after the run is through.
                    let _ = stalled_work.recv_timeout(HUNG_WRITER);
                    work_ends.store(true, SeqCst);
                    Ok(())
                }
                Work::FailsAtOnce => Err("the input was not an event".to_owned()),
            },
            || made.pass(takes.claim),
            || {
                made.pass(takes.answer);
                answered.set(Some(made.passed()));
            },
            move |_| {
                if matches!(write, Write::Stalls) {
                    // The write stalls too, until the case lets it go.
                    let _ = stalled_write.recv_timeout(HUNG_WRITER);
                }
                write_ends.store(true, SeqCst);
            },
            || made.now(),
            |channel, by| made.wait(channel, by),
        );
        let ran = OnMade {
            ended: made.passed(),
            answered: answered.get().expect("the answer is written"),
            asked: made.asked(),
            work_ended: work_ended.load(SeqCst),
            write_ended: write_ended.load(SeqCst),
        };
        drop(release_work);
        drop(release_write);
        ran
    }

    /// What every run holds, whatever stalls: no wait it makes is asked to last past its bound,
    /// which is the deadline, or the allowance after its answer when that came later; it is through
    /// by then; it is through at its bound when the write stalls, or at its answer when the write
    /// finishes; and a thread that stalled is still stalled when the run is through.
    fn assert_held_to_its_bound(ran: &OnMade, work: Work, write: Write) {
        let bound = HOOK_DEADLINE.max(ran.answered + DIAGNOSTIC_ALLOWANCE);
        assert!(
            ran.asked.iter().all(|until| *until <= bound),
            "a wait was asked to last past the bound {bound:?}: {:?}",
            ran.asked
        );
        assert!(
            ran.ended <= bound,
            "the run ended at {:?}, past {bound:?}",
            ran.ended
        );
        match write {
            Write::Stalls => {
                assert_eq!(
                    ran.ended, bound,
                    "a stalled write holds the run to its bound"
                );
                assert!(
                    !ran.write_ended,
                    "it was through while the write was stalled"
                );
            }
            Write::Finishes => {
                assert_eq!(
                    ran.ended, ran.answered,
                    "a write that finished holds nothing"
                );
            }
        }
        if matches!(work, Work::NeverAnswers) {
            assert!(!ran.work_ended, "it was through while its work was stalled");
            assert!(
                ran.answered >= HOOK_DEADLINE,
                "work that never finishes is answered no earlier than the deadline"
            );
        }
    }

    /// Work that never answers holds a run to its deadline, and no longer when the diagnostic is
    /// written at once.
    #[test]
    fn a_run_whose_work_never_answers_is_through_at_the_deadline() {
        let ran = on_made_clock(Work::NeverAnswers, Write::Finishes, Takes::default());
        assert_held_to_its_bound(&ran, Work::NeverAnswers, Write::Finishes);
        assert_eq!(ran.ended, HOOK_DEADLINE);
    }

    /// A diagnostic whose write stalls holds a run whose work failed at once until the deadline:
    /// the allowance after an answer that early ends before it.
    #[test]
    fn a_run_whose_diagnostic_write_stalls_is_through_at_the_deadline() {
        let ran = on_made_clock(Work::FailsAtOnce, Write::Stalls, Takes::default());
        assert_held_to_its_bound(&ran, Work::FailsAtOnce, Write::Stalls);
        assert_eq!(ran.ended, HOOK_DEADLINE);
    }

    /// Work that never answers and a write that stalls hold a run to the deadline and the allowance
    /// after its start, and no longer.
    #[test]
    fn a_run_whose_work_never_answers_and_whose_write_stalls_is_through_at_the_deadline_and_the_allowance()
     {
        let ran = on_made_clock(Work::NeverAnswers, Write::Stalls, Takes::default());
        assert_held_to_its_bound(&ran, Work::NeverAnswers, Write::Stalls);
        assert_eq!(ran.ended, HOOK_DEADLINE + DIAGNOSTIC_ALLOWANCE);
    }

    /// A run whose thread began to wait after its start is asked to wait until its deadline from
    /// its start, and not from the moment it began to wait.
    #[test]
    fn a_run_that_began_to_wait_after_its_start_is_asked_to_wait_until_the_deadline_from_its_start()
    {
        let takes = Takes {
            before: Duration::from_millis(40),
            ..Takes::default()
        };
        for write in [Write::Stalls, Write::Finishes] {
            let ran = on_made_clock(Work::NeverAnswers, write, takes);
            assert_held_to_its_bound(&ran, Work::NeverAnswers, write);
            assert_eq!(
                ran.asked[0], HOOK_DEADLINE,
                "the work's wait is asked until"
            );
            let ran = on_made_clock(Work::FailsAtOnce, write, takes);
            assert_held_to_its_bound(&ran, Work::FailsAtOnce, write);
            assert_eq!(ran.answered, takes.before, "the answer follows the start");
        }
    }

    /// The write of an answer takes time, and the allowance counts from when it was through: the
    /// run is through at the allowance after that, and no later.
    #[test]
    fn a_run_whose_answer_takes_time_is_through_at_the_allowance_after_it_and_no_later() {
        let takes = Takes {
            answer: Duration::from_millis(20),
            ..Takes::default()
        };
        let ran = on_made_clock(Work::NeverAnswers, Write::Stalls, takes);
        assert_held_to_its_bound(&ran, Work::NeverAnswers, Write::Stalls);
        assert_eq!(
            ran.ended,
            HOOK_DEADLINE + takes.answer + DIAGNOSTIC_ALLOWANCE,
            "the allowance counts from the answer's end"
        );
    }

    /// A claim that comes late moves the answer, and with it the bound: when the write stalls the
    /// run is through at the allowance after its answer, or at the deadline when that is later,
    /// and when the write finishes it is through at its answer, whichever way its work goes.
    #[test]
    fn a_run_whose_claim_comes_late_is_through_at_its_bound_and_no_later() {
        for claim in [100, 300, 450].map(Duration::from_millis) {
            for work in [Work::NeverAnswers, Work::FailsAtOnce] {
                for write in [Write::Stalls, Write::Finishes] {
                    let takes = Takes {
                        claim,
                        ..Takes::default()
                    };
                    let ran = on_made_clock(work, write, takes);
                    assert_held_to_its_bound(&ran, work, write);
                    let work_waited = match work {
                        Work::NeverAnswers => HOOK_DEADLINE,
                        Work::FailsAtOnce => Duration::ZERO,
                    };
                    assert_eq!(
                        ran.answered,
                        work_waited + claim,
                        "the answer follows the claim"
                    );
                }
            }
        }
    }

    /// The waits that a run whose worker is silent asks for add up to less than the one-second
    /// timeout a session ending is given: its deadline, what its claim waits for a replacement
    /// that is starting in its place (on Unix, where a launch is handed over), and the allowance
    /// after its answer. That sum is 700 ms on Unix and 600 ms on Windows, which has no claim to
    /// wait for: 300 ms and 400 ms inside the timeout. The clock is made, so the sum is of what the
    /// run asks to wait and not of the time a machine takes: on the system's clock each wake-up
    /// can come later, and that is the machine's.
    #[test]
    fn the_waits_of_a_run_whose_worker_is_silent_add_up_to_less_than_the_session_end_timeout() {
        #[cfg(unix)]
        let claim = crate::helper::CLAIM_WAIT;
        #[cfg(not(unix))]
        let claim = Duration::ZERO;
        let takes = Takes {
            claim,
            ..Takes::default()
        };
        let longest = Duration::from_millis(if cfg!(unix) { 700 } else { 600 });
        for write in [Write::Stalls, Write::Finishes] {
            let ran = on_made_clock(Work::NeverAnswers, write, takes);
            assert_held_to_its_bound(&ran, Work::NeverAnswers, write);
            assert!(
                ran.ended < SESSION_END_TIMEOUT,
                "the waits add up to {:?}, past the {SESSION_END_TIMEOUT:?} timeout",
                ran.ended
            );
            if matches!(write, Write::Stalls) {
                assert_eq!(ran.ended, longest, "the most a run waits");
            }
        }
    }

    /// A run whose work failed says why, with how long it had run when its answer was written.
    #[test]
    fn a_run_whose_work_failed_says_why_and_when_it_answered() {
        let mut last = String::new();
        for _ in 0..ATTEMPTS {
            let ran = immediate(Err("the input was not an event".to_owned()));
            assert!(ran.answered, "the answer is written");
            if ran_out_of_its_deadline(&ran.said) {
                // The work thread was kept off the processor for the whole deadline.
                last = ran.said;
                continue;
            }
            assert!(
                ran.said.starts_with("kr-hook: the input was not an event"),
                "{:?}",
                ran.said
            );
            assert!(
                answered_after(&ran.said).is_some_and(|after| after < SESSION_END_TIMEOUT),
                "{:?}",
                ran.said
            );
            assert!(
                ran.ran_for < SESSION_END_TIMEOUT,
                "a run whose work failed was through inside the one-second timeout: {:?}",
                ran.ran_for
            );
            return;
        }
        panic!(
            "no run of {ATTEMPTS} had its work fail before its deadline; the last said {last:?}"
        );
    }

    /// The three package words that exist today, which these tests use.
    fn every() -> [Application; 3] {
        ["claude-code", "gemini-cli", "qoder-cli"].map(Application::for_word)
    }

    fn translated(events: &HookEvents, payload: &serde_json::Value) -> Option<serde_json::Value> {
        let input = read_input(payload.to_string().as_bytes(), events).expect("a hook's input")?;
        observation(events, &input).map(|frame| frame["kr_observation"].clone())
    }

    /// Claude Code's events with only `events` mapped, and its contact and places as they are.
    fn mapping(events: &[(&str, HookReport, Option<&str>)]) -> HookEvents {
        HookEvents {
            events: events
                .iter()
                .map(|(name, report, continued_by)| HookEvent {
                    name: (*name).to_owned(),
                    report: *report,
                    continued_by: continued_by.map(str::to_owned),
                })
                .collect(),
            ..HookEvents::claude_code()
        }
    }

    /// Each application declares itself under its own name, as the `hook` surface, and holds each
    /// event of the vocabulary once.
    #[test]
    fn each_application_declares_its_own_hook_bridge() {
        let every = every();
        let names: Vec<&str> = every
            .iter()
            .map(|application| application.name.as_ref())
            .collect();
        assert_eq!(names, ["claude-code", "gemini-cli", "qoder-cli"]);
        for application in &every {
            assert_eq!(application.bridge().application, application.name);
            assert_eq!(application.bridge().surface, "hook");
            let defaults = HookEvents::claude_code();
            let mut events: Vec<&str> = defaults
                .events
                .iter()
                .map(|event| event.name.as_str())
                .collect();
            let registered = events.len();
            events.sort_unstable();
            events.dedup();
            assert_eq!(events.len(), registered, "{}", application.name);
        }
    }

    /// Only a session starting or ending is held back, and never past the deadline, for every
    /// application.
    #[test]
    fn a_thread_report_is_held_two_ticks_and_inside_the_deadline() {
        assert!(THREAD_REPORT_LINGER < HOOK_DEADLINE);
        for application in &every() {
            let events = HookEvents::claude_code();
            for HookEvent {
                name: event,
                report,
                ..
            } in &events.events
            {
                let input = read_input(
                    serde_json::json!({"session_id": "t", "hook_event_name": event})
                        .to_string()
                        .as_bytes(),
                    &events,
                )
                .expect("a hook's input")
                .expect("an event the map names");
                assert_eq!(
                    reports_thread(&events, &input),
                    matches!(
                        report,
                        HookReport::SessionStarted | HookReport::SessionEnded
                    ),
                    "{} {event}",
                    application.name
                );
            }
        }
    }

    /// A start is a continuation only where the application names the source that makes one, and
    /// only from that source.
    #[test]
    fn a_continuation_is_the_named_source_and_nothing_else() {
        let without = mapping(&[("SessionStart", HookReport::SessionStarted, None)]);
        let with = mapping(&[("SessionStart", HookReport::SessionStarted, Some("compact"))]);
        for (application, name, source, event) in [
            (&without, "no-continuation", "compact", "thread_started"),
            (&with, "continuation", "compact", "thread_continued"),
            (&with, "continuation", "Compact", "thread_started"),
            (&with, "continuation", "resume", "thread_started"),
        ] {
            let reported = translated(
                application,
                &serde_json::json!({"session_id": "s", "hook_event_name": "SessionStart", "source": source}),
            )
            .expect("an observation");
            assert_eq!(reported["event"], event, "{name} {source}");
        }
    }

    /// A finished `ask_user` call of the contact skill names its request only when every name the
    /// application gives for the server and the tool agrees, whether it names the server as Claude
    /// Code does or as Qoder CLI does.
    #[test]
    fn a_contact_request_is_named_only_when_every_name_agrees() {
        let finished = mapping(&[("PostToolUse", HookReport::ToolFinished, None)]);
        let asked = |tool: &str, extra: serde_json::Value| {
            let mut payload = serde_json::json!({"session_id": "s", "hook_event_name": "PostToolUse",
                "tool_name": tool, "tool_input": {"request_id": "r-7f3a", "question": "which?"}});
            for (key, value) in extra.as_object().expect("members") {
                payload[key] = value.clone();
            }
            translated(&finished, &payload).expect("an observation")["contact_request"].clone()
        };
        for extra in [
            serde_json::json!({}),
            serde_json::json!({"mcp_server": {"name": "kalareach"}}),
            serde_json::json!({"mcp_context": {"server_name": "kalareach", "tool_name": "ask_user"}}),
            serde_json::json!({"mcp_context": {"server_name": "kalareach"}}),
            serde_json::json!({"mcp_server": {"name": "kalareach"},
                "mcp_context": {"server_name": "kalareach", "tool_name": "ask_user"}}),
        ] {
            assert_eq!(
                asked("mcp__kalareach__ask_user", extra.clone()),
                "r-7f3a",
                "{extra}"
            );
        }
        for (tool, extra) in [
            (
                "mcp__kalareach__ask_user",
                serde_json::json!({"mcp_server": {"name": "elsewhere"}}),
            ),
            (
                "mcp__kalareach__ask_user",
                serde_json::json!({"mcp_context": {"server_name": "elsewhere", "tool_name": "ask_user"}}),
            ),
            (
                "mcp__kalareach__ask_user",
                serde_json::json!({"mcp_context": {"server_name": "kalareach", "tool_name": "wait_for_answer"}}),
            ),
            (
                "mcp__kalareach__ask_user",
                serde_json::json!({"mcp_server": {"name": "kalareach"},
                    "mcp_context": {"server_name": "elsewhere"}}),
            ),
            ("mcp_kalareach_ask_user", serde_json::json!({})),
            ("mcp__other__ask_user", serde_json::json!({})),
        ] {
            assert!(asked(tool, extra.clone()).is_null(), "{tool} {extra}");
        }
    }

    #[test]
    fn long_text_is_cut_at_a_character_boundary() {
        let notified = mapping(&[("Notification", HookReport::Notification, None)]);
        let message = format!("{}{}", "x".repeat(MAX_TEXT_BYTES - 1), "\u{00e9}");
        let payload = serde_json::json!({"session_id": "s", "hook_event_name": "Notification",
            "message": message, "notification_type": "y".repeat(MAX_DETAIL_BYTES + 10)});
        let reported = translated(&notified, &payload).expect("an observation");
        let text = reported["text"].as_str().expect("text");
        assert_eq!(
            text.len(),
            MAX_TEXT_BYTES - 1,
            "the two-byte character did not fit"
        );
        assert_eq!(
            reported["detail"].as_str().expect("detail").len(),
            MAX_DETAIL_BYTES
        );
    }

    /// A worker that refuses a hello closes the connection without reading what follows it, and
    /// that close can land before the observation behind the hello is written. The write then
    /// finds the connection gone, and the hook still says the worker refused it rather than that
    /// the write failed.
    ///
    /// The order is made here rather than waited for: the worker's end reads the hello and closes
    /// before the observation is delivered at all.
    #[tokio::test]
    async fn a_refusal_that_closes_before_the_observation_is_written_is_reported_as_one() {
        use tokio::io::AsyncBufReadExt as _;

        let host = kr_ipc::testing::TempHost::create();
        // The endpoint the platform gives a launch: a socket in the tree on Unix, and a pipe of a
        // fresh name on Windows.
        let (address, endpoint) = if cfg!(windows) {
            let fresh: String = kr_ipc::new_uuid()
                .to_string()
                .chars()
                .filter(char::is_ascii_hexdigit)
                .collect();
            let name = format!("kr-hook-refusal-{fresh}");
            (
                format!("{}{name}", crate::registration::PIPE_PREFIX),
                kr_ipc::paths::Endpoint::from_name(name),
            )
        } else {
            let path = host.root().join("endpoint");
            (
                path.display().to_string(),
                kr_ipc::paths::Endpoint::from_path(path),
            )
        };
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint.expect("a usable endpoint"))
            .expect("the endpoint binds");
        let paths = crate::registration::Paths {
            registration: host.root().join("registration"),
        };
        let credential = host.root().join("credential");
        kr_ipc::paths::create_new_owner_only_file(&credential, "0".repeat(64).as_bytes())
            .expect("the credential is the owner's alone");
        kr_ipc::paths::write_owner_only_file(
            &paths.registration,
            format!(
                "endpoint={address}\nprofile=p\ninstance=i\npid=1\nstart=1\ncredential={}\n\
                 framing=json_lines\n",
                credential.display()
            )
            .as_bytes(),
        )
        .expect("the registration");
        let registration =
            Registration::read(&paths, Duration::from_secs(5)).expect("the registration reads");

        let mut exchange =
            Exchange::open(&registration, Application::for_word("claude-code").bridge())
                .await
                .expect("the hook connects and writes its hello");
        let (worker, _) = listener.accept().await.expect("the worker accepts");
        let mut worker = tokio::io::BufReader::new(worker);
        let mut hello = Vec::new();
        worker
            .read_until(b'\n', &mut hello)
            .await
            .expect("the hello arrives");
        assert!(hello.starts_with(br#"{"kr_hello":"#), "{hello:?}");
        // Refused: closed without a word, before anything behind the hello is read.
        drop(worker);

        let observation = serde_json::json!({"kr_observation": {"event": "thread_started"}});
        let delivered = deliver(&mut exchange, &observation).await;
        assert!(
            matches!(delivered, Err(crate::exchange::ExchangeError::Refused)),
            "the hook reports a refusal as a refusal: {delivered:?}"
        );
    }

    /// KR-REQ-11.44: every application word reports the same five events, each as the observation
    /// written out here, a start from the source `compact` continues the thread, and an event
    /// outside the five reports nothing.
    #[test]
    fn kr_req_11_44_every_application_word_reports_the_same_five_events_and_compact_continues() {
        let thread = "4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11";
        let cases = [
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "SessionStart", "source": "startup"}),
                Some(
                    serde_json::json!({"event": "thread_started", "thread": thread, "detail": "startup"}),
                ),
            ),
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "SessionStart", "source": "compact"}),
                Some(
                    serde_json::json!({"event": "thread_continued", "thread": thread, "detail": "compact"}),
                ),
            ),
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "SessionStart", "source": "Compact"}),
                Some(
                    serde_json::json!({"event": "thread_started", "thread": thread, "detail": "Compact"}),
                ),
            ),
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "SessionEnd", "reason": "exit"}),
                Some(
                    serde_json::json!({"event": "thread_ended", "thread": thread, "detail": "exit"}),
                ),
            ),
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "PostToolUse", "tool_name": "Bash"}),
                Some(
                    serde_json::json!({"event": "tool_finished", "thread": thread, "detail": "Bash"}),
                ),
            ),
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "PostToolUseFailure", "tool_name": "Bash"}),
                Some(
                    serde_json::json!({"event": "tool_failed", "thread": thread, "detail": "Bash"}),
                ),
            ),
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "Notification", "message": "m", "notification_type": "n"}),
                Some(
                    serde_json::json!({"event": "notification", "thread": thread, "detail": "n", "text": "m"}),
                ),
            ),
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "BeforeTool", "tool_name": "Bash"}),
                None,
            ),
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "AfterTool", "tool_name": "Bash"}),
                None,
            ),
        ];
        // The events a launch gets when its package declares none do not depend on the word.
        let events = HookEvents::claude_code();
        for word in ["claude-code", "gemini-cli", "qoder-cli", "amp"] {
            for (payload, expected) in &cases {
                assert_eq!(translated(&events, payload), *expected, "{word} {payload}");
            }
        }
    }

    /// Qoder CLI: the events its hooks send, read through the one vocabulary.
    mod qoder_cli {
        use super::{HookEvents, observation, read_input};

        const THREAD: &str = "6b3bbfa1-1e44-480a-ae1f-a44fb86916f2";

        fn translated(payload: &serde_json::Value) -> Option<serde_json::Value> {
            let events = HookEvents::claude_code();
            let input =
                read_input(payload.to_string().as_bytes(), &events).expect("a hook's input")?;
            observation(&events, &input).map(|frame| frame["kr_observation"].clone())
        }

        /// The payloads Qoder CLI 1.1.63 wrote for a session starting and ending, and the ones its hook
        /// reference documents for the other three events, each become their observation.
        #[test]
        fn each_registered_event_becomes_its_observation() {
            let cases = [
                (
                    serde_json::json!({"session_id": THREAD, "transcript_path": "/tmp/t.jsonl",
                        "cwd": "/tmp/work", "hook_event_name": "SessionStart",
                        "permission_mode": "default", "source": "startup"}),
                    serde_json::json!({"event": "thread_started", "thread": THREAD, "detail": "startup"}),
                ),
                (
                    serde_json::json!({"session_id": THREAD, "hook_event_name": "SessionStart",
                        "source": "new"}),
                    serde_json::json!({"event": "thread_started", "thread": THREAD, "detail": "new"}),
                ),
                (
                    serde_json::json!({"session_id": THREAD, "hook_event_name": "SessionStart",
                        "source": "compact"}),
                    serde_json::json!({"event": "thread_continued", "thread": THREAD, "detail": "compact"}),
                ),
                (
                    serde_json::json!({"session_id": THREAD, "transcript_path": "/tmp/t.jsonl",
                        "cwd": "/tmp/work", "hook_event_name": "SessionEnd",
                        "permission_mode": "default", "reason": "other"}),
                    serde_json::json!({"event": "thread_ended", "thread": THREAD, "detail": "other"}),
                ),
                (
                    serde_json::json!({"session_id": THREAD, "hook_event_name": "PostToolUse",
                        "tool_name": "Write", "tool_input": {"file_path": "/p/f.ts", "content": "x"},
                        "tool_response": {"success": true, "bytes_written": 1024},
                        "tool_use_id": "toolu_01ABC123"}),
                    serde_json::json!({"event": "tool_finished", "thread": THREAD, "detail": "Write"}),
                ),
                (
                    serde_json::json!({"session_id": THREAD, "hook_event_name": "PostToolUseFailure",
                        "tool_name": "Bash", "tool_input": {"command": "npm test"},
                        "tool_use_id": "toolu_01ABC123",
                        "error": "Command exited with non-zero status code 1",
                        "error_type": "execution_failed", "is_interrupt": false}),
                    serde_json::json!({"event": "tool_failed", "thread": THREAD, "detail": "Bash"}),
                ),
                (
                    serde_json::json!({"session_id": THREAD, "hook_event_name": "Notification",
                        "notification_type": "permission_prompt",
                        "message": "Agent is requesting permission to run: rm -rf node_modules",
                        "title": "Permission Required", "details": {}}),
                    serde_json::json!({"event": "notification", "thread": THREAD,
                        "detail": "permission_prompt",
                        "text": "Agent is requesting permission to run: rm -rf node_modules"}),
                ),
            ];
            for (payload, expected) in cases {
                assert_eq!(translated(&payload), Some(expected), "{payload}");
            }
        }

        /// A finished call of the contact skill's `ask_user`, which Qoder CLI names
        /// `mcp__kalareach__ask_user` and describes in its MCP context, names the request it asked.
        #[test]
        fn a_finished_contact_question_names_its_request() {
            let reported = translated(&serde_json::json!({"session_id": THREAD,
                "hook_event_name": "PostToolUse", "tool_name": "mcp__kalareach__ask_user",
                "tool_input": {"request_id": "r-7f3a", "question": "Which one?", "type": "input"},
                "tool_response": {"content": []}, "tool_use_id": "toolu_02",
                "mcp_context": {"server_name": "kalareach", "tool_name": "ask_user"}}))
            .expect("an observation");
            assert_eq!(reported["contact_request"], "r-7f3a");
        }

        /// Every event the registration does not name is answered and reports nothing.
        #[test]
        fn an_event_the_registration_does_not_name_reports_nothing() {
            for event in [
                "PreToolUse",
                "UserPromptSubmit",
                "PermissionRequest",
                "PermissionDenied",
                "Stop",
                "StopFailure",
                "SubagentStart",
                "SubagentStop",
                "PreCompact",
                "PostCompact",
                "InstructionsLoaded",
                "ConfigChange",
                "CwdChanged",
                "FileChanged",
                "WorktreeCreate",
                "WorktreeRemove",
                "Elicitation",
                "ElicitationResult",
            ] {
                let payload = serde_json::json!({"session_id": THREAD, "hook_event_name": event});
                assert_eq!(translated(&payload), None, "{event}");
            }
        }
    }

    /// Gemini CLI: the events its hooks send, read through the one vocabulary.
    mod gemini_cli {
        use super::{HookEvents, observation, read_input};

        const THREAD: &str = "1740a246-b45f-4436-932a-3107700094f5";

        fn translated(payload: &serde_json::Value) -> Option<serde_json::Value> {
            let events = HookEvents::claude_code();
            let input =
                read_input(payload.to_string().as_bytes(), &events).expect("a hook's input")?;
            observation(&events, &input).map(|frame| frame["kr_observation"].clone())
        }

        /// The payloads Gemini CLI 0.60.0 wrote for a session starting and ending, and the one its
        /// hook reference documents for a tool permission notification, each become their observation.
        #[test]
        fn each_registered_event_becomes_its_observation() {
            let cases = [
                (
                    serde_json::json!({"session_id": THREAD, "transcript_path": "/tmp/t.jsonl",
                        "cwd": "/tmp/work", "hook_event_name": "SessionStart",
                        "timestamp": "2026-09-25T17:39:42.013Z", "source": "startup"}),
                    serde_json::json!({"event": "thread_started", "thread": THREAD, "detail": "startup"}),
                ),
                (
                    serde_json::json!({"session_id": THREAD, "hook_event_name": "SessionStart",
                        "source": "clear"}),
                    serde_json::json!({"event": "thread_started", "thread": THREAD, "detail": "clear"}),
                ),
                (
                    serde_json::json!({"session_id": THREAD, "hook_event_name": "SessionStart",
                        "source": "resume"}),
                    serde_json::json!({"event": "thread_started", "thread": THREAD, "detail": "resume"}),
                ),
                (
                    serde_json::json!({"session_id": THREAD, "transcript_path": "/tmp/t.jsonl",
                        "cwd": "/tmp/work", "hook_event_name": "SessionEnd",
                        "timestamp": "2026-09-25T17:39:42.193Z", "reason": "exit"}),
                    serde_json::json!({"event": "thread_ended", "thread": THREAD, "detail": "exit"}),
                ),
                (
                    serde_json::json!({"session_id": THREAD, "hook_event_name": "Notification",
                        "timestamp": "2026-09-25T17:40:02.000Z", "notification_type": "ToolPermission",
                        "message": "Tool Shell requires execution",
                        "details": {"type": "exec", "title": "Shell", "command": "ls", "rootCommand": "ls"}}),
                    serde_json::json!({"event": "notification", "thread": THREAD,
                        "detail": "ToolPermission", "text": "Tool Shell requires execution"}),
                ),
            ];
            for (payload, expected) in cases {
                assert_eq!(translated(&payload), Some(expected), "{payload}");
            }
        }

        /// An event outside the forwarder's vocabulary is answered and reports nothing, Gemini CLI's own
        /// `AfterTool` included, however it names the contact skill's tool.
        #[test]
        fn an_event_the_registration_does_not_name_reports_nothing() {
            for event in [
                "AfterTool",
                "BeforeTool",
                "BeforeAgent",
                "AfterAgent",
                "BeforeModel",
                "AfterModel",
                "BeforeToolSelection",
                "PreCompress",
            ] {
                let payload = serde_json::json!({"session_id": THREAD, "hook_event_name": event,
                    "tool_name": "mcp_kalareach_ask_user", "tool_input": {"request_id": "r-7f3a"},
                    "mcp_context": {"server_name": "kalareach", "tool_name": "ask_user"}});
                assert_eq!(translated(&payload), None, "{event}");
            }
        }
    }

    /// An application that names its events and members another way than Claude Code does.
    fn vendor() -> HookEvents {
        let place = |names: &[&str]| {
            serde_json::json!({"segments": names.iter()
                .map(|name| serde_json::json!({"type": "member", "name": name}))
                .collect::<Vec<_>>()})
        };
        let events: HookEvents = serde_json::from_value(serde_json::json!({
            "event": place(&["event", "name"]),
            "thread": place(&["thread", "id"]),
            "events": [
                {"name": "session_open", "report": "session_started", "continued_by": "resume"},
                {"name": "session_close", "report": "session_ended"},
                {"name": "tool_done", "report": "tool_finished"},
            ],
            "details": {
                "start_source": place(&["origin"]),
                "end_reason": place(&["cause"]),
                "tool_name": place(&["tool", "label"]),
            },
            "contact": {
                "tool_name": "{server}.{tool}",
                "tool_input": place(&["call", "arguments"]),
                "agreeing": [{"place": place(&["call", "server"]), "names": "server"}],
            },
        }))
        .expect("events");
        assert_eq!(events.refusals(), Vec::new());
        events
    }

    /// A package that declares its own names is read by them: its events report, Claude Code's
    /// names report nothing, and a continuation is the source the package names.
    #[test]
    fn an_application_with_other_event_names_reports_by_its_declared_map() {
        let events = vendor();
        let opened = translated(
            &events,
            &serde_json::json!({"event": {"name": "session_open"}, "thread": {"id": "t-1"},
                "origin": "startup"}),
        )
        .expect("an observation");
        assert_eq!(
            opened,
            serde_json::json!({"event": "thread_started", "thread": "t-1", "detail": "startup"})
        );
        let resumed = translated(
            &events,
            &serde_json::json!({"event": {"name": "session_open"}, "thread": {"id": "t-1"},
                "origin": "resume"}),
        )
        .expect("an observation");
        assert_eq!(resumed["event"], "thread_continued");
        let closed = translated(
            &events,
            &serde_json::json!({"event": {"name": "session_close"}, "thread": {"id": "t-1"},
                "cause": "logout"}),
        )
        .expect("an observation");
        assert_eq!(
            closed,
            serde_json::json!({"event": "thread_ended", "thread": "t-1", "detail": "logout"})
        );
        // Claude Code's names are not this application's.
        assert_eq!(
            translated(
                &events,
                &serde_json::json!({"event": {"name": "SessionStart"}, "thread": {"id": "t-1"}})
            ),
            None
        );
        // And the members of Claude Code's places are not read.
        let read = read_input(
            br#"{"hook_event_name":"SessionStart","session_id":"x"}"#.as_slice(),
            &events,
        );
        assert!(read.is_err(), "{read:?}");
    }

    /// A member the events do not name is skipped as it is read, however large, and changes
    /// nothing about what is observed.
    #[test]
    fn a_member_outside_the_declared_places_is_skipped() {
        let events = vendor();
        let plain = serde_json::json!({"event": {"name": "session_open"}, "thread": {"id": "t-1"},
            "origin": "startup"});
        let mut crowded = plain.clone();
        crowded["tool_response"] = serde_json::json!("x".repeat(1024 * 1024));
        crowded["event"]["extra"] = serde_json::json!({"a": [1, 2, {"b": null}]});
        crowded["thread"]["more"] = serde_json::json!("y".repeat(1024));
        crowded["call"] = serde_json::json!({"unrelated": ["z".repeat(4096)]});
        assert_eq!(
            translated(&events, &crowded),
            translated(&events, &plain),
            "what is not named changes nothing"
        );
    }

    /// The contact skill's tool is named by the template the package declares, expanded by the core
    /// over its own server and tool names, and every member the package names the server by has to
    /// agree.
    #[test]
    fn a_declared_contact_template_is_expanded_by_the_core_and_agrees_by_its_places() {
        let events = vendor();
        let finished = |label: &str, server: serde_json::Value| {
            let mut payload = serde_json::json!({"event": {"name": "tool_done"},
                "thread": {"id": "t-1"}, "tool": {"label": label},
                "call": {"arguments": {"request_id": "r-9"}}});
            if !server.is_null() {
                payload["call"]["server"] = server;
            }
            translated(&events, &payload).expect("an observation")["contact_request"].clone()
        };
        assert_eq!(
            finished("kalareach.ask_user", serde_json::Value::Null),
            "r-9"
        );
        assert_eq!(
            finished("kalareach.ask_user", serde_json::json!("kalareach")),
            "r-9"
        );
        assert!(finished("kalareach.ask_user", serde_json::json!("elsewhere")).is_null());
        assert!(finished("mcp__kalareach__ask_user", serde_json::Value::Null).is_null());
        assert!(finished("elsewhere.ask_user", serde_json::Value::Null).is_null());
    }

    /// Reading by the default places gives what the reader gave before the places were data: an
    /// input that names no event or no session, one with a named member of the wrong type or held
    /// twice, and a named object that is not one are refused; a null optional member is absent; a
    /// member nothing names may repeat; the request identifier takes the last of its repeats and
    /// nothing from a value that is not a string.
    #[test]
    fn the_default_map_reads_missing_null_wrong_type_and_repeated_members_as_before() {
        let events = HookEvents::claude_code();
        let refused = |text: &str| read_input(text.as_bytes(), &events).is_err();
        for text in [
            r#"{"hook_event_name":"SessionStart"}"#,
            r#"{"session_id":"s"}"#,
            r#"{"session_id":null,"hook_event_name":"SessionStart"}"#,
            r#"{"session_id":"s","hook_event_name":null}"#,
            r#"{"session_id":7,"hook_event_name":"SessionStart"}"#,
            r#"{"session_id":"s","hook_event_name":"SessionStart","source":3}"#,
            r#"{"session_id":"s","hook_event_name":"SessionStart","source":["a"]}"#,
            r#"{"session_id":"s","session_id":"t","hook_event_name":"SessionStart"}"#,
            r#"{"session_id":"s","hook_event_name":"SessionStart","source":"a","source":"b"}"#,
            r#"{"session_id":"s","hook_event_name":"PostToolUse","mcp_server":"kalareach"}"#,
            r#"{"session_id":"s","hook_event_name":"PostToolUse","mcp_server":{"name":5}}"#,
            r#"{"session_id":"s","hook_event_name":"PostToolUse","mcp_context":[1]}"#,
            r#"{"session_id":"s","hook_event_name":"SessionStart"} {}"#,
            r#"[]"#,
            r#"7"#,
            "",
        ] {
            assert!(refused(text), "{text}");
        }
        let read = |text: &str| {
            read_input(text.as_bytes(), &events)
                .expect(text)
                .expect(text)
        };
        assert_eq!(
            read(r#"{"session_id":"s","hook_event_name":"SessionStart","source":null}"#)
                .start_source,
            None
        );
        assert_eq!(
            read(r#"{"session_id":"s","hook_event_name":"SessionStart","other":1,"other":2}"#)
                .thread,
            "s"
        );
        for text in [
            r#"{"session_id":"s","hook_event_name":"PostToolUse","mcp_server":null}"#,
            r#"{"session_id":"s","hook_event_name":"PostToolUse","tool_input":null}"#,
            r#"{"session_id":"s","hook_event_name":"PostToolUse","tool_input":[1,{"a":2}]}"#,
            r#"{"session_id":"s","hook_event_name":"PostToolUse","tool_input":"text"}"#,
            r#"{"session_id":"s","hook_event_name":"PostToolUse","tool_input":{"request_id":5}}"#,
        ] {
            assert_eq!(read(text).tool_request_id, None, "{text}");
        }
        for (text, request) in [
            (
                r#"{"session_id":"s","hook_event_name":"PostToolUse","tool_input":{"request_id":"a","request_id":"b"}}"#,
                Some("b"),
            ),
            (
                r#"{"session_id":"s","hook_event_name":"PostToolUse","tool_input":{"request_id":"a","request_id":3}}"#,
                None,
            ),
            (
                r#"{"session_id":"s","hook_event_name":"PostToolUse","tool_input":{"request_id":"a"}}"#,
                Some("a"),
            ),
        ] {
            assert_eq!(read(text).tool_request_id.as_deref(), request, "{text}");
        }
    }

    /// A map whose contact request identifier is also the place of `role`, which is `event` or
    /// `tool_name`: the member is read by both, and the stricter one decides what it may hold.
    fn coinciding_with(role: &str) -> HookEvents {
        let place = |names: &[&str]| {
            serde_json::json!({"segments": names.iter()
                .map(|name| serde_json::json!({"type": "member", "name": name}))
                .collect::<Vec<_>>()})
        };
        let shared = place(&["tool_input", "request_id"]);
        let events: HookEvents = serde_json::from_value(serde_json::json!({
            "event": if role == "event" { shared.clone() } else { place(&["hook_event_name"]) },
            "thread": place(&["session_id"]),
            "events": [
                {"name": "SessionStart", "report": "session_started"},
                {"name": "PostToolUse", "report": "tool_finished"},
            ],
            "details": {
                "tool_name": if role == "tool_name" { shared } else { place(&["tool_name"]) },
            },
            "contact": {
                "tool_name": "mcp__{server}__{tool}",
                "tool_input": place(&["tool_input"]),
                "agreeing": [],
            },
        }))
        .expect("events");
        assert_eq!(events.refusals(), Vec::new(), "{role}");
        events
    }

    /// The request identifier's leniency (a value that is not a string, or a repeat, is no value)
    /// belongs to a place that holds no stricter role. Where the event or the tool name is read at
    /// the same place, a repeat or a value that is not a string is refused, as it is for any other
    /// place, and cannot leave the first value in the role.
    #[test]
    fn a_place_two_roles_read_is_held_to_the_stricter_role() {
        for (role, held, start, tail) in [
            (
                "event",
                "SessionStart",
                r#"{"session_id":"s","tool_input":{"#,
                "}}",
            ),
            (
                "tool_name",
                "mcp__kalareach__ask_user",
                r#"{"session_id":"s","hook_event_name":"PostToolUse","tool_input":{"#,
                "}}",
            ),
        ] {
            let events = coinciding_with(role);
            let read =
                |members: &str| read_input(format!("{start}{members}{tail}").as_bytes(), &events);
            for members in [
                format!(r#""request_id":"{held}","request_id":7"#),
                format!(r#""request_id":"{held}","request_id":{{"a":1}}"#),
                format!(r#""request_id":"{held}","request_id":["a"]"#),
                format!(r#""request_id":"{held}","request_id":null"#),
                format!(r#""request_id":"{held}","request_id":"{held}""#),
                r#""request_id":7"#.to_owned(),
                r#""request_id":{"a":1}"#.to_owned(),
            ] {
                let outcome = read(&members);
                assert!(outcome.is_err(), "{role} {members}: {outcome:?}");
            }
            let alone = read(&format!(r#""request_id":"{held}""#))
                .expect("one string value")
                .expect("a named event");
            assert_eq!(alone.tool_request_id.as_deref(), Some(held), "{role}");
            let named = if role == "event" {
                Some(alone.event.as_str())
            } else {
                alone.tool_name.as_deref()
            };
            assert_eq!(named, Some(held), "{role}");
        }
    }

    /// An event the events do not name reports nothing and is no fault, whatever else its input
    /// holds: a member of the wrong type, one held twice, or no session at all. The same faults in
    /// an event they name are refused. An event that cannot be told, because the input is not JSON
    /// or the event is not one string, is refused either way.
    #[test]
    fn an_event_the_map_does_not_name_is_no_fault_whatever_else_the_input_holds() {
        let events = HookEvents::claude_code();
        let faults = [
            r#","source":3"#,
            r#","source":["a"]"#,
            r#","source":{"a":1}"#,
            r#","source":"a","source":"b""#,
            r#","session_id":["s"]"#,
            r#","session_id":null"#,
            r#","session_id":"s","session_id":"t""#,
            r#","mcp_server":"kalareach""#,
            r#","tool_input":{"request_id":{"a":1}}"#,
        ];
        for fault in faults {
            let input = |event: &str| format!(r#"{{"hook_event_name":"{event}"{fault}}}"#);
            let unnamed = read_input(input("Elsewhere").as_bytes(), &events);
            assert!(matches!(unnamed, Ok(None)), "{fault}: {unnamed:?}");
        }
        let unnamed_without_a_session =
            read_input(&br#"{"hook_event_name":"Elsewhere"}"#[..], &events);
        assert!(matches!(unnamed_without_a_session, Ok(None)));
        for fault in &faults[..8] {
            let named = format!(r#"{{"session_id":"s","hook_event_name":"SessionStart"{fault}}}"#);
            let read = read_input(named.as_bytes(), &events);
            assert!(read.is_err(), "{fault}: {read:?}");
        }
        for text in [
            "not json",
            r#"{"hook_event_name":3}"#,
            r#"{"hook_event_name":null}"#,
            r#"{"hook_event_name":["Elsewhere"]}"#,
            r#"{"hook_event_name":"Elsewhere","hook_event_name":"Elsewhere"}"#,
            r#"{"hook_event_name":"Elsewhere"} {}"#,
            r#"{"hook_event_name":"Elsewhere""#,
        ] {
            let read = read_input(text.as_bytes(), &events);
            assert!(read.is_err(), "{text}: {read:?}");
        }
    }

    /// A reader that counts what it has given.
    struct Counted<R> {
        inner: R,
        given: std::rc::Rc<std::cell::Cell<usize>>,
    }

    impl<R: std::io::Read> std::io::Read for Counted<R> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let read = self.inner.read(buffer)?;
            self.given.set(self.given.get() + read);
            Ok(read)
        }
    }

    /// However a read ends, whether the input is not JSON, names its event twice, holds a member of
    /// the wrong type, holds something after its object, or is for an event the events do not name,
    /// the whole of the input has been read when it returns: an application's write of a large
    /// input does not complete until it is.
    #[test]
    fn a_read_ends_only_at_the_end_of_the_input_however_it_goes() {
        use std::io::Read as _;

        let events = HookEvents::claude_code();
        let tail = 1024 * 1024;
        for (name, prefix, suffix, shape) in [
            ("not json", "not json", "", "refused"),
            (
                "an event named twice",
                r#"{"hook_event_name":"SessionStart","hook_event_name":"SessionEnd","tool_response":""#,
                r#""}"#,
                "refused",
            ),
            (
                "a member of the wrong type",
                r#"{"session_id":"s","hook_event_name":"SessionStart","source":3,"tool_response":""#,
                r#""}"#,
                "refused",
            ),
            (
                "something after the object",
                r#"{"session_id":"s","hook_event_name":"SessionStart"} "#,
                "",
                "refused",
            ),
            (
                "an event the events do not name",
                r#"{"session_id":"s","hook_event_name":"Elsewhere","source":3,"tool_response":""#,
                r#""}"#,
                "unnamed",
            ),
            (
                "an event they name",
                r#"{"session_id":"s","hook_event_name":"SessionStart","tool_response":""#,
                r#""}"#,
                "read",
            ),
        ] {
            let given = std::rc::Rc::new(std::cell::Cell::new(0));
            let reader = Counted {
                inner: prefix
                    .as_bytes()
                    .chain(std::io::repeat(b'x').take(tail as u64))
                    .chain(suffix.as_bytes()),
                given: given.clone(),
            };
            let read = read_input(reader, &events);
            let found = match &read {
                Err(_) => "refused",
                Ok(None) => "unnamed",
                Ok(Some(_)) => "read",
            };
            assert_eq!(found, shape, "{name}: {read:?}");
            assert_eq!(
                given.get(),
                prefix.len() + tail + suffix.len(),
                "{name}: the input is read to its end"
            );
        }
    }
}
