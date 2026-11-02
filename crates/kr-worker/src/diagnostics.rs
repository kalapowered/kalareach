//! What this worker says to its own standard error, for a person looking into a host that did less
//! than it was asked to.
//!
//! On Unix that is where the reason is found: a launchd job's or a detached process's diagnostics
//! file, a transient unit's journal. A Windows worker has a console with no window, so nobody reads
//! it there.
//!
//! A write to a standard error that has stopped draining, a pipe nobody reads or a journal that has
//! stalled, does not return until a reader drains it, and nothing can cancel it. So nothing that
//! serves a person or keeps the host's records makes the write itself. A line is handed to a
//! thread of its own, started when a line is said and no thread is running, which writes the lines
//! one at a time and ends when none waits. A worker that says nothing holds no thread, and one that
//! has said its lines holds none either. That thread is not a task of the runtime, and the runtime
//! does not wait for it when it is dropped: the process ends with the thread still in its write. At
//! most eight lines wait for it. A line offered beyond that is dropped, not waited for.
//!
//! A line said just before the process ends can be lost to the exit, because the thread has not
//! reached it. A program that says its last lines on the way out, as the worker's does, calls
//! [`drain`] before it ends, which waits for the lines the thread took for a time the program names
//! and no longer.
//!
//! The write can fail as well: a volume that is full refuses it as it refused what made the host
//! say it. A write that fails is let go.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

/// How many lines wait for the thread that writes them before a further line is dropped.
const WAITING: usize = 8;

/// What is done once the write of a line has ended, told whether it was written.
type Ended = Box<dyn FnOnce(bool) + Send>;

/// A line to write, and what is done once its write has ended.
struct Line {
    text: String,
    ended: Option<Ended>,
}

/// What the thread that writes the lines shares with the callers that hand lines over.
struct Shared {
    queue: Mutex<Queue>,
    /// Signalled when no line is unfinished.
    none: Condvar,
    /// Where the lines are written. The thread holds it for as long as it runs, and only one runs.
    destination: Mutex<Box<dyn Write + Send>>,
}

/// The lines handed over, and whether a thread is there to write them.
#[derive(Default)]
struct Queue {
    /// The lines that wait for the thread, oldest first. A line in its write is not among them.
    waiting: VecDeque<Line>,
    /// Whether a thread is running: from the moment it is started until it has found no line
    /// waiting.
    running: bool,
    /// The lines handed over whose write has not ended, those that wait among them.
    unfinished: usize,
}

/// Writes lines to one destination, one at a time, from a thread of its own that runs while a line
/// waits or is being written.
pub(crate) struct Writer {
    shared: Arc<Shared>,
}

impl Writer {
    /// Makes a writer of lines to `destination`. No thread is started until a line is offered.
    pub(crate) fn new(destination: impl Write + Send + 'static) -> Self {
        Self {
            shared: Arc::new(Shared {
                queue: Mutex::default(),
                none: Condvar::new(),
                destination: Mutex::new(Box::new(destination)),
            }),
        }
    }

    /// Hands `text` to the thread, starting it when none is running, and says whether it took it. It
    /// never waits: a line is dropped when [`WAITING`] lines already wait, or when no thread could
    /// be started for it, and the next line tries again. `ended` is called by the thread once the
    /// write has ended, and not at all for a line that is dropped.
    pub(crate) fn offer(&self, text: String, ended: Option<Ended>) -> bool {
        let mut queue = locked(&self.shared.queue);
        if queue.waiting.len() >= WAITING {
            return false;
        }
        queue.waiting.push_back(Line { text, ended });
        queue.unfinished += 1;
        if !queue.running {
            let shared = Arc::clone(&self.shared);
            let started = std::thread::Builder::new()
                .name("kr-worker-diagnostics".to_owned())
                .spawn(move || write_lines(&shared))
                .is_ok();
            if !started {
                queue.waiting.pop_back();
                queue.unfinished -= 1;
                return false;
            }
            queue.running = true;
        }
        true
    }

    /// Waits for at most `within` until every line the thread took has been written or refused, and
    /// says whether they have. A write that waits for a reader holds this for `within` and no
    /// longer.
    pub(crate) fn drain(&self, within: Duration) -> bool {
        let (queue, _) = self
            .shared
            .none
            .wait_timeout_while(locked(&self.shared.queue), within, |queue| {
                queue.unfinished > 0
            })
            .unwrap_or_else(PoisonError::into_inner);
        queue.unfinished == 0
    }
}

/// Writes the lines that wait to the destination, and tells whether each was written. It ends when
/// none waits.
fn write_lines(shared: &Shared) {
    let mut destination = locked(&shared.destination);
    loop {
        let line = {
            let mut queue = locked(&shared.queue);
            let Some(line) = queue.waiting.pop_front() else {
                queue.running = false;
                return;
            };
            line
        };
        let written = destination.write_all(line.text.as_bytes()).is_ok();
        if let Some(ended) = line.ended {
            ended(written);
        }
        let mut queue = locked(&shared.queue);
        queue.unfinished -= 1;
        if queue.unfinished == 0 {
            shared.none.notify_all();
        }
    }
}

/// The writer of this process's standard error, which the first line makes.
static STANDARD_ERROR: OnceLock<Writer> = OnceLock::new();

/// Returns the writer of this process's standard error, making it if no line has been said.
pub(crate) fn standard_error() -> &'static Writer {
    STANDARD_ERROR.get_or_init(|| Writer::new(std::io::stderr()))
}

/// Says one line to this process's standard error, and lets it go if it cannot be written or the
/// writer is behind. The line is handed over whole, and the thread writes it with `write_all`: a
/// volume that is nearly full can take part of it. This never waits for the write.
///
/// A line is also let go when no thread could be started for it. The next line tries again.
pub fn tell(line: std::fmt::Arguments<'_>) {
    let _ = standard_error().offer(format!("kr-worker: {line}\n"), None);
}

/// Waits for at most `within` until every line the thread took has been written to this process's
/// standard error or refused by it, and says whether they have. A line that was dropped, or that
/// had no thread to take it, is not waited for.
///
/// A program that says its last lines on its way out calls this before it ends, since a line the
/// thread has not reached can be lost to the exit. A standard error that has stopped draining holds
/// this for `within` and no longer, and the lines still waiting are lost when the process ends.
pub fn drain(within: Duration) -> bool {
    STANDARD_ERROR
        .get()
        .is_none_or(|writer| writer.drain(within))
}

/// Takes `state`, whose holders never leave it half changed.
fn locked<T>(state: &Mutex<T>) -> MutexGuard<'_, T> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The reasons an output retention pass left output behind, as this worker has said them.
#[derive(Debug, Default)]
struct Said {
    /// The reason of the last line that was written while its offer still stood.
    said: Option<String>,
    /// The offer whose line waits for the writer or is being written, and that no pass has
    /// withdrawn.
    offered: Option<Offered>,
    /// How many offers have been made, which names the next one.
    offers: u64,
}

/// A reason offered to the writer as a line.
#[derive(Debug)]
struct Offered {
    /// Names this offer. The end of a write is told which offer it belongs to, because the same
    /// reason can go and be offered again while the first line is still in its write.
    id: u64,
    reason: String,
}

impl Said {
    /// Decides what a pass that left `reason` behind is to say, and returns the name of the offer
    /// when it is a reason that is neither said nor on its way.
    ///
    /// A reason that goes and comes back is said again. A pass that applied no age bound
    /// (`age_applied` is false), as a look at the host's cap does not and as a pass on a wall clock
    /// the host cannot prove does not, keeps what was said when it finds no reason, since it
    /// cannot tell that a reason the age bound left has gone. The same holds for a reason of the
    /// byte caps while the wall clock cannot be proved.
    fn offer(&mut self, reason: Option<&str>, age_applied: bool) -> Option<u64> {
        match reason {
            None if !age_applied => None,
            None => {
                self.said = None;
                self.offered = None;
                None
            }
            Some(reason)
                if self.said.as_deref() == Some(reason)
                    || self
                        .offered
                        .as_ref()
                        .is_some_and(|offered| offered.reason == reason) =>
            {
                None
            }
            Some(reason) => {
                self.offers += 1;
                self.offered = Some(Offered {
                    id: self.offers,
                    reason: reason.to_owned(),
                });
                Some(self.offers)
            }
        }
    }

    /// Records that the line of offer `id` was written, unless that offer has been withdrawn or
    /// replaced since.
    fn written(&mut self, id: u64) {
        if self
            .offered
            .as_ref()
            .is_some_and(|offered| offered.id == id)
        {
            self.said = self.offered.take().map(|offered| offered.reason);
        }
    }

    /// Records that the line of offer `id` was not written, so that the next pass offers its reason
    /// again, unless that offer has been withdrawn or replaced since.
    fn refused(&mut self, id: u64) {
        if self
            .offered
            .as_ref()
            .is_some_and(|offered| offered.id == id)
        {
            self.offered = None;
        }
    }
}

/// What this worker has said of why its output retention left output behind.
///
/// Only the writer's thread knows whether a line was written, so it records that here, and a
/// reason is not taken as said before then. Nothing here waits for the write.
#[derive(Clone, Debug, Default)]
pub(crate) struct OutputReasons {
    state: Arc<Mutex<Said>>,
}

impl OutputReasons {
    /// Says why a pass left output behind, when it is not the reason last said, through the writer
    /// `writer` returns. The writer is asked for only when there is a line to hand it.
    ///
    /// `reason` is why the pass left output it was asked to remove, when it did, and `age_applied`
    /// whether the pass applied the age bound. This never waits for the write.
    pub(crate) fn say<'w>(
        &self,
        reason: Option<&str>,
        age_applied: bool,
        writer: impl FnOnce() -> &'w Writer,
    ) {
        let mut state = locked(&self.state);
        let Some(reason) = reason else {
            state.offer(None, age_applied);
            return;
        };
        let Some(id) = state.offer(Some(reason), age_applied) else {
            return;
        };
        let line =
            format!("kr-worker: output retention left output it was asked to remove: {reason}\n");
        let ended: Ended = {
            let state = Arc::clone(&self.state);
            Box::new(move |written| {
                let mut state = locked(&state);
                if written {
                    state.written(id);
                } else {
                    state.refused(id);
                }
            })
        };
        if !writer().offer(line, Some(ended)) {
            state.refused(id);
        }
    }

    /// Returns the reason of the last line written while its offer still stood, for this host's
    /// own tests. It is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub(crate) fn said(&self) -> Option<String> {
        locked(&self.state).said.clone()
    }

    /// Returns whether the line of the offer that stands waits for its write or is being written,
    /// for this host's own tests. A reason that has gone since is not on its way, though its line
    /// may still be in the write. It is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub(crate) fn being_written(&self) -> bool {
        locked(&self.state).offered.is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::{OutputReasons, Said, WAITING, Writer, locked};

    /// The most a case waits for something it expects.
    const DEADLINE: Duration = Duration::from_secs(30);

    /// A destination that takes writes while it is open to them, as a volume does until it is full,
    /// and that a case can look into.
    #[derive(Clone)]
    struct Volume {
        taken: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        open: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl Volume {
        fn new() -> Self {
            Self {
                taken: std::sync::Arc::default(),
                open: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            }
        }

        fn fill(&self) {
            self.open.store(false, std::sync::atomic::Ordering::SeqCst);
        }

        fn empty(&self) {
            self.open.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        fn lines(&self) -> Vec<String> {
            String::from_utf8(self.taken.lock().expect("not poisoned").clone())
                .expect("text")
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    impl std::io::Write for Volume {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.open.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(std::io::Error::other("no space left on device"));
            }
            self.taken
                .lock()
                .expect("not poisoned")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A destination whose writes wait for a reader, as a pipe that nobody reads does: each write
    /// tells that it has begun, and ends when the case lets it, either taking the bytes or refusing
    /// them, as the case says.
    struct Stalled {
        begun: mpsc::Sender<()>,
        release: mpsc::Receiver<bool>,
        taken: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl std::io::Write for Stalled {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let _ = self.begun.send(());
            if !self.release.recv().unwrap_or(true) {
                return Err(std::io::Error::other("no space left on device"));
            }
            self.taken
                .lock()
                .expect("not poisoned")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Waits until `condition` holds.
    fn until(condition: impl Fn() -> bool) {
        let started = std::time::Instant::now();
        while !condition() {
            assert!(started.elapsed() < DEADLINE, "the condition held");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// A reason that stands is offered once, and again if it goes and comes back or changes.
    #[test]
    fn a_reason_is_offered_once_while_it_stands() {
        let mut said = Said::default();
        assert_eq!(said.offer(None, true), None);
        let first = said.offer(Some("the lock"), true).expect("offered");
        assert_eq!(
            said.offer(Some("the lock"), true),
            None,
            "not again while its line is on its way"
        );
        said.written(first);
        assert_eq!(
            said.offer(Some("the lock"), true),
            None,
            "nor once it is written"
        );
        assert_eq!(said.offer(None, true), None, "it goes");
        let second = said
            .offer(Some("the lock"), true)
            .expect("offered again when it comes back");
        said.written(second);
        assert!(
            said.offer(Some("the boundary"), true).is_some(),
            "as is another"
        );
    }

    /// A reason refused after another was written is not taken as said: the volume that refused it
    /// takes it later, and it is written then, once.
    #[test]
    fn a_reason_refused_after_another_was_written_is_offered_until_it_is_written() {
        let mut said = Said::default();
        let lock = said.offer(Some("the lock"), true).expect("offered");
        said.written(lock);

        let boundary = said.offer(Some("the boundary"), true).expect("offered");
        said.refused(boundary);
        let again = said
            .offer(Some("the boundary"), true)
            .expect("the second is offered again at the next pass");
        said.written(again);
        assert_eq!(
            said.offer(Some("the boundary"), true),
            None,
            "and not again once it is written"
        );
    }

    /// A pass that applied no age bound cannot tell that a reason the age bound left has gone, so a
    /// reason written by a pass that applied age is not offered again after a pass that did not:
    /// the host's look at its cap sits between two passes of the tick.
    #[test]
    fn a_pass_that_applied_no_age_bound_does_not_make_a_reason_repeat() {
        let mut said = Said::default();
        let segment = said.offer(Some("a segment"), true).expect("offered");
        said.written(segment);
        assert_eq!(
            said.offer(None, false),
            None,
            "a look finds no reason, as it applied no age bound"
        );
        assert_eq!(
            said.offer(Some("a segment"), true),
            None,
            "so the pass that applies it again has nothing new to say"
        );
        assert_eq!(
            said.offer(None, true),
            None,
            "a pass that applied it finds none"
        );
        assert!(
            said.offer(Some("a segment"), true).is_some(),
            "and then the reason is new again"
        );
    }

    /// A late end of a write does not mark as said a reason that has gone or changed since.
    #[test]
    fn a_write_that_ends_after_its_reason_went_says_nothing() {
        let mut said = Said::default();
        let old = said.offer(Some("the lock"), true).expect("offered");
        assert_eq!(said.offer(None, true), None, "it goes while its line waits");
        said.written(old);
        let new = said
            .offer(Some("the lock"), true)
            .expect("so it is offered when it comes back");
        said.written(old);
        said.refused(old);
        assert_eq!(
            said.offer(Some("the lock"), true),
            None,
            "the end of the old line leaves the new offer on its way"
        );
        said.written(new);
        assert_eq!(said.said.as_deref(), Some("the lock"));
    }

    /// Lines are written one at a time, in order, and each is told how its write ended.
    #[test]
    fn lines_are_written_in_order_and_each_is_told_how_it_ended() {
        let volume = Volume::new();
        let writer = Writer::new(volume.clone());
        let (ended, results) = mpsc::channel();
        for text in ["one\n", "two\n"] {
            let ended = ended.clone();
            assert!(writer.offer(
                text.to_owned(),
                Some(Box::new(move |written| {
                    let _ = ended.send(written);
                }))
            ));
        }
        assert_eq!(results.recv_timeout(DEADLINE), Ok(true));
        assert_eq!(results.recv_timeout(DEADLINE), Ok(true));
        assert_eq!(volume.lines(), ["one", "two"]);

        volume.fill();
        let refused = ended.clone();
        assert!(writer.offer(
            "three\n".to_owned(),
            Some(Box::new(move |written| {
                let _ = refused.send(written);
            }))
        ));
        assert_eq!(
            results.recv_timeout(DEADLINE),
            Ok(false),
            "a full volume refuses the line"
        );
        volume.empty();
        assert!(writer.offer(
            "four\n".to_owned(),
            Some(Box::new(move |written| {
                let _ = ended.send(written);
            }))
        ));
        assert_eq!(
            results.recv_timeout(DEADLINE),
            Ok(true),
            "and the writer goes on"
        );
        assert_eq!(volume.lines(), ["one", "two", "four"]);
    }

    /// The thread ends when no line waits, so a worker that has said its lines holds none, and a
    /// line said later is written by another.
    #[test]
    fn the_thread_ends_when_no_line_waits_and_a_later_line_starts_another() {
        let volume = Volume::new();
        let writer = Writer::new(volume.clone());
        // The thread holds a reference to what it shares until it returns.
        let thread_ended = || {
            !locked(&writer.shared.queue).running
                && std::sync::Arc::strong_count(&writer.shared) == 1
        };
        assert!(thread_ended(), "no thread runs before a line is said");
        for (number, text) in ["one\n", "two\n"].into_iter().enumerate() {
            assert!(writer.offer(text.to_owned(), None));
            assert!(writer.drain(DEADLINE), "the line was written");
            until(thread_ended);
            assert_eq!(volume.lines().len(), number + 1);
        }
        assert_eq!(volume.lines(), ["one", "two"]);
    }

    /// A write that waits for a reader holds the writer's thread and nothing else: lines are taken
    /// until [`WAITING`] wait, then dropped without the caller waiting, and the waiting lines are
    /// written once the reader comes.
    #[test]
    fn a_write_that_waits_for_a_reader_holds_the_thread_and_nothing_else() {
        let (begun, begun_at) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let taken = std::sync::Arc::default();
        let writer = Writer::new(Stalled {
            begun,
            release: released,
            taken: std::sync::Arc::clone(&taken),
        });
        assert!(writer.offer("first\n".to_owned(), None));
        begun_at.recv_timeout(DEADLINE).expect("the write began");

        // The thread is in its write; the offers below return at once, however many.
        let (offered, offers) = mpsc::channel();
        std::thread::spawn(move || {
            let taken_while_waiting = (0..WAITING + 3)
                .filter(|number| writer.offer(format!("line {number}\n"), None))
                .count();
            let _ = offered.send((taken_while_waiting, writer));
        });
        let (took, writer) = offers
            .recv_timeout(DEADLINE)
            .expect("the offers returned without waiting");
        assert_eq!(
            took, WAITING,
            "[`WAITING`] lines wait and the rest are dropped"
        );

        drop(writer);
        for _ in 0..=WAITING {
            release.send(true).expect("lets a write end");
        }
        until(|| taken.lock().expect("not poisoned").ends_with(b"line 7\n"));
        let written = String::from_utf8(taken.lock().expect("not poisoned").clone()).expect("text");
        assert!(written.starts_with("first\nline 0\n"), "{written}");
    }

    /// A drain waits for the lines the thread took, for as long as its bound and no longer.
    #[test]
    fn a_drain_waits_for_the_lines_taken_and_gives_up_at_its_bound() {
        let (begun, begun_at) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let writer = std::sync::Arc::new(Writer::new(Stalled {
            begun,
            release: released,
            taken: std::sync::Arc::default(),
        }));
        assert!(writer.drain(Duration::ZERO), "nothing was taken");

        assert!(writer.offer("first\n".to_owned(), None));
        begun_at.recv_timeout(DEADLINE).expect("the write began");
        // A drain with no bound would not return while the write waits, so it runs on a thread of
        // its own and the case waits for its answer for a limited time.
        let (answered, answer) = mpsc::channel();
        std::thread::spawn({
            let writer = std::sync::Arc::clone(&writer);
            move || {
                let _ = answered.send(writer.drain(Duration::from_millis(20)));
            }
        });
        assert_eq!(
            answer.recv_timeout(DEADLINE),
            Ok(false),
            "a write that waits for a reader holds a drain to its bound"
        );
        release.send(true).expect("lets the write end");
        assert!(writer.drain(DEADLINE), "the line was written");
    }

    /// A reason is not taken as said until its line is written, is offered again after a write
    /// that failed, and is not offered a second time while its first line waits.
    #[test]
    fn a_reason_is_said_when_its_line_is_written_and_not_before() {
        let (begun, begun_at) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let taken = std::sync::Arc::default();
        let writer = Writer::new(Stalled {
            begun,
            release: released,
            taken: std::sync::Arc::clone(&taken),
        });
        let reasons = OutputReasons::default();

        reasons.say(Some("the lock"), true, || &writer);
        begun_at.recv_timeout(DEADLINE).expect("the write began");
        assert!(reasons.being_written());
        assert_eq!(reasons.said(), None, "the line is not written yet");
        reasons.say(Some("the lock"), true, || {
            panic!("a second line is not offered")
        });

        release.send(true).expect("lets the write end");
        until(|| reasons.said().is_some());
        assert!(!reasons.being_written());
        assert!(
            String::from_utf8(taken.lock().expect("not poisoned").clone())
                .expect("text")
                .ends_with("the lock\n")
        );
    }

    /// A line that is refused leaves its reason to be offered at the next pass, and a full volume
    /// does not stop the passes that follow.
    #[test]
    fn a_reason_whose_line_was_refused_is_offered_at_the_next_pass() {
        let volume = Volume::new();
        volume.fill();
        let writer = Writer::new(volume.clone());
        let reasons = OutputReasons::default();

        reasons.say(Some("the lock"), true, || &writer);
        until(|| !reasons.being_written());
        assert_eq!(
            reasons.said(),
            None,
            "a reason that was not written is not said"
        );
        assert!(volume.lines().is_empty());

        volume.empty();
        reasons.say(Some("the lock"), true, || &writer);
        until(|| reasons.said().is_some());
        assert_eq!(
            volume.lines().len(),
            1,
            "the next pass that can write it says it"
        );
        reasons.say(Some("the lock"), true, || {
            panic!("a said reason is not offered")
        });
    }

    /// A line that fails after its reason went and came back does not take back the offer the
    /// returned reason made: the old line's end is not the new line's.
    ///
    /// The reason goes and comes back while the first line is in its write, so a second line for
    /// the same text waits behind it. The first write then fails. The second line is still on its
    /// way, and a pass that finds the reason again offers nothing, while the second line is
    /// written and says the reason once.
    #[test]
    fn a_line_that_fails_after_its_reason_came_back_does_not_take_back_the_new_offer() {
        let (begun, begun_at) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let taken = std::sync::Arc::default();
        let writer = Writer::new(Stalled {
            begun,
            release: released,
            taken: std::sync::Arc::clone(&taken),
        });
        let reasons = OutputReasons::default();

        reasons.say(Some("the lock"), true, || &writer);
        begun_at.recv_timeout(DEADLINE).expect("the write began");
        reasons.say(None, true, || panic!("nothing to say"));
        assert!(!reasons.being_written(), "the reason went");
        reasons.say(Some("the lock"), true, || &writer);
        assert!(reasons.being_written(), "and came back");

        // The thread writes one line at a time, so the second write beginning means the end of the
        // first has been told.
        release.send(false).expect("refuses the first write");
        begun_at
            .recv_timeout(DEADLINE)
            .expect("the second write began");
        assert!(
            reasons.being_written(),
            "the refusal of the old line took back the new offer"
        );
        reasons.say(Some("the lock"), true, || {
            panic!("the reason is offered a third time")
        });

        release.send(true).expect("lets the second write end");
        until(|| reasons.said().is_some());
        assert_eq!(
            String::from_utf8(taken.lock().expect("not poisoned").clone())
                .expect("text")
                .matches("the lock\n")
                .count(),
            1,
            "the reason was written once"
        );
    }

    /// A line the writer drops leaves its reason to be offered at the next pass, and is not taken
    /// as on its way.
    #[test]
    fn a_reason_whose_line_the_writer_drops_is_offered_at_the_next_pass() {
        let (begun, begun_at) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let taken = std::sync::Arc::default();
        let writer = Writer::new(Stalled {
            begun,
            release: released,
            taken: std::sync::Arc::clone(&taken),
        });
        let reasons = OutputReasons::default();

        assert!(writer.offer("first\n".to_owned(), None));
        begun_at.recv_timeout(DEADLINE).expect("the write began");
        for number in 0..WAITING {
            assert!(writer.offer(format!("line {number}\n"), None));
        }

        reasons.say(Some("the lock"), true, || &writer);
        assert!(
            !reasons.being_written(),
            "a line the writer dropped is not on its way"
        );
        assert_eq!(reasons.said(), None);

        for _ in 0..=WAITING {
            release.send(true).expect("lets a write end");
        }
        until(|| taken.lock().expect("not poisoned").ends_with(b"line 7\n"));
        reasons.say(Some("the lock"), true, || &writer);
        assert!(
            reasons.being_written(),
            "the next pass offers the reason again"
        );
        release.send(true).expect("lets the write end");
        until(|| reasons.said().is_some());
        assert!(
            writer.drain(DEADLINE),
            "the line the writer dropped is not counted as unfinished"
        );
    }

    /// Fills this process's standard error, a pipe, to the last byte, so that the next write to it
    /// waits for a reader.
    #[cfg(unix)]
    fn fill_standard_error() {
        use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

        let standard_error = std::io::stderr();
        let flags = fcntl_getfl(&standard_error).expect("the flags of the standard error");
        fcntl_setfl(&standard_error, flags | OFlags::NONBLOCK).expect("a write that does not wait");
        for chunk in [1024_usize, 1] {
            let bytes = vec![b'.'; chunk];
            loop {
                match rustix::io::write(&standard_error, &bytes) {
                    Ok(_) => {}
                    Err(rustix::io::Errno::AGAIN) => break,
                    Err(error) => panic!("filling the standard error: {error}"),
                }
            }
        }
        fcntl_setfl(&standard_error, flags).expect("a write that waits again");
    }

    /// A line told to a standard error that refuses the write, or that has stopped draining, waits
    /// for nothing: the caller goes on, and the process ends with the writer still in its write.
    /// One told to a standard error that is read is there to read once the process has drained.
    ///
    /// The case runs itself again as a process of its own, once with a standard error whose
    /// reading end is closed, once with a pipe that is full and that nobody reads, and once with a
    /// pipe that is read when the process has ended. Told lines are more than [`WAITING`] for the
    /// first two, so the ones beyond are dropped.
    #[cfg(unix)]
    #[test]
    fn a_line_told_to_a_standard_error_that_refuses_or_has_stopped_draining_waits_for_nothing() {
        use std::io::Read as _;
        use std::process::{Command, Stdio};

        const NAME: &str = "diagnostics::tests::a_line_told_to_a_standard_error_that_refuses_or_has_stopped_draining_waits_for_nothing";
        const CHILD: &str = "KR_TEST_TELL_PROCESS";

        if let Some(mode) = std::env::var_os(CHILD) {
            if mode == "read" {
                super::tell(format_args!("a line to a standard error that is read"));
                assert!(super::drain(DEADLINE), "the line was written");
                println!("told");
                return;
            }
            if mode == "full" {
                fill_standard_error();
            }
            for number in 0..WAITING * 3 {
                super::tell(format_args!("a line to a standard error, number {number}"));
            }
            // The standard error is full, so a panic message would wait for a reader too: the
            // fault is told on standard output, which the parent reads.
            if mode == "full" && super::drain(Duration::from_millis(20)) {
                println!("a write that waits for a reader was drained");
                return;
            }
            println!("told");
            return;
        }

        for mode in ["gone", "full", "read"] {
            let mut worker = Command::new(std::env::current_exe().expect("this test's program"))
                .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
                .env(CHILD, mode)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("starts the process");
            // Held without being read, or closed at once.
            let mut pipe = worker.stderr.take();
            if mode == "gone" {
                pipe = None;
            }
            let started = std::time::Instant::now();
            let status = loop {
                if let Some(status) = worker.try_wait().expect("polls the process") {
                    break Some(status);
                }
                if started.elapsed() > DEADLINE {
                    worker.kill().expect("ends the process by its pid");
                    worker.wait().expect("the process ends");
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            let mut output = String::new();
            worker
                .stdout
                .take()
                .expect("its standard output")
                .read_to_string(&mut output)
                .expect("reads its standard output");
            assert!(
                status.is_some_and(|status| status.success()) && output.contains("told"),
                "the process with its standard error {mode} told its lines and ended: {output}"
            );
            if mode == "read" {
                let mut said = String::new();
                pipe.as_mut()
                    .expect("its standard error")
                    .read_to_string(&mut said)
                    .expect("reads its standard error");
                assert!(
                    said.contains("a line to a standard error that is read"),
                    "the line was there to read: {said}"
                );
            }
        }
    }

    /// A pass with nothing to say does not ask for the writer, so no thread is started for it.
    #[test]
    fn a_pass_with_nothing_to_say_does_not_ask_for_the_writer() {
        let reasons = OutputReasons::default();
        reasons.say(None, true, || panic!("asked for the writer"));
        reasons.say(None, false, || panic!("asked for the writer"));
    }
}
