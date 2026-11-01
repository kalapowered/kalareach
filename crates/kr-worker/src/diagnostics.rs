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
//! thread of its own, started when the first line is said, which writes the lines one at a time.
//! That thread is not a task of the runtime, and the runtime does not wait for it when it is
//! dropped: the process ends with the thread still in its write. At most [`WAITING`] lines wait
//! for it. A line offered beyond that is dropped, not waited for.
//!
//! The write can fail as well: a volume that is full refuses it as it refused what made the host
//! say it. A write that fails is let go.

use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, mpsc};

/// How many lines wait for the thread that writes them before a further line is dropped.
const WAITING: usize = 8;

/// What is done once the write of a line has ended, told whether it was written.
type Ended = Box<dyn FnOnce(bool) + Send>;

/// A line to write, and what is done once its write has ended.
struct Line {
    text: String,
    ended: Option<Ended>,
}

/// The thread that writes lines to one destination, one at a time.
pub(crate) struct Writer {
    /// Where lines are handed to the thread; none when the thread could not be started.
    lines: Option<mpsc::SyncSender<Line>>,
}

impl Writer {
    /// Starts the thread, which writes to `destination`.
    pub(crate) fn start(destination: impl Write + Send + 'static) -> Self {
        let (lines, waiting) = mpsc::sync_channel::<Line>(WAITING);
        let started = std::thread::Builder::new()
            .name("kr-worker-diagnostics".to_owned())
            .spawn(move || write_lines(destination, &waiting))
            .is_ok();
        Self {
            lines: started.then_some(lines),
        }
    }

    /// Hands `text` to the thread, and says whether it took it. It never waits: a line is dropped
    /// when [`WAITING`] lines already wait, or when the thread could not be started. `ended` is
    /// called by the thread once the write has ended, and not at all for a line that is dropped.
    pub(crate) fn offer(&self, text: String, ended: Option<Ended>) -> bool {
        self.lines
            .as_ref()
            .is_some_and(|lines| lines.try_send(Line { text, ended }).is_ok())
    }
}

/// Writes each line that arrives to `destination`, and tells whether it was written.
fn write_lines(mut destination: impl Write, waiting: &mpsc::Receiver<Line>) {
    for line in waiting {
        let written = destination.write_all(line.text.as_bytes()).is_ok();
        if let Some(ended) = line.ended {
            ended(written);
        }
    }
}

/// The writer of this process's standard error, which is started by the first line.
pub(crate) fn standard_error() -> &'static Writer {
    static WRITER: OnceLock<Writer> = OnceLock::new();
    WRITER.get_or_init(|| Writer::start(std::io::stderr()))
}

/// Takes `state`, whose holders never leave it half changed.
fn locked(state: &Mutex<Said>) -> MutexGuard<'_, Said> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The reasons an output retention pass left output behind, as this worker has said them.
#[derive(Debug, Default)]
struct Said {
    /// The reason whose line was last written.
    said: Option<String>,
    /// The reason whose line has been handed to the writer and not yet written or refused.
    offered: Option<String>,
}

impl Said {
    /// Decides what a pass that left `reason` behind is to say, and returns it when it is a reason
    /// that is neither said nor on its way.
    ///
    /// A reason that goes and comes back is said again. A pass that applied no age bound
    /// (`age_applied` is false), as a look at the host's cap does not and as a pass on a wall clock
    /// the host cannot prove does not, keeps what was said when it finds no reason, since it
    /// cannot tell that a reason the age bound left has gone. The same holds for a reason of the
    /// byte caps while the wall clock cannot be proved.
    fn offer(&mut self, reason: Option<&str>, age_applied: bool) -> Option<String> {
        match reason {
            None if !age_applied => None,
            None => {
                self.said = None;
                self.offered = None;
                None
            }
            Some(reason)
                if self.said.as_deref() == Some(reason)
                    || self.offered.as_deref() == Some(reason) =>
            {
                None
            }
            Some(reason) => {
                self.offered = Some(reason.to_owned());
                Some(reason.to_owned())
            }
        }
    }

    /// Records that the line for `reason` was written, unless the reason has gone or changed since.
    fn written(&mut self, reason: &str) {
        if self.offered.as_deref() == Some(reason) {
            self.said = self.offered.take();
        }
    }

    /// Records that the line for `reason` was not written, so that the next pass offers it again.
    fn refused(&mut self, reason: &str) {
        if self.offered.as_deref() == Some(reason) {
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
        let Some(reason) = state.offer(reason, age_applied) else {
            return;
        };
        let line =
            format!("kr-worker: output retention left output it was asked to remove: {reason}\n");
        let ended: Ended = {
            let state = Arc::clone(&self.state);
            let reason = reason.clone();
            Box::new(move |written| {
                let mut state = locked(&state);
                if written {
                    state.written(&reason);
                } else {
                    state.refused(&reason);
                }
            })
        };
        if !writer().offer(line, Some(ended)) {
            state.refused(&reason);
        }
    }

    /// Returns the reason whose line was last written, for this host's own tests. It is compiled
    /// away in every shipped build.
    #[cfg(feature = "testing")]
    pub(crate) fn said(&self) -> Option<String> {
        locked(&self.state).said.clone()
    }

    /// Returns whether a line for a reason waits for its write or is being written, for this host's
    /// own tests. It is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub(crate) fn being_written(&self) -> bool {
        locked(&self.state).offered.is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::{OutputReasons, Said, WAITING, Writer};

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
    /// tells that it has begun, and ends when the case lets it.
    struct Stalled {
        begun: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        taken: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl std::io::Write for Stalled {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let _ = self.begun.send(());
            let _ = self.release.recv();
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
        assert_eq!(
            said.offer(Some("the lock"), true).as_deref(),
            Some("the lock")
        );
        assert_eq!(
            said.offer(Some("the lock"), true),
            None,
            "not again while its line is on its way"
        );
        said.written("the lock");
        assert_eq!(
            said.offer(Some("the lock"), true),
            None,
            "nor once it is written"
        );
        assert_eq!(said.offer(None, true), None, "it goes");
        assert_eq!(
            said.offer(Some("the lock"), true).as_deref(),
            Some("the lock"),
            "and is offered again when it comes back"
        );
        said.written("the lock");
        assert_eq!(
            said.offer(Some("the boundary"), true).as_deref(),
            Some("the boundary"),
            "as is another"
        );
    }

    /// A reason refused after another was written is not taken as said: the volume that refused it
    /// takes it later, and it is written then, once.
    #[test]
    fn a_reason_refused_after_another_was_written_is_offered_until_it_is_written() {
        let mut said = Said::default();
        assert!(said.offer(Some("the lock"), true).is_some());
        said.written("the lock");

        assert!(said.offer(Some("the boundary"), true).is_some());
        said.refused("the boundary");
        assert_eq!(
            said.offer(Some("the boundary"), true).as_deref(),
            Some("the boundary"),
            "the second is offered again at the next pass"
        );
        said.written("the boundary");
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
        assert!(said.offer(Some("a segment"), true).is_some());
        said.written("a segment");
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
        assert!(said.offer(Some("the lock"), true).is_some());
        assert_eq!(said.offer(None, true), None, "it goes while its line waits");
        said.written("the lock");
        assert!(
            said.offer(Some("the lock"), true).is_some(),
            "so it is offered when it comes back"
        );
    }

    /// Lines are written one at a time, in order, and each is told how its write ended.
    #[test]
    fn lines_are_written_in_order_and_each_is_told_how_it_ended() {
        let volume = Volume::new();
        let writer = Writer::start(volume.clone());
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

    /// A write that waits for a reader holds the writer's thread and nothing else: lines are taken
    /// until [`WAITING`] wait, then dropped without the caller waiting, and the waiting lines are
    /// written once the reader comes.
    #[test]
    fn a_write_that_waits_for_a_reader_holds_the_thread_and_nothing_else() {
        let (begun, begun_at) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let taken = std::sync::Arc::default();
        let writer = Writer::start(Stalled {
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
            release.send(()).expect("lets a write end");
        }
        until(|| taken.lock().expect("not poisoned").ends_with(b"line 7\n"));
        let written = String::from_utf8(taken.lock().expect("not poisoned").clone()).expect("text");
        assert!(written.starts_with("first\nline 0\n"), "{written}");
    }

    /// A reason is not taken as said until its line is written, is offered again after a write
    /// that failed, and is not offered a second time while its first line waits.
    #[test]
    fn a_reason_is_said_when_its_line_is_written_and_not_before() {
        let (begun, begun_at) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let taken = std::sync::Arc::default();
        let writer = Writer::start(Stalled {
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

        release.send(()).expect("lets the write end");
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
        let writer = Writer::start(volume.clone());
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

    /// A pass with nothing to say does not ask for the writer, so no thread is started for it.
    #[test]
    fn a_pass_with_nothing_to_say_does_not_ask_for_the_writer() {
        let reasons = OutputReasons::default();
        reasons.say(None, true, || panic!("asked for the writer"));
        reasons.say(None, false, || panic!("asked for the writer"));
    }
}
