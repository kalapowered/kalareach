//! A clock and a wait that a case moves, for the cases that hold how long a run waits at the most.
//!
//! Time passes on a [`Made`] clock only when a case moves it or when a wait of its own runs out, so
//! what a run waited is read off the clock by a condition and never measured. Nothing here waits for
//! a duration: a wait that runs out moves the clock to the moment it was asked to wait until, and
//! one that is given a message waits for the message and moves nothing.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::Done;

/// How long a wait that is given a message waits for it, which only ends a case whose message never
/// comes. The wait never takes this long when the run is right.
const MESSAGE_GUARD: Duration = Duration::from_secs(30);

/// What one wait of a run is, in the order the run makes them.
#[derive(Clone, Copy)]
pub(crate) enum Wait {
    /// The thread waited for sends: the wait takes its message, and no time passes.
    Message,
    /// The thread waited for never sends: the clock moves to the moment waited until, and the wait
    /// times out. A wait beyond the ones a case lists runs out.
    RunsOut,
}

/// A clock that stands where it is until it is moved.
pub(crate) struct Made {
    start: Instant,
    passed: Cell<Duration>,
    waits: RefCell<VecDeque<Wait>>,
    asked: RefCell<Vec<Duration>>,
}

impl Made {
    /// A clock at its start, whose waits are the given ones, in the order a run makes them.
    pub(crate) fn new(waits: impl IntoIterator<Item = Wait>) -> Self {
        Self {
            start: Instant::now(),
            passed: Cell::new(Duration::ZERO),
            waits: RefCell::new(waits.into_iter().collect()),
            asked: RefCell::new(Vec::new()),
        }
    }

    /// Where the clock began, which is when a case starts its run.
    pub(crate) fn start(&self) -> Instant {
        self.start
    }

    /// The clock's reading.
    pub(crate) fn now(&self) -> Instant {
        self.start + self.passed.get()
    }

    /// How far the clock has moved from its start.
    pub(crate) fn passed(&self) -> Duration {
        self.passed.get()
    }

    /// Moves the clock on: time that something other than a wait takes.
    pub(crate) fn pass(&self, time: Duration) {
        self.passed.set(self.passed.get() + time);
    }

    /// Every moment a run asked a wait to wait until, as how long after the start, in the order it
    /// asked.
    pub(crate) fn asked(&self) -> Vec<Duration> {
        self.asked.borrow().clone()
    }

    /// The wait a run is given: the next one of the clock's list, asked to wait until `by`.
    pub(crate) fn wait(
        &self,
        channel: &Receiver<Done>,
        by: Instant,
    ) -> Result<Done, RecvTimeoutError> {
        let until = by.saturating_duration_since(self.start);
        self.asked.borrow_mut().push(until);
        match self.waits.borrow_mut().pop_front().unwrap_or(Wait::RunsOut) {
            Wait::Message => channel.recv_timeout(MESSAGE_GUARD),
            Wait::RunsOut => {
                self.passed.set(self.passed.get().max(until));
                Err(RecvTimeoutError::Timeout)
            }
        }
    }
}

/// What a clock that a case moves cannot see: a wait that does not go through the wait a run is
/// given. These cases hold that there is none in the code a hook run executes.
#[cfg(test)]
mod waits_only_through_the_seam {
    /// What blocks a thread for a time or until another thread acts, as it is written.
    const BLOCKING: [&str; 11] = [
        "recv_timeout",
        "recv_deadline",
        "sleep",
        "park_timeout",
        "wait_timeout",
        "thread::park",
        ".join(",
        ".recv()",
        ".wait(",
        "wait_while",
        "block_on",
    ];

    /// The lines of `source`, up to its test module, that hold a blocking wait outside a comment,
    /// as the function they are in and the line, leaving out the functions named in `allowed`.
    fn blocking_waits(source: &str, allowed: &[&str]) -> Vec<String> {
        let mut found = Vec::new();
        // The function a line is in, and the line that closes it.
        let mut within: Option<(String, String)> = None;
        let mut previous = "";
        for line in source.lines() {
            if line.trim_end() == "mod tests {" && previous.trim() == "#[cfg(test)]" {
                break;
            }
            previous = line;
            let code = line.find("//").map_or(line, |at| &line[..at]);
            let mut opened_here = false;
            if within.is_none() {
                let indent = &line[..line.len() - line.trim_start().len()];
                let item = line.trim_start();
                let item = item.strip_prefix("pub(crate) ").unwrap_or(item);
                let item = item.strip_prefix("pub ").unwrap_or(item);
                if let Some(rest) = item.strip_prefix("fn ") {
                    let name = rest.split(['(', '<']).next().unwrap_or(rest);
                    within = Some((name.to_owned(), format!("{indent}}}")));
                    opened_here = true;
                }
            }
            let name = within.as_ref().map_or("", |(name, _)| name.as_str());
            if !allowed.contains(&name) && BLOCKING.iter().any(|word| code.contains(word)) {
                found.push(format!("in `{name}`: {}", line.trim()));
            }
            // A function that opens and closes on its own line is through at once.
            let one_line = opened_here && line.trim_end().ends_with('}');
            if one_line
                || within
                    .as_ref()
                    .is_some_and(|(_, closing)| line.trim_end() == closing)
            {
                within = None;
            }
        }
        found
    }

    /// A hook run waits only through the wait it is given, which is what a clock that a case moves
    /// holds: there is no other wait in what the run executes, so no case can pass with a wait it
    /// cannot see. `observe` is the run's work, which the run abandons at its deadline; `wait_by`
    /// is the system's wait that a run is given; `start` and `finish` are the report writer's own
    /// thread and its closing wait, which the channel server runs and a hook run never does.
    #[test]
    fn a_hook_run_waits_only_through_the_wait_it_is_given() {
        for (file, source, allowed) in [
            ("hook.rs", include_str!("hook.rs"), &["observe"][..]),
            (
                "lib.rs",
                include_str!("lib.rs"),
                &["wait_by", "start", "finish"][..],
            ),
        ] {
            let found = blocking_waits(source, allowed);
            assert!(
                found.is_empty(),
                "{file} waits other than through the wait a run is given: {found:#?}"
            );
        }
    }

    /// The scan finds each word it looks for, in any function that is not allowed, and passes a
    /// comment, an allowed function by its name, and a test module.
    #[test]
    fn the_scan_finds_every_blocking_wait_and_passes_a_comment() {
        for word in BLOCKING {
            let wait = format!("fn run_with() {{\n    let _ = outcome {word} 5;\n}}\n");
            assert_eq!(blocking_waits(&wait, &[]).len(), 1, "`{word}` is found");
            let nested =
                format!("impl Run {{\n    fn finish(&self) {{\n        {word}\n    }}\n}}\n");
            assert_eq!(
                blocking_waits(&nested, &[]).len(),
                1,
                "`{word}` in a method is found"
            );
            assert_eq!(
                blocking_waits(&nested, &["finish"]),
                Vec::<String>::new(),
                "`{word}` in an allowed function passes"
            );
            let other =
                format!("fn run_with() {{\n    {word}\n}}\nfn wait_by() {{\n    {word}\n}}\n");
            assert_eq!(
                blocking_waits(&other, &["wait_by"]),
                ["in `run_with`: ".to_owned() + word],
                "only the function that is not allowed is found"
            );
            for comment in [
                format!("    // {word}"),
                format!("    /// {word}"),
                format!("    x(); // {word}"),
            ] {
                let source = format!("fn run_with() {{\n{comment}\n}}\n");
                assert!(
                    blocking_waits(&source, &[]).is_empty(),
                    "`{comment}` is a comment"
                );
            }
            let after_a_short_one = format!("fn quick() {{}}\nfn wait_by() {{\n    {word}\n}}\n");
            assert!(
                blocking_waits(&after_a_short_one, &["wait_by"]).is_empty(),
                "a function on one line does not hold the next one's name"
            );
            let tests = format!("fn run_with() {{}}\n#[cfg(test)]\nmod tests {{\n    {word}\n}}\n");
            assert!(
                blocking_waits(&tests, &[]).is_empty(),
                "`{word}` in the test module passes"
            );
            let item = format!("static WAIT: u64 = {word};\n");
            assert_eq!(
                blocking_waits(&item, &[]).len(),
                1,
                "`{word}` outside a function is found"
            );
        }
    }
}
