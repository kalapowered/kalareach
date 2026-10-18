//! Reaching a worker of another release through that release's own forwarder.
//!
//! An application's settings start the forwarder an update has made current, and a worker keeps
//! running across the update that made it so. A worker of a release whose bridge exchange this
//! forwarder does not speak is reached by the forwarder of that worker's own release: this one
//! replaces itself with it, before it reads anything, so the other forwarder is given the same
//! standard input, output and arguments, and starts already holding the worker's release.
//!
//! The decision reads files and nothing else: the registration, which names the release the
//! launch's worker runs, and that release's manifest, which states its level. A forwarder of the
//! worker's release is started only where the worker admits it
//! ([`kr_protocol::retained::FIRST_LEVEL_ADMITTING_OWN_FORWARDER`]); a worker below that level
//! admits only the forwarder reached through `current`, and is spoken to directly.
//!
//! A forwarder started this way is told so by [`MARKER`], and never starts another, so the hand-off
//! cannot loop. For a hook the marker also carries the moment its deadline ends on the machine's
//! continuous clock, which no step of the wall clock can move, so the time spent choosing, pinning
//! and starting counts against the one deadline the application gave the hook.

use std::time::{Duration, Instant};

use kr_ipc::install::Program;
use kr_protocol::retained::FIRST_LEVEL_ADMITTING_OWN_FORWARDER;
use kr_protocol::update::{CompatibilityLevel, THIS_LEVEL};

use crate::registration::{self, Paths};

/// The variable a forwarder started in place of another is given.
///
/// Its value is the release of the forwarder that started it, and for a hook a semicolon and the
/// moment, in milliseconds on the continuous clock, that the hook's deadline ends.
pub const MARKER: &str = "KR_HELPER_FROM";

/// The least of its deadline a hook must have left to be handed to another forwarder: a start that
/// might not finish before the deadline would leave the application two answers or none.
pub const MINIMUM_LEFT: Duration = Duration::from_millis(100);

/// What a marker says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Marker {
    /// The release of the forwarder that handed over.
    pub from: String,
    /// When the hook's deadline ends, in milliseconds on the continuous clock; none for a
    /// forwarder that serves for as long as its session does.
    pub deadline_ms: Option<u64>,
}

impl Marker {
    /// The marker as the variable carries it.
    #[must_use]
    pub fn render(&self) -> String {
        match self.deadline_ms {
            Some(deadline) => format!("{};{deadline}", self.from),
            None => self.from.clone(),
        }
    }

    /// Reads the variable's value; none for a value that is not a marker.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (from, deadline_ms) = match text.split_once(';') {
            Some((from, deadline)) => (from, Some(deadline.parse().ok()?)),
            None => (text, None),
        };
        kr_protocol::update::ReleaseName::new(from).ok()?;
        Some(Self {
            from: from.to_owned(),
            deadline_ms,
        })
    }

    /// The marker this process was started with, where it was started in place of another
    /// forwarder.
    #[must_use]
    pub fn of_this_process() -> Option<Self> {
        std::env::var(MARKER)
            .ok()
            .and_then(|value| Self::parse(&value))
    }
}

/// Where a hook stands against its deadline, given the marker it was started with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// The deadline ended before this forwarder started.
    Passed,
    /// This much of the deadline is left.
    Left(Duration),
}

impl Marker {
    /// What is left of the deadline, given what the continuous clock says now.
    #[must_use]
    pub fn standing(&self, now_ms: u64) -> Option<Standing> {
        self.deadline_ms.map(|deadline| {
            if deadline > now_ms {
                Standing::Left(Duration::from_millis(deadline - now_ms))
            } else {
                Standing::Passed
            }
        })
    }
}

/// Replaces this forwarder with the one of the release its launch's worker runs, where that is
/// right, and returns only when it is not or when the replacement failed.
///
/// `deadline` is the hook's own: when it began and how long it has altogether. A forwarder with no
/// deadline passes `None`. The reasons to go on directly are not errors: no registration, a worker
/// of this release, a worker below the level that admits the other forwarder, a release the store
/// lacks or is removing, a forwarder that is not there. A failed replacement is returned, so the
/// caller can say so.
pub fn hand_over(
    registration_wait: Duration,
    deadline: Option<(Instant, Duration)>,
) -> Option<String> {
    if Marker::of_this_process().is_some() {
        return None;
    }
    let paths = Paths::from_environment()?;
    let this = kr_ipc::install::this_process().ok()?;
    let own = this.release()?;
    let store = this.store()?;
    let left = deadline.map(|(started, whole)| whole.saturating_sub(started.elapsed()));
    let wait = left.map_or(registration_wait, |left| registration_wait.min(left));
    let target = registration::release_of(&paths, wait).ok().flatten()?;
    if &target == own {
        return None;
    }
    let pin = store.pin(&target).ok().flatten()?;
    let level = CompatibilityLevel::of(pin.manifest().protocol_version);
    if level == THIS_LEVEL || level < FIRST_LEVEL_ADMITTING_OWN_FORWARDER {
        return None;
    }
    let program = store
        .release_directory(&target)
        .join("bin")
        .join(Program::Hook.file_name());
    if !program.is_file() {
        return None;
    }
    let deadline_ms = match deadline {
        Some((started, whole)) => Some(deadline_on_the_machine_clock(
            kr_ipc::clock::boot_elapsed_ms,
            || whole.saturating_sub(started.elapsed()),
        )?),
        None => None,
    };
    let marker = Marker {
        from: own.as_str().to_owned(),
        deadline_ms,
    };
    let mut command = std::process::Command::new(&program);
    command
        .args(std::env::args_os().skip(1))
        .env(MARKER, marker.render());
    let error = replace_unless_answered(&ANSWERED, || pin.exec(&mut command))?;
    Some(format!(
        "{} could not be started in this forwarder's place: {error}",
        program.display()
    ))
}

/// Whether the hook has written its answer: the one thing that ends the choice to start another
/// forwarder in its place. A hook that has answered because its time ran out must not be replaced by
/// one that answers again.
static ANSWERED: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

/// Records that this hook is answering, and waits first for a replacement that is being started
/// to start or to fail. A replacement that starts takes the process with it, so the answer is
/// written only by the hook that is left.
pub fn claim_answer() {
    claim(&ANSWERED);
}

/// Whether this hook has claimed its answer.
#[cfg(test)]
pub(crate) fn has_answered() -> bool {
    *ANSWERED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn claim(answered: &std::sync::Mutex<bool>) {
    *answered
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
}

/// Starts the replacement with `exec` unless the answer has been claimed, and holds the claim from
/// being made while it starts: `exec` returns only when it failed, and the error is returned.
fn replace_unless_answered(
    answered: &std::sync::Mutex<bool>,
    exec: impl FnOnce() -> std::io::Error,
) -> Option<std::io::Error> {
    let answered = answered
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if *answered {
        return None;
    }
    Some(exec())
}

/// The moment the continuous clock reaches the end of a deadline kept on another clock, given the
/// reading of the continuous clock and what is left of the deadline.
///
/// The continuous clock is read first and what is left is measured after, so that a pause between
/// the two shortens the deadline instead of lengthening it. None when too little is left to start
/// another forwarder in it ([`MINIMUM_LEFT`]).
fn deadline_on_the_machine_clock(
    machine_now: impl FnOnce() -> u64,
    left: impl FnOnce() -> Duration,
) -> Option<u64> {
    let anchor = machine_now();
    let left = left();
    if left < MINIMUM_LEFT {
        return None;
    }
    kr_ipc::clock::transferred_deadline(anchor, left)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// The continuous clock is read before what is left of the deadline is measured, whatever the
    /// two readings are, and a deadline with less than the least left is not carried over.
    #[test]
    fn the_machine_clock_is_read_before_what_is_left_is_measured() {
        let readings = RefCell::new(Vec::new());
        let carried = deadline_on_the_machine_clock(
            || {
                readings.borrow_mut().push("machine");
                7_000
            },
            || {
                readings.borrow_mut().push("left");
                Duration::from_millis(300)
            },
        );
        assert_eq!(*readings.borrow(), ["machine", "left"]);
        assert_eq!(carried, Some(7_300));
        assert_eq!(
            deadline_on_the_machine_clock(|| 7_000, || MINIMUM_LEFT - Duration::from_millis(1)),
            None
        );
    }

    /// A hook that has answered is not replaced, and an answer waits for a replacement that is
    /// being started: only one of the two answers.
    #[test]
    fn a_hook_that_has_answered_is_not_replaced_and_an_answer_waits_for_a_replacement_in_progress()
    {
        let answered = std::sync::Mutex::new(false);
        let events = std::sync::Mutex::new(Vec::new());
        let (inside_tx, inside) = std::sync::mpsc::channel();
        let (go, wait) = std::sync::mpsc::channel::<()>();
        std::thread::scope(|scope| {
            let (answered, events) = (&answered, &events);
            scope.spawn(move || {
                let failed = replace_unless_answered(answered, || {
                    inside_tx.send(()).expect("told");
                    wait.recv().expect("let go");
                    events.lock().unwrap().push("replacement failed");
                    std::io::Error::other("it did not start")
                });
                assert!(failed.is_some());
            });
            inside.recv().expect("the replacement is being started");
            scope.spawn(move || {
                claim(answered);
                events.lock().unwrap().push("answered");
            });
            go.send(()).expect("let go");
        });
        assert_eq!(*events.lock().unwrap(), ["replacement failed", "answered"]);

        let started = std::cell::Cell::new(false);
        let replaced = replace_unless_answered(&answered, || {
            started.set(true);
            std::io::Error::other("started")
        });
        assert!(replaced.is_none() && !started.get());
    }
}
