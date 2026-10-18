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
        Some((started, whole)) => {
            let left = whole.saturating_sub(started.elapsed());
            if left < MINIMUM_LEFT {
                return None;
            }
            let left_ms = u64::try_from(left.as_millis()).unwrap_or(u64::MAX);
            Some(kr_ipc::clock::boot_elapsed_ms().saturating_add(left_ms))
        }
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
    let error = pin.exec(&mut command);
    Some(format!(
        "{} could not be started in this forwarder's place: {error}",
        program.display()
    ))
}
