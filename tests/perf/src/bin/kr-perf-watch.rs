//! Reads how much work other than a run's own this machine does, for `scripts/bench-all.sh`.
//!
//! ```text
//! kr-perf-watch --run <pid> (--for <seconds> | --until <file>) [--every <seconds>] [--ready <file>]
//! ```
//!
//! It reads the whole machine, creates the `--ready` file, and reads the machine again every
//! `--every` seconds, two by default, until `--for` seconds have passed or the `--until` file
//! exists, and then once more. It then prints `<bound> <average> <allowance>`: the most
//! processors' worth of processor time the machine can have spent on anything but the run in any
//! five seconds from the first reading to the last, the same over all of that time, and how much of
//! the bound the counts' allowances for rounding and trailing make up. Where the readings cannot
//! show that, it prints `unread: <why>` instead. The run is process `--run` and every process
//! descended from it; a run whose process has gone is unread, so a watcher whose run was stopped
//! stops too.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use kr_perf::machine::Machine;
use kr_perf::other_work::{Summary, Tally};

/// The length of the windows other work is bounded over.
const WINDOW: f64 = 5.0;

/// How often the `--until` file is looked for.
const POLL: Duration = Duration::from_millis(50);

const USAGE: &str = "usage: kr-perf-watch --run <pid> (--for <seconds> | --until <file>) \
                     [--every <seconds>] [--ready <file>]";

enum End {
    After(Duration),
    When(PathBuf),
}

struct Options {
    run: u32,
    end: End,
    every: Duration,
    ready: Option<PathBuf>,
}

fn main() -> ExitCode {
    let Some(options) = options(std::env::args().skip(1)) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match watch(&options) {
        Ok(summary) => println!(
            "{:.2} {:.2} {:.2}",
            summary.bound, summary.average, summary.allowance
        ),
        Err(why) => println!("unread: {why}"),
    }
    ExitCode::SUCCESS
}

fn options(mut arguments: impl Iterator<Item = String>) -> Option<Options> {
    let seconds = |text: String| {
        text.parse::<f64>()
            .ok()
            .filter(|seconds| seconds.is_finite() && *seconds > 0.0)
            .map(Duration::from_secs_f64)
    };
    let (mut run, mut end, mut every, mut ready) = (None, None, Duration::from_secs(2), None);
    while let Some(option) = arguments.next() {
        let value = arguments.next()?;
        match option.as_str() {
            "--run" => run = Some(value.parse().ok()?),
            "--for" if end.is_none() => end = Some(End::After(seconds(value)?)),
            "--until" if end.is_none() => end = Some(End::When(value.into())),
            "--every" => every = seconds(value)?,
            "--ready" => ready = Some(value.into()),
            _ => return None,
        }
    }
    Some(Options {
        run: run?,
        end: end?,
        every,
        ready,
    })
}

fn watch(options: &Options) -> Result<Summary, String> {
    let mut machine = Machine::open()?;
    let mut tally = Tally::new(options.run);
    tally.add(&machine.reading()?)?;
    if let Some(ready) = &options.ready {
        std::fs::write(ready, b"")
            .map_err(|error| format!("create {}: {error}", ready.display()))?;
    }
    let started = Instant::now();
    let mut next = started + options.every;
    loop {
        let now = Instant::now();
        let over = match &options.end {
            End::After(length) => now >= started + *length,
            End::When(file) => file.exists(),
        };
        if over {
            break;
        }
        if now >= next {
            tally.add(&machine.reading()?)?;
            // A reading that took longer than the interval moves the next one a whole interval on,
            // rather than taking readings back to back to catch up.
            next += options.every;
            let now = Instant::now();
            if next < now {
                next = now + options.every;
            }
        }
        let wait = match &options.end {
            End::After(length) => (started + *length).min(next),
            End::When(_) => next.min(Instant::now() + POLL),
        };
        std::thread::sleep(wait.saturating_duration_since(Instant::now()));
    }
    tally.add(&machine.reading()?)?;
    tally.summary(WINDOW)
}
