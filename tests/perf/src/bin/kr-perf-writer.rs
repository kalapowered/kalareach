//! A program that writes terminal output at a steady rate, for the stress run.
//!
//! `kr-perf-writer <bytes-per-second>` writes lines like a build or an agent printing into its
//! terminal, some of them coloured, twenty times a second, until its terminal goes away. It never
//! writes faster than the rate it was given: when the terminal holds it up it falls behind rather
//! than catching up in a burst, so what reaches the host is at most the rate, and what a view is
//! sent is what the host kept up with.

use std::io::Write as _;
use std::process::ExitCode;
use std::time::{Duration, Instant};

/// How often it writes.
const TICK: Duration = Duration::from_millis(50);

fn main() -> ExitCode {
    let argument = std::env::args().nth(1).unwrap_or_default();
    if argument == "--version" {
        println!("kr-perf-writer {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let Some(rate) = argument.parse::<u64>().ok().filter(|rate| *rate > 0) else {
        eprintln!("usage: kr-perf-writer <bytes-per-second>");
        return ExitCode::from(2);
    };
    let per_tick = i64::try_from(u128::from(rate) * TICK.as_millis() / 1000).unwrap_or(i64::MAX);
    let mut stdout = std::io::stdout().lock();
    // What the rate allows that has not been written yet. A line written past it is owed back from
    // the next tick, so the rate holds on average whatever the lines measure.
    let mut owed: i64 = 0;
    let mut line: u64 = 0;
    let mut chunk = Vec::new();
    let mut next = Instant::now();
    loop {
        owed += per_tick;
        chunk.clear();
        while owed > 0 {
            let before = chunk.len();
            write_line(&mut chunk, line);
            line += 1;
            owed -= i64::try_from(chunk.len() - before).unwrap_or(i64::MAX);
        }
        // A terminal that has gone away is the end of the run.
        if stdout
            .write_all(&chunk)
            .and_then(|()| stdout.flush())
            .is_err()
        {
            return ExitCode::SUCCESS;
        }
        next += TICK;
        let now = Instant::now();
        if next > now {
            std::thread::sleep(next - now);
        } else {
            // Held up past the next tick: start again from now rather than owe a burst.
            next = now;
            owed = 0;
        }
    }
}

/// Appends one line of the kind a build or an agent prints.
fn write_line(chunk: &mut Vec<u8>, line: u64) {
    let crate_number = line % 997;
    let text = match line % 20 {
        0 => format!(
            "\x1b[33mwarning\x1b[0m: unused variable: `value_{line}` --> src/stage_{crate_number}.rs:{}:{}\n",
            line % 400 + 1,
            line % 80 + 1
        ),
        7 => format!(
            "\x1b[1;36m[{:>3}%]\x1b[0m streaming response for request {line}: the next part of the answer arrives here\n",
            line % 101
        ),
        13 => format!("test stage_{crate_number}::case_{line} ... \x1b[32mok\x1b[0m\n"),
        _ => format!(
            "\x1b[1;32m   Compiling\x1b[0m stage-{crate_number:03} v0.{}.{} (/work/stages/stage-{crate_number:03})\n",
            line % 10,
            line % 7
        ),
    };
    chunk.extend_from_slice(text.as_bytes());
}
