//! Runs the corpus in the terminal this program is started in and writes the record.
//!
//! ```text
//! kr-term-probe --out <record.json> [--launcher <facts.json>]
//! ```
//!
//! Standard input and output must be the terminal to measure. The launcher file is a JSON value the
//! launcher wrote from outside the terminal's own answers (its application, its version and its
//! configuration), and goes into the record with what identifies the account taken out: see
//! `report::keep_private`.

#[cfg(unix)]
mod unix {
    use std::io;
    use std::os::fd::AsFd as _;
    use std::process::ExitCode;
    use std::time::{Duration, Instant};

    use kr_term_probe::corpus;
    use kr_term_probe::replies;
    use kr_term_probe::report::{self, Report};
    use kr_term_probe::run::{self, Terminal};
    use rustix::termios::{OptionalActions, SpecialCodeIndex, Termios};

    /// The longest a read waits for the reply to primary device attributes, in total, and the most
    /// bytes it takes while waiting. A terminal that keeps writing without ever sending the reply
    /// is not waited on for ever.
    const DEADLINE: Duration = Duration::from_secs(10);
    const MOST_BYTES: usize = 64 * 1024;

    /// Raw mode on standard input, read in short slices so the deadline is kept.
    struct Raw {
        saved: Termios,
        buffer: Vec<u8>,
    }

    impl Raw {
        fn enter() -> io::Result<Self> {
            let stdin = io::stdin();
            let saved = rustix::termios::tcgetattr(stdin.as_fd())?;
            let mut raw = saved.clone();
            raw.make_raw();
            raw.special_codes[SpecialCodeIndex::VMIN] = 0;
            // Tenths of a second: each read waits a fifth of a second for a byte, and the deadline
            // above is the total.
            raw.special_codes[SpecialCodeIndex::VTIME] = 2;
            rustix::termios::tcsetattr(stdin.as_fd(), OptionalActions::Flush, &raw)?;
            Ok(Self {
                saved,
                buffer: Vec::new(),
            })
        }
    }

    impl Drop for Raw {
        fn drop(&mut self) {
            let stdin = io::stdin();
            let _ = rustix::termios::tcsetattr(stdin.as_fd(), OptionalActions::Flush, &self.saved);
        }
    }

    impl Terminal for Raw {
        fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            let stdout = io::stdout();
            let mut written = 0;
            while written < bytes.len() {
                written += rustix::io::write(stdout.as_fd(), &bytes[written..])?;
            }
            Ok(())
        }

        fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
            let stdin = io::stdin();
            let mut chunk = [0_u8; 512];
            let started = Instant::now();
            self.buffer.clear();
            while started.elapsed() < DEADLINE && self.buffer.len() < MOST_BYTES {
                let read = rustix::io::read(stdin.as_fd(), &mut chunk)?;
                self.buffer.extend_from_slice(&chunk[..read]);
                if replies::primary_attributes(&self.buffer).is_some() {
                    return Ok(Some(std::mem::take(&mut self.buffer)));
                }
            }
            Ok(None)
        }
    }

    pub fn main() -> ExitCode {
        match run() {
            Ok(summary) => {
                eprintln!("{summary}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("kr-term-probe: {error}");
                ExitCode::FAILURE
            }
        }
    }

    fn run() -> Result<String, Box<dyn std::error::Error>> {
        let mut out = None;
        let mut launcher = serde_json::Value::Null;
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--out" => out = arguments.next(),
                "--launcher" => {
                    let path = arguments.next().ok_or("--launcher needs a file")?;
                    launcher = serde_json::from_str(&std::fs::read_to_string(path)?)?;
                }
                other => return Err(format!("unknown argument {other}").into()),
            }
        }
        let out = out.ok_or("--out <record.json> is required")?;
        if !rustix::termios::isatty(io::stdin().as_fd()) {
            return Err("standard input is not a terminal".into());
        }
        let size = rustix::termios::tcgetwinsize(io::stdin().as_fd())?;
        let (cols, rows) = (u32::from(size.ws_col), u32::from(size.ws_row));
        if cols < 40 || rows < 12 {
            return Err(
                format!("the window is {cols} by {rows}; the corpus needs 40 by 12").into(),
            );
        }

        let (identity, measured) = {
            let mut terminal = Raw::enter()?;
            let identity = run::identify(&mut terminal)?;
            let measured = run::measure_all(&mut terminal, &corpus::steps(cols, rows), cols, rows)?;
            (identity, measured)
        };
        let home = std::env::var("HOME").ok();
        let launcher = report::keep_private(launcher, home.as_deref());
        let report = Report::new(launcher, identity, (cols, rows), measured);
        let mut text = serde_json::to_string_pretty(&report)?;
        text.push('\n');
        std::fs::write(&out, text)?;
        let summary = report.summary;
        let stopped = report
            .stopped
            .as_deref()
            .map_or_else(String::new, |why| format!("; stopped early: {why}"));
        Ok(format!(
            "{} steps: {} agree, {} differ, {} unanswered{stopped}; record in {out}",
            summary.steps, summary.agree, summary.differ, summary.unanswered
        ))
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    unix::main()
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("kr-term-probe measures a Unix terminal; a Windows console is measured separately");
    std::process::ExitCode::FAILURE
}
