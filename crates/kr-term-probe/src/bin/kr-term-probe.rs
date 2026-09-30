//! Runs the corpus in the terminal this program is started in and writes the record.
//!
//! ```text
//! kr-term-probe --out <record.json> [--launcher <facts.json>]
//! ```
//!
//! Standard input and output must be the terminal to measure. The launcher file is a JSON value the
//! launcher wrote from outside the terminal's own answers (its application, its version and its
//! configuration), and goes into the record unchanged.

#[cfg(unix)]
mod unix {
    use std::io;
    use std::os::fd::AsFd as _;
    use std::process::ExitCode;

    use kr_term_probe::corpus;
    use kr_term_probe::replies;
    use kr_term_probe::report::Report;
    use kr_term_probe::run::{self, Terminal};
    use rustix::termios::{OptionalActions, SpecialCodeIndex, Termios};

    /// Raw mode on standard input, with a read that gives up after five seconds without a byte.
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
            // Tenths of a second: a read that hears nothing for five seconds is a terminal that
            // will not answer, and the step is recorded as unanswered.
            raw.special_codes[SpecialCodeIndex::VTIME] = 50;
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
            self.buffer.clear();
            loop {
                let read = rustix::io::read(stdin.as_fd(), &mut chunk)?;
                if read == 0 {
                    return Ok(None);
                }
                self.buffer.extend_from_slice(&chunk[..read]);
                if replies::primary_attributes(&self.buffer).is_some() {
                    return Ok(Some(std::mem::take(&mut self.buffer)));
                }
            }
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

        let (identity, outcomes) = {
            let mut terminal = Raw::enter()?;
            let identity = run::identify(&mut terminal)?;
            let outcomes = run::measure_all(&mut terminal, &corpus::steps(cols, rows), cols, rows)?;
            (identity, outcomes)
        };
        let report = Report::new(launcher, identity, (cols, rows), outcomes);
        let mut text = serde_json::to_string_pretty(&report)?;
        text.push('\n');
        std::fs::write(&out, text)?;
        let summary = report.summary;
        Ok(format!(
            "{} steps: {} agree, {} differ, {} unanswered; record in {out}",
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
