//! A terminal a person types at: a program run on a pseudo-terminal that answers the questions an
//! attaching `kr` asks it, with what it shows kept so a case can wait for a line of it.

use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};

/// How long a wait for something to appear is given. It fails when the thing never does.
const WAIT: Duration = Duration::from_secs(120);

/// What a terminal that implements the Kitty keyboard protocol at flags 5 and `modifyOtherKeys` at
/// level 2 answers, followed by the device attributes that end the exchange: `kr attach` asks the
/// outer terminal what it has negotiated before it changes anything.
const ANSWER: &[u8] = b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c";

/// The question every profile asks first, which is what the answer waits for.
const QUESTION: &[u8] = b"\x1b[c";

pub struct Terminal {
    seen: Arc<Mutex<Vec<u8>>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    child: Mutex<Box<dyn Child + Send + Sync>>,
    _master: Box<dyn MasterPty + Send>,
}

impl Terminal {
    /// Runs `command` on a new terminal, 80 columns by 24 rows.
    pub fn run(mut command: CommandBuilder, directory: &Path) -> Self {
        command.cwd(directory);
        command.env("TERM", "xterm-256color");
        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("a pseudo-terminal");
        let child = pty
            .slave
            .spawn_command(command)
            .expect("the program starts");
        drop(pty.slave);
        let mut reader = pty.master.try_clone_reader().expect("a reader");
        let writer = Arc::new(Mutex::new(pty.master.take_writer().expect("a writer")));
        let seen = Arc::new(Mutex::new(Vec::new()));
        {
            let seen = Arc::clone(&seen);
            let writer = Arc::clone(&writer);
            std::thread::spawn(move || {
                let mut answered = false;
                let mut buffer = [0_u8; 4096];
                while let Ok(read) = reader.read(&mut buffer) {
                    if read == 0 {
                        break;
                    }
                    let mut seen = seen.lock().expect("the output is not poisoned");
                    seen.extend_from_slice(&buffer[..read]);
                    if !answered && seen.windows(QUESTION.len()).any(|w| w == QUESTION) {
                        answered = true;
                        let mut writer = writer.lock().expect("the writer is not poisoned");
                        let _ = writer.write_all(ANSWER).and_then(|()| writer.flush());
                    }
                }
            });
        }
        Self {
            seen,
            writer,
            child: Mutex::new(child),
            _master: pty.master,
        }
    }

    /// Types a line that prints a different marker each time until a shell at the other end has
    /// run one, which says the attachment takes input.
    pub async fn ready(&self) {
        let started = Instant::now();
        let mut attempt = 0_u32;
        loop {
            attempt += 1;
            self.type_line(&format!("echo READY-$(({attempt}*7))-X"));
            let marker = format!("READY-{}-X", attempt * 7);
            for _ in 0..50 {
                if self.text().contains(&marker) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(
                started.elapsed() < WAIT,
                "the terminal took no input in {:?}; it shows: {}",
                started.elapsed(),
                self.text().escape_debug()
            );
        }
    }

    /// Types one line, as a person does.
    pub fn type_line(&self, line: &str) {
        let mut writer = self.writer.lock().expect("the writer is not poisoned");
        writer
            .write_all(format!("{line}\n").as_bytes())
            .and_then(|()| writer.flush())
            .expect("the terminal takes the line");
    }

    /// Everything the terminal has shown, as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().expect("the output is not poisoned")).into_owned()
    }

    /// Waits until the program has ended, and returns its exit code.
    pub async fn ended(&self) -> u32 {
        let started = Instant::now();
        loop {
            let status = self
                .child
                .lock()
                .expect("the child is not poisoned")
                .try_wait()
                .expect("the program's state is readable");
            if let Some(status) = status {
                return status.exit_code();
            }
            assert!(
                started.elapsed() < WAIT,
                "the program ran on for {:?}; the terminal shows: {}",
                started.elapsed(),
                self.text().escape_debug()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Waits until the terminal has shown `marker`, and returns what it showed up to the end of it.
    pub async fn expect(&self, marker: &str) -> String {
        let started = Instant::now();
        loop {
            let shown = self.text();
            if let Some(at) = shown.find(marker) {
                return shown[..at + marker.len()].to_owned();
            }
            assert!(
                started.elapsed() < WAIT,
                "waited {:?} for {marker:?}; the terminal shows: {}",
                started.elapsed(),
                shown.escape_debug()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // A program that has ended was reaped, and its number may be another process's by now.
        if let Ok(child) = self.child.get_mut()
            && matches!(child.try_wait(), Ok(None))
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
