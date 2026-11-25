//! The pipe harness of the stand-in agents: a stand-in program started with a script, and the test's
//! end of its pipes, which stands for the worker. The pipe tests and the scenario tests of the
//! case scripts both play against it.

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use kr_e2e_agents::acp_agent::{MARKER_FILE, RECORD_FILE, SCRIPT_FILE};
use serde_json::{Value, json};

/// How long a test waits for a frame that must come.
pub const WITHIN: Duration = Duration::from_secs(10);

/// How long a test waits to show that a frame does not come.
pub const QUIET: Duration = Duration::from_millis(400);

/// A stand-in program started with a script, and the test's end of its pipes.
pub struct Played {
    /// The program.
    pub child: Child,
    /// Its standard input, until the test closes it.
    pub input: Option<ChildStdin>,
    /// The lines of its standard output.
    pub frames: Receiver<String>,
    /// Its working directory.
    pub directory: tempfile::TempDir,
}

impl Played {
    /// Starts `program` with the one argument `--acp`, as the host starts the agent, in a working
    /// directory that holds `script`.
    pub fn start(program: &str, script: &Value) -> Self {
        Self::start_with(program, &["--acp"], script)
    }

    /// Starts `program` with `arguments` in a working directory that holds `script`.
    pub fn start_with(program: &str, arguments: &[&str], script: &Value) -> Self {
        let directory = tempfile::tempdir().expect("a working directory");
        std::fs::write(directory.path().join(SCRIPT_FILE), script.to_string()).expect("the script");
        let mut child = Command::new(program)
            .args(arguments)
            .current_dir(directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("the stand-in starts");
        let input = child.stdin.take();
        let output = child.stdout.take().expect("its standard output");
        let (lines, frames) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { break };
                if lines.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            frames,
            directory,
        }
    }

    /// Sends one frame.
    pub fn send(&mut self, frame: &Value) {
        let input = self.input.as_mut().expect("the input is open");
        writeln!(input, "{frame}").expect("the stand-in reads its input");
        input.flush().expect("the stand-in reads its input");
    }

    /// The next line the stand-in wrote.
    pub fn line(&self) -> String {
        self.frames
            .recv_timeout(WITHIN)
            .unwrap_or_else(|why| panic!("no frame within {WITHIN:?}: {why}"))
    }

    /// The next frame the stand-in wrote.
    pub fn frame(&self) -> Value {
        serde_json::from_str(&self.line()).expect("a frame is json")
    }

    /// Whether the stand-in writes nothing for [`QUIET`].
    pub fn is_quiet(&self) -> bool {
        self.frames.recv_timeout(QUIET).is_err()
    }

    /// The lines of the record, parsed.
    pub fn record(&self) -> Vec<Value> {
        std::fs::read_to_string(self.directory.path().join(RECORD_FILE))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("a record line is json"))
            .collect()
    }

    /// The bytes an `import` step wrote to the marker, or none when it wrote none.
    pub fn marker(&self) -> Option<Vec<u8>> {
        std::fs::read(self.directory.path().join(MARKER_FILE)).ok()
    }

    /// Makes the file of the working directory that a `hold` step waits for.
    pub fn release(&self, name: &str) {
        std::fs::write(self.directory.path().join(name), b"go").expect("the release");
    }

    /// Closes the stand-in's input and returns without waiting for it to end.
    pub fn close_input(&mut self) {
        drop(self.input.take());
    }

    /// The record once it holds a line that says the stand-in received `what`, or what it holds
    /// after [`WITHIN`].
    pub fn record_with_received(&self, what: &str) -> Vec<Value> {
        let deadline = std::time::Instant::now() + WITHIN;
        loop {
            let record = self.record();
            if record.iter().any(|line| line["received"] == what)
                || std::time::Instant::now() > deadline
            {
                return record;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Closes the stand-in's input and waits for it to end.
    pub fn close(&mut self) -> std::process::ExitStatus {
        drop(self.input.take());
        self.child.wait().expect("the stand-in ends")
    }

    /// Sends the two requests every session starts with and reads their answers.
    pub fn open_session(&mut self) {
        self.send(&json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": 1 } }));
        assert_eq!(self.frame()["id"], 1);
        self.send(&json!({ "jsonrpc": "2.0", "id": 2, "method": "session/new", "params": { "cwd": "/", "mcpServers": [] } }));
        assert_eq!(self.frame()["id"], 2);
    }

    /// Sends a prompt of one text block under request number `id`.
    pub fn prompt(&mut self, id: u64, text: &str) {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "session/prompt",
            "params": { "sessionId": "stand-in-session", "prompt": [{ "type": "text", "text": text }] },
        }));
    }

    /// Answers the agent's request number `id` by choosing `option`.
    pub fn choose(&mut self, id: u64, option: &str) {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "outcome": { "outcome": "selected", "optionId": option } },
        }));
    }
}

impl Drop for Played {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The program that stands in for Qoder CLI.
pub const QODER: &str = env!("CARGO_BIN_EXE_acp-qoder-stand-in");

/// The program that stands in for the interpreter that runs Gemini CLI.
pub const GEMINI_NODE: &str = env!("CARGO_BIN_EXE_acp-gemini-stand-in-node");

/// The bytes of the chunk after an upgrade of the installation.
pub const UPGRADED_CHUNK: &[u8] = b"// The chunk after an upgrade.\n";

/// The script package that stands in for Gemini CLI, as this crate keeps it.
pub fn package_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/acp-gemini-package")
}

/// Copies the script package to a new folder and returns the folder.
pub fn installed_package() -> tempfile::TempDir {
    let folder = tempfile::tempdir().expect("an installation folder");
    for name in ["gemini.js", "chunk.js"] {
        std::fs::copy(package_source().join(name), folder.path().join(name))
            .expect("a copy of the package");
    }
    folder
}

/// Starts the interpreter stand-in on the main file of the package in `folder`, as the host does.
pub fn gemini_from(folder: &Path, script: &Value) -> Played {
    let main_file = folder.join("gemini.js");
    let main_file = main_file.to_str().expect("a path of text");
    Played::start_with(GEMINI_NODE, &[main_file, "--acp"], script)
}
