//! The launcher's side of a launch on Windows, played over the real private frames.
//!
//! The Windows launcher presents its environment, creates the program held and tells the backend
//! its process, and reads the backend's answer under a clock of its own. Until that launcher exists
//! the backend's wire cases play it from here: the same pipe, the same record and credential, the
//! same frames in the same order, and a real program, created held, whose process the backend
//! reads from the kernel.
//!
//! The launcher has to be a process of its own. The backend admits a launcher only when the
//! session's root shell started it after the backend was established, and it shows a program only
//! when the launcher started that. A case plays the root shell and starts the launcher as its child
//! through [`Launcher::start`]; the launcher is this test program started again, which plays the
//! role [`play_when_asked`] gives it and reports what it saw. A test file that uses this declares
//! the one case that gives the program its role, named [`ROLE_CASE`]:
//!
//! ```ignore
//! #[test]
//! fn the_launcher_fixture_plays_its_role() {
//!     windows_launcher::play_when_asked();
//! }
//! ```
//!
//! The case does nothing in an ordinary run: only the program a [`Launcher`] starts is asked.

#![cfg(windows)]

use std::collections::BTreeMap;
use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

/// How long the launcher counts the commit from before it writes `going`, which is the Windows
/// launcher's own `COMMIT_DEADLINE` (kr-hook `launch.rs`).
pub const COMMIT_DEADLINE: Duration = Duration::from_secs(4);

/// How long the launcher gives the backend to admit it: the connect, the hello and the admission,
/// which is the Windows launcher's own `ADMISSION_DEADLINE`.
pub const ADMISSION_DEADLINE: Duration = Duration::from_secs(6);

/// How much longer than [`COMMIT_DEADLINE`] the launcher keeps reading for the answer, so that an
/// answer that comes late is read, and its time is known, and a case can say it was late.
pub const LATE_GRACE: Duration = Duration::from_secs(10);

/// The name of the case a test file declares so that the program a launcher is started from has a
/// role to play.
pub const ROLE_CASE: &str = "the_launcher_fixture_plays_its_role";

/// The variable that asks a program started again to play the launcher, with what it plays.
const ROLE: &str = "KR_LAUNCHER_FIXTURE";

/// What the launcher process says, one line each, after this.
const REPORT: &str = "kr-launcher-fixture ";

/// How long the case waits for the launcher to say something it was asked for.
const LIVENESS: Duration = Duration::from_secs(60);

/// What the launcher presents, and how it behaves.
#[derive(Clone, Debug)]
pub struct Launch {
    /// The registration the backend's answer names, beside which the launch record and the
    /// credential are.
    pub registration: PathBuf,
    /// The program the backend was established for, as it presents it and as it creates it.
    pub executable: PathBuf,
    /// The argument vector presented, with the program's own name first, as the backend answered
    /// it.
    pub arguments: Vec<String>,
    /// The environment presented, which a backend that starts a server starts it with.
    pub environment: Vec<(String, String)>,
    /// The directory the launcher is in, which the program inherits and `going` names.
    pub directory: PathBuf,
    /// What the program is created with after its name. Where it is not given, it is the presented
    /// vector without its first element and with the record's gateway address in place of
    /// `{gateway}`, as the launcher does.
    pub program_arguments: Option<Vec<String>>,
    /// Whether the launcher starts the program once the backend has committed, and says so.
    pub resume: bool,
}

impl Launch {
    /// A launch of `executable` with the vector `arguments`, registered at `registration`,
    /// presenting this process's own environment, in this process's own directory, and not starting
    /// the program.
    #[must_use]
    pub fn new(registration: &Path, executable: &Path, arguments: &[String]) -> Self {
        Self {
            registration: registration.to_path_buf(),
            executable: executable.to_path_buf(),
            arguments: arguments.to_vec(),
            environment: process_environment(),
            directory: std::env::current_dir().expect("this process's directory"),
            program_arguments: None,
            resume: false,
        }
    }
}

/// This process's environment, as text, which a launcher presents to a backend that asks for it.
///
/// The console's own per-drive entries, whose names start with `=`, are left out, and so is any
/// variable that is not text: a case that presents either states it itself.
#[must_use]
pub fn process_environment() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(name, _)| !name.starts_with('='))
        .collect()
}

/// How the backend received the launcher's hello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// It answered `admitted`.
    Admitted,
    /// It closed the connection without a word, which is how a launch it refuses is answered.
    Closed,
    /// It answered something else, which is given.
    Other(String),
    /// The launcher could not present itself at all, for the reason given.
    Failed(String),
}

/// What the backend said after `going`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// `committed`.
    Committed,
    /// `failed`, with the reason it gave.
    Failed(String),
    /// The connection closed with nothing said.
    Closed,
    /// Something that is neither, which is given.
    Other(String),
    /// Nothing, and the connection stayed open, until the launcher stopped waiting.
    Nothing,
}

/// What a launcher saw, from its own side.
#[derive(Clone, Debug)]
pub struct Played {
    /// How the backend received the hello.
    pub admission: Admission,
    /// The process the launcher created and named in `going`, where it got that far.
    pub program: Option<u32>,
    /// What the backend answered, where the launcher got as far as to wait for an answer.
    pub answer: Option<Answer>,
    /// How long after the launcher began counting, which is before it wrote `going`, the answer was
    /// read. It is how long the launcher waited, where there was none.
    pub after: Duration,
    /// Whether the launcher started the program afterwards.
    pub resumed: bool,
}

impl Played {
    /// Whether the answer was read within [`COMMIT_DEADLINE`] of the count's beginning, which is
    /// the only time a launcher takes an answer into account.
    #[must_use]
    pub fn in_time(&self) -> bool {
        self.after <= COMMIT_DEADLINE
    }
}

/// A launcher a case started, and what it has said.
pub struct Launcher {
    process: Child,
    lines: tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>,
    // Kept so that the launcher's standard input stays open until the case lets it go.
    input: Option<std::process::ChildStdin>,
}

impl Launcher {
    /// Starts the launcher as this process's child, to play `launch`.
    ///
    /// # Panics
    ///
    /// Panics when the program cannot be started again.
    #[must_use]
    pub fn start(launch: &Launch) -> Self {
        let plan = serde_json::json!({
            "registration": launch.registration.to_str().expect("a text path"),
            "executable": launch.executable.to_str().expect("a text path"),
            "arguments": launch.arguments,
            "environment": launch.environment.iter().cloned().collect::<BTreeMap<_, _>>(),
            "directory": launch.directory.to_str().expect("a text path"),
            "program_arguments": launch.program_arguments,
            "resume": launch.resume,
        });
        let mut process = Command::new(std::env::current_exe().expect("this test's program"))
            .args(["--exact", ROLE_CASE, "--nocapture", "--test-threads=1"])
            .env(ROLE, plan.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the launcher starts");
        let input = process.stdin.take();
        let output = process.stdout.take().expect("the launcher's output");
        let (sender, lines) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(output).lines() {
                let Ok(line) = line else { return };
                if let Some(report) = line.strip_prefix(REPORT)
                    && let Ok(value) = serde_json::from_str(report)
                {
                    let _ = sender.send(value);
                }
            }
        });
        Self {
            process,
            lines,
            input,
        }
    }

    /// Waits for the launcher to play to its end, and returns what it saw: until it has read an
    /// answer, or been refused.
    ///
    /// # Panics
    ///
    /// Panics when the launcher ends or says nothing in time.
    pub async fn played(&mut self) -> Played {
        let mut played = Played {
            admission: Admission::Failed("the launcher said nothing of it".to_owned()),
            program: None,
            answer: None,
            after: Duration::ZERO,
            resumed: false,
        };
        loop {
            let said = tokio::time::timeout(LIVENESS, self.lines.recv())
                .await
                .expect("the launcher said something in time")
                .expect("the launcher went on until it had played");
            match said["event"].as_str().unwrap_or_default() {
                "not_presented" => {
                    played.admission = Admission::Failed(text(&said, "why"));
                    return played;
                }
                "admission" => {
                    played.admission = match said["answer"].as_str().unwrap_or_default() {
                        "admitted" => Admission::Admitted,
                        "closed" => Admission::Closed,
                        _ => Admission::Other(text(&said, "read")),
                    };
                    if played.admission != Admission::Admitted {
                        return played;
                    }
                }
                "created" => {
                    played.program = said["program"].as_u64().and_then(|p| p.try_into().ok())
                }
                "answer" => {
                    played.answer = Some(match said["answer"].as_str().unwrap_or_default() {
                        "committed" => Answer::Committed,
                        "failed" => Answer::Failed(text(&said, "reason")),
                        "closed" => Answer::Closed,
                        "nothing" => Answer::Nothing,
                        _ => Answer::Other(text(&said, "read")),
                    });
                    played.after = Duration::from_micros(said["after_us"].as_u64().unwrap_or(0));
                    if played.answer != Some(Answer::Committed) || !self_resumes(&said) {
                        return played;
                    }
                }
                "resumed" => {
                    played.resumed = true;
                    return played;
                }
                _ => {}
            }
        }
    }

    /// Lets the launcher go: it ends the program it created and itself.
    pub async fn end(mut self) {
        drop(self.input.take());
        let ended = Instant::now() + Duration::from_secs(10);
        while Instant::now() < ended {
            if matches!(self.process.try_wait(), Ok(Some(_))) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl Drop for Launcher {
    fn drop(&mut self) {
        drop(self.input.take());
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Whether the launcher that said this was to start the program, which it says on its answer.
fn self_resumes(answer: &serde_json::Value) -> bool {
    answer["resumes"].as_bool().unwrap_or(false)
}

fn text(value: &serde_json::Value, name: &str) -> String {
    value[name].as_str().unwrap_or_default().to_owned()
}

/// Plays the launcher when this program was started to, and returns at once when it was not.
///
/// It reports each step to its standard output, one line each, for [`Launcher`] to read; it ends
/// when its standard input is closed, and the program it created ends with it. The program has no
/// standard input and no output of its own.
///
/// # Panics
///
/// Panics when the launch cannot be played: the record cannot be read, the pipe cannot be reached,
/// or a frame cannot be written.
pub fn play_when_asked() {
    let Some(plan) = std::env::var_os(ROLE) else {
        return;
    };
    let plan: serde_json::Value =
        serde_json::from_str(plan.to_str().expect("a text plan")).expect("a plan");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(play(&plan));
}

/// Says one thing to the case.
fn report(event: serde_json::Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{REPORT}{event}");
    let _ = out.flush();
}

/// The frame a backend answers an admitted launcher with, and the ones after.
async fn play(plan: &serde_json::Value) {
    let registration = Path::new(plan["registration"].as_str().expect("a registration"));
    let directory = registration.parent().expect("the registration's directory");
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(directory.join(kr_worker::broker::commands::LAUNCH_RECORD_FILE))
            .expect("the launch record"),
    )
    .expect("a launch record");
    let credential = std::fs::read_to_string(
        record["credential"]
            .as_str()
            .expect("the record names a credential"),
    )
    .expect("the credential")
    .trim()
    .to_owned();
    let pipe = record["endpoint"]
        .as_str()
        .and_then(|endpoint| endpoint.strip_prefix(r"\\.\pipe\"))
        .expect("the record names a local pipe");
    let address = kr_ipc::paths::Endpoint::from_name(pipe).expect("a pipe's name");

    let began_connecting = Instant::now();
    let connected = tokio::time::timeout(
        ADMISSION_DEADLINE,
        kr_ipc::endpoint::Connection::connect(&address),
    )
    .await;
    let connection = match connected {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            report(serde_json::json!({"event": "not_presented", "why": error.to_string()}));
            return;
        }
        Err(_) => {
            report(
                serde_json::json!({"event": "not_presented", "why": "the pipe did not accept in time"}),
            );
            return;
        }
    };
    let (reader, mut writer) = tokio::io::split(connection);
    let mut reader = tokio::io::BufReader::new(reader);

    let identity = kr_ipc::identity::process_start_identity(std::process::id())
        .expect("this process is identified");
    let hello = serde_json::json!({ "kr_launch": {
        "credential": credential,
        "pid": identity.pid.get(),
        "start": identity.start_value.get(),
        "executable": plan["executable"],
        "arguments": plan["arguments"],
        "environment": plan["environment"],
    }});
    writer
        .write_all(format!("{hello}\n").as_bytes())
        .await
        .expect("the hello is written");
    writer.flush().await.expect("the hello is flushed");
    let admission_left = ADMISSION_DEADLINE.saturating_sub(began_connecting.elapsed());
    let (admission, read) = read_line(&mut reader, admission_left).await;
    let admitted = read
        .as_deref()
        .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .is_some_and(|frame| frame["kr_launch"]["admitted"] == true);
    report(serde_json::json!({
        "event": "admission",
        "answer": if admitted { "admitted" } else { admission },
        "read": read,
    }));
    if !admitted {
        return;
    }

    // The program is created before the backend is told, held, and in a job that ends it with this
    // launcher, so that the backend can name it and nothing of it runs yet.
    let job = kr_worker::windows::job::AgentJob::create_owning().expect("the launcher's job");
    let executable = Path::new(plan["executable"].as_str().expect("an executable"));
    let presented: Vec<String> = plan["arguments"]
        .as_array()
        .expect("a vector")
        .iter()
        .map(|argument| argument.as_str().expect("text").to_owned())
        .collect();
    let arguments: Vec<String> = match plan["program_arguments"].as_array() {
        Some(given) => given
            .iter()
            .map(|argument| argument.as_str().expect("text").to_owned())
            .collect(),
        None => presented
            .iter()
            .skip(1)
            .map(|argument| match record["gateway"].as_str() {
                Some(gateway) if argument == "{gateway}" => gateway.to_owned(),
                _ => argument.clone(),
            })
            .collect(),
    };
    let working = plan["directory"].as_str().expect("a directory");
    let mut command = Command::new(executable);
    command
        .args(&arguments)
        .current_dir(working)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for variable in record["variables"].as_array().into_iter().flatten() {
        command.env(
            variable["name"].as_str().expect("a name"),
            variable["value"].as_str().expect("a value"),
        );
    }
    let mut program = kr_ipc::memory_limit::start_held(&mut command)
        .spawn()
        .expect("the program is created held");
    job.assign(program.id())
        .expect("the program is put in the launcher's job");
    report(serde_json::json!({"event": "created", "program": program.id()}));

    // The count is from before `going` is written, as the launcher counts it, and covers the write
    // and the wait for the answer.
    let began = Instant::now();
    let going = serde_json::json!({ "kr_launch": {
        "going": true, "program": program.id(), "directory": working,
    }});
    writer
        .write_all(format!("{going}\n").as_bytes())
        .await
        .expect("going is written");
    writer.flush().await.expect("going is flushed");
    let (kind, read) = read_line(&mut reader, COMMIT_DEADLINE + LATE_GRACE).await;
    let after = began.elapsed();
    let frame = read
        .as_deref()
        .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok());
    let launch = frame.as_ref().map(|frame| &frame["kr_launch"]);
    let (answer, reason) = match launch {
        Some(launch) if launch["committed"] == true => ("committed", None),
        Some(launch) if launch["committed"] == false => (
            "failed",
            Some(launch["failed"].as_str().unwrap_or_default().to_owned()),
        ),
        _ => (kind, None),
    };
    let resumes = plan["resume"] == true && answer == "committed";
    report(serde_json::json!({
        "event": "answer", "answer": answer, "reason": reason, "read": read,
        "after_us": u64::try_from(after.as_micros()).unwrap_or(u64::MAX),
        "resumes": resumes,
    }));
    if resumes {
        kr_ipc::memory_limit::resume(std::os::windows::io::AsHandle::as_handle(&program))
            .expect("the program is started");
        writer
            .write_all(b"{\"kr_launch\":{\"resumed\":true}}\n")
            .await
            .expect("resumed is written");
        let _ = writer.flush().await;
        report(serde_json::json!({"event": "resumed"}));
    }
    // Held until the case lets go, with the connection open and the program alive, as a launcher
    // waits for its program. Closing this process's input is the case letting go.
    let _ = tokio::task::spawn_blocking(|| {
        let mut sink = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut sink)
    })
    .await;
    // The job ends the program with this process.
    drop(job);
    let _ = program.wait();
}

/// Reads one line within `within`, and says how it ended: `"line"`, `"closed"` with nothing read,
/// `"nothing"` when nothing came in time, and `"other"` for a line that was cut off.
async fn read_line<R>(
    reader: &mut tokio::io::BufReader<R>,
    within: Duration,
) -> (&'static str, Option<String>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut line = String::new();
    match tokio::time::timeout(within, reader.read_line(&mut line)).await {
        Err(_) => ("nothing", None),
        Ok(Ok(0)) => ("closed", None),
        Ok(Ok(_)) if line.ends_with('\n') => ("line", Some(line.trim_end().to_owned())),
        Ok(Ok(_)) | Ok(Err(_)) => ("other", Some(line)),
    }
}
