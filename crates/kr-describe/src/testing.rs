//! What the tests of the description crates drive in place of a model.
//!
//! [`StubModel`] answers from the prompt's data section, which is all a real model has to work
//! with, and does what its [`Script`] says: take a given time, wait for its cancellation, report a
//! resident set, produce an answer that is not a description, or end its process. The stub
//! executable, `kr-describe-stub`, serves it through [`crate::serve::run`] over its real standard
//! input and output, so a test starts the process the daemon starts, less the weights.
//!
//! A script can also break the process on purpose - stop reading, stop writing, answer twice, cut a
//! frame short, never answer - so the daemon's side is tested against children that misbehave.
//!
//! None of this is compiled without the `testing` feature.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use kr_protocol::scalars::{Bytes, Nullable, U64};

use crate::priority::Cancellation;
use crate::profile::catalogue::Catalogue;
use crate::serve::{Generating, Job, LoadWork, Loading, Model, Options};
use crate::wire::{
    Answer, Background, JobEnd, Phases, Request, WIRE_VERSION, frame_of, read_message,
    write_message,
};

/// The environment variable a stub executable reads its script from.
pub const SCRIPT_VARIABLE: &str = "KR_DESCRIBE_STUB";

/// The exit status of a stub whose script ended it inside a job, as a crashed model would.
pub const CRASH_EXIT: i32 = 9;

/// How often a stub looks at its token while it waits.
const LOOK: Duration = Duration::from_millis(2);

/// The start of the name of the file a stub that marks its start leaves in its runtime directory,
/// followed by its process identifier.
pub const STARTED_PREFIX: &str = "stub-started-";

thread_local! {
    /// The frame thread a driver on this thread does not start next, by name.
    static REFUSED_THREAD: std::cell::Cell<Option<&'static str>> =
        const { std::cell::Cell::new(None) };
}

/// Makes the next start of the frame thread named `name`, by a driver on this thread, fail as a
/// thread the operating system would not create. The names are
/// [`crate::supervise::WRITER_THREAD`] and [`crate::supervise::READER_THREAD`].
pub fn refuse_thread_start(name: &'static str) {
    REFUSED_THREAD.with(|refused| refused.set(Some(name)));
}

/// Returns whether the start of the thread named `name` is to fail, which it does once.
pub(crate) fn thread_start_refused(name: &str) -> bool {
    REFUSED_THREAD.with(|refused| {
        let refuse = refused.get() == Some(name);
        if refuse {
            refused.set(None);
        }
        refuse
    })
}

/// What a stub does.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Script {
    /// How long a load takes, in milliseconds.
    pub load_ms: u64,
    /// Whether a load waits until it is cancelled or passes its deadline.
    pub load_until_cancelled: bool,
    /// How long a job takes, in milliseconds.
    pub generate_ms: u64,
    /// Whether a job waits until it is cancelled or passes its deadline.
    pub generate_until_cancelled: bool,
    /// How long a job sleeps without looking at its token, in milliseconds.
    pub ignore_token_ms: u64,
    /// The peak resident set a job reports, in bytes, in place of the process's own.
    pub peak_rss_bytes: Option<u64>,
    /// Whether a job ends because the process passed the memory ceiling.
    pub memory_ceiling: bool,
    /// What a job's answer looks like.
    pub output: Output,
    /// Whether the process ends inside a job, as a crashed model would.
    pub crash_in_generate: bool,
    /// Whether the model panics inside a job.
    pub panic_in_generate: bool,
    /// After this many whole requests, reading them stops for good.
    pub wedge_input_after: Option<u64>,
    /// From this answer on, counting from one, writing blocks for good.
    pub wedge_output_from: Option<u64>,
    /// A process that does not serve through [`crate::serve::run`] at all.
    pub raw: Option<Raw>,
    /// Whether the process leaves a file named [`STARTED_PREFIX`] and its identifier in its
    /// runtime directory as it starts, so a test can tell whether it was ever started.
    pub mark_start: bool,
}

/// What a job's answer looks like.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Output {
    /// A well-formed description built from the prompt.
    #[default]
    WellFormed,
    /// Bytes that are not the grammar's object.
    Malformed,
    /// An object with a field this product does not know.
    UnknownField,
    /// A title with a control character in it.
    ControlCharacter,
    /// A title longer than section 22's bound.
    OverlongTitle,
    /// Activity text longer than section 22's bound.
    OverlongActivity,
    /// A description that claims a revision other than the prompt's.
    WrongRevision(u64),
}

/// A process that breaks the wire on purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Raw {
    /// Reads everything and answers nothing.
    Silent,
    /// Answers `hello` and `load`, cuts its answer to the first job short, and exits.
    PartialFrameThenExit,
    /// Answers `hello` and `load`, cuts its answer to the first job short, and goes quiet.
    PartialFrameThenHang,
    /// Answers each job twice, and once more for work nobody asked for.
    AnswerTwice,
}

impl Script {
    /// Renders the script as the value of [`SCRIPT_VARIABLE`].
    #[must_use]
    pub fn to_env(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut number = |name: &str, value: u64| {
            if value != 0 {
                parts.push(format!("{name}={value}"));
            }
        };
        number("load-ms", self.load_ms);
        number("generate-ms", self.generate_ms);
        number("ignore-token-ms", self.ignore_token_ms);
        if let Some(bytes) = self.peak_rss_bytes {
            parts.push(format!("peak-rss={bytes}"));
        }
        if let Some(count) = self.wedge_input_after {
            parts.push(format!("wedge-input-after={count}"));
        }
        if let Some(count) = self.wedge_output_from {
            parts.push(format!("wedge-output-from={count}"));
        }
        let mut flag = |name: &str, set: bool| {
            if set {
                parts.push(name.to_owned());
            }
        };
        flag("load-until-cancelled", self.load_until_cancelled);
        flag("generate-until-cancelled", self.generate_until_cancelled);
        flag("memory-ceiling", self.memory_ceiling);
        flag("crash-in-generate", self.crash_in_generate);
        flag("panic-in-generate", self.panic_in_generate);
        flag("mark-start", self.mark_start);
        match &self.output {
            Output::WellFormed => {}
            Output::Malformed => parts.push("output=malformed".to_owned()),
            Output::UnknownField => parts.push("output=unknown-field".to_owned()),
            Output::ControlCharacter => parts.push("output=control-character".to_owned()),
            Output::OverlongTitle => parts.push("output=overlong-title".to_owned()),
            Output::OverlongActivity => parts.push("output=overlong-activity".to_owned()),
            Output::WrongRevision(revision) => {
                parts.push(format!("output=wrong-revision-{revision}"));
            }
        }
        match self.raw {
            None => {}
            Some(Raw::Silent) => parts.push("raw=silent".to_owned()),
            Some(Raw::PartialFrameThenExit) => parts.push("raw=partial-frame-then-exit".to_owned()),
            Some(Raw::PartialFrameThenHang) => parts.push("raw=partial-frame-then-hang".to_owned()),
            Some(Raw::AnswerTwice) => parts.push("raw=answer-twice".to_owned()),
        }
        parts.join(",")
    }

    /// Reads a script from the value of [`SCRIPT_VARIABLE`].
    ///
    /// # Errors
    ///
    /// Returns the directive this build does not know.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut script = Self::default();
        for directive in text
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
        {
            let (name, value) = directive.split_once('=').unwrap_or((directive, ""));
            let number = || {
                value
                    .parse::<u64>()
                    .map_err(|_| format!("{name} takes a whole number, and was given {value}"))
            };
            match name {
                "load-ms" => script.load_ms = number()?,
                "generate-ms" => script.generate_ms = number()?,
                "ignore-token-ms" => script.ignore_token_ms = number()?,
                "peak-rss" => script.peak_rss_bytes = Some(number()?),
                "wedge-input-after" => script.wedge_input_after = Some(number()?),
                "wedge-output-from" => script.wedge_output_from = Some(number()?),
                "load-until-cancelled" => script.load_until_cancelled = true,
                "generate-until-cancelled" => script.generate_until_cancelled = true,
                "memory-ceiling" => script.memory_ceiling = true,
                "crash-in-generate" => script.crash_in_generate = true,
                "panic-in-generate" => script.panic_in_generate = true,
                "mark-start" => script.mark_start = true,
                "output" => {
                    script.output = match value {
                        "malformed" => Output::Malformed,
                        "unknown-field" => Output::UnknownField,
                        "control-character" => Output::ControlCharacter,
                        "overlong-title" => Output::OverlongTitle,
                        "overlong-activity" => Output::OverlongActivity,
                        other => match other.strip_prefix("wrong-revision-") {
                            Some(revision) => Output::WrongRevision(
                                revision
                                    .parse()
                                    .map_err(|_| format!("output={other} names no revision"))?,
                            ),
                            None => return Err(format!("output={other} is not an output")),
                        },
                    };
                }
                "raw" => {
                    script.raw = Some(match value {
                        "silent" => Raw::Silent,
                        "partial-frame-then-exit" => Raw::PartialFrameThenExit,
                        "partial-frame-then-hang" => Raw::PartialFrameThenHang,
                        "answer-twice" => Raw::AnswerTwice,
                        other => return Err(format!("raw={other} is not a raw mode")),
                    });
                }
                other => return Err(format!("{other} is not a directive")),
            }
        }
        Ok(script)
    }
}

/// A model that answers from the prompt, as its script says.
#[derive(Clone, Debug, Default)]
pub struct StubModel {
    script: Script,
}

impl StubModel {
    /// Builds a model that follows a script.
    #[must_use]
    pub const fn new(script: Script) -> Self {
        Self { script }
    }
}

/// How a wait of a stub's ended.
enum Waited {
    Done,
    Cancelled,
    PastDeadline,
}

/// Waits `duration`, or until the token is cancelled or the deadline passes, whichever is first;
/// with no duration, until one of the other two.
fn wait(duration: Option<Duration>, token: &Cancellation, deadline: Instant) -> Waited {
    let started = Instant::now();
    loop {
        if token.is_cancelled() {
            return Waited::Cancelled;
        }
        if duration.is_some_and(|duration| started.elapsed() >= duration) {
            return Waited::Done;
        }
        if Instant::now() >= deadline {
            return Waited::PastDeadline;
        }
        std::thread::sleep(LOOK);
    }
}

impl Model for StubModel {
    fn load(&mut self, _work: &LoadWork<'_>, token: &Cancellation, deadline: Instant) -> Loading {
        let duration =
            (!self.script.load_until_cancelled).then(|| Duration::from_millis(self.script.load_ms));
        match wait(duration, token, deadline) {
            Waited::Done => Loading::Loaded,
            Waited::Cancelled => Loading::Ended {
                why: crate::wire::LoadEnd::Cancelled,
                detail: None,
            },
            Waited::PastDeadline => Loading::Ended {
                why: crate::wire::LoadEnd::DeadlineExceeded,
                detail: None,
            },
        }
    }

    fn generate(&mut self, job: &Job<'_>, token: &Cancellation, deadline: Instant) -> Generating {
        let started = Instant::now();
        if self.script.crash_in_generate {
            eprintln!("kr-describe-stub: ending inside a job, as its script says");
            std::process::exit(CRASH_EXIT);
        }
        assert!(
            !self.script.panic_in_generate,
            "kr-describe-stub: failing inside a job, as its script says"
        );
        if self.script.ignore_token_ms > 0 {
            std::thread::sleep(Duration::from_millis(self.script.ignore_token_ms));
        }
        let duration = (!self.script.generate_until_cancelled)
            .then(|| Duration::from_millis(self.script.generate_ms));
        match wait(duration, token, deadline) {
            Waited::Done => {}
            Waited::Cancelled => {
                return Generating::Ended {
                    why: JobEnd::Cancelled,
                    detail: None,
                };
            }
            Waited::PastDeadline => {
                return Generating::Ended {
                    why: JobEnd::DeadlineExceeded,
                    detail: None,
                };
            }
        }
        if self.script.memory_ceiling {
            return Generating::Ended {
                why: JobEnd::MemoryCeiling,
                detail: Some(format!(
                    "the process passed the ceiling of {} bytes",
                    job.ceiling_bytes
                )),
            };
        }
        let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Generating::Produced {
            bytes: answer_of(job.prompt, &self.script.output),
            phases: Phases {
                prompt_tokens: U64::new((job.prompt.len() / 4) as u64),
                prompt_ms: U64::new(elapsed / 2),
                sampling_ms: U64::new(0),
                decode_ms: U64::new(elapsed - elapsed / 2),
            },
            peak_rss_bytes: self
                .script
                .peak_rss_bytes
                .unwrap_or_else(|| crate::serve::own_rss_bytes().unwrap_or(0)),
        }
    }
}

/// Reads a field out of the prompt's data section.
fn data_field<'a>(prompt: &'a str, label: &str) -> Option<&'a str> {
    prompt.lines().find_map(|line| {
        let rest = line.strip_prefix(label)?.strip_prefix(": <<")?;
        rest.strip_suffix(">>")
    })
}

/// Reads the revision the prompt states.
fn prompt_revision(prompt: &str) -> u64 {
    prompt
        .lines()
        .find_map(|line| line.strip_prefix("context_revision: "))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}

/// Reads the cursor interval the prompt states.
fn prompt_cursor(prompt: &str) -> (u64, u64) {
    let Some(line) = prompt
        .lines()
        .find_map(|line| line.strip_prefix("source_cursor: "))
    else {
        return (0, 0);
    };
    let number = |label: &str| -> u64 {
        line.split_once(label)
            .and_then(|(_, rest)| {
                rest.trim_start()
                    .trim_start_matches(':')
                    .trim_start()
                    .split(|character: char| !character.is_ascii_digit())
                    .find(|piece| !piece.is_empty())
                    .and_then(|digits| digits.parse().ok())
            })
            .unwrap_or(0)
    };
    (number("\"from\""), number("\"to\""))
}

/// Builds the answer a job's prompt gets.
///
/// The subject is taken from the data section, which is the whole of what a real model has to
/// work with. A stub that invented a title from nothing would pass a test that a real model with
/// an empty context would fail.
#[must_use]
pub fn answer_of(prompt: &str, output: &Output) -> Vec<u8> {
    let revision = match output {
        Output::WrongRevision(claimed) => *claimed,
        _ => prompt_revision(prompt),
    };
    let (from, to) = prompt_cursor(prompt);
    let subject = data_field(prompt, "repository")
        .or_else(|| data_field(prompt, "directory"))
        .or_else(|| data_field(prompt, "application"))
        .unwrap_or("Session");
    let doing = data_field(prompt, "intent")
        .or_else(|| data_field(prompt, "thread"))
        .unwrap_or("Working in this session");
    let (title, activity) = match output {
        Output::ControlCharacter => (format!("{subject}\u{7}"), doing.to_owned()),
        Output::OverlongTitle => ("t".repeat(65), doing.to_owned()),
        Output::OverlongActivity => (subject.to_owned(), "a".repeat(161)),
        _ => (
            subject.chars().take(64).collect(),
            doing.chars().take(160).collect(),
        ),
    };
    match output {
        Output::Malformed => b"not an object at all".to_vec(),
        Output::UnknownField => format!(
            "{{\"title\":{title},\"activity_text\":{activity},\
             \"source_cursor\":{{\"from\":{from},\"to\":{to}}},\
             \"context_revision\":{revision},\"confidence\":0.9}}",
            title = escape(&title),
            activity = escape(&activity),
        )
        .into_bytes(),
        _ => format!(
            "{{\"title\":{title},\"activity_text\":{activity},\
             \"source_cursor\":{{\"from\":{from},\"to\":{to}}},\
             \"context_revision\":{revision}}}",
            title = escape(&title),
            activity = escape(&activity),
        )
        .into_bytes(),
    }
}

/// Renders a string as a JSON string literal.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            control if control.is_control() => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// This stub's build identifier.
#[must_use]
pub fn stub_build() -> String {
    format!("kr-describe-stub/{}", crate::wire::RELEASE)
}

/// Runs the stub executable: serves its script's model over standard input and output, or breaks
/// the wire as its script says. It returns the process's exit status.
#[must_use]
pub fn stub_main() -> i32 {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.first().map(String::as_str) == Some("--daemon") {
        return run_daemon(&arguments);
    }
    let script = match Script::parse(&std::env::var(SCRIPT_VARIABLE).unwrap_or_default()) {
        Ok(script) => script,
        Err(error) => {
            eprintln!("kr-describe-stub: {error}");
            return 64;
        }
    };
    let (runtime_dir, daemon) = match crate::serve::arguments(&arguments) {
        Ok(read) => read,
        Err(error) => {
            eprintln!("kr-describe-stub: {error}");
            return 64;
        }
    };
    if script.mark_start {
        let mark = runtime_dir.join(format!("{STARTED_PREFIX}{}", std::process::id()));
        if let Err(error) = std::fs::write(&mark, b"") {
            eprintln!(
                "kr-describe-stub: {} could not be written: {error}",
                mark.display()
            );
            return 74;
        }
    }
    if let Some(raw) = script.raw {
        return run_raw(raw, &script);
    }
    let catalogue = match Catalogue::builtin() {
        Ok(catalogue) => catalogue,
        Err(error) => {
            eprintln!("kr-describe-stub: {error}");
            return 64;
        }
    };
    let options = Options {
        build: stub_build(),
        runtime_dir,
        catalogue,
        daemon,
    };
    let input = Wedging::reading(std::io::stdin(), script.wedge_input_after);
    let output = Wedging::writing(std::io::stdout(), script.wedge_output_from);
    crate::serve::run(options, StubModel::new(script), input, output).code()
}

/// Runs a stub daemon, which a test ends to see its description process go with it.
///
/// It drives the description service over a child of its own - this executable, following the
/// script after `--child-script` - until the job it queues is in the child, or with `--until
/// published` until that job's description is published, prints the child's start identity on
/// its own output as one line, and then waits to be ended.
fn run_daemon(arguments: &[String]) -> i32 {
    use crate::context::{ContextBinding, ContextSignal};
    use crate::environment::{EnvironmentKind, ExecutionEnvironment, build_target};
    use crate::profile::catalogue::MetGates;
    use crate::queue::Priority;
    use crate::resource::{HostConditions, PowerSource, ResourceSettings, ThermalState};
    use crate::service::{DescriptionService, HostPlacement};
    use crate::store::DescriptionStore;
    use crate::supervise::{Driver, Launch};
    use crate::time::Reading;
    use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
    use kr_protocol::scalars::Uuid;

    let (Some(runtime_dir), Ok(program), Ok(catalogue), Ok(store)) = (
        flag(arguments, "--runtime-dir").map(PathBuf::from),
        std::env::current_exe(),
        Catalogue::builtin(),
        DescriptionStore::in_memory(),
    ) else {
        eprintln!("usage: kr-describe-stub --daemon --runtime-dir <directory>");
        return 64;
    };
    let child = flag(arguments, "--child-script").unwrap_or_default();
    let published = flag(arguments, "--until").as_deref() == Some("published");
    let launch = Launch {
        program,
        arguments: vec!["--runtime-dir".into(), runtime_dir.clone().into()],
        working_directory: runtime_dir.clone(),
        environment: vec![(SCRIPT_VARIABLE.into(), child.into())],
        models: runtime_dir,
    };
    let service = DescriptionService::new(
        HostPlacement {
            environment: ExecutionEnvironment::new(
                EnvironmentId::new(Uuid::from_bytes([7; 16])),
                EnvironmentKind::Native,
            ),
            data_access: None,
            target: build_target().to_owned(),
        },
        catalogue,
        MetGates::default(),
        ResourceSettings::default(),
        store,
    );
    let mut driver = Driver::new(service, launch, stub_build());
    let session_id = SessionId::new(Uuid::from_bytes([1; 16]));
    let service = driver.service_mut();
    service.session_opened(
        session_id,
        SessionEpoch::V1,
        ContextBinding::new("stub-daemon"),
    );
    service.observe(
        &session_id,
        ContextSignal::WorkingDirectory {
            directory: "kalareach".to_owned(),
            repository: None,
        },
        Reading::new(0, 0),
    );
    service.settle(&session_id, Priority::Ordinary, Reading::new(2_000, 2_000));
    let conditions = HostConditions::measured(
        16 << 30,
        12 << 30,
        PowerSource::Mains,
        ThermalState::Nominal,
    );
    let until = Instant::now() + Duration::from_secs(20);
    loop {
        if driver
            .turn(&conditions, Reading::new(3_000, 3_000))
            .is_err()
        {
            return 70;
        }
        let there = if published {
            driver.service().counts().published == 1
        } else {
            driver.service().in_flight() == 1
        };
        if there && let Some(identity) = driver.identity() {
            let line = serde_json::to_string(identity).unwrap_or_default();
            let mut output = std::io::stdout();
            if writeln!(output, "{line}")
                .and_then(|()| output.flush())
                .is_err()
            {
                return 74;
            }
            stop_for_good();
        }
        if Instant::now() >= until {
            eprintln!("kr-describe-stub: the job did not get where it was to go in time");
            return 70;
        }
        driver.wait(Duration::from_millis(50));
    }
}

/// Returns the value after a flag.
fn flag(arguments: &[String], name: &str) -> Option<String> {
    arguments
        .iter()
        .position(|argument| argument == name)
        .and_then(|index| arguments.get(index + 1))
        .cloned()
}

/// A stream that stops for good after a number of frames.
///
/// Reading, it counts whole frames by their length prefixes and never returns from the read after
/// the last one it lets through. Writing, it counts the answers it has flushed and never returns
/// from the write of the one it stops at.
struct Wedging<T> {
    inner: T,
    stop_at: Option<u64>,
    frames: u64,
    /// Reading: how much of the current frame is still to come, and the prefix bytes seen so far.
    remaining: usize,
    prefix: Vec<u8>,
}

impl<T> Wedging<T> {
    const fn reading(inner: T, after: Option<u64>) -> Self {
        Self {
            inner,
            stop_at: after,
            frames: 0,
            remaining: 0,
            prefix: Vec::new(),
        }
    }

    const fn writing(inner: T, from: Option<u64>) -> Self {
        Self::reading(inner, from)
    }
}

/// Never returns: what a stream that has stopped for good does.
fn stop_for_good() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(3_600));
    }
}

impl<R: Read> Read for Wedging<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.stop_at.is_some_and(|after| self.frames >= after) {
            stop_for_good();
        }
        // Reading one byte at a time keeps the count exact without buffering ahead of the frame
        // that stops the stream.
        let Some(first) = buffer.first_mut() else {
            return Ok(0);
        };
        let mut one = [0_u8; 1];
        let read = self.inner.read(&mut one)?;
        if read == 0 {
            return Ok(0);
        }
        *first = one[0];
        if self.remaining == 0 {
            self.prefix.push(one[0]);
            if self.prefix.len() == 4 {
                let length = u32::from_be_bytes([
                    self.prefix[0],
                    self.prefix[1],
                    self.prefix[2],
                    self.prefix[3],
                ]);
                self.prefix.clear();
                self.remaining = length as usize;
                if self.remaining == 0 {
                    self.frames += 1;
                }
            }
        } else {
            self.remaining -= 1;
            if self.remaining == 0 {
                self.frames += 1;
            }
        }
        Ok(1)
    }
}

impl<W: Write> Write for Wedging<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.stop_at.is_some_and(|from| self.frames + 1 >= from) {
            stop_for_good();
        }
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()?;
        self.frames += 1;
        Ok(())
    }
}

/// Runs a stub that breaks the wire on purpose, and returns its exit status.
fn run_raw(raw: Raw, script: &Script) -> i32 {
    let mut input = std::io::stdin();
    let mut output = std::io::stdout();
    if raw == Raw::Silent {
        let mut sink = Vec::new();
        let _ = input.read_to_end(&mut sink);
        return 0;
    }
    loop {
        let request = match read_message::<Request>(&mut input) {
            Ok(Some(request)) => request,
            Ok(None) | Err(_) => return 0,
        };
        let answers: Vec<Answer> = match request {
            Request::Hello { .. } => vec![Answer::Ready {
                build: stub_build(),
                wire: U64::new(WIRE_VERSION),
                target: crate::environment::build_target().to_owned(),
                identity: Nullable(kr_ipc::identity::current_process_start_identity().ok()),
                background: Background::from(crate::priority::Applied {
                    mechanism: crate::priority::Mechanism::None,
                    cpu: false,
                    io: false,
                    why: Some("this stub applies nothing"),
                }),
            }],
            Request::Load { id, .. } => vec![Answer::Loaded {
                id,
                load_ms: U64::new(0),
                rss_bytes: U64::new(0),
            }],
            Request::Generate { id, prompt, .. } => {
                let produced = |id: U64| Answer::Produced {
                    id,
                    bytes: Bytes::from(answer_of(&prompt, &script.output)),
                    phases: Phases::default(),
                    peak_rss_bytes: U64::new(0),
                };
                match raw {
                    Raw::PartialFrameThenExit | Raw::PartialFrameThenHang => {
                        let frame = frame_of(&produced(id)).unwrap_or_default();
                        let _ = output.write_all(&frame[..frame.len() / 2]);
                        let _ = output.flush();
                        if raw == Raw::PartialFrameThenExit {
                            return 0;
                        }
                        stop_for_good();
                    }
                    Raw::AnswerTwice => vec![
                        produced(id),
                        produced(id),
                        produced(U64::new(id.get().saturating_add(1_000))),
                    ],
                    Raw::Silent => Vec::new(),
                }
            }
            Request::Cancel { .. } => Vec::new(),
        };
        for answer in answers {
            if write_message(&mut output, &answer).is_err() {
                return 0;
            }
        }
    }
}

/// What the in-process answerer does with the next piece of work, for tests that drive the service
/// with no process at all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Behaviour {
    /// Produce a well-formed description from the prompt.
    #[default]
    WellFormed,
    /// Produce bytes that are not the object the grammar describes.
    Malformed,
    /// Produce an object with a field this product does not know.
    UnknownField,
    /// Produce a title with a control character in it.
    ControlCharacter,
    /// Produce a title longer than section 22's bound.
    OverlongTitle,
    /// Produce activity text longer than section 22's bound.
    OverlongActivity,
    /// Produce a description claiming a revision that is not the prompt's.
    WrongRevision(u64),
    /// Take this long, so a test can drive the deadline.
    Slow {
        /// How long the job takes.
        duration_ms: u64,
    },
    /// Fail, as a runtime whose model file has gone would.
    Fails {
        /// What it says.
        detail: String,
    },
    /// Take this long to load.
    SlowLoad {
        /// How long the load takes.
        duration_ms: u64,
    },
    /// Fail during load, as a missing or corrupt weights file would.
    FailsLoad {
        /// What it says.
        detail: String,
    },
    /// End the load cancelled.
    CancelDuringLoad,
    /// Produce a description, and have the job cancelled before its answer is taken.
    CancelBeforePublish,
}

impl Behaviour {
    /// Returns what a job's answer looks like under this behaviour.
    fn output(&self) -> Output {
        match self {
            Self::Malformed => Output::Malformed,
            Self::UnknownField => Output::UnknownField,
            Self::ControlCharacter => Output::ControlCharacter,
            Self::OverlongTitle => Output::OverlongTitle,
            Self::OverlongActivity => Output::OverlongActivity,
            Self::WrongRevision(revision) => Output::WrongRevision(*revision),
            _ => Output::WellFormed,
        }
    }
}

/// A behaviour two owners share: the test that sets it, and the answerer that reads it.
#[derive(Clone, Debug, Default)]
pub struct SharedBehaviour(std::sync::Arc<std::sync::Mutex<Behaviour>>);

impl SharedBehaviour {
    /// Builds a shared behaviour that produces a well-formed description.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets what the next answer looks like.
    pub fn set(&self, behaviour: Behaviour) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = behaviour;
    }

    /// Returns what the next answer looks like.
    #[must_use]
    pub fn get(&self) -> Behaviour {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// What one turn of the in-process driver came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tick {
    /// Nothing was due.
    Idle,
    /// Inference is paused, and whether the model was unloaded to get here.
    ResourcePaused {
        /// Why.
        reason: crate::resource::PauseReason,
        /// Whether a model was unloaded.
        unloaded: bool,
    },
    /// The model was unloaded because the host has had no sessions for this long.
    IdleUnloaded {
        /// How long.
        idle_ms: u64,
    },
    /// The process was ended for another reason.
    Unloaded(crate::service::UnloadReason),
    /// A load ended with no model.
    LoadEnded {
        /// Why.
        why: crate::wire::LoadEnd,
    },
    /// A description was published.
    Published {
        /// The session.
        session_id: kr_protocol::ids::SessionId,
        /// How long its job waited.
        queue_wait_ms: u64,
        /// How long its job took once dequeued.
        execution_ms: u64,
    },
    /// A result was refused.
    Rejected {
        /// The session.
        session_id: kr_protocol::ids::SessionId,
        /// Why.
        rejection: crate::output::Rejection,
    },
    /// A job was cancelled.
    Cancelled {
        /// The session.
        session_id: kr_protocol::ids::SessionId,
    },
    /// A job passed its deadline.
    DeadlineExceeded {
        /// The session.
        session_id: kr_protocol::ids::SessionId,
    },
    /// A job did not finish and was queued again.
    Requeued {
        /// The session.
        session_id: kr_protocol::ids::SessionId,
    },
    /// A job failed and was not queued again.
    InferenceFailed {
        /// The session.
        session_id: kr_protocol::ids::SessionId,
        /// What went wrong.
        detail: String,
    },
}

impl From<crate::service::Outcome> for Tick {
    fn from(outcome: crate::service::Outcome) -> Self {
        use crate::service::Outcome;
        match outcome {
            Outcome::LoadEnded { why, .. } => Self::LoadEnded { why },
            Outcome::Published {
                session_id,
                queue_wait_ms,
                execution_ms,
            } => Self::Published {
                session_id,
                queue_wait_ms,
                execution_ms,
            },
            Outcome::Rejected {
                session_id,
                rejection,
            } => Self::Rejected {
                session_id,
                rejection,
            },
            Outcome::Cancelled { session_id } => Self::Cancelled { session_id },
            Outcome::DeadlineExceeded { session_id } => Self::DeadlineExceeded { session_id },
            Outcome::Requeued { session_id } => Self::Requeued { session_id },
            Outcome::Failed { session_id, detail } => Self::InferenceFailed { session_id, detail },
            Outcome::Loaded { .. } | Outcome::Dropped { .. } | Outcome::ProcessEnded { .. } => {
                Self::Idle
            }
        }
    }
}

/// Drives the service through one turn with the in-process answerer: asks what to do, answers it
/// at once, and says what it came to.
///
/// A load and the job after it happen in one turn. A behaviour that takes time moves the reading
/// the answer arrives at, which is how a deadline is driven without waiting for it.
///
/// # Errors
///
/// Returns the store failures the service returns.
pub fn tick(
    service: &mut crate::service::DescriptionService,
    behaviour: &SharedBehaviour,
    conditions: &crate::resource::HostConditions,
    now: crate::time::Reading,
) -> crate::Result<Tick> {
    use crate::service::{Answered, Instruction, LOAD_DEADLINE_MS, Outcome, UnloadReason, Work};
    use crate::wire::LoadEnd;
    let mut at = now;
    loop {
        match service.next(conditions, at)? {
            Instruction::Wait { .. } => {
                return Ok(match service.resource_state() {
                    crate::resource::ResourceState::ResourcePaused { reason, unloaded } => {
                        Tick::ResourcePaused { reason, unloaded }
                    }
                    _ => Tick::Idle,
                });
            }
            Instruction::Unload { why } => {
                return Ok(match why {
                    UnloadReason::Idle { idle_ms } => Tick::IdleUnloaded { idle_ms },
                    UnloadReason::Paused(reason) => Tick::ResourcePaused {
                        reason,
                        unloaded: true,
                    },
                    other => Tick::Unloaded(other),
                });
            }
            Instruction::Cancel { id, work } => {
                let answer = match work {
                    Work::Load => Answered::LoadEnded {
                        why: LoadEnd::Cancelled,
                        detail: None,
                    },
                    Work::Job => Answered::Ended {
                        why: JobEnd::Cancelled,
                        detail: None,
                    },
                };
                return Ok(Tick::from(service.finished(id, answer, at)?));
            }
            Instruction::Load { id, .. } => {
                let (answer, took_ms) = match behaviour.get() {
                    Behaviour::SlowLoad { duration_ms } if duration_ms > LOAD_DEADLINE_MS => (
                        Answered::LoadEnded {
                            why: LoadEnd::DeadlineExceeded,
                            detail: None,
                        },
                        LOAD_DEADLINE_MS,
                    ),
                    Behaviour::SlowLoad { duration_ms } => (
                        Answered::Loaded {
                            load_ms: duration_ms,
                            rss_bytes: 0,
                        },
                        duration_ms,
                    ),
                    Behaviour::FailsLoad { detail } => (
                        Answered::LoadEnded {
                            why: LoadEnd::Failed,
                            detail: Some(detail),
                        },
                        0,
                    ),
                    Behaviour::CancelDuringLoad => (
                        Answered::LoadEnded {
                            why: LoadEnd::Cancelled,
                            detail: None,
                        },
                        0,
                    ),
                    _ => (
                        Answered::Loaded {
                            load_ms: 0,
                            rss_bytes: 0,
                        },
                        0,
                    ),
                };
                at = at.after_ms(took_ms);
                match service.finished(id, answer, at)? {
                    Outcome::Loaded { .. } => {}
                    other => return Ok(Tick::from(other)),
                }
            }
            Instruction::Generate {
                id,
                session_id,
                request,
            } => {
                let behaviour = behaviour.get();
                let produced = |output: &Output| Answered::Produced {
                    bytes: answer_of(&request.prompt, output),
                    phases: Phases::default(),
                    peak_rss_bytes: 0,
                };
                let (answer, took_ms) = match &behaviour {
                    Behaviour::Slow { duration_ms } if *duration_ms > request.deadline_ms => (
                        Answered::Ended {
                            why: JobEnd::DeadlineExceeded,
                            detail: None,
                        },
                        request.deadline_ms,
                    ),
                    Behaviour::Slow { duration_ms } => {
                        (produced(&Output::WellFormed), *duration_ms)
                    }
                    Behaviour::Fails { detail } => (
                        Answered::Ended {
                            why: JobEnd::Failed,
                            detail: Some(detail.clone()),
                        },
                        0,
                    ),
                    other => (produced(&other.output()), 0),
                };
                if behaviour == Behaviour::CancelBeforePublish {
                    service.cancel_running(&session_id);
                }
                return Ok(Tick::from(service.finished(
                    id,
                    answer,
                    at.after_ms(took_ms),
                )?));
            }
        }
    }
}
