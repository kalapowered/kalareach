//! The description process's side of the wire, over any model.
//!
//! `kr-describe-inference` runs this over the llama.cpp model, and the stub executable the tests
//! start runs it over a model that answers from the prompt, so the process the tests drive is the
//! process the daemon starts. Three threads divide the work:
//!
//! * **The control thread**, the caller's own, reads requests from standard input. It answers
//!   `hello` itself, hands `load` and `generate` to the model thread, and cancels on `cancel` by
//!   setting the token of the work named. When its input ends, which is the daemon going away, it
//!   cancels whatever is running and ends the process.
//! * **The model thread** owns the model, takes this environment's lock before its first load, and
//!   answers each piece of work it is given.
//! * **The watchdog** ends the process when the control thread has spent longer than
//!   [`CONTROL_BOUND_MS`] on one request, which is a control thread stuck writing to a daemon that
//!   is not reading; when a load or a job is [`OVERDUE_GRACE_MS`] past its deadline, which is a
//!   model that did not stop; and when the daemon that started it has ended, by its start
//!   identity, whether or not the control thread saw its input end. No end of this process
//!   depends on the daemon alone.
//!
//! # One process per environment
//!
//! The model thread takes [`LOCK_FILE`] in the runtime directory it is given, without blocking,
//! and tries again until the load's deadline while the control thread keeps answering. It keeps
//! the lock for the rest of the process's life and the operating system releases it at exit, so a
//! process a replacement daemon starts loads nothing until the one before it has gone.
//!
//! # A process loads one model
//!
//! The daemon ends the process to unload a model or to load another, so a second load in a process
//! that has one is refused rather than served beside it.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::scalars::{Bytes, Nullable, U64};

use crate::environment::build_target;
use crate::priority::{Applied, Cancellation, background_current_thread};
use crate::profile::catalogue::Catalogue;
use crate::profile::{Asset, ModelProfile, SamplerSettings};
use crate::prompt::Prompt;
use crate::wire::{
    Answer, AssetFile, Background, JobEnd, JobLimits, LoadEnd, Phases, Request, VerifyResult,
    WIRE_VERSION, WireError, read_message, write_message,
};

/// The longest the control thread may spend on one request before the process ends itself.
pub const CONTROL_BOUND_MS: u64 = 2_000;

/// How far past its deadline a load or a job may run before the process ends itself.
pub const OVERDUE_GRACE_MS: u64 = 2_000;

/// How this process's memory ceiling is enforced: by the daemon's own reading of its resident set.
pub const CEILING_MECHANISM: &str = "sampler";

/// The file in the runtime directory whose lock one description process holds.
pub const LOCK_FILE: &str = "describe-inference.lock";

/// How often the watchdog looks.
const WATCH_INTERVAL: Duration = Duration::from_millis(100);

/// How often the watchdog asks whether the daemon that started this process is still there.
const DAEMON_LOOK_EVERY: u32 = 10;

/// The argument a daemon passes its own start identity in, as JSON.
pub const DAEMON_IDENTITY_ARGUMENT: &str = "--daemon-identity";

/// How often a load waiting for the lock tries it again.
const LOCK_RETRY: Duration = Duration::from_millis(50);

/// How long the end of input waits for the model thread to stop what it was doing.
const END_WAIT: Duration = Duration::from_secs(1);

/// How many loads and jobs wait for the model thread at most. The daemon sends one at a time, and
/// waits for its answer; work beyond this is refused rather than held.
const WAITING_WORK: usize = 4;

/// A model the description process runs.
pub trait Model: Send + 'static {
    /// Loads a profile's model, before the deadline and unless the token is cancelled.
    fn load(&mut self, work: &LoadWork<'_>, token: &Cancellation, deadline: Instant) -> Loading;

    /// Runs one job on the loaded model, before the deadline and unless the token is cancelled.
    fn generate(&mut self, job: &Job<'_>, token: &Cancellation, deadline: Instant) -> Generating;

    /// Checks one file against the size and digest its asset records, before the deadline and
    /// unless the token is cancelled. It needs no loaded model, and a process that has none can
    /// do it.
    fn verify(
        &mut self,
        asset: &Asset,
        path: &Path,
        token: &Cancellation,
        deadline: Instant,
    ) -> Verifying;

    /// Hears that another description process holds this environment's lock, so this one waits
    /// for it before it loads. Said once per wait; a model has no need to act on it.
    fn lock_held(&mut self) {}
}

/// What checking a file did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verifying {
    /// The file is the one the asset records.
    Verified,
    /// The check ended some other way, and why.
    Ended {
        /// How.
        result: VerifyResult,
        /// What went wrong, when something did.
        detail: Option<String>,
    },
}

/// What a model is asked to load: a profile from the process's own catalogue, and where each of
/// its files is.
#[derive(Clone, Copy, Debug)]
pub struct LoadWork<'a> {
    /// The profile, as this build's signed catalogue holds it.
    pub profile: &'a ModelProfile,
    /// Each of the profile's files, with where the daemon keeps it.
    pub assets: &'a [LoadAsset],
}

/// One of a profile's files, and where it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadAsset {
    /// The file as the profile records it: its role, size and digest.
    pub asset: Asset,
    /// Where it is on this host.
    pub path: PathBuf,
}

/// What loading did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Loading {
    /// The model is loaded.
    Loaded,
    /// There is no model, and why.
    Ended {
        /// Why.
        why: LoadEnd,
        /// What went wrong, when something did.
        detail: Option<String>,
    },
}

/// One job, as the model thread hands it to a model.
#[derive(Clone, Copy, Debug)]
pub struct Job<'a> {
    /// The prompt, in its parts, which the model makes fit [`Self::prompt_tokens`].
    pub prompt: &'a Prompt,
    /// The grammar the sampler is held to.
    pub grammar: &'a str,
    /// The context window, in tokens.
    pub context_tokens: u32,
    /// The output bound, in tokens.
    pub max_output_tokens: u32,
    /// How many tokens the prompt may be, beside the answer's bound.
    pub prompt_tokens: u32,
    /// How many processor threads the job may use.
    pub cpu_threads: u32,
    /// The sampler, from the loaded profile.
    pub sampler: &'a SamplerSettings,
    /// The resident set past which the job is ended between tokens, in bytes.
    pub ceiling_bytes: u64,
}

/// What a job did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Generating {
    /// Bytes nothing has trusted yet.
    Produced {
        /// What the model produced.
        bytes: Vec<u8>,
        /// Where the time went.
        phases: Phases,
        /// The process's largest resident set during the job, in bytes.
        peak_rss_bytes: u64,
    },
    /// Nothing, and why.
    Ended {
        /// Why.
        why: JobEnd,
        /// What went wrong, when something did.
        detail: Option<String>,
    },
}

/// What a description process is given when it starts.
#[derive(Clone, Debug)]
pub struct Options {
    /// Its own build identifier, `name/release`.
    pub build: String,
    /// The environment's runtime directory, where [`LOCK_FILE`] is.
    pub runtime_dir: PathBuf,
    /// The profiles this build ships, which a load is looked up in.
    pub catalogue: Catalogue,
    /// The start identity of the daemon that started this process, when it said.
    pub daemon: Option<ProcessStartIdentity>,
}

/// How a description process ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// Its input ended: the daemon closed it, or went away.
    Ended,
    /// A frame from the daemon was not one of this wire.
    WireBroken,
    /// The daemon has gone: an answer could not be written, or the daemon's process has ended.
    DaemonGone,
    /// The control thread spent too long on one request.
    ControlStalled,
    /// A load or a job ran too far past its deadline.
    Overdue,
    /// The model failed in a way that left no model thread to serve with.
    ModelFailed,
}

impl Exit {
    /// Returns the process's exit status for this end.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Ended => 0,
            Self::WireBroken => 65,
            Self::ControlStalled => 70,
            Self::Overdue => 71,
            Self::ModelFailed => 72,
            Self::DaemonGone => 74,
        }
    }

    /// Returns the end a process exit status stands for, when it stands for one.
    #[must_use]
    pub const fn of_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Ended),
            65 => Some(Self::WireBroken),
            70 => Some(Self::ControlStalled),
            71 => Some(Self::Overdue),
            72 => Some(Self::ModelFailed),
            74 => Some(Self::DaemonGone),
            _ => None,
        }
    }
}

/// Reads the arguments a description process is started with: `--runtime-dir <directory>`, and
/// the daemon's start identity after [`DAEMON_IDENTITY_ARGUMENT`] when the daemon gave it.
///
/// # Errors
///
/// Returns what is wrong with them.
pub fn arguments(
    given: &[String],
) -> std::result::Result<(PathBuf, Option<ProcessStartIdentity>), String> {
    let mut runtime_dir = None;
    let mut daemon = None;
    let mut given = given.iter();
    while let Some(name) = given.next() {
        let value = given
            .next()
            .ok_or_else(|| format!("{name} needs a value"))?;
        match name.as_str() {
            "--runtime-dir" => runtime_dir = Some(PathBuf::from(value)),
            DAEMON_IDENTITY_ARGUMENT => {
                daemon = Some(
                    serde_json::from_str(value)
                        .map_err(|error| format!("{name} is not a start identity: {error}"))?,
                );
            }
            other => return Err(format!("{other} is not an argument of this process")),
        }
    }
    let runtime_dir = runtime_dir.ok_or_else(|| "--runtime-dir is required".to_owned())?;
    Ok((runtime_dir, daemon))
}

/// Serves requests from `input` with `model` until the input ends, answering on `output`.
///
/// It returns [`Exit::Ended`] when the input ends and [`Exit::WireBroken`] when it breaks. The
/// other ends are the watchdog's and the model thread's, and they end the process where they are
/// found, because the thread that would have returned is the one that is stuck.
pub fn run<M: Model>(
    options: Options,
    model: M,
    mut input: impl Read,
    output: impl Write + Send + 'static,
) -> Exit {
    let shared = Arc::new(Shared {
        origin: Instant::now(),
        control_since: AtomicU64::new(0),
        work_due: AtomicU64::new(0),
        tokens: Mutex::new(BTreeMap::new()),
        output: Mutex::new(Box::new(output)),
        returned: AtomicBool::new(false),
    });
    let (work, received) = std::sync::mpsc::sync_channel::<Work>(WAITING_WORK);
    let (applied_tell, applied_heard) = std::sync::mpsc::channel::<Applied>();
    {
        let shared = shared.clone();
        let Options {
            runtime_dir,
            catalogue,
            ..
        } = options.clone();
        std::thread::Builder::new()
            .name("describe-model".to_owned())
            .spawn(move || {
                // A model that panics has left no thread to serve with, and a process that goes
                // on answering without one would only refuse work. So the process ends, and the
                // daemon restarts inference.
                let served = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    model_thread(
                        &shared,
                        model,
                        &received,
                        &applied_tell,
                        &runtime_dir,
                        &catalogue,
                    );
                }));
                if served.is_err() {
                    eprintln!("kr-describe: the model failed, so this process ends");
                    std::process::exit(Exit::ModelFailed.code());
                }
            })
            .expect("the model thread starts");
    }
    {
        let shared = shared.clone();
        let daemon = options.daemon.clone();
        std::thread::Builder::new()
            .name("describe-watchdog".to_owned())
            .spawn(move || watchdog(&shared, daemon.as_ref()))
            .expect("the watchdog starts");
    }
    let mut applied: Option<Applied> = None;
    loop {
        shared.control_since.store(0, Ordering::Release);
        let request = read_message::<Request>(&mut input);
        shared
            .control_since
            .store(shared.stamp(), Ordering::Release);
        match request {
            Ok(Some(Request::Hello { .. })) => {
                let background = applied
                    .get_or_insert_with(|| {
                        applied_heard
                            .recv_timeout(Duration::from_millis(CONTROL_BOUND_MS / 2))
                            .unwrap_or(Applied {
                                mechanism: crate::priority::Mechanism::None,
                                cpu: false,
                                io: false,
                                why: Some("the model thread did not say what it applied"),
                            })
                    })
                    .to_owned();
                shared.answer(&Answer::Ready {
                    build: options.build.clone(),
                    wire: U64::new(WIRE_VERSION),
                    target: build_target().to_owned(),
                    identity: Nullable(kr_ipc::identity::current_process_start_identity().ok()),
                    background: Background::from(background),
                    ceiling: CEILING_MECHANISM.to_owned(),
                });
            }
            Ok(Some(Request::Load {
                id,
                profile_id,
                revision,
                assets,
                deadline_ms,
            })) => {
                let id = id.get();
                let due = due_in(deadline_ms.get());
                let token = shared.token_for(id);
                let load = Work::Load {
                    id,
                    profile_id,
                    revision: revision.get(),
                    assets,
                    due,
                    token,
                };
                if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
                    work.try_send(load)
                {
                    shared.forget(id);
                    shared.answer(&Answer::LoadEnded {
                        id: U64::new(id),
                        why: LoadEnd::Refused,
                        detail: Nullable::some("too much work is waiting".to_owned()),
                    });
                }
            }
            Ok(Some(Request::Generate {
                id,
                prompt,
                grammar,
                limits,
                deadline_ms,
                ceiling_bytes,
            })) => {
                let id = id.get();
                let due = due_in(deadline_ms.get());
                let token = shared.token_for(id);
                let job = Work::Generate {
                    id,
                    prompt,
                    grammar,
                    limits,
                    due,
                    ceiling_bytes: ceiling_bytes.get(),
                    token,
                };
                if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
                    work.try_send(job)
                {
                    shared.forget(id);
                    shared.answer(&Answer::Ended {
                        id: U64::new(id),
                        why: JobEnd::Refused,
                        detail: Nullable::some("too much work is waiting".to_owned()),
                    });
                }
            }
            Ok(Some(Request::Verify {
                id,
                profile_id,
                revision,
                file_name,
                path,
                deadline_ms,
            })) => {
                let id = id.get();
                let due = due_in(deadline_ms.get());
                let token = shared.token_for(id);
                let check = Work::Verify {
                    id,
                    profile_id,
                    revision: revision.get(),
                    file_name,
                    path: PathBuf::from(path),
                    due,
                    token,
                };
                if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
                    work.try_send(check)
                {
                    shared.forget(id);
                    shared.answer(&Answer::Verified {
                        id: U64::new(id),
                        result: VerifyResult::Refused,
                        detail: Nullable::some("too much work is waiting".to_owned()),
                    });
                }
            }
            // The acknowledgement is the control thread's own, written before the work stops: it
            // says this thread is reading, which is the condition the daemon waits for. It is
            // sent only for work still in hand, so a cancellation that crosses the work's answer
            // is not acknowledged after it.
            Ok(Some(Request::Cancel { id })) => shared.cancel_and_acknowledge(id),
            // The input ended, or failed, which on a pipe the daemon holds is the same thing: the
            // daemon is not going to send anything more.
            Ok(None) | Err(WireError::Io(_)) => return shared.end(Exit::Ended),
            Err(error) => {
                eprintln!("kr-describe: a request from the daemon was refused: {error}");
                return shared.end(Exit::WireBroken);
            }
        }
    }
}

/// The longest deadline the process accepts, so that one the daemon sends cannot overflow the
/// clock it is counted on.
const LONGEST_DEADLINE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Returns when a piece of work given `deadline_ms` is due.
fn due_in(deadline_ms: u64) -> Instant {
    Instant::now() + Duration::from_millis(deadline_ms).min(LONGEST_DEADLINE)
}

/// What the threads of one process share.
struct Shared {
    origin: Instant,
    /// When the control thread started on its current request, in milliseconds since the origin
    /// plus one, or nought while it is waiting for one.
    control_since: AtomicU64,
    /// When the model thread's current work is overdue, in milliseconds since the origin plus
    /// one, or nought while it is idle.
    work_due: AtomicU64,
    /// The token of each piece of work received and not yet answered.
    tokens: Mutex<BTreeMap<u64, Cancellation>>,
    output: Mutex<Box<dyn Write + Send>>,
    /// Whether [`run`] has returned, after which the watchdog has nothing to watch.
    returned: AtomicBool,
}

impl Shared {
    /// Cancels what is running, waits a moment for it to stop, and stops watching.
    fn end(&self, exit: Exit) -> Exit {
        self.cancel_all();
        self.control_since.store(0, Ordering::Release);
        self.wait_for_idle(END_WAIT);
        self.returned.store(true, Ordering::Release);
        exit
    }

    /// Returns the time now as a stamp: milliseconds since the origin, plus one.
    fn stamp(&self) -> u64 {
        self.stamp_of(Instant::now())
    }

    fn stamp_of(&self, instant: Instant) -> u64 {
        u64::try_from(instant.saturating_duration_since(self.origin).as_millis())
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1)
    }

    /// Writes one answer, and ends the process when nothing is reading them.
    fn answer(&self, answer: &Answer) {
        let mut output = self.output.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(error) = write_message(&mut *output, answer) {
            eprintln!(
                "kr-describe: an answer could not be written, so the daemon is gone: {error}"
            );
            std::process::exit(Exit::DaemonGone.code());
        }
    }

    fn token_for(&self, id: u64) -> Cancellation {
        let token = Cancellation::new();
        self.tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, token.clone());
        token
    }

    fn forget(&self, id: u64) {
        self.tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
    }

    /// Acknowledges the cancellation of the work with this identifier and then cancels it, when
    /// there is any in hand.
    ///
    /// Both happen under the lock the model thread takes to forget the work before it answers, so
    /// the acknowledgement is written before the work's own answer: the work cannot be seen
    /// cancelled, forgotten and answered in the gap between cancelling it and saying so.
    fn cancel_and_acknowledge(&self, id: U64) {
        let tokens = self.tokens.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(token) = tokens.get(&id.get()) {
            self.answer(&Answer::Cancelling { id });
            token.cancel();
        }
    }

    fn cancel_all(&self) {
        for token in self
            .tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            token.cancel();
        }
    }

    /// Waits, at most `limit`, for the model thread to have nothing in hand.
    fn wait_for_idle(&self, limit: Duration) {
        let until = Instant::now() + limit;
        while self.work_due.load(Ordering::Acquire) != 0 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// One piece of work, as the control thread hands it to the model thread.
enum Work {
    Load {
        id: u64,
        profile_id: String,
        revision: u64,
        assets: Vec<AssetFile>,
        due: Instant,
        token: Cancellation,
    },
    Generate {
        id: u64,
        prompt: Prompt,
        grammar: String,
        limits: JobLimits,
        due: Instant,
        ceiling_bytes: u64,
        token: Cancellation,
    },
    Verify {
        id: u64,
        profile_id: String,
        revision: u64,
        file_name: String,
        path: PathBuf,
        due: Instant,
        token: Cancellation,
    },
}

/// Loads and runs jobs, one at a time, until the control thread stops handing it work.
fn model_thread<M: Model>(
    shared: &Shared,
    mut model: M,
    received: &Receiver<Work>,
    applied_tell: &std::sync::mpsc::Sender<Applied>,
    runtime_dir: &Path,
    catalogue: &Catalogue,
) {
    // The class is applied on this thread, which is the one that loads and runs the model, before
    // the model starts any thread of its own.
    let _ = applied_tell.send(background_current_thread());
    let mut lock: Option<ProcessLock> = None;
    let mut loaded: Option<ModelProfile> = None;
    while let Ok(work) = received.recv() {
        match work {
            Work::Load {
                id,
                profile_id,
                revision,
                assets,
                due,
                token,
            } => {
                shared.work_due.store(
                    shared.stamp_of(due + Duration::from_millis(OVERDUE_GRACE_MS)),
                    Ordering::Release,
                );
                let started = Instant::now();
                let ended = |why: LoadEnd, detail: Option<String>| Answer::LoadEnded {
                    id: U64::new(id),
                    why,
                    detail: Nullable(detail),
                };
                let answer = if token.is_cancelled() {
                    ended(LoadEnd::Cancelled, None)
                } else if loaded.is_some() {
                    ended(
                        LoadEnd::Refused,
                        Some("this process has a model loaded already".to_owned()),
                    )
                } else {
                    match resolve(catalogue, &profile_id, revision, &assets) {
                        Err(detail) => ended(LoadEnd::Refused, Some(detail)),
                        Ok((profile, assets)) => {
                            // The lock is taken before the first load and kept after it.
                            let locked = if lock.is_some() {
                                Ok(())
                            } else {
                                ProcessLock::acquire_until(runtime_dir, &token, due, &mut || {
                                    model.lock_held();
                                })
                                .map(|held| lock = Some(held))
                            };
                            match locked {
                                Err(LockWait::Cancelled) => ended(LoadEnd::Cancelled, None),
                                Err(LockWait::DeadlinePassed) => ended(
                                    LoadEnd::LockHeld,
                                    Some(format!(
                                        "another description process held {} until the deadline",
                                        runtime_dir.join(LOCK_FILE).display()
                                    )),
                                ),
                                Err(LockWait::Failed(error)) => ended(
                                    LoadEnd::Failed,
                                    Some(format!(
                                        "{} could not be locked: {error}",
                                        runtime_dir.join(LOCK_FILE).display()
                                    )),
                                ),
                                Ok(()) => match model.load(
                                    &LoadWork {
                                        profile: &profile,
                                        assets: &assets,
                                    },
                                    &token,
                                    due,
                                ) {
                                    Loading::Loaded => {
                                        loaded = Some(profile);
                                        Answer::Loaded {
                                            id: U64::new(id),
                                            load_ms: U64::new(elapsed_ms(started)),
                                            rss_bytes: U64::new(own_rss_bytes().unwrap_or(0)),
                                        }
                                    }
                                    Loading::Ended { why, detail } => ended(why, detail),
                                },
                            }
                        }
                    }
                };
                // Forgotten before it is answered, so a cancellation read after the answer is seen
                // finds nothing in hand and is acknowledged by nothing.
                shared.forget(id);
                shared.answer(&answer);
                shared.work_due.store(0, Ordering::Release);
            }
            Work::Generate {
                id,
                prompt,
                grammar,
                limits,
                due,
                ceiling_bytes,
                token,
            } => {
                shared.work_due.store(
                    shared.stamp_of(due + Duration::from_millis(OVERDUE_GRACE_MS)),
                    Ordering::Release,
                );
                let answer = match (&loaded, token.is_cancelled()) {
                    (_, true) => Generating::Ended {
                        why: JobEnd::Cancelled,
                        detail: None,
                    },
                    (None, false) => Generating::Ended {
                        why: JobEnd::NotLoaded,
                        detail: None,
                    },
                    (Some(profile), false) => model.generate(
                        &Job {
                            prompt: &prompt,
                            grammar: &grammar,
                            context_tokens: bounded(limits.context_tokens),
                            max_output_tokens: bounded(limits.max_output_tokens),
                            prompt_tokens: bounded(limits.prompt_tokens),
                            cpu_threads: bounded(limits.cpu_threads),
                            sampler: profile.sampler(),
                            ceiling_bytes,
                        },
                        &token,
                        due,
                    ),
                };
                // Forgotten before it is answered, as a load is.
                shared.forget(id);
                shared.answer(&match answer {
                    Generating::Produced {
                        bytes,
                        phases,
                        peak_rss_bytes,
                    } => Answer::Produced {
                        id: U64::new(id),
                        bytes: Bytes::from(bytes),
                        phases,
                        peak_rss_bytes: U64::new(peak_rss_bytes),
                    },
                    Generating::Ended { why, detail } => Answer::Ended {
                        id: U64::new(id),
                        why,
                        detail: Nullable(detail),
                    },
                });
                shared.work_due.store(0, Ordering::Release);
            }
            Work::Verify {
                id,
                profile_id,
                revision,
                file_name,
                path,
                due,
                token,
            } => {
                shared.work_due.store(
                    shared.stamp_of(due + Duration::from_millis(OVERDUE_GRACE_MS)),
                    Ordering::Release,
                );
                let ended = |result: VerifyResult, detail: Option<String>| Answer::Verified {
                    id: U64::new(id),
                    result,
                    detail: Nullable(detail),
                };
                let answer = if token.is_cancelled() {
                    ended(VerifyResult::Cancelled, None)
                } else {
                    match asset_of(catalogue, &profile_id, revision, &file_name) {
                        Err(detail) => ended(VerifyResult::Refused, Some(detail)),
                        Ok(asset) => match model.verify(&asset, &path, &token, due) {
                            Verifying::Verified => ended(VerifyResult::Verified, None),
                            Verifying::Ended { result, detail } => ended(result, detail),
                        },
                    }
                };
                // Forgotten before it is answered, so a cancellation read after the answer is seen
                // finds nothing in hand and is acknowledged by nothing.
                shared.forget(id);
                shared.answer(&answer);
                shared.work_due.store(0, Ordering::Release);
            }
        }
    }
}

/// Finds one of a profile's files in this build's catalogue, by name.
fn asset_of(
    catalogue: &Catalogue,
    profile_id: &str,
    revision: u64,
    file_name: &str,
) -> Result<Asset, String> {
    let Some(profile) = catalogue.profile(profile_id) else {
        return Err(format!("this build ships no profile called {profile_id}"));
    };
    if profile.revision().get() != revision {
        return Err(format!(
            "this build ships {profile_id} at revision {}, and revision {revision} was asked for",
            profile.revision().get()
        ));
    }
    profile
        .assets()
        .iter()
        .find(|asset| asset.file_name == file_name)
        .cloned()
        .ok_or_else(|| format!("{profile_id} records no file called {file_name}"))
}

/// Finds a load's profile in this build's catalogue, and each of its files among the paths sent.
fn resolve(
    catalogue: &Catalogue,
    profile_id: &str,
    revision: u64,
    assets: &[AssetFile],
) -> Result<(ModelProfile, Vec<LoadAsset>), String> {
    let Some(profile) = catalogue.profile(profile_id) else {
        return Err(format!("this build ships no profile called {profile_id}"));
    };
    if profile.revision().get() != revision {
        return Err(format!(
            "this build ships {profile_id} at revision {}, and revision {revision} was asked for",
            profile.revision().get()
        ));
    }
    let mut placed = Vec::with_capacity(profile.assets().len());
    for asset in profile.assets() {
        let Some(sent) = assets.iter().find(|sent| sent.file_name == asset.file_name) else {
            return Err(format!("no path was sent for {}", asset.file_name));
        };
        placed.push(LoadAsset {
            asset: asset.clone(),
            path: PathBuf::from(&sent.path),
        });
    }
    Ok((profile.clone(), placed))
}

/// Ends the process when the control thread is stuck on one request, work is overdue, or the
/// daemon that started it has gone.
fn watchdog(shared: &Shared, daemon: Option<&ProcessStartIdentity>) {
    let mut looks: u32 = 0;
    while !shared.returned.load(Ordering::Acquire) {
        std::thread::sleep(WATCH_INTERVAL);
        // The end of the input is how the process usually learns its daemon has gone. A control
        // thread that never sees that end, stuck inside a read, would leave the process and its
        // model behind, so the daemon is also looked for by its own start identity.
        looks = looks.wrapping_add(1);
        if let Some(daemon) = daemon
            && looks.is_multiple_of(DAEMON_LOOK_EVERY)
            && kr_ipc::identity::process_state(daemon) == kr_ipc::identity::ProcessState::Ended
        {
            eprintln!("kr-describe: the daemon that started this process has gone, so it ends");
            std::process::exit(Exit::DaemonGone.code());
        }
        let now = shared.stamp();
        let since = shared.control_since.load(Ordering::Acquire);
        if since != 0 && now.saturating_sub(since) > CONTROL_BOUND_MS {
            eprintln!(
                "kr-describe: the control thread has been on one request for more than \
                 {CONTROL_BOUND_MS} ms, so this process ends"
            );
            std::process::exit(Exit::ControlStalled.code());
        }
        let due = shared.work_due.load(Ordering::Acquire);
        if due != 0 && now > due {
            eprintln!(
                "kr-describe: work ran more than {OVERDUE_GRACE_MS} ms past its deadline, so this \
                 process ends"
            );
            std::process::exit(Exit::Overdue.code());
        }
    }
}

/// The lock one description process holds for its environment, for the rest of its life.
///
/// On Unix it is an exclusive advisory lock on [`LOCK_FILE`]; on Windows it is an exclusive open
/// of that file with no sharing. Either way the operating system releases it when the process
/// ends, however it ends.
#[derive(Debug)]
pub struct ProcessLock {
    _file: File,
}

/// Why a lock was not taken.
#[derive(Debug)]
pub enum LockWait {
    /// The work that wanted it was cancelled.
    Cancelled,
    /// Another process still held it at the deadline.
    DeadlinePassed,
    /// The lock file could not be opened or locked.
    Failed(std::io::Error),
}

impl ProcessLock {
    /// Takes the lock in `directory` without blocking, trying again until it is taken, the token
    /// is cancelled or the deadline passes. `held` is called once, the first time the lock is
    /// found held by another process.
    ///
    /// # Errors
    ///
    /// Returns why the lock was not taken.
    pub fn acquire_until(
        directory: &Path,
        token: &Cancellation,
        deadline: Instant,
        held: &mut dyn FnMut(),
    ) -> Result<Self, LockWait> {
        let path = directory.join(LOCK_FILE);
        let mut told = false;
        loop {
            match try_lock(&path) {
                Ok(Some(file)) => return Ok(Self { _file: file }),
                Ok(None) => {
                    if !std::mem::replace(&mut told, true) {
                        held();
                    }
                }
                Err(error) => return Err(LockWait::Failed(error)),
            }
            if token.is_cancelled() {
                return Err(LockWait::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(LockWait::DeadlinePassed);
            }
            std::thread::sleep(LOCK_RETRY);
        }
    }
}

/// Takes the lock if nothing holds it, and answers `None` when something does.
#[cfg(unix)]
fn try_lock(path: &Path) -> std::io::Result<Option<File>> {
    use rustix::fs::{FlockOperation, flock};

    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)?;
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(Some(file)),
        Err(error) if error == rustix::io::Errno::WOULDBLOCK => Ok(None),
        Err(error) => Err(std::io::Error::from(error)),
    }
}

/// Takes the lock if nothing holds it, and answers `None` when something does.
#[cfg(windows)]
fn try_lock(path: &Path) -> std::io::Result<Option<File>> {
    use std::os::windows::fs::OpenOptionsExt as _;

    /// What Windows says when another handle holds the file.
    const ERROR_SHARING_VIOLATION: i32 = 32;
    // Opening with no sharing bits set is the lock: every later open fails with a sharing
    // violation until this handle is closed.
    match std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .share_mode(0)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Returns this process's resident set, when the platform will say.
#[must_use]
pub fn own_rss_bytes() -> Option<u64> {
    let pid = sysinfo::Pid::from_u32(std::process::id());
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).map(sysinfo::Process::memory)
}

/// Returns the milliseconds since `started`.
fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Narrows a wire count to the width a job states it in.
fn bounded(value: U64) -> u32 {
    u32::try_from(value.get()).unwrap_or(u32::MAX)
}
