//! The proof that the boundary is in force, and the proof that it has been released.
//!
//! A launch that fails does not show that the policy refused it: a permission, a missing file or
//! another control could fail it the same way. So the proof asks three things of the platform,
//! through the broker, the only holder of the right to make the account's token:
//!
//! 1. an unlisted copy of a system program, made in a directory only administrators can write, is
//!    refused to the account with the policy's own error, and the application-control log names
//!    the account's own deny rule, by its identifier, as the rule that refused it;
//! 2. a program on the account's list runs;
//! 3. the same unlisted copy run under the broker's own token runs, so the refusal was the
//!    policy's and not a defect of the copy.
//!
//! The policy binds a moment after it is written, and how long that takes was not the same twice
//! on the guest it was measured on, so the first question is asked again until the platform
//! answers it. The wait ends on the platform's own answer or on an absolute deadline, which every
//! wait, every query of the log and every program of the proof stays within and which is checked
//! again before a success is taken; a deadline that runs out is a proof that did not succeed, not a
//! pass. An unlisted program that runs after an earlier refusal fails the proof: the refusal the
//! log names would then belong to an enforcement that has stopped.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::env::{self, EnvBlock, Kind, QualifiedGit, RootPaths};
use crate::frame::Class;
use crate::manifest::{GitSet, Manifest, ObjectKind};
use crate::policy::{RULE_CHECKOUT, RULE_CONNECT};
use crate::quote::quote_command_line;
use crate::window::{
    Bound, Next, QueryResult, bound, may_ask_the_log, next_after_a_query, search_is_over,
};

use super::applocker;
use super::ffi::{self, Sid};
use super::fresh;
use super::install::Paths;
use super::job::{Ended, Job, Limits};
use super::launch::{
    ChildSpec, LaunchError, Outcome, REFUSED_BY_POLICY, ResumePermit, Std, TokenSpec, VerifiedPath,
    launch, pipe, read_pipe,
};
use super::pipe::Stop;
use super::sd::{Principals, SdKind, descriptor};
use super::token::{boundary_token, new_invocation_group};

/// How long the proof waits between two launches of the unlisted program.
const LAUNCH_EVERY: Duration = Duration::from_secs(2);

/// The longest one program of the proof may run, when the deadline leaves that long.
const PROGRAM_BOUND: Duration = Duration::from_secs(30);

/// How much of the deadline is kept for the application-control log's last words, which the failure
/// of the search for a refusal quotes. The search stops that long before the deadline, and the query
/// that follows stays within the deadline itself.
const DIAGNOSTIC_RESERVE: Duration = Duration::from_secs(20);

/// How much of the time before the deadline is left, or the proof's failure when none is.
fn left_before(deadline: Instant) -> Result<Duration, Proof> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(fail("the proof's deadline passed"))
    } else {
        Ok(left)
    }
}

/// The deadline of one program of the proof: the proof's own, or [`PROGRAM_BOUND`] from now when that
/// comes first, and never later than `limit`. The proof's failure when no time is left.
fn program_deadline(deadline: Instant, limit: Instant) -> Result<Instant, Proof> {
    left_before(deadline)?;
    Ok(limit.min(Instant::now() + PROGRAM_BOUND))
}

/// The deadline of one program of the search for a refusal: the search window's end, or
/// [`PROGRAM_BOUND`] from now when that comes first, with which of the two it is. The proof's
/// failure when no time is left.
fn search_bound(deadline: Instant, search_until: Instant) -> Result<Bound, Proof> {
    left_before(deadline)?;
    Ok(bound(search_until, Instant::now() + PROGRAM_BOUND))
}

/// The result of a proof.
pub struct Proof {
    /// Whether every question was answered as the boundary requires.
    pub ready: bool,
    /// What the proof saw.
    pub detail: String,
}

fn fail(detail: impl Into<String>) -> Proof {
    Proof {
        ready: false,
        detail: detail.into(),
    }
}

/// The account of a class, from the manifest: its name and its identifier text.
fn account_of(manifest: &Manifest, class: Class) -> Option<(String, String)> {
    let name = match class {
        Class::Checkout => super::install::CHECKOUT,
        Class::Connect => super::install::CONNECT,
    };
    let object = manifest.find(ObjectKind::Account, name)?;
    Some((name.to_owned(), object.detail.clone()?))
}

/// What to run for [`run_captured`].
pub struct Run<'a> {
    /// The token the program runs under.
    pub token: TokenSpec<'a>,
    /// The group the token carries, named on the program's process and thread; none for a program
    /// of the broker's own token.
    pub group: Option<&'a Sid>,
    /// The program.
    pub program: VerifiedPath,
    /// Its command line.
    pub command_line: String,
    /// Its working directory.
    pub cwd: &'a Path,
    /// Its environment.
    pub env: &'a EnvBlock,
}

/// What a captured run wrote and how it ended.
#[derive(Debug)]
pub struct Captured {
    /// How the program ended.
    pub outcome: Outcome,
    /// What it wrote to its standard output.
    pub stdout: Vec<u8>,
    /// What it wrote to its standard error.
    pub stderr: Vec<u8>,
}

/// Runs a program of the proof to its end, up to an absolute deadline, and keeps what it wrote.
///
/// The program has a job of its own, which is ended before the function returns, so nothing it
/// started outlives the call. Its process and thread name the token's group and the system, or the
/// system alone for the broker's own token. It belongs to no invocation, so its permit to resume
/// is the proof's own: this is the one place that makes one.
///
/// The call returns by the deadline, and at most 100 ms more in the launch's cleanup of a child
/// that never ran and in the cancel of a read that did not finish: those two waits keep a floor
/// that the caller's deadline does not shorten. The program is waited for until two seconds before
/// the deadline and the job's end and the pipes' end take the rest, so the caller's own promise
/// holds inside the two seconds. A program that is not shown to have ended by the deadline is an
/// uncertain end and not a late success.
///
/// # Errors
///
/// Returns [`LaunchError::NotStarted`] when the platform refuses to start the program, the other
/// errors of [`launch`] and of the pipes, and [`LaunchError::EndUncertain`] when the job's end is
/// not proved, when a child reported that it was not seen to end (also on a launch that failed
/// after the process was made), or when a pipe did not reach its end after the job's end (also
/// after a launch that failed: a writer outside the job may still hold the pipe, and the error then
/// says both).
pub fn run_captured(run: Run<'_>, deadline: Instant) -> Result<Captured, LaunchError> {
    run_captured_until(run, deadline, None)
}

/// [`run_captured`] for a request of the broker's service: the wait for the program ends at the
/// stop as well, and the program is then ended with its job like one that ran out of time. The
/// outcome of such a run is [`Outcome::TimedOut`] and the caller, which looks at the stop, tells it
/// from a program that ran out of its time.
///
/// # Errors
///
/// As for [`run_captured`].
pub fn run_captured_until(
    run: Run<'_>,
    deadline: Instant,
    stop: Option<&Stop>,
) -> Result<Captured, LaunchError> {
    if Instant::now() >= deadline {
        return Err(LaunchError::DeadlinePassed);
    }
    let mut job = Job::new(Limits::INVOCATION)?;
    let (out_read, out_write) = pipe()?;
    let (err_read, err_write) = pipe()?;
    let descriptor = descriptor(
        SdKind::ProcessThread,
        &Principals {
            group: run.group.cloned(),
            ..Principals::default()
        },
    )?;
    let launched = launch(ChildSpec {
        invocation: None,
        token: run.token,
        job: &job,
        program: run.program,
        command_line: run.command_line,
        cwd: run.cwd,
        env: run.env,
        stdin: Std::Nul,
        stdout: Std::Pipe(out_write),
        stderr: Std::Pipe(err_write),
        process_descriptor: &descriptor,
        thread_descriptor: &descriptor,
        deadline: Some(deadline),
    });
    let wait_until = deadline
        .checked_sub(END_RESERVE)
        .unwrap_or_else(Instant::now);
    let (result, out, err) = std::thread::scope(|scope| {
        // The readers stop at the deadline, so that a process that keeps the pipes open after the
        // job's end is not waited for: the end is then not proved and the call says so. They read
        // after a launch that failed too: the launch may have made a process, and a writer outside
        // the job may hold a pipe whatever became of it.
        let out = scope.spawn(|| read_pipe(&out_read, deadline));
        let err = scope.spawn(|| read_pipe(&err_read, deadline));
        let result = match launched.and_then(|suspended| {
            let permit = ResumePermit::for_proof(&suspended);
            suspended.resume(permit)
        }) {
            Ok(child) => {
                let bound = wait_until.saturating_duration_since(Instant::now());
                let waited = match stop {
                    Some(stop) => child.wait_or_stop(bound, stop),
                    None => child.wait(bound),
                };
                // Anything the program started ends with the job, which also lets the pipes
                // reach their end. A program still running at the bound is ended the same way.
                let ended = job.end(&[&child], deadline);
                match settled(&job, ended) {
                    Ok(()) => match waited {
                        Ok(Some(code)) => Ok(Outcome::Ran(code)),
                        Ok(None) => Ok(Outcome::TimedOut),
                        Err(error) => Err(LaunchError::Platform(error)),
                    },
                    Err(uncertain) => Err(uncertain),
                }
            }
            Err(error) => Err(after_failed_launch(&mut job, error, deadline)),
        };
        (result, out.join(), err.join())
    });
    // Both readers are read before any error is returned. The job's end may be proved while a pipe
    // is still held open by a writer that is not in the job, and then what the program wrote may be
    // incomplete and the end is uncertain, whatever the error says that the run failed on.
    let readers = match (out, err) {
        (Ok(out), Ok(err)) if out.ended && err.ended => Ok((out, err)),
        (Ok(out), Ok(err)) => Err(format!(
            "a pipe of a program of the proof was still open after the end of its job (standard output ended {}, standard error ended {})",
            out.ended, err.ended
        )),
        _ => Err("a reader of the program's output failed".to_owned()),
    };
    let (outcome, out, err) = match (result, readers) {
        (Err(error @ LaunchError::EndUncertain(_)), _) => return Err(error),
        (Err(error), Err(reason)) => {
            return Err(LaunchError::EndUncertain(format!(
                "{reason}; the run had also failed: {error}"
            )));
        }
        (Err(error), Ok(_)) => return Err(error),
        (Ok(_), Err(reason)) => return Err(LaunchError::EndUncertain(reason)),
        (Ok(outcome), Ok((out, err))) => (outcome, out, err),
    };
    Ok(Captured {
        outcome,
        stdout: out.bytes,
        stderr: err.bytes,
    })
}

/// How much of a run's time before its deadline is kept for the job's end and for the pipes' end.
/// A job whose processes are ended is empty within milliseconds, so this is generous, and it is
/// part of the deadline, not an addition to it.
const END_RESERVE: Duration = Duration::from_secs(2);

/// What a launch that failed leaves: the job is ended and the job's reports are read, because the
/// launch may have made a process before it failed (a process that is not in the job, a thread
/// that cannot be held, a time that cannot be read) and the child it ended on the way may not have
/// been seen to end. The error is the launch's own unless the end is not proved.
fn after_failed_launch(job: &mut Job, error: LaunchError, deadline: Instant) -> LaunchError {
    let ended = job.end(&[], deadline);
    match settled(job, ended) {
        Ok(()) => error,
        Err(uncertain) => uncertain,
    }
}

/// Whether the end of a job is proved and nothing reported otherwise: the job's own count and its
/// retained processes agree, and no child told the owner that it was not seen to end.
fn settled(job: &Job, ended: Ended) -> Result<(), LaunchError> {
    if ended.proved() && job.unproved_reasons().is_empty() {
        Ok(())
    } else {
        Err(uncertain_end(job, ended))
    }
}

/// The error for a job that was not shown empty: the end is uncertain, the reasons are the job's
/// own.
fn uncertain_end(job: &Job, ended: Ended) -> LaunchError {
    let reasons = job.unproved_reasons().join("; ");
    LaunchError::EndUncertain(format!(
        "a program of the proof was not shown to have ended (exited {}, job empty {}): {reasons}",
        ended.all_exited, ended.active_zero
    ))
}

/// The system's own Windows directory, from the platform and not from any environment.
fn system_windows_directory() -> Result<String, String> {
    ffi::system_windows_directory().map_err(|error| error.to_string())
}

/// The environment of a program of the proof, which runs in no repository. The proof's scratch
/// directory stands for the private root.
pub(super) fn proof_environment(git: &GitSet, scratch: &Path) -> Result<EnvBlock, String> {
    let roots = RootPaths {
        system: system_windows_directory()?,
        boundary: Paths::system()
            .map_err(|error| error.to_string())?
            .program
            .display()
            .to_string(),
        private_root: scratch.display().to_string(),
    };
    env::build_env(
        Kind::Proof,
        &roots,
        None,
        &QualifiedGit {
            dir: git.dir.clone(),
        },
    )
    .map_err(|error| error.to_string())
}

/// Starts one program of the proof through the launcher and waits for it.
fn run_program(
    token: TokenSpec<'_>,
    group: Option<&Sid>,
    program: &Path,
    arguments: &[&str],
    cwd: &Path,
    env: &EnvBlock,
    limit: Limit<'_>,
) -> Result<Captured, LaunchError> {
    let name = program.display().to_string();
    let mut parts = vec![name.as_str()];
    parts.extend_from_slice(arguments);
    run_captured_until(
        Run {
            token,
            group,
            program: VerifiedPath::new(program)?,
            command_line: quote_command_line(&parts),
            cwd,
            env,
        },
        limit.by,
        Some(limit.stop),
    )
}

/// What ends one program of the proof: its deadline, and the service's stop.
#[derive(Clone, Copy)]
struct Limit<'a> {
    by: Instant,
    stop: &'a Stop,
}

/// The failure of a proof that the service's stop reached, or none. A proof looks at the stop after
/// each query and before and after each program, so that a stop does not wait for the proof's own
/// deadline.
fn stopped(stop: &Stop) -> Option<Proof> {
    stop.is_set().then(|| fail("the service is stopping"))
}

fn same_path(left: &str, right: &Path) -> bool {
    left.eq_ignore_ascii_case(&right.display().to_string())
}

/// Makes the unlisted program as a new file with its own descriptor (owned by the administrators,
/// read and run through the invocation's group that the proof's token carries, changed by none)
/// and copies a system program into it. The file holds the bytes of that system program and no
/// secret.
fn make_unlisted(source: &Path, target: &Path, group: &Sid) -> std::io::Result<()> {
    let mut from = std::fs::File::open(source)?;
    let mut to = fresh::file_with(
        target,
        SdKind::ProofProgram,
        &Principals {
            group: Some(group.clone()),
            ..Principals::default()
        },
        true,
    )?;
    std::io::copy(&mut from, &mut to)?;
    to.sync_all()
}

/// A scratch directory that only administrators can write and every account can read and enter,
/// removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(under: &Path) -> Result<Scratch, String> {
        // The name is new and random and the descriptor is in the call that makes the directory:
        // no list is changed by path, and nothing that was there before can be in it.
        let dir = fresh::directory(
            under,
            "proof",
            SdKind::AdminDir,
            &Principals {
                users_may_read: true,
                ..Principals::default()
            },
        )
        .map_err(|error| format!("making a directory in {}: {error}", under.display()))?;
        Ok(Scratch(dir))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What one launch of the unlisted program showed.
enum Seen {
    /// The policy refused it.
    Refused,
    /// It ran, with nothing refused before: the policy may not bind yet. The text says how it ended.
    Ran(String),
}

/// What the proof makes of one launch of the unlisted program. A launch that runs after an earlier
/// refusal fails the proof: the policy has stopped refusing, so a refusal that the log names late
/// belongs to enforcement that is no longer in force.
fn judge_launch(
    launched: Result<Captured, LaunchError>,
    refused_before: bool,
    account: &str,
    attempts: u32,
) -> Result<Seen, Proof> {
    match launched {
        Err(LaunchError::NotStarted(code)) if code == REFUSED_BY_POLICY => Ok(Seen::Refused),
        Err(LaunchError::NotStarted(code)) => Err(fail(format!(
            "the unlisted program could not be started for {account}, with error {code} and not the policy's {REFUSED_BY_POLICY}"
        ))),
        Ok(Captured {
            outcome: Outcome::Ran(code),
            stdout,
            stderr,
        }) => {
            let text = format!(
                "it ended with {code} after writing {} and {} bytes",
                stdout.len(),
                stderr.len()
            );
            if refused_before {
                Err(fail(format!(
                    "the unlisted program ran for {account} after it was refused ({attempts} launches; {text})"
                )))
            } else {
                Ok(Seen::Ran(text))
            }
        }
        Ok(Captured {
            outcome: Outcome::TimedOut,
            ..
        }) => Err(fail("the unlisted program ran for its whole bound")),
        Err(error) => Err(fail(error.to_string())),
    }
}

/// What the cases use to judge a launch as the proof does, and to make a stop come at a point of a
/// proof that no case could otherwise hit.
#[cfg(feature = "testing")]
pub mod testing {
    use std::sync::Mutex;

    use super::{Captured, LaunchError, Seen, judge_launch};

    type Hook = Box<dyn Fn() + Send + Sync>;

    static AFTER_THE_SEARCH: Mutex<Option<Hook>> = Mutex::new(None);

    /// Sets, or with none clears, what a proof does when its search for a refusal has found one, before
    /// it starts any program that follows. The hook is a flag of the whole process.
    pub fn after_the_search(hook: Option<Hook>) {
        *AFTER_THE_SEARCH
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    pub(super) fn search_ended() {
        if let Some(hook) = AFTER_THE_SEARCH
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            hook();
        }
    }

    /// Judges one launch of the unlisted program: `Ok(true)` when it was refused, `Ok(false)` when
    /// it ran with nothing refused before, and the failure's text when the proof fails on it.
    ///
    /// # Errors
    ///
    /// Returns the proof's failure text.
    pub fn judge(
        launched: Result<Captured, LaunchError>,
        refused_before: bool,
    ) -> Result<bool, String> {
        match judge_launch(launched, refused_before, "the account", 1) {
            Ok(Seen::Refused) => Ok(true),
            Ok(Seen::Ran(_)) => Ok(false),
            Err(failed) => Err(failed.detail),
        }
    }
}

/// Proves that the policy refuses an unlisted program to a class's token and runs a listed one,
/// all before the deadline.
#[must_use]
pub fn prove(
    manifest: &Manifest,
    class: Class,
    staging: &Path,
    deadline: Instant,
    stop: &Stop,
) -> Proof {
    let Some((account, sid)) = account_of(manifest, class) else {
        return fail("the manifest records no account for this class");
    };
    let Some(git) = manifest.git.as_ref() else {
        return fail("the manifest records no Git installation");
    };
    let rule = match class {
        Class::Checkout => RULE_CHECKOUT,
        Class::Connect => RULE_CONNECT,
    };
    let scratch = match Scratch::new(staging) {
        Ok(scratch) => scratch,
        Err(reason) => return fail(reason),
    };
    let system = match system_windows_directory() {
        Ok(system) => PathBuf::from(system),
        Err(reason) => return fail(reason),
    };
    // The group is the token's own, enabled in it, and the only identifier of the token that the
    // unlisted program's descriptor can name: the account's identifier is deny-only in the token.
    let group = new_invocation_group();
    let unlisted = scratch.0.join("unlisted.exe");
    if let Err(error) = make_unlisted(
        &system.join("System32").join("hostname.exe"),
        &unlisted,
        &group,
    ) {
        return fail(format!(
            "copying a system program into the scratch directory: {error}"
        ));
    }
    let token = match boundary_token(&account, &group) {
        Ok(token) => token,
        Err(error) => return fail(format!("making the token for {account}: {error}")),
    };
    let environment = match proof_environment(git, &scratch.0) {
        Ok(environment) => environment,
        Err(reason) => return fail(reason),
    };
    let record = applocker::newest_record_until(&scratch.0, &environment, deadline, Some(stop));
    if let Some(failed) = stopped(stop) {
        return failed;
    }
    let record = match record {
        Ok(record) => record,
        Err(error) => return fail(error.to_string()),
    };
    // The platform refuses the program from the first launch, but its log names the rule only some
    // time after the start of Windows (170 s on the guest, none at all before that), and a refused
    // launch that the log never names proves nothing about which rule refused it. So the program
    // is started again, one launch every two seconds, until the refusal and an event of the log
    // that names this rule, this account and this program are both in hand.
    let started = Instant::now();
    // The search stops this much before the deadline; the log's last words come from the time kept
    // by that, so every query of the search itself ends by `search_until`, not by the deadline.
    let search_until = deadline.checked_sub(DIAGNOSTIC_RESERVE).unwrap_or(deadline);
    let mut attempts = 0_u32;
    let mut refused = false;
    let mut over = false;
    let mut cut_launch = false;
    let mut last = String::from("no launch was made");
    loop {
        if stop.is_set() {
            return fail("the service is stopping");
        }
        if over || Instant::now() >= search_until {
            // The log's last words come from the time kept for them, and the query stays within the
            // deadline like everything else.
            let log = applocker::latest(&scratch.0, &environment, deadline, Some(stop))
                .unwrap_or_else(|error| format!("unreadable: {error}"));
            if let Some(failed) = stopped(stop) {
                return failed;
            }
            let seen = match (refused, cut_launch) {
                (true, true) => {
                    "refused earlier; the launch that the search's end cut had started, and was not refused"
                }
                (false, true) => "not refused; the launch that the search's end cut had started",
                (true, false) => "refused, but the log named no rule",
                (false, false) => "not refused",
            };
            return fail(format!(
                "the policy did not show a refusal of the unlisted program to {account} by rule {rule} before the proof's deadline ({seen}; {attempts} launches in {:.0} s; the last: {last}; the application-control log last said: {log})",
                started.elapsed().as_secs_f32()
            ));
        }
        let bound = match search_bound(deadline, search_until) {
            Ok(bound) => bound,
            Err(failed) => return failed,
        };
        attempts += 1;
        let launched = run_program(
            TokenSpec::Boundary(&token),
            Some(&group),
            &unlisted,
            &[],
            &scratch.0,
            &environment,
            Limit { by: bound.by, stop },
        );
        if let Some(failed) = stopped(stop) {
            return failed;
        }
        // A launch that the search's own end kept from starting is the end of the search, not a
        // failure of the proof: the log is read next, from the reserve.
        if matches!(launched, Err(LaunchError::DeadlinePassed)) && search_is_over(true, bound) {
            continue;
        }
        // A program that was given the window's end as its deadline and was cut at it ran for no
        // bound of its own: the search is over, not the proof. The launch did start, and the
        // failure's text says so. A program cut at its own bound, and every other result of a
        // launch, is judged as it is at any time.
        if matches!(
            launched,
            Ok(Captured {
                outcome: Outcome::TimedOut,
                ..
            })
        ) && search_is_over(true, bound)
        {
            over = true;
            cut_launch = true;
            last = String::from("a launch cut by the end of the search had started");
            continue;
        }
        match judge_launch(launched, refused, &account, attempts) {
            Ok(Seen::Refused) => {
                refused = true;
                last = format!("it was refused with {REFUSED_BY_POLICY}");
            }
            Ok(Seen::Ran(text)) => last = text,
            Err(failed) => return failed,
        }
        if refused && !may_ask_the_log(Instant::now(), search_until) {
            // The refusal came back after the search's own end: the search is over, and the failure
            // that follows says what it saw and what the log last said.
            over = true;
        } else if refused {
            let answer = applocker::blocked_after(
                record,
                &scratch.0,
                &environment,
                search_until,
                Some(stop),
            );
            if let Some(failed) = stopped(stop) {
                return failed;
            }
            let result = match &answer {
                Ok(events) => QueryResult::Answered {
                    refusal_found: events.iter().any(|event| {
                        event.rule_id == rule
                            && event.user.eq_ignore_ascii_case(&sid)
                            && same_path(&event.path, &unlisted)
                    }),
                },
                Err(error) => QueryResult::Ended(error.query_end()),
            };
            // A query that the search's own end stopped ends the search: one cut at the deadline it
            // was given, one that found the deadline passed before it was made, and one whose
            // program could not start because the deadline had passed. A query that failed to
            // start, a pipe error, a bad exit or a cut at the query's own bound is a failure of
            // the proof at any time.
            match next_after_a_query(result) {
                Next::Found => {
                    // The evidence counts only if it was in hand before the deadline.
                    if let Err(failed) = left_before(deadline) {
                        return failed;
                    }
                    break;
                }
                Next::Keep => {}
                Next::Over => over = true,
                Next::Fail => {
                    return fail(
                        answer
                            .err()
                            .map_or_else(String::new, |error| error.to_string()),
                    );
                }
            }
        }
        if over {
            continue;
        }
        // The pause ends at the stop, and the next pass of the loop sees it.
        let _ = stop.wait(LAUNCH_EVERY.min(search_until.saturating_duration_since(Instant::now())));
    }
    #[cfg(feature = "testing")]
    testing::search_ended();
    if let Some(failed) = stopped(stop) {
        return failed;
    }
    let git_exe = Path::new(&git.dir)
        .join("mingw64")
        .join("bin")
        .join("git.exe");
    let by = match program_deadline(deadline, deadline) {
        Ok(by) => by,
        Err(failed) => return failed,
    };
    match run_program(
        TokenSpec::Boundary(&token),
        Some(&group),
        &git_exe,
        &["--version"],
        &scratch.0,
        &environment,
        Limit { by, stop },
    ) {
        _ if stop.is_set() => return fail("the service is stopping"),
        Ok(Captured {
            outcome: Outcome::Ran(0),
            ..
        }) => {}
        Ok(other) => {
            return fail(format!(
                "Git did not run for {account}: {:?}",
                other.outcome
            ));
        }
        Err(error) => return fail(error.to_string()),
    }
    if let Some(failed) = stopped(stop) {
        return failed;
    }
    let by = match program_deadline(deadline, deadline) {
        Ok(by) => by,
        Err(failed) => return failed,
    };
    match run_program(
        TokenSpec::Own,
        None,
        &unlisted,
        &[],
        &scratch.0,
        &environment,
        Limit { by, stop },
    ) {
        _ if stop.is_set() => return fail("the service is stopping"),
        Ok(Captured {
            outcome: Outcome::Ran(0),
            ..
        }) => {}
        Ok(other) => {
            return fail(format!(
                "the unlisted program did not run under the broker's own token: {:?}",
                other.outcome
            ));
        }
        Err(error) => {
            return fail(format!(
                "the unlisted program did not run under the broker's own token: {error}"
            ));
        }
    }
    // A success is taken only before the deadline, and not after a stop.
    if let Some(failed) = stopped(stop) {
        return failed;
    }
    if let Err(failed) = left_before(deadline) {
        return failed;
    }
    Proof {
        ready: true,
        detail: format!(
            "{account}: an unlisted program was refused with {REFUSED_BY_POLICY} by rule {rule} after {attempts} launch(es) in {:.1} s, Git ran, and the same program ran under the broker's own token",
            started.elapsed().as_secs_f32()
        ),
    }
}

/// Proves that a program the policy refused runs again for a class's token, before the deadline.
#[must_use]
pub fn release(
    manifest: &Manifest,
    class: Class,
    staging: &Path,
    deadline: Instant,
    stop: &Stop,
) -> Proof {
    let Some((account, _)) = account_of(manifest, class) else {
        return fail("the manifest records no account for this class");
    };
    let Some(git) = manifest.git.as_ref() else {
        return fail("the manifest records no Git installation");
    };
    let group = new_invocation_group();
    let token = match boundary_token(&account, &group) {
        Ok(token) => token,
        Err(error) => return fail(format!("making the token for {account}: {error}")),
    };
    let environment = match proof_environment(git, staging) {
        Ok(environment) => environment,
        Err(reason) => return fail(reason),
    };
    let cmd = match system_windows_directory() {
        Ok(system) => Path::new(&system).join("System32").join("cmd.exe"),
        Err(reason) => return fail(reason),
    };
    let started = Instant::now();
    let mut attempts = 0_u32;
    loop {
        if stop.is_set() {
            return fail("the service is stopping");
        }
        let by = match program_deadline(deadline, deadline) {
            Ok(by) => by,
            Err(failed) => return failed,
        };
        attempts += 1;
        match run_program(
            TokenSpec::Boundary(&token),
            Some(&group),
            &cmd,
            &["/c", "exit", "0"],
            staging,
            &environment,
            Limit { by, stop },
        ) {
            _ if stop.is_set() => return fail("the service is stopping"),
            Ok(Captured {
                outcome: Outcome::Ran(0),
                ..
            }) => {
                if let Err(failed) = left_before(deadline) {
                    return failed;
                }
                return Proof {
                    ready: true,
                    detail: format!(
                        "{account}: cmd.exe runs again after {attempts} launch(es) in {:.1} s",
                        started.elapsed().as_secs_f32()
                    ),
                };
            }
            Err(LaunchError::NotStarted(code)) if code == REFUSED_BY_POLICY => {}
            Ok(other) => return fail(format!("cmd.exe for {account}: {:?}", other.outcome)),
            Err(error) => return fail(error.to_string()),
        }
        if Instant::now() >= deadline {
            return fail(format!(
                "cmd.exe is still refused to {account} after {:.0} seconds ({attempts} launches)",
                started.elapsed().as_secs_f32()
            ));
        }
        let _ = stop
            .wait(Duration::from_secs(1).min(deadline.saturating_duration_since(Instant::now())));
    }
}
