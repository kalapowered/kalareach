//! `kr host desktop-checks`: running the disclosed desktop checks and showing what each found.
//!
//! The checks take a screen image and start an application, so the host never performs them on a
//! read: a person asks, here, and the control daemon has the worker of one of the host's sessions
//! perform them, because a platform files what they need under the program that asks and the
//! worker is the context an agent runs in. This command asks, waits for the run to end for a
//! bounded time, and prints the records the way `kr doctor` does, so one renderer says what each
//! check found wherever a person reads it.
//!
//! The command runs outside every session, as `kr host stop` does, and refuses where whether it is
//! inside one cannot be established. The guard stops a command started by accident in a session
//! from starting the checks or naming a file for them; it is not isolation from other code that
//! runs as the same user.
//!
//! `--file` names the file the read check reads. A path relative to the directory the command runs
//! in is made absolute here, because the host reads it from a worker that runs elsewhere. Without
//! the option the read check reads nothing and says so.

use std::path::Path;
use std::time::Duration;

use tokio::time::Instant;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::paths::HostPaths;
use kr_protocol::desktop::{
    CapabilityChecks, CapabilityChecksFailure, CapabilityChecksState, DesktopCapabilityReport,
    EnvironmentCapabilitiesCheckParams, EnvironmentCapabilitiesParams,
    EnvironmentCapabilitiesResult,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::SessionId;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, TimestampMs};

use crate::cli::DesktopChecksArguments;
use crate::daemon::Daemon;
use crate::error::{CliError, Result};
use crate::output::{self, Document, closed};
use crate::report::{self, Completion};
use crate::stdout_line;

/// How long the command takes in all, from its start: the one deadline of every call it makes to
/// the host and of its waits between them. The setup page says a run takes about two minutes, most
/// of it a person answering a platform's question.
const WAIT: Duration = Duration::from_secs(300);

/// How often the daemon is asked where the run stands.
const POLL: Duration = Duration::from_millis(500);

/// Runs `kr host desktop-checks` and prints what the checks found.
///
/// # Errors
///
/// Returns the refusal inside a session, a usage error for a path that is not text, the daemon's
/// refusal of the request, or a transport failure. A run that ends without findings is reported as
/// a failure that has already been written.
pub async fn run(
    paths: &HostPaths,
    arguments: &DesktopChecksArguments,
    json: bool,
) -> Result<Completion> {
    let deadline = Instant::now() + WAIT;
    crate::bind::require_outside_to_run_the_checks(&crate::build_id()).await?;
    let authorised_file = arguments.file.as_deref().map(named).transpose()?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let followed = follow(
        &mut Calls {
            daemon: &mut daemon,
        },
        authorised_file,
        deadline,
        || {
            if !json {
                say_the_checks_are_running();
            }
        },
    )
    .await?;
    let (unfinished, checks, records) = match followed {
        Followed::Found { checks, records } => (None, Some(checks), Some(records)),
        Followed::Unfinished {
            checks,
            records,
            words,
        } => (
            Some(CliError::Unfinished {
                code: ErrorCode::ResourceUnavailable,
                message: words,
            }),
            checks,
            records,
        ),
    };
    match (&unfinished, json) {
        (None, true) => output::document(&document(checks.as_ref(), records.as_ref())),
        (Some(error), true) => output::document(&report::with_failure(
            document(checks.as_ref(), records.as_ref()),
            error,
        )),
        (None, false) => {
            output::line(&stdout_line!("Disclosed desktop checks"));
            if let Some(records) = &records {
                output::lines(&report::capability_lines(records));
            }
        }
        (Some(error), false) => report::failed(error),
    }
    Ok(unfinished.map_or(Completion::Done, Completion::Reported))
}

/// What the command asks of the control daemon, so that a case can give it the answers, and the
/// silence, that a real daemon gives only by chance.
trait Asked {
    /// What the host holds besides where the checks stand, which the command prints.
    type Records;

    /// Asks for a run, reading `authorised_file` where there is one.
    async fn begin(&mut self, authorised_file: Option<String>) -> Result<CapabilityChecks>;

    /// Reads where the checks stand and what the host holds.
    async fn read(&mut self) -> Result<(CapabilityChecks, Self::Records)>;
}

/// The control daemon of the environment the command works on.
struct Calls<'a> {
    daemon: &'a mut Daemon,
}

impl Asked for Calls<'_> {
    type Records = DesktopCapabilityReport;

    async fn begin(&mut self, authorised_file: Option<String>) -> Result<CapabilityChecks> {
        let environment_id = self.daemon.environment_id();
        self.daemon
            .mutate(
                Method::EnvironmentCapabilitiesCheck,
                &EnvironmentCapabilitiesCheckParams {
                    environment_id,
                    authorised_file: Nullable(authorised_file),
                },
            )
            .await
    }

    async fn read(&mut self) -> Result<(CapabilityChecks, DesktopCapabilityReport)> {
        let environment_id = self.daemon.environment_id();
        let result: EnvironmentCapabilitiesResult = self
            .daemon
            .read(
                Method::EnvironmentCapabilities,
                &EnvironmentCapabilitiesParams { environment_id },
            )
            .await?;
        Ok((result.checks, result.desktop))
    }
}

/// What the command came to.
enum Followed<R> {
    /// The run ended with findings, which are these.
    Found {
        /// Where the run stands.
        checks: CapabilityChecks,
        /// What the host holds.
        records: R,
    },
    /// The command has no findings to give, and says why.
    Unfinished {
        /// Where the run stood when the command last saw it, where it saw it.
        checks: Option<CapabilityChecks>,
        /// What the host held when the command last read it, where this run's own are the ones.
        records: Option<R>,
        /// What a person is told.
        words: Shown,
    },
}

/// Asks for a run and follows it until it ends or `deadline` passes.
///
/// The deadline bounds every call the command makes, the first request and each read, and the wait
/// between reads: a daemon that holds its connection open and never answers ends the command at the
/// deadline with nothing to show but the words that say so.
///
/// The run is the one the host named in its first answer ([`Run`]), and the command reports no
/// other: a read that finds another run, which a second caller began once this one ended, ends the
/// command with the words that say so, and the findings of that run are not shown as this one's.
/// Where the first answer already says the run ended, that answer is the command's own, and a later
/// read only supplies the records if they are still that run's.
///
/// A file named for a run that was already going is not read, and the command says so instead of
/// reporting that run: it is not the run the person asked for.
///
/// `announce` is called once the host has started a run.
async fn follow<A: Asked>(
    asked: &mut A,
    authorised_file: Option<String>,
    deadline: Instant,
    announce: impl FnOnce(),
) -> Result<Followed<A::Records>> {
    let named = authorised_file.is_some();
    let before = kr_ipc::now_ms();
    let Some(begun) = within(deadline, asked.begin(authorised_file))
        .await
        .transpose()?
    else {
        return Ok(unanswered(None));
    };
    // A run that began before the request was going already, and the host does not start a run it
    // is already performing: it answers with that run and the file this command named is lost.
    if named
        && begun.state == CapabilityChecksState::Running
        && begun.started_at_ms.0.is_some_and(|began| began < before)
    {
        return Ok(Followed::Unfinished {
            checks: Some(begun),
            records: None,
            words: shown!(
                "A run of the checks was already going, so the file you named was not read. Run \
                 the command again once it ends."
            ),
        });
    }
    let accepted = Run::of(&begun);
    let running = begun.state == CapabilityChecksState::Running;
    if running {
        announce();
    }
    let mut seen = begun;
    loop {
        let Some((checks, records)) = within(deadline, asked.read()).await.transpose()? else {
            return Ok(unanswered(Some(seen)));
        };
        let ours = Run::of(&checks) == accepted;
        if !running {
            return Ok(kept(seen, ours.then_some(records)));
        }
        if !ours {
            return Ok(replaced(seen));
        }
        if checks.state != CapabilityChecksState::Running || Instant::now() >= deadline {
            return Ok(ended(checks, records));
        }
        seen = checks;
        tokio::time::sleep_until(deadline.min(Instant::now() + POLL)).await;
    }
}

/// A run of the checks as the host names it: when it began and the session whose worker performs
/// it. Another run has another pair, so a command that reads the host again can tell that the run
/// it asked for is no longer the one the host holds.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Run {
    started_at_ms: Option<TimestampMs>,
    session_id: Option<SessionId>,
}

impl Run {
    fn of(checks: &CapabilityChecks) -> Self {
        Self {
            started_at_ms: checks.started_at_ms.0,
            session_id: checks.session_id.0,
        }
    }
}

/// The outcome of a call, or `None` where `deadline` passed before the host answered it.
async fn within<T>(deadline: Instant, call: impl Future<Output = T>) -> Option<T> {
    tokio::time::timeout_at(deadline, call).await.ok()
}

/// What a run that has stopped, or has gone on to the deadline, comes to.
fn ended<R>(checks: CapabilityChecks, records: R) -> Followed<R> {
    match unfinished(&checks) {
        None => Followed::Found { checks, records },
        Some(words) => Followed::Unfinished {
            checks: Some(checks),
            records: Some(records),
            words,
        },
    }
}

/// What a run comes to that the host's first answer already ended: that answer says how, and the
/// records come with it where a later read found them still that run's.
fn kept<R>(first: CapabilityChecks, records: Option<R>) -> Followed<R> {
    match (unfinished(&first), records) {
        (None, Some(records)) => Followed::Found {
            checks: first,
            records,
        },
        (words, records) => Followed::Unfinished {
            words: words.unwrap_or_else(replaced_words),
            checks: Some(first),
            records,
        },
    }
}

/// What the command comes to where the host holds another run than the one it asked for.
fn replaced<R>(seen: CapabilityChecks) -> Followed<R> {
    Followed::Unfinished {
        checks: Some(seen),
        records: None,
        words: replaced_words(),
    }
}

/// What a person is told where another run took the place of the one the command started.
fn replaced_words() -> Shown {
    shown!(
        "Another run of the checks replaced the one this command started, so what the host holds \
         now is not this run's findings. Run the command again."
    )
}

/// What the command comes to where the host did not answer a call in time.
fn unanswered<R>(seen: Option<CapabilityChecks>) -> Followed<R> {
    Followed::Unfinished {
        checks: seen,
        records: None,
        words: shown!(
            "The host did not answer within five minutes, so it is not known where the checks \
             stand. Run kr doctor to see what the host holds once it answers."
        ),
    }
}

/// Says on standard error that the checks are running, and what a person may be asked meanwhile.
fn say_the_checks_are_running() {
    // Only macOS asks the person at the machine for permission while the checks run.
    report::say(&if cfg!(target_os = "macos") {
        shown!(
            "The checks are running in a session's worker. macOS may ask you to allow \
             something while they do, and they can take about two minutes."
        )
    } else {
        shown!("The checks are running in a session's worker, and they can take about two minutes.")
    });
}

/// The path the host is asked to read: absolute, and text, which the request carries it as.
fn named(file: &Path) -> Result<String> {
    let absolute = std::path::absolute(file).map_err(|error| {
        CliError::Usage(shown!(
            "the directory this command runs in cannot be read, so a relative path cannot be \
             made absolute: {}",
            Shown::io(&error)
        ))
    })?;
    absolute.to_str().map(str::to_owned).ok_or_else(|| {
        CliError::Usage(shown!(
            "that path is not text, so the host cannot be asked to read it"
        ))
    })
}

/// What the command prints with `--json`: where the run stands, and the records the host holds,
/// each where the command has it.
fn document(
    checks: Option<&CapabilityChecks>,
    records: Option<&DesktopCapabilityReport>,
) -> Document {
    let mut document = Document::new();
    if let Some(checks) = checks {
        document = document.with(
            "checks",
            Document::new()
                .with("state", closed(&checks.state))
                .with("failure", closed(&checks.failure))
                .with("started_at_ms", closed(&checks.started_at_ms))
                .with("finished_at_ms", closed(&checks.finished_at_ms))
                .with("session_id", closed(&checks.session_id)),
        );
    }
    if let Some(records) = records {
        document = document.with("desktop", report::desktop_capabilities(records));
    }
    document
}

/// What a run that has not given findings says, or nothing where it has.
///
/// The words of a run that failed are the setup page's, with this program in place of the
/// application: a person reads one account of a failure wherever the checks are run.
fn unfinished(checks: &CapabilityChecks) -> Option<Shown> {
    match checks.state {
        CapabilityChecksState::Current => None,
        CapabilityChecksState::Running => Some(shown!(
            "The checks are still running after five minutes. They go on in the session's \
             worker, and kr doctor shows what they found once they end."
        )),
        CapabilityChecksState::NotRun => Some(shown!(
            "The host holds no run of the checks, so nothing was checked. Run the command again."
        )),
        CapabilityChecksState::Stale => Some(shown!(
            "The checks were run before something changed. Run them again."
        )),
        CapabilityChecksState::Failed => Some(match checks.failure.as_ref() {
            Some(CapabilityChecksFailure::NoSession) => shown!(
                "No session of the kind this host creates is running. The checks run inside a \
                 session's own worker, which is the place an agent runs, so start a session and \
                 run them again."
            ),
            Some(CapabilityChecksFailure::WorkerRefused) => shown!(
                "The session's worker answered with an error: it was already performing a run, \
                 could not start one, or its run did not finish. Run the checks again."
            ),
            Some(CapabilityChecksFailure::WorkerUnreachable) => shown!(
                "The session's worker did not answer in time, or could not be reached. Run the \
                 checks again."
            ),
            Some(CapabilityChecksFailure::WorkerFailed) => shown!(
                "The session's worker answered with something this program cannot use. Run the \
                 checks again."
            ),
            None => shown!(
                "The latest run ended without a result, and the host gave no reason. Run the \
                 checks again."
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::scalars::Uuid;

    use super::*;

    /// Where a run stands, as the host says it.
    fn stands(
        state: CapabilityChecksState,
        started_at_ms: u64,
        session: u8,
        failure: Option<CapabilityChecksFailure>,
    ) -> CapabilityChecks {
        CapabilityChecks {
            state,
            started_at_ms: Nullable::some(TimestampMs::new(started_at_ms)),
            finished_at_ms: Nullable::null(),
            session_id: Nullable::some(SessionId::new(Uuid::from_bytes([session; 16]))),
            failure: Nullable(failure),
        }
    }

    /// An answer of a scripted host: where the checks stand, or silence, which is a daemon that
    /// keeps the connection open and says nothing.
    #[derive(Clone)]
    enum Answer {
        Stands(CapabilityChecks),
        Silent,
    }

    /// A host that answers the request and each read as it is told to, the reads one after the
    /// other and the last again from then on, each after `read_takes`.
    struct Script {
        begun: Answer,
        reads: Vec<Answer>,
        taken: usize,
        read_takes: Duration,
    }

    impl Script {
        fn new(begun: Answer, reads: Vec<Answer>) -> Self {
            Self {
                begun,
                reads,
                taken: 0,
                read_takes: Duration::ZERO,
            }
        }
    }

    impl Asked for Script {
        type Records = ();

        async fn begin(&mut self, _authorised_file: Option<String>) -> Result<CapabilityChecks> {
            match self.begun.clone() {
                Answer::Stands(checks) => Ok(checks),
                Answer::Silent => std::future::pending().await,
            }
        }

        async fn read(&mut self) -> Result<(CapabilityChecks, ())> {
            tokio::time::sleep(self.read_takes).await;
            let answer = self.reads[self.taken.min(self.reads.len() - 1)].clone();
            self.taken += 1;
            match answer {
                Answer::Stands(checks) => Ok((checks, ())),
                Answer::Silent => std::future::pending().await,
            }
        }
    }

    /// Follows a script from a command that began now, and says what it came to and how long the
    /// command took on the paused clock. A command that does not end by its deadline fails here.
    async fn run_script(mut script: Script) -> (Followed<()>, Duration) {
        run_naming(&mut script, None).await
    }

    /// Follows a script as [`run_script`] does, from a command that names `file`.
    async fn run_naming(script: &mut Script, file: Option<&str>) -> (Followed<()>, Duration) {
        let started = Instant::now();
        let followed = tokio::time::timeout(
            WAIT + Duration::from_secs(60),
            follow(script, file.map(str::to_owned), started + WAIT, || {}),
        )
        .await
        .expect("the command ended at its deadline")
        .expect("the scripted host does not fail");
        (followed, started.elapsed())
    }

    /// What a command that gave no findings said, and where it saw the run.
    fn unfinished_with(followed: Followed<()>) -> (Option<CapabilityChecks>, String) {
        match followed {
            Followed::Unfinished { checks, words, .. } => (checks, words.to_string()),
            Followed::Found { .. } => panic!("the command reported findings"),
        }
    }

    /// A host that holds its connection open and never answers the request does not hold the
    /// command: it ends at its deadline and says that the host did not answer.
    #[tokio::test(start_paused = true)]
    async fn a_host_that_never_answers_the_request_ends_the_command_at_its_deadline() {
        let (followed, _) = run_script(Script::new(Answer::Silent, vec![Answer::Silent])).await;
        let (seen, words) = unfinished_with(followed);
        assert!(seen.is_none(), "{seen:?}");
        assert!(
            words.contains("did not answer within five minutes"),
            "{words}"
        );
    }

    /// A host that answers the request and then never answers a read ends the command at its
    /// deadline too, with the run as it was last seen.
    #[tokio::test(start_paused = true)]
    async fn a_host_that_stops_answering_reads_ends_the_command_at_its_deadline() {
        let running = stands(CapabilityChecksState::Running, 10, 1, None);
        let (followed, _) = run_script(Script::new(
            Answer::Stands(running.clone()),
            vec![Answer::Silent],
        ))
        .await;
        let (seen, words) = unfinished_with(followed);
        assert_eq!(seen, Some(running));
        assert!(
            words.contains("did not answer within five minutes"),
            "{words}"
        );
    }

    /// A run that goes on past the deadline is not waited for past it, however long each read takes
    /// and wherever the deadline falls between two reads.
    #[tokio::test(start_paused = true)]
    async fn the_waits_between_reads_do_not_pass_the_deadline() {
        let running = stands(CapabilityChecksState::Running, 10, 1, None);
        let mut script = Script::new(
            Answer::Stands(running.clone()),
            vec![Answer::Stands(running)],
        );
        script.read_takes = Duration::from_millis(400);
        let (followed, took) = run_script(script).await;
        assert!(matches!(followed, Followed::Unfinished { .. }));
        assert!(took <= WAIT, "the command took {took:?}");
    }

    /// A run that is still going when the deadline passes, with the host answering in time, is
    /// reported as still going.
    #[tokio::test(start_paused = true)]
    async fn a_run_still_going_at_the_deadline_is_said_to_be_still_going() {
        let running = stands(CapabilityChecksState::Running, 10, 1, None);
        let (followed, _) = run_script(Script::new(
            Answer::Stands(running.clone()),
            vec![Answer::Stands(running)],
        ))
        .await;
        let (_, words) = unfinished_with(followed);
        assert!(
            words.contains("still running after five minutes"),
            "{words}"
        );
    }

    /// A run another caller began once this one had ended, or another session's worker took over,
    /// is not this command's run, whether it is going or has ended: the command says that its own
    /// was replaced, and shows no findings.
    #[tokio::test(start_paused = true)]
    async fn a_run_that_another_caller_replaced_between_two_reads_is_not_reported_as_this_ones() {
        let ours = stands(CapabilityChecksState::Running, 10, 1, None);
        for replacement in [
            stands(CapabilityChecksState::Current, 20, 1, None),
            stands(CapabilityChecksState::Running, 20, 1, None),
            stands(CapabilityChecksState::Current, 10, 2, None),
        ] {
            let (followed, _) = run_script(Script::new(
                Answer::Stands(ours.clone()),
                vec![
                    Answer::Stands(ours.clone()),
                    Answer::Stands(replacement.clone()),
                ],
            ))
            .await;
            let Followed::Unfinished {
                checks,
                records,
                words,
            } = followed
            else {
                panic!("the command reported the findings of {replacement:?} as its own");
            };
            assert_eq!(checks, Some(ours.clone()), "{replacement:?}");
            assert!(records.is_none(), "{replacement:?}");
            assert!(
                words
                    .to_string()
                    .contains("Another run of the checks replaced"),
                "{words}"
            );
        }
    }

    /// The control of the case above: the run this command started is reported when it ends.
    #[tokio::test(start_paused = true)]
    async fn the_run_this_command_started_is_reported_when_it_ends() {
        let running = stands(CapabilityChecksState::Running, 10, 1, None);
        let current = stands(CapabilityChecksState::Current, 10, 1, None);
        let (followed, _) = run_script(Script::new(
            Answer::Stands(running.clone()),
            vec![Answer::Stands(running), Answer::Stands(current.clone())],
        ))
        .await;
        let Followed::Found { checks, .. } = followed else {
            panic!("the run that ended was not reported");
        };
        assert_eq!(checks, current);
    }

    /// A run the host refused to begin ended in its first answer, and that failure is what the
    /// command reports: a run another caller begins after it is not this command's, and its
    /// records are not shown with this failure.
    #[tokio::test(start_paused = true)]
    async fn a_failure_in_the_first_answer_is_kept_over_a_run_another_caller_began_after() {
        let refused = CapabilityChecks {
            session_id: Nullable::null(),
            ..stands(
                CapabilityChecksState::Failed,
                10,
                1,
                Some(CapabilityChecksFailure::NoSession),
            )
        };
        let theirs = stands(CapabilityChecksState::Running, 20, 2, None);
        let (followed, _) = run_script(Script::new(
            Answer::Stands(refused.clone()),
            vec![Answer::Stands(theirs)],
        ))
        .await;
        let Followed::Unfinished {
            checks,
            records,
            words,
        } = followed
        else {
            panic!("the command reported findings");
        };
        assert_eq!(checks, Some(refused.clone()));
        assert!(records.is_none());
        assert!(
            words
                .to_string()
                .contains("No session of the kind this host creates"),
            "{words}"
        );

        // With nothing in its way, the same failure comes with the records the host holds.
        let (followed, _) = run_script(Script::new(
            Answer::Stands(refused.clone()),
            vec![Answer::Stands(refused)],
        ))
        .await;
        let Followed::Unfinished { records, words, .. } = followed else {
            panic!("the command reported findings");
        };
        assert!(records.is_some());
        assert!(
            words
                .to_string()
                .contains("No session of the kind this host creates"),
            "{words}"
        );
    }

    /// A file named for a run the host was already performing was not read, and the command says
    /// that instead of reporting that run's findings, and asks nothing more of the host. Without a
    /// file, a run already going is followed, and so is a run this command began, with or without
    /// one.
    #[tokio::test(start_paused = true)]
    async fn a_file_named_for_a_run_that_was_already_going_is_not_reported_as_read() {
        let going = stands(CapabilityChecksState::Running, 1, 1, None);
        let current = stands(CapabilityChecksState::Current, 1, 1, None);
        let mut script = Script::new(
            Answer::Stands(going.clone()),
            vec![Answer::Stands(current.clone())],
        );
        let (followed, _) = run_naming(&mut script, Some("notes.txt")).await;
        let Followed::Unfinished {
            checks,
            records,
            words,
        } = followed
        else {
            panic!("the findings of a run that did not read the file were reported");
        };
        assert_eq!(checks, Some(going.clone()));
        assert!(records.is_none());
        assert!(
            words
                .to_string()
                .contains("already going, so the file you named was not read"),
            "{words}"
        );
        assert_eq!(script.taken, 0, "the command read the host again");

        // No file named: nothing is lost, and the run going is followed to its end.
        let mut script = Script::new(
            Answer::Stands(going.clone()),
            vec![Answer::Stands(current.clone())],
        );
        let (followed, _) = run_naming(&mut script, None).await;
        assert!(matches!(followed, Followed::Found { .. }));

        // A run this command began, which the host dates after the request, is its own.
        let ours = stands(CapabilityChecksState::Running, u64::MAX, 1, None);
        let done = stands(CapabilityChecksState::Current, u64::MAX, 1, None);
        let mut script = Script::new(Answer::Stands(ours), vec![Answer::Stands(done)]);
        let (followed, _) = run_naming(&mut script, Some("notes.txt")).await;
        assert!(matches!(followed, Followed::Found { .. }));
    }
}
