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
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;

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
/// `announce` is called once the host has started a run.
async fn follow<A: Asked>(
    asked: &mut A,
    authorised_file: Option<String>,
    deadline: Instant,
    announce: impl FnOnce(),
) -> Result<Followed<A::Records>> {
    let Some(begun) = within(deadline, asked.begin(authorised_file))
        .await
        .transpose()?
    else {
        return Ok(unanswered(None));
    };
    if begun.state == CapabilityChecksState::Running {
        announce();
    }
    let mut seen = begun;
    loop {
        let Some((checks, records)) = within(deadline, asked.read()).await.transpose()? else {
            return Ok(unanswered(Some(seen)));
        };
        if checks.state != CapabilityChecksState::Running || Instant::now() >= deadline {
            return Ok(ended(checks, records));
        }
        seen = checks;
        tokio::time::sleep_until(deadline.min(Instant::now() + POLL)).await;
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
    use kr_protocol::ids::SessionId;
    use kr_protocol::scalars::{TimestampMs, Uuid};

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
    async fn followed(mut script: Script) -> (Followed<()>, Duration) {
        let started = Instant::now();
        let followed = tokio::time::timeout(
            WAIT + Duration::from_secs(60),
            follow(&mut script, None, started + WAIT, || {}),
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
        let (followed, _) = followed(Script::new(Answer::Silent, vec![Answer::Silent])).await;
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
        let (followed, _) = followed(Script::new(
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
        let (followed, took) = followed(script).await;
        assert!(matches!(followed, Followed::Unfinished { .. }));
        assert!(took <= WAIT, "the command took {took:?}");
    }

    /// A run that is still going when the deadline passes, with the host answering in time, is
    /// reported as still going.
    #[tokio::test(start_paused = true)]
    async fn a_run_still_going_at_the_deadline_is_said_to_be_still_going() {
        let running = stands(CapabilityChecksState::Running, 10, 1, None);
        let (followed, _) = followed(Script::new(
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
}
