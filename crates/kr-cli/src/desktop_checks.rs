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
    EnvironmentCapabilitiesResult, capabilities,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::export::{ContentClass, Sentence, withheld};
use kr_protocol::ids::SessionId;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, TimestampMs};

use crate::cli::DesktopChecksArguments;
use crate::daemon::Daemon;
use crate::error::{CliError, Result};
use crate::output::{self, Document, closed};
use crate::report::{self, Completion};
use crate::stdout_line;

/// How long the command waits on the host in all, from its start: every call it makes to the
/// control daemon and every wait between them ends by then. The guard's probes and the connection's
/// hello have bounds of their own, inside it. The setup page says a run takes about two minutes,
/// most of it a person answering a platform's question.
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

    /// Whether what the host holds shows that the read check read the file at `path`, the path as
    /// the request carried it.
    fn shows_the_read_of(records: &Self::Records, path: &str) -> bool;
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

    fn shows_the_read_of(report: &DesktopCapabilityReport, path: &str) -> bool {
        report
            .record(capabilities::AUTHORISED_FILE_READ)
            .and_then(|record| record.disabled_reason.as_ref())
            .is_some_and(|reason| shows_a_read_of(reason, path))
    }
}

/// Whether the words of the read check's record say that it read `path`.
///
/// The record holds no path: the worker composes the read check's words with the path as its class
/// and its length in bytes, `[path withheld, N bytes]` ([`Sentence::path`]), whatever the check
/// found. The request carries `path` as text and the worker takes it from the daemon unchanged, so
/// the words hold what [`withheld`] renders for that same text where the check read this path, and
/// they hold nothing like it where it read none or another path of another length. A path of the
/// same length cannot be told from this one: that is the one case in which another caller's run, begun at the
/// same moment as this command's, is taken for its own.
fn shows_a_read_of(reason: &Sentence, path: &str) -> bool {
    reason
        .as_str()
        .contains(&withheld(ContentClass::Path, path))
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
/// The deadline bounds every call the command makes: the read before the request, the request, each
/// read, and the wait between reads. No call starts at the deadline or after it, so a command that
/// begins past it, or whose answer to one call comes at it, asks the host nothing more. A run still
/// going when it passes is reported as still going, with what the last read found; a daemon that
/// holds its connection open and never answers ends the command at the deadline with nothing to
/// show but the words that say so.
///
/// The run is the one the host named in its first answer ([`Run`]), and the command reports no
/// other: a read that finds another run, which a second caller began once this one ended, ends the
/// command with the words that say so, and the findings of that run are not shown as this one's.
/// Where the first answer already says the run ended, that answer is the command's own, and a later
/// read only supplies the records if they are still that run's: a read that fails or does not
/// answer leaves that answer as the verdict, with no records.
///
/// The answer to the request does not say whether the request began the run it names, and no clock
/// can: another caller's request may be admitted between the command's clock reading and its own.
/// So where a file is named, the command reads the host once before the request. The same run
/// before and in the answer, going at both, was going already, and the file named was not read. A
/// run that had ended when the host was read before the request is not taken for one going
/// already, whatever start and session it bears. Any other run in the answer is taken for the one this request began, and the
/// findings are reported as a read of the file named only where the read check's record shows a path
/// of the length of that file's: a record that shows another length, or none, may be another
/// caller's run, begun at the same moment, and the command says it is not known whether the file
/// was read. A run of another caller with a file whose path has the same length cannot be told from
/// this command's own.
///
/// A run is told by its start, in milliseconds of the daemon's wall clock, and its session, and the
/// daemon checks no uniqueness. So a limit remains: a run that was going when the host was read
/// before the request and ended before it, and a run that this request begins in the same session in
/// the same millisecond, which a clock set back can repeat, are taken for one run going already.
/// The reads that follow the run tell it by the same pair, so there too a run of another caller in
/// the same session and the same millisecond is taken for this command's own.
///
/// `announce` is called once the host has started a run.
async fn follow<A: Asked>(
    asked: &mut A,
    authorised_file: Option<String>,
    deadline: Instant,
    announce: impl FnOnce(),
) -> Result<Followed<A::Records>> {
    let going_before = if authorised_file.is_some() {
        match within(deadline, asked.read()).await.transpose()? {
            // Only a run that was going can be the one the request finds going: a run that had
            // ended before, whatever start and session it bears, is not.
            Some((checks, _)) => {
                (checks.state == CapabilityChecksState::Running).then(|| Run::of(&checks))
            }
            None => return Ok(unanswered(None)),
        }
    } else {
        None
    };
    let named = authorised_file.clone();
    let Some(begun) = within(deadline, asked.begin(authorised_file))
        .await
        .transpose()?
    else {
        return Ok(unanswered(None));
    };
    // A run that was going when the host was read before the request and is going in its answer was
    // going already, and the host does not start a run it is already performing: it answers with
    // that run and the file this command named is lost.
    if begun.state == CapabilityChecksState::Running && going_before == Some(Run::of(&begun)) {
        return Ok(Followed::Unfinished {
            checks: Some(begun),
            records: None,
            words: shown!(
                "A run of the checks was already going, so the file you named was not read. Run \
                 the command again once it ends."
            ),
        });
    }
    // Whether what the host holds is no reason to doubt that the run read the file named: no file
    // named, or a read check whose record shows that file's path.
    let read = |records: &A::Records| {
        named
            .as_deref()
            .is_none_or(|path| A::shows_the_read_of(records, path))
    };
    let accepted = Run::of(&begun);
    let running = begun.state == CapabilityChecksState::Running;
    if running {
        announce();
    }
    let mut seen = begun;
    // What the host held when the last read of a run that was still going answered.
    let mut held: Option<A::Records> = None;
    // The longest the host has taken to answer one read, which the read the deadline cuts off is
    // measured against, and no less than one wait between reads.
    let mut slowest = POLL;
    loop {
        let asked_at = Instant::now();
        let (checks, records) = match within(deadline, asked.read()).await {
            Some(Ok(answer)) => {
                slowest = slowest.max(asked_at.elapsed());
                answer
            }
            // The first answer already gave the verdict, and a read that only brings the records
            // that go with it does not take it back by failing or by not answering.
            _ if !running => return Ok(kept(seen, None, true)),
            Some(Err(error)) => return Err(error),
            // A read that the deadline cut off after no longer than the host took to answer one
            // before is the deadline's doing, and the run was still going when the host last
            // answered. One that had been out longer is a host that stopped answering.
            None => {
                return Ok(if deadline.saturating_duration_since(asked_at) <= slowest {
                    out_of_time(seen, held)
                } else {
                    unanswered(Some(seen))
                });
            }
        };
        let ours = Run::of(&checks) == accepted;
        if !running {
            let records = ours.then_some(records);
            let shown = records.as_ref().is_none_or(read);
            return Ok(kept(seen, records, shown));
        }
        if !ours {
            return Ok(replaced(seen));
        }
        if checks.state != CapabilityChecksState::Running {
            let shown = read(&records);
            return Ok(ended(checks, records, shown));
        }
        seen = checks;
        held = Some(records);
        tokio::time::sleep_until(deadline.min(Instant::now() + POLL)).await;
    }
}

/// What the command comes to where its deadline passed while the run it follows was going: the run
/// as the host last said it, with what the host held then, where a read answered since the request.
/// A run that has not ended has no findings to be read as anyone's.
fn out_of_time<R>(seen: CapabilityChecks, held: Option<R>) -> Followed<R> {
    Followed::Unfinished {
        words: unfinished(&seen).unwrap_or_else(unanswered_words),
        checks: Some(seen),
        records: held,
    }
}

/// A run of the checks as the host names it: when it began and the session whose worker performs
/// it. Another run has another pair unless the daemon's clock gives two runs of one session the same
/// start, so a command that reads the host again can tell, within the limit stated at `follow`,
/// that the run it asked for is no longer the one the host holds.
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

/// The outcome of a call, or `None` where `deadline` had passed before the call started or passes
/// before the host answers it.
///
/// A call that starts at the deadline or after it could not be answered in time, and the clock is
/// read first because `timeout_at` polls the call before it looks at the deadline.
async fn within<T>(deadline: Instant, call: impl Future<Output = T>) -> Option<T> {
    if Instant::now() >= deadline {
        return None;
    }
    tokio::time::timeout_at(deadline, call).await.ok()
}

/// What a run that has stopped, or has gone on to the deadline, comes to. `read` is whether the
/// records give no reason to doubt that it read the file the command named, where it named one.
fn ended<R>(checks: CapabilityChecks, records: R, read: bool) -> Followed<R> {
    match unfinished(&checks) {
        None if read => Followed::Found { checks, records },
        None => Followed::Unfinished {
            checks: Some(checks),
            records: Some(records),
            words: not_known_words(),
        },
        Some(words) => Followed::Unfinished {
            checks: Some(checks),
            records: Some(records),
            words,
        },
    }
}

/// What a run comes to that the host's first answer already ended: that answer says how, and the
/// records come with it where a later read found them still that run's. `read` is as for [`ended`].
fn kept<R>(first: CapabilityChecks, records: Option<R>, read: bool) -> Followed<R> {
    match (unfinished(&first), records) {
        (None, Some(records)) if read => Followed::Found {
            checks: first,
            records,
        },
        (None, Some(records)) => Followed::Unfinished {
            words: not_known_words(),
            checks: Some(first),
            records: Some(records),
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

/// What a person is told where the run that ended may be another caller's, begun at the same
/// moment as this command's, and its records do not show the file that was named.
fn not_known_words() -> Shown {
    shown!(
        "Another run of the checks may have started at the same moment, and it is not known \
         whether the file you named was read. Run the command again."
    )
}

/// What the command comes to where the host did not answer a call in time.
fn unanswered<R>(seen: Option<CapabilityChecks>) -> Followed<R> {
    Followed::Unfinished {
        checks: seen,
        records: None,
        words: unanswered_words(),
    }
}

/// What a person is told where the host did not answer a call in time.
fn unanswered_words() -> Shown {
    shown!(
        "The host did not answer within five minutes, so it is not known where the checks \
         stand. Run kr doctor to see what the host holds once it answers."
    )
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
        Fails,
    }

    /// What a host that cut the connection gives.
    fn connection_cut() -> CliError {
        CliError::Other(shown!("the connection to the host was cut"))
    }

    /// A host that answers the request and each read as it is told to, the reads one after the
    /// other and the last again from then on, each after `read_takes`.
    struct Script {
        begun: Answer,
        reads: Vec<Answer>,
        taken: usize,
        read_takes: Duration,
        /// When each read was asked, on the paused clock.
        asked_at: Vec<Instant>,
        /// How many times the request was made.
        begins: usize,
        /// How long the request takes to be answered.
        begin_takes: Duration,
        /// The length of the path the read check's record shows, where it shows one.
        path_bytes: Option<usize>,
    }

    impl Script {
        fn new(begun: Answer, reads: Vec<Answer>) -> Self {
            Self {
                begun,
                reads,
                taken: 0,
                read_takes: Duration::ZERO,
                asked_at: Vec::new(),
                begins: 0,
                begin_takes: Duration::ZERO,
                path_bytes: None,
            }
        }
    }

    impl Asked for Script {
        type Records = Option<usize>;

        async fn begin(&mut self, _authorised_file: Option<String>) -> Result<CapabilityChecks> {
            self.begins += 1;
            tokio::time::sleep(self.begin_takes).await;
            match self.begun.clone() {
                Answer::Stands(checks) => Ok(checks),
                Answer::Silent => std::future::pending().await,
                Answer::Fails => Err(connection_cut()),
            }
        }

        async fn read(&mut self) -> Result<(CapabilityChecks, Option<usize>)> {
            self.asked_at.push(Instant::now());
            tokio::time::sleep(self.read_takes).await;
            let answer = self.reads[self.taken.min(self.reads.len() - 1)].clone();
            self.taken += 1;
            match answer {
                Answer::Stands(checks) => Ok((checks, self.path_bytes)),
                Answer::Silent => std::future::pending().await,
                Answer::Fails => Err(connection_cut()),
            }
        }

        fn shows_the_read_of(records: &Option<usize>, path: &str) -> bool {
            *records == Some(path.len())
        }
    }

    /// Follows a script from a command that began now, and says what it came to and how long the
    /// command took on the paused clock. A command that does not end by its deadline fails here.
    async fn run_script(mut script: Script) -> (Followed<Option<usize>>, Duration) {
        run_naming(&mut script, None).await
    }

    /// Follows a script as [`run_script`] does, from a command that names `file`.
    async fn run_naming(
        script: &mut Script,
        file: Option<&str>,
    ) -> (Followed<Option<usize>>, Duration) {
        let (followed, took) = try_naming(script, file).await;
        (followed.expect("the scripted host does not fail"), took)
    }

    /// Follows a script as [`run_naming`] does, and gives the command's failure where it has one.
    async fn try_naming(
        script: &mut Script,
        file: Option<&str>,
    ) -> (Result<Followed<Option<usize>>>, Duration) {
        let started = Instant::now();
        let followed = tokio::time::timeout(
            WAIT + Duration::from_secs(60),
            follow(script, file.map(str::to_owned), started + WAIT, || {}),
        )
        .await
        .expect("the command ended at its deadline");
        (followed, started.elapsed())
    }

    /// What a command that gave no findings said, and where it saw the run.
    fn unfinished_with(followed: Followed<Option<usize>>) -> (Option<CapabilityChecks>, String) {
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
    /// and wherever the deadline falls between two reads, and a host that answered every read in
    /// time is told to be still running, not to have stopped answering.
    #[tokio::test(start_paused = true)]
    async fn the_waits_between_reads_do_not_pass_the_deadline() {
        let running = stands(CapabilityChecksState::Running, 10, 1, None);
        let mut script = Script::new(
            Answer::Stands(running.clone()),
            vec![Answer::Stands(running)],
        );
        script.read_takes = Duration::from_millis(400);
        let (followed, took) = run_naming(&mut script, None).await;
        assert!(took <= WAIT, "the command took {took:?}");
        let (_, words) = unfinished_with(followed);
        assert!(
            words.contains("still running after five minutes"),
            "{words}"
        );
    }

    /// A run that is still going when the deadline passes, with the host answering each read at
    /// once, is reported as still going, with what the last read found.
    #[tokio::test(start_paused = true)]
    async fn a_run_still_going_at_the_deadline_is_said_to_be_still_going() {
        let running = stands(CapabilityChecksState::Running, 10, 1, None);
        let mut script = Script::new(
            Answer::Stands(running.clone()),
            vec![Answer::Stands(running.clone())],
        );
        script.read_takes = Duration::from_millis(1);
        let (followed, _) = run_naming(&mut script, None).await;
        let Followed::Unfinished {
            checks,
            records,
            words,
        } = followed
        else {
            panic!("the command reported findings of a run that had not ended");
        };
        assert_eq!(checks, Some(running));
        assert!(records.is_some(), "the last read's records were dropped");
        assert!(
            words
                .to_string()
                .contains("still running after five minutes"),
            "{words}"
        );
    }

    /// No read starts at the deadline or after it: a read that starts there cannot be answered in
    /// time, and the command would say that the host did not answer.
    #[tokio::test(start_paused = true)]
    async fn no_read_starts_at_the_deadline_or_after_it() {
        let origin = Instant::now();
        let running = stands(CapabilityChecksState::Running, 10, 1, None);
        let mut script = Script::new(
            Answer::Stands(running.clone()),
            vec![Answer::Stands(running)],
        );
        script.read_takes = Duration::from_millis(1);
        run_naming(&mut script, None).await;
        let last = script.asked_at.last().expect("the command read the host");
        assert!(
            *last < origin + WAIT,
            "a read started {:?} after the command began",
            *last - origin
        );
    }

    /// Follows a script as [`try_naming`] does, from a command whose deadline is `deadline`.
    async fn follow_until(
        script: &mut Script,
        file: Option<&str>,
        deadline: Instant,
    ) -> Followed<Option<usize>> {
        tokio::time::timeout(
            WAIT + Duration::from_secs(60),
            follow(script, file.map(str::to_owned), deadline, || {}),
        )
        .await
        .expect("the command ended")
        .expect("the scripted host does not fail")
    }

    /// A command that begins past its deadline asks the host nothing, whether it names a file, which
    /// it reads the host before the request for, or not: a call that starts there cannot be answered
    /// in time, and the host that answers it at once would be taken for one that answered in time.
    #[tokio::test(start_paused = true)]
    async fn a_command_that_begins_past_its_deadline_asks_the_host_nothing() {
        for file in [None, Some(NOTES)] {
            let running = stands(CapabilityChecksState::Running, 10, 1, None);
            let mut script = Script::new(
                Answer::Stands(running.clone()),
                vec![Answer::Stands(running)],
            );
            let deadline = Instant::now();
            tokio::time::advance(Duration::from_millis(1)).await;
            let followed = follow_until(&mut script, file, deadline).await;
            assert!(
                script.asked_at.is_empty(),
                "the host was read past the deadline (file {file:?})"
            );
            assert_eq!(
                script.begins, 0,
                "the request was made past the deadline (file {file:?})"
            );
            let (seen, words) = unfinished_with(followed);
            assert_eq!(seen, None);
            assert!(
                words.contains("did not answer within five minutes"),
                "{words}"
            );
        }
    }

    /// The read before the request that answers at the deadline is not followed by the request: the
    /// deadline bounds the request as it bounds each read.
    #[tokio::test(start_paused = true)]
    async fn a_read_before_the_request_that_answers_at_the_deadline_is_not_followed_by_the_request()
    {
        let current = stands(CapabilityChecksState::Current, 10, 1, None);
        let mut script = Script::new(
            Answer::Stands(current.clone()),
            vec![Answer::Stands(current)],
        );
        script.read_takes = WAIT;
        let (followed, took) = run_naming(&mut script, Some(NOTES)).await;
        assert_eq!(
            script.taken, 1,
            "the host was read once, before the request"
        );
        assert_eq!(script.begins, 0, "the request was made at the deadline");
        assert!(took <= WAIT, "the command took {took:?}");
        let (seen, words) = unfinished_with(followed);
        assert_eq!(seen, None);
        assert!(
            words.contains("did not answer within five minutes"),
            "{words}"
        );
    }

    /// A read that the deadline cut off after no longer than the host took to answer a read before
    /// is the deadline's doing, however long that is, and not a host that stopped answering: the run
    /// was going when the host last answered, and is said to be still going.
    #[tokio::test(start_paused = true)]
    async fn a_slow_read_that_the_deadline_cut_off_does_not_make_a_host_that_stopped_answering() {
        let running = stands(CapabilityChecksState::Running, 10, 1, None);
        let mut script = Script::new(
            Answer::Stands(running.clone()),
            vec![Answer::Stands(running.clone())],
        );
        // The last read starts 298.8 s in and is cut off after 1.2 s, which is more than POLL and
        // less than the 1.3 s that the reads before it took.
        script.read_takes = Duration::from_millis(1300);
        let (followed, _) = run_naming(&mut script, None).await;
        let Followed::Unfinished {
            checks,
            records,
            words,
        } = followed
        else {
            panic!("the command reported findings of a run that had not ended");
        };
        assert_eq!(checks, Some(running));
        assert!(
            records.is_some(),
            "the last answered read's records were dropped"
        );
        assert!(
            words
                .to_string()
                .contains("still running after five minutes"),
            "{words}"
        );
    }

    /// A request that the host answers with the run going just before the deadline is said to be
    /// still going where no read can answer before the deadline: the host did answer, and the run was
    /// going when it did.
    #[tokio::test(start_paused = true)]
    async fn a_run_going_in_the_answer_to_the_request_just_before_the_deadline_is_said_to_be_still_going()
     {
        let running = stands(CapabilityChecksState::Running, 10, 1, None);
        let mut script = Script::new(Answer::Stands(running.clone()), vec![Answer::Silent]);
        script.begin_takes = WAIT - Duration::from_millis(100);
        let (followed, _) = run_naming(&mut script, None).await;
        let Followed::Unfinished {
            checks,
            records,
            words,
        } = followed
        else {
            panic!("the command reported findings of a run that had not ended");
        };
        assert_eq!(checks, Some(running));
        assert!(records.is_none());
        assert!(
            words
                .to_string()
                .contains("still running after five minutes"),
            "{words}"
        );
    }

    /// A host that answered some reads and then stops answering is not told to be still going: the
    /// command says that the host did not answer, as it does of a host that never answered a read.
    #[tokio::test(start_paused = true)]
    async fn a_host_that_answered_some_reads_and_then_stopped_is_said_not_to_answer() {
        let running = stands(CapabilityChecksState::Running, 10, 1, None);
        let (followed, _) = run_script(Script::new(
            Answer::Stands(running.clone()),
            vec![
                Answer::Stands(running.clone()),
                Answer::Stands(running.clone()),
                Answer::Silent,
            ],
        ))
        .await;
        let (seen, words) = unfinished_with(followed);
        assert_eq!(seen, Some(running));
        assert!(
            words.contains("did not answer within five minutes"),
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

    /// A run the host refused to begin ended in its first answer, and that failure is the
    /// command's report whatever becomes of the read that only brings the records: the person is
    /// told why no checks ran, not that the connection was cut or that the host did not answer.
    async fn the_first_failure_is_the_report_where_the_read_after_it(read: Answer) {
        let refused = CapabilityChecks {
            session_id: Nullable::null(),
            ..stands(
                CapabilityChecksState::Failed,
                10,
                1,
                Some(CapabilityChecksFailure::NoSession),
            )
        };
        let mut script = Script::new(Answer::Stands(refused.clone()), vec![read]);
        let (followed, _) = try_naming(&mut script, None).await;
        let followed = followed.unwrap_or_else(|error| {
            panic!("the failure of a read replaced the verdict of the first answer: {error:?}")
        });
        let Followed::Unfinished {
            checks,
            records,
            words,
        } = followed
        else {
            panic!("the command reported findings");
        };
        assert_eq!(checks, Some(refused));
        assert!(records.is_none());
        assert!(
            words
                .to_string()
                .contains("No session of the kind this host creates"),
            "{words}"
        );
    }

    /// A read that fails after the first answer ended the run does not replace its verdict.
    #[tokio::test(start_paused = true)]
    async fn a_first_failure_is_kept_when_the_read_after_it_fails() {
        the_first_failure_is_the_report_where_the_read_after_it(Answer::Fails).await;
    }

    /// A read that never answers after the first answer ended the run does not replace its
    /// verdict either, and the command does not say that the host did not answer.
    #[tokio::test(start_paused = true)]
    async fn a_first_failure_is_kept_when_the_read_after_it_never_answers() {
        the_first_failure_is_the_report_where_the_read_after_it(Answer::Silent).await;
    }

    /// A read that fails while the run is still going is the command's failure: nothing says how
    /// the run ended.
    #[tokio::test(start_paused = true)]
    async fn a_read_that_fails_while_the_run_goes_on_fails_the_command() {
        let running = stands(CapabilityChecksState::Running, 10, 1, None);
        let mut script = Script::new(Answer::Stands(running), vec![Answer::Fails]);
        let started = Instant::now();
        let failed = follow(&mut script, None, started + WAIT, || {}).await;
        assert!(
            matches!(failed, Err(CliError::Other(_))),
            "the connection's failure was not the command's"
        );
    }

    /// The file the cases name.
    const NOTES: &str = "notes.txt";

    /// Where the checks stood before any run.
    fn nothing_yet() -> CapabilityChecks {
        CapabilityChecks {
            state: CapabilityChecksState::NotRun,
            started_at_ms: Nullable::null(),
            finished_at_ms: Nullable::null(),
            session_id: Nullable::null(),
            failure: Nullable::null(),
        }
    }

    /// A file named for a run that the host held before the request, and holds in its answer, was
    /// not read, and the command says that and asks nothing more of the host: the request began no
    /// run. No clock tells it, so whatever date the run bears, it is the same run.
    #[tokio::test(start_paused = true)]
    async fn a_file_named_for_a_run_that_was_already_going_is_not_reported_as_read() {
        for started in [1, u64::MAX] {
            let going = stands(CapabilityChecksState::Running, started, 1, None);
            let current = stands(CapabilityChecksState::Current, started, 1, None);
            let mut script = Script::new(
                Answer::Stands(going.clone()),
                vec![Answer::Stands(going.clone()), Answer::Stands(current)],
            );
            script.path_bytes = Some(NOTES.len());
            let (followed, _) = run_naming(&mut script, Some(NOTES)).await;
            let Followed::Unfinished {
                checks,
                records,
                words,
            } = followed
            else {
                panic!("the findings of a run that did not read the file were reported");
            };
            assert_eq!(checks, Some(going), "a run dated {started}");
            assert!(records.is_none());
            assert!(
                words
                    .to_string()
                    .contains("already going, so the file you named was not read"),
                "{words}"
            );
            assert_eq!(
                script.taken, 1,
                "the command reads the host once, before its request, and not after it"
            );
        }
    }

    /// A run that had ended before the request is not one going already, whatever start and session
    /// it bears: where the run this request begins has the start and session of the one that ended,
    /// which the daemon's wall clock can give it, the command follows it as its own and reports the
    /// file as read.
    #[tokio::test(start_paused = true)]
    async fn a_run_that_had_ended_before_the_request_is_not_taken_for_one_going_already() {
        for ended in [
            stands(CapabilityChecksState::Current, 10, 1, None),
            stands(
                CapabilityChecksState::Failed,
                10,
                1,
                Some(CapabilityChecksFailure::WorkerRefused),
            ),
            stands(CapabilityChecksState::Stale, 10, 1, None),
        ] {
            let ours = stands(CapabilityChecksState::Running, 10, 1, None);
            let done = stands(CapabilityChecksState::Current, 10, 1, None);
            let mut script = Script::new(
                Answer::Stands(ours.clone()),
                vec![
                    Answer::Stands(ended.clone()),
                    Answer::Stands(ours),
                    Answer::Stands(done.clone()),
                ],
            );
            script.path_bytes = Some(NOTES.len());
            let (followed, _) = run_naming(&mut script, Some(NOTES)).await;
            let Followed::Found { checks, .. } = followed else {
                panic!("the run this request began was not followed (run before: {ended:?})");
            };
            assert_eq!(checks, done);
        }
    }

    /// With no file named nothing is lost: a run already going is followed to its end, and so is
    /// a run this command began.
    #[tokio::test(start_paused = true)]
    async fn without_a_file_a_run_already_going_is_followed_to_its_end() {
        let going = stands(CapabilityChecksState::Running, 1, 1, None);
        let current = stands(CapabilityChecksState::Current, 1, 1, None);
        let mut script = Script::new(
            Answer::Stands(going.clone()),
            vec![Answer::Stands(current.clone())],
        );
        let (followed, _) = run_naming(&mut script, None).await;
        let Followed::Found { checks, .. } = followed else {
            panic!("the run that ended was not reported");
        };
        assert_eq!(checks, current);
    }

    /// A run in the answer that is not the one the host held before the request, or a run where it
    /// held none, is the one this request began, and the read check's record says which file it
    /// read: where that is the file named, the command reports the findings, whatever date the run
    /// bears, since the command reads no clock.
    #[tokio::test(start_paused = true)]
    async fn a_run_that_the_request_began_is_reported_as_having_read_the_file_named() {
        for before in [
            nothing_yet(),
            stands(CapabilityChecksState::Current, 5, 1, None),
            stands(CapabilityChecksState::Running, 5, 1, None),
        ] {
            for started in [1, u64::MAX] {
                let ours = stands(CapabilityChecksState::Running, started, 2, None);
                let done = stands(CapabilityChecksState::Current, started, 2, None);
                let mut script = Script::new(
                    Answer::Stands(ours.clone()),
                    vec![
                        Answer::Stands(before.clone()),
                        Answer::Stands(ours),
                        Answer::Stands(done.clone()),
                    ],
                );
                script.path_bytes = Some(NOTES.len());
                let (followed, _) = run_naming(&mut script, Some(NOTES)).await;
                let Followed::Found { checks, .. } = followed else {
                    panic!(
                        "the findings were not reported (held before: {before:?}, run dated {started})"
                    );
                };
                assert_eq!(checks, done);
            }
        }
    }

    /// A run that ends with no record that it read the file named, or with one that read a file whose
    /// path has another length, may be another caller's, begun at the same moment: the command
    /// does not report it as having read the file, and says that it is not known.
    #[tokio::test(start_paused = true)]
    async fn a_run_whose_records_do_not_show_the_file_named_is_not_reported_as_having_read_it() {
        for shown in [Some(NOTES.len() + 1), Some(NOTES.len() - 1), Some(0), None] {
            let ours = stands(CapabilityChecksState::Running, 20, 2, None);
            let done = stands(CapabilityChecksState::Current, 20, 2, None);
            let mut script = Script::new(
                Answer::Stands(ours.clone()),
                vec![
                    Answer::Stands(nothing_yet()),
                    Answer::Stands(ours),
                    Answer::Stands(done.clone()),
                ],
            );
            script.path_bytes = shown;
            let (followed, _) = run_naming(&mut script, Some(NOTES)).await;
            let Followed::Unfinished {
                checks,
                records,
                words,
            } = followed
            else {
                panic!(
                    "the findings were reported as a read of the file named (records show {shown:?})"
                );
            };
            assert_eq!(checks, Some(done), "{shown:?}");
            assert!(records.is_some(), "{shown:?}");
            assert!(
                words.to_string().contains(
                    "may have started at the same moment, and it is not known whether the file \
                     you named was read"
                ),
                "{words}"
            );
        }
    }

    /// A run that does not end with findings says how it ended, whatever file was named: the
    /// words of a run that failed are not the words of a run that may not be this command's.
    #[tokio::test(start_paused = true)]
    async fn a_run_that_failed_says_how_it_failed_where_a_file_was_named() {
        let ours = stands(CapabilityChecksState::Running, 20, 2, None);
        let failed = stands(
            CapabilityChecksState::Failed,
            20,
            2,
            Some(CapabilityChecksFailure::WorkerUnreachable),
        );
        let mut script = Script::new(
            Answer::Stands(ours.clone()),
            vec![
                Answer::Stands(nothing_yet()),
                Answer::Stands(ours),
                Answer::Stands(failed.clone()),
            ],
        );
        let (followed, _) = run_naming(&mut script, Some(NOTES)).await;
        let (seen, words) = unfinished_with(followed);
        assert_eq!(seen, Some(failed));
        assert!(words.contains("did not answer in time"), "{words}");
    }

    /// A host that does not answer the read before the request is not asked to begin a run, and the
    /// command says that the host did not answer; one whose read fails ends the command with that
    /// failure, before it asks.
    #[tokio::test(start_paused = true)]
    async fn the_request_is_not_made_where_the_read_before_it_gets_no_answer() {
        let running = stands(CapabilityChecksState::Running, 10, 1, None);
        let mut script = Script::new(Answer::Stands(running.clone()), vec![Answer::Silent]);
        let (followed, _) = run_naming(&mut script, Some(NOTES)).await;
        let (seen, words) = unfinished_with(followed);
        assert!(seen.is_none(), "{seen:?}");
        assert!(
            words.contains("did not answer within five minutes"),
            "{words}"
        );
        assert_eq!(script.begins, 0, "a run was asked for");

        let mut script = Script::new(Answer::Stands(running), vec![Answer::Fails]);
        let (followed, _) = try_naming(&mut script, Some(NOTES)).await;
        assert!(followed.is_err(), "the failed read did not end the command");
        assert_eq!(script.begins, 0, "a run was asked for");
    }

    /// The read check's words show a path by its class and its length in bytes, and the command
    /// takes the length from the same text it sends: a path whose characters take more than a byte
    /// each is shown at its length in bytes, and a sentence that holds no path, or a path of another
    /// length, does not show it.
    #[test]
    fn the_words_of_the_read_check_show_the_path_the_request_carried() {
        let said = |path: &str| {
            Sentence::new()
                .stated("it read ")
                .number(23)
                .stated(" bytes of ")
                .path(Path::new(path))
        };
        let accented = "/Users/someone/Documents/caf\u{e9} \u{1f4c4}.txt";
        assert!(accented.len() > accented.chars().count());
        assert!(shows_a_read_of(&said(accented), accented));
        assert!(!shows_a_read_of(
            &said(accented),
            "/Users/someone/Documents/cafe.txt"
        ));
        assert!(!shows_a_read_of(
            &Sentence::new().stated("no file was nominated for this check"),
            accented
        ));
        // The limit that cannot be removed without the host naming the path: another caller's file
        // whose path is as long is shown alike.
        assert!(shows_a_read_of(&said("/a/b/c.txt"), "/a/b/d.txt"));
    }
}
