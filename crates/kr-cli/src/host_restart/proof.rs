//! The proof that the daemon which answers after a restart's start is the one the command started,
//! and what the command does where the exchange that proves it is cut.
//!
//! The proof reads the daemon's generation and its process on the one connection that answered. An
//! exchange that does not complete leaves no proof, and that is not yet a failure: the daemon that
//! the connection reached may have been stopped by another command, as this one stopped the daemon
//! before it, and a daemon of that command's start comes up next. The command then starts nothing
//! more. It waits, within the start's bound counted from the cut, for a daemon to give a whole
//! exchange, and judges what answers by that one exchange on its connection.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kr_client::shown;
use kr_client::shown::{Said, Shown};
use kr_ipc::client::LocalClient;
use kr_ipc::paths::HostPaths;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ControllerGeneration;

use super::{Answering, Old, Proved, StartFailed, judge};
use crate::error::{CliError, Result};
use crate::host_stop::{self, Asked, LOOK_EVERY, Progress};
use crate::resolve::KnownEnvironment;
use crate::startup::{self, Started};

/// What the proof makes and reads, given to it so that a case can supply each answer, with the
/// runtime's clock in its own hands. [`Real`] is the command's own.
pub(super) trait Operations {
    /// A connection to a daemon that answered.
    type Connection;

    /// The start as `kr new` makes it, or the connection of a daemon that already answers.
    /// `launched` is set as the start sets it.
    async fn start(&self, launched: &AtomicBool) -> Result<(Self::Connection, Option<Started>)>;

    /// The generation the daemon states on `connection`, or why it could not be read.
    async fn generation(
        &self,
        connection: &mut Self::Connection,
    ) -> std::result::Result<ControllerGeneration, Shown>;

    /// The process the daemon states on `connection`: none where the daemon says it states none,
    /// and an error where the exchange was cut.
    async fn process(
        &self,
        connection: &mut Self::Connection,
    ) -> std::result::Result<Option<u64>, Shown>;

    /// One attempt to connect to the daemon that answers now, bounded by `within`.
    async fn connect(&self, within: Duration) -> Option<Self::Connection>;

    /// Waits `time` between two attempts.
    async fn pause(&self, time: Duration);
}

/// The operations on this machine: the start, the daemon's own answers and the timer.
pub(super) struct Real<'a> {
    pub(super) host: &'a HostPaths,
    pub(super) environment: &'a KnownEnvironment,
    pub(super) progress: &'a Progress,
}

impl Operations for Real<'_> {
    type Connection = LocalClient;

    async fn start(&self, launched: &AtomicBool) -> Result<(LocalClient, Option<Started>)> {
        startup::open_or_start_telling(self.host, self.environment, launched).await
    }

    async fn generation(
        &self,
        connection: &mut LocalClient,
    ) -> std::result::Result<ControllerGeneration, Shown> {
        match tokio::time::timeout(
            startup::ANSWER_BOUND,
            host_stop::host_info(connection, &self.environment.paths),
        )
        .await
        {
            Ok(Ok(info)) => Ok(info.generation),
            Ok(Err(error)) => Err(shown!(
                "a control daemon answered and its generation could not be read: {}",
                error.said()
            )),
            Err(_) => Err(Shown::said(
                "a control daemon answered and did not state its generation in time",
            )),
        }
    }

    /// The process comes from a request for the launch alone, which answers the daemon's process
    /// and stops nothing.
    async fn process(
        &self,
        connection: &mut LocalClient,
    ) -> std::result::Result<Option<u64>, Shown> {
        match host_stop::ask(
            connection,
            self.environment.environment_id,
            false,
            self.progress,
            true,
        )
        .await
        {
            Asked::Taken(result) => Ok(Some(result.pid.get())),
            // A daemon that refuses the request states no process.
            Asked::Refused(_) => Ok(None),
            Asked::Unknown(why) => Err(shown!(
                "a control daemon answered and its process could not be read: {}",
                why
            )),
            Asked::NotComposed { error } => Err(shown!(
                "a control daemon answered and its process could not be read: {}",
                Shown::ipc(&error)
            )),
        }
    }

    async fn connect(&self, within: Duration) -> Option<LocalClient> {
        let endpoint = self.environment.paths.controller_endpoint().ok()?;
        match startup::reach(&endpoint, within, &[]).await {
            startup::Reached::Answered(listed) => startup::ours(*listed).ok(),
            startup::Reached::Silent | startup::Reached::Refused(_) => None,
        }
    }

    async fn pause(&self, time: Duration) {
        tokio::time::sleep(time).await;
    }
}

/// What one connection says of the daemon behind it: its generation, and then its process, both
/// read on that connection, so that they are of one process. Two reads on two connections cannot
/// be told from a daemon that ended and another that took its place.
pub(super) async fn answering<O: Operations>(
    operations: &O,
    connection: &mut O::Connection,
) -> std::result::Result<Answering, Shown> {
    let generation = operations.generation(connection).await?;
    let pid = operations.process(connection).await?;
    Ok(Answering { generation, pid })
}

/// Starts a daemon as `kr new` does and proves that the daemon which answers is the one this
/// command started: the connection that answered gives a generation newer than the one that was
/// stopped and, where the start knows its process, that process.
///
/// Where the exchange on that connection is cut, nothing more is started: see [`after_a_cut`].
pub(super) async fn prove<O: Operations>(
    operations: &O,
    stopped: Old,
    bound: Duration,
) -> std::result::Result<Proved, StartFailed> {
    let launched = AtomicBool::new(false);
    let (mut connection, started) = match operations.start(&launched).await {
        Ok(found) => found,
        Err(error) => {
            return Err(StartFailed {
                error,
                launched: launched.load(Ordering::SeqCst),
            });
        }
    };
    // A daemon answered, so there is no requested daemon that may still start.
    let (answering, cut) = match answering(operations, &mut connection).await {
        Ok(answering) => (answering, false),
        Err(_) => (after_a_cut(operations, started, bound).await?, true),
    };
    let proved = judge(started, stopped, &answering).map_err(|message| StartFailed {
        error: CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: Shown::said(message),
        },
        launched: started.is_some(),
    })?;
    Ok(if cut { proved.after_a_cut() } else { proved })
}

/// The exchange on the connection that the start gave did not complete: it failed, it reached its
/// bound, or the daemon gave no process that could be read. This starts nothing: the daemon may
/// have been stopped by another command, whose own start comes up next. It waits, within `bound`
/// counted from here, for a daemon to give a whole exchange, and gives what that daemon says on
/// its connection. A wait that runs out is the failure of a proof that was cut, which says that
/// the command could not read which daemon serves the environment and that none answered within
/// the bound.
async fn after_a_cut<O: Operations>(
    operations: &O,
    started: Option<Started>,
    bound: Duration,
) -> std::result::Result<Answering, StartFailed> {
    let deadline = tokio::time::Instant::now() + bound;
    let left = || deadline.saturating_duration_since(tokio::time::Instant::now());
    loop {
        if let Some(mut connection) = operations.connect(left()).await
            && let Ok(Ok(answering)) =
                tokio::time::timeout(left(), answering(operations, &mut connection)).await
        {
            return Ok(answering);
        }
        if left().is_zero() {
            let message = cut_failed_said(started, bound);
            return Err(StartFailed {
                error: CliError::Unfinished {
                    code: ErrorCode::EnvironmentUnavailable,
                    message,
                },
                // A daemon answered, so there is no requested daemon that may still start.
                launched: false,
            });
        }
        operations.pause(LOOK_EVERY.min(left())).await;
    }
}

/// What a proof whose exchange was cut says where no daemon gave a whole exchange within `bound`:
/// that this command could not read which control daemon serves the environment, and the process
/// it launched where it launched one. It says nothing of an end that the command did not see.
fn cut_failed_said(started: Option<Started>, bound: Duration) -> Shown {
    match started {
        Some(started) => shown!(
            "this command started a control daemon{} but could not read which control daemon \
             serves the environment, and no control daemon answered within {} seconds",
            super::process_said(started.pid.map(u64::from)),
            bound.as_secs()
        ),
        None => shown!(
            "this command could not read which control daemon serves the environment, and no \
             control daemon answered within {} seconds",
            bound.as_secs()
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use kr_protocol::hostinfo::configuration::ControllerStartup;

    use super::*;

    /// One answer of an operation, and the time it takes on the clock.
    struct Step<T> {
        gives: T,
        takes: Duration,
    }

    fn at_once<T>(gives: T) -> Step<T> {
        Step {
            gives,
            takes: Duration::ZERO,
        }
    }

    /// The answers an operation gives in turn, the last one for every call after them.
    struct Script<T>(Mutex<Vec<Step<T>>>);

    impl<T: Clone> Script<T> {
        fn of(steps: Vec<Step<T>>) -> Self {
            Self(Mutex::new(steps))
        }

        fn next(&self) -> Step<T> {
            let mut steps = self.0.lock().expect("the script");
            let step = if steps.len() > 1 {
                steps.remove(0)
            } else {
                let last = steps.first().expect("a step");
                Step {
                    gives: last.gives.clone(),
                    takes: last.takes,
                }
            };
            drop(steps);
            step
        }
    }

    /// What one daemon says on its connection.
    #[derive(Clone)]
    struct Says {
        generation: std::result::Result<u64, &'static str>,
        process: std::result::Result<Option<u64>, &'static str>,
        /// Whether its generation is never said.
        hangs: bool,
    }

    fn says(generation: u64, process: Option<u64>) -> Says {
        Says {
            generation: Ok(generation),
            process: Ok(process),
            hangs: false,
        }
    }

    /// A daemon whose exchange is cut before it says its generation.
    fn cut() -> Says {
        Says {
            generation: Err("the connection was cut"),
            process: Err("the connection was cut"),
            hangs: false,
        }
    }

    /// A daemon that answers the connection and then never says its generation.
    fn hangs() -> Says {
        Says {
            hangs: true,
            ..says(6, Some(100))
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Call {
        Start,
        Generation(usize),
        Process(usize),
        Connect(Duration),
        Pause(Duration),
    }

    /// The operations of a case. The start gives connection 0 and what the case says it started;
    /// a later connection is the next one the script of connects gives, and each connection is the
    /// daemon of the same number in `daemons`. Every call is recorded with the time on the paused
    /// clock.
    struct Supplied {
        began: tokio::time::Instant,
        calls: Mutex<Vec<(Duration, Call)>>,
        start_takes: Duration,
        started: Option<Started>,
        daemons: Vec<Says>,
        connects: Script<Option<usize>>,
    }

    impl Supplied {
        fn new(
            start_takes: Duration,
            started: Option<Started>,
            daemons: Vec<Says>,
            connects: Vec<Step<Option<usize>>>,
        ) -> Self {
            Self {
                began: tokio::time::Instant::now(),
                calls: Mutex::new(Vec::new()),
                start_takes,
                started,
                daemons,
                connects: Script::of(connects),
            }
        }

        fn record(&self, call: Call) {
            self.calls
                .lock()
                .expect("the calls")
                .push((self.began.elapsed(), call));
        }

        fn calls(&self) -> Vec<(Duration, Call)> {
            self.calls.lock().expect("the calls").clone()
        }

        fn count(&self, wanted: impl Fn(&Call) -> bool) -> usize {
            self.calls().iter().filter(|(_, call)| wanted(call)).count()
        }

        fn starts(&self) -> usize {
            self.count(|call| matches!(call, Call::Start))
        }
    }

    impl Operations for Supplied {
        type Connection = usize;

        async fn start(&self, _launched: &AtomicBool) -> Result<(usize, Option<Started>)> {
            self.record(Call::Start);
            tokio::time::advance(self.start_takes).await;
            Ok((0, self.started))
        }

        async fn generation(
            &self,
            connection: &mut usize,
        ) -> std::result::Result<ControllerGeneration, Shown> {
            self.record(Call::Generation(*connection));
            if self.daemons[*connection].hangs {
                std::future::pending::<()>().await;
            }
            self.daemons[*connection]
                .generation
                .map(ControllerGeneration::new)
                .map_err(Shown::said)
        }

        async fn process(&self, connection: &mut usize) -> std::result::Result<Option<u64>, Shown> {
            self.record(Call::Process(*connection));
            self.daemons[*connection].process.map_err(Shown::said)
        }

        async fn connect(&self, within: Duration) -> Option<usize> {
            self.record(Call::Connect(within));
            let step = self.connects.next();
            tokio::time::advance(step.takes).await;
            step.gives
        }

        async fn pause(&self, time: Duration) {
            self.record(Call::Pause(time));
            tokio::time::advance(time).await;
        }
    }

    const BOUND: Duration = Duration::from_secs(30);

    fn started(pid: u32) -> Option<Started> {
        Some(Started {
            pid: Some(pid),
            start: ControllerStartup::Standalone,
            manager: None,
        })
    }

    fn failed_with(proved: std::result::Result<Proved, StartFailed>) -> (String, bool) {
        match proved {
            Err(failed) => (failed.error.said().to_string(), failed.launched),
            Ok(_) => panic!("the proof should have failed"),
        }
    }

    /// The proof's exchange is one connection: the generation and then the process are read on the
    /// connection the start gave, and nothing connects again to read either.
    #[tokio::test(start_paused = true)]
    async fn the_exchange_reads_the_generation_and_the_process_on_the_one_connection() {
        let supplied = Supplied::new(
            Duration::ZERO,
            started(100),
            vec![says(5, Some(100))],
            vec![at_once(None)],
        );
        let proved = prove(
            &supplied,
            Old::Generation(ControllerGeneration::new(4)),
            BOUND,
        )
        .await;
        assert!(matches!(proved, Ok(Proved::Ours(ours)) if ours.pid == Some(100)));
        assert_eq!(
            supplied.calls(),
            vec![
                (Duration::ZERO, Call::Start),
                (Duration::ZERO, Call::Generation(0)),
                (Duration::ZERO, Call::Process(0)),
            ],
            "one start, two reads on its connection, no second connection"
        );
    }

    /// The exchange gives what the connection said, and a daemon that refuses the request states
    /// no process.
    #[tokio::test(start_paused = true)]
    async fn the_exchange_gives_what_the_connection_said_and_none_for_a_refused_process() {
        let supplied = Supplied::new(
            Duration::ZERO,
            started(100),
            vec![says(5, Some(100)), says(7, None)],
            vec![at_once(None)],
        );
        assert_eq!(
            answering(&supplied, &mut 0).await.expect("answers"),
            Answering {
                generation: ControllerGeneration::new(5),
                pid: Some(100)
            }
        );
        assert_eq!(
            answering(&supplied, &mut 1).await.expect("answers"),
            Answering {
                generation: ControllerGeneration::new(7),
                pid: None
            }
        );
        assert_eq!(supplied.count(|call| matches!(call, Call::Connect(_))), 0);
    }

    /// A cut exchange followed by the started process answering is proved: nothing is started a
    /// second time, the wait connects first at the cut with the whole bound and pauses a look's
    /// interval between attempts, and the answer comes from the one exchange on the new connection.
    #[tokio::test(start_paused = true)]
    async fn a_cut_then_the_started_process_is_proved_and_nothing_is_started_again() {
        let supplied = Supplied::new(
            Duration::ZERO,
            started(100),
            vec![cut(), says(6, Some(100))],
            vec![at_once(None), at_once(Some(1))],
        );
        let proved = prove(
            &supplied,
            Old::Generation(ControllerGeneration::new(4)),
            BOUND,
        )
        .await;
        assert!(matches!(proved, Ok(Proved::Ours(ours)) if ours.pid == Some(100)));
        assert_eq!(
            supplied.calls(),
            vec![
                (Duration::ZERO, Call::Start),
                (Duration::ZERO, Call::Generation(0)),
                (Duration::ZERO, Call::Connect(BOUND)),
                (Duration::ZERO, Call::Pause(LOOK_EVERY)),
                (LOOK_EVERY, Call::Connect(BOUND - LOOK_EVERY)),
                (LOOK_EVERY, Call::Generation(1)),
                (LOOK_EVERY, Call::Process(1)),
            ]
        );
        assert_eq!(supplied.starts(), 1, "no second start");
    }

    /// A cut exchange followed by another process answering, of a generation newer than the daemon
    /// that was stopped, is the outcome for another daemon, which carries what this command
    /// launched and that the exchange was cut.
    #[tokio::test(start_paused = true)]
    async fn a_cut_then_another_process_is_another_and_carries_what_was_launched() {
        let supplied = Supplied::new(
            Duration::ZERO,
            started(100),
            vec![cut(), says(6, Some(200))],
            vec![at_once(Some(1))],
        );
        let proved = prove(
            &supplied,
            Old::Generation(ControllerGeneration::new(4)),
            BOUND,
        )
        .await;
        assert!(matches!(
            proved,
            Ok(Proved::Another {
                serving: Some(200),
                launched: Some(launched),
                cut: true
            }) if launched.pid == Some(100)
        ));
        assert_eq!(supplied.starts(), 1, "no second start");
        assert_eq!(
            supplied.count(|call| matches!(call, Call::Pause(_))),
            0,
            "the first attempt answered"
        );
    }

    /// A cut exchange after which a daemon answers that is not newer than the one that was
    /// stopped proves nothing, as an exchange that was not cut does not.
    #[tokio::test(start_paused = true)]
    async fn a_cut_then_the_generation_that_was_stopped_is_no_proof() {
        let supplied = Supplied::new(
            Duration::ZERO,
            started(100),
            vec![cut(), says(4, Some(100))],
            vec![at_once(Some(1))],
        );
        let (said, launched) = failed_with(
            prove(
                &supplied,
                Old::Generation(ControllerGeneration::new(4)),
                BOUND,
            )
            .await,
        );
        assert!(said.contains("generation that was told to stop"), "{said}");
        assert!(launched, "a daemon was started and did not prove itself");
    }

    /// A cut exchange after which nothing answers fails at the bound, and the bound is counted
    /// from the cut: the start and the read that was cut took 7 seconds, and the wait ran its own
    /// 30 after them. Nothing is started a second time, and no call comes after the bound.
    #[tokio::test(start_paused = true)]
    async fn a_cut_then_nothing_to_the_bound_fails_with_the_bound_counted_from_the_cut() {
        let supplied = Supplied::new(
            Duration::from_secs(7),
            started(100),
            vec![cut()],
            vec![at_once(None)],
        );
        let (said, launched) = failed_with(
            prove(
                &supplied,
                Old::Generation(ControllerGeneration::new(4)),
                BOUND,
            )
            .await,
        );
        assert_eq!(
            said,
            "this command started a control daemon (process 100) but could not read which control \
             daemon serves the environment, and no control daemon answered within 30 seconds"
        );
        assert!(!launched, "a daemon answered, so none may still start");
        let cut_at = Duration::from_secs(7);
        assert_eq!(supplied.began.elapsed(), cut_at + BOUND);
        assert_eq!(supplied.starts(), 1, "no second start");
        let calls = supplied.calls();
        assert!(
            calls.iter().all(|(at, call)| *at <= cut_at + BOUND
                && !matches!(call, Call::Pause(time) if *time > LOOK_EVERY)),
            "no call after the bound and no pause longer than a look's interval"
        );
        assert!(
            calls.len() > 100,
            "it looked again and again: {}",
            calls.len()
        );
        assert_eq!(
            calls.get(2),
            Some(&(cut_at, Call::Connect(BOUND))),
            "the first attempt is at the cut with the whole bound"
        );
    }

    /// The exchange is not complete where the generation was not read and where the generation was
    /// read and the process was not: the failure at the bound says the same of both, with the
    /// process this command launched, and with no launch where the start's look found a daemon.
    #[tokio::test(start_paused = true)]
    async fn each_way_the_exchange_is_not_complete_says_that_the_daemon_could_not_be_read() {
        let process_not_read = Says {
            process: Err("the process could not be read"),
            ..says(5, Some(100))
        };
        for first in [cut(), process_not_read] {
            let supplied = Supplied::new(
                Duration::ZERO,
                started(100),
                vec![first],
                vec![at_once(None)],
            );
            let (said, launched) = failed_with(
                prove(
                    &supplied,
                    Old::Generation(ControllerGeneration::new(4)),
                    BOUND,
                )
                .await,
            );
            assert_eq!(
                said,
                "this command started a control daemon (process 100) but could not read which \
                 control daemon serves the environment, and no control daemon answered within \
                 30 seconds"
            );
            assert!(!launched);
        }
        let supplied = Supplied::new(Duration::ZERO, None, vec![cut()], vec![at_once(None)]);
        let (said, launched) = failed_with(
            prove(
                &supplied,
                Old::Generation(ControllerGeneration::new(4)),
                BOUND,
            )
            .await,
        );
        assert_eq!(
            said,
            "this command could not read which control daemon serves the environment, and no \
             control daemon answered within 30 seconds"
        );
        assert!(!launched);
    }

    /// The failure at the bound says where the start was made by a manager that states no process:
    /// the launch without a process.
    #[tokio::test(start_paused = true)]
    async fn the_failure_at_the_bound_names_no_process_where_the_start_states_none() {
        let started = Some(Started {
            pid: None,
            start: ControllerStartup::Standalone,
            manager: None,
        });
        let supplied = Supplied::new(Duration::ZERO, started, vec![cut()], vec![at_once(None)]);
        let (said, _) = failed_with(
            prove(
                &supplied,
                Old::Generation(ControllerGeneration::new(4)),
                BOUND,
            )
            .await,
        );
        assert_eq!(
            said,
            "this command started a control daemon but could not read which control daemon \
             serves the environment, and no control daemon answered within 30 seconds"
        );
    }

    /// A daemon that answers the connection and is cut again is waited through, not a failure and
    /// not a reason to start: the next daemon that answers whole is judged.
    #[tokio::test(start_paused = true)]
    async fn a_cut_again_is_waited_through_and_the_next_answer_is_judged() {
        let supplied = Supplied::new(
            Duration::ZERO,
            started(100),
            vec![cut(), cut(), says(6, Some(100))],
            vec![at_once(Some(1)), at_once(Some(2))],
        );
        let proved = prove(
            &supplied,
            Old::Generation(ControllerGeneration::new(4)),
            BOUND,
        )
        .await;
        assert!(matches!(proved, Ok(Proved::Ours(_))));
        assert_eq!(supplied.starts(), 1, "no second start");
        assert_eq!(supplied.count(|call| matches!(call, Call::Connect(_))), 2);
    }

    /// An answer that is never read is not waited for past the bound: the wait ends there, and it
    /// starts nothing.
    #[tokio::test(start_paused = true)]
    async fn an_answer_that_is_never_read_ends_the_wait_at_the_bound() {
        let supplied = Supplied::new(
            Duration::ZERO,
            started(100),
            vec![cut(), hangs()],
            vec![at_once(Some(1))],
        );
        let (said, _) = failed_with(
            prove(
                &supplied,
                Old::Generation(ControllerGeneration::new(4)),
                BOUND,
            )
            .await,
        );
        assert!(
            said.contains("no control daemon answered within 30 seconds"),
            "{said}"
        );
        assert_eq!(supplied.began.elapsed(), BOUND);
        assert_eq!(supplied.starts(), 1, "no second start");
    }

    /// Where the start's look found a daemon (none was started), a cut exchange is waited through
    /// the same way, and what answers is named by what it states and carries no launch.
    #[tokio::test(start_paused = true)]
    async fn a_cut_after_a_daemon_that_the_look_found_names_the_one_that_answers_next() {
        let supplied = Supplied::new(
            Duration::ZERO,
            None,
            vec![cut(), says(6, Some(200))],
            vec![at_once(Some(1))],
        );
        let proved = prove(
            &supplied,
            Old::Generation(ControllerGeneration::new(4)),
            BOUND,
        )
        .await;
        assert!(matches!(
            proved,
            Ok(Proved::Another {
                serving: Some(200),
                launched: None,
                cut: false
            })
        ));
        assert_eq!(supplied.starts(), 1, "no second start");
    }
}
