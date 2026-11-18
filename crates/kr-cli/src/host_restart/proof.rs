//! The reads of the daemon that a restart makes after its stop, and the start that follows.
//!
//! Every read writes what it saw into the record of the wait as it sees it: that it began, the
//! greeting, what `host.info` gave and the answer to the request for the launch alone, so that a
//! time-out or a failure that comes later discards none of it. A read is whole where it gave a
//! usable greeting, the daemon's generation and the answer to the launch-only request on the one
//! connection that answered.
//!
//! A start that does not give a whole exchange is not yet a failure: the daemon that the
//! connection reached may have been stopped by another command, as this one stopped the daemon
//! before it, and a daemon of that command's start comes up next. The command then starts nothing
//! more. It waits, within the start's bound counted from the cut, for a daemon to give a whole
//! exchange.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kr_ipc::client::{Listed, LocalClient};
use kr_ipc::paths::{EnvironmentPaths, HostPaths};
use kr_protocol::ids::EnvironmentId;
use kr_protocol::method::Method;

use super::record::{Last, Launch, Observation, Record, Shared};
use super::{Old, StartFailed};
use crate::error::Result;
use crate::host_stop::{self, Asked, Gave, LOOK_EVERY, Progress, Sight};
use crate::resolve::KnownEnvironment;
use crate::startup::{self, Started};

/// What the proof makes and reads, given to it so that a case can supply each answer, with the
/// runtime's clock in its own hands. [`Real`] is the command's own.
pub(super) trait Operations {
    /// A connection to a daemon that gave a usable greeting.
    type Connection;

    /// The start as `kr new` makes it, or the connection of a daemon that already answers.
    /// `launched` is set as the start sets it. The start's own reads are written to `record`.
    async fn start(
        &self,
        launched: &AtomicBool,
        record: &Shared,
    ) -> Result<(Self::Connection, Option<Started>)>;

    /// The exchange on `connection`, whose greeting is in the record: `host.info`, and the request
    /// for the launch alone where it gave a generation. Each step is written to `record` as it is
    /// seen.
    async fn exchange(&self, connection: &mut Self::Connection, record: &Shared);

    /// One attempt to connect to the daemon that answers now, bounded by `within`. It writes that
    /// it began and what it gave to `record`.
    async fn connect(&self, within: Duration, record: &Shared) -> Option<Self::Connection>;

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

    async fn start(
        &self,
        launched: &AtomicBool,
        record: &Shared,
    ) -> Result<(LocalClient, Option<Started>)> {
        let told = record.clone();
        startup::open_or_start_telling(self.host, self.environment, launched, &move |sight| {
            told.observe(Observation::Sight(sight));
        })
        .await
    }

    async fn exchange(&self, connection: &mut LocalClient, record: &Shared) {
        exchange(
            connection,
            self.environment.environment_id,
            self.progress,
            record,
        )
        .await;
    }

    async fn connect(&self, within: Duration, record: &Shared) -> Option<LocalClient> {
        connect(&self.environment.paths, within, record).await
    }

    async fn pause(&self, time: Duration) {
        tokio::time::sleep(time).await;
    }
}

/// One attempt to connect to the daemon at the environment's endpoint, bounded by `within`: it
/// began, and the connection and the greeting gave what they gave. A daemon that gave a usable
/// greeting is the connection that is returned.
pub(super) async fn connect(
    environment: &EnvironmentPaths,
    within: Duration,
    record: &Shared,
) -> Option<LocalClient> {
    let sight = |sight| record.observe(Observation::Sight(sight));
    sight(Sight::Began);
    let Ok(endpoint) = environment.controller_endpoint() else {
        sight(Sight::Gave(Gave::NoAddress));
        return None;
    };
    match startup::reach(&endpoint, within, &[]).await {
        startup::Reached::Silent => {
            sight(Sight::Gave(Gave::NothingInTime));
            None
        }
        startup::Reached::Refused(error) => {
            sight(Sight::Gave(host_stop::gave_by_the_greeting(&error)));
            None
        }
        startup::Reached::Answered(listed) => match *listed {
            Listed::Other(_) => {
                sight(Sight::Gave(Gave::GreetingOfAnotherMajor));
                None
            }
            Listed::Ours(client) => {
                sight(Sight::Greeted);
                Some(*client)
            }
        },
    }
}

/// The exchange on a connection that gave a usable greeting: `host.info`, and then the request for
/// the launch alone, which answers the daemon's process and stops nothing, on the same connection.
/// The process is none where the daemon refuses the request; an exchange that is cut, withheld or
/// not answered is not whole.
pub(super) async fn exchange(
    connection: &mut LocalClient,
    id: EnvironmentId,
    progress: &Progress,
    record: &Shared,
) {
    let gave = host_stop::gave_by_the_read(connection.request(Method::HostInfo, &()).await);
    record.observe(Observation::Sight(Sight::Gave(gave)));
    if !matches!(gave, Gave::Reported(_)) {
        return;
    }
    let launch = match host_stop::ask(connection, id, false, progress, true).await {
        Asked::Taken(result) => Launch::Stated(Some(result.pid.get())),
        // A daemon that refuses the request states no process.
        Asked::Refused(_) => Launch::Stated(None),
        Asked::Unknown(_) | Asked::NotComposed { .. } => Launch::NotWhole,
    };
    record.observe(Observation::Launch(launch));
}

/// One read of the daemon at the environment's endpoint, as a whole bounded by `within`: the
/// connection, the greeting and the exchange. What it saw is in `record` where the time-out ends
/// it.
pub(super) async fn read(
    environment: &KnownEnvironment,
    progress: &Progress,
    record: &Shared,
    within: Duration,
) {
    let _ = tokio::time::timeout(within, async {
        if let Some(mut connection) = connect(&environment.paths, within, record).await {
            exchange(
                &mut connection,
                environment.environment_id,
                progress,
                record,
            )
            .await;
        }
    })
    .await;
}

/// What one read of a wait that ends at `deadline` is given: its own bound, or the time that is
/// left of the wait, whichever is less.
pub(super) fn within(deadline: tokio::time::Instant) -> Duration {
    startup::ANSWER_BOUND.min(deadline.saturating_duration_since(tokio::time::Instant::now()))
}

/// Whether the last read of `record` was a whole exchange, and its generation is not the one of
/// the daemon that was told to stop: where the stopped generation was never read the later answer
/// stands, and no comparison is made.
pub(super) fn answers_as_another_daemon(record: &Record, stopped: Old) -> bool {
    match (record.last, stopped) {
        (Some(Last::Whole(generation)), Old::Generation(old)) => generation > old,
        (Some(Last::Whole(_)), Old::None | Old::Unread) => true,
        _ => false,
    }
}

/// Reads until a read gives a whole exchange or `deadline` passes; each read is given the less of
/// its own bound and the time that is left. Says whether the last read was whole.
pub(super) async fn until_whole<O: Operations>(
    operations: &O,
    record: &Shared,
    deadline: tokio::time::Instant,
) -> bool {
    let left = || deadline.saturating_duration_since(tokio::time::Instant::now());
    loop {
        let within = startup::ANSWER_BOUND.min(left());
        let _ = tokio::time::timeout(within, async {
            if let Some(mut connection) = operations.connect(within, record).await {
                operations.exchange(&mut connection, record).await;
            }
        })
        .await;
        if matches!(record.read().last, Some(Last::Whole(_))) {
            return true;
        }
        if left().is_zero() {
            return false;
        }
        operations.pause(LOOK_EVERY.min(left())).await;
    }
}

/// Starts a daemon as `kr new` does and reads what answers: the exchange on the connection that
/// the start gave, and, where it is not whole, nothing more is started and the reads go on within
/// `bound` counted from the start. What the daemon that answers is, is in `record`; what this
/// command launched is returned, none where the look found a daemon already there. A start is a
/// failure where it gave no whole exchange within the bound, or where the daemon that answers is
/// of the generation that was told to stop.
pub(super) async fn prove<O: Operations>(
    operations: &O,
    stopped: Old,
    bound: Duration,
    record: &Shared,
) -> std::result::Result<Option<Started>, StartFailed> {
    let launched = AtomicBool::new(false);
    let (mut connection, started) = match operations.start(&launched, record).await {
        Ok(found) => found,
        Err(error) => {
            return Err(StartFailed {
                error: Some(error),
                launched: launched.load(Ordering::SeqCst),
            });
        }
    };
    let deadline = tokio::time::Instant::now() + bound;
    // The start's connection gave a usable greeting.
    record.observe(Observation::Sight(Sight::Greeted));
    let _ = tokio::time::timeout(
        startup::ANSWER_BOUND.min(bound),
        operations.exchange(&mut connection, record),
    )
    .await;
    let whole = matches!(record.read().last, Some(Last::Whole(_)))
        || until_whole(operations, record, deadline).await;
    if whole && answers_as_another_daemon(&record.read(), stopped) {
        return Ok(started);
    }
    Err(StartFailed {
        error: None,
        launched: launched.load(Ordering::SeqCst),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use kr_protocol::hostinfo::configuration::ControllerStartup;
    use kr_protocol::ids::ControllerGeneration;

    use super::*;

    fn generation(number: u64) -> ControllerGeneration {
        ControllerGeneration::new(number)
    }

    /// What one connection of a case does.
    #[derive(Clone, Copy)]
    enum Daemon {
        /// Nothing answers within `0`.
        Silent(Duration),
        /// A usable greeting, then a whole exchange after `takes`.
        Whole {
            generation: u64,
            process: Option<u64>,
            takes: Duration,
        },
        /// A usable greeting, the generation, and then the launch-only answer is cut.
        Cut(u64),
        /// A usable greeting, and then nothing.
        Hangs,
    }

    /// The operations of a case: each start and each connect takes the next daemon of the script,
    /// the last one for every call after it.
    struct Supplied {
        script: Mutex<VecDeque<Daemon>>,
        started: Option<Started>,
    }

    impl Supplied {
        fn of(script: Vec<Daemon>) -> Self {
            Self {
                script: Mutex::new(script.into()),
                started: Some(Started {
                    pid: Some(77),
                    start: ControllerStartup::Standalone,
                    manager: None,
                }),
            }
        }

        fn next(&self) -> Daemon {
            let mut script = self.script.lock().expect("the script");
            if script.len() > 1 {
                script.pop_front().expect("a daemon")
            } else {
                *script.front().expect("a daemon")
            }
        }
    }

    impl Operations for Supplied {
        type Connection = Daemon;

        async fn start(
            &self,
            _launched: &AtomicBool,
            _record: &Shared,
        ) -> Result<(Daemon, Option<Started>)> {
            Ok((self.next(), self.started))
        }

        async fn exchange(&self, connection: &mut Daemon, record: &Shared) {
            let sight = |gave| record.observe(Observation::Sight(Sight::Gave(gave)));
            match *connection {
                Daemon::Whole {
                    generation: number,
                    process,
                    takes,
                } => {
                    tokio::time::sleep(takes).await;
                    sight(Gave::Reported(generation(number)));
                    record.observe(Observation::Launch(Launch::Stated(process)));
                }
                Daemon::Cut(number) => {
                    sight(Gave::Reported(generation(number)));
                    record.observe(Observation::Launch(Launch::NotWhole));
                }
                Daemon::Hangs => tokio::time::sleep(Duration::from_secs(3600)).await,
                Daemon::Silent(_) => {}
            }
        }

        async fn connect(&self, within: Duration, record: &Shared) -> Option<Daemon> {
            record.observe(Observation::Sight(Sight::Began));
            let daemon = self.next();
            if let Daemon::Silent(takes) = daemon {
                tokio::time::sleep(takes.min(within)).await;
                record.observe(Observation::Sight(Sight::Gave(Gave::NothingInTime)));
                return None;
            }
            record.observe(Observation::Sight(Sight::Greeted));
            Some(daemon)
        }

        async fn pause(&self, time: Duration) {
            tokio::time::sleep(time).await;
        }
    }

    fn whole(number: u64, process: Option<u64>) -> Daemon {
        Daemon::Whole {
            generation: number,
            process,
            takes: Duration::ZERO,
        }
    }

    /// A start whose connection gives a whole exchange of another generation succeeds, and the
    /// record holds the process that the daemon stated.
    #[tokio::test(start_paused = true)]
    async fn a_start_whose_connection_gives_a_whole_exchange_of_another_generation_succeeds() {
        let record = Shared::new();
        let started = prove(
            &Supplied::of(vec![whole(2, Some(91))]),
            Old::Generation(generation(1)),
            Duration::from_secs(30),
            &record,
        )
        .await
        .map_err(|failed| failed.launched)
        .expect("a whole exchange of another generation");
        assert_eq!(started.and_then(|started| started.pid), Some(77));
        let read = record.read();
        assert_eq!(read.last, Some(Last::Whole(generation(2))));
        assert_eq!(read.whole.and_then(|whole| whole.process), Some(91));
    }

    /// The generation that was told to stop is no success where it gives a whole exchange, and
    /// where the stopped generation was never read the answer stands.
    #[tokio::test(start_paused = true)]
    async fn the_generation_that_was_told_to_stop_is_a_failure_and_an_unread_one_is_not() {
        let record = Shared::new();
        let failed = prove(
            &Supplied::of(vec![whole(1, Some(91))]),
            Old::Generation(generation(1)),
            Duration::from_secs(30),
            &record,
        )
        .await;
        assert!(failed.is_err());
        assert_eq!(record.read().last, Some(Last::Whole(generation(1))));
        let record = Shared::new();
        assert!(
            prove(
                &Supplied::of(vec![whole(1, None)]),
                Old::Unread,
                Duration::from_secs(30),
                &record,
            )
            .await
            .is_ok()
        );
    }

    /// An exchange that is cut starts nothing more: the reads go on, and a later whole exchange
    /// ends the wait; the greeting of the cut read stays in the record.
    #[tokio::test(start_paused = true)]
    async fn a_cut_exchange_is_read_again_and_a_later_whole_exchange_succeeds() {
        let record = Shared::new();
        let result = prove(
            &Supplied::of(vec![
                Daemon::Cut(2),
                Daemon::Silent(Duration::ZERO),
                whole(2, None),
            ]),
            Old::None,
            Duration::from_secs(30),
            &record,
        )
        .await;
        assert!(result.is_ok());
        assert!(record.read().greeted);
        assert_eq!(record.read().last, Some(Last::Whole(generation(2))));
    }

    /// One deadline for the wait: where each read of the wait would use its full bound the wait
    /// still ends at its own bound, and what a read saw before the time-out is in the record.
    #[tokio::test(start_paused = true)]
    async fn a_wait_does_not_pass_its_bound_where_each_read_uses_its_full_time() {
        let record = Shared::new();
        let began = tokio::time::Instant::now();
        let operations = Supplied::of(vec![Daemon::Hangs]);
        let deadline = began + Duration::from_secs(30);
        assert!(!until_whole(&operations, &record, deadline).await);
        assert!(
            tokio::time::Instant::now() <= deadline,
            "the wait ended after {:?}",
            began.elapsed()
        );
        let read = record.read();
        assert!(
            read.greeted,
            "the greeting that came before the time-out stays"
        );
        assert!(matches!(read.last, Some(Last::Greeting(None))));
        // A start whose exchange hangs ends within the start's bound as well.
        let record = Shared::new();
        let began = tokio::time::Instant::now();
        let failed = prove(
            &Supplied::of(vec![Daemon::Hangs]),
            Old::None,
            Duration::from_secs(30),
            &record,
        )
        .await;
        assert!(failed.is_err());
        assert!(began.elapsed() <= Duration::from_secs(30));
        assert!(record.read().greeted);
    }
}
