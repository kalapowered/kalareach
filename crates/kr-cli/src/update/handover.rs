//! Handing each environment's control daemon over to the release an update installs, and starting
//! that release's daemon as the one it replaces was started.
//!
//! A daemon is asked through its own door, `host.update.handover`: to prepare, which begins an
//! attempt, closes its gate to new sessions and waits for the creates it has started, and then to
//! stop under that attempt, or to resume when the update is not going ahead. Its answer to
//! `prepare` says how it was started and under which attempt, and how is recorded before it is
//! told to stop. The environment is known to be free once its singleton lock can be taken, which
//! the kernel gives up only when the daemon's process has gone.
//!
//! A daemon found holding an environment whose daemon an update stopped is asked to resume before
//! it is taken for the environment's daemon, naming no attempt, so whichever is open ends: one that
//! resumes goes on serving, and no stop of any earlier attempt can end it after, since a stop
//! names its attempt; one told to stop refuses, and is waited for until it has gone.
//!
//! The store's install lock is only ever waited for a bounded time ([`install_lock`]): a control
//! daemon holds it, shared, while it starts, and one that never finishes starting must not hold
//! an update, or a recovery, for ever.

use std::time::Duration;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_controller::singleton::SingletonLock;
use kr_ipc::client::LocalClient;
use kr_ipc::install::Store;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ActionId;
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, Uuid};
use kr_protocol::update::{
    HANDOVER_SETTLE_MS, HandoverStep, HostUpdateHandoverParams, HostUpdateHandoverResult,
    ReleaseName,
};

use super::inventory::Environment;
use crate::error::{CliError, Result};

/// How long a daemon is given to answer a connection.
const DAEMON_ANSWER: Duration = Duration::from_secs(5);

/// How long a daemon's process is given to end once it has been told to stop.
const DAEMON_STOP: Duration = Duration::from_secs(30);

/// How long a daemon of the new release is given to answer once it has been started.
pub const DAEMON_START: Duration = Duration::from_secs(60);

/// How long the install lock is waited for, which a control daemon holds, shared, while it starts.
pub const INSTALL_LOCK_WAIT: Duration = Duration::from_secs(30);

/// A daemon that has prepared to make way: its gate is closed for an attempt, and the connection
/// it answered on.
pub struct Prepared {
    /// What it said about how it was started.
    pub started_as: HostUpdateHandoverResult,
    /// The attempt it prepared under, which a stop or a resume of this update names.
    attempt: Uuid,
    client: LocalClient,
}

/// Asks an environment's daemon to prepare; `None` when no daemon listens there.
///
/// # Errors
///
/// Returns a refusal naming the environment when a daemon is there and does not prepare: one of
/// an earlier build, which does not know the handover, one that does not answer, and one whose
/// creates did not settle all refuse the update for now.
pub async fn prepare(environment: &Environment, target: &ReleaseName) -> Result<Option<Prepared>> {
    let endpoint = environment.paths.controller_endpoint()?;
    let connected = tokio::time::timeout(
        DAEMON_ANSWER,
        LocalClient::connect(&endpoint, LocalClientKind::Cli, crate::build_id()),
    )
    .await;
    let mut client = match connected {
        Ok(Ok(client)) => client,
        // Nothing listens: this environment has no daemon to hand over.
        Ok(Err(error)) if nothing_listening(&error) => return Ok(None),
        Ok(Err(error)) => {
            return Err(CliError::UpdateDeferred(shown!(
                "the control daemon of environment {} could not be reached: {}",
                environment.environment_id,
                Shown::ipc(&error)
            )));
        }
        Err(_) => {
            return Err(CliError::UpdateDeferred(shown!(
                "the control daemon of environment {} accepted the connection and did not answer \
                 within {} seconds",
                environment.environment_id,
                DAEMON_ANSWER.as_secs()
            )));
        }
    };
    let answered = step(
        &mut client,
        environment,
        target,
        HandoverStep::Prepare,
        None,
        Duration::from_millis(HANDOVER_SETTLE_MS) + DAEMON_ANSWER,
    )
    .await?;
    let attempt = answered.attempt.0.ok_or_else(|| {
        refusal(
            environment,
            Shown::said("its answer to prepare names no attempt"),
        )
    })?;
    Ok(Some(Prepared {
        started_as: answered,
        attempt,
        client,
    }))
}

/// What a daemon told to stop answers.
pub enum Stop {
    /// It was told, and whether it stops is what its lock says: it may end before its answer is
    /// written, so a lost answer is not a refusal.
    Told,
    /// It answered that it does not stop, and why: its attempt is over, its hold lapsed, or it
    /// was not prepared. It goes on serving, so nothing is waited for.
    Refused(Shown),
}

/// Tells a prepared daemon to stop, under the attempt it prepared.
pub async fn stop(mut prepared: Prepared, environment: &Environment, target: &ReleaseName) -> Stop {
    match ask(
        &mut prepared.client,
        environment,
        target,
        HandoverStep::Stop,
        Some(prepared.attempt),
        DAEMON_ANSWER,
    )
    .await
    {
        Asked::Refused(error) => Stop::Refused(Shown::protocol(&error)),
        Asked::Answered(_) | Asked::Lost(_) => Stop::Told,
    }
}

/// Tells a prepared daemon the update is not going ahead, so its attempt ends and its gate opens
/// again. A daemon that does not hear it opens its gate by itself when its hold lapses.
pub async fn resume(mut prepared: Prepared, environment: &Environment, target: &ReleaseName) {
    let _ = step(
        &mut prepared.client,
        environment,
        target,
        HandoverStep::Resume,
        Some(prepared.attempt),
        DAEMON_ANSWER,
    )
    .await;
}

/// What the daemon holding an environment says when it is asked to resume.
pub enum Resumed {
    /// It resumed: it serves, and no stop of the handover ends it.
    Serving,
    /// It has been told to stop, and is going.
    Stopping,
    /// Nothing listens at its endpoint: it is still starting, or it is going and has stopped
    /// listening.
    NotListening,
}

/// Asks the daemon that holds an environment to resume.
///
/// # Errors
///
/// Returns a failure naming the environment when the daemon answers neither way.
pub async fn resume_holder(environment: &Environment, target: &ReleaseName) -> Result<Resumed> {
    let endpoint = environment.paths.controller_endpoint()?;
    let connected = tokio::time::timeout(
        DAEMON_ANSWER,
        LocalClient::connect(&endpoint, LocalClientKind::Cli, crate::build_id()),
    )
    .await;
    let failed = |said: Shown| {
        CliError::Other(shown!(
            "the control daemon of environment {} did not say whether it goes on serving: {}",
            environment.environment_id,
            said
        ))
    };
    let mut client = match connected {
        Ok(Ok(client)) => client,
        Ok(Err(error)) if nothing_listening(&error) => return Ok(Resumed::NotListening),
        Ok(Err(error)) => return Err(failed(Shown::ipc(&error))),
        Err(_) => {
            return Err(failed(shown!(
                "it did not answer within {} seconds",
                DAEMON_ANSWER.as_secs()
            )));
        }
    };
    // No attempt is named: whichever is open ends, and it is not this run's to know which.
    let params = HostUpdateHandoverParams {
        step: HandoverStep::Resume,
        target: target.clone(),
        attempt: Nullable::null(),
    };
    let asked = tokio::time::timeout(
        DAEMON_ANSWER,
        client.mutate(
            Method::HostUpdateHandover,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment.environment_id),
            &params,
        ),
    )
    .await;
    match asked {
        Ok(Ok(Ok(_))) => Ok(Resumed::Serving),
        Ok(Ok(Err(error))) if error.code == ErrorCode::EnvironmentUnavailable => {
            Ok(Resumed::Stopping)
        }
        Ok(Ok(Err(error))) => Err(failed(Shown::protocol(&error))),
        Ok(Err(error)) => Err(failed(Shown::ipc(&error))),
        Err(_) => Err(failed(shown!(
            "it did not answer within {} seconds",
            DAEMON_ANSWER.as_secs()
        ))),
    }
}

/// The refusal that a daemon that does not make way is met with.
fn refusal(environment: &Environment, said: Shown) -> CliError {
    CliError::UpdateDeferred(shown!(
        "the control daemon of environment {} did not make way: {}",
        environment.environment_id,
        said
    ))
}

/// Takes the store's install lock, exclusively, waiting up to `within` for the control daemons
/// that hold it while they start.
///
/// This is the only way an update or an install takes the lock: it never waits without a bound.
/// `command` is the one to run again, `install` or `update`, when the wait runs out.
///
/// # Errors
///
/// Returns a refusal saying a control daemon is starting and holds the lock when `within` has
/// passed, and the failure to take it for any other reason.
pub async fn install_lock(
    store: &Store,
    within: Duration,
    command: &'static str,
) -> Result<kr_ipc::install::StoreLock> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match store.try_lock_install() {
            Ok(Some(lock)) => return Ok(lock),
            Ok(None) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok(None) => {
                return Err(CliError::UpdateDeferred(shown!(
                    "a control daemon of the store at {} is starting and has held its start lock \
                     for more than {} seconds; run kr host {} again once it has started or \
                     stopped",
                    Shown::root(store.root()),
                    within.as_secs(),
                    command
                )));
            }
            Err(error) => return Err(CliError::Other(super::said(&error))),
        }
    }
}

/// Whether a daemon holds an environment.
///
/// Asked under the store's install lock: a starting daemon holds that lock, shared, from its look
/// at `current` until it has taken its environment, so no daemon is part way through taking it
/// while this takes the environment's lock for a moment to see. The lock is waited for up to
/// `within`.
///
/// # Errors
///
/// Returns the refusal of [`install_lock`], and the failure to take the environment's lock for any
/// reason but a holder.
pub async fn held(store: &Store, environment: &Environment, within: Duration) -> Result<bool> {
    let _install = install_lock(store, within, "update").await?;
    match SingletonLock::hold(
        &environment.paths.singleton_lock(),
        environment.environment_id,
    ) {
        Ok(_) => Ok(false),
        Err(kr_controller::ControllerError::AlreadyRunning { .. }) => Ok(true),
        Err(error) => Err(CliError::Other(shown!(
            "environment {}'s lock could not be taken: {}",
            environment.environment_id,
            Shown::protocol(&error.to_protocol_error())
        ))),
    }
}

/// Waits up to [`DAEMON_STOP`] for the daemon holding an environment to have gone.
///
/// # Errors
///
/// Returns a failure naming the process the lock names when it has not gone by then.
pub async fn gone(store: &Store, environment: &Environment) -> Result<()> {
    let deadline = tokio::time::Instant::now() + DAEMON_STOP;
    while held(store, environment, INSTALL_LOCK_WAIT).await? {
        if tokio::time::Instant::now() >= deadline {
            return Err(CliError::Other(still_running(environment)));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

/// What a daemon answers to one step of the handover.
enum Asked {
    /// It took the step.
    Answered(HostUpdateHandoverResult),
    /// It refused the step, which is definite: it did not take it.
    Refused(kr_protocol::error::ProtocolError),
    /// No answer arrived, or one that is not a handover's: whether it took the step is not known.
    Lost(Shown),
}

/// Asks one step of the handover on a daemon's connection, for `attempt` where the step names one,
/// bounded by `within`.
async fn ask(
    client: &mut LocalClient,
    environment: &Environment,
    target: &ReleaseName,
    step: HandoverStep,
    attempt: Option<Uuid>,
    within: Duration,
) -> Asked {
    let params = HostUpdateHandoverParams {
        step,
        target: target.clone(),
        attempt: Nullable(attempt),
    };
    let asked = tokio::time::timeout(
        within,
        client.mutate(
            Method::HostUpdateHandover,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment.environment_id),
            &params,
        ),
    )
    .await;
    match asked {
        Ok(Ok(Ok(answer))) => match answer.to_typed() {
            Ok(answer) => Asked::Answered(answer),
            Err(error) => Asked::Lost(shown!(
                "its answer is not a handover's: {}",
                Shown::cbor(&error)
            )),
        },
        Ok(Ok(Err(error))) => Asked::Refused(error),
        Ok(Err(error)) => Asked::Lost(Shown::ipc(&error)),
        Err(_) => Asked::Lost(shown!(
            "it did not answer within {} seconds",
            within.as_secs()
        )),
    }
}

/// Takes one step of the handover, and refuses the update, for now, when the daemon does not.
async fn step(
    client: &mut LocalClient,
    environment: &Environment,
    target: &ReleaseName,
    step: HandoverStep,
    attempt: Option<Uuid>,
    within: Duration,
) -> Result<HostUpdateHandoverResult> {
    match ask(client, environment, target, step, attempt, within).await {
        Asked::Answered(answer) => Ok(answer),
        Asked::Refused(error) => Err(refusal(environment, Shown::protocol(&error))),
        Asked::Lost(said) => Err(refusal(environment, said)),
    }
}

/// Takes an environment's lock: once its daemon's process has gone, waiting up to [`DAEMON_STOP`],
/// where the update `told_to_stop` its daemon, and at once where it told none.
///
/// # Errors
///
/// Returns a refusal naming the process the lock names when a daemon the update stopped has not
/// gone by then, and one saying a daemon holds the environment where the update stopped none: it
/// started after the update asked each daemon to make way, or was not listening then, and was
/// never asked.
pub async fn hold(environment: &Environment, told_to_stop: bool) -> Result<SingletonLock> {
    let path = environment.paths.singleton_lock();
    let deadline = tokio::time::Instant::now()
        + if told_to_stop {
            DAEMON_STOP
        } else {
            Duration::ZERO
        };
    loop {
        match SingletonLock::hold(&path, environment.environment_id) {
            Ok(held) => return Ok(held),
            Err(kr_controller::ControllerError::AlreadyRunning { .. })
                if tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(kr_controller::ControllerError::AlreadyRunning { .. }) if told_to_stop => {
                return Err(CliError::UpdateDeferred(still_running(environment)));
            }
            Err(kr_controller::ControllerError::AlreadyRunning { .. }) => {
                return Err(CliError::UpdateDeferred(shown!(
                    "a control daemon holds environment {}, and it was not listening when the \
                     update asked each daemon to make way",
                    environment.environment_id
                )));
            }
            Err(error) => {
                return Err(CliError::Other(shown!(
                    "environment {}'s lock could not be taken: {}",
                    environment.environment_id,
                    Shown::protocol(&error.to_protocol_error())
                )));
            }
        }
    }
}

/// What a daemon that is still there says: the process its lock names, and how to stop it.
#[must_use]
pub fn still_running(environment: &Environment) -> Shown {
    match SingletonLock::holder(&environment.paths.singleton_lock()) {
        Ok(Some(pid)) => shown!(
            "the control daemon of environment {} (process {}) is still running and does not \
             answer; stop it with `kill {}` and run kr host update again",
            environment.environment_id,
            pid,
            pid
        ),
        _ => shown!(
            "the control daemon of environment {} is still running and does not answer; stop it \
             and run kr host update again",
            environment.environment_id
        ),
    }
}

/// Waits up to [`DAEMON_START`] for an environment's daemon to answer as a daemon of `target`.
///
/// `started` is the process this run started to be that daemon, where it started one: once it has
/// ended and no other daemon holds the environment, nothing is going to answer, and the wait ends
/// there. Whether another holds it is asked as [`held`] asks, so the look refuses no daemon that
/// is starting.
///
/// # Errors
///
/// Returns a failure naming what answered instead, or that nothing did.
pub async fn answers_as(
    store: &Store,
    environment: &Environment,
    target: &ReleaseName,
    mut started: Option<&mut std::process::Child>,
) -> Result<()> {
    let endpoint = environment.paths.controller_endpoint()?;
    let expected = format!("kr-controller/{target}");
    let deadline = tokio::time::Instant::now() + DAEMON_START;
    loop {
        let connected = tokio::time::timeout(
            DAEMON_ANSWER,
            LocalClient::connect(&endpoint, LocalClientKind::Cli, crate::build_id()),
        )
        .await;
        if let Ok(Ok(client)) = connected {
            let stated = client
                .acknowledgement()
                .build
                .as_ref()
                .map(|build| build.build_id.clone());
            if stated
                .as_ref()
                .is_some_and(|build_id| build_id.as_str() == expected)
            {
                return Ok(());
            }
            return Err(CliError::Other(shown!(
                "the control daemon of environment {} answers as {}, not as a daemon of {}",
                environment.environment_id,
                stated.as_ref().map_or_else(
                    || Shown::said("a build that states none"),
                    |build_id| shown!("{}", crate::shown::build_name(build_id))
                ),
                crate::shown::release(target)
            )));
        }
        if let Some(child) = started.as_deref_mut()
            && let Ok(Some(status)) = child.try_wait()
        {
            if !held(store, environment, INSTALL_LOCK_WAIT).await? {
                let how = match (
                    status.code(),
                    std::os::unix::process::ExitStatusExt::signal(&status),
                ) {
                    (Some(code), _) => shown!("with exit code {}", code),
                    (None, Some(signal)) => shown!("on signal {}", signal),
                    (None, None) => Shown::said("for a reason its status does not say"),
                };
                return Err(CliError::Other(shown!(
                    "the control daemon of environment {} ended {} before it answered; what it \
                     wrote is in its log in {}",
                    environment.environment_id,
                    how,
                    Shown::root(environment.paths.state_dir())
                )));
            }
            // Another daemon holds the environment, which is why this one ended: that one is
            // waited for.
            started = None;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(CliError::Other(shown!(
                "the control daemon of environment {} did not answer within {} seconds of its \
                 start; what it writes is in its log in {}",
                environment.environment_id,
                DAEMON_START.as_secs(),
                Shown::root(environment.paths.state_dir())
            )));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Whether a connection's failure means nothing listens at the endpoint at all.
fn nothing_listening(error: &kr_ipc::IpcError) -> bool {
    match error {
        kr_ipc::IpcError::Socket { source, .. } | kr_ipc::IpcError::Io { source, .. } => matches!(
            source.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
        ),
        _ => false,
    }
}
