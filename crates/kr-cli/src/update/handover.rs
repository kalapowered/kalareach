//! Handing each environment's control daemon over to the release an update installs, and starting
//! that release's daemon as the one it replaces was started.
//!
//! A daemon is asked through its own door, `host.update.handover`: to prepare, which closes its
//! gate to new sessions and waits for the creates it has started, and then to stop, or to resume
//! when the update is not going ahead. Its answer to `prepare` says how it was started, and that
//! is recorded before it is told to stop. The environment is known to be free once its singleton
//! lock can be taken, which the kernel gives up only when the daemon's process has gone.

use std::time::Duration;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_controller::singleton::SingletonLock;
use kr_ipc::client::LocalClient;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::ActionId;
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
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

/// A daemon that has prepared to make way: its gate is closed, and the connection it answered on.
pub struct Prepared {
    /// What it said about how it was started.
    pub started_as: HostUpdateHandoverResult,
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
        Duration::from_millis(HANDOVER_SETTLE_MS) + DAEMON_ANSWER,
    )
    .await?;
    Ok(Some(Prepared {
        started_as: answered,
        client,
    }))
}

/// Tells a prepared daemon to stop. Its answer is not waited for: the daemon may end before it
/// is written, and whether it has stopped is what its lock says.
pub async fn stop(mut prepared: Prepared, environment: &Environment, target: &ReleaseName) {
    let _ = step(
        &mut prepared.client,
        environment,
        target,
        HandoverStep::Stop,
        DAEMON_ANSWER,
    )
    .await;
}

/// Tells a prepared daemon the update is not going ahead, so its gate opens again. A daemon that
/// does not hear it opens its gate by itself when its hold lapses.
pub async fn resume(mut prepared: Prepared, environment: &Environment, target: &ReleaseName) {
    let _ = step(
        &mut prepared.client,
        environment,
        target,
        HandoverStep::Resume,
        DAEMON_ANSWER,
    )
    .await;
}

/// Takes one step of the handover on a daemon's connection, bounded by `within`.
async fn step(
    client: &mut LocalClient,
    environment: &Environment,
    target: &ReleaseName,
    step: HandoverStep,
    within: Duration,
) -> Result<HostUpdateHandoverResult> {
    let params = HostUpdateHandoverParams {
        step,
        target: target.clone(),
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
    let refused = |said: Shown| {
        CliError::UpdateDeferred(shown!(
            "the control daemon of environment {} did not make way: {}",
            environment.environment_id,
            said
        ))
    };
    match asked {
        Ok(Ok(Ok(answer))) => answer.to_typed().map_err(|error| {
            refused(shown!(
                "its answer is not a handover's: {}",
                Shown::cbor(&error)
            ))
        }),
        Ok(Ok(Err(error))) => Err(refused(Shown::protocol(&error))),
        Ok(Err(error)) => Err(refused(Shown::ipc(&error))),
        Err(_) => Err(refused(shown!(
            "it did not answer within {} seconds",
            within.as_secs()
        ))),
    }
}

/// Takes an environment's lock once its daemon's process has gone, waiting up to [`DAEMON_STOP`].
///
/// # Errors
///
/// Returns a refusal naming the process the lock names when the daemon has not gone by then.
pub async fn hold(environment: &Environment) -> Result<SingletonLock> {
    let path = environment.paths.singleton_lock();
    let deadline = tokio::time::Instant::now() + DAEMON_STOP;
    loop {
        match SingletonLock::hold(&path, environment.environment_id) {
            Ok(held) => return Ok(held),
            Err(kr_controller::ControllerError::AlreadyRunning { .. })
                if tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(kr_controller::ControllerError::AlreadyRunning { .. }) => {
                return Err(CliError::UpdateDeferred(still_running(environment)));
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
/// # Errors
///
/// Returns a failure naming what answered instead, or that nothing did.
pub async fn answers_as(environment: &Environment, target: &ReleaseName) -> Result<()> {
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
