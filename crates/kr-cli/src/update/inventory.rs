//! The environments this store's control daemons have served, and the live workers in each: what
//! an update asks before it stops anything, and what it classes once every daemon has stopped.
//!
//! A worker is asked what it is the way `kr attach` asks: connected to as a command-line client and
//! challenged for the key its session was given, after which its answer to the hello says its build
//! and the protocol version it was built from. Nothing a worker is asked changes it.

use std::time::Duration;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_controller::registry::{LaunchPhase, Registry};
use kr_ipc::client::LocalClient;
use kr_ipc::identity::{ProcessState, process_state};
use kr_ipc::install::Store;
use kr_ipc::paths::{EnvironmentPaths, HostPaths};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::local::{LocalBuild, LocalClientKind};
use kr_protocol::session::DisplayNumber;
use kr_protocol::update::ReleaseManifest;

use crate::error::{CliError, Result};

/// How long one worker is given to answer its connection and its challenge.
const WORKER_ANSWER: Duration = Duration::from_secs(5);

/// One environment a daemon of this store has served, whose state is still there.
pub struct Environment {
    /// Its identity.
    pub environment_id: EnvironmentId,
    /// Its directories.
    pub paths: EnvironmentPaths,
    /// The roots the daemon was started with.
    pub host: HostPaths,
}

/// Every environment the store's daemons have served whose state is still there, in the order of
/// their identities: the order their locks are taken in.
///
/// # Errors
///
/// Returns the failure to read the store's record of roots or an environment's identity.
pub fn environments(store: &Store) -> Result<Vec<Environment>> {
    let mut environments: Vec<Environment> = Vec::new();
    for roots in store
        .recorded_roots()
        .map_err(|error| CliError::Other(super::said(&error)))?
    {
        let host = HostPaths::new(&roots.runtime_root, &roots.state_root)?;
        let Some(environment_id) = host.recorded_environment_id()? else {
            continue;
        };
        if environments
            .iter()
            .any(|known| known.environment_id == environment_id)
        {
            continue;
        }
        environments.push(Environment {
            environment_id,
            paths: host.environment(environment_id),
            host,
        });
    }
    environments.sort_by_key(|environment| environment.environment_id.to_string());
    Ok(environments)
}

/// What one live worker says it is.
pub struct Stated {
    /// Its session's display number.
    pub display: DisplayNumber,
    /// Its build, or `None` for a build before its build was stated.
    pub build: Option<LocalBuild>,
}

/// What an update meets that holds it: a worker at a level the new release does not retain, one
/// that does not answer and has not ended, or a session still being started.
pub enum Holding {
    /// A worker of a build the new release's daemon cannot speak to.
    Unretained(Stated),
    /// A worker that did not answer its challenge and has not ended.
    Silent(DisplayNumber),
    /// A launch the daemon handed to the service manager, still under way.
    Starting(DisplayNumber),
}

impl Holding {
    /// What an update waiting for this says, for `target`.
    #[must_use]
    pub fn said(&self, target: &ReleaseManifest) -> Shown {
        let release = crate::shown::release(&target.release);
        match self {
            Self::Unretained(Stated {
                display,
                build: Some(build),
            }) => shown!(
                "session {} runs {} with protocol {}.{}.{}, which the control daemon of {} does \
                 not speak",
                display.get(),
                crate::shown::build_name(&build.build_id),
                build.protocol_version.major,
                build.protocol_version.minor,
                build.protocol_version.patch,
                release
            ),
            Self::Unretained(Stated {
                display,
                build: None,
            }) => shown!(
                "session {} runs a worker of a build that does not state its protocol version, \
                 which the control daemon of {} does not speak",
                display.get(),
                release
            ),
            Self::Silent(display) => shown!(
                "session {}'s worker did not answer its challenge and has not ended",
                display.get()
            ),
            Self::Starting(display) => shown!("session {} is still being started", display.get()),
        }
    }
}

/// Asks every worker an environment's descriptors name what it is, and stops nothing.
///
/// A worker that nothing answers for is passed over here: its descriptor may outlive it, and what
/// the registry says of it is read once the environment's daemon has stopped.
pub async fn described(environment: &EnvironmentPaths) -> Vec<Stated> {
    let Ok(entries) = kr_ipc::descriptor::read_all(environment) else {
        return Vec::new();
    };
    let mut stated = Vec::new();
    for entry in entries {
        let Ok(descriptor) = entry.descriptor else {
            continue;
        };
        let Ok(endpoint) = kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint) else {
            continue;
        };
        let asked = tokio::time::timeout(WORKER_ANSWER, async {
            let mut client =
                LocalClient::connect(&endpoint, LocalClientKind::Cli, crate::build_id()).await?;
            client.verify_worker(&descriptor).await?;
            Ok::<_, kr_ipc::IpcError>(client.acknowledgement().build.clone())
        })
        .await;
        if let Ok(Ok(build)) = asked {
            stated.push(Stated {
                display: descriptor.display_number,
                build,
            });
        }
    }
    stated
}

/// Classes every record of an environment's registry for an update to `target`, and returns what
/// holds the update. The environment's daemon has stopped and its lock is held.
///
/// A reservation nothing was handed to the service manager for holds nothing, and neither does a
/// launch with no recorded launcher or an ended one: the next daemon fails it before it serves its
/// rendezvous, so no late launch can claim it. Every other record whose session may be running,
/// a fenced one included, is challenged for its key: a worker at a level `target` retains holds
/// nothing, and one whose process the kernel says has ended holds nothing; anything else holds
/// the update.
///
/// # Errors
///
/// Returns the failure to read the registry.
pub async fn classify(environment: &Environment, target: &ReleaseManifest) -> Result<Vec<Holding>> {
    let database = environment.paths.registry_database();
    // Only a regular file is opened: a pipe under the registry's name would hold the update, which
    // holds the install lock, for as long as nothing wrote to it.
    match std::fs::symlink_metadata(&database) {
        Ok(about) if about.is_file() => {}
        Ok(_) => {
            return Err(CliError::Other(shown!(
                "environment {}'s registry is not a regular file",
                environment.environment_id
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(CliError::Other(shown!(
                "environment {}'s registry could not be read: {}",
                environment.environment_id,
                Shown::io(&error)
            )));
        }
    }
    let (spawned, running, workers) = {
        let registry =
            Registry::open_read_only(&database, environment.environment_id).map_err(|error| {
                CliError::Other(shown!(
                    "environment {}'s registry could not be read: {}",
                    environment.environment_id,
                    Shown::protocol(&error.to_protocol_error())
                ))
            })?;
        let read = |phase| {
            registry.reservations_in(phase).map_err(|error| {
                CliError::Other(shown!(
                    "environment {}'s registry could not be read: {}",
                    environment.environment_id,
                    Shown::protocol(&error.to_protocol_error())
                ))
            })
        };
        let spawned = read(LaunchPhase::Spawned)?;
        let mut running = read(LaunchPhase::Claimed)?;
        running.extend(read(LaunchPhase::Live)?);
        running.extend(read(LaunchPhase::Fenced)?);
        let workers = registry.workers().map_err(|error| {
            CliError::Other(shown!(
                "environment {}'s registry could not be read: {}",
                environment.environment_id,
                Shown::protocol(&error.to_protocol_error())
            ))
        })?;
        (spawned, running, workers)
    };
    let mut holding = Vec::new();
    for reservation in spawned {
        let under_way = reservation
            .launcher_identity
            .as_ref()
            .is_some_and(|identity| !ended(identity));
        if under_way {
            holding.push(Holding::Starting(reservation.display_number));
        }
    }
    for reservation in running {
        let worker = workers
            .iter()
            .find(|worker| worker.session_id == reservation.session_id);
        let key = worker
            .map(|worker| worker.public_key)
            .or(reservation.claimed_key);
        let endpoint = match worker {
            Some(worker) => kr_ipc::paths::Endpoint::from_path(&worker.endpoint).ok(),
            None => environment
                .paths
                .worker_endpoint(reservation.display_number)
                .ok(),
        };
        let answered = match (key, endpoint) {
            (Some(key), Some(endpoint)) => challenge(&endpoint, &key, reservation.session_id).await,
            _ => None,
        };
        match answered {
            Some(build)
                if build
                    .as_ref()
                    .is_some_and(|build| target.retains(build.protocol_version)) => {}
            Some(build) => holding.push(Holding::Unretained(Stated {
                display: reservation.display_number,
                build,
            })),
            None => {
                let process = worker
                    .map(|worker| &worker.process_identity)
                    .or(reservation.launcher_identity.as_ref());
                if !process.is_some_and(ended) {
                    holding.push(Holding::Silent(reservation.display_number));
                }
            }
        }
    }
    Ok(holding)
}

/// Whether the kernel says a recorded process has ended.
fn ended(identity: &ProcessStartIdentity) -> bool {
    matches!(process_state(identity), ProcessState::Ended)
}

/// Challenges a worker for the key its session was given, and returns what its answer to the hello
/// states about its build; `None` when it does not answer or does not prove the key.
async fn challenge(
    endpoint: &kr_ipc::paths::Endpoint,
    key: &kr_protocol::scalars::AuthorisationKey,
    session_id: SessionId,
) -> Option<Option<LocalBuild>> {
    let endpoint_text = endpoint.as_text();
    tokio::time::timeout(WORKER_ANSWER, async {
        let mut client =
            LocalClient::connect(endpoint, LocalClientKind::Cli, crate::build_id()).await?;
        client
            .challenge_worker(key, session_id, SessionEpoch::V1, &endpoint_text)
            .await?;
        Ok::<_, kr_ipc::IpcError>(client.acknowledgement().build.clone())
    })
    .await
    .ok()?
    .ok()
}
