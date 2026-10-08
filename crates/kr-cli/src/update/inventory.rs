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

use super::Unreached;
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

/// What looking for the environments a store's daemons have served found.
pub struct Surveyed {
    /// Every environment whose state is still there, in the order of their identities: the order
    /// their locks are taken in.
    pub environments: Vec<Environment>,
    /// The roots the store records whose environment could not be looked at.
    pub unreached: Vec<Unreached>,
    /// The state root of every pair the store records through which an environment was found, and
    /// the environment: several pairs, spelled differently, can name one.
    pub reached: Vec<(std::path::PathBuf, EnvironmentId)>,
}

/// What a failure to look at an environment's identity says, when it says that what holds the
/// identity is gone: a directory above it is not a directory, the file system behind it is stale,
/// or its device or address is not there. Any other failure says nothing of the kind, and an
/// environment whose daemon may be running is never passed over for it.
fn what_holds_it_is_gone(error: &kr_ipc::IpcError) -> Option<&std::io::Error> {
    let kr_ipc::IpcError::Io { source, .. } = error else {
        return None;
    };
    let gone = source.kind() == std::io::ErrorKind::NotFound
        || source.raw_os_error().is_some_and(|code| {
            [libc::ENOTDIR, libc::ESTALE, libc::ENODEV, libc::ENXIO].contains(&code)
        });
    gone.then_some(source)
}

/// Every environment the store's daemons have served whose state is still there, in the order of
/// their identities: the order their locks are taken in, and the roots of those whose state is
/// not: a stopped distribution, a removed container, a mount that is gone.
///
/// An environment is passed over only when what holds its identity is gone, which is also what a
/// removed environment looks like. An identity that is there and cannot be trusted, or cannot be
/// looked at for any other reason, stops the update: that environment may have a daemon running.
///
/// # Errors
///
/// Returns the failure to read the store's record of roots or an environment's identity.
pub fn environments(store: &Store) -> Result<Surveyed> {
    let mut environments: Vec<Environment> = Vec::new();
    let mut unreached = Vec::new();
    let mut reached = Vec::new();
    for roots in store
        .recorded_roots()
        .map_err(|error| CliError::Other(super::said(&error)))?
    {
        let host = HostPaths::new(&roots.runtime_root, &roots.state_root)?;
        let not_reached = |reason: Shown| Unreached {
            runtime_root: roots.runtime_root.clone(),
            state_root: roots.state_root.clone(),
            reason,
        };
        let environment_id = match host.recorded_environment_id() {
            Ok(Some(environment_id)) => environment_id,
            Ok(None) => {
                unreached.push(not_reached(Shown::said(
                    "no environment identity is recorded there",
                )));
                continue;
            }
            Err(error) => match what_holds_it_is_gone(&error) {
                Some(source) => {
                    unreached.push(not_reached(shown!(
                        "its environment identity could not be looked at: {}",
                        Shown::io(source)
                    )));
                    continue;
                }
                None => return Err(error.into()),
            },
        };
        reached.push((roots.state_root.clone(), environment_id));
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
    Ok(Surveyed {
        environments,
        unreached,
        reached,
    })
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

/// Brings the registry of an environment whose daemon has not run since an earlier schema step
/// forward to the schema this release reads, which is the schema [`classify`] reads one by, and says
/// what it did. The environment's daemon has stopped and its lock, and the store's install lock,
/// are held, so no daemon writes the registry or starts meanwhile.
///
/// It is the registry's own migration, the one a daemon's start runs, and nothing else: a registry
/// at the schema this release reads is not migrated, and one this cannot bring forward, because it
/// records a later schema, no schema or several, or is not a file, is left for [`classify`]'s
/// reader to refuse in its own words. A registry that lost a table its records are read from is
/// refused here, by the table's name.
///
/// # Errors
///
/// Returns the failure to read the registry or to bring it forward, naming the environment, which
/// holds the update.
pub fn carry_forward(
    environment: &Environment,
) -> Result<Option<kr_controller::registry::Carried>> {
    Registry::bring_forward(
        environment.paths.registry_database(),
        environment.environment_id,
    )
    .map_err(|error| {
        CliError::Other(shown!(
            "environment {}'s registry could not be read or brought forward: {}. The update \
             switched nothing; run kr host update again once the cause is dealt with",
            environment.environment_id,
            Shown::protocol(&error.to_protocol_error())
        ))
    })
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
    if !has_registry(environment)? {
        return Ok(Vec::new());
    }
    let database = environment.paths.registry_database();
    // What a daemon that ended by a signal left in its log is taken into the file first, as its own
    // clean stop would have: the environment's lock is held, so nothing writes meanwhile.
    Registry::take_in_its_log(&database).map_err(|error| unreadable(environment, &error))?;
    classify_in(environment, target, &database).await
}

/// Classes every record of an environment's registry for a rollback to `target`, as [`classify`]
/// does, from a private copy of the registry that is brought to the schema this release reads, and
/// returns what holds the rollback.
///
/// The registry itself is read and not changed, not even to take in a log: a rollback goes to a
/// release older than the one now current, which reads a registry no newer than its own schema,
/// so bringing the registry forward to this release's would put it out of that release's reach. The
/// copy is what the registry would be if a daemon of this release had started in the environment, and
/// holds the same records, so a worker the registry names that no daemon of this release has met is
/// classed all the same. The copy goes when this returns.
///
/// # Errors
///
/// Returns the failure to copy the registry, to bring the copy forward or to read it.
pub async fn classify_apart(
    environment: &Environment,
    target: &ReleaseManifest,
) -> Result<Vec<Holding>> {
    if !has_registry(environment)? {
        return Ok(Vec::new());
    }
    let original = environment.paths.registry_database();
    let Some(copy) = ApartRegistry::of(environment, &original)? else {
        // Not a regular file: the reader refuses it in its own words, before it opens anything.
        return classify_in(environment, target, &original).await;
    };
    let database = copy.database();
    Registry::bring_forward(&database, environment.environment_id)
        .map_err(|error| unreadable(environment, &error))?;
    classify_in(environment, target, &database).await
}

/// What a failure to read an environment's registry says.
fn unreadable(environment: &Environment, error: &kr_controller::ControllerError) -> CliError {
    CliError::Other(shown!(
        "environment {}'s registry could not be read: {}",
        environment.environment_id,
        Shown::protocol(&error.to_protocol_error())
    ))
}

/// A private copy of an environment's registry, with the log or journal beside it, which goes when
/// the copy does.
struct ApartRegistry {
    directory: std::path::PathBuf,
}

impl Drop for ApartRegistry {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

impl ApartRegistry {
    /// Copies the registry at `original`; `None` where it is not a regular file.
    fn of(environment: &Environment, original: &std::path::Path) -> Result<Option<Self>> {
        let failed = |what: &'static str, error: &std::io::Error| {
            CliError::Other(shown!(
                "environment {}'s registry could not be copied to be read: {} {}",
                environment.environment_id,
                what,
                Shown::io(error)
            ))
        };
        match std::fs::symlink_metadata(original) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Ok(None),
            Err(error) => return Err(failed("it could not be looked at:", &error)),
        }
        let directory = std::env::temp_dir().join(format!("kr-registry-{}", kr_ipc::new_uuid()));
        let copy = Self { directory };
        kr_ipc::paths::create_private_tree(&copy.directory, &copy.directory).map_err(|error| {
            CliError::Other(shown!(
                "environment {}'s registry could not be copied to be read: no directory could be \
                 made for the copy: {}",
                environment.environment_id,
                Shown::ipc(&error)
            ))
        })?;
        std::fs::copy(original, copy.database())
            .map_err(|error| failed("the file could not be copied:", &error))?;
        for suffix in ["-wal", "-journal"] {
            let mut beside = original.as_os_str().to_owned();
            beside.push(suffix);
            let beside = std::path::PathBuf::from(beside);
            match std::fs::symlink_metadata(&beside) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(metadata) if metadata.is_file() => {
                    let mut named = copy.database().as_os_str().to_owned();
                    named.push(suffix);
                    std::fs::copy(&beside, &named).map_err(|error| {
                        failed("what is beside it could not be copied:", &error)
                    })?;
                }
                Ok(_) => {
                    return Err(CliError::Other(shown!(
                        "environment {}'s registry has beside it something that is not a regular file, {}",
                        environment.environment_id,
                        Shown::root(&beside)
                    )));
                }
                Err(error) => {
                    return Err(failed("what is beside it could not be looked at:", &error));
                }
            }
        }
        Ok(Some(copy))
    }

    /// Where the copy of the registry is.
    fn database(&self) -> std::path::PathBuf {
        self.directory.join("registry.sqlite")
    }
}

/// Classes the records of the registry at `database`, which is the environment's or a copy of it,
/// and has been brought to the schema this release reads, if it was to be.
async fn classify_in(
    environment: &Environment,
    target: &ReleaseManifest,
    database: &std::path::Path,
) -> Result<Vec<Holding>> {
    let (spawned, running, workers) = {
        let registry =
            Registry::open_to_read(database, environment.environment_id).map_err(|error| {
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

/// Whether an environment has a registry to read.
///
/// Only its being there is looked at: the reader ([`Registry::open_to_read`]) refuses one that is
/// not a regular file, and one that is a link, before it opens anything, so a pipe there holds
/// nothing up, and reads it as it is, with nothing made beside it, once a log that a daemon ended
/// by a signal left has been taken in ([`Registry::take_in_its_log`]).
///
/// # Errors
///
/// Returns the failure to look at it.
fn has_registry(environment: &Environment) -> Result<bool> {
    match std::fs::symlink_metadata(environment.paths.registry_database()) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(CliError::Other(shown!(
            "environment {}'s registry could not be looked at: {}",
            environment.environment_id,
            Shown::io(&error)
        ))),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// An environment's registry is looked for before it is read: none is none, and one that is a
    /// pipe or a link is there, and the reader refuses it at once without opening it, where a plain
    /// open of a pipe would have waited for a writer.
    #[test]
    fn a_registry_that_is_a_pipe_or_a_link_is_refused_by_the_reader_and_not_waited_for() {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = Environment {
            environment_id: temp.environment_id(),
            paths: temp.environment(),
            host: temp.paths().clone(),
        };
        let registry = environment.paths.registry_database();
        assert!(!has_registry(&environment).expect("looks"), "none");
        let made = std::process::Command::new("mkfifo")
            .arg(&registry)
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "a pipe is made");
        assert!(
            has_registry(&environment).expect("looks"),
            "a pipe is there"
        );
        // On a thread of its own, so that a wait for a writer fails the test and does not hang it.
        let read = |path: std::path::PathBuf, id: EnvironmentId| {
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = sender.send(Registry::open_to_read(&path, id).is_err());
            });
            receiver
                .recv_timeout(Duration::from_secs(20))
                .expect("the reader was not held up by a pipe")
        };
        assert!(
            read(registry.clone(), environment.environment_id),
            "a pipe is refused"
        );
        let pipe = registry.with_file_name("pipe");
        std::fs::rename(&registry, &pipe).expect("moved");
        std::os::unix::fs::symlink(&pipe, &registry).expect("a link");
        assert!(
            read(registry.clone(), environment.environment_id),
            "a link to a pipe is refused"
        );
        // The control: a registry that the daemon made is read.
        std::fs::remove_file(&registry).expect("the link goes");
        drop(Registry::open(&registry, environment.environment_id).expect("a registry"));
        assert!(
            !read(registry, environment.environment_id),
            "a registry of its own is read"
        );
    }

    /// An environment is passed over, and named, only when its identity cannot be looked at because
    /// what holds it is gone. Every other failure may be an environment whose daemon runs, and stops
    /// the update.
    #[test]
    fn only_a_failure_that_says_what_holds_an_identity_is_gone_passes_an_environment_over() {
        let path = std::path::Path::new("/state/environment-id");
        let failed =
            |code: i32| kr_ipc::IpcError::io("open", path, std::io::Error::from_raw_os_error(code));
        for gone in [libc::ENOTDIR, libc::ESTALE, libc::ENODEV, libc::ENXIO] {
            assert!(
                what_holds_it_is_gone(&failed(gone)).is_some(),
                "error {gone} says what holds it is gone"
            );
        }
        assert!(
            what_holds_it_is_gone(&kr_ipc::IpcError::io(
                "open",
                path,
                std::io::Error::from(std::io::ErrorKind::NotFound)
            ))
            .is_some(),
            "a name that is not there"
        );
        for other in [
            libc::EACCES,
            libc::EPERM,
            libc::EIO,
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOMEM,
            libc::EINTR,
            libc::ELOOP,
            libc::ETIMEDOUT,
        ] {
            assert!(
                what_holds_it_is_gone(&failed(other)).is_none(),
                "error {other} says nothing of the kind"
            );
        }
        for untrusted in [
            kr_ipc::IpcError::UntrustedFile {
                path: path.to_path_buf(),
                reason: "this file must not be a symbolic link",
            },
            kr_ipc::IpcError::IdentityUnavailable {
                what: "environment identity",
                detail: "the file is not text".to_owned(),
            },
        ] {
            assert!(
                what_holds_it_is_gone(&untrusted).is_none(),
                "{untrusted} is not an environment that is gone"
            );
        }
    }
}
