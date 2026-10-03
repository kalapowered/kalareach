//! Creating a session: its admission, its launch, its presentation and a replayed create.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{ActorId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    EnvironmentVariable, Presentation, SessionCreateParams, SessionCreateResult,
};
use kr_protocol::worker::{ReservationId, WorkerReady};
use tokio::sync::oneshot;

use crate::error::{ControllerError, Result};
use crate::registry::LaunchPhase;
use crate::supervision::{LaunchOutcome, WorkerLaunch};

use super::admission::Door;
use super::{Controller, encode, parse};

/// What a caller is told when it asks for a desktop this host does not have.
const NO_DESKTOP_TO_BIND: &str = "this host has no graphical login session to bind a session to; create it in the headless \
     user profile instead";

/// How long a create waits for its worker to report itself.
pub const RENDEZVOUS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Whose environment a session is started with.
///
/// Decided by where the create came through, what the client says it is and what the session is
/// for, and never by whether the request carries variables: a client that sends none is not
/// asking for the host's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CreateOrigin {
    /// The command line's own environment, which it sends with a session it creates for a person
    /// to see: filtered for the terminal's identity and for reserved variables by the worker.
    CliSnapshot,
    /// The environment of the execution context this host runs in, which is what a session no
    /// person's shell stands behind is started with: one an app creates, one created invisibly,
    /// and one a paired device asks for, whose own environment is never used.
    HostContext,
}

impl CreateOrigin {
    /// Decides the origin of a create that came through `door`.
    ///
    /// # Errors
    ///
    /// A connection that declared itself the control daemon or a worker is not a source of
    /// sessions, and is refused.
    pub(super) fn decide(door: Door, create: &SessionCreateParams) -> Result<Self> {
        match door {
            Door::Local(LocalClientKind::Controller | LocalClientKind::Worker) => {
                Err(ControllerError::PermissionDenied {
                    detail: "a connection that declared itself the control daemon or a worker \
                             creates no session"
                        .to_owned(),
                })
            }
            // A session nobody sees takes the host's environment even from the command line: the
            // command line's own is the person's, for the sessions the person is shown.
            Door::Local(LocalClientKind::Cli) if create.presentation != Presentation::Invisible => {
                Ok(Self::CliSnapshot)
            }
            Door::Local(LocalClientKind::Cli | LocalClientKind::App) | Door::Network => {
                Ok(Self::HostContext)
            }
        }
    }
}

/// The names of a daemon's own environment that a session started with the host's environment
/// takes, besides the locale's.
const HOST_CONTEXT_NAMES: &[&str] = if cfg!(windows) {
    &[
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "USERNAME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "LANG",
        "TZ",
    ]
} else {
    &["PATH", "HOME", "USER", "LOGNAME", "LANG", "TZ", "TMPDIR"]
};

/// The prefix of the locale's variables, all of which are taken.
const LOCALE_PREFIX: &str = "LC_";

/// What of a daemon's own environment a session started with the host's environment takes.
///
/// An allowlist and not a filter: a daemon started from a terminal holds that terminal's exports,
/// a credential among them, a login's agent socket and the terminal's identity, and none of those
/// are the session's. What it takes is the person's path, their locale and who they are, which is
/// what a shell cannot start without. A name is compared as the platform compares it, and a
/// Windows name is kept in capitals, which is how the worker reads `PATH`.
pub(super) fn host_context_variables(
    environment: impl IntoIterator<Item = (String, String)>,
) -> Vec<EnvironmentVariable> {
    let mut taken: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (name, value) in environment {
        let name = if cfg!(windows) {
            name.to_ascii_uppercase()
        } else {
            name
        };
        if HOST_CONTEXT_NAMES.contains(&name.as_str()) || name.starts_with(LOCALE_PREFIX) {
            taken.insert(name, value);
        }
    }
    taken
        .into_iter()
        .map(|(name, value)| EnvironmentVariable { name, value })
        .collect()
}

/// The environment variables a session's creator sent, from the reservation to the worker's claim.
///
/// They are in this memory and nowhere else: the record of the request leaves them out, so a
/// credential among them is not on disk after the launch, or at all. The worker's claim takes them
/// once, to put them into its launch specification, and the create withdraws them when it stops
/// waiting for the worker; whichever takes them first decides which of the two has them.
pub(super) type CreatorEnvironment = Arc<std::sync::Mutex<Option<Vec<EnvironmentVariable>>>>;

/// A create that is waiting for its worker.
pub(super) struct PendingCreate {
    pub(super) ready: oneshot::Sender<std::result::Result<WorkerReady, ProtocolError>>,
    /// The creator's variables, until the claim of this create's worker takes them.
    pub(super) environment: CreatorEnvironment,
}

/// Takes what is in `slot`, and says whether the other party had already taken it.
///
/// It never waits for anything but the slot's own lock, which nobody holds across an await.
fn withdraw(slot: &CreatorEnvironment) -> bool {
    slot.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .is_none()
}

/// A create's wait for its worker, held from the moment the wait is registered until the create
/// ends, however it ends.
///
/// Where the create ends its wait it says so with [`Self::end_wait`]. Anywhere else, a return, a
/// panic or a future that is dropped, the drop does the same without waiting for anything.
pub(super) struct CreateHold {
    controller: Arc<Controller>,
    reservation_id: ReservationId,
    environment: CreatorEnvironment,
    /// Whether the wait has been ended and its entry removed.
    ended: bool,
}

impl CreateHold {
    /// Registers the wait for `reservation_id`'s worker and the variables its claim may take.
    pub(super) async fn open(
        controller: &Arc<Controller>,
        reservation_id: ReservationId,
        environment: Vec<EnvironmentVariable>,
        ready: oneshot::Sender<std::result::Result<WorkerReady, ProtocolError>>,
    ) -> Self {
        let environment: CreatorEnvironment = Arc::new(std::sync::Mutex::new(Some(environment)));
        controller.pending.lock().await.insert(
            reservation_id,
            PendingCreate {
                ready,
                environment: Arc::clone(&environment),
            },
        );
        Self {
            controller: Arc::clone(controller),
            reservation_id,
            environment,
            ended: false,
        }
    }

    /// Ends this create's wait, and says whether a worker's claim had already taken the variables.
    ///
    /// The variables are withdrawn first, before anything is awaited, so no claim can take them
    /// once the create has stopped waiting; only then is the entry removed. A claim that took them
    /// means a launch that may still complete, which the create's caller is told is not known.
    pub(super) async fn end_wait(&mut self) -> bool {
        let taken = withdraw(&self.environment);
        self.controller
            .pending
            .lock()
            .await
            .remove(&self.reservation_id);
        // Only once the entry is gone: a future dropped while it waits for the lock is a create
        // that has not removed it, and the drop does.
        self.ended = true;
        taken
    }
}

impl Drop for CreateHold {
    fn drop(&mut self) {
        withdraw(&self.environment);
        if self.ended {
            return;
        }
        // The entry goes now when its lock is free, and otherwise from a task that does not keep
        // this daemon alive. With no runtime to run one the entry goes with the daemon.
        match self.controller.pending.try_lock() {
            Ok(mut pending) => {
                pending.remove(&self.reservation_id);
            }
            Err(_) => {
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    let controller = Arc::downgrade(&self.controller);
                    let reservation_id = self.reservation_id;
                    runtime.spawn(async move {
                        if let Some(controller) = controller.upgrade() {
                            controller.pending.lock().await.remove(&reservation_id);
                        }
                    });
                }
            }
        }
    }
}

impl Controller {
    /// The environment a session started with the host's is given.
    fn host_context_environment(&self) -> Vec<EnvironmentVariable> {
        self.host_environment
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Refuses a managed create whose shell no installed package qualifies.
    ///
    /// Reserves a session and starts its worker.
    ///
    /// `connection_id` is the connection that asked, on whichever ingress. A create is the one
    /// mutation this daemon performs itself and the slowest thing it does: it writes the
    /// reservation, waits for a lock, starts a process and waits for that process to report
    /// itself. The connection identity travels with it so the registration behind it can be
    /// checked again at the moment the launch becomes possible, rather than only when the request
    /// arrived.
    pub(super) async fn session_create(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        // Through the gate first, and counted until this create has settled: a daemon making way
        // for an update of the host starts nothing new, and waits for what it has started.
        let _under_way = self.handover.admit()?;
        let mut create: SessionCreateParams = parse(&mutation.params)?;
        // Before the reservation, because this is a request that can never be served rather than
        // one this environment happens to have no room for. The palette travels to the worker in
        // the launch specification and is recorded there; what cannot travel is a provenance
        // nothing measured.
        if let Some(refusal) = create.palette_refusal() {
            return Err(ControllerError::InvalidArgument(refusal));
        }
        // A session's command integrations are its environment's: the configuration turns them on
        // and the host fills them in when the session is launched. A request that could name one
        // could turn on an integration the owner did not.
        if !create.launch_profile.command_integrations.is_empty() {
            return Err(ControllerError::InvalidArgument(
                "a create request names no command integration: a session applies the ones its \
                 environment's configuration turns on"
                    .to_owned(),
            ));
        }
        // Whose environment the session is started with, from where the create came through. A
        // connection that is no longer registered has no door and no create.
        let door = self.door_of(carried.connection_id).ok_or_else(|| {
            ControllerError::PermissionDenied {
                detail: "the authority this connection was admitted under has been withdrawn; \
                         open a new connection"
                    .to_owned(),
            }
        })?;
        let origin = CreateOrigin::decide(door, &create)?;
        if origin == CreateOrigin::HostContext && !create.environment_snapshot.is_empty() {
            // Said, and not ignored: a client that sends variables to a session that takes none of
            // them would think they had been used. Nothing of them is repeated here.
            return Err(ControllerError::InvalidArgument(
                "this session is started with this host's environment, so its request carries no \
                 environment variables"
                    .to_owned(),
            ));
        }
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        // The environment the session is started with is for the worker's launch and for nothing
        // else: held in memory until the worker claims it, and never written down. A create that
        // sends its own has it taken out of the request here, and the digest above covers it, as a
        // hash; any other takes the host's.
        let environment = match origin {
            CreateOrigin::CliSnapshot => std::mem::take(&mut create.environment_snapshot),
            CreateOrigin::HostContext => self.host_context_environment(),
        };
        // The create request itself is recorded with the reservation, before anything is spawned.
        // A daemon that dies between the reservation and the launch then finds a request it can
        // resolve rather than an identifier with nothing behind it.
        let intent = kr_cbor::to_canonical_vec(&create)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        // The action identifier is the create token. One identifier, one session; a retry with the
        // same payload resolves to the same reservation rather than launching a second shell.
        // A managed session needs a KalaReach-qualified shell package, and this is the one place
        // every ingress passes through: the local endpoint reaches it through its own dispatch and
        // a caller on the network reaches it directly. The answer is worked out here, before the
        // registry is locked, because finding a package reads directories and opens files and a
        // filesystem that answers slowly must not hold up every other request in this environment.
        // Finding a package reads directories and opens files, which is work for a thread that may
        // block: a package root on a filesystem that has stopped answering would otherwise occupy
        // one of the runtime's own threads until the platform gave up on it.
        let qualified = match create.shell_mode {
            kr_protocol::session::ShellMode::Managed => {
                let root = self.shell_packages.clone();
                let requested = create.shell.0.clone();
                Some(
                    tokio::task::spawn_blocking(move || {
                        qualified_package(root.as_deref(), requested.as_deref())
                    })
                    .await
                    .map_err(|error| ControllerError::supervision(error.to_string()))?,
                )
            }
            kr_protocol::session::ShellMode::NativeCompat => None,
        };
        let admission = {
            let mut registry = self.registry.lock().await;
            // The token is looked at under the same lock the reservation is taken under, and the
            // refusal above is applied only to a token this registry has never seen. A create this
            // actor already made is a retry, and section 9 says a retry is answered from what its
            // first attempt produced; refusing one because the package went away in between would
            // be refusing an action that already has an outcome.
            let known = registry
                .reservation_for_token(actor_id, mutation.action_id.get())?
                .is_some();
            if !known && let Some(qualified) = qualified {
                // Nothing is reserved and nothing is spawned before this, so an unsupported shell
                // costs the caller a named error rather than a session that closes itself a moment
                // later.
                let _resolved = qualified?;
            }
            registry.reserve(
                actor_id,
                mutation.action_id.get(),
                digest,
                &intent,
                kr_ipc::now_ms(),
            )?
        };
        let reservation = admission.reservation;
        if admission.deduplicated {
            // A repeated token resolves to the session it already created, whatever this host's
            // conditions are now. A desktop that has gone since is a reason not to start a new
            // session rather than a reason to withhold the answer about one that already exists.
            return self.replay_create(&reservation).await;
        }

        // A desktop-bound session needs a desktop, and this host does not manufacture one: an SSH
        // connection is a transport rather than a graphical login, and a request bound to a
        // desktop that is not there would be given a session bound to nothing. The desktop's own
        // environment is collected in the same breath, because both are conversations with the
        // platform and neither may happen after the deadline below is checked.
        let desktop_environment = if create.worker_profile == WorkerProfile::DesktopBound {
            let (desktop, _) = self.desktop().await;
            if !desktop.is_desktop() || !desktop.graphic_access {
                let mut registry = self.registry.lock().await;
                registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                drop(registry);
                return Err(ControllerError::NotConfigured(
                    NO_DESKTOP_TO_BIND.to_owned(),
                ));
            }
            // The session this host just read its desktop from, so the worker is started on the
            // desktop this host describes rather than on another login of the same user.
            crate::desktop::agent::environment(
                create.worker_profile,
                desktop.platform_session.as_ref().map(String::as_str),
            )
        } else {
            Vec::new()
        };

        let (sender, receiver) = oneshot::channel();
        let mut hold =
            CreateHold::open(self, reservation.reservation_id, environment, sender).await;

        // Everything the launch needs is prepared before the checks that admit it, so nothing
        // between the last check and the launch can wait: a directory tree is several filesystem
        // operations, and a slow disk would otherwise spend the rest of an accepted deadline here.
        // The directory is inside this environment's state directory, which this daemon owns and
        // which holds nothing a person keeps.
        let working_directory = self.paths.worker_dir(reservation.session_id);
        if let Err(error) =
            kr_ipc::paths::create_private_tree(self.paths.state_root(), &working_directory)
        {
            // Nothing was started, so the reservation is resolved as a confirmed failure and stops
            // occupying the environment.
            hold.end_wait().await;
            self.resolve_failed(reservation.reservation_id).await?;
            return Err(error.into());
        }

        // The session owes its cleanup from the moment its worker is asked for, if privacy mode is
        // on, and the worker is told the privacy state in its launch specification: the obligation
        // is on the disk before anything is started, so turning privacy mode off waits for the
        // session from here. This waits for everything that holds the privacy record, a change of
        // privacy mode among it, which can be for as long as that change waits for the deliveries
        // on the wire. So it comes before the critical section below, whose deadline and
        // registration are read as the last thing before the launch and must not be read before a
        // wait; and it holds neither the registry nor the pending map. A launch refused here
        // started nothing and has recorded nothing owed.
        let privacy = Arc::clone(&self.privacy);
        let session_id = reservation.session_id;
        let noted = tokio::task::spawn_blocking(move || {
            privacy.note_session_launching(session_id, kr_ipc::now_ms())
        })
        .await;
        if let Err(error) = noted
            .map_err(|error| ControllerError::supervision(error.to_string()))
            .and_then(|noted| noted)
        {
            hold.end_wait().await;
            self.resolve_failed(reservation.reservation_id).await?;
            return Err(error);
        }

        // The reservation moves to `spawned` before anything is started. A worker can reach the
        // rendezvous socket the instant the service manager starts it, which is sooner than the
        // launcher returns, and a reservation still recorded as merely reserved would fence its own
        // worker. The deadline the host accepted and the registration behind the request are both
        // checked in the same critical section, and after the durable write rather than before it:
        // everything from there to the launch runs without waiting for anything, so neither an
        // action whose life ran out queueing for this lock nor one whose authority was withdrawn
        // while it queued goes on to start a shell.
        //
        // The registration is read with the registry lock already held, which is the order a
        // revocation takes: a revocation that has installed its revision has already withdrawn the
        // registrations that revision replaced, so what this reads is never a registration the
        // revocation is part way through removing.
        {
            let mut registry = self.registry.lock().await;
            registry.set_phase(reservation.reservation_id, LaunchPhase::Spawned)?;
            // The admission this create carries, against the registry this guard holds: the
            // authority revision it was admitted under, the registration behind it, and the
            // deadline, in that order. The registration is read with the registry lock already
            // held, which is the order a revocation takes, and the clock is read last, so the last
            // thing between this create and its launch is a reading with nothing left to wait for.
            if let Err(refusal) = self.check_admission(&registry, &carried) {
                // Nothing was started, so the reservation is resolved as a confirmed failure and
                // stops occupying the environment. The caller is told which of the two it was.
                registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                drop(registry);
                hold.end_wait().await;
                self.discard_worker_dir(reservation.session_id);
                return Err(refusal);
            }
        }
        let launch = WorkerLaunch {
            reservation_id: reservation.reservation_id,
            session_id: reservation.session_id,
            environment_id: self.paths.environment_id(),
            display_number: reservation.display_number,
            program: self.worker_program.clone(),
            rendezvous: self.paths.rendezvous_endpoint()?.as_path().to_path_buf(),
            // The roots, not this environment's directories: the worker derives its own paths
            // from the environment identity, and giving it the derived directory would make it
            // apply the prefix twice.
            runtime_directory: self.paths.runtime_root().to_path_buf(),
            state_directory: self.paths.state_root().to_path_buf(),
            jobs_directory: self.paths.jobs_dir(),
            working_directory,
            // The desktop the worker is started in. Two platforms place a per-user job in the
            // login session that started it and need nothing here; Linux publishes the session's
            // display, compositor and message bus into the user manager, and that is what was
            // collected above.
            desktop_environment,
            // Which login context the worker is started in at all, which its environment alone
            // does not decide.
            profile: create.worker_profile,
        };
        let identity = match self.supervisor.start(&launch) {
            LaunchOutcome::Started(identity) => identity,
            // Nothing started, so the reservation is resolved as a confirmed failure and stops
            // occupying the environment. It is never resumed.
            LaunchOutcome::NotStarted { detail } => {
                hold.end_wait().await;
                let mut registry = self.registry.lock().await;
                registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                drop(registry);
                self.discard_worker_dir(reservation.session_id);
                // A definition may have been written, and even loaded, before the platform
                // refused; it goes with the launch.
                self.retire_job_when_ended(reservation.reservation_id, None);
                return Err(ControllerError::Supervision { detail });
            }
            // A process may be running. The create fails for the caller, and the reservation stays
            // spawned: it keeps its slot until something settles what happened to that process.
            LaunchOutcome::Uncertain { detail, pid } => {
                // Before the launcher's identity is recorded: a claim waits for that identity, so
                // none can take the variables of a create that has stopped waiting. A reservation
                // that is spawned, with no create waiting for it, is refused every claim, which
                // privacy mode's tick relies on to forget its session.
                hold.end_wait().await;
                let launched =
                    pid.and_then(|pid| kr_ipc::identity::process_start_identity(pid).ok());
                if let Some(identity) = &launched {
                    let mut registry = self.registry.lock().await;
                    registry.record_launch(reservation.reservation_id, identity)?;
                }
                self.retire_job_when_ended(reservation.reservation_id, launched);
                return Err(ControllerError::Supervision { detail });
            }
        };
        {
            let mut registry = self.registry.lock().await;
            registry.record_launch(reservation.reservation_id, &identity)?;
        }

        let ready = match tokio::time::timeout(RENDEZVOUS_TIMEOUT, receiver).await {
            Ok(Ok(Ok(ready))) => ready,
            // A worker that failed its rendezvous, or never reported, has no session to close, so
            // no closure removes its job. It goes once the worker has ended.
            Ok(Ok(Err(error))) => {
                self.retire_job_when_ended(reservation.reservation_id, Some(identity));
                return Err(ControllerError::Supervision {
                    detail: error.to_string(),
                });
            }
            Ok(Err(_)) | Err(_) => {
                let claimed = hold.end_wait().await;
                self.retire_job_when_ended(reservation.reservation_id, Some(identity));
                // A claim that took the variables has a launch that may still complete, and its
                // worker may yet report itself: what became of this create is not known, and its
                // caller asks again under the same token rather than making another session.
                return Err(if claimed {
                    ControllerError::Uncertain {
                        detail: "the worker did not report itself in time, and its launch may \
                                 still be under way"
                            .to_owned(),
                    }
                } else {
                    ControllerError::supervision("the worker did not report itself in time")
                });
            }
        };

        let worker = self
            .directory
            .lock()
            .await
            .get(reservation.session_id)
            .cloned()
            .ok_or_else(|| ControllerError::supervision("the worker is not in the directory"))?;
        let summary = self.read_from_worker(&worker).await?.session;
        // A new session can be the work that justifies keeping this host awake, and the setting
        // decides whether it does. That is looked at beside this answer rather than before it:
        // what the host does about its own sleep policy is no reason to hold a caller's receipt.
        self.review_power_soon();
        // Last, and never before the session exists: opening a window is a separate step, so a
        // host that cannot open one answers with the session it made and the reason. Nothing here
        // creates a second session, and a repeated create token never reaches this line, so a
        // retry cannot open a second window either.
        let presentation_error = self.present(&create, reservation.session_id).await;
        encode(&SessionCreateResult {
            session: summary,
            endpoint: Nullable::some(ready.endpoint),
            deduplicated: false,
            presentation_error: Nullable(presentation_error),
        })
    }

    /// Opens the local terminal a `terminal` presentation asks for.
    ///
    /// Section 7: a session created anywhere, including on a paired device, can ask for a local
    /// tab, and failing to open it leaves the session available and returns a separate
    /// presentation error rather than creating a duplicate session. The window runs `kr attach` on
    /// the session's own identifier and environment, never on a display number: two environments
    /// can each have a session one, and a window opened on the number would attach to whichever
    /// the command happened to resolve.
    async fn present(
        &self,
        create: &SessionCreateParams,
        session_id: SessionId,
    ) -> Option<ProtocolError> {
        if create.presentation != kr_protocol::session::Presentation::Terminal {
            return None;
        }
        let command = vec![
            self.attach_program().display().to_string(),
            "attach".to_owned(),
            session_id.to_string(),
            "--environment".to_owned(),
            create.environment_id.to_string(),
        ];
        let terminal = Arc::clone(&self.terminal);
        let requested = create.terminal.0.clone();
        // Opening a window starts a process and waits a bounded moment on it, which is work for a
        // thread that may block rather than for the runtime this daemon serves every other client
        // on.
        let outcome = tokio::task::spawn_blocking(move || {
            terminal.present(requested.as_deref(), &command).err()
        })
        .await
        .unwrap_or_else(|error| {
            Some(
                kr_shell_integration::host::terminal::TerminalUnavailable::CouldNotOpen {
                    application: "the selected terminal".to_owned(),
                    detail: error.to_string(),
                },
            )
        })
        .map(|unavailable| unavailable.to_protocol_error());
        // Retained so a create token asked twice is answered with what happened rather than with
        // a second window or a claim that the first one opened.
        self.presentations
            .lock()
            .await
            .insert(session_id, outcome.clone());
        outcome
    }

    /// Returns what a replayed create says about its session's presentation.
    ///
    /// The outcome this host retained, where it has one. Where it has none the create was admitted
    /// by a daemon that has since been replaced, and whether a window opened is not something this
    /// one can establish: it says so rather than opening a second one or claiming the first.
    async fn replayed_presentation(
        &self,
        create: Option<&SessionCreateParams>,
        session_id: SessionId,
    ) -> Option<ProtocolError> {
        if create.is_none_or(|create| {
            create.presentation != kr_protocol::session::Presentation::Terminal
        }) {
            return None;
        }
        match self.presentations.lock().await.get(&session_id) {
            Some(outcome) => outcome.clone(),
            None => Some(ProtocolError::new(
                ErrorCode::OutcomeUnknown,
                "this host did not admit the create this token replays, so whether its terminal \
                 window opened is not something it can say",
            )),
        }
    }

    /// Returns the client executable a terminal window runs.
    ///
    /// This daemon's own release's `kr`, because they are installed together and a host with two
    /// installations, or two releases side by side, must open the one it is running: the window
    /// attaches to a worker this daemon launched, and that worker is of this daemon's release.
    fn attach_program(&self) -> PathBuf {
        kr_ipc::install::this_process().map_or_else(
            |_| PathBuf::from("kr"),
            |running| running.own(kr_ipc::install::Program::Kr),
        )
    }

    /// Resolves a reservation that never reached a launch, and releases what it was holding.
    ///
    /// The phase is the durable half: a reservation recorded as failed stops occupying the
    /// environment and is never resumed. The directory prepared for the worker goes with it,
    /// because nothing is going to use it.
    async fn resolve_failed(&self, reservation_id: ReservationId) -> Result<()> {
        let mut registry = self.registry.lock().await;
        let session_id = registry
            .reservation(reservation_id)?
            .map(|reservation| reservation.session_id);
        registry.set_phase(reservation_id, LaunchPhase::Failed)?;
        drop(registry);
        if let Some(session_id) = session_id {
            self.discard_worker_dir(session_id);
        }
        Ok(())
    }

    /// Gives back the directory a worker was to run in.
    ///
    /// Best effort by design. A worker on its way out may still be holding it, which on Windows
    /// refuses the removal; what that leaves is an empty directory, and the sweep this daemon runs
    /// at startup takes it then.
    pub(super) fn discard_worker_dir(&self, session_id: SessionId) {
        let _ = std::fs::remove_dir_all(self.paths.worker_dir(session_id));
    }

    pub(super) async fn replay_create(
        &self,
        reservation: &crate::registry::Reservation,
    ) -> Result<ParamsValue> {
        // A retry can arrive before this daemon has adopted the worker its first attempt started,
        // which is what happens when a restart landed while the session was still qualifying.
        if self
            .directory
            .lock()
            .await
            .get(reservation.session_id)
            .is_none()
        {
            self.recover_claim_for(reservation.session_id).await?;
        }
        let worker = self
            .directory
            .lock()
            .await
            .get(reservation.session_id)
            .cloned();
        // What the first attempt asked for, which is what says whether a window was ever part of
        // this create. A record this build cannot read says nothing about a presentation.
        let requested = reservation
            .create_intent
            .as_deref()
            .and_then(|recorded| recorded_create(recorded).ok());
        if let Some(worker) = worker {
            let summary = self.read_from_worker(&worker).await?.session;
            return encode(&SessionCreateResult {
                session: summary,
                endpoint: Nullable::some(worker.endpoint.as_text()),
                deduplicated: true,
                presentation_error: Nullable(
                    self.replayed_presentation(requested.as_ref(), reservation.session_id)
                        .await,
                ),
            });
        }
        let registry = self.registry.lock().await;
        let closure = registry.closure(reservation.session_id)?;
        drop(registry);
        match closure {
            Some(closure) => encode(&SessionCreateResult {
                session: self
                    .closed_session(&closure, reservation.display_number)
                    .await,
                // A closed session has no endpoint to attach to, which the reply says rather than
                // handing back a path that leads nowhere.
                endpoint: Nullable::null(),
                // A closed session has no window either way, so there is no presentation to
                // report on: what the caller is owed here is the closure record.
                presentation_error: Nullable::null(),
                deduplicated: true,
            }),
            None => Err(ControllerError::supervision(format!(
                "this create token is already recorded as {} and its worker is not available",
                reservation.phase.as_str()
            ))),
        }
    }
}

pub(super) fn qualified_package(root: Option<&Path>, requested: Option<&str>) -> Result<PathBuf> {
    use kr_shell_integration::host::package::{PackageSet, default_package_root};

    let installed = match root {
        Some(root) => PackageSet::discover(root),
        None => PackageSet::installed(&default_package_root()),
    }
    .map_err(|fault| ControllerError::ShellIntegrationUnsupported(fault.to_string()))?;
    installed
        .select(requested)
        .map(|package| package.directory.clone())
        .map_err(|fault| ControllerError::ShellIntegrationUnsupported(fault.to_string()))
}

/// Reads the create request a reservation recorded.
///
/// What a reservation records is what the session was asked to be, without the environment its
/// creator sent: that is held in memory for the launch and written nowhere, so the list of
/// variables in a recorded request is always empty and says nothing about the creator.
///
/// # Errors
///
/// Returns the decoding failure when the record is not a create request.
pub(super) fn recorded_create(recorded: &[u8]) -> std::result::Result<SessionCreateParams, String> {
    kr_cbor::from_canonical_slice::<SessionCreateParams>(recorded, &kr_cbor::Limits::DEFAULT)
        .map_err(|error| error.to_string())
}
