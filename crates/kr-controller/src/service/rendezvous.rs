//! A launched worker's rendezvous: its launch identity and its ready report.

use std::sync::Arc;

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::split;
use kr_ipc::paths::Endpoint;
use kr_ipc::peer::PeerIdentity;
use kr_ipc::verify::check_rendezvous;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::ProtocolError;
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::ids::{ConnectionId, SessionEpoch};
use kr_protocol::local::{LocalClientKind, LocalRole};
use kr_protocol::scalars::Nullable;
use kr_protocol::session::SessionState;
use kr_protocol::worker::{
    ReservationId, WorkerDescriptor, WorkerLaunchSpec, WorkerReady, WorkerRendezvous,
};

use crate::directory::KnownWorker;
use crate::error::{ControllerError, Result};
use crate::registry::{LaunchPhase, WorkerRecord};

use super::Controller;
use super::create::{qualified_package, recorded_create};
use super::workers::WORKER_EXCHANGE;

#[cfg(feature = "testing")]
use tokio::sync::oneshot;

/// How long the rendezvous waits for the launcher to report the worker's identity.
pub const LAUNCH_IDENTITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl Controller {
    /// Arms the pause a worker's rendezvous stops at once its claim is committed, before its
    /// specification and first admissions are made. Returns the end that says the rendezvous has
    /// arrived, and the end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_rendezvous_after_claim(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        self.after_the_claim.arm()
    }

    /// Serves the owner-only rendezvous socket.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting fails.
    pub async fn serve_rendezvous(self: Arc<Self>, listener: Listener) -> Result<()> {
        loop {
            let (connection, peer) = listener.accept().await?;
            let controller = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(error) = controller.rendezvous(connection, peer).await {
                    eprintln!("kr-controller: a worker rendezvous failed: {error}");
                }
            });
        }
    }

    async fn rendezvous(&self, connection: Connection, peer: PeerIdentity) -> Result<()> {
        let (mut reader, mut writer) = split(connection, StreamKind::Control);
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let hello: ControlFrame = reader.read_message().await?;
        let ControlFrame::Hello(hello) = hello else {
            return Err(ControllerError::rendezvous("the worker did not say hello"));
        };
        if hello.client != LocalClientKind::Worker {
            return Err(ControllerError::rendezvous(
                "only a worker's startup claim is accepted here",
            ));
        }
        let outcome = self
            .rendezvous_exchange(&mut reader, &mut writer, connection_id, &peer)
            .await;
        // A rendezvous connection is one exchange. Its window goes with it rather than staying
        // outstanding for the life of the daemon.
        self.windows.retire_connection(connection_id);
        outcome
    }

    async fn rendezvous_exchange(
        &self,
        reader: &mut kr_ipc::framed::FrameReader,
        writer: &mut kr_ipc::framed::FrameWriter,
        connection_id: ConnectionId,
        peer: &PeerIdentity,
    ) -> Result<()> {
        writer
            .write_message(&ControlFrame::HelloAck(self.acknowledgement(
                LocalRole::Rendezvous,
                self.issue_window(connection_id)?,
                peer,
            )))
            .await?;

        let claim: ControlFrame = reader.read_message().await?;
        let ControlFrame::Rendezvous(claim) = claim else {
            return Err(ControllerError::rendezvous(
                "the worker did not present a startup claim",
            ));
        };
        let (specification, admissions) = self.admit_rendezvous(&claim, peer).await?;
        writer
            .write_message(&ControlFrame::LaunchSpec(Box::new(specification)))
            .await?;
        // The first snapshot of admissions follows the specification on this connection, before
        // the worker starts its shell. Nothing answers it here: the worker answers a round on its
        // own endpoint once it is recorded.
        for part in admissions {
            writer
                .write_message(&ControlFrame::PluginAdmissions(Box::new(part)))
                .await?;
        }

        let report: ControlFrame = reader.read_message().await?;
        let reservation_id = claim.reservation_id;
        match report {
            ControlFrame::WorkerReady(ready) => {
                self.record_ready(reservation_id, &claim, &ready).await?;
                self.resolve(reservation_id, Ok(ready)).await;
                Ok(())
            }
            ControlFrame::WorkerFailed(error) => {
                // A worker that says it could not start resolves its own claim, but only its own:
                // a reservation that was fenced while this report was in flight stays fenced,
                // because the report does not answer the question fencing asked.
                let mut registry = self.registry.lock().await;
                let resolved = registry.resolve_claim(reservation_id, LaunchPhase::Failed)?;
                drop(registry);
                // Only a reservation this report actually resolved. A fenced one is still
                // somebody's question, and the directory stays until it is answered.
                if resolved {
                    self.discard_worker_dir(claim.session_id);
                    self.plugin_bridge.ended(claim.session_id);
                }
                self.resolve(reservation_id, Err(error)).await;
                Ok(())
            }
            _ => Err(ControllerError::rendezvous(
                "the worker did not report whether it started",
            )),
        }
    }

    async fn admit_rendezvous(
        &self,
        claim: &WorkerRendezvous,
        peer: &PeerIdentity,
    ) -> Result<(
        WorkerLaunchSpec,
        Vec<kr_protocol::admission::PluginAdmissions>,
    )> {
        check_rendezvous(claim).map_err(ControllerError::rendezvous)?;
        {
            let registry = self.registry.lock().await;
            let reservation = registry
                .reservation(claim.reservation_id)?
                .ok_or_else(|| ControllerError::rendezvous("no reservation matches this claim"))?;
            if reservation.session_id != claim.session_id {
                return Err(ControllerError::rendezvous(
                    "the claim names a different session from its reservation",
                ));
            }
        }
        if claim.boot_identity != self.boot_identity {
            return Err(ControllerError::rendezvous(
                "the claim names a different boot",
            ));
        }
        // The launcher's identity is recorded as soon as the service manager reports it, which can
        // be after the worker has already connected. Waiting for it is not optional: without it
        // there is nothing to compare the connecting process against.
        let launcher = self.await_launch_identity(claim.reservation_id).await?;
        let peer_pid = peer
            .pid
            .ok_or_else(|| ControllerError::rendezvous("the platform did not report the peer"))?;
        if u64::from(peer_pid) != launcher.pid.get() {
            self.registry.lock().await.fence(claim.reservation_id)?;
            self.plugin_bridge.fenced(claim.session_id);
            return Err(ControllerError::rendezvous(
                "the connecting process is not the one the launcher started",
            ));
        }
        // The kernel is asked about the process on the other end of this socket, now. A signed
        // claim only says what the worker believes about itself; reading the identity here is what
        // rules out a different process that happens to hold the same identifier.
        let connected = kr_ipc::identity::process_start_identity(peer_pid).map_err(|error| {
            ControllerError::rendezvous(format!(
                "the kernel would not describe the connecting process: {error}"
            ))
        })?;
        if connected != launcher {
            self.registry.lock().await.fence(claim.reservation_id)?;
            self.plugin_bridge.fenced(claim.session_id);
            return Err(ControllerError::rendezvous(
                "the connecting process did not start when the launcher's did",
            ));
        }
        if claim.process_start_identity != connected {
            self.registry.lock().await.fence(claim.reservation_id)?;
            self.plugin_bridge.fenced(claim.session_id);
            return Err(ControllerError::rendezvous(
                "the claim's process identity is not the connecting process's",
            ));
        }

        // The environment the session is started with is taken here, once, by the claim of the
        // create that is still waiting for this worker. Nothing else holds it: a claim that finds none belongs to
        // a create that has stopped waiting, or to one a daemon that has since ended was making,
        // and is refused rather than launched with an environment it was not sent.
        let environment = self.take_session_environment(claim.reservation_id).await;

        // Admission is consumed here, in one transaction, together with the key that authenticates
        // this worker from now on. Everything above is a check; this is the commitment.
        let reservation = {
            let mut registry = self.registry.lock().await;
            if environment.is_none() && registry.fail_if_spawned(claim.reservation_id)? {
                // A launch that produced no session: no key was recorded, and nothing was told
                // anything. A reservation in any other phase is left to the claim's own rules
                // below, which fence a second claim.
                drop(registry);
                self.discard_worker_dir(claim.session_id);
                self.retire_job_when_ended(claim.reservation_id, Some(launcher));
                return Err(ControllerError::rendezvous(
                    "the create this worker was started for is not waiting for it, so its \
                     launch is not admitted",
                ));
            }
            match registry.claim_rendezvous(claim.reservation_id, claim.worker_public_key) {
                Ok(reservation) => {
                    // A member from the moment the claim commits, before anything is awaited: a
                    // second claim that fences this reservation meanwhile finds it a member.
                    self.plugin_bridge
                        .claimed(claim.session_id, Some(launcher.clone()));
                    reservation
                }
                Err(error) => {
                    // A claim on a reservation already claimed fences it, and the worker that
                    // made the first claim may hold admissions by now: it stays a member, never
                    // sent another round, until its process is known to have ended.
                    self.plugin_bridge.fenced(claim.session_id);
                    return Err(error);
                }
            }
        };
        #[cfg(feature = "testing")]
        self.after_the_claim.wait().await;
        let recorded = reservation.create_intent.as_deref().ok_or_else(|| {
            ControllerError::rendezvous(
                "this reservation has no recorded create request, so nothing can be launched from it",
            )
        })?;
        let mut create = recorded_create(recorded).map_err(|error| {
            ControllerError::registry(format!(
                "the recorded create request cannot be read: {error}"
            ))
        })?;
        // Before the specification is measured: the variables are part of what the frame carries.
        let environment = environment.ok_or_else(|| {
            ControllerError::rendezvous("this claim found no environment to launch with")
        })?;
        create.environment_snapshot = environment.variables;

        // The package this worker will launch is resolved here, by the daemon, against the
        // package root the daemon is configured with. The worker is told which directory to read
        // rather than left to find one in its own environment: the two can differ, and a session
        // must run the package its create was admitted against.
        let shell_package = if create.shell_mode == kr_protocol::session::ShellMode::Managed {
            // On a thread that may block, for the same reason the admission check is: finding a
            // package reads directories and opens files, and a package root that has stopped
            // answering must not occupy one of the runtime's own threads.
            let root = self.shell_packages.clone();
            let requested = create.shell.0.clone();
            let resolved = tokio::task::spawn_blocking(move || {
                qualified_package(root.as_deref(), requested.as_deref())
            })
            .await
            .map_err(|error| ControllerError::supervision(error.to_string()))??;
            Nullable::some(resolved.display().to_string())
        } else {
            Nullable::null()
        };
        let admissions = self.first_admissions(reservation.session_id).await;
        // The session's command integrations are fixed here, when it is launched: from the
        // admissions its worker is handed first, read by a worker's own rules, and the
        // configuration in force now.
        let fill = self.session_integrations(&admissions).await;
        create.launch_profile.command_integrations = fill.entries;
        let mut omitted = fill.omitted;
        let plugins = admissions
            .first()
            .map(|first| kr_protocol::admission::AdmissionsHeader {
                frame: first.frame,
                parts: first.parts,
            })
            .ok_or_else(|| {
                ControllerError::supervision("the first admissions for this worker are empty")
            })?;
        // The privacy state this worker starts under, read now that its claim is accepted and as
        // late as it can be before the specification is built. It is read on a thread that may
        // block: a change of privacy mode holds the state's write side while it waits for the
        // exchanges already admitted. A worker applies it before it starts its shell, and a change
        // after this reaches it as the daemon's notice, which the session's obligation, recorded
        // when the worker was asked for if privacy mode was on then and when it was turned on
        // otherwise, keeps the daemon repeating until it is answered.
        let privacy = self.privacy.state();
        let launched_under = tokio::task::spawn_blocking(move || privacy.now())
            .await
            .map_err(|error| ControllerError::supervision(error.to_string()))?;
        let mut specification = WorkerLaunchSpec {
            session_id: reservation.session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: self.paths.environment_id(),
            display_number: reservation.display_number,
            create,
            shell_package,
            controller_public_key: *self.identity.public_key(),
            controller_generation: self.generation,
            release: self.release.clone(),
            plugins,
            privacy: launched_under.to_launch(),
            environment_origin: environment.origin,
            environment_additions: environment.additions,
        };
        // The specification is one control frame. Beside a create request that leaves too little
        // room, the largest integrations are left out as well. The session starts without them,
        // and one note names every integration turned on that it was launched without.
        omitted.extend(
            crate::catalogue::integrations::fit_launch_specification(&mut specification)
                .into_iter()
                .filter(|entry| entry.enabled)
                .map(|entry| entry.plugin_id),
        );
        if let Some(note) =
            crate::catalogue::integrations::omission_note(reservation.session_id, &omitted)
        {
            self.note_admissions(note);
        }
        Ok((specification, admissions))
    }

    /// The command integrations a session launched with `admissions` gets: one for each
    /// connector whose integration applies there, on where the configuration in force names its
    /// package. None where nothing is admitted, or where the packages cannot be read in time, which
    /// is noted for the doctor: the worker then runs every command as typed.
    async fn session_integrations(
        &self,
        admissions: &[kr_protocol::admission::PluginAdmissions],
    ) -> crate::catalogue::integrations::Fill {
        let packages: Vec<kr_protocol::admission::AdmittedPackage> = admissions
            .iter()
            .flat_map(|part| part.packages.iter().cloned())
            .collect();
        if packages.is_empty() {
            return crate::catalogue::integrations::Fill::default();
        }
        let enabled = self.in_force().command_integrations;
        let integrations = Arc::clone(&self.integrations);
        let read = tokio::task::spawn_blocking(move || {
            crate::catalogue::integrations::fill(
                &integrations.read(&packages),
                &enabled,
                crate::catalogue::integrations::registered_forwarder().as_deref(),
            )
        });
        match tokio::time::timeout(WORKER_EXCHANGE, read).await {
            Ok(Ok(fill)) => fill,
            Ok(Err(_)) | Err(_) => {
                self.note_admissions(
                    "a session's command integrations could not be read from its admissions in \
                     time, so it was launched with none"
                        .to_owned(),
                );
                crate::catalogue::integrations::Fill::default()
            }
        }
    }

    /// Takes the environment this reservation's session is started with, when its create is still
    /// waiting for the worker, and says nothing of it otherwise.
    ///
    /// It leaves the create's own slot, so the create cannot also have it. The list of
    /// waiting creates is released before anything else is awaited.
    async fn take_session_environment(
        &self,
        reservation_id: ReservationId,
    ) -> Option<super::create::SessionEnvironment> {
        let slot = self
            .pending
            .lock()
            .await
            .get(&reservation_id)
            .map(|pending| Arc::clone(&pending.environment))?;
        slot.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Waits for the launcher's reported identity to reach the registry.
    async fn await_launch_identity(
        &self,
        reservation_id: ReservationId,
    ) -> Result<kr_protocol::identity::ProcessStartIdentity> {
        let deadline = std::time::Instant::now() + LAUNCH_IDENTITY_TIMEOUT;
        loop {
            {
                let registry = self.registry.lock().await;
                if let Some(reservation) = registry.reservation(reservation_id)?
                    && let Some(identity) = reservation.launcher_identity
                {
                    return Ok(identity);
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(ControllerError::rendezvous(
                    "the launcher did not report the worker's identity",
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    pub(super) async fn record_ready(
        &self,
        reservation_id: ReservationId,
        claim: &WorkerRendezvous,
        ready: &WorkerReady,
    ) -> Result<()> {
        // This reservation, taken from whatever else might look at it. A report that arrives after
        // its create gave up on waiting is still this worker's own word, and a look that started
        // before it would otherwise challenge the worker while this is publishing it: two
        // connections to one worker, and the second generation token fences the first.
        let _held = self.hold_reservation(reservation_id).await;
        let mut registry = self.registry.lock().await;
        let reservation = registry
            .reservation(reservation_id)?
            .ok_or_else(|| ControllerError::rendezvous("the reservation vanished"))?;
        // The profile is the one the create request recorded, not a default: it decides what a
        // logout does to this session, and a record that said otherwise would promise the wrong
        // lifetime.
        let recorded = reservation.create_intent.as_deref().ok_or_else(|| {
            ControllerError::rendezvous(
                "this reservation has no recorded create request, so the session it would publish \
                 has no recorded execution context",
            )
        })?;
        let profile = recorded_create(recorded)
            .map_err(|error| {
                ControllerError::registry(format!(
                    "the recorded create request cannot be read: {error}"
                ))
            })?
            .worker_profile;
        let record = WorkerRecord {
            session_id: reservation.session_id,
            display_number: reservation.display_number,
            public_key: claim.worker_public_key,
            process_identity: claim.process_start_identity.clone(),
            endpoint: ready.endpoint.clone(),
            profile,
            state: SessionState::Live,
            // A worker starts having acknowledged nothing. The first announcement it receives is
            // what moves this.
            acknowledged_revision: kr_protocol::ids::AuthorityRevision::new(0),
        };
        // The key and the live phase are committed together: a registry that says a session is
        // live always knows which key answers for it. The desktop the worker says it is bound to
        // goes with them, from its own report: what this daemon reads of the desktop it runs on
        // now is not what the worker was bound to, and a daemon that starts on another login has
        // to know which desktop each worker belongs to.
        registry.record_worker(reservation_id, &record, &ready.session.desktop)?;
        drop(registry);

        let descriptor = WorkerDescriptor {
            session_id: reservation.session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: self.paths.environment_id(),
            display_number: reservation.display_number,
            boot_identity: claim.boot_identity.clone(),
            process_start_identity: claim.process_start_identity.clone(),
            protocol_version: PROTOCOL_VERSION,
            endpoint: ready.endpoint.clone(),
            worker_public_key: claim.worker_public_key,
            worker_profile: profile,
            published_at_ms: kr_ipc::now_ms(),
        };
        let endpoint = Endpoint::from_path(&ready.endpoint)?;
        // The worker's own description of its session, as its report gives it: nothing is asked of
        // the worker here, and a report that came after its create stopped waiting still leaves
        // the session described, as a read that meets the worker on its way out needs it.
        self.publish_worker(
            KnownWorker {
                descriptor,
                endpoint,
            },
            Some(ready.session.as_ref().clone()),
        )
        .await
    }

    async fn resolve(
        &self,
        reservation_id: ReservationId,
        outcome: std::result::Result<WorkerReady, ProtocolError>,
    ) {
        if let Some(pending) = self.pending.lock().await.remove(&reservation_id) {
            let _ = pending.ready.send(outcome);
        }
    }
}
