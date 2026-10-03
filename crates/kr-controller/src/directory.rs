//! The verified directory of workers this daemon knows about.
//!
//! A restarting daemon does not rebuild its picture of the host from process names or from
//! whatever files happen to be lying about. It reads the registry rows it wrote and the
//! descriptors it published, and then it asks each worker to prove itself with a fresh challenge.
//!
//! A descriptor whose challenge fails is quarantined: it stays out of the directory and is never
//! spawned from. It might be stale, or it might have been planted; the daemon cannot tell and does
//! not need to, because either way it is not a session. A descriptor whose reservation this host
//! fenced is quarantined without a challenge: the fence is the host's word that the worker is not
//! to be reached again.
//!
//! Beside each worker is what it last said about its session: its ready report, its answers to
//! reads and its acceptance of a close each describe the session. A worker that has finished its
//! closure stops answering before the kernel says its process has ended, and in between that is
//! what the daemon knows of the session. A worker this daemon finds when it starts is asked for
//! its description over the connection it proved itself on.
//!
//! Nothing here kills a worker. A daemon restart is not a reason to end a shell.

use std::collections::BTreeMap;

use kr_ipc::client::LocalClient;
use kr_ipc::paths::{Endpoint, EnvironmentPaths};
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::{BuildId, ControllerGeneration, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{SessionReadParams, SessionReadResult, SessionState, SessionSummary};
use kr_protocol::worker::WorkerDescriptor;

use crate::error::Result;
use crate::registry::{LaunchPhase, Registry};

/// How long one worker has to answer its challenge and accept a generation during a rebuild, and
/// then, separately, to describe its session (`describe`).
///
/// A silent endpoint is a reason to quarantine one descriptor, never a reason for the daemon not
/// to finish starting.
pub const RECONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// One entry in the directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownWorker {
    /// The descriptor the daemon published.
    pub descriptor: WorkerDescriptor,
    /// The worker's endpoint.
    pub endpoint: Endpoint,
}

/// Why a descriptor is not in the directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quarantined {
    /// The session the descriptor claimed.
    pub session_id: SessionId,
    /// Why it was refused.
    pub reason: String,
}

/// What one worker last said about its session.
#[derive(Debug, Default)]
struct Heard {
    /// The session as the worker last described it, where one of its answers has reached this
    /// daemon since it started: its ready report, a read, its answer to a close. The description
    /// alone: what else a read carries either reaches the worker or is the session's content, and
    /// neither is this daemon's to hand out.
    session: Option<SessionSummary>,
    /// Whether the worker accepted a close this daemon passed to it.
    closing: bool,
}

impl Heard {
    /// Keeps a worker's description of the session `session_id`, unless it describes another
    /// session or puts this one earlier in its lifecycle than the description kept.
    ///
    /// The lifecycle only moves forward, so an answer that puts the session earlier is one an
    /// earlier moment gave and a later one overtook. A description of another session says nothing
    /// about this one, whatever carried it.
    fn keep(&mut self, session_id: SessionId, described: &SessionSummary) {
        if described.session_id != session_id {
            return;
        }
        if self
            .session
            .as_ref()
            .is_none_or(|kept| stage(described.state) >= stage(kept.state))
        {
            self.session = Some(described.clone());
        }
    }
}

/// The result of rebuilding the directory.
#[derive(Debug, Default)]
pub struct Directory {
    /// Workers that answered their challenge.
    pub verified: BTreeMap<SessionId, KnownWorker>,
    /// Descriptors that did not, which are never spawned from.
    pub quarantined: Vec<Quarantined>,
    /// What each verified worker last said. An entry goes with its worker, so what a worker said
    /// is never kept past the closure that took it out of the directory.
    heard: BTreeMap<SessionId, Heard>,
}

impl Directory {
    /// Rebuilds the directory from the registry rows and the published descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor directory cannot be listed or the registry cannot be
    /// read.
    pub async fn rebuild(
        paths: &EnvironmentPaths,
        registry: &Registry,
        reconnect: &Reconnect<'_>,
    ) -> Result<Self> {
        let mut directory = Self::default();
        let recorded = registry.workers()?;
        for entry in kr_ipc::descriptor::read_all(paths)? {
            let descriptor = match entry.descriptor {
                Ok(descriptor) => descriptor,
                Err(reason) => {
                    directory.quarantined.push(Quarantined {
                        session_id: SessionId::new(kr_protocol::scalars::Uuid::NIL),
                        reason: format!("{}: {reason}", entry.path.display()),
                    });
                    continue;
                }
            };
            // The registry is the daemon's own record. A descriptor with no row behind it, or one
            // whose key disagrees with the row, is not this host's worker.
            let Some(row) = recorded
                .iter()
                .find(|row| row.session_id == descriptor.session_id)
            else {
                directory.quarantined.push(Quarantined {
                    session_id: descriptor.session_id,
                    reason: "no registry row records this session".to_owned(),
                });
                continue;
            };
            if row.public_key != descriptor.worker_public_key {
                directory.quarantined.push(Quarantined {
                    session_id: descriptor.session_id,
                    reason: "the descriptor's key is not the one the rendezvous established"
                        .to_owned(),
                });
                continue;
            }
            // A fenced reservation is one this host stopped trusting, and its worker is not reached
            // again: challenging it would hand it this daemon's generation, and admitting it would
            // undo the fence. Recovery leaves such a worker out of the directory for the same
            // reason, and so does a start.
            if registry
                .reservation_for_session(descriptor.session_id)?
                .is_some_and(|reservation| reservation.phase == LaunchPhase::Fenced)
            {
                directory.quarantined.push(Quarantined {
                    session_id: descriptor.session_id,
                    reason: "the reservation this worker was started for is fenced".to_owned(),
                });
                continue;
            }
            match reconnect_to(&descriptor, reconnect).await {
                Ok((endpoint, described)) => {
                    directory.insert(
                        KnownWorker {
                            descriptor,
                            endpoint,
                        },
                        described,
                    );
                }
                Err(reason) => directory.quarantined.push(Quarantined {
                    session_id: descriptor.session_id,
                    reason,
                }),
            }
        }
        Ok(directory)
    }

    /// Returns one verified worker.
    #[must_use]
    pub fn get(&self, session_id: SessionId) -> Option<&KnownWorker> {
        self.verified.get(&session_id)
    }

    /// Adds a worker, with its own description of its session where this daemon has one.
    ///
    /// Proving itself is what admits a worker, because a close has to be able to reach every
    /// worker that has. A worker the rendezvous has just established describes its session in its
    /// ready report. A worker found at a start or recovered later is asked for its description as
    /// it is admitted (`describe`), and may be admitted without one; its answer to a close this
    /// daemon passes on describes the session then ([`Self::accepted_close`]).
    pub fn insert(&mut self, worker: KnownWorker, described: Option<SessionSummary>) {
        let session_id = worker.descriptor.session_id;
        self.verified.insert(session_id, worker);
        let mut heard = Heard::default();
        if let Some(described) = &described {
            heard.keep(session_id, described);
        }
        self.heard.insert(session_id, heard);
    }

    /// Removes a worker whose session has closed, and what it last said.
    pub fn remove(&mut self, session_id: SessionId) {
        self.verified.remove(&session_id);
        self.heard.remove(&session_id);
    }

    /// Returns every verified worker.
    pub fn iter(&self) -> impl Iterator<Item = &KnownWorker> {
        self.verified.values()
    }

    /// Keeps how a worker in the directory has just described its session.
    ///
    /// A worker that has left the directory had its closure recorded while it was being asked,
    /// and the record is the answer from then on, so what it said is not kept. Nor is a
    /// description of another session, or one that puts the session earlier in its lifecycle than
    /// the one kept (`Heard::keep`).
    pub fn heard(&mut self, session_id: SessionId, described: &SessionSummary) {
        if !self.verified.contains_key(&session_id) {
            return;
        }
        self.heard
            .entry(session_id)
            .or_default()
            .keep(session_id, described);
    }

    /// Notes that a worker in the directory accepted a close this daemon passed on, and keeps
    /// the description of the session its acceptance carried, as [`Self::heard`] keeps one.
    ///
    /// A worker built before its acceptance described the session carries none, and then the
    /// session is closing with whatever description this daemon already had.
    pub fn accepted_close(&mut self, session_id: SessionId, described: Option<&SessionSummary>) {
        if !self.verified.contains_key(&session_id) {
            return;
        }
        let heard = self.heard.entry(session_id).or_default();
        heard.closing = true;
        if let Some(described) = described {
            heard.keep(session_id, described);
        }
    }

    /// Describes a session whose worker has stopped answering, where its end is under way.
    ///
    /// A worker that has finished its closure stops answering before the kernel says its process
    /// has ended, and until the kernel says so this daemon neither takes the session over from
    /// its worker nor writes a closure of its own for it. The session is what its worker last said
    /// it was, and `closing` where the worker had not said so but had accepted a close this daemon
    /// passed to it: what is left of the closure is this daemon's to record. The rest of a read is
    /// left unsaid. The endpoint, the launch profile and the launches waiting on the worker are how
    /// a client reaches a worker that no longer answers, and the last command block is the
    /// session's content, which only its worker hands out.
    ///
    /// Nothing is described where no end is under way, or where the worker has never described its
    /// session to this daemon: that is a worker this daemon cannot reach, and nothing here says
    /// what its session is now.
    #[must_use]
    pub fn ending(&self, session_id: SessionId) -> Option<SessionReadResult> {
        let heard = self.heard.get(&session_id)?;
        let mut session = heard.session.clone()?;
        match session.state {
            SessionState::Closing | SessionState::Closed => {}
            SessionState::Creating | SessionState::Live if heard.closing => {
                session.state = SessionState::Closing;
            }
            SessionState::Creating | SessionState::Live => return None,
        }
        Some(SessionReadResult {
            session,
            endpoint: Nullable::null(),
            launch_profile: Nullable::null(),
            last_command_block: Nullable::null(),
            outstanding_launches: Nullable::null(),
        })
    }
}

/// Where a state is in the session lifecycle, which only moves forward: creating, live, closing,
/// closed.
const fn stage(state: SessionState) -> u8 {
    match state {
        SessionState::Creating => 0,
        SessionState::Live => 1,
        SessionState::Closing => 2,
        SessionState::Closed => 3,
    }
}

/// What a replacement daemon needs to reconnect to a worker.
#[derive(Clone, Copy, Debug)]
pub struct Reconnect<'a> {
    /// The identity that signs generation tokens.
    pub identity: &'a ControllerIdentity,
    /// The generation this daemon advanced to.
    pub generation: ControllerGeneration,
    /// The boot this daemon is running in.
    pub boot_identity: &'a BootIdentity,
    /// This daemon's build.
    pub build_id: &'a BuildId,
}

async fn reconnect_to(
    descriptor: &WorkerDescriptor,
    reconnect: &Reconnect<'_>,
) -> std::result::Result<(Endpoint, Option<SessionSummary>), String> {
    let endpoint = Endpoint::from_path(&descriptor.endpoint).map_err(|error| error.to_string())?;
    // Bounded, because starting the daemon must not depend on a worker that never answers. A
    // descriptor that runs out of time is quarantined like any other that fails its challenge.
    let mut client = tokio::time::timeout(RECONNECT_TIMEOUT, async {
        let mut client = LocalClient::connect(
            &endpoint,
            LocalClientKind::Controller,
            reconnect.build_id.clone(),
        )
        .await
        .map_err(|error| error.to_string())?;
        client
            .verify_worker(descriptor)
            .await
            .map_err(|error| error.to_string())?;
        // Presenting the generation is what fences the daemon this one replaced. Verifying the
        // worker only establishes that the endpoint is the session it claims to be.
        client
            .present_generation(|nonce| {
                reconnect
                    .identity
                    .generation_token(reconnect.generation, reconnect.boot_identity, nonce)
                    .map_err(kr_ipc::IpcError::from)
            })
            .await
            .map_err(|error| error.to_string())?;
        Ok::<_, String>(client)
    })
    .await
    .map_err(|_| "the worker did not answer its challenge in time".to_owned())??;
    let described = describe(&mut client, descriptor.session_id).await;
    Ok((endpoint, described))
}

/// Asks a worker this daemon has just verified to describe its session, over the connection it
/// proved itself on.
///
/// The description is what a read that later meets the worker on its way out is answered from
/// ([`Directory::ending`]). It is asked for with a bound of its own, after the worker has proved
/// itself, and a worker that does not give one in time, or refuses, is admitted without it: a
/// close has to be able to reach it all the same. An answer from a worker of an earlier build is
/// read as that build wrote it.
pub(crate) async fn describe(
    client: &mut LocalClient,
    session_id: SessionId,
) -> Option<SessionSummary> {
    let answer = tokio::time::timeout(
        RECONNECT_TIMEOUT,
        client.request(Method::SessionRead, &SessionReadParams { session_id }),
    )
    .await
    .ok()?
    .ok()?
    .ok()?;
    crate::service::reported_read(&answer)
        .ok()
        .map(|read| read.session)
}

#[cfg(test)]
mod tests {
    use kr_protocol::identity::{
        BootIdentity, BootIdentitySource, DesktopBinding, ProcessStartIdentity, ProcessStartSource,
        WorkerProfile,
    };
    use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
    use kr_protocol::scalars::{AuthorisationKey, Bytes, Nullable, TimestampMs, U64, Uuid};
    use kr_protocol::session::{
        Dimensions, DisplayNumber, SessionState, SessionSummary, ShellMode,
    };
    use kr_protocol::worker::WorkerDescriptor;

    use super::{Directory, KnownWorker};

    /// A verified worker of `session_id`, on an endpoint of `host`.
    fn worker(host: &kr_ipc::testing::TempHost, session_id: SessionId) -> KnownWorker {
        let endpoint = host
            .environment()
            .worker_endpoint(DisplayNumber::new(1))
            .expect("an endpoint");
        KnownWorker {
            descriptor: WorkerDescriptor {
                session_id,
                session_epoch: SessionEpoch::V1,
                environment_id: host.environment_id(),
                display_number: DisplayNumber::new(1),
                boot_identity: BootIdentity {
                    source: BootIdentitySource::LinuxBootId,
                    value: Bytes::new(b"boot".to_vec()),
                },
                process_start_identity: ProcessStartIdentity::new(
                    11,
                    ProcessStartSource::LinuxProcStat,
                    22,
                ),
                protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
                endpoint: endpoint.as_text(),
                worker_public_key: AuthorisationKey::from_bytes([7; 32]),
                worker_profile: WorkerProfile::HeadlessUser,
                published_at_ms: TimestampMs::new(1),
            },
            endpoint,
        }
    }

    /// `session_id` in `state`, `columns` wide, as a worker describes it.
    fn described(session_id: SessionId, state: SessionState, columns: u64) -> SessionSummary {
        SessionSummary {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: EnvironmentId::new(Uuid::from_bytes([8; 16])),
            display_number: DisplayNumber::new(1),
            state,
            shell_mode: ShellMode::NativeCompat,
            shell_path: "/bin/sh".to_owned(),
            cwd: "/work".to_owned(),
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            created_at_ms: TimestampMs::new(1),
            dimensions: Dimensions::new(columns, 24),
            attachment_count: U64::ZERO,
            application_state: Nullable::null(),
            root_process: Nullable::null(),
            closure: Nullable::null(),
            environment_sources: None,
        }
    }

    /// What the directory answers a read that meets the worker on its way out with.
    fn ending(directory: &Directory, session_id: SessionId) -> Option<SessionSummary> {
        directory.ending(session_id).map(|read| read.session)
    }

    /// A description of another session is not kept as this one's, whichever way it arrives:
    /// with the worker's admission, in its answer to a read, or in its acceptance of a close.
    #[test]
    fn a_description_of_another_session_is_never_kept() {
        let host = kr_ipc::testing::TempHost::create();
        let session_id = SessionId::new(Uuid::from_bytes([1; 16]));
        let other = SessionId::new(Uuid::from_bytes([2; 16]));
        let mut directory = Directory::default();
        directory.insert(
            worker(&host, session_id),
            Some(described(other, SessionState::Live, 80)),
        );
        directory.heard(session_id, &described(other, SessionState::Closing, 80));
        directory.accepted_close(
            session_id,
            Some(&described(other, SessionState::Closing, 80)),
        );
        assert_eq!(
            ending(&directory, session_id),
            None,
            "nothing kept describes this session"
        );

        directory.accepted_close(
            session_id,
            Some(&described(session_id, SessionState::Closing, 100)),
        );
        assert_eq!(
            ending(&directory, session_id),
            Some(described(session_id, SessionState::Closing, 100)),
            "and this session's own description is kept"
        );
    }

    /// An acceptance's description is kept by the lifecycle's order like any answer's: it
    /// replaces a live description, a later live answer does not take it back, and it does not take
    /// back a description that says the session has closed.
    #[test]
    fn an_acceptance_is_kept_in_the_lifecycles_order() {
        let host = kr_ipc::testing::TempHost::create();
        let session_id = SessionId::new(Uuid::from_bytes([1; 16]));
        let mut directory = Directory::default();
        directory.insert(
            worker(&host, session_id),
            Some(described(session_id, SessionState::Live, 80)),
        );
        directory.accepted_close(
            session_id,
            Some(&described(session_id, SessionState::Closing, 100)),
        );
        directory.heard(session_id, &described(session_id, SessionState::Live, 90));
        assert_eq!(
            ending(&directory, session_id),
            Some(described(session_id, SessionState::Closing, 100))
        );

        directory.heard(
            session_id,
            &described(session_id, SessionState::Closed, 110),
        );
        directory.accepted_close(
            session_id,
            Some(&described(session_id, SessionState::Closing, 120)),
        );
        assert_eq!(
            ending(&directory, session_id),
            Some(described(session_id, SessionState::Closed, 110))
        );
    }

    /// An acceptance without a description, as a worker built before it gives one, still marks
    /// the session closing, from the description already kept.
    #[test]
    fn an_acceptance_without_a_description_marks_the_kept_one_closing() {
        let host = kr_ipc::testing::TempHost::create();
        let session_id = SessionId::new(Uuid::from_bytes([1; 16]));
        let mut directory = Directory::default();
        directory.insert(worker(&host, session_id), None);
        directory.accepted_close(session_id, None);
        assert_eq!(
            ending(&directory, session_id),
            None,
            "a session nothing described stays undescribed"
        );

        directory.heard(session_id, &described(session_id, SessionState::Live, 80));
        assert_eq!(
            ending(&directory, session_id),
            Some(described(session_id, SessionState::Closing, 80))
        );
    }
}
