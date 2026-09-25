//! The verified directory of workers this daemon knows about.
//!
//! A restarting daemon does not rebuild its picture of the host from process names or from
//! whatever files happen to be lying about. It reads the registry rows it wrote and the
//! descriptors it published, and then it asks each worker to prove itself with a fresh challenge.
//!
//! A descriptor whose challenge fails is quarantined: it stays out of the directory and is never
//! spawned from. It might be stale, or it might have been planted; the daemon cannot tell and does
//! not need to, because either way it is not a session.
//!
//! Beside each worker is what it last said about its session. A worker that has finished its
//! closure stops answering before the kernel says its process has ended, and in between that is
//! what the daemon knows of the session.
//!
//! Nothing here kills a worker. A daemon restart is not a reason to end a shell.

use std::collections::BTreeMap;

use kr_ipc::client::LocalClient;
use kr_ipc::paths::{Endpoint, EnvironmentPaths};
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::{BuildId, ControllerGeneration, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{SessionReadResult, SessionState};
use kr_protocol::worker::WorkerDescriptor;

use crate::error::Result;
use crate::registry::Registry;

/// How long one worker has to answer its challenge and accept a generation during a rebuild.
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
    /// The worker's last answer to a read, where one has reached this daemon since it started.
    read: Option<SessionReadResult>,
    /// Whether the worker accepted a close this daemon passed to it.
    closing: bool,
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
    /// Returns an error when the descriptor directory cannot be listed.
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
            match reconnect_to(&descriptor, reconnect).await {
                Ok(endpoint) => {
                    directory.verified.insert(
                        descriptor.session_id,
                        KnownWorker {
                            descriptor,
                            endpoint,
                        },
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

    /// Adds a worker the rendezvous has just established.
    pub fn insert(&mut self, worker: KnownWorker) {
        self.verified.insert(worker.descriptor.session_id, worker);
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

    /// Keeps what a worker in the directory has just said about its session.
    ///
    /// A worker that has left the directory had its closure recorded while it was being asked,
    /// and the record is the answer from then on, so what it said is not kept.
    pub fn heard(&mut self, session_id: SessionId, read: &SessionReadResult) {
        if self.verified.contains_key(&session_id) {
            self.heard.entry(session_id).or_default().read = Some(read.clone());
        }
    }

    /// Notes that a worker in the directory accepted a close this daemon passed to it.
    pub fn accepted_close(&mut self, session_id: SessionId) {
        if self.verified.contains_key(&session_id) {
            self.heard.entry(session_id).or_default().closing = true;
        }
    }

    /// Describes a session whose worker has stopped answering, where its end is under way.
    ///
    /// A worker that has finished its closure stops answering before the kernel says its process
    /// has ended, and until then no closure can be recorded. The session is what its worker last
    /// said it was, and `closing` where the worker had not said so but had accepted a close this
    /// daemon passed to it: the closure is this daemon's to record once the kernel says the worker
    /// has gone. The endpoint, the launch profile and the launches waiting on it are left out,
    /// because they are how a client reaches a worker that no longer answers.
    ///
    /// Nothing is described where no end is under way, or where the worker has not answered this
    /// daemon since it started. That is a worker this daemon cannot reach, and nothing here says
    /// what its session is now.
    #[must_use]
    pub fn ending(&self, session_id: SessionId) -> Option<SessionReadResult> {
        let heard = self.heard.get(&session_id)?;
        let mut read = heard.read.clone()?;
        match read.session.state {
            SessionState::Closing | SessionState::Closed => {}
            SessionState::Creating | SessionState::Live if heard.closing => {
                read.session.state = SessionState::Closing;
            }
            SessionState::Creating | SessionState::Live => return None,
        }
        read.endpoint = Nullable::null();
        read.launch_profile = Nullable::null();
        read.outstanding_launches = Nullable::null();
        Some(read)
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
) -> std::result::Result<Endpoint, String> {
    let endpoint = Endpoint::from_path(&descriptor.endpoint).map_err(|error| error.to_string())?;
    // Bounded, because starting the daemon must not depend on a worker that never answers. A
    // descriptor that runs out of time is quarantined like any other that fails its challenge.
    tokio::time::timeout(RECONNECT_TIMEOUT, async {
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
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "the worker did not answer its challenge in time".to_owned())??;
    Ok(endpoint)
}
