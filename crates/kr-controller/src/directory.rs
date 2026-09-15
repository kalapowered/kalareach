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
//! Nothing here kills a worker. A daemon restart is not a reason to end a shell.

use std::collections::BTreeMap;

use kr_ipc::client::LocalClient;
use kr_ipc::paths::{Endpoint, EnvironmentPaths};
use kr_protocol::ids::{BuildId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::worker::WorkerDescriptor;

use crate::error::Result;
use crate::registry::Registry;

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

/// The result of rebuilding the directory.
#[derive(Debug, Default)]
pub struct Directory {
    /// Workers that answered their challenge.
    pub verified: BTreeMap<SessionId, KnownWorker>,
    /// Descriptors that did not, which are never spawned from.
    pub quarantined: Vec<Quarantined>,
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
        build_id: &BuildId,
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
            match verify(&descriptor, build_id).await {
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

    /// Removes a worker whose session has closed.
    pub fn remove(&mut self, session_id: SessionId) {
        self.verified.remove(&session_id);
    }

    /// Returns every verified worker.
    pub fn iter(&self) -> impl Iterator<Item = &KnownWorker> {
        self.verified.values()
    }
}

async fn verify(
    descriptor: &WorkerDescriptor,
    build_id: &BuildId,
) -> std::result::Result<Endpoint, String> {
    let endpoint = Endpoint::from_path(&descriptor.endpoint).map_err(|error| error.to_string())?;
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Controller, build_id.clone())
        .await
        .map_err(|error| error.to_string())?;
    client
        .verify_worker(descriptor)
        .await
        .map_err(|error| error.to_string())?;
    Ok(endpoint)
}
