//! How the attention store reaches this daemon's workers and closed sessions.

use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::ids::SessionId;
use kr_protocol::local::LocalClientKind;

use crate::directory::KnownWorker;
use crate::error::{ControllerError, Result};

use super::Controller;
use super::workers::UNACCOUNTED_WORKER;

impl Controller {
    /// Opens a connection to a worker for one of the daemon's readers of it: verified, declared
    /// for `role`, and speaking for this daemon's generation.
    ///
    /// The daemon is held only to read what the connection presents and to sign its token, never
    /// across a wait for the worker, so a connection being made keeps nothing of a daemon that is
    /// stopping.
    pub(crate) async fn connect_role(
        me: &std::sync::Weak<Self>,
        worker: &KnownWorker,
        role: kr_protocol::local::ControllerConnectionRole,
    ) -> Result<LocalClient> {
        let stopping = || ControllerError::supervision("the daemon is stopping");
        let build_id = me
            .upgrade()
            .map(|controller| controller.build_id.clone())
            .ok_or_else(stopping)?;
        let mut client =
            LocalClient::connect(&worker.endpoint, LocalClientKind::Controller, build_id).await?;
        client.verify_worker(&worker.descriptor).await?;
        client
            .writer()
            .write_message(&ControlFrame::ControllerRole(role))
            .await?;
        match client.recv().await? {
            ControlFrame::ControllerRole(declared) if declared == role => {}
            _ => {
                return Err(ControllerError::supervision(format!(
                    "the worker did not accept this connection for {}",
                    role.as_str()
                )));
            }
        }
        let me = me.clone();
        client
            .present_generation(move |nonce| {
                let controller = me.upgrade().ok_or_else(|| {
                    kr_ipc::IpcError::socket(
                        "present",
                        std::io::Error::other("the daemon is stopping"),
                    )
                })?;
                controller
                    .identity
                    .generation_token(controller.generation, &controller.boot_identity, nonce)
                    .map_err(kr_ipc::IpcError::from)
            })
            .await?;
        Ok(client)
    }

    /// Returns how the attention store reaches this daemon's workers and closed sessions.
    #[must_use]
    pub fn attention_reach(&self) -> Arc<dyn crate::attention::Reach> {
        Arc::new(AttentionReach(self.me.clone()))
    }

    /// Starts the attention store's reading of every session it has to read, and its own work.
    pub(super) async fn start_attention(self: &Arc<Self>) -> Result<()> {
        self.watch_open_sessions().await?;
        // The environment's own source: the workflow journal's attention records, taken up where
        // the store and the journal left off before the timers run.
        self.attention
            .consume_automation(Arc::clone(self.automation.journal()))
            .await;
        self.attention.maintain(self.attention_reach());
        Ok(())
    }

    /// Starts the attention store's reading of every session it has to read: the live ones over
    /// their workers, and the ones whose closure an earlier daemon recorded and which the store has
    /// not finished yet.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub(super) async fn watch_open_sessions(self: &Arc<Self>) -> Result<()> {
        let reach = self.attention_reach();
        // In one section under the registry's lock, as a worker is made known (`publish_worker`):
        // a closure recorded after this section has the worker's tidying still to run, and the
        // tidying stops what this starts, and one recorded before it is found here and the store
        // does not read the session at a worker.
        let registry = self.registry.lock().await;
        let live = self.workers_without_a_closure(&registry).await?;
        let live_sessions: std::collections::BTreeSet<SessionId> = live
            .iter()
            .map(|worker| worker.descriptor.session_id)
            .collect();
        for worker in live {
            self.attention.watch(Arc::clone(&reach), worker);
        }
        // A session the store holds that has no worker here is one of two things. Its closure is
        // recorded, and the store finishes it; or it is not, and its timers wait for something to
        // say what happened to it.
        for session_id in self.attention.open_sessions() {
            if live_sessions.contains(&session_id) {
                continue;
            }
            if registry.closure(session_id)?.is_some() {
                let module = Arc::clone(&self.attention);
                let reach = Arc::clone(&reach);
                tokio::spawn(async move {
                    module.session_closed(reach.as_ref(), session_id).await;
                });
            }
        }
        drop(registry);
        Ok(())
    }
}

/// How the attention store reaches this daemon's workers and its closed sessions.
struct AttentionReach(std::sync::Weak<Controller>);

impl crate::attention::Reach for AttentionReach {
    /// Opens a connection to a worker for the attention store: verified, declared for attention,
    /// and speaking for this daemon's generation.
    ///
    /// The daemon is held only to read what the connection presents and to sign its token, never
    /// across a wait for the worker, so a connection being made keeps nothing of a daemon that is
    /// stopping.
    fn connect<'a>(
        &'a self,
        worker: &'a KnownWorker,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<LocalClient>> + Send + 'a>> {
        Box::pin(Controller::connect_role(
            &self.0,
            worker,
            kr_protocol::local::ControllerConnectionRole::Attention,
        ))
    }

    fn unaccounted<'a>(
        &'a self,
        session_id: SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let Some(controller) = self.0.upgrade() else {
                return true;
            };
            // The closure is the fact: a worker's own handover and a closure after a death this
            // host confirmed name no unaccounted worker, and a worker still on its way out after
            // handing over does not change that. A closure this host cannot read ends nothing.
            let closure = controller.registry.lock().await.closure(session_id);
            match closure {
                Ok(Some(closure)) => closure
                    .surviving
                    .iter()
                    .any(|resource| resource.kind == UNACCOUNTED_WORKER),
                Ok(None) | Err(_) => true,
            }
        })
    }

    fn closed_journal(&self, session_id: SessionId) -> Option<kr_worker::journal::Journal> {
        let controller = self.0.upgrade()?;
        // A session that closed under an earlier build wrote an earlier schema, and the archive
        // brings it forward once, under this daemon's ownership of a session with no worker.
        controller.archive().bring_forward(session_id);
        kr_worker::journal::Journal::open_read_only(controller.paths.journal_database(session_id))
            .ok()
    }

    fn output_floor(&self, session_id: SessionId) -> Option<u64> {
        let controller = self.0.upgrade()?;
        kr_worker::history::OutputHistory::read_spool(
            controller.paths.session_spool(session_id),
            kr_worker::history::SpoolLayout::DEFAULT,
        )
        .ok()
        .map(|history| history.oldest_retained_cursor())
    }
}
