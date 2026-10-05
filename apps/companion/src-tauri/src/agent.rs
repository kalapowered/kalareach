//! The agent methods, on the session's own worker.
//!
//! A session's agent belongs to its worker. The worker's broker holds the binding, the semantic
//! history and the pending approvals, and it checks every caller's rights itself. The control
//! daemon on this machine does not carry these methods for this computer, so the application
//! reaches each session's worker over a link of its own, opened the way a raw terminal view opens
//! one ([`crate::worker::reach`]): the worker proves it holds its descriptor's key before anything
//! else crosses the link. A prompt that names a draft is the one call that does not travel here:
//! the draft and its attachments are the control daemon's, so that prompt goes through it, which
//! records where the attachments go before it passes the prompt to the worker.
//!
//! One link is held for each session and every agent call about that session goes over it, so a
//! mutation and the read that follows it travel the same connection. The client library keeps the
//! correlation, the action identifiers and the receipts on it, exactly as it does on the control
//! daemon's connection. A link that fails is let go, and the next call opens another: a worker that
//! restarted has published a new descriptor, and a session that has ended has none.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_client::{ClientError, Session};
use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::gateway::PendingResource;
use kr_protocol::ids::{AgentBindingRevision, ApplicationInstanceId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::projection::{AgentInstanceList, AgentResourceSnapshotContinuation};
use kr_protocol::recovery::{EventsSnapshotParams, EventsSnapshotResult};
use kr_protocol::scalars::Nullable;
use kr_protocol::worker::WorkerDescriptor;
use serde::Serialize;

use crate::error::{CommandError, Result};
use crate::terminal::Locate;
use crate::worker::Unreached;

/// How long opening a link may take before the call that needed it is refused.
///
/// A worker that accepts the connection and never proves its key would otherwise hold the call,
/// and every call after it for the same session, for as long as it liked.
const OPEN_DEADLINE: Duration = Duration::from_secs(10);

/// The most pages one read of a session's pending resources follows.
///
/// A page is bounded by one control frame, so this bounds the read at far more resources than a
/// session holds, and a host that answered with a continuation for ever still ends the read.
const MAX_RESOURCE_PAGES: usize = 256;

/// How many times one read of the pending resources starts again after the host let the snapshot
/// it was continuing go.
const MAX_RESOURCE_RESTARTS: usize = 2;

/// One session's link, and the worker it reaches.
struct Link {
    session: Session,
    descriptor: WorkerDescriptor,
}

/// The place one session's link is held, which the calls for that session take turns with while
/// it opens.
type Slot = Arc<tokio::sync::Mutex<Option<Arc<Link>>>>;

/// The links this application holds to its sessions' workers, one for each session.
pub struct WorkerLinks {
    locate: Locate,
    held: Mutex<BTreeMap<SessionId, Slot>>,
}

/// A session's live agent instances and the resources its broker is still arbitrating.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionAgents {
    /// The instances, as the session keeps them.
    pub instances: AgentInstanceList,
    /// Every pending resource, from every page of one snapshot of the broker's state.
    pub resources: Vec<PendingResource>,
}

impl WorkerLinks {
    /// The links to the workers of the host on this machine.
    #[must_use]
    pub fn local() -> Self {
        Self::with(Arc::new(crate::worker::this_machine))
    }

    /// The links to the workers of the host whose environment `paths` names.
    #[must_use]
    pub fn at(paths: EnvironmentPaths) -> Self {
        Self::with(Arc::new(move || Ok(paths.clone())))
    }

    pub(crate) fn with(locate: Locate) -> Self {
        Self {
            locate,
            held: Mutex::default(),
        }
    }

    /// Calls a read method on `session_id`'s worker.
    ///
    /// # Errors
    ///
    /// Returns why the worker could not be reached, or the worker's own refusal.
    pub async fn read<P, R>(&self, session_id: SessionId, method: Method, params: &P) -> Result<R>
    where
        P: Serialize + ?Sized,
        R: kr_protocol::wire::WireMessage,
    {
        let link = self.link(session_id).await?;
        let answer = link.session.read(method, params).await;
        self.settle(session_id, &link, answer)
    }

    /// Submits one agent mutation to `session_id`'s worker, about `instance` at the binding
    /// revision `binding`, and waits for the worker to settle it.
    ///
    /// The target is the worker's own: its environment, its session at its epoch, and the instance
    /// and revision the parameters name. The page supplies the parameters and nothing about the
    /// envelope, so the two can never name different things.
    ///
    /// # Errors
    ///
    /// Returns why the worker could not be reached, or what the client library returns for the
    /// submission, [`ClientError::SubmissionUncertain`] among it.
    pub async fn mutate<P>(
        &self,
        session_id: SessionId,
        instance: ApplicationInstanceId,
        binding: AgentBindingRevision,
        method: Method,
        params: &P,
    ) -> Result<std::result::Result<kr_client::Settled, ClientError>>
    where
        P: Serialize + ?Sized,
    {
        let link = self.link(session_id).await?;
        let target = ActionTarget {
            environment_id: link.descriptor.environment_id,
            session_id: Nullable::some(link.descriptor.session_id),
            session_epoch: Nullable::some(link.descriptor.session_epoch),
            application_instance_id: Nullable::some(instance),
            agent_binding_revision: Nullable::some(binding),
        };
        target
            .validate()
            .map_err(|error| CommandError::invalid(error.to_string()))?;
        let answer = link
            .session
            .mutate(
                method,
                target,
                None,
                &crate::commands::NoPreconditions {},
                params,
                crate::commands::MUTATION_TTL,
            )
            .await;
        if answer.as_ref().is_err_and(ends_the_link) {
            self.forget(session_id, &link);
        }
        Ok(answer)
    }

    /// Reads `session_id`'s live agent instances and every resource its broker is arbitrating.
    ///
    /// The resources come in pages of one snapshot; every page is read before anything is
    /// answered, so the answer is one state rather than parts of two. A snapshot the host let go
    /// part way through is started again.
    ///
    /// # Errors
    ///
    /// Returns why the worker could not be reached, or the worker's own refusal.
    pub async fn agents(&self, session_id: SessionId) -> Result<SessionAgents> {
        let mut restarts = 0;
        'snapshot: loop {
            let mut instances = None;
            let mut resources = Vec::new();
            let mut from = None;
            for _ in 0..MAX_RESOURCE_PAGES {
                let params = EventsSnapshotParams {
                    session_id,
                    agent_resources_from: Nullable(from),
                };
                let link = self.link(session_id).await?;
                let answer: std::result::Result<EventsSnapshotResult, ClientError> =
                    link.session.read(Method::EventsSnapshot, &params).await;
                let page = match answer {
                    Err(error)
                        if lets_the_snapshot_go(&error) && restarts < MAX_RESOURCE_RESTARTS =>
                    {
                        restarts += 1;
                        continue 'snapshot;
                    }
                    other => self.settle(session_id, &link, other)?,
                };
                // The instances are the snapshot's own, read with its first page.
                let listed = instances.get_or_insert(page.agent_instances);
                resources.extend(page.agent_resources.resources);
                match page.agent_resources.continue_after.0 {
                    None => {
                        return Ok(SessionAgents {
                            instances: listed.clone(),
                            resources,
                        });
                    }
                    Some(after_resource_id) => {
                        from = Some(AgentResourceSnapshotContinuation {
                            snapshot_id: page.agent_resources.snapshot_id,
                            after_resource_id,
                        });
                    }
                }
            }
            return Err(CommandError::unavailable(
                "This session's pending requests did not fit the pages one read follows.",
            ));
        }
    }

    /// Whether `session_id`'s worker on this machine is the one that serves it: whether it has
    /// published a descriptor here, rather than having ended, when the host's archive serves it.
    ///
    /// # Errors
    ///
    /// Returns why the host or the descriptor could not be read.
    pub fn serves(&self, session_id: SessionId) -> Result<bool> {
        let paths = (self.locate)().map_err(CommandError::unavailable)?;
        crate::worker::publishes(&paths, session_id).map_err(CommandError::unavailable)
    }

    /// How many sessions this application holds a link to.
    #[must_use]
    pub fn held(&self) -> usize {
        self.lock()
            .values()
            .filter(|slot| slot.try_lock().is_ok_and(|held| held.is_some()))
            .count()
    }

    /// The link to `session_id`'s worker: the one held, or a new one.
    async fn link(&self, session_id: SessionId) -> Result<Arc<Link>> {
        let slot = Arc::clone(self.lock().entry(session_id).or_default());
        let mut held = slot.lock().await;
        if let Some(link) = held.as_ref() {
            return Ok(Arc::clone(link));
        }
        let paths = (self.locate)().map_err(CommandError::unavailable)?;
        let reached = tokio::time::timeout(OPEN_DEADLINE, crate::worker::reach(&paths, session_id))
            .await
            .map_err(|_| CommandError::unavailable("This session's worker did not answer."))?
            .map_err(|unreached| match unreached {
                Unreached::NotRunning => {
                    CommandError::new(ErrorCode::UnknownSession, Unreached::NotRunning.words())
                }
                Unreached::Failed(reason) => CommandError::unavailable(reason),
            })?;
        let transport = kr_client::ipc::IpcTransport::over(reached.client);
        let session = Session::start(transport.shared())?;
        let link = Arc::new(Link {
            session,
            descriptor: reached.descriptor,
        });
        *held = Some(Arc::clone(&link));
        Ok(link)
    }

    /// Hands back what a call on `link` answered, and lets the link go when the answer says it
    /// has ended.
    fn settle<T>(
        &self,
        session_id: SessionId,
        link: &Arc<Link>,
        answer: std::result::Result<T, ClientError>,
    ) -> Result<T> {
        answer.map_err(|error| {
            if ends_the_link(&error) {
                self.forget(session_id, link);
            }
            CommandError::from(error)
        })
    }

    /// Lets `link` go, if it is still the one held for `session_id`: a call that failed on an old
    /// link does not take a new one away.
    fn forget(&self, session_id: SessionId, link: &Arc<Link>) {
        let Some(slot) = self.lock().get(&session_id).cloned() else {
            return;
        };
        if let Ok(mut held) = slot.try_lock()
            && held
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, link))
        {
            *held = None;
            link.session.close();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<SessionId, Slot>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Whether a failure means the link itself has ended, rather than that the worker refused one
/// call on a link that still stands.
fn ends_the_link(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::Transport(_)
            | ClientError::Ipc(_)
            | ClientError::ConnectionEnded
            | ClientError::SubmissionUncertain { .. }
    )
}

/// Whether a failure means the host let go of the snapshot a page was continuing.
fn lets_the_snapshot_go(error: &ClientError) -> bool {
    matches!(error, ClientError::ResyncRequired)
        || matches!(error, ClientError::Host(refusal) if refusal.code == ErrorCode::ResyncRequired)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failure of the connection lets the link go; a refusal the worker made on it does not.
    #[test]
    fn only_a_failure_of_the_connection_lets_a_link_go() {
        assert!(ends_the_link(&ClientError::ConnectionEnded));
        assert!(ends_the_link(&ClientError::SubmissionUncertain {
            action_id: kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
        }));
        for code in [
            ErrorCode::StaleSession,
            ErrorCode::PermissionDenied,
            ErrorCode::UnsupportedCapability,
            ErrorCode::DraftConflict,
        ] {
            assert!(
                !ends_the_link(&ClientError::Host(kr_protocol::error::ProtocolError::new(
                    code, "refused"
                ))),
                "{code:?}"
            );
        }
    }

    /// A snapshot the host let go is started again; any other refusal is the answer.
    #[test]
    fn only_a_snapshot_the_host_let_go_is_started_again() {
        assert!(lets_the_snapshot_go(&ClientError::ResyncRequired));
        assert!(lets_the_snapshot_go(&ClientError::Host(
            kr_protocol::error::ProtocolError::new(ErrorCode::ResyncRequired, "gone")
        )));
        assert!(!lets_the_snapshot_go(&ClientError::Host(
            kr_protocol::error::ProtocolError::new(ErrorCode::PermissionDenied, "no")
        )));
    }

    /// A session with no descriptor here is not served by a worker here, and nothing is held for
    /// it.
    #[test]
    fn a_session_with_no_descriptor_is_not_served_here() {
        let host = kr_ipc::testing::TempHost::create();
        let links = WorkerLinks::at(host.environment());
        let session = SessionId::new(kr_ipc::new_uuid());
        assert_eq!(links.serves(session), Ok(false));
        assert_eq!(links.held(), 0);
    }
}
