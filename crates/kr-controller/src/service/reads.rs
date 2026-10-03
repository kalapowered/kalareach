//! Reading sessions: the list, a read, and what a closed session left behind.

use std::sync::Arc;

use kr_protocol::envelope::{ControlFrame, ParamsValue, Request};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{ActorId, EnvironmentId, SessionId};
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::session::{
    ClosureRecord, SessionListParams, SessionListResult, SessionReadParams, SessionReadResult,
    SessionState, SessionSummary,
};

use crate::directory::KnownWorker;
use crate::error::{ControllerError, Result};
use crate::registry::LaunchPhase;

use super::workers::{UNACCOUNTED_WORKER, WORKER_EXCHANGE};
use super::{Controller, encode, parse};

impl Controller {
    pub(super) async fn session_list(
        self: &Arc<Self>,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: SessionListParams = parse(params)?;
        // Any worker that has started answering since the last attempt rejoins the directory here,
        // so a list is the current picture rather than the picture at startup. A claim this daemon
        // could not resolve when it started is looked at again for the same reason.
        let _ = self.recover_claims().await;
        let _ = self.recover_workers().await;
        let mut sessions = Listed::default();
        // The sessions the pass over the workers has settled, whether it listed them or not: a
        // session whose worker said it is closed is not one this daemon lists as live because its
        // closure is not recorded yet, and one whose closure is recorded is the closed pass's.
        let mut settled = std::collections::BTreeSet::new();
        let workers: Vec<KnownWorker> = self.directory.lock().await.iter().cloned().collect();
        for worker in workers {
            let session_id = worker.descriptor.session_id;
            // A worker that is connected and does not answer holds the list for two exchanges, and
            // no longer: every other session is listed whatever it does. Two, because the daemon's
            // own link to the worker can be held by an exchange of its own, which takes up to one,
            // and the read then waits for its turn and for the answer.
            let session = match self
                .read_from_worker_within(&worker, Some(WORKER_EXCHANGE * 2))
                .await
            {
                Ok(read) => {
                    settled.insert(session_id);
                    Some(read.session)
                }
                // As for a read, and in the same order: a session whose closure is recorded is
                // listed with the closed sessions below, and one whose worker is on its way out is
                // listed as this daemon last knew it. Short of either, the worker cannot be
                // reached and nothing says its session has ended, so the session is not settled
                // here: it is listed below from what this daemon holds of it.
                Err(_) => match self.reconcile(session_id).await {
                    Ok(Some(_)) => {
                        settled.insert(session_id);
                        None
                    }
                    Ok(None) => {
                        let ending = self.directory.lock().await.ending(session_id);
                        let recorded = self.registry.lock().await.closure(session_id);
                        match (recorded, ending) {
                            (Ok(None), Some(read)) => {
                                settled.insert(session_id);
                                Some(read.session)
                            }
                            _ => None,
                        }
                    }
                    Err(_) => None,
                },
            };
            // A session that has closed is listed only where closed sessions were asked for,
            // whether its worker said so or this daemon's record did.
            if let Some(session) = session
                && (params.include_closed || session.state != SessionState::Closed)
            {
                sessions.describe(session);
            }
        }
        for session in self.unresolved_sessions(&settled).await? {
            sessions.describe_unless_described(session);
        }
        // The closed sessions last: a session whose closure was recorded while this list was being
        // made is described from its closure, whatever the passes before it said of it.
        if params.include_closed {
            let mut closed = Vec::new();
            let registry = self.registry.lock().await;
            for reservation in registry.closed_reservations()? {
                if let Some(closure) = registry.closure(reservation.session_id)? {
                    closed.push((closure, reservation.display_number));
                }
            }
            drop(registry);
            for (closure, display_number) in closed {
                // A closure recorded after a worker described the session as it was is the later
                // word on it.
                sessions.describe(self.closed_session(&closure, display_number).await);
            }
        }
        encode(&SessionListResult {
            sessions: sessions.into_sorted(),
        })
    }

    pub(super) async fn session_read(
        self: &Arc<Self>,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: SessionReadParams = parse(params)?;
        // A worker that did not answer at startup is not gone; it was busy, or it started slowly.
        // Trying again here is what keeps a session readable without another daemon restart.
        if self.directory.lock().await.get(params.session_id).is_none() {
            // This session's own claim, and the reason when it cannot be resolved: a caller that
            // named one session is owed that rather than "no such session".
            self.recover_claim_for(params.session_id).await?;
            let _ = self.recover_workers().await;
        }
        let worker = self.directory.lock().await.get(params.session_id).cloned();
        if let Some(worker) = worker {
            match self.read_from_worker(&worker).await {
                Ok(read) => {
                    return encode(&SessionReadResult {
                        session: read.session,
                        endpoint: Nullable::some(worker.endpoint.as_text()),
                        launch_profile: read.launch_profile,
                        last_command_block: read.last_command_block,
                        outstanding_launches: read.outstanding_launches,
                    });
                }
                // A worker that cannot be reached is not necessarily gone. Reconciliation asks the
                // kernel; only a confirmed death produces a closure record.
                //
                // Short of that, the session is answered from this daemon's own record rather than
                // with the failed connection. A worker that has finished its closure stops
                // answering before the kernel says it has ended, and a read that meets it on its
                // way out is owed the session's state: its closure where one was recorded
                // meanwhile, by the close's watcher or another path, and otherwise the session
                // closing (`Directory::ending`). Only where this daemon has no word of an end is
                // there nothing to answer with, and that read is refused as one to try again.
                //
                // The directory is asked before the registry. A closure is written to the registry
                // before its worker leaves the directory, so a worker found gone from the
                // directory has its closure in the registry by the time the registry is asked, and
                // the closure is the answer wherever there is one.
                Err(error) => {
                    if self.reconcile(params.session_id).await?.is_none() {
                        #[cfg(test)]
                        self.before_the_record.wait().await;
                        let ending = self.directory.lock().await.ending(params.session_id);
                        let recorded = self.registry.lock().await.closure(params.session_id)?;
                        if recorded.is_none() {
                            return match ending {
                                Some(read) => encode(&read),
                                None => Err(error),
                            };
                        }
                    }
                }
            }
        }
        // A closed session answers with its record. It never starts anything.
        let registry = self.registry.lock().await;
        let closure = registry.closure(params.session_id)?;
        // The reservation row outlives the worker row, so a closed session keeps the number it was
        // listed under.
        let display = registry
            .reservation_for_session(params.session_id)?
            .map(|reservation| reservation.display_number);
        drop(registry);
        match closure {
            Some(closure) => {
                let display = display.unwrap_or(kr_protocol::session::DisplayNumber::new(0));
                encode(&SessionReadResult {
                    session: self.closed_session(&closure, display).await,
                    endpoint: Nullable::null(),
                    launch_profile: Nullable::null(),
                    last_command_block: Nullable::null(),
                    outstanding_launches: Nullable::null(),
                })
            }
            None => Err(ControllerError::UnknownSession {
                session: params.session_id.to_string(),
            }),
        }
    }

    /// Serves one page of a closed session's retained output.
    ///
    /// KR-ACC-029: a history request never creates a worker. A session whose worker is alive is
    /// refused here with the endpoint to ask, because that worker owns its own spool and reading
    /// it from outside would be a second reader of a store that is still being written.
    pub(super) async fn archive_history_page(
        self: &Arc<Self>,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::recovery::HistoryPageParams = parse(params)?;
        self.refuse_if_live(params.session_id).await?;
        let page = self.archive().history_page(
            params.session_id,
            params.from_cursor.get(),
            params.max_bytes.get(),
        )?;
        encode(&page)
    }

    /// Answers `action.read` for a catalogue action this actor performed, where there is one.
    ///
    /// `None` is a request this does not answer: one that names a session, or an action the
    /// catalogue holds no receipt for.
    pub(super) async fn host_action_read(
        self: &Arc<Self>,
        actor_id: &ActorId,
        request: &Request,
    ) -> Option<ControlFrame> {
        let params: kr_protocol::receipt::ActionReadParams = request.params.to_typed().ok()?;
        if params.session_id.is_some() {
            return None;
        }
        match self.catalogue.action_read(actor_id, params.action_id).await {
            Ok(Some(read)) => Some(crate::catalogue::frame(
                request.request_id,
                ParamsValue::from_typed(&read).map_err(|error| {
                    ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string())
                }),
            )),
            Ok(None) => None,
            Err(error) => Some(crate::catalogue::frame(request.request_id, Err(error))),
        }
    }

    /// Serves one retained receipt of a closed session, as `owner` says its reader may be shown it:
    /// whole to the owner at this machine, and as the state of the action alone to anybody else.
    pub(super) async fn archive_action_read(
        self: &Arc<Self>,
        actor_id: &ActorId,
        params: &ParamsValue,
        owner: bool,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::receipt::ActionReadParams = parse(params)?;
        let Some(session_id) = params.session_id else {
            return Err(ControllerError::InvalidArgument(
                "a receipt this daemon serves belongs to a session, which this request does not \
                 name"
                    .to_owned(),
            ));
        };
        self.refuse_if_live(session_id).await?;
        let read = self
            .archive()
            .receipt(session_id, actor_id, params.action_id, owner)?;
        encode(&read)
    }

    /// Refuses a read of a session whose worker this daemon has not confirmed gone.
    ///
    /// Three things can say so, and a closure erases two of them: writing it removes the
    /// registry's worker row and retires the published descriptor. So the closure carries the
    /// third itself. A session closed without a confirmed death lists its worker as a surviving
    /// resource rather than a terminated one, and that is what this reads once the other two are
    /// gone.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument refusal naming what this host has not established.
    async fn refuse_if_live(self: &Arc<Self>, session_id: SessionId) -> Result<()> {
        if self.a_worker_may_still_own(session_id).await? {
            return Err(ControllerError::InvalidArgument(format!(
                "session {session_id} has a worker this daemon has not confirmed ended"
            )));
        }
        Ok(())
    }

    /// Returns whether anything this host can read says the session's worker may still be there.
    ///
    /// This is the one question every read and every migration asks. It is deliberately
    /// pessimistic: a query the platform declines establishes nothing, and nothing is the answer
    /// that keeps a store shut.
    async fn a_worker_may_still_own(self: &Arc<Self>, session_id: SessionId) -> Result<bool> {
        let (row, closure) = {
            let registry = self.registry.lock().await;
            // A registry this host cannot read answers nothing, and nothing is not "no worker".
            // Both reads are propagated rather than flattened away, because the caller refusing
            // with the registry's own error is the safe end of that.
            let row = registry
                .workers()?
                .into_iter()
                .find(|row| row.session_id == session_id);
            (row, registry.closure(session_id)?)
        };
        if let Some(row) = row
            && !matches!(
                kr_ipc::identity::process_state(&row.process_identity),
                kr_ipc::identity::ProcessState::Ended
            )
        {
            return Ok(true);
        }
        if let Some(closure) = closure
            && closure
                .surviving
                .iter()
                .any(|resource| resource.kind == UNACCOUNTED_WORKER)
        {
            return Ok(true);
        }
        Ok(self.archive().a_worker_may_still_own(session_id))
    }

    /// Reads what one session left behind, with the registry's own record beside it.
    ///
    /// A crashed worker never wrote its own closure and the record this host wrote for it is in
    /// the registry, so the archive is given it rather than left to report a closure as missing
    /// that this host is holding.
    ///
    /// # Errors
    ///
    /// Returns the registry's refusal, or the archive's.
    pub async fn session_archive(
        self: &Arc<Self>,
        session_id: SessionId,
    ) -> Result<crate::archive::Archive> {
        // The same question every archive read asks first. A session whose registry record names
        // a process this daemon has not seen end is refused here rather than read from: the
        // worker owns its own stores while it is alive, and a closure written over a death this
        // host could not confirm is not a licence to open them.
        self.refuse_if_live(session_id).await?;
        let recorded = self.registry.lock().await.closure(session_id)?;
        self.archive().archive_beside(session_id, recorded)
    }

    /// Reads the closure a worker wrote for itself, when one survived it.
    pub(super) fn recovered_closure(&self, session_id: SessionId) -> Option<ClosureRecord> {
        self.archive().bring_forward(session_id);
        let path = self.paths.journal_database(session_id);
        let journal = kr_worker::journal::Journal::open_read_only(&path).ok()?;
        journal.read_closure(session_id).ok().flatten()
    }

    /// Reads the session a worker described, when its journal survived it.
    fn recovered_summary(&self, session_id: SessionId) -> Option<SessionSummary> {
        // A session that closed before this build shipped wrote an earlier schema. The archive
        // brings such a store forward once, under this daemon's ownership of a session with no
        // worker, so the shell, the directory, the geometry and the creation time it holds are
        // still what a person is shown.
        self.archive().bring_forward(session_id);
        let path = self.paths.journal_database(session_id);
        let journal = kr_worker::journal::Journal::open_read_only(&path).ok()?;
        journal.read_session(session_id).ok().flatten()
    }

    /// Describes a closed session from what its worker recorded, or from what is left.
    pub(super) async fn closed_session(
        &self,
        closure: &ClosureRecord,
        display_number: kr_protocol::session::DisplayNumber,
    ) -> SessionSummary {
        // The worker recorded what its session was. Using it keeps the shell, the directory, the
        // geometry and the creation time a person sees after the session has closed - but only
        // where this host established that the worker ended. A closure this host wrote over a
        // death it could not confirm says so in its own surviving list, and then the store stays
        // shut and the summary is built from the closure alone.
        if closure
            .surviving
            .iter()
            .any(|resource| resource.kind == UNACCOUNTED_WORKER)
        {
            return closed_summary(closure, self.paths.environment_id(), display_number);
        }
        self.recovered_summary(closure.session_id).map_or_else(
            || closed_summary(closure, self.paths.environment_id(), display_number),
            |mut summary| {
                summary.state = SessionState::Closed;
                summary.attachment_count = U64::ZERO;
                summary.application_state = Nullable::null();
                summary.root_process = Nullable::null();
                summary.closure = Nullable::some(closure.clone());
                summary
            },
        )
    }
}

/// The sessions a list describes, one for each session identifier.
///
/// A session is described by its worker, by its closure, or from the registry's rows when neither
/// does, and a list takes those one pass after another. Holding them by identifier makes a
/// session listed twice impossible however the passes interleave with a closure being recorded: a
/// closure replaces what a worker said of the session before it, and a description from the
/// registry's rows never replaces another.
#[derive(Default)]
struct Listed(std::collections::BTreeMap<SessionId, SessionSummary>);

impl Listed {
    /// Describes a session, replacing any earlier description of it.
    fn describe(&mut self, session: SessionSummary) {
        self.0.insert(session.session_id, session);
    }

    /// Describes a session unless it is already described.
    fn describe_unless_described(&mut self, session: SessionSummary) {
        self.0.entry(session.session_id).or_insert(session);
    }

    /// The descriptions, by display number.
    fn into_sorted(self) -> Vec<SessionSummary> {
        let mut sessions: Vec<SessionSummary> = self.0.into_values().collect();
        sessions.sort_by_key(|session| session.display_number.get());
        sessions
    }
}

impl Controller {
    /// Describes every session this daemon holds that no worker described and no closure covers.
    ///
    /// A list is every session the registry holds that has not closed, which is what `host.info`
    /// counts as live or creating: a worker that cannot be reached now is no less the session's, a
    /// create whose worker has not reported is a session being created, and a reservation
    /// recovery has not resolved still occupies a place. Each is described from the registry's own
    /// rows ([`unresolved_summary`]) and none is described as more than they say.
    async fn unresolved_sessions(
        &self,
        settled: &std::collections::BTreeSet<SessionId>,
    ) -> Result<Vec<SessionSummary>> {
        let registry = self.registry.lock().await;
        let workers = registry.workers()?;
        let mut described = Vec::new();
        for phase in [
            LaunchPhase::Reserved,
            LaunchPhase::Spawned,
            LaunchPhase::Claimed,
            LaunchPhase::Live,
            LaunchPhase::Fenced,
        ] {
            for reservation in registry.reservations_in(phase)? {
                let session_id = reservation.session_id;
                if settled.contains(&session_id) || registry.closure(session_id)?.is_some() {
                    continue;
                }
                let worker = workers.iter().find(|row| row.session_id == session_id);
                let desktop = registry.desktop_of(session_id)?;
                described.push(unresolved_summary(
                    self.paths.environment_id(),
                    &reservation,
                    worker,
                    desktop,
                ));
            }
        }
        Ok(described)
    }
}

/// Describes one session from the registry's rows alone, when nothing else describes it.
///
/// The state is the registry's: creating until a worker has reported, live after, as the worker's
/// row records it, and closing for a reservation this daemon fenced, whose worker it never reaches
/// again and whose end it is resolving. The shell, the directory, the geometry and the profile are
/// what the create asked for, where it named them: a choice it left to the host is not known here,
/// so the shell and the directory read empty and the geometry the invisible default, as for a
/// closed session whose worker did not describe it. Nothing else of a session is known without its
/// worker, so it has no attachments, no application and no root process.
fn unresolved_summary(
    environment_id: EnvironmentId,
    reservation: &crate::registry::Reservation,
    worker: Option<&crate::registry::WorkerRecord>,
    desktop: Option<kr_protocol::identity::DesktopBinding>,
) -> SessionSummary {
    let state = match reservation.phase {
        LaunchPhase::Reserved | LaunchPhase::Spawned | LaunchPhase::Claimed => {
            SessionState::Creating
        }
        LaunchPhase::Live => worker.map_or(SessionState::Live, |row| row.state),
        LaunchPhase::Fenced => SessionState::Closing,
        LaunchPhase::Failed | LaunchPhase::Closed => SessionState::Closed,
    };
    let intent = reservation
        .create_intent
        .as_deref()
        .and_then(|recorded| super::create::recorded_create(recorded).ok());
    SessionSummary {
        session_id: reservation.session_id,
        session_epoch: kr_protocol::ids::SessionEpoch::V1,
        environment_id,
        display_number: reservation.display_number,
        state,
        shell_mode: intent
            .as_ref()
            .map_or(kr_protocol::session::ShellMode::NativeCompat, |create| {
                create.shell_mode
            }),
        shell_path: intent
            .as_ref()
            .and_then(|create| create.shell.as_ref().cloned())
            .unwrap_or_default(),
        cwd: intent
            .as_ref()
            .and_then(|create| create.cwd.as_ref().cloned())
            .unwrap_or_default(),
        worker_profile: worker.map(|row| row.profile).unwrap_or_else(|| {
            intent
                .as_ref()
                .map_or(WorkerProfile::HeadlessUser, |create| create.worker_profile)
        }),
        desktop: desktop.unwrap_or_else(kr_protocol::identity::DesktopBinding::none),
        created_at_ms: reservation.created_at_ms,
        dimensions: intent
            .as_ref()
            .and_then(|create| create.dimensions.as_ref().copied())
            .unwrap_or(kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS),
        attachment_count: U64::ZERO,
        application_state: Nullable::null(),
        root_process: Nullable::null(),
        closure: Nullable::null(),
        // The registry's rows do not hold where its environment came from.
        environment_sources: None,
    }
}

fn closed_summary(
    closure: &ClosureRecord,
    environment_id: EnvironmentId,
    display_number: kr_protocol::session::DisplayNumber,
) -> SessionSummary {
    SessionSummary {
        session_id: closure.session_id,
        session_epoch: closure.session_epoch,
        environment_id,
        display_number,
        state: SessionState::Closed,
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        shell_path: String::new(),
        cwd: String::new(),
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        created_at_ms: closure.closed_at_ms,
        dimensions: kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS,
        attachment_count: U64::ZERO,
        application_state: Nullable::null(),
        root_process: Nullable::null(),
        closure: Nullable::some(closure.clone()),
        environment_sources: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(session: u8, display: u64, state: SessionState) -> SessionSummary {
        let mut summary = closed_summary(
            &super::super::a_read_that_meets_a_worker_on_its_way_out::closure_of(SessionId::new(
                kr_protocol::scalars::Uuid::from_bytes([session; 16]),
            )),
            EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
            kr_protocol::session::DisplayNumber::new(display),
        );
        summary.state = state;
        summary
    }

    /// A session a worker described and whose closure was recorded after it is listed once, as the
    /// closure has it; a description from the registry's rows never replaces another; and the list
    /// is in display order, not in the order of the identifiers, which here run the other way.
    #[test]
    fn a_session_is_listed_once_however_the_passes_describe_it() {
        let mut listed = Listed::default();
        listed.describe(summary(3, 2, SessionState::Live));
        listed.describe(summary(2, 1, SessionState::Live));
        // The closure of the session numbered 2 is recorded after its worker described it.
        listed.describe(summary(3, 2, SessionState::Closed));
        // The registry's rows describe the session numbered 1 as creating, and a session no worker
        // described.
        listed.describe_unless_described(summary(2, 1, SessionState::Creating));
        listed.describe_unless_described(summary(1, 3, SessionState::Creating));

        let sessions = listed.into_sorted();
        assert_eq!(
            sessions
                .iter()
                .map(|session| (session.display_number.get(), session.state))
                .collect::<Vec<_>>(),
            vec![
                (1, SessionState::Live),
                (2, SessionState::Closed),
                (3, SessionState::Creating)
            ]
        );
    }
}
