//! The rounds of plugin admissions this daemon sends its workers, and the answers it uses.
//!
//! A worker is handed its first snapshot with its launch specification, and every later one on
//! this daemon's authority connection to it: after it is recorded or adopted, after every change
//! that raises the admission revision, and on a cadence while it is pending, reports a release no
//! installation describes, or reports a binding due to end, which closes only at a snapshot. Each
//! round is bounded: a worker that does not answer in time stays pending, and the next round
//! follows on the cadence. Nothing is evicted on a guess.

use std::sync::Arc;

use kr_protocol::admission::{LiveRelease, PluginAdmissions};
use kr_protocol::catalogue::PluginLeftOutReason;
use kr_protocol::ids::SessionId;

use crate::catalogue::admissions::Snapshot;
use crate::catalogue::bridge::{Acceptance, LiveView, Report};

use super::{Controller, LaunchPhase, UNACCOUNTED_WORKER, WORKER_EXCHANGE};

/// How often the cadence asks again: every member that needs one a round, and the kernel about
/// every member whose end is not confirmed.
pub(crate) const ADMISSIONS_CADENCE: std::time::Duration = std::time::Duration::from_secs(30);

/// How many rounds one member is sent in a row while each answer discovers a release the round
/// before did not cover.
const DISCOVERY_ROUNDS: usize = 4;

impl Controller {
    /// Returns every release a worker reported live.
    fn reported_live(&self) -> Vec<LiveRelease> {
        self.plugin_bridge
            .live()
            .into_values()
            .map(|(release, _)| release)
            .collect()
    }

    /// Computes the admissions in force now, within one bounded exchange of `start`, or `None`
    /// with the refusal recorded for the doctor.
    pub(super) async fn current_snapshot(&self, start: tokio::time::Instant) -> Option<Snapshot> {
        let live = self.reported_live();
        match self
            .catalogue
            .snapshot_within(&live, start + WORKER_EXCHANGE)
            .await
        {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                self.note_admissions(format!(
                    "the admissions could not be computed: {}",
                    error.message
                ));
                None
            }
        }
    }

    /// The catalogue's evidence for the doctor: each enrolled repository, each installation the
    /// admissions in force leave out for a reason other than being disabled, each package a worker
    /// said it would not read, bind or use in full, with its session, and each set of admissions
    /// this daemon could not hand over.
    pub(crate) async fn catalogue_evidence(&self) -> crate::catalogue::evidence::Evidence {
        let start = tokio::time::Instant::now();
        let deadline = start + WORKER_EXCHANGE;
        let mut warnings = Vec::new();
        let repositories = match self.catalogue.evidence_within(deadline).await {
            Ok(repositories) => repositories,
            Err(error) => {
                warnings.push(format!(
                    "the catalogue's records could not be read: {}",
                    error.message
                ));
                Vec::new()
            }
        };
        if let Some(snapshot) = self.current_snapshot(start).await {
            warnings.extend(
                snapshot
                    .left_out
                    .iter()
                    // A disabled installation is its owner's decision, and nothing anybody needs
                    // telling.
                    .filter(|left| left.reason != PluginLeftOutReason::Disabled)
                    .map(|left| format!("{}, so no new binding uses it", left.detail)),
            );
        }
        for (session_id, refusal) in self.plugin_bridge.refusals() {
            warnings.push(format!(
                "session {session_id} could not use all of the package {}: {}{}",
                kr_plugin_sdk::digest::PayloadDigest::from_bytes(
                    *refusal.package_digest.as_bytes()
                ),
                refusal.detail,
                if refusal.detail_cut {
                    " (cut short)"
                } else {
                    ""
                }
            ));
        }
        warnings.extend(
            self.admission_notes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .cloned(),
        );
        crate::catalogue::evidence::Evidence {
            repositories,
            warnings,
        }
    }

    /// Records why admissions could not be handed over, for the doctor's catalogue check.
    pub(super) fn note_admissions(&self, why: String) {
        let mut notes = self
            .admission_notes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        notes.push(why);
        let excess = notes.len().saturating_sub(16);
        notes.drain(..excess);
    }

    /// The first snapshot a worker is handed, with its launch specification, once its
    /// reservation's claim is consumed. The member was added when the claim committed, so a
    /// reclaim that needs room waits for it from there on.
    pub(super) async fn first_admissions(&self, session_id: SessionId) -> Vec<PluginAdmissions> {
        let start = tokio::time::Instant::now();
        let snapshot = match self.current_snapshot(start).await {
            Some(snapshot) => snapshot,
            None => Snapshot::nothing(
                self.catalogue
                    .admission_revision_within(start + WORKER_EXCHANGE)
                    .await
                    .unwrap_or(0),
            ),
        };
        let frame =
            self.plugin_bridge
                .first_frame(session_id, snapshot.revision, snapshot.covered());
        let environment_id = self.paths.environment_id();
        match snapshot.parts(environment_id, frame) {
            Ok(parts) => parts,
            Err(why) => {
                self.note_admissions(format!("session {session_id}: {why}"));
                Snapshot::nothing(snapshot.revision)
                    .parts(environment_id, frame)
                    .unwrap_or_default()
            }
        }
    }

    /// Sends one recorded member a round at the current revision and uses its answer, and sends it
    /// the next round at once while its answers discover releases the round did not cover.
    pub(crate) async fn admissions_round(&self, session_id: SessionId) {
        for _ in 0..DISCOVERY_ROUNDS {
            if self.one_round(session_id).await != Some(Acceptance::Discovered) {
                return;
            }
        }
    }

    /// One round: the snapshot, a frame this round owns, the exchange, and the answer used.
    ///
    /// It runs on a task of its own and is never cut part way by a caller that stopped waiting:
    /// every step is bounded by itself, and a client whose exchange did not finish is retired, so
    /// the next round opens a connection whose position is known.
    async fn one_round(&self, session_id: SessionId) -> Option<Acceptance> {
        let snapshot = self.current_snapshot(tokio::time::Instant::now()).await?;
        let frame =
            self.plugin_bridge
                .next_frame(session_id, snapshot.revision, snapshot.covered())?;
        let parts = match snapshot.parts(self.paths.environment_id(), frame) {
            Ok(parts) => parts,
            Err(why) => {
                self.note_admissions(format!("session {session_id}: {why}"));
                return self.unanswered(session_id);
            }
        };
        let answered =
            match tokio::time::timeout(WORKER_EXCHANGE, self.worker_client_of(session_id)).await {
                Ok(Ok(mut held)) => {
                    let exchanged = match held.as_mut() {
                        Some(client) => client.exchange_admissions(parts, WORKER_EXCHANGE).await,
                        None => return self.unanswered(session_id),
                    };
                    match exchanged {
                        Ok(report) => Some(report),
                        Err(_) => {
                            // A client whose stream position nothing knows is retired, as an
                            // announcement retires one.
                            *held = None;
                            None
                        }
                    }
                }
                Ok(Err(_)) | Err(_) => None,
            };
        let Some(parts) = answered else {
            return self.unanswered(session_id);
        };
        let Some(first) = parts.first() else {
            return self.unanswered(session_id);
        };
        if first.session_id != session_id {
            return self.unanswered(session_id);
        }
        let report = Report {
            frame: first.frame,
            report_seq: first.report_seq.get(),
            bindings: parts
                .iter()
                .flat_map(|part| part.bindings.iter().cloned())
                .collect(),
            refusals: parts
                .iter()
                .flat_map(|part| part.refusals.iter().cloned())
                .collect(),
        };
        Some(self.plugin_bridge.accept(session_id, report))
    }

    fn unanswered(&self, session_id: SessionId) -> Option<Acceptance> {
        self.plugin_bridge.unanswered(session_id);
        None
    }

    /// Sends each of `members` a round, each on a task of its own, and waits for them all, or
    /// until `deadline` where there is one.
    ///
    /// A round still running at the deadline is left to finish rather than cut part way: each
    /// exchange is bounded by itself, and one cut between two frames would leave the connection
    /// at a position nothing knows.
    async fn rounds_to(&self, members: Vec<SessionId>, deadline: Option<tokio::time::Instant>) {
        let Some(controller) = self.me.upgrade() else {
            return;
        };
        // Handles, never a set that aborts its tasks when dropped: a caller that stops waiting (a
        // refresh past its deadline, a connection that went away) leaves each round to finish on
        // its own bound.
        let rounds: Vec<tokio::task::JoinHandle<()>> = members
            .into_iter()
            .map(|session_id| {
                let controller = Arc::clone(&controller);
                tokio::spawn(async move { controller.admissions_round(session_id).await })
            })
            .collect();
        drop(controller);
        let all = async {
            for round in rounds {
                let _ = round.await;
            }
        };
        match deadline {
            None => all.await,
            Some(deadline) => {
                let _ = tokio::time::timeout_at(deadline, all).await;
            }
        }
    }

    /// Asks every recorded member for a report now, and counts what the reports used after the
    /// read began say: every member answers within one bounded exchange, or the counts are
    /// unknown. A member with a round already out is not sent a second one; its answer counts.
    pub(crate) async fn refreshed_view(&self) -> LiveView {
        // One bound from entry covers the whole read: the wait for the catalogue, the rounds and
        // the wait for rounds already out.
        let deadline = tokio::time::Instant::now() + WORKER_EXCHANGE;
        let mark = self.plugin_bridge.mark();
        let Ok(revision) = self.catalogue.admission_revision_within(deadline).await else {
            return LiveView {
                revision: 0,
                live: self.plugin_bridge.live(),
                counts: None,
                admissions: None,
            };
        };
        let asked: Vec<SessionId> = self
            .plugin_bridge
            .recorded_members()
            .into_iter()
            .filter(|session_id| !self.plugin_bridge.in_flight(*session_id))
            .collect();
        self.rounds_to(asked, Some(deadline)).await;
        while !self.plugin_bridge.answered_since(mark) && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        LiveView {
            revision,
            live: self.plugin_bridge.live(),
            counts: self.plugin_bridge.counts_since(mark, revision),
            admissions: None,
        }
    }

    /// One pass of the cadence: a round to every recorded member that is pending, reports a
    /// release no installation describes or reports a binding due to end, and a question to the
    /// kernel about every member whose end is not confirmed.
    pub(crate) async fn admissions_pass(&self) {
        // The kernel first: letting go of an ended member waits for nothing else.
        self.check_unconfirmed_members();
        let deadline = tokio::time::Instant::now() + WORKER_EXCHANGE;
        let Ok((revision, installed)) = self.catalogue.installed_within(deadline).await else {
            return;
        };
        let due: Vec<SessionId> = self
            .plugin_bridge
            .recorded_members()
            .into_iter()
            .filter(|session_id| {
                self.plugin_bridge
                    .needs_round(*session_id, revision, &|release| {
                        installed.contains(release)
                    })
            })
            .collect();
        self.rounds_to(due, None).await;
    }

    /// Asks the kernel about every member whose end is not confirmed, and lets go of each whose
    /// process has ended.
    fn check_unconfirmed_members(&self) {
        for (session_id, process) in self.plugin_bridge.to_check() {
            let ended = process.as_ref().is_none_or(|process| {
                kr_ipc::identity::process_state(process) == kr_ipc::identity::ProcessState::Ended
            });
            if ended {
                self.plugin_bridge.ended(session_id);
            }
        }
    }

    /// Seeds the member set at start, before anything is served: every reservation whose claim was
    /// consumed, every registered worker, and every session a closure left with a worker nothing
    /// confirmed ended. Each starts pending; a fenced or closed one whose process has already ended
    /// is let go at once.
    pub(super) async fn seed_admission_members(&self) -> crate::Result<()> {
        let registry = self.registry.lock().await;
        for reservation in registry.reservations_in(LaunchPhase::Claimed)? {
            self.plugin_bridge.claimed(
                reservation.session_id,
                reservation.launcher_identity.clone(),
            );
        }
        for reservation in registry.reservations_in(LaunchPhase::Fenced)? {
            if reservation.claimed_key.is_some() {
                self.plugin_bridge.claimed(
                    reservation.session_id,
                    reservation.launcher_identity.clone(),
                );
                self.plugin_bridge.fenced(reservation.session_id);
            }
        }
        for worker in registry.workers()? {
            self.plugin_bridge
                .claimed(worker.session_id, Some(worker.process_identity.clone()));
            self.plugin_bridge
                .recorded(worker.session_id, worker.process_identity);
        }
        for (session_id, record) in registry.closures()? {
            let unaccounted = record
                .surviving
                .iter()
                .any(|resource| resource.kind == UNACCOUNTED_WORKER);
            if !unaccounted {
                continue;
            }
            let launcher = registry
                .reservation_for_session(session_id)?
                .and_then(|reservation| reservation.launcher_identity);
            self.plugin_bridge.claimed(session_id, launcher);
            self.plugin_bridge.closed(session_id, false);
        }
        drop(registry);
        // Every worker the last daemon left is a member now, so what the bridge reports of the
        // workers' live releases is the whole account and a commit may forget what none holds.
        self.plugin_bridge.members_known();
        self.check_unconfirmed_members();
        Ok(())
    }

    /// Starts the cadence, which runs a pass every [`ADMISSIONS_CADENCE`] and at once whenever a
    /// change or a new member asks for one. It holds this daemon weakly between passes, so a daemon
    /// dropped everywhere else is dropped.
    pub(super) fn start_admissions_cadence(self: &Arc<Self>) {
        let controller = Arc::downgrade(self);
        let due = Arc::clone(&self.admissions_due);
        tokio::spawn(async move {
            let mut cadence = tokio::time::interval(ADMISSIONS_CADENCE);
            loop {
                tokio::select! {
                    _ = cadence.tick() => {}
                    () = due.notified() => {}
                }
                let Some(controller) = controller.upgrade() else {
                    return;
                };
                controller.admissions_pass().await;
            }
        });
    }

    /// Seeds the catalogue from the generation compiled into this host, and tells the cadence when
    /// the admission revision moved.
    ///
    /// The `kr-controller` binary calls this at every start, right after the daemon starts and
    /// before it binds the local endpoints a client reaches; a request that arrives sooner on the
    /// network endpoint waits for the catalogue's lock. A daemon that never calls it seeds nothing:
    /// a test seeds only when it asks.
    /// What the run did, skipped or stopped at is kept for the doctor's catalogue check; a seed
    /// that fails does not stop the daemon.
    pub async fn seed_catalogue(
        &self,
        bundle: &kr_plugin_catalogue::SeedBundle,
    ) -> kr_plugin_catalogue::SeedOutcome {
        let before = self.catalogue.admission_revision().await.ok();
        let outcome = self.catalogue.seed(bundle).await;
        if self.catalogue.admission_revision().await.ok() != before {
            self.admissions_due();
        }
        if outcome.failure.is_some()
            || !outcome.skipped.is_empty()
            || !outcome.notes.is_empty()
            || outcome.expired.is_some()
        {
            self.note_admissions(format!("the bundled catalogue: {}", outcome.report()));
        }
        outcome
    }

    /// Asks the cadence for a pass now.
    pub(crate) fn admissions_due(&self) {
        #[cfg(feature = "testing")]
        self.plugin_bridge.pass_asked();
        self.admissions_due.notify_one();
    }

    /// Returns the members a reclaim that needs room would wait for now: every one not reconciled
    /// at the current admission revision, as the catalogue's reclaim is told. For this host's own
    /// tests.
    ///
    /// # Errors
    ///
    /// Returns the refusal the catalogue gave when its revision could not be read.
    #[cfg(feature = "testing")]
    pub async fn pending_admissions(
        &self,
    ) -> std::result::Result<Vec<String>, kr_protocol::error::ProtocolError> {
        use kr_plugin_catalogue::BrokerBridge as _;
        let revision = self.catalogue.admission_revision().await?;
        Ok(self.plugin_bridge.live_packages(revision).pending)
    }

    /// Refreshes every recorded member's report as `plugin.list` does, and says whether the counts
    /// are known. For this host's own tests, which stop waiting for it part way as a caller that
    /// goes away does.
    #[cfg(feature = "testing")]
    pub async fn refresh_admissions(&self) -> bool {
        self.refreshed_view().await.counts.is_some()
    }

    /// The warnings the doctor's catalogue check carries now, with their words, which the check
    /// itself withholds. For this host's own tests.
    #[cfg(feature = "testing")]
    pub async fn catalogue_warnings(&self) -> Vec<String> {
        self.catalogue_evidence().await.warnings
    }

    /// Returns true while a round to the member for `session_id` is out. For this host's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn admission_round_out(&self, session_id: SessionId) -> bool {
        self.plugin_bridge.in_flight(session_id)
    }

    /// Makes the accepted report of the member for `session_id` list a binding of `release` due
    /// to end, as the answer of a worker does while a request that binding admitted is open, and
    /// says whether the member had an accepted report. For this host's own tests.
    #[cfg(feature = "testing")]
    pub fn report_ending_binding(&self, session_id: SessionId, release: LiveRelease) -> bool {
        self.plugin_bridge.list_in_accepted_report(
            session_id,
            kr_protocol::admission::LiveBinding {
                binding_id: kr_protocol::ids::BrokerBindingId::new(kr_ipc::new_uuid()),
                application_instance_id: kr_protocol::ids::ApplicationInstanceId::new(
                    kr_ipc::new_uuid(),
                ),
                release,
                ending: true,
                component: kr_protocol::scalars::Nullable::null(),
            },
        )
    }

    /// Returns every release the accepted reports list live, with whether it is ending there, read
    /// with no round. For this host's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn reported_releases(&self) -> Vec<(LiveRelease, bool)> {
        self.plugin_bridge.live().into_values().collect()
    }

    /// Returns how many times a pass of the cadence was asked for ahead of its tick. For this
    /// host's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn passes_asked(&self) -> u64 {
        self.plugin_bridge.passes_asked()
    }

    /// Asks the cadence for a pass now, as a change does. For this host's own tests.
    #[cfg(feature = "testing")]
    pub fn ask_for_admissions_pass(&self) {
        self.admissions_due();
    }

    /// Serves one catalogue or plugin read: `plugin.list` counts from a fresh round of every
    /// worker's report, and every other read asks none.
    pub(crate) async fn catalogue_read_frame(
        &self,
        ingress: kr_protocol::actor::ActorIngress,
        request: &kr_protocol::envelope::Request,
    ) -> kr_protocol::envelope::ControlFrame {
        if request.method.method() == Some(kr_protocol::method::Method::PluginList) {
            let mut view = self.refreshed_view().await;
            view.admissions = self.current_snapshot(tokio::time::Instant::now()).await;
            return self
                .catalogue
                .read_frame(ingress, request, Some(&view))
                .await;
        }
        self.catalogue.read_frame(ingress, request, None).await
    }

    /// Serves one catalogue or plugin mutation, and announces the admissions it changed.
    ///
    /// A removal first asks every worker for a fresh report and counts the package's live
    /// bindings in them, at the admission revision it read before asking; the catalogue answers
    /// with that count only when it commits right after that revision.
    pub(crate) async fn catalogue_write(
        &self,
        actor_id: &kr_protocol::ids::ActorId,
        mutation: &kr_protocol::envelope::MutationRequest,
        method: kr_protocol::method::Method,
        confirmations: Option<&dyn crate::sharing::OwnerConfirmations>,
        admission: Arc<dyn crate::catalogue::Admission>,
    ) -> crate::catalogue::Answer<kr_protocol::envelope::ParamsValue> {
        let before = self.catalogue.admission_revision().await.ok();
        let removal = if method == kr_protocol::method::Method::PluginRemove {
            let plugin = crate::catalogue::plugin_named(method, &mutation.params);
            let view = self.refreshed_view().await;
            match (plugin, view.counts) {
                (Some(plugin), Some(counts)) => Some((
                    view.revision,
                    counts
                        .iter()
                        .filter(|(key, _)| key.0 == plugin)
                        .map(|(_, (_, count, _))| *count)
                        .sum(),
                )),
                _ => None,
            }
        } else {
            None
        };
        let answer = self
            .catalogue
            .write(
                actor_id,
                mutation,
                method,
                confirmations,
                admission,
                removal,
            )
            .await;
        if self.catalogue.admission_revision().await.ok() != before {
            self.admissions_due();
        }
        answer
    }
}
