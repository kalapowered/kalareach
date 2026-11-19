//! The voice coordinator's seams: its start, a session's facts and a voice change performed once.

use std::sync::Arc;

use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::error::ProtocolError;
use kr_protocol::ids::{ActionId, ActorId, AuthorityRevision, SessionId};
use kr_protocol::method::Method;
use kr_protocol::session::{SessionReadParams, SessionReadResult};
use kr_protocol::voice::{VoiceDelegateResult, VoiceDelegationOutcome};

use crate::error::{ControllerError, Result};
use crate::given::{Given, Recorded};

use super::authority_changes::decoded;
use super::workers::WorkerLink;
use super::{Controller, parse};

/// How long the voice service waits on a session's worker for one request.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VoiceBudgets {
    /// A read of a session. The phone is told that the worker did not answer once it has passed.
    pub(crate) read: std::time::Duration,
    /// A close, from the start of its forward to the end of the time its worker may still take it
    /// up: the deadline the close travels with.
    pub(crate) close: std::time::Duration,
}

impl VoiceBudgets {
    /// What this host waits.
    pub(crate) const STATED: Self = Self {
        read: std::time::Duration::from_secs(10),
        close: crate::service::net::dispatch::EFFECT_WAIT,
    };
}

/// The managed calls on this host, as the host's account sees them.
///
/// Held weakly: the account is the daemon's, and the daemon holds the voice service.
struct VoiceCalls {
    module: std::sync::Weak<crate::voice::VoiceModule>,
    daemon: std::sync::Weak<Controller>,
}

impl crate::account::Calls for VoiceCalls {
    fn open(&self) -> bool {
        self.module
            .upgrade()
            .is_some_and(|module| module.coordinator().calls_open())
    }

    fn end_those_that_are_over(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let (Some(module), Some(daemon)) = (self.module.upgrade(), self.daemon.upgrade())
            else {
                return;
            };
            // The time every voice deadline is decided on.
            module
                .coordinator()
                .end_calls_that_are_over(daemon.settled_now_ms())
                .await;
        })
    }
}

/// What a repeat of a voice change is told when the result it kept cannot be read back.
fn unreadable_voice_record() -> ControllerError {
    ControllerError::record_unreadable("voice changes")
}

impl Controller {
    /// How long the voice service waits on a worker now.
    pub(crate) fn voice_budgets(&self) -> VoiceBudgets {
        *self
            .voice_budgets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Registers the voice coordinator beside the other services.
    ///
    /// After the daemon exists, because two of the coordinator's seams hold a weak reference back
    /// to it: a service built inside `Arc::new_cyclic` could not read a session or propose an
    /// effect, which is most of what those seams are for.
    ///
    /// The managed broker is attached when the configuration document names its origin, in the
    /// voice section this daemon read when it started. A host without one is a complete host: a
    /// person's own provider credential and the agent already running in the session both still
    /// work, and `voice.start` says so rather than failing obscurely.
    pub(super) fn start_voice(self: &Arc<Self>) {
        let authority = Arc::new(crate::voice::GrantAuthority::new(
            Arc::clone(&self.sharing),
            Arc::clone(&self.devices),
            self.sharing.host_device_id(),
            self.me.clone(),
        ));
        let provider = self.clients.managed_inference.clone();
        let module = crate::voice::VoiceModule::new(
            Arc::new(crate::voice::ControllerFacts::new(self.me.clone())),
            authority,
            Arc::new(crate::voice::ControllerDispatch::new(self.me.clone())),
            provider,
            self.sharing.host_device_id(),
            self.paths.environment_id(),
            self.started
                .voice
                .broker_origin()
                .unwrap_or_default()
                .to_owned(),
        );
        let module = Arc::new(module);
        // The account never changes under a call: from the moment a start asks the broker to the
        // moment the close has been told, the call is open, and signing in or out waits for it.
        self.account.watch_calls(Arc::new(VoiceCalls {
            module: Arc::downgrade(&module),
            daemon: Arc::downgrade(self),
        }));
        let _ = self.voice.set(module);
    }

    /// The environment's voice service.
    ///
    /// # Panics
    ///
    /// Panics when the daemon has not finished starting, which no request path can observe: the
    /// endpoint is served after startup returns.
    #[must_use]
    pub fn voice(&self) -> &Arc<crate::voice::VoiceModule> {
        self.voice.get().expect("the voice service is registered")
    }

    /// The device a paired actor acts as, when this host knows one.
    ///
    /// A voice method is reachable from a paired device and nothing else, so the actor has to
    /// resolve to a device record before the coordinator sees it. An actor that resolves to no
    /// live device reaches nothing.
    pub(crate) fn paired_device(&self, actor_id: &ActorId) -> Option<kr_protocol::ids::DeviceId> {
        self.devices
            .devices()
            .ok()?
            .into_iter()
            .find(|record| record.is_paired() && &record.principal() == actor_id)
            .map(|record| record.device_id)
    }

    /// The facts the voice coordinator may read about one session.
    ///
    /// Read through this daemon's ordinary session read, so voice sees what any other reader sees
    /// and nothing more. What the session's worker holds of its agents, the decisions waiting on a
    /// person and the semantic messages, is read beside it (`voice_worker_half`); a part
    /// that cannot be read is reported as unavailable rather than left out silently.
    ///
    /// Every item carries the moment its content was produced, because that moment is what a
    /// grant's history lower bound is checked against. The shell a session runs and the directory
    /// it started in are fixed when the session is created, so the creation time is theirs; a fact
    /// this daemon cannot place in time is withheld rather than stamped with the moment it was
    /// read, which would let a retained summary of a session that closed long ago pass a bound
    /// written after it. What the description host holds of the session is read beside it: the
    /// directory and the program it observed, each with the moment it observed them, and what a
    /// model wrote, placed at the session's start ([`crate::voice::snapshot_with`]).
    ///
    /// # Errors
    ///
    /// Returns the refusal of the session read, and [`ControllerError::RegistryUnavailable`] when
    /// the description store cannot be read.
    pub async fn voice_session_snapshot(
        self: &Arc<Self>,
        session_id: SessionId,
    ) -> Result<crate::voice::SessionSnapshot> {
        // The worker's half is read within the time this read of a session is given, from its
        // start: a half that has run out of it is left, with its reason, not waited for.
        let deadline = tokio::time::Instant::now() + self.voice_budgets().read;
        let params = ParamsValue::from_typed(&SessionReadParams { session_id })
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let read: SessionReadResult = parse(
            &self
                .session_read_within(&params, Some(self.voice_budgets().read))
                .await?,
        )?;
        let described = self.voice_description_of(&read.session).await?;
        let half = self.voice_worker_half(session_id, deadline).await;
        Ok(
            crate::voice::snapshot_with(&read.session, session_id, &described)
                .with_worker_half(half),
        )
    }

    /// What the session's worker holds that the default context carries: the decisions waiting on
    /// a person and the semantic messages of its agents.
    ///
    /// Read over this daemon's own link to the worker, with the three reads the worker already
    /// serves (`agent.instances`, `question.read` and `agent.snapshot`) and nothing else. It is
    /// read wide and filtered once, in [`crate::voice::filtered`], under the requesting device's
    /// grant, as the session and its description are. A part that cannot be read is one withheld
    /// run with its reason, and the rest is still served.
    ///
    /// While privacy mode is on nothing is read. After it was on, only what was produced after the
    /// moment it last took effect, or after this daemon last started if that is later, is carried
    /// (`Published::since_ms`), so that a worker that kept its history, or a decision that stayed
    /// pending, through the change cannot give it up to a call.
    async fn voice_worker_half(
        self: &Arc<Self>,
        session_id: SessionId,
        deadline: tokio::time::Instant,
    ) -> crate::voice::WorkerHalf {
        use crate::voice::{PRIVACY_ON, WorkerHalf};

        // Without waiting: a change being made is a state that has moved, and nothing is read.
        let published = self
            .privacy
            .state()
            .try_reading()
            .map(|reading| reading.published());
        let Some(published) = published.filter(|published| !published.private) else {
            return WorkerHalf::not_read(PRIVACY_ON);
        };
        let boundary = (published.generation.get() > 0).then_some(published.since_ms);
        let Some(worker) = self.directory.lock().await.get(session_id).cloned() else {
            return WorkerHalf::not_read("this session has no worker to read");
        };

        let mut half = WorkerHalf::default();
        let mut decisions = Vec::new();
        let instances = self
            .voice_agent_instances(&worker, session_id, deadline)
            .await;
        match &instances {
            Ok((_, resources)) => {
                decisions.extend(resources.iter().filter_map(crate::voice::approval));
            }
            Err(()) => half.could_not_read("the session's pending approvals"),
        }
        match self
            .ask_worker::<_, kr_protocol::question::QuestionReadResult>(
                &worker,
                deadline,
                Method::QuestionRead,
                &kr_protocol::question::QuestionReadParams {
                    session_id,
                    question_id: kr_protocol::scalars::Nullable::null(),
                    include_resolved: false,
                },
            )
            .await
        {
            Some(read) => {
                decisions.extend(read.questions.iter().filter_map(crate::voice::question))
            }
            None => half.could_not_read("the session's pending questions"),
        }
        half.decisions = crate::voice::decisions(decisions);

        if let Ok((agents, _)) = &instances {
            let mut histories = Vec::new();
            for agent in agents {
                match self
                    .voice_agent_history(&worker, session_id, *agent, deadline)
                    .await
                {
                    Some(entries) => histories.push(entries),
                    None => half.could_not_read("an agent's recent messages"),
                }
            }
            half.messages = crate::voice::messages(histories);
        } else {
            half.could_not_read("the session's agents");
        }
        half.after(boundary)
    }

    /// The live agent instances of a session and the approvals waiting on a person, paged to the
    /// end. Errs, with nothing said of why, when the worker cannot give them.
    ///
    /// The worker keeps one snapshot of its pending resources for each link and replaces it when
    /// the first page is asked for again, so the pages are read over one link taken for the whole
    /// read: a read that took the link for each page could find another reader's first page
    /// between its own and be refused the rest. A snapshot that ended before its last page was
    /// read is read again from its first, within `deadline`.
    async fn voice_agent_instances(
        &self,
        worker: &crate::directory::KnownWorker,
        session_id: SessionId,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<
        (
            Vec<kr_protocol::ids::ApplicationInstanceId>,
            Vec<kr_protocol::gateway::PendingResource>,
        ),
        (),
    > {
        use kr_protocol::error::ErrorCode;
        use kr_protocol::recovery::{AgentInstancesParams, AgentInstancesResult};

        let mut link = self.take_worker_link(worker, deadline).await.ok_or(())?;
        // A request that did not finish is not given back, and the link is closed with the link
        // that holds it; one that finished, a refusal included, is.
        'snapshot: loop {
            let mut agents = Vec::new();
            let mut resources = Vec::new();
            let mut from = kr_protocol::scalars::Nullable::null();
            for part in 0..crate::voice::MAX_HISTORY_PARTS {
                if tokio::time::Instant::now() >= deadline {
                    link.give_back();
                    return Err(());
                }
                let level = link.client().level();
                let params = AgentInstancesParams {
                    session_id,
                    agent_resources_from: from,
                };
                let answered = tokio::time::timeout_at(
                    deadline,
                    link.client().request(Method::AgentInstances, &params),
                )
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
                let page: AgentInstancesResult = match answered {
                    Ok(value) => {
                        let Ok(page) = level.decode_value::<AgentInstancesResult>(&value) else {
                            link.give_back();
                            return Err(());
                        };
                        page
                    }
                    Err(error) if error.code == ErrorCode::ResyncRequired => continue 'snapshot,
                    Err(_) => {
                        link.give_back();
                        return Err(());
                    }
                };
                if part == 0 {
                    agents = page
                        .agent_instances
                        .instances
                        .iter()
                        .filter(|instance| instance.ended_at.as_ref().is_none())
                        .map(|instance| instance.application_instance_id)
                        .collect();
                }
                resources.extend(page.agent_resources.resources);
                match page.agent_resources.continue_after.0 {
                    Some(after_resource_id) => {
                        from = kr_protocol::scalars::Nullable::some(
                            kr_protocol::projection::AgentResourceSnapshotContinuation {
                                snapshot_id: page.agent_resources.snapshot_id,
                                after_resource_id,
                            },
                        );
                    }
                    None => {
                        link.give_back();
                        return Ok((agents, resources));
                    }
                }
            }
            link.give_back();
            return Err(());
        }
    }

    /// One agent's retained semantic history, paged to the end: a history has no tail read, and
    /// the last twenty entries are the end of it. `None` when the worker cannot give it, or gives
    /// more parts than a read follows ([`crate::voice::MAX_HISTORY_PARTS`]).
    async fn voice_agent_history(
        &self,
        worker: &crate::directory::KnownWorker,
        session_id: SessionId,
        application_instance_id: kr_protocol::ids::ApplicationInstanceId,
        deadline: tokio::time::Instant,
    ) -> Option<Vec<kr_protocol::agent::AgentSnapshotEntry>> {
        use kr_protocol::agent::{AgentSnapshotParams, AgentSnapshotResult, AgentSubject};

        let mut entries = Vec::new();
        let mut from_node = kr_protocol::scalars::Nullable::null();
        for _ in 0..crate::voice::MAX_HISTORY_PARTS {
            let part: AgentSnapshotResult = self
                .ask_worker(
                    worker,
                    deadline,
                    Method::AgentSnapshot,
                    &AgentSnapshotParams {
                        subject: AgentSubject {
                            session_id,
                            application_instance_id,
                        },
                        from_node,
                    },
                )
                .await?;
            entries.extend(part.entries);
            match part.continuation.0 {
                Some(continuation) => {
                    from_node = kr_protocol::scalars::Nullable::some(continuation.from_node);
                }
                None => return Some(entries),
            }
        }
        None
    }

    /// Takes this daemon's link to a session's worker, waiting for it no longer than `deadline`.
    /// `None` when the time has run out, before or while waiting, or the link cannot be had. A
    /// link that came as the time ran out has sent nothing, so it goes back whole.
    async fn take_worker_link(
        &self,
        worker: &crate::directory::KnownWorker,
        deadline: tokio::time::Instant,
    ) -> Option<WorkerLink> {
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        let mut link = tokio::time::timeout_at(deadline, self.worker_client(worker))
            .await
            .ok()?
            .ok()?;
        if tokio::time::Instant::now() >= deadline {
            link.give_back();
            return None;
        }
        Some(link)
    }

    /// Asks a session's worker one read over this daemon's own link, and gives the link back once
    /// the answer, a refusal included, is read to its end. `None` when the link cannot be had or
    /// the worker does not answer by `deadline` or refuses: a link that did not finish an exchange
    /// is closed, not given back.
    async fn ask_worker<P, R>(
        &self,
        worker: &crate::directory::KnownWorker,
        deadline: tokio::time::Instant,
        method: Method,
        params: &P,
    ) -> Option<R>
    where
        P: serde::Serialize + ?Sized,
        R: kr_protocol::wire::WireMessage,
    {
        let mut link = self.take_worker_link(worker, deadline).await?;
        let level = link.client().level();
        let answered = tokio::time::timeout_at(deadline, link.client().request(method, params))
            .await
            .ok()?
            .ok()?;
        link.give_back();
        level.decode_value::<R>(&answered.ok()?).ok()
    }

    /// The display number of one session as a person says it, or nothing when this daemon holds
    /// none for it.
    ///
    /// Read from this daemon's own records and from no worker: the directory's entry for a live
    /// session, and the registry's reservation for any session it ever made, which keeps the
    /// number a closed session was listed under. A lookup that asked each session's worker would
    /// wait on a worker that does not answer, for a session the person did not name, and would
    /// read a worker's silence as a session that has no number.
    ///
    /// # Errors
    ///
    /// Returns the registry's error when it cannot be read: a registry that cannot say is not a
    /// session with no number, and the answer a person is given for the second is kept.
    pub(crate) async fn voice_session_number(
        self: &Arc<Self>,
        session_id: SessionId,
    ) -> Result<Option<u64>> {
        if let Some(worker) = self.directory.lock().await.get(session_id) {
            return Ok(Some(worker.descriptor.display_number.get()));
        }
        let registry = self.registry.lock().await;
        Ok(registry
            .reservation_for_session(session_id)?
            .map(|reservation| reservation.display_number.get()))
    }

    /// What the description host holds of a session: the name a person pinned, what a model wrote
    /// and what the host observed, read under the privacy state as it stands.
    async fn voice_description_of(
        &self,
        session: &kr_protocol::session::SessionSummary,
    ) -> Result<crate::describe::VoiceDescription> {
        let descriptions = Arc::clone(&self.descriptions);
        let privacy = self.privacy.state();
        let facts = crate::describe::facts_of(session);
        let session_id = session.session_id;
        let started_ms = session.created_at_ms.get();
        tokio::task::spawn_blocking(move || {
            descriptions.voice_description(session_id, &facts, started_ms, &privacy)
        })
        .await
        .map_err(|_| ControllerError::RegistryUnavailable {
            detail: "the session's description could not be read".to_owned(),
        })?
    }

    /// Performs one voice proposal under the method the registry lists for its effect.
    ///
    /// The reads this daemon serves are performed here, as the device that asked and under the
    /// authority that admitted the proposal, checked again immediately before the effect and again
    /// before the answer is served. A proposal waits for the coordinator's own checks, for a
    /// confirmation and for this dispatch, and authority withdrawn inside any of those waits has
    /// to stop it: what the contract forbids is *serving* that state, not reading it.
    ///
    /// A read waits on the session's worker for a stated time and no longer
    /// ([`VoiceBudgets::read`]): a worker that does not answer is told to the phone as an error,
    /// not waited on for ever.
    ///
    /// A close goes to the session's worker through the path a device's own close takes
    /// ([`Self::voice_close`]), once the device has confirmed it on its unlocked screen.
    ///
    /// Everything else belongs to the worker's own dispatch, which this daemon does not forward,
    /// so it is **admitted and not performed**: section 15 ¶10 makes the receipt the authority, and
    /// reporting an effect this daemon did not cause would be the exact mistake that paragraph
    /// forbids.
    pub(crate) async fn voice_perform(
        self: &Arc<Self>,
        method: Method,
        proposal: &kr_voice::Proposal,
        admission: &Arc<dyn kr_voice::Admission>,
    ) -> Result<kr_voice::seams::HostReceipt> {
        let action_id = proposal.action_id;
        if method == Method::SessionClose {
            return self.voice_close(proposal, admission).await;
        }
        if method == Method::SessionRead {
            let session_id = proposal.session_id.ok_or_else(|| {
                ControllerError::InvalidArgument("that action names a session".to_owned())
            })?;
            let _ = self.voice_authority_now(proposal, session_id)?;
            let params = ParamsValue::from_typed(&SessionReadParams { session_id })
                .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
            let read: SessionReadResult = parse(
                &self
                    .session_read_within(&params, Some(self.voice_budgets().read))
                    .await?,
            )?;
            // The session as the context names it, with the name a person pinned. What a model
            // wrote of it and what the description host observed are left out: a receipt leaves
            // this daemon with nothing that holds that text to the privacy state it was read
            // under, and it would carry it past the removal privacy mode makes.
            let described = self.voice_description_of(&read.session).await?.pin_only();
            let snapshot = crate::voice::snapshot_with(&read.session, session_id, &described);
            let narrowed = self.voice_authority_now(proposal, session_id)?;
            // The same bound the context path applies, and the answer is built from what it
            // admitted and from nothing else. A session's description carries its number and the
            // shell it runs, and both are facts from the moment it was created: naming them after
            // the filter had withheld them would be the way round the bound rather than an answer
            // under it. Whether a session that is still running is running is a fact about now,
            // so it travels with a description the bound admitted.
            let live = read.session.state != kr_protocol::session::SessionState::Closed;
            let state = read.session.state.as_str().to_owned();
            // This receipt does not go through `select_context`, because it holds nothing that
            // function would take out. It is made of the two items a selection leads with, the
            // description and the directory, built by the functions the selection uses and passed
            // through the same bound just above, and of the session's state. The worker's half
            // (messages and decisions) is not read here and nothing of the session's output,
            // environment, files or attachments is, so no item of a class a selection leaves out
            // can enter it. The coordinator strips it with its secret patterns and cuts it to the
            // bytes an append may carry, which is far below the selection's cap.
            let filtered = crate::voice::filtered(snapshot, &narrowed);
            let summary = match (filtered.session_description, filtered.working_directory) {
                (None, _) => "this grant's history does not reach that session".to_owned(),
                (Some(description), directory) => {
                    let mut summary = description.text;
                    if live {
                        summary.push_str(" is ");
                        summary.push_str(&state);
                    }
                    match directory {
                        Some(directory) => {
                            summary.push_str(" in ");
                            summary.push_str(&directory.text);
                        }
                        None => {
                            summary.push_str("; where it runs is outside what this grant may see");
                        }
                    }
                    summary
                }
            };
            return Ok(kr_voice::seams::HostReceipt {
                action_id,
                performed: true,
                summary,
            });
        }
        Ok(kr_voice::seams::HostReceipt {
            action_id,
            performed: false,
            summary: format!(
                "{} belongs to the session's worker, which this host does not dispatch",
                method.as_str()
            ),
        })
    }

    /// Performs one voice mutation exactly once for its action identifier.
    ///
    /// Section 23 marks the four voice mutations action-deduplicated, and none of them is safe to
    /// repeat: a second `voice.grant` would replace the grant the first one wrote and end the calls
    /// started under it, a second `voice.stop` would find nothing, a second `voice.start` would be
    /// a second metered call, and a second delegation under one identifier would be a second
    /// action. The claim and the retained answer are the same ones this host already keeps for an
    /// authority change, because a voice grant is a grant in that same store.
    ///
    /// A delegation is claimed like the others, with one difference in what it asks of the claim.
    /// The answer to a first submission of an action that needs a confirmation is the challenge the
    /// device signs, and the signed delegation comes back under the same identifier carrying a
    /// different payload. That answer admits nothing, so its claim is given back rather than kept,
    /// and the same delegation then claims the identifier afresh. Every other answer is kept under
    /// the claim, and a repeat is answered from it.
    ///
    /// `carried` is the admission the mutation was accepted under: the connection it arrived on,
    /// the authority revision that connection was admitted at and the deadline this host accepted.
    /// It is asked again through the check every service asks from inside its work, before
    /// anything is claimed and wherever the coordinator and the grant store write.
    ///
    /// An answer this reads from what an earlier attempt claimed is given as a copy.
    ///
    /// # Errors
    ///
    /// Returns the refusal the caller is given.
    pub(crate) async fn voice_mutation(
        self: &Arc<Self>,
        from: VoiceIngress,
        mutation: &MutationRequest,
        method: Method,
        authority_revision: AuthorityRevision,
        carried: crate::authority::AdmittedMutation,
    ) -> Given<Result<ParamsValue>> {
        let mut origin = crate::given::Origin::Fresh;
        let answer = self
            .voice_change(
                from,
                mutation,
                method,
                authority_revision,
                carried,
                &mut origin,
            )
            .await;
        Given::from_origin(answer, origin)
    }

    /// [`Self::voice_mutation`], noting in `origin` when the answer is the record's.
    async fn voice_change(
        self: &Arc<Self>,
        from: VoiceIngress,
        mutation: &MutationRequest,
        method: Method,
        authority_revision: AuthorityRevision,
        carried: crate::authority::AdmittedMutation,
        origin: &mut crate::given::Origin,
    ) -> Result<ParamsValue> {
        let VoiceIngress {
            actor_id,
            actor,
            route,
        } = from;
        // The admission this mutation was accepted under, as a question the coordinator can ask
        // rather than a figure it has to convert. Everything after this waits — for the claim, for
        // the coordinator's own lock, for the store, for the broker — and the write at the end of
        // those waits is what has to stand on that admission, not merely the dispatch that began
        // it. The question is the one every service asks from inside its work: whether this host
        // owes a fence it could not raise, whether the connection's registration still stands
        // under the revision the mutation was admitted at, and whether the deadline has passed on
        // this daemon's own continuous clock.
        // A start names the earlier start it supersedes, when it names one. The key is read before
        // anything is claimed: a key that is not an action identifier is the caller's mistake, and
        // nothing is held for it.
        let start = if method == Method::VoiceStart {
            Some(StartHold {
                row: Arc::new(AttemptRow::new(
                    Arc::clone(&self.voice_start_holds),
                    actor_id.clone(),
                    mutation.action_id,
                )),
                supersedes: supersession_named_by(&mutation.expected)?,
                send_by: std::sync::Mutex::new(None),
            })
        } else {
            None
        };
        let mut admission = VoiceAdmission::new(Arc::clone(self), carried);
        if let Some(start) = start {
            admission = admission.for_a_start(start);
        }
        let admission = Arc::new(admission);
        // What this host already holds about this action, if anything. Answered before the claim,
        // so a retry of a completed change is its own result rather than a conflict, and one whose
        // first attempt is running or ended unrecorded is told so rather than performed.
        // What it finds goes back under the registration the repeat arrived under, a refusal it
        // kept as much as a result.
        if let Some(found) = self.voice_answered(&actor_id, mutation).await.present() {
            return self
                .retained_under_authority(&carried, origin, async { found })
                .await;
        }
        // A first admission is asked before anything is claimed or created. A start asks the
        // broker for a call before it writes the call's grant, and a call created for a start this
        // host then refuses is a metered call nobody can use. A stop is not asked. It takes
        // authority away rather than exercising it: section 15 ends a call's grant the moment the
        // call ends, and a fence this host owes is a reason to withdraw authority, never a reason
        // to keep a call's grant alive.
        if method != Method::VoiceStop {
            admission.check()?;
        }
        #[cfg(test)]
        self.before_a_voice_change_claims.wait().await;
        let claimed = match self.claim_voice_action(&actor_id, mutation) {
            Ok(claimed) => claimed,
            // Another copy claimed the action for another payload while this one waited: what that
            // says of its record goes back only under this copy's authority, as its answer does.
            Err(error) => {
                return Err(self.conflict_under_authority(&carried, origin, error).await);
            }
        };
        let hold = match claimed {
            crate::grants::ActionClaim::Claimed { hold } => hold,
            crate::grants::ActionClaim::Recorded(record) => {
                return self
                    .retained_under_authority(
                        &carried,
                        origin,
                        self.voice_recorded(&actor_id, mutation, record),
                    )
                    .await;
            }
        };
        let attempt = VoiceAttempt {
            hold,
            actor,
            route,
            mutation: mutation.clone(),
            method,
            authority_revision,
            admission,
        };
        // A delegation can have an effect that the request which asked for it does not wait out,
        // and an effect is not stopped by the connection that asked for it going away: dropping a
        // future is a cancellation, and a close that has reached a worker cannot be called back. So
        // its attempt runs on a task of its own, which owns the claim and records what the effect
        // came to under it, and a retry after a dropped connection is answered from that record.
        // So does a change of the voice grant that waits for the workers before it answers: the
        // grant is revoked once it has committed, and the answer is owed under the claim whether
        // or not the link it was asked on is still there to carry it.
        if matches!(
            method,
            Method::VoiceDelegate | Method::VoiceStop | Method::VoiceGrant
        ) {
            let daemon = Arc::clone(self);
            return match tokio::spawn(async move { daemon.voice_attempt(attempt).await }).await {
                Ok(outcome) => outcome,
                Err(_) => Err(ControllerError::Uncertain {
                    detail: "this host could not report what happened to that voice change"
                        .to_owned(),
                }),
            };
        }
        self.voice_attempt(attempt).await
    }

    /// One claimed voice action, performed and recorded under its claim.
    async fn voice_attempt(self: &Arc<Self>, attempt: VoiceAttempt) -> Result<ParamsValue> {
        let VoiceAttempt {
            hold,
            actor,
            route,
            mutation,
            method,
            authority_revision,
            admission,
        } = attempt;
        let outcome = self
            .voice()
            .answer(
                actor,
                &mutation,
                method,
                authority_revision,
                self.settled_now_ms(),
                &(Arc::clone(&admission) as Arc<dyn kr_voice::Admission>),
            )
            .await;
        // The challenge a device signs admits nothing, so nothing is kept for it: the signed
        // delegation is the same action under the same identifier, and claims it afresh. The route
        // the ingress claimed goes back first, while this attempt still holds its claim: a request
        // under the identifier is refused as running until the claim is given back, so no other
        // attempt can have taken the route in the meantime, and one that comes after takes both
        // afresh. If the claim then cannot be given back, both stay spent.
        if method == Method::VoiceDelegate && is_a_challenge(&outcome) {
            if let Some(route) = &route {
                route.give_back()?;
            }
            if let Err(error) = self.sharing.grants().release_claim(hold) {
                if let Some(route) = &route {
                    route.take_again();
                }
                return Err(error);
            }
            return outcome;
        }
        // Recorded before the hold goes, so a retry finds the answer rather than a claim with
        // neither an answer nor an attempt behind it.
        self.settle_claim(&hold, &outcome)?;
        // Whatever the claim recorded, and only now: the hold's row ends when its start's effect is
        // known and its claim is settled, in either order.
        admission.settled();
        drop(hold);
        outcome
    }

    /// The digest one voice action is claimed and answered under.
    ///
    /// The mutation's own digest. A confirmed delegation is the same action as the one that asked
    /// for the confirmation and carries a different payload, which is why the challenge's claim is
    /// given back: a payload digest would otherwise refuse the signed resubmission.
    fn voice_action_digest(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<kr_protocol::scalars::Digest256> {
        kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Claims one voice action for this attempt, or reports what an earlier attempt's claim is
    /// owed.
    ///
    /// [`crate::grants::ActionClaim::Claimed`] is this attempt's hold: it wrote the claim and is
    /// the one attempt that may perform the change. [`crate::grants::ActionClaim::Recorded`] is
    /// answered by [`Self::voice_recorded`], and nothing is performed.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::IdConflict`] when the identifier was used with another payload,
    /// and [`ControllerError::Uncertain`] when the claim cannot be read: a copy of this change may
    /// have claimed the action since the early look found no record of it.
    fn claim_voice_action(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<crate::grants::ActionClaim> {
        let digest = self.voice_action_digest(actor_id, mutation)?;
        self.sharing.grants().claim_action(
            actor_id,
            mutation.action_id,
            &digest,
            kr_ipc::now_ms().get(),
        )
    }

    /// What this host holds about one voice action, when an earlier attempt claimed it.
    ///
    /// Read, not claimed, so a retry whose freshness window has gone is still told what happened.
    /// An action identifier reused with another payload is refused here, which is how a second
    /// delegation under the first one's identifier never reaches the coordinator.
    pub(super) async fn voice_answered(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Recorded<Result<Option<ParamsValue>>> {
        Recorded::read(self.voice_on_record(actor_id, mutation).await)
    }

    async fn voice_on_record(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Result<Option<ParamsValue>> {
        let digest = self.voice_action_digest(actor_id, mutation)?;
        // A store that cannot be read is not one that holds no record: an earlier attempt may have
        // made the change, so the repeat is not told a transient word, which says nothing took
        // effect. A reused identifier keeps its code.
        match self
            .sharing
            .grants()
            .recorded_action(actor_id, mutation.action_id, &digest)
            .map_err(|error| error.found_unreadable("voice changes"))?
        {
            Some(record) => self
                .voice_record_answer(actor_id, mutation, record)
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    /// The answer a voice change an earlier attempt claimed is owed.
    ///
    /// A delegation's is given back only under the authority it is owed under now
    /// ([`Self::delegation_again`]). The others name no session and carry no content about one:
    /// what each produced is the grant it wrote, the call it created or the call it ended.
    async fn voice_recorded(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        record: crate::grants::ActionRecord,
    ) -> Recorded<Result<ParamsValue>> {
        Recorded::read(self.voice_record_answer(actor_id, mutation, record).await)
    }

    async fn voice_record_answer(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        record: crate::grants::ActionRecord,
    ) -> Result<ParamsValue> {
        match record {
            crate::grants::ActionRecord::Answered { result }
                if mutation.method.method() == Some(Method::VoiceDelegate) =>
            {
                self.delegation_again(actor_id, mutation, &result).await
            }
            record => Self::recorded_voice_action(record),
        }
    }

    /// The answer a delegation this host already answered is owed when it is submitted again.
    ///
    /// Section 23 returns the retained receipt to a duplicate from a still-authorised actor, and the
    /// host checks current authority before it does, so that a revoked device cannot use an old
    /// action identifier to retrieve what it was told. The actor is a paired device, and it has to
    /// still be one. A receipt that carries nothing about a session goes back as it was kept. One
    /// that carries content read from a session does not go back from what it said then: the read
    /// is made again under every check a first submission passes, against the voice grant and the
    /// device's grant and history bound as they stand now, so a call that has ended, a grant that
    /// has gone or a bound that has narrowed gives the refusal and not the content.
    ///
    /// A receipt for an action that is not a read goes back as it was kept, whatever it says: an
    /// effect is never performed again for a repeat.
    async fn delegation_again(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        kept: &[u8],
    ) -> Result<ParamsValue> {
        let Some(device_id) = self.paired_device(actor_id) else {
            return Err(ControllerError::PermissionDenied {
                detail: "this device is no longer paired with this host".to_owned(),
            });
        };
        // A result this host kept and cannot read back leaves open what the delegation came to.
        let answered = decoded(kept).map_err(|_| unreadable_voice_record())?;
        let receipt: VoiceDelegateResult =
            parse(&answered).map_err(|_| unreadable_voice_record())?;
        // What the first answer recorded the words to ask for, and nothing read from them again.
        if !matches!(receipt.outcome, VoiceDelegationOutcome::Performed { .. }) {
            return Ok(answered);
        }
        // A read that recorded no action is one this host cannot say what it read: it is not given
        // back as kept, because it may carry content, and not read again, because nothing says
        // what to read.
        let Some(action) = receipt.action.0 else {
            return Err(ControllerError::Uncertain {
                detail:
                    "that delegation was performed, and this host did not record what it read, \
                         so it is neither given again nor read again"
                        .to_owned(),
            });
        };
        if crate::voice::method_for(action) != Some(Method::SessionRead) {
            return Ok(answered);
        }
        self.voice()
            .answer_again(device_id, mutation, &receipt, self.settled_now_ms())
            .await
    }

    /// The answer a voice change an earlier attempt claimed is owed, as the claim holds it.
    ///
    /// As an authority change's ([`Self::recorded_authority_change`]), with one difference: none of
    /// the four leaves anything in this host's records that names the action. A voice grant takes a
    /// fresh identity, a voice session is held in memory, a started call is the broker's, and a
    /// delegation's effect is the worker's. So a change whose attempt ended without recording what
    /// it did is an outcome this host does not know, and it is never performed again: a second
    /// start would be a second metered call.
    fn recorded_voice_action(record: crate::grants::ActionRecord) -> Result<ParamsValue> {
        match record {
            crate::grants::ActionRecord::Answered { result } => {
                decoded(&result).map_err(|_| unreadable_voice_record())
            }
            crate::grants::ActionRecord::Refused { code, detail } => {
                Err(ControllerError::Refused { code, detail })
            }
            crate::grants::ActionRecord::InFlight => Err(ControllerError::attempt_still_running()),
            crate::grants::ActionRecord::Unfinished => Err(ControllerError::Uncertain {
                detail: "an earlier attempt at this voice change ended without recording what it \
                         did, so what it changed may exist; it is not performed again"
                    .to_owned(),
            }),
        }
    }

    /// Checks that the authority a voice proposal was admitted under still stands, now.
    ///
    /// Three things, on this host's one authority store: the device is still paired, the voice
    /// grant the coordinator admitted it under is still live and still reaches the session, and
    /// the device's own ordinary grant still carries what the action needs. The intersection is
    /// `kr_voice::permits`, which is the same rule the coordinator applied, so this is the same
    /// decision taken again rather than a second rule that could disagree with it.
    pub(super) fn voice_authority_now(
        &self,
        proposal: &kr_voice::Proposal,
        session_id: SessionId,
    ) -> Result<kr_protocol::grant::Grant> {
        use kr_voice::seams::VoiceAuthority as _;

        let denied = |detail: &str| ControllerError::PermissionDenied {
            detail: detail.to_owned(),
        };
        let paired = self
            .devices
            .record_for_device(proposal.device_id)?
            .is_some_and(|record| record.is_paired());
        if !paired {
            return Err(denied("this device is no longer paired with this host"));
        }
        let authority = crate::voice::GrantAuthority::new(
            Arc::clone(&self.sharing),
            Arc::clone(&self.devices),
            self.sharing.host_device_id(),
            self.me.clone(),
        );
        let store = |error: kr_voice::VoiceError| ControllerError::Refused {
            code: error.code(),
            detail: error.to_string(),
        };
        // Standing is the host's to decide, on its own clocks and its recorded floor: a grant
        // that has run out, or whose end is not on record yet, is not given back.
        let voice_grant = authority
            .grant(proposal.voice_grant_id)
            .map_err(store)?
            .ok_or_else(|| denied("the voice grant this action was admitted under has ended"))?;
        if !voice_grant.session_selector.admits(session_id) {
            return Err(denied(
                "the voice grant this action was admitted under no longer reaches that session",
            ));
        }
        let device_grant = authority
            .device_grant(proposal.device_id, Some(session_id))
            .map_err(store)?
            .ok_or_else(|| denied("this device's grant no longer covers that session"))?;
        if !kr_voice::permits(&voice_grant, &device_grant, proposal.action) {
            return Err(denied(
                "the authority this action was admitted under no longer carries it",
            ));
        }
        // The narrower of the two history scopes, which is what any content this effect answers
        // with is filtered under.
        Ok(kr_voice::narrower_history(&device_grant, &voice_grant))
    }
}

/// Who a voice mutation comes from, and what the ingress it came by holds for it.
pub(crate) struct VoiceIngress {
    /// The verified actor the action is de-duplicated under.
    pub(crate) actor_id: ActorId,
    /// The device, or the owner at this machine, it acts as.
    pub(crate) actor: crate::voice::VoiceActor,
    /// The route a network ingress claimed for the action, which a challenge gives back. None for
    /// the local door, which claims none.
    pub(crate) route: Option<Arc<dyn ClaimedRoute>>,
}

/// One voice action that has been claimed, with everything its attempt needs: it may run on a task
/// of its own, so it owns what it holds.
struct VoiceAttempt {
    hold: crate::grants::ClaimHold,
    actor: crate::voice::VoiceActor,
    route: Option<Arc<dyn ClaimedRoute>>,
    mutation: MutationRequest,
    method: Method,
    authority_revision: AuthorityRevision,
    admission: Arc<VoiceAdmission>,
}

/// The route a network ingress claimed for an action before it reached the voice service.
///
/// A route is the host's record that an identifier is one action whichever route it came by. The
/// voice service gives it back only for an answer that admitted nothing, and only while it still
/// holds the claim it took for the same action.
pub(crate) trait ClaimedRoute: Send + Sync {
    /// Gives the route back.
    ///
    /// # Errors
    ///
    /// Returns an error when the route cannot be given back, and it stays claimed.
    fn give_back(&self) -> Result<()>;

    /// Claims the route again after a give-back whose claim could not be returned, so that the
    /// identifier stays spent on every route.
    fn take_again(&self);
}

/// The route one action claimed in this host's device directory, which is what a network ingress
/// holds for a voice mutation.
pub(crate) struct DeviceRoute {
    /// The directory the route is recorded in.
    pub(crate) devices: Arc<crate::service::net::devices::DeviceDirectory>,
    /// The verified actor the action is claimed under.
    pub(crate) actor_id: ActorId,
    /// The mutation the route was claimed for.
    pub(crate) mutation: MutationRequest,
}

impl DeviceRoute {
    fn digest(&self) -> Result<kr_protocol::scalars::Digest256> {
        kr_protocol::digest::mutation_digest(&self.mutation, &self.actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }
}

impl ClaimedRoute for DeviceRoute {
    fn give_back(&self) -> Result<()> {
        self.devices
            .release_action_route(&self.actor_id, self.mutation.action_id, self.digest()?)
    }

    fn take_again(&self) {
        // Nothing more to do if it cannot be taken: the claim that could not be given back is what
        // keeps the identifier spent for voice, and this is the same fault again.
        if let Ok(digest) = self.digest() {
            let _ = self.devices.claim_action_route(
                &self.actor_id,
                self.mutation.action_id,
                None,
                digest,
                kr_ipc::now_ms(),
            );
        }
    }
}

/// The admission one voice mutation arrived under, as the coordinator and the grant store ask
/// about it.
///
/// Every answer is the check each service asks from inside the work a mutation has begun,
/// [`Controller::check_registration`]: a fence this host owes and could not raise, then the
/// connection's registration under the revision the mutation was admitted at, then the accepted
/// deadline on this daemon's own continuous clock. A voice change waits for the coordinator's
/// lock, for the store and for the broker; the coordinator asks once its lock and the broker have
/// answered, and the grant store's seam asks again immediately before it writes. A deadline alone
/// would let a change that waited write while a fence is owed, or after the authority it was
/// admitted under was replaced.
///
/// The refusal the check gave is what the seam answers with, so it is what the coordinator and the
/// store carry back to the caller, the same one the project service and the workflow journal give.
pub(super) struct VoiceAdmission {
    controller: Arc<Controller>,
    carried: crate::authority::AdmittedMutation,
    /// What a start owes the hold store; nothing for any other voice change.
    start: Option<StartHold>,
}

/// What one voice start keeps for the hold store while it runs.
struct StartHold {
    row: Arc<AttemptRow>,
    /// The earlier start the request names, when it names one.
    supersedes: Option<ActionId>,
    /// The instant by which the request has to be written, once the hold is written.
    send_by: std::sync::Mutex<Option<kr_transport::clock::ContinuousInstant>>,
}

/// The row one voice start writes before it asks the managed service, and the one gate that ends it.
///
/// It holds the store and two identifiers, never the controller, so a closure that captures it does
/// not keep a stopped controller alive. The row ends when both have happened, in either order: the
/// start's effect says that no call of it can still be running unreconciled, and the claim the
/// start answers under has settled. A claim that could not settle (the answer could not be kept)
/// leaves the row standing whatever the effect said.
pub(super) struct AttemptRow {
    holds: Arc<crate::voice_start_holds::Record>,
    actor: ActorId,
    action: ActionId,
    gate: std::sync::Mutex<RowGate>,
}

#[derive(Default)]
struct RowGate {
    ended: bool,
    settled: bool,
    deleted: bool,
}

impl AttemptRow {
    fn new(holds: Arc<crate::voice_start_holds::Record>, actor: ActorId, action: ActionId) -> Self {
        Self {
            holds,
            actor,
            action,
            gate: std::sync::Mutex::new(RowGate::default()),
        }
    }

    /// The start's effect says that no call of it can still be running unreconciled.
    pub(super) fn ended(&self) {
        self.advance(|gate| gate.ended = true);
    }

    /// The claim the start answers under has settled, whatever it recorded.
    pub(super) fn settled(&self) {
        self.advance(|gate| gate.settled = true);
    }

    fn advance(&self, step: impl FnOnce(&mut RowGate)) {
        let run = {
            let mut gate = self
                .gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            step(&mut gate);
            let due = gate.ended && gate.settled && !gate.deleted;
            gate.deleted |= due;
            due
        };
        if run {
            // The delete waits for the store, so it runs where a wait is allowed.
            let delete = || {
                if let Err(error) = self.holds.end(self.actor.clone(), self.action) {
                    // The row stays until its end or a start that names it.
                    eprintln!("kr-controller: a voice start's hold could not be ended: {error}");
                }
            };
            if tokio::runtime::Handle::try_current().is_ok_and(|runtime| {
                runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
            }) {
                tokio::task::block_in_place(delete);
            } else {
                delete();
            }
        }
    }
}

/// The earlier start a voice start names in its preconditions, when it names one.
///
/// # Errors
///
/// Returns an invalid-argument refusal when the key is present and is not an action identifier.
fn supersession_named_by(expected: &ParamsValue) -> Result<Option<ActionId>> {
    let kr_cbor::CanonicalValue::Map(map) = expected.as_value() else {
        return Ok(None);
    };
    for (key, value) in map.entries() {
        if key.as_str() != kr_protocol::action::SUPERSEDES_ACTION_KEY {
            continue;
        }
        if matches!(value, kr_cbor::CanonicalValue::Null) {
            return Err(ControllerError::InvalidArgument(format!(
                "the precondition {key} names an earlier start and then says nothing about it"
            )));
        }
        return kr_protocol::wire::from_value::<ActionId>(value)
            .map(Some)
            .map_err(|error| {
                ControllerError::InvalidArgument(format!("the precondition {key}: {error}"))
            });
    }
    Ok(None)
}

impl VoiceAdmission {
    pub(super) fn new(
        controller: Arc<Controller>,
        carried: crate::authority::AdmittedMutation,
    ) -> Self {
        Self {
            controller,
            carried,
            start: None,
        }
    }

    /// Makes this the admission of a voice start, which writes its hold before the service is
    /// asked.
    fn for_a_start(mut self, start: StartHold) -> Self {
        self.start = Some(start);
        self
    }

    /// The claim this admission's start answers under has settled.
    pub(super) fn settled(&self) {
        if let Some(start) = &self.start {
            start.row.settled();
        }
    }

    /// Asks the check, and answers with its own refusal.
    fn check(&self) -> Result<()> {
        self.controller.check_registration(&self.carried)
    }
}

impl std::fmt::Debug for VoiceAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VoiceAdmission")
            .field("carried", &self.carried)
            .finish_non_exhaustive()
    }
}

impl kr_voice::Admission for VoiceAdmission {
    fn still_admitted(&self) -> std::result::Result<(), ProtocolError> {
        self.check().map_err(|refusal| refusal.to_protocol_error())
    }

    fn time_left(&self) -> Option<std::time::Duration> {
        self.carried
            .deadline
            .map(|deadline| deadline.saturating_duration_since(self.controller.clock.now()))
    }

    fn connection(&self) -> Option<kr_protocol::ids::ConnectionId> {
        Some(self.carried.connection_id)
    }

    /// Writes the start's hold, or refuses the start in the hold's own words.
    ///
    /// The readings come in this order, so that every wait before the write lock counts toward the
    /// start's moment and none of it extends the time the start has to send: the continuous clock;
    /// the settled wall clock, which can wait for the policy lock and the floor's write; the write
    /// lock; and the continuous clock again, once the lock is held. The start's moment is the wall
    /// reading plus what the continuous clock counted between the first and the last of them.
    fn before_the_broker(&self, duration_seconds: u32) -> std::result::Result<(), ProtocolError> {
        use crate::voice_start_holds::{Decision, SEND_LIMIT_MS, hold_ends_ms, hold_words};
        use kr_protocol::error::ErrorCode;
        use kr_protocol::grant::GrantExpiry;
        use kr_protocol::scalars::TimestampMs;

        let Some(start) = &self.start else {
            return Ok(());
        };
        let controller = &self.controller;
        let first = controller.clock.now();
        let wall = controller.settled_now_ms();
        let at_the_lock = std::cell::Cell::new(first);
        let moments = || {
            let now = controller.clock.now();
            at_the_lock.set(now);
            let waited =
                u64::try_from(now.saturating_duration_since(first).as_millis()).unwrap_or(u64::MAX);
            let asked = wall.saturating_add(waited);
            (asked, hold_ends_ms(asked, duration_seconds))
        };
        let grants = controller.sharing.grants();
        // The clock floor's own refusal (storage, or a clock whose continuity is lost) goes back
        // unchanged: it is never the hold's words.
        let floor_refusal = std::cell::RefCell::new(None);
        let bound_passed = |ends: u64, asked: u64| {
            grants
                .bound_passed(
                    GrantExpiry::At {
                        expires_at_ms: TimestampMs::new(ends),
                    },
                    asked,
                )
                .map_err(|refusal| {
                    *floor_refusal.borrow_mut() = Some(refusal);
                    ControllerError::registry("the clock floor could not decide the hold")
                })
        };
        let floor_covers = |ends: u64| {
            grants.floor_on_disk_covers(GrantExpiry::At {
                expires_at_ms: TimestampMs::new(ends),
            })
        };
        let begin = || {
            start.row.holds.begin(
                start.row.actor.clone(),
                start.row.action,
                start.supersedes,
                &moments,
                &bound_passed,
                &floor_covers,
            )
        };
        // The write waits for the store, up to its busy timeout, so it runs where a wait is allowed.
        let decided = if tokio::runtime::Handle::try_current().is_ok_and(|runtime| {
            runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        }) {
            tokio::task::block_in_place(begin)
        } else {
            begin()
        };
        match decided {
            Ok(Decision::Admitted) => {
                let limit = std::time::Duration::from_millis(SEND_LIMIT_MS);
                let by = at_the_lock.get().checked_add(limit);
                // A request written after the admission's own deadline would make a call that the
                // second check then closes, so the limit is bounded by that deadline too.
                let by = match (by, self.carried.deadline) {
                    (Some(by), Some(deadline)) => Some(by.min(deadline)),
                    (by, _) => by,
                };
                *start
                    .send_by
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = by;
                Ok(())
            }
            Ok(Decision::Held(held)) => Err(ProtocolError::new(
                ErrorCode::DraftConflict,
                hold_words(&held, start.supersedes),
            )),
            Err(error) => {
                if let Some(refusal) = floor_refusal.into_inner() {
                    return Err(refusal.to_protocol_error());
                }
                // A failed commit can leave the row on disk, and nothing was asked: the row ends
                // when the claim settles. The delete names the action, so it harms nothing when
                // the row is absent.
                start.row.ended();
                eprintln!("kr-controller: a voice start's hold could not be written: {error}");
                Err(ProtocolError::new(
                    ErrorCode::StorageUnavailable,
                    crate::voice_start_holds::HOLD_NOT_RECORDED_WORDS.to_owned(),
                ))
            }
        }
    }

    fn after_the_broker(&self, effect: kr_voice::BrokerEffect) {
        if let Some(start) = &self.start
            && ends_the_row(effect)
        {
            start.row.ended();
        }
    }

    fn send_by(&self) -> Option<kr_transport::clock::ContinuousInstant> {
        *self
            .start
            .as_ref()?
            .send_by
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn deferred(&self) -> Option<kr_voice::AfterDeferred> {
        let row = Arc::clone(&self.start.as_ref()?.row);
        Some(Box::new(move |effect| {
            if ends_the_row(effect) {
                row.ended();
            }
        }))
    }
}

/// Whether a start's effect says that no call of the start can still be running unreconciled, so
/// that the row it wrote may end once its claim has settled.
fn ends_the_row(effect: kr_voice::BrokerEffect) -> bool {
    use kr_voice::BrokerEffect::{
        Bound, Closed, Deferred, Handed, NotAsked, Open, Refused, Unknown,
    };
    match effect {
        NotAsked | Refused | Bound | Handed | Closed => true,
        Unknown | Open | Deferred => false,
    }
}

/// Whether a delegation's answer is the challenge a device signs, which admits nothing.
fn is_a_challenge(outcome: &Result<ParamsValue>) -> bool {
    outcome
        .as_ref()
        .ok()
        .and_then(|answer| answer.to_typed::<VoiceDelegateResult>().ok())
        .is_some_and(|result| {
            matches!(
                result.outcome,
                VoiceDelegationOutcome::ConfirmationRequired { .. }
            )
        })
}

#[cfg(test)]
mod attempt_row {
    use super::*;
    use crate::voice_start_holds::{Decision, Record};

    fn actor() -> ActorId {
        ActorId::new("local:1").expect("an actor")
    }

    fn action(n: u8) -> ActionId {
        ActionId::new(kr_protocol::scalars::Uuid::from_bytes([n; 16]))
    }

    /// A record with one row for the actor under the first action, and the gate over that row.
    fn written() -> (tempfile::TempDir, Arc<Record>, AttemptRow) {
        let directory = tempfile::tempdir().expect("a directory");
        let holds = Arc::new(Record::open(directory.path()).expect("the record opens"));
        let admitted = holds
            .begin(
                actor(),
                action(1),
                None,
                &|| (10, 100),
                &|_, _| Ok(false),
                &|_| false,
            )
            .expect("begin");
        assert_eq!(admitted, Decision::Admitted);
        let row = AttemptRow::new(Arc::clone(&holds), actor(), action(1));
        (directory, holds, row)
    }

    fn stands(holds: &Record) -> bool {
        holds.standing(actor()).expect("the record reads").is_some()
    }

    /// The row ends when the start's effect and the claim's settlement have both happened, in
    /// either order, and not when only one has.
    #[test]
    fn the_row_ends_when_the_effect_and_the_claim_have_both_happened_in_either_order() {
        for effect_first in [true, false] {
            let (_directory, holds, row) = written();
            if effect_first {
                row.ended();
            } else {
                row.settled();
            }
            assert!(stands(&holds), "one of the two is not enough");
            if effect_first {
                row.settled();
            } else {
                row.ended();
            }
            assert!(!stands(&holds), "effect first: {effect_first}");
        }
    }

    /// A claim that could not settle (its answer could not be kept) leaves the row, however often
    /// the effect says that nothing is running.
    #[test]
    fn a_claim_that_never_settled_leaves_the_row() {
        let (_directory, holds, row) = written();
        row.ended();
        row.ended();
        assert!(stands(&holds));
    }

    /// The gate deletes once: a later row of the same device is not deleted by a gate that has run.
    #[test]
    fn a_gate_that_has_run_deletes_nothing_again() {
        let (_directory, holds, row) = written();
        row.ended();
        row.settled();
        assert!(!stands(&holds));
        holds
            .begin(
                actor(),
                action(2),
                None,
                &|| (20, 200),
                &|_, _| Ok(false),
                &|_| false,
            )
            .expect("a later start");
        row.ended();
        row.settled();
        assert_eq!(
            holds
                .standing(actor())
                .expect("reads")
                .map(|row| row.action),
            Some(action(2)),
            "the later row stands"
        );
    }

    /// A delete that comes after a named start replaced the row leaves the row the named start
    /// wrote: the earlier attempt's gate names its own action, so the device is still held by the
    /// later one, and a start that names neither is refused in the later one's words.
    #[test]
    fn a_delayed_delete_of_an_earlier_attempt_leaves_the_row_that_a_named_start_replaced() {
        let (_directory, holds, earlier) = written();
        // The later start names the earlier one and replaces its row before the earlier delete runs.
        let replaced = holds
            .begin(
                actor(),
                action(2),
                Some(action(1)),
                &|| (20, 120),
                &|_, _| Ok(false),
                &|_| false,
            )
            .expect("a named start");
        assert_eq!(replaced, Decision::Admitted);
        // The earlier attempt's effect and claim now end its gate, and its delete runs late.
        earlier.ended();
        earlier.settled();
        let unnamed = holds
            .begin(
                actor(),
                action(3),
                None,
                &|| (30, 130),
                &|_, _| Ok(false),
                &|_| false,
            )
            .expect("an unnamed start");
        let Decision::Held(held) = unnamed else {
            panic!("the later start's row holds the device: {unnamed:?}");
        };
        assert_eq!(held.action, action(2));
    }
}

/// The hold a voice start writes before the managed service is asked, on clocks the test moves.
#[cfg(test)]
mod a_start_hold_on_clocks_moved_by_hand {
    use super::*;
    use crate::service::net::tests::{daemon_on_clocks_to_move, manual_clocks};
    use kr_protocol::error::ErrorCode;
    use kr_voice::Admission as _;
    use kr_voice::BrokerEffect;

    fn actor() -> ActorId {
        ActorId::new("local:1").expect("an actor")
    }

    fn action(n: u8) -> ActionId {
        ActionId::new(kr_protocol::scalars::Uuid::from_bytes([n; 16]))
    }

    /// The admission of the start of `action` by the actor, with a deadline `deadline_in` out.
    async fn start_of(
        controller: &Arc<Controller>,
        action: ActionId,
        deadline_in: std::time::Duration,
    ) -> (VoiceAdmission, kr_transport::clock::ContinuousInstant) {
        let deadline = controller
            .clock
            .now()
            .checked_add(deadline_in)
            .expect("a deadline");
        let carried = crate::service::a_close_a_worker_never_answers::admission(
            controller,
            kr_transport::window::AcceptedDeadline {
                deadline,
                bound: kr_transport::window::DeadlineBound::RequestedTtl,
            },
        )
        .await;
        let admission =
            VoiceAdmission::new(Arc::clone(controller), carried).for_a_start(StartHold {
                row: Arc::new(AttemptRow::new(
                    Arc::clone(&controller.voice_start_holds),
                    actor(),
                    action,
                )),
                supersedes: None,
                send_by: std::sync::Mutex::new(None),
            });
        (admission, deadline)
    }

    fn standing(controller: &Controller) -> crate::voice_start_holds::Row {
        controller
            .voice_start_holds
            .standing(actor())
            .expect("the record reads")
            .expect("a hold stands")
    }

    /// The host ends a start's row only for the effects that say no call of the start can still be
    /// running unreconciled.
    #[test]
    fn a_start_ends_its_row_only_for_the_effects_that_leave_no_call_unreconciled() {
        for (effect, ends) in [
            (BrokerEffect::NotAsked, true),
            (BrokerEffect::Refused, true),
            (BrokerEffect::Bound, true),
            (BrokerEffect::Handed, true),
            (BrokerEffect::Closed, true),
            (BrokerEffect::Unknown, false),
            (BrokerEffect::Open, false),
            (BrokerEffect::Deferred, false),
        ] {
            assert_eq!(ends_the_row(effect), ends, "{effect:?}");
        }
    }

    /// The time a start has to send is bounded by its own deadline when that comes first, and is
    /// the send limit from the moment the hold is written when the deadline is farther.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_send_limit_is_cut_short_by_the_deadline_of_the_start() {
        let temp = kr_ipc::testing::TempHost::create();
        let (_continuous, _wall, clocks) = manual_clocks();
        let controller = daemon_on_clocks_to_move(&temp, clocks).await;

        let (near, deadline) =
            start_of(&controller, action(1), std::time::Duration::from_secs(10)).await;
        near.before_the_broker(600).expect("admitted");
        assert_eq!(
            near.send_by(),
            Some(deadline),
            "the deadline is nearer than the limit"
        );

        // The second start names the first, so that it is admitted over the standing row.
        let (mut far, _) =
            start_of(&controller, action(2), std::time::Duration::from_secs(600)).await;
        if let Some(start) = far.start.as_mut() {
            start.supersedes = Some(action(1));
        }
        far.before_the_broker(600).expect("admitted");
        let limit = std::time::Duration::from_millis(crate::voice_start_holds::SEND_LIMIT_MS);
        assert_eq!(
            far.send_by(),
            Some(controller.clock.now().checked_add(limit).expect("a limit")),
            "the limit counts from the moment the hold is written"
        );
    }

    /// Every wait before the write lock counts toward the start's moment: the time the continuous
    /// clock counts between the start's first reading and the write adds to the wall reading, and
    /// the wall clock itself is read once. The wall clock this case gives the daemon moves the
    /// continuous clock four seconds when the start reads it, which is after the start's first
    /// reading of the continuous clock and before the lock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_moment_of_a_start_counts_what_the_continuous_clock_counted_before_the_lock() {
        let temp = kr_ipc::testing::TempHost::create();
        let continuous = kr_transport::clock::ManualClock::new();
        let wall_ms = kr_ipc::now_ms().get();
        let armed = Arc::new(std::sync::Mutex::new(None::<std::thread::ThreadId>));
        let clocks = crate::service::Clocks {
            continuous: Arc::new(continuous.clone()),
            wall: {
                let (armed, continuous) = (Arc::clone(&armed), continuous.clone());
                crate::service::WallClock::from_fn(move || {
                    let mut on = armed
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if *on == Some(std::thread::current().id()) {
                        *on = None;
                        continuous.advance(std::time::Duration::from_secs(4));
                    }
                    wall_ms
                })
            },
        };
        let controller = daemon_on_clocks_to_move(&temp, clocks).await;
        let (start, _) = start_of(&controller, action(1), std::time::Duration::from_secs(60)).await;
        // The start's own thread, and no other, moves the continuous clock at its next reading of
        // the wall clock.
        *armed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(std::thread::current().id());
        start.before_the_broker(600).expect("admitted");
        assert_eq!(
            *armed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            None,
            "the start read the wall clock on its own thread"
        );
        let row = standing(&controller);
        assert_eq!(row.asked_ms, wall_ms + 4_000);
        assert_eq!(
            row.ends_ms,
            crate::voice_start_holds::hold_ends_ms(wall_ms + 4_000, 600)
        );
    }

    /// A hold ends at its end and not before, to the millisecond, on the clocks the host keeps: a
    /// start read one millisecond before the end is held, and one read at the end is admitted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hold_stands_until_the_millisecond_it_ends() {
        let temp = kr_ipc::testing::TempHost::create();
        let (_continuous, wall, clocks) = manual_clocks();
        let controller = daemon_on_clocks_to_move(&temp, clocks).await;
        let (first, _) = start_of(&controller, action(1), std::time::Duration::from_secs(60)).await;
        first.before_the_broker(600).expect("admitted");
        let ends = standing(&controller).ends_ms;

        wall.store(ends - 1, std::sync::atomic::Ordering::SeqCst);
        let (early, _) = start_of(&controller, action(2), std::time::Duration::from_secs(60)).await;
        let held = early
            .before_the_broker(600)
            .expect_err("a start one millisecond before the end is held");
        assert_eq!(held.code, ErrorCode::DraftConflict, "{held}");
        assert_eq!(standing(&controller).action, action(1));

        wall.store(ends, std::sync::atomic::Ordering::SeqCst);
        let (at_the_end, _) =
            start_of(&controller, action(3), std::time::Duration::from_secs(60)).await;
        let admitted = at_the_end.before_the_broker(600);
        assert!(
            admitted.is_ok(),
            "a start read at the end is admitted: {admitted:?}"
        );
        assert_eq!(standing(&controller).action, action(3));
    }

    /// The thread that runs a wall clock's reading is armed, and the first reading by that thread
    /// runs the step: the case's own thread is the start's thread, so no task of the daemon sets it
    /// off.
    type Armed = Arc<std::sync::Mutex<Option<std::thread::ThreadId>>>;

    /// Clocks whose wall clock always answers `wall_ms`, and runs `at_the_reading` at the first
    /// reading by the armed thread, which is after the start's first reading of `continuous` and
    /// before the write lock.
    fn clocks_that_move_at_a_reading(
        continuous: Arc<dyn kr_transport::clock::ContinuousClock>,
        wall_ms: u64,
        at_the_reading: impl Fn() + Send + Sync + 'static,
    ) -> (Armed, crate::service::Clocks) {
        let armed: Armed = Arc::new(std::sync::Mutex::new(None));
        let clocks = crate::service::Clocks {
            continuous,
            wall: {
                let armed = Arc::clone(&armed);
                crate::service::WallClock::from_fn(move || {
                    let fire = {
                        let mut on = armed
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let fire = *on == Some(std::thread::current().id());
                        if fire {
                            *on = None;
                        }
                        fire
                    };
                    if fire {
                        at_the_reading();
                    }
                    wall_ms
                })
            },
        };
        (armed, clocks)
    }

    /// A continuous clock that, from the moment it is armed, asks a third connection to the record
    /// of holds for the write lock at each reading, waits no time for it, and keeps the answer:
    /// the code of the refusal, or none when the lock was free.
    #[derive(Debug)]
    struct ProbingClock {
        inner: kr_transport::clock::ManualClock,
        record: std::path::PathBuf,
        armed: std::sync::atomic::AtomicBool,
        answers: std::sync::Mutex<Vec<Option<rusqlite::ErrorCode>>>,
    }

    impl ProbingClock {
        fn over(inner: &kr_transport::clock::ManualClock, record: std::path::PathBuf) -> Arc<Self> {
            Arc::new(Self {
                inner: inner.clone(),
                record,
                armed: std::sync::atomic::AtomicBool::new(false),
                answers: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn arm(&self, armed: bool) {
            self.armed.store(armed, std::sync::atomic::Ordering::SeqCst);
        }

        fn answers(&self) -> Vec<Option<rusqlite::ErrorCode>> {
            self.answers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl kr_transport::clock::ContinuousClock for ProbingClock {
        fn now(&self) -> kr_transport::clock::ContinuousInstant {
            if self.armed.load(std::sync::atomic::Ordering::SeqCst) {
                let probe = rusqlite::Connection::open(&self.record).expect("a third connection");
                probe
                    .busy_timeout(std::time::Duration::ZERO)
                    .expect("no wait for the lock");
                let asked = probe.execute_batch("BEGIN IMMEDIATE");
                let answer = match asked {
                    Ok(()) => {
                        probe.execute_batch("ROLLBACK").expect("the lock is let go");
                        None
                    }
                    Err(rusqlite::Error::SqliteFailure(refused, _)) => Some(refused.code),
                    Err(other) => panic!("the probe failed in another way: {other}"),
                };
                self.answers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(answer);
            }
            kr_transport::clock::ContinuousClock::now(&self.inner)
        }
    }

    fn arm_for_this_thread(armed: &Armed) {
        *armed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(std::thread::current().id());
    }

    /// Another connection to the record of holds that takes its write lock now, waits for the
    /// message the returned sender sends, runs `then`, lets the lock go, and says so on `ended`.
    fn another_writer_of_the_holds(
        temp: &kr_ipc::testing::TempHost,
        then: impl FnOnce() + Send + 'static,
        ended: std::sync::mpsc::Sender<()>,
    ) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let path = temp
            .environment()
            .state_dir()
            .join(crate::voice_start_holds::VOICE_START_HOLDS_RECORD);
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let writer = std::thread::spawn(move || {
            let connection = rusqlite::Connection::open(path).expect("the record opens");
            connection
                .execute_batch("BEGIN IMMEDIATE")
                .expect("another writer holds the record");
            held_tx.send(()).expect("the case waits");
            wait.recv().expect("the case lets the writer go");
            then();
            connection
                .execute_batch("ROLLBACK")
                .expect("the other writer lets the record go");
            let _ = ended.send(());
        });
        held_rx.recv().expect("the record is held");
        (release, writer)
    }

    /// A slot the clock's step finds the writer's release in, once the case has made the writer.
    type Release = Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>>;

    fn let_the_writer_go(release: &Release) {
        if let Some(release) = release
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            release.send(()).expect("the writer waits");
        }
    }

    /// Both waits before the lock count toward the start's moment: the continuous clock moves
    /// four seconds while the start reads the settled wall clock, and four more while another
    /// writer holds the record. The moment is the wall reading plus eight seconds, and the time to
    /// send counts from the reading once the lock is held: the other writer has let go before the
    /// first reading that follows, and a third connection that asks for the lock at that reading,
    /// and waits no time for it, is refused as busy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_moment_of_a_start_counts_the_wait_for_the_floor_and_the_wait_for_the_lock() {
        let temp = kr_ipc::testing::TempHost::create();
        let continuous = kr_transport::clock::ManualClock::new();
        let probe = ProbingClock::over(
            &continuous,
            temp.environment()
                .state_dir()
                .join(crate::voice_start_holds::VOICE_START_HOLDS_RECORD),
        );
        let wall_ms = kr_ipc::now_ms().get();
        let release: Release = Arc::new(std::sync::Mutex::new(None));
        let ended: Arc<std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>> =
            Arc::new(std::sync::Mutex::new(None));
        let (armed, clocks) = clocks_that_move_at_a_reading(
            Arc::clone(&probe) as Arc<dyn kr_transport::clock::ContinuousClock>,
            wall_ms,
            {
                let (continuous, release, ended, probe) = (
                    continuous.clone(),
                    Arc::clone(&release),
                    Arc::clone(&ended),
                    Arc::clone(&probe),
                );
                move || {
                    continuous.advance(std::time::Duration::from_secs(4));
                    let_the_writer_go(&release);
                    // The other writer has let the record go before any later reading is probed,
                    // so a busy answer to the probe is the start's own lock.
                    if let Some(ended) = ended
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                    {
                        ended.recv().expect("the other writer let go");
                    }
                    probe.arm(true);
                }
            },
        );
        let controller = daemon_on_clocks_to_move(&temp, clocks).await;
        let (writer_ended, writer_ends) = std::sync::mpsc::channel::<()>();
        let (writer_release, writer) = another_writer_of_the_holds(
            &temp,
            {
                let continuous = continuous.clone();
                move || continuous.advance(std::time::Duration::from_secs(4))
            },
            writer_ended,
        );
        *release
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(writer_release);
        *ended
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(writer_ends);
        let (start, _) =
            start_of(&controller, action(1), std::time::Duration::from_secs(600)).await;
        arm_for_this_thread(&armed);
        start.before_the_broker(600).expect("admitted");
        probe.arm(false);
        writer.join().expect("the other writer ran");
        let row = standing(&controller);
        assert_eq!(row.asked_ms, wall_ms + 8_000, "both waits count");
        let answers = probe.answers();
        assert_eq!(
            answers.first(),
            Some(&Some(rusqlite::ErrorCode::DatabaseBusy)),
            "the first reading of the continuous clock after the other writer let go was made while \
             the write lock was free: {answers:?}"
        );
        let limit = std::time::Duration::from_millis(crate::voice_start_holds::SEND_LIMIT_MS);
        assert_eq!(
            start.send_by(),
            Some(controller.clock.now().checked_add(limit).expect("a limit")),
            "the time to send counts from the reading once the lock is held"
        );
    }

    /// An admission that ends while the hold waits for the write lock is refused in its own words
    /// before the service is asked, and the row the start wrote ends with it: the caller's own
    /// sequence is the check, the hold, the check that stands immediately before the service, and
    /// the effect the host is told when that check refuses.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_admission_that_ends_while_the_hold_is_written_asks_the_broker_nothing() {
        let temp = kr_ipc::testing::TempHost::create();
        let continuous = kr_transport::clock::ManualClock::new();
        let wall_ms = kr_ipc::now_ms().get();
        let release: Release = Arc::new(std::sync::Mutex::new(None));
        let (armed, clocks) =
            clocks_that_move_at_a_reading(Arc::new(continuous.clone()), wall_ms, {
                let (continuous, release) = (continuous.clone(), Arc::clone(&release));
                move || {
                    // The admission's deadline is a minute out, and it passes during the wait.
                    continuous.advance(std::time::Duration::from_secs(61));
                    let_the_writer_go(&release);
                }
            });
        let controller = daemon_on_clocks_to_move(&temp, clocks).await;
        let (writer_release, writer) =
            another_writer_of_the_holds(&temp, || (), std::sync::mpsc::channel().0);
        *release
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(writer_release);
        let (start, _) = start_of(&controller, action(1), std::time::Duration::from_secs(60)).await;
        start
            .still_admitted()
            .expect("the check before the hold passes");
        arm_for_this_thread(&armed);
        start
            .before_the_broker(600)
            .expect("the hold is written once the other writer lets go");
        writer.join().expect("the other writer ran");
        let refused = start
            .still_admitted()
            .expect_err("the check before the service sees the admission over");
        assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused}");
        assert!(
            refused
                .to_string()
                .contains("the deadline this action was admitted under passed"),
            "the refusal says the admission's deadline passed: {refused}"
        );
        assert_eq!(standing(&controller).action, action(1), "the row stands");
        // Nothing was asked, so the effect ends the row, and the claim's settlement deletes it.
        start.after_the_broker(BrokerEffect::NotAsked);
        start.settled();
        assert!(
            controller
                .voice_start_holds
                .standing(actor())
                .expect("the record reads")
                .is_none(),
            "no row stands for a start that asked nothing"
        );
    }

    /// A hold the store reports it could not write can still have left its row: the start is
    /// refused in the unrecorded words before the service, the row stands until the start's claim
    /// settles, and the claim's settlement ends it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hold_the_store_reports_failed_leaves_no_row_once_its_claim_has_settled() {
        let temp = kr_ipc::testing::TempHost::create();
        let (_continuous, _wall, clocks) = manual_clocks();
        let controller = daemon_on_clocks_to_move(&temp, clocks).await;
        // The row of the action stands on disk, as a commit that reported failure can leave it.
        let (planted, _) =
            start_of(&controller, action(1), std::time::Duration::from_secs(60)).await;
        planted.before_the_broker(600).expect("admitted");
        let other = rusqlite::Connection::open(
            temp.environment()
                .state_dir()
                .join(crate::voice_start_holds::VOICE_START_HOLDS_RECORD),
        )
        .expect("the record opens beside the daemon's own handle");
        other
            .busy_timeout(std::time::Duration::from_secs(10))
            .expect("waits for the daemon's own writes");
        other
            .execute_batch(
                "CREATE TRIGGER refuses_a_row BEFORE INSERT ON voice_start_holds
                 BEGIN SELECT RAISE(ABORT, 'the store refused'); END",
            )
            .expect("the store refuses a row");
        // The same action is written again, naming itself so that the standing row does not hold
        // it, and the store fails the write.
        let (mut start, _) =
            start_of(&controller, action(1), std::time::Duration::from_secs(60)).await;
        if let Some(hold) = start.start.as_mut() {
            hold.supersedes = Some(action(1));
        }
        let refused = start
            .before_the_broker(600)
            .expect_err("the store could not write the hold");
        assert_eq!(refused.code, ErrorCode::StorageUnavailable, "{refused}");
        assert!(
            refused
                .to_string()
                .contains(crate::voice_start_holds::HOLD_NOT_RECORDED_WORDS),
            "{refused}"
        );
        assert_eq!(
            standing(&controller).action,
            action(1),
            "the row stands until the claim has settled"
        );
        start.settled();
        assert!(
            controller
                .voice_start_holds
                .standing(actor())
                .expect("the record reads")
                .is_none(),
            "the claim settled, so the row of the start that asked nothing ends"
        );
    }

    /// While the clock floor is ahead of the wall clock, a start's moment is the floor's, so the
    /// row ends an hour of the host's own time after it was written: a start the wall clock alone
    /// would admit is held until the floor's end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_row_written_while_the_floor_is_ahead_of_the_wall_clock_ends_at_the_floors_time() {
        let temp = kr_ipc::testing::TempHost::create();
        let (_continuous, wall, clocks) = manual_clocks();
        let controller = daemon_on_clocks_to_move(&temp, clocks).await;
        let behind = wall.load(std::sync::atomic::Ordering::SeqCst);
        let ahead = behind + 3_600_000;
        // The floor takes the reading an hour ahead, and the wall clock then steps back.
        wall.store(ahead, std::sync::atomic::Ordering::SeqCst);
        let _ = controller.settled_now_ms();
        controller.settle_floor();
        wall.store(behind, std::sync::atomic::Ordering::SeqCst);

        let (first, _) = start_of(&controller, action(1), std::time::Duration::from_secs(60)).await;
        first.before_the_broker(600).expect("admitted");
        let row = standing(&controller);
        assert!(
            row.asked_ms >= ahead,
            "the moment is the floor's: {} against {ahead}",
            row.asked_ms
        );
        assert_eq!(
            row.ends_ms,
            crate::voice_start_holds::hold_ends_ms(row.asked_ms, 600)
        );
        // The wall clock alone is far behind the row's end, and the start is held all the same.
        let (second, _) =
            start_of(&controller, action(2), std::time::Duration::from_secs(60)).await;
        let held = second
            .before_the_broker(600)
            .expect_err("a start inside the floor's hold is held");
        assert_eq!(held.code, ErrorCode::DraftConflict, "{held}");
        // The wall clock catches up with the end, and the start is admitted.
        wall.store(row.ends_ms, std::sync::atomic::Ordering::SeqCst);
        let (third, _) = start_of(&controller, action(3), std::time::Duration::from_secs(60)).await;
        let admitted = third.before_the_broker(600);
        assert!(
            admitted.is_ok(),
            "a start read at the end is admitted: {admitted:?}"
        );
    }

    /// A start is not decided while the floor is owed its record: where the floor's write fails,
    /// the start is refused before the service under the floor's own code, never the hold's, and
    /// the standing row is untouched; once the write succeeds the start is admitted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hold_is_not_decided_while_the_clock_floor_is_owed_its_record() {
        let temp = kr_ipc::testing::TempHost::create();
        let (_continuous, wall, clocks) = manual_clocks();
        let controller = daemon_on_clocks_to_move(&temp, clocks).await;
        let (first, _) = start_of(&controller, action(1), std::time::Duration::from_secs(60)).await;
        first.before_the_broker(600).expect("admitted");
        let ends = standing(&controller).ends_ms;

        // The row has run out on the wall clock, and the registry cannot be written.
        wall.store(ends + 1_000, std::sync::atomic::Ordering::SeqCst);
        let registry = rusqlite::Connection::open(temp.environment().registry_database())
            .expect("the registry opens beside the daemon's own handle");
        registry
            .busy_timeout(std::time::Duration::from_secs(10))
            .expect("waits for the daemon's own writes");
        controller
            .sharing
            .grants()
            .wait_for_storage_up_to(std::time::Duration::ZERO)
            .expect("the store waits no time for another writer");
        registry
            .execute_batch("BEGIN IMMEDIATE")
            .expect("another writer holds the registry");
        let (second, _) =
            start_of(&controller, action(2), std::time::Duration::from_secs(60)).await;
        let refused = second
            .before_the_broker(600)
            .expect_err("the floor cannot be written, so nothing is decided");
        assert_ne!(refused.code, ErrorCode::DraftConflict, "{refused}");
        assert_eq!(refused.code, ErrorCode::StorageUnavailable, "{refused}");
        assert!(
            !refused
                .to_string()
                .contains(crate::voice_start_holds::HOLD_NOT_RECORDED_WORDS),
            "the floor's own refusal goes back, not the hold's words: {refused}"
        );
        assert_eq!(
            standing(&controller).action,
            action(1),
            "a refusal of the floor leaves the standing row as it was"
        );

        registry
            .execute_batch("ROLLBACK")
            .expect("the other writer lets the registry go");
        controller
            .sharing
            .grants()
            .wait_for_storage_up_to(std::time::Duration::from_secs(5))
            .expect("the store waits as it does");
        let (third, _) = start_of(&controller, action(3), std::time::Duration::from_secs(60)).await;
        let admitted = third.before_the_broker(600);
        assert!(
            admitted.is_ok(),
            "the floor is written, so the lapsed row no longer holds: {admitted:?}"
        );
    }

    /// The closure a start leaves for a deferred call holds the store and two identifiers, not the
    /// controller: a controller that stops while the closure is queued is not kept alive by it,
    /// and the closure still runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_deferred_closure_does_not_keep_a_stopped_controller_alive() {
        let temp = kr_ipc::testing::TempHost::create();
        let (_continuous, _wall, clocks) = manual_clocks();
        let controller = daemon_on_clocks_to_move(&temp, clocks).await;
        let (start, _) = start_of(&controller, action(1), std::time::Duration::from_secs(60)).await;
        start.before_the_broker(600).expect("admitted");
        let closure = start.deferred().expect("a start defers its closure");
        let controller_after = Arc::downgrade(&controller);
        drop(start);
        drop(controller);
        // The daemon's own tasks let go of their handles as they run, so the count is read up to a
        // bound; what the closure holds is never let go of by them.
        for _ in 0..120_000 {
            if controller_after.strong_count() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(
            controller_after.strong_count(),
            0,
            "the closure keeps the controller alive after its last handle was dropped"
        );
        closure(BrokerEffect::Closed);
    }
}
