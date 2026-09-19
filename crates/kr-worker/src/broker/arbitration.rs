//! One arbitration for every pending resource, and exactly one resolution each.
//!
//! Section 11: "The host resolves each pending resource once through the encode, recheck, claim
//! and dispatch transaction... Reconnect reconciles upstream IDs and receipts; it does not reissue
//! an uncertain response."
//!
//! The order of the four steps is what makes the rule hold. Encoding happens *outside* the claim,
//! because encoding can be slow and a native answer that arrives during it must win. The recheck
//! and the claim happen together, so between deciding that the request is still answerable and
//! taking it nothing can move. The dispatch marker is committed before the answer is written to
//! the upstream, so a crash in the middle leaves a record that says an answer may already have
//! gone. And an answer whose outcome nobody can establish leaves the resource `uncertain` rather
//! than pending, because a pending resource is one a later answer could still claim.
//!
//! Every state change here is *planned* before it is *committed*. A plan validates and produces
//! the record as it would be; the caller writes that record durably and only then commits the plan
//! to memory. That split is what keeps a failed or racing write from leaving memory ahead of the
//! ledger.

use std::collections::BTreeMap;

use kr_protocol::gateway::{
    ArbitrationError, DownstreamRequestId, PendingResource, PendingState, check_transition,
};
use kr_protocol::ids::{ActorId, ApplicationInstanceId, BrokerBindingId, PendingResourceId};
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_protocol::session::Durability;

use crate::broker::error::{BrokerError, Result};

/// One pending resource and what has happened to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    /// The resource as clients see it.
    pub resource: PendingResource,
    /// The claim currently held, while one is.
    pub claim: Option<Claim>,
    /// True once an answer has left this host for the upstream.
    ///
    /// This is the flag that decides what a reconnect does. A claimed resource that was never
    /// dispatched can go back to pending; one that was dispatched and never confirmed is
    /// uncertain, and an uncertain resource is never answered a second time.
    pub dispatched: bool,
    /// Which writer holds the one admission to transmit an answer, once one does.
    ///
    /// A resource has two possible writers: the rich answer a component encoded, and the native
    /// client's own answer travelling the forwarding path. Both consume this, and there is one, so
    /// the second one to arrive is refused *before* its bytes go rather than recorded as a
    /// competing answer afterwards.
    pub transmitter: Option<Transmitter>,
    /// The binding whose decoder produced it, where one did.
    pub decoder: Option<BrokerBindingId>,
    /// The source event this request was recorded from.
    ///
    /// An interpretation must be of *this* frame. Without the link a decoder could interpret one
    /// request from another's bytes, and the ledger would record the wrong original beside the
    /// wrong identifier.
    pub source: Option<kr_protocol::ids::SourceEventHandle>,
}

/// Which writer holds the one admission to transmit an answer for a pending resource.
///
/// Section 11 gives every pending resource one resolution, and a resolution is bytes reaching the
/// upstream. Two writers can produce those bytes, so the admission is exclusive and named: a rich
/// answer is admitted under the claim that encoded it, and the native client's own answer is
/// admitted on the forwarding path it travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transmitter {
    /// A rich answer, admitted under the claim named.
    Rich(Uuid),
    /// The native client's own answer, admitted as it was forwarded.
    Native,
    /// An answer that went before this process started, read back from the dispatch marker.
    ///
    /// Which writer sent it is not recorded, because nothing needs it: what the marker says is
    /// that the one admission is spent, and that is what stops either writer taking it again.
    Spent,
}

impl Transmitter {
    /// Returns what a refusal calls this writer.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rich(_) => "a rich answer",
            Self::Native => "the native client's own answer",
            Self::Spent => "an answer this host had already sent",
        }
    }
}

/// What a claim gives its holder.
///
/// The identifier is the point. Checking only the actor would let a claim that a reconnect
/// released resolve the *next* claim the same actor takes, which is two answers under one
/// authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// This claim, distinct from every other claim on this resource.
    pub claim_id: Uuid,
    /// The resource claimed.
    pub resource_id: PendingResourceId,
    /// The actor holding it.
    pub actor_id: ActorId,
    /// When the claim was taken.
    pub claimed_at: TimestampMs,
}

/// A validated state change that has not been applied yet.
///
/// The caller writes [`Transition::resource`] durably, then calls [`Arbitration::commit`]. Nothing
/// between those two points changes what the transition will do, because the arbitration is held
/// under the broker's one lock for both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    /// The resource as it will be.
    pub resource: PendingResource,
    /// The state it is in now, which the durable write is conditional on.
    pub from: PendingState,
    /// The claim this transition establishes or discharges.
    claim: Option<Claim>,
    /// Whether the transition takes the claim or gives it up.
    holds_claim: bool,
    /// Whether this transition also sets the dispatch marker.
    dispatched: bool,
    /// The writer this transition admits to transmit, when it admits one.
    transmitter: Option<Transmitter>,
}

impl Transition {
    /// Returns the claim this transition establishes, for a caller that took one.
    #[must_use]
    pub fn claim(&self) -> Option<&Claim> {
        self.claim.as_ref()
    }

    /// Returns true when this transition sets the dispatch marker.
    #[must_use]
    pub const fn sets_marker(&self) -> bool {
        self.dispatched
    }
}

/// What a reconnect found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reconciliation {
    /// Resources the upstream still has pending, which stay exactly as they were.
    pub still_pending: Vec<PendingResourceId>,
    /// Resources this host may already have answered, now uncertain and never reissued.
    pub uncertain: Vec<PendingResourceId>,
    /// Resources the upstream no longer has, which it resolved itself.
    pub withdrawn: Vec<PendingResourceId>,
    /// Claims that were never dispatched, released back to pending for a fresh answer.
    pub released: Vec<PendingResourceId>,
}

/// Which resources one reconciliation is about.
///
/// A reconnect knows what one upstream connection still has pending. It knows nothing about any
/// other, so applying its list to every resource this broker holds would cancel other upstreams'
/// requests for the crime of not being on a list that was never about them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconcileScope {
    /// The application instance that reconnected.
    pub application_instance_id: ApplicationInstanceId,
    /// The gateway connection whose identifiers the list names.
    pub connection: kr_protocol::ids::GatewayConnectionId,
}

/// The broker's live arbitration.
#[derive(Debug, Default)]
pub struct Arbitration {
    by_id: BTreeMap<PendingResourceId, Pending>,
    by_request: BTreeMap<DownstreamRequestId, PendingResourceId>,
    /// Every resource this arbitration touched while the journal was faulted.
    ///
    /// Recovery commits all of them, whatever state they reached. Keeping only the unresolved
    /// ones would leave a request the upstream withdrew inside the gap recorded as pending for
    /// ever, because nothing would ever write its ending down.
    volatile_touched: std::collections::BTreeSet<PendingResourceId>,
}

impl Arbitration {
    /// An empty arbitration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one pending resource.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the namespaced downstream identifier is
    /// already in use. Two live requests cannot share one identifier on one connection: the
    /// response correlation would be ambiguous, and an ambiguous correlation is how one answer
    /// resolves the wrong request.
    pub fn record(
        &mut self,
        resource: PendingResource,
        decoder: Option<BrokerBindingId>,
        source: Option<kr_protocol::ids::SourceEventHandle>,
    ) -> Result<()> {
        if let Some(existing) = self.by_request.get(&resource.request) {
            return Err(BrokerError::invalid(format!(
                "{} already names pending resource {existing}",
                resource.request
            )));
        }
        if resource.durability == Durability::Volatile {
            // Recorded inside a gap. Recovery commits it like everything else the gap touched;
            // without this a request that arrived while the journal was faulted would exist only
            // in memory and would be lost at the next restart.
            self.volatile_touched.insert(resource.resource_id);
        }
        self.by_request
            .insert(resource.request.clone(), resource.resource_id);
        self.by_id.insert(
            resource.resource_id,
            Pending {
                resource,
                claim: None,
                dispatched: false,
                transmitter: None,
                decoder,
                source,
            },
        );
        Ok(())
    }

    /// Replaces one resource with its verified interpretation.
    ///
    /// The resource keeps its identity and its place in the arbitration: this is the same request,
    /// now understood. Replacing it with a second resource would give one upstream request two
    /// identifiers and two answers.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when the resource has gone.
    pub fn set_interpretation(
        &mut self,
        resource_id: PendingResourceId,
        interpreted: PendingResource,
        decoder: BrokerBindingId,
    ) -> Result<()> {
        let pending = self.by_id.get_mut(&resource_id).ok_or_else(|| {
            BrokerError::unknown(format!("no pending resource {resource_id} to interpret"))
        })?;
        pending.resource = interpreted;
        pending.decoder = Some(decoder);
        Ok(())
    }

    /// Returns the source event one request was recorded from.
    #[must_use]
    pub fn source_of(
        &self,
        resource_id: PendingResourceId,
    ) -> Option<&kr_protocol::ids::SourceEventHandle> {
        self.by_id
            .get(&resource_id)
            .and_then(|pending| pending.source.as_ref())
    }

    /// Returns true when this downstream identifier already names a live resource.
    #[must_use]
    pub fn holds_request(&self, request: &DownstreamRequestId) -> bool {
        self.by_request.contains_key(request)
    }

    /// Restores a resource read back from the ledger, without the duplicate check.
    ///
    /// Recovery is not a second record: the identifiers were already unique when they were
    /// written, and refusing them now would drop what a restart is meant to recover. The claim is
    /// not restored, because the client that held it is gone; what is restored is whether an
    /// answer had already been dispatched, which is what a reconnect needs.
    pub fn restore(
        &mut self,
        resource: PendingResource,
        dispatched: bool,
        decoder: Option<BrokerBindingId>,
    ) {
        self.by_request
            .insert(resource.request.clone(), resource.resource_id);
        self.by_id.insert(
            resource.resource_id,
            Pending {
                resource,
                claim: None,
                dispatched,
                // A resource whose marker was committed comes back with its one admission already
                // spent. Which writer spent it is not recorded and does not matter: what matters
                // is that neither may take it again, which is the whole of "never reissue".
                transmitter: dispatched.then_some(Transmitter::Spent),
                decoder,
                source: None,
            },
        );
    }

    /// Returns one resource.
    #[must_use]
    pub fn get(&self, resource_id: PendingResourceId) -> Option<&Pending> {
        self.by_id.get(&resource_id)
    }

    /// Returns the resource one downstream identifier names.
    #[must_use]
    pub fn by_request(&self, request: &DownstreamRequestId) -> Option<&Pending> {
        self.by_request
            .get(request)
            .and_then(|resource_id| self.by_id.get(resource_id))
    }

    /// Returns every resource, oldest identifier first.
    pub fn iter(&self) -> impl Iterator<Item = &Pending> {
        self.by_id.values()
    }

    /// Returns how many resources are in one state.
    #[must_use]
    pub fn count(&self, state: PendingState) -> usize {
        self.by_id
            .values()
            .filter(|pending| pending.resource.state == state)
            .count()
    }

    /// Plans the claim on one resource.
    ///
    /// This is the "recheck" half of the transaction. The caller has already encoded its answer;
    /// if a native answer arrived while it was encoding, the resource is no longer claimable and
    /// the caller is told the resolved state instead of dispatching over it.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when nothing has that identifier,
    /// [`BrokerError::Arbitration`] when the resource is already claimed or already resolved, and
    /// [`BrokerError::PreconditionFailed`] when its interpretation has not been verified.
    pub fn plan_claim(
        &self,
        resource_id: PendingResourceId,
        actor_id: &ActorId,
        now: TimestampMs,
    ) -> Result<Transition> {
        let pending = self
            .by_id
            .get(&resource_id)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource {resource_id}")))?;
        check_transition(pending.resource.state, PendingState::Claimed)?;
        // The one admission to transmit is already held, so there is no answer left to encode.
        // Without this a native answer on the wire would still leave the resource claimable, and
        // the claim would end in a second set of bytes for one request.
        if let Some(held) = pending.transmitter {
            return Err(BrokerError::denied(format!(
                "{} has already been admitted to transmit for {resource_id}",
                held.as_str()
            )));
        }
        if !pending.resource.interpretation_verified {
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "pending resource {resource_id} has not been interpreted by a granted decoder"
                ),
            });
        }
        if let Some(deadline) = pending.resource.deadline_ms.as_ref()
            && deadline.get() <= now.get()
        {
            return Err(BrokerError::PreconditionFailed {
                detail: format!("the upstream's deadline for {resource_id} has passed"),
            });
        }
        let mut resource = pending.resource.clone();
        resource.state = PendingState::Claimed;
        Ok(Transition {
            resource,
            from: pending.resource.state,
            claim: Some(Claim {
                claim_id: Uuid::from_bytes(*kr_ipc::new_uuid().as_bytes()),
                resource_id,
                actor_id: actor_id.clone(),
                claimed_at: now,
            }),
            holds_claim: true,
            dispatched: false,
            transmitter: None,
        })
    }

    /// Plans the dispatch marker for a claimed resource.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] or [`BrokerError::PermissionDenied`] as the claim
    /// requires, and [`BrokerError::Arbitration`] when the marker is already set, because a second
    /// admission to dispatch is a second answer.
    pub fn plan_dispatch(&self, claim: &Claim) -> Result<Transition> {
        let pending = self.claimed_by(claim)?;
        if pending.dispatched || pending.transmitter.is_some() {
            return Err(BrokerError::Arbitration(ArbitrationError::AlreadyClaimed));
        }
        Ok(Transition {
            resource: pending.resource.clone(),
            from: pending.resource.state,
            claim: Some(claim.clone()),
            holds_claim: true,
            dispatched: true,
            transmitter: Some(Transmitter::Rich(claim.claim_id)),
        })
    }

    /// Plans the exclusive admission of the native client's own answer, before its bytes go.
    ///
    /// This is the other half of section 11's one resolution per resource. A native answer that
    /// arrives while a rich answer is still encoding wins: the claim it beats has not taken the
    /// admission, so this takes it and the rich answer is told the resolved state at its recheck.
    /// A native answer that arrives after a rich answer has been admitted is refused **here**,
    /// before it is forwarded, because forwarding it would be the second answer to one request.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when nothing has that identifier,
    /// [`BrokerError::Arbitration`] when the resource has already ended, and
    /// [`BrokerError::PermissionDenied`] when the one admission is already held.
    pub fn plan_native_dispatch(&self, request: &DownstreamRequestId) -> Result<Transition> {
        let pending = self.require_request(request)?;
        if pending.resource.state.is_terminal() {
            return Err(BrokerError::Arbitration(
                ArbitrationError::AlreadyResolved {
                    state: pending.resource.state,
                },
            ));
        }
        if let Some(held) = pending.transmitter {
            return Err(BrokerError::denied(format!(
                "{} has already been admitted to transmit for {}",
                held.as_str(),
                pending.resource.resource_id
            )));
        }
        // The native writer takes the resource's one claim, which is what the state machine
        // already means by `claimed`: one answer is on its way and no other may start. A rich
        // claim this beats is discharged, because its holder has nothing left to dispatch and the
        // recheck tells it so.
        let mut resource = pending.resource.clone();
        resource.state = PendingState::Claimed;
        Ok(Transition {
            resource,
            from: pending.resource.state,
            claim: None,
            holds_claim: false,
            dispatched: true,
            transmitter: Some(Transmitter::Native),
        })
    }

    /// Plans the end of a native answer this arbitration admitted.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when nothing has that identifier,
    /// [`BrokerError::PermissionDenied`] when the native writer does not hold the admission, and
    /// [`BrokerError::Arbitration`] when the state cannot reach the one asked for.
    pub fn plan_native_settled(
        &self,
        request: &DownstreamRequestId,
        to: PendingState,
    ) -> Result<Transition> {
        let pending = self.require_request(request)?;
        if pending.transmitter != Some(Transmitter::Native) {
            return Err(BrokerError::denied(format!(
                "the native writer does not hold the admission on {}",
                pending.resource.resource_id
            )));
        }
        check_transition(pending.resource.state, to)?;
        let mut resource = pending.resource.clone();
        resource.state = to;
        Ok(Transition {
            resource,
            from: pending.resource.state,
            claim: None,
            holds_claim: false,
            dispatched: true,
            transmitter: None,
        })
    }

    /// Plans giving a claim back, because nothing was dispatched under it.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] when another claim holds the resource, and
    /// [`BrokerError::Arbitration`] when an answer has already gone, because a resource an answer
    /// went for is never handed back to somebody else.
    pub fn plan_release(&self, claim: &Claim) -> Result<Transition> {
        let pending = self.claimed_by(claim)?;
        if pending.dispatched {
            return Err(BrokerError::Arbitration(ArbitrationError::AlreadyClaimed));
        }
        self.plan_from_claim(claim, PendingState::Pending, false)
    }

    /// Plans the resolution of a claimed resource: the upstream confirmed the answer.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`], [`BrokerError::PermissionDenied`] or
    /// [`BrokerError::Arbitration`] as the claim, the actor or the state requires.
    pub fn plan_resolve(&self, claim: &Claim) -> Result<Transition> {
        self.plan_from_claim(claim, PendingState::Resolved, true)
    }

    /// Plans leaving a claimed resource uncertain: an answer went and nothing confirmed it.
    ///
    /// # Errors
    ///
    /// Returns the same failures [`Arbitration::plan_resolve`] does.
    pub fn plan_uncertain(&self, claim: &Claim) -> Result<Transition> {
        self.plan_from_claim(claim, PendingState::Uncertain, true)
    }

    /// Plans the record of the upstream answering or withdrawing the request itself.
    ///
    /// A native answer that arrives while a rich answer is encoding wins. The claim it beats is
    /// released as the upstream's own resolution rather than as a second dispatch, and the rich
    /// caller is later told the resolved state.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when nothing has that identifier, and
    /// [`BrokerError::Arbitration`] when the resource has already reached a terminal state.
    pub fn plan_upstream_resolved(&self, request: &DownstreamRequestId) -> Result<Transition> {
        let resource_id = *self
            .by_request
            .get(request)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource for {request}")))?;
        let pending = self
            .by_id
            .get(&resource_id)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource {resource_id}")))?;
        // An answer of this host's has already gone for it. The upstream answering as well does
        // not make that answer un-sent, and the outcome is genuinely unknown: the two may be the
        // same decision or they may not, and nothing here can tell. `Cancelled` would say the
        // upstream decided alone, which is the one thing that is certainly untrue.
        let to = if pending.dispatched {
            PendingState::Uncertain
        } else {
            PendingState::Cancelled
        };
        check_transition(pending.resource.state, to)?;
        let mut resource = pending.resource.clone();
        resource.state = to;
        Ok(Transition {
            resource,
            from: pending.resource.state,
            claim: None,
            holds_claim: false,
            dispatched: pending.dispatched,
            transmitter: None,
        })
    }

    /// Applies a planned transition.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when the resource has gone since the plan was made,
    /// which cannot happen while both are under the broker's lock and is reported rather than
    /// ignored if it ever does.
    pub fn commit(&mut self, transition: Transition) -> Result<PendingResource> {
        let resource_id = transition.resource.resource_id;
        if transition.resource.durability == Durability::Volatile {
            self.volatile_touched.insert(resource_id);
        }
        let pending = self.by_id.get_mut(&resource_id).ok_or_else(|| {
            BrokerError::unknown(format!("no pending resource {resource_id} to commit"))
        })?;
        pending.resource = transition.resource;
        pending.claim = if transition.holds_claim {
            transition.claim
        } else {
            None
        };
        pending.dispatched = pending.dispatched || transition.dispatched;
        if let Some(admitted) = transition.transmitter {
            pending.transmitter = Some(admitted);
        }
        Ok(pending.resource.clone())
    }

    /// Expires every pending resource whose upstream deadline has passed.
    ///
    /// A claimed resource is never expired out from under its answer: the claim is what decides
    /// its outcome, and the deadline the upstream stated is about how long it will wait, not about
    /// what this host has already done.
    pub fn expire(&mut self, now: TimestampMs) -> Vec<PendingResource> {
        let mut expired = Vec::new();
        for pending in self.by_id.values_mut() {
            if pending.resource.state != PendingState::Pending {
                continue;
            }
            let Some(deadline) = pending.resource.deadline_ms.as_ref() else {
                continue;
            };
            if deadline.get() <= now.get() {
                pending.resource.state = PendingState::Expired;
                expired.push(pending.resource.clone());
            }
        }
        expired
    }

    /// Plans the reconciliation of one upstream's records with what it still has pending.
    ///
    /// The three outcomes are the whole contract:
    ///
    /// * The upstream still has it and this host never dispatched: nothing changes.
    /// * The upstream no longer has it: the upstream resolved it, and so does this host.
    /// * This host dispatched an answer and cannot tell whether it landed: uncertain, for ever.
    ///   Asking again is the one thing that must not happen, because the answer may already have
    ///   been applied.
    ///
    /// Only resources inside `scope` are considered. A reconnect speaks for one upstream on one
    /// connection and for nothing else.
    ///
    /// Nothing is applied here. The caller writes each transition durably and commits it, the
    /// same way it does for a single resource.
    #[must_use]
    pub fn plan_reconcile(
        &self,
        scope: ReconcileScope,
        still_open: &[DownstreamRequestId],
    ) -> (Reconciliation, Vec<Transition>) {
        let open: std::collections::BTreeSet<&DownstreamRequestId> = still_open.iter().collect();
        let mut result = Reconciliation::default();
        let mut transitions = Vec::new();
        for (resource_id, pending) in &self.by_id {
            if pending.resource.state.is_terminal() {
                continue;
            }
            if pending.resource.application_instance_id != scope.application_instance_id
                || pending.resource.request.connection != scope.connection
            {
                continue;
            }
            let upstream_has_it = open.contains(&pending.resource.request);
            let to = match (upstream_has_it, pending.dispatched) {
                (_, true) => {
                    result.uncertain.push(*resource_id);
                    PendingState::Uncertain
                }
                (true, false) => {
                    if pending.resource.state == PendingState::Claimed {
                        result.released.push(*resource_id);
                        PendingState::Pending
                    } else {
                        result.still_pending.push(*resource_id);
                        continue;
                    }
                }
                (false, false) => {
                    result.withdrawn.push(*resource_id);
                    PendingState::Cancelled
                }
            };
            let mut resource = pending.resource.clone();
            resource.state = to;
            transitions.push(Transition {
                resource,
                from: pending.resource.state,
                claim: None,
                holds_claim: false,
                dispatched: pending.dispatched,
                transmitter: None,
            });
        }
        (result, transitions)
    }

    /// Marks every unresolved resource volatile, and returns the records that changed.
    ///
    /// The returned count of already-claimed identifiers is what the evidence gap carries: these
    /// are the ones a second response must never be emitted for, and they are carried across the
    /// gap rather than forgotten.
    pub fn enter_volatile(&mut self) -> (u64, Vec<PendingResource>) {
        let mut carried = 0;
        let mut changed = Vec::new();
        let mut touched = Vec::new();
        for (resource_id, pending) in &mut self.by_id {
            if pending.resource.state.is_terminal() {
                continue;
            }
            pending.resource.durability = Durability::Volatile;
            changed.push(pending.resource.clone());
            touched.push(*resource_id);
            if pending.resource.state == PendingState::Claimed || pending.dispatched {
                carried += 1;
            }
        }
        self.volatile_touched.extend(touched);
        (carried, changed)
    }

    /// Returns every resource that was touched while the journal was faulted.
    ///
    /// This is what recovery commits: the resources that lived inside a gap, in whatever state
    /// they actually reached, rather than a replay of the operations that produced them. A
    /// resource the upstream withdrew inside the gap is here too, so its ending is written down.
    #[must_use]
    pub fn volatile_records(&self) -> Vec<(PendingResource, Option<BrokerBindingId>, bool)> {
        self.volatile_touched
            .iter()
            .filter_map(|resource_id| self.by_id.get(resource_id))
            .map(|pending| {
                (
                    pending.resource.clone(),
                    pending.decoder,
                    pending.dispatched,
                )
            })
            .collect()
    }

    /// Forgets the record of what the gap touched, because it has been committed.
    pub fn clear_volatile_records(&mut self) {
        self.volatile_touched.clear();
    }

    /// Forgets every resource that has reached a terminal state.
    ///
    /// The ledger keeps them; this is the live map, and a resolved resource in it is only a
    /// resource a later answer has to be told about.
    pub fn forget_resolved(&mut self) -> usize {
        let resolved: Vec<PendingResourceId> = self
            .by_id
            .iter()
            .filter(|(_, pending)| pending.resource.state.is_terminal())
            .map(|(resource_id, _)| *resource_id)
            .collect();
        for resource_id in &resolved {
            if let Some(pending) = self.by_id.remove(resource_id) {
                self.by_request.remove(&pending.resource.request);
            }
        }
        resolved.len()
    }

    fn plan_from_claim(
        &self,
        claim: &Claim,
        to: PendingState,
        dispatched: bool,
    ) -> Result<Transition> {
        let pending = self.claimed_by(claim)?;
        check_transition(pending.resource.state, to)?;
        let mut resource = pending.resource.clone();
        resource.state = to;
        Ok(Transition {
            resource,
            from: pending.resource.state,
            claim: Some(claim.clone()),
            holds_claim: false,
            dispatched,
            transmitter: None,
        })
    }

    fn require_request(&self, request: &DownstreamRequestId) -> Result<&Pending> {
        let resource_id = *self
            .by_request
            .get(request)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource for {request}")))?;
        self.by_id
            .get(&resource_id)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource {resource_id}")))
    }

    fn claimed_by(&self, claim: &Claim) -> Result<&Pending> {
        let pending = self.by_id.get(&claim.resource_id).ok_or_else(|| {
            BrokerError::unknown(format!("no pending resource {}", claim.resource_id))
        })?;
        match pending.claim.as_ref() {
            Some(held) if held.claim_id == claim.claim_id => Ok(pending),
            Some(_) => Err(BrokerError::denied(format!(
                "another answer holds the claim on {}",
                claim.resource_id
            ))),
            None => Err(BrokerError::Arbitration(
                ArbitrationError::ForbiddenTransition {
                    from: pending.resource.state,
                    to: PendingState::Resolved,
                },
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::gateway::{NativeClassification, NativeMethodClass, PendingKind};
    use kr_protocol::ids::{
        GatewayConnectionId, SourceGeneration, UpstreamMethod, UpstreamRequestId,
    };
    use kr_protocol::scalars::Nullable;

    fn actor(name: &str) -> ActorId {
        ActorId::new(name).expect("valid")
    }

    fn instance() -> ApplicationInstanceId {
        ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
    }

    fn scope() -> ReconcileScope {
        ReconcileScope {
            application_instance_id: instance(),
            connection: GatewayConnectionId::new(1),
        }
    }

    fn resource(byte: u8, request: &str) -> PendingResource {
        PendingResource {
            resource_id: PendingResourceId::new(Uuid::from_bytes([byte; 16])),
            application_instance_id: instance(),
            request: DownstreamRequestId::new(
                GatewayConnectionId::new(1),
                UpstreamRequestId::new(request).expect("valid"),
            ),
            kind: PendingKind::Approval,
            method: UpstreamMethod::new("session/request_permission").expect("valid"),
            classification: NativeClassification::declared(NativeMethodClass::Mutation),
            source_generation: SourceGeneration::new(1),
            state: PendingState::Pending,
            durability: Durability::Durable,
            deadline_ms: Nullable::null(),
            recorded_at: TimestampMs::new(1),
            interpretation_verified: true,
        }
    }

    /// Reconciles and applies, the way the broker does under its lock.
    fn reconcile(
        arbitration: &mut Arbitration,
        scope: ReconcileScope,
        still_open: &[DownstreamRequestId],
    ) -> Reconciliation {
        let (result, transitions) = arbitration.plan_reconcile(scope, still_open);
        for transition in transitions {
            arbitration.commit(transition).expect("committed");
        }
        result
    }

    /// Takes a claim and applies it, the way the broker does under its lock.
    fn claim(
        arbitration: &mut Arbitration,
        resource_id: PendingResourceId,
        who: &str,
        now: u64,
    ) -> Result<Claim> {
        let transition = arbitration.plan_claim(resource_id, &actor(who), TimestampMs::new(now))?;
        let claim = transition.claim().cloned().expect("a claim was planned");
        arbitration.commit(transition)?;
        Ok(claim)
    }

    #[test]
    fn one_resource_takes_one_claim() {
        let mut arbitration = Arbitration::new();
        let resource = resource(7, "11");
        let resource_id = resource.resource_id;
        arbitration.record(resource, None, None).expect("recorded");
        let held = claim(&mut arbitration, resource_id, "device-1", 2).expect("claimed");
        assert!(
            claim(&mut arbitration, resource_id, "device-2", 3).is_err(),
            "a second answer cannot claim a resource that is already claimed"
        );
        let resolve = arbitration.plan_resolve(&held).expect("planned");
        arbitration.commit(resolve).expect("committed");
        assert!(
            claim(&mut arbitration, resource_id, "device-2", 4).is_err(),
            "a resolved resource takes no further claim"
        );
    }

    #[test]
    fn a_released_claim_cannot_resolve_the_claim_that_replaced_it() {
        let mut arbitration = Arbitration::new();
        let resource = resource(7, "11");
        let resource_id = resource.resource_id;
        let request = resource.request.clone();
        arbitration.record(resource, None, None).expect("recorded");
        let released = claim(&mut arbitration, resource_id, "device-1", 2).expect("claimed");
        reconcile(&mut arbitration, scope(), &[request]);
        // The same actor claims again. The old claim names an older attempt and must not resolve
        // the new one.
        let fresh = claim(&mut arbitration, resource_id, "device-1", 3).expect("claimed again");
        assert_ne!(released.claim_id, fresh.claim_id);
        assert!(arbitration.plan_resolve(&released).is_err());
        arbitration
            .plan_resolve(&fresh)
            .expect("the claim in force resolves it");
    }

    #[test]
    fn a_duplicate_downstream_identifier_is_refused() {
        let mut arbitration = Arbitration::new();
        arbitration
            .record(resource(7, "11"), None, None)
            .expect("recorded");
        assert!(arbitration.record(resource(8, "11"), None, None).is_err());
        // The same identifier on another connection is a different resource.
        let mut other = resource(8, "11");
        other.request =
            DownstreamRequestId::new(GatewayConnectionId::new(2), other.request.upstream.clone());
        arbitration.record(other, None, None).expect("recorded");
    }

    #[test]
    fn a_native_answer_that_lands_before_the_recheck_wins() {
        let mut arbitration = Arbitration::new();
        let resource = resource(7, "11");
        let resource_id = resource.resource_id;
        let request = resource.request.clone();
        arbitration.record(resource, None, None).expect("recorded");

        // The rich answer has been encoded by its component and has not reached the recheck yet;
        // the encoding itself happens outside this type, which is the point of the order. The
        // upstream answers itself in that window.
        let native = arbitration
            .plan_upstream_resolved(&request)
            .expect("the upstream answered itself");
        arbitration.commit(native).expect("committed");

        // Now the rich answer reaches the recheck, and there is nothing left to claim.
        assert!(
            arbitration
                .plan_claim(resource_id, &actor("device-1"), TimestampMs::new(5))
                .is_err(),
            "the encoded answer must not be dispatched over the native one"
        );
        assert_eq!(
            arbitration
                .get(resource_id)
                .expect("recorded")
                .resource
                .state,
            PendingState::Cancelled
        );
    }

    #[test]
    fn a_reconnect_never_reissues_an_uncertain_answer() {
        let mut arbitration = Arbitration::new();
        let dispatched = resource(7, "11");
        let dispatched_id = dispatched.resource_id;
        let dispatched_request = dispatched.request.clone();
        let untouched = resource(8, "12");
        let untouched_id = untouched.resource_id;
        let untouched_request = untouched.request.clone();
        let withdrawn = resource(9, "13");
        let withdrawn_id = withdrawn.resource_id;
        arbitration
            .record(dispatched, None, None)
            .expect("recorded");
        arbitration.record(untouched, None, None).expect("recorded");
        arbitration.record(withdrawn, None, None).expect("recorded");

        let held = claim(&mut arbitration, dispatched_id, "device-1", 2).expect("claimed");
        let marker = arbitration.plan_dispatch(&held).expect("planned");
        arbitration.commit(marker).expect("the marker is committed");

        let reconciliation = reconcile(
            &mut arbitration,
            scope(),
            &[dispatched_request, untouched_request],
        );
        assert_eq!(reconciliation.uncertain, vec![dispatched_id]);
        assert_eq!(reconciliation.still_pending, vec![untouched_id]);
        assert_eq!(reconciliation.withdrawn, vec![withdrawn_id]);
        assert!(
            claim(&mut arbitration, dispatched_id, "device-1", 5).is_err(),
            "an uncertain resource is never answered again"
        );
    }

    #[test]
    fn a_reconnect_touches_only_the_upstream_it_speaks_for() {
        let mut arbitration = Arbitration::new();
        let mine = resource(7, "11");
        let mine_id = mine.resource_id;
        arbitration.record(mine, None, None).expect("recorded");

        let mut another_instance = resource(8, "21");
        another_instance.application_instance_id =
            ApplicationInstanceId::new(Uuid::from_bytes([3; 16]));
        let another_instance_id = another_instance.resource_id;
        arbitration
            .record(another_instance, None, None)
            .expect("recorded");

        let mut another_connection = resource(9, "31");
        another_connection.request = DownstreamRequestId::new(
            GatewayConnectionId::new(2),
            UpstreamRequestId::new("31").expect("valid"),
        );
        let another_connection_id = another_connection.resource_id;
        arbitration
            .record(another_connection, None, None)
            .expect("recorded");

        // The reconnect lists nothing. Only its own resource is withdrawn.
        let reconciliation = reconcile(&mut arbitration, scope(), &[]);
        assert_eq!(reconciliation.withdrawn, vec![mine_id]);
        assert_eq!(
            arbitration
                .get(another_instance_id)
                .expect("recorded")
                .resource
                .state,
            PendingState::Pending
        );
        assert_eq!(
            arbitration
                .get(another_connection_id)
                .expect("recorded")
                .resource
                .state,
            PendingState::Pending
        );
    }

    #[test]
    fn a_claim_that_never_dispatched_is_released_by_a_reconnect() {
        let mut arbitration = Arbitration::new();
        let resource = resource(7, "11");
        let resource_id = resource.resource_id;
        let request = resource.request.clone();
        arbitration.record(resource, None, None).expect("recorded");
        claim(&mut arbitration, resource_id, "device-1", 2).expect("claimed");
        let reconciliation = reconcile(&mut arbitration, scope(), &[request]);
        assert_eq!(reconciliation.released, vec![resource_id]);
        assert_eq!(
            arbitration
                .get(resource_id)
                .expect("recorded")
                .resource
                .state,
            PendingState::Pending
        );
        claim(&mut arbitration, resource_id, "device-2", 3)
            .expect("a fresh answer may claim it again");
    }

    #[test]
    fn an_uninterpreted_resource_is_not_an_answerable_approval() {
        let mut arbitration = Arbitration::new();
        let mut resource = resource(7, "11");
        resource.interpretation_verified = false;
        let resource_id = resource.resource_id;
        arbitration.record(resource, None, None).expect("recorded");
        assert!(claim(&mut arbitration, resource_id, "device-1", 2).is_err());
    }

    #[test]
    fn a_claim_is_refused_after_the_upstream_deadline() {
        let mut arbitration = Arbitration::new();
        let mut resource = resource(7, "11");
        resource.deadline_ms = Nullable::some(TimestampMs::new(100));
        let resource_id = resource.resource_id;
        arbitration.record(resource, None, None).expect("recorded");
        assert!(claim(&mut arbitration, resource_id, "device-1", 200).is_err());
        claim(&mut arbitration, resource_id, "device-1", 50).expect("inside the deadline");
    }

    #[test]
    fn entering_volatile_counts_what_must_never_be_answered_twice() {
        let mut arbitration = Arbitration::new();
        let claimed = resource(7, "11");
        let claimed_id = claimed.resource_id;
        arbitration.record(claimed, None, None).expect("recorded");
        arbitration
            .record(resource(8, "12"), None, None)
            .expect("recorded");
        let held = claim(&mut arbitration, claimed_id, "device-1", 2).expect("claimed");
        let marker = arbitration.plan_dispatch(&held).expect("planned");
        arbitration.commit(marker).expect("committed");
        let (carried, changed) = arbitration.enter_volatile();
        assert_eq!(carried, 1);
        assert_eq!(changed.len(), 2);
        for pending in arbitration.iter() {
            assert_eq!(pending.resource.durability, Durability::Volatile);
        }
    }

    #[test]
    fn a_deadline_expires_a_pending_resource_and_not_a_claimed_one() {
        let mut arbitration = Arbitration::new();
        let mut waiting = resource(7, "11");
        waiting.deadline_ms = Nullable::some(TimestampMs::new(100));
        let waiting_id = waiting.resource_id;
        let mut answered = resource(8, "12");
        answered.deadline_ms = Nullable::some(TimestampMs::new(100));
        let answered_id = answered.resource_id;
        arbitration.record(waiting, None, None).expect("recorded");
        arbitration.record(answered, None, None).expect("recorded");
        claim(&mut arbitration, answered_id, "device-1", 50).expect("claimed");
        let expired = arbitration.expire(TimestampMs::new(200));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].resource_id, waiting_id);
        assert_eq!(
            arbitration
                .get(answered_id)
                .expect("recorded")
                .resource
                .state,
            PendingState::Claimed
        );
    }
}
