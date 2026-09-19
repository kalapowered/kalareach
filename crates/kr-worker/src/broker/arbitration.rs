//! One arbitration for every pending resource, and exactly one resolution each.
//!
//! Section 11: "The host resolves each pending resource once through the encode, recheck, claim
//! and dispatch transaction... Reconnect reconciles upstream IDs and receipts; it does not reissue
//! an uncertain response."
//!
//! The order of the four steps is what makes the rule hold. Encoding happens *outside* the claim,
//! because encoding can be slow and a native answer that arrives during it must win. The recheck
//! and the claim happen together under one lock, so between deciding that the request is still
//! answerable and taking it nothing can move. Dispatch happens after the claim, so two answers
//! cannot both be sent. And an answer whose outcome nobody can establish leaves the resource
//! `uncertain` rather than pending, because a pending resource is one a later answer could still
//! claim and that would be the second dispatch.

use std::collections::BTreeMap;

use kr_protocol::gateway::{
    ArbitrationError, DownstreamRequestId, Durability, PendingResource, PendingState,
    check_transition,
};
use kr_protocol::ids::{ActorId, PendingResourceId};
use kr_protocol::scalars::TimestampMs;

use crate::broker::error::{BrokerError, Result};

/// One pending resource and what has happened to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    /// The resource as clients see it.
    pub resource: PendingResource,
    /// The actor whose answer holds the claim, while one does.
    pub claimed_by: Option<ActorId>,
    /// True once an answer has left this host for the upstream.
    ///
    /// This is the flag that decides what a reconnect does. A claimed resource that was never
    /// dispatched can go back to pending; one that was dispatched and never confirmed is
    /// uncertain, and an uncertain resource is never answered a second time.
    pub dispatched: bool,
}

/// What a claim gives its holder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// The resource claimed.
    pub resource_id: PendingResourceId,
    /// The actor holding it.
    pub actor_id: ActorId,
    /// The state the resource was in when the claim was taken.
    pub claimed_at: TimestampMs,
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

/// The broker's live arbitration.
#[derive(Debug, Default)]
pub struct Arbitration {
    by_id: BTreeMap<PendingResourceId, Pending>,
    by_request: BTreeMap<DownstreamRequestId, PendingResourceId>,
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
    pub fn record(&mut self, resource: PendingResource) -> Result<()> {
        if let Some(existing) = self.by_request.get(&resource.request) {
            return Err(BrokerError::invalid(format!(
                "{} already names pending resource {existing}",
                resource.request
            )));
        }
        self.by_request
            .insert(resource.request.clone(), resource.resource_id);
        self.by_id.insert(
            resource.resource_id,
            Pending {
                resource,
                claimed_by: None,
                dispatched: false,
            },
        );
        Ok(())
    }

    /// Restores a resource read back from the ledger, without the duplicate check.
    ///
    /// Recovery is not a second record: the identifiers were already unique when they were
    /// written, and refusing them now would drop what a restart is meant to recover.
    pub fn restore(&mut self, resource: PendingResource, dispatched: bool) {
        self.by_request
            .insert(resource.request.clone(), resource.resource_id);
        self.by_id.insert(
            resource.resource_id,
            Pending {
                resource,
                claimed_by: None,
                dispatched,
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

    /// Takes the claim on one resource.
    ///
    /// This is the "recheck and claim" half of the transaction, and it is one operation because
    /// the two halves have to be. The caller encodes its answer first, then calls this; if a
    /// native answer arrived while it was encoding, the resource is no longer claimable and the
    /// caller is told the resolved state instead of dispatching over it.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when nothing has that identifier, and
    /// [`BrokerError::Arbitration`] when the resource is already claimed or already resolved.
    pub fn claim(
        &mut self,
        resource_id: PendingResourceId,
        actor_id: &ActorId,
        now: TimestampMs,
    ) -> Result<Claim> {
        let pending = self
            .by_id
            .get_mut(&resource_id)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource {resource_id}")))?;
        check_transition(pending.resource.state, PendingState::Claimed)?;
        if !pending.resource.interpretation_verified {
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "pending resource {resource_id} has not been interpreted by a granted decoder"
                ),
            });
        }
        pending.resource.state = PendingState::Claimed;
        pending.claimed_by = Some(actor_id.clone());
        Ok(Claim {
            resource_id,
            actor_id: actor_id.clone(),
            claimed_at: now,
        })
    }

    /// Marks that the claimed answer has left this host.
    ///
    /// Called between the write and the confirmation, so a crash in the middle leaves a record
    /// that says an answer may already have been sent.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when nothing has that identifier, and
    /// [`BrokerError::PermissionDenied`] when another actor holds the claim.
    pub fn mark_dispatched(&mut self, claim: &Claim) -> Result<()> {
        let pending = self.claimed_by(claim)?;
        pending.dispatched = true;
        Ok(())
    }

    /// Resolves a claimed resource: the upstream confirmed the answer.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`], [`BrokerError::PermissionDenied`] or
    /// [`BrokerError::Arbitration`] as the claim, the actor or the state requires.
    pub fn resolve(&mut self, claim: &Claim) -> Result<PendingResource> {
        let pending = self.claimed_by(claim)?;
        check_transition(pending.resource.state, PendingState::Resolved)?;
        pending.resource.state = PendingState::Resolved;
        pending.claimed_by = None;
        Ok(pending.resource.clone())
    }

    /// Leaves a claimed resource uncertain: an answer went and nothing confirmed it.
    ///
    /// # Errors
    ///
    /// Returns the same failures [`Arbitration::resolve`] does.
    pub fn uncertain(&mut self, claim: &Claim) -> Result<PendingResource> {
        let pending = self.claimed_by(claim)?;
        check_transition(pending.resource.state, PendingState::Uncertain)?;
        pending.resource.state = PendingState::Uncertain;
        pending.dispatched = true;
        pending.claimed_by = None;
        Ok(pending.resource.clone())
    }

    /// Records that the upstream answered or withdrew the request itself.
    ///
    /// A native answer that arrives while a rich answer is encoding wins. The claim it beats is
    /// released as the upstream's own resolution rather than as a second dispatch, and the rich
    /// caller is later told the resolved state.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when nothing has that identifier, and
    /// [`BrokerError::Arbitration`] when the resource has already reached a terminal state.
    pub fn upstream_resolved(&mut self, request: &DownstreamRequestId) -> Result<PendingResource> {
        let resource_id = *self
            .by_request
            .get(request)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource for {request}")))?;
        let pending = self
            .by_id
            .get_mut(&resource_id)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource {resource_id}")))?;
        check_transition(pending.resource.state, PendingState::Cancelled)?;
        pending.resource.state = PendingState::Cancelled;
        pending.claimed_by = None;
        Ok(pending.resource.clone())
    }

    /// Expires every pending resource whose upstream deadline has passed.
    ///
    /// A claimed resource is never expired out from under its answer: the claim is what decides
    /// its outcome, and the deadline the upstream stated is about how long it will wait, not about
    /// what this host has already done.
    pub fn expire(&mut self, now: TimestampMs) -> Vec<PendingResourceId> {
        let mut expired = Vec::new();
        for (resource_id, pending) in &mut self.by_id {
            if pending.resource.state != PendingState::Pending {
                continue;
            }
            let Some(deadline) = pending.resource.deadline_ms.as_ref() else {
                continue;
            };
            if deadline.get() <= now.get() {
                pending.resource.state = PendingState::Expired;
                expired.push(*resource_id);
            }
        }
        expired
    }

    /// Reconciles this host's records with what the upstream still has pending.
    ///
    /// The three outcomes are the whole contract:
    ///
    /// * The upstream still has it and this host never dispatched: nothing changes.
    /// * The upstream no longer has it: the upstream resolved it, and so does this host.
    /// * This host dispatched an answer and cannot tell whether it landed: uncertain, for ever.
    ///   Asking again is the one thing that must not happen, because the answer may already have
    ///   been applied.
    pub fn reconcile(&mut self, still_open: &[DownstreamRequestId]) -> Reconciliation {
        let open: std::collections::BTreeSet<&DownstreamRequestId> = still_open.iter().collect();
        let mut result = Reconciliation::default();
        for (resource_id, pending) in &mut self.by_id {
            if pending.resource.state.is_terminal() {
                continue;
            }
            let upstream_has_it = open.contains(&pending.resource.request);
            match (upstream_has_it, pending.dispatched) {
                (_, true) => {
                    pending.resource.state = PendingState::Uncertain;
                    pending.claimed_by = None;
                    result.uncertain.push(*resource_id);
                }
                (true, false) => {
                    if pending.resource.state == PendingState::Claimed {
                        pending.resource.state = PendingState::Pending;
                        pending.claimed_by = None;
                        result.released.push(*resource_id);
                    } else {
                        result.still_pending.push(*resource_id);
                    }
                }
                (false, false) => {
                    pending.resource.state = PendingState::Cancelled;
                    pending.claimed_by = None;
                    result.withdrawn.push(*resource_id);
                }
            }
        }
        result
    }

    /// Marks every unresolved resource volatile, and returns how many were already claimed.
    ///
    /// The count is what the evidence gap carries: these are the identifiers a second response
    /// must never be emitted for, and they are carried across the gap rather than forgotten.
    pub fn enter_volatile(&mut self) -> u64 {
        let mut carried = 0;
        for pending in self.by_id.values_mut() {
            if pending.resource.state.is_terminal() {
                continue;
            }
            pending.resource.durability = Durability::Volatile;
            if pending.resource.state == PendingState::Claimed || pending.dispatched {
                carried += 1;
            }
        }
        carried
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

    fn claimed_by(&mut self, claim: &Claim) -> Result<&mut Pending> {
        let pending = self.by_id.get_mut(&claim.resource_id).ok_or_else(|| {
            BrokerError::unknown(format!("no pending resource {}", claim.resource_id))
        })?;
        match pending.claimed_by.as_ref() {
            Some(holder) if holder == &claim.actor_id => Ok(pending),
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
        ApplicationInstanceId, GatewayConnectionId, SourceGeneration, UpstreamMethod,
        UpstreamRequestId,
    };
    use kr_protocol::scalars::{Nullable, Uuid};

    fn actor(name: &str) -> ActorId {
        ActorId::new(name).expect("valid")
    }

    fn resource(byte: u8, request: &str) -> PendingResource {
        PendingResource {
            resource_id: PendingResourceId::new(Uuid::from_bytes([byte; 16])),
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([2; 16])),
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

    #[test]
    fn one_resource_takes_one_claim() {
        let mut arbitration = Arbitration::new();
        let resource = resource(7, "11");
        let resource_id = resource.resource_id;
        arbitration.record(resource).expect("recorded");
        let claim = arbitration
            .claim(resource_id, &actor("device-1"), TimestampMs::new(2))
            .expect("the first answer claims it");
        assert!(
            arbitration
                .claim(resource_id, &actor("device-2"), TimestampMs::new(3))
                .is_err(),
            "a second answer cannot claim a resource that is already claimed"
        );
        arbitration.resolve(&claim).expect("the claim resolves it");
        assert!(
            arbitration
                .claim(resource_id, &actor("device-2"), TimestampMs::new(4))
                .is_err(),
            "a resolved resource takes no further claim"
        );
    }

    #[test]
    fn a_duplicate_downstream_identifier_is_refused() {
        let mut arbitration = Arbitration::new();
        arbitration.record(resource(7, "11")).expect("recorded");
        assert!(arbitration.record(resource(8, "11")).is_err());
        // The same identifier on another connection is a different resource.
        let mut other = resource(8, "11");
        other.request =
            DownstreamRequestId::new(GatewayConnectionId::new(2), other.request.upstream.clone());
        arbitration.record(other).expect("recorded");
    }

    #[test]
    fn a_native_answer_during_encoding_wins() {
        let mut arbitration = Arbitration::new();
        let resource = resource(7, "11");
        let resource_id = resource.resource_id;
        let request = resource.request.clone();
        arbitration.record(resource).expect("recorded");
        let claim = arbitration
            .claim(resource_id, &actor("device-1"), TimestampMs::new(2))
            .expect("claimed while the rich answer encodes");
        let resolved = arbitration
            .upstream_resolved(&request)
            .expect("the upstream answered itself");
        assert_eq!(resolved.state, PendingState::Cancelled);
        // The later rich answer is told the resolved state rather than dispatching over it.
        assert!(arbitration.resolve(&claim).is_err());
        assert_eq!(
            arbitration
                .get(resource_id)
                .expect("still recorded")
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
        arbitration.record(dispatched).expect("recorded");
        arbitration.record(untouched).expect("recorded");
        arbitration.record(withdrawn).expect("recorded");

        let claim = arbitration
            .claim(dispatched_id, &actor("device-1"), TimestampMs::new(2))
            .expect("claimed");
        arbitration.mark_dispatched(&claim).expect("dispatched");

        let reconciliation = arbitration.reconcile(&[dispatched_request, untouched_request]);
        assert_eq!(reconciliation.uncertain, vec![dispatched_id]);
        assert_eq!(reconciliation.still_pending, vec![untouched_id]);
        assert_eq!(reconciliation.withdrawn, vec![withdrawn_id]);
        assert_eq!(
            arbitration
                .get(dispatched_id)
                .expect("recorded")
                .resource
                .state,
            PendingState::Uncertain
        );
        assert!(
            arbitration
                .claim(dispatched_id, &actor("device-1"), TimestampMs::new(5))
                .is_err(),
            "an uncertain resource is never answered again"
        );
    }

    #[test]
    fn a_claim_that_never_dispatched_is_released_by_a_reconnect() {
        let mut arbitration = Arbitration::new();
        let resource = resource(7, "11");
        let resource_id = resource.resource_id;
        let request = resource.request.clone();
        arbitration.record(resource).expect("recorded");
        arbitration
            .claim(resource_id, &actor("device-1"), TimestampMs::new(2))
            .expect("claimed");
        let reconciliation = arbitration.reconcile(&[request]);
        assert_eq!(reconciliation.released, vec![resource_id]);
        assert_eq!(
            arbitration
                .get(resource_id)
                .expect("recorded")
                .resource
                .state,
            PendingState::Pending
        );
        arbitration
            .claim(resource_id, &actor("device-2"), TimestampMs::new(3))
            .expect("a fresh answer may claim it again");
    }

    #[test]
    fn an_uninterpreted_resource_is_not_an_answerable_approval() {
        let mut arbitration = Arbitration::new();
        let mut resource = resource(7, "11");
        resource.interpretation_verified = false;
        let resource_id = resource.resource_id;
        arbitration.record(resource).expect("recorded");
        assert!(
            arbitration
                .claim(resource_id, &actor("device-1"), TimestampMs::new(2))
                .is_err()
        );
    }

    #[test]
    fn entering_volatile_counts_what_must_never_be_answered_twice() {
        let mut arbitration = Arbitration::new();
        let claimed = resource(7, "11");
        let claimed_id = claimed.resource_id;
        arbitration.record(claimed).expect("recorded");
        arbitration.record(resource(8, "12")).expect("recorded");
        let claim = arbitration
            .claim(claimed_id, &actor("device-1"), TimestampMs::new(2))
            .expect("claimed");
        arbitration.mark_dispatched(&claim).expect("dispatched");
        assert_eq!(arbitration.enter_volatile(), 1);
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
        arbitration.record(waiting).expect("recorded");
        arbitration.record(answered).expect("recorded");
        arbitration
            .claim(answered_id, &actor("device-1"), TimestampMs::new(50))
            .expect("claimed");
        assert_eq!(arbitration.expire(TimestampMs::new(200)), vec![waiting_id]);
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
