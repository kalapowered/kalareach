//! Issuing and spending action tokens.
//!
//! Section 11: "Every action callback receives a token bound to actor, grant, application/thread
//! revision, declared action and parameter hash. Its effect plan can use only resources and
//! operations permitted by that invocation."
//!
//! Two properties make that true rather than aspirational. A token is **single use**: the record
//! is removed when the effect plan arrives, so the same invocation's authority cannot be spent
//! twice. And a token is **rechecked against the present**: the binding revision it was issued at
//! is compared with the revision in force at dispatch, not only with the revision the component
//! reports, so a thread that changed while the component was working invalidates the token.

use std::collections::BTreeMap;

use kr_protocol::broker::{
    ActionName, ActionToken, ActionTokenClaim, BrokerGrant, BrokerGrants, TokenError,
};
use kr_protocol::ids::{
    ActionTokenId, ActorId, AgentBindingRevision, ApplicationInstanceId, GrantId,
};
use kr_protocol::scalars::{Digest256, TimestampMs};

use crate::broker::error::{BrokerError, Result};

/// How many unspent tokens one broker holds at once.
///
/// A token is spent by the callback it was issued for, which returns promptly or hits its own
/// deadline, so a backlog past this is a component that is not answering. Refusing to issue is
/// better than growing without bound.
pub const MAX_UNSPENT_TOKENS: usize = 256;

/// What one action invocation needs before a token is issued.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    /// The verified actor. A component never asserts it.
    pub actor_id: ActorId,
    /// Which of the three grants authorises this call.
    pub grant: BrokerGrant,
    /// The grant record the authority comes from.
    pub grant_id: GrantId,
    /// The instance the action runs against.
    pub application_instance_id: ApplicationInstanceId,
    /// The binding revision in force.
    pub binding_revision: AgentBindingRevision,
    /// The declared action.
    pub action: ActionName,
    /// The canonical bytes of the parameters.
    pub parameters: Vec<u8>,
}

/// The tokens this broker has issued and not yet seen spent.
#[derive(Debug, Default)]
pub struct TokenStore {
    unspent: BTreeMap<ActionTokenId, ActionToken>,
}

impl TokenStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns how many tokens are outstanding.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.unspent.len()
    }

    /// Issues one token for one invocation.
    ///
    /// The grant is checked here rather than at dispatch, because a callback that should never
    /// have been invited to run is one that never runs: an observation-only binding asked to
    /// prepare an effect is refused before its component is called.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Grant`] when the binding does not hold the grant the invocation
    /// names, and [`BrokerError::QuotaExceeded`]-shaped [`BrokerError::InvalidArgument`] when too
    /// many tokens are already outstanding.
    pub fn issue(
        &mut self,
        grants: &BrokerGrants,
        invocation: &Invocation,
        now: TimestampMs,
    ) -> Result<ActionToken> {
        grants.require(invocation.grant)?;
        if self.unspent.len() >= MAX_UNSPENT_TOKENS {
            return Err(BrokerError::invalid(format!(
                "this broker holds {MAX_UNSPENT_TOKENS} unspent action tokens already"
            )));
        }
        let token_id = ActionTokenId::new(format!("act-{}", kr_ipc::new_uuid()))
            .map_err(|error| BrokerError::invalid(format!("token handle: {error}")))?;
        let token = ActionToken {
            token_id: token_id.clone(),
            actor_id: invocation.actor_id.clone(),
            grant: invocation.grant,
            grant_id: invocation.grant_id,
            application_instance_id: invocation.application_instance_id,
            binding_revision: invocation.binding_revision,
            action: invocation.action.clone(),
            parameter_hash: Digest256::from_bytes(kr_cbor::sha256(&invocation.parameters)),
            issued_at: now,
        };
        self.unspent.insert(token_id, token.clone());
        Ok(token)
    }

    /// Spends one token against the effect plan a component returned.
    ///
    /// Every binding is checked, and then the revision in force is checked again. The second check
    /// is the one that matters after a slow call: the token was valid when it was issued, and what
    /// authorises the dispatch is whether it is still valid now.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Token`] for an unknown or spent handle, a binding that disagrees, or
    /// a revision that has moved on.
    pub fn spend(
        &mut self,
        claim: &ActionTokenClaim,
        revision_in_force: AgentBindingRevision,
    ) -> Result<ActionToken> {
        let token = self
            .unspent
            .remove(&claim.token_id)
            .ok_or(BrokerError::Token(TokenError::UnknownToken))?;
        // Removed before it is checked: a claim that fails has still consumed its one attempt, so
        // a component cannot probe the bindings one field at a time.
        token.check(claim)?;
        token.check_current_revision(revision_in_force)?;
        Ok(token)
    }

    /// Withdraws every token issued against one instance.
    ///
    /// The binding revision advancing already invalidates them; this removes the records so the
    /// store does not carry tokens nothing can spend.
    pub fn withdraw(&mut self, application_instance_id: ApplicationInstanceId) -> usize {
        let withdrawn: Vec<ActionTokenId> = self
            .unspent
            .iter()
            .filter(|(_, token)| token.application_instance_id == application_instance_id)
            .map(|(token_id, _)| token_id.clone())
            .collect();
        for token_id in &withdrawn {
            self.unspent.remove(token_id);
        }
        withdrawn.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn invocation() -> Invocation {
        Invocation {
            actor_id: ActorId::new("device-1").expect("valid"),
            grant: BrokerGrant::UpstreamAction,
            grant_id: GrantId::new(Uuid::from_bytes([7; 16])),
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([2; 16])),
            binding_revision: AgentBindingRevision::new(4),
            action: ActionName::new("prompt.submit").expect("valid"),
            parameters: b"{\"text\":\"hello\"}".to_vec(),
        }
    }

    fn grants() -> BrokerGrants {
        BrokerGrants::granted([BrokerGrant::Observation, BrokerGrant::UpstreamAction])
    }

    #[test]
    fn an_observation_binding_gets_no_upstream_action_token() {
        let mut store = TokenStore::new();
        let observation_only = BrokerGrants::granted([BrokerGrant::Observation]);
        assert!(
            store
                .issue(&observation_only, &invocation(), TimestampMs::new(1))
                .is_err(),
            "reading output is not permission to submit input"
        );
        assert_eq!(store.outstanding(), 0);
    }

    #[test]
    fn a_token_is_spent_once() {
        let mut store = TokenStore::new();
        let token = store
            .issue(&grants(), &invocation(), TimestampMs::new(1))
            .expect("issued");
        let claim = ActionTokenClaim::from(&token);
        store
            .spend(&claim, AgentBindingRevision::new(4))
            .expect("the first spend succeeds");
        assert!(
            store.spend(&claim, AgentBindingRevision::new(4)).is_err(),
            "the same invocation's authority cannot be spent twice"
        );
    }

    #[test]
    fn a_parameter_the_component_changed_does_not_spend_the_token() {
        let mut store = TokenStore::new();
        let token = store
            .issue(&grants(), &invocation(), TimestampMs::new(1))
            .expect("issued");
        let mut claim = ActionTokenClaim::from(&token);
        claim.parameter_hash = Digest256::from_bytes([0; 32]);
        assert!(store.spend(&claim, AgentBindingRevision::new(4)).is_err());
    }

    #[test]
    fn a_thread_that_changed_while_the_component_worked_invalidates_the_token() {
        let mut store = TokenStore::new();
        let token = store
            .issue(&grants(), &invocation(), TimestampMs::new(1))
            .expect("issued");
        let claim = ActionTokenClaim::from(&token);
        assert!(
            store.spend(&claim, AgentBindingRevision::new(5)).is_err(),
            "the revision in force decides, not the revision the component reports"
        );
    }

    #[test]
    fn withdrawing_an_instance_takes_its_tokens() {
        let mut store = TokenStore::new();
        store
            .issue(&grants(), &invocation(), TimestampMs::new(1))
            .expect("issued");
        let mut other = invocation();
        other.application_instance_id = ApplicationInstanceId::new(Uuid::from_bytes([3; 16]));
        store
            .issue(&grants(), &other, TimestampMs::new(1))
            .expect("issued");
        assert_eq!(
            store.withdraw(ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))),
            1
        );
        assert_eq!(store.outstanding(), 1);
    }

    #[test]
    fn the_store_refuses_to_grow_without_bound() {
        let mut store = TokenStore::new();
        for _ in 0..MAX_UNSPENT_TOKENS {
            store
                .issue(&grants(), &invocation(), TimestampMs::new(1))
                .expect("issued");
        }
        assert!(
            store
                .issue(&grants(), &invocation(), TimestampMs::new(1))
                .is_err()
        );
    }
}
