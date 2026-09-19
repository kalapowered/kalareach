//! The component-facing half of the broker's contract.
//!
//! The broker itself is the worker's, in `crates/kr-worker/src/broker`. What lives here is the
//! gate every call into a component passes, expressed against the shared types in
//! `kr_protocol::broker` so that both sides read the same contract rather than two descriptions of
//! one.
//!
//! Three things are decided here, and each of them before a component runs rather than after.
//!
//! * **Whether this binding may be asked at all.** [`ComponentAuthority::may_prepare_action`],
//!   [`ComponentAuthority::may_decode`] and [`ComponentAuthority::may_encode`] answer from the
//!   grants and the decoding-trust record. An observation-only binding is never invited to prepare
//!   an effect, so a component that would have tried never gets the chance.
//! * **Whether what came back is inside the trust that was granted.** A projection is checked
//!   against the schema policy of the record that authorised the decoding, before anything treats
//!   it as an approval.
//! * **Whether this binding's rich capabilities are available.** [`RichCapability`] is disabled by
//!   a component's faults and by the host's volatile fence, and it is deliberately separate from
//!   anything the native forwarding path reads, because a fault here must not stall that.

use kr_protocol::broker::{
    BrokerGrant, BrokerGrants, DecodedProjection, DecodingTrust, GrantError, TrustError,
};
use kr_protocol::ids::UpstreamMethod;

/// Why a call into a component was refused before it ran.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    /// The binding does not hold the grant the call needs.
    #[error("{0}")]
    Grant(#[from] GrantError),
    /// The binding holds no decoding trust, or none that covers this method.
    #[error("this binding is not trusted to interpret {method}")]
    NotTrusted {
        /// The method that was asked for.
        method: UpstreamMethod,
    },
    /// The binding is trusted to interpret and not to answer.
    #[error("this binding may interpret {method} and may not answer it")]
    MayNotAnswer {
        /// The method that was asked for.
        method: UpstreamMethod,
    },
    /// What came back is outside the trust that was granted.
    #[error("{0}")]
    Trust(#[from] TrustError),
    /// This binding's rich capabilities are disabled.
    #[error("this binding's rich capabilities are disabled: {reason}")]
    RichDisabled {
        /// Why they are disabled.
        reason: String,
    },
}

/// What one binding is permitted to be asked.
#[derive(Clone, Debug)]
pub struct ComponentAuthority {
    /// The three grants, each held separately.
    pub grants: BrokerGrants,
    /// The decoding trust, where the binding has any.
    pub trust: Option<DecodingTrust>,
}

impl ComponentAuthority {
    /// A binding with the grants it was given and no decoding trust.
    #[must_use]
    pub const fn observing(grants: BrokerGrants) -> Self {
        Self {
            grants,
            trust: None,
        }
    }

    /// Checks that this binding may be given an observation.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::Grant`] when it holds no observation grant.
    pub fn may_observe(&self) -> Result<(), AuthorityError> {
        Ok(self.grants.require(BrokerGrant::Observation)?)
    }

    /// Checks that this binding may be asked to prepare an effect.
    ///
    /// Section 11: "Observation callbacks cannot submit input merely because they can read
    /// output." The check is here rather than on the returned plan, so a component that would have
    /// tried is never invited to.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::Grant`] when it holds no upstream-action grant.
    pub fn may_prepare_action(&self) -> Result<(), AuthorityError> {
        Ok(self.grants.require(BrokerGrant::UpstreamAction)?)
    }

    /// Checks that this binding may be asked to interpret one upstream method.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::Grant`] without the interpreter grant, and
    /// [`AuthorityError::NotTrusted`] without a trust record covering this exact method.
    pub fn may_decode(&self, method: &UpstreamMethod) -> Result<&DecodingTrust, AuthorityError> {
        self.grants.require(BrokerGrant::ApprovalInterpreter)?;
        self.trust
            .as_ref()
            .filter(|trust| trust.covers(method))
            .ok_or_else(|| AuthorityError::NotTrusted {
                method: method.clone(),
            })
    }

    /// Checks that this binding may be asked to encode an answer to one upstream method.
    ///
    /// # Errors
    ///
    /// Returns whatever [`ComponentAuthority::may_decode`] refuses, and
    /// [`AuthorityError::MayNotAnswer`] when the trust covers interpretation and not answering.
    pub fn may_encode(&self, method: &UpstreamMethod) -> Result<&DecodingTrust, AuthorityError> {
        let trust = self.may_decode(method)?;
        if trust.may_encode_response {
            Ok(trust)
        } else {
            Err(AuthorityError::MayNotAnswer {
                method: method.clone(),
            })
        }
    }

    /// Checks what a component returned against the trust that authorised the call.
    ///
    /// # Errors
    ///
    /// Returns whatever [`ComponentAuthority::may_decode`] refuses, and [`AuthorityError::Trust`]
    /// when the projection is outside the schema policy the trust was granted under.
    pub fn check_projection(
        &self,
        method: &UpstreamMethod,
        projection: &DecodedProjection,
    ) -> Result<(), AuthorityError> {
        let trust = self.may_decode(method)?;
        Ok(trust.check_projection(projection)?)
    }
}

/// Whether one binding's rich capabilities are available, and why not when they are not.
///
/// Nothing on the native forwarding path reads this. That is the point: section 11 requires a Wasm
/// fault to disable the affected rich capabilities without stalling or discarding otherwise valid
/// native traffic, and a fence the forwarding path cannot see is a fence it cannot be stopped by.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RichCapability {
    disabled: Option<String>,
}

impl RichCapability {
    /// A binding whose rich capabilities are available.
    #[must_use]
    pub const fn available() -> Self {
        Self { disabled: None }
    }

    /// Returns true when rich work may be asked of this binding.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        self.disabled.is_none()
    }

    /// Returns why rich work is refused, when it is.
    #[must_use]
    pub fn disabled_reason(&self) -> Option<&str> {
        self.disabled.as_deref()
    }

    /// Disables rich work, because the component faulted often enough to be stopped.
    pub fn disable(&mut self, reason: impl Into<String>) {
        if self.disabled.is_none() {
            self.disabled = Some(reason.into());
        }
    }

    /// Restores rich work, because the binding was replaced.
    ///
    /// A disabled binding is not re-enabled by waiting. It is re-enabled by being bound again,
    /// which is a new component instance with its own fault count.
    pub fn restore(&mut self) {
        self.disabled = None;
    }

    /// Refuses a rich call while rich work is disabled.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::RichDisabled`] with the reason.
    pub fn require(&self) -> Result<(), AuthorityError> {
        match self.disabled.as_ref() {
            None => Ok(()),
            Some(reason) => Err(AuthorityError::RichDisabled {
                reason: reason.clone(),
            }),
        }
    }
}
