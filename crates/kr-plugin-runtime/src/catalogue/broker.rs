//! What the catalogue needs from the trusted broker, expressed as a trait.
//!
//! The catalogue decides what a package is and what it may do. Two things it cannot decide live in
//! the worker's broker and its gateway:
//!
//! * **Capability evidence from a live binding.** The catalogue can say what a release was
//!   qualified against. Only something that performed the operation on this host can say that it
//!   works here, and that is the broker, through the instance it holds.
//! * **Admission of a package's declarative proxy.** A connector table is metadata until the
//!   gateway admits it for one application instance, and admission is the gateway's: it owns the
//!   transport, the fence and the arbitration the proxy sits behind.
//!
//! Both are reads. Nothing in this trait grants anything, and nothing in it dispatches: a
//! catalogue that asked a broker for permission would be a second permission system, which is the
//! thing section 11 says not to build.
//!
//! [`UnboundBroker`] is the answer when no broker is bound, which is also what a host does before
//! a worker exists: there is no live evidence, no proxy is admitted, and nothing pretends
//! otherwise. It is what the suites bind against, and what a host uses until a broker is there.

use kr_plugin_sdk::capability::{CapabilityEvidence, PluginCapability};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::ids::PluginId;
use kr_protocol::ids::EnvironmentId;

use crate::catalogue::error::{CatalogueError, CatalogueResult};

/// What the catalogue asks the broker about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRequest {
    /// The environment the question is about.
    pub environment_id: EnvironmentId,
    /// The package.
    pub plugin_id: PluginId,
    /// The exact hash the binding holds, which is not necessarily the installed one.
    pub package_digest: PayloadDigest,
    /// The capability being asked about.
    pub capability: PluginCapability,
}

/// What the catalogue asks the gateway to admit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyRequest {
    /// The environment.
    pub environment_id: EnvironmentId,
    /// The package whose connector table would be admitted.
    pub plugin_id: PluginId,
    /// The exact hash the binding holds.
    pub package_digest: PayloadDigest,
    /// The digest of the connector table itself.
    pub connector_digest: PayloadDigest,
}

/// What the gateway admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyAdmission {
    /// The connector table that was admitted.
    pub connector_digest: PayloadDigest,
    /// The revision the admission is bound to, which every later action rechecks.
    pub revision: kr_protocol::ids::CapabilityRevision,
}

/// The broker, as the catalogue needs it.
pub trait BrokerBridge: core::fmt::Debug + Send + Sync {
    /// Returns the evidence a live binding established, where one has.
    ///
    /// `None` means the broker holds nothing about this, which is different from holding a
    /// negative result: the catalogue reports "not tested" rather than inventing an answer.
    fn live_evidence(&self, request: &EvidenceRequest) -> Option<CapabilityEvidence>;

    /// Asks the gateway to admit one package's declarative proxy.
    ///
    /// # Errors
    ///
    /// Returns the refusal the gateway decided.
    fn admit_proxy(&self, request: &ProxyRequest) -> CatalogueResult<ProxyAdmission>;

    /// Returns every package hash a live binding currently holds.
    ///
    /// A sync never evicts one of these to finish, so the catalogue asks before it reclaims rather
    /// than after somebody's binding stopped working.
    fn live_packages(&self) -> Vec<PayloadDigest>;
}

/// The broker that is not bound.
///
/// A host with no worker has no live evidence and admits no proxy. Saying so is the honest answer
/// and the safe one: an uncached payload gets `PACKAGE_UNAVAILABLE_OFFLINE` rather than a
/// capability that is not there, and an unadmitted proxy gets a refusal rather than a table
/// nothing is enforcing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnboundBroker;

impl BrokerBridge for UnboundBroker {
    fn live_evidence(&self, _request: &EvidenceRequest) -> Option<CapabilityEvidence> {
        None
    }

    fn admit_proxy(&self, request: &ProxyRequest) -> CatalogueResult<ProxyAdmission> {
        Err(CatalogueError::Disabled {
            detail: format!(
                "no broker is bound in this environment, so {}'s proxy is not admitted",
                request.plugin_id
            ),
        })
    }

    fn live_packages(&self) -> Vec<PayloadDigest> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn request() -> ProxyRequest {
        ProxyRequest {
            environment_id: EnvironmentId::new(Uuid::NIL),
            plugin_id: PluginId::new("kalareach/example-declarative").expect("a valid identifier"),
            package_digest: PayloadDigest::of(b"package"),
            connector_digest: PayloadDigest::of(b"connector"),
        }
    }

    #[test]
    fn an_unbound_broker_holds_nothing_and_admits_nothing() {
        let broker = UnboundBroker;
        assert!(broker.live_packages().is_empty());
        assert!(
            broker
                .live_evidence(&EvidenceRequest {
                    environment_id: EnvironmentId::new(Uuid::NIL),
                    plugin_id: request().plugin_id,
                    package_digest: PayloadDigest::of(b"package"),
                    capability: PluginCapability::BrokerSemanticEvents,
                })
                .is_none()
        );
        let refusal = broker
            .admit_proxy(&request())
            .expect_err("nothing is bound");
        assert!(
            refusal.to_string().contains("no broker is bound"),
            "{refusal}"
        );
    }
}
