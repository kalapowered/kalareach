//! How the delivery service reaches the network: one managed transport per origin.
//!
//! Every exchange delivery makes is addressed to an origin it already knows. A notification, a
//! status question and a renewal go to the gateway the delivery credential names, because that
//! gateway issued the credential and its signature covers that origin and no other. A webhook
//! message goes to the origin of the address its owner configured. So the delivery service holds
//! no origin of its own: it asks for the transport of the origin in front of it.
//!
//! [`DeliveryTransports`] is that question. [`ManagedTransports`] is the answer a shipped daemon
//! attaches at startup: one [`HttpService`] per origin, built the first time the origin is asked
//! for and kept, so the calls to one gateway share one set of connections. Every rule the managed
//! transport keeps holds here unchanged: HTTPS off loopback, no redirects, no retry of a request
//! that may have arrived, finite deadlines and a bounded answer. Every exchange goes through the
//! proxy this host's configuration document selected when the daemon started, or directly when it
//! selected none, so a webhook address that proxy cannot reach fails through it rather than going
//! around it.
//!
//! A test attaches a recorder instead, which is how a test sees exactly what left the host.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use kr_client::services::{HttpDeadlines, HttpService, ResponseLimits, ServiceHttp};
use kr_protocol::service::GatewayOrigin;
use kr_transport::config::ProxyUrl;

/// Where the delivery service's exchanges go.
pub trait DeliveryTransports: std::fmt::Debug + Send + Sync {
    /// The transport that reaches one origin.
    ///
    /// # Errors
    ///
    /// Returns why no transport reaches that origin. Nothing has been sent when this fails.
    fn to(&self, origin: &GatewayOrigin) -> Result<Arc<dyn ServiceHttp>, String>;
}

/// The managed transport of every origin delivery reaches, built on first use.
#[derive(Debug)]
pub struct ManagedTransports {
    built: Mutex<BTreeMap<String, Arc<HttpService>>>,
    /// The proxy every one of them goes through, or none.
    proxy: Option<ProxyUrl>,
}

impl ManagedTransports {
    /// Builds an empty set whose transports go through `proxy`, or directly when that is `None`;
    /// each origin's transport is built the first time it is asked for.
    ///
    /// A shipped daemon passes the proxy its configuration document selected when it started.
    #[must_use]
    pub fn new(proxy: Option<ProxyUrl>) -> Self {
        Self {
            built: Mutex::default(),
            proxy,
        }
    }
}

impl DeliveryTransports for ManagedTransports {
    fn to(&self, origin: &GatewayOrigin) -> Result<Arc<dyn ServiceHttp>, String> {
        let mut built = self
            .built
            .lock()
            .map_err(|_| "the delivery transports were left locked by a failed call".to_owned())?;
        if let Some(transport) = built.get(origin.as_str()) {
            return Ok(Arc::clone(transport) as Arc<dyn ServiceHttp>);
        }
        let transport = Arc::new(
            HttpService::through(
                origin.clone(),
                HttpDeadlines::default(),
                ResponseLimits::default(),
                self.proxy.as_ref(),
            )
            .map_err(|error| format!("no transport reaches {origin}: {error}"))?,
        );
        built.insert(origin.as_str().to_owned(), Arc::clone(&transport));
        Ok(transport as Arc<dyn ServiceHttp>)
    }
}

/// Whether a failed exchange left anything that could have been carried out.
///
/// The managed transport keeps two classes apart, and so does everything here that reads one of
/// its failures: [`kr_protocol::error::ErrorCode::UpstreamUnavailable`] is a failure the connector
/// reported before a byte of the request was written, and
/// [`kr_protocol::error::ErrorCode::InvalidArgument`] is a request the transport refused to send.
/// Everything else may have reached the service.
#[must_use]
pub fn nothing_was_sent(error: &kr_client::ClientError) -> bool {
    matches!(
        error.code(),
        kr_protocol::error::ErrorCode::UpstreamUnavailable
            | kr_protocol::error::ErrorCode::InvalidArgument
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_origin_is_one_transport_and_two_origins_are_two() {
        let transports = ManagedTransports::new(None);
        let gateway = GatewayOrigin::new("https://reach.invalid").expect("an origin");
        let hooks = GatewayOrigin::new("https://hooks.invalid").expect("an origin");
        let first = transports.to(&gateway).expect("a transport");
        let again = transports.to(&gateway).expect("a transport");
        let other = transports.to(&hooks).expect("a transport");
        assert!(
            Arc::ptr_eq(&first, &again),
            "one origin shares one set of connections"
        );
        assert!(!Arc::ptr_eq(&first, &other));
    }

    #[test]
    fn a_refusal_and_an_unreachable_service_sent_nothing_and_everything_else_may_have() {
        let failure = |code| {
            kr_client::ClientError::Host(kr_protocol::error::ProtocolError::new(
                code,
                "a failure".to_owned(),
            ))
        };
        assert!(nothing_was_sent(&failure(
            kr_protocol::error::ErrorCode::UpstreamUnavailable
        )));
        assert!(nothing_was_sent(&failure(
            kr_protocol::error::ErrorCode::InvalidArgument
        )));
        assert!(!nothing_was_sent(&failure(
            kr_protocol::error::ErrorCode::OutcomeUnknown
        )));
        assert!(!nothing_was_sent(&kr_client::ClientError::ConnectionEnded));
    }
}
