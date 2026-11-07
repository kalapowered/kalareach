//! The gateways this host delivers through.
//!
//! A delivery credential names the gateway that issued it, and the host sends every notification,
//! status question and renewal under it to that origin. So the origin is the host's to allow, not
//! the device's to choose: the host delivers through the official gateway and through the origins
//! its configuration document lists, and through no other. [`AllowedGateways`] is that set.
//!
//! The set is read in three places, and the rule that ties them is that a credential for an origin
//! outside it cannot be used:
//!
//! * a registration is checked against it before the gateway is asked, and again when the
//!   registration is written ([`crate::push::check_offered_credential`]);
//! * the store of held credentials returns none for an origin outside it
//!   ([`super::credentials::HeldCredentials`]), so a notification, a status question and a
//!   renewal never start;
//! * every exchange under a bearer is made through [`GatedTransports`], whose transport asks the
//!   set again each time it is given a request, so a request that is put after the origin left
//!   the set sends nothing, whatever looked at the credential or took the transport before. A
//!   revocation is not made through it: it carries no bearer and no notification, and it is how a
//!   gateway that was taken out of the list is told to end what it issued.
//!
//! The set is a leaf: its lock is never held while another lock is taken.

use std::sync::{Arc, RwLock};

use kr_protocol::service::GatewayOrigin;

use super::transport::DeliveryTransports;

/// The origins a credential may name: the official gateway and the ones the document lists.
///
/// The list is kept in the order the document gives it, which is the order the report says it in,
/// and holds at most sixteen origins, so a lookup reads it through.
#[derive(Debug)]
pub struct AllowedGateways {
    official: String,
    listed: RwLock<Arc<Vec<String>>>,
}

impl AllowedGateways {
    /// Builds the set from the official gateway's origin and the document's list.
    #[must_use]
    pub fn new(official: &str, listed: &[String]) -> Self {
        Self {
            official: official.to_owned(),
            listed: RwLock::new(Arc::new(listed.to_vec())),
        }
    }

    /// The official gateway's origin, which is always allowed and is never listed.
    #[must_use]
    pub fn official(&self) -> &str {
        &self.official
    }

    /// Whether a credential may name this origin.
    #[must_use]
    pub fn allows(&self, origin: &str) -> bool {
        origin == self.official || self.snapshot().iter().any(|listed| listed == origin)
    }

    /// Makes the document's list the one in force.
    ///
    /// Only the delivery service moves the set, in its journal's lock
    /// ([`super::DeliveryModule::replace_gateways`]), which is where the sweep of owed revocations
    /// reads it.
    pub(super) fn replace(&self, listed: &[String]) {
        let listed = Arc::new(listed.to_vec());
        *self
            .listed
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = listed;
    }

    /// The listed origins now in force.
    #[must_use]
    pub fn listed(&self) -> Vec<String> {
        self.snapshot().as_ref().clone()
    }

    fn snapshot(&self) -> Arc<Vec<String>> {
        Arc::clone(
            &self
                .listed
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

/// The transports every exchange under a delivery credential goes through, which carry a request
/// to an origin only while it is allowed.
///
/// The check is made when a request is put, not when the transport is taken: an exchange can hold
/// its transport across a change of the set (a request that is prepared and sent later), and the
/// request it then puts must find the origin as it stands. A request is put when its future is
/// first polled, which is where the transport starts its work, so one that was called while the
/// origin was allowed and polled after it was removed sends nothing. One already put completes,
/// including one still waiting for its connection: the transport waits five seconds for a
/// connection and tries once more, so such a request can leave the host for up to about ten
/// seconds after the origin was taken out.
#[derive(Debug)]
pub struct GatedTransports {
    inner: Arc<dyn DeliveryTransports>,
    gateways: Arc<AllowedGateways>,
}

impl GatedTransports {
    /// Gates `inner` by `gateways`.
    #[must_use]
    pub fn new(inner: Arc<dyn DeliveryTransports>, gateways: Arc<AllowedGateways>) -> Self {
        Self { inner, gateways }
    }
}

impl DeliveryTransports for GatedTransports {
    fn to(
        &self,
        origin: &GatewayOrigin,
    ) -> Result<Arc<dyn kr_client::services::ServiceHttp>, String> {
        Ok(Arc::new(GatedHttp {
            inner: self.inner.to(origin)?,
            origin: origin.as_str().to_owned(),
            gateways: Arc::clone(&self.gateways),
        }))
    }

    fn outbound(&self) -> crate::config::Outbound {
        self.inner.outbound()
    }
}

/// One origin's transport, which puts a request only while the origin is allowed.
#[derive(Debug)]
struct GatedHttp {
    inner: Arc<dyn kr_client::services::ServiceHttp>,
    origin: String,
    gateways: Arc<AllowedGateways>,
}

impl GatedHttp {
    /// Whether the origin is allowed now, as the failure of a request this host no longer puts:
    /// one the transport refused to send, so nothing left.
    fn allowed_now(&self) -> kr_client::Result<()> {
        if self.gateways.allows(&self.origin) {
            return Ok(());
        }
        Err(kr_client::ClientError::refusal(
            kr_protocol::error::ErrorCode::InvalidArgument,
            kr_client::shown::Shown::said(
                "this host delivers through the official gateway and the ones its configuration \
                 lists, and this is not one of them, so nothing was sent",
            ),
        ))
    }
}

impl kr_client::services::ServiceHttp for GatedHttp {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> kr_client::services::ServiceFuture<'a, kr_client::services::ServiceHttpAnswer> {
        Box::pin(async move {
            self.allowed_now()?;
            self.inner.post_json(url, body, headers).await
        })
    }

    fn post_bytes<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> kr_client::services::ServiceFuture<'a, kr_client::services::ServiceHttpAnswer> {
        Box::pin(async move {
            self.allowed_now()?;
            self.inner.post_bytes(url, body, headers).await
        })
    }

    fn get_json<'a>(
        &'a self,
        url: &'a str,
        headers: &'a [(&'a str, &'a str)],
    ) -> kr_client::services::ServiceFuture<'a, kr_client::services::ServiceHttpAnswer> {
        Box::pin(async move {
            self.allowed_now()?;
            self.inner.get_json(url, headers).await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use kr_client::services::{ServiceFuture, ServiceHttp, ServiceHttpAnswer};

    use super::*;

    /// A transport that counts the requests it carries, at the moment its future runs.
    #[derive(Debug, Default)]
    struct Carrying {
        carried: AtomicUsize,
    }

    impl Carrying {
        fn carry(&self) -> ServiceFuture<'_, ServiceHttpAnswer> {
            Box::pin(async {
                self.carried.fetch_add(1, Ordering::SeqCst);
                Ok(ServiceHttpAnswer {
                    status: 200,
                    body: Vec::new(),
                })
            })
        }
    }

    impl ServiceHttp for Carrying {
        fn post_json<'a>(
            &'a self,
            _url: &'a str,
            _body: &'a [u8],
            _headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            self.carry()
        }

        fn post_bytes<'a>(
            &'a self,
            _url: &'a str,
            _body: &'a [u8],
            _headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            self.carry()
        }

        fn get_json<'a>(
            &'a self,
            _url: &'a str,
            _headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            self.carry()
        }
    }

    #[derive(Debug)]
    struct Reaching(Arc<Carrying>);

    impl DeliveryTransports for Reaching {
        fn to(
            &self,
            _origin: &GatewayOrigin,
        ) -> Result<Arc<dyn kr_client::services::ServiceHttp>, String> {
            Ok(Arc::clone(&self.0) as Arc<dyn kr_client::services::ServiceHttp>)
        }

        fn outbound(&self) -> crate::config::Outbound {
            crate::config::Outbound::Direct
        }
    }

    /// KR-REQ-16.04: a request is put only while its gateway is allowed, whichever way it is
    /// made, and the check is made when the request is put: one called while the gateway was
    /// allowed and polled after it was taken out sends nothing, and neither does one called after.
    #[test]
    fn a_request_is_put_only_while_its_gateway_is_allowed_however_late_it_is_polled() {
        const LISTED: &str = "https://push.listed.invalid";
        let reactor = tokio::runtime::Runtime::new().expect("a runtime");
        let carrying = Arc::new(Carrying::default());
        let gateways = Arc::new(AllowedGateways::new(
            "https://reach.invalid",
            &[LISTED.to_owned()],
        ));
        let gated =
            GatedTransports::new(Arc::new(Reaching(Arc::clone(&carrying))), gateways.clone());
        let origin = GatewayOrigin::new(LISTED).expect("an origin");
        let transport = gated.to(&origin).expect("a transport");

        type Call<'a> = Box<dyn Fn() -> ServiceFuture<'a, ServiceHttpAnswer> + 'a>;
        let calls: Vec<(&str, Call<'_>)> = vec![
            ("post_json", Box::new(|| transport.post_json("u", b"", &[]))),
            (
                "post_bytes",
                Box::new(|| transport.post_bytes("u", b"", &[])),
            ),
            ("get_json", Box::new(|| transport.get_json("u", &[]))),
        ];

        // The control: while the gateway is allowed each is carried.
        for (what, call) in &calls {
            let before = carrying.carried.load(Ordering::SeqCst);
            reactor
                .block_on(call())
                .unwrap_or_else(|_| panic!("{what} was refused"));
            assert_eq!(
                carrying.carried.load(Ordering::SeqCst),
                before + 1,
                "{what}"
            );
        }

        // Called while allowed, polled after the removal: nothing is carried.
        let waiting: Vec<_> = calls.iter().map(|(_, call)| call()).collect();
        gateways.replace(&[]);
        let before = carrying.carried.load(Ordering::SeqCst);
        for ((what, _), future) in calls.iter().zip(waiting) {
            assert!(reactor.block_on(future).is_err(), "{what} was carried late");
        }
        // And called after the removal.
        for (what, call) in &calls {
            assert!(reactor.block_on(call()).is_err(), "{what} was carried");
        }
        assert_eq!(carrying.carried.load(Ordering::SeqCst), before);
    }
}
