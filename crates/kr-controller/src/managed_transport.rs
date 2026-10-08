//! How the host reaches the managed service: the voice broker and the account service.
//!
//! The transport is built when a request first needs it and kept once it is built, as delivery's
//! is. A host whose platform cannot set up certificate verification still starts, serves
//! everything that needs no managed service, and says why whenever a request needs the service. A
//! failed build is not kept, so a host whose platform is repaired reaches the service at its next
//! request without a restart.

use std::sync::Mutex;

use kr_client::error::ClientError;
use kr_client::services::{
    AccountHttp, HttpDeadlines, HttpService, ResponseLimits, ServiceFuture, ServiceHttp,
    ServiceHttpAnswer,
};
use kr_client::shown::Shown;
use kr_protocol::error::ErrorCode;
use kr_protocol::service::GatewayOrigin;
use kr_transport::config::ProxyUrl;

/// How long an exchange with the managed voice service may take.
///
/// Longer than the client library's defaults, because the service takes up to 30 seconds to create
/// a call and make its metering channel durable before it answers a start, and a start whose
/// answer this host stopped waiting for is a call that may be running and metered.
pub const VOICE_DEADLINES: HttpDeadlines = HttpDeadlines {
    connect: std::time::Duration::from_secs(5),
    read: std::time::Duration::from_secs(45),
    total: std::time::Duration::from_secs(50),
};

/// A managed service's transport: one gateway, through the proxy the host's configuration selects
/// or directly, and never through one the environment names.
#[derive(Debug)]
pub struct ManagedTransport {
    origin: GatewayOrigin,
    proxy: Option<ProxyUrl>,
    deadlines: HttpDeadlines,
    built: Mutex<Option<HttpService>>,
}

impl ManagedTransport {
    /// A transport to `origin` with `deadlines` that is built on its first use.
    #[must_use]
    pub const fn new(
        origin: GatewayOrigin,
        proxy: Option<ProxyUrl>,
        deadlines: HttpDeadlines,
    ) -> Self {
        Self {
            origin,
            proxy,
            deadlines,
            built: Mutex::new(None),
        }
    }

    /// The built transport, building it now when none is kept; `None` when the platform cannot.
    /// A clone shares the connection pool of the kept one.
    fn transport(&self) -> Option<HttpService> {
        let mut built = self
            .built
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if built.is_none() {
            *built = HttpService::through(
                self.origin.clone(),
                self.deadlines,
                ResponseLimits::default(),
                self.proxy.as_ref(),
            )
            .ok();
        }
        built.clone()
    }
}

/// The refusal a request gets when the platform cannot set up certificate verification. Nothing was
/// sent.
fn unavailable() -> ClientError {
    ClientError::refusal(
        ErrorCode::UpstreamUnavailable,
        Shown::said(
            "this host could not set up the platform's certificate verification, so it reaches no \
             managed service",
        ),
    )
}

impl ServiceHttp for ManagedTransport {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            match self.transport() {
                Some(transport) => transport.post_json(url, body, headers).await,
                None => Err(unavailable()),
            }
        })
    }
}

impl AccountHttp for ManagedTransport {
    fn post_form<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            match self.transport() {
                Some(transport) => transport.post_form(url, body).await,
                None => Err(unavailable()),
            }
        })
    }

    fn get<'a>(
        &'a self,
        url: &'a str,
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            match self.transport() {
                Some(transport) => AccountHttp::get(&transport, url, headers).await,
                None => Err(unavailable()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The service takes up to 30 seconds to answer a start (its creation window), so the
    /// transport this host builds for it waits longer than that for the answer's head and for the
    /// whole exchange.
    #[test]
    fn the_voice_transport_waits_longer_for_a_start_than_the_service_takes() {
        const SERVICE_CREATION_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);
        let origin = GatewayOrigin::new("https://voice.example.test").expect("an origin");
        let transport = ManagedTransport::new(origin, None, VOICE_DEADLINES)
            .transport()
            .expect("a transport on a platform with certificate verification");
        let deadlines = transport.deadlines();
        assert!(deadlines.read > SERVICE_CREATION_WINDOW);
        assert!(deadlines.total > deadlines.read);
    }
}
