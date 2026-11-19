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
    AccountHttp, HttpDeadlines, HttpService, ResponseLimits, SendGate, ServiceFuture, ServiceHttp,
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
    /// Told each time a request reaches the build step, so a case can act only after that.
    #[cfg(test)]
    reached_setup: Mutex<Option<std::sync::mpsc::Sender<()>>>,
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
            #[cfg(test)]
            reached_setup: Mutex::new(None),
        }
    }

    /// The built transport, building it now when none is kept; `None` when the platform cannot.
    /// A clone shares the connection pool of the kept one.
    fn transport(&self) -> Option<HttpService> {
        #[cfg(test)]
        if let Some(sender) = self
            .reached_setup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            let _ = sender.send(());
        }
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

    /// The setup comes first and the gate after it: building the transport takes a lock and can
    /// build the connection service, and a wait there is time the request has spent before it is
    /// written. The check stands immediately before the write.
    fn post_json_by<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
        gate: &'a SendGate,
    ) -> ServiceFuture<'a, Option<ServiceHttpAnswer>> {
        Box::pin(async move {
            let Some(transport) = self.transport() else {
                return Err(unavailable());
            };
            if gate.passed() {
                return Ok(None);
            }
            transport.post_json(url, body, headers).await.map(Some)
        })
    }

    fn get_json<'a>(
        &'a self,
        url: &'a str,
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            match self.transport() {
                Some(transport) => ServiceHttp::get_json(&transport, url, headers).await,
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

/// The account service's transport while the host's outbound route is closed: it connects to
/// nothing and turns every request away, so the account the host keeps can still be read and
/// ended locally, and what is owed to the service waits for the route.
#[derive(Debug)]
pub struct ClosedTransport;

impl ClosedTransport {
    fn refuse() -> ClientError {
        ClientError::refusal(
            ErrorCode::UpstreamUnavailable,
            Shown::said(
                "no request is sent: this host's configuration document cannot be used, so its \
                 outbound route is closed until its daemon starts over one it can use",
            ),
        )
    }
}

impl AccountHttp for ClosedTransport {
    fn post_form<'a>(
        &'a self,
        _url: &'a str,
        _body: &'a [u8],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move { Err(Self::refuse()) })
    }

    fn get<'a>(
        &'a self,
        _url: &'a str,
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move { Err(Self::refuse()) })
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

    /// The gate is checked after the transport is set up: the build lock is held from this thread,
    /// the request reaches the setup and waits, the clock passes the limit, and the lock is let go.
    /// The request then sends nothing and makes no connection.
    #[test]
    fn a_limit_that_passes_during_transport_setup_sends_nothing() {
        use kr_transport::clock::{ContinuousClock, ManualClock};
        use std::time::Duration;

        let clock = ManualClock::new();
        let by = clock
            .now()
            .checked_add(Duration::from_secs(30))
            .expect("an instant");
        let origin = GatewayOrigin::new("https://voice.example.test").expect("an origin");
        let transport = std::sync::Arc::new(ManagedTransport::new(origin, None, VOICE_DEADLINES));
        let (sender, reached) = std::sync::mpsc::channel();
        *transport.reached_setup.lock().expect("the hook") = Some(sender);
        let held = transport.built.lock().expect("the build lock");

        let runner = {
            let transport = std::sync::Arc::clone(&transport);
            let clock = clock.clone();
            std::thread::spawn(move || {
                let gate = SendGate {
                    by,
                    clock: std::sync::Arc::new(clock),
                };
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a runtime")
                    .block_on(transport.post_json_by(
                        "https://voice.example.test/api/voice/sessions",
                        b"{}",
                        &[],
                        &gate,
                    ))
            })
        };
        reached
            .recv_timeout(Duration::from_secs(60))
            .expect("the request reached the transport's setup");
        clock.advance(Duration::from_secs(31));
        drop(held);
        let answer = runner.join().expect("the request finished");
        assert!(
            matches!(answer, Ok(None)),
            "a limit that passed during the setup sends nothing"
        );
    }
}
