//! The loop that drives delivery for one environment.
//!
//! [`DeliveryRuntime`] is started from the controller's start path and runs for as long as the
//! daemon does. It does three things, in this order:
//!
//! 1. **Recovery, once**, before anything else: attempts that were on the wire when the host
//!    stopped become outcomes nobody knows, queued work whose authority has ended is taken back,
//!    and events taken and never produced from are finished. That is
//!    [`DeliveryModule::reconcile`].
//! 2. **A pass on every tick** of [`Cadence::pass`]: the due outbox is claimed and sent, which is
//!    [`DeliveryModule::run_due`].
//! 3. **Questions on a slower tick**, [`Cadence::questions`]: credentials inside their renewal
//!    window are renewed ahead of need, and every outcome nobody knows is asked about, which is
//!    [`HeldCredentials::renew_due`] and [`DeliveryModule::resolve_unknown`]. A status question
//!    is counted against a budget at the gateway, so it is asked minutes apart rather than on
//!    every pass.
//!
//! A pass blocks: it opens connections and waits for gateways, and the journal is behind a
//! synchronous lock. So every pass runs on a blocking thread and the loop waits for it, which also
//! means two passes never overlap.
//!
//! # Before a transport is attached
//!
//! Nothing reaches the network until the composition root attaches a transport
//! ([`DeliveryRuntime::attach_transport`]). Until then recovery still runs, because recovery is
//! a matter of this host's own records, and every pass is skipped: nothing is claimed, so nothing
//! spends an attempt against a gateway nobody can reach.

use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use kr_client::services::ServiceSigner;
use kr_delivery::destination::{DestinationId, DestinationRecord};
use kr_delivery::producer::RecipientAuthority;

use super::client::GatewayClient;
use super::credentials::HeldCredentials;
use super::external::WebhookSender;
use super::sender::GatewaySenders;
use super::status::GatewayStatus;
use super::transport::DeliveryTransports;
use super::{Clock, DeliveryModule, SystemClock};

/// How often the runtime works.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cadence {
    /// How often the outbox is driven.
    pub pass: Duration,
    /// How often credentials are renewed ahead of need and unknown outcomes are asked about.
    pub questions: Duration,
}

impl Cadence {
    /// A pass every second, because a notification that waits for the next pass waits that long,
    /// and questions every five minutes.
    pub const DEFAULT: Self = Self {
        pass: Duration::from_secs(1),
        questions: Duration::from_secs(5 * 60),
    };
}

/// What a pass reaches the network through, built once a transport is attached.
#[derive(Debug)]
struct Adapters {
    sender: GatewayClient,
    status: GatewayStatus,
    external: WebhookSender,
}

/// The loop that drives one environment's delivery.
#[derive(Debug)]
pub struct DeliveryRuntime {
    module: Arc<DeliveryModule>,
    credentials: Arc<HeldCredentials>,
    authority: Arc<dyn RecipientAuthority + Send + Sync>,
    signer: Arc<dyn ServiceSigner>,
    adapters: OnceLock<Adapters>,
    cadence: Cadence,
    runtime: tokio::runtime::Handle,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl DeliveryRuntime {
    /// Builds the runtime for one delivery module. Nothing runs until [`Self::start`].
    ///
    /// `authority` answers what an external destination's grant allows, `signer` proves this
    /// host's renewals, and `runtime` is the daemon's own reactor, which every exchange is driven
    /// by.
    #[must_use]
    pub fn new(
        module: Arc<DeliveryModule>,
        credentials: Arc<HeldCredentials>,
        authority: Arc<dyn RecipientAuthority + Send + Sync>,
        signer: Arc<dyn ServiceSigner>,
        cadence: Cadence,
        runtime: tokio::runtime::Handle,
    ) -> Arc<Self> {
        Arc::new(Self {
            module,
            credentials,
            authority,
            signer,
            adapters: OnceLock::new(),
            cadence,
            runtime,
            task: Mutex::new(None),
        })
    }

    /// The credentials this runtime delivers under.
    #[must_use]
    pub const fn credentials(&self) -> &Arc<HeldCredentials> {
        &self.credentials
    }

    /// Returns true once a transport has been attached.
    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.adapters.get().is_some()
    }

    /// Attaches the transport every delivery exchange goes through.
    ///
    /// Once: the transport is the composition root's decision, made at startup, and a second one
    /// would put two sets of rules on one host's exchanges. Returns false when one was already
    /// attached.
    pub fn attach_transport(&self, transports: Arc<dyn DeliveryTransports>) -> bool {
        let attached = self
            .adapters
            .set(Adapters {
                sender: GatewayClient::new(Arc::clone(&transports), self.runtime.clone()),
                status: GatewayStatus::new(Arc::clone(&transports), self.runtime.clone()),
                external: WebhookSender::new(Arc::clone(&transports), self.runtime.clone()),
            })
            .is_ok();
        if attached {
            self.credentials
                .attach_renewal(Arc::new(GatewaySenders::new(
                    transports,
                    Arc::clone(&self.signer),
                    self.runtime.clone(),
                )));
        }
        attached
    }

    /// Runs the recovery pass, then starts the loop.
    ///
    /// Recovery is awaited, so a daemon that has started has already put what its predecessor
    /// left unfinished in order. A recovery that failed is reported and does not stop the daemon:
    /// the journal it could not write is the one every later pass reads, and each of those says
    /// so again.
    pub async fn start(self: &Arc<Self>) {
        let recovering = Arc::clone(self);
        let recovered = tokio::task::spawn_blocking(move || recovering.recover()).await;
        match recovered {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                eprintln!("kr-controller: delivery recovery did not finish: {error}");
            }
            Err(_) => eprintln!("kr-controller: delivery recovery stopped before it finished"),
        }
        let weak = Arc::downgrade(self);
        let task = self.runtime.spawn(drive(weak, self.cadence));
        if let Ok(mut held) = self.task.lock()
            && let Some(previous) = held.replace(task)
        {
            previous.abort();
        }
    }

    /// Finishes what a stopped host left unfinished.
    fn recover(&self) -> crate::error::Result<usize> {
        let destinations = self
            .module
            .with(|producer| producer.journal().destinations().map_err(storage))?;
        let authorised: Vec<DestinationId> = destinations
            .iter()
            .filter(|record| self.still_authorised(record))
            .map(|record| record.id.clone())
            .collect();
        self.module.reconcile(
            &destinations,
            self.authority.as_ref(),
            &|destination_id| authorised.contains(destination_id),
            SystemClock.now_ms(),
        )
    }

    /// Whether queued work for one destination may still be sent after a restart.
    ///
    /// A destination still configured and enabled, with a rule, and for an external destination a
    /// grant that is still in force. A push destination's credential is not asked about: it is
    /// renewed or handed over afterwards, and a restart is not a revocation.
    fn still_authorised(&self, record: &DestinationRecord) -> bool {
        let Ok(rule) = record.require_rule() else {
            return false;
        };
        record.enabled && (record.as_push().is_some() || self.authority.scope_for(rule).is_some())
    }

    /// Runs one pass, and returns whether there was a transport to run it with.
    fn pass(&self, ask: bool) -> bool {
        let Some(adapters) = self.adapters.get() else {
            return false;
        };
        if let Err(error) = self.module.run_due(
            &adapters.sender,
            &adapters.status,
            self.credentials.as_ref(),
            &adapters.external,
            self.authority.as_ref(),
            &SystemClock,
        ) {
            eprintln!("kr-controller: a delivery pass did not finish: {error}");
        }
        if ask {
            let _ = self.credentials.renew_due(SystemClock.now_ms());
            if let Err(error) = self.module.resolve_unknown(
                &adapters.status,
                self.credentials.as_ref(),
                &SystemClock,
            ) {
                eprintln!("kr-controller: unknown delivery outcomes were not asked about: {error}");
            }
        }
        true
    }
}

impl Drop for DeliveryRuntime {
    fn drop(&mut self) {
        if let Ok(mut held) = self.task.lock()
            && let Some(task) = held.take()
        {
            task.abort();
        }
    }
}

/// The loop: a pass on every tick, the questions on the slower one, until the runtime goes.
async fn drive(runtime: Weak<DeliveryRuntime>, cadence: Cadence) {
    let mut ticker = tokio::time::interval(cadence.pass);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut asked_at: Option<Instant> = None;
    loop {
        ticker.tick().await;
        let Some(runtime) = runtime.upgrade() else {
            return;
        };
        let ask = asked_at.is_none_or(|at| at.elapsed() >= cadence.questions);
        let ran = tokio::task::spawn_blocking(move || runtime.pass(ask))
            .await
            .unwrap_or(false);
        if ask && ran {
            asked_at = Some(Instant::now());
        }
    }
}

fn storage(error: kr_delivery::DeliveryError) -> crate::error::ControllerError {
    crate::error::ControllerError::Storage {
        operation: "read the configured delivery destinations",
        detail: error.to_string(),
    }
}
