//! The loops that drive delivery for one environment.
//!
//! [`DeliveryRuntime`] is started from the controller's start path and runs for as long as the
//! daemon does. It does three things:
//!
//! 1. **Recovery first**: attempts that were on the wire when the host stopped become outcomes
//!    nobody knows, queued work whose authority has ended is taken back, and every event taken and
//!    never produced from is finished, page after page. That is [`DeliveryModule::reconcile`].
//!    Nothing is delivered until it has succeeded: a recovery that failed is tried again before
//!    every pass until it does.
//! 2. **A pass on every tick** of [`Cadence::pass`]: the due outbox is claimed and sent, which is
//!    [`DeliveryModule::run_due`].
//! 3. **Questions on their own loop**, every [`Cadence::questions`]: credentials inside their
//!    renewal window are renewed ahead of need, and a bounded batch of the outcomes nobody knows
//!    is asked about, within a time budget ([`HeldCredentials::renew_due`] and
//!    [`DeliveryModule::resolve_unknown`]). A slow answer must not hold a notification back, so
//!    these questions never run on the loop that delivers.
//!
//! The gateway counts status questions against an hourly allowance whichever loop asks them. Each
//! loop asks through a [`GatewayStatus`] of its own with a fixed share of that allowance
//! ([`Cadence::receipts`] and [`Cadence::unknown`]), and the shares together stay under it. A loop
//! that has spent its share waits for it to refill; it never takes the other loop's, so a steady
//! run of either kind of question cannot stop the other kind being asked.
//!
//! A pass blocks: it opens connections and waits for gateways, and the journal is behind a
//! synchronous lock. So every pass runs on a blocking thread and its loop waits for it, which also
//! means two passes never overlap.
//!
//! # Before a transport is attached
//!
//! Nothing reaches the network until the composition root attaches a transport
//! ([`DeliveryRuntime::attach_transport`]). Until then recovery still runs, because recovery is
//! a matter of this host's own records, and every pass and every question is skipped: nothing is
//! claimed, so nothing spends an attempt against a gateway nobody can reach.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use kr_client::services::ServiceSigner;
use kr_delivery::destination::{DestinationId, DestinationRecord};
use kr_delivery::producer::RecipientAuthority;

use super::client::GatewayClient;
use super::credentials::HeldCredentials;
use super::external::ExternalSenders;
use super::mail::MailSubmission;
use super::sender::GatewaySenders;
use super::status::{GatewayStatus, StatusAllowance};
use super::transport::DeliveryTransports;
use super::{Clock, DeliveryModule, SystemClock};

/// How often the runtime works, and how often each loop may ask a gateway what became of a
/// notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cadence {
    /// How often the outbox is driven.
    pub pass: Duration,
    /// How often credentials are renewed ahead of need and unknown outcomes are asked about.
    pub questions: Duration,
    /// The pass's share of the status allowance, for notifications the gateway is retrying.
    pub receipts: StatusAllowance,
    /// The sweep's share of the status allowance, for outcomes nobody knows.
    pub unknown: StatusAllowance,
}

impl Cadence {
    /// A pass every second, because a notification that waits for the next pass waits that long,
    /// questions every five minutes, and the two shares of the gateway's status allowance.
    pub const DEFAULT: Self = Self {
        pass: Duration::from_secs(1),
        questions: Duration::from_secs(5 * 60),
        receipts: StatusAllowance::RECEIPTS,
        unknown: StatusAllowance::UNKNOWN,
    };
}

/// The most unknown outcomes one sweep considers.
///
/// A record the sweep may no longer ask about takes no question, so a sweep considers more records
/// than its share's burst; the share decides how many it asks.
pub const QUESTIONS_PER_SWEEP: usize = 60;

/// The longest one sweep of questions may take.
pub const QUESTION_BUDGET: Duration = Duration::from_secs(30);

/// What the loops reach the network through, built once a transport is attached.
#[derive(Debug)]
struct Adapters {
    sender: GatewayClient,
    /// The pass's status questions, within its share.
    receipts: GatewayStatus,
    /// The sweep's status questions, within its share.
    unknown: GatewayStatus,
    /// Every external destination's adapter: webhooks, the chat services and mail submission.
    external: ExternalSenders,
}

/// The loop that drives one environment's delivery.
#[derive(Debug)]
pub struct DeliveryRuntime {
    module: Arc<DeliveryModule>,
    credentials: Arc<HeldCredentials>,
    authority: Arc<dyn RecipientAuthority + Send + Sync>,
    signer: Arc<dyn ServiceSigner>,
    adapters: OnceLock<Adapters>,
    recovered: AtomicBool,
    cadence: Cadence,
    runtime: tokio::runtime::Handle,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
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
            recovered: AtomicBool::new(false),
            cadence,
            runtime,
            tasks: Mutex::new(Vec::new()),
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
                receipts: GatewayStatus::new(
                    Arc::clone(&transports),
                    self.runtime.clone(),
                    self.cadence.receipts,
                ),
                unknown: GatewayStatus::new(
                    Arc::clone(&transports),
                    self.runtime.clone(),
                    self.cadence.unknown,
                ),
                external: ExternalSenders::new(
                    Arc::clone(&transports),
                    self.runtime.clone(),
                    MailSubmission::verified(),
                ),
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

    /// Returns true once recovery has succeeded.
    #[must_use]
    pub fn is_recovered(&self) -> bool {
        self.recovered.load(Ordering::Acquire)
    }

    /// Runs recovery, then starts the loops.
    ///
    /// The first recovery is awaited, so a daemon that has started has put what its predecessor
    /// left unfinished in order, or has said why it could not. One that failed is reported and does
    /// not stop the daemon: the pass loop tries it again before each pass, and delivers nothing
    /// until it has succeeded.
    pub async fn start(self: &Arc<Self>) {
        let _ = self.recover_now().await;
        let passes = self
            .runtime
            .spawn(drive_passes(Arc::downgrade(self), self.cadence));
        let questions = self
            .runtime
            .spawn(drive_questions(Arc::downgrade(self), self.cadence));
        if let Ok(mut held) = self.tasks.lock() {
            for previous in held.drain(..) {
                previous.abort();
            }
            held.extend([passes, questions]);
        }
    }

    /// Runs recovery on a blocking thread, and returns whether it succeeded.
    async fn recover_now(self: &Arc<Self>) -> bool {
        let recovering = Arc::clone(self);
        match tokio::task::spawn_blocking(move || recovering.recover()).await {
            Ok(Ok(_)) => {
                self.recovered.store(true, Ordering::Release);
                true
            }
            Ok(Err(error)) => {
                eprintln!("kr-controller: delivery recovery did not finish: {error}");
                false
            }
            Err(_) => {
                eprintln!("kr-controller: delivery recovery stopped before it finished");
                false
            }
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

    /// Runs one delivery pass, when there is a transport to run it with.
    fn pass(&self) {
        let Some(adapters) = self.adapters.get() else {
            return;
        };
        if let Err(error) = self.module.run_due(
            &adapters.sender,
            &adapters.receipts,
            self.credentials.as_ref(),
            &adapters.external,
            self.authority.as_ref(),
            &SystemClock,
        ) {
            eprintln!("kr-controller: a delivery pass did not finish: {error}");
        }
    }

    /// Runs one sweep of questions, and returns whether there was a transport to run it with.
    fn ask(&self) -> bool {
        let Some(adapters) = self.adapters.get() else {
            return false;
        };
        let _ = self.credentials.renew_due(SystemClock.now_ms());
        if let Err(error) = self.module.resolve_unknown(
            &adapters.unknown,
            self.credentials.as_ref(),
            &SystemClock,
            QUESTIONS_PER_SWEEP,
            QUESTION_BUDGET,
        ) {
            eprintln!("kr-controller: unknown delivery outcomes were not asked about: {error}");
        }
        true
    }
}

impl Drop for DeliveryRuntime {
    fn drop(&mut self) {
        if let Ok(mut held) = self.tasks.lock() {
            for task in held.drain(..) {
                task.abort();
            }
        }
    }
}

/// The delivery loop: recovery until it has succeeded, then a pass on every tick, until the
/// runtime goes.
async fn drive_passes(runtime: Weak<DeliveryRuntime>, cadence: Cadence) {
    let mut ticker = tokio::time::interval(cadence.pass);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let Some(runtime) = runtime.upgrade() else {
            return;
        };
        // Nothing is delivered before what the last daemon left is in order.
        if !runtime.is_recovered() && !runtime.recover_now().await {
            continue;
        }
        let _ = tokio::task::spawn_blocking(move || runtime.pass()).await;
    }
}

/// The question loop: a sweep whenever [`Cadence::questions`] has passed since the last one that
/// could run, checked on every pass tick, until the runtime goes.
async fn drive_questions(runtime: Weak<DeliveryRuntime>, cadence: Cadence) {
    let mut ticker = tokio::time::interval(cadence.pass);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut asked_at: Option<Instant> = None;
    loop {
        ticker.tick().await;
        let Some(runtime) = runtime.upgrade() else {
            return;
        };
        if !runtime.is_recovered() || !runtime.is_attached() {
            continue;
        }
        if asked_at.is_some_and(|at| at.elapsed() < cadence.questions) {
            continue;
        }
        let ran = tokio::task::spawn_blocking(move || runtime.ask())
            .await
            .unwrap_or(false);
        if ran {
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
