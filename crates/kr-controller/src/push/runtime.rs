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
//! 2. **A pass on every tick** of [`Cadence::pass`]: what the environment's attention store has
//!    announced is taken, which is [`DeliveryRuntime::attach_attention`]'s feed, whatever is taken
//!    and not yet produced from is produced, and then the due outbox is claimed and sent, which is
//!    [`DeliveryModule::run_due`].
//! 3. **Questions on their own loop**, every [`Cadence::questions`]: revocations owed to a gateway
//!    for authorisations of devices since unpaired are asked for, credentials inside their
//!    renewal window are renewed ahead of need, and a bounded batch of the outcomes nobody knows
//!    is asked about, within a time budget ([`DeliveryModule::settle_revocations`],
//!    [`HeldCredentials::renew_due`] and [`DeliveryModule::resolve_unknown`]). A slow answer must
//!    not hold a notification back, so these questions never run on the loop that delivers.
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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use kr_client::services::ServiceSigner;
use kr_delivery::destination::{DestinationId, DestinationRecord};
use kr_delivery::producer::RecipientAuthority;
use kr_delivery::push::DeliveryStatus;

use super::client::GatewayClient;
use super::credentials::HeldCredentials;
use super::external::ExternalSenders;
use super::forget::{GatewayForget, PreparedForget};
use super::mail::MailSubmission;
use super::sender::GatewaySenders;
use super::status::{GatewayStatus, StatusAllowance, StatusBudget};
use super::transport::DeliveryTransports;
use super::{Clock, DeliveryModule, SystemClock};

/// The scope the attention store's announcements are taken under: one store, so one cursor.
pub const ATTENTION_SCOPE: &str = "environment";

/// The scope the host's pairing outbox is taken under: a store of its own, so a cursor of its own.
pub const PAIRING_SCOPE: &str = "pairings";

/// The completed pairings one pass reads from the outbox.
const PAIRINGS_PER_PASS: usize = 64;

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

/// How many times an hour one paired device may have a credential it hands over confirmed with
/// the gateway: a burst of three, then six an hour.
pub const CONFIRMATIONS_PER_DEVICE: StatusAllowance = StatusAllowance {
    burst: 3,
    per_hour: 6,
};

/// How many times an hour one paired device may have a credential confirmed that only changes its
/// choice of previews: a burst of three, then six an hour.
///
/// Every change of the choice reaches the host as a registration with a new bearer, since the
/// device asks the gateway to issue first, and every bearer is confirmed. The changes are counted
/// apart from [`CONFIRMATIONS_PER_DEVICE`], so that a person who changes the choice does not spend
/// what the device's next token refresh needs. The host-wide allowance for the nonce
/// ([`CONFIRMATIONS_PER_HOST`]) is shared by both.
pub const PREVIEW_CHANGES_PER_DEVICE: StatusAllowance = StatusAllowance {
    burst: 3,
    per_hour: 6,
};

/// What a registration is, for the allowance of the device that makes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Registering {
    /// Every registration that is not a change of the choice of previews: a first registration, a
    /// token refresh, a new authorisation, a destination that was out of service.
    NewCredential,
    /// A credential for the authorisation and installation the destination in service already
    /// names, with the other choice of previews.
    PreviewsChoice,
}

impl Registering {
    fn allowance(self) -> StatusAllowance {
        match self {
            Self::NewCredential => CONFIRMATIONS_PER_DEVICE,
            Self::PreviewsChoice => PREVIEW_CHANGES_PER_DEVICE,
        }
    }

    fn refusal(self) -> &'static str {
        match self {
            Self::NewCredential => "this device has registered too often; try again later",
            Self::PreviewsChoice => {
                "this device has changed its choice of previews too often; try again later"
            }
        }
    }
}

/// How many nonces for a renewal this host asks the gateway for, to confirm credentials, whichever
/// devices hand them over: a burst of six, then six an hour.
///
/// The gateway counts this host's renewals and revocations together, sixty requests an hour, and
/// every renewal and every revocation takes two. A registration's nonce comes out of the same
/// count, so what registrations may spend is a share of it that leaves most to the work the host
/// owes: at most twelve nonces in any hour, and eighteen when the daemon starts again inside the
/// hour. A registration that replaces an authorisation also owes a revocation of the old one, two
/// requests more, which is the host's own work and outside this share.
pub const CONFIRMATIONS_PER_HOST: StatusAllowance = StatusAllowance {
    burst: 6,
    per_hour: 6,
};

/// How many renewal and revocation requests the gateway takes from one host key in an hour.
const GATEWAY_RENEWAL_LIMIT: u64 = 60;

const _: () = assert!(
    CONFIRMATIONS_PER_HOST.most_in_an_hour() + CONFIRMATIONS_PER_HOST.burst
        <= GATEWAY_RENEWAL_LIMIT / 2
);

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
    /// The transport as it was attached, which reaches any origin. Revocations, the mailbox placer
    /// and the external senders go through it; every exchange under a bearer goes through the
    /// gate over it ([`super::gateways::GatedTransports`]).
    transports: Arc<dyn DeliveryTransports>,
    sender: GatewayClient,
    /// Renewals and revocations, proven with this host's key.
    senders: Arc<GatewaySenders>,
    /// The pass's status questions, within its share.
    receipts: GatewayStatus,
    /// The sweep's status questions, within its share.
    unknown: GatewayStatus,
    /// A person's request to delete what the gateway holds for a notification.
    forgetter: GatewayForget,
    /// Every external destination's adapter: webhooks, the chat services and mail submission.
    external: ExternalSenders,
}

/// The time the loop's passes read: the machine's, unless a test holds it still.
///
/// A held time is what makes a figure that depends on how long a burst took, such as how many
/// notifications an allowance lets through, reproducible however slow the machine is: the
/// notification allowance refills by the time held here. The steady reading, on which the status
/// questions and the nonce allowance are counted, is the machine's own and a test never holds it.
#[derive(Debug, Default)]
struct PassClock {
    /// The held time, or nought for the machine's own.
    held_ms: AtomicU64,
}

impl Clock for PassClock {
    fn now_ms(&self) -> u64 {
        match self.held_ms.load(Ordering::SeqCst) {
            0 => SystemClock.now_ms(),
            held => held,
        }
    }

    fn steady_ms(&self) -> u64 {
        SystemClock.steady_ms()
    }
}

/// The loop that drives one environment's delivery.
#[derive(Debug)]
pub struct DeliveryRuntime {
    module: Arc<DeliveryModule>,
    credentials: Arc<HeldCredentials>,
    authority: Arc<dyn RecipientAuthority + Send + Sync>,
    signer: Arc<dyn ServiceSigner>,
    adapters: OnceLock<Adapters>,
    attention: OnceLock<Arc<crate::attention::AttentionModule>>,
    /// The host's pairing outbox, which every pass takes the completed pairings of.
    pairings: OnceLock<crate::service::net::invitations::InvitationRows>,
    /// The mailbox service this host places the objects of its previews in, when its configuration
    /// document selects one.
    mailbox: OnceLock<kr_protocol::service::GatewayOrigin>,
    recovered: AtomicBool,
    /// Woken when recovery succeeds and when a transport is attached: the two things the question
    /// loop waits for before its first sweep.
    ready: Arc<tokio::sync::Notify>,
    /// What each paired device may still ask the gateway about a credential it hands over, for
    /// each kind of registration.
    confirmations:
        Mutex<std::collections::BTreeMap<(kr_protocol::ids::DeviceId, Registering), StatusBudget>>,
    /// What all devices together may still spend of the gateway's allowance for renewing and
    /// revoking, on nonces that confirm a credential.
    nonces: StatusBudget,
    /// One sweep of owed revocations at a time: a debt two sweeps ask about costs four requests.
    sweeping: Mutex<()>,
    /// Whether a sweep was asked for while another was running, which then goes round again.
    sweep_wanted: AtomicBool,
    /// How many sweeps of questions have run to their end.
    questions_asked: AtomicU64,
    cadence: Cadence,
    runtime: tokio::runtime::Handle,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// The time the passes read.
    pass_clock: PassClock,
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
            attention: OnceLock::new(),
            pairings: OnceLock::new(),
            mailbox: OnceLock::new(),
            recovered: AtomicBool::new(false),
            ready: Arc::new(tokio::sync::Notify::new()),
            confirmations: Mutex::new(std::collections::BTreeMap::new()),
            nonces: StatusBudget::new(CONFIRMATIONS_PER_HOST),
            sweeping: Mutex::new(()),
            sweep_wanted: AtomicBool::new(false),
            questions_asked: AtomicU64::new(0),
            cadence,
            runtime,
            tasks: Mutex::new(Vec::new()),
            pass_clock: PassClock::default(),
        })
    }

    /// How many sweeps of questions have run to their end: revocations owed, credentials renewed
    /// ahead of need and unknown outcomes asked about. The first runs soon after the daemon has
    /// recovered and been given its transport, and the next one `Cadence::questions` later, so a
    /// test that scripts the gateway's answers to renewals starts when the first is over. For this
    /// host's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn questions_asked(&self) -> u64 {
        self.questions_asked.load(Ordering::SeqCst)
    }

    /// Holds the time the passes read at `at_ms`, so that everything the loop admits from now on
    /// is admitted at that moment. For this host's own tests.
    #[cfg(feature = "testing")]
    pub fn hold_time_at(&self, at_ms: u64) {
        self.pass_clock.held_ms.store(at_ms, Ordering::SeqCst);
    }

    /// The credentials this runtime delivers under.
    #[must_use]
    pub const fn credentials(&self) -> &Arc<HeldCredentials> {
        &self.credentials
    }

    /// What a delivery rule's grant lets its destination be told, or none when the grant does not
    /// stand: it is not found, has not been redeemed, has run out, was revoked, or belongs to a
    /// device that is no longer paired.
    #[must_use]
    pub fn recipient_scope(
        &self,
        rule: &kr_delivery::destination::DeliveryRule,
    ) -> Option<kr_delivery::producer::RecipientScope> {
        self.authority.scope_for(rule)
    }

    /// Returns true once a transport has been attached.
    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.adapters.get().is_some()
    }

    /// The transport as it was attached, once one is, before the gate that every exchange under a
    /// bearer goes through. It is what revocations, the mailbox placer and the external senders
    /// use.
    #[must_use]
    pub fn transports(&self) -> Option<&Arc<dyn DeliveryTransports>> {
        self.adapters.get().map(|adapters| &adapters.transports)
    }

    /// The senders every external destination is sent through (webhooks, the chat services and
    /// mail), once a transport has been attached. They are the ones a pass uses.
    #[must_use]
    pub fn external_senders(&self) -> Option<&ExternalSenders> {
        self.adapters.get().map(|adapters| &adapters.external)
    }

    /// Names the mailbox service this host places the encrypted objects of its previews in.
    ///
    /// Once, and before the transport is attached, which is what builds the placer that reaches
    /// it: the service is the composition root's decision, made at startup from the configuration
    /// document. Returns false when one was already named or the transport is attached.
    pub fn select_mailbox(&self, origin: kr_protocol::service::GatewayOrigin) -> bool {
        self.adapters.get().is_none() && self.mailbox.set(origin).is_ok()
    }

    /// Attaches the transport the delivery service reaches the network through, which every
    /// exchange under a bearer goes through behind the gate of the gateways the host allows.
    ///
    /// Once: the transport is the composition root's decision, made at startup, and a second one
    /// would put two sets of rules on one host's exchanges. Returns false when one was already
    /// attached.
    pub fn attach_transport(&self, transports: Arc<dyn DeliveryTransports>) -> bool {
        // Every exchange under a bearer goes through the gateways the host allows: a post, a
        // status question, a person's request to forget, a renewal and the confirmation of a
        // registration. The gate asks the set again when each request is put, so one put after a
        // gateway was taken out of the list never leaves the host. A revocation is the one
        // exchange that does not: it carries no bearer, and it is how that gateway is told to end
        // what it issued.
        let gated: Arc<dyn DeliveryTransports> = match self.credentials.gateways() {
            Some(gateways) => Arc::new(super::gateways::GatedTransports::new(
                Arc::clone(&transports),
                gateways,
            )),
            None => Arc::clone(&transports),
        };
        let senders = Arc::new(
            GatewaySenders::new(
                Arc::clone(&gated),
                Arc::clone(&self.signer),
                self.runtime.clone(),
            )
            .revoking_through(Arc::clone(&transports)),
        );
        // The placer is attached before the adapters are published: a pass starts to present as
        // soon as they are, and a push that went out before the placer was there would go without
        // the detail it refers to and with no reason in its record.
        if self.adapters.get().is_none()
            && let Some(origin) = self.mailbox.get()
        {
            self.module
                .attach_placer(Arc::new(super::mailbox::MailboxPlacer::new(
                    origin.clone(),
                    Arc::clone(&transports),
                    Arc::clone(&self.signer),
                    self.runtime.clone(),
                )));
        }
        let attached = self
            .adapters
            .set(Adapters {
                transports: Arc::clone(&transports),
                sender: GatewayClient::new(Arc::clone(&gated), self.runtime.clone()),
                senders: Arc::clone(&senders),
                receipts: GatewayStatus::new(
                    Arc::clone(&gated),
                    self.runtime.clone(),
                    self.cadence.receipts,
                ),
                unknown: GatewayStatus::new(
                    Arc::clone(&gated),
                    self.runtime.clone(),
                    self.cadence.unknown,
                ),
                forgetter: GatewayForget::new(Arc::clone(&gated), self.runtime.clone()),
                external: ExternalSenders::new(
                    Arc::clone(&transports),
                    self.runtime.clone(),
                    MailSubmission::verified(),
                ),
            })
            .is_ok();
        if attached {
            self.credentials.attach_renewal(senders);
            self.ready.notify_one();
        }
        attached
    }

    /// Readies the request that asks the gateway that gave a credential its authorisation to
    /// delete what it still holds for one notification this host gave it.
    ///
    /// It is a person's request, so it takes none of the passes' shares and is not stopped by
    /// privacy mode. Nothing is sent until [`PreparedForget::send`], which blocks on the daemon's
    /// reactor, so a caller runs it on a blocking thread.
    ///
    /// # Errors
    ///
    /// Returns why no request can be put: no transport is attached or reaches the gateway, or this
    /// host holds no credential for the authorisation, such as a device that was unpaired since.
    /// Nothing was sent.
    pub fn prepare_forget(
        &self,
        sender_record_id: kr_protocol::ids::PushSenderRecordId,
        notification_id: kr_protocol::ids::NotificationId,
    ) -> Result<PreparedForget, String> {
        let Some(adapters) = self.adapters.get() else {
            return Err("this host has no transport to the gateway yet".to_owned());
        };
        let Some(credential) = self.credentials.held(sender_record_id) else {
            return Err("this host holds no credential for the device's gateway".to_owned());
        };
        adapters.forgetter.prepare(credential, notification_id)
    }

    /// Hands the runtime the environment's attention store, which every pass takes the
    /// announcements of.
    ///
    /// Once, like the transport: the store is the composition root's decision. Returns false when
    /// one was already attached.
    pub fn attach_attention(&self, attention: Arc<crate::attention::AttentionModule>) -> bool {
        self.attention.set(attention).is_ok()
    }

    /// Hands the runtime the host's pairing outbox, whose completed pairings every pass takes and
    /// tells the owner's devices of.
    ///
    /// Once, like the attention store. Returns false when one was already attached.
    pub fn attach_pairings(&self, rows: crate::service::net::invitations::InvitationRows) -> bool {
        self.pairings.set(rows).is_ok()
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
                self.ready.notify_one();
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
    /// A destination still configured and enabled, with a rule, and a grant that is still in force
    /// for the recipient. A push destination's credential is not asked about: it is renewed or
    /// handed over afterwards, and a restart is not a revocation.
    fn still_authorised(&self, record: &DestinationRecord) -> bool {
        let Ok(rule) = record.require_rule() else {
            return false;
        };
        record.enabled
            && if record.as_push().is_some() {
                self.authority.device_scope(record).is_some()
            } else {
                self.authority.scope_for(rule).is_some()
            }
    }

    /// Takes what the attention store has announced, and produces from what is taken and not yet
    /// produced from.
    ///
    /// The order is the producer's: take, commit the events and the cursor in the journal, settle
    /// with the store. It is made on every pass, with or without a transport: what is taken is
    /// this host's own record, and a notification waits in the outbox for the transport the same
    /// as one that was produced before it was attached. A take the journal and the published
    /// privacy state do not agree on takes nothing, and the store offers the announcements again.
    fn feed(&self) {
        let Some(attention) = self.attention.get() else {
            return;
        };
        let published = self.module.privacy_state().now();
        let view = kr_delivery::producer::PrivacyView {
            generation: published.generation.get(),
            private: published.private,
        };
        let now_ms = self.pass_clock.now_ms();
        let taken = attention.take_for_delivery(|store, offer| {
            self.module.with(|producer| {
                producer
                    .take_from_attention(
                        store,
                        offer,
                        self.authority.as_ref(),
                        ATTENTION_SCOPE,
                        view,
                        now_ms,
                    )
                    .map_err(storage)
            })
        });
        match taken {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                eprintln!("kr-controller: attention announcements were not taken: {error}");
            }
            Err(refusal) => {
                eprintln!("kr-controller: the attention store could not be taken from: {refusal}");
            }
        }
        self.take_pairings(view, now_ms);
        if let Err(error) = self.module.finish_pending(self.authority.as_ref(), now_ms) {
            eprintln!("kr-controller: taken announcements were not produced from: {error}");
        }
    }

    /// Takes the completed pairings the outbox holds past this journal's cursor into it.
    ///
    /// The outbox keeps every row, so the cursor is the one this journal holds under its own
    /// consumer: a row is read again after a stop until the journal has committed it with its
    /// cursor, and the event key absorbs a repeat.
    fn take_pairings(&self, view: kr_delivery::producer::PrivacyView, now_ms: u64) {
        let Some(rows) = self.pairings.get() else {
            return;
        };
        let consumer = kr_delivery::journal::EventSource::Attention.consumer(PAIRING_SCOPE);
        let cursor = match self.module.with(|producer| {
            producer
                .journal()
                .consumer_cursor(&consumer)
                .map_err(storage)
        }) {
            Ok(held) => held.map_or(0, |held| held.cursor),
            Err(error) => {
                eprintln!("kr-controller: the pairing cursor could not be read: {error}");
                return;
            }
        };
        let events = match rows.events_after(
            Some(kr_protocol::ids::PairingEventSequence::new(cursor)),
            PAIRINGS_PER_PASS,
        ) {
            Ok(events) if events.is_empty() => return,
            Ok(events) => events,
            Err(error) => {
                eprintln!("kr-controller: completed pairings could not be read: {error}");
                return;
            }
        };
        let pairings: Vec<kr_delivery::producer::PairingEvent> = events
            .iter()
            .map(|event| kr_delivery::producer::PairingEvent {
                sequence: event.sequence.get(),
                invitation_id: event.invitation_id,
                device_id: event.device_id,
                device_name: event.device_name.as_str().to_owned(),
                committed_at_ms: event.committed_at_ms.get(),
            })
            .collect();
        if let Err(error) = self.module.with(|producer| {
            producer
                .take_from_pairings(
                    &pairings,
                    self.authority.as_ref(),
                    PAIRING_SCOPE,
                    view,
                    now_ms,
                )
                .map_err(storage)
        }) {
            eprintln!("kr-controller: completed pairings were not taken: {error}");
        }
    }

    /// Runs one delivery pass, when there is a transport to run it with.
    fn pass(&self) {
        self.feed();
        let Some(adapters) = self.adapters.get() else {
            return;
        };
        if let Err(error) = self.module.run_due(
            &adapters.sender,
            &adapters.receipts,
            self.credentials.as_ref(),
            &adapters.external,
            self.authority.as_ref(),
            &self.pass_clock,
        ) {
            eprintln!("kr-controller: a delivery pass did not finish: {error}");
        }
    }

    /// Asks the gateways for the revocations this host owes, when there is a transport to ask
    /// through. Blocks.
    ///
    /// One sweep runs at a time. A sweep asked for while another is running leaves the asking to
    /// it, and the running one goes round again before it lets go: a debt written after it read
    /// its list is then asked about as soon as it is done, and a debt two sweeps asked about would
    /// cost four requests of the gateway's allowance for renewing and revoking.
    pub fn sweep_revocations(&self) {
        let Some(adapters) = self.adapters.get() else {
            return;
        };
        // A request is written down before the lock is tried for, and read after the lock is let
        // go of. A request that fails the lock was written before the holder lets go, so the
        // holder reads it; one that comes after finds the lock free.
        self.sweep_wanted.store(true, Ordering::SeqCst);
        loop {
            {
                let Ok(_one_sweep) = self.sweeping.try_lock() else {
                    return;
                };
                // Cleared before each round reads the list: a request that comes in meanwhile is
                // either answered by a round that reads the list after it, or seen below.
                while self.sweep_wanted.swap(false, Ordering::SeqCst) {
                    let credentials = Arc::clone(&self.credentials);
                    let forget = move |sender_record_id| match credentials.forget(sender_record_id)
                    {
                        Ok(()) => true,
                        Err(detail) => {
                            eprintln!(
                                "kr-controller: a delivery credential could not be removed from \
                                 the secret store: {detail}"
                            );
                            false
                        }
                    };
                    if let Err(error) = self.module.settle_revocations(
                        adapters.senders.as_ref(),
                        &forget,
                        &SystemClock,
                    ) {
                        eprintln!("kr-controller: owed revocations were not asked about: {error}");
                        return;
                    }
                }
            }
            if !self.sweep_wanted.load(Ordering::SeqCst) {
                return;
            }
        }
    }

    /// Asks the gateway whether it holds an authorisation a device says it was issued, and takes
    /// the bearer, before the host keeps anything of it. Blocks, so a caller on the daemon's
    /// reactor runs it on a blocking thread.
    ///
    /// Two questions, because the gateway answers each of them at any time. The first is a status
    /// question about a notification that does not exist, under the bearer the device handed
    /// over: the gateway authenticates the bearer first, so its success says the bearer belongs
    /// to an active authorisation that has not expired. The second is a renewal's opening, signed
    /// with this host's key: the gateway hands out a nonce only for an authorisation that names
    /// that key, so its success says the gateway holds the authorisation and this host is the one
    /// it names. Renewing itself is not asked, because the gateway renews only in the last week
    /// of a credential's life. Nothing is sent to the device and no notification is sent; the
    /// gateway keeps the nonce until it lapses and counts both requests.
    ///
    /// What neither question shows is that the bearer is that authorisation's, or which
    /// installation it is for: the identifier, the expiry and the revision in the credential are
    /// the device's word. A bearer for another authorisation is found at the first delivery, which
    /// the gateway refuses as aimed at another authorisation.
    ///
    /// A device may ask a few times an hour, whatever it hands over, and all devices together a few
    /// more: the questions come out of the gateway's allowances for this host, and a device that
    /// registers over and over would spend the renewals and revocations of every other. A device's
    /// changes of its choice of previews have an allowance of their own
    /// ([`PREVIEW_CHANGES_PER_DEVICE`]), so that they do not spend the one new credentials need;
    /// both are counted before the gateway is asked, and every bearer is asked about all the same.
    /// The nonce is the dearer question, so it is asked only for a bearer the first question took,
    /// and the host-wide allowance for it ([`CONFIRMATIONS_PER_HOST`]) is spent only then.
    ///
    /// # Errors
    ///
    /// Returns [`Confirmation::Refused`] for the gateway's own refusal,
    /// [`Confirmation::Limited`] when this device or this host has asked too often, and
    /// [`Confirmation::NotAsked`] when it was not asked or was not answered as the gateway answers.
    ///
    /// [`Confirmation::Refused`]: super::Confirmation::Refused
    /// [`Confirmation::Limited`]: super::Confirmation::Limited
    /// [`Confirmation::NotAsked`]: super::Confirmation::NotAsked
    pub fn confirm(
        &self,
        device_id: kr_protocol::ids::DeviceId,
        credential: &kr_protocol::push::PushDeliveryCredential,
        registering: Registering,
    ) -> Result<(), super::Confirmation> {
        use super::Confirmation::{Limited, NotAsked};

        let Some(adapters) = self.adapters.get() else {
            return Err(NotAsked(
                "this host has no transport to ask the gateway through".to_owned(),
            ));
        };
        let allowed = self
            .confirmations
            .lock()
            .map_err(|_| NotAsked("an earlier registration failed part way".to_owned()))?
            .entry((device_id, registering))
            .or_insert_with(|| StatusBudget::new(registering.allowance()))
            .take(SystemClock.steady_ms());
        if !allowed {
            return Err(Limited(registering.refusal().to_owned()));
        }
        // From the sweep's share, so a device that registers over and over cannot spend the
        // pass's, which notifications a person is waiting on depend on.
        if !adapters.unknown.reserve(SystemClock.steady_ms()) {
            return Err(Limited(
                "this host has asked the gateway too often; try again later".to_owned(),
            ));
        }
        // The bearer first, from the larger allowance, so a bearer the gateway does not take
        // costs this host's allowance for renewing and revoking nothing.
        adapters
            .unknown
            .probe(credential, kr_delivery::preview::fresh_notification_id())?;
        // Then the nonce, from the host's share of the allowance it is counted in.
        if !self.nonces.take(SystemClock.steady_ms()) {
            return Err(Limited(
                "this host has confirmed as many credentials as it allows itself for now; try \
                 again later"
                    .to_owned(),
            ));
        }
        adapters
            .senders
            .begin_renewal(&credential.gateway_origin, credential.sender_record_id)
    }

    /// Starts a sweep of owed revocations on a blocking thread and does not wait for it, so an
    /// unpairing does not wait for a gateway. What the sweep does not settle is owed still.
    pub fn sweep_revocations_soon(self: &Arc<Self>) {
        let sweeping = Arc::clone(self);
        self.runtime
            .spawn_blocking(move || sweeping.sweep_revocations());
    }

    /// Runs one sweep of questions, and returns whether there was a transport to run it with.
    fn ask(&self) -> bool {
        let Some(adapters) = self.adapters.get() else {
            return false;
        };
        self.sweep_revocations();
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
        self.questions_asked.fetch_add(1, Ordering::SeqCst);
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

/// What the question loop does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuestionStep {
    /// Wait until recovery has succeeded or a transport is attached.
    AwaitReadiness,
    /// Wait until the next sweep is due.
    SleepUntil(tokio::time::Instant),
    /// Sweep now.
    Ask,
}

/// What the question loop does next, given whether it can ask at all, when it last did, and how
/// long it leaves between sweeps. It is woken for nothing in between.
fn next_question_step(
    able: bool,
    asked_at: Option<tokio::time::Instant>,
    every: Duration,
    now: tokio::time::Instant,
) -> QuestionStep {
    if !able {
        return QuestionStep::AwaitReadiness;
    }
    match asked_at.map(|at| at + every) {
        Some(due) if due > now => QuestionStep::SleepUntil(due),
        _ => QuestionStep::Ask,
    }
}

/// The question loop: a sweep as soon as the runtime has recovered and been given a transport, and
/// the next one [`Cadence::questions`] after each, until the runtime goes.
///
/// It waits for the moment a sweep is due and for nothing else, so an idle host spends no wake on
/// it between sweeps.
async fn drive_questions(runtime: Weak<DeliveryRuntime>, cadence: Cadence) {
    let mut asked_at: Option<tokio::time::Instant> = None;
    loop {
        let Some(held) = runtime.upgrade() else {
            return;
        };
        // Taken before the checks, so a readiness that comes between them and the wait is kept.
        let readiness = Arc::clone(&held.ready);
        let ready = readiness.notified();
        tokio::pin!(ready);
        ready.as_mut().enable();
        let able = held.is_recovered() && held.is_attached();
        match next_question_step(
            able,
            asked_at,
            cadence.questions,
            tokio::time::Instant::now(),
        ) {
            QuestionStep::AwaitReadiness => {
                drop(held);
                ready.await;
            }
            QuestionStep::SleepUntil(due) => {
                drop(held);
                tokio::time::sleep_until(due).await;
            }
            QuestionStep::Ask => {
                let ran = tokio::task::spawn_blocking(move || held.ask())
                    .await
                    .unwrap_or(false);
                if ran {
                    asked_at = Some(tokio::time::Instant::now());
                } else {
                    // Nothing to ask through yet: look again after a pass, not at once.
                    tokio::time::sleep(cadence.pass).await;
                }
            }
        }
    }
}

fn storage(error: kr_delivery::DeliveryError) -> crate::error::ControllerError {
    crate::error::ControllerError::Storage {
        operation: "read the configured delivery destinations",
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use kr_client::services::{ServiceFuture, ServiceHttp, ServiceHttpAnswer};
    use kr_delivery::destination::DestinationRecord;
    use kr_delivery::producer::RecipientScope;
    use kr_delivery::push::{DeliveryStatus, PushSender};
    use kr_protocol::ids::{
        CollapseId, EnvironmentId, InstallationId, NotificationId, PushSenderRecordId,
        PushSenderRevision,
    };
    use kr_protocol::push::{
        PushAlert, PushDeliveryCredential, PushDeliveryRequest, PushPlatformHints, PushUrgency,
    };
    use kr_protocol::scalars::{Nullable, SecretBytes32, TimestampMs, Uuid};
    use kr_protocol::service::GatewayOrigin;

    use super::super::credentials::CredentialRenewal as _;
    use super::super::gateways::AllowedGateways;
    use super::super::sender::{HostSigner, SenderRevocation as _};
    use super::super::transport::DeliveryTransports;
    use super::{Cadence, DeliveryRuntime, QuestionStep, next_question_step};

    /// KR-PERF-003: an idle daemon's question loop is woken for the moment a sweep is due and for
    /// nothing in between, where it used to look at every pass. This shows the loop's decision
    /// ([`next_question_step`]). That the loop sweeps again after its wait is shown by the runtime
    /// cases of `tests/gateway_answers.rs`, which fail when the wait never ends; no case shows that
    /// it is woken for nothing in between.
    #[test]
    fn kr_perf_003_the_question_loop_waits_for_readiness_and_then_for_its_due_moment() {
        let now = tokio::time::Instant::now();
        let every = Duration::from_secs(300);

        assert_eq!(
            next_question_step(false, None, every, now),
            QuestionStep::AwaitReadiness,
            "before recovery or a transport it waits to be told"
        );
        assert_eq!(
            next_question_step(false, Some(now), every, now),
            QuestionStep::AwaitReadiness,
            "and again if it has lost either"
        );
        assert_eq!(
            next_question_step(true, None, every, now),
            QuestionStep::Ask,
            "the first sweep is made as soon as it can ask"
        );
        assert_eq!(
            next_question_step(true, Some(now), every, now + every / 2),
            QuestionStep::SleepUntil(now + every),
            "after a sweep it waits for the whole of the next period, not for a look at each pass"
        );
        assert_eq!(
            next_question_step(true, Some(now), every, now + every),
            QuestionStep::Ask,
            "and sweeps when the period is over"
        );
    }

    /// What the wiring is proved against: it counts the requests put to it and answers each one
    /// with a refusal, since only whether a request arrived matters here.
    #[derive(Debug, Default)]
    struct Counting {
        put: Mutex<usize>,
    }

    impl Counting {
        fn put(&self) -> usize {
            *self.put.lock().expect("not poisoned")
        }
    }

    impl ServiceHttp for Counting {
        fn post_json<'a>(
            &'a self,
            _url: &'a str,
            _body: &'a [u8],
            _headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            *self.put.lock().expect("not poisoned") += 1;
            Box::pin(async {
                Ok(ServiceHttpAnswer {
                    status: 503,
                    body: Vec::new(),
                })
            })
        }
    }

    /// Every origin reaches the one counting transport.
    #[derive(Debug)]
    struct Reaching(Arc<Counting>);

    impl DeliveryTransports for Reaching {
        fn to(&self, _origin: &GatewayOrigin) -> Result<Arc<dyn ServiceHttp>, String> {
            Ok(Arc::clone(&self.0) as Arc<dyn ServiceHttp>)
        }

        fn outbound(&self) -> crate::config::Outbound {
            crate::config::Outbound::Direct
        }
    }

    /// Nobody is a recipient: the wiring has no use for one.
    #[derive(Debug)]
    struct NoRecipients;

    impl kr_delivery::producer::RecipientAuthority for NoRecipients {
        fn scope_for(
            &self,
            _rule: &kr_delivery::destination::DeliveryRule,
        ) -> Option<RecipientScope> {
            None
        }

        fn device_scope(&self, _destination: &DestinationRecord) -> Option<RecipientScope> {
            None
        }
    }

    /// KR-REQ-16.04: every exchange the runtime makes under a bearer (a notification, a status
    /// question of either loop, a request to delete, a renewal) is put only to a gateway the host
    /// allows, however it came by its transport: the check is made when the request is put. A
    /// revocation is the one that still reaches a gateway that was taken out. A request prepared
    /// while the gateway was allowed and sent after it was taken out sends nothing.
    ///
    /// The adapters are the runtime's own, built by `attach_transport` over a transport that
    /// counts what it is given, so an adapter built over the raw transport fails here.
    #[test]
    fn every_exchange_under_a_bearer_is_put_only_to_a_gateway_the_host_allows() {
        const LISTED: &str = "https://push.listed.invalid";
        let reactor = tokio::runtime::Runtime::new().expect("a runtime");
        let directory = tempfile::tempdir().expect("a directory");
        let module = Arc::new(
            crate::push::DeliveryModule::open_at(
                &directory.path().join("delivery.sqlite3"),
                kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair"),
                kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair"),
                crate::push::secrets::DestinationSecrets::new(
                    Arc::new(kr_crypto::store::MemoryStore::new()),
                    EnvironmentId::new(Uuid::from_bytes([0xee; 16])),
                ),
            )
            .expect("a delivery module"),
        );
        let credentials = Arc::new(super::HeldCredentials::new());
        let gateways = Arc::new(AllowedGateways::new(
            "https://reach.invalid",
            &[LISTED.to_owned()],
        ));
        assert!(credentials.attach_gateways(Arc::clone(&gateways)));
        let runtime = DeliveryRuntime::new(
            module,
            credentials,
            Arc::new(NoRecipients),
            Arc::new(HostSigner::new(
                kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key"),
            )),
            Cadence::DEFAULT,
            reactor.handle().clone(),
        );
        let counting = Arc::new(Counting::default());
        assert!(runtime.attach_transport(Arc::new(Reaching(Arc::clone(&counting)))));
        let adapters = runtime.adapters.get().expect("the adapters are built");

        let origin = GatewayOrigin::new(LISTED).expect("an origin");
        let sender = PushSenderRecordId::new(Uuid::from_bytes([0x31; 16]));
        let notification = NotificationId::new(Uuid::from_bytes([0x41; 16]));
        let credential = PushDeliveryCredential {
            expires_at_ms: TimestampMs::new(1_700_000_000_000 + 30 * 24 * 60 * 60 * 1000),
            gateway_origin: origin.clone(),
            installation_id: InstallationId::new(Uuid::from_bytes([0x51; 16])),
            issued_at_ms: TimestampMs::new(1_700_000_000_000),
            revision: PushSenderRevision::new(1),
            secret: SecretBytes32::from_bytes([9; 32]),
            sender_record_id: sender,
        };
        let request = PushDeliveryRequest {
            collapse_id: CollapseId::new(Uuid::from_bytes([0x61; 16])),
            expires_at_ms: TimestampMs::new(1_700_000_000_000 + 60 * 60 * 1000),
            hints: PushPlatformHints {
                alert: PushAlert::ApprovalWaiting,
                urgency: PushUrgency::Attention,
            },
            notification_id: notification,
            preview: Nullable::null(),
            sender_record_id: sender,
        };

        type Exchange<'a> = Box<dyn Fn() + 'a>;
        let exchanges: Vec<(&str, Exchange<'_>)> = vec![
            (
                "a notification",
                Box::new(|| {
                    let _ = adapters.sender.send(&credential, &request);
                }),
            ),
            (
                "a status question of the pass",
                Box::new(|| {
                    let _ = adapters.receipts.status(&credential, notification);
                }),
            ),
            (
                "a status question of the sweep",
                Box::new(|| {
                    let _ = adapters.unknown.status(&credential, notification);
                }),
            ),
            (
                "a request to delete",
                Box::new(|| {
                    if let Ok(prepared) =
                        adapters.forgetter.prepare(credential.clone(), notification)
                    {
                        let _ = prepared.send();
                    }
                }),
            ),
            (
                "the confirmation of a registration",
                Box::new(|| {
                    let _ = adapters.senders.begin_renewal(&origin, sender);
                }),
            ),
            (
                "a renewal",
                Box::new(|| {
                    let _ = adapters.senders.renew(&credential);
                }),
            ),
        ];

        // The control: while the gateway is listed each one is put.
        for (what, exchange) in &exchanges {
            let before = counting.put();
            exchange();
            assert!(
                counting.put() > before,
                "{what} was put to a listed gateway"
            );
        }

        // A request prepared while the gateway was listed, and sent after it was taken out.
        let prepared = adapters
            .forgetter
            .prepare(credential.clone(), notification)
            .expect("a request is prepared for a listed gateway");
        gateways.replace(&[]);
        let before = counting.put();
        let _ = prepared.send();
        assert_eq!(
            counting.put(),
            before,
            "a prepared request was put after the removal"
        );

        // Taken out, none is put.
        for (what, exchange) in &exchanges {
            let before = counting.put();
            exchange();
            assert_eq!(
                counting.put(),
                before,
                "{what} was put to a gateway taken out"
            );
        }

        // And the revocation still is: it is how that gateway is told to end what it issued.
        let before = counting.put();
        let _ = adapters.senders.revoke(&origin, sender);
        assert!(counting.put() > before, "the revocation was not put");
    }
}
