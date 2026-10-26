//! The carrier of this host's half of the remote authority feed: the task that reads what remote
//! owners published, carries it out, tells the feed what became of it, and tells the owners it
//! trusts which keys may remove the feed.
//!
//! Section 10 divides remote revocation between a remote owner, who publishes a signed request, the
//! target host, which judges it and is the sole issuer of its ordered revisions and
//! acknowledgements, and the durable feed, which stores both and judges neither. This is the
//! host's part of it. The record of what the host has taken, issued and acknowledged is
//! [`crate::grants::AuthorityFeed`]; the judging and the carrying out are the daemon's
//! (`service::remote_revocation`); what this adds is when to ask, and what to do with what the feed
//! says.
//!
//! # When it asks
//!
//! * **When the daemon starts**, so a revocation published while the host was down is carried out
//!   before the host is rid of the connections that were waiting for it.
//! * **When a connection is established**, before anything the connection asks is answered
//!   ([`FeedRuntime::synchronised_before_serving`]). Polling alone would leave a revoked device its
//!   first requests until the next poll; section 10 asks for the synchronisation before affected
//!   remote access, so a connection waits for one that began after it was admitted, and waits at
//!   most [`GATE_WAIT`] for it. A feed that does not answer in that time leaves the connection
//!   served; the status goes stale when the pass that was held ends without an answer, as it does
//!   for an unreachable feed.
//! * **Every [`FEED_POLL_INTERVAL_MS`] after that**, while the daemon runs.
//! * **When an owner is revoked**, so the key it held stops being named as one that may remove the
//!   feed.
//! * **When the host finds an announcement in its mailbox** ([`crate::mailbox_reader`]), so a
//!   change a remote owner just published is read when the announcement is found and not at the
//!   next poll.
//!
//! # What a record becomes
//!
//! One request at a time, in the feed's order: judged from this host's own records; refused with a
//! reason the publisher reads, or written down, carried out, issued a revision and acknowledged. A
//! request is written down before it takes effect and the revision record is rebuilt from that
//! note, so a host that stops anywhere between the first step and the last finishes the same
//! request the same way and takes it once. A request that withdraws nothing, because the owner at
//! this machine already did, is refused as covered by an earlier revocation: there is no revision
//! to issue for it, and the registry is the one allocator.
//!
//! # When the feed says it removed this host
//!
//! A feed answers its own host that it was removed (`summary.removed`) after any key the host named
//! removed it. The feed then keeps nothing for the host, for good, so the host reads no revocation
//! again. That is recorded with the origin that said it, and shown by `kr doctor`, `device.list`
//! and the attention inbox. It refuses the grants whose validity rests on the feed and leaves the
//! rest, as section 10 asks: the default non-expiring owner grant is account-free. An owner who
//! changes `authority.origin` clears it at the next start.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::Duration;

use kr_client::error::ClientError;
use kr_client::services::authority::{
    AuthorityFeedClient, AuthorityFeedRecord, AuthorityFeedState, FeedAnnouncement, RejectionReason,
};
use kr_client::services::{
    HttpDeadlines, HttpService, ServiceHttp, ServiceSigner, managed_response_limits,
};
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};
use kr_protocol::ids::{AuthorityRevision, DeviceId, GrantId, RevocationRequestId};
use kr_protocol::pairing::{
    AUTHORITY_REVISION_DOMAIN, AuthorityRevisionRecord, RevocationAcknowledgement,
    RevocationCompletion, RevocationRequest,
};
use kr_protocol::scalars::{CanonicalSet, KeyId, Signature64, TimestampMs};
use kr_protocol::service::GatewayOrigin;
use kr_transport::config::ProxyUrl;
use kr_transport::reconnect::Backoff;
use tokio::task::JoinHandle;

use crate::error::{ControllerError, Result};
use crate::grants::Refusal;
use crate::grants::feed::{FEED_POLL_INTERVAL_MS, RetainedRevocation};
use crate::grants::restored::Target;
use crate::quiet::{Quiet, Timer};
use crate::service::remote_revocation::{DrainWhy, Ground, Judged, Replay, StuckDrain, Unverified};
use crate::service::{Controller, OwedWrite};

/// The deadlines the feed's exchanges are made under. A request and its answer are small.
pub const FEED_DEADLINES: HttpDeadlines = HttpDeadlines {
    connect: Duration::from_secs(5),
    read: Duration::from_secs(10),
    total: Duration::from_secs(15),
};

/// The most a connection waits for the synchronisation section 10 asks for before affected remote
/// access.
pub const GATE_WAIT: Duration = Duration::from_secs(5);

/// The most pages of a feed one pass reads, so a feed that never stops saying there is more cannot
/// hold the carrier. A pass that stops there has not read the feed through, and the next goes on at
/// the cursor.
const MOST_PAGES: usize = 32;

tokio::task_local! {
    /// Set while the host carries a request out of the feed (`Controller::apply_feed_plan`). The
    /// revocation it makes wakes whatever watches the owners this host is paired with, and the
    /// carrier is one of those; but it names the owners itself when its pass ends, and a wake it
    /// made for itself would end the wait a failed pass asked for.
    pub(crate) static CARRYING_OUT: ();
}

/// The feed's client for `origin`, signing as the host.
///
/// # Errors
///
/// Returns [`ControllerError::NotConfigured`] when the transport cannot be built, which is a fault
/// in this machine's TLS configuration rather than in the service.
pub fn managed_client(
    origin: &GatewayOrigin,
    proxy: Option<&ProxyUrl>,
    signer: Arc<dyn ServiceSigner>,
) -> Result<AuthorityFeedClient> {
    let http: Arc<dyn ServiceHttp> = Arc::new(
        HttpService::through(
            origin.clone(),
            FEED_DEADLINES,
            managed_response_limits(),
            proxy,
        )
        .map_err(|error| {
            ControllerError::NotConfigured(format!(
                "{} in this host's configuration document ({}) names a service no transport \
                     reaches: {error}",
                kr_protocol::hostinfo::configuration::AUTHORITY_ORIGIN.key,
                kr_protocol::hostinfo::configuration::FILE_NAME,
            ))
        })?,
    );
    Ok(AuthorityFeedClient::new(origin.clone(), http, signer).leaving_delays_to_the_caller())
}

/// Why a pass stopped before it had read the feed through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stopped {
    /// The feed could not be reached, or answered something this client cannot read.
    Unreachable,
    /// The feed turned a request back.
    Refused,
    /// This host could not carry a request out or read its own records. The feed is not at fault.
    Local,
}

impl Stopped {
    /// This host's own failure, said once to its log where the carrier meets it.
    fn local(error: ControllerError) -> Self {
        eprintln!(
            "kr-controller: the authority feed's carrier could not finish a request: {error}"
        );
        Self::Local
    }

    fn of(error: &ClientError, quiet: &Quiet) -> Self {
        match error {
            ClientError::Refused {
                retry_after_seconds,
                ..
            } => {
                if let Some(seconds) = retry_after_seconds {
                    quiet.owe(Duration::from_secs(*seconds));
                }
                Self::Refused
            }
            _ => Self::Unreachable,
        }
    }
}

/// What the doctor says of the carrier.
#[derive(Debug, Default)]
struct Observed {
    /// How the last pass ended, when it did not read the feed through.
    stopped: Option<Stopped>,
    /// Whether the host could not issue a revision because the feed holds a higher one than the
    /// registry has reached.
    unissued: bool,
    /// Whether the feed holds a revision above the registry's, so that this host is catching up
    /// with it and refuses every grant but the owner's at this machine until it has.
    catching_up: bool,
    /// Whether the feed shows complete a withdrawal this host cannot verify, so that this host
    /// refuses every grant but the owner's at this machine until the owner at this machine has
    /// dealt with what it names.
    unverified: bool,
    /// How many owners are paired beyond the keys the feed takes.
    unnamed_owners: usize,
    /// The devices that made a request waiting for this host's clock, which lost its continuity,
    /// and that a withdrawal this host cannot verify names: revoking one of them refuses its
    /// request.
    waiting_named: Vec<DeviceId>,
}

/// What the scan in hand owes the wait for a restored policy: the devices and grants the requests
/// it met name, until it settles the request that names them. Held in memory, and written to the
/// record of the restore before the host acts on the page that names them, so a stop, an error, an
/// abort or a removal part way through a scan keeps them ([`crate::grants::restored`]).
#[derive(Debug, Default)]
struct Owing {
    /// Each target an unsettled record names, with the sequences of the records that name it.
    unsettled: std::collections::BTreeMap<Target, std::collections::BTreeSet<u64>>,
    /// The targets each unsettled record names.
    by_record: std::collections::BTreeMap<u64, Vec<Target>>,
    /// The targets that records this scan settled named, which the reconcile takes out of the list
    /// unless an unsettled record names them too.
    settled: std::collections::BTreeSet<Target>,
}

impl Owing {
    /// A record at `sequence` names `targets`, and is not settled.
    fn add(&mut self, sequence: u64, targets: Vec<Target>) {
        for target in &targets {
            self.unsettled.entry(*target).or_default().insert(sequence);
        }
        self.by_record.insert(sequence, targets);
    }

    /// The record at `sequence` is settled: carried out, or dismissed on evidence.
    fn settle(&mut self, sequence: u64) {
        let Some(targets) = self.by_record.remove(&sequence) else {
            return;
        };
        for target in targets {
            let Some(sequences) = self.unsettled.get_mut(&target) else {
                continue;
            };
            sequences.remove(&sequence);
            if sequences.is_empty() {
                self.unsettled.remove(&target);
                self.settled.insert(target);
            }
        }
    }

    /// The targets unsettled records name, lowest feed sequence first.
    fn unsettled_in_order(&self) -> Vec<Target> {
        let mut targets: Vec<(u64, Target)> = self
            .unsettled
            .iter()
            .filter_map(|(target, sequences)| sequences.first().map(|first| (*first, *target)))
            .collect();
        targets.sort();
        targets.into_iter().map(|(_, target)| target).collect()
    }

    /// The targets only settled records named: what the reconcile takes out of the list.
    fn cleared(&self) -> Vec<Target> {
        self.settled
            .iter()
            .filter(|target| !self.unsettled.contains_key(*target))
            .copied()
            .collect()
    }
}

/// What the carrier shares with the daemon.
struct Shared {
    client: AuthorityFeedClient,
    origin: String,
    own_feed: KeyId,
    host_device_id: DeviceId,
    key: AuthorisationKeyPair,
    /// The key this host seals an announcement to a remote owner with. It is the key the host's
    /// own mailbox is addressed by: an owner knows it from the pairing.
    stored_envelope: StoredEnvelopeKeyPair,
    quiet: Quiet,
    /// How long a connection waits for a synchronisation, in milliseconds.
    gate_wait_ms: AtomicU64,
    /// How many pages of the feed one pass reads before it goes on at the cursor in the next.
    most_pages: AtomicUsize,
    /// How many times a synchronisation has been asked for, by a connection or by the carrier.
    requested: AtomicU64,
    /// The newest request count that a pass which began after the request was made has finished.
    completed: tokio::sync::watch::Sender<u64>,
    wake: tokio::sync::Notify,
    /// How many times something asked the carrier to look again now, for a suite that checks a
    /// wake was or was not made.
    #[cfg(feature = "testing")]
    wakes: AtomicU64,
    removed: AtomicBool,
    /// Whether a scan of this run has read the feed through since the last finding that the
    /// registry is behind it, and has written what it owes to the record of the restore (or had no
    /// record to write it to, which is checked in memory), without the cap keeping an entry out.
    /// Held in memory only: a start begins without it. It guards the list in the record against
    /// being one from another registry: a second restore between two runs leaves the file in place,
    /// and its list does not describe what this run's scan has yet to learn.
    read_through: AtomicBool,
    /// The cutoff of a wait: the highest sequence the first scan of this run that read the feed
    /// through while a wait stood saw, or the maximum before it. A request above it was published
    /// after the run read the feed, and is judged as today. A finding resets it.
    finding_through: AtomicU64,
    /// The highest sequence the scan in hand has seen.
    scan_highest: AtomicU64,
    /// How many findings the scan has handled ([`Controller::findings`]).
    findings_seen: AtomicU64,
    /// What the scan in hand owes.
    owing: Mutex<Owing>,
    /// Whether the cap kept an owed target out of the record, since the last finding.
    owing_full: AtomicBool,
    /// The highest sequence of the feed up to which everything is settled, where a scan starts.
    settled_through: AtomicU64,
    /// Where a scan that stopped at the page limit goes on, or 0 when none is under way.
    scan_cursor: AtomicU64,
    /// Whether a record the scan met so far is not settled yet.
    scan_unfinished: AtomicBool,
    /// Whether a record the scan met so far was put off because the host is behind its feed.
    scan_put_off: AtomicBool,
    /// What the scan met so far of withdrawals the feed shows complete and this host cannot verify.
    scan_found: Mutex<Unverified>,
    /// The first request the scan met so far whose issuer's standing this host could not decide.
    scan_undecided: Mutex<Option<Undecided>>,
    observed: Mutex<Observed>,
    controller: OnceLock<Weak<Controller>>,
    /// How many passes have finished, for whatever waits on one.
    passes: tokio::sync::watch::Sender<u64>,
}

impl Shared {
    fn observed(&self) -> std::sync::MutexGuard<'_, Observed> {
        self.observed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn owing(&self) -> std::sync::MutexGuard<'_, Owing> {
        self.owing.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The record at `sequence` is settled: what only it named is no longer owed by this scan.
    fn settle(&self, sequence: u64) {
        self.owing().settle(sequence);
    }

    /// Whether a record at `sequence` is one the host holds and does not refuse for a ground a
    /// restore can change: a wait for a restored policy stands, and the record is at or below the
    /// cutoff, so it may be a request the host carried out before the restore.
    fn holds_for_the_wait(&self, controller: &Controller, sequence: u64) -> bool {
        controller.restored_policy_waits()
            && sequence <= self.finding_through.load(Ordering::SeqCst)
    }
}

/// Restarts the scan when a finding was made since the last pass handled one: the registry was
/// found behind the feed, or put back again. What the scan settled, and its cursor, belong to a
/// registry that is gone. Says whether it did.
fn handle_findings(shared: &Shared, controller: &Controller) -> bool {
    let count = controller.findings();
    if shared.findings_seen.swap(count, Ordering::SeqCst) == count {
        return false;
    }
    shared.settled_through.store(0, Ordering::SeqCst);
    shared.scan_cursor.store(0, Ordering::SeqCst);
    shared.scan_unfinished.store(false, Ordering::SeqCst);
    shared.scan_put_off.store(false, Ordering::SeqCst);
    *shared
        .scan_found
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Unverified::default();
    *shared
        .scan_undecided
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = None;
    shared.scan_highest.store(0, Ordering::SeqCst);
    *shared.owing() = Owing::default();
    shared.owing_full.store(false, Ordering::SeqCst);
    shared.read_through.store(false, Ordering::SeqCst);
    shared.finding_through.store(u64::MAX, Ordering::SeqCst);
    true
}

/// Writes what the requests on a page name to the record of the restore, before the host acts on
/// any record of it, while a wait stands. A request above the cutoff is not written: it was
/// published after the run read the feed. A write that fails stops the pass before anything is
/// carried out.
async fn write_ahead(
    shared: &Shared,
    controller: &Controller,
    records: &[AuthorityFeedRecord],
) -> std::result::Result<(), Stopped> {
    if !controller.restored_policy_waits() {
        return Ok(());
    }
    let cutoff = shared.finding_through.load(Ordering::SeqCst);
    let ahead = {
        let mut owing = shared.owing();
        for record in records
            .iter()
            .filter(|record| record.sequence.get() <= cutoff)
        {
            let named = controller.named_targets_of(&record.request);
            if !named.is_empty() {
                owing.add(record.sequence.get(), named);
            }
        }
        owing.unsettled_in_order()
    };
    if ahead.is_empty() {
        return Ok(());
    }
    if let OwedWrite::Kept { full: true } = controller
        .keep_what_is_owed(&shared.origin, &ahead, &[])
        .await
        .map_err(Stopped::local)?
    {
        shared.owing_full.store(true, Ordering::SeqCst);
    }
    Ok(())
}

/// What a scan that read the feed through does with what it owes: the record's list gains every
/// target an unsettled record names and loses every target only settled records named, and the
/// scan's own memory of it ends once the record holds it. The first read-through of a run that
/// stands in a wait sets the cutoff.
async fn reconcile(shared: &Shared, controller: &Controller) -> std::result::Result<(), Stopped> {
    let (add, clear) = {
        let owing = shared.owing();
        (owing.unsettled_in_order(), owing.cleared())
    };
    if !controller.restored_policy_waits() {
        *shared.owing() = Owing::default();
        shared.read_through.store(true, Ordering::SeqCst);
        return Ok(());
    }
    match controller
        .keep_what_is_owed(&shared.origin, &add, &clear)
        .await
        .map_err(Stopped::local)?
    {
        OwedWrite::Kept { full } => {
            // A list the cap kept an entry out of is not the whole of what is owed: the scan keeps
            // what it met, for the confirmation to name, and does not count as read through.
            if !full {
                *shared.owing() = Owing::default();
            }
            shared.owing_full.store(full, Ordering::SeqCst);
            shared.read_through.store(!full, Ordering::SeqCst);
        }
        // The record could not be read at the start and is not written over: what the run owes
        // stays in memory, where a confirmation reads it.
        OwedWrite::NoRecord => shared.read_through.store(true, Ordering::SeqCst),
        // The wait ended while the scan ran.
        OwedWrite::NotWaiting => {
            *shared.owing() = Owing::default();
            shared.read_through.store(true, Ordering::SeqCst);
            return Ok(());
        }
    }
    // A request above this sequence was published after the run read the feed.
    let _ = shared.finding_through.compare_exchange(
        u64::MAX,
        shared.scan_highest.load(Ordering::SeqCst),
        Ordering::SeqCst,
        Ordering::SeqCst,
    );
    Ok(())
}

/// The carrier of the host's authority feed.
pub struct FeedRuntime {
    shared: Arc<Shared>,
    timer: Arc<dyn Timer>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for FeedRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FeedRuntime")
            .field("origin", &self.shared.origin)
            .finish_non_exhaustive()
    }
}

impl FeedRuntime {
    /// Builds the carrier of the feed at `origin`, signing as the host whose authorisation key is
    /// `key` and sealing announcements with its stored-envelope key `stored_envelope`. Nothing runs
    /// and nothing is sent until [`Self::run`].
    #[must_use]
    pub fn new(
        client: AuthorityFeedClient,
        origin: &GatewayOrigin,
        host_device_id: DeviceId,
        key: AuthorisationKeyPair,
        stored_envelope: StoredEnvelopeKeyPair,
        timer: Arc<dyn Timer>,
    ) -> Self {
        let own_feed = client.own_feed();
        Self {
            shared: Arc::new(Shared {
                client,
                origin: origin.as_str().to_owned(),
                own_feed,
                host_device_id,
                key,
                stored_envelope,
                quiet: Quiet::new(Arc::clone(&timer)),
                gate_wait_ms: AtomicU64::new(
                    u64::try_from(GATE_WAIT.as_millis()).unwrap_or(u64::MAX),
                ),
                most_pages: AtomicUsize::new(MOST_PAGES),
                requested: AtomicU64::new(0),
                completed: tokio::sync::watch::channel(0).0,
                wake: tokio::sync::Notify::new(),
                #[cfg(feature = "testing")]
                wakes: AtomicU64::new(0),
                removed: AtomicBool::new(false),
                read_through: AtomicBool::new(false),
                finding_through: AtomicU64::new(u64::MAX),
                scan_highest: AtomicU64::new(0),
                findings_seen: AtomicU64::new(0),
                owing: Mutex::default(),
                owing_full: AtomicBool::new(false),
                settled_through: AtomicU64::new(0),
                scan_cursor: AtomicU64::new(0),
                scan_unfinished: AtomicBool::new(false),
                scan_put_off: AtomicBool::new(false),
                scan_found: Mutex::default(),
                scan_undecided: Mutex::default(),
                observed: Mutex::default(),
                controller: OnceLock::new(),
                passes: tokio::sync::watch::channel(0).0,
            }),
            timer,
            task: Mutex::new(None),
        }
    }

    /// Notes that the feed this host reads answered, in an earlier run, that it was removed from
    /// it, so the carrier has nothing left to ask.
    pub fn found_removed(&self) {
        self.shared.removed.store(true, Ordering::SeqCst);
    }

    /// Whether this host has nothing left to learn from its feed in this run: a scan has read it
    /// through since the registry was last found behind it and written what it owes to the record
    /// of the restore, or the feed removed this host and is read no more. A host that has not
    /// cannot tell whether the registry it started on still holds live a device an owner revoked
    /// through the feed.
    #[must_use]
    pub fn has_read_the_feed_through(&self) -> bool {
        self.shared.read_through.load(Ordering::SeqCst)
            || self.shared.removed.load(Ordering::SeqCst)
    }

    /// The devices and grants the scan in hand owes and has not yet written to the record, with
    /// whether the cap kept an owed target out of the record. A confirmation reads these beside
    /// the record's list.
    #[must_use]
    pub fn what_the_scan_owes(&self) -> (Vec<Target>, bool) {
        let owing = self
            .shared
            .owing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        (
            owing.unsettled_in_order(),
            self.shared.owing_full.load(Ordering::SeqCst),
        )
    }

    /// The origin this carrier reads.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.shared.origin
    }

    /// The identifier of the host key the feed is addressed by, which a remote owner publishes to.
    #[must_use]
    pub fn feed(&self) -> KeyId {
        self.shared.own_feed
    }

    /// Starts the carrier on `controller`. It does nothing the second time.
    pub fn run(&self, controller: &Arc<Controller>) {
        if self
            .shared
            .controller
            .set(Arc::downgrade(controller))
            .is_err()
        {
            return;
        }
        let task = tokio::spawn(drive(Arc::clone(&self.shared), Arc::clone(&self.timer)));
        *self.task.lock().unwrap_or_else(PoisonError::into_inner) = Some(task);
    }

    /// Ends the carrier where it is, as the daemon's process ending would. For a suite that stops
    /// the daemon between two steps of a request.
    #[cfg(feature = "testing")]
    pub fn crash(&self) {
        if let Some(task) = self
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }

    /// Shortens what a connection waits for a synchronisation, for a suite that holds the feed's
    /// answer and needs the bound to end without waiting out [`GATE_WAIT`].
    #[cfg(feature = "testing")]
    pub fn wait_for_a_synchronisation_at_most(&self, bound: Duration) {
        self.shared.gate_wait_ms.store(
            u64::try_from(bound.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    /// Lowers the pages one pass reads, for a suite that needs a feed longer than a pass reads
    /// without publishing the thousands of records it takes to fill that many pages.
    #[cfg(feature = "testing")]
    pub fn read_at_most_pages(&self, pages: usize) {
        self.shared.most_pages.store(pages, Ordering::SeqCst);
    }

    /// A count of the passes the carrier has finished, which changes each time one ends.
    #[must_use]
    pub fn passes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.shared.passes.subscribe()
    }

    /// Tells the carrier to look again now, without anything waiting for it. A wake made by the
    /// carrier's own revocation is not kept: the pass that makes it names the owners when it ends.
    pub fn wake(&self) {
        if CARRYING_OUT.try_with(|()| ()).is_ok() {
            return;
        }
        #[cfg(feature = "testing")]
        self.shared.wakes.fetch_add(1, Ordering::SeqCst);
        self.shared.wake.notify_one();
    }

    /// How many times something has asked the carrier to look again now, without counting a wake
    /// the carrier made of itself while carrying a request out.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn wakes(&self) -> u64 {
        self.shared.wakes.load(Ordering::SeqCst)
    }

    /// Holds a connection that was just admitted until the host has synchronised the feed after
    /// it, or until [`GATE_WAIT`] has passed.
    ///
    /// Section 10: synchronise at reconnect before affected remote access when the feed is
    /// reachable. A connection's first request is answered after a revocation the feed holds for
    /// the device has been carried out, so it finds its registration gone. A feed that is slow or
    /// unreachable does not hold the connection beyond the bound.
    pub async fn synchronised_before_serving(&self) {
        let shared = &self.shared;
        if shared.removed.load(Ordering::SeqCst) || shared.controller.get().is_none() {
            return;
        }
        let ticket = shared.requested.fetch_add(1, Ordering::SeqCst) + 1;
        // A carrier in the middle of a pass reads the count when it ends, so this wakes only one
        // that is waiting, and keeps nothing for one that is not.
        shared.wake.notify_waiters();
        let mut completed = shared.completed.subscribe();
        let gate_wait = Duration::from_millis(shared.gate_wait_ms.load(Ordering::SeqCst));
        let _ = tokio::time::timeout(gate_wait, async {
            while *completed.borrow_and_update() < ticket {
                if completed.changed().await.is_err() {
                    return;
                }
            }
        })
        .await;
    }

    /// What `kr doctor` says of the feed.
    #[must_use]
    pub fn doctor_check(&self, controller: &Controller) -> DoctorCheck {
        let status = controller.authority_feed().status();
        let observed = self.shared.observed();
        let now = controller.wall_now_ms();
        let synchronised = match status.last_synchronised_at_ms.0 {
            Some(at) => Sentence::new()
                .stated("it was last synchronised ")
                .number(now.saturating_sub(at.get()) / 1000)
                .stated(" seconds ago"),
            None => Sentence::new().stated("it has not been synchronised"),
        };
        let reads =
            Sentence::new().stated("this host reads its remote revocations from an authority feed");
        let (state, detail, remedy): (DoctorStatus, Sentence, Option<&'static str>) =
            if status.removed_at_ms.0.is_some() {
                (
                    DoctorStatus::Warning,
                    reads
                        .stated(
                            " that was removed, so it learns no revocation from it, and a \
                             revocation an owner published there that this host had not applied is \
                             gone; the grants that rest on the feed are refused. Before that, ",
                        )
                        .sentence(&synchronised),
                    Some(
                        "Revoke any device you did not expect from this host directly. To carry \
                         on, point `authority.origin` in the configuration document at another \
                         feed, or remove it, and start the daemon again.",
                    ),
                )
            } else if let Some(stopped) = observed.stopped {
                let why = match stopped {
                    Stopped::Unreachable => ", which could not be reached",
                    Stopped::Refused => ", which turned a request back",
                    Stopped::Local => ", which this host could not finish reading",
                };
                (
                    DoctorStatus::Warning,
                    reads.stated(why).stated("; ").sentence(&synchronised),
                    Some(
                        "This host asks again by itself. Until the feed answers, what is shown \
                         of remote revocations is stale.",
                    ),
                )
            } else if status.stale {
                (
                    DoctorStatus::Warning,
                    reads
                        .stated("; ")
                        .sentence(&synchronised)
                        .stated(", so what is shown of it may be stale"),
                    Some("This host reads the feed by itself shortly."),
                )
            } else {
                (
                    DoctorStatus::Ok,
                    reads.stated("; ").sentence(&synchronised),
                    None,
                )
            };
        // A refusal this host raised may be waiting for the registry to take a write, and the pass
        // that raised it goes no further until it has: the refusal stands and nothing more is read.
        let stuck = controller.stuck_drain();
        // A refusal the feed puts on every remote grant is a warning whatever else the check found,
        // and its remedy is the one that ends it.
        let (state, remedy) = if status.removed_at_ms.0.is_some() {
            (state, remedy)
        } else if observed.unverified {
            (
                DoctorStatus::Warning,
                Some(if observed.waiting_named.is_empty() {
                    UNVERIFIED_REMEDY
                } else {
                    UNVERIFIED_WAITING_REMEDY
                }),
            )
        } else if observed.catching_up
            && !matches!(
                observed.stopped,
                Some(Stopped::Unreachable | Stopped::Refused)
            )
        {
            // The registry is the likely cause only when the pass was not stopped by the feed.
            (DoctorStatus::Warning, Some(CATCHING_UP_REMEDY))
        } else if stuck.is_some() {
            // The feed's own state is stale, or a pass stopped (the feed turned a request back, or
            // this host could not finish it), and the wait for the registry is why nothing more is
            // read: its remedy replaces theirs.
            (DoctorStatus::Warning, Some(STUCK_DRAIN_REMEDY))
        } else {
            (state, remedy)
        };
        let detail = if observed.catching_up {
            detail.stated(
                "; the feed holds a revision above this host's own records, so this host is \
                 catching up with it and refuses every grant but the owner's at this machine until \
                 it has",
            )
        } else {
            detail
        };
        let detail = if observed.unverified {
            // A removed feed is read no more, so nothing finds the withdrawal settled before the
            // daemon starts again.
            let ends = if status.removed_at_ms.0.is_some() {
                "until the daemon starts again"
            } else {
                "until the owner at this machine has revoked them"
            };
            detail.stated(
                "; the feed shows complete a revocation by an owner this host does not know, so the \
                 devices it names may still be live here, and this host refuses every grant but the \
                 owner's at this machine ",
            )
            .stated(ends)
            .sentence(&names_of(&controller.unverified_withdrawals()))
        } else {
            detail
        };
        let detail =
            observed
                .waiting_named
                .iter()
                .take(MOST_NAMED)
                .fold(detail, |detail, device| {
                    detail.stated("; device ").identifier(device).stated(
                        " made a request that waits for this host's clock, which lost its \
                         continuity, and the withdrawal names it, so revoking it refuses that \
                         request",
                    )
                });
        let detail = if observed.unissued {
            detail.stated(
                "; the feed holds a revision this host has not reached, so it cannot issue its own",
            )
        } else {
            detail
        };
        let detail = match stuck {
            Some(stuck) => the_wait_for_the_registry(detail, &stuck, now),
            None => detail,
        };
        let detail = if observed.unnamed_owners > 0 {
            detail
                .stated("; ")
                .number(observed.unnamed_owners as u64)
                .stated(
                    " paired owner device(s) are beyond the keys the feed takes, so they cannot \
                     remove a lost host",
                )
        } else {
            detail
        };
        DoctorCheck::new(
            "authority-feed",
            "This host reads its remote revocations from its authority feed",
            state,
            detail,
            remedy,
        )
    }

    /// What `kr doctor` says of a host that reads no authority feed: one that selects none, or
    /// whose configuration document cannot be used. `removed` is whether the feed it read before
    /// removed it, which stands until a document it can use selects another feed or none.
    #[must_use]
    pub fn unconfigured_check(removed: bool) -> DoctorCheck {
        if removed {
            return DoctorCheck::new(
                "authority-feed",
                "This host reads its remote revocations from its authority feed",
                DoctorStatus::Warning,
                Sentence::new().stated(
                    "this host reads no authority feed now, and the one it read before removed it, \
                     so the grants that rest on the feed are refused and a remote owner's \
                     revocation cannot reach it",
                ),
                Some(
                    "Revoke any device you did not expect from this host directly. To carry on, \
                     point `authority.origin` in a configuration document this host can use at \
                     another feed, or remove it, and start the daemon again.",
                ),
            );
        }
        DoctorCheck::new(
            "authority-feed",
            "This host reads its remote revocations from its authority feed",
            DoctorStatus::NotApplicable,
            Sentence::new().stated(
                "no authority feed is selected, so a remote owner's revocation cannot reach this \
                 host; only the owner at this machine revokes a device (`kr device revoke`)",
            ),
            None,
        )
    }
}

impl Drop for FeedRuntime {
    fn drop(&mut self) {
        if let Some(task) = self
            .task
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }
}

/// The text of [`UNVERIFIED_REMEDY`], which [`UNVERIFIED_WAITING_REMEDY`] goes on from.
macro_rules! unverified_remedy {
    () => {
        "Never revoke the last owner device of this host while this stands: no confirmation from an \
         owner device is accepted until it ends, and a host with no owner device left cannot pair \
         one again. Otherwise revoke what the request names, at this machine, with `kr device \
         revoke <device>` for a device and `kr share revoke <grant>` for a grant. Neither needs a \
         confirmation. Remote access returns once the request names nothing live here. If the \
         request names every owner device, remove `authority.origin` from the configuration \
         document and start the daemon again, which ends the refusal because the host keeps none \
         of it. Then pair a new owner device, revoke what the request names, set \
         `authority.origin` back and start the daemon again. If this host bounds offline \
         validity, finish this inside the bound: once it ends, the host refuses every remote \
         request under a personal grant, an owner device's included. If the doctor also says \
         this host found the policy it holds restored, run `kr host policy --confirm` at this \
         machine before you pair a new owner device: pairing waits for an owner device's \
         confirmation, which that wait refuses. Until you revoke them, this host serves the \
         devices the request names, and while it reads no feed it learns no remote revocation."
    };
}

/// What a person who finds the host refusing remote access for a withdrawal it cannot verify does:
/// the devices and the grants the withdrawal names are what to revoke, unless it names every owner
/// device. A revocation at the machine needs no owner device's confirmation, and none is spent while
/// the refusal stands, so a host whose last owner device is revoked can pair none again. The refusal
/// is not stored, which is what the way out for that case rests on.
const UNVERIFIED_REMEDY: &str = unverified_remedy!();

/// As [`UNVERIFIED_REMEDY`], for a host whose clock lost its continuity while a request waits that
/// was made by a device the withdrawal names: revoking that device refuses the request, and the
/// clock is what keeps the request from being judged.
const UNVERIFIED_WAITING_REMEDY: &str = concat!(
    unverified_remedy!(),
    " A request that waits for this host's clock is refused if you revoke the device that made \
     it. A reboot of this machine ends a lost clock continuity, after which the host can decide \
     the request."
);

/// What a person who finds the host refusing remote access while it catches up with its feed does.
const CATCHING_UP_REMEDY: &str = "This host catches up by itself and asks again. If it stays like \
     this, the registry cannot take the write, or the record that the policy this host holds was \
     found restored cannot be written: check the disk and the permissions of the state \
     directory. Once it has caught up, `kr host policy --confirm` at this machine ends the wait \
     that restored policy puts on remote access.";

/// What a person who finds a refusal waiting for the registry to take a write does.
const STUCK_DRAIN_REMEDY: &str = "This host asks again by itself and goes on once the registry \
     takes a write; the refusal stands until then. Check that the disk of the state directory has \
     room, that the daemon may write there and that no other program holds the registry database. \
     If it stays like this, start the daemon again.";

/// How many of each of the issuers, devices and grants a withdrawal names a check says by name.
const MOST_NAMED: usize = 8;

/// What `kr doctor` says of a refusal that waits for the registry to take a write: how long the
/// wait has gone on in all, and why it has not ended, with the time of the reason that stands now.
/// A reason can have replaced another, so the two times differ.
fn the_wait_for_the_registry(detail: Sentence, stuck: &StuckDrain, now_ms: u64) -> Sentence {
    let in_all = now_ms.saturating_sub(stuck.since_ms) / 1000;
    let this_long = now_ms.saturating_sub(stuck.why_since_ms) / 1000;
    let detail = detail
        .stated(
            "; a refusal this host raised on remote grants waits for the registry to take a \
             write, as it has for at least ",
        )
        .number(in_all)
        .stated(" seconds, so this host reads no more of the feed until it has: ");
    match stuck.why {
        DrainWhy::Held => detail
            .stated(
                "a write to the pairing records has held the registry's write lock for at least ",
            )
            .number(this_long)
            .stated(" seconds"),
        DrainWhy::Unanswered => detail
            .stated("the ask for the registry's write lock has not been answered for at least ")
            .number(this_long)
            .stated(" seconds"),
        DrainWhy::Failed(kind) => detail
            .stated("the registry could not take the write for at least ")
            .number(this_long)
            .stated(" seconds, because ")
            .stated(kind),
    }
}

/// Names `grant` in a sentence. A grant is identified by a UUID this host generated, as a device is,
/// and the identifiers a sentence may name in full are a closed list that does not hold the
/// grant's, so the UUID is named through the device identifier, which prints the same text.
fn named_grant(sentence: Sentence, grant: &GrantId) -> Sentence {
    sentence.identifier(&DeviceId::new(grant.get()))
}

/// The sentence that says whose withdrawal the host cannot verify and what it names: the identifier
/// and key each request gives for its issuer, in sixteen hexadecimal digits of the key's
/// identifier, and the devices and grants it would withdraw.
fn names_of(found: &Unverified) -> Sentence {
    let mut sentence = Sentence::new();
    for (position, (issuer, key)) in found.issuers.iter().take(MOST_NAMED).enumerate() {
        let digits = key.as_bytes()[..8].try_into().map_or(0, u64::from_be_bytes);
        sentence = sentence
            .stated(if position == 0 {
                "; it says it was made by device "
            } else {
                ", and by device "
            })
            .identifier(issuer)
            .stated(" with key ")
            .hexadecimal(digits);
    }
    for (position, device) in found.devices.keys().take(MOST_NAMED).enumerate() {
        sentence = sentence
            .stated(if position == 0 {
                "; it names device "
            } else {
                ", device "
            })
            .identifier(device);
    }
    for (position, grant) in found.grants.iter().take(MOST_NAMED).enumerate() {
        sentence = named_grant(
            sentence.stated(if position == 0 {
                "; it names grant "
            } else {
                ", grant "
            }),
            grant,
        );
    }
    let beyond = found.issuers.len().saturating_sub(MOST_NAMED)
        + found.devices.len().saturating_sub(MOST_NAMED)
        + found.grants.len().saturating_sub(MOST_NAMED);
    if beyond > 0 {
        sentence = sentence
            .stated("; ")
            .number(beyond as u64)
            .stated(" more are not listed");
    }
    sentence
}

/// What the carrier does for as long as the daemon lives.
async fn drive(shared: Arc<Shared>, timer: Arc<dyn Timer>) {
    let mut backoff = Backoff::default();
    loop {
        // Every request made before this point is answered by the pass that follows it.
        let target = shared.requested.load(Ordering::SeqCst);
        let Some(controller) = shared.controller.get().and_then(Weak::upgrade) else {
            return;
        };
        let mut chained = false;
        let wait = if shared.removed.load(Ordering::SeqCst) {
            None
        } else if let Some(owed) = shared.quiet.owed() {
            // The feed asked to be left alone, and every question to it waits.
            Some(owed.left)
        } else {
            match pass(&shared, &controller).await {
                Ok(Pass::Read) => {
                    backoff = Backoff::default();
                    Some(Duration::from_millis(FEED_POLL_INTERVAL_MS))
                }
                Ok(Pass::Unfinished) => Some(backoff.next_delay()),
                Ok(Pass::More) => {
                    chained = true;
                    None
                }
                Ok(Pass::Removed) => None,
                Err(stopped) => {
                    controller.authority_feed_unreachable();
                    shared.observed().stopped = Some(stopped);
                    Some(
                        backoff
                            .next_delay()
                            .max(shared.quiet.left().unwrap_or_default()),
                    )
                }
            }
        };
        drop(controller);
        if chained {
            // The feed holds more than a pass reads. Nothing waits for this pass, because it
            // is not the synchronisation a connection waits for, and the next goes on at once.
            shared.passes.send_modify(|passes| *passes += 1);
            continue;
        }
        shared.completed.send_replace(target);
        shared.passes.send_modify(|passes| *passes += 1);
        // Interest in a wake is registered before the count of questions is read again, so a
        // question asked in between is either seen by the read or wakes the wait: none is lost.
        let woken = shared.wake.notified();
        tokio::pin!(woken);
        woken.as_mut().enable();
        if shared.requested.load(Ordering::SeqCst) > target {
            continue;
        }
        match wait {
            Some(duration) => {
                tokio::select! {
                    () = &mut woken => {}
                    () = timer.sleep(duration) => {}
                }
            }
            None => woken.await,
        }
    }
}

/// How a pass ended when it did not fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pass {
    /// The feed was read through, and everything in it settled.
    Read,
    /// The feed was read, and something it holds is not settled yet: a barrier still running.
    Unfinished,
    /// The feed was read as far as a pass reads, and the scan goes on at once where this stopped;
    /// or it was read through while the host caught up with it, and a new scan begins at once to
    /// judge what that put off.
    More,
    /// The feed answered that this host was removed from it.
    Removed,
}

/// What the carrier knows of the feed after its last answer.
struct Latest {
    /// The highest revision the feed holds for this host.
    revision: u64,
    /// The keys the feed lists as permitted to remove it.
    removal_keys: Vec<KeyId>,
}

impl Latest {
    fn of(state: &AuthorityFeedState) -> Self {
        Self {
            revision: state
                .summary
                .authority_revision
                .0
                .map_or(0, |revision| revision.get()),
            removal_keys: state.summary.removal_keys.clone(),
        }
    }

    /// Takes the state an answer to a change carries, and says whether the answer is that the feed
    /// removed this host. Every change reads its answer here, so none can drop the removal: a feed
    /// that stores a revision for a host it removed answers `removed`, and the pass that read it
    /// ends as a removal then and not when the next read finds it.
    fn took(&mut self, state: &AuthorityFeedState) -> bool {
        *self = Self::of(state);
        state.summary.removed
    }
}

/// One pass: read what the feed holds, carry out what it asks, say what became of it, and name the
/// keys that may remove the feed.
async fn pass(
    shared: &Arc<Shared>,
    controller: &Arc<Controller>,
) -> std::result::Result<Pass, Stopped> {
    // A scan starts after what is settled and goes on, pass after pass, until it has read the feed
    // through. A pass that goes on from where an earlier one stopped does not know what lies
    // before its cursor, so only the pass that starts a scan moves the settled mark.
    let resumed = shared.scan_cursor.load(Ordering::SeqCst);
    let starting = resumed == 0;
    let mut unfinished = shared.scan_unfinished.load(Ordering::SeqCst);
    let mut put_off = !starting && shared.scan_put_off.load(Ordering::SeqCst);
    let mut found = if starting {
        Unverified::default()
    } else {
        shared
            .scan_found
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    };
    // Why a request earlier in this scan could not be judged: the requests after it are judged by a
    // later scan, in the order the feed holds them.
    let mut undecided = if starting {
        None
    } else {
        shared
            .scan_undecided
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    };
    let mut cursor = if starting {
        shared.settled_through.load(Ordering::SeqCst)
    } else {
        resumed
    };
    let mut through = cursor;
    let mut contiguous = starting;
    let mut latest = None;
    let mut read_through = false;
    let mut compared = false;
    for _ in 0..shared.most_pages.load(Ordering::SeqCst) {
        let state = shared
            .client
            .read(shared.own_feed, (cursor > 0).then_some(cursor), false)
            .await
            .map_err(|error| Stopped::of(&error, &shared.quiet))?;
        if state.summary.removed {
            return removed(shared, controller).await;
        }
        let mut now = Latest::of(&state);
        // The feed's revision for this host, against the registry's, before a record is settled: a
        // registry restored to an earlier state is behind a revision this host issued.
        if !compared {
            compared = true;
            let behind = controller.authority_feed_behind(now.revision).await;
            // A finding restarts the scan, however its record fared: the count of findings is
            // raised before the record is written, so a write that failed and is made again by the
            // next pass is still a finding here, and so is a registry put back while the host was
            // catching up.
            let found_anew = handle_findings(shared, controller);
            let behind = match behind {
                Ok(behind) => behind,
                Err(error) => {
                    // A finding that could not be written down stops the pass with the host still
                    // behind its feed, and the doctor says so.
                    shared.observed().catching_up = controller.policy().behind_its_feed();
                    return Err(Stopped::local(error));
                }
            };
            shared.observed().catching_up = behind;
            if found_anew && cursor > 0 {
                // The page was read after a cursor the finding has taken away: the scan starts at
                // the first record, and nothing is settled on this page.
                return Ok(Pass::More);
            }
        }
        // What the page names is written to the record of the restore before any record of it is
        // acted on: a stop, an error, an abort or a removal after this keeps it.
        write_ahead(shared, controller, &state.records).await?;
        for record in &state.records {
            shared
                .scan_highest
                .fetch_max(record.sequence.get(), Ordering::SeqCst);
            // A request is judged by its issuer's standing, and judgment stays in the order the feed
            // holds the requests: one behind a request whose issuer's standing could not be decided
            // waits for the scan that can decide it. What the feed shows complete is only carried
            // out again, which asks no clock, and finds the withdrawals this host cannot verify.
            // A complete record that would revoke the issuer of a request that waits is not carried
            // out ahead of it either: the request would then be refused for a revocation that came
            // after it. That record waits as well, and so does anything that would revoke its issuer,
            // while the scan goes on reading, to settle the refusals and catch up.
            if let Some(waiting) = undecided.as_mut() {
                let waits = !shown_complete(record);
                let held = waits
                    || controller
                        .would_revoke_one_of(&record.request, &waiting.issuers())
                        .map_err(Stopped::local)?;
                if held {
                    waiting.hold(record.request.issuer_device_id, waits);
                    contiguous = false;
                    continue;
                }
            }
            match settle(shared, controller, record, &mut now).await? {
                Settled::Done => {
                    shared.settle(record.sequence.get());
                    if contiguous {
                        through = record.sequence.get();
                    }
                }
                Settled::Held => {
                    // A request this host cannot settle while the wait stands, and neither carries
                    // out nor refuses: it owes what it names, is judged again by every scan, and is
                    // refused as today once the wait has ended.
                    contiguous = false;
                }
                Settled::Unverified(these) => {
                    // Refused from this moment, and read again by every scan until the owner at
                    // this machine has dealt with what it names.
                    contiguous = false;
                    found.extend(&these);
                    let (wait_owed, keys) =
                        controller.refuse_for_an_unverified_withdrawal(&found).await;
                    if let Err(error) = keys {
                        // The refusal stands, and a later scan owes no wait for it.
                        if wait_owed {
                            controller.wait_for_the_confirmations_being_spent().await;
                        }
                        return Err(Stopped::local(error));
                    }
                    shared.observed().unverified = true;
                    // The feed takes a removal from the keys it lists, so the keys of the devices
                    // this names are taken out of the list now, not when the scan has read the
                    // feed through, and before the wait for the registry: a write that is held
                    // keeps the wait from ending, and the list must not wait with it. A scan that
                    // stops half way leaves the list as it is. A change the feed turns back stops
                    // the pass like any other request it turns back, with the delay it asked for.
                    let delegation = withhold_from_the_feed(shared, controller, &mut now).await;
                    if matches!(delegation, Ok(Delegation::Removed)) {
                        // The removal is recorded first: a registry that cannot take a write must
                        // not keep it from being recorded and shown. The wait this raise owes
                        // follows.
                        let ended = removed(shared, controller).await;
                        if wait_owed {
                            controller.wait_for_the_confirmations_being_spent().await;
                        }
                        return ended;
                    }
                    if wait_owed {
                        controller.wait_for_the_confirmations_being_spent().await;
                    }
                    delegation?;
                }
                Settled::Waiting => {
                    contiguous = false;
                    // While the host is behind its feed, a record that is not settled is one put
                    // off: the scan that follows the catch-up judges it, in the order the feed
                    // holds it.
                    if controller.policy().behind_its_feed() {
                        put_off = true;
                    } else {
                        unfinished = true;
                    }
                }
                Settled::Undecided(refusal) => {
                    contiguous = false;
                    undecided.get_or_insert_with(|| Undecided {
                        refusal,
                        requesters: [record.request.issuer_device_id].into_iter().collect(),
                        held: std::collections::BTreeSet::new(),
                    });
                }
                Settled::Removed => return removed(shared, controller).await,
            }
        }
        cursor = state.next_after_sequence.get();
        latest = Some(now);
        if !state.more {
            read_through = true;
            break;
        }
    }
    if starting {
        shared.settled_through.store(through, Ordering::SeqCst);
    }
    shared.scan_unfinished.store(unfinished, Ordering::SeqCst);
    shared.scan_put_off.store(put_off, Ordering::SeqCst);
    *shared
        .scan_found
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = found.clone();
    *shared
        .scan_undecided
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = undecided.clone();
    if !read_through {
        // The feed holds more than a pass reads, so this is no synchronisation: nothing is shown
        // as read, the bounded offline validity is not extended from it, and nothing waits for
        // this pass. What is shown is stale until the scan has read the feed through, which a feed
        // that always says there is more never lets it. The scan goes on at the cursor at once.
        controller.authority_feed_unreachable();
        shared.scan_cursor.store(cursor, Ordering::SeqCst);
        return Ok(Pass::More);
    }
    shared.scan_cursor.store(0, Ordering::SeqCst);
    shared.scan_unfinished.store(false, Ordering::SeqCst);
    shared.scan_put_off.store(false, Ordering::SeqCst);
    *shared
        .scan_found
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Unverified::default();
    *shared
        .scan_undecided
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = None;
    // What the scan owes is reconciled with the record before anything is carried out for the
    // catch-up, and the scan counts as read through only when the record holds it.
    reconcile(shared, controller).await?;
    // Read through, the scan has seen every withdrawal the feed shows complete that is not settled:
    // the refusal is lifted when it saw none, and stands, naming what they name, when it saw one.
    controller
        .settle_unverified_withdrawals((!found.is_empty()).then_some(&found))
        .await
        .map_err(Stopped::local)?;
    {
        let mut observed = shared.observed();
        observed.unverified = !found.is_empty();
        observed.waiting_named = waiting_issuers_the_withdrawal_names(undecided.as_ref(), &found);
    }
    if let Some(latest) = latest {
        // A registry found behind the feed is raised to the feed's revision, in one barrier, before
        // the feed is called read: until then what the host decides stands on an earlier state.
        if controller.policy().behind_its_feed() {
            controller
                .authority_feed_caught_up(latest.revision)
                .await
                .map_err(Stopped::local)?;
            shared.observed().catching_up = false;
            // What was put off is judged by the scan that begins now, on the registry as it
            // stands, in the order the feed holds it and numbered above everything the host has
            // issued. This scan is no synchronisation: a connection that waits for one waits for
            // that scan, and so is not served before those requests are carried out.
            if put_off {
                return Ok(Pass::More);
            }
        }
        if let Some(Undecided { refusal, .. }) = undecided {
            // The records held behind these requests are not carried out, and what they name is
            // owed until a scan can judge them.
            // The refusal and the catch-up are done, and what the feed shows complete is carried
            // out again, but for what waits. A pass that could not judge a request is no
            // synchronisation: nothing is shown as read, no key is added to the owners' list, and
            // the next pass waits out its backoff, then judges the request again. Keys of devices
            // the carrying out revoked are taken off the list all the same, as the feed removes the
            // host by a key.
            if drop_revoked_owners_from_the_feed(shared, controller, &latest).await?
                == Delegation::Removed
            {
                return removed(shared, controller).await;
            }
            return Err(Stopped::local(Controller::undecided_standing(&refusal)));
        }
        if name_owners(shared, controller, &latest).await? == Delegation::Removed {
            return removed(shared, controller).await;
        }
    }
    // The feed is read through, the registry is level with it, and every record it holds is carried
    // out, settled, or held with what it names written to the record of the restore: a revocation
    // still pending in the workers is carried out, and a withdrawal this host cannot verify raises
    // the refusal that its own wait keeps up.
    shared.observed().stopped = None;
    controller.authority_feed_synchronised();
    Ok(if unfinished {
        Pass::Unfinished
    } else {
        Pass::Read
    })
}

/// Records that the feed answered that it removed this host, whichever request it answered, and
/// ends the pass there: the grants that rest on the feed are refused from this moment and nothing
/// more is asked of a feed that removed the host.
async fn removed(
    shared: &Arc<Shared>,
    controller: &Arc<Controller>,
) -> std::result::Result<Pass, Stopped> {
    controller
        .authority_feed_removed(&shared.origin)
        .await
        .map_err(Stopped::local)?;
    shared.removed.store(true, Ordering::SeqCst);
    // A pass that found the registry behind the feed and stopped before the catch-up leaves that
    // refusal up, and no pass will end it now. The wait for the policy found restored refuses the
    // same grants, so it takes the refusal's place, and the person at this machine ends it.
    let caught_up = controller.end_a_catch_up_that_a_removed_feed_leaves().await;
    // The refusal a withdrawal this host cannot verify puts on remote grants may outlive the
    // removal. A feed that is read no more leaves no request waiting for the clock.
    let unverified = !controller.unverified_withdrawals().is_empty();
    let mut observed = shared.observed();
    observed.unverified = unverified;
    observed.waiting_named.clear();
    if caught_up {
        observed.catching_up = false;
    }
    Ok(Pass::Removed)
}

/// The devices that made a request waiting for this host's clock, which lost its continuity, and
/// that a withdrawal this host cannot verify names. The request cannot be judged until the clock is
/// decided again, and revoking its issuer refuses it. Another reason a standing is undecided names
/// no such device.
fn waiting_issuers_the_withdrawal_names(
    undecided: Option<&Undecided>,
    found: &Unverified,
) -> Vec<DeviceId> {
    undecided
        .filter(|waiting| matches!(waiting.refusal, Refusal::ClockUnproven))
        .map(|waiting| {
            waiting
                .requesters
                .iter()
                .filter(|issuer| found.devices.contains_key(issuer))
                .copied()
                .collect()
        })
        .unwrap_or_default()
}

/// What the feed answered a change to the list of keys that may remove it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delegation {
    /// The feed took the change, or none was asked.
    Taken,
    /// The feed answered that it removed this host. A list changed after the removal proves nothing
    /// about who removed it, so nothing is concluded from it.
    Removed,
}

/// Names the keys of the owners this host is paired with as the ones that may remove the feed,
/// when the feed lists others. The feed replaces the whole list, so one delegation is in flight at
/// a time, and what the feed lists on its answers is what is compared.
async fn name_owners(
    shared: &Arc<Shared>,
    controller: &Arc<Controller>,
    latest: &Latest,
) -> std::result::Result<Delegation, Stopped> {
    let (named, beyond) = controller.owner_key_ids().map_err(Stopped::local)?;
    shared.observed().unnamed_owners = beyond;
    let mut wanted = named.clone();
    let mut listed = latest.removal_keys.clone();
    wanted.sort();
    listed.sort();
    if wanted != listed {
        let answer = shared
            .client
            .delegate(&named)
            .await
            .map_err(|error| Stopped::of(&error, &shared.quiet))?;
        if answer.summary.removed {
            // A feed that was removed in between takes the change and says so.
            return Ok(Delegation::Removed);
        }
    }
    // The list the feed holds is the owners this host names, and none of them is a key a
    // withdrawal this host cannot verify takes the right from.
    controller.feed_lists_no_withheld_key();
    Ok(Delegation::Taken)
}

/// Takes the keys no live device holds out of the keys the feed lists as permitted to remove it,
/// and adds none: what a pass that ended undecided leaves of the list.
async fn drop_revoked_owners_from_the_feed(
    shared: &Arc<Shared>,
    controller: &Arc<Controller>,
    latest: &Latest,
) -> std::result::Result<Delegation, Stopped> {
    let live = controller.live_key_ids().map_err(Stopped::local)?;
    let kept: Vec<KeyId> = latest
        .removal_keys
        .iter()
        .filter(|key| live.contains(key))
        .copied()
        .collect();
    if kept.len() == latest.removal_keys.len() {
        return Ok(Delegation::Taken);
    }
    let answer = shared
        .client
        .delegate(&kept)
        .await
        .map_err(|error| Stopped::of(&error, &shared.quiet))?;
    Ok(if answer.summary.removed {
        Delegation::Removed
    } else {
        Delegation::Taken
    })
}

/// Takes the keys of the devices a withdrawal this host cannot verify names out of the keys the
/// feed lists as permitted to remove it, leaving every other as it is: the host adds no key to the
/// list on what a registry it has found wrong holds.
async fn withhold_from_the_feed(
    shared: &Arc<Shared>,
    controller: &Arc<Controller>,
    latest: &mut Latest,
) -> std::result::Result<Delegation, Stopped> {
    let withheld = controller.withheld_key_ids();
    let kept: Vec<KeyId> = latest
        .removal_keys
        .iter()
        .filter(|key| !withheld.contains(key))
        .copied()
        .collect();
    if kept.len() != latest.removal_keys.len() {
        let answer = shared
            .client
            .delegate(&kept)
            .await
            .map_err(|error| Stopped::of(&error, &shared.quiet))?;
        if answer.summary.removed {
            return Ok(Delegation::Removed);
        }
        latest.removal_keys = kept;
    }
    controller.feed_lists_no_withheld_key();
    Ok(Delegation::Taken)
}

/// How a record the feed holds stands after this host has dealt with it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Settled {
    /// The feed has nothing more to wait for on it.
    Done,
    /// It waits: a barrier still running, or the host catching up with its feed.
    Waiting,
    /// The feed shows it complete, and this host holds what it names live and cannot tell whose
    /// word it is. It stays unsettled, so every scan reads it again.
    Unverified(Unverified),
    /// This host cannot yet decide whether the device that made it may manage the host, for the
    /// reason given. It stays unsettled, and a later scan judges it again.
    Undecided(Refusal),
    /// While a wait for a restored policy stands, this host neither carries it out nor refuses it
    /// and sends nothing: it cannot settle it on evidence a restore cannot change. It owes what it
    /// names, every scan judges it again, and the first scan after the wait refuses it as today.
    Held,
    /// The feed answered a change to this host's records by saying it removed the host.
    Removed,
}

/// A request whose issuer's standing this host could not decide, and why.
#[derive(Clone, Debug)]
struct Undecided {
    refusal: Refusal,
    /// The devices that made the requests that wait: the one that cannot be decided and those behind
    /// it that are not complete. Revoking one of them refuses its request.
    requesters: std::collections::BTreeSet<DeviceId>,
    /// The devices that made the complete records held because they would revoke one of the
    /// others. Revoking one of them dismisses its record, which carries out nothing, and what it
    /// names stays served.
    held: std::collections::BTreeSet<DeviceId>,
}

impl Undecided {
    /// Notes the issuer of a record that waits behind the undecided request. A request that is not
    /// complete waits for the one before it, and revoking its issuer refuses it. A complete record
    /// waits only to keep its order, and is dismissed if its issuer is revoked.
    fn hold(&mut self, issuer: DeviceId, waits: bool) {
        if waits {
            self.requesters.insert(issuer);
        } else {
            self.held.insert(issuer);
        }
    }

    /// Every device whose record or request waits.
    fn issuers(&self) -> std::collections::BTreeSet<DeviceId> {
        self.requesters.union(&self.held).copied().collect()
    }
}

/// Whether the feed shows the record's request completed by this host, and not refused.
fn shown_complete(record: &AuthorityFeedRecord) -> bool {
    record.rejected.0.is_none()
        && record
            .acknowledgement
            .0
            .as_ref()
            .is_some_and(|held| held.completion == RevocationCompletion::Complete)
}

/// Whether the feed's record carries an acknowledgement this host made.
fn acknowledged_by(record: &AuthorityFeedRecord, host: DeviceId) -> bool {
    record
        .acknowledgement
        .0
        .as_ref()
        .is_some_and(|held| held.host_device_id == host)
}

/// Settles one record the feed holds: refuses it, or carries it out and acknowledges it.
async fn settle(
    shared: &Arc<Shared>,
    controller: &Arc<Controller>,
    record: &AuthorityFeedRecord,
    latest: &mut Latest,
) -> std::result::Result<Settled, Stopped> {
    // A request the feed shows this host acknowledged took effect here, as an acknowledgement is
    // only made after the host carried it out, whatever its completion and whether or not the
    // record is also refused. A registry restored to an earlier state has lost what this host
    // carried out for it: what the registry does not show done is carried out again, whatever its
    // counter says. When the registry holds a note of this very request, the note decides as it
    // always did.
    let noted_this = controller
        .authority_feed_record(record.request.request_id)
        .is_some_and(|held| held.request == record.request);
    if shown_complete(record) || (acknowledged_by(record, shared.host_device_id) && !noted_this) {
        return replay_a_record(shared, controller, record, latest).await;
    }
    settle_request(shared, controller, record, latest).await
}

/// Carries out again a request the feed shows this host acknowledged, and, when the feed shows it
/// Pending and the barrier now holds, says so.
async fn replay_a_record(
    shared: &Arc<Shared>,
    controller: &Arc<Controller>,
    record: &AuthorityFeedRecord,
    latest: &mut Latest,
) -> std::result::Result<Settled, Stopped> {
    let pending = record.rejected.0.is_none()
        && record.acknowledgement.0.as_ref().is_some_and(|held| {
            held.host_device_id == shared.host_device_id
                && held.completion != RevocationCompletion::Complete
        });
    let place = record.sequence.get();
    let replayed = if pending {
        controller
            .replay_a_pending_request(&record.request, place)
            .await
    } else {
        controller.replay_feed_request(&record.request, place).await
    }
    .map_err(Stopped::local)?;
    match replayed {
        Replay::Done => {
            controller.authority_feed_settled(&record.request, shared.host_device_id);
            Ok(Settled::Done)
        }
        Replay::Applied(RevocationCompletion::Complete) => {
            acknowledge_as_complete(shared, controller, record, latest).await
        }
        // The barrier has not held for every worker: a later scan applies it again and reads it.
        Replay::Applied(_) => Ok(Settled::Waiting),
        Replay::Unverified(found) => Ok(Settled::Unverified(found)),
        Replay::Owed => Ok(Settled::Held),
    }
}

/// Acknowledges a request the feed shows Pending as complete, under the revision the feed's own
/// acknowledgement names, which the feed checks applied the request, at a time not older than
/// that acknowledgement's. The feed keeps a record until the host completes or refuses it, and one
/// that is left Pending holds one of its publisher's open records for ever.
async fn acknowledge_as_complete(
    shared: &Arc<Shared>,
    controller: &Arc<Controller>,
    record: &AuthorityFeedRecord,
    latest: &mut Latest,
) -> std::result::Result<Settled, Stopped> {
    let Some(held) = record.acknowledgement.0.as_ref() else {
        return Ok(Settled::Waiting);
    };
    let acknowledgement = RevocationAcknowledgement {
        request_id: record.request.request_id,
        host_device_id: shared.host_device_id,
        authority_revision: held.authority_revision,
        completion: RevocationCompletion::Complete,
        acknowledged_at_ms: TimestampMs::new(
            controller.wall_now_ms().max(held.acknowledged_at_ms.get()),
        ),
    };
    let announcement =
        announcement_to_the_issuer(shared, controller, record, RevocationCompletion::Complete);
    match shared
        .client
        .acknowledge(&acknowledgement, announcement.as_ref())
        .await
    {
        Ok(state) => {
            if latest.took(&state) {
                return Ok(Settled::Removed);
            }
            controller.authority_feed_settled(&record.request, shared.host_device_id);
            Ok(Settled::Done)
        }
        // The feed refused the acknowledgement: the record was refused or completed meanwhile, or
        // its time is older. The next scan reads the record as the feed holds it now.
        Err(error) if error.service_code() == Some("INVALID_REQUEST") => Ok(Settled::Waiting),
        Err(error) => Err(Stopped::of(&error, &shared.quiet)),
    }
}

/// Settles a record the feed does not show complete: refuses it, or carries it out and
/// acknowledges it. Says whether the feed has nothing more to wait for on it.
async fn settle_request(
    shared: &Arc<Shared>,
    controller: &Arc<Controller>,
    record: &AuthorityFeedRecord,
    latest: &mut Latest,
) -> std::result::Result<Settled, Stopped> {
    let request = &record.request;
    let id = request.request_id;
    let place = record.sequence.get();
    if record.rejected.0.is_some() {
        // Only this host refuses a request, so a note it kept of this one is a refusal.
        controller
            .authority_feed_refusal_noted(request, shared.host_device_id)
            .map_err(Stopped::local)?;
        return Ok(Settled::Done);
    }
    // A request the registry does not show completed waits until the host has caught up: it is
    // judged, numbered and carried out on the registry as it will stand then, not on the earlier
    // state it was restored to, and the owner who issued it is not refused for the host's being
    // behind.
    if controller.policy().behind_its_feed() {
        return Ok(Settled::Waiting);
    }
    let now = controller.wall_now_ms();
    let noted = controller.authority_feed_record(id);
    let plan = match &noted {
        // A different request under an identity this host took: refused, and never carried out.
        // While a wait stands the note is a fact about the registry and not about this request,
        // which may be one the host carried out before the restore, so it is held.
        Some(held) if held.request != *request => {
            if shared.holds_for_the_wait(controller, place) {
                return Ok(Settled::Held);
            }
            return refuse(
                shared,
                controller,
                request,
                RejectionReason::Superseded,
                latest,
            )
            .await;
        }
        // One this host refused after it began to take it and is published again: refused, and
        // never carried out. The feed shows this host acknowledged it, which a refusal in the same
        // registry contradicts (two states of it): during a wait it is held.
        Some(held) if held.is_refused_by(shared.host_device_id) => {
            if acknowledged_by(record, shared.host_device_id)
                && shared.holds_for_the_wait(controller, place)
            {
                return Ok(Settled::Held);
            }
            return refuse(
                shared,
                controller,
                request,
                RejectionReason::Superseded,
                latest,
            )
            .await;
        }
        Some(_) => controller.plan_of(request).map_err(Stopped::local)?,
        None => match controller
            .judge_feed_request(request, now, place)
            .map_err(Stopped::local)?
        {
            Judged::Refuse(reason, ground) => {
                // A refusal the feed keeps for a week reads, at a later restore, as "this host
                // never applied it". While a wait stands the host sends one only on what a
                // restore cannot change; on anything else it holds the request, which owes what
                // it names.
                if ground == Ground::Mutable && shared.holds_for_the_wait(controller, place) {
                    return Ok(Settled::Held);
                }
                // The obligation ends with the decision, whatever becomes of the delivery.
                shared.settle(place);
                return refuse(shared, controller, request, reason, latest).await;
            }
            Judged::Apply(plan) => plan,
            Judged::Undecided(refusal) => return Ok(Settled::Undecided(refusal)),
        },
    };
    let held = controller
        .authority_feed_begin(
            request.clone(),
            &shared.origin,
            AuthorityRevision::new(latest.revision),
            now,
        )
        .await
        .map_err(Stopped::local)?;
    let applied = controller
        .apply_feed_plan(&plan)
        .await
        .map_err(Stopped::local)?;
    #[cfg(feature = "testing")]
    controller.feed_request_was_carried_out().await;
    // A request is numbered when it takes effect. One not numbered yet that left the registry
    // where it stood when the host began to take it withdrew nothing: the owner at this machine,
    // or an earlier request, had already withdrawn what it names. There is no revision to issue
    // for it, and the registry is the one allocator. This holds however the host was interrupted
    // since it began, because it compares the registry with what it was then.
    let numbered = held.authority_revision.is_some();
    if !numbered && applied.revision <= held.registry_revision {
        // What the request names was withdrawn already, as the registry stands: a fact about the
        // registry, which a restore can undo, so the refusal is not sent while a wait stands.
        if shared.holds_for_the_wait(controller, place) {
            return Ok(Settled::Held);
        }
        return refuse(
            shared,
            controller,
            request,
            RejectionReason::Superseded,
            latest,
        )
        .await;
    }
    // This host numbers what it issues from the registry, and the feed takes only a number above
    // the one it holds. A request not numbered yet therefore needs the registry past the feed; a
    // request already numbered is issued again under its own number, and needs only that the
    // registry has not fallen behind the feed.
    let behind = if numbered {
        latest.revision > applied.revision.get()
    } else {
        latest.revision >= applied.revision.get()
    };
    if behind {
        shared.observed().unissued = true;
        return Err(Stopped::Local);
    }
    shared.observed().unissued = false;
    // A request is numbered once, by the registry's revision when it took effect, and issued under
    // that number whatever the feed has been issued since: the feed takes the same record again as
    // the revision that already stands.
    let taken = controller
        .authority_feed_took_effect(id, applied.revision)
        .map_err(Stopped::local)?;
    let number = taken.authority_revision.unwrap_or(applied.revision);
    let revision = revision_record(shared, &taken, number, id)?;
    let state = shared
        .client
        .revise(&revision, None)
        .await
        .map_err(|error| Stopped::of(&error, &shared.quiet))?;
    // A feed that removed the host answers its revision with the removal, and holds no record to
    // acknowledge: the request was carried out and written down above, and nothing more is asked.
    if latest.took(&state) {
        return Ok(Settled::Removed);
    }
    let acknowledgement = RevocationAcknowledgement {
        request_id: id,
        host_device_id: shared.host_device_id,
        authority_revision: number,
        completion: applied.completion,
        acknowledged_at_ms: TimestampMs::new(controller.wall_now_ms()),
    };
    let announcement = announcement_to_the_issuer(shared, controller, record, applied.completion);
    let state = shared
        .client
        .acknowledge(&acknowledgement, announcement.as_ref())
        .await
        .map_err(|error| Stopped::of(&error, &shared.quiet))?;
    if latest.took(&state) {
        return Ok(Settled::Removed);
    }
    if applied.completion == RevocationCompletion::Complete {
        controller.authority_feed_settled(request, shared.host_device_id);
        Ok(Settled::Done)
    } else {
        Ok(Settled::Waiting)
    }
}

/// The announcement that the feed changed, for the owner who published `record`'s request, to place
/// in that owner's mailbox beside the acknowledgement.
///
/// The owner reads the feed to learn what became of its request; the announcement tells the
/// owner's mailbox that the feed changed. It is made when the acknowledgement tells the owner
/// something new, which is the first one or a change of its completion: a request left pending is
/// acknowledged again on each pass, and announcing each of those would fill the owner's mailbox
/// with one thing said again. The owner is the device that published, only while its pairing is in
/// force and its key is recorded; a host that cannot seal one acknowledges without, because the
/// feed is the record.
fn announcement_to_the_issuer(
    shared: &Shared,
    controller: &Controller,
    record: &AuthorityFeedRecord,
    completion: RevocationCompletion,
) -> Option<FeedAnnouncement> {
    if !tells_something_new(record.acknowledgement.0.as_ref(), completion) {
        return None;
    }
    let issuer = controller
        .paired_stored_envelope_key(record.request.issuer_device_id)
        .ok()??;
    FeedAnnouncement::sealed_for(&shared.stored_envelope, &issuer, controller.wall_now_ms()).ok()
}

/// Whether acknowledging with `completion` tells the owner something the feed's `held`
/// acknowledgement does not already say: the first acknowledgement, or a change of how much of the
/// revocation the host's sessions have confirmed.
fn tells_something_new(
    held: Option<&RevocationAcknowledgement>,
    completion: RevocationCompletion,
) -> bool {
    held.is_none_or(|held| held.completion != completion)
}

/// Refuses a record with a reason the publisher reads, and settles it here.
async fn refuse(
    shared: &Arc<Shared>,
    controller: &Arc<Controller>,
    request: &RevocationRequest,
    reason: RejectionReason,
    latest: &mut Latest,
) -> std::result::Result<Settled, Stopped> {
    // Written down before it is sent: a refusal that never arrives is made again, and the same
    // request published again after the feed dropped it is refused again and not carried out.
    controller
        .authority_feed_refusal_noted(request, shared.host_device_id)
        .map_err(Stopped::local)?;
    let state = shared
        .client
        .reject(request.request_id, reason)
        .await
        .map_err(|error| Stopped::of(&error, &shared.quiet))?;
    if latest.took(&state) {
        return Ok(Settled::Removed);
    }
    Ok(Settled::Done)
}

/// The revision this host issues for one request, from what it wrote down before it began, so the
/// same record is issued again after a stop.
fn revision_record(
    shared: &Shared,
    held: &RetainedRevocation,
    number: AuthorityRevision,
    id: RevocationRequestId,
) -> std::result::Result<AuthorityRevisionRecord, Stopped> {
    let mut record = AuthorityRevisionRecord {
        host_device_id: shared.host_device_id,
        authority_revision: number,
        previous_revision: held.previous_revision,
        applied_requests: [id].into_iter().collect::<CanonicalSet<_>>(),
        issued_at_ms: TimestampMs::new(held.applied_at_ms),
        host_key_id: shared.key.key_id(),
        signature: Signature64::from_bytes([0; 64]),
    };
    let signed = record
        .signing_input()
        .map_err(|error| error.to_string())
        .and_then(|input| {
            SigningTranscript::from_canonical_bytes(AUTHORITY_REVISION_DOMAIN, input)
                .map_err(|error| error.to_string())
        })
        .and_then(|transcript| sign(&shared.key, &transcript).map_err(|error| error.to_string()));
    match signed {
        Ok(signature) => {
            record.signature = signature;
            Ok(record)
        }
        Err(error) => Err(Stopped::local(ControllerError::Storage {
            operation: "sign a revision record",
            detail: error,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt as _;

    /// KR-REQ-24.15: `kr doctor` says that revoking a device refuses its request only for a device
    /// that made a request that waits. A device that made a complete record held behind it is not
    /// named: revoking it dismisses the record, which carries out nothing, and refuses nothing. A
    /// device that made both is named.
    #[test]
    fn the_doctor_names_only_the_devices_whose_waiting_request_a_revocation_would_refuse() {
        let device = |byte: u8| DeviceId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16]));
        let (requester, held_only, both) = (device(1), device(2), device(3));
        // The undecided request is the first requester's. The records behind it are sorted as the
        // scan sorts them: a request that is not complete waits, and a complete record is held.
        let mut waiting = Undecided {
            refusal: Refusal::ClockUnproven,
            requesters: [requester].into_iter().collect(),
            held: std::collections::BTreeSet::new(),
        };
        waiting.hold(held_only, false);
        waiting.hold(both, false);
        waiting.hold(both, true);
        let found = Unverified {
            devices: [(requester, 1), (held_only, 1), (both, 1)]
                .into_iter()
                .collect(),
            ..Unverified::default()
        };
        let mut named = waiting_issuers_the_withdrawal_names(Some(&waiting), &found);
        named.sort();
        assert_eq!(
            named,
            vec![requester, both],
            "the devices whose waiting request a revocation refuses, and not the held record's"
        );
    }

    /// KR-REQ-24.15: `kr doctor` gives a refusal that waits for the registry the time the wait has
    /// gone on in all, and gives the reason that stands now its own time: a reason that replaced
    /// another has not stood for as long as the wait has gone on.
    #[test]
    fn the_doctor_gives_a_later_reason_its_own_time_beside_the_waits() {
        let stuck = StuckDrain {
            since_ms: 0,
            why_since_ms: 600_000,
            why: DrainWhy::Failed("the disk is full"),
        };
        let check = DoctorCheck::new(
            "authority-feed",
            "This host reads its remote revocations from its authority feed",
            DoctorStatus::Warning,
            the_wait_for_the_registry(Sentence::new(), &stuck, 605_000),
            None,
        );
        let said = check.detail();
        assert!(
            said.contains("as it has for at least 605 seconds"),
            "the wait's time in all: {said}"
        );
        assert!(
            said.contains("for at least 5 seconds, because the disk is full"),
            "the reason's own time, and not the wait's: {said}"
        );
    }

    /// A request a host acknowledges again on every pass while some of its sessions have yet to
    /// confirm it announces once, and again when how much is confirmed changes. The daemon's
    /// suites cannot hold a barrier pending, which takes a running session that does not answer.
    #[test]
    fn an_acknowledgement_that_says_nothing_new_is_not_announced() {
        use kr_protocol::scalars::U64;
        let pending = |workers| RevocationCompletion::Pending {
            pending_workers: U64::new(workers),
        };
        let acknowledged = |completion| RevocationAcknowledgement {
            request_id: RevocationRequestId::new(kr_ipc::new_uuid()),
            host_device_id: DeviceId::new(kr_ipc::new_uuid()),
            authority_revision: AuthorityRevision::new(2),
            completion,
            acknowledged_at_ms: TimestampMs::new(1),
        };
        assert!(
            tells_something_new(None, pending(2)),
            "the first one is news"
        );
        assert!(!tells_something_new(
            Some(&acknowledged(pending(2))),
            pending(2)
        ));
        assert!(tells_something_new(
            Some(&acknowledged(pending(2))),
            pending(1)
        ));
        assert!(tells_something_new(
            Some(&acknowledged(pending(1))),
            RevocationCompletion::Complete
        ));
    }

    #[derive(Debug)]
    struct NoSigner(kr_crypto::keys::AuthorisationKeyPair);

    impl kr_client::services::ServiceSigner for NoSigner {
        fn signer(&self) -> kr_protocol::service::ServiceRequestSigner {
            kr_protocol::service::ServiceRequestSigner::Host
        }

        fn public_key(&self) -> kr_protocol::scalars::AuthorisationKey {
            *self.0.public()
        }

        fn sign(&self, _message: &[u8]) -> kr_client::Result<Signature64> {
            Ok(Signature64::from_bytes([0; 64]))
        }
    }

    /// A carrier that has made no request, for a suite of its waking.
    fn carrier() -> FeedRuntime {
        let key = AuthorisationKeyPair::generate().expect("a key");
        let origin = GatewayOrigin::new("http://127.0.0.1:9").expect("an origin");
        let client =
            managed_client(&origin, None, Arc::new(NoSigner(key.clone()))).expect("a client");
        FeedRuntime::new(
            client,
            &origin,
            DeviceId::new(kr_ipc::new_uuid()),
            key,
            kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a key pair"),
            Arc::new(crate::quiet::RealTimer),
        )
    }

    /// A revocation the carrier carries out wakes whatever watches the owners this host is paired
    /// with, and the carrier is one of those. It is not woken by its own: a wake it kept would end
    /// the wait a failed pass asked for, and a feed that keeps failing would be asked again
    /// without one. A wake from anything else is kept.
    #[tokio::test]
    async fn the_carriers_own_revocation_does_not_wake_it_and_anothers_does() {
        let runtime = carrier();
        CARRYING_OUT.scope((), async { runtime.wake() }).await;
        assert!(
            runtime.shared.wake.notified().now_or_never().is_none(),
            "a wake made while the carrier carries a request out is not kept"
        );
        runtime.wake();
        assert!(
            runtime.shared.wake.notified().now_or_never().is_some(),
            "a wake from anywhere else is"
        );
    }
}
