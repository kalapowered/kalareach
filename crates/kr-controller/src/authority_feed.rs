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
use kr_protocol::ids::{AuthorityRevision, DeviceId, RevocationRequestId};
use kr_protocol::pairing::{
    AUTHORITY_REVISION_DOMAIN, AuthorityRevisionRecord, RevocationAcknowledgement,
    RevocationCompletion,
};
use kr_protocol::scalars::{CanonicalSet, KeyId, Signature64, TimestampMs};
use kr_protocol::service::GatewayOrigin;
use kr_transport::config::ProxyUrl;
use kr_transport::reconnect::Backoff;
use tokio::task::JoinHandle;

use crate::error::{ControllerError, Result};
use crate::grants::Refusal;
use crate::grants::feed::{FEED_POLL_INTERVAL_MS, RetainedRevocation};
use crate::quiet::{Quiet, Timer};
use crate::service::Controller;
use crate::service::remote_revocation::{Judged, Replay, Unverified};

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
        // A refusal the feed puts on every remote grant is a warning whatever else the check found,
        // and its remedy is the one that ends it.
        let (state, remedy) = if status.removed_at_ms.0.is_some() {
            (state, remedy)
        } else if observed.unverified {
            (DoctorStatus::Warning, Some(UNVERIFIED_REMEDY))
        } else if observed.catching_up
            && !matches!(
                observed.stopped,
                Some(Stopped::Unreachable | Stopped::Refused)
            )
        {
            // The registry is the likely cause only when the pass was not stopped by the feed.
            (DoctorStatus::Warning, Some(CATCHING_UP_REMEDY))
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
        let detail = if observed.unissued {
            detail.stated(
                "; the feed holds a revision this host has not reached, so it cannot issue its own",
            )
        } else {
            detail
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

/// What a person who finds the host refusing remote access for a withdrawal it cannot verify does:
/// the devices and the grants the withdrawal names are what to revoke, unless it names every owner
/// device. A revocation at the machine needs no owner device's confirmation, and none is spent while
/// the refusal stands, so a host whose last owner device is revoked can pair none again. The refusal
/// is not stored, which is what the way out for that case rests on.
const UNVERIFIED_REMEDY: &str = "Never revoke the last owner device of this host while this \
     stands: no confirmation from an owner device is accepted until it ends, and a host with no \
     owner device left cannot pair one again. Otherwise revoke what the request names, at this \
     machine, with `kr device revoke <device>` for a device and `kr share revoke <grant>` for a \
     grant. Neither needs a confirmation. Remote access returns once the request names nothing \
     live here. If the request names every owner device, remove `authority.origin` from the \
     configuration document and start the daemon again, which ends the refusal because the host \
     keeps none of it. Then pair a new owner device, revoke what the request names, set \
     `authority.origin` back and start the daemon again. Until you revoke them, this host serves \
     the devices the request names, and while it reads no feed it learns no remote revocation.";

/// What a person who finds the host refusing remote access while it catches up with its feed does.
const CATCHING_UP_REMEDY: &str = "This host catches up by itself and asks again. If it stays like \
     this, the registry cannot take the write: check the disk and the permissions of the state \
     directory.";

/// How many of each of the issuers, devices and grants a withdrawal names a check says by name.
const MOST_NAMED: usize = 8;

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
        sentence = sentence
            .stated(if position == 0 {
                "; it names grant "
            } else {
                ", grant "
            })
            .identifier(grant);
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
            let behind = controller
                .authority_feed_behind(now.revision)
                .await
                .map_err(Stopped::local)?;
            shared.observed().catching_up = behind;
        }
        for record in &state.records {
            // A request is judged by its issuer's standing, and judgment stays in the order the feed
            // holds the requests: one behind a request whose issuer's standing could not be decided
            // waits for the scan that can decide it. What the feed shows complete is only carried
            // out again, which asks no clock, and finds the withdrawals this host cannot verify.
            // A complete record that would revoke the issuer of a request that waits is not carried
            // out ahead of it either: the request would then be refused for a revocation that came
            // after it. That record waits as well, and so does anything that would revoke its issuer,
            // while the scan goes on reading, to settle the refusals and catch up.
            if let Some(waiting) = undecided.as_mut() {
                let held = !shown_complete(record)
                    || controller
                        .would_revoke_one_of(&record.request, &waiting.issuers)
                        .map_err(Stopped::local)?;
                if held {
                    waiting.issuers.insert(record.request.issuer_device_id);
                    contiguous = false;
                    continue;
                }
            }
            match settle(shared, controller, record, &mut now).await? {
                Settled::Done => {
                    if contiguous {
                        through = record.sequence.get();
                    }
                }
                Settled::Unverified(these) => {
                    // Refused from this moment, and read again by every scan until the owner at
                    // this machine has dealt with what it names.
                    contiguous = false;
                    found.extend(&these);
                    controller
                        .note_unverified_withdrawal(&found)
                        .await
                        .map_err(Stopped::local)?;
                    shared.observed().unverified = true;
                    // The feed takes a removal from the keys it lists, so the keys of the devices
                    // this names are taken out of the list now, not when the scan has read the
                    // feed through: a scan that stops half way leaves the list as it is. A change
                    // the feed turns back stops the pass like any other request it turns back,
                    // with the delay it asked for.
                    if withhold_from_the_feed(shared, controller, &mut now).await?
                        == Delegation::Removed
                    {
                        return removed(shared, controller).await;
                    }
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
                        issuers: [record.request.issuer_device_id].into_iter().collect(),
                    });
                }
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
    // Read through, the scan has seen every withdrawal the feed shows complete that is not settled:
    // the refusal is lifted when it saw none, and stands, naming what they name, when it saw one.
    controller
        .settle_unverified_withdrawals((!found.is_empty()).then_some(&found))
        .await
        .map_err(Stopped::local)?;
    shared.observed().unverified = !found.is_empty();
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
    controller.authority_feed_synchronised();
    shared.observed().stopped = None;
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
    // The refusal a withdrawal this host cannot verify puts on remote grants may outlive the
    // removal.
    shared.observed().unverified = !controller.unverified_withdrawals().is_empty();
    Ok(Pass::Removed)
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
}

/// A request whose issuer's standing this host could not decide, and why.
#[derive(Clone, Debug)]
struct Undecided {
    refusal: Refusal,
    /// The devices that made the requests that wait for it, those behind it that are not complete
    /// and the complete records held because they would revoke one of these.
    issuers: std::collections::BTreeSet<DeviceId>,
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

/// Settles one record the feed holds: refuses it, or carries it out and acknowledges it.
async fn settle(
    shared: &Arc<Shared>,
    controller: &Arc<Controller>,
    record: &AuthorityFeedRecord,
    latest: &mut Latest,
) -> std::result::Result<Settled, Stopped> {
    if shown_complete(record) {
        // A registry restored to an earlier state has lost what this host carried out for the
        // request, which the feed still shows complete: what the registry does not show done is
        // carried out again, whatever its counter says.
        let id = record.request.request_id;
        return match controller
            .replay_feed_request(&record.request, record.sequence.get())
            .await
            .map_err(Stopped::local)?
        {
            Replay::Done => {
                controller.authority_feed_settled(id, shared.host_device_id);
                Ok(Settled::Done)
            }
            Replay::Unverified(found) => Ok(Settled::Unverified(found)),
        };
    }
    settle_request(shared, controller, record, latest).await
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
            .authority_feed_refusal_noted(id, shared.host_device_id)
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
        // A different request under an identity this host took, or one this host refused after
        // it began to take it and is published again: refused, and never carried out.
        Some(held) if held.request != *request || held.is_refused_by(shared.host_device_id) => {
            return refuse(shared, controller, id, RejectionReason::Superseded, latest).await;
        }
        Some(_) => controller.plan_of(request).map_err(Stopped::local)?,
        None => match controller
            .judge_feed_request(request, now, place)
            .map_err(Stopped::local)?
        {
            Judged::Refuse(reason) => return refuse(shared, controller, id, reason, latest).await,
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
        return refuse(shared, controller, id, RejectionReason::Superseded, latest).await;
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
    *latest = Latest::of(&state);
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
    *latest = Latest::of(&state);
    if applied.completion == RevocationCompletion::Complete {
        controller.authority_feed_settled(id, shared.host_device_id);
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
    id: RevocationRequestId,
    reason: RejectionReason,
    latest: &mut Latest,
) -> std::result::Result<Settled, Stopped> {
    // Written down before it is sent: a refusal that never arrives is made again, and the same
    // request published again after the feed dropped it is refused again and not carried out.
    controller
        .authority_feed_refusal_noted(id, shared.host_device_id)
        .map_err(Stopped::local)?;
    let state = shared
        .client
        .reject(id, reason)
        .await
        .map_err(|error| Stopped::of(&error, &shared.quiet))?;
    *latest = Latest::of(&state);
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
