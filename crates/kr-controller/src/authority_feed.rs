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
//!   most [`GATE_WAIT`] for it. A feed that does not answer in that time leaves the status stale and
//!   the connection served, as an unreachable feed does.
//! * **Every [`FEED_POLL_INTERVAL_MS`] after that**, while the daemon runs.
//! * **When an owner is revoked**, so the key it held stops being named as one that may remove the
//!   feed.
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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::Duration;

use kr_client::error::ClientError;
use kr_client::services::authority::{
    AuthorityFeedClient, AuthorityFeedRecord, AuthorityFeedState, RejectionReason,
};
use kr_client::services::{
    HttpDeadlines, HttpService, ServiceHttp, ServiceSigner, managed_response_limits,
};
use kr_crypto::keys::AuthorisationKeyPair;
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
use crate::grants::feed::{Beginning, FEED_POLL_INTERVAL_MS, RetainedRevocation};
use crate::quiet::{Quiet, Timer};
use crate::service::Controller;
use crate::service::remote_revocation::Judged;

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
/// hold the carrier.
const MOST_PAGES: usize = 32;

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
    quiet: Quiet,
    gate_wait: Duration,
    /// How many times a synchronisation has been asked for, by a connection or by the carrier.
    requested: AtomicU64,
    /// The newest request count that a pass which began after the request was made has finished.
    completed: tokio::sync::watch::Sender<u64>,
    wake: tokio::sync::Notify,
    removed: AtomicBool,
    /// The highest sequence of the feed up to which everything is settled.
    settled_through: AtomicU64,
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
    /// `key`. Nothing runs and nothing is sent until [`Self::run`].
    #[must_use]
    pub fn new(
        client: AuthorityFeedClient,
        origin: &GatewayOrigin,
        host_device_id: DeviceId,
        key: AuthorisationKeyPair,
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
                quiet: Quiet::new(Arc::clone(&timer)),
                gate_wait: GATE_WAIT,
                requested: AtomicU64::new(0),
                completed: tokio::sync::watch::channel(0).0,
                wake: tokio::sync::Notify::new(),
                removed: AtomicBool::new(false),
                settled_through: AtomicU64::new(0),
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

    /// A count of the passes the carrier has finished, which changes each time one ends.
    #[must_use]
    pub fn passes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.shared.passes.subscribe()
    }

    /// Tells the carrier to look again now, without anything waiting for it.
    pub fn wake(&self) {
        self.shared.wake.notify_one();
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
        shared.wake.notify_one();
        let mut completed = shared.completed.subscribe();
        let _ = tokio::time::timeout(shared.gate_wait, async {
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
        let now = kr_ipc::now_ms().get();
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
                    reads.stated("; it has not been read since this host started"),
                    Some("This host reads the feed by itself shortly."),
                )
            } else {
                (
                    DoctorStatus::Ok,
                    reads.stated("; ").sentence(&synchronised),
                    None,
                )
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

    /// What `kr doctor` says of a host that selects no authority feed.
    #[must_use]
    pub fn unconfigured_check() -> DoctorCheck {
        DoctorCheck::new(
            "authority-feed",
            "This host reads its remote revocations from its authority feed",
            DoctorStatus::NotApplicable,
            Sentence::new().stated(
                "no authority feed is selected, so a remote owner's revocation cannot reach this \
                 host; the owners paired with it revoke directly",
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

/// What the carrier does for as long as the daemon lives.
async fn drive(shared: Arc<Shared>, timer: Arc<dyn Timer>) {
    let mut backoff = Backoff::default();
    loop {
        // Every request made before this point is answered by the pass that follows it.
        let target = shared.requested.load(Ordering::SeqCst);
        let Some(controller) = shared.controller.get().and_then(Weak::upgrade) else {
            return;
        };
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
                Ok(Pass::Removed) => None,
                Err(stopped) => {
                    if stopped != Stopped::Local {
                        controller.authority_feed_unreachable();
                    }
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
        shared.completed.send_replace(target);
        shared.passes.send_modify(|passes| *passes += 1);
        if shared.requested.load(Ordering::SeqCst) > target {
            continue;
        }
        match wait {
            Some(duration) => {
                tokio::select! {
                    () = shared.wake.notified() => {}
                    () = timer.sleep(duration) => {}
                }
            }
            None => shared.wake.notified().await,
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
    let mut unfinished = false;
    let mut cursor = shared.settled_through.load(Ordering::SeqCst);
    let mut through = cursor;
    let mut contiguous = true;
    let mut latest = None;
    for _ in 0..MOST_PAGES {
        let state = shared
            .client
            .read(shared.own_feed, (cursor > 0).then_some(cursor), false)
            .await
            .map_err(|error| Stopped::of(&error, &shared.quiet))?;
        if state.summary.removed {
            controller.authority_feed_removed(&shared.origin).await;
            shared.removed.store(true, Ordering::SeqCst);
            return Ok(Pass::Removed);
        }
        let mut now = Latest::of(&state);
        for record in &state.records {
            if settle(shared, controller, record, &mut now).await? {
                if contiguous {
                    through = record.sequence.get();
                }
            } else {
                contiguous = false;
                unfinished = true;
            }
        }
        cursor = state.next_after_sequence.get();
        latest = Some(now);
        if !state.more {
            break;
        }
    }
    shared.settled_through.store(through, Ordering::SeqCst);
    if let Some(latest) = latest {
        name_owners(shared, controller, &latest).await?;
    }
    controller.authority_feed_synchronised(&shared.origin);
    shared.observed().stopped = None;
    Ok(if unfinished {
        Pass::Unfinished
    } else {
        Pass::Read
    })
}

/// Names the keys of the owners this host is paired with as the ones that may remove the feed,
/// when the feed lists others. The feed replaces the whole list, so one delegation is in flight at
/// a time, and what the feed lists on its answers is what is compared.
async fn name_owners(
    shared: &Arc<Shared>,
    controller: &Arc<Controller>,
    latest: &Latest,
) -> std::result::Result<(), Stopped> {
    let (named, beyond) = controller.owner_key_ids().map_err(Stopped::local)?;
    shared.observed().unnamed_owners = beyond;
    let mut wanted = named.clone();
    let mut listed = latest.removal_keys.clone();
    wanted.sort();
    listed.sort();
    if wanted == listed {
        return Ok(());
    }
    shared
        .client
        .delegate(&named)
        .await
        .map_err(|error| Stopped::of(&error, &shared.quiet))?;
    Ok(())
}

/// Settles one record the feed holds: refuses it, or carries it out and acknowledges it. Returns
/// whether the feed has nothing more to wait for on it.
async fn settle(
    shared: &Arc<Shared>,
    controller: &Arc<Controller>,
    record: &AuthorityFeedRecord,
    latest: &mut Latest,
) -> std::result::Result<bool, Stopped> {
    let request = &record.request;
    let id = request.request_id;
    if record.rejected.0.is_some() {
        return Ok(true);
    }
    if let Some(held) = record.acknowledgement.0.as_ref()
        && held.completion == RevocationCompletion::Complete
    {
        controller.authority_feed_settled(id, shared.host_device_id);
        return Ok(true);
    }
    let now = kr_ipc::now_ms().get();
    let plan = match controller.authority_feed_record(id) {
        Some(held) if held.request != *request => {
            return refuse(shared, controller, id, RejectionReason::Superseded, latest).await;
        }
        Some(_) => controller.plan_of(request).map_err(Stopped::local)?,
        None => match controller
            .judge_feed_request(request, now)
            .map_err(Stopped::local)?
        {
            Judged::Refuse(reason) => return refuse(shared, controller, id, reason, latest).await,
            Judged::Apply(plan) => plan,
        },
    };
    let beginning = controller
        .authority_feed_begin(
            request.clone(),
            AuthorityRevision::new(latest.revision),
            now,
        )
        .map_err(Stopped::local)?;
    let applied = controller
        .apply_feed_plan(&plan)
        .await
        .map_err(Stopped::local)?;
    #[cfg(feature = "testing")]
    controller.feed_request_was_carried_out().await;
    if beginning == Beginning::New && !applied.changed {
        // The owner at this machine had already withdrawn what it names. There is no revision to
        // issue for a request that changed nothing, and the registry is the one allocator.
        return refuse(shared, controller, id, RejectionReason::Superseded, latest).await;
    }
    let held = controller
        .authority_feed_took_effect(id, applied.revision)
        .map_err(Stopped::local)?;
    let number = held.authority_revision.unwrap_or(applied.revision);
    if latest.revision > number.get() {
        shared.observed().unissued = true;
        return Err(Stopped::Local);
    }
    shared.observed().unissued = false;
    let revision = revision_record(shared, &held, number, id);
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
        acknowledged_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
    };
    let state = shared
        .client
        .acknowledge(&acknowledgement, None)
        .await
        .map_err(|error| Stopped::of(&error, &shared.quiet))?;
    *latest = Latest::of(&state);
    if applied.completion == RevocationCompletion::Complete {
        controller.authority_feed_settled(id, shared.host_device_id);
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Refuses a record with a reason the publisher reads, and settles it here.
async fn refuse(
    shared: &Arc<Shared>,
    controller: &Arc<Controller>,
    id: RevocationRequestId,
    reason: RejectionReason,
    latest: &mut Latest,
) -> std::result::Result<bool, Stopped> {
    let state = shared
        .client
        .reject(id, reason)
        .await
        .map_err(|error| Stopped::of(&error, &shared.quiet))?;
    *latest = Latest::of(&state);
    controller.authority_feed_settled(id, shared.host_device_id);
    Ok(true)
}

/// The revision this host issues for one request, from what it wrote down before it began, so the
/// same record is issued again after a stop.
fn revision_record(
    shared: &Shared,
    held: &RetainedRevocation,
    number: AuthorityRevision,
    id: RevocationRequestId,
) -> AuthorityRevisionRecord {
    let mut record = AuthorityRevisionRecord {
        host_device_id: shared.host_device_id,
        authority_revision: number,
        previous_revision: held.previous_revision,
        applied_requests: [id].into_iter().collect::<CanonicalSet<_>>(),
        issued_at_ms: TimestampMs::new(held.applied_at_ms),
        host_key_id: shared.key.key_id(),
        signature: Signature64::from_bytes([0; 64]),
    };
    let input = record.signing_input().expect("a revision record encodes");
    let transcript = SigningTranscript::from_canonical_bytes(AUTHORITY_REVISION_DOMAIN, input)
        .expect("a transcript");
    record.signature = sign(&shared.key, &transcript).expect("a signature");
    record
}
