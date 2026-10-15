//! The keeper of this host's relay leases: one lease with the managed relay service for each device
//! this host has paired, kept for as long as the pairing stands.
//!
//! A relay carries encrypted payloads between two endpoints only while it holds a lease the service
//! signed for that pair, and only the service can issue one: it holds the ledger the bytes are
//! reserved from. The host is the paying side of every pair it belongs to, so it asks. This is when
//! it asks and what it does with the answer; the exchange itself is the client library's
//! ([`kr_client::services::RelayLeaseService`]).
//!
//! # What the keeper holds
//!
//! For each paired device, the lease the service issued for the pair of this host's endpoint and
//! the device's, and the endings the service has not yet answered. Both are kept in a record that
//! survives a restart ([`record`]), because a lease nothing remembers cannot be ended, and a host
//! that had forgotten it owed an ending would leave the pair carried until the lease ran out.
//!
//! # When it asks
//!
//! * **When a device is paired**, and when the daemon starts for a device paired before, so the
//!   managed relay can carry the pair from its first connection. The set of paired devices raises a
//!   signal each time it changes, and the keeper waits on it.
//! * **Before a lease runs out.** A lease lasts [`LEASE_SECONDS`]; the keeper refills it when
//!   [`REFILL_WHEN_LEFT`] or less of it remains, naming the lease it holds, so the service raises
//!   that reservation and never opens a second one. The service moves a lease's deadline only when
//!   the reservation's cumulative ceiling is raised, so a refill raises it by at least one byte:
//!   to what the relay had counted when the service last answered plus one block
//!   ([`BLOCK_BYTES`]), or by that byte when the pair is idle. An idle lease kept alive this way
//!   costs nothing while it lives and is settled from the relay's receipts when the host ends it; a
//!   lease left to run out is charged in full.
//! * **When a device is unpaired**, or when the account that pays is not the one the lease was
//!   asked for, it ends the lease. The ending is written down before it is sent and sent again,
//!   after any failure and after a restart, until the service answers.
//! * **Every [`POLL_INTERVAL`]**, so a change nothing woke the keeper for is found.
//!
//! A lease is refilled no oftener than [`MIN_ASK_GAP`], whatever the service answered, and a pass
//! that a device's pairing or revocation woke early does not send what is held back for a delay:
//! a signal brings forward the bookkeeping, not the next request to a service that asked to wait.
//! What a pass met decides what is held, whatever else it met: a failure holds every request for
//! the backoff, an answer only the owner or the calendar changes holds every ask for a lease for
//! [`STANDING_RETRY`], and an ending turned back for such a reason holds every request for it and
//! ends the pass.
//!
//! # What the answers mean
//!
//! A lease, with the deadline and the ceiling the service chose. An allowance that is spent, or a
//! service that could not issue a lease, is an answer about capacity and not a fault: the keeper
//! holds what it has, shows the owner the grace left and the paths that still work (a direct
//! connection, a relay the owner runs), and asks again after the delay the service named or
//! [`STANDING_RETRY`], whichever is longer. A refusal that only the owner can clear, such as a host
//! that names no account the service accepts, is shown the same way and is asked again as seldom. A
//! refusal that names a delay, or a service that cannot be reached, is waited out with the backoff
//! every carrier of this host uses, and a lease running out meanwhile stops forwarding for its pair
//! and nothing else: direct paths do not depend on it.
//!
//! The service answers `unavailable` to a refill for more than one reason: the relay carrying the
//! lease is no longer one it can bill through, the raise would pass the aggregate it holds
//! outstanding for the account, or the allowance does not cover it. It answers `INVALID_REQUEST`
//! when the raise would pass what the authorisation lets one lease hold outstanding, and also when
//! it does not carry the lease. The answer does not say which, so the keeper asks once more for the
//! ceiling the lease already holds, which the service answers as it stands unless the relay is
//! retired or the lease is not carried. If the lease stands, the raise was refused and not the
//! lease: the keeper keeps it, tells the owner, and tries the raise again after a wait. If the
//! relay is retired, it ends the lease and asks for the pair afresh in the same pass. If the lease
//! is not carried, it asks for the pair afresh.
//!
//! A lease that has run out is ended at the service before the pair is asked for again: the service
//! keeps its record of the lease until it is revoked, and a pair whose lease sits on a retired
//! relay is turned away for as long as that record stands. A refill that the service finds past its
//! deadline, because this host's clock is behind the service's, is answered with a new lease whose
//! reservation holds the ceiling the refill asked for, within the bound of the authorisation. The
//! same lease is found by the request that asks for the pair afresh when the answer to the refill
//! was lost. The keeper ends it and asks for the pair afresh, so the pair holds a block and not the
//! figures of a reservation that is gone. The ended lease holds its bytes until the service has
//! settled it, so the new request can find the account without room, and the pair then waits as for
//! any answer about capacity. If the service answers the revocation as a lease it does not carry,
//! which it does when the lease changed meanwhile, the lease is kept.
//!
//! A row for a pair that is no longer paired is asked about only until no lease its requests could
//! have issued is alive: a request that issued nothing leaves the time of the row as it was, and
//! an answer about capacity holds the next request for [`STANDING_RETRY`].
//!
//! A request whose answer was lost may have issued a lease, or have revised the lease it named into
//! another. The keeper has not written down a lease identifier it was not told, so it asks again
//! for the same pair, and the service answers with the lease the pair already holds. The row is
//! written again with the time of each request, before it is sent, and with none once the answer is
//! seen. It stays until the longest a lease can live has passed since the last request whose answer
//! was not seen, whatever the later answers say, so a device unpaired in the meantime still has its
//! lease ended, also when the lease the row names is another. The same holds after a restart, and
//! for a change of payer: the pair is asked again under the payer the row was kept for, the lease
//! it finds is ended, and only then is the pair asked for under the new payer, because the service
//! refuses another authorisation of the same account for a pair whose lease stands. If the service
//! turns the old payer back, no lease can be alive under it and the row is dropped.

pub mod record;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

use kr_client::error::ClientError;
use kr_client::services::relay::ManagedRelayLeaseService;
use kr_client::services::{
    HttpDeadlines, HttpService, LeaseEndReason, LeasePayer, LeaseRequest, RelayDirection,
    RelayLeaseAnswer, RelayLeaseGrant, RelayLeaseRefusal, RelayLeaseService, ServiceHttp,
    ServiceSigner, managed_response_limits,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};
use kr_protocol::ids::RelayLeaseId;
use kr_protocol::scalars::EndpointKey;
use kr_protocol::service::GatewayOrigin;
use kr_transport::config::ProxyUrl;
use kr_transport::reconnect::Backoff;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

use crate::error::{ControllerError, Result};
use crate::quiet::{Quiet, Timer};
use crate::service::Controller;
use crate::service::net::devices::{DeviceDirectory, DeviceRecord};
use record::{Ending, Record, Row};

/// The deadlines the lease service's exchanges are made under. A lease request waits on the
/// service's ledger and on the relay that installs the lease, so it is given longer than the
/// feed's.
pub const RELAY_DEADLINES: HttpDeadlines = HttpDeadlines {
    connect: Duration::from_secs(5),
    read: Duration::from_secs(25),
    total: Duration::from_secs(30),
};

/// How long a lease the keeper asks for lasts, in seconds: the longest the service issues.
pub const LEASE_SECONDS: u32 = 900;

/// The keeper refills a lease when this much of it or less remains: a third of its life has
/// passed, which leaves time for further tries before the lease runs out.
pub const REFILL_WHEN_LEFT: Duration = Duration::from_secs(600);

/// The bytes the keeper reserves for a pair beyond what the relay has counted for it. A principal
/// holds at most 8 MiB outstanding across all its leases, so sixteen idle leases of this size hold
/// all of it and none can be raised by a byte: fifteen can be kept alive. A pair that is carrying
/// traffic is given a block
/// beyond what the relay counted at the last answer, so a pair that spends its whole block between
/// two refills is given one byte at the first and a block at the second.
pub const BLOCK_BYTES: u64 = 512 * 1024;

/// The bytes a refill raises the ceiling by at least, because the service moves a lease's
/// deadline only when the reservation's ceiling is raised.
const IDLE_RAISE: u64 = 1;

/// The requests one ask may make for one pair: the refill, the request that finds out why it was
/// turned back, the new request, and the new request after a replacement was ended.
const ATTEMPTS: usize = 4;

/// How often the keeper reads the paired devices when nothing woke it.
pub const POLL_INTERVAL: Duration = Duration::from_secs(60);

/// The fewest seconds between two refills of one pair's lease, whatever the service answered. A
/// refill that was turned back is followed at once by the request that finds out why, and by the
/// request for a new lease when the old one is gone.
pub const MIN_ASK_GAP: Duration = Duration::from_secs(60);

/// How long the keeper leaves the service alone after an answer only the owner or the calendar can
/// change: an allowance that is spent, a service that could not issue a lease, or a refusal of the
/// host's request.
pub const STANDING_RETRY: Duration = Duration::from_secs(5 * 60);

/// How many times an ending is sent again when the service answers that it never issued the lease,
/// and for at least how long ([`LONGEST_LEASE_MS`]), before the host takes that for the truth. The
/// service gives the same answer, in the same code, when a revocation raced a refill and should be
/// asked again, so the answer proves the lease absent only once no lease the service could have
/// held then is still alive.
const UNKNOWN_ENDING_TRIES: u32 = 3;

/// The longest a lease can live, in milliseconds, with the margin two clocks may differ by.
const LONGEST_LEASE_MS: u64 = (LEASE_SECONDS as u64 + 100) * 1000;

/// The most a cumulative byte count may be: the largest whole number the service carries exactly.
const COUNTER_LIMIT: u64 = (1 << 53) - 1;

/// Builds the lease client for `origin`, signing as the host.
///
/// # Errors
///
/// Returns [`ControllerError::NotConfigured`] when the transport cannot be built, which is a fault
/// in this machine's TLS configuration rather than in the service.
pub fn managed_service(
    origin: &GatewayOrigin,
    proxy: Option<&ProxyUrl>,
    signer: Arc<dyn ServiceSigner>,
) -> Result<Arc<dyn RelayLeaseService>> {
    let http: Arc<dyn ServiceHttp> = Arc::new(
        HttpService::through(
            origin.clone(),
            RELAY_DEADLINES,
            managed_response_limits(),
            proxy,
        )
        .map_err(|error| {
            ControllerError::NotConfigured(format!(
                "{} in this host's configuration document ({}) names a service no transport \
                 reaches: {error}",
                kr_protocol::hostinfo::configuration::RELAY_ORIGIN.key,
                kr_protocol::hostinfo::configuration::FILE_NAME,
            ))
        })?,
    );
    Ok(Arc::new(ManagedRelayLeaseService::new(
        origin.clone(),
        http,
        signer,
    )))
}

/// What the owner is told about the last answer that was not a lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    /// The payer's allowance is spent.
    Exhausted {
        /// When the grace ends, in UTC milliseconds on this host's clock.
        grace_ends_ms: Option<u64>,
        /// The bytes of grace the service said were left.
        grace_bytes: Option<u64>,
    },
    /// The service could not issue a lease: no relay to offer, or no room for one more.
    NoLease,
    /// The service has no room for the raise a lease needs, and the lease it has stands.
    NoRoom,
    /// The service turned the request back, and only the owner can change that.
    Refused(ErrorCode),
    /// The service refused to raise a lease: the authorisation lets one lease hold less
    /// outstanding than a refill needs, or the lease changed while the request was handled.
    Bound,
}

/// What the doctor says of the keeper.
#[derive(Debug, Default)]
struct Observed {
    /// How many paired devices there were at the last pass.
    paired: usize,
    /// When each lease the host holds stops being valid, in UTC milliseconds.
    expiries: Vec<u64>,
    /// When the earliest lease of those held is due for a refill, in UTC milliseconds.
    next_refill_ms: Option<u64>,
    /// How many endings the service has not answered.
    endings_owed: usize,
    /// The last answer that was not a lease, when nothing since replaced it.
    standing: Option<Standing>,
    /// Whether the service did not answer at the last pass, or asked the host to wait.
    unreachable: bool,
    /// Whether the host could not read or write its own records.
    local_fault: bool,
    /// The highest allowance warning the service raised in its last answer, in percent.
    warning: Option<u32>,
    /// The grace the service said was left to connections already running when it last granted a
    /// lease: when it ends, in UTC milliseconds on this host's clock, and the bytes left.
    grace: Option<(u64, u64)>,
}

/// How long requests wait, by the timer's clock.
#[derive(Clone, Copy, Debug, Default)]
struct Holds {
    /// No request of any kind: the service could not be reached, or asked the host to wait.
    requests: Option<Instant>,
    /// No request for a lease: the service answered something only the owner or the calendar
    /// changes.
    asks: Option<Instant>,
}

/// What the keeper was given when the daemon went on the network.
struct Running {
    controller: Weak<Controller>,
    devices: Arc<DeviceDirectory>,
    endpoint: EndpointKey,
}

/// What the keeper shares with the daemon.
struct Shared {
    service: Arc<dyn RelayLeaseService>,
    origin: String,
    payer: Option<LeasePayer>,
    record: Arc<Record>,
    timer: Arc<dyn Timer>,
    quiet: Quiet,
    wake: Notify,
    passes: watch::Sender<u64>,
    /// How many passes have been asked for, by whoever needs to know the keeper has looked since.
    requested: AtomicU64,
    /// The newest request count that a pass which began after the request was made has finished.
    completed: watch::Sender<u64>,
    holds: Mutex<Holds>,
    /// When each pair was last asked for, in UTC milliseconds on this host's clock.
    asked_at: Mutex<BTreeMap<[u8; 32], u64>>,
    /// How each ending that was answered "never issued" has fared: how many times, when first and
    /// when last.
    unknown_endings: Mutex<BTreeMap<[u8; 16], UnknownEnding>>,
    observed: Mutex<Observed>,
    running: OnceLock<Running>,
}

/// An ending the service answered "never issued".
#[derive(Clone, Copy, Debug)]
struct UnknownEnding {
    answers: u32,
    /// When it was first answered so, in UTC milliseconds on this host's clock.
    first_ms: u64,
    /// When it was last answered so, on the timer's clock.
    last: Instant,
}

impl Shared {
    fn observed(&self) -> std::sync::MutexGuard<'_, Observed> {
        self.observed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn holds(&self) -> std::sync::MutexGuard<'_, Holds> {
        self.holds.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The account and the authorisation the leases are asked for under, which a row is kept with
    /// so that a change of payer is found and a request that may have been answered is asked again
    /// under the payer it was made for.
    fn payer_key(&self) -> Option<String> {
        match &self.payer {
            Some(LeasePayer::Account {
                account_id,
                authorisation_id,
            }) => Some(format!("{account_id}/{authorisation_id}")),
            _ => None,
        }
    }

    /// When the pair was last asked for.
    fn last_asked(&self, destination: &EndpointKey) -> Option<u64> {
        self.asked_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(destination.as_bytes())
            .copied()
    }

    fn note_asked(&self, destination: &EndpointKey, at_ms: u64) {
        self.asked_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(*destination.as_bytes(), at_ms);
    }

    /// Runs a read or a write of the record where it cannot hold a reactor thread.
    async fn on_record<T: Send + 'static>(
        &self,
        body: impl FnOnce(&Record) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let record = Arc::clone(&self.record);
        tokio::task::spawn_blocking(move || body(&record))
            .await
            .map_err(|_| ControllerError::registry("the relay lease record could not be reached"))?
    }
}

/// The keeper of the host's relay leases.
pub struct RelayKeeper {
    shared: Arc<Shared>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for RelayKeeper {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayKeeper")
            .field("origin", &self.shared.origin)
            .finish_non_exhaustive()
    }
}

impl RelayKeeper {
    /// Builds the keeper of the leases at `origin`, asking for them under `payer`. Nothing runs and
    /// nothing is sent until [`Self::run`].
    #[must_use]
    pub fn new(
        service: Arc<dyn RelayLeaseService>,
        origin: &GatewayOrigin,
        payer: Option<LeasePayer>,
        record: Record,
        timer: Arc<dyn Timer>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                service,
                origin: origin.as_str().to_owned(),
                payer,
                record: Arc::new(record),
                quiet: Quiet::new(Arc::clone(&timer)),
                timer,
                wake: Notify::new(),
                passes: watch::channel(0).0,
                requested: AtomicU64::new(0),
                completed: watch::channel(0).0,
                holds: Mutex::default(),
                asked_at: Mutex::default(),
                unknown_endings: Mutex::default(),
                observed: Mutex::default(),
                running: OnceLock::new(),
            }),
            task: Mutex::new(None),
        }
    }

    /// Starts the keeper for a daemon that is on the network at `endpoint`, serving the devices in
    /// `devices`. It does nothing the second time.
    pub fn run(
        &self,
        controller: &Arc<Controller>,
        devices: Arc<DeviceDirectory>,
        endpoint: EndpointKey,
    ) {
        if self
            .shared
            .running
            .set(Running {
                controller: Arc::downgrade(controller),
                devices,
                endpoint,
            })
            .is_err()
        {
            return;
        }
        let task = tokio::spawn(drive(Arc::clone(&self.shared)));
        *self.task.lock().unwrap_or_else(PoisonError::into_inner) = Some(task);
    }

    /// A count of the passes the keeper has finished, which changes each time one ends.
    #[must_use]
    pub fn passes(&self) -> watch::Receiver<u64> {
        self.shared.passes.subscribe()
    }

    /// Waits until the keeper has finished a pass that began after this call, so that whatever
    /// was true when it was made is what the pass read. For a suite that arranges the world
    /// and then needs the keeper to have looked at it.
    #[cfg(feature = "testing")]
    pub async fn after_a_pass(&self) {
        let ticket = self.shared.requested.fetch_add(1, Ordering::SeqCst) + 1;
        let mut completed = self.shared.completed.subscribe();
        self.shared.wake.notify_one();
        while *completed.borrow_and_update() < ticket {
            if completed.changed().await.is_err() {
                return;
            }
        }
    }

    /// What `kr doctor` says of the keeper.
    #[must_use]
    pub fn doctor_check(&self, controller: &Controller) -> DoctorCheck {
        let observed = self.shared.observed();
        let title = "This host keeps a relay lease for each paired device";
        if self.shared.running.get().is_none() {
            return DoctorCheck::new(
                "relay-leases",
                title,
                DoctorStatus::NotApplicable,
                Sentence::new().stated(
                    "this host is not on the network, so no device can be paired and it keeps no \
                     lease",
                ),
                None,
            );
        }
        let now = controller.wall_now_ms();
        let held = observed
            .expiries
            .iter()
            .filter(|expires| **expires > now)
            .count();
        let mut detail = Sentence::new()
            .stated("this host holds a relay lease for ")
            .number(held as u64)
            .stated(" of ")
            .number(observed.paired as u64)
            .stated(" paired devices");
        if let Some(due) = observed.next_refill_ms {
            detail = detail
                .stated("; the next refill is due in ")
                .number(due.saturating_sub(now) / 1000)
                .stated(" seconds");
        }
        if observed.endings_owed > 0 {
            detail = detail
                .stated("; ")
                .number(observed.endings_owed as u64)
                .stated(" lease(s) wait to be ended at the service");
        }
        let warned = observed.warning.is_some();
        if let Some(percent) = observed.warning {
            detail = detail
                .stated("; the allowance of the account that pays has passed ")
                .number(u64::from(percent))
                .stated(" percent");
        }
        if let Some((ends, bytes)) = observed.grace
            && ends > now
            && !matches!(observed.standing, Some(Standing::Exhausted { .. }))
        {
            detail = detail
                .stated("; the grace left to a connection already running is ")
                .number((ends - now) / 1000)
                .stated(" seconds, or ")
                .number(bytes)
                .stated(" bytes at the last answer");
        }
        let (status, remedy) = if observed.local_fault {
            (
                DoctorStatus::Warning,
                Some(
                    "This host could not read or write its record of leases, so it asks the \
                     service for nothing it cannot write down. It tries again by itself.",
                ),
            )
        } else if let Some(standing) = observed.standing {
            detail = match standing {
                Standing::Exhausted {
                    grace_ends_ms,
                    grace_bytes,
                } => {
                    let mut detail = detail.stated(
                        "; the allowance of the account that pays is spent, so the service issues \
                         no new lease",
                    );
                    if let Some(ends) = grace_ends_ms {
                        detail = if ends > now {
                            detail
                                .stated("; the grace left to a connection already running is ")
                                .number((ends - now) / 1000)
                                .stated(" seconds")
                        } else {
                            detail.stated("; the grace for a connection already running has ended")
                        };
                    }
                    if let Some(bytes) = grace_bytes {
                        detail = detail
                            .stated(", or ")
                            .number(bytes)
                            .stated(" bytes at the last answer");
                    }
                    detail
                }
                Standing::NoLease => detail.stated(
                    "; the service could not issue a lease: it has no relay to offer, or no room \
                     for one more for the account that pays",
                ),
                Standing::Refused(ErrorCode::PermissionDenied) => detail.stated(
                    "; the service turned this host's request back: the account that pays, the \
                     authorisation for this host's key, this machine's clock or the service \
                     origin is not one it accepts",
                ),
                Standing::NoRoom => detail.stated(
                    "; the service could not raise a lease: the account that pays has no room for \
                     it, because of the bytes it holds outstanding across its leases or its \
                     allowance",
                ),
                Standing::Bound => detail.stated(
                    "; the service refused to raise a lease: the authorisation lets one lease hold \
                     too little for it to be extended, or the lease changed while the request was \
                     handled, and a lease the service cannot extend runs out at its whole hold",
                ),
                Standing::Refused(ErrorCode::HostNotConfigured) => detail
                    .stated("; the service answered that it is not set up to issue relay leases"),
                Standing::Refused(_) => detail.stated(
                    "; the service turned this host's request back as one it does not accept",
                ),
            };
            let remedy = match standing {
                Standing::Exhausted { .. } | Standing::NoLease | Standing::NoRoom => {
                    "A direct connection between the devices needs no relay, and so does a relay \
                     you run yourself. This host asks the service again by itself."
                }
                Standing::Refused(ErrorCode::PermissionDenied) => {
                    "Check that `relay.payer` in the configuration document names an authorisation \
                     given to this host's key and still in force, that `relay.origin` is the \
                     service you mean, and that this machine's clock is right, and start the \
                     daemon again. The daemon's log has the service's own words. This host asks \
                     the service again by itself."
                }
                Standing::Bound => {
                    "Give the authorisation a byte bound above 512 KiB; 1 MiB is the smallest \
                     sensible value. This host asks the service again by itself."
                }
                Standing::Refused(_) => {
                    "Check `relay.origin` in the configuration document and that this host is \
                     up to date. This host asks the service again by itself."
                }
            };
            (DoctorStatus::Warning, Some(remedy))
        } else if observed.unreachable {
            detail = detail.stated(
                "; the service did not answer, or asked this host to wait, so a lease that runs \
                 out is not refilled until it can be",
            );
            (
                DoctorStatus::Warning,
                Some(
                    "A lease that runs out stops the relay carrying its pair and nothing else: \
                     direct connections are not affected. This host asks again by itself.",
                ),
            )
        } else if warned {
            (
                DoctorStatus::Warning,
                Some(
                    "The account that pays is close to its monthly relay allowance. Past it, no \
                     new lease is issued and a connection that is running has a short grace.",
                ),
            )
        } else {
            (DoctorStatus::Ok, None)
        };
        DoctorCheck::new("relay-leases", title, status, detail, remedy)
    }

    /// What `kr doctor` says of a host that selects no relay lease service.
    #[must_use]
    pub fn unconfigured_check() -> DoctorCheck {
        DoctorCheck::new(
            "relay-leases",
            "This host keeps a relay lease for each paired device",
            DoctorStatus::NotApplicable,
            Sentence::new().stated(
                "no relay lease service is selected, so this host asks for no lease; a device \
                 reaches it directly or through a relay its owner runs",
            ),
            None,
        )
    }
}

impl Drop for RelayKeeper {
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

/// What the keeper does for as long as the daemon lives.
async fn drive(shared: Arc<Shared>) {
    let mut backoff = Backoff::default();
    loop {
        let Some(running) = shared.running.get() else {
            return;
        };
        let Some(controller) = running.controller.upgrade() else {
            return;
        };
        // Every request made before this point is answered by the pass that follows it.
        let target = shared.requested.load(Ordering::SeqCst);
        let wait = if let Some(left) = shared.quiet.left() {
            // The service asked to be left alone, and every question to it waits.
            left
        } else {
            let report = pass(&shared, running, &controller).await;
            let now = shared.timer.now();
            let mut wait = match report.next {
                Next::Failed => backoff.next_delay(),
                Next::Standing => STANDING_RETRY,
                Next::Due(wait) => {
                    if report.asked {
                        backoff = Backoff::default();
                    }
                    wait
                }
            };
            // What the pass met decides the holds, whatever else it met: a failure holds every
            // request for the backoff; an answer only the owner or the calendar changes holds the
            // asks for the standing interval, so a pair that was turned back is not asked again at
            // the pace of another pair's backoff; and an ending turned back for a reason only the
            // owner can change holds every request for the standing interval, so that no signal
            // sends it again.
            {
                let mut holds = shared.holds();
                if report.next == Next::Failed {
                    holds.requests = now.checked_add(wait);
                }
                if report.met_a_standing {
                    holds.asks = now.checked_add(STANDING_RETRY);
                }
                if report.refused_an_ending {
                    holds.requests = now.checked_add(STANDING_RETRY);
                    wait = wait.max(STANDING_RETRY);
                }
            }
            shared
                .completed
                .send_modify(|completed| *completed = (*completed).max(target));
            wait.max(shared.quiet.left().unwrap_or_default())
        };
        drop(controller);
        // The wait is asked for before the pass is counted, so whoever sees the count change finds
        // the keeper waiting.
        let sleeping = shared.timer.sleep(wait);
        tokio::pin!(sleeping);
        shared.passes.send_modify(|passes| *passes += 1);
        // Interest in a change is registered before the wait starts, so a device paired in
        // between either shortens the wait or is seen by the next pass: none is lost. The keeper
        // is the only task that waits on the directory's signal.
        let changed = running.devices.changed();
        let device_changed = changed.notified();
        tokio::pin!(device_changed);
        device_changed.as_mut().enable();
        let woken = shared.wake.notified();
        tokio::pin!(woken);
        woken.as_mut().enable();
        tokio::select! {
            () = &mut device_changed => {}
            () = &mut woken => {}
            () = &mut sleeping => {}
        }
    }
}

/// When the keeper looks again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Next {
    /// After this long: the earliest refill that can be asked for, or the poll interval.
    Due(Duration),
    /// After the service could not be reached, or asked for a delay.
    Failed,
    /// After an answer the owner or the calendar must change.
    Standing,
}

/// How a pass ended.
struct Report {
    next: Next,
    /// Whether the pass made a request and none of them failed.
    asked: bool,
    /// Whether the service turned an ending back for a reason only the owner can change.
    refused_an_ending: bool,
    /// Whether the pass met an answer only the owner or the calendar changes, whatever else it met.
    met_a_standing: bool,
}

/// What a failed request means for the pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    /// The service answered that it did not act, and why.
    NotActed(ErrorCode),
    /// The service may have acted: its answer did not come, or could not be read.
    MayHaveActed,
}

fn failure_of(error: &ClientError, quiet: &Quiet) -> Failure {
    if let ClientError::Refused {
        error: refused,
        retry_after_seconds,
        ..
    } = error
    {
        if let Some(seconds) = retry_after_seconds {
            quiet.owe(Duration::from_secs(*seconds));
        }
        return match refused.code {
            code @ (ErrorCode::PermissionDenied
            | ErrorCode::InvalidArgument
            | ErrorCode::HostNotConfigured
            | ErrorCode::RateLimited
            | ErrorCode::QuotaExceeded) => Failure::NotActed(code),
            _ => Failure::MayHaveActed,
        };
    }
    Failure::MayHaveActed
}

/// Whether a refusal is one that waits for the owner, as against one that waits for the service.
const fn needs_the_owner(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::PermissionDenied | ErrorCode::HostNotConfigured | ErrorCode::InvalidArgument
    )
}

/// One pass: end what is owed, read the paired devices, and give each the lease it is due.
async fn pass(shared: &Arc<Shared>, running: &Running, controller: &Arc<Controller>) -> Report {
    let outcome = Box::pin(reconcile(shared, running, controller)).await;
    match outcome {
        Ok(report) => {
            shared.observed().local_fault = false;
            report
        }
        Err(error) => {
            eprintln!("kr-controller: the relay lease keeper could not use its record: {error}");
            shared.observed().local_fault = true;
            Report {
                next: Next::Failed,
                asked: false,
                refused_an_ending: false,
                met_a_standing: false,
            }
        }
    }
}

/// How long until `until` on the timer's clock, in milliseconds.
fn left_ms(until: Option<Instant>, now: Instant) -> u64 {
    until
        .and_then(|until| until.checked_duration_since(now))
        .map_or(0, |left| {
            u64::try_from(left.as_millis()).unwrap_or(u64::MAX)
        })
}

async fn reconcile(
    shared: &Arc<Shared>,
    running: &Running,
    controller: &Arc<Controller>,
) -> Result<Report> {
    let now = controller.wall_now_ms();
    let holds = *shared.holds();
    let timer_now = shared.timer.now();
    let requests_held_ms = left_ms(holds.requests, timer_now);
    let asks_held_ms = left_ms(holds.asks, timer_now).max(requests_held_ms);
    let mut unreachable = false;
    let mut standing = None;
    let mut asked = false;
    let mut refusals = 0_u32;
    let refill_ms = u64::try_from(REFILL_WHEN_LEFT.as_millis()).unwrap_or(u64::MAX);
    let gap_ms = u64::try_from(MIN_ASK_GAP.as_millis()).unwrap_or(u64::MAX);

    let devices = Arc::clone(&running.devices);
    let paired: Vec<_> = tokio::task::spawn_blocking(move || devices.devices())
        .await
        .map_err(|_| ControllerError::registry("the device records could not be reached"))??
        .into_iter()
        .filter(DeviceRecord::is_paired)
        .collect();
    let is_paired =
        |endpoint: &EndpointKey| paired.iter().any(|device| device.endpoint_id == *endpoint);
    let payer_key = shared.payer_key();
    // A row whose device is no longer paired, or whose lease was asked for under another payer or
    // for another host key, is a lease to end. So is a lease that has run out: the service settled
    // its reservation, but it keeps its record of the lease until it is revoked, and a pair whose
    // lease sits on a retired relay is turned away for as long as that record stands.
    //
    // A row that holds the time of a request the host never saw answered, whether or not it names a
    // lease, may stand for a lease the service holds that the host does not know of, until the
    // longest a lease lives has passed since that request. Asking is how the host learns which, and
    // the ask is made under the payer the row was kept for, never under the current one: the
    // service finds a pair's lease within the account that pays, and refuses another authorisation
    // of that account for as long as it stands. For a device that is no longer paired, and for one
    // whose payer changed, the ask ends what it finds. Where the host's own endpoint has changed
    // the pair cannot be asked for at all, and the row is dropped; the lease, if there was one,
    // runs out by itself.
    let mut unwanted = Vec::new();
    for row in shared.on_record(Record::rows).await? {
        let same_source = row.source == running.endpoint;
        let same_payer = row.payer == payer_key;
        let device_is_paired = is_paired(&row.destination);
        let destination = row.destination;
        if same_source && same_payer && device_is_paired {
            if let Some(lease) = row.lease_id
                && row.expires_at_ms <= now
            {
                shared
                    .on_record(move |record| {
                        record.end(&destination, lease, LeaseEndReason::Finished)
                    })
                    .await?;
            }
            continue;
        }
        let reason = if device_is_paired {
            LeaseEndReason::PayerWithdrew
        } else {
            LeaseEndReason::Unpaired
        };
        let may_hold_another = row.written_at_ms > 0
            && now.saturating_sub(row.written_at_ms) <= LONGEST_LEASE_MS
            && same_source;
        match row.lease_id {
            Some(lease) => {
                let recovery = Row {
                    lease_id: None,
                    ceiling: BLOCK_BYTES,
                    consumed: 0,
                    expires_at_ms: 0,
                    ..row
                };
                shared
                    .on_record(move |record| {
                        record.end(&destination, lease, reason)?;
                        if may_hold_another {
                            record.save(&recovery)?;
                        }
                        Ok(())
                    })
                    .await?;
                if may_hold_another {
                    shared.wake.notify_one();
                }
            }
            None if may_hold_another => unwanted.push((row, reason)),
            None => {
                shared
                    .on_record(move |record| record.forget(&destination))
                    .await?;
            }
        }
    }

    // What the service is owed an ending for goes before anything is asked of it, so a pair it
    // still carries after its device was unpaired is not left waiting behind the asks below.
    let mut refused_an_ending = false;
    if requests_held_ms == 0 {
        match send_owed_endings(shared, now, &mut asked).await? {
            Owed::Sent => {}
            Owed::Later => unreachable = true,
            Owed::Refused(code) => {
                standing = Some(Standing::Refused(code));
                refused_an_ending = true;
            }
        }
    }

    // An ending the service turned back for a reason only the owner can change ends the pass's
    // requests: what else it would ask is turned back for the same reason.
    if asks_held_ms == 0 && !unreachable && !refused_an_ending {
        let mut recovered = false;
        for (row, reason) in unwanted {
            asked = true;
            let foreign = row.payer != payer_key;
            let destination = row.destination;
            match ask(shared, running, controller, row, Some(reason)).await? {
                Asked::Held => recovered = true,
                Asked::Later => {
                    unreachable = true;
                    break;
                }
                Asked::EndingRefused(code) => {
                    standing = Some(Standing::Refused(code));
                    refused_an_ending = true;
                    break;
                }
                // The service turns the old payer back: the authorisation is withdrawn or was
                // never the host's, and no lease can be alive under it. The row is done with.
                Asked::Standing(Standing::Refused(_)) if foreign => {
                    shared
                        .on_record(move |record| record.forget(&destination))
                        .await?;
                }
                Asked::Standing(why) => {
                    standing = Some(why);
                    break;
                }
            }
        }
        // The lease a recovery ask found is ended before the pair is asked for under the payer
        // now in force, which the service would refuse while the old lease stands.
        if recovered && requests_held_ms == 0 && !unreachable && !refused_an_ending {
            match send_owed_endings(shared, now, &mut asked).await? {
                Owed::Sent => {}
                Owed::Later => unreachable = true,
                Owed::Refused(code) => {
                    standing = Some(Standing::Refused(code));
                    refused_an_ending = true;
                }
            }
        }
    }

    let rows = shared.on_record(Record::rows).await?;
    // When each paired device can next be asked for, in milliseconds from now, and whether it is
    // asked for in this pass.
    let mut soonest: Option<u64> = None;
    if !unreachable && !refused_an_ending {
        // The leases the host holds are refilled before a pair with none is asked for, so a pair
        // the service has no room for does not keep the rest from being refilled.
        let mut ordered: Vec<&DeviceRecord> = paired.iter().collect();
        ordered.sort_by_key(|device| {
            !rows
                .iter()
                .any(|row| row.destination == device.endpoint_id && row.lease_id.is_some())
        });
        for device in ordered {
            let row = rows
                .iter()
                .find(|row| row.destination == device.endpoint_id)
                .cloned();
            let due_at = row.as_ref().map_or(now, |row| match row.lease_id {
                Some(_) => row.expires_at_ms.saturating_sub(refill_ms),
                None => now,
            });
            // A lease is refilled no oftener than the gap, whatever the service answered. A pair
            // that holds none is asked for again as the backoff allows: an answer that was lost
            // is not one to wait a minute over.
            let held_lease = row.as_ref().is_some_and(|row| row.lease_id.is_some());
            let ready_at = shared
                .last_asked(&device.endpoint_id)
                .filter(|_| held_lease)
                .map_or(due_at, |last| {
                    // A clock set back does not hold a pair back for longer than the gap.
                    let allowed = if last > now { now } else { last + gap_ms };
                    due_at.max(allowed)
                })
                .max(now + asks_held_ms);
            if ready_at > now {
                soonest = Some(soonest.map_or(ready_at, |soonest| soonest.min(ready_at)));
                continue;
            }
            let row = row.unwrap_or_else(|| Row {
                source: running.endpoint,
                destination: device.endpoint_id,
                lease_id: None,
                payer: payer_key.clone(),
                ceiling: BLOCK_BYTES,
                consumed: 0,
                expires_at_ms: 0,
                written_at_ms: now,
            });
            asked = true;
            match ask(shared, running, controller, row, None).await? {
                Asked::Held => {}
                Asked::Later => {
                    unreachable = true;
                    break;
                }
                Asked::EndingRefused(code) => {
                    standing = Some(Standing::Refused(code));
                    refused_an_ending = true;
                    break;
                }
                // A raise that is turned back for want of room, or for the bound on one lease,
                // says nothing of the leases after it: one that needs less may be raised.
                Asked::Standing(why @ (Standing::NoLease | Standing::NoRoom | Standing::Bound))
                    if held_lease =>
                {
                    standing = Some(why);
                }
                Asked::Standing(Standing::Refused(code)) => {
                    // A refusal can be about one pair, so the next device is asked; two in one pass
                    // are the account or the host's key being turned away, and the rest wait.
                    standing = Some(Standing::Refused(code));
                    refusals += 1;
                    if refusals >= 2 {
                        break;
                    }
                }
                Asked::Standing(why) => {
                    standing = Some(why);
                    break;
                }
            }
        }
    }

    let rows = shared.on_record(Record::rows).await?;
    let owed = shared.on_record(Record::endings).await?.len();
    let expiries: Vec<u64> = paired
        .iter()
        .filter_map(|device| {
            rows.iter()
                .find(|row| row.destination == device.endpoint_id && row.lease_id.is_some())
                .map(|row| row.expires_at_ms)
        })
        .collect();
    let next_refill = expiries
        .iter()
        .map(|expires| expires.saturating_sub(refill_ms))
        .min();
    {
        let mut observed = shared.observed();
        observed.paired = paired.len();
        observed.expiries = expiries;
        observed.next_refill_ms = next_refill;
        observed.endings_owed = owed;
        // What was said stays until a pass that reached the service has nothing to say. A pass
        // that sent nothing, because a delay is being waited out, says nothing.
        if asked || requests_held_ms == 0 {
            observed.unreachable = unreachable;
        }
        if (!unreachable || standing.is_some()) && (asks_held_ms == 0 || refused_an_ending) {
            observed.standing = standing;
        }
    }
    let next = if unreachable {
        Next::Failed
    } else if standing.is_some() {
        Next::Standing
    } else {
        let until = [soonest, next_refill.filter(|due| *due > now)]
            .into_iter()
            .flatten()
            .min()
            .map_or(POLL_INTERVAL, |at| {
                Duration::from_millis(at.saturating_sub(now))
            });
        Next::Due(until.clamp(Duration::from_secs(1), POLL_INTERVAL))
    };
    Ok(Report {
        next,
        asked,
        refused_an_ending,
        met_a_standing: standing.is_some(),
    })
}

/// How sending what the service is owed an ending for went.
enum Owed {
    /// Every ending that is due was answered, or left to a later pass by its own wait.
    Sent,
    /// The service could not be reached, or asked for a delay.
    Later,
    /// The service turned an ending back for a reason only the owner can change.
    Refused(ErrorCode),
}

/// Sends the endings the service has not answered, in the order they were owed, until one cannot
/// be answered.
async fn send_owed_endings(shared: &Arc<Shared>, now: u64, asked: &mut bool) -> Result<Owed> {
    for ending in shared.on_record(Record::endings).await? {
        if unknown_waits(shared, ending.lease_id) {
            continue;
        }
        *asked = true;
        match end(shared, ending, now).await? {
            Ended::Answered | Ended::Unknown => {}
            Ended::Later => return Ok(Owed::Later),
            Ended::OwnerMustLook(code) => return Ok(Owed::Refused(code)),
        }
    }
    Ok(Owed::Sent)
}

/// What an ending came to.
enum Ended {
    /// The service answered, or answered in a way that proves there is nothing of that name to end.
    Answered,
    /// The service answered that it never issued the lease, and the host has not yet asked often
    /// enough, or for long enough, to take that for the truth. The ending stays owed.
    Unknown,
    /// The service could not be reached, or asked for a delay.
    Later,
    /// The service turned the request back and only the owner can change that.
    OwnerMustLook(ErrorCode),
}

/// Whether an ending the service answered "never issued" is left alone for now: it is asked again
/// no oftener than the gap, by the timer's clock.
fn unknown_waits(shared: &Shared, lease: RelayLeaseId) -> bool {
    let now = shared.timer.now();
    shared
        .unknown_endings
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(lease.get().as_bytes())
        .is_some_and(|seen| {
            now.checked_duration_since(seen.last)
                .is_some_and(|since| since < MIN_ASK_GAP)
        })
}

/// Asks the service to end one lease, and writes down that it answered.
async fn end(shared: &Arc<Shared>, ending: Ending, now: u64) -> Result<Ended> {
    if let Err(error) = shared.service.revoke(ending.lease_id, ending.reason).await {
        return Ok(match failure_of(&error, &shared.quiet) {
            // The service says it never issued a lease of that name. It says the same when a
            // revocation raced a refill and should be asked again, so the answer is believed only
            // when it has been given [`UNKNOWN_ENDING_TRIES`] times and the longest a lease lives
            // has passed since the first: a lease that was alive then is gone by now, and the
            // service settles it by itself.
            Failure::NotActed(ErrorCode::InvalidArgument) => {
                let believed = {
                    let mut tried = shared
                        .unknown_endings
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    let seen =
                        tried
                            .entry(*ending.lease_id.get().as_bytes())
                            .or_insert(UnknownEnding {
                                answers: 0,
                                first_ms: now,
                                last: shared.timer.now(),
                            });
                    seen.answers += 1;
                    seen.last = shared.timer.now();
                    seen.answers >= UNKNOWN_ENDING_TRIES
                        && now.saturating_sub(seen.first_ms) >= LONGEST_LEASE_MS
                };
                if believed {
                    shared
                        .on_record(move |record| record.settle(ending.lease_id))
                        .await?;
                    Ended::Answered
                } else {
                    Ended::Unknown
                }
            }
            Failure::NotActed(code) if needs_the_owner(code) => {
                log_refusal(&error);
                Ended::OwnerMustLook(code)
            }
            _ => Ended::Later,
        });
    }
    shared
        .on_record(move |record| record.settle(ending.lease_id))
        .await?;
    Ok(Ended::Answered)
}

/// Says in the daemon's log what the service answered, which the doctor's sentence for the code
/// does not carry.
fn log_refusal(error: &ClientError) {
    if let ClientError::Refused { error, .. } = error {
        eprintln!(
            "kr-controller: the relay lease service turned a request back ({:?}): {}",
            error.code, error.message
        );
    }
}

/// What an ask came to.
enum Asked {
    /// The service issued or refilled the lease, or the pair is no longer wanted and is ended.
    Held,
    /// The service could not be reached, or may have acted without answering.
    Later,
    /// The service turned back the ending of a lease for a reason only the owner can change.
    EndingRefused(ErrorCode),
    /// The service answered something the owner or the calendar must change.
    Standing(Standing),
}

/// A named lease at the start of a new reservation: nothing counted, no deadline.
fn afresh(row: Row, now: u64) -> Row {
    Row {
        lease_id: None,
        ceiling: BLOCK_BYTES,
        consumed: 0,
        expires_at_ms: 0,
        written_at_ms: now,
        ..row
    }
}

/// The payer a row was kept for, as the request names it.
fn payer_of(text: &Option<String>) -> Option<LeasePayer> {
    let (account_id, authorisation_id) = text.as_deref()?.split_once('/')?;
    Some(LeasePayer::Account {
        account_id: account_id.to_owned(),
        authorisation_id: authorisation_id.to_owned(),
    })
}

/// Writes down that a lease is to be ended, and ends it at the service. The pair's row goes with
/// it: what the host holds for the pair is what the pass asks for next.
async fn end_lease(
    shared: &Arc<Shared>,
    destination: EndpointKey,
    lease: RelayLeaseId,
    now: u64,
) -> Result<Ended> {
    shared
        .on_record(move |record| record.end(&destination, lease, LeaseEndReason::Finished))
        .await?;
    let owed = Ending {
        lease_id: lease,
        reason: LeaseEndReason::Finished,
    };
    end(shared, owed, now).await
}

/// How a refill that raised a lease's ceiling was turned back, before it is known whether the lease
/// or only the raise was refused.
#[derive(Clone, Copy, Debug)]
enum Turned {
    /// The service answered `unavailable`: a retired relay, the aggregate it holds outstanding, or
    /// an allowance that does not cover the raise.
    Unavailable,
    /// The service answered `INVALID_REQUEST`: the raise would pass what the authorisation lets one
    /// lease hold outstanding, or the service does not carry the lease.
    Invalid,
}

/// Asks the service for the lease a device is due, or for the lease it may hold that the host has
/// not seen, and writes down what came back.
///
/// `ending` is set when the device is no longer wanted: the ask is made only to learn the lease
/// the service may be carrying, which is then ended.
///
/// A refill that raised the ceiling and was turned back with one of the two answers that do not say
/// why is followed by a request for the ceiling the lease already holds, which the service answers
/// as it stands unless the relay is retired or the lease is not carried. A lease that stands is
/// kept and the owner is told why the raise was refused. A retired relay's lease is ended and the
/// pair asked for afresh; a lease the service does not carry is dropped and the pair asked for
/// afresh.
///
/// A lease the answer names that the row does not, with a ceiling above a block, is a replacement
/// the service opened for a refill it found past its deadline, or one it opened for a refill whose
/// answer was lost. It holds the ceiling the refill asked for, which for a pair that has carried
/// traffic is far more than a new reservation needs, so it is ended and the pair asked afresh.
#[allow(clippy::too_many_lines)]
async fn ask(
    shared: &Arc<Shared>,
    running: &Running,
    controller: &Controller,
    mut row: Row,
    ending: Option<LeaseEndReason>,
) -> Result<Asked> {
    let mut probing: Option<Turned> = None;
    // The time the row held when the ask began, which an answer that issued nothing gives back, and
    // whether the ask has dropped a lease it did not end, which the service may still carry.
    let original = row.written_at_ms;
    let mut dropped = false;
    let payer = payer_of(&row.payer);
    for _ in 0..ATTEMPTS {
        // The time of this request, read as it is sent: a pass that asks for several pairs, each
        // under a deadline of its own, is not one moment.
        let now = controller.wall_now_ms();
        // Written before it is sent, with the time of this request, whether it names a lease or
        // not: a request whose answer is lost may have issued a lease, or revised the one it named
        // into another, and a stop between the write and the answer leaves a row that says the
        // pair may hold a lease the host does not know of. The row is kept so for as long as a
        // lease asked for now can live.
        row.written_at_ms = now;
        let saved = row.clone();
        shared.on_record(move |record| record.save(&saved)).await?;
        // A named lease is refilled to what the relay had counted plus a block, or by one byte
        // when that would not raise it: the service moves a lease's deadline only with a raised
        // ceiling. A request that names none asks for the block it was written with, so it is the
        // same request each time it is asked again.
        let ceiling = if row.lease_id.is_none() {
            row.ceiling.max(BLOCK_BYTES)
        } else if probing.is_some() {
            row.ceiling
        } else {
            row.ceiling
                .saturating_add(IDLE_RAISE)
                .max(row.consumed.saturating_add(BLOCK_BYTES))
        }
        .min(COUNTER_LIMIT);
        let raises = row.lease_id.is_some() && ceiling > row.ceiling;
        let request = LeaseRequest {
            source: running.endpoint,
            destination: row.destination,
            direction: RelayDirection::Bidirectional,
            byte_ceiling: ceiling,
            duration_seconds: LEASE_SECONDS,
            region_preference: None,
            payer: payer.clone(),
            lease_id: row.lease_id,
        };
        let answer = shared.service.issue(&request).await;
        // An answer starts the gap; a request that went unanswered is paced by the backoff.
        let failure = answer
            .as_ref()
            .err()
            .map(|error| failure_of(error, &shared.quiet));
        if failure != Some(Failure::MayHaveActed) {
            shared.note_asked(&row.destination, now);
        }
        match answer {
            Ok(RelayLeaseAnswer::Granted(grant)) => {
                observe(shared, &grant.warnings, grant.grace.0.as_ref(), now);
                let granted = grant.lease.lease.lease_id;
                // A lease that was never revised and holds more than a block is not one this host
                // asked for: its ceiling is that of a refill the service found past its deadline.
                // A lease this host has raised has been revised, and is left alone, whichever
                // request returned it.
                if ending.is_none()
                    && grant.lease.lease.revision.get() == 1
                    && grant.lease.lease.byte_ceiling.get() > BLOCK_BYTES
                {
                    match end_lease(shared, row.destination, granted, now).await? {
                        Ended::Answered => {
                            row = afresh(row, now);
                            probing = None;
                            continue;
                        }
                        // The service did not take the revocation, because the lease kept
                        // changing under it. It is the lease the pair holds, so it is kept and no
                        // ending is owed for it: asking afresh would be answered with it again.
                        Ended::Unknown => {
                            shared
                                .on_record(move |record| record.settle(granted))
                                .await?;
                            forget_unknown(shared, granted);
                        }
                        Ended::Later => return Ok(Asked::Later),
                        Ended::OwnerMustLook(code) => return Ok(Asked::EndingRefused(code)),
                    }
                }
                let settled = settle_grant(shared, row, &grant, ending).await?;
                return Ok(match (probing, settled) {
                    // The lease stands, so it was the raise that was refused: the owner is told
                    // why, and the raise is tried again after a wait.
                    (Some(Turned::Unavailable), Asked::Held) => Asked::Standing(Standing::NoRoom),
                    (Some(Turned::Invalid), Asked::Held) => Asked::Standing(Standing::Bound),
                    (_, settled) => settled,
                });
            }
            Ok(RelayLeaseAnswer::Exhausted(refusal)) => {
                observe(shared, &refusal.warnings, refusal.grace.0.as_ref(), now);
                let standing = Standing::Exhausted {
                    grace_ends_ms: refusal
                        .grace
                        .0
                        .as_ref()
                        .map(|grace| now.saturating_add(grace.remaining_ms.get())),
                    grace_bytes: refusal
                        .grace
                        .0
                        .as_ref()
                        .map(|grace| grace.remaining_bytes.get()),
                };
                let_the_time_stand(shared, &row, original, dropped).await?;
                return Ok(nothing_issued(shared, standing, &refusal));
            }
            Ok(RelayLeaseAnswer::Unavailable(refusal)) => {
                observe(shared, &refusal.warnings, refusal.grace.0.as_ref(), now);
                if let (Some(lease), true) = (row.lease_id, ending.is_none()) {
                    if raises && probing.is_none() {
                        probing = Some(Turned::Unavailable);
                        continue;
                    }
                    // The lease is turned away at the ceiling it already holds: the relay carrying
                    // it is no longer one the service can bill through, and the service asks that
                    // the lease be revoked and another asked for.
                    match end_lease(shared, row.destination, lease, now).await? {
                        Ended::Answered | Ended::Unknown => {
                            row = afresh(row, now);
                            probing = None;
                            continue;
                        }
                        Ended::Later => return Ok(Asked::Later),
                        Ended::OwnerMustLook(code) => return Ok(Asked::EndingRefused(code)),
                    }
                }
                let_the_time_stand(shared, &row, original, dropped).await?;
                return Ok(nothing_issued(shared, Standing::NoLease, &refusal));
            }
            Err(error) => match failure.expect("a failed request has a failure") {
                // The raise was refused, or the service does not carry the lease the host named:
                // the ceiling the lease already holds tells which. If the service does not carry
                // it, it ended or was never kept, and the pair is asked for afresh, with the
                // figures of a new reservation; the service answers with the lease it holds for
                // the pair, if it holds one.
                Failure::NotActed(ErrorCode::InvalidArgument) if row.lease_id.is_some() => {
                    if raises && probing.is_none() {
                        probing = Some(Turned::Invalid);
                        continue;
                    }
                    row = afresh(row, now);
                    probing = None;
                    dropped = true;
                }
                // Nothing was issued by this request. The row stays: an earlier request whose
                // answer was lost may have issued a lease, and the row is how it is ended.
                Failure::NotActed(code) if needs_the_owner(code) => {
                    log_refusal(&error);
                    let_the_time_stand(shared, &row, original, dropped).await?;
                    return Ok(Asked::Standing(Standing::Refused(code)));
                }
                Failure::NotActed(ErrorCode::QuotaExceeded) => {
                    let_the_time_stand(shared, &row, original, dropped).await?;
                    return Ok(Asked::Standing(Standing::Exhausted {
                        grace_ends_ms: None,
                        grace_bytes: None,
                    }));
                }
                Failure::NotActed(_) => {
                    let_the_time_stand(shared, &row, original, dropped).await?;
                    return Ok(Asked::Later);
                }
                // The service may have acted: the row keeps the time of this request.
                Failure::MayHaveActed => return Ok(Asked::Later),
            },
        }
    }
    Ok(Asked::Later)
}

/// Takes the allowance warning and the grace an answer about a lease carries, whatever the answer
/// was: what an earlier answer said is replaced, and an answer that carries none clears it.
fn observe(
    shared: &Shared,
    warnings: &[kr_client::services::relay::RelayWarning],
    grace: Option<&kr_client::services::relay::RelayGraceRemainder>,
    now: u64,
) {
    let mut observed = shared.observed();
    observed.warning = warning_of(warnings);
    observed.grace = grace.map(|grace| {
        (
            now.saturating_add(grace.remaining_ms.get()),
            grace.remaining_bytes.get(),
        )
    });
}

/// The highest allowance warning in an answer, in percent.
fn warning_of(warnings: &[kr_client::services::relay::RelayWarning]) -> Option<u32> {
    warnings.iter().map(|warning| warning.threshold).max()
}

/// Writes down a lease the service granted, or ends it when the device is no longer wanted.
async fn settle_grant(
    shared: &Arc<Shared>,
    row: Row,
    grant: &RelayLeaseGrant,
    ending: Option<LeaseEndReason>,
) -> Result<Asked> {
    let lease = &grant.lease.lease;
    if let Some(reason) = ending {
        let destination = row.destination;
        let lease_id = lease.lease_id;
        shared
            .on_record(move |record| record.end(&destination, lease_id, reason))
            .await?;
        // The ending is sent by the pass that follows at once, not at the next poll.
        shared.wake.notify_one();
        return Ok(Asked::Held);
    }
    let consumed = grant
        .installed
        .0
        .as_ref()
        .map_or(row.consumed, |ack| ack.bytes_consumed.get());
    let kept = Row {
        lease_id: Some(lease.lease_id),
        ceiling: lease.byte_ceiling.get(),
        consumed,
        expires_at_ms: lease.expires_at_ms.get(),
        // Every lease the host asked for is now one it knows.
        written_at_ms: 0,
        ..row
    };
    shared.on_record(move |record| record.save(&kept)).await?;
    Ok(Asked::Held)
}

/// What the keeper does with an answer that issued nothing: it holds what it has, and tells the
/// owner. A row with no lease stays, because an earlier request of the same pair may have issued
/// one.
fn nothing_issued(shared: &Arc<Shared>, standing: Standing, refusal: &RelayLeaseRefusal) -> Asked {
    if let Some(seconds) = refusal.retry_after_seconds {
        shared.quiet.owe(Duration::from_secs(seconds));
    }
    Asked::Standing(standing)
}

/// Gives a row that names no lease back the time it had before a request that is now known to
/// have issued nothing. The time of such a row is the latest request that may have issued a lease,
/// and an answer that says this one did not leaves the earlier one as the latest.
async fn let_the_time_stand(
    shared: &Arc<Shared>,
    row: &Row,
    original: u64,
    dropped: bool,
) -> Result<()> {
    // A lease the ask dropped without ending may still be carried, and the row keeps the time of
    // the request that followed.
    if dropped {
        return Ok(());
    }
    let mut kept = row.clone();
    kept.written_at_ms = original;
    shared.on_record(move |record| record.save(&kept)).await
}

/// Forgets how often the service has answered that it never issued a lease, for a lease the host
/// has stopped owing an ending for: the next ending owed for it is a new question.
fn forget_unknown(shared: &Shared, lease: RelayLeaseId) {
    shared
        .unknown_endings
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(lease.get().as_bytes());
}
