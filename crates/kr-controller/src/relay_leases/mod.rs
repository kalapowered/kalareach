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
//! For each paired device, the lease the service issued for the pair of this host's endpoint and the
//! device's, and the endings the service has not yet answered. Both are kept in a record that
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
//!   that reservation and moves its deadline and never opens a second one. The ceiling it asks for
//!   is the larger of what it holds and what the relay has counted plus one block
//!   ([`BLOCK_BYTES`]), because the figure is the reservation's cumulative total and not an
//!   increment.
//! * **When a device is unpaired**, or when the account that pays is not the one the lease was
//!   asked for, it ends the lease. The ending is written down before it is sent and sent again,
//!   after any failure and after a restart, until the service answers.
//! * **Every [`POLL_INTERVAL`]**, so a change nothing woke the keeper for is found.
//!
//! # What the answers mean
//!
//! A lease, with the deadline and the ceiling the service chose. An allowance that is spent, or no
//! relay to offer, is an answer about capacity and not a fault: the keeper holds what it has, shows
//! the owner the grace left and the paths that still work (a direct connection, a relay the owner
//! runs), and asks again after the delay the service named or [`STANDING_RETRY`]. A refusal that
//! only the owner can clear, such as a host that names no account the service accepts, is shown the
//! same way and is asked again as seldom. A refusal that names a delay, or a service that cannot be
//! reached, is waited out with the backoff every carrier of this host uses, and a lease running out
//! meanwhile stops forwarding for its pair and nothing else: direct paths do not depend on it.
//!
//! A request whose answer was lost may have issued a lease. The keeper has not written down a lease
//! identifier it was not told, so it asks again for the same pair before anything else, and the
//! service answers with the lease the pair already holds. The same holds after a restart.

pub mod record;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::Duration;

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
/// passed, which leaves two further tries before the lease runs out.
pub const REFILL_WHEN_LEFT: Duration = Duration::from_secs(600);

/// The bytes the keeper reserves for a pair beyond what the relay has counted for it. A principal
/// holds at most 8 MiB outstanding across all its leases, so a block this size serves sixteen
/// paired devices before the service answers that no more can be held.
pub const BLOCK_BYTES: u64 = 512 * 1024;

/// How often the keeper reads the paired devices when nothing woke it.
pub const POLL_INTERVAL: Duration = Duration::from_secs(60);

/// How long the keeper leaves the service alone after an answer only the owner or the calendar can
/// change: an allowance that is spent, no relay to offer, or a refusal of the host's request.
pub const STANDING_RETRY: Duration = Duration::from_secs(5 * 60);

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
        grace_ms: Option<u64>,
        grace_bytes: Option<u64>,
    },
    /// The service has no relay to offer.
    NoRelay,
    /// The service turned the request back, and only the owner can change that.
    Refused(ErrorCode),
}

/// What the doctor says of the keeper.
#[derive(Debug, Default)]
struct Observed {
    /// How many paired devices there were at the last pass.
    paired: usize,
    /// How many of them hold a lease.
    held: usize,
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
    quiet: Quiet,
    wake: Notify,
    passes: watch::Sender<u64>,
    /// How many passes have been asked for, by whoever needs to know the keeper has looked since.
    requested: AtomicU64,
    /// The newest request count that a pass which began after the request was made has finished.
    completed: watch::Sender<u64>,
    observed: Mutex<Observed>,
    running: OnceLock<Running>,
    stopped: AtomicBool,
}

impl Shared {
    fn observed(&self) -> std::sync::MutexGuard<'_, Observed> {
        self.observed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The authorisation the leases are asked for under, which a lease is kept with so that a
    /// change of payer is found.
    fn payer_key(&self) -> Option<String> {
        match &self.payer {
            Some(LeasePayer::Account {
                authorisation_id, ..
            }) => Some(authorisation_id.clone()),
            _ => None,
        }
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
    timer: Arc<dyn Timer>,
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
                wake: Notify::new(),
                passes: watch::channel(0).0,
                requested: AtomicU64::new(0),
                completed: watch::channel(0).0,
                observed: Mutex::default(),
                running: OnceLock::new(),
                stopped: AtomicBool::new(false),
            }),
            timer,
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
        let task = tokio::spawn(drive(Arc::clone(&self.shared), Arc::clone(&self.timer)));
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

    /// Ends the keeper where it is, as the daemon's process ending would. For a suite that stops
    /// the daemon between two steps of a request.
    #[cfg(feature = "testing")]
    pub fn crash(&self) {
        self.shared.stopped.store(true, Ordering::SeqCst);
        if let Some(task) = self
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            task.abort();
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
        let mut detail = Sentence::new()
            .stated("this host holds a relay lease for ")
            .number(observed.held as u64)
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
                    grace_ms,
                    grace_bytes,
                } => {
                    let mut detail = detail.stated(
                        "; the allowance of the account that pays is spent, so the service issues \
                         no new lease",
                    );
                    if let Some(milliseconds) = grace_ms {
                        detail = detail
                            .stated("; the grace left to a connection already running is ")
                            .number(milliseconds / 1000)
                            .stated(" seconds");
                    }
                    if let Some(bytes) = grace_bytes {
                        detail = detail.stated(" or ").number(bytes).stated(" bytes");
                    }
                    detail
                }
                Standing::NoRelay => {
                    detail.stated("; the service has no relay to offer a new lease on right now")
                }
                Standing::Refused(ErrorCode::PermissionDenied) => detail.stated(
                    "; the service turned this host's request back: it names the account a host \
                     spends, and the authorisation has to be in force for this host's key",
                ),
                Standing::Refused(_) => detail.stated(
                    "; the service turned this host's request back as one it does not accept",
                ),
            };
            let remedy = match standing {
                Standing::Exhausted { .. } | Standing::NoRelay => {
                    "A direct connection between the devices needs no relay, and so does a relay \
                     you run yourself. This host asks the service again by itself."
                }
                Standing::Refused(_) => {
                    "Check that `relay.payer` in the configuration document names an authorisation \
                     given to this host's key and still in force, and start the daemon again. \
                     This host asks the service again by itself."
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
async fn drive(shared: Arc<Shared>, timer: Arc<dyn Timer>) {
    let mut backoff = Backoff::default();
    loop {
        if shared.stopped.load(Ordering::SeqCst) {
            return;
        }
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
            let wait = match report.next {
                Next::Failed => backoff.next_delay(),
                Next::Standing => STANDING_RETRY,
                Next::Due(wait) => wait,
            };
            if report.next != Next::Failed {
                backoff = Backoff::default();
            }
            shared
                .completed
                .send_modify(|completed| *completed = (*completed).max(target));
            wait.max(shared.quiet.left().unwrap_or_default())
        };
        drop(controller);
        // The wait is asked for before the pass is counted, so whoever sees the count change finds
        // the keeper waiting.
        let sleeping = timer.sleep(wait);
        tokio::pin!(sleeping);
        shared.passes.send_modify(|passes| *passes += 1);
        // Interest in a change is registered before the wait starts, so a device paired in
        // between either shortens the wait or is seen by the next pass: none is lost.
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
    /// After the earliest refill is due, or the poll interval.
    Due(Duration),
    /// After the service could not be reached, or asked for a delay.
    Failed,
    /// After an answer the owner or the calendar must change.
    Standing,
}

/// How a pass ended.
struct Report {
    next: Next,
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
            Report { next: Next::Failed }
        }
    }
}

async fn reconcile(
    shared: &Arc<Shared>,
    running: &Running,
    controller: &Arc<Controller>,
) -> Result<Report> {
    let mut unreachable = false;
    let mut standing = None;

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
    // for another host key, is a lease to end. A row with no lease is a request whose answer the
    // host never saw: the pair may hold a lease, and asking again is how the host learns which.
    // That can be asked only of the payer it was asked under; a row for another payer is dropped
    // and its lease, if the service issued one, runs out by itself.
    let mut unwanted = Vec::new();
    for row in shared.on_record(Record::rows).await? {
        let same_asker = row.source == running.endpoint && row.payer == payer_key;
        let device_is_paired = is_paired(&row.destination);
        if same_asker && device_is_paired {
            continue;
        }
        let destination = row.destination;
        match row.lease_id {
            Some(lease) => {
                let reason = if device_is_paired {
                    LeaseEndReason::PayerWithdrew
                } else {
                    LeaseEndReason::Unpaired
                };
                shared
                    .on_record(move |record| record.end(&destination, lease, reason))
                    .await?;
            }
            None if same_asker => unwanted.push((row, LeaseEndReason::Unpaired)),
            None => {
                shared
                    .on_record(move |record| record.forget(&destination))
                    .await?;
            }
        }
    }

    // What the service is owed an ending for goes before anything is asked of it, so a pair it
    // still carries after its device was unpaired is not left waiting behind the asks below.
    for ending in shared.on_record(Record::endings).await? {
        match end(shared, ending).await? {
            Ended::Answered => {}
            Ended::Later => {
                unreachable = true;
                break;
            }
            Ended::OwnerMustLook(code) => standing = Some(Standing::Refused(code)),
        }
    }

    if !unreachable {
        for (row, reason) in unwanted {
            match ask(shared, running, row, Some(reason)).await? {
                Asked::Held | Asked::Nothing => {}
                Asked::Later => {
                    unreachable = true;
                    break;
                }
                Asked::Standing(why) => {
                    standing = Some(why);
                    break;
                }
            }
        }
    }

    let now = controller.wall_now_ms();
    let refill_ms = u64::try_from(REFILL_WHEN_LEFT.as_millis()).unwrap_or(u64::MAX);
    if !unreachable && standing.is_none() {
        let rows = shared.on_record(Record::rows).await?;
        for device in &paired {
            let row = rows
                .iter()
                .find(|row| row.destination == device.endpoint_id)
                .cloned();
            let due = row.as_ref().is_none_or(|row| {
                row.lease_id.is_none() || row.expires_at_ms.saturating_sub(now) <= refill_ms
            });
            if !due {
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
            });
            match ask(shared, running, row, None).await? {
                Asked::Held | Asked::Nothing => {}
                Asked::Later => {
                    unreachable = true;
                    break;
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
    let held = paired
        .iter()
        .filter(|device| {
            rows.iter()
                .any(|row| row.destination == device.endpoint_id && row.lease_id.is_some())
        })
        .count();
    let next_refill = rows
        .iter()
        .filter(|row| row.lease_id.is_some())
        .map(|row| row.expires_at_ms.saturating_sub(refill_ms))
        .min();
    {
        let mut observed = shared.observed();
        observed.paired = paired.len();
        observed.held = held;
        observed.next_refill_ms = next_refill;
        observed.endings_owed = owed;
        observed.unreachable = unreachable;
        // What was said stays until a pass that reached the service has nothing to say.
        if !unreachable {
            observed.standing = standing;
        }
    }
    let next = if unreachable {
        Next::Failed
    } else if standing.is_some() {
        Next::Standing
    } else {
        let until = next_refill.map_or(POLL_INTERVAL, |due| {
            Duration::from_millis(due.saturating_sub(now))
        });
        Next::Due(until.clamp(Duration::from_secs(1), POLL_INTERVAL))
    };
    Ok(Report { next })
}

/// What an ending came to.
enum Ended {
    /// The service answered, or answered that there is nothing of that name to end.
    Answered,
    /// The service could not be reached or asked for a delay.
    Later,
    /// The service turned the request back and only the owner can change that.
    OwnerMustLook(ErrorCode),
}

/// Asks the service to end one lease, and writes down that it answered.
async fn end(shared: &Arc<Shared>, ending: Ending) -> Result<Ended> {
    if let Err(error) = shared.service.revoke(ending.lease_id, ending.reason).await {
        return Ok(match failure_of(&error, &shared.quiet) {
            // The service has never issued a lease of that name: there is nothing to end.
            Failure::NotActed(ErrorCode::InvalidArgument) => {
                shared
                    .on_record(move |record| record.settle(ending.lease_id))
                    .await?;
                Ended::Answered
            }
            Failure::NotActed(code) if needs_the_owner(code) => Ended::OwnerMustLook(code),
            _ => Ended::Later,
        });
    }
    shared
        .on_record(move |record| record.settle(ending.lease_id))
        .await?;
    Ok(Ended::Answered)
}

/// What an ask came to.
enum Asked {
    /// The service issued or refilled the lease, or the pair is no longer wanted and is ended.
    Held,
    /// The service issued nothing for a pair that is no longer wanted.
    Nothing,
    /// The service could not be reached, or may have acted without answering.
    Later,
    /// The service answered something the owner or the calendar must change.
    Standing(Standing),
}

/// Asks the service for the lease a device is due, or for the lease it may hold that the host has
/// not seen, and writes down what came back.
///
/// `ending` is set when the device is no longer wanted: the ask is made only to learn the lease
/// the service may be carrying, which is then ended.
async fn ask(
    shared: &Arc<Shared>,
    running: &Running,
    mut row: Row,
    ending: Option<LeaseEndReason>,
) -> Result<Asked> {
    for attempt in 0..2 {
        if row.lease_id.is_none() && attempt == 0 {
            // Written before it is sent: a stop between the two leaves a row that says the pair
            // may hold a lease.
            let saved = row.clone();
            shared.on_record(move |record| record.save(&saved)).await?;
        }
        let request = LeaseRequest {
            source: running.endpoint,
            destination: row.destination,
            direction: RelayDirection::Bidirectional,
            byte_ceiling: row.ceiling.max(row.consumed + BLOCK_BYTES).clamp(
                BLOCK_BYTES,
                kr_protocol::relay::MAX_OUTSTANDING_RESERVED_BYTES,
            ),
            duration_seconds: LEASE_SECONDS,
            region_preference: None,
            payer: shared.payer.clone(),
            lease_id: row.lease_id,
        };
        match shared.service.issue(&request).await {
            Ok(RelayLeaseAnswer::Granted(grant)) => {
                return settle_grant(shared, row, &grant, ending).await;
            }
            Ok(RelayLeaseAnswer::Exhausted(refusal)) => {
                let standing = Standing::Exhausted {
                    grace_ms: refusal
                        .grace
                        .0
                        .as_ref()
                        .map(|grace| grace.remaining_ms.get()),
                    grace_bytes: refusal
                        .grace
                        .0
                        .as_ref()
                        .map(|grace| grace.remaining_bytes.get()),
                };
                return nothing_issued(shared, &row, ending, standing, &refusal).await;
            }
            Ok(RelayLeaseAnswer::Unavailable(refusal)) => {
                return nothing_issued(shared, &row, ending, Standing::NoRelay, &refusal).await;
            }
            Err(error) => match failure_of(&error, &shared.quiet) {
                // The service is not carrying the lease the host named: it ended, or it was
                // never kept. The pair is asked for afresh, and the service answers with the
                // lease it holds for the pair, if it holds one.
                Failure::NotActed(ErrorCode::InvalidArgument)
                    if row.lease_id.is_some() && attempt == 0 =>
                {
                    row.lease_id = None;
                    let saved = row.clone();
                    shared.on_record(move |record| record.save(&saved)).await?;
                }
                Failure::NotActed(code)
                    if needs_the_owner(code) || code == ErrorCode::QuotaExceeded =>
                {
                    // Nothing was issued. A pair with no lease needs no row.
                    if row.lease_id.is_none() {
                        let destination = row.destination;
                        shared
                            .on_record(move |record| record.forget(&destination))
                            .await?;
                    }
                    return Ok(if ending.is_some() {
                        Asked::Nothing
                    } else if code == ErrorCode::QuotaExceeded {
                        Asked::Standing(Standing::Exhausted {
                            grace_ms: None,
                            grace_bytes: None,
                        })
                    } else {
                        Asked::Standing(Standing::Refused(code))
                    });
                }
                Failure::NotActed(_) | Failure::MayHaveActed => return Ok(Asked::Later),
            },
        }
    }
    Ok(Asked::Later)
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
        ..row
    };
    shared.on_record(move |record| record.save(&kept)).await?;
    Ok(Asked::Held)
}

/// What the keeper does with an answer that issued nothing: it holds what it has, forgets a request
/// that created nothing, and tells the owner, unless the pair is one it is only ending.
async fn nothing_issued(
    shared: &Arc<Shared>,
    row: &Row,
    ending: Option<LeaseEndReason>,
    standing: Standing,
    refusal: &RelayLeaseRefusal,
) -> Result<Asked> {
    if row.lease_id.is_none() {
        let destination = row.destination;
        shared
            .on_record(move |record| record.forget(&destination))
            .await?;
    }
    if let Some(seconds) = refusal.retry_after_seconds {
        shared.quiet.owe(Duration::from_secs(seconds));
    }
    Ok(if ending.is_some() {
        Asked::Nothing
    } else {
        Asked::Standing(standing)
    })
}
