//! The host reading the signed release matrix.
//!
//! The managed service publishes which client builds it is meant to work with, signed, and this
//! build pins the key ([`kr_client::services::matrix`]). The daemon reads the matrix, keeps the
//! newest accepted copy, and answers two questions from it: what `kr doctor` says of this build,
//! and whether the managed relay lease service is asked for a new lease
//! ([`kr_client::services::matrix::ReleaseGate`]). A build the verified matrix lists no tier for is
//! refused a new lease with the route error; nothing else on the host is touched: no session, worker,
//! grant or pairing, no direct or self-hosted route, no refill of a lease the host holds, no
//! revocation, no update.
//!
//! # Where the host reads
//!
//! Only when `relay.origin` is the managed service, because the pin is the managed service's: a
//! self-hosted deployment publishes a matrix under its own key, which this build does not trust.
//! Any other origin, and a host that selects none, reads nothing, has no gate and says so. A build
//! with the `testing` feature never reads the managed origin itself, only an origin a suite moved
//! it to.
//!
//! # When
//!
//! When the daemon starts (the kept copy is loaded and verified first, so a held skew gates the first
//! lease request and the check has an answer before the first read ends; the read itself runs on a
//! task and start never waits for it), every [`PERIOD`] with up to ten per cent of jitter, after a
//! failed read at [`RETRIES`] and then at the period, and when `kr doctor` runs and the held copy is
//! older than [`STALE_AFTER`] or there is none, bounded to [`DOCTOR_READ_BOUND`] in all. One read
//! runs at a time and a read does not begin within a minute of the last, so a doctor that asks while
//! the runtime reads shares that read. The read is never gated.
//!
//! # What a read that is not accepted does
//!
//! Nothing to the gate. A reply that is not accepted, an older or conflicting revision and a service
//! that does not answer leave the held verified copy deciding, or, with none held, the built-in
//! compatible tier, which is no gate at all. The check says what happened and that the host asks
//! again by itself.

pub mod record;

use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

use kr_client::services::matrix::{
    self, Alternative, HeldMatrix, Pins, Refusal, ReleaseGate, Unread, Verdict, View,
};
use kr_client::services::{HttpDeadlines, HttpService, ServiceHttp, managed_response_limits};
use kr_protocol::hello::PackageVersion;
use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};
use kr_protocol::service::GatewayOrigin;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::{Outbound, Started};
use crate::quiet::Timer;
use crate::service::Controller;

/// How long the matrix is read and kept between two reads when nothing failed.
pub const PERIOD: Duration = Duration::from_secs(6 * 60 * 60);

/// How long to wait after the first failed read, and after the second. Later failures wait the
/// period.
pub const RETRIES: [Duration; 2] = [Duration::from_secs(15 * 60), Duration::from_secs(60 * 60)];

/// How old the held copy is when `kr doctor` reads again.
pub const STALE_AFTER: Duration = Duration::from_secs(15 * 60);

/// The longest `kr doctor` waits for a read, a wait for a read already in progress included.
pub const DOCTOR_READ_BOUND: Duration = Duration::from_secs(5);

/// A read does not begin within this long of the last.
const AT_MOST_ONE_READ_EVERY: Duration = Duration::from_secs(60);

/// The deadlines of the exchange: the matrix is a few kilobytes.
const DEADLINES: HttpDeadlines = HttpDeadlines {
    connect: Duration::from_secs(5),
    read: Duration::from_secs(10),
    total: Duration::from_secs(20),
};

/// The managed service's origin, for the build that is running.
///
/// A build with the `testing` feature has none unless a suite moved the account service, so that no
/// suite reaches the real service by leaving `relay.origin` at the managed origin.
#[cfg(not(any(test, feature = "testing")))]
#[must_use]
pub(crate) fn managed_origin() -> Option<String> {
    Some(kr_client::services::account::ACCOUNT_ORIGIN.to_owned())
}

/// The origin a suite stood the account service at, or nothing.
#[cfg(any(test, feature = "testing"))]
#[must_use]
pub(crate) fn managed_origin() -> Option<String> {
    crate::testing::account_origin()
}

/// The keys the matrix is verified against: this build's pin, or the one a suite gave the start.
#[cfg(not(any(test, feature = "testing")))]
fn pins() -> Pins {
    Pins::production()
}

#[cfg(any(test, feature = "testing"))]
fn pins() -> Pins {
    crate::testing::release_matrix_pins().unwrap_or_else(Pins::production)
}

/// What the host has seen of the last reads, for `kr doctor` and the log.
#[derive(Debug, Default)]
struct Observed {
    /// Why the last read did not read the service, when it did not.
    unread: Option<Unread>,
    /// Why the last reply was not accepted, when it was not.
    refused: Option<Refusal>,
    /// Whether the kept copy could not be written.
    save_failed: bool,
    /// What was last written to standard error, so that a line is written when it changes.
    logged: Option<String>,
}

/// What a read did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Read {
    /// A reply was accepted.
    Accepted,
    /// The service did not answer, or the reply was not accepted.
    Missed,
    /// The last read began less than a minute ago, so none was made.
    TooSoon,
}

/// What the daemon shares with the task that reads.
struct Shared {
    held: HeldMatrix,
    origin: GatewayOrigin,
    http: Arc<dyn ServiceHttp>,
    pins: Pins,
    build: PackageVersion,
    relay_only: bool,
    file: Arc<record::File>,
    timer: Arc<dyn Timer>,
    /// One read at a time; holds when the last one began.
    reading: tokio::sync::Mutex<Option<Instant>>,
    passes: watch::Sender<u64>,
    observed: Mutex<Observed>,
    controller: OnceLock<Weak<Controller>>,
}

impl Shared {
    fn observed(&self) -> std::sync::MutexGuard<'_, Observed> {
        self.observed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reads the matrix once, unless one began within the last minute. Callers share it: whoever
    /// asks while a read is in progress waits for it, and finds the last one recent.
    async fn read(&self, now_ms: u64) -> Read {
        let mut began = self.reading.lock().await;
        let now = self.timer.now();
        if began.is_some_and(|began| now.saturating_duration_since(began) < AT_MOST_ONE_READ_EVERY)
        {
            return Read::TooSoon;
        }
        *began = Some(now);
        let outcome = match matrix::fetch(&*self.http, &self.origin).await {
            Err(unread) => {
                self.observed().unread = Some(unread);
                Read::Missed
            }
            Ok(body) => {
                self.observed().unread = None;
                match self
                    .held
                    .accept(&self.pins, self.origin.as_str(), self.build, now_ms, &body)
                {
                    Ok(update) => {
                        self.observed().refused = None;
                        let file = Arc::clone(&self.file);
                        let saved = update.saved;
                        let written = tokio::task::spawn_blocking(move || file.write(&saved))
                            .await
                            .is_ok_and(|written| written.is_ok());
                        self.observed().save_failed = !written;
                        Read::Accepted
                    }
                    Err(refusal) => {
                        self.observed().refused = Some(refusal);
                        Read::Missed
                    }
                }
            }
        };
        self.log_a_change();
        outcome
    }

    /// Writes one line to standard error when what the host holds or has seen changes.
    fn log_a_change(&self) {
        let view = self.held.view(self.origin.as_str(), self.build);
        let (unread, refused) = {
            let observed = self.observed();
            (observed.unread, observed.refused)
        };
        let line = match (&view, unread, refused) {
            (Some(view), unread, refused) if view.gates() => {
                let latest = match (unread, refused) {
                    (Some(unread), _) => format!("; the last read failed ({unread:?})"),
                    (None, Some(refusal)) => {
                        format!("; the last published matrix was not accepted ({refusal:?})")
                    }
                    (None, None) => String::new(),
                };
                format!("this build is outside every tier of the signed release matrix{latest}")
            }
            (_, Some(unread), _) => format!("the release matrix was not read ({unread:?})"),
            (_, None, Some(Refusal::Older)) => {
                "the service served a release matrix older than the one held".to_owned()
            }
            (_, None, Some(refusal)) => {
                format!("a published release matrix was not accepted ({refusal:?})")
            }
            (Some(_), None, None) => "the release matrix serves this build".to_owned(),
            (None, None, None) => return,
        };
        let mut observed = self.observed();
        if observed.logged.as_deref() != Some(line.as_str()) {
            eprintln!("kr-controller: {line}");
            observed.logged = Some(line);
        }
    }
}

/// The host's reader of the signed release matrix.
pub struct ReleaseMatrixRuntime {
    shared: Arc<Shared>,
    timer: Arc<dyn Timer>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for ReleaseMatrixRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReleaseMatrixRuntime")
            .field("origin", &self.shared.origin.as_str())
            .finish_non_exhaustive()
    }
}

impl ReleaseMatrixRuntime {
    /// The reader for a host whose configuration selects the managed relay service, or nothing:
    /// any other origin, and a host that selects none, reads no matrix.
    ///
    /// The kept copy is loaded and verified here, so a held skew is known before anything is sent.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::ControllerError::NotConfigured`] when the transport to the managed
    /// service cannot be built, which is a fault in this machine's TLS configuration.
    pub fn for_host(
        started: &Started,
        state_dir: &Path,
        outbound: &Outbound,
        timer: Arc<dyn Timer>,
    ) -> crate::error::Result<Option<Self>> {
        let Some(relay) = started.relay.origin() else {
            return Ok(None);
        };
        let (Ok(relay), Some(managed)) = (GatewayOrigin::new(relay), managed_origin()) else {
            return Ok(None);
        };
        if GatewayOrigin::new(&managed).map_or(true, |managed| managed.as_str() != relay.as_str()) {
            return Ok(None);
        }
        let http: Arc<dyn ServiceHttp> = Arc::new(
            HttpService::through(
                relay.clone(),
                DEADLINES,
                managed_response_limits(),
                outbound.proxy()?,
            )
            .map_err(|error| {
                crate::error::ControllerError::NotConfigured(format!(
                    "{} in this host's configuration document ({}) names a service no transport \
                     reaches: {error}",
                    kr_protocol::hostinfo::configuration::RELAY_ORIGIN.key,
                    kr_protocol::hostinfo::configuration::FILE_NAME,
                ))
            })?,
        );
        Ok(Some(Self::new(
            relay,
            http,
            pins(),
            kr_protocol::hello::PACKAGE_VERSION,
            started.network.relay_only(),
            state_dir,
            timer,
        )))
    }

    /// A reader of the matrix at `origin`. Nothing runs and nothing is sent until [`Self::run`].
    #[must_use]
    pub fn new(
        origin: GatewayOrigin,
        http: Arc<dyn ServiceHttp>,
        pins: Pins,
        build: PackageVersion,
        relay_only: bool,
        state_dir: &Path,
        timer: Arc<dyn Timer>,
    ) -> Self {
        let file = Arc::new(record::File::in_dir(state_dir));
        let held = HeldMatrix::none();
        // A copy that does not verify under the pins is no copy.
        if let Some(saved) = file.load() {
            let _ = held.restore(&pins, &saved);
        }
        Self {
            shared: Arc::new(Shared {
                held,
                origin,
                http,
                pins,
                build,
                relay_only,
                file,
                timer: Arc::clone(&timer),
                reading: tokio::sync::Mutex::new(None),
                passes: watch::channel(0).0,
                observed: Mutex::default(),
                controller: OnceLock::new(),
            }),
            timer,
            task: Mutex::new(None),
        }
    }

    /// What the managed relay lease service asks before it sends a request for a new lease.
    #[must_use]
    pub fn gate(&self) -> Arc<ReleaseGate> {
        Arc::new(ReleaseGate::new(
            self.shared.held.clone(),
            self.shared.origin.clone(),
            self.shared.build,
            self.shared.relay_only,
        ))
    }

    /// Starts the reader for a daemon. It does nothing the second time, and the first read begins
    /// at once on a task: the daemon never waits for it.
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

    /// A count that changes each time the reader begins to wait between two reads.
    #[must_use]
    pub fn passes(&self) -> watch::Receiver<u64> {
        self.shared.passes.subscribe()
    }

    /// What `kr doctor` says of this build against the matrix. When the held copy is older than
    /// [`STALE_AFTER`], or there is none, it first asks for a read and waits for it at most
    /// [`DOCTOR_READ_BOUND`]; a read that fails or does not finish never fails the doctor, and it
    /// does not move the schedule of the reads the runtime makes.
    pub async fn doctor_check(&self, controller: &Controller) -> DoctorCheck {
        let now_ms = controller.wall_now_ms();
        let shared = &self.shared;
        let stale = shared
            .held
            .view(shared.origin.as_str(), shared.build)
            .is_none_or(|view| {
                now_ms.saturating_sub(view.fetched_at_ms)
                    >= u64::try_from(STALE_AFTER.as_millis()).unwrap_or(u64::MAX)
            });
        if stale {
            tokio::select! {
                _ = shared.read(now_ms) => {}
                () = self.timer.sleep(DOCTOR_READ_BOUND) => {}
            }
        }
        self.compose(now_ms)
    }

    /// The check, from what is held and what the reads have seen.
    fn compose(&self, now_ms: u64) -> DoctorCheck {
        let shared = &self.shared;
        let view = shared.held.view(shared.origin.as_str(), shared.build);
        let observed = shared.observed();
        let (status, detail, remedy) = compose(
            view,
            observed.unread,
            observed.refused,
            observed.save_failed,
            now_ms,
            &shared
                .held
                .route_error(shared.origin.as_str(), shared.build, shared.relay_only),
        );
        DoctorCheck::new(
            "release-matrix",
            "This build against the release matrix",
            status,
            detail,
            remedy,
        )
    }

    /// What `kr doctor` says of a host that reads no matrix.
    #[must_use]
    pub fn unconfigured_check() -> DoctorCheck {
        DoctorCheck::new(
            "release-matrix",
            "This build against the release matrix",
            DoctorStatus::NotApplicable,
            Sentence::new().stated(
                "relay.origin does not name the managed service, so this host reads no release \
                 matrix and asks no tier of this build",
            ),
            None,
        )
    }
}

impl Drop for ReleaseMatrixRuntime {
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

/// What the reader does for as long as the daemon lives.
async fn drive(shared: Arc<Shared>, timer: Arc<dyn Timer>) {
    let mut missed = 0_usize;
    loop {
        let Some(controller) = shared.controller.get().and_then(Weak::upgrade) else {
            return;
        };
        let wait = match shared.read(controller.wall_now_ms()).await {
            Read::Accepted => {
                missed = 0;
                jittered(PERIOD)
            }
            Read::TooSoon => AT_MOST_ONE_READ_EVERY,
            Read::Missed => {
                let wait = RETRIES
                    .get(missed)
                    .copied()
                    .unwrap_or_else(|| jittered(PERIOD));
                missed += 1;
                wait
            }
        };
        drop(controller);
        // The wait is asked for before the pass is counted, so whoever sees the count change finds
        // the reader waiting.
        let sleeping = timer.sleep(wait);
        shared.passes.send_modify(|passes| *passes += 1);
        sleeping.await;
    }
}

/// `period` and up to ten per cent more, so that hosts started together do not read together.
fn jittered(period: Duration) -> Duration {
    let span = u64::try_from(period.as_millis() / 10)
        .unwrap_or(0)
        .saturating_add(1);
    let extra = kr_transport::random::fresh_u64().map_or(0, |value| value % span);
    period.saturating_add(Duration::from_millis(extra))
}

fn age(now_ms: u64, view: &View) -> Sentence {
    Sentence::new()
        .stated("revision ")
        .number(view.revision)
        .stated(", read ")
        .number(now_ms.saturating_sub(view.fetched_at_ms) / 1000)
        .stated(" seconds ago")
}

fn why_unread(unread: Unread) -> Sentence {
    match unread {
        Unread::Unreachable => Sentence::new().stated("the service did not answer"),
        Unread::NoMatrix => Sentence::new().stated("the service publishes no matrix"),
        Unread::Refused(status) => Sentence::new()
            .stated("the service answered with status ")
            .number(u64::from(status)),
    }
}

fn why_refused(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::Unreadable => "it is not one document of a shape this build reads",
        Refusal::NewerSchema => "it is of a schema newer than this build reads",
        Refusal::Malformed => "it breaks a rule of its own",
        Refusal::Revision => "its revision is not a counter",
        Refusal::Signature => {
            "its signature does not verify under the key this build pins, which may mean a wrong \
             key or a field this build does not know"
        }
        Refusal::Older => "it is older than the copy held",
        Refusal::Conflicts => "it has the revision of the copy held over other signed content",
    }
}

/// The status, the detail and the remedy of the check.
fn compose(
    view: Option<View>,
    unread: Option<Unread>,
    refused: Option<Refusal>,
    save_failed: bool,
    now_ms: u64,
    gated: &Option<matrix::RouteError>,
) -> (DoctorStatus, Sentence, Option<&'static str>) {
    let held = match &view {
        Some(view) => Sentence::new()
            .stated("the copy held, ")
            .sentence(&age(now_ms, view))
            .stated(", still decides"),
        None => Sentence::new().stated("no copy is held, so no tier is asked of this build"),
    };
    let saved = if save_failed {
        "; the copy could not be saved, so it is read again after a restart"
    } else {
        ""
    };

    if let (Some(view), Some(error)) = (&view, gated) {
        let mut paths = Sentence::new();
        for (position, alternative) in error.alternatives().iter().enumerate() {
            paths = paths
                .stated(if position == 0 { "" } else { ", " })
                .stated(Alternative::sentence(*alternative));
        }
        let detail = Sentence::new()
            .stated("this build is outside every tier of the signed release matrix (")
            .sentence(&age(now_ms, view))
            .stated(
                "); this host asks the managed relay service for no new lease and no pairing \
                 admission, and a lease it holds keeps being refilled; no session, worker or \
                 grant is stopped",
            )
            .stated(if error.alternatives().is_empty() {
                ""
            } else {
                "; paths that work once set up: "
            })
            .sentence(&paths);
        // The copy held decides, and what the last read met is said beside it: a service that no
        // longer answers, or serves a matrix this build does not accept, is why a corrected matrix
        // has not reopened the gate.
        let detail = match (unread, refused) {
            (Some(unread), _) => detail
                .stated("; the last read of the matrix failed: ")
                .sentence(&why_unread(unread)),
            (None, Some(refusal)) => detail
                .stated("; the last published matrix was not accepted: ")
                .stated(why_refused(refusal)),
            (None, None) => detail,
        }
        .stated(saved);
        return (
            DoctorStatus::Warning,
            detail,
            Some(
                "Update KalaReach on this host, or use one of those paths. If the matrix was \
                 corrected and this still shows, delete release-matrix.json in the state \
                 directory and restart the daemon.",
            ),
        );
    }

    if let Some(unread) = unread {
        return (
            DoctorStatus::Warning,
            Sentence::new()
                .stated("the signed release matrix could not be read: ")
                .sentence(&why_unread(unread))
                .stated("; ")
                .sentence(&held)
                .stated(saved),
            Some("This host asks again by itself."),
        );
    }
    if let Some(refusal) = refused.filter(|refusal| *refusal != Refusal::Older) {
        return (
            DoctorStatus::Warning,
            Sentence::new()
                .stated("a published release matrix was not accepted: ")
                .stated(why_refused(refusal))
                .stated("; ")
                .sentence(&held)
                .stated(saved),
            Some(if refusal == Refusal::NewerSchema {
                "Update KalaReach on this host. This host asks again by itself."
            } else {
                "This host asks again by itself."
            }),
        );
    }

    let detail = match view {
        None => {
            Sentence::new().stated("the signed release matrix has not been read for this build yet")
        }
        Some(view) if view.verdict == Verdict::Skew => Sentence::new().stated(
            "the signed release matrix has not been read for this build yet; the copy an \
                 earlier build read lists no tier for this build, and nothing is acted on until \
                 a read for this build says so",
        ),
        Some(view) => {
            let tier = match view.verdict {
                Verdict::Served { compatible: true } => {
                    "this build is served by the compatible tier of the signed release matrix ("
                }
                _ => {
                    "this build is served by a later tier of the signed release matrix, and the \
                     compatible tier does not cover it ("
                }
            };
            Sentence::new()
                .stated(tier)
                .sentence(&age(now_ms, &view))
                .stated(")")
        }
    };
    (DoctorStatus::Ok, detail.stated(saved), None)
}
