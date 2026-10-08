//! The carrier of this host's backup outbox: the task that takes it to the managed storage
//! service, and what `kr doctor` says of that.
//!
//! [`Uploader`] does one step at a time and says what it did. This is what runs it for as long as
//! the daemon lives. It builds the managed storage and backup manifest clients from the
//! configuration document's `storage.origin`, signs as the writer key only this host holds, and
//! presents the account token the operator imported. It never decides what a refusal means: the
//! uploader and the service do. What it decides is when to ask again.
//!
//! # When it asks again
//!
//! * **Work arrives or becomes possible** (a generation admitted, a writer enrolled, a fence
//!   released): at once, unless the service asked to be left alone, and then when it said.
//! * **A privacy fence is raised**: at once, whatever else it waits for. The cleanup a fence owes
//!   ends the work in flight, and it must not wait out a delay the service asked for.
//! * **The service is busy, unavailable or slow**: after the longer of the delay it named and a
//!   jittered, doubling delay of 250 ms to 30 s.
//! * **Only a person can clear the cause** (backup storage off, no backup allowance, a writer
//!   nobody enrolled, no usable account token): after five minutes, or when work or a writer
//!   arrives. The host's own account token is checked first and every 30 seconds, because
//!   importing one only writes a file, and no request leaves the host without a usable one.
//! * **Nothing is owed**: when something changes.
//!
//! # Where it runs
//!
//! On a task of its own on the daemon's reactor, so a service that never answers holds one task and
//! stopping the daemon ends the exchange in flight. The uploader hands the disk work it does
//! between exchanges to a thread the reactor can spare.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_client::services::account::{AccountTokenSource, BACKUP_WRITE_SCOPE};
use kr_client::services::voice::AccountTokenFile;
use kr_client::services::{
    BackupState, HttpDeadlines, HttpService, ManagedBackupManifestService, ManagedStorageService,
    ServiceClients, ServiceHttp, ServiceSigner, StorageService, StorageStatus,
    managed_response_limits,
};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};
use kr_protocol::scalars::{AuthorisationKey, Signature64};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_transport::config::ProxyUrl;
use kr_transport::reconnect::Backoff;
use tokio::task::JoinHandle;

use crate::backup::uploader::{Hold, Idle, PassReport, Stepped, Uploader};
use crate::backup::{BackupService, BackupSignals};
use crate::error::{ControllerError, Result};

/// How long a condition only a person can clear waits before the host asks again.
pub const OPERATOR_CEILING: Duration = Duration::from_secs(5 * 60);

/// How often the host looks again at the account token it holds, while there is work and no usable
/// token. A token is imported by writing a file, which nothing tells the daemon about.
pub const TOKEN_CHECK: Duration = Duration::from_secs(30);

/// How long a status read made for `kr doctor` may take.
pub const DOCTOR_STATUS_READ: Duration = Duration::from_secs(5);

/// How long the host waits, before it restarts, for the answer to a publication an earlier run sent
/// and never saw answered. A service that does not answer in that time is asked again by the first
/// pass, and the generation is recorded as one this host cannot establish in the meantime.
pub const SETTLE_BUDGET: Duration = Duration::from_secs(5);

/// The deadlines storage exchanges are made under.
///
/// A part is 8 MiB and the answer begins only after the whole part has been sent, so the read
/// deadline is the time the slowest uplink this host supports gets to send one: 60 seconds is about
/// 1.1 Mbit/s. The total adds the time the service takes to verify and store it.
pub const STORAGE_DEADLINES: HttpDeadlines = HttpDeadlines {
    connect: Duration::from_secs(5),
    read: Duration::from_secs(60),
    total: Duration::from_secs(90),
};

/// What the host waits on between two passes.
pub trait Timer: Send + Sync + std::fmt::Debug {
    /// A wait of `duration`.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// The clock the daemon waits by.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealTimer;

impl Timer for RealTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// The key this host signs its managed-storage requests and the generations it publishes with.
///
/// The service reads it as a host's, which is how it treats a host-produced archive.
struct WriterSigner {
    key: AuthorisationKeyPair,
}

impl std::fmt::Debug for WriterSigner {
    /// The public key, which is what names this writer to the service. Never the private half.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WriterSigner")
            .field("public_key", self.key.public())
            .finish_non_exhaustive()
    }
}

impl ServiceSigner for WriterSigner {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Host
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.key.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let refused = |what: String| {
            kr_client::ClientError::Host(ProtocolError::new(ErrorCode::InvalidArgument, what))
        };
        let transcript = SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Host.domain(),
            message.to_vec(),
        )
        .map_err(|error| refused(format!("the request could not be signed: {error}")))?;
        sign(&self.key, &transcript)
            .map_err(|error| refused(format!("the request could not be signed: {error}")))
    }
}

/// What this host holds for the account token it presents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenState {
    /// Nothing has been imported.
    Absent,
    /// The imported token was issued for another service.
    OtherService,
    /// The imported token has stopped being accepted.
    Expired,
    /// The imported token was not issued with the scope backup storage needs.
    WithoutScope,
    /// The token is usable now, and stops being accepted at the time shown, when it says.
    Usable,
}

impl TokenState {
    const fn words(self) -> &'static str {
        match self {
            Self::Absent => "no account token is imported",
            Self::OtherService => "the imported account token belongs to another service",
            Self::Expired => "the imported account token has expired",
            Self::WithoutScope => "the imported account token lacks the backup.write scope",
            Self::Usable => "an account token with the backup.write scope is imported",
        }
    }
}

/// Reads the token file as the transport will, without sending anything.
fn token_state(tokens: &AccountTokenFile, origin: &str) -> TokenState {
    let Ok(stored) = tokens.stored() else {
        return TokenState::Absent;
    };
    if stored.origin != origin {
        TokenState::OtherService
    } else if stored
        .expires_at_ms
        .is_some_and(|expires| expires <= kr_ipc::now_ms().get())
    {
        TokenState::Expired
    } else if !stored.carries(BACKUP_WRITE_SCOPE) {
        TokenState::WithoutScope
    } else {
        TokenState::Usable
    }
}

/// What the carrier knows of the service, for `kr doctor`.
#[derive(Debug, Default)]
struct Observed {
    /// The last answer the service gave to a status read.
    status: Option<StorageStatus>,
    /// Why the last status read, or the last pass, was turned back by the service.
    hold: Option<Hold>,
    /// What the last pass did.
    last_pass: Option<LastPass>,
    /// Whether the carrier is waiting out a delay the service asked for, in which case nothing is
    /// sent until it ends.
    in_delay: bool,
    /// Whether the carrier found work and no usable account token the last time it looked.
    token_blocked: bool,
}

/// What one pass did, in the words `kr doctor` uses.
#[derive(Clone, Copy, Debug)]
struct LastPass {
    steps: u64,
    idle: Option<&'static str>,
}

/// What the carrier waits on next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wait {
    /// Until work arrives or a fence is raised.
    Signals,
    /// For `duration`, or until a fence is raised, or, when `wakeable`, until work arrives.
    Timed { duration: Duration, wakeable: bool },
}

/// The clients a host with a storage service builds, and the key it signs them with.
///
/// # Errors
///
/// Returns [`ControllerError::NotConfigured`] when the transport cannot be built, which is a fault
/// in this machine's TLS configuration rather than in the service.
pub fn managed_clients(
    origin: &GatewayOrigin,
    proxy: Option<&ProxyUrl>,
    writer: &AuthorisationKeyPair,
    tokens: &Arc<AccountTokenFile>,
) -> Result<ServiceClients> {
    let http: Arc<dyn ServiceHttp> = Arc::new(
        HttpService::through(
            origin.clone(),
            STORAGE_DEADLINES,
            managed_response_limits(),
            proxy,
        )
        .map_err(|error| {
            ControllerError::NotConfigured(format!(
                "{} in this host's configuration document ({}) names a service no transport \
                 reaches: {error}",
                kr_protocol::hostinfo::configuration::STORAGE_ORIGIN.key,
                kr_protocol::hostinfo::configuration::FILE_NAME,
            ))
        })?,
    );
    let signer: Arc<dyn ServiceSigner> = Arc::new(WriterSigner {
        key: writer.clone(),
    });
    let source: Arc<dyn AccountTokenSource> = Arc::clone(tokens) as _;
    Ok(ServiceClients {
        storage: Some(Arc::new(
            ManagedStorageService::new(origin.clone(), Arc::clone(&http), Arc::clone(&signer))
                .presenting(Arc::clone(&source)),
        )),
        backup_manifest: Some(Arc::new(
            ManagedBackupManifestService::new(origin.clone(), http, signer).presenting(source),
        )),
        ..ServiceClients::none()
    })
}

/// What the carrier shares with the daemon.
struct Shared {
    /// Where the carrier asks `kr doctor`'s own status question, apart from the uploader's.
    storage: Arc<dyn StorageService>,
    tokens: Arc<AccountTokenFile>,
    origin: String,
    writer_public: AuthorisationKey,
    signals: Arc<BackupSignals>,
    observed: Mutex<Observed>,
    /// How many passes have finished, for whatever waits on one.
    passes: tokio::sync::watch::Sender<u64>,
}

impl Shared {
    fn observed(&self) -> std::sync::MutexGuard<'_, Observed> {
        self.observed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Notes what a pass found, and says what to wait on.
    fn absorb(&self, report: &PassReport, backoff: &mut Backoff) -> Wait {
        let progressed = report
            .steps
            .iter()
            .any(|step| !matches!(step, Stepped::Waiting { .. }));
        let waited = report
            .steps
            .iter()
            .any(|step| matches!(step, Stepped::Waiting { .. }));
        {
            let mut observed = self.observed();
            if let Some(status) = &report.status {
                observed.status = Some(status.clone());
            }
            observed.hold = report.hold;
            observed.last_pass = Some(LastPass {
                steps: report.steps.len() as u64,
                idle: match &report.idle {
                    None => None,
                    Some(Idle::Unready { .. }) => {
                        Some("this host has not reconciled its backup store")
                    }
                    Some(Idle::BackupOff) => Some("backup storage is off for the account"),
                    Some(Idle::Unavailable { .. }) => Some("the service could not be asked"),
                },
            });
        }
        if progressed && report.hold.is_none() {
            backoff.reset();
        }
        if let Some(hold) = report.hold {
            return if hold.needs_a_person() {
                Wait::Timed {
                    duration: OPERATOR_CEILING,
                    wakeable: true,
                }
            } else {
                Wait::Timed {
                    duration: backoff
                        .next_delay()
                        .max(hold.retry_after.unwrap_or(Duration::ZERO)),
                    wakeable: false,
                }
            };
        }
        match report.idle {
            Some(Idle::BackupOff) => Wait::Timed {
                duration: OPERATOR_CEILING,
                wakeable: true,
            },
            Some(Idle::Unready { .. } | Idle::Unavailable { .. }) => Wait::Timed {
                duration: backoff.next_delay(),
                wakeable: true,
            },
            None if waited => Wait::Timed {
                duration: backoff.next_delay(),
                wakeable: true,
            },
            None => Wait::Signals,
        }
    }

    async fn wait(&self, wait: Wait, timer: &dyn Timer) {
        let signals = &self.signals;
        match wait {
            Wait::Signals => {
                tokio::select! {
                    () = signals.work.notified() => {}
                    () = signals.fence.notified() => {}
                }
            }
            Wait::Timed {
                duration,
                wakeable: true,
            } => {
                tokio::select! {
                    () = timer.sleep(duration) => {}
                    () = signals.work.notified() => {}
                    () = signals.fence.notified() => {}
                }
            }
            Wait::Timed {
                duration,
                wakeable: false,
            } => {
                self.observed().in_delay = true;
                tokio::select! {
                    () = timer.sleep(duration) => {}
                    () = signals.fence.notified() => {}
                }
                self.observed().in_delay = false;
            }
        }
    }

    /// One pass, or the reason none was made.
    async fn carry(
        &self,
        uploader: &mut Uploader,
        backup: &BackupService,
        backoff: &mut Backoff,
    ) -> Wait {
        if token_state(&self.tokens, &self.origin) != TokenState::Usable {
            // Nothing leaves this host without a usable token. With nothing to carry there is
            // nothing to check for either, and work arriving is what looks again.
            let nothing_to_carry = backup.outbox().is_ok_and(|outbox| outbox.is_empty());
            self.observed().token_blocked = !nothing_to_carry;
            return if nothing_to_carry {
                Wait::Signals
            } else {
                Wait::Timed {
                    duration: TOKEN_CHECK,
                    wakeable: true,
                }
            };
        }
        self.observed().token_blocked = false;
        match uploader.pass(kr_ipc::now_ms()).await {
            Ok(report) => self.absorb(&report, backoff),
            Err(error) => {
                eprintln!("kr-controller: the backup pass could not use its store: {error}");
                Wait::Timed {
                    duration: backoff.next_delay(),
                    wakeable: true,
                }
            }
        }
    }

    /// Asks the service what it says about backup storage and notes the answer.
    async fn read_status(&self, storage: &dyn StorageService) {
        match storage.status().await {
            Ok(status) => {
                let mut observed = self.observed();
                observed.status = Some(status);
                observed.hold = None;
            }
            Err(error) => self.observed().hold = Some(Hold::of(&error)),
        }
    }
}

/// The carrier of one host's backup outbox.
pub struct BackupRuntime {
    shared: Arc<Shared>,
    backup: Arc<BackupService>,
    timer: Arc<dyn Timer>,
    /// The uploader, until the task takes it.
    uploader: Mutex<Option<Uploader>>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for BackupRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackupRuntime")
            .field("writer_public_key", &self.shared.writer_public)
            .finish_non_exhaustive()
    }
}

impl BackupRuntime {
    /// Builds the carrier of `backup`'s outbox over the storage and manifest clients `clients`
    /// holds, publishing as `writer`.
    ///
    /// Nothing runs and nothing is sent until [`Self::run`].
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] when `clients` holds no storage client or no
    /// backup manifest client.
    pub fn new(
        backup: Arc<BackupService>,
        clients: &ServiceClients,
        writer: AuthorisationKeyPair,
        origin: &GatewayOrigin,
        tokens: Arc<AccountTokenFile>,
        timer: Arc<dyn Timer>,
    ) -> Result<Self> {
        let (Some(storage), Some(manifest)) = (&clients.storage, &clients.backup_manifest) else {
            return Err(ControllerError::NotConfigured(
                "backup needs a storage client and a backup manifest client".to_owned(),
            ));
        };
        let writer_public = *writer.public();
        let shared = Arc::new(Shared {
            storage: Arc::clone(storage),
            tokens,
            origin: origin.as_str().to_owned(),
            writer_public,
            signals: backup.signals(),
            observed: Mutex::default(),
            passes: tokio::sync::watch::channel(0).0,
        });
        let uploader = Uploader::new(
            Arc::clone(&backup),
            Arc::clone(storage),
            Arc::clone(manifest),
            writer,
            kr_ipc::now_ms(),
        );
        Ok(Self {
            shared,
            backup,
            timer,
            uploader: Mutex::new(Some(uploader)),
            task: Mutex::new(None),
        })
    }

    /// The public half of the key this host publishes as, which an owner enrols at the service as
    /// the writer of a collection.
    #[must_use]
    pub fn writer_public_key(&self) -> AuthorisationKey {
        self.shared.writer_public
    }

    /// Records the publications an earlier run sent that the service holds, giving the service
    /// `budget` to say, before the store is reconciled.
    ///
    /// A service that does not say in time is left for the first pass, and reconciliation records
    /// the publication as one this host cannot establish in the meantime.
    pub async fn settle(&self, budget: Duration) {
        let taken = self
            .uploader
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(mut uploader) = taken else {
            return;
        };
        if token_state(&self.shared.tokens, &self.shared.origin) == TokenState::Usable {
            let now = kr_ipc::now_ms();
            match tokio::time::timeout(budget, uploader.settle(now)).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    eprintln!(
                        "kr-controller: backup could not settle what an earlier run sent: {error}"
                    );
                }
                Err(_) => eprintln!(
                    "kr-controller: the storage service did not say what became of an earlier \
                     publication in time, so reconciliation records it as one this host cannot \
                     establish"
                ),
            }
        }
        *self.uploader.lock().unwrap_or_else(PoisonError::into_inner) = Some(uploader);
    }

    /// Starts carrying the outbox. It does nothing the second time.
    pub fn run(&self) {
        let Some(uploader) = self
            .uploader
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        let task = tokio::spawn(drive(
            uploader,
            Arc::clone(&self.shared),
            Arc::clone(&self.backup),
            Arc::clone(&self.timer),
        ));
        *self.task.lock().unwrap_or_else(PoisonError::into_inner) = Some(task);
    }

    /// A count of the passes the carrier has finished, which changes each time one ends, so that
    /// whatever waits for the carrier to have seen something waits for that and not for a time.
    #[must_use]
    pub fn passes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.shared.passes.subscribe()
    }

    /// Tells the carrier to look again now.
    pub fn wake(&self) {
        self.shared.signals.work.notify_one();
    }

    /// What `kr doctor` says of the storage service.
    ///
    /// It asks the service about backup storage, once and for a few seconds, unless the carrier is
    /// waiting out a delay the service asked for or has no usable token, in which case nothing is
    /// sent and the last answer stands.
    pub async fn doctor_check(&self) -> DoctorCheck {
        let token = token_state(&self.shared.tokens, &self.shared.origin);
        let delayed = self.shared.observed().in_delay;
        if token == TokenState::Usable && !delayed {
            let _ = tokio::time::timeout(
                DOCTOR_STATUS_READ,
                self.shared.read_status(&*self.shared.storage),
            )
            .await;
            // A token that has become usable since the carrier looked and found none is a reason
            // to look again.
            if self.shared.observed().token_blocked {
                self.wake();
            }
        }
        let observed = self.shared.observed();
        let mut detail = Sentence::new().stated(token.words()).stated("; ");
        detail = match (&observed.status, observed.hold) {
            (Some(status), _) if status.backup == BackupState::On => {
                detail.stated("backup storage is on for the account")
            }
            (Some(_), _) => detail.stated("backup storage is off for the account"),
            (None, Some(hold)) => detail.stated(hold_words(hold)),
            (None, None) => detail.stated("the service has not been asked yet"),
        };
        if let Some(pass) = observed.last_pass {
            detail = detail
                .stated("; the last pass took ")
                .number(pass.steps)
                .stated(" steps");
            if let Some(idle) = pass.idle {
                detail = detail.stated(" and stopped because ").stated(idle);
            }
        }
        if let Some(hold) = observed.hold.filter(|_| observed.status.is_some()) {
            detail = detail.stated("; ").stated(hold_words(hold));
        }
        let well = token == TokenState::Usable
            && observed
                .status
                .as_ref()
                .is_some_and(|status| status.backup == BackupState::On)
            && observed.hold.is_none();
        DoctorCheck::new(
            "managed-storage",
            "This host reaches its managed storage service",
            if well {
                DoctorStatus::Ok
            } else {
                DoctorStatus::Warning
            },
            detail,
            (!well).then_some(
                "Import an account token with the backup.write scope with `kr account token \
                 import`, turn backup storage on for the account, and have the account's owner \
                 enrol this host's writer key.",
            ),
        )
    }

    /// What `kr doctor` says of a host that selects no storage service.
    #[must_use]
    pub fn unconfigured_check() -> DoctorCheck {
        DoctorCheck::new(
            "managed-storage",
            "This host reaches its managed storage service",
            DoctorStatus::NotApplicable,
            Sentence::new()
                .stated("no managed storage service is selected, so this host uploads nothing"),
            None,
        )
    }
}

impl Drop for BackupRuntime {
    fn drop(&mut self) {
        // Ends the exchange in flight with the daemon. A store step that has begun finishes first,
        // because the task is cancelled only where it waits.
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
async fn drive(
    mut uploader: Uploader,
    shared: Arc<Shared>,
    backup: Arc<BackupService>,
    timer: Arc<dyn Timer>,
) {
    let mut backoff = Backoff::default();
    if token_state(&shared.tokens, &shared.origin) == TokenState::Usable {
        shared.read_status(&*shared.storage).await;
    }
    loop {
        let wait = shared.carry(&mut uploader, &backup, &mut backoff).await;
        shared.passes.send_modify(|passes| *passes += 1);
        shared.wait(wait, &*timer).await;
    }
}

/// What a hold says, in words this build wrote.
const fn hold_words(hold: Hold) -> &'static str {
    match hold.code {
        ErrorCode::QuotaExceeded => {
            "the service reports no backup allowance for the account, or no account"
        }
        ErrorCode::PermissionDenied => {
            "the service refused this host: its writer is not enrolled, or the account may not do this"
        }
        ErrorCode::HostNotConfigured => "the service is not configured for backup storage",
        ErrorCode::RateLimited | ErrorCode::ServiceCapacity | ErrorCode::UpstreamUnavailable => {
            "the service is busy or unreachable, and this host asks again"
        }
        _ => "the service turned a request back",
    }
}
