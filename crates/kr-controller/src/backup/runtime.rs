//! The carrier of this host's backup outbox: the task that takes it to the managed storage
//! service, and what `kr doctor` says of that.
//!
//! [`Uploader`] does one step at a time and says what it did. This is what runs it for as long as
//! the daemon lives. It builds the managed storage and backup manifest clients from the
//! configuration document's `storage.origin`, signs as the writer key only this host holds, and
//! presents the account token of the sign-in the host holds. It never decides what a refusal means:
//! the uploader and the service do. What it decides is when to ask again.
//!
//! # When it asks again
//!
//! * **Work arrives or becomes possible** (a generation admitted, a writer enrolled, a fence
//!   released): at once, unless the service asked to be left alone, and then when it said.
//! * **A privacy fence is raised**: at once, whatever else it waits for and whatever account token
//!   the host holds. The cleanup a fence owes ends the work in flight, and it must not wait out a
//!   delay the service asked for. A delay stays owed after a fence: it is asked for again when the
//!   fence is lifted.
//! * **The service is busy, unavailable or slow**: after the longer of the delay it named and a
//!   jittered, doubling delay of 250 ms to 30 s. A delay the service names holds every question
//!   to it, the one `kr doctor` asks and the one the host asks when it starts as well as a pass.
//! * **Only a person can clear the cause** (backup storage off, no backup allowance, a writer
//!   nobody enrolled, no usable account token): after five minutes, or when work or a writer
//!   arrives. The host's own account token is checked first and every 30 seconds, because a person
//!   signs in at a command line that tells the carrier nothing, and no request that carries the
//!   token leaves the host without a usable one. Requests that carry no token are not held back by that check: the host
//!   settles what an earlier run sent, and ends work in flight under a fence, whatever the token.
//! * **Nothing is owed**: when something changes.
//!
//! # Where it runs
//!
//! On a task of its own on the daemon's reactor, so a service that never answers holds one task and
//! stopping the daemon ends the exchange in flight. The uploader reaches the backup store only
//! through a handle that hands the thread's other tasks to another thread while it blocks, so a
//! slow disk holds one request's turn and not the reactor.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_client::services::account::{AccountTokenSource, BACKUP_WRITE_SCOPE};
use kr_client::services::{
    BackupState, HttpDeadlines, HttpService, ManagedBackupManifestService, ManagedStorageService,
    ServiceClients, ServiceHttp, ServiceSigner, StorageService, StorageStatus,
    managed_response_limits,
};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::host_account::AccountState;
use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};
use kr_protocol::scalars::{AuthorisationKey, KeyId, Signature64};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_transport::config::ProxyUrl;
use kr_transport::reconnect::Backoff;
use tokio::task::JoinHandle;

use crate::account::HostAccount;
use crate::backup::quiet::{Owed, Quiet, Timer};
use crate::backup::uploader::{Hold, Idle, PassReport, Stepped, Uploader};
use crate::backup::{BackupService, BackupSignals};
use crate::error::{ControllerError, Result};

/// How long a condition only a person can clear waits before the host asks again.
pub const OPERATOR_CEILING: Duration = Duration::from_secs(5 * 60);

/// How often the host looks again at the account token it holds, while there is work and no usable
/// token. A person signs in at a command line, which tells the carrier nothing.
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

/// What this host holds for the account token it presents, as the doctor words it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenState {
    /// No account is signed in.
    Absent,
    /// A sign-in is waiting for the person's browser, and nothing is signed in yet.
    SigningIn,
    /// The account was signed in at another service than the one storage is selected at.
    OtherService,
    /// The service ended the sign-in.
    Ended,
    /// The account is signed in and its grant lacks the scope backup storage needs, as one made
    /// before storage was selected does.
    WithoutScope,
    /// The sign-in looks whole and no token could be had from it just now, as when the account
    /// service does not answer a renewal.
    NotRenewed,
    /// The token is usable now.
    Usable,
}

impl TokenState {
    const fn words(self) -> &'static str {
        match self {
            Self::Absent => "no account is signed in on this host",
            Self::SigningIn => "a sign-in on this host is waiting to finish",
            Self::OtherService => "the account signed in on this host belongs to another service",
            Self::Ended => "the service ended the sign-in on this host",
            Self::WithoutScope => "the account signed in on this host lacks the backup.write scope",
            Self::NotRenewed => {
                "this host could not renew the token of the account signed in on this host"
            }
            Self::Usable => "an account with the backup.write scope is signed in on this host",
        }
    }

    /// What a person does about it: the sign-in is the one thing that mends each.
    const fn remedy(self) -> &'static str {
        match self {
            Self::Absent => "Sign this host in with `kr account sign-in`.",
            Self::SigningIn => "Finish the sign-in at the address `kr account sign-in` printed.",
            Self::OtherService => {
                "Sign this host in again with `kr account sign-in`, at the service storage.origin \
                 names."
            }
            Self::Ended => "Sign this host in again with `kr account sign-in`.",
            Self::WithoutScope => {
                "Sign this host in again with `kr account sign-in`, which asks for backup \
                 storage because storage.origin is set."
            }
            Self::NotRenewed => {
                "This host asks again by itself. Check that the account service is reachable, or \
                 sign this host in again with `kr account sign-in`."
            }
            Self::Usable => "",
        }
    }
}

/// Reads the sign-in as the doctor describes it when the token source gave no token, without
/// sending anything.
///
/// Whether a request may carry the token is decided by asking the [`AccountTokenSource`], which is
/// what the clients ask. This only says why, and it is read for no other purpose.
fn describe_token(account: &HostAccount, origin: &str) -> TokenState {
    match account.report().state {
        AccountState::SignedIn {
            origin: signed_in_at,
            scopes,
            ..
        } => {
            if signed_in_at != origin {
                TokenState::OtherService
            } else if !scopes.iter().any(|scope| scope == BACKUP_WRITE_SCOPE) {
                TokenState::WithoutScope
            } else {
                TokenState::NotRenewed
            }
        }
        AccountState::Ended => TokenState::Ended,
        AccountState::WaitingForBrowser { .. } | AccountState::Finishing => TokenState::SigningIn,
        AccountState::SignedOut => TokenState::Absent,
    }
}

/// What the carrier knows of the service, for `kr doctor`.
///
/// Three facts that are kept apart because each is cleared by something different: what the
/// service said about backup storage, whether the last question to it was turned back, and what
/// held back the work of the last pass. A status that reads well does not answer a publication that
/// was refused, and a pass that moved nothing does not answer a question that was.
#[derive(Debug, Default)]
struct Observed {
    /// The last answer the service gave to a status read.
    status: Option<StorageStatus>,
    /// Why the last status read was turned back by the service, when it was.
    status_refusal: Option<Hold>,
    /// What held back the work of the last pass, when something did.
    pass_hold: Option<Hold>,
    /// Whether the last question `kr doctor` put to the service went unanswered in the time it
    /// has, which leaves the last answer in hand and not known to be current.
    status_unanswered: bool,
    /// What the last pass did.
    last_pass: Option<LastPass>,
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
    /// For `duration`, which is at least what is left of the delay the service asked for, or until a
    /// fence is raised, which leaves it owed. What ends the wait clears the delay `until` names and
    /// no other.
    Owed { until: Instant, duration: Duration },
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
    tokens: &Arc<dyn AccountTokenSource>,
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
    let source = Arc::clone(tokens);
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
    /// What decides whether a request may carry an account: the same source the clients ask.
    account: Arc<dyn AccountTokenSource>,
    /// The host's sign-in, read only to say what is wrong with it.
    sign_in: Arc<HostAccount>,
    origin: String,
    writer_key_id: KeyId,
    signals: Arc<BackupSignals>,
    observed: Mutex<Observed>,
    /// When the service said it may be asked again, if it asked for a delay that has not passed.
    /// Every question to the service waits for it, whoever asks, except the ones a fence owes. The
    /// uploader holds the same record and stops between requests when it is owed.
    quiet: Arc<Quiet>,
    /// How many passes have finished, for whatever waits on one.
    passes: tokio::sync::watch::Sender<u64>,
}

impl Shared {
    fn observed(&self) -> std::sync::MutexGuard<'_, Observed> {
        self.observed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether a request may carry the host's account token now.
    async fn token_usable(&self) -> bool {
        self.account.token(BACKUP_WRITE_SCOPE).await.is_ok()
    }

    /// What to wait on after the service held work back. Any delay it named was recorded where
    /// the answer arrived.
    fn after(&self, hold: Hold, backoff: &mut Backoff) -> Wait {
        let owed = self.quiet.owed();
        if hold.needs_a_person() {
            // Waiting does not clear the cause, so the host asks again after five minutes or when
            // work or a writer arrives, and after a longer delay the service named. Work that
            // arrives sooner still waits out the delay: the next pass begins by looking at it.
            return Wait::Timed {
                duration: owed.map_or(OPERATOR_CEILING, |owed| OPERATOR_CEILING.max(owed.left)),
                wakeable: true,
            };
        }
        match owed {
            Some(Owed { until, left }) => Wait::Owed {
                until,
                duration: backoff.next_delay().max(left),
            },
            None => Wait::Timed {
                duration: backoff.next_delay(),
                wakeable: false,
            },
        }
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
                observed.status_refusal = None;
                observed.status_unanswered = false;
            }
            if matches!(report.idle, Some(Idle::Unavailable { .. })) {
                observed.status_refusal = report.hold;
                observed.status_unanswered = false;
            }
            // What the pass met while it carried work is what held the work back. When it met
            // nothing, that stands cleared only if the pass ran its work to the end: one that
            // stopped at a delay did not, and says nothing of what held the work before. A pass
            // that was turned back at its first question carried no work, and what it met is the
            // status refusal above.
            if report.idle.is_none() && (report.hold.is_some() || report.quiet.is_none()) {
                observed.pass_hold = report.hold;
            }
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
            return self.after(hold, backoff);
        }
        // The pass stopped because the service asked to be left alone, in an answer to some
        // question, and work remains. It waits for the delay as it stood when the pass stopped.
        if let Some(Owed { until, left }) = report.quiet {
            return Wait::Owed {
                until,
                duration: left,
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
                tokio::select! {
                    () = timer.sleep(duration) => {}
                    () = signals.fence.notified() => {}
                }
            }
            Wait::Owed { until, duration } => {
                tokio::select! {
                    // What was asked for has passed, unless the service asked for more while this
                    // waited.
                    () = timer.sleep(duration) => self.quiet.passed(until),
                    () = signals.fence.notified() => {}
                }
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
        let fenced = on_disk(|| {
            backup
                .privacy_status()
                .is_ok_and(|privacy| privacy.inhibited_at().is_some())
        });
        // A fence is answered whatever the service asked and whatever token the host holds: ending
        // work in flight is what the host owes, and a request that cannot be signed in is not sent.
        if !fenced {
            if let Some(Owed { until, left }) = self.quiet.owed() {
                return Wait::Owed {
                    until,
                    duration: left,
                };
            }
            if !self.token_usable().await {
                // The question `Uploader::pass` asks before it asks the service anything.
                let nothing_to_carry = !uploader.has_work().unwrap_or(true);
                // Nothing that carries the token leaves this host without a usable one. With
                // nothing to carry there is nothing to check for either, and work arriving is
                // what looks again.
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
        }
        self.observed().token_blocked = false;
        match uploader.pass(kr_ipc::now_ms()).await {
            Ok(report) => {
                let wait = self.absorb(&report, backoff);
                // A refusal only a person can mend, met by a host whose token has stopped being
                // usable since the check, is the token to wait for and not a five-minute wait.
                if !fenced
                    && report.hold.is_some_and(|hold| hold.needs_a_person())
                    && !self.token_usable().await
                {
                    // What was refused was the host's own token and not a thing at the service, so
                    // the doctor says the token and not a refusal.
                    let mut observed = self.observed();
                    observed.token_blocked = true;
                    observed.pass_hold = None;
                    drop(observed);
                    return Wait::Timed {
                        duration: TOKEN_CHECK,
                        wakeable: true,
                    };
                }
                wait
            }
            Err(error) => {
                eprintln!("kr-controller: the backup pass could not use its store: {error}");
                Wait::Timed {
                    duration: backoff.next_delay(),
                    wakeable: true,
                }
            }
        }
    }

    /// Asks the service what it says about backup storage and notes the answer. A refusal is
    /// returned, and any delay in it is owed to every question that follows.
    async fn read_status(&self) -> Option<Hold> {
        match self.storage.status().await {
            Ok(status) => {
                let mut observed = self.observed();
                observed.status = Some(status);
                observed.status_refusal = None;
                observed.status_unanswered = false;
                None
            }
            Err(error) => {
                let hold = Hold::of(&error);
                {
                    let mut observed = self.observed();
                    observed.status_refusal = Some(hold);
                    observed.status_unanswered = false;
                }
                if let Some(delay) = hold.retry_after {
                    self.quiet.owe(delay);
                }
                Some(hold)
            }
        }
    }
}

/// Runs `access`, which blocks on the disk, without holding a thread the reactor runs other tasks
/// on.
fn on_disk<T>(access: impl FnOnce() -> T) -> T {
    tokio::task::block_in_place(access)
}

/// The carrier of one host's backup outbox.
pub struct BackupRuntime {
    shared: Arc<Shared>,
    backup: Arc<BackupService>,
    timer: Arc<dyn Timer>,
    writer_public: AuthorisationKey,
    /// The uploader, until the task takes it.
    uploader: Mutex<Option<Uploader>>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for BackupRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackupRuntime")
            .field("writer_public_key", &self.writer_public)
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
        account: Arc<HostAccount>,
        timer: Arc<dyn Timer>,
    ) -> Result<Self> {
        let (Some(storage), Some(manifest)) = (&clients.storage, &clients.backup_manifest) else {
            return Err(ControllerError::NotConfigured(
                "backup needs a storage client and a backup manifest client".to_owned(),
            ));
        };
        let writer_public = *writer.public();
        let quiet = Arc::new(Quiet::new(Arc::clone(&timer)));
        let shared = Arc::new(Shared {
            storage: Arc::clone(storage),
            account: account.tokens(),
            sign_in: account,
            origin: origin.as_str().to_owned(),
            writer_key_id: writer.key_id(),
            signals: backup.signals(),
            observed: Mutex::default(),
            quiet: Arc::clone(&quiet),
            passes: tokio::sync::watch::channel(0).0,
        });
        let uploader = Uploader::new(
            Arc::clone(&backup),
            Arc::clone(storage),
            Arc::clone(manifest),
            writer,
            quiet,
            kr_ipc::now_ms(),
        );
        Ok(Self {
            shared,
            backup,
            timer,
            writer_public,
            uploader: Mutex::new(Some(uploader)),
            task: Mutex::new(None),
        })
    }

    /// The public half of the key this host publishes as, which an owner enrols at the service as
    /// the writer of a collection.
    #[must_use]
    pub const fn writer_public_key(&self) -> AuthorisationKey {
        self.writer_public
    }

    /// Records the publications an earlier run sent that the service holds, giving the service
    /// `budget` to say, before the store is reconciled.
    ///
    /// A fetch carries no account token, so this does not wait for one. A service that does not
    /// say in time is left for the first pass, and reconciliation records the publication as one
    /// this host cannot establish in the meantime.
    pub async fn settle(&self, budget: Duration) {
        let taken = self
            .uploader
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(mut uploader) = taken else {
            return;
        };
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
    /// It asks the service about backup storage, once and for a few seconds, unless the service
    /// asked to be left alone or the host has no usable token, in which case nothing is sent and
    /// the last answer stands.
    pub async fn doctor_check(&self) -> DoctorCheck {
        let usable = self.shared.token_usable().await;
        if usable && self.shared.quiet.left().is_none() {
            if tokio::time::timeout(DOCTOR_STATUS_READ, self.shared.read_status())
                .await
                .is_err()
            {
                self.shared.observed().status_unanswered = true;
            }
            // A token that has become usable since the carrier looked and found none is a reason
            // to look again.
            if self.shared.observed().token_blocked {
                self.wake();
            }
        }
        let state = if usable {
            TokenState::Usable
        } else {
            describe_token(&self.shared.sign_in, &self.shared.origin)
        };
        let observed = self.shared.observed();
        let writer = self.shared.writer_key_id;

        let mut detail = Sentence::new().stated(state.words()).stated("; ");
        detail = match (&observed.status, observed.status_refusal) {
            (Some(status), _) if status.backup == BackupState::On => {
                let detail = detail.stated("backup storage is on for the account");
                match status.allowance_bytes {
                    Some(bytes) => detail
                        .stated(", which has an allowance of ")
                        .number(bytes)
                        .stated(" bytes"),
                    None => detail,
                }
            }
            (Some(_), _) => detail.stated("backup storage is off for the account"),
            (None, Some(hold)) => hold_sentence(detail, hold, writer),
            (None, None) if self.shared.quiet.left().is_some() => {
                detail.stated("the service asked to be left alone, and the host is waiting it out")
            }
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
        if observed.status.is_some()
            && let Some(hold) = observed.status_refusal
        {
            detail = hold_sentence(
                detail.stated("; the last question to the service was turned back: "),
                hold,
                writer,
            );
        }
        if let Some(hold) = observed.pass_hold {
            detail = hold_sentence(
                detail.stated("; the last pass that carried work was held back: "),
                hold,
                writer,
            );
        }
        if observed.status_unanswered {
            detail = detail.stated(
                "; the service did not answer the last question in time, so the answer above may \
                 be out of date",
            );
        }
        let backup_on = observed
            .status
            .as_ref()
            .is_some_and(|status| status.backup == BackupState::On);
        let well = state == TokenState::Usable
            && backup_on
            && observed.status_refusal.is_none()
            && observed.pass_hold.is_none()
            && !observed.status_unanswered;
        // An answer that backup storage is off is the newest fact only while no later question to
        // the service was turned back.
        let backup_off = observed.status.is_some()
            && !backup_on
            && !observed.status_unanswered
            && observed.status_refusal.is_none();
        let remedy = if well {
            None
        } else if state != TokenState::Usable {
            Some(state.remedy())
        } else if backup_off {
            Some("Turn backup storage on for the account.")
        } else {
            // The newest fact decides: a status read the service turned back is newer than the pass
            // before it, and, while the answer in hand says storage is off, it is the pass's hold
            // that is old.
            let held = if observed.status.is_some() && !backup_on {
                observed.status_refusal
            } else {
                match (observed.pass_hold, observed.status_refusal) {
                    // What only a person can mend outranks what passes by itself.
                    (Some(pass), Some(refusal)) => Some(pass.and(refusal)),
                    (pass, refusal) => pass.or(refusal),
                }
            };
            match held {
                Some(hold) => Some(remedy_for(hold)),
                None => Some("Run `kr doctor` again once the service answers."),
            }
        };
        DoctorCheck::new(
            "managed-storage",
            "This host reaches its managed storage service",
            if well {
                DoctorStatus::Ok
            } else {
                DoctorStatus::Warning
            },
            detail,
            remedy,
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
    // The first question to the service is the host's own, made as it starts. What the service says
    // to it binds the carrier like any other answer: a delay it names is waited out before the
    // first pass, and a refusal only a person can mend is waited for as one.
    let mut next = None;
    if let Some(Owed { until, left }) = shared.quiet.owed() {
        // The question the host asked about a publication an earlier run sent was turned back with
        // a delay, which binds this one too. A host that starts under a privacy fence is not held
        // by it: the fence is raised again before this task runs, and its permit ends this wait at
        // once.
        next = Some(Wait::Owed {
            until,
            duration: left,
        });
    } else if shared.token_usable().await
        && let Some(hold) = shared.read_status().await
    {
        next = Some(shared.after(hold, &mut backoff));
    }
    loop {
        let wait = match next.take() {
            Some(wait) => wait,
            None => shared.carry(&mut uploader, &backup, &mut backoff).await,
        };
        shared.passes.send_modify(|passes| *passes += 1);
        shared.wait(wait, &*timer).await;
    }
}

/// Says what a hold is, in words this build wrote. The writer's key identifier is named where the
/// remedy is to enrol it.
fn hold_sentence(detail: Sentence, hold: Hold, writer: KeyId) -> Sentence {
    match hold.code {
        ErrorCode::QuotaExceeded => {
            detail.stated("the service reports no backup allowance for the account, or no account")
        }
        ErrorCode::PermissionDenied => detail
            .stated(
                "the service refused a request as not permitted, which is what it answers when \
                 nobody has enrolled this host's writer key (its identifier starts, in \
                 hexadecimal, ",
            )
            .hexadecimal(u64::from_be_bytes(
                writer.as_bytes()[..8].try_into().unwrap_or([0; 8]),
            ))
            .stated(") or when the account may not do this"),
        ErrorCode::HostNotConfigured => {
            detail.stated("the service is not configured for backup storage")
        }
        ErrorCode::RateLimited | ErrorCode::ServiceCapacity | ErrorCode::UpstreamUnavailable => {
            detail.stated("the service is busy or unreachable, and this host asks again")
        }
        _ => detail.stated("the service turned a request back"),
    }
}

/// What a person does about a hold.
const fn remedy_for(hold: Hold) -> &'static str {
    match hold.code {
        ErrorCode::QuotaExceeded => {
            "Sign the host in to an account with a backup allowance, or raise the allowance."
        }
        ErrorCode::PermissionDenied => {
            "If nobody has yet, have the account's owner enrol this host's writer key as a \
             backup writer."
        }
        ErrorCode::HostNotConfigured => {
            "Tell the service's operator that backup storage is not configured."
        }
        _ => "This host asks again by itself. Check that the service is reachable.",
    }
}
