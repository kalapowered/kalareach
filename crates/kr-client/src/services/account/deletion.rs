//! Deleting the signed-in account from the application.
//!
//! The managed service offers four routes for it: what deleting would do, an emailed code that
//! confirms it, the confirmation, and the outcome by receipt. This module is the client of those
//! routes and the record that makes a lost answer recoverable.
//!
//! # One owner
//!
//! A deletion is begun, confirmed, looked at and settled by one owner at a time: a lock in this
//! process and, on a computer, where a second launch of the application is a second process over
//! the same store, an advisory lock on a file that the system lets go of when its holder ends. A
//! caller that finds the owner held does not wait and does not race it. Beginning or confirming is
//! refused as [`DeletionFault::InProgress`], and a look reports what the record shows. Nothing else
//! acts on the record while the owner holds it, so the record carries no claims, no times of
//! requests and no margins.
//!
//! # The receipt
//!
//! The confirmation carries a receipt the client made: 128 random bits that the service keeps only
//! a digest of. It is written to the secure store, with the account it is for, before the
//! confirmation leaves, because the receipt is the only way to learn what became of a request whose
//! answer was lost, and the account that sent it will not be able to sign in once the request has
//! been carried out.
//!
//! A record that exists says that a request of its deletion may have run and is not known to have:
//! a request the service answered, or refused before it ran, is not kept. A later confirmation for
//! the same account reuses the receipt. The record is removed when the closure is known and what
//! this device has to settle is settled, when the person gives up on it ([`forget`]), and after
//! [`KEPT_FOR_MS`]. It is never read as proof that a deletion did not go through: the service
//! saying `unknown` to a receipt means no more than that.
//!
//! # Learning that the account is closed
//!
//! A `closed` answer, and a status of `open` or `done`, all say the same thing: the account no
//! longer exists at the service. Each does the same local work, under the owner and again if it was
//! interrupted: it ends the stored grant without telling the service (the service has ended it
//! already), and it runs the application's own steps (the notifications of a phone, the recovery
//! record of a computer), each until it says it is done.
//!
//! # Whose it is to see
//!
//! The record of a deletion is the person's who began it. It is reported to the account that is
//! signed in when that account is the record's, and, when nobody is signed in, to the flow in this
//! process that began it for as long as nobody has signed in or out since. A sign-out of another
//! account does not bring a closed account's deletion back.
//!
//! # What is never rendered
//!
//! The code, the token, the receipt and the address are never in a rendering of anything here.

use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kr_protocol::error::ErrorCode;
use kr_protocol::service::GatewayOrigin;
use serde::{Deserialize, Serialize};

use super::{AccountMark, AccountStatus, SignedInAccount, storage};
use crate::error::{ClientError, Result};
use crate::services::signed::{Repeat, data_or_refusal};
use crate::services::{ServiceHttp, ServiceHttpAnswer};
use crate::shown::Shown;

/// What a deletion asks of the token: the scope every sign-in has.
const SCOPE: &str = "openid";

/// Where the routes are, on the account origin.
const VIEW_PATH: &str = "/api/account/deletion";
const CODE_PATH: &str = "/api/account/deletion/code";
const STATUS_PATH: &str = "/api/account/deletion/status";

/// The stored item that holds the record.
const DELETION_ITEM: &str = "account/deletion";

/// The record's version.
const RECORD_VERSION: u32 = 1;

/// How long a record is kept: a deletion with no outcome, or an account that is closed whose removal
/// the service has not said is done. Stored backup files are gone within seven days, and a deletion
/// replayed after a restore can leave one the service cannot match to its receipt.
pub const KEPT_FOR_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// The most organisations one confirmation can accept.
pub const ACKNOWLEDGED_MAXIMUM: usize = 50;

/// The digits in the code.
pub const CODE_DIGITS: usize = 8;

/// How often and how long a lost answer is looked for by receipt.
const LOOKS: usize = 3;
const LOOK_EVERY: Duration = Duration::from_secs(3);

/* -------------------------------------------------------------------------- */
/* What the person is told before                                              */
/* -------------------------------------------------------------------------- */

/// Something the person should know before they confirm.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeletionWarning {
    /// The account owns an organisation, which is left with no one able to administer it.
    OrganisationOwner {
        /// The organisation.
        organisation_id: String,
        /// Its name.
        name: String,
        /// How many members it has.
        members: u64,
    },
    /// A live subscription ends at once.
    Subscription,
    /// A credit balance is lost.
    Credit,
    /// Money owed stays recorded.
    MoneyOwed,
}

/// What a deletion removes.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletedKind {
    /// Every sign-in on every device.
    SignIns,
    /// The passkeys, the address and the name.
    PasskeysAndAddress,
    /// The public records of the backups the account paid for.
    BackupRecords,
    /// The recovery bundle.
    RecoveryBundle,
    /// Relay and voice use.
    RelayAndVoiceEnded,
    /// The customer record at the payment provider.
    PaymentRecord,
    /// The organisation memberships.
    OrganisationMemberships,
    /// The notification registrations and settings copies of the devices the account's records name.
    DeviceRegistrations,
}

impl DeletedKind {
    fn from_key(key: &str) -> Option<Self> {
        Some(match key {
            "sign_ins" => Self::SignIns,
            "passkeys_and_address" => Self::PasskeysAndAddress,
            "backup_records" => Self::BackupRecords,
            "recovery_bundle" => Self::RecoveryBundle,
            "relay_and_voice_ended" => Self::RelayAndVoiceEnded,
            "payment_record" => Self::PaymentRecord,
            "organisation_memberships" => Self::OrganisationMemberships,
            "device_registrations" => Self::DeviceRegistrations,
            _ => return None,
        })
    }
}

/// What a deletion leaves.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeptKind {
    /// Invoices and records of what was charged.
    BillingRecords,
    /// Relay leases and use.
    RelayRecords,
    /// Voice calls.
    CallRecords,
    /// Voice reasoning requests.
    ReasoningRecords,
    /// An index row for each backed-up object.
    BackupIndexRows,
    /// Records that belong to an organisation.
    OrganisationRecords,
    /// Records that name the devices' keys.
    DeviceRecords,
    /// The service's own recovery copies.
    RecoveryCopies,
    /// What other services keep.
    OtherServices,
}

impl KeptKind {
    fn from_key(key: &str) -> Option<Self> {
        Some(match key {
            "billing_records" => Self::BillingRecords,
            "relay_records" => Self::RelayRecords,
            "call_records" => Self::CallRecords,
            "reasoning_records" => Self::ReasoningRecords,
            "backup_index_rows" => Self::BackupIndexRows,
            "organisation_records" => Self::OrganisationRecords,
            "device_records" => Self::DeviceRecords,
            "recovery_copies" => Self::RecoveryCopies,
            "other_services" => Self::OtherServices,
            _ => return None,
        })
    }
}

/// What deleting the account would do, as the service says it.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct DeletionPreview {
    /// The account's address, masked by the service.
    pub address: String,
    /// What the person should know first.
    pub warnings: Vec<DeletionWarning>,
    /// What is removed.
    pub deleted: Vec<DeletedKind>,
    /// What is left.
    pub kept: Vec<KeptKind>,
    /// Whether the service listed something removed or kept that this build has no words for.
    pub unlisted: bool,
    /// Years the invoices and records of what was charged are kept.
    pub kept_records_years: u32,
    /// Days within which stored backup files are removed.
    pub backup_file_days: u32,
    /// Minutes the code lasts.
    pub code_lifetime_minutes: u32,
}

impl fmt::Debug for DeletionPreview {
    /// What a rendering says: that there is a preview and how much it lists, never the address.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeletionPreview")
            .field("warnings", &self.warnings.len())
            .field("deleted", &self.deleted.len())
            .field("kept", &self.kept.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DeletionWarning {
    /// Which warning it is, never the organisation's name.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OrganisationOwner { .. } => {
                formatter.write_str("DeletionWarning::OrganisationOwner")
            }
            Self::Subscription => formatter.write_str("DeletionWarning::Subscription"),
            Self::Credit => formatter.write_str("DeletionWarning::Credit"),
            Self::MoneyOwed => formatter.write_str("DeletionWarning::MoneyOwed"),
        }
    }
}

impl fmt::Debug for DeletedKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeletedKind")
    }
}

impl fmt::Debug for KeptKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeptKind")
    }
}

/// What reading the preview came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeletionRead {
    /// The preview, to show.
    Ready(DeletionPreview),
    /// A warning or a choice this build does not know: it concerns money or other people, so the
    /// person is not asked to go on.
    CannotShow,
}

/* -------------------------------------------------------------------------- */
/* What came of a confirmation                                                 */
/* -------------------------------------------------------------------------- */

/// An organisation the account owns.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct OwnedOrganisation {
    /// The organisation.
    pub organisation_id: String,
    /// Its name.
    pub name: String,
    /// How many members it has.
    pub members: u64,
}

impl fmt::Debug for OwnedOrganisation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedOrganisation")
            .finish_non_exhaustive()
    }
}

/// Why a code was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeRefusal {
    /// The code is not the one sent. The same code can be tried again while tries are left.
    Wrong,
    /// The code ran out of time.
    Expired,
    /// The code is used up, or none is held.
    Spent,
}

/// What the confirmation came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeletionOutcome {
    /// The account is closed. `finished` says the removal had finished already.
    Closed {
        /// Whether the whole removal was done inside the request.
        finished: bool,
    },
    /// The code was refused and nothing changed.
    CodeRefused {
        /// Why.
        reason: CodeRefusal,
        /// How many checks the current code still allows.
        attempts_left: u32,
    },
    /// The account owns organisations the request did not accept losing; nothing changed.
    Acknowledge {
        /// The organisations.
        organisations: Vec<OwnedOrganisation>,
    },
    /// The answer was lost and the receipt could not say whether the request arrived.
    Unsettled,
}

/* -------------------------------------------------------------------------- */
/* How it is going                                                             */
/* -------------------------------------------------------------------------- */

/// How the removal is going, for the person who began it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionProgress {
    /// No deletion of this person's is followed on this device.
    None,
    /// A confirmation left and nothing yet says whether it arrived: it may still close the account.
    Unsettled,
    /// The account is closed and the removal is running.
    Open,
    /// The removal has finished.
    Done,
}

/// What a look found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeletionStatus {
    /// How the removal is going.
    pub progress: DeletionProgress,
    /// Whether this look is the one that learned the account is closed, so that the sign-in it just
    /// ended is told to whoever shows it.
    pub closed_now: bool,
}

/// What a step came to: whether it is done, or has nothing to do. A step that is not done is tried
/// again at the next look and the next start.
pub type StepFuture<'a> = Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

/// The application's own state, settled once the account is closed.
pub trait DeviceSteps: Send + Sync {
    /// Settles the notifications of a phone.
    fn notifications(&self) -> StepFuture<'_>;
    /// Settles the recovery record of a computer, if it is the record of `deleted`: a record that is
    /// not known to be that account's is left as it is.
    fn recovery(&self, deleted: AccountMark) -> StepFuture<'_>;
}

/// Why a step could not be taken, as a kind the page branches on and never as a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeletionFault {
    /// No account is signed in, the sign-in has ended, or it lacks the scope: signing in mends it.
    NeedsSignIn,
    /// The service or this client does not accept the request as made.
    Refused,
    /// Too many tries; wait this many seconds.
    Busy {
        /// Seconds to wait.
        seconds: u64,
    },
    /// The service could not send the email.
    MailFailed,
    /// Whether the request had its effect is not known.
    Unsure,
    /// The service could not be reached or did not answer.
    Unreachable,
    /// A different account is signed in than the one this deletion began for.
    AccountChanged,
    /// The deletion is being worked on, in this application or in another window of it.
    InProgress,
    /// This device could not keep or read its own records.
    Local(Shown),
}

/* -------------------------------------------------------------------------- */
/* The record                                                                  */
/* -------------------------------------------------------------------------- */

/// The deletion this device is part of, kept in the secure store.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    v: u32,
    /// The account it is for, as the hex of its mark.
    mark: String,
    /// The receipt: 32 lowercase hex characters.
    receipt: String,
    /// When it was begun, and, once the account is closed, when that was learned.
    since_ms: u64,
    /// Whether the account is known to be closed.
    closed: bool,
    /// Whether the service said the removal is done.
    done: bool,
    /// Whether the application has settled a phone's notifications.
    notifications: bool,
    /// Whether the application has settled a computer's recovery record.
    recovery: bool,
}

impl Record {
    fn begun(mark: &str, receipt: &str, now: u64) -> Self {
        Self {
            v: RECORD_VERSION,
            mark: mark.to_owned(),
            receipt: receipt.to_owned(),
            since_ms: now,
            closed: false,
            done: false,
            notifications: false,
            recovery: false,
        }
    }

    const fn settled(&self) -> bool {
        self.notifications && self.recovery
    }

    fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.since_ms) > KEPT_FOR_MS
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

fn fresh_receipt() -> Result<String> {
    let mut bytes = [0u8; 16];
    kr_crypto::random_bytes(&mut bytes).map_err(|error| {
        storage(crate::shown!(
            "a receipt could not be drawn: {}",
            Shown::crypto(&error)
        ))
    })?;
    Ok(hex(&bytes))
}

fn held<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl SignedInAccount {
    fn deletion_clock(&self) -> u64 {
        (self.clock_ms)()
    }

    fn read_deletion(&self) -> Result<Option<Record>> {
        let found = self
            .store
            .get(&self.name(DELETION_ITEM)?)
            .map_err(|error| {
                storage(crate::shown!(
                    "the deletion record could not be read: {}",
                    Shown::crypto(&error)
                ))
            })?;
        // A record this build cannot read is no record: the next deletion makes a new one.
        Ok(found
            .and_then(|bytes| serde_json::from_slice::<Record>(bytes.expose()).ok())
            .filter(|record| record.v == RECORD_VERSION))
    }

    fn write_deletion(&self, record: &Record) -> Result<()> {
        let bytes = serde_json::to_vec(record).map_err(|error| {
            storage(crate::shown!(
                "the deletion record could not be written: {}",
                Shown::json(&error)
            ))
        })?;
        self.store
            .set(&self.name(DELETION_ITEM)?, &bytes)
            .map_err(|error| {
                storage(crate::shown!(
                    "the deletion record could not be kept: {}",
                    Shown::crypto(&error)
                ))
            })
    }

    fn drop_deletion(&self) -> Result<()> {
        self.store
            .delete(&self.name(DELETION_ITEM)?)
            .map_err(|error| {
                storage(crate::shown!(
                    "the deletion record could not be removed: {}",
                    Shown::crypto(&error)
                ))
            })
    }

    /// The account the stored grant is for at `origin`, when one is stored.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read.
    pub fn signed_in_mark(&self, origin: &str) -> Result<Option<AccountMark>> {
        Ok(self.read_grant()?.map(|grant| grant.mark_at(origin)))
    }

    /// Ends the stored grant if it is still the grant of the closed account `mark`, without telling
    /// the service, and lets go of a note that the sign-in ended: the account is closed, and a
    /// sign-in that ended with it is not a separate event. Once, and again if it was interrupted.
    /// Says whether it changed anything.
    async fn end_closed_grant(&self, origin: &str, mark: &str) -> Result<bool> {
        let _held = self.hold().await?;
        let grant = self.read_grant()?;
        let ours = grant
            .as_ref()
            .is_some_and(|grant| grant.mark_at(origin).to_hex() == mark);
        if ours {
            self.delete_grant()?;
        }
        let noted = (ours || grant.is_none()) && self.ended.swap(false, Ordering::SeqCst);
        if ours || noted {
            self.publish();
        }
        Ok(ours || noted)
    }
}

/* -------------------------------------------------------------------------- */
/* The client                                                                  */
/* -------------------------------------------------------------------------- */

/// What one request came to, before a route decides what it means.
enum Sent {
    /// The service's `data`.
    Data(serde_json::Value),
    /// The service named a refusal.
    Refusal {
        code: Option<&'static str>,
        retry_after_seconds: Option<u64>,
        /// Whether the failure is the kind that can follow the service acting.
        server_side: bool,
    },
    /// No answer this client can read: none at all, a gateway's page, an unreadable success.
    Lost,
    /// The request was not made.
    Fault(DeletionFault),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Route {
    View,
    Code,
    Confirm,
    Status,
}

impl Route {
    fn path(self) -> &'static str {
        match self {
            Self::View => VIEW_PATH,
            Self::Code => CODE_PATH,
            Self::Confirm => VIEW_PATH,
            Self::Status => STATUS_PATH,
        }
    }

    fn repeat(self) -> Repeat {
        match self {
            Self::View | Self::Status => Repeat::Safe,
            Self::Code | Self::Confirm => Repeat::Unsafe,
        }
    }
}

/// The account the deletion in front of the person is for, and whether anyone has signed in or out
/// since it was last followed.
struct Flow {
    mark: Option<AccountMark>,
    seen: tokio::sync::watch::Receiver<AccountStatus>,
}

/// The one owner of a deletion, held. The shared file goes first, so it is let go of before the lock
/// in this process.
struct Owner<'a> {
    file: Option<std::fs::File>,
    _mutex: tokio::sync::MutexGuard<'a, ()>,
}

impl Drop for Owner<'_> {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = kr_flush::lock::release(&file);
        }
    }
}

/// The deletion a confirmation carries.
struct Begun {
    mark: String,
    receipt: String,
    /// Whether this confirmation made the record. A record that was there already belongs to an
    /// earlier request that may have run, which nothing this one learns can say did not.
    fresh: bool,
}

/// What a look at a record came to.
struct Advanced {
    progress: DeletionProgress,
    closed_now: bool,
}

/// The managed service's account deletion, for the account signed in on this device.
pub struct ManagedAccountDeletion {
    origin: String,
    http: Arc<dyn ServiceHttp>,
    account: Arc<SignedInAccount>,
    /// The owner, in this process.
    owner: tokio::sync::Mutex<()>,
    /// The file the owner is also held on, for another process on this machine.
    shared_lock: Option<PathBuf>,
    flow: Mutex<Flow>,
    look_every: Duration,
}

impl fmt::Debug for ManagedAccountDeletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedAccountDeletion")
            .field("origin", &Shown::address(&self.origin))
            .finish_non_exhaustive()
    }
}

impl ManagedAccountDeletion {
    /// The deletion of the account `account` holds, asked of the service at `origin` through `http`.
    #[must_use]
    pub fn new(
        origin: &GatewayOrigin,
        http: Arc<dyn ServiceHttp>,
        account: Arc<SignedInAccount>,
    ) -> Self {
        let seen = account.subscribe();
        Self {
            origin: origin.as_str().to_owned(),
            http,
            account,
            owner: tokio::sync::Mutex::new(()),
            shared_lock: None,
            flow: Mutex::new(Flow { mark: None, seen }),
            look_every: LOOK_EVERY,
        }
    }

    /// Also holds the owner on an advisory lock on `path`, for another process on this machine that
    /// shares the store.
    #[must_use]
    pub fn with_shared_lock(mut self, path: PathBuf) -> Self {
        self.shared_lock = Some(path);
        self
    }

    /// Looks for a lost answer every `interval`, for a test that must not wait.
    #[must_use]
    pub const fn looking_every(mut self, interval: Duration) -> Self {
        self.look_every = interval;
        self
    }

    fn url(&self, route: Route) -> String {
        format!("{}{}", self.origin, route.path())
    }

    /// Takes the owner if nobody holds it. Says none when someone does; it never waits.
    async fn try_own(&self) -> std::result::Result<Option<Owner<'_>>, DeletionFault> {
        let Ok(mutex) = self.owner.try_lock() else {
            return Ok(None);
        };
        let file = match &self.shared_lock {
            None => None,
            Some(path) => {
                let path = path.clone();
                let taken = tokio::task::spawn_blocking(
                    move || -> std::io::Result<Option<std::fs::File>> {
                        let mut options = std::fs::OpenOptions::new();
                        options.create(true).truncate(false).write(true);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::OpenOptionsExt as _;
                            options.mode(0o600);
                        }
                        let file = options.open(&path)?;
                        match kr_flush::lock::try_exclusive(&file) {
                            Ok(()) => Ok(Some(file)),
                            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
                            Err(std::fs::TryLockError::Error(error)) => Err(error),
                        }
                    },
                )
                .await
                .map_err(|_| local(storage("the deletion lock could not be taken")))?
                .map_err(|error| {
                    local(storage(crate::shown!(
                        "the deletion lock could not be taken: {}",
                        Shown::io(&error)
                    )))
                })?;
                match taken {
                    Some(file) => Some(file),
                    None => return Ok(None),
                }
            }
        };
        Ok(Some(Owner {
            file,
            _mutex: mutex,
        }))
    }

    /// Takes the owner, or refuses: the deletion is being worked on.
    async fn own(&self) -> std::result::Result<Owner<'_>, DeletionFault> {
        self.try_own().await?.ok_or(DeletionFault::InProgress)
    }

    /// The bearer value and the account's mark, from one read of the grant.
    async fn authorise(
        &self,
        renew: bool,
    ) -> std::result::Result<(String, AccountMark), DeletionFault> {
        match self.account.token_marked(SCOPE, &self.origin, renew).await {
            Ok((token, mark)) => Ok((format!("Bearer {}", token.expose()), mark)),
            Err(error) => Err(match error.code() {
                ErrorCode::HostNotConfigured | ErrorCode::PermissionDenied => {
                    DeletionFault::NeedsSignIn
                }
                ErrorCode::StorageUnavailable | ErrorCode::InvalidArgument => {
                    DeletionFault::Local(crate::shown::Said::said(&error))
                }
                _ => DeletionFault::Unreachable,
            }),
        }
    }

    /// Binds the deletion in front of the person to one account, and refuses another.
    fn bind(&self, mark: AccountMark, begin: bool) -> std::result::Result<(), DeletionFault> {
        let mut flow = held(&self.flow);
        match flow.mark {
            Some(bound) if bound != mark && !begin => Err(DeletionFault::AccountChanged),
            Some(bound) if bound == mark && !begin => Ok(()),
            _ => {
                flow.mark = Some(mark);
                flow.seen.borrow_and_update();
                Ok(())
            }
        }
    }

    /// Whether the deletion in front of the person began for the account `mark` names.
    fn is_flow(&self, mark: &str) -> bool {
        held(&self.flow)
            .mark
            .is_some_and(|bound| bound.to_hex() == mark)
    }

    /// The record of the account that is signed in is followed by this flow from now on, so that a
    /// closure learned meanwhile, which ends the very sign-in that says whose it is, is still shown.
    fn follow_if_signed_in(&self, mark: &str) -> std::result::Result<(), DeletionFault> {
        let signed_in = self
            .account
            .signed_in_mark(&self.origin)
            .map_err(local)?
            .map(AccountMark::to_hex);
        if signed_in.as_deref() == Some(mark) {
            let mut flow = held(&self.flow);
            flow.mark = AccountMark::from_hex(mark);
            flow.seen.borrow_and_update();
        }
        Ok(())
    }

    /// `progress`, if the deletion it is of is the person's: the signed-in account's, or, when no one
    /// is signed in, that of the flow in this process that began it, until someone signs in or out.
    fn shown(
        &self,
        mark: &str,
        progress: DeletionProgress,
    ) -> std::result::Result<DeletionProgress, DeletionFault> {
        let signed_in = self
            .account
            .signed_in_mark(&self.origin)
            .map_err(local)?
            .map(AccountMark::to_hex);
        let theirs = match signed_in {
            Some(signed_in) => signed_in == mark,
            None => {
                let flow = held(&self.flow);
                flow.mark.is_some_and(|bound| bound.to_hex() == mark)
                    && !flow.seen.has_changed().unwrap_or(true)
            }
        };
        Ok(if theirs {
            progress
        } else {
            DeletionProgress::None
        })
    }

    /// Sends one request and says what came of it.
    async fn send(&self, route: Route, authorisation: Option<&str>, body: Option<&[u8]>) -> Sent {
        let url = self.url(route);
        let headers_with;
        let headers: &[(&str, &str)] = match authorisation {
            Some(value) => {
                headers_with = [("authorization", value)];
                &headers_with
            }
            None => &[],
        };
        let answer: std::result::Result<ServiceHttpAnswer, ClientError> = match (route, body) {
            (Route::View, _) => self.http.get_json(&url, headers).await,
            (_, body) => {
                self.http
                    .post_json(&url, body.unwrap_or(b"{}"), headers)
                    .await
            }
        };
        let Ok(answer) = answer else {
            return Sent::Lost;
        };
        match data_or_refusal(&answer, route.repeat()) {
            Ok(data) => Sent::Data(data),
            Err(error) => {
                let ClientError::Refused {
                    retry_after_seconds,
                    service_code,
                    ..
                } = &error
                else {
                    return Sent::Lost;
                };
                // The service may have acted when it failed (a fault of its own, a gateway that lost
                // its answer) or when this client could not read a success: the shared reader says so
                // with `OutcomeUnknown`.
                let server_side = error.code() == ErrorCode::OutcomeUnknown
                    || service_code.is_none() && answer.status >= 500
                    || matches!(service_code, Some("INTERNAL" | "SERVICE_UNAVAILABLE"));
                Sent::Refusal {
                    code: *service_code,
                    retry_after_seconds: *retry_after_seconds,
                    server_side,
                }
            }
        }
    }

    /// Sends a request that needs the bearer token, renewing the token once on a 401 and repeating
    /// the request once for the same account. A 401 means the request was refused before it ran.
    async fn send_bearer(&self, route: Route, body: Option<&[u8]>, begin: bool) -> Sent {
        let (mut authorisation, mark) = match self.authorise(false).await {
            Ok(held) => held,
            Err(fault) => return Sent::Fault(fault),
        };
        if let Err(fault) = self.bind(mark, begin) {
            return Sent::Fault(fault);
        }
        let first = self.send(route, Some(&authorisation), body).await;
        if !matches!(
            &first,
            Sent::Refusal {
                code: Some("UNAUTHENTICATED"),
                ..
            }
        ) {
            return first;
        }
        match self.authorise(true).await {
            Ok((renewed, again)) if again == mark => authorisation = renewed,
            Ok(_) => return Sent::Fault(DeletionFault::AccountChanged),
            Err(fault) => return Sent::Fault(fault),
        }
        self.send(route, Some(&authorisation), body).await
    }

    /* ---- What would happen ---- */

    /// Reads what deleting the account would do, and binds the deletion to the account that asked.
    ///
    /// # Errors
    ///
    /// Returns the fault that stopped it.
    pub async fn preview(&self) -> std::result::Result<DeletionRead, DeletionFault> {
        match self.send_bearer(Route::View, None, true).await {
            Sent::Data(data) => Ok(read_preview(&data)),
            Sent::Refusal {
                code,
                retry_after_seconds,
                ..
            } => Err(refusal_fault(
                code,
                retry_after_seconds,
                DeletionFault::Unreachable,
            )),
            Sent::Lost => Err(DeletionFault::Unreachable),
            Sent::Fault(fault) => Err(fault),
        }
    }

    /* ---- The code ---- */

    /// Asks the service to email the code to the account's own address.
    ///
    /// # Errors
    ///
    /// Returns the fault that stopped it. [`DeletionFault::Unsure`] means the email may have been sent.
    pub async fn send_code(&self) -> std::result::Result<(), DeletionFault> {
        match self.send_bearer(Route::Code, Some(b"{}"), false).await {
            Sent::Data(data) if data.get("sent") == Some(&serde_json::Value::Bool(true)) => Ok(()),
            Sent::Data(_) | Sent::Lost => Err(DeletionFault::Unsure),
            Sent::Refusal {
                code,
                retry_after_seconds,
                ..
            } => Err(match code {
                Some("SERVICE_UNAVAILABLE") => DeletionFault::MailFailed,
                Some("INTERNAL" | "OUTCOME_UNKNOWN") | None => DeletionFault::Unsure,
                other => refusal_fault(other, retry_after_seconds, DeletionFault::Unsure),
            }),
            Sent::Fault(fault) => Err(fault),
        }
    }

    /* ---- The confirmation ---- */

    /// Confirms the deletion with the code from the email, as the one owner of the deletion.
    ///
    /// Everything that can happen to the request is told apart. A refusal of the code, or of the
    /// organisations, changes nothing. A lost answer is settled by the receipt. Once the account is
    /// known to be closed, the stored grant is ended here and `steps` settles the rest.
    ///
    /// # Errors
    ///
    /// Returns the fault that stopped it. [`DeletionFault::InProgress`] means another confirmation,
    /// look or settling holds the deletion, in this application or in another window of it.
    pub async fn confirm(
        &self,
        code: &str,
        acknowledged: &[String],
        steps: &dyn DeviceSteps,
    ) -> std::result::Result<DeletionOutcome, DeletionFault> {
        if code.len() != CODE_DIGITS
            || !code.bytes().all(|byte| byte.is_ascii_digit())
            || acknowledged.len() > ACKNOWLEDGED_MAXIMUM
        {
            return Err(DeletionFault::Refused);
        }
        let _owner = self.own().await?;
        let mark = match self.authorise(false).await {
            Ok((_, mark)) => mark,
            Err(DeletionFault::NeedsSignIn) => return self.after_sign_in_gone(steps).await,
            Err(fault) => return Err(fault),
        };
        self.bind(mark, false)?;
        let begun = self.begin(mark, steps).await.map_err(local)?;
        let body = confirmation(code, &begun.receipt, acknowledged);
        match self.send_bearer(Route::Confirm, Some(&body), false).await {
            Sent::Data(data) => match read_confirmed(&data) {
                Some(Confirmed::Closed { finished }) => {
                    self.closed(&begun.mark, &begun.receipt, finished, steps)
                        .await;
                    Ok(DeletionOutcome::Closed { finished })
                }
                Some(Confirmed::Outcome(outcome)) => {
                    // The service answered, and the answer says the request did nothing.
                    self.unbegin(&begun);
                    Ok(outcome)
                }
                None => self.after_lost_answer(&begun, steps).await,
            },
            Sent::Refusal {
                code: Some("UNAUTHENTICATED"),
                ..
            }
            | Sent::Fault(DeletionFault::NeedsSignIn) => {
                self.after_unauthenticated(&begun, steps).await
            }
            Sent::Refusal {
                server_side: true, ..
            }
            | Sent::Lost => self.after_lost_answer(&begun, steps).await,
            Sent::Refusal {
                code,
                retry_after_seconds,
                ..
            } => {
                // Refused before it ran.
                self.unbegin(&begun);
                Err(refusal_fault(
                    code,
                    retry_after_seconds,
                    DeletionFault::Refused,
                ))
            }
            Sent::Fault(fault) => {
                // The request was not made.
                self.unbegin(&begun);
                Err(fault)
            }
        }
    }

    /// The deletion a confirmation for the account `mark` carries: the one already kept for that
    /// account while it has not closed the account, else a new one, kept before it is returned. A
    /// record of another account, or one that is closed, is looked after as far as it can be and
    /// then made way for.
    async fn begin(&self, mark: AccountMark, steps: &dyn DeviceSteps) -> Result<Begun> {
        let now = self.account.deletion_clock();
        let wanted = mark.to_hex();
        if let Some(record) = self.account.read_deletion()? {
            if record.mark == wanted && !record.closed && !record.expired(now) {
                return Ok(Begun {
                    mark: wanted,
                    receipt: record.receipt,
                    fresh: false,
                });
            }
            let _ = self.advance(record, steps).await;
        }
        let receipt = fresh_receipt()?;
        self.account
            .write_deletion(&Record::begun(&wanted, &receipt, now))?;
        Ok(Begun {
            mark: wanted,
            receipt,
            fresh: true,
        })
    }

    /// Takes back the record a confirmation made, when what came of it says its request did not run.
    fn unbegin(&self, begun: &Begun) {
        if begun.fresh {
            let _ = self.account.drop_deletion();
        }
    }

    /// The account `mark` is closed, whichever way this was learned: say so in the record, end the
    /// stored grant and settle this device's own state.
    async fn closed(&self, mark: &str, receipt: &str, done: bool, steps: &dyn DeviceSteps) {
        let now = self.account.deletion_clock();
        let mut record = self
            .account
            .read_deletion()
            .ok()
            .flatten()
            .filter(|record| record.receipt == receipt)
            .unwrap_or_else(|| Record::begun(mark, receipt, now));
        record.closed = true;
        record.done |= done;
        record.since_ms = now;
        let _ = self.settle_closed(record, false, steps, false).await;
    }

    /// Looks for a lost answer by receipt. An account found closed is settled as if the answer had
    /// come; one not found is not known to be unclosed, so it stays unsettled.
    async fn after_lost_answer(
        &self,
        begun: &Begun,
        steps: &dyn DeviceSteps,
    ) -> std::result::Result<DeletionOutcome, DeletionFault> {
        for look in 0..LOOKS {
            if look > 0 {
                tokio::time::sleep(self.look_every).await;
            }
            if let Ok(Some(done)) = self.read_status(&begun.receipt).await {
                self.closed(&begun.mark, &begun.receipt, done, steps).await;
                return Ok(DeletionOutcome::Closed { finished: done });
            }
        }
        Ok(DeletionOutcome::Unsettled)
    }

    /// The service says the credential is dead, before the request ran. If this confirmation made
    /// the record, nothing else is out and the sign-in is what is needed. If an earlier request left
    /// the record, that one may have closed the account, so the receipt is asked.
    async fn after_unauthenticated(
        &self,
        begun: &Begun,
        steps: &dyn DeviceSteps,
    ) -> std::result::Result<DeletionOutcome, DeletionFault> {
        if begun.fresh {
            self.unbegin(begun);
            return Err(DeletionFault::NeedsSignIn);
        }
        match self.read_status(&begun.receipt).await {
            Ok(Some(done)) => {
                self.closed(&begun.mark, &begun.receipt, done, steps).await;
                Ok(DeletionOutcome::Closed { finished: done })
            }
            Ok(None) | Err(_) => Ok(DeletionOutcome::Unsettled),
        }
    }

    /// The sign-in is gone before anything was sent. A deletion this device kept for the account the
    /// person began with may have been carried out by an earlier try; another account's is none of
    /// this one's.
    async fn after_sign_in_gone(
        &self,
        steps: &dyn DeviceSteps,
    ) -> std::result::Result<DeletionOutcome, DeletionFault> {
        let Some(record) = self
            .account
            .read_deletion()
            .map_err(local)?
            .filter(|record| !record.closed && self.is_flow(&record.mark))
        else {
            return Err(DeletionFault::NeedsSignIn);
        };
        match self.read_status(&record.receipt).await {
            Ok(Some(done)) => {
                self.closed(&record.mark, &record.receipt, done, steps)
                    .await;
                Ok(DeletionOutcome::Closed { finished: done })
            }
            Ok(None) | Err(_) => Ok(DeletionOutcome::Unsettled),
        }
    }

    /* ---- How it is going ---- */

    /// One look by receipt: `Some(done)` when the account is closed, `None` when the service knows
    /// no such request, which is not proof that none is on its way.
    async fn read_status(&self, receipt: &str) -> std::result::Result<Option<bool>, DeletionFault> {
        let body = serde_json::to_vec(&serde_json::json!({ "receipt": receipt }))
            .map_err(|_| DeletionFault::Refused)?;
        match self.send(Route::Status, None, Some(&body)).await {
            Sent::Data(data) => match data.get("state").and_then(serde_json::Value::as_str) {
                Some(state @ ("open" | "done")) => Ok(Some(state == "done")),
                Some("unknown") => Ok(None),
                _ => Err(DeletionFault::Unreachable),
            },
            Sent::Refusal {
                code,
                retry_after_seconds,
                ..
            } => Err(refusal_fault(
                code,
                retry_after_seconds,
                DeletionFault::Unreachable,
            )),
            Sent::Lost | Sent::Fault(_) => Err(DeletionFault::Unreachable),
        }
    }

    /// How the removal is going, for the deletion this device holds a record of, as the owner. When
    /// the owner is held, the record is reported as it stands and nothing is touched.
    ///
    /// The progress is the person's own: the record of another account's deletion is looked after,
    /// and its closure ends that account's grant and no other, but it is not shown as this one's.
    ///
    /// # Errors
    ///
    /// Returns the fault that stopped it; the record is kept.
    pub async fn status(
        &self,
        steps: &dyn DeviceSteps,
    ) -> std::result::Result<DeletionStatus, DeletionFault> {
        let nothing = DeletionStatus {
            progress: DeletionProgress::None,
            closed_now: false,
        };
        let owner = self.try_own().await?;
        let Some(record) = self.account.read_deletion().map_err(local)? else {
            return Ok(nothing);
        };
        self.follow_if_signed_in(&record.mark)?;
        let mark = record.mark.clone();
        let advanced = if owner.is_some() {
            self.advance(record, steps).await?
        } else {
            // Someone holds the deletion: what the record shows is all there is to say.
            Advanced {
                progress: match (record.closed, record.done) {
                    (_, true) => DeletionProgress::Done,
                    (true, false) => DeletionProgress::Open,
                    (false, false) => DeletionProgress::Unsettled,
                },
                closed_now: false,
            }
        };
        Ok(DeletionStatus {
            progress: self.shown(&mark, advanced.progress)?,
            closed_now: advanced.closed_now,
        })
    }

    /// Brings a record as far as it can go: an account not yet known to be closed is asked about by
    /// receipt; a closed one is settled. Called as the owner.
    async fn advance(
        &self,
        mut record: Record,
        steps: &dyn DeviceSteps,
    ) -> std::result::Result<Advanced, DeletionFault> {
        if record.closed {
            return Ok(Advanced {
                progress: self.settle_closed(record, true, steps, true).await?,
                closed_now: false,
            });
        }
        let now = self.account.deletion_clock();
        if record.expired(now) {
            self.account.drop_deletion().map_err(local)?;
            return Ok(Advanced {
                progress: DeletionProgress::None,
                closed_now: false,
            });
        }
        match self.read_status(&record.receipt).await? {
            None => Ok(Advanced {
                progress: DeletionProgress::Unsettled,
                closed_now: false,
            }),
            Some(done) => {
                record.closed = true;
                record.done = done;
                record.since_ms = now;
                Ok(Advanced {
                    progress: self.settle_closed(record, false, steps, false).await?,
                    closed_now: true,
                })
            }
        }
    }

    /// The account of a closed record: the closure is written (when `kept` says it is not in the
    /// store yet), the stored grant is ended, the application's own steps run, and the service is
    /// asked whether the removal is done (when `look` and it was not known). The record is dropped
    /// once the removal is done and the steps are, or after [`KEPT_FOR_MS`], whatever the steps came
    /// to. A write that fails is not an answer for the person: the account is closed whatever this
    /// device manages to keep, and the next look does the work again.
    ///
    /// # Errors
    ///
    /// Returns the fault of the look at the service, after everything else was done.
    async fn settle_closed(
        &self,
        mut record: Record,
        kept: bool,
        steps: &dyn DeviceSteps,
        look: bool,
    ) -> std::result::Result<DeletionProgress, DeletionFault> {
        let mut written =
            (kept || self.account.write_deletion(&record).is_ok()).then(|| record.clone());
        let ended = self
            .account
            .end_closed_grant(&self.origin, &record.mark)
            .await
            .unwrap_or(false);
        if ended {
            // The sign-in this ended is not a sign-in or out since the flow was followed.
            let mut flow = held(&self.flow);
            if flow.mark.is_some_and(|bound| bound.to_hex() == record.mark) {
                flow.seen.borrow_and_update();
            }
        }
        if !record.notifications && steps.notifications().await {
            record.notifications = true;
            self.keep(&record, &mut written);
        }
        if !record.recovery {
            let done = match AccountMark::from_hex(&record.mark) {
                Some(deleted) => steps.recovery(deleted).await,
                None => true,
            };
            if done {
                record.recovery = true;
                self.keep(&record, &mut written);
            }
        }
        let looked = if look && !record.done {
            self.read_status(&record.receipt).await
        } else {
            Ok(None)
        };
        if let Ok(Some(done)) = looked {
            record.done = done;
        }
        let expired = record.expired(self.account.deletion_clock());
        if (record.done && record.settled()) || expired {
            let _ = self.account.drop_deletion();
        } else {
            self.keep(&record, &mut written);
        }
        looked?;
        Ok(if record.done {
            DeletionProgress::Done
        } else if expired {
            DeletionProgress::None
        } else {
            DeletionProgress::Open
        })
    }

    /// Writes `record` unless it is what `written` says the store holds already.
    fn keep(&self, record: &Record, written: &mut Option<Record>) {
        if written.as_ref() != Some(record) && self.account.write_deletion(record).is_ok() {
            *written = Some(record.clone());
        }
    }

    /// Gives up on a deletion whose request is not known to have run: the record is removed, and
    /// whatever that request does later, the sign-in on this device finds out when it next asks the
    /// service for a token. A record of a closed account is left to settle.
    ///
    /// # Errors
    ///
    /// Returns [`DeletionFault::InProgress`] while the deletion is held, and the fault of this
    /// device's own records.
    pub async fn forget(&self) -> std::result::Result<(), DeletionFault> {
        let _owner = self.own().await?;
        if let Some(record) = self.account.read_deletion().map_err(local)?
            && !record.closed
        {
            self.follow_if_signed_in(&record.mark)?;
            if self.shown(&record.mark, DeletionProgress::Unsettled)? != DeletionProgress::None {
                self.account.drop_deletion().map_err(local)?;
            }
        }
        Ok(())
    }

    /// Ends the stored grant if a deletion has closed its account and the grant is still that
    /// account's, with no request. Called at start, before the first view, so that a closure that was
    /// interrupted before the grant was ended is not shown as a sign-in.
    ///
    /// # Errors
    ///
    /// Returns the fault that stopped it.
    pub async fn settle_grant(&self) -> std::result::Result<(), DeletionFault> {
        if let Some(record) = self.account.read_deletion().map_err(local)?
            && record.closed
        {
            self.account
                .end_closed_grant(&self.origin, &record.mark)
                .await
                .map_err(local)?;
        }
        Ok(())
    }
}

fn local(error: ClientError) -> DeletionFault {
    DeletionFault::Local(crate::shown::Said::said(&error))
}

/// What a refusal the service named means for a request that changes nothing when it fails.
fn refusal_fault(
    code: Option<&'static str>,
    retry_after_seconds: Option<u64>,
    otherwise: DeletionFault,
) -> DeletionFault {
    match code {
        Some("UNAUTHENTICATED") => DeletionFault::NeedsSignIn,
        Some("RATE_LIMITED") => DeletionFault::Busy {
            seconds: retry_after_seconds.unwrap_or(60),
        },
        Some(
            "FORBIDDEN"
            | "REAUTHENTICATION_REQUIRED"
            | "INVALID_REQUEST"
            | "NOT_FOUND"
            | "METHOD_NOT_ALLOWED",
        ) => DeletionFault::Refused,
        _ => otherwise,
    }
}

fn confirmation(code: &str, receipt: &str, acknowledged: &[String]) -> Vec<u8> {
    let mut body = serde_json::json!({ "code": code, "receipt": receipt });
    if !acknowledged.is_empty() {
        body["acknowledged"] = serde_json::json!(acknowledged);
    }
    // A value of strings has no way to fail to serialise.
    serde_json::to_vec(&body).unwrap_or_default()
}

/* -------------------------------------------------------------------------- */
/* Reading the service's answers                                               */
/* -------------------------------------------------------------------------- */

fn read_preview(data: &serde_json::Value) -> DeletionRead {
    read_preview_members(data).map_or(DeletionRead::CannotShow, DeletionRead::Ready)
}

fn read_preview_members(data: &serde_json::Value) -> Option<DeletionPreview> {
    let text = |value: &serde_json::Value, name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let number = |value: &serde_json::Value, name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .and_then(|found| u32::try_from(found).ok())
    };

    // A choice this build does not know is a term about money it cannot state, so the person is
    // not asked to go on: every member must be one of the four it has words for.
    let choices = data.get("choices")?;
    let known_choices = choices.as_object()?.keys().all(|name| {
        matches!(
            name.as_str(),
            "subscription" | "refund" | "credit" | "keptRecordsYears"
        )
    }) && text(choices, "subscription").as_deref() == Some("end_at_once")
        && text(choices, "refund").as_deref() == Some("none")
        && text(choices, "credit").as_deref() == Some("forfeited");
    let kept_records_years = number(choices, "keptRecordsYears").filter(|years| *years > 0)?;
    let code_digits = number(data, "codeDigits")?;
    if !known_choices || usize::try_from(code_digits).ok()? != CODE_DIGITS {
        return None;
    }

    let mut warnings = Vec::new();
    for warning in data.get("warnings")?.as_array()? {
        warnings.push(match warning.get("kind")?.as_str()? {
            "organisation_owner" => DeletionWarning::OrganisationOwner {
                organisation_id: text(warning, "organisation_id")?,
                name: text(warning, "name")?,
                members: warning.get("members")?.as_u64()?,
            },
            "subscription" => DeletionWarning::Subscription,
            "credit" => DeletionWarning::Credit,
            "money_owed" => DeletionWarning::MoneyOwed,
            _ => return None,
        });
    }

    let mut unlisted = false;
    let mut deleted = Vec::new();
    for key in data.get("deleted")?.as_array()? {
        match key.as_str().and_then(DeletedKind::from_key) {
            Some(kind) => deleted.push(kind),
            None => unlisted = true,
        }
    }
    let mut kept = Vec::new();
    for key in data.get("kept")?.as_array()? {
        match key.as_str().and_then(KeptKind::from_key) {
            Some(kind) => kept.push(kind),
            None => unlisted = true,
        }
    }

    Some(DeletionPreview {
        address: text(data, "address")?,
        warnings,
        deleted,
        kept,
        unlisted,
        kept_records_years,
        backup_file_days: number(data, "backupFileDays")?,
        code_lifetime_minutes: number(data, "codeLifetimeSeconds")?.div_ceil(60),
    })
}

enum Confirmed {
    Closed { finished: bool },
    Outcome(DeletionOutcome),
}

/// The confirmation's `data`, or none when the result is one this build does not know.
fn read_confirmed(data: &serde_json::Value) -> Option<Confirmed> {
    match data.get("result")?.as_str()? {
        "closed" => Some(Confirmed::Closed {
            finished: match data.get("state")?.as_str()? {
                "deleted" => true,
                "closing" => false,
                _ => return None,
            },
        }),
        "code_refused" => Some(Confirmed::Outcome(DeletionOutcome::CodeRefused {
            reason: match data.get("reason")?.as_str()? {
                "wrong" => CodeRefusal::Wrong,
                "expired" => CodeRefusal::Expired,
                "spent" => CodeRefusal::Spent,
                _ => return None,
            },
            attempts_left: u32::try_from(data.get("attempts_left")?.as_u64()?).ok()?,
        })),
        "acknowledge" => {
            let mut organisations = Vec::new();
            for each in data.get("organisations")?.as_array()? {
                organisations.push(OwnedOrganisation {
                    organisation_id: each.get("organisation_id")?.as_str()?.to_owned(),
                    name: each.get("name")?.as_str()?.to_owned(),
                    members: each.get("members")?.as_u64()?,
                });
            }
            Some(Confirmed::Outcome(DeletionOutcome::Acknowledge {
                organisations,
            }))
        }
        _ => None,
    }
}
