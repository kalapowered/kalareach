//! Deleting the signed-in account from the application.
//!
//! The managed service offers four routes for it: what deleting would do, an emailed code that
//! confirms it, the confirmation, and the outcome by receipt. This module is the client of those
//! routes and the record that makes a lost answer recoverable.
//!
//! # The receipt
//!
//! The confirmation carries a receipt the client made: 128 random bits that the service keeps only
//! a digest of. It is written to the secure store, with the account it is for, before the
//! confirmation leaves, because the receipt is the only way to learn what became of a request whose
//! answer was lost, and the account that sent it will not be able to sign in once the request has
//! been carried out. The record is therefore bound to the account (an [`AccountMark`]), is reused
//! only for that account while the deletion has not closed it, and is kept until the removal is
//! known to have finished and what this device has to do about it is done.
//!
//! A status of `unknown` is not proof that nothing arrived: a confirmation that is still running
//! has no row yet. A record whose request left less than [`UNSETTLED_FOR_MS`] ago is therefore kept
//! on `unknown`, and dropped after that, when nothing can still be running.
//!
//! # Learning that the account is closed
//!
//! A `closed` answer, a status of `open` or `done`, and a status read after a restart all say the
//! same thing: the account no longer exists at the service. Each does the same local work, once and
//! again if it was interrupted: it ends the stored grant without telling the service (the service
//! has ended it already), and it leaves the record for the application to finish what only it can
//! (the notifications of a phone, the recovery record of a computer).
//!
//! # What is never rendered
//!
//! The code, the token, the receipt and the address are never in a rendering of anything here.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_protocol::error::ErrorCode;
use kr_protocol::service::GatewayOrigin;
use serde::{Deserialize, Serialize};

use super::{AccountMark, SignedInAccount, storage};
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

/// How long a request that left without an answer may still be running at the service: the route's
/// own deadline is about eight seconds, and this leaves a wide margin for the network.
pub const UNSETTLED_FOR_MS: u64 = 2 * 60 * 1000;

/// How long a closed record is kept waiting for `done`: stored backup files are gone within seven
/// days, and a deletion replayed after a restore can leave one the service cannot match to its
/// receipt.
pub const CLOSED_FOR_MS: u64 = 7 * 24 * 60 * 60 * 1000;

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

/// How the removal is going.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionProgress {
    /// No deletion is in progress on this device.
    None,
    /// The account is closed and the removal is running.
    Open,
    /// The removal has finished.
    Done,
}

/// What a status read found, and what this device still has to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeletionStatus {
    /// How the removal is going.
    pub progress: DeletionProgress,
    /// Whether the application has device state to settle: call [`ManagedAccountDeletion::settle`]
    /// and, when it is done, [`ManagedAccountDeletion::device_settled`].
    pub device_pending: bool,
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
    /// This device could not keep or read its own records.
    Local(Shown),
}

/* -------------------------------------------------------------------------- */
/* The record                                                                  */
/* -------------------------------------------------------------------------- */

/// The deletion this device is part of, kept in the secure store.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    v: u32,
    /// The account it is for, as the hex of its mark.
    mark: String,
    /// The receipt: 32 lowercase hex characters.
    receipt: String,
    /// When the last confirmation left.
    sent_ms: u64,
    /// When the account was learned to be closed.
    closed_ms: Option<u64>,
    /// Whether the stored grant has been ended.
    grant_ended: bool,
    /// Whether the application has settled what is its own.
    device_settled: bool,
    /// Whether the service said the removal is done.
    done_seen: bool,
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

fn mark_hex(mark: AccountMark) -> String {
    hex(&mark.to_bytes())
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

    /// The receipt a confirmation for the account `mark` carries: the one already kept for that
    /// account while its deletion has not closed it, else a new one (with `replace`, always a
    /// new one). It is kept, with the time the request is about to leave, before it is returned.
    async fn begin_deletion(&self, mark: AccountMark, replace: bool) -> Result<String> {
        let _held = self.hold().await?;
        let now = self.deletion_clock();
        let wanted = mark_hex(mark);
        if !replace
            && let Some(mut record) = self.read_deletion()?
            && record.mark == wanted
            && record.closed_ms.is_none()
        {
            record.sent_ms = now;
            self.write_deletion(&record)?;
            return Ok(record.receipt);
        }
        let receipt = fresh_receipt()?;
        self.write_deletion(&Record {
            v: RECORD_VERSION,
            mark: wanted,
            receipt: receipt.clone(),
            sent_ms: now,
            closed_ms: None,
            grant_ended: false,
            device_settled: false,
            done_seen: false,
        })?;
        Ok(receipt)
    }

    /// Changes the record under the lock, and removes it once the removal is done and the
    /// application has settled its own.
    async fn edit_deletion(&self, edit: impl FnOnce(&mut Record)) -> Result<Option<Record>> {
        let _held = self.hold().await?;
        let Some(mut record) = self.read_deletion()? else {
            return Ok(None);
        };
        edit(&mut record);
        if record.done_seen && record.device_settled {
            self.drop_deletion()?;
            return Ok(None);
        }
        self.write_deletion(&record)?;
        Ok(Some(record))
    }

    /// Removes the record under the lock.
    async fn forget_deletion(&self) -> Result<()> {
        let _held = self.hold().await?;
        self.drop_deletion()
    }

    /// Ends the stored grant if its account is closed and the grant is still that account's,
    /// without telling the service. The closure is the record's, or `known` when the caller has just
    /// learned it and the record could not be written. Once, and again if it was interrupted.
    async fn end_closed_grant(&self, origin: &str, known: Option<&str>) -> Result<()> {
        let _held = self.hold().await?;
        let mut record = self.read_deletion()?;
        let mark = match (&record, known) {
            (Some(kept), _) if kept.closed_ms.is_some() && kept.grant_ended => return Ok(()),
            (Some(kept), _) if kept.closed_ms.is_some() => kept.mark.clone(),
            (_, Some(known)) => known.to_owned(),
            _ => return Ok(()),
        };
        let ours = self
            .read_grant()?
            .is_some_and(|grant| mark_hex(grant.mark_at(origin)) == mark);
        if ours {
            self.delete_grant()?;
        }
        if ours || self.read_grant()?.is_none() {
            self.ended.store(false, Ordering::SeqCst);
        }
        if let Some(record) = record.as_mut()
            && record.mark == mark
            && record.closed_ms.is_some()
        {
            record.grant_ended = true;
            self.write_deletion(record)?;
        }
        self.publish();
        Ok(())
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

/// The managed service's account deletion, for the account signed in on this device.
pub struct ManagedAccountDeletion {
    origin: String,
    http: Arc<dyn ServiceHttp>,
    account: Arc<SignedInAccount>,
    /// The account the deletion in front of the person began for.
    flow: Mutex<Option<AccountMark>>,
    /// How many confirmations are in flight in this process, which nothing may drop the record under.
    in_flight: AtomicUsize,
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

/// Counts one confirmation in flight for as long as it lives.
struct Flight<'a>(&'a AtomicUsize);

impl<'a> Flight<'a> {
    fn begin(count: &'a AtomicUsize) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(count)
    }
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
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
        Self {
            origin: origin.as_str().to_owned(),
            http,
            account,
            flow: Mutex::new(None),
            in_flight: AtomicUsize::new(0),
            look_every: LOOK_EVERY,
        }
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
        let mut flow = self
            .flow
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *flow {
            Some(held) if held != mark && !begin => Err(DeletionFault::AccountChanged),
            _ => {
                *flow = Some(mark);
                Ok(())
            }
        }
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
            Err(ClientError::Refused {
                retry_after_seconds,
                service_code,
                ..
            }) => Sent::Refusal {
                code: service_code,
                retry_after_seconds,
                server_side: service_code.is_none() && answer.status >= 500
                    || matches!(
                        service_code,
                        Some("INTERNAL" | "OUTCOME_UNKNOWN" | "SERVICE_UNAVAILABLE")
                    ),
            },
            Err(_) => Sent::Lost,
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

    /// Confirms the deletion with the code from the email.
    ///
    /// Everything that can happen to the request is told apart. A refusal of the code, or of the
    /// organisations, changes nothing. A lost answer is settled by the receipt. Once the account
    /// is known to be closed, the stored grant is ended here.
    ///
    /// # Errors
    ///
    /// Returns the fault that stopped it.
    pub async fn confirm(
        &self,
        code: &str,
        acknowledged: &[String],
    ) -> std::result::Result<DeletionOutcome, DeletionFault> {
        if code.len() != CODE_DIGITS
            || !code.bytes().all(|byte| byte.is_ascii_digit())
            || acknowledged.len() > ACKNOWLEDGED_MAXIMUM
        {
            return Err(DeletionFault::Refused);
        }
        let _flight = Flight::begin(&self.in_flight);

        let mark = match self.authorise(false).await {
            Ok((_, mark)) => mark,
            Err(DeletionFault::NeedsSignIn) => return self.after_unauthenticated().await,
            Err(fault) => return Err(fault),
        };
        self.bind(mark, false)?;
        let mut receipt = self
            .account
            .begin_deletion(mark, false)
            .await
            .map_err(local)?;
        let mut replaced = false;
        loop {
            let body = confirmation(code, &receipt, acknowledged);
            match self.send_bearer(Route::Confirm, Some(&body), false).await {
                Sent::Data(data) => {
                    return match read_confirmed(&data) {
                        Some(Confirmed::Closed { finished }) => {
                            self.closed(finished, &mark_hex(mark)).await;
                            Ok(DeletionOutcome::Closed { finished })
                        }
                        Some(Confirmed::Outcome(outcome)) => Ok(outcome),
                        None => self.after_lost_answer().await,
                    };
                }
                Sent::Refusal {
                    code: Some("INVALID_REQUEST"),
                    ..
                } if !replaced => {
                    // The receipt was used for another account's deletion. Nothing has happened
                    // under it for this one, so it is replaced, once.
                    replaced = true;
                    receipt = self
                        .account
                        .begin_deletion(mark, true)
                        .await
                        .map_err(local)?;
                }
                Sent::Refusal {
                    code: Some("UNAUTHENTICATED"),
                    ..
                } => {
                    return self.after_unauthenticated().await;
                }
                Sent::Refusal {
                    code,
                    retry_after_seconds,
                    server_side,
                } => {
                    if server_side {
                        return self.after_lost_answer().await;
                    }
                    return Err(refusal_fault(
                        code,
                        retry_after_seconds,
                        DeletionFault::Refused,
                    ));
                }
                Sent::Lost => return self.after_lost_answer().await,
                Sent::Fault(DeletionFault::NeedsSignIn) => {
                    return self.after_unauthenticated().await;
                }
                Sent::Fault(fault) => return Err(fault),
            }
        }
    }

    /// The account is closed: say so in the record and end the stored grant.
    ///
    /// Neither step can change what the person is told, because the account is closed whatever
    /// this device manages to write. A step that fails is retried by [`Self::settle`], at the next
    /// start or the next look.
    async fn closed(&self, finished: bool, mark: &str) {
        let now = self.account.deletion_clock();
        let _ = self
            .account
            .edit_deletion(|record| {
                record.closed_ms.get_or_insert(now);
                record.done_seen |= finished;
            })
            .await;
        let _ = self
            .account
            .end_closed_grant(&self.origin, Some(mark))
            .await;
    }

    /// Looks for a lost answer by receipt. An account found closed is settled as if the answer had
    /// come; one not found is not known to be unclosed, so it stays unsettled.
    async fn after_lost_answer(&self) -> std::result::Result<DeletionOutcome, DeletionFault> {
        for look in 0..LOOKS {
            if look > 0 {
                tokio::time::sleep(self.look_every).await;
            }
            if let Ok(Some(done)) = self.read_status().await {
                return Ok(DeletionOutcome::Closed { finished: done });
            }
        }
        Ok(DeletionOutcome::Unsettled)
    }

    /// The service says the credential is dead: if the request that was refused was an earlier
    /// one's repeat, the account may be closed already, so the receipt is asked first.
    async fn after_unauthenticated(&self) -> std::result::Result<DeletionOutcome, DeletionFault> {
        match self.read_status().await {
            Ok(Some(done)) => Ok(DeletionOutcome::Closed { finished: done }),
            _ => Err(DeletionFault::NeedsSignIn),
        }
    }

    /* ---- How it is going ---- */

    /// One look by receipt: `Some(done)` when the account is closed (and settled locally), `None`
    /// when the service knows no such request.
    async fn read_status(&self) -> std::result::Result<Option<bool>, DeletionFault> {
        let Some(record) = self.account.read_deletion().map_err(local)? else {
            return Ok(None);
        };
        let body = serde_json::to_vec(&serde_json::json!({ "receipt": record.receipt }))
            .map_err(|_| DeletionFault::Refused)?;
        match self.send(Route::Status, None, Some(&body)).await {
            Sent::Data(data) => match data.get("state").and_then(serde_json::Value::as_str) {
                Some(state @ ("open" | "done")) => {
                    let done = state == "done";
                    self.closed(done, &record.mark).await;
                    Ok(Some(done))
                }
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

    /// How the removal is going, for the deletion this device holds a record of.
    ///
    /// # Errors
    ///
    /// Returns the fault that stopped it; the record is kept.
    pub async fn status(&self) -> std::result::Result<DeletionStatus, DeletionFault> {
        let none = DeletionStatus {
            progress: DeletionProgress::None,
            device_pending: false,
        };
        let Some(record) = self.account.read_deletion().map_err(local)? else {
            return Ok(none);
        };
        if self.in_flight.load(Ordering::SeqCst) > 0 {
            return Ok(none);
        }
        let now = self.account.deletion_clock();
        if let Some(closed) = record.closed_ms
            && now.saturating_sub(closed) > CLOSED_FOR_MS
        {
            self.account.forget_deletion().await.map_err(local)?;
            return Ok(none);
        }
        let found = self.read_status().await;
        let after = self.account.read_deletion().map_err(local)?;
        match found {
            Ok(Some(done)) => Ok(DeletionStatus {
                progress: if done {
                    DeletionProgress::Done
                } else {
                    DeletionProgress::Open
                },
                device_pending: after.as_ref().is_some_and(|kept| !kept.device_settled),
            }),
            Ok(None) if record.closed_ms.is_some() => Ok(DeletionStatus {
                progress: DeletionProgress::Open,
                device_pending: !record.device_settled,
            }),
            Ok(None) => {
                // Nothing at the service carries the receipt. A request that left a moment ago
                // may still be running, so the record waits; after that nothing can be.
                if now.saturating_sub(record.sent_ms) > UNSETTLED_FOR_MS {
                    self.account.forget_deletion().await.map_err(local)?;
                }
                Ok(none)
            }
            Err(fault) => Err(fault),
        }
    }

    /// Ends the stored grant if a deletion has closed its account and the grant is still that
    /// account's, with no request, and says whether the application has device state to settle.
    /// Called at start and before the application settles its own state.
    ///
    /// # Errors
    ///
    /// Returns the fault that stopped it.
    pub async fn settle(&self) -> std::result::Result<bool, DeletionFault> {
        self.account
            .end_closed_grant(&self.origin, None)
            .await
            .map_err(local)?;
        Ok(self
            .account
            .read_deletion()
            .map_err(local)?
            .is_some_and(|record| record.closed_ms.is_some() && !record.device_settled))
    }

    /// Says the application has settled what is its own, so the record can go once the removal is
    /// done.
    ///
    /// # Errors
    ///
    /// Returns the fault that stopped it.
    pub async fn device_settled(&self) -> std::result::Result<(), DeletionFault> {
        self.account
            .edit_deletion(|record| record.device_settled = true)
            .await
            .map_err(local)?;
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
        Some("FORBIDDEN" | "REAUTHENTICATION_REQUIRED" | "INVALID_REQUEST") => {
            DeletionFault::Refused
        }
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

    let choices = data.get("choices")?;
    let known_choices = text(choices, "subscription").as_deref() == Some("end_at_once")
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
            finished: data.get("state")?.as_str()? == "deleted",
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
