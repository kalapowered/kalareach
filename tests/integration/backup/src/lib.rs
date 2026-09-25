//! The recovery bundle and settings sync, against services this repository does not stand in for.
//!
//! Every other suite holds the recovery module and the sync client to a service written for the
//! test. These legs hold them to the web service itself: a local deployment `wrangler dev` serves, or
//! a deployment over HTTPS.
//!
//! * **The bundle** (`tests/bundle.rs`): a bundle written at a stable locator by one installation
//!   with the account's `backup.write` token, found and authenticated by another that holds only the
//!   kit, the origin and the same account's `backup.restore` token, moved on by compare and swap and
//!   read again with the same kit, and refused wherever its origin or its locator is substituted or
//!   the kit belongs to another seed.
//! * **A restored deployment** (`tests/restore.rs`): a device's settings, drafts and membership,
//!   made against one local deployment, meeting a second deployment restored from the first one's
//!   export. That leg runs in phases, between which the deployments are exported, stopped, prepared
//!   and restored, so what the device holds lives in a run directory rather than in memory.
//!
//! # What they run against
//!
//! Variables name the services, and a leg without the ones it needs says why it did nothing and
//! passes, so an ordinary test run of this workspace stays offline. [`REQUIRE_VARIABLE`] set to
//! `1` turns that absence into a failure, which is how a run that promised a service finds out it
//! did not get one. `scripts/e2e-backup.sh` sets them.
//!
//! # What every answer names
//!
//! A deployment put back from an export names its recovery beside every place it answers with,
//! and one that was never put back names none. [`Watched`] carries a leg's requests and reads each
//! answer as it came back, before any client parses it, so the rule is checked on every answer
//! rather than on the ones a leg thought to look at, and a missing name is told from a null one.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use kr_client::ClientError;
use kr_client::services::account::{AccountToken, AccountTokenSource};
use kr_client::services::relay::{ServiceHttp, ServiceHttpAnswer, ServiceSigner};
use kr_client::services::{ServiceFuture, SyncRecoveryId};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::InstallationId;
use kr_protocol::scalars::{AuthorisationKey, Signature64};
use kr_protocol::service::{ServiceRequestSigner, installation_id};

pub use kr_sync_integration::REQUIRE_VARIABLE;

/// Whether this run was promised the services its legs need.
#[must_use]
pub fn required() -> bool {
    std::env::var(REQUIRE_VARIABLE).is_ok_and(|value| value == "1")
}

/// The value of one variable, or nothing when the run did not set it.
///
/// # Panics
///
/// Panics when the run was promised its services and the variable is missing, because a leg that
/// was meant to run and quietly did not has proved nothing.
#[must_use]
pub fn variable(name: &str) -> Option<String> {
    let value = std::env::var(name).unwrap_or_default();
    if value.is_empty() {
        assert!(
            !required(),
            "{REQUIRE_VARIABLE}=1 and {name} is not set, so this leg could not run"
        );
        return None;
    }
    Some(value)
}

/// Says a leg did nothing because a variable it needs was not set.
pub fn skipped(name: &str) {
    eprintln!("skipping: {name} is not set, so nothing was sent anywhere");
}

/* -------------------------------------------------------------------------- */
/* The account a bundle belongs to                                             */
/* -------------------------------------------------------------------------- */

/// The variable naming the file that holds the run's account tokens, for each origin.
///
/// A recovery bundle belongs to an account, so every request about it carries an account token
/// beside the device's signature. The file is a JSON object from each origin to the two tokens one
/// account holds there, `{"write": "...", "restore": "..."}`: one issued with `backup.write` for the
/// device that writes the bundle, and one issued with `backup.restore` for the device that restores
/// from the kit. `scripts/e2e-backup.sh` has each local deployment's development-only sign-in write
/// it; a run against a deployment is handed one. It is readable by this account alone, and nothing
/// here prints a token.
pub const TOKENS_VARIABLE: &str = "KR_BACKUP_TOKENS";

/// The two account tokens a run holds at one origin.
#[derive(Debug)]
pub struct AccountTokens {
    /// Issued with `backup.write`, for the device that writes the bundle.
    pub write: Arc<dyn AccountTokenSource>,
    /// Issued with `backup.restore`, for the device that restores from the kit.
    pub restore: Arc<dyn AccountTokenSource>,
}

/// The account tokens the run holds at `origin`, or nothing when the run named no token file.
///
/// # Panics
///
/// Panics when the run was promised its services and named no file, and when the file cannot be
/// read, is not the shape above, or names no tokens for `origin`.
#[must_use]
pub fn account_tokens(origin: &str) -> Option<AccountTokens> {
    let path = variable(TOKENS_VARIABLE)?;
    let text = std::fs::read(&path).expect("the run's token file");
    let tokens: serde_json::Value = serde_json::from_slice(&text).expect("a JSON object");
    let held = &tokens[origin];
    let token = |which: &str| {
        let value = held[which]
            .as_str()
            .unwrap_or_else(|| panic!("the token file holds a {which} token for {origin}"));
        Arc::new(Given(
            AccountToken::new(value).expect("a token a header can carry"),
        )) as Arc<dyn AccountTokenSource>
    };
    Some(AccountTokens {
        write: token("write"),
        restore: token("restore"),
    })
}

/// A token the run was given, handed out for whatever scope is asked: the service checks the
/// scope it was issued with.
#[derive(Debug)]
struct Given(AccountToken);

impl AccountTokenSource for Given {
    fn token<'a>(&'a self, _scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        let token = self.0.clone();
        Box::pin(async move { Ok(token) })
    }
}

/* -------------------------------------------------------------------------- */
/* The transport every leg watches                                             */
/* -------------------------------------------------------------------------- */

/// One signed request as it left: which of a service's members it asked for, and what it named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    /// The member the request asked for: `exchange`, `compare`, `status`, `fence` and the rest.
    pub member: String,
    /// The collection it named, or the recovery bundle's locator, when it named one.
    pub collection: Option<String>,
    /// The request identity it named, when it named one.
    pub request_id: Option<String>,
}

/// A fence's answer as it came back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FenceAnswer {
    /// The request identity the fence was about.
    pub request_id: String,
    /// What the service recorded: `applied`, `refused` or `fenced`.
    pub state: String,
    /// Whether the service established that the request never ran.
    pub never_ran: bool,
}

/// The transport a leg's service clients share, holding every answer to the history it expects.
///
/// Every request is written down before it leaves, so one whose answer never arrives is written
/// down all the same. Every answer is read raw before a client parses it: an answer that names a
/// place in a collection's order has to name the history that place is in, as the member itself
/// and as the value this leg expects, null for a deployment that was never put back. What it finds
/// wrong is kept rather than raised inside a call, so the leg reports it where it can say which
/// step met it.
pub struct Watched {
    inner: Arc<dyn ServiceHttp>,
    expected: Option<SyncRecoveryId>,
    sent: Mutex<Vec<Sent>>,
    fences: Mutex<Vec<FenceAnswer>>,
    wrong: Mutex<Vec<String>>,
    named: AtomicUsize,
    calls: AtomicUsize,
    lose_the_next_answer: AtomicBool,
    lost: Mutex<Option<ServiceHttpAnswer>>,
}

impl fmt::Debug for Watched {
    /// How many requests left and how many answers named their history. Never one of them.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Watched")
            .field(
                "sent",
                &self.sent.lock().map(|sent| sent.len()).unwrap_or(0),
            )
            .field("named", &self.named.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Watched {
    /// Watches one transport, expecting every answer to name `expected`.
    #[must_use]
    pub fn new(inner: Arc<dyn ServiceHttp>, expected: Option<SyncRecoveryId>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            expected,
            sent: Mutex::new(Vec::new()),
            fences: Mutex::new(Vec::new()),
            wrong: Mutex::new(Vec::new()),
            named: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            lose_the_next_answer: AtomicBool::new(false),
            lost: Mutex::new(None),
        })
    }

    /// The history every answer is held to.
    #[must_use]
    pub const fn expected(&self) -> Option<SyncRecoveryId> {
        self.expected
    }

    /// Loses the next answer on its way back, as a connection that dropped would.
    pub fn lose_the_next_answer(&self) {
        self.lose_the_next_answer.store(true, Ordering::SeqCst);
    }

    /// The answer that was lost, as the service gave it, once.
    ///
    /// # Panics
    ///
    /// Panics when the record is poisoned.
    pub fn take_lost(&self) -> Option<ServiceHttpAnswer> {
        self.lost.lock().expect("the lost answer").take()
    }

    /// Every request that left, in order.
    ///
    /// # Panics
    ///
    /// Panics when the record is poisoned.
    #[must_use]
    pub fn sent(&self) -> Vec<Sent> {
        self.sent.lock().expect("the requests").clone()
    }

    /// Every fence's answer, in order.
    ///
    /// # Panics
    ///
    /// Panics when the record is poisoned.
    #[must_use]
    pub fn fences(&self) -> Vec<FenceAnswer> {
        self.fences.lock().expect("the fences").clone()
    }

    /// How many answers named the history they were held to.
    #[must_use]
    pub fn named(&self) -> usize {
        self.named.load(Ordering::SeqCst)
    }

    /// How many calls went through, counted before anything in them is read, so a request this
    /// transport cannot read is counted all the same.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// What this transport found wrong so far.
    ///
    /// # Panics
    ///
    /// Panics when the record is poisoned.
    #[must_use]
    pub fn findings(&self) -> Vec<String> {
        self.wrong.lock().expect("the findings").clone()
    }

    /// Says that every answer so far named the history this transport expects, and that some did.
    ///
    /// # Panics
    ///
    /// Panics with what was wrong when an answer named no history or another one, or when no answer
    /// named any.
    pub fn assert_every_answer_named_its_history(&self) {
        let wrong = self.wrong.lock().expect("the findings").clone();
        assert!(
            wrong.is_empty(),
            "answers that did not name {}: {wrong:?}",
            self.describe()
        );
        assert!(
            self.named() > 0,
            "no answer named any history, so none was checked"
        );
    }

    fn describe(&self) -> String {
        self.expected.map_or_else(
            || "the null history of a deployment never put back".to_owned(),
            |recovery| format!("recovery {recovery}"),
        )
    }

    /// Writes down one request before it leaves.
    fn note(&self, body: &[u8]) -> Option<String> {
        let request: serde_json::Value = serde_json::from_slice(body).ok()?;
        let (member, asked) = request["body"].as_object()?.iter().next()?;
        self.sent.lock().expect("the requests").push(Sent {
            member: member.clone(),
            collection: asked["collection_id"]
                .as_str()
                .or_else(|| asked["locator"].as_str())
                .map(str::to_owned),
            request_id: asked["request_id"].as_str().map(str::to_owned),
        });
        Some(member.clone())
    }

    /// Holds one answer to naming its history.
    fn check(&self, member: &str, answer: &ServiceHttpAnswer) {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&answer.body) else {
            self.wrong(format!(
                "a {member} answer that is not the service's envelope"
            ));
            return;
        };
        if value["ok"] == true {
            let data = &value["data"];
            match member {
                // A resolution names no place, so it names no history.
                "resolve" => {}
                // A listing names each collection's history beside its entry.
                "memberships" => {
                    for entry in data["memberships"].as_array().into_iter().flatten() {
                        self.hold(member, entry.get("recovery_id"));
                    }
                }
                _ => self.hold(member, data.get("recovery_id")),
            }
            if member == "fence" {
                self.fences.lock().expect("the fences").push(FenceAnswer {
                    request_id: data["request_id"].as_str().unwrap_or_default().to_owned(),
                    state: data["state"].as_str().unwrap_or_default().to_owned(),
                    never_ran: data["never_ran"] == true,
                });
            }
        } else if value["error"]["code"] == "KEY_EPOCH_RETIRED" {
            // The one refusal that names a place, a key record's revision, has to name its
            // history as well.
            self.hold(member, value["error"].get("recovery_id"));
        } else if let Some(named) = value["error"].get("recovery_id") {
            self.hold(member, Some(named));
        }
    }

    fn hold(&self, member: &str, named: Option<&serde_json::Value>) {
        let expected = self.expected.map(|recovery| recovery.get().to_string());
        match (named, expected) {
            (None, _) => self.wrong(format!("a {member} answer named no history")),
            (Some(serde_json::Value::Null), None) => {
                self.named.fetch_add(1, Ordering::SeqCst);
            }
            (Some(serde_json::Value::String(found)), Some(expected)) if *found == expected => {
                self.named.fetch_add(1, Ordering::SeqCst);
            }
            (Some(found), _) => self.wrong(format!(
                "a {member} answer named {found} where {} was expected",
                self.describe()
            )),
        }
    }

    fn wrong(&self, what: String) {
        self.wrong.lock().expect("the findings").push(what);
    }
}

impl ServiceHttp for Watched {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let member = self.note(body);
            if member.is_none() {
                self.wrong(
                    "a request this transport could not read, so its answer went unchecked"
                        .to_owned(),
                );
            }
            let answer = self.inner.post_json(url, body, headers).await;
            if let (Some(member), Ok(answer)) = (&member, &answer) {
                self.check(member, answer);
            }
            if self.lose_the_next_answer.swap(false, Ordering::SeqCst) {
                // The service has answered, and the answer goes no further than here: what a
                // connection that dropped on the way back looks like to the device that sent it.
                *self.lost.lock().expect("the lost answer") = answer.ok();
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::OutcomeUnknown,
                    "the answer never came back",
                )));
            }
            answer
        })
    }
}

/* -------------------------------------------------------------------------- */
/* A device's keys                                                             */
/* -------------------------------------------------------------------------- */

/// A device signing its managed-service requests as an installation, with its own keys.
///
/// The authorisation key that signs is the one a membership names the device by, so the
/// collection a device starts lives in the namespace the service derives from the same key.
pub struct DeviceSigner {
    keys: DeviceKeys,
}

impl fmt::Debug for DeviceSigner {
    /// The installation, which is public. Never a key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceSigner")
            .field("installation", &self.installation())
            .finish_non_exhaustive()
    }
}

impl DeviceSigner {
    /// Signs with `keys`.
    #[must_use]
    pub const fn new(keys: DeviceKeys) -> Self {
        Self { keys }
    }

    /// The device's keys.
    #[must_use]
    pub const fn keys(&self) -> &DeviceKeys {
        &self.keys
    }

    /// The installation the service derives from the signing key.
    #[must_use]
    pub fn installation(&self) -> InstallationId {
        installation_id(self.keys.authorisation.public())
    }
}

impl ServiceSigner for DeviceSigner {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.keys.authorisation.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        // The transcript refuses bytes that are not a domain-tagged array, so a signer cannot be
        // handed arbitrary bytes to sign under a domain it holds a key for.
        let transcript = SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Installation.domain(),
            message.to_vec(),
        )
        .expect("a domain-tagged credential");
        Ok(sign(&self.keys.authorisation, &transcript).expect("a signature"))
    }
}

/* -------------------------------------------------------------------------- */
/* A run directory                                                             */
/* -------------------------------------------------------------------------- */

/// Where one leg's device keeps what it holds between the phases of a run.
///
/// A device's stores are directories and its keys are items in an owner-only file store, exactly
/// as on a device that restarts, so a phase that opens them again holds what the phase before it
/// left and nothing it kept in memory.
#[derive(Clone, Debug)]
pub struct RunDirectory {
    root: PathBuf,
}

/// The scope a run's device keys are kept under in its file store.
const KEY_SCOPE: &str = "kalareach-backup-integration";

impl RunDirectory {
    /// The directory `variable` names, or nothing when the run named none.
    ///
    /// # Panics
    ///
    /// Panics when the run was promised its services and named no directory, or named one that is
    /// not absolute.
    #[must_use]
    pub fn from_variable(variable_name: &str) -> Option<Self> {
        let root = PathBuf::from(variable(variable_name)?);
        assert!(
            root.is_absolute(),
            "{variable_name} names an absolute directory"
        );
        std::fs::create_dir_all(&root).expect("the run directory");
        Some(Self { root })
    }

    /// A path inside the run directory.
    #[must_use]
    pub fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// The run directory itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The device's keys: made and stored by the first phase, read back by every later one.
    ///
    /// # Panics
    ///
    /// Panics when the store cannot be opened, written or read.
    #[must_use]
    pub fn device_keys(&self) -> DeviceKeys {
        // The run's own directory rather than this machine's credential store, on every platform:
        // the keys are made for the run and thrown away with it.
        let opened = kr_crypto::store::open_store_in(&self.path("device-keys"))
            .expect("the device's key store");
        let store = opened.store.as_ref();
        if let Some(keys) =
            kr_crypto::store::load_device_keys(store, KEY_SCOPE).expect("the device's keys")
        {
            return keys;
        }
        let keys = DeviceKeys::generate().expect("fresh device keys");
        kr_crypto::store::store_device_keys(store, KEY_SCOPE, &keys).expect("stored");
        keys
    }

    /// Writes one value the next phase reads.
    ///
    /// # Panics
    ///
    /// Panics when the file cannot be written.
    pub fn write(&self, name: &str, value: &serde_json::Value) {
        use std::io::Write as _;
        // Readable by this account alone: a phase can hand the next one a printed kit, which holds
        // a seed, even one made for the run.
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(self.path(name)).expect("the file");
        file.write_all(&serde_json::to_vec_pretty(value).expect("a JSON value"))
            .expect("written");
    }

    /// Reads one value an earlier phase wrote.
    ///
    /// # Panics
    ///
    /// Panics when the file is missing or is not JSON, which is a phase run out of order.
    #[must_use]
    pub fn read(&self, name: &str) -> serde_json::Value {
        let bytes = std::fs::read(self.path(name))
            .unwrap_or_else(|_| panic!("{name} was not written by an earlier phase"));
        serde_json::from_slice(&bytes).expect("a JSON value")
    }
}

/// Copies a directory tree, for a control that starts from exactly what a device holds.
///
/// Each directory keeps its own permissions, so a key store copied from an owner-only directory is
/// still one, and opens.
///
/// # Errors
///
/// Returns an error when anything cannot be read or written.
pub fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    std::fs::set_permissions(to, std::fs::metadata(from)?.permissions())?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A service that answers every request with one answer.
    #[derive(Debug)]
    struct Answering(serde_json::Value);

    impl ServiceHttp for Answering {
        fn post_json<'a>(
            &'a self,
            _url: &'a str,
            _body: &'a [u8],
            _headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            let body = serde_json::to_vec(&self.0).expect("an answer");
            Box::pin(std::future::ready(Ok(ServiceHttpAnswer {
                status: 200,
                body,
            })))
        }
    }

    fn recovery(byte: u8) -> SyncRecoveryId {
        SyncRecoveryId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16]))
    }

    /// What a transport expecting `expected` makes of one `member` request answered with `answer`.
    async fn watched(
        expected: Option<SyncRecoveryId>,
        member: &str,
        answer: serde_json::Value,
    ) -> (usize, Vec<String>) {
        let watched = Watched::new(Arc::new(Answering(answer)), expected);
        let request = serde_json::json!({ "body": { member: { "collection_id": "c" } } });
        let body = serde_json::to_vec(&request).expect("a request");
        watched
            .post_json("http://127.0.0.1:1/api/sync", &body, &[])
            .await
            .expect("answered");
        let wrong = watched.wrong.lock().expect("the findings").clone();
        (watched.named(), wrong)
    }

    fn data(recovery: Option<serde_json::Value>) -> serde_json::Value {
        let mut data = serde_json::json!({ "state": "written" });
        if let Some(recovery) = recovery {
            data["recovery_id"] = recovery;
        }
        serde_json::json!({ "ok": true, "data": data })
    }

    #[tokio::test]
    async fn a_null_history_is_named_where_none_was_ever_put_back() {
        let (named, wrong) = watched(None, "exchange", data(Some(serde_json::Value::Null))).await;
        assert_eq!((named, wrong.len()), (1, 0));
    }

    #[tokio::test]
    async fn an_answer_missing_its_history_is_told_from_one_naming_none() {
        let (named, wrong) = watched(None, "exchange", data(None)).await;
        assert_eq!(named, 0);
        assert_eq!(wrong, ["a exchange answer named no history"]);
    }

    #[tokio::test]
    async fn the_recovery_expected_is_named_and_any_other_is_not() {
        let expected = recovery(1);
        let right = data(Some(expected.get().to_string().into()));
        assert_eq!(watched(Some(expected), "status", right.clone()).await.0, 1);
        let other = data(Some(recovery(2).get().to_string().into()));
        assert_eq!(watched(Some(expected), "status", other).await.1.len(), 1);
        // A null where a recovery is expected is a deployment that forgot it was put back.
        let none = data(Some(serde_json::Value::Null));
        assert_eq!(watched(Some(expected), "fence", none).await.1.len(), 1);
        // And a recovery where none is expected is a deployment that was put back after all.
        assert_eq!(watched(None, "compare", right).await.1.len(), 1);
    }

    #[tokio::test]
    async fn a_retired_epoch_names_its_history_and_other_refusals_need_not() {
        let retired = |recovery: Option<serde_json::Value>| {
            let mut error = serde_json::json!({ "code": "KEY_EPOCH_RETIRED", "key_epoch": "1" });
            if let Some(recovery) = recovery {
                error["recovery_id"] = recovery;
            }
            serde_json::json!({ "ok": false, "error": error })
        };
        assert_eq!(
            watched(None, "exchange", retired(Some(serde_json::Value::Null))).await,
            (1, Vec::new())
        );
        assert_eq!(watched(None, "exchange", retired(None)).await.1.len(), 1);
        let absent = serde_json::json!({ "ok": false, "error": { "code": "COLLECTION_ABSENT" } });
        assert_eq!(watched(None, "keys", absent).await, (0, Vec::new()));
    }

    #[tokio::test]
    async fn a_listing_names_each_entrys_history_and_a_resolution_names_none() {
        let listing = serde_json::json!({ "ok": true, "data": { "memberships": [
            { "recovery_id": null }, { "recovery_id": null }
        ] } });
        assert_eq!(watched(None, "memberships", listing).await, (2, Vec::new()));
        let short = serde_json::json!({ "ok": true, "data": { "memberships": [ {} ] } });
        assert_eq!(watched(None, "memberships", short).await.1.len(), 1);
        let resolved = serde_json::json!({ "ok": true, "data": { "dropped": "1" } });
        assert_eq!(watched(None, "resolve", resolved).await, (0, Vec::new()));
    }

    #[tokio::test]
    async fn a_request_the_transport_cannot_read_is_a_finding() {
        let watched = Watched::new(Arc::new(Answering(data(None))), None);
        watched
            .post_json("http://127.0.0.1:1/api/sync", b"not json", &[])
            .await
            .expect("answered");
        assert_eq!(watched.findings().len(), 1);
        // Counted as a call although nothing in it could be read.
        assert_eq!((watched.calls(), watched.sent().len()), (1, 0));
    }
}
