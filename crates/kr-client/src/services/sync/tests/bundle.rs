//! The recovery bundle through the managed client, against a service kept to the contract a real
//! service keeps for it.
//!
//! [`Web`] answers the bundle's four requests as the managed service does. One collection for the
//! whole origin is kept at the locator, and the account whose write first applies there owns it.
//! Every request carries an account token: `backup.write` for a writer, and for a read either that
//! or `backup.restore`. A caller the collection does not admit is answered as for a collection
//! that does not exist. Receipts, fences and request identities belong to the collection rather
//! than to whoever presented them, and a write signed before the collection's cutoff runs
//! nothing. It checks no signature; the deployed legs hold the client to the service itself.
//!
//! What it does not model is stated, so nothing here is read as evidence of it: it sweeps no
//! receipt, so a fence that finds none always says the request never ran, where a service works that
//! out from the signing instants and what it has swept; and its cutoff refuses writes only, where a
//! service's refuses every request signed before it.
//!
//! Each suite drives `BundleStore` and `FreshRestore` through `ManagedSyncService`, which is the
//! path a device takes to a real service.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::recovery::{
    BundleStore, FreshRestore, LostWrite, RecoveryError, RetrievalPolicy, ServiceAccess,
    bundle_collection, fresh_locator, parse_kit, render_kit,
};
use crate::services::account::{
    AccountToken, AccountTokenSource, BACKUP_RESTORE_SCOPE, BACKUP_WRITE_SCOPE,
};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::archive::{CollectionLocator, RecoveryContext, RecoveryKit, TrustedWriter};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ArchiveId;
use kr_protocol::service::ServiceRequestSignature;
use kr_protocol::sync::{MAX_SEALED_RECOVERY_BUNDLE_BYTES, SealedRecoveryBundle};

const ORIGIN: &str = "https://reach.kala.to";

/* -------------------------------------------------------------------------- */
/* The service                                                                 */
/* -------------------------------------------------------------------------- */

/// One account token the account system issued: whose it is, and the scopes it carries.
#[derive(Clone, Copy, Debug)]
struct Issued {
    account: &'static str,
    scopes: &'static [&'static str],
}

/// The bundle as the collection holds it.
#[derive(Clone, Debug)]
struct Kept {
    revision: String,
    write_sequence: u64,
    /// The stream, as it arrived.
    ciphertext: serde_json::Value,
}

/// What one receipt recorded about one request identity.
#[derive(Clone, Debug)]
struct Recorded {
    /// What the write asked, less its identity: an exact retry asks the same.
    digest: serde_json::Value,
    /// `written`, `conflict` or `fenced`.
    outcome: &'static str,
    /// What an exact retry of the write is answered again.
    answer: Option<serde_json::Value>,
    current_revision: Option<String>,
    current_write_sequence: Option<String>,
    never_ran: bool,
}

/// The collection one locator names, as its collection object keeps it.
#[derive(Debug, Default)]
struct Held {
    /// The account whose write first applied, which is the only one admitted afterwards.
    owner: Option<&'static str>,
    kept: Option<Kept>,
    receipts: BTreeMap<String, Recorded>,
    /// Revisions the service gives writes, counted so each is new.
    revisions: u8,
    /// A request signed before this instant runs nothing and records nothing.
    cutoff_ms: u64,
    /// What the refusal of such a request says, when a test gives it words of its own.
    cutoff_words: Option<String>,
}

/// One request as the service read it.
#[derive(Clone, Debug)]
struct Seen {
    member: String,
    asked: serde_json::Value,
    authorization: Option<String>,
}

/// The managed service's contract for the recovery bundle.
#[derive(Debug, Default)]
struct Web {
    tokens: Mutex<BTreeMap<String, Issued>>,
    collections: Mutex<BTreeMap<String, Held>>,
    /// The history every answer names: none until the service is put back.
    recovery: Mutex<Option<Uuid>>,
    seen: Mutex<Vec<Seen>>,
    /// The next exchange runs and its answer never comes back.
    lose_the_next_answer: AtomicBool,
    /// The next exchange runs and is answered by something in front of the service with a fault.
    fault_the_next_exchange: AtomicBool,
    /// A read of the first locator is served the second locator's bundle.
    substitution: Mutex<Option<(String, String)>>,
    /// A status query or a fence about a refused write names a copy, which no service keeps of a
    /// bundle.
    names_copies_in_receipts: AtomicBool,
    /// An applied write is answered naming a copy as well, which no service keeps of a bundle.
    names_a_copy_on_writes: AtomicBool,
}

impl Web {
    fn open() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The account system issues `token` to `account`, carrying `scopes`.
    fn issue(&self, token: &str, account: &'static str, scopes: &'static [&'static str]) {
        self.tokens
            .lock()
            .expect("the tokens")
            .insert(token.to_owned(), Issued { account, scopes });
    }

    /// The account system forgets `token`, as it does once a grant ends or rotates.
    fn revoke(&self, token: &str) {
        self.tokens.lock().expect("the tokens").remove(token);
    }

    /// Serves a read of `asked` from what `served` holds, under `asked`'s name.
    fn substitute(&self, asked: &str, served: &str) {
        *self.substitution.lock().expect("the script") =
            Some((asked.to_owned(), served.to_owned()));
    }

    /// Puts the service back from an archive that held no bundle: a history of its own, and no
    /// collection, owner included.
    fn put_back_without_bundles(&self, recovery: Uuid) {
        *self.recovery.lock().expect("the history") = Some(recovery);
        self.collections.lock().expect("the collections").clear();
    }

    /// Moves one collection's cutoff to `cutoff_ms`, as a sweep past its retention does.
    fn cut_off(&self, locator: &str, cutoff_ms: u64) {
        self.collections
            .lock()
            .expect("the collections")
            .entry(locator.to_owned())
            .or_default()
            .cutoff_ms = cutoff_ms;
    }

    /// Moves one collection's cutoff as [`Self::cut_off`] does, and has its refusal of a request
    /// signed before it say `words`.
    fn cut_off_saying(&self, locator: &str, cutoff_ms: u64, words: &str) {
        self.cut_off(locator, cutoff_ms);
        self.collections
            .lock()
            .expect("the collections")
            .entry(locator.to_owned())
            .or_default()
            .cutoff_words = Some(words.to_owned());
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("the requests").clone()
    }

    fn members(&self) -> Vec<String> {
        self.seen().into_iter().map(|seen| seen.member).collect()
    }

    /// Where the bundle at `locator` stands, and who owns it.
    fn standing(&self, locator: &str) -> (Option<u64>, Option<&'static str>) {
        let collections = self.collections.lock().expect("the collections");
        collections.get(locator).map_or((None, None), |held| {
            (
                held.kept.as_ref().map(|kept| kept.write_sequence),
                held.owner,
            )
        })
    }

    fn history(&self) -> serde_json::Value {
        self.recovery
            .lock()
            .expect("the history")
            .map_or(serde_json::Value::Null, |recovery| {
                serde_json::Value::String(recovery.to_string())
            })
    }

    /// Answers one request as the collection object does.
    fn take(
        &self,
        body: &serde_json::Value,
        authorization: Option<&str>,
        at_ms: u64,
    ) -> ServiceHttpAnswer {
        let (member, asked) = body
            .as_object()
            .and_then(|members| members.iter().next())
            .expect("one member");
        self.seen.lock().expect("the requests").push(Seen {
            member: member.clone(),
            asked: asked.clone(),
            authorization: authorization.map(str::to_owned),
        });
        // A bundle's request names its locator and nothing that addresses a namespace: the
        // collection is the origin's, whoever asks.
        assert!(
            asked.get("collection_id").is_none() && asked.get("home").is_none(),
            "a bundle's request names no collection and no home"
        );
        let locator = asked["locator"].as_str().expect("a locator").to_owned();
        // The second proof: a live token that carries a scope this request reads. A missing one, an
        // unknown one and one without the scope are one answer, and so is an account the
        // collection does not admit.
        let needs: &[&str] = if member == "compare" {
            &[BACKUP_WRITE_SCOPE, BACKUP_RESTORE_SCOPE]
        } else {
            &[BACKUP_WRITE_SCOPE]
        };
        let issued = authorization
            .and_then(|value| value.strip_prefix("Bearer "))
            .and_then(|token| self.tokens.lock().expect("the tokens").get(token).copied())
            .filter(|issued| issued.scopes.iter().any(|scope| needs.contains(scope)));
        let Some(issued) = issued else {
            return absent();
        };
        let served = match &*self.substitution.lock().expect("the script") {
            Some((from, to)) if member == "compare" && *from == locator => to.clone(),
            _ => locator.clone(),
        };
        let history = self.history();
        let names_a_copy = self.names_copies_in_receipts.load(Ordering::SeqCst);
        let copy_on_writes = self.names_a_copy_on_writes.load(Ordering::SeqCst);
        let mut collections = self.collections.lock().expect("the collections");
        let held = collections.entry(served).or_default();
        if held.owner.is_some_and(|owner| owner != issued.account) {
            return absent();
        }
        match member.as_str() {
            "exchange" => {
                Self::exchange(held, issued.account, at_ms, asked, &history, copy_on_writes)
            }
            "compare" => Self::compare(held, &locator, &history),
            "status" => {
                let request = asked["request_id"].as_str().expect("an identity");
                held.receipts.get(request).map_or_else(
                    || answered(Self::unknown(request, &history)),
                    |receipt| answered(Self::receipt(request, receipt, &history, names_a_copy)),
                )
            }
            "fence" => {
                let request = asked["request_id"]
                    .as_str()
                    .expect("an identity")
                    .to_owned();
                let receipt = held.receipts.entry(request.clone()).or_insert(Recorded {
                    digest: serde_json::Value::Null,
                    outcome: "fenced",
                    answer: None,
                    current_revision: None,
                    current_write_sequence: None,
                    never_ran: true,
                });
                answered(Self::receipt(&request, receipt, &history, names_a_copy))
            }
            other => panic!("a bundle is written, read, asked about and fenced, not {other}"),
        }
    }

    /// One write, in the service's order: the cutoff, a receipt for the identity, the bound, and
    /// then the comparison. The first write that applies claims the collection.
    fn exchange(
        held: &mut Held,
        account: &'static str,
        at_ms: u64,
        asked: &serde_json::Value,
        history: &serde_json::Value,
        copy_on_writes: bool,
    ) -> ServiceHttpAnswer {
        if at_ms < held.cutoff_ms {
            return refusal(
                409,
                "SIGNED_BEFORE_CUTOFF",
                held.cutoff_words
                    .as_deref()
                    .unwrap_or("signed before the cutoff"),
            );
        }
        let request = asked["request_id"]
            .as_str()
            .expect("an identity")
            .to_owned();
        let digest = serde_json::json!({
            "locator": asked["locator"],
            "kind": asked["kind"],
            "expected_revision": asked["expected_revision"],
            "object": asked["object"],
        });
        if let Some(receipt) = held.receipts.get(&request) {
            if receipt.outcome == "fenced" {
                return refusal(409, "REQUEST_FENCED", "fenced");
            }
            if receipt.digest != digest {
                return refusal(409, "ID_CONFLICT", "another request wore that identity");
            }
            return answered(receipt.answer.clone().expect("the answer it was given"));
        }
        assert_eq!(asked["kind"], "recovery_bundle");
        let object: SealedRecoveryBundle =
            serde_json::from_value(asked["object"].clone()).expect("a sealed recovery bundle");
        if object.check_structure().is_err() {
            return refusal(
                400,
                "INVALID_ARGUMENT",
                "not a recovery bundle this service keeps",
            );
        }
        let current = held.kept.clone();
        let expected = asked["expected_revision"].as_str().map(str::to_owned);
        if current.as_ref().map(|kept| kept.revision.clone()) != expected {
            let (revision, write_sequence) =
                current.map_or((None, 0), |kept| (Some(kept.revision), kept.write_sequence));
            let answer = serde_json::json!({
                "state": "conflict",
                "record": null,
                "current_revision": revision,
                "current_write_sequence": write_sequence.to_string(),
                "conflict": null,
                "recovery_id": history,
                "stored": stored(held.kept.is_some()),
            });
            held.receipts.insert(
                request,
                Recorded {
                    digest,
                    outcome: "conflict",
                    answer: Some(answer.clone()),
                    current_revision: revision,
                    current_write_sequence: Some(write_sequence.to_string()),
                    never_ran: false,
                },
            );
            return answered(answer);
        }
        held.revisions += 1;
        let kept = Kept {
            revision: revision(0xb0 + held.revisions).to_string(),
            write_sequence: current.map_or(1, |kept| kept.write_sequence + 1),
            ciphertext: asked["object"]["ciphertext"].clone(),
        };
        held.kept = Some(kept.clone());
        held.owner.get_or_insert(account);
        let answer = serde_json::json!({
            "state": "written",
            "record": {
                "kind": "recovery_bundle",
                "object_id": asked["locator"],
                "revision": kept.revision,
                "write_sequence": kept.write_sequence.to_string(),
                "updated_at": "2026-09-25T10:00:00.000Z",
                "bytes": "4096",
            },
            "current_revision": kept.revision,
            "current_write_sequence": kept.write_sequence.to_string(),
            "conflict": if copy_on_writes {
                serde_json::json!({
                    "sequence": "1",
                    "conflict_id": identity(0xef).to_string(),
                    "object_id": asked["locator"],
                    "expected_revision": asked["expected_revision"],
                    "current_revision": kept.revision,
                    "current_write_sequence": kept.write_sequence.to_string(),
                    "recorded_at": "2026-09-25T10:00:00.000Z",
                })
            } else {
                serde_json::Value::Null
            },
            "recovery_id": history,
            "stored": stored(true),
        });
        held.receipts.insert(
            request,
            Recorded {
                digest,
                outcome: "written",
                answer: Some(answer.clone()),
                current_revision: Some(kept.revision.clone()),
                current_write_sequence: Some(kept.write_sequence.to_string()),
                never_ran: false,
            },
        );
        answered(answer)
    }

    /// A read: the bundle and where it stands, or nothing, in the history the service answers
    /// from. The object is named by the locator the request asked for.
    fn compare(held: &Held, locator: &str, history: &serde_json::Value) -> ServiceHttpAnswer {
        let (changed, revisions) = held.kept.as_ref().map_or_else(
            || (Vec::new(), Vec::new()),
            |kept| {
                (
                    vec![serde_json::json!({
                        "kind": "recovery_bundle",
                        "object_id": locator,
                        "revision": kept.revision,
                        "write_sequence": kept.write_sequence.to_string(),
                        "object": { "ciphertext": kept.ciphertext },
                        "updated_at": "2026-09-25T10:00:00.000Z",
                    })],
                    vec![serde_json::json!({
                        "object_id": locator,
                        "revision": kept.revision,
                        "write_sequence": kept.write_sequence.to_string(),
                    })],
                )
            },
        );
        answered(serde_json::json!({
            "changed": changed,
            "removed": [],
            "revisions": revisions,
            "conflicts": [],
            "next_conflicts_after_sequence": "0",
            "more_conflicts": false,
            "recovery_id": history,
            "stored": stored(held.kept.is_some()),
        }))
    }

    fn unknown(request: &str, history: &serde_json::Value) -> serde_json::Value {
        let mut answer = status(request.parse().expect("an identity"), "unknown", false);
        answer["recovery_id"] = history.clone();
        answer
    }

    /// What a status query and a fence are answered about one receipt, naming a copy of a refused
    /// write where the test asks for one.
    fn receipt(
        request: &str,
        receipt: &Recorded,
        history: &serde_json::Value,
        names_a_copy: bool,
    ) -> serde_json::Value {
        let state = match receipt.outcome {
            "written" => "applied",
            "conflict" => "refused",
            _ => "fenced",
        };
        let conflict_id =
            (names_a_copy && receipt.outcome == "conflict").then(|| identity(0xee).to_string());
        serde_json::json!({
            "request_id": request,
            "state": state,
            "never_ran": receipt.never_ran,
            "outcome": receipt.outcome,
            "record": null,
            "current_revision": receipt.current_revision,
            "current_write_sequence": receipt.current_write_sequence,
            "conflict_id": conflict_id,
            "recovery_id": history,
            "recorded_at": "2026-09-25T10:00:00.000Z",
        })
    }
}

impl ServiceHttp for Web {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        let request: serde_json::Value = serde_json::from_slice(body).expect("a signed request");
        let signature: ServiceRequestSignature =
            serde_json::from_value(request["signature"].clone()).expect("a credential");
        let authorization = headers
            .iter()
            .find(|(name, _)| *name == "authorization")
            .map(|(_, value)| *value);
        let is_exchange = request["body"].get("exchange").is_some();
        let answer = self.take(
            &request["body"],
            authorization,
            signature.payload.signed_at_ms.get(),
        );
        let answer = if is_exchange && self.fault_the_next_exchange.swap(false, Ordering::SeqCst) {
            Ok(ServiceHttpAnswer {
                status: 502,
                body: b"<html>Bad Gateway</html>".to_vec(),
            })
        } else if is_exchange && self.lose_the_next_answer.swap(false, Ordering::SeqCst) {
            Err(ClientError::refusal(
                ErrorCode::UpstreamUnavailable,
                Shown::said("the answer never came back"),
            ))
        } else {
            Ok(answer)
        };
        Box::pin(async move { answer })
    }
}

/// What the service answers a caller the collection does not admit, and a collection nobody made.
fn absent() -> ServiceHttpAnswer {
    refusal(
        404,
        "COLLECTION_ABSENT",
        "That collection does not exist, or this caller may not reach it.",
    )
}

/// A successful envelope around `data`.
fn answered(data: serde_json::Value) -> ServiceHttpAnswer {
    ServiceHttpAnswer {
        status: 200,
        body: serde_json::to_vec(&serde_json::json!({ "ok": true, "data": data }))
            .expect("an answer"),
    }
}

/// What the collection reports about itself, which no assertion here is about.
fn stored(holds: bool) -> serde_json::Value {
    serde_json::json!({
        "objects": if holds { "1" } else { "0" },
        "conflicts": "0",
        "bytes": if holds { "4352" } else { "0" },
        "object_limit": "1",
        "allowance_bytes": null,
    })
}

/* -------------------------------------------------------------------------- */
/* A device                                                                    */
/* -------------------------------------------------------------------------- */

/// Where a device's account token comes from: whatever it holds now, or nothing while it is signed
/// out.
#[derive(Debug, Default)]
struct SignIn {
    token: Mutex<Option<String>>,
}

impl SignIn {
    fn holding(token: &str) -> Arc<Self> {
        Arc::new(Self {
            token: Mutex::new(Some(token.to_owned())),
        })
    }

    fn signed_out() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn now_holds(&self, token: Option<&str>) {
        *self.token.lock().expect("the token") = token.map(str::to_owned);
    }
}

impl AccountTokenSource for SignIn {
    fn token<'a>(&'a self, _scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        let token = match self.token.lock().expect("the token").clone() {
            Some(token) => AccountToken::new(token),
            None => Err(ClientError::refusal(
                ErrorCode::HostNotConfigured,
                Shown::said("no account is signed in on this device"),
            )),
        };
        Box::pin(async move { token })
    }
}

/// A device's client to `web`: an installation key of its own, presenting `sign_in`'s token for
/// `scope` with every request about a recovery bundle.
fn client(web: &Arc<Web>, sign_in: &Arc<SignIn>, scope: &'static str) -> Arc<ManagedSyncService> {
    Arc::new(
        unsigned_client(web).presenting(Arc::clone(sign_in) as Arc<dyn AccountTokenSource>, scope),
    )
}

/// A device's client to `web` that presents no account.
fn unsigned_client(web: &Arc<Web>) -> ManagedSyncService {
    ManagedSyncService::new(
        GatewayOrigin::new(ORIGIN).expect("an origin"),
        Arc::clone(web) as Arc<dyn ServiceHttp>,
        Arc::new(Device {
            pair: AuthorisationKeyPair::generate().expect("a key pair"),
        }) as Arc<dyn ServiceSigner>,
    )
}

fn at(origin: &str, locator: &str) -> RecoveryContext {
    RecoveryContext {
        service_origin: origin.to_owned(),
        bundle_locator: locator.to_owned(),
    }
}

/// A bundle store on a disk of its own, which it keeps its write record on.
struct Store {
    store: BundleStore,
    disk: tempfile::TempDir,
}

impl std::ops::Deref for Store {
    type Target = BundleStore;

    fn deref(&self) -> &BundleStore {
        &self.store
    }
}

impl std::ops::DerefMut for Store {
    fn deref_mut(&mut self) -> &mut BundleStore {
        &mut self.store
    }
}

fn store(client: &Arc<ManagedSyncService>, context: RecoveryContext) -> Store {
    let disk = tempfile::tempdir().expect("a directory on the internal disk");
    let store = BundleStore::open(
        Arc::clone(client) as Arc<dyn SyncBackupService>,
        context,
        disk.path(),
    )
    .expect("the store opens");
    Store { store, disk }
}

impl Store {
    /// Ends this store, as a process that stops does, and opens another over its disk.
    fn restart(self, client: &Arc<ManagedSyncService>) -> Self {
        let Self { store, disk } = self;
        let context = store.context().clone();
        drop(store);
        let store = BundleStore::open(
            Arc::clone(client) as Arc<dyn SyncBackupService>,
            context,
            disk.path(),
        )
        .expect("the store opens again");
        Self { store, disk }
    }

    /// The bytes of the write record on this store's disk, if there is one.
    fn record(&self) -> Option<Vec<u8>> {
        std::fs::read_dir(self.disk.path())
            .expect("the disk")
            .map(|entry| entry.expect("an entry").path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "bundle-write")
            })
            .map(|path| std::fs::read(path).expect("the record"))
    }
}

fn now() -> TimestampMs {
    TimestampMs::new(now_ms())
}

/// The kit as a person keeps it: printed, then read back from the page.
fn kept(kit: &RecoveryKit) -> RecoveryKit {
    parse_kit(&render_kit(kit).expect("a printable kit")).expect("the kit reads back")
}

fn trusted(writer: &AuthorisationKeyPair) -> TrustedWriter {
    TrustedWriter {
        writer_key_id: writer.key_id(),
        signing_key: *writer.public(),
        enrolled_at_ms: TimestampMs::new(1_780_000_000_000),
    }
}

/// A restore from `kit` whose retrieval policy gave it `reader` at `origin`.
fn restore_with(kit: RecoveryKit, origin: &str, reader: Arc<ManagedSyncService>) -> FreshRestore {
    let mut restore = FreshRestore::new(kit, RetrievalPolicy::Account);
    restore
        .obtained_access(ServiceAccess::new(
            RetrievalPolicy::Account,
            origin,
            reader as Arc<dyn SyncBackupService>,
        ))
        .expect("the kit names that origin");
    restore
}

/// An owner who has written the bundle, with one writer in it, at a fresh locator.
struct Owner {
    web: Arc<Web>,
    sign_in: Arc<SignIn>,
    client: Arc<ManagedSyncService>,
    seed: RecoverySeed,
    locator: String,
    store: Store,
    bundle: kr_protocol::archive::RecoveryBundle,
    writer: AuthorisationKeyPair,
}

async fn owner_with_a_writer() -> Owner {
    let web = Web::open();
    web.issue("owner-write", "owner", &[BACKUP_WRITE_SCOPE]);
    let sign_in = SignIn::holding("owner-write");
    let client = client(&web, &sign_in, BACKUP_WRITE_SCOPE);
    let seed = RecoverySeed::generate().expect("a seed");
    let locator = fresh_locator().expect("a locator");
    let mut store = store(&client, at(ORIGIN, &locator));
    let mut bundle = BundleStore::empty(now());
    store
        .commit(&seed, &mut bundle, now())
        .await
        .expect("the first bundle");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    store
        .enable_writer(&seed, &mut bundle, trusted(&writer), now())
        .await
        .expect("the writer's bundle");
    Owner {
        web,
        sign_in,
        client,
        seed,
        locator,
        store,
        bundle,
        writer,
    }
}

/* -------------------------------------------------------------------------- */
/* The path                                                                    */
/* -------------------------------------------------------------------------- */

/// KR-REQ-20.15 and 20.18 through the managed client: the bundle is written by compare and swap at
/// its locator, the writer is declared only once its bundle has landed, and a store that knows
/// nothing reads it back. Every request names the locator and the kind and nothing that addresses a
/// namespace, carries the account token beside its signature, and carries the stream the seed
/// sealed and nothing beside it.
#[tokio::test]
async fn a_bundle_is_written_and_read_at_its_locator_with_the_account_token_beside_every_request() {
    let owner = owner_with_a_writer().await;
    assert_eq!(
        owner
            .store
            .position()
            .map(|at| (at.write_sequence, at.recovery())),
        Some((2, None))
    );
    assert_eq!(owner.web.standing(&owner.locator), (Some(2), Some("owner")));

    let mut reading = store(&owner.client, at(ORIGIN, &owner.locator));
    let read = reading.fetch(&owner.seed).await.expect("the bundle");
    assert_eq!(read, owner.bundle);
    assert!(
        read.trusted_writers
            .iter()
            .any(|trusted| trusted.writer_key_id == owner.writer.key_id())
    );

    let seen = owner.web.seen();
    assert_eq!(owner.web.members(), ["exchange", "exchange", "compare"]);
    for request in &seen {
        assert_eq!(request.authorization.as_deref(), Some("Bearer owner-write"));
        assert_eq!(request.asked["locator"], owner.locator.as_str());
        assert_eq!(request.asked["kind"], "recovery_bundle");
    }
    assert_eq!(seen[0].asked["expected_revision"], serde_json::Value::Null);
    assert!(seen[1].asked["expected_revision"].is_string());
    // The object is the stream, and it opens under the key the seed derives for this origin and
    // locator: what travelled is what was sealed, byte for byte.
    let object: SealedRecoveryBundle = serde_json::from_value(seen[1].asked["object"].clone())
        .expect("the stream and nothing else");
    let key = owner
        .seed
        .bundle_key_for(&at(ORIGIN, &owner.locator))
        .expect("the bundle key");
    assert_eq!(
        kr_crypto::archive::decrypt_recovery_bundle(&key, object.ciphertext.as_slice())
            .expect("it opens"),
        owner.bundle
    );
    assert_eq!(
        bundle_collection(&at(ORIGIN, &owner.locator)),
        format!("recovery_bundle/{}", owner.locator)
    );
}

/// KR-REQ-20.18 and KR-REQ-04.19: each request this client sends about a recovery bundle is the one
/// the vectors publish for its member, field for field and value for value, with the account token
/// beside a signature that carries the published digest. A service's contract reads the same
/// cases, so neither side can come to address the bundle by anything but its locator.
#[tokio::test]
async fn every_request_about_a_bundle_is_the_one_the_vectors_publish() {
    let cases = published_requests();
    let recorder = Recorder::presented("owner-write");
    let client = ManagedSyncService::new(
        GatewayOrigin::new(ORIGIN).expect("an origin"),
        Arc::clone(&recorder) as Arc<dyn ServiceHttp>,
        Arc::new(Device {
            pair: AuthorisationKeyPair::generate().expect("a key pair"),
        }) as Arc<dyn ServiceSigner>,
    )
    .presenting(
        SignIn::holding("owner-write") as Arc<dyn AccountTokenSource>,
        BACKUP_WRITE_SCOPE,
    );
    // What a caller hands over is the name the kit's locator gives the bundle's collection.
    let named = |case: &serde_json::Value| {
        bundle_collection(&at(ORIGIN, &published_field::<String>(case, "locator")))
    };

    let case = &cases["bundle_exchange"];
    let bundle: SealedRecoveryBundle = published_field(case, "object");
    let expected: Option<SyncRevision> = published_field(case, "expected_revision");
    recorder.answering(vec![exchanged(
        "written",
        serde_json::json!({
            "kind": "recovery_bundle",
            "object_id": published_field::<String>(case, "locator"),
            "revision": revision(0xb1).to_string(),
            "write_sequence": "1",
            "updated_at": "2026-09-25T10:00:00.000Z",
            "bytes": "4096",
        }),
        Some(revision(0xb1)),
        "1",
        serde_json::Value::Null,
    )]);
    client
        .compare_exchange(
            &named(case),
            published_field(case, "request_id"),
            now_ms(),
            expected.map(|replaced| SyncPosition::at(1, replaced, None)),
            bundle.ciphertext.as_slice(),
        )
        .await
        .expect("applied");
    sent_as_published(&recorder, case);

    let case = &cases["bundle_compare"];
    recorder.answering(vec![serde_json::json!({
        "changed": [],
        "removed": [],
        "revisions": [],
        "conflicts": [],
        "next_conflicts_after_sequence": "0",
        "more_conflicts": false,
        "recovery_id": null,
        "stored": stored(false),
    })]);
    client.fetch(&named(case)).await.expect("an answer");
    sent_as_published(&recorder, case);

    let case = &cases["bundle_status"];
    let request: Uuid = published_field(case, "request_id");
    recorder.answering(vec![status(request, "unknown", false)]);
    client
        .request_status(&named(case), request)
        .await
        .expect("an answer");
    sent_as_published(&recorder, case);

    let case = &cases["bundle_fence"];
    let request: Uuid = published_field(case, "request_id");
    let first: U64 = published_field(case, "first_signed_at_ms");
    let last: U64 = published_field(case, "last_signed_at_ms");
    let mut fenced = status(request, "fenced", true);
    fenced["outcome"] = serde_json::Value::String("fenced".to_owned());
    recorder.answering(vec![fenced]);
    client
        .fence_request(&named(case), request, first.get(), last.get())
        .await
        .expect("an answer");
    sent_as_published(&recorder, case);
}

/// KR-REQ-20.18: this service reads each request about a recovery bundle the vectors publish, as it
/// reads the requests this client sends. The write lands at the locator it names, the read serves
/// back the stream the write carried, and the status query and the fence each find the receipt of
/// the write their request identity names.
#[test]
fn this_service_reads_every_request_about_a_bundle_the_vectors_publish() {
    let cases = published_requests();
    let web = Web::open();
    web.issue("owner-write", "owner", &[BACKUP_WRITE_SCOPE]);
    let take = |id: &str| {
        let (member, fields) = one_member(&cases[id]["json"]);
        let answer = web.take(&cases[id]["json"], Some("Bearer owner-write"), now_ms());
        assert_eq!(answer.status, 200, "{id}");
        let seen = web.seen().pop().expect("the request it read");
        assert_eq!(&seen.member, member, "{id}");
        assert_eq!(seen.asked.as_object(), Some(fields), "{id}");
        let answer: serde_json::Value = serde_json::from_slice(&answer.body).expect("an envelope");
        answer["data"].clone()
    };
    let write = &cases["bundle_exchange"]["json"]["exchange"];

    let written = take("bundle_exchange");
    assert_eq!(written["state"], "written");
    assert_eq!(written["record"]["object_id"], write["locator"]);
    let read = take("bundle_compare");
    assert_eq!(read["changed"][0]["object_id"], write["locator"]);
    assert_eq!(read["changed"][0]["object"], write["object"]);
    for id in ["bundle_status", "bundle_fence"] {
        let receipt = take(id);
        let (_, asked) = one_member(&cases[id]["json"]);
        assert_eq!(receipt["request_id"], asked["request_id"], "{id}");
        assert_eq!(receipt["state"], "applied", "{id}: the write's receipt");
    }
}

/// KR-ACC-033 and KR-REQ-20.19 through the managed client: a device holding only the kit reaches
/// the bundle through the access its retrieval policy gave it, a token for the restore alone, and
/// authenticates it with the kit. Without that access it reaches nothing: a device presenting no
/// account sends nothing, a token of another account reads the bundle as absent, and a token for
/// the restore writes nothing.
#[tokio::test]
async fn a_device_with_only_the_kit_reads_the_bundle_through_the_access_its_policy_gives_it() {
    let owner = owner_with_a_writer().await;
    let kit = kept(
        &owner
            .seed
            .to_kit(vec![ORIGIN.to_owned()], owner.locator.clone()),
    );

    owner
        .web
        .issue("owner-restore", "owner", &[BACKUP_RESTORE_SCOPE]);
    let restoring = client(
        &owner.web,
        &SignIn::holding("owner-restore"),
        BACKUP_RESTORE_SCOPE,
    );
    let found = restore_with(kit.clone(), ORIGIN, Arc::clone(&restoring))
        .open_bundle(ORIGIN)
        .await
        .expect("the bundle, with only the kit");
    assert_eq!(found.bundle_revision, 2);
    assert_eq!(found.trusted_writers, [trusted(&owner.writer)]);

    let before = owner.web.seen().len();
    match restore_with(kit.clone(), ORIGIN, Arc::new(unsigned_client(&owner.web)))
        .open_bundle(ORIGIN)
        .await
    {
        Err(RecoveryError::Service(error)) => {
            assert_eq!(error.code(), ErrorCode::HostNotConfigured);
        }
        other => panic!("no account, no request: {other:?}"),
    }
    assert_eq!(owner.web.seen().len(), before, "nothing was sent");

    owner
        .web
        .issue("stranger-restore", "stranger", &[BACKUP_RESTORE_SCOPE]);
    let stranger = client(
        &owner.web,
        &SignIn::holding("stranger-restore"),
        BACKUP_RESTORE_SCOPE,
    );
    match restore_with(kit, ORIGIN, stranger)
        .open_bundle(ORIGIN)
        .await
    {
        Err(RecoveryError::Service(error)) => assert_eq!(error.code(), ErrorCode::UnknownSession),
        other => panic!("another account's token reads the bundle as absent: {other:?}"),
    }

    // A token for the restore reads and writes nothing: its write is answered as for a bundle that
    // does not exist, and the bundle stays where it was.
    let mut restored = store(&restoring, at(ORIGIN, &owner.locator));
    let mut bundle = owner.bundle.clone();
    restored
        .fetch(&owner.seed)
        .await
        .expect("read with the restore token");
    let refused = restored
        .commit(&owner.seed, &mut bundle, now())
        .await
        .expect_err("a restore token writes nothing");
    match refused {
        RecoveryError::BundleOutcomeUnknown { source, .. } => {
            assert_eq!(source.code(), ErrorCode::UnknownSession);
        }
        other => panic!("the service answered after the request left: {other:?}"),
    }
    assert_eq!(owner.web.standing(&owner.locator), (Some(2), Some("owner")));
}

/// KR-REQ-20.16 and 20.19 through the managed client: the owner's real bundle, served under
/// another locator or read as another origin's, does not authenticate, and neither does it under a
/// kit of another seed; nothing is trusted from any of them.
#[tokio::test]
async fn a_bundle_served_under_another_locator_or_origin_fails_authentication() {
    let owner = owner_with_a_writer().await;
    owner
        .web
        .issue("owner-restore", "owner", &[BACKUP_RESTORE_SCOPE]);
    let reader = client(
        &owner.web,
        &SignIn::holding("owner-restore"),
        BACKUP_RESTORE_SCOPE,
    );

    let elsewhere = fresh_locator().expect("a locator");
    owner.web.substitute(&elsewhere, &owner.locator);
    let moved = kept(&owner.seed.to_kit(vec![ORIGIN.to_owned()], elsewhere));
    assert!(matches!(
        restore_with(moved, ORIGIN, Arc::clone(&reader))
            .open_bundle(ORIGIN)
            .await,
        Err(RecoveryError::BundleNotAuthentic)
    ));

    let other_origin = "https://recovery-substitute.invalid";
    let other = kept(
        &owner
            .seed
            .to_kit(vec![other_origin.to_owned()], owner.locator.clone()),
    );
    assert!(matches!(
        restore_with(other, other_origin, Arc::clone(&reader))
            .open_bundle(other_origin)
            .await,
        Err(RecoveryError::BundleNotAuthentic)
    ));

    let stranger = kept(
        &RecoverySeed::generate()
            .expect("a seed")
            .to_kit(vec![ORIGIN.to_owned()], owner.locator.clone()),
    );
    assert!(matches!(
        restore_with(stranger, ORIGIN, reader)
            .open_bundle(ORIGIN)
            .await,
        Err(RecoveryError::BundleNotAuthentic)
    ));
}

/// KR-REQ-20.18: two devices of one account write from the same place, and one of them is told the
/// bundle moved on, with no copy kept; it reads again and writes after the other.
#[tokio::test]
async fn two_writers_of_one_account_race_and_one_is_told_the_bundle_moved_on() {
    let owner = owner_with_a_writer().await;
    let second = client(&owner.web, &owner.sign_in, BACKUP_WRITE_SCOPE);
    let mut other = store(&second, at(ORIGIN, &owner.locator));
    let mut theirs = other.fetch(&owner.seed).await.expect("the bundle");

    let Owner {
        seed,
        mut store,
        mut bundle,
        web,
        locator,
        ..
    } = owner;
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&AuthorisationKeyPair::generate().expect("a writer key")),
            now(),
        )
        .await
        .expect("the first write of the two");
    let refused = other
        .enable_writer(
            &seed,
            &mut theirs,
            trusted(&AuthorisationKeyPair::generate().expect("a writer key")),
            now(),
        )
        .await
        .expect_err("the second write of the two");
    assert!(
        matches!(
            refused,
            RecoveryError::BundleConflict {
                expected: Some(at),
                retained: None,
            } if at.write_sequence == 2
        ),
        "{refused:?}"
    );
    let mut theirs = other.fetch(&seed).await.expect("read again");
    assert_eq!(theirs.revision.get(), 3);
    other
        .enable_writer(
            &seed,
            &mut theirs,
            trusted(&AuthorisationKeyPair::generate().expect("a writer key")),
            now(),
        )
        .await
        .expect("written after the other");
    assert_eq!(web.standing(&locator), (Some(4), Some("owner")));
}

/// The first write that applies claims the collection for its account. A competing first claim
/// from another account, made after it, is answered as for a collection that does not exist, and
/// so is that account's read, its status query and its fence; the owner's bundle is untouched.
#[tokio::test]
async fn competing_first_claims_leave_one_owner_and_every_other_account_meets_an_absent_bundle() {
    let owner = owner_with_a_writer().await;
    owner
        .web
        .issue("stranger-write", "stranger", &[BACKUP_WRITE_SCOPE]);
    let stranger_sign_in = SignIn::holding("stranger-write");
    let stranger = client(&owner.web, &stranger_sign_in, BACKUP_WRITE_SCOPE);
    let mut theirs = store(&stranger, at(ORIGIN, &owner.locator));
    let their_seed = RecoverySeed::generate().expect("their seed");

    match theirs.fetch(&their_seed).await {
        Err(RecoveryError::Service(error)) => assert_eq!(error.code(), ErrorCode::UnknownSession),
        other => panic!("another account reads nothing: {other:?}"),
    }
    let mut bundle = BundleStore::empty(now());
    match theirs.commit(&their_seed, &mut bundle, now()).await {
        Err(RecoveryError::BundleOutcomeUnknown { source, .. }) => {
            assert_eq!(source.code(), ErrorCode::UnknownSession);
        }
        other => panic!("another account's first claim is refused: {other:?}"),
    }
    assert!(matches!(
        theirs.end_lost_write(&their_seed).await,
        Err(RecoveryError::Service(_))
    ));
    let collection = bundle_collection(&at(ORIGIN, &owner.locator));
    for refused in [
        stranger
            .request_status(&collection, identity(0x61))
            .await
            .map(|_| ()),
        stranger
            .fence_request(&collection, identity(0x62), now_ms(), now_ms())
            .await
            .map(|_| ()),
    ] {
        assert_eq!(
            refused.expect_err("absent").code(),
            ErrorCode::UnknownSession
        );
    }
    assert_eq!(owner.web.standing(&owner.locator), (Some(2), Some("owner")));
    assert_eq!(
        owner.web.collections.lock().expect("the collections")[&owner.locator]
            .receipts
            .len(),
        2,
        "the owner's two writes, and nothing of another account's"
    );
}

/// A first write that does not apply claims nothing: another account can still claim the locator
/// with a write of its own, and then the first account meets an absent bundle.
#[tokio::test]
async fn a_first_write_that_did_not_apply_claims_nothing() {
    let web = Web::open();
    web.issue("first-write", "first", &[BACKUP_WRITE_SCOPE]);
    web.issue("second-write", "second", &[BACKUP_WRITE_SCOPE]);
    let first = client(&web, &SignIn::holding("first-write"), BACKUP_WRITE_SCOPE);
    let second = client(&web, &SignIn::holding("second-write"), BACKUP_WRITE_SCOPE);
    let locator = fresh_locator().expect("a locator");
    let collection = bundle_collection(&at(ORIGIN, &locator));

    // A write that expects a bundle where there is none is refused, and claims nothing.
    let seed = RecoverySeed::generate().expect("a seed");
    let key = seed.bundle_key_for(&at(ORIGIN, &locator)).expect("a key");
    let sealed = kr_crypto::archive::encrypt_recovery_bundle(&key, &BundleStore::empty(now()))
        .expect("sealed");
    let refused = first
        .compare_exchange(
            &collection,
            identity(0x71),
            now_ms(),
            Some(SyncPosition::at(1, revision(0x72), None)),
            &sealed,
        )
        .await
        .expect("an answer");
    assert!(matches!(
        refused,
        SyncExchanged::Refused {
            retained: None,
            current: None,
            ..
        }
    ));
    assert_eq!(web.standing(&locator), (None, None));

    let theirs_seed = RecoverySeed::generate().expect("a seed");
    let mut theirs = store(&second, at(ORIGIN, &locator));
    theirs
        .commit(&theirs_seed, &mut BundleStore::empty(now()), now())
        .await
        .expect("the second account claims it");
    assert_eq!(web.standing(&locator), (Some(1), Some("second")));
    assert_eq!(
        first
            .fetch(&collection)
            .await
            .expect_err("absent to the first account")
            .code(),
        ErrorCode::UnknownSession
    );
}

/// A fence made before the locator is claimed belongs to the collection, and survives the claim: a
/// write under that identity that arrives afterwards runs nothing, whoever sends it.
#[tokio::test]
async fn a_fence_made_before_the_claim_survives_it() {
    let web = Web::open();
    web.issue("owner-write", "owner", &[BACKUP_WRITE_SCOPE]);
    web.issue("other-write", "other", &[BACKUP_WRITE_SCOPE]);
    let owner = client(&web, &SignIn::holding("owner-write"), BACKUP_WRITE_SCOPE);
    let other = client(&web, &SignIn::holding("other-write"), BACKUP_WRITE_SCOPE);
    let locator = fresh_locator().expect("a locator");
    let collection = bundle_collection(&at(ORIGIN, &locator));
    let delayed = identity(0x81);

    let fenced = other
        .fence_request(&collection, delayed, now_ms(), now_ms())
        .await
        .expect("fenced before any claim");
    assert!(matches!(
        fenced,
        SyncRequestFence::Fenced {
            never_ran: true,
            ..
        }
    ));

    let seed = RecoverySeed::generate().expect("a seed");
    let mut theirs = store(&owner, at(ORIGIN, &locator));
    theirs
        .commit(&seed, &mut BundleStore::empty(now()), now())
        .await
        .expect("the owner claims it");
    let key = seed.bundle_key_for(&at(ORIGIN, &locator)).expect("a key");
    let sealed = kr_crypto::archive::encrypt_recovery_bundle(&key, &BundleStore::empty(now()))
        .expect("sealed");
    let refused = owner
        .compare_exchange(&collection, delayed, now_ms(), theirs.position(), &sealed)
        .await
        .expect_err("the fence holds");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    assert!(matches!(
        owner
            .request_status(&collection, delayed)
            .await
            .expect("an answer"),
        SyncRequestStatus::Fenced {
            never_ran: true,
            ..
        }
    ));
    assert_eq!(web.standing(&locator), (Some(1), Some("owner")));
}

/// A write whose answer was lost is ended under the token the account holds now, because its
/// identity belongs to the collection and not to the token that sent it; and so is one a restart
/// left, from the record on the device's disk.
#[tokio::test]
async fn a_lost_write_is_ended_under_a_new_token_and_after_a_restart() {
    let owner = owner_with_a_writer().await;
    let Owner {
        web,
        sign_in,
        client,
        seed,
        locator,
        mut store,
        mut bundle,
        ..
    } = owner;

    web.lose_the_next_answer.store(true, Ordering::SeqCst);
    assert!(matches!(
        store
            .enable_writer(
                &seed,
                &mut bundle,
                trusted(&AuthorisationKeyPair::generate().expect("a writer key")),
                now()
            )
            .await,
        Err(RecoveryError::BundleOutcomeUnknown { .. })
    ));
    web.revoke("owner-write");
    web.issue("owner-write-2", "owner", &[BACKUP_WRITE_SCOPE]);
    sign_in.now_holds(Some("owner-write-2"));
    assert_eq!(
        store.end_lost_write(&seed).await.expect("ended"),
        Some(LostWrite::Applied)
    );
    assert_eq!(store.position().map(|at| at.write_sequence), Some(3));

    let mut bundle = store.fetch(&seed).await.expect("the bundle");
    web.lose_the_next_answer.store(true, Ordering::SeqCst);
    assert!(matches!(
        store
            .enable_writer(
                &seed,
                &mut bundle,
                trusted(&AuthorisationKeyPair::generate().expect("a key")),
                now()
            )
            .await,
        Err(RecoveryError::BundleOutcomeUnknown { .. })
    ));
    let mut store = store.restart(&client);
    assert!(matches!(
        store.lost_write(),
        Some(LostWrite::Unsettled { .. })
    ));
    web.revoke("owner-write-2");
    web.issue("owner-write-3", "owner", &[BACKUP_WRITE_SCOPE]);
    sign_in.now_holds(Some("owner-write-3"));
    assert_eq!(
        store
            .end_lost_write(&seed)
            .await
            .expect("ended after the restart"),
        Some(LostWrite::Applied)
    );
    let mut bundle = store.fetch(&seed).await.expect("the bundle");
    store
        .commit(&seed, &mut bundle, now())
        .await
        .expect("the next write goes out");
    assert_eq!(web.standing(&locator), (Some(5), Some("owner")));
}

/* -------------------------------------------------------------------------- */
/* What is refused before anything leaves                                      */
/* -------------------------------------------------------------------------- */

/// A bundle sealed past its bound is refused before anything is recorded or sent: the service is
/// never asked, the store records no write, and the next write goes out.
#[tokio::test]
async fn a_bundle_over_its_bound_is_refused_before_anything_is_recorded_or_sent() {
    let web = Web::open();
    web.issue("owner-write", "owner", &[BACKUP_WRITE_SCOPE]);
    let owner = client(&web, &SignIn::holding("owner-write"), BACKUP_WRITE_SCOPE);
    let locator = fresh_locator().expect("a locator");
    let seed = RecoverySeed::generate().expect("a seed");
    let mut store = store(&owner, at(ORIGIN, &locator));
    let mut bundle = BundleStore::empty(now());
    bundle.collections.push(CollectionLocator {
        service_origin: ORIGIN.to_owned(),
        locator: "x".repeat(usize::try_from(MAX_SEALED_RECOVERY_BUNDLE_BYTES).expect("a length")),
        archive_id: ArchiveId::new(identity(0x91)),
    });
    let before = bundle.clone();
    match store.commit(&seed, &mut bundle, now()).await {
        Err(RecoveryError::BundleTooLarge { len, limit }) => {
            assert!(len as u64 > limit);
            assert_eq!(limit, MAX_SEALED_RECOVERY_BUNDLE_BYTES);
        }
        other => panic!("refused before it was recorded: {other:?}"),
    }
    assert!(web.seen().is_empty(), "nothing was sent");
    assert_eq!(store.lost_write(), None);
    assert_eq!(store.record(), None, "nothing was recorded");
    assert_eq!(bundle, before, "the caller's bundle is as it was");

    bundle.collections.clear();
    store
        .commit(&seed, &mut bundle, now())
        .await
        .expect("the next write goes out");
}

/// A write refused on this device before anything left it, for want of an account token or for a
/// signing instant outside the service's window, is reported as not sent, leaves the store and its
/// record as the call found them, and the next write goes out. Over no record and over one.
#[tokio::test]
async fn a_write_refused_before_it_was_sent_leaves_the_store_as_it_was_and_the_next_write_goes_out()
{
    let web = Web::open();
    web.issue("owner-write", "owner", &[BACKUP_WRITE_SCOPE]);
    let sign_in = SignIn::signed_out();
    let owner = client(&web, &sign_in, BACKUP_WRITE_SCOPE);
    let locator = fresh_locator().expect("a locator");
    let seed = RecoverySeed::generate().expect("a seed");
    let mut store = store(&owner, at(ORIGIN, &locator));
    let mut bundle = BundleStore::empty(now());

    match store.commit(&seed, &mut bundle, now()).await {
        Err(RecoveryError::BundleNotSent { source }) => {
            assert_eq!(source.code(), ErrorCode::HostNotConfigured);
        }
        other => panic!("no token, nothing sent: {other:?}"),
    }
    assert!(web.seen().is_empty(), "nothing was sent");
    assert_eq!(store.lost_write(), None);
    assert_eq!(store.record(), None, "the store holds no record, as before");
    assert_eq!(bundle.revision.get(), 0);

    sign_in.now_holds(Some("owner-write"));
    store
        .commit(&seed, &mut bundle, now())
        .await
        .expect("the next write goes out");
    let answered = store.record().expect("the answered write's record");

    let stale = TimestampMs::new(now_ms() - 2 * SERVICE_REQUEST_FRESHNESS_MS);
    match store.commit(&seed, &mut bundle, stale).await {
        Err(RecoveryError::BundleNotSent { source }) => {
            assert_eq!(source.code(), ErrorCode::ClockUntrusted);
        }
        other => panic!("a stale instant, nothing sent: {other:?}"),
    }
    assert_eq!(web.members(), ["exchange"], "nothing more was sent");
    assert_eq!(store.lost_write(), None);
    assert_eq!(
        store.record(),
        Some(answered),
        "the record as the call found it"
    );
    assert_eq!(bundle.revision.get(), 1);
    store
        .commit(&seed, &mut bundle, now())
        .await
        .expect("the next write goes out");
    assert_eq!(web.standing(&locator), (Some(2), Some("owner")));
}

/// A migration whose write at the destination is refused before anything left reports that, and
/// leaves both locations and both stores as they were; made again with the destination's account
/// signed in, it completes.
#[tokio::test]
async fn a_migration_refused_before_it_was_sent_leaves_both_locations_as_they_were() {
    let owner = owner_with_a_writer().await;
    let Owner {
        web,
        seed,
        locator,
        mut store,
        mut bundle,
        ..
    } = owner;
    let destination_origin = "https://self-hosted.example";
    let destination_sign_in = SignIn::signed_out();
    let destination = client(&web, &destination_sign_in, BACKUP_WRITE_SCOPE);
    let moved_locator = fresh_locator().expect("a locator");
    let mut moved = self::store(&destination, at(destination_origin, &moved_locator));
    let kit = seed.to_kit(vec![ORIGIN.to_owned()], locator.clone());
    let source_at = store.position();

    match store
        .migrate(&seed, &mut bundle, &kit, &mut moved, now())
        .await
    {
        Err(RecoveryError::BundleNotSent { .. }) => {}
        other => panic!("the destination write was not sent: {other:?}"),
    }
    assert_eq!(store.position(), source_at);
    assert_eq!(moved.lost_write(), None);
    assert_eq!(moved.record(), None);
    assert_eq!(web.standing(&moved_locator), (None, None));
    assert_eq!(bundle.revision.get(), 2);

    destination_sign_in.now_holds(Some("owner-write"));
    let migrated = store
        .migrate(&seed, &mut bundle, &kit, &mut moved, now())
        .await
        .expect("the migration completes");
    assert_eq!(migrated.updated_kit.bundle_locator, moved_locator);
    assert_eq!(web.standing(&moved_locator), (Some(1), Some("owner")));
}

/// A request the service may have received is never reported as not sent: a fault from something
/// in front of the service, with no envelope, leaves the write unknown and the store refusing to
/// write until the write is ended.
#[tokio::test]
async fn a_fault_after_the_request_left_leaves_the_write_unknown() {
    let owner = owner_with_a_writer().await;
    let Owner {
        web,
        seed,
        mut store,
        mut bundle,
        ..
    } = owner;
    web.fault_the_next_exchange.store(true, Ordering::SeqCst);
    match store.commit(&seed, &mut bundle, now()).await {
        Err(RecoveryError::BundleOutcomeUnknown { source, .. }) => {
            assert_eq!(source.code(), ErrorCode::UpstreamUnavailable);
        }
        other => panic!("sent, and unknown: {other:?}"),
    }
    assert!(matches!(
        store.lost_write(),
        Some(LostWrite::Unsettled { .. })
    ));
    assert!(matches!(
        store.commit(&seed, &mut bundle, now()).await,
        Err(RecoveryError::BundleWriteUnsettled { .. })
    ));
    assert_eq!(
        store.end_lost_write(&seed).await.expect("ended"),
        Some(LostWrite::Applied),
        "the fault came after the write ran"
    );
}

/// An answer about a bundle write names no copy in any state: a write answered as applied and
/// naming a copy beside it is an answer about something else, and an unknown outcome, where the
/// same answer naming none is read as it always is.
#[tokio::test]
async fn a_bundle_write_answered_as_applied_with_a_copy_is_not_an_answer_this_client_reads() {
    let owner = owner_with_a_writer().await;
    let collection = bundle_collection(&at(ORIGIN, &owner.locator));
    let key = owner
        .seed
        .bundle_key_for(&at(ORIGIN, &owner.locator))
        .expect("a key");
    let sealed = kr_crypto::archive::encrypt_recovery_bundle(&key, &owner.bundle).expect("sealed");
    let at_two = owner.store.position();

    owner
        .web
        .names_a_copy_on_writes
        .store(true, Ordering::SeqCst);
    let refused = owner
        .client
        .compare_exchange(&collection, identity(0xd3), now_ms(), at_two, &sealed)
        .await
        .expect_err("applied, and a copy beside it");
    assert_eq!(refused.code(), ErrorCode::OutcomeUnknown);

    owner
        .web
        .names_a_copy_on_writes
        .store(false, Ordering::SeqCst);
    let at_three = owner
        .client
        .compare_exchange(&collection, identity(0xd4), now_ms(), None, &sealed)
        .await;
    assert!(
        matches!(at_three, Ok(SyncExchanged::Refused { retained: None, .. })),
        "the same kind of answer naming no copy is read: {at_three:?}"
    );
    // Read on its own, so the service's lock is released before the write asks for it.
    let third: SyncRevision = {
        let collections = owner.web.collections.lock().expect("the collections");
        let kept = collections[&owner.locator]
            .kept
            .as_ref()
            .expect("the bundle");
        SyncRevision::new(kept.revision.parse().expect("a revision"))
    };
    let applied = owner
        .client
        .compare_exchange(
            &collection,
            identity(0xd5),
            now_ms(),
            Some(SyncPosition::at(3, third, None)),
            &sealed,
        )
        .await
        .expect("the write applied");
    assert!(
        matches!(applied, SyncExchanged::Applied { position } if position.write_sequence == 4),
        "{applied:?}"
    );
}

/// Where a device's account token comes from while a refresh is in flight: it waits until the test
/// lets it through.
#[derive(Debug)]
struct Refreshing {
    through: tokio::sync::Semaphore,
}

impl AccountTokenSource for Refreshing {
    fn token<'a>(&'a self, _scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        Box::pin(async move {
            self.through
                .acquire()
                .await
                .expect("the source stays open")
                .forget();
            AccountToken::new("owner-write")
        })
    }
}

/// Two writes in flight at once each say whether their own request left. One waits for its token,
/// as a refresh makes it wait, while the other's request leaves and its answer is lost; the waiting
/// one is then refused here, its instant out of the service's window, and reaches the service not at
/// all. The one refused here is not sent and leaves its store as it was; the lost one may have run
/// and stays outstanding.
#[tokio::test]
async fn two_writes_in_flight_at_once_each_say_whether_their_own_request_left() {
    let web = Web::open();
    web.issue("owner-write", "owner", &[BACKUP_WRITE_SCOPE]);
    let refreshing = Arc::new(Refreshing {
        through: tokio::sync::Semaphore::new(0),
    });
    let waiting = Arc::new(unsigned_client(&web).presenting(
        Arc::clone(&refreshing) as Arc<dyn AccountTokenSource>,
        BACKUP_WRITE_SCOPE,
    ));
    let answering = client(&web, &SignIn::holding("owner-write"), BACKUP_WRITE_SCOPE);
    let seed = RecoverySeed::generate().expect("a seed");
    let mut first = store(&waiting, at(ORIGIN, &fresh_locator().expect("a locator")));
    let mut second = store(&answering, at(ORIGIN, &fresh_locator().expect("a locator")));
    let (mut one, mut two) = (BundleStore::empty(now()), BundleStore::empty(now()));
    web.lose_the_next_answer.store(true, Ordering::SeqCst);
    let stale = TimestampMs::new(now_ms() - 2 * SERVICE_REQUEST_FRESHNESS_MS);
    let meanwhile = async {
        let lost = second.commit(&seed, &mut two, now()).await;
        assert_eq!(
            web.members(),
            ["exchange"],
            "the write waiting for its token has sent nothing"
        );
        refreshing.through.add_permits(1);
        lost
    };
    let (refused, lost) = tokio::join!(first.commit(&seed, &mut one, stale), meanwhile);
    match refused {
        Err(RecoveryError::BundleNotSent { source }) => {
            assert_eq!(source.code(), ErrorCode::ClockUntrusted);
        }
        other => panic!("refused here once its token came: {other:?}"),
    }
    assert!(
        matches!(lost, Err(RecoveryError::BundleOutcomeUnknown { .. })),
        "{lost:?}"
    );
    assert_eq!(
        web.members(),
        ["exchange"],
        "only the lost write reached the service"
    );
    assert_eq!(first.lost_write(), None);
    assert!(matches!(
        second.lost_write(),
        Some(LostWrite::Unsettled { .. })
    ));
}

/// A service keeps no copy of a refused bundle write, so a status query or a fence about one whose
/// answer names a copy is an answer about something else, and an unknown outcome; the same answers
/// naming none are read as the refusal they are.
#[tokio::test]
async fn a_bundle_receipt_that_names_a_copy_is_not_an_answer_this_client_reads() {
    let owner = owner_with_a_writer().await;
    let collection = bundle_collection(&at(ORIGIN, &owner.locator));
    let key = owner
        .seed
        .bundle_key_for(&at(ORIGIN, &owner.locator))
        .expect("a key");
    let sealed = kr_crypto::archive::encrypt_recovery_bundle(&key, &owner.bundle).expect("sealed");
    let refused_write = identity(0xd1);
    let refused = owner
        .client
        .compare_exchange(&collection, refused_write, now_ms(), None, &sealed)
        .await
        .expect("an answer");
    assert!(matches!(
        refused,
        SyncExchanged::Refused { retained: None, .. }
    ));
    assert!(matches!(
        owner
            .client
            .request_status(&collection, refused_write)
            .await
            .expect("a receipt"),
        SyncRequestStatus::Refused { retained: None, .. }
    ));
    assert!(matches!(
        owner
            .client
            .fence_request(&collection, refused_write, now_ms(), now_ms())
            .await
            .expect("a receipt"),
        SyncRequestFence::Refused { retained: None, .. }
    ));

    owner
        .web
        .names_copies_in_receipts
        .store(true, Ordering::SeqCst);
    assert_eq!(
        owner
            .client
            .request_status(&collection, refused_write)
            .await
            .expect_err("a copy no service keeps")
            .code(),
        ErrorCode::OutcomeUnknown
    );
    assert_eq!(
        owner
            .client
            .fence_request(&collection, refused_write, now_ms(), now_ms())
            .await
            .expect_err("a copy no service keeps")
            .code(),
        ErrorCode::OutcomeUnknown
    );
}

/// A locator the service cannot address, and a request the bundle's contract does not have, are
/// refused before anything leaves: a locator that is not a canonical identifier, a resolution of a
/// copy the bundle never keeps, and a bundle named where a collection's object is.
#[tokio::test]
async fn a_bundle_request_the_service_cannot_take_never_leaves_this_device() {
    let web = Web::open();
    web.issue("owner-write", "owner", &[BACKUP_WRITE_SCOPE]);
    let owner = client(&web, &SignIn::holding("owner-write"), BACKUP_WRITE_SCOPE);
    let seed = RecoverySeed::generate().expect("a seed");
    let locator = fresh_locator().expect("a locator");
    for unaddressable in [
        format!("kr-recovery-{locator}"),
        locator.to_uppercase(),
        String::new(),
    ] {
        let mut store = store(&owner, at(ORIGIN, &unaddressable));
        match store
            .commit(&seed, &mut BundleStore::empty(now()), now())
            .await
        {
            Err(RecoveryError::BundleNotSent { source }) => {
                assert_eq!(source.code(), ErrorCode::InvalidArgument, "{unaddressable}");
            }
            other => panic!("{unaddressable} is not sent: {other:?}"),
        }
        assert_eq!(store.lost_write(), None);
    }
    let collection = bundle_collection(&at(ORIGIN, &locator));
    assert_eq!(
        owner
            .resolve(&collection, SyncConflictId::new(identity(0xa1)))
            .await
            .expect_err("a bundle keeps no copies")
            .code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        owner
            .compare(&collection, false, None)
            .await
            .expect_err("a bundle is read by a fetch")
            .code(),
        ErrorCode::InvalidArgument
    );
    let shared = crate::sync::membership::CollectionRef {
        home: InstallationId::new(identity(0xa2)),
        collection_id: SyncCollectionId::new(identity(0xa3)),
    };
    // A real sealed object, so the only thing wrong with the request is where it points.
    assert_eq!(
        owner
            .exchange_shared(
                &shared,
                &collection,
                0,
                identity(0xa4),
                now_ms(),
                None,
                &published(&sealed(b"a setting")),
            )
            .await
            .expect_err("a bundle is never a shared collection's object")
            .code(),
        ErrorCode::InvalidArgument
    );
    assert!(web.seen().is_empty(), "nothing was sent");
}

/// The bundle's history is the collection's: a service put back from an archive that held no
/// bundle names its new history, which a store that read the bundle refuses as a bundle put back,
/// and a restore reads as a locator that holds nothing.
#[tokio::test]
async fn a_service_put_back_without_the_bundle_is_refused_as_a_bundle_put_back() {
    let owner = owner_with_a_writer().await;
    let Owner {
        web,
        seed,
        locator,
        mut store,
        ..
    } = owner;
    let recovery = identity(0xc1);
    web.put_back_without_bundles(recovery);
    match store.fetch(&seed).await {
        Err(RecoveryError::BundlePutBackEmpty {
            expected,
            recovery: found,
        }) => {
            assert_eq!(expected.write_sequence, 2);
            assert_eq!(found, Some(SyncRecoveryId::new(recovery)));
        }
        other => panic!("a bundle put back empty: {other:?}"),
    }
    web.issue("owner-restore", "owner", &[BACKUP_RESTORE_SCOPE]);
    let reader = client(
        &web,
        &SignIn::holding("owner-restore"),
        BACKUP_RESTORE_SCOPE,
    );
    let kit = kept(&seed.to_kit(vec![ORIGIN.to_owned()], locator));
    match restore_with(kit, ORIGIN, reader).open_bundle(ORIGIN).await {
        Err(RecoveryError::Service(error)) => assert_eq!(error.code(), ErrorCode::UnknownSession),
        other => panic!("nothing held there: {other:?}"),
    }
}

/// A write signed before the collection's cutoff runs nothing, and the store holds it as a write
/// that did not settle, as it holds one never answered.
#[tokio::test]
async fn a_write_signed_before_the_cutoff_is_held_as_unsettled() {
    let owner = owner_with_a_writer().await;
    let Owner {
        web,
        seed,
        locator,
        mut store,
        mut bundle,
        ..
    } = owner;
    web.cut_off(&locator, now_ms() + 60_000);
    assert!(matches!(
        store.commit(&seed, &mut bundle, now()).await,
        Err(RecoveryError::BundleOutcomeUnknown { .. })
    ));
    assert!(matches!(
        store.lost_write(),
        Some(LostWrite::Unsettled { .. })
    ));
    assert_eq!(web.standing(&locator), (Some(2), Some("owner")));
}

/// A bundle write says what became of it in this program's words and nothing it carried or was
/// answered: not the stream, which a refusal before anything is sent names by its length; not the
/// account token that travels beside every request; and not what a service wrote in refusing a
/// write as signed before its cutoff, which the store holds as unsettled in words of its own.
#[tokio::test]
async fn a_bundle_write_says_nothing_of_its_stream_its_token_or_the_services_words() {
    use crate::shown::marker::{MARKER, assert_unmarked, failure_renderings};
    use kr_protocol::sync::MIN_SEALED_RECOVERY_BUNDLE_BYTES;

    let marked = |length: usize| -> Vec<u8> { MARKER.bytes().cycle().take(length).collect() };
    let web = Web::open();
    web.issue(MARKER, "owner", &[BACKUP_WRITE_SCOPE]);
    let sign_in = SignIn::holding(MARKER);
    let owner = client(&web, &sign_in, BACKUP_WRITE_SCOPE);
    let locator = fresh_locator().expect("a locator");
    let collection = bundle_collection(&at(ORIGIN, &locator));

    // A stream a service does not keep, too short and too long: the negative control is the
    // stream, which holds the marker; the neutral control is the rule it broke, with its lengths.
    let shortest = usize::try_from(MIN_SEALED_RECOVERY_BUNDLE_BYTES).expect("a length");
    let longest = usize::try_from(MAX_SEALED_RECOVERY_BUNDLE_BYTES).expect("a length");
    for (stream, rule) in [
        (
            marked(shortest - 1),
            format!(
                "at least {MIN_SEALED_RECOVERY_BUNDLE_BYTES} bytes; this one is {}",
                shortest - 1
            ),
        ),
        (
            marked(longest + 1),
            format!(
                "at most {MAX_SEALED_RECOVERY_BUNDLE_BYTES} bytes; this one is {}",
                longest + 1
            ),
        ),
    ] {
        assert!(
            stream
                .windows(MARKER.len())
                .any(|window| window == MARKER.as_bytes())
        );
        let dispatched = owner
            .compare_exchange_dispatched(&collection, identity(0xd1), now_ms(), None, &stream)
            .await
            .expect("an account of the request");
        let SyncDispatch::NotSent(refused) = dispatched else {
            panic!("a stream no service keeps is not sent: {dispatched:?}");
        };
        let said = refused.to_string();
        assert_eq!(
            said,
            format!(
                "INVALID_ARGUMENT: that recovery bundle is not one a service admits: a sealed \
                 recovery bundle is {rule}"
            )
        );
        assert_unmarked("a stream no service keeps", &failure_renderings(refused));
    }

    // A client that presents no account refuses the write in its own words.
    let dispatched = unsigned_client(&web)
        .compare_exchange_dispatched(&collection, identity(0xd2), now_ms(), None, &marked(140))
        .await
        .expect("an account of the request");
    let SyncDispatch::NotSent(refused) = dispatched else {
        panic!("a bundle write with no account is not sent: {dispatched:?}");
    };
    assert_eq!(
        refused.to_string(),
        "HOST_NOT_CONFIGURED: a recovery bundle is reached with an account token, and this client \
         presents no account"
    );
    assert_unmarked(
        "a bundle write with no account",
        &failure_renderings(refused),
    );
    assert!(web.seen().is_empty(), "nothing was sent");

    // A write the service holds as signed before its cutoff, refused with the marker as its words.
    let seed = RecoverySeed::generate().expect("a seed");
    let mut store = store(&owner, at(ORIGIN, &locator));
    let mut bundle = BundleStore::empty(now());
    store
        .commit(&seed, &mut bundle, now())
        .await
        .expect("the first bundle");
    web.cut_off_saying(&locator, now_ms() + 60_000, MARKER);
    let unsettled = store
        .commit(&seed, &mut bundle, now())
        .await
        .expect_err("a write signed before the cutoff");
    assert!(
        matches!(unsettled, RecoveryError::BundleOutcomeUnknown { .. }),
        "{unsettled:?}"
    );
    assert!(
        unsettled
            .to_string()
            .contains("the service refused the write as signed before its cutoff, and ran nothing"),
        "{unsettled}"
    );
    assert_unmarked(
        "a write signed before the cutoff",
        &failure_renderings(unsettled),
    );
    // The negative control for the token: it travelled beside every request that was sent.
    let seen = web.seen();
    assert!(!seen.is_empty());
    for request in &seen {
        assert_eq!(
            request.authorization.as_deref(),
            Some(format!("Bearer {MARKER}").as_str())
        );
    }
}

#[test]
fn a_rendering_of_a_bundle_request_carries_nothing_sealed() {
    let object = SealedRecoveryBundle {
        ciphertext: Bytes::new(NEVER_RENDERED.as_bytes().to_vec()),
    };
    renders_only(
        &BundleExchangeBody {
            request_id: identity(1),
            locator: identity(2),
            kind: SyncObjectKind::RecoveryBundle,
            expected_revision: Some(revision(3)),
            object: &object,
        },
        &format!(
            "BundleExchangeBody{{kind:RecoveryBundle,ciphertext_bytes:{},expects_a_bundle:true,..}}",
            NEVER_RENDERED.len()
        ),
    );
}
