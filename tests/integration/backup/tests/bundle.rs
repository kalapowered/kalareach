//! The recovery bundle, against a service this repository does not stand in for.
//!
//! Section 20: the recovery kit carries the seed, each configured service origin and a stable
//! locator; a fresh restore reaches the service through its retrieval policy and then authenticates
//! the bundle with the kit, and a substituted origin or locator fails authentication rather than
//! bringing in a writer key from somewhere else. The recovery module's own suite proves that
//! against a service written for it, which stores any bytes under any name. These legs prove it
//! against the web service, through the same client every other managed call uses.
//!
//! The bundle belongs to an account. The device that writes it presents the account's
//! `backup.write` token beside its signature; the device that reads it is not the device that wrote
//! it but a new installation, with a key of its own, the printed kit and a token the same account
//! issued for the restore alone, `backup.restore`, which is what a device restoring from the kit
//! is. The run's token file names both for each origin ([`kr_backup_integration::TOKENS_VARIABLE`]).
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-ACC-033, KR-REQ-20.15, KR-REQ-20.18 and KR-REQ-20.19 against a service | `a_bundle_is_found_and_authenticated_with_only_the_kit_and_its_origin` |
//! | KR-REQ-20.18 several services, KR-REQ-20.19 a lost service | `a_kit_naming_two_services_reads_the_bundle_at_either`, then, once the first service is gone, `with_one_service_gone_the_same_kit_still_reads_at_the_other` |
//!
//! # What they leave
//!
//! Against a deployment: the bundle collection at the run's locator, owned by the account whose
//! tokens the run was given, and the receipts and spent nonces the service keeps by its own rules.
//! No client operation removes a bundle, because a bundle is the only thing a restore takes a writer
//! key from. Every key that signed is discarded with the run.

use std::sync::Arc;

use kr_backup_integration::{
    RunDirectory, TOKENS_VARIABLE, Watched, account_tokens, skipped, variable,
};
use kr_client::recovery::{
    BundleStore, FreshRestore, RecoveryError, RetrievalPolicy, ServiceAccess, bundle_collection,
    fresh_locator, parse_kit, render_kit,
};
use kr_client::services::account::{AccountTokenSource, BACKUP_RESTORE_SCOPE, BACKUP_WRITE_SCOPE};
use kr_client::services::relay::{ServiceHttp, ServiceSigner};
use kr_client::services::sync::ManagedSyncService;
use kr_client::services::{
    ServiceFuture, SyncBackupService, SyncExchanged, SyncFetched, SyncPosition, SyncRequestFence,
    SyncRequestStatus,
};
use kr_crypto::kdf::RecoverySeed;
use kr_protocol::archive::{RecoveryContext, RecoveryKit, TrustedWriter};
use kr_protocol::ids::SyncConflictId;
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_protocol::service::GatewayOrigin;
use kr_sync_integration::{Deployment, RunKey, now_ms, proved};

/// The variable naming the second local service a kit may name.
const SECOND_VARIABLE: &str = "KR_BACKUP_SECOND_ORIGIN";
/// The variable naming the directory the two-service leg keeps its printed kit in between phases.
const RUN_VARIABLE: &str = "KR_BACKUP_RUN_DIR";
/// The file that printed kit is kept in.
const KIT: &str = "kit.json";

fn now() -> TimestampMs {
    TimestampMs::new(now_ms())
}

/// A locator made for the run, as a new kit's is: a random identifier nobody else holds.
fn locator() -> String {
    fresh_locator().expect("a locator")
}

/// One installation's client at one service, presenting `tokens`' account token for `scope` with
/// every request about the bundle, over a transport that holds every answer to naming no history.
fn client_at(
    deployment: &Deployment,
    who: &Arc<RunKey>,
    tokens: &Arc<dyn AccountTokenSource>,
    scope: &'static str,
) -> (Arc<ManagedSyncService>, Arc<Watched>) {
    let transport = Watched::new(deployment.transport(), None);
    let service = Arc::new(
        ManagedSyncService::new(
            deployment.origin().clone(),
            Arc::clone(&transport) as Arc<dyn ServiceHttp>,
            Arc::clone(who) as Arc<dyn ServiceSigner>,
        )
        .presenting(Arc::clone(tokens), scope),
    );
    (service, transport)
}

/// The kit as a person keeps it: printed, then read back from the page.
fn kept(kit: &RecoveryKit) -> RecoveryKit {
    parse_kit(&render_kit(kit).expect("a printable kit")).expect("the kit reads back")
}

/// Stops a leg at a write that did not land, saying whether anything was sent at all.
fn blocked(what: &str, origin: &str, transport: &Watched, error: &RecoveryError) -> ! {
    let sent = if transport.sent().is_empty() {
        "nothing was sent"
    } else {
        "the request was sent"
    };
    panic!("blocked: {what} at {origin} ({sent}), so nothing after it ran: {error}");
}

/// A service that answers for one collection with what it holds at another.
///
/// It is the substitution section 20 ¶13 names: the bytes are real, written by the owner and
/// served by the service, and only the place they are served from is wrong.
#[derive(Debug)]
struct Substituting {
    inner: Arc<dyn SyncBackupService>,
    asked: String,
    served: String,
}

impl Substituting {
    fn collection<'a>(&'a self, collection: &'a str) -> &'a str {
        if collection == self.asked {
            &self.served
        } else {
            collection
        }
    }
}

impl SyncBackupService for Substituting {
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        self.inner.compare_exchange(
            self.collection(collection),
            request_id,
            signed_at_ms,
            expected,
            ciphertext,
        )
    }

    fn request_status<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        self.inner
            .request_status(self.collection(collection), request_id)
    }

    fn fence_request<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        first_signed_at_ms: u64,
        last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        self.inner.fence_request(
            self.collection(collection),
            request_id,
            first_signed_at_ms,
            last_signed_at_ms,
        )
    }

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, SyncFetched> {
        self.inner.fetch(self.collection(collection))
    }

    fn resolve<'a>(
        &'a self,
        collection: &'a str,
        retained: SyncConflictId,
    ) -> ServiceFuture<'a, bool> {
        self.inner.resolve(self.collection(collection), retained)
    }
}

/// A restore from `kit` whose retrieval policy, the owner's account, gave it `reader` at `origin`.
fn restore_with(
    kit: RecoveryKit,
    origin: &str,
    reader: Arc<dyn SyncBackupService>,
) -> FreshRestore {
    let mut restore = FreshRestore::new(kit, RetrievalPolicy::Account);
    restore
        .obtained_access(ServiceAccess::new(RetrievalPolicy::Account, origin, reader))
        .expect("the kit names that origin");
    restore
}

/// The collection a kit's bundle is kept in at one origin.
fn collection_of(origin: &str, locator: &str) -> String {
    bundle_collection(&RecoveryContext {
        service_origin: origin.to_owned(),
        bundle_locator: locator.to_owned(),
    })
}

/// KR-ACC-033 against a service: a bundle written at a stable locator is found and authenticated by
/// a new installation holding only the kit, the origin and the account's token for the restore; the
/// same bytes served under another locator or from another origin fail authentication and bring in
/// no writer; a kit of another seed fails too; and a writer enabled by compare and swap at the same
/// locator is read with the same kit.
#[tokio::test]
async fn a_bundle_is_found_and_authenticated_with_only_the_kit_and_its_origin() {
    let Some(deployment) = Deployment::from_environment() else {
        return;
    };
    let origin = deployment.origin().as_str().to_owned();
    let Some(tokens) = account_tokens(&origin) else {
        skipped(TOKENS_VARIABLE);
        return;
    };
    let directory = tempfile::tempdir().expect("a directory for the stores");

    // The owner's device: a fresh installation, a fresh seed, and a locator made for the run.
    let owner = RunKey::installation();
    let (owner_service, owner_transport) =
        client_at(&deployment, &owner, &tokens.write, BACKUP_WRITE_SCOPE);
    let seed = RecoverySeed::generate().expect("a seed");
    let locator = locator();
    let kit = seed.to_kit(vec![origin.clone()], locator.clone());
    std::fs::create_dir_all(directory.path().join("owner")).expect("a directory");
    let mut store = BundleStore::open(
        Arc::clone(&owner_service) as Arc<dyn SyncBackupService>,
        kit.context(&origin).expect("the kit names the origin"),
        &directory.path().join("owner"),
    )
    .expect("the owner's bundle store");
    let mut bundle = BundleStore::empty(now());
    let written = match store.commit(&seed, &mut bundle, now()).await {
        Ok(position) => position,
        Err(error) => blocked(
            "the recovery bundle could not be written",
            &origin,
            &owner_transport,
            &error,
        ),
    };
    assert_eq!((written.write_sequence, written.recovery()), (1, None));

    // A new installation, holding the printed kit and the account's token for the restore and
    // nothing else, reaches the service through that access and authenticates the bundle with the
    // kit.
    let reader = RunKey::installation();
    let (reader_service, reader_transport) =
        client_at(&deployment, &reader, &tokens.restore, BACKUP_RESTORE_SCOPE);
    let reader_service = reader_service as Arc<dyn SyncBackupService>;
    let found = restore_with(kept(&kit), &origin, Arc::clone(&reader_service))
        .open_bundle(&origin)
        .await
        .expect("the bundle is found and authenticated with only the kit");
    assert_eq!(found.bundle_revision, 1);
    assert!(
        found.trusted_writers.is_empty(),
        "the first bundle trusts no writer yet"
    );

    // The same bytes, served under another locator: the kit naming that locator does not open
    // them, and nothing is trusted.
    let elsewhere = self::locator();
    let substituted = Arc::new(Substituting {
        inner: Arc::clone(&reader_service),
        asked: collection_of(&origin, &elsewhere),
        served: collection_of(&origin, &locator),
    }) as Arc<dyn SyncBackupService>;
    let moved_kit = seed.to_kit(vec![origin.clone()], elsewhere);
    assert!(matches!(
        restore_with(kept(&moved_kit), &origin, substituted)
            .open_bundle(&origin)
            .await,
        Err(RecoveryError::BundleNotAuthentic)
    ));

    // The same bytes, served as another origin's: a kit naming that origin does not open them.
    let other_origin = "https://recovery-substitute.invalid";
    let other_kit = seed.to_kit(vec![other_origin.to_owned()], locator.clone());
    assert!(matches!(
        restore_with(kept(&other_kit), other_origin, Arc::clone(&reader_service))
            .open_bundle(other_origin)
            .await,
        Err(RecoveryError::BundleNotAuthentic)
    ));

    // A kit of another seed, naming this very origin and locator, does not open them either.
    let stranger = RecoverySeed::generate()
        .expect("a seed")
        .to_kit(vec![origin.clone()], locator.clone());
    assert!(matches!(
        restore_with(kept(&stranger), &origin, Arc::clone(&reader_service))
            .open_bundle(&origin)
            .await,
        Err(RecoveryError::BundleNotAuthentic)
    ));

    // The owner enables a writer: the bundle moves on at the same locator by compare and swap,
    // and the writer is declared only once that write has landed.
    let writer = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a writer key");
    let enabled = store
        .enable_writer(
            &seed,
            &mut bundle,
            TrustedWriter {
                writer_key_id: writer.key_id(),
                signing_key: *writer.public(),
                enrolled_at_ms: now(),
            },
            now(),
        )
        .await
        .expect("the writer's bundle landed");
    assert_eq!(enabled.bundle_revision(), 2);
    assert_eq!(
        (
            enabled.bundle_position().write_sequence,
            enabled.bundle_position().recovery()
        ),
        (2, None)
    );

    // The same kit reads the bundle as it now stands, writer and all, from a store that holds
    // nothing but the kit, the origin and the restore's access.
    let reading_directory = directory.path().join("reader");
    std::fs::create_dir_all(&reading_directory).expect("a directory");
    let mut reading = BundleStore::open(
        Arc::clone(&reader_service),
        kept(&kit)
            .context(&origin)
            .expect("the kit names the origin"),
        &reading_directory,
    )
    .expect("a store that knows nothing");
    let read = reading
        .fetch(&RecoverySeed::from_kit(&kept(&kit)).expect("the kit's seed"))
        .await
        .expect("the updated bundle");
    assert_eq!(read.revision.get(), 2);
    assert!(
        read.trusted_writers
            .iter()
            .any(|trusted| trusted.writer_key_id == writer.key_id()),
        "the writer is in the bundle the kit opens"
    );
    assert_eq!(
        reading.position().map(|position| position.recovery()),
        Some(None)
    );

    owner_transport.assert_every_answer_named_its_history();
    reader_transport.assert_every_answer_named_its_history();
    proved(
        "bundle",
        &deployment,
        "a new installation with only the printed kit and a token for the restore found and authenticated the bundle and read the writer a compare and swap added; another locator, another origin and another seed's kit all failed authentication; every answer named no history",
    );
}

/// The two services a leg over several services runs against, the account tokens the run holds at
/// each, and the directory it keeps the printed kit in between its phases.
fn two_services() -> Option<(
    Deployment,
    Deployment,
    RunDirectory,
    [kr_backup_integration::AccountTokens; 2],
)> {
    let first = Deployment::from_environment()?;
    let Some(second) = variable(SECOND_VARIABLE) else {
        skipped(SECOND_VARIABLE);
        return None;
    };
    let Some(run) = RunDirectory::from_variable(RUN_VARIABLE) else {
        skipped(RUN_VARIABLE);
        return None;
    };
    let second = Deployment::at(GatewayOrigin::new(second).expect("an origin"));
    let (Some(at_first), Some(at_second)) = (
        account_tokens(first.origin().as_str()),
        account_tokens(second.origin().as_str()),
    ) else {
        skipped(TOKENS_VARIABLE);
        return None;
    };
    Some((first, second, run, [at_first, at_second]))
}

/// KR-REQ-20.18 against two services, first phase: a kit naming both reads the bundle at either.
/// The phase keeps the printed kit for the next one, which runs once the first service is gone.
#[tokio::test]
async fn a_kit_naming_two_services_reads_the_bundle_at_either() {
    let Some((first, second, run, tokens)) = two_services() else {
        return;
    };
    let origins = [
        first.origin().as_str().to_owned(),
        second.origin().as_str().to_owned(),
    ];

    let owner = RunKey::installation();
    let seed = RecoverySeed::generate().expect("a seed");
    let kit = seed.to_kit(origins.to_vec(), locator());
    let mut transports = Vec::new();
    for (index, (deployment, tokens)) in [&first, &second].into_iter().zip(&tokens).enumerate() {
        let origin = deployment.origin().as_str().to_owned();
        let (service, transport) = client_at(deployment, &owner, &tokens.write, BACKUP_WRITE_SCOPE);
        let path = run.path(&format!("owner-{index}"));
        std::fs::create_dir_all(&path).expect("a directory");
        let mut store = BundleStore::open(
            service as Arc<dyn SyncBackupService>,
            kit.context(&origin).expect("the kit names the origin"),
            &path,
        )
        .expect("the owner's bundle store");
        let mut bundle = BundleStore::empty(now());
        if let Err(error) = store.commit(&seed, &mut bundle, now()).await {
            blocked(
                "the recovery bundle could not be written",
                &origin,
                &transport,
                &error,
            );
        }
        transports.push(transport);
    }

    // A new installation with the printed kit and a token for the restore reads the bundle at each
    // service it names.
    let reader = RunKey::installation();
    for (deployment, tokens) in [&first, &second].into_iter().zip(&tokens) {
        let origin = deployment.origin().as_str().to_owned();
        let (service, transport) =
            client_at(deployment, &reader, &tokens.restore, BACKUP_RESTORE_SCOPE);
        let found = restore_with(kept(&kit), &origin, service as Arc<dyn SyncBackupService>)
            .open_bundle(&origin)
            .await
            .expect("the bundle at that service");
        assert_eq!(found.bundle_revision, 1);
        assert_eq!(found.context.service_origin, origin);
        transports.push(transport);
    }
    for transport in &transports {
        transport.assert_every_answer_named_its_history();
    }
    let printed = render_kit(&kit).expect("a printable kit");
    run.write(KIT, &serde_json::json!({ "kit": printed.as_str() }));
    proved(
        "bundle",
        &first,
        "a kit naming two services read the bundle at each",
    );
}

/// KR-REQ-20.19 against two services, second phase, once the first service is gone: the same printed
/// kit still reads the bundle at the service that is left, and a kit naming only the one that is
/// gone reads nothing, since a seed alone rebuilds no service.
#[tokio::test]
async fn with_one_service_gone_the_same_kit_still_reads_at_the_other() {
    let Some((first, second, run, tokens)) = two_services() else {
        return;
    };
    let [at_first, at_second] = tokens;
    let printed = run.read(KIT);
    let kit = parse_kit(printed["kit"].as_str().expect("the printed kit")).expect("a kit");
    let gone = first.origin().as_str().to_owned();
    let left = second.origin().as_str().to_owned();

    let reader = RunKey::installation();
    let (gone_service, _) = client_at(&first, &reader, &at_first.restore, BACKUP_RESTORE_SCOPE);
    assert!(
        matches!(
            restore_with(
                kit.clone(),
                &gone,
                gone_service as Arc<dyn SyncBackupService>
            )
            .open_bundle(&gone)
            .await,
            Err(RecoveryError::Service(_))
        ),
        "the service that is gone gives nothing back"
    );
    let (left_service, transport) =
        client_at(&second, &reader, &at_second.restore, BACKUP_RESTORE_SCOPE);
    let found = restore_with(
        kit.clone(),
        &left,
        left_service as Arc<dyn SyncBackupService>,
    )
    .open_bundle(&left)
    .await
    .expect("the service that is left still serves the bundle");
    assert_eq!(found.bundle_revision, 1);
    transport.assert_every_answer_named_its_history();

    let seed = RecoverySeed::from_kit(&kit).expect("the kit's seed");
    let only_gone = seed.to_kit(vec![gone.clone()], kit.bundle_locator.clone());
    let (gone_service, _) = client_at(&first, &reader, &at_first.restore, BACKUP_RESTORE_SCOPE);
    assert!(matches!(
        restore_with(
            kept(&only_gone),
            &gone,
            gone_service as Arc<dyn SyncBackupService>
        )
        .open_bundle(&gone)
        .await,
        Err(RecoveryError::Service(_))
    ));
    proved(
        "bundle",
        &second,
        "with one service gone, the same printed kit read the bundle at the other, and a kit naming only the one that is gone read nothing",
    );
}
