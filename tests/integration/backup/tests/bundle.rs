//! The recovery bundle, against a service this repository does not stand in for.
//!
//! Section 20: the recovery kit carries the seed, each configured service origin and a stable
//! locator; a fresh restore reaches the service through its retrieval policy and then authenticates
//! the bundle with the kit, and a substituted origin or locator fails authentication rather than
//! bringing in a writer key from somewhere else. The recovery module's own suite proves that
//! against a service written for it, which stores any bytes under any name. These legs prove it
//! against the web service, through the same client every other managed call uses.
//!
//! The device that reads the bundle is not the device that wrote it. It is a new installation,
//! with a key of its own and the printed kit, which is what a device restoring from the kit is.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-ACC-033, KR-REQ-20.15, KR-REQ-20.18 and KR-REQ-20.19 against a service | `a_bundle_is_found_and_authenticated_with_only_the_kit_and_its_origin` |
//! | KR-REQ-20.18 several services, KR-REQ-20.19 a lost service | `a_kit_naming_two_services_reads_the_bundle_at_either` |
//!
//! # What they leave
//!
//! Against a deployment: the bundle collection under the run's locator, in the writing
//! installation's namespace, with the receipts and spent nonces the service keeps by its own rules.
//! No client operation removes a bundle, because a bundle is the only thing a restore takes a writer
//! key from. The key that wrote it is discarded with the run.

use std::sync::Arc;

use kr_backup_integration::{Watched, skipped, variable};
use kr_client::recovery::{
    BundleStore, FreshRestore, RecoveryError, RetrievalPolicy, ServiceAccess, parse_kit, render_kit,
};
use kr_client::services::relay::{ServiceHttp, ServiceSigner};
use kr_client::services::sync::ManagedSyncService;
use kr_client::services::{
    ServiceFuture, SyncBackupService, SyncExchanged, SyncFetched, SyncPosition, SyncRequestFence,
    SyncRequestStatus,
};
use kr_crypto::kdf::RecoverySeed;
use kr_protocol::archive::{RecoveryKit, TrustedWriter};
use kr_protocol::ids::SyncConflictId;
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_protocol::service::GatewayOrigin;
use kr_sync_integration::{Deployment, RunKey, SilentService, fresh_uuid, now_ms, proved};

/// The variable naming the second local service a kit may name.
const SECOND_VARIABLE: &str = "KR_BACKUP_SECOND_ORIGIN";

fn now() -> TimestampMs {
    TimestampMs::new(now_ms())
}

/// A locator made for the run: opaque, stable for the life of the kit, and nobody else's.
fn fresh_locator() -> String {
    format!("kr-recovery-{}", fresh_uuid())
}

/// One installation's settings-sync client at one service, over a transport that holds every
/// answer to naming no history.
fn client_at(
    deployment: &Deployment,
    who: &Arc<RunKey>,
) -> (Arc<ManagedSyncService>, Arc<Watched>) {
    let transport = Watched::new(deployment.transport(), None);
    let service = Arc::new(ManagedSyncService::new(
        deployment.origin().clone(),
        Arc::clone(&transport) as Arc<dyn ServiceHttp>,
        Arc::clone(who) as Arc<dyn ServiceSigner>,
    ));
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

/// A service that answers for one locator with what it holds at another.
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

/// A restore from `kit` that has been given access to `origin` through the owner's account.
fn restore_with(kit: RecoveryKit, origin: &str) -> FreshRestore {
    let mut restore = FreshRestore::new(kit, RetrievalPolicy::Account);
    restore
        .obtained_access(ServiceAccess {
            policy: RetrievalPolicy::Account,
            service_origin: origin.to_owned(),
        })
        .expect("the kit names that origin");
    restore
}

/// KR-ACC-033 against a service: a bundle written at a stable locator is found and authenticated by
/// a new installation holding only the kit and the origin; the same bytes served under another
/// locator or from another origin fail authentication and bring in no writer; a kit of another seed
/// fails too; and a writer enabled by compare and swap at the same locator is read with the same
/// kit.
#[tokio::test]
async fn a_bundle_is_found_and_authenticated_with_only_the_kit_and_its_origin() {
    let Some(deployment) = Deployment::from_environment() else {
        return;
    };
    let origin = deployment.origin().as_str().to_owned();
    let directory = tempfile::tempdir().expect("a directory for the stores");

    // The owner's device: a fresh installation, a fresh seed, and a locator made for the run.
    let owner = RunKey::installation();
    let (owner_service, owner_transport) = client_at(&deployment, &owner);
    let seed = RecoverySeed::generate().expect("a seed");
    let locator = fresh_locator();
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

    // A new installation, holding the printed kit and nothing else, reaches the service through
    // its own access and authenticates the bundle with the kit.
    let reader = RunKey::installation();
    let (reader_service, reader_transport) = client_at(&deployment, &reader);
    let reader_service = reader_service as Arc<dyn SyncBackupService>;
    let found = restore_with(kept(&kit), &origin)
        .open_bundle(Arc::clone(&reader_service), &origin)
        .await
        .expect("the bundle is found and authenticated with only the kit");
    assert_eq!(found.bundle_revision, 1);
    assert!(
        found.trusted_writers.is_empty(),
        "the first bundle trusts no writer yet"
    );

    // The same bytes, served under another locator: the kit naming that locator does not open
    // them, and nothing is trusted.
    let elsewhere = fresh_locator();
    let substituted = Arc::new(Substituting {
        inner: Arc::clone(&reader_service),
        asked: elsewhere.clone(),
        served: locator.clone(),
    }) as Arc<dyn SyncBackupService>;
    let moved_kit = seed.to_kit(vec![origin.clone()], elsewhere);
    assert!(matches!(
        restore_with(kept(&moved_kit), &origin)
            .open_bundle(substituted, &origin)
            .await,
        Err(RecoveryError::BundleNotAuthentic)
    ));

    // The same bytes, served as another origin's: a kit naming that origin does not open them.
    let other_origin = "https://recovery-substitute.invalid";
    let other_kit = seed.to_kit(vec![other_origin.to_owned()], locator.clone());
    assert!(matches!(
        restore_with(kept(&other_kit), other_origin)
            .open_bundle(Arc::clone(&reader_service), other_origin)
            .await,
        Err(RecoveryError::BundleNotAuthentic)
    ));

    // A kit of another seed, naming this very origin and locator, does not open them either.
    let stranger = RecoverySeed::generate()
        .expect("a seed")
        .to_kit(vec![origin.clone()], locator.clone());
    assert!(matches!(
        restore_with(kept(&stranger), &origin)
            .open_bundle(Arc::clone(&reader_service), &origin)
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
    // nothing but the kit and the origin.
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
        "a new installation with only the printed kit found and authenticated the bundle and read the writer a compare and swap added; another locator, another origin and another seed's kit all failed authentication; every answer named no history",
    );
}

/// KR-REQ-20.18 and KR-REQ-20.19 against two services: a kit naming both reads the bundle at
/// either, and a service that is gone gives nothing back, not even a bundle it once held.
#[tokio::test]
async fn a_kit_naming_two_services_reads_the_bundle_at_either() {
    let Some(first) = Deployment::from_environment() else {
        return;
    };
    let Some(second_origin) = variable(SECOND_VARIABLE) else {
        return skipped(SECOND_VARIABLE);
    };
    let second = Deployment::at(GatewayOrigin::new(second_origin).expect("an origin"));
    let origins = [
        first.origin().as_str().to_owned(),
        second.origin().as_str().to_owned(),
    ];
    let directory = tempfile::tempdir().expect("a directory for the stores");

    let owner = RunKey::installation();
    let seed = RecoverySeed::generate().expect("a seed");
    let locator = fresh_locator();
    let kit = seed.to_kit(origins.to_vec(), locator.clone());
    let mut transports = Vec::new();
    for (index, deployment) in [&first, &second].into_iter().enumerate() {
        let origin = deployment.origin().as_str().to_owned();
        let (service, transport) = client_at(deployment, &owner);
        let path = directory.path().join(format!("owner-{index}"));
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

    // A new installation with the printed kit reads the bundle at each service it names.
    let reader = RunKey::installation();
    for deployment in [&first, &second] {
        let origin = deployment.origin().as_str().to_owned();
        let (service, transport) = client_at(deployment, &reader);
        let found = restore_with(kept(&kit), &origin)
            .open_bundle(service as Arc<dyn SyncBackupService>, &origin)
            .await
            .expect("the bundle at that service");
        assert_eq!(found.bundle_revision, 1);
        assert_eq!(found.context.service_origin, origin);
        transports.push(transport);
    }

    // A service that is gone. A kit naming it and a live one still reads at the live one; a kit
    // naming only the one that is gone reads nothing, and says so as a service that did not
    // answer rather than as a bundle.
    let gone = SilentService::start().await;
    let gone_origin = gone.origin().as_str().to_owned();
    let (gone_service, _) = client_at(&gone.deployment(), &reader);
    let with_gone = seed.to_kit(
        vec![gone_origin.clone(), origins[1].clone()],
        locator.clone(),
    );
    assert!(matches!(
        restore_with(kept(&with_gone), &gone_origin)
            .open_bundle(
                Arc::clone(&gone_service) as Arc<dyn SyncBackupService>,
                &gone_origin
            )
            .await,
        Err(RecoveryError::Service(_))
    ));
    let (live, transport) = client_at(&second, &reader);
    restore_with(kept(&with_gone), &origins[1])
        .open_bundle(live as Arc<dyn SyncBackupService>, &origins[1])
        .await
        .expect("the live service it names");
    transports.push(transport);
    let only_gone = seed.to_kit(vec![gone_origin.clone()], locator);
    assert!(matches!(
        restore_with(kept(&only_gone), &gone_origin)
            .open_bundle(gone_service as Arc<dyn SyncBackupService>, &gone_origin)
            .await,
        Err(RecoveryError::Service(_))
    ));

    for transport in &transports {
        transport.assert_every_answer_named_its_history();
    }
    proved(
        "bundle",
        &first,
        "a kit naming two services read the bundle at each, and a kit naming a service that is gone read nothing there",
    );
}
