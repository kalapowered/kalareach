//! Deleting a copy that left the host, from the application on the computer the host runs on
//! (KR-REQ-24.29, KR-ACC-033).
//!
//! The daemon is kr-controller's in-process host with a storage service selected, and the service is
//! the stand-in, which answers as the deployed one does. The host has made two backups and they are
//! published. The application is this crate's backend, connected to the host over its own socket.
//!
//! The one thing a test answers for is the native dialog, which a person answers. Everything on the
//! other side of it is real: the host's list of what left, the deletion the host sends, and what the
//! service holds afterwards.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-24.29 | `a_yes_deletes_the_copy_the_host_listed_and_no_other` |
//! | KR-REQ-24.29 | `a_no_mints_nothing_and_deletes_nothing` |
//! | KR-REQ-24.29 | `nothing_is_asked_of_the_person_about_a_copy_the_host_does_not_offer` |
//! | KR-REQ-24.29 | `a_confirmation_works_once` |
//! | KR-REQ-24.29 | `a_cancelled_or_run_out_or_unknown_confirmation_deletes_nothing` |
//! | KR-REQ-24.29 | `a_confirmation_does_not_outlast_a_change_of_privacy_mode` |
//! | KR-REQ-24.29 | `the_page_cannot_confirm_for_the_person` |

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use companion_tauri::connection::{Connection, Standing};
use companion_tauri::retained::{Confirm, Deletions, Question};
use companion_tauri::settings::Settings;
use kr_client::ipc::IpcTransport;
use kr_client::pairing::BoxFuture;
use kr_client::services::account::{
    AccountIdentity, AccountService, AccountToken, AccountUsage, AuthorisationGrant, Exchanged,
    IssuedGrant, RefreshToken, Refreshed, StoredGrant,
};
use kr_client::services::{
    BackupManifestService, HttpService, ManagedBackupManifestService, ServiceFuture, ServiceHttp,
    ServiceSigner, managed_response_limits,
};
use kr_controller::account::{HostAccount, Service};
use kr_controller::quiet::Timer;
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_controller::testing::HeldTimer;
use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CollectionKind, KeyRotation, ObjectSource, StagedObject,
    seal_archive, stage_object,
};
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_crypto::store::{StoreSelection, load_or_create_backup_writer, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::archive::{
    BACKUP_WRITER_DOMAIN, BackupWriterRecord, BackupWriterRecordPayload, TrustedWriter,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{
    ActionId, ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, BuildId, DeviceId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::privacy::{PrivacyReport, PrivacySetParams, PrivacyStatusParams};
use kr_protocol::scalars::{AuthorisationKey, Nullable, Signature64, TimestampMs, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{Served, TOKEN, serve};
use serde_json::{Value, json};
use tauri::Manager as _;

const DELETE: &str = "/api/storage/object/delete";

/// Where the bundle's pages are served from.
const BUNDLE: &str = "tauri://localhost";

/// How long a step of the daemon's may take before the test calls it hung.
const WATCHDOG: Duration = Duration::from_secs(60);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn archive() -> ArchiveId {
    ArchiveId::new(Uuid::from_bytes([0x11; 16]))
}

fn object(seed: u8) -> BackupObjectId {
    BackupObjectId::new(Uuid::from_bytes([seed; 16]))
}

fn reference(generation: u64) -> String {
    format!("{} generation {generation}", archive())
}

/// The objects of generation 1: two members and the manifest. Generation 2 has one member and its
/// manifest.
fn first_objects() -> [BackupObjectId; 3] {
    [object(1), object(2), object(0xf1)]
}

fn second_objects() -> [BackupObjectId; 2] {
    [object(3), object(0xf2)]
}

#[derive(Debug)]
struct NoWorkers;

impl WorkerSupervisor for NoWorkers {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

/// The account service of a host that is signed in before its daemon starts: it is never asked.
#[derive(Debug)]
struct NeverAsked;

fn never_asked<T>() -> ServiceFuture<'static, T> {
    Box::pin(async {
        Err(kr_client::ClientError::refusal(
            kr_protocol::error::ErrorCode::ResourceUnavailable,
            kr_client::shown::Shown::said("this stand-in is never asked"),
        ))
    })
}

impl AccountService for NeverAsked {
    fn exchange<'a>(&'a self, _grant: &'a AuthorisationGrant) -> ServiceFuture<'a, Exchanged> {
        never_asked()
    }

    fn refresh<'a>(&'a self, _stored: &'a StoredGrant) -> ServiceFuture<'a, Refreshed> {
        never_asked()
    }

    fn revoke<'a>(&'a self, _refresh: &'a RefreshToken) -> ServiceFuture<'a, ()> {
        never_asked()
    }

    fn identity<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, AccountIdentity> {
        never_asked()
    }

    fn usage<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, AccountUsage> {
        never_asked()
    }
}

/// The owner's device: a key of its own, signing as an installation.
#[derive(Debug)]
struct OwnerDevice {
    key: AuthorisationKeyPair,
}

impl ServiceSigner for OwnerDevice {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.key.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let transcript = SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Installation.domain(),
            message.to_vec(),
        )
        .expect("a transcript");
        Ok(sign(&self.key, &transcript).expect("a signature"))
    }
}

/// The person's answer to the dialog, and how many times the dialog was shown.
struct Person {
    yes: AtomicBool,
    asked: AtomicUsize,
    last: std::sync::Mutex<Option<Question>>,
}

impl Person {
    fn saying(yes: bool) -> Self {
        Self {
            yes: AtomicBool::new(yes),
            asked: AtomicUsize::new(0),
            last: std::sync::Mutex::new(None),
        }
    }
}

impl Confirm for Person {
    fn confirm(&self, question: Question) -> BoxFuture<'_, bool> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().expect("the question") = Some(question);
        let yes = self.yes.load(Ordering::SeqCst);
        Box::pin(async move { yes })
    }
}

/// A host that has made two backups and published them, an application connected to it, and the
/// storage service the backups are at.
struct Rig {
    host: kr_ipc::testing::TempHost,
    served: Served,
    controller: Arc<Controller>,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    endpoint: kr_ipc::paths::Endpoint,
    connection: Connection,
    /// This computer's settings and the sync that keeps copies at the service, which hold none here.
    settings: Settings,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.clients.abort();
    }
}

impl Rig {
    async fn start() -> Self {
        let host = kr_ipc::testing::TempHost::create();
        let served = serve().await;
        served.web().set_backup(true);
        write_document(&host, served.origin());
        keep_sign_in(&host, served.origin()).await;
        let environment = host.environment();
        let environment_id = host.environment_id();
        environment.create().expect("the environment's directories");
        let secrets = environment.secrets_dir();
        let origin = served.origin().to_owned();
        let timer = HeldTimer::automatic();
        let controller = kr_controller::testing::taken_over(|| {
            let secrets = secrets.clone();
            kr_controller::testing::with_account_origin(
                Some(origin.clone()),
                Controller::start_on_timer(
                    ControllerSetup {
                        paths: environment.clone(),
                        environment_id,
                        identity: Box::new(move || {
                            let store = open_store_in(&secrets)
                                .expect("a secret store for the test environment");
                            Ok(ControllerIdentity::open(
                                store.store.as_ref(),
                                environment_id,
                                false,
                            )
                            .expect("an identity"))
                        }),
                        secret_store: StoreSelection::File,
                        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
                        supervisor: Box::new(NoWorkers),
                        worker_program: PathBuf::from("/nonexistent/kr-worker"),
                        build_id: build(),
                        release: "0".to_owned(),
                        shell_packages: None,
                        terminal: Box::new(kr_controller::supervision::NoTerminal),
                    },
                    Arc::clone(&timer) as Arc<dyn Timer>,
                ),
            )
        })
        .await
        .unwrap_or_else(|error| panic!("the daemon starts: {error}"));
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let clients = tokio::spawn(
            Arc::clone(&controller)
                .serve_clients(Listener::bind(&endpoint).expect("binds the client endpoint")),
        );
        let transport = IpcTransport::connect(
            &endpoint,
            companion_tauri::connection::build_id().expect("a build identity"),
        )
        .await
        .expect("connects to the control endpoint");
        let connection = Connection::over(transport).expect("a connection");
        assert!(matches!(connection.standing(), Standing::Owner));
        let settings = Settings::open(&host.root().join("companion"));
        let rig = Self {
            host,
            served,
            controller,
            clients,
            endpoint,
            connection,
            settings,
        };
        rig.owner_enrols_the_writer().await;
        rig
    }

    /// The writer key the daemon holds, read from the secret store it keeps in the host tree.
    fn writer(&self) -> AuthorisationKeyPair {
        let store = open_store_in(&self.host.environment().secrets_dir())
            .expect("the daemon's secret store");
        load_or_create_backup_writer(
            store.store.as_ref(),
            &kr_controller::service::net::device_key_scope(self.host.environment_id()),
        )
        .expect("the daemon's writer key")
    }

    /// The owner's device enrols the daemon's writer at the service.
    async fn owner_enrols_the_writer(&self) {
        let origin = GatewayOrigin::new(self.served.origin()).expect("the service's origin");
        let http: Arc<dyn ServiceHttp> = Arc::new(
            HttpService::with(
                origin.clone(),
                kr_client::services::HttpDeadlines::default(),
                managed_response_limits(),
            )
            .expect("a transport"),
        );
        let owner = Arc::new(OwnerDevice {
            key: AuthorisationKeyPair::generate().expect("an owner key"),
        });
        let manifest = ManagedBackupManifestService::new(origin, http, Arc::clone(&owner) as _);
        let writer = self
            .controller
            .backup_runtime()
            .expect("a carrier")
            .writer_public_key();
        manifest
            .enrol(&enrolment(&owner.key, writer, archive(), 1))
            .await
            .expect("the service enrols the writer");
    }

    /// Seals generation `generation` of the setup's archive with the objects named and admits it to
    /// the daemon's outbox.
    fn admit(&self, generation: u64, members: &[(u8, Vec<u8>)]) {
        let writer = self.writer();
        let sender = StoredEnvelopeKeyPair::generate().expect("a producer key");
        let device = StoredEnvelopeKeyPair::generate().expect("a device key");
        let staged: Vec<StagedObject> = members
            .iter()
            .map(|(seed, plaintext)| {
                stage_object(
                    &ObjectSource {
                        object_id: object(*seed),
                        filename: "notes.txt",
                        plaintext,
                    },
                    KeyRotation::INITIAL,
                )
                .expect("a staged object")
            })
            .collect();
        let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
        assert!(recipients.add(*device.public()));
        let sealed = seal_archive(
            &writer,
            &sender,
            &recipients,
            &ArchivePlan {
                archive_id: archive(),
                backup_generation: BackupGeneration::new(generation),
                owner_device_id: DeviceId::new(Uuid::from_bytes([0x33; 16])),
                manifest_object_id: object(
                    0xf0 + u8::try_from(generation).expect("a small generation"),
                ),
                created_at_ms: TimestampMs::new(1_700_000_000_000),
            },
            &staged,
        )
        .expect("a sealed archive");
        let backup = self.controller.backup();
        let now = kr_ipc::now_ms();
        if generation == 1 {
            backup
                .enrol_writer(writer.key_id(), archive(), now)
                .expect("the daemon enrols its own writer");
        }
        backup
            .admit(&sealed, &staged, writer.key_id(), now)
            .expect("the generation is admitted");
    }

    /// Whether the daemon's store holds `generation` as published.
    fn published(&self, generation: u64) -> bool {
        self.controller
            .backup()
            .generation(archive(), BackupGeneration::new(generation))
            .expect("the store reads")
            .is_some_and(|record| {
                record.production == kr_controller::backup::store::Production::Complete
                    && record.remote == kr_controller::backup::store::Remote::Published
            })
    }

    async fn until_published(&self, generation: u64) {
        let mut passes = self
            .controller
            .backup_runtime()
            .expect("a carrier")
            .passes();
        tokio::time::timeout(WATCHDOG, async {
            while !self.published(generation) {
                passes.changed().await.expect("the carrier is running");
            }
        })
        .await
        .unwrap_or_else(|_| panic!("generation {generation} was never published"));
    }

    /// The host has made two backups, published, with its setup recorded and privacy mode on.
    async fn after_two_backups_under_privacy_mode() -> Self {
        let rig = Self::start().await;
        rig.admit(1, &[(1, plaintext(2048)), (2, plaintext(1024))]);
        rig.until_published(1).await;
        rig.admit(2, &[(3, plaintext(2048))]);
        rig.until_published(2).await;
        let mark = rig
            .controller
            .host_account()
            .mark_at(
                GatewayOrigin::new(rig.served.origin())
                    .expect("an origin")
                    .as_str(),
            )
            .expect("an account is signed in");
        let writer = rig.writer();
        rig.controller
            .backup()
            .commit_setup(
                &kr_controller::backup::store::SetupRecord {
                    archive_id: archive(),
                    origin: GatewayOrigin::new(rig.served.origin())
                        .expect("an origin")
                        .as_str()
                        .to_owned(),
                    account_mark: mark.to_bytes(),
                    recovery_public_key: *StoredEnvelopeKeyPair::generate()
                        .expect("a key")
                        .public(),
                    kit_fingerprint: "ABCD2345".to_owned(),
                    writer_key_id: writer.key_id(),
                    producer_key_id: StoredEnvelopeKeyPair::generate().expect("a key").key_id(),
                    enabled_at_ms: TimestampMs::new(1_000),
                },
                false,
                TimestampMs::new(1_000),
            )
            .expect("the setup is written");
        rig.controller
            .backup()
            .raise_generation_counter(archive(), BackupGeneration::new(2))
            .expect("the count of generations is raised");
        assert!(rig.set_privacy(true).await);
        rig
    }

    async fn set_privacy(&self, enabled: bool) -> bool {
        let mut client = LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        client
            .mutate(
                Method::PrivacySet,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(self.host.environment_id()),
                &PrivacySetParams { enabled },
            )
            .await
            .expect("the call reaches the daemon")
            .is_ok()
    }

    async fn report(&self) -> PrivacyReport {
        self.connection
            .session()
            .read(Method::PrivacyStatus, &PrivacyStatusParams {})
            .await
            .expect("privacy mode's report")
    }

    fn held(&self, object: BackupObjectId) -> bool {
        self.served
            .web()
            .stored(&archive().to_string(), &object.to_string())
            .is_some()
    }
}

fn plaintext(length: usize) -> Vec<u8> {
    (0..length)
        .map(|at| u8::try_from((at * 31 + at / 251) % 251).expect("a byte"))
        .collect()
}

fn write_document(host: &kr_ipc::testing::TempHost, origin: &str) {
    let environment = host.environment();
    let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    document.revision = 1;
    document.storage.origin = Nullable::some(origin.to_owned());
    let path = kr_worker::config::document_path(&environment);
    std::fs::create_dir_all(path.parent().expect("a state directory")).expect("the directory");
    kr_ipc::paths::write_owner_only_file(
        &path,
        kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
    )
    .expect("the document");
}

async fn keep_sign_in(host: &kr_ipc::testing::TempHost, origin: &str) {
    let environment = host.environment();
    let store = open_store_in(&environment.secrets_dir()).expect("the daemon's secret store");
    let account = HostAccount::new(
        Arc::from(store.store),
        host.environment_id(),
        environment.runtime_root(),
        Ok(Service {
            origin: origin.to_owned(),
            scopes: Vec::new(),
            account: Arc::new(NeverAsked),
            closed: None,
        }),
        None,
    );
    account
        .keep_for_test(IssuedGrant {
            access_token: AccountToken::new(TOKEN).expect("a token"),
            expires_in_seconds: 86_400,
            refresh_token: RefreshToken::new("a-refresh-token").expect("a token"),
            scopes: ["openid", "voice", "backup.write"]
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect(),
            subject: "account-1".to_owned(),
        })
        .await;
}

/// The owner's signed enrolment of `writer` as the writer of `archive`'s collection.
fn enrolment(
    owner: &AuthorisationKeyPair,
    writer: AuthorisationKey,
    archive: ArchiveId,
    revision: u64,
) -> BackupWriterRecord {
    let payload = BackupWriterRecordPayload {
        archive_id: archive,
        writer: TrustedWriter {
            writer_key_id: kr_crypto::keys::key_id(
                kr_protocol::pairing::KeyPurpose::Authorisation,
                writer.as_bytes(),
            ),
            signing_key: writer,
            enrolled_at_ms: TimestampMs::new(1_000),
        },
        writer_revision: BackupWriterRevision::new(revision),
        owner_key_id: owner.key_id(),
        enrolled_at_ms: TimestampMs::new(1_000),
    };
    let transcript = SigningTranscript::from_canonical_bytes(
        BACKUP_WRITER_DOMAIN,
        payload.signing_input().expect("an enrolment input"),
    )
    .expect("a transcript");
    let signature = sign(owner, &transcript).expect("a signature");
    BackupWriterRecord { payload, signature }
}

/// The person says yes: the copy the host lists is deleted at the service, and no other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_yes_deletes_the_copy_the_host_listed_and_no_other() {
    let rig = Rig::after_two_backups_under_privacy_mode().await;
    let deletions = Deletions::default();
    let person = Person::saying(true);

    let asked = deletions
        .ask(Some(&rig.connection), &rig.settings, &person, &reference(1))
        .await
        .expect("the host lists the copy as deletable");
    assert!(asked.confirmed);
    let token = asked.token.expect("a yes mints a token");
    assert_eq!(person.asked.load(Ordering::SeqCst), 1);
    let question = person
        .last
        .lock()
        .expect("the question")
        .clone()
        .expect("asked");
    assert_eq!(question.reference, reference(1));
    assert_eq!(
        rig.served.web().requests_to(DELETE),
        0,
        "the question deletes nothing"
    );

    let finished = deletions
        .finish(Some(&rig.connection), &rig.settings, &token)
        .await
        .expect("the deletion is asked of the host");
    assert!(finished.deleted, "the service confirmed every object");
    assert!(
        finished
            .report
            .as_ref()
            .expect("the host's own copy answers with its report")
            .enabled,
        "privacy mode stays on"
    );
    for gone in first_objects() {
        assert!(!rig.held(gone), "{gone} is deleted");
    }
    for kept in second_objects() {
        assert!(rig.held(kept), "{kept} is not asked for");
    }
    assert_eq!(rig.served.web().requests_to(DELETE), first_objects().len());
}

/// The person says no: no token is minted and nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_no_mints_nothing_and_deletes_nothing() {
    let rig = Rig::after_two_backups_under_privacy_mode().await;
    let deletions = Deletions::default();

    let asked = deletions
        .ask(
            Some(&rig.connection),
            &rig.settings,
            &Person::saying(false),
            &reference(1),
        )
        .await
        .expect("the person is asked");
    assert!(!asked.confirmed);
    assert!(asked.token.is_none());
    assert_eq!(rig.served.web().requests_to(DELETE), 0);
    for kept in first_objects().into_iter().chain(second_objects()) {
        assert!(rig.held(kept), "{kept}");
    }
}

/// A reference the host's list does not hold, and a copy it cannot ask the removal of, are refused
/// before the person is asked anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_is_asked_of_the_person_about_a_copy_the_host_does_not_offer() {
    let rig = Rig::after_two_backups_under_privacy_mode().await;
    let deletions = Deletions::default();
    let person = Person::saying(true);

    for unlisted in ["no such copy".to_owned(), reference(3)] {
        deletions
            .ask(Some(&rig.connection), &rig.settings, &person, &unlisted)
            .await
            .expect_err("the host lists nothing under that reference");
    }
    assert_eq!(person.asked.load(Ordering::SeqCst), 0);

    // A copy that is deleted is listed and is no longer one to delete.
    let asked = deletions
        .ask(Some(&rig.connection), &rig.settings, &person, &reference(1))
        .await
        .expect("asked");
    let token = asked.token.expect("a token");
    deletions
        .finish(Some(&rig.connection), &rig.settings, &token)
        .await
        .expect("deleted");
    deletions
        .ask(Some(&rig.connection), &rig.settings, &person, &reference(1))
        .await
        .expect_err("a copy already deleted is not deletable");
    assert_eq!(person.asked.load(Ordering::SeqCst), 1);
}

/// A confirmation deletes once. Finishing it again asks the service for nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_confirmation_works_once() {
    let rig = Rig::after_two_backups_under_privacy_mode().await;
    let deletions = Deletions::default();
    let token = deletions
        .ask(
            Some(&rig.connection),
            &rig.settings,
            &Person::saying(true),
            &reference(1),
        )
        .await
        .expect("asked")
        .token
        .expect("a token");

    deletions
        .finish(Some(&rig.connection), &rig.settings, &token)
        .await
        .expect("the first finish deletes");
    let sent = rig.served.web().requests_to(DELETE);
    deletions
        .finish(Some(&rig.connection), &rig.settings, &token)
        .await
        .expect_err("the token is spent");
    assert_eq!(rig.served.web().requests_to(DELETE), sent);
}

/// A token that was cancelled, one that ran out and one this application never minted delete
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_or_run_out_or_unknown_confirmation_deletes_nothing() {
    let rig = Rig::after_two_backups_under_privacy_mode().await;
    let person = Person::saying(true);

    let deletions = Deletions::default();
    let cancelled = deletions
        .ask(Some(&rig.connection), &rig.settings, &person, &reference(1))
        .await
        .expect("asked")
        .token
        .expect("a token");
    deletions.cancel(&cancelled);
    deletions
        .finish(Some(&rig.connection), &rig.settings, &cancelled)
        .await
        .expect_err("a cancelled confirmation is gone");

    deletions
        .finish(
            Some(&rig.connection),
            &rig.settings,
            "a token nobody minted",
        )
        .await
        .expect_err("an unknown token is refused");

    let short = Deletions::with_lifetime(Duration::ZERO);
    let ran_out = short
        .ask(Some(&rig.connection), &rig.settings, &person, &reference(1))
        .await
        .expect("asked")
        .token
        .expect("a token");
    short
        .finish(Some(&rig.connection), &rig.settings, &ran_out)
        .await
        .expect_err("a confirmation past its time is gone");

    assert_eq!(rig.served.web().requests_to(DELETE), 0);
    for kept in first_objects().into_iter().chain(second_objects()) {
        assert!(rig.held(kept), "{kept}");
    }
}

/// A yes was given for privacy mode as it stood. When it changes first, the host's list is not the
/// one the person looked at, and the confirmation deletes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_confirmation_does_not_outlast_a_change_of_privacy_mode() {
    let rig = Rig::after_two_backups_under_privacy_mode().await;
    let deletions = Deletions::default();
    let token = deletions
        .ask(
            Some(&rig.connection),
            &rig.settings,
            &Person::saying(true),
            &reference(1),
        )
        .await
        .expect("asked")
        .token
        .expect("a token");

    let before = rig.report().await.generation;
    // Off and on again: the generation moves twice and privacy mode is on as it was.
    assert!(rig.set_privacy(false).await);
    assert!(rig.set_privacy(true).await);
    assert_ne!(rig.report().await.generation, before);

    deletions
        .finish(Some(&rig.connection), &rig.settings, &token)
        .await
        .expect_err("privacy mode changed since the person was asked");
    assert_eq!(rig.served.web().requests_to(DELETE), 0);
}

/// The page can name a copy and cannot answer for the person. Through the commands the page calls,
/// a token the page makes up deletes nothing, and the ask refuses a host that is not reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_page_cannot_confirm_for_the_person() {
    let rig = Rig::after_two_backups_under_privacy_mode().await;
    let app = tauri::test::mock_builder()
        .manage(companion_tauri::AppState::new())
        .invoke_handler(tauri::generate_handler![
            companion_tauri::commands::retained_delete_ask,
            companion_tauri::commands::retained_delete_finish,
            companion_tauri::commands::retained_delete_cancel,
        ])
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .expect("an application");
    let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("a window");
    let call = |command: &'static str, body: Value| {
        let window = window.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                tauri::test::get_ipc_response(
                    &window,
                    tauri::webview::InvokeRequest {
                        cmd: command.into(),
                        callback: tauri::ipc::CallbackFn(0),
                        error: tauri::ipc::CallbackFn(1),
                        url: BUNDLE.parse().expect("the bundle's address"),
                        body: tauri::ipc::InvokeBody::Json(body),
                        headers: Default::default(),
                        invoke_key: tauri::test::INVOKE_KEY.to_owned(),
                    },
                )
                .map(|answer| {
                    answer
                        .deserialize::<Value>()
                        .expect("an answer the page reads")
                })
            })
            .await
            .expect("the command's thread finished")
        }
    };
    let state = app.state::<companion_tauri::AppState>();
    state.keep_under(&rig.host.root().join("app"));

    // Not connected to a host: nothing to ask, and nothing to finish.
    assert!(
        call("retained_delete_ask", json!({ "reference": reference(1) }))
            .await
            .is_err()
    );
    assert!(
        call("retained_delete_finish", json!({ "token": "made up" }))
            .await
            .is_err()
    );

    // Connected to the host: a token the page makes up still deletes nothing.
    state.connected(rig.connection.clone());
    assert!(
        call("retained_delete_finish", json!({ "token": "made up" }))
            .await
            .is_err()
    );
    assert!(
        call("retained_delete_cancel", json!({ "token": "made up" }))
            .await
            .is_ok(),
        "dropping a confirmation nobody holds is no error"
    );
    assert_eq!(rig.served.web().requests_to(DELETE), 0);
}
