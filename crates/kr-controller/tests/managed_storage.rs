//! The daemon's carrier of its backup outbox, against the managed storage service.
//!
//! A real daemon, started from a configuration document that selects a storage service, and the
//! service on a loopback socket, answering as its contract states (`kr-service-stand-in`). The
//! generation each test admits is sealed with the writer key the daemon holds, which the test reads
//! from the daemon's own file-backed secret store, because the producer that will seal one belongs
//! to the host-backup task; and the owner's enrolment of that writer at the service is made by a
//! client with a key of its own, as the owner's device makes it.
//!
//! The daemon waits between two passes on a timer the test holds, so what these tests decide on is
//! how long the daemon asked to wait and not how long a wait took.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kr_client::services::account::{
    AccountIdentity, AccountService, AccountToken, AccountUsage, AuthorisationGrant, Exchanged,
    IssuedGrant, RefreshToken, Refreshed, StoredGrant,
};
use kr_client::services::{
    BackupManifestService, HttpService, ManagedBackupManifestService, ServiceFuture, ServiceHttp,
    ServiceSigner, managed_response_limits,
};
use kr_controller::account::{HostAccount, Service};
use kr_controller::backup::runtime::{OPERATOR_CEILING, TOKEN_CHECK};
use kr_controller::backup::store::{AttemptStatus, Production, Remote};
use kr_controller::quiet::{LONGEST_DELAY, Timer};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_controller::testing::HeldTimer;
use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CollectionKind, KeyRotation, ObjectSource, SealedArchive,
    StagedObject, seal_archive, stage_object,
};
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_crypto::store::{StoreSelection, load_or_create_backup_writer, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::archive::{
    ArchiveCheckpoint, BACKUP_WRITER_DOMAIN, BackupWriterRecord, BackupWriterRecordPayload,
    TrustedWriter,
};
use kr_protocol::backup_read::{BackupBundle, BackupReadParams, BackupReadResult, BackupSignIn};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::host_account::{
    AccountReport, AccountSignInParams, AccountState, AccountStatusParams,
};
use kr_protocol::hostinfo::{DoctorStatus, HostDoctorResult};
use kr_protocol::ids::{
    ActionId, ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, BuildId, DeviceId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::privacy::PrivacySetParams;
use kr_protocol::scalars::{AuthorisationKey, Nullable, Signature64, TimestampMs, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{ACCOUNT, Moment, Served, TOKEN, serve};

const CREATE: &str = "/api/storage/upload/create";
const PART: &str = "/api/storage/upload/part";
const ABORT: &str = "/api/storage/upload/abort";
const STATUS: &str = "/api/storage/status";
const MANIFEST: &str = "/api/backup/manifest";
const OBJECT_READ: &str = "/api/storage/object/read";
const SYNC: &str = "/api/sync/exchange";

/// A failure guard for a test that waits on a condition: the tests decide on what the daemon did,
/// and this only keeps one that went wrong from hanging.
async fn within<T>(what: &str, work: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(180), work)
        .await
        .unwrap_or_else(|_| panic!("gave up waiting for {what}"))
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

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn archive_id() -> ArchiveId {
    ArchiveId::new(Uuid::from_bytes([0x11; 16]))
}

fn object_id(seed: u8) -> BackupObjectId {
    BackupObjectId::new(Uuid::from_bytes([seed; 16]))
}

/// What the sign-in the host holds is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token {
    /// No account is signed in.
    None,
    /// An account signed in at the service with the scope backup storage needs.
    Usable,
    /// An account signed in at the service without the scope, as one made before storage was
    /// selected is.
    WithoutTheScope,
    /// An account signed in at the service whose access token has run out and which the service
    /// does not answer a renewal for.
    NotRenewable,
}

/// What the test arranges before the daemon starts.
#[derive(Clone, Copy, Debug)]
struct Arrangement {
    token: Token,
    /// Whether the owner's device has enrolled the daemon's writer at the service.
    enrolled: bool,
    /// Whether backup storage is on for the account.
    backup_on: bool,
    /// Whether the configuration document selects the service.
    selects_the_service: bool,
    /// How the service meets the daemon's first question about backup storage, when it does not
    /// simply answer it.
    first_status: Option<Moment>,
}

impl Arrangement {
    const NORMAL: Self = Self {
        token: Token::Usable,
        enrolled: true,
        backup_on: true,
        selects_the_service: true,
        first_status: None,
    };
}

/// The owner's device: a key of its own, signing as an installation.
#[derive(Debug)]
struct Owner {
    key: AuthorisationKeyPair,
}

impl ServiceSigner for Owner {
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

/// A daemon on a host tree, the service it selects, and the keys a test seals with.
struct Rig {
    host: kr_ipc::testing::TempHost,
    served: Served,
    timer: Arc<HeldTimer>,
    controller: Arc<Controller>,
    client_endpoint: kr_ipc::paths::Endpoint,
    serving: Vec<tokio::task::JoinHandle<kr_controller::Result<()>>>,
    writer: AuthorisationKeyPair,
    owner: Arc<Owner>,
    sender: StoredEnvelopeKeyPair,
    device: StoredEnvelopeKeyPair,
}

impl Rig {
    async fn start(arrangement: Arrangement, timer: Arc<HeldTimer>) -> Self {
        let host = kr_ipc::testing::TempHost::create();
        let served = serve().await;
        served.web().set_backup(arrangement.backup_on);
        if let Some(moment) = arrangement.first_status {
            served.web().fail(STATUS, 1, moment);
        }
        if arrangement.selects_the_service {
            write_document(&host, Some(served.origin()));
        }
        sign_in(&host, arrangement.token, served.origin()).await;
        let (controller, client_endpoint, serving) = start_daemon(&host, Arc::clone(&timer)).await;
        let writer = daemon_writer(&host);
        let rig = Self {
            host,
            served,
            timer,
            controller,
            client_endpoint,
            serving,
            writer,
            owner: Arc::new(Owner {
                key: AuthorisationKeyPair::generate().expect("an owner key"),
            }),
            sender: StoredEnvelopeKeyPair::generate().expect("a producer key"),
            device: StoredEnvelopeKeyPair::generate().expect("a device key"),
        };
        if arrangement.enrolled {
            rig.owner_enrols_the_writer().await;
        }
        rig
    }

    /// The owner's device enrols the daemon's writer at the service, as it will for a host the
    /// owner trusts to back up.
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
        let manifest =
            ManagedBackupManifestService::new(origin, http, Arc::clone(&self.owner) as _);
        let writer = self
            .controller
            .backup_runtime()
            .expect("a carrier")
            .writer_public_key();
        let record = enrolment(&self.owner.key, writer, archive_id(), 1);
        manifest
            .enrol(&record)
            .await
            .expect("the service enrols the writer");
    }

    /// Seals one generation as the daemon's writer would, and admits it to the daemon's outbox.
    /// The first generation also enrols the daemon's writer for the archive, which wakes the
    /// carrier once and the admission a second time.
    fn admit(&self, generation: u64, objects: &[(u8, Vec<u8>)]) {
        admit(
            &self.controller,
            &self.writer,
            (&self.sender, &self.device),
            archive_id(),
            generation,
            objects,
        );
    }

    /// Enrols the daemon's writer for the archive, and returns once the carrier has looked at it
    /// and is idle again. What is admitted after that wakes the carrier once, and a carrier that
    /// is looking at the work the admission brought is not woken a second time by anything.
    async fn enrol_the_writer_and_let_the_carrier_settle(&self) {
        let runtime = self.controller.backup_runtime().expect("a carrier");
        // Nothing has woken the carrier since it began, so once the pass it began with has ended
        // it is idle, and the pass the enrolment wakes is the next one.
        let mut passes = runtime.passes();
        within("the pass the carrier began with", async {
            while *passes.borrow_and_update() < 1 {
                passes.changed().await.expect("the carrier is running");
            }
        })
        .await;
        self.controller
            .backup()
            .enrol_writer(self.writer.key_id(), archive_id(), kr_ipc::now_ms())
            .expect("the daemon enrols its own writer for the archive");
        within("the pass the enrolment woke", async {
            while *passes.borrow_and_update() < 2 {
                passes.changed().await.expect("the carrier is running");
            }
        })
        .await;
    }

    /// Admits a generation to an archive the daemon's writer is already enrolled for.
    fn admit_to_an_enrolled_archive(&self, generation: u64, objects: &[(u8, Vec<u8>)]) {
        seal_and_admit(
            &self.controller,
            &self.writer,
            (&self.sender, &self.device),
            archive_id(),
            generation,
            objects,
            false,
        );
    }

    /// Signs the host in again at the service with a usable grant. The grant is another grant
    /// than the one the host held, as a sign-in made by a person is.
    async fn sign_in_again(&self) {
        self.controller
            .host_account()
            .keep_for_test(IssuedGrant {
                access_token: AccountToken::new(TOKEN).expect("a token"),
                expires_in_seconds: 3600,
                refresh_token: RefreshToken::new("a-refresh-token").expect("a token"),
                scopes: vec![
                    "openid".to_owned(),
                    "voice".to_owned(),
                    "backup.write".to_owned(),
                ],
                subject: "account-1".to_owned(),
            })
            .await;
    }

    /// Whether the daemon's store holds `generation` as published.
    fn published(&self, generation: u64) -> bool {
        self.controller
            .backup()
            .generation(archive_id(), BackupGeneration::new(generation))
            .expect("the store reads")
            .is_some_and(|record| {
                record.production == Production::Complete && record.remote == Remote::Published
            })
    }

    /// Waits until `done` holds, looking again each time the daemon finishes a pass.
    async fn until(&self, what: &str, mut done: impl FnMut(&Self) -> bool) {
        let runtime = self.controller.backup_runtime().expect("a carrier");
        let mut passes = runtime.passes();
        within(what, async {
            while !done(self) {
                passes.changed().await.expect("the carrier is running");
            }
        })
        .await;
    }

    /// The daemon's diagnostics, as `kr doctor` asks for them.
    async fn doctor(&self) -> HostDoctorResult {
        let mut client = LocalClient::connect(&self.client_endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        client
            .request(Method::HostDoctor, &())
            .await
            .expect("the call reaches the daemon")
            .expect("host.doctor is served on the local socket")
            .to_typed()
            .expect("a result of the declared shape")
    }

    /// What the doctor tells a person to do about the storage service.
    async fn storage_remedy(&self) -> String {
        let result = self.doctor().await;
        result
            .checks
            .iter()
            .find(|check| check.id() == "managed-storage")
            .and_then(|check| check.remedy().map(str::to_owned))
            .expect("a remedy")
    }

    async fn storage_check(&self) -> (DoctorStatus, String) {
        let result = self.doctor().await;
        let check = result
            .checks
            .iter()
            .find(|check| check.id() == "managed-storage")
            .expect("the storage check is reported");
        (check.status, check.detail().to_owned())
    }

    /// Whether every backup attempt the daemon holds has ended.
    fn every_attempt_ended(&self) -> bool {
        self.controller
            .backup()
            .attempts()
            .expect("the store reads")
            .iter()
            .all(|attempt| attempt.status == AttemptStatus::Terminal)
    }

    /// Turns privacy mode on or off, through the daemon's local socket as a person does.
    async fn set_privacy(&self, enabled: bool) -> bool {
        let mut client = LocalClient::connect(&self.client_endpoint, LocalClientKind::Cli, build())
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

    /// Turns privacy mode on and waits until the daemon has ended the work it had in hand, which is
    /// what a fence owes. It is a point of the daemon's own order to decide after: whatever it did
    /// about work that arrived before the fence has been done by then.
    async fn fence(&self) {
        assert!(self.set_privacy(true).await, "privacy mode is turned on");
        self.until(
            "the fence ended the work in hand",
            Self::every_attempt_ended,
        )
        .await;
    }

    /// Stops the daemon as its process ending would, and keeps the host tree.
    async fn stop(self) -> (kr_ipc::testing::TempHost, Served, Arc<HeldTimer>) {
        let Self {
            host,
            served,
            timer,
            controller,
            serving,
            ..
        } = self;
        for task in &serving {
            task.abort();
        }
        for task in serving {
            let _ = task.await;
        }
        drop(controller);
        (host, served, timer)
    }
}

/// Writes the configuration document that selects `origin`, or one that selects nothing.
fn write_document(host: &kr_ipc::testing::TempHost, origin: Option<&str>) {
    write_document_selecting(host, origin, None);
}

/// Writes the configuration document that selects `storage` as the storage service and `voice` as
/// the voice broker, either of which may be none.
fn write_document_selecting(
    host: &kr_ipc::testing::TempHost,
    storage: Option<&str>,
    voice: Option<&str>,
) {
    let environment = host.environment();
    let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    document.revision = 1;
    document.storage.origin =
        storage.map_or_else(Nullable::null, |origin| Nullable::some(origin.to_owned()));
    document.voice.broker_origin =
        voice.map_or_else(Nullable::null, |origin| Nullable::some(origin.to_owned()));
    let path = kr_worker::config::document_path(&environment);
    std::fs::create_dir_all(path.parent().expect("a state directory")).expect("the directory");
    kr_ipc::paths::write_owner_only_file(
        &path,
        kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
    )
    .expect("the document");
}

/// Signs the host in as `token` says, before its daemon starts.
async fn sign_in(host: &kr_ipc::testing::TempHost, token: Token, origin: &str) {
    match token {
        Token::None => {}
        Token::Usable => {
            keep_sign_in(
                host,
                origin,
                TOKEN,
                &["openid", "voice", "backup.write"],
                3600,
            )
            .await;
        }
        Token::WithoutTheScope => {
            keep_sign_in(host, origin, TOKEN, &["openid", "voice"], 3600).await;
        }
        Token::NotRenewable => {
            keep_sign_in(host, origin, TOKEN, &["openid", "voice", "backup.write"], 0).await;
        }
    }
}

/// Keeps a sign-in in the secret store the daemon will open, as a finished browser sign-in leaves
/// one: the grant the service issued, and the service it was signed in at.
async fn keep_sign_in(
    host: &kr_ipc::testing::TempHost,
    origin: &str,
    access: &str,
    scopes: &[&str],
    expires_in_seconds: u64,
) -> HostAccount {
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
            access_token: AccountToken::new(access).expect("a token"),
            expires_in_seconds,
            refresh_token: RefreshToken::new("a-refresh-token").expect("a token"),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            subject: "account-1".to_owned(),
        })
        .await;
    account
}

/// The account service of a host that is signed in before its daemon starts: the seeding keeps a
/// grant and asks the service nothing, so every question it is asked is turned away.
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

/// Starts a daemon on `host`, whose carrier waits by `timer`, and serves its local socket.
async fn start_daemon(
    host: &kr_ipc::testing::TempHost,
    timer: Arc<HeldTimer>,
) -> (
    Arc<Controller>,
    kr_ipc::paths::Endpoint,
    Vec<tokio::task::JoinHandle<kr_controller::Result<()>>>,
) {
    let controller = try_start_controller(host, timer, selected_origin_of(host))
        .await
        .unwrap_or_else(|error| panic!("the daemon starts: {error}"));
    let endpoint = host
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let serving = vec![tokio::spawn(Arc::clone(&controller).serve_clients(
        Listener::bind(&endpoint).expect("binds the client endpoint"),
    ))];
    (controller, endpoint, serving)
}

/// The origin the service the host's document selects for storage is at, or else the voice broker,
/// which a suite stands the account service at as well, because the managed account service is the
/// one service a host presents its account token to.
fn selected_origin_of(host: &kr_ipc::testing::TempHost) -> Option<String> {
    let bytes = std::fs::read(kr_worker::config::document_path(&host.environment())).ok()?;
    let document = kr_protocol::hostinfo::configuration::load(Some(&bytes)).document?;
    document
        .storage
        .origin()
        .or_else(|| document.voice.broker_origin())
        .map(str::to_owned)
}

/// Starts a daemon on `host`, whose carrier waits by `timer` and whose account service is at
/// `account_at`, or says why it does not start.
async fn try_start_controller(
    host: &kr_ipc::testing::TempHost,
    timer: Arc<HeldTimer>,
    account_at: Option<String>,
) -> kr_controller::Result<Arc<Controller>> {
    let environment = host.environment();
    let environment_id = host.environment_id();
    environment.create().expect("the environment's directories");
    let secrets = environment.secrets_dir();
    kr_controller::testing::taken_over(|| {
        let secrets = secrets.clone();
        kr_controller::testing::with_account_origin(
            account_at.clone(),
            Controller::start_on_timer(
                ControllerSetup {
                    paths: environment.clone(),
                    environment_id,
                    identity: Box::new(move || {
                        let store = open_store_in(&secrets)
                            .expect("a secret store for the test environment");
                        Ok(
                            ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                                .expect("an identity"),
                        )
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
}

/// The writer key the daemon holds, read from the secret store it keeps in the host tree.
fn daemon_writer(host: &kr_ipc::testing::TempHost) -> AuthorisationKeyPair {
    let store =
        open_store_in(&host.environment().secrets_dir()).expect("the daemon's secret store");
    load_or_create_backup_writer(
        store.store.as_ref(),
        &kr_controller::service::net::device_key_scope(host.environment_id()),
    )
    .expect("the daemon's writer key")
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

/// Seals one generation as `writer` would, and admits it to the daemon's outbox. The first
/// generation enrols the writer for the archive first.
fn admit(
    controller: &Controller,
    writer: &AuthorisationKeyPair,
    sealing: (&StoredEnvelopeKeyPair, &StoredEnvelopeKeyPair),
    archive: ArchiveId,
    generation: u64,
    objects: &[(u8, Vec<u8>)],
) {
    seal_and_admit(
        controller,
        writer,
        sealing,
        archive,
        generation,
        objects,
        generation == 1,
    );
}

/// Seals one generation as `writer` would and admits it, enrolling the writer first when asked.
fn seal_and_admit(
    controller: &Controller,
    writer: &AuthorisationKeyPair,
    (sender, device): (&StoredEnvelopeKeyPair, &StoredEnvelopeKeyPair),
    archive: ArchiveId,
    generation: u64,
    objects: &[(u8, Vec<u8>)],
    enrolling: bool,
) {
    let staged: Vec<StagedObject> = objects
        .iter()
        .map(|(seed, plaintext)| {
            stage_object(
                &ObjectSource {
                    object_id: object_id(*seed),
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
    let sealed: SealedArchive = seal_archive(
        writer,
        sender,
        &recipients,
        &ArchivePlan {
            archive_id: archive,
            backup_generation: BackupGeneration::new(generation),
            owner_device_id: DeviceId::new(Uuid::from_bytes([0x33; 16])),
            // Each generation's manifest is an object of its own.
            manifest_object_id: object_id(
                0xf0 + u8::try_from(generation).expect("a small generation number"),
            ),
            created_at_ms: TimestampMs::new(1_700_000_000_000),
        },
        &staged,
    )
    .expect("a sealed archive");
    let backup = controller.backup();
    let now = kr_ipc::now_ms();
    if enrolling {
        backup
            .enrol_writer(writer.key_id(), archive, now)
            .expect("the daemon enrols its own writer for the archive");
    }
    backup
        .admit(&sealed, &staged, writer.key_id(), now)
        .expect("the generation is admitted");
}

/// 3 MiB of bytes that do not compress to nothing.
fn plaintext(length: usize) -> Vec<u8> {
    (0..length)
        .map(|at| u8::try_from((at * 31 + at / 251) % 251).expect("a byte"))
        .collect()
}

/// A generation admitted to a running daemon is uploaded, published and recorded as published,
/// and the doctor says the service is reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_generation_admitted_to_a_running_daemon_reaches_the_service_and_settles() {
    let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
    rig.admit(1, &[(1, plaintext(3 * 1024 * 1024)), (2, plaintext(2048))]);

    rig.until("generation 1 is published", |rig| rig.published(1))
        .await;

    let web = rig.served.web();
    assert_eq!(web.generations(&archive_id().to_string()), vec![1]);
    assert_eq!(
        web.stored_objects(),
        3,
        "two objects and the encrypted manifest"
    );
    let (status, detail) = rig.storage_check().await;
    assert_eq!(status, DoctorStatus::Ok, "{detail}");
    assert!(detail.contains("backup storage is on"), "{detail}");
}

/// A daemon stopped part way through an upload goes on at the next part when it starts again, and
/// sends no part the service acknowledged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_restarted_part_way_through_an_upload_goes_on_at_the_next_part() {
    let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
    let web = Arc::clone(rig.served.web());
    // Three parts: 8 MiB, 8 MiB and what is left. The second is held open, so the first has been
    // acknowledged and the daemon is stopped while the second is on its way.
    web.fail(PART, 2, Moment::Hold);
    rig.admit(1, &[(1, plaintext(17 * 1024 * 1024))]);
    within("the second part is on its way", web.requests_reach(PART, 2)).await;

    let (host, served, timer) = rig.stop().await;
    web.release_held();

    let (controller, _, _serving) = start_daemon(&host, timer).await;
    let runtime = controller.backup_runtime().expect("a carrier");
    let mut passes = runtime.passes();
    within("generation 1 is published", async {
        loop {
            let published = controller
                .backup()
                .generation(archive_id(), BackupGeneration::new(1))
                .expect("the store reads")
                .is_some_and(|record| record.production == Production::Complete);
            if published {
                break;
            }
            passes.changed().await.expect("the carrier is running");
        }
    })
    .await;

    let parts = served.web().parts_sent();
    assert_eq!(
        parts,
        vec![1, 2, 2, 3, 1],
        "the object's part 1 once, its part 2 as it was held and again, its part 3 once, and then \
         the encrypted manifest's only part"
    );
    assert_eq!(served.web().generations(&archive_id().to_string()), vec![1]);
}

/// A publication the service acted on and whose answer was lost is found by asking the service,
/// and is not sent again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_publication_whose_answer_was_lost_is_found_by_the_fetch_and_not_sent_again() {
    let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
    let web = Arc::clone(rig.served.web());
    web.fail(MANIFEST, 1, Moment::After);
    rig.admit(1, &[(1, plaintext(2048))]);

    rig.until("generation 1 is published", |rig| rig.published(1))
        .await;

    let published = web
        .arrived()
        .iter()
        .filter(|request| request.body.get("publish").is_some())
        .count();
    assert_eq!(published, 1, "the publication was sent once");
    assert_eq!(web.generations(&archive_id().to_string()), vec![1]);
}

/// A short delay the service names to a request that is safe to repeat is waited out by the
/// carrier, which holds every question to it, and not by the client with a second send of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_short_delay_the_service_names_is_waited_out_by_the_carrier_and_not_by_the_client() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    let asked = web.requests_to(STATUS);
    // The enrolment's wake is spent before the work arrives, so the one pass that follows is the
    // admission's, and the wait it asks for is the first the timer holds.
    rig.enrol_the_writer_and_let_the_carrier_settle().await;
    web.fail(
        STATUS,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: Some(2),
        },
    );
    rig.admit_to_an_enrolled_archive(1, &[(1, plaintext(2048))]);
    let (waited, _) = within("the carrier waits out the delay", timer.next_wait()).await;

    assert!(
        waited >= Duration::from_secs(2),
        "the carrier waits out the delay the service named: {waited:?}"
    );
    assert_eq!(
        web.requests_to(STATUS),
        asked + 1,
        "nothing was sent inside the delay the service named"
    );
}

/// A publication the service turned back as an outcome it cannot say is not sent again blind: the
/// next look at the service asks whether it holds the generation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_publication_the_service_cannot_settle_is_asked_after_and_not_sent_again() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    rig.enrol_the_writer_and_let_the_carrier_settle().await;
    web.fail(
        MANIFEST,
        1,
        Moment::Refuse {
            status: 504,
            code: "OUTCOME_UNKNOWN",
            retry_after_seconds: None,
        },
    );
    rig.admit_to_an_enrolled_archive(1, &[(1, plaintext(2048))]);
    let (_, first) = within("the first pass is held back", timer.next_wait()).await;
    let runtime = rig.controller.backup_runtime().expect("a carrier");
    let finished = *runtime.passes().borrow();
    first.notify_one();
    rig.until("the pass after it finishes", |_| {
        *runtime.passes().borrow() > finished
    })
    .await;

    let sent = |member: &str| {
        web.arrived()
            .iter()
            .filter(|request| request.body.get(member).is_some())
            .count()
    };
    assert_eq!(
        sent("publish"),
        1,
        "the publication the service could not settle was not sent again"
    );
    assert!(
        sent("fetch") >= 1,
        "the pass after it asked the service what it holds"
    );
    assert!(!rig.published(1));
}

/// The wait a daemon asks for after the service turned a request back, by what the refusal says.
///
/// One case each for the reactions: ask again no sooner than the service asked, ask again soon,
/// and wait for a person.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_daemon_waits_as_long_as_the_service_asked_and_a_person_is_waited_for() {
    enum Expect {
        AtLeast(Duration),
        AtMost(Duration),
        Exactly(Duration),
    }
    let cases: [(&str, &str, Moment, Expect); 6] = [
        (
            "rate limited, asking for a second",
            CREATE,
            Moment::Refuse {
                status: 429,
                code: "RATE_LIMITED",
                retry_after_seconds: Some(1),
            },
            Expect::AtLeast(Duration::from_secs(1)),
        ),
        (
            "unavailable, asking for five minutes",
            CREATE,
            Moment::Refuse {
                status: 503,
                code: "SERVICE_UNAVAILABLE",
                retry_after_seconds: Some(300),
            },
            Expect::AtLeast(Duration::from_secs(300)),
        ),
        (
            "a person's refusal that asks for a delay of nothing",
            CREATE,
            Moment::Refuse {
                status: 403,
                code: "FORBIDDEN",
                retry_after_seconds: Some(0),
            },
            Expect::Exactly(OPERATOR_CEILING),
        ),
        (
            "unavailable, asking for longer than any number of seconds could say",
            CREATE,
            Moment::Refuse {
                status: 503,
                code: "SERVICE_UNAVAILABLE",
                retry_after_seconds: Some(u64::MAX),
            },
            Expect::Exactly(LONGEST_DELAY),
        ),
        (
            "a fault of the service's own, naming no delay",
            CREATE,
            Moment::Refuse {
                status: 500,
                code: "INTERNAL",
                retry_after_seconds: None,
            },
            Expect::AtMost(Duration::from_secs(30)),
        ),
        (
            "the allowance is spent",
            CREATE,
            Moment::Refuse {
                status: 402,
                code: "QUOTA_EXHAUSTED",
                retry_after_seconds: None,
            },
            Expect::Exactly(OPERATOR_CEILING),
        ),
    ];
    for (name, path, refusal, expect) in cases {
        let timer = HeldTimer::held();
        let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
        let web = Arc::clone(rig.served.web());
        // The daemon's first look at the service, made when it starts, has been made.
        within("the first status read", web.requests_reach(STATUS, 1)).await;
        web.fail(path, 1, refusal);
        rig.admit(1, &[(1, plaintext(2048))]);

        let (waited, _) = within(name, timer.next_wait()).await;
        let a_persons = matches!(expect, Expect::Exactly(_));
        match expect {
            Expect::AtLeast(least) => assert!(waited >= least, "{name}: asked for {waited:?}"),
            Expect::AtMost(most) => assert!(waited <= most, "{name}: asked for {waited:?}"),
            Expect::Exactly(exactly) => assert_eq!(waited, exactly, "{name}"),
        }
        // A wait that a person's action ends is also ended by new work, which asks again at once,
        // so only a wait that holds the service off is one in which nothing can be published.
        if !a_persons {
            assert!(
                !rig.published(1),
                "{name}: nothing was published while the daemon waited"
            );
        }

        // When the wait ends the daemon asks again, the service answers, and the generation goes.
        timer.run_by_itself();
        rig.until("generation 1 is published", |rig| rig.published(1))
            .await;
    }
}

/// A pass was held back by a fault that passes by itself, and then a question to the service is
/// turned back with something only a person can mend: whether the answer in hand says storage is on
/// or off, the doctor tells the person what to mend and not that the host asks again by itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_status_turned_back_after_an_earlier_hold_is_told_for_what_a_person_must_mend() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    // A pass is held back by a fault of the service's own, which the host asks again about.
    web.fail(
        CREATE,
        1,
        Moment::Refuse {
            status: 500,
            code: "INTERNAL",
            retry_after_seconds: None,
        },
    );
    rig.admit(1, &[(1, plaintext(2048))]);
    within("the pass is held back", timer.next_wait()).await;
    let remedy = rig.storage_remedy().await;
    assert!(remedy.contains("asks again by itself"), "{remedy}");

    // The answer in hand says storage is on, and a later question is turned back for a cause only a
    // person can mend.
    let turned_back = || {
        web.fail(
            STATUS,
            1,
            Moment::Refuse {
                status: 402,
                code: "QUOTA_EXHAUSTED",
                retry_after_seconds: None,
            },
        );
    };
    turned_back();
    let remedy = rig.storage_remedy().await;
    assert!(remedy.contains("allowance"), "{remedy}");

    // The answer in hand says storage is off: that is the remedy until a later question is turned
    // back, and then the later fact decides.
    web.set_backup(false);
    let remedy = rig.storage_remedy().await;
    assert!(remedy.contains("Turn backup storage on"), "{remedy}");
    turned_back();
    let remedy = rig.storage_remedy().await;
    assert!(remedy.contains("allowance"), "{remedy}");
}

/// An account the service no longer knows is a thing only a person can mend, so the daemon waits for
/// one, and says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_the_service_turns_away_is_waited_for_as_a_person() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    web.expire_token(TOKEN);
    rig.admit(1, &[(1, plaintext(2048))]);

    let (waited, _) = within("the account is turned away", timer.next_wait()).await;
    assert_eq!(waited, OPERATOR_CEILING);
    assert!(!rig.published(1));
    let (status, detail) = rig.storage_check().await;
    assert_eq!(status, DoctorStatus::Warning, "{detail}");
}

/// While the service asks to be left alone, nothing is sent: work that arrives in the meantime
/// waits for the timer. A privacy fence does not wait for it, and does not end the service's
/// request either: the delay is still owed when the fence is lifted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn work_that_arrives_while_the_service_asked_for_quiet_waits_and_a_fence_does_not() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    web.fail(
        CREATE,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: Some(300),
        },
    );
    rig.admit(1, &[(1, plaintext(2048))]);
    let (waited, _) = within("the five minutes", timer.next_wait()).await;
    assert!(waited >= Duration::from_secs(300));
    let before = web.arrived().len();

    // More work is no reason to ask the service before it said. The daemon is asked to look, then a
    // fence is raised and answered, and only then is it known what the daemon did about the work.
    rig.admit(2, &[(3, plaintext(2048))]);
    rig.controller.backup_runtime().expect("a carrier").wake();
    rig.fence().await;
    assert_eq!(
        web.arrived().len(),
        before,
        "nothing was sent while the service asked for quiet, and the fence sent nothing"
    );
    assert!(web.generations(&archive_id().to_string()).is_empty());

    // The fence is lifted. What the service asked for is still owed.
    assert!(rig.set_privacy(false).await, "privacy mode is turned off");
    let (owed, _) = within("the rest of the five minutes", timer.next_wait()).await;
    assert_eq!(
        owed,
        Duration::from_secs(300),
        "the daemon owes what is left of the service's five minutes"
    );
    assert_eq!(web.arrived().len(), before, "and still sent nothing");
}

/// A service that asks to be left alone when the daemon starts, or when `kr doctor` asks, is left
/// alone by the carrier as well: the delay it named holds every question to it, whichever of them
/// asked first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delay_named_to_the_start_or_to_the_doctor_holds_the_carrier_too() {
    let busy = Moment::Refuse {
        status: 503,
        code: "SERVICE_UNAVAILABLE",
        retry_after_seconds: Some(600),
    };

    // At the start: the first question is turned back with a delay, so the carrier waits it out
    // before it asks again, with work queued or not.
    let timer = HeldTimer::held();
    let rig = Rig::start(
        Arrangement {
            first_status: Some(busy),
            ..Arrangement::NORMAL
        },
        Arc::clone(&timer),
    )
    .await;
    let web = Arc::clone(rig.served.web());
    let (waited, _) = tokio::select! {
        waited = within("the delay is waited out", timer.next_wait()) => waited,
        () = web.requests_reach(STATUS, 2) => panic!("the service was asked inside its delay"),
    };
    assert!(waited >= Duration::from_secs(600), "{waited:?}");
    rig.admit(1, &[(1, plaintext(2048))]);
    rig.controller.backup_runtime().expect("a carrier").wake();
    rig.fence().await;
    assert_eq!(
        web.requests_to(STATUS),
        1,
        "nothing more was asked inside the delay"
    );
    drop(rig);

    // At the doctor: the carrier is idle, a doctor read is turned back with a delay, and the work
    // that arrives afterwards is held by it.
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    web.fail(STATUS, 1, busy);
    let (status, detail) = rig.storage_check().await;
    assert_eq!(status, DoctorStatus::Warning, "{detail}");
    assert_eq!(web.requests_to(STATUS), 2);
    rig.admit(1, &[(1, plaintext(2048))]);
    let (waited, _) = tokio::select! {
        waited = within("the delay is waited out", timer.next_wait()) => waited,
        () = web.requests_reach(STATUS, 3) => panic!("the service was asked inside its delay"),
    };
    assert_eq!(waited, Duration::from_secs(600));
    rig.fence().await;
    assert_eq!(web.requests_to(STATUS), 2);
}

/// A refusal that only a person can mend does not hide a delay the service asked for in the same
/// pass: the daemon leaves the service alone for as long as it asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_a_person_must_mend_does_not_hide_the_delay_the_service_asked_for() {
    let timer = HeldTimer::held();
    let rig = Rig::start(
        Arrangement {
            enrolled: false,
            ..Arrangement::NORMAL
        },
        Arc::clone(&timer),
    )
    .await;
    let web = Arc::clone(rig.served.web());
    // The publication is refused because nobody enrolled the writer; the question the daemon asks
    // next, what the service holds, is turned back with a delay.
    web.fail(
        MANIFEST,
        2,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: Some(600),
        },
    );
    rig.admit(1, &[(1, plaintext(2048))]);
    let (waited, _) = within("the publication is refused", timer.next_wait()).await;
    assert!(
        waited >= Duration::from_secs(600),
        "the service asked for ten minutes and the daemon waited {waited:?}"
    );
    rig.fence().await;
}

/// A service that answers `NOT_FOUND` to a part has lost the upload: the daemon forgets it and
/// creates the object again. One that answers `FORBIDDEN` to a part has closed it, and so has one
/// whose storage did not confirm the write of a part: the daemon abandons the upload and creates it
/// again. None of them needs a person.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upload_the_service_lost_or_closed_is_made_again() {
    for (name, moment, aborts) in [
        ("the service holds none of it", Moment::UploadsLost, 0),
        (
            "storage did not confirm the write of the part, so the service closed the upload",
            Moment::PartWriteFails,
            1,
        ),
        (
            "the service refused the part as not permitted",
            Moment::Refuse {
                status: 403,
                code: "FORBIDDEN",
                retry_after_seconds: None,
            },
            1,
        ),
    ] {
        let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
        let web = Arc::clone(rig.served.web());
        web.fail(PART, 1, moment);
        rig.admit(1, &[(1, plaintext(2048))]);
        rig.until("generation 1 is published", |rig| rig.published(1))
            .await;
        // The object and the encrypted manifest are two uploads, and the first was made twice.
        assert_eq!(web.requests_to(CREATE), 3, "{name}");
        assert_eq!(web.requests_to(ABORT), aborts, "{name}");
    }
}

/// A collection the owner deleted from the account console takes nothing again: the attempt stops
/// and the daemon asks for nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deleted_collection_stops_the_attempt() {
    let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
    let web = Arc::clone(rig.served.web());
    web.delete_collection(&archive_id().to_string());
    rig.admit(1, &[(1, plaintext(2048))]);
    rig.until("the attempt stopped", |rig| {
        rig.controller
            .backup()
            .attempts()
            .expect("the store reads")
            .iter()
            .all(|attempt| attempt.status == kr_controller::backup::store::AttemptStatus::Terminal)
    })
    .await;
    assert!(
        !rig.published(1),
        "nothing was published to a collection that takes nothing"
    );
    assert!(web.generations(&archive_id().to_string()).is_empty());
}

/// A writer the owner has not enrolled is refused its publication every time, and the daemon asks
/// again only when a person can have acted. It says what is wrong while it waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_writer_nobody_enrolled_is_asked_for_again_only_as_a_person_can_act() {
    let timer = HeldTimer::held();
    let rig = Rig::start(
        Arrangement {
            enrolled: false,
            ..Arrangement::NORMAL
        },
        Arc::clone(&timer),
    )
    .await;
    rig.admit(1, &[(1, plaintext(2048))]);

    let (waited, _) = within("the publication is refused", timer.next_wait()).await;
    assert_eq!(waited, OPERATOR_CEILING);
    assert!(!rig.published(1));

    // The service says backup storage is on, and the doctor still does not say all is well: the
    // publication was refused, and the writer is the thing to enrol.
    let (status, detail) = rig.storage_check().await;
    assert_eq!(status, DoctorStatus::Warning, "{detail}");
    assert!(detail.contains("enrolled"), "{detail}");
    let (status_again, _) = rig.storage_check().await;
    assert_eq!(
        status_again,
        DoctorStatus::Warning,
        "a second look at the service does not clear what the last pass met"
    );
    // A pass that is turned back at its first question does no work, so it does not clear what
    // the pass before it met either.
    let asked = rig.served.web().requests_to(STATUS);
    rig.served.web().fail(
        STATUS,
        1,
        Moment::Refuse {
            status: 500,
            code: "INTERNAL",
            retry_after_seconds: None,
        },
    );
    rig.controller.backup_runtime().expect("a carrier").wake();
    within(
        "the pass asks about backup storage",
        rig.served.web().requests_reach(STATUS, asked + 1),
    )
    .await;
    within("the doctor says the last pass was turned back", async {
        loop {
            let (status, detail) = rig.storage_check().await;
            assert_eq!(status, DoctorStatus::Warning, "{detail}");
            assert!(detail.contains("enrolled"), "{detail}");
            if detail.contains("could not be asked") {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;

    // A later question turned back for another cause only a person can mend is the newer fact, and
    // the remedy is the one it needs and not the one the pass before it asked for.
    rig.served.web().fail(
        STATUS,
        1,
        Moment::Refuse {
            status: 402,
            code: "QUOTA_EXHAUSTED",
            retry_after_seconds: None,
        },
    );
    let remedy = rig.storage_remedy().await;
    assert!(remedy.contains("allowance"), "{remedy}");

    // The owner enrols the writer, and the next look at the service publishes.
    rig.owner_enrols_the_writer().await;
    timer.run_by_itself();
    rig.until("generation 1 is published", |rig| rig.published(1))
        .await;
    assert!(
        timer
            .asked_for()
            .iter()
            .all(|waited| *waited == OPERATOR_CEILING || *waited <= Duration::from_secs(30)),
        "every wait before the enrolment was the one a person is waited for, or the short one \
         after the service failed: {:?}",
        timer.asked_for()
    );
    let (status, detail) = rig.storage_check().await;
    assert_eq!(status, DoctorStatus::Ok, "{detail}");
}

/// No request carrying an account leaves the host with a token that is not usable, and one that is
/// usable does. The doctor says which sign-in the host holds and that signing in again is the
/// remedy, as it must for a host that selected storage after it signed in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_that_is_not_usable_never_leaves_the_host() {
    for (token, said) in [
        (Token::None, "no account is signed in"),
        (Token::WithoutTheScope, "lacks the backup.write scope"),
        (Token::NotRenewable, "could not renew the token"),
    ] {
        let timer = HeldTimer::held();
        let rig = Rig::start(
            Arrangement {
                token,
                ..Arrangement::NORMAL
            },
            Arc::clone(&timer),
        )
        .await;
        rig.admit(1, &[(1, plaintext(2048))]);
        let web = Arc::clone(rig.served.web());
        let (waited, _release) = tokio::select! {
            waited = within("the token is looked at again", timer.next_wait()) => waited,
            () = web.requests_reach(STATUS, 1) => panic!("{token:?}: the host asked the service"),
        };
        assert_eq!(waited, TOKEN_CHECK, "{token:?}");
        let sent: Vec<_> = rig
            .served
            .web()
            .arrived()
            .into_iter()
            .filter(|request| request.token.is_some())
            .collect();
        assert!(
            sent.is_empty(),
            "{token:?}: a token left the host: {sent:?}"
        );
        let (status, detail) = rig.storage_check().await;
        assert_eq!(status, DoctorStatus::Warning, "{token:?}");
        assert!(detail.contains(said), "{token:?}: {detail}");
        let remedy = rig.storage_remedy().await;
        assert!(remedy.contains("kr account sign-in"), "{token:?}: {remedy}");
    }

    // The control: with a usable token the same work goes, and every request that carries an
    // account carries that token.
    let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
    rig.admit(1, &[(1, plaintext(2048))]);
    rig.until("generation 1 is published", |rig| rig.published(1))
        .await;
    assert!(
        rig.served
            .web()
            .arrived()
            .iter()
            .any(|request| request.token.as_deref() == Some(TOKEN))
    );
}

/// A privacy fence raised while a part is on its way ends the upload at the service and publishes
/// nothing, and the daemon does not wait out a delay to do it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn privacy_mode_turned_on_while_a_part_is_on_its_way_abandons_the_upload_and_publishes_nothing()
 {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    web.fail(PART, 1, Moment::Hold);
    rig.admit(1, &[(1, plaintext(2048))]);
    within("the part is on its way", web.requests_reach(PART, 1)).await;

    let mut client = LocalClient::connect(&rig.client_endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let set = client
        .mutate(
            Method::PrivacySet,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(rig.host.environment_id()),
            &PrivacySetParams { enabled: true },
        )
        .await
        .expect("the call reaches the daemon");
    assert!(set.is_ok(), "privacy mode is turned on: {set:?}");
    // The service lets the connection go with no answer. The daemon, which has not been told that
    // the timer ended, still ends the upload, because a fence is not a thing it waits out.
    web.release_held();
    within("the upload is abandoned", web.requests_reach(ABORT, 1)).await;
    assert!(web.generations(&archive_id().to_string()).is_empty());
}

/// A service that holds a connection open and never answers holds one task of the daemon. The
/// daemon goes on answering its local socket, and stops when it is stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_that_never_answers_holds_one_task_and_not_the_daemon() {
    let host = kr_ipc::testing::TempHost::create();
    let served = serve().await;
    served.web().set_backup(true);
    write_document(&host, Some(served.origin()));
    sign_in(&host, Token::Usable, served.origin()).await;
    served.web().fail(STATUS, 1, Moment::Hold);
    let (controller, endpoint, serving) = start_daemon(&host, HeldTimer::held()).await;
    within(
        "the daemon's first look at the service is held",
        served.web().requests_reach(STATUS, 1),
    )
    .await;

    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let result: HostDoctorResult = client
        .request(Method::HostDoctor, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.doctor is served on the local socket")
        .to_typed()
        .expect("a result of the declared shape");
    assert!(
        result
            .checks
            .iter()
            .any(|check| check.id() == "managed-storage")
    );

    // The local connection is let go as well, because a daemon is kept alive by every connection
    // it serves.
    drop(client);
    for task in &serving {
        task.abort();
    }
    for task in serving {
        let _ = task.await;
    }
    drop(controller);
    // The environment is free again, so a daemon starts on it: the held exchange did not keep the
    // first one alive.
    let (second, _, _serving) = start_daemon(&host, HeldTimer::held()).await;
    drop(second);
}

/// A publication left unanswered when the daemon stopped is asked about when it starts, for as
/// long as the settle budget allows. A service that does not say in time does not hold the start:
/// the generation is recorded as one this host cannot establish.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_that_does_not_say_what_became_of_a_publication_does_not_hold_the_start() {
    let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
    let web = Arc::clone(rig.served.web());
    // The publication reaches the service and is held there, never answered.
    web.fail(MANIFEST, 1, Moment::Hold);
    rig.admit(1, &[(1, plaintext(2048))]);
    within(
        "the publication is on its way",
        web.requests_reach(MANIFEST, 2),
    )
    .await;
    let (host, served, _) = rig.stop().await;
    // And the question the next start asks about it is held as well. The carrier's own first
    // question is held too, so that nothing it does can reach the count below before the start
    // returns.
    served.web().release_held();
    served.web().fail(MANIFEST, 1, Moment::Hold);
    served.web().fail(STATUS, 1, Moment::Hold);

    let (controller, _, _serving) = start_daemon(&host, HeldTimer::held()).await;
    assert_eq!(
        served.web().requests_to(MANIFEST),
        3,
        "the enrolment, the publication and the question the start asked about it"
    );
    let record = controller
        .backup()
        .generation(archive_id(), BackupGeneration::new(1))
        .expect("the store reads")
        .expect("the generation");
    assert_eq!(
        record.remote,
        Remote::Unknown,
        "the daemon started while the service had not said"
    );
}

/// A carrier woken inside a delay waits only for what is left of it: the delay is counted from when
/// the service named it and not from when the carrier looks again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_woken_carrier_waits_only_for_what_is_left_of_a_delay() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    // The enrolment and the admission each wake the carrier. If the second came while the first
    // wake's pass was looking at the work, the carrier would look again at once, inside the delay
    // and before the clock below has moved, and ask for the whole delay a second time; it would
    // then wait that out without listening for work, and the wake this test is about would have
    // nothing to wake. So the enrolment's pass ends before the work is admitted.
    rig.enrol_the_writer_and_let_the_carrier_settle().await;
    // Something only a person can mend, and a delay longer than the five minutes a person is given.
    web.fail(
        CREATE,
        1,
        Moment::Refuse {
            status: 403,
            code: "FORBIDDEN",
            retry_after_seconds: Some(600),
        },
    );
    rig.admit_to_an_enrolled_archive(1, &[(1, plaintext(2048))]);
    let (waited, _) = within("the refusal", timer.next_wait()).await;
    assert_eq!(waited, Duration::from_secs(600));

    // A hundred seconds go by, and new work wakes the carrier. It looks, finds the service still
    // asked to be left alone, and waits the rest.
    timer.advance(Duration::from_secs(100));
    rig.admit(2, &[(3, plaintext(2048))]);
    let (left, _) = within("the rest of the delay", timer.next_wait()).await;
    assert_eq!(left, Duration::from_secs(500));
    assert!(!rig.published(1));
}

/// A request that is on its way when the service asks `kr doctor` to leave it alone does not make
/// another inside the delay: the refusal it meets is kept for the next pass, and the question about
/// what the service holds is not put.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_met_inside_a_delay_does_not_send_the_question_that_follows_it() {
    let timer = HeldTimer::held();
    let rig = Rig::start(
        Arrangement {
            enrolled: false,
            ..Arrangement::NORMAL
        },
        Arc::clone(&timer),
    )
    .await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    // The publication is slow to be refused, and while it is on its way the doctor is told to wait.
    web.fail(MANIFEST, 1, Moment::Slow);
    rig.admit(1, &[(1, plaintext(2048))]);
    within(
        "the publication is on its way",
        web.requests_reach(MANIFEST, 1),
    )
    .await;
    web.fail(
        STATUS,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: Some(600),
        },
    );
    let (status, detail) = rig.storage_check().await;
    assert_eq!(status, DoctorStatus::Warning, "{detail}");

    web.release_held();
    let (waited, _) = within("the publication is refused", timer.next_wait()).await;
    assert_eq!(waited, Duration::from_secs(600));
    assert_eq!(
        web.requests_to(MANIFEST),
        1,
        "the question about what the service holds was not sent inside the delay"
    );
    let (status, detail) = rig.storage_check().await;
    assert_eq!(status, DoctorStatus::Warning, "{detail}");
    assert!(detail.contains("enrolled"), "{detail}");
}

/// A service that turns the start's question about an earlier publication back with a delay is left
/// alone for that long: the daemon starts, and its first question about backup storage waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delay_named_to_the_start_about_an_earlier_publication_binds_the_first_pass() {
    let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
    let web = Arc::clone(rig.served.web());
    web.fail(MANIFEST, 1, Moment::Hold);
    rig.admit(1, &[(1, plaintext(2048))]);
    within(
        "the publication is on its way",
        web.requests_reach(MANIFEST, 2),
    )
    .await;
    let (host, served, _) = rig.stop().await;
    served.web().release_held();
    served.web().fail(
        MANIFEST,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: Some(600),
        },
    );
    let asked_before = served.web().requests_to(STATUS);

    let timer = HeldTimer::held();
    let (controller, _, _serving) = start_daemon(&host, Arc::clone(&timer)).await;
    let (waited, _) = within("the delay is waited out", timer.next_wait()).await;
    assert_eq!(waited, Duration::from_secs(600));
    // The daemon asks the timer in place of asking the service, so nothing was asked of it.
    assert_eq!(
        served.web().requests_to(STATUS),
        asked_before,
        "the service was asked about backup storage inside its delay"
    );
    drop(controller);
}

/// A delay named to `kr doctor` while a part is on its way holds back what the daemon would send
/// next: the next part of the object and the next generation's upload.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delay_named_to_the_doctor_in_the_middle_of_an_upload_holds_what_comes_next() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    // Three parts, and a second generation behind them. The second part is slow to be answered, so
    // the first has been acknowledged and the daemon waits for the second.
    web.fail(PART, 2, Moment::Slow);
    rig.admit(1, &[(1, plaintext(17 * 1024 * 1024))]);
    rig.admit(2, &[(3, plaintext(2048))]);
    within("the second part is on its way", web.requests_reach(PART, 2)).await;

    web.fail(
        STATUS,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: Some(600),
        },
    );
    let (status, detail) = rig.storage_check().await;
    assert_eq!(status, DoctorStatus::Warning, "{detail}");
    // The part is answered. The daemon then asks the timer what to wait, and in doing so has sent
    // neither the third part nor anything of the second generation.
    web.release_held();
    let (waited, _) = within("the daemon waits", timer.next_wait()).await;
    assert_eq!(waited, Duration::from_secs(600));
    assert_eq!(
        web.requests_to(PART),
        2,
        "no part was sent inside the delay"
    );
    assert_eq!(
        web.requests_to(CREATE),
        1,
        "no upload was begun inside the delay"
    );

    // When the delay has passed, the work goes on until both generations are published.
    timer.run_by_itself();
    rig.until("both generations are published", |rig| {
        rig.published(1) && rig.published(2)
    })
    .await;
}

/// A delay named to `kr doctor` while a part is on its way, and a sign-in made while that part is
/// on its way, still hold back what the daemon would send next, and the doctor still says so: the
/// pass ends under another grant than it began under, and the delay is the service's whichever grant
/// asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delay_the_service_names_stands_when_the_host_signs_in_again_during_the_pass() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    web.fail(PART, 2, Moment::Slow);
    rig.admit(1, &[(1, plaintext(17 * 1024 * 1024))]);
    within("the second part is on its way", web.requests_reach(PART, 2)).await;

    web.fail(
        STATUS,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: Some(600),
        },
    );
    let (status, detail) = rig.storage_check().await;
    assert_eq!(status, DoctorStatus::Warning, "{detail}");
    rig.sign_in_again().await;
    web.release_held();
    // The pass ended under another grant, so the carrier looks again soon, and finds the delay
    // still owed and sends nothing inside it.
    let (waited, release) = within("the daemon looks again", timer.next_wait()).await;
    assert_eq!(waited, TOKEN_CHECK);
    let (status, detail) = rig.storage_check().await;
    assert_eq!(
        status,
        DoctorStatus::Warning,
        "the doctor says the delay is owed: {detail}"
    );
    release.notify_one();
    let (waited, _) = within("the daemon waits out the delay", timer.next_wait()).await;
    assert!(
        waited > Duration::from_secs(500) && waited <= Duration::from_secs(600),
        "{waited:?}"
    );
    assert_eq!(
        web.requests_to(PART),
        2,
        "no part was sent inside the delay"
    );
}

/// A part the service turns back with a delay, in a pass during which the host signs in again,
/// holds the carrier for the delay: the sign-in costs a short look again and the doctor says the
/// service asked to be left alone, not that all is well.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_part_turned_back_with_a_delay_in_a_pass_that_spans_a_sign_in_holds_the_carrier() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    rig.enrol_the_writer_and_let_the_carrier_settle().await;
    web.fail(CREATE, 1, Moment::Slow);
    rig.admit_to_an_enrolled_archive(1, &[(1, plaintext(2048))]);
    within("the upload is being begun", web.requests_reach(CREATE, 1)).await;
    rig.sign_in_again().await;
    web.fail(
        PART,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: Some(600),
        },
    );
    web.release_held();
    let (waited, release) = within("the daemon looks again", timer.next_wait()).await;
    assert_eq!(
        waited, TOKEN_CHECK,
        "a pass that spans a sign-in is looked at again soon"
    );
    let (status, detail) = rig.storage_check().await;
    assert_eq!(status, DoctorStatus::Warning, "{detail}");
    assert_eq!(web.requests_to(PART), 1, "the part was sent once");

    // The look again finds the delay still owed and sends nothing inside it.
    release.notify_one();
    let (waited, _) = within("the daemon waits out the delay", timer.next_wait()).await;
    assert!(
        waited > Duration::from_secs(500) && waited <= Duration::from_secs(600),
        "{waited:?}"
    );
    assert_eq!(
        web.requests_to(PART),
        1,
        "no part was sent inside the delay"
    );
}

/// A publication left unanswered when the daemon stopped, which the service holds, is found when the
/// daemon starts and the generation ends complete, whatever account token the host holds then: the
/// question carries no token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_daemon_finds_the_publication_the_service_holds_whatever_its_token_is() {
    for token in [Token::Usable, Token::NotRenewable] {
        let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
        let web = Arc::clone(rig.served.web());
        // The publication reaches the service and its answer is lost. The question the daemon asks
        // next, what the service holds, is held, so the daemon stops with the publication
        // unanswered.
        web.fail(MANIFEST, 1, Moment::After);
        web.fail(MANIFEST, 2, Moment::Hold);
        rig.admit(1, &[(1, plaintext(2048))]);
        within(
            "the daemon asks what the service holds",
            web.requests_reach(MANIFEST, 3),
        )
        .await;
        assert_eq!(web.generations(&archive_id().to_string()), vec![1]);
        let (host, served, _) = rig.stop().await;
        served.web().release_held();
        sign_in(&host, token, served.origin()).await;
        let before = served.web().arrived().len();

        let (controller, _, _serving) = start_daemon(&host, HeldTimer::held()).await;
        let record = controller
            .backup()
            .generation(archive_id(), BackupGeneration::new(1))
            .expect("the store reads")
            .expect("the generation");
        assert_eq!(
            (record.production, record.remote),
            (Production::Complete, Remote::Published),
            "{token:?}: the start found the publication the service holds"
        );
        let arrived = served.web().arrived();
        assert!(
            arrived[before..]
                .iter()
                .filter(|request| request.path == MANIFEST)
                .all(|request| request.token.is_none()),
            "{token:?}: the question about the publication carries no account token"
        );
        assert_eq!(
            arrived
                .iter()
                .filter(|request| request.body.get("publish").is_some())
                .count(),
            1,
            "{token:?}: the publication was sent once and not again"
        );
    }
}

/// Privacy mode ends the work in hand and can be turned off again, whatever account token the host
/// holds when the fence comes: a request the host cannot sign in for is not sent, and the work it
/// would have ended ends without it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cleanup_privacy_mode_owes_ends_the_work_in_hand_whatever_the_token_is() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    // The upload is created, and the service turns its first part back and asks to be left alone.
    web.fail(
        PART,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: Some(600),
        },
    );
    rig.admit(1, &[(1, plaintext(2048))]);
    let (waited, _) = within("the part is turned back", timer.next_wait()).await;
    assert!(waited >= Duration::from_secs(600), "{waited:?}");

    // The host is signed in again with a grant that lacks the scope, with a token of its own, so
    // the token it held stops being usable, and then privacy mode is turned on.
    rig.controller
        .host_account()
        .keep_for_test(IssuedGrant {
            access_token: AccountToken::new("a-token-without-the-scope").expect("a token"),
            expires_in_seconds: 3600,
            refresh_token: RefreshToken::new("a-refresh-token").expect("a token"),
            scopes: vec!["openid".to_owned(), "voice".to_owned()],
            subject: "account-1".to_owned(),
        })
        .await;
    rig.fence().await;
    assert!(
        web.arrived()
            .iter()
            .all(|request| request.token.as_deref() != Some("a-token-without-the-scope")),
        "nothing left the host with a token it could not use"
    );

    // What the abandonment was turned back for was the host's own token and not a thing at the
    // service. The person signs in again with a usable grant, and the doctor does not go on blaming
    // the writer key or the service for it.
    rig.sign_in_again().await;
    let (status, detail) = rig.storage_check().await;
    assert_eq!(status, DoctorStatus::Ok, "{detail}");

    // Nothing is left owed, so privacy mode turns off.
    assert!(
        rig.set_privacy(false).await,
        "privacy mode is turned off once its cleanup is done"
    );
}

/// The sign-in asks for the scope of each service the host presents its account to and no other:
/// backup storage where the document selects a storage service, voice where the broker is the
/// account service. A broker at another origin is asked for nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_asks_for_the_scope_of_each_service_the_host_presents_its_account_to() {
    for (storage, voice, backup, voice_scope) in [
        (Some(true), None, true, false),
        (None, Some(true), false, true),
        (Some(true), Some(true), true, true),
        (Some(true), Some(false), true, false),
    ] {
        let host = kr_ipc::testing::TempHost::create();
        let served = serve().await;
        let origin = served.origin();
        let broker = |at_the_account: bool| {
            if at_the_account {
                origin
            } else {
                "https://elsewhere.example"
            }
        };
        write_document_selecting(&host, storage.map(|_| origin), voice.map(broker));
        let (controller, endpoint, _serving) = start_daemon(&host, HeldTimer::held()).await;
        controller
            .host_account()
            .listen_on("127.0.0.1:0".parse().expect("an address"));
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        client
            .mutate(
                Method::AccountSignIn,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id()),
                &AccountSignInParams {},
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the daemon starts the sign-in");
        let report: AccountReport = client
            .request(Method::AccountStatus, &AccountStatusParams {})
            .await
            .expect("the call reaches the daemon")
            .expect("the daemon reports")
            .to_typed()
            .expect("a report");
        let AccountState::WaitingForBrowser { authorise_url, .. } = report.state else {
            panic!("a sign-in is waiting for the browser: {:?}", report.state);
        };
        let asked: Vec<String> = url::Url::parse(&authorise_url)
            .expect("an address")
            .query_pairs()
            .find(|(name, _)| name == "scope")
            .map(|(_, value)| value.split(' ').map(str::to_owned).collect())
            .expect("the sign-in names its scopes");
        let case = format!("storage {storage:?}, voice {voice:?}: {asked:?}");
        assert_eq!(
            asked.iter().any(|scope| scope == "backup.write"),
            backup,
            "{case}"
        );
        assert_eq!(
            asked.iter().any(|scope| scope == "voice"),
            voice_scope,
            "{case}"
        );
    }
}

/// A host whose document selects a storage service that is not the account service does not start,
/// and says which key: its account token would go to a service that did not issue it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_selects_a_storage_service_other_than_the_account_service_does_not_start() {
    let host = kr_ipc::testing::TempHost::create();
    let served = serve().await;
    write_document(&host, Some(served.origin()));
    let error = try_start_controller(
        &host,
        HeldTimer::held(),
        Some("https://elsewhere.example".to_owned()),
    )
    .await
    .expect_err("the daemon refuses to start");
    assert!(error.to_string().contains("storage.origin"), "{error}");
}

/// The account token goes to the account service and to no other: a call to a service at another
/// origin is refused one, whatever the account holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_account_token_is_handed_to_the_account_service_and_to_no_other() {
    let host = kr_ipc::testing::TempHost::create();
    let served = serve().await;
    let account = keep_sign_in(
        &host,
        served.origin(),
        TOKEN,
        &["openid", "voice", "backup.write"],
        3600,
    )
    .await;
    account
        .tokens_for(served.origin())
        .token("backup.write")
        .await
        .expect("the account service is handed the token");
    account
        .tokens_for("https://elsewhere.example")
        .token("backup.write")
        .await
        .expect_err("another service is handed none");
}

/// A host whose document selects no storage service reaches none, and says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_selects_no_storage_service_contacts_none() {
    let rig = Rig::start(
        Arrangement {
            selects_the_service: false,
            enrolled: false,
            ..Arrangement::NORMAL
        },
        HeldTimer::automatic(),
    )
    .await;
    assert!(rig.controller.backup_runtime().is_none());
    let (status, _) = rig.storage_check().await;
    assert_eq!(status, DoctorStatus::NotApplicable);
    assert!(rig.served.web().arrived().is_empty());
}

/// A daemon this test started from its own copy of the program, killed when the guard goes.
#[cfg(unix)]
struct Daemon(Option<std::process::Child>);

#[cfg(unix)]
impl Drop for Daemon {
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        if let Ok(pid) = i32::try_from(child.id())
            && let Some(pid) = rustix::process::Pid::from_raw(pid)
        {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
        let _ = child.wait();
    }
}

/// The daemon a person runs, started from a copy of the program on the internal disk with a storage
/// service in its configuration document and a sign-in the service issued, asks that service about
/// backup storage as it starts and says so in `kr doctor`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_daemon_a_person_runs_reaches_the_storage_service_it_selects() {
    use std::path::Path;

    let host = kr_ipc::testing::TempHost::create();
    let served = serve().await;
    served.web().set_backup(true);
    write_document(&host, Some(served.origin()));
    sign_in(&host, Token::Usable, served.origin()).await;
    let program = host.root().join("kr-controller");
    kr_ipc::testing::place_program(Path::new(env!("CARGO_BIN_EXE_kr-controller")), &program);
    let log_path = host.root().join("daemon.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .expect("opens the daemon's log");
    let mut child = std::process::Command::new(&program)
        // On the internal disk, never the checkout: a copied program is a new one to the
        // operating system's privacy rules.
        .current_dir(host.root())
        .arg("--runtime-dir")
        .arg(host.root().join("r"))
        .arg("--state-dir")
        .arg(host.root().join("s"))
        .arg("--worker")
        .arg(host.root().join("no-such-worker"))
        .arg("--secret-store")
        .arg("file")
        .env(
            kr_controller::testing::ACCOUNT_ORIGIN_VARIABLE,
            served.origin(),
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(log.try_clone().expect("duplicates the log"))
        .spawn()
        .expect("the daemon starts");
    // The daemon says what it serves once its endpoints are bound, and that is the condition to
    // connect on. What it says after is kept in its log.
    let stdout = child.stdout.take().expect("the daemon's output");
    let _daemon = Daemon(Some(child));
    let (bound, ready) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        use std::io::{BufRead as _, Write as _};
        let mut log = log;
        let mut bound = Some(bound);
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            let _ = writeln!(log, "{line}");
            if line.starts_with("kr-controller: environment ")
                && let Some(bound) = bound.take()
            {
                let _ = bound.send(());
            }
        }
    });
    // The daemon's own words, for a failure that would otherwise say only that something is missing.
    let daemon_says = || std::fs::read_to_string(&log_path).unwrap_or_default();
    within("the daemon binds its endpoints", async {
        ready.await.unwrap_or_else(|_| {
            panic!(
                "the daemon ended before it said what it serves; its log says: {}",
                daemon_says()
            )
        });
    })
    .await;
    let endpoint = host
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .unwrap_or_else(|error| {
            panic!(
                "connects: {error}; the daemon's log says: {}",
                daemon_says()
            )
        });
    within(
        "the daemon's first question about backup storage",
        served.web().requests_reach(STATUS, 1),
    )
    .await;
    // The doctor asks the service itself, and gives it a few seconds to answer. A service that a
    // busy machine is slow to answer is a question the doctor says it could not settle, and what it
    // says the next time it asks is the service's answer to that one. So the check is asked for
    // until the doctor has heard the service within its patience; a refusal or anything else the
    // check says ends the test at once, and a service that never answers in time is the guard's.
    let check = within("the doctor to hear the storage service answer", async {
        loop {
            let result: HostDoctorResult = client
                .request(Method::HostDoctor, &())
                .await
                .expect("the call reaches the daemon")
                .expect("host.doctor is served on the local socket")
                .to_typed()
                .expect("a result of the declared shape");
            let check = result
                .checks
                .into_iter()
                .find(|check| check.id() == "managed-storage")
                .unwrap_or_else(|| {
                    panic!(
                        "the storage check is reported; the daemon's log says: {}",
                        std::fs::read_to_string(&log_path).unwrap_or_default()
                    )
                });
            if check.status == DoctorStatus::Ok
                || !check
                    .detail()
                    .contains("did not answer the last question in time")
            {
                return check;
            }
        }
    })
    .await;
    assert_eq!(check.status, DoctorStatus::Ok, "{}", check.detail());
    assert!(
        check.detail().contains("backup storage is on"),
        "{}",
        check.detail()
    );
    assert!(
        served
            .web()
            .arrived()
            .iter()
            .all(|request| request.token.as_deref().is_none_or(|token| token == TOKEN)),
        "only the token of the host's sign-in left the host"
    );
}

/// An account token, as a source hands it over.
#[derive(Debug)]
struct Bearer(String);

impl kr_client::services::account::AccountTokenSource for Bearer {
    fn token<'a>(
        &'a self,
        _scope: &'a str,
    ) -> kr_client::services::ServiceFuture<'a, AccountToken> {
        let token = AccountToken::new(self.0.clone());
        Box::pin(async move { token })
    }
}

/// The daemon publishes a generation to a Worker on this machine, and the owner finds it there.
///
/// This is the check that the stand-in is not what makes the others pass: the same daemon, with
/// the same writer key and the same transport, against the service the web repository serves. It
/// is ignored unless it is asked for, and then it needs the Worker to ask and the account tokens
/// that Worker's development sign-in wrote, so an ordinary run of this workspace sends nothing
/// anywhere:
///
/// ```text
/// node infra/scripts/testing/local-restore.mjs start   --state <dir> --name first --port <port>
/// node infra/scripts/testing/local-restore.mjs sign-in --state <dir> --name first --tokens <file>
/// KR_DEPLOYED_ORIGIN=http://127.0.0.1:<port> KR_BACKUP_TOKENS=<file> \
///   cargo test -p kr-controller --test managed_storage a_daemon_publishes_to_a_local_worker \
///   -- --ignored
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs only against a Worker on this machine named by KR_DEPLOYED_ORIGIN and KR_BACKUP_TOKENS"]
async fn a_daemon_publishes_to_a_local_worker() {
    let (Some(origin), Some(tokens)) = (
        std::env::var("KR_DEPLOYED_ORIGIN").ok(),
        std::env::var_os("KR_BACKUP_TOKENS"),
    ) else {
        panic!("KR_DEPLOYED_ORIGIN and KR_BACKUP_TOKENS name the Worker to ask");
    };
    let tokens: serde_json::Value =
        serde_json::from_slice(&std::fs::read(tokens).expect("the tokens file")).expect("tokens");
    let secret = tokens[&origin]["write"]
        .as_str()
        .expect("a backup.write token for this origin")
        .to_owned();

    let host = kr_ipc::testing::TempHost::create();
    write_document(&host, Some(&origin));
    keep_sign_in(&host, &origin, &secret, &["openid", "backup.write"], 3600).await;
    let (controller, _endpoint, _serving) = start_daemon(&host, HeldTimer::automatic()).await;
    let writer = daemon_writer(&host);
    let archive = ArchiveId::new(kr_ipc::new_uuid());

    // The owner's device: its own key and the account's token. It turns backup storage on for the
    // account and enrols the daemon's writer, as it will for a host the owner trusts to back up.
    let owner = Arc::new(Owner {
        key: AuthorisationKeyPair::generate().expect("an owner key"),
    });
    let gateway = GatewayOrigin::new(origin.clone()).expect("the Worker's origin");
    let http: Arc<dyn ServiceHttp> = Arc::new(
        HttpService::with(
            gateway.clone(),
            kr_client::services::HttpDeadlines::default(),
            managed_response_limits(),
        )
        .expect("a transport"),
    );
    let storage = kr_client::services::ManagedStorageService::new(
        gateway.clone(),
        Arc::clone(&http),
        Arc::clone(&owner) as _,
    )
    .presenting(Arc::new(Bearer(secret.clone())));
    let status = kr_client::services::StorageService::status(&storage)
        .await
        .expect("the account's storage status");
    if status.backup != kr_client::services::BackupState::On {
        kr_client::services::StorageService::set_retention(
            &storage,
            &kr_client::services::RetentionChange {
                backup: kr_client::services::BackupState::On,
                daily_snapshots: None,
                expected_revision: status.retention_revision,
            },
        )
        .await
        .expect("backup storage is turned on");
    }
    let manifest = ManagedBackupManifestService::new(gateway, http, Arc::clone(&owner) as _);
    manifest
        .enrol(&enrolment(
            &owner.key,
            controller
                .backup_runtime()
                .expect("a carrier")
                .writer_public_key(),
            archive,
            1,
        ))
        .await
        .expect("the Worker enrols the writer");

    let sender = StoredEnvelopeKeyPair::generate().expect("a producer key");
    let device = StoredEnvelopeKeyPair::generate().expect("a device key");
    admit(
        &controller,
        &writer,
        (&sender, &device),
        archive,
        1,
        &[(1, plaintext(3 * 1024 * 1024)), (2, plaintext(2048))],
    );
    let runtime = controller.backup_runtime().expect("a carrier");
    let mut passes = runtime.passes();
    within("the generation is published at the Worker", async {
        loop {
            let published = controller
                .backup()
                .generation(archive, BackupGeneration::new(1))
                .expect("the store reads")
                .is_some_and(|record| {
                    record.production == Production::Complete && record.remote == Remote::Published
                });
            if published {
                break;
            }
            passes.changed().await.expect("the carrier is running");
        }
    })
    .await;

    let fetched = manifest
        .fetch(archive, None, None)
        .await
        .expect("the Worker answers the owner")
        .expect("the Worker holds the generation");
    assert_eq!(
        fetched.publication.payload.descriptor.backup_generation,
        BackupGeneration::new(1)
    );
    assert_eq!(fetched.publication.payload.writer_key_id, writer.key_id());
    eprintln!("a daemon published generation 1 of an archive at the Worker on {origin}");
}

/* -------------------------------------------------------------------------- */
/* A restore's reads, relayed                                                  */
/* -------------------------------------------------------------------------- */

/// Asks the daemon for one read of what the storage service holds, as `kr backup restore` does.
async fn relay_read(
    endpoint: &kr_ipc::paths::Endpoint,
    params: &BackupReadParams,
) -> Result<BackupReadResult, ProtocolError> {
    let mut client = LocalClient::connect(endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    client
        .request(Method::BackupRead, params)
        .await
        .expect("the call reaches the daemon")
        .map(|value| value.to_typed().expect("a result of the declared shape"))
}

impl Rig {
    async fn read(&self, params: &BackupReadParams) -> Result<BackupReadResult, ProtocolError> {
        relay_read(&self.client_endpoint, params).await
    }

    /// A read of `length` bytes of the first member object of the archive, from `offset`.
    fn object_read(offset: u64, length: u64) -> BackupReadParams {
        BackupReadParams::Object {
            archive_id: archive_id(),
            object_id: object_id(1),
            offset: kr_protocol::scalars::U64::new(offset),
            length: kr_protocol::scalars::U64::new(length),
        }
    }
}

fn locator() -> Uuid {
    Uuid::from_bytes([0x61; 16])
}

fn sealed_bundle_bytes() -> Vec<u8> {
    plaintext(2048)
}

/// KR-REQ-24.16, 20.19 and KR-ACC-033: a restore's reads reach the service through the daemon's
/// account, and the bundle read is signed by a key of its own that is neither the daemon's writer
/// nor anything the daemon stores. The daemon relays what the service held, and keeps apart a
/// bundle that is held, one that is not, a generation that is not there, and an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restores_reads_reach_the_service_through_the_daemons_account_and_a_key_of_its_own() {
    let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
    rig.admit(1, &[(1, plaintext(1_300_000)), (2, plaintext(2048))]);
    rig.until("generation 1 is published", |rig| rig.published(1))
        .await;
    let web = Arc::clone(rig.served.web());

    // The service this host is configured for, and that a token is usable.
    match rig.read(&BackupReadParams::Service {}).await {
        Ok(BackupReadResult::Service { origin, sign_in }) => {
            assert_eq!(origin, rig.served.origin());
            assert_eq!(sign_in, BackupSignIn::Usable);
        }
        other => panic!("the service read: {other:?}"),
    }

    // A bundle the service holds, with its place in the order, and one it does not.
    let ciphertext = sealed_bundle_bytes();
    web.put_bundle(&locator().to_string(), ACCOUNT, ciphertext.clone());
    match rig
        .read(&BackupReadParams::Bundle { locator: locator() })
        .await
    {
        Ok(BackupReadResult::Bundle {
            bundle:
                BackupBundle::Held {
                    write_sequence,
                    revision,
                    recovery,
                    ciphertext: held,
                },
        }) => {
            assert_eq!(write_sequence.get(), 1);
            assert!(revision.0.is_some());
            assert!(recovery.0.is_none());
            assert_eq!(held.as_slice(), ciphertext.as_slice());
        }
        other => panic!("a held bundle: {other:?}"),
    }
    let nobody = Uuid::from_bytes([0x62; 16]);
    match rig
        .read(&BackupReadParams::Bundle { locator: nobody })
        .await
    {
        Ok(BackupReadResult::Bundle {
            bundle: BackupBundle::Absent { recovery },
        }) => assert!(recovery.0.is_none()),
        other => panic!("an absent bundle: {other:?}"),
    }
    // A collection put back from an export names its history, held or not.
    let history = Uuid::from_bytes([0x63; 16]);
    web.put_bundle_back(&nobody.to_string(), &history.to_string());
    match rig
        .read(&BackupReadParams::Bundle { locator: nobody })
        .await
    {
        Ok(BackupReadResult::Bundle {
            bundle: BackupBundle::Absent { recovery },
        }) => assert_eq!(recovery.0, Some(history)),
        other => panic!("an absent bundle in a put-back history: {other:?}"),
    }
    // A locator another account owns is told as an absent one is.
    web.put_bundle(
        &Uuid::from_bytes([0x64; 16]).to_string(),
        "account-two",
        ciphertext,
    );
    assert!(matches!(
        rig.read(&BackupReadParams::Bundle {
            locator: Uuid::from_bytes([0x64; 16])
        })
        .await,
        Ok(BackupReadResult::Bundle {
            bundle: BackupBundle::Absent { .. }
        })
    ));

    // The bundle read was signed as an installation, by a key that is not the daemon's writer, and
    // carried the host's token; the control is that the writer's own requests are signed as a host.
    let writer = rig
        .controller
        .backup_runtime()
        .expect("a carrier")
        .writer_public_key();
    let host_authorisation = {
        let store = open_store_in(&rig.host.environment().secrets_dir()).expect("the secret store");
        *kr_crypto::store::load_device_keys(
            store.store.as_ref(),
            &kr_controller::service::net::device_key_scope(rig.host.environment_id()),
        )
        .expect("the store reads")
        .expect("the daemon made its device keys")
        .authorisation
        .public()
    };
    let arrived = web.arrived();
    let bundle_reads: Vec<_> = arrived.iter().filter(|got| got.path == SYNC).collect();
    assert_eq!(bundle_reads.len(), 4);
    let keys: Vec<_> = bundle_reads
        .iter()
        .map(|got| got.signed_by.expect("signed"))
        .collect();
    assert!(keys.iter().all(|(signer, key)| {
        *signer == ServiceRequestSigner::Installation
            && *key != writer
            && *key != host_authorisation
    }));
    assert!(
        keys.windows(2).all(|pair| pair[0].1 == pair[1].1),
        "one key for the process, made in memory"
    );
    assert!(
        bundle_reads
            .iter()
            .all(|got| got.token.as_deref() == Some(TOKEN))
    );
    assert!(
        arrived
            .iter()
            .filter(|got| got.path == "/api/storage/upload/create")
            .all(|got| got.signed_by.expect("signed").0 == ServiceRequestSigner::Host),
        "the carrier signs as a host, which the sync route refuses"
    );

    // The newest generation, and none as new as a checkpoint the service has not reached.
    match rig
        .read(&BackupReadParams::Generation {
            archive_id: archive_id(),
            checkpoint: Nullable::null(),
        })
        .await
    {
        Ok(BackupReadResult::Generation { publication }) => {
            let publication = publication.0.expect("the generation the carrier published");
            assert_eq!(
                publication.payload.descriptor.backup_generation,
                BackupGeneration::new(1)
            );
            assert_eq!(publication.payload.writer_key_id, rig.writer.key_id());
        }
        other => panic!("the generation read: {other:?}"),
    }
    let ahead = ArchiveCheckpoint {
        archive_id: archive_id(),
        backup_generation: BackupGeneration::new(9),
        encrypted_manifest_hash: kr_protocol::scalars::Digest256::from_bytes([7; 32]),
        verified_at_ms: TimestampMs::new(1),
    };
    match rig
        .read(&BackupReadParams::Generation {
            archive_id: archive_id(),
            checkpoint: Nullable::some(ahead),
        })
        .await
    {
        Ok(BackupReadResult::Generation { publication }) => assert!(
            publication.0.is_none(),
            "nothing as new as the checkpoint is an answer, not an error"
        ),
        other => panic!("a generation held to a checkpoint ahead of it: {other:?}"),
    }

    // The ciphertext of an object, in ranges that join to what the service stores; a range past
    // the bound, or an empty one, is refused before anything is sent.
    let stored = web
        .stored(&archive_id().to_string(), &object_id(1).to_string())
        .expect("the object the carrier uploaded");
    let mut joined = Vec::new();
    while joined.len() < stored.len() {
        let want = u64::try_from(stored.len() - joined.len())
            .expect("a length")
            .min(512 * 1024);
        match rig.read(&Rig::object_read(joined.len() as u64, want)).await {
            Ok(BackupReadResult::Object { bytes }) => joined.extend_from_slice(bytes.as_slice()),
            other => panic!("an object read: {other:?}"),
        }
    }
    assert_eq!(joined, stored);
    for length in [0, 512 * 1024 + 1] {
        let refused = rig
            .read(&Rig::object_read(0, length))
            .await
            .expect_err("an unreasonable range is refused");
        assert_eq!(refused.code, ErrorCode::InvalidArgument);
    }
}

/// What a restore is told of the sign-in is what the doctor tells a person: a host that cannot
/// present a token says why, and a read of the bundle, which needs one, sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_cannot_present_a_token_says_why_and_sends_no_bundle_read() {
    for (token, expected) in [
        (Token::None, BackupSignIn::SignedOut),
        (Token::WithoutTheScope, BackupSignIn::WithoutScope),
        (Token::NotRenewable, BackupSignIn::NotRenewed),
    ] {
        let rig = Rig::start(
            Arrangement {
                token,
                ..Arrangement::NORMAL
            },
            HeldTimer::automatic(),
        )
        .await;
        match rig.read(&BackupReadParams::Service {}).await {
            Ok(BackupReadResult::Service { sign_in, .. }) => assert_eq!(sign_in, expected),
            other => panic!("{token:?}: {other:?}"),
        }
        let refused = rig
            .read(&BackupReadParams::Bundle { locator: locator() })
            .await
            .expect_err("no token, no bundle read");
        assert_ne!(refused.code, ErrorCode::InvalidArgument);
        // The failure is this host's, and the words say so rather than blaming the service.
        assert!(
            !refused.message.contains("storage service"),
            "{token:?}: {}",
            refused.message
        );
        assert_eq!(
            rig.served.web().requests_to(SYNC),
            0,
            "{token:?}: nothing about a bundle left the host"
        );
    }
}

/// The host is configured for no storage service: a read says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_selects_no_storage_service_has_nothing_to_read() {
    let rig = Rig::start(
        Arrangement {
            selects_the_service: false,
            enrolled: false,
            ..Arrangement::NORMAL
        },
        HeldTimer::automatic(),
    )
    .await;
    let refused = rig
        .read(&BackupReadParams::Service {})
        .await
        .expect_err("no service to read");
    assert_eq!(refused.code, ErrorCode::HostNotConfigured);
}

/// KR-REQ-24.27: while privacy mode is on the daemon reads nothing for a restore, and an answer
/// whose read ended under another state than it began under is not given.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restores_reads_are_refused_while_privacy_mode_is_on_and_held_to_the_state_they_were_read_under()
 {
    let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
    rig.admit(1, &[(1, plaintext(2048))]);
    rig.until("generation 1 is published", |rig| rig.published(1))
        .await;
    let web = Arc::clone(rig.served.web());
    web.put_bundle(&locator().to_string(), ACCOUNT, sealed_bundle_bytes());
    let reads = || {
        [
            BackupReadParams::Bundle { locator: locator() },
            BackupReadParams::Generation {
                archive_id: archive_id(),
                checkpoint: Nullable::null(),
            },
            Rig::object_read(0, 1024),
        ]
    };

    // The control: with privacy mode off every read answers.
    for read in reads() {
        assert!(rig.read(&read).await.is_ok(), "{read:?}");
    }

    // On: all three are refused, nothing is sent for them, and the service question still answers.
    assert!(rig.set_privacy(true).await);
    rig.until("the fence ended the work in hand", Rig::every_attempt_ended)
        .await;
    let sent = web.arrived().len();
    for read in reads() {
        let refused = rig.read(&read).await.expect_err("refused while private");
        assert_eq!(refused.code, ErrorCode::PermissionDenied, "{read:?}");
    }
    assert_eq!(
        web.arrived().len(),
        sent,
        "nothing was sent for a refused read"
    );
    assert!(matches!(
        rig.read(&BackupReadParams::Service {}).await,
        Ok(BackupReadResult::Service { .. })
    ));

    // Off again, and a read in flight when it turns on is not given: the service answers after
    // privacy mode was enabled, and the daemon holds the answer back.
    assert!(rig.set_privacy(false).await);
    let reads_before = web.requests_to(OBJECT_READ);
    web.fail(OBJECT_READ, 1, Moment::Slow);
    let endpoint = rig.client_endpoint.clone();
    let in_flight =
        tokio::spawn(async move { relay_read(&endpoint, &Rig::object_read(0, 1024)).await });
    within(
        "the read reaches the service",
        web.requests_reach(OBJECT_READ, reads_before + 1),
    )
    .await;
    assert!(rig.set_privacy(true).await);
    web.release_held();
    let held = within("the held read ends", in_flight)
        .await
        .expect("the read task");
    assert_eq!(
        held.expect_err("an answer read before privacy mode was enabled is not given")
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        web.requests_to(OBJECT_READ),
        reads_before + 1,
        "the read did reach the service: it was the answer that was held back, not the request"
    );
}

/// A delay the service names to a restore's read is owed to everything that asks next: the relay
/// sends nothing inside it and answers what is left, and an hour is the most it is held to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delay_the_service_names_to_a_restores_read_is_owed_to_every_later_read() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    rig.admit(1, &[(1, plaintext(4096))]);
    // The first generation is published with the timer let go, so the passes need no hand.
    timer.run_by_itself();
    rig.until("generation 1 is published", |rig| rig.published(1))
        .await;

    let busy = |seconds| Moment::Refuse {
        status: 429,
        code: "RATE_LIMITED",
        retry_after_seconds: Some(seconds),
    };
    web.fail(OBJECT_READ, 1, busy(30));
    let wait_of = |answer: Result<BackupReadResult, ProtocolError>| match answer {
        Ok(BackupReadResult::Wait {
            retry_after_seconds,
        }) => retry_after_seconds.get(),
        other => panic!("a wait: {other:?}"),
    };
    assert_eq!(wait_of(rig.read(&Rig::object_read(0, 1024)).await), 30);
    let sent = web.requests_to(OBJECT_READ);

    // Inside the delay no read of any kind leaves the host, and each answers what is left.
    timer.advance(Duration::from_secs(10));
    assert_eq!(wait_of(rig.read(&Rig::object_read(0, 1024)).await), 20);
    assert_eq!(
        wait_of(
            rig.read(&BackupReadParams::Bundle { locator: locator() })
                .await
        ),
        20
    );
    assert_eq!(web.requests_to(OBJECT_READ), sent);
    assert_eq!(web.requests_to(SYNC), 0);
    assert!(matches!(
        rig.read(&BackupReadParams::Service {}).await,
        Ok(BackupReadResult::Service { .. })
    ));

    // Past it, a read goes through (the control).
    timer.advance(Duration::from_secs(21));
    assert!(matches!(
        rig.read(&Rig::object_read(0, 1024)).await,
        Ok(BackupReadResult::Object { .. })
    ));

    // A delay longer than an hour is held to an hour.
    web.fail(OBJECT_READ, 1, busy(7200));
    assert_eq!(wait_of(rig.read(&Rig::object_read(0, 1024)).await), 3600);
    timer.advance(Duration::from_secs(3601));
    assert!(rig.read(&Rig::object_read(0, 1024)).await.is_ok());
}

/// A service's refusal can repeat what it was asked, the locator among it, so the daemon answers a
/// refusal with its code and a sentence of its own, and the locator is nowhere in the answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_the_service_words_with_the_locator_reaches_the_restore_without_it() {
    let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
    let web = Arc::clone(rig.served.web());
    web.put_bundle(&locator().to_string(), ACCOUNT, sealed_bundle_bytes());
    web.fail(
        SYNC,
        1,
        Moment::Echo {
            status: 500,
            code: "INTERNAL",
        },
    );
    let refused = rig
        .read(&BackupReadParams::Bundle { locator: locator() })
        .await
        .expect_err("the service refused");
    assert!(
        !refused.message.contains(&locator().to_string()),
        "the locator is not in what the daemon says"
    );
    assert!(!refused.message.contains("locator"), "{}", refused.message);
    // The control: the request the service refused did carry the locator.
    let arrived = web.arrived();
    let sent = arrived
        .iter()
        .find(|got| got.path == SYNC)
        .expect("a bundle read");
    assert!(sent.body.to_string().contains(&locator().to_string()));
}

/// The delay is one record for the whole host. A delay a restore's read meets holds the carrier of
/// the host's own backups, and a delay the carrier met holds a restore's read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_relay_and_the_carrier_owe_the_service_one_delay_between_them() {
    let busy = Moment::Refuse {
        status: 429,
        code: "RATE_LIMITED",
        retry_after_seconds: Some(600),
    };

    // A restore's read meets the delay; work that reaches the carrier afterwards waits it out and
    // sends nothing in the meantime.
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    web.put_bundle(&locator().to_string(), ACCOUNT, sealed_bundle_bytes());
    web.fail(SYNC, 1, busy);
    assert!(matches!(
        rig.read(&BackupReadParams::Bundle { locator: locator() })
            .await,
        Ok(BackupReadResult::Wait { .. })
    ));
    let sent = web.arrived().len();
    rig.admit(1, &[(1, plaintext(2048))]);
    rig.controller.backup_runtime().expect("a carrier").wake();
    let (waited, _) = within("the carrier waits out the delay", timer.next_wait()).await;
    assert_eq!(waited, Duration::from_secs(600));
    assert_eq!(
        web.arrived().len(),
        sent,
        "the carrier sent nothing inside a delay a restore's read met"
    );
    rig.fence().await;
    drop(rig);

    // The carrier meets the delay at its first question; a restore's read then sends nothing.
    let timer = HeldTimer::held();
    let rig = Rig::start(
        Arrangement {
            first_status: Some(busy),
            ..Arrangement::NORMAL
        },
        Arc::clone(&timer),
    )
    .await;
    let web = Arc::clone(rig.served.web());
    let (waited, _) = within("the carrier waits out the delay", timer.next_wait()).await;
    assert!(waited >= Duration::from_secs(600), "{waited:?}");
    web.put_bundle(&locator().to_string(), ACCOUNT, sealed_bundle_bytes());
    match rig
        .read(&BackupReadParams::Bundle { locator: locator() })
        .await
    {
        Ok(BackupReadResult::Wait {
            retry_after_seconds,
        }) => assert_eq!(retry_after_seconds.get(), 600),
        other => panic!("a read inside a delay the carrier met: {other:?}"),
    }
    assert_eq!(web.requests_to(SYNC), 0);
}

/// A short delay on the bundle route comes back to the caller at once, and nothing in the daemon
/// waits it out and sends the request again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_short_delay_on_a_bundle_read_is_the_callers_to_wait_out() {
    let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
    let web = Arc::clone(rig.served.web());
    web.put_bundle(&locator().to_string(), ACCOUNT, sealed_bundle_bytes());
    web.fail(
        SYNC,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: Some(2),
        },
    );
    match rig
        .read(&BackupReadParams::Bundle { locator: locator() })
        .await
    {
        Ok(BackupReadResult::Wait {
            retry_after_seconds,
        }) => assert_eq!(retry_after_seconds.get(), 2),
        other => panic!("a short delay is a wait: {other:?}"),
    }
    assert_eq!(web.requests_to(SYNC), 1, "the request was not sent again");
}

/// A sealed bundle is at most 128 KiB, so a service that answers with more is not behaving, and
/// the daemon says so in its own words rather than passing the bytes on or calling it the
/// service's refusal. The control is a bundle of exactly the most.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_larger_than_any_sealed_bundle_is_refused_by_name_and_one_at_the_limit_is_not() {
    let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
    let web = Arc::clone(rig.served.web());
    let most = kr_protocol::backup_read::BACKUP_READ_MAX_BUNDLE_BYTES;
    web.put_bundle(&locator().to_string(), ACCOUNT, plaintext(most));
    match rig
        .read(&BackupReadParams::Bundle { locator: locator() })
        .await
    {
        Ok(BackupReadResult::Bundle {
            bundle: BackupBundle::Held { ciphertext, .. },
        }) => assert_eq!(ciphertext.len(), most),
        other => panic!("a bundle at the limit: {other:?}"),
    }
    let over = Uuid::from_bytes([0x65; 16]);
    web.put_bundle(&over.to_string(), ACCOUNT, plaintext(most + 1));
    let refused = rig
        .read(&BackupReadParams::Bundle { locator: over })
        .await
        .expect_err("a bundle over the limit");
    assert_eq!(refused.code, ErrorCode::ResourceUnavailable);
    assert!(
        refused.message.contains(&most.to_string()),
        "the limit is named: {}",
        refused.message
    );
    assert!(!refused.message.contains(&over.to_string()));
}

/// An object the account owns reads; one another account owns is told as no object is, and neither
/// is a refusal in the service's words.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_object_another_account_stored_is_told_as_no_object_is() {
    let rig = Rig::start(Arrangement::NORMAL, HeldTimer::automatic()).await;
    let web = Arc::clone(rig.served.web());
    let (mine, theirs) = (object_id(0x41), object_id(0x42));
    let archive = archive_id().to_string();
    web.put_object(&archive, &mine.to_string(), ACCOUNT, plaintext(4096));
    web.put_object(
        &archive,
        &theirs.to_string(),
        "account-two",
        plaintext(4096),
    );
    let read = |object: BackupObjectId| BackupReadParams::Object {
        archive_id: archive_id(),
        object_id: object,
        offset: kr_protocol::scalars::U64::new(0),
        length: kr_protocol::scalars::U64::new(1024),
    };
    assert!(matches!(
        rig.read(&read(mine)).await,
        Ok(BackupReadResult::Object { .. })
    ));
    let theirs = rig
        .read(&read(theirs))
        .await
        .expect_err("not this account's");
    let nothing = rig
        .read(&read(object_id(0x43)))
        .await
        .expect_err("no such object");
    assert_eq!(theirs.code, nothing.code);
    assert_eq!(theirs.message, nothing.message);
}
