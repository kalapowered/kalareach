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
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::services::account::AccountToken;
use kr_client::services::voice::{StoredAccountToken, account_token_path};
use kr_client::services::{
    BackupManifestService, HttpService, ManagedBackupManifestService, ServiceHttp, ServiceSigner,
    managed_response_limits,
};
use kr_controller::backup::runtime::{OPERATOR_CEILING, TOKEN_CHECK};
use kr_controller::backup::store::{AttemptStatus, Production, Remote};
use kr_controller::quiet::{LONGEST_DELAY, Timer};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
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
    BACKUP_WRITER_DOMAIN, BackupWriterRecord, BackupWriterRecordPayload, TrustedWriter,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hostinfo::{DoctorStatus, HostDoctorResult};
use kr_protocol::ids::{
    ActionId, ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, BuildId, DeviceId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::privacy::PrivacySetParams;
use kr_protocol::scalars::{AuthorisationKey, Nullable, Signature64, TimestampMs, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{Moment, Served, TOKEN, serve};
use tokio::sync::Notify;

const CREATE: &str = "/api/storage/upload/create";
const PART: &str = "/api/storage/upload/part";
const ABORT: &str = "/api/storage/upload/abort";
const STATUS: &str = "/api/storage/status";
const MANIFEST: &str = "/api/backup/manifest";

/// A failure guard for a test that waits on a condition: the tests decide on what the daemon did,
/// and this only keeps one that went wrong from hanging.
async fn within<T>(what: &str, work: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(180), work)
        .await
        .unwrap_or_else(|_| panic!("gave up waiting for {what}"))
}

/// The wait between two passes, held by the test.
///
/// Each wait the daemon asks for is recorded with its length and goes on only when the test
/// releases it, or at once once the test lets the timer run by itself. A timer that runs by itself
/// releases the waits it already holds as well, because the daemon may have asked for one the test
/// has not looked at.
///
/// The clock a delay the service named is counted against stands still too, until the test moves
/// it, so what is left of a delay is exactly what the test made it, however long the test takes.
#[derive(Debug)]
struct HeldTimer {
    automatic: AtomicBool,
    waits: Mutex<Vec<Held>>,
    asked: Notify,
    now: Mutex<std::time::Instant>,
}

impl Default for HeldTimer {
    fn default() -> Self {
        Self {
            automatic: AtomicBool::new(false),
            waits: Mutex::default(),
            asked: Notify::new(),
            now: Mutex::new(std::time::Instant::now()),
        }
    }
}

/// One wait the daemon asked for.
#[derive(Debug)]
struct Held {
    duration: Duration,
    release: Arc<Notify>,
    /// Whether the test has taken it from [`HeldTimer::next_wait`].
    taken: bool,
}

impl Timer for HeldTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        // The flag and the list are read and changed under one lock, so a wait is either released
        // by the test or held for it, never both missed.
        let mut waits = self.waits.lock().expect("the waits");
        if self.automatic.load(Ordering::SeqCst) {
            return Box::pin(tokio::task::yield_now());
        }
        let release = Arc::new(Notify::new());
        waits.push(Held {
            duration,
            release: Arc::clone(&release),
            taken: false,
        });
        drop(waits);
        self.asked.notify_one();
        Box::pin(async move { release.notified().await })
    }

    fn now(&self) -> std::time::Instant {
        *self.now.lock().expect("the clock")
    }
}

impl HeldTimer {
    fn automatic() -> Arc<Self> {
        let timer = Arc::new(Self::default());
        timer.automatic.store(true, Ordering::SeqCst);
        timer
    }

    fn held() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The next wait the daemon asked for that the test has not looked at, with the means to let
    /// it end.
    async fn next_wait(&self) -> (Duration, Arc<Notify>) {
        loop {
            let asked = self.asked.notified();
            if let Some(held) = self
                .waits
                .lock()
                .expect("the waits")
                .iter_mut()
                .find(|held| !held.taken)
            {
                held.taken = true;
                return (held.duration, Arc::clone(&held.release));
            }
            asked.await;
        }
    }

    /// Moves the clock a delay is counted against.
    fn advance(&self, by: Duration) {
        *self.now.lock().expect("the clock") += by;
    }

    /// Every wait the daemon has asked for so far.
    fn asked_for(&self) -> Vec<Duration> {
        self.waits
            .lock()
            .expect("the waits")
            .iter()
            .map(|held| held.duration)
            .collect()
    }

    /// Lets every wait, those held and those to come, end at once.
    fn run_by_itself(&self) {
        let waits = self.waits.lock().expect("the waits");
        self.automatic.store(true, Ordering::SeqCst);
        for held in waits.iter() {
            held.release.notify_one();
        }
    }
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

/// What the account token on the host's disk is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token {
    /// None is imported.
    None,
    /// The token the service issued, with the scope backup storage needs.
    Usable,
    /// A token issued for another service.
    ForAnotherService,
    /// A token the service issued without the scope.
    WithoutTheScope,
    /// A token whose file says it has stopped being accepted.
    Expired,
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
        write_token(&host, arrangement.token, served.origin());
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
    let environment = host.environment();
    let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    document.revision = 1;
    document.storage.origin =
        origin.map_or_else(Nullable::null, |origin| Nullable::some(origin.to_owned()));
    let path = kr_worker::config::document_path(&environment);
    std::fs::create_dir_all(path.parent().expect("a state directory")).expect("the directory");
    kr_ipc::paths::write_owner_only_file(
        &path,
        kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
    )
    .expect("the document");
}

/// Writes the account token the operator would import.
fn write_token(host: &kr_ipc::testing::TempHost, token: Token, origin: &str) {
    let (origin, scopes, expires_at_ms): (&str, Vec<String>, Option<u64>) = match token {
        Token::None => return,
        Token::Usable => (origin, vec!["backup.write".to_owned()], None),
        Token::ForAnotherService => (
            "https://elsewhere.example",
            vec!["backup.write".to_owned()],
            None,
        ),
        Token::WithoutTheScope => (origin, vec!["voice".to_owned()], None),
        Token::Expired => (origin, vec!["backup.write".to_owned()], Some(1)),
    };
    write_token_file(host, origin, TOKEN, scopes, expires_at_ms);
}

/// Writes an account token document into the host's runtime root.
fn write_token_file(
    host: &kr_ipc::testing::TempHost,
    origin: &str,
    secret: &str,
    scopes: Vec<String>,
    expires_at_ms: Option<u64>,
) {
    let environment = host.environment();
    let stored = StoredAccountToken {
        origin: origin.to_owned(),
        access_token: AccountToken::new(secret).expect("a token"),
        scopes,
        expires_at_ms,
    };
    let root: PathBuf = environment.runtime_root().to_path_buf();
    std::fs::create_dir_all(&root).expect("the runtime root");
    kr_ipc::paths::write_owner_only_file(
        &account_token_path(&root),
        &stored.write().expect("a token document"),
    )
    .expect("the token file");
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
    let environment = host.environment();
    let environment_id = host.environment_id();
    environment.create().expect("the environment's directories");
    let secrets = environment.secrets_dir();
    let controller = kr_controller::testing::taken_over(|| {
        let secrets = secrets.clone();
        Controller::start_on_timer(
            ControllerSetup {
                paths: environment.clone(),
                environment_id,
                identity: Box::new(move || {
                    let store =
                        open_store_in(&secrets).expect("a secret store for the test environment");
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
        )
    })
    .await
    .unwrap_or_else(|error| panic!("the daemon starts: {error}"));
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let serving = vec![tokio::spawn(Arc::clone(&controller).serve_clients(
        Listener::bind(&endpoint).expect("binds the client endpoint"),
    ))];
    (controller, endpoint, serving)
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

/// Seals one generation as `writer` would, and admits it to the daemon's outbox.
fn admit(
    controller: &Controller,
    writer: &AuthorisationKeyPair,
    (sender, device): (&StoredEnvelopeKeyPair, &StoredEnvelopeKeyPair),
    archive: ArchiveId,
    generation: u64,
    objects: &[(u8, Vec<u8>)],
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
    if generation == 1 {
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
    web.fail(
        STATUS,
        1,
        Moment::Refuse {
            status: 503,
            code: "SERVICE_UNAVAILABLE",
            retry_after_seconds: Some(2),
        },
    );
    let runtime = rig.controller.backup_runtime().expect("a carrier");
    let finished = *runtime.passes().borrow();
    rig.admit(1, &[(1, plaintext(2048))]);
    rig.until("the pass finishes", |_| {
        *runtime.passes().borrow() > finished
    })
    .await;

    assert_eq!(
        web.requests_to(STATUS),
        asked + 1,
        "nothing was sent inside the delay the service named"
    );
    assert!(
        timer
            .asked_for()
            .iter()
            .any(|waited| *waited >= Duration::from_secs(2)),
        "the carrier waits out the delay: {:?}",
        timer.asked_for()
    );
}

/// A publication the service turned back as an outcome it cannot say is not sent again blind: the
/// next look at the service asks whether it holds the generation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_publication_the_service_cannot_settle_is_found_by_the_fetch_and_not_sent_again() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    web.fail(
        MANIFEST,
        1,
        Moment::Refuse {
            status: 504,
            code: "OUTCOME_UNKNOWN",
            retry_after_seconds: None,
        },
    );
    rig.admit(1, &[(1, plaintext(2048))]);
    let (_, first) = within("the first pass is held back", timer.next_wait()).await;
    let runtime = rig.controller.backup_runtime().expect("a carrier");
    let finished = *runtime.passes().borrow();
    first.notify_one();
    rig.until("the pass after it finishes", |_| {
        *runtime.passes().borrow() > finished
    })
    .await;

    let publications = web
        .arrived()
        .iter()
        .filter(|request| request.body.get("publish").is_some())
        .count();
    assert_eq!(
        publications, 1,
        "the publication the service could not settle was not sent again"
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
/// usable does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_that_is_not_usable_never_leaves_the_host() {
    for token in [
        Token::None,
        Token::ForAnotherService,
        Token::WithoutTheScope,
        Token::Expired,
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
        let (status, _) = rig.storage_check().await;
        assert_eq!(status, DoctorStatus::Warning, "{token:?}");
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
    write_token(&host, Token::Usable, served.origin());
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
    rig.admit(1, &[(1, plaintext(2048))]);
    let (waited, _) = within("the refusal", timer.next_wait()).await;
    assert_eq!(waited, Duration::from_secs(600));

    // A hundred seconds go by, and new work wakes the carrier. It looks, finds the service still
    // asked to be left alone, and waits the rest.
    timer.advance(Duration::from_secs(100));
    rig.admit(2, &[(3, plaintext(2048))]);
    // A pass the first admission woke may have asked for the whole delay before the clock moved:
    // that wait was asked for at the earlier reading and is not the one this test is about.
    let left = within("the rest of the delay", async {
        loop {
            let (asked, _) = timer.next_wait().await;
            if asked < Duration::from_secs(600) {
                break asked;
            }
        }
    })
    .await;
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

/// A publication left unanswered when the daemon stopped, which the service holds, is found when the
/// daemon starts and the generation ends complete, whatever account token the host holds then: the
/// question carries no token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_daemon_finds_the_publication_the_service_holds_whatever_its_token_is() {
    for token in [Token::Usable, Token::Expired] {
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
        write_token(&host, token, served.origin());
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

    // The token the host holds stops being usable, a new one with a secret of its own, and then
    // privacy mode is turned on.
    write_token_file(
        &rig.host,
        rig.served.origin(),
        "a-token-that-has-expired",
        vec!["backup.write".to_owned()],
        Some(1),
    );
    rig.fence().await;
    assert!(
        web.arrived()
            .iter()
            .all(|request| request.token.as_deref() != Some("a-token-that-has-expired")),
        "nothing left the host with a token it could not use"
    );

    // What the abandonment was turned back for was the host's own token and not a thing at the
    // service. The person imports a usable one, and the doctor does not go on blaming the writer
    // key or the service for it.
    write_token(&rig.host, Token::Usable, rig.served.origin());
    let (status, detail) = rig.storage_check().await;
    assert_eq!(status, DoctorStatus::Ok, "{detail}");

    // Nothing is left owed, so privacy mode turns off.
    assert!(
        rig.set_privacy(false).await,
        "privacy mode is turned off once its cleanup is done"
    );
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
/// service in its configuration document and an account token on its disk, asks that service about
/// backup storage as it starts and says so in `kr doctor`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_daemon_a_person_runs_reaches_the_storage_service_it_selects() {
    use std::path::Path;

    let host = kr_ipc::testing::TempHost::create();
    let served = serve().await;
    served.web().set_backup(true);
    write_document(&host, Some(served.origin()));
    write_token(&host, Token::Usable, served.origin());
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
    within("the daemon binds its endpoints", async {
        let _ = ready.await;
    })
    .await;
    let endpoint = host
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    within(
        "the daemon's first question about backup storage",
        served.web().requests_reach(STATUS, 1),
    )
    .await;
    let result: HostDoctorResult = client
        .request(Method::HostDoctor, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.doctor is served on the local socket")
        .to_typed()
        .expect("a result of the declared shape");
    let check = result
        .checks
        .iter()
        .find(|check| check.id() == "managed-storage")
        .unwrap_or_else(|| {
            panic!(
                "the storage check is reported; the daemon's log says: {}",
                std::fs::read_to_string(&log_path).unwrap_or_default()
            )
        });
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
        "only the token the operator imported left the host"
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
    write_token_file(
        &host,
        &origin,
        &secret,
        vec!["backup.write".to_owned()],
        None,
    );
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
