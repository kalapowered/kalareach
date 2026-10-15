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
use kr_protocol::backup_setup::{
    BackupEnableCause, BackupEnableParams, BackupEnableResult, BackupSetupState,
    BackupStatusParams, BackupStatusResult, BackupStorageState, BackupUnusable,
};
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
use kr_protocol::privacy::{
    PrivacyCompletion, PrivacyReport, PrivacySetParams, PrivacyStatusParams,
};
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
const RETENTION: &str = "/api/storage/retention";
const COMPLETE: &str = "/api/storage/upload/complete";
const DELETE: &str = "/api/storage/object/delete";

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
        Self::start_with(arrangement, timer, |_| {}).await
    }

    /// Starts as [`Self::start`] does, after `prepare` has put what a test needs into the host
    /// tree: the registry and the spools are the daemon's to open, so a closed session is made
    /// before it does.
    async fn start_with(
        arrangement: Arrangement,
        timer: Arc<HeldTimer>,
        prepare: impl FnOnce(&kr_ipc::testing::TempHost),
    ) -> Self {
        let host = kr_ipc::testing::TempHost::create();
        prepare(&host);
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

    /// Signs the host in at the service as another account than the one it held.
    async fn sign_in_as(&self, subject: &str) {
        self.sign_in_with(subject, TOKEN).await;
    }

    /// Signs the host in at the service as `subject`, with an access token the service issued.
    async fn sign_in_with(&self, subject: &str, token: &str) {
        self.controller
            .host_account()
            .keep_for_test(IssuedGrant {
                access_token: AccountToken::new(token).expect("a token"),
                expires_in_seconds: 3600,
                refresh_token: RefreshToken::new("another-refresh-token").expect("a token"),
                scopes: vec![
                    "openid".to_owned(),
                    "voice".to_owned(),
                    "backup.write".to_owned(),
                ],
                subject: subject.to_owned(),
            })
            .await;
    }

    /// The service's origin as the daemon holds it.
    fn origin(&self) -> String {
        GatewayOrigin::new(self.served.origin())
            .expect("the service's origin")
            .as_str()
            .to_owned()
    }

    /// Records the owner's setup for the account signed in now, with the daemon's writer.
    fn set_up(&self) -> kr_controller::backup::store::SetupRecord {
        let mark = self
            .controller
            .host_account()
            .mark_at(&self.origin())
            .expect("an account is signed in");
        self.set_up_for(mark)
    }

    /// Records the owner's setup for the account `mark` names, whichever is signed in now.
    fn set_up_for(
        &self,
        mark: kr_client::services::AccountMark,
    ) -> kr_controller::backup::store::SetupRecord {
        let record = kr_controller::backup::store::SetupRecord {
            archive_id: archive_id(),
            origin: self.origin(),
            account_mark: mark.to_bytes(),
            recovery_public_key: *self.device.public(),
            kit_fingerprint: kr_client::recovery::kit_fingerprint(self.device.public()),
            writer_key_id: self.writer.key_id(),
            producer_key_id: daemon_producer(&self.host).key_id(),
            enabled_at_ms: TimestampMs::new(1_000),
        };
        self.controller
            .backup()
            .commit_setup(&record, false, TimestampMs::new(1_000))
            .expect("the setup is written");
        record
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

    /// What the doctor says of the producer.
    async fn production_check(&self) -> (DoctorStatus, String) {
        let result = self.doctor().await;
        let check = result
            .checks
            .iter()
            .find(|check| check.id() == "backup-production")
            .expect("the producer's check is reported");
        (check.status, check.detail().to_owned())
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

    /// Where privacy mode stands, as `privacy.status` says.
    async fn privacy_report(&self) -> PrivacyReport {
        let mut client = LocalClient::connect(&self.client_endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        client
            .request(Method::PrivacyStatus, &PrivacyStatusParams {})
            .await
            .expect("the call reaches the daemon")
            .expect("privacy mode's report")
            .to_typed()
            .expect("decodes")
    }

    /// Whether privacy mode's last change has finished taking effect.
    async fn privacy_complete(&self) -> bool {
        matches!(
            self.privacy_report().await.completion,
            PrivacyCompletion::Complete
        )
    }

    /// Waits until the producer has looked at its checks `looks` times in all.
    async fn production_looked(&self, looks: u64) {
        let mut seen = self.controller.production_looks();
        within("the producer's look", async {
            while *seen.borrow_and_update() < looks {
                seen.changed().await.expect("the producer is running");
            }
        })
        .await;
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

/// The key the daemon's wraps are sent from: its stored-envelope device key, read from its own
/// file-backed secret store once the daemon has made it.
fn daemon_producer(host: &kr_ipc::testing::TempHost) -> StoredEnvelopeKeyPair {
    let store =
        open_store_in(&host.environment().secrets_dir()).expect("the daemon's secret store");
    kr_crypto::store::load_device_keys(
        store.store.as_ref(),
        &kr_controller::service::net::device_key_scope(host.environment_id()),
    )
    .expect("the device keys read")
    .expect("the daemon made its device keys")
    .stored_envelope
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

/// Every request of the backup clients is held to the account the backups belong to, where the
/// token is handed out: a host signed in as another account than the setup's sends nothing, says so
/// at `kr doctor`, and goes on when the account is the one the backups belong to again. The control
/// is the same host before it signed in as another account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_signed_in_as_another_account_than_its_backups_belong_to_sends_nothing() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    // The setup is the first account's, and the host is signed in as another before it commits, so
    // the producer, which this host's document wakes, has nothing it may send either.
    let mark = rig
        .controller
        .host_account()
        .mark_at(&rig.origin())
        .expect("an account is signed in");
    rig.sign_in_as("account-2").await;
    rig.set_up_for(mark);
    rig.admit_to_an_enrolled_archive(1, &[(1, plaintext(2048))]);
    within("the carrier says the account is another", async {
        loop {
            let (_, detail) = rig.storage_check().await;
            if detail.contains("another account") {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(web.requests_to(CREATE), 0, "no upload was begun");
    assert_eq!(web.requests_to(PART), 0);
    assert!(
        rig.storage_remedy()
            .await
            .contains("kr backup setup --replace")
    );

    // The control: the account the backups belong to, and the host goes on. The doctor looks
    // again at the token, which wakes a carrier that found work and no usable token.
    rig.sign_in_as("account-1").await;
    rig.storage_check().await;
    timer.run_by_itself();
    rig.until("the generation is published", |rig| rig.published(1))
        .await;
}

/// A request that passed its checks under one account and asks for its token after a replacement of
/// the setup committed is refused before it is signed, however its checks said: the carrier notes
/// the binding's epoch at the top of an iteration and the token source holds each request in it to
/// that epoch. A request outside an iteration is held to the account only, and the control is the
/// same request before the replacement.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_in_flight_when_a_replacement_commits_is_refused_its_token() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    rig.set_up();
    let backup = rig.controller.backup();
    let source = rig
        .controller
        .host_account()
        .bound_tokens_for(&rig.origin(), backup.binding());
    let scope = "backup.write";

    // The control, inside an iteration that began before any replacement.
    let epoch = backup.binding().read().epoch;
    kr_controller::backup::binding::in_iteration(epoch, source.token(scope))
        .await
        .expect("a token before the replacement");

    // The replacement of the same account commits while a request waits for its token.
    let other = ArchiveId::new(Uuid::from_bytes([0x12; 16]));
    let mut replacement = backup.setup().expect("a read").expect("a setup").record;
    replacement.archive_id = other;
    replacement.kit_fingerprint = "QQQQ2345".to_owned();
    backup
        .commit_setup(&replacement, true, TimestampMs::new(2_000))
        .expect("the replacement commits");
    let refused = kr_controller::backup::binding::in_iteration(epoch, source.token(scope)).await;
    assert!(refused.is_err(), "the request began before the commit");
    assert!(
        !refused
            .as_ref()
            .err()
            .is_some_and(|error| error.code() == ErrorCode::UnknownSession),
        "not the code the uploader reads as the service's answer of not found"
    );
    // Outside an iteration, and in one that began after the commit, the same account has its token.
    source.token(scope).await.expect("outside an iteration");
    let later = backup.binding().read().epoch;
    kr_controller::backup::binding::in_iteration(later, source.token(scope))
        .await
        .expect("an iteration that began after the commit");
}

/// The ciphertext of a generation whose production is over leaves the disk at the top of the
/// carrier's iteration, whatever the service or the account is doing: the host is signed out and
/// still gives its disk back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_signed_out_host_still_gives_back_the_ciphertext_of_a_finished_generation() {
    let timer = HeldTimer::held();
    let rig = Rig::start(
        Arrangement {
            token: Token::None,
            ..Arrangement::NORMAL
        },
        Arc::clone(&timer),
    )
    .await;
    let runtime = rig.controller.backup_runtime().expect("a carrier");
    let mut passes = runtime.passes();
    within("the pass the carrier began with", async {
        while *passes.borrow_and_update() < 1 {
            passes.changed().await.expect("the carrier is running");
        }
    })
    .await;
    rig.admit(1, &[(1, plaintext(2048))]);
    let backup = rig.controller.backup();
    let staged = backup.staging_root();
    assert!(walk(&staged) > 0, "the ciphertext is staged");

    backup
        .cancel_production(
            archive_id(),
            BackupGeneration::new(1),
            "given up in this test",
            TimestampMs::new(2_000),
        )
        .expect("production ends");
    rig.until("the ciphertext is released", |_| walk(&staged) == 0)
        .await;
    assert!(
        backup
            .objects(archive_id(), BackupGeneration::new(1))
            .expect("a read")
            .iter()
            .all(|object| object.local_state == kr_controller::backup::store::LocalState::Absent)
    );
}

fn walk(root: &std::path::Path) -> usize {
    let mut files = 0;
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory)
            .into_iter()
            .flatten()
            .flatten()
        {
            if entry.path().is_dir() {
                directories.push(entry.path());
            } else {
                files += 1;
            }
        }
    }
    files
}

// ---------------------------------------------------------------------------------------------
// The host makes its backups.
// ---------------------------------------------------------------------------------------------

/// A closed session the registry holds a closure for, with output in its spool, written into the
/// host tree before the daemon starts.
fn closed_session(
    host: &kr_ipc::testing::TempHost,
    output: &[u8],
    closed_at_ms: u64,
) -> kr_protocol::ids::SessionId {
    use kr_controller::registry::{LaunchPhase, Registry};
    use kr_protocol::ids::{ActorId, SessionEpoch, SessionId};
    use kr_protocol::session::{ClosureReason, ClosureRecord, Durability, OwnershipCoverage};

    let mut registry = Registry::open(
        host.environment().registry_database(),
        host.environment_id(),
    )
    .expect("the registry");
    let admission = registry
        .reserve(
            &ActorId::new("local:501").expect("a principal"),
            kr_ipc::new_uuid(),
            kr_protocol::scalars::Digest256::from_bytes([1; 32]),
            &[0xa0],
            TimestampMs::new(1),
        )
        .expect("a reservation");
    let session_id: SessionId = admission.reservation.session_id;
    registry
        .set_phase(admission.reservation.reservation_id, LaunchPhase::Closed)
        .expect("the session closes");
    registry
        .record_closure(&ClosureRecord {
            session_id,
            session_epoch: SessionEpoch::V1,
            reason: ClosureReason::RootExit,
            root_exit_code: Nullable::some(kr_protocol::scalars::U64::new(0)),
            root_signal: Nullable::null(),
            terminated: Vec::new(),
            surviving: Vec::new(),
            ownership_coverage: OwnershipCoverage::Complete,
            durability: Durability::Durable,
            closed_at_ms: TimestampMs::new(closed_at_ms),
        })
        .expect("the closure");
    let mut history = kr_worker::history::OutputHistory::with_spool(
        8,
        host.environment().session_spool(session_id),
        kr_worker::history::SpoolLayout::new(8, 1 << 20),
    )
    .expect("a spool");
    history.append(output);
    session_id
}

/// What a generation holds, opened as the recovery recipient opens it: the members by name, with
/// their plaintext.
fn opened_members(rig: &Rig, generation: u64) -> std::collections::BTreeMap<String, Vec<u8>> {
    opened_members_as(
        rig,
        generation,
        &kr_crypto::backup::ArchiveReader::Device(&rig.device),
    )
}

/// What a generation holds, opened as `reader` opens it.
fn opened_members_as(
    rig: &Rig,
    generation: u64,
    reader: &kr_crypto::backup::ArchiveReader<'_>,
) -> std::collections::BTreeMap<String, Vec<u8>> {
    use kr_crypto::backup::{ArchiveExpectation, GenerationExpectation, open_archive};

    let record = rig
        .controller
        .backup()
        .generation(archive_id(), BackupGeneration::new(generation))
        .expect("a read")
        .expect("the generation");
    let descriptor_bytes = record.descriptor.expect("a descriptor");
    let descriptor =
        kr_protocol::archive::ArchiveDescriptor::from_canonical_bytes(&descriptor_bytes)
            .expect("a descriptor");
    let web = rig.served.web();
    let stored = |object: BackupObjectId| {
        web.stored(&archive_id().to_string(), &object.to_string())
            .expect("the service holds the object")
    };
    let manifest = stored(descriptor.encrypted_manifest.object_id);
    let sender = daemon_producer(&rig.host);
    let opened = open_archive(
        reader,
        sender.public(),
        &[TrustedWriter {
            writer_key_id: rig.writer.key_id(),
            signing_key: *rig.writer.public(),
            enrolled_at_ms: TimestampMs::new(1_000),
        }],
        &ArchiveExpectation {
            archive_id: archive_id(),
            generation: GenerationExpectation::Unverified,
        },
        &descriptor_bytes,
        &manifest,
    )
    .expect("the recovery recipient opens the generation");
    opened
        .objects()
        .iter()
        .map(|entry| {
            let restored = opened
                .restore_object(
                    reader,
                    sender.public(),
                    entry.object.object_id,
                    &stored(entry.object.object_id),
                )
                .expect("a member opens");
            (entry.filename.clone(), restored.plaintext.expose().to_vec())
        })
        .collect()
}

/// A generation is made of a closed session and the configuration document, uploaded, published,
/// and opened by the recovery recipient with the members the convention names. A second pass finds
/// nothing changed and makes no second generation; a changed document, a day later, makes the next
/// one, numbered after the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_host_makes_a_backup_of_a_closed_session_and_its_configuration_once_a_day() {
    let timer = HeldTimer::held();
    let mut closed = None;
    let rig = Rig::start_with(Arrangement::NORMAL, Arc::clone(&timer), |host| {
        closed = Some(closed_session(
            host,
            b"first line\r\nsecond line\r\n",
            9_000,
        ));
    })
    .await;
    let session = closed.expect("a closed session");
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    rig.set_up();
    rig.until("the first generation is published", |rig| rig.published(1))
        .await;

    let members = opened_members(&rig, 1);
    let names: Vec<&str> = members.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "host/configuration.json".to_owned(),
            format!("sessions/{session}.json")
        ]
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
    );
    let document: serde_json::Value =
        serde_json::from_slice(&members[&format!("sessions/{session}.json")])
            .expect("a session export");
    assert_eq!(document["format"], "kalareach-session-export/1");
    let output: Vec<u8> = document["output"]["chunks"]
        .as_array()
        .expect("chunks")
        .iter()
        .flat_map(|chunk| {
            kr_protocol::scalars::from_base64url(chunk["base64url"].as_str().expect("text"))
                .expect("decodes")
        })
        .collect();
    assert_eq!(output, b"first line\r\nsecond line\r\n");

    // Nothing changed: a day later there is still one generation.
    timer.advance_day(Duration::from_secs(25 * 3600));
    rig.controller.backup().signals().produce.notify_one();
    within("the producer sees nothing changed", async {
        loop {
            let (_, detail) = rig.production_check().await;
            if detail.contains("nothing has changed") {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(
        rig.controller.backup().generations().expect("a read").len(),
        1
    );

    // A document changed in place makes the next one.
    let mut changed = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    changed.revision = 2;
    changed.storage.origin = Nullable::some(rig.served.origin().to_owned());
    kr_ipc::paths::write_owner_only_file(
        &kr_worker::config::document_path(&rig.host.environment()),
        kr_protocol::hostinfo::configuration::contents(&changed).as_bytes(),
    )
    .expect("the document");
    rig.controller.backup().signals().produce.notify_one();
    rig.until("the second generation is published", |rig| rig.published(2))
        .await;
    assert_eq!(
        rig.controller
            .backup()
            .setup()
            .expect("a read")
            .expect("a setup")
            .generation_counter,
        2
    );
}

/// The sizes a generation is held to are the convention's, which a restore accepts: an external
/// fact the producer and the restore must agree on, so the production value is written out here.
#[test]
fn the_producers_bounds_are_the_conventions() {
    assert_eq!(
        kr_controller::service::ProducerBounds::PRODUCTION,
        kr_controller::service::ProducerBounds {
            session_member_bytes: 192 * 1024 * 1024,
            configuration_member_bytes: 1024 * 1024,
            total_bytes: 3 * 512 * 1024 * 1024,
            members: 4096,
            disk_reserve_bytes: 1024 * 1024 * 1024,
        }
    );
}

/// Over the count the convention allows, the sessions after the newest ones that fit are left out of
/// the generation, and `kr doctor` says so. The bound is lowered through the same path production
/// takes. The control is the same host with both sessions inside the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_sessions_past_the_member_bound_are_left_out_and_the_doctor_says_so() {
    let timer = HeldTimer::held();
    let mut closed = Vec::new();
    let rig = Rig::start_with(Arrangement::NORMAL, Arc::clone(&timer), |host| {
        closed.push(closed_session(host, b"the older session\r\n", 8_000));
        closed.push(closed_session(host, b"the newer session\r\n", 9_000));
    })
    .await;
    let newer = closed[1];
    rig.controller
        .lower_producer_bounds(kr_controller::service::ProducerBounds {
            members: 2,
            ..kr_controller::service::ProducerBounds::PRODUCTION
        });
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    rig.set_up();
    rig.until("the generation is published", |rig| rig.published(1))
        .await;
    let members = opened_members(&rig, 1);
    let names: Vec<&String> = members.keys().collect();
    assert_eq!(
        names,
        [
            &"host/configuration.json".to_owned(),
            &format!("sessions/{newer}.json")
        ]
    );
    let (_, detail) = rig.production_check().await;
    assert!(
        detail.contains("1 closed sessions were left out"),
        "{detail}"
    );
}

/// Nothing is read or made while privacy mode is on, whatever the setup says, and a generation
/// follows when it is off again. A setup made while it is on is allowed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_is_made_while_privacy_mode_is_on_and_a_generation_follows_when_it_is_off() {
    let timer = HeldTimer::held();
    let rig = Rig::start_with(Arrangement::NORMAL, Arc::clone(&timer), |host| {
        closed_session(host, b"a session\r\n", 9_000);
    })
    .await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    assert!(rig.set_privacy(true).await);
    rig.set_up();
    within("the producer finds privacy mode on", async {
        loop {
            let (_, detail) = rig.production_check().await;
            if detail.contains("privacy mode is on") {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        rig.controller
            .backup()
            .generations()
            .expect("a read")
            .is_empty(),
        "nothing was made"
    );
    assert!(web.arrived().iter().all(|arrived| arrived.path != CREATE));

    within("privacy mode is turned off", async {
        while !rig.set_privacy(false).await {
            tokio::task::yield_now().await;
        }
    })
    .await;
    rig.until("a generation is published", |rig| rig.published(1))
        .await;
}

/// The members together never pass the total a restore accepts, the configuration among them: it
/// is counted first, and a session that no longer fits beside it is left out whole. The total here
/// takes the session and the configuration each alone, and not both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_configuration_is_counted_in_the_total_a_restore_accepts() {
    let timer = HeldTimer::held();
    let rig = Rig::start_with(Arrangement::NORMAL, Arc::clone(&timer), |host| {
        closed_session(host, b"a session\r\n", 9_000);
    })
    .await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    rig.set_up();
    rig.until("the first generation is published", |rig| rig.published(1))
        .await;
    let first = opened_members(&rig, 1);
    assert_eq!(first.len(), 2, "the control: both fit under the convention");
    let session: u64 = first
        .iter()
        .filter(|(name, _)| name.starts_with("sessions/"))
        .map(|(_, member)| member.len() as u64)
        .sum();
    let configuration = first["host/configuration.json"].len() as u64;

    // A day on and a changed document (of the same length): the next generation may hold the
    // session or the configuration, and not both.
    rig.controller
        .lower_producer_bounds(kr_controller::service::ProducerBounds {
            total_bytes: session + configuration - 1,
            ..kr_controller::service::ProducerBounds::PRODUCTION
        });
    let mut changed = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    changed.revision = 2;
    changed.storage.origin = Nullable::some(rig.served.origin().to_owned());
    assert_eq!(
        kr_protocol::hostinfo::configuration::contents(&changed).len() as u64,
        configuration,
        "the document keeps its length"
    );
    kr_ipc::paths::write_owner_only_file(
        &kr_worker::config::document_path(&rig.host.environment()),
        kr_protocol::hostinfo::configuration::contents(&changed).as_bytes(),
    )
    .expect("the document");
    timer.advance_day(Duration::from_secs(25 * 3600));
    rig.controller.backup().signals().produce.notify_one();
    timer.run_by_itself();
    rig.until("the second generation is published", |rig| rig.published(2))
        .await;
    let second = opened_members(&rig, 2);
    assert_eq!(
        second.keys().collect::<Vec<_>>(),
        ["host/configuration.json"],
        "the session no longer fits beside the configuration and is left out whole"
    );
    assert!(
        second
            .values()
            .map(|member| member.len() as u64)
            .sum::<u64>()
            < session + configuration
    );
}

/// Whether this user can write to a directory whose mode forbids it, as a superuser can: a test
/// that makes a write fail by a directory's mode has nothing to show then.
#[cfg(unix)]
fn can_write_through_a_forbidding_mode(directory: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o500))
        .expect("the directory is made read-only");
    let probe = directory.join("probe");
    let writes = std::fs::File::create(&probe).is_ok();
    let _ = std::fs::remove_file(&probe);
    if writes {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .expect("the directory is writable again");
    }
    writes
}

#[cfg(unix)]
fn allow_writing(directory: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        .expect("the directory is writable again");
}

/// A pass that fails waits out its delay before it looks again: the end of a pass does not wake
/// the producer. The directory the pass staged in is writable again by the time it could look, so a
/// pass that began at once would succeed and the test would see the generation.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_that_fails_waits_before_it_looks_again() {
    let timer = HeldTimer::held();
    let rig = Rig::start_with(Arrangement::NORMAL, Arc::clone(&timer), |host| {
        closed_session(host, b"a session\r\n", 9_000);
    })
    .await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    rig.production_looked(1).await;
    let staging = rig.controller.backup().staging_root();
    if can_write_through_a_forbidding_mode(&staging) {
        return;
    }
    rig.set_up();
    rig.production_looked(2).await;
    let (_, detail) = rig.production_check().await;
    assert!(detail.contains("the last pass failed"), "{detail}");
    allow_writing(&staging);
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        *rig.controller.production_looks().borrow(),
        2,
        "the producer looked again before its delay was over"
    );
    assert!(
        rig.controller
            .backup()
            .generations()
            .expect("a read")
            .is_empty()
    );

    // The delay ends, and the next pass makes the generation.
    timer.run_by_itself();
    rig.until("the generation is published", |rig| rig.published(1))
        .await;
}

/// No new generation is staged while the ciphertext of a finished one is still on the disk, and the
/// doctor says why; once it is released the next one is made. An unlink that fails stands for the
/// ciphertext that cannot be released.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_generation_is_staged_while_a_finished_ones_ciphertext_is_still_on_the_disk() {
    let timer = HeldTimer::held();
    let rig = Rig::start_with(Arrangement::NORMAL, Arc::clone(&timer), |host| {
        closed_session(host, b"a session\r\n", 9_000);
    })
    .await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    // Nothing to pack, so the producer leaves the first generation to the test.
    let nothing = kr_controller::service::ProducerBounds {
        configuration_member_bytes: 0,
        members: 0,
        ..kr_controller::service::ProducerBounds::PRODUCTION
    };
    rig.controller.lower_producer_bounds(nothing);
    rig.set_up();
    rig.production_looked(2).await;
    let (_, detail) = rig.production_check().await;
    assert!(detail.contains("no closed session"), "{detail}");

    web.fail(PART, 1, Moment::Slow);
    rig.admit_to_an_enrolled_archive(1, &[(1, plaintext(2048))]);
    within("the part is on its way", web.requests_reach(PART, 1)).await;
    let staging = rig.controller.backup().staging_root();
    let directory = std::fs::read_dir(&staging)
        .expect("the staging directory")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .expect("the generation's directory");
    if can_write_through_a_forbidding_mode(&directory) {
        web.release_held();
        return;
    }
    web.release_held();
    rig.until("the first generation is published", |rig| rig.published(1))
        .await;
    let staged = walk(&staging);
    assert!(staged > 0, "its ciphertext cannot be released");

    // Now there is something to pack, a day on.
    rig.controller
        .lower_producer_bounds(kr_controller::service::ProducerBounds::PRODUCTION);
    timer.advance_day(Duration::from_secs(25 * 3600));
    let looked = *rig.controller.production_looks().borrow();
    rig.controller.backup().signals().produce.notify_one();
    rig.production_looked(looked + 1).await;
    let (status, detail) = rig.production_check().await;
    assert_eq!(status, DoctorStatus::Warning);
    assert!(detail.contains("still on this host's disk"), "{detail}");
    assert_eq!(walk(&staging), staged, "nothing new was staged");
    assert_eq!(
        rig.controller.backup().generations().expect("a read").len(),
        1
    );

    // The directory can be written again; the release goes through and the next generation follows.
    allow_writing(&directory);
    timer.run_by_itself();
    rig.until("the second generation is published", |rig| rig.published(2))
        .await;
}

/// Privacy mode turned on while a pass is between two writes waits for the pass: the backup part
/// of the cleanup is reported outstanding and privacy mode is not turned off until the pass has
/// stopped and taken away what it wrote, and the generation that follows holds nothing from the
/// private time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn privacy_mode_turned_on_between_two_writes_of_a_pass_waits_for_the_pass() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    rig.production_looked(1).await;
    let staging = rig.controller.backup().staging_root();
    let pause = rig.controller.pause_the_next_pass_after_its_first_member();
    rig.set_up();
    within("the pass has staged its first member", pause.reached()).await;
    assert!(walk(&staging) > 0, "the pass wrote a file");

    assert!(rig.set_privacy(true).await, "privacy mode is turned on");
    let backup_outstanding = |report: &PrivacyReport| match &report.completion {
        PrivacyCompletion::Complete => false,
        PrivacyCompletion::Reconciling { outstanding }
        | PrivacyCompletion::Unavailable { outstanding, .. } => outstanding
            .iter()
            .any(|work| work.subsystem == kr_controller::backup::SUBSYSTEM_NAME),
    };
    assert!(
        backup_outstanding(&rig.privacy_report().await),
        "the backup cleanup is not complete while the pass can still write"
    );
    assert!(
        !rig.set_privacy(false).await,
        "privacy mode is not turned off while its cleanup is unfinished"
    );

    pause.resume();
    within("the backup cleanup completes", async {
        while backup_outstanding(&rig.privacy_report().await) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(walk(&staging), 0, "the pass took away what it wrote");
    assert!(
        rig.controller
            .backup()
            .generations()
            .expect("a read")
            .is_empty(),
        "nothing was admitted"
    );
    assert!(rig.privacy_complete().await);

    assert!(rig.set_privacy(false).await, "privacy mode is turned off");
    rig.until("a generation follows", |rig| rig.published(1))
        .await;
}

/// A daemon that stops tells a pass that is between two writes to stop: the pass writes no more,
/// takes away what it wrote and admits nothing, so ending the process never waits for it to read
/// and seal the rest of its members.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_between_two_writes_stops_when_the_daemon_is_told_to_stop() {
    let timer = HeldTimer::held();
    let rig = Rig::start(Arrangement::NORMAL, Arc::clone(&timer)).await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    rig.production_looked(1).await;
    let staging = rig.controller.backup().staging_root();
    let pause = rig.controller.pause_the_next_pass_after_its_first_member();
    rig.set_up();
    within("the pass has staged its first member", pause.reached()).await;
    assert!(walk(&staging) > 0, "the pass wrote a file");

    drop(rig.controller.stop_backup_production_when_dropped());
    pause.resume();
    within("the pass takes away what it wrote", async {
        while rig.controller.backup().production_running() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(walk(&staging), 0);
    assert!(
        rig.controller
            .backup()
            .generations()
            .expect("a read")
            .is_empty(),
        "nothing was admitted"
    );
}

/// A pass that would leave the disk its staging directory is on with less than its reserve free
/// stages nothing, and the doctor says why. The control is the same host with the reserve at what
/// the disk can give.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_that_would_fill_the_disk_stages_nothing() {
    let timer = HeldTimer::held();
    let rig = Rig::start_with(Arrangement::NORMAL, Arc::clone(&timer), |host| {
        closed_session(host, b"a session\r\n", 9_000);
    })
    .await;
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    rig.production_looked(1).await;
    rig.controller
        .lower_producer_bounds(kr_controller::service::ProducerBounds {
            disk_reserve_bytes: u64::MAX / 2,
            ..kr_controller::service::ProducerBounds::PRODUCTION
        });
    rig.set_up();
    rig.production_looked(2).await;
    let (status, detail) = rig.production_check().await;
    assert_eq!(status, DoctorStatus::Warning);
    assert!(detail.contains("too little room"), "{detail}");
    assert!(
        rig.controller
            .backup()
            .generations()
            .expect("a read")
            .is_empty()
    );
    assert_eq!(walk(&rig.controller.backup().staging_root()), 0);

    rig.controller
        .lower_producer_bounds(kr_controller::service::ProducerBounds::PRODUCTION);
    timer.run_by_itself();
    rig.until("the generation is published", |rig| rig.published(1))
        .await;
}

/// The files of one closed session's spool, which the test makes unreadable and readable again.
#[cfg(unix)]
fn set_spool_mode(
    host: &kr_ipc::testing::TempHost,
    session: kr_protocol::ids::SessionId,
    mode: u32,
) {
    use std::os::unix::fs::PermissionsExt as _;

    let spool = host.environment().session_spool(session);
    for entry in std::fs::read_dir(&spool).expect("the spool").flatten() {
        if entry.path().is_file() {
            std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(mode))
                .expect("the file's mode");
        }
    }
}

/// A closed session whose spool cannot be read is left out of a generation and counted in what the
/// generation was made from like every other: two days on, with nothing changed, no second
/// generation is made, however long the spool stays unreadable. Once the spool reads, the next day's
/// look makes the generation that holds the session. The control is the same host with the spool
/// readable, which packs it at once.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_that_cannot_be_read_makes_no_generation_each_day_and_is_tried_again() {
    let timer = HeldTimer::held();
    let mut closed = None;
    let rig = Rig::start_with(Arrangement::NORMAL, Arc::clone(&timer), |host| {
        let session = closed_session(host, b"a session\r\n", 9_000);
        set_spool_mode(host, session, 0o000);
        closed = Some(session);
    })
    .await;
    let session = closed.expect("a closed session");
    let spool = rig.host.environment().session_spool(session);
    let readable = std::fs::read_dir(&spool)
        .expect("the spool")
        .flatten()
        .any(|entry| std::fs::File::open(entry.path()).is_ok());
    if readable {
        // A user that reads anywhere (root): the failure cannot be made.
        return;
    }
    let web = Arc::clone(rig.served.web());
    within("the first status read", web.requests_reach(STATUS, 1)).await;
    rig.set_up();
    rig.until("the first generation is published", |rig| rig.published(1))
        .await;
    let first = opened_members(&rig, 1);
    assert_eq!(
        first.keys().collect::<Vec<_>>(),
        ["host/configuration.json"],
        "the session that cannot be read is left out"
    );
    let (_, detail) = rig.production_check().await;
    assert!(detail.contains("could not be read"), "{detail}");

    // Two days on, nothing changed: no second generation, and the doctor still says why.
    for _ in 0..2 {
        timer.advance_day(Duration::from_secs(25 * 3600));
        let looked = *rig.controller.production_looks().borrow();
        rig.controller.backup().signals().produce.notify_one();
        rig.production_looked(looked + 1).await;
        assert_eq!(
            rig.controller.backup().generations().expect("a read").len(),
            1,
            "a spool that stays unreadable makes no generation"
        );
        let (_, detail) = rig.production_check().await;
        assert!(detail.contains("nothing has changed"), "{detail}");
        assert!(detail.contains("could not be read"), "{detail}");
    }

    // The spool reads again: the next day's look finds it and makes the generation.
    set_spool_mode(&rig.host, session, 0o600);
    timer.advance_day(Duration::from_secs(25 * 3600));
    timer.run_by_itself();
    rig.controller.backup().signals().produce.notify_one();
    rig.until("the second generation is published", |rig| rig.published(2))
        .await;
    let second = opened_members(&rig, 2);
    assert!(
        second.contains_key(&format!("sessions/{session}.json")),
        "the session is in the generation made once it could be read"
    );
}

// ---------------------------------------------------------------------------------------------
// The owner sets backups up.
// ---------------------------------------------------------------------------------------------

/// What the owner's command sends and reads, as the daemon is asked.
impl Rig {
    /// What `kr backup setup` would send for `archive`: a kit, the sealed bundle and the call, built
    /// from the keys `backup.status` names.
    fn prepared_setup(
        &self,
        archive: ArchiveId,
        replace: bool,
    ) -> kr_client::recovery::PreparedSetup {
        let producer = daemon_producer(&self.host);
        kr_client::recovery::prepare_setup(&kr_client::recovery::SetupInputs {
            origin: &self.origin(),
            archive_id: archive,
            writer: (self.writer.key_id(), *self.writer.public()),
            producer: (producer.key_id(), *producer.public()),
            enabled_at_ms: kr_ipc::now_ms(),
            replace,
        })
        .expect("a setup is prepared")
    }

    /// `backup.enable`, as the command's connection makes it.
    async fn enable(&self, params: &BackupEnableParams) -> BackupEnableResult {
        enable_at(&self.client_endpoint, self.host.environment_id(), params).await
    }

    /// `backup.enable` in a task of its own, for a call the test watches while it runs.
    fn enable_in_the_background(
        &self,
        params: &BackupEnableParams,
    ) -> tokio::task::JoinHandle<BackupEnableResult> {
        let endpoint = self.client_endpoint.clone();
        let environment = self.host.environment_id();
        let params = params.clone();
        tokio::spawn(async move { enable_at(&endpoint, environment, &params).await })
    }

    /// `backup.status`.
    async fn backup_status(&self) -> BackupStatusResult {
        let mut client = LocalClient::connect(&self.client_endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        client
            .request(Method::BackupStatus, &BackupStatusParams {})
            .await
            .expect("the call reaches the daemon")
            .expect("backup.status is served on the local socket")
            .to_typed()
            .expect("a result of the declared shape")
    }

    /// Has the carrier look at its work `count` times, and waits until it has. The waits are on
    /// the passes the carrier finishes, and not on a number of turns of the scheduler.
    async fn carrier_passes(&self, count: u64) {
        let mut passes = self
            .controller
            .backup_runtime()
            .expect("a carrier")
            .passes();
        let before = *passes.borrow_and_update();
        for step in 1..=count {
            self.controller.backup().signals().work.notify_one();
            within("the carrier's pass", async {
                while *passes.borrow_and_update() < before + step {
                    passes.changed().await.expect("the carrier is running");
                }
            })
            .await;
        }
    }

    /// The paths of the requests the stand-in has been given, in order, from `from` on.
    fn requested_since(&self, from: usize) -> Vec<String> {
        self.served.web().arrived()[from..]
            .iter()
            .map(|arrived| arrived.path.clone())
            .collect()
    }
}

async fn enable_at(
    endpoint: &kr_ipc::paths::Endpoint,
    environment: kr_protocol::ids::EnvironmentId,
    params: &BackupEnableParams,
) -> BackupEnableResult {
    let mut client = LocalClient::connect(endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    client
        .mutate(
            Method::BackupEnable,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment),
            params,
        )
        .await
        .expect("the call reaches the daemon")
        .expect("backup.enable answers")
        .to_typed()
        .expect("a result of the declared shape")
}

fn archive_two() -> ArchiveId {
    ArchiveId::new(Uuid::from_bytes([0x22; 16]))
}

/// A host with no setup, no enrolment and backup storage off, and a closed session to back up.
async fn a_host_to_set_up(timer: &Arc<HeldTimer>) -> (Rig, kr_protocol::ids::SessionId) {
    let mut closed = None;
    let rig = Rig::start_with(
        Arrangement {
            enrolled: false,
            backup_on: false,
            ..Arrangement::NORMAL
        },
        Arc::clone(timer),
        |host| closed = Some(closed_session(host, b"a line\r\n", 9_000)),
    )
    .await;
    let session = closed.expect("a closed session");
    within(
        "the first status read",
        rig.served.web().requests_reach(STATUS, 1),
    )
    .await;
    (rig, session)
}

/// The owner's setup through the daemon, as the command makes it: the bundle is written to the
/// service first, the writer is enrolled by the host's owner key, managed backup storage is turned
/// on, and then the setup is recorded; the host then makes a backup that the recovery recipient the
/// kit's seed derives opens, with the producer and the writer the bundle names. A call made again
/// with the same bytes is answered from what the first left, and sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owners_setup_writes_the_bundle_then_enrols_the_writer_and_the_host_then_backs_up() {
    let timer = HeldTimer::held();
    let (rig, session) = a_host_to_set_up(&timer).await;
    let web = Arc::clone(rig.served.web());

    let before = rig.backup_status().await;
    assert_eq!(before.service.0.as_deref(), Some(rig.origin().as_str()));
    assert_eq!(before.sign_in, BackupSignIn::Usable);
    assert!(matches!(before.setup, BackupSetupState::None {}));
    let keys = before.keys.0.expect("the host's keys");
    assert_eq!(keys.writer_key_id, rig.writer.key_id());
    assert_eq!(keys.producer_key_id, daemon_producer(&rig.host).key_id());
    assert!(matches!(
        before.storage,
        BackupStorageState::Read {
            backup_on: false,
            ..
        }
    ));

    let made = rig.prepared_setup(archive_id(), false);
    let asked = web.arrived().len();
    let result = rig.enable(&made.params).await;
    assert_eq!(
        result,
        BackupEnableResult::Enabled {
            archive_id: archive_id(),
            kit_fingerprint: made.kit_fingerprint.clone(),
            enabled_at_ms: made.params.enabled_at_ms,
        }
    );

    // The order the specification gives: the bundle, then the writer, then storage on.
    let paths = rig.requested_since(asked);
    let at = |wanted: &str, skip: usize| {
        paths
            .iter()
            .enumerate()
            .filter(|(_, path)| path.as_str() == wanted)
            .nth(skip)
            .map(|(index, _)| index)
            .unwrap_or_else(|| panic!("no {wanted} in {paths:?}"))
    };
    assert!(at(SYNC, 0) < at(MANIFEST, 0), "{paths:?}");
    assert!(at(MANIFEST, 0) < at(RETENTION, 0), "{paths:?}");
    assert_eq!(
        web.bundle(&made.params.bundle_locator.to_string()),
        Some(made.params.sealed_bundle.as_slice().to_vec())
    );
    let sent = web.arrived();
    let signer = |path: &str| {
        sent[asked..]
            .iter()
            .find(|arrived| arrived.path == path)
            .and_then(|arrived| arrived.signed_by)
            .expect("a signed request")
    };
    let owner = kr_crypto::store::load_device_keys(
        open_store_in(&rig.host.environment().secrets_dir())
            .expect("the daemon's secret store")
            .store
            .as_ref(),
        &kr_controller::service::net::device_key_scope(rig.host.environment_id()),
    )
    .expect("the device keys read")
    .expect("the daemon made its device keys")
    .authorisation;
    let (kind, key) = signer(SYNC);
    assert_eq!(
        kind,
        kr_protocol::service::ServiceRequestSigner::Installation
    );
    assert_ne!(
        key,
        *rig.writer.public(),
        "the bundle is not signed with the writer"
    );
    assert_ne!(key, *owner.public(), "nor with the owner's key");
    assert_eq!(
        signer(MANIFEST),
        (
            kr_protocol::service::ServiceRequestSigner::Host,
            *owner.public()
        ),
        "the enrolment is the host's owner key's"
    );

    // Recorded, with the writer enrolled for the archive.
    let row = rig
        .controller
        .backup()
        .setup()
        .expect("a read")
        .expect("a setup");
    assert_eq!(row.record.archive_id, archive_id());
    assert_eq!(row.record.kit_fingerprint, made.kit_fingerprint);
    assert!(
        rig.controller
            .backup()
            .authorised_writers()
            .expect("a read")
            .contains(&(archive_id(), rig.writer.key_id()))
    );
    let after = rig.backup_status().await;
    assert!(matches!(
        after.setup,
        BackupSetupState::Committed { unusable, .. } if unusable.0.is_none()
    ));
    let (_, detail) = rig.production_check().await;
    assert!(detail.contains(&made.kit_fingerprint), "{detail}");

    // And the host backs up: the generation opens as the recovery recipient opens it.
    rig.until("the first generation is published", |rig| rig.published(1))
        .await;
    let kit = kr_client::recovery::parse_kit(&made.kit).expect("the kit");
    let seed = kr_crypto::kdf::RecoverySeed::from_kit(&kit).expect("the seed");
    let recipient = seed.recipient().expect("the recipient");
    let members = opened_members_as(
        &rig,
        1,
        &kr_crypto::backup::ArchiveReader::Recovery(&recipient),
    );
    assert!(members.contains_key(&format!("sessions/{session}.json")));

    // Made again with the same bytes: answered from the record, with nothing sent.
    let asked = web.arrived().len();
    assert_eq!(rig.enable(&made.params).await, result);
    assert_eq!(
        web.arrived().len(),
        asked,
        "a repeat after success sends nothing"
    );
}

/// A bundle the service refuses is not followed by the writer's enrolment or a recorded setup, and
/// a call made again once the service takes it finishes the setup.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_the_service_refuses_is_followed_by_no_enrolment_and_no_setup() {
    let timer = HeldTimer::held();
    let (rig, _) = a_host_to_set_up(&timer).await;
    let web = Arc::clone(rig.served.web());
    let made = rig.prepared_setup(archive_id(), false);

    web.refuse_bundle_writes(true);
    assert_eq!(
        rig.enable(&made.params).await,
        BackupEnableResult::Declined {
            cause: BackupEnableCause::NoAllowance {}
        }
    );
    assert_eq!(
        web.requests_to(MANIFEST),
        0,
        "no enrolment follows a refused bundle"
    );
    assert!(rig.controller.backup().setup().expect("a read").is_none());
    let (_, detail) = rig.production_check().await;
    assert!(
        detail.contains("the account has no backup allowance"),
        "{detail}"
    );
    let status = rig.backup_status().await;
    assert!(status.last_attempt.0.is_some());

    // The control: the same kit offered again once the service takes the bundle.
    web.refuse_bundle_writes(false);
    assert!(matches!(
        rig.enable(&made.params).await,
        BackupEnableResult::Enabled { .. }
    ));
    assert!(rig.backup_status().await.last_attempt.0.is_none());
    assert_eq!(web.requests_to(MANIFEST), 1);
}

/// A write whose answer was lost is settled by reading the bundle: the same bytes are there, and
/// the call goes on in one try. A write that never reached the service is an unknown outcome the
/// repeat finishes, under the same request identity, and nothing is recorded in between.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_write_whose_answer_was_lost_is_settled_by_the_bundle_and_one_that_never_left_is_made_again()
 {
    let timer = HeldTimer::held();
    let (rig, _) = a_host_to_set_up(&timer).await;
    let web = Arc::clone(rig.served.web());

    // Applied, and the answer lost.
    let made = rig.prepared_setup(archive_id(), false);
    web.fail(SYNC, 1, Moment::After);
    assert!(matches!(
        rig.enable(&made.params).await,
        BackupEnableResult::Enabled { .. }
    ));
    assert_eq!(
        web.requests_to(SYNC),
        2,
        "the write, and the read that found it applied"
    );

    // Never left: nothing at the service, an unknown outcome, nothing recorded.
    let (other, _) = a_host_to_set_up(&HeldTimer::held()).await;
    let web = Arc::clone(other.served.web());
    let made = other.prepared_setup(archive_id(), false);
    web.fail(SYNC, 1, Moment::Before);
    assert!(matches!(
        other.enable(&made.params).await,
        BackupEnableResult::Unknown { .. }
    ));
    assert!(other.controller.backup().setup().expect("a read").is_none());
    assert_eq!(web.requests_to(MANIFEST), 0);
    assert!(matches!(
        other.enable(&made.params).await,
        BackupEnableResult::Enabled { .. }
    ));
    let identities: Vec<String> = web
        .arrived()
        .iter()
        .filter(|arrived| arrived.path == SYNC)
        .filter_map(|arrived| {
            arrived.body["exchange"]["request_id"]
                .as_str()
                .map(str::to_owned)
        })
        .collect();
    assert_eq!(identities.len(), 2);
    assert_eq!(
        identities[0], identities[1],
        "the repeat carries the same identity"
    );
}

/// An enrolment whose answer was lost is an unknown outcome with nothing recorded, and the repeat
/// sends the same bytes: the service answers a different record at the same revision `FORBIDDEN`,
/// so a repeat that finishes is a repeat that sent the same bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrolment_whose_answer_was_lost_is_sent_again_with_the_same_bytes() {
    let timer = HeldTimer::held();
    let (rig, _) = a_host_to_set_up(&timer).await;
    let web = Arc::clone(rig.served.web());
    let made = rig.prepared_setup(archive_id(), false);

    web.fail(MANIFEST, 1, Moment::After);
    assert!(matches!(
        rig.enable(&made.params).await,
        BackupEnableResult::Unknown { .. }
    ));
    assert!(rig.controller.backup().setup().expect("a read").is_none());
    // Not an instant later in the repeat: the same bytes are `unchanged`, a new instant is refused.
    assert!(matches!(
        rig.enable(&made.params).await,
        BackupEnableResult::Enabled { .. }
    ));
    let bodies: Vec<serde_json::Value> = web
        .arrived()
        .iter()
        .filter(|arrived| arrived.path == MANIFEST)
        .map(|arrived| arrived.body["enrol"]["record"]["payload"].clone())
        .collect();
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0], bodies[1]);
}

/// Another archive is refused without `replace` and sends nothing; a call that is not the setup's
/// own keys is refused; the host's keys are named by `backup.status`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_archive_is_refused_without_replace_and_a_call_naming_other_keys_is_refused() {
    let timer = HeldTimer::held();
    let (rig, _) = a_host_to_set_up(&timer).await;
    let web = Arc::clone(rig.served.web());
    let first = rig.prepared_setup(archive_id(), false);
    assert!(matches!(
        rig.enable(&first.params).await,
        BackupEnableResult::Enabled { .. }
    ));

    let asked = web.arrived().len();
    let second = rig.prepared_setup(archive_two(), false);
    assert_eq!(
        rig.enable(&second.params).await,
        BackupEnableResult::Declined {
            cause: BackupEnableCause::AlreadySetUp {}
        }
    );
    assert_eq!(web.arrived().len(), asked, "nothing was sent");

    // Keys other than the ones the host holds.
    let mut wrong = rig.prepared_setup(archive_two(), true);
    wrong.params.writer_key_id = kr_crypto::keys::key_id(
        kr_protocol::pairing::KeyPurpose::Authorisation,
        AuthorisationKeyPair::generate()
            .expect("a key")
            .public()
            .as_bytes(),
    );
    assert_eq!(
        rig.enable(&wrong.params).await,
        BackupEnableResult::Declined {
            cause: BackupEnableCause::KeysChanged {}
        }
    );
    assert_eq!(web.arrived().len(), asked);
}

/// `backup.status` and `kr doctor` tell a setup that is under way: while the call waits at the
/// service, while a repeat waits for the mutex after the first call failed (the first call's entry
/// is gone, the repeat's is not), and while the call is before its local transaction. The control is
/// the status when no call is running.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_setup_under_way_is_told_by_status_and_the_doctor_at_each_point_of_the_call() {
    let timer = HeldTimer::held();
    let (rig, _) = a_host_to_set_up(&timer).await;
    let web = Arc::clone(rig.served.web());
    let made = rig.prepared_setup(archive_id(), false);
    assert!(matches!(
        rig.backup_status().await.setup,
        BackupSetupState::None {}
    ));

    // The first call is held at the service; a repeat waits behind it for the mutex.
    web.fail(SYNC, 1, Moment::Hold);
    let first = rig.enable_in_the_background(&made.params);
    within("the bundle write", web.requests_reach(SYNC, 1)).await;
    let second = rig.enable_in_the_background(&made.params);
    within("both calls are told", async {
        loop {
            if let BackupSetupState::InProgress { kit_fingerprints } =
                rig.backup_status().await.setup
                && kit_fingerprints.len() == 2
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let (_, detail) = rig.production_check().await;
    assert!(
        detail.contains("a setup is in progress with the kit"),
        "{detail}"
    );

    // The first call fails; the repeat gets its turn and is held at the enrolment, so it is still
    // under way when the first call's entry is gone, and is told alone.
    web.fail(MANIFEST, 1, Moment::Hold);
    web.release_held();
    assert!(matches!(
        first.await.expect("the first call ends"),
        BackupEnableResult::Unknown { .. }
    ));
    within("the repeat's enrolment", web.requests_reach(MANIFEST, 1)).await;
    match rig.backup_status().await.setup {
        BackupSetupState::InProgress { kit_fingerprints } => assert_eq!(
            kit_fingerprints,
            [made.kit_fingerprint.clone()],
            "the repeat alone is told"
        ),
        other => panic!("the repeat is under way, and the status says {other:?}"),
    }
    let (_, detail) = rig.production_check().await;
    assert!(
        detail.contains("a setup is in progress with the kit"),
        "{detail}"
    );
    web.release_held();
    let finished = second.await.expect("the repeat ends");
    assert!(matches!(finished, BackupEnableResult::Enabled { .. }));
    assert!(matches!(
        rig.backup_status().await.setup,
        BackupSetupState::Committed { .. }
    ));

    // Held before its local transaction: the enrolment waits at the service.
    let (other, _) = a_host_to_set_up(&HeldTimer::held()).await;
    let web = Arc::clone(other.served.web());
    let made = other.prepared_setup(archive_id(), false);
    web.fail(MANIFEST, 1, Moment::Hold);
    let call = other.enable_in_the_background(&made.params);
    within("the enrolment", web.requests_reach(MANIFEST, 1)).await;
    assert!(matches!(
        other.backup_status().await.setup,
        BackupSetupState::InProgress { .. }
    ));
    assert!(other.controller.backup().setup().expect("a read").is_none());
    web.release_held();
    let _ = call.await.expect("the call ends");
}

/// A call that waits for another keeps the account it was admitted under. The host signs in as
/// another account while the call waits behind one that is held at the service: when its turn comes
/// no request of it leaves under the new account, and nothing is recorded. A call that took its
/// account when its turn came would write the bundle under the account that signed in meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_that_waits_for_another_keeps_the_account_it_was_admitted_under() {
    let timer = HeldTimer::held();
    let (rig, _) = a_host_to_set_up(&timer).await;
    let web = Arc::clone(rig.served.web());
    web.issue_token("the-second-token", "account-two", &["backup.write"]);
    let made = rig.prepared_setup(archive_id(), false);

    web.fail(SYNC, 1, Moment::Hold);
    let first = rig.enable_in_the_background(&made.params);
    within("the bundle write", web.requests_reach(SYNC, 1)).await;
    let second = rig.enable_in_the_background(&made.params);
    within("both calls are told", async {
        loop {
            if let BackupSetupState::InProgress { kit_fingerprints } =
                rig.backup_status().await.setup
                && kit_fingerprints.len() == 2
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;

    rig.sign_in_with("account-two", "the-second-token").await;
    web.release_held();
    let another_account = BackupEnableResult::Declined {
        cause: BackupEnableCause::AnotherAccount {},
    };
    assert_eq!(first.await.expect("the first call ends"), another_account);
    assert_eq!(second.await.expect("the second call ends"), another_account);
    assert_eq!(
        web.requests_to(SYNC),
        1,
        "nothing of either call left under the account that signed in"
    );
    assert!(rig.controller.backup().setup().expect("a read").is_none());
    assert!(
        web.bundle(&made.params.bundle_locator.to_string())
            .is_none()
    );
}

/// A bundle write the service answers with a delay is not followed by the read that settles it
/// until the delay has passed: the call ends with the delay, and the service is asked nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delay_the_service_names_to_the_bundle_write_is_owed_to_the_read_that_settles_it() {
    let timer = HeldTimer::held();
    let (rig, _) = a_host_to_set_up(&timer).await;
    let web = Arc::clone(rig.served.web());
    let made = rig.prepared_setup(archive_id(), false);
    web.fail(
        SYNC,
        1,
        Moment::Refuse {
            status: 429,
            code: "RATE_LIMITED",
            retry_after_seconds: Some(30),
        },
    );
    let result = rig.enable(&made.params).await;
    assert!(
        matches!(
            &result,
            BackupEnableResult::Unknown { retry_after_seconds }
                if retry_after_seconds.0.is_some()
        ),
        "{result:?}"
    );
    assert_eq!(
        web.requests_to(SYNC),
        1,
        "the read that settles the write waits for the delay"
    );
}

/// The causes of a bundle write the service refuses, each with its own answer and nothing recorded
/// or enrolled: a locator that holds another bundle, and a token the service does not take as an
/// account's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_conflict_and_a_token_the_service_does_not_take_are_told_apart() {
    let timer = HeldTimer::held();
    let (rig, _) = a_host_to_set_up(&timer).await;
    let web = Arc::clone(rig.served.web());
    let made = rig.prepared_setup(archive_id(), false);

    web.put_bundle(
        &made.params.bundle_locator.to_string(),
        ACCOUNT,
        vec![1, 2, 3],
    );
    assert_eq!(
        rig.enable(&made.params).await,
        BackupEnableResult::Declined {
            cause: BackupEnableCause::BundleConflict {}
        }
    );

    let other = rig.prepared_setup(archive_two(), false);
    web.expire_token(TOKEN);
    assert_eq!(
        rig.enable(&other.params).await,
        BackupEnableResult::Declined {
            cause: BackupEnableCause::TokenNotAccepted {}
        }
    );
    assert_eq!(web.requests_to(MANIFEST), 0, "nothing was enrolled");
    assert!(rig.controller.backup().setup().expect("a read").is_none());
}

/// A host signed in as another account while a call runs commits nothing: the request that carries
/// a token is stopped before it leaves, and the enrolment, which carries none, is followed by a
/// comparison of the account before the setup is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_as_another_account_during_the_call_stops_it_before_anything_is_recorded() {
    // During the bundle write, which the service has applied and not yet answered: the enrolment
    // goes out, which carries no token, and the request that follows it, which does, does not.
    let timer = HeldTimer::held();
    let (rig, _) = a_host_to_set_up(&timer).await;
    let web = Arc::clone(rig.served.web());
    let made = rig.prepared_setup(archive_id(), false);
    web.fail(SYNC, 1, Moment::Slow);
    let call = rig.enable_in_the_background(&made.params);
    within("the bundle write", web.requests_reach(SYNC, 1)).await;
    rig.sign_in_as("account-2").await;
    web.release_held();
    assert_eq!(
        call.await.expect("the call ends"),
        BackupEnableResult::Declined {
            cause: BackupEnableCause::AnotherAccount {}
        }
    );
    assert_eq!(
        web.requests_to(MANIFEST),
        1,
        "the enrolment carries no token"
    );
    assert_eq!(
        web.requests_to(RETENTION),
        0,
        "no request that carries a token left under the account signed in since"
    );
    assert!(rig.controller.backup().setup().expect("a read").is_none());

    // During the last request, which the service has applied and not yet answered: every request
    // has left under the account the call began under, and the account is compared again before
    // anything is recorded.
    let (rig, _) = a_host_to_set_up(&HeldTimer::held()).await;
    let web = Arc::clone(rig.served.web());
    let made = rig.prepared_setup(archive_id(), false);
    web.fail(RETENTION, 1, Moment::Slow);
    let call = rig.enable_in_the_background(&made.params);
    within("the retention change", web.requests_reach(RETENTION, 1)).await;
    rig.sign_in_as("account-2").await;
    web.release_held();
    assert_eq!(
        call.await.expect("the call ends"),
        BackupEnableResult::Declined {
            cause: BackupEnableCause::AnotherAccount {}
        }
    );
    assert!(rig.controller.backup().setup().expect("a read").is_none());
}

/// `backup.status` says why a setup that is recorded cannot make backups: the account signed in is
/// not the one it belongs to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_status_of_a_setup_says_when_another_account_is_signed_in() {
    let timer = HeldTimer::held();
    let (rig, _) = a_host_to_set_up(&timer).await;
    let made = rig.prepared_setup(archive_id(), false);
    assert!(matches!(
        rig.enable(&made.params).await,
        BackupEnableResult::Enabled { .. }
    ));
    rig.sign_in_as("account-2").await;
    assert!(matches!(
        rig.backup_status().await.setup,
        BackupSetupState::Committed { unusable, .. }
            if unusable.0 == Some(BackupUnusable::Account)
    ));
}

/// A replacement commits the setup of another archive, retires the earlier archive's writer and
/// takes back what the earlier archive had not finished; the earlier archive's published
/// generations and objects stay at the service. A replacement that fails before it commits leaves
/// all of it as it was, and the carrier still bound to the earlier account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replacement_retires_the_earlier_writer_and_takes_back_its_unfinished_work_and_a_failed_one_changes_nothing()
 {
    let timer = HeldTimer::held();
    let (rig, _) = a_host_to_set_up(&timer).await;
    let web = Arc::clone(rig.served.web());
    let first = rig.prepared_setup(archive_id(), false);
    assert!(matches!(
        rig.enable(&first.params).await,
        BackupEnableResult::Enabled { .. }
    ));
    rig.until("the first generation is published", |rig| rig.published(1))
        .await;

    // Work of the earlier archive that has not left: its upload waits at the service.
    let sent_before = web.requests_to(PART) + web.requests_to(COMPLETE);
    web.fail(CREATE, 1, Moment::Hold);
    rig.admit_to_an_enrolled_archive(2, &[(2, plaintext(2048))]);
    within("the upload begins", web.requests_reach(CREATE, 2)).await;
    let epoch = rig.controller.backup().binding().read().epoch;

    // A replacement the service refuses changes nothing.
    let second = rig.prepared_setup(archive_two(), true);
    web.refuse_bundle_writes(true);
    assert!(matches!(
        rig.enable(&second.params).await,
        BackupEnableResult::Declined { .. }
    ));
    web.refuse_bundle_writes(false);
    assert_eq!(rig.controller.backup().binding().read().epoch, epoch);
    assert_eq!(
        rig.controller
            .backup()
            .setup()
            .expect("a read")
            .expect("a setup")
            .record
            .archive_id,
        archive_id()
    );
    assert_eq!(
        rig.controller
            .backup()
            .generation(archive_id(), BackupGeneration::new(2))
            .expect("a read")
            .expect("the generation")
            .production,
        Production::Producing
    );

    // The replacement that goes through.
    let result = rig.enable(&second.params).await;
    assert!(
        matches!(result, BackupEnableResult::Enabled { .. }),
        "{result:?}"
    );
    assert!(rig.controller.backup().binding().read().epoch > epoch);
    assert_eq!(
        rig.controller
            .backup()
            .setup()
            .expect("a read")
            .expect("a setup")
            .record
            .archive_id,
        archive_two()
    );
    let writers = rig
        .controller
        .backup()
        .authorised_writers()
        .expect("a read");
    assert!(writers.contains(&(archive_two(), rig.writer.key_id())));
    assert!(
        !writers.contains(&(archive_id(), rig.writer.key_id())),
        "the earlier archive's writer is retired"
    );
    assert_eq!(
        rig.controller
            .backup()
            .generation(archive_id(), BackupGeneration::new(2))
            .expect("a read")
            .expect("the generation")
            .production,
        Production::Cancelled,
        "what the earlier archive had not finished is taken back"
    );
    // What was published stays published, and its objects stay at the service.
    assert!(rig.published(1));
    web.release_held();
    timer.run_by_itself();
    rig.carrier_passes(2).await;
    assert_eq!(
        web.requests_to(PART) + web.requests_to(COMPLETE),
        sent_before,
        "nothing of the earlier archive's second generation is sent"
    );
}

/// A replacement under another account sends no request for the earlier archive, and records no
/// deletion of its objects as done: the service answers "not found" to the other account for an
/// object the first account paid for, and a deletion recorded then would be one that never
/// happened. The account's recorded snapshots are lower than the generations the earlier archive
/// holds, which is when a host that kept deleting would delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replacement_under_another_account_sends_nothing_for_the_earlier_archive() {
    let timer = HeldTimer::held();
    let (rig, _) = a_host_to_set_up(&timer).await;
    let web = Arc::clone(rig.served.web());
    web.issue_token("the-second-token", "account-two", &["backup.write"]);
    let first = rig.prepared_setup(archive_id(), false);
    assert!(matches!(
        rig.enable(&first.params).await,
        BackupEnableResult::Enabled { .. }
    ));
    rig.until("the first generation is published", |rig| rig.published(1))
        .await;
    rig.admit_to_an_enrolled_archive(2, &[(2, plaintext(2048))]);
    rig.until("the second generation is published", |rig| rig.published(2))
        .await;
    rig.admit_to_an_enrolled_archive(3, &[(3, plaintext(2048))]);
    rig.until("the third generation is published", |rig| rig.published(3))
        .await;

    // Another account signs in and replaces the setup; its snapshots would delete the oldest.
    rig.sign_in_with("account-two", "the-second-token").await;
    let second = rig.prepared_setup(archive_two(), true);
    let result = rig.enable(&second.params).await;
    assert!(
        matches!(result, BackupEnableResult::Enabled { .. }),
        "{result:?}"
    );
    let asked = web.arrived().len();
    web.set_daily_snapshots(2);
    timer.run_by_itself();
    // The carrier looks at its work again, twice, and asks the service what the account records:
    // that is the pass in which a host that kept deleting would delete.
    rig.carrier_passes(2).await;
    let since = rig.requested_since(asked);
    assert!(
        since.iter().any(|path| path == STATUS),
        "the pass asked the service what the account records: {since:?}"
    );
    assert!(
        since.iter().all(|path| path != DELETE),
        "no deletion left for the earlier archive: {since:?}"
    );
    for generation in 1..=3 {
        assert!(
            rig.controller
                .backup()
                .objects(archive_id(), BackupGeneration::new(generation))
                .expect("a read")
                .iter()
                .all(|object| object.released_at_ms.is_none()),
            "no deletion of generation {generation} is recorded as done"
        );
    }
}
