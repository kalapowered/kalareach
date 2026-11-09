//! `kr backup restore`, against a real control daemon, the storage service stand-in and the real
//! `kr` binary.
//!
//! A fresh host with only the recovery kit reads the archive back through its own account, the
//! bundle authenticates under the kit, the writers and producers it trusts come from that bundle
//! alone, and the data comes back as readable files while no key, grant or device does.
//!
//! Everything but the service is real. The service is the stand-in (`kr-service-stand-in`), which
//! answers as the deployed Worker does and is held to a recording of it. The archive and the bundle
//! are sealed here with the production primitives, in the convention a host's producer follows, and
//! put into the stand-in as the owner's device and the writer would.
//!
//! The cases run on Windows as well as on Unix, by the way the command is used there: the kit is
//! named with `--kit-file` or piped, and a plan is confirmed with `--confirm-plan`. A case that
//! needs what only Unix has (a terminal that is asked, a signal, a file's mode, a link made with
//! Unix's call, a pipe on the file system, the rename of a folder a run holds open) is Unix's
//! alone, and the file says so at each.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_client::recovery::fresh_locator;
use kr_client::services::account::{
    AccountIdentity, AccountService, AccountToken, AccountTokenSource, AccountUsage,
    AuthorisationGrant, Exchanged, IssuedGrant, RefreshToken, Refreshed, StoredGrant,
};
use kr_client::services::{
    BackupManifestService, HttpDeadlines, HttpService, ManagedBackupManifestService, ServiceFuture,
    ServiceHttp, ServiceSigner, managed_response_limits,
};
use kr_controller::account::{HostAccount, Service};
use kr_controller::error::ControllerError;
use kr_controller::quiet::Timer;
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::singleton::SingletonLock;
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_controller::testing::HeldTimer;
use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CollectionKind, Material, ObjectSource, seal_archive,
    stage_object,
};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_crypto::sign::{SigningTranscript, sign};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::archive::{
    ArchiveCheckpoint, BACKUP_PUBLICATION_DOMAIN, BACKUP_WRITER_DOMAIN,
    BackupGenerationPublication, BackupGenerationPublicationPayload, BackupWriterRecord,
    BackupWriterRecordPayload, CollectionLocator, RECOVERY_BUNDLE_SCHEMA_VERSION, RecoveryBundle,
    RecoveryContext, TrustedProducer, TrustedWriter,
};
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, BuildId, DeviceId,
};
use kr_protocol::scalars::{AuthorisationKey, Nullable, Signature64, TimestampMs, U64, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{ACCOUNT, Moment, Served, ServiceWeb, TOKEN, serve};
use serde_json::Value;

mod support;

use support::kr;

/// How long a wait for something to happen is given. It fails when the thing never happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// Where the stand-in is asked for a stored object, and for the recovery bundle.
const OBJECT_READ: &str = "/api/storage/object/read";
const SYNC: &str = "/api/sync/exchange";

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn id(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn archive() -> ArchiveId {
    ArchiveId::new(id(0x11))
}

/* -------------------------------------------------------------------------- */
/* The owner's side: what a host's producer and the owner's device would make  */
/* -------------------------------------------------------------------------- */

/// The owner's keys, the seed, and the collection a host backs up to.
struct World {
    seed: RecoverySeed,
    locator: String,
    owner: Arc<Signer>,
    writer: Arc<Signer>,
    writer_pair: AuthorisationKeyPair,
    producer: StoredEnvelopeKeyPair,
}

/// A key that signs service requests as one kind of signer.
#[derive(Debug)]
struct Signer {
    kind: ServiceRequestSigner,
    key: AuthorisationKeyPair,
}

impl ServiceSigner for Signer {
    fn signer(&self) -> ServiceRequestSigner {
        self.kind
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.key.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let transcript =
            SigningTranscript::from_canonical_bytes(self.kind.domain(), message.to_vec())
                .expect("a transcript");
        Ok(sign(&self.key, &transcript).expect("a signature"))
    }
}

/// The account token the stand-in knows, as a source hands it over.
#[derive(Debug)]
struct Bearer;

impl AccountTokenSource for Bearer {
    fn token<'a>(&'a self, _scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        Box::pin(async { Ok(AccountToken::new(TOKEN).expect("a token")) })
    }
}

impl World {
    fn new() -> Self {
        let writer_pair = AuthorisationKeyPair::generate().expect("a writer key");
        Self {
            seed: RecoverySeed::generate().expect("a seed"),
            locator: fresh_locator().expect("a locator"),
            owner: Arc::new(Signer {
                kind: ServiceRequestSigner::Installation,
                key: AuthorisationKeyPair::generate().expect("an owner key"),
            }),
            writer: Arc::new(Signer {
                kind: ServiceRequestSigner::Host,
                key: writer_pair.clone(),
            }),
            writer_pair,
            producer: StoredEnvelopeKeyPair::generate().expect("a producer key"),
        }
    }

    fn trusted_writer(&self) -> TrustedWriter {
        TrustedWriter {
            writer_key_id: self.writer_pair.key_id(),
            signing_key: *self.writer_pair.public(),
            enrolled_at_ms: TimestampMs::new(1_000),
        }
    }

    fn trusted_producer(&self) -> TrustedProducer {
        TrustedProducer {
            sender_key_id: self.producer.key_id(),
            stored_envelope_key: *self.producer.public(),
            enrolled_at_ms: TimestampMs::new(1_000),
        }
    }

    /// The kit text for the service at `origin`, as the owner's client prints it.
    fn kit_text(&self, origins: &[&str]) -> String {
        let kit = self.seed.to_kit(
            origins.iter().map(|origin| (*origin).to_owned()).collect(),
            self.locator.clone(),
        );
        kr_client::recovery::render_kit(&kit)
            .expect("a kit renders")
            .to_string()
    }

    /// The seed as the kit prints it, so a test can look for it in what a command printed.
    fn seed_text(&self) -> String {
        let kit = self.kit_text(&["https://reach.kala.to"]);
        kit.lines()
            .find_map(|line| line.strip_prefix("seed: "))
            .expect("a seed line")
            .to_owned()
    }
}

/// One sealed generation: its signed publication and every object it names.
struct Sealed {
    publication: BackupGenerationPublication,
    objects: BTreeMap<BackupObjectId, Vec<u8>>,
}

fn object(byte: u8) -> BackupObjectId {
    BackupObjectId::new(id(byte))
}

/// Seals `members` as one generation of the archive, for the recovery recipient.
fn seal(world: &World, generation: u64, members: &[(&str, Vec<u8>)]) -> Sealed {
    let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(recipients.add_recovery(&world.seed.recipient().expect("a recipient")));
    let staged: Vec<_> = members
        .iter()
        .enumerate()
        .map(|(at, (name, plaintext))| {
            stage_object(
                &ObjectSource {
                    object_id: object(0x20 + u8::try_from(at).expect("few members")),
                    filename: name,
                    plaintext,
                },
                recipients.rotation(),
            )
            .expect("a staged object")
        })
        .collect();
    let manifest_object = object(0xf0 + u8::try_from(generation).expect("a small generation"));
    let sealed = seal_archive(
        &world.writer_pair,
        &world.producer,
        &recipients,
        &ArchivePlan {
            archive_id: archive(),
            backup_generation: BackupGeneration::new(generation),
            owner_device_id: DeviceId::new(id(0x33)),
            manifest_object_id: manifest_object,
            created_at_ms: TimestampMs::new(1_700_000_000_000),
        },
        &staged,
    )
    .expect("a sealed archive");
    let mut objects: BTreeMap<_, _> = staged
        .iter()
        .map(|staged| (staged.object_id(), staged.bytes().to_vec()))
        .collect();
    objects.insert(manifest_object, sealed.encrypted_manifest.clone());
    let payload = BackupGenerationPublicationPayload {
        descriptor: sealed.descriptor,
        writer_key_id: world.writer_pair.key_id(),
        published_at_ms: TimestampMs::new(1_700_000_001_000),
    };
    let signature = sign(
        &world.writer_pair,
        &SigningTranscript::from_canonical_bytes(
            BACKUP_PUBLICATION_DOMAIN,
            payload.signing_input().expect("a publication input"),
        )
        .expect("a transcript"),
    )
    .expect("a signature");
    Sealed {
        publication: BackupGenerationPublication { payload, signature },
        objects,
    }
}

/// The bundle the owner keeps at the locator: the writer and the producer it trusts, the archive,
/// and optionally the checkpoint the owner last verified.
fn bundle(
    world: &World,
    origin: &str,
    checkpoint: Option<ArchiveCheckpoint>,
    archives: &[ArchiveId],
) -> Vec<u8> {
    let bundle = RecoveryBundle {
        schema_version: U64::new(RECOVERY_BUNDLE_SCHEMA_VERSION),
        collections: archives
            .iter()
            .enumerate()
            .map(|(at, archive_id)| CollectionLocator {
                service_origin: origin.to_owned(),
                locator: format!("collection-{}", at + 1),
                archive_id: *archive_id,
            })
            .collect(),
        trusted_writers: [world.trusted_writer()].into_iter().collect(),
        trusted_producers: [world.trusted_producer()].into_iter().collect(),
        checkpoints: checkpoint.into_iter().collect(),
        revision: U64::new(3),
        written_at_ms: TimestampMs::new(2_000),
    };
    let key = world
        .seed
        .bundle_key_for(&RecoveryContext {
            service_origin: origin.to_owned(),
            bundle_locator: world.locator.clone(),
        })
        .expect("a bundle key");
    kr_crypto::archive::encrypt_recovery_bundle(&key, &bundle).expect("a sealed bundle")
}

fn enrolment(world: &World, revision: u64) -> BackupWriterRecord {
    let payload = BackupWriterRecordPayload {
        archive_id: archive(),
        writer: world.trusted_writer(),
        writer_revision: BackupWriterRevision::new(revision),
        owner_key_id: world.owner.key.key_id(),
        enrolled_at_ms: TimestampMs::new(1_000),
    };
    let transcript = SigningTranscript::from_canonical_bytes(
        BACKUP_WRITER_DOMAIN,
        payload.signing_input().expect("an enrolment input"),
    )
    .expect("a transcript");
    let signature = sign(&world.owner.key, &transcript).expect("a signature");
    BackupWriterRecord { payload, signature }
}

/* -------------------------------------------------------------------------- */
/* A host and its daemon                                                       */
/* -------------------------------------------------------------------------- */

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

/// The account service of a host that is signed in before its daemon starts: the seeding keeps a
/// grant and asks the service nothing.
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

/// What the account the host is signed in with is allowed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SignIn {
    /// Signed in with the scope backup storage needs.
    Usable,
    /// Not signed in.
    Nobody,
}

/// A host: its tree, its daemon, the storage service it is configured for, and directories of its
/// own for the commands it runs.
struct Rig {
    temp: kr_ipc::testing::TempHost,
    served: Served,
    timer: Arc<HeldTimer>,
    controller: Option<Arc<Controller>>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::error::Result<()>>>,
    work: PathBuf,
    home: PathBuf,
}

impl Drop for Rig {
    /// Ends the daemon before the tree goes.
    ///
    /// The daemon holds `controller.lock` until the daemon value itself is gone, and on Windows that
    /// is an open file that shares nothing, which the removal of the folder it is in is refused for:
    /// the tree would stay in the temporary folder for good. So the tasks that serve are cancelled,
    /// the rig lets go of the daemon, and the tree is removed once the lock can be taken. The wait
    /// needs another thread of the runtime to cancel the aborted tasks, so a case that holds a rig
    /// runs on the multi-thread runtime, and it ends at the liveness deadline at the latest. The
    /// fields go after this, the tree first.
    fn drop(&mut self) {
        for task in &self.serving {
            task.abort();
        }
        drop(self.controller.take());
        let lock = self.temp.environment().singleton_lock();
        let begun = Instant::now();
        let problem = loop {
            match SingletonLock::hold(&lock, self.temp.environment_id()) {
                Ok(held) => {
                    drop(held);
                    break None;
                }
                Err(ControllerError::AlreadyRunning { .. })
                    if begun.elapsed() < LIVENESS_DEADLINE =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => break Some(error),
            }
        };
        // A case that is already failing is not made to panic twice.
        if let Some(error) = problem {
            assert!(
                std::thread::panicking(),
                "the lock {} was not free {:?} after the rig let go of the daemon: {error}",
                lock.display(),
                begun.elapsed()
            );
        }
        // The lock being free shows the daemon value is gone, not that every task that holds a part
        // of it has ended: the backup carrier's task is aborted when the daemon goes and cannot be
        // joined from here, and it may hold the backup store's files a moment longer. So the tree
        // is removed here, again for as long as the removal is refused, and a tree that is left is
        // said (and fails the case, unless it is failing already).
        let root = self.temp.root().to_path_buf();
        if let Err(error) = remove_tree(&root, |_| {}) {
            let said = format!(
                "{} is left in the temporary folder, and its removal is refused: {error}",
                root.display()
            );
            if std::thread::panicking() {
                let _ = writeln!(std::io::stderr(), "{said}");
            } else {
                panic!("{said}");
            }
        }
    }
}

/// Removes the tree at `root`, again for as long as the removal is refused and for no longer than
/// the liveness deadline, and returns the refusal that was still there at the end. `refused` is
/// called after each refusal, with it.
fn remove_tree(
    root: &Path,
    mut refused: impl FnMut(&std::io::Error),
) -> Result<(), std::io::Error> {
    let begun = Instant::now();
    loop {
        match std::fs::remove_dir_all(root) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) if begun.elapsed() < LIVENESS_DEADLINE => {
                refused(&error);
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

impl Rig {
    async fn start(sign_in: SignIn) -> Self {
        Self::start_at(serve().await, sign_in).await
    }

    /// A host configured for `served`, which may hold a backup already: another host's, or this
    /// test's.
    async fn start_at(served: Served, sign_in: SignIn) -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let work = temp.root().join("w");
        let home = temp.root().join("h");
        for directory in [&work, &home] {
            std::fs::create_dir(directory).expect("a directory on the internal disk");
        }
        #[cfg(windows)]
        for directory in ["Local", "Roaming"] {
            std::fs::create_dir_all(home.join("AppData").join(directory))
                .expect("a folder for the host's program data");
        }
        write_document(&temp, served.origin());
        if sign_in == SignIn::Usable {
            keep_sign_in(&temp, served.origin()).await;
        }
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        environment.create().expect("the environment's directories");
        let secrets = environment.secrets_dir();
        let timer = HeldTimer::automatic();
        let origin = served.origin().to_owned();
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
                        worker_program: temp.root().join("none").join("kr-worker"),
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
        let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
            .expect("binds the client endpoint");
        let serving = vec![tokio::spawn(Arc::clone(&controller).serve_clients(clients))];
        Self {
            temp,
            served,
            timer,
            controller: Some(controller),
            serving,
            work,
            home,
        }
    }

    fn origin(&self) -> &str {
        self.served.origin()
    }

    /// The environment every `kr` this test runs is given on Windows: what a program needs to start
    /// there, and this host's directories.
    #[cfg(windows)]
    fn variables(&self) -> Vec<(&'static str, String)> {
        let mut variables = Vec::new();
        for name in [
            "SystemRoot",
            "SystemDrive",
            "windir",
            "TEMP",
            "TMP",
            "ComSpec",
            "PATHEXT",
        ] {
            if let Ok(value) = std::env::var(name) {
                variables.push((name, value));
            }
        }
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        variables.push(("PATH", format!(r"{root}\System32")));
        // The folders a program keeps its data in are the host's own below its home.
        variables.push(("USERPROFILE", self.home.display().to_string()));
        variables.push((
            "LOCALAPPDATA",
            self.home
                .join("AppData")
                .join("Local")
                .display()
                .to_string(),
        ));
        variables.push((
            "APPDATA",
            self.home
                .join("AppData")
                .join("Roaming")
                .display()
                .to_string(),
        ));
        variables.push((
            "KR_RUNTIME_DIR",
            self.temp.paths().runtime_root().display().to_string(),
        ));
        variables.push((
            "KR_STATE_DIR",
            self.temp.paths().state_root().display().to_string(),
        ));
        variables
    }

    /// The environment every `kr` this test runs is given: this host's directories, a home of its
    /// own, and nothing of the person running the test.
    #[cfg(unix)]
    fn variables(&self) -> Vec<(&'static str, String)> {
        vec![
            ("PATH", "/usr/bin:/bin".to_owned()),
            ("TERM", "xterm-256color".to_owned()),
            ("HOME", self.home.display().to_string()),
            (
                "KR_RUNTIME_DIR",
                self.temp.paths().runtime_root().display().to_string(),
            ),
            (
                "KR_STATE_DIR",
                self.temp.paths().state_root().display().to_string(),
            ),
        ]
    }

    /// The command `kr` with `line`, in this host's environment.
    fn command(&self, line: &[&str], more: &[(&str, &str)]) -> std::process::Command {
        let mut command = std::process::Command::new(kr());
        command
            .args(line)
            .env_clear()
            .envs(self.variables())
            .envs(more.iter().copied())
            .current_dir(&self.work)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        command
    }

    /// Runs `kr` with `stdin` as its standard input, and waits for it.
    async fn run(&self, line: &[&str], stdin: Option<&[u8]>) -> std::process::Output {
        self.run_with(line, stdin, &[]).await
    }

    /// As [`Self::run`], with more variables in the command's environment.
    async fn run_with(
        &self,
        line: &[&str],
        stdin: Option<&[u8]>,
        more: &[(&str, &str)],
    ) -> std::process::Output {
        let input = stdin.map_or(Input::Nothing, Input::Bytes);
        start(self.command(line, more), &input).ended().await
    }

    /// Starts `kr` and leaves it running.
    fn spawn(&self, line: &[&str], input: &Input<'_>) -> Running {
        start(self.command(line, &[]), input)
    }

    /// The new backup `world` owns, put in the service the way the owner's device and the host's
    /// writer would: the writer enrolled, the objects stored and the generation published.
    async fn put(&self, world: &World, sealed: &Sealed, checkpoint: Option<ArchiveCheckpoint>) {
        let origin = GatewayOrigin::new(self.origin()).expect("the service's origin");
        let http: Arc<dyn ServiceHttp> = Arc::new(
            HttpService::with(
                origin.clone(),
                HttpDeadlines::default(),
                managed_response_limits(),
            )
            .expect("a transport"),
        );
        let owner = ManagedBackupManifestService::new(
            origin.clone(),
            Arc::clone(&http),
            Arc::clone(&world.owner) as _,
        );
        owner
            .enrol(&enrolment(world, 1))
            .await
            .expect("the service enrols the writer");
        let web = self.served.web();
        for (object, bytes) in &sealed.objects {
            web.put_object(
                &archive().to_string(),
                &object.to_string(),
                ACCOUNT,
                bytes.clone(),
            );
        }
        let writer =
            ManagedBackupManifestService::new(origin, http, Arc::clone(&world.writer) as _)
                .presenting(Arc::new(Bearer));
        writer
            .publish(&sealed.publication)
            .await
            .expect("the service publishes the generation");
        web.put_bundle(
            &world.locator,
            ACCOUNT,
            bundle(world, self.origin(), checkpoint, &[archive()]),
        );
    }
}

/// A command that is running, with what it has written so far.
struct Running {
    pid: u32,
    /// The pipe the command reads, when the test keeps it open past what it wrote.
    stdin: Option<std::process::ChildStdin>,
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    /// Told whenever the command writes something.
    wrote: Arc<tokio::sync::Notify>,
    ended: tokio::task::JoinHandle<std::process::ExitStatus>,
}

/// What a command is given on standard input.
enum Input<'a> {
    /// Nothing: standard input is empty.
    Nothing,
    /// These bytes, then the end of the input.
    Bytes(&'a [u8]),
    /// These bytes, and the pipe left open for the test to hold.
    #[cfg_attr(not(unix), allow(dead_code))]
    Held(&'a [u8]),
}

/// Copies everything `from` gives into `into`, telling `wrote` each time.
fn collect(
    mut from: impl Read + Send + 'static,
    into: Arc<Mutex<Vec<u8>>>,
    wrote: Arc<tokio::sync::Notify>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        while let Ok(read) = from.read(&mut buffer) {
            if read == 0 {
                break;
            }
            into.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(&buffer[..read]);
            wrote.notify_waiters();
        }
    })
}

/// Starts `command` with `input` as its standard input.
fn start(mut command: std::process::Command, input: &Input<'_>) -> Running {
    command.stdin(match input {
        Input::Nothing => std::process::Stdio::null(),
        Input::Bytes(_) | Input::Held(_) => std::process::Stdio::piped(),
    });
    let mut child = command.spawn().expect("kr runs");
    let pid = child.id();
    let mut stdin = child.stdin.take();
    if let (Some(pipe), Input::Bytes(bytes) | Input::Held(bytes)) = (stdin.as_mut(), input) {
        // The command may stop reading before the end; that is its answer, not a failure here.
        let _ = pipe.write_all(bytes);
        let _ = pipe.flush();
    }
    if matches!(input, Input::Bytes(_)) {
        stdin = None;
    }
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let wrote = Arc::new(tokio::sync::Notify::new());
    let readers = [
        collect(
            child.stdout.take().expect("piped"),
            Arc::clone(&stdout),
            Arc::clone(&wrote),
        ),
        collect(
            child.stderr.take().expect("piped"),
            Arc::clone(&stderr),
            Arc::clone(&wrote),
        ),
    ];
    let ended = tokio::task::spawn_blocking(move || {
        let status = child.wait().expect("kr ends");
        for reader in readers {
            let _ = reader.join();
        }
        status
    });
    Running {
        pid,
        stdin,
        stdout,
        stderr,
        wrote,
        ended,
    }
}

impl Running {
    /// Waits for the command to end.
    async fn ended(self) -> std::process::Output {
        let Self {
            stdin,
            stdout,
            stderr,
            ended,
            ..
        } = self;
        let status = ended.await.expect("the command ran");
        drop(stdin);
        let take =
            |held: &Mutex<Vec<u8>>| held.lock().unwrap_or_else(PoisonError::into_inner).clone();
        std::process::Output {
            status,
            stdout: take(&stdout),
            stderr: take(&stderr),
        }
    }

    /// Waits for the command to end, and ends it and fails when it does not within the deadline,
    /// so a command that ignored what the test did to it fails the test and does not hold it.
    async fn ended_within_the_deadline(self) -> std::process::Output {
        let pid = self.pid;
        match tokio::time::timeout(LIVENESS_DEADLINE, self.ended()).await {
            Ok(output) => output,
            Err(_) => {
                end_at_once(pid);
                panic!("the command did not end");
            }
        }
    }

    /// What the command has written on its error stream so far.
    fn said(&self) -> String {
        text(&self.stderr.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Waits until the command has written `marker` on its error stream. It fails when it never
    /// does.
    async fn stderr_shows(&self, marker: &str) {
        let waiting = async {
            loop {
                let wrote = self.wrote.notified();
                tokio::pin!(wrote);
                wrote.as_mut().enable();
                if self.said().contains(marker) {
                    return;
                }
                wrote.await;
            }
        };
        tokio::time::timeout(LIVENESS_DEADLINE, waiting)
            .await
            .unwrap_or_else(|_| panic!("the command never said {marker:?}: {}", self.said()));
    }

    /// Sends the command an interrupt, as Ctrl-C does to a process outside a terminal.
    #[cfg(unix)]
    fn interrupt(&self) {
        self.signal(rustix::process::Signal::INT);
    }

    /// Sends the command a signal.
    #[cfg(unix)]
    fn signal(&self, signal: rustix::process::Signal) {
        let pid = rustix::process::Pid::from_raw(i32::try_from(self.pid).expect("a process id"))
            .expect("a process id");
        rustix::process::kill_process(pid, signal).expect("the signal is sent");
    }
}

/// Ends the command with process id `pid` at once, for a command that did not end by itself.
fn end_at_once(pid: u32) {
    #[cfg(unix)]
    {
        let pid = rustix::process::Pid::from_raw(i32::try_from(pid).expect("a process id"))
            .expect("a process id");
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output();
    }
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

/// Keeps a sign-in in the secret store the daemon will open, as a finished browser sign-in leaves
/// one.
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
            expires_in_seconds: 3600,
            refresh_token: RefreshToken::new("a-refresh-token").expect("a token"),
            scopes: ["openid", "voice", "backup.write"]
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect(),
            subject: "account-1".to_owned(),
        })
        .await;
}

/* -------------------------------------------------------------------------- */
/* What a test reads back                                                      */
/* -------------------------------------------------------------------------- */

fn session_name(byte: u8) -> String {
    format!("sessions/{}.json", id(byte))
}

/// Text a test can recognise in a file and in what a command printed.
fn plaintext(label: &str, length: usize) -> Vec<u8> {
    let mut bytes = label.as_bytes().to_vec();
    while bytes.len() < length {
        bytes.push(b'a' + u8::try_from(bytes.len() % 26).expect("a letter"));
    }
    bytes
}

/// A folder the person made, which the command fills.
fn folder(rig: &Rig, name: &str) -> PathBuf {
    let path = rig.temp.root().join(name);
    std::fs::create_dir(&path).expect("a folder");
    path
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn names(folder: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(folder)
        .expect("the folder reads")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn digest_of(preview: &std::process::Output) -> String {
    let document: Value = serde_json::from_slice(&preview.stdout).unwrap_or_else(|error| {
        panic!(
            "the preview printed no document ({error}): {}{}",
            text(&preview.stdout),
            text(&preview.stderr)
        )
    });
    document["digest"].as_str().expect("a digest").to_owned()
}

/// What the members of the archive every case below starts from hold that no restore may put
/// back: a control key, host authority and a name no host archive carries.
const KEY_BYTES: &[u8] = b"CONTROL-KEY-BYTES-A-RESTORE-MUST-NOT-WRITE";

/// The members every case below starts from: two sessions and the configuration, which a restore
/// writes, and three it does not.
fn members() -> Vec<(String, Vec<u8>)> {
    vec![
        (session_name(0x01), plaintext("session one: ", 3000)),
        (session_name(0x02), plaintext("session two: ", 1_500_000)),
        (
            "host/configuration.json".to_owned(),
            br#"{"revision":7}"#.to_vec(),
        ),
        ("keys/control/main".to_owned(), KEY_BYTES.to_vec()),
        ("authority/grant-1".to_owned(), b"AUTHORITY".to_vec()),
        ("other/unknown.bin".to_owned(), b"UNKNOWN".to_vec()),
    ]
}

/// The archive of [`members`] with the two kinds of member a host's archive never carries and a
/// restore never puts back: an endpoint key and a revoked grant.
fn members_with_every_kind_a_restore_refuses() -> Vec<(String, Vec<u8>)> {
    let mut held = members();
    held.push((
        "keys/endpoint/device".to_owned(),
        b"ENDPOINT-KEY-BYTES-A-RESTORE-MUST-NOT-WRITE".to_vec(),
    ));
    held.push((
        "grants/revoked/grant-2".to_owned(),
        b"REVOKED-GRANT-A-RESTORE-MUST-NOT-WRITE".to_vec(),
    ));
    held
}

/// Asserts that the plan of a restore of [`members_with_every_kind_a_restore_refuses`] shows the
/// five members that are not restored, each by the object the plan names it by, with the table's
/// reason for its kind; the unknown name has a reason of its own, and none of the three members
/// that are restored is among them.
fn plan_names_what_it_does_not_restore(plan: &Value, held: &[(String, Vec<u8>)]) {
    let not_restored = plan["not_restored"].as_array().expect("refused");
    assert_eq!(
        not_restored.len(),
        5,
        "an endpoint key, a control key, host authority, a revoked grant and an unknown name are \
         shown as not restored"
    );
    let object_of = |name: &str| {
        let at = held
            .iter()
            .position(|(member, _)| member == name)
            .expect("a member of the archive");
        object(0x20 + u8::try_from(at).expect("few members"))
            .get()
            .to_string()
    };
    let reason_of = |material| {
        kr_crypto::backup::may_restore(material)
            .because()
            .expect("the table refuses it")
    };
    let table_reasons = [
        ("keys/endpoint/device", Material::EndpointPrivateKey),
        ("keys/control/main", Material::ControlSigningPrivateKey),
        ("authority/grant-1", Material::HostGrantAuthority),
        ("grants/revoked/grant-2", Material::Grant { revoked: true }),
    ];
    for (name, material) in table_reasons {
        let entry = not_restored
            .iter()
            .find(|refused| refused["object"] == object_of(name).as_str())
            .unwrap_or_else(|| panic!("{name} is shown as not restored: {plan}"));
        assert_eq!(
            entry["because"],
            reason_of(material),
            "{name} is refused for its kind's reason"
        );
    }
    let unknown = not_restored
        .iter()
        .find(|refused| refused["object"] == object_of("other/unknown.bin").as_str())
        .unwrap_or_else(|| panic!("the unknown name is shown as not restored: {plan}"));
    assert_eq!(
        unknown["because"],
        kr_client::recovery::MemberRefusal::UnknownKind
            .said()
            .to_string(),
        "a name no host archive carries is refused as an unknown name, not for a kind's reason"
    );
    assert!(
        table_reasons
            .iter()
            .all(|(_, material)| unknown["because"] != reason_of(*material)),
        "a name no host archive carries is not given a kind's reason: {plan}"
    );
    for name in [held[0].0.as_str(), held[1].0.as_str(), held[2].0.as_str()] {
        assert!(
            not_restored
                .iter()
                .all(|refused| refused["object"] != object_of(name).as_str()),
            "{name} is restored, not refused: {plan}"
        );
    }
}

/// Asserts that nothing a restore refuses was written into `into`.
fn nothing_refused_came_back(into: &Path) {
    for refused in [
        "ENDPOINT-KEY-BYTES",
        "CONTROL-KEY-BYTES",
        "AUTHORITY",
        "REVOKED-GRANT",
        "UNKNOWN",
    ] {
        assert!(
            tree(into)
                .values()
                .all(|bytes| !text(bytes).contains(refused)),
            "{refused} is not restored"
        );
    }
}

fn borrowed(members: &[(String, Vec<u8>)]) -> Vec<(&str, Vec<u8>)> {
    members
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.clone()))
        .collect()
}

/* -------------------------------------------------------------------------- */
/* Cases                                                                       */
/* -------------------------------------------------------------------------- */

/// A rig removes the whole tree it made when it goes, the daemon's lock file in it. Windows refuses
/// the removal of a folder below a file the daemon still holds open, and the folder's remains would
/// stay in the temporary folder for good; on Unix a lock file is no obstacle, so this case cannot
/// fail there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rig_leaves_no_part_of_its_tree_behind() {
    let rig = Rig::start(SignIn::Nobody).await;
    let root = rig.temp.root().to_path_buf();
    assert!(
        rig.temp.environment().singleton_lock().exists(),
        "the daemon holds its lock file in the tree"
    );
    drop(rig);
    assert!(
        !root.exists(),
        "{} is left in the temporary folder",
        root.display()
    );
}

/// KR-REQ-24.16, 20.16, 20.19, KR-ACC-033: a fresh host with only the kit previews, then confirms
/// the digest it saw, and the folder holds exactly the plaintexts; the host's stored keys,
/// configuration and devices are as they were.
///
/// KR-REQ-20.17, the restore through the shipped command only: the archive here also carries an
/// endpoint key, a control key, host authority, a revoked grant and a name no host archive carries,
/// and the plan lists those five as not restored, with a reason each; none of their bytes is in
/// the restored folder, and the host's own secrets, configuration and devices are as they were.
/// Not shown here: that a backup is made without those keys, which the daemon's production case
/// reads in part (its doc says which), or the kind the table gives each name, which the library's
/// case shows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_host_restores_a_backup_from_the_kit_alone_and_changes_nothing_of_its_own() {
    let world = World::new();
    let rig = Rig::start(SignIn::Usable).await;
    let held = members_with_every_kind_a_restore_refuses();
    let sealed = seal(&world, 1, &borrowed(&held));
    rig.put(&world, &sealed, None).await;
    let kit = rig.work.join("kit.txt");
    std::fs::write(&kit, world.kit_text(&[rig.origin()])).expect("the kit file");
    let kit_arg = kit.display().to_string();
    let into = folder(&rig, "restored");
    let into_arg = into.display().to_string();

    let before = host_state(&rig).await;

    let preview = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--preview",
                "--json",
            ],
            None,
        )
        .await;
    assert!(preview.status.success(), "{}", text(&preview.stderr));
    assert!(names(&into).is_empty(), "a preview writes nothing");
    let digest = digest_of(&preview);
    let plan: Value = serde_json::from_slice(&preview.stdout).expect("the plan is JSON");
    assert_eq!(plan["files"].as_array().expect("files").len(), 3);
    // The plan names the archive, the generation, the writer whose signature was checked and where
    // the generation stands, which a person confirms with the digest.
    assert_eq!(plan["backup_generation"], 1);
    assert_eq!(plan["archive"], archive().get().to_string());
    let writer: String = world
        .writer_pair
        .key_id()
        .as_bytes()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(plan["writer_key"], writer);
    assert!(
        plan["standing"]
            .as_str()
            .is_some_and(|standing| standing.contains("generation 1")),
        "{plan}"
    );
    plan_names_what_it_does_not_restore(&plan, &held);

    let restored = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--confirm-plan",
                &digest,
                "--json",
            ],
            None,
        )
        .await;
    assert!(restored.status.success(), "{}", text(&restored.stderr));
    assert_eq!(
        names(&into),
        [
            "configuration.json",
            "restore.json",
            "session-0001.json",
            "session-0002.json"
        ]
    );
    assert_eq!(
        std::fs::read(into.join("session-0001.json")).expect("a file"),
        held[0].1
    );
    assert_eq!(
        std::fs::read(into.join("session-0002.json")).expect("a file"),
        held[1].1
    );
    assert_eq!(
        std::fs::read(into.join("configuration.json")).expect("a file"),
        held[2].1
    );
    let record: Value =
        serde_json::from_slice(&std::fs::read(into.join("restore.json")).expect("the record"))
            .expect("the record is JSON");
    assert_eq!(record["plan_digest"], digest);
    assert_eq!(record["backup_generation"], 1);
    // A file's mode is Unix's alone.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for name in names(&into) {
            let mode = std::fs::metadata(into.join(&name))
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
    }
    assert_eq!(
        host_state(&rig).await,
        before,
        "a restore imports nothing into the host"
    );
    // The kit's seed and the full locator are in nothing this host kept and nothing it reports:
    // not in a file below its tree, and not in a support bundle.
    let bundle_path = rig.temp.root().join("support.tar");
    let _ = rig
        .run(
            &["doctor", "--bundle", &bundle_path.display().to_string()],
            None,
        )
        .await;
    assert!(bundle_path.is_file(), "the support bundle was written");
    for (name, bytes) in tree(rig.temp.root()) {
        if name == "w/kit.txt" || name.starts_with("restored/") {
            continue;
        }
        for needle in [world.seed_text(), world.locator.clone()] {
            assert!(
                !text(&bytes).contains(&needle),
                "{name} holds the kit's seed or locator"
            );
        }
    }
    nothing_refused_came_back(&into);
    // Nothing of the kit reached anything the commands printed.
    for output in [&preview, &restored] {
        let shown = format!("{}{}", text(&output.stdout), text(&output.stderr));
        assert!(!shown.contains(&world.seed_text()));
        assert!(!shown.contains(&world.locator));
    }
}

/// The forms in which a document could carry `key`, as the bytes to look for in it: the bytes
/// themselves and their hexadecimal in either case; and base64 in either alphabet, which puts three
/// bytes in four characters, so that the characters standing for the key's whole groups of three are
/// the same wherever the key lies in a longer value. Which groups those are depends on where the key
/// starts, so each of the three ways it can start is looked for.
fn forms_of(key: &[u8]) -> Vec<(String, Vec<u8>)> {
    let hex = |upper: bool| -> Vec<u8> {
        key.iter()
            .map(|byte| {
                if upper {
                    format!("{byte:02X}")
                } else {
                    format!("{byte:02x}")
                }
            })
            .collect::<String>()
            .into_bytes()
    };
    let mut forms = vec![
        ("as bytes".to_owned(), key.to_vec()),
        ("in lower-case hexadecimal".to_owned(), hex(false)),
        ("in upper-case hexadecimal".to_owned(), hex(true)),
    ];
    for start in 0..3 {
        let whole = &key[start..start + (key.len() - start) / 3 * 3];
        let url = kr_protocol::scalars::to_base64url(whole);
        forms.push((
            format!("in base64url from its byte {start}"),
            url.clone().into_bytes(),
        ));
        forms.push((
            format!("in base64 from its byte {start}"),
            url.replace('-', "+").replace('_', "/").into_bytes(),
        ));
    }
    forms
}

/// How `key` is carried in `haystack`, in a form [`forms_of`] names or as serde writes a list of
/// bytes, a list of numbers, with any space between its items; nothing when it is not.
fn carried_in(haystack: &[u8], key: &[u8]) -> Option<String> {
    let found = |needle: &[u8], haystack: &[u8]| {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    };
    if let Some((form, _)) = forms_of(key)
        .into_iter()
        .find(|(_, needle)| found(needle, haystack))
    {
        return Some(form);
    }
    let compact: Vec<u8> = haystack
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let numbers = key
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",")
        .into_bytes();
    found(&numbers, &compact).then(|| "as a list of numbers".to_owned())
}

/// Every key of `kept` that is carried in an object of `clear`, as the object's label and the key's
/// name with the form. Each object is read on its own.
fn carried_keys(clear: &[(String, Vec<u8>)], kept: &[(String, Vec<u8>)]) -> Vec<String> {
    let mut found = Vec::new();
    for (label, bytes) in clear {
        for (name, key) in kept {
            if let Some(form) = carried_in(bytes, key) {
                found.push(format!("{label} holds the {name} {form}"));
            }
        }
    }
    found
}

/// The private keys the host keeps, read from the secret store its daemon wrote them to, as a name
/// and the bytes: the seeds of the controller identity and of the device keys (transport, which is
/// the reusable endpoint key; authorisation, which is the control-signing key; stored envelope; and
/// notification preview), the backup writer's seed when the host has one, and the private keys of
/// the four X25519 pairs, which are made from their seeds by a hash (the first half of the seed's
/// SHA-512, which is what libsodium's `crypto_box_seed_keypair` makes of it) and are checked here
/// against the public key each pair has.
fn host_private_keys_held(rig: &Rig) -> Vec<(String, Vec<u8>)> {
    use kr_crypto::store::{SecretName, load_device_keys};
    use kr_protocol::pairing::KeyPurpose;

    let store = open_store_in(&rig.temp.environment().secrets_dir()).expect("the daemon's store");
    let identity_scope = rig.temp.environment_id().to_string();
    let device_scope = kr_controller::service::net::device_key_scope(rig.temp.environment_id());
    let mut kept = Vec::new();
    for (whose, scope) in [
        ("controller identity", &identity_scope),
        ("device", &device_scope),
    ] {
        for purpose in [
            KeyPurpose::Transport,
            KeyPurpose::Authorisation,
            KeyPurpose::StoredEnvelope,
            KeyPurpose::NotificationPreview,
        ] {
            let name = SecretName::device_key(scope, purpose).expect("a name");
            let seed = store
                .store
                .get(&name)
                .expect("the store reads")
                .unwrap_or_else(|| panic!("the daemon kept a {whose} {purpose:?} key"));
            kept.push((format!("{whose} {purpose:?}"), seed.expose().to_vec()));
        }
        let pairs = load_device_keys(store.store.as_ref(), scope)
            .expect("the store reads")
            .unwrap_or_else(|| panic!("the daemon kept a {whose} set of keys"));
        for (purpose, public) in [
            (
                KeyPurpose::StoredEnvelope,
                pairs.stored_envelope.public().as_bytes(),
            ),
            (
                KeyPurpose::NotificationPreview,
                pairs.notification_preview.public().as_bytes(),
            ),
        ] {
            let seed = &kept
                .iter()
                .find(|(name, _)| *name == format!("{whose} {purpose:?}"))
                .expect("the seed was read")
                .1;
            let secret =
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512, seed).as_ref()[..32].to_vec();
            let derived = aws_lc_rs::agreement::PrivateKey::from_private_key(
                &aws_lc_rs::agreement::X25519,
                &secret,
            )
            .expect("an X25519 private key")
            .compute_public_key()
            .expect("its public key");
            assert_eq!(
                derived.as_ref(),
                public.as_slice(),
                "the {whose} {purpose:?} private key is the first half of its seed's hash"
            );
            kept.push((format!("{whose} {purpose:?} private (derived)"), secret));
        }
    }
    let writer = SecretName::backup_writer(&device_scope).expect("a name");
    if let Some(seed) = store.store.get(&writer).expect("the store reads") {
        kept.push(("backup writer".to_owned(), seed.expose().to_vec()));
    }
    assert!(
        kept.len() >= 12,
        "two sets of four seeds and the four X25519 private keys made from them"
    );
    for (name, key) in &kept {
        assert!(key.len() >= 32, "the {name} key is a key, not a stub");
    }
    kept
}

/// The bundle the service holds for `world`, opened under the kit.
fn stored_bundle(rig: &Rig, world: &World) -> RecoveryBundle {
    let bytes = rig
        .served
        .web()
        .bundle(&world.locator)
        .expect("the service holds the bundle");
    let key = world
        .seed
        .bundle_key_for(&RecoveryContext {
            service_origin: rig.origin().to_owned(),
            bundle_locator: world.locator.clone(),
        })
        .expect("a bundle key");
    kr_crypto::archive::decrypt_recovery_bundle(&key, &bytes).expect("the bundle opens")
}

/// The checkpoint a restore of `sealed` records, as the bundle should hold it.
fn checkpoint_of(sealed: &Sealed) -> ArchiveCheckpoint {
    let descriptor = &sealed.publication.payload.descriptor;
    ArchiveCheckpoint {
        archive_id: archive(),
        backup_generation: descriptor.backup_generation,
        encrypted_manifest_hash: descriptor.encrypted_manifest.encrypted_object_hash,
        verified_at_ms: TimestampMs::new(4_000),
    }
}

/// KR-REQ-24.16, 20.12: the bundle a host's setup makes holds no checkpoint, because no generation
/// exists then and the host holds no seed. A restore holds the kit and has verified a generation,
/// so it records that generation in the bundle: a checkpoint for the archive, one revision on, and
/// every writer, producer and collection the bundle held carried through as it was.
///
/// KR-REQ-20.17, the restore's write-back of that checkpoint only, and only what this case reads:
/// the output of the preview and of the restore, the bundle the service holds after the restore
/// (opened with the kit's seed, as the JSON a client sees and as canonical bytes), and every
/// request the service was sent, each body, the content beside it and the account token, hold none
/// of the private keys the host keeps. The host keeps two sets of four keys (transport, which is
/// the reusable endpoint key; authorisation, which is the control-signing key; stored envelope; and
/// notification preview): the controller identity and the device keys it pairs with; the case reads
/// their eight seeds from the secret store the daemon wrote them to (and the backup writer's seed
/// when the host has one), and the private keys of the four X25519 pairs, each checked against the
/// pair's public key. Each key is looked for as bytes, in hexadecimal of either case, in either
/// base64 alphabet wherever it lies in a longer value, and as a list of numbers. The controls are
/// the scan finding each form where a key is put, the report's `checkpoint_recorded` member in the
/// restore's output, the bundle's writer key in the bundle and the bundle's ciphertext in the
/// requests. Not shown here: the local call to the daemon that carries the bundle
/// (`backup.bundle.write`) and its reply, whose parameters are typed and refuse unknown members;
/// what the restore writes into its folder, which the restore cases read for the members and fields
/// they name and not for the host's keys; the second restore's requests; the parts of a request the stand-in does not keep (its headers other than the token,
/// a query on its path, the signature block, any member of the signed document other than its body, and the authentication requests, which the stand-in answers before it keeps a record); a key in a binary list of integers,
/// split, reversed or otherwise transformed; or the other data paths of backup and recovery
/// material.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_records_the_generation_it_verified_in_the_bundle() {
    let world = World::new();
    let rig = Rig::start(SignIn::Usable).await;
    let held = members();
    let sealed = seal(&world, 2, &borrowed(&held));
    rig.put(&world, &sealed, None).await;
    let before = stored_bundle(&rig, &world);
    assert!(
        before.checkpoints.iter().next().is_none(),
        "a bundle a host makes carries no checkpoint"
    );
    let kit = rig.work.join("kit.txt");
    std::fs::write(&kit, world.kit_text(&[rig.origin()])).expect("the kit file");
    let kit_arg = kit.display().to_string();
    let into = folder(&rig, "restored");
    let into_arg = into.display().to_string();
    let line = |more: &[&str]| {
        let mut line = vec![
            "backup",
            "restore",
            "--into",
            &into_arg,
            "--kit-file",
            &kit_arg,
        ];
        line.extend_from_slice(more);
        line.into_iter().map(str::to_owned).collect::<Vec<_>>()
    };
    let run = |line: Vec<String>| {
        let rig = &rig;
        async move {
            let line: Vec<&str> = line.iter().map(String::as_str).collect();
            rig.run(&line, None).await
        }
    };

    let preview = run(line(&["--preview", "--json"])).await;
    assert!(preview.status.success(), "{}", text(&preview.stderr));
    let digest = digest_of(&preview);
    let restored = run(line(&["--confirm-plan", &digest, "--json"])).await;
    assert!(restored.status.success(), "{}", text(&restored.stderr));
    let report: Value = serde_json::from_slice(&restored.stdout).expect("a document");
    assert_eq!(report["checkpoint_recorded"], true, "{report}");

    let after = stored_bundle(&rig, &world);

    // What the restore printed, wrote to the service and recorded holds none of the host's keys.
    let kept = host_private_keys_held(&rig);
    let bundle_json = serde_json::to_vec(&after).expect("a bundle encodes");
    let sealed_after = rig
        .served
        .web()
        .bundle(&world.locator)
        .expect("the service holds the bundle");
    let mut clear = vec![
        (
            "the preview's output".to_owned(),
            [preview.stdout.clone(), preview.stderr.clone()].concat(),
        ),
        (
            "the restore's output".to_owned(),
            [restored.stdout.clone(), restored.stderr.clone()].concat(),
        ),
        ("the bundle as JSON".to_owned(), bundle_json.clone()),
        (
            "the bundle as canonical bytes".to_owned(),
            kr_cbor::to_canonical_vec(&after).expect("a bundle encodes"),
        ),
    ];
    let mut sent = Vec::new();
    for (at, arrived) in rig.served.web().arrived().iter().enumerate() {
        let to = format!("request {at} to {}", arrived.path);
        sent.push((
            format!("the body of {to}"),
            serde_json::to_vec(&arrived.body).expect("a body encodes"),
        ));
        if let Some(content) = &arrived.content {
            sent.push((format!("the content of {to}"), content.clone()));
        }
        if let Some(token) = &arrived.token {
            sent.push((format!("the token of {to}"), token.clone().into_bytes()));
        }
    }
    // The controls: the scan finds a key in each form it looks for, wherever the key lies in a
    // longer value, and reads what the restore printed, the bundle and what was sent.
    let (_, probe) = &kept[0];
    // The bytes and the hexadecimal forms are made here and not by the scan's own list of forms,
    // so a form dropped from that list fails here.
    let lower: String = probe.iter().map(|byte| format!("{byte:02x}")).collect();
    for (form, needle) in [
        ("as bytes", probe.clone()),
        ("in lower-case hexadecimal", lower.clone().into_bytes()),
        (
            "in upper-case hexadecimal",
            lower.to_uppercase().into_bytes(),
        ),
    ] {
        let document = [b"{\"a\":\"".as_slice(), &needle, b"\"}"].concat();
        assert!(
            carried_in(&document, probe).is_some(),
            "the scan misses a key {form}"
        );
    }
    for alphabet in ["base64url", "base64"] {
        for before in 0..3 {
            let mut longer = vec![0x5a_u8; before];
            longer.extend_from_slice(probe);
            longer.extend_from_slice(b"tail");
            let encoded = kr_protocol::scalars::to_base64url(&longer);
            let encoded = if alphabet == "base64" {
                encoded.replace('-', "+").replace('_', "/")
            } else {
                encoded
            };
            let value = format!("{{\"k\":\"{encoded}\"}}").into_bytes();
            assert!(
                carried_in(&value, probe).is_some(),
                "the scan misses a key inside a longer {alphabet} value that starts {before} \
                 bytes before it"
            );
        }
    }
    let list = format!(
        "{{\"k\":[\n  {}\n]}}",
        probe
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",\n  ")
    )
    .into_bytes();
    assert_eq!(
        carried_in(&list, probe).as_deref(),
        Some("as a list of numbers")
    );
    // A member the report names, whatever the platform spells a folder with.
    assert!(
        carried_in(&restored.stdout, b"checkpoint_recorded").is_some(),
        "the scan does not read the restore's output"
    );
    let writer = after
        .trusted_writers
        .iter()
        .next()
        .expect("the bundle names a writer")
        .signing_key;
    assert!(
        carried_in(&bundle_json, writer.as_bytes()).is_some(),
        "the scan does not read the bundle's writer key"
    );
    assert!(
        sent.iter()
            .any(|(_, bytes)| carried_in(bytes, &sealed_after).is_some()),
        "the scan does not read the bundle in the requests"
    );
    clear.extend(sent);
    assert_eq!(
        carried_keys(&clear, &kept),
        Vec::<String>::new(),
        "something a restore prints or sends holds a private key the host keeps"
    );

    assert_eq!(
        after.checkpoints.iter().cloned().collect::<Vec<_>>(),
        [ArchiveCheckpoint {
            verified_at_ms: after.checkpoints.iter().next().expect("one").verified_at_ms,
            ..checkpoint_of(&sealed)
        }],
        "the bundle records the generation the restore verified, with its manifest"
    );
    assert_eq!(after.revision.get(), before.revision.get() + 1);
    assert_eq!(after.collections, before.collections);
    assert_eq!(after.trusted_writers, before.trusted_writers);
    assert_eq!(after.trusted_producers, before.trusted_producers);

    // The same restore again finds its generation recorded and leaves the bundle as it is.
    let into_again = folder(&rig, "again");
    let again_arg = into_again.display().to_string();
    let again = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &again_arg,
                "--kit-file",
                &kit_arg,
                "--preview",
                "--json",
            ],
            None,
        )
        .await;
    assert!(again.status.success(), "{}", text(&again.stderr));
    let again_digest = digest_of(&again);
    let again = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &again_arg,
                "--kit-file",
                &kit_arg,
                "--confirm-plan",
                &again_digest,
                "--json",
            ],
            None,
        )
        .await;
    assert!(again.status.success(), "{}", text(&again.stderr));
    assert_eq!(
        stored_bundle(&rig, &world),
        after,
        "nothing newer to record"
    );
}

/// KR-REQ-24.16: a bundle that records a generation makes a service that offers an older one a
/// refusal that names both and the way through, and the way through is a person's own word: the
/// one generation, accepted, restores and leaves the checkpoint where it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_that_offers_a_generation_older_than_the_bundles_checkpoint_is_refused_by_name() {
    let world = World::new();
    let rig = Rig::start(SignIn::Usable).await;
    let held = members();
    let newer = seal(&world, 2, &borrowed(&held));
    let older = seal(&world, 1, &borrowed(&held));
    // The service holds generation 1 and the bundle records generation 2.
    rig.put(&world, &older, Some(checkpoint_of(&newer))).await;
    let kit = rig.work.join("kit.txt");
    std::fs::write(&kit, world.kit_text(&[rig.origin()])).expect("the kit file");
    let kit_arg = kit.display().to_string();
    let into = folder(&rig, "restored");
    let into_arg = into.display().to_string();
    let stored_before = rig.served.web().bundle(&world.locator).expect("a bundle");

    let refused = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--preview",
            ],
            None,
        )
        .await;
    assert!(!refused.status.success());
    let said = text(&refused.stderr);
    assert!(said.contains("generation 1"), "{said}");
    assert!(said.contains("older than generation 2"), "{said}");
    assert!(said.contains("--accept-older 1"), "{said}");
    assert!(names(&into).is_empty(), "nothing was written");

    // A generation the service does not hold is not accepted, and the refusal says what it holds.
    let wrong = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--preview",
                "--accept-older",
                "5",
            ],
            None,
        )
        .await;
    assert!(!wrong.status.success());
    assert!(
        text(&wrong.stderr).contains("--accept-older 1"),
        "{}",
        text(&wrong.stderr)
    );

    // The one generation the service holds, named, is shown in the plan and restores.
    let preview = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--preview",
                "--accept-older",
                "1",
                "--json",
            ],
            None,
        )
        .await;
    assert!(preview.status.success(), "{}", text(&preview.stderr));
    let plan: Value = serde_json::from_slice(&preview.stdout).expect("a document");
    assert!(
        plan["standing"]
            .as_str()
            .is_some_and(|standing| standing.contains("was named")),
        "{plan}"
    );
    assert!(
        plan["records_generation"].is_null(),
        "the bundle keeps its newer checkpoint, so the plan records nothing: {plan}"
    );
    let digest = digest_of(&preview);
    // The confirmation is for the plan that named the generation: without the flag, the same
    // digest does not write.
    let without = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--confirm-plan",
                &digest,
            ],
            None,
        )
        .await;
    assert!(!without.status.success());
    assert!(names(&into).is_empty());
    let restored = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--confirm-plan",
                &digest,
                "--accept-older",
                "1",
                "--json",
            ],
            None,
        )
        .await;
    assert!(restored.status.success(), "{}", text(&restored.stderr));
    assert!(names(&into).contains(&"session-0001.json".to_owned()));
    assert_eq!(
        rig.served.web().bundle(&world.locator).expect("a bundle"),
        stored_before,
        "the checkpoint is not lowered, and nothing newer is recorded"
    );
}

/// An offline export of `sealed` and the bundle for `world`, as the companion would write it: the
/// ciphertext the service holds and nothing else.
fn export_of(world: &World, origin: &str, sealed: &Sealed) -> kr_client::recovery::OfflineExport {
    use kr_client::recovery::{ExportedArchive, ExportedObject, OfflineExport};
    use kr_protocol::scalars::Bytes;

    let manifest = sealed
        .publication
        .payload
        .descriptor
        .encrypted_manifest
        .object_id;
    OfflineExport::new(
        origin.to_owned(),
        bundle(world, origin, None, &[archive()]),
        Some(ExportedArchive {
            archive_id: archive(),
            publication: sealed.publication.clone(),
            encrypted_manifest: Bytes::new(sealed.objects[&manifest].clone()),
            objects: sealed
                .objects
                .iter()
                .filter(|(object, _)| **object != manifest)
                .map(|(object, bytes)| ExportedObject {
                    object_id: *object,
                    bytes: Bytes::new(bytes.clone()),
                })
                .collect(),
        }),
    )
}

/// KR-REQ-20.18 and 24.16: the plan a person confirms says what the restore does to the recovery
/// bundle, and the confirmation is bound to it. A restore from the service records the generation it
/// verified; a restore from an export file reaches no service and records none, and says so before
/// it is confirmed. A digest confirmed for one is not the other's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_from_a_file_is_confirmed_apart_from_one_that_records_a_generation() {
    let world = World::new();
    let rig = Rig::start(SignIn::Usable).await;
    let held = members();
    let sealed = seal(&world, 1, &borrowed(&held));
    rig.put(&world, &sealed, None).await;
    let kit = rig.work.join("kit.txt");
    std::fs::write(&kit, world.kit_text(&[rig.origin()])).expect("the kit file");
    let kit_arg = kit.display().to_string();
    let file = rig.work.join("backup.krexport");
    std::fs::write(
        &file,
        export_of(&world, rig.origin(), &sealed)
            .to_canonical_bytes()
            .expect("canonical bytes"),
    )
    .expect("the export file");
    let file_arg = file.display().to_string();
    let into = folder(&rig, "restored");
    let into_arg = into.display().to_string();
    let preview = |extra: &[&str]| {
        let mut arguments = vec![
            "backup".to_owned(),
            "restore".to_owned(),
            "--into".to_owned(),
            into_arg.clone(),
            "--kit-file".to_owned(),
            kit_arg.clone(),
            "--preview".to_owned(),
        ];
        arguments.extend(extra.iter().map(|word| (*word).to_owned()));
        let rig = &rig;
        async move {
            let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
            rig.run(&arguments, None).await
        }
    };

    let online = preview(&["--json"]).await;
    assert!(online.status.success(), "{}", text(&online.stderr));
    let offline = preview(&["--from-export", &file_arg, "--json"]).await;
    assert!(offline.status.success(), "{}", text(&offline.stderr));
    let online_plan: Value = serde_json::from_slice(&online.stdout).expect("a document");
    let offline_plan: Value = serde_json::from_slice(&offline.stdout).expect("a document");
    assert_eq!(online_plan["records_generation"], 1, "{online_plan}");
    assert!(
        offline_plan["records_generation"].is_null(),
        "an export file reaches no service: {offline_plan}"
    );
    assert_ne!(
        digest_of(&online),
        digest_of(&offline),
        "what is confirmed covers whether the bundle records the generation"
    );

    // In words, before it is confirmed.
    let said = preview(&["--from-export", &file_arg]).await;
    assert!(said.status.success(), "{}", text(&said.stderr));
    let lines = format!("{}{}", text(&said.stdout), text(&said.stderr));
    assert!(lines.contains("records nothing"), "{lines}");
    assert!(!lines.contains("is updated to record"), "{lines}");
}

/// KR-REQ-20.18: a host that is signed in to nothing restores from an export file and the kit
/// alone: no service is reached, the files are the ones a restore from the service writes, and the
/// output says the recovery bundle at the service was left as it is. A file that is not an export,
/// in another format, or sealed for another kit restores nothing and is refused by name.
///
/// KR-REQ-20.17, the restore from an export file only: the archive in the file also carries an
/// endpoint key, a control key, host authority, a revoked grant and a name no host archive carries;
/// the plan lists those five as not restored, with the reason of each kind, the folder holds
/// exactly the three files the restore writes and its record, none of the five's bytes is in it,
/// and the host's own secrets, configuration and devices are as they were. Not shown here: that an
/// export holds none of those keys, which the companion's case reads for the export of the bundle
/// alone and the library's case for the equality of an archive export with the service's bytes (a
/// successful export of an archive by the companion is read by neither); or the kind the table
/// gives each name, which the library's case shows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_from_an_export_file_needs_no_service_and_no_sign_in() {
    let world = World::new();
    let rig = Rig::start(SignIn::Nobody).await;
    let held = members_with_every_kind_a_restore_refuses();
    let sealed = seal(&world, 1, &borrowed(&held));
    let kit = rig.work.join("kit.txt");
    std::fs::write(&kit, world.kit_text(&[rig.origin()])).expect("the kit file");
    let kit_arg = kit.display().to_string();
    let file = rig.work.join("backup.krexport");
    std::fs::write(
        &file,
        export_of(&world, rig.origin(), &sealed)
            .to_canonical_bytes()
            .expect("canonical bytes"),
    )
    .expect("the export file");
    let file_arg = file.display().to_string();
    let into = folder(&rig, "restored");
    let into_arg = into.display().to_string();
    let asked = rig.served.web().arrived().len();
    let before = host_state(&rig).await;

    // Without the file the host has no sign-in to ask the service with.
    let unsigned = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--preview",
            ],
            None,
        )
        .await;
    assert!(!unsigned.status.success());
    assert!(names(&into).is_empty());

    let preview = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--from-export",
                &file_arg,
                "--preview",
                "--json",
            ],
            None,
        )
        .await;
    assert!(preview.status.success(), "{}", text(&preview.stderr));
    let digest = digest_of(&preview);
    let plan: Value = serde_json::from_slice(&preview.stdout).expect("the plan is JSON");
    assert_eq!(plan["files"].as_array().expect("files").len(), 3);
    plan_names_what_it_does_not_restore(&plan, &held);
    let restored = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--from-export",
                &file_arg,
                "--confirm-plan",
                &digest,
                "--json",
            ],
            None,
        )
        .await;
    assert!(restored.status.success(), "{}", text(&restored.stderr));
    let report: Value = serde_json::from_slice(&restored.stdout).expect("a document");
    assert_eq!(report["checkpoint_recorded"], false, "{report}");
    assert!(
        report["checkpoint"]
            .as_str()
            .is_some_and(|words| words.contains("reached no service")),
        "{report}"
    );
    assert_eq!(
        names(&into),
        [
            "configuration.json",
            "restore.json",
            "session-0001.json",
            "session-0002.json"
        ],
        "the folder holds what the restore writes and nothing else"
    );
    assert_eq!(
        std::fs::read(into.join("session-0001.json")).expect("a session"),
        held[0].1,
        "the file gives back the member as the service would"
    );
    nothing_refused_came_back(&into);
    assert_eq!(
        host_state(&rig).await,
        before,
        "a restore from a file imports nothing into the host"
    );
    assert_eq!(
        rig.served.web().arrived().len(),
        asked,
        "no request left for the service"
    );

    // Refused by name, each writing nothing.
    let refused = |name: &str, bytes: Vec<u8>, kit_arg: &str| {
        let path = rig.work.join(name);
        std::fs::write(&path, bytes).expect("a file");
        let path = path.display().to_string();
        let into = folder(&rig, name);
        let into_arg = into.display().to_string();
        let kit_arg = kit_arg.to_owned();
        let name = name.to_owned();
        let rig = &rig;
        async move {
            let output = rig
                .run(
                    &[
                        "backup",
                        "restore",
                        "--into",
                        &into_arg,
                        "--kit-file",
                        &kit_arg,
                        "--from-export",
                        &path,
                        "--preview",
                    ],
                    None,
                )
                .await;
            assert!(!output.status.success(), "{name}");
            assert!(names(&into).is_empty(), "{name}");
            text(&output.stderr)
        }
    };
    let said = refused("not-an-export", b"not an export".to_vec(), &kit_arg).await;
    assert!(said.contains("not an offline export"), "{said}");
    let mut other = export_of(&world, rig.origin(), &sealed);
    other.format = "kalareach-offline-export/2".to_owned();
    let said = refused(
        "another-format",
        other.to_canonical_bytes().expect("canonical bytes"),
        &kit_arg,
    )
    .await;
    assert!(said.contains("format this release does not read"), "{said}");
    // Sealed for a kit other than the one given.
    let stranger = World::new();
    let stranger_kit = rig.work.join("stranger.txt");
    std::fs::write(&stranger_kit, stranger.kit_text(&[rig.origin()])).expect("a kit");
    let said = refused(
        "another-kit",
        export_of(&world, rig.origin(), &sealed)
            .to_canonical_bytes()
            .expect("canonical bytes"),
        &stranger_kit.display().to_string(),
    )
    .await;
    assert!(said.contains("did not authenticate"), "{said}");
}

/// KR-REQ-20.18: a kit that names several services restores from the one this host is configured
/// for, whichever of them is first, and does not reach the others.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kit_that_names_several_services_restores_from_the_one_this_host_is_configured_for() {
    let world = World::new();
    let rig = Rig::start(SignIn::Usable).await;
    let held = members();
    let sealed = seal(&world, 1, &borrowed(&held));
    rig.put(&world, &sealed, None).await;
    let kit = rig.work.join("kit.txt");
    // The first service is not this host's and cannot be reached; the kit names it all the same.
    std::fs::write(
        &kit,
        world.kit_text(&["https://storage.unreachable.invalid", rig.origin()]),
    )
    .expect("the kit file");
    let kit_arg = kit.display().to_string();
    let into = folder(&rig, "restored");
    let into_arg = into.display().to_string();
    let preview = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--preview",
                "--json",
            ],
            None,
        )
        .await;
    assert!(preview.status.success(), "{}", text(&preview.stderr));
    let digest = digest_of(&preview);
    let restored = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--confirm-plan",
                &digest,
            ],
            None,
        )
        .await;
    assert!(restored.status.success(), "{}", text(&restored.stderr));
    assert!(names(&into).contains(&"session-0001.json".to_owned()));
}

/// A configuration document for a backup to carry: the device's settings an owner chose, and the
/// things a restore must not take, which this host's own document does not have.
fn backed_up_configuration() -> Vec<u8> {
    use kr_protocol::desktop::SleepInhibitionSetting;
    use kr_protocol::hostinfo::configuration::{
        ConfigurationDocument, ControllerStartup, contents,
    };

    let mut document = ConfigurationDocument::empty();
    document.revision = 9;
    document.preferences.sleep_inhibition = Nullable::some(SleepInhibitionSetting::BatteryToo);
    document.descriptions.enabled = Nullable::some(true);
    // What can carry a secret or run code: a variable a session is given and a package's command
    // integration, in the base preferences and in a profile. A restore keeps the host's own.
    document.preferences.environment_additions = Nullable::some(
        [("BASH_ENV".to_owned(), "/tmp/restored-env".to_owned())]
            .into_iter()
            .collect(),
    );
    document.profiles.insert(
        "tools".to_owned(),
        kr_protocol::hostinfo::configuration::PreferenceSet {
            command_integrations: Nullable::some(vec!["restored/tool".to_owned()]),
            sleep_inhibition: Nullable::some(SleepInhibitionSetting::Off),
            ..kr_protocol::hostinfo::configuration::PreferenceSet::default()
        },
    );
    // What no restore may move: a restriction, the service this host selects, how its daemon starts.
    document.ceilings.session_limit = Nullable::some(1);
    document.storage.origin = Nullable::some("https://elsewhere.example".to_owned());
    document.startup.controller = Nullable::some(ControllerStartup::Standalone);
    contents(&document).into_bytes()
}

/// The host's own document, as the daemon and every command read it.
fn host_document(rig: &Rig) -> kr_protocol::hostinfo::configuration::ConfigurationDocument {
    let environment = rig.temp.environment();
    kr_cli::doctor::configuration::load(&environment)
        .document
        .expect("the host's document is usable")
}

/// KR-REQ-20.17: a restore applies the device's configuration when it is asked to, and only that:
/// the preferences and the settings of descriptions come back; a ceiling, the service this host
/// selects and how its daemon starts stay as the host has them, however the backup's document
/// states them. The plan the person confirms says what changes, and a document that moved since
/// is not written over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_applies_the_devices_configuration_and_nothing_that_restricts_or_redirects_it() {
    use kr_protocol::desktop::SleepInhibitionSetting;

    let world = World::new();
    let rig = Rig::start(SignIn::Usable).await;
    let held: Vec<(String, Vec<u8>)> = vec![
        (session_name(0x01), plaintext("session one: ", 300)),
        (
            "host/configuration.json".to_owned(),
            backed_up_configuration(),
        ),
    ];
    let sealed = seal(&world, 1, &borrowed(&held));
    rig.put(&world, &sealed, None).await;
    let kit = rig.work.join("kit.txt");
    std::fs::write(&kit, world.kit_text(&[rig.origin()])).expect("the kit file");
    let kit_arg = kit.display().to_string();
    let into = folder(&rig, "restored");
    let into_arg = into.display().to_string();
    let before = host_document(&rig);
    assert_eq!(before.preferences.sleep_inhibition, Nullable::null());

    // Without the option the file is a file to read, and the host's document is as it was.
    let plain = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--preview",
                "--json",
            ],
            None,
        )
        .await;
    assert!(plain.status.success(), "{}", text(&plain.stderr));
    let plain_plan: Value = serde_json::from_slice(&plain.stdout).expect("a document");
    assert_eq!(plain_plan["applies_configuration"], false);
    assert_eq!(plain_plan["records_generation"], 1, "{plain_plan}");

    let preview = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--preview",
                "--apply-configuration",
                "--json",
            ],
            None,
        )
        .await;
    assert!(preview.status.success(), "{}", text(&preview.stderr));
    let plan: Value = serde_json::from_slice(&preview.stdout).expect("a document");
    assert_eq!(plan["applies_configuration"], true);
    // What stays the host's own is named by set and never by variable or value.
    assert_eq!(
        plan["configuration_left_out"]["preferences"], true,
        "{plan}"
    );
    assert_eq!(
        plan["configuration_left_out"]["profiles"],
        serde_json::json!(["tools"]),
        "{plan}"
    );
    assert!(!plan.to_string().contains("BASH_ENV"));
    assert!(!plan.to_string().contains("restored/tool"));
    let changes: Vec<&str> = plan["configuration_changes"]
        .as_array()
        .expect("the changes")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(changes.contains(&"the sleep setting"), "{changes:?}");
    assert!(changes.contains(&"the description settings"), "{changes:?}");
    assert_ne!(
        digest_of(&preview),
        digest_of(&plain),
        "the confirmation covers what is applied"
    );
    let digest = digest_of(&preview);
    assert_eq!(host_document(&rig), before, "a preview changes nothing");

    // The host's document moves after the plan was shown: the confirmation is for another document.
    let moved = rig.run(&["host", "power", "--set", "off"], None).await;
    assert!(moved.status.success(), "{}", text(&moved.stderr));
    let refused = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--confirm-plan",
                &digest,
                "--apply-configuration",
            ],
            None,
        )
        .await;
    assert!(!refused.status.success());
    assert!(names(&into).is_empty(), "nothing was written");
    assert_eq!(
        host_document(&rig).preferences.sleep_inhibition,
        Nullable::some(SleepInhibitionSetting::Off),
        "the document stands as the person left it"
    );

    // The plan shown for the document as it now stands is the one that writes.
    let again = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--preview",
                "--apply-configuration",
                "--json",
            ],
            None,
        )
        .await;
    assert!(again.status.success(), "{}", text(&again.stderr));
    let again_digest = digest_of(&again);
    let applied = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into_arg,
                "--kit-file",
                &kit_arg,
                "--confirm-plan",
                &again_digest,
                "--apply-configuration",
                "--json",
            ],
            None,
        )
        .await;
    assert!(applied.status.success(), "{}", text(&applied.stderr));
    // The record beside the files does not say the configuration was left unapplied.
    let record: Value =
        serde_json::from_slice(&std::fs::read(into.join("restore.json")).expect("the record"))
            .expect("a document");
    let says = record["what_this_is"].as_str().expect("a sentence");
    assert!(!says.contains("not applied"), "{says}");
    assert!(says.contains("applied to this host"), "{says}");
    let after = host_document(&rig);
    assert_eq!(
        after.preferences.sleep_inhibition,
        Nullable::some(SleepInhibitionSetting::BatteryToo),
        "the preference came back"
    );
    assert_eq!(after.descriptions.enabled, Nullable::some(true));
    // The profile came back with its own settings and without what runs code or carries a secret.
    assert_eq!(
        after.profiles["tools"].sleep_inhibition,
        Nullable::some(SleepInhibitionSetting::Off)
    );
    assert_eq!(
        after.profiles["tools"].command_integrations,
        Nullable::null()
    );
    assert_eq!(
        after.preferences.environment_additions, before.preferences.environment_additions,
        "a variable is not restored"
    );
    assert_eq!(
        after.preferences.command_integrations, before.preferences.command_integrations,
        "a command integration is not restored"
    );
    let report: Value = serde_json::from_slice(&applied.stdout).expect("a document");
    assert_eq!(
        report["configuration_left_out"]["profiles"],
        serde_json::json!(["tools"]),
        "{report}"
    );
    // The same restore in words names the set, so that the person can add what was left out again.
    let words_into = folder(&rig, "restored-in-words");
    let words_into_arg = words_into.display().to_string();
    let words_preview = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &words_into_arg,
                "--kit-file",
                &kit_arg,
                "--preview",
                "--apply-configuration",
                "--json",
            ],
            None,
        )
        .await;
    assert!(
        words_preview.status.success(),
        "{}",
        text(&words_preview.stderr)
    );
    // A preview in words names the same sets before anything is confirmed.
    let plain_preview = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &words_into_arg,
                "--kit-file",
                &kit_arg,
                "--preview",
                "--apply-configuration",
            ],
            None,
        )
        .await;
    assert!(
        plain_preview.status.success(),
        "{}",
        text(&plain_preview.stderr)
    );
    let previewed = text(&plain_preview.stdout);
    assert_eq!(
        previewed
            .lines()
            .filter(|line| line.starts_with("Not applied"))
            .count(),
        2,
        "{previewed}"
    );
    assert!(
        previewed
            .lines()
            .any(|line| line.starts_with("Not applied") && line.contains("tools")),
        "{previewed}"
    );
    let in_words = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &words_into_arg,
                "--kit-file",
                &kit_arg,
                "--confirm-plan",
                &digest_of(&words_preview),
                "--apply-configuration",
            ],
            None,
        )
        .await;
    assert!(in_words.status.success(), "{}", text(&in_words.stderr));
    let said = text(&in_words.stdout);
    let not_applied: Vec<&str> = said
        .lines()
        .filter(|line| line.starts_with("Not applied"))
        .collect();
    assert_eq!(not_applied.len(), 2, "{said}");
    assert!(
        not_applied.iter().any(|line| line.contains("tools")),
        "{said}"
    );
    assert!(
        !said.contains("BASH_ENV") && !said.contains("restored/tool"),
        "{said}"
    );
    assert_eq!(
        after.ceilings, before.ceilings,
        "a restriction is not restored"
    );
    assert_eq!(
        after.storage, before.storage,
        "the service this host selects is its own"
    );
    assert_eq!(
        after.startup, before.startup,
        "how its daemon starts is its own"
    );
    assert_eq!(after.network, before.network);
    assert!(after.revision > before.revision, "one validated edit");
}

/// KR-REQ-20.17: a configuration from a release newer than this one reads is not applied, by
/// whatever the loader would have left out of it, and the restore stops before it writes anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_configuration_from_a_newer_release_is_not_applied_and_nothing_is_written() {
    let world = World::new();
    let rig = Rig::start(SignIn::Usable).await;
    let mut newer: serde_json::Value =
        serde_json::from_slice(&backed_up_configuration()).expect("a document is JSON");
    newer["level"] = serde_json::json!(kr_protocol::hostinfo::configuration::LEVEL + 1);
    newer["a_section_of_a_newer_release"] = serde_json::json!({});
    let held: Vec<(String, Vec<u8>)> = vec![
        (session_name(0x01), plaintext("session one: ", 300)),
        (
            "host/configuration.json".to_owned(),
            serde_json::to_vec(&newer).expect("a document"),
        ),
    ];
    let sealed = seal(&world, 1, &borrowed(&held));
    rig.put(&world, &sealed, None).await;
    let kit = rig.work.join("kit.txt");
    std::fs::write(&kit, world.kit_text(&[rig.origin()])).expect("the kit file");
    let into = folder(&rig, "restored");
    let before = host_document(&rig);
    let refused = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into.display().to_string(),
                "--kit-file",
                &kit.display().to_string(),
                "--preview",
                "--apply-configuration",
            ],
            None,
        )
        .await;
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("newer release"),
        "{}",
        text(&refused.stderr)
    );
    assert!(names(&into).is_empty());
    assert_eq!(host_document(&rig), before);
}

/// What this host keeps of itself, read through its own interfaces: its stored secrets, its
/// configuration document and its paired devices.
async fn host_state(rig: &Rig) -> String {
    let environment = rig.temp.environment();
    let mut parts = Vec::new();
    for (name, bytes) in tree(&environment.secrets_dir()) {
        parts.push(format!("secret {name} {}", sha(&bytes)));
    }
    let configuration = std::fs::read(kr_worker::config::document_path(&environment))
        .expect("the configuration document");
    parts.push(format!("configuration {}", sha(&configuration)));
    let devices = rig.run(&["device", "list", "--json"], None).await;
    assert!(devices.status.success(), "{}", text(&devices.stderr));
    parts.push(format!("devices {}", text(&devices.stdout)));
    parts.join("\n")
}

fn sha(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Whether reading a file failed because another process holds it open without sharing it, which
/// is a Windows error (a sharing violation or a lock violation).
fn held_open(error: &std::io::Error) -> bool {
    cfg!(windows) && matches!(error.raw_os_error(), Some(32 | 33))
}

/// The name of the lock file the daemon holds for its environment (the file `EnvironmentPaths::singleton_lock` names).
const HOST_LOCK_FILE: &str = "controller.lock";

/// Whether a file that cannot be read is the daemon's own lock file, which the daemon holds open on
/// Windows without sharing it (it records the daemon's process id, which holds no secret). A lock
/// file nothing holds is read, and so is every lock file on Unix. A directory or an entry that is
/// named like one is not this, whatever the error.
fn is_the_daemons_held_lock_file(path: &Path, error: &std::io::Error) -> bool {
    held_open(error) && path.file_name().is_some_and(|name| name == HOST_LOCK_FILE)
}

/// Whether a failure to look at something leaves nothing there to scan: it was removed since its
/// folder was listed, or was never made.
fn is_gone(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
}

/// Every file below `root`, by relative path.
///
/// A folder, an entry or a file the scan cannot look at would leave a scan of the tree vacuous, so
/// it fails the case, unless it is gone ([`is_gone`]) or is the daemon's lock file held open
/// ([`is_the_daemons_held_lock_file`], a file that is read, nothing else). A socket or a pipe is not
/// a file and is not read.
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, at: &Path, into: &mut BTreeMap<String, Vec<u8>>) {
        let entries = match std::fs::read_dir(at) {
            Ok(entries) => entries,
            Err(error) if is_gone(&error) => return,
            Err(error) => panic!("{} cannot be listed: {error}", at.display()),
        };
        for entry in entries {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(error) if is_gone(&error) => continue,
                Err(error) => panic!("an entry of {} cannot be read: {error}", at.display()),
            };
            let kind = match std::fs::metadata(&path) {
                Ok(kind) => kind,
                Err(error) if is_gone(&error) => continue,
                Err(error) => panic!("{} cannot be examined: {error}", path.display()),
            };
            if kind.is_dir() {
                walk(root, &path, into);
            } else if kind.is_file() {
                let bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(error)
                        if is_gone(&error) || is_the_daemons_held_lock_file(&path, &error) =>
                    {
                        continue;
                    }
                    Err(error) => panic!("{} cannot be read: {error}", path.display()),
                };
                // Named with `/` between its parts on every platform, so a case compares a name
                // with the same text wherever it runs.
                into.insert(
                    path.strip_prefix(root)
                        .expect("below the root")
                        .components()
                        .map(|part| part.as_os_str().to_string_lossy())
                        .collect::<Vec<_>>()
                        .join("/"),
                    bytes,
                );
            }
        }
    }
    let mut found = BTreeMap::new();
    walk(root, root, &mut found);
    found
}

/* -------------------------------------------------------------------------- */
/* A terminal window                                                           */
/* -------------------------------------------------------------------------- */

/// A terminal window `kr` runs in, with the person's side of it: what the window has shown, and a
/// way to type.
#[cfg(unix)]
struct Window {
    terminal: portable_pty::PtyPair,
    shell: Box<dyn portable_pty::Child + Send + Sync>,
    typing: Box<dyn Write + Send>,
    seen: Arc<Mutex<Vec<u8>>>,
}

#[cfg(unix)]
impl Drop for Window {
    fn drop(&mut self) {
        let _ = self.shell.kill();
        let _ = self.shell.wait();
    }
}

#[cfg(unix)]
impl Window {
    /// Opens a window whose shell runs `kr` with `arguments`, prints the status it ended with, and
    /// then reads one line of its own, so a test can tell whether anything was left waiting in the
    /// terminal's input.
    fn run(rig: &Rig, arguments: &[&str]) -> Self {
        Self::open(rig, arguments, "", b"")
    }

    /// As [`Self::run`], with `kr`'s standard input redirected as the shell word `input` says
    /// (`< /dev/tty` makes it the terminal device itself, which some systems cannot poll).
    fn run_with_input(rig: &Rig, arguments: &[&str], input: &str) -> Self {
        Self::open(rig, arguments, input, b"")
    }

    /// As [`Self::run`], with `typed_ahead` already typed into the window before the shell starts,
    /// so it is waiting in the terminal's input before `kr` has shown anything.
    fn run_after_typing(rig: &Rig, arguments: &[&str], typed_ahead: &[u8]) -> Self {
        Self::open(rig, arguments, "", typed_ahead)
    }

    fn open(rig: &Rig, arguments: &[&str], input: &str, typed_ahead: &[u8]) -> Self {
        let terminal = portable_pty::native_pty_system()
            .openpty(portable_pty::PtySize {
                rows: 24,
                cols: 200,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a terminal");
        let mut command = portable_pty::CommandBuilder::new("/bin/sh");
        command.arg("-c");
        // The shell ignores the interrupt a Ctrl-C raises, so that it outlives the command it runs
        // and the test can read what the command left; `kr` installs its own handler.
        command.arg(format!(
            "trap '' INT; \"$KR\" \"$@\" {input}; echo \"kr ended $?\"; IFS= read -r first; echo \"first:$first\""
        ));
        command.arg("sh");
        for argument in arguments {
            command.arg(argument);
        }
        command.env_clear();
        for (name, value) in rig.variables() {
            command.env(name, value);
        }
        command.env("KR", kr().display().to_string());
        command.cwd(&rig.work);
        let mut typing = terminal.master.take_writer().expect("a writer");
        typing
            .write_all(typed_ahead)
            .and_then(|()| typing.flush())
            .expect("types into the window");
        let shell = terminal
            .slave
            .spawn_command(command)
            .expect("starts the window's shell");
        let mut reader = terminal.master.try_clone_reader().expect("a reader");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                collected
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(&buffer[..read]);
            }
        });
        Self {
            terminal,
            shell,
            typing,
            seen,
        }
    }

    /// What the window has shown so far, with the terminal's own line endings made plain.
    fn shown(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().unwrap_or_else(PoisonError::into_inner))
            .replace("\r\n", "\n")
    }

    /// Waits until the window has shown `marker`, and returns what it has shown. It fails when it
    /// never does.
    fn wait_for(&self, marker: &str) -> String {
        let started = Instant::now();
        loop {
            let shown = self.shown();
            if shown.contains(marker) {
                return shown;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the window never showed {marker:?}: {}",
                shown.escape_debug()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Types bytes as they are.
    fn type_bytes(&mut self, bytes: &[u8]) {
        self.typing
            .write_all(bytes)
            .and_then(|()| self.typing.flush())
            .expect("types into the window");
    }

    /// Types one line, as a person does.
    fn type_line(&mut self, line: &str) {
        self.type_bytes(format!("{line}\n").as_bytes());
    }

    /// Whether the terminal echoes what is typed, as its modes say now.
    fn echoes(&self) -> bool {
        use std::os::unix::fs::OpenOptionsExt as _;

        let name = self
            .terminal
            .master
            .tty_name()
            .expect("the terminal's name");
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOCTTY)
            .open(name)
            .expect("the terminal opens");
        rustix::termios::tcgetattr(&tty)
            .expect("the terminal's modes")
            .local_modes
            .contains(rustix::termios::LocalModes::ECHO)
    }
}

/* -------------------------------------------------------------------------- */
/* What a restore needs before it reads anything                               */
/* -------------------------------------------------------------------------- */

/// Waits until the service has been asked `count` times for `path`. It fails when it never is, so a
/// command that stopped early fails the test and does not hold it.
async fn reached(web: &ServiceWeb, path: &str, count: usize) {
    tokio::time::timeout(LIVENESS_DEADLINE, web.requests_reach(path, count))
        .await
        .unwrap_or_else(|_| panic!("the service was never asked {count} times for {path}"));
}

/// A host with a backup in its service, a kit file naming it, and a folder to fill.
struct Fixture {
    world: World,
    rig: Rig,
    held: Vec<(String, Vec<u8>)>,
    kit: String,
    into: PathBuf,
}

impl Fixture {
    async fn new() -> Self {
        let world = World::new();
        let rig = Rig::start(SignIn::Usable).await;
        let held = members();
        let sealed = seal(&world, 1, &borrowed(&held));
        rig.put(&world, &sealed, None).await;
        let kit = rig.work.join("kit.txt");
        std::fs::write(&kit, world.kit_text(&[rig.origin()])).expect("the kit file");
        let into = folder(&rig, "restored");
        Self {
            world,
            rig,
            held,
            kit: kit.display().to_string(),
            into,
        }
    }

    fn folder_arg(&self) -> String {
        self.into.display().to_string()
    }

    /// `kr backup restore` with the kit file and `more`.
    fn line<'a>(&'a self, into: &'a str, more: &[&'a str]) -> Vec<&'a str> {
        let mut line = vec!["backup", "restore", "--into", into, "--kit-file", &self.kit];
        line.extend_from_slice(more);
        line
    }

    async fn preview(&self) -> std::process::Output {
        let into = self.folder_arg();
        let preview = self
            .rig
            .run(&self.line(&into, &["--preview", "--json"]), None)
            .await;
        assert!(preview.status.success(), "{}", text(&preview.stderr));
        preview
    }

    fn bundle_reads(&self) -> usize {
        self.rig.served.web().requests_to(SYNC)
    }
}

/// KR-REQ-24.27: privacy mode on keeps a restore from starting, before a kit is read or anything
/// is asked of the service. The control is that the same command goes on once it is off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_is_refused_while_privacy_mode_is_on_before_anything_leaves_the_host() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let on = fixture.rig.run(&["privacy", "on"], None).await;
    assert!(on.status.success(), "{}", text(&on.stderr));

    // The kit file is not there to be read: a command that refused only when the daemon did would
    // fail on the kit and not on privacy mode.
    let refused = fixture
        .rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into,
                "--kit-file",
                "/nonexistent/kit.txt",
                "--preview",
            ],
            None,
        )
        .await;
    assert_eq!(refused.status.code(), Some(8), "{}", text(&refused.stderr));
    assert!(text(&refused.stderr).contains("privacy mode is on"));
    assert_eq!(fixture.bundle_reads(), 0, "no bundle was asked for");
    assert_eq!(
        fixture.rig.served.web().requests_to(OBJECT_READ),
        0,
        "no object was asked for"
    );
    assert!(names(&fixture.into).is_empty());

    let off = fixture.rig.run(&["privacy", "off"], None).await;
    assert!(off.status.success(), "{}", text(&off.stderr));
    let allowed = fixture
        .rig
        .run(&fixture.line(&into, &["--preview"]), None)
        .await;
    assert!(allowed.status.success(), "{}", text(&allowed.stderr));
}

/// KR-REQ-20.19: self-hosted retrieval is refused by name, and nothing is asked of any service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kit_that_names_only_a_self_hosted_service_is_refused_by_name_and_asks_nothing() {
    let fixture = Fixture::new().await;
    std::fs::write(
        &fixture.kit,
        fixture
            .world
            .kit_text(&["https://backups.self-hosted.example"]),
    )
    .expect("the kit file");
    let into = fixture.folder_arg();
    let refused = fixture
        .rig
        .run(&fixture.line(&into, &["--preview"]), None)
        .await;
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("self-hosted"),
        "{}",
        text(&refused.stderr)
    );
    assert_eq!(fixture.bundle_reads(), 0);
    assert!(names(&fixture.into).is_empty());
}

/// A host that is signed in to no account says so and what to do, and sends no bundle read, because
/// the service answers a read with no token as a bundle that is not there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_is_signed_in_to_no_account_says_so_and_sends_no_read() {
    let world = World::new();
    let rig = Rig::start(SignIn::Nobody).await;
    let kit = rig.work.join("kit.txt");
    std::fs::write(&kit, world.kit_text(&[rig.origin()])).expect("the kit file");
    let into = folder(&rig, "restored");
    let refused = rig
        .run(
            &[
                "backup",
                "restore",
                "--into",
                &into.display().to_string(),
                "--kit-file",
                &kit.display().to_string(),
                "--preview",
            ],
            None,
        )
        .await;
    assert_eq!(refused.status.code(), Some(8), "{}", text(&refused.stderr));
    let said = text(&refused.stderr);
    assert!(said.contains("no account is signed in"), "{said}");
    assert!(said.contains("kr account sign-in"), "{said}");
    assert_eq!(rig.served.web().requests_to(SYNC), 0);
}

/// KR-REQ-20.14: a service's refusal can repeat the locator the kit supplied. Nothing the command
/// prints carries more of the locator than the eight characters it shows back to be checked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_the_service_words_with_the_locator_reaches_no_output_with_it() {
    let fixture = Fixture::new().await;
    fixture.rig.served.web().fail(
        SYNC,
        1,
        Moment::Echo {
            status: 500,
            code: "INTERNAL",
        },
    );
    let into = fixture.folder_arg();
    let refused = fixture
        .rig
        .run(&fixture.line(&into, &["--preview"]), None)
        .await;
    assert!(!refused.status.success());
    let shown = format!("{}{}", text(&refused.stdout), text(&refused.stderr));
    let locator = &fixture.world.locator;
    assert!(
        !shown.contains(&locator[..9]),
        "more of the locator than the first eight characters is in {shown}"
    );
    assert!(
        shown.contains(&locator[..8]),
        "the first eight are shown back"
    );
    // The control: the request the service refused did carry the whole locator.
    let sent = fixture
        .rig
        .served
        .web()
        .arrived()
        .into_iter()
        .find(|got| got.path == SYNC)
        .expect("a bundle read");
    assert!(sent.body.to_string().contains(locator.as_str()));
}

/// The confirmation is for the plan that was shown: a digest that is not the plan's, a digest that
/// a newer generation made stale, and no way to ask all write nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_digest_of_the_plan_in_hand_writes_anything() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let digest = digest_of(&fixture.preview().await);

    // A digest that is not the plan's.
    let wrong = "0".repeat(64);
    let refused = fixture
        .rig
        .run(&fixture.line(&into, &["--confirm-plan", &wrong]), None)
        .await;
    assert!(!refused.status.success());
    assert!(names(&fixture.into).is_empty());
    // One that is not a digest at all is a usage failure.
    let malformed = fixture
        .rig
        .run(&fixture.line(&into, &["--confirm-plan", "yes"]), None)
        .await;
    assert_eq!(malformed.status.code(), Some(2));

    // No terminal and neither flag: the command has no way to ask, and says what to do.
    let unasked = fixture.rig.run(&fixture.line(&into, &[]), None).await;
    assert_eq!(unasked.status.code(), Some(2));
    assert!(text(&unasked.stderr).contains("--confirm-plan"));
    assert!(names(&fixture.into).is_empty());

    // The digest is for this folder: the same backup into another folder has another.
    let other = folder(&fixture.rig, "restored-elsewhere");
    let elsewhere = fixture
        .rig
        .run(
            &fixture.line(&other.display().to_string(), &["--preview", "--json"]),
            None,
        )
        .await;
    assert_ne!(digest_of(&elsewhere), digest);

    // A newer generation published after the preview changes the plan, so its digest is stale.
    let newer = seal(&fixture.world, 2, &borrowed(&fixture.held));
    fixture.rig.put(&fixture.world, &newer, None).await;
    let stale = fixture
        .rig
        .run(&fixture.line(&into, &["--confirm-plan", &digest]), None)
        .await;
    assert!(!stale.status.success());
    assert!(
        names(&fixture.into).is_empty(),
        "a stale digest writes nothing"
    );

    // The control: the digest of the plan now in hand writes.
    let fresh = digest_of(&fixture.preview().await);
    assert_ne!(fresh, digest);
    let written = fixture
        .rig
        .run(&fixture.line(&into, &["--confirm-plan", &fresh]), None)
        .await;
    assert!(written.status.success(), "{}", text(&written.stderr));
    assert!(names(&fixture.into).contains(&"restore.json".to_owned()));
}

/// A relative folder is resolved in the command's own directory, and the plan says where.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relative_folder_is_resolved_in_the_commands_own_directory() {
    let fixture = Fixture::new().await;
    let relative = fixture.rig.work.join("here");
    std::fs::create_dir(&relative).expect("a folder");
    let preview = fixture
        .rig
        .run(&fixture.line("here", &["--preview", "--json"]), None)
        .await;
    assert!(preview.status.success(), "{}", text(&preview.stderr));
    let plan: Value = serde_json::from_slice(&preview.stdout).expect("the plan is JSON");
    assert_eq!(
        std::fs::canonicalize(plan["folder"].as_str().expect("a folder")).expect("it exists"),
        std::fs::canonicalize(&relative).expect("it exists")
    );
}

/* -------------------------------------------------------------------------- */
/* The relay under privacy mode, and the waits the service asks for           */
/* -------------------------------------------------------------------------- */

impl Fixture {
    /// The request number, counted from the start of a confirmed run, that reads the first range
    /// of the second session member: the manifest is first and the first member's one range second.
    const SECOND_MEMBER: u32 = 3;

    fn confirm_line<'a>(&'a self, into: &'a str, digest: &'a str) -> Vec<&'a str> {
        self.line(into, &["--confirm-plan", digest])
    }

    /// Everything the service was asked for an object, so far.
    fn object_reads(&self) -> usize {
        self.rig.served.web().requests_to(OBJECT_READ)
    }
}

/// A read in flight when privacy mode changes: nothing more is sent, the files the run wrote are
/// removed, and the run says which it was.
async fn a_read_in_flight_when_privacy_mode_changes(turn_it_off_again: bool) -> String {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let digest = digest_of(&fixture.preview().await);
    let web = fixture.rig.served.web();
    let base = fixture.object_reads();
    web.fail(OBJECT_READ, Fixture::SECOND_MEMBER, Moment::Slow);
    let run = fixture
        .rig
        .spawn(&fixture.confirm_line(&into, &digest), &Input::Nothing);
    reached(web, OBJECT_READ, base + 3).await;
    assert_eq!(
        names(&fixture.into),
        ["session-0001.json"],
        "the first member is written while the second is being read"
    );

    let on = fixture.rig.run(&["privacy", "on"], None).await;
    assert!(on.status.success(), "{}", text(&on.stderr));
    if turn_it_off_again {
        let off = fixture.rig.run(&["privacy", "off"], None).await;
        assert!(off.status.success(), "{}", text(&off.stderr));
    }
    web.release_held();
    let ended = run.ended_within_the_deadline().await;
    assert!(!ended.status.success());
    assert!(
        names(&fixture.into).is_empty(),
        "the run removed what it wrote"
    );
    assert_eq!(
        fixture.object_reads(),
        base + 3,
        "nothing more was asked of the service once privacy mode had changed"
    );
    text(&ended.stderr)
}

/// KR-REQ-24.27, 24.28: a read in flight when privacy mode turns on is not delivered, and the run
/// says privacy mode is on and what to do about it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_in_flight_when_privacy_mode_turns_on_is_not_delivered_and_the_run_removes_its_files()
 {
    let said = a_read_in_flight_when_privacy_mode_changes(false).await;
    assert!(said.contains("kr privacy off"), "{said}");
}

/// Privacy mode turned on and off again while a read is in flight is a change too, and the advice
/// is not to turn it off, which it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_in_flight_when_privacy_mode_turns_on_and_off_again_is_not_delivered_either() {
    let said = a_read_in_flight_when_privacy_mode_changes(true).await;
    assert!(said.contains("turned on and off"), "{said}");
    assert!(!said.contains("kr privacy off"), "{said}");
}

/// The relay refuses with one code for privacy mode and for a sign-in the service did not accept,
/// and the command tells them apart: with privacy mode off the advice is to sign in again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_the_service_did_not_accept_is_told_as_one_and_not_as_privacy_mode() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    fixture.rig.served.web().fail(
        OBJECT_READ,
        1,
        Moment::Refuse {
            status: 403,
            code: "FORBIDDEN",
            retry_after_seconds: None,
        },
    );
    let refused = fixture
        .rig
        .run(&fixture.line(&into, &["--preview"]), None)
        .await;
    assert_eq!(refused.status.code(), Some(8), "{}", text(&refused.stderr));
    let said = text(&refused.stderr);
    assert!(said.contains("kr account sign-in"), "{said}");
    assert!(!said.contains("privacy"), "{said}");
}

/// What the person typed at the terminal, scripted for the library's own seam.
struct Scripted(Vec<&'static str>);

impl kr_cli::backup::restore::Conversation for Scripted {
    fn show(&mut self, _lines: &[kr_client::shown::Shown]) {}

    async fn ask(&mut self, _question: &kr_client::shown::Shown) -> kr_cli::Result<Option<String>> {
        Ok(self.0.pop().map(str::to_owned))
    }
}

/// A host that turns privacy mode on, through a connection of its own, after the restore has
/// written its last member and before it reads privacy mode again.
struct TurnsPrivacyOnAfterTheLastMember {
    asking: kr_cli::daemon::Daemon,
    other: kr_cli::daemon::Daemon,
    turn_on: bool,
    asked: usize,
    folder: PathBuf,
}

impl kr_cli::backup::restore::Privacy for TurnsPrivacyOnAfterTheLastMember {
    async fn status(&mut self) -> kr_cli::Result<kr_protocol::privacy::PrivacyReport> {
        self.asked += 1;
        if self.turn_on {
            assert_eq!(
                names(&self.folder),
                [
                    "configuration.json",
                    "session-0001.json",
                    "session-0002.json"
                ],
                "privacy mode turns on after the last member is written and before the record"
            );
            let _: kr_protocol::privacy::PrivacyReport = self
                .other
                .mutate(
                    kr_protocol::method::Method::PrivacySet,
                    &kr_protocol::privacy::PrivacySetParams { enabled: true },
                )
                .await?;
        }
        self.asking.status().await
    }
}

async fn restore_through_the_library(
    fixture: &Fixture,
    turn_on: bool,
) -> (
    kr_cli::Result<kr_cli::backup::restore::Outcome>,
    Option<kr_cli::backup::directory::Held>,
    usize,
) {
    restore_through_the_library_pausing(
        fixture,
        turn_on,
        kr_cli::backup::source::real_pause(),
        || {},
    )
    .await
}

/// As [`restore_through_the_library`], spending the waits the service names with `pause`, and
/// calling `armed` between the preview and the confirmed run.
async fn restore_through_the_library_pausing(
    fixture: &Fixture,
    turn_on: bool,
    pause: kr_cli::backup::source::Pause,
    armed: impl FnOnce(),
) -> (
    kr_cli::Result<kr_cli::backup::restore::Outcome>,
    Option<kr_cli::backup::directory::Held>,
    usize,
) {
    use kr_cli::backup::directory::Destination;
    use kr_cli::backup::restore::{Decision, Privacy as _, Run, restore_with};
    use kr_cli::backup::source::{DaemonBundleWriter, DaemonSource};
    use kr_cli::cli::EnvironmentSelector;
    use kr_cli::daemon::Daemon;

    let paths = fixture.rig.temp.paths();
    let bundles = DaemonBundleWriter::new(paths.clone(), None);
    let selector = EnvironmentSelector { environment: None };
    let mut privacy = TurnsPrivacyOnAfterTheLastMember {
        asking: Daemon::open(paths, &selector).await.expect("a connection"),
        other: Daemon::open(paths, &selector)
            .await
            .expect("another connection"),
        turn_on: false,
        asked: 0,
        folder: fixture.into.clone(),
    };
    let began = privacy.status().await.expect("privacy mode reads");
    privacy.asked = 0;
    let source = Arc::new(DaemonSource::new(
        Daemon::open(paths, &selector).await.expect("a connection"),
        pause,
    ));
    let destination = Destination::check(&fixture.into).expect("the folder passes");
    let kit = kr_client::recovery::parse_kit(&fixture.world.kit_text(&[fixture.rig.origin()]))
        .expect("the kit reads");
    let environment = fixture.rig.temp.environment_id().to_string();
    let run = |decision| Run {
        source: Arc::clone(&source) as _,
        bundles: Some(&bundles),
        accept_older: None,
        configuration: None,
        began: &began,
        destination: &destination,
        environment: environment.clone(),
        archive: None,
        decision,
    };
    // The digest of the plan, as a preview gives it.
    let mut held = None;
    let previewed = restore_with(
        run(Decision::Preview),
        kit.clone(),
        &mut privacy,
        &mut Scripted(Vec::new()),
        &mut held,
    )
    .await
    .expect("the preview");
    let kr_cli::backup::restore::Outcome::Previewed(planned) = previewed else {
        panic!("a preview previews");
    };
    privacy.turn_on = turn_on;
    armed();
    let mut held = None;
    let outcome = restore_with(
        run(Decision::Confirmed(planned.digest().to_owned())),
        kit,
        &mut privacy,
        &mut Scripted(Vec::new()),
        &mut held,
    )
    .await;
    (outcome, held, privacy.asked)
}

/// KR-REQ-24.27: privacy mode turned on after the last member is written and before the record is
/// made stops the run, which removes its files and publishes no record. The control is the same
/// restore with nothing turned on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn privacy_mode_turned_on_after_the_last_member_removes_the_files_and_makes_no_record() {
    let control = Fixture::new().await;
    let (outcome, _held, asked) = restore_through_the_library(&control, false).await;
    assert!(outcome.is_ok(), "{:?}", outcome.err());
    assert_eq!(
        asked, 1,
        "privacy mode is read once more after the last member"
    );
    assert!(names(&control.into).contains(&"restore.json".to_owned()));

    let fixture = Fixture::new().await;
    let (outcome, held, _) = restore_through_the_library(&fixture, true).await;
    let error = outcome.expect_err("the run is stopped");
    assert!(error.to_string().contains("privacy mode"), "{error}");
    let mut held = held.expect("the folder was opened, so the files were written");
    assert!(held.clean().is_empty());
    assert!(
        names(&fixture.into).is_empty(),
        "no file is left and no record was made: {:?}",
        names(&fixture.into)
    );
}

/// The wait a service names: a read it asked to be left alone for is repeated once the time has
/// passed, with nothing removed meanwhile; the daemon's clock is the test's, which moves it when
/// the command says it is waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delay_the_service_names_is_waited_out_and_the_same_read_repeated() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let digest = digest_of(&fixture.preview().await);
    let web = fixture.rig.served.web();
    let base = fixture.object_reads();
    web.fail(
        OBJECT_READ,
        Fixture::SECOND_MEMBER,
        Moment::Refuse {
            status: 429,
            code: "RATE_LIMITED",
            retry_after_seconds: Some(1),
        },
    );
    let run = fixture
        .rig
        .spawn(&fixture.confirm_line(&into, &digest), &Input::Nothing);
    run.stderr_shows("Waiting 1 s, wait 1 of 5.").await;
    assert_eq!(
        names(&fixture.into),
        ["session-0001.json"],
        "what was written is kept while the command waits"
    );
    assert_eq!(
        fixture.object_reads(),
        base + 3,
        "nothing is sent inside the delay"
    );
    fixture.rig.timer.advance(Duration::from_secs(2));
    let ended = run.ended_within_the_deadline().await;
    assert!(ended.status.success(), "{}", text(&ended.stderr));
    assert!(names(&fixture.into).contains(&"restore.json".to_owned()));
    assert_eq!(
        std::fs::read(fixture.into.join("session-0002.json")).expect("a file"),
        fixture.held[1].1
    );
}

/// The wait a service names is spent before the same read is asked again: the command does not ask
/// again until the time it said it would wait has passed. The test holds the wait where it is spent,
/// so a command that did not wait at all would finish before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_wait_a_service_names_is_spent_before_the_same_read_is_asked_again() {
    let fixture = Fixture::new().await;
    let spent = Arc::new(Mutex::new(Vec::<Duration>::new()));
    let begun = Arc::new(tokio::sync::Notify::new());
    let over = Arc::new(tokio::sync::Notify::new());
    let pause: kr_cli::backup::source::Pause = {
        let (spent, begun, over) = (Arc::clone(&spent), Arc::clone(&begun), Arc::clone(&over));
        Arc::new(move |time| {
            spent
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(time);
            begun.notify_one();
            let over = Arc::clone(&over);
            Box::pin(async move { over.notified().await })
        })
    };
    let web = Arc::clone(fixture.rig.served.web());
    let restore = restore_through_the_library_pausing(&fixture, false, pause, || {
        web.fail(
            OBJECT_READ,
            Fixture::SECOND_MEMBER,
            Moment::Refuse {
                status: 429,
                code: "RATE_LIMITED",
                retry_after_seconds: Some(1),
            },
        );
    });
    tokio::pin!(restore);
    tokio::select! {
        _ = &mut restore => panic!("the restore finished without waiting for the service"),
        () = begun.notified() => {}
    }
    assert_eq!(
        *spent.lock().unwrap_or_else(PoisonError::into_inner),
        [Duration::from_secs(1)]
    );
    // The daemon's clock is the test's: the delay is over once it is moved past it.
    fixture.rig.timer.advance(Duration::from_secs(2));
    over.notify_one();
    let (outcome, _held, _asked) = restore.await;
    assert!(outcome.is_ok(), "{:?}", outcome.err());
    assert!(names(&fixture.into).contains(&"restore.json".to_owned()));
}

/// After five waits for one read the run stops, removes its files and says when to try again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_that_keeps_asking_for_quiet_stops_the_run_after_five_waits_and_removes_its_files()
 {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let digest = digest_of(&fixture.preview().await);
    let web = fixture.rig.served.web();
    let base = fixture.object_reads();
    web.fail(
        OBJECT_READ,
        Fixture::SECOND_MEMBER,
        Moment::Refuse {
            status: 429,
            code: "RATE_LIMITED",
            retry_after_seconds: Some(1),
        },
    );
    // The clock stands still, so the delay is never over: the command waits out what it is told.
    let ended = fixture
        .rig
        .spawn(&fixture.confirm_line(&into, &digest), &Input::Nothing)
        .ended_within_the_deadline()
        .await;
    assert!(!ended.status.success());
    let said = text(&ended.stderr);
    assert_eq!(said.matches("Waiting 1 s,").count(), 5, "{said}");
    assert!(said.contains("try again after"), "{said}");
    assert!(
        names(&fixture.into).is_empty(),
        "the run removed what it wrote"
    );
    assert_eq!(
        fixture.object_reads(),
        base + 3,
        "not one read was sent inside the delay"
    );
}

/* -------------------------------------------------------------------------- */
/* The folder                                                                  */
/* -------------------------------------------------------------------------- */

/// A folder other accounts may write in and a link to a folder are each refused before a kit is
/// read or the service is asked; a folder a group may write in is the person's own choice, and goes
/// ahead. A file's mode is Unix's, and the link is made here with Unix's call.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_folder_that_other_accounts_write_in_or_a_link_is_refused_before_anything_is_read() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new().await;
    let preview = |into: String| {
        let fixture = &fixture;
        async move {
            fixture
                .rig
                .run(&fixture.line(&into, &["--preview"]), Some(b""))
                .await
        }
    };

    // Other accounts may write in it.
    std::fs::set_permissions(&fixture.into, std::fs::Permissions::from_mode(0o777)).expect("mode");
    let refused = preview(fixture.folder_arg()).await;
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    assert!(text(&refused.stderr).contains("every account"));

    // A group may: the control, which goes ahead.
    std::fs::set_permissions(&fixture.into, std::fs::Permissions::from_mode(0o775)).expect("mode");
    let allowed = preview(fixture.folder_arg()).await;
    assert!(allowed.status.success(), "{}", text(&allowed.stderr));

    // A link to a folder.
    let link = fixture.rig.temp.root().join("link");
    std::os::unix::fs::symlink(&fixture.into, &link).expect("a link");
    let refused = preview(link.display().to_string()).await;
    assert_eq!(refused.status.code(), Some(2));
    assert!(text(&refused.stderr).contains("symbolic link"));

    assert_eq!(
        fixture.bundle_reads(),
        1,
        "only the control asked the service"
    );
}

/// A folder with something in it, one that is not there and a file are each refused before a kit
/// is read or the service is asked, and what a file manager adds to a folder is named.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_folder_with_something_in_it_one_that_is_not_there_and_a_file_are_refused_before_anything_is_read()
 {
    let fixture = Fixture::new().await;
    let preview = |into: String| {
        let fixture = &fixture;
        async move {
            fixture
                .rig
                .run(&fixture.line(&into, &["--preview"]), Some(b""))
                .await
        }
    };

    // A folder with something in it, and what a file manager adds is named.
    std::fs::write(fixture.into.join(".DS_Store"), b"x").expect("a file");
    let refused = preview(fixture.folder_arg()).await;
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    let said = text(&refused.stderr);
    assert!(
        said.contains("not empty") && said.contains(".DS_Store"),
        "{said}"
    );

    // A folder that is not there, and a file.
    let missing = fixture.rig.temp.root().join("missing");
    let refused = preview(missing.display().to_string()).await;
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    assert!(text(&refused.stderr).contains("does not exist"));
    let file = fixture.rig.temp.root().join("file");
    std::fs::write(&file, b"x").expect("a file");
    let refused = preview(file.display().to_string()).await;
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    assert!(text(&refused.stderr).contains("not a folder"));

    assert_eq!(fixture.bundle_reads(), 0, "no refusal asked the service");
}

/// While a member is being read the folder is renamed away and another is put at its path, which
/// holds files with the restore's own names. The run goes on through the handle it holds: what it
/// wrote is in the folder it opened, and what it removes is removed there. Nothing in the
/// replacement is touched, and no folder is removed.
#[cfg(unix)]
async fn the_folder_swapped_during_a_read(replacement_holds_decoys: bool) {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let digest = digest_of(&fixture.preview().await);
    let web = fixture.rig.served.web();
    let base = fixture.object_reads();
    // The second member's first range is slow, and its second is refused, so the run fails after
    // the swap and has to clean up.
    web.fail(OBJECT_READ, Fixture::SECOND_MEMBER, Moment::Slow);
    web.fail(
        OBJECT_READ,
        Fixture::SECOND_MEMBER + 1,
        Moment::Refuse {
            status: 403,
            code: "FORBIDDEN",
            retry_after_seconds: None,
        },
    );
    let run = fixture
        .rig
        .spawn(&fixture.confirm_line(&into, &digest), &Input::Nothing);
    reached(web, OBJECT_READ, base + 3).await;

    let moved = fixture.rig.temp.root().join("moved-away");
    std::fs::rename(&fixture.into, &moved).expect("the folder is renamed");
    std::fs::create_dir(&fixture.into).expect("another folder at its path");
    let decoys = [
        "session-0001.json",
        "session-0002.json",
        "configuration.json",
        "restore.json",
    ];
    if replacement_holds_decoys {
        for name in decoys {
            std::fs::write(fixture.into.join(name), b"DECOY").expect("a decoy");
        }
    }
    web.release_held();
    let ended = run.ended_within_the_deadline().await;
    assert!(!ended.status.success());

    if replacement_holds_decoys {
        for name in decoys {
            assert_eq!(
                std::fs::read(fixture.into.join(name)).expect("the decoy is still there"),
                b"DECOY",
                "{name} is untouched"
            );
        }
    }
    assert_eq!(
        names(&fixture.into).len(),
        if replacement_holds_decoys {
            decoys.len()
        } else {
            0
        },
        "the replacement gained and lost nothing"
    );
    assert!(
        names(&moved).is_empty(),
        "the folder the run opened holds none of its files once it removed them: {:?}",
        names(&moved)
    );
    assert!(
        moved.is_dir() && fixture.into.is_dir(),
        "no folder was removed"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_folder_swapped_for_one_holding_the_same_names_is_not_written_into_or_cleaned() {
    the_folder_swapped_during_a_read(true).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_folder_swapped_for_an_empty_one_is_not_written_into_or_removed() {
    the_folder_swapped_during_a_read(false).await;
}

/* -------------------------------------------------------------------------- */
/* The kit                                                                     */
/* -------------------------------------------------------------------------- */

/// KR-REQ-20.14: a kit is read outside every session. The command refuses before it reads the kit
/// or asks the service anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kit_is_not_read_inside_a_session() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let kit = fixture.world.kit_text(&[fixture.rig.origin()]);
    for variable in ["KR_SESSION", "KR_ATTACHMENT"] {
        let refused = fixture
            .rig
            .run_with(
                &["backup", "restore", "--into", &into, "--preview"],
                Some(kit.as_bytes()),
                &[(variable, "a-session")],
            )
            .await;
        assert_eq!(refused.status.code(), Some(8), "{}", text(&refused.stderr));
        assert!(text(&refused.stderr).contains("inside a KalaReach session"));
    }
    assert_eq!(fixture.bundle_reads(), 0);
    // The control: outside a session the same kit, piped, previews.
    let allowed = fixture
        .rig
        .run(
            &["backup", "restore", "--into", &into, "--preview"],
            Some(kit.as_bytes()),
        )
        .await;
    assert!(allowed.status.success(), "{}", text(&allowed.stderr));
}

/// A kit saved by an editor, with a byte-order mark and CR LF line ends and as long as a kit can
/// be, restores; one longer than any kit after those are taken out is refused before any service
/// is asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_longest_kit_with_a_byte_order_mark_and_crlf_restores_and_a_longer_one_is_refused() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let mut kit = fixture.world.kit_text(&[fixture.rig.origin()]);
    let mut more = 0;
    while kit.len() + "origin: https://pad-00.example\n".len() <= kit_limit() {
        kit.push_str(&format!("origin: https://pad-{more:02}.example\n"));
        more += 1;
    }
    assert!(
        kit.len() <= kit_limit() && kit.len() + 20 > kit_limit(),
        "{}",
        kit.len()
    );
    let mut sent = vec![0xEF, 0xBB, 0xBF];
    sent.extend_from_slice(kit.replace('\n', "\r\n").as_bytes());
    assert!(
        sent.len() > kit_limit(),
        "the document as sent is over the limit"
    );
    let allowed = fixture
        .rig
        .run(
            &["backup", "restore", "--into", &into, "--preview"],
            Some(&sent),
        )
        .await;
    assert!(allowed.status.success(), "{}", text(&allowed.stderr));

    let reads = fixture.bundle_reads();
    let mut longer = kit.clone();
    longer.push_str("origin: https://one-too-many.example\n");
    let refused = fixture
        .rig
        .run(
            &["backup", "restore", "--into", &into, "--preview"],
            Some(longer.as_bytes()),
        )
        .await;
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    assert_eq!(
        fixture.bundle_reads(),
        reads,
        "nothing was asked of the service"
    );
}

fn kit_limit() -> usize {
    kr_client::recovery::MAX_RECOVERY_KIT_BYTES
}

/// A kit file that is a named pipe nobody writes to is refused, and does not hold the command.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kit_file_that_is_a_pipe_with_no_writer_is_refused_and_does_not_hang() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let fifo = fixture.rig.work.join("kit.fifo");
    let made = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "a named pipe is made");
    let fifo = fifo.display().to_string();
    let refused = tokio::time::timeout(
        LIVENESS_DEADLINE,
        fixture.rig.run(
            &[
                "backup",
                "restore",
                "--into",
                &into,
                "--kit-file",
                &fifo,
                "--preview",
            ],
            None,
        ),
    )
    .await
    .expect("the command did not hang");
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    assert!(text(&refused.stderr).contains("not a regular file"));
}

/// An interrupt, a termination, a hang-up or Ctrl-\ while a kit is being piped in and the writer
/// holds the pipe open ends the command promptly, with nothing asked of the service. The last would
/// otherwise end it with a core dump.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_signal_that_ends_a_command_waiting_for_a_kit_on_a_pipe_that_stays_open() {
    use rustix::process::Signal;

    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let kit = fixture.world.kit_text(&[fixture.rig.origin()]);
    let partial = &kit.as_bytes()[..kit.len() / 2];
    for signal in [Signal::INT, Signal::TERM, Signal::HUP, Signal::QUIT] {
        let run = fixture.rig.spawn(
            &["backup", "restore", "--into", &into, "--preview"],
            &Input::Held(partial),
        );
        run.stderr_shows("Reading the recovery kit from standard input.")
            .await;
        run.signal(signal);
        let ended = run.ended_within_the_deadline().await;
        assert!(!ended.status.success(), "{signal:?}");
        assert!(
            text(&ended.stderr).contains("stopped"),
            "{signal:?}: {}",
            text(&ended.stderr)
        );
    }
    assert_eq!(fixture.bundle_reads(), 0);
}

/// Ctrl-C while the files are being written stops the run and removes what it wrote.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interrupt_while_the_members_are_read_stops_the_run_and_removes_its_files() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let digest = digest_of(&fixture.preview().await);
    let web = fixture.rig.served.web();
    let base = fixture.object_reads();
    web.fail(OBJECT_READ, Fixture::SECOND_MEMBER, Moment::Slow);
    let run = fixture
        .rig
        .spawn(&fixture.confirm_line(&into, &digest), &Input::Nothing);
    reached(web, OBJECT_READ, base + 3).await;
    assert_eq!(names(&fixture.into), ["session-0001.json"]);
    run.interrupt();
    let ended = run.ended_within_the_deadline().await;
    assert!(!ended.status.success());
    assert!(
        names(&fixture.into).is_empty(),
        "the run removed what it wrote"
    );
}

/// The kit typed at a terminal: nothing is shown as it is typed, the document ends at a blank line,
/// what is shown back names the locator by its first eight characters, and what was pasted after
/// the document never reaches the shell the command was run from.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kit_typed_at_a_terminal_is_not_shown_and_what_follows_it_never_reaches_the_shell() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let kit = fixture.world.kit_text(&[fixture.rig.origin()]);
    let seed = fixture.world.seed_text();
    let locator = fixture.world.locator.clone();
    let mut window = Window::run(
        &fixture.rig,
        &["backup", "restore", "--into", &into, "--preview"],
    );
    window.wait_for("Nothing you paste is shown.");
    assert!(
        !window.echoes(),
        "the terminal shows nothing while the kit is typed"
    );
    // The kit, a blank line, and more than the command reads at once, which stays in the
    // terminal's queue unless the command throws it away.
    // Line ends are CR LF, as a kit pasted from a Windows editor has them.
    let after = "PASTED-AFTER-THE-KIT\n".repeat(25);
    window.type_bytes(format!("{kit}\n{after}").replace('\n', "\r\n").as_bytes());
    let shown = window.wait_for("Type yes if that is the kit you meant");
    assert!(!shown.contains(&seed), "the seed was shown");
    assert!(
        !shown.contains(&locator[..9]),
        "more of the locator than eight characters was shown"
    );
    assert!(
        shown.contains(&locator[..8]),
        "the first eight characters are shown back"
    );
    assert!(window.echoes(), "echo is back for the question");
    window.type_line("yes");
    let shown = window.wait_for("kr ended 0");
    assert!(
        shown.contains("Digest of this plan") || shown.contains("digest"),
        "{shown}"
    );
    // What follows in the terminal is the next thing typed, not what was pasted after the kit.
    window.type_line("marker");
    let shown = window.wait_for("first:");
    assert!(shown.contains("first:marker"), "{}", shown.escape_debug());
    assert!(!shown.contains(&seed));
}

/// A paste that is not a kit ends the command with no question after it, so what was pasted past
/// the end of the document is left for the shell unless the command throws it away.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn text_pasted_after_a_document_that_is_not_a_kit_never_reaches_the_shell() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let mut window = Window::run(
        &fixture.rig,
        &["backup", "restore", "--into", &into, "--preview"],
    );
    window.wait_for("Nothing you paste is shown.");
    // More than the command reads at once, so some of it is still in the terminal's queue when the
    // document ends.
    let after = "PASTED-AFTER-THE-DOCUMENT\n".repeat(25);
    window.type_bytes(
        format!("not a kit\n\n{after}")
            .replace('\n', "\r\n")
            .as_bytes(),
    );
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert_eq!(fixture.bundle_reads(), 0);
    window.type_line("marker");
    let shown = window.wait_for("first:");
    assert!(shown.contains("first:marker"), "{}", shown.escape_debug());
}

/// A kit typed at a terminal is not used until the person says it is the kit they meant: a wrong
/// answer ends the command before the service is asked anything.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kit_typed_at_a_terminal_is_not_used_unless_the_person_says_it_is_the_one_meant() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let kit = fixture.world.kit_text(&[fixture.rig.origin()]);
    let mut window = Window::run(
        &fixture.rig,
        &["backup", "restore", "--into", &into, "--preview"],
    );
    window.wait_for("Nothing you paste is shown.");
    window.type_bytes(format!("{kit}\n").as_bytes());
    window.wait_for("Type yes if that is the kit you meant");
    window.type_line("no");
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert_eq!(fixture.bundle_reads(), 0, "the kit was not used");
}

/// Ctrl-C while a kit is half typed ends the command and leaves the terminal as it was found.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interrupt_while_a_kit_is_half_typed_ends_the_command_and_puts_the_terminal_back() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let seed = fixture.world.seed_text();
    let mut window = Window::run(
        &fixture.rig,
        &["backup", "restore", "--into", &into, "--preview"],
    );
    window.wait_for("Nothing you paste is shown.");
    window.type_bytes(format!("kalareach-recovery-kit/1\nseed: {seed}\n").as_bytes());
    assert!(!window.echoes());
    window.type_bytes(&[0x03]);
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert!(window.echoes(), "echo is on again");
    assert!(!shown.contains(&seed));
    assert_eq!(fixture.bundle_reads(), 0);
}

/// At a terminal the command asks, and only yes writes. Ctrl-C at the question stops the run.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_a_terminal_only_yes_writes_and_an_interrupt_at_the_question_writes_nothing() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let question = "Type yes to write these files";

    let mut window = Window::run(&fixture.rig, &fixture.line(&into, &[]));
    window.wait_for(question);
    window.type_line("no");
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"));
    assert!(names(&fixture.into).is_empty());

    let mut window = Window::run(&fixture.rig, &fixture.line(&into, &[]));
    window.wait_for(question);
    window.type_bytes(&[0x03]);
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"));
    assert!(
        names(&fixture.into).is_empty(),
        "an interrupt at the question writes nothing"
    );

    let mut window = Window::run(&fixture.rig, &fixture.line(&into, &[]));
    window.wait_for(question);
    window.type_line("yes");
    window.wait_for("kr ended 0");
    assert!(names(&fixture.into).contains(&"restore.json".to_owned()));
}

/// Ctrl-C at the question ends the command also when its standard input is the terminal device
/// itself, which some systems cannot wait on with a timeout.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interrupt_at_the_question_ends_the_command_when_its_input_is_the_terminal_device() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let mut window = Window::run_with_input(&fixture.rig, &fixture.line(&into, &[]), "< /dev/tty");
    window.wait_for("Type yes to write these files");
    window.type_bytes(&[0x03]);
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert!(names(&fixture.into).is_empty());
}

/// A line typed before the question is shown is not the answer to it: the person answers what is on
/// the screen.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_line_typed_before_the_question_is_shown_does_not_answer_it() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let mut window = Window::run_after_typing(&fixture.rig, &fixture.line(&into, &[]), b"yes\n");
    window.wait_for("Type yes to write these files");
    window.type_line("no");
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert!(
        names(&fixture.into).is_empty(),
        "the line typed ahead confirmed nothing"
    );
}

/// What was typed before the kit prompt appeared is not part of the kit.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lines_typed_before_the_kit_prompt_appears_are_not_part_of_the_kit() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let kit = fixture.world.kit_text(&[fixture.rig.origin()]);
    let mut window = Window::run_after_typing(
        &fixture.rig,
        &["backup", "restore", "--into", &into, "--preview"],
        b"stray\n\n",
    );
    window.wait_for("Nothing you paste is shown.");
    window.type_bytes(format!("{kit}\n").as_bytes());
    window.wait_for("Type yes if that is the kit you meant");
    window.type_line("no");
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
}

/// A bundle that names more than one archive at the service is refused with each listed, and
/// `--archive` chooses one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_that_names_several_archives_lists_them_and_the_person_chooses_one() {
    let fixture = Fixture::new().await;
    let into = fixture.folder_arg();
    let other = ArchiveId::new(id(0x12));
    fixture.rig.served.web().put_bundle(
        &fixture.world.locator,
        ACCOUNT,
        bundle(
            &fixture.world,
            fixture.rig.origin(),
            None,
            &[archive(), other],
        ),
    );
    let refused = fixture
        .rig
        .run(&fixture.line(&into, &["--preview"]), None)
        .await;
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    let said = text(&refused.stderr);
    for listed in [archive(), other] {
        assert!(said.contains(&listed.to_string()), "{said}");
    }
    assert!(said.contains("--archive"), "{said}");
    assert!(names(&fixture.into).is_empty());

    let chosen = archive().to_string();
    let allowed = fixture
        .rig
        .run(
            &fixture.line(&into, &["--archive", &chosen, "--preview"]),
            None,
        )
        .await;
    assert!(allowed.status.success(), "{}", text(&allowed.stderr));
}

/// The folder is checked again when it is opened, so an entry put in after the first check is found;
/// the probe of how the record is published removes only the names it made, so a name another
/// writer put in meanwhile stays; and a record published whole leaves nothing to warn about.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_folder_is_checked_again_when_opened_and_the_probe_removes_only_what_it_made() {
    use kr_cli::backup::directory::Destination;

    let fixture = Fixture::new().await;
    let destination = Destination::check(&fixture.into).expect("the folder passes");
    // The path as the operating system names it, in bytes: what the plan's digest holds.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        assert_eq!(
            destination.native_bytes(),
            fixture.into.as_os_str().as_bytes()
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        let wide: Vec<u8> = fixture
            .into
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(destination.native_bytes(), wide);
    }
    std::fs::write(fixture.into.join("late"), b"x").expect("an entry");
    assert!(
        destination.open().is_err(),
        "an entry put in after the check is found"
    );
    std::fs::remove_file(fixture.into.join("late")).expect("removed");

    let mut held = destination.open().expect("the folder opens");
    let theirs = fixture.into.join(".restore-probe-link");
    std::fs::write(&theirs, b"THEIRS").expect("another writer's file");
    assert!(held.probe_publication().is_err(), "the name is taken");
    assert_eq!(
        std::fs::read(&theirs).expect("it is still there"),
        b"THEIRS",
        "a name the probe did not make is not removed"
    );
    assert_eq!(names(&fixture.into), [".restore-probe-link"]);
    std::fs::remove_file(&theirs).expect("removed");

    held.probe_publication().expect("a folder that publishes");
    assert!(
        names(&fixture.into).is_empty(),
        "the probe took its names away"
    );
    let warnings = held.publish_record(b"{}").expect("the record is published");
    assert!(warnings.is_empty(), "nothing is left to say");
    assert_eq!(names(&fixture.into), ["restore.json"]);
}

/// A run that ends without publishing its record removes what it made, however it ended, a panic
/// included: dropping the held folder is the backstop under the explicit cleanup.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_held_folder_dropped_before_the_record_is_published_is_emptied_of_what_was_made() {
    use kr_cli::backup::directory::Destination;

    let fixture = Fixture::new().await;
    let destination = Destination::check(&fixture.into).expect("the folder passes");
    let mut held = destination.open().expect("the folder opens");
    held.write_member("session-0001.json", b"what a restore wrote")
        .expect("a member is written");
    assert_eq!(names(&fixture.into), ["session-0001.json"]);
    drop(held);
    assert!(
        names(&fixture.into).is_empty(),
        "the file was removed with the handle"
    );
    assert!(fixture.into.is_dir(), "the folder is never removed");
}

/// A rig's tree is removed again for as long as the removal is refused, and the removal that was
/// refused is said: a file held open without sharing, as the backup carrier's task holds the
/// backup store's, is let go of after the first refusal, and the tree then goes.
#[cfg(windows)]
#[test]
fn a_tree_whose_removal_is_refused_is_removed_when_the_file_is_let_go_of() {
    use std::os::windows::fs::OpenOptionsExt as _;

    let place = kr_ipc::testing::PrivateTempDir::create();
    let root = place.path().join("tree");
    std::fs::create_dir(&root).expect("a tree");
    let held = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .share_mode(0)
        .open(root.join("store.db"))
        .expect("a file held open without sharing");
    let mut held = Some(held);
    let mut refusals = 0_u32;

    let outcome = remove_tree(&root, |_| {
        refusals += 1;
        drop(held.take());
    });

    assert!(outcome.is_ok(), "the tree is removed: {outcome:?}");
    assert!(
        refusals >= 1,
        "the first removal was refused, which is what the case is about"
    );
    assert!(!root.exists(), "{} is left", root.display());
}

/// The scan's exception for a held lock file covers the daemon's lock file by its name and nothing
/// else: not a directory or a file named like a lock file.
#[cfg(windows)]
#[test]
fn the_scans_exception_for_a_held_file_is_the_daemons_lock_file_alone() {
    let sharing_violation = std::io::Error::from_raw_os_error(32);
    assert!(is_the_daemons_held_lock_file(
        Path::new(r"C:\host\s\controller.lock"),
        &sharing_violation
    ));
    for other in [
        r"C:\host\s\other.lock",
        r"C:\host\s\controller.lock.d\inner",
        r"C:\host\s\directory.lock",
    ] {
        assert!(
            !is_the_daemons_held_lock_file(Path::new(other), &sharing_violation),
            "{other} is not the daemon's lock file"
        );
    }
    assert!(
        !is_the_daemons_held_lock_file(
            Path::new(r"C:\host\s\controller.lock"),
            &std::io::Error::from_raw_os_error(5)
        ),
        "an access that is refused is not a file held open"
    );
}

/// A folder the account cannot list fails the scan of the tree it is in, and so does nothing less:
/// a scan that passed over it would pass on what it holds unread.
#[test]
fn a_folder_the_account_cannot_list_fails_the_scan() {
    let place = kr_ipc::testing::PrivateTempDir::create();
    let hidden = place.path().join("hidden");
    std::fs::create_dir(&hidden).expect("a folder");
    std::fs::write(hidden.join("secret"), b"x").expect("a file in it");
    let restore = denying_a_listing(&hidden);
    let listed = std::fs::read_dir(&hidden).map(|_| ());
    let scanned = std::panic::catch_unwind(|| tree(place.path()));
    restore();
    // An account that cannot be denied a listing (the superuser on Unix) shows nothing here.
    if cfg!(unix) && listed.is_ok() {
        eprintln!("this account can list a folder whatever its mode: nothing is shown");
        return;
    }
    assert!(
        listed.is_err(),
        "the folder could still be listed: this account cannot be denied a listing here, and the case shows nothing"
    );
    assert!(
        scanned.is_err(),
        "the scan went past a folder it could not list"
    );
}

/// Makes `folder` one this account cannot list, and returns what undoes it.
#[cfg(windows)]
fn denying_a_listing(folder: &Path) -> impl FnOnce() + '_ {
    let icacls = Path::new(&std::env::var_os("SystemRoot").expect("a system directory"))
        .join("System32")
        .join("icacls.exe");
    let denied = std::process::Command::new(&icacls)
        .arg(folder)
        .args(["/deny", "*S-1-1-0:(RD)"])
        .output()
        .expect("icacls runs");
    assert!(denied.status.success(), "icacls: {denied:?}");
    move || {
        let _ = std::process::Command::new(&icacls)
            .arg(folder)
            .args(["/remove:d", "*S-1-1-0"])
            .output();
    }
}

/// Makes `folder` one this account cannot list, and returns what undoes it.
#[cfg(unix)]
fn denying_a_listing(folder: &Path) -> impl FnOnce() + '_ {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o000))
        .expect("a folder nobody may list");
    move || {
        let _ = std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700));
    }
}
