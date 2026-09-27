//! A host installed as a store of releases: each program holds the release it runs, starts the
//! programs of that release, and names it; `kr host install` puts a first release in, and
//! `kr host update` hands the control daemon over to another while every live session keeps the
//! release it started from, or waits, exit 9, and says why.
//!
//! Every release here is assembled from the programs this workspace built: `kr`, the restoration
//! guard, the control daemon, the worker and the forwarder, copied once to the internal disk and
//! then given to each release as files of its own, as an installed release has. Each release
//! carries an update channel root this process makes, whose targets key signs its manifest. Each
//! test builds its store inside a host tree of its own, with its own runtime and state roots, so
//! nothing here reads or changes the person's own installation. A daemon runs as a process of its
//! own, with its keys in the tree's own secrets directory; every daemon still serving the tree when
//! a test ends is handed over and stopped through its own door, and the tree ends every worker it
//! started before it goes.

#![cfg(unix)]

use std::collections::HashMap;
use std::io::Write as _;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use aws_lc_rs::signature::Ed25519KeyPair;
use kr_ipc::client::LocalClient;
use kr_ipc::install::{Program, Store};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hello::{PACKAGE_VERSION, PackageVersion};
use kr_protocol::ids::{ActionId, BuildId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Digest256, U64};
use kr_protocol::update::{
    CommitId, CompatibilityLevel, FileMode, FloorSystem, FloorVersion, HandoverStep,
    HostUpdateHandoverParams, ManifestKind, OsFloor, ReleaseFile, ReleaseManifest, ReleaseName,
    ReleasePath, SignedMembers,
};
use serde_json::Value;

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;

/// How long a wait for something to happen is given. It fails when the thing never happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// One release this suite assembles.
fn release(name: &str) -> ReleaseName {
    ReleaseName::new(name).expect("a release name")
}

/// A build identifier for this suite's own connections.
fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/* -------------------------------------------------------------------------------------------- */
/* The channel's keys and root                                                                   */
/* -------------------------------------------------------------------------------------------- */

/// The keys this process's releases are signed with: the channel root's own key, the key it names
/// for its targets role, and one key it names for nothing.
struct Keys {
    root: Ed25519KeyPair,
    targets: Ed25519KeyPair,
    stranger: Ed25519KeyPair,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pair = || {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("a key");
            Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("a key pair")
        };
        Keys {
            root: pair(),
            targets: pair(),
            stranger: pair(),
        }
    })
}

/// The identifier The Update Framework gives a key.
fn key_id(pair: &Ed25519KeyPair) -> tough::schema::decoded::Decoded<tough::schema::decoded::Hex> {
    tough::sign::Sign::tuf_key(pair)
        .key_id()
        .expect("a key identifier")
}

/// Signs `message` with `pair`, as a signature The Update Framework's metadata carries.
fn signature(pair: &Ed25519KeyPair, message: &[u8]) -> tough::schema::Signature {
    tough::schema::Signature {
        keyid: key_id(pair),
        sig: Ed25519KeyPair::sign(pair, message).as_ref().to_vec().into(),
    }
}

/// A channel root at `version` naming `root_key` for its root role and the targets key for its
/// targets role, signed by each of `signers`.
fn channel_root(version: u64, root_key: &Ed25519KeyPair, signers: &[&Ed25519KeyPair]) -> String {
    use tough::schema::{RoleKeys, RoleType, Root, Signed};

    let one = NonZeroU64::new(1).expect("one");
    let named = |pair: &Ed25519KeyPair| RoleKeys {
        keyids: vec![key_id(pair)],
        threshold: one,
        _extra: HashMap::new(),
    };
    let mut keys_named = HashMap::new();
    keys_named.insert(key_id(root_key), tough::sign::Sign::tuf_key(root_key));
    keys_named.insert(
        key_id(&keys().targets),
        tough::sign::Sign::tuf_key(&keys().targets),
    );
    let mut roles = HashMap::new();
    roles.insert(RoleType::Root, named(root_key));
    roles.insert(RoleType::Targets, named(&keys().targets));
    roles.insert(RoleType::Snapshot, named(root_key));
    roles.insert(RoleType::Timestamp, named(root_key));
    let root = Root {
        spec_version: "1.0.0".to_owned(),
        consistent_snapshot: false,
        version: NonZeroU64::new(version).expect("a version"),
        expires: "2099-01-01T00:00:00Z".parse().expect("a time"),
        keys: keys_named,
        roles,
        _extra: HashMap::new(),
    };
    let canonical = tough::schema::Role::canonical_form(&root).expect("canonical");
    let signed = Signed {
        signed: root,
        signatures: signers
            .iter()
            .map(|pair| signature(pair, &canonical))
            .collect(),
    };
    serde_json::to_string_pretty(&signed).expect("encodes")
}

/// The channel root every release here carries.
fn the_root() -> &'static str {
    static ROOT: OnceLock<String> = OnceLock::new();
    ROOT.get_or_init(|| channel_root(1, &keys().root, &[&keys().root]))
}

/// A manifest's document, signed by `signer`.
fn signed_document(manifest: &ReleaseManifest, signer: &Ed25519KeyPair) -> String {
    let members = SignedMembers::of(manifest).expect("members");
    let canonical =
        tough::schema::Role::canonical_form(&kr_cli::update::release::Signable(members.clone()))
            .expect("canonical");
    serde_json::json!({
        "signed": members,
        "signatures": [signature(signer, &canonical)],
    })
    .to_string()
}

/* -------------------------------------------------------------------------------------------- */
/* Releases                                                                                      */
/* -------------------------------------------------------------------------------------------- */

/// The programs this workspace built, beside this test or where Cargo says, each with its digest.
///
/// Copied once for this whole process into the run's own directory on the internal disk, which
/// goes when the process does. A build of this crate alone builds `kr` and the guard; the daemon,
/// the worker and the forwarder are built by a workspace run, or by
/// `cargo build -p kr-controller -p kr-worker -p kr-hook`, and a run without them fails and says
/// so rather than passing without having tested anything.
fn programs() -> &'static [(Program, PathBuf, Digest256, u64)] {
    static COPIED: OnceLock<Vec<(Program, PathBuf, Digest256, u64)>> = OnceLock::new();
    COPIED.get_or_init(|| {
        let beside = |name: &str| {
            let executable = std::env::current_exe().expect("this test binary");
            let profile = executable
                .parent()
                .and_then(Path::parent)
                .expect("inside a target directory");
            let candidate = profile.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
            assert!(
                candidate.is_file(),
                "{} is not built beside this test, so this suite cannot assemble a release; a \
                 workspace test run builds it, and so does `cargo build -p kr-controller -p \
                 kr-worker -p kr-hook`",
                candidate.display()
            );
            candidate
        };
        let sources = [
            (Program::Kr, PathBuf::from(env!("CARGO_BIN_EXE_kr"))),
            (
                Program::AttachGuard,
                PathBuf::from(env!("CARGO_BIN_EXE_kr-attach-guard")),
            ),
            (Program::Controller, beside("kr-controller")),
            (Program::Worker, beside("kr-worker")),
            (Program::Hook, beside("kr-hook")),
        ];
        let directory = support::command_binaries().join("releases");
        std::fs::create_dir_all(&directory).expect("a directory for the programs");
        sources
            .into_iter()
            .map(|(program, source)| {
                let copied = directory.join(program.file_name());
                kr_ipc::testing::place_program(&source, &copied);
                let bytes = std::fs::read(&copied).expect("the program");
                (
                    program,
                    copied,
                    Digest256::from_bytes(kr_cbor::sha256(&bytes)),
                    bytes.len() as u64,
                )
            })
            .collect()
    })
}

/// Gives `destination` a file of its own with `source`'s bytes: a clone where the filesystem makes
/// one, a copy otherwise, by a process of its own so no descriptor of this one is open on a program
/// another test may start.
fn clone_file(source: &Path, destination: &Path) {
    let cloned = Command::new("/bin/cp")
        .arg(if cfg!(target_os = "macos") {
            "-c"
        } else {
            "--reflink=auto"
        })
        .arg(source)
        .arg(destination)
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !cloned {
        kr_ipc::testing::place_program(source, destination);
    }
}

/// The target this build is for, as a release names it.
fn this_target() -> &'static str {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("aarch64", "macos") => "aarch64-apple-darwin",
        ("x86_64", "macos") => "x86_64-apple-darwin",
        ("aarch64", "linux") => "aarch64-unknown-linux-gnu",
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu",
        other => panic!("no release target for {other:?}"),
    }
}

/// The module tree each release's shell packages carry here: files a shell of that release would
/// load, which have to outlast the release's own replacement for as long as a session runs it.
fn module_tree() -> [(&'static str, &'static str); 2] {
    [
        (
            "shells/zsh/package/modules/zle.zsh",
            "# a module of this release\n",
        ),
        ("shells/zsh/package/kr-shell-identity.json", "{}\n"),
    ]
}

/// What one release assembled here is.
struct Assembled {
    manifest: ReleaseManifest,
    root: String,
}

impl Assembled {
    /// A release of this workspace's programs, retaining `retained`, carrying `root`.
    fn new(name: &str, sequence: u64, retained: CompatibilityLevel, root: &str) -> Self {
        let name = release(name);
        let mut files: Vec<ReleaseFile> = programs()
            .iter()
            .map(|(program, _, digest, length)| ReleaseFile {
                path: ReleasePath::new(format!("bin/{}", program.file_name())).expect("a path"),
                length: U64::new(*length),
                sha256: *digest,
                mode: FileMode::Executable,
            })
            .collect();
        let mut listed = |path: &str, contents: &[u8]| {
            files.push(ReleaseFile {
                path: ReleasePath::new(path).expect("a path"),
                length: U64::new(contents.len() as u64),
                sha256: Digest256::from_bytes(kr_cbor::sha256(contents)),
                mode: FileMode::Regular,
            });
        };
        for (path, contents) in module_tree() {
            listed(path, contents.as_bytes());
        }
        listed(kr_cli::update::release::CHANNEL_ROOT, root.as_bytes());
        let commit = format!(
            "{}{}",
            &name.as_str()[name.as_str().len() - 12..],
            "0".repeat(28)
        );
        Self {
            manifest: ReleaseManifest {
                kind: ManifestKind::Release,
                release: name,
                sequence: U64::new(sequence),
                commit: CommitId::new(commit).expect("a commit"),
                target: this_target().to_owned(),
                os_floor: OsFloor {
                    system: if cfg!(target_os = "macos") {
                        FloorSystem::Macos
                    } else {
                        FloorSystem::Glibc
                    },
                    version: FloorVersion { major: 1, minor: 0 },
                },
                protocol_version: PACKAGE_VERSION,
                public_majors: vec![1],
                retained_levels: vec![retained],
                shells: Vec::new(),
                files,
            },
            root: root.to_owned(),
        }
    }

    /// A release of this workspace's programs at this build's own level, carrying this process's
    /// channel root.
    fn at_this_level(name: &str, sequence: u64) -> Self {
        Self::new(
            name,
            sequence,
            CompatibilityLevel::of(PACKAGE_VERSION),
            the_root(),
        )
    }

    fn name(&self) -> &ReleaseName {
        &self.manifest.release
    }

    /// Writes the release's tree at `directory`, its manifest signed by `signer`.
    fn write_signed(&self, directory: &Path, signer: &Ed25519KeyPair) {
        std::fs::create_dir_all(directory.join("bin")).expect("the release's bin");
        for (program, copied, _, _) in programs() {
            clone_file(copied, &directory.join("bin").join(program.file_name()));
        }
        let write = |path: &str, contents: &[u8]| {
            let file = directory.join(path);
            std::fs::create_dir_all(file.parent().expect("a directory")).expect("the tree");
            std::fs::write(&file, contents).expect("a file");
        };
        for (path, contents) in module_tree() {
            write(path, contents.as_bytes());
        }
        write(kr_cli::update::release::CHANNEL_ROOT, self.root.as_bytes());
        write(
            kr_protocol::update::MANIFEST_FILE,
            signed_document(&self.manifest, signer).as_bytes(),
        );
    }

    /// Writes the release's tree at `directory`, signed by the channel's targets key.
    fn write(&self, directory: &Path) {
        self.write_signed(directory, &keys().targets);
    }

    /// Writes the release as an archive at `archive`: its tree under one top directory, gzipped.
    fn archive(&self, scratch: &Path, archive: &Path) {
        let top = format!("kalareach-{}-{}", this_target(), self.name());
        let tree = scratch.join(&top);
        self.write(&tree);
        pack(&tree, &top, archive);
        std::fs::remove_dir_all(&tree).expect("the tree goes");
    }
}

/// Packs `tree` as an archive whose entries are under `top`, gzipped quickly.
fn pack(tree: &Path, top: &str, archive: &Path) {
    let file = std::fs::File::create(archive).expect("an archive");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    let mut builder = tar::Builder::new(encoder);
    builder.append_dir_all(top, tree).expect("packs the tree");
    builder
        .into_inner()
        .and_then(flate2::write::GzEncoder::finish)
        .and_then(|mut file| file.flush())
        .expect("the archive is written");
}

/// Starts each program of a release once, where nothing is timed: the operating system checks a
/// newly written program the first time it starts, and that is paid here rather than inside a wait.
fn start_each_once(directory: &Path) {
    for program in Program::ALL {
        let path = directory.join("bin").join(program.file_name());
        let output = Command::new(&path)
            .arg("--version")
            .current_dir(directory)
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|error| panic!("{} did not start: {error}", path.display()));
        assert!(
            output.status.success(),
            "{} --version: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/* -------------------------------------------------------------------------------------------- */
/* A host                                                                                        */
/* -------------------------------------------------------------------------------------------- */

/// A host tree with a store of releases in it, and the daemons this test started.
///
/// However a test ends, what it started ends with it: a daemon still serving the tree is handed
/// over and stopped through its own door, a daemon this test started is ended, and then, through
/// the tree, every worker a daemon recorded and on macOS every launchd job defined inside the
/// host's own state directory.
struct Host {
    daemons: Vec<std::process::Child>,
    store: Store,
    tree: teardown::Tree,
}

impl Drop for Host {
    fn drop(&mut self) {
        // A daemon `kr host update` started is not this test's child: it is stopped the way an
        // update stops one, and the environment's lock says when it has gone.
        let stopped = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .ok()
                        .map(|runtime| runtime.block_on(self.stop_the_daemon()))
                })
                .join()
                .ok()
                .flatten()
        });
        if stopped == Some(false) {
            self.tree
                .hold("a daemon serving this host could not be stopped".to_owned());
        }
        for mut daemon in self.daemons.drain(..) {
            if let Err(error) = daemon.kill().and_then(|()| daemon.wait().map(|_| ())) {
                self.tree.hold(format!(
                    "a daemon this test started could not be established as ended: {error}"
                ));
            }
        }
        // An installed release is read-only, and the tree goes whole: its directories are opened
        // to removal first.
        writable(self.store.root());
    }
}

/// Makes every directory under `root` writable by its owner, so the tree can be removed.
fn writable(root: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let _ = std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700));
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                pending.push(entry.path());
            }
        }
    }
}

impl Host {
    /// A tree with an empty store.
    fn create() -> Self {
        let host = Self::bare();
        host.store
            .create_directories()
            .expect("the store's directories");
        std::fs::write(host.store.record(), b"{\"format\":1}\n").expect("the store's record");
        host
    }

    /// A tree with nothing at the store's place yet.
    fn bare() -> Self {
        let tree = teardown::Tree::create();
        let store = Store::at(tree.root().join("host"));
        Self {
            daemons: Vec::new(),
            store,
            tree,
        }
    }

    /// Puts a release in the store, as it is once installed.
    fn put(&self, assembled: &Assembled) -> PathBuf {
        let directory = self.store.release_directory(assembled.name());
        assembled.write(&directory);
        start_each_once(&directory);
        directory
    }

    /// Makes a release current, under the locks every switch is made under.
    fn switch(&self, name: &ReleaseName) {
        let update = self
            .store
            .try_lock_update()
            .expect("the update lock")
            .expect("nothing else updates");
        let install = self.store.lock_install().expect("the install lock");
        self.store
            .switch(name, &update, &install)
            .expect("switches");
    }

    /// A program of a release, by its path in the store.
    fn program(&self, name: &ReleaseName, program: Program) -> PathBuf {
        self.store
            .release_directory(name)
            .join("bin")
            .join(program.file_name())
    }

    /// A place of this test's own in the tree.
    fn scratch(&self, name: &str) -> PathBuf {
        let path = self.tree.root().join(name);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        path
    }

    /// Runs a program with this host's roots and nothing of this test's own environment.
    fn run(&self, program: &Path, arguments: &[&str]) -> Output {
        self.command(program, arguments)
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|error| panic!("{} did not start: {error}", program.display()))
    }

    fn command(&self, program: &Path, arguments: &[&str]) -> Command {
        let mut command = Command::new(program);
        command
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env(
                "KR_RUNTIME_DIR",
                self.tree.paths().runtime_root().display().to_string(),
            )
            .env(
                "KR_STATE_DIR",
                self.tree.paths().state_root().display().to_string(),
            )
            .current_dir(self.tree.root());
        command
    }

    /// Runs `kr` of the current release and reads what it printed as JSON.
    fn kr_json(&self, arguments: &[&str]) -> (Output, Value) {
        let output = self.run(&self.store.stable(Program::Kr), arguments);
        let said = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        (output, said)
    }

    /// Runs `kr host update` of the current release with `archive` and `--json`, with a variable
    /// set that no control daemon of a store starts with: every daemon it starts refuses to run.
    fn update_whose_daemons_fail(&self, archive: &str) -> (Output, Value) {
        let output = self
            .command(
                &self.store.stable(Program::Kr),
                &["host", "update", "--archive", archive, "--json"],
            )
            .env(
                kr_shell_integration::host::package::PACKAGE_ROOT_VARIABLE,
                self.tree.root(),
            )
            .stdin(Stdio::null())
            .output()
            .expect("kr runs");
        let said = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        (output, said)
    }

    /// The arguments a daemon of this host is started with: this host's roots, and its keys in the
    /// host's own secrets directory.
    fn daemon_arguments(&self) -> Vec<String> {
        vec![
            "--runtime-dir".to_owned(),
            self.tree.paths().runtime_root().display().to_string(),
            "--state-dir".to_owned(),
            self.tree.paths().state_root().display().to_string(),
            "--secret-store".to_owned(),
            "file".to_owned(),
        ]
    }

    /// Starts `program` as this host's daemon and waits for it to answer.
    async fn start_daemon(&mut self, program: &Path) {
        let log = self
            .tree
            .root()
            .join(format!("daemon-{}.log", self.daemons.len()));
        let file = std::fs::File::create(&log).expect("the daemon's log");
        let arguments = self.daemon_arguments();
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let child = self
            .command(program, &arguments)
            .stdin(Stdio::null())
            .stdout(file.try_clone().expect("duplicates the log"))
            .stderr(file)
            .spawn()
            .expect("the daemon starts");
        self.daemons.push(child);
        let endpoint = self
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let started = Instant::now();
        while LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .is_err()
        {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the daemon did not answer; its log says: {}",
                std::fs::read_to_string(&log).unwrap_or_default()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Hands over and stops whatever daemon serves this host, through its own door, and says
    /// whether none is left serving it.
    async fn stop_the_daemon(&self) -> bool {
        let environment = self.tree.environment();
        let Ok(endpoint) = environment.controller_endpoint() else {
            return true;
        };
        if let Ok(mut client) = LocalClient::connect(&endpoint, LocalClientKind::Cli, build()).await
        {
            for step in [HandoverStep::Prepare, HandoverStep::Stop] {
                let _ = tokio::time::timeout(
                    Duration::from_secs(60),
                    client.mutate(
                        Method::HostUpdateHandover,
                        ActionId::new(kr_ipc::new_uuid()),
                        ActionTarget::environment(self.tree.environment_id()),
                        &HostUpdateHandoverParams {
                            step,
                            target: release("0.0.0+000000000000"),
                        },
                    ),
                )
                .await;
            }
        }
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(30) {
            if kr_controller::singleton::SingletonLock::hold(
                &environment.singleton_lock(),
                self.tree.environment_id(),
            )
            .is_ok()
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    /// Creates a session with a release's `kr`, and returns its display number and identifier.
    fn new_session(&self, kr: &Path) -> (String, SessionId) {
        let cwd = self.tree.root().display().to_string();
        let output = self.run(
            kr,
            &[
                "new",
                "--invisible",
                "--headless",
                "--cwd",
                &cwd,
                "--shell",
                "/bin/sh",
                "--startup",
                "interactive",
                "--json",
            ],
        );
        assert!(
            output.status.success(),
            "kr new: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let created: Value = serde_json::from_slice(&output.stdout).expect("kr printed JSON");
        let session_id = created["session_id"]
            .as_str()
            .expect("a session identifier")
            .parse()
            .expect("parses");
        (created["display_number"].to_string(), session_id)
    }

    /// What a session's worker states about its build, from its answer to a hello.
    async fn worker_build(&self, session_id: SessionId) -> String {
        let descriptor = kr_ipc::descriptor::read(&self.tree.environment(), session_id)
            .expect("reads the descriptor")
            .expect("the session is published");
        let endpoint =
            kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint).expect("an endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the worker");
        client
            .verify_worker(&descriptor)
            .await
            .expect("the worker answers its descriptor's challenge");
        client
            .acknowledgement()
            .build
            .as_ref()
            .map(|build| build.build_id.as_str().to_owned())
            .unwrap_or_default()
    }

    /// What this host's daemon states about its build.
    async fn daemon_build(&self) -> String {
        let endpoint = self
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the daemon");
        client
            .acknowledgement()
            .build
            .as_ref()
            .map(|build| build.build_id.as_str().to_owned())
            .unwrap_or_default()
    }

    /// Closes a session with a release's `kr`.
    fn close(&self, kr: &Path, display: &str) {
        let output = self.run(kr, &["close", display, "--json"]);
        assert!(
            output.status.success(),
            "kr close: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Waits until no running program holds `name`.
    async fn released(&self, name: &ReleaseName) {
        let started = Instant::now();
        while self.store.held(name).expect("asks") {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "release {name} is still held"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// The store's record, as JSON.
    fn record(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.store.record()).expect("the record"))
            .expect("the record is JSON")
    }

    /// Installs a first release with the unpacked release's own `kr`, and starts its programs once.
    fn install(&self, assembled: &Assembled) {
        let unpacked = self.scratch("unpacked").join(assembled.name().as_str());
        assembled.write(&unpacked);
        let store = self.store.root().display().to_string();
        let output = self.run(
            &unpacked.join("bin").join(Program::Kr.file_name()),
            &["host", "install", "--store", &store, "--json"],
        );
        assert!(
            output.status.success(),
            "kr host install: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        start_each_once(&self.store.release_directory(assembled.name()));
    }
}

/* -------------------------------------------------------------------------------------------- */
/* Each program's hold                                                                          */
/* -------------------------------------------------------------------------------------------- */

/// KR-REQ-26.06: every program of a release that is being removed refuses to start, and the same
/// programs start from the release's place in the store.
#[test]
fn no_program_of_a_release_being_removed_starts() {
    let host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let installed = host.put(&one);
    // What the removal of a release leaves between its move and its deletion.
    let removing = host.store.trash().join(format!("{}-leaving", one.name()));
    one.write(&removing);
    for program in Program::ALL {
        // The control: from the release's own place, each program starts.
        let started = host.run(
            &installed.join("bin").join(program.file_name()),
            &["--version"],
        );
        assert!(
            started.status.success(),
            "{} starts from its release: {}",
            program.name(),
            String::from_utf8_lossy(&started.stderr)
        );
        let refused = host.run(
            &removing.join("bin").join(program.file_name()),
            &["--version"],
        );
        assert!(
            !refused.status.success(),
            "{} of a release being removed does not start",
            program.name()
        );
        // The guard says nothing of its own: the attach that started it says the guard did not
        // start. Every other program says why.
        if program != Program::AttachGuard {
            let said = String::from_utf8_lossy(&refused.stderr);
            assert!(
                said.contains("is being removed from this host"),
                "{} says why: {said}",
                program.name()
            );
        }
    }
}

/// KR-REQ-26.06: a daemon of a release states it, records the roots it serves, holds its release,
/// and starts its own release's worker, which states the release too; the release stays for as
/// long as either runs.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_of_a_release_starts_its_own_release_s_worker_and_holds_the_release() {
    let mut host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.put(&one);
    host.switch(one.name());
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    let roots = host.store.recorded_roots().expect("reads the roots");
    assert_eq!(roots.len(), 1, "the daemon recorded the roots it serves");
    assert_eq!(
        std::fs::canonicalize(&roots[0].state_root).expect("resolves"),
        std::fs::canonicalize(host.tree.paths().state_root()).expect("resolves")
    );

    let kr = host.store.stable(Program::Kr);
    let (display, session_id) = host.new_session(&kr);
    assert_eq!(
        host.worker_build(session_id).await,
        format!("kr-worker/{}", one.name()),
        "the worker the daemon started is of the daemon's own release"
    );
    assert!(
        host.store.held(one.name()).expect("asks"),
        "the release is held while its programs run"
    );
    host.close(&kr, &display);
}

/// A daemon of a release starts its own release's worker with its own release's packages, and
/// takes no other: a session it launched with another would run what the store does not hold.
#[test]
fn a_daemon_of_a_release_takes_no_other_worker_and_no_other_packages() {
    let host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.put(&one);
    host.switch(one.name());
    let controller = host.program(one.name(), Program::Controller);
    let arguments = host.daemon_arguments();
    let mut with_worker: Vec<&str> = arguments.iter().map(String::as_str).collect();
    with_worker.extend(["--worker", "/bin/sh"]);
    let refused = host.run(&controller, &with_worker);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--worker names another program"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let plain: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let refused = host
        .command(&controller, &plain)
        .env("KR_SHELL_PACKAGES", host.tree.root())
        .stdin(Stdio::null())
        .output()
        .expect("runs");
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("KR_SHELL_PACKAGES names others"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        host.store.recorded_roots().expect("reads").is_empty(),
        "neither refusal served the environment"
    );
}

/// A daemon of a release that is no longer current does not start: the current release's daemon
/// serves this host. The current release's own daemon does.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_of_a_release_that_is_no_longer_current_does_not_start() {
    let mut host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.put(&one);
    host.put(&two);
    host.switch(two.name());
    let arguments = host.daemon_arguments();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let refused = host.run(&host.program(one.name(), Program::Controller), &arguments);
    assert!(!refused.status.success());
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(
        said.contains(&format!(
            "this daemon is of release {}, and this host's current release is {}",
            one.name(),
            two.name()
        )),
        "{said}"
    );
    // The control: the current release's daemon starts.
    let current = host.program(two.name(), Program::Controller);
    host.start_daemon(&current).await;
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
}

/* -------------------------------------------------------------------------------------------- */
/* Installing and updating                                                                       */
/* -------------------------------------------------------------------------------------------- */

/// KR-REQ-26.09: `kr host install`, run as the unpacked release's own `kr`, puts the release into a
/// new store read-only, makes it current and records the store; a tree that is not what its
/// manifest says is refused and nothing is made current.
#[test]
fn kr_host_install_puts_a_first_release_in_a_store_and_makes_it_current() {
    let host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let store = host.store.root().display().to_string();

    // The control: the same tree with one module changed is refused.
    let tampered = host.scratch("tampered").join(one.name().as_str());
    one.write(&tampered);
    std::fs::write(tampered.join(module_tree()[0].0), "# something else\n").expect("changed");
    let refused = host.run(
        &tampered.join("bin").join(Program::Kr.file_name()),
        &["host", "install", "--store", &store],
    );
    assert!(!refused.status.success(), "a tampered tree is refused");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("is not what its manifest says"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(host.store.current().ok().flatten(), None);

    host.install(&one);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert!(host.store.is_store(), "the store's record is written");
    let installed = host.store.release_directory(one.name());
    for file in [
        "bin/kr",
        module_tree()[0].0,
        kr_protocol::update::MANIFEST_FILE,
    ] {
        let about = std::fs::metadata(installed.join(file)).expect("installed");
        assert!(about.permissions().readonly(), "{file} is read-only");
    }
    // A second install into a store with a current release goes through an update instead.
    let again = host.scratch("again").join(one.name().as_str());
    one.write(&again);
    let refused = host.run(
        &again.join("bin").join(Program::Kr.file_name()),
        &["host", "install", "--store", &store],
    );
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("already has a current release"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
}

/// KR-REQ-26.06, KR-REQ-26.08, KR-REQ-26.09, KR-ACC-035: an update checks the release, hands the
/// daemon over and starts the new release's daemon as the old one was started, while a live
/// session keeps running the release it started from with that release's module tree, which stays
/// for as long as the session holds it and goes once nothing does.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_replaces_the_daemon_and_a_live_session_keeps_its_release() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let three = Assembled::at_this_level("0.3.0+cccccccccccc", 3);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let (display, session_id) = host.new_session(&host.program(one.name(), Program::Kr));
    let scratch = host.scratch("archives");
    let archive_two = scratch.join("two.tar.gz");
    two.archive(&scratch, &archive_two);

    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive_two.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["target"], two.name().as_str(), "{said}");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the daemon was started again, of the new release"
    );
    assert_eq!(
        host.worker_build(session_id).await,
        format!("kr-worker/{}", one.name()),
        "the live session runs the release it started from"
    );
    let module = host
        .store
        .release_directory(one.name())
        .join(module_tree()[0].0);
    assert!(module.is_file(), "its module tree is still there");
    let record = host.record();
    assert_eq!(record["previous"], one.name().as_str());
    assert!(record["update"].is_null(), "the update settled: {record}");

    // Another update: the first release is no longer the previous one, and the live session still
    // holds it, so it stays with its module tree.
    let archive_three = scratch.join("three.tar.gz");
    three.archive(&scratch, &archive_three);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive_three.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["removed"], serde_json::json!([]), "{said}");
    assert!(module.is_file(), "a held release is never removed");
    let (_, versions) = host.kr_json(&["host", "versions", "--json"]);
    let first = versions["releases"]
        .as_array()
        .and_then(|releases| {
            releases
                .iter()
                .find(|kept| kept["release"] == one.name().as_str())
        })
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(first["held"], true, "{versions}");
    assert_eq!(first["previous"], false, "{versions}");
    assert_eq!(
        first["sequence"], 1,
        "a release's sequence is read from it: {versions}"
    );

    // The control: once the session closes nothing holds the first release, and the next update
    // takes it away.
    host.close(&host.store.stable(Program::Kr), &display);
    host.released(one.name()).await;
    let four = Assembled::at_this_level("0.4.0+dddddddddddd", 4);
    let archive_four = scratch.join("four.tar.gz");
    four.archive(&scratch, &archive_four);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive_four.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The first release, and the second, which is no longer the previous one either.
    assert_eq!(
        said["removed"],
        serde_json::json!([one.name().as_str(), two.name().as_str()]),
        "{said}"
    );
    assert!(!host.store.release_directory(one.name()).exists());
    assert!(
        host.store.release_directory(three.name()).exists(),
        "the previous one stays"
    );
}

/// KR-REQ-26.08: an update to a release whose daemon does not retain a live session's level waits,
/// exit 9, naming the session and its protocol, with nothing stopped and the release staged.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_waits_for_a_session_its_release_does_not_retain() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let (display, _) = host.new_session(&host.store.stable(Program::Kr));
    let another = if PACKAGE_VERSION.major == 0 {
        PackageVersion::new(0, PACKAGE_VERSION.minor + 1, 0)
    } else {
        PackageVersion::new(PACKAGE_VERSION.major + 1, 0, 0)
    };
    let elsewhere = Assembled::new(
        "0.2.0+bbbbbbbbbbbb",
        2,
        CompatibilityLevel::of(another),
        the_root(),
    );
    let scratch = host.scratch("archives");
    let archive = scratch.join("elsewhere.tar.gz");
    elsewhere.archive(&scratch, &archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "an update that waits exits 9"
    );
    assert_eq!(said["exit_code"], 9, "{said}");
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&format!(
            "the update to {} waits: session {display} runs kr-worker/{} with protocol {}",
            elsewhere.name(),
            one.name(),
            PACKAGE_VERSION
        )),
        "{said}"
    );
    assert_eq!(said["code"], "RESOURCE_UNAVAILABLE", "{said}");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "nothing was stopped"
    );
    assert!(
        host.daemons
            .iter_mut()
            .all(|daemon| matches!(daemon.try_wait(), Ok(None))),
        "the daemon this test started is still the one running"
    );
    assert_eq!(host.record()["staged"], elsewhere.name().as_str());
    assert!(host.store.release_directory(elsewhere.name()).is_dir());
}

/// KR-REQ-26.09: an update an earlier run left after its switch is finished by the next run: the
/// daemon it recorded is started from the release `current` names, and the update settles.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_left_after_its_switch_is_finished_by_the_next_run() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    host.put(&two);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    // What a run that stopped after its switch leaves: the daemon stopped, `current` on the
    // target, and the update recorded as switched.
    for mut daemon in host.daemons.drain(..) {
        daemon.kill().expect("stops");
        daemon.wait().expect("ends");
    }
    host.switch(two.name());
    let restart = serde_json::json!({
        "environment": host.tree.environment_id(),
        "runtime_root": host.tree.paths().runtime_root(),
        "state_root": host.tree.paths().state_root(),
        "start": {
            "arguments": {
                "arguments": host.daemon_arguments(),
                "working_directory": host.tree.root(),
            }
        },
    });
    let record = serde_json::json!({
        "format": 1,
        "previous": null,
        "staged": two.name().as_str(),
        "update": {
            "source": one.name().as_str(),
            "target": two.name().as_str(),
            "state": "switched",
            "restarts": [restart],
        },
    });
    std::fs::write(host.store.record(), record.to_string()).expect("the record");

    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&scratch, &archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["target"], two.name().as_str(), "{said}");
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the recorded daemon was started from the release current names"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], one.name().as_str(), "{record}");
}

/// KR-REQ-26.09: a daemon the update stopped that does not start from the new release keeps the
/// update recorded, as switched, through every run that meets the same failure; the run after the
/// failure has gone starts it from the release `current` names and settles the update.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_that_does_not_start_after_the_switch_keeps_the_update_for_the_next_run() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&scratch, &archive);
    let archive = archive.display().to_string();

    let (output, said) = host.update_whose_daemons_fail(&archive);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&format!(
            "this host's current release is {} now, and a control daemon the update stopped did \
             not start from it",
            two.name()
        )),
        "{said}"
    );
    assert!(
        message.contains("ended with exit code 1 before it answered"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
    let record = host.record();
    assert_eq!(record["update"]["state"], "switched", "{record}");
    assert_eq!(
        record["update"]["restarts"].as_array().map(Vec::len),
        Some(1),
        "the daemon's restart is kept: {record}"
    );

    // A second run that meets the same failure keeps the update as well.
    let (output, said) = host.update_whose_daemons_fail(&archive);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("an update an earlier run left part way is not settled yet"),
        "{said}"
    );
    assert_eq!(host.record()["update"]["state"], "switched");

    // The control: once the daemon can start, the next run starts it from the release `current`
    // names, and the update settles.
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], one.name().as_str(), "{record}");
}

/// KR-REQ-26.09: an update that a daemon it never stopped holds waits, and when a daemon it did
/// stop does not start again from the release still current, the update stays recorded; the next
/// run starts that daemon before anything else, and then updates the host.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_that_does_not_start_again_before_the_switch_keeps_the_update_for_the_next_run() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    // A second environment of the store, held by something that is not listening: it was not
    // there to be asked to make way, so the update stops nothing of it and is held by it.
    let other = kr_ipc::testing::TempHost::create();
    host.store
        .record_roots(other.paths().runtime_root(), other.paths().state_root())
        .expect("records the other environment's roots");
    let other_lock = kr_controller::singleton::SingletonLock::hold(
        &other.environment().singleton_lock(),
        other.environment_id(),
    )
    .expect("holds the other environment");
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&scratch, &archive);
    let archive = archive.display().to_string();

    let (output, said) = host.update_whose_daemons_fail(&archive);
    assert_eq!(output.status.code(), Some(1), "{said}");
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&format!(
            "the update to {} waits: a control daemon holds environment {}",
            two.name(),
            other.environment_id()
        )),
        "{said}"
    );
    assert!(
        message.contains("A control daemon the update stopped did not start again"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    let record = host.record();
    assert_eq!(record["update"]["state"], "handing_over", "{record}");
    assert_eq!(record["staged"], two.name().as_str(), "{record}");

    // The control: once nothing holds the update and the daemon can start, the next run starts it
    // again from the release that is still current, and then updates the host.
    drop(other_lock);
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["source"], one.name().as_str(), "{said}");
    assert_eq!(said["target"], two.name().as_str(), "{said}");
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], one.name().as_str(), "{record}");
}

/// KR-REQ-26.09: an install stopped between putting its release in the store and making it
/// current is finished by the next install of the same release, and no daemon of the release
/// starts meanwhile; another release under the same name is refused, and an install waits while
/// another install or update of the store runs.
#[test]
fn an_install_stopped_before_its_switch_is_finished_by_the_next() {
    let host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    // What such an install leaves: the store's record, and the release in `versions/`.
    host.put(&one);
    let store = host.store.root().display().to_string();
    let arguments = host.daemon_arguments();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let refused = host.run(&host.program(one.name(), Program::Controller), &arguments);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("names no current release"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );

    let unpacked = |name: &str, assembled: &Assembled| {
        let tree = host.scratch(name).join(assembled.name().as_str());
        assembled.write(&tree);
        tree.join("bin").join(Program::Kr.file_name())
    };
    {
        let _update = host
            .store
            .try_lock_update()
            .expect("locks")
            .expect("nothing else updates");
        let waited = host.run(
            &unpacked("waiting", &one),
            &["host", "install", "--store", &store],
        );
        assert_eq!(waited.status.code(), Some(9));
        assert!(
            String::from_utf8_lossy(&waited.stderr)
                .contains("another install or update of the store"),
            "{}",
            String::from_utf8_lossy(&waited.stderr)
        );
    }
    let impostor = Assembled::at_this_level(one.name().as_str(), 5);
    let refused = host.run(
        &unpacked("impostor", &impostor),
        &["host", "install", "--store", &store],
    );
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains("already holds a release named 0.1.0+aaaaaaaaaaaa that is not this one"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(host.store.current().expect("reads"), None);

    // The control: the same release is made current as it is.
    host.install(&one);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert!(host.record()["update"].is_null());
}

/// KR-REQ-26.06: a program of a release still being staged does not start once it is runnable,
/// where an install copies it and where an update unpacks it; the same tree outside the store
/// starts.
#[test]
fn no_program_of_a_release_being_staged_starts() {
    use std::os::unix::fs::DirBuilderExt as _;

    let host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let tree = host.scratch("unpacked").join(one.name().as_str());
    one.write(&tree);
    let started = host.run(
        &tree.join("bin").join(Program::Kr.file_name()),
        &["--version"],
    );
    assert!(
        started.status.success(),
        "outside the store it starts: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    let private = |name: &str| {
        let path = host.store.staging().join(name);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("a staging directory");
        path
    };
    let (copied, _) = kr_cli::update::release::copy_tree(&tree, &private("copied"))
        .unwrap_or_else(|error| panic!("copies: {error}"));
    let archives = host.scratch("archives");
    let archive = archives.join("one.tar.gz");
    one.archive(&archives, &archive);
    let (unpacked, _) = kr_cli::update::release::unpack(&archive, &private("unpacked"))
        .unwrap_or_else(|error| panic!("unpacks: {error}"));
    for staged in [copied, unpacked] {
        kr_cli::update::release::seal(&staged, &one.manifest)
            .unwrap_or_else(|error| panic!("seals: {error}"));
        let refused = host.run(
            &staged.join("bin").join(Program::Kr.file_name()),
            &["--version"],
        );
        assert!(!refused.status.success(), "{}", staged.display());
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("is still being installed"),
            "{}: {}",
            staged.display(),
            String::from_utf8_lossy(&refused.stderr)
        );
    }
}

/// Only the current release's `kr` updates the host: another release's refuses, naming the one to
/// run, and so does a build outside a store.
#[test]
fn only_the_current_release_s_kr_updates_the_host() {
    let host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.put(&one);
    host.put(&two);
    host.switch(two.name());
    let archive = host.tree.root().join("nothing.tar.gz");
    let archive = archive.display().to_string();
    let refused = host.run(
        &host.program(one.name(), Program::Kr),
        &["host", "update", "--archive", &archive],
    );
    assert_eq!(refused.status.code(), Some(3));
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(
        said.contains(&format!(
            "this kr is of release {}, and this host's current release is {}",
            one.name(),
            two.name()
        )),
        "{said}"
    );
    let outside = host.run(&support::kr(), &["host", "update", "--archive", &archive]);
    assert_eq!(outside.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&outside.stderr).contains("this kr is not of an installed release"),
        "{}",
        String::from_utf8_lossy(&outside.stderr)
    );
}

/// Writes a zsh package into a release's `shells/`, as a build installs one, and the release's
/// stable entry for zsh beside it: the file a store's startup entries source.
fn write_zsh_package(shells: &Path) {
    use kr_shell_integration::contract::qualification::ShellKind;
    use kr_shell_integration::host::package::{
        CURRENT_BASENAME, MANIFEST_BASENAME, PackageManifest, PackageShell, PackageStartupEntry,
    };

    let package = shells.join("zsh").join("test-1");
    std::fs::create_dir_all(package.join("startup")).expect("the package's directory");
    let manifest = PackageManifest {
        identity: "test-1".to_owned(),
        shell: PackageShell {
            kind: ShellKind::Zsh,
            executable: package.join("bin/zsh"),
            upstream_version: "5.9".to_owned(),
            editor_abi: "zle-5.9".to_owned(),
            integration_version: "1".to_owned(),
            patches: Vec::new(),
            modules: Vec::new(),
        },
        startup_entry: PackageStartupEntry {
            file: "startup/kr-zshrc.zsh".to_owned(),
        },
    };
    std::fs::write(
        package.join(MANIFEST_BASENAME),
        serde_json::to_string(&manifest).expect("the record encodes"),
    )
    .expect("the identity record");
    std::fs::write(shells.join("zsh").join(CURRENT_BASENAME), "test-1\n").expect("current");
    let entry = "if builtin kr-bridge status 2>/dev/null; then builtin kr-bridge activated; fi\n";
    std::fs::write(package.join("startup/kr-zshrc.zsh"), entry).expect("the package's entry");
    std::fs::write(shells.join("zsh").join("kr-zshrc.zsh"), entry).expect("the stable entry");
}

/// A kr of an installed release writes a startup entry that sources the current release's entry
/// through the store's `current`, which every update leaves in place; a kr outside a store sources
/// the package's own file.
#[test]
fn a_store_s_startup_entry_sources_the_current_release_s_entry() {
    let host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let directory = host.put(&one);
    host.switch(one.name());
    let shells = directory.join("shells");
    write_zsh_package(&shells);
    let home = host.scratch("home");
    let output = host
        .command(
            &host.store.stable(Program::Kr),
            &["shell", "install", "--shell", "zsh"],
        )
        .env("HOME", &home)
        .stdin(Stdio::null())
        .output()
        .expect("kr runs");
    assert!(
        output.status.success(),
        "kr shell install: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let written = std::fs::read_to_string(home.join(".zshrc")).expect("the entry is written");
    let stable = host.store.stable_shells().join("zsh").join("kr-zshrc.zsh");
    assert!(
        written.contains(&stable.display().to_string()),
        "the entry sources the stable file: {written}"
    );
    assert!(
        !written.contains("versions"),
        "the entry names no release's own directory: {written}"
    );

    // The control: outside a store, the same packages give an entry that sources the package's
    // own file.
    let home = host.scratch("home-outside");
    let output = Command::new(support::kr())
        .args(["shell", "install", "--shell", "zsh"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("KR_RUNTIME_DIR", host.tree.paths().runtime_root())
        .env("KR_STATE_DIR", host.tree.paths().state_root())
        .env(
            kr_shell_integration::host::package::PACKAGE_ROOT_VARIABLE,
            &shells,
        )
        .current_dir(host.tree.root())
        .stdin(Stdio::null())
        .output()
        .expect("kr runs");
    assert!(
        output.status.success(),
        "kr shell install: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let written = std::fs::read_to_string(home.join(".zshrc")).expect("the entry is written");
    assert!(
        written.contains(
            &shells
                .join("zsh/test-1/startup/kr-zshrc.zsh")
                .display()
                .to_string()
        ),
        "{written}"
    );
}

/* -------------------------------------------------------------------------------------------- */
/* What a release has to be                                                                      */
/* -------------------------------------------------------------------------------------------- */

/// A small release: two files, its root and its manifest, signed by `signer`.
fn small_release(signer: &Ed25519KeyPair) -> (ReleaseManifest, BTreeMapFiles, String) {
    let files: BTreeMapFiles = [
        ("bin/kr".to_owned(), b"#!/bin/sh\n".to_vec()),
        (
            "share/update-root.json".to_owned(),
            the_root().as_bytes().to_vec(),
        ),
    ]
    .into_iter()
    .collect();
    let manifest = ReleaseManifest {
        kind: ManifestKind::Release,
        release: release("0.2.0+bbbbbbbbbbbb"),
        sequence: U64::new(2),
        commit: CommitId::new("b".repeat(40)).expect("a commit"),
        target: this_target().to_owned(),
        os_floor: OsFloor {
            system: FloorSystem::Macos,
            version: FloorVersion { major: 1, minor: 0 },
        },
        protocol_version: PACKAGE_VERSION,
        public_majors: vec![1],
        retained_levels: vec![CompatibilityLevel::of(PACKAGE_VERSION)],
        shells: Vec::new(),
        files: files
            .iter()
            .map(|(path, contents)| ReleaseFile {
                path: ReleasePath::new(path.as_str()).expect("a path"),
                length: U64::new(contents.len() as u64),
                sha256: Digest256::from_bytes(kr_cbor::sha256(contents)),
                mode: if path.starts_with("bin/") {
                    FileMode::Executable
                } else {
                    FileMode::Regular
                },
            })
            .collect(),
    };
    let document = signed_document(&manifest, signer);
    (manifest, files, document)
}

type BTreeMapFiles = std::collections::BTreeMap<String, Vec<u8>>;

/// The channel root this process makes, read back as a release would carry it.
fn trusted() -> kr_cli::update::release::ChannelRoot {
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join(kr_cli::update::release::CHANNEL_ROOT);
    std::fs::create_dir_all(path.parent().expect("share")).expect("share");
    std::fs::write(&path, the_root()).expect("the root");
    kr_cli::update::release::ChannelRoot::read(directory.path())
        .unwrap_or_else(|error| panic!("the root reads: {error}"))
        .expect("the root is there")
}

/// KR-REQ-26.09: a manifest is taken only when a threshold of the keys the trusted root names for
/// its targets role signed it, over exactly what it says.
#[test]
fn a_manifest_is_taken_only_as_the_root_s_targets_keys_signed_it() {
    let root = trusted();
    // The control: signed by the targets key, it is taken.
    let (manifest, _, document) = small_release(&keys().targets);
    assert_eq!(
        root.verify(document.as_bytes())
            .unwrap_or_else(|error| panic!("taken: {error}")),
        manifest
    );
    for signer in [&keys().root, &keys().stranger] {
        let (_, _, document) = small_release(signer);
        assert!(
            root.verify(document.as_bytes()).is_err(),
            "a key the root names for no targets role signs nothing"
        );
    }
    // A signed document changed afterwards, by one member this build does not even read.
    let mut changed: Value = serde_json::from_str(&document).expect("JSON");
    changed["signed"]["stores"] = serde_json::json!([]);
    assert!(root.verify(changed.to_string().as_bytes()).is_err());
    // And one that names a member twice with the same value, which leaves the canonical form and
    // the signature as they were: refused by the updater, as by every program of the release.
    let repeated = document.replacen(
        "\"signed\":{",
        &format!("\"signed\":{{\"release\":\"{}\",", manifest.release),
        1,
    );
    assert_ne!(repeated, document, "the member is repeated");
    assert!(root.verify(repeated.as_bytes()).is_err());
    assert!(ReleaseManifest::read_document(repeated.as_bytes()).is_err());
}

/// A release carries the host's root or the one that follows it, signed by the host's root keys and
/// its own; any other root is refused.
#[test]
fn a_channel_root_is_followed_only_by_its_successor() {
    let trusted = trusted();
    let carried = |text: String| {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join(kr_cli::update::release::CHANNEL_ROOT);
        std::fs::create_dir_all(path.parent().expect("share")).expect("share");
        std::fs::write(&path, text).expect("the root");
        kr_cli::update::release::ChannelRoot::read(directory.path())
            .map(|root| root.expect("there"))
    };
    let same = carried(the_root().to_owned()).unwrap_or_else(|error| panic!("reads: {error}"));
    assert!(
        trusted.admits_successor(&same).is_ok(),
        "the same root follows"
    );
    // The next version, with a new root key, signed by the old root key and the new one.
    let new_key = &keys().stranger;
    let next = carried(channel_root(2, new_key, &[&keys().root, new_key]))
        .unwrap_or_else(|error| panic!("reads: {error}"));
    assert!(
        trusted.admits_successor(&next).is_ok(),
        "its successor follows"
    );
    // The controls: signed by the new key alone, or skipping a version, it does not.
    let unsigned_by_the_old = carried(channel_root(2, new_key, &[new_key]))
        .unwrap_or_else(|error| panic!("reads: {error}"));
    assert!(trusted.admits_successor(&unsigned_by_the_old).is_err());
    let skipping = carried(channel_root(3, new_key, &[&keys().root, new_key]))
        .unwrap_or_else(|error| panic!("reads: {error}"));
    assert!(trusted.admits_successor(&skipping).is_err());
    // A root its own root key did not sign is not root metadata anybody may trust.
    assert!(carried(channel_root(1, &keys().root, &[&keys().stranger])).is_err());
}

/// KR-REQ-26.09: an archive is refused at its first entry that is not a file or a directory of the
/// one release under one top directory, and an archive that is only files unpacks.
#[test]
fn an_archive_is_refused_at_its_first_entry_that_is_not_a_release_file() {
    let scratch = tempfile::tempdir().expect("a directory");
    let write_archive = |name: &str, entries: &[(&str, tar::EntryType, &[u8])]| {
        let path = scratch.path().join(name);
        let file = std::fs::File::create(&path).expect("an archive");
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            file,
            flate2::Compression::fast(),
        ));
        for (entry_path, kind, contents) in entries {
            let mut header = tar::Header::new_gnu();
            // Written into the header's name as it is, so a path the builder would refuse to make
            // is exactly what an archive can carry.
            let name = &mut header.as_old_mut().name;
            name[..entry_path.len()].copy_from_slice(entry_path.as_bytes());
            header.set_entry_type(*kind);
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            if *kind == tar::EntryType::Symlink {
                header.set_link_name("/etc/passwd").expect("a link");
            }
            header.set_cksum();
            builder.append(&header, *contents).expect("an entry");
        }
        builder
            .into_inner()
            .and_then(flate2::write::GzEncoder::finish)
            .expect("written");
        path
    };
    // Owner-only, as the store's own staging directory is.
    let staging = |name: &str| {
        use std::os::unix::fs::DirBuilderExt as _;

        let path = scratch.path().join(name);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("a staging directory");
        path
    };
    // The control: files and directories under one top directory unpack, each with its digest.
    let archive = write_archive(
        "good.tar.gz",
        &[
            ("release/bin", tar::EntryType::Directory, b""),
            ("release/bin/kr", tar::EntryType::Regular, b"#!/bin/sh\n"),
        ],
    );
    let (unpacked, written) = kr_cli::update::release::unpack(&archive, &staging("good"))
        .unwrap_or_else(|error| panic!("unpacks: {error}"));
    assert!(unpacked.join("bin/kr").is_file());
    assert_eq!(
        written.get("bin/kr").map(|(length, _)| *length),
        Some(10),
        "each file's length and digest are taken as it is written"
    );
    for (name, entries) in [
        (
            "link",
            vec![("release/bin/kr", tar::EntryType::Symlink, &b""[..])],
        ),
        (
            "hard-link",
            vec![("release/bin/kr", tar::EntryType::Link, &b""[..])],
        ),
        (
            "device",
            vec![("release/bin/kr", tar::EntryType::Char, &b""[..])],
        ),
        (
            "climbing",
            vec![("release/../escape", tar::EntryType::Regular, &b"x"[..])],
        ),
        (
            "absolute",
            vec![("/release/bin/kr", tar::EntryType::Regular, &b"x"[..])],
        ),
        (
            "two-tops",
            vec![
                ("release/bin/kr", tar::EntryType::Regular, &b"x"[..]),
                ("other/bin/kr", tar::EntryType::Regular, &b"x"[..]),
            ],
        ),
        (
            "twice",
            vec![
                ("release/bin/kr", tar::EntryType::Regular, &b"x"[..]),
                ("release/bin/kr", tar::EntryType::Regular, &b"y"[..]),
            ],
        ),
    ] {
        let archive = write_archive(&format!("{name}.tar.gz"), &entries);
        let refused = kr_cli::update::release::unpack(&archive, &staging(name));
        assert!(refused.is_err(), "{name} is refused");
        assert!(
            !scratch.path().join("escape").exists(),
            "nothing was written outside the staging directory"
        );
    }
}

/// KR-REQ-26.09: what was written is checked against the manifest: every listed file with its
/// length and digest, and nothing unlisted.
#[test]
fn a_release_is_every_file_its_manifest_lists_and_nothing_else() {
    let (manifest, files, _) = small_release(&keys().targets);
    let written = |files: &BTreeMapFiles| -> kr_cli::update::release::Written {
        files
            .iter()
            .map(|(path, contents)| {
                (
                    path.clone(),
                    (
                        contents.len() as u64,
                        Digest256::from_bytes(kr_cbor::sha256(contents)),
                    ),
                )
            })
            .collect()
    };
    // The control: what the manifest lists, and the manifest itself, is the release.
    let mut whole = written(&files);
    whole.insert(
        kr_protocol::update::MANIFEST_FILE.to_owned(),
        (1, Digest256::from_bytes([0; 32])),
    );
    assert!(kr_cli::update::release::check_files(&manifest, &whole).is_ok());
    let mut changed = files.clone();
    changed.insert("bin/kr".to_owned(), b"#!/bin/zsh\n".to_vec());
    let mut missing = files.clone();
    missing.remove("bin/kr");
    let mut extra = files;
    extra.insert("share/extra".to_owned(), b"x".to_vec());
    for (what, files) in [("changed", changed), ("missing", missing), ("extra", extra)] {
        assert!(
            kr_cli::update::release::check_files(&manifest, &written(&files)).is_err(),
            "a {what} file is refused"
        );
    }
}
