//! A host installed as a store of releases: each program holds the release it runs, starts the
//! programs of that release, and names it; `kr host install` puts a first release in, and
//! `kr host update` hands the control daemon over to another while every live session keeps the
//! release it started from, or waits, exit 9, and says why.
//!
//! Every release here is assembled from the programs this workspace built: `kr`, the restoration
//! guard, the control daemon, the worker, the description process, the forwarder and the plugin
//! host, copied once to the internal disk and then given to each release as files of its own, as
//! an installed release has. Each release
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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use aws_lc_rs::signature::Ed25519KeyPair;
use kr_ipc::client::LocalClient;
use kr_ipc::install::{Program, Store};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hello::{PACKAGE_VERSION, PackageVersion};
use kr_protocol::ids::{ActionId, BuildId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Digest256, Nullable, U64, Uuid};
use kr_protocol::update::{
    CommitId, CompatibilityLevel, FileMode, FloorSystem, FloorVersion, HandoverStep,
    HostUpdateHandoverParams, ManifestKind, OsFloor, Recording, ReleaseFile, ReleaseManifest,
    ReleaseName, ReleasePath, ReleaseStore, SignedMembers, StoreScope,
};
use serde_json::Value;

mod stored_formats;
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
    /// The targets key a rotation of the channel's root names in place of `targets`.
    next_targets: Ed25519KeyPair,
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
            next_targets: pair(),
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
    channel_root_naming(version, root_key, &keys().targets, signers)
}

/// A channel root at `version` naming `root_key` for its root role and `targets_key` for its
/// targets role, signed by each of `signers`.
fn channel_root_naming(
    version: u64,
    root_key: &Ed25519KeyPair,
    targets_key: &Ed25519KeyPair,
    signers: &[&Ed25519KeyPair],
) -> String {
    use tough::schema::{RoleKeys, RoleType, Root, Signed};

    let one = NonZeroU64::new(1).expect("one");
    let named = |pair: &Ed25519KeyPair| RoleKeys {
        keyids: vec![key_id(pair)],
        threshold: one,
        _extra: HashMap::new(),
    };
    let mut keys_named = HashMap::new();
    keys_named.insert(key_id(root_key), tough::sign::Sign::tuf_key(root_key));
    keys_named.insert(key_id(targets_key), tough::sign::Sign::tuf_key(targets_key));
    let mut roles = HashMap::new();
    roles.insert(RoleType::Root, named(root_key));
    roles.insert(RoleType::Targets, named(targets_key));
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

/// The programs of a release, by name: every executable a host runs, which a release carries in
/// `bin/`. Written out here, not read from the list a release is checked against, so that a name
/// dropped from that list is a release these tests still assemble whole.
const PROGRAM_NAMES: [&str; 7] = [
    "kr",
    "kr-attach-guard",
    "kr-worker",
    "kr-controller",
    "kr-describe-inference",
    "kr-hook",
    "kr-plugin-host",
];

/// The programs this workspace built, beside this test or where Cargo says, each by its name with
/// its digest.
///
/// Copied once for this whole process into the run's own directory on the internal disk, which
/// goes when the process does. A build of this crate alone builds `kr` and the guard; the others
/// are built by a workspace run, or by `cargo build -p kr-controller -p kr-worker -p kr-hook -p
/// kr-plugin-host` and `cargo build -p kr-describe-model --bin kr-describe-inference`, and a run
/// without them fails and says so rather than passing without having tested anything.
fn programs() -> &'static [(&'static str, PathBuf, Digest256, u64)] {
    static COPIED: OnceLock<Vec<(&'static str, PathBuf, Digest256, u64)>> = OnceLock::new();
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
                 workspace test run builds it, and so do `cargo build -p kr-controller -p \
                 kr-worker -p kr-hook -p kr-plugin-host` and `cargo build -p kr-describe-model \
                 --bin kr-describe-inference`",
                candidate.display()
            );
            candidate
        };
        let sources = PROGRAM_NAMES.map(|name| {
            let source = match name {
                "kr" => PathBuf::from(env!("CARGO_BIN_EXE_kr")),
                "kr-attach-guard" => PathBuf::from(env!("CARGO_BIN_EXE_kr-attach-guard")),
                other => beside(other),
            };
            (name, source)
        });
        let directory = support::command_binaries().join("releases");
        std::fs::create_dir_all(&directory).expect("a directory for the programs");
        sources
            .into_iter()
            .map(|(name, source)| {
                let copied = directory.join(name);
                kr_ipc::testing::place_program(&source, &copied);
                let bytes = std::fs::read(&copied).expect("the program");
                (
                    name,
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

/// The stores a release assembled here declares it reads: every store this build declares, at the
/// versions it writes and migrates from.
fn release_stores() -> Vec<ReleaseStore> {
    static STORES: OnceLock<Vec<ReleaseStore>> = OnceLock::new();
    STORES
        .get_or_init(|| {
            stored_formats::table::table()
                .into_iter()
                .map(|store| store.entry)
                .collect()
        })
        .clone()
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
            .map(|(name, _, digest, length)| ReleaseFile {
                path: ReleasePath::new(format!("bin/{name}")).expect("a path"),
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
                stores: release_stores(),
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

    /// This release as a build that did not yet need `names` would have assembled it: it lists none
    /// of them and its tree holds none, the rest unchanged.
    fn without(mut self, names: &[&str]) -> Self {
        self.manifest.files.retain(|file| {
            !names
                .iter()
                .any(|name| file.path.as_str() == format!("bin/{name}"))
        });
        self
    }

    /// This release as one that reads `stores` and no others would have been assembled.
    fn reading(mut self, stores: Vec<ReleaseStore>) -> Self {
        self.manifest.stores = stores;
        self
    }

    /// This release as one that lists no store would have been assembled.
    fn without_stores(mut self) -> Self {
        self.manifest.stores.clear();
        self
    }

    /// This release with `name` listed as a file that is not a program: its bytes are in the tree
    /// and in the manifest, so every file check passes, and the manifest does not say it runs.
    fn with_data(mut self, name: &str) -> Self {
        for file in &mut self.manifest.files {
            if file.path.as_str() == format!("bin/{name}") {
                file.mode = FileMode::Regular;
            }
        }
        self
    }

    fn name(&self) -> &ReleaseName {
        &self.manifest.release
    }

    /// Writes the release's tree at `directory`, its manifest signed by `signer`.
    fn write_signed(&self, directory: &Path, signer: &Ed25519KeyPair) {
        std::fs::create_dir_all(directory.join("bin")).expect("the release's bin");
        for (name, copied, _, _) in programs() {
            // A release assembled without a program lists none and carries none.
            if self.manifest.file(&format!("bin/{name}")).is_some() {
                clone_file(copied, &directory.join("bin").join(name));
            }
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

    /// Gives `archive` the release as an archive: its tree under one top directory, gzipped.
    ///
    /// A release is packed once for the whole process, by whichever test asks first, into the run's
    /// own directory on the internal disk, which goes when the process does. Each test is given a
    /// copy of its own: the archive is hundreds of megabytes of programs, and a test that packed its
    /// own would repeat what another has already done.
    fn archive(&self, archive: &Path) {
        self.archive_signed(archive, &keys().targets);
    }

    /// Gives `archive` the release as an archive whose manifest `signer` signed.
    fn archive_signed(&self, archive: &Path, signer: &Ed25519KeyPair) {
        static PACKED: OnceLock<Mutex<HashMap<String, Arc<OnceLock<PathBuf>>>>> = OnceLock::new();
        // Two releases that are signed alike are packed alike: the signature covers every file's
        // digest, and the channel root is one of the files.
        let identity = format!("{}\n{}", signed_document(&self.manifest, signer), self.root);
        let packed = Arc::clone(
            PACKED
                .get_or_init(Mutex::default)
                .lock()
                .expect("the packed releases")
                .entry(identity)
                .or_default(),
        );
        let packed = packed.get_or_init(|| {
            let top = format!("kalareach-{}-{}", this_target(), self.name());
            let directory = tempfile::Builder::new()
                .prefix("kr-archive-")
                .tempdir_in(support::command_binaries())
                .expect("a directory for the archive")
                .keep();
            let tree = directory.join(&top);
            self.write_signed(&tree, signer);
            let packed = directory.join("release.tar.gz");
            pack(&tree, &top, &packed);
            std::fs::remove_dir_all(&tree).expect("the tree goes");
            packed
        });
        std::fs::copy(packed, archive).expect("a copy of the archive");
    }
}

/// Packs `tree` as an archive whose entries are under `top`, gzipped quickly.
fn pack(tree: &Path, top: &str, archive: &Path) {
    let file = std::fs::File::create(archive).expect("an archive");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    let mut builder = tar::Builder::new(encoder);
    // Every file whole, as a release archive has them: the builder writes a file that has holes as
    // a sparse entry, which some file systems make of a copied program, and which is refused.
    builder.sparse(false);
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

/// How many cases that install and start releases run at once, where the operating system checks
/// a program the first time it starts: on macOS. Nothing else checks one, so nothing else bounds
/// the cases.
const HOST_CASES_AT_ONCE: Option<usize> = if cfg!(target_os = "macos") {
    Some(2)
} else {
    None
};

/// One of the places [`HOST_CASES_AT_ONCE`] gives, held for as long as a case has its host.
///
/// macOS checks each program the first time it starts from a file that was just written, one
/// program at a time for the whole machine, and a release the commands under test install or
/// unpack is made of such files. Starting the daemon of such a release waits for that check behind
/// every program written before it, so cases that all write releases at once keep each other
/// waiting, for as long as the longest of their queues, and no deadline a case or the update
/// holds says anything about the case. With a few places the queue holds a few programs, and a
/// case's wait is its own program's check and what the rest of the machine adds, however many
/// cases the test run would otherwise start at once.
struct Place;

impl Place {
    fn take() -> Self {
        let (taken, freed) = places();
        let mut taken = taken
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while HOST_CASES_AT_ONCE.is_some_and(|limit| *taken >= limit) {
            taken = freed
                .wait(taken)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *taken += 1;
        Self
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let (taken, freed) = places();
        *taken
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) -= 1;
        freed.notify_one();
    }
}

/// The places taken, and the signal that one was given back.
fn places() -> &'static (Mutex<usize>, std::sync::Condvar) {
    static PLACES: (Mutex<usize>, std::sync::Condvar) = (Mutex::new(0), std::sync::Condvar::new());
    &PLACES
}

/// A stand-in for an agent that a session's shell started: a process that runs until the test lets go
/// of the pipe it reads.
struct Agent {
    /// The identity the kernel gives its process.
    identity: kr_protocol::identity::ProcessStartIdentity,
    /// The pipe it reads, held open for as long as it should run.
    _life: std::fs::File,
}

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
    // Last, so that it is given back once the tree is gone.
    _place: Place,
}

/// Prints what the daemons of a case that failed wrote, and how long before it was read each log was
/// last written: the tree goes with the test, and a daemon's log carries no times of its own.
///
/// A write that fails is no reason to stop a teardown, so this uses no macro that panics on one.
fn show_what_the_daemons_wrote(tree: &teardown::Tree) {
    let mut logs: Vec<PathBuf> = std::fs::read_dir(tree.root())
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("daemon") && name.ends_with(".log"))
        })
        .collect();
    logs.extend(
        std::fs::read_dir(tree.paths().state_root().join("environments"))
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path().join("controller.log")),
    );
    logs.sort();
    for log in logs {
        let Ok(text) = std::fs::read_to_string(&log) else {
            continue;
        };
        let ago = std::fs::metadata(&log)
            .and_then(|about| about.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok());
        let _ = writeln!(
            std::io::stderr(),
            "the log of a daemon, {}, last written {} before it was read as this test failed:\n{text}",
            log.display(),
            ago.map_or_else(
                || "at a time that is not known".to_owned(),
                |ago| format!("{:.1} s", ago.as_secs_f64())
            ),
        );
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        if std::thread::panicking() {
            show_what_the_daemons_wrote(&self.tree);
        }
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

/// Hands over and stops whatever daemon serves `tree`'s environment, through its own door, and says
/// whether none is left serving it.
async fn stop_daemon_of(tree: &teardown::Tree) -> bool {
    let environment = tree.environment();
    let Ok(endpoint) = environment.controller_endpoint() else {
        return true;
    };
    if let Ok(mut client) = LocalClient::connect(&endpoint, LocalClientKind::Cli, build()).await {
        let target = release("0.0.0+000000000000");
        let prepared = tokio::time::timeout(
            Duration::from_secs(60),
            handover_step_of(
                tree.environment_id(),
                &mut client,
                HandoverStep::Prepare,
                None,
                &target,
            ),
        )
        .await;
        // The stop names the attempt the daemon began, which is the only one it stops under.
        if let Ok(Ok(answered)) = prepared
            && let Ok(answer) = answered.to_typed::<kr_protocol::update::HostUpdateHandoverResult>()
        {
            let _ = tokio::time::timeout(
                Duration::from_secs(60),
                handover_stop_of(
                    tree.environment_id(),
                    &mut client,
                    answer.attempt.0,
                    &target,
                ),
            )
            .await;
        }
    }
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if kr_controller::singleton::SingletonLock::hold(
            &environment.singleton_lock(),
            tree.environment_id(),
        )
        .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Waits for `child` to end, and returns what it printed; a child that has not ended within `limit`
/// is ended, and the test fails.
fn finish_within(mut child: std::process::Child, limit: Duration) -> Output {
    let deadline = Instant::now() + limit;
    while matches!(child.try_wait(), Ok(None)) {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the program did not end within {} seconds", limit.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().expect("the program ends")
}

/// Makes every directory under `root`, and `root`, read-only, as a release in the store is.
fn seal_directories(root: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("a directory") {
            let entry = entry.expect("an entry");
            if entry.file_type().expect("a type").is_dir() {
                pending.push(entry.path());
            }
        }
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o555))
            .expect("sealed");
    }
}

/// A second environment of a host's store: a tree of its own, and a daemon of the store's current
/// release serving it. Whatever daemon serves it when the test ends, the one this started or one an
/// update started in its place, is stopped through its own door before the tree goes.
struct Second {
    daemon: Option<std::process::Child>,
    tree: teardown::Tree,
}

impl Second {
    /// Starts `program`, a daemon of the store, in a new tree, and waits for it to answer.
    async fn start(program: &Path) -> Self {
        let tree = teardown::Tree::create();
        let log = tree.root().join("daemon.log");
        let file = std::fs::File::create(&log).expect("the daemon's log");
        let runtime = tree.paths().runtime_root().display().to_string();
        let state = tree.paths().state_root().display().to_string();
        let child = Command::new(program)
            .args([
                "--runtime-dir",
                &runtime,
                "--state-dir",
                &state,
                "--secret-store",
                "file",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("KR_RUNTIME_DIR", &runtime)
            .env("KR_STATE_DIR", &state)
            .current_dir(tree.root())
            .stdin(Stdio::null())
            .stdout(file.try_clone().expect("duplicates the log"))
            .stderr(file)
            .spawn()
            .expect("the daemon starts");
        let second = Self {
            daemon: Some(child),
            tree,
        };
        let endpoint = second
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
        second
    }

    /// What this environment's daemon states about its build.
    async fn build(&self) -> String {
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
}

impl Drop for Second {
    fn drop(&mut self) {
        if std::thread::panicking() {
            show_what_the_daemons_wrote(&self.tree);
        }
        let stopped = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .ok()
                        .map(|runtime| runtime.block_on(stop_daemon_of(&self.tree)))
                })
                .join()
                .ok()
                .flatten()
        });
        if stopped == Some(false) {
            self.tree
                .hold("a daemon serving this environment could not be stopped".to_owned());
        }
        if let Some(mut daemon) = self.daemon.take() {
            let _ = daemon.kill();
            let _ = daemon.wait();
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
        Self::bare_in(teardown::Tree::create())
    }

    /// A tree with nothing at the store's place yet whose state root is named as a default install
    /// on Linux names it, `kalareach`, inside the tree's own directory: the state home a daemon is
    /// given there.
    #[cfg(all(unix, not(target_os = "macos")))]
    fn bare_as_a_default_install() -> Self {
        Self::bare_in(teardown::Tree::create_with_state_name("kalareach"))
    }

    fn bare_in(tree: teardown::Tree) -> Self {
        let place = Place::take();
        let store = Store::at(tree.root().join("host"));
        Self {
            daemons: Vec::new(),
            store,
            tree,
            _place: place,
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
        let install = self
            .store
            .try_lock_install()
            .expect("the install lock")
            .expect("nothing starts a daemon");
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

    /// Runs a program with this host's roots and nothing of this test's own environment, and fails
    /// the test, ending the program, when it has not ended within five minutes: a program that
    /// waits for a writer for ever does not hang the suite.
    fn run(&self, program: &Path, arguments: &[&str]) -> Output {
        let child = self
            .command(program, arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("{} did not start: {error}", program.display()));
        finish_within(child, Duration::from_secs(300))
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

    /// Runs `kr` of the current release with variables of its own, `set` given, and reads what it
    /// printed as JSON.
    fn kr_json_with(
        &self,
        set: &[(&str, &std::ffi::OsStr)],
        arguments: &[&str],
    ) -> (Output, Value) {
        let mut command = self.command(&self.store.stable(Program::Kr), arguments);
        for (name, value) in set {
            command.env(name, value);
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("kr runs");
        let output = finish_within(child, Duration::from_secs(300));
        let said = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        (output, said)
    }

    /// What this host's daemon says of how it was started, asked as an update asks it and taken back
    /// at once: its gate is open again when this returns.
    async fn daemon_started_like(&self) -> kr_protocol::update::HostUpdateHandoverResult {
        let endpoint = self
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the daemon");
        let target = release("0.0.0+000000000000");
        let environment = self.tree.environment_id();
        let prepared: kr_protocol::update::HostUpdateHandoverResult = handover_step_of(
            environment,
            &mut client,
            HandoverStep::Prepare,
            None,
            &target,
        )
        .await
        .expect("the daemon prepares")
        .to_typed()
        .expect("decodes");
        handover_step_of(
            environment,
            &mut client,
            HandoverStep::Resume,
            prepared.attempt.0,
            &target,
        )
        .await
        .expect("the daemon resumes");
        prepared
    }

    /// Runs `kr host update` of the current release with `archive` and `--json`, with a variable
    /// set that no control daemon of a store starts with: every daemon it starts refuses to run.
    fn update_whose_daemons_fail(&self, archive: &str) -> (Output, Value) {
        let update = self
            .command(
                &self.store.stable(Program::Kr),
                &["host", "update", "--archive", archive, "--json"],
            )
            .env(
                kr_shell_integration::host::package::PACKAGE_ROOT_VARIABLE,
                self.tree.root(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("kr runs");
        // An update that waits for a writer, or for a daemon, for ever fails the test and does not
        // hang it: its own waits are bounded by a few minutes at most.
        let output = finish_within(update, Duration::from_secs(300));
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
        let root = self.tree.root().to_path_buf();
        self.start_daemon_in(program, &root).await;
    }

    /// Starts `program` as this host's daemon, with `working_directory` as its own, and waits for
    /// it to answer.
    async fn start_daemon_in(&mut self, program: &Path, working_directory: &Path) {
        let arguments = self.daemon_arguments();
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let mut command = self.command(program, &arguments);
        command.current_dir(working_directory);
        self.start_daemon_as(command).await;
    }

    /// Starts this host's daemon with variables of its own: each of `set` given, and each of
    /// `unset` taken away from what [`Host::command`] gives every program.
    async fn start_daemon_with(
        &mut self,
        program: &Path,
        set: &[(&str, &std::ffi::OsStr)],
        unset: &[&str],
    ) {
        let arguments = self.daemon_arguments();
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let mut command = self.command(program, &arguments);
        for name in unset {
            command.env_remove(name);
        }
        for (name, value) in set {
            command.env(name, value);
        }
        self.start_daemon_as(command).await;
    }

    /// Starts `command` as this host's daemon, in the directory it names, and waits for it to answer.
    async fn start_daemon_as(&mut self, mut command: Command) {
        let log = self
            .tree
            .root()
            .join(format!("daemon-{}.log", self.daemons.len()));
        let file = std::fs::File::create(&log).expect("the daemon's log");
        let child = command
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
        stop_daemon_of(&self.tree).await
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

    /// Creates a session with a release's `kr` whose root shell starts a stand-in agent, a process
    /// of its own that outlasts anything the shell does, and then goes on as the shell.
    ///
    /// The agent reads a pipe this test holds open, and ends when the test lets go of it, however
    /// the test ends. Returns the session's display number and identifier, and the agent.
    fn new_session_with_an_agent(&self, kr: &Path, name: &str) -> (String, SessionId, Agent) {
        let directory = self.scratch(&format!("agent-{name}"));
        let pid_file = directory.join("pid");
        let life = directory.join("life");
        let made = Command::new("mkfifo")
            .arg(&life)
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "a pipe is made");
        // Open for reading and writing, which a pipe allows without waiting for the other end: the
        // agent sees the end of its input when this descriptor is closed, and not before.
        let hold = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&life)
            .expect("the pipe is held");
        // Named for the shell it goes on as, because the worker recognises a shell by its name.
        let shell = directory.join("sh");
        std::fs::write(
            &shell,
            format!(
                "#!/bin/sh\n/bin/cat < '{life}' > /dev/null &\n\
                 printf '%s\\n' \"$!\" > '{pid}.partial'\n\
                 mv '{pid}.partial' '{pid}'\nexec /bin/sh \"$@\"\n",
                life = life.display(),
                pid = pid_file.display()
            ),
        )
        .expect("the stand-in agent's shell");
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o755))
                .expect("executable");
        }
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
                &shell.display().to_string(),
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
        let started = Instant::now();
        let pid: u32 = loop {
            if let Some(pid) = std::fs::read_to_string(&pid_file)
                .ok()
                .and_then(|text| text.trim().parse().ok())
            {
                break pid;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the session's shell did not start its agent"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let identity = kr_ipc::identity::started_process_identity(pid).expect("the agent runs");
        (
            created["display_number"].to_string(),
            session_id,
            Agent {
                identity,
                _life: hold,
            },
        )
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

    /// The identity of the process a session's worker runs as, from the descriptor it published.
    fn worker_process(&self, session_id: SessionId) -> kr_protocol::identity::ProcessStartIdentity {
        kr_ipc::descriptor::read(&self.tree.environment(), session_id)
            .expect("reads the descriptor")
            .expect("the session is published")
            .process_start_identity
    }

    /// Waits until the kernel says a worker's process has ended.
    ///
    /// `kr close` answers when the worker accepts the close, and the worker ends after that. An
    /// update that meets a worker on its way out waits for it, which is what an update owes a
    /// worker that has not ended, so a test that goes on to update asks for this first.
    async fn worker_ended(&self, worker: &kr_protocol::identity::ProcessStartIdentity) {
        let started = Instant::now();
        while !matches!(
            kr_ipc::identity::process_state(worker),
            kr_ipc::identity::ProcessState::Ended
        ) {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the worker did not end after its session was closed"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
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

    /// What a run that stopped after its switch leaves: `two` current, no daemon running, and the
    /// update recorded as switched, with the daemon of this host to be started as it was.
    fn record_a_switched_update(&mut self, one: &Assembled, two: &Assembled) {
        for mut daemon in self.daemons.drain(..) {
            daemon.kill().expect("stops");
            daemon.wait().expect("ends");
        }
        self.switch(two.name());
        self.record_the_update_as_switched(one, two);
    }

    /// Records an update from `one` to `two` as switched, with the daemon of this host to be
    /// started as it was, whatever runs and whatever `current` names.
    fn record_the_update_as_switched(&self, one: &Assembled, two: &Assembled) {
        let restart = serde_json::json!({
            "environment": self.tree.environment_id(),
            "runtime_root": self.tree.paths().runtime_root(),
            "state_root": self.tree.paths().state_root(),
            "start": {
                "arguments": {
                    "arguments": self.daemon_arguments(),
                    "working_directory": self.tree.root(),
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
        std::fs::write(self.store.record(), record.to_string()).expect("the record");
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

/// KR-REQ-26.09: `kr host install` refuses a tree whose signed manifest lists no plugin host, a
/// program every host runs, and the same release with it is installed into the same store.
#[test]
fn kr_host_install_refuses_a_release_that_lacks_a_program_a_host_runs() {
    let host = Host::bare();
    let store = host.store.root().display().to_string();
    let lacking = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).without(&["kr-plugin-host"]);
    let tree = host.scratch("lacking").join(lacking.name().as_str());
    lacking.write(&tree);
    let refused = host.run(
        &tree.join("bin").join("kr"),
        &["host", "install", "--store", &store],
    );
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a release without it is refused"
    );
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(said.contains("`kr-plugin-host`"), "{said}");
    assert_eq!(host.store.current().ok().flatten(), None);

    let whole = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&whole);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(whole.name().clone())
    );
}

/// KR-REQ-26.10: `kr host install` refuses a tree whose signed manifest lists no store, because the
/// stores a release reads are what a host checks before it switches to the release, and the same
/// release with its stores is installed into the same store.
#[test]
fn kr_host_install_refuses_a_release_that_lists_no_store() {
    let host = Host::bare();
    let store = host.store.root().display().to_string();
    let lacking = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).without_stores();
    let tree = host.scratch("lacking").join(lacking.name().as_str());
    lacking.write(&tree);
    let refused = host.run(
        &tree.join("bin").join("kr"),
        &["host", "install", "--store", &store],
    );
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a release that lists no store is refused"
    );
    assert_eq!(host.store.current().ok().flatten(), None);

    let whole = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&whole);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(whole.name().clone())
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
    two.archive(&archive_two);

    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive_two.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
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
    three.archive(&archive_three);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive_three.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
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
    four.archive(&archive_four);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive_four.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
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
    elsewhere.archive(&archive);
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
    host.record_a_switched_update(&one, &two);

    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
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
    // The record the update left was written by an earlier build, as format 1; it is written again
    // in the format this build writes.
    assert_eq!(record["format"], 2, "{record}");
}

/// KR-REQ-26.10: a transaction an earlier build began holds no root, and settles on the roots of its
/// two releases that can be read, each on its own: the root file of the release left is damaged,
/// and the second root the release switched to carries is still the root the host trusts.
#[tokio::test(flavor = "multi_thread")]
async fn a_transaction_with_no_root_settles_on_the_release_roots_that_can_be_read() {
    use std::os::unix::fs::PermissionsExt as _;

    let mut host = Host::bare();
    let rotated = channel_root_naming(2, &keys().root, &keys().next_targets, &[&keys().root]);
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::new(
        "0.2.0+bbbbbbbbbbbb",
        2,
        CompatibilityLevel::of(PACKAGE_VERSION),
        &rotated,
    );
    host.install(&one);
    host.put(&two);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    host.record_a_switched_update(&one, &two);
    assert!(
        host.record()["update"]["trusted_root"].is_null(),
        "the transaction is one an earlier build began"
    );
    // The root of the release left cannot be read.
    let share = host.store.release_directory(one.name()).join("share");
    std::fs::set_permissions(&share, std::fs::Permissions::from_mode(0o755)).expect("opened");
    let root_file = share.join("update-root.json");
    std::fs::set_permissions(&root_file, std::fs::Permissions::from_mode(0o644)).expect("opened");
    std::fs::write(&root_file, b"{ not a root").expect("damaged");

    let archive = host.scratch("archives").join("two.tar.gz");
    // Release two carries the second root, so the host that has switched to it checks an archive
    // against that root: the manifest is signed with the key it names.
    two.archive_signed(&archive, &keys().next_targets);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(
        record["trusted_root"]["signed"]["version"], 2,
        "the root the release switched to carries is the one trusted: {record}"
    );
}

/// KR-REQ-26.09: an update an earlier run left after its switch finds the environment held by a
/// daemon of the release before it, which resumes and goes on answering as that release: the update
/// says what it answered as, and then names the daemon with how to stop it, and keeps the update.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_left_after_its_switch_names_a_daemon_that_answers_as_the_release_before() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    host.put(&two);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    // `current` names the release after it, and the update is recorded as switched, while the
    // daemon of the release before it still runs.
    host.switch(two.name());
    host.record_the_update_as_switched(&one, &two);
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);

    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(1), "{said}");
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&format!("answers as kr-controller/{}", one.name()))
            && message.contains(&format!("not as a daemon of {}", two.name())),
        "what failed comes first: {said}"
    );
    let pid = host.daemons[0].id();
    assert!(
        message.contains(&format!(
            "(process {pid}) answers as kr-controller/{}",
            one.name()
        )) && message.contains(&format!("kill {pid}")),
        "the daemon is named, with what it answers as and how to stop it: {said}"
    );
    assert_eq!(host.record()["update"]["state"], "switched");
}

/// KR-REQ-26.09: an update an earlier run left after its switch finds the environment held by a
/// daemon that does not listen, one on its way out: it waits for that daemon to have gone, and then
/// starts the daemon it recorded, where it used to wait for an answer that could not come.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_left_after_its_switch_waits_for_a_daemon_on_its_way_out() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    host.put(&two);
    host.record_a_switched_update(&one, &two);
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();

    // A daemon that has stopped listening and not yet let go of its environment.
    let going = kr_controller::singleton::SingletonLock::acquire(
        &host.tree.environment().singleton_lock(),
        host.tree.environment_id(),
    )
    .expect("holds the environment");
    let update = host
        .command(
            &host.store.stable(Program::Kr),
            &["host", "update", "--archive", &archive, "--json"],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kr runs");
    tokio::time::sleep(Duration::from_secs(3)).await;
    drop(going);

    let output = finish_within(update, Duration::from_secs(300));
    let said: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the recorded daemon was started from the release current names"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
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
    two.archive(&archive);
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

/// KR-REQ-26.09: when a daemon the update stopped does not start again from the release still
/// current, the update stays recorded; the next run starts that daemon before anything else, and
/// then updates the host. What ends this update, after the stop, is a registry that is not a regular
/// file, which is refused and never opened: a pipe there would hold the update for as long as
/// nothing wrote to it.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_that_does_not_start_again_before_the_switch_keeps_the_update_for_the_next_run() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    // A second environment of the store, no daemon of it running, whose registry is a pipe: the
    // update finds nothing holding it before it stops this host's daemon, and refuses to read it
    // after.
    let other = kr_ipc::testing::TempHost::create();
    host.store
        .record_roots(other.paths().runtime_root(), other.paths().state_root())
        .expect("records the other environment's roots");
    let registry = other.environment().registry_database();
    let made = Command::new("mkfifo")
        .arg(&registry)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "a pipe is made");
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();

    let (output, said) = host.update_whose_daemons_fail(&archive);
    assert_eq!(output.status.code(), Some(1), "{said}");
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&other.environment_id().to_string())
            && message.contains("is not a regular file"),
        "the pipe is refused by the reader, and never opened: {said}"
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

    // The control: once the registry is not a pipe and the daemon can start, the next run starts it
    // again from the release that is still current, and then updates the host.
    std::fs::remove_file(&registry).expect("the pipe is removed");
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

/// Sends one step of the handover to this host's daemon on `client`, targeting `target`, for
/// `attempt` where the step names one.
async fn handover_step(
    host: &Host,
    client: &mut LocalClient,
    step: HandoverStep,
    attempt: Option<Uuid>,
    target: &ReleaseName,
) -> Result<kr_protocol::envelope::ParamsValue, kr_protocol::error::ProtocolError> {
    handover_step_of(host.tree.environment_id(), client, step, attempt, target).await
}

/// Sends one step of the handover to the daemon of `environment` on `client`, and returns what came
/// back: the daemon's answer, or the failure of the call itself.
async fn handover_call_of(
    environment: kr_protocol::ids::EnvironmentId,
    client: &mut LocalClient,
    step: HandoverStep,
    attempt: Option<Uuid>,
    target: &ReleaseName,
) -> Result<
    Result<kr_protocol::envelope::ParamsValue, kr_protocol::error::ProtocolError>,
    kr_ipc::IpcError,
> {
    client
        .mutate(
            Method::HostUpdateHandover,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment),
            &HostUpdateHandoverParams {
                step,
                target: target.clone(),
                attempt: Nullable(attempt),
            },
        )
        .await
}

/// Sends one step of the handover to the daemon of `environment` on `client`, for a step whose
/// answer always reaches the caller: a daemon that refuses a step, or takes any step but a stop,
/// goes on serving and writes its answer.
async fn handover_step_of(
    environment: kr_protocol::ids::EnvironmentId,
    client: &mut LocalClient,
    step: HandoverStep,
    attempt: Option<Uuid>,
    target: &ReleaseName,
) -> Result<kr_protocol::envelope::ParamsValue, kr_protocol::error::ProtocolError> {
    handover_call_of(environment, client, step, attempt, target)
        .await
        .expect("the call reaches the daemon")
}

/// Tells the daemon of `environment` to stop under `attempt`, and returns its refusal when it
/// refused.
///
/// A daemon that takes a stop ends, and may end before it has written its answer, so an answer
/// that does not come because the connection ended is not a refusal: the daemon's end is what says
/// the stop was taken, and the caller waits for that and for how it ended. A refusal is an answer,
/// and the daemon that gives one serves on. Any other failure of the call is returned as it is.
async fn handover_stop_of(
    environment: kr_protocol::ids::EnvironmentId,
    client: &mut LocalClient,
    attempt: Option<Uuid>,
    target: &ReleaseName,
) -> Result<Option<kr_protocol::error::ProtocolError>, kr_ipc::IpcError> {
    match handover_call_of(environment, client, HandoverStep::Stop, attempt, target).await {
        Ok(answer) => Ok(answer.err()),
        Err(kr_ipc::IpcError::PeerClosed | kr_ipc::IpcError::TruncatedFrame { .. }) => Ok(None),
        Err(other) => Err(other),
    }
}

/// KR-REQ-26.09: a daemon an update prepared, and may have told to stop, is taken back for the
/// environment's daemon only once it has resumed, so no stop of that attempt still on its way can
/// end it afterwards, however the daemon is prepared again meanwhile: the stop names the attempt it
/// belongs to, finds it over, and is refused, and the daemon goes on serving.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_an_update_prepared_is_taken_back_only_once_no_stop_of_it_can_end_it() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = release("0.2.0+bbbbbbbbbbbb");
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    // What an update that stopped part way leaves while its stop to the daemon is still on its
    // way: the daemon prepared, and the update recorded as handing over.
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    let attempt = handover_step(&host, &mut client, HandoverStep::Prepare, None, &two)
        .await
        .expect("the daemon prepares")
        .to_typed::<kr_protocol::update::HostUpdateHandoverResult>()
        .expect("decodes")
        .attempt
        .0
        .expect("it answers the attempt it began");
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
        "update": {
            "source": one.name().as_str(),
            "target": two.as_str(),
            "state": "handing_over",
            "restarts": [restart],
        },
    });
    std::fs::write(host.store.record(), record.to_string()).expect("the record");

    let scratch = host.scratch("archives");
    let archive = scratch.join("one.tar.gz");
    one.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(host.record()["update"].is_null(), "the update is settled");

    // The stop still on its way arrives, and is refused: the daemon resumed before it was taken
    // back.
    let refused = handover_step(&host, &mut client, HandoverStep::Stop, Some(attempt), &two)
        .await
        .expect_err("a daemon that resumed is not stopped");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::ResourceUnavailable
    );
    // The same stop, arriving after another update has begun its own attempt on the daemon, is
    // refused as well: the daemon is closed to new sessions for that attempt, and this stop
    // belongs to another.
    let later = handover_step(&host, &mut client, HandoverStep::Prepare, None, &two)
        .await
        .expect("the daemon prepares again")
        .to_typed::<kr_protocol::update::HostUpdateHandoverResult>()
        .expect("decodes")
        .attempt
        .0
        .expect("it answers the attempt it began");
    assert_ne!(attempt, later, "each attempt has an identity of its own");
    let refused = handover_step(&host, &mut client, HandoverStep::Stop, Some(attempt), &two)
        .await
        .expect_err("a stop of an earlier attempt ends nothing while a later one is open");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::ResourceUnavailable
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon serves"
    );
    // The control: the attempt that is open ends as its own update ends it, and the daemon goes on
    // serving as it did.
    handover_step(&host, &mut client, HandoverStep::Resume, Some(later), &two)
        .await
        .expect("the open attempt ends");
    assert!(
        host.daemons
            .iter_mut()
            .all(|daemon| matches!(daemon.try_wait(), Ok(None))),
        "the daemon this test started still serves the environment"
    );
}

/// KR-REQ-26.09: a daemon whose working directory was removed cannot say how it was started, and a
/// `prepare` finds that out before it has changed anything: it is refused and the gate stays open.
/// A `resume` and a `stop` are taken all the same, and are not refused, since what they answer is not
/// what a daemon is started from: a step that answers an error is a step that was not taken. A daemon
/// that takes a stop ends, and may end before its answer is written.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_that_cannot_say_how_it_was_started_is_refused_before_its_gate_closes() {
    use kr_protocol::error::ErrorCode;
    use kr_protocol::update::HostUpdateHandoverResult;

    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = release("0.2.0+bbbbbbbbbbbb");
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    let kr = host.store.stable(Program::Kr);
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");

    // A daemon prepared while its directory is there, whose directory then goes: its resume is taken
    // and answers, and its gate is open.
    let directory = host.scratch("first-daemon-directory");
    host.start_daemon_in(&controller, &directory).await;
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    let attempt = handover_step(&host, &mut client, HandoverStep::Prepare, None, &two)
        .await
        .expect("the daemon prepares")
        .to_typed::<HostUpdateHandoverResult>()
        .expect("decodes")
        .attempt
        .0
        .expect("it answers the attempt it began");
    std::fs::remove_dir(&directory).expect("the daemon's directory is removed");
    handover_step(
        &host,
        &mut client,
        HandoverStep::Resume,
        Some(attempt),
        &two,
    )
    .await
    .expect("a resume is taken and answers");
    let (display, _) = host.new_session(&kr);
    host.close(&kr, &display);
    // Another prepare is refused before it closes the gate: the daemon cannot say how it was
    // started, and a session is still created.
    let refused = handover_step(&host, &mut client, HandoverStep::Prepare, None, &two)
        .await
        .expect_err("a daemon that cannot say how it was started does not prepare");
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    assert!(
        refused.message.contains("no longer exists")
            && refused
                .message
                .contains("start it again from a directory that exists"),
        "the refusal says what happened and what to do: {}",
        refused.message
    );
    let (display, _) = host.new_session(&kr);
    host.close(&kr, &display);

    // Another daemon, prepared with its directory there: its stop is taken and answers, and the
    // daemon ends.
    for mut daemon in host.daemons.drain(..) {
        daemon.kill().expect("stops");
        daemon.wait().expect("ends");
    }
    let directory = host.scratch("second-daemon-directory");
    host.start_daemon_in(&controller, &directory).await;
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    let attempt = handover_step(&host, &mut client, HandoverStep::Prepare, None, &two)
        .await
        .expect("the daemon prepares")
        .to_typed::<HostUpdateHandoverResult>()
        .expect("decodes")
        .attempt
        .0
        .expect("it answers the attempt it began");
    std::fs::remove_dir(&directory).expect("the daemon's directory is removed");
    // The stop is taken, and the daemon ends, which may be before it has written its answer: what
    // it must not do is refuse the stop, and that it ends is what shows the stop was taken.
    let refused = handover_stop_of(host.tree.environment_id(), &mut client, Some(attempt), &two)
        .await
        .expect("the stop call failed only because the daemon ended");
    assert!(
        refused.is_none(),
        "a stop is taken, not refused: {refused:?}"
    );
    let daemon = host
        .daemons
        .last_mut()
        .expect("the daemon this test started");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = daemon.try_wait().expect("the daemon's end is read") {
            break status;
        }
        assert!(Instant::now() < deadline, "the daemon did not stop");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    // A daemon that stops as it is told ends in success: one that was lost to a crash before it
    // answered is not a stop that was taken.
    assert!(
        status.success(),
        "the daemon ended by a stop, not by a failure: {status:?}"
    );
}

/// KR-REQ-26.08: a daemon that starts after an update's first look, in an environment the update
/// did not know, is found once no daemon can start: it records its roots before it takes its
/// environment, under the install lock, and the update reads them again under that lock and waits.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_finds_a_daemon_that_started_after_its_first_look() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();

    // A daemon part way through its start holds the install lock, shared, as each one does.
    let starting = host.store.lock_start().expect("the start lock");
    let update = host
        .command(
            &host.store.stable(Program::Kr),
            &["host", "update", "--archive", &archive, "--json"],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kr runs");
    // Once the update has looked, and has told this host's daemon to make way, the starting daemon
    // records its roots and takes its environment, and then lets go of the install lock.
    let deadline = Instant::now() + LIVENESS_DEADLINE;
    loop {
        let state = std::fs::read(host.store.record())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .map(|record| record["update"]["state"].clone());
        if state == Some(Value::from("handing_over")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the update did not reach its handover"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let other = kr_ipc::testing::TempHost::create();
    host.store
        .record_roots(other.paths().runtime_root(), other.paths().state_root())
        .expect("records the roots it serves");
    let other_lock = kr_controller::singleton::SingletonLock::hold(
        &other.environment().singleton_lock(),
        other.environment_id(),
    )
    .expect("takes its environment");
    drop(starting);

    let output = finish_within(update, Duration::from_secs(300));
    let said: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    assert_eq!(
        output.status.code(),
        Some(9),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&format!(
                "the update to {} waits: a control daemon holds environment {}",
                two.name(),
                other.environment_id()
            )),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon it prepared serves from the release still current"
    );
    assert!(
        host.daemons
            .iter_mut()
            .all(|daemon| matches!(daemon.try_wait(), Ok(None))),
        "the daemon this test started was never stopped: the holder was found before any stop"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["staged"], two.name().as_str(), "{record}");
    drop(other_lock);
}

/// KR-REQ-26.08: the install lock is waited for before any daemon is stopped, for a bound. A daemon
/// that never finishes starting, holding the start lock past the bound, makes the update exit 9,
/// naming the store, with nothing stopped: every daemon it prepared is resumed and serves, its gate
/// open again, and the release stays staged; once the daemon has started, the next update goes
/// through.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_that_cannot_take_the_install_lock_stops_nothing() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();

    // A daemon that never finishes starting holds the install lock, shared, past the update's bound.
    let starting = host.store.lock_start().expect("the start lock");
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("is starting and has held its start lock for more than 30 seconds")
            && message.contains("run kr host update again"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    assert!(
        host.daemons
            .iter_mut()
            .all(|daemon| matches!(daemon.try_wait(), Ok(None))),
        "the daemon this test started was never stopped"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["staged"], two.name().as_str(), "{record}");
    // Its gate is open again: a session is created.
    let kr = host.store.stable(Program::Kr);
    let (display, session_id) = host.new_session(&kr);
    let worker = host.worker_process(session_id);
    host.close(&kr, &display);
    host.worker_ended(&worker).await;

    // The control: once the daemon has started, the next update goes through.
    drop(starting);
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
}

/// KR-REQ-26.09: a daemon that answers that it does not stop, because its attempt is over, goes on
/// serving: the update says which daemon and why, exits 9 without waiting for it to go, and starts
/// again what it did stop; nobody is told to kill a daemon that is healthy.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_that_refuses_to_stop_goes_on_serving_and_the_update_waits() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();

    // The update prepares the daemon, records how to start it again, and then waits for the install
    // lock a starting daemon holds; meanwhile another attempt begins on the daemon, which ends the
    // update's.
    let starting = host.store.lock_start().expect("the start lock");
    let update = host
        .command(
            &host.store.stable(Program::Kr),
            &["host", "update", "--archive", &archive, "--json"],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kr runs");
    let deadline = Instant::now() + LIVENESS_DEADLINE;
    loop {
        let state = std::fs::read(host.store.record())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .map(|record| record["update"]["state"].clone());
        if state == Some(Value::from("handing_over")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the update did not reach its handover"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    handover_step(&host, &mut client, HandoverStep::Prepare, None, two.name())
        .await
        .expect("the daemon begins another attempt");
    drop(starting);

    let output = finish_within(update, Duration::from_secs(300));
    let said: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    assert_eq!(
        output.status.code(),
        Some(9),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("did not stop:") && !message.contains("kill"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon goes on serving"
    );
    assert!(
        host.daemons
            .iter_mut()
            .all(|daemon| matches!(daemon.try_wait(), Ok(None))),
        "the daemon this test started was never stopped"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["staged"], two.name().as_str(), "{record}");
    // Both attempts are over, and its gate is open: a session is created.
    let kr = host.store.stable(Program::Kr);
    let (display, _) = host.new_session(&kr);
    host.close(&kr, &display);
}

/// KR-REQ-26.09: with two environments, one whose daemon answers that it does not stop and one that
/// stopped, the update waits for the one it stopped to have gone before it starts it again: nothing
/// is met on its way out, nobody is told to kill anything, the update exits 9, and both daemons
/// serve.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_stop_leaves_every_daemon_serving_and_the_update_waits() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let second = Second::start(&controller).await;
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();
    // The update tells the daemons in the order of their environments' identities, so the daemon
    // whose attempt is superseded is the last one: the one before it accepts its stop first.
    let (last_environment, last_endpoint) = {
        let ours = host.tree.environment_id();
        let theirs = second.tree.environment_id();
        if ours.to_string() > theirs.to_string() {
            (
                ours,
                host.tree
                    .environment()
                    .controller_endpoint()
                    .expect("an endpoint"),
            )
        } else {
            (
                theirs,
                second
                    .tree
                    .environment()
                    .controller_endpoint()
                    .expect("an endpoint"),
            )
        }
    };

    let starting = host.store.lock_start().expect("the start lock");
    let update = host
        .command(
            &host.store.stable(Program::Kr),
            &["host", "update", "--archive", &archive, "--json"],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kr runs");
    let deadline = Instant::now() + LIVENESS_DEADLINE;
    loop {
        let state = std::fs::read(host.store.record())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .map(|record| record["update"]["state"].clone());
        if state == Some(Value::from("handing_over")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the update did not reach its handover"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut client = LocalClient::connect(&last_endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    handover_step_of(
        last_environment,
        &mut client,
        HandoverStep::Prepare,
        None,
        two.name(),
    )
    .await
    .expect("the daemon begins another attempt");
    drop(starting);

    let output = finish_within(update, Duration::from_secs(300));
    let said: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    assert_eq!(
        output.status.code(),
        Some(9),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("did not stop:") && !message.contains("kill"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the first environment's daemon serves"
    );
    assert_eq!(
        second.build().await,
        format!("kr-controller/{}", one.name()),
        "and so does the second's"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["staged"], two.name().as_str(), "{record}");
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

    // The control: the same release, whole, is made current as it is, and sealed as it is used:
    // what an install left before it made the release read-only is read-only now.
    host.install(&one);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert!(host.record()["update"].is_null());
    let kept = host.store.release_directory(one.name());
    for path in [
        kept.clone(),
        kept.join("bin"),
        kept.join(module_tree()[0].0),
    ] {
        assert!(
            std::fs::metadata(&path)
                .expect("installed")
                .permissions()
                .readonly(),
            "{} is read-only",
            path.display()
        );
    }
}

/// KR-REQ-26.09: an install writes the store's record before any program of its release is in the
/// store, and puts the release in and makes it current under the install lock: while a daemon of
/// the store is part way through its start, the install has made the directory a store and has
/// published nothing, and it finishes once the daemon's start has.
#[test]
fn an_install_makes_the_store_first_and_publishes_under_the_install_lock() {
    let host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.store
        .create_directories()
        .expect("the store's directories");
    let starting = host.store.lock_start().expect("the start lock");
    let tree = host.scratch("unpacked").join(one.name().as_str());
    one.write(&tree);
    let store = host.store.root().display().to_string();
    let mut install = host
        .command(
            &tree.join("bin").join(Program::Kr.file_name()),
            &["host", "install", "--store", &store, "--json"],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kr runs");
    // The release copied, checked and sealed in the staging directory: all that comes before the
    // install lock.
    let sealed = || {
        std::fs::read_dir(host.store.staging())
            .into_iter()
            .flatten()
            .flatten()
            .any(|run| {
                std::fs::metadata(run.path().join("release/bin")).is_ok_and(|about| {
                    std::os::unix::fs::PermissionsExt::mode(&about.permissions()) & 0o777 == 0o555
                })
            })
    };
    let deadline = Instant::now() + LIVENESS_DEADLINE;
    while !sealed() {
        assert!(
            matches!(install.try_wait(), Ok(None)),
            "the install ended before it staged its release"
        );
        assert!(
            Instant::now() < deadline,
            "the install did not stage its release"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(500));
    assert!(matches!(install.try_wait(), Ok(None)), "the install waits");
    assert!(host.store.is_store(), "the store's record comes first");
    assert!(
        !host.store.release_directory(one.name()).exists(),
        "nothing is published while a daemon is part way through its start"
    );
    assert_eq!(host.store.current().expect("reads"), None);

    drop(starting);
    let output = finish_within(install, Duration::from_secs(300));
    assert!(
        output.status.success(),
        "kr host install: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// What is under `root`, as a comparison shows it: each entry's path, kind, mode and length, the
/// links as links.
fn what_is_under(root: &Path) -> Vec<(String, &'static str, u32, u64)> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("reads").flatten() {
            let about = std::fs::symlink_metadata(entry.path()).expect("there");
            let kind = if about.file_type().is_symlink() {
                "link"
            } else if about.is_dir() {
                pending.push(entry.path());
                "directory"
            } else {
                "file"
            };
            found.push((
                entry
                    .path()
                    .strip_prefix(root)
                    .expect("under the root")
                    .display()
                    .to_string(),
                kind,
                about.permissions().mode() & 0o7777,
                about.len(),
            ));
        }
    }
    found.sort();
    found
}

/// KR-REQ-26.09: a release an earlier install left in the store is never used as it is: the copy
/// this install checked takes its place, so nothing the kept one was short of, changed in, linked
/// to or left writable survives, and nothing outside the store is touched; a release a running
/// program holds is not replaced, and the install waits.
#[test]
fn a_release_kept_in_the_store_is_replaced_by_the_copy_checked_in_this_run() {
    use std::os::unix::fs::PermissionsExt as _;

    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    // What is done to the kept release, given its directory and a directory outside the store.
    type Tampering = fn(&Path, &Path);
    let tamperings: [(&str, Tampering); 5] = [
        ("a missing file", |kept, _| {
            std::fs::remove_file(kept.join("bin/kr")).expect("removed");
        }),
        ("a changed file", |kept, _| {
            std::fs::write(kept.join("bin/kr"), b"#!/bin/zsh\n").expect("changed");
        }),
        ("a file it does not list", |kept, _| {
            std::fs::write(kept.join("share/extra"), b"x").expect("written");
        }),
        (
            "a file that is a hard link to one elsewhere",
            |kept, outside| {
                let file = kept.join(kr_cli::update::release::CHANNEL_ROOT);
                let elsewhere = outside.join("root.json");
                std::fs::copy(&file, &elsewhere).expect("copied");
                std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o444))
                    .expect("read-only");
                std::fs::remove_file(&file).expect("removed");
                std::fs::hard_link(&elsewhere, &file).expect("linked");
            },
        ),
        (
            "a name that is a link to a whole release elsewhere",
            |kept, outside| {
                std::fs::rename(kept, outside.join("release")).expect("moved");
                std::os::unix::fs::symlink(outside.join("release"), kept).expect("linked");
            },
        ),
    ];
    for (what, tamper) in tamperings {
        let host = Host::bare();
        host.store
            .create_directories()
            .expect("the store's directories");
        std::fs::write(host.store.record(), b"{\"format\":1}\n").expect("the store's record");
        let kept = host.store.release_directory(one.name());
        one.write(&kept);
        let outside = host.scratch("outside");
        tamper(&kept, &outside);
        let elsewhere = what_is_under(&outside);

        host.install(&one);

        assert_eq!(
            host.store.current().expect("reads"),
            Some(one.name().clone()),
            "{what}"
        );
        // A directory of the store's own, holding every file the manifest lists as it lists it,
        // each read-only and its own, and nothing else.
        let release = host.store.release_directory(one.name());
        let about = std::fs::symlink_metadata(&release).expect("there");
        assert!(about.is_dir() && !about.file_type().is_symlink(), "{what}");
        assert_eq!(about.permissions().mode() & 0o777, 0o555, "{what}");
        for file in &one.manifest.files {
            let path = release.join(file.path.as_str());
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("{what}: {}: {error}", path.display()));
            assert_eq!(
                Digest256::from_bytes(kr_cbor::sha256(&bytes)),
                file.sha256,
                "{what}: {}",
                path.display()
            );
            let about = std::fs::symlink_metadata(&path).expect("there");
            assert!(about.permissions().readonly(), "{what}: {}", path.display());
            assert_eq!(
                std::os::unix::fs::MetadataExt::nlink(&about),
                1,
                "{what}: {} is a file of its own",
                path.display()
            );
        }
        assert!(!release.join("share/extra").exists(), "{what}");
        // Nothing outside the store was changed, or removed: the hard link's other name and the
        // release a link led to are as they were, modes included.
        assert_eq!(what_is_under(&outside), elsewhere, "{what}");
    }

    // A release a running program holds is not replaced: the install waits, exit 9, and once the
    // program has gone, replaces it.
    let host = Host::bare();
    host.store
        .create_directories()
        .expect("the store's directories");
    std::fs::write(host.store.record(), b"{\"format\":1}\n").expect("the store's record");
    let kept = host.store.release_directory(one.name());
    one.write(&kept);
    let store = host.store.root().display().to_string();
    let unpacked = host.scratch("unpacked").join(one.name().as_str());
    one.write(&unpacked);
    let program = unpacked.join("bin").join(Program::Kr.file_name());
    let running = std::fs::File::open(host.store.manifest(one.name())).expect("the manifest");
    running
        .lock_shared()
        .expect("held as a running program holds it");
    let waited = host.run(&program, &["host", "install", "--store", &store]);
    assert_eq!(waited.status.code(), Some(9));
    assert!(
        String::from_utf8_lossy(&waited.stderr).contains("a running program holds it"),
        "{}",
        String::from_utf8_lossy(&waited.stderr)
    );
    assert_eq!(host.store.current().expect("reads"), None);
    drop(running);
    // A program another test starts while the hold is open keeps a copy of it until its own program
    // takes over, so the install is run again once no copy is left.
    let started = Instant::now();
    while host.store.held(one.name()).expect("asks") {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "release {} is still held",
            one.name()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    host.install(&one);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// KR-REQ-26.09: a release kept in the store whose manifest is a link or a pipe is not trusted and
/// not read: the install refuses by naming its directory and says what to do, and once the directory
/// has been removed the install goes through.
#[test]
fn a_kept_release_whose_manifest_is_not_a_file_is_refused_with_the_way_out() {
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    // What is put where the kept release's manifest is, given the manifest's path and a directory
    // outside the store.
    type Instead = fn(&Path, &Path);
    let insteads: [(&str, Instead); 2] = [
        (
            "a link to a file with the same bytes",
            |manifest, outside| {
                let elsewhere = outside.join("release.json");
                std::fs::copy(manifest, &elsewhere).expect("copied");
                std::fs::remove_file(manifest).expect("removed");
                std::os::unix::fs::symlink(&elsewhere, manifest).expect("linked");
            },
        ),
        ("a pipe", |manifest, _| {
            std::fs::remove_file(manifest).expect("removed");
            let made = Command::new("mkfifo")
                .arg(manifest)
                .status()
                .expect("mkfifo runs");
            assert!(made.success(), "a pipe is made");
        }),
    ];
    for (what, instead) in insteads {
        let host = Host::bare();
        host.store
            .create_directories()
            .expect("the store's directories");
        std::fs::write(host.store.record(), b"{\"format\":1}\n").expect("the store's record");
        let kept = host.store.release_directory(one.name());
        one.write(&kept);
        let outside = host.scratch("outside");
        instead(&host.store.manifest(one.name()), &outside);
        // As a release in the store is: every directory read-only.
        seal_directories(&kept);
        let store = host.store.root().display().to_string();
        let unpacked = host.scratch("unpacked").join(one.name().as_str());
        one.write(&unpacked);
        let program = unpacked.join("bin").join(Program::Kr.file_name());

        // A pipe waited for would fail the test at the limit; the run itself takes a moment.
        let refused = host.run(&program, &["host", "install", "--store", &store]);
        assert_eq!(refused.status.code(), Some(1), "{what}");
        let said = String::from_utf8_lossy(&refused.stderr).into_owned();
        assert!(
            said.contains(&kept.display().to_string())
                && said.contains("chmod -R u+w")
                && said.contains("kr host install again"),
            "{what}: {said}"
        );
        assert_eq!(host.store.current().expect("reads"), None, "{what}");

        // The control: as the refusal says, the directory is made writable and removed, and the
        // install goes through. Removed as it is, it would not be.
        assert!(
            std::fs::remove_dir_all(&kept).is_err(),
            "{what}: a sealed directory is not removed as it is"
        );
        let opened = Command::new("chmod")
            .args(["-R", "u+w"])
            .arg(&kept)
            .status()
            .expect("chmod runs");
        assert!(opened.success(), "{what}: the directory is made writable");
        std::fs::remove_dir_all(&kept).expect("removes");
        host.install(&one);
        assert_eq!(
            host.store.current().expect("reads"),
            Some(one.name().clone()),
            "{what}"
        );
    }
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
    one.archive(&archive);
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
        stores: release_stores(),
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
    changed["signed"]["notes"] = serde_json::json!([]);
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
            "volume",
            vec![("release/bin/kr", tar::EntryType::new(b'V'), &b""[..])],
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
    // The refusal says what the entry was, by the character tar gives it and its usual name.
    for (name, expected) in [
        ("link", "2, a symbolic link"),
        ("hard-link", "1, a hard link"),
        ("device", "3, a character device"),
        ("volume", "of type V that"),
    ] {
        let archive = scratch.path().join(format!("{name}.tar.gz"));
        let said = kr_cli::update::release::unpack(&archive, &staging(&format!("{name}-said")))
            .expect_err("it is refused")
            .to_string();
        assert!(said.contains(expected), "{name}: {said}");
    }
    // A pipe named as the archive is refused at once, and not waited for.
    let pipe = scratch.path().join("pipe.tar.gz");
    let made = Command::new("mkfifo")
        .arg(&pipe)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "a pipe is made");
    // Run on a thread of its own, so that a wait for a writer fails the test and does not hang it.
    let target = staging("pipe");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(
            kr_cli::update::release::unpack(&pipe, &target)
                .map(|_| ())
                .map_err(|error| error.to_string()),
        );
    });
    let refused = receiver
        .recv_timeout(Duration::from_secs(20))
        .expect("a pipe named as the archive was waited for")
        .expect_err("a pipe is not an archive");
    assert!(refused.contains("is not a regular file"), "{refused}");
}

/// KR-REQ-26.09: a sparse entry, a file written with its holes left out, which the tar crate's
/// builder writes of a file that has some on the systems that report holes, is refused, and said to
/// be a sparse entry, not taken for a link or a device; a file with holes written whole is taken.
#[test]
fn a_sparse_entry_is_refused_as_one() {
    use std::os::unix::fs::{DirBuilderExt as _, FileExt as _};

    let scratch = tempfile::tempdir().expect("a directory");
    let staging = |name: &str| {
        let path = scratch.path().join(name);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("a staging directory");
        path
    };
    // The control: a file with a hole in it, written whole, unpacks as a file of its whole length.
    let tree = scratch.path().join("release");
    std::fs::create_dir_all(tree.join("bin")).expect("a tree");
    let file = std::fs::File::create(tree.join("bin/kr")).expect("a file");
    file.set_len(4 << 20).expect("a file with a hole in it");
    file.write_all_at(b"data", 2 << 20)
        .expect("data in the middle");
    drop(file);
    let whole = scratch.path().join("whole.tar.gz");
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        std::fs::File::create(&whole).expect("an archive"),
        flate2::Compression::fast(),
    ));
    builder.sparse(false);
    builder.append_dir_all("release", &tree).expect("packs");
    builder
        .into_inner()
        .and_then(flate2::write::GzEncoder::finish)
        .expect("written");
    let (unpacked, written) = kr_cli::update::release::unpack(&whole, &staging("whole"))
        .unwrap_or_else(|error| panic!("a whole file unpacks: {error}"));
    assert!(unpacked.join("bin/kr").is_file());
    assert_eq!(
        written.get("bin/kr").map(|(length, _)| *length),
        Some(4 << 20)
    );

    // A sparse entry, made by hand so that every system has one: a file of 1024 bytes of which the
    // first 512 are in the archive and the rest is a hole, which the last, empty block ends at the
    // file's length.
    let sparse = scratch.path().join("sparse.tar.gz");
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        std::fs::File::create(&sparse).expect("an archive"),
        flate2::Compression::fast(),
    ));
    let mut header = tar::Header::new_gnu();
    header.set_path("release/bin/kr").expect("a path");
    header.set_entry_type(tar::EntryType::GNUSparse);
    header.set_mode(0o644);
    header.set_size(512);
    {
        let gnu = header.as_gnu_mut().expect("a GNU header");
        gnu.set_real_size(1024);
        gnu.sparse[0].set_offset(0);
        gnu.sparse[0].set_length(512);
        gnu.sparse[1].set_offset(1024);
        gnu.sparse[1].set_length(0);
    }
    header.set_cksum();
    builder.append(&header, &[7_u8; 512][..]).expect("an entry");
    builder
        .into_inner()
        .and_then(flate2::write::GzEncoder::finish)
        .expect("written");
    let said = kr_cli::update::release::unpack(&sparse, &staging("sparse"))
        .expect_err("a sparse entry is refused")
        .to_string();
    assert!(said.contains("a sparse entry"), "{said}");

    // The POSIX form of a sparse file is a regular entry that carries `GNU.sparse.*` extension keys:
    // it is refused as a sparse entry at its first entry too, not later as a file that is missing.
    let posix = scratch.path().join("posix.tar.gz");
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        std::fs::File::create(&posix).expect("an archive"),
        flate2::Compression::fast(),
    ));
    builder
        .append_pax_extensions([
            ("GNU.sparse.major", &b"1"[..]),
            ("GNU.sparse.name", &b"release/bin/kr"[..]),
        ])
        .expect("extensions");
    let mut header = tar::Header::new_gnu();
    header
        .set_path("release/GNUSparseFile.1/kr")
        .expect("a path");
    header.set_size(4);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &b"data"[..]).expect("an entry");
    builder
        .into_inner()
        .and_then(flate2::write::GzEncoder::finish)
        .expect("written");
    let said = kr_cli::update::release::unpack(&posix, &staging("posix"))
        .expect_err("a POSIX sparse entry is refused")
        .to_string();
    assert!(said.contains("a sparse entry"), "{said}");
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

/// KR-REQ-26.09: an update refuses a release whose signed manifest lists no program of one a host
/// runs, whichever program that is, and says which; so does a manifest that lists the file as data,
/// whose bytes are all there. The same release with the program is taken, so the one program is
/// the whole of the refusal.
#[test]
fn an_update_refuses_a_release_that_lacks_a_program_a_host_runs() {
    let host = Host::bare();
    let current = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&current);
    let kr = host.store.stable(Program::Kr);
    let check = |release: &Assembled, label: &str| {
        let archive = host.scratch("archives").join(format!("{label}.tar.gz"));
        release.archive(&archive);
        host.run(
            &kr,
            &[
                "host",
                "update",
                "--archive",
                &archive.display().to_string(),
                "--check",
            ],
        )
    };

    let control = check(&Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2), "whole");
    assert!(
        control.status.success(),
        "a release that carries every program is checked: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    // Every program is tried before the test says anything, so one run names each that is let
    // through.
    let mut wrong = Vec::new();
    let whole = || Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let mut cases: Vec<(String, &str, Assembled)> = PROGRAM_NAMES
        .iter()
        .map(|name| (format!("without-{name}"), *name, whole().without(&[name])))
        .collect();
    cases.push((
        "hook-as-data".to_owned(),
        "kr-hook",
        whole().with_data("kr-hook"),
    ));
    for (label, name, release) in cases {
        let refused = check(&release, &label);
        let said = String::from_utf8_lossy(&refused.stderr);
        if refused.status.code() != Some(1) {
            wrong.push(format!(
                "{label}: not refused, exit {:?}",
                refused.status.code()
            ));
        } else if !said.contains(&format!("`{name}`")) {
            wrong.push(format!("{label}: {name} is not named: {said}"));
        } else if let Some(other) = PROGRAM_NAMES
            .iter()
            .find(|other| **other != name && said.contains(&format!("`{other}`")))
        {
            wrong.push(format!("{label}: {other} is named too: {said}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(current.name().clone())
    );
}

/// KR-REQ-26.09: a release an earlier build put in the store, whose manifest lists fewer programs
/// than a host now runs, stays: its programs start, `kr host versions` reads its manifest, and an
/// update from it to a release that carries every program is taken. Only a release being taken in
/// is held to the list of programs.
#[test]
fn a_release_in_the_store_that_lacks_a_program_is_kept_and_updated_from() {
    let host = Host::create();
    // The store's record, as an install writes it: readable by its owner alone.
    std::fs::set_permissions(
        host.store.record(),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("the record's mode");
    let older = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1)
        .without(&["kr-plugin-host", "kr-describe-inference"]);
    host.put(&older);
    host.switch(older.name());

    let (listed, versions) = host.kr_json(&["host", "versions", "--json"]);
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert_eq!(
        versions["releases"][0]["release"],
        older.name().as_str(),
        "{versions}"
    );
    assert_eq!(versions["releases"][0]["sequence"], 1, "{versions}");

    let newer = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let archive = host.scratch("archives").join("newer.tar.gz");
    newer.archive(&archive);
    let updated = host.run(
        &host.store.stable(Program::Kr),
        &[
            "host",
            "update",
            "--archive",
            &archive.display().to_string(),
        ],
    );
    assert!(
        updated.status.success(),
        "{}",
        String::from_utf8_lossy(&updated.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(newer.name().clone())
    );
}

/* -------------------------------------------------------------------------------------------- */
/* Environments no daemon served between two updates                                            */
/* -------------------------------------------------------------------------------------------- */

/// An environment of a host's store that no daemon serves: a tree of its own, whose roots the store
/// records as the daemon that once served it recorded them, and whose registry holds a launch that
/// came to nothing, a live session's worker and a closed session. Its processes have all ended, so
/// no record of it holds an update.
struct Idle {
    temp: kr_ipc::testing::TempHost,
}

impl Idle {
    /// The environment, with a registry at the schema this build reads.
    fn new(store: &Store) -> Self {
        use kr_controller::registry::{Registry, WorkerRecord};
        use kr_protocol::identity::{DesktopBinding, WorkerProfile};
        use kr_protocol::ids::{ActorId, AuthorityRevision};
        use kr_protocol::scalars::{AuthorisationKey, TimestampMs};
        use kr_protocol::session::{
            ClosureReason, ClosureRecord, Durability, OwnershipCoverage, SessionState,
        };

        let temp = kr_ipc::testing::TempHost::create();
        store
            .record_roots(temp.paths().runtime_root(), temp.paths().state_root())
            .expect("records the roots a daemon of the store served");
        let idle = Self { temp };
        let mut registry = Registry::open(idle.registry(), idle.temp.environment_id())
            .expect("a registry at the schema this build reads");
        let actor = ActorId::new("local:501").expect("a principal");
        let ended = kr_ipc::identity::ended_process_identity(4242);
        // A launch that came to nothing: its launcher has ended. Its recorded create request holds
        // an environment variable its creator sent, as an earlier schema recorded them.
        reserve_with(&mut registry, &actor, &ended, 1, &recorded_create(SECRET));
        // A session that is live, and one that has closed, each with its worker.
        let worker_of = |registry: &mut Registry, byte: u8| {
            let reservation = reserve_with(registry, &actor, &ended, byte, b"intent");
            let key = AuthorisationKey::from_bytes([byte; 32]);
            registry
                .claim_rendezvous(reservation.reservation_id, key)
                .expect("claims");
            let worker = WorkerRecord {
                session_id: reservation.session_id,
                display_number: reservation.display_number,
                public_key: key,
                process_identity: ended.clone(),
                endpoint: "worker".to_owned(),
                profile: WorkerProfile::HeadlessUser,
                state: SessionState::Live,
                acknowledged_revision: AuthorityRevision::new(0),
            };
            registry
                .record_worker(reservation.reservation_id, &worker, &DesktopBinding::none())
                .expect("records the worker");
            reservation
        };
        worker_of(&mut registry, 2);
        let closed = worker_of(&mut registry, 3);
        registry
            .record_closure(&ClosureRecord {
                session_id: closed.session_id,
                session_epoch: kr_protocol::ids::SessionEpoch::V1,
                reason: ClosureReason::CloseRequested,
                root_exit_code: Nullable::null(),
                root_signal: Nullable::null(),
                terminated: Vec::new(),
                surviving: Vec::new(),
                ownership_coverage: OwnershipCoverage::Incomplete,
                durability: Durability::Durable,
                closed_at_ms: TimestampMs::new(2_000),
            })
            .expect("records the closure");
        drop(registry);
        idle
    }

    /// A live session whose worker is a process that is running and does not answer, which holds an
    /// update: this test's own process stands in for it.
    fn with_a_worker_that_holds_the_update(self) -> Self {
        use kr_controller::registry::{Registry, WorkerRecord};
        use kr_protocol::identity::{DesktopBinding, WorkerProfile};
        use kr_protocol::ids::{ActorId, AuthorityRevision};
        use kr_protocol::scalars::AuthorisationKey;
        use kr_protocol::session::SessionState;

        let mut registry = Registry::open(self.registry(), self.temp.environment_id())
            .expect("the registry opens");
        let running =
            kr_ipc::identity::current_process_start_identity().expect("this process's identity");
        let reservation = reserve_with(
            &mut registry,
            &ActorId::new("local:501").expect("a principal"),
            &running,
            4,
            b"intent",
        );
        let key = AuthorisationKey::from_bytes([4; 32]);
        registry
            .claim_rendezvous(reservation.reservation_id, key)
            .expect("claims");
        registry
            .record_worker(
                reservation.reservation_id,
                &WorkerRecord {
                    session_id: reservation.session_id,
                    display_number: reservation.display_number,
                    public_key: key,
                    process_identity: running,
                    endpoint: "worker".to_owned(),
                    profile: WorkerProfile::HeadlessUser,
                    state: SessionState::Live,
                    acknowledged_revision: AuthorityRevision::new(0),
                },
                &DesktopBinding::none(),
            )
            .expect("records the worker");
        drop(registry);
        self
    }

    /// The registry as an earlier release left it at `version`, between 4 and 6: what each later
    /// schema added is taken away, and the version says so.
    fn shaped_as(self, version: i64) -> Self {
        let mut statements = String::new();
        if version < 6 {
            statements.push_str(
                "ALTER TABLE workers DROP COLUMN desktop_session_id;
                 ALTER TABLE workers DROP COLUMN login_generation;",
            );
        }
        if version < 5 {
            statements.push_str("DROP TABLE utc_floors; DROP TABLE clock_continuity;");
        }
        self.change(&format!(
            "{statements} UPDATE schema_version SET version = {version};"
        ))
    }

    /// The registry's version row says `version` and nothing else changes.
    fn labelled(self, version: i64) -> Self {
        self.change(&format!("UPDATE schema_version SET version = {version};"))
    }

    fn change(self, statements: &str) -> Self {
        let connection = rusqlite::Connection::open(self.registry()).expect("opens");
        connection
            .execute_batch(statements)
            .expect("changes the registry");
        drop(connection);
        self
    }

    fn registry(&self) -> PathBuf {
        self.temp.environment().registry_database()
    }

    fn environment_id(&self) -> String {
        self.temp.environment_id().to_string()
    }

    /// What the registry records, read as the file alone: every column the first schema this suite
    /// forges has, apart from the recorded create request, which a later schema rewrites.
    fn records(&self) -> Vec<Vec<Vec<String>>> {
        let uri = format!("file:{}?immutable=1", self.registry().display());
        let connection = rusqlite::Connection::open_with_flags(
            uri,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_URI
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("the registry reads");
        [
            "SELECT reservation_id, actor_id, create_token, payload_digest, session_id,
                    display_number, phase, launcher_pid, launcher_source, launcher_start,
                    claimed_key, created_at_ms FROM reservations ORDER BY reservation_id",
            "SELECT session_id, display_number, public_key, process_pid, process_source,
                    process_start, endpoint, profile, state, acknowledged_revision, stated_source
             FROM workers ORDER BY session_id",
            "SELECT * FROM tombstones ORDER BY session_id",
            "SELECT * FROM environment",
        ]
        .iter()
        .map(|query| {
            let mut statement = connection.prepare(query).expect("prepares");
            let columns = statement.column_count();
            statement
                .query_map([], |row| {
                    Ok((0..columns)
                        .map(|column| format!("{:?}", row.get_ref(column).expect("a value")))
                        .collect::<Vec<_>>())
                })
                .expect("reads")
                .collect::<Result<_, _>>()
                .expect("rows")
        })
        .collect()
    }

    /// The schema version the registry records, read as the file alone.
    fn version(&self) -> i64 {
        kr_controller::registry::Registry::open_to_read(self.registry(), self.temp.environment_id())
            .map(|_| kr_controller::registry::SCHEMA_VERSION)
            .unwrap_or_else(|_| {
                let uri = format!("file:{}?immutable=1", self.registry().display());
                rusqlite::Connection::open_with_flags(
                    uri,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_URI,
                )
                .expect("reads")
                .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
                .expect("a version")
            })
    }

    /// Every file in the environment's directories whose name says a database's log or journal.
    fn sidecars(&self) -> Vec<String> {
        let mut found = Vec::new();
        let mut pending = vec![self.temp.root().to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory)
                .expect("a directory")
                .flatten()
            {
                let name = entry.file_name().to_string_lossy().into_owned();
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    pending.push(entry.path());
                } else if ["-wal", "-shm", "-journal"]
                    .iter()
                    .any(|suffix| name.ends_with(suffix))
                {
                    found.push(name);
                }
            }
        }
        found
    }
}

/// Reserves a launch with the ended process `ended` as its launcher.
fn reserve_with(
    registry: &mut kr_controller::registry::Registry,
    actor: &kr_protocol::ids::ActorId,
    ended: &kr_protocol::identity::ProcessStartIdentity,
    byte: u8,
    intent: &[u8],
) -> kr_controller::registry::Reservation {
    let reservation = registry
        .reserve(
            actor,
            Uuid::from_bytes([byte; 16]),
            Digest256::from_bytes([byte; 32]),
            intent,
            kr_protocol::scalars::TimestampMs::new(u64::from(byte)),
        )
        .expect("reserves")
        .reservation;
    registry
        .record_launch(reservation.reservation_id, ended)
        .expect("records the launcher");
    registry
        .set_phase(
            reservation.reservation_id,
            kr_controller::registry::LaunchPhase::Spawned,
        )
        .expect("the launch is spawned");
    reservation
}

/// The value of an environment variable a creator sent, which an earlier schema recorded with the
/// create request it came in.
const SECRET: &str = "a-secret-an-earlier-schema-recorded";

/// A create request as an earlier schema recorded it: whole, with the environment its creator sent.
fn recorded_create(secret: &str) -> Vec<u8> {
    use kr_protocol::identity::WorkerProfile;
    use kr_protocol::session::{
        EnvironmentVariable, LaunchProfile, Presentation, SessionCreateParams, ShellMode,
    };

    kr_cbor::to_canonical_vec(&SessionCreateParams {
        environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([9; 16])),
        presentation: Presentation::Invisible,
        shell: Nullable::null(),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some("/".to_owned()),
        dimensions: Nullable::null(),
        worker_profile: WorkerProfile::HeadlessUser,
        environment_snapshot: vec![EnvironmentVariable {
            name: "API_TOKEN".to_owned(),
            value: secret.to_owned(),
        }],
        palette: Nullable::null(),
        launch_profile: LaunchProfile::default(),
        terminal: Nullable::null(),
    })
    .expect("encodes")
}

/// A host with a release installed and its daemon serving, and a newer release archived.
async fn host_to_update() -> (Host, Assembled, Assembled, String) {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();
    (host, one, two, archive)
}

/// KR-REQ-26.08, KR-REQ-24.30: an environment whose daemon did not run since an earlier schema
/// step does not stop the update. Its registry is two schema steps behind the one the update's
/// release reads; the update, with every daemon stopped and every environment's lock held, brings
/// it forward through the registry's own migration before it classes it, says so, and the rows it
/// held are the rows it holds: nothing is left beside the file.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_carries_an_environment_whose_daemon_did_not_run_forward() {
    let (host, one, two, archive) = host_to_update().await;
    let idle = Idle::new(&host.store).shaped_as(4);
    let before = idle.records();
    assert_eq!(idle.version(), 4);

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["target"], two.name().as_str(), "{said}");
    assert_eq!(
        said["carried"],
        serde_json::json!([{
            "environment": idle.environment_id(),
            "from": 4,
            "to": kr_controller::registry::SCHEMA_VERSION,
        }]),
        "{said}"
    );
    assert_eq!(
        said["restarted"],
        serde_json::json!([host.tree.environment_id().to_string()]),
        "the environment a daemon served is started again, and the idle one is not: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
    let _ = one;
    assert_eq!(idle.version(), kr_controller::registry::SCHEMA_VERSION);
    assert_eq!(
        idle.records(),
        before,
        "every row it held is the row it holds"
    );
    assert_eq!(
        idle.sidecars(),
        Vec::<String>::new(),
        "no log or journal is left beside it"
    );
}

/// KR-REQ-24.30: the carry is the registry's own chain, every step of it: an idle registry two
/// steps behind comes through the step that removes the environment its creators sent from the
/// recorded create requests as a daemon's start would take it, and the old bytes are gone from the
/// file and from its log, and the request is what it was, with no environment.
#[tokio::test(flavor = "multi_thread")]
async fn the_carry_takes_an_idle_registry_through_the_step_that_removes_recorded_environments() {
    let (host, _one, _two, archive) = host_to_update().await;
    let idle = Idle::new(&host.store).shaped_as(4);
    let held_before = std::fs::read(idle.registry()).expect("the registry");
    assert!(
        held_before
            .windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes()),
        "the old registry holds what its creator sent"
    );

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["carried"][0]["from"], 4, "{said}");
    let after = std::fs::read(idle.registry()).expect("the registry");
    assert!(
        !after
            .windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes()),
        "nothing of what the creator sent is in the file"
    );
    assert_eq!(idle.sidecars(), Vec::<String>::new(), "or in a log");
    let registry = kr_controller::registry::Registry::open_to_read(
        idle.registry(),
        idle.temp.environment_id(),
    )
    .expect("reads at the schema this build reads");
    let reservation = registry
        .reservations_in(kr_controller::registry::LaunchPhase::Spawned)
        .expect("reads")
        .into_iter()
        .next()
        .expect("the launch that came to nothing");
    let intent = reservation.create_intent.expect("its request is kept");
    let create: kr_protocol::session::SessionCreateParams =
        kr_cbor::from_canonical_slice(&intent, &kr_cbor::Limits::DEFAULT).expect("a request");
    let mut expected: kr_protocol::session::SessionCreateParams =
        kr_cbor::from_canonical_slice(&recorded_create(SECRET), &kr_cbor::Limits::DEFAULT)
            .expect("the request as it was recorded");
    expected.environment_snapshot.clear();
    assert_eq!(
        create, expected,
        "the request is what it was, with no environment"
    );
}

/// KR-REQ-24.30: a step of the chain that cannot finish holds the update and says so, and the next
/// run goes on from where it stopped. The step that removes the recorded environments cannot take
/// its log in while another connection reads the registry: the update exits 1 with the registry at
/// the version before that step, its requests already rewritten, nothing switched and the daemon it
/// stopped serving; once the reader is gone, the next update carries from that version.
#[tokio::test(flavor = "multi_thread")]
async fn a_step_that_cannot_finish_holds_the_update_and_the_next_run_goes_on_from_it() {
    let (host, one, two, archive) = host_to_update().await;
    let idle = Idle::new(&host.store).shaped_as(4);
    // Another program has the registry open and a read under way, as a tool a person runs might.
    let reader = rusqlite::Connection::open(idle.registry()).expect("opens");
    reader
        .execute_batch("BEGIN; SELECT COUNT(*) FROM reservations;")
        .expect("a read under way");

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&idle.environment_id())
            && message.contains("recorded schema version 4 when it was opened")
            && message.contains("write-ahead log still holds the old copies")
            && message.contains("run kr host update again"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon the update stopped serves from the release still current"
    );
    drop(reader);
    assert_eq!(
        idle.version(),
        6,
        "the step before the one that could not finish"
    );

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["carried"][0]["from"], 6, "{said}");
    assert_eq!(idle.version(), kr_controller::registry::SCHEMA_VERSION);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
}

/// The control of the above: every environment ran, so every registry is at the schema this build
/// reads, the update finishes, and it carries nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_across_environments_that_all_ran_carries_nothing() {
    let (host, _one, two, archive) = host_to_update().await;
    let second = Second::start(&host.store.stable(Program::Controller)).await;

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["carried"], serde_json::json!([]), "{said}");
    assert_eq!(said["not_reached"], serde_json::json!([]), "{said}");
    let mut restarted: Vec<String> = said["restarted"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|environment| environment.as_str().unwrap_or_default().to_owned())
        .collect();
    restarted.sort();
    let mut expected = vec![
        host.tree.environment_id().to_string(),
        second.tree.environment_id().to_string(),
    ];
    expected.sort();
    assert_eq!(restarted, expected, "{said}");
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
    assert_eq!(
        second.build().await,
        format!("kr-controller/{}", two.name())
    );
}

/// KR-REQ-26.09: a check changes nothing, and so does not carry: an idle registry two steps behind
/// is as it was after it, byte for byte and with nothing made beside it, and the check names none.
#[tokio::test(flavor = "multi_thread")]
async fn a_check_leaves_an_idle_registry_as_it_was() {
    let (host, _one, _two, archive) = host_to_update().await;
    let idle = Idle::new(&host.store).shaped_as(4);
    let before = std::fs::read(idle.registry()).expect("the registry");
    let removed = host.tree.root().join("removed-state");
    host.store
        .record_roots(&host.tree.root().join("removed-runtime"), &removed)
        .expect("records a state root that is gone");

    let (output, said) =
        host.kr_json(&["host", "update", "--archive", &archive, "--check", "--json"]);
    assert!(
        output.status.success(),
        "kr host update --check: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["carried"], serde_json::json!([]), "{said}");
    assert_eq!(
        said["not_reached"][0]["state_root"],
        removed.display().to_string(),
        "a check names the root it could not reach: {said}"
    );
    assert_eq!(
        std::fs::read(idle.registry()).expect("the registry"),
        before
    );
    assert_eq!(idle.version(), 4);
    assert_eq!(idle.sidecars(), Vec::<String>::new());
}

/// KR-REQ-26.08: an update that waits after it brought a registry forward says so, and the registry
/// stays at the schema this release reads, which the release still current reads as well: the idle
/// environment's registry is two steps behind and holds a live worker that does not answer, so the
/// carry happens and the registry is then classed and holds the update, exit 9, with nothing switched
/// and the daemon the update stopped serving again. A recorded environment whose state is gone is
/// named in that message too.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_that_waits_after_a_carry_says_what_it_carried_and_leaves_it_so() {
    let (host, one, _two, archive) = host_to_update().await;
    let idle = Idle::new(&host.store)
        .with_a_worker_that_holds_the_update()
        .shaped_as(4);
    let removed = host.tree.root().join("removed-state");
    host.store
        .record_roots(&host.tree.root().join("removed-runtime"), &removed)
        .expect("records a state root that is gone");

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("did not answer its challenge and has not ended")
            && message.contains(&format!(
                "The update had already brought forward the registry of environment {} from \
                 schema version 4 to {}",
                idle.environment_id(),
                kr_controller::registry::SCHEMA_VERSION
            ))
            && message.contains(&format!(
                "The update found that the environment recorded with runtime root {} and state \
                 root {} could not be reached",
                host.tree.root().join("removed-runtime").display(),
                removed.display()
            )),
        "{said}"
    );
    assert_eq!(idle.version(), kr_controller::registry::SCHEMA_VERSION);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon the update stopped serves from the release still current"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
}

/// KR-REQ-24.30: a registry that cannot be brought forward holds the update, and what it left is
/// said. Labelled version 3 with every column of this build, its first step adds a column that is
/// already there: the step fails whole, the registry stays at version 3 for the release that is
/// current to continue from, nothing is switched, and the daemon the update stopped serves again.
#[tokio::test(flavor = "multi_thread")]
async fn a_registry_that_cannot_be_carried_holds_the_update_and_says_where_it_is() {
    let (host, one, _two, archive) = host_to_update().await;
    let idle = Idle::new(&host.store).labelled(3);

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&idle.environment_id())
            && message.contains("brought forward")
            && message.contains("schema version 3")
            && message.contains("stated_source"),
        "{said}"
    );
    assert_eq!(idle.version(), 3);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon the update stopped serves from the release still current"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
}

/// KR-REQ-24.30: the migration never makes a table again that a registry lost, which would read as
/// a registry that recorded no worker: a registry two steps behind with no `reservations` table
/// holds the update, names the table, and is left as it was.
#[tokio::test(flavor = "multi_thread")]
async fn a_registry_that_lost_a_table_is_not_carried_and_holds_the_update() {
    let (host, one, _two, archive) = host_to_update().await;
    let idle = Idle::new(&host.store)
        .shaped_as(4)
        .change("DROP TABLE reservations;");

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&idle.environment_id()) && message.contains("reservations"),
        "{said}"
    );
    assert_eq!(idle.version(), 4);
    let tables: i64 = rusqlite::Connection::open(idle.registry())
        .expect("opens")
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'reservations'",
            [],
            |row| row.get(0),
        )
        .expect("reads the schema");
    assert_eq!(tables, 0, "no table was made again, empty");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// The control of the two above, for a registry of a later schema than this release reads: it is
/// not carried back, and the update holds as it did.
#[tokio::test(flavor = "multi_thread")]
async fn a_registry_of_a_later_schema_holds_the_update_and_is_left() {
    let (host, one, _two, archive) = host_to_update().await;
    let later = kr_controller::registry::SCHEMA_VERSION + 1;
    let idle = Idle::new(&host.store).labelled(later);

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&idle.environment_id())
            && message.contains(&format!("schema version {later}")),
        "{said}"
    );
    assert_eq!(idle.version(), later);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// KR-REQ-26.08: an environment whose identity cannot be looked at because what holds it is gone,
/// a state root that is a file where a directory was, or one that was removed, is named in the
/// outcome, and every other environment goes ahead: the daemon the host's own environment has is
/// handed over and started again from the new release.
#[tokio::test(flavor = "multi_thread")]
async fn an_environment_that_cannot_be_reached_is_named_and_the_others_go_ahead() {
    let (host, _one, two, archive) = host_to_update().await;
    let file = host.tree.root().join("not-a-directory");
    std::fs::write(&file, b"a container's mount that became a file").expect("a file");
    let runtime = host.tree.root().join("unreached-runtime");
    let removed = host.tree.root().join("removed-state");
    host.store
        .record_roots(&runtime, &file)
        .expect("records a state root that is a file");
    host.store
        .record_roots(&runtime, &removed)
        .expect("records a state root that is gone");

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let unreached = said["not_reached"].as_array().cloned().unwrap_or_default();
    let mut states: Vec<String> = unreached
        .iter()
        .map(|entry| entry["state_root"].as_str().unwrap_or_default().to_owned())
        .collect();
    states.sort();
    let mut expected = vec![file.display().to_string(), removed.display().to_string()];
    expected.sort();
    assert_eq!(states, expected, "{said}");
    assert!(
        unreached.iter().all(|entry| entry["reason"]
            .as_str()
            .is_some_and(|said| !said.is_empty())),
        "each says why: {said}"
    );
    assert_eq!(
        said["restarted"],
        serde_json::json!([host.tree.environment_id().to_string()]),
        "{said}"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
}

/// The control of the above: an identity that is there and cannot be trusted, a link, is not a
/// reason to go on without the environment: the update stops before it stops anything.
#[tokio::test(flavor = "multi_thread")]
async fn an_identity_that_is_there_and_not_trusted_still_stops_the_update() {
    let (host, one, _two, archive) = host_to_update().await;
    let state = host.tree.root().join("untrusted-state");
    std::fs::create_dir_all(&state).expect("a state root");
    std::os::unix::fs::symlink(
        host.tree.root().join("elsewhere"),
        state.join("environment-id"),
    )
    .expect("a link where the identity is");
    host.store
        .record_roots(&host.tree.root().join("untrusted-runtime"), &state)
        .expect("records the roots");

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "nothing was stopped"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
}

/* -------------------------------------------------------------------------------------------- */
/* Going back                                                                                    */
/* -------------------------------------------------------------------------------------------- */

/// The stores a release assembled here declares it reads, with the registry's versions given.
fn reading_the_registry_at(migrates_from: u32, version: u32) -> Vec<ReleaseStore> {
    release_stores()
        .into_iter()
        .map(|store| {
            if store.store == "registry" {
                ReleaseStore {
                    migrates_from,
                    version,
                    ..store
                }
            } else {
                store
            }
        })
        .collect()
}

/// The registry's schema version, as the daemon wrote it.
fn registry_version() -> u32 {
    u32::try_from(kr_controller::registry::SCHEMA_VERSION).expect("a small number")
}

/// KR-REQ-26.10: `kr host rollback` goes back to the release this host was on before its last
/// switch, as an update goes forward: the control daemon is handed over and started again from the
/// older release, the release left is kept as the one to go back to, and no live session is moved.
/// A session started under the older release and one started under the newer keep their workers,
/// and so does the agent in the shell of each, through the update and through the rollback.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_goes_back_to_the_release_before_and_moves_no_live_session() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let (old_display, old_session, old_agent) =
        host.new_session_with_an_agent(&host.program(one.name(), Program::Kr), "old");
    let old_worker = host.worker_process(old_session);

    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["rolled_back"], false, "{said}");
    let (new_display, new_session, new_agent) =
        host.new_session_with_an_agent(&host.program(two.name(), Program::Kr), "new");
    let new_worker = host.worker_process(new_session);
    assert_eq!(
        host.worker_build(new_session).await,
        format!("kr-worker/{}", two.name())
    );

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["rolled_back"], true, "{said}");
    assert_eq!(said["source"], two.name().as_str(), "{said}");
    assert_eq!(said["target"], one.name().as_str(), "{said}");
    assert_eq!(
        said["restarted"],
        serde_json::json!([host.tree.environment_id().to_string()]),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone()),
        "the older release is current"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the control daemon was started again, from the older release"
    );
    let record = host.record();
    assert_eq!(record["previous"], two.name().as_str(), "{record}");
    assert!(record["update"].is_null(), "the rollback settled: {record}");
    assert!(
        host.store.release_directory(two.name()).is_dir(),
        "the release left is kept"
    );

    // No session moved: each worker is the process it was, on the release it started from, and
    // each agent runs on.
    for (session, worker, agent, release) in [
        (old_session, &old_worker, &old_agent, &one),
        (new_session, &new_worker, &new_agent, &two),
    ] {
        assert_eq!(
            &host.worker_process(session),
            worker,
            "the worker of the session started under {} is the process it was",
            release.name()
        );
        assert_eq!(
            host.worker_build(session).await,
            format!("kr-worker/{}", release.name())
        );
        assert_eq!(
            kr_ipc::identity::process_state(&agent.identity),
            kr_ipc::identity::ProcessState::Running,
            "the agent in the shell of the session started under {} runs on",
            release.name()
        );
    }
    let (_, versions) = host.kr_json(&["host", "versions", "--json"]);
    let state_of = |name: &ReleaseName| {
        versions["releases"]
            .as_array()
            .and_then(|releases| {
                releases
                    .iter()
                    .find(|kept| kept["release"] == name.as_str())
            })
            .cloned()
            .unwrap_or(Value::Null)
    };
    assert_eq!(state_of(one.name())["current"], true, "{versions}");
    assert_eq!(state_of(two.name())["previous"], true, "{versions}");
    assert_eq!(
        state_of(two.name())["held"],
        true,
        "the session started under the release left holds it: {versions}"
    );

    // A session started now runs the older release again.
    let (display, session_id) = host.new_session(&host.store.stable(Program::Kr));
    assert_eq!(
        host.worker_build(session_id).await,
        format!("kr-worker/{}", one.name())
    );
    for display in [&display, &old_display, &new_display] {
        host.close(&host.store.stable(Program::Kr), display);
    }
}

/// KR-REQ-26.10: a rollback brings no registry forward. An environment whose daemon has not run since
/// a schema before this release's has a registry the older release can read as it is, and a rollback
/// that migrated it to this release's schema would put it beyond that release. It is left as the file
/// it was, with nothing made beside it, and the rollback says it carried nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_leaves_a_registry_behind_this_release_s_schema_as_it_is() {
    let (host, one, two, archive) = host_to_update().await;
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let idle = Idle::new(&host.store).shaped_as(6);
    let before = idle.records();
    assert_eq!(idle.version(), 6);

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["target"], one.name().as_str(), "{said}");
    assert_eq!(said["carried"], serde_json::json!([]), "{said}");
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    assert_eq!(idle.version(), 6, "the registry was not brought forward");
    assert_eq!(idle.records(), before, "and what it records is as it was");
    assert!(
        idle.sidecars().is_empty(),
        "and nothing is left beside it: {:?}",
        idle.sidecars()
    );
    let _ = two;
}

/// KR-REQ-26.10: a rollback classes the records of a registry that is behind this release's schema
/// all the same, from a copy it brings forward: a worker the registry names that does not answer and
/// has not ended holds the rollback, as it holds an update, and the registry is left as it was.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_classes_a_registry_behind_this_release_s_schema_without_changing_it() {
    let (host, one, two, archive) = host_to_update().await;
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let idle = Idle::new(&host.store)
        .with_a_worker_that_holds_the_update()
        .shaped_as(6);
    let before = idle.records();

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("did not answer its challenge and has not ended"),
        "{said}"
    );
    assert_eq!(idle.version(), 6, "the registry was not brought forward");
    assert_eq!(idle.records(), before, "and what it records is as it was");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone()),
        "nothing was switched"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the daemon the rollback stopped serves again"
    );
    let _ = one;
}

/// KR-REQ-26.10: a rollback is refused, naming the store, when a store as it stands is at a version
/// the older release does not read, and nothing is switched: the registry a daemon of this build
/// wrote is at this build's schema version, and a release that reads the one before cannot take it.
/// The daemon the rollback stopped serves again from the release still current.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_is_refused_naming_a_store_the_older_release_cannot_read() {
    let mut host = Host::bare();
    let older = registry_version() - 1;
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1)
        .reading(reading_the_registry_at(1, older));
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let registry = host.tree.environment().registry_database();
    let recorded = |path: &Path| -> i64 {
        rusqlite::Connection::open(path)
            .expect("opens")
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .expect("reads")
    };
    assert_eq!(
        recorded(&registry),
        i64::from(registry_version()),
        "the daemon of this build wrote the registry at this build's version"
    );

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("registry")
            && message.contains(&host.tree.environment_id().to_string())
            && message.contains(&format!("schema version {}", registry_version()))
            && message.contains(&format!("versions 1 to {older}")),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone()),
        "nothing was switched"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the daemon the rollback stopped serves again, from the release still current"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], one.name().as_str(), "{record}");
    assert_eq!(
        recorded(&registry),
        i64::from(registry_version()),
        "the registry was left as it was"
    );
}

/// KR-REQ-26.10: an update is held to the same rule, forward: a release that reads a version of the
/// registry above the one a host's registry is at, and one that migrates from a version above it,
/// are both refused naming the store, with nothing switched.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_is_refused_naming_a_store_the_new_release_cannot_read() {
    let (host, one, _two, _archive) = host_to_update().await;
    let beyond = registry_version() + 1;
    let scratch = host.scratch("archives");
    // A release that reads only versions the registry has not reached.
    let ahead = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2)
        .reading(reading_the_registry_at(beyond, beyond));
    let archive = scratch.join("ahead.tar.gz");
    ahead.archive(&archive);

    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("registry")
            && message.contains(&format!("schema version {}", registry_version()))
            && message.contains(&format!("versions {beyond} to {beyond}")),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone()),
        "nothing was switched"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon the update stopped serves again"
    );
}

/// KR-REQ-26.10: a release that lists a store by a scope or a way of recording its version that
/// this build does not know cannot be checked against, so the switch is refused naming the store
/// before anything is surveyed or stopped: no update is recorded as begun and the daemon keeps
/// serving.
#[tokio::test(flavor = "multi_thread")]
async fn a_store_listed_in_a_way_this_kr_does_not_know_refuses_the_switch_before_anything_stops() {
    let (mut host, one, _two, _archive) = host_to_update().await;
    let mut stores = release_stores();
    stores.push(ReleaseStore {
        store: "ledgers".to_owned(),
        scope: StoreScope::Unknown,
        path: "ledgers.sqlite".to_owned(),
        recording: Recording::SqliteUserVersion,
        version: 1,
        migrates_from: 1,
    });
    stores.push(ReleaseStore {
        store: "journals".to_owned(),
        scope: StoreScope::Environment,
        path: "journals.sqlite".to_owned(),
        recording: Recording::Unknown,
        version: 1,
        migrates_from: 1,
    });
    let target = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).reading(stores);
    let archive = host.scratch("archives").join("newer-kinds.tar.gz");
    target.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("ledgers") && message.contains("a scope this kr does not know"),
        "the store of an unknown scope is named: {said}"
    );
    assert!(
        message.contains("journals")
            && message.contains("a way of recording its version this kr does not know"),
        "the store of an unknown recording is named: {said}"
    );
    assert!(
        host.record()["update"].is_null(),
        "no update began: {}",
        host.record()
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert!(
        host.daemons
            .iter_mut()
            .all(|daemon| matches!(daemon.try_wait(), Ok(None))),
        "the daemon this test started was never stopped"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
}

/// KR-REQ-26.10: a store of a host's that is too old for the release switched to is named as well,
/// and so is a store whose version cannot be read: an environment whose transfer journal is at
/// version 1 against a release that migrates from 2, and one whose record of enrolments is not
/// JSON. The control, in the same environment, is the store that is in range, which is not named.
#[tokio::test(flavor = "multi_thread")]
async fn a_store_too_old_or_unreadable_is_named_and_a_store_in_range_is_not() {
    let (host, one, _two, _archive) = host_to_update().await;
    let idle = Idle::new(&host.store);
    let environment = idle.temp.environment();
    let transfers = kr_transfer::staging::StagingArea::store_path(&environment);
    std::fs::create_dir_all(transfers.parent().expect("a directory")).expect("transfers/");
    drop(
        kr_transfer::store::Store::open(&transfers, idle.temp.environment_id())
            .expect("a transfer journal"),
    );
    rusqlite::Connection::open(&transfers)
        .expect("opens")
        .execute("UPDATE schema_version SET version = 1", [])
        .expect("an earlier version, which the check reads and nothing else");
    std::fs::write(
        environment.state_dir().join("environments.json"),
        b"{ not JSON",
    )
    .expect("a record that is not JSON");

    // The release reads transfer journals from version 2, and the record of enrolments as a JSON
    // object that states its version.
    let stores: Vec<ReleaseStore> = release_stores()
        .into_iter()
        .map(|store| match store.store.as_str() {
            "transfers" => ReleaseStore {
                migrates_from: 2,
                ..store
            },
            _ => store,
        })
        .collect();
    assert!(
        stores.iter().any(|store| store.store == "environments"),
        "the release lists the record of enrolments"
    );
    let target = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).reading(stores);
    let archive = host.scratch("archives").join("target.tar.gz");
    target.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    let named = idle.environment_id();
    assert!(
        message.contains(&format!("transfers of environment {named}"))
            && message.contains("schema version 1")
            && message.contains(&format!(
                "versions 2 to {}",
                kr_transfer::store::SCHEMA_VERSION
            )),
        "the journal that is too old is named: {said}"
    );
    assert!(
        message.contains(&format!("environments of environment {named}"))
            && message.contains("environments.json cannot be read"),
        "the record that cannot be read is named: {said}"
    );
    assert!(
        !message.contains(&format!("registry of environment {named}")),
        "the registry is at a version the release reads, so it is not named: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone()),
        "nothing was switched"
    );
}

/// KR-REQ-26.10, KR-REQ-26.08: a rollback waits, exit 9, for a live session whose level the older
/// release's daemon does not retain, as an update does, with nothing stopped.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_waits_for_a_session_the_older_release_does_not_retain() {
    let mut host = Host::bare();
    let another = if PACKAGE_VERSION.major == 0 {
        PackageVersion::new(0, PACKAGE_VERSION.minor + 1, 0)
    } else {
        PackageVersion::new(PACKAGE_VERSION.major + 1, 0, 0)
    };
    let one = Assembled::new(
        "0.1.0+aaaaaaaaaaaa",
        1,
        CompatibilityLevel::of(another),
        the_root(),
    );
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (display, _) = host.new_session(&host.store.stable(Program::Kr));

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "a rollback that waits exits 9: {said}"
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(one.name().as_str())
            && message.contains(&format!("session {display} runs kr-worker/{}", two.name())),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "nothing was stopped"
    );
    host.close(&host.store.stable(Program::Kr), &display);
}

/// KR-REQ-26.10: a rollback needs a release to go back to, and it is refused, usage, when there is
/// none recorded, when the one named is not in the store, when it is not older than the current
/// release, and when it is the current release.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_needs_an_older_release_in_the_store() {
    let (host, one, two, archive) = host_to_update().await;
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "no earlier release is recorded: {said}"
    );
    let (output, said) =
        host.kr_json(&["host", "rollback", "--to", "0.9.0+eeeeeeeeeeee", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a release the store does not keep: {said}"
    );
    let (output, said) = host.kr_json(&["host", "rollback", "--to", "not a release", "--json"]);
    assert_eq!(output.status.code(), Some(2), "not a release name: {said}");
    let (output, said) = host.kr_json(&["host", "rollback", "--to", one.name().as_str(), "--json"]);
    assert_eq!(output.status.code(), Some(2), "the current release: {said}");
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(output.status.success(), "{said}");
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(output.status.success(), "{said}");
    // Now the newer release is the one recorded as before the last switch, and it is not older.
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a rollback does not go forward: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    let _ = two;
}

/// KR-REQ-26.10: going back does not bring back a key the channel retired. Release two carries the
/// next version of the channel's root, which names a new targets key in place of the first. An
/// update that waits trusts nothing it has not switched to, so it can be run again once what held
/// it has gone; once the host has switched to release two, a rollback to release one, whose own
/// root is the first, still trusts the second: an archive signed with the retired key is refused
/// and one signed with the new key is taken. The archive release two came in, which only the retired
/// key signed, is refused too.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_does_not_bring_back_a_key_the_channel_retired() {
    let mut host = Host::bare();
    let rotated = channel_root_naming(2, &keys().root, &keys().next_targets, &[&keys().root]);
    let another = if PACKAGE_VERSION.major == 0 {
        PackageVersion::new(0, PACKAGE_VERSION.minor + 1, 0)
    } else {
        PackageVersion::new(PACKAGE_VERSION.major + 1, 0, 0)
    };
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    // It retains another level than the session below runs at, so its update waits for the session.
    let two = Assembled::new(
        "0.2.0+bbbbbbbbbbbb",
        2,
        CompatibilityLevel::of(another),
        &rotated,
    );
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let (display, session) = host.new_session(&host.store.stable(Program::Kr));
    let session_worker = host.worker_process(session);
    let scratch = host.scratch("archives");
    let archive_two = scratch.join("two.tar.gz");
    two.archive(&archive_two);
    let update = |archive: &Path| {
        host.kr_json(&[
            "host",
            "update",
            "--archive",
            &archive.display().to_string(),
            "--json",
        ])
    };

    let (output, said) = update(&archive_two);
    assert_eq!(
        output.status.code(),
        Some(9),
        "waits for the session: {said}"
    );
    assert!(
        host.record()["trusted_root"].is_null(),
        "an update that waits has switched to nothing, so it trusts nothing new: {}",
        host.record()
    );
    host.close(&host.store.stable(Program::Kr), &display);
    host.worker_ended(&session_worker).await;
    // The session has gone; the same archive is taken now, though its manifest is signed by the key
    // the first root names and the root it carries names another.
    let (output, said) = update(&archive_two);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.record()["trusted_root"]["signed"]["version"],
        2,
        "the switch settled, so the host trusts the second root: {}",
        host.record()
    );

    // The root the host recorded is damaged: a rollback would settle on the older root of the
    // release it goes back to, and so it is refused before anything is switched.
    let kept = std::fs::read(host.store.record()).expect("the record");
    let mut damaged: Value = serde_json::from_slice(&kept).expect("JSON");
    for signature in damaged["trusted_root"]["signatures"]
        .as_array_mut()
        .expect("the recorded root is signed")
    {
        let sig = signature["sig"].as_str().expect("a signature").to_owned();
        let first = if sig.starts_with('0') { '1' } else { '0' };
        signature["sig"] = Value::String(format!("{first}{}", &sig[1..]));
    }
    std::fs::write(host.store.record(), damaged.to_string()).expect("damaged");
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a root the host cannot establish stops the rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("this host kept is not signed by the root keys it names"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone()),
        "nothing was switched"
    );
    assert!(
        host.record()["update"].is_null(),
        "and no update is left recorded: {}",
        host.record()
    );
    std::fs::write(host.store.record(), &kept).expect("restored");

    // The root of the release to go back to is damaged: refused before anything is switched too.
    {
        use std::os::unix::fs::PermissionsExt as _;

        let root_file = host
            .store
            .release_directory(one.name())
            .join("share")
            .join("update-root.json");
        let share = root_file.parent().expect("a directory");
        let (file_mode, directory_mode) = (
            std::fs::metadata(&root_file)
                .expect("the root")
                .permissions(),
            std::fs::metadata(share)
                .expect("the directory")
                .permissions(),
        );
        let original = std::fs::read(&root_file).expect("the root");
        std::fs::set_permissions(share, std::fs::Permissions::from_mode(0o755)).expect("opened");
        std::fs::set_permissions(&root_file, std::fs::Permissions::from_mode(0o644))
            .expect("opened");
        std::fs::write(&root_file, b"{ not a root").expect("damaged");
        let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "a root of the target that cannot be read stops the rollback: {said} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            said["message"]
                .as_str()
                .unwrap_or_default()
                .contains("update channel's root"),
            "{said}"
        );
        assert_eq!(
            host.store.current().expect("reads"),
            Some(two.name().clone()),
            "nothing was switched"
        );
        assert!(host.record()["update"].is_null(), "{}", host.record());
        std::fs::write(&root_file, &original).expect("restored");
        std::fs::set_permissions(&root_file, file_mode).expect("closed");
        std::fs::set_permissions(share, directory_mode).expect("closed");
    }

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.record()["trusted_root"]["signed"]["version"],
        2,
        "going back does not give the second root up"
    );

    // The release just left comes in an archive only the retired key signed, so it is not taken
    // again from that archive.
    let (output, said) = update(&archive_two);
    assert_eq!(
        output.status.code(),
        Some(1),
        "the archive of the release left is signed by the retired key and is refused: {said}"
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not signed by the release keys"),
        "and it is refused for the signature: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );

    // A later release of the second root, signed with the key that root retired: refused.
    let three = Assembled::new(
        "0.3.0+cccccccccccc",
        3,
        CompatibilityLevel::of(PACKAGE_VERSION),
        &rotated,
    );
    let with_retired_key = scratch.join("three-retired.tar.gz");
    three.archive_signed(&with_retired_key, &keys().targets);
    let (output, said) = update(&with_retired_key);
    assert_eq!(
        output.status.code(),
        Some(1),
        "an archive signed with the retired key is refused: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    // The control: the same release signed with the key the second root names is taken.
    let with_new_key = scratch.join("three-new.tar.gz");
    three.archive_signed(&with_new_key, &keys().next_targets);
    let (output, said) = update(&with_new_key);
    assert!(
        output.status.success(),
        "an archive signed with the new key is taken: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(three.name().clone())
    );
}

/// KR-REQ-26.10: a switch an earlier run left after it happened settles on the root that run decided
/// on before it began, and reads no release to do so. An update to release two, which carries the
/// second root, switches and then stops because its daemon does not start; the transaction it
/// leaves holds the second root, and the root file of release two is gone when the next run settles
/// it. A rollback then goes on, and the host still trusts the second root: going back did not give
/// up the trust the switch earned, and the key the second root retired stays retired.
#[tokio::test(flavor = "multi_thread")]
async fn a_switch_left_after_it_happened_settles_on_the_root_decided_before_it() {
    use std::os::unix::fs::PermissionsExt as _;

    let mut host = Host::bare();
    let rotated = channel_root_naming(2, &keys().root, &keys().next_targets, &[&keys().root]);
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::new(
        "0.2.0+bbbbbbbbbbbb",
        2,
        CompatibilityLevel::of(PACKAGE_VERSION),
        &rotated,
    );
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);

    let (output, said) = host.update_whose_daemons_fail(&archive.display().to_string());
    assert_eq!(
        output.status.code(),
        Some(1),
        "the daemon does not start from the new release: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let record = host.record();
    assert_eq!(record["update"]["state"], "switched", "{record}");
    assert_eq!(
        record["update"]["trusted_root"]["signed"]["version"], 2,
        "the transaction holds the root decided before the switch: {record}"
    );
    assert!(
        record["trusted_root"].is_null(),
        "and nothing is trusted on it yet: {record}"
    );
    // Release two's own copy of that root is gone by the time the next run settles it.
    let share = host.store.release_directory(two.name()).join("share");
    std::fs::set_permissions(&share, std::fs::Permissions::from_mode(0o755)).expect("opened");
    let root_file = share.join("update-root.json");
    std::fs::set_permissions(&root_file, std::fs::Permissions::from_mode(0o644)).expect("opened");
    std::fs::remove_file(&root_file).expect("removed");

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], two.name().as_str(), "{record}");
    assert_eq!(
        record["trusted_root"]["signed"]["version"], 2,
        "the second root is the root the host trusts: {record}"
    );
}

/// KR-REQ-26.10: a rollback to a release whose update channel root has the version of the root the
/// host trusts and is another document is refused: the host trusts neither, nothing is switched or
/// recorded, and the root it recorded stays what it was. The control, in the same store, is the
/// rollback to a release whose root is the first, which goes back.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_to_a_release_with_another_root_of_the_trusted_version_is_refused() {
    let mut host = Host::bare();
    let level = CompatibilityLevel::of(PACKAGE_VERSION);
    let trusted = channel_root_naming(2, &keys().root, &keys().next_targets, &[&keys().root]);
    let other = channel_root_naming(2, &keys().root, &keys().targets, &[&keys().root]);
    assert_ne!(trusted, other, "two roots of one version that differ");
    let one = Assembled::new("0.2.0+aaaaaaaaaaaa", 2, level, the_root());
    let elder = Assembled::new("0.1.0+eeeeeeeeeeee", 1, level, &other);
    let two = Assembled::new("0.3.0+bbbbbbbbbbbb", 3, level, &trusted);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let before = host.record();
    assert_eq!(before["trusted_root"]["signed"]["version"], 2, "{before}");
    // An older release, put in the store now that the update has collected what nothing needs,
    // whose root is another document of the version the host trusts.
    host.put(&elder);

    let (output, said) =
        host.kr_json(&["host", "rollback", "--to", elder.name().as_str(), "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("trusts neither"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone()),
        "nothing was switched"
    );
    let after = host.record();
    assert!(after["update"].is_null(), "{after}");
    assert_eq!(
        after["trusted_root"], before["trusted_root"],
        "and the root the host trusts is what it was"
    );

    // The control: the release before it, whose root is the first, goes back.
    let (output, said) = host.kr_json(&["host", "rollback", "--to", one.name().as_str(), "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// KR-REQ-26.10: `kr host terminal --clear` changes the saved preference while holding it, as the
/// daemon's stamping of its format does, and an environment that has no state directory yet has
/// nothing to clear and needs none held: with the preference held by another change the command is
/// refused and leaves the file; once it is let go the command clears it.
#[tokio::test(flavor = "multi_thread")]
async fn kr_host_terminal_clear_holds_the_preference_and_needs_no_directory_that_is_not_there() {
    use kr_shell_integration::host::terminal::{
        PREFERENCE_FILE, hold_preference, preference_document,
    };

    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let clear = |host: &Host| host.kr_json(&["host", "terminal", "--clear", "--json"]);
    let state_dir = host.tree.environment().state_dir().to_path_buf();
    std::fs::remove_dir_all(&state_dir).expect("an environment with no state directory yet");
    let (output, said) = clear(&host);
    assert!(
        output.status.success(),
        "an environment that has not run has nothing to clear: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let file = state_dir.join(PREFERENCE_FILE);
    kr_ipc::paths::write_owner_only_file(&file, preference_document("iterm2").as_bytes())
        .expect("a preference");
    let held = hold_preference(&state_dir).expect("held");
    let (output, said) = clear(&host);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a change of the preference waits for the one under way and is refused: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("could not hold"),
        "{said}"
    );
    assert!(file.exists(), "and the preference is left");
    drop(held);
    let (output, said) = clear(&host);
    assert!(
        output.status.success(),
        "kr host terminal --clear: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !file.exists(),
        "and once it is let go the command clears it"
    );
}

/// A named pipe left at the saved terminal preference's name does not hold `kr host terminal`: the
/// preference is read as a regular file only, and a pipe reads as no preference. A program that read
/// it would wait for a writer for ever.
#[tokio::test(flavor = "multi_thread")]
async fn a_pipe_where_the_saved_terminal_preference_belongs_does_not_hold_kr() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let pipe = host
        .tree
        .environment()
        .state_dir()
        .join(kr_shell_integration::host::terminal::PREFERENCE_FILE);
    let made = Command::new("mkfifo")
        .arg(&pipe)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "a pipe is made");
    let child = host
        .command(
            &host.store.stable(Program::Kr),
            &["host", "terminal", "--json"],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kr runs");
    // Ended by the test and not left waiting, so that a kr which does wait fails this case.
    let output = finish_within(child, Duration::from_secs(30));
    let said: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    assert!(
        output.status.success(),
        "kr host terminal: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["preferred"].is_null(),
        "a pipe is no preference: {said}"
    );
}

/* -------------------------------------------------------------------------------------------- */
/* The variables a daemon started again keeps                                                    */
/* -------------------------------------------------------------------------------------------- */

/// The value a daemon says it has for a variable that decides its paths: `None` where it has none.
fn variable_of(
    started: &kr_protocol::update::HostUpdateHandoverResult,
    name: &str,
) -> Option<String> {
    let found = started
        .environment
        .iter()
        .find(|variable| variable.name == name)
        .unwrap_or_else(|| panic!("the daemon states {name}"));
    found.value.0.clone()
}

/// KR-REQ-26.10: a daemon an update, a rollback or the undo of a refused switch starts again has the
/// variables that decide its paths that the daemon it replaces had, and none that the command which
/// starts it has and the daemon did not: it keeps what it keeps where its predecessor did. What it
/// states of itself is what it has, so this asks the restarted daemon and compares.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_started_again_has_the_variables_that_decide_its_paths_the_one_before_had() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let daemon_home = host.scratch("daemon-home");
    let daemon_config = host.scratch("daemon-config");
    let updater_home = host.scratch("updater-home");
    let updater_run = host.scratch("updater-run");
    let controller = host.store.stable(Program::Controller);
    // The daemon has a home and a configuration home of its own, and an empty state home, which is
    // not the same as none; the commands that start it again have another home, a runtime
    // directory the daemon never had, and no configuration home.
    host.start_daemon_with(
        &controller,
        &[
            ("HOME", daemon_home.as_os_str()),
            ("XDG_CONFIG_HOME", daemon_config.as_os_str()),
            ("XDG_STATE_HOME", std::ffi::OsStr::new("")),
        ],
        &[],
    )
    .await;
    let updater = [
        ("HOME", updater_home.as_os_str()),
        ("XDG_RUNTIME_DIR", updater_run.as_os_str()),
    ];
    let before = host.daemon_started_like().await;
    assert_eq!(
        variable_of(&before, "XDG_CONFIG_HOME").as_deref(),
        daemon_config.to_str(),
        "the daemon states the variables it was given"
    );
    assert_eq!(variable_of(&before, "XDG_STATE_HOME").as_deref(), Some(""));
    assert_eq!(variable_of(&before, "XDG_RUNTIME_DIR"), None);

    let scratch = host.scratch("archives");
    let archive_two = scratch.join("two.tar.gz");
    two.archive(&archive_two);
    let (output, said) = host.kr_json_with(
        &updater,
        &[
            "host",
            "update",
            "--archive",
            &archive_two.display().to_string(),
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
    let after_update = host.daemon_started_like().await;
    assert_eq!(
        after_update.environment, before.environment,
        "after the update"
    );
    assert_eq!(
        after_update.configuration_directory, before.configuration_directory,
        "after the update"
    );

    let (output, said) = host.kr_json_with(&updater, &["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    let after_rollback = host.daemon_started_like().await;
    assert_eq!(
        after_rollback.environment, before.environment,
        "after the rollback"
    );

    // A switch the stores refuse stops the daemon and starts it again from the release still
    // current, which is the same restart.
    let beyond = registry_version() + 1;
    let ahead = Assembled::at_this_level("0.3.0+cccccccccccc", 3)
        .reading(reading_the_registry_at(beyond, beyond));
    let archive_ahead = scratch.join("ahead.tar.gz");
    ahead.archive(&archive_ahead);
    let (output, said) = host.kr_json_with(
        &updater,
        &[
            "host",
            "update",
            "--archive",
            &archive_ahead.display().to_string(),
            "--json",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    let after_refusal = host.daemon_started_like().await;
    assert_eq!(
        after_refusal.environment, before.environment,
        "after the refused switch"
    );
}

/// KR-REQ-26.10: a daemon that cannot say which values of the variables that decide its paths it
/// has, because one is not text, is not prepared to make way: it cannot be started again like itself.
/// Its gate is not closed by the attempt.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_with_a_path_variable_that_is_not_text_is_not_prepared() {
    use std::os::unix::ffi::OsStrExt as _;

    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    let not_text = std::ffi::OsStr::from_bytes(b"/home/\xff");
    host.start_daemon_with(&controller, &[("HOME", not_text)], &[])
        .await;
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    let refused = handover_step(
        &host,
        &mut client,
        HandoverStep::Prepare,
        None,
        &release("0.2.0+bbbbbbbbbbbb"),
    )
    .await
    .expect_err("a daemon that cannot say its variables does not prepare");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::InvalidArgument,
        "{refused:?}"
    );
    assert!(refused.message.contains("HOME"), "{}", refused.message);
    // The gate was not closed: a session is created.
    let kr = host.store.stable(Program::Kr);
    let (display, _) = host.new_session(&kr);
    host.close(&kr, &display);
}

/// What a default install on Linux gives a daemon of its own: a home, a configuration home and a state
/// home that is the directory the tree's state root is in, and nothing that names the state root.
#[cfg(all(unix, not(target_os = "macos")))]
async fn a_daemon_that_finds_its_document_under_its_own_configuration_home()
-> (Host, Assembled, PathBuf) {
    let mut host = Host::bare_as_a_default_install();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let daemon_home = host.scratch("daemon-home");
    let daemon_config = host.scratch("daemon-config");
    let controller = host.store.stable(Program::Controller);
    let state_home = host.tree.root().to_path_buf();
    host.start_daemon_with(
        &controller,
        &[
            ("HOME", daemon_home.as_os_str()),
            ("XDG_CONFIG_HOME", daemon_config.as_os_str()),
            ("XDG_STATE_HOME", state_home.as_os_str()),
        ],
        &["KR_STATE_DIR", "KR_RUNTIME_DIR"],
    )
    .await;
    let document = daemon_config
        .join("kalareach")
        .join("environments")
        .join(kr_ipc::paths::short_prefix(host.tree.environment_id()))
        .join("config.json");
    std::fs::create_dir_all(document.parent().expect("a directory")).expect("the directory");
    // The daemon resolves its document from its own variables, under its own configuration home,
    // and not beside the rest of its state, where the commands that update it look first.
    let started = host.daemon_started_like().await;
    assert_eq!(
        started.configuration_directory.0.as_deref(),
        document.parent().and_then(Path::to_str),
        "the daemon states where it reads its document"
    );
    (host, one, document)
}

/// KR-REQ-26.10: a daemon that reads its configuration document under a configuration home of its
/// own is checked like any other: the document it published is looked at, and a switch to a release
/// that cannot read that document is refused naming it, where this command's own environment finds
/// nothing there. The places this command's environment gives are looked at too, so a document a
/// daemon started later from there would read is not passed over because the daemon in front of
/// the update read another.
#[cfg(all(unix, not(target_os = "macos")))]
#[tokio::test(flavor = "multi_thread")]
async fn a_document_a_daemon_reads_under_its_own_configuration_home_is_checked() {
    let (host, one, document) =
        a_daemon_that_finds_its_document_under_its_own_configuration_home().await;
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();
    let update = || host.kr_json(&["host", "update", "--archive", &archive, "--json"]);

    // The daemon's document is at a version the release cannot read.
    std::fs::write(&document, br#"{"version": 99}"#).expect("a document");
    let (output, said) = update();
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&document.display().to_string()) && message.contains("records version 99"),
        "the document the daemon reads is named: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );

    // The daemon's document is one the release reads, and the document where this command's
    // environment puts it is not: that one is refused too.
    std::fs::write(&document, br#"{"version": 1}"#).expect("a document");
    let beside = host.tree.environment().state_dir().join("config.json");
    std::fs::write(&beside, br#"{"version": 99}"#).expect("a document");
    let (output, said) = update();
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&beside.display().to_string()),
        "the document beside the daemon's state is named: {said}"
    );

    // The control: with both in range the update goes ahead.
    std::fs::remove_file(&beside).expect("removed");
    let (output, said) = update();
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
}

/// KR-REQ-26.10: a daemon is started again as its own document chose, and not as the document of the
/// environment of the command that starts it: this command's environment chooses the service start
/// and finds no service definition, and the daemon in front of the update was started by hand and reads
/// a document of its own that chooses nothing, so it is started again as it was.
#[cfg(all(unix, not(target_os = "macos")))]
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_is_started_again_as_its_own_document_chose() {
    let (host, _one, document) =
        a_daemon_that_finds_its_document_under_its_own_configuration_home().await;
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    std::fs::write(&document, br#"{"version": 1}"#).expect("a document");
    std::fs::write(
        host.tree.environment().state_dir().join("config.json"),
        br#"{"version": 1, "revision": 1, "startup": {"controller": "service"}}"#,
    )
    .expect("a document that chooses the service start");
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
}

/* -------------------------------------------------------------------------------------------- */
/* The stored formats                                                                            */
/* -------------------------------------------------------------------------------------------- */

/// A host whose daemon has run: a session created and closed, and the daemon stopped through its own
/// door, so that what it kept is on disk as a stopped daemon leaves it.
async fn a_host_whose_daemon_has_run() -> Host {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let (display, session) = host.new_session(&host.store.stable(Program::Kr));
    let worker = host.worker_process(session);
    host.close(&host.store.stable(Program::Kr), &display);
    host.worker_ended(&worker).await;
    assert!(
        host.stop_the_daemon().await,
        "the daemon is stopped through its own door"
    );
    host
}

/// What this build says of every store, with the definitions of each database as the daemon's files
/// hold them.
fn observed_stores(host: &Host) -> Vec<stored_formats::Observed> {
    let environment = host.tree.environment();
    stored_formats::table::table()
        .iter()
        .map(|store| {
            let ddl = match store.entry.recording {
                Recording::SqliteTable { .. } | Recording::SqliteUserVersion => {
                    let file = environment.state_dir().join(&store.entry.path);
                    assert!(
                        file.is_file(),
                        "the daemon made the store {} at {}",
                        store.entry.store,
                        file.display()
                    );
                    stored_formats::ddl_of(&file).expect("the database's definitions")
                }
                _ => Vec::new(),
            };
            stored_formats::observe(store, &ddl).expect("what the store keeps is read")
        })
        .collect()
}

/// KR-REQ-26.10, KR-REQ-24.30: every store has a format version, and `stored-formats.lock` maps each
/// to the version the code writes and a digest of what the version stands for: the tables a real
/// daemon made, the types it keeps and the words it matches by hand. A change to any of them moves
/// the digest, and this fails until the version has been raised and the lock written.
#[tokio::test(flavor = "multi_thread")]
async fn the_lock_names_every_store_at_the_version_and_digest_the_code_has() {
    let host = a_host_whose_daemon_has_run().await;
    let found = stored_formats::findings(
        &stored_formats::Lock::committed(),
        &observed_stores(&host),
        &stored_formats::table::named(),
    );
    assert!(
        found.is_empty(),
        "stored-formats.lock does not match the code:\n{}",
        found.join("\n")
    );
}

/// KR-REQ-26.10: a state root's files are all named. After a daemon has run and a session has been
/// made and closed, every entry of the state root and of the environment's directory is a store's or
/// is named in the lock with the reason it has no version, and a file that nothing names is found,
/// whether it is beside the stores or inside a directory a store owns.
#[tokio::test(flavor = "multi_thread")]
async fn no_file_of_a_state_root_goes_unnamed() {
    let host = a_host_whose_daemon_has_run().await;
    let table = stored_formats::table::table();
    let named = stored_formats::table::named();
    let root = host.tree.paths().state_root().to_path_buf();
    let unnamed = stored_formats::unnamed(&root, &table, &named);
    assert!(unnamed.is_empty(), "named by nothing: {unnamed:?}");

    let environment = host.tree.environment();
    let prefix = format!(
        "environments/{}",
        kr_ipc::paths::short_prefix(host.tree.environment_id())
    );
    std::fs::write(environment.state_dir().join("stray"), b"nothing names this").expect("a file");
    std::fs::write(
        environment
            .state_dir()
            .join("changesets")
            .join("stray.record"),
        b"nor this",
    )
    .expect("a file in a directory a store owns");
    std::fs::copy(
        environment.registry_database(),
        environment
            .state_dir()
            .join("projects")
            .join("another.sqlite"),
    )
    .expect("a database beside a store's");
    std::fs::create_dir_all(environment.state_dir().join("agent-tools").join("actions"))
        .expect("the directory of retained actions");
    std::fs::write(
        environment
            .state_dir()
            .join("agent-tools")
            .join("actions")
            .join("stray.record"),
        b"nor this",
    )
    .expect("a file in a directory two below a store's");
    let unnamed = stored_formats::unnamed(&root, &table, &named);
    for expected in [
        format!("{prefix}/stray"),
        format!("{prefix}/changesets/stray.record"),
        format!("{prefix}/projects/another.sqlite"),
        format!("{prefix}/agent-tools/actions/stray.record"),
    ] {
        assert!(
            unnamed.contains(&expected),
            "{expected} is found: {unnamed:?}"
        );
    }
    assert_eq!(unnamed.len(), 4, "and nothing else: {unnamed:?}");
}

/// KR-REQ-26.10: no record a command writes is raised past version 1 while nothing holds a command
/// off between an update's check of the stores and its switch.
///
/// A switch is checked against every version on disk, and a `kr` command that is not held off can
/// write a record after the check and before the switch, or a program of a newer release that a
/// rollback left running can write one after it. Neither can put a record out of the range of the
/// release switched to while every record a command writes is at version 1, which every release
/// reads. Raising such a record's version needs the writer barrier first: every writer of the record
/// takes a lock the update holds exclusively across its check and its switch, and refuses to write a
/// version that the current release does not write.
///
/// Remove this test once all of these hold: the barrier and the rule for a pinned program have
/// landed; a state root names the store that serves it, and a `kr` outside a store takes that
/// store's barrier or refuses to write; the configuration document of an environment with no
/// running daemon is found where its next daemon reads it, or the switch is refused for it; and,
/// for as long as a supported release has no barrier, the `migrates_from` of each record a command
/// writes stays at or below the version that release writes.
#[test]
fn no_record_a_command_writes_is_raised_past_version_one_while_no_barrier_exists() {
    let past: Vec<String> = stored_formats::table::table()
        .into_iter()
        .filter(|store| {
            store.writers == stored_formats::Writers::Commands && store.entry.version != 1
        })
        .map(|store| {
            format!(
                "{} is at version {}",
                store.entry.store, store.entry.version
            )
        })
        .collect();
    assert!(
        past.is_empty(),
        "a record a command writes cannot be raised past version 1 until every writer of it \
         takes the lock an update holds exclusively across its check and its switch: {}",
        past.join("; ")
    );
}

/// Writes `stored-formats.lock` from the code and a daemon's files, refusing a change that would
/// bring the lock past a version that was not raised.
///
/// Run it after raising the version of a store whose tables or values changed:
/// `cargo test -p kr-cli --test update write_the_lock -- --ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes stored-formats.lock"]
async fn write_the_lock() {
    let host = a_host_whose_daemon_has_run().await;
    // A lock that is not there is the first; one that is there and cannot be read is not written
    // over, which would lift the refusals the writer makes against it.
    let committed = match std::fs::read(stored_formats::lock_path()) {
        Ok(bytes) => Some(
            serde_json::from_slice::<stored_formats::Lock>(&bytes)
                .expect("stored-formats.lock is a lock; repair it before it is written again"),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("stored-formats.lock could not be read: {error}"),
    };
    let lock = stored_formats::write(
        committed.as_ref(),
        &observed_stores(&host),
        &stored_formats::table::named(),
    )
    .unwrap_or_else(|refused| panic!("the lock is not written:\n{}", refused.join("\n")));
    std::fs::write(stored_formats::lock_path(), lock.text()).expect("writes the lock");
}

/// KR-REQ-26.10: the check says what to do about each way the code and the lock can differ, and the
/// writer refuses the ways that are a change nobody gave a version to: a digest that moved while the
/// version stood still, a version that went down, a store that is kept somewhere else and a store
/// that is dropped.
#[test]
fn the_lock_check_fails_on_a_moved_digest_and_the_writer_refuses_it() {
    let store = |version: u32, digest: &str, path: &str| stored_formats::Observed {
        entry: ReleaseStore {
            store: "registry".to_owned(),
            scope: StoreScope::Environment,
            path: path.to_owned(),
            recording: Recording::SqliteTable {
                table: "schema_version".to_owned(),
            },
            version,
            migrates_from: 1,
        },
        digest: digest.to_owned(),
        kept: Vec::new(),
    };
    let lock = stored_formats::write(None, &[store(7, "aa", "registry.sqlite")], &[])
        .expect("a first lock is written");
    assert!(
        stored_formats::findings(&lock, &[store(7, "aa", "registry.sqlite")], &[]).is_empty(),
        "the lock matches itself"
    );

    // A name the code gives to a thing under the state root is held to the lock as the stores are:
    // one the lock lacks is found, and so is one whose terms differ.
    let note = stored_formats::Named {
        scope: StoreScope::Environment,
        name: "scratch",
        children: &[],
        opaque: false,
        databases: false,
        reason: "a leftover that holds nothing",
    };
    let registry = [store(7, "aa", "registry.sqlite")];
    assert!(
        !stored_formats::findings(&lock, &registry, &[note]).is_empty(),
        "a name the code has and the lock does not"
    );
    let with_note = stored_formats::write(Some(&lock), &registry, &[note]).expect("is written");
    assert!(stored_formats::findings(&with_note, &registry, &[note]).is_empty());
    for changed in [
        stored_formats::Named {
            databases: true,
            ..note
        },
        stored_formats::Named {
            opaque: true,
            ..note
        },
        stored_formats::Named {
            children: &["a.json"],
            ..note
        },
    ] {
        assert!(
            !stored_formats::findings(&with_note, &registry, &[changed]).is_empty(),
            "a name whose terms moved"
        );
    }

    // The tables or a kept value changed and the version stood still.
    let moved = [store(7, "bb", "registry.sqlite")];
    let found = stored_formats::findings(&lock, &moved, &[]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("registry") && found[0].contains("raise the version"),
        "{found:?}"
    );
    let refused = stored_formats::write(Some(&lock), &moved, &[]).expect_err("is not written");
    assert!(refused[0].contains("raise it first"), "{refused:?}");

    // The version was raised, and the lock is behind; then it is written.
    let raised = [store(8, "bb", "registry.sqlite")];
    let found = stored_formats::findings(&lock, &raised, &[]);
    assert!(found[0].contains("write the lock"), "{found:?}");
    let written = stored_formats::write(Some(&lock), &raised, &[]).expect("is written");
    assert!(stored_formats::findings(&written, &raised, &[]).is_empty());

    // A version that went down, a store kept somewhere else and a store that is dropped are not
    // written either.
    assert!(
        stored_formats::write(Some(&written), &[store(7, "aa", "registry.sqlite")], &[]).is_err()
    );
    assert!(
        stored_formats::write(Some(&written), &[store(8, "bb", "elsewhere.sqlite")], &[]).is_err()
    );
    let dropped =
        stored_formats::write(Some(&written), &[], &[]).expect_err("a dropped store is refused");
    assert!(dropped[0].contains("would leave the lock"), "{dropped:?}");
    // And a store the lock lists that the code does not declare is found.
    assert!(!stored_formats::findings(&written, &[], &[]).is_empty());
}

/// What the digest leaves out and what it keeps: the words of a doc comment, the spacing and the
/// comments of the SQL, and the name of a type move nothing; a column, a property, a word and a
/// quoted default do.
#[test]
fn the_digest_follows_what_a_store_keeps_and_not_how_it_is_written() {
    use stored_formats::{normalise_schema, normalise_sql};

    assert_eq!(
        normalise_sql("CREATE TABLE t (\n  a INTEGER, -- the first\n  b TEXT /* second */\n)"),
        normalise_sql("CREATE TABLE t (a INTEGER,b TEXT)")
    );
    assert_ne!(
        normalise_sql("CREATE TABLE t (a TEXT DEFAULT 'x  y')"),
        normalise_sql("CREATE TABLE t (a TEXT DEFAULT 'x y')"),
        "a quoted default is kept as it is"
    );
    assert_ne!(
        normalise_sql("CREATE TABLE t (a INTEGER)"),
        normalise_sql("CREATE TABLE t (a INTEGER, b TEXT)")
    );

    let schema = |name: &str, doc: &str, property: &str| {
        serde_json::json!({
            "$ref": format!("#/$defs/{name}"),
            "$defs": { name: {
                "description": doc,
                "type": "object",
                "properties": { property: { "type": "string", "description": "a field" } },
            }},
        })
    };
    assert_eq!(
        normalise_schema(&schema("Create", "the first words", "intent")),
        normalise_schema(&schema("Created", "other words", "intent")),
        "neither a doc comment nor the name of a type moves it"
    );
    assert_ne!(
        normalise_schema(&schema("Create", "words", "intent")),
        normalise_schema(&schema("Create", "words", "purpose")),
        "a property does"
    );
    assert_eq!(
        normalise_schema(&schema("Create", "words", "description"))["properties"]["description"]["type"],
        "string",
        "a property that is called description is a property, not prose"
    );
}
