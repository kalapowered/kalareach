// The host and the releases the update suite assembles, which the upgrade suite assembles the same
// way. Included by each suite's root file, which declares `stored_formats`, `support` and `teardown`.

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
use kr_protocol::hello::{PACKAGE_VERSION, PackageVersion, ProtocolVersion};
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

/// How long a wait for something to happen is given. It fails when the thing never happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// The variable that makes a program of a build with debug assertions state a later public major of
/// the protocol on its local links, and list only that major to a device: the way a test makes a
/// release of a later major without one existing.
const LATER_MAJOR_VARIABLE: &str = "KR_TEST_LOCAL_MAJOR";

/// The later major the suites make a program state.
const LATER_MAJOR: u16 = 2;

/// Connects to the daemon at `endpoint` as a client of the release that runs it: of this build's
/// own major, and where the daemon refuses that, of the later major a test made it state.
async fn connect_to_daemon(endpoint: &kr_ipc::paths::Endpoint) -> kr_ipc::Result<LocalClient> {
    match LocalClient::connect(endpoint, LocalClientKind::Cli, build()).await {
        Ok(client) => Ok(client),
        Err(refused) => LocalClient::connect_stating(
            endpoint,
            LocalClientKind::Cli,
            build(),
            ProtocolVersion::new(LATER_MAJOR, 0),
        )
        .await
        .map_err(|_| refused),
    }
}

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

/// A manifest's document, signed by `signer` with the signer a release is built with.
fn signed_document(manifest: &ReleaseManifest, signer: &Ed25519KeyPair) -> String {
    let members = SignedMembers::of(manifest).expect("members");
    // On a thread of its own, since a test that calls this may be inside a runtime already.
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("a runtime")
                    .block_on(kr_release::sign_manifest(&members, &[signer]))
                    .expect("signed")
            })
            .join()
            .expect("the signer finished")
    })
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

/// The root of this checkout.
fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The crate whose sources a program is built from, by the program's name.
fn crate_of(program: &str) -> &str {
    match program {
        "kr-describe-inference" => "kr-describe-model",
        other => other,
    }
}

/// Why `program`, built into a target directory, is not one built from the checkout at `repository`
/// as it is now, or `None` when it is.
///
/// A build of a program by name (`cargo build -p ...`) writes beside it a file that lists each source
/// it was built from. A program older than any of them was built before the tree changed, as one left
/// in a target directory by an earlier run is, and a program whose list names the crate's sources in
/// another checkout was built there: both would be assembled into a release and started, and would
/// write and read what this tree does not. This is Cargo's own rule for a stale build, applied before
/// the suite relies on the program.
///
/// What it does not judge: a program with no such list, or with a list older than the program. A run
/// that builds the programs only to test (`cargo test --workspace`) writes no list, or leaves the
/// one of an earlier build beside a program it has made again, so there is nothing to tell that
/// program by and it is used as it is. It does not see a program copied over a fresh one with a later
/// time, or a build with other features either.
fn built_from_another_tree(program: &Path, name: &str, repository: &Path) -> Option<String> {
    let listing = program.with_file_name(format!("{name}.d"));
    let text = match std::fs::read_to_string(&listing) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            return Some(format!("{} cannot be read: {error}", listing.display()));
        }
    };
    let built = match std::fs::metadata(program).and_then(|about| about.modified()) {
        Ok(built) => built,
        Err(error) => return Some(format!("its time cannot be read: {error}")),
    };
    // A list written before the program was is the list of an earlier build: Cargo writes the list
    // after the program it describes, so the list of the same build is never the older of the two.
    let listed = std::fs::metadata(&listing).and_then(|about| about.modified());
    if listed.is_ok_and(|listed| listed < built) {
        return None;
    }
    // Makefile syntax: the program, a colon, then each source, a space escaped with a backslash.
    let Some((_, after)) = text.split_once(": ") else {
        return Some(format!("{} is not a dependency file", listing.display()));
    };
    let mut sources: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut characters = after.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\\' if characters.peek() == Some(&' ') => {
                current.push(' ');
                characters.next();
            }
            '\\' if characters.peek() == Some(&'\n') => {
                characters.next();
                if !current.is_empty() {
                    sources.push(std::mem::take(&mut current));
                }
            }
            ' ' | '\n' => {
                if !current.is_empty() {
                    sources.push(std::mem::take(&mut current));
                }
            }
            other => current.push(other),
        }
    }
    if !current.is_empty() {
        sources.push(current);
    }
    let own = format!("crates/{}/src/", crate_of(name));
    let here = repository.join(&own);
    let here = std::fs::canonicalize(&here).unwrap_or(here);
    let mut found = false;
    for source in &sources {
        let path = Path::new(source);
        // A source that is listed and cannot be looked at is one the tree no longer has.
        let modified = match std::fs::metadata(path).and_then(|about| about.modified()) {
            Ok(modified) => modified,
            Err(error) => return Some(format!("{source} cannot be looked at: {error}")),
        };
        // A file a crate includes from outside its sources is named through `..` from inside them;
        // it is read as the path it comes to, and is one of the crate's sources only if that is.
        let mut named = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::ParentDir => {
                    named.pop();
                }
                other => named.push(other),
            }
        }
        if named.to_string_lossy().contains(&own) {
            let there = std::fs::canonicalize(&named).unwrap_or(named);
            if !there.starts_with(&here) {
                return Some(format!("it was built from the sources at {source}"));
            }
            found = true;
        }
        if modified > built {
            return Some(format!("{source} has changed since it was built"));
        }
    }
    (!found).then(|| {
        format!(
            "{} lists none of the sources of {}",
            listing.display(),
            crate_of(name)
        )
    })
}

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
            if let Some(why) = built_from_another_tree(&candidate, name, &repository()) {
                panic!(
                    "{} was not built from this tree: {why}; build the programs again with `cargo \
                     build --locked -p kr-controller -p kr-worker -p kr-hook -p kr-plugin-host` and \
                     `cargo build --locked -p kr-describe-model --bin kr-describe-inference`",
                    candidate.display()
                );
            }
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
    /// The programs the release is made of, copied from these files.
    programs: &'static [(&'static str, PathBuf, Digest256, u64)],
    /// Programs of the release written from these bytes in place of the workspace's own, by the name
    /// they have in `bin/`.
    written: Vec<(String, Vec<u8>)>,
}

impl Assembled {
    /// A release of this workspace's programs, retaining `retained`, carrying `root`.
    fn new(name: &str, sequence: u64, retained: CompatibilityLevel, root: &str) -> Self {
        Self::of_programs(
            programs(),
            name,
            sequence,
            (retained, PACKAGE_VERSION),
            root,
        )
    }

    /// A release made of `programs`, at the level and protocol version `level` gives, carrying
    /// `root`: the programs of this workspace, or those of another build of it.
    fn of_programs(
        programs: &'static [(&'static str, PathBuf, Digest256, u64)],
        name: &str,
        sequence: u64,
        level: (CompatibilityLevel, PackageVersion),
        root: &str,
    ) -> Self {
        let (retained, protocol_version) = level;
        let name = release(name);
        let mut files: Vec<ReleaseFile> = programs
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
                protocol_version,
                public_majors: kr_protocol::hello::PUBLIC_MAJORS
                    .iter()
                    .filter(|row| !row.retired)
                    .map(|row| row.major)
                    .collect(),
                retained_levels: vec![retained],
                // Older builds of the upgrade suite require the members a shell entry had before the
                // manifest named its patches, so a release assembled here lists no shell package;
                // its shell packages are the module tree the files list.
                shells: Vec::new(),
                agents: Vec::new(),
                dependencies: kr_protocol::update::ReleaseDependencies {
                    lock_sha256: Digest256::from_bytes([0; 32]),
                    pinned: Vec::new(),
                    vectors: Vec::new(),
                },
                stores: release_stores(),
                files,
            },
            root: root.to_owned(),
            programs,
            written: Vec::new(),
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

    /// This release as one whose table of public majors lists `majors` and no other.
    fn listing_public_majors(mut self, majors: &[u16]) -> Self {
        self.manifest.public_majors = majors.to_vec();
        self
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

    /// This release with the executable `name` in `bin/` written from `contents`, listed in the
    /// manifest by its digest: its own program in place of the workspace's, or one more.
    fn with_program(mut self, name: &str, contents: &[u8]) -> Self {
        let path = ReleasePath::new(format!("bin/{name}")).expect("a path");
        self.manifest.files.retain(|file| file.path != path);
        self.manifest.files.push(ReleaseFile {
            path,
            length: U64::new(contents.len() as u64),
            sha256: Digest256::from_bytes(kr_cbor::sha256(contents)),
            mode: FileMode::Executable,
        });
        self.written.retain(|(known, _)| known != name);
        self.written.push((name.to_owned(), contents.to_vec()));
        self
    }

    /// The bytes of the workspace's own program `name`.
    fn program_bytes(name: &str) -> Vec<u8> {
        let (_, copied, _, _) = programs()
            .iter()
            .find(|(known, ..)| *known == name)
            .expect("a program of the workspace");
        std::fs::read(copied).expect("the program")
    }

    /// This release's control daemon as a program that records each start in `log` and ends with
    /// status 1, apart from `--version`, which it answers like any program of a release, so that a
    /// release whose daemon cannot start can be installed and switched to.
    fn whose_daemon_cannot_start(self, log: &Path) -> Self {
        self.with_program(
            "kr-controller",
            format!(
                "#!/bin/sh\ncase \"$1\" in --version) echo kr-controller; exit 0;; esac\n\
                 echo started >> '{}'\nexit 1\n",
                log.display()
            )
            .as_bytes(),
        )
    }

    /// This release as one whose daemon cannot start where its state directory is `broken`'s, and
    /// is the workspace's own daemon, kept beside as `kr-controller-real`, everywhere else.
    fn whose_daemon_cannot_start_in(self, broken: &Path, log: &Path) -> Self {
        self.with_program("kr-controller-real", &Self::program_bytes("kr-controller"))
            .with_program(
                "kr-controller",
                format!(
                    "#!/bin/sh\ncase \"$1\" in --version) echo kr-controller; exit 0;; esac\n\
                     case \"$*\" in *'{broken}'*) echo started >> '{log}'; exit 1;; esac\n\
                     exec \"$(dirname \"$0\")/kr-controller-real\" \"$@\"\n",
                    broken = broken.display(),
                    log = log.display()
                )
                .as_bytes(),
            )
    }

    /// This release as one whose daemon cannot start while the file `held` exists, recording each
    /// start it refuses in `log`, and is the workspace's own daemon, kept beside as
    /// `kr-controller-real`, when it does not.
    fn whose_daemon_cannot_start_while(self, held: &Path, log: &Path) -> Self {
        self.with_program("kr-controller-real", &Self::program_bytes("kr-controller"))
            .with_program(
                "kr-controller",
                format!(
                    "#!/bin/sh\ncase \"$1\" in --version) echo kr-controller; exit 0;; esac\n\
                     if [ -e '{held}' ]; then echo started >> '{log}'; exit 1; fi\n\
                     exec \"$(dirname \"$0\")/kr-controller-real\" \"$@\"\n",
                    held = held.display(),
                    log = log.display()
                )
                .as_bytes(),
            )
    }

    /// This release as one whose control daemon states the public major `major` on its local links
    /// and lists only that major to a device, wherever the daemon is started from; with `None`, as
    /// one whose daemon states this build's own, even when the program that starts it states a
    /// later major. The workspace's own daemon is kept beside as `kr-controller-real`.
    fn whose_daemon_states(self, major: Option<u16>) -> Self {
        let setting = match major {
            Some(major) => format!("{LATER_MAJOR_VARIABLE}={major}"),
            None => format!("-u {LATER_MAJOR_VARIABLE}"),
        };
        self.with_program("kr-controller-real", &Self::program_bytes("kr-controller"))
            .with_program(
                "kr-controller",
                format!(
                    "#!/bin/sh\ncase \"$1\" in --version) echo kr-controller; exit 0;; esac\n\
                     exec /usr/bin/env {setting} \"$(dirname \"$0\")/kr-controller-real\" \"$@\"\n"
                )
                .as_bytes(),
            )
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
        for (name, copied, _, _) in self.programs {
            // A release assembled without a program lists none and carries none.
            if self.manifest.file(&format!("bin/{name}")).is_some()
                && !self.written.iter().any(|(known, _)| known == name)
            {
                clone_file(copied, &directory.join("bin").join(name));
            }
        }
        for (name, contents) in &self.written {
            use std::os::unix::fs::PermissionsExt as _;

            let file = directory.join("bin").join(name);
            std::fs::write(&file, contents).expect("a program written for the release");
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755))
                .expect("executable");
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

/// The locks an update holds when it switches, held by a test that stands in for the update.
struct StandingIn<'a> {
    host: &'a Host,
    update: kr_ipc::install::StoreLock,
    install: kr_ipc::install::ExclusiveInstall,
    writers: kr_ipc::install::ExclusiveWriters,
}

impl StandingIn<'_> {
    /// Makes a release current under the three locks.
    fn switch(&self, name: &ReleaseName) {
        self.host
            .store
            .switch(name, &self.update, &self.install, &self.writers)
            .expect("switches");
    }
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

/// Whether a daemon answers for the environment of `tree`.
async fn answers_for(tree: &teardown::Tree) -> bool {
    let Ok(endpoint) = tree.environment().controller_endpoint() else {
        return false;
    };
    connect_to_daemon(&endpoint).await.is_ok()
}

/// Hands over and stops whatever daemon serves `tree`'s environment, through its own door, and says
/// whether none is left serving it.
async fn stop_daemon_of(tree: &teardown::Tree) -> bool {
    let environment = tree.environment();
    let Ok(endpoint) = environment.controller_endpoint() else {
        return true;
    };
    if let Ok(mut client) = connect_to_daemon(&endpoint).await {
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
/// is described, ended, and the test fails with the description: the program and its arguments,
/// the programs it started, and what each of their threads waits for.
///
/// What the child prints is read while it runs. A program that writes more than a pipe holds waits
/// for its reader, so a reader that waited for the program to end first would wait for ever, and
/// whether the program wrote that much depends on what it was asked.
fn finish_within(mut child: std::process::Child, limit: Duration) -> Output {
    fn drain(
        pipe: Option<impl std::io::Read + Send + 'static>,
    ) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            bytes
        })
    }

    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait().expect("the program's status") {
            break status;
        }
        if Instant::now() >= deadline {
            let waiting = what_the_program_waits_on(child.id());
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "the program did not end within {} seconds:\n{waiting}",
                limit.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Output {
        status,
        stdout: stdout.join().expect("what the program printed"),
        stderr: stderr
            .join()
            .expect("what the program printed to standard error"),
    }
}

/// Describes the program `pid`, which has not ended: the program with its arguments and its state,
/// the programs it started, and, where the host says, the kernel's name for what each thread
/// waits for, the sockets the program holds, and the other programs of the same host (those with
/// the same runtime directory), whose threads show whether the host answered at all.
fn what_the_program_waits_on(pid: u32) -> String {
    use std::fmt::Write as _;

    let listing = Command::new("ps")
        .args(["-axo", "pid=,ppid=,stat=,etime=,command="])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
    // (process, parent, state, elapsed, command line)
    let processes: Vec<(u32, u32, &str, &str, &str)> = listing
        .lines()
        .filter_map(|line| {
            let mut rest = line.trim_start();
            let mut word = || {
                let (word, tail) = rest.split_at(rest.find(char::is_whitespace)?);
                rest = tail.trim_start();
                Some(word)
            };
            let process = word()?.parse().ok()?;
            let parent = word()?.parse().ok()?;
            let state = word()?;
            let elapsed = word()?;
            Some((process, parent, state, elapsed, rest))
        })
        .collect();
    let mut related = vec![pid];
    let mut next = 0;
    while next < related.len() {
        let parent = related[next];
        next += 1;
        let children: Vec<u32> = processes
            .iter()
            .filter(|(process, ppid, ..)| *ppid == parent && !related.contains(process))
            .map(|(process, ..)| *process)
            .collect();
        related.extend(children);
    }
    #[cfg(target_os = "linux")]
    {
        let environment_of = |process: u32| {
            std::fs::read(format!("/proc/{process}/environ"))
                .unwrap_or_default()
                .split(|byte| *byte == 0)
                .find(|entry| entry.starts_with(b"KR_RUNTIME_DIR="))
                .map(<[u8]>::to_vec)
        };
        if let Some(runtime) = environment_of(pid) {
            for (process, ..) in &processes {
                if !related.contains(process) && environment_of(*process) == Some(runtime.clone()) {
                    related.push(*process);
                }
            }
        }
    }
    let mut said = String::new();
    for process in &related {
        let Some((_, parent, state, elapsed, command)) = processes
            .iter()
            .find(|(candidate, ..)| candidate == process)
        else {
            continue;
        };
        let _ = writeln!(
            said,
            "  {process}{} (parent {parent}, state {state}, running {elapsed}): {command}",
            if *process == pid {
                " (the program)"
            } else {
                ""
            }
        );
        #[cfg(target_os = "linux")]
        {
            let mut waits: std::collections::BTreeMap<String, usize> =
                std::collections::BTreeMap::new();
            for thread in std::fs::read_dir(format!("/proc/{process}/task"))
                .into_iter()
                .flatten()
                .flatten()
            {
                let read = |name: &str| {
                    std::fs::read_to_string(thread.path().join(name))
                        .map(|text| text.trim().to_owned())
                        .unwrap_or_default()
                };
                *waits
                    .entry(format!("{} in {}", read("comm"), read("wchan")))
                    .or_default() += 1;
            }
            let _ = writeln!(said, "    threads: {waits:?}");
        }
    }
    #[cfg(target_os = "linux")]
    {
        // The unix sockets the program holds open: what it can be waiting to hear from.
        let sockets = std::fs::read_to_string("/proc/net/unix").unwrap_or_default();
        for descriptor in std::fs::read_dir(format!("/proc/{pid}/fd"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let Ok(target) = std::fs::read_link(descriptor.path()) else {
                continue;
            };
            let target = target.display().to_string();
            if let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
            {
                let path = sockets
                    .lines()
                    .find(|line| line.split_whitespace().nth(6) == Some(inode))
                    .and_then(|line| line.split_whitespace().nth(7))
                    .unwrap_or("with no name");
                let _ = writeln!(said, "    holds the unix socket {path}");
            }
        }
    }
    said
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
        while connect_to_daemon(&endpoint).await.is_err() {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the daemon did not answer; its log says: {}",
                std::fs::read_to_string(&log).unwrap_or_default()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        second
    }

    /// Whether a daemon answers for this environment.
    async fn answers(&self) -> bool {
        answers_for(&self.tree).await
    }

    /// What this environment's daemon states about its build.
    async fn build(&self) -> String {
        let endpoint = self
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let client = connect_to_daemon(&endpoint).await.expect("reaches the daemon");
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

/// The store record format the build before this one wrote, which this build reads and writes again
/// in its own.
const EARLIER_RECORD_FORMAT: u32 = kr_cli::update::RECORD_FORMAT - 1;

/// A store's record that holds nothing, in the format this build writes.
fn an_empty_record() -> String {
    format!("{{\"format\":{}}}\n", kr_cli::update::RECORD_FORMAT)
}

impl Host {
    /// A tree with an empty store.
    fn create() -> Self {
        let host = Self::bare();
        host.store
            .create_directories()
            .expect("the store's directories");
        std::fs::write(host.store.record(), an_empty_record()).expect("the store's record");
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
        self.stand_in_for_the_updater().switch(name);
    }

    /// Takes the locks an update holds when it switches: the update lock, the install lock and the
    /// writers' lock.
    fn stand_in_for_the_updater(&self) -> StandingIn<'_> {
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
        let writers = self
            .store
            .try_lock_writers()
            .expect("the writers' lock")
            .expect("no command is writing");
        StandingIn {
            host: self,
            update,
            install,
            writers,
        }
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

    /// What this host's daemon says of its configuration document: where it is, and what it turned out
    /// to be. It is the daemon's own reading, asked through `kr doctor`.
    #[cfg(all(unix, not(target_os = "macos")))]
    fn daemon_document(&self) -> (String, String) {
        let (_, report) = self.kr_json(&["--json", "doctor"]);
        let say = |value: &Value| value.as_str().unwrap_or_default().to_owned();
        (
            say(&report["configuration"]["document"]),
            say(&report["configuration"]["status"]["state"]),
        )
    }

    /// What this host's daemon says of how it was started, asked as an update asks it and taken back
    /// at once: its gate is open again when this returns.
    async fn daemon_started_like(&self) -> kr_protocol::update::HostUpdateHandoverResult {
        let endpoint = self
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let mut client = connect_to_daemon(&endpoint)
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
        while connect_to_daemon(&endpoint).await.is_err() {
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
        self.new_session_as(kr, &["--shell", "/bin/sh"])
    }

    fn new_session_as(&self, kr: &Path, shell: &[&str]) -> (String, SessionId) {
        let cwd = self.tree.root().display().to_string();
        let mut arguments = vec!["new", "--invisible", "--headless", "--cwd", &cwd];
        arguments.extend_from_slice(shell);
        arguments.extend_from_slice(&["--startup", "interactive", "--json"]);
        let output = self.run(kr, &arguments);
        assert!(
            output.status.success(),
            "kr new said {}: {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
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
        let client = connect_to_daemon(&endpoint).await.expect("reaches the daemon");
        client
            .acknowledgement()
            .build
            .as_ref()
            .map(|build| build.build_id.as_str().to_owned())
            .unwrap_or_default()
    }

    /// The public major this host's daemon states in its answer to a hello.
    async fn daemon_states(&self) -> u16 {
        let endpoint = self
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        connect_to_daemon(&endpoint)
            .await
            .expect("reaches the daemon")
            .acknowledgement()
            .selected_version
            .major
    }

    /// The identity of the process this host's daemon runs as, which differs each time a daemon
    /// starts.
    async fn daemon_process(&self) -> kr_protocol::identity::ProcessStartIdentity {
        let pid = self.daemon_started_like().await.pid.get();
        kr_ipc::identity::process_start_identity(u32::try_from(pid).expect("a process identifier"))
            .expect("the daemon's process")
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
            "format": EARLIER_RECORD_FORMAT,
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

    /// Replaces the store's record with `record`, as a run that stopped part way left it.
    fn write_record(&self, record: &Value) {
        std::fs::write(self.store.record(), record.to_string()).expect("the record");
    }

    /// The restart of this host's daemon an update records, as a released build recorded it: how it
    /// is started again, with the arguments it was started with and none of its variables.
    fn restart(&self) -> Value {
        serde_json::json!({
            "environment": self.tree.environment_id(),
            "runtime_root": self.tree.paths().runtime_root(),
            "state_root": self.tree.paths().state_root(),
            "start": {
                "arguments": {
                    "arguments": self.daemon_arguments(),
                    "working_directory": self.tree.root(),
                }
            },
        })
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
            "kr host install said {}: {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        start_each_once(&self.store.release_directory(assembled.name()));
    }
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
