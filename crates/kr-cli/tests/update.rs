//! A host installed as a store of releases: each program holds the release it runs, starts the
//! programs of that release, and names it; an update to another release never touches a live
//! session.
//!
//! Every release here is assembled from the programs this workspace built: `kr`, the restoration
//! guard, the control daemon, the worker and the forwarder, copied once to the internal disk and
//! then given to each release as files of its own, as an installed release has. Each test builds
//! its store inside a host tree of its own, with its own runtime and state roots, so nothing here
//! reads or changes the person's own installation. A daemon runs as a process of its own, with its
//! keys in the tree's own secrets directory, and the tree ends every worker it started before it
//! goes.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_ipc::install::{Program, Store};
use kr_protocol::hello::PACKAGE_VERSION;
use kr_protocol::ids::{BuildId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::scalars::{Digest256, U64};
use kr_protocol::update::{
    CommitId, CompatibilityLevel, FileMode, FloorSystem, FloorVersion, ManifestKind, OsFloor,
    ReleaseFile, ReleaseManifest, ReleaseName, ReleasePath,
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

/// The manifest of a release assembled from this workspace's programs, before it is signed.
fn manifest_of(name: &ReleaseName, sequence: u64, retained: CompatibilityLevel) -> ReleaseManifest {
    let mut files: Vec<ReleaseFile> = programs()
        .iter()
        .map(|(program, _, digest, length)| ReleaseFile {
            path: ReleasePath::new(format!("bin/{}", program.file_name())).expect("a path"),
            length: U64::new(*length),
            sha256: *digest,
            mode: FileMode::Executable,
        })
        .collect();
    for (path, contents) in module_tree() {
        files.push(ReleaseFile {
            path: ReleasePath::new(path).expect("a path"),
            length: U64::new(contents.len() as u64),
            sha256: Digest256::from_bytes(kr_cbor::sha256(contents.as_bytes())),
            mode: FileMode::Regular,
        });
    }
    ReleaseManifest {
        kind: ManifestKind::Release,
        release: name.clone(),
        sequence: U64::new(sequence),
        commit: CommitId::new(format!(
            "{}{}",
            &name.as_str()[name.as_str().len() - 12..],
            "0".repeat(28)
        ))
        .expect("a commit"),
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

/// Writes a release's tree at `directory`: its programs, its module tree and its manifest.
fn write_release(directory: &Path, manifest: &ReleaseManifest) {
    std::fs::create_dir_all(directory.join("bin")).expect("the release's bin");
    for (program, copied, _, _) in programs() {
        clone_file(copied, &directory.join("bin").join(program.file_name()));
    }
    for (path, contents) in module_tree() {
        let file = directory.join(path);
        std::fs::create_dir_all(file.parent().expect("a directory")).expect("the tree");
        std::fs::write(&file, contents).expect("a module");
    }
    let document = serde_json::json!({ "signed": manifest, "signatures": [] });
    std::fs::write(
        directory.join(kr_protocol::update::MANIFEST_FILE),
        document.to_string(),
    )
    .expect("the manifest");
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

/// A host tree with a store of releases in it, and the daemons this test started.
///
/// However a test ends, what it started ends with it: the daemons it started, and then, through
/// the tree, every worker a daemon recorded and on macOS every launchd job defined inside the
/// host's own state directory.
struct Host {
    daemons: Vec<std::process::Child>,
    store: Store,
    tree: teardown::Tree,
}

impl Drop for Host {
    fn drop(&mut self) {
        for mut daemon in self.daemons.drain(..) {
            if let Err(error) = daemon.kill().and_then(|()| daemon.wait().map(|_| ())) {
                self.tree.hold(format!(
                    "a daemon this test started could not be established as ended: {error}"
                ));
            }
        }
    }
}

impl Host {
    /// A tree with an empty store.
    fn create() -> Self {
        let tree = teardown::Tree::create();
        let store = Store::at(tree.root().join("host"));
        store.create_directories().expect("the store's directories");
        std::fs::write(store.record(), b"{\"format\":1}\n").expect("the store's record");
        Self {
            daemons: Vec::new(),
            store,
            tree,
        }
    }

    /// Puts a release in the store, as it is once installed.
    fn put(&self, name: &ReleaseName, sequence: u64) -> PathBuf {
        let directory = self.store.release_directory(name);
        write_release(
            &directory,
            &manifest_of(name, sequence, CompatibilityLevel::of(PACKAGE_VERSION)),
        );
        start_each_once(&directory);
        directory
    }

    /// Makes a release current.
    fn switch(&self, name: &ReleaseName) {
        let held = self.store.lock_install().expect("the install lock");
        self.store.switch(name, &held).expect("switches");
    }

    /// A program of a release, by its path in the store.
    fn program(&self, name: &ReleaseName, program: Program) -> PathBuf {
        self.store
            .release_directory(name)
            .join("bin")
            .join(program.file_name())
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

    /// Closes a session with a release's `kr` and waits for its worker to have gone.
    fn close(&self, kr: &Path, display: &str) {
        let output = self.run(kr, &["close", display, "--json"]);
        assert!(
            output.status.success(),
            "kr close: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// KR-REQ-26.06: every program of a release that is being removed refuses to start, and the same
/// programs start from the release's place in the store.
#[test]
fn no_program_of_a_release_being_removed_starts() {
    let host = Host::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let installed = host.put(&one, 1);
    // What the removal of a release leaves between its move and its deletion.
    let removing = host.store.trash().join(format!("{one}-leaving"));
    write_release(
        &removing,
        &manifest_of(&one, 1, CompatibilityLevel::of(PACKAGE_VERSION)),
    );
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
    let one = release("0.1.0+aaaaaaaaaaaa");
    host.put(&one, 1);
    host.switch(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    assert_eq!(host.daemon_build().await, format!("kr-controller/{one}"));
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
        format!("kr-worker/{one}"),
        "the worker the daemon started is of the daemon's own release"
    );
    assert!(
        host.store.held(&one).expect("asks"),
        "the release is held while its programs run"
    );
    host.close(&kr, &display);
}

/// A daemon of a release starts its own release's worker with its own release's packages, and
/// takes no other: a session it launched with another would run what the store does not hold.
#[test]
fn a_daemon_of_a_release_takes_no_other_worker_and_no_other_packages() {
    let host = Host::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    host.put(&one, 1);
    host.switch(&one);
    let controller = host.program(&one, Program::Controller);
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
    let one = release("0.1.0+aaaaaaaaaaaa");
    let two = release("0.2.0+bbbbbbbbbbbb");
    host.put(&one, 1);
    host.put(&two, 2);
    host.switch(&two);
    let arguments = host.daemon_arguments();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let refused = host.run(&host.program(&one, Program::Controller), &arguments);
    assert!(!refused.status.success());
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(
        said.contains(&format!(
            "this daemon is of release {one}, and this host's current release is {two}"
        )),
        "{said}"
    );
    // The control: the current release's daemon starts.
    let current = host.program(&two, Program::Controller);
    host.start_daemon(&current).await;
    assert_eq!(host.daemon_build().await, format!("kr-controller/{two}"));
}
