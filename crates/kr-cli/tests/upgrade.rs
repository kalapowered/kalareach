//! A host updated beside a live session of the release before it.
//!
//! The release before this one is built from its own commit, in a tree and a target directory of its
//! own, and installed as a host's first release; its programs, a control daemon, a worker and a
//! `kr`, run a session. The release under test is assembled from this workspace's programs, and
//! the host is updated to it by the first release's own `kr`, as a person's would be. The session's
//! worker is then a worker of the release before, beside a control daemon of this one, and each
//! case checks what the person and the programs of this release can still do with it, and that the
//! worker and the programs it started are the processes they were.
//!
//! The release before is whatever `retained/<level>/RELEASE` of the retained surface names. A
//! commit that is not there, or a build of it that fails, fails the suite: nothing here skips.
//! The suite is behind the `upgrade-suite` feature, because building a second tree takes minutes
//! and a network.

#![cfg(unix)]
#![allow(dead_code, unused_imports)]

mod stored_formats;
mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;
// A device pairs with the installed host's daemon over the network. The pairing calls are the ones
// the control daemon's own network suites make.
#[path = "upgrade/door.rs"]
mod door;
#[path = "../../kr-controller/tests/net_support/pairing.rs"]
mod pairing;
// A person's terminal: a program run on a pseudo-terminal that a case types at.
#[path = "upgrade/terminal.rs"]
mod terminal;

include!("support/update_harness.rs");

use serde_json::json;

/// The release before this one, built from its commit.
struct Previous {
    /// The release's name, from the retained surface's record of it.
    release: ReleaseName,
    /// The commit it was built from.
    commit: String,
    /// The compatibility level it speaks.
    level: CompatibilityLevel,
    /// Its programs, copied once to the internal disk.
    programs: &'static [(&'static str, PathBuf, Digest256, u64)],
}

impl Previous {
    /// A release of the release before's own programs, at its own level, carrying this process's
    /// channel root.
    fn assembled(&self, sequence: u64) -> Assembled {
        // The release's version is the one its name states, and its manifest names its own commit.
        let version = self
            .release
            .as_str()
            .split('+')
            .next()
            .and_then(|text| {
                let mut numbers = text.split('.').map(|part| part.parse::<u16>().ok());
                Some(PackageVersion::new(
                    numbers.next()??,
                    numbers.next()??,
                    numbers.next()??,
                ))
            })
            .expect("a release name states a version");
        let mut assembled = Assembled::of_programs(
            self.programs,
            self.release.as_str(),
            sequence,
            (self.level, version),
            the_root(),
        );
        assembled.manifest.commit = CommitId::new(self.commit.clone()).expect("a commit");
        assembled
    }
}

/// A line `name=value` of the record of a release.
fn recorded(record: &str, name: &str) -> String {
    record
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("the release record has no {name}: {record}"))
        .to_owned()
}

/// Where trees of the release before are built and kept between runs.
fn cache_root() -> PathBuf {
    let home = PathBuf::from(std::env::var_os("HOME").expect("a home directory"));
    if cfg!(target_os = "macos") {
        home.join("Library/Caches/kalareach-upgrade")
    } else {
        home.join(".cache/kalareach-upgrade")
    }
}

/// The programs the release before is assembled from, besides the description process.
const PREVIOUS_PROGRAMS: [&str; 6] = [
    "kr",
    "kr-attach-guard",
    "kr-controller",
    "kr-worker",
    "kr-hook",
    "kr-plugin-host",
];

/// The release before this one, built once for the whole run.
fn previous() -> &'static Previous {
    static PREVIOUS: OnceLock<Previous> = OnceLock::new();
    PREVIOUS.get_or_init(|| {
        // The release before is the newest level this build retains.
        let level = kr_protocol::retained::RETAINED
            .iter()
            .max_by_key(|level| level.level)
            .expect("a level is retained");
        let record = level.release;
        let commit = recorded(record, "commit");
        let release = release(&recorded(record, "release"));
        // Held until the programs are copied: another run for another commit removes this tree.
        let _held = cache_lock();
        let built = build_previous(&commit);
        let directory = support::command_binaries().join("previous");
        std::fs::create_dir_all(&directory).expect("a directory for the programs");
        let mut copied = Vec::new();
        for name in PREVIOUS_PROGRAMS {
            let source = built.join(name);
            assert!(source.is_file(), "{} was not built", source.display());
            copied.push(placed(name, &source, &directory));
        }
        // No live process of the description process is under test, so this tree's is used.
        let (_, ours, _, _) = programs()
            .iter()
            .find(|(name, ..)| *name == "kr-describe-inference")
            .expect("this build's description process");
        copied.push(placed("kr-describe-inference", ours, &directory));
        Previous {
            release,
            commit,
            level: level.level,
            programs: Box::leak(copied.into_boxed_slice()),
        }
    })
}

/// Copies one program to the internal disk and says what it is.
fn placed(
    name: &'static str,
    source: &Path,
    directory: &Path,
) -> (&'static str, PathBuf, Digest256, u64) {
    let destination = directory.join(name);
    kr_ipc::testing::place_program(source, &destination);
    let bytes = std::fs::read(&destination).expect("the program");
    (
        name,
        destination,
        Digest256::from_bytes(kr_cbor::sha256(&bytes)),
        bytes.len() as u64,
    )
}

/// The lock on the cache, taken for one run at a time and held until the guard is dropped.
fn cache_lock() -> std::fs::File {
    let cache = cache_root();
    std::fs::create_dir_all(&cache).expect("the cache directory");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(cache.join(".lock"))
        .expect("the cache's lock");
    lock.lock().expect("the cache's lock is taken");
    lock
}

/// Builds the programs of `commit` in a tree and a target directory of their own under the cache,
/// and returns the directory they are in. The caller holds [`cache_lock`].
///
/// The commit has to be in this checkout's repository, whether or not an earlier run built it: a
/// checkout without it fails here, and so does a build that fails. A stamp of the commit and the
/// compiler is written once the tree is extracted, so a tree is extracted once; the build is run
/// every time, and takes seconds when nothing changed. Any other commit's tree is removed.
fn build_previous(commit: &str) -> PathBuf {
    let cache = cache_root();
    let present = Command::new("git")
        .arg("-C")
        .arg(repository())
        .args(["cat-file", "-e", &format!("{commit}^{{commit}}")])
        .status()
        .unwrap_or_else(|error| panic!("git did not start: {error}"));
    assert!(
        present.success(),
        "the release before is not in this repository: {commit} is absent; the suite does not skip"
    );
    let toolchain = Command::new("rustc")
        .arg("-vV")
        .output()
        .expect("rustc runs");
    assert!(
        toolchain.status.success(),
        "rustc -vV said {}",
        toolchain.status
    );
    let stamp = format!("{commit}\n{}", String::from_utf8_lossy(&toolchain.stdout));
    let place = cache.join(commit);
    let tree = place.join("tree");
    let programs = place.join("target/debug");
    // The tree is the commit's, as extracted by a run with this compiler, or it is made again.
    if !std::fs::read_to_string(place.join("stamp")).is_ok_and(|kept| kept == stamp) {
        // A tree of another commit, or an extraction that did not finish, goes.
        for entry in std::fs::read_dir(&cache).expect("the cache") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                std::fs::remove_dir_all(&path).expect("an old tree goes");
            }
        }
        std::fs::create_dir_all(&tree).expect("the tree's directory");
        let mut archive = Command::new("git")
            .arg("-C")
            .arg(repository())
            .args(["archive", "--format=tar", commit])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("git archive did not start: {error}"));
        tar::Archive::new(archive.stdout.take().expect("the archive"))
            .unpack(&tree)
            .expect("the commit's tree is unpacked");
        let status = archive.wait().expect("git archive ends");
        assert!(
            status.success(),
            "the release before is not in this repository: git archive {commit} said {status}; \
             the suite does not skip"
        );
        std::fs::write(place.join("stamp"), &stamp).expect("the stamp");
    }
    {
        // The packages build every binary they have: the release before is these programs of it.
        // The environment is this process's without what a test run sets for this tree, so the
        // older tree builds with its own settings and the toolchain it pins.
        let output = Command::new("cargo")
            .current_dir(&tree)
            .env_clear()
            .envs(std::env::vars_os().filter(|(name, _)| {
                let name = name.to_string_lossy();
                let carried = ["CARGO_HOME", "CARGO_NET", "CARGO_HTTP", "CARGO_REGISTR"];
                (!name.starts_with("CARGO") || carried.iter().any(|kept| name.starts_with(kept)))
                    && !["RUSTFLAGS", "RUSTUP_TOOLCHAIN", "RUSTC_WRAPPER"].contains(&&*name)
            }))
            .env("CARGO_TARGET_DIR", place.join("target"))
            .args(["build", "--locked", "-p", "kr-cli", "-p", "kr-controller"])
            .args(["-p", "kr-worker", "-p", "kr-hook", "-p", "kr-plugin-host"])
            .output()
            .expect("cargo runs");
        assert!(
            output.status.success(),
            "the release before did not build: {}",
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .rev()
                .take(40)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    programs
}

/// The extra levels this build retains besides its own are named in the manifest of a release
/// assembled here, as a real release names them.
impl Assembled {
    /// This release as one that names every level this build speaks at, as its manifest does.
    fn retaining_what_this_build_does(mut self) -> Self {
        self.manifest.retained_levels = kr_protocol::retained::levels();
        self
    }
}

/// A host on the release before, with a live session, updated by that release's own `kr` to this
/// build's release.
struct Updated {
    host: Host,
    /// The release before.
    one: Assembled,
    /// This build's release, which names every level this build speaks at.
    two: Assembled,
    /// The session's display number and identifier.
    display: String,
    session_id: SessionId,
    /// The process of the session's worker before the update.
    worker: kr_protocol::identity::ProcessStartIdentity,
    /// The pipes of the session's contact server, for a host set up with one.
    contact: Option<ContactPipes>,
    /// The stand-in agent the session's root shell started, for a host set up with one.
    agent: Option<Agent>,
}

/// What a host on the release before is set up with.
#[derive(Clone, Copy, Default)]
struct Setup {
    /// The configuration document puts the host's daemon on the network, on the loopback interface
    /// alone, from the first release's daemon on.
    network: bool,
    /// The session's root shell waits at a gate and then becomes the contact server of whichever
    /// release is current, with its standard streams on named pipes.
    contact: bool,
    /// A plugin package whose component the host's plugin runtime runs is installed and enabled
    /// before the first daemon opens the catalogue.
    plugin: bool,
    /// The session's root shell starts a stand-in agent, a process of its own that outlasts the
    /// shell, before it goes on as the shell.
    agent: bool,
}

/// The named pipes the contact server of a session runs on.
struct ContactPipes {
    /// The root shell waits to read a line from here.
    gate: PathBuf,
    /// The server's standard input.
    to_server: PathBuf,
    /// The server's standard output.
    from_server: PathBuf,
}

impl Updated {
    async fn new() -> Self {
        Self::start(Setup::default()).await
    }

    /// As [`Self::new`], with the host's daemon on the network.
    async fn on_the_network() -> Self {
        Self::start(Setup {
            network: true,
            ..Setup::default()
        })
        .await
    }

    /// As [`Self::on_the_network`], with a stand-in agent started by the session's root shell.
    async fn on_the_network_with_an_agent() -> Self {
        Self::start(Setup {
            network: true,
            agent: true,
            ..Setup::default()
        })
        .await
    }

    /// As [`Self::new`], with a session whose root shell becomes the contact server once the test
    /// opens its gate.
    async fn with_a_contact_session() -> Self {
        Self::start(Setup {
            contact: true,
            ..Setup::default()
        })
        .await
    }

    async fn start(setup: Setup) -> Self {
        Self::prepare(setup).await.update().await
    }

    /// A host on the release before with its live session, not yet updated.
    async fn prepare(setup: Setup) -> Prepared {
        let Setup {
            network: on_the_network,
            contact,
            plugin,
            agent,
        } = setup;
        let before = previous();
        let one = before.assembled(1);
        let two = Assembled::at_this_level(&format!("{PACKAGE_VERSION}+bbbbbbbbbbbb"), 2)
            .retaining_what_this_build_does();
        let mut host = Host::bare();
        host.install(&one);
        if on_the_network {
            // The document is what puts a host on the network: this one joins on loopback alone,
            // and selects no relay and no discovery.
            let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
            document.revision = 1;
            document.network.enabled = Nullable::some(true);
            document.network.bind_address = Nullable::some("127.0.0.1:0".to_owned());
            let path = kr_worker::config::document_path(&host.tree.environment());
            std::fs::create_dir_all(path.parent().expect("the document has a directory"))
                .expect("the state directory");
            kr_ipc::paths::write_owner_only_file(
                &path,
                kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
            )
            .expect("the configuration document");
        }
        if plugin {
            install_plugin(&host).await;
        }
        let started_through_current = host.store.stable(Program::Controller);
        host.start_daemon(&started_through_current).await;
        let kr = host.program(one.name(), Program::Kr);
        let mut pipes = None;
        let mut started_agent = None;
        let (display, session_id) = if agent {
            let (display, session_id, made) = host.new_session_with_an_agent(&kr, "session");
            started_agent = Some(made);
            (display, session_id)
        } else if contact {
            let directory = host.scratch("contact");
            let made = ContactPipes {
                gate: directory.join("gate"),
                to_server: directory.join("to-server"),
                from_server: directory.join("from-server"),
            };
            for pipe in [&made.gate, &made.to_server, &made.from_server] {
                let status = Command::new("mkfifo")
                    .arg(pipe)
                    .status()
                    .expect("mkfifo runs");
                assert!(status.success(), "a pipe is made");
            }
            // Named for the shell it stands for, because the worker recognises a shell by its name.
            let shell = directory.join("sh");
            std::fs::write(
                &shell,
                format!(
                    "#!/bin/sh\nPATH=/usr/bin:/bin\nexport PATH\nKR_RUNTIME_DIR='{runtime}'\n\
                     KR_STATE_DIR='{state}'\nexport KR_RUNTIME_DIR KR_STATE_DIR\n\
                     read -r _ < '{gate}'\nexec '{server}' agent-tools --stdio < '{to}' > '{from}'\n",
                    runtime = host.tree.paths().runtime_root().display(),
                    state = host.tree.paths().state_root().display(),
                    gate = made.gate.display(),
                    // Through `current`: the release that is current when the gate opens.
                    server = host.store.stable(Program::Kr).display(),
                    to = made.to_server.display(),
                    from = made.from_server.display(),
                ),
            )
            .expect("the contact session's shell");
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o755))
                    .expect("executable");
            }
            pipes = Some(made);
            host.new_session_as(&kr, &["--shell", &shell.display().to_string()])
        } else {
            host.new_session(&kr)
        };
        let worker = host.worker_process(session_id);
        assert_eq!(
            host.worker_build(session_id).await,
            format!("kr-worker/{}", one.name()),
            "the session's worker is the release before's"
        );
        Prepared {
            host,
            one,
            two,
            display,
            session_id,
            worker,
            contact: pipes,
            agent: started_agent,
        }
    }

    /// The release before's `kr`, and this release's.
    fn kr_before(&self) -> PathBuf {
        self.host.program(self.one.name(), Program::Kr)
    }

    fn kr_now(&self) -> PathBuf {
        self.host.program(self.two.name(), Program::Kr)
    }

    /// The worker still runs the release before, and is the process it was.
    async fn the_worker_is_as_it_was(&self) {
        assert_eq!(
            self.host.worker_build(self.session_id).await,
            format!("kr-worker/{}", self.one.name()),
            "the worker still runs the release before"
        );
        assert_eq!(
            self.host.worker_process(self.session_id),
            self.worker,
            "and it is the process it was"
        );
        if let Some(agent) = &self.agent {
            assert_eq!(
                kr_ipc::identity::process_state(&agent.identity),
                kr_ipc::identity::ProcessState::Running,
                "and the agent its shell started is the process it was, running"
            );
        }
    }
}

/// A host on the release before with its live session, before the update.
struct Prepared {
    host: Host,
    one: Assembled,
    two: Assembled,
    display: String,
    session_id: SessionId,
    worker: kr_protocol::identity::ProcessStartIdentity,
    contact: Option<ContactPipes>,
    agent: Option<Agent>,
}

impl Prepared {
    /// The release before's `kr`, and this release's once it is current.
    fn kr_before(&self) -> PathBuf {
        self.host.program(self.one.name(), Program::Kr)
    }

    /// Updates the host to this build's release with the release before's own `kr`.
    async fn update(self) -> Updated {
        let Self {
            host,
            one,
            two,
            display,
            session_id,
            worker,
            contact: pipes,
            agent,
        } = self;
        let archive = host.scratch("archives").join("two.tar.gz");
        two.archive(&archive);
        let (output, said) = host.kr_json(&[
            "host",
            "update",
            "--archive",
            &archive.display().to_string(),
            "--json",
        ]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "the release before's kr host update goes on: {said} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            host.store.current().expect("reads"),
            Some(two.name().clone())
        );
        assert_eq!(
            host.daemon_build().await,
            format!("kr-controller/{}", two.name()),
            "the daemon is of the new release"
        );
        let updated = Updated {
            host,
            one,
            two,
            display,
            session_id,
            worker,
            contact: pipes,
            agent,
        };
        updated.the_worker_is_as_it_was().await;
        updated
    }
}

/// KR-REQ-26.06, KR-REQ-26.08, KR-ACC-035: a host on the release before is updated, by that
/// release's own `kr`, to this one while a session's worker still runs the release before: the
/// update goes on and does not wait, the worker is the process it was, the new control daemon lists
/// the session and closes it with the answer of the worker's level, and the release the worker holds
/// is let go once the session ends.
#[tokio::test(flavor = "multi_thread")]
async fn kr_host_update_goes_on_beside_a_live_worker_of_the_release_before() {
    let updated = Updated::new().await;
    let host = &updated.host;

    // The new daemon lists the session it adopted.
    let listed = host.run(&updated.kr_now(), &["--json", "list"]);
    assert!(
        listed.status.success(),
        "kr list: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("a document");
    assert!(
        listed.to_string().contains(&updated.session_id.to_string()),
        "the session is listed: {listed}"
    );

    // The worker of the release before holds its release, and this build's store sees the hold.
    assert!(
        host.store.held(updated.one.name()).expect("asks"),
        "the release the worker runs is held by it"
    );

    // The new daemon closes it, and the release the worker held is let go.
    host.close(&updated.kr_now(), &updated.display);
    host.worker_ended(&updated.worker).await;
    host.released(updated.one.name()).await;
}

/// KR-REQ-26.06, KR-ACC-035: a control daemon of this release that starts again beside the worker
/// of the release before finds it again from its descriptor and publishes the descriptor in the
/// shape the release before reads, so that release's own `kr` still finds and reads the session.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_start_of_the_daemon_leaves_the_session_readable_by_the_release_before() {
    let mut updated = Updated::new().await;
    assert!(updated.host.stop_the_daemon().await, "the daemon stops");
    let controller = updated.host.store.stable(Program::Controller);
    updated.host.start_daemon(&controller).await;

    let host = &updated.host;
    let read = host.run(
        &updated.kr_before(),
        &["--json", "status", &updated.display],
    );
    assert!(
        read.status.success(),
        "the release before's kr status: {}",
        String::from_utf8_lossy(&read.stderr)
    );
    let read: Value = serde_json::from_slice(&read.stdout).expect("a document");
    assert_eq!(read["session_id"], updated.session_id.to_string(), "{read}");
    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_now(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// KR-REQ-26.06, KR-ACC-035: the `kr` of this release does not read the frames of the worker of the
/// release before. `kr status` says which session it did not read, which release it runs and the
/// `kr` that reads it, and that `kr` does; `kr question list` says the same beside the questions it
/// did read; and `kr detach` is handed to the `kr` of the release before, which answers it.
#[tokio::test(flavor = "multi_thread")]
async fn the_kr_of_this_release_hands_the_worker_of_the_release_before_to_the_kr_that_reads_it() {
    let updated = Updated::new().await;
    let host = &updated.host;
    let their_kr = updated.kr_before().display().to_string();

    let refused = host.run(&updated.kr_now(), &["status", &updated.display]);
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(refused.status.code(), Some(8), "{said}");
    for named in [
        format!("session {} was not read", updated.display),
        format!("kr-worker/{}", updated.one.name()),
        their_kr,
    ] {
        assert!(said.contains(&named), "{named} is not in: {said}");
    }
    let read = host.run(
        &updated.kr_before(),
        &["--json", "status", &updated.display],
    );
    assert!(
        read.status.success(),
        "the release before's kr reads it: {}",
        String::from_utf8_lossy(&read.stderr)
    );

    let listed = host.run(&updated.kr_now(), &["--json", "question", "list"]);
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("a document");
    assert_eq!(listed["questions"], serde_json::json!([]), "{listed}");
    let unread = listed["unread"]
        .as_array()
        .expect("a list of unread sessions");
    assert_eq!(unread.len(), 1, "{listed}");
    let note = unread[0].to_string();
    assert!(
        note.contains(&format!("session {} was not read", updated.display))
            && note.contains(&updated.kr_before().display().to_string()),
        "the note names the session and the kr that reads it: {note}"
    );

    // `kr attach` of this release is handed to the `kr` of the release before, which attaches: a
    // person types at the session through it, and the worker is the process it was.
    let typing = terminal_for(host, &updated.kr_now(), &["attach", &updated.display]);
    typing.ready().await;
    updated.the_worker_is_as_it_was().await;
    drop(typing);

    // Handed over: the answer is the release before's own, whatever it is, and not this release's
    // refusal. The release before's `kr` is asked the same thing directly for the comparison.
    let session = updated.session_id.to_string();
    let direct = host.run(&updated.kr_before(), &["--json", "detach", &session]);
    let handed = host.run(&updated.kr_now(), &["--json", "detach", &updated.display]);
    let (direct_said, handed_said): (Value, Value) = (
        serde_json::from_slice(&direct.stdout).expect("the release before answers in JSON"),
        serde_json::from_slice(&handed.stdout).expect("the handed-over kr answers in JSON"),
    );
    assert_eq!(
        handed.status.code(),
        direct.status.code(),
        "{handed_said} against {direct_said}"
    );
    assert_eq!(handed_said["code"], direct_said["code"], "{handed_said}");
    assert_ne!(handed_said["code"], "UNSUPPORTED_SCHEMA", "{handed_said}");
    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_now(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// The lowercase hexadecimal text of `bytes`.
fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// KR-REQ-26.06, KR-ACC-035: the frames a control daemon sends a worker on its own, and the worker's
/// answers, are read by the real worker of the release before, and the exchange, recorded as it
/// went over the wire, reads under the level that release stated.
///
/// A link of the test process speaks for the host with the host's own keys, once the host's daemon
/// has stopped (a generation there takes authority from the daemon's link), and is bound to the
/// level the worker states. It proves the worker, presents a generation, and tells it what the
/// daemon tells a worker: what the local owner may do, two authority revisions (the second
/// withdrawing a grant and a device), the privacy generation, and reads the session. Every frame
/// either way is kept as its payload. Run with `KR_RECORD_FRAMES` set, the exchange is printed as
/// the record `retained/<level>/frames.json` holds, which `kr-protocol`'s retained cases decode.
#[tokio::test(flavor = "multi_thread")]
async fn the_frames_the_controller_sends_on_its_own_are_read_by_the_worker_of_the_release_before() {
    use kr_ipc::client::BoundLink;
    use kr_ipc::framed::Tap;
    use kr_ipc::verify::{CONTROLLER_SECRET_SERVICE, ControllerIdentity};
    use kr_protocol::ids::{AuthorityRevision, ControllerGeneration, DeviceId, GrantId};
    use kr_protocol::privacy::PrivacyGenerationNotice;
    use kr_protocol::retained::Level;
    use kr_protocol::session::{SessionReadParams, SessionReadResult};
    use kr_protocol::worker::{AuthorityRevisionNotice, LocalAccess, LocalBound, RevisionReach};

    let updated = Updated::new().await;
    let host = &updated.host;
    assert!(host.stop_the_daemon().await, "the daemon stops");

    let environment = host.tree.environment();
    let descriptor = kr_ipc::descriptor::read(&environment, updated.session_id)
        .expect("reads the descriptor")
        .expect("the session is published");
    let endpoint = kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint).expect("an endpoint");
    let opened = kr_crypto::store::StoreSelection::File
        .open(CONTROLLER_SECRET_SERVICE, &environment.secrets_dir())
        .expect("the host's secrets");
    let identity = ControllerIdentity::load(opened.store.as_ref(), environment.environment_id())
        .expect("the host's own identity");

    let tap = Tap::default();
    let mut link = BoundLink::connect(&endpoint, build())
        .await
        .expect("the worker of the release before is met at its own level");
    link.record_into(&tap);
    link.verify_worker(&descriptor)
        .await
        .expect("the worker proves it is the one the descriptor names");
    let boot = link.acknowledgement().boot_identity.clone();
    link.present_generation(|nonce| {
        identity
            .generation_token(ControllerGeneration::new(1_000), &boot, nonce)
            .map_err(kr_ipc::IpcError::from)
    })
    .await
    .expect("the worker accepts the generation");

    let environment_id = environment.environment_id();
    let local = link
        .announce_local_access(LocalAccess {
            sequence: kr_protocol::scalars::U64::new(1),
            bound: LocalBound::Open,
        })
        .await
        .expect("the worker holds what the local owner may do");
    assert_eq!(local.sequence.get(), 1);
    for (revision, reach) in [
        (2, RevisionReach::Host),
        (
            3,
            RevisionReach::Within {
                since: AuthorityRevision::new(2),
                grants: [GrantId::new(kr_protocol::scalars::Uuid::from_bytes(
                    [7; 16],
                ))]
                .into_iter()
                .collect(),
                devices: [DeviceId::new(kr_protocol::scalars::Uuid::from_bytes(
                    [8; 16],
                ))]
                .into_iter()
                .collect(),
            },
        ),
    ] {
        let acknowledged = link
            .announce_revision(AuthorityRevisionNotice {
                environment_id,
                revision: AuthorityRevision::new(revision),
                reach,
                evidence_from: 0,
            })
            .await
            .expect("the worker installs the revision");
        assert_eq!(acknowledged.revision.get(), revision);
    }
    link.announce_privacy(PrivacyGenerationNotice {
        environment_id,
        generation: kr_protocol::scalars::U64::new(1),
        enabled: false,
    })
    .await
    .expect("the worker takes the privacy generation");
    // The snapshot of plugin admissions a daemon sends every worker: here one with no package.
    let admitted = link
        .exchange_admissions(
            vec![kr_protocol::admission::PluginAdmissions {
                environment_id,
                frame: kr_protocol::admission::FrameId {
                    generation: ControllerGeneration::new(1_000),
                    revision: kr_protocol::scalars::U64::new(3),
                    round: kr_protocol::scalars::U64::new(1),
                },
                part: 1,
                parts: 1,
                policy: kr_protocol::admission::RevocationPolicy::WarnOnly,
                packages: Vec::new(),
                releases: Vec::new(),
            }],
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("the worker takes the plugin admissions");
    assert_eq!(admitted.len(), 1);
    let read = link
        .request(
            kr_protocol::method::Method::SessionRead,
            &SessionReadParams {
                session_id: updated.session_id,
            },
        )
        .await
        .expect("the read goes over")
        .expect("the worker answers the read");
    let read: SessionReadResult = link.decode(&read).expect("the answer reads at the level");
    assert_eq!(read.session.session_id, updated.session_id);

    // Every frame of the exchange reads under the level the worker stated, which is the level of
    // the release before; what this side wrote reads back the same under it.
    let retained = kr_protocol::retained::RETAINED
        .iter()
        .find(|retained| retained.level == previous().level)
        .expect("the release before is a retained level");
    let level = Level::retained(retained);
    assert_eq!(
        format!("{:?}", link.level()),
        format!("{level:?}"),
        "the link speaks the worker's level"
    );
    let frames = tap.frames();
    let mut keys = Vec::new();
    let mut reaches = Vec::new();
    for frame in &frames {
        let decoded = level
            .decode(&frame.payload, &kr_cbor::Limits::DEFAULT)
            .unwrap_or_else(|error| panic!("a frame reads under the level: {error:?}"));
        let document = serde_json::to_value(&decoded).expect("a frame is a document");
        let (key, body) = document
            .as_object()
            .and_then(|object| object.iter().next())
            .map(|(key, body)| (key.clone(), body.clone()))
            .expect("a frame names its kind");
        if key == "authority_revision" {
            reaches.push(body.get("reach").is_some());
        }
        keys.push(key);
        if frame.written {
            assert_eq!(
                level
                    .encode(&decoded, &kr_cbor::Limits::DEFAULT)
                    .expect("it writes again"),
                frame.payload,
                "a frame this side wrote is the one the level writes"
            );
        }
    }
    assert_eq!(
        keys,
        [
            "verify_challenge",
            "verify_proof",
            "generation_token",
            "generation_accepted",
            "local_access",
            "local_access_ack",
            "authority_revision",
            "authority_revision_ack",
            "authority_revision",
            "authority_revision_ack",
            "privacy_generation",
            "privacy_generation_ack",
            "plugin_admissions",
            "plugin_admissions_ack",
            "request",
            "response",
        ],
        "the exchange, frame by frame"
    );
    assert_eq!(
        reaches,
        [false, true],
        "a revision without reach, then one with it"
    );
    if std::env::var_os("KR_RECORD_FRAMES").is_some() {
        let record: Vec<Value> = frames
            .iter()
            .map(|frame| {
                serde_json::json!({
                    "direction": if frame.written { "controller_to_worker" } else { "worker_to_controller" },
                    "payload": hexadecimal(&frame.payload),
                })
            })
            .collect();
        println!(
            "FRAMES-JSON-BEGIN\n{}\nFRAMES-JSON-END",
            serde_json::to_string_pretty(&record).expect("a record")
        );
    }
    // The session is closed with the release before's own `kr`, which reaches the worker itself now
    // that no daemon runs.
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// KR-REQ-26.10, KR-REQ-26.08: a rollback to the release before goes on while only its session is
/// live, and waits, exit 9, naming the session, while a session of this release is live.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_to_the_release_before_goes_on_beside_its_session_and_waits_for_one_of_this_release()
 {
    let updated = Updated::new().await;
    let host = &updated.host;

    // A session of this release: the older release's daemon does not retain its level.
    let (display, session_now) = host.new_session(&updated.kr_now());
    let worker_now = host.worker_process(session_now);
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "a rollback waits for a session of this release: {said}"
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&format!(
            "session {display} runs kr-worker/{}",
            updated.two.name()
        )),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(updated.two.name().clone()),
        "nothing was switched"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", updated.two.name()),
        "the daemon this release started is serving again"
    );
    host.close(&updated.kr_now(), &display);
    host.worker_ended(&worker_now).await;

    // With only the release before's session live the rollback goes on.
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(updated.one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", updated.one.name()),
        "the daemon is the release before's again"
    );
    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// A mutation's expected-state evidence for a method that needs none.
#[derive(serde::Serialize)]
struct Empty {}

/// KR-REQ-26.06, KR-REQ-23.34, KR-ACC-035: a device paired with the updated host's daemon over the
/// network, as a phone is, meets the worker of the release before through the new daemon. The
/// daemon lists the session, reads it, its description, and its attention inbox
/// at the worker's level, and closes it for the device, answering with what the worker answered;
/// the worker is the process it was throughout.
#[tokio::test(flavor = "multi_thread")]
async fn a_device_at_the_door_of_the_updated_host_meets_the_worker_of_the_release_before() {
    use kr_protocol::describe::{SessionDescribeParams, SessionDescribeResult};
    use kr_protocol::session::{
        SessionCloseParams, SessionCloseResult, SessionListParams, SessionListResult,
        SessionReadParams, SessionReadResult,
    };

    let updated = Updated::on_the_network_with_an_agent().await;
    let host = &updated.host;
    let door = door::Door::pair_the_first_owner(
        &host
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint"),
        host.tree.environment_id(),
    )
    .await;
    let session = &door.session;
    let session_id = updated.session_id;

    let listed: SessionListResult = session
        .read(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed: false,
            },
        )
        .await
        .expect("the device lists the sessions");
    let summary = listed
        .sessions
        .iter()
        .find(|summary| summary.session_id == session_id)
        .unwrap_or_else(|| panic!("the session is listed: {listed:?}"));
    assert!(summary.closure.0.is_none(), "{summary:?}");

    let read: SessionReadResult = session
        .read(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("the device reads the session");
    assert_eq!(read.session.session_id, session_id, "{read:?}");

    let described: SessionDescribeResult = session
        .read(
            Method::SessionDescribe,
            &SessionDescribeParams { session_id },
        )
        .await
        .expect("the device reads the description");
    assert_eq!(described.session_id, session_id, "{described:?}");

    // The attention inbox the daemon keeps for the session, built from what the worker reported.
    let attention: kr_protocol::attention::AttentionReadResult = session
        .read(
            Method::AttentionRead,
            &kr_protocol::attention::AttentionReadParams {
                session_id: Nullable::some(session_id),
                include_acknowledged: true,
                max_items: U64::new(50),
                after: Nullable::null(),
            },
        )
        .await
        .expect("the device reads the attention inbox");
    assert!(attention.gaps.is_empty(), "{attention:?}");

    // The worker is the process it was, and runs the release before.
    updated.the_worker_is_as_it_was().await;

    // The device closes the session, and the worker's own answer comes back through the daemon.
    let settled = session
        .mutate(
            Method::SessionClose,
            kr_protocol::envelope::ActionTarget {
                environment_id: host.tree.environment_id(),
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            None,
            &Empty {},
            &SessionCloseParams { session_id },
            kr_protocol::scalars::DurationMs::new(120_000),
        )
        .await
        .expect("the device closes the session");
    let closed: SessionCloseResult = settled
        .to_typed()
        .expect("the host answers with the closure the worker gave");
    assert_eq!(closed.session_id, session_id, "{closed:?}");
    host.worker_ended(&updated.worker).await;
    host.released(updated.one.name()).await;

    // The daemon keeps the closed session's record, with the worker's closure.
    let closed = until(
        "the closed session to be listed with its closure",
        || async {
            let listed: SessionListResult = session
                .read(
                    Method::SessionList,
                    &SessionListParams {
                        environment_id: Nullable::null(),
                        include_closed: true,
                    },
                )
                .await
                .ok()?;
            listed
                .sessions
                .into_iter()
                .find(|summary| summary.session_id == session_id && summary.closure.0.is_some())
        },
    )
    .await;
    assert!(closed.closure.0.is_some(), "{closed:?}");
}

/// A terminal running `program` with the arguments, as a person's does on this host.
fn terminal_for(host: &Host, program: &Path, arguments: &[&str]) -> terminal::Terminal {
    let mut command = portable_pty::CommandBuilder::new(program);
    command.args(arguments);
    command.env_clear();
    command.env("PATH", "/usr/bin:/bin");
    command.env("KR_RUNTIME_DIR", host.tree.paths().runtime_root());
    command.env("KR_STATE_DIR", host.tree.paths().state_root());
    terminal::Terminal::run(command, host.tree.root())
}

impl Updated {
    /// Opens the gate of the contact session, so its root shell becomes the contact server of
    /// the release that is current, and connects a Model Context Protocol client to that server.
    async fn contact_client(&self) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
        use rmcp::ServiceExt as _;

        let pipes = self
            .contact
            .as_ref()
            .expect("a host set up with a contact session");
        let gate = pipes.gate.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;

            // A write end opened without waiting is refused until the root shell reads the gate.
            let deadline = Instant::now() + LIVENESS_DEADLINE;
            loop {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&gate)
                {
                    Ok(mut gate) => {
                        gate.write_all(b"\n").expect("lets the root shell past");
                        return;
                    }
                    Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                        assert!(
                            Instant::now() < deadline,
                            "the root shell never read the gate"
                        );
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("opens the gate: {error}"),
                }
            }
        })
        .await
        .expect("the gate is opened");
        // The server opens its input first and its output second, and each open waits for the other
        // end. Neither end here waits: the input's writer is opened as soon as the server's open of
        // it is waiting (a reader that waits in `open` counts as one), and the output's reader
        // after it. A server that never opens its input, or never answers the handshake, fails the
        // case at the deadline.
        let deadline = Instant::now() + LIVENESS_DEADLINE;
        let writer = loop {
            match tokio::net::unix::pipe::OpenOptions::new().open_sender(&pipes.to_server) {
                Ok(writer) => break writer,
                Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                    assert!(
                        Instant::now() < deadline,
                        "the server never opened its input"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("opens the server's input: {error}"),
            }
        };
        let reader = tokio::net::unix::pipe::OpenOptions::new()
            .open_receiver(&pipes.from_server)
            .expect("opens the server's output");
        tokio::time::timeout(LIVENESS_DEADLINE, ().serve((reader, writer)))
            .await
            .expect("the tool server answered the handshake in time")
            .expect("the tool server answered the handshake")
    }
}

/// Calls one contact tool and returns its structured content and whether it failed.
async fn call_tool(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &str,
    arguments: Value,
) -> (Value, bool) {
    let result = tokio::time::timeout(
        LIVENESS_DEADLINE,
        client.call_tool(
            rmcp::model::CallToolRequestParams::new(name.to_owned())
                .with_arguments(arguments.as_object().cloned().unwrap_or_default()),
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("{name} did not answer within {LIVENESS_DEADLINE:?}"))
    .unwrap_or_else(|error| panic!("{name} answered: {error}"));
    let content = result
        .structured_content
        .clone()
        .unwrap_or_else(|| panic!("{name} returned structured content"));
    (content, result.is_error.unwrap_or_default())
}

/// KR-REQ-26.06, KR-ACC-035: the contact server of this release, the root of a session whose worker
/// is of the release before, asks the person's question through that release's `kr`. The `kr` of
/// this release does not read the worker, so it lists the question as unread and does not answer
/// it; the `kr` of the release before lists and answers it, and the server returns the answer.
#[tokio::test(flavor = "multi_thread")]
async fn the_contact_server_of_this_release_asks_the_worker_of_the_release_before_and_gets_its_answer()
 {
    let updated = Updated::with_a_contact_session().await;
    let host = &updated.host;
    let client = updated.contact_client().await;
    let (created, failed) = call_tool(
        &client,
        "ask_user",
        json!({
            "request_id": "ask-1",
            "agent_name": "a test agent",
            "context": "two ways to do it",
            "question": "which one?",
            "type": "select",
            "choices": [
                {"choice_id": "left", "label": "Left"},
                {"choice_id": "right", "label": "Right"}
            ]
        }),
    )
    .await;
    assert!(!failed, "the question was created: {created}");
    assert_eq!(created["state"], "pending", "{created}");
    let question_id = created["question_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let token = created["caller_token"]
        .as_str()
        .expect("a token")
        .to_owned();

    // This release's `kr` does not read the worker: the question is not among its questions, and
    // the session it did not read is named with the `kr` that reads it.
    let listed = host.run(&updated.kr_now(), &["--json", "question", "list"]);
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("a document");
    assert_eq!(listed["questions"], json!([]), "{listed}");
    assert_eq!(
        listed["unread"].as_array().map(Vec::len),
        Some(1),
        "{listed}"
    );
    let refused = host.run(
        &updated.kr_now(),
        &["question", "answer", &question_id, "--other", "neither"],
    );
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        !refused.status.success(),
        "this release's kr does not answer it: {said}"
    );
    assert!(
        said.contains(&updated.kr_before().display().to_string()),
        "and it names the kr that reads the worker: {said}"
    );

    // The release before's `kr` lists and answers it.
    let theirs = host.run(&updated.kr_before(), &["--json", "question", "list"]);
    assert!(
        theirs.status.success(),
        "{}",
        String::from_utf8_lossy(&theirs.stderr)
    );
    let theirs: Value = serde_json::from_slice(&theirs.stdout).expect("a document");
    assert_eq!(
        theirs["questions"][0]["question_id"],
        question_id.as_str(),
        "{theirs}"
    );
    let answered = host.run(
        &updated.kr_before(),
        &[
            "question",
            "answer",
            &question_id,
            "--other",
            "neither",
            "--json",
        ],
    );
    assert!(
        answered.status.success(),
        "the release before's kr answers: {}",
        String::from_utf8_lossy(&answered.stderr)
    );

    let (waited, failed) = call_tool(
        &client,
        "wait_for_answer",
        json!({"question_id": question_id, "caller_token": token, "wait_seconds": 20}),
    )
    .await;
    assert!(!failed, "the wait answered: {waited}");
    assert_eq!(waited["state"], "answered", "{waited}");
    assert_eq!(waited["answer"]["text"], "neither", "{waited}");

    updated.the_worker_is_as_it_was().await;
    drop(client);
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// The catalogue's own builder of signed generations, for a package this suite writes.
#[allow(dead_code)]
#[path = "../../kr-plugin-catalogue/tests/support/mod.rs"]
mod generations;

/// The variable that makes a placed copy of this binary a program a person starts in a session: it
/// sleeps for as many seconds as it names.
const STAND_IN: &str = "KR_RUNTIME_STAND_IN";

/// The variable naming a file the program writes its process number to once it runs.
const STAND_IN_RUNNING: &str = "KR_RUNTIME_STAND_IN_RUNNING";

/// The stand-in program's body. Run by the test harness with nothing set, it does nothing.
#[test]
fn the_stand_in_program() {
    if let Ok(seconds) = std::env::var(STAND_IN) {
        if let Some(running) = std::env::var_os(STAND_IN_RUNNING) {
            std::fs::write(running, std::process::id().to_string()).expect("says it is running");
        }
        let until = Instant::now() + Duration::from_secs(seconds.parse().unwrap_or(60));
        std::thread::sleep(until.saturating_duration_since(Instant::now()));
    }
}

fn the_plugin() -> kr_protocol::ids::PluginId {
    kr_protocol::ids::PluginId::new("kalareach/example-declarative").expect("an identifier")
}

fn directory_url(path: &Path) -> url::Url {
    url::Url::from_directory_path(std::fs::canonicalize(path).expect("an existing directory"))
        .expect("an absolute path")
}

/// The example declarative package with the built test component shipped in it, written into
/// `into`. The component is built by `scripts/build-plugin-fixtures.sh`; the suite fails, and does
/// not skip, when it is absent.
fn write_package(into: &Path) {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins");
    let component = std::fs::read(fixtures.join("components/build/well-behaved.wasm"))
        .unwrap_or_else(|error| {
            panic!(
                "the test component is not built ({error}); run scripts/build-plugin-fixtures.sh"
            )
        });
    let example = fixtures.join("valid/example-declarative");
    std::fs::create_dir_all(into).expect("a package directory");
    std::fs::copy(
        example.join("presentation.json"),
        into.join("presentation.json"),
    )
    .expect("the presentation");
    let mut manifest: Value = serde_json::from_slice(
        &std::fs::read(example.join("plugin.json")).expect("the example manifest"),
    )
    .expect("a manifest");
    manifest["payloads"]
        .as_array_mut()
        .expect("the manifest lists its payloads")
        .push(json!({
            "role": "component",
            "path": "component.wasm",
            "digest": kr_plugin_sdk::digest::PayloadDigest::of(&component).to_string(),
            "size_bytes": component.len().to_string(),
        }));
    std::fs::write(
        into.join("plugin.json"),
        serde_json::to_vec_pretty(&manifest).expect("a manifest"),
    )
    .expect("the manifest");
    std::fs::write(into.join("component.wasm"), component).expect("the component");
}

/// Enrols a repository holding the package as the owner acting directly, synchronises it, and
/// installs and enables the package, before any daemon opens the catalogue.
async fn install_plugin(host: &Host) {
    use kr_plugin_catalogue::transport::RepositoryTransport;
    use kr_plugin_catalogue::{
        CapabilityCeiling, Catalogue, Enrolment, InstallationGrant, RepositoryId, RepositoryKind,
    };

    let published = tempfile::tempdir().expect("a directory on the internal disk");
    let package = published.path().join("package");
    write_package(&package);
    let generation = generations::Generation::build(
        published.path(),
        generations::GenerationSpec {
            package: Some(package),
            ..generations::GenerationSpec::default()
        },
    )
    .await;
    let environment = host.tree.environment();
    let directory = generation.directory();
    let mut catalogue = Catalogue::open(
        &environment.state_dir().join("catalogue"),
        Arc::new(RepositoryTransport::local_only(
            "this test reads its repository from disk",
        )),
    )
    .expect("an openable catalogue");
    let id = RepositoryId::new("development").expect("an identifier");
    catalogue
        .enrol(
            Enrolment::new(
                id.clone(),
                RepositoryKind::Local,
                directory_url(&directory.join("metadata")),
                directory_url(&directory.join("targets")),
                std::fs::read(directory.join("root.json")).expect("a trust root"),
                kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrollable repository"),
            true,
        )
        .expect("the owner adopted the root");
    catalogue.sync(&id).await.expect("a generation");
    let version = kr_plugin_sdk::version::PackageVersion::parse("0.1.0").expect("a version");
    let digest = catalogue
        .index(&id)
        .expect("activated")
        .find(&the_plugin(), &version)
        .expect("the package")
        .manifest_digest;
    catalogue
        .install(
            &id,
            host.tree.environment_id(),
            &the_plugin(),
            &version,
            digest,
            InstallationGrant::none(),
        )
        .await
        .expect("installed");
    catalogue
        .set_enabled(host.tree.environment_id(), &the_plugin(), true)
        .await
        .expect("enabled");
}

/// Waits for `check` to give something, and fails with `what` when it never does.
async fn until<T, F, Fut>(what: &str, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let started = Instant::now();
    loop {
        if let Some(found) = check().await {
            return found;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {:?} for {what}",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

impl Host {
    /// The process of the plugin runtime this host's environment publishes, when one is.
    fn plugin_host(&self) -> Option<kr_protocol::identity::ProcessStartIdentity> {
        kr_plugin_service::launcher::read_descriptor(&self.tree.environment())
            .ok()
            .flatten()
            .map(|descriptor| descriptor.process_start_identity)
    }

    /// What the plugin runtime says it holds, asked as a connection of this test's own.
    async fn plugin_health(&self) -> Option<kr_plugin_service::protocol::HostHealth> {
        let client = kr_plugin_service::client::PluginClient::connect(&self.tree.environment())
            .await
            .ok()?;
        client.health().await.ok()
    }

    /// Waits until the plugin runtime holds `bindings` bindings, and returns what it reports.
    async fn plugin_holding(&self, bindings: u64) -> kr_plugin_service::protocol::HostHealth {
        until("the plugin runtime to hold the bindings", || async {
            self.plugin_health()
                .await
                .filter(|health| health.live_bindings == bindings)
        })
        .await
    }

    /// Ends the plugin runtime this host's environment publishes, by the process recorded for it.
    async fn end_the_plugin_host(&self) {
        let Some(runtime) = self.plugin_host() else {
            return;
        };
        let ended = Command::new("kill")
            .arg(runtime.pid.get().to_string())
            .status()
            .expect("kill runs");
        assert!(ended.success(), "the recorded runtime is ended");
        until("the plugin runtime to end", || async {
            matches!(
                kr_ipc::identity::process_state(&runtime),
                kr_ipc::identity::ProcessState::Ended
            )
            .then_some(())
        })
        .await;
    }

    /// A copy of this test's binary named for the program the example package recognises, placed
    /// on the internal disk.
    fn plugin_agent(&self) -> PathBuf {
        let agent = self.scratch("agent").join("example-agent");
        kr_ipc::testing::place_and_start_once(
            &std::env::current_exe().expect("this test's own binary"),
            &agent,
            &["--exact", "the_stand_in_program", "--test-threads", "1"],
        );
        agent
    }
}

/// The command line a process was started with, as the operating system reports it.
fn command_of(process: &kr_protocol::identity::ProcessStartIdentity) -> String {
    let output = Command::new("ps")
        .args(["-ww", "-o", "args=", "-p", &process.pid.get().to_string()])
        .output()
        .expect("ps runs");
    assert!(output.status.success(), "ps said {}", output.status);
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Types the program the package recognises at a terminal's prompt, and returns its process once
/// it is running. The worker finds the program in the terminal's foreground and binds the package.
async fn start_agent(
    host: &Host,
    typing: &terminal::Terminal,
    agent: &Path,
) -> kr_protocol::identity::ProcessStartIdentity {
    let running = host
        .scratch("agent-running")
        .join(format!("running-{}", kr_ipc::new_uuid()));
    typing.type_line(&format!(
        "{STAND_IN}=300 {STAND_IN_RUNNING}='{}' '{}' --exact the_stand_in_program \
         --test-threads 1 --nocapture",
        running.display(),
        agent.display()
    ));
    let pid = until("the program the line started to run", || async {
        std::fs::read_to_string(&running)
            .ok()
            .and_then(|said| said.trim().parse::<u32>().ok())
    })
    .await;
    kr_ipc::identity::process_start_identity(pid).expect("the program runs")
}

/// KR-REQ-05.06, KR-REQ-26.06, KR-ACC-035: the plugin runtime the release before started outlives
/// the update and serves the worker of a session of this release, which registers with it; and
/// once their programs and that runtime have ended, the next session's worker asks the daemon of
/// this release, which starts a runtime of this release that holds that one binding.
#[tokio::test(flavor = "multi_thread")]
async fn the_plugin_runtime_of_the_release_before_survives_the_update_and_is_replaced_by_this_releases()
 {
    let prepared = Updated::prepare(Setup {
        plugin: true,
        ..Setup::default()
    })
    .await;
    let host_ref = &prepared.host;
    let agent = host_ref.plugin_agent();
    let first = terminal_for(
        host_ref,
        &prepared.kr_before(),
        &["attach", &prepared.display],
    );
    first.ready().await;
    let first_program = start_agent(host_ref, &first, &agent).await;
    host_ref.plugin_holding(1).await;
    let old_runtime = host_ref
        .plugin_host()
        .expect("the release before started a runtime");
    assert!(
        command_of(&old_runtime).contains(&format!(
            "/versions/{}/bin/kr-plugin-host",
            prepared.one.name()
        )),
        "the runtime is the release before's: {}",
        command_of(&old_runtime)
    );

    let updated = prepared.update().await;
    let host = &updated.host;
    assert_eq!(
        host.plugin_host(),
        Some(old_runtime.clone()),
        "the update left the runtime alone"
    );
    host.plugin_holding(1).await;

    // A session of this release: its worker registers with the runtime that is running.
    let (second_display, second_session) = host.new_session(&updated.kr_now());
    let second_worker = host.worker_process(second_session);
    let second = terminal_for(host, &updated.kr_now(), &["attach", &second_display]);
    second.ready().await;
    let second_program = start_agent(host, &second, &agent).await;
    host.plugin_holding(2).await;
    assert_eq!(
        host.plugin_host(),
        Some(old_runtime.clone()),
        "the new worker registered with the runtime of the release before"
    );

    // Both programs end, by the processes recorded for them, and with them their bindings: a
    // worker whose runtime ends asks the daemon for another while its program runs, so nothing
    // is left to ask until the third session's program starts.
    for program in [&first_program, &second_program] {
        let ended = Command::new("kill")
            .arg(program.pid.get().to_string())
            .status()
            .expect("kill runs");
        assert!(ended.success(), "the recorded program is ended");
    }
    host.plugin_holding(0).await;

    // The runtime of the release before ends, by the process recorded for it, and a session
    // created after that gets a runtime of this release.
    host.end_the_plugin_host().await;
    until("the runtime of the release before to end", || async {
        matches!(
            kr_ipc::identity::process_state(&old_runtime),
            kr_ipc::identity::ProcessState::Ended
        )
        .then_some(())
    })
    .await;
    let (third_display, third_session) = host.new_session(&updated.kr_now());
    let third_worker = host.worker_process(third_session);
    let third = terminal_for(host, &updated.kr_now(), &["attach", &third_display]);
    third.ready().await;
    start_agent(host, &third, &agent).await;
    let new_runtime = until("a runtime of this release to be published", || async {
        host.plugin_host()
            .filter(|published| *published != old_runtime)
    })
    .await;
    assert!(
        command_of(&new_runtime).contains(&format!(
            "/versions/{}/bin/kr-plugin-host",
            updated.two.name()
        )),
        "the new runtime is this release's: {}",
        command_of(&new_runtime)
    );
    // The binding it holds is the third session's, the only program that runs.
    host.plugin_holding(1).await;
    assert_eq!(
        host.plugin_host(),
        Some(new_runtime),
        "one runtime serves it"
    );

    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_now(), &third_display);
    host.worker_ended(&third_worker).await;
    host.close(&updated.kr_now(), &second_display);
    host.worker_ended(&second_worker).await;
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
    host.end_the_plugin_host().await;
}

/// KR-REQ-05.06, KR-REQ-26.06, KR-ACC-035: a program the package recognises, started in the session
/// of the release before after the update, makes its worker ask the daemon of this release for the
/// plugin runtime. The daemon starts one of this release, the worker registers with it, and a
/// session of this release registers with the same runtime.
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_of_the_release_before_asks_this_releases_daemon_for_the_plugin_runtime() {
    let updated = Updated::prepare(Setup {
        plugin: true,
        ..Setup::default()
    })
    .await
    .update()
    .await;
    let host = &updated.host;
    assert_eq!(
        host.plugin_host(),
        None,
        "no program has wanted a runtime yet"
    );
    let agent = host.plugin_agent();
    let old = terminal_for(host, &updated.kr_before(), &["attach", &updated.display]);
    old.ready().await;
    start_agent(host, &old, &agent).await;
    host.plugin_holding(1).await;
    let runtime = host.plugin_host().expect("the daemon started a runtime");
    assert!(
        command_of(&runtime).contains(&format!(
            "/versions/{}/bin/kr-plugin-host",
            updated.two.name()
        )),
        "the runtime is this release's: {}",
        command_of(&runtime)
    );

    // A session of this release registers with the runtime that is running.
    let (display, session_id) = host.new_session(&updated.kr_now());
    let worker = host.worker_process(session_id);
    let now = terminal_for(host, &updated.kr_now(), &["attach", &display]);
    now.ready().await;
    start_agent(host, &now, &agent).await;
    host.plugin_holding(2).await;
    assert_eq!(host.plugin_host(), Some(runtime), "one runtime serves both");

    updated.the_worker_is_as_it_was().await;
    // The sessions end before the runtime does: a worker whose runtime ends while its program
    // runs asks for another, and nothing here would end that one.
    host.close(&updated.kr_now(), &display);
    host.worker_ended(&worker).await;
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
    host.end_the_plugin_host().await;
}

/// KR-REQ-05.06, KR-REQ-26.06, KR-ACC-035: the plugin runtime of the release before ends while a
/// program the package recognises still runs in the session of the release before. The worker,
/// left without a runtime, asks the daemon of this release for another; the daemon starts one of
/// this release and the worker registers with it, so the program's binding survives the end of the
/// runtime that held it.
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_of_the_release_before_registers_again_with_the_runtime_of_this_release_when_its_own_ends()
 {
    let prepared = Updated::prepare(Setup {
        plugin: true,
        ..Setup::default()
    })
    .await;
    let agent = prepared.host.plugin_agent();
    let terminal = terminal_for(
        &prepared.host,
        &prepared.kr_before(),
        &["attach", &prepared.display],
    );
    terminal.ready().await;
    start_agent(&prepared.host, &terminal, &agent).await;
    prepared.host.plugin_holding(1).await;
    let old_runtime = prepared
        .host
        .plugin_host()
        .expect("the release before started a runtime");

    let updated = prepared.update().await;
    let host = &updated.host;
    host.plugin_holding(1).await;
    assert_eq!(
        host.plugin_host(),
        Some(old_runtime.clone()),
        "the update left the runtime alone"
    );

    // The runtime of the release before ends, by the process recorded for it, with the program
    // still running.
    host.end_the_plugin_host().await;
    let new_runtime = until("a runtime of this release to be published", || async {
        host.plugin_host()
            .filter(|published| *published != old_runtime)
    })
    .await;
    assert!(
        command_of(&new_runtime).contains(&format!(
            "/versions/{}/bin/kr-plugin-host",
            updated.two.name()
        )),
        "the new runtime is this release's: {}",
        command_of(&new_runtime)
    );
    // The binding the new runtime holds is the one the worker of the release before registered.
    host.plugin_holding(1).await;
    assert_eq!(
        host.plugin_host(),
        Some(new_runtime),
        "one runtime serves it"
    );

    updated.the_worker_is_as_it_was().await;
    drop(terminal);
    host.close(&updated.kr_now(), &updated.display);
    host.worker_ended(&updated.worker).await;
    host.end_the_plugin_host().await;
}

/// KR-REQ-26.06, KR-ACC-029, KR-ACC-035: what the worker of the release before wrote to the
/// session's terminal is kept by the daemon of this release when the session closes, and `kr
/// export` of this release reads it back through the daemon.
#[tokio::test(flavor = "multi_thread")]
async fn the_output_of_a_session_of_the_release_before_is_exported_through_the_daemon_of_this_release()
 {
    let updated = Updated::new().await;
    let host = &updated.host;
    let typing = terminal_for(host, &updated.kr_before(), &["attach", &updated.display]);
    typing.ready().await;
    // The shell computes the marker, so the line as typed does not hold it.
    typing.type_line("echo KEPT-$((6*7))-OUTPUT");
    typing.expect("KEPT-42-OUTPUT").await;
    drop(typing);

    host.close(&updated.kr_now(), &updated.display);
    host.worker_ended(&updated.worker).await;
    let file = host.scratch("export").join("session.json");
    // The daemon refuses an export until it has seen the worker end and has the session's output.
    let started = Instant::now();
    loop {
        let output = host.run(
            &updated.kr_now(),
            &[
                "export",
                &updated.session_id.to_string(),
                "--output",
                &file.display().to_string(),
            ],
        );
        if output.status.success() {
            break;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the closed session was not exported in {:?}: {}",
            started.elapsed(),
            String::from_utf8_lossy(&output.stderr)
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let document: Value = serde_json::from_slice(&std::fs::read(&file).expect("the exported file"))
        .expect("the export is one JSON document");
    assert_eq!(
        document["session"]["session_id"],
        updated.session_id.to_string(),
        "{document}"
    );
    let mut output = Vec::new();
    for chunk in document["output"]["chunks"]
        .as_array()
        .expect("the retained output is a list of pieces")
    {
        use base64::Engine as _;
        output.extend(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(chunk["base64url"].as_str().expect("base64 text"))
                .expect("the piece decodes"),
        );
    }
    assert!(
        String::from_utf8_lossy(&output).contains("KEPT-42-OUTPUT"),
        "the export holds what the session showed: {}",
        String::from_utf8_lossy(&output).escape_debug()
    );
    // The closure the worker gave to the close this test asked for, not one the daemon wrote for a
    // worker that was lost.
    assert_eq!(
        document["closure"]["reason"], "close_requested",
        "and the worker's closure: {document}"
    );
    assert_eq!(
        document["closure"]["session_id"],
        updated.session_id.to_string(),
        "{document}"
    );
}

/// KR-REQ-23.34, KR-REQ-26.06, KR-ACC-035: the `kr` of the release before issues a share of its
/// session with the live screen to a paired device, at a terminal. The daemon of this release reads
/// the lines on the screen from the worker of the release before, as the share asks, and holds the
/// share, which `kr share list` of this release shows.
#[tokio::test(flavor = "multi_thread")]
async fn a_share_with_the_live_screen_of_the_session_of_the_release_before_is_issued_through_the_daemon_of_this_release()
 {
    let updated = Updated::on_the_network().await;
    let host = &updated.host;
    let controller = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let environment_id = host.tree.environment_id();
    let owner = door::Door::pair_the_first_owner(&controller, environment_id).await;
    owner
        .pair_a_guest(&controller, environment_id, "A guest phone")
        .await;

    let issuing = terminal_for(
        host,
        &updated.kr_before(),
        &[
            "share",
            "invite",
            &updated.display,
            "--to",
            "A guest phone",
            "--live",
        ],
    );
    issuing.expect("to issue this invitation").await;
    issuing.type_line("share");
    let code = issuing.ended().await;
    assert_eq!(
        code,
        0,
        "the release before's kr issued the share: {}",
        issuing.text().escape_debug()
    );

    let listed = host.run(&updated.kr_now(), &["--json", "share", "list"]);
    assert!(
        listed.status.success(),
        "kr share list: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("a document");
    let held: Vec<&Value> = listed["grants"]
        .as_array()
        .expect("a list of shares")
        .iter()
        .filter(|share| share["recipient_name"] == "A guest phone")
        .collect();
    assert_eq!(held.len(), 1, "the guest holds the share: {listed}");
    assert_eq!(held[0]["live_screen"], true, "{listed}");

    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_now(), &updated.display);
    host.worker_ended(&updated.worker).await;
    drop(owner);
}
