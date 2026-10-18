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

include!("support/update_harness.rs");

/// The release before this one, built from its commit.
struct Previous {
    /// The release's name, from the retained surface's record of it.
    release: ReleaseName,
    /// The compatibility level it speaks.
    level: CompatibilityLevel,
    /// Its programs, copied once to the internal disk.
    programs: &'static [(&'static str, PathBuf, Digest256, u64)],
}

impl Previous {
    /// A release of the release before's own programs, at its own level, carrying this process's
    /// channel root.
    fn assembled(&self, sequence: u64) -> Assembled {
        let version = PackageVersion::new(self.level.major(), self.level.minor().unwrap_or(0), 0);
        Assembled::of_programs(
            self.programs,
            self.release.as_str(),
            sequence,
            (self.level, version),
            the_root(),
        )
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
        let level = &kr_protocol::retained::RETAINED[0];
        let record = level.release;
        let commit = recorded(record, "commit");
        let release = release(&recorded(record, "release"));
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

/// Builds the programs of `commit` in a tree and a target directory of their own under the cache,
/// unless an earlier run built them from the same commit with the same compiler, and returns the
/// directory they are in.
///
/// One run at a time builds a commit, under a lock. A stamp of the commit and the compiler is
/// written once the tree is extracted, and the build is made when a program is missing. Any other
/// commit's tree is removed.
fn build_previous(commit: &str) -> PathBuf {
    let cache = cache_root();
    std::fs::create_dir_all(&cache).expect("the cache directory");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(cache.join(".lock"))
        .expect("the cache's lock");
    lock.lock().expect("the cache's lock is taken");
    let toolchain = Command::new("rustc")
        .arg("-vV")
        .output()
        .expect("rustc runs");
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
    if !PREVIOUS_PROGRAMS
        .iter()
        .all(|name| programs.join(name).is_file())
    {
        // The packages build every binary they have: the release before is these programs of it.
        let output = Command::new("cargo")
            .current_dir(&tree)
            .env_clear()
            .envs(std::env::vars().filter(|(name, _)| {
                !name.starts_with("CARGO_") || name == "CARGO_HOME" || name.starts_with("CARGO_NET")
            }))
            .env_remove("RUSTFLAGS")
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
}

impl Updated {
    async fn new() -> Self {
        let before = previous();
        let one = before.assembled(1);
        let two =
            Assembled::at_this_level("0.75.0+bbbbbbbbbbbb", 2).retaining_what_this_build_does();
        let mut host = Host::bare();
        host.install(&one);
        let started_through_current = host.store.stable(Program::Controller);
        host.start_daemon(&started_through_current).await;
        let (display, session_id) = host.new_session(&host.program(one.name(), Program::Kr));
        let worker = host.worker_process(session_id);
        assert_eq!(
            host.worker_build(session_id).await,
            format!("kr-worker/{}", one.name()),
            "the session's worker is the release before's"
        );

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
        let updated = Self {
            host,
            one,
            two,
            display,
            session_id,
            worker,
        };
        updated.the_worker_is_as_it_was().await;
        updated
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
    let (display, _) = host.new_session(&updated.kr_now());
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
    host.close(&updated.kr_now(), &display);

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
