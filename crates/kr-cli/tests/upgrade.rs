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
}

impl Updated {
    async fn new() -> Self {
        let before = previous();
        let one = before.assembled(1);
        let two = Assembled::at_this_level(&format!("{PACKAGE_VERSION}+bbbbbbbbbbbb"), 2)
            .retaining_what_this_build_does();
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
