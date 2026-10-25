//! A Windows host that ran the release before in place, moved to this release's store beside a live
//! session of the release before.
//!
//! The release before this one is built from its own commit, in a tree and a target directory of
//! its own, and run in place as a Windows host runs a build: its `kr` registers the environment's
//! task, the task starts its control daemon, and a session gets its worker. This build's release is
//! then installed into a store beside the running daemon, the task is repaired to name this
//! release, and an update hands the daemon of the release before over to this release's daemon.
//! The session's worker is then a worker of the release before, beside a daemon of this one.
//!
//! The release before cannot install or update a host on Windows, and holds nothing on its release,
//! so what this shows is the daemon's handover and the adoption of a worker of an older level, not
//! the hold of a release by a worker of the release before.
//!
//! The release before is whatever `retained/<level>/RELEASE` of the retained surface names. A commit
//! that is not there, or a build of it that fails, fails the suite: nothing here skips. The suite is
//! behind the `upgrade-suite` feature, because building a second tree takes a long time and a
//! network.

#![cfg(windows)]
#![allow(dead_code, unused_imports)]

mod stored_formats;
mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;

include!("support/update_harness.rs");

/// The programs the release before runs from.
const PREVIOUS_PROGRAMS: [&str; 6] = [
    "kr",
    "kr-attach-guard",
    "kr-controller",
    "kr-worker",
    "kr-hook",
    "kr-plugin-host",
];

/// A line `name=value` of the record of a release.
fn recorded(record: &str, name: &str) -> String {
    record
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("the release record has no {name}: {record}"))
        .to_owned()
}

/// Where the tree of the release before is built and kept between runs.
fn cache_root() -> PathBuf {
    std::env::var_os("KR_UPGRADE_CACHE")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("LOCALAPPDATA")
                .map(|base| PathBuf::from(base).join("kalareach-upgrade"))
        })
        .expect("a place for the cache")
}

/// The level the retained surface holds newest: the level of the release before this one.
fn retained_level() -> &'static kr_protocol::retained::RetainedLevel {
    kr_protocol::retained::RETAINED
        .iter()
        .max_by_key(|level| level.level)
        .expect("a level is retained")
}

/// Builds the programs of `commit` in a tree and a target directory of their own under the cache,
/// and returns the directory they are in.
///
/// The commit has to be in this checkout's repository: a checkout without it fails here, and so does
/// a build that fails. A stamp of the commit and the compiler is written once the tree is extracted,
/// so a tree is extracted once; the build is run every time, and takes seconds when nothing changed.
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
    if !std::fs::read_to_string(place.join("stamp")).is_ok_and(|kept| kept == stamp) {
        if place.exists() {
            std::fs::remove_dir_all(&place).expect("an old tree goes");
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
            "the release before is not in this repository: git archive {commit} said {status}"
        );
        std::fs::write(place.join("stamp"), &stamp).expect("the stamp");
    }
    // The environment is this process's without what a test run sets for this tree, so the older
    // tree builds with its own settings and the toolchain it pins.
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
    place.join("target").join("debug")
}

/// The release before, built once for the whole run: its name, and the directory of its programs.
fn previous() -> &'static (ReleaseName, PathBuf) {
    static PREVIOUS: OnceLock<(ReleaseName, PathBuf)> = OnceLock::new();
    PREVIOUS.get_or_init(|| {
        let level = retained_level();
        (
            release(&recorded(level.release, "release")),
            build_previous(&recorded(level.release, "commit")),
        )
    })
}

/// This build's release as it names the levels it speaks at: every level this build retains.
fn retaining_every_level(mut release: Assembled) -> Assembled {
    release.manifest.retained_levels = kr_protocol::retained::levels();
    release
}

/// KR-REQ-26.06, KR-REQ-26.10: a host that ran the release before in place is moved to a store of
/// this release while a session's worker runs the release before. The first install leaves the
/// daemon of the release before running, the repaired task names this release, and an update hands
/// that daemon over: the new daemon is of the new release, the worker is the process it was, the
/// new daemon lists the session and closes it, and the worker ends.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_hands_the_daemon_of_the_release_before_over_and_its_worker_goes_on() {
    let (_, built) = previous();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = retaining_every_level(Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2));
    let mut host = Host::bare();

    // The release before, run in place: its task, its daemon, and a session.
    let before = host.scratch("before").join("bin");
    std::fs::create_dir_all(&before).expect("a directory");
    for name in PREVIOUS_PROGRAMS {
        kr_ipc::testing::place_program(&built.join(exe(name)), &before.join(exe(name)));
    }
    let before_kr = before.join(exe("kr"));
    let registered = host.run(&before_kr, &["host", "startup", "--set", "standalone"]);
    assert!(
        registered.status.success(),
        "the release before registers the task: {}",
        String::from_utf8_lossy(&registered.stderr)
    );
    host.start_daemon_by_task(&before.join(exe("kr-controller")))
        .await;
    let (display, session) = host.new_session(&before_kr);
    let worker = host.worker_process(session);

    // This build's release goes into a store beside the daemon, which keeps running; the task is
    // repaired to name it; and an update hands the daemon of the release before over.
    host.install(&one);
    // A daemon of a store records the roots it serves there, which is how an update finds the
    // environment. The release before keeps no store on Windows and records nothing, so the roots
    // are recorded here as a daemon of the store would have recorded them.
    host.store
        .record_roots(
            host.tree.paths().runtime_root(),
            host.tree.paths().state_root(),
        )
        .expect("the roots are recorded");
    host.register_the_standalone_start();
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.zip");
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
        said["restarted"],
        serde_json::json!([host.tree.environment_id().to_string()]),
        "{said}"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the daemon the task started is of the new release"
    );
    assert_eq!(
        host.worker_process(session),
        worker,
        "the worker is the process it was"
    );
    assert_eq!(
        kr_ipc::identity::process_state(&worker),
        kr_ipc::identity::ProcessState::Running,
        "and it runs on"
    );

    // The new daemon lists the session it adopted, and closes it.
    let kr = host.store.stable(Program::Kr);
    let listed = host.run(&kr, &["--json", "list"]);
    assert!(
        listed.status.success(),
        "kr list: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains(&session.to_string()),
        "the session is listed: {}",
        String::from_utf8_lossy(&listed.stdout)
    );
    host.close(&kr, &display);
    host.worker_ended(&worker).await;
}
