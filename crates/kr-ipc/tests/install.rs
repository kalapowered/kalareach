//! A program of an installed release, run as a process: which release it finds it runs, and the
//! hold it keeps on that release until it exits.
//!
//! The program is this test binary itself, placed in a store of the test's own on the internal
//! disk and started through the store's `current` link with one test selected. That test does
//! nothing unless [`HELPER`] names a directory; then it waits there for word to go on, and writes
//! down what it found about itself.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_ipc::install::{Program, Running, Store, WriteRefused, Written};
use kr_protocol::update::ReleaseName;

/// The variable that makes the helper test act, naming the directory it talks through.
const HELPER: &str = "KR_INSTALL_TEST_HELPER";

/// How long anything here waits for the other side.
const WAIT: Duration = Duration::from_secs(60);

/// What the helper does when it is started as a program of a release.
///
/// It reads what it runs first, as every host executable does, then waits for `go` so the test
/// can change the store underneath it, and then writes what it found: its image as the kernel
/// records it, the release it holds, and the path it was started as.
#[test]
fn helper() {
    let Some(directory) = std::env::var_os(HELPER).map(PathBuf::from) else {
        return;
    };
    let running = kr_ipc::install::this_process().map_err(ToString::to_string);
    std::fs::write(directory.join("started"), b"").expect("says it started");
    let deadline = Instant::now() + WAIT;
    while !directory.join("go").exists() {
        assert!(Instant::now() < deadline, "nobody said go");
        std::thread::sleep(Duration::from_millis(20));
    }
    let image = kr_ipc::install::image_path().expect("the image");
    let release = match &running {
        Ok(running) => running
            .release()
            .map_or("outside", ReleaseName::as_str)
            .to_owned(),
        Err(error) => format!("refused: {error}"),
    };
    let started_as = std::env::current_exe().expect("the path it was started as");
    // Written whole under another name and then given its own, so that the test, which goes on
    // as soon as `said` exists, never reads a file that is there and not yet written.
    let writing = directory.join("said.part");
    std::fs::write(
        &writing,
        format!("{}\n{release}\n{}\n", image.display(), started_as.display()),
    )
    .expect("writes what it found");
    std::fs::rename(&writing, directory.join("said")).expect("says what it found");
    // Held until this process ends, as every host executable holds its release.
    while !directory.join("end").exists() {
        assert!(Instant::now() < deadline, "nobody said end");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A store of this test's own, with its record, removed with it.
struct TestStore {
    root: PathBuf,
    store: Store,
}

impl TestStore {
    fn create() -> Self {
        let root = std::env::temp_dir().join(format!("kr-install-{}", kr_ipc::new_uuid()));
        let store = Store::at(root.join("host"));
        store.create_directories().expect("the store's directories");
        std::fs::write(store.record(), b"{}\n").expect("the store's record");
        Self { root, store }
    }

    /// Puts a release in the store: this test binary as its `kr`, and its manifest.
    fn install(&self, release: &ReleaseName) -> PathBuf {
        let directory = self.store.release_directory(release);
        std::fs::create_dir_all(directory.join("bin")).expect("the release's bin");
        std::fs::write(self.store.manifest(release), manifest(release)).expect("the manifest");
        let program = directory.join("bin").join(Program::Kr.file_name());
        kr_ipc::testing::place_program(
            &std::env::current_exe().expect("this test binary"),
            &program,
        );
        program
    }

    /// What a command of this store works in: roots of its own beside the store.
    fn writing(&self) -> kr_ipc::install::Writing {
        kr_ipc::install::Writing::in_roots(self.root.join("run"), self.root.join("state"))
    }

    /// Makes a release current, under the locks every switch is made under.
    fn switch(&self, release: &ReleaseName) {
        let update = self
            .store
            .try_lock_update()
            .expect("locks")
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
        self.store
            .switch(release, &update, &install, &writers)
            .expect("the release is current");
    }
}

impl Drop for TestStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn manifest(release: &ReleaseName) -> String {
    serde_json::json!({
        "signed": {
            "_type": "kalareach-release",
            "release": release,
            "sequence": "1",
            "commit": "4254aa6e62e585478ff8dcff5518f23c7263f4ce",
            "target": "aarch64-apple-darwin",
            "os_floor": { "system": "macos", "version": "14.0" },
            "protocol_version": { "major": 0, "minor": 48, "patch": 0 },
            "public_majors": [1],
            "retained_levels": ["0.48"],
            "shells": [],
            "agents": [],
            "dependencies": { "lock_sha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "pinned": [], "vectors": [] },
            "stores": [{
                "store": "registry",
                "scope": "environment",
                "path": "registry.sqlite",
                "recording": { "kind": "sqlite_table", "table": "schema_version" },
                "version": 7,
                "migrates_from": 1,
            }],
            "files": [],
        },
        "signatures": [],
    })
    .to_string()
}

fn release(name: &str) -> ReleaseName {
    ReleaseName::new(name).expect("a release name")
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + WAIT;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "{} did not appear",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Waits for `path` to appear, and fails at once, saying how, if `child` ends first.
fn wait_for_unless_ended(path: &Path, child: &mut std::process::Child) {
    let deadline = Instant::now() + WAIT;
    while !path.exists() {
        if let Some(status) = child.try_wait().expect("asks the child") {
            panic!(
                "the program ended ({status}) before {} appeared",
                path.display()
            );
        }
        assert!(
            Instant::now() < deadline,
            "{} did not appear",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// KR-REQ-26.06: a program started through `current` runs the release it started from, and holds
/// it, even after `current` names another release; the release goes only once it has exited.
#[test]
fn a_program_started_through_current_keeps_its_release_after_the_switch() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let two = release("0.2.0+bbbbbbbbbbbb");
    let program = test.install(&one);
    test.install(&two);
    test.switch(&one);
    let talk = test.root.join("talk");
    std::fs::create_dir(&talk).expect("a directory to talk through");
    let mut child = std::process::Command::new(test.store.stable(Program::Kr))
        .args(["--exact", "helper", "--nocapture", "--test-threads", "1"])
        .env(HELPER, &talk)
        .current_dir(&test.root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the program starts through current");
    wait_for(&talk.join("started"));

    // The update happens while the program runs.
    test.switch(&two);
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");
    assert!(
        !test.store.retire(&one, &update).expect("asks"),
        "the release a running program holds is not removed"
    );
    std::fs::write(talk.join("go"), b"").expect("go");
    wait_for(&talk.join("said"));
    let said = std::fs::read_to_string(talk.join("said")).expect("what it found");
    let mut lines = said.lines();
    let image = PathBuf::from(lines.next().expect("its image"));
    let held_release = lines.next().expect("its release");
    let started_as = PathBuf::from(lines.next().expect("the path it was started as"));
    let expected = std::fs::canonicalize(&program).expect("the program's own path");
    assert_eq!(
        std::fs::canonicalize(&image).expect("its image resolves"),
        expected,
        "the kernel names the program of the release it started from"
    );
    assert_eq!(
        held_release,
        one.as_str(),
        "it holds the release it started from"
    );
    // The control, where it shows: macOS and Windows say the path the program was started as, and
    // that path resolves to the other release once `current` has moved on, which is why no program
    // asks it.
    if cfg!(any(target_os = "macos", windows)) {
        assert_eq!(started_as, test.store.stable(Program::Kr));
        assert_ne!(
            std::fs::canonicalize(&started_as).expect("resolves"),
            expected,
            "the path as started now names the other release's program"
        );
    }
    std::fs::write(talk.join("end"), b"").expect("end");
    let status = child.wait().expect("the program ends");
    assert!(status.success(), "the helper ran as asked: {status}");
    assert!(
        test.store.retire(&one, &update).expect("removes"),
        "once it has exited, nothing holds the release and it goes"
    );
    assert!(!test.store.release_directory(&one).exists());
    assert!(test.store.release_directory(&two).exists());
}

/// A build outside a store is what it always was: its programs are the ones beside it, and it
/// holds nothing.
#[test]
fn a_program_outside_a_store_finds_its_programs_beside_it() {
    let image = kr_ipc::install::image_path().expect("this test's image");
    let running = Running::of_image(&image).expect("outside a store");
    assert_eq!(running.release(), None);
    let beside = image.with_file_name(Program::Worker.file_name());
    assert_eq!(running.own(Program::Worker), beside);
    assert_eq!(running.stable(Program::Worker), beside);
    assert_eq!(running.shells(), None);
}

/// KR-REQ-26.10: the writers' lock is shared by commands that write and exclusive to an update. Any
/// number of commands hold it at once and an update cannot take it meanwhile; an update that holds it
/// keeps a command waiting until the command's wait ends, and the command says once that it waits.
#[test]
fn the_writers_lock_is_shared_by_commands_and_exclusive_to_an_update() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);
    test.switch(&one);
    let mut waits = 0;
    let first = test
        .store
        .hold_writers(None, &test.writing(), Duration::from_secs(1), &mut || {
            waits += 1
        })
        .expect("a command holds the lock");
    let second = test
        .store
        .hold_writers(None, &test.writing(), Duration::from_secs(1), &mut || {
            waits += 1
        })
        .expect("another command holds it at once");
    assert_eq!(waits, 0, "neither waited");
    assert!(
        test.store.try_lock_writers().expect("asks").is_none(),
        "an update cannot take the lock while a command holds it"
    );
    drop((first, second));

    let update = test
        .store
        .try_lock_writers()
        .expect("asks")
        .expect("an update takes it once no command holds it");
    let refused = test.store.hold_writers(
        None,
        &test.writing(),
        Duration::from_millis(100),
        &mut || waits += 1,
    );
    assert!(
        matches!(refused, Err(WriteRefused::Switching)),
        "a command that waits the whole wait is refused: {refused:?}"
    );
    assert_eq!(waits, 1, "and said once that it waited");
    drop(update);
    test.store
        .hold_writers(
            None,
            &test.writing(),
            Duration::from_millis(100),
            &mut || waits += 1,
        )
        .expect("a command holds the lock once the update lets go");
    assert_eq!(waits, 1);
}

/// KR-REQ-26.10: a record is permitted at the version the release `current` names lists for it and at
/// no other; a record the release does not list is one it does not read, and any version goes. A
/// permit is for one record, and a store with no current release permits nothing.
#[test]
fn a_record_is_permitted_only_at_the_version_the_current_release_lists() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);

    let nothing = test.store.hold_writers(
        None,
        &test.writing(),
        Duration::from_millis(100),
        &mut || {},
    );
    assert!(
        matches!(nothing, Err(WriteRefused::Store(_))),
        "a store with no current release holds nothing: {nothing:?}"
    );

    test.switch(&one);
    let writers = test
        .store
        .hold_writers(
            Some(&one),
            &test.writing(),
            Duration::from_secs(1),
            &mut || {},
        )
        .expect("holds");
    let listed = Written::new("registry", 7);
    let permit = writers.permit(&listed).expect("the version it lists");
    assert!(permit.require(&listed).is_ok());
    assert!(
        matches!(
            permit.require(&Written::new("unlisted", 7)),
            Err(WriteRefused::WrongRecord { .. })
        ),
        "a permit is for the record it was asked for"
    );
    match writers.permit(&Written::new("registry", 8)) {
        Err(WriteRefused::NotWhatCurrentReads {
            store,
            writes,
            reads,
            current,
            own,
        }) => {
            assert_eq!((store, writes, reads), ("registry", 8, 7));
            assert_eq!(current, one);
            assert_eq!(own, Some(one.clone()));
        }
        other => panic!("another version than the release lists is refused: {other:?}"),
    }
    assert!(
        writers.permit(&Written::new("unlisted", 3)).is_ok(),
        "a record the release does not list is not one it reads"
    );
    drop(writers);

    // A program outside a store, as this test binary is, holds nothing and is permitted every record.
    let outside =
        kr_ipc::install::hold_writers(&test.writing(), &mut || {}).expect("holds nothing");
    assert!(outside.permit(&Written::new("registry", 8)).is_ok());
}

/// KR-REQ-26.10: a command registers what it works in before it holds the writers' lock, under the
/// install lock, and a registration never replaces the record of a control daemon's roots. The
/// install lock is not held once the command holds the writers' lock, and a refused command has
/// registered nothing it did not mean to: a registration that cannot be written refuses the command.
#[test]
fn a_command_registers_what_it_works_in_before_it_writes() {
    use kr_protocol::ids::EnvironmentId;
    use kr_protocol::scalars::Uuid;

    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);
    test.switch(&one);
    let environment = EnvironmentId::new(Uuid::from_bytes([7; 16]));
    let first_home = test.root.join("config-one").join("config.json");
    let second_home = test.root.join("config-two").join("config.json");

    // The daemon's record of the same state root is kept apart from the command's.
    test.store
        .record_roots(&test.root.join("daemon-run"), &test.root.join("state"))
        .expect("a daemon records its roots");
    for home in [&first_home, &second_home] {
        let writing = test.writing().with_document(environment, home);
        let writers = test
            .store
            .hold_writers(Some(&one), &writing, Duration::from_secs(1), &mut || {})
            .expect("a command holds the lock");
        assert!(
            test.store.try_lock_install().expect("asks").is_some(),
            "the install lock is let go of once the writers' lock is held"
        );
        drop(writers);
    }
    let daemon = test.store.recorded_roots().expect("reads");
    assert_eq!(daemon.len(), 1, "a command writes no record of a daemon's");
    assert_eq!(daemon[0].runtime_root, test.root.join("daemon-run"));
    let registered = test.store.registered_roots().expect("reads");
    assert_eq!(registered.len(), 1, "one state root, one record");
    assert_eq!(registered[0].runtime_root, test.root.join("run"));
    assert_eq!(registered[0].state_root, test.root.join("state"));
    let documents = test.store.recorded_documents().expect("reads");
    let mut paths: Vec<_> = documents
        .iter()
        .map(|document| document.path.clone())
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        vec![first_home, second_home],
        "two paths for one environment are both kept, as absolute paths"
    );
    assert!(
        documents
            .iter()
            .all(|document| document.environment == environment)
    );

    // A registration that cannot be written refuses the command.
    let roots = test.store.roots();
    std::fs::remove_dir_all(&roots).expect("the records are removed");
    std::fs::write(&roots, b"a file where the directory of records belongs").expect("a file");
    let refused = test.store.hold_writers(
        Some(&one),
        &test.writing(),
        Duration::from_secs(1),
        &mut || {},
    );
    assert!(
        matches!(refused, Err(WriteRefused::Store(_))),
        "a command that cannot register does not hold the lock: {refused:?}"
    );
    assert!(
        test.store.try_lock_writers().expect("asks").is_some(),
        "and holds nothing"
    );
}

/// The variable that makes the launcher test act: the store's root, the release to pin and the
/// directory the program it becomes reports through, one to a line.
#[cfg(unix)]
const PINNING: &str = "KR_INSTALL_TEST_PINNING";

/// What the launcher does when it is started to pin a release and replace itself with a program
/// that takes no hold of its own: the pin passes to the program, or nothing holds the release.
#[cfg(unix)]
#[test]
fn launcher() {
    let Some(text) = std::env::var_os(PINNING) else {
        return;
    };
    let text = text.to_string_lossy().into_owned();
    let mut lines = text.lines();
    let store = Store::at(lines.next().expect("the store"));
    let release = release(lines.next().expect("the release"));
    let ready = lines.next().expect("the file to write once started");
    let pin = store
        .pin(&release)
        .expect("asks")
        .expect("the release is pinned");
    let mut command = std::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(format!("echo started > '{ready}'; exec sleep 600"));
    let error = pin.exec(&mut command);
    panic!("the launcher could not replace itself: {error}");
}

/// KR-REQ-26.06: a program that replaces itself with another passes the hold on its release to it,
/// so a release is held from the moment it is pinned to the moment the program that took over
/// ends, with nothing in between that an update could retire it in.
#[cfg(unix)]
#[test]
fn a_pinned_release_stays_held_by_the_program_that_takes_over() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);
    let ready = test.root.join("ready");
    let mut child = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", "launcher", "--nocapture", "--test-threads", "1"])
        .env(
            PINNING,
            format!(
                "{}\n{one}\n{}\n",
                test.store.root().display(),
                ready.display()
            ),
        )
        .current_dir(&test.root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the launcher starts");
    wait_for(&ready);

    // The program that wrote the file is a shell and then `sleep`, and neither is a program of the
    // release: the only thing that holds it is the pin they inherited.
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");
    assert!(test.store.held(&one).expect("asks"), "the release is held");
    assert!(
        !test.store.retire(&one, &update).expect("asks"),
        "an update does not remove a release a pin is held on"
    );
    child.kill().expect("the program is ended");
    child.wait().expect("the program has ended");
    assert!(
        !test.store.held(&one).expect("asks"),
        "nothing holds it now"
    );
    assert!(
        test.store.retire(&one, &update).expect("removes"),
        "and it goes"
    );
}

/// The variable that makes the launcher test act on Windows: the store's root, the release to pin and
/// the directory the program it runs reports through, one to a line.
#[cfg(windows)]
const PINNING: &str = "KR_INSTALL_TEST_PINNING";

/// What the launcher does when it is started to pin a release and run a program of that release
/// with the pin held: the program is the release's own `kr`, which is this test binary, and it
/// reports through the directory it is given. The launcher waits for it, so its pin is the release's
/// hold until it ends.
#[cfg(windows)]
#[test]
fn launcher() {
    let Some(text) = std::env::var_os(PINNING) else {
        return;
    };
    let text = text.to_string_lossy().into_owned();
    let mut lines = text.lines();
    let store = Store::at(lines.next().expect("the store"));
    let release = release(lines.next().expect("the release"));
    let talk = lines.next().expect("the directory to talk through");
    let pin = store
        .pin(&release)
        .expect("asks")
        .expect("the release is pinned");
    let mut command = std::process::Command::new(
        store
            .release_directory(&release)
            .join("bin")
            .join(Program::Kr.file_name()),
    );
    command
        .args([
            "--exact",
            "stored_child",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(HELPER, talk);
    let error = pin.run(&mut command);
    panic!("the launcher could not run the program: {error}");
}

/// What the program a launcher runs does: it says it started, waits for `go` before it asks what it
/// runs, and writes down whether it was let run, as every host executable asks first thing.
#[cfg(windows)]
#[test]
fn stored_child() {
    let Some(directory) = std::env::var_os(HELPER).map(PathBuf::from) else {
        return;
    };
    std::fs::write(directory.join("started"), b"").expect("says it started");
    wait_for(&directory.join("go"));
    let said = match kr_ipc::install::this_process() {
        Ok(running) => format!(
            "ran {}",
            running.release().map_or("outside", ReleaseName::as_str)
        ),
        Err(error) => format!("refused: {error}"),
    };
    std::fs::write(directory.join("said"), said).expect("says what it found");
    wait_for(&directory.join("end"));
}

/// KR-REQ-26.06: a program that runs another of its release with the release pinned holds the
/// release for as long as it runs it, and an update does not remove the release meanwhile. The
/// pin cannot pass to the program as it does where a program replaces itself, so when the holder is
/// ended first, the program that is left, which has not yet taken a hold of its own, is refused by
/// the release's removal and does not start work in a release that is gone.
#[cfg(windows)]
#[test]
fn a_pinned_release_stays_held_by_the_program_that_takes_over() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);
    let talk = test.root.join("talk");
    std::fs::create_dir(&talk).expect("a directory to talk through");
    let mut launcher =
        std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args(["--exact", "launcher", "--nocapture", "--test-threads", "1"])
            .env(
                PINNING,
                format!(
                    "{}\n{one}\n{}\n",
                    test.store.root().display(),
                    talk.display()
                ),
            )
            .current_dir(&test.root)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("the launcher starts");
    wait_for_unless_ended(&talk.join("started"), &mut launcher);

    // The program has not asked what it runs, so nothing holds the release but the launcher's pin.
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");
    assert!(test.store.held(&one).expect("asks"), "the release is held");
    assert!(
        !test.store.retire(&one, &update).expect("asks"),
        "an update does not remove a release a pin is held on"
    );

    // The launcher ends before the program has a hold of its own.
    launcher.kill().expect("the launcher is ended");
    launcher.wait().expect("the launcher has ended");
    assert!(
        !test.store.held(&one).expect("asks"),
        "nothing holds it now"
    );
    assert!(
        test.store.retire(&one, &update).expect("removes"),
        "and it goes"
    );
    std::fs::write(talk.join("go"), b"").expect("go");
    wait_for(&talk.join("said"));
    let said = std::fs::read_to_string(talk.join("said")).expect("what it found");
    assert!(
        said.starts_with("refused:"),
        "the program of a release that went does not run: {said}"
    );
    std::fs::write(talk.join("end"), b"").expect("end");
}

/// A release that is not there, or that an update is removing, is not pinned and is not waited
/// for.
#[test]
fn a_release_that_is_gone_or_being_removed_is_not_pinned() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let two = release("0.2.0+bbbbbbbbbbbb");
    let removed = release("0.3.0+cccccccccccc");
    test.install(&one);
    test.install(&removed);
    assert!(
        test.store.pin(&two).expect("asks").is_none(),
        "a release the store lacks"
    );
    let pinned = test.store.pin(&one).expect("asks").expect("pinned");
    assert_eq!(pinned.manifest().release, one);
    drop(pinned);

    // An update that has taken the manifest to remove the release holds it exclusively. The
    // release is one this test never pinned: another test of this binary starting a program can
    // hold a copy of a pin's file for a moment after the pin is dropped, and its lock with it.
    let path = test.store.manifest(&removed);
    #[cfg(unix)]
    let removing = {
        let removing = std::fs::File::open(&path).expect("opens");
        rustix::fs::flock(
            &removing,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .expect("the removal's lock");
        removing
    };
    // On Windows the removal holds the manifest open with a share mode that allows nothing.
    #[cfg(windows)]
    let removing = {
        use std::os::windows::fs::OpenOptionsExt as _;

        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .expect("the removal's hold")
    };
    assert!(
        test.store.pin(&removed).expect("asks").is_none(),
        "a release being removed, without waiting for the removal"
    );
    drop(removing);
}

/// The variable that makes the late helper act, naming the directory it talks through.
const LATE: &str = "KR_INSTALL_TEST_LATE";

/// What a program does that is started from a release and asks what it runs only when it is told
/// to go: it says it started, waits, and then writes down whether it was let run.
#[test]
fn late_helper() {
    let Some(directory) = std::env::var_os(LATE).map(PathBuf::from) else {
        return;
    };
    std::fs::write(directory.join("started"), b"").expect("says it started");
    wait_for(&directory.join("go"));
    let said = match kr_ipc::install::this_process() {
        Ok(running) => format!(
            "ran {}",
            running.release().map_or("outside", ReleaseName::as_str)
        ),
        Err(error) => format!("refused: {error}"),
    };
    std::fs::write(directory.join("said"), said).expect("says what it found");
}

/// KR-REQ-26.06: a release that was removed before a program of it took its hold is not run by that
/// program, however late the program asks what it runs: the removal is judged by the program's own
/// image at the moment it asks, and the release is gone or in the trash by then.
#[test]
fn a_program_that_asks_what_it_runs_after_its_release_was_removed_is_refused() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let program = test.install(&one);
    let talk = test.root.join("talk");
    std::fs::create_dir(&talk).expect("a directory to talk through");
    let mut child = std::process::Command::new(&program)
        .args([
            "--exact",
            "late_helper",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(LATE, &talk)
        .current_dir(&test.root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the program starts");
    wait_for_unless_ended(&talk.join("started"), &mut child);

    // Nothing holds the release: the program has not asked what it runs.
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");
    assert!(
        !test.store.held(&one).expect("asks"),
        "nothing holds it yet"
    );
    assert!(
        test.store.retire(&one, &update).expect("removes"),
        "a release nothing holds is removed"
    );
    std::fs::write(talk.join("go"), b"").expect("go");
    let status = child.wait().expect("the program ends");
    assert!(status.success(), "the helper ran as asked: {status}");
    let said = std::fs::read_to_string(talk.join("said")).expect("what it found");
    assert!(
        said.starts_with("refused:"),
        "a program of a release that went does not run: {said}"
    );
}

/// KR-REQ-26.06: `current` always names a release whole while it is switched, to a reader that never
/// stops: a program started through it at any moment finds one release or the other and never
/// neither. Judged by a count of switches, not by how long they take.
#[test]
fn current_names_a_whole_release_at_every_moment_of_a_switch() {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let two = release("0.2.0+bbbbbbbbbbbb");
    test.install(&one);
    test.install(&two);
    test.switch(&one);
    let finished = AtomicBool::new(false);
    let reads = AtomicU32::new(0);
    std::thread::scope(|scope| {
        for _ in 0..3 {
            scope.spawn(|| {
                while !finished.load(Ordering::SeqCst) {
                    let named = test.store.current().expect("current is readable");
                    assert!(named.is_some(), "current names a release");
                    let program = test.store.stable(Program::Kr);
                    assert!(
                        program.is_file(),
                        "the program through current is there: {}",
                        program.display()
                    );
                    reads.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
        for round in 0..200 {
            test.switch(if round % 2 == 0 { &two } else { &one });
        }
        finished.store(true, Ordering::SeqCst);
    });
    assert!(reads.load(Ordering::SeqCst) > 0, "the readers read");
}

/// Seals a release the way an install does: every file read-only and without a right to write it,
/// then every directory, deepest first, without a right to add a name or take one away.
#[cfg(windows)]
fn seal_tree(directory: &Path) {
    let mut directories = vec![directory.to_path_buf()];
    let mut at = 0;
    while at < directories.len() {
        for entry in std::fs::read_dir(&directories[at]).expect("reads") {
            let entry = entry.expect("an entry");
            if entry.file_type().expect("a type").is_dir() {
                directories.push(entry.path());
            } else {
                kr_ipc::install::seal_file(&entry.path()).expect("a file is sealed");
            }
        }
        at += 1;
    }
    for directory in directories.iter().rev() {
        kr_ipc::install::seal_directory(directory).expect("a directory is sealed");
    }
}

/// KR-REQ-26.06: a release that was sealed is not changed by the account that owns it, by any of the
/// ways a program changes a file: nothing is created beside its files or overwritten, appended to,
/// renamed or removed, and its read-only attribute cannot be cleared. Its programs still read and run
/// as they did. The control is the same release before it is sealed, where each change is made.
#[cfg(windows)]
#[test]
fn a_sealed_release_refuses_to_create_or_overwrite_a_file_as_its_owner() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let program = test.install(&one);
    let directory = test.store.release_directory(&one);
    std::fs::create_dir_all(directory.join("share")).expect("a directory");
    std::fs::write(directory.join("share/data"), b"data").expect("a file");

    // The control: an unsealed release is changed in every way.
    let changes = |program: &Path, directory: &Path| -> Vec<(&'static str, bool)> {
        vec![
            (
                "create a file",
                std::fs::File::create_new(directory.join("bin/new")).is_ok(),
            ),
            (
                "overwrite a file",
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(program)
                    .is_ok(),
            ),
            (
                "append to a file",
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(directory.join("share/data"))
                    .is_ok(),
            ),
            (
                "make a directory",
                std::fs::create_dir(directory.join("bin/sub")).is_ok(),
            ),
            (
                "rename a file",
                std::fs::rename(directory.join("share/data"), directory.join("share/moved"))
                    .is_ok(),
            ),
            (
                "remove a file",
                std::fs::remove_file(directory.join("release.json")).is_ok(),
            ),
        ]
    };
    let before = changes(&program, &directory);
    assert!(
        before.iter().all(|(_, made)| *made),
        "an unsealed release is changed in every way: {before:?}"
    );

    // Put the release back as it was, and seal it.
    std::fs::remove_file(directory.join("bin/new")).expect("tidied");
    std::fs::remove_dir(directory.join("bin/sub")).expect("tidied");
    std::fs::rename(directory.join("share/moved"), directory.join("share/data")).expect("tidied");
    std::fs::write(test.store.manifest(&one), manifest(&one)).expect("the manifest again");
    seal_tree(&directory);

    let after = changes(&program, &directory);
    assert!(
        after.iter().all(|(_, made)| !*made),
        "a sealed release is changed in none: {after:?}"
    );
    let mut permissions = std::fs::metadata(&program).expect("there").permissions();
    permissions.set_readonly(false);
    assert!(
        std::fs::set_permissions(&program, permissions).is_err(),
        "the read-only attribute of a sealed file cannot be cleared"
    );
    assert!(std::fs::read(&program).is_ok(), "a sealed program reads");

    // A program of the sealed release starts and holds it, and the release is then removed whole
    // once nothing holds it: the owner can still take a sealed release away.
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");
    assert!(
        test.store.retire(&one, &update).expect("removes"),
        "a sealed release nobody holds goes"
    );
    assert!(!directory.exists());
}

/// KR-REQ-26.06: removing a release follows no link and changes nothing outside it. A name that is a
/// junction is taken away and what it leads to is left as it was, and a release whose program is a
/// hard link to a file elsewhere goes as names only: that file keeps its contents and its read-only
/// attribute, which clearing by the release's path would have taken from it.
#[cfg(windows)]
#[test]
fn removing_a_release_follows_no_link_and_touches_nothing_outside_it() {
    let test = TestStore::create();
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");
    let outside = test.root.join("outside");
    std::fs::create_dir_all(outside.join("release/bin")).expect("a directory elsewhere");
    let read_only = |path: &Path| {
        std::fs::metadata(path)
            .expect("there")
            .permissions()
            .readonly()
    };

    // A name that is a junction to a whole release elsewhere.
    let one = release("0.1.0+aaaaaaaaaaaa");
    std::fs::write(outside.join("release/release.json"), manifest(&one)).expect("written");
    std::fs::write(outside.join("release/bin/kr.exe"), b"program").expect("written");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(test.store.release_directory(&one))
        .arg(outside.join("release"))
        .stdout(std::process::Stdio::null())
        .status()
        .expect("mklink runs");
    assert!(made.success(), "a junction under the release's name");
    assert!(
        test.store.retire(&one, &update).expect("removes the name"),
        "a junction is removed as a name"
    );
    assert!(
        std::fs::symlink_metadata(test.store.release_directory(&one)).is_err(),
        "the name is gone"
    );
    assert!(
        outside.join("release/bin/kr.exe").is_file()
            && outside.join("release/release.json").is_file(),
        "what it led to is not followed or removed"
    );

    // A release whose program is a hard link to a read-only file elsewhere.
    let two = release("0.2.0+bbbbbbbbbbbb");
    let program = test.install(&two);
    std::fs::write(outside.join("shared"), b"shared contents").expect("written");
    let mut permissions = std::fs::metadata(outside.join("shared"))
        .expect("there")
        .permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(outside.join("shared"), permissions).expect("read-only");
    std::fs::remove_file(&program).expect("the copy goes");
    std::fs::hard_link(outside.join("shared"), &program).expect("a hard link");
    let probe = |label: &str| {
        let shown = std::process::Command::new("icacls")
            .arg(outside.join("shared"))
            .output()
            .expect("icacls runs");
        eprintln!(
            "PROBE {label}: {} {:?}\n{}",
            outside.join("shared").display(),
            std::fs::metadata(outside.join("shared")).map(|about| {
                use std::os::windows::fs::MetadataExt as _;
                about.file_attributes()
            }),
            String::from_utf8_lossy(&shown.stdout)
        );
    };
    probe("before");
    assert!(test.store.retire(&two, &update).expect("removes"));
    probe("after");
    assert!(!test.store.release_directory(&two).exists());
    assert_eq!(
        std::fs::read(outside.join("shared")).expect("still there"),
        b"shared contents"
    );
    assert!(read_only(&outside.join("shared")), "its attribute is kept");
}

/// KR-REQ-26.06: `current` is a junction to the release's own directory, `Store::current` reads the
/// release it names, and it names a release of this store only: a store that was moved has a
/// `current` that leads to the place it was made for, which is refused, and a junction a crash left
/// beside `current` is taken away by the next switch.
#[cfg(windows)]
#[test]
fn current_is_a_junction_that_names_a_release_of_this_store_only() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let two = release("0.2.0+bbbbbbbbbbbb");
    test.install(&one);
    test.install(&two);
    test.switch(&one);
    assert_eq!(test.store.current().expect("reads"), Some(one.clone()));
    assert_eq!(
        std::fs::read_link(test.store.current_link()).expect("a junction"),
        test.store.release_directory(&one),
        "the junction names the release's own directory"
    );

    // A junction a crash left, as `mklink /J` makes one.
    let stale = test.store.root().join(".current-crashed");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&stale)
        .arg(test.store.release_directory(&one))
        .stdout(std::process::Stdio::null())
        .status()
        .expect("mklink runs");
    assert!(
        made.success() && stale.exists(),
        "a junction is left behind"
    );
    test.switch(&two);
    assert!(!stale.exists(), "the next switch takes it away");
    assert_eq!(test.store.current().expect("reads"), Some(two));

    // The store is moved: its junction still leads where it was made.
    let moved = test.root.join("moved");
    std::fs::rename(test.store.root(), &moved).expect("the store is moved");
    let refused = Store::at(&moved).current();
    assert!(
        matches!(refused, Err(kr_ipc::install::InstallError::Replaced { .. })),
        "a store that was moved does not follow its junction: {refused:?}"
    );
}

/// KR-REQ-26.06: a store is kept on an NTFS volume, and one named on another file system is refused
/// before anything is made there. The volume is a virtual disk formatted FAT32 that the native run
/// attaches and names by the variable; without it there is no other file system to ask, and the case
/// has nothing to assert.
#[cfg(windows)]
#[test]
fn a_store_on_a_volume_that_is_not_ntfs_is_refused() {
    let Some(volume) = std::env::var_os("KR_INSTALL_TEST_FAT_VOLUME") else {
        return;
    };
    let store = Store::at(PathBuf::from(volume).join("host"));
    let refused = store.create_directories();
    assert!(
        matches!(refused, Err(kr_ipc::install::InstallError::Replaced { .. })),
        "a store is not made on a volume that is not NTFS: {refused:?}"
    );
    assert!(!store.root().exists(), "and nothing is made there");
}
