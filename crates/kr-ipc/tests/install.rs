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

/// KR-REQ-26.09: what the host reads from the release `current` names comes from one release
/// whichever way a switch falls between its looks. Through the link a second look names the other
/// release (the control); a path read once keeps naming the release it was read in.
#[cfg(unix)]
#[test]
fn what_the_host_reads_from_current_once_is_of_one_release_though_a_switch_falls_between_looks() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let two = release("0.2.0+bbbbbbbbbbbb");
    for name in [&one, &two] {
        test.install(name);
        // A release's package files say which release they are in.
        for shell in ["zsh", "bash"] {
            let package = test
                .store
                .release_directory(name)
                .join("shells")
                .join(shell);
            std::fs::create_dir_all(&package).expect("a package's directory");
            std::fs::write(package.join("marker"), name.as_str()).expect("names its release");
        }
    }
    test.switch(&one);
    let marker = |shells: &Path, shell: &str| {
        std::fs::read_to_string(shells.join(shell).join("marker")).expect("a package's marker")
    };

    // The control: the host's two looks through the link, with a switch between them.
    let first = marker(&test.store.stable_shells(), "zsh");
    let current = test
        .store
        .hold_current()
        .expect("current is readable")
        .expect("a release is current");
    let (program, shells) = (current.program(Program::Kr), current.shells());
    test.switch(&two);
    let second = marker(&test.store.stable_shells(), "bash");
    assert_eq!(
        (first.as_str(), second.as_str()),
        (one.as_str(), two.as_str()),
        "through the link the two looks name two releases"
    );

    // Read once: both packages, and the program, are the first release's still.
    assert_eq!(marker(&shells, "zsh"), one.as_str());
    assert_eq!(marker(&shells, "bash"), one.as_str());
    assert_eq!(program, test.store.release_program(&one, Program::Kr));
    assert!(
        program.is_file(),
        "the program is there: {}",
        program.display()
    );
    assert!(
        !program.starts_with(test.store.current_link())
            && !shells.starts_with(test.store.current_link()),
        "neither path has the link in it"
    );
    // A read after the switch names the other release.
    let after = test.store.hold_current().expect("reads");
    assert_eq!(after.as_ref().map(|after| after.release()), Some(&two));
}

/// KR-REQ-26.09: a program the host starts from the release `current` names runs that release,
/// whole, whichever way `current` is switched around the start: the one its read named, held, from
/// the image the read named. A switch falls between each read and its start, and another while the
/// program runs; judged by a count of starts, not by how long they take.
#[cfg(unix)]
#[test]
fn a_program_started_from_the_release_current_names_runs_that_release_through_switches() {
    /// Ends the program a start made if the case leaves before the program has ended.
    struct Started(std::process::Child);
    impl Drop for Started {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    const STARTS: u32 = 40;
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let two = release("0.2.0+bbbbbbbbbbbb");
    test.install(&one);
    test.install(&two);
    test.switch(&one);
    for start in 0..STARTS {
        let current = test
            .store
            .hold_current()
            .expect("current is readable")
            .expect("a release is current");
        let program = current.program(Program::Kr);
        // The release the read named, from the path it returned.
        let named = program
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .and_then(std::ffi::OsStr::to_str)
            .expect("the path is a release's program")
            .to_owned();
        let (read, other) = if named == one.as_str() {
            (&one, &two)
        } else {
            (&two, &one)
        };
        assert_eq!(
            program,
            test.store.release_program(read, Program::Kr),
            "the path names a release of the store, not the link"
        );

        // A switch falls between the read and the start: through the link the program would be
        // the other release's now.
        test.switch(other);
        let talk = test.root.join(format!("talk-{start}"));
        std::fs::create_dir(&talk).expect("a directory to talk through");
        let mut child = Started(
            std::process::Command::new(&program)
                .args(["--exact", "helper", "--nocapture", "--test-threads", "1"])
                .env(HELPER, &talk)
                .current_dir(&test.root)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("the program starts"),
        );
        wait_for_unless_ended(&talk.join("started"), &mut child.0);
        // And another while it runs, back to the release it was read in.
        test.switch(read);
        std::fs::write(talk.join("go"), b"").expect("go");
        wait_for_unless_ended(&talk.join("said"), &mut child.0);
        let said = std::fs::read_to_string(talk.join("said")).expect("what it found");
        let mut lines = said.lines();
        let image = PathBuf::from(lines.next().expect("its image"));
        let held = lines.next().expect("its release");
        assert_eq!(held, named, "it runs and holds the release the read named");
        assert_eq!(
            std::fs::canonicalize(&image).expect("its image resolves"),
            std::fs::canonicalize(&program).expect("the program resolves"),
            "the kernel names the program the read named"
        );
        std::fs::write(talk.join("end"), b"").expect("end");
        assert!(child.0.wait().expect("the program ends").success());
        // So that the next start reads the other release.
        test.switch(other);
    }
}

/// KR-REQ-26.09: the release a command reads from `current` for a start stays on disk until its
/// program has the hold of its own, though two updates, and the removal of every release they leave
/// unneeded, fall between the read and the start. Nothing but the command's own hold keeps it: once
/// that is let go, and the program has ended, the release is removed.
#[cfg(unix)]
#[test]
fn the_release_a_command_reads_for_a_start_is_there_to_start_after_two_updates_collect_it() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let two = release("0.2.0+bbbbbbbbbbbb");
    let three = release("0.3.0+cccccccccccc");
    for name in [&one, &two, &three] {
        test.install(name);
    }
    test.switch(&one);

    // The command reads `current` for its start.
    let current = test
        .store
        .hold_current()
        .expect("current is readable")
        .expect("a release is current");
    let program = current.program(Program::Kr);
    assert_eq!(program, test.store.release_program(&one, Program::Kr));

    // It is paused. Two updates fall, and the second removes the release that is no longer needed.
    test.switch(&two);
    test.switch(&three);
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");
    assert!(
        !test.store.retire(&one, &update).expect("asks"),
        "the release the command read is not removed before its start"
    );

    // The start is made: the program is there and runs the release the read named.
    let talk = test.root.join("talk");
    std::fs::create_dir(&talk).expect("a directory to talk through");
    let mut child = std::process::Command::new(&program)
        .args(["--exact", "helper", "--nocapture", "--test-threads", "1"])
        .env(HELPER, &talk)
        .current_dir(&test.root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the program of the release the read named starts");
    wait_for_unless_ended(&talk.join("started"), &mut child);
    std::fs::write(talk.join("go"), b"").expect("go");
    wait_for_unless_ended(&talk.join("said"), &mut child);
    let said = std::fs::read_to_string(talk.join("said")).expect("what it found");
    assert_eq!(
        said.lines().nth(1),
        Some(one.as_str()),
        "it holds the release the read named"
    );

    // Once the program has ended and the command has let go, nothing holds the release.
    std::fs::write(talk.join("end"), b"").expect("end");
    assert!(child.wait().expect("the program ends").success());
    assert!(
        !test.store.retire(&one, &update).expect("asks"),
        "the command still holds the release it read"
    );
    drop(current);
    // A program another case starts at this moment carries a copy of the descriptor until it takes
    // over, so the release goes when the last copy has gone, a moment after the command let go.
    let deadline = Instant::now() + WAIT;
    while !test.store.retire(&one, &update).expect("removes") {
        assert!(
            Instant::now() < deadline,
            "nothing holds the release now, so it goes"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// KR-REQ-26.09: the hold a command takes on the release `current` names does not read that
/// release's manifest, so a `kr` that cannot read a newer release's manifest still holds the release
/// and hands its command to it. `Store::pin`, which reads the manifest, is the control.
#[cfg(unix)]
#[test]
fn a_release_whose_manifest_this_build_cannot_read_is_held_for_a_start() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let program = test.install(&one);
    std::fs::write(
        test.store.manifest(&one),
        br#"{"signed":{"_type":"a-release-format-from-later"},"signatures":[]}"#,
    )
    .expect("a manifest this build does not read");
    test.switch(&one);

    assert!(
        matches!(
            test.store.pin(&one),
            Err(kr_ipc::install::InstallError::Manifest { .. })
        ),
        "the manifest is not one this build reads"
    );
    let current = test
        .store
        .hold_current()
        .expect("current is readable")
        .expect("a release is current");
    assert_eq!(current.release(), &one);
    assert_eq!(current.program(Program::Kr), program);
    assert!(test.store.held(&one).expect("asks"), "the release is held");
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
fn launcher_on_windows() {
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
fn a_pinned_release_stays_held_by_the_program_it_runs() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);
    let talk = test.root.join("talk");
    std::fs::create_dir(&talk).expect("a directory to talk through");
    let mut launcher =
        std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([
                "--exact",
                "launcher_on_windows",
                "--nocapture",
                "--test-threads",
                "1",
            ])
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

/// KR-REQ-26.06: asking whether a release is held opens its manifest for an instant with no sharing
/// at all, and a program that starts in that instant is not refused: it waits out the question and
/// holds the release. A program of the release starts two thousand times while another thread asks
/// without a pause, and every start is granted.
#[cfg(windows)]
#[test]
fn a_program_that_starts_is_not_refused_by_a_question_whether_its_release_is_held() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let program = test.install(&one);
    let asking = Arc::new(AtomicBool::new(true));
    let asked = {
        let store = Store::at(test.store.root());
        let asking = Arc::clone(&asking);
        let one = one.clone();
        std::thread::spawn(move || {
            let mut asked = 0_u64;
            while asking.load(Ordering::Relaxed) {
                store.held(&one).expect("asks");
                asked += 1;
            }
            asked
        })
    };
    let mut refused = Vec::new();
    for round in 0..2000 {
        match Running::of_image(&program) {
            Ok(running) => assert_eq!(running.release(), Some(&one)),
            Err(error) => refused.push(format!("round {round}: {error}")),
        }
    }
    asking.store(false, Ordering::Relaxed);
    let asked = asked.join().expect("the asking thread ends");
    assert!(asked > 0, "the question was asked");
    assert!(
        refused.is_empty(),
        "a program that starts is refused by a question: {refused:?}"
    );
}

/// KR-REQ-26.06: a release a program holds cannot be moved or deleted by anyone, whatever the state
/// the check whether it is held was made in: the hold itself, the open manifest, refuses the rename
/// of the release's directory and of the directories above it, and the deletion of the manifest.
/// Once the hold is let go, the same rename goes through.
#[cfg(windows)]
#[test]
fn a_release_a_program_holds_cannot_be_renamed_or_deleted_by_anyone() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);
    let directory = test.store.release_directory(&one);
    let elsewhere = test.root.join("elsewhere");
    let pin = test.store.pin(&one).expect("asks").expect("held");
    assert!(
        std::fs::rename(&directory, &elsewhere).is_err(),
        "the release's directory is not renamed under a program"
    );
    assert!(
        std::fs::rename(test.store.versions(), test.root.join("versions-elsewhere")).is_err(),
        "nor is the directory above it"
    );
    assert!(
        std::fs::remove_file(test.store.manifest(&one)).is_err(),
        "nor is the manifest deleted"
    );
    assert!(directory.is_dir() && test.store.manifest(&one).is_file());
    drop(pin);
    std::fs::rename(&directory, &elsewhere).expect("once nothing holds it, it moves");
}

/// KR-REQ-26.06: a release as an install leaves it, sealed, is removed whole: nothing of it is left
/// in the store or in the trash, and a file of it that is a second name for a file outside is deleted
/// as a name and the file outside is not changed.
#[cfg(windows)]
#[test]
fn a_sealed_release_is_removed_whole() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);
    let directory = test.store.release_directory(&one);
    std::fs::create_dir_all(directory.join("share")).expect("a directory");
    std::fs::write(directory.join("share/data"), b"data").expect("a file");
    seal_tree(&directory);
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");
    assert!(test.store.retire(&one, &update).expect("removes"));
    assert!(!directory.exists(), "the store has no trace of it");
    let left: Vec<_> = std::fs::read_dir(test.store.trash())
        .expect("reads the trash")
        .flatten()
        .map(|entry| entry.path())
        .collect();
    assert!(left.is_empty(), "and neither has the trash: {left:?}");
}

/// KR-REQ-26.06: a read of a file of a release is not refused by the question whether the release
/// is held, which opens the manifest with no sharing for an instant: `kr host versions` asks it of
/// every release while another command reads a manifest. A manifest is read two thousand times while
/// another thread asks without a pause, and every read is granted.
#[cfg(windows)]
#[test]
fn a_read_of_a_manifest_is_not_refused_by_a_question_whether_its_release_is_held() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);
    let asking = Arc::new(AtomicBool::new(true));
    let asked = {
        let store = Store::at(test.store.root());
        let asking = Arc::clone(&asking);
        let one = one.clone();
        std::thread::spawn(move || {
            let mut asked = 0_u64;
            while asking.load(Ordering::Relaxed) {
                store.held(&one).expect("asks");
                asked += 1;
            }
            asked
        })
    };
    let manifest = test.store.manifest(&one);
    let mut refused = Vec::new();
    for round in 0..2000 {
        if let Err(error) = kr_ipc::install::read_regular_file(&manifest, 1 << 20) {
            refused.push(format!("round {round}: {error}"));
        }
    }
    asking.store(false, Ordering::Relaxed);
    let asked = asked.join().expect("the asking thread ends");
    assert!(asked > 0, "the question was asked");
    assert!(
        refused.is_empty(),
        "a read is refused by a question: {refused:?}"
    );
}

/// KR-REQ-26.06: what a removal left in the trash is deleted by a sweep, whatever it is: a release
/// a program without a hold still ran from is deleted once that program has ended, and a junction
/// left there is taken away as a name, with the directory it names and the access list of that
/// directory as they were.
#[cfg(windows)]
#[test]
fn a_sweep_of_the_trash_deletes_what_is_left_and_follows_no_junction() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);
    let system = PathBuf::from(std::env::var_os("SystemRoot").expect("a system directory"));
    let waiting = test
        .store
        .release_directory(&one)
        .join("bin")
        .join("kr-plugin-host.exe");
    std::fs::copy(system.join("System32").join("ping.exe"), &waiting).expect("a program");
    // As an install leaves a release: sealed.
    seal_tree(&test.store.release_directory(&one));
    let mut running = std::process::Command::new(&waiting)
        .args(["-n", "300", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("a program that holds nothing runs from the release");
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");
    assert!(
        test.store.retire(&one, &update).expect("removes"),
        "a release nothing holds is removed"
    );
    assert!(!test.store.release_directory(&one).exists());
    let left = || {
        std::fs::read_dir(test.store.trash())
            .expect("reads the trash")
            .flatten()
            .count()
    };
    assert_eq!(
        left(),
        1,
        "the running program keeps its release in the trash"
    );
    let kept = std::fs::read_dir(test.store.trash())
        .expect("reads the trash")
        .flatten()
        .next()
        .expect("one entry")
        .path();
    let refused = kr_ipc::install::remove_sealed_tree(&kept);
    assert!(
        refused.is_err(),
        "a program still runs from it: {refused:?}"
    );

    // A junction in the trash to a sealed directory elsewhere.
    let outside = test.root.join("outside");
    std::fs::create_dir_all(&outside).expect("a directory");
    std::fs::write(outside.join("kept"), b"kept").expect("a file");
    kr_ipc::install::seal_directory(&outside).expect("sealed");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(test.store.trash().join("a-junction"))
        .arg(&outside)
        .stdout(std::process::Stdio::null())
        .status()
        .expect("mklink runs");
    assert!(made.success(), "a junction in the trash");

    running.kill().expect("the program is ended");
    running.wait().expect("and gone");
    test.store
        .sweep_trash(&update)
        .expect("a sweep after the program ended deletes the release and the junction");
    let result = (
        left(),
        std::fs::read(outside.join("kept")).ok(),
        std::fs::write(outside.join("added"), b"x").is_err(),
    );
    kr_ipc::install::unseal_directory(&outside).expect("given back");
    assert_eq!(result.0, 0, "the trash is empty once the program has ended");
    assert_eq!(
        result.1.as_deref(),
        Some(&b"kept"[..]),
        "what the junction named is as it was"
    );
    assert!(result.2, "and still sealed");
}

/// KR-REQ-26.06: a release that cannot be removed for a reason no program gave is reported and is
/// not left in the trash as if a program held it: a directory of it refuses its owner the right to
/// change its access list, which the removal asks for, so neither the removal of the release nor a
/// sweep of the trash can finish, and each says so.
#[cfg(windows)]
#[test]
fn a_release_that_cannot_be_removed_for_no_program_s_sake_is_reported() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);
    let locked = test.store.release_directory(&one).join("locked");
    std::fs::create_dir_all(&locked).expect("a directory");
    seal_tree(&test.store.release_directory(&one));
    // The owner's right to change the list is taken from the owner itself, as the list of a file
    // that an account other than the owner's made would take it.
    let denied = std::process::Command::new("icacls")
        .arg(&locked)
        .args(["/deny", "*S-1-3-4:(WDAC)"])
        .stdout(std::process::Stdio::null())
        .status()
        .expect("icacls runs");
    assert!(denied.success(), "the right is denied");
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");

    let answer = test.store.retire(&one, &update);
    let kept = std::fs::read_dir(test.store.trash())
        .expect("reads the trash")
        .flatten()
        .next()
        .expect("what could not be removed is in the trash")
        .path();
    let swept = test.store.sweep_trash(&update);

    // Put it right, so that the test leaves nothing behind: an empty directory goes by the right
    // its parent gives.
    std::fs::remove_dir(kept.join("locked")).expect("the directory goes with its parent's right");
    kr_ipc::install::remove_sealed_tree(&kept).expect("the rest of the release goes");
    assert!(
        answer.is_err(),
        "a refusal no program gave is not taken for a program that holds the release: {answer:?}"
    );
    assert!(
        swept.is_err(),
        "nor does a sweep take it for one: {swept:?}"
    );
}

/// Removes a release whose program is a second name for a read-only file elsewhere that carries the
/// access list `icacls` makes of `lists` (each a call's arguments), and checks that the list of the
/// file outside is as it was, that the removal reports it and that the release stays in the trash.
/// `put_right` is the call that undoes the lists, so that the test leaves nothing behind.
#[cfg(windows)]
fn removal_meets_a_list_that_is_not_the_seal_s(lists: &[&[&str]], put_right: &[&str]) {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let program = test.install(&one);
    let outside = test.root.join("outside");
    std::fs::create_dir_all(&outside).expect("a directory elsewhere");
    let shared = outside.join("shared");
    std::fs::write(&shared, b"shared contents").expect("written");
    std::fs::remove_file(&program).expect("the copy goes");
    std::fs::hard_link(&shared, &program).expect("a hard link");
    let mut permissions = std::fs::metadata(&shared).expect("there").permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&shared, permissions).expect("read-only");
    let icacls = |arguments: &[&str]| {
        let run = std::process::Command::new("icacls")
            .arg(&shared)
            .args(arguments)
            .output()
            .expect("icacls runs");
        assert!(run.status.success(), "icacls {arguments:?}");
        String::from_utf8_lossy(&run.stdout).into_owned()
    };
    for list in lists {
        icacls(list);
    }
    let before = icacls(&[]);
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");

    let answer = test.store.retire(&one, &update);
    let after = icacls(&[]);

    // Put it right, so that the test leaves nothing behind.
    icacls(put_right);
    let kept = std::fs::read_dir(test.store.trash())
        .expect("reads the trash")
        .flatten()
        .next()
        .map(|entry| entry.path());
    if let Some(kept) = &kept {
        kr_ipc::install::remove_sealed_tree(kept).expect("the release goes once the list is right");
    }
    assert!(
        answer.is_err(),
        "a list that is not the seal's is reported, not taken for a program: {answer:?}"
    );
    assert!(
        kept.is_some(),
        "what could not be removed is in the trash: {answer:?}"
    );
    assert_eq!(before, after, "the list of the file outside is as it was");
    assert_eq!(
        std::fs::read(&shared).expect("still there"),
        b"shared contents"
    );
}

/// KR-REQ-26.06: a file of a release that is a second name for a file outside, whose access list
/// denies its owner the right to change attributes but is not the seal's, is not given back: the
/// list of the file outside is as it was, the removal reports it, and the release stays in the trash.
#[cfg(windows)]
#[test]
fn a_list_that_is_not_the_seal_s_is_left_as_it_is() {
    removal_meets_a_list_that_is_not_the_seal_s(
        &[&["/deny", "*S-1-1-0:(WA)"]],
        &["/remove:d", "*S-1-1-0"],
    );
}

/// KR-REQ-26.06: a list that begins as the seal's does, with the denial of the owner-rights
/// principal's right to change attributes, but is not the whole of the seal's list, is not given
/// back either. Here the list is `D:P(D;;0x100;;;OW)(A;;FA;;;OW)`.
#[cfg(windows)]
#[test]
fn a_list_that_begins_as_the_seal_s_does_and_is_not_the_seal_s_is_left_as_it_is() {
    removal_meets_a_list_that_is_not_the_seal_s(
        &[
            &["/inheritance:r"],
            &["/grant", "*S-1-3-4:(F)"],
            &["/deny", "*S-1-3-4:(WA)"],
        ],
        &["/reset"],
    );
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
/// stops: at any moment it names one release or the other, never none, and the release it names has
/// its program. Judged by a count of switches, not by how long they take.
///
/// A reader reads the link once and then the named release's own program, a path with no link in
/// it. It does not walk a path through the link: on the build machine (Linux 7.0, ext4) a walk
/// through a link that is being replaced sometimes meets a missing path, about once in some tens
/// of millions of walks, whether the link is replaced by a rename or by exchanging two names. A
/// program that only replaces a link and flushes the directory after each replace, as the switch
/// does, shows it, so the store and its locks are not needed for it. What the switch decides is
/// what the link names, and that is read whole.
///
/// There are twice as many readers as processors, counted as three to eight (six to sixteen readers),
/// so that on a small machine some are taken off a processor in the middle of a read. On macOS a read that is still going when the
/// next switch takes away the link it looked up finds no link, though `current` was a link at every
/// moment; the store's read of `current` reads again, and this is where that shows.
#[test]
fn current_names_a_whole_release_at_every_moment_of_a_switch() {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    struct Stop<'a>(&'a AtomicBool);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let readers = 2 * std::thread::available_parallelism()
        .map_or(3, usize::from)
        .clamp(3, 8);

    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let two = release("0.2.0+bbbbbbbbbbbb");
    test.install(&one);
    test.install(&two);
    test.switch(&one);
    let finished = AtomicBool::new(false);
    let reads = AtomicU32::new(0);
    std::thread::scope(|scope| {
        // The readers stop when the switches end or fail, so a failure is a failure and not a wait.
        let _stop = Stop(&finished);
        for _ in 0..readers {
            scope.spawn(|| {
                while !finished.load(Ordering::SeqCst) {
                    let named = test
                        .store
                        .current()
                        .expect("current is readable")
                        .expect("current names a release");
                    let program = test
                        .store
                        .release_directory(&named)
                        .join("bin")
                        .join(Program::Kr.file_name());
                    assert!(
                        program.is_file(),
                        "the release current names has its program: {}",
                        program.display()
                    );
                    reads.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
        for round in 0..200 {
            test.switch(if round % 2 == 0 { &two } else { &one });
        }
    });
    assert!(reads.load(Ordering::SeqCst) > 0, "the readers read");
}

/// Opens `current` itself, not what it names, the way a program reads the link, and keeps it open.
#[cfg(windows)]
fn open_current_itself(test: &TestStore) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    std::fs::OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(test.store.current_link())
        .expect("current opens")
}

/// The target a junction names, as the system keeps it, read through a handle that is open on the
/// junction.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "a handle's reparse data is read through a control code that has no safe interface"
)]
fn target_through(held: &std::fs::File) -> std::io::Result<String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;

    let mut buffer = vec![0_u8; 16 * 1024];
    let mut returned = 0_u32;
    // SAFETY: the handle is the open file's own, and the output buffer is as long as the length
    // says; no input is given.
    let done = unsafe {
        DeviceIoControl(
            held.as_raw_handle(),
            FSCTL_GET_REPARSE_POINT,
            std::ptr::null(),
            0,
            buffer.as_mut_ptr().cast(),
            u32::try_from(buffer.len()).expect("a length"),
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if done == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // A junction's record: the tag, the data's length and a reserved word, then the offset and the
    // length of the name the junction names, and of the name it shows, then the names from byte 16.
    let word = |at: usize| usize::from(u16::from_le_bytes([buffer[at], buffer[at + 1]]));
    let (offset, length) = (16 + word(8), word(10));
    let units: Vec<u16> = buffer[offset..offset + length]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

/// A program that opened `current` before a switch and reads it after reads the release that is
/// current after it, whole. A switch changes where the junction points and does not put another
/// junction in its place, which a reader that has the old one open would be refused or read as it
/// was.
#[cfg(windows)]
#[test]
fn a_reader_that_holds_current_open_across_a_switch_reads_the_release_switched_to() {
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let two = release("0.2.0+bbbbbbbbbbbb");
    test.install(&one);
    test.install(&two);
    test.switch(&one);
    let named = |of: &ReleaseName| {
        std::path::absolute(test.store.release_directory(of))
            .expect("a path")
            .display()
            .to_string()
    };
    let held = open_current_itself(&test);
    let before = target_through(&held).expect("the junction reads");
    assert!(
        before.ends_with(&named(&one)),
        "it names the first: {before}"
    );
    test.switch(&two);
    let after = target_through(&held).expect("the junction still reads");
    assert!(
        after.ends_with(&named(&two)),
        "it names the second: {after}"
    );
    assert_eq!(test.store.current().expect("reads"), Some(two));
}

/// A switch that ends at any moment of the change leaves `current` naming a whole release, the one
/// it was or the one it goes to, and never none or a mixture: before the target is set it names the
/// old one, and after it the new one, with the change not yet flushed. A panic in the seam stands
/// for the end of the process there, and a store opened afresh for what a restart finds.
#[cfg(windows)]
#[test]
fn a_switch_that_ends_at_any_moment_leaves_current_naming_a_whole_release() {
    use kr_ipc::install::removal_race::{Moment, hook};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let _hooked = HOOKED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (moment, goes_to_the_new) in [
        (Moment::JunctionChecked, false),
        (Moment::JunctionPointed, true),
    ] {
        let test = TestStore::create();
        let one = release("0.1.0+aaaaaaaaaaaa");
        let two = release("0.2.0+bbbbbbbbbbbb");
        test.install(&one);
        test.install(&two);
        test.switch(&one);
        let link = test.store.current_link();
        hook(Some(std::sync::Arc::new(move |at, path: &Path| {
            assert!(!(at == moment && path == link), "the switch ends here");
        })));
        let ended = catch_unwind(AssertUnwindSafe(|| test.switch(&two)));
        hook(None);
        assert!(ended.is_err(), "the switch ends at {moment:?}");
        let restarted = Store::at(test.store.root().to_path_buf());
        let named = restarted
            .current()
            .expect("current reads after the end")
            .expect("current names a release after the end");
        assert_eq!(
            named,
            if goes_to_the_new { two } else { one },
            "at {moment:?}"
        );
        assert!(
            restarted.release_program(&named, Program::Kr).is_file(),
            "the release it names is whole, at {moment:?}"
        );
    }
}

/// A `current` that is a plain directory is not made a junction where it is: the directory that was
/// there stays what it is, whether the switch then replaces it or refuses.
#[cfg(windows)]
#[test]
fn a_current_that_is_a_plain_directory_is_not_turned_into_a_junction_in_place() {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);
    std::fs::create_dir(test.store.current_link()).expect("a directory in the place of current");
    let held = open_current_itself(&test);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test.switch(&one)));
    assert!(
        !matches!(
            held.metadata(),
            Ok(kept) if kept.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        ),
        "the directory that was there is not a junction now"
    );
}

/// What another process of the account puts in the place of `current` after the switch has looked
/// at it and before it sets the target is left as it is: the target is set through the handle that
/// was looked at, and not through the name.
#[cfg(windows)]
#[test]
fn a_name_put_in_the_place_of_current_during_a_switch_is_not_pointed_at_the_release() {
    use kr_ipc::install::removal_race::{Moment, hook, make_junction_in_place};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let _hooked = HOOKED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    let two = release("0.2.0+bbbbbbbbbbbb");
    test.install(&one);
    test.install(&two);
    test.switch(&one);
    let elsewhere = test.root.join("elsewhere");
    std::fs::create_dir(&elsewhere).expect("a place for the other junction to name");
    let link = test.store.current_link();
    let moved = test.store.root().join("moved-current");
    let (at_link, to_name) = (link.clone(), elsewhere.clone());
    hook(Some(std::sync::Arc::new(move |at, path: &Path| {
        if at == Moment::JunctionChecked && path == at_link {
            std::fs::rename(&at_link, &moved).expect("the junction that was looked at moves away");
            std::fs::create_dir(&at_link).expect("another directory takes the name");
            make_junction_in_place(&at_link, &to_name).expect("which is a junction");
        }
    })));
    let _ = catch_unwind(AssertUnwindSafe(|| test.switch(&two)));
    hook(None);
    assert_eq!(
        std::fs::read_link(&link).expect("the name is still a junction"),
        elsewhere,
        "the junction put there still names what it named"
    );
}

/// A `current` that is no link is an error, and a store with no `current` has no current release:
/// the read that reads again for a link a switch took away does not turn the one into the other.
#[test]
fn a_current_that_is_a_directory_is_an_error_and_not_the_absence_of_a_release() {
    let test = TestStore::create();
    assert_eq!(
        test.store.current().expect("a store with no current reads"),
        None
    );
    std::fs::create_dir(test.store.current_link()).expect("a directory in the place of current");
    assert!(
        matches!(
            test.store.current(),
            Err(kr_ipc::install::InstallError::Io {
                operation: "read the link",
                ..
            })
        ),
        "a directory is no link"
    );
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
    // On Windows the attribute is all this clears, and a sealed file refuses even that.
    #[allow(clippy::permissions_set_readonly_false)]
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
    // And a junction inside the release to a directory elsewhere.
    std::fs::create_dir_all(outside.join("inner")).expect("a directory elsewhere");
    std::fs::write(outside.join("inner/kept"), b"kept").expect("written");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(
            test.store
                .release_directory(&two)
                .join("bin")
                .join("linked"),
        )
        .arg(outside.join("inner"))
        .stdout(std::process::Stdio::null())
        .status()
        .expect("mklink runs");
    assert!(made.success(), "a junction inside the release");
    assert!(test.store.retire(&two, &update).expect("removes"));
    assert!(!test.store.release_directory(&two).exists());
    let in_the_trash = std::fs::read_dir(test.store.trash()).map(|entries| entries.count());
    assert_eq!(
        in_the_trash.ok(),
        Some(0),
        "and nothing of it is left in the trash"
    );
    assert_eq!(
        std::fs::read(outside.join("inner/kept")).ok().as_deref(),
        Some(&b"kept"[..]),
        "what the junction inside it named is not followed"
    );
    assert_eq!(
        std::fs::read(outside.join("shared")).expect("still there"),
        b"shared contents"
    );
    assert!(read_only(&outside.join("shared")), "its attribute is kept");
}

/// KR-REQ-26.06: a directory of a release that another process of the account turns into a junction
/// after the removal has pinned it and checked that it is a plain directory leads the removal
/// nowhere. The pin keeps the directory from being renamed or deleted, and does not keep it from
/// being made a junction (the system allows that to any handle that may write attributes, whatever
/// its share mode), so what is in the directory is read through the pinned handle and each name
/// opened relative to it: the listing is the directory's own and empty, the directory goes as a
/// name, and the folder the junction names keeps everything in it.
#[cfg(windows)]
#[test]
fn a_directory_made_a_junction_after_it_was_checked_leads_the_removal_nowhere() {
    use kr_ipc::install::removal_race;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let _alone = HOOKED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);
    let directory = test.store.release_directory(&one);
    std::fs::create_dir_all(directory.join("share/empty")).expect("an empty directory");
    seal_tree(&directory);
    let outside = test.root.join("outside");
    std::fs::create_dir_all(outside.join("inner")).expect("a folder elsewhere");
    std::fs::write(outside.join("kept"), b"kept").expect("written");
    std::fs::write(outside.join("inner/kept"), b"kept too").expect("written");
    let target = outside.clone();
    let root = test.root.clone();
    let turned = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&turned);
    removal_race::hook(Some(Arc::new(move |moment, pinned: &Path| {
        if moment == removal_race::Moment::Pinned
            && pinned.file_name().is_some_and(|name| name == "empty")
            && pinned.starts_with(&root)
        {
            removal_race::make_junction_in_place(pinned, &target)
                .expect("the pinned directory becomes a junction");
            counted.fetch_add(1, Ordering::SeqCst);
        }
    })));
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");

    let answer = test.store.retire(&one, &update);
    removal_race::hook(None);

    assert_eq!(turned.load(Ordering::SeqCst), 1, "the race was run once");
    assert!(
        answer.as_ref().is_ok_and(|removed| *removed),
        "the release is removed: {answer:?}"
    );
    assert_eq!(
        std::fs::read(outside.join("kept")).ok().as_deref(),
        Some(&b"kept"[..]),
        "the folder the junction named keeps its file"
    );
    assert_eq!(
        std::fs::read(outside.join("inner/kept")).ok().as_deref(),
        Some(&b"kept too"[..]),
        "and its subfolder"
    );
    let in_the_trash = std::fs::read_dir(test.store.trash()).map(|entries| entries.count());
    assert_eq!(in_the_trash.ok(), Some(0), "nothing of the release is left");
}

/// Held by each case that sets the removal hook: the hook is the process's, and the cases of this
/// binary run side by side.
#[cfg(windows)]
static HOOKED: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A store whose trash is a junction to a folder with a directory and a file of its own in it, as
/// another process of the account can leave it. Returns the folder.
#[cfg(windows)]
fn trash_made_a_junction(test: &TestStore) -> PathBuf {
    let outside = test.root.join("outside");
    std::fs::create_dir_all(outside.join("decoy")).expect("a folder elsewhere");
    std::fs::write(outside.join("decoy/file"), b"kept").expect("written");
    std::fs::write(outside.join("other"), b"kept too").expect("written");
    std::fs::remove_dir(test.store.trash()).expect("the trash is empty");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(test.store.trash())
        .arg(&outside)
        .stdout(std::process::Stdio::null())
        .status()
        .expect("mklink runs");
    assert!(made.success(), "a junction in place of the trash");
    outside
}

/// KR-REQ-26.06: the sweep of the trash is opened once without following a link and refused when it
/// is not a plain directory: with a junction in its place it lists nothing, and what the junction
/// names is neither listed, nor reset, nor deleted.
#[cfg(windows)]
#[test]
fn a_junction_in_place_of_the_trash_leads_the_sweep_nowhere() {
    let test = TestStore::create();
    let outside = trash_made_a_junction(&test);
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");

    let swept = test.store.sweep_trash(&update);

    assert!(swept.is_err(), "a trash that is not a directory is refused");
    assert_eq!(
        std::fs::read(outside.join("decoy/file")).ok().as_deref(),
        Some(&b"kept"[..]),
        "what the junction names keeps its directory"
    );
    assert_eq!(
        std::fs::read(outside.join("other")).ok().as_deref(),
        Some(&b"kept too"[..]),
        "and its file"
    );
}

/// KR-REQ-26.06: a release is moved into the trash through the handle the trash was opened by, so a
/// trash that another process of the account makes a junction after it was checked takes nothing
/// out of the store: the release stays where it was and the folder the junction names is as it was.
#[cfg(windows)]
#[test]
fn a_trash_made_a_junction_after_it_was_checked_takes_no_release_out_of_the_store() {
    use kr_ipc::install::removal_race;
    use std::sync::Arc;

    let _alone = HOOKED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);
    let outside = test.root.join("outside");
    std::fs::create_dir_all(&outside).expect("a folder elsewhere");
    let trash = test.store.trash();
    let target = outside.clone();
    removal_race::hook(Some(Arc::new(move |moment, at: &Path| {
        if moment == removal_race::Moment::TrashChecked && at == trash {
            std::fs::remove_dir(&trash).expect("the trash is empty");
            let made = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&trash)
                .arg(&target)
                .stdout(std::process::Stdio::null())
                .status()
                .expect("mklink runs");
            assert!(made.success(), "a junction in place of the trash");
        }
    })));
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");

    let answer = test.store.retire(&one, &update);
    removal_race::hook(None);

    assert!(
        answer.is_err(),
        "a trash that is not a directory is refused: {answer:?}"
    );
    assert!(
        test.store.manifest(&one).is_file(),
        "the release is where it was"
    );
    assert_eq!(
        std::fs::read_dir(&outside)
            .map(|entries| entries.count())
            .ok(),
        Some(0),
        "and nothing of it is in the folder the junction names"
    );
}

/// KR-REQ-26.06: the handle a name is deleted through, and the one its access list is reset
/// through, allow nobody to delete or rename the name while they are open, so a name cannot be
/// moved out of the release between the open and the deletion or the reset: the other process's
/// move is refused, and the release goes whole.
#[cfg(windows)]
#[test]
fn a_name_cannot_be_moved_out_of_a_release_between_its_open_and_its_removal() {
    use kr_ipc::install::removal_race;
    use std::sync::Arc;

    let _alone = HOOKED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let test = TestStore::create();
    let one = release("0.1.0+aaaaaaaaaaaa");
    test.install(&one);
    let directory = test.store.release_directory(&one);
    std::fs::write(directory.join("bin/plain"), b"plain").expect("written");
    std::fs::write(directory.join("bin/sealed"), b"sealed").expect("written");
    kr_ipc::install::seal_file(&directory.join("bin/sealed")).expect("a file is sealed");
    let outside = test.root.join("outside");
    std::fs::create_dir_all(&outside).expect("a folder elsewhere");
    let tried: Arc<std::sync::Mutex<Vec<(String, bool)>>> = Arc::default();
    let root = test.root.clone();
    let (to, note) = (outside.clone(), Arc::clone(&tried));
    removal_race::hook(Some(Arc::new(move |moment, at: &Path| {
        let name = at.file_name().and_then(|name| name.to_str()).unwrap_or("");
        let acts = matches!(
            (moment, name),
            (removal_race::Moment::Opened, "plain")
                | (removal_race::Moment::AboutToGiveBack, "sealed")
        );
        if acts && at.starts_with(&root) {
            let moved = std::fs::rename(at, to.join(name)).is_ok();
            note.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((format!("{moment:?} {name}"), moved));
        }
    })));
    let update = test
        .store
        .try_lock_update()
        .expect("locks")
        .expect("nothing else updates");

    let answer = test.store.retire(&one, &update);
    removal_race::hook(None);

    let tried = tried
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(
        tried,
        [
            ("Opened plain".to_owned(), false),
            ("AboutToGiveBack sealed".to_owned(), false)
        ],
        "both moves were tried and both were refused"
    );
    assert!(
        answer.as_ref().is_ok_and(|removed| *removed),
        "the release goes whole: {answer:?}"
    );
    assert_eq!(
        std::fs::read_dir(test.store.trash())
            .map(|entries| entries.count())
            .ok(),
        Some(0),
        "and nothing of it is left"
    );
    assert_eq!(
        std::fs::read_dir(&outside)
            .map(|entries| entries.count())
            .ok(),
        Some(0),
        "and nothing of it is outside"
    );
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
/// before anything is made there. The volume is a virtual disk formatted FAT32 that the run attaches
/// and names by the variable; the case is run by hand against one.
#[cfg(windows)]
#[test]
#[ignore = "needs a volume that is not NTFS: set KR_INSTALL_TEST_FAT_VOLUME to its root"]
fn a_store_on_a_volume_that_is_not_ntfs_is_refused() {
    let volume = std::env::var_os("KR_INSTALL_TEST_FAT_VOLUME")
        .expect("KR_INSTALL_TEST_FAT_VOLUME names the volume this case is run against");
    let store = Store::at(PathBuf::from(volume).join("host"));
    let refused = store.create_directories();
    assert!(
        matches!(refused, Err(kr_ipc::install::InstallError::Replaced { .. })),
        "a store is not made on a volume that is not NTFS: {refused:?}"
    );
    assert!(!store.root().exists(), "and nothing is made there");
}

/// A measurement, not a case: readers of `current` run beside a loop of switches, and every
/// refused read is recorded with the step that was refused, the raw code, and what the same read
/// did when it was made again at once.
#[cfg(windows)]
mod switch_probe {
    use super::{Duration, Instant, Path, Program, Store, TestStore, release};
    use std::collections::BTreeMap;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::sync::atomic::{AtomicBool, Ordering};
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const SHARE_ALL: u32 = 7;

    type Refusal = (&'static str, i32);

    #[derive(Default)]
    struct Tally {
        ok: BTreeMap<&'static str, u64>,
        refused: BTreeMap<Refusal, u64>,
        lines: Vec<String>,
        unrecovered: u64,
        worst_micros: u128,
    }

    impl Tally {
        fn run(&mut self, ok_label: &'static str, call: impl Fn() -> Result<(), Refusal>) {
            let Err((kind, code)) = call() else {
                *self.ok.entry(ok_label).or_default() += 1;
                return;
            };
            *self.refused.entry((kind, code)).or_default() += 1;
            let began = Instant::now();
            let mut attempts = 1_u32;
            let recovered = loop {
                attempts += 1;
                if call().is_ok() {
                    break true;
                }
                if began.elapsed() > Duration::from_secs(2) {
                    break false;
                }
            };
            let micros = began.elapsed().as_micros();
            if !recovered {
                self.unrecovered += 1;
            }
            self.worst_micros = self.worst_micros.max(micros);
            if self.lines.len() < 200 {
                self.lines.push(format!(
                    "PROBE-REFUSAL kind={kind} code={code} attempts={attempts} micros={micros} recovered={recovered}"
                ));
            }
        }
    }

    fn code_of(error: &std::io::Error) -> i32 {
        error.raw_os_error().unwrap_or(-1)
    }

    /// What `std::fs::read_link` does, in its two steps, so that a refusal says which step.
    #[allow(unsafe_code)]
    fn stepped_read(link: &Path) -> Result<(), Refusal> {
        let file = std::fs::OpenOptions::new()
            .access_mode(0)
            .share_mode(SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(link)
            .map_err(|error| ("open", code_of(&error)))?;
        let mut buffer = vec![0_u8; 16 * 1024];
        let mut returned = 0_u32;
        // SAFETY: the handle is the open file's own, and the buffer is as long as the length says.
        let done = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_GET_REPARSE_POINT,
                std::ptr::null(),
                0,
                buffer.as_mut_ptr().cast(),
                u32::try_from(buffer.len()).unwrap_or(0),
                &raw mut returned,
                std::ptr::null_mut(),
            )
        };
        if done == 0 {
            return Err(("ioctl", code_of(&std::io::Error::last_os_error())));
        }
        Ok(())
    }

    fn code_in(text: &str) -> i32 {
        text.split("code: ")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|digits| digits.parse().ok())
            .unwrap_or(-1)
    }

    fn named(store: &Store) -> Result<(), Refusal> {
        match store.current() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(("current", -2)),
            Err(error) => Err(("current", code_in(&format!("{error:?}")))),
        }
    }

    fn reader(store: &Store, finished: &AtomicBool) -> Tally {
        let link = store.current_link();
        let program = link.join("bin").join(Program::Kr.file_name());
        let mut tally = Tally::default();
        while !finished.load(Ordering::SeqCst) {
            tally.run("link", || stepped_read(&link));
            tally.run("current", || named(store));
            tally.run("meta", || {
                std::fs::metadata(&program)
                    .map(|_| ())
                    .map_err(|error| ("meta", code_of(&error)))
            });
            tally.run("through", || {
                std::fs::File::open(&program)
                    .map(|_| ())
                    .map_err(|error| ("through", code_of(&error)))
            });
        }
        tally
    }

    fn setting(name: &str, default: u64) -> u64 {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    }

    #[test]
    fn probe_current_during_a_switch() {
        struct Stop<'a>(&'a AtomicBool);
        impl Drop for Stop<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let seconds = setting("KR_PROBE_SECONDS", 120);
        let cap = setting("KR_PROBE_SWITCHES", 200_000);
        let default_readers = 2 * std::thread::available_parallelism()
            .map_or(3, usize::from)
            .clamp(3, 8);
        let readers = usize::try_from(setting(
            "KR_PROBE_READERS",
            u64::try_from(default_readers).unwrap_or(8),
        ))
        .unwrap_or(8);
        let protection =
            std::env::var("KR_PROBE_PROTECTION").unwrap_or_else(|_| "unset".to_owned());

        let test = TestStore::create();
        let one = release("0.1.0+aaaaaaaaaaaa");
        let two = release("0.2.0+bbbbbbbbbbbb");
        test.install(&one);
        test.install(&two);
        test.switch(&one);
        let finished = AtomicBool::new(false);
        let began = Instant::now();
        let mut switches = 0_u64;
        let tallies = std::thread::scope(|scope| {
            let _stop = Stop(&finished);
            let handles: Vec<_> = (0..readers)
                .map(|_| scope.spawn(|| reader(&test.store, &finished)))
                .collect();
            while switches < cap && began.elapsed() < Duration::from_secs(seconds) {
                test.switch(if switches % 2 == 0 { &two } else { &one });
                switches += 1;
            }
            finished.store(true, Ordering::SeqCst);
            handles
                .into_iter()
                .map(|handle| handle.join().expect("a reader ends"))
                .collect::<Vec<_>>()
        });

        let mut ok: BTreeMap<&str, u64> = BTreeMap::new();
        let mut refused: BTreeMap<Refusal, u64> = BTreeMap::new();
        let mut unrecovered = 0;
        let mut worst = 0;
        let mut lines = Vec::new();
        for tally in tallies {
            for (label, count) in tally.ok {
                *ok.entry(label).or_default() += count;
            }
            for (key, count) in tally.refused {
                *refused.entry(key).or_default() += count;
            }
            unrecovered += tally.unrecovered;
            worst = worst.max(tally.worst_micros);
            lines.extend(tally.lines);
        }
        println!(
            "PROBE-RUN protection={protection} readers={readers} switches={switches} seconds={}",
            began.elapsed().as_secs()
        );
        for (label, count) in &ok {
            println!("PROBE-OK read={label} count={count}");
        }
        for ((kind, code), count) in &refused {
            println!("PROBE-REFUSED kind={kind} code={code} count={count}");
        }
        for line in lines.iter().take(60) {
            println!("{line}");
        }
        println!(
            "PROBE-END switches={switches} refused_total={} unrecovered={unrecovered} worst_micros={worst}",
            refused.values().sum::<u64>()
        );
    }
}
