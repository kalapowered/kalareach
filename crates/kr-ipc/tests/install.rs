//! A program of an installed release, run as a process: which release it finds it runs, and the
//! hold it keeps on that release until it exits.
//!
//! The program is this test binary itself, placed in a store of the test's own on the internal
//! disk and started through the store's `current` link with one test selected. That test does
//! nothing unless [`HELPER`] names a directory; then it waits there for word to go on, and writes
//! down what it found about itself.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_ipc::install::{Program, Running, Store};
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
    std::fs::write(
        directory.join("said"),
        format!("{}\n{release}\n{}\n", image.display(), started_as.display()),
    )
    .expect("writes what it found");
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
        self.store
            .switch(release, &update, &install)
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
    // The control, where it shows: macOS says the path the program was started as, and that path
    // resolves to the other release once `current` has moved on, which is why no program asks it.
    if cfg!(target_os = "macos") {
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
