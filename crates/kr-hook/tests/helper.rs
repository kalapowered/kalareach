//! A forwarder reaches the worker of another release through that release's own forwarder.
//!
//! An application's settings start the forwarder an update has made current, while the worker of
//! the session it serves may run an earlier release. Where that worker admits its own release's
//! forwarder, the forwarder replaces itself with it, before it reads anything, and the replacement
//! starts already holding the worker's release. These cases run the real forwarder of one release
//! of a store and a launch whose registration names another release of it, which holds a recording
//! program in place of its forwarder.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-26.06 | the cases below |
//! | KR-REQ-26.08 | the cases below |

#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{Placed, run_with_input};
use kr_ipc::install::{Program, Store};
use kr_protocol::update::ReleaseName;

const HOOK_INPUT: &[u8] = br#"{"session_id":"4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11","hook_event_name":"SessionStart","source":"startup"}"#;

fn release(name: &str) -> ReleaseName {
    ReleaseName::new(name).expect("a release")
}

fn manifest(release: &ReleaseName, minor: u16) -> String {
    serde_json::json!({
        "signed": {
            "_type": "kalareach-release",
            "release": release,
            "sequence": "1",
            "commit": "4254aa6e62e585478ff8dcff5518f23c7263f4ce",
            "target": "aarch64-apple-darwin",
            "os_floor": { "system": "macos", "version": "14.0" },
            "protocol_version": { "major": 0, "minor": minor, "patch": 0 },
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

/// The level of the forwarders under test, which is the protocol package version's minor number
/// below 1.0.
fn this_minor() -> u16 {
    kr_protocol::hello::PACKAGE_VERSION.minor
}

/// A store of two releases: the one whose forwarder runs, and the one a launch's worker runs.
struct Launch {
    placed: Placed,
    store: Store,
    /// The release whose real forwarder runs.
    mine: ReleaseName,
    /// The release the launch's worker runs, which holds a recording program as its forwarder.
    theirs: ReleaseName,
    /// What the recording program writes, and what it is told to wait for.
    out: PathBuf,
    started: PathBuf,
    go: PathBuf,
}

impl Launch {
    /// A store whose second release states protocol version `0.<theirs_minor>`.
    fn new(theirs_minor: u16) -> Self {
        let placed = Placed::new();
        let store = Store::at(placed.host.root().join("store"));
        store.create_directories().expect("the store's directories");
        std::fs::write(store.record(), b"{}\n").expect("the store's record");
        let mine = release("0.1.0+aaaaaaaaaaaa");
        let theirs = release("0.2.0+bbbbbbbbbbbb");
        for (name, minor) in [(&mine, this_minor()), (&theirs, theirs_minor)] {
            std::fs::create_dir_all(store.release_directory(name).join("bin"))
                .expect("the release's bin");
            std::fs::write(store.manifest(name), manifest(name, minor)).expect("the manifest");
        }
        kr_ipc::testing::place_program(
            &placed.forwarder,
            &store
                .release_directory(&mine)
                .join("bin")
                .join(Program::Hook.file_name()),
        );
        let root = placed.host.root().to_path_buf();
        let launch = Self {
            out: root.join("recorded"),
            started: root.join("started"),
            go: root.join("go"),
            placed,
            store,
            mine,
            theirs,
        };
        launch.install_recorder();
        launch
    }

    /// Puts a program in place of the second release's forwarder that writes down what it was
    /// started with, says it has started, and waits to be told to go on.
    fn install_recorder(&self) {
        use std::os::unix::fs::PermissionsExt as _;

        let script = format!(
            "#!/bin/sh\n\
             printf 'args:%s\\nmarker:%s\\n' \"$*\" \"$KR_HELPER_FROM\" > '{out}.tmp'\n\
             cat >> '{out}.tmp'\n\
             mv '{out}.tmp' '{out}'\n\
             : > '{started}'\n\
             while [ ! -e '{go}' ]; do sleep 0.02; done\n",
            out = self.out.display(),
            started = self.started.display(),
            go = self.go.display(),
        );
        let program = self
            .store
            .release_directory(&self.theirs)
            .join("bin")
            .join(Program::Hook.file_name());
        std::fs::write(&program, script).expect("the recording program");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
            .expect("it can be run");
    }

    /// The launch's registration, naming `release` as the release of its worker when it names one.
    fn register(&self, release: Option<&ReleaseName>) -> PathBuf {
        let directory = self.placed.host.root().join("launch");
        std::fs::create_dir_all(&directory).expect("the launch's directory");
        let registration = directory.join("registration");
        let mut text = format!(
            "endpoint={}\nprofile=p\ninstance=i\npid=1\nstart=1\ncredential={}\nframing=json_lines\n",
            directory.join("worker.sock").display(),
            directory.join("credential").display(),
        );
        if let Some(release) = release {
            text.push_str(&format!("release={release}\n"));
        }
        std::fs::write(&registration, text).expect("the registration");
        registration
    }

    /// The hook of the first release, run against `registration` with `arguments`.
    fn command(
        &self,
        registration: &Path,
        arguments: &[&str],
        marker: Option<&str>,
    ) -> std::process::Command {
        let mut command = std::process::Command::new(
            self.store
                .release_directory(&self.mine)
                .join("bin")
                .join(Program::Hook.file_name()),
        );
        command
            .args(arguments)
            .current_dir(self.placed.host.root())
            .env("KR_REGISTRATION", registration);
        for variable in ["KR_CREDENTIAL", "KR_SESSION", kr_hook::helper::MARKER] {
            command.env_remove(variable);
        }
        if let Some(marker) = marker {
            command.env(kr_hook::helper::MARKER, marker);
        }
        command
    }

    /// Waits for the recording program to say it has started.
    fn wait_for_it(&self) {
        let deadline = Instant::now() + common::LIVENESS;
        while !self.started.exists() {
            assert!(
                Instant::now() < deadline,
                "the recording program did not start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn let_it_go(&self) {
        std::fs::write(&self.go, b"").expect("go");
    }

    /// Whether the recording program ran.
    fn it_ran(&self) -> bool {
        self.started.exists() || self.out.exists()
    }
}

/// KR-REQ-26.06, KR-REQ-26.08: a forwarder whose launch's worker runs another release, at a level
/// above the first that admits that release's own forwarder and not its own level, is replaced by
/// that release's forwarder with the same arguments and input. The release is held from before the
/// replacement to after it, and the forwarder's own is not held by the replacement.
#[test]
fn a_forwarder_hands_a_launch_of_another_release_to_that_releases_forwarder() {
    for arguments in [["claude-code", "hook"], ["claude-code", "channel"]] {
        let launch = Launch::new(this_minor() + 1);
        let registration = launch.register(Some(&launch.theirs));
        let mut running = launch
            .command(&registration, &arguments, None)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the forwarder starts");
        {
            use std::io::Write as _;
            let mut input = running.stdin.take().expect("its input");
            input.write_all(HOOK_INPUT).expect("the input");
        }
        launch.wait_for_it();

        // The replacement holds the release it was handed, and the release it replaced is free.
        assert!(
            launch.store.held(&launch.theirs).expect("asks"),
            "{arguments:?}: the worker's release is held by the forwarder that took over"
        );
        assert!(
            !launch.store.held(&launch.mine).expect("asks"),
            "{arguments:?}: the release the forwarder was started from is no longer held"
        );
        let update = launch
            .store
            .try_lock_update()
            .expect("locks")
            .expect("nothing else updates");
        assert!(
            !launch.store.retire(&launch.theirs, &update).expect("asks"),
            "{arguments:?}: an update does not remove the release it was handed"
        );
        drop(update);

        launch.let_it_go();
        let status = running.wait().expect("it ends");
        assert!(status.success(), "{arguments:?}: {status}");
        let recorded = std::fs::read_to_string(&launch.out).expect("what it recorded");
        let mut lines = recorded.lines();
        assert_eq!(
            lines.next(),
            Some(&*format!("args:{}", arguments.join(" ")))
        );
        let marker = lines.next().expect("the marker").to_owned();
        let marker = marker.strip_prefix("marker:").expect("a marker");
        let (from, deadline) = match marker.split_once(';') {
            Some((from, deadline)) => (from, Some(deadline)),
            None => (marker, None),
        };
        assert_eq!(from, launch.mine.as_str(), "{arguments:?}");
        match arguments[1] {
            "hook" => assert!(
                deadline.is_some_and(|ms| ms.parse::<u64>().is_ok()),
                "a hook hands on the end of its deadline: {marker}"
            ),
            _ => assert_eq!(
                deadline, None,
                "a channel serves as long as its session does"
            ),
        }
        if arguments[1] == "hook" {
            assert_eq!(
                lines.collect::<Vec<_>>().join("\n").as_bytes(),
                HOOK_INPUT,
                "the replacement is given the input unread"
            );
        }
    }
}

/// A forwarder talks to its worker directly, and starts nothing, when the worker is of this release,
/// when its level is this build's, when its level is below the first that admits the other
/// forwarder, when the registration names no release, when the forwarder was itself started in
/// another's place, and when the release is being removed by an update.
#[test]
fn a_forwarder_goes_on_directly_where_the_other_forwarder_is_not_for_it() {
    enum Case {
        OwnRelease,
        ThisLevel,
        BelowTheFirstLevelThatAdmitsIt,
        NoRelease,
        StartedInAnotherPlace,
        BeingRemoved,
    }
    for case in [
        Case::OwnRelease,
        Case::ThisLevel,
        Case::BelowTheFirstLevelThatAdmitsIt,
        Case::NoRelease,
        Case::StartedInAnotherPlace,
        Case::BeingRemoved,
    ] {
        let minor = match case {
            Case::ThisLevel => this_minor(),
            // Below the level the constant names, whatever this build's own level is: the decision
            // reads the manifest's level and not what a release still retains.
            Case::BelowTheFirstLevelThatAdmitsIt => {
                kr_protocol::retained::FIRST_LEVEL_ADMITTING_OWN_FORWARDER
                    .minor()
                    .expect("a level below 1.0")
                    - 1
            }
            _ => this_minor() + 1,
        };
        let launch = Launch::new(minor);
        let registration = match case {
            Case::OwnRelease => launch.register(Some(&launch.mine)),
            Case::NoRelease => launch.register(None),
            _ => launch.register(Some(&launch.theirs)),
        };
        let marker = matches!(case, Case::StartedInAnotherPlace)
            .then(|| format!("{};{}", launch.theirs, u64::MAX));
        // An update that has taken the release to remove it holds its manifest exclusively.
        let removing = matches!(case, Case::BeingRemoved).then(|| {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(launch.store.manifest(&launch.theirs))
                .expect("the manifest opens");
            file.lock().expect("the removal's lock");
            file
        });
        let ran = run_with_input(
            launch.command(&registration, &["claude-code", "hook"], marker.as_deref()),
            HOOK_INPUT,
        );
        drop(removing);
        assert_eq!(ran.code, Some(0), "{}", ran.stderr);
        assert_eq!(ran.stdout, b"{}\n");
        assert!(
            !launch.it_ran(),
            "the other release's forwarder was started where it is not for the launch"
        );
    }
}

/// A hook started in place of another has what is left of the deadline the application gave the
/// first, and one whose deadline ended before it began answers neutrally and reaches for nothing:
/// it says nothing, where a hook that does its work without a worker to reach says why it could
/// not.
#[test]
fn a_hook_whose_deadline_ended_before_it_began_answers_at_once_and_reaches_for_nothing() {
    let launch = Launch::new(this_minor());
    let registration = launch.register(Some(&launch.mine));
    let worked = run_with_input(
        launch.command(&registration, &["claude-code", "hook"], None),
        HOOK_INPUT,
    );
    assert_eq!(worked.code, Some(0));
    assert_eq!(worked.stdout, b"{}\n");
    assert!(
        !worked.stderr.is_empty(),
        "control: a hook that does its work, with no worker to reach, says why it could not"
    );

    let marker = format!("{};1", launch.theirs);
    let expired = run_with_input(
        launch.command(&registration, &["claude-code", "hook"], Some(&marker)),
        HOOK_INPUT,
    );
    assert_eq!(expired.code, Some(0));
    assert_eq!(expired.stdout, b"{}\n");
    assert!(
        expired.stderr.is_empty(),
        "a hook past its deadline does no work: {:?}",
        expired.stderr
    );
}
