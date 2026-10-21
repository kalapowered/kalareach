//! The release a package manager puts on a host is admitted to the host's store by the first
//! command of its `kr`, and the command runs as the store's own copy.
//!
//! A package manager keeps the release unpacked under a prefix of its own (`Cellar` or `Caskroom`
//! for Homebrew). Each release here is assembled from the programs this workspace built, signed
//! with a channel root this process makes, and written under such a prefix inside a host tree of the
//! test's own, whose home directory names the store as a default install does.

#![cfg(unix)]
#![allow(dead_code, unused_imports)]

mod stored_formats;
mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;
#[cfg(target_os = "linux")]
#[path = "support/user_manager.rs"]
mod user_manager;

include!("support/update_harness.rs");

/// A host tree whose home directory names the store: where `kr` looks for it when nothing says.
struct Home {
    host: Host,
    home: PathBuf,
    store: Store,
}

impl Home {
    fn new() -> Self {
        let host = Host::bare();
        let home = host.scratch("home");
        let root = if cfg!(target_os = "macos") {
            home.join("Library/Application Support/KalaReach/host")
        } else {
            home.join(".local/share/kalareach/host")
        };
        Self {
            store: Store::at(root),
            host,
            home,
        }
    }

    /// Writes a release under a package manager's prefix, and returns its `kr`.
    fn prefix(&self, manager_directory: &str, release: &Assembled) -> PathBuf {
        let tree = self
            .host
            .scratch(manager_directory)
            .join("kalareach")
            .join(release.name().as_str())
            .join("libexec");
        release.write(&tree);
        start_each_once(&tree);
        tree
    }

    fn command(&self, program: &Path, arguments: &[&str]) -> Command {
        let mut command = self.host.command(program, arguments);
        command
            .env("HOME", &self.home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn run(&self, program: &Path, arguments: &[&str]) -> Output {
        let child = self
            .command(program, arguments)
            .spawn()
            .unwrap_or_else(|error| panic!("{} did not start: {error}", program.display()));
        finish_within(child, Duration::from_secs(300))
    }

    fn versions(&self, program: &Path) -> (Output, Value) {
        let output = self.run(program, &["--json", "host", "versions"]);
        let said = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        (output, said)
    }

    fn record(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.store.record()).expect("the store's record"))
            .expect("JSON")
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        // An installed release is read-only, and the tree goes whole: its directories are opened
        // to removal first.
        writable(self.store.root());
    }
}

fn kr(tree: &Path) -> PathBuf {
    tree.join("bin").join(Program::Kr.file_name())
}

/// What a command said, on standard error and, in `--json` mode, in the failure it printed.
fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    )
}

/// KR-REQ-26.03: the first command of a package manager's `kr` puts its release into the store and
/// makes it current, runs as the store's copy, and records the package manager; a `kr` that no
/// package manager put where it is does none of it, which is the control.
#[test]
fn the_first_command_of_a_package_managers_kr_admits_its_release() {
    let home = Home::new();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);

    // The control: an unpacked release that no package manager keeps is not admitted by running it.
    let unpacked = home.prefix("unpacked", &one);
    let (control, _) = home.versions(&kr(&unpacked));
    assert!(
        !control.status.success(),
        "an unpacked release is not a store's"
    );
    assert!(
        said(&control).contains("not of an installed release"),
        "{}",
        said(&control)
    );
    assert!(!home.store.is_store(), "nothing was admitted");

    let tree = home.prefix("Cellar", &one);
    let (admitted, listed) = home.versions(&kr(&tree));
    assert!(admitted.status.success(), "{}", said(&admitted));
    assert_eq!(
        home.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(home.record()["installer"], "homebrew");
    // `host versions` answers only for a kr of a store, so the command ran as the store's copy.
    assert_eq!(listed["releases"][0]["release"], one.name().as_str());
    assert_eq!(listed["releases"][0]["current"], true);

    // The prefix is the package manager's, and its removal leaves the host as it is.
    std::fs::remove_dir_all(home.host.scratch("Cellar")).expect("the prefix goes");
    let (after, listed) = home.versions(&home.store.stable(Program::Kr));
    assert!(after.status.success(), "{}", said(&after));
    assert_eq!(listed["releases"][0]["release"], one.name().as_str());
    assert!(
        home.store
            .release_directory(one.name())
            .join("bin/kr")
            .is_file()
    );
}

/// KR-REQ-26.03: a release that is not what its signed manifest says is refused with its reason, and
/// the command does not run.
#[test]
fn a_tree_that_cannot_be_checked_is_not_admitted_and_the_command_does_not_run() {
    let home = Home::new();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let tree = home.prefix("Cellar", &one);
    std::fs::write(tree.join(module_tree()[0].0), "# something else\n").expect("changed");

    let (refused, listed) = home.versions(&kr(&tree));
    assert!(!refused.status.success());
    assert!(
        said(&refused).contains("is not what its manifest says"),
        "{}",
        said(&refused)
    );
    assert_eq!(listed["ok"], false, "{listed}");
    assert!(listed.get("releases").is_none(), "the command did not run");
    assert_eq!(home.store.current().ok().flatten(), None);
}

/// KR-REQ-26.03: a package manager's upgrade leaves the release before it in `versions/`, and the
/// new release is current from its first command.
#[test]
fn an_upgrade_by_a_package_manager_leaves_the_release_before_it_in_the_store() {
    let home = Home::new();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let first = home.prefix("Cellar", &one);
    assert!(home.versions(&kr(&first)).0.status.success());

    let second = home.prefix("Cellar", &two);
    // The upgrade removes the old keg, as Homebrew does, before the new release runs.
    std::fs::remove_dir_all(first.parent().expect("a keg")).expect("the old keg goes");
    let (upgraded, listed) = home.versions(&kr(&second));
    assert!(upgraded.status.success(), "{}", said(&upgraded));
    assert_eq!(
        home.store.current().expect("reads"),
        Some(two.name().clone())
    );
    assert!(
        home.store
            .release_directory(one.name())
            .join("bin/kr")
            .is_file(),
        "the release before it is kept"
    );
    let names: Vec<&str> = listed["releases"]
        .as_array()
        .expect("releases")
        .iter()
        .filter_map(|kept| kept["release"].as_str())
        .collect();
    assert!(names.contains(&one.name().as_str()) && names.contains(&two.name().as_str()));
    assert_eq!(home.record()["installer"], "homebrew");
}

/// KR-REQ-26.03: an update that waits leaves the release that is current in place and does not stop
/// the command, which runs as that release.
#[test]
fn an_update_that_waits_does_not_stop_the_command() {
    let home = Home::new();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let first = home.prefix("Cellar", &one);
    assert!(home.versions(&kr(&first)).0.status.success());

    // Another update of the host is under way: it holds the update lock.
    let busy = home
        .store
        .try_lock_update()
        .expect("the lock")
        .expect("free");
    let second = home.prefix("Cellar", &two);
    let (waited, listed) = home.versions(&kr(&second));
    assert!(waited.status.success(), "{}", said(&waited));
    assert!(
        said(&waited).contains("another update of this host is running"),
        "{}",
        said(&waited)
    );
    assert_eq!(listed["releases"][0]["release"], one.name().as_str());
    drop(busy);
    assert_eq!(
        home.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// KR-REQ-26.03: two first commands at once admit the release once, and both run.
#[test]
fn two_first_commands_at_once_admit_one_release() {
    let home = Home::new();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let tree = home.prefix("Cellar", &one);
    let children: Vec<_> = (0..2)
        .map(|_| {
            home.command(&kr(&tree), &["--json", "host", "versions"])
                .spawn()
                .expect("kr starts")
        })
        .collect();
    for child in children {
        let output = finish_within(child, Duration::from_secs(300));
        assert!(output.status.success(), "{}", said(&output));
    }
    assert_eq!(
        home.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(home.store.releases().expect("reads").len(), 1);
}
