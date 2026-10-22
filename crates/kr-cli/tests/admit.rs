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

    /// `kr host versions`, which answers only for a `kr` of a store.
    fn versions(&self, program: &Path) -> (Output, Value) {
        let output = self.run(program, &["--json", "host", "versions"]);
        let said = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        (output, said)
    }

    /// A command that reads nothing of the host and recovers nothing, so a package manager's `kr`
    /// admits its release before it runs: what the first command of a person's day is. What it
    /// printed is the runtime and state roots, when it ran.
    fn first_command(&self, program: &Path) -> (Output, Value) {
        let output = self.run(program, &["--json", "host", "paths"]);
        let said = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        (output, said)
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
    let (admitted, shown) = home.first_command(&kr(&tree));
    assert!(admitted.status.success(), "{}", said(&admitted));
    assert!(
        shown.get("state_root").is_some(),
        "the command ran: {shown}"
    );
    assert_eq!(
        home.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        kr_cli::update::installer(&home.store)
            .expect("reads")
            .as_deref(),
        Some("homebrew")
    );
    // `host versions` answers only for a kr of a store.
    let (_, listed) = home.versions(&home.store.stable(Program::Kr));
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

    let (refused, shown) = home.first_command(&kr(&tree));
    assert!(!refused.status.success());
    assert!(
        said(&refused).contains("is not what its manifest says"),
        "{}",
        said(&refused)
    );
    assert_eq!(shown["ok"], false, "{shown}");
    assert!(shown.get("state_root").is_none(), "the command did not run");
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
    assert!(home.first_command(&kr(&first)).0.status.success());

    let second = home.prefix("Cellar", &two);
    // The upgrade removes the old keg, as Homebrew does, before the new release runs.
    std::fs::remove_dir_all(first.parent().expect("a keg")).expect("the old keg goes");
    let (upgraded, _) = home.first_command(&kr(&second));
    assert!(upgraded.status.success(), "{}", said(&upgraded));
    let (_, listed) = home.versions(&home.store.stable(Program::Kr));
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
    assert_eq!(
        kr_cli::update::installer(&home.store)
            .expect("reads")
            .as_deref(),
        Some("homebrew")
    );
}

/// KR-REQ-26.03: an update that waits leaves the release that is current in place and does not stop
/// the command, which runs as that release.
#[test]
fn an_update_that_waits_does_not_stop_the_command() {
    let home = Home::new();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let first = home.prefix("Cellar", &one);
    assert!(home.first_command(&kr(&first)).0.status.success());

    // Another update of the host is under way: it holds the update lock.
    let busy = home
        .store
        .try_lock_update()
        .expect("the lock")
        .expect("free");
    let second = home.prefix("Cellar", &two);
    let (waited, shown) = home.first_command(&kr(&second));
    assert!(waited.status.success(), "{}", said(&waited));
    assert!(
        said(&waited).contains("another update of this host is running"),
        "{}",
        said(&waited)
    );
    assert!(
        shown.get("state_root").is_some(),
        "the command ran: {shown}"
    );
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
            home.command(&kr(&tree), &["--json", "host", "paths"])
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

/// KR-REQ-26.03: a release that carries no update channel root is refused, and the command does not
/// run: nothing could check what the package manager's release says it is. The first test is the
/// control, a release with its root.
#[test]
fn a_release_with_no_channel_root_is_not_admitted_and_the_command_does_not_run() {
    let home = Home::new();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let tree = home.prefix("Cellar", &one);
    // A release whose manifest lists no root and whose files are all there: nothing but the root's
    // absence is wrong with it, and a first installation by hand takes it without a signature check.
    std::fs::remove_file(tree.join(kr_cli::update::release::CHANNEL_ROOT)).expect("removed");
    let path = tree.join("release.json");
    let mut document: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("the manifest")).expect("JSON");
    let files = document["signed"]["files"].as_array_mut().expect("files");
    files.retain(|file| file["path"] != kr_cli::update::release::CHANNEL_ROOT);
    std::fs::write(&path, document.to_string()).expect("written");

    let (refused, shown) = home.first_command(&kr(&tree));
    assert!(!refused.status.success(), "{}", said(&refused));
    assert!(
        said(&refused).contains("update channel root"),
        "{}",
        said(&refused)
    );
    assert!(shown.get("state_root").is_none(), "the command did not run");
    assert!(!home.store.is_store(), "nothing was admitted");
}

/// KR-REQ-26.03: a package manager's prefix that has lost its manifest is refused, and is never
/// taken for a build of this checkout that runs from where it is.
#[test]
fn a_package_managers_release_without_its_manifest_is_refused() {
    let home = Home::new();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let tree = home.prefix("Cellar", &one);
    std::fs::remove_file(tree.join("release.json")).expect("removed");

    let (refused, shown) = home.first_command(&kr(&tree));
    assert!(!refused.status.success());
    assert!(said(&refused).contains("no manifest"), "{}", said(&refused));
    assert_eq!(shown["ok"], false, "{shown}");
    assert!(shown.get("state_root").is_none(), "the command did not run");
    assert!(!home.store.is_store(), "nothing was admitted");
}

/// KR-REQ-26.03: a release older than the one the host runs is not put in the store, and the
/// command runs as the release that is current.
#[test]
fn a_package_managers_older_release_leaves_the_current_one_running() {
    let home = Home::new();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let newer = home.prefix("Cellar", &two);
    assert!(home.first_command(&kr(&newer)).0.status.success());

    let older = home.prefix("Cellar", &one);
    let (ran, shown) = home.first_command(&kr(&older));
    assert!(ran.status.success(), "{}", said(&ran));
    assert!(said(&ran).contains("no newer"), "{}", said(&ran));
    assert!(
        shown.get("state_root").is_some(),
        "the command ran: {shown}"
    );
    assert_eq!(
        home.store.current().expect("reads"),
        Some(two.name().clone())
    );
    assert!(
        !home.store.release_directory(one.name()).exists(),
        "the older release was not put in the store"
    );
}

/// KR-REQ-26.03: a release a rollback left in the store is not switched back to by running the
/// package manager's `kr` for it.
#[test]
fn a_release_kept_after_a_rollback_is_not_switched_back_to() {
    let home = Home::new();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let first = home.prefix("Cellar", &one);
    assert!(home.first_command(&kr(&first)).0.status.success());
    let second = home.prefix("Cellar", &two);
    assert!(home.first_command(&kr(&second)).0.status.success());
    let store_kr = home.store.stable(Program::Kr);
    let rolled = home.run(&store_kr, &["host", "rollback"]);
    assert!(rolled.status.success(), "{}", said(&rolled));
    assert_eq!(
        home.store.current().expect("reads"),
        Some(one.name().clone())
    );

    let (ran, _) = home.first_command(&kr(&second));
    assert!(ran.status.success(), "{}", said(&ran));
    assert_eq!(
        home.store.current().expect("reads"),
        Some(one.name().clone()),
        "the rollback stands"
    );
}

/// KR-REQ-26.03: a release that an update left staged because it waited is offered again at the next
/// command, and the host switches to it once nothing holds it. The release kept after a rollback is
/// the control: it is not offered, and the rollback stands.
#[test]
fn a_release_an_update_left_staged_is_offered_again() {
    let home = Home::new();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let first = home.prefix("Cellar", &one);
    assert!(home.first_command(&kr(&first)).0.status.success());

    // An update that waited for a live worker left the new release in the store, staged for the
    // next attempt, and made nothing current.
    let directory = home.store.release_directory(two.name());
    two.write(&directory);
    start_each_once(&directory);
    std::fs::write(
        home.store.record(),
        serde_json::json!({
            "format": kr_cli::update::RECORD_FORMAT,
            "previous": null,
            "staged": two.name().as_str(),
        })
        .to_string(),
    )
    .expect("the record");

    let second = home.prefix("Cellar", &two);
    let (taken, _) = home.first_command(&kr(&second));
    assert!(taken.status.success(), "{}", said(&taken));
    assert_eq!(
        home.store.current().expect("reads"),
        Some(two.name().clone()),
        "the staged release is made current at the next command: {}",
        said(&taken)
    );
}

/// KR-REQ-26.03: a package manager's copy of the release already current takes ownership of the
/// store, since the store's copy is that release byte for byte; a copy that only has its name does
/// not, and is refused.
#[test]
fn a_package_manager_takes_over_the_release_that_is_current_only_by_its_manifest() {
    let home = Home::new();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let by_hand = home.prefix("unpacked", &one);
    let installed = home.run(&kr(&by_hand), &["host", "install"]);
    assert!(installed.status.success(), "{}", said(&installed));
    assert_eq!(kr_cli::update::installer(&home.store).expect("reads"), None);

    let tree = home.prefix("Cellar", &one);
    let (ran, _) = home.first_command(&kr(&tree));
    assert!(ran.status.success(), "{}", said(&ran));
    assert_eq!(
        kr_cli::update::installer(&home.store)
            .expect("reads")
            .as_deref(),
        Some("homebrew")
    );

    // The control: a tree of the same name that is another release's manifest is not that release.
    let other = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 7);
    let forged = home.prefix("Caskroom", &other);
    let (refused, shown) = home.first_command(&kr(&forged));
    assert!(!refused.status.success(), "{}", said(&refused));
    assert!(shown.get("state_root").is_none(), "the command did not run");
}

/// KR-REQ-26.03: a release the current one refuses stops the commands that need it admitted, and the
/// refusal names the store's own `kr`; `kr host versions` and `kr host rollback` do not need it
/// admitted, and run as the store's copy of the release that is current.
#[test]
fn a_refused_release_does_not_hold_back_the_commands_that_recover() {
    let home = Home::new();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let first = home.prefix("Cellar", &one);
    assert!(home.first_command(&kr(&first)).0.status.success());
    let second = home.prefix("Cellar", &two);
    std::fs::write(second.join(module_tree()[0].0), "# something else\n").expect("changed");

    let (refused, shown) = home.first_command(&kr(&second));
    assert!(!refused.status.success(), "{}", said(&refused));
    assert!(shown.get("state_root").is_none(), "the command did not run");
    let store_kr = home.store.stable(Program::Kr).display().to_string();
    assert!(
        said(&refused).contains(&store_kr),
        "the refusal names the store's own kr: {}",
        said(&refused)
    );

    let (listed, versions) = home.versions(&kr(&second));
    assert!(listed.status.success(), "{}", said(&listed));
    assert_eq!(versions["releases"][0]["release"], one.name().as_str());
    // The store's copy answers a rollback, and has none to go back to: a `kr` of the prefix would
    // say it is not of an installed release.
    let rolled = home.run(&kr(&second), &["host", "rollback"]);
    assert!(!rolled.status.success(), "{}", said(&rolled));
    assert!(
        said(&rolled).contains("no release it was on before"),
        "{}",
        said(&rolled)
    );
    assert_eq!(
        home.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// KR-REQ-26.03: an update that fails once it has staged the release is refused once. The release
/// is not offered again at each command, which would repack it and fail again.
#[test]
fn an_update_that_fails_after_it_staged_the_release_is_not_offered_again() {
    let home = Home::new();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let first = home.prefix("Cellar", &one);
    assert!(home.first_command(&kr(&first)).0.status.success());

    // A store listed in a way the current kr does not know: the update stages the release and then
    // refuses the switch, before anything stops.
    let mut stores = release_stores();
    stores.push(ReleaseStore {
        store: "ledgers".to_owned(),
        scope: StoreScope::Unknown,
        path: "ledgers.sqlite".to_owned(),
        recording: Recording::SqliteUserVersion,
        version: 1,
        migrates_from: 1,
        reads_through: None,
    });
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).reading(stores);
    let second = home.prefix("Cellar", &two);
    let (refused, _) = home.first_command(&kr(&second));
    assert!(!refused.status.success(), "{}", said(&refused));
    assert!(
        said(&refused).contains("was not admitted"),
        "{}",
        said(&refused)
    );
    assert!(
        home.store.release_directory(two.name()).exists(),
        "the update staged the release before it refused the switch"
    );

    let (again, shown) = home.first_command(&kr(&second));
    assert!(again.status.success(), "{}", said(&again));
    assert!(
        said(&again).contains("is in this host's store already"),
        "{}",
        said(&again)
    );
    assert!(
        shown.get("state_root").is_some(),
        "the command ran: {shown}"
    );
    assert_eq!(
        home.store.current().expect("reads"),
        Some(one.name().clone())
    );
}
