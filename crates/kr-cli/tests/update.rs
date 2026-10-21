//! A host installed as a store of releases: each program holds the release it runs, starts the
//! programs of that release, and names it; `kr host install` puts a first release in, and
//! `kr host update` hands the control daemon over to another while every live session keeps the
//! release it started from, or waits, exit 9, and says why.
//!
//! Every release here is assembled from the programs this workspace built: `kr`, the restoration
//! guard, the control daemon, the worker, the description process, the forwarder and the plugin
//! host, copied once to the internal disk and then given to each release as files of its own, as
//! an installed release has. Each release
//! carries an update channel root this process makes, whose targets key signs its manifest. Each
//! test builds its store inside a host tree of its own, with its own runtime and state roots, so
//! nothing here reads or changes the person's own installation. A daemon runs as a process of its
//! own, with its keys in the tree's own secrets directory; every daemon still serving the tree when
//! a test ends is handed over and stopped through its own door, and the tree ends every worker it
//! started before it goes.

#![cfg(unix)]

mod stored_formats;
mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;
#[cfg(target_os = "linux")]
#[path = "support/user_manager.rs"]
mod user_manager;

include!("support/update_harness.rs");

/// A program that is older than a source it was built from, one built from another checkout's sources,
/// and one whose list names a source that is gone are each refused by name, and a program newer than
/// every source it lists, one with no list and one with a list older than itself are not. This is the
/// check the suite makes before it assembles a release from the daemons found in a target directory,
/// for a program built by name (`cargo build -p ...`), which writes its list with it. A program a
/// workspace test run made has no list of its own to judge it by, and is used as it is: the box and
/// core-ci build every program first, and a package-scoped run builds them by the command the
/// refusal names.
#[test]
fn a_program_not_built_from_this_tree_is_refused() {
    let directory = tempfile::tempdir().expect("a directory");
    let repository = directory.path().join("tree");
    let own = repository.join("crates/kr-controller/src/bin");
    std::fs::create_dir_all(&own).expect("the crate");
    let source = own.join("kr-controller.rs");
    std::fs::write(&source, "fn main() {}").expect("a source");
    let other_tree = directory
        .path()
        .join("another/crates/kr-controller/src/bin/kr-controller.rs");
    std::fs::create_dir_all(other_tree.parent().expect("a directory")).expect("another tree");
    std::fs::write(&other_tree, "fn main() {}").expect("a source");
    let target = directory.path().join("target");
    std::fs::create_dir_all(&target).expect("the target directory");
    let program = target.join("kr-controller");
    let listing = |lists: &[&Path]| {
        let sources: Vec<String> = lists
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        std::fs::write(
            target.join("kr-controller.d"),
            format!("{}: {}\n", program.display(), sources.join(" ")),
        )
        .expect("a list of sources");
    };
    let long_ago = std::time::SystemTime::now() - Duration::from_secs(3600);
    let set_time = |path: &Path, when: std::time::SystemTime| {
        std::fs::File::options()
            .write(true)
            .open(path)
            .expect("opens")
            .set_modified(when)
            .expect("sets the time");
    };

    // The control: a program built after its sources.
    std::fs::write(&program, "built").expect("a program");
    set_time(&source, long_ago);
    listing(&[&source]);
    assert_eq!(
        built_from_another_tree(&program, "kr-controller", &repository),
        None
    );

    // A file the crate includes from outside its sources, named through `..` as an included skill
    // text is, is not another checkout's source.
    let included = repository.join("skills/contact.md");
    std::fs::create_dir_all(included.parent().expect("a directory")).expect("the skills");
    std::fs::write(&included, "text").expect("a file the crate includes");
    set_time(&included, long_ago);
    let through_parents = repository.join("crates/kr-controller/src/../../../skills/contact.md");
    listing(&[&source, &through_parents]);
    assert_eq!(
        built_from_another_tree(&program, "kr-controller", &repository),
        None
    );
    listing(&[&source]);

    // A source changed since it was built.
    set_time(
        &source,
        std::time::SystemTime::now() + Duration::from_secs(60),
    );
    let why = built_from_another_tree(&program, "kr-controller", &repository)
        .expect("a stale program is refused");
    assert!(why.contains("has changed since it was built"), "{why}");
    set_time(&source, long_ago);

    // A source it lists that the tree no longer has.
    let gone = repository.join("crates/kr-controller/src/bin/gone.rs");
    listing(&[&source, &gone]);
    let why = built_from_another_tree(&program, "kr-controller", &repository)
        .expect("a program built from a source that is gone is refused");
    assert!(why.contains("cannot be looked at"), "{why}");
    listing(&[&source]);

    // Built from the sources of another checkout.
    listing(&[&other_tree]);
    let why = built_from_another_tree(&program, "kr-controller", &repository)
        .expect("another checkout's build is refused");
    assert!(why.contains("another/crates/kr-controller"), "{why}");

    // No list of its sources: a program made again by a run that writes none is not judged.
    std::fs::remove_file(target.join("kr-controller.d")).expect("removes the list");
    assert_eq!(
        built_from_another_tree(&program, "kr-controller", &repository),
        None
    );
    // A list older than the program is the list of an earlier build, whatever it names.
    listing(&[&other_tree, &gone]);
    set_time(&target.join("kr-controller.d"), long_ago);
    set_time(&program, std::time::SystemTime::now());
    assert_eq!(
        built_from_another_tree(&program, "kr-controller", &repository),
        None
    );
    // A list that names none of its crate's sources. The program is made older first, because a
    // file written now is stamped with the kernel's coarse clock, which can read earlier than the
    // exact time just given to the program, and then the list would be one of an earlier build.
    set_time(&program, long_ago);
    listing(&[]);
    let why = built_from_another_tree(&program, "kr-controller", &repository)
        .expect("a list of nothing is refused");
    assert!(why.contains("lists none of the sources"), "{why}");
}

/* -------------------------------------------------------------------------------------------- */
/* Each program's hold                                                                          */
/* -------------------------------------------------------------------------------------------- */

/// KR-REQ-26.06: every program of a release that is being removed refuses to start, and the same
/// programs start from the release's place in the store.
#[test]
fn no_program_of_a_release_being_removed_starts() {
    let host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let installed = host.put(&one);
    // What the removal of a release leaves between its move and its deletion.
    let removing = host.store.trash().join(format!("{}-leaving", one.name()));
    one.write(&removing);
    for program in Program::ALL {
        // The control: from the release's own place, each program starts.
        let started = host.run(
            &installed.join("bin").join(program.file_name()),
            &["--version"],
        );
        assert!(
            started.status.success(),
            "{} starts from its release: {}",
            program.name(),
            String::from_utf8_lossy(&started.stderr)
        );
        let refused = host.run(
            &removing.join("bin").join(program.file_name()),
            &["--version"],
        );
        assert!(
            !refused.status.success(),
            "{} of a release being removed does not start",
            program.name()
        );
        // The guard says nothing of its own: the attach that started it says the guard did not
        // start. Every other program says why.
        if program != Program::AttachGuard {
            let said = String::from_utf8_lossy(&refused.stderr);
            assert!(
                said.contains("is being removed from this host"),
                "{} says why: {said}",
                program.name()
            );
        }
    }
    // A hook an application runs is the one program that answers instead: its contract is a
    // neutral answer whatever prevents its work, and an application reads a failing exit as an
    // error. It does no work, and says why on standard error.
    let hook = host.run(
        &removing.join("bin").join(Program::Hook.file_name()),
        &["claude-code", "hook"],
    );
    let said = String::from_utf8_lossy(&hook.stderr);
    assert_eq!(hook.status.code(), Some(0), "a hook answers: {said}");
    assert_eq!(hook.stdout, b"{}\n", "a hook answers neutrally");
    assert!(
        said.contains("is being removed from this host"),
        "a hook says why: {said}"
    );
}

/// KR-REQ-26.06: a daemon of a release states it, records the roots it serves, holds its release,
/// and starts its own release's worker, which states the release too; the release stays for as
/// long as either runs.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_of_a_release_starts_its_own_release_s_worker_and_holds_the_release() {
    let mut host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.put(&one);
    host.switch(one.name());
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    let roots = host.store.recorded_roots().expect("reads the roots");
    assert_eq!(roots.len(), 1, "the daemon recorded the roots it serves");
    assert_eq!(
        std::fs::canonicalize(&roots[0].state_root).expect("resolves"),
        std::fs::canonicalize(host.tree.paths().state_root()).expect("resolves")
    );

    let kr = host.store.stable(Program::Kr);
    let (display, session_id) = host.new_session(&kr);
    assert_eq!(
        host.worker_build(session_id).await,
        format!("kr-worker/{}", one.name()),
        "the worker the daemon started is of the daemon's own release"
    );
    assert!(
        host.store.held(one.name()).expect("asks"),
        "the release is held while its programs run"
    );
    host.close(&kr, &display);
}

/// A daemon of a release starts its own release's worker with its own release's packages, and
/// takes no other: a session it launched with another would run what the store does not hold.
#[test]
fn a_daemon_of_a_release_takes_no_other_worker_and_no_other_packages() {
    let host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.put(&one);
    host.switch(one.name());
    let controller = host.program(one.name(), Program::Controller);
    let arguments = host.daemon_arguments();
    let mut with_worker: Vec<&str> = arguments.iter().map(String::as_str).collect();
    with_worker.extend(["--worker", "/bin/sh"]);
    let refused = host.run(&controller, &with_worker);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--worker names another program"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let plain: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let refused = host
        .command(&controller, &plain)
        .env("KR_SHELL_PACKAGES", host.tree.root())
        .stdin(Stdio::null())
        .output()
        .expect("runs");
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("KR_SHELL_PACKAGES names others"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        host.store.recorded_roots().expect("reads").is_empty(),
        "neither refusal served the environment"
    );
}

/// A daemon of a release that is no longer current does not start: the current release's daemon
/// serves this host. The current release's own daemon does.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_of_a_release_that_is_no_longer_current_does_not_start() {
    let mut host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.put(&one);
    host.put(&two);
    host.switch(two.name());
    let arguments = host.daemon_arguments();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let refused = host.run(&host.program(one.name(), Program::Controller), &arguments);
    assert!(!refused.status.success());
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(
        said.contains(&format!(
            "this daemon is of release {}, and this host's current release is {}",
            one.name(),
            two.name()
        )),
        "{said}"
    );
    // The control: the current release's daemon starts.
    let current = host.program(two.name(), Program::Controller);
    host.start_daemon(&current).await;
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
}

/* -------------------------------------------------------------------------------------------- */
/* Installing and updating                                                                       */
/* -------------------------------------------------------------------------------------------- */

/// KR-REQ-26.09: `kr host install`, run as the unpacked release's own `kr`, puts the release into a
/// new store read-only, makes it current and records the store; a tree that is not what its
/// manifest says is refused and nothing is made current.
#[test]
fn kr_host_install_puts_a_first_release_in_a_store_and_makes_it_current() {
    let host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let store = host.store.root().display().to_string();

    // The control: the same tree with one module changed is refused.
    let tampered = host.scratch("tampered").join(one.name().as_str());
    one.write(&tampered);
    std::fs::write(tampered.join(module_tree()[0].0), "# something else\n").expect("changed");
    let refused = host.run(
        &tampered.join("bin").join(Program::Kr.file_name()),
        &["host", "install", "--store", &store],
    );
    assert!(!refused.status.success(), "a tampered tree is refused");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("is not what its manifest says"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(host.store.current().ok().flatten(), None);

    host.install(&one);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert!(host.store.is_store(), "the store's record is written");
    let installed = host.store.release_directory(one.name());
    for file in [
        "bin/kr",
        module_tree()[0].0,
        kr_protocol::update::MANIFEST_FILE,
    ] {
        let about = std::fs::metadata(installed.join(file)).expect("installed");
        assert!(about.permissions().readonly(), "{file} is read-only");
    }
    // A second install into a store with a current release goes through an update instead.
    let again = host.scratch("again").join(one.name().as_str());
    one.write(&again);
    let refused = host.run(
        &again.join("bin").join(Program::Kr.file_name()),
        &["host", "install", "--store", &store],
    );
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("already has a current release"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
}

/// KR-REQ-26.09: `kr host install` refuses a tree whose signed manifest lists no plugin host, a
/// program every host runs, and the same release with it is installed into the same store.
#[test]
fn kr_host_install_refuses_a_release_that_lacks_a_program_a_host_runs() {
    let host = Host::bare();
    let store = host.store.root().display().to_string();
    let lacking = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).without(&["kr-plugin-host"]);
    let tree = host.scratch("lacking").join(lacking.name().as_str());
    lacking.write(&tree);
    let refused = host.run(
        &tree.join("bin").join("kr"),
        &["host", "install", "--store", &store],
    );
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a release without it is refused"
    );
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(said.contains("`kr-plugin-host`"), "{said}");
    assert_eq!(host.store.current().ok().flatten(), None);

    let whole = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&whole);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(whole.name().clone())
    );
}

/// KR-REQ-26.10: `kr host install` refuses a tree whose signed manifest lists no store, because the
/// stores a release reads are what a host checks before it switches to the release, and the same
/// release with its stores is installed into the same store.
#[test]
fn kr_host_install_refuses_a_release_that_lists_no_store() {
    let host = Host::bare();
    let store = host.store.root().display().to_string();
    let lacking = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).without_stores();
    let tree = host.scratch("lacking").join(lacking.name().as_str());
    lacking.write(&tree);
    let refused = host.run(
        &tree.join("bin").join("kr"),
        &["host", "install", "--store", &store],
    );
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a release that lists no store is refused"
    );
    assert_eq!(host.store.current().ok().flatten(), None);

    let whole = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&whole);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(whole.name().clone())
    );
}

/// KR-REQ-26.06, KR-REQ-26.08, KR-REQ-26.09, KR-ACC-035: an update checks the release, hands the
/// daemon over and starts the new release's daemon as the old one was started, while a live
/// session keeps running the release it started from with that release's module tree, which stays
/// for as long as the session holds it and goes once nothing does.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_replaces_the_daemon_and_a_live_session_keeps_its_release() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let three = Assembled::at_this_level("0.3.0+cccccccccccc", 3);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let (display, session_id) = host.new_session(&host.program(one.name(), Program::Kr));
    let scratch = host.scratch("archives");
    let archive_two = scratch.join("two.tar.gz");
    two.archive(&archive_two);

    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive_two.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["target"], two.name().as_str(), "{said}");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the daemon was started again, of the new release"
    );
    assert_eq!(
        host.worker_build(session_id).await,
        format!("kr-worker/{}", one.name()),
        "the live session runs the release it started from"
    );
    let module = host
        .store
        .release_directory(one.name())
        .join(module_tree()[0].0);
    assert!(module.is_file(), "its module tree is still there");
    let record = host.record();
    assert_eq!(record["previous"], one.name().as_str());
    assert!(record["update"].is_null(), "the update settled: {record}");

    // Another update: the first release is no longer the previous one, and the live session still
    // holds it, so it stays with its module tree.
    let archive_three = scratch.join("three.tar.gz");
    three.archive(&archive_three);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive_three.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["removed"], serde_json::json!([]), "{said}");
    assert!(module.is_file(), "a held release is never removed");
    let (_, versions) = host.kr_json(&["host", "versions", "--json"]);
    let first = versions["releases"]
        .as_array()
        .and_then(|releases| {
            releases
                .iter()
                .find(|kept| kept["release"] == one.name().as_str())
        })
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(first["held"], true, "{versions}");
    assert_eq!(first["previous"], false, "{versions}");
    assert_eq!(
        first["sequence"], 1,
        "a release's sequence is read from it: {versions}"
    );

    // The control: once the session closes nothing holds the first release, and the next update
    // takes it away.
    host.close(&host.store.stable(Program::Kr), &display);
    host.released(one.name()).await;
    let four = Assembled::at_this_level("0.4.0+dddddddddddd", 4);
    let archive_four = scratch.join("four.tar.gz");
    four.archive(&archive_four);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive_four.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The first release, and the second, which is no longer the previous one either.
    assert_eq!(
        said["removed"],
        serde_json::json!([one.name().as_str(), two.name().as_str()]),
        "{said}"
    );
    assert!(!host.store.release_directory(one.name()).exists());
    assert!(
        host.store.release_directory(three.name()).exists(),
        "the previous one stays"
    );
}

/// KR-REQ-26.08: an update to a release whose daemon does not retain a live session's level waits,
/// exit 9, naming the session and its protocol, with nothing stopped and the release staged.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_waits_for_a_session_its_release_does_not_retain() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let (display, _) = host.new_session(&host.store.stable(Program::Kr));
    let another = if PACKAGE_VERSION.major == 0 {
        PackageVersion::new(0, PACKAGE_VERSION.minor + 1, 0)
    } else {
        PackageVersion::new(PACKAGE_VERSION.major + 1, 0, 0)
    };
    let elsewhere = Assembled::new(
        "0.2.0+bbbbbbbbbbbb",
        2,
        CompatibilityLevel::of(another),
        the_root(),
    );
    let scratch = host.scratch("archives");
    let archive = scratch.join("elsewhere.tar.gz");
    elsewhere.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "an update that waits exits 9"
    );
    assert_eq!(said["exit_code"], 9, "{said}");
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&format!(
            "the update to {} waits: session {display} runs kr-worker/{} with protocol {}",
            elsewhere.name(),
            one.name(),
            PACKAGE_VERSION
        )),
        "{said}"
    );
    assert_eq!(said["code"], "RESOURCE_UNAVAILABLE", "{said}");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "nothing was stopped"
    );
    assert!(
        host.daemons
            .iter_mut()
            .all(|daemon| matches!(daemon.try_wait(), Ok(None))),
        "the daemon this test started is still the one running"
    );
    assert_eq!(host.record()["staged"], elsewhere.name().as_str());
    assert!(host.store.release_directory(elsewhere.name()).is_dir());
}

/// KR-REQ-26.07: how long a session lasts across updates is decided by the compatibility levels a
/// release retains and by how long the session runs, whatever the release's table of public majors
/// lists. A release whose table lists major 2 and no longer major 1, the major the session's release
/// listed, and whose daemon retains the session's level, is updated to with the session kept: the
/// worker is the process it was, and the session closes at the end through release two's `kr`. A
/// release whose table lists no major 1 either, and which does not retain the session's level, still
/// waits for the session, exit 9, with nothing stopped, and goes ahead once the session has closed.
/// This build has one public major, so no public window ends in this case: it shows that an update
/// reads the levels a release retains and never its table of public majors, so the local window is
/// independent of the public table. That the local window outlasts a public window that ended is
/// shown against a daemon that states a later major, in the upgrade suite.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_keeps_or_waits_for_a_session_by_the_levels_it_retains_whatever_its_table_lists()
{
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    assert_eq!(
        one.manifest.public_majors,
        [1],
        "the release the session starts from lists major 1"
    );
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let (display, session_id) = host.new_session(&host.program(one.name(), Program::Kr));
    let worker = host.worker_process(session_id);
    let scratch = host.scratch("archives");

    // A release whose table no longer lists major 1 and whose daemon retains the session's level.
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).listing_public_majors(&[2]);
    let archive_two = scratch.join("two.tar.gz");
    two.archive(&archive_two);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive_two.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "an update whose table no longer lists the session's major still goes ahead over a \
         session it retains: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the daemon is the new release's"
    );
    let daemon_of_two = host.daemon_process().await;
    assert_eq!(
        host.worker_process(session_id),
        worker,
        "the session's worker is the process it was"
    );
    assert_eq!(
        host.worker_build(session_id).await,
        format!("kr-worker/{}", one.name()),
        "and it answers, on the release it started from"
    );

    // A release whose table does not list major 1 either, and which retains the level of the release
    // before this one and not the session's: the session still holds the update.
    let three = Assembled::new(
        "0.3.0+cccccccccccc",
        3,
        kr_protocol::retained::RETAINED_WORKER_LEVELS[0],
        the_root(),
    )
    .listing_public_majors(&[2]);
    let archive_three = scratch.join("three.tar.gz");
    three.archive(&archive_three);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive_three.display().to_string(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "the table having no major 1 does not free the host of the session: {said}"
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&format!(
            "the update to {} waits: session {display} runs kr-worker/{}",
            three.name(),
            one.name()
        )),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
    assert_eq!(
        host.daemon_process().await,
        daemon_of_two,
        "nothing was stopped: the daemon is the process that started with release two"
    );
    assert_eq!(
        kr_ipc::identity::process_state(&worker),
        kr_ipc::identity::ProcessState::Running,
        "the session's worker runs on"
    );
    // The session closes through release two's `kr`, and the wait ends with the worker: the same
    // update, run again, goes ahead.
    host.close(&host.store.stable(Program::Kr), &display);
    host.worker_ended(&worker).await;
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive_three.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "the update that waited goes ahead once the session has ended: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(three.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", three.name())
    );
}

/// KR-REQ-26.07: a host goes from a release of public major 1 to a release whose daemon states major
/// 2, and back, with no session live. The `kr` of the release before updates to it and sees that its
/// daemon answers, though that daemon admits clients of major 2 alone, because the manifest of the
/// release it makes current lists major 2; the `kr` of release two, which states major 2, rolls the
/// host back and sees release one's daemon answer in the same way. Each daemon states the major its
/// release names however it is started, and a client of the other major is refused by it.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_goes_from_one_public_major_to_the_next_and_back() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).whose_daemon_states(None);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2)
        .whose_daemon_states(Some(LATER_MAJOR))
        .listing_public_majors(&[LATER_MAJOR]);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    assert_eq!(
        host.daemon_states().await,
        1,
        "release one's daemon states major 1"
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
    assert!(
        output.status.success(),
        "an update across a public major goes ahead: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the daemon is the new release's"
    );
    assert_eq!(
        host.daemon_states().await,
        LATER_MAJOR,
        "and it states major 2"
    );
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    assert!(
        LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .is_err(),
        "a client of major 1 is refused by a daemon that states major 2"
    );

    // Release two's `kr` states major 2, as a program of a release of that major does.
    let (output, said) = host.kr_json_with(
        &[(LATER_MAJOR_VARIABLE, std::ffi::OsStr::new("2"))],
        &["host", "rollback", "--json"],
    );
    assert!(
        output.status.success(),
        "a rollback across a public major goes ahead: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon is release one's again"
    );
    assert_eq!(
        host.daemon_states().await,
        1,
        "and it states major 1, though the rollback ran with major 2 set"
    );
    assert!(
        LocalClient::connect_stating(
            &endpoint,
            LocalClientKind::Cli,
            build(),
            kr_protocol::hello::ProtocolVersion::new(LATER_MAJOR, 0),
        )
        .await
        .is_err(),
        "a client of major 2 is refused by a daemon that states major 1"
    );
}

/// KR-REQ-26.09: an update an earlier run left after its switch is finished by the next run: the
/// daemon it recorded is started from the release `current` names, and the update settles.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_left_after_its_switch_is_finished_by_the_next_run() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    host.put(&two);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    // What a run that stopped after its switch leaves: the daemon stopped, `current` on the
    // target, and the update recorded as switched.
    for mut daemon in host.daemons.drain(..) {
        daemon.kill().expect("stops");
        daemon.wait().expect("ends");
    }
    host.record_a_switched_update(&one, &two);

    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
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
    assert_eq!(said["target"], two.name().as_str(), "{said}");
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the recorded daemon was started from the release current names"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], one.name().as_str(), "{record}");
    // The record the update left was written by an earlier build, as format 1; it is written again
    // in the format this build writes.
    assert_eq!(record["format"], 2, "{record}");
}

/// KR-REQ-26.10: a transaction an earlier build began holds no root, and settles on the roots of its
/// two releases that can be read, each on its own: the root file of the release left is damaged,
/// and the second root the release switched to carries is still the root the host trusts.
#[tokio::test(flavor = "multi_thread")]
async fn a_transaction_with_no_root_settles_on_the_release_roots_that_can_be_read() {
    use std::os::unix::fs::PermissionsExt as _;

    let mut host = Host::bare();
    let rotated = channel_root_naming(2, &keys().root, &keys().next_targets, &[&keys().root]);
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::new(
        "0.2.0+bbbbbbbbbbbb",
        2,
        CompatibilityLevel::of(PACKAGE_VERSION),
        &rotated,
    );
    host.install(&one);
    host.put(&two);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    host.record_a_switched_update(&one, &two);
    assert!(
        host.record()["update"]["trusted_root"].is_null(),
        "the transaction is one an earlier build began"
    );
    // The root of the release left cannot be read.
    let share = host.store.release_directory(one.name()).join("share");
    std::fs::set_permissions(&share, std::fs::Permissions::from_mode(0o755)).expect("opened");
    let root_file = share.join("update-root.json");
    std::fs::set_permissions(&root_file, std::fs::Permissions::from_mode(0o644)).expect("opened");
    std::fs::write(&root_file, b"{ not a root").expect("damaged");

    let archive = host.scratch("archives").join("two.tar.gz");
    // Release two carries the second root, so the host that has switched to it checks an archive
    // against that root: the manifest is signed with the key it names.
    two.archive_signed(&archive, &keys().next_targets);
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
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(
        record["trusted_root"]["signed"]["version"], 2,
        "the root the release switched to carries is the one trusted: {record}"
    );
}

/// KR-REQ-26.09: an update an earlier run left after its switch finds the environment held by a
/// daemon of the release before it, which resumes and goes on answering as that release: the update
/// says what it answered as, and then names the daemon with how to stop it, and keeps the update.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_left_after_its_switch_names_a_daemon_that_answers_as_the_release_before() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    host.put(&two);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    // `current` names the release after it, and the update is recorded as switched, while the
    // daemon of the release before it still runs.
    host.switch(two.name());
    host.record_the_update_as_switched(&one, &two);
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);

    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(1), "{said}");
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&format!("answers as kr-controller/{}", one.name()))
            && message.contains(&format!("not as a daemon of {}", two.name())),
        "what failed comes first: {said}"
    );
    let pid = host.daemons[0].id();
    assert!(
        message.contains(&format!(
            "(process {pid}) answers as kr-controller/{}",
            one.name()
        )) && message.contains(&format!("kill {pid}")),
        "the daemon is named, with what it answers as and how to stop it: {said}"
    );
    assert_eq!(host.record()["update"]["state"], "switched");
}

/// KR-REQ-26.09: an update an earlier run left after its switch finds the environment held by a
/// daemon that does not listen, one on its way out: it waits for that daemon to have gone, and then
/// starts the daemon it recorded, where it used to wait for an answer that could not come.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_left_after_its_switch_waits_for_a_daemon_on_its_way_out() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    host.put(&two);
    host.record_a_switched_update(&one, &two);
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();

    // A daemon that has stopped listening and not yet let go of its environment.
    let going = kr_controller::singleton::SingletonLock::acquire(
        &host.tree.environment().singleton_lock(),
        host.tree.environment_id(),
    )
    .expect("holds the environment");
    let update = host
        .command(
            &host.store.stable(Program::Kr),
            &["host", "update", "--archive", &archive, "--json"],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kr runs");
    tokio::time::sleep(Duration::from_secs(3)).await;
    drop(going);

    let output = finish_within(update, Duration::from_secs(300));
    let said: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the recorded daemon was started from the release current names"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
}

/// KR-REQ-26.09: a daemon the update stopped that does not start from the new release keeps the
/// update recorded, as switched, through every run that meets the same failure; the run after the
/// failure has gone starts it from the release `current` names and settles the update.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_that_does_not_start_after_the_switch_keeps_the_update_for_the_next_run() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();

    let (output, said) = host.update_whose_daemons_fail(&archive);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&format!(
            "this host's current release is {} now, and a control daemon the update stopped did \
             not start from it",
            two.name()
        )),
        "{said}"
    );
    assert!(
        message.contains("ended with exit code 1 before it answered"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
    let record = host.record();
    assert_eq!(record["update"]["state"], "switched", "{record}");
    assert_eq!(
        record["update"]["restarts"].as_array().map(Vec::len),
        Some(1),
        "the daemon's restart is kept: {record}"
    );

    // A second run that meets the same failure keeps the update as well.
    let (output, said) = host.update_whose_daemons_fail(&archive);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("an update an earlier run left part way is not settled yet"),
        "{said}"
    );
    assert_eq!(host.record()["update"]["state"], "switched");

    // The control: once the daemon can start, the next run starts it from the release `current`
    // names, and the update settles.
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        said["restarted"],
        serde_json::json!([host.tree.environment_id().to_string()]),
        "it says which daemon it started: {said}"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], one.name().as_str(), "{record}");
}

/// KR-REQ-26.09: when a daemon the update stopped does not start again from the release still
/// current, the update stays recorded; the next run starts that daemon before anything else, and
/// then updates the host. What ends this update, after the stop, is a registry that is not a regular
/// file, which is refused and never opened: a pipe there would hold the update for as long as
/// nothing wrote to it.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_that_does_not_start_again_before_the_switch_keeps_the_update_for_the_next_run() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    // A second environment of the store, no daemon of it running, whose registry is a pipe: the
    // update finds nothing holding it before it stops this host's daemon, and refuses to read it
    // after.
    let other = kr_ipc::testing::TempHost::create();
    host.store
        .record_roots(other.paths().runtime_root(), other.paths().state_root())
        .expect("records the other environment's roots");
    let registry = other.environment().registry_database();
    let made = Command::new("mkfifo")
        .arg(&registry)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "a pipe is made");
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();

    let (output, said) = host.update_whose_daemons_fail(&archive);
    assert_eq!(output.status.code(), Some(1), "{said}");
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&other.environment_id().to_string())
            && message.contains("is not a regular file"),
        "the pipe is refused by the reader, and never opened: {said}"
    );
    assert!(
        message.contains("A control daemon the update stopped did not start again"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    let record = host.record();
    assert_eq!(record["update"]["state"], "handing_over", "{record}");
    assert_eq!(record["staged"], two.name().as_str(), "{record}");

    // The control: once the registry is not a pipe and the daemon can start, the next run starts it
    // again from the release that is still current, and then updates the host.
    std::fs::remove_file(&registry).expect("the pipe is removed");
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["source"], one.name().as_str(), "{said}");
    assert_eq!(said["target"], two.name().as_str(), "{said}");
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], one.name().as_str(), "{record}");
}

/// KR-REQ-26.09: a daemon an update prepared, and may have told to stop, is taken back for the
/// environment's daemon only once it has resumed, so no stop of that attempt still on its way can
/// end it afterwards, however the daemon is prepared again meanwhile: the stop names the attempt it
/// belongs to, finds it over, and is refused, and the daemon goes on serving.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_an_update_prepared_is_taken_back_only_once_no_stop_of_it_can_end_it() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = release("0.2.0+bbbbbbbbbbbb");
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    // What an update that stopped part way leaves while its stop to the daemon is still on its
    // way: the daemon prepared, and the update recorded as handing over.
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    let attempt = handover_step(&host, &mut client, HandoverStep::Prepare, None, &two)
        .await
        .expect("the daemon prepares")
        .to_typed::<kr_protocol::update::HostUpdateHandoverResult>()
        .expect("decodes")
        .attempt
        .0
        .expect("it answers the attempt it began");
    let restart = serde_json::json!({
        "environment": host.tree.environment_id(),
        "runtime_root": host.tree.paths().runtime_root(),
        "state_root": host.tree.paths().state_root(),
        "start": {
            "arguments": {
                "arguments": host.daemon_arguments(),
                "working_directory": host.tree.root(),
            }
        },
    });
    let record = serde_json::json!({
        "format": 1,
        "update": {
            "source": one.name().as_str(),
            "target": two.as_str(),
            "state": "handing_over",
            "restarts": [restart],
        },
    });
    std::fs::write(host.store.record(), record.to_string()).expect("the record");

    let scratch = host.scratch("archives");
    let archive = scratch.join("one.tar.gz");
    one.archive(&archive);
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
    assert!(host.record()["update"].is_null(), "the update is settled");

    // The stop still on its way arrives, and is refused: the daemon resumed before it was taken
    // back.
    let refused = handover_step(&host, &mut client, HandoverStep::Stop, Some(attempt), &two)
        .await
        .expect_err("a daemon that resumed is not stopped");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::ResourceUnavailable
    );
    // The same stop, arriving after another update has begun its own attempt on the daemon, is
    // refused as well: the daemon is closed to new sessions for that attempt, and this stop
    // belongs to another.
    let later = handover_step(&host, &mut client, HandoverStep::Prepare, None, &two)
        .await
        .expect("the daemon prepares again")
        .to_typed::<kr_protocol::update::HostUpdateHandoverResult>()
        .expect("decodes")
        .attempt
        .0
        .expect("it answers the attempt it began");
    assert_ne!(attempt, later, "each attempt has an identity of its own");
    let refused = handover_step(&host, &mut client, HandoverStep::Stop, Some(attempt), &two)
        .await
        .expect_err("a stop of an earlier attempt ends nothing while a later one is open");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::ResourceUnavailable
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon serves"
    );
    // The control: the attempt that is open ends as its own update ends it, and the daemon goes on
    // serving as it did.
    handover_step(&host, &mut client, HandoverStep::Resume, Some(later), &two)
        .await
        .expect("the open attempt ends");
    assert!(
        host.daemons
            .iter_mut()
            .all(|daemon| matches!(daemon.try_wait(), Ok(None))),
        "the daemon this test started still serves the environment"
    );
}

/// KR-REQ-26.09: a daemon whose working directory was removed cannot say how it was started, and a
/// `prepare` finds that out before it has changed anything: it is refused and the gate stays open.
/// A `resume` and a `stop` are taken all the same, and are not refused, since what they answer is not
/// what a daemon is started from: a step that answers an error is a step that was not taken. A daemon
/// that takes a stop ends, and may end before its answer is written.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_that_cannot_say_how_it_was_started_is_refused_before_its_gate_closes() {
    use kr_protocol::error::ErrorCode;
    use kr_protocol::update::HostUpdateHandoverResult;

    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = release("0.2.0+bbbbbbbbbbbb");
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    let kr = host.store.stable(Program::Kr);
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");

    // A daemon prepared while its directory is there, whose directory then goes: its resume is taken
    // and answers, and its gate is open.
    let directory = host.scratch("first-daemon-directory");
    host.start_daemon_in(&controller, &directory).await;
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    let attempt = handover_step(&host, &mut client, HandoverStep::Prepare, None, &two)
        .await
        .expect("the daemon prepares")
        .to_typed::<HostUpdateHandoverResult>()
        .expect("decodes")
        .attempt
        .0
        .expect("it answers the attempt it began");
    std::fs::remove_dir(&directory).expect("the daemon's directory is removed");
    handover_step(
        &host,
        &mut client,
        HandoverStep::Resume,
        Some(attempt),
        &two,
    )
    .await
    .expect("a resume is taken and answers");
    let (display, _) = host.new_session(&kr);
    host.close(&kr, &display);
    // Another prepare is refused before it closes the gate: the daemon cannot say how it was
    // started, and a session is still created.
    let refused = handover_step(&host, &mut client, HandoverStep::Prepare, None, &two)
        .await
        .expect_err("a daemon that cannot say how it was started does not prepare");
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    assert!(
        refused.message.contains("no longer exists")
            && refused
                .message
                .contains("start it again from a directory that exists"),
        "the refusal says what happened and what to do: {}",
        refused.message
    );
    let (display, _) = host.new_session(&kr);
    host.close(&kr, &display);

    // Another daemon, prepared with its directory there: its stop is taken and answers, and the
    // daemon ends.
    for mut daemon in host.daemons.drain(..) {
        daemon.kill().expect("stops");
        daemon.wait().expect("ends");
    }
    let directory = host.scratch("second-daemon-directory");
    host.start_daemon_in(&controller, &directory).await;
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    let attempt = handover_step(&host, &mut client, HandoverStep::Prepare, None, &two)
        .await
        .expect("the daemon prepares")
        .to_typed::<HostUpdateHandoverResult>()
        .expect("decodes")
        .attempt
        .0
        .expect("it answers the attempt it began");
    std::fs::remove_dir(&directory).expect("the daemon's directory is removed");
    // The stop is taken, and the daemon ends, which may be before it has written its answer: what
    // it must not do is refuse the stop, and that it ends is what shows the stop was taken.
    let refused = handover_stop_of(host.tree.environment_id(), &mut client, Some(attempt), &two)
        .await
        .expect("the stop call failed only because the daemon ended");
    assert!(
        refused.is_none(),
        "a stop is taken, not refused: {refused:?}"
    );
    let daemon = host
        .daemons
        .last_mut()
        .expect("the daemon this test started");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = daemon.try_wait().expect("the daemon's end is read") {
            break status;
        }
        assert!(Instant::now() < deadline, "the daemon did not stop");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    // A daemon that stops as it is told ends in success: one that was lost to a crash before it
    // answered is not a stop that was taken.
    assert!(
        status.success(),
        "the daemon ended by a stop, not by a failure: {status:?}"
    );
}

/// KR-REQ-26.08: a daemon that starts after an update's first look, in an environment the update
/// did not know, is found once no daemon can start: it records its roots before it takes its
/// environment, under the install lock, and the update reads them again under that lock and waits.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_finds_a_daemon_that_started_after_its_first_look() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();

    // A daemon part way through its start holds the install lock, shared, as each one does.
    let starting = host.store.lock_start().expect("the start lock");
    let update = host
        .command(
            &host.store.stable(Program::Kr),
            &["host", "update", "--archive", &archive, "--json"],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kr runs");
    // Once the update has looked, and has told this host's daemon to make way, the starting daemon
    // records its roots and takes its environment, and then lets go of the install lock.
    let deadline = Instant::now() + LIVENESS_DEADLINE;
    loop {
        let state = std::fs::read(host.store.record())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .map(|record| record["update"]["state"].clone());
        if state == Some(Value::from("handing_over")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the update did not reach its handover"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let other = kr_ipc::testing::TempHost::create();
    host.store
        .record_roots(other.paths().runtime_root(), other.paths().state_root())
        .expect("records the roots it serves");
    let other_lock = kr_controller::singleton::SingletonLock::hold(
        &other.environment().singleton_lock(),
        other.environment_id(),
    )
    .expect("takes its environment");
    drop(starting);

    let output = finish_within(update, Duration::from_secs(300));
    let said: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    assert_eq!(
        output.status.code(),
        Some(9),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&format!(
                "the update to {} waits: a control daemon holds environment {}",
                two.name(),
                other.environment_id()
            )),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon it prepared serves from the release still current"
    );
    assert!(
        host.daemons
            .iter_mut()
            .all(|daemon| matches!(daemon.try_wait(), Ok(None))),
        "the daemon this test started was never stopped: the holder was found before any stop"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["staged"], two.name().as_str(), "{record}");
    drop(other_lock);
}

/// KR-REQ-26.08: the install lock is waited for before any daemon is stopped, for a bound. A daemon
/// that never finishes starting, holding the start lock past the bound, makes the update exit 9,
/// naming the store, with nothing stopped: every daemon it prepared is resumed and serves, its gate
/// open again, and the release stays staged; once the daemon has started, the next update goes
/// through.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_that_cannot_take_the_install_lock_stops_nothing() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();

    // A daemon that never finishes starting holds the install lock, shared, past the update's bound,
    // and its environment, which no daemon answers for: this process stands in for it.
    let starting = host.store.lock_start().expect("the start lock");
    let idle = Idle::new(&host.store);
    let hanging = kr_controller::singleton::SingletonLock::acquire(
        &idle.temp.environment().singleton_lock(),
        idle.temp.environment_id(),
    )
    .expect("holds the environment");
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("is starting and has held its start lock for more than 30 seconds")
            && message.contains("run kr host update again"),
        "{said}"
    );
    assert!(
        message.contains(&format!("kill {}", std::process::id())),
        "the process that holds the environment nothing answers for is named: {said}"
    );
    assert!(
        !message.contains(&format!("kill {}", host.daemons[0].id())),
        "and the daemon that made way is not: {said}"
    );
    drop(hanging);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    assert!(
        host.daemons
            .iter_mut()
            .all(|daemon| matches!(daemon.try_wait(), Ok(None))),
        "the daemon this test started was never stopped"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["staged"], two.name().as_str(), "{record}");
    // Its gate is open again: a session is created.
    let kr = host.store.stable(Program::Kr);
    let (display, session_id) = host.new_session(&kr);
    let worker = host.worker_process(session_id);
    host.close(&kr, &display);
    host.worker_ended(&worker).await;

    // The control: once the daemon has started, the next update goes through.
    drop(starting);
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
}

/// KR-REQ-26.09: a daemon that answers that it does not stop, because its attempt is over, goes on
/// serving: the update says which daemon and why, exits 9 without waiting for it to go, and starts
/// again what it did stop; nobody is told to kill a daemon that is healthy.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_that_refuses_to_stop_goes_on_serving_and_the_update_waits() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();

    // The update prepares the daemon, records how to start it again, and then waits for the install
    // lock a starting daemon holds; meanwhile another attempt begins on the daemon, which ends the
    // update's.
    let starting = host.store.lock_start().expect("the start lock");
    let update = host
        .command(
            &host.store.stable(Program::Kr),
            &["host", "update", "--archive", &archive, "--json"],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kr runs");
    let deadline = Instant::now() + LIVENESS_DEADLINE;
    loop {
        let state = std::fs::read(host.store.record())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .map(|record| record["update"]["state"].clone());
        if state == Some(Value::from("handing_over")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the update did not reach its handover"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    handover_step(&host, &mut client, HandoverStep::Prepare, None, two.name())
        .await
        .expect("the daemon begins another attempt");
    drop(starting);

    let output = finish_within(update, Duration::from_secs(300));
    let said: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    assert_eq!(
        output.status.code(),
        Some(9),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("did not stop:") && !message.contains("kill"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon goes on serving"
    );
    assert!(
        host.daemons
            .iter_mut()
            .all(|daemon| matches!(daemon.try_wait(), Ok(None))),
        "the daemon this test started was never stopped"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["staged"], two.name().as_str(), "{record}");
    // Both attempts are over, and its gate is open: a session is created.
    let kr = host.store.stable(Program::Kr);
    let (display, _) = host.new_session(&kr);
    host.close(&kr, &display);
}

/// KR-REQ-26.09: with two environments, one whose daemon answers that it does not stop and one that
/// stopped, the update waits for the one it stopped to have gone before it starts it again: nothing
/// is met on its way out, nobody is told to kill anything, the update exits 9, and both daemons
/// serve.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_stop_leaves_every_daemon_serving_and_the_update_waits() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let second = Second::start(&controller).await;
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();
    // The update tells the daemons in the order of their environments' identities, so the daemon
    // whose attempt is superseded is the last one: the one before it accepts its stop first.
    let (last_environment, last_endpoint) = {
        let ours = host.tree.environment_id();
        let theirs = second.tree.environment_id();
        if ours.to_string() > theirs.to_string() {
            (
                ours,
                host.tree
                    .environment()
                    .controller_endpoint()
                    .expect("an endpoint"),
            )
        } else {
            (
                theirs,
                second
                    .tree
                    .environment()
                    .controller_endpoint()
                    .expect("an endpoint"),
            )
        }
    };

    let starting = host.store.lock_start().expect("the start lock");
    let update = host
        .command(
            &host.store.stable(Program::Kr),
            &["host", "update", "--archive", &archive, "--json"],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kr runs");
    let deadline = Instant::now() + LIVENESS_DEADLINE;
    loop {
        let state = std::fs::read(host.store.record())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .map(|record| record["update"]["state"].clone());
        if state == Some(Value::from("handing_over")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the update did not reach its handover"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut client = LocalClient::connect(&last_endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    handover_step_of(
        last_environment,
        &mut client,
        HandoverStep::Prepare,
        None,
        two.name(),
    )
    .await
    .expect("the daemon begins another attempt");
    drop(starting);

    let output = finish_within(update, Duration::from_secs(300));
    let said: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    assert_eq!(
        output.status.code(),
        Some(9),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("did not stop:") && !message.contains("kill"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the first environment's daemon serves"
    );
    assert_eq!(
        second.build().await,
        format!("kr-controller/{}", one.name()),
        "and so does the second's"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["staged"], two.name().as_str(), "{record}");
}

/// KR-REQ-26.09: an install stopped between putting its release in the store and making it
/// current is finished by the next install of the same release, and no daemon of the release
/// starts meanwhile; another release under the same name is refused, and an install waits while
/// another install or update of the store runs.
#[test]
fn an_install_stopped_before_its_switch_is_finished_by_the_next() {
    let host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    // What such an install leaves: the store's record, and the release in `versions/`.
    host.put(&one);
    let store = host.store.root().display().to_string();
    let arguments = host.daemon_arguments();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let refused = host.run(&host.program(one.name(), Program::Controller), &arguments);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("names no current release"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );

    let unpacked = |name: &str, assembled: &Assembled| {
        let tree = host.scratch(name).join(assembled.name().as_str());
        assembled.write(&tree);
        tree.join("bin").join(Program::Kr.file_name())
    };
    {
        let _update = host
            .store
            .try_lock_update()
            .expect("locks")
            .expect("nothing else updates");
        let waited = host.run(
            &unpacked("waiting", &one),
            &["host", "install", "--store", &store],
        );
        assert_eq!(waited.status.code(), Some(9));
        assert!(
            String::from_utf8_lossy(&waited.stderr)
                .contains("another install or update of the store"),
            "{}",
            String::from_utf8_lossy(&waited.stderr)
        );
    }
    let impostor = Assembled::at_this_level(one.name().as_str(), 5);
    let refused = host.run(
        &unpacked("impostor", &impostor),
        &["host", "install", "--store", &store],
    );
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains("already holds a release named 0.1.0+aaaaaaaaaaaa that is not this one"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(host.store.current().expect("reads"), None);

    // The control: the same release, whole, is made current as it is, and sealed as it is used:
    // what an install left before it made the release read-only is read-only now.
    host.install(&one);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert!(host.record()["update"].is_null());
    let kept = host.store.release_directory(one.name());
    for path in [
        kept.clone(),
        kept.join("bin"),
        kept.join(module_tree()[0].0),
    ] {
        assert!(
            std::fs::metadata(&path)
                .expect("installed")
                .permissions()
                .readonly(),
            "{} is read-only",
            path.display()
        );
    }
}

/// KR-REQ-26.09: an install writes the store's record before any program of its release is in the
/// store, and puts the release in and makes it current under the install lock: while a daemon of
/// the store is part way through its start, the install has made the directory a store and has
/// published nothing, and it finishes once the daemon's start has.
#[test]
fn an_install_makes_the_store_first_and_publishes_under_the_install_lock() {
    let host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.store
        .create_directories()
        .expect("the store's directories");
    let starting = host.store.lock_start().expect("the start lock");
    let tree = host.scratch("unpacked").join(one.name().as_str());
    one.write(&tree);
    let store = host.store.root().display().to_string();
    let mut install = host
        .command(
            &tree.join("bin").join(Program::Kr.file_name()),
            &["host", "install", "--store", &store, "--json"],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kr runs");
    // The release copied, checked and sealed in the staging directory: all that comes before the
    // install lock.
    let sealed = || {
        std::fs::read_dir(host.store.staging())
            .into_iter()
            .flatten()
            .flatten()
            .any(|run| {
                std::fs::metadata(run.path().join("release/bin")).is_ok_and(|about| {
                    std::os::unix::fs::PermissionsExt::mode(&about.permissions()) & 0o777 == 0o555
                })
            })
    };
    let deadline = Instant::now() + LIVENESS_DEADLINE;
    while !sealed() {
        assert!(
            matches!(install.try_wait(), Ok(None)),
            "the install ended before it staged its release"
        );
        assert!(
            Instant::now() < deadline,
            "the install did not stage its release"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(500));
    assert!(matches!(install.try_wait(), Ok(None)), "the install waits");
    assert!(host.store.is_store(), "the store's record comes first");
    assert!(
        !host.store.release_directory(one.name()).exists(),
        "nothing is published while a daemon is part way through its start"
    );
    assert_eq!(host.store.current().expect("reads"), None);

    drop(starting);
    let output = finish_within(install, Duration::from_secs(300));
    assert!(
        output.status.success(),
        "kr host install: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// What is under `root`, as a comparison shows it: each entry's path, kind, mode and length, the
/// links as links.
fn what_is_under(root: &Path) -> Vec<(String, &'static str, u32, u64)> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("reads").flatten() {
            let about = std::fs::symlink_metadata(entry.path()).expect("there");
            let kind = if about.file_type().is_symlink() {
                "link"
            } else if about.is_dir() {
                pending.push(entry.path());
                "directory"
            } else {
                "file"
            };
            found.push((
                entry
                    .path()
                    .strip_prefix(root)
                    .expect("under the root")
                    .display()
                    .to_string(),
                kind,
                about.permissions().mode() & 0o7777,
                about.len(),
            ));
        }
    }
    found.sort();
    found
}

/// KR-REQ-26.09: a release an earlier install left in the store is never used as it is: the copy
/// this install checked takes its place, so nothing the kept one was short of, changed in, linked
/// to or left writable survives, and nothing outside the store is touched; a release a running
/// program holds is not replaced, and the install waits.
#[test]
fn a_release_kept_in_the_store_is_replaced_by_the_copy_checked_in_this_run() {
    use std::os::unix::fs::PermissionsExt as _;

    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    // What is done to the kept release, given its directory and a directory outside the store.
    type Tampering = fn(&Path, &Path);
    let tamperings: [(&str, Tampering); 5] = [
        ("a missing file", |kept, _| {
            std::fs::remove_file(kept.join("bin/kr")).expect("removed");
        }),
        ("a changed file", |kept, _| {
            std::fs::write(kept.join("bin/kr"), b"#!/bin/zsh\n").expect("changed");
        }),
        ("a file it does not list", |kept, _| {
            std::fs::write(kept.join("share/extra"), b"x").expect("written");
        }),
        (
            "a file that is a hard link to one elsewhere",
            |kept, outside| {
                let file = kept.join(kr_cli::update::release::CHANNEL_ROOT);
                let elsewhere = outside.join("root.json");
                std::fs::copy(&file, &elsewhere).expect("copied");
                std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o444))
                    .expect("read-only");
                std::fs::remove_file(&file).expect("removed");
                std::fs::hard_link(&elsewhere, &file).expect("linked");
            },
        ),
        (
            "a name that is a link to a whole release elsewhere",
            |kept, outside| {
                std::fs::rename(kept, outside.join("release")).expect("moved");
                std::os::unix::fs::symlink(outside.join("release"), kept).expect("linked");
            },
        ),
    ];
    for (what, tamper) in tamperings {
        let host = Host::bare();
        host.store
            .create_directories()
            .expect("the store's directories");
        std::fs::write(host.store.record(), b"{\"format\":1}\n").expect("the store's record");
        let kept = host.store.release_directory(one.name());
        one.write(&kept);
        let outside = host.scratch("outside");
        tamper(&kept, &outside);
        let elsewhere = what_is_under(&outside);

        host.install(&one);

        assert_eq!(
            host.store.current().expect("reads"),
            Some(one.name().clone()),
            "{what}"
        );
        // A directory of the store's own, holding every file the manifest lists as it lists it,
        // each read-only and its own, and nothing else.
        let release = host.store.release_directory(one.name());
        let about = std::fs::symlink_metadata(&release).expect("there");
        assert!(about.is_dir() && !about.file_type().is_symlink(), "{what}");
        assert_eq!(about.permissions().mode() & 0o777, 0o555, "{what}");
        for file in &one.manifest.files {
            let path = release.join(file.path.as_str());
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("{what}: {}: {error}", path.display()));
            assert_eq!(
                Digest256::from_bytes(kr_cbor::sha256(&bytes)),
                file.sha256,
                "{what}: {}",
                path.display()
            );
            let about = std::fs::symlink_metadata(&path).expect("there");
            assert!(about.permissions().readonly(), "{what}: {}", path.display());
            assert_eq!(
                std::os::unix::fs::MetadataExt::nlink(&about),
                1,
                "{what}: {} is a file of its own",
                path.display()
            );
        }
        assert!(!release.join("share/extra").exists(), "{what}");
        // Nothing outside the store was changed, or removed: the hard link's other name and the
        // release a link led to are as they were, modes included.
        assert_eq!(what_is_under(&outside), elsewhere, "{what}");
    }

    // A release a running program holds is not replaced: the install waits, exit 9, and once the
    // program has gone, replaces it.
    let host = Host::bare();
    host.store
        .create_directories()
        .expect("the store's directories");
    std::fs::write(host.store.record(), b"{\"format\":1}\n").expect("the store's record");
    let kept = host.store.release_directory(one.name());
    one.write(&kept);
    let store = host.store.root().display().to_string();
    let unpacked = host.scratch("unpacked").join(one.name().as_str());
    one.write(&unpacked);
    let program = unpacked.join("bin").join(Program::Kr.file_name());
    let running = std::fs::File::open(host.store.manifest(one.name())).expect("the manifest");
    running
        .lock_shared()
        .expect("held as a running program holds it");
    let waited = host.run(&program, &["host", "install", "--store", &store]);
    assert_eq!(waited.status.code(), Some(9));
    assert!(
        String::from_utf8_lossy(&waited.stderr).contains("a running program holds it"),
        "{}",
        String::from_utf8_lossy(&waited.stderr)
    );
    assert_eq!(host.store.current().expect("reads"), None);
    drop(running);
    // A program another test starts while the hold is open keeps a copy of it until its own program
    // takes over, so the install is run again once no copy is left.
    let started = Instant::now();
    while host.store.held(one.name()).expect("asks") {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "release {} is still held",
            one.name()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    host.install(&one);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// KR-REQ-26.09: a release kept in the store whose manifest is a link or a pipe is not trusted and
/// not read: the install refuses by naming its directory and says what to do, and once the directory
/// has been removed the install goes through.
#[test]
fn a_kept_release_whose_manifest_is_not_a_file_is_refused_with_the_way_out() {
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    // What is put where the kept release's manifest is, given the manifest's path and a directory
    // outside the store.
    type Instead = fn(&Path, &Path);
    let insteads: [(&str, Instead); 2] = [
        (
            "a link to a file with the same bytes",
            |manifest, outside| {
                let elsewhere = outside.join("release.json");
                std::fs::copy(manifest, &elsewhere).expect("copied");
                std::fs::remove_file(manifest).expect("removed");
                std::os::unix::fs::symlink(&elsewhere, manifest).expect("linked");
            },
        ),
        ("a pipe", |manifest, _| {
            std::fs::remove_file(manifest).expect("removed");
            let made = Command::new("mkfifo")
                .arg(manifest)
                .status()
                .expect("mkfifo runs");
            assert!(made.success(), "a pipe is made");
        }),
    ];
    for (what, instead) in insteads {
        let host = Host::bare();
        host.store
            .create_directories()
            .expect("the store's directories");
        std::fs::write(host.store.record(), b"{\"format\":1}\n").expect("the store's record");
        let kept = host.store.release_directory(one.name());
        one.write(&kept);
        let outside = host.scratch("outside");
        instead(&host.store.manifest(one.name()), &outside);
        // As a release in the store is: every directory read-only.
        seal_directories(&kept);
        let store = host.store.root().display().to_string();
        let unpacked = host.scratch("unpacked").join(one.name().as_str());
        one.write(&unpacked);
        let program = unpacked.join("bin").join(Program::Kr.file_name());

        // A pipe waited for would fail the test at the limit; the run itself takes a moment.
        let refused = host.run(&program, &["host", "install", "--store", &store]);
        assert_eq!(refused.status.code(), Some(1), "{what}");
        let said = String::from_utf8_lossy(&refused.stderr).into_owned();
        assert!(
            said.contains(&kept.display().to_string())
                && said.contains("chmod -R u+w")
                && said.contains("kr host install again"),
            "{what}: {said}"
        );
        assert_eq!(host.store.current().expect("reads"), None, "{what}");

        // The control: as the refusal says, the directory is made writable and removed, and the
        // install goes through. Removed as it is, it would not be.
        assert!(
            std::fs::remove_dir_all(&kept).is_err(),
            "{what}: a sealed directory is not removed as it is"
        );
        let opened = Command::new("chmod")
            .args(["-R", "u+w"])
            .arg(&kept)
            .status()
            .expect("chmod runs");
        assert!(opened.success(), "{what}: the directory is made writable");
        std::fs::remove_dir_all(&kept).expect("removes");
        host.install(&one);
        assert_eq!(
            host.store.current().expect("reads"),
            Some(one.name().clone()),
            "{what}"
        );
    }
}

/// KR-REQ-26.06: a program of a release still being staged does not start once it is runnable,
/// where an install copies it and where an update unpacks it; the same tree outside the store
/// starts.
#[test]
fn no_program_of_a_release_being_staged_starts() {
    use std::os::unix::fs::DirBuilderExt as _;

    let host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let tree = host.scratch("unpacked").join(one.name().as_str());
    one.write(&tree);
    let started = host.run(
        &tree.join("bin").join(Program::Kr.file_name()),
        &["--version"],
    );
    assert!(
        started.status.success(),
        "outside the store it starts: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    let private = |name: &str| {
        let path = host.store.staging().join(name);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("a staging directory");
        path
    };
    let (copied, _) = kr_cli::update::release::copy_tree(&tree, &private("copied"))
        .unwrap_or_else(|error| panic!("copies: {error}"));
    let archives = host.scratch("archives");
    let archive = archives.join("one.tar.gz");
    one.archive(&archive);
    let (unpacked, _) = kr_cli::update::release::unpack(&archive, &private("unpacked"))
        .unwrap_or_else(|error| panic!("unpacks: {error}"));
    for staged in [copied, unpacked] {
        kr_cli::update::release::seal(&staged, &one.manifest)
            .unwrap_or_else(|error| panic!("seals: {error}"));
        let refused = host.run(
            &staged.join("bin").join(Program::Kr.file_name()),
            &["--version"],
        );
        assert!(!refused.status.success(), "{}", staged.display());
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("is still being installed"),
            "{}: {}",
            staged.display(),
            String::from_utf8_lossy(&refused.stderr)
        );
    }
}

/// Only the current release's `kr` updates the host: another release's refuses, naming the one to
/// run, and so does a build outside a store.
#[test]
fn only_the_current_release_s_kr_updates_the_host() {
    let host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.put(&one);
    host.put(&two);
    host.switch(two.name());
    let archive = host.tree.root().join("nothing.tar.gz");
    let archive = archive.display().to_string();
    let refused = host.run(
        &host.program(one.name(), Program::Kr),
        &["host", "update", "--archive", &archive],
    );
    assert_eq!(refused.status.code(), Some(3));
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(
        said.contains(&format!(
            "this kr is of release {}, and this host's current release is {}",
            one.name(),
            two.name()
        )),
        "{said}"
    );
    let outside = host.run(&support::kr(), &["host", "update", "--archive", &archive]);
    assert_eq!(outside.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&outside.stderr).contains("this kr is not of an installed release"),
        "{}",
        String::from_utf8_lossy(&outside.stderr)
    );
}

/// Writes a zsh package into a release's `shells/`, as a build installs one, and the release's
/// stable entry for zsh beside it: the file a store's startup entries source.
fn write_zsh_package(shells: &Path) {
    use kr_shell_integration::contract::qualification::ShellKind;
    use kr_shell_integration::host::package::{
        CURRENT_BASENAME, MANIFEST_BASENAME, PackageManifest, PackageShell, PackageStartupEntry,
    };

    let package = shells.join("zsh").join("test-1");
    std::fs::create_dir_all(package.join("startup")).expect("the package's directory");
    let manifest = PackageManifest {
        identity: "test-1".to_owned(),
        shell: PackageShell {
            kind: ShellKind::Zsh,
            executable: package.join("bin/zsh"),
            upstream_version: "5.9".to_owned(),
            editor_abi: "zle-5.9".to_owned(),
            integration_version: "1".to_owned(),
            patches: Vec::new(),
            modules: Vec::new(),
        },
        startup_entry: PackageStartupEntry {
            file: "startup/kr-zshrc.zsh".to_owned(),
        },
    };
    std::fs::write(
        package.join(MANIFEST_BASENAME),
        serde_json::to_string(&manifest).expect("the record encodes"),
    )
    .expect("the identity record");
    std::fs::write(shells.join("zsh").join(CURRENT_BASENAME), "test-1\n").expect("current");
    let entry = "if builtin kr-bridge status 2>/dev/null; then builtin kr-bridge activated; fi\n";
    std::fs::write(package.join("startup/kr-zshrc.zsh"), entry).expect("the package's entry");
    std::fs::write(shells.join("zsh").join("kr-zshrc.zsh"), entry).expect("the stable entry");
}

/// A kr of an installed release writes a startup entry that sources the current release's entry
/// through the store's `current`, which every update leaves in place; a kr outside a store sources
/// the package's own file.
#[test]
fn a_store_s_startup_entry_sources_the_current_release_s_entry() {
    let host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let directory = host.put(&one);
    host.switch(one.name());
    let shells = directory.join("shells");
    write_zsh_package(&shells);
    let home = host.scratch("home");
    let output = host
        .command(
            &host.store.stable(Program::Kr),
            &["shell", "install", "--shell", "zsh"],
        )
        .env("HOME", &home)
        .stdin(Stdio::null())
        .output()
        .expect("kr runs");
    assert!(
        output.status.success(),
        "kr shell install: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let written = std::fs::read_to_string(home.join(".zshrc")).expect("the entry is written");
    let stable = host.store.stable_shells().join("zsh").join("kr-zshrc.zsh");
    assert!(
        written.contains(&stable.display().to_string()),
        "the entry sources the stable file: {written}"
    );
    assert!(
        !written.contains("versions"),
        "the entry names no release's own directory: {written}"
    );

    // The control: outside a store, the same packages give an entry that sources the package's
    // own file.
    let home = host.scratch("home-outside");
    let output = Command::new(support::kr())
        .args(["shell", "install", "--shell", "zsh"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("KR_RUNTIME_DIR", host.tree.paths().runtime_root())
        .env("KR_STATE_DIR", host.tree.paths().state_root())
        .env(
            kr_shell_integration::host::package::PACKAGE_ROOT_VARIABLE,
            &shells,
        )
        .current_dir(host.tree.root())
        .stdin(Stdio::null())
        .output()
        .expect("kr runs");
    assert!(
        output.status.success(),
        "kr shell install: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let written = std::fs::read_to_string(home.join(".zshrc")).expect("the entry is written");
    assert!(
        written.contains(
            &shells
                .join("zsh/test-1/startup/kr-zshrc.zsh")
                .display()
                .to_string()
        ),
        "{written}"
    );
}

/* -------------------------------------------------------------------------------------------- */
/* What a release has to be                                                                      */
/* -------------------------------------------------------------------------------------------- */

/// A small release: two files, its root and its manifest, signed by `signer`.
fn small_release(signer: &Ed25519KeyPair) -> (ReleaseManifest, BTreeMapFiles, String) {
    let files: BTreeMapFiles = [
        ("bin/kr".to_owned(), b"#!/bin/sh\n".to_vec()),
        (
            "share/update-root.json".to_owned(),
            the_root().as_bytes().to_vec(),
        ),
    ]
    .into_iter()
    .collect();
    let manifest = ReleaseManifest {
        kind: ManifestKind::Release,
        release: release("0.2.0+bbbbbbbbbbbb"),
        sequence: U64::new(2),
        commit: CommitId::new("b".repeat(40)).expect("a commit"),
        target: this_target().to_owned(),
        os_floor: OsFloor {
            system: FloorSystem::Macos,
            version: FloorVersion { major: 1, minor: 0 },
        },
        protocol_version: PACKAGE_VERSION,
        public_majors: vec![1],
        retained_levels: vec![CompatibilityLevel::of(PACKAGE_VERSION)],
        shells: Vec::new(),
        stores: release_stores(),
        files: files
            .iter()
            .map(|(path, contents)| ReleaseFile {
                path: ReleasePath::new(path.as_str()).expect("a path"),
                length: U64::new(contents.len() as u64),
                sha256: Digest256::from_bytes(kr_cbor::sha256(contents)),
                mode: if path.starts_with("bin/") {
                    FileMode::Executable
                } else {
                    FileMode::Regular
                },
            })
            .collect(),
    };
    let document = signed_document(&manifest, signer);
    (manifest, files, document)
}

type BTreeMapFiles = std::collections::BTreeMap<String, Vec<u8>>;

/// The channel root this process makes, read back as a release would carry it.
fn trusted() -> kr_cli::update::release::ChannelRoot {
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join(kr_cli::update::release::CHANNEL_ROOT);
    std::fs::create_dir_all(path.parent().expect("share")).expect("share");
    std::fs::write(&path, the_root()).expect("the root");
    kr_cli::update::release::ChannelRoot::read(directory.path())
        .unwrap_or_else(|error| panic!("the root reads: {error}"))
        .expect("the root is there")
}

/// KR-REQ-26.09: a manifest is taken only when a threshold of the keys the trusted root names for
/// its targets role signed it, over exactly what it says.
#[test]
fn a_manifest_is_taken_only_as_the_root_s_targets_keys_signed_it() {
    let root = trusted();
    // The control: signed by the targets key, it is taken.
    let (manifest, _, document) = small_release(&keys().targets);
    assert_eq!(
        root.verify(document.as_bytes())
            .unwrap_or_else(|error| panic!("taken: {error}")),
        manifest
    );
    for signer in [&keys().root, &keys().stranger] {
        let (_, _, document) = small_release(signer);
        assert!(
            root.verify(document.as_bytes()).is_err(),
            "a key the root names for no targets role signs nothing"
        );
    }
    // A signed document changed afterwards, by one member this build does not even read.
    let mut changed: Value = serde_json::from_str(&document).expect("JSON");
    changed["signed"]["notes"] = serde_json::json!([]);
    assert!(root.verify(changed.to_string().as_bytes()).is_err());
    // And one that names a member twice with the same value, which leaves the canonical form and
    // the signature as they were: refused by the updater, as by every program of the release.
    let repeated = document.replacen(
        "\"signed\":{",
        &format!("\"signed\":{{\"release\":\"{}\",", manifest.release),
        1,
    );
    assert_ne!(repeated, document, "the member is repeated");
    assert!(root.verify(repeated.as_bytes()).is_err());
    assert!(ReleaseManifest::read_document(repeated.as_bytes()).is_err());
}

/// A release carries the host's root or the one that follows it, signed by the host's root keys and
/// its own; any other root is refused.
#[test]
fn a_channel_root_is_followed_only_by_its_successor() {
    let trusted = trusted();
    let carried = |text: String| {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join(kr_cli::update::release::CHANNEL_ROOT);
        std::fs::create_dir_all(path.parent().expect("share")).expect("share");
        std::fs::write(&path, text).expect("the root");
        kr_cli::update::release::ChannelRoot::read(directory.path())
            .map(|root| root.expect("there"))
    };
    let same = carried(the_root().to_owned()).unwrap_or_else(|error| panic!("reads: {error}"));
    assert!(
        trusted.admits_successor(&same).is_ok(),
        "the same root follows"
    );
    // The next version, with a new root key, signed by the old root key and the new one.
    let new_key = &keys().stranger;
    let next = carried(channel_root(2, new_key, &[&keys().root, new_key]))
        .unwrap_or_else(|error| panic!("reads: {error}"));
    assert!(
        trusted.admits_successor(&next).is_ok(),
        "its successor follows"
    );
    // The controls: signed by the new key alone, or skipping a version, it does not.
    let unsigned_by_the_old = carried(channel_root(2, new_key, &[new_key]))
        .unwrap_or_else(|error| panic!("reads: {error}"));
    assert!(trusted.admits_successor(&unsigned_by_the_old).is_err());
    let skipping = carried(channel_root(3, new_key, &[&keys().root, new_key]))
        .unwrap_or_else(|error| panic!("reads: {error}"));
    assert!(trusted.admits_successor(&skipping).is_err());
    // A root its own root key did not sign is not root metadata anybody may trust.
    assert!(carried(channel_root(1, &keys().root, &[&keys().stranger])).is_err());
}

/// KR-REQ-26.09: an archive is refused at its first entry that is not a file or a directory of the
/// one release under one top directory, and an archive that is only files unpacks.
#[test]
fn an_archive_is_refused_at_its_first_entry_that_is_not_a_release_file() {
    let scratch = tempfile::tempdir().expect("a directory");
    let write_archive = |name: &str, entries: &[(&str, tar::EntryType, &[u8])]| {
        let path = scratch.path().join(name);
        let file = std::fs::File::create(&path).expect("an archive");
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            file,
            flate2::Compression::fast(),
        ));
        for (entry_path, kind, contents) in entries {
            let mut header = tar::Header::new_gnu();
            // Written into the header's name as it is, so a path the builder would refuse to make
            // is exactly what an archive can carry.
            let name = &mut header.as_old_mut().name;
            name[..entry_path.len()].copy_from_slice(entry_path.as_bytes());
            header.set_entry_type(*kind);
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            if *kind == tar::EntryType::Symlink {
                header.set_link_name("/etc/passwd").expect("a link");
            }
            header.set_cksum();
            builder.append(&header, *contents).expect("an entry");
        }
        builder
            .into_inner()
            .and_then(flate2::write::GzEncoder::finish)
            .expect("written");
        path
    };
    // Owner-only, as the store's own staging directory is.
    let staging = |name: &str| {
        use std::os::unix::fs::DirBuilderExt as _;

        let path = scratch.path().join(name);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("a staging directory");
        path
    };
    // The control: files and directories under one top directory unpack, each with its digest.
    let archive = write_archive(
        "good.tar.gz",
        &[
            ("release/bin", tar::EntryType::Directory, b""),
            ("release/bin/kr", tar::EntryType::Regular, b"#!/bin/sh\n"),
        ],
    );
    let (unpacked, written) = kr_cli::update::release::unpack(&archive, &staging("good"))
        .unwrap_or_else(|error| panic!("unpacks: {error}"));
    assert!(unpacked.join("bin/kr").is_file());
    assert_eq!(
        written.get("bin/kr").map(|(length, _)| *length),
        Some(10),
        "each file's length and digest are taken as it is written"
    );
    for (name, entries) in [
        (
            "link",
            vec![("release/bin/kr", tar::EntryType::Symlink, &b""[..])],
        ),
        (
            "hard-link",
            vec![("release/bin/kr", tar::EntryType::Link, &b""[..])],
        ),
        (
            "device",
            vec![("release/bin/kr", tar::EntryType::Char, &b""[..])],
        ),
        (
            "volume",
            vec![("release/bin/kr", tar::EntryType::new(b'V'), &b""[..])],
        ),
        (
            "climbing",
            vec![("release/../escape", tar::EntryType::Regular, &b"x"[..])],
        ),
        (
            "absolute",
            vec![("/release/bin/kr", tar::EntryType::Regular, &b"x"[..])],
        ),
        (
            "two-tops",
            vec![
                ("release/bin/kr", tar::EntryType::Regular, &b"x"[..]),
                ("other/bin/kr", tar::EntryType::Regular, &b"x"[..]),
            ],
        ),
        (
            "twice",
            vec![
                ("release/bin/kr", tar::EntryType::Regular, &b"x"[..]),
                ("release/bin/kr", tar::EntryType::Regular, &b"y"[..]),
            ],
        ),
    ] {
        let archive = write_archive(&format!("{name}.tar.gz"), &entries);
        let refused = kr_cli::update::release::unpack(&archive, &staging(name));
        assert!(refused.is_err(), "{name} is refused");
        assert!(
            !scratch.path().join("escape").exists(),
            "nothing was written outside the staging directory"
        );
    }
    // The refusal says what the entry was, by the character tar gives it and its usual name.
    for (name, expected) in [
        ("link", "2, a symbolic link"),
        ("hard-link", "1, a hard link"),
        ("device", "3, a character device"),
        ("volume", "of type V that"),
    ] {
        let archive = scratch.path().join(format!("{name}.tar.gz"));
        let said = kr_cli::update::release::unpack(&archive, &staging(&format!("{name}-said")))
            .expect_err("it is refused")
            .to_string();
        assert!(said.contains(expected), "{name}: {said}");
    }
    // A pipe named as the archive is refused at once, and not waited for.
    let pipe = scratch.path().join("pipe.tar.gz");
    let made = Command::new("mkfifo")
        .arg(&pipe)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "a pipe is made");
    // Run on a thread of its own, so that a wait for a writer fails the test and does not hang it.
    let target = staging("pipe");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(
            kr_cli::update::release::unpack(&pipe, &target)
                .map(|_| ())
                .map_err(|error| error.to_string()),
        );
    });
    let refused = receiver
        .recv_timeout(Duration::from_secs(20))
        .expect("a pipe named as the archive was waited for")
        .expect_err("a pipe is not an archive");
    assert!(refused.contains("is not a regular file"), "{refused}");
}

/// KR-REQ-26.09: a sparse entry, a file written with its holes left out, which the tar crate's
/// builder writes of a file that has some on the systems that report holes, is refused, and said to
/// be a sparse entry, not taken for a link or a device; a file with holes written whole is taken.
#[test]
fn a_sparse_entry_is_refused_as_one() {
    use std::os::unix::fs::{DirBuilderExt as _, FileExt as _};

    let scratch = tempfile::tempdir().expect("a directory");
    let staging = |name: &str| {
        let path = scratch.path().join(name);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("a staging directory");
        path
    };
    // The control: a file with a hole in it, written whole, unpacks as a file of its whole length.
    let tree = scratch.path().join("release");
    std::fs::create_dir_all(tree.join("bin")).expect("a tree");
    let file = std::fs::File::create(tree.join("bin/kr")).expect("a file");
    file.set_len(4 << 20).expect("a file with a hole in it");
    file.write_all_at(b"data", 2 << 20)
        .expect("data in the middle");
    drop(file);
    let whole = scratch.path().join("whole.tar.gz");
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        std::fs::File::create(&whole).expect("an archive"),
        flate2::Compression::fast(),
    ));
    builder.sparse(false);
    builder.append_dir_all("release", &tree).expect("packs");
    builder
        .into_inner()
        .and_then(flate2::write::GzEncoder::finish)
        .expect("written");
    let (unpacked, written) = kr_cli::update::release::unpack(&whole, &staging("whole"))
        .unwrap_or_else(|error| panic!("a whole file unpacks: {error}"));
    assert!(unpacked.join("bin/kr").is_file());
    assert_eq!(
        written.get("bin/kr").map(|(length, _)| *length),
        Some(4 << 20)
    );

    // A sparse entry, made by hand so that every system has one: a file of 1024 bytes of which the
    // first 512 are in the archive and the rest is a hole, which the last, empty block ends at the
    // file's length.
    let sparse = scratch.path().join("sparse.tar.gz");
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        std::fs::File::create(&sparse).expect("an archive"),
        flate2::Compression::fast(),
    ));
    let mut header = tar::Header::new_gnu();
    header.set_path("release/bin/kr").expect("a path");
    header.set_entry_type(tar::EntryType::GNUSparse);
    header.set_mode(0o644);
    header.set_size(512);
    {
        let gnu = header.as_gnu_mut().expect("a GNU header");
        gnu.set_real_size(1024);
        gnu.sparse[0].set_offset(0);
        gnu.sparse[0].set_length(512);
        gnu.sparse[1].set_offset(1024);
        gnu.sparse[1].set_length(0);
    }
    header.set_cksum();
    builder.append(&header, &[7_u8; 512][..]).expect("an entry");
    builder
        .into_inner()
        .and_then(flate2::write::GzEncoder::finish)
        .expect("written");
    let said = kr_cli::update::release::unpack(&sparse, &staging("sparse"))
        .expect_err("a sparse entry is refused")
        .to_string();
    assert!(said.contains("a sparse entry"), "{said}");

    // The POSIX form of a sparse file is a regular entry that carries `GNU.sparse.*` extension keys:
    // it is refused as a sparse entry at its first entry too, not later as a file that is missing.
    let posix = scratch.path().join("posix.tar.gz");
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        std::fs::File::create(&posix).expect("an archive"),
        flate2::Compression::fast(),
    ));
    builder
        .append_pax_extensions([
            ("GNU.sparse.major", &b"1"[..]),
            ("GNU.sparse.name", &b"release/bin/kr"[..]),
        ])
        .expect("extensions");
    let mut header = tar::Header::new_gnu();
    header
        .set_path("release/GNUSparseFile.1/kr")
        .expect("a path");
    header.set_size(4);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &b"data"[..]).expect("an entry");
    builder
        .into_inner()
        .and_then(flate2::write::GzEncoder::finish)
        .expect("written");
    let said = kr_cli::update::release::unpack(&posix, &staging("posix"))
        .expect_err("a POSIX sparse entry is refused")
        .to_string();
    assert!(said.contains("a sparse entry"), "{said}");
}

/// KR-REQ-26.09: what was written is checked against the manifest: every listed file with its
/// length and digest, and nothing unlisted.
#[test]
fn a_release_is_every_file_its_manifest_lists_and_nothing_else() {
    let (manifest, files, _) = small_release(&keys().targets);
    let written = |files: &BTreeMapFiles| -> kr_cli::update::release::Written {
        files
            .iter()
            .map(|(path, contents)| {
                (
                    path.clone(),
                    (
                        contents.len() as u64,
                        Digest256::from_bytes(kr_cbor::sha256(contents)),
                    ),
                )
            })
            .collect()
    };
    // The control: what the manifest lists, and the manifest itself, is the release.
    let mut whole = written(&files);
    whole.insert(
        kr_protocol::update::MANIFEST_FILE.to_owned(),
        (1, Digest256::from_bytes([0; 32])),
    );
    assert!(kr_cli::update::release::check_files(&manifest, &whole).is_ok());
    let mut changed = files.clone();
    changed.insert("bin/kr".to_owned(), b"#!/bin/zsh\n".to_vec());
    let mut missing = files.clone();
    missing.remove("bin/kr");
    let mut extra = files;
    extra.insert("share/extra".to_owned(), b"x".to_vec());
    for (what, files) in [("changed", changed), ("missing", missing), ("extra", extra)] {
        assert!(
            kr_cli::update::release::check_files(&manifest, &written(&files)).is_err(),
            "a {what} file is refused"
        );
    }
}

/// KR-REQ-26.09: an update refuses a release whose signed manifest lists no program of one a host
/// runs, whichever program that is, and says which; so does a manifest that lists the file as data,
/// whose bytes are all there. The same release with the program is taken, so the one program is
/// the whole of the refusal.
#[test]
fn an_update_refuses_a_release_that_lacks_a_program_a_host_runs() {
    let host = Host::bare();
    let current = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&current);
    let kr = host.store.stable(Program::Kr);
    let check = |release: &Assembled, label: &str| {
        let archive = host.scratch("archives").join(format!("{label}.tar.gz"));
        release.archive(&archive);
        host.run(
            &kr,
            &[
                "host",
                "update",
                "--archive",
                &archive.display().to_string(),
                "--check",
            ],
        )
    };

    let control = check(&Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2), "whole");
    assert!(
        control.status.success(),
        "a release that carries every program is checked: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    // Every program is tried before the test says anything, so one run names each that is let
    // through.
    let mut wrong = Vec::new();
    let whole = || Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let mut cases: Vec<(String, &str, Assembled)> = PROGRAM_NAMES
        .iter()
        .map(|name| (format!("without-{name}"), *name, whole().without(&[name])))
        .collect();
    cases.push((
        "hook-as-data".to_owned(),
        "kr-hook",
        whole().with_data("kr-hook"),
    ));
    for (label, name, release) in cases {
        let refused = check(&release, &label);
        let said = String::from_utf8_lossy(&refused.stderr);
        if refused.status.code() != Some(1) {
            wrong.push(format!(
                "{label}: not refused, exit {:?}",
                refused.status.code()
            ));
        } else if !said.contains(&format!("`{name}`")) {
            wrong.push(format!("{label}: {name} is not named: {said}"));
        } else if let Some(other) = PROGRAM_NAMES
            .iter()
            .find(|other| **other != name && said.contains(&format!("`{other}`")))
        {
            wrong.push(format!("{label}: {other} is named too: {said}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(current.name().clone())
    );
}

/// KR-REQ-26.09: a release an earlier build put in the store, whose manifest lists fewer programs
/// than a host now runs, stays: its programs start, `kr host versions` reads its manifest, and an
/// update from it to a release that carries every program is taken. Only a release being taken in
/// is held to the list of programs.
#[test]
fn a_release_in_the_store_that_lacks_a_program_is_kept_and_updated_from() {
    let host = Host::create();
    // The store's record, as an install writes it: readable by its owner alone.
    std::fs::set_permissions(
        host.store.record(),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("the record's mode");
    let older = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1)
        .without(&["kr-plugin-host", "kr-describe-inference"]);
    host.put(&older);
    host.switch(older.name());

    let (listed, versions) = host.kr_json(&["host", "versions", "--json"]);
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert_eq!(
        versions["releases"][0]["release"],
        older.name().as_str(),
        "{versions}"
    );
    assert_eq!(versions["releases"][0]["sequence"], 1, "{versions}");

    let newer = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let archive = host.scratch("archives").join("newer.tar.gz");
    newer.archive(&archive);
    let updated = host.run(
        &host.store.stable(Program::Kr),
        &[
            "host",
            "update",
            "--archive",
            &archive.display().to_string(),
        ],
    );
    assert!(
        updated.status.success(),
        "{}",
        String::from_utf8_lossy(&updated.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(newer.name().clone())
    );
}

/* -------------------------------------------------------------------------------------------- */
/* Environments no daemon served between two updates                                            */
/* -------------------------------------------------------------------------------------------- */

/// An environment of a host's store that no daemon serves: a tree of its own, whose roots the store
/// records as the daemon that once served it recorded them, and whose registry holds a launch that
/// came to nothing, a live session's worker and a closed session. Its processes have all ended, so
/// no record of it holds an update.
struct Idle {
    temp: kr_ipc::testing::TempHost,
}

impl Idle {
    /// The environment, with a registry at the schema this build reads.
    fn new(store: &Store) -> Self {
        use kr_controller::registry::{Registry, WorkerRecord};
        use kr_protocol::identity::{DesktopBinding, WorkerProfile};
        use kr_protocol::ids::{ActorId, AuthorityRevision};
        use kr_protocol::scalars::{AuthorisationKey, TimestampMs};
        use kr_protocol::session::{
            ClosureReason, ClosureRecord, Durability, OwnershipCoverage, SessionState,
        };

        let temp = kr_ipc::testing::TempHost::create();
        store
            .record_roots(temp.paths().runtime_root(), temp.paths().state_root())
            .expect("records the roots a daemon of the store served");
        let idle = Self { temp };
        let mut registry = Registry::open(idle.registry(), idle.temp.environment_id())
            .expect("a registry at the schema this build reads");
        let actor = ActorId::new("local:501").expect("a principal");
        let ended = kr_ipc::identity::ended_process_identity(4242);
        // A launch that came to nothing: its launcher has ended. Its recorded create request holds
        // an environment variable its creator sent, as an earlier schema recorded them.
        reserve_with(&mut registry, &actor, &ended, 1, &recorded_create(SECRET));
        // A session that is live, and one that has closed, each with its worker.
        let worker_of = |registry: &mut Registry, byte: u8| {
            let reservation = reserve_with(registry, &actor, &ended, byte, b"intent");
            let key = AuthorisationKey::from_bytes([byte; 32]);
            registry
                .claim_rendezvous(reservation.reservation_id, key)
                .expect("claims");
            let worker = WorkerRecord {
                session_id: reservation.session_id,
                display_number: reservation.display_number,
                public_key: key,
                process_identity: ended.clone(),
                endpoint: "worker".to_owned(),
                profile: WorkerProfile::HeadlessUser,
                state: SessionState::Live,
                acknowledged_revision: AuthorityRevision::new(0),
            };
            registry
                .record_worker(reservation.reservation_id, &worker, &DesktopBinding::none())
                .expect("records the worker");
            reservation
        };
        worker_of(&mut registry, 2);
        let closed = worker_of(&mut registry, 3);
        registry
            .record_closure(&ClosureRecord {
                session_id: closed.session_id,
                session_epoch: kr_protocol::ids::SessionEpoch::V1,
                reason: ClosureReason::CloseRequested,
                root_exit_code: Nullable::null(),
                root_signal: Nullable::null(),
                terminated: Vec::new(),
                surviving: Vec::new(),
                ownership_coverage: OwnershipCoverage::Incomplete,
                durability: Durability::Durable,
                closed_at_ms: TimestampMs::new(2_000),
            })
            .expect("records the closure");
        drop(registry);
        idle
    }

    /// A live session whose worker is a process that is running and does not answer, which holds an
    /// update: this test's own process stands in for it.
    fn with_a_worker_that_holds_the_update(self) -> Self {
        use kr_controller::registry::{Registry, WorkerRecord};
        use kr_protocol::identity::{DesktopBinding, WorkerProfile};
        use kr_protocol::ids::{ActorId, AuthorityRevision};
        use kr_protocol::scalars::AuthorisationKey;
        use kr_protocol::session::SessionState;

        let mut registry = Registry::open(self.registry(), self.temp.environment_id())
            .expect("the registry opens");
        let running =
            kr_ipc::identity::current_process_start_identity().expect("this process's identity");
        let reservation = reserve_with(
            &mut registry,
            &ActorId::new("local:501").expect("a principal"),
            &running,
            4,
            b"intent",
        );
        let key = AuthorisationKey::from_bytes([4; 32]);
        registry
            .claim_rendezvous(reservation.reservation_id, key)
            .expect("claims");
        registry
            .record_worker(
                reservation.reservation_id,
                &WorkerRecord {
                    session_id: reservation.session_id,
                    display_number: reservation.display_number,
                    public_key: key,
                    process_identity: running,
                    endpoint: "worker".to_owned(),
                    profile: WorkerProfile::HeadlessUser,
                    state: SessionState::Live,
                    acknowledged_revision: AuthorityRevision::new(0),
                },
                &DesktopBinding::none(),
            )
            .expect("records the worker");
        drop(registry);
        self
    }

    /// The registry as an earlier release left it at `version`, between 4 and 6: what each later
    /// schema added is taken away, and the version says so.
    fn shaped_as(self, version: i64) -> Self {
        let mut statements = String::new();
        if version < 6 {
            statements.push_str(
                "ALTER TABLE workers DROP COLUMN desktop_session_id;
                 ALTER TABLE workers DROP COLUMN login_generation;",
            );
        }
        if version < 5 {
            statements.push_str("DROP TABLE utc_floors; DROP TABLE clock_continuity;");
        }
        self.change(&format!(
            "{statements} UPDATE schema_version SET version = {version};"
        ))
    }

    /// The registry's version row says `version` and nothing else changes.
    fn labelled(self, version: i64) -> Self {
        self.change(&format!("UPDATE schema_version SET version = {version};"))
    }

    fn change(self, statements: &str) -> Self {
        let connection = rusqlite::Connection::open(self.registry()).expect("opens");
        connection
            .execute_batch(statements)
            .expect("changes the registry");
        drop(connection);
        self
    }

    fn registry(&self) -> PathBuf {
        self.temp.environment().registry_database()
    }

    fn environment_id(&self) -> String {
        self.temp.environment_id().to_string()
    }

    /// What the registry records, read as the file alone: every column the first schema this suite
    /// forges has, apart from the recorded create request, which a later schema rewrites.
    fn records(&self) -> Vec<Vec<Vec<String>>> {
        let uri = format!("file:{}?immutable=1", self.registry().display());
        let connection = rusqlite::Connection::open_with_flags(
            uri,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_URI
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("the registry reads");
        [
            "SELECT reservation_id, actor_id, create_token, payload_digest, session_id,
                    display_number, phase, launcher_pid, launcher_source, launcher_start,
                    claimed_key, created_at_ms FROM reservations ORDER BY reservation_id",
            "SELECT session_id, display_number, public_key, process_pid, process_source,
                    process_start, endpoint, profile, state, acknowledged_revision, stated_source
             FROM workers ORDER BY session_id",
            "SELECT * FROM tombstones ORDER BY session_id",
            "SELECT * FROM environment",
        ]
        .iter()
        .map(|query| {
            let mut statement = connection.prepare(query).expect("prepares");
            let columns = statement.column_count();
            statement
                .query_map([], |row| {
                    Ok((0..columns)
                        .map(|column| format!("{:?}", row.get_ref(column).expect("a value")))
                        .collect::<Vec<_>>())
                })
                .expect("reads")
                .collect::<Result<_, _>>()
                .expect("rows")
        })
        .collect()
    }

    /// The schema version the registry records, read as the file alone.
    fn version(&self) -> i64 {
        kr_controller::registry::Registry::open_to_read(self.registry(), self.temp.environment_id())
            .map(|_| kr_controller::registry::SCHEMA_VERSION)
            .unwrap_or_else(|_| {
                let uri = format!("file:{}?immutable=1", self.registry().display());
                rusqlite::Connection::open_with_flags(
                    uri,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_URI,
                )
                .expect("reads")
                .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
                .expect("a version")
            })
    }

    /// Every file in the environment's directories whose name says a database's log or journal.
    fn sidecars(&self) -> Vec<String> {
        let mut found = Vec::new();
        let mut pending = vec![self.temp.root().to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory)
                .expect("a directory")
                .flatten()
            {
                let name = entry.file_name().to_string_lossy().into_owned();
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    pending.push(entry.path());
                } else if ["-wal", "-shm", "-journal"]
                    .iter()
                    .any(|suffix| name.ends_with(suffix))
                {
                    found.push(name);
                }
            }
        }
        found
    }
}

/// Reserves a launch with the ended process `ended` as its launcher.
fn reserve_with(
    registry: &mut kr_controller::registry::Registry,
    actor: &kr_protocol::ids::ActorId,
    ended: &kr_protocol::identity::ProcessStartIdentity,
    byte: u8,
    intent: &[u8],
) -> kr_controller::registry::Reservation {
    let reservation = registry
        .reserve(
            actor,
            Uuid::from_bytes([byte; 16]),
            Digest256::from_bytes([byte; 32]),
            intent,
            kr_protocol::scalars::TimestampMs::new(u64::from(byte)),
        )
        .expect("reserves")
        .reservation;
    registry
        .record_launch(reservation.reservation_id, ended)
        .expect("records the launcher");
    registry
        .set_phase(
            reservation.reservation_id,
            kr_controller::registry::LaunchPhase::Spawned,
        )
        .expect("the launch is spawned");
    reservation
}

/// The value of an environment variable a creator sent, which an earlier schema recorded with the
/// create request it came in.
const SECRET: &str = "a-secret-an-earlier-schema-recorded";

/// A create request as an earlier schema recorded it: whole, with the environment its creator sent.
fn recorded_create(secret: &str) -> Vec<u8> {
    use kr_protocol::identity::WorkerProfile;
    use kr_protocol::session::{
        EnvironmentVariable, LaunchProfile, Presentation, SessionCreateParams, ShellMode,
    };

    kr_cbor::to_canonical_vec(&SessionCreateParams {
        environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([9; 16])),
        presentation: Presentation::Invisible,
        shell: Nullable::null(),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some("/".to_owned()),
        dimensions: Nullable::null(),
        worker_profile: WorkerProfile::HeadlessUser,
        environment_snapshot: vec![EnvironmentVariable {
            name: "API_TOKEN".to_owned(),
            value: secret.to_owned(),
        }],
        palette: Nullable::null(),
        launch_profile: LaunchProfile::default(),
        terminal: Nullable::null(),
    })
    .expect("encodes")
}

/// A host with a release installed and its daemon serving, and a newer release archived.
async fn host_to_update() -> (Host, Assembled, Assembled, String) {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();
    (host, one, two, archive)
}

/// KR-REQ-26.08, KR-REQ-24.30: an environment whose daemon did not run since an earlier schema
/// step does not stop the update. Its registry is two schema steps behind the one the update's
/// release reads; the update, with every daemon stopped and every environment's lock held, brings
/// it forward through the registry's own migration before it classes it, says so, and the rows it
/// held are the rows it holds: nothing is left beside the file.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_carries_an_environment_whose_daemon_did_not_run_forward() {
    let (host, one, two, archive) = host_to_update().await;
    let idle = Idle::new(&host.store).shaped_as(4);
    let before = idle.records();
    assert_eq!(idle.version(), 4);

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["target"], two.name().as_str(), "{said}");
    assert_eq!(
        said["carried"],
        serde_json::json!([{
            "environment": idle.environment_id(),
            "from": 4,
            "to": kr_controller::registry::SCHEMA_VERSION,
        }]),
        "{said}"
    );
    assert_eq!(
        said["restarted"],
        serde_json::json!([host.tree.environment_id().to_string()]),
        "the environment a daemon served is started again, and the idle one is not: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
    let _ = one;
    assert_eq!(idle.version(), kr_controller::registry::SCHEMA_VERSION);
    assert_eq!(
        idle.records(),
        before,
        "every row it held is the row it holds"
    );
    assert_eq!(
        idle.sidecars(),
        Vec::<String>::new(),
        "no log or journal is left beside it"
    );
}

/// KR-REQ-24.30: the carry is the registry's own chain, every step of it: an idle registry two
/// steps behind comes through the step that removes the environment its creators sent from the
/// recorded create requests as a daemon's start would take it, and the old bytes are gone from the
/// file and from its log, and the request is what it was, with no environment.
#[tokio::test(flavor = "multi_thread")]
async fn the_carry_takes_an_idle_registry_through_the_step_that_removes_recorded_environments() {
    let (host, _one, _two, archive) = host_to_update().await;
    let idle = Idle::new(&host.store).shaped_as(4);
    let held_before = std::fs::read(idle.registry()).expect("the registry");
    assert!(
        held_before
            .windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes()),
        "the old registry holds what its creator sent"
    );

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["carried"][0]["from"], 4, "{said}");
    let after = std::fs::read(idle.registry()).expect("the registry");
    assert!(
        !after
            .windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes()),
        "nothing of what the creator sent is in the file"
    );
    assert_eq!(idle.sidecars(), Vec::<String>::new(), "or in a log");
    let registry = kr_controller::registry::Registry::open_to_read(
        idle.registry(),
        idle.temp.environment_id(),
    )
    .expect("reads at the schema this build reads");
    let reservation = registry
        .reservations_in(kr_controller::registry::LaunchPhase::Spawned)
        .expect("reads")
        .into_iter()
        .next()
        .expect("the launch that came to nothing");
    let intent = reservation.create_intent.expect("its request is kept");
    let create: kr_protocol::session::SessionCreateParams =
        kr_cbor::from_canonical_slice(&intent, &kr_cbor::Limits::DEFAULT).expect("a request");
    let mut expected: kr_protocol::session::SessionCreateParams =
        kr_cbor::from_canonical_slice(&recorded_create(SECRET), &kr_cbor::Limits::DEFAULT)
            .expect("the request as it was recorded");
    expected.environment_snapshot.clear();
    assert_eq!(
        create, expected,
        "the request is what it was, with no environment"
    );
}

/// KR-REQ-24.30: a step of the chain that cannot finish holds the update and says so, and the next
/// run goes on from where it stopped. The step that removes the recorded environments cannot take
/// its log in while another connection reads the registry: the update exits 1 with the registry at
/// the version before that step, its requests already rewritten, nothing switched and the daemon it
/// stopped serving; once the reader is gone, the next update carries from that version.
#[tokio::test(flavor = "multi_thread")]
async fn a_step_that_cannot_finish_holds_the_update_and_the_next_run_goes_on_from_it() {
    let (host, one, two, archive) = host_to_update().await;
    let idle = Idle::new(&host.store).shaped_as(4);
    // Another program has the registry open and a read under way, as a tool a person runs might.
    let reader = rusqlite::Connection::open(idle.registry()).expect("opens");
    reader
        .execute_batch("BEGIN; SELECT COUNT(*) FROM reservations;")
        .expect("a read under way");

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&idle.environment_id())
            && message.contains("recorded schema version 4 when it was opened")
            && message.contains("write-ahead log still holds the old copies")
            && message.contains("run kr host update again"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon the update stopped serves from the release still current"
    );
    drop(reader);
    assert_eq!(
        idle.version(),
        6,
        "the step before the one that could not finish"
    );

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["carried"][0]["from"], 6, "{said}");
    assert_eq!(idle.version(), kr_controller::registry::SCHEMA_VERSION);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
}

/// The control of the above: every environment ran, so every registry is at the schema this build
/// reads, the update finishes, and it carries nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_across_environments_that_all_ran_carries_nothing() {
    let (host, _one, two, archive) = host_to_update().await;
    let second = Second::start(&host.store.stable(Program::Controller)).await;

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["carried"], serde_json::json!([]), "{said}");
    assert_eq!(said["not_reached"], serde_json::json!([]), "{said}");
    let mut restarted: Vec<String> = said["restarted"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|environment| environment.as_str().unwrap_or_default().to_owned())
        .collect();
    restarted.sort();
    let mut expected = vec![
        host.tree.environment_id().to_string(),
        second.tree.environment_id().to_string(),
    ];
    expected.sort();
    assert_eq!(restarted, expected, "{said}");
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
    assert_eq!(
        second.build().await,
        format!("kr-controller/{}", two.name())
    );
}

/// KR-REQ-26.09: a check changes nothing, and so does not carry: an idle registry two steps behind
/// is as it was after it, byte for byte and with nothing made beside it, and the check names none.
#[tokio::test(flavor = "multi_thread")]
async fn a_check_leaves_an_idle_registry_as_it_was() {
    let (host, _one, _two, archive) = host_to_update().await;
    let idle = Idle::new(&host.store).shaped_as(4);
    let before = std::fs::read(idle.registry()).expect("the registry");
    let removed = host.tree.root().join("removed-state");
    host.store
        .record_roots(&host.tree.root().join("removed-runtime"), &removed)
        .expect("records a state root that is gone");

    let (output, said) =
        host.kr_json(&["host", "update", "--archive", &archive, "--check", "--json"]);
    assert!(
        output.status.success(),
        "kr host update --check: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["carried"], serde_json::json!([]), "{said}");
    assert_eq!(
        said["not_reached"][0]["state_root"],
        removed.display().to_string(),
        "a check names the root it could not reach: {said}"
    );
    assert_eq!(
        std::fs::read(idle.registry()).expect("the registry"),
        before
    );
    assert_eq!(idle.version(), 4);
    assert_eq!(idle.sidecars(), Vec::<String>::new());
}

/// KR-REQ-26.08: an update that waits after it brought a registry forward says so, and the registry
/// stays at the schema this release reads, which the release still current reads as well: the idle
/// environment's registry is two steps behind and holds a live worker that does not answer, so the
/// carry happens and the registry is then classed and holds the update, exit 9, with nothing switched
/// and the daemon the update stopped serving again. A recorded environment whose state is gone is
/// named in that message too.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_that_waits_after_a_carry_says_what_it_carried_and_leaves_it_so() {
    let (host, one, _two, archive) = host_to_update().await;
    let idle = Idle::new(&host.store)
        .with_a_worker_that_holds_the_update()
        .shaped_as(4);
    let removed = host.tree.root().join("removed-state");
    host.store
        .record_roots(&host.tree.root().join("removed-runtime"), &removed)
        .expect("records a state root that is gone");

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("did not answer its challenge and has not ended")
            && message.contains(&format!(
                "The update had already brought forward the registry of environment {} from \
                 schema version 4 to {}",
                idle.environment_id(),
                kr_controller::registry::SCHEMA_VERSION
            ))
            && message.contains(&format!(
                "The update found that the environment recorded with runtime root {} and state \
                 root {} could not be reached",
                host.tree.root().join("removed-runtime").display(),
                removed.display()
            )),
        "{said}"
    );
    assert_eq!(idle.version(), kr_controller::registry::SCHEMA_VERSION);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon the update stopped serves from the release still current"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
}

/// KR-REQ-24.30: a registry that cannot be brought forward holds the update, and what it left is
/// said. Labelled version 3 with every column of this build, its first step adds a column that is
/// already there: the step fails whole, the registry stays at version 3 for the release that is
/// current to continue from, nothing is switched, and the daemon the update stopped serves again.
#[tokio::test(flavor = "multi_thread")]
async fn a_registry_that_cannot_be_carried_holds_the_update_and_says_where_it_is() {
    let (host, one, _two, archive) = host_to_update().await;
    let idle = Idle::new(&host.store).labelled(3);

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&idle.environment_id())
            && message.contains("brought forward")
            && message.contains("schema version 3")
            && message.contains("stated_source"),
        "{said}"
    );
    assert_eq!(idle.version(), 3);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon the update stopped serves from the release still current"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
}

/// KR-REQ-24.30: the migration never makes a table again that a registry lost, which would read as
/// a registry that recorded no worker: a registry two steps behind with no `reservations` table
/// holds the update, names the table, and is left as it was.
#[tokio::test(flavor = "multi_thread")]
async fn a_registry_that_lost_a_table_is_not_carried_and_holds_the_update() {
    let (host, one, _two, archive) = host_to_update().await;
    let idle = Idle::new(&host.store)
        .shaped_as(4)
        .change("DROP TABLE reservations;");

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&idle.environment_id()) && message.contains("reservations"),
        "{said}"
    );
    assert_eq!(idle.version(), 4);
    let tables: i64 = rusqlite::Connection::open(idle.registry())
        .expect("opens")
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'reservations'",
            [],
            |row| row.get(0),
        )
        .expect("reads the schema");
    assert_eq!(tables, 0, "no table was made again, empty");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// The control of the two above, for a registry of a later schema than this release reads: it is
/// not carried back, and the update holds as it did.
#[tokio::test(flavor = "multi_thread")]
async fn a_registry_of_a_later_schema_holds_the_update_and_is_left() {
    let (host, one, _two, archive) = host_to_update().await;
    let later = kr_controller::registry::SCHEMA_VERSION + 1;
    let idle = Idle::new(&host.store).labelled(later);

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&idle.environment_id())
            && message.contains(&format!("schema version {later}")),
        "{said}"
    );
    assert_eq!(idle.version(), later);
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// KR-REQ-26.08: an environment whose identity cannot be looked at because what holds it is gone,
/// a state root that is a file where a directory was, or one that was removed, is named in the
/// outcome, and every other environment goes ahead: the daemon the host's own environment has is
/// handed over and started again from the new release.
#[tokio::test(flavor = "multi_thread")]
async fn an_environment_that_cannot_be_reached_is_named_and_the_others_go_ahead() {
    let (host, _one, two, archive) = host_to_update().await;
    let file = host.tree.root().join("not-a-directory");
    std::fs::write(&file, b"a container's mount that became a file").expect("a file");
    let runtime = host.tree.root().join("unreached-runtime");
    let removed = host.tree.root().join("removed-state");
    host.store
        .record_roots(&runtime, &file)
        .expect("records a state root that is a file");
    host.store
        .record_roots(&runtime, &removed)
        .expect("records a state root that is gone");

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let unreached = said["not_reached"].as_array().cloned().unwrap_or_default();
    let mut states: Vec<String> = unreached
        .iter()
        .map(|entry| entry["state_root"].as_str().unwrap_or_default().to_owned())
        .collect();
    states.sort();
    let mut expected = vec![file.display().to_string(), removed.display().to_string()];
    expected.sort();
    assert_eq!(states, expected, "{said}");
    assert!(
        unreached.iter().all(|entry| entry["reason"]
            .as_str()
            .is_some_and(|said| !said.is_empty())),
        "each says why: {said}"
    );
    assert_eq!(
        said["restarted"],
        serde_json::json!([host.tree.environment_id().to_string()]),
        "{said}"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
}

/// The control of the above: an identity that is there and cannot be trusted, a link, is not a
/// reason to go on without the environment: the update stops before it stops anything.
#[tokio::test(flavor = "multi_thread")]
async fn an_identity_that_is_there_and_not_trusted_still_stops_the_update() {
    let (host, one, _two, archive) = host_to_update().await;
    let state = host.tree.root().join("untrusted-state");
    std::fs::create_dir_all(&state).expect("a state root");
    std::os::unix::fs::symlink(
        host.tree.root().join("elsewhere"),
        state.join("environment-id"),
    )
    .expect("a link where the identity is");
    host.store
        .record_roots(&host.tree.root().join("untrusted-runtime"), &state)
        .expect("records the roots");

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "nothing was stopped"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
}

/* -------------------------------------------------------------------------------------------- */
/* Going back                                                                                    */
/* -------------------------------------------------------------------------------------------- */

/// The stores of a release that reads transfer journals from version 2, and every other store as the
/// code writes it.
fn reading_transfers_from_2() -> Vec<ReleaseStore> {
    release_stores()
        .into_iter()
        .map(|store| match store.store.as_str() {
            "transfers" => ReleaseStore {
                migrates_from: 2,
                ..store
            },
            _ => store,
        })
        .collect()
}

/// The stores a release assembled here declares it reads, with the versions of the store `name` given.
fn reading_a_store_at(name: &str, migrates_from: u32, version: u32) -> Vec<ReleaseStore> {
    release_stores()
        .into_iter()
        .map(|store| {
            if store.store == name {
                ReleaseStore {
                    migrates_from,
                    version,
                    ..store
                }
            } else {
                store
            }
        })
        .collect()
}

/// The registry's schema version, as the daemon wrote it.
fn registry_version() -> u32 {
    u32::try_from(kr_controller::registry::SCHEMA_VERSION).expect("a small number")
}

/// KR-REQ-26.10: `kr host rollback` goes back to the release this host was on before its last
/// switch, as an update goes forward: the control daemon is handed over and started again from the
/// older release, the release left is kept as the one to go back to, and no live session is moved.
/// A session started under the older release and one started under the newer keep their workers,
/// and so does the agent in the shell of each, through the update and through the rollback.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_goes_back_to_the_release_before_and_moves_no_live_session() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let (old_display, old_session, old_agent) =
        host.new_session_with_an_agent(&host.program(one.name(), Program::Kr), "old");
    let old_worker = host.worker_process(old_session);

    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
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
    assert_eq!(said["rolled_back"], false, "{said}");
    let (new_display, new_session, new_agent) =
        host.new_session_with_an_agent(&host.program(two.name(), Program::Kr), "new");
    let new_worker = host.worker_process(new_session);
    assert_eq!(
        host.worker_build(new_session).await,
        format!("kr-worker/{}", two.name())
    );

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["rolled_back"], true, "{said}");
    assert_eq!(said["source"], two.name().as_str(), "{said}");
    assert_eq!(said["target"], one.name().as_str(), "{said}");
    assert_eq!(
        said["restarted"],
        serde_json::json!([host.tree.environment_id().to_string()]),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone()),
        "the older release is current"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the control daemon was started again, from the older release"
    );
    let record = host.record();
    assert_eq!(record["previous"], two.name().as_str(), "{record}");
    assert!(record["update"].is_null(), "the rollback settled: {record}");
    assert!(
        host.store.release_directory(two.name()).is_dir(),
        "the release left is kept"
    );

    // No session moved: each worker is the process it was, on the release it started from, and
    // each agent runs on.
    for (session, worker, agent, release) in [
        (old_session, &old_worker, &old_agent, &one),
        (new_session, &new_worker, &new_agent, &two),
    ] {
        assert_eq!(
            &host.worker_process(session),
            worker,
            "the worker of the session started under {} is the process it was",
            release.name()
        );
        assert_eq!(
            host.worker_build(session).await,
            format!("kr-worker/{}", release.name())
        );
        assert_eq!(
            kr_ipc::identity::process_state(&agent.identity),
            kr_ipc::identity::ProcessState::Running,
            "the agent in the shell of the session started under {} runs on",
            release.name()
        );
    }
    let (_, versions) = host.kr_json(&["host", "versions", "--json"]);
    let state_of = |name: &ReleaseName| {
        versions["releases"]
            .as_array()
            .and_then(|releases| {
                releases
                    .iter()
                    .find(|kept| kept["release"] == name.as_str())
            })
            .cloned()
            .unwrap_or(Value::Null)
    };
    assert_eq!(state_of(one.name())["current"], true, "{versions}");
    assert_eq!(state_of(two.name())["previous"], true, "{versions}");
    assert_eq!(
        state_of(two.name())["held"],
        true,
        "the session started under the release left holds it: {versions}"
    );

    // A session started now runs the older release again.
    let (display, session_id) = host.new_session(&host.store.stable(Program::Kr));
    assert_eq!(
        host.worker_build(session_id).await,
        format!("kr-worker/{}", one.name())
    );
    for display in [&display, &old_display, &new_display] {
        host.close(&host.store.stable(Program::Kr), display);
    }
}

/// KR-REQ-26.10: a rollback brings no registry forward. An environment whose daemon has not run since
/// a schema before this release's has a registry the older release can read as it is, and a rollback
/// that migrated it to this release's schema would put it beyond that release. It is left as the file
/// it was, with nothing made beside it, and the rollback says it carried nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_leaves_a_registry_behind_this_release_s_schema_as_it_is() {
    let (host, one, two, archive) = host_to_update().await;
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let idle = Idle::new(&host.store).shaped_as(6);
    let before = idle.records();
    assert_eq!(idle.version(), 6);

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["target"], one.name().as_str(), "{said}");
    assert_eq!(said["carried"], serde_json::json!([]), "{said}");
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    assert_eq!(idle.version(), 6, "the registry was not brought forward");
    assert_eq!(idle.records(), before, "and what it records is as it was");
    assert!(
        idle.sidecars().is_empty(),
        "and nothing is left beside it: {:?}",
        idle.sidecars()
    );
    let _ = two;
}

/// KR-REQ-26.10: a rollback classes the records of a registry that is behind this release's schema
/// all the same, from a copy it brings forward: a worker the registry names that does not answer and
/// has not ended holds the rollback, as it holds an update, and the registry is left as it was.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_classes_a_registry_behind_this_release_s_schema_without_changing_it() {
    let (host, one, two, archive) = host_to_update().await;
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let idle = Idle::new(&host.store)
        .with_a_worker_that_holds_the_update()
        .shaped_as(6);
    let before = idle.records();

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("did not answer its challenge and has not ended"),
        "{said}"
    );
    assert_eq!(idle.version(), 6, "the registry was not brought forward");
    assert_eq!(idle.records(), before, "and what it records is as it was");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone()),
        "nothing was switched"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the daemon the rollback stopped serves again"
    );
    let _ = one;
}

/// KR-REQ-26.10: a rollback is refused, naming the store, when a store as it stands is at a version
/// the older release does not read, and nothing is switched: the registry a daemon of this build
/// wrote is at this build's schema version, and a release that reads the one before cannot take it.
/// The daemon the rollback stopped serves again from the release still current.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_is_refused_naming_a_store_the_older_release_cannot_read() {
    let mut host = Host::bare();
    let older = registry_version() - 1;
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1)
        .reading(reading_a_store_at("registry", 1, older));
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let scratch = host.scratch("archives");
    let archive = scratch.join("two.tar.gz");
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
    let registry = host.tree.environment().registry_database();
    let recorded = |path: &Path| -> i64 {
        rusqlite::Connection::open(path)
            .expect("opens")
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .expect("reads")
    };
    assert_eq!(
        recorded(&registry),
        i64::from(registry_version()),
        "the daemon of this build wrote the registry at this build's version"
    );

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("registry")
            && message.contains(&host.tree.environment_id().to_string())
            && message.contains(&format!("schema version {}", registry_version()))
            && message.contains(&format!("versions 1 to {older}")),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone()),
        "nothing was switched"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the daemon the rollback stopped serves again, from the release still current"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], one.name().as_str(), "{record}");
    assert_eq!(
        recorded(&registry),
        i64::from(registry_version()),
        "the registry was left as it was"
    );
}

/// KR-REQ-26.10: a rollback is refused, naming the document, when the configuration document is at a
/// version the older release does not read: the document this build writes is at version 3, and a release
/// that reads versions 1 to 2 cannot take it. Nothing is switched, and the document is left as it was; a
/// document at the older release's own version is no obstacle.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_is_refused_naming_a_configuration_document_the_older_release_cannot_read() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).reading(reading_a_store_at(
        "configuration",
        1,
        2,
    ));
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let archive = host.scratch("archives").join("two.tar.gz");
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

    // The owner's choice, written by this build as it writes one.
    let environment = host.tree.environment();
    let writers = kr_cli::barrier::hold_for_configuration(&environment)
        .expect("a test outside a store holds nothing");
    let permit = kr_cli::barrier::permit(&writers, &kr_cli::doctor::configuration::WRITTEN)
        .expect("permitted");
    kr_cli::doctor::configuration::apply(
        &environment,
        &kr_protocol::hostinfo::configuration::Change::SleepInhibition(
            kr_protocol::desktop::SleepInhibitionSetting::MainsOnly,
        ),
        &permit,
    )
    .expect("the owner's choice");
    let document = kr_cli::doctor::configuration::document_path(&environment);
    let written = std::fs::read(&document).expect("the document");

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&document.display().to_string())
            && message.contains("records version 3")
            && message.contains("reads versions 1 to 2"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone()),
        "nothing was switched"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the daemon the rollback stopped serves again, from the release still current"
    );
    assert_eq!(
        std::fs::read(&document).expect("the document"),
        written,
        "the document was left as it was"
    );

    // The control: a document at the version the older release reads goes back.
    kr_ipc::paths::write_owner_only_file(&document, br#"{"version": 2}"#).expect("a document");
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
}

/// KR-REQ-26.10: an update is held to the same rule, forward: a release that reads a version of the
/// registry above the one a host's registry is at, and one that migrates from a version above it,
/// are both refused naming the store, with nothing switched.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_is_refused_naming_a_store_the_new_release_cannot_read() {
    let (host, one, _two, _archive) = host_to_update().await;
    let beyond = registry_version() + 1;
    let scratch = host.scratch("archives");
    // A release that reads only versions the registry has not reached.
    let ahead = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2)
        .reading(reading_a_store_at("registry", beyond, beyond));
    let archive = scratch.join("ahead.tar.gz");
    ahead.archive(&archive);

    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("registry")
            && message.contains(&format!("schema version {}", registry_version()))
            && message.contains(&format!("versions {beyond} to {beyond}")),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone()),
        "nothing was switched"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon the update stopped serves again"
    );
}

/// KR-REQ-26.10: a release that lists a store by a scope or a way of recording its version that
/// this build does not know cannot be checked against, so the switch is refused naming the store
/// before anything is surveyed or stopped: no update is recorded as begun and the daemon keeps
/// serving.
#[tokio::test(flavor = "multi_thread")]
async fn a_store_listed_in_a_way_this_kr_does_not_know_refuses_the_switch_before_anything_stops() {
    let (mut host, one, _two, _archive) = host_to_update().await;
    let mut stores = release_stores();
    stores.push(ReleaseStore {
        store: "ledgers".to_owned(),
        scope: StoreScope::Unknown,
        path: "ledgers.sqlite".to_owned(),
        recording: Recording::SqliteUserVersion,
        version: 1,
        migrates_from: 1,
    });
    stores.push(ReleaseStore {
        store: "journals".to_owned(),
        scope: StoreScope::Environment,
        path: "journals.sqlite".to_owned(),
        recording: Recording::Unknown,
        version: 1,
        migrates_from: 1,
    });
    let target = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).reading(stores);
    let archive = host.scratch("archives").join("newer-kinds.tar.gz");
    target.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("ledgers") && message.contains("a scope this kr does not know"),
        "the store of an unknown scope is named: {said}"
    );
    assert!(
        message.contains("journals")
            && message.contains("a way of recording its version this kr does not know"),
        "the store of an unknown recording is named: {said}"
    );
    assert!(
        host.record()["update"].is_null(),
        "no update began: {}",
        host.record()
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert!(
        host.daemons
            .iter_mut()
            .all(|daemon| matches!(daemon.try_wait(), Ok(None))),
        "the daemon this test started was never stopped"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
}

/// KR-REQ-26.10: a store of a host's that is too old for the release switched to is named as well,
/// and so is a store whose version cannot be read: an environment whose transfer journal is at
/// version 1 against a release that migrates from 2, and one whose record of enrolments is not
/// JSON. The control, in the same environment, is the store that is in range, which is not named.
#[tokio::test(flavor = "multi_thread")]
async fn a_store_too_old_or_unreadable_is_named_and_a_store_in_range_is_not() {
    let (host, one, _two, _archive) = host_to_update().await;
    let idle = Idle::new(&host.store);
    let environment = idle.temp.environment();
    let transfers = kr_transfer::staging::StagingArea::store_path(&environment);
    std::fs::create_dir_all(transfers.parent().expect("a directory")).expect("transfers/");
    drop(
        kr_transfer::store::Store::open(&transfers, idle.temp.environment_id())
            .expect("a transfer journal"),
    );
    rusqlite::Connection::open(&transfers)
        .expect("opens")
        .execute("UPDATE schema_version SET version = 1", [])
        .expect("an earlier version, which the check reads and nothing else");
    std::fs::write(
        environment.state_dir().join("environments.json"),
        b"{ not JSON",
    )
    .expect("a record that is not JSON");

    // The release reads transfer journals from version 2, and the record of enrolments as a JSON
    // object that states its version.
    let stores: Vec<ReleaseStore> = reading_transfers_from_2();
    assert!(
        stores.iter().any(|store| store.store == "environments"),
        "the release lists the record of enrolments"
    );
    let target = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).reading(stores);
    let archive = host.scratch("archives").join("target.tar.gz");
    target.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    let named = idle.environment_id();
    assert!(
        message.contains(&format!("transfers of environment {named}"))
            && message.contains("schema version 1")
            && message.contains(&format!(
                "versions 2 to {}",
                kr_transfer::store::SCHEMA_VERSION
            )),
        "the journal that is too old is named: {said}"
    );
    assert!(
        message.contains(&format!("environments of environment {named}"))
            && message.contains("environments.json cannot be read"),
        "the record that cannot be read is named: {said}"
    );
    assert!(
        !message.contains(&format!("registry of environment {named}")),
        "the registry is at a version the release reads, so it is not named: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone()),
        "nothing was switched"
    );
}

/// KR-REQ-26.08: a control daemon whose release's manifest names a compatibility level its binary
/// does not retain does not start, and says which level. A manifest that names the levels the
/// binary retains starts, and so does one that names fewer of them: that only holds more updates
/// back.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_whose_manifest_names_a_level_it_does_not_retain_does_not_start() {
    let another = if PACKAGE_VERSION.major == 0 {
        PackageVersion::new(0, PACKAGE_VERSION.minor + 1, 0)
    } else {
        PackageVersion::new(PACKAGE_VERSION.major + 1, 0, 0)
    };
    let this = CompatibilityLevel::of(PACKAGE_VERSION);
    let retained = kr_protocol::retained::RETAINED_WORKER_LEVELS[0];

    // The refusal: a level above this build's, alone and beside the ones it retains.
    for named in [
        vec![CompatibilityLevel::of(another)],
        vec![this, retained, CompatibilityLevel::of(another)],
    ] {
        let host = Host::bare();
        let mut release = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
        release.manifest.retained_levels = named;
        host.install(&release);
        let controller = host.store.stable(Program::Controller);
        let arguments = host.daemon_arguments();
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let mut command = host.command(&controller, &arguments);
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the daemon starts");
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("it can be waited on") {
                break status;
            }
            if started.elapsed() > LIVENESS_DEADLINE {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the daemon went on running over a manifest that names a level it lacks");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(!status.success(), "{status}");
        let mut said = String::new();
        std::io::Read::read_to_string(&mut child.stderr.take().expect("its output"), &mut said)
            .expect("what it said");
        assert!(
            said.contains(&CompatibilityLevel::of(another).to_string()),
            "it names the level: {said}"
        );
    }

    // The controls: exactly what the binary retains, and fewer.
    for named in [vec![this, retained], vec![retained], vec![this]] {
        let mut host = Host::bare();
        let mut release = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
        release.manifest.retained_levels = named.clone();
        host.install(&release);
        let controller = host.store.stable(Program::Controller);
        host.start_daemon(&controller).await;
        assert_eq!(
            host.daemon_build().await,
            format!("kr-controller/{}", release.name()),
            "a manifest that names {named:?} starts"
        );
    }
}

/// KR-REQ-26.10, KR-REQ-26.08: a rollback waits, exit 9, for a live session whose level the older
/// release's daemon does not retain, as an update does, with nothing stopped.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_waits_for_a_session_the_older_release_does_not_retain() {
    let mut host = Host::bare();
    // The older release retains only the level the previous release spoke at, which its daemon
    // does retain; the session below runs at this build's own level.
    let one = Assembled::new(
        "0.1.0+aaaaaaaaaaaa",
        1,
        kr_protocol::retained::RETAINED_WORKER_LEVELS[0],
        the_root(),
    );
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let archive = host.scratch("archives").join("two.tar.gz");
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
    let (display, _) = host.new_session(&host.store.stable(Program::Kr));

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "a rollback that waits exits 9: {said}"
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(one.name().as_str())
            && message.contains(&format!("session {display} runs kr-worker/{}", two.name())),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "nothing was stopped"
    );
    host.close(&host.store.stable(Program::Kr), &display);
}

/// KR-REQ-26.10: a rollback needs a release to go back to, and it is refused, usage, when there is
/// none recorded, when the one named is not in the store, when it is not older than the current
/// release, and when it is the current release.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_needs_an_older_release_in_the_store() {
    let (host, one, two, archive) = host_to_update().await;
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "no earlier release is recorded: {said}"
    );
    let (output, said) =
        host.kr_json(&["host", "rollback", "--to", "0.9.0+eeeeeeeeeeee", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a release the store does not keep: {said}"
    );
    let (output, said) = host.kr_json(&["host", "rollback", "--to", "not a release", "--json"]);
    assert_eq!(output.status.code(), Some(2), "not a release name: {said}");
    let (output, said) = host.kr_json(&["host", "rollback", "--to", one.name().as_str(), "--json"]);
    assert_eq!(output.status.code(), Some(2), "the current release: {said}");
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(output.status.success(), "{said}");
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(output.status.success(), "{said}");
    // Now the newer release is the one recorded as before the last switch, and it is not older.
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a rollback does not go forward: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    let _ = two;
}

/// KR-REQ-26.10: going back does not bring back a key the channel retired. Release two carries the
/// next version of the channel's root, which names a new targets key in place of the first. An
/// update that waits trusts nothing it has not switched to, so it can be run again once what held
/// it has gone; once the host has switched to release two, a rollback to release one, whose own
/// root is the first, still trusts the second: an archive signed with the retired key is refused
/// and one signed with the new key is taken. The archive release two came in, which only the retired
/// key signed, is refused too.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_does_not_bring_back_a_key_the_channel_retired() {
    let mut host = Host::bare();
    let rotated = channel_root_naming(2, &keys().root, &keys().next_targets, &[&keys().root]);
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    // It retains only the level before the session's below, so its update waits for the session.
    let two = Assembled::new(
        "0.2.0+bbbbbbbbbbbb",
        2,
        kr_protocol::retained::RETAINED_WORKER_LEVELS[0],
        &rotated,
    );
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let (display, session) = host.new_session(&host.store.stable(Program::Kr));
    let session_worker = host.worker_process(session);
    let scratch = host.scratch("archives");
    let archive_two = scratch.join("two.tar.gz");
    two.archive(&archive_two);
    let update = |archive: &Path| {
        host.kr_json(&[
            "host",
            "update",
            "--archive",
            &archive.display().to_string(),
            "--json",
        ])
    };

    let (output, said) = update(&archive_two);
    assert_eq!(
        output.status.code(),
        Some(9),
        "waits for the session: {said}"
    );
    assert!(
        host.record()["trusted_root"].is_null(),
        "an update that waits has switched to nothing, so it trusts nothing new: {}",
        host.record()
    );
    host.close(&host.store.stable(Program::Kr), &display);
    host.worker_ended(&session_worker).await;
    // The session has gone; the same archive is taken now, though its manifest is signed by the key
    // the first root names and the root it carries names another.
    let (output, said) = update(&archive_two);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.record()["trusted_root"]["signed"]["version"],
        2,
        "the switch settled, so the host trusts the second root: {}",
        host.record()
    );

    // The root the host recorded is damaged: a rollback would settle on the older root of the
    // release it goes back to, and so it is refused before anything is switched.
    let kept = std::fs::read(host.store.record()).expect("the record");
    let mut damaged: Value = serde_json::from_slice(&kept).expect("JSON");
    for signature in damaged["trusted_root"]["signatures"]
        .as_array_mut()
        .expect("the recorded root is signed")
    {
        let sig = signature["sig"].as_str().expect("a signature").to_owned();
        let first = if sig.starts_with('0') { '1' } else { '0' };
        signature["sig"] = Value::String(format!("{first}{}", &sig[1..]));
    }
    std::fs::write(host.store.record(), damaged.to_string()).expect("damaged");
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a root the host cannot establish stops the rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("this host kept is not signed by the root keys it names"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone()),
        "nothing was switched"
    );
    assert!(
        host.record()["update"].is_null(),
        "and no update is left recorded: {}",
        host.record()
    );
    std::fs::write(host.store.record(), &kept).expect("restored");

    // The root of the release to go back to is damaged: refused before anything is switched too.
    {
        use std::os::unix::fs::PermissionsExt as _;

        let root_file = host
            .store
            .release_directory(one.name())
            .join("share")
            .join("update-root.json");
        let share = root_file.parent().expect("a directory");
        let (file_mode, directory_mode) = (
            std::fs::metadata(&root_file)
                .expect("the root")
                .permissions(),
            std::fs::metadata(share)
                .expect("the directory")
                .permissions(),
        );
        let original = std::fs::read(&root_file).expect("the root");
        std::fs::set_permissions(share, std::fs::Permissions::from_mode(0o755)).expect("opened");
        std::fs::set_permissions(&root_file, std::fs::Permissions::from_mode(0o644))
            .expect("opened");
        std::fs::write(&root_file, b"{ not a root").expect("damaged");
        let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "a root of the target that cannot be read stops the rollback: {said} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            said["message"]
                .as_str()
                .unwrap_or_default()
                .contains("update channel's root"),
            "{said}"
        );
        assert_eq!(
            host.store.current().expect("reads"),
            Some(two.name().clone()),
            "nothing was switched"
        );
        assert!(host.record()["update"].is_null(), "{}", host.record());
        std::fs::write(&root_file, &original).expect("restored");
        std::fs::set_permissions(&root_file, file_mode).expect("closed");
        std::fs::set_permissions(share, directory_mode).expect("closed");
    }

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.record()["trusted_root"]["signed"]["version"],
        2,
        "going back does not give the second root up"
    );

    // The release just left comes in an archive only the retired key signed, so it is not taken
    // again from that archive.
    let (output, said) = update(&archive_two);
    assert_eq!(
        output.status.code(),
        Some(1),
        "the archive of the release left is signed by the retired key and is refused: {said}"
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not signed by the release keys"),
        "and it is refused for the signature: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );

    // A later release of the second root, signed with the key that root retired: refused.
    let three = Assembled::new(
        "0.3.0+cccccccccccc",
        3,
        CompatibilityLevel::of(PACKAGE_VERSION),
        &rotated,
    );
    let with_retired_key = scratch.join("three-retired.tar.gz");
    three.archive_signed(&with_retired_key, &keys().targets);
    let (output, said) = update(&with_retired_key);
    assert_eq!(
        output.status.code(),
        Some(1),
        "an archive signed with the retired key is refused: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    // The control: the same release signed with the key the second root names is taken.
    let with_new_key = scratch.join("three-new.tar.gz");
    three.archive_signed(&with_new_key, &keys().next_targets);
    let (output, said) = update(&with_new_key);
    assert!(
        output.status.success(),
        "an archive signed with the new key is taken: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(three.name().clone())
    );
}

/// KR-REQ-26.10: a switch an earlier run left after it happened settles on the root that run decided
/// on before it began, and reads no release to do so. An update to release two, which carries the
/// second root, switches and then stops because its daemon does not start; the transaction it
/// leaves holds the second root, and the root file of release two is gone when the next run settles
/// it. A rollback then goes on, and the host still trusts the second root: going back did not give
/// up the trust the switch earned, and the key the second root retired stays retired.
#[tokio::test(flavor = "multi_thread")]
async fn a_switch_left_after_it_happened_settles_on_the_root_decided_before_it() {
    use std::os::unix::fs::PermissionsExt as _;

    let mut host = Host::bare();
    let rotated = channel_root_naming(2, &keys().root, &keys().next_targets, &[&keys().root]);
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::new(
        "0.2.0+bbbbbbbbbbbb",
        2,
        CompatibilityLevel::of(PACKAGE_VERSION),
        &rotated,
    );
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);

    let (output, said) = host.update_whose_daemons_fail(&archive.display().to_string());
    assert_eq!(
        output.status.code(),
        Some(1),
        "the daemon does not start from the new release: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let record = host.record();
    assert_eq!(record["update"]["state"], "switched", "{record}");
    assert_eq!(
        record["update"]["trusted_root"]["signed"]["version"], 2,
        "the transaction holds the root decided before the switch: {record}"
    );
    assert!(
        record["trusted_root"].is_null(),
        "and nothing is trusted on it yet: {record}"
    );
    // Release two's own copy of that root is gone by the time the next run settles it.
    let share = host.store.release_directory(two.name()).join("share");
    std::fs::set_permissions(&share, std::fs::Permissions::from_mode(0o755)).expect("opened");
    let root_file = share.join("update-root.json");
    std::fs::set_permissions(&root_file, std::fs::Permissions::from_mode(0o644)).expect("opened");
    std::fs::remove_file(&root_file).expect("removed");

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], two.name().as_str(), "{record}");
    assert_eq!(
        record["trusted_root"]["signed"]["version"], 2,
        "the second root is the root the host trusts: {record}"
    );
}

/// KR-REQ-26.10: a rollback to a release whose update channel root has the version of the root the
/// host trusts and is another document is refused: the host trusts neither, nothing is switched or
/// recorded, and the root it recorded stays what it was. The control, in the same store, is the
/// rollback to a release whose root is the first, which goes back.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_to_a_release_with_another_root_of_the_trusted_version_is_refused() {
    let mut host = Host::bare();
    let level = CompatibilityLevel::of(PACKAGE_VERSION);
    let trusted = channel_root_naming(2, &keys().root, &keys().next_targets, &[&keys().root]);
    let other = channel_root_naming(2, &keys().root, &keys().targets, &[&keys().root]);
    assert_ne!(trusted, other, "two roots of one version that differ");
    let one = Assembled::new("0.2.0+aaaaaaaaaaaa", 2, level, the_root());
    let elder = Assembled::new("0.1.0+eeeeeeeeeeee", 1, level, &other);
    let two = Assembled::new("0.3.0+bbbbbbbbbbbb", 3, level, &trusted);
    host.install(&one);
    let started_through_current = host.store.stable(Program::Controller);
    host.start_daemon(&started_through_current).await;
    let archive = host.scratch("archives").join("two.tar.gz");
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
    let before = host.record();
    assert_eq!(before["trusted_root"]["signed"]["version"], 2, "{before}");
    // An older release, put in the store now that the update has collected what nothing needs,
    // whose root is another document of the version the host trusts.
    host.put(&elder);

    let (output, said) =
        host.kr_json(&["host", "rollback", "--to", elder.name().as_str(), "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("trusts neither"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone()),
        "nothing was switched"
    );
    let after = host.record();
    assert!(after["update"].is_null(), "{after}");
    assert_eq!(
        after["trusted_root"], before["trusted_root"],
        "and the root the host trusts is what it was"
    );

    // The control: the release before it, whose root is the first, goes back.
    let (output, said) = host.kr_json(&["host", "rollback", "--to", one.name().as_str(), "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// KR-REQ-26.10: `kr host terminal --clear` changes the saved preference while holding it, as the
/// daemon's stamping of its format does, and an environment that has no state directory yet has
/// nothing to clear and needs none held: with the preference held by another change the command is
/// refused and leaves the file; once it is let go the command clears it.
#[tokio::test(flavor = "multi_thread")]
async fn kr_host_terminal_clear_holds_the_preference_and_needs_no_directory_that_is_not_there() {
    use kr_shell_integration::host::terminal::{
        PREFERENCE_FILE, hold_preference, preference_document,
    };

    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let clear = |host: &Host| host.kr_json(&["host", "terminal", "--clear", "--json"]);
    let state_dir = host.tree.environment().state_dir().to_path_buf();
    std::fs::remove_dir_all(&state_dir).expect("an environment with no state directory yet");
    let (output, said) = clear(&host);
    assert!(
        output.status.success(),
        "an environment that has not run has nothing to clear: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let file = state_dir.join(PREFERENCE_FILE);
    kr_ipc::paths::write_owner_only_file(&file, preference_document("iterm2").as_bytes())
        .expect("a preference");
    let held = hold_preference(&state_dir).expect("held");
    let (output, said) = clear(&host);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a change of the preference waits for the one under way and is refused: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("could not hold"),
        "{said}"
    );
    assert!(file.exists(), "and the preference is left");
    drop(held);
    let (output, said) = clear(&host);
    assert!(
        output.status.success(),
        "kr host terminal --clear: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !file.exists(),
        "and once it is let go the command clears it"
    );
}

/// A named pipe left at the saved terminal preference's name does not hold `kr host terminal`: the
/// preference is read as a regular file only, and a pipe reads as no preference. A program that read
/// it would wait for a writer for ever.
#[tokio::test(flavor = "multi_thread")]
async fn a_pipe_where_the_saved_terminal_preference_belongs_does_not_hold_kr() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let pipe = host
        .tree
        .environment()
        .state_dir()
        .join(kr_shell_integration::host::terminal::PREFERENCE_FILE);
    let made = Command::new("mkfifo")
        .arg(&pipe)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "a pipe is made");
    let child = host
        .command(
            &host.store.stable(Program::Kr),
            &["host", "terminal", "--json"],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kr runs");
    // Ended by the test and not left waiting, so that a kr which does wait fails this case.
    let output = finish_within(child, Duration::from_secs(30));
    let said: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    assert!(
        output.status.success(),
        "kr host terminal: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["preferred"].is_null(),
        "a pipe is no preference: {said}"
    );
}

/* -------------------------------------------------------------------------------------------- */
/* Going back from an update whose daemon did not start                                          */
/* -------------------------------------------------------------------------------------------- */

/// How many times a release whose daemon cannot start was started, by the lines it wrote in `log`.
fn starts_in(log: &Path) -> usize {
    std::fs::read_to_string(log).map_or(0, |text| text.lines().count())
}

/// KR-REQ-26.10: `kr host rollback` goes back from an update that switched and whose daemon did not
/// start, which is the case a rollback exists for: it does not start the daemon of the release that
/// failed again, it goes to the release the update began from and starts the daemon from there, and
/// a registry the failed release never opened is not brought forward on the way.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_rescues_an_update_whose_daemon_did_not_start() {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).whose_daemon_cannot_start(&log);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
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
        Some(1),
        "the update's daemon cannot start: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(host.record()["update"]["state"], "switched");
    assert_eq!(starts_in(&log), 1, "the update tried the daemon once");
    // An environment whose daemon has not run since an earlier schema: a rollback leaves its
    // registry as it is, and still classes it.
    let idle = Idle::new(&host.store).shaped_as(6);

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["source"], two.name().as_str(), "{said}");
    assert_eq!(said["target"], one.name().as_str(), "{said}");
    assert_eq!(said["carried"], serde_json::json!([]), "{said}");
    assert_eq!(idle.version(), 6, "the registry was not brought forward");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon serves again, from the release the update began from"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], two.name().as_str(), "{record}");
    assert_eq!(
        starts_in(&log),
        1,
        "the daemon of the release that failed was not started again"
    );
}

/// KR-REQ-26.10: a rescue is held to the same rule as any switch: a store the older release cannot read
/// as it is refuses it, naming the store, and the failed update stays recorded for an update to a
/// release that fixes it, or for the rescue once the store has been put right.
#[tokio::test(flavor = "multi_thread")]
async fn a_rescue_the_older_release_cannot_read_the_stores_for_is_refused_and_the_failed_update_stays()
 {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    // The older release reads transfer journals from version 2.
    let stores = reading_transfers_from_2();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).reading(stores);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).whose_daemon_cannot_start(&log);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(1), "{said}");
    // The failed release's daemon migrated a store before it ended, as far as the older release can
    // tell: the transfer journal is below the lowest version the older release reads.
    let journal = kr_transfer::staging::StagingArea::store_path(&host.tree.environment());
    let set = |version: i64| {
        rusqlite::Connection::open(&journal)
            .expect("opens")
            .execute("UPDATE schema_version SET version = ?1", [version])
            .expect("a version");
    };
    set(1);

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains("transfers") && message.contains("schema version 1"),
        "the store is named: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone()),
        "nothing was switched"
    );
    assert_eq!(
        host.record()["update"]["state"],
        "switched",
        "the failed update is still recorded"
    );
    assert_eq!(
        starts_in(&log),
        1,
        "and the daemon that failed was not started again"
    );

    // The store put right, the same command goes back.
    set(kr_transfer::store::SCHEMA_VERSION);
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
}

/// KR-REQ-26.10: an update goes on past a failed one, so that a person whose update left a daemon
/// that does not start can update to a release that fixes it: the daemon is started from the new
/// release, the release that failed is the previous one, and nothing is left recorded.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_goes_on_past_a_failed_one() {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).whose_daemon_cannot_start(&log);
    let three = Assembled::at_this_level("0.3.0+cccccccccccc", 3);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let scratch = host.scratch("archives");
    let archive_two = scratch.join("two.tar.gz");
    two.archive(&archive_two);
    let archive_three = scratch.join("three.tar.gz");
    three.archive(&archive_three);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive_two.display().to_string(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(1), "{said}");

    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive_three.display().to_string(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["target"], three.name().as_str(), "{said}");
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", three.name()),
        "the daemon the failed update stopped is started from the release that fixes it"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], two.name().as_str(), "{record}");
    assert_eq!(
        starts_in(&log),
        1,
        "the daemon of the release that failed was not started again on the way"
    );
}

/// KR-REQ-26.10: an update to a release that fixes the fault is not held by a daemon of the release that
/// failed which holds its environment and answers nothing: the archive is staged and checked before
/// any daemon is started, so the run names the process, starts nothing, and once the person has
/// stopped it the same update goes on.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_to_a_fixed_release_is_not_held_by_a_daemon_of_the_one_that_failed() {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).whose_daemon_cannot_start(&log);
    let three = Assembled::at_this_level("0.3.0+cccccccccccc", 3);
    host.install(&one);
    host.put(&two);
    host.record_a_switched_update(&one, &two);
    host.store
        .record_roots(
            host.tree.paths().runtime_root(),
            host.tree.paths().state_root(),
        )
        .expect("records the roots");
    let archive = host.scratch("archives").join("three.tar.gz");
    three.archive(&archive);
    let archive = archive.display().to_string();
    // A daemon of the release that failed that holds the environment and listens to nothing: this
    // process stands in for it.
    let holding = kr_controller::singleton::SingletonLock::acquire(
        &host.tree.environment().singleton_lock(),
        host.tree.environment_id(),
    )
    .expect("holds the environment");

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&format!("kill {}", std::process::id())),
        "the process that holds the environment is named: {said}"
    );
    assert_eq!(
        starts_in(&log),
        0,
        "nothing of the release that failed was started"
    );
    assert_eq!(host.record()["update"]["state"], "switched");

    drop(holding);
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", three.name())
    );
    assert_eq!(starts_in(&log), 0);
}

/// KR-REQ-26.10: after three updates that each left a daemon that does not start, a rollback goes back to
/// the last release whose daemon ran, which is the release the first of them began from and not the
/// release before the current one, and starts none of the daemons that failed: each was tried once by
/// its own update, and the last once more by an archive of the release now current, which names that
/// release too.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_after_three_failed_updates_goes_back_to_the_last_release_that_ran() {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let failing = |name: &str, sequence: u64| {
        Assembled::at_this_level(name, sequence).whose_daemon_cannot_start(&log)
    };
    let (two, three, four) = (
        failing("0.2.0+bbbbbbbbbbbb", 2),
        failing("0.3.0+cccccccccccc", 3),
        failing("0.4.0+dddddddddddd", 4),
    );
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let scratch = host.scratch("archives");
    let mut last = Value::Null;
    for (release, name) in [
        (&two, "two.tar.gz"),
        (&three, "three.tar.gz"),
        (&four, "four.tar.gz"),
    ] {
        let archive = scratch.join(name);
        release.archive(&archive);
        let (output, said) = host.kr_json(&[
            "host",
            "update",
            "--archive",
            &archive.display().to_string(),
            "--json",
        ]);
        assert_eq!(output.status.code(), Some(1), "{said}");
        last = said;
    }
    let names_one = |said: &Value| {
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&format!("kr host rollback goes back to {}", one.name()))
    };
    assert!(
        names_one(&last),
        "the failure names the release a rollback goes back to: {last}"
    );
    assert_eq!(starts_in(&log), 3);

    // An archive of the release now current, whose daemon still cannot start, names it too, and
    // tries the daemons the chain owes once.
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &scratch.join("four.tar.gz").display().to_string(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        names_one(&said),
        "an archive of the current release names it too: {said}"
    );
    assert_eq!(starts_in(&log), 4);

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["target"], one.name().as_str(), "{said}");
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    assert_eq!(
        starts_in(&log),
        4,
        "none of the daemons that failed was started again by the rollback"
    );
}

/// KR-REQ-26.10: a failed update does not name a release a rollback would refuse. A rollback to
/// release two whose daemon did not start, and then an update to release three that fails, leave a
/// rollback without `--to` nowhere to go: the release it would take, four, is newer than three.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_update_does_not_name_a_release_a_rollback_would_refuse() {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let held = host.tree.root().join("held");
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2)
        .whose_daemon_cannot_start_while(&held, &log);
    let three = Assembled::at_this_level("0.3.0+cccccccccccc", 3).whose_daemon_cannot_start(&log);
    let four = Assembled::at_this_level("0.4.0+dddddddddddd", 4);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let scratch = host.scratch("archives");
    let update = |release: &Assembled, name: &str| {
        let archive = scratch.join(name);
        release.archive(&archive);
        host.kr_json(&[
            "host",
            "update",
            "--archive",
            &archive.display().to_string(),
            "--json",
        ])
    };
    for (release, name) in [(&two, "two.tar.gz"), (&four, "four.tar.gz")] {
        let (output, said) = update(release, name);
        assert!(output.status.success(), "{said}");
    }
    // The rollback to two fails: its daemon cannot start.
    std::fs::write(&held, b"").expect("the daemon is held");
    let (output, said) = host.kr_json(&["host", "rollback", "--to", two.name().as_str(), "--json"]);
    assert_eq!(output.status.code(), Some(1), "{said}");
    // The update to three fails in its turn.
    let (output, said) = update(&three, "three.tar.gz");
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        !said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("kr host rollback goes back to"),
        "the release a rollback would take, four, is newer than three: {said}"
    );
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(output.status.code(), Some(2), "{said}");
}

/// KR-REQ-26.10: a rollback without `--to` goes back to the last release whose daemon ran, and an update
/// that goes on past a chain does not change which that is. The update from one to two fails, a rollback
/// to one fails, and the update to three switches and fails: the failure names one, which ran, and
/// not two, whose daemon never did, and a rollback without `--to` goes there.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_after_a_chain_leaves_the_release_that_ran_as_the_one_to_go_back_to() {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let held = host.tree.root().join("held");
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1)
        .whose_daemon_cannot_start_while(&held, &log);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2)
        .whose_daemon_cannot_start_while(&held, &log);
    let three = Assembled::at_this_level("0.3.0+cccccccccccc", 3)
        .whose_daemon_cannot_start_while(&held, &log);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let scratch = host.scratch("archives");
    let update = |release: &Assembled, name: &str| {
        let archive = scratch.join(name);
        release.archive(&archive);
        host.kr_json(&[
            "host",
            "update",
            "--archive",
            &archive.display().to_string(),
            "--json",
        ])
    };
    std::fs::write(&held, b"").expect("the daemons are held");
    let (output, said) = update(&two, "two.tar.gz");
    assert_eq!(output.status.code(), Some(1), "{said}");
    let (output, said) = host.kr_json(&["host", "rollback", "--to", one.name().as_str(), "--json"]);
    assert_eq!(output.status.code(), Some(1), "{said}");
    let (output, said) = update(&three, "three.tar.gz");
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&format!("kr host rollback goes back to {}", one.name())),
        "the failure names the release that ran: {said}"
    );

    std::fs::remove_file(&held).expect("the daemons are let go");
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["target"], one.name().as_str(), "{said}");
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
}

/// KR-REQ-26.10: an update after a chain of failed ones that stops before its switch leaves the chain as it
/// was, with the release it began from to go back to. The updates to two and to three both fail to start a
/// daemon; an update to four that the stores refuse after it has recorded itself ends without a switch; and a
/// rollback without `--to` then goes to one, which ran, and not to two, whose daemon never did.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_that_stops_before_its_switch_leaves_the_start_of_the_chain_to_go_back_to() {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let held = host.tree.root().join("held");
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1)
        .whose_daemon_cannot_start_while(&held, &log);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2)
        .whose_daemon_cannot_start_while(&held, &log);
    let three = Assembled::at_this_level("0.3.0+cccccccccccc", 3)
        .whose_daemon_cannot_start_while(&held, &log);
    let four =
        Assembled::at_this_level("0.4.0+dddddddddddd", 4).reading(reading_transfers_from_2());
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let scratch = host.scratch("archives");
    let update = |release: &Assembled, name: &str| {
        let archive = scratch.join(name);
        release.archive(&archive);
        host.kr_json(&[
            "host",
            "update",
            "--archive",
            &archive.display().to_string(),
            "--json",
        ])
    };
    std::fs::write(&held, b"").expect("the daemons are held");
    for (release, name) in [(&two, "two.tar.gz"), (&three, "three.tar.gz")] {
        let (output, said) = update(release, name);
        assert_eq!(output.status.code(), Some(1), "{said}");
    }
    let journal = kr_transfer::staging::StagingArea::store_path(&host.tree.environment());
    rusqlite::Connection::open(&journal)
        .expect("opens")
        .execute("UPDATE schema_version SET version = 1", [])
        .expect("an earlier version");
    let (output, said) = update(&four, "four.tar.gz");
    assert_eq!(output.status.code(), Some(1), "{said}");

    std::fs::remove_file(&held).expect("the daemons are let go");
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["target"], one.name().as_str(), "{said}");
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
}

/// KR-REQ-26.10: a chain of failed updates that comes back to the release it began from still has a
/// release to go back to, however many switches stop before they happen. A rollback from three to one
/// and an update from one to three both fail to start a daemon; an update to four that the stores
/// refuse leaves them recorded; and a rollback without `--to` then goes to one, which ran, and not to
/// three, which is already current.
#[tokio::test(flavor = "multi_thread")]
async fn a_chain_that_comes_back_to_its_start_still_goes_back_to_the_release_that_ran() {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let held = host.tree.root().join("held");
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1)
        .whose_daemon_cannot_start_while(&held, &log);
    let three = Assembled::at_this_level("0.3.0+cccccccccccc", 3)
        .whose_daemon_cannot_start_while(&held, &log);
    let four =
        Assembled::at_this_level("0.4.0+dddddddddddd", 4).reading(reading_transfers_from_2());
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let scratch = host.scratch("archives");
    let update = |release: &Assembled, name: &str| {
        let archive = scratch.join(name);
        release.archive(&archive);
        host.kr_json(&[
            "host",
            "update",
            "--archive",
            &archive.display().to_string(),
            "--json",
        ])
    };
    let (output, said) = update(&three, "three.tar.gz");
    assert!(output.status.success(), "{said}");

    // Neither daemon can start now: not one's, which the rollback goes to, and not three's, which
    // the update after it goes back to.
    std::fs::write(&held, b"").expect("the daemons are held");
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(output.status.code(), Some(1), "{said}");
    let (output, said) = update(&three, "three.tar.gz");
    assert_eq!(output.status.code(), Some(1), "{said}");

    // An update that the stores refuse after it has recorded itself leaves both recorded.
    let journal = kr_transfer::staging::StagingArea::store_path(&host.tree.environment());
    rusqlite::Connection::open(&journal)
        .expect("opens")
        .execute("UPDATE schema_version SET version = 1", [])
        .expect("an earlier version");
    let (output, said) = update(&four, "four.tar.gz");
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(three.name().clone())
    );

    std::fs::remove_file(&held).expect("the daemons are let go");
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["target"], one.name().as_str(), "{said}");
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
}

/// KR-REQ-26.10: a rollback goes on past a rescue whose own daemon did not start, to an older release,
/// without starting the daemon of the release it leaves: the rescue is a switch that happened whose
/// daemon is owed, like any other.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_goes_on_past_a_rescue_whose_own_daemon_did_not_start() {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let zero = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let one = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).whose_daemon_cannot_start(&log);
    let two = Assembled::at_this_level("0.3.0+cccccccccccc", 3).whose_daemon_cannot_start(&log);
    host.install(&zero);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let scratch = host.scratch("archives");
    for (release, name) in [(&one, "one.tar.gz"), (&two, "two.tar.gz")] {
        let archive = scratch.join(name);
        release.archive(&archive);
        let (output, said) = host.kr_json(&[
            "host",
            "update",
            "--archive",
            &archive.display().to_string(),
            "--json",
        ]);
        assert_eq!(output.status.code(), Some(1), "{said}");
    }
    // The rescue to the release before, whose own daemon cannot start either. A rollback without
    // `--to` goes on to the release that ran, which is older than this one, and the failure says so.
    let (output, said) = host.kr_json(&["host", "rollback", "--to", one.name().as_str(), "--json"]);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&format!("kr host rollback goes back to {}", zero.name())),
        "the failure names the release that ran: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(starts_in(&log), 3);

    // A rollback to the release that ran goes on past it, and starts nothing of the two that failed.
    let (output, said) =
        host.kr_json(&["host", "rollback", "--to", zero.name().as_str(), "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", zero.name())
    );
    assert_eq!(
        starts_in(&log),
        3,
        "the daemon of the release left was not started again"
    );
}

/// KR-REQ-26.10: an update that failed in one of two environments is rescued in both: the daemon
/// that runs is handed over, as an update hands one over, and the one that does not is started from the
/// older release, from what the failed update recorded of it.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_update_in_one_of_two_environments_is_rescued_in_both() {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let stores = reading_transfers_from_2();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).reading(stores);
    let controller_state = host.tree.paths().state_root().to_path_buf();
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2)
        .whose_daemon_cannot_start_in(&controller_state, &log);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let second = Second::start(&controller).await;
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert_eq!(
        second.build().await,
        format!("kr-controller/{}", two.name()),
        "the second environment's daemon started from the new release"
    );

    // A rescue the stores refuse stops the daemon that runs and starts it again from the release
    // still current, and leaves the failed update recorded owing both daemons, the one that runs
    // with the newer record it made of it.
    let journal = kr_transfer::staging::StagingArea::store_path(&host.tree.environment());
    let set = |version: i64| {
        rusqlite::Connection::open(&journal)
            .expect("opens")
            .execute("UPDATE schema_version SET version = ?1", [version])
            .expect("a version");
    };
    set(1);
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert_eq!(
        second.build().await,
        format!("kr-controller/{}", two.name()),
        "the daemon the rescue stopped is started again from the release still current"
    );
    let owed: std::collections::BTreeSet<String> = host.record()["update"]["restarts"]
        .as_array()
        .expect("the restarts")
        .iter()
        .map(|restart| {
            restart["environment"]
                .as_str()
                .expect("an environment")
                .to_owned()
        })
        .collect();
    assert_eq!(
        owed,
        [
            host.tree.environment_id().to_string(),
            second.tree.environment_id().to_string()
        ]
        .into(),
        "the failed update is recorded owing both daemons: {}",
        host.record()
    );
    set(kr_transfer::store::SCHEMA_VERSION);

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon that did not start is started from the older release"
    );
    assert_eq!(
        second.build().await,
        format!("kr-controller/{}", one.name()),
        "and the one that ran was handed over and started from it"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], two.name().as_str(), "{record}");
    assert_eq!(starts_in(&log), 1, "the failed daemon was tried once");
}

/// KR-REQ-26.10: a rescue the stores refuse, whose undo cannot start again the daemon it stopped,
/// leaves the failed update recorded and nothing switched. The next rescue, once the stores are right,
/// goes back to the older release and starts both daemons from it, while the daemon of the release
/// that failed stays unable to start.
#[tokio::test(flavor = "multi_thread")]
async fn a_rescue_whose_undo_cannot_start_the_daemon_again_is_finished_by_the_next_rescue() {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let held = host.tree.root().join("held");
    let stores = reading_transfers_from_2();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).reading(stores);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2)
        .whose_daemon_cannot_start_while(&held, &log);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);
    let archive_path = archive.display().to_string();
    let update = ["host", "update", "--archive", &archive_path, "--json"];

    // The update's daemon cannot start: the failed update is recorded, and no daemon runs.
    std::fs::write(&held, b"").expect("the daemon is held");
    let (output, said) = host.kr_json(&update);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert_eq!(starts_in(&log), 1, "the update tried the daemon once");
    // A daemon of the release now current runs in another environment, once it can start.
    std::fs::remove_file(&held).expect("the daemon is let go");
    let second = Second::start(&host.store.stable(Program::Controller)).await;
    assert_eq!(
        second.build().await,
        format!("kr-controller/{}", two.name())
    );

    // A rescue the stores refuse stops that daemon, and cannot start it again from the release still
    // current. Nothing is switched, and the failed update stays recorded under the rescue.
    std::fs::write(&held, b"").expect("the daemon is held");
    let journal = kr_transfer::staging::StagingArea::store_path(&host.tree.environment());
    let set = |version: i64| {
        rusqlite::Connection::open(&journal)
            .expect("opens")
            .execute("UPDATE schema_version SET version = ?1", [version])
            .expect("a version");
    };
    set(1);
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        !second.answers().await,
        "the daemon the rescue stopped is not serving"
    );
    assert_eq!(starts_in(&log), 2, "the undo tried it once");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
    let record = host.record();
    assert_eq!(record["update"]["target"], one.name().as_str(), "{record}");
    assert_eq!(
        record["update"]["abandoned"]["target"],
        two.name().as_str(),
        "{record}"
    );

    // The stores put right, the next rescue starts what both owe from the older release. The daemon
    // of the release that failed is still held: the rescue has no use for it.
    set(kr_transfer::store::SCHEMA_VERSION);
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon the update could not start is started from the older release"
    );
    assert_eq!(
        second.build().await,
        format!("kr-controller/{}", one.name()),
        "and the one the first rescue could not start again"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], two.name().as_str(), "{record}");
    assert_eq!(
        starts_in(&log),
        2,
        "nothing of the release that failed was started again"
    );
}

/// KR-REQ-26.10: an update that goes on past a failed one and fails in its turn leaves both owing, as
/// one record, and an update after them starts the daemon each owed from the release that fixes them:
/// a chain of failed updates is never more than the daemons owed and the root that was recorded.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_goes_on_past_two_failed_ones() {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).whose_daemon_cannot_start(&log);
    let three = Assembled::at_this_level("0.3.0+cccccccccccc", 3).whose_daemon_cannot_start(&log);
    let four = Assembled::at_this_level("0.4.0+dddddddddddd", 4);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let scratch = host.scratch("archives");
    let update = |release: &Assembled, name: &str| {
        let archive = scratch.join(name);
        release.archive(&archive);
        host.kr_json(&[
            "host",
            "update",
            "--archive",
            &archive.display().to_string(),
            "--json",
        ])
    };
    let (output, said) = update(&two, "two.tar.gz");
    assert_eq!(output.status.code(), Some(1), "{said}");
    let (output, said) = update(&three, "three.tar.gz");
    assert_eq!(
        output.status.code(),
        Some(1),
        "the update goes on past the first, switches, and its daemon cannot start: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(three.name().clone())
    );
    let record = host.record();
    assert_eq!(
        record["update"]["abandoned"]["source"],
        one.name().as_str(),
        "what is owed is one record, from the release whose daemon ran: {record}"
    );

    let (output, said) = update(&four, "four.tar.gz");
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", four.name()),
        "the daemon the first update stopped is started from the release that fixes both"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], three.name().as_str(), "{record}");
}

/// KR-REQ-26.10: a rescue that stopped after its switch is finished by the next run, which starts the
/// daemons it and the update it went on past owed, from the older release, and settles it.
#[tokio::test(flavor = "multi_thread")]
async fn a_rescue_that_stopped_after_its_switch_is_finished_by_the_next_run() {
    let host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    host.put(&two);
    // The rescue from two back to one switched, and stopped before it started the daemon the update
    // to two had stopped: the record states the rescue, that update it went on past, and no daemon
    // running.
    host.write_record(&serde_json::json!({
        "format": 2,
        "previous": null,
        "staged": two.name().as_str(),
        "update": {
            "source": two.name().as_str(),
            "target": one.name().as_str(),
            "state": "handing_over",
            "restarts": [],
            "abandoned": {
                "source": one.name().as_str(),
                "target": two.name().as_str(),
                "restarts": [host.restart()],
            },
        },
    }));
    let archive = host.scratch("archives").join("one.tar.gz");
    one.archive(&archive);
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
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon owed is started from the release current names"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], two.name().as_str(), "{record}");
}

/// KR-REQ-26.10: a rescue that stopped before its switch is the failed update again: the next
/// rollback goes back to the release that update began from, which is not the release before it, and
/// the daemon is started from there; of an environment both the rescue and that update recorded, the
/// rescue's record, which is the newer, is the one that is started.
#[tokio::test(flavor = "multi_thread")]
async fn a_rescue_that_stopped_before_its_switch_is_the_failed_update_again() {
    let host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    host.put(&two);
    host.switch(two.name());
    // The failed update recorded the daemon so that it cannot be started; the rescue, which stopped
    // after it recorded the daemon of its own, recorded it so that it can.
    let mut unstartable = host.restart();
    unstartable["start"]["arguments"]["arguments"] = serde_json::json!(["--no-such-argument"]);
    host.write_record(&serde_json::json!({
        "format": 2,
        "previous": null,
        "staged": two.name().as_str(),
        "update": {
            "source": two.name().as_str(),
            "target": one.name().as_str(),
            "state": "handing_over",
            "restarts": [host.restart()],
            "abandoned": {
                "source": one.name().as_str(),
                "target": two.name().as_str(),
                "restarts": [unstartable],
            },
        },
    }));
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(said["target"], one.name().as_str(), "{said}");
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon is started from the release the failed update began from, as the newer record says"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");
    assert_eq!(record["previous"], two.name().as_str(), "{record}");
}

/// KR-REQ-26.10: the root a failed update recorded is kept by the rescue that goes back past it, even
/// when the root file of the failed release is gone: the host never trusts an older root than the one
/// it recorded.
#[tokio::test(flavor = "multi_thread")]
async fn a_rescue_keeps_the_root_the_failed_update_recorded() {
    use std::os::unix::fs::PermissionsExt as _;

    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let rotated = channel_root_naming(2, &keys().root, &keys().next_targets, &[&keys().root]);
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::new(
        "0.2.0+bbbbbbbbbbbb",
        2,
        CompatibilityLevel::of(PACKAGE_VERSION),
        &rotated,
    )
    .whose_daemon_cannot_start(&log);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert_eq!(
        host.record()["update"]["trusted_root"]["signed"]["version"],
        2,
        "the failed update recorded the root it was to settle on: {}",
        host.record()
    );
    // The root file of the release that failed is gone.
    let share = host.store.release_directory(two.name()).join("share");
    std::fs::set_permissions(&share, std::fs::Permissions::from_mode(0o755)).expect("opened");
    let root_file = share.join("update-root.json");
    std::fs::set_permissions(&root_file, std::fs::Permissions::from_mode(0o644)).expect("opened");
    std::fs::remove_file(&root_file).expect("removed");

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.record()["trusted_root"]["signed"]["version"],
        2,
        "the rescue settled on the root the failed update recorded: {}",
        host.record()
    );
}

/// KR-REQ-26.10: a rescue the stores refuse starts again the daemon it stopped and leaves the failed
/// update owing it as the rescue recorded it, which is the newer record of that daemon, and owing the
/// daemon that did not run as the failed update recorded it.
#[tokio::test(flavor = "multi_thread")]
async fn a_rescue_the_stores_refuse_leaves_the_failed_update_owing_the_daemon_as_it_now_is() {
    let host = Host::bare();
    let stores = reading_transfers_from_2();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).reading(stores);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    host.put(&two);
    host.switch(two.name());
    // A second environment whose daemon runs, of the release now current; the first has none.
    let second = Second::start(&host.store.stable(Program::Controller)).await;
    host.store
        .record_roots(
            host.tree.paths().runtime_root(),
            host.tree.paths().state_root(),
        )
        .expect("records the roots");
    // The update recorded both daemons: the first can no longer be started as it says, and the second
    // as an earlier daemon of it was started, from a directory it has since left.
    let restart_of_second = |directory: &Path| {
        serde_json::json!({
            "environment": second.tree.environment_id(),
            "runtime_root": second.tree.paths().runtime_root(),
            "state_root": second.tree.paths().state_root(),
            "start": {
                "arguments": {
                    "arguments": [
                        "--runtime-dir", second.tree.paths().runtime_root(),
                        "--state-dir", second.tree.paths().state_root(),
                        "--secret-store", "file"
                    ],
                    "working_directory": directory,
                }
            },
        })
    };
    let mut first = host.restart();
    first["start"]["arguments"]["arguments"] = serde_json::json!(["--no-such-argument"]);
    host.write_record(&serde_json::json!({
        "format": 2,
        "previous": null,
        "staged": two.name().as_str(),
        "update": {
            "source": one.name().as_str(),
            "target": two.name().as_str(),
            "state": "switched",
            "restarts": [first, restart_of_second(Path::new("/"))],
        },
    }));
    // A store the older release cannot read refuses the rescue.
    let journal = kr_transfer::staging::StagingArea::store_path(&host.tree.environment());
    std::fs::create_dir_all(journal.parent().expect("a directory")).expect("transfers/");
    drop(
        kr_transfer::store::Store::open(&journal, host.tree.environment_id())
            .expect("a transfer journal"),
    );
    rusqlite::Connection::open(&journal)
        .expect("opens")
        .execute("UPDATE schema_version SET version = 1", [])
        .expect("an earlier version");

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        second.build().await,
        format!("kr-controller/{}", two.name()),
        "the daemon the rescue stopped serves again, from the release still current"
    );
    let record = host.record();
    let owed = record["update"]["restarts"].as_array().expect("restarts");
    assert_eq!(owed.len(), 2, "the failed update still owes both: {record}");
    let of = |environment: String| {
        owed.iter()
            .find(|restart| restart["environment"] == environment.as_str())
            .unwrap_or_else(|| panic!("a restart of {environment}: {record}"))
    };
    // The directory the daemon runs in, as the daemon states it: the system resolves a link in the
    // temporary directory's name (macOS reaches it through `/var`), so both are compared resolved.
    let recorded_in =
        of(second.tree.environment_id().to_string())["start"]["arguments"]["working_directory"]
            .as_str()
            .expect("a directory")
            .to_owned();
    assert_eq!(
        std::fs::canonicalize(&recorded_in).expect("the directory is there"),
        std::fs::canonicalize(second.tree.root()).expect("the tree is there"),
        "the daemon that runs is owed as the rescue recorded it: {record}"
    );
    assert_eq!(
        of(host.tree.environment_id().to_string())["start"]["arguments"]["arguments"],
        serde_json::json!(["--no-such-argument"]),
        "and the one that did not is owed as the failed update recorded it: {record}"
    );
}

/// KR-REQ-26.10: the root a failed update recorded is held to the same rule as any root: a rescue to a
/// release that carries another document of the version that update was to trust is refused, and the
/// failed update stays recorded.
#[tokio::test(flavor = "multi_thread")]
async fn a_rescue_to_a_release_with_another_root_of_the_version_the_failed_update_recorded_is_refused()
 {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let level = CompatibilityLevel::of(PACKAGE_VERSION);
    let trusted = channel_root_naming(2, &keys().root, &keys().next_targets, &[&keys().root]);
    let other = channel_root_naming(2, &keys().root, &keys().targets, &[&keys().root]);
    assert_ne!(trusted, other, "two roots of one version that differ");
    let one = Assembled::new("0.2.0+aaaaaaaaaaaa", 2, level, the_root());
    let elder = Assembled::new("0.1.0+eeeeeeeeeeee", 1, level, &other);
    let two =
        Assembled::new("0.3.0+bbbbbbbbbbbb", 3, level, &trusted).whose_daemon_cannot_start(&log);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);
    let (output, said) = host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(1), "{said}");
    host.put(&elder);
    // The release that failed has no root file now, so the root its update recorded is the only
    // record of the version it was to trust.
    {
        use std::os::unix::fs::PermissionsExt as _;

        let share = host.store.release_directory(two.name()).join("share");
        std::fs::set_permissions(&share, std::fs::Permissions::from_mode(0o755)).expect("opened");
        let root_file = share.join("update-root.json");
        std::fs::set_permissions(&root_file, std::fs::Permissions::from_mode(0o644))
            .expect("opened");
        std::fs::remove_file(&root_file).expect("removed");
    }

    let (output, said) =
        host.kr_json(&["host", "rollback", "--to", elder.name().as_str(), "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("trusts neither"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone()),
        "nothing was switched"
    );
    assert_eq!(host.record()["update"]["state"], "switched");

    // The control: the release the update began from, whose root is the first, goes back.
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// KR-REQ-26.10: a rollback names the process that holds an environment, and starts nothing of the
/// release that failed: a daemon of it that holds the environment and answers nothing is the person's
/// to stop, as every daemon the updater did not stop is, and once it is stopped the same command goes
/// back.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_names_the_process_that_holds_the_environment_and_starts_nothing() {
    let mut host = Host::bare();
    let log = host.tree.root().join("starts.log");
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).whose_daemon_cannot_start(&log);
    host.install(&one);
    host.put(&two);
    host.record_a_switched_update(&one, &two);
    // The environment a daemon of the store served, as its start records it.
    host.store
        .record_roots(
            host.tree.paths().runtime_root(),
            host.tree.paths().state_root(),
        )
        .expect("records the roots");
    // A daemon of the release that failed that holds the environment and listens to nothing: this
    // process stands in for it.
    let holding = kr_controller::singleton::SingletonLock::acquire(
        &host.tree.environment().singleton_lock(),
        host.tree.environment_id(),
    )
    .expect("holds the environment");

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&format!("kill {}", std::process::id())),
        "the process that holds the environment is named: {said}"
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("kr host rollback"),
        "and the message names the command that was run: {said}"
    );
    assert_eq!(
        starts_in(&log),
        0,
        "nothing of the release that failed was started"
    );
    assert_eq!(host.record()["update"]["state"], "switched");

    drop(holding);
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    assert_eq!(starts_in(&log), 0);
}

/// KR-REQ-26.10: a Linux daemon that read its document under a configuration home of its own, in an
/// update whose daemon did not start, is checked by the rescue where it read it: the failed update
/// recorded the directory when the daemon made way, and nothing runs to say it now.
#[cfg(all(unix, not(target_os = "macos")))]
#[tokio::test(flavor = "multi_thread")]
async fn a_rescue_checks_the_document_the_abandoned_daemon_read() {
    let (host, one, document) =
        a_daemon_that_finds_its_document_under_its_own_configuration_home().await;
    let log = host.tree.root().join("starts.log");
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).whose_daemon_cannot_start(&log);
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);
    // The updater has other variables than the daemon, so that nothing but the record knows where
    // the daemon's document is.
    let other_home = host.scratch("updater-home");
    let (output, said) = host.kr_json_with(
        &[("HOME", other_home.as_os_str())],
        &[
            "host",
            "update",
            "--archive",
            &archive.display().to_string(),
            "--json",
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{said}");
    kr_ipc::paths::write_owner_only_file(&document, br#"{"version": 99}"#).expect("a document");

    let (output, said) = host.kr_json_with(
        &[("HOME", other_home.as_os_str())],
        &["host", "rollback", "--json"],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&document.display().to_string()),
        "the document the daemon read is named: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone()),
        "nothing was switched"
    );

    kr_ipc::paths::write_owner_only_file(&document, br#"{"version": 1, "revision": 1}"#)
        .expect("a document");
    let (output, said) = host.kr_json_with(
        &[("HOME", other_home.as_os_str())],
        &["host", "rollback", "--json"],
    );
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    assert_eq!(
        host.daemon_document(),
        (document.display().to_string(), "loaded".to_owned()),
        "the daemon the rescue started reads the document where the abandoned one did"
    );
}

/* -------------------------------------------------------------------------------------------- */
/* The variables a daemon started again keeps                                                    */
/* -------------------------------------------------------------------------------------------- */

/// The value a daemon says it has for a variable that decides its paths: `None` where it has none.
fn variable_of(
    started: &kr_protocol::update::HostUpdateHandoverResult,
    name: &str,
) -> Option<String> {
    let found = started
        .environment
        .iter()
        .find(|variable| variable.name == name)
        .unwrap_or_else(|| panic!("the daemon states {name}"));
    found.value.0.clone()
}

/// KR-REQ-26.10: a daemon an update, a rollback or the undo of a refused switch starts again has the
/// variables that decide its paths that the daemon it replaces had, and none that the command which
/// starts it has and the daemon did not: it keeps what it keeps where its predecessor did. What it
/// states of itself is what it has, so this asks the restarted daemon and compares.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_started_again_has_the_variables_that_decide_its_paths_the_one_before_had() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let daemon_home = host.scratch("daemon-home");
    let daemon_config = host.scratch("daemon-config");
    let updater_home = host.scratch("updater-home");
    let updater_run = host.scratch("updater-run");
    let controller = host.store.stable(Program::Controller);
    // The daemon has a home and a configuration home of its own, and an empty state home, which is
    // not the same as none; the commands that start it again have another home, a runtime
    // directory the daemon never had, and no configuration home.
    host.start_daemon_with(
        &controller,
        &[
            ("HOME", daemon_home.as_os_str()),
            ("XDG_CONFIG_HOME", daemon_config.as_os_str()),
            ("XDG_STATE_HOME", std::ffi::OsStr::new("")),
        ],
        &[],
    )
    .await;
    let updater = [
        ("HOME", updater_home.as_os_str()),
        ("XDG_RUNTIME_DIR", updater_run.as_os_str()),
    ];
    let before = host.daemon_started_like().await;
    assert_eq!(
        before.configuration_directory.0.as_deref(),
        host.tree.environment().state_dir().to_str(),
        "the daemon states the directory it reads its document in, which `KR_STATE_DIR` puts beside its state"
    );
    assert_eq!(
        variable_of(&before, "XDG_CONFIG_HOME").as_deref(),
        daemon_config.to_str(),
        "the daemon states the variables it was given"
    );
    assert_eq!(variable_of(&before, "XDG_STATE_HOME").as_deref(), Some(""));
    assert_eq!(variable_of(&before, "XDG_RUNTIME_DIR"), None);

    let scratch = host.scratch("archives");
    let archive_two = scratch.join("two.tar.gz");
    two.archive(&archive_two);
    let (output, said) = host.kr_json_with(
        &updater,
        &[
            "host",
            "update",
            "--archive",
            &archive_two.display().to_string(),
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
    let after_update = host.daemon_started_like().await;
    assert_eq!(
        after_update.environment, before.environment,
        "after the update"
    );
    assert_eq!(
        after_update.configuration_directory, before.configuration_directory,
        "after the update"
    );

    let (output, said) = host.kr_json_with(&updater, &["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    let after_rollback = host.daemon_started_like().await;
    assert_eq!(
        after_rollback.environment, before.environment,
        "after the rollback"
    );

    // A switch the stores refuse stops the daemon and starts it again from the release still
    // current, which is the same restart.
    let beyond = registry_version() + 1;
    let ahead = Assembled::at_this_level("0.3.0+cccccccccccc", 3)
        .reading(reading_a_store_at("registry", beyond, beyond));
    let archive_ahead = scratch.join("ahead.tar.gz");
    ahead.archive(&archive_ahead);
    let (output, said) = host.kr_json_with(
        &updater,
        &[
            "host",
            "update",
            "--archive",
            &archive_ahead.display().to_string(),
            "--json",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    let after_refusal = host.daemon_started_like().await;
    assert_eq!(
        after_refusal.environment, before.environment,
        "after the refused switch"
    );
}

/// KR-REQ-26.10: a daemon that cannot say which values of the variables that decide its paths it
/// has, because one is not text, is not prepared to make way: it cannot be started again like itself.
/// Its gate is not closed by the attempt.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_with_a_path_variable_that_is_not_text_is_not_prepared() {
    use std::os::unix::ffi::OsStrExt as _;

    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    let not_text = std::ffi::OsStr::from_bytes(b"/home/\xff");
    host.start_daemon_with(&controller, &[("HOME", not_text)], &[])
        .await;
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    let refused = handover_step(
        &host,
        &mut client,
        HandoverStep::Prepare,
        None,
        &release("0.2.0+bbbbbbbbbbbb"),
    )
    .await
    .expect_err("a daemon that cannot say its variables does not prepare");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::InvalidArgument,
        "{refused:?}"
    );
    assert!(refused.message.contains("HOME"), "{}", refused.message);
    // The gate was not closed: a session is created.
    let kr = host.store.stable(Program::Kr);
    let (display, _) = host.new_session(&kr);
    host.close(&kr, &display);
    // This daemon refuses to prepare, so the teardown cannot hand it over: it is ended here.
    for mut daemon in host.daemons.drain(..) {
        daemon.kill().expect("stops");
        daemon.wait().expect("ends");
    }
}

/// What a default install on Linux gives a daemon of its own: a home, a configuration home and a state
/// home that is the directory the tree's state root is in, and nothing that names the state root.
#[cfg(all(unix, not(target_os = "macos")))]
async fn a_daemon_that_finds_its_document_under_its_own_configuration_home()
-> (Host, Assembled, PathBuf) {
    let mut host = Host::bare_as_a_default_install();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let daemon_home = host.scratch("daemon-home");
    let daemon_config = host.scratch("daemon-config");
    let controller = host.store.stable(Program::Controller);
    let state_home = host.tree.root().to_path_buf();
    host.start_daemon_with(
        &controller,
        &[
            ("HOME", daemon_home.as_os_str()),
            ("XDG_CONFIG_HOME", daemon_config.as_os_str()),
            ("XDG_STATE_HOME", state_home.as_os_str()),
        ],
        &["KR_STATE_DIR", "KR_RUNTIME_DIR"],
    )
    .await;
    let document = daemon_config
        .join("kalareach")
        .join("environments")
        .join(kr_ipc::paths::short_prefix(host.tree.environment_id()))
        .join("config.json");
    std::fs::create_dir_all(document.parent().expect("a directory")).expect("the directory");
    // The daemon resolves its document from its own variables, under its own configuration home,
    // and not beside the rest of its state, where the commands that update it look first.
    let started = host.daemon_started_like().await;
    assert_eq!(
        started.configuration_directory.0.as_deref(),
        document.parent().and_then(Path::to_str),
        "the daemon states where it reads its document"
    );
    (host, one, document)
}

/// KR-REQ-26.10: a daemon that reads its configuration document under a configuration home of its
/// own is checked like any other: the document it published is looked at, and a switch to a release
/// that cannot read that document is refused naming it, where this command's own environment finds
/// nothing there. The places this command's environment gives are looked at too, so a document a
/// daemon started later from there would read is not passed over because the daemon in front of
/// the update read another.
#[cfg(all(unix, not(target_os = "macos")))]
#[tokio::test(flavor = "multi_thread")]
async fn a_document_a_daemon_reads_under_its_own_configuration_home_is_checked() {
    let (host, one, document) =
        a_daemon_that_finds_its_document_under_its_own_configuration_home().await;
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();
    let update = || host.kr_json(&["host", "update", "--archive", &archive, "--json"]);

    // The daemon's document is at a version the release cannot read.
    kr_ipc::paths::write_owner_only_file(&document, br#"{"version": 99}"#).expect("a document");
    let (output, said) = update();
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&document.display().to_string()) && message.contains("records version 99"),
        "the document the daemon reads is named: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    assert_eq!(
        host.daemon_document(),
        (document.display().to_string(), "unknown_version".to_owned()),
        "the daemon the refusal started again reads the document where the one before did"
    );

    // The daemon's document is one the release reads, and the document where this command's
    // environment puts it is not: that one is refused too.
    kr_ipc::paths::write_owner_only_file(&document, br#"{"version": 1}"#).expect("a document");
    let beside = host.tree.environment().state_dir().join("config.json");
    kr_ipc::paths::write_owner_only_file(&beside, br#"{"version": 99}"#).expect("a document");
    let (output, said) = update();
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&beside.display().to_string()),
        "the document beside the daemon's state is named: {said}"
    );

    // The control: with both in range the update goes ahead.
    std::fs::remove_file(&beside).expect("removed");
    let (output, said) = update();
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
}

/// KR-REQ-26.10: the document a daemon read is recorded when it starts, so that a daemon that has
/// stopped is covered too. The daemon is ended; the document it read, under a configuration home of
/// its own, is put at a version the release switched to cannot read; the update names it. With the
/// document in range, the control, the update goes ahead.
#[cfg(all(unix, not(target_os = "macos")))]
#[tokio::test(flavor = "multi_thread")]
async fn a_document_a_stopped_daemon_read_under_its_own_configuration_home_is_checked() {
    let (mut host, one, document) =
        a_daemon_that_finds_its_document_under_its_own_configuration_home().await;
    for mut daemon in host.daemons.drain(..) {
        daemon.kill().expect("stops");
        daemon.wait().expect("ends");
    }
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);
    let archive = archive.display().to_string();
    let update = || host.kr_json(&["host", "update", "--archive", &archive, "--json"]);

    kr_ipc::paths::write_owner_only_file(&document, br#"{"version": 99}"#).expect("a document");
    let (output, said) = update();
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&document.display().to_string()),
        "the document the stopped daemon read is named: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );

    kr_ipc::paths::write_owner_only_file(&document, br#"{"version": 1}"#).expect("a document");
    let (output, said) = update();
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
}

/// KR-REQ-26.10: a daemon is started again as its own document chose, and not as the document of the
/// environment of the command that starts it: this command's environment chooses the service start
/// and finds no service definition, and the daemon in front of the update was started by hand and reads
/// a document of its own that chooses nothing, so it is started again as it was.
#[cfg(all(unix, not(target_os = "macos")))]
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_is_started_again_as_its_own_document_chose() {
    let (host, _one, document) =
        a_daemon_that_finds_its_document_under_its_own_configuration_home().await;
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    kr_ipc::paths::write_owner_only_file(&document, br#"{"version": 1, "revision": 1}"#)
        .expect("a document");
    kr_ipc::paths::write_owner_only_file(
        &host.tree.environment().state_dir().join("config.json"),
        br#"{"version": 1, "revision": 1, "startup": {"controller": "service"}}"#,
    )
    .expect("a document that chooses the service start");
    let archive = host.scratch("archives").join("two.tar.gz");
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
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
    assert_eq!(
        host.daemon_document(),
        (document.display().to_string(), "loaded".to_owned()),
        "and it reads the document where the daemon before it did"
    );
}

/// A release whose control daemon keeps its keys in the environment's own files and not in the
/// person's credential store, as every harness here has it, unless it is started with a choice of
/// its own. It is the daemon itself, because it hands over with `exec`: the process a service
/// manager starts from this release is the daemon.
#[cfg(target_os = "linux")]
fn with_keys_in_files(release: Assembled) -> Assembled {
    stating_with_keys_in_files(release, "")
}

/// [`with_keys_in_files`], and a daemon that states the later public major `LATER_MAJOR`, however
/// the service manager starts it.
#[cfg(target_os = "linux")]
fn stating_the_later_major_with_keys_in_files(release: Assembled) -> Assembled {
    stating_with_keys_in_files(
        release,
        &format!("/usr/bin/env {LATER_MAJOR_VARIABLE}={LATER_MAJOR} "),
    )
}

/// A release whose daemon runs through `prefix`, a command that puts a variable in its
/// environment, or through none.
#[cfg(target_os = "linux")]
fn stating_with_keys_in_files(release: Assembled, prefix: &str) -> Assembled {
    release
        .with_program(
            "kr-controller-real",
            &Assembled::program_bytes("kr-controller"),
        )
        .with_program(
            "kr-controller",
            format!(
                "#!/bin/sh\ncase \"$1\" in --version) echo kr-controller; exit 0;; esac\n\
                 real=\"$(dirname \"$0\")/kr-controller-real\"\n\
                 case \" $* \" in *\" --secret-store \"*) exec {prefix}\"$real\" \"$@\";; esac\n\
                 exec {prefix}\"$real\" --secret-store file \"$@\"\n"
            )
            .as_bytes(),
        )
}

/// The process the user service manager of a test runs `unit` as, or 0 when it runs none.
#[cfg(target_os = "linux")]
fn main_process_of(manager: &user_manager::UserManager, unit: &str) -> u32 {
    let shown = user_manager::bounded(
        manager.systemctl(&["show", "--property=MainPID", "--value", unit]),
        user_manager::STREAMS_DEADLINE,
    )
    .expect("the manager answers");
    String::from_utf8_lossy(&shown.stdout)
        .trim()
        .parse()
        .expect("a process number")
}

/// Waits until a daemon answers for the environment of `tree`.
#[cfg(target_os = "linux")]
async fn waited_for_a_daemon_of(tree: &teardown::Tree) {
    let started = Instant::now();
    while !answers_for(tree).await {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "no daemon answered for the environment"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// KR-REQ-26.10: a daemon the user's service manager started is started again by it, from the release
/// that is current when it starts, in an update and in a rollback: the daemon that answers afterwards is
/// the process the manager runs the unit as, and not one `kr` started beside it.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_the_service_manager_started_is_started_again_by_it() {
    let host = Host::bare();
    let home = host.scratch("home");
    let manager = match user_manager::UserManager::start(&home, host.tree.holder()) {
        Ok(manager) => manager,
        Err(why) => {
            user_manager::not_tested_here(&why);
            return;
        }
    };
    let one = with_keys_in_files(Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1));
    let two = with_keys_in_files(Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2));
    host.install(&one);
    let manager_of_kr = [
        ("HOME", home.as_os_str()),
        ("XDG_RUNTIME_DIR", manager.runtime.as_os_str()),
    ];

    // The service start is chosen, and the manager starts the daemon of the release installed.
    let (output, said) = host.kr_json_with(
        &manager_of_kr,
        &["host", "startup", "--set", "service", "--json"],
    );
    assert!(
        output.status.success(),
        "kr host startup: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let unit = format!(
        "{}.service",
        said["startup"]["definition"]["label"]
            .as_str()
            .expect("the unit's label")
    );
    let started = user_manager::bounded(
        manager.systemctl(&["start", &unit]),
        user_manager::STREAMS_DEADLINE,
    )
    .expect("the manager answers");
    assert!(
        started.status.success(),
        "systemctl start: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    waited_for_a_daemon_of(&host.tree).await;
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    let served_by = |host: &Host| {
        kr_controller::singleton::SingletonLock::holder(&host.tree.environment().singleton_lock())
            .expect("reads the lock")
            .expect("a daemon holds the environment")
    };
    assert_eq!(served_by(&host), main_process_of(&manager, &unit));

    // An update: the manager's daemon is handed over, and the manager starts the new release's.
    let before = served_by(&host);
    let archive = host.scratch("archives").join("two.tar.gz");
    two.archive(&archive);
    let (output, said) = host.kr_json_with(
        &manager_of_kr,
        &[
            "host",
            "update",
            "--archive",
            &archive.display().to_string(),
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name())
    );
    assert_ne!(served_by(&host), before, "a daemon of the new release");
    assert_eq!(
        served_by(&host),
        main_process_of(&manager, &unit),
        "the manager started it"
    );

    // A rollback: the same, back to the older release.
    let (output, said) = host.kr_json_with(&manager_of_kr, &["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    assert_eq!(
        served_by(&host),
        main_process_of(&manager, &unit),
        "the manager started it"
    );

    // KR-REQ-26.07: across a public major the same holds. The manager starts the daemon of a release
    // that states major 2 and lists only that major, which the updater of release one reaches by the
    // majors the release's manifest lists, and it starts release one's again in the rollback that
    // release two's `kr` makes.
    let three = stating_the_later_major_with_keys_in_files(Assembled::at_this_level(
        "0.3.0+cccccccccccc",
        3,
    ))
    .listing_public_majors(&[LATER_MAJOR]);
    let archive_three = host.scratch("archives").join("three.tar.gz");
    three.archive(&archive_three);
    let (output, said) = host.kr_json_with(
        &manager_of_kr,
        &[
            "host",
            "update",
            "--archive",
            &archive_three.display().to_string(),
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "kr host update across a public major: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", three.name())
    );
    assert_eq!(host.daemon_states().await, LATER_MAJOR);
    assert_eq!(
        served_by(&host),
        main_process_of(&manager, &unit),
        "the manager started it"
    );
    let mut across = manager_of_kr.to_vec();
    across.push((LATER_MAJOR_VARIABLE, std::ffi::OsStr::new("2")));
    let (output, said) = host.kr_json_with(&across, &["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "kr host rollback across a public major: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name())
    );
    assert_eq!(host.daemon_states().await, 1);
    assert_eq!(
        served_by(&host),
        main_process_of(&manager, &unit),
        "the manager started it"
    );
}

/* -------------------------------------------------------------------------------------------- */
/* The lock the writers of stored records take                                                   */
/* -------------------------------------------------------------------------------------------- */

/// What a command of an installed release says, once, when it finds an update switching releases and
/// waits for it.
const WAITS_FOR_AN_UPDATE: &str = "switching releases";

use kr_ipc::install::WRITERS_LOCK;

impl Host {
    /// Holds the writers' lock exclusively, as an update does between its check and its switch.
    fn hold_writers_as_an_update(&self) -> std::fs::File {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.store.root().join(WRITERS_LOCK))
            .expect("the writers' lock file");
        file.lock().expect("the lock is taken");
        file
    }

    /// Holds the writers' lock shared, as a command that is writing a record does.
    fn hold_writers_as_a_command(&self) -> std::fs::File {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.store.root().join(WRITERS_LOCK))
            .expect("the writers' lock file");
        file.lock_shared().expect("the lock is taken");
        file
    }

    /// Starts `kr host startup --set standalone` of the current release, which writes the
    /// environment's configuration document and nothing else, and does not wait for it.
    fn write_the_configuration(&self) -> Writing {
        self.spawn_kr(&["host", "startup", "--set", "standalone", "--json"])
    }

    /// Starts `kr` of the current release with `arguments` and does not wait for it.
    fn spawn_kr(&self, arguments: &[&str]) -> Writing {
        self.spawn_kr_with(&[], arguments)
    }

    /// Starts `kr` of the current release with `arguments` and the variables `set`, and does not
    /// wait for it.
    fn spawn_kr_with(&self, set: &[(&str, &std::ffi::OsStr)], arguments: &[&str]) -> Writing {
        let mut command = self.command(&self.store.stable(Program::Kr), arguments);
        for (name, value) in set {
            command.env(name, value);
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("kr runs");
        let mut stdout = child.stdout.take().expect("piped");
        let said = std::thread::spawn(move || {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut stdout, &mut text).expect("reads");
            text
        });
        let stderr = child.stderr.take().expect("piped");
        let (send, notices) = std::sync::mpsc::channel();
        let lines = std::thread::spawn(move || {
            let mut all = String::new();
            for line in std::io::BufRead::lines(std::io::BufReader::new(stderr)) {
                let line = line.expect("a line");
                all.push_str(&line);
                all.push('\n');
                let _ = send.send(line);
            }
            all
        });
        Writing {
            child,
            notices,
            said: Some(said),
            lines: Some(lines),
        }
    }

    /// Where the environment's configuration document is.
    fn configuration_document(&self) -> PathBuf {
        kr_cli::doctor::configuration::document_path(&self.tree.environment())
    }
}

/// A `kr` command that writes a stored record, started and not ended.
struct Writing {
    child: std::process::Child,
    /// Each line it prints on standard error, as it prints it.
    notices: std::sync::mpsc::Receiver<String>,
    said: Option<std::thread::JoinHandle<String>>,
    lines: Option<std::thread::JoinHandle<String>>,
}

impl Drop for Writing {
    /// A command a failed test left running holds the store's locks until it ends: it ends here.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Writing {
    /// Waits until the command says it is waiting for an update, and says whether it did: a command
    /// that ended without saying so did not wait.
    fn waits_for_an_update(&self) -> bool {
        loop {
            match self.notices.recv_timeout(LIVENESS_DEADLINE) {
                Ok(line) if line.contains(WAITS_FOR_AN_UPDATE) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    }

    /// Waits for the command to end, and returns its exit status and what it printed on standard
    /// output as JSON.
    fn finish(mut self) -> (Option<i32>, Value) {
        let deadline = Instant::now() + Duration::from_secs(300);
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("asks") {
                break status;
            }
            assert!(Instant::now() < deadline, "the command did not end");
            std::thread::sleep(Duration::from_millis(50));
        };
        let said = self
            .said
            .take()
            .expect("stdout is read once")
            .join()
            .expect("stdout is read");
        self.lines
            .take()
            .expect("stderr is read once")
            .join()
            .expect("stderr is read");
        (
            status.code(),
            serde_json::from_str(&said).unwrap_or(Value::Null),
        )
    }
}

/// KR-REQ-26.10: a command that writes a stored record waits for an update that is switching releases
/// and then writes. The writers' lock is held exclusively, as an update holds it between its check of
/// the stores and its switch; the command says it waits, writes nothing while the lock is held, and
/// writes once it is let go.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_waits_for_an_update_and_then_writes() {
    let host = Host::bare();
    host.install(&Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1));
    let document = host.configuration_document();

    let update = host.hold_writers_as_an_update();
    let writing = host.write_the_configuration();
    assert!(
        writing.waits_for_an_update(),
        "the command says it waits for the update"
    );
    assert!(!document.exists(), "and writes nothing while it waits");
    drop(update);
    let (code, said) = writing.finish();
    assert_eq!(
        code,
        Some(0),
        "once the update lets go the command goes on: {said}"
    );
    assert!(document.exists(), "and writes");
}

/// KR-REQ-26.10: a command that has waited for an update's switch for longer than the bound is
/// refused with the code for an update that waits, exit 9, and writes nothing; the same command
/// succeeds once the lock is let go.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_is_refused_while_an_update_holds_the_lock_past_the_bound() {
    let host = Host::bare();
    host.install(&Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1));
    let document = host.configuration_document();

    let update = host.hold_writers_as_an_update();
    let writing = host.write_the_configuration();
    assert!(writing.waits_for_an_update(), "the command waits");
    let (code, said) = writing.finish();
    assert_eq!(
        code,
        Some(9),
        "the command is refused past the bound: {said}"
    );
    assert!(!document.exists(), "and wrote nothing");

    drop(update);
    let (code, said) = host.write_the_configuration().finish();
    assert_eq!(
        code,
        Some(0),
        "the control: with the lock let go it writes: {said}"
    );
    assert!(document.exists());
}

/// KR-REQ-26.10, KR-REQ-24.30: a command writes a record only at the version the current release
/// lists for it. A current release that lists the configuration document at a version this `kr` does
/// not write refuses the command, naming both versions, and the document is not written; a current
/// release that lists no such store does not.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_refuses_to_write_a_version_current_does_not_write() {
    let host = Host::bare();
    let writes = u32::try_from(kr_protocol::hostinfo::configuration::VERSION).expect("small");
    let reads = writes - 1;
    host.install(
        &Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).reading(reading_a_store_at(
            "configuration",
            reads,
            reads,
        )),
    );
    let document = host.configuration_document();
    let (code, said) = host.write_the_configuration().finish();
    assert_eq!(code, Some(1), "{said}");
    let message = said["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("configuration")
            && message.contains(&format!("version {reads}"))
            && message.contains(&format!("version {writes}")),
        "it names the store and both versions: {said}"
    );
    assert!(!document.exists(), "and nothing was written");

    // The control: a release that does not list the store does not read it, so any version goes.
    let other = Host::bare();
    other.install(
        &Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).reading(
            release_stores()
                .into_iter()
                .filter(|store| store.store != "configuration")
                .collect(),
        ),
    );
    let (code, said) = other.write_the_configuration().finish();
    assert_eq!(code, Some(0), "{said}");
    assert!(other.configuration_document().exists());
}

/// KR-REQ-26.10, KR-REQ-24.30: the service start's record is written only at the version the current
/// release lists. Where it lists the record at another, `kr host startup --set service` is refused
/// before anything is changed: no record, no document, and nothing the service manager would take.
#[tokio::test(flavor = "multi_thread")]
async fn the_service_start_is_refused_a_record_version_current_does_not_write() {
    let host = Host::bare();
    let writes = release_stores()
        .into_iter()
        .find(|listed| listed.store == "controller-service")
        .expect("a store this build declares")
        .version;
    host.install(
        &Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).reading(reading_a_store_at(
            "controller-service",
            0,
            writes + 1,
        )),
    );
    // A home of the test's own, so that nothing is ever written in this user's.
    let home = host.scratch("home");
    let (output, said) = host.kr_json_with(
        &[
            ("HOME", home.as_os_str()),
            ("XDG_CONFIG_HOME", home.as_os_str()),
        ],
        &["host", "startup", "--set", "service", "--json"],
    );
    assert_eq!(output.status.code(), Some(1), "{said}");
    let message = said["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("controller-service")
            && message.contains(&format!("version {}", writes + 1))
            && message.contains(&format!("version {writes}")),
        "it names the record and both versions: {said}"
    );
    assert!(!host.configuration_document().exists(), "no document");
    let state = host.tree.environment().state_dir().to_path_buf();
    assert!(
        !state.join(kr_cli::service_manager::RECORD_FILE).exists(),
        "no record"
    );
    assert_eq!(
        std::fs::read_dir(&home).expect("the home").count(),
        0,
        "and nothing was written in the home the command would have written a definition in"
    );
}

/// KR-REQ-26.10: a command that cannot use the writers' lock writes nothing, and says why; and a
/// current release whose manifest this build cannot read refuses the command of another release's
/// `kr`, which says to run the current release's.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_that_cannot_use_the_lock_or_read_current_writes_nothing() {
    let host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let document = host.configuration_document();

    // A directory where the lock file belongs cannot be opened as one.
    let lock = host.store.root().join(WRITERS_LOCK);
    std::fs::remove_file(&lock).expect("the lock file an install made");
    std::fs::create_dir(&lock).expect("a directory in its place");
    let (code, said) = host.write_the_configuration().finish();
    assert_eq!(code, Some(1), "{said}");
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(WRITERS_LOCK),
        "it names the lock: {said}"
    );
    assert!(!document.exists(), "and writes nothing");
    std::fs::remove_dir(&lock).expect("removed");

    // A current release whose manifest is damaged, with the command run from the release before.
    host.put(&two);
    host.switch(two.name());
    let directory = host.store.release_directory(two.name());
    writable(&directory);
    let manifest = host.store.manifest(two.name());
    let sealed = std::fs::read_to_string(&manifest).expect("the manifest");
    std::fs::remove_file(&manifest).expect("the manifest a release is sealed with");
    std::fs::write(&manifest, b"not a manifest").expect("damaged");
    let output = host.run(
        &host.program(one.name(), Program::Kr),
        &["host", "startup", "--set", "standalone", "--json"],
    );
    let said: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("the kr of the current release"),
        "it says which kr to run: {said}"
    );
    assert!(!document.exists(), "and writes nothing");

    // A current release whose manifest lists no stores, which is what an earlier release's was: with
    // no `stores` member, and with an empty list. The reader refuses either before a permit is asked
    // for, so a command of another release is not permitted every record on it.
    let as_written: Value = serde_json::from_str(&sealed).expect("a manifest");
    for emptied in [false, true] {
        let mut changed = as_written.clone();
        let members = changed["signed"]
            .as_object_mut()
            .expect("the signed members");
        if emptied {
            members.insert("stores".to_owned(), serde_json::json!([]));
        } else {
            members.remove("stores");
        }
        std::fs::remove_file(&manifest).expect("the manifest a release is sealed with");
        std::fs::write(&manifest, changed.to_string()).expect("a manifest that lists no stores");
        let output = host.run(
            &host.program(one.name(), Program::Kr),
            &["host", "startup", "--set", "standalone", "--json"],
        );
        let said: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        assert_eq!(
            output.status.code(),
            Some(1),
            "a manifest with {} is refused: {said}",
            if emptied {
                "an empty list of stores"
            } else {
                "no list of stores"
            }
        );
        assert!(!document.exists(), "and nothing is written");
    }
}

/// KR-REQ-26.08, KR-REQ-26.10: an update whose writers' lock cannot be used stops nothing for good.
/// With a directory where the lock file belongs the update, after it has stopped the daemon, ends
/// with exit 1 and starts the daemon again from the release still current, and the next update
/// goes through once the directory is gone.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_whose_writers_lock_cannot_be_used_stops_nothing_for_good() {
    let (host, one, two, archive) = host_to_update().await;
    let lock = host.store.root().join(WRITERS_LOCK);
    std::fs::remove_file(&lock).expect("the lock file an install made");
    std::fs::create_dir(&lock).expect("a directory in its place");

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone()),
        "nothing was switched"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon the update stopped serves again, from the release still current"
    );
    assert!(host.record()["update"].is_null());

    std::fs::remove_dir(&lock).expect("removed");
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "the control: kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
}

/// KR-REQ-26.10: a command that waited through an update's switch is judged by the release the
/// switch made current. The release switched to reads the configuration document at version 1 only,
/// this `kr` writes version 3, and the command that was waiting is refused: the document is never at
/// a version the release switched to cannot read.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_that_waited_through_a_switch_is_judged_by_the_release_switched_to() {
    let host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).reading(reading_a_store_at(
        "configuration",
        1,
        1,
    ));
    host.install(&one);
    host.put(&two);
    let document = host.configuration_document();

    let update = host.stand_in_for_the_updater();
    let writing = host.write_the_configuration();
    assert!(writing.waits_for_an_update(), "the command waits");
    update.switch(two.name());
    drop(update);
    let (code, said) = writing.finish();
    assert_eq!(
        code,
        Some(1),
        "the release now current does not read what this kr writes: {said}"
    );
    assert!(!document.exists(), "so nothing was written");
}

/// KR-REQ-26.10, KR-REQ-24.30: every command that writes a stored record is judged by the release
/// `current` names. Where it lists the record at another version than this `kr` writes, the command
/// is refused naming the record, with nothing written; where it lists no such record the command is
/// not stopped by that.
#[tokio::test(flavor = "multi_thread")]
async fn every_command_that_writes_a_stored_record_is_refused_a_version_current_does_not_write() {
    for (store, arguments) in [
        (
            "terminal-preference",
            &["host", "terminal", "--set", "apple-terminal", "--json"][..],
        ),
        ("shell-entries", &["shell", "remove", "--json"][..]),
    ] {
        let writes = release_stores()
            .into_iter()
            .find(|listed| listed.store == store)
            .expect("a store this build declares")
            .version;
        let refused = Host::bare();
        refused.install(
            &Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).reading(reading_a_store_at(
                store,
                0,
                writes + 1,
            )),
        );
        let (output, said) = refused.kr_json(arguments);
        let message = said["message"].as_str().unwrap_or_default();
        assert_eq!(output.status.code(), Some(1), "{store}: {said}");
        assert!(
            message.contains(store)
                && message.contains(&format!("version {writes}"))
                && message.contains(&format!("version {}", writes + 1)),
            "{store}: it names the record and both versions: {said}"
        );
        let record = match store {
            "terminal-preference" => refused.tree.environment().state_dir().join("terminal.json"),
            _ => refused.tree.paths().state_root().join("shell-entries.json"),
        };
        assert!(!record.exists(), "{store}: nothing was written");

        // The control: a release that does not list the record does not stop the command with that.
        let unlisted = Host::bare();
        unlisted.install(
            &Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).reading(
                release_stores()
                    .into_iter()
                    .filter(|listed| listed.store != store)
                    .collect(),
            ),
        );
        let (output, said) = unlisted.kr_json(arguments);
        assert!(
            !said["message"]
                .as_str()
                .unwrap_or_default()
                .contains("nothing was written: the current release"),
            "{store}: {said} {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// KR-REQ-26.10: a command that tries while a real rollback holds the locks, after it has checked the
/// stores and before it has switched, waits, and is judged by the release switched to. The rollback to
/// a release that reads the configuration document at version 1 is held by the test at the step before
/// the switch, which is a condition of the test and not a time. A command started then says it waits;
/// the rollback is let go on, switches, and the command is refused: the document was never at version
/// 3 while the rollback was under way. The pause points exist in a debug build only.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_that_tries_while_a_real_rollback_holds_the_locks_waits_and_is_refused() {
    if !cfg!(debug_assertions) {
        eprintln!("skipped: a release build has no pause points in its updater");
        return;
    }
    let mut host = Host::bare();
    let one = reading_the_document_at_1("0.1.0+aaaaaaaaaaaa");
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let archive = host.scratch("archives").join("two.tar.gz");
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
    let document = host.configuration_document();
    assert!(!document.exists(), "no document is written yet");

    let pause = host.scratch("pause");
    std::fs::write(pause.join("before-install-lock.release"), b"").expect("lets that step go");
    let rollback = host.spawn_kr_with(
        &[("KR_UPDATE_PAUSE_DIR", pause.as_os_str())],
        &["host", "rollback", "--json"],
    );
    wait_for(&pause.join("before-switch.reached"));

    // The rollback has checked the stores and holds the locks; `current` has not changed.
    let writing = host.write_the_configuration();
    assert!(
        writing.waits_for_an_update(),
        "the command says it waits for the rollback"
    );
    assert!(!document.exists(), "and writes nothing while it waits");
    std::fs::write(pause.join("before-switch.release"), b"").expect("lets the switch go");

    let (code, said) = rollback.finish();
    assert_eq!(code, Some(0), "the rollback goes through: {said}");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
    let (code, said) = writing.finish();
    assert_eq!(
        code,
        Some(1),
        "the release rolled back to reads the document at version 1 only: {said}"
    );
    assert!(!document.exists(), "the document was never written");
}

/// KR-REQ-26.08, KR-REQ-26.10: an update that cannot take the writers' lock stops nothing for good.
/// A command holds it, shared, past the update's bound: the update exits 9 with every daemon it
/// stopped started again from the release still current, and the next update goes through once the
/// lock is let go.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_that_cannot_take_the_writers_lock_stops_nothing_for_good() {
    let (host, one, two, archive) = host_to_update().await;

    let writing = host.hold_writers_as_a_command();
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "{said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone()),
        "nothing was switched"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "the daemon the update stopped serves again, from the release still current"
    );
    let record = host.record();
    assert!(record["update"].is_null(), "{record}");

    drop(writing);
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "the control: kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
}

/* -------------------------------------------------------------------------------------------- */
/* A configuration document the daemon cannot use                                                */
/* -------------------------------------------------------------------------------------------- */

/// A document at the first version this build does not read.
fn the_next_version() -> Vec<u8> {
    format!(
        r#"{{"version": {}}}"#,
        kr_protocol::hostinfo::configuration::VERSION + 1
    )
    .into_bytes()
}

/// The ways a configuration document is unusable, each with the bytes that make it so and a word
/// its remedy must carry.
fn unusable_documents() -> Vec<(&'static str, Vec<u8>, u32, &'static str)> {
    vec![
        (
            "the next version",
            the_next_version(),
            0o600,
            "use a release that reads",
        ),
        (
            "the highest version",
            br#"{"version": 4294967295}"#.to_vec(),
            0o600,
            "use a release that reads",
        ),
        (
            "a version below the oldest",
            br#"{"version": 0}"#.to_vec(),
            0o600,
            "rewrite the document",
        ),
        (
            "a member the schema lacks",
            br#"{"version": 2, "not_a_member": 1}"#.to_vec(),
            0o600,
            "valid against its schema",
        ),
        (
            "permissions wider than owner-only",
            br#"{"version": 2}"#.to_vec(),
            0o644,
            "only you can read and write",
        ),
    ]
}

impl Host {
    /// Runs `kr new` of the current release with an execution context given, as a person does, and
    /// returns what it printed.
    fn kr_new(&self) -> (Output, Value) {
        let cwd = self.tree.root().display().to_string();
        let output = self.run(
            &self.store.stable(Program::Kr),
            &[
                "new",
                "--invisible",
                "--headless",
                "--cwd",
                &cwd,
                "--shell",
                "/bin/sh",
                "--startup",
                "interactive",
                "--json",
            ],
        );
        let said = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        (output, said)
    }

    /// Writes the configuration document with `contents` and `mode`, replacing what is there.
    fn write_the_configuration_as(&self, contents: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;

        let document = self.configuration_document();
        std::fs::create_dir_all(document.parent().expect("a directory")).expect("a directory");
        let _ = std::fs::remove_file(&document);
        std::fs::write(&document, contents).expect("writes the document");
        std::fs::set_permissions(&document, std::fs::Permissions::from_mode(mode))
            .expect("sets its mode");
    }

    /// A create request for a headless session in this host's own environment, as `kr new` makes
    /// one.
    fn headless_create_params(&self) -> kr_protocol::session::SessionCreateParams {
        kr_protocol::session::SessionCreateParams {
            environment_id: self.tree.environment_id(),
            presentation: kr_protocol::session::Presentation::Invisible,
            shell: Nullable::some("/bin/sh".to_owned()),
            shell_mode: kr_protocol::session::ShellMode::NativeCompat,
            cwd: Nullable::some(self.tree.root().display().to_string()),
            dimensions: Nullable::null(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            environment_snapshot: Vec::new(),
            palette: Nullable::null(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: Nullable::null(),
        }
    }

    /// Asks the daemon to accept its document, as every `kr doctor` does, and returns the
    /// diagnostics.
    fn doctor(&self) -> Value {
        self.kr_json(&["--json", "doctor"]).1
    }

    /// Whether session descriptions are on, as the daemon says it.
    fn descriptions_are_on(&self) -> bool {
        let (output, said) = self.kr_json(&["host", "descriptions", "--json"]);
        assert!(
            output.status.success(),
            "kr host descriptions: {said} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        said["enabled"].as_bool().expect("a setting")
    }
}

/// KR-REQ-26.13: a daemon whose configuration document it cannot use (a version it does not know,
/// a damaged document, a file it may not read) fails closed. It turns descriptions off and creates
/// no new session, whatever execution context the request names, and says the document and how to
/// put it right; a session it already serves is untouched, and a document put right lifts all of it
/// at the next create. The control is a document it reads.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_is_refused_over_a_document_the_daemon_cannot_read_and_made_again_when_it_is_rewritten()
 {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let kr = host.store.stable(Program::Kr);

    // The control: a document it reads, a session made, descriptions on.
    host.write_the_configuration_as(br#"{"version": 2}"#, 0o600);
    host.doctor();
    assert!(host.descriptions_are_on());
    let (kept, _) = host.new_session(&kr);

    for (what, contents, mode, remedy) in unusable_documents() {
        host.write_the_configuration_as(&contents, mode);
        let report = host.doctor();
        let found = report["configuration"]["status"]["detail"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(
            found.contains(remedy) && found.contains("no new session is created"),
            "{what}: kr doctor says what happens and how to put it right: {report}"
        );
        let descriptions = report["doctor"]["checks"]
            .as_array()
            .and_then(|checks| checks.iter().find(|check| check["id"] == "descriptions"))
            .expect("the diagnostics check descriptions");
        assert!(
            descriptions["remedy"]
                .as_str()
                .unwrap_or_default()
                .contains("configuration document"),
            "{what}: descriptions are off, and the check does not send a person to a command the \
             unusable document refuses: {descriptions}"
        );
        assert!(!host.descriptions_are_on(), "{what}: descriptions are off");
        let (output, said) = host.kr_new();
        assert!(
            !output.status.success(),
            "{what}: no session is created, though the request names its execution context: {said}"
        );
        let message = said["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("config.json") && message.contains(remedy),
            "{what}: the refusal names the document and the remedy: {said}"
        );
        assert!(
            !message.contains(&host.tree.root().display().to_string()),
            "{what}: and not the path of the host's own directories: {said}"
        );
        // A command that edits the document is refused with the same words and leaves the file.
        let (edit, refused) = host.kr_json(&["host", "startup", "--set", "standalone", "--json"]);
        assert!(!edit.status.success(), "{what}: {refused}");
        assert!(
            refused["message"]
                .as_str()
                .unwrap_or_default()
                .contains(remedy),
            "{what}: {refused}"
        );
        assert_eq!(
            std::fs::read(host.configuration_document()).expect("the document"),
            contents,
            "{what}: through the doctor, the refused create and the refused edit, the file is as it was written"
        );
        {
            use std::os::unix::fs::PermissionsExt as _;
            let kept = std::fs::metadata(host.configuration_document())
                .expect("the document")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                kept, mode,
                "{what}: and its permissions are as they were written"
            );
        }

        // Rewritten, the next create is made and descriptions are on again.
        host.write_the_configuration_as(br#"{"version": 2}"#, 0o600);
        let (output, said) = host.kr_new();
        assert!(
            output.status.success(),
            "{what}: a document put right lifts the refusal at the next create: {said} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let again = said["display_number"].to_string();
        assert!(
            host.descriptions_are_on(),
            "{what}: descriptions are on again"
        );
        host.close(&kr, &again);
    }

    // The session made before any of it is still served: closed here, with the document unusable.
    host.write_the_configuration_as(&the_next_version(), 0o600);
    host.doctor();
    host.close(&kr, &kept);
}

/// KR-REQ-26.13: a create the daemon already answered is answered again when the document breaks
/// afterwards, and a new one is refused: a repeated token is a retry of an action that has an
/// outcome, whatever the host's conditions are now.
#[tokio::test(flavor = "multi_thread")]
async fn a_create_repeated_after_the_document_breaks_is_answered_and_a_new_one_is_refused() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    host.write_the_configuration_as(br#"{"version": 2}"#, 0o600);
    host.doctor();

    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    let params = host.headless_create_params();
    let created = client
        .compose(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.tree.environment_id()),
            &params,
        )
        .await
        .expect("composes the create");
    let first = client
        .repeat(&created)
        .await
        .expect("the host answers")
        .expect("the first create is made");

    host.write_the_configuration_as(&the_next_version(), 0o600);
    host.doctor();
    let again = client
        .repeat(&created)
        .await
        .expect("the host answers")
        .expect("the repeated create is answered from what it produced");
    let first: kr_protocol::session::SessionCreateResult = first.to_typed().expect("decodes");
    let again: kr_protocol::session::SessionCreateResult = again.to_typed().expect("decodes");
    assert!(
        !first.deduplicated && again.deduplicated,
        "the repeat is a replay"
    );
    assert_eq!(
        again.session.session_id, first.session.session_id,
        "the same session answers the repeat"
    );
    let fresh = client
        .compose(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.tree.environment_id()),
            &params,
        )
        .await
        .expect("composes the create");
    let refused = client
        .repeat(&fresh)
        .await
        .expect("the host answers")
        .expect_err("a new create is refused");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::HostNotConfigured,
        "{refused:?}"
    );
}

/// KR-REQ-26.13: a create made right after the document is put right, with nothing asking the host
/// what it is configured as first, is made under what the document now says: the host accepts the
/// document before it reads what the session is started with, so the variable the owner added is
/// the session's. A direct create is how an app or a paired device creates; `kr new` asks the host
/// first and would not show it.
#[tokio::test(flavor = "multi_thread")]
async fn a_create_made_right_after_the_document_is_put_right_takes_what_it_now_says() {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    host.write_the_configuration_as(&the_next_version(), 0o600);
    host.doctor();

    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    let params = host.headless_create_params();
    let refused = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.tree.environment_id()),
            &params,
        )
        .await
        .expect("the host answers")
        .expect_err("refused while the document cannot be used");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::HostNotConfigured,
        "{refused:?}"
    );

    // Put right, with a variable added to every session this host starts; nothing asks the host
    // what it is configured as before the create.
    host.write_the_configuration_as(
        br#"{"version": 2, "preferences": {"environment_additions": {"PATH": "/usr/bin:/bin"}}}"#,
        0o600,
    );
    let created: kr_protocol::session::SessionCreateResult = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.tree.environment_id()),
            &params,
        )
        .await
        .expect("the host answers")
        .expect("the document is put right, so the create is made")
        .to_typed()
        .expect("decodes");
    assert!(!created.deduplicated);
    let report = host.doctor();
    let sessions = report["session_environments"]["sessions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        sessions
            .iter()
            .any(|session| session["path"] == "configured_addition"),
        "the session was started with the variable the document now adds: {report}"
    );
}

/// KR-REQ-26.13: with no daemon running, `kr new` over a document that cannot be used names the
/// document's way out, not "start the control daemon".
#[tokio::test(flavor = "multi_thread")]
async fn kr_new_with_no_daemon_over_an_unusable_document_names_the_way_out() {
    let host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    for (what, contents, mode, remedy) in unusable_documents() {
        host.write_the_configuration_as(&contents, mode);
        let (output, said) = host.kr_new();
        assert!(!output.status.success(), "{what}: {said}");
        let message = said["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("config.json") && message.contains(remedy),
            "{what}: {said}"
        );
    }
}

/* -------------------------------------------------------------------------------------------- */
/* What a command registers                                                                      */
/* -------------------------------------------------------------------------------------------- */

/// A release that reads the configuration document at version 1 only: a rollback to it is refused
/// for a document at a later version.
fn reading_the_document_at_1(name: &str) -> Assembled {
    Assembled::at_this_level(name, 1).reading(reading_a_store_at("configuration", 1, 1))
}

/// Waits until `path` is there, which a condition of the test decides, and fails after the bound a
/// test that went wrong is given.
fn wait_for(path: &Path) {
    let started = Instant::now();
    while !path.exists() {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

impl Host {
    /// Runs `kr` of the current release as a command that works in the roots of `tree`, which
    /// no control daemon of this store has served, and not in this host's own.
    fn kr_in(&self, tree: &teardown::Tree, arguments: &[&str]) -> (Output, Value) {
        let runtime = tree.paths().runtime_root().as_os_str().to_owned();
        let state = tree.paths().state_root().as_os_str().to_owned();
        self.kr_json_with(
            &[("KR_RUNTIME_DIR", &runtime), ("KR_STATE_DIR", &state)],
            arguments,
        )
    }

    /// Rolls back to `release`, as a person types it.
    fn roll_back_to(&self, release: &Assembled) -> (Output, Value) {
        self.kr_json(&[
            "host",
            "rollback",
            "--to",
            release.name().as_str(),
            "--json",
        ])
    }
}

/// KR-REQ-26.10: a command that writes the configuration document in a state root no control daemon of
/// the store recorded is found by the check, and the switch is refused while the document is out of
/// range. The command registered the root and the document before it wrote; the control is the same
/// rollback once the document is gone.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_that_writes_in_a_root_no_daemon_recorded_is_found_by_the_check() {
    let host = Host::bare();
    let one = reading_the_document_at_1("0.1.0+aaaaaaaaaaaa");
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&two);
    host.put(&one);
    let other = teardown::Tree::create();
    let (output, said) = host.kr_in(
        &other,
        &["host", "startup", "--set", "standalone", "--json"],
    );
    assert!(
        output.status.success(),
        "kr host startup: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = kr_cli::doctor::configuration::document_path(&other.environment());
    assert!(document.exists(), "the command wrote the document");

    let (output, said) = host.roll_back_to(&one);
    assert_eq!(output.status.code(), Some(1), "{said}");
    let message = said["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&document.display().to_string())
            && message.contains(&format!(
                "records version {}",
                kr_protocol::hostinfo::configuration::VERSION
            )),
        "the refusal names the document: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone()),
        "nothing was switched"
    );

    std::fs::remove_file(&document).expect("the document goes");
    let (output, said) = host.roll_back_to(&one);
    assert!(
        output.status.success(),
        "the control: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// KR-REQ-26.10: a command that writes a state-root record, here the startup entries `kr shell
/// install` records, in a root no control daemon of the store served has it found by the check: the
/// command registered the root before it wrote.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_that_writes_a_state_root_record_in_a_root_no_daemon_recorded_is_found() {
    let host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).reading(reading_a_store_at(
        "shell-entries",
        0,
        0,
    ));
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let directory = host.put(&two);
    host.switch(two.name());
    // The commands run against the store read its record as an owner-only file.
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(host.store.record(), std::fs::Permissions::from_mode(0o600))
            .expect("the record is owner-only");
    }
    write_zsh_package(&directory.join("shells"));
    host.put(&one);
    let other = teardown::Tree::create();
    let home = host.scratch("home");
    let runtime = other.paths().runtime_root().as_os_str().to_owned();
    let state = other.paths().state_root().as_os_str().to_owned();
    let (output, _) = host.kr_json_with(
        &[
            ("HOME", home.as_os_str()),
            ("KR_RUNTIME_DIR", &runtime),
            ("KR_STATE_DIR", &state),
        ],
        &["shell", "install", "--shell", "zsh"],
    );
    assert!(
        output.status.success(),
        "kr shell install: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let record = other.paths().state_root().join("shell-entries.json");
    assert!(record.exists(), "the command recorded its entries");

    let (output, said) = host.roll_back_to(&one);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("shell-entries.json"),
        "the refusal names the record: {said}"
    );
    std::fs::remove_file(&record).expect("the record goes");
    let (output, said) = host.roll_back_to(&one);
    assert!(output.status.success(), "the control: {said}");
}

/// KR-REQ-26.10: a registered root is looked at when its records can be opened by name, whether or
/// not the root can be listed, and is named, with the switch going ahead, when it cannot be
/// searched. The records of a root are opened by name, so a root a person can search but not list
/// still has its records checked.
#[tokio::test(flavor = "multi_thread")]
async fn a_registered_root_is_looked_at_when_it_can_be_searched_and_named_when_it_cannot() {
    use std::os::unix::fs::PermissionsExt as _;

    let host = Host::create();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).reading(reading_a_store_at(
        "shell-entries",
        0,
        0,
    ));
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    let directory = host.put(&two);
    host.switch(two.name());
    std::fs::set_permissions(host.store.record(), std::fs::Permissions::from_mode(0o600))
        .expect("the record is owner-only");
    write_zsh_package(&directory.join("shells"));
    host.put(&one);
    let other = teardown::Tree::create();
    let home = host.scratch("home");
    let runtime = other.paths().runtime_root().as_os_str().to_owned();
    let state = other.paths().state_root().as_os_str().to_owned();
    let (output, _) = host.kr_json_with(
        &[
            ("HOME", home.as_os_str()),
            ("KR_RUNTIME_DIR", &runtime),
            ("KR_STATE_DIR", &state),
        ],
        &["shell", "install", "--shell", "zsh"],
    );
    assert!(
        output.status.success(),
        "kr shell install: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let root = other.paths().state_root().to_path_buf();
    let record = root.join("shell-entries.json");
    assert!(record.exists(), "the command recorded its entries");

    // Searchable and not listable: the record is opened by name, found, and the switch refused.
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o300)).expect("not listable");
    let (output, said) = host.roll_back_to(&one);
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("restored");
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("shell-entries.json"),
        "the refusal names the record: {said}"
    );

    // Listable and not searchable: nothing in it can be looked at; the root is named, and the
    // switch goes ahead.
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o600))
        .expect("not searchable");
    let (output, said) = host.roll_back_to(&one);
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("restored");
    assert!(
        output.status.success(),
        "a root that cannot be searched is named and left: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["not_reached"]
            .to_string()
            .contains(&root.display().to_string()),
        "the root nobody could search is named: {said}"
    );
}

/// KR-REQ-26.10: a command that registers before an update takes the install lock is found by the
/// update's survey under it. The rollback is held by the test at the step before the lock; the
/// command runs to its end meanwhile; the rollback then finds the root and refuses.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_that_registers_before_the_update_takes_the_install_lock_is_checked() {
    if !cfg!(debug_assertions) {
        eprintln!("skipped: a release build has no pause points in its updater");
        return;
    }
    let host = Host::bare();
    let one = reading_the_document_at_1("0.1.0+aaaaaaaaaaaa");
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&two);
    host.put(&one);
    let other = teardown::Tree::create();
    let pause = host.scratch("pause");
    std::fs::write(pause.join("before-switch.release"), b"").expect("lets that step go");
    let rollback = host.spawn_kr_with(
        &[("KR_UPDATE_PAUSE_DIR", pause.as_os_str())],
        &["host", "rollback", "--to", one.name().as_str(), "--json"],
    );
    wait_for(&pause.join("before-install-lock.reached"));

    let (output, said) = host.kr_in(
        &other,
        &["host", "startup", "--set", "standalone", "--json"],
    );
    assert!(
        output.status.success(),
        "the install lock is free, so the command runs to its end: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::write(pause.join("before-install-lock.release"), b"").expect("lets the lock be taken");

    let (code, said) = rollback.finish();
    assert_eq!(code, Some(1), "{said}");
    let document = kr_cli::doctor::configuration::document_path(&other.environment());
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&document.display().to_string()),
        "the rollback found the root the command registered: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
}

/// KR-REQ-26.10: a command waits for an update from the moment the update holds the install lock,
/// and registers and writes once it lets go. Only the install lock is held here, so a command that
/// did not take it would write at once.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_waits_for_an_update_that_holds_the_install_lock() {
    let host = Host::bare();
    host.install(&Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1));
    let document = host.configuration_document();
    let held = host
        .store
        .try_lock_install()
        .expect("asks")
        .expect("nothing holds it");
    let writing = host.write_the_configuration();
    assert!(
        writing.waits_for_an_update(),
        "the command says it waits for the update"
    );
    assert!(!document.exists(), "and writes nothing while it waits");
    drop(held);
    let (code, said) = writing.finish();
    assert_eq!(code, Some(0), "{said}");
    assert!(document.exists(), "it writes once the update lets go");
}

/// KR-REQ-26.10: commands that registered a root and were refused, or that work in a root with no
/// state of its own, leave a host an update can switch. The roots are only checked: a path too long
/// for a socket, a state root nobody can read, and a terminal the host lacks stop nothing, and the
/// root nobody could read is named.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_that_registered_and_was_refused_leaves_a_host_that_can_be_updated() {
    use std::os::unix::fs::PermissionsExt as _;

    let (host, _one, two, archive) = host_to_update().await;
    let refused = teardown::Tree::create();
    let state_directory = refused.environment().state_dir().to_path_buf();
    std::fs::remove_dir_all(&state_directory).expect("the environment has no state directory");
    let (output, said) = host.kr_in(
        &refused,
        &["host", "terminal", "--set", "no-such-terminal", "--json"],
    );
    assert!(
        !output.status.success(),
        "a terminal the host lacks is refused: {said}"
    );
    assert!(
        !state_directory.exists(),
        "and it made none of the environment's directories"
    );
    let long = host.scratch(&"r".repeat(110));
    std::fs::set_permissions(&long, std::fs::Permissions::from_mode(0o700)).expect("owner-only");
    let elsewhere = teardown::Tree::create();
    let state = elsewhere.paths().state_root().as_os_str().to_owned();
    let (output, said) = host.kr_json_with(
        &[
            ("KR_RUNTIME_DIR", long.as_os_str()),
            ("KR_STATE_DIR", &state),
        ],
        &["host", "terminal", "--set", "no-such-terminal", "--json"],
    );
    assert!(!output.status.success(), "{said}");
    let unreadable = refused.paths().state_root().to_path_buf();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000))
        .expect("nobody can read the root");

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o700))
        .expect("the root can be read again");
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
    assert!(
        said["not_reached"]
            .to_string()
            .contains(&unreadable.display().to_string()),
        "the root nobody could read is named: {said}"
    );
}

/// KR-REQ-26.10: a registration of a command that cannot be read refuses the switch, whatever the
/// others say, before anything is stopped: a record that is wider than owner-only, or that names no
/// roots, hides a root the update must look at. Removing it lets the same rollback go ahead.
#[tokio::test(flavor = "multi_thread")]
async fn a_registration_that_cannot_be_read_refuses_the_switch_until_it_is_removed() {
    use std::os::unix::fs::PermissionsExt as _;

    let host = Host::bare();
    let one = reading_the_document_at_1("0.1.0+aaaaaaaaaaaa");
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&two);
    host.put(&one);
    kr_ipc::paths::create_private_directory(&host.store.roots()).expect("the records");
    let damaged = host.store.roots().join("0123456789abcdef.registered");

    // Wider than owner-only.
    std::fs::write(&damaged, b"/nowhere\0/nowhere").expect("a registration");
    std::fs::set_permissions(&damaged, std::fs::Permissions::from_mode(0o666))
        .expect("wider than owner-only");
    let (output, said) = host.roll_back_to(&one);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone()),
        "nothing was switched"
    );

    // Owner-only, and naming no roots, a runtime root alone, or a root that is not an absolute path.
    std::fs::set_permissions(&damaged, std::fs::Permissions::from_mode(0o600)).expect("owner-only");
    for contents in [
        b"no roots here".as_slice(),
        b"/run\0".as_slice(),
        b"\0/state".as_slice(),
        b"run\0/state".as_slice(),
        b"/run\0state".as_slice(),
        b"/run\0/state\0extra".as_slice(),
    ] {
        std::fs::write(&damaged, contents).expect("a registration that names no usable roots");
        let (output, said) = host.roll_back_to(&one);
        assert_eq!(output.status.code(), Some(1), "{contents:?}: {said}");
        assert_eq!(
            host.store.current().expect("reads"),
            Some(two.name().clone()),
            "{contents:?}: nothing was switched"
        );
    }

    // A record of a configuration document that names no document, or one that is not absolute.
    std::fs::remove_file(&damaged).expect("removed");
    let document = host.store.roots().join("fedcba9876543210.document");
    let environment = host.tree.environment_id().to_string();
    for path in ["", "relative/config.json", "/etc/x\0y/config.json"] {
        std::fs::write(&document, format!("{environment}\0{path}")).expect("a document record");
        std::fs::set_permissions(&document, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only");
        let (output, said) = host.roll_back_to(&one);
        assert_eq!(output.status.code(), Some(1), "document {path:?}: {said}");
    }
    std::fs::remove_file(&document).expect("removed");

    // The control: all removed, the same rollback goes ahead.
    let (output, said) = host.roll_back_to(&one);
    assert!(
        output.status.success(),
        "the control: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );
}

/// KR-REQ-26.10: a registration that cannot be read refuses the update before the daemon is
/// stopped. The daemon the host was serving with is still the process that serves it afterwards, on
/// the release it ran, and removing the record lets the same update go ahead.
#[tokio::test(flavor = "multi_thread")]
async fn a_registration_that_cannot_be_read_refuses_the_update_before_a_daemon_is_stopped() {
    use std::os::unix::fs::PermissionsExt as _;

    let (mut host, one, two, archive) = host_to_update().await;
    let damaged = host.store.roots().join("0123456789abcdef.registered");
    std::fs::write(&damaged, b"/run\0").expect("a registration with no state root");
    std::fs::set_permissions(&damaged, std::fs::Permissions::from_mode(0o600)).expect("owner-only");

    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        said.to_string().contains("0123456789abcdef.registered"),
        "the refusal names the record: {said}"
    );
    assert!(
        host.daemons[0]
            .try_wait()
            .expect("asks the daemon")
            .is_none(),
        "the daemon was not stopped: it is still the process it was"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", one.name()),
        "and it still serves the release it ran"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(one.name().clone())
    );

    // The control: removed, the same update goes ahead and the daemon is the new release's.
    std::fs::remove_file(&damaged).expect("removed");
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "the control: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
}

/// KR-REQ-26.10: a store does not hand over, and does not read the daemon records of, a root another
/// store serves. A `kr` of one store run against another store's roots registers them; the first
/// store's update checks what a command writes there and leaves the second store's daemon serving,
/// and a record only that daemon writes, at a version the first store's target does not read, does
/// not refuse the switch.
#[tokio::test(flavor = "multi_thread")]
async fn a_store_does_not_hand_over_or_read_the_daemon_records_of_another_store() {
    let mut served = Host::bare();
    let served_release = Assembled::at_this_level("0.1.0+cccccccccccc", 1);
    served.install(&served_release);
    let controller = served.store.stable(Program::Controller);
    served.start_daemon(&controller).await;

    let host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2).reading(reading_a_store_at(
        "machine-group",
        5,
        5,
    ));
    host.install(&one);
    let runtime = served.tree.paths().runtime_root().as_os_str().to_owned();
    let state = served.tree.paths().state_root().as_os_str().to_owned();
    let (output, said) = host.kr_json_with(
        &[("KR_RUNTIME_DIR", &runtime), ("KR_STATE_DIR", &state)],
        &["host", "startup", "--set", "standalone", "--json"],
    );
    assert!(
        output.status.success(),
        "a kr of the first store works in the second's roots: {said} {}",
        String::from_utf8_lossy(&output.stderr)
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
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
    assert_eq!(
        served.daemon_build().await,
        format!("kr-controller/{}", served_release.name()),
        "the other store's daemon was not handed over"
    );
}

/// KR-REQ-26.10: a command that works in the state root of a running daemon but with other runtime
/// variables registers its roots without replacing the daemon's, so the update still reaches the
/// daemon at the runtime root it was started with.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_run_with_other_runtime_variables_does_not_replace_the_daemons_runtime_root() {
    let (host, _one, two, archive) = host_to_update().await;
    let runtime = host.scratch("another-runtime");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
            .expect("owner-only");
    }
    let (output, said) = host.kr_json_with(
        &[("KR_RUNTIME_DIR", runtime.as_os_str())],
        &["host", "startup", "--set", "standalone", "--json"],
    );
    assert!(
        output.status.success(),
        "kr host startup: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", two.name()),
        "the update handed the daemon over"
    );
}

/// KR-REQ-26.10: a root a command registered that is gone later, or is a file, stops no switch.
#[tokio::test(flavor = "multi_thread")]
async fn a_registered_root_that_is_gone_does_not_stop_a_switch() {
    let (host, _one, two, archive) = host_to_update().await;
    let gone = teardown::Tree::create();
    let (output, said) = host.kr_in(&gone, &["host", "startup", "--set", "standalone", "--json"]);
    assert!(output.status.success(), "{said}");
    let state = gone.paths().state_root().to_path_buf();
    std::fs::remove_dir_all(&state).expect("the root goes");
    std::fs::write(&state, b"a file where the root was").expect("a file");
    let (output, said) = host.kr_json(&["host", "update", "--archive", &archive, "--json"]);
    std::fs::remove_file(&state).expect("the file goes");
    std::fs::create_dir(&state).expect("a root for the teardown");
    assert!(
        output.status.success(),
        "kr host update: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(two.name().clone())
    );
}

/// KR-REQ-26.10: a document a command writes under a configuration home of its own, which no daemon
/// read, is found by the check: the command recorded where it wrote.
#[cfg(all(unix, not(target_os = "macos")))]
#[tokio::test(flavor = "multi_thread")]
async fn a_document_a_command_writes_under_another_configuration_home_is_checked() {
    let host = Host::bare_as_a_default_install();
    let one = reading_the_document_at_1("0.1.0+aaaaaaaaaaaa");
    let two = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&two);
    host.put(&one);
    let home = host.scratch("command-home");
    let config = host.scratch("command-config");
    let state_home = host.tree.root().to_path_buf();
    let output = host
        .command(
            &host.store.stable(Program::Kr),
            &["host", "startup", "--set", "standalone", "--json"],
        )
        .env_remove("KR_STATE_DIR")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_STATE_HOME", &state_home)
        .stdin(Stdio::null())
        .output()
        .expect("kr runs");
    assert!(
        output.status.success(),
        "kr host startup: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = config
        .join("kalareach")
        .join("environments")
        .join(kr_ipc::paths::short_prefix(host.tree.environment_id()))
        .join("config.json");
    assert!(document.exists(), "the command wrote under its own home");

    let (output, said) = host.roll_back_to(&one);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&document.display().to_string()),
        "the refusal names the document: {said}"
    );
    std::fs::remove_file(&document).expect("the document goes");
    let (output, said) = host.roll_back_to(&one);
    assert!(output.status.success(), "the control: {said}");
}

/// KR-REQ-26.10: a command that cannot register what it works in writes nothing and says so.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_whose_registration_cannot_be_written_writes_nothing() {
    use std::os::unix::fs::PermissionsExt as _;

    let host = Host::bare();
    host.install(&Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1));
    let roots = host.store.roots();
    std::fs::create_dir_all(&roots).expect("the records");
    std::fs::set_permissions(&roots, std::fs::Permissions::from_mode(0o500))
        .expect("read-only records");
    let (code, said) = host.write_the_configuration().finish();
    std::fs::set_permissions(&roots, std::fs::Permissions::from_mode(0o700))
        .expect("writable again");
    assert_eq!(code, Some(1), "{said}");
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("roots"),
        "the command names the records it could not write: {said}"
    );
    assert!(
        !host.configuration_document().exists(),
        "and writes nothing"
    );
}

/* -------------------------------------------------------------------------------------------- */
/* The stored formats                                                                            */
/* -------------------------------------------------------------------------------------------- */

/// A host whose daemon has run: a session created and closed, and the daemon stopped through its own
/// door, so that what it kept is on disk as a stopped daemon leaves it.
async fn a_host_whose_daemon_has_run() -> Host {
    let mut host = Host::bare();
    let one = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1);
    host.install(&one);
    let controller = host.store.stable(Program::Controller);
    host.start_daemon(&controller).await;
    let (display, session) = host.new_session(&host.store.stable(Program::Kr));
    let worker = host.worker_process(session);
    host.close(&host.store.stable(Program::Kr), &display);
    host.worker_ended(&worker).await;
    assert!(
        host.stop_the_daemon().await,
        "the daemon is stopped through its own door"
    );
    host
}

/// What this build says of every store, with the definitions of each database as the daemon's files
/// hold them.
fn observed_stores(host: &Host) -> Vec<stored_formats::Observed> {
    let environment = host.tree.environment();
    stored_formats::table::table()
        .iter()
        .map(|store| {
            let ddl = match store.entry.recording {
                Recording::SqliteTable { .. } | Recording::SqliteUserVersion => {
                    let file = environment.state_dir().join(&store.entry.path);
                    assert!(
                        file.is_file(),
                        "the daemon made the store {} at {}",
                        store.entry.store,
                        file.display()
                    );
                    stored_formats::ddl_of(&file).expect("the database's definitions")
                }
                _ => Vec::new(),
            };
            stored_formats::observe(store, &ddl).expect("what the store keeps is read")
        })
        .collect()
}

/// KR-REQ-26.10, KR-REQ-24.30: every store has a format version, and `stored-formats.lock` maps each
/// to the version the code writes and a digest of what the version stands for: the tables a real
/// daemon made, the types it keeps and the words it matches by hand. A change to any of them moves
/// the digest, and this fails until the version has been raised and the lock written.
#[tokio::test(flavor = "multi_thread")]
async fn the_lock_names_every_store_at_the_version_and_digest_the_code_has() {
    let host = a_host_whose_daemon_has_run().await;
    let found = stored_formats::findings(
        &stored_formats::Lock::committed(),
        &observed_stores(&host),
        &stored_formats::table::named(),
    );
    assert!(
        found.is_empty(),
        "stored-formats.lock does not match the code:\n{}",
        found.join("\n")
    );
}

/// KR-REQ-26.10: no type a store keeps goes undeclared. Every type that a source item the table
/// declares holds in a field is declared for the same store or listed as known for it, however deep;
/// every method whose answer the registry keeps is paired with the type of that answer, which the
/// registry declares or lists as known; and a known type is the one it was when it was listed. A
/// type added to a stored item, or a listed method that keeps an answer, without a line in the table
/// fails here until it has one. A method that reaches the registry's authority claim without being
/// listed fails the first test that runs it; a path that claims elsewhere is not covered by that.
#[test]
fn no_type_a_store_keeps_is_undeclared() {
    let table = stored_formats::table::table();
    let known = stored_formats::table::known();
    let undeclared = stored_formats::undeclared_in(&table, &known).expect("the sources are read");
    assert!(
        undeclared.is_empty(),
        "a type a store keeps is neither declared nor known:\n{}",
        undeclared.join("\n")
    );
    let mut answers: Vec<&str> = stored_formats::table::retained_answers()
        .iter()
        .map(|(_, answer)| *answer)
        .collect();
    answers.extend(stored_formats::table::kept_without_a_holder());
    let changed = stored_formats::known_that_changed(&table, &known, &answers)
        .expect("the known types are read");
    assert!(changed.is_empty(), "{}", changed.join("\n"));

    // The answers the registry keeps.
    let retained: Vec<_> = kr_controller::service::RETAINED_AUTHORITY_ANSWERS
        .iter()
        .chain(kr_controller::service::RETAINED_MACHINE_ANSWERS.iter())
        .copied()
        .collect();
    let unaccounted = stored_formats::retained_unaccounted(
        &table,
        &known,
        &stored_formats::table::retained_answers(),
        &retained,
    );
    assert!(unaccounted.is_empty(), "{}", unaccounted.join("\n"));
}

/// KR-REQ-26.10: every record the grants store writes under a name of its own is in the lock. The
/// registry lists the types it keeps from `grants/durable.rs`, and a record added there without a
/// line is a stored format the lock would never see change.
#[test]
fn every_record_the_grants_store_writes_is_listed_in_the_lock() {
    let unlisted = stored_formats::records_unlisted(
        &stored_formats::table::table(),
        "crates/kr-controller/src/grants/durable.rs",
    )
    .expect("the source is read");
    assert!(unlisted.is_empty(), "{}", unlisted.join("\n"));
}

/// KR-REQ-26.10: the detection finds what it is for. A line of the known list taken away is found as
/// the type it named; a known type whose pinned digest is not the one it has is found; a known type
/// the store has since declared, and one listed for a store the table does not have, are found as
/// lines to delete; and a method whose answer the registry keeps is found when it is not paired, when
/// its type is named nowhere, and when it is paired and keeps none.
#[test]
fn the_detection_of_undeclared_types_finds_a_missing_line_a_changed_type_and_a_stale_line() {
    use kr_protocol::method::Method;

    let table = stored_formats::table::table();
    let known = stored_formats::table::known();
    assert!(
        stored_formats::undeclared_in(&table, &known)
            .expect("read")
            .is_empty()
    );

    let without: Vec<_> = stored_formats::table::known()
        .into_iter()
        .filter(|line| line.name != "Audience")
        .collect();
    let found = stored_formats::undeclared_in(&table, &without).expect("read");
    assert!(
        found.iter().any(|said| said.contains("holds Audience")),
        "a nested type without a line is found: {found:?}"
    );

    let mut moved = stored_formats::table::known();
    moved
        .iter_mut()
        .find(|line| line.name == "EventKey")
        .expect("listed")
        .pinned = "0000";
    let mut answers: Vec<&str> = stored_formats::table::retained_answers()
        .iter()
        .map(|(_, answer)| *answer)
        .collect();
    answers.extend(stored_formats::table::kept_without_a_holder());
    let found = stored_formats::known_that_changed(&table, &moved, &answers).expect("read");
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].starts_with("EventKey "), "{found:?}");

    let mut stale = stored_formats::table::known();
    stale.push(stored_formats::known_protocol::<
        kr_protocol::push::PushDeliveryRequest,
    >("delivery", "PushDeliveryRequest", "0000"));
    stale.push(
        stored_formats::known_protocol::<kr_protocol::push::PushAlert>(
            "no-such-store",
            "PushAlert",
            "0000",
        ),
    );
    let found = stored_formats::known_that_changed(&table, &stale, &answers).expect("read");
    assert!(
        found
            .iter()
            .any(|said| said.contains("PushDeliveryRequest") && said.contains("delete the line")),
        "{found:?}"
    );
    assert!(
        found.iter().any(|said| said.contains("no-such-store")),
        "{found:?}"
    );

    // A known line for a type the store keeps nothing that holds.
    let mut unheld = stored_formats::table::known();
    unheld.push(stored_formats::known_protocol::<
        kr_protocol::push::PushRatePolicy,
    >("privacy", "PushRatePolicy", "0000"));
    let found = stored_formats::known_that_changed(&table, &unheld, &answers).expect("read");
    assert!(
        found.iter().any(|said| said.contains("PushRatePolicy")
            && said.contains("nothing the store keeps holds it")),
        "{found:?}"
    );

    let paired = stored_formats::table::retained_answers();
    let retained = [Method::SessionRename, Method::GrantCreate];
    let found = stored_formats::retained_unaccounted(&table, &known, &paired, &retained);
    assert!(
        found
            .iter()
            .any(|said| said.contains("is paired with an answer and keeps none")),
        "{found:?}"
    );
    let found = stored_formats::retained_unaccounted(&table, &known, &[], &retained);
    assert_eq!(found.len(), 2, "two unpaired methods: {found:?}");
    let found = stored_formats::retained_unaccounted(
        &table,
        &[],
        &[(Method::DevicePushRegister, "NoSuchAnswer")],
        &[Method::DevicePushRegister],
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("names that type nowhere"), "{found:?}");
}

/// KR-REQ-26.10: a word the code matches stored text against is found when a word is added, not only
/// when a listed one is changed. The digest of a set holds how often each listed word occurs where
/// the code writes it, which a word added beside them does not move, and the definition of the enum
/// the words stand for, which a variant added to it does.
#[test]
fn a_word_added_to_the_enum_behind_a_set_of_words_moves_its_digest() {
    let directory = tempfile::tempdir().expect("a directory");
    let write = |path: &str, text: &str| {
        std::fs::write(directory.path().join(path), text).expect("a source");
    };
    let words = vec!["one".to_owned(), "two".to_owned()];
    let basis = |enums: &[(&str, &str)]| {
        stored_formats::words_basis(directory.path(), &words, Some("store.rs"), enums)
            .expect("the basis")
    };
    let enums = [("kinds.rs", "Kinds")];
    write(
        "store.rs",
        "fn out(k: Kinds) -> &str { match k { A => \"one\", B => \"two\" } }\n",
    );
    write("kinds.rs", "pub enum Kinds {\n    A,\n    B,\n}\n");
    let (before, without_enums) = (basis(&enums), basis(&[]));

    // A variant, and the arm that writes its word, are added.
    write(
        "store.rs",
        "fn out(k: Kinds) -> &str { match k { A => \"one\", B => \"two\", C => \"three\" } }\n",
    );
    write("kinds.rs", "pub enum Kinds {\n    A,\n    B,\n    C,\n}\n");
    assert_ne!(
        basis(&enums),
        before,
        "the enum's new variant moves the digest"
    );
    assert_eq!(
        basis(&[]),
        without_enums,
        "and the occurrences of the listed words alone do not: the case the enum is for"
    );

    // A listed word changed where the code writes it moves the digest too.
    write("kinds.rs", "pub enum Kinds {\n    A,\n    B,\n}\n");
    write(
        "store.rs",
        "fn out(k: Kinds) -> &str { match k { A => \"one\", B => \"zwei\" } }\n",
    );
    assert_ne!(basis(&enums), before);
}

/// KR-REQ-26.10: a type a stored item holds is followed to the file that defines it, and what cannot
/// be followed is reported, never skipped. Two types of one name in two files are two types, a `use`
/// that renames or groups or globs is followed, and an alias, a name nothing brings in, a type
/// defined twice in one file, a trait object and a type made by a macro are each reported.
#[test]
fn a_held_type_is_followed_to_the_file_that_defines_it_and_what_cannot_be_followed_is_reported() {
    use stored_formats::resolve::{Origin, Type, Workspace};

    let directory = tempfile::tempdir().expect("a directory");
    let write = |path: &str, text: &str| {
        let path = directory.path().join(path);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("directories");
        std::fs::write(path, text).expect("a source");
    };
    write(
        "crates/kr-protocol/src/ids.rs",
        "macro_rules! ids {}\nids! {\n    SessionId,\n}\n",
    );
    write(
        "crates/kr-protocol/src/scalars.rs",
        "pub struct U64(u64);\n",
    );
    write(
        "crates/kr-protocol/src/lib.rs",
        "pub mod ids;\npub mod scalars;\n",
    );
    write(
        "crates/kr-a/src/lib.rs",
        "pub mod holder;\npub mod holder2;\npub mod holder3;\npub mod one;\npub mod strings;\npub mod two;\npub use one::Notice as Renamed;\n",
    );
    // A `String` an inline module exports through a glob the walk cannot follow is not the
    // standard library's, and two globs that bring in different types of one name are an error.
    write(
        "crates/kr-a/src/holder2.rs",
        "use self::exports::*;\nmod exports {\n    pub struct String {}\n}\npub struct Hidden {\n    a: String,\n}\n",
    );
    write(
        "crates/kr-a/src/holder3.rs",
        "use crate::one::*;\nuse crate::two::*;\npub struct Both {\n    a: Notice,\n}\n",
    );
    write(
        "crates/kr-a/src/one.rs",
        "pub struct Notice {}\npub struct Plain {}\npub struct Notice2 {}\n",
    );
    write("crates/kr-a/src/strings.rs", "pub struct String {}\n");
    write("crates/kr-a/src/two.rs", "pub struct Notice {}\n");
    write(
        "crates/kr-a/src/holder.rs",
        r#"
use crate::one::{Notice, Plain as Simple};
use crate::two::Notice as Other;
use kr_protocol::ids::SessionId;
use other_crate::schema::Signed;
use super::one::*;
use crate::strings::*;
use crate::one::Notice as notice;

pub struct Holds {
    a: Notice,
    b: Other,
    c: Option<Vec<Notice>>,
    d: (u8, String, SessionId),
    e: &'static [Simple],
    f: std::collections::BTreeMap<String, crate::two::Notice>,
    g: crate::Renamed,
    h: Signed<other_crate::schema::Root>,
}

pub enum Variants {
    A(Notice),
    B { inside: Other },
}

pub struct Opaque {
    a: Box<dyn Fn()>,
}

pub struct Aliased {
    a: Short,
}
type Short = Notice;

pub struct Unbound {
    a: Missing,
}

pub struct Twice {
    a: u8,
}
pub enum Twice {
    A,
}
mod inner {
    use crate::two::Notice;

    pub struct Inside {
        a: Notice,
    }
}

pub struct Lower {
    a: notice,
}

pub struct Glob {
    a: Notice2,
}

pub struct Shadow {
    a: String,
}

pub struct Made {
    a: made!(),
}
"#,
    );
    let workspace = Workspace::at(directory.path().to_path_buf()).expect("the workspace");
    let in_a = |file: &str| Origin::Defined(format!("crates/kr-a/src/{file}"));
    let notice = |file: &str| Type {
        origin: in_a(file),
        name: "Notice".to_owned(),
    };

    let held = workspace
        .held_by("crates/kr-a/src/holder.rs", "Holds")
        .expect("everything it holds is followed");
    // Two types of one name are two types, a rename is followed to the original, and a re-export
    // to the file that defines it.
    assert!(held.contains(&notice("one.rs")), "{held:?}");
    assert!(held.contains(&notice("two.rs")), "{held:?}");
    assert!(
        held.contains(&Type {
            origin: in_a("one.rs"),
            name: "Plain".to_owned()
        }),
        "{held:?}"
    );
    assert!(
        held.contains(&Type {
            origin: Origin::Scalar,
            name: "SessionId".to_owned()
        }),
        "{held:?}"
    );
    assert!(
        held.contains(&Type {
            origin: Origin::External("other_crate".to_owned()),
            name: "Signed".to_owned()
        }),
        "{held:?}"
    );
    assert!(
        held.iter()
            .all(|held| !matches!(&held.origin, Origin::Defined(file) if file.ends_with("lib.rs"))),
        "a re-export is followed to the file that defines the type: {held:?}"
    );
    // A name brought in under a lowercase name, a type a glob brings in, and a `String` of the
    // workspace's own are each followed to their file, and the last is not the standard library's.
    let lower = workspace
        .held_by("crates/kr-a/src/holder.rs", "Lower")
        .expect("a lowercase rename is followed");
    assert_eq!(lower, vec![notice("one.rs")]);
    let glob = workspace
        .held_by("crates/kr-a/src/holder.rs", "Glob")
        .expect("a glob is followed");
    assert_eq!(
        glob,
        vec![Type {
            origin: in_a("one.rs"),
            name: "Notice2".to_owned()
        }]
    );
    let shadow = workspace
        .held_by("crates/kr-a/src/holder.rs", "Shadow")
        .expect("a String of the workspace's own is followed");
    assert_eq!(
        shadow,
        vec![Type {
            origin: in_a("strings.rs"),
            name: "String".to_owned()
        }]
    );
    for (file, item, said) in [
        ("holder2.rs", "Hidden", "cannot be followed"),
        ("holder3.rs", "Both", "more than one glob"),
    ] {
        let problems = workspace
            .held_by(&format!("crates/kr-a/src/{file}"), item)
            .expect_err(item);
        assert!(
            problems.iter().any(|problem| problem.contains(said)),
            "{item}: {problems:?}"
        );
    }
    let variants = workspace
        .held_by("crates/kr-a/src/holder.rs", "Variants")
        .expect("the fields of a variant are followed");
    assert!(variants.contains(&notice("one.rs")) && variants.contains(&notice("two.rs")));

    for (item, said) in [
        ("Opaque", "trait object"),
        ("Aliased", "alias"),
        ("Unbound", "neither defined"),
        ("Twice", "exactly once"),
        ("Inside", "exactly once"),
        ("Made", "macro"),
    ] {
        let problems = workspace
            .held_by("crates/kr-a/src/holder.rs", item)
            .expect_err(item);
        assert!(
            problems.iter().any(|problem| problem.contains(said)),
            "{item}: {problems:?}"
        );
    }
}

/// KR-REQ-26.10: a state root's files are all named. After a daemon has run and a session has been
/// made and closed, every entry of the state root and of the environment's directory is a store's or
/// is named in the lock with the reason it has no version, and a file that nothing names is found,
/// whether it is beside the stores or inside a directory a store owns.
#[tokio::test(flavor = "multi_thread")]
async fn no_file_of_a_state_root_goes_unnamed() {
    let host = a_host_whose_daemon_has_run().await;
    let table = stored_formats::table::table();
    let named = stored_formats::table::named();
    let root = host.tree.paths().state_root().to_path_buf();
    // What a client leaves in the state root when it keeps an answer: the answer, and the lock the
    // write of the next one holds.
    let kept = root.join("kept-answers");
    std::fs::create_dir_all(&kept).expect("the directory of kept answers");
    std::fs::write(kept.join("answers.lock"), b"").expect("the lock a write holds");
    std::fs::write(
        kept.join(format!("{}.answer", kr_ipc::new_uuid())),
        b"a kept answer",
    )
    .expect("a kept answer");
    let unnamed = stored_formats::unnamed(&root, &table, &named);
    assert!(unnamed.is_empty(), "named by nothing: {unnamed:?}");

    let environment = host.tree.environment();
    let prefix = format!(
        "environments/{}",
        kr_ipc::paths::short_prefix(host.tree.environment_id())
    );
    std::fs::write(environment.state_dir().join("stray"), b"nothing names this").expect("a file");
    std::fs::write(
        environment
            .state_dir()
            .join("changesets")
            .join("stray.record"),
        b"nor this",
    )
    .expect("a file in a directory a store owns");
    std::fs::copy(
        environment.registry_database(),
        environment
            .state_dir()
            .join("projects")
            .join("another.sqlite"),
    )
    .expect("a database beside a store's");
    std::fs::create_dir_all(environment.state_dir().join("agent-tools").join("actions"))
        .expect("the directory of retained actions");
    std::fs::write(
        environment
            .state_dir()
            .join("agent-tools")
            .join("actions")
            .join("stray.record"),
        b"nor this",
    )
    .expect("a file in a directory two below a store's");
    let unnamed = stored_formats::unnamed(&root, &table, &named);
    for expected in [
        format!("{prefix}/stray"),
        format!("{prefix}/changesets/stray.record"),
        format!("{prefix}/projects/another.sqlite"),
        format!("{prefix}/agent-tools/actions/stray.record"),
    ] {
        assert!(
            unnamed.contains(&expected),
            "{expected} is found: {unnamed:?}"
        );
    }
    assert_eq!(unnamed.len(), 4, "and nothing else: {unnamed:?}");
}

/// For a record a command writes, the highest version that every release that lists its stores reads,
/// where that is not 1.
///
/// The premise is that a host switches only to a release whose manifest lists its stores: `kr host
/// rollback` refuses one that lists none, and `a_rollback_is_refused_to_a_release_that_lists_no_store`
/// holds that, so that a later change which allows such a rollback fails beside this floor. The first
/// release that lists its stores reads the configuration document at versions 1 and 2, because the
/// document gained its `storage` section before it, so every release a host can switch to reads
/// version 2 of it, and a command-written record that no barrier holds off may not be raised
/// past that. Every other record a command writes is at version 1.
const READ_BY_EVERY_LISTED_RELEASE: [(&str, u32); 1] = [("configuration", 2)];

/// For a record a command writes, the version a release that has no writers' lock writes it at, which
/// is the most a release with the lock may require of a record to be read by its programs: such a
/// release holds nothing off a switch, so a command of it can write that version after the check.
/// Release 0.66.1 and the releases before it stamp no version on four of these records, which a
/// manifest reads as 0; they all write the configuration document and the service record at 1.
///
/// Remove an entry's release from the supported ones, and this table with it, only when no host
/// can update from a release that lacks the lock.
const WRITTEN_BY_RELEASES_WITHOUT_THE_LOCK: [(&str, u32); 6] = [
    ("configuration", 1),
    ("controller-service", 1),
    ("kept-answers", 0),
    ("machine-merge-plan", 0),
    ("shell-entries", 0),
    ("terminal-preference", 0),
];

/// A way a record a command writes can reach a switch without the writers' lock, and the records it
/// leaves exposed. While one is open, a record it exposes is not raised past its floor, however the
/// lock is taken: closing the gap, or accepting what it permits for a record, removes the record
/// from the line.
struct OpenGap {
    /// What the gap is.
    what: &'static str,
    /// The records, by name, that it exposes.
    exposes: &'static [&'static str],
}

/// A limit that is accepted for one record, in the words the documents state it in.
struct AcceptedLimit {
    /// What the limit is.
    what: &'static str,
    /// The record it is accepted for.
    record: &'static str,
    /// What a person is told it costs.
    statement: &'static str,
}

/// Every record a command writes.
const COMMAND_WRITTEN: &[&str] = &[
    "configuration",
    "controller-service",
    "kept-answers",
    "machine-merge-plan",
    "shell-entries",
    "terminal-preference",
];

/// The gaps that are open. The lock holds off the commands of an installed release, and what a
/// command writes is registered with the store before it writes, so the check finds it; this is the
/// way a record still gets past the lock:
/// - a `kr` outside an installed release (a development build, an unpacked archive) takes no lock,
///   and a state root does not name the store that serves it, so a store's update cannot hold such a
///   command off. A `kr` of another store takes its own store's lock, which does not hold this one's
///   update off either.
///
/// The records it leaves exposed are the five whose floor stays. The configuration document is not
/// among them: the limit is accepted for it ([`ACCEPTED_FOR_CONFIGURATION`]).
const OPEN_GAPS: [OpenGap; 1] = [OpenGap {
    what: "a kr outside an installed release takes no lock, and a state root names no store",
    exposes: &[
        "controller-service",
        "kept-answers",
        "machine-merge-plan",
        "shell-entries",
        "terminal-preference",
    ],
}];

/// The limits accepted for the configuration document, in the words the documents state them in:
///
/// - a `kr` outside an installed release, or of another store, can write the document into a host on
///   any release, at its own version;
/// - a control daemon in an environment the update could not reach keeps its release, and after a
///   rollback it can write the document at that release's version.
///
/// The gaps the check had (a root no daemon recorded, a document a later daemon with other
/// variables would read) are closed: a command registers the roots and the document it writes
/// before it writes, and the check reads every one. What stays open there is a document a person
/// writes by hand where no program recorded a path.
const ACCEPTED_FOR_CONFIGURATION: [AcceptedLimit; 2] = [
    AcceptedLimit {
        what: "a kr outside an installed release, or of another store, takes no lock of this store",
        record: "configuration",
        statement: "A `kr` outside an installed release (a development build, or an unpacked \
            archive) takes no writers' lock, and a `kr` of another store takes that store's lock \
            and registers its roots there, which does not hold this store's update off. Whatever \
            release is current, such a `kr` can write the document at its own version. A release \
            that holds the change to fail closed over a document it cannot read then creates no new \
            session until the document is put right. Each release before the first that holds it \
            reads the document with the product defaults: descriptions on, the platform's worker \
            profile, no proxy and no network. A restriction that only the unreadable document holds \
            is not applied by any release. An update to a release that reads the version restores \
            every setting.",
    },
    AcceptedLimit {
        what: "a daemon of an environment the update could not reach writes the configuration of its own release",
        record: "configuration",
        statement: "A control daemon in an environment that the update cannot reach keeps its release, \
            and after a rollback it can write the document at that release's version. Its registry \
            is then at that release's schema, so no daemon of the current release starts there until \
            the host is updated again. This rests on every raise of the document also raising the \
            registry, which ends rollback across the release once its daemon runs; configuration \
            levels, which raise no registry, remove that premise.",
    },
];

/// The records a command writes that no open gap exposes and no accepted limit covers: a record
/// whose gap was deleted instead of ruled on.
fn unruled_command_written_records(
    gaps: &[OpenGap],
    accepted: &[AcceptedLimit],
) -> Vec<&'static str> {
    COMMAND_WRITTEN
        .iter()
        .copied()
        .filter(|name| {
            !gaps.iter().any(|gap| gap.exposes.contains(name))
                && !accepted.iter().any(|limit| limit.record == *name)
        })
        .collect()
}

/// What a command-written record's version and writers break, given the gaps that are open.
///
/// A record no barrier holds off may not be raised past what every release that lists its stores
/// reads. A record that is barred may be, once no open gap exposes it; whatever its version, its
/// reader may not require more than a release without the lock writes, and the name and version its
/// writer is given leave to write are the ones the lock records.
fn broken_by_command_written_records(
    stores: &[(stored_formats::Writers, &str, u32, u32)],
    gaps: &[OpenGap],
) -> Vec<String> {
    let floor = |name: &str| {
        READ_BY_EVERY_LISTED_RELEASE
            .iter()
            .find(|(known, _)| *known == name)
            .map_or(1, |(_, version)| *version)
    };
    let mut broken = Vec::new();
    for (writers, name, version, migrates_from) in stores {
        match writers {
            stored_formats::Writers::Daemon | stored_formats::Writers::Update => {}
            stored_formats::Writers::Commands => {
                if *version > floor(name) {
                    broken.push(format!(
                        "{name} is at version {version}, and a command writes it with nothing to hold \
                         it off an update's switch: every release that lists its stores reads up to {}",
                        floor(name)
                    ));
                }
            }
            stored_formats::Writers::Barred(written) => {
                if written.store != *name || written.version != *version {
                    broken.push(format!(
                        "{name} is listed at version {version}, and its writer is given leave to write \
                         {} at version {}",
                        written.store, written.version
                    ));
                }
                let lowest = WRITTEN_BY_RELEASES_WITHOUT_THE_LOCK
                    .iter()
                    .find(|(known, _)| known == name)
                    .map_or(0, |(_, version)| *version);
                if *migrates_from > lowest {
                    broken.push(format!(
                        "{name} migrates from version {migrates_from}, and a release without the \
                         lock writes version {lowest}"
                    ));
                }
                let open: Vec<&str> = gaps
                    .iter()
                    .filter(|gap| gap.exposes.contains(name))
                    .map(|gap| gap.what)
                    .collect();
                if *version > floor(name) && !open.is_empty() {
                    broken.push(format!(
                        "{name} is at version {version}, past {}, while {}",
                        floor(name),
                        open.join("; and ")
                    ));
                }
            }
        }
    }
    broken
}

/// KR-REQ-26.10: no record a command writes is raised past the highest version that every release that
/// lists its stores reads, which is version 1 but for the entries above, unless every writer of it
/// takes the writers' lock that an update holds across its check and its switch and no gap in that
/// lock is open for it.
///
/// A switch is checked against every version on disk, and a `kr` command that is not held off can
/// write a record after the check and before the switch, or a program of a newer release that a
/// rollback left running can write one after it. The writers' lock holds the commands of an installed
/// release off, and a record of the release `current` names listed at another version is not
/// written. Each way a record gets past the lock has one ruling for each record it exposes:
/// - a `kr` outside an installed release is open for the five records whose floor stays, and
///   accepted for the configuration document;
/// - a root no daemon of the store recorded, and a document a daemon started later with other
///   variables would read, are closed for every record: a command registers the roots and the
///   document it writes before it writes, and the check reads every one of them;
/// - a daemon in an environment the update could not reach is accepted for the configuration
///   document.
///
/// A raise of the configuration document past the version every listed release reads needs:
/// - the document's `VERSION` raised, with `OLDEST_VERSION` kept at 1 while a release that writes
///   version 1 is a source of an update and the version-1 reading kept; the table of what releases
///   without the lock write stays, because it bounds what the reader may require;
/// - the registry's version raised with its forward step, since the registry keeps the document it
///   accepted, and `stored-formats.lock` written, the document at the new version in the release's
///   `stores` list (with equality a list at the version before refuses the release's own commands);
/// - the schema the protocol generates and the guides' examples, and the test of a document the
///   build does not recognise, which names the version after the current one as that document's
///   unknown version;
/// - a test that a rollback is refused naming a document at the current version, as
///   `a_rollback_is_refused_naming_a_configuration_document_the_older_release_cannot_read` does,
///   and the `version` row of `docs/host/README.md`, which states the version the document is
///   written at;
/// - a base that holds the writers' lock and the registration.
///
/// A line of `OPEN_GAPS` goes when its gap is closed for the record, or the limit is accepted for it
/// and stated in `ACCEPTED_FOR_CONFIGURATION` and in `docs/host/updates.md`, in the change that
/// rules it.
#[test]
fn no_record_a_command_writes_is_raised_past_what_every_listed_release_reads_while_a_gap_is_open() {
    let stores: Vec<_> = stored_formats::table::table()
        .into_iter()
        .map(|store| {
            (
                store.writers,
                store.entry.store.clone(),
                store.entry.version,
                store.entry.migrates_from,
            )
        })
        .collect();
    let borrowed: Vec<_> = stores
        .iter()
        .map(|(writers, name, version, migrates_from)| {
            (*writers, name.as_str(), *version, *migrates_from)
        })
        .collect();
    let broken = broken_by_command_written_records(&borrowed, &OPEN_GAPS);
    assert!(
        broken.is_empty(),
        "a record a command writes cannot be raised past what every release that lists its \
         stores reads until every writer of it takes the lock an update holds across its check \
         and its switch, and no gap in that lock is open for it: {}",
        broken.join("; ")
    );
    let barred: Vec<&str> = borrowed
        .iter()
        .filter(|(writers, ..)| matches!(writers, stored_formats::Writers::Barred(_)))
        .map(|(_, name, ..)| *name)
        .collect();
    for name in COMMAND_WRITTEN {
        assert!(
            barred.contains(name),
            "{name} is a record a command writes and holds the writers' lock"
        );
    }
    // The stores an update looks for in a root only a command registered are the ones this list
    // names, and no others.
    let mut looked_for: Vec<&str> = kr_cli::barrier::COMMAND_WRITTEN_STORES.to_vec();
    looked_for.sort_unstable();
    let mut written: Vec<&str> = COMMAND_WRITTEN.to_vec();
    written.sort_unstable();
    assert_eq!(
        looked_for, written,
        "the stores a command writes, which an update reads in a root only a command registered, \
         are the records the gate rules on"
    );
    // Every record has one ruling for the way a `kr` outside the lock gets past it: open, or a limit
    // accepted and stated. Deleting a gap's line does not let a record pass its floor unruled.
    assert_eq!(
        unruled_command_written_records(&OPEN_GAPS, &ACCEPTED_FOR_CONFIGURATION),
        Vec::<&str>::new(),
        "a record passes its floor only with a ruling for the way a kr outside the lock reaches it: \
         state the limit in ACCEPTED_FOR_CONFIGURATION or keep the record in OPEN_GAPS"
    );
    for limit in &ACCEPTED_FOR_CONFIGURATION {
        assert!(
            limit.record == "configuration" && !limit.statement.is_empty(),
            "{}: a limit is accepted for the configuration document only, and stated",
            limit.what
        );
    }
    // And the other way: the gaps expose the records of this list, so a record a command writes that
    // is not in it would pass with the gaps open. A record added to the table as one a command
    // writes is added to the list, with the gaps that expose it.
    for (writers, name, ..) in &borrowed {
        if matches!(
            writers,
            stored_formats::Writers::Barred(_) | stored_formats::Writers::Commands
        ) {
            assert!(
                COMMAND_WRITTEN.contains(name),
                "{name} is a record a command writes: add it to COMMAND_WRITTEN, and to the gaps that expose it"
            );
        }
    }
}

/// KR-REQ-26.10: the rule above stops what it is for and lets through what it is not. A barred record
/// at its floor passes whatever gap is open; one raised past it passes only with no gap open for it;
/// a record nothing holds off, one whose reader requires more than a release without the lock
/// writes, and one whose writer is given leave for another name or version are refused.
#[test]
fn the_gate_on_command_written_records_refuses_what_it_is_for() {
    use stored_formats::Writers;

    static CONFIGURATION_2: kr_ipc::install::Written =
        kr_ipc::install::Written::new("configuration", 2);
    static CONFIGURATION_3: kr_ipc::install::Written =
        kr_ipc::install::Written::new("configuration", 3);
    static ANSWERS_1: kr_ipc::install::Written = kr_ipc::install::Written::new("kept-answers", 1);
    let exposed = [OpenGap {
        what: "a gap",
        exposes: &["configuration"],
    }];

    // The control: records at their floors, with the gaps open.
    let at_floor = [
        (Writers::Barred(&CONFIGURATION_2), "configuration", 2, 1),
        (Writers::Barred(&ANSWERS_1), "kept-answers", 1, 0),
    ];
    assert!(broken_by_command_written_records(&at_floor, &exposed).is_empty());

    // Raised past its floor while a gap exposes it: refused. With the gap gone: allowed.
    let raised = [(Writers::Barred(&CONFIGURATION_3), "configuration", 3, 1)];
    assert_eq!(
        broken_by_command_written_records(&raised, &exposed).len(),
        1
    );
    assert!(broken_by_command_written_records(&raised, &[]).is_empty());
    // A gap that exposes another record does not stop it.
    let elsewhere = [OpenGap {
        what: "a gap",
        exposes: &["kept-answers"],
    }];
    assert!(broken_by_command_written_records(&raised, &elsewhere).is_empty());

    // One gap that exposes several records stops each of them and not the ones it does not name.
    static ANSWERS_2: kr_ipc::install::Written = kr_ipc::install::Written::new("kept-answers", 2);
    static ENTRIES_2: kr_ipc::install::Written = kr_ipc::install::Written::new("shell-entries", 2);
    static TERMINAL_2: kr_ipc::install::Written =
        kr_ipc::install::Written::new("terminal-preference", 2);
    let several = [OpenGap {
        what: "a gap",
        exposes: &["kept-answers", "shell-entries"],
    }];
    let raised_several = [
        (Writers::Barred(&ANSWERS_2), "kept-answers", 2, 0),
        (Writers::Barred(&ENTRIES_2), "shell-entries", 2, 0),
        (Writers::Barred(&TERMINAL_2), "terminal-preference", 2, 0),
    ];
    assert_eq!(
        broken_by_command_written_records(&raised_several, &several).len(),
        2,
        "the two records the gap exposes are refused and the third is not"
    );
    assert!(broken_by_command_written_records(&raised_several, &[]).is_empty());

    // A gap deleted instead of ruled on leaves its records unruled; a limit accepted for a record
    // or a gap that exposes it rules on it.
    let limit = |record| AcceptedLimit {
        what: "a limit",
        record,
        statement: "stated",
    };
    assert_eq!(
        unruled_command_written_records(&[], &[limit("configuration")]).len(),
        COMMAND_WRITTEN.len() - 1
    );
    assert!(unruled_command_written_records(&OPEN_GAPS, &[limit("configuration")]).is_empty());
    assert_eq!(
        unruled_command_written_records(&several, &[]).len(),
        COMMAND_WRITTEN.len() - 2
    );

    // A record nothing holds off is held to its floor whatever gaps are open.
    let unbarred = [(Writers::Commands, "configuration", 3, 1)];
    assert_eq!(broken_by_command_written_records(&unbarred, &[]).len(), 1);
    assert!(
        broken_by_command_written_records(&[(Writers::Commands, "configuration", 2, 1)], &[])
            .is_empty()
    );

    // A reader that requires more than a release without the lock writes.
    let requiring = [(Writers::Barred(&ANSWERS_1), "kept-answers", 1, 1)];
    assert_eq!(broken_by_command_written_records(&requiring, &[]).len(), 1);

    // A writer given leave for another version than the one the lock records, and for another name.
    let strayed = [(Writers::Barred(&CONFIGURATION_3), "configuration", 2, 1)];
    assert_eq!(broken_by_command_written_records(&strayed, &[]).len(), 1);
    let misnamed = [(Writers::Barred(&ANSWERS_1), "configuration", 1, 1)];
    assert_eq!(broken_by_command_written_records(&misnamed, &[]).len(), 1);
}

/// KR-REQ-26.10: a rollback to a release whose manifest lists no store is refused, naming that, and
/// nothing is switched. This is the premise of the floor of the guard above: every release a host
/// can switch to lists its stores, and so reads the configuration document at version 2.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_is_refused_to_a_release_that_lists_no_store() {
    let host = Host::bare();
    let unlisted = Assembled::at_this_level("0.1.0+aaaaaaaaaaaa", 1).without_stores();
    let listed = Assembled::at_this_level("0.2.0+bbbbbbbbbbbb", 2);
    host.install(&listed);
    // Written into the store as an earlier build left it: this build starts none of its programs,
    // because its manifest is not one this build reads.
    unlisted.write(&host.store.release_directory(unlisted.name()));

    let (output, said) = host.kr_json(&[
        "host",
        "rollback",
        "--to",
        unlisted.name().as_str(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains("lists no store"),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(listed.name().clone()),
        "nothing was switched"
    );
}

/// Writes `stored-formats.lock` from the code and a daemon's files, refusing a change that would
/// bring the lock past a version that was not raised.
///
/// Run it after raising the version of a store whose tables or values changed:
/// `cargo test -p kr-cli --test update write_the_lock -- --ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes stored-formats.lock"]
async fn write_the_lock() {
    let host = a_host_whose_daemon_has_run().await;
    // A lock that is not there is the first; one that is there and cannot be read is not written
    // over, which would lift the refusals the writer makes against it.
    let committed = match std::fs::read(stored_formats::lock_path()) {
        Ok(bytes) => Some(
            serde_json::from_slice::<stored_formats::Lock>(&bytes)
                .expect("stored-formats.lock is a lock; repair it before it is written again"),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("stored-formats.lock could not be read: {error}"),
    };
    let lock = stored_formats::write(
        committed.as_ref(),
        &observed_stores(&host),
        &stored_formats::table::named(),
    )
    .unwrap_or_else(|refused| panic!("the lock is not written:\n{}", refused.join("\n")));
    std::fs::write(stored_formats::lock_path(), lock.text()).expect("writes the lock");
}

/// KR-REQ-26.10: the check says what to do about each way the code and the lock can differ, and the
/// writer refuses the ways that are a change nobody gave a version to: a digest that moved while the
/// version stood still, a version that went down, a store that is kept somewhere else and a store
/// that is dropped.
#[test]
fn the_lock_check_fails_on_a_moved_digest_and_the_writer_refuses_it() {
    let store = |version: u32, digest: &str, path: &str| stored_formats::Observed {
        entry: ReleaseStore {
            store: "registry".to_owned(),
            scope: StoreScope::Environment,
            path: path.to_owned(),
            recording: Recording::SqliteTable {
                table: "schema_version".to_owned(),
            },
            version,
            migrates_from: 1,
        },
        digest: digest.to_owned(),
        kept: Vec::new(),
        levels: None,
    };
    let lock = stored_formats::write(None, &[store(7, "aa", "registry.sqlite")], &[])
        .expect("a first lock is written");
    assert!(
        stored_formats::findings(&lock, &[store(7, "aa", "registry.sqlite")], &[]).is_empty(),
        "the lock matches itself"
    );

    // A name the code gives to a thing under the state root is held to the lock as the stores are:
    // one the lock lacks is found, and so is one whose terms differ.
    let note = stored_formats::Named {
        scope: StoreScope::Environment,
        name: "scratch",
        children: &[],
        opaque: false,
        databases: false,
        reason: "a leftover that holds nothing",
    };
    let registry = [store(7, "aa", "registry.sqlite")];
    assert!(
        !stored_formats::findings(&lock, &registry, &[note]).is_empty(),
        "a name the code has and the lock does not"
    );
    let with_note = stored_formats::write(Some(&lock), &registry, &[note]).expect("is written");
    assert!(stored_formats::findings(&with_note, &registry, &[note]).is_empty());
    for changed in [
        stored_formats::Named {
            databases: true,
            ..note
        },
        stored_formats::Named {
            opaque: true,
            ..note
        },
        stored_formats::Named {
            children: &["a.json"],
            ..note
        },
    ] {
        assert!(
            !stored_formats::findings(&with_note, &registry, &[changed]).is_empty(),
            "a name whose terms moved"
        );
    }

    // The tables or a kept value changed and the version stood still.
    let moved = [store(7, "bb", "registry.sqlite")];
    let found = stored_formats::findings(&lock, &moved, &[]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("registry") && found[0].contains("raise the version"),
        "{found:?}"
    );
    let refused = stored_formats::write(Some(&lock), &moved, &[]).expect_err("is not written");
    assert!(refused[0].contains("raise it first"), "{refused:?}");

    // The version was raised, and the lock is behind; then it is written.
    let raised = [store(8, "bb", "registry.sqlite")];
    let found = stored_formats::findings(&lock, &raised, &[]);
    assert!(found[0].contains("write the lock"), "{found:?}");
    let written = stored_formats::write(Some(&lock), &raised, &[]).expect("is written");
    assert!(stored_formats::findings(&written, &raised, &[]).is_empty());

    // A version that went down, a store kept somewhere else and a store that is dropped are not
    // written either.
    assert!(
        stored_formats::write(Some(&written), &[store(7, "aa", "registry.sqlite")], &[]).is_err()
    );
    assert!(
        stored_formats::write(Some(&written), &[store(8, "bb", "elsewhere.sqlite")], &[]).is_err()
    );
    let dropped =
        stored_formats::write(Some(&written), &[], &[]).expect_err("a dropped store is refused");
    assert!(dropped[0].contains("would leave the lock"), "{dropped:?}");
    // And a store the lock lists that the code does not declare is found.
    assert!(!stored_formats::findings(&written, &[], &[]).is_empty());
}

/// What the digest leaves out and what it keeps: the words of a doc comment, the spacing and the
/// comments of the SQL, and the name of a type move nothing; a column, a property, a word and a
/// quoted default do.
#[test]
fn the_digest_follows_what_a_store_keeps_and_not_how_it_is_written() {
    use stored_formats::{normalise_schema, normalise_sql};

    assert_eq!(
        normalise_sql("CREATE TABLE t (\n  a INTEGER, -- the first\n  b TEXT /* second */\n)"),
        normalise_sql("CREATE TABLE t (a INTEGER,b TEXT)")
    );
    assert_ne!(
        normalise_sql("CREATE TABLE t (a TEXT DEFAULT 'x  y')"),
        normalise_sql("CREATE TABLE t (a TEXT DEFAULT 'x y')"),
        "a quoted default is kept as it is"
    );
    assert_ne!(
        normalise_sql("CREATE TABLE t (a INTEGER)"),
        normalise_sql("CREATE TABLE t (a INTEGER, b TEXT)")
    );

    let schema = |name: &str, doc: &str, property: &str| {
        serde_json::json!({
            "$ref": format!("#/$defs/{name}"),
            "$defs": { name: {
                "description": doc,
                "type": "object",
                "properties": { property: { "type": "string", "description": "a field" } },
            }},
        })
    };
    assert_eq!(
        normalise_schema(&schema("Create", "the first words", "intent")),
        normalise_schema(&schema("Created", "other words", "intent")),
        "neither a doc comment nor the name of a type moves it"
    );
    assert_ne!(
        normalise_schema(&schema("Create", "words", "intent")),
        normalise_schema(&schema("Create", "words", "purpose")),
        "a property does"
    );
    assert_eq!(
        normalise_schema(&schema("Create", "words", "description"))["properties"]["description"]["type"],
        "string",
        "a property that is called description is a property, not prose"
    );
}
