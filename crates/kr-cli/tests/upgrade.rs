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
//! The cases of a release at this build's own level (`inside_the_level`) update from and roll back to
//! the newest release of that level in this commit's history. A commit whose history has no such
//! release says so and ends them, and nothing else is skipped; a checkout with no release tags at all fails them. They print `inside the level:` and
//! the release they chose, or that they have none, so run them with `--nocapture` to see it.
//! The suite is behind the `upgrade-suite` feature, because building a second tree takes minutes
//! and a network.

#![cfg(unix)]
#![allow(dead_code, unused_imports)]

mod stored_formats;
mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;
// The one reader of Rust source the release tooling has, which the tags' roots are read with.
#[path = "../../kr-protocol/src/bin/kr-protocol-gen/public_majors.rs"]
mod public_majors;
// The release tags: the same selection that `kr-protocol-gen` makes, so the suite updates from the
// release the check holds this commit to.
#[path = "../../kr-protocol/src/bin/kr-protocol-gen/releases.rs"]
mod releases;
// A device pairs with the installed host's daemon over the network. The pairing calls are the ones
// the control daemon's own network suites make.
#[path = "upgrade/door.rs"]
mod door;
#[path = "../../kr-controller/tests/net_support/pairing.rs"]
mod pairing;
// An organisation's keys, which sign the chain a host enrols from and the policy it applies.
#[path = "../../kr-controller/tests/organisation_support/mod.rs"]
mod organisation_support;
// A person's terminal: a program run on a pseudo-terminal that a case types at.
#[path = "upgrade/terminal.rs"]
mod terminal;
// The plugin host an environment publishes, seen from outside.
#[path = "upgrade/plugin_hosts.rs"]
mod plugin_hosts;
// The frames of a plugin host of the release before, taken from a real one.
#[path = "upgrade/plugin_host_frames.rs"]
mod plugin_host_frames;

include!("support/update_harness.rs");

use serde_json::json;

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
    /// The stores the release declares it reads, taken from its tree while the cache was held:
    /// another run may remove the tree afterwards.
    stores: Vec<ReleaseStore>,
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
        // Its manifest is the one that build wrote, as long as the release before is one built
        // before the manifest said what each shell package is made of, as every retained release
        // is: a rollback to it reads that document, and the release's own `kr` reads it when it
        // installs. A later release before this one writes the form of its own build.
        assembled = assembled.as_an_earlier_build_wrote_it();
        // The stores the release declares it reads are its own, and not this build's: a store this
        // build raised or added is one the release before refuses or does not name, and a rollback
        // to it has to be decided by what the release says it reads, not left to a daemon that
        // cannot open it. They are the entries of the release's own stored-formats lock.
        assembled.manifest.stores = self.stores.clone();
        assembled
    }
}

/// The stores the release at `commit` declares it reads: the entries of the stored-formats lock
/// that release was built with.
fn stores_of_the_release_at(commit: &str) -> Vec<ReleaseStore> {
    let path = cache_root().join(commit).join("tree/stored-formats.lock");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let lock: Value =
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    lock["stores"]
        .as_array()
        .unwrap_or_else(|| panic!("{} lists no stores", path.display()))
        .iter()
        .map(|store| {
            serde_json::from_value(store["entry"].clone())
                .unwrap_or_else(|error| panic!("{}: a store entry: {error}", path.display()))
        })
        .collect()
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

/// The level the retained surface holds newest: the level of the release before this one.
fn retained_level() -> &'static kr_protocol::retained::RetainedLevel {
    kr_protocol::retained::RETAINED
        .iter()
        .max_by_key(|level| level.level)
        .expect("a level is retained")
}

/// The commits of the trees the cases of a run build: the release before this one, and the newest
/// kept release of this build's own level. Each is kept when another is built.
fn trees_a_run_builds() -> Vec<String> {
    let level = retained_level();
    [
        Some(recorded(level.release, "commit")),
        newest_kept_release(CompatibilityLevel::of(PACKAGE_VERSION), |_| true)
            .map(|release| release.commit),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The release before this one, built once for the whole run.
fn previous() -> &'static Previous {
    static PREVIOUS: OnceLock<Previous> = OnceLock::new();
    PREVIOUS.get_or_init(|| {
        // The release before is the newest level this build retains.
        let level = retained_level();
        let record = level.release;
        Previous::built(
            recorded(record, "commit"),
            release(&recorded(record, "release")),
            level.level,
        )
    })
}

/// The newest release of `level` in this commit's history that `accepted` takes, by the depth of its
/// commit; none where this commit's history has none.
///
/// The release tags are this checkout's, which the gates hold equal to origin's: a checkout with no
/// release tag at all fails the suite, since an empty list is not the answer "no release at the
/// level".
fn newest_kept_release(
    level: CompatibilityLevel,
    accepted: impl Fn(&releases::Release) -> bool,
) -> Option<releases::Release> {
    let repository = repository();
    let head = releases::git_in(&repository, &["rev-parse", "--verify", "HEAD^{commit}"])
        .expect("this checkout's head")
        .trim()
        .to_owned();
    let all = releases::inventory(&repository).expect("the release tags");
    assert!(
        !all.is_empty(),
        "this checkout has no release tags: fetch them (git fetch --force --prune origin \
         '+refs/tags/packages/v*:refs/tags/packages/v*'); the suite does not skip"
    );
    let mut newest: Option<(usize, releases::Release)> = None;
    for release in releases::kept(&all, level, &head) {
        if !releases::is_ancestor(&repository, &release.commit, &head)
            .expect("the history of this commit")
            || !accepted(&release)
        {
            continue;
        }
        let depth: usize = releases::git_in(&repository, &["rev-list", "--count", &release.commit])
            .expect("the depth of a release")
            .trim()
            .parse()
            .expect("a count");
        if newest.as_ref().is_none_or(|(deepest, _)| depth > *deepest) {
            newest = Some((depth, release));
        }
    }
    newest.map(|(_, release)| release)
}

/// The newest release of this build's own level in this commit's history, built; none where this
/// commit's history has none, which is the case of a commit that moves the level. The release chosen, or that there is none, is printed on
/// standard output, which a run shows with `--nocapture`.
fn inside_the_level() -> Option<&'static Previous> {
    static INSIDE: OnceLock<Option<Previous>> = OnceLock::new();
    INSIDE
        .get_or_init(|| {
            let level = CompatibilityLevel::of(PACKAGE_VERSION);
            let Some(release) = newest_kept_release(level, |_| true) else {
                println!(
                    "inside the level: no kept release of level {level} is in the history of \
                     this commit, so there is no release at this level to update from or roll \
                     back to, and the cases inside the level end here"
                );
                return None;
            };
            let name = release
                .tag
                .strip_prefix("packages/v")
                .expect("a release tag");
            println!(
                "inside the level: the cases update from and roll back to {} ({})",
                release.tag, release.commit
            );
            Some(Previous::built(
                release.commit.clone(),
                self::release(name),
                level,
            ))
        })
        .as_ref()
}

/// As [`inside_the_level`], for the case `case`, which says it did not run when the commit's
/// history holds no release at its level: a case that returns with no assertion would otherwise
/// report that it passed.
fn inside_the_level_for(case: &str) -> Option<&'static Previous> {
    let found = inside_the_level();
    if found.is_none() {
        println!(
            "{case}: not run, because no kept release of level {} is in the history of this \
             commit; the cases that update from, and roll back to, the release before still run",
            CompatibilityLevel::of(PACKAGE_VERSION)
        );
    }
    found
}

impl Previous {
    /// The release at `commit`, built in a tree of its own under the cache and copied, with its
    /// programs in a directory of their own: two releases a run builds do not share one.
    fn built(commit: String, release: ReleaseName, level: CompatibilityLevel) -> Self {
        // Held until the programs are copied and the stores read: another run for another commit
        // removes the trees no case selects, and a tree is read only under this lock.
        let _held = cache_lock();
        let built = build_previous(&commit);
        let directory = support::command_binaries().join("previous").join(&commit);
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
        let stores = stores_of_the_release_at(&commit);
        Self {
            release,
            commit,
            level,
            programs: Box::leak(copied.into_boxed_slice()),
            stores,
        }
    }
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
/// every time, and takes seconds when nothing changed. This commit's tree and the retained level's
/// are kept, and when they are one, the tree used most recently besides it.
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
    // The trees the cases of a run select are kept between runs (the retained level's release and
    // the newest of this build's own level; see [`trees_a_run_builds`]); every other goes before
    // anything is extracted, since a tree and its build are about 12 GB. A tree is read only while
    // the cache lock is held.
    let kept = trees_a_run_builds();
    for entry in std::fs::read_dir(&cache).expect("the cache") {
        let path = entry.expect("an entry").path();
        if !path.is_dir() || path == place {
            continue;
        }
        // An extraction that did not finish has no stamp.
        let finished = std::fs::metadata(path.join("stamp")).is_ok();
        let selected = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| kept.iter().any(|commit| commit == name));
        if !finished || !selected {
            std::fs::remove_dir_all(&path).expect("an old or unfinished tree goes");
        }
    }
    // The tree is the commit's, as extracted by a run with this compiler, or it is made again.
    if !std::fs::read_to_string(place.join("stamp")).is_ok_and(|kept| kept == stamp) {
        // An extraction that did not finish, or one made with another compiler, goes.
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
            "the release before is not in this repository: git archive {commit} said {status}; \
             the suite does not skip"
        );
        std::fs::write(place.join("stamp"), &stamp).expect("the stamp");
    }
    // This use is the stamp's time, so a tree in use is not the one that goes.
    std::fs::File::options()
        .write(true)
        .open(place.join("stamp"))
        .and_then(|stamp| stamp.set_modified(std::time::SystemTime::now()))
        .expect("the stamp is touched");
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
    /// This release as a build before this one wrote it, which the release before this one is: its
    /// manifest has no `agents` and no `dependencies`, and each shell package it lists states its
    /// identity and the revisions of its patches, which is all that build had to say of one.
    fn as_an_earlier_build_wrote_it(mut self) -> Self {
        self.earlier = true;
        self
    }

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
    /// The pipes of the session's contact server, for a host set up with one.
    contact: Option<ContactPipes>,
    /// The stand-in agent the session's root shell started, for a host set up with one.
    agent: Option<Agent>,
}

/// What a host on the release before is set up with.
#[derive(Clone, Copy, Default)]
struct Setup {
    /// The configuration document puts the host's daemon on the network, on the loopback interface
    /// alone, from the first release's daemon on.
    network: bool,
    /// The session's root shell waits at a gate and then becomes the contact server of whichever
    /// release is current, with its standard streams on named pipes.
    contact: bool,
    /// A plugin package whose component the host's plugin runtime runs is installed and enabled
    /// before the first daemon opens the catalogue.
    plugin: bool,
    /// The session's root shell starts a stand-in agent, a process of its own that outlasts the
    /// shell, before it goes on as the shell.
    agent: bool,
    /// The first release's control daemon states the public major of its own build wherever it is
    /// started from, as a release of that major does: the variable that makes a program state a
    /// later major reaches the programs a command starts, and this keeps it from this daemon.
    states_its_own_major: bool,
    /// The first release's manifest names no store for the policies applied for organisations, as
    /// the manifest of a release from before that store does not: a rollback to it is decided by
    /// the update check on that manifest, with the release's own programs behind it.
    without_the_organisation_store: bool,
    /// The configuration document names a test suite, `reports`, that writes a JUnit report as its
    /// output, for a workflow's `run_tests` node to run.
    suite: bool,
}

/// The suite a host set up with one is given: it writes a report with a failed case beside a passed
/// one, as a runner does, and ends with status 0.
const REPORTING_SUITE: &str = "mkdir -p reports && printf '%s\\n' '<testsuite name=\"s\">' \
    '<testcase name=\"passes\"/>' '<testcase name=\"fails\"><failure/></testcase>' \
    '</testsuite>' > reports/junit.xml";

/// The named pipes the contact server of a session runs on.
struct ContactPipes {
    /// The root shell waits to read a line from here.
    gate: PathBuf,
    /// The server's standard input.
    to_server: PathBuf,
    /// The server's standard output.
    from_server: PathBuf,
}

/// Writes the configuration document that puts `host`'s daemon on the network, bound to `address`
/// on loopback, with no relay and no discovery. A daemon reads it when it starts.
fn bind_the_network_at(host: &Host, address: &str) {
    configure_the_host(host, Some(address), false);
}

/// Writes the configuration document of `host`'s daemon: on the network at `address` on loopback
/// when one is given, and naming the suite that writes a JUnit report when `suite` is set.
fn configure_the_host(host: &Host, address: Option<&str>, suite: bool) {
    let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    document.revision = 1;
    if let Some(address) = address {
        document.network.enabled = Nullable::some(true);
        document.network.bind_address = Nullable::some(address.to_owned());
    }
    if suite {
        document.automation.test_suites = Nullable::some(
            [(
                "reports".to_owned(),
                kr_protocol::hostinfo::configuration::TestSuite {
                    command: REPORTING_SUITE.to_owned(),
                    outputs: vec!["reports/junit.xml".to_owned()],
                },
            )]
            .into_iter()
            .collect(),
        );
    }
    let path = kr_worker::config::document_path(&host.tree.environment());
    std::fs::create_dir_all(path.parent().expect("the document has a directory"))
        .expect("the state directory");
    kr_ipc::paths::write_owner_only_file(
        &path,
        kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
    )
    .expect("the configuration document");
}

impl Updated {
    async fn new() -> Self {
        Self::start(Setup::default()).await
    }

    /// As [`Self::new`], with the host's daemon on the network.
    async fn on_the_network() -> Self {
        Self::start(Setup {
            network: true,
            ..Setup::default()
        })
        .await
    }

    /// As [`Self::on_the_network`], with a stand-in agent started by the session's root shell.
    async fn on_the_network_with_an_agent() -> Self {
        Self::start(Setup {
            network: true,
            agent: true,
            ..Setup::default()
        })
        .await
    }

    /// As [`Self::new`], with a session whose root shell becomes the contact server once the test
    /// opens its gate.
    async fn with_a_contact_session() -> Self {
        Self::start(Setup {
            contact: true,
            ..Setup::default()
        })
        .await
    }

    async fn start(setup: Setup) -> Self {
        Self::prepare(setup).await.update().await
    }

    /// As [`Self::start`], on the release `before` and not the release before this one.
    async fn start_on(before: &'static Previous, setup: Setup) -> Self {
        Self::prepare_on(before, setup).await.update().await
    }

    /// A host on the release before with its live session, not yet updated.
    async fn prepare(setup: Setup) -> Prepared {
        Self::prepare_on(previous(), setup).await
    }

    /// A host on `before`, with its live session, not yet updated.
    async fn prepare_on(before: &'static Previous, setup: Setup) -> Prepared {
        let Setup {
            network: on_the_network,
            contact,
            plugin,
            agent,
            states_its_own_major,
            without_the_organisation_store,
            suite,
        } = setup;
        let mut one = before.assembled(1);
        if without_the_organisation_store {
            one.manifest
                .stores
                .retain(|store| store.store != "organisation-policy");
        }
        if states_its_own_major {
            one = one.whose_daemon_states(None);
        }
        let two = Assembled::at_this_level(&format!("{PACKAGE_VERSION}+bbbbbbbbbbbb"), 2)
            .retaining_what_this_build_does();
        let mut host = Host::bare();
        host.install(&one);
        if on_the_network || suite {
            // The document is what puts a host on the network: this one joins on loopback alone,
            // and selects no relay and no discovery.
            configure_the_host(&host, on_the_network.then_some("127.0.0.1:0"), suite);
        }
        if plugin {
            install_plugin(&host).await;
        }
        let started_through_current = host.store.stable(Program::Controller);
        host.start_daemon(&started_through_current).await;
        let kr = host.program(one.name(), Program::Kr);
        let mut pipes = None;
        let mut started_agent = None;
        let (display, session_id) = if agent {
            let (display, session_id, made) = host.new_session_with_an_agent(&kr, "session");
            started_agent = Some(made);
            (display, session_id)
        } else if contact {
            let directory = host.scratch("contact");
            let made = ContactPipes {
                gate: directory.join("gate"),
                to_server: directory.join("to-server"),
                from_server: directory.join("from-server"),
            };
            for pipe in [&made.gate, &made.to_server, &made.from_server] {
                let status = Command::new("mkfifo")
                    .arg(pipe)
                    .status()
                    .expect("mkfifo runs");
                assert!(status.success(), "a pipe is made");
            }
            // Named for the shell it stands for, because the worker recognises a shell by its name.
            let shell = directory.join("sh");
            std::fs::write(
                &shell,
                format!(
                    "#!/bin/sh\nPATH=/usr/bin:/bin\nexport PATH\nKR_RUNTIME_DIR='{runtime}'\n\
                     KR_STATE_DIR='{state}'\nexport KR_RUNTIME_DIR KR_STATE_DIR\n\
                     read -r _ < '{gate}'\nexec '{server}' agent-tools --stdio < '{to}' > '{from}'\n",
                    runtime = host.tree.paths().runtime_root().display(),
                    state = host.tree.paths().state_root().display(),
                    gate = made.gate.display(),
                    // Through `current`: the release that is current when the gate opens.
                    server = host.store.stable(Program::Kr).display(),
                    to = made.to_server.display(),
                    from = made.from_server.display(),
                ),
            )
            .expect("the contact session's shell");
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o755))
                    .expect("executable");
            }
            pipes = Some(made);
            host.new_session_as(&kr, &["--shell", &shell.display().to_string()])
        } else {
            host.new_session(&kr)
        };
        let worker = host.worker_process(session_id);
        assert_eq!(
            host.worker_build(session_id).await,
            format!("kr-worker/{}", one.name()),
            "the session's worker is the release before's"
        );
        Prepared {
            host,
            one,
            two,
            display,
            session_id,
            worker,
            contact: pipes,
            agent: started_agent,
        }
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
        if let Some(agent) = &self.agent {
            assert_eq!(
                kr_ipc::identity::process_state(&agent.identity),
                kr_ipc::identity::ProcessState::Running,
                "and the agent its shell started is the process it was, running"
            );
        }
    }
}

/// A host on the release before with its live session, before the update.
struct Prepared {
    host: Host,
    one: Assembled,
    two: Assembled,
    display: String,
    session_id: SessionId,
    worker: kr_protocol::identity::ProcessStartIdentity,
    contact: Option<ContactPipes>,
    agent: Option<Agent>,
}

impl Prepared {
    /// The release before's `kr`, and this release's once it is current.
    fn kr_before(&self) -> PathBuf {
        self.host.program(self.one.name(), Program::Kr)
    }

    /// Updates the host to this build's release with the release before's own `kr`.
    async fn update(self) -> Updated {
        let Self {
            host,
            one,
            two,
            display,
            session_id,
            worker,
            contact: pipes,
            agent,
        } = self;
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
        let updated = Updated {
            host,
            one,
            two,
            display,
            session_id,
            worker,
            contact: pipes,
            agent,
        };
        updated.the_worker_is_as_it_was().await;
        updated
    }
}

/// KR-REQ-26.03: the first command of a package manager's `kr` brings a host that
/// runs the release before to this release. The release before knows nothing of package managers,
/// so what is offered it is what it takes of any update, a release archive; it checks the release
/// and switches as it does for one a person names, and the manager is recorded.
#[tokio::test(flavor = "multi_thread")]
async fn a_package_managers_first_command_updates_a_host_on_the_release_before() {
    struct Writable(PathBuf);
    impl Drop for Writable {
        fn drop(&mut self) {
            // An installed release is read-only, and the tree goes whole.
            writable(&self.0);
        }
    }

    let one = previous().assembled(1);
    let two = Assembled::at_this_level(&format!("{PACKAGE_VERSION}+bbbbbbbbbbbb"), 2)
        .retaining_what_this_build_does();
    let host = Host::bare();
    // The store at the place a default install names, which the package manager's `kr` looks in.
    let home = host.scratch("home");
    let store = Store::at(if cfg!(target_os = "macos") {
        home.join("Library/Application Support/KalaReach/host")
    } else {
        home.join(".local/share/kalareach/host")
    });
    let _clear = Writable(store.root().to_path_buf());
    host.install_in(&store, &one);

    let tree = host
        .scratch("Cellar")
        .join("kalareach")
        .join(two.name().as_str())
        .join("libexec");
    two.write(&tree);
    start_each_once(&tree);
    let mut command = host.command(
        &tree.join("bin").join(Program::Kr.file_name()),
        &["--json", "host", "paths"],
    );
    command
        .env("HOME", &home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn().expect("kr starts");
    let output = finish_within(child, Duration::from_secs(300));
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );

    assert!(output.status.success(), "{said}");
    assert_eq!(
        store.current().expect("reads"),
        Some(two.name().clone()),
        "the release before's own kr took this release in as an update: {said}"
    );
    assert_eq!(
        kr_cli::update::installer(&store).expect("reads").as_deref(),
        Some("homebrew"),
        "the package manager is recorded"
    );
}

/// KR-REQ-26.06, KR-REQ-26.08, KR-REQ-20.23, KR-ACC-035: a host on the release before is updated,
/// by that release's own `kr`, to this one while a session's worker still runs the release before:
/// the update goes on and does not wait, the worker is the process it was, the new control daemon
/// lists the session and closes it with the answer of the worker's level, and the release the
/// worker holds is let go once the session ends.
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

/// KR-REQ-26.06, KR-REQ-20.23, KR-ACC-035: a control daemon of this release that starts again
/// beside the worker of the release before finds it again from its descriptor and publishes the
/// descriptor in the shape the release before reads, so that release's own `kr` still finds and
/// reads the session, and the restarted daemon still closes it.
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

    // `kr attach` of this release is handed to the `kr` of the release before, which attaches: a
    // person types at the session through it, and the worker is the process it was.
    let typing = terminal_for(host, &updated.kr_now(), &["attach", &updated.display]);
    typing.ready().await;
    updated.the_worker_is_as_it_was().await;
    drop(typing);

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

/// KR-REQ-26.06, KR-REQ-20.23, KR-ACC-035: the frames a control daemon sends a worker on its own,
/// and the worker's answers, are read by the real worker of the release before, and the exchange,
/// recorded as it went over the wire, reads under the level that release stated.
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

/// What the host's daemon answers to `host.info`, as this release reads it.
async fn host_info_of(host: &Host) -> kr_protocol::hostinfo::HostInfoResult {
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    client
        .request(Method::HostInfo, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.info answers")
        .to_typed()
        .expect("this release reads the answer")
}

/// KR-REQ-26.10, KR-REQ-26.08: a rollback to the release before goes on while only its session is
/// live, and waits, exit 9, naming the session, while a session of this release is live.
///
/// The two releases also read each other's `host.info`: the release before's own `kr` reads the
/// answer of this release's daemon, and this release reads the answer of the release before's
/// daemon; each says where privacy mode stands, and `privacy.status` reports it as well.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_to_the_release_before_goes_on_beside_its_session_and_waits_for_one_of_this_release()
 {
    let updated = Updated::new().await;
    let host = &updated.host;

    // This release's daemon tells where privacy mode stands, and the release before's `kr`, whose
    // command reads only `host.info`, reads the answer and says what it holds.
    assert_eq!(
        host_info_of(host).await.privacy.map(|state| (
            state.enabled,
            state.generation.get(),
            state.changing
        )),
        Some((false, 0, false)),
        "this release's daemon says where privacy mode stands"
    );
    let output = host.run(&updated.kr_before(), &["--json", "host", "machine"]);
    assert!(
        output.status.success(),
        "the release before's kr reads this release's host.info: {}",
        String::from_utf8_lossy(&output.stderr)
    );

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
    // The release before's daemon says where privacy mode stands in `host.info` too, and reports it
    // under `privacy.status`, which is what a device that manages the host asks of it.
    assert_eq!(
        host_info_of(host).await.privacy.map(|state| (
            state.enabled,
            state.generation.get(),
            state.changing
        )),
        Some((false, 0, false)),
        "the release before's daemon says where privacy mode stands"
    );
    {
        let endpoint = host
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the daemon");
        let report: kr_protocol::privacy::PrivacyReport = client
            .request(
                Method::PrivacyStatus,
                &kr_protocol::privacy::PrivacyStatusParams {},
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the release before's daemon reports privacy mode")
            .to_typed()
            .expect("this release reads the report");
        assert!(!report.enabled);
    }
    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// KR-REQ-26.10: a session of this release whose journal holds a name for the application in its
/// foreground is read by the release before, once the session has closed and the host has been
/// rolled back to it: the archive of that release reads the summary row, which keeps the shape every
/// release reads, and shows the session as it did before, with no application. This release shows
/// a closed session no application either, whatever its journal holds: the application is what is in
/// the foreground of a session, and a closed session has none.
///
/// A worker clears the application when its session closes, so the journal is written the way a
/// worker that did not would write it, through the worker's own journal, once the session's worker
/// has ended.
#[tokio::test(flavor = "multi_thread")]
async fn a_closed_session_naming_an_application_is_read_by_the_release_before_after_a_rollback() {
    let updated = Updated::new().await;
    let host = &updated.host;
    let (display, session_id) = host.new_session(&updated.kr_now());
    let worker = host.worker_process(session_id);
    host.close(&updated.kr_now(), &display);
    host.worker_ended(&worker).await;

    let path = host.tree.environment().journal_database(session_id);
    {
        let mut journal = kr_worker::journal::Journal::open_existing(&path)
            .expect("the journal of the session this release's worker ran");
        let mut summary = journal
            .read_session(session_id)
            .expect("the journal reads")
            .expect("the worker recorded what the session was");
        assert_eq!(summary.application, None);
        summary.application = Some("Claude Code".to_owned());
        journal
            .record_session(&summary)
            .expect("the journal takes the application");
        assert_eq!(
            journal
                .read_session(session_id)
                .expect("the journal reads")
                .expect("the session")
                .application
                .as_deref(),
            Some("Claude Code"),
            "this release's journal reads the application back"
        );
    }

    // This release's daemon shows the closed session with no application, though the journal holds
    // one.
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    let read: kr_protocol::session::SessionReadResult = client
        .request(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams { session_id },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("session.read answers")
        .to_typed()
        .expect("this release reads the answer");
    assert_eq!(
        read.session.application, None,
        "this release's daemon shows a closed session no application"
    );
    drop(client);

    // And the release before's daemon reads the same journal after the rollback: the summary row
    // keeps the shape it reads, so the session shows as it did, with its shell and directory.
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let read = host.run(&updated.kr_before(), &["--json", "status", &display]);
    assert!(
        read.status.success(),
        "the release before's kr status: {}",
        String::from_utf8_lossy(&read.stderr)
    );
    let read: Value = serde_json::from_slice(&read.stdout).expect("a document");
    assert_eq!(read["session_id"], session_id.to_string(), "{read}");
    assert_eq!(read["state"], "closed", "{read}");
    // What only the summary row holds: the shell the session ran and where it ran it. A summary the
    // release before could not read would be rebuilt from the closure and hold neither.
    assert_eq!(read["shell"], "/bin/sh", "{read}");
    assert_eq!(
        read["cwd"],
        host.tree.root().display().to_string(),
        "{read}"
    );
    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// Enrols the host of `updated` in an organisation on the confirmation of the owner's device and
/// applies the policy the organisation signed, which states `list` as its adapters. Returns the
/// organisation and the file the host keeps the applied policies in.
async fn enrolled_with_a_policy(
    updated: &Updated,
    list: Option<&[&str]>,
) -> (kr_protocol::ids::OrganisationId, PathBuf) {
    use kr_protocol::confirmation::ConfirmationSubject;
    use kr_protocol::organisation::{
        OrganisationEnrolParams, OrganisationEnrolResult, OrganisationListParams,
        OrganisationListResult, OrganisationPolicyApplyParams, OrganisationPolicyApplyResult,
    };

    const DAY_MS: u64 = 24 * 60 * 60 * 1000;
    let host = &updated.host;
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let environment_id = host.tree.environment_id();
    let door = door::Door::pair_the_first_owner(&endpoint, environment_id).await;

    let now = kr_ipc::now_ms().get();
    let mut organisation = organisation_support::Organisation::new(0x21, now - 2 * DAY_MS);
    organisation.rotate(now - DAY_MS);
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    let enrol = OrganisationEnrolParams {
        authority: organisation.authority(now - 1_000),
    };
    pairing::confirm_subject(
        environment_id,
        &mut client,
        ConfirmationSubject::EnrolOrganisation(Box::new(enrol.clone())),
        &pairing::Signer::OwnerDevice(&door.keys),
    )
    .await
    .expect("the owner's device confirms the chain");
    let _: OrganisationEnrolResult = pairing::mutate_as(
        environment_id,
        &mut client,
        kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
        Method::OrganisationEnrol,
        &enrol,
    )
    .await
    .expect("the host enrols");
    let applied: OrganisationPolicyApplyResult = pairing::mutate_as(
        environment_id,
        &mut client,
        kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
        Method::OrganisationPolicyApply,
        &OrganisationPolicyApplyParams {
            policy: organisation.policy(2, 1, list, now),
            authority: Nullable::null(),
        },
    )
    .await
    .expect("the host applies the organisation's policy");
    assert_eq!(
        applied
            .effective_adapter_allowlist
            .0
            .map(|stated| stated.len()),
        list.map(<[&str]>::len)
    );
    let listed: OrganisationListResult = pairing::read(
        &mut client,
        Method::OrganisationList,
        &OrganisationListParams::default(),
    )
    .await
    .expect("the owner reads what the host holds");
    assert_eq!(listed.enrolments.len(), 1);
    let store = host
        .tree
        .environment()
        .state_dir()
        .join("organisation-policy.json");
    assert!(store.is_file(), "the policy is kept in its store");
    (organisation.organisation_id, store)
}

/// KR-REQ-26.10, KR-REQ-26.08, KR-REQ-18.06: a release whose manifest names no store for the
/// policies applied for organisations would admit every adapter, so the update check refuses a
/// rollback to it while an organisation's policy states an adapter list. The refusal names the
/// organisation, with nothing switched and the daemon serving again. The way through is the
/// withdrawal from the organisation, which needs no confirmation; after it the rollback goes on.
///
/// A package manager has put these releases here: its name is in a file beside the record, and the
/// rollback leaves it where it was.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_that_would_lift_an_organisations_adapter_list_is_refused_until_the_host_leaves_it()
 {
    let updated = Updated::start_on(
        previous(),
        Setup {
            network: true,
            without_the_organisation_store: true,
            ..Setup::default()
        },
    )
    .await;
    let host = &updated.host;
    let (organisation_id, store) =
        enrolled_with_a_policy(&updated, Some(&["kalareach/codex"])).await;

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a rollback that would lift the list is refused: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = said["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        message.contains(&organisation_id.to_string())
            && message.contains("kr organisation withdraw"),
        "the refusal names the organisation and the way through: {said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(updated.two.name().clone()),
        "nothing was switched"
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", updated.two.name()),
        "the daemon the rollback stopped serves again"
    );
    assert!(store.is_file(), "the refusal leaves the store alone");

    let (output, said) = host.kr_json(&[
        "organisation",
        "withdraw",
        &organisation_id.to_string(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the withdrawal needs no confirmation: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!store.exists(), "the list went with the enrolment");

    std::fs::write(host.store.root().join("installer"), "homebrew\n").expect("the installer file");
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
    assert!(
        host.store.root().join("installer").is_file(),
        "the package manager's name is where it was after the rollback"
    );
    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// KR-REQ-26.10, KR-REQ-26.08: a policy that states no adapter list lifts nothing, so a rollback to
/// a release whose manifest names no store for the policies goes on while the host keeps the
/// policy, and the file the policy is kept in stays on disk.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_goes_on_while_an_applied_policy_states_no_list_and_leaves_its_store() {
    let updated = Updated::start_on(
        previous(),
        Setup {
            network: true,
            without_the_organisation_store: true,
            ..Setup::default()
        },
    )
    .await;
    let host = &updated.host;
    let (_, store) = enrolled_with_a_policy(&updated, None).await;

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", updated.one.name()),
        "the daemon is the release before's again"
    );
    assert!(store.is_file(), "the rollback leaves the store alone");
    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// KR-REQ-26.10, KR-REQ-26.08: the release before reads the store the host keeps the applied
/// policies in, so a rollback to it goes on while a policy states an adapter list, and its daemon
/// puts the list in force again: the rollback lifts nothing. The release's own `kr` shows the
/// policy and the list the daemon holds, and the store this release wrote is still on disk.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_to_a_release_that_reads_the_organisation_store_goes_on_with_the_list_in_force()
{
    let updated = Updated::on_the_network().await;
    let host = &updated.host;
    let (_, store) = enrolled_with_a_policy(&updated, Some(&["kalareach/codex"])).await;

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a rollback to a release that reads the store goes on: {said} {}",
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
    assert!(
        store.is_file(),
        "the store stays where this release wrote it"
    );

    let output = host.run(&updated.kr_before(), &["--json", "organisation", "list"]);
    assert!(
        output.status.success(),
        "the release before's kr lists the organisations: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let said: Value = serde_json::from_slice(&output.stdout).expect("a document");
    let listed = json!(["kalareach/codex"]);
    let enrolments = said["enrolments"].as_array().expect("a list of enrolments");
    assert_eq!(enrolments.len(), 1, "{said}");
    assert_eq!(
        enrolments[0]["organisation_policy_revision"], "1",
        "the release before applies the policy: {said}"
    );
    assert_eq!(
        enrolments[0]["adapter_allowlist"], listed,
        "and the list the policy states: {said}"
    );
    assert_eq!(
        said["effective_adapter_allowlist"], listed,
        "which its daemon puts in force: {said}"
    );
    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// A mutation's expected-state evidence for a method that needs none.
#[derive(serde::Serialize)]
struct Empty {}

/// Adds host events to a session's journal through a connection of the test's own, as a worker's
/// other writer would, and leaves the worker to find them.
fn insert_host_events(journal: &Path, rows: &[(String, String)]) {
    let connection = rusqlite::Connection::open(journal).expect("opens the session's journal");
    let at = i64::try_from(kr_ipc::now_ms().get()).expect("a time that fits");
    for (kind, detail) in rows {
        connection
            .execute(
                "INSERT INTO host_events (kind, detail, output_cursor, recorded_at_ms) \
                 VALUES (?1, ?2, 0, ?3)",
                rusqlite::params![kind, detail, at],
            )
            .expect("the journal takes the row");
    }
}

/// The attention inbox of one session as a paired device reads it, when it can be read.
async fn read_inbox_through(
    session: &kr_client::session::Session,
    session_id: SessionId,
) -> Option<kr_protocol::attention::AttentionReadResult> {
    session
        .read(
            Method::AttentionRead,
            &kr_protocol::attention::AttentionReadParams {
                session_id: Nullable::some(session_id),
                include_acknowledged: true,
                max_items: U64::new(50),
                after: Nullable::null(),
            },
        )
        .await
        .ok()
}

/// The attention inbox of one session as the owner at this machine reads it, when it can be read.
async fn read_inbox_here(
    endpoint: &kr_ipc::paths::Endpoint,
    session_id: SessionId,
) -> Option<kr_protocol::attention::AttentionReadResult> {
    let mut client = LocalClient::connect(endpoint, LocalClientKind::Cli, build())
        .await
        .ok()?;
    client
        .request(
            Method::AttentionRead,
            &kr_protocol::attention::AttentionReadParams {
                session_id: Nullable::some(session_id),
                include_acknowledged: true,
                max_items: U64::new(50),
                after: Nullable::null(),
            },
        )
        .await
        .ok()?
        .ok()?
        .to_typed()
        .ok()
}

/// The host events a worker of this release records for an agent turn that ended and a command that
/// failed, as (kind, detail), written by this release's own journal.
fn rows_this_release_records_of_a_session_s_work() -> Vec<(String, String)> {
    let mut journal = kr_worker::journal::Journal::in_memory().expect("a journal");
    journal
        .record_session_event(
            &kr_protocol::attention::SessionEventNotice::TurnCompleted {
                turn_id: kr_protocol::ids::AgentTurnId::new("turn-1").expect("an identifier"),
            },
            0,
            kr_protocol::scalars::TimestampMs::new(1),
        )
        .expect("the turn is recorded");
    journal
        .record_session_event(
            &kr_protocol::attention::SessionEventNotice::CommandCompleted {
                exit_status: U64::new(3),
            },
            0,
            kr_protocol::scalars::TimestampMs::new(1),
        )
        .expect("the command is recorded");
    journal
        .host_events()
        .expect("the rows read")
        .into_iter()
        .map(|event| (event.kind, event.detail))
        .collect()
}

/// KR-REQ-26.06, KR-REQ-23.34, KR-REQ-20.23, KR-ACC-035, KR-REQ-18.01: a device paired with the
/// updated host's daemon over the network, as a phone is, meets the worker of the release before
/// through the new daemon. The daemon lists the session, reads it, its description, and its
/// attention inbox at the worker's level, which holds a notification that worker recorded after
/// rows of kinds only this release writes, and closes it for the device, answering with what the
/// worker answered; the worker is the process it was throughout.
#[tokio::test(flavor = "multi_thread")]
async fn a_device_at_the_door_of_the_updated_host_meets_the_worker_of_the_release_before() {
    use kr_protocol::describe::{SessionDescribeParams, SessionDescribeResult};
    use kr_protocol::session::{
        SessionCloseParams, SessionCloseResult, SessionListParams, SessionListResult,
        SessionReadParams, SessionReadResult,
    };

    let updated = Updated::on_the_network_with_an_agent().await;
    let host = &updated.host;
    let door = door::Door::pair_the_first_owner(
        &host
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint"),
        host.tree.environment_id(),
    )
    .await;
    let session = &door.session;
    let session_id = updated.session_id;

    let listed: SessionListResult = session
        .read(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed: false,
            },
        )
        .await
        .expect("the device lists the sessions");
    let summary = listed
        .sessions
        .iter()
        .find(|summary| summary.session_id == session_id)
        .unwrap_or_else(|| panic!("the session is listed: {listed:?}"));
    assert!(summary.closure.0.is_none(), "{summary:?}");

    let read: SessionReadResult = session
        .read(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("the device reads the session");
    assert_eq!(read.session.session_id, session_id, "{read:?}");

    let described: SessionDescribeResult = session
        .read(
            Method::SessionDescribe,
            &SessionDescribeParams { session_id },
        )
        .await
        .expect("the device reads the description");
    assert_eq!(described.session_id, session_id, "{described:?}");

    // The attention inbox the daemon keeps for the session, built from what the worker reported.
    // The worker's journal then holds what a worker of this release records of a session's own
    // work, which the worker of the release before reads as host events of kinds it does not know,
    // and a notification as that release records it, after them. The inbox gains the notification
    // and nothing for the work, and has no gap: the page of the worker of the release before
    // carries no member this release added, and the rows it carries are read through.
    let notices = |inbox: &kr_protocol::attention::AttentionReadResult| {
        inbox
            .items
            .iter()
            .filter(|item| item.rule == kr_protocol::attention::AttentionRule::ApplicationNotice)
            .count()
    };
    let before = read_inbox_through(session, session_id)
        .await
        .expect("the device reads the attention inbox");
    assert_eq!(
        notices(&before),
        0,
        "the control: the inbox holds no notification before the worker records one"
    );
    let mut rows = rows_this_release_records_of_a_session_s_work();
    rows.push((
        "notification".to_owned(),
        "Normal: the build finished".to_owned(),
    ));
    insert_host_events(&host.tree.environment().journal_database(session_id), &rows);
    let attention = until(
        "the inbox to hold the notification the worker of the release before recorded",
        || async {
            let inbox = read_inbox_through(session, session_id).await?;
            (notices(&inbox) > 0).then_some(inbox)
        },
    )
    .await;
    assert!(attention.gaps.is_empty(), "{attention:?}");
    assert!(
        attention.items.iter().all(|item| !matches!(
            item.rule,
            kr_protocol::attention::AttentionRule::ReviewReady
                | kr_protocol::attention::AttentionRule::CommandFailed
        )),
        "the work this release records is no item of a worker that does not report it: {attention:?}"
    );

    // The launch surface is read of the worker, and the worker of the release before has no row for
    // it: it would refuse it as it refuses any method it does not serve, which reads as a missing
    // right. It states what it serves, so the daemon refuses the read itself and sends it nothing,
    // and the device is told the host does not serve the read. The read goes on a connection of its
    // own, as a phone's session screen does, because a connection that reads from a worker ends
    // with the worker's session.
    let screen = door.connect_again().await;
    assert_eq!(
        screen
            .read_launch_surface(session_id)
            .await
            .expect("the read is answered"),
        kr_client::LaunchSurfaceRead::NotServed
    );
    screen.close();

    // The worker is the process it was, and runs the release before.
    updated.the_worker_is_as_it_was().await;

    // The device closes the session, and the worker's own answer comes back through the daemon.
    let settled = session
        .mutate(
            Method::SessionClose,
            kr_protocol::envelope::ActionTarget {
                environment_id: host.tree.environment_id(),
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            None,
            &Empty {},
            &SessionCloseParams { session_id },
            kr_protocol::scalars::DurationMs::new(120_000),
        )
        .await
        .expect("the device closes the session");
    let closed: SessionCloseResult = settled
        .to_typed()
        .expect("the host answers with the closure the worker gave");
    assert_eq!(closed.session_id, session_id, "{closed:?}");
    host.worker_ended(&updated.worker).await;
    host.released(updated.one.name()).await;

    // The daemon keeps the closed session's record, with the worker's closure.
    let closed = until(
        "the closed session to be listed with its closure",
        || async {
            let listed: SessionListResult = session
                .read(
                    Method::SessionList,
                    &SessionListParams {
                        environment_id: Nullable::null(),
                        include_closed: true,
                    },
                )
                .await
                .ok()?;
            listed
                .sessions
                .into_iter()
                .find(|summary| summary.session_id == session_id && summary.closure.0.is_some())
        },
    )
    .await;
    assert!(closed.closure.0.is_some(), "{closed:?}");
}

/// KR-REQ-13.11, KR-REQ-26.06: a device of this release that meets a host still on the release
/// before is told that the host does not serve the launch surface, and is not told it lacks a right.
/// That daemon does not list the method and refuses it as it refuses any method it does not list,
/// `PERMISSION_DENIED`; the client asks for what the same right reads, which is answered, and asks
/// again, which is refused as before.
#[tokio::test(flavor = "multi_thread")]
async fn a_device_of_this_release_is_told_the_host_before_it_does_not_serve_the_launch_surface() {
    let prepared = Updated::prepare(Setup {
        network: true,
        ..Setup::default()
    })
    .await;
    let host = &prepared.host;
    let door = door::Door::pair_the_first_owner(
        &host
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint"),
        host.tree.environment_id(),
    )
    .await;

    let read = door
        .session
        .read_launch_surface(prepared.session_id)
        .await
        .expect("a host that does not serve the read is not one that refuses the device");
    assert_eq!(read, kr_client::LaunchSurfaceRead::NotServed);
    drop(door);
    host.close(&prepared.kr_before(), &prepared.display);
    host.worker_ended(&prepared.worker).await;
}

/// KR-REQ-09.10, KR-REQ-26.06, KR-REQ-20.23: a mutation a paired device makes, which the daemon of
/// this release takes a remote dispatch lease for, is performed by the worker of the release
/// before.
///
/// That worker reads no lease and holds the daemon's deadline and the revision its grant was
/// checked at, so the daemon sends it the frame it read before this release and not the lease: a
/// frame that carried one is refused by name at that level and nothing is sent. The device attaches
/// to the session through the updated daemon, and the worker, which is the process it was
/// throughout, admits the attachment.
#[tokio::test(flavor = "multi_thread")]
async fn a_mutation_of_a_paired_device_is_performed_by_the_worker_of_the_release_before_through_the_daemon_of_this_release()
 {
    use kr_protocol::attachment::{
        AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
    };
    use kr_protocol::scalars::CanonicalSet;
    use kr_protocol::session::Dimensions;

    let updated = Updated::on_the_network().await;
    let host = &updated.host;
    let owner = door::Door::pair_the_first_owner(
        &host
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint"),
        host.tree.environment_id(),
    )
    .await;
    let session_id = updated.session_id;

    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    let settled = owner
        .session
        .mutate(
            Method::SessionAttach,
            kr_protocol::envelope::ActionTarget {
                environment_id: host.tree.environment_id(),
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            None,
            &Empty {},
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
            kr_protocol::scalars::DurationMs::new(120_000),
        )
        .await
        .expect("the worker of the release before admits the device's attach");
    let attached: SessionAttachResult = settled
        .to_typed()
        .expect("the worker answers with the attachment it made");
    assert!(
        attached
            .attachment
            .granted
            .contains(&AttachmentCapability::ObserveTerminal),
        "the attachment observes the terminal: {attached:?}"
    );

    // The worker is the process it was, and runs the release before. The session is closed with
    // this release's own `kr`, which reaches the daemon's local socket, and nothing is read over the
    // device's connection after the worker ends: its link to the worker ends with it.
    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_now(), &updated.display);
    host.worker_ended(&updated.worker).await;
    drop(owner);
}

/// KR-REQ-26.06, KR-REQ-08.53, KR-REQ-20.23: a device paired with the updated host types into the
/// session of the release before through the new daemon. Its bytes are written in the shape that
/// worker reads and the session's shell runs them; its console key records are refused by the
/// daemon, by name, because that worker has no counterpart for them, and the shell runs nothing of
/// them. The refused write spends no sequence number: the next bytes write takes it.
///
/// Each line the shell runs makes a file named by an arithmetic expansion the typed text does not
/// contain, so a file shows that the line was run and not that it was typed. The files are waited
/// for while the session is live, which is when the worker forwards what it accepted.
#[tokio::test(flavor = "multi_thread")]
async fn a_paired_device_types_bytes_into_the_session_of_the_release_before_and_its_key_records_are_refused()
 {
    use kr_protocol::attachment::{
        AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
    };
    use kr_protocol::error::ErrorCode;
    use kr_protocol::ids::{InputLeaseEpoch, InputSequence};
    use kr_protocol::input::{
        ConsoleKey, InputAcquireParams, InputAcquireResult, InputContent, InputWriteParams,
    };
    use kr_protocol::scalars::{Bytes, CanonicalSet, DurationMs};
    use kr_protocol::session::Dimensions;

    let updated = Updated::on_the_network().await;
    let host = &updated.host;
    let owner = door::Door::pair_the_first_owner(
        &host
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint"),
        host.tree.environment_id(),
    )
    .await;
    let session_id = updated.session_id;
    let target = || kr_protocol::envelope::ActionTarget {
        environment_id: host.tree.environment_id(),
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };

    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    let attached: SessionAttachResult = owner
        .session
        .mutate(
            Method::SessionAttach,
            target(),
            None,
            &Empty {},
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
            DurationMs::new(120_000),
        )
        .await
        .expect("the worker of the release before admits the device's attach")
        .to_typed()
        .expect("the worker answers with the attachment it made");
    assert!(
        attached
            .attachment
            .granted
            .contains(&AttachmentCapability::Input),
        "the attachment may type: {attached:?}"
    );
    let attachment_id = attached.attachment.attachment_id;
    let lease: InputAcquireResult = owner
        .session
        .mutate(
            Method::InputAcquire,
            target(),
            None,
            &Empty {},
            &InputAcquireParams {
                session_id,
                attachment_id,
                expected_epoch: Nullable::null(),
            },
            DurationMs::new(120_000),
        )
        .await
        .expect("the device takes the input lease")
        .to_typed()
        .expect("a lease");
    let write = |sequence: u64, input: InputContent| InputWriteParams {
        session_id,
        attachment_id,
        epoch: lease.lease.epoch,
        sequence: InputSequence::new(sequence),
        input,
    };
    let marks = host.scratch("typed");
    // A line that makes the file `<name>-42`, named by an expansion the shell has to run.
    let typed = |name: &str| InputContent::Bytes {
        bytes: Bytes::new(format!(": > '{}'/{name}-$((6*7))\n", marks.display()).into_bytes()),
    };

    owner
        .session
        .write_input(&write(0, typed("kept")))
        .await
        .expect("the worker of the release before takes the bytes of a paired device");

    // Key records spelling a line the shell must not run. The refusal is the daemon's: a worker of
    // the release before would answer with an invalid argument.
    let keys = format!(": > '{}'/refused-$((6*7))\n", marks.display())
        .chars()
        .map(|character| ConsoleKey {
            virtual_key: 0,
            scan_code: 0,
            unicode: u16::try_from(u32::from(character)).expect("a basic plane character"),
            key_down: true,
            control_keys: 0,
            repeat: 1,
        })
        .collect();
    let refused = owner
        .session
        .write_input(&write(1, InputContent::ConsoleKeys { keys }))
        .await
        .expect_err("the daemon has no way to give key records to that worker");
    assert_eq!(
        refused.code(),
        ErrorCode::UnsupportedCapability,
        "{refused}"
    );
    owner
        .session
        .write_input(&write(1, typed("after")))
        .await
        .expect("the refused write spent no sequence number");

    // The shell ran the lines it was given, in order: the file of the line after the refusal is
    // there, so a line of the refused records, which came before it, has been run if it ever was.
    for name in ["kept-42", "after-42"] {
        let file = marks.join(name);
        until(
            &format!("the shell to run the line that makes {name}"),
            || async { file.exists().then_some(()) },
        )
        .await;
    }
    assert!(
        !marks.join("refused-42").exists(),
        "the shell ran nothing of the refused key records"
    );

    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_now(), &updated.display);
    host.worker_ended(&updated.worker).await;
    drop(owner);
}

/// KR-REQ-26.06, KR-REQ-26.08, KR-REQ-20.23, KR-REQ-09.10: a host on the newest release of this
/// build's own level is updated to this build, by that release's own `kr`, while a session's worker
/// still runs the release. The worker is the process it was; a device paired with the new daemon has
/// the mutation it makes forwarded, with the dispatch lease this level's frames carry, to that
/// worker, which admits it, so the updated control daemon speaks the protocol of the worker that
/// stays alive; and this build's `kr` reads that worker's frames itself (`kr status`, which never
/// hands a session over) and a person types at the session through `kr attach`. A level is one
/// surface, so none of it needs a rewrite, and a release at the level that lacked a member of the
/// level would fail here.
#[tokio::test(flavor = "multi_thread")]
async fn inside_the_level_an_update_leaves_the_worker_running_and_serves_a_device_and_kr_attach() {
    use kr_protocol::attachment::{
        AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
    };
    use kr_protocol::scalars::CanonicalSet;
    use kr_protocol::session::Dimensions;

    let Some(before) = inside_the_level_for(
        "inside_the_level_an_update_leaves_the_worker_running_and_serves_a_device_and_kr_attach",
    ) else {
        return;
    };
    let updated = Updated::prepare_on(
        before,
        Setup {
            network: true,
            ..Setup::default()
        },
    )
    .await
    .update()
    .await;
    let host = &updated.host;
    let owner = door::Door::pair_the_first_owner(
        &host
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint"),
        host.tree.environment_id(),
    )
    .await;
    let session_id = updated.session_id;

    // The device's mutation goes through the new daemon, with the lease, to the worker of the
    // release before, which is at the same level and admits it.
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    let settled = owner
        .session
        .mutate(
            Method::SessionAttach,
            kr_protocol::envelope::ActionTarget {
                environment_id: host.tree.environment_id(),
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            None,
            &Empty {},
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
            kr_protocol::scalars::DurationMs::new(120_000),
        )
        .await
        .expect("the worker of the release at this level admits the device's attach");
    let attached: SessionAttachResult = settled
        .to_typed()
        .expect("the worker answers with the attachment it made");
    assert!(
        attached
            .attachment
            .granted
            .contains(&AttachmentCapability::ObserveTerminal),
        "{attached:?}"
    );
    updated.the_worker_is_as_it_was().await;

    // This build's `kr` reads the worker's frames itself: `kr status` never hands a session to the
    // `kr` of another release (it refuses a worker of another level, exit 8), so that it reads this
    // one says the frames are the same. A person then types at the session through `kr attach`.
    let read = host.run(&updated.kr_now(), &["--json", "status", &updated.display]);
    assert!(
        read.status.success(),
        "this build's kr reads the worker of the release at its level: {}{}",
        String::from_utf8_lossy(&read.stdout),
        String::from_utf8_lossy(&read.stderr)
    );
    let read: Value = serde_json::from_slice(&read.stdout).expect("a document");
    assert_eq!(read["session_id"], updated.session_id.to_string(), "{read}");
    // Only the worker's own answer carries its attachments: a status the daemon answered in its
    // place, as it does when the worker cannot be reached, does not.
    assert!(read["terminal_attachments"].is_array(), "{read}");
    let typing = terminal_for(host, &updated.kr_now(), &["attach", &updated.display]);
    typing.ready().await;
    updated.the_worker_is_as_it_was().await;
    drop(typing);

    host.close(&updated.kr_now(), &updated.display);
    host.worker_ended(&updated.worker).await;
    drop(owner);
}

/// KR-REQ-26.10, KR-REQ-26.08, KR-REQ-09.10: after an update inside a level, a session started by
/// this build has a worker of this build; a rollback to the release at the level goes on beside it,
/// without waiting, because the release speaks this level's frames; the workers of both releases are
/// the processes they were; a device paired with the rolled-back daemon has the mutation it makes
/// forwarded to this build's worker, which admits it; and the release's own `kr attach` reads that
/// worker and a person types at it.
#[tokio::test(flavor = "multi_thread")]
async fn inside_the_level_a_rollback_goes_on_beside_a_worker_of_this_build_and_serves_a_device() {
    use kr_protocol::attachment::{
        AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
    };
    use kr_protocol::scalars::CanonicalSet;
    use kr_protocol::session::Dimensions;

    let Some(before) = inside_the_level_for(
        "inside_the_level_a_rollback_goes_on_beside_a_worker_of_this_build_and_serves_a_device",
    ) else {
        return;
    };
    let updated = Updated::prepare_on(
        before,
        Setup {
            network: true,
            ..Setup::default()
        },
    )
    .await
    .update()
    .await;
    let host = &updated.host;

    // A session of this build: its worker is the process the rollback has to leave running.
    let (display, session_now) = host.new_session(&updated.kr_now());
    let worker_now = host.worker_process(session_now);
    assert_eq!(
        host.worker_build(session_now).await,
        format!("kr-worker/{}", updated.two.name()),
        "the new session's worker is this build's"
    );

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a rollback to a release at this level does not wait for a session of this build: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(updated.one.name().clone())
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", updated.one.name()),
        "the daemon is the release at this level again"
    );
    updated.the_worker_is_as_it_was().await;
    assert_eq!(host.worker_process(session_now), worker_now);
    assert_eq!(
        host.worker_build(session_now).await,
        format!("kr-worker/{}", updated.two.name()),
        "this build's worker still runs"
    );

    // A device paired with the rolled-back daemon reaches this build's worker through it.
    let owner = door::Door::pair_the_first_owner(
        &host
            .tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint"),
        host.tree.environment_id(),
    )
    .await;
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    let settled = owner
        .session
        .mutate(
            Method::SessionAttach,
            kr_protocol::envelope::ActionTarget {
                environment_id: host.tree.environment_id(),
                session_id: Nullable::some(session_now),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            None,
            &Empty {},
            &SessionAttachParams {
                session_id: session_now,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
            kr_protocol::scalars::DurationMs::new(120_000),
        )
        .await
        .expect("this build's worker admits the device's attach through the rolled-back daemon");
    let attached: SessionAttachResult = settled
        .to_typed()
        .expect("the worker answers with the attachment it made");
    assert!(
        attached
            .attachment
            .granted
            .contains(&AttachmentCapability::ObserveTerminal),
        "{attached:?}"
    );

    // The release's own `kr` reads this build's worker, which is at its level: `kr status` reads
    // it itself, and a person types at the session through `kr attach`.
    let read = host.run(&updated.kr_before(), &["--json", "status", &display]);
    assert!(
        read.status.success(),
        "the release's kr reads the worker of this build: {}{}",
        String::from_utf8_lossy(&read.stdout),
        String::from_utf8_lossy(&read.stderr)
    );
    let read: Value = serde_json::from_slice(&read.stdout).expect("a document");
    assert_eq!(read["session_id"], session_now.to_string(), "{read}");
    assert!(read["terminal_attachments"].is_array(), "{read}");
    let typing = terminal_for(host, &updated.kr_before(), &["attach", &display]);
    typing.ready().await;
    drop(typing);
    assert_eq!(host.worker_process(session_now), worker_now);

    host.close(&updated.kr_before(), &display);
    host.worker_ended(&worker_now).await;
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
    drop(owner);
}

/// A terminal running `program` with the arguments, as a person's does on this host.
fn terminal_for(host: &Host, program: &Path, arguments: &[&str]) -> terminal::Terminal {
    let mut command = portable_pty::CommandBuilder::new(program);
    command.args(arguments);
    command.env_clear();
    command.env("PATH", "/usr/bin:/bin");
    command.env("KR_RUNTIME_DIR", host.tree.paths().runtime_root());
    command.env("KR_STATE_DIR", host.tree.paths().state_root());
    terminal::Terminal::run(command, host.tree.root())
}

impl Updated {
    /// Opens the gate of the contact session, so its root shell becomes the contact server of
    /// the release that is current, and connects a Model Context Protocol client to that server.
    async fn contact_client(&self) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
        use rmcp::ServiceExt as _;

        let pipes = self
            .contact
            .as_ref()
            .expect("a host set up with a contact session");
        let gate = pipes.gate.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;

            // A write end opened without waiting is refused until the root shell reads the gate.
            let deadline = Instant::now() + LIVENESS_DEADLINE;
            loop {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&gate)
                {
                    Ok(mut gate) => {
                        gate.write_all(b"\n").expect("lets the root shell past");
                        return;
                    }
                    Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                        assert!(
                            Instant::now() < deadline,
                            "the root shell never read the gate"
                        );
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("opens the gate: {error}"),
                }
            }
        })
        .await
        .expect("the gate is opened");
        // The server opens its input first and its output second, and each open waits for the other
        // end. Neither end here waits: the input's writer is opened as soon as the server's open of
        // it is waiting (a reader that waits in `open` counts as one), and the output's reader
        // after it. A server that never opens its input, or never answers the handshake, fails the
        // case at the deadline.
        let deadline = Instant::now() + LIVENESS_DEADLINE;
        let writer = loop {
            match tokio::net::unix::pipe::OpenOptions::new().open_sender(&pipes.to_server) {
                Ok(writer) => break writer,
                Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                    assert!(
                        Instant::now() < deadline,
                        "the server never opened its input"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("opens the server's input: {error}"),
            }
        };
        let reader = tokio::net::unix::pipe::OpenOptions::new()
            .open_receiver(&pipes.from_server)
            .expect("opens the server's output");
        tokio::time::timeout(LIVENESS_DEADLINE, ().serve((reader, writer)))
            .await
            .expect("the tool server answered the handshake in time")
            .expect("the tool server answered the handshake")
    }
}

/// Calls one contact tool and returns its structured content and whether it failed.
async fn call_tool(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &str,
    arguments: Value,
) -> (Value, bool) {
    let result = tokio::time::timeout(
        LIVENESS_DEADLINE,
        client.call_tool(
            rmcp::model::CallToolRequestParams::new(name.to_owned())
                .with_arguments(arguments.as_object().cloned().unwrap_or_default()),
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("{name} did not answer within {LIVENESS_DEADLINE:?}"))
    .unwrap_or_else(|error| panic!("{name} answered: {error}"));
    let content = result
        .structured_content
        .clone()
        .unwrap_or_else(|| panic!("{name} returned structured content"));
    (content, result.is_error.unwrap_or_default())
}

/// KR-REQ-26.06, KR-ACC-035: the contact server of this release, the root of a session whose worker
/// is of the release before, asks the person's question through that release's `kr`. The `kr` of
/// this release does not read the worker, so it lists the question as unread and does not answer
/// it; the `kr` of the release before lists and answers it, and the server returns the answer.
#[tokio::test(flavor = "multi_thread")]
async fn the_contact_server_of_this_release_asks_the_worker_of_the_release_before_and_gets_its_answer()
 {
    let updated = Updated::with_a_contact_session().await;
    let host = &updated.host;
    let client = updated.contact_client().await;
    let (created, failed) = call_tool(
        &client,
        "ask_user",
        json!({
            "request_id": "ask-1",
            "agent_name": "a test agent",
            "context": "two ways to do it",
            "question": "which one?",
            "type": "select",
            "choices": [
                {"choice_id": "left", "label": "Left"},
                {"choice_id": "right", "label": "Right"}
            ]
        }),
    )
    .await;
    assert!(!failed, "the question was created: {created}");
    assert_eq!(created["state"], "pending", "{created}");
    let question_id = created["question_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let token = created["caller_token"]
        .as_str()
        .expect("a token")
        .to_owned();

    // This release's `kr` does not read the worker: the question is not among its questions, and
    // the session it did not read is named with the `kr` that reads it.
    let listed = host.run(&updated.kr_now(), &["--json", "question", "list"]);
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("a document");
    assert_eq!(listed["questions"], json!([]), "{listed}");
    assert_eq!(
        listed["unread"].as_array().map(Vec::len),
        Some(1),
        "{listed}"
    );
    let refused = host.run(
        &updated.kr_now(),
        &["question", "answer", &question_id, "--other", "neither"],
    );
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        !refused.status.success(),
        "this release's kr does not answer it: {said}"
    );
    assert!(
        said.contains(&updated.kr_before().display().to_string()),
        "and it names the kr that reads the worker: {said}"
    );

    // The release before's `kr` lists and answers it.
    let theirs = host.run(&updated.kr_before(), &["--json", "question", "list"]);
    assert!(
        theirs.status.success(),
        "{}",
        String::from_utf8_lossy(&theirs.stderr)
    );
    let theirs: Value = serde_json::from_slice(&theirs.stdout).expect("a document");
    assert_eq!(
        theirs["questions"][0]["question_id"],
        question_id.as_str(),
        "{theirs}"
    );
    let answered = host.run(
        &updated.kr_before(),
        &[
            "question",
            "answer",
            &question_id,
            "--other",
            "neither",
            "--json",
        ],
    );
    assert!(
        answered.status.success(),
        "the release before's kr answers: {}",
        String::from_utf8_lossy(&answered.stderr)
    );

    let (waited, failed) = call_tool(
        &client,
        "wait_for_answer",
        json!({"question_id": question_id, "caller_token": token, "wait_seconds": 20}),
    )
    .await;
    assert!(!failed, "the wait answered: {waited}");
    assert_eq!(waited["state"], "answered", "{waited}");
    assert_eq!(waited["answer"]["text"], "neither", "{waited}");

    updated.the_worker_is_as_it_was().await;
    drop(client);
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// The catalogue's own builder of signed generations, for a package this suite writes.
#[allow(dead_code)]
#[path = "../../kr-plugin-catalogue/tests/support/mod.rs"]
mod generations;

/// The variable that makes a placed copy of this binary a program a person starts in a session: it
/// sleeps for as many seconds as it names.
const STAND_IN: &str = "KR_RUNTIME_STAND_IN";

/// The variable naming a file the program writes its process number to once it runs.
const STAND_IN_RUNNING: &str = "KR_RUNTIME_STAND_IN_RUNNING";

/// The stand-in program's body. Run by the test harness with nothing set, it does nothing.
#[test]
fn the_stand_in_program() {
    if let Ok(seconds) = std::env::var(STAND_IN) {
        if let Some(running) = std::env::var_os(STAND_IN_RUNNING) {
            std::fs::write(running, std::process::id().to_string()).expect("says it is running");
        }
        let until = Instant::now() + Duration::from_secs(seconds.parse().unwrap_or(60));
        std::thread::sleep(until.saturating_duration_since(Instant::now()));
    }
}

fn the_plugin() -> kr_protocol::ids::PluginId {
    kr_protocol::ids::PluginId::new("kalareach/example-declarative").expect("an identifier")
}

fn directory_url(path: &Path) -> url::Url {
    url::Url::from_directory_path(std::fs::canonicalize(path).expect("an existing directory"))
        .expect("an absolute path")
}

/// The example declarative package with the built test component shipped in it, written into
/// `into`. The component is built by `scripts/build-plugin-fixtures.sh`; the suite fails, and does
/// not skip, when it is absent.
fn write_package(into: &Path) {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins");
    let component = std::fs::read(fixtures.join("components/build/well-behaved.wasm"))
        .unwrap_or_else(|error| {
            panic!(
                "the test component is not built ({error}); run scripts/build-plugin-fixtures.sh"
            )
        });
    let example = fixtures.join("valid/example-declarative");
    std::fs::create_dir_all(into).expect("a package directory");
    std::fs::copy(
        example.join("presentation.json"),
        into.join("presentation.json"),
    )
    .expect("the presentation");
    let mut manifest: Value = serde_json::from_slice(
        &std::fs::read(example.join("plugin.json")).expect("the example manifest"),
    )
    .expect("a manifest");
    manifest["payloads"]
        .as_array_mut()
        .expect("the manifest lists its payloads")
        .push(json!({
            "role": "component",
            "path": "component.wasm",
            "digest": kr_plugin_sdk::digest::PayloadDigest::of(&component).to_string(),
            "size_bytes": component.len().to_string(),
        }));
    std::fs::write(
        into.join("plugin.json"),
        serde_json::to_vec_pretty(&manifest).expect("a manifest"),
    )
    .expect("the manifest");
    std::fs::write(into.join("component.wasm"), component).expect("the component");
}

/// Enrols a repository holding the package as the owner acting directly, synchronises it, and
/// installs and enables the package, before any daemon opens the catalogue.
async fn install_plugin(host: &Host) {
    use kr_plugin_catalogue::transport::RepositoryTransport;
    use kr_plugin_catalogue::{
        CapabilityCeiling, Catalogue, Enrolment, InstallationGrant, RepositoryId, RepositoryKind,
    };

    let published = tempfile::tempdir().expect("a directory on the internal disk");
    let package = published.path().join("package");
    write_package(&package);
    let generation = generations::Generation::build(
        published.path(),
        generations::GenerationSpec {
            package: Some(package),
            ..generations::GenerationSpec::default()
        },
    )
    .await;
    let environment = host.tree.environment();
    let directory = generation.directory();
    let mut catalogue = Catalogue::open(
        &environment.state_dir().join("catalogue"),
        Arc::new(RepositoryTransport::local_only(
            "this test reads its repository from disk",
        )),
    )
    .expect("an openable catalogue");
    let id = RepositoryId::new("development").expect("an identifier");
    catalogue
        .enrol(
            Enrolment::new(
                id.clone(),
                RepositoryKind::Local,
                directory_url(&directory.join("metadata")),
                directory_url(&directory.join("targets")),
                std::fs::read(directory.join("root.json")).expect("a trust root"),
                kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrollable repository"),
            true,
        )
        .expect("the owner adopted the root");
    catalogue.sync(&id).await.expect("a generation");
    let version = kr_plugin_sdk::version::PackageVersion::parse("0.1.0").expect("a version");
    let digest = catalogue
        .index(&id)
        .expect("activated")
        .find(&the_plugin(), &version)
        .expect("the package")
        .manifest_digest;
    catalogue
        .install(
            &id,
            host.tree.environment_id(),
            &the_plugin(),
            &version,
            digest,
            InstallationGrant::none(),
        )
        .await
        .expect("installed");
    catalogue
        .set_enabled(host.tree.environment_id(), &the_plugin(), true)
        .await
        .expect("enabled");
}

/// Waits for `check` to give something, and fails with `what` when it never does.
async fn until<T, F, Fut>(what: &str, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let started = Instant::now();
    loop {
        if let Some(found) = check().await {
            return found;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {:?} for {what}",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

impl Host {
    /// A copy of this test's binary named for the program the example package recognises, placed
    /// on the internal disk.
    fn plugin_agent(&self) -> PathBuf {
        let agent = self.scratch("agent").join("example-agent");
        kr_ipc::testing::place_and_start_once(
            &std::env::current_exe().expect("this test's own binary"),
            &agent,
            &["--exact", "the_stand_in_program", "--test-threads", "1"],
        );
        agent
    }
}

/// The command line a process was started with, as the operating system reports it.
fn command_of(process: &kr_protocol::identity::ProcessStartIdentity) -> String {
    let output = Command::new("ps")
        .args(["-ww", "-o", "args=", "-p", &process.pid.get().to_string()])
        .output()
        .expect("ps runs");
    assert!(output.status.success(), "ps said {}", output.status);
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Types the program the package recognises at a terminal's prompt, and returns its process once
/// it is running. The worker finds the program in the terminal's foreground and binds the package.
async fn start_agent(
    host: &Host,
    typing: &terminal::Terminal,
    agent: &Path,
) -> kr_protocol::identity::ProcessStartIdentity {
    let running = host
        .scratch("agent-running")
        .join(format!("running-{}", kr_ipc::new_uuid()));
    typing.type_line(&format!(
        "{STAND_IN}=300 {STAND_IN_RUNNING}='{}' '{}' --exact the_stand_in_program \
         --test-threads 1 --nocapture",
        running.display(),
        agent.display()
    ));
    let pid = until("the program the line started to run", || async {
        std::fs::read_to_string(&running)
            .ok()
            .and_then(|said| said.trim().parse::<u32>().ok())
    })
    .await;
    kr_ipc::identity::process_start_identity(pid).expect("the program runs")
}

/// Ends a program the test started, by the process recorded for it.
fn end_program(program: &kr_protocol::identity::ProcessStartIdentity) {
    let ended = Command::new("kill")
        .arg(program.pid.get().to_string())
        .status()
        .expect("kill runs");
    assert!(ended.success(), "the recorded program is ended");
}

/// Asserts that the plugin host `process` runs the program of `release` from the store.
fn assert_runs_the_host_of(
    process: &kr_protocol::identity::ProcessStartIdentity,
    release: &ReleaseName,
) {
    assert!(
        command_of(process).contains(&format!("/versions/{release}/bin/kr-plugin-host")),
        "the plugin host is {release}'s: {}",
        command_of(process)
    );
}

/// KR-REQ-05.06, KR-REQ-26.06, KR-REQ-20.23, KR-ACC-035: the plugin host the release before started
/// outlives the update and serves the sessions of both releases. A session of this release binds
/// a component and gets the process the release before started, not another, and so does a session
/// created after the daemon of this release stops and starts again. The host stays until it is
/// ended, whichever session binds to it.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_host_the_release_before_started_serves_the_sessions_of_both_releases() {
    let prepared = Updated::prepare(Setup {
        plugin: true,
        ..Setup::default()
    })
    .await;
    let agent = prepared.host.plugin_agent();
    let first = terminal_for(
        &prepared.host,
        &prepared.kr_before(),
        &["attach", &prepared.display],
    );
    first.ready().await;
    let first_program = start_agent(&prepared.host, &first, &agent).await;
    prepared.host.plugin_holding(1).await;
    let old_host = prepared
        .host
        .plugin_host()
        .expect("the release before started a plugin host");
    assert_runs_the_host_of(&old_host, prepared.one.name());

    let mut updated = prepared.update().await;
    assert_eq!(
        updated.host.plugin_host(),
        Some(old_host.clone()),
        "the update left the release before's host alone"
    );
    updated.host.plugin_holding(1).await;

    // A session of this release binds a component and is served by the same process.
    let (second_display, second_session) = updated.host.new_session(&updated.kr_now());
    let second_worker = updated.host.worker_process(second_session);
    let second = terminal_for(
        &updated.host,
        &updated.kr_now(),
        &["attach", &second_display],
    );
    second.ready().await;
    let second_program = start_agent(&updated.host, &second, &agent).await;
    updated.host.plugin_holding(2).await;
    assert_eq!(
        updated.host.plugin_host(),
        Some(old_host.clone()),
        "this release's session is served by the host the release before started"
    );

    // The daemon of this release stops and starts again: it adopts the host, and a session that
    // binds afterwards is served by it too.
    assert!(
        updated.host.stop_the_daemon().await,
        "no daemon serves the host"
    );
    let controller = updated.host.store.stable(Program::Controller);
    updated.host.start_daemon(&controller).await;
    let host = &updated.host;
    assert_eq!(host.plugin_host(), Some(old_host.clone()));
    host.plugin_holding(2).await;
    let (third_display, third_session) = host.new_session(&updated.kr_now());
    let third_worker = host.worker_process(third_session);
    let third = terminal_for(host, &updated.kr_now(), &["attach", &third_display]);
    third.ready().await;
    let third_program = start_agent(host, &third, &agent).await;
    host.plugin_holding(3).await;
    assert_eq!(
        host.plugin_host(),
        Some(old_host.clone()),
        "the daemon adopted the host and started no other"
    );
    assert_eq!(
        kr_ipc::identity::process_state(&old_host),
        kr_ipc::identity::ProcessState::Running,
        "a host runs until it is ended"
    );

    updated.the_worker_is_as_it_was().await;
    for program in [&first_program, &second_program, &third_program] {
        end_program(program);
    }
    drop(third);
    drop(second);
    drop(first);
    host.close(&updated.kr_now(), &third_display);
    host.worker_ended(&third_worker).await;
    host.close(&updated.kr_now(), &second_display);
    host.worker_ended(&second_worker).await;
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
    host.end_the_plugin_host().await;
}

/// KR-REQ-05.06, KR-REQ-26.06, KR-REQ-20.23, KR-ACC-035: with no plugin host running, a program the
/// package recognises, started in the session of the release before after the update, makes its
/// worker ask the daemon of this release for the plugin runtime. The daemon starts this release's
/// own host, the worker registers with it, and when the host ends under the running program the
/// daemon starts another of this release's.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_of_the_release_before_gets_the_plugin_host_this_releases_daemon_starts() {
    let updated = Updated::prepare(Setup {
        plugin: true,
        ..Setup::default()
    })
    .await
    .update()
    .await;
    let host = &updated.host;
    assert_eq!(
        host.plugin_host(),
        None,
        "no program has wanted a plugin host yet"
    );
    let agent = host.plugin_agent();
    let old = terminal_for(host, &updated.kr_before(), &["attach", &updated.display]);
    old.ready().await;
    let program = start_agent(host, &old, &agent).await;

    // First use: the daemon starts this release's host.
    host.plugin_holding(1).await;
    let first = host
        .plugin_host()
        .expect("the daemon started a host for the worker of the release before");
    assert_runs_the_host_of(&first, updated.two.name());

    // The host ends under the program still running; the worker asks again and gets another of
    // this release's.
    host.end_the_plugin_host().await;
    let second = host.another_plugin_host(&first).await;
    assert_runs_the_host_of(&second, updated.two.name());
    host.plugin_holding(1).await;

    updated.the_worker_is_as_it_was().await;
    // The program ends before the session does: a worker whose host ends while its program runs
    // asks for another, and nothing here would end that one.
    end_program(&program);
    drop(old);
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
    host.end_the_plugin_host().await;
}

/// KR-REQ-05.06, KR-REQ-26.06, KR-REQ-26.08, KR-REQ-26.10, KR-ACC-035: a rollback waits for a live
/// session of this release (exit 9, naming it) and then goes on. The plugin host this release's
/// daemon started survives it, running and published, and a session the release before's daemon
/// then creates binds a component and is served by that host, which the daemon adopts.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_leaves_the_plugin_host_of_this_release_for_the_release_before_to_adopt() {
    let updated = Updated::prepare(Setup {
        plugin: true,
        ..Setup::default()
    })
    .await
    .update()
    .await;
    let host = &updated.host;
    let agent = host.plugin_agent();
    let (second_display, second_session) = host.new_session(&updated.kr_now());
    let second_worker = host.worker_process(second_session);
    let second = terminal_for(host, &updated.kr_now(), &["attach", &second_display]);
    second.ready().await;
    let second_program = start_agent(host, &second, &agent).await;
    host.plugin_holding(1).await;
    let this_host = host
        .plugin_host()
        .expect("this release's daemon started a host");
    assert_runs_the_host_of(&this_host, updated.two.name());

    // The session of this release holds the rollback.
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(9),
        "a rollback waits for a session of this release: {said}"
    );
    assert!(
        said["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&format!(
                "session {second_display} runs kr-worker/{}",
                updated.two.name()
            )),
        "{said}"
    );
    assert_eq!(
        host.store.current().expect("reads"),
        Some(updated.two.name().clone()),
        "nothing was switched"
    );

    // Its program and session end, and the rollback goes on.
    end_program(&second_program);
    drop(second);
    host.close(&updated.kr_now(), &second_display);
    host.worker_ended(&second_worker).await;
    host.plugin_holding(0).await;
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
    assert_eq!(
        host.plugin_host(),
        Some(this_host.clone()),
        "this release's host survived the rollback"
    );
    assert_eq!(
        kr_ipc::identity::process_state(&this_host),
        kr_ipc::identity::ProcessState::Running,
        "this release's host runs on"
    );

    // A session of the release before binds a component; its daemon adopts the host.
    let (third_display, third_session) = host.new_session(&updated.kr_before());
    let third_worker = host.worker_process(third_session);
    let third = terminal_for(host, &updated.kr_before(), &["attach", &third_display]);
    third.ready().await;
    let third_program = start_agent(host, &third, &agent).await;
    host.plugin_holding(1).await;
    assert_eq!(
        host.plugin_host(),
        Some(this_host),
        "the release before's daemon adopted the host this release's daemon started"
    );

    end_program(&third_program);
    drop(third);
    host.close(&updated.kr_before(), &third_display);
    host.worker_ended(&third_worker).await;
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
    host.end_the_plugin_host().await;
}

/// The version the delivery journal records and the privacy generation it holds, read from the
/// file beside the daemon that has it open.
fn delivery_journal_of(host: &Host) -> (i64, i64) {
    let path = host
        .tree
        .environment()
        .state_dir()
        .join(kr_controller::push::DELIVERY_JOURNAL);
    let connection =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("the delivery journal opens");
    let version = connection
        .query_row("SELECT version FROM delivery_schema", [], |row| row.get(0))
        .expect("the journal records a version");
    let generation = connection
        .query_row(
            "SELECT generation FROM delivery_privacy WHERE id = 0",
            [],
            |row| row.get(0),
        )
        .expect("the journal records a privacy generation");
    (version, generation)
}

/// Turns privacy mode on and then off with the `kr` of the current release, which writes the
/// privacy generation of the delivery journal twice. The change can report that it is still
/// settling, so each is asked for until the status says it took.
async fn privacy_on_and_off(host: &Host) {
    for enabled in [true, false] {
        let word = if enabled { "on" } else { "off" };
        until(&format!("privacy mode to be {word}"), || async {
            let _ = host.kr_json(&["privacy", word, "--json"]);
            let (_, status) = host.kr_json(&["privacy", "status", "--json"]);
            (status["enabled"] == Value::Bool(enabled)).then_some(())
        })
        .await;
    }
}

/// KR-REQ-26.10, KR-REQ-26.08: the update brings the delivery journal to version 11 and keeps what
/// it holds; this release writes it; and after a rollback the release before opens it at 11,
/// writes it too, and the file still says 11. The privacy generation is what the suite can see of
/// the journal: no `kr` command reads a notification. Each daemon writes it from the privacy
/// record it keeps, so the case shows the open, the write and the version, and not the content of
/// a notification.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_leaves_the_delivery_journal_at_version_11_and_the_release_before_reads_it() {
    let prepared = Updated::prepare(Setup::default()).await;
    let host = &prepared.host;

    // The release before writes the journal at version 10: two turns of privacy mode are
    // generation 2.
    privacy_on_and_off(host).await;
    assert_eq!(delivery_journal_of(host), (10, 2));

    // The update brings it to 11 and keeps the generation.
    let updated = prepared.update().await;
    let host = &updated.host;
    assert_eq!(
        delivery_journal_of(host),
        (11, 2),
        "the update brought the journal to version 11 and kept what it held"
    );

    // This release writes it.
    privacy_on_and_off(host).await;
    assert_eq!(delivery_journal_of(host), (11, 4));

    // The rollback starts the release before's daemon, which opens the journal at version 11,
    // reads the generation this release wrote and writes the next ones.
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", updated.one.name()),
        "the daemon is the release before's again"
    );
    assert_eq!(delivery_journal_of(host), (11, 4));
    privacy_on_and_off(host).await;
    assert_eq!(
        delivery_journal_of(host),
        (11, 6),
        "the release before wrote the journal and left its version alone"
    );
    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// The retained output an export document carries, joined.
fn exported_output(document: &Value) -> Vec<u8> {
    use base64::Engine as _;

    let mut output = Vec::new();
    for chunk in document["output"]["chunks"]
        .as_array()
        .expect("the retained output is a list of pieces")
    {
        output.extend(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(chunk["base64url"].as_str().expect("base64 text"))
                .expect("the piece decodes"),
        );
    }
    output
}

/// KR-REQ-26.06, KR-REQ-20.23, KR-ACC-029, KR-ACC-035: what the worker of the release before wrote
/// to the session's terminal is kept by the daemon of this release when the session closes, and `kr
/// export` of this release reads it back through the daemon.
#[tokio::test(flavor = "multi_thread")]
async fn the_output_of_a_session_of_the_release_before_is_exported_through_the_daemon_of_this_release()
 {
    let updated = Updated::new().await;
    let host = &updated.host;
    let typing = terminal_for(host, &updated.kr_before(), &["attach", &updated.display]);
    typing.ready().await;
    // The shell computes the marker, so the line as typed does not hold it.
    typing.type_line("echo KEPT-$((6*7))-OUTPUT");
    typing.expect("KEPT-42-OUTPUT").await;
    drop(typing);

    host.close(&updated.kr_now(), &updated.display);
    host.worker_ended(&updated.worker).await;
    let file = host.scratch("export").join("session.json");
    // The daemon refuses an export until it has seen the worker end and has the session's output.
    let started = Instant::now();
    loop {
        let output = host.run(
            &updated.kr_now(),
            &[
                "export",
                &updated.session_id.to_string(),
                "--output",
                &file.display().to_string(),
            ],
        );
        if output.status.success() {
            break;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the closed session was not exported in {:?}: {}",
            started.elapsed(),
            String::from_utf8_lossy(&output.stderr)
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let document: Value = serde_json::from_slice(&std::fs::read(&file).expect("the exported file"))
        .expect("the export is one JSON document");
    assert_eq!(
        document["session"]["session_id"],
        updated.session_id.to_string(),
        "{document}"
    );
    let output = exported_output(&document);
    assert!(
        String::from_utf8_lossy(&output).contains("KEPT-42-OUTPUT"),
        "the export holds what the session showed: {}",
        String::from_utf8_lossy(&output).escape_debug()
    );
    // The closure the worker gave to the close this test asked for, not one the daemon wrote for a
    // worker that was lost.
    assert_eq!(
        document["closure"]["reason"], "close_requested",
        "and the worker's closure: {document}"
    );
    assert_eq!(
        document["closure"]["session_id"],
        updated.session_id.to_string(),
        "{document}"
    );
}

/// KR-REQ-23.34, KR-REQ-26.06, KR-REQ-20.23, KR-ACC-035: the `kr` of the release before issues a
/// share of its session with the live screen to a paired device, at a terminal. The daemon of this
/// release reads the lines on the screen from the worker of the release before, as the share asks,
/// and holds the share, which `kr share list` of this release shows.
#[tokio::test(flavor = "multi_thread")]
async fn a_share_with_the_live_screen_of_the_session_of_the_release_before_is_issued_through_the_daemon_of_this_release()
 {
    let updated = Updated::on_the_network().await;
    let host = &updated.host;
    let controller = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let environment_id = host.tree.environment_id();
    let owner = door::Door::pair_the_first_owner(&controller, environment_id).await;
    owner
        .pair_a_guest(&controller, environment_id, "A guest phone")
        .await;

    let issuing = terminal_for(
        host,
        &updated.kr_before(),
        &[
            "share",
            "invite",
            &updated.display,
            "--to",
            "A guest phone",
            "--live",
        ],
    );
    issuing.expect("to issue this invitation").await;
    issuing.type_line("share");
    let code = issuing.ended().await;
    assert_eq!(
        code,
        0,
        "the release before's kr issued the share: {}",
        issuing.text().escape_debug()
    );

    let listed = host.run(&updated.kr_now(), &["--json", "share", "list"]);
    assert!(
        listed.status.success(),
        "kr share list: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("a document");
    let held: Vec<&Value> = listed["grants"]
        .as_array()
        .expect("a list of shares")
        .iter()
        .filter(|share| share["recipient_name"] == "A guest phone")
        .collect();
    assert_eq!(held.len(), 1, "the guest holds the share: {listed}");
    assert_eq!(held[0]["live_screen"], true, "{listed}");

    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_now(), &updated.display);
    host.worker_ended(&updated.worker).await;
    drop(owner);
}

/// KR-REQ-26.10, KR-REQ-26.08: a rollback to the release before reads every session archived under
/// this release. The journal of a closed session whose root was a command holds the session's
/// summary in the form the release before reads, so the shell and the directory it recorded are
/// what that release shows; the word that says the root was a command is kept in a
/// row of its own, which that release does not read. The host events this release records for an
/// agent turn that ended and a command that failed are in the same journal: this release raised
/// an item for each while the session was live, and after the rollback the release before lists
/// them, with no gap, and serves what it reads of them.
#[tokio::test(flavor = "multi_thread")]
async fn the_release_before_reads_the_journal_of_a_command_session_this_release_wrote() {
    let updated = Updated::new().await;
    let host = &updated.host;

    // A session of this release, live, whose journal takes what a worker of this release records of
    // the session's own work. The daemon of this release raises an item for each before the
    // session closes.
    let (display, session_now) = host.new_session(&updated.kr_now());
    let worker_now = host.worker_process(session_now);
    let path = host.tree.environment().journal_database(session_now);
    insert_host_events(&path, &rows_this_release_records_of_a_session_s_work());
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let raised = |inbox: &kr_protocol::attention::AttentionReadResult,
                  rule: kr_protocol::attention::AttentionRule| {
        inbox.items.iter().any(|item| item.rule == rule)
    };
    until("the daemon of this release to raise the work", || async {
        let inbox = read_inbox_here(&endpoint, session_now).await?;
        (raised(&inbox, kr_protocol::attention::AttentionRule::ReviewReady)
            && raised(&inbox, kr_protocol::attention::AttentionRule::CommandFailed))
        .then_some(())
    })
    .await;

    // The session closes, and its journal is then written as a command session's is: by this
    // release's own writer, from the summary the worker recorded with the marker set.
    host.close(&updated.kr_now(), &display);
    host.worker_ended(&worker_now).await;
    let recorded = {
        let mut journal = kr_worker::journal::Journal::open(&path).expect("opens the journal");
        let mut summary = journal
            .read_session(session_now)
            .expect("reads the summary")
            .expect("the worker recorded the session");
        summary.root = Some(kr_protocol::session::SessionRoot::Command);
        journal
            .record_session(&summary)
            .expect("records the command session");
        assert_eq!(
            journal
                .read_session(session_now)
                .expect("reads it back")
                .expect("the summary")
                .root,
            Some(kr_protocol::session::SessionRoot::Command),
            "this release reads the marker back"
        );
        summary
    };

    // The rollback goes on beside the release before's own session, and that release's `kr` reads
    // the closed session whole.
    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", updated.one.name()),
        "the daemon is the release before's again"
    );
    let read = host.run(&updated.kr_before(), &["--json", "status", &display]);
    assert!(
        read.status.success(),
        "the release before's kr status: {}",
        String::from_utf8_lossy(&read.stderr)
    );
    let read: Value = serde_json::from_slice(&read.stdout).expect("a document");
    assert_eq!(read["session_id"], session_now.to_string(), "{read}");
    assert_eq!(read["shell"], recorded.shell_path, "{read}");
    assert_eq!(
        read["cwd"], recorded.cwd,
        "the directory the journal recorded is shown, not a summary rebuilt from the closure: {read}"
    );

    // The release before's daemon lists what this release raised from the rows it does not know,
    // with no gap, and serves what it reads of them: the line of identifiers, then the words.
    let inbox = until(
        "the daemon of the release before to list the work this release raised",
        || async {
            let inbox = read_inbox_here(&endpoint, session_now).await?;
            (raised(&inbox, kr_protocol::attention::AttentionRule::ReviewReady)
                && raised(&inbox, kr_protocol::attention::AttentionRule::CommandFailed)
                && inbox.items.iter().all(|item| item.summary.0.is_some()))
            .then_some(inbox)
        },
    )
    .await;
    assert!(inbox.gaps.is_empty(), "{inbox:?}");
    let words = |rule: kr_protocol::attention::AttentionRule| {
        inbox
            .items
            .iter()
            .find(|item| item.rule == rule)
            .and_then(|item| item.summary.0.clone())
            .unwrap_or_default()
    };
    assert!(
        words(kr_protocol::attention::AttentionRule::ReviewReady).starts_with("turn-1\n"),
        "{inbox:?}"
    );
    assert!(
        words(kr_protocol::attention::AttentionRule::CommandFailed).starts_with("3\n"),
        "{inbox:?}"
    );

    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// KR-REQ-26.10, KR-REQ-26.08, KR-REQ-25.25: a session of this release keeps when its output was
/// produced in a store of its own beside the spool, which the release before does not name. A
/// rollback leaves that store where it is, and the release before reads the session's output from
/// its spool by its own rules: the bytes and the file its `kr export` writes are all there.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_leaves_the_record_of_when_output_was_produced_and_the_release_before_exports_the_output()
 {
    let updated = Updated::new().await;
    let host = &updated.host;

    let (display, session_now) = host.new_session(&updated.kr_now());
    let worker_now = host.worker_process(session_now);
    let typing = terminal_for(host, &updated.kr_now(), &["attach", &display]);
    typing.ready().await;
    // The shell computes the marker, so the line as typed does not hold it.
    typing.type_line("echo KEPT-$((6*7))-OUTPUT");
    typing.expect("KEPT-42-OUTPUT").await;
    drop(typing);
    host.close(&updated.kr_now(), &display);
    host.worker_ended(&worker_now).await;
    let times = host.tree.environment().session_output_times(session_now);
    assert!(
        times.is_file(),
        "the session's worker kept when its output was produced in {}",
        times.display()
    );

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "kr host rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", updated.one.name()),
        "the daemon is the release before's again"
    );
    assert!(times.is_file(), "the rollback leaves the store alone");

    let file = host.scratch("export-after-rollback").join("session.json");
    let started = Instant::now();
    loop {
        let output = host.run(
            &updated.kr_before(),
            &[
                "export",
                &session_now.to_string(),
                "--output",
                &file.display().to_string(),
            ],
        );
        if output.status.success() {
            break;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the release before did not export the closed session in {:?}: {}",
            started.elapsed(),
            String::from_utf8_lossy(&output.stderr)
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let document: Value = serde_json::from_slice(&std::fs::read(&file).expect("the exported file"))
        .expect("the export is one JSON document");
    assert_eq!(
        document["session"]["session_id"],
        session_now.to_string(),
        "{document}"
    );
    let output = exported_output(&document);
    assert!(
        String::from_utf8_lossy(&output).contains("KEPT-42-OUTPUT"),
        "the release before exports what the session showed: {}",
        String::from_utf8_lossy(&output).escape_debug()
    );

    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// KR-REQ-26.07, KR-REQ-20.23: the local window outlasts the public one. A host whose daemon states
/// public major 2 lists only major 2 to a device, so a device of major 1 is refused at the door; and
/// in the same run that daemon adopts the live worker of the release before, which speaks major 1
/// and is at a level the daemon retains, and the session is kept: the worker is the process it was,
/// the `kr` of release two, which states major 2, closes it through the daemon, so the daemon of
/// this release speaks the protocol of the worker that outlived the update, and a client of major 1
/// is refused by that daemon.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_of_a_later_public_major_keeps_the_session_of_the_release_before() {
    let mut updated = Updated::on_the_network().await;
    let host = &mut updated.host;
    assert!(host.stop_the_daemon().await, "the daemon stops");
    let controller = host.store.stable(Program::Controller);
    host.start_daemon_with(
        &controller,
        &[(LATER_MAJOR_VARIABLE, std::ffi::OsStr::new("2"))],
        &[],
    )
    .await;
    let endpoint = host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let later = kr_protocol::hello::ProtocolVersion::new(LATER_MAJOR, 0);
    assert_eq!(host.daemon_states().await, LATER_MAJOR);

    // Major 1 has left the device list: a device that offers it is refused at the door.
    assert_eq!(
        door::refused_at_the_door(&endpoint, host.tree.environment_id(), later).await,
        kr_protocol::error::ErrorCode::UnsupportedSchema
    );
    // And the daemon admits clients of the major it states alone.
    assert!(
        LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .is_err(),
        "a client of major 1 is refused by a daemon that states major 2"
    );

    // The worker of the release before, which speaks major 1, is still reached through the daemon
    // of major 2, and the session is kept.
    updated.the_worker_is_as_it_was().await;
    let host = &updated.host;
    let (closed, said) = host.kr_json_with(
        &[(LATER_MAJOR_VARIABLE, std::ffi::OsStr::new("2"))],
        &["close", &updated.display, "--json"],
    );
    assert!(
        closed.status.success(),
        "release two's kr closes the session through the daemon of major 2: {said} {}",
        String::from_utf8_lossy(&closed.stderr)
    );
    host.worker_ended(&updated.worker).await;
    host.released(updated.one.name()).await;
}

/// KR-REQ-26.07, KR-REQ-26.10: a rollback goes back across a public major beside a live worker of
/// the release before. The host's daemon states major 2 beside the session's worker, which speaks
/// major 1 (the case before shows the daemon adopting it); release two's `kr`, which states major 2,
/// looks at that worker with the offer of a build that retains its level, finds its level held by
/// the release it goes back to, and goes ahead: the daemon is the release before's again, and the
/// worker is the process it was.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_from_a_daemon_of_a_later_public_major_goes_on_beside_the_session_of_the_release_before()
 {
    // The rollback's own `kr` states major 2, and the daemon it restores is the release before's,
    // which states its own major whatever variable the program that starts it carries.
    let mut updated = Updated::start(Setup {
        states_its_own_major: true,
        ..Setup::default()
    })
    .await;
    let host = &mut updated.host;
    assert!(host.stop_the_daemon().await, "the daemon stops");
    let controller = host.store.stable(Program::Controller);
    host.start_daemon_with(
        &controller,
        &[(LATER_MAJOR_VARIABLE, std::ffi::OsStr::new("2"))],
        &[],
    )
    .await;
    assert_eq!(host.daemon_states().await, LATER_MAJOR);
    updated.the_worker_is_as_it_was().await;

    let host = &updated.host;
    let (output, said) = host.kr_json_with(
        &[(LATER_MAJOR_VARIABLE, std::ffi::OsStr::new("2"))],
        &["host", "rollback", "--json"],
    );
    assert!(
        output.status.success(),
        "a rollback across a public major goes ahead beside the worker: {said} {}",
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
    assert_eq!(host.daemon_states().await, 1, "and it states major 1 again");
    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// The definition E2 installs: three apply nodes in the shape the release before stored them, with
/// no object for a reference to move to. One is a reference apply that is not a preflight, which a
/// release that moves a reference would refuse for naming none, one is a preflight and one is a
/// proposal.
fn a_definition_of_stored_apply_nodes(
    grant: kr_protocol::ids::GrantId,
) -> kr_protocol::automation::WorkflowDefinition {
    use kr_protocol::automation::{
        WorkflowActionKind, WorkflowDeadlines, WorkflowDefinition, WorkflowNode,
        WorkflowResourceScope, WorkflowTrigger,
    };
    use kr_protocol::changeset::{DestinationClass, DiffApplyParams, ExpectedReference};
    use kr_protocol::ids::{ChangeSetId, ChangeSetVersion, WorkflowId, WorkspaceId};
    use kr_protocol::scalars::{U64, Uuid};

    let params = |edit: &dyn Fn(&mut DiffApplyParams)| {
        let mut params = DiffApplyParams {
            change_set_id: ChangeSetId::new(Uuid::from_bytes([0x33; 16])),
            version: ChangeSetVersion::new(1),
            destination: DestinationClass::Proposal,
            workspace_id: Nullable::some(WorkspaceId::new(Uuid::from_bytes([0x34; 16]))),
            expected_reference: Nullable::null(),
            affected: Vec::new(),
            paths: Vec::new(),
            preflight_only: false,
            acknowledged_limitations: Vec::new(),
        };
        edit(&mut params);
        serde_json::to_string(&params).expect("the node's parameters")
    };
    let reference = |expected: Nullable<String>| {
        Nullable::some(ExpectedReference {
            name: "refs/heads/main".to_owned(),
            expected_old_value: expected,
            new_value: Nullable::null(),
        })
    };
    let node = |id: &str, action_params: String| WorkflowNode {
        node_id: id.to_owned(),
        action_kind: WorkflowActionKind::ApplyDiff,
        action_params,
        declared_environment: Nullable::null(),
    };
    WorkflowDefinition {
        workflow_id: WorkflowId::new(Uuid::from_bytes([0x41; 16])),
        revision: U64::new(1),
        name: "stored apply nodes".to_owned(),
        description: Nullable::null(),
        trigger: WorkflowTrigger {
            event_type: "manual".to_owned(),
        },
        resource_scope: WorkflowResourceScope::default(),
        nodes: vec![
            node(
                "move",
                params(&|params| {
                    params.destination = DestinationClass::VersionedReference;
                    params.expected_reference = reference(Nullable::null());
                }),
            ),
            node(
                "preflight",
                params(&|params| {
                    params.destination = DestinationClass::VersionedReference;
                    params.expected_reference = reference(Nullable::some("a".repeat(40)));
                    params.preflight_only = true;
                }),
            ),
            node("proposal", params(&|_| {})),
        ],
        edges: Vec::new(),
        deadlines: WorkflowDeadlines::default(),
        grant_reference: grant,
        enabled: false,
        explicit_recurrence: false,
    }
}

/// One workflow mutation, made over the daemon's own socket as the person at the host, and what the
/// daemon answered.
async fn a_workflow_mutation<P: serde::Serialize + ?Sized>(
    endpoint: &kr_ipc::paths::Endpoint,
    environment_id: kr_protocol::ids::EnvironmentId,
    method: Method,
    params: &P,
) -> Result<kr_protocol::envelope::ParamsValue, kr_protocol::error::ProtocolError> {
    let mut client = LocalClient::connect(endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    client
        .mutate(
            method,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            kr_protocol::envelope::ActionTarget::environment(environment_id),
            params,
        )
        .await
        .expect("the call reaches the daemon")
}

/// KR-REQ-25.13, KR-REQ-26.10, KR-REQ-26.08: a definition the release before stored is admitted by
/// this release and by the release before again after a rollback, whatever its apply nodes say.
///
/// A stored apply node is decoded again at every run's admission, and the release before decodes
/// it in the shape it stored. A node this release lets a reference move to an object with is not a
/// node a stored one can be, and a stored one that names none must stay admitted: a run of the
/// definition returns a run each time, and never a refusal that names a node. The apply nodes
/// themselves are refused by name when the run reaches them, as they always were.
///
/// This case is rewritten when the workflows store keeps the object a reference moves to.
#[tokio::test(flavor = "multi_thread")]
async fn a_stored_apply_node_is_admitted_across_an_update_and_a_rollback() {
    use kr_protocol::automation::{
        WorkflowEnableParams, WorkflowInstallParams, WorkflowRunParams, WorkflowRunResult,
    };

    let prepared = Updated::prepare(Setup {
        network: true,
        ..Setup::default()
    })
    .await;
    let endpoint = prepared
        .host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let environment_id = prepared.host.tree.environment_id();
    // The grant a workflow acts under is one the host issued, and the first owner's carries every
    // right, the right to apply a diff among them.
    let owner = door::Door::pair_the_first_owner(&endpoint, environment_id).await;
    let document = a_definition_of_stored_apply_nodes(owner.grant_id);
    let _: kr_protocol::automation::WorkflowInstallResult = a_workflow_mutation(
        &endpoint,
        environment_id,
        Method::WorkflowInstall,
        &WorkflowInstallParams {
            workflow_id: document.workflow_id,
            revision: document.revision,
            definition: document.clone(),
            grant_reference: document.grant_reference,
        },
    )
    .await
    .expect("the release before installs the definition")
    .to_typed()
    .expect("an install result");
    a_workflow_mutation(
        &endpoint,
        environment_id,
        Method::WorkflowEnable,
        &WorkflowEnableParams {
            workflow_id: document.workflow_id,
            revision: document.revision,
        },
    )
    .await
    .expect("the release before enables it");

    let run = |event: &'static str| {
        let (endpoint, document) = (endpoint.clone(), document.clone());
        async move {
            a_workflow_mutation(
                &endpoint,
                environment_id,
                Method::WorkflowRun,
                &WorkflowRunParams {
                    workflow_id: document.workflow_id,
                    revision: document.revision,
                    event_id: event.to_owned(),
                    event_type: "manual".to_owned(),
                    event_payload: Nullable::null(),
                },
            )
            .await
            .unwrap_or_else(|refusal| {
                panic!("a run of a stored definition is admitted ({event}): {refusal:?}")
            })
            .to_typed::<WorkflowRunResult>()
            .expect("a run result")
        }
    };
    run("evt-before-the-update").await;

    let updated = prepared.update().await;
    run("evt-after-the-update").await;

    let (output, said) = updated.host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "the rollback goes ahead: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        updated.host.daemon_build().await,
        format!("kr-controller/{}", updated.one.name()),
        "the daemon is the release before's again"
    );
    run("evt-after-the-rollback").await;
    drop(owner);
}

/// KR-REQ-26.10, KR-REQ-26.08, KR-REQ-24.15: the record that a restored policy waits for the person
/// at the machine is a store of its own that the release before does not name. A host that reads it
/// refuses an owner device for the wait. A rollback to the release before is not refused, and it
/// leaves the record where it was, unread: the release before serves the same device, which is the
/// loss the guide states. An update again finds the record, and the host waits again, refusing the
/// device and with the record rewritten to name the policy it holds, and the moment the restore was
/// found and the list of what the wait owes kept, until the person at the machine has revoked what
/// the list names and confirms.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_leaves_the_record_of_a_restored_policy_and_an_update_again_waits_on_it() {
    use kr_controller::grants::restored::{self, Found, Record};
    use kr_protocol::organisation::{HostPolicyConfirmParams, HostPolicyConfirmResult};

    let mut updated = Updated::on_the_network().await;
    let environment = updated.host.tree.environment();
    let file = restored::file_beside(&environment.registry_database());
    let endpoint = environment.controller_endpoint().expect("an endpoint");

    // An owner device is paired with this release's daemon, and the host binds where it listens
    // now, so that the device dials the same socket after each restart.
    let door =
        door::Door::pair_the_first_owner(&endpoint, updated.host.tree.environment_id()).await;
    door.is_served_again()
        .await
        .expect("the control: with no wait standing the owner device is served");
    // A device the wait will owe: the record lists it, and the release before knows nothing of the
    // list.
    let guest = door
        .pair_a_guest(&endpoint, updated.host.tree.environment_id(), "A guest")
        .await;
    assert!(updated.host.stop_the_daemon().await, "the daemon stops");
    bind_the_network_at(&updated.host, &door.host_socket().to_string());
    let owed = restored::Owed {
        origin: kr_protocol::scalars::Digest256::from_bytes([9; 32]),
        target: restored::Target::Device(guest),
    };
    let found = Record {
        owed: vec![owed],
        ..Record::of(
            kr_protocol::scalars::Digest256::from_bytes([7; 32]),
            kr_protocol::scalars::TimestampMs::new(1_000),
        )
    };
    restored::write(&file, &found).expect("a record of a restore");
    let controller = updated.host.store.stable(Program::Controller);
    updated.host.start_daemon(&controller).await;
    let host = &updated.host;
    let refusal = door
        .is_served_again()
        .await
        .expect_err("a daemon that reads the record refuses the device for the wait");
    assert!(
        refusal
            .to_string()
            .contains("restored from an earlier state"),
        "refused for the restored policy: {refusal}"
    );
    // The record named another policy, so the start rewrote it to name the one the host holds and
    // kept the moment the restore was found.
    let Found::Record(held) = restored::read(&file) else {
        panic!("the record stands");
    };
    assert_ne!(held.subject, found.subject);
    assert_eq!(held.found_at_ms, found.found_at_ms);
    assert_eq!(held.owed, vec![owed], "and kept the list");
    let written = std::fs::read(&file).expect("the record reads");

    let (output, said) = host.kr_json(&["host", "rollback", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a record of a restore does not refuse a rollback: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", updated.one.name()),
        "the daemon is the release before's again"
    );
    assert_eq!(
        std::fs::read(&file).expect("the record is still there"),
        written,
        "the release before leaves the record alone"
    );
    door.is_served_again()
        .await
        .expect("the release before does not read the record, and serves the device");

    let archive = host.scratch("archives").join("two-again.tar.gz");
    updated.two.archive(&archive);
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
        "the update again goes ahead: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        host.daemon_build().await,
        format!("kr-controller/{}", updated.two.name()),
        "the daemon is this build's again"
    );
    assert_eq!(
        std::fs::read(&file).expect("the record is still there"),
        written,
        "the update again finds the record as it was left, naming the policy the host holds, with \
         the moment the restore was found"
    );
    let refusal = door
        .is_served_again()
        .await
        .expect_err("the host waits again and refuses the device");
    assert!(
        refusal
            .to_string()
            .contains("restored from an earlier state"),
        "refused for the restored policy again: {refusal}"
    );

    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    let refused = pairing::mutate_as::<_, HostPolicyConfirmResult>(
        host.tree.environment_id(),
        &mut client,
        kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
        Method::HostPolicyConfirm,
        &HostPolicyConfirmParams {},
    )
    .await
    .expect_err("the guest the list owes is live, so the wait is not ended");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::PermissionDenied
    );
    assert!(
        refused.message.contains(&guest.to_string()),
        "the refusal names it: {refused:?}"
    );
    let _: kr_protocol::sharing::RevocationResult = pairing::mutate_as(
        host.tree.environment_id(),
        &mut client,
        kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
        Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams { device_id: guest },
    )
    .await
    .expect("the person at this machine revokes the guest");
    let confirmed: HostPolicyConfirmResult = pairing::mutate_as(
        host.tree.environment_id(),
        &mut client,
        kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
        Method::HostPolicyConfirm,
        &HostPolicyConfirmParams {},
    )
    .await
    .expect("the person at this machine confirms");
    assert!(confirmed.lifted, "the update again found a wait to end");
    assert_eq!(restored::read(&file), Found::Missing, "and it ended it");
    door.is_served_again()
        .await
        .expect("the confirmation lifts the refusal and the device is served");
    updated.the_worker_is_as_it_was().await;
    host.close(&updated.kr_before(), &updated.display);
    host.worker_ended(&updated.worker).await;
}

/// Runs installed Git directly, to build a repository for the host to adopt.
fn git_fixture(directory: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(["-c", "user.name=KalaReach Fixture"])
        .args(["-c", "user.email=fixture@example.invalid"])
        .args(["-c", "commit.gpgSign=false"])
        .args(arguments)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("LC_ALL", "C")
        .output()
        .expect("installed Git runs");
    assert!(
        output.status.success(),
        "the fixture could not be built: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// What a run of the reporting suite is: a workflow of one `run_tests` node against `version`.
fn a_definition_that_runs_the_reporting_suite(
    grant: kr_protocol::ids::GrantId,
    environment_id: kr_protocol::ids::EnvironmentId,
    version: kr_protocol::changeset::VersionRef,
) -> kr_protocol::automation::WorkflowDefinition {
    use kr_protocol::automation::{
        RunTestsParams, WorkflowActionKind, WorkflowDeadlines, WorkflowDefinition, WorkflowNode,
        WorkflowResourceScope, WorkflowTrigger,
    };
    use kr_protocol::ids::WorkflowId;
    use kr_protocol::scalars::{U64, Uuid};

    WorkflowDefinition {
        workflow_id: WorkflowId::new(Uuid::from_bytes([0x42; 16])),
        revision: U64::new(1),
        name: "a suite that writes a report".to_owned(),
        description: Nullable::null(),
        trigger: WorkflowTrigger {
            event_type: "manual".to_owned(),
        },
        resource_scope: WorkflowResourceScope::default(),
        nodes: vec![WorkflowNode {
            node_id: "tests".to_owned(),
            action_kind: WorkflowActionKind::RunTests,
            action_params: serde_json::to_string(&RunTestsParams {
                suite: "reports".to_owned(),
                version,
            })
            .expect("the node's typed parameters"),
            declared_environment: Nullable::some(environment_id),
        }],
        edges: Vec::new(),
        deadlines: WorkflowDeadlines::default(),
        grant_reference: grant,
        enabled: false,
        explicit_recurrence: false,
    }
}

/// One read, made over the daemon's own socket as the person at the host, and what the daemon
/// answered.
async fn a_host_read<P: serde::Serialize + ?Sized, T: kr_protocol::wire::WireMessage>(
    endpoint: &kr_ipc::paths::Endpoint,
    method: Method,
    params: &P,
) -> Result<T, kr_protocol::error::ProtocolError> {
    let mut client = LocalClient::connect(endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    client
        .request(method, params)
        .await
        .expect("the call reaches the daemon")
        .map(|answer| answer.to_typed().expect("an answer of the declared shape"))
}

/// KR-REQ-25.06, KR-REQ-26.10, KR-REQ-26.08: what this release reads out of a suite's reports lives
/// in a store of its own, which the release before ignores, so a rollback loses nothing it protected
/// and an update brings the reports back.
///
/// The release before runs the suite (its result carries the declared output's reference and no
/// report), this release runs it again (a result and a report row), the release before reads that
/// result and its evidence as it reads any, refuses the method that reads reports as a method it
/// does not list, and records a run of its own with no row; this release then serves the one row,
/// bound to the run it came from. A `kr` of this release tells that daemon from a lost right.
#[tokio::test(flavor = "multi_thread")]
async fn a_report_store_the_release_before_ignores_is_kept_across_a_rollback_and_an_update() {
    use kr_protocol::automation::{
        WorkflowEnableParams, WorkflowInstallParams, WorkflowRunParams, WorkflowRunResult,
    };
    use kr_protocol::changeset::{ChangesetReadParams, ChangesetReadResult, VersionRef};
    use kr_protocol::error::ErrorCode;
    use kr_protocol::ids::{ChangeSetId, ChangeSetVersion};
    use kr_protocol::scalars::Uuid;
    use kr_protocol::test_report::{ReportReading, TestReportsParams, TestReportsResult};

    let prepared = Updated::prepare(Setup {
        network: true,
        suite: true,
        ..Setup::default()
    })
    .await;
    let endpoint = prepared
        .host
        .tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let environment_id = prepared.host.tree.environment_id();
    let owner = door::Door::pair_the_first_owner(&endpoint, environment_id).await;

    // A repository with one edit in it, adopted, its own tree selected, and one version of that.
    let source = prepared.host.scratch("work").join("source");
    std::fs::create_dir_all(&source).expect("a directory for the repository");
    git_fixture(&source, &["init", "--initial-branch=main"]);
    std::fs::write(source.join("README.md"), "a repository\n").expect("a tracked file");
    git_fixture(&source, &["add", "-A"]);
    git_fixture(&source, &["commit", "-m", "the first commit"]);
    std::fs::write(source.join("README.md"), "changed after the commit\n").expect("a dirty file");
    let said = |(output, said): (Output, Value)| {
        assert!(
            output.status.success(),
            "{said} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        said
    };
    let adopted =
        said(
            prepared
                .host
                .kr_json(&["project", "adopt", &source.display().to_string(), "--json"]),
        );
    let project = adopted["project"]["project_repository_id"]
        .as_str()
        .expect("the project's identifier")
        .to_owned();
    let created = said(prepared.host.kr_json(&[
        "workspace",
        "create",
        &project,
        "--kind",
        "shared",
        "--json",
    ]));
    let workspace = created["workspace"]["workspace_id"]
        .as_str()
        .expect("the workspace's identifier")
        .to_owned();
    let captured = said(prepared.host.kr_json(&[
        "changeset",
        "capture",
        &workspace,
        "--label",
        "the work",
        "--include",
        "all",
        "--json",
    ]));
    let change_set = captured["version"]["change_set_id"]
        .as_str()
        .expect("the change set's identifier")
        .to_owned();
    let version = VersionRef {
        change_set_id: ChangeSetId::new(change_set.parse::<Uuid>().expect("an identifier")),
        version: ChangeSetVersion::new(1),
    };

    let document =
        a_definition_that_runs_the_reporting_suite(owner.grant_id, environment_id, version);
    a_workflow_mutation(
        &endpoint,
        environment_id,
        Method::WorkflowInstall,
        &WorkflowInstallParams {
            workflow_id: document.workflow_id,
            revision: document.revision,
            definition: document.clone(),
            grant_reference: document.grant_reference,
        },
    )
    .await
    .expect("the release before installs the definition");
    a_workflow_mutation(
        &endpoint,
        environment_id,
        Method::WorkflowEnable,
        &WorkflowEnableParams {
            workflow_id: document.workflow_id,
            revision: document.revision,
        },
    )
    .await
    .expect("the release before enables it");
    let run = |event: &'static str| {
        let (endpoint, document) = (endpoint.clone(), document.clone());
        async move {
            let run: WorkflowRunResult = a_workflow_mutation(
                &endpoint,
                environment_id,
                Method::WorkflowRun,
                &WorkflowRunParams {
                    workflow_id: document.workflow_id,
                    revision: document.revision,
                    event_id: event.to_owned(),
                    event_type: "manual".to_owned(),
                    event_payload: Nullable::null(),
                },
            )
            .await
            .unwrap_or_else(|refusal| panic!("the run is admitted ({event}): {refusal:?}"))
            .to_typed()
            .expect("a run result");
            assert_eq!(
                run.status,
                kr_protocol::automation::WorkflowRunStatus::Completed,
                "the suite ends with status 0 against the version ({event}): {run:?}"
            );
        }
    };
    let results = || {
        let endpoint = endpoint.clone();
        async move {
            a_host_read::<_, ChangesetReadResult>(
                &endpoint,
                Method::ChangesetRead,
                &ChangesetReadParams {
                    change_set_id: version.change_set_id,
                    version: Nullable::some(version.version),
                },
            )
            .await
            .expect("changeset.read answers")
            .results
        }
    };
    let reports = || {
        let endpoint = endpoint.clone();
        async move {
            a_host_read::<_, TestReportsResult>(
                &endpoint,
                Method::ChangesetTestReports,
                &TestReportsParams {
                    change_set_id: version.change_set_id,
                    version: Nullable::some(version.version),
                    materialisation_id: Nullable::null(),
                },
            )
            .await
        }
    };

    // The release before: a result, and a method it does not list.
    run("evt-before-the-update").await;
    assert_eq!(results().await.len(), 1);
    let refused = reports()
        .await
        .expect_err("the release before lists no such method");
    assert_eq!(refused.code, ErrorCode::PermissionDenied);

    // This release: a result and the report beside it, bound to that run.
    let updated = prepared.update().await;
    run("evt-after-the-update").await;
    let after_the_update = results().await;
    assert_eq!(after_the_update.len(), 2);
    let second = after_the_update[1].materialisation_id;
    let answered = reports().await.expect("this release reads reports");
    let [report] = &answered.reports[..] else {
        panic!("one report, of the run this release made: {answered:?}");
    };
    assert_eq!(report.materialisation_id, second);
    assert!(
        matches!(&report.reading, ReportReading::Parsed { totals, .. }
            if totals.tests.get() == 2 && totals.failed.get() == 1),
        "{report:?}"
    );

    // Back to the release before: it reads the result this release wrote as it reads any, ignores
    // the store of reports, and records a run of its own with no row.
    let (output, said) = updated.host.kr_json(&["host", "rollback", "--json"]);
    assert!(
        output.status.success(),
        "the rollback goes ahead: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        updated.host.daemon_build().await,
        format!("kr-controller/{}", updated.one.name()),
        "the daemon is the release before's again"
    );
    let after_the_rollback = results().await;
    assert_eq!(after_the_rollback.len(), 2);
    assert_eq!(
        after_the_rollback[1], after_the_update[1],
        "the result this release wrote reads as it was"
    );
    run("evt-after-the-rollback").await;
    assert_eq!(results().await.len(), 3);
    assert_eq!(
        reports()
            .await
            .expect_err("the release before still lists no such method")
            .code,
        ErrorCode::PermissionDenied
    );
    // The `kr` of this release asks again with a read the release before lists, which is answered,
    // so what it says is that the daemon is too old and not that a right is missing.
    let refused = updated.host.run(
        &updated.kr_now(),
        &["changeset", "test-reports", &change_set, "--json"],
    );
    assert!(!refused.status.success());
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(said.contains("update"), "{said}");

    // Forward again: the store the release before left alone serves the one report of the run it
    // was written for, and none for the runs the release before made.
    let archive = updated.host.scratch("archives").join("two-again.tar.gz");
    updated.two.archive(&archive);
    let (output, said) = updated.host.kr_json(&[
        "host",
        "update",
        "--archive",
        &archive.display().to_string(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the update again goes on: {said} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        updated.host.daemon_build().await,
        format!("kr-controller/{}", updated.two.name()),
        "the daemon is of the new release again"
    );
    let again = reports().await.expect("this release reads reports again");
    let [report] = &again.reports[..] else {
        panic!("the one report is served again: {again:?}");
    };
    assert_eq!(report.materialisation_id, second);
    drop(owner);
}
