//! The core readers' lines for the website's release matrix.
//!
//! The managed service's matrix is deployed from the website's repository, and a host release of
//! this repository reads it with the `kr-release-matrix-check` of its own commit. Before a revision
//! is deployed, the reader of every host release, of each release this build retains and of this
//! build read the exact candidate, and the lines they leave say which tier each found for its
//! version. The website's deployment holds the matrix to those lines.
//!
//! A reader pins the production key and cannot verify a matrix signed by a test, so each run signs
//! the candidate with a key of its own and builds every reader with that key in place of its pin
//! and nothing else changed: its parser and its first revision stay the release's own. The trees
//! and their dependency builds come from the cache; each run compiles every reader again.
//!
//! The real run, `make_the_readers_lines`, builds each distinct commit's reader once and is run by
//! hand on a clean checkout of main (`KR_CANDIDATE`, `KR_REGISTER`, `KR_LINES_OUT` and
//! `KR_READER_CACHE`, each an absolute path). The cases that do not build a reader run in the
//! ordinary suite against a fixture repository and stand-in readers.
#![cfg(unix)]

#[path = "support/previous_reader.rs"]
mod previous_reader;
#[path = "support/reader_roster.rs"]
mod reader_roster;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use previous_reader::{Build, CacheGuard, Job, Reading};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// One row of the website's register of host releases.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    tag: String,
    commit: String,
    version: String,
}

/// A release this build retains, as its release record names it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Retained {
    commit: String,
    version: String,
}

/// The four paths a run is given, each absolute.
struct Paths {
    candidate: PathBuf,
    register: PathBuf,
    lines_out: PathBuf,
    cache: PathBuf,
}

/// The paths a run is given, as `get` finds them by name. A relative path names a different folder
/// from each directory a run starts in, so it is refused before any work.
fn read_inputs(get: impl Fn(&str) -> Option<String>) -> Result<Paths, String> {
    let mut found = Vec::new();
    for name in [
        "KR_CANDIDATE",
        "KR_REGISTER",
        "KR_LINES_OUT",
        "KR_READER_CACHE",
    ] {
        let value = get(name).ok_or_else(|| format!("{name} is not set"))?;
        if !Path::new(&value).is_absolute() {
            return Err(format!(
                "The core readers take absolute paths: {name} is `{value}`. Give an absolute path, then run them again."
            ));
        }
        found.push(PathBuf::from(value));
    }
    let mut found = found.into_iter();
    Ok(Paths {
        candidate: found.next().expect("the candidate"),
        register: found.next().expect("the register"),
        lines_out: found.next().expect("the lines' file"),
        cache: found.next().expect("the cache"),
    })
}

/// The register's rows, from the website's `host-releases.json`.
fn read_register(bytes: &[u8]) -> Result<Vec<Row>, String> {
    let rows: Value =
        serde_json::from_slice(bytes).map_err(|error| format!("register: {error}"))?;
    let rows = rows.as_array().ok_or("the register is not a list")?;
    rows.iter()
        .map(|row| {
            let field = |name: &str| {
                row[name]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("a register row has no `{name}`"))
            };
            Ok(Row {
                tag: field("tag")?,
                commit: field("commit")?,
                version: field("version")?,
            })
        })
        .collect()
}

/// The releases a build retains, from their release records: each record's commit and the package
/// version in its `release` line, before the `+`.
fn header_writer(records: &[&str]) -> Result<Vec<Retained>, String> {
    records
        .iter()
        .map(|record| {
            let commit = kr_protocol::retained::record(record, "commit")
                .ok_or("a release record has no `commit`")?;
            let release = kr_protocol::retained::record(record, "release")
                .ok_or("a release record has no `release`")?;
            Ok(Retained {
                commit: commit.to_owned(),
                version: release.split('+').next().unwrap_or(release).to_owned(),
            })
        })
        .collect()
}

/// This build's own retained releases.
fn retained_here() -> Vec<Retained> {
    let records: Vec<&str> = kr_protocol::retained::RETAINED
        .iter()
        .map(|level| level.release)
        .collect();
    header_writer(&records).expect("the retained records name their commits and versions")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `HEAD` when this checkout is at the tip of origin's main and has no change, else what differs.
fn clean_main(repository: &Path) -> Result<String, String> {
    let head = previous_reader::git(repository, &["rev-parse", "HEAD"])?
        .trim()
        .to_owned();
    let remote = previous_reader::git(repository, &["ls-remote", "origin", "refs/heads/main"])?;
    let main = remote.split_whitespace().next().unwrap_or("");
    if main.is_empty() {
        return Err("origin has no main".to_owned());
    }
    if head != main {
        return Err(format!("HEAD is {head} and origin's main is {main}"));
    }
    let changes = previous_reader::git(
        repository,
        &["status", "--porcelain", "--untracked-files=all"],
    )?;
    if changes.trim().is_empty() {
        Ok(head)
    } else {
        let shown: Vec<&str> = changes.lines().take(5).collect();
        Err(format!("the tree has changes: {}", shown.join("; ")))
    }
}

/// What one run is given.
struct Setup<'a> {
    /// The checkout the commits come from, at the tip of origin's main.
    repository: &'a Path,
    /// The cache, locked for the run.
    cache: &'a Path,
    /// The candidate file's bytes: the last history file of the website.
    candidate: &'a [u8],
    /// The register's rows.
    register: &'a [Row],
    /// The releases this build retains.
    retained: &'a [Retained],
    /// This build's package version.
    core_version: &'a str,
    /// The text of the public key every reader pins in this run.
    key_text: &'a str,
}

/// What one commit is read as.
#[derive(Default)]
struct Roles {
    host: Vec<String>,
    retained: Option<String>,
    current: bool,
}

impl Roles {
    fn names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if !self.host.is_empty() {
            names.push("host");
        }
        if self.retained.is_some() {
            names.push("retained");
        }
        if self.current {
            names.push("current");
        }
        names
    }

    /// The versions the commit's reader has to report: one for each role.
    fn versions(&self, core_version: &str) -> Vec<String> {
        let mut versions = self.host.clone();
        versions.extend(self.retained.clone());
        if self.current {
            versions.push(core_version.to_owned());
        }
        versions
    }
}

/// The lines file for the candidate: each distinct commit's reader built once and run against it.
///
/// The commits are the register's, the retained releases' and `HEAD`, chosen without looking at the
/// candidate. A commit with no reader is recorded `no reader` and has to be a retained release.
fn make_lines(
    setup: &Setup,
    build: &Build,
    run: &dyn Fn(&Path) -> Result<Reading, String>,
) -> Result<Value, String> {
    let head = clean_main(setup.repository).map_err(|what| {
        format!("The core readers run only on a clean checkout of core's main: {what}.")
    })?;
    let _guard = CacheGuard::take(setup.cache)?;
    let matrix: Value =
        serde_json::from_slice(setup.candidate).map_err(|error| format!("candidate: {error}"))?;
    let revision = matrix["revision"]
        .as_str()
        .ok_or("the candidate has no revision")?
        .to_owned();

    let mut commits: BTreeMap<String, Roles> = BTreeMap::new();
    for row in setup.register {
        commits
            .entry(row.commit.clone())
            .or_default()
            .host
            .push(row.version.clone());
    }
    for kept in setup.retained {
        commits.entry(kept.commit.clone()).or_default().retained = Some(kept.version.clone());
    }
    commits.entry(head.clone()).or_default().current = true;

    let mut lines = Vec::new();
    for (commit, roles) in &commits {
        let reading = if previous_reader::has_reader(setup.repository, commit) {
            let tree = previous_reader::extract(setup.repository, commit, setup.cache)?;
            previous_reader::write_patched(setup.repository, commit, &tree, setup.key_text)?;
            let target = setup.cache.join(commit).join("target");
            let program = build(&Job {
                tree: &tree,
                target: &target,
                commit,
            })?;
            let reading = run(&program).map_err(|why| {
                format!(
                    "The reader of {commit} refused the matrix: {why}. A release that cannot read a matrix keeps the copy it holds, so fix the matrix before it is deployed."
                )
            })?;
            for expected in roles.versions(setup.core_version) {
                if reading.version != expected {
                    return Err(format!(
                        "The reader of {commit} reads version {}, where its record says {expected}.",
                        reading.version
                    ));
                }
            }
            Some(reading)
        } else if roles.host.is_empty() && !roles.current && roles.retained.is_some() {
            None
        } else {
            return Err(format!(
                "The commit {commit} has no release matrix program and is not only a retained release, so it cannot be read."
            ));
        };
        let (verdict, version, read_revision) = reading.map_or_else(
            || {
                (
                    "no reader",
                    roles.retained.clone().unwrap_or_default(),
                    revision.clone(),
                )
            },
            |reading| (reading.verdict, reading.version, reading.revision),
        );
        lines.push(json!({
            "commit": commit,
            "version": version,
            "roles": roles.names(),
            "verdict": verdict,
            "revision": read_revision,
        }));
    }

    let after = clean_main(setup.repository).map_err(|what| {
        format!("The tree changed while the readers ran: {what}. Run them again.")
    })?;
    if after != head {
        return Err(format!(
            "The tree changed while the readers ran: HEAD was {head} and is {after}. Run them again."
        ));
    }

    let mut register: Vec<&str> = setup.register.iter().map(|row| row.tag.as_str()).collect();
    register.sort_unstable();
    Ok(json!({
        "candidate_sha256": sha256_hex(setup.candidate),
        "core": { "commit": head, "version": setup.core_version },
        "retained": setup
            .retained
            .iter()
            .map(|kept| json!({ "commit": kept.commit, "version": kept.version }))
            .collect::<Vec<_>>(),
        "register": register,
        "lines": lines,
    }))
}

/// Writes the whole file, as one rename, so a run that fails leaves the earlier file as it was.
fn write_lines(path: &Path, lines: &Value) {
    let text = serde_json::to_string_pretty(lines).expect("the lines are JSON") + "\n";
    let partial = path.with_extension("partial");
    std::fs::write(&partial, text).expect("the lines are written");
    std::fs::rename(&partial, path).expect("the lines replace the earlier file");
}

/* -------------------------------------------------------------------------- */
/* The cases that need no reader built                                         */
/* -------------------------------------------------------------------------- */

/// A repository with a local bare origin, for the cases that run the producer without a build.
mod fixture {
    use super::{Path, PathBuf};
    use crate::previous_reader::{MATRIX_SOURCE, READER_CRATE};

    /// The repository and its origin, in a folder that goes with the value.
    pub struct Repository {
        pub folder: tempfile::TempDir,
        pub work: PathBuf,
        pub commits: Vec<String>,
    }

    pub fn git(directory: &Path, arguments: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(directory)
            .args([
                "-c",
                "user.name=Tester",
                "-c",
                "user.email=tester@example.com",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(arguments)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "git {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// The matrix client of a release, as far as the producer reads it.
    pub const MATRIX_CLIENT: &str = "//! A matrix client.\n\n/// The key.\npub const PRODUCTION_PINS: [&str; 1] = [\"production-key\"];\n\n/// The floor.\npub const PRODUCTION_FIRST_REVISION: u64 = 2;\n";

    /// Two commits that have no reader and one that has, pushed to the origin's main: the first is
    /// a release that predates the program, the last is the head.
    pub fn repository() -> Repository {
        let folder = tempfile::tempdir().expect("a folder");
        let origin = folder.path().join("origin.git");
        let work = folder.path().join("work");
        std::fs::create_dir_all(&origin).expect("origin");
        std::fs::create_dir_all(&work).expect("work");
        git(&origin, &["init", "--bare", "--quiet"]);
        git(&work, &["init", "--quiet"]);
        git(&work, &["checkout", "--quiet", "-b", "main"]);
        git(
            &work,
            &["remote", "add", "origin", origin.to_str().expect("a path")],
        );
        let mut commits = Vec::new();
        std::fs::write(work.join("README"), "a release before the program\n").expect("a file");
        git(&work, &["add", "."]);
        git(&work, &["commit", "--quiet", "-m", "before"]);
        commits.push(git(&work, &["rev-parse", "HEAD"]));
        for (index, name) in ["with the program", "with the program again"]
            .into_iter()
            .enumerate()
        {
            let reader = work.join(READER_CRATE);
            std::fs::create_dir_all(&reader).expect("the crate");
            std::fs::write(
                reader.join("Cargo.toml"),
                "[package]\nname = \"kr-release-matrix-check\"\n",
            )
            .expect("a manifest");
            let client = work.join(MATRIX_SOURCE);
            std::fs::create_dir_all(client.parent().expect("a folder")).expect("the client");
            std::fs::write(&client, MATRIX_CLIENT).expect("the matrix client");
            std::fs::write(work.join("README"), format!("{name} {index}\n")).expect("a file");
            git(&work, &["add", "."]);
            git(&work, &["commit", "--quiet", "-m", name]);
            commits.push(git(&work, &["rev-parse", "HEAD"]));
        }
        git(
            &work,
            &["push", "--quiet", "origin", "HEAD:refs/heads/main"],
        );
        Repository {
            folder,
            work,
            commits,
        }
    }
}

/// The reader of each commit as a script that prints one line and exits, written where the build
/// step is told to put its program, and a count of the builds made.
struct Readers {
    lines: BTreeMap<String, (&'static str, i32)>,
    built: std::cell::RefCell<Vec<String>>,
}

impl Readers {
    fn new(lines: &[(&str, &'static str, i32)]) -> Self {
        Self {
            lines: lines
                .iter()
                .map(|(commit, line, code)| ((*commit).to_owned(), (*line, *code)))
                .collect(),
            built: std::cell::RefCell::default(),
        }
    }

    fn build(&self, job: &Job) -> Result<PathBuf, String> {
        self.built.borrow_mut().push(job.commit.to_owned());
        let (line, code) = self
            .lines
            .get(job.commit)
            .copied()
            .ok_or_else(|| format!("no stand-in reader for {}", job.commit))?;
        std::fs::create_dir_all(job.target).map_err(|error| error.to_string())?;
        let script = job.target.join("reader");
        // The line is quoted for the shell: a single quote in it ends the quote and starts another.
        let quoted = line.replace('\'', "'\\''");
        std::fs::write(&script, format!("printf '%s\\n' '{quoted}'\nexit {code}\n"))
            .map_err(|error| error.to_string())?;
        Ok(script)
    }
}

/// Runs a stand-in reader through the shell and reads its answer.
fn run_stand_in(program: &Path) -> Result<Reading, String> {
    let output = std::process::Command::new("/bin/sh")
        .arg(program)
        .output()
        .map_err(|error| error.to_string())?;
    previous_reader::read_answer(
        output.status.code(),
        &String::from_utf8_lossy(&output.stdout),
    )
}

const COMPATIBLE: &str =
    "release 0.78.0: served by the compatible tier of the release matrix, revision 2";
const LATER: &str = "::warning::release 0.78.0 is served only by a later tier of the release matrix, revision 2: deploy that tier's relay and discovery versions before this release reaches hosts";
const UNSUPPORTED: &str = "::error::release 0.78.0 is in no tier of the release matrix at revision 2: publish a matrix revision that lists it first";

fn candidate_bytes() -> Vec<u8> {
    serde_json::to_vec(&reader_roster::serving_every_release()).expect("a matrix")
}

fn row(tag: &str, commit: &str, version: &str) -> Row {
    Row {
        tag: tag.to_owned(),
        commit: commit.to_owned(),
        version: version.to_owned(),
    }
}

/// Runs the producer on a fixture with the register's rows and the retained commit it names.
fn produce(
    fixture: &fixture::Repository,
    readers: &Readers,
    register: &[Row],
    retained: &[Retained],
    core_version: &str,
) -> Result<Value, String> {
    let cache = fixture.folder.path().join("cache");
    let candidate = candidate_bytes();
    make_lines(
        &Setup {
            repository: &fixture.work,
            cache: &cache,
            candidate: &candidate,
            register,
            retained,
            core_version,
            key_text: "a-key-this-run-made",
        },
        &|job| readers.build(job),
        &run_stand_in,
    )
}

/// KR-REQ-17.46: the readers read only a checkout that is the tip of origin's main.
#[test]
fn the_readers_refuse_a_head_that_is_not_origin_main() {
    let fixture = fixture::repository();
    std::fs::write(fixture.work.join("README"), "a commit origin has not got\n").expect("a file");
    fixture::git(&fixture.work, &["commit", "--quiet", "-a", "-m", "local"]);
    let readers = Readers::new(&[]);
    let refused = produce(&fixture, &readers, &[], &[], "0.78.0").expect_err("a head off main");
    assert!(
        refused
            .starts_with("The core readers run only on a clean checkout of core's main: HEAD is "),
        "{refused}"
    );
    assert!(readers.built.borrow().is_empty(), "nothing was built");

    // A tree with a change is refused the same way, by the same sentence.
    let fixture = fixture::repository();
    std::fs::write(fixture.work.join("stray.txt"), "not committed\n").expect("a file");
    let refused = produce(&fixture, &readers, &[], &[], "0.78.0").expect_err("a changed tree");
    assert!(
        refused.contains("the tree has changes: ?? stray.txt"),
        "{refused}"
    );
}

/// KR-REQ-17.46: lines made from a tree that changed while the readers ran are not written.
#[test]
fn the_readers_refuse_a_tree_that_changed_while_they_ran() {
    let fixture = fixture::repository();
    let head = fixture.commits.last().expect("a head").clone();
    let readers = Readers::new(&[(head.as_str(), COMPATIBLE, 0)]);
    let cache = fixture.folder.path().join("cache");
    let candidate = candidate_bytes();
    let refused = make_lines(
        &Setup {
            repository: &fixture.work,
            cache: &cache,
            candidate: &candidate,
            register: &[],
            retained: &[],
            core_version: "0.78.0",
            key_text: "k",
        },
        &|job| {
            // A build that leaves a file in the checkout it was started from.
            std::fs::write(fixture.work.join("left-behind.txt"), "a build's output\n")
                .map_err(|error| error.to_string())?;
            readers.build(job)
        },
        &run_stand_in,
    )
    .expect_err("a tree that changed");
    assert!(
        refused.starts_with(
            "The tree changed while the readers ran: the tree has changes: ?? left-behind.txt."
        ),
        "{refused}"
    );
}

/// KR-REQ-17.46: a reader that reports another version than the row it stands for fails the run.
#[test]
fn a_reader_whose_version_differs_from_its_row_fails() {
    let fixture = fixture::repository();
    let head = fixture.commits.last().expect("a head").clone();
    let reader = fixture.commits[1].clone();
    let readers = Readers::new(&[
        (head.as_str(), COMPATIBLE, 0),
        (
            reader.as_str(),
            "release 0.79.0: served by the compatible tier of the release matrix, revision 2",
            0,
        ),
    ]);
    let refused = produce(
        &fixture,
        &readers,
        &[row("host/v0.1.0+x", &reader, "0.78.0")],
        &[],
        "0.78.0",
    )
    .expect_err("a version that differs");
    assert!(
        refused.contains(&format!(
            "The reader of {reader} reads version 0.79.0, where its record says 0.78.0."
        )),
        "{refused}"
    );
}

/// KR-REQ-17.46: a reader that cannot read the matrix fails the run and names its commit.
#[test]
fn a_reader_that_refuses_the_matrix_fails_the_run() {
    let fixture = fixture::repository();
    let head = fixture.commits.last().expect("a head").clone();
    // A synthetic matrix of schema version 2 is what such a reader answers for; its answer is an
    // error line that is not a verdict.
    let readers = Readers::new(&[(
        head.as_str(),
        "::error::the published release matrix was not accepted: it is of a schema newer than this build reads",
        1,
    )]);
    let refused = produce(&fixture, &readers, &[], &[], "0.78.0").expect_err("a refusal");
    assert!(
        refused.starts_with(&format!("The reader of {head} refused the matrix: ")),
        "{refused}"
    );
    assert!(
        refused.ends_with("A release that cannot read a matrix keeps the copy it holds, so fix the matrix before it is deployed."),
        "{refused}"
    );
}

/// KR-REQ-17.46: the producer writes the whole file, and builds each distinct commit once.
#[test]
fn the_producer_writes_the_whole_file_and_builds_each_commit_once() {
    let fixture = fixture::repository();
    let (before, shared, head) = (
        fixture.commits[0].clone(),
        fixture.commits[1].clone(),
        fixture.commits[2].clone(),
    );
    let readers = Readers::new(&[
        (shared.as_str(), COMPATIBLE, 0),
        (head.as_str(), COMPATIBLE, 0),
    ]);
    let register = [
        row("host/v0.1.0+aaaaaaaaaaaa", &shared, "0.78.0"),
        row("host/v0.1.0+bbbbbbbbbbbb", &shared, "0.78.0"),
    ];
    let retained = [Retained {
        commit: before.clone(),
        version: "0.77.0".to_owned(),
    }];
    let lines = produce(&fixture, &readers, &register, &retained, "0.78.0").expect("lines");

    assert_eq!(
        *readers.built.borrow(),
        {
            let mut built = vec![shared.clone(), head.clone()];
            built.sort();
            built
        },
        "two rows that name one commit share one build, and the commit with no reader is not built"
    );
    assert_eq!(lines["candidate_sha256"], sha256_hex(&candidate_bytes()));
    assert_eq!(
        lines["core"],
        json!({ "commit": head, "version": "0.78.0" })
    );
    assert_eq!(
        lines["retained"],
        json!([{ "commit": before, "version": "0.77.0" }])
    );
    assert_eq!(
        lines["register"],
        json!(["host/v0.1.0+aaaaaaaaaaaa", "host/v0.1.0+bbbbbbbbbbbb"])
    );
    let found = lines["lines"].as_array().expect("lines");
    assert_eq!(found.len(), 3);
    let line_of = |commit: &str| {
        found
            .iter()
            .find(|line| line["commit"] == commit)
            .expect("a line")
            .clone()
    };
    assert_eq!(
        line_of(&shared),
        json!({ "commit": shared, "version": "0.78.0", "roles": ["host"], "verdict": "compatible", "revision": "2" })
    );
    assert_eq!(
        line_of(&head),
        json!({ "commit": head, "version": "0.78.0", "roles": ["current"], "verdict": "compatible", "revision": "2" })
    );
    assert_eq!(
        line_of(&before),
        json!({ "commit": before, "version": "0.77.0", "roles": ["retained"], "verdict": "no reader", "revision": "2" })
    );

    // The file is the whole answer, written in one rename.
    let out = fixture.folder.path().join("read-by-core.json");
    write_lines(&out, &lines);
    let written: Value =
        serde_json::from_slice(&std::fs::read(&out).expect("the file")).expect("JSON");
    assert_eq!(written, lines);
    assert!(!out.with_extension("partial").exists());
}

/// KR-REQ-17.46: each verdict is the one the reader's exit status and line state.
#[test]
fn each_reader_verdict_is_read_from_its_exit_status_and_line() {
    let fixture = fixture::repository();
    let head = fixture.commits.last().expect("a head").clone();
    for (line, code, verdict) in [
        (COMPATIBLE, 0, "compatible"),
        (LATER, 0, "later"),
        (UNSUPPORTED, 1, "unsupported"),
    ] {
        let readers = Readers::new(&[(head.as_str(), line, code)]);
        let lines = produce(&fixture, &readers, &[], &[], "0.78.0").expect("lines");
        assert_eq!(lines["lines"][0]["verdict"], verdict, "{line}");
    }
    // A verdict line under the wrong exit status is not a verdict.
    let readers = Readers::new(&[(head.as_str(), COMPATIBLE, 1)]);
    produce(&fixture, &readers, &[], &[], "0.78.0").expect_err("a line the status contradicts");
}

/// KR-REQ-17.46: a commit with no reader is recorded `no reader` only when it is retained.
#[test]
fn a_commit_without_a_reader_is_recorded_no_reader_only_when_it_is_retained() {
    let fixture = fixture::repository();
    let (before, head) = (fixture.commits[0].clone(), fixture.commits[2].clone());
    let readers = Readers::new(&[(head.as_str(), COMPATIBLE, 0)]);
    // A host release at a commit that has no reader is not readable.
    let refused = produce(
        &fixture,
        &readers,
        &[row("host/v0.1.0+cccccccccccc", &before, "0.78.0")],
        &[],
        "0.78.0",
    )
    .expect_err("a host release with no reader");
    assert!(
        refused.contains("has no release matrix program"),
        "{refused}"
    );
    // A retained release at that commit is recorded without a reader.
    let retained = [Retained {
        commit: before.clone(),
        version: "0.77.0".to_owned(),
    }];
    let lines = produce(&fixture, &readers, &[], &retained, "0.78.0").expect("lines");
    let found = lines["lines"].as_array().expect("lines");
    assert!(
        found
            .iter()
            .any(|line| line["commit"] == before && line["verdict"] == "no reader")
    );
}

/// KR-REQ-17.46: the header names the releases the build retains, as their records do.
#[test]
fn the_header_writer_names_the_retained_records() {
    let retained_folder = Path::new(env!("CARGO_MANIFEST_DIR")).join("../kr-protocol/retained");
    let mut records = Vec::new();
    for entry in std::fs::read_dir(&retained_folder).expect("the retained folder") {
        let release = entry.expect("an entry").path().join("RELEASE");
        if release.exists() {
            records.push(std::fs::read_to_string(&release).expect("a release record"));
        }
    }
    let records: Vec<&str> = records.iter().map(String::as_str).collect();
    let mut named = header_writer(&records).expect("the records name their commits");
    named.sort_by(|left, right| left.commit.cmp(&right.commit));
    let mut here = retained_here();
    here.sort_by(|left, right| left.commit.cmp(&right.commit));
    assert!(!named.is_empty());
    assert_eq!(
        named, here,
        "the header is the RELEASE records under retained/"
    );
    for kept in &named {
        assert!(previous_reader::is_a_commit_name(&kept.commit));
        assert!(!kept.version.contains('+') && kept.version.split('.').count() == 3);
    }
}

/// KR-REQ-17.46: the production pin is replaced once, and the first revision a reader reads stays.
#[test]
fn the_pin_text_is_replaced_exactly_once() {
    let patched = previous_reader::replace_pins(fixture::MATRIX_CLIENT, "a-test-key").expect("one");
    assert_eq!(patched.matches("a-test-key").count(), 1);
    assert!(!patched.contains("production-key"));
    assert!(patched.contains("pub const PRODUCTION_FIRST_REVISION: u64 = 2;"));
    assert!(patched.contains("[&str; 1] = [\"a-test-key\"];"));
    for source in [
        "pub const OTHER: u8 = 1;\n".to_owned(),
        format!("{0}{0}", fixture::MATRIX_CLIENT),
    ] {
        let refused = previous_reader::replace_pins(&source, "k").expect_err("not once");
        assert!(refused.contains("not once"), "{refused}");
    }
}

/// KR-REQ-17.46: the producer takes absolute paths and refuses a relative one before any work.
#[test]
fn the_producer_refuses_a_relative_path() {
    let names = [
        "KR_CANDIDATE",
        "KR_REGISTER",
        "KR_LINES_OUT",
        "KR_READER_CACHE",
    ];
    for relative in names {
        let refused = read_inputs(|name| {
            Some(if name == relative {
                "cache/here".to_owned()
            } else {
                "/an/absolute/path".to_owned()
            })
        })
        .err()
        .unwrap_or_else(|| panic!("{relative} was a relative path and was taken"));
        assert_eq!(
            refused,
            format!(
                "The core readers take absolute paths: {relative} is `cache/here`. Give an absolute path, then run them again."
            )
        );
    }
    assert!(read_inputs(|_| Some("/an/absolute/path".to_owned())).is_ok());
}

/// KR-REQ-17.46: one run holds the cache at a time, and a second is told so rather than waiting.
#[test]
fn the_cache_is_held_by_one_run_at_a_time() {
    let folder = tempfile::tempdir().expect("a folder");
    let first = CacheGuard::take(folder.path()).expect("the first run takes the cache");
    let cache = folder.path().to_path_buf();
    let second = std::thread::spawn(move || CacheGuard::take(&cache).err())
        .join()
        .expect("the thread ends");
    assert_eq!(
        second,
        Some(format!(
            "The core readers' cache {} is in use by another run. Wait for that run to end, then run the readers again.",
            folder.path().display()
        ))
    );
    drop(first);
}

/// KR-REQ-17.46: the cache is free again at once after the guard drops, though a program started
/// while it was held still has a copy of the descriptor.
#[test]
fn the_cache_is_free_after_the_guard_drops() {
    let folder = tempfile::tempdir().expect("a folder");
    let guard = CacheGuard::take(folder.path()).expect("the cache");
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .stdin(std::process::Stdio::from(
            guard
                .handle()
                .try_clone()
                .expect("a copy of the descriptor"),
        ))
        .spawn()
        .expect("a program that keeps the descriptor");
    drop(guard);
    let again = CacheGuard::take(folder.path());
    child.kill().expect("the program ends");
    child.wait().expect("the program is reaped");
    assert!(
        again.is_ok(),
        "the lock was released by the guard, not by the program's exit"
    );
}

/// KR-REQ-17.46: an extraction that did not finish has no stamp and is made again.
#[test]
fn an_extraction_without_its_stamp_is_made_again() {
    let fixture = fixture::repository();
    let cache = fixture.folder.path().join("cache");
    let commit = fixture.commits[1].clone();
    let tree = previous_reader::extract(&fixture.work, &commit, &cache).expect("an extraction");
    assert!(tree.join("README").exists());
    assert!(cache.join(&commit).join("stamp").exists());

    // An earlier run that stopped part way: a file in the tree that the commit does not have, and
    // no stamp.
    std::fs::write(tree.join("left-over"), "partial\n").expect("a file");
    std::fs::remove_file(cache.join(&commit).join("stamp")).expect("the stamp goes");
    let again = previous_reader::extract(&fixture.work, &commit, &cache).expect("made again");
    assert!(
        !again.join("left-over").exists(),
        "the tree is made again from the commit"
    );
    assert!(cache.join(&commit).join("stamp").exists());
}

/* -------------------------------------------------------------------------- */
/* The cases that build a real reader, run by hand on the build box            */
/* -------------------------------------------------------------------------- */

mod real {
    use super::*;
    use base64::Engine as _;
    use kr_crypto::keys::AuthorisationKeyPair;
    use kr_service_stand_in::{serve, signed_release_matrix};

    fn repository() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("the repository")
    }

    fn inputs() -> Paths {
        read_inputs(|name| std::env::var(name).ok()).unwrap_or_else(|why| panic!("{why}"))
    }

    /// A key for one run, and the text a reader pins it by.
    fn run_key() -> (AuthorisationKeyPair, String) {
        let key = AuthorisationKeyPair::generate().expect("a key pair");
        let text = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public().as_bytes());
        (key, text)
    }

    /// The program of one commit, built under the run's key in place of its pin.
    fn built(commit: &str, cache: &Path, key_text: &str) -> PathBuf {
        let _guard = CacheGuard::take(cache).expect("the cache");
        let tree = previous_reader::extract(&repository(), commit, cache).expect("the tree");
        previous_reader::write_patched(&repository(), commit, &tree, key_text).expect("a patch");
        previous_reader::cargo_build(&Job {
            tree: &tree,
            target: &cache.join(commit).join("target"),
            commit,
        })
        .expect("the reader builds")
    }

    /// What the reader of `commit` printed for `matrix`, with its exit status.
    async fn answer(commit: &str, matrix: &Value) -> (Option<i32>, String) {
        let cache = inputs().cache;
        let (key, text) = run_key();
        let program = built(commit, &cache, &text);
        let served = serve().await;
        served.web().publish_release_matrix(
            &serde_json::to_vec(&signed_release_matrix(matrix, &key)).expect("a reply"),
        );
        previous_reader::run_program(&program, served.origin()).expect("the reader runs")
    }

    /// KR-REQ-17.46: the real run, which writes the lines for the candidate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "builds a reader for every release; run by hand on the build box"]
    async fn make_the_readers_lines() {
        let paths = inputs();
        let candidate = std::fs::read(&paths.candidate).expect("the candidate file");
        let register = read_register(&std::fs::read(&paths.register).expect("the register"))
            .unwrap_or_else(|why| panic!("{why}"));
        let matrix: Value = serde_json::from_slice(&candidate).expect("a matrix");
        let (key, key_text) = run_key();
        let served = serve().await;
        served.web().publish_release_matrix(
            &serde_json::to_vec(&signed_release_matrix(&matrix, &key)).expect("a reply"),
        );
        let origin = served.origin().to_owned();
        let core_version = kr_protocol::hello::PACKAGE_VERSION.to_string();
        let lines = make_lines(
            &Setup {
                repository: &repository(),
                cache: &paths.cache,
                candidate: &candidate,
                register: &register,
                retained: &retained_here(),
                core_version: &core_version,
                key_text: &key_text,
            },
            &previous_reader::cargo_build,
            &|program| {
                let (code, stdout) = previous_reader::run_program(program, &origin)?;
                previous_reader::read_answer(code, &stdout)
            },
        )
        .unwrap_or_else(|why| panic!("{why}"));
        write_lines(&paths.lines_out, &lines);
    }

    /// KR-REQ-17.46: a reader built with the run's key still refuses a reply below its floor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "builds a reader of an earlier release; run by hand on the build box"]
    async fn a_patched_reader_still_refuses_a_reply_below_its_floor() {
        let floored = &reader_roster::HOST_RELEASES[0];
        assert_eq!(floored.floor, Some(2));
        let (code, stdout) = answer(floored.commit, &reader_roster::first_revision()).await;
        assert_eq!(code, Some(1), "{stdout}");
        assert!(
            stdout.contains("its revision is below the first this build reads"),
            "{stdout}"
        );
    }

    /// KR-REQ-17.46: the reader that has no floor is read as built: the patch adds none.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "builds a reader of an earlier release; run by hand on the build box"]
    async fn a_reader_with_no_floor_is_read_as_built() {
        let unfloored = &reader_roster::HOST_RELEASES[1];
        assert_eq!(unfloored.floor, None);
        let (code, stdout) = answer(unfloored.commit, &reader_roster::first_revision()).await;
        let reading =
            previous_reader::read_answer(code, &stdout).expect("a verdict, not a refusal");
        assert_eq!(reading.verdict, "unsupported", "{stdout}");
        assert_eq!(reading.revision, "1");
    }

    /// KR-REQ-17.46: a second run on one cache reuses the trees and reads with a key of its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "builds readers twice; run by hand on the build box"]
    async fn a_second_run_on_one_cache_reads_with_its_own_key() {
        let paths = inputs();
        let candidate =
            serde_json::to_vec(&reader_roster::serving_every_release()).expect("a matrix");
        let host = &reader_roster::HOST_RELEASES[2];
        let register = [row(host.tag, host.commit, host.version)];
        let core_version = kr_protocol::hello::PACKAGE_VERSION.to_string();
        let mut made = Vec::new();
        for _ in 0..2 {
            let (key, key_text) = run_key();
            let served = serve().await;
            let matrix = reader_roster::serving_every_release();
            served.web().publish_release_matrix(
                &serde_json::to_vec(&signed_release_matrix(&matrix, &key)).expect("a reply"),
            );
            let origin = served.origin().to_owned();
            let lines = make_lines(
                &Setup {
                    repository: &repository(),
                    cache: &paths.cache,
                    candidate: &candidate,
                    register: &register,
                    retained: &retained_here(),
                    core_version: &core_version,
                    key_text: &key_text,
                },
                &previous_reader::cargo_build,
                &|program| {
                    let (code, stdout) = previous_reader::run_program(program, &origin)?;
                    previous_reader::read_answer(code, &stdout)
                },
            )
            .unwrap_or_else(|why| panic!("{why}"));
            made.push(lines);
        }
        assert_eq!(made[0], made[1], "the second run reads the same verdicts");
        assert!(
            made[1]["lines"]
                .as_array()
                .expect("lines")
                .iter()
                .filter(|line| line["verdict"] != "no reader")
                .all(|line| line["verdict"] == "compatible")
        );
    }
}
