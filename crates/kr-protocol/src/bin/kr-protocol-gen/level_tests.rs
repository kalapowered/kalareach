//! The record of excluded releases and the in-level check, against repositories with the history
//! the real one has: a level released more than once, a bare origin, and a surface that changes
//! between two releases of one level.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use kr_protocol::hello::PackageVersion;
use kr_protocol::update::CompatibilityLevel;

use crate::excluded::{Exclusions, kept, surface_digest};
use crate::in_level::{Head, Outcome, WorkerSurface, check};
use crate::releases::{agree_with_origin, inventory};

/// What one commit of the fixture repository holds: the files the checks read.
#[derive(Clone)]
struct Tree {
    version: &'static str,
    schema: Value,
    worker: Option<Value>,
    host: &'static str,
    majors: &'static str,
    /// The roots of the retained surface the release's own source declares.
    roots: Vec<&'static str>,
}

fn schema(lease: bool, peer_member: &str, outside_member: &str) -> Value {
    let mut mutation = json!({
        "type": "object",
        "properties": { "actor": { "type": "string" } },
        "required": ["actor"],
    });
    if lease {
        mutation["properties"]["lease"] = json!({ "type": "string" });
    }
    json!({ "$defs": {
        "ControlFrame": {
            "type": "object",
            "properties": { "mutation": { "$ref": "#/$defs/ForwardedMutation" } },
            "required": ["mutation"],
        },
        "ForwardedMutation": mutation,
        "PeerParams": {
            "type": "object",
            "properties": { "member": { "type": peer_member } },
            "required": ["member"],
        },
        "PeerResult": { "type": "object", "properties": {}, "required": [] },
        "OutsideEveryRoot": {
            "type": "object",
            "properties": { "member": { "type": outside_member } },
            "required": ["member"],
        },
    } })
}

fn worker(method: &str, event: &str) -> Value {
    json!({
        "surface_roots": ["ControlFrame"],
        "peer_roots": ["PeerParams", "PeerResult"],
        "methods": [{ "name": method, "params": "PeerParams", "result": "PeerResult" }],
        "events": [{ "name": event, "payload": "PeerResult" }],
    })
}

impl Tree {
    /// A release of level 0.76 as it was made before the lease: no `lease` member, and no table of
    /// what the worker serves.
    fn before_the_lease() -> Self {
        Self {
            version: "0.76.0",
            schema: schema(false, "string", "string"),
            worker: None,
            host: "kr-plugin-host/2",
            majors: "major=1 versions=1.0 replaced=- supported_until=- retired=false\n",
            roots: vec!["ControlFrame"],
        }
    }

    /// A release of level 0.76 as it is now, with the table.
    fn the_level() -> Self {
        Self {
            schema: schema(true, "string", "string"),
            worker: Some(worker("session.read", "session.output")),
            ..Self::before_the_lease()
        }
    }
}

struct Repo {
    directory: PathBuf,
    origin: PathBuf,
}

impl Repo {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "kr-protocol-gen-levels-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let (directory, origin) = (root.join("work"), root.join("origin.git"));
        std::fs::create_dir_all(&directory).expect("a directory");
        std::fs::create_dir_all(&origin).expect("a directory");
        let repo = Self { directory, origin };
        repo.git_in(&repo.origin, &["init", "-q", "--bare", "-b", "main"]);
        repo.git(&["init", "-q", "-b", "main"]);
        repo.git(&[
            "remote",
            "add",
            "origin",
            &repo.origin.display().to_string(),
        ]);
        repo
    }

    fn git_in(&self, directory: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.directory)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(["-c", "user.name=a", "-c", "user.email=a@example.invalid"])
            .args(["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
            .args(["-c", "core.hooksPath=/dev/null"])
            .args(arguments)
            .current_dir(directory)
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "git {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("text")
    }

    fn git(&self, arguments: &[&str]) -> String {
        self.git_in(&self.directory, arguments)
    }

    fn write(&self, path: &str, contents: &str) {
        let path = self.directory.join(path);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        std::fs::write(path, contents).expect("a file");
    }

    /// A commit holding `tree`; its full hash.
    fn commit(&self, tree: &Tree, note: &str) -> String {
        self.write(
            "packages/protocol/package.json",
            &format!("{{\"version\": \"{}\"}}\n", tree.version),
        );
        self.write(
            "packages/protocol/schema/kalareach-protocol.schema.json",
            &serde_json::to_string_pretty(&tree.schema).expect("text"),
        );
        self.write(
            "crates/kr-protocol/src/hello.rs",
            "pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);\n",
        );
        let roots: String = tree
            .roots
            .iter()
            .map(|root| format!("    \"{root}\",\n"))
            .collect();
        self.write(
            "crates/kr-protocol/src/retained.rs",
            &format!(
                "pub const PLUGIN_HOST_PROTOCOL: &str = \"{}\";\n\
                 pub const SURFACE_ROOTS: &[&str] = &[\n{roots}];\n",
                tree.host
            ),
        );
        let table = "crates/kr-protocol/worker-surface.json";
        match &tree.worker {
            Some(worker) => self.write(table, &worker.to_string()),
            None => {
                let _ = std::fs::remove_file(self.directory.join(table));
            }
        }
        self.write("note", note);
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", note]);
        self.git(&["rev-parse", "HEAD"]).trim().to_owned()
    }

    /// Tags `commit` as the release of `version`, here and on origin; the tag.
    fn release(&self, version: &str, commit: &str) -> String {
        let tag = self.tag_here(version, commit);
        self.git(&["push", "-q", "origin", &tag]);
        tag
    }

    /// Tags `commit` here only.
    fn tag_here(&self, version: &str, commit: &str) -> String {
        let tag = format!("packages/v{version}+{}", &commit[..12]);
        self.git(&["tag", &tag, commit]);
        tag
    }

    /// The head of a check: `tree` as this build would have it at `commit`.
    fn head(&self, tree: &Tree, commit: &str) -> Head {
        Head {
            commit: commit.to_owned(),
            level: CompatibilityLevel::of(PackageVersion::new(0, 76, 0)),
            schema: tree.schema.clone(),
            worker: WorkerSurface::parse(
                &tree
                    .worker
                    .clone()
                    .unwrap_or_else(|| worker("session.read", "session.output"))
                    .to_string(),
            )
            .expect("a table"),
            plugin_host: tree.host.to_owned(),
            public_majors: tree.majors.to_owned(),
        }
    }

    /// The record of excluded releases for `releases`, as the repository's own digests give them.
    fn record(&self, releases: &[(&str, &str)]) -> Exclusions {
        let mut text = String::new();
        for (tag, commit) in releases {
            text.push_str(&format!(
                "tag={tag}\ncommit={commit}\nlevel=0.76\nsurface={}\nwhy=made before the level was whole\n\n",
                surface_digest(&self.directory, commit).expect("a digest")
            ));
        }
        Exclusions::parse(&text).expect("a record")
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.directory.parent().expect("a root"));
    }
}

/// A level released twice before its last change, then once with it, and a commit after.
struct Split {
    repo: Repo,
    early: (String, String),
    second: (String, String),
    whole: (String, String),
    head: String,
}

fn split(name: &str, head_tree: &Tree) -> Split {
    let repo = Repo::new(name);
    let old = Tree::before_the_lease();
    let first = repo.commit(&old, "first of the level");
    let early = (repo.release("0.76.0", &first), first);
    let next = repo.commit(&old, "second of the level");
    let second = (repo.release("0.76.0", &next), next);
    let whole_commit = repo.commit(&Tree::the_level(), "the level with the lease");
    let whole = (repo.release("0.76.0", &whole_commit), whole_commit);
    let head = repo.commit(head_tree, "after");
    Split {
        repo,
        early,
        second,
        whole,
        head,
    }
}

fn run(split: &Split, tree: &Tree, exclusions: &Exclusions) -> Result<Outcome, String> {
    let releases = inventory(&split.repo.directory).expect("an inventory");
    check(
        &split.repo.directory,
        &split.repo.head(tree, &split.head),
        &releases,
        exclusions,
    )
}

/// The split of train 2026-10-31: two releases of a level without a member the level has. Without
/// the record the check names both and the member; with it the level is the release that has it.
#[test]
fn the_split_of_a_level_fails_without_the_exclusion_and_holds_with_it() {
    let now = Tree::the_level();
    let split = split("split", &now);
    let error = run(&split, &now, &Exclusions::none()).expect_err("the early releases differ");
    assert!(error.contains(&split.early.0), "{error}");
    assert!(error.contains(&split.second.0), "{error}");
    assert!(error.contains("ForwardedMutation.lease"), "{error}");
    assert!(!error.contains(&split.whole.0), "{error}");

    let record = split.repo.record(&[
        (&split.early.0, &split.early.1),
        (&split.second.0, &split.second.1),
    ]);
    record
        .validate(
            &split.repo.directory,
            &inventory(&split.repo.directory).expect("an inventory"),
        )
        .expect("the record holds");
    let outcome = run(&split, &now, &record).expect("the level holds with the record");
    assert_eq!(
        outcome,
        Outcome::Held {
            releases: vec![split.whole.0.clone()],
            notes: vec![],
        }
    );
}

/// A change inside a root a worker's peers read is a difference, and the same change to a type no
/// root reaches is not.
#[test]
fn a_change_to_a_widened_root_fails_and_a_change_outside_every_root_does_not() {
    let now = Tree::the_level();
    let split = split("widened", &now);
    let record = split.repo.record(&[
        (&split.early.0, &split.early.1),
        (&split.second.0, &split.second.1),
    ]);
    let widened = Tree {
        schema: schema(true, "integer", "string"),
        ..now.clone()
    };
    let error = run(&split, &widened, &record).expect_err("a root changed");
    assert!(error.contains(&split.whole.0), "{error}");
    assert!(error.contains("PeerParams.member"), "{error}");
    let outside = Tree {
        schema: schema(true, "string", "integer"),
        ..now.clone()
    };
    run(&split, &outside, &record).expect("no root reaches that type");
}

/// A root the head no longer has cannot hide the difference: the release's own list is cut too, and
/// the root it named is missing from the head.
#[test]
fn a_root_the_head_dropped_is_a_difference() {
    let now = Tree::the_level();
    let split = split("dropped", &now);
    let record = split.repo.record(&[
        (&split.early.0, &split.early.1),
        (&split.second.0, &split.second.1),
    ]);
    // A release of the level, made later, that reads a root of its own.
    let mut with_root = now.clone();
    with_root.schema["$defs"]["OnlyThere"] = json!({
        "type": "object",
        "properties": {},
        "required": [],
    });
    let mut table = worker("session.read", "session.output");
    table["peer_roots"] = json!(["OnlyThere", "PeerParams", "PeerResult"]);
    with_root.worker = Some(table);
    let commit = split.repo.commit(&with_root, "a root of its own");
    let tag = split.repo.release("0.76.0", &commit);
    let head = split.repo.commit(&now, "the head without it");
    let releases = inventory(&split.repo.directory).expect("an inventory");
    let error = check(
        &split.repo.directory,
        &split.repo.head(&now, &head),
        &releases,
        &record,
    )
    .expect_err("a root went");
    assert!(error.contains(&tag), "{error}");
    assert!(
        error.contains("OnlyThere removed: a root the new surface lacks"),
        "{error}"
    );
}

/// A renamed notification and a method the worker stopped serving change no definition, and the
/// tables each release committed show them. A release before the tables is compared by schema and
/// the run says so.
#[test]
fn a_renamed_event_and_a_method_no_longer_served_are_differences() {
    let now = Tree::the_level();
    let split = split("tables", &now);
    let record = split.repo.record(&[
        (&split.early.0, &split.early.1),
        (&split.second.0, &split.second.1),
    ]);
    let renamed = Tree {
        worker: Some(worker("session.read", "session.output.v2")),
        ..now.clone()
    };
    let error = run(&split, &renamed, &record).expect_err("an event was renamed");
    assert!(error.contains("session.output was sent there"), "{error}");
    let unserved = Tree {
        worker: Some(worker("session.close", "session.output")),
        ..now.clone()
    };
    let error = run(&split, &unserved, &record).expect_err("a method went");
    assert!(error.contains("session.read was served there"), "{error}");
    assert!(error.contains("session.close is served here"), "{error}");
}

/// A release before the tables is compared by schema alone, and the run says what it left out.
#[test]
fn a_release_before_the_tables_is_compared_by_schema_and_the_run_says_so() {
    let repo = Repo::new("no-tables");
    let old = Tree::before_the_lease();
    let first = repo.commit(&old, "a release before the tables");
    let tag = repo.release("0.76.0", &first);
    let head = repo.commit(&old, "after");
    let releases = inventory(&repo.directory).expect("an inventory");
    let outcome = check(
        &repo.directory,
        &repo.head(&old, &head),
        &releases,
        &Exclusions::none(),
    )
    .expect("the schema is the same");
    let Outcome::Held { releases, notes } = outcome else {
        panic!("the level holds");
    };
    assert_eq!(releases, std::slice::from_ref(&tag));
    assert!(notes.iter().any(|note| note.contains(&tag)), "{notes:?}");

    // The head's own list of the roots a worker's peers read is what widens the cut for it.
    let widened = Tree {
        schema: schema(false, "integer", "string"),
        ..old.clone()
    };
    let releases = inventory(&repo.directory).expect("an inventory");
    let error = check(
        &repo.directory,
        &repo.head(&widened, &head),
        &releases,
        &Exclusions::none(),
    )
    .expect_err("a root the release had no list for changed");
    assert!(error.contains("PeerParams.member"), "{error}");
}

/// The plugin host's protocol and the table of public majors are the level's too.
#[test]
fn the_plugin_host_protocol_and_the_public_majors_are_held() {
    let now = Tree::the_level();
    let split = split("host", &now);
    let record = split.repo.record(&[
        (&split.early.0, &split.early.1),
        (&split.second.0, &split.second.1),
    ]);
    let host = Tree {
        host: "kr-plugin-host/3",
        ..now.clone()
    };
    let error = run(&split, &host, &record).expect_err("the host protocol moved");
    assert!(error.contains("kr-plugin-host/2"), "{error}");
    let majors = Tree {
        majors: "major=1 versions=1.0,1.1 replaced=- supported_until=- retired=false\n",
        ..now.clone()
    };
    let error = run(&split, &majors, &record).expect_err("the public majors moved");
    assert!(error.contains("public majors"), "{error}");
}

/// With no release at the commit's level the commit moves it, and a level none of whose releases
/// is kept is refused by the record.
#[test]
fn a_commit_with_no_release_at_its_level_moves_it() {
    let repo = Repo::new("moves");
    let old = Tree {
        version: "0.75.0",
        ..Tree::before_the_lease()
    };
    let first = repo.commit(&old, "an older level");
    repo.release("0.75.0", &first);
    let now = Tree::the_level();
    let head = repo.commit(&now, "the next level");
    let releases = inventory(&repo.directory).expect("an inventory");
    let outcome = check(
        &repo.directory,
        &repo.head(&now, &head),
        &releases,
        &Exclusions::none(),
    );
    assert_eq!(outcome, Ok(Outcome::MovesTheLevel));
}

fn record_text(tag: &str, commit: &str, surface: &str, level: &str) -> String {
    format!("tag={tag}\ncommit={commit}\nlevel={level}\nsurface={surface}\nwhy=a reason\n")
}

const TAG: &str = "packages/v0.76.0+53a2e0be5111";
const COMMIT: &str = "53a2e0be511158180ff0e1654681b96ff90d97c2";

/// A record that is not well formed is refused, each shape by its own message.
#[test]
fn a_malformed_record_is_refused() {
    let surface = "0".repeat(64);
    let good = record_text(TAG, COMMIT, &surface, "0.76");
    Exclusions::parse(&good).expect("a record");
    for (what, text) in [
        ("a line that is no field", format!("{good}a line\n")),
        ("an unknown field", format!("{good}extra=1\n")),
        ("a field twice", format!("{good}why=again\n")),
        ("a missing field", good.replace("why=a reason\n", "")),
        (
            "a commit that is short",
            record_text(TAG, &COMMIT[..39], &surface, "0.76"),
        ),
        (
            "a commit in capitals",
            record_text(TAG, &COMMIT.to_uppercase(), &surface, "0.76"),
        ),
        (
            "a surface that is short",
            record_text(TAG, COMMIT, &surface[..63], "0.76"),
        ),
        (
            "a level that is not one",
            record_text(TAG, COMMIT, &surface, "0.x"),
        ),
        (
            "a tag that is not a release",
            record_text("v0.76.0", COMMIT, &surface, "0.76"),
        ),
        ("a tag twice", format!("{good}\n{good}")),
        ("a record of nothing", "# only a comment\n".to_owned()),
    ] {
        assert!(Exclusions::parse(&text).is_err(), "{what} is refused");
    }
}

/// The record is closed: it names the two tags and no others, and the file is read as a checkout
/// has it.
#[test]
fn the_record_names_the_two_closed_tags_and_no_others() {
    let directory =
        std::env::temp_dir().join(format!("kr-protocol-gen-closed-{}", std::process::id()));
    let path = directory.join(crate::excluded::RECORD);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
    let surface = "0".repeat(64);
    let one = record_text(TAG, COMMIT, &surface, "0.76");
    std::fs::write(&path, &one).expect("a record");
    let error = Exclusions::read(&directory).expect_err("one of two");
    assert!(error.contains("closed"), "{error}");
    let other = record_text("packages/v0.76.0+0123456789ab", COMMIT, &surface, "0.76");
    std::fs::write(&path, format!("{one}\n{other}")).expect("a record");
    assert!(
        Exclusions::read(&directory).is_err(),
        "a third tag is refused"
    );
    let both = format!(
        "{one}\n{}",
        record_text(
            "packages/v0.76.0+d3a552aa2ea6",
            "d3a552aa2ea66b5e175962eaa436d4a6f852405a",
            &surface,
            "0.76"
        )
    );
    std::fs::write(&path, both).expect("a record");
    Exclusions::read(&directory).expect("the closed set");
    let _ = std::fs::remove_dir_all(&directory);
}

/// A record that does not match the repository is refused: an unknown tag, a commit the tag does
/// not point at, a level that is not the tag's, a digest that is not its own schema's, a level with
/// no release that is kept, and an excluded release that is newer than one that is kept.
#[test]
fn a_record_that_does_not_match_the_repository_is_refused() {
    let now = Tree::the_level();
    let split = split("refused", &now);
    let inventory = inventory(&split.repo.directory).expect("an inventory");
    let digest = surface_digest(&split.repo.directory, &split.early.1).expect("a digest");
    let validate = |text: String| {
        Exclusions::parse(&text)
            .expect("a record")
            .validate(&split.repo.directory, &inventory)
    };
    let good = record_text(&split.early.0, &split.early.1, &digest, "0.76");
    validate(good.clone()).expect("the record holds");

    let unknown = validate(record_text(
        "packages/v0.76.0+0123456789ab",
        &split.early.1,
        &digest,
        "0.76",
    ));
    assert!(
        unknown
            .expect_err("an unknown tag")
            .contains("not a release tag")
    );
    let other = validate(record_text(
        &split.early.0,
        &split.second.1,
        &digest,
        "0.76",
    ));
    assert!(other.expect_err("another commit").contains("points at"));
    let level = validate(record_text(&split.early.0, &split.early.1, &digest, "0.75"));
    assert!(level.expect_err("another level").contains("level"));
    let wrong = validate(record_text(
        &split.early.0,
        &split.early.1,
        &"1".repeat(64),
        "0.76",
    ));
    assert!(
        wrong
            .expect_err("another digest")
            .contains("own schema gives")
    );

    // The release that has the member is not the schema of the excluded one.
    let newer = validate(record_text(
        &split.whole.0,
        &split.whole.1,
        &surface_digest(&split.repo.directory, &split.whole.1).expect("a digest"),
        "0.76",
    ));
    assert!(
        newer
            .expect_err("the newest is excluded")
            .contains("is not in the history of"),
        "an excluded release is older than every kept one"
    );

    // Every release of the level excluded leaves nothing that says what it is.
    let mut all = String::new();
    for (tag, commit) in [&split.early, &split.second, &split.whole] {
        all.push_str(&record_text(
            tag,
            commit,
            &surface_digest(&split.repo.directory, commit).expect("a digest"),
            "0.76",
        ));
        all.push('\n');
    }
    assert!(
        validate(all)
            .expect_err("nothing kept")
            .contains("no release that is not excluded")
    );
}

/// The kept releases of a level are the level's without the excluded ones and without the commit
/// being checked.
#[test]
fn the_kept_releases_leave_out_the_excluded_and_the_commit_under_test() {
    let now = Tree::the_level();
    let split = split("kept", &now);
    let inventory = inventory(&split.repo.directory).expect("an inventory");
    let level = CompatibilityLevel::of(PackageVersion::new(0, 76, 0));
    let record = split.repo.record(&[(&split.early.0, &split.early.1)]);
    let tags = |except: &str| -> Vec<String> {
        kept(&inventory, level, &record, except)
            .into_iter()
            .map(|release| release.tag)
            .collect()
    };
    let mut both = [split.second.0.clone(), split.whole.0.clone()];
    both.sort();
    assert_eq!(tags(""), both);
    assert_eq!(tags(&split.whole.1), std::slice::from_ref(&split.second.0));
}

/// A checkout whose tags are not origin's is refused with its own message, and a tag at the commit
/// under test, which a release makes after it lands, is on one side or both without a failure.
#[test]
fn tags_that_are_not_origins_are_refused() {
    let now = Tree::the_level();
    let split = split("origin", &now);
    let directory = &split.repo.directory;
    let here = inventory(directory).expect("an inventory");
    agree_with_origin(directory, &here, &split.head).expect("the tags agree");

    // A tag origin has and this checkout lacks, and one only this checkout has.
    split.repo.git(&["tag", "-d", &split.second.0]);
    let error = agree_with_origin(
        directory,
        &inventory(directory).expect("an inventory"),
        &split.head,
    )
    .expect_err("a tag is missing here");
    assert!(error.contains(&format!(
        "{} is on origin and not in this checkout",
        split.second.0
    )));
    assert!(error.contains("git fetch --force --prune"), "{error}");
    split.repo.git(&["tag", &split.second.0, &split.second.1]);
    let local_only = split.repo.tag_here("0.76.1", &split.head);
    // At the commit under test: left out on its own side.
    agree_with_origin(
        directory,
        &inventory(directory).expect("an inventory"),
        &split.head,
    )
    .expect("a tag at the commit under test may be on one side");
    // At any other commit it is a difference.
    let error = agree_with_origin(
        directory,
        &inventory(directory).expect("an inventory"),
        &split.whole.1,
    )
    .expect_err("a tag only here");
    assert!(error.contains(&format!(
        "{local_only} is in this checkout and not on origin"
    )));
    split.repo.git(&["tag", "-d", &local_only]);

    // The same name at another commit.
    split.repo.git(&["tag", "-d", &split.second.0]);
    split.repo.git(&["tag", &split.second.0, &split.early.1]);
    let error = agree_with_origin(
        directory,
        &[crate::releases::Release {
            tag: split.second.0.clone(),
            version: PackageVersion::new(0, 76, 0),
            commit: split.early.1.clone(),
        }],
        &split.head,
    )
    .expect_err("another commit");
    assert!(error.contains("on origin"), "{error}");
}

/// An origin that cannot be listed fails the check, and is never an empty list.
#[test]
fn an_origin_that_cannot_be_listed_fails_closed() {
    let now = Tree::the_level();
    let split = split("closed", &now);
    split
        .repo
        .git(&["remote", "set-url", "origin", "/nonexistent/origin.git"]);
    let error = agree_with_origin(
        &split.repo.directory,
        &inventory(&split.repo.directory).expect("an inventory"),
        &split.head,
    )
    .expect_err("an origin that does not answer");
    assert!(error.contains("cannot be listed"), "{error}");
    let _ = split.repo.origin.exists();
}

/// A release whose tree cannot be read fails the check and is not left out of it.
#[test]
fn a_release_whose_schema_cannot_be_read_fails_the_check() {
    let now = Tree::the_level();
    let split = split("unreadable", &now);
    let record = split.repo.record(&[
        (&split.early.0, &split.early.1),
        (&split.second.0, &split.second.1),
    ]);
    // A release tag whose commit holds no schema: made from an empty commit on a branch.
    split.repo.git(&["checkout", "-q", "--orphan", "bare"]);
    split.repo.git(&["rm", "-rfq", "--cached", "."]);
    split.repo.write("empty", "nothing");
    split.repo.write(
        "packages/protocol/package.json",
        "{\"version\": \"0.76.0\"}\n",
    );
    split
        .repo
        .git(&["add", "empty", "packages/protocol/package.json"]);
    split
        .repo
        .git(&["commit", "-q", "-m", "a release without a schema"]);
    let bare = split.repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    split.repo.release("0.76.0", &bare);
    let releases = inventory(&split.repo.directory).expect("an inventory");
    let error = check(
        &split.repo.directory,
        &split.repo.head(&now, &split.head),
        &releases,
        &record,
    )
    .expect_err("no schema to read");
    assert!(error.contains("cannot be read"), "{error}");
}

/// A schema with a closed object a client reads, and a read-only metadata object.
fn public(root: bool, privacy: bool, required_privacy: bool) -> Value {
    let mut summary = json!({
        "type": "object",
        "properties": { "id": { "type": "string" } },
        "required": ["id"],
    });
    if root {
        summary["properties"]["root"] = json!({ "type": "string" });
    }
    let mut host = json!({
        "type": "object",
        "x-kalareach-read-only-metadata": true,
        "properties": { "name": { "type": "string" } },
        "required": ["name"],
    });
    let mut definitions = json!({ "SessionSummary": summary });
    if privacy {
        host["properties"]["privacy"] = json!({ "$ref": "#/$defs/HostPrivacyState" });
        if required_privacy {
            host["required"] = json!(["name", "privacy"]);
        }
        definitions["HostPrivacyState"] = json!({ "type": "string", "enum": ["on", "off"] });
    }
    definitions["HostInfoResult"] = host;
    json!({ "$defs": definitions })
}

/// `SessionSummary.root` is the member of the early 0.76 builds' closed reader: it is reported, and
/// it fails once public 1.0 is frozen. An optional member of an object that drops what it does not
/// know, with the definition it brings, is not a difference.
#[test]
fn a_member_an_earlier_closed_reader_cannot_read_is_reported_and_fails_from_the_freeze() {
    use crate::public_contract::{Report, compare, conclude};
    let lines =
        compare(&public(false, false, false), &public(true, true, false)).expect("two schemas");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].starts_with("SessionSummary.root added"),
        "{lines:?}"
    );

    // The object that drops what it does not know takes an optional member and its definition;
    // it does not take a required one.
    assert!(
        compare(&public(true, false, false), &public(true, true, false))
            .expect("two schemas")
            .is_empty()
    );
    let lines =
        compare(&public(true, false, false), &public(true, true, true)).expect("two schemas");
    assert!(
        lines
            .iter()
            .any(|line| line.contains("HostInfoResult.privacy")),
        "{lines:?}"
    );
    // A member that goes and a variant that comes are differences.
    assert!(
        !compare(&public(true, true, false), &public(false, true, false))
            .expect("two schemas")
            .is_empty()
    );

    let report = |frozen_at: Option<&str>| Report {
        frozen_at: frozen_at.map(str::to_owned),
        references: vec!["packages/v0.76.0+53a2e0be5111".to_owned()],
        differences: vec![(
            "packages/v0.76.0+53a2e0be5111".to_owned(),
            vec!["SessionSummary.root added: a member".to_owned()],
        )],
    };
    conclude(&report(None)).expect("reports and does not fail before the freeze");
    let error = conclude(&report(Some("packages/v1.0.0+0123456789ab"))).expect_err("frozen");
    assert!(
        error.contains("frozen at packages/v1.0.0+0123456789ab"),
        "{error}"
    );
}

/// The references before the freeze are every release at the level, the excluded ones included;
/// from the freeze they are the release it names and the later ones; a record of the freeze that is
/// not one is refused.
#[test]
fn the_references_follow_the_freeze_and_a_bad_record_of_it_is_refused() {
    use crate::public_contract::{FREEZE, freeze, report};
    let old = Tree {
        schema: public(false, false, false),
        ..Tree::before_the_lease()
    };
    let new = Tree {
        schema: public(true, false, false),
        ..Tree::before_the_lease()
    };
    let repo = Repo::new("freeze");
    let early = repo.commit(&old, "early");
    let early_tag = repo.release("0.76.0", &early);
    let later = repo.commit(&new, "later");
    let later_tag = repo.release("0.76.0", &later);
    let head = repo.commit(&new, "after");
    let releases = inventory(&repo.directory).expect("an inventory");
    let head_data = repo.head(&new, &head);

    // Before the freeze every release at the level is a reference, and the early one differs.
    let before = report(&repo.directory, &head_data, &releases, None).expect("a report");
    let mut expected = [early_tag.clone(), later_tag.clone()];
    expected.sort();
    assert_eq!(before.references, expected);
    assert_eq!(before.differences.len(), 1);
    assert_eq!(before.differences[0].0, early_tag);

    // From a freeze at the later release, the early one is not a reference.
    let path = repo.directory.join(FREEZE);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
    std::fs::write(&path, format!("release={later_tag}\n")).expect("a record");
    let frozen = freeze(&repo.directory, &head, &releases)
        .expect("a record")
        .expect("a release");
    let after = report(&repo.directory, &head_data, &releases, Some(&frozen)).expect("a report");
    assert_eq!(after.references, std::slice::from_ref(&later_tag));
    assert!(after.differences.is_empty(), "{after:?}");
    assert_eq!(after.frozen_at, Some(later_tag.clone()));

    for (what, text) in [
        ("a record of nothing", "# nothing\n".to_owned()),
        (
            "a tag that is not one",
            "release=packages/v0.76.0+0123456789ab\n".to_owned(),
        ),
        (
            "two lines",
            format!("release={early_tag}\nrelease={later_tag}\n"),
        ),
        ("a line that is no release", format!("{later_tag}\n")),
    ] {
        std::fs::write(&path, text).expect("a record");
        assert!(freeze(&repo.directory, &head, &releases).is_err(), "{what}");
    }
    // A freeze made at a release the commit does not come after.
    std::fs::write(&path, format!("release={later_tag}\n")).expect("a record");
    assert!(freeze(&repo.directory, &early, &releases).is_err());
}

/// The decision after the comparison: a commit that moves the level has the cut's own check run, once,
/// unless it is told to leave it; a commit that holds the surface does not run it.
#[test]
fn a_commit_that_moves_the_level_runs_the_cuts_check_once_and_one_that_holds_does_not() {
    use crate::in_level::conclude;
    use std::cell::Cell;

    let repo = Repo::new("decision");
    let old = Tree {
        version: "0.75.0",
        ..Tree::before_the_lease()
    };
    let first = repo.commit(&old, "an older level");
    repo.release("0.75.0", &first);
    let now = Tree::the_level();
    let head = repo.commit(&now, "the next level");
    let releases = inventory(&repo.directory).expect("an inventory");
    let calls = Cell::new(0);
    let cut = |_: &Path| {
        calls.set(calls.get() + 1);
        Ok(())
    };
    let data = repo.head(&now, &head);
    conclude(
        &repo.directory,
        &data,
        &releases,
        &Exclusions::none(),
        true,
        &cut,
    )
    .expect("the cut's check passes");
    assert_eq!(
        calls.get(),
        1,
        "run once for the commit that moves the level"
    );
    conclude(
        &repo.directory,
        &data,
        &releases,
        &Exclusions::none(),
        false,
        &cut,
    )
    .expect("nothing to compare");
    assert_eq!(calls.get(), 1, "not run when it is told to leave it");
    let failing = |_: &Path| Err("the cut's check said no".to_owned());
    let error = conclude(
        &repo.directory,
        &data,
        &releases,
        &Exclusions::none(),
        true,
        &failing,
    )
    .expect_err("its failure is the check's");
    assert!(error.contains("said no"), "{error}");

    // A commit at a level that has a release does not run it.
    let level = Repo::new("decision-held");
    let kept = level.commit(&now, "a release of the level");
    level.release("0.76.0", &kept);
    let after = level.commit(&now, "after");
    let tags = inventory(&level.directory).expect("an inventory");
    let calls = Cell::new(0);
    let cut = |_: &Path| {
        calls.set(calls.get() + 1);
        Ok(())
    };
    conclude(
        &level.directory,
        &level.head(&now, &after),
        &tags,
        &Exclusions::none(),
        true,
        &cut,
    )
    .expect("the level holds");
    assert_eq!(calls.get(), 0);
}

/// The cut compares every kept release of the retained level with what the level kept, from the
/// tags: a root the release declares that the kept surface lacks, a root the release lacks, a
/// plugin host protocol and a table of public majors that differ are each a difference, even in a
/// release the checkout's history does not reach.
#[test]
fn a_kept_release_of_a_retained_level_is_compared_over_both_root_lists_and_both_records() {
    use crate::retained::kept_release_differences;
    use kr_protocol::retained::Surface;

    let kept_tree = Tree::the_level();
    let repo = Repo::new("kept-release");
    let base = repo.commit(&kept_tree, "the release the level was cut from");
    let kept = Surface::cut(&kept_tree.schema, &["ControlFrame"]).expect("a surface");
    let majors = Some(kept_tree.majors);
    let release_of = |tree: &Tree, note: &str, aside: bool| {
        if aside {
            repo.git(&["checkout", "-q", "-b", "aside", &base]);
        }
        let commit = repo.commit(tree, note);
        let tag = repo.tag_here("0.76.0", &commit);
        if aside {
            repo.git(&["checkout", "-q", "main"]);
        }
        crate::releases::release_of(&repo.directory, &tag).expect("a release")
    };

    // The same: nothing differs.
    let same = release_of(&kept_tree, "the same", false);
    assert!(
        kept_release_differences(&repo.directory, &same, &kept, majors, "kr-plugin-host/2")
            .expect("compared")
            .is_empty()
    );

    // A root the release declares that the kept surface does not have, and a difference in it.
    let mut more = kept_tree.clone();
    more.roots = vec!["ControlFrame", "PeerParams"];
    let extra = release_of(&more, "a root of its own", false);
    let found =
        kept_release_differences(&repo.directory, &extra, &kept, majors, "kr-plugin-host/2")
            .expect("compared");
    assert!(
        found.iter().any(|line| line.contains("PeerParams")),
        "{found:?}"
    );

    // A root that is not a definition of the release's own schema is refused, not cut around.
    let mut misspelled = kept_tree.clone();
    misspelled.roots = vec!["ControlFrame", "ControlFrme"];
    let bad = release_of(&misspelled, "a misspelled root", false);
    let error = kept_release_differences(&repo.directory, &bad, &kept, majors, "kr-plugin-host/2")
        .expect_err("refused");
    assert!(error.contains("ControlFrme"), "{error}");

    // A release on a branch the history does not reach, whose plugin host protocol differs, held
    // against a table of public majors that is not the one it has.
    let aside = Tree {
        host: "kr-plugin-host/3",
        ..kept_tree.clone()
    };
    let beside = release_of(&aside, "on a branch", true);
    let other_majors =
        Some("major=1 versions=1.0,1.1 replaced=- supported_until=- retired=false\n");
    let found = kept_release_differences(
        &repo.directory,
        &beside,
        &kept,
        other_majors,
        "kr-plugin-host/2",
    )
    .expect("compared");
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found.iter().any(|line| line.contains("public majors")));
    assert!(found.iter().any(|line| line.contains("kr-plugin-host/3")));
}

/// The list of roots is read in the one shape it is written in, wherever the declaration is spaced,
/// and a source that declares it another way, twice, or not at all is told apart.
#[test]
fn the_list_of_surface_roots_is_read_strictly() {
    use crate::releases::surface_roots_in;
    let source = |declaration: &str| {
        format!("// SURFACE_ROOTS: not this\n{declaration}\nuse(SURFACE_ROOTS);\n")
    };
    let good = source("pub const SURFACE_ROOTS: &[&str] = &[\n    \"A\",\n    \"B\",\n];");
    assert_eq!(
        surface_roots_in(&good).expect("a list"),
        Some(vec!["A".to_owned(), "B".to_owned()])
    );
    assert_eq!(
        surface_roots_in("fn nothing() { f(SURFACE_ROOTS); }").expect("none"),
        None
    );
    for (what, text) in [
        (
            "no space before the colon is no other declaration",
            source("pub const SURFACE_ROOTS:&[&str] = &[\n    \"A\",\n];"),
        ),
        (
            "the name apart from its colon",
            source("pub const SURFACE_ROOTS : &[&str] = &[\n    \"A\",\n];"),
        ),
        (
            "an entry that is not a literal",
            source("pub const SURFACE_ROOTS: &[&str] = &[\n    NAMED,\n];"),
        ),
        (
            "a list that does not end",
            source("pub const SURFACE_ROOTS: &[&str] = &[\n    \"A\",\n"),
        ),
        ("twice", format!("{good}{good}")),
    ] {
        assert!(surface_roots_in(&text).is_err(), "{what}");
    }
}

/// A root a revision declares that its own schema does not define is refused, and is not cut around:
/// the release's table lists one, and so does the head's.
#[test]
fn a_declared_root_that_is_no_definition_is_refused() {
    let now = Tree::the_level();
    let split = split("misspelled", &now);
    let record = split.repo.record(&[
        (&split.early.0, &split.early.1),
        (&split.second.0, &split.second.1),
    ]);
    let mut bad = now.clone();
    let mut table = worker("session.read", "session.output");
    table["peer_roots"] = json!(["PeerParams", "PeerResult", "PeerParamz"]);
    bad.worker = Some(table);
    let commit = split
        .repo
        .commit(&bad, "a release that lists a root it lacks");
    split.repo.release("0.76.0", &commit);
    let head = split.repo.commit(&now, "after");
    let releases = inventory(&split.repo.directory).expect("an inventory");
    let error = check(
        &split.repo.directory,
        &split.repo.head(&now, &head),
        &releases,
        &record,
    )
    .expect_err("a release lists a root its schema lacks");
    assert!(error.contains("PeerParamz"), "{error}");

    let mut table = worker("session.read", "session.output");
    table["peer_roots"] = json!(["PeerParams", "PeerResult", "PeerParamz"]);
    let mut head_data = split.repo.head(&now, &head);
    head_data.worker = WorkerSurface::parse(&table.to_string()).expect("a table");
    let only_whole = inventory(&split.repo.directory).expect("an inventory");
    let error = check(&split.repo.directory, &head_data, &only_whole, &record)
        .expect_err("the head lists a root its schema lacks");
    assert!(error.contains("this commit declares"), "{error}");
}

/// A file that is in the release's tree and cannot be read is a failure; it is not the absence of the
/// file, which is how a release from before the retained levels reads.
#[test]
fn a_roots_file_that_cannot_be_read_is_not_an_absent_one() {
    use crate::releases::surface_roots_at;
    let repo = Repo::new("unreadable-roots");
    let commit = repo.commit(&Tree::the_level(), "a release");
    assert_eq!(
        surface_roots_at(&repo.directory, &commit).expect("a list"),
        Some(vec!["ControlFrame".to_owned()])
    );
    // A tree with no such file: absent.
    repo.git(&["rm", "-q", "crates/kr-protocol/src/retained.rs"]);
    repo.git(&["commit", "-q", "-m", "without the file"]);
    let without = repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    assert_eq!(
        surface_roots_at(&repo.directory, &without).expect("absent"),
        None
    );
    // A tree where the path is a commit of another repository: listed, and not a file git can show.
    repo.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        "160000,0123456789abcdef0123456789abcdef01234567,crates/kr-protocol/src/retained.rs",
    ]);
    repo.git(&["commit", "-q", "-m", "a path that cannot be shown"]);
    let broken = repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    let error = surface_roots_at(&repo.directory, &broken).expect_err("unreadable");
    assert!(error.contains("cannot be read"), "{error}");
}
