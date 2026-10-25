//! The in-level check, against repositories with the history the real one has: a level released
//! more than once, a bare origin, and a surface that changes between two releases of one level.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use kr_protocol::hello::PackageVersion;
use kr_protocol::update::CompatibilityLevel;

use crate::in_level::{Head, Outcome, WorkerSurface, check};
use crate::releases::{agree_with_origin, inventory, kept};

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
    /// The plugin SDK schema the release committed, when it had one.
    sdk: Option<Value>,
}

fn sdk_schema(description: &str, extra_member: bool) -> Value {
    let mut manifest = json!({
        "description": description,
        "type": "object",
        "properties": { "name": { "type": "string" } },
        "required": ["name"],
    });
    if extra_member {
        manifest["properties"]["added"] = json!({ "type": "string" });
    }
    json!({ "$defs": { "Manifest": manifest } })
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
            host: "kr-plugin-host/3",
            majors: "major=1 versions=1.0 replaced=- supported_until=- retired=false\n",
            roots: vec!["ControlFrame"],
            sdk: Some(sdk_schema("The manifest.", false)),
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
        let sdk = "packages/plugin-sdk/schema/kalareach-plugin-sdk.schema.json";
        match &tree.sdk {
            Some(sdk_schema) => self.write(
                sdk,
                &serde_json::to_string_pretty(sdk_schema).expect("text"),
            ),
            None => {
                let _ = std::fs::remove_file(self.directory.join(sdk));
            }
        }
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
            sdk_schema: tree
                .sdk
                .clone()
                .unwrap_or_else(|| sdk_schema("The manifest.", false)),
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
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.directory.parent().expect("a root"));
    }
}

/// A level released three times, the first two from `first_two` and the last from the level's own
/// tree, and a commit after.
struct Released {
    repo: Repo,
    first: (String, String),
    second: (String, String),
    last: (String, String),
    head: String,
}

fn released(name: &str, head_tree: &Tree, first_two: &Tree) -> Released {
    let repo = Repo::new(name);
    let first_commit = repo.commit(first_two, "first of the level");
    let first = (repo.release("0.76.0", &first_commit), first_commit);
    let next = repo.commit(first_two, "second of the level");
    let second = (repo.release("0.76.0", &next), next);
    let last_commit = repo.commit(&Tree::the_level(), "the level with the lease");
    let last = (repo.release("0.76.0", &last_commit), last_commit);
    let head = repo.commit(head_tree, "after");
    Released {
        repo,
        first,
        second,
        last,
        head,
    }
}

/// A level whose first two releases were made before its last change: they have no `lease`.
fn split(name: &str, head_tree: &Tree) -> Released {
    released(name, head_tree, &Tree::before_the_lease())
}

/// A level whose releases all have the surface the level has.
fn whole_level(name: &str, head_tree: &Tree) -> Released {
    released(name, head_tree, &Tree::the_level())
}

fn run(level: &Released, tree: &Tree) -> Result<Outcome, String> {
    let releases = inventory(&level.repo.directory).expect("an inventory");
    check(
        &level.repo.directory,
        &level.repo.head(tree, &level.head),
        &releases,
    )
}

/// Two releases of a level made before a member the level has: the check names both and the
/// member, and not the release that has it.
#[test]
fn a_level_released_before_its_last_change_fails_naming_the_early_releases() {
    let now = Tree::the_level();
    let level = split("split", &now);
    let error = run(&level, &now).expect_err("the early releases differ");
    assert!(error.contains(&level.first.0), "{error}");
    assert!(error.contains(&level.second.0), "{error}");
    assert!(error.contains("ForwardedMutation.lease"), "{error}");
    assert!(!error.contains(&level.last.0), "{error}");
}

/// A change inside a root a worker's peers read is a difference, and the same change to a type no
/// root reaches is one as well: it is a change to the public contract. A difference both
/// comparisons see is one line.
#[test]
fn a_change_to_a_type_fails_whether_or_not_a_root_reaches_it_and_is_named_once() {
    let now = Tree::the_level();
    let level = whole_level("widened", &now);
    let widened = Tree {
        schema: schema(true, "integer", "string"),
        ..now.clone()
    };
    let error = run(&level, &widened).expect_err("a root changed");
    assert!(error.contains(&level.last.0), "{error}");
    assert!(error.contains("PeerParams.member"), "{error}");
    let outside = Tree {
        schema: schema(true, "string", "integer"),
        ..now.clone()
    };
    let error = run(&level, &outside).expect_err("the public contract changed");
    assert!(error.contains("OutsideEveryRoot.member"), "{error}");

    let repo = Repo::new("named-once");
    let commit = repo.commit(&now, "the level");
    repo.release("0.76.0", &commit);
    let head = repo.commit(&widened, "after");
    let releases = inventory(&repo.directory).expect("an inventory");
    let error =
        check(&repo.directory, &repo.head(&widened, &head), &releases).expect_err("a root changed");
    assert_eq!(
        error.matches("PeerParams.member changed").count(),
        1,
        "{error}"
    );
}

/// A member added to an existing type fails, optional or not, and names the type and the member.
/// A definition that is new passes, and so does a variant added to `Method`; a variant removed from
/// it does not.
#[test]
fn a_member_added_to_a_type_fails_and_a_new_definition_and_a_new_method_pass() {
    let now = Tree::the_level();
    let level = whole_level("members", &now);

    let mut with_member = now.clone();
    with_member.schema["$defs"]["OutsideEveryRoot"]["properties"]["added"] =
        json!({ "type": "string" });
    let error = run(&level, &with_member).expect_err("a member was added");
    assert!(
        error.contains("OutsideEveryRoot.added added: a member"),
        "{error}"
    );

    let mut with_definition = now.clone();
    with_definition.schema["$defs"]["Brand"] = json!({
        "type": "object",
        "properties": { "name": { "type": "string" } },
        "required": ["name"],
    });
    run(&level, &with_definition).expect("a new definition keeps the level");

    let methods = |names: &[&str]| -> Value {
        json!({ "oneOf": names
            .iter()
            .map(|name| json!({ "const": name, "type": "string" }))
            .collect::<Vec<_>>() })
    };
    let repo = Repo::new("methods");
    let mut before = now.clone();
    before.schema["$defs"]["Method"] = methods(&["host.info", "session.read"]);
    let commit = repo.commit(&before, "the level");
    repo.release("0.76.0", &commit);
    let releases = inventory(&repo.directory).expect("an inventory");

    let mut with_method = now.clone();
    with_method.schema["$defs"]["Method"] =
        methods(&["host.info", "session.read", "history.times"]);
    let head = repo.commit(&with_method, "a method");
    check(&repo.directory, &repo.head(&with_method, &head), &releases)
        .expect("a method a daemon serves keeps the level");

    let mut without_method = now.clone();
    without_method.schema["$defs"]["Method"] = methods(&["host.info"]);
    let head = repo.commit(&without_method, "a method fewer");
    let error = check(
        &repo.directory,
        &repo.head(&without_method, &head),
        &releases,
    )
    .expect_err("a method went");
    assert!(
        error.contains("Method#const:session.read removed"),
        "{error}"
    );
}

/// An optional member added to an object the release marked read-only metadata passes, a required
/// one fails, and so does an optional member added to an object that is not marked.
#[test]
fn an_optional_member_of_read_only_metadata_passes_and_a_required_one_fails() {
    let now = Tree::the_level();
    let marked = |members: &[(&str, bool)]| -> Value {
        let mut object = json!({
            "x-kalareach-read-only-metadata": true,
            "type": "object",
            "properties": { "id": { "type": "string" } },
            "required": ["id"],
        });
        for (name, required) in members {
            object["properties"][*name] = json!({ "type": "string" });
            if *required {
                object["required"]
                    .as_array_mut()
                    .expect("a list")
                    .push(json!(name));
            }
        }
        object
    };
    let repo = Repo::new("metadata");
    let mut before = now.clone();
    before.schema["$defs"]["Metadata"] = marked(&[]);
    let commit = repo.commit(&before, "the level");
    repo.release("0.76.0", &commit);
    let releases = inventory(&repo.directory).expect("an inventory");

    let mut optional = now.clone();
    optional.schema["$defs"]["Metadata"] = marked(&[("note", false)]);
    let head = repo.commit(&optional, "an optional member");
    check(&repo.directory, &repo.head(&optional, &head), &releases)
        .expect("a reader of read-only metadata drops a member it does not know");

    let mut required = now.clone();
    required.schema["$defs"]["Metadata"] = marked(&[("note", true)]);
    let head = repo.commit(&required, "a required member");
    let error = check(&repo.directory, &repo.head(&required, &head), &releases)
        .expect_err("a required member is read by no earlier release");
    assert!(error.contains("Metadata.note"), "{error}");

    let mut unmarked = before.clone();
    unmarked.schema["$defs"]["Metadata"]
        .as_object_mut()
        .expect("an object")
        .remove("x-kalareach-read-only-metadata");
    let repo = Repo::new("unmarked");
    let commit = repo.commit(&unmarked, "the level");
    repo.release("0.76.0", &commit);
    let releases = inventory(&repo.directory).expect("an inventory");
    let mut grown = unmarked.clone();
    grown.schema["$defs"]["Metadata"]["properties"]["note"] = json!({ "type": "string" });
    let head = repo.commit(&grown, "an optional member");
    let error = check(&repo.directory, &repo.head(&grown, &head), &releases)
        .expect_err("the earlier release's object was not marked");
    assert!(error.contains("Metadata.note added"), "{error}");
}

/// The plugin SDK schema is held to the level too: a member added to a definition fails, a changed
/// description passes, and a release before the file is compared by the rest with the run saying so.
#[test]
fn the_plugin_sdk_schema_is_held_and_a_description_is_not() {
    let now = Tree::the_level();
    let level = whole_level("sdk", &now);

    let grown = Tree {
        sdk: Some(sdk_schema("The manifest.", true)),
        ..now.clone()
    };
    let error = run(&level, &grown).expect_err("a member was added to the SDK schema");
    assert!(
        error.contains("the plugin SDK schema: Manifest.added added: a member"),
        "{error}"
    );

    let reworded = Tree {
        sdk: Some(sdk_schema("What a plugin states about itself.", false)),
        ..now.clone()
    };
    run(&level, &reworded).expect("a description is not part of the schema's meaning");

    let repo = Repo::new("sdk-absent");
    let early = Tree {
        sdk: None,
        ..now.clone()
    };
    let commit = repo.commit(&early, "a release before the SDK schema");
    let tag = repo.release("0.76.0", &commit);
    let head = repo.commit(&now, "after");
    let releases = inventory(&repo.directory).expect("an inventory");
    let outcome =
        check(&repo.directory, &repo.head(&now, &head), &releases).expect("nothing else differs");
    let Outcome::Held { notes, .. } = outcome else {
        panic!("the level holds");
    };
    assert!(
        notes
            .iter()
            .any(|note| note.contains(&tag) && note.contains("plugin SDK schema")),
        "{notes:?}"
    );
}

/// A root the head no longer has cannot hide the difference: the release's own list is cut too, and
/// the root it named is missing from the head.
#[test]
fn a_root_the_head_dropped_is_a_difference() {
    let now = Tree::the_level();
    let level = whole_level("dropped", &now);
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
    let commit = level.repo.commit(&with_root, "a root of its own");
    let tag = level.repo.release("0.76.0", &commit);
    let head = level.repo.commit(&now, "the head without it");
    let releases = inventory(&level.repo.directory).expect("an inventory");
    let error = check(
        &level.repo.directory,
        &level.repo.head(&now, &head),
        &releases,
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
    let level = whole_level("tables", &now);
    let renamed = Tree {
        worker: Some(worker("session.read", "session.output.v2")),
        ..now.clone()
    };
    let error = run(&level, &renamed).expect_err("an event was renamed");
    assert!(error.contains("session.output was sent there"), "{error}");
    let unserved = Tree {
        worker: Some(worker("session.close", "session.output")),
        ..now.clone()
    };
    let error = run(&level, &unserved).expect_err("a method went");
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
    let outcome =
        check(&repo.directory, &repo.head(&old, &head), &releases).expect("the schema is the same");
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
    let error = check(&repo.directory, &repo.head(&widened, &head), &releases)
        .expect_err("a root the release had no list for changed");
    assert!(error.contains("PeerParams.member"), "{error}");
}

/// The plugin host's protocol and the table of public majors are the level's too.
#[test]
fn the_plugin_host_protocol_and_the_public_majors_are_held() {
    let now = Tree::the_level();
    let level = whole_level("host", &now);
    let host = Tree {
        host: "kr-plugin-host/4",
        ..now.clone()
    };
    let error = run(&level, &host).expect_err("the host protocol moved");
    assert!(error.contains("kr-plugin-host/3"), "{error}");
    let majors = Tree {
        majors: "major=1 versions=1.0,1.1 replaced=- supported_until=- retired=false\n",
        ..now.clone()
    };
    let error = run(&level, &majors).expect_err("the public majors moved");
    assert!(error.contains("public majors"), "{error}");
}

/// With no release at the commit's level the commit moves it.
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
    let outcome = check(&repo.directory, &repo.head(&now, &head), &releases);
    assert_eq!(outcome, Ok(Outcome::MovesTheLevel));
}

/// The releases of a level are the level's without the commit being checked.
#[test]
fn the_releases_of_a_level_leave_out_the_commit_under_test() {
    let now = Tree::the_level();
    let level = whole_level("kept", &now);
    let inventory = inventory(&level.repo.directory).expect("an inventory");
    let wanted = CompatibilityLevel::of(PackageVersion::new(0, 76, 0));
    let tags = |except: &str| -> Vec<String> {
        kept(&inventory, wanted, except)
            .into_iter()
            .map(|release| release.tag)
            .collect()
    };
    let mut all = [
        level.first.0.clone(),
        level.second.0.clone(),
        level.last.0.clone(),
    ];
    all.sort();
    assert_eq!(tags(""), all);
    let mut without_last = [level.first.0.clone(), level.second.0.clone()];
    without_last.sort();
    assert_eq!(tags(&level.last.1), without_last);
}

/// A checkout whose tags are not origin's is refused with its own message, and a tag at the commit
/// under test, which a release makes after it lands, is on one side or both without a failure.
#[test]
fn tags_that_are_not_origins_are_refused() {
    let now = Tree::the_level();
    let level = whole_level("origin", &now);
    let directory = &level.repo.directory;
    let here = inventory(directory).expect("an inventory");
    agree_with_origin(directory, &here, &level.head).expect("the tags agree");

    // A tag origin has and this checkout lacks, and one only this checkout has.
    level.repo.git(&["tag", "-d", &level.second.0]);
    let error = agree_with_origin(
        directory,
        &inventory(directory).expect("an inventory"),
        &level.head,
    )
    .expect_err("a tag is missing here");
    assert!(error.contains(&format!(
        "{} is on origin and not in this checkout",
        level.second.0
    )));
    assert!(error.contains("git fetch --force --prune"), "{error}");
    level.repo.git(&["tag", &level.second.0, &level.second.1]);
    let local_only = level.repo.tag_here("0.76.1", &level.head);
    // At the commit under test: left out on its own side.
    agree_with_origin(
        directory,
        &inventory(directory).expect("an inventory"),
        &level.head,
    )
    .expect("a tag at the commit under test may be on one side");
    // At any other commit it is a difference.
    let error = agree_with_origin(
        directory,
        &inventory(directory).expect("an inventory"),
        &level.last.1,
    )
    .expect_err("a tag only here");
    assert!(error.contains(&format!(
        "{local_only} is in this checkout and not on origin"
    )));
    level.repo.git(&["tag", "-d", &local_only]);

    // The same name at another commit.
    level.repo.git(&["tag", "-d", &level.second.0]);
    level.repo.git(&["tag", &level.second.0, &level.first.1]);
    let error = agree_with_origin(
        directory,
        &[crate::releases::Release {
            tag: level.second.0.clone(),
            version: PackageVersion::new(0, 76, 0),
            commit: level.first.1.clone(),
        }],
        &level.head,
    )
    .expect_err("another commit");
    assert!(error.contains("on origin"), "{error}");
}

/// An origin that cannot be listed fails the check, and is never an empty list.
#[test]
fn an_origin_that_cannot_be_listed_fails_closed() {
    let now = Tree::the_level();
    let level = whole_level("closed", &now);
    level
        .repo
        .git(&["remote", "set-url", "origin", "/nonexistent/origin.git"]);
    let error = agree_with_origin(
        &level.repo.directory,
        &inventory(&level.repo.directory).expect("an inventory"),
        &level.head,
    )
    .expect_err("an origin that does not answer");
    assert!(error.contains("cannot be listed"), "{error}");
    let _ = level.repo.origin.exists();
}

/// A release whose tree cannot be read fails the check and is not left out of it.
#[test]
fn a_release_whose_schema_cannot_be_read_fails_the_check() {
    let now = Tree::the_level();
    let level = whole_level("unreadable", &now);
    // A release tag whose commit holds no schema: made from an empty commit on a branch.
    level.repo.git(&["checkout", "-q", "--orphan", "bare"]);
    level.repo.git(&["rm", "-rfq", "--cached", "."]);
    level.repo.write("empty", "nothing");
    level.repo.write(
        "packages/protocol/package.json",
        "{\"version\": \"0.76.0\"}\n",
    );
    level
        .repo
        .git(&["add", "empty", "packages/protocol/package.json"]);
    level
        .repo
        .git(&["commit", "-q", "-m", "a release without a schema"]);
    let bare = level.repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    level.repo.release("0.76.0", &bare);
    let releases = inventory(&level.repo.directory).expect("an inventory");
    let error = check(
        &level.repo.directory,
        &level.repo.head(&now, &level.head),
        &releases,
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
    conclude(&repo.directory, &data, &releases, true, &cut).expect("the cut's check passes");
    assert_eq!(
        calls.get(),
        1,
        "run once for the commit that moves the level"
    );
    conclude(&repo.directory, &data, &releases, false, &cut).expect("nothing to compare");
    assert_eq!(calls.get(), 1, "not run when it is told to leave it");
    let failing = |_: &Path| Err("the cut's check said no".to_owned());
    let error = conclude(&repo.directory, &data, &releases, true, &failing)
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
        kept_release_differences(&repo.directory, &same, &kept, majors, "kr-plugin-host/3")
            .expect("compared")
            .is_empty()
    );

    // A root the release declares that the kept surface does not have, and a difference in it.
    let mut more = kept_tree.clone();
    more.roots = vec!["ControlFrame", "PeerParams"];
    let extra = release_of(&more, "a root of its own", false);
    let found =
        kept_release_differences(&repo.directory, &extra, &kept, majors, "kr-plugin-host/3")
            .expect("compared");
    assert!(
        found.iter().any(|line| line.contains("PeerParams")),
        "{found:?}"
    );

    // A root that is not a definition of the release's own schema is refused, not cut around.
    let mut misspelled = kept_tree.clone();
    misspelled.roots = vec!["ControlFrame", "ControlFrme"];
    let bad = release_of(&misspelled, "a misspelled root", false);
    let error = kept_release_differences(&repo.directory, &bad, &kept, majors, "kr-plugin-host/3")
        .expect_err("refused");
    assert!(error.contains("ControlFrme"), "{error}");

    // A root of the kept surface that the release's own schema does not define: removed.
    let kept_wide =
        Surface::cut(&kept_tree.schema, &["ControlFrame", "PeerResult"]).expect("a surface");
    let mut narrower = kept_tree.clone();
    narrower.schema["$defs"]
        .as_object_mut()
        .expect("definitions")
        .remove("PeerResult");
    let lacking = release_of(&narrower, "without a root the level kept", false);
    let found = kept_release_differences(
        &repo.directory,
        &lacking,
        &kept_wide,
        majors,
        "kr-plugin-host/3",
    )
    .expect("compared");
    assert!(
        found
            .iter()
            .any(|line| line.contains("PeerResult removed: a root the new surface lacks")),
        "{found:?}"
    );

    // A release on a branch the history does not reach, whose plugin host protocol differs, held
    // against a table of public majors that is not the one it has.
    let aside = Tree {
        host: "kr-plugin-host/4",
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
        "kr-plugin-host/3",
    )
    .expect("compared");
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found.iter().any(|line| line.contains("public majors")));
    assert!(found.iter().any(|line| line.contains("kr-plugin-host/4")));
}

/// The list of roots is read by the one reader of Rust source the tooling has: in whatever layout
/// it is written, with comments and strings that look like code left alone, and a source that
/// declares it otherwise, twice, or not at all is told apart.
#[test]
fn the_list_of_surface_roots_is_read_strictly() {
    use crate::releases::surface_roots_in;
    let around = |declaration: &str| {
        format!(
            "// SURFACE_ROOTS: not this\n/* pub const SURFACE_ROOTS: &[&str] = &[\"Old\"]; */\n\
             const MARKER: &str = \"/*\";\nconst GLOB: &str = \"crates/*\";\n{declaration}\n\
             const SHOWN: &str = \"{{SURFACE_ROOTS:?}}\";\nuse(SURFACE_ROOTS);\n"
        )
    };
    let two = Some(vec!["A".to_owned(), "B".to_owned()]);
    for (what, declaration) in [
        (
            "one to a line",
            "pub const SURFACE_ROOTS: &[&str] = &[\n    \"A\",\n    \"B\",\n];",
        ),
        (
            "a root on the line of the declaration",
            "pub const SURFACE_ROOTS: &[&str] = &[\"A\",\n    \"B\",\n];",
        ),
        (
            "all on one line",
            "pub const SURFACE_ROOTS: &[&str] = &[\"A\", \"B\"];",
        ),
        (
            "with comments between the entries",
            "pub const SURFACE_ROOTS: &[&str] = &[\n    \"A\", // the first\n    /* then */ \"B\"\n];",
        ),
    ] {
        assert_eq!(
            surface_roots_in(&around(declaration)).expect(what),
            two,
            "{what}"
        );
    }
    assert_eq!(
        surface_roots_in("fn nothing() { f(SURFACE_ROOTS); }").expect("none"),
        None
    );
    for (what, declaration) in [
        (
            "no space before the colon is no other declaration",
            "pub const SURFACE_ROOTS:&[&str] = &[\n    \"A\",\n];".to_owned(),
        ),
        (
            "the name apart from its colon by a line break",
            "pub const SURFACE_ROOTS\n    : &[&str] = &[\n    \"A\",\n];".to_owned(),
        ),
        (
            "the name apart from its colon by a comment",
            "pub const SURFACE_ROOTS /* the roots */: &[&str] = &[\n    \"A\",\n];".to_owned(),
        ),
        (
            "another keyword before it",
            "static SURFACE_ROOTS: &[&str] = &[\n    \"A\",\n];".to_owned(),
        ),
        (
            "an entry that is not a literal",
            "pub const SURFACE_ROOTS: &[&str] = &[\n    NAMED,\n];".to_owned(),
        ),
        (
            "a list that does not end",
            "pub const SURFACE_ROOTS: &[&str] = &[\n    \"A\",\n".to_owned(),
        ),
        (
            "twice",
            "pub const SURFACE_ROOTS: &[&str] = &[\"A\"];\npub const SURFACE_ROOTS: &[&str] = &[\"B\"];"
                .to_owned(),
        ),
    ] {
        assert!(
            surface_roots_in(&around(&declaration)).is_err(),
            "{what} is refused"
        );
    }
}

/// The plugin host protocol is read as a constant of the one shape, from the code and not from a
/// comment that quotes an older one.
#[test]
fn the_plugin_host_protocol_is_read_from_the_code() {
    use crate::public_majors::string_const;
    let source = "// pub const PLUGIN_HOST_PROTOCOL: &str = \"kr-plugin-host/1\";\n\
                  pub const PLUGIN_HOST_PROTOCOL: &str = \"kr-plugin-host/3\";\n";
    assert_eq!(
        string_const(source, "PLUGIN_HOST_PROTOCOL").expect("read"),
        Some("kr-plugin-host/3".to_owned())
    );
    assert_eq!(
        string_const("fn f() {}", "PLUGIN_HOST_PROTOCOL").expect("none"),
        None
    );
    for (what, text) in [
        (
            "twice",
            "pub const PLUGIN_HOST_PROTOCOL: &str = \"a\";\npub const PLUGIN_HOST_PROTOCOL: &str = \"b\";",
        ),
        (
            "not a string literal",
            "pub const PLUGIN_HOST_PROTOCOL: &str = OTHER;",
        ),
        (
            "another keyword",
            "static PLUGIN_HOST_PROTOCOL: &str = \"a\";",
        ),
        (
            "an escape",
            "pub const PLUGIN_HOST_PROTOCOL: &str = \"a\\nb\";",
        ),
    ] {
        assert!(
            string_const(text, "PLUGIN_HOST_PROTOCOL").is_err(),
            "{what}"
        );
    }
    // Another constant that ends in the name is not it.
    assert_eq!(
        string_const(
            "pub const OTHER_PLUGIN_HOST_PROTOCOL: &str = \"x\";",
            "PLUGIN_HOST_PROTOCOL"
        )
        .expect("none"),
        None
    );
}

/// A root a revision declares that its own schema does not define is refused, and is not cut around:
/// the release's table lists one, and so does the head's.
#[test]
fn a_declared_root_that_is_no_definition_is_refused() {
    let now = Tree::the_level();
    let level = whole_level("misspelled", &now);
    let mut bad = now.clone();
    let mut table = worker("session.read", "session.output");
    table["peer_roots"] = json!(["PeerParams", "PeerResult", "PeerParamz"]);
    bad.worker = Some(table);
    let commit = level
        .repo
        .commit(&bad, "a release that lists a root it lacks");
    level.repo.release("0.76.0", &commit);
    let head = level.repo.commit(&now, "after");
    let releases = inventory(&level.repo.directory).expect("an inventory");
    let error = check(
        &level.repo.directory,
        &level.repo.head(&now, &head),
        &releases,
    )
    .expect_err("a release lists a root its schema lacks");
    assert!(error.contains("PeerParamz"), "{error}");

    let mut table = worker("session.read", "session.output");
    table["peer_roots"] = json!(["PeerParams", "PeerResult", "PeerParamz"]);
    let mut head_data = level.repo.head(&now, &head);
    head_data.worker = WorkerSurface::parse(&table.to_string()).expect("a table");
    let only_whole = inventory(&level.repo.directory).expect("an inventory");
    let error = check(&level.repo.directory, &head_data, &only_whole)
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
    // A file that is there and declares no list is not an absent one either.
    repo.git(&["reset", "-q", "--hard", &commit]);
    repo.write(
        "crates/kr-protocol/src/retained.rs",
        "pub const PLUGIN_HOST_PROTOCOL: &str = \"kr-plugin-host/3\";\n",
    );
    repo.git(&["add", "-A"]);
    repo.git(&["commit", "-q", "-m", "a file without the list"]);
    let unlisted = repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    let error = surface_roots_at(&repo.directory, &unlisted).expect_err("no list");
    assert!(error.contains("declares no SURFACE_ROOTS"), "{error}");
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

/// What looks like code inside a literal is not code, whichever literal it is in: a raw string of
/// any form that holds a whole declaration and a stray quote does not hide the real one (it is
/// refused, since the reader does not read raw strings), and a character literal that is a quote, or
/// is not ASCII, neither opens a string (a comment after it is still a comment) nor moves the
/// offsets of what follows.
#[test]
fn literals_that_look_like_code_do_not_change_what_is_read() {
    use crate::public_majors::{string_const, string_list};
    let raw = "const EXAMPLE: &str = r#\"\" pub const SURFACE_ROOTS: &[&str] = &[\"ControlFrame\"]; \"#;\n\
               pub const SURFACE_ROOTS: &[&str] = &[\"ControlFrame\", \"PeerParams\"];\n\
               const QUOTE: &str = r#\"\"\"#;\n";
    assert!(
        string_list(raw, "SURFACE_ROOTS").is_err(),
        "a raw string is refused"
    );
    // The same, after two character literals that a lexer reading a bounded stretch of an escape
    // would take for one (`','` between a long unicode escape and a quote), so that the quote
    // opens a false string and the raw string's opener is not seen.
    let after_literals = "const PAIR: (char, char) = ('\\u{0__________}','\"');\n\
         const EXAMPLE: &str = r#\"pub const SURFACE_ROOTS: &[&str] = &[\"ControlFrame\"]; \"#;\n\
         pub const SURFACE_ROOTS: &[&str] = &[\"ControlFrame\", \"PeerParams\"];\n\
         const QUOTE: &str = r#\"\"\"#;\n";
    let error = string_list(after_literals, "SURFACE_ROOTS").expect_err("refused");
    assert!(
        error.contains("raw string"),
        "a raw string after two character literals is refused as one: {error}"
    );
    // Every prefix a raw string has: the quote that opens it follows an `r` or a `#`.
    for opener in ["r\"", "r#\"", "r##\"", "br\"", "br#\"", "cr\"", "cr#\""] {
        let source =
            format!("const A: &[u8] = {opener}x\";\npub const SURFACE_ROOTS: &[&str] = &[\"A\"];");
        assert!(
            string_list(&source, "SURFACE_ROOTS").is_err(),
            "{opener} opens a raw string and is refused"
        );
    }
    // The strings that are not raw, and a raw identifier, are read.
    assert_eq!(
        string_list(
            "const A: &[u8] = b\"x\";\nconst B: &CStr = c\"y\";\nconst r#type: u8 = 1;\n\
             pub const SURFACE_ROOTS: &[&str] = &[\"A\"];",
            "SURFACE_ROOTS"
        )
        .expect("read"),
        Some(vec!["A".to_owned()])
    );
    for (what, literal) in [
        ("an escaped double quote", "'\\\"'"),
        ("an escaped single quote", "'\\''"),
        ("an escaped newline", "'\\n'"),
        ("a unicode escape", "'\\u{1F600}'"),
        ("a unicode escape with underscores", "'\\u{1_F_6_0_0}'"),
        ("a hexadecimal escape", "'\\x41'"),
        ("a null escape", "'\\0'"),
        ("an escaped tab", "'\\t'"),
        ("an escaped carriage return", "'\\r'"),
        ("an escaped backslash", "'\\\\'"),
        ("an escaped quote and a quote", "('\\'','\"')"),
        (
            "a long unicode escape and a quote",
            "('\\u{0__________}','\"')",
        ),
        ("a non-ASCII character", "'é'"),
        ("a double quote", "'\"'"),
    ] {
        let source = format!(
            "const C: char = {literal};\n// pub const SURFACE_ROOTS: &[&str] = &[\"Decoy\"];\n\
             pub const PLUGIN_HOST_PROTOCOL: &str = \"kr-plugin-host/3\";\n\
             pub const SURFACE_ROOTS: &[&str] = &[\"A\"];\n"
        );
        assert_eq!(
            string_const(&source, "PLUGIN_HOST_PROTOCOL").expect(what),
            Some("kr-plugin-host/3".to_owned()),
            "{what}"
        );
        assert_eq!(
            string_list(&source, "SURFACE_ROOTS").expect(what),
            Some(vec!["A".to_owned()]),
            "{what}"
        );
    }
    // A quote and a backslash that make no character literal are no valid source: refused.
    for literal in ["'\\q'", "'\\u{12'", "'\\u12'", "'\\x4'", "'\\n"] {
        let source =
            format!("const C: char = {literal};\npub const SURFACE_ROOTS: &[&str] = &[\"A\"];\n");
        assert!(
            string_list(&source, "SURFACE_ROOTS").is_err(),
            "{literal} is no character literal and is refused"
        );
    }
}

/// This tree's own `retained.rs` reads, with the reader the cut uses, as the roots and the plugin
/// host protocol the build has, so a form the reader refuses is found in the commit that writes it
/// and not at the next release, whose tag cannot change.
#[test]
fn this_trees_retained_source_reads_as_the_build_has_it() {
    use crate::public_majors::{string_const, string_list};
    use kr_protocol::retained::{PLUGIN_HOST_PROTOCOL, SURFACE_ROOTS};
    let source = include_str!("../../retained.rs");
    assert_eq!(
        string_list(source, "SURFACE_ROOTS").expect("read"),
        Some(
            SURFACE_ROOTS
                .iter()
                .map(|root| (*root).to_owned())
                .collect()
        )
    );
    assert_eq!(
        string_const(source, "PLUGIN_HOST_PROTOCOL")
            .expect("read")
            .as_deref(),
        Some(PLUGIN_HOST_PROTOCOL)
    );
}
