//! The rules that decide what the types of the retained surface accept, held against the release
//! each retained level was cut from.
//!
//! The schema a release generates shows the shape of its types and none of the rules their decoders
//! apply: an identifier refuses a control character in a function its macro calls, a set refuses an
//! order, a right refuses to travel. `kr-protocol-gen --check` compares the shapes. This compares
//! the rules, three ways, and is a regression net and not a proof:
//!
//! * **Sources.** Each rule is a root in [`ROOTS`]. The walker follows everything the root names in
//!   the workspace's crates and digests it, so a change in a helper moves the digest of every root
//!   that reaches the helper. A level records the digests its release had
//!   (`retained/<level>/sources.json`).
//! * **Completeness.** Every type of the surface that carries a rule (a hand-written decoder, a
//!   type-defining macro, a serde attribute that changes how it is read or written), and every
//!   such type a surface type holds, is covered by the items some root followed, or is excluded by
//!   name with a reason.
//! * **Probes.** [`probes::probes`] gives inputs and whether this build accepts each; a level
//!   records what its release did (`retained/<level>/vectors.json`).
//!
//! A difference from a level's record needs a reviewed [`SAME`] entry, which says the change leaves
//! what the level accepts as it was and carries the new digest.
//!
//! The limits of this, which the document on the support window states: a rule in a dependency
//! (serde, uuid, base64), a rule reached through trait dispatch that no path names, a rule applied
//! in a handler that is not a root, an input no probe covers, and the encode side of a type, which
//! the recorded frames and golden pairs show.
//!
//! Run with `KR_RELEASE_TREE=<a checkout of the release's crates>` the same comparison reads that
//! tree's source, which is how a landing checks that the release a level was cut from is the one
//! it names. `record_the_rules_of_the_surface` (ignored by default) writes the records of a level
//! from such a tree.

#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use kr_protocol::retained::{RETAINED, RetainedLevel};
use serde_json::{Value, json};

#[path = "retained_surface/probes.rs"]
mod probes;
// The reader that `kr-protocol-gen` records a level's table of public majors with.
#[path = "../../kr-protocol/src/bin/kr-protocol-gen/public_majors.rs"]
mod public_majors;
#[path = "retained_surface/walker.rs"]
mod walker;

use walker::{Depth, Followed, Tree};

/// A rule of the surface: where it is rooted, and the names it is followed from.
struct Root {
    label: String,
    krate: &'static str,
    names: Vec<String>,
    depth: Depth,
}

fn root(label: &str, krate: &'static str, names: &[&str], depth: Depth) -> Root {
    Root {
        label: label.to_owned(),
        krate,
        names: names.iter().map(|name| (*name).to_owned()).collect(),
        depth,
    }
}

/// The wrappers that carry a rule and that types of the surface hold in their fields, which are no
/// definitions of the schema themselves. `Sentence` is the text of a capability record's reason,
/// which the disclosed checks' answer carries.
const WRAPPERS: &[&str] = &["Nullable", "CanonicalSet", "Sentence"];

/// Types with a rule of their own that are held by a type of the surface and that no root covers,
/// with why.
const EXCLUDED: &[(&str, &str)] = &[];

/// The digest a [`Same`] entry names for a root that is no longer followed, because the rule that
/// made it a root is gone.
const REMOVED: &str = "removed";

/// A change to a rule that a reviewer found leaves what the level accepts as it was: the root, the
/// digest it now has ([`REMOVED`] when the rule is gone), and why.
struct Same {
    root: &'static str,
    digest: &'static str,
    reason: &'static str,
}

const SAME: &[Same] = &[
    Same {
        root: "ForwardedMutation",
        digest: "815a9cb51701f6f459514684e2c818c6d59640522d10ab55100bbe2bbc18c3c6",
        reason: "Two members that are absent from the wire. One is sent only in a workflow's close \
                 of a session it started, to the worker the daemon started that session's command \
                 on, never to a worker of the retained level. The other is sent only when the \
                 daemon forwards a paired device's mutation to a worker at this release's own \
                 level, which holds the dispatch to the lease; the daemon omits it on a link to a \
                 worker of the retained level. Every other forwarded mutation is byte for byte \
                 what that level reads, and what that level accepts is unchanged.",
    },
    Same {
        root: "SessionSummary",
        digest: "7fe58d83a5989335c94b5e105f5cbce3a42cda57d60510c18ba096a3e6bb6c19",
        reason: "A member that is absent from the wire for the interactive shell every other \
                 session has. A worker of the retained level never writes it, and this build \
                 reads a summary without it as a session whose root is a shell, so what that \
                 level writes is read as before.",
    },
    Same {
        root: "WorkerLaunchSpec",
        digest: "1dbe88292acb0c5093405c88fd4b6de5b953318737d9466ff8a23c569a8db469",
        reason: "Three members that are absent from the wire unless a workflow started the \
                 session. The specification of an ordinary session is byte for byte what a \
                 worker of the retained level reads, and a launch specification goes only to a \
                 worker the daemon of this release started, so what that level accepts is \
                 unchanged.",
    },
];

/// The rules of the surface, as the roots the walker follows them from:
///
/// * the rules of every macro that defines items (`macro opaque_id`): what its body does with its
///   arguments, helpers included, and none of its calls;
/// * every type of the surface that carries a rule of its own (a hand-written decoder, a macro
///   that defines it, a serde attribute that changes how it is read or written), by name: its
///   definition, what its macro and its attributes name, and its trait impls with everything they
///   call. A type added to the surface has no record and is not a difference; one that changes is;
/// * the wrappers such types are held in;
/// * the rules that are methods or modules (`ActionTarget::validate`, `worker_rights`);
/// * the limits every frame is read under;
/// * the rules a worker applies to what it receives, digested alone.
fn roots(tree: &Tree) -> Vec<Root> {
    let mut roots = Vec::new();
    for name in tree.called_macros("kr_protocol").expect("the macros") {
        roots.push(root(
            &format!("macro {name}"),
            "kr_protocol",
            &[&format!("macro:{name}")],
            Depth::Everything,
        ));
    }
    for name in WRAPPERS {
        roots.push(root(name, "kr_protocol", &[name], Depth::Rules));
    }
    for name in tree.rule_bearing_surface_types() {
        roots.push(root(&name, "kr_protocol", &[&name], Depth::Rules));
    }
    for (label, names) in [
        (
            "the rights beside a forwarded mutation",
            vec!["worker_rights"],
        ),
        ("ActionTarget::validate", vec!["ActionTarget::validate"]),
        ("Dimensions::validate", vec!["Dimensions::validate"]),
        (
            "CallerToken::is_well_formed",
            vec!["CallerToken::is_well_formed", "CALLER_TOKEN_BYTES"],
        ),
        ("RevisionReach::is_host", vec!["RevisionReach::is_host"]),
    ] {
        roots.push(root(label, "kr_protocol", &names, Depth::Everything));
    }
    roots.push(root(
        "the limits of every frame",
        "kr_cbor",
        &["Limits"],
        Depth::Everything,
    ));
    roots.push(root(
        "the attention text a worker serves",
        "kr_worker",
        &["texts"],
        Depth::Alone,
    ));
    roots.push(root(
        "the envelope a worker checks",
        "kr_worker",
        &["check_envelope"],
        Depth::Alone,
    ));
    roots
}

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The tree whose source is read: the release named by `KR_RELEASE_TREE`, else this checkout.
fn tree() -> Tree {
    let root = std::env::var_os("KR_RELEASE_TREE").map_or_else(repository, PathBuf::from);
    Tree::at(&root).unwrap_or_else(|error| panic!("{}: {error}", root.display()))
}

fn follow_all(tree: &Tree) -> BTreeMap<String, Followed> {
    roots(tree)
        .into_iter()
        .map(|root| {
            let names: Vec<&str> = root.names.iter().map(String::as_str).collect();
            let followed = tree
                .follow_with(root.krate, &names, root.depth)
                .unwrap_or_else(|error| panic!("{}: {error}", root.label));
            (root.label, followed)
        })
        .collect()
}

fn level_directory(level: &RetainedLevel) -> PathBuf {
    repository()
        .join("crates/kr-protocol/retained")
        .join(level.level.to_string())
}

fn read_record(level: &RetainedLevel, name: &str) -> Value {
    let path = level_directory(level).join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn same_for(root: &str, digest: &str) -> Option<&'static Same> {
    SAME.iter()
        .find(|entry| entry.root == root && entry.digest == digest)
}

/// The digests of the rules are the ones the previous release had, or a reviewer says the change
/// leaves what it accepted as it was.
#[test]
fn the_rules_of_the_surface_are_the_ones_the_previous_release_had() {
    let followed = follow_all(&tree());
    let mut problems = Vec::new();
    for level in &RETAINED {
        let recorded = read_record(level, "sources.json");
        let recorded = recorded["roots"].as_object().expect("a record of roots");
        // A rule the previous release had that this tree does not follow any more (a decoder
        // written by hand that a derive replaced, a type renamed) is a change in what is accepted
        // unless a reviewer says otherwise.
        for label in recorded.keys() {
            if !followed.contains_key(label.as_str()) && same_for(label, REMOVED).is_none() {
                problems.push(format!(
                    "level {}: {label} had a rule recorded and this tree follows none",
                    level.level
                ));
            }
        }
        for (label, now) in &followed {
            let Some(before) = recorded.get(label.as_str()) else {
                // A type the previous release's surface held without a rule of its own, and that
                // has one now, accepts what it did not before. A type or a macro the surface did
                // not hold is not a difference from it.
                if level.surface().definition(label).is_some()
                    && same_for(label, &now.digest).is_none()
                {
                    problems.push(format!(
                        "level {}: {label} is a type of the surface that had no rule of its own and has one now (digest {})",
                        level.level, now.digest
                    ));
                }
                continue;
            };
            let before = before["digest"].as_str().unwrap_or_default();
            if before != now.digest && same_for(label, &now.digest).is_none() {
                let names: BTreeSet<&str> = before_items(&recorded[label.as_str()])
                    .into_iter()
                    .collect();
                let now_names: BTreeSet<&str> = now.items.iter().map(String::as_str).collect();
                problems.push(format!(
                    "level {}: what {label} names changed (digest {} now, {before} recorded); items only recorded: {:?}; items only now: {:?}",
                    level.level,
                    now.digest,
                    names.difference(&now_names).collect::<Vec<_>>(),
                    now_names.difference(&names).collect::<Vec<_>>(),
                ));
            }
        }
    }
    // An entry says why this checkout's digest of a root differs from the record, so it is held
    // to this checkout. A release's own tree has no difference to explain and is never held to
    // one.
    let own_tree = std::env::var_os("KR_RELEASE_TREE").is_none();
    for entry in SAME.iter().filter(|_| own_tree) {
        let now = followed.get(entry.root);
        let matches = match now {
            Some(now) => now.digest == entry.digest,
            None => entry.digest == REMOVED,
        };
        if !matches {
            problems.push(format!(
                "a Same entry for {} matches no digest now ({})",
                entry.root, entry.reason
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

fn before_items(record: &Value) -> Vec<&str> {
    record["followed"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

/// The table of public majors a level recorded is the one in the tree of its release.
///
/// Unlike the records above, which this checkout is held to whatever tree is read, a table may
/// legitimately differ in this checkout (a major replaced since), so this runs where the release's
/// own tree is named: a landing sets `KR_RELEASE_TREE`. The tree's package version says which
/// retained level it is the release of, and that level's record is compared whole, digest
/// included, with the table read out of the tree's `hello.rs`; for a tree whose source lists no
/// table the record is the one major its protocol version names. A tree that is no retained
/// level's release is a failure.
#[test]
fn the_table_of_public_majors_a_level_recorded_is_the_one_in_its_release_tree() {
    let Some(root) = std::env::var_os("KR_RELEASE_TREE") else {
        return;
    };
    let root = Path::new(&root);
    let source = std::fs::read_to_string(root.join("crates/kr-protocol/src/hello.rs"))
        .unwrap_or_else(|error| panic!("hello.rs of the release tree: {error}"));
    let expected = match public_majors::record_of(&source)
        .unwrap_or_else(|error| panic!("the table in the release tree: {error}"))
    {
        Some(record) => record,
        None => public_majors::record_without_a_table(&source)
            .unwrap_or_else(|error| panic!("the release tree lists no table: {error}")),
    };
    let package: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("packages/protocol/package.json"))
            .unwrap_or_else(|error| panic!("the release tree's package: {error}")),
    )
    .expect("a package manifest");
    let version = package["version"].as_str().expect("a package version");
    let numbers: Vec<u16> = version
        .split('.')
        .map(|part| part.parse().expect("a number"))
        .collect();
    let level = kr_protocol::update::CompatibilityLevel::of(
        kr_protocol::hello::PackageVersion::new(numbers[0], numbers[1], numbers[2]),
    );
    let retained = RETAINED
        .iter()
        .find(|retained| retained.level == level)
        .unwrap_or_else(|| {
            panic!("the release tree is {version}, and no retained level is {level}")
        });
    assert_eq!(
        retained.public_majors,
        Some(expected.as_str()),
        "level {level}: recorded against the release tree"
    );
}

/// A limit may be added and may not change or go.
#[test]
fn a_limit_the_previous_release_had_is_the_one_this_build_has() {
    let now = tree().limits("kr_protocol").expect("limits");
    let mut problems = Vec::new();
    for level in &RETAINED {
        let recorded = read_record(level, "limits.json");
        for (name, before) in recorded.as_object().expect("a record of limits") {
            match now.get(name) {
                None => problems.push(format!("level {}: limit {name} is gone", level.level)),
                Some(text) if Some(text.as_str()) != before.as_str() => {
                    problems.push(format!("level {}: limit {name} is now {text}", level.level));
                }
                Some(_) => {}
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The probes come out as the previous release's did.
#[test]
fn the_probes_are_answered_as_the_previous_release_answered_them() {
    let now = probes::probes();
    let mut problems = Vec::new();
    for level in &RETAINED {
        let recorded = read_record(level, "vectors.json");
        let recorded = recorded.as_object().expect("a record of probes");
        for (label, accepted) in &now {
            match recorded.get(*label).and_then(Value::as_bool) {
                Some(before) if before == *accepted => {}
                Some(before) => problems.push(format!(
                    "level {}: \"{label}\" was {} and is {}",
                    level.level,
                    answer(before),
                    answer(*accepted)
                )),
                // A probe added after the level was kept has no answer from it; it is compared from
                // the next level.
                None => {}
            }
        }
        for label in recorded.keys() {
            if !now.iter().any(|(name, _)| name == label) {
                problems.push(format!(
                    "level {}: the probe \"{label}\" is gone",
                    level.level
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

fn answer(accepted: bool) -> &'static str {
    if accepted { "accepted" } else { "refused" }
}

/// Every type with a rule that a type of the surface holds is covered by a root or excluded by name.
///
/// The types of the surface that carry a rule are roots by construction. What this finds is a
/// wrapper or a helper type that a surface type holds in a field, which is no definition of the
/// schema itself and so would be missed: `Nullable` and `CanonicalSet` are such.
#[test]
fn every_type_with_a_rule_that_the_surface_holds_is_covered() {
    let tree = tree();
    let with_rules = tree
        .types_with_rules("kr_protocol")
        .expect("the types with rules");
    let surface = kr_protocol::retained::current();
    let held = tree
        .held_by("kr_protocol", surface.names().map(str::to_owned).collect())
        .expect("what the surface types hold");
    let covered: BTreeSet<String> = roots(&tree)
        .iter()
        .flat_map(|root| root.names.iter().cloned())
        .collect();
    let mut uncovered = Vec::new();
    for name in &held {
        let Some(why) = with_rules.get(name) else {
            continue;
        };
        let in_surface = surface.definition(name).is_some();
        if in_surface
            || covered.contains(name)
            || EXCLUDED.iter().any(|(excluded, _)| excluded == name)
        {
            continue;
        }
        uncovered.push(format!("{name} ({why})"));
    }
    assert!(
        uncovered.is_empty(),
        "types with a rule that a type of the surface holds and that no root covers; add a root or an exclusion with a reason:\n{}",
        uncovered.join("\n")
    );
    for (name, reason) in EXCLUDED {
        assert!(!reason.is_empty(), "the exclusion of {name} needs a reason");
        assert!(
            held.contains(*name),
            "{name} is excluded and no type of the surface holds it"
        );
    }
    for name in WRAPPERS {
        assert!(
            held.contains(*name),
            "{name} is a wrapper root and no type of the surface holds it"
        );
    }
}

/// Writes the records of a level from a checkout of the release it was cut from. Run with
/// `KR_RELEASE_TREE` set to that checkout and `--ignored`.
#[test]
#[ignore = "writes the records of a retained level; run by hand against a checkout of its release"]
fn record_the_rules_of_the_surface() {
    let release =
        std::env::var_os("KR_RELEASE_TREE").expect("KR_RELEASE_TREE names the release's checkout");
    let released = Tree::at(Path::new(&release)).expect("the release's tree");
    let in_release = follow_all(&released);
    // The probes are answered by this checkout's code, so the rules it holds must be the
    // release's: every root must digest the same in both.
    let here = follow_all(&Tree::at(&repository()).expect("this checkout"));
    for (label, followed) in &in_release {
        let (now, then): (BTreeSet<&String>, BTreeSet<&String>) = (
            here[label].items.iter().collect(),
            followed.items.iter().collect(),
        );
        assert_eq!(
            here[label].digest,
            followed.digest,
            "{label} differs between this checkout and the release, so the probes would not be the \
             release's; items only here: {:?}; items only there: {:?}",
            now.difference(&then).collect::<Vec<_>>(),
            then.difference(&now).collect::<Vec<_>>()
        );
    }
    for level in &RETAINED {
        let directory = level_directory(level);
        let roots: serde_json::Map<String, Value> = in_release
            .iter()
            .map(|(label, followed)| {
                (
                    label.clone(),
                    json!({ "digest": followed.digest, "followed": followed.items }),
                )
            })
            .collect();
        write(&directory.join("sources.json"), &json!({ "roots": roots }));
        let limits: serde_json::Map<String, Value> = released
            .limits("kr_protocol")
            .expect("limits")
            .into_iter()
            .map(|(name, text)| (name, Value::String(text)))
            .collect();
        write(&directory.join("limits.json"), &Value::Object(limits));
        let vectors: serde_json::Map<String, Value> = probes::probes()
            .into_iter()
            .map(|(label, accepted)| (label.to_owned(), Value::Bool(accepted)))
            .collect();
        write(&directory.join("vectors.json"), &Value::Object(vectors));
    }
}

fn write(path: &Path, value: &Value) {
    let mut text = serde_json::to_string_pretty(value).expect("text");
    text.push('\n');
    std::fs::write(path, text).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    println!("wrote {}", path.display());
}

/// A change inside a helper that a rule calls moves the digest of the rule: the walker follows the
/// control-character check an identifier macro calls, and a changed check is a changed digest.
#[test]
fn a_change_inside_a_helper_a_rule_calls_moves_its_digest() {
    let copy = tempfile::tempdir().expect("a temporary directory");
    copy_crates(
        &repository(),
        copy.path(),
        &["kr-protocol", "kr-cbor", "kr-worker"],
    );
    let before = Tree::at(copy.path())
        .expect("the copy")
        .follow("kr_protocol", &["opaque_id"])
        .expect("followed");
    assert!(
        before
            .items
            .iter()
            .any(|item| item.ends_with(": validate_opaque_id")),
        "the helper the macro calls is followed: {:?}",
        before.items
    );
    // The control-character check of the helper, loosened.
    let ids = copy.path().join("crates/kr-protocol/src/ids.rs");
    let text = std::fs::read_to_string(&ids).expect("ids.rs");
    let loosened = text.replace(
        "value.chars().any(char::is_control)",
        "value.chars().any(|c| c == '\\u{0}')",
    );
    assert_ne!(text, loosened, "the check is where this test expects it");
    std::fs::write(&ids, loosened).expect("write");
    let after = Tree::at(copy.path())
        .expect("the changed copy")
        .follow("kr_protocol", &["opaque_id"])
        .expect("followed");
    assert_ne!(before.digest, after.digest);
    // The control: the same two trees, digested at the macro alone, are the same. Without the walk
    // the change would pass unseen.
    let alone = |root: &Path| {
        Tree::at(root)
            .expect("a tree")
            .follow_with("kr_protocol", &["macro:opaque_id"], Depth::Alone)
            .expect("digested")
            .digest
    };
    let untouched = tempfile::tempdir().expect("a temporary directory");
    copy_crates(
        &repository(),
        untouched.path(),
        &["kr-protocol", "kr-cbor", "kr-worker"],
    );
    assert_eq!(
        alone(untouched.path()),
        alone(copy.path()),
        "the macro alone does not show the change"
    );

    // A comment and the layout around it move nothing.
    let text = std::fs::read_to_string(&ids).expect("ids.rs");
    std::fs::write(
        &ids,
        format!(
            "// a note\n{}\n\n",
            text.replace("fn validate_opaque_id", "fn   validate_opaque_id")
        ),
    )
    .expect("write");
    let reworded = Tree::at(copy.path())
        .expect("the reworded copy")
        .follow("kr_protocol", &["opaque_id"])
        .expect("followed");
    assert_eq!(after.digest, reworded.digest);
}

/// A path through another crate of the workspace that cannot be followed is an error, never
/// skipped.
#[test]
fn a_name_behind_another_crate_that_cannot_be_followed_is_an_error() {
    let copy = tempfile::tempdir().expect("a temporary directory");
    copy_crates(
        &repository(),
        copy.path(),
        &["kr-protocol", "kr-cbor", "kr-worker"],
    );
    let ids = copy.path().join("crates/kr-protocol/src/ids.rs");
    let text = std::fs::read_to_string(&ids).expect("ids.rs");
    std::fs::write(
        &ids,
        text.replace(
            "fn validate_opaque_id(value: &str, limit: usize) -> Result<(), OpaqueIdError> {",
            "fn validate_opaque_id(value: &str, limit: usize) -> Result<(), OpaqueIdError> {\n    let _ = kr_cbor::nothing_of_this_name();",
        ),
    )
    .expect("write");
    let error = Tree::at(copy.path())
        .expect("the copy")
        .follow("kr_protocol", &["opaque_id"])
        .err()
        .expect("an error");
    assert!(error.contains("kr_cbor::nothing_of_this_name"), "{error}");
}

/// The same holds for a path written inside a serde attribute: it names another crate of the
/// workspace, and is followed there or is an error.
#[test]
fn a_serde_path_behind_another_crate_that_cannot_be_followed_is_an_error() {
    let copy = tempfile::tempdir().expect("a temporary directory");
    copy_crates(
        &repository(),
        copy.path(),
        &["kr-protocol", "kr-cbor", "kr-worker"],
    );
    let local = copy.path().join("crates/kr-protocol/src/local.rs");
    let text = std::fs::read_to_string(&local).expect("local.rs");
    let changed = text.replacen(
        "#[serde(with = \"worker_rights\")]",
        "#[serde(with = \"kr_cbor::nothing_of_this_name\")]",
        1,
    );
    assert_ne!(text, changed, "the attribute is where this test expects it");
    std::fs::write(&local, changed).expect("write");
    let error = Tree::at(copy.path())
        .expect("the copy")
        .follow("kr_protocol", &["ForwardedMutation"])
        .err()
        .expect("an error");
    assert!(error.contains("kr_cbor::nothing_of_this_name"), "{error}");
}

fn copy_crates(from: &Path, to: &Path, crates: &[&str]) {
    for name in crates {
        let source = from.join("crates").join(name);
        let target = to.join("crates").join(name);
        std::fs::create_dir_all(&target).expect("a directory");
        std::fs::copy(source.join("Cargo.toml"), target.join("Cargo.toml")).expect("the manifest");
        copy_directory(&source.join("src"), &target.join("src"));
    }
}

fn copy_directory(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("a directory") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_directory(&entry.path(), &target);
        } else if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "rs")
        {
            std::fs::copy(entry.path(), &target).expect("a file");
        }
    }
}
