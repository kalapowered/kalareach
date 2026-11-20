//! The cases of the walker's lookups and of the scan for senders, on small trees a temporary
//! folder holds.

use std::collections::BTreeMap;
use std::path::Path;

use super::repository;
use super::walker::{Depth, Lookup, SightKind, Tree};

fn manifest(name: &str) -> String {
    format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\n")
}

fn write(root: &Path, path: &str, text: &str) {
    let full = root.join(path);
    std::fs::create_dir_all(full.parent().expect("a parent")).expect("a directory");
    std::fs::write(full, text).expect("a file");
}

/// A tree with a `kr-worker` crate, a `kr-sender` crate whose library is `lib`, and a
/// `kr-protocol` crate.
fn small_tree(lib: &str) -> tempfile::TempDir {
    let folder = tempfile::tempdir().expect("a temporary directory");
    for (name, source) in [
        ("kr-worker", "pub fn worker() {}\n"),
        ("kr-sender", lib),
        ("kr-protocol", "pub enum Method {}\n"),
    ] {
        write(
            folder.path(),
            &format!("crates/{name}/Cargo.toml"),
            &manifest(name),
        );
        write(folder.path(), &format!("crates/{name}/src/lib.rs"), source);
    }
    folder
}

fn alone(tree: &Tree, name: &str) -> Lookup {
    tree.lookup("kr_sender", &[name], Depth::Alone)
}

#[test]
fn a_crate_under_apps_is_read_by_its_package_name() {
    let with = small_tree("");
    write(
        with.path(),
        "apps/x/src-tauri/Cargo.toml",
        &manifest("companion-tauri"),
    );
    write(
        with.path(),
        "apps/x/src-tauri/src/lib.rs",
        "pub fn app() {}\n",
    );
    let tree = Tree::at(with.path()).expect("the tree");
    let present = Lookup::Found(String::new());
    assert_eq!(tree.krate("companion_tauri"), present);
    assert_eq!(tree.krate("kr_worker"), present);
    let without = small_tree("");
    let tree = Tree::at(without.path()).expect("the tree");
    assert_eq!(tree.krate("kr_worker"), present);
    assert_eq!(tree.krate("companion_tauri"), Lookup::Absent);
    // The repository's own tree has the companion's crate, and its roots are followed as before.
    let real = Tree::at(&repository()).expect("this checkout");
    assert_eq!(real.krate("companion_tauri"), present);
    assert_eq!(real.krate("kr_worker"), present);
    real.follow("kr_protocol", &["opaque_id"])
        .expect("a rule is followed");
}

#[test]
fn a_lookup_says_what_it_found_and_why_it_could_not() {
    let folder = small_tree("pub fn present() {}\n");
    let tree = Tree::at(folder.path()).expect("the tree");
    assert_eq!(tree.krate("kr_nothing"), Lookup::Absent);
    assert_eq!(tree.item("kr_nothing", "x"), Lookup::Absent);
    assert_eq!(tree.item("kr_sender", "missing"), Lookup::Absent);
    assert!(matches!(
        tree.item("kr_sender", "present"),
        Lookup::Found(_)
    ));
    assert!(matches!(alone(&tree, "present"), Lookup::Found(_)));
    assert_eq!(alone(&tree, "missing"), Lookup::Absent);
    assert!(
        matches!(
            tree.lookup("kr_sender", &["present", "missing"], Depth::Alone),
            Lookup::Failed(ref text) if text.contains("missing")
        ),
        "a list of names that is only partly defined is a failure"
    );
    // A manifest that exists and names no package makes a crate that no manifest names unknown.
    write(folder.path(), "crates/odd/Cargo.toml", "[workspace]\n");
    let tree = Tree::at(folder.path()).expect("the tree");
    assert!(matches!(tree.krate("kr_nothing"), Lookup::Failed(_)));
    assert!(matches!(tree.item("kr_nothing", "x"), Lookup::Failed(_)));
    assert!(matches!(
        tree.item("kr_sender", "present"),
        Lookup::Found(_)
    ));
    // A source that does not parse makes every lookup in its crate a failure.
    let broken = small_tree("fn (\n");
    let tree = Tree::at(broken.path()).expect("the tree");
    assert!(matches!(
        tree.item("kr_sender", "present"),
        Lookup::Failed(_)
    ));
    assert!(matches!(alone(&tree, "present"), Lookup::Failed(_)));
}

#[test]
fn a_comment_moves_no_digest_and_a_token_of_a_helper_moves_the_helper_and_not_the_root_alone() {
    let digests = |lib: &str| {
        let folder = small_tree(lib);
        let tree = Tree::at(folder.path()).expect("the tree");
        let Lookup::Found(root_alone) = alone(&tree, "root_fn") else {
            panic!("the root is found");
        };
        let Lookup::Found(helper) = alone(&tree, "helper") else {
            panic!("the helper is found");
        };
        let Lookup::Found(everything) = tree.lookup("kr_sender", &["root_fn"], Depth::Everything)
        else {
            panic!("the root is followed");
        };
        (root_alone, helper, everything)
    };
    let before = digests("pub fn root_fn() { helper(); }\nfn helper() { let _ = 1; }\n");
    let reworded = digests(
        "pub fn root_fn() {\n    // a comment\n    helper();\n}\n/// documentation\nfn helper() {\n    let _ = 1;\n}\n",
    );
    assert_eq!(reworded, before);
    let changed = digests("pub fn root_fn() { helper(); }\nfn helper() { let _ = 2; }\n");
    assert_eq!(
        changed.0, before.0,
        "the root alone does not move with a helper"
    );
    assert_ne!(changed.1, before.1, "the helper moves");
    assert_ne!(changed.2, before.2, "the root followed moves");
}

#[test]
fn the_body_of_a_macro_and_an_invocation_have_digests_that_move_on_a_token() {
    let digests = |lib: &str| {
        let folder = small_tree(lib);
        let tree = Tree::at(folder.path()).expect("the tree");
        let take = |name: &str| match tree.item("kr_sender", name) {
            Lookup::Found(digest) => digest,
            other => panic!("{name}: {other:?}"),
        };
        (take("macro:m"), take("first"), take("second"))
    };
    let before =
        digests("macro_rules! m { ($x:expr) => { $x }; }\nm!(first, 1);\nm!(second, 2);\n");
    let body =
        digests("macro_rules! m { ($x:expr) => { $x + 1 }; }\nm!(first, 1);\nm!(second, 2);\n");
    assert_ne!(body.0, before.0);
    assert_eq!((&body.1, &body.2), (&before.1, &before.2));
    let argument =
        digests("macro_rules! m { ($x:expr) => { $x }; }\nm!(first, 1);\nm!(second, 3);\n");
    assert_eq!((&argument.0, &argument.1), (&before.0, &before.1));
    assert_ne!(argument.2, before.2);
}

const SENDER_LIB: &str = r#"
use kr_protocol::Method::AgentTurnCancel;
#[cfg(test)]
mod hidden;
#[cfg(test)]
#[path = "x.rs"]
mod moved;
#[path = "y.rs"]
mod through_path;
mod sub;
fn names_a_method() { let _ = Method::AgentPromptSubmit; }
fn names_by_wire() -> &'static str { "agent.turn.steer" }
fn names_a_right() { let _ = ActionRight::AgentApprovalRespond; }
/// Sends `Method::AgentTurnCancel` and says "agent.turn.cancel".
fn documented() {}
#[cfg(test)]
fn under_test() { let _ = Method::AgentTurnCancel; }
struct Holder;
impl Holder {
    fn in_method(&self) { let _ = Method::PluginActionInvoke; }
    #[cfg(test)]
    fn test_method(&self) { let _ = Method::AgentTurnCancel; }
}
trait Sends {
    fn default_method(&self) { let _ = Method::AgentTurnSteer; }
    #[cfg(test)]
    fn test_only(&self) { let _ = MutationRequest { x: 1 }; }
}
mod inline {
    fn in_inline() { let _ = MutationRequest { x: 1 }; }
    #[cfg(test)]
    mod tests { fn deep() { let _ = Method::AgentTurnCancel; } }
}
fn builds_request() { let _ = MutationRequest { a: 1 }; }
fn target() -> ActionTarget { ActionTarget { x: 1 } }
#[cfg(any(test, feature = "testing"))]
fn kept_by_feature() { let _ = Method::AgentPromptQueue; }
macro_rules! sends { ($name:ident, $method:expr) => { fn $name() { let _ = $method; } }; }
sends!(first, Method::AgentTurnCancel);
sends!(second, Method::AgentTurnSteer);
macro_rules! own { () => { Method::AgentTurnCancel }; }
macro_rules! idle { () => {}; }
macro_rules! unnamed { ($($t:tt)*) => {}; }
unnamed!("agent.turn.cancel");
unnamed!("agent.turn.steer");
"#;

fn names(sightings: &[super::walker::Sighting], krate: &str) -> BTreeMap<String, Vec<SightKind>> {
    sightings
        .iter()
        .filter(|sighting| sighting.krate == krate)
        .map(|sighting| {
            (
                sighting.name.clone(),
                sighting.kinds.iter().copied().collect(),
            )
        })
        .collect()
}

#[test]
fn the_scan_finds_each_way_a_sender_is_written_and_none_that_is_not() {
    let folder = small_tree(SENDER_LIB);
    let src = "crates/kr-sender/src";
    write(
        folder.path(),
        &format!("{src}/hidden.rs"),
        "fn from_hidden() { let _ = Method::AgentTurnCancel; }\n",
    );
    write(
        folder.path(),
        &format!("{src}/x.rs"),
        "fn from_x() { let _ = Method::AgentTurnCancel; }\n",
    );
    write(
        folder.path(),
        &format!("{src}/y.rs"),
        "fn from_y() { let _ = Method::AgentTurnSteer; }\n",
    );
    write(
        folder.path(),
        &format!("{src}/sub.rs"),
        "unnamed!(\"agent.prompt.queue\");\n",
    );
    let tree = Tree::at(folder.path()).expect("the tree");
    let root_before = tree
        .follow("kr_sender", &["names_a_method"])
        .expect("followed")
        .digest;
    let sightings = tree.sightings(&|_| true).expect("the scan");
    let found = names(&sightings, "kr_sender");
    use SightKind::{Expands, Names, Request, Target};
    let expected: BTreeMap<String, Vec<SightKind>> = [
        ("use:lib.rs", vec![Names]),
        ("names_a_method", vec![Names]),
        ("names_by_wire", vec![Names]),
        ("Holder::in_method", vec![Names]),
        ("Sends", vec![Names]),
        ("in_inline", vec![Request]),
        ("builds_request", vec![Request]),
        ("target", vec![Target]),
        ("kept_by_feature", vec![Names]),
        ("from_y", vec![Names]),
        ("first", vec![Names]),
        ("second", vec![Names]),
        ("macro:sends", vec![Expands]),
        ("macro:own", vec![Names]),
        ("macro:unnamed", vec![Expands]),
        ("unnamed! invocation @lib.rs", vec![Names]),
        ("unnamed! invocation @sub.rs", vec![Names]),
    ]
    .into_iter()
    .map(|(name, kinds)| (name.to_owned(), kinds))
    .collect();
    assert_eq!(found, expected);
    // Every name resolves through the walker or the scan, and a root's digest is the one it had.
    for name in found.keys() {
        assert!(
            matches!(tree.item("kr_sender", name), Lookup::Found(_)),
            "{name}"
        );
    }
    assert_eq!(
        tree.follow("kr_sender", &["names_a_method"])
            .expect("followed")
            .digest,
        root_before
    );
    // The two unnamed invocations of one file are one sighting whose text is both.
    let shown = tree
        .source("kr_sender", "unnamed! invocation @lib.rs")
        .expect("a lookup")
        .expect("a source");
    assert!(shown.text.contains("agent.turn.cancel") && shown.text.contains("agent.turn.steer"));
    assert_eq!(shown.files, vec!["crates/kr-sender/src/lib.rs".to_owned()]);
}

#[test]
fn a_scan_reads_only_what_it_may_hold_a_sighting_in() {
    // A file with none of the words is not parsed, so what does not parse there raises nothing.
    let quiet = small_tree("pub fn quiet() {}\n");
    write(quiet.path(), "crates/kr-sender/src/other.rs", "fn (\n");
    let tree = Tree::at(quiet.path()).expect("the tree");
    assert_eq!(
        tree.sightings(&|krate| krate == "kr_sender"),
        Ok(Vec::new())
    );
    // A file with a word that does not parse is an error.
    let loud = small_tree("pub fn quiet() {}\n");
    write(
        loud.path(),
        "crates/kr-sender/src/other.rs",
        "fn ( Method\n",
    );
    let tree = Tree::at(loud.path()).expect("the tree");
    assert!(tree.sightings(&|krate| krate == "kr_sender").is_err());
    // A manifest that cannot be read leaves the scan incomplete.
    let odd = small_tree("pub fn quiet() {}\n");
    write(odd.path(), "crates/odd/Cargo.toml", "[workspace]\n");
    let tree = Tree::at(odd.path()).expect("the tree");
    assert!(tree.sightings(&|_| true).is_err());
}

#[test]
fn a_sighting_in_the_companions_crate_under_apps_is_found() {
    let folder = small_tree("pub fn quiet() {}\n");
    write(
        folder.path(),
        "apps/x/src-tauri/Cargo.toml",
        &manifest("companion-tauri"),
    );
    write(
        folder.path(),
        "apps/x/src-tauri/src/lib.rs",
        "fn send() { let _ = Method::AgentTurnSteer; }\n",
    );
    let tree = Tree::at(folder.path()).expect("the tree");
    let sightings = tree.sightings(&|_| true).expect("the scan");
    assert_eq!(
        names(&sightings, "companion_tauri"),
        BTreeMap::from([("send".to_owned(), vec![SightKind::Names])])
    );
    assert!(matches!(
        tree.item("companion_tauri", "send"),
        Lookup::Found(_)
    ));
}
