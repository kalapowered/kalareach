//! The cases of the walker's lookups and of the scan for senders, on small trees a temporary
//! folder holds.

use std::collections::BTreeMap;
use std::path::Path;

use quote::ToTokens as _;

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
    assert_eq!(
        tree.lookup("kr_sender", &["present", "missing"], Depth::Alone),
        Lookup::Failed("kr_sender defines only some of present, missing; not missing".to_owned()),
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

const SENDER_LIB: &str = r##"
use kr_protocol::Method::AgentTurnCancel;
#[cfg(test)]
mod hidden;
#[cfg(test)]
#[path = "x.rs"]
mod moved;
#[cfg(test)]
#[path = "shared/mod.rs"]
mod test_support;
#[cfg(test)]
mod tests_outer;
#[path = "shared/send.rs"]
mod sender;
#[path = "y.rs"]
mod through_path;
mod sub;
mod grouped;
mod wire;
mod req;
mod tgt;
mod mac;
fn names_a_method() { let _ = Method::AgentPromptSubmit; }
fn raw() -> &'static str { r#"agent.turn.cancel"# }
fn names_a_right() { let _ = ActionRight::AgentApprovalRespond; }
/// Sends `Method::AgentTurnCancel` and says "agent.turn.cancel".
#[doc = "agent.turn.cancel"]
fn documented() {}
fn takes_two() { idle!(Method => AgentTurnSteer); }
fn other_method() { let _ = Method::SessionOpen; }
#[cfg(test)]
mod wrapper { mod nested; }
#[cfg(test)]
fn under_test() { let _ = Method::AgentTurnCancel; }
fn takes(_r: MutationRequest, _t: &ActionTarget) { let _ = Method; }
struct Holder;
impl Holder {
    const STEER: Method = Method::AgentTurnSteer;
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
#[cfg(any(test, feature = "testing"))]
fn kept_by_feature() { let _ = Method::AgentPromptQueue; }
const SUBMIT: Method = Method::AgentPromptSubmit;
static QUEUE: &str = "agent.prompt.queue";
#[serde(rename = "agent.turn.cancel")]
struct Renamed;
enum Tag { #[serde(rename = "agent.turn.steer")] Steer }
#[serde(rename = "agent.prompt.submit")]
union U { a: u8 }
type Alias = [u8; Method::AgentTurnCancel as usize];
sends!(first, Method::AgentTurnCancel);
sends!(second, Method::AgentTurnSteer);
fn caller() { via_fn!(Method::AgentTurnCancel); }
struct Maker;
impl Maker { via_impl!(Method::AgentPromptQueue); }
macro_rules! own { () => { Method::AgentTurnCancel }; }
macro_rules! forwards { () => { via_body!(Method::AgentTurnSteer) }; }
macro_rules! check { (idle!(Method::AgentTurnCancel)) => {}; }
wrapper!(outer_made, inner_call!(Method::AgentPromptQueue));
fn mixed() { let _ = Method::AgentTurnCancel; idle!(); }
impl Sends for [u8] {
    const X: Method = Method::AgentTurnSteer;
    fn m(&self) { let _ = Method::AgentTurnCancel; }
    via_slice!(Method::AgentPromptQueue);
}
idle!();
unnamed!("agent.turn.cancel");
unnamed!("agent.turn.steer");
"##;

/// The files of the sender tree beside its library.
fn sender_tree() -> tempfile::TempDir {
    let folder = small_tree(SENDER_LIB);
    let src = "crates/kr-sender/src";
    for (path, text) in [
        (
            "hidden.rs",
            "fn from_hidden() { let _ = Method::AgentTurnCancel; }\n",
        ),
        ("x.rs", "fn from_x() { let _ = Method::AgentTurnCancel; }\n"),
        (
            "shared/mod.rs",
            "mod child;\nfn from_shared_mod() { let _ = Method::AgentTurnCancel; }\n",
        ),
        (
            "shared/child.rs",
            "fn from_child() { let _ = Method::AgentTurnCancel; }\n",
        ),
        (
            "shared/send.rs",
            "fn from_shared_send() { let _ = Method::AgentTurnSteer; }\n",
        ),
        (
            "tests_outer.rs",
            "#[path = \"elsewhere/inner.rs\"]\nmod inner;\nfn from_outer() { let _ = Method::AgentTurnCancel; }\n",
        ),
        (
            "elsewhere/inner.rs",
            "fn from_inner() { let _ = Method::AgentTurnCancel; }\n",
        ),
        (
            "y.rs",
            "mod grand;\n#[cfg(test)]\nmod t;\nfn from_y() { let _ = Method::AgentTurnSteer; }\n",
        ),
        (
            "grand.rs",
            "fn from_grand() { let _ = Method::AgentTurnSteer; }\n",
        ),
        ("t.rs", "fn from_t() { let _ = Method::AgentTurnCancel; }\n"),
        (
            "wrapper/nested.rs",
            "fn from_wrapper() { let _ = Method::AgentTurnCancel; }\n",
        ),
        ("sub.rs", "unnamed!(\"agent.prompt.queue\");\n"),
        (
            "grouped.rs",
            "use kr_protocol::Method::{AgentTurnCancel, AgentTurnSteer};\n",
        ),
        (
            "wire.rs",
            "fn names_by_wire() -> &'static str { \"agent.turn.steer\" }\n",
        ),
        (
            "req.rs",
            "fn builds_request() { let _ = MutationRequest { a: 1 }; }\n",
        ),
        (
            "tgt.rs",
            "fn target() -> ActionTarget { ActionTarget { x: 1 } }\nfn returns_only() -> ActionTarget { build() }\n",
        ),
        (
            "mac.rs",
            "macro_rules! sends { ($name:ident, $method:expr) => { fn $name() { let _ = $method; } }; }\nmacro_rules! via_fn { ($m:expr) => { $m }; }\nmacro_rules! via_impl { ($m:expr) => { const X: u8 = 0; }; }\nmacro_rules! idle { () => {}; }\nmacro_rules! via_body { ($m:expr) => { $m }; }\nmacro_rules! wrapper { ($($t:tt)*) => {}; }\nmacro_rules! inner_call { ($m:expr) => { $m }; }\nmacro_rules! via_slice { ($m:expr) => { const Y: u8 = 0; }; }\nmacro_rules! unnamed { ($($t:tt)*) => {}; }\n",
        ),
    ] {
        write(folder.path(), &format!("{src}/{path}"), text);
    }
    folder
}

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
    let folder = sender_tree();
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
        ("use:grouped.rs", vec![Names]),
        ("names_a_method", vec![Names]),
        ("names_by_wire", vec![Names]),
        ("raw", vec![Names]),
        ("Holder::in_method", vec![Names]),
        ("Holder", vec![Names]),
        ("Sends", vec![Names]),
        ("in_inline", vec![Request]),
        ("builds_request", vec![Request]),
        ("target", vec![Target]),
        ("returns_only", vec![Target]),
        ("kept_by_feature", vec![Names]),
        ("SUBMIT", vec![Names]),
        ("QUEUE", vec![Names]),
        ("Renamed", vec![Names]),
        ("Tag", vec![Names]),
        ("U", vec![Names]),
        ("Alias", vec![Names]),
        ("from_y", vec![Names]),
        ("from_grand", vec![Names]),
        ("from_shared_send", vec![Names]),
        ("first", vec![Names]),
        ("second", vec![Names]),
        ("caller", vec![Names]),
        ("Maker", vec![Names]),
        ("macro:sends", vec![Expands]),
        ("macro:via_fn", vec![Expands]),
        ("macro:via_impl", vec![Expands]),
        ("macro:own", vec![Names]),
        ("macro:forwards", vec![Names]),
        ("macro:check", vec![Names]),
        ("macro:via_body", vec![Expands]),
        ("outer_made", vec![Names]),
        ("macro:wrapper", vec![Expands]),
        ("macro:inner_call", vec![Expands]),
        ("mixed", vec![Names]),
        ("impl:lib.rs", vec![Names]),
        ("::m", vec![Names]),
        ("macro:via_slice", vec![Expands]),
        ("macro:unnamed", vec![Expands]),
        ("unnamed! invocation @lib.rs", vec![Names]),
        ("unnamed! invocation @sub.rs", vec![Names]),
    ]
    .into_iter()
    .map(|(name, kinds)| (name.to_owned(), kinds))
    .collect();
    assert_eq!(found, expected);
    // Every name resolves through the walker or the scan; a walker name's digest is the one the
    // walker gives it alone, and a root's digest is the one it had.
    for name in found.keys() {
        let Lookup::Found(digest) = tree.item("kr_sender", name) else {
            panic!("{name} does not resolve");
        };
        if !name.starts_with("use:")
            && !name.starts_with("impl:")
            && !name.contains("! invocation @")
        {
            assert_eq!(
                tree.lookup("kr_sender", &[name.as_str()], Depth::Alone),
                Lookup::Found(digest),
                "{name}"
            );
        }
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
    // The constant and the macro call of an impl block whose type has no path are one sighting
    // named by the file, with both texts; its method keeps the walker's own label.
    let slice = tree
        .source("kr_sender", "impl:lib.rs")
        .expect("a lookup")
        .expect("a source");
    assert!(slice.text.contains("AgentTurnSteer") && slice.text.contains("via_slice"));
    assert_eq!(slice.files, vec!["crates/kr-sender/src/lib.rs".to_owned()]);
}

#[test]
fn the_digest_of_a_name_only_the_scan_gives_moves_on_a_token() {
    let digests = |import: &str, call: &str, constant: &str| {
        let lib = format!(
            "use kr_protocol::Method::{import};\nunnamed!(\"{call}\");\nimpl T for [u8] {{ const NAME: &'static str = \"{constant}\"; }}\n"
        );
        let folder = small_tree(&lib);
        let tree = Tree::at(folder.path()).expect("the tree");
        let take = |name: &str| {
            let found = tree.item("kr_sender", name);
            assert!(matches!(found, Lookup::Found(_)), "{name}: {found:?}");
            let Lookup::Found(digest) = found else {
                unreachable!("{name}");
            };
            digest
        };
        (
            take("use:lib.rs"),
            take("unnamed! invocation @lib.rs"),
            take("impl:lib.rs"),
        )
    };
    let before = digests("AgentTurnCancel", "agent.turn.cancel", "agent.turn.cancel");
    // The digest of a scan name is that of the crate, the file, the name and the text.
    let text = syn::parse_str::<syn::ItemUse>("use kr_protocol::Method::AgentTurnCancel;")
        .expect("a use")
        .to_token_stream()
        .to_string();
    let record = format!("kr_sender crates/kr-sender/src/lib.rs use:lib.rs\n{text}\n");
    let expected: String = kr_cbor::sha256(record.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(before.0, expected);
    let import = digests("AgentTurnSteer", "agent.turn.cancel", "agent.turn.cancel");
    assert_ne!(import.0, before.0);
    assert_eq!((&import.1, &import.2), (&before.1, &before.2));
    let call = digests("AgentTurnCancel", "agent.turn.steer", "agent.turn.cancel");
    assert_ne!(call.1, before.1);
    assert_eq!((&call.0, &call.2), (&before.0, &before.2));
    let constant = digests("AgentTurnCancel", "agent.turn.cancel", "agent.turn.steer");
    assert_ne!(constant.2, before.2);
    assert_eq!((&constant.0, &constant.1), (&before.0, &before.1));
}

const MODULE_LIB: &str = r##"
#[cfg(test)]
#[path = "wide/send.rs"]
mod test_support;
#[path = "wide/../wide/send.rs"]
mod sender;
#[cfg(test)]
#[path = "dots/../only_tests.rs"]
mod only_tests;
#[cfg(test)]
mod a;
#[path = "a.rs"]
mod b;
#[cfg(test)]
#[path = "folder"]
mod holder { mod nested; }
mod plain;
#[cfg(test)]
#[path = "d/inner.rs"]
mod inner_test;
mod product_raw;
#[cfg(test)]
#[path = "shared.rs"]
mod support;
mod product_commented;
#[cfg(test)]
#[path = "shared2.rs"]
mod support_two;
#[cfg(test)]
mod r#loop;
"##;

#[test]
fn a_module_file_is_product_where_a_product_declaration_reaches_it_however_the_path_is_written() {
    let folder = small_tree(MODULE_LIB);
    let sends = |name: &str, method: &str| format!("fn {name}() {{ let _ = Method::{method}; }}\n");
    for (path, text) in [
        // Reached by a test declaration with the plain path and by a product one with dots.
        ("wide/send.rs", sends("from_wide", "AgentTurnCancel")),
        // Reached by a test declaration whose path has dots: nothing else reaches it.
        ("only_tests.rs", sends("from_only_tests", "AgentTurnCancel")),
        // Declared by a test module and by a product module with a `#[path]`: its own modules are
        // beside it for the second and in a folder of its name for the first.
        (
            "a.rs",
            format!("mod child;\n{}", sends("from_a", "AgentTurnSteer")),
        ),
        ("a/child.rs", sends("from_a_child", "AgentTurnCancel")),
        ("child.rs", sends("from_beside", "AgentTurnSteer")),
        // Under an inline module whose `#[path]` is a folder, which a test attribute marks.
        ("folder/nested.rs", sends("from_nested", "AgentTurnCancel")),
        // An inline `#[path]` in a file that is no `mod.rs`: relative to the file's folder.
        (
            "plain.rs",
            "#[path = \"d\"]\nmod p { mod inner; }\n".to_owned(),
        ),
        ("d/inner.rs", sends("from_inner_d", "AgentTurnSteer")),
        // A file a test module reaches by path and a product module reaches by path from a module
        // with a raw name, and from one with a comment before its name.
        (
            "product_raw.rs",
            "#[path = \"shared.rs\"]\nmod r#type;\n".to_owned(),
        ),
        ("shared.rs", sends("from_shared", "AgentTurnSteer")),
        (
            "product_commented.rs",
            "#[path = \"shared2.rs\"]\nmod/* a note */commented;\n".to_owned(),
        ),
        ("shared2.rs", sends("from_shared_two", "AgentTurnSteer")),
        // A test module with a raw name is the file of the name without `r#`.
        ("loop.rs", sends("from_loop", "AgentTurnCancel")),
    ] {
        write(
            folder.path(),
            &format!("crates/kr-sender/src/{path}"),
            &text,
        );
    }
    let expected: BTreeMap<String, Vec<SightKind>> = [
        "from_a",
        "from_beside",
        "from_inner_d",
        "from_shared",
        "from_shared_two",
        "from_wide",
    ]
    .into_iter()
    .map(|name| (name.to_owned(), vec![SightKind::Names]))
    .collect();
    let scan = |root: &Path| {
        let tree = Tree::at(root).expect("the tree");
        let sightings = tree
            .sightings(&|krate| krate == "kr_sender")
            .expect("the scan");
        names(&sightings, "kr_sender")
    };
    assert_eq!(scan(folder.path()), expected);
    // The same tree through a root with `..` in it, as the repository's own root is.
    assert_eq!(
        scan(&folder.path().join("crates/kr-sender/../..")),
        expected
    );
}

#[test]
fn a_root_lookup_in_a_crate_that_is_absent_or_unreadable_says_so_and_a_failed_follow_says_why() {
    let folder = small_tree("pub fn present() { kr_worker::nothing_of_this_name(); }\n");
    let tree = Tree::at(folder.path()).expect("the tree");
    assert_eq!(
        tree.lookup("kr_nothing", &["x"], Depth::Alone),
        Lookup::Absent
    );
    assert!(matches!(
        tree.follow("kr_sender", &["missing"]),
        Err(super::walker::WalkError::Undefined(_))
    ));
    assert!(matches!(
        tree.follow("kr_sender", &["present"]),
        Err(super::walker::WalkError::Other(_))
    ));
    assert!(matches!(
        tree.lookup("kr_sender", &["present"], Depth::Everything),
        Lookup::Failed(_)
    ));
    write(folder.path(), "crates/odd/Cargo.toml", "[workspace]\n");
    let tree = Tree::at(folder.path()).expect("the tree");
    assert!(matches!(
        tree.lookup("kr_nothing", &["x"], Depth::Alone),
        Lookup::Failed(_)
    ));
    // Only a missing `apps` folder is an absence: one that cannot be read is an error.
    let file_for_apps = small_tree("");
    write(file_for_apps.path(), "apps", "not a folder\n");
    assert!(Tree::at(file_for_apps.path()).is_err());
}

#[test]
fn a_scan_reads_only_what_it_may_hold_a_sighting_in() {
    // A file with none of the words is not parsed, so what does not parse there raises nothing.
    let quiet = small_tree("mod other;\npub fn quiet() {}\n");
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
    // The crates the caller leaves out are not scanned.
    let two = small_tree("pub fn quiet() {}\n");
    write(
        two.path(),
        "crates/kr-worker/src/extra.rs",
        "fn x() { let _ = Method::AgentTurnSteer; }\n",
    );
    let tree = Tree::at(two.path()).expect("the tree");
    assert_eq!(
        tree.sightings(&|krate| krate == "kr_sender"),
        Ok(Vec::new())
    );
    assert_eq!(
        names(&tree.sightings(&|_| true).expect("the scan"), "kr_worker"),
        BTreeMap::from([("x".to_owned(), vec![SightKind::Names])])
    );
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

#[test]
fn the_reader_of_a_tree_does_not_scan_the_receiver_crates() {
    use super::narrower::Reader;
    let folder = small_tree("fn sends() { let _ = Method::AgentTurnSteer; }\n");
    write(
        folder.path(),
        "crates/kr-worker/src/extra.rs",
        "fn receives() { let _ = Method::AgentTurnSteer; }\n",
    );
    let tree = Tree::at(folder.path()).expect("the tree");
    let sightings = Reader::sightings(&tree).expect("the scan");
    assert_eq!(
        names(&sightings, "kr_sender"),
        BTreeMap::from([("sends".to_owned(), vec![SightKind::Names])])
    );
    assert!(
        sightings
            .iter()
            .all(|sighting| sighting.krate == "kr_sender")
    );
    assert!(Reader::sightings(&tree).expect("the scan").len() == 1);
}
