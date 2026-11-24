//! The cases of the walker's lookups and of the digests' file list, on small trees a temporary
//! folder holds.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use super::repository;
use super::walker::{Depth, Lookup, Tree, normalised};

fn manifest(name: &str) -> String {
    format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\n")
}

/// The first line of a root manifest this file writes, so that a fixture that changed since gets a new
/// one.
const PLANTED: &str = "# a fixture's workspace\n";

/// Reads the tree at `root`; a fixture that has no root manifest gets one first, with the crates and
/// the applications' crates it holds as its members.
pub(super) fn tree_at(root: &Path) -> Result<Tree, String> {
    let planted = std::fs::read_to_string(root.join("Cargo.toml"))
        .map_or(true, |text| text.starts_with(PLANTED));
    if root.is_dir() && planted {
        let mut members = Vec::new();
        for entry in std::fs::read_dir(root.join("crates")).into_iter().flatten() {
            let name = entry.expect("an entry").file_name();
            if root.join("crates").join(&name).join("Cargo.toml").exists() {
                members.push(format!("crates/{}", name.to_string_lossy()));
            }
        }
        for entry in std::fs::read_dir(root.join("apps")).into_iter().flatten() {
            let name = entry.expect("an entry").file_name();
            let member = format!("apps/{}/src-tauri", name.to_string_lossy());
            if root.join(&member).join("Cargo.toml").exists() {
                members.push(member);
            }
        }
        members.sort();
        let listed: Vec<String> = members.iter().map(|member| format!("{member:?}")).collect();
        write(
            root,
            "Cargo.toml",
            &format!(
                "{PLANTED}[workspace]\nmembers = [{}]\nresolver = \"2\"\n",
                listed.join(", ")
            ),
        );
    }
    Tree::at(root)
}

pub(super) fn write(root: &Path, path: &str, text: &str) {
    let full = root.join(path);
    std::fs::create_dir_all(full.parent().expect("a parent")).expect("a directory");
    std::fs::write(full, text).expect("a file");
}

/// A tree with a `kr-worker` crate, a `kr-sender` crate whose library is `lib`, and a
/// `kr-protocol` crate.
pub(super) fn small_tree(lib: &str) -> tempfile::TempDir {
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

/// The tree is not read: Cargo cannot read its workspace, and the text says so with the folder.
fn cannot_read(folder: &tempfile::TempDir) {
    let error = tree_at(folder.path())
        .err()
        .expect("a workspace Cargo cannot read");
    let root = std::fs::canonicalize(folder.path()).expect("a folder");
    let start = format!(
        "{}: cargo cannot read the workspace (error: ",
        root.display()
    );
    assert!(error.starts_with(&start) && error.ends_with(')'), "{error}");
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
    let tree = tree_at(with.path()).expect("the tree");
    let present = Lookup::Found(String::new());
    assert_eq!(tree.krate("companion_tauri"), present);
    assert_eq!(tree.krate("kr_worker"), present);
    let without = small_tree("");
    let tree = tree_at(without.path()).expect("the tree");
    assert_eq!(tree.krate("kr_worker"), present);
    assert_eq!(tree.krate("companion_tauri"), Lookup::Absent);
    // The repository's own tree has the companion's crate, and its roots are followed as before.
    let real = tree_at(&repository()).expect("this checkout");
    assert_eq!(real.krate("companion_tauri"), present);
    assert_eq!(real.krate("kr_worker"), present);
    real.follow("kr_protocol", &["opaque_id"])
        .expect("a rule is followed");
}

#[test]
fn a_lookup_says_what_it_found_and_why_it_could_not() {
    let folder = small_tree("pub fn present() {}\n");
    let tree = tree_at(folder.path()).expect("the tree");
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
    // A manifest that names no package is a workspace Cargo cannot read: the tree is not read, and
    // no crate is called absent for it.
    write(folder.path(), "crates/odd/Cargo.toml", "[workspace]\n");
    cannot_read(&folder);
    // A source that does not parse makes every lookup in its crate a failure.
    let broken = small_tree("fn (\n");
    let tree = tree_at(broken.path()).expect("the tree");
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
        let tree = tree_at(folder.path()).expect("the tree");
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
        let tree = tree_at(folder.path()).expect("the tree");
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

const MODULE_LIB: &str = r##"
#[cfg(test)]
#[path = "wide/send.rs"]
mod test_support;
#[path = "wide/send.rs"]
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
mod r#match;
#[cfg(all(test, unix))]
mod t_all;
#[cfg(not(not(test)))]
mod t_not;
#[cfg(not(all(test, unix)))]
mod p_not;
#[cfg(any(all(unix, not(target_os = "macos")), test))]
mod p_any;
"##;

#[test]
fn a_module_file_is_product_where_a_product_declaration_reaches_it_however_the_path_is_written() {
    let folder = small_tree(MODULE_LIB);
    let sends = |name: &str, method: &str| format!("fn {name}() {{ let _ = Method::{method}; }}\n");
    for (path, text) in [
        // Reached by a test declaration and by a product one.
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
        // A module with a raw name is the file of the name without `r#`, for a test module (left
        // out) and for a product one.
        ("loop.rs", sends("from_loop", "AgentTurnCancel")),
        ("match.rs", sends("from_match", "AgentTurnSteer")),
        // Conditions no configuration without `test` enables, and ones some configuration does.
        ("t_all.rs", sends("from_t_all", "AgentTurnCancel")),
        ("t_not.rs", sends("from_t_not", "AgentTurnCancel")),
        ("p_not.rs", sends("from_p_not", "AgentTurnSteer")),
        ("p_any.rs", sends("from_p_any", "AgentTurnSteer")),
    ] {
        write(
            folder.path(),
            &format!("crates/kr-sender/src/{path}"),
            &text,
        );
    }
    // The files that product code reaches, by their place under the crate's `src`.
    let expected: BTreeSet<String> = [
        "a.rs",
        "child.rs",
        "d/inner.rs",
        "lib.rs",
        "match.rs",
        "p_any.rs",
        "p_not.rs",
        "plain.rs",
        "product_commented.rs",
        "product_raw.rs",
        "shared.rs",
        "shared2.rs",
        "wide/send.rs",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let base = std::fs::canonicalize(folder.path())
        .expect("the folder")
        .join("crates/kr-sender/src");
    let scan = |root: &Path| -> Result<BTreeSet<String>, String> {
        let tree = tree_at(root)?;
        Ok(tree
            .product_files("kr_sender")?
            .iter()
            .map(|file| {
                file.strip_prefix(&base)
                    .expect("a file under the crate's src")
                    .display()
                    .to_string()
            })
            .collect())
    };
    assert_eq!(scan(folder.path()), Ok(expected.clone()));
    // The same tree through a root with `..` in it, as the repository's own root is.
    assert_eq!(
        scan(&folder.path().join("crates/kr-sender/../..")),
        Ok(expected.clone())
    );
    // And through a relative root that steps up past every folder of the working directory, as a
    // release tree named by a relative path is.
    let here = std::env::current_dir().expect("a working directory");
    let up: PathBuf = here
        .components()
        .filter(|part| matches!(part, Component::Normal(_)))
        .map(|_| "..")
        .collect();
    let absolute = folder.path().to_owned();
    let relative = up.join(absolute.strip_prefix("/").expect("an absolute path"));
    assert!(
        relative.starts_with("../.."),
        "{} does not step up twice",
        relative.display()
    );
    assert_eq!(scan(&relative), Ok(expected));
}

#[test]
fn a_path_keeps_every_step_up_that_nothing_before_it_can_take() {
    let table = [
        ("", ""),
        ("../..", "../.."),
        ("../../release-tree", "../../release-tree"),
        ("a/../../x", "../x"),
        ("./a/./b/..", "a"),
        ("/a/b/../c", "/a/c"),
        ("/a/../..", "/"),
        ("/../x", "/x"),
    ];
    for (given, expected) in table {
        assert_eq!(normalised(Path::new(given)), Path::new(expected), "{given}");
    }
    let missing = Path::new("/this/folder/does/not/exist-r5");
    let error = tree_at(missing).err().expect("a root that is not there");
    assert!(error.contains("exist-r5"), "{error}");
}

#[test]
fn a_root_lookup_in_a_crate_that_is_absent_or_unreadable_says_so_and_a_failed_follow_says_why() {
    let folder = small_tree("pub fn present() { kr_worker::nothing_of_this_name(); }\n");
    let tree = tree_at(folder.path()).expect("the tree");
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
    cannot_read(&folder);
    // The applications are the workspace's members, so a file called `apps` names none.
    let file_for_apps = small_tree("");
    write(file_for_apps.path(), "apps", "not a folder\n");
    let tree = tree_at(file_for_apps.path()).expect("the tree");
    assert_eq!(tree.krate("companion_tauri"), Lookup::Absent);
}

/// The readings that keep Cargo's lines as text hold where the environment asks Cargo for colour, as
/// the hosted runners' workflows do with `CARGO_TERM_COLOR=always`: the test program is started again
/// with that variable set and runs the three cases that read a workspace's refusal, and the case of
/// the failed fetch, which keeps its text in the same way.
#[test]
fn a_workspace_is_read_and_refused_in_words_whatever_colour_the_environment_asks_for() {
    let output = std::process::Command::new(std::env::current_exe().expect("this test program"))
        .args([
            "--test-threads",
            "1",
            "--exact",
            "walker_cases::a_lookup_says_what_it_found_and_why_it_could_not",
            "walker_cases::a_root_lookup_in_a_crate_that_is_absent_or_unreadable_says_so_and_a_failed_follow_says_why",
            "history_cases::a_text_the_entry_does_not_list_or_a_reading_that_is_missing_or_failed_names_the_tag",
            "compiler_cases::a_fetch_of_a_tree_with_no_lock_file_fails_with_its_exit_and_one_with_a_lock_file_passes",
        ])
        .env("CARGO_TERM_COLOR", "always")
        .output()
        .expect("this test program starts");
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && said.contains("4 passed"),
        "{said}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

const SCANNED: &str = "use std::fmt;\n\
macro_rules! make {\n    ($name:ident) => {\n        pub fn $name() {}\n    };\n}\n\
gen!(a, b);\n\
gen!(c);\n\
pub struct Holder;\n\
impl Holder {\n    pub fn held(&self) {}\n}\n\
#[cfg(test)]\nmod tests {\n    #[test]\n    fn only_a_test_reads_this() {}\n}\n";

fn digest_of(tree: &Tree, name: &str) -> String {
    match tree.item("kr_sender", name) {
        Lookup::Found(digest) => digest,
        other => panic!("{name}: {other:?}"),
    }
}

/// W5: each kind of name the compiler's reading gives a sighting resolves through `Tree::item`, with
/// a digest that holds its file's path and the tokens of its items.
#[test]
fn a_name_the_compiler_gives_a_sighting_resolves_with_a_digest_that_holds_its_file_and_its_tokens()
{
    let folder = small_tree(SCANNED);
    write(
        folder.path(),
        "crates/kr-sender/data/fixture.json",
        "{\"a\": 1}\n",
    );
    write(
        folder.path(),
        "crates/kr-sender/src/unreached.rs",
        "fn only_here() {}\n",
    );
    let tree = tree_at(folder.path()).expect("the tree");
    let lib = "crates/kr-sender/src/lib.rs";
    let names = [
        format!("use:{lib}"),
        format!("gen! invocation @{lib}"),
        "macro:make".to_owned(),
        "Holder::held".to_owned(),
        "only_a_test_reads_this".to_owned(),
        "only_here".to_owned(),
        "file:crates/kr-sender/data/fixture.json".to_owned(),
    ];
    let digests: BTreeSet<String> = names.iter().map(|name| digest_of(&tree, name)).collect();
    assert_eq!(
        digests.len(),
        names.len(),
        "each name has a digest of its own"
    );
    // A name that nothing defines is absent, and a file that is not there is absent.
    for name in [
        "defined_nowhere",
        "gen! invocation @crates/kr-sender/src/other.rs",
        "use:crates/kr-sender/src/other.rs",
        "file:crates/kr-sender/data/other.json",
    ] {
        assert_eq!(tree.item("kr_sender", name), Lookup::Absent, "{name}");
    }
    // The two invocations of one macro in one file are one name, and its text holds both.
    let invocations = tree
        .source("kr_sender", &format!("gen! invocation @{lib}"))
        .expect("read")
        .expect("found");
    assert!(
        invocations.text.contains("a , b") && invocations.text.contains("gen ! (c)"),
        "{}",
        invocations.text
    );
    assert_eq!(invocations.files, vec![lib.to_owned()]);
    // A comment moves no digest, a token of one invocation moves that name's digest and no other,
    // and the same text in another file is another digest.
    let invocation = format!("gen! invocation @{lib}");
    let before = digest_of(&tree, &invocation);
    let used = digest_of(&tree, &format!("use:{lib}"));
    let commented = small_tree(&format!("// a comment\n{SCANNED}"));
    let tree_commented = tree_at(commented.path()).expect("the tree");
    assert_eq!(digest_of(&tree_commented, &invocation), before);
    let changed = small_tree(&SCANNED.replace("gen!(c);", "gen!(d);"));
    let tree_changed = tree_at(changed.path()).expect("the tree");
    assert_ne!(digest_of(&tree_changed, &invocation), before);
    assert_eq!(digest_of(&tree_changed, &format!("use:{lib}")), used);
    let moved = small_tree("");
    write(moved.path(), "crates/kr-sender/src/lib.rs", "mod inner;\n");
    write(moved.path(), "crates/kr-sender/src/inner.rs", SCANNED);
    let tree_moved = tree_at(moved.path()).expect("the tree");
    assert_ne!(
        digest_of(
            &tree_moved,
            "gen! invocation @crates/kr-sender/src/inner.rs"
        ),
        before
    );
    // A file that does not parse is a failure with its text, never an absence.
    let broken = small_tree("pub fn plain() {}\n");
    write(
        broken.path(),
        "crates/kr-sender/src/lib.rs",
        "pub fn plain() {}\nfn (\n",
    );
    let tree_broken = tree_at(broken.path()).expect("the tree");
    let Lookup::Failed(error) = tree_broken.item("kr_sender", "only_here") else {
        panic!("a file that does not parse");
    };
    assert!(error.contains("lib.rs"), "{error}");
}

/// W5: the identity of a name is every item of that name in its crate. A product item and an item
/// in a file no build reads share the name `send`; a change to either moves the one digest, so the
/// sighted item cannot hide behind its namesake. A namesake beside the product item in its own file
/// (a test item) counts too, and a name that only the walker's item has keeps the walker's digest.
#[test]
fn the_identity_of_a_name_is_every_item_of_that_name_in_its_crate() {
    let lib = "crates/kr-sender/src/lib.rs";
    let unreached = "crates/kr-sender/src/unreached.rs";
    let product = "pub fn send() {}\npub fn only_here() {}\n";
    let sender = |unreached_body: &str, test_body: &str| {
        let folder = small_tree(&format!(
            "{product}#[cfg(test)]\nmod tests {{\n    fn twice() {{ {test_body} }}\n}}\npub fn twice() {{}}\n"
        ));
        write(
            folder.path(),
            unreached,
            &format!("fn send() {{ {unreached_body} }}\n"),
        );
        folder
    };
    let base = sender("first();", "one();");
    let tree = tree_at(base.path()).expect("the tree");
    let source = tree
        .source("kr_sender", "send")
        .expect("read")
        .expect("found");
    assert_eq!(
        source.files,
        vec![lib.to_owned(), unreached.to_owned()],
        "the product item's file and the namesake's file"
    );
    let before = digest_of(&tree, "send");
    // A change to the unreached item moves the name's digest; it moves no other name's.
    let moved = sender("second();", "one();");
    let tree_moved = tree_at(moved.path()).expect("the tree");
    assert_ne!(digest_of(&tree_moved, "send"), before);
    assert_eq!(
        digest_of(&tree_moved, "only_here"),
        digest_of(&tree, "only_here")
    );
    assert_eq!(
        tree.source("kr_sender", "only_here")
            .expect("read")
            .expect("found")
            .files,
        vec![lib.to_owned()],
        "a name the walker's file alone holds is the walker's"
    );
    // A test item beside the product item of one name, in the same file, moves the digest too.
    let before_twice = digest_of(&tree, "twice");
    let test_moved = sender("first();", "two();");
    let tree_test_moved = tree_at(test_moved.path()).expect("the tree");
    assert_ne!(digest_of(&tree_test_moved, "twice"), before_twice);
}

/// W5: a method and a test function of one bare name in one file are two items. The walker's item
/// of `send` is the method (`Link::send`); the scan finds the test function alone, so the file's
/// one scanned item is not the walker's own and the test function is in the name's identity.
#[test]
fn a_test_function_beside_a_method_of_its_bare_name_is_in_the_identity_of_the_name() {
    let lib = "crates/kr-sender/src/lib.rs";
    let sender = |method_body: &str, test_body: &str| {
        small_tree(&format!(
            "pub struct Link;\nimpl Link {{\n    pub fn send(&self) {{ {method_body} }}\n}}\n\
             #[cfg(test)]\nmod tests {{\n    fn send() {{ {test_body} }}\n}}\n"
        ))
    };
    let base = sender("first();", "one();");
    let tree = tree_at(base.path()).expect("the tree");
    let source = tree
        .source("kr_sender", "send")
        .expect("read")
        .expect("found");
    assert!(
        source.text.contains("first ()") && source.text.contains("one ()"),
        "the method and the test function are both in the identity: {}",
        source.text
    );
    assert_eq!(source.files, vec![lib.to_owned()]);
    let before = digest_of(&tree, "send");
    // A change to the test function moves the digest, and so does a change to the method.
    let test_moved = sender("first();", "two();");
    let tree_test_moved = tree_at(test_moved.path()).expect("the tree");
    assert_ne!(
        digest_of(&tree_test_moved, "send"),
        before,
        "a change to the test function"
    );
    let method_moved = sender("second();", "one();");
    let tree_method_moved = tree_at(method_moved.path()).expect("the tree");
    assert_ne!(
        digest_of(&tree_method_moved, "send"),
        before,
        "a change to the method"
    );
    // The method named as a method has no namesake: the test function is not its item.
    let method = digest_of(&tree, "Link::send");
    assert_eq!(digest_of(&tree_test_moved, "Link::send"), method);
}

/// W5: an item the walker indexes is in the identity of its name once. A file whose scanned items of
/// a name are all the walker's own adds nothing to the digest: a `macro_rules!` item (named
/// `macro:name`, where the walker's label is the bare name), a method (`Type::name`), and two
/// functions of one bare name in one file, which the walker indexes both.
#[test]
fn an_item_the_walker_indexes_is_in_the_identity_of_its_name_once() {
    let lib = "crates/kr-sender/src/lib.rs";
    let folder = small_tree(
        "macro_rules! make {\n    () => {};\n}\n\
         pub struct Link;\nimpl Link {\n    pub fn send(&self) {}\n}\n\
         mod one {\n    pub fn helper() { a(); }\n}\n\
         mod two {\n    pub fn helper() { b(); }\n}\n",
    );
    let tree = tree_at(folder.path()).expect("the tree");
    for (name, needle, times) in [
        ("macro:make", "macro_rules ! make", 1),
        ("Link::send", "fn send", 1),
        ("helper", "fn helper", 2),
    ] {
        let source = tree
            .source("kr_sender", name)
            .expect("read")
            .expect("found");
        assert_eq!(
            source.text.matches(needle).count(),
            times,
            "{name}: {}",
            source.text
        );
        assert_eq!(source.files, vec![lib.to_owned()], "{name}");
    }
}

/// W5: a plain name that only files no build reads hold, in two files, is one identity of both: a
/// change to either file moves it, and each file's path is in it.
#[test]
fn a_name_in_two_files_is_one_identity_that_holds_both_files() {
    let two_files = |first: &str, second: &str| {
        let folder = small_tree("pub fn worker_side() {}\n");
        write(
            folder.path(),
            "crates/kr-sender/src/one.rs",
            &format!("fn helper() {{ {first} }}\n"),
        );
        write(
            folder.path(),
            "crates/kr-sender/src/two.rs",
            &format!("fn helper() {{ {second} }}\n"),
        );
        folder
    };
    let base = two_files("a();", "b();");
    let tree = tree_at(base.path()).expect("the tree");
    let source = tree
        .source("kr_sender", "helper")
        .expect("read")
        .expect("found");
    assert_eq!(
        source.files,
        vec![
            "crates/kr-sender/src/one.rs".to_owned(),
            "crates/kr-sender/src/two.rs".to_owned()
        ]
    );
    assert!(source.text.contains("a ()") && source.text.contains("b ()"));
    let before = digest_of(&tree, "helper");
    for (first, second) in [("c();", "b();"), ("a();", "c();")] {
        let changed = two_files(first, second);
        let tree_changed = tree_at(changed.path()).expect("the tree");
        assert_ne!(
            digest_of(&tree_changed, "helper"),
            before,
            "{first} {second}"
        );
    }
}

/// W5: a `file:`, `use:` or invocation name reads a file under the tree's root and no other: an
/// absolute path, a path with `..` and a link that leads out of the tree are refused in words.
#[test]
fn a_name_that_names_a_file_outside_the_tree_is_refused() {
    let folder = small_tree(SCANNED);
    let outside = tempfile::tempdir().expect("a folder outside the tree");
    write(outside.path(), "secret.rs", "pub fn leaked() {}\n");
    write(outside.path(), "secret.json", "{\"a\": 1}\n");
    write(
        folder.path(),
        "crates/kr-sender/data/inside.json",
        "{\"b\": 2}\n",
    );
    std::os::unix::fs::symlink(
        outside.path().join("secret.json"),
        folder.path().join("crates/kr-sender/data/link.json"),
    )
    .expect("a link");
    let tree = tree_at(folder.path()).expect("the tree");
    let absolute_rust = outside.path().join("secret.rs").display().to_string();
    let absolute_json = outside.path().join("secret.json").display().to_string();
    let names = [
        format!("file:{absolute_json}"),
        "file:../../secret.json".to_owned(),
        "file:crates/kr-sender/../kr-sender/data/inside.json".to_owned(),
        format!("use:{absolute_rust}"),
        "use:../outside/secret.rs".to_owned(),
        format!("gen! invocation @{absolute_rust}"),
        "gen! invocation @../outside/secret.rs".to_owned(),
        "file:crates/kr-sender/data/link.json".to_owned(),
    ];
    for name in names {
        match tree.item("kr_sender", &name) {
            Lookup::Failed(error) => assert!(
                error.contains("under the tree's root") || error.contains("leads out"),
                "{name}: {error}"
            ),
            other => panic!("{name} is refused: {other:?}"),
        }
    }
    // The same name by a path under the root is read.
    assert!(matches!(
        tree.item("kr_sender", "file:crates/kr-sender/data/inside.json"),
        Lookup::Found(_)
    ));
}
