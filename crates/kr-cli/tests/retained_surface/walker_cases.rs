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
