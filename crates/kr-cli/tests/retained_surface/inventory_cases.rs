//! The cases of the condition rule and of the module inventory.

use std::collections::BTreeMap;

use super::condition::Condition;
use super::walker::{Lookup, SightKind, Tree};
use super::walker_cases::{small_tree, write};

/// Whether some configuration without `test` enables a function written with `attributes`.
fn enabled(attributes: &str) -> Result<bool, String> {
    let item: syn::ItemFn = syn::parse_str(&format!("{attributes} fn f() {{}}")).expect("an item");
    Condition::default()
        .within(&item.attrs, "lib.rs")
        .map(|found| found.is_some())
}

#[test]
fn a_place_is_read_when_some_configuration_without_test_enables_every_condition_around_it() {
    for (attributes, expected) in [
        ("", true),
        ("#[cfg(test)]", false),
        ("#[cfg(all(test, unix))]", false),
        ("#[cfg(not(not(test)))]", false),
        ("#[cfg(any(all(test, unix), all(test, windows)))]", false),
        ("#[cfg(not(all(test, unix)))]", true),
        ("#[cfg(any(test, feature = \"testing\"))]", true),
        ("#[cfg(not(test))]", true),
        ("#[cfg(all(unix, windows))]", false),
        ("#[cfg(any(unix, windows))]", true),
        ("#[cfg(all(target_os = \"macos\", unix))]", true),
        ("#[cfg(all(target_os = \"macos\", windows))]", false),
        (
            "#[cfg(all(target_os = \"windows\", target_family = \"unix\"))]",
            false,
        ),
        (
            "#[cfg(all(target_vendor = \"apple\", target_os = \"linux\"))]",
            false,
        ),
        ("#[cfg(any(target_os = \"ios\", test))]", true),
        ("#[cfg(all(mobile, target_os = \"macos\"))]", false),
        ("#[cfg(all(desktop, target_os = \"android\"))]", false),
        (
            "#[cfg(any(all(unix, not(target_os = \"macos\")), test))]",
            true,
        ),
        // One atom has one value in a configuration.
        ("#[cfg(all(feature = \"a\", not(feature = \"a\")))]", false),
        ("#[cfg(all(feature = \"a\", feature = \"b\"))]", true),
        (
            "#[cfg(all(target_feature = \"sse4.2\", not(target_feature = \"sse4.2\")))]",
            false,
        ),
        ("#[cfg(target_feature = \"sse4.2\")]", true),
        // Several attributes are one conjunction.
        ("#[cfg(unix)] #[cfg(windows)]", false),
        ("#[cfg(unix)] #[cfg(not(target_os = \"linux\"))]", true),
        (
            "#[cfg_attr(not(debug_assertions), windows_subsystem = \"windows\")]",
            true,
        ),
        ("#[cfg_attr(test, derive(Debug))]", true),
        (
            "#[cfg_attr(not(debug_assertions), cfg_attr(windows, windows_subsystem = \"windows\"))]",
            true,
        ),
    ] {
        assert_eq!(enabled(attributes), Ok(expected), "{attributes}");
    }
    // A condition around a condition holds as one.
    let outer: syn::ItemFn = syn::parse_str("#[cfg(unix)] fn f() {}").expect("an item");
    let inner: syn::ItemFn = syn::parse_str("#[cfg(windows)] fn f() {}").expect("an item");
    let around = Condition::default()
        .within(&outer.attrs, "lib.rs")
        .expect("readable")
        .expect("enabled");
    assert!(
        around
            .within(&inner.attrs, "lib.rs")
            .expect("readable")
            .is_none()
    );
}

#[test]
fn a_condition_the_rule_cannot_read_is_an_error_and_never_a_skip() {
    let unreadable = |text: &str| format!("lib.rs: the scan cannot read the condition {text}");
    for (attributes, text) in [
        ("#[cfg(some_atom)]", "some_atom"),
        ("#[cfg(some_atom = \"x\")]", "some_atom = \"x\""),
        ("#[cfg(not(unix, windows))]", "not (unix , windows)"),
        ("#[cfg(target_os = 7)]", "target_os = 7"),
        ("#[cfg(a::b)]", "a :: b"),
    ] {
        assert_eq!(enabled(attributes), Err(unreadable(text)), "{attributes}");
    }
    let many = (0..13)
        .map(|at| format!("feature = \"f{at}\""))
        .collect::<Vec<_>>()
        .join(", ");
    assert_eq!(
        enabled(&format!("#[cfg(all({many}))]")),
        Err(unreadable("(more atoms than the scan tries together)"))
    );
    let sets = |text: &str| {
        format!(
            "lib.rs: the scan does not read a cfg_attr that sets a path or a condition ({text})"
        )
    };
    for (attributes, text) in [
        (
            "#[cfg_attr(unix, path = \"x.rs\")]",
            "# [cfg_attr (unix , path = \"x.rs\")]",
        ),
        (
            "#[cfg_attr(unix, cfg_attr(windows, path = \"x.rs\"))]",
            "# [cfg_attr (unix , cfg_attr (windows , path = \"x.rs\"))]",
        ),
        (
            "#[cfg_attr(unix, cfg(test))]",
            "# [cfg_attr (unix , cfg (test))]",
        ),
    ] {
        assert_eq!(enabled(attributes), Err(sets(text)), "{attributes}");
    }
}

#[test]
fn an_item_that_only_a_configuration_with_test_builds_is_not_defined() {
    let lib = "pub fn product() {}\npub fn both() { let _ = 1; }\n\
               #[cfg(all(test, unix))]\nmod t {\n    pub fn both() { let _ = 2; }\n    pub fn only_test() {}\n}\n";
    let folder = small_tree(lib);
    let tree = Tree::at(folder.path()).expect("the tree");
    let source = tree
        .source("kr_sender", "both")
        .expect("a lookup")
        .expect("a source");
    assert_eq!(source.files, vec!["crates/kr-sender/src/lib.rs".to_owned()]);
    assert!(
        source.text.contains("let _ = 1") && !source.text.contains("let _ = 2"),
        "{}",
        source.text
    );
    assert_eq!(tree.item("kr_sender", "only_test"), Lookup::Absent);
    assert!(matches!(
        tree.item("kr_sender", "product"),
        Lookup::Found(_)
    ));
}

fn sender_names(tree: &Tree) -> Result<Vec<String>, String> {
    tree.sightings(&|krate| krate == "kr_sender")
        .map(|sightings| sightings.into_iter().map(|found| found.name).collect())
}

/// The error the scan of `kr_sender` gives for a tree made of `lib` and `files`, and the error the
/// index of the same crate gives for a lookup.
fn refused(lib: &str, files: &[(&str, &str)]) -> (String, String) {
    let folder = small_tree(lib);
    for (path, text) in files {
        write(folder.path(), &format!("crates/kr-sender/{path}"), text);
    }
    let tree = Tree::at(folder.path()).expect("the tree");
    let scan = tree
        .sightings(&|krate| krate == "kr_sender")
        .expect_err("a refusal");
    let Lookup::Failed(lookup) = tree.item("kr_sender", "anything") else {
        panic!("a lookup that failed");
    };
    (scan, lookup)
}

/// The names the scan finds in a tree made of `lib` and `files`, where it has no error.
fn read_names(lib: &str, files: &[(&str, &str)]) -> Vec<String> {
    let folder = small_tree(lib);
    for (path, text) in files {
        write(folder.path(), &format!("crates/kr-sender/{path}"), text);
    }
    sender_names(&Tree::at(folder.path()).expect("the tree")).expect("a scan")
}

const SENDS: &str = "pub fn sends() { let _ = Method::AgentTurnCancel; }\n";

#[test]
fn a_file_that_no_declaration_reaches_is_not_product_code_and_is_not_read() {
    let lib = "mod used;\n#[cfg(test)]\nmod tests;\npub fn both() { let _ = 1; }\n";
    let folder = small_tree(lib);
    for (path, text) in [
        (
            "used.rs",
            "fn from_used() { let _ = Method::AgentTurnCancel; }\n",
        ),
        (
            "tests.rs",
            "pub fn both() { let _ = 2; }\npub fn only_test() {}\nfn from_tests() { let _ = Method::AgentTurnCancel; }\n",
        ),
        (
            "orphan.rs",
            "fn from_orphan() { let _ = Method::AgentTurnCancel; }\n",
        ),
        ("broken.rs", "fn (\n"),
    ] {
        write(folder.path(), &format!("crates/kr-sender/src/{path}"), text);
    }
    let tree = Tree::at(folder.path()).expect("the tree");
    assert_eq!(sender_names(&tree), Ok(vec!["from_used".to_owned()]));
    // The index reads the same files: a name that only a test file or an orphan defines is not
    // defined, and one that both define has the product text only.
    let both = tree
        .source("kr_sender", "both")
        .expect("a lookup")
        .expect("a source");
    assert_eq!(both.files, vec!["crates/kr-sender/src/lib.rs".to_owned()]);
    assert!(!both.text.contains("let _ = 2"), "{}", both.text);
    for name in ["only_test", "from_tests", "from_orphan"] {
        assert_eq!(tree.item("kr_sender", name), Lookup::Absent, "{name}");
    }
}

#[test]
fn a_declared_file_that_does_not_parse_is_an_error_where_an_undeclared_one_is_not_read() {
    let folder = small_tree("mod other;\npub fn quiet() {}\n");
    write(folder.path(), "crates/kr-sender/src/other.rs", "fn (\n");
    let tree = Tree::at(folder.path()).expect("the tree");
    let error = sender_names(&tree).expect_err("a parse error");
    assert!(error.contains("other.rs"), "{error}");
    assert!(matches!(tree.item("kr_sender", "quiet"), Lookup::Failed(_)));
}

#[test]
fn a_form_the_inventory_does_not_read_is_refused_with_a_text_of_its_own() {
    let at = "crates/kr-sender/src/lib.rs";
    let refuse = |lib: &str, files: &[(&str, &str)], text: String| {
        let (scan, lookup) = refused(lib, files);
        assert_eq!(scan, text, "{lib}");
        assert_eq!(lookup, text, "{lib}");
    };
    refuse(
        "pub fn f() { #[path = \"x.rs\"] mod inner; }\n",
        &[],
        format!("{at}: the scan does not read a module declared in a block (mod inner;)"),
    );
    refuse(
        "#[cfg_attr(unix, path = \"x.rs\")]\nmod m;\n",
        &[],
        format!(
            "{at}: the scan does not read a cfg_attr that sets a path or a condition (# [cfg_attr (unix , path = \"x.rs\")])"
        ),
    );
    refuse(
        "include!(\"x.rs\");\n",
        &[],
        format!("{at}: the scan does not read include!"),
    );
    refuse(
        "macro_rules! make { ($n:ident) => { mod $n; }; }\n",
        &[],
        format!(
            "{at}: the scan does not read a module declared in a macro (mod $n; in the tokens of macro_rules!)"
        ),
    );
    refuse(
        "other! { mod m; }\n",
        &[],
        format!(
            "{at}: the scan does not read a module declared in a macro (mod m; in the tokens of other!)"
        ),
    );
    refuse(
        "#[path = concat!(\"a\", \".rs\")]\nmod m;\n",
        &[],
        format!("{at}: the scan reads #[path] as one string literal only (mod m)"),
    );
    refuse(
        "mod missing;\n",
        &[],
        format!(
            "{at}: mod missing is at no file the scan can find (tried crates/kr-sender/src/missing.rs, crates/kr-sender/src/missing/mod.rs)"
        ),
    );
    refuse(
        "mod both;\n",
        &[
            ("src/both.rs", "pub fn a() {}\n"),
            ("src/both/mod.rs", "pub fn b() {}\n"),
        ],
        format!(
            "{at}: mod both is at two files (crates/kr-sender/src/both.rs, crates/kr-sender/src/both/mod.rs)"
        ),
    );
    refuse(
        "#[path = \"gone.rs\"]\nmod m;\n",
        &[],
        format!("{at}: mod m is at no file the scan can find (tried crates/kr-sender/src/gone.rs)"),
    );
    // A macro defined twice where one definition can hide the other: in one file, with an export
    // among them, or with a module under `#[macro_use]` among them.
    let twice = |files: &str| {
        format!(
            "kr_sender: the macro m is defined twice where one definition can hide the other ({files}); the scan reads one definition of a name"
        )
    };
    refuse(
        "macro_rules! m { () => {}; }\nmacro_rules! m { () => {}; }\n",
        &[],
        twice("crates/kr-sender/src/lib.rs, crates/kr-sender/src/lib.rs"),
    );
    refuse(
        "mod other;\n#[macro_export]\nmacro_rules! m { () => {}; }\n",
        &[("src/other.rs", "macro_rules! m { () => {}; }\n")],
        twice("crates/kr-sender/src/lib.rs, crates/kr-sender/src/other.rs"),
    );
    refuse(
        "#[macro_use]\nmod other;\nmacro_rules! m { () => {}; }\n",
        &[("src/other.rs", "macro_rules! m { () => {}; }\n")],
        twice("crates/kr-sender/src/lib.rs, crates/kr-sender/src/other.rs"),
    );
    // An item-position macro that nothing defines.
    refuse(
        "thing! { pub struct S; }\n",
        &[],
        format!(
            "{at}: thing! is called at item position, is not defined in kr_sender and is not one the scan accepts"
        ),
    );
    // A `use` of the variants by glob, or of `Method` under another name.
    for import in [
        "use kr_protocol::Method::*;",
        "use kr_protocol::Method as M;",
        "use kr_protocol::Method::{self as M};",
        "fn f() { use kr_protocol::Method::*; }",
    ] {
        let (scan, _) = refused(&format!("{import}\n"), &[]);
        assert_eq!(
            scan,
            format!(
                "{at}: a use of Method::* or of Method under another name; the scan reads Method::<Variant> only"
            ),
            "{import}"
        );
    }
    // Targets and roots.
    let manifest = |extra: &str| {
        format!(
            "{}{extra}",
            "[package]\nname = \"kr-sender\"\nversion = \"0.0.0\"\n"
        )
    };
    let (scan, _) = refused(
        "pub fn quiet() {}\n",
        &[(
            "Cargo.toml",
            &manifest("[[bin]]\nname = \"x\"\npath = \"build/x.rs\"\n"),
        )],
    );
    assert_eq!(
        scan,
        "crates/kr-sender/Cargo.toml: the target path build/x.rs is not src/lib.rs, src/main.rs, src/bin/*.rs or src/bin/*/main.rs"
    );
    let folder = small_tree("pub fn quiet() {}\n");
    std::fs::remove_file(folder.path().join("crates/kr-sender/src/lib.rs")).expect("a file");
    write(folder.path(), "crates/kr-sender/src/other.rs", SENDS);
    let tree = Tree::at(folder.path()).expect("the tree");
    assert_eq!(
        sender_names(&tree),
        Err("kr_sender: no crate root under src".to_owned())
    );
}

#[test]
fn a_form_that_no_configuration_without_test_builds_is_not_refused() {
    // Each form the inventory refuses, under a test attribute, is test code: it is not read.
    let lib = "#[cfg(test)]\nmod missing;\n\
        #[cfg(test)]\n#[path = \"../tests/support/mod.rs\"]\nmod support;\n\
        #[cfg(test)]\n#[path = concat!(\"a\", \".rs\")]\nmod computed;\n\
        #[cfg(test)]\n#[cfg_attr(unix, path = \"x.rs\")]\nmod conditional;\n\
        #[cfg(test)]\nfn f() { include!(\"x.rs\"); #[path = \"y.rs\"] mod inner; }\n\
        #[cfg(test)]\nmod t { macro_rules! make { ($n:ident) => { mod $n; }; } use kr_protocol::Method::*; }\n\
        #[cfg(test)]\nthing! { pub struct S; }\n\
        #[cfg(all(test, unix))]\nmacro_rules! m { () => {}; }\n\
        macro_rules! m { () => {}; }\n";
    assert_eq!(read_names(lib, &[]), Vec::<String>::new());
    // A module with a body in a function is no declaration of a file, and a macro defined in the
    // crate may be called at item position.
    let lib = "pub fn f() { mod inner { pub fn g() {} } }\nmacro_rules! make { () => { pub fn made() { let _ = Method::AgentTurnCancel; } }; }\nmake!();\n";
    assert_eq!(read_names(lib, &[]), vec!["macro:make".to_owned()]);
}

#[test]
fn a_root_through_a_link_reads_what_the_root_itself_does_and_a_link_in_the_tree_is_refused() {
    let folder = small_tree("mod used;\n");
    write(folder.path(), "crates/kr-sender/src/used.rs", SENDS);
    let link = tempfile::tempdir().expect("a folder");
    let through = link.path().join("through");
    std::os::unix::fs::symlink(folder.path(), &through).expect("a link");
    let direct = sender_names(&Tree::at(folder.path()).expect("the tree"));
    assert_eq!(direct, Ok(vec!["sends".to_owned()]));
    assert_eq!(sender_names(&Tree::at(&through).expect("the tree")), direct);
    // A declared file that is a link, and a `#[path]` that leaves the checkout.
    let folder = small_tree("mod linked;\n");
    write(folder.path(), "crates/kr-sender/src/real.rs", SENDS);
    let real = std::fs::canonicalize(folder.path())
        .expect("a path")
        .join("crates/kr-sender/src/real.rs");
    std::os::unix::fs::symlink(&real, folder.path().join("crates/kr-sender/src/linked.rs"))
        .expect("a link");
    let tree = Tree::at(folder.path()).expect("the tree");
    assert_eq!(
        sender_names(&tree),
        Err(format!(
            "crates/kr-sender/src/linked.rs: the scan does not read a path through a link or outside the checkout (it is {})",
            real.display()
        ))
    );
    let outer = tempfile::tempdir().expect("a folder");
    let inner = outer.path().join("inner");
    for (name, text) in [
        ("kr-worker", "pub fn worker() {}\n"),
        (
            "kr-sender",
            "#[path = \"../../../../escape.rs\"]\nmod out;\n",
        ),
        ("kr-protocol", "pub enum Method {}\n"),
    ] {
        write(
            &inner,
            &format!("crates/{name}/Cargo.toml"),
            &format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\n"),
        );
        write(&inner, &format!("crates/{name}/src/lib.rs"), text);
    }
    write(outer.path(), "escape.rs", SENDS);
    let escaped = std::fs::canonicalize(outer.path())
        .expect("a path")
        .join("escape.rs");
    let tree = Tree::at(&inner).expect("the tree");
    assert_eq!(
        sender_names(&tree),
        Err(format!(
            "{0}: the scan does not read a path through a link or outside the checkout (it is {0})",
            escaped.display()
        ))
    );
}

#[test]
fn a_manifest_names_a_target_and_a_procedural_macro_crate_is_refused() {
    let manifest =
        |extra: &str| format!("[package]\nname = \"kr-sender\"\nversion = \"0.0.0\"\n{extra}");
    // A binary named at its conventional path is read, and so is a library at the conventional one.
    let folder = small_tree("pub fn quiet() {}\n");
    write(
        folder.path(),
        "crates/kr-sender/Cargo.toml",
        &manifest(
            "[lib]\npath = \"src/lib.rs\"\n[[bin]]\nname = \"tool\"\npath = \"src/bin/tool.rs\"\n",
        ),
    );
    write(folder.path(), "crates/kr-sender/src/bin/tool.rs", SENDS);
    assert_eq!(
        sender_names(&Tree::at(folder.path()).expect("the tree")),
        Ok(vec!["sends".to_owned()])
    );
    // A binary in a folder of its own and one beside the library are roots without a manifest line.
    let folder = small_tree("pub fn quiet() {}\n");
    write(
        folder.path(),
        "crates/kr-sender/src/bin/one/main.rs",
        "mod two;\n",
    );
    write(folder.path(), "crates/kr-sender/src/bin/one/two.rs", SENDS);
    write(
        folder.path(),
        "crates/kr-sender/src/main.rs",
        "fn main() {}\n",
    );
    assert_eq!(
        sender_names(&Tree::at(folder.path()).expect("the tree")),
        Ok(vec!["sends".to_owned()])
    );
    let folder = small_tree("pub fn quiet() {}\n");
    write(
        folder.path(),
        "crates/kr-sender/Cargo.toml",
        &manifest("[lib]\nproc-macro = true\n"),
    );
    assert_eq!(
        sender_names(&Tree::at(folder.path()).expect("the tree")),
        Err("crates/kr-sender/Cargo.toml: a procedural-macro crate; the scan does not read what it generates".to_owned())
    );
}

#[test]
fn an_item_position_macro_of_another_crate_that_the_scan_accepts_is_read() {
    for name in [
        "thread_local",
        "task_local",
        "bindgen",
        "compile_error",
        "debug_as_display",
        "debug_as_name",
        "debug_fields",
        "display_as_said",
    ] {
        // By its own name and by a path to it, as the source writes them.
        let lib =
            format!("{name}! {{ static X: u8 = 0; }}\ntokio::{name}! {{ static Y: u8 = 0; }}\n");
        assert_eq!(read_names(&lib, &[]), Vec::<String>::new(), "{name}");
    }
}

#[test]
fn an_item_position_macro_of_another_crate_that_nothing_accepts_is_refused() {
    let (scan, lookup) = refused("tokio::unlisted! { static X: u8 = 0; }\n", &[]);
    let text = "crates/kr-sender/src/lib.rs: unlisted! is called at item position, is not defined in kr_sender and is not one the scan accepts".to_owned();
    assert_eq!(scan, text);
    assert_eq!(lookup, text);
}

#[test]
fn a_macro_called_through_a_metavariable_or_exported_to_a_crate_the_scan_reads_is_refused() {
    let at = "kr_sender";
    // A macro that is expanded and calls a macro through a metavariable.
    let lib = "macro_rules! meta { ($m:ident) => { $m!(Method::AgentTurnCancel) }; }\nfn uses() { meta!(Method::AgentTurnCancel); }\n";
    let (scan, _) = refused(lib, &[]);
    assert_eq!(
        scan,
        format!(
            "{at}: the macro meta calls a macro through a metavariable, which the scan cannot follow"
        )
    );
    // The same macro that nothing calls with a sighting is not followed, so nothing is refused.
    let lib = "macro_rules! meta { ($m:ident) => { $m!(Method::AgentTurnCancel) }; }\nfn uses() { meta!(x); }\n";
    assert_eq!(read_names(lib, &[]), vec!["macro:meta".to_owned()]);
    // A call with a sighting to a macro another crate of the scan exports.
    let folder = small_tree("fn f() { shared!(Method::AgentTurnCancel); }\n");
    write(
        folder.path(),
        "crates/kr-worker/src/lib.rs",
        "#[macro_export]\nmacro_rules! shared { ($m:expr) => { $m }; }\n",
    );
    let tree = Tree::at(folder.path()).expect("the tree");
    assert_eq!(
        tree.sightings(&|_| true),
        Err("kr_sender: shared! is called with a sighting and kr_worker exports it; the scan does not follow it across crates".to_owned())
    );
    // The crate that exports it is not read, or the call holds no sighting: nothing is refused.
    assert_eq!(
        tree.sightings(&|krate| krate == "kr_sender")
            .map(|found| found.len()),
        Ok(1)
    );
    write(
        folder.path(),
        "crates/kr-sender/src/lib.rs",
        "fn f() { shared!(1); }\n",
    );
    let tree = Tree::at(folder.path()).expect("the tree");
    assert_eq!(tree.sightings(&|_| true), Ok(Vec::new()));
}

#[test]
fn two_private_definitions_of_one_macro_in_different_files_are_merged_by_name() {
    let lib = "macro_rules! callee_a { () => {}; }\nmacro_rules! callee_b { ($x:expr) => {}; }\nmod a;\nmod b;\n";
    let folder = small_tree(lib);
    write(
        folder.path(),
        "crates/kr-sender/src/a.rs",
        "macro_rules! m { () => { callee_a!() }; }\npub fn user() { m!(Method::AgentTurnCancel); }\n",
    );
    write(
        folder.path(),
        "crates/kr-sender/src/b.rs",
        "macro_rules! m { ($x:expr) => { callee_b!($x) }; }\n",
    );
    let tree = Tree::at(folder.path()).expect("the tree");
    let found = tree
        .sightings(&|krate| krate == "kr_sender")
        .expect("a scan");
    // What either `m` calls is expanded when the call of `m` holds a sighting: the calls of the
    // two definitions are taken under their one name.
    assert_eq!(
        super::walker_cases::names(&found, "kr_sender"),
        BTreeMap::from([
            ("macro:callee_a".to_owned(), vec![SightKind::Expands]),
            ("macro:callee_b".to_owned(), vec![SightKind::Expands]),
            ("macro:m".to_owned(), vec![SightKind::Expands]),
            ("user".to_owned(), vec![SightKind::Names]),
        ])
    );
}
