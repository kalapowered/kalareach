//! The cases of the condition rule and of the module inventory.

use std::collections::BTreeMap;

use super::condition;
use super::repository;
use super::walker::{Depth, Lookup, SightKind, Tree};
use super::walker_cases::{small_tree, tree_at, write};

/// Whether product code can be in a function written with `attributes`.
fn enabled(attributes: &str) -> Result<bool, String> {
    let item: syn::ItemFn = syn::parse_str(&format!("{attributes} fn f() {{}}")).expect("an item");
    condition::enabled(&item.attrs, "lib.rs")
}

#[test]
fn a_place_is_skipped_when_a_condition_around_it_is_false_with_test_false_and_the_rest_unknown() {
    for (attributes, expected) in [
        ("", true),
        ("#[cfg(true)]", true),
        ("#[cfg(false)]", false),
        ("#[cfg(any(false, unix))]", true),
        ("#[cfg(not(false))]", true),
        ("#[cfg(not(true))]", false),
        ("#[cfg(all())]", true),
        ("#[cfg(any())]", false),
        // `test` is false.
        ("#[cfg(test)]", false),
        ("#[cfg(all(test, unix))]", false),
        ("#[cfg(all(unix, test))]", false),
        ("#[cfg(not(not(test)))]", false),
        ("#[cfg(any(all(test, unix), all(test, windows)))]", false),
        ("#[cfg(not(all(test, unix)))]", true),
        ("#[cfg(not(any(test, windows)))]", true),
        ("#[cfg(not(test))]", true),
        ("#[cfg(not(any(true, test)))]", false),
        ("#[cfg(not(all(true, true)))]", false),
        ("#[cfg(not(any(false, test)))]", true),
        // A cfg that is false decides before a cfg_attr that no scan could read.
        ("#[cfg(test)] #[cfg_attr(unix, path = \"x.rs\")]", false),
        // Every other name is unknown, and a place that is not false is read.
        ("#[cfg(any(test, feature = \"testing\"))]", true),
        (
            "#[cfg(any(all(unix, not(target_os = \"macos\")), test))]",
            true,
        ),
        ("#[cfg(any(target_os = \"ios\", test))]", true),
        ("#[cfg(unix)]", true),
        ("#[cfg(windows)]", true),
        ("#[cfg(target_os = \"freebsd\")]", true),
        ("#[cfg(some_atom)]", true),
        ("#[cfg(some_atom = \"x\")]", true),
        ("#[cfg(target_arch)]", true),
        ("#[cfg(debug_assertions = \"x\")]", true),
        // A stack that no configuration builds is read: the rule does not tell the names apart.
        ("#[cfg(all(unix, windows))]", true),
        ("#[cfg(unix)] #[cfg(windows)]", true),
        ("#[cfg(all(feature = \"a\", not(feature = \"a\")))]", true),
        // Several attributes: one false decides.
        ("#[cfg(unix)] #[cfg(test)]", false),
        ("#[cfg(test)] #[cfg(unix)]", false),
        // A predicate may be followed by one comma, and a list ends in one.
        ("#[cfg(unix,)]", true),
        ("#[cfg(test,)]", false),
        ("#[cfg(any(false, unix,),)]", true),
        ("#[cfg(all(test, unix,),)]", false),
        ("#[cfg(true,)]", true),
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
}

#[test]
fn a_condition_the_rule_cannot_read_is_an_error_and_never_a_skip() {
    let unreadable = |text: &str| format!("lib.rs: the scan cannot read the condition {text}");
    for (attributes, text) in [
        ("#[cfg(not(unix, windows))]", "not (unix , windows)"),
        ("#[cfg(not())]", "not ()"),
        ("#[cfg(target_os = 7)]", "target_os = 7"),
        ("#[cfg(a::b)]", "a :: b"),
        ("#[cfg(unix, windows)]", "# [cfg (unix , windows)]"),
        ("#[cfg(version(\"1.2\"))]", "version (\"1.2\")"),
    ] {
        assert_eq!(enabled(attributes), Err(unreadable(text)), "{attributes}");
    }
    let sets =
        |text: &str| format!("lib.rs: the scan does not read a cfg_attr that sets a path ({text})");
    for (attributes, text) in [
        (
            "#[cfg_attr(unix, path = \"x.rs\")]",
            "# [cfg_attr (unix , path = \"x.rs\")]",
        ),
        (
            "#[cfg_attr(unix, cfg_attr(windows, path = \"x.rs\"))]",
            "# [cfg_attr (unix , cfg_attr (windows , path = \"x.rs\"))]",
        ),
    ] {
        assert_eq!(enabled(attributes), Err(sets(text)), "{attributes}");
    }
    // A `cfg_attr` that adds a `cfg` is not read, so it only reads more.
    assert_eq!(enabled("#[cfg_attr(unix, cfg(test))]"), Ok(true));
}

#[test]
fn an_item_that_only_a_configuration_with_test_builds_is_not_defined() {
    let lib = "pub fn product() {}\npub fn both() { let _ = 1; }\n\
               #[cfg(all(test, unix))]\nmod t {\n    pub fn both() { let _ = 2; }\n    pub fn only_test() {}\n}\n";
    let folder = small_tree(lib);
    let tree = tree_at(folder.path()).expect("the tree");
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

/// What the scan of `kr_sender` gives for a tree made of `lib` and `files`, and what a lookup in the
/// same crate gives: the cases hold both to an error where the tree is refused.
fn scanned(lib: &str, files: &[(&str, &str)]) -> (Result<Vec<String>, String>, Lookup) {
    let folder = small_tree(lib);
    for (path, text) in files {
        write(folder.path(), &format!("crates/kr-sender/{path}"), text);
    }
    let tree = tree_at(folder.path()).expect("the tree");
    (sender_names(&tree), tree.item("kr_sender", "anything"))
}

/// What the scan finds in a tree made of `lib` and `files`.
fn read_names(lib: &str, files: &[(&str, &str)]) -> Result<Vec<String>, String> {
    scanned(lib, files).0
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
    let tree = tree_at(folder.path()).expect("the tree");
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
    let tree = tree_at(folder.path()).expect("the tree");
    let error = sender_names(&tree).expect_err("a parse error");
    assert!(error.contains("other.rs"), "{error}");
    assert!(matches!(tree.item("kr_sender", "quiet"), Lookup::Failed(_)));
}

#[test]
fn a_form_the_inventory_does_not_read_is_refused_with_a_text_of_its_own() {
    let at = "crates/kr-sender/src/lib.rs";
    let refuse = |lib: &str, files: &[(&str, &str)], text: String| {
        let (scan, lookup) = scanned(lib, files);
        assert_eq!(scan, Err(text.clone()), "{lib}");
        assert_eq!(lookup, Lookup::Failed(text), "{lib}");
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
            "{at}: the scan does not read a cfg_attr that sets a path (# [cfg_attr (unix , path = \"x.rs\")])"
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
    // `include!` in the tokens of a macro, in a definition's transcriber or in another call's
    // arguments, and a module made by a repetition.
    for lib in [
        "macro_rules! load { () => { include!(\"send.rs\"); }; }\nload!();\n",
        "macro_rules! load { () => { std::include!(\"send.rs\"); }; }\n",
        "other! { include!(\"x.rs\"); }\n",
    ] {
        refuse(lib, &[], format!("{at}: the scan does not read include!"));
    }
    refuse(
        "macro_rules! make { ($($n:ident)*) => { mod $($n)*; }; }\nmake!(hidden);\n",
        &[],
        format!(
            "{at}: the scan does not read a module declared in a macro (mod $(...); in the tokens of macro_rules!)"
        ),
    );
    refuse(
        "other! { mod $($n)*; }\n",
        &[],
        format!(
            "{at}: the scan does not read a module declared in a macro (mod $(...); in the tokens of other!)"
        ),
    );
    // A `macro_rules!` written in the tokens of another macro, in a definition's transcriber or in
    // the arguments of a call, is no definition the scan reads.
    refuse(
        "macro_rules! outer { () => { macro_rules! inner { () => {}; } }; }\n",
        &[],
        format!(
            "{at}: the scan does not read a macro_rules! written in the tokens of another macro (macro_rules! inner in the tokens of macro_rules!)"
        ),
    );
    refuse(
        "other! { macro_rules! inner { () => {}; } }\n",
        &[],
        format!(
            "{at}: the scan does not read a macro_rules! written in the tokens of another macro (macro_rules! inner in the tokens of other!)"
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
    // An item-position macro that nothing defines.
    refuse(
        "thing! { pub struct S; }\n",
        &[],
        format!(
            "{at}: thing! is called at item position and is not written as one of the macros the scan accepts"
        ),
    );
    // A rename of a name the scan reads hides it: `Method`, the two types, `ActionRight`, a variant, a
    // macro the scan accepts (R1), whether the name comes as the old or as the new one.
    for import in [
        "use kr_protocol::Method as M;",
        "use kr_protocol::Method::{self as M};",
        "use kr_protocol::{Method as M, other};",
        "fn f() { use kr_protocol::Method as M; }",
        "use kr_protocol::MutationRequest as Request;",
        "use kr_protocol::ActionTarget as Target;",
        "use kr_protocol::ActionRight as Right;",
        "use kr_protocol::Method::AgentTurnCancel as Cancel;",
        "use kr_protocol::something as AgentTurnCancel;",
        "use kr_protocol::something as Method;",
        "use kr_client::debug_fields as shown;",
        "extern crate kr_protocol as Method;",
        "use kr_protocol::Method::AgentTurnCancel as _;",
    ] {
        let (scan, _) = scanned(&format!("{import}\n"), &[]);
        assert!(
            matches!(&scan, Err(text) if text.starts_with(&format!("{at}: the scan does not read "))
                && text.contains(" under another name (as ")),
            "{import}: {scan:?}"
        );
    }
    assert_eq!(
        read_names("use kr_protocol::Method as M;\n", &[]),
        Err(format!(
            "{at}: the scan does not read Method under another name (as M)"
        ))
    );
    assert_eq!(
        read_names("use kr_protocol::something as Method;\n", &[]),
        Err(format!(
            "{at}: the scan does not read something under another name (as Method)"
        ))
    );
    // A rename of any other name, and a `use` that renames nothing, are not refused.
    for lib in [
        "use kr_protocol::Method::*;",
        "use kr_protocol::Method;",
        "use kr_protocol::other as renamed;",
        "use std::fmt::Result as FmtResult;",
    ] {
        assert_eq!(
            read_names(&format!("{lib}\n"), &[]),
            Ok(Vec::<String>::new()),
            "{lib}"
        );
    }
    // A `type` alias of `MutationRequest` or `ActionTarget` hides the literal it makes (R2), in any
    // place a `type` can stand; an alias of any other type is not refused.
    for alias in [
        "type M = MutationRequest;",
        "type T = kr_protocol::ActionTarget;",
        "type G = kr_protocol::MutationRequest<u8>;",
        "fn f() { type T = ActionTarget; }",
        "trait Tr { type A; }\nimpl Tr for S { type A = ActionTarget; }",
    ] {
        let (scan, _) = scanned(&format!("{alias}\n"), &[]);
        assert!(
            matches!(&scan, Err(text) if text.starts_with(&format!("{at}: the scan does not read a type alias of "))),
            "{alias}: {scan:?}"
        );
    }
    assert_eq!(
        read_names("type M = MutationRequest;\n", &[]),
        Err(format!(
            "{at}: the scan does not read a type alias of MutationRequest (M)"
        ))
    );
    for lib in [
        "type M = Other;",
        "type M = Method;",
        "type B = Box<ActionTarget>;",
        "fn f() { let _ = <Other>::AgentTurnCancelled; }",
    ] {
        assert_eq!(
            read_names(&format!("{lib}\n"), &[]),
            Ok(Vec::<String>::new()),
            "{lib}"
        );
    }
    // A variant name is read wherever it stands (S1): there is no exemption for a crate that defines
    // an enum named `Method`, and none for a form that spells the name by `Self`, a glob or an alias.
    let definition = "pub enum Method { AgentTurnCancel }\nuse Method::*;\ntype M = Method;\nimpl Method { fn f() -> Self { Self::AgentTurnCancel } }\n";
    assert_eq!(
        read_names(&format!("mod local {{ {definition} }}\n"), &[]),
        Ok(vec!["Method".to_owned(), "Method::f".to_owned()])
    );
    // Targets and roots: Cargo's own report gives them, so a binary at any path is a root.
    let manifest = |extra: &str| {
        format!(
            "{}{extra}",
            "[package]\nname = \"kr-sender\"\nversion = \"0.0.0\"\n"
        )
    };
    let (scan, _) = scanned(
        "pub fn quiet() {}\n",
        &[
            (
                "Cargo.toml",
                &manifest("[[bin]]\nname = \"x\"\npath = \"build/x.rs\"\n"),
            ),
            ("build/x.rs", SENDS),
        ],
    );
    assert_eq!(scan, Ok(vec!["sends".to_owned()]));
    // A crate Cargo gives no library or binary (only a test) has no root.
    let folder = small_tree("pub fn quiet() {}\n");
    std::fs::remove_file(folder.path().join("crates/kr-sender/src/lib.rs")).expect("a file");
    write(folder.path(), "crates/kr-sender/src/other.rs", SENDS);
    write(
        folder.path(),
        "crates/kr-sender/tests/only.rs",
        "fn t() {}\n",
    );
    let tree = tree_at(folder.path()).expect("the tree");
    assert_eq!(
        sender_names(&tree),
        Err("kr_sender: no library or binary target".to_owned())
    );
}

#[test]
fn an_inner_condition_of_a_file_decides_whether_the_file_is_read() {
    let files = [
        (
            "src/windows_only.rs",
            "#![cfg(windows)]\nfn from_windows() { let _ = Method::AgentTurnCancel; }\n",
        ),
        (
            "src/tested.rs",
            "#![cfg(test)]\nfn from_tested() { let _ = Method::AgentTurnSteer; }\ninclude!(\"x.rs\");\n",
        ),
        // The condition of the file does not stop an item in it from being skipped by its own.
        (
            "src/mixed.rs",
            "#![cfg(unix)]\n#[cfg(test)]\nfn from_both() { let _ = Method::AgentPromptQueue; }\nfn from_unix() { let _ = Method::AgentTurnCancel; }\n",
        ),
    ];
    assert_eq!(
        read_names("mod windows_only;\nmod tested;\nmod mixed;\n", &files),
        Ok(vec!["from_unix".to_owned(), "from_windows".to_owned()])
    );
    // The index holds the same.
    let folder = small_tree("mod windows_only;\nmod tested;\nmod mixed;\n");
    for (path, text) in files {
        write(folder.path(), &format!("crates/kr-sender/{path}"), text);
    }
    let tree = tree_at(folder.path()).expect("the tree");
    assert_eq!(tree.item("kr_sender", "from_both"), Lookup::Absent);
    assert_eq!(tree.item("kr_sender", "from_tested"), Lookup::Absent);
    for name in ["from_unix", "from_windows"] {
        assert!(
            matches!(tree.item("kr_sender", name), Lookup::Found(_)),
            "{name}"
        );
    }
    // A file that only a declaration that is false reaches is not read, and one that a declaration
    // that is not false reaches is.
    let folder =
        small_tree("#[cfg(all(test, unix))]\nmod only_by_test;\n#[cfg(unix)]\nmod by_unix;\n");
    write(
        folder.path(),
        "crates/kr-sender/src/only_by_test.rs",
        "fn from_a_test_file() { include!(\"x.rs\"); }\n",
    );
    write(
        folder.path(),
        "crates/kr-sender/src/by_unix.rs",
        "#[cfg(test)]\nfn from_test_in_unix() {}\nfn from_unix_file() {}\n",
    );
    let tree = tree_at(folder.path()).expect("the tree");
    assert_eq!(tree.item("kr_sender", "from_a_test_file"), Lookup::Absent);
    assert_eq!(tree.item("kr_sender", "from_test_in_unix"), Lookup::Absent);
    assert!(matches!(
        tree.item("kr_sender", "from_unix_file"),
        Lookup::Found(_)
    ));
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
        macro_rules! m { () => {}; }\n\
        pub struct S;\n\
        impl S {\n\
            #[cfg(test)]\nfn g() { include!(\"x.rs\"); }\n\
            #[cfg(test)]\nconst C: u8 = { include!(\"x.rs\") };\n\
            #[cfg(test)]\nunlisted_in_impl!();\n\
        }\n\
        pub trait T {\n\
            #[cfg(test)]\nfn h() { include!(\"x.rs\"); }\n\
            #[cfg(test)]\nconst D: u8 = { include!(\"x.rs\") };\n\
            #[cfg(test)]\nunlisted_in_trait!();\n\
        }\n";
    assert_eq!(read_names(lib, &[]), Ok(Vec::<String>::new()));
    // A module with a body in a function is no declaration of a file, and a macro defined in the
    // crate may be called at item position.
    let lib = "pub fn f() { mod inner { pub fn g() {} } }\nmacro_rules! make { () => { pub fn made() { let _ = Method::AgentTurnCancel; } }; }\nmake!();\n";
    assert_eq!(read_names(lib, &[]), Ok(vec!["macro:make".to_owned()]));
}

#[test]
fn a_root_through_a_link_reads_what_the_root_itself_does_and_a_link_in_the_tree_is_refused() {
    let folder = small_tree("mod used;\n");
    write(folder.path(), "crates/kr-sender/src/used.rs", SENDS);
    let link = tempfile::tempdir().expect("a folder");
    let through = link.path().join("through");
    std::os::unix::fs::symlink(folder.path(), &through).expect("a link");
    let direct = sender_names(&tree_at(folder.path()).expect("the tree"));
    assert_eq!(direct, Ok(vec!["sends".to_owned()]));
    assert_eq!(sender_names(&tree_at(&through).expect("the tree")), direct);
    // A declared file that is a link, and a `#[path]` that leaves the checkout.
    let folder = small_tree("mod linked;\n");
    write(folder.path(), "crates/kr-sender/src/real.rs", SENDS);
    let real = std::fs::canonicalize(folder.path())
        .expect("a path")
        .join("crates/kr-sender/src/real.rs");
    std::os::unix::fs::symlink(&real, folder.path().join("crates/kr-sender/src/linked.rs"))
        .expect("a link");
    let tree = tree_at(folder.path()).expect("the tree");
    assert_eq!(
        sender_names(&tree),
        Err(format!(
            "crates/kr-sender/src/linked.rs: the scan does not read a path through a link, with .. or from the root of the file system (it is {})",
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
    let tree = tree_at(&inner).expect("the tree");
    // A path that leaves the checkout by `..` is refused where it is written.
    assert_eq!(
        sender_names(&tree),
        Err("crates/kr-sender/src/lib.rs: the scan does not read a path through a link, with .. or from the root of the file system (it is ../../../../escape.rs)".to_owned())
    );
}

#[test]
fn a_link_in_a_written_path_is_refused_where_it_stands_whatever_file_it_leads_to() {
    let written = |path: &str| format!("#[path = \"{path}\"]\nmod chosen;\n");
    let prepare = |path: &str| {
        let folder = small_tree(&written(path));
        // Two files of the one name: the one the cancelled path names, and the one the file
        // system finds when `link/..` is the parent of the link's target.
        write(
            folder.path(),
            "crates/kr-sender/src/chosen.rs",
            "pub fn lexical() { let _ = Method::AgentTurnCancel; }\n",
        );
        write(
            folder.path(),
            "crates/kr-sender/src/deep/chosen.rs",
            "pub fn by_the_file_system() { let _ = Method::AgentTurnSteer; }\n",
        );
        let source = folder.path().join("crates/kr-sender/src");
        std::fs::create_dir_all(source.join("deep/inner")).expect("a folder");
        std::fs::create_dir_all(source.join("beside")).expect("a folder");
        std::os::unix::fs::symlink(source.join("deep/inner"), source.join("link")).expect("a link");
        // A link to a folder beside the file's own: its parent is the file's folder, so the step up
        // after it cancels to the file the file system finds too.
        std::os::unix::fs::symlink(source.join("beside"), source.join("sibling")).expect("a link");
        folder
    };
    let refused = |folder: &std::path::Path, link: &str| {
        let root = std::fs::canonicalize(folder).expect("a path");
        format!(
            "crates/kr-sender/src/lib.rs: the scan does not read a path through a link, with .. or from the root of the file system ({} is a link)",
            root.join("crates/kr-sender/src").join(link).display()
        )
    };
    let dotted = |written: &str| {
        format!(
            "crates/kr-sender/src/lib.rs: the scan does not read a path through a link, with .. or from the root of the file system (it is {written})"
        )
    };
    // A `..` among the steps is refused where it stands, whatever file the steps lead to.
    let folder = prepare("link/../chosen.rs");
    let tree = tree_at(folder.path()).expect("the tree");
    let text = dotted("link/../chosen.rs");
    assert_eq!(sender_names(&tree), Err(text.clone()));
    assert_eq!(tree.item("kr_sender", "lexical"), Lookup::Failed(text));
    for written in [
        "sibling/../chosen.rs",
        "deep/../chosen.rs",
        "gone/../chosen.rs",
    ] {
        let folder = prepare(written);
        assert_eq!(
            sender_names(&tree_at(folder.path()).expect("the tree")),
            Err(dotted(written)),
            "{written}"
        );
    }
    // A start at the root of the file system is refused the same way.
    let folder = prepare("/etc/chosen.rs");
    assert_eq!(
        sender_names(&tree_at(folder.path()).expect("the tree")),
        Err(dotted("/etc/chosen.rs"))
    );
    // A link among the steps with no `..`, as a folder.
    // A file that is a link, and a link at the end of the path.
    let folder = prepare("chosen.rs");
    let source = folder.path().join("crates/kr-sender/src");
    std::fs::rename(source.join("chosen.rs"), source.join("real.rs")).expect("a rename");
    std::os::unix::fs::symlink(source.join("real.rs"), source.join("chosen.rs")).expect("a link");
    assert_eq!(
        sender_names(&tree_at(folder.path()).expect("the tree")),
        Err(refused(folder.path(), "chosen.rs"))
    );
    let folder = prepare("link/chosen.rs");
    assert_eq!(
        sender_names(&tree_at(folder.path()).expect("the tree")),
        Err(refused(folder.path(), "link"))
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
        sender_names(&tree_at(folder.path()).expect("the tree")),
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
        sender_names(&tree_at(folder.path()).expect("the tree")),
        Ok(vec!["sends".to_owned()])
    );
    let folder = small_tree("pub fn quiet() {}\n");
    write(
        folder.path(),
        "crates/kr-sender/Cargo.toml",
        &manifest("[lib]\nproc-macro = true\n"),
    );
    assert_eq!(
        sender_names(&tree_at(folder.path()).expect("the tree")),
        Err("crates/kr-sender/Cargo.toml: a procedural-macro crate; the scan does not read what it generates".to_owned())
    );
}

#[test]
fn a_refused_crate_gives_no_lookup_result_whatever_the_index_holds() {
    let existing = "pub fn existing() {}\n";
    // What the lookups of a crate give: an item the index holds, one it does not, as an item, as a
    // source and as a root.
    let lookups = |tree: &Tree| {
        let item = |name: &str| tree.item("kr_sender", name);
        let source = |name: &str| tree.source("kr_sender", name).map(|found| found.is_some());
        let root = |name: &str| tree.lookup("kr_sender", &[name], Depth::Alone);
        (
            [item("existing"), item("missing")],
            [source("existing"), source("missing")],
            [root("existing"), root("missing")],
        )
    };
    // No refusal: the index answers.
    let folder = small_tree(existing);
    let tree = tree_at(folder.path()).expect("the tree");
    let (items, sources, roots) = lookups(&tree);
    assert!(matches!(items[0], Lookup::Found(_)), "{items:?}");
    assert_eq!(items[1], Lookup::Absent);
    assert_eq!(sources, [Ok(true), Ok(false)]);
    assert!(matches!(roots[0], Lookup::Found(_)), "{roots:?}");
    assert_eq!(roots[1], Lookup::Absent);
    // Each refusal of the scan and of the crate gives no `Found` and no `Absent`.
    let meta = "macro_rules! meta { ($m:ident) => { $m!(Method::AgentTurnCancel) }; }\nfn uses() { meta!(Method::AgentTurnCancel); }\n";
    for (lib, text) in [
        (
            format!("use kr_protocol::Method as M;\n{existing}"),
            "crates/kr-sender/src/lib.rs: the scan does not read Method under another name (as M)",
        ),
        (
            format!("{meta}{existing}"),
            "kr_sender: the macro meta calls a macro through a metavariable, which the scan cannot follow",
        ),
    ] {
        let folder = small_tree(&lib);
        let tree = tree_at(folder.path()).expect("the tree");
        let (items, sources, roots) = lookups(&tree);
        let failed = Lookup::Failed(text.to_owned());
        assert_eq!(items, [failed.clone(), failed.clone()], "{text}");
        assert_eq!(
            sources,
            [Err(text.to_owned()), Err(text.to_owned())],
            "{text}"
        );
        assert_eq!(roots, [failed.clone(), failed], "{text}");
    }
    // A procedural-macro crate.
    let folder = small_tree(existing);
    write(
        folder.path(),
        "crates/kr-sender/Cargo.toml",
        "[package]\nname = \"kr-sender\"\nversion = \"0.0.0\"\n[lib]\nproc-macro = true\n",
    );
    let tree = tree_at(folder.path()).expect("the tree");
    let text = "crates/kr-sender/Cargo.toml: a procedural-macro crate; the scan does not read what it generates";
    let (items, sources, roots) = lookups(&tree);
    let failed = Lookup::Failed(text.to_owned());
    assert_eq!(items, [failed.clone(), failed.clone()]);
    assert_eq!(sources, [Err(text.to_owned()), Err(text.to_owned())]);
    assert_eq!(roots, [failed.clone(), failed]);
    // A macro that calls through a metavariable and that a call with a sighting in another crate marks:
    // refused where that crate is in the tree's scope, read where it is not.
    let folder = small_tree(&format!(
        "macro_rules! meta {{ ($m:ident) => {{ $m!(1) }}; }}\n{existing}"
    ));
    write(
        folder.path(),
        "crates/kr-worker/src/lib.rs",
        "fn f() { meta!(Method::AgentTurnCancel); }\n",
    );
    let text = "kr_sender: the macro meta calls a macro through a metavariable, which the scan cannot follow";
    let tree = tree_at(folder.path()).expect("the tree");
    let (items, sources, roots) = lookups(&tree);
    let failed = Lookup::Failed(text.to_owned());
    assert_eq!(items, [failed.clone(), failed.clone()]);
    assert_eq!(sources, [Err(text.to_owned()), Err(text.to_owned())]);
    assert_eq!(roots, [failed.clone(), failed]);
    let tree = tree.scoped(&|krate| krate == "kr_sender");
    let (items, sources, roots) = lookups(&tree);
    assert!(matches!(items[0], Lookup::Found(_)), "{items:?}");
    assert_eq!(items[1], Lookup::Absent);
    assert_eq!(sources, [Ok(true), Ok(false)]);
    assert!(matches!(roots[0], Lookup::Found(_)), "{roots:?}");
    assert_eq!(roots[1], Lookup::Absent);
}

#[test]
fn an_item_position_macro_of_another_crate_that_the_scan_accepts_is_read() {
    // Each family by the provider that makes it safe, as the source writes it: bare, by a path, and
    // by a `use` line of the file that gives the name.
    for call in [
        "thread_local! { static X: u8 = 0; }",
        "std::thread_local! { static X: u8 = 0; }",
        "tokio::task_local! { static X: u8; }",
        "wasmtime::component::bindgen!({ path: \"x.wit\" });",
        "compile_error!(\"no\");",
        "std::compile_error!(\"no\");",
        "core::compile_error!(\"no\");",
        "tauri::ios_plugin_binding!(init_plugin_x);",
        "kr_client::debug_as_display!(E);",
        "kr_client::debug_as_name!(E);",
        "kr_client::debug_fields!(E { a });",
        "kr_client::display_as_said!(E);",
        "use tokio::task_local;\ntask_local! { static X: u8; }",
        "use wasmtime::component::bindgen;\nbindgen!({ path: \"x.wit\" });",
        "use schemars::json_schema;\nmacro_rules! schema { () => { json_schema!({}) }; }",
        "macro_rules! schema { () => { schemars::json_schema!({}) }; }",
    ] {
        assert_eq!(
            read_names(&format!("{call}\n"), &[]),
            Ok(Vec::<String>::new()),
            "{call}"
        );
    }
    // The macros of the standard library that the transcribers of the workspace call, bare and by a
    // path, and the crate's own, bare and by a path to its own modules and its root.
    let lib = "mod inner;\nmacro_rules! own { () => {}; }\nmacro_rules! uses {\n    ($x:expr) => {\n        assert_eq!($x, 1);\n        core::matches!($x, 1);\n        std::format!(\"{}\", $x);\n        stringify!($x);\n        own!();\n        $crate::own!();\n        crate::own!();\n        inner::inside!();\n        vec![0];\n    };\n}\n";
    let files = [("src/inner.rs", "macro_rules! inside { () => {}; }\n")];
    assert_eq!(read_names(lib, &files), Ok(Vec::<String>::new()));
    // A name is accepted where its own file imports the path: another file's import of the same name
    // from another provider does not make it a different macro there.
    let files = [
        (
            "src/a.rs",
            "use schemars::json_schema;\njson_schema!({});\n",
        ),
        ("src/b.rs", "use foreign::json_schema;\n"),
    ];
    assert_eq!(
        read_names("mod a;\nmod b;\n", &files),
        Ok(Vec::<String>::new())
    );
}

#[test]
fn an_item_position_macro_of_another_crate_that_nothing_accepts_is_refused() {
    // The path the refused call is written with: the one that ends in `name!` in `lib`.
    let text = |lib: &str, name: &str, position: &str| {
        let end = lib.find(&format!("{name}!")).expect("the call") + name.len();
        let start = lib[..end]
            .rfind(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | ':' | '$')))
            .map_or(0, |at| at + 1);
        format!(
            "crates/kr-sender/src/lib.rs: {}! is called at {position} and is not written as one of the macros the scan accepts",
            &lib[start..end]
        )
    };
    for (lib, name, position) in [
        (
            "tokio::unlisted! { static X: u8 = 0; }",
            "unlisted",
            "item position",
        ),
        // A family name from a provider that is not its own, bare where it has no bare form, and
        // through an import that names another provider or a glob.
        ("foreign::bindgen!({});", "bindgen", "item position"),
        ("tokio::bindgen!({});", "bindgen", "item position"),
        ("bindgen!({});", "bindgen", "item position"),
        (
            "task_local! { static X: u8; }",
            "task_local",
            "item position",
        ),
        (
            "std::task_local! { static X: u8; }",
            "task_local",
            "item position",
        ),
        (
            "foreign::thread_local! { static X: u8 = 0; }",
            "thread_local",
            "item position",
        ),
        ("json_schema!({});", "json_schema", "item position"),
        (
            "use schemars::*;\njson_schema!({});",
            "json_schema",
            "item position",
        ),
        (
            "use foreign::json_schema;\njson_schema!({});",
            "json_schema",
            "item position",
        ),
        (
            "kr_worker::debug_fields!(E { a });",
            "debug_fields",
            "item position",
        ),
        // A name that a file imports from two providers is read as each of them.
        (
            "use schemars::json_schema;\nmod m { use foreign::json_schema; }\njson_schema!({});\n",
            "json_schema",
            "item position",
        ),
        // Of several refused calls the one first by name is told.
        (
            "zz_thing! { pub struct S; }\naa_thing! { pub struct T; }\n",
            "aa_thing",
            "item position",
        ),
        // A module of the crate named like a listed provider is no provider: the path is the crate's
        // own, and the crate defines no macro of that name.
        (
            "mod tokio { pub fn f() {} }\ntokio::task_local! { static X: u8; }\n",
            "task_local",
            "item position",
        ),
        (
            "mod std {}\nstd::thread_local! { static X: u8 = 0; }\n",
            "thread_local",
            "item position",
        ),
        // The crate's own prefix, or one of its modules, names a macro the crate defines, and not
        // one that a `use` or a re-export brought in from elsewhere.
        (
            "use foreign::generate as new_items;\ncrate::new_items!();\n",
            "new_items",
            "item position",
        ),
        (
            "use foreign::generate;\ncrate::generate!();\n",
            "generate",
            "item position",
        ),
        (
            "mod bridge { pub use foreign::*; }\nbridge::generate!();\n",
            "generate",
            "item position",
        ),
        (
            "macro_rules! m { () => { crate::generate!(); }; }\nm!();\n",
            "generate",
            "a transcriber",
        ),
        // A name that stands for a module gives a qualified call no provider: the path is judged as
        // written.
        (
            "use wasmtime::component;\ncomponent::bindgen!({ path: \"x.wit\" });",
            "bindgen",
            "item position",
        ),
        (
            "use wasmtime::component as w;\nw::bindgen!({});",
            "bindgen",
            "item position",
        ),
        (
            "use tokio as t;\nt::task_local! { static X: u8; }",
            "task_local",
            "item position",
        ),
        // A macro of the crate's own name behind another crate's path is that crate's macro.
        (
            "macro_rules! mine { () => {}; }\nforeign::mine! {}\n",
            "mine",
            "item position",
        ),
        // The transcribers of a definition, at any depth.
        (
            "macro_rules! m { () => { other::generate!(); }; }\nm!();\n",
            "generate",
            "a transcriber",
        ),
        (
            "macro_rules! m { () => { generate!(); }; }\nm!();\n",
            "generate",
            "a transcriber",
        ),
        (
            "macro_rules! m { () => { vec![other::generate!()]; }; }\n",
            "generate",
            "a transcriber",
        ),
        (
            "fn f() { macro_rules! local { () => { other::generate!(); }; } }\n",
            "generate",
            "a transcriber",
        ),
        // An item of an impl block or a trait is at item position too.
        (
            "struct S;\nimpl S { generate!(); }\n",
            "generate",
            "item position",
        ),
        ("trait T { generate!(); }\n", "generate", "item position"),
    ] {
        let (scan, lookup) = scanned(lib, &[]);
        assert_eq!(scan, Err(text(lib, name, position)), "{lib}");
        assert_eq!(lookup, Lookup::Failed(text(lib, name, position)), "{lib}");
    }
    // A name that another file imports from the accepted provider is not imported here: the call is
    // read as the file that holds it writes it.
    let (scan, _) = scanned(
        "mod a;\nmod b;\n",
        &[
            ("src/a.rs", "json_schema!({});\n"),
            ("src/b.rs", "use schemars::json_schema;\n"),
        ],
    );
    assert_eq!(
        scan,
        Err("crates/kr-sender/src/a.rs: json_schema! is called at item position and is not written as one of the macros the scan accepts".to_owned())
    );
}

#[test]
fn a_macro_called_through_a_metavariable_is_refused_where_a_call_with_a_sighting_expands_it() {
    let at = "kr_sender";
    // A macro that is expanded and calls a macro through a metavariable.
    let lib = "macro_rules! meta { ($m:ident) => { $m!(Method::AgentTurnCancel) }; }\nfn uses() { meta!(Method::AgentTurnCancel); }\n";
    let (scan, _) = scanned(lib, &[]);
    assert_eq!(
        scan,
        Err(format!(
            "{at}: the macro meta calls a macro through a metavariable, which the scan cannot follow"
        ))
    );
    // The same macro that nothing calls with a sighting is not followed, so nothing is refused.
    let lib = "macro_rules! meta { ($m:ident) => { $m!(Method::AgentTurnCancel) }; }\nfn uses() { meta!(x); }\n";
    assert_eq!(read_names(lib, &[]), Ok(vec!["macro:meta".to_owned()]));
    // A call in another crate marks the name, so the macro of that name here is expanded and refused.
    let folder = small_tree("fn f() { meta!(Method::AgentTurnCancel); }\n");
    write(
        folder.path(),
        "crates/kr-worker/src/lib.rs",
        "macro_rules! meta { ($m:ident) => { $m!(Method::AgentTurnCancel) }; }\n",
    );
    let tree = tree_at(folder.path()).expect("the tree");
    assert_eq!(
        tree.sightings(&|_| true),
        Err("kr_worker: the macro meta calls a macro through a metavariable, which the scan cannot follow".to_owned())
    );
    assert_eq!(
        tree.refusals("kr_worker"),
        Err("kr_worker: the macro meta calls a macro through a metavariable, which the scan cannot follow".to_owned())
    );
    // The crate that calls it is not read: nothing marks the name.
    assert_eq!(
        tree.sightings(&|krate| krate == "kr_worker")
            .map(|found| found.len()),
        Ok(1)
    );
}

#[test]
fn a_name_that_ends_a_call_with_a_sighting_expands_the_macros_of_that_name_in_every_crate_the_scan_reads()
 {
    use SightKind::{Expands, Names};
    let sightings = |sender: &str, worker: &str, scope: &dyn Fn(&str) -> bool| {
        let folder = small_tree(sender);
        write(folder.path(), "crates/kr-worker/src/lib.rs", worker);
        let tree = tree_at(folder.path()).expect("the tree");
        tree.sightings(scope).map(|found| {
            let mut by = BTreeMap::new();
            for krate in ["kr_sender", "kr_worker"] {
                by.insert(krate, super::walker_cases::names(&found, krate));
            }
            by
        })
    };
    let worker = "#[macro_export]\nmacro_rules! shared { ($m:expr) => { $m }; }\n";
    // A call with a sighting, bare or by a path to the other crate, marks the macro the other
    // crate defines under that name: the scan knows a macro by its last name.
    for call in [
        "shared!(Method::AgentTurnCancel)",
        "kr_worker::shared!(Method::AgentTurnCancel)",
    ] {
        let lib = format!("fn f() {{ {call}; }}\n");
        assert_eq!(
            sightings(&lib, worker, &|_| true),
            Ok(BTreeMap::from([
                ("kr_sender", BTreeMap::from([("f".to_owned(), vec![Names])])),
                (
                    "kr_worker",
                    BTreeMap::from([("macro:shared".to_owned(), vec![Expands])])
                ),
            ])),
            "{call}"
        );
    }
    // A raw identifier names the same macro: a raw call marks the definition, and a raw definition is
    // marked by a plain call.
    let raw_worker = "#[macro_export]\nmacro_rules! r#shared { ($m:expr) => { $m }; }\n";
    for (call, definition) in [
        ("r#shared!(Method::AgentTurnCancel)", worker),
        ("kr_worker::r#shared!(Method::AgentTurnCancel)", worker),
        ("shared!(Method::AgentTurnCancel)", raw_worker),
    ] {
        let lib = format!("fn f() {{ {call}; }}\n");
        assert_eq!(
            sightings(&lib, definition, &|_| true).map(|by| by["kr_worker"].clone()),
            Ok(BTreeMap::from([("macro:shared".to_owned(), vec![Expands])])),
            "{call}"
        );
    }
    // A scope without the crate that holds the definition has nothing to mark, and a scope without the
    // crate that makes the call marks nothing.
    let lib = "fn f() { shared!(Method::AgentTurnCancel); }\n";
    assert_eq!(
        sightings(lib, worker, &|krate| krate == "kr_sender"),
        Ok(BTreeMap::from([
            ("kr_sender", BTreeMap::from([("f".to_owned(), vec![Names])])),
            ("kr_worker", BTreeMap::new()),
        ]))
    );
    assert_eq!(
        sightings(lib, worker, &|krate| krate == "kr_worker"),
        Ok(BTreeMap::from([
            ("kr_sender", BTreeMap::new()),
            ("kr_worker", BTreeMap::new()),
        ]))
    );
    // A call with no sighting in its arguments marks nothing.
    assert_eq!(
        sightings("fn f() { shared!(1); }\n", worker, &|_| true),
        Ok(BTreeMap::from([
            ("kr_sender", BTreeMap::new()),
            ("kr_worker", BTreeMap::new()),
        ]))
    );
    // The names that the transcribers of a marked definition call are marked in every crate too: the
    // definition here calls one of the listed macros of another crate by its path.
    let lib = "macro_rules! fwd { ($x:expr) => { kr_client::debug_fields!($x) }; }\nfn f() { fwd!(Method::AgentTurnCancel); }\n";
    let worker = "macro_rules! debug_fields { ($x:expr) => { $x }; }\n";
    assert_eq!(
        sightings(lib, worker, &|_| true),
        Ok(BTreeMap::from([
            (
                "kr_sender",
                BTreeMap::from([
                    ("f".to_owned(), vec![Names]),
                    ("macro:fwd".to_owned(), vec![Expands]),
                ])
            ),
            (
                "kr_worker",
                BTreeMap::from([("macro:debug_fields".to_owned(), vec![Expands])])
            ),
        ]))
    );
}

#[test]
fn a_rename_of_the_name_of_a_macro_that_a_crate_in_scope_defines_is_refused() {
    let across = |lib: &str, name: &str| {
        let folder = small_tree(lib);
        write(
            folder.path(),
            "crates/kr-worker/src/lib.rs",
            &format!("#[macro_export]\nmacro_rules! {name} {{ ($m:expr) => {{ $m }}; }}\n"),
        );
        let tree = tree_at(folder.path()).expect("the tree");
        tree.sightings(&|_| true).map(|found| found.len())
    };
    let renamed = |old: &str, new: &str| {
        Err(format!(
            "crates/kr-sender/src/lib.rs: the scan does not read {old} under another name (as {new})"
        ))
    };
    // A call through the name a `use` gives the other crate's macro.
    let lib = "use kr_worker::shared as renamed;\nfn f() { renamed!(Method::AgentTurnCancel); }\n";
    assert_eq!(across(lib, "shared"), renamed("shared", "renamed"));
    // The new name is the name of a macro the other crate defines.
    let lib = "use kr_worker::other as shared;\nfn f() { shared!(Method::AgentTurnCancel); }\n";
    assert_eq!(across(lib, "shared"), renamed("other", "shared"));
    // A name that is no rename of the other crate's macro is not that macro.
    let lib = "use kr_worker::other as renamed;\nfn f() { renamed!(Method::AgentTurnCancel); }\n";
    assert_eq!(across(lib, "shared"), Ok(1));
    // In a transcriber, the renamed name is a macro of another crate that nothing accepts.
    let lib = "use kr_worker::shared as renamed;\nmacro_rules! fwd { ($x:expr) => { renamed!($x) }; }\nfn f() { fwd!(Method::AgentTurnCancel); }\n";
    assert_eq!(
        across(lib, "shared"),
        Err("crates/kr-sender/src/lib.rs: renamed! is called at a transcriber and is not written as one of the macros the scan accepts".to_owned())
    );
}

#[test]
fn a_macro_defined_in_a_function_body_is_part_of_the_function() {
    use SightKind::{Expands, Names};
    let folder = small_tree(
        "fn f() {\n    macro_rules! inner { ($m:expr) => { $m }; }\n    inner!(Method::AgentTurnCancel);\n}\nfn g() {\n    macro_rules! holds { () => { Method::AgentTurnSteer }; }\n    #[cfg(test)]\n    macro_rules! gone { () => {}; }\n}\n",
    );
    let tree = tree_at(folder.path()).expect("the tree");
    let found = tree
        .sightings(&|krate| krate == "kr_sender")
        .map(|found| super::walker_cases::names(&found, "kr_sender"));
    // The function holds the sightings its definitions write: none is an item of its own.
    assert_eq!(
        found,
        Ok(BTreeMap::from([
            ("f".to_owned(), vec![Names]),
            ("g".to_owned(), vec![Names]),
        ]))
    );
    for name in ["macro:inner", "macro:holds", "macro:gone"] {
        assert_eq!(tree.item("kr_sender", name), Lookup::Absent, "{name}");
    }
    // What a definition in a body calls is called when the macro is marked: the name it calls is
    // marked, and the macro of that name at item level is expanded.
    let folder = small_tree(
        "fn f() {\n    macro_rules! inner { ($x:expr) => { forward!($x) }; }\n    inner!(Method::AgentTurnCancel);\n}\nmacro_rules! forward { ($x:expr) => { $x }; }\n",
    );
    let tree = tree_at(folder.path()).expect("the tree");
    let found = tree
        .sightings(&|krate| krate == "kr_sender")
        .map(|found| super::walker_cases::names(&found, "kr_sender"));
    assert_eq!(
        found,
        Ok(BTreeMap::from([
            ("f".to_owned(), vec![Names]),
            ("macro:forward".to_owned(), vec![Expands]),
        ]))
    );
}

#[test]
fn definitions_of_one_macro_name_are_one_under_it_and_add_marks_and_take_none() {
    use SightKind::{Expands, Names};
    let marks = |lib: &str, files: &[(&str, &str)]| {
        let folder = small_tree(lib);
        for (path, text) in files {
            write(folder.path(), &format!("crates/kr-sender/{path}"), text);
        }
        let tree = tree_at(folder.path()).expect("the tree");
        tree.sightings(&|krate| krate == "kr_sender")
            .map(|found| super::walker_cases::names(&found, "kr_sender"))
    };
    let both = Ok(BTreeMap::from([
        ("macro:callee_a".to_owned(), vec![Expands]),
        ("macro:callee_b".to_owned(), vec![Expands]),
        ("macro:m".to_owned(), vec![Expands]),
        ("user".to_owned(), vec![Names]),
    ]));
    let callees = "macro_rules! callee_a { () => {}; }\nmacro_rules! callee_b { () => {}; }\n";
    let user = "pub fn user() { m!(Method::AgentTurnCancel); }\n";
    // In one file twice, with an export among them.
    let lib = format!(
        "{callees}#[macro_export]\nmacro_rules! m {{ () => {{ callee_a!() }}; }}\nmacro_rules! m {{ () => {{ callee_b!() }}; }}\n{user}"
    );
    assert_eq!(marks(&lib, &[]), both);
    // In a parent before `mod child;` and in the child, and in a module under `#[macro_use]`.
    let lib = format!("{callees}macro_rules! m {{ () => {{ callee_a!() }}; }}\nmod child;\n{user}");
    let child = [(
        "src/child.rs",
        "macro_rules! m { () => { callee_b!() }; }\n",
    )];
    assert_eq!(marks(&lib, &child), both);
    let lib = format!(
        "{callees}macro_rules! m {{ () => {{ callee_a!() }}; }}\n#[macro_use]\nmod child;\n{user}"
    );
    assert_eq!(marks(&lib, &child), both);
    // One file that two declarations reach holds one definition.
    let lib = "#[cfg(unix)]\n#[path = \"shared.rs\"]\nmod as_unix;\n\
               #[cfg(windows)]\n#[path = \"shared.rs\"]\nmod as_windows;\n";
    let shared = [(
        "src/shared.rs",
        "macro_rules! m { () => {}; }\npub fn shared() { m!(Method::AgentTurnCancel); }\n",
    )];
    assert_eq!(
        marks(lib, &shared),
        Ok(BTreeMap::from([
            ("macro:m".to_owned(), vec![Expands]),
            ("shared".to_owned(), vec![Names]),
        ]))
    );
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
    let tree = tree_at(folder.path()).expect("the tree");
    let found = tree
        .sightings(&|krate| krate == "kr_sender")
        .map(|found| super::walker_cases::names(&found, "kr_sender"));
    // What either `m` calls is expanded when the call of `m` holds a sighting: the calls of the
    // two definitions are taken under their one name.
    assert_eq!(
        found,
        Ok(BTreeMap::from([
            ("macro:callee_a".to_owned(), vec![SightKind::Expands]),
            ("macro:callee_b".to_owned(), vec![SightKind::Expands]),
            ("macro:m".to_owned(), vec![SightKind::Expands]),
            ("user".to_owned(), vec![SightKind::Names]),
        ]))
    );
}

#[test]
fn a_file_that_two_declarations_reach_in_different_ways_is_read_for_each() {
    // `x.rs` is a module of its own by `mod x;` (its modules are in `x/`) and the file of `y` by a
    // `#[path]` (its modules are beside it): each reading finds a file of its own.
    let lib = "mod x;\n#[path = \"x.rs\"]\nmod y;\n";
    let files = [
        ("src/x.rs", "mod inner;\n"),
        (
            "src/x/inner.rs",
            "fn from_in_folder() { let _ = Method::AgentTurnCancel; }\n",
        ),
        (
            "src/inner.rs",
            "fn from_beside() { let _ = Method::AgentTurnSteer; }\n",
        ),
    ];
    assert_eq!(
        read_names(lib, &files),
        Ok(vec!["from_beside".to_owned(), "from_in_folder".to_owned()])
    );
}

fn package(name: &str, extra: &str) -> String {
    format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\n{extra}")
}

/// What the scan finds in the crate `krate` of `tree`.
fn names_in(tree: &Tree, krate: &str) -> Result<Vec<String>, String> {
    tree.sightings(&|found| found == krate)
        .map(|sightings| sightings.into_iter().map(|found| found.name).collect())
}

#[test]
fn a_crate_is_read_from_the_targets_cargo_reports_for_it() {
    // A member that no convention names is read; a crate of the repository's `tests/` is not.
    let folder = small_tree("pub fn quiet() {}\n");
    write(
        folder.path(),
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/*\", \"apps/x/native/y\", \"tests/support/z\"]\nresolver = \"2\"\n",
    );
    for (path, name) in [
        ("apps/x/native/y", "companion-y"),
        ("tests/support/z", "kr-z"),
    ] {
        write(
            folder.path(),
            &format!("{path}/Cargo.toml"),
            &package(name, ""),
        );
        write(folder.path(), &format!("{path}/src/lib.rs"), SENDS);
    }
    let tree = tree_at(folder.path()).expect("the tree");
    assert_eq!(tree.krate("companion_y"), Lookup::Found(String::new()));
    assert_eq!(names_in(&tree, "companion_y"), Ok(vec!["sends".to_owned()]));
    assert_eq!(tree.krate("kr_z"), Lookup::Absent);
    // The repository's own tree has the companion's native crates, and its test crates are not read.
    let real = tree_at(&repository()).expect("this checkout");
    for krate in ["companion_platform", "companion_preview", "companion_tauri"] {
        assert_eq!(real.krate(krate), Lookup::Found(String::new()), "{krate}");
    }
    assert_eq!(real.krate("kr_conformance"), Lookup::Absent);
    // A binary that Cargo builds only with a feature is read, and a feature is an unknown name: the
    // item for the feature's absence is read too.
    let folder = small_tree("pub fn quiet() {}\n");
    write(
        folder.path(),
        "crates/kr-sender/Cargo.toml",
        &package(
            "kr-sender",
            "[features]\ntesting = []\n[[bin]]\nname = \"stub\"\npath = \"src/bin/stub.rs\"\nrequired-features = [\"testing\"]\n",
        ),
    );
    write(
        folder.path(),
        "crates/kr-sender/src/bin/stub.rs",
        "#[cfg(not(feature = \"testing\"))]\nfn off() { let _ = Method::AgentTurnCancel; }\n\
         #[cfg(feature = \"testing\")]\nfn on() { let _ = Method::AgentTurnSteer; }\n",
    );
    assert_eq!(
        sender_names(&tree_at(folder.path()).expect("the tree")),
        Ok(vec!["off".to_owned(), "on".to_owned()])
    );
    // A workspace Cargo cannot read is no tree, and the first line of its complaint is the text.
    let folder = small_tree("pub fn quiet() {}\n");
    write(folder.path(), "crates/odd/Cargo.toml", "[workspace]\n");
    let refused = tree_at(folder.path()).err();
    assert!(
        refused.as_ref().is_some_and(|error| error
            .contains(": cargo cannot read the workspace (error: ")
            && error.ends_with(')')),
        "{refused:?}"
    );
}

#[test]
fn a_module_candidate_that_cannot_be_looked_at_is_an_error_and_not_an_absence() {
    use std::os::unix::fs::PermissionsExt as _;
    let folder = small_tree("mod sub;\npub fn quiet() {}\n");
    let shut = folder.path().join("crates/kr-sender/src/sub");
    std::fs::create_dir_all(&shut).expect("a folder");
    std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o0)).expect("permissions");
    let tree = tree_at(folder.path());
    let outcome = tree
        .as_ref()
        .map(|tree| (sender_names(tree), tree.item("kr_sender", "x")));
    std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o755)).expect("permissions");
    let (scan, lookup) = outcome.expect("the tree");
    let root = std::fs::canonicalize(folder.path()).expect("a folder");
    let text = format!(
        "{}: Permission denied (os error 13)",
        root.join("crates/kr-sender/src/sub/mod.rs").display()
    );
    assert_eq!(scan, Err(text.clone()));
    assert_eq!(lookup, Lookup::Failed(text));
}

#[test]
fn a_file_is_read_when_a_declaration_that_reaches_it_is_not_false() {
    // A declaration that is false reaches nothing, and an `include!` in the file it names is no
    // refusal; a declaration that is not false reaches the file whatever its name is.
    let folder = small_tree("#[cfg(test)]\nmod child;\n#[cfg(windows)]\nmod other;\n");
    write(
        folder.path(),
        "crates/kr-sender/src/child.rs",
        "include!(\"x.rs\");\npub fn from_child() { let _ = Method::AgentTurnCancel; }\n",
    );
    write(
        folder.path(),
        "crates/kr-sender/src/other.rs",
        "pub fn from_other() { let _ = Method::AgentTurnSteer; }\n#[cfg(test)]\npub fn tested() {}\n",
    );
    let tree = tree_at(folder.path()).expect("the tree");
    assert_eq!(sender_names(&tree), Ok(vec!["from_other".to_owned()]));
    assert_eq!(tree.item("kr_sender", "from_child"), Lookup::Absent);
    assert_eq!(tree.item("kr_sender", "tested"), Lookup::Absent);
    // Two declarations reach one file and one of them is false: the file is read.
    let lib = "#[cfg(test)]\n#[path = \"shared.rs\"]\nmod as_test;\n\
               #[cfg(unix)]\n#[path = \"shared.rs\"]\nmod as_unix;\n";
    let folder = small_tree(lib);
    write(
        folder.path(),
        "crates/kr-sender/src/shared.rs",
        "pub fn shared() { let _ = Method::AgentTurnCancel; }\n\
         #[cfg(test)]\npub fn tested() { let _ = Method::AgentTurnSteer; }\n",
    );
    let tree = tree_at(folder.path()).expect("the tree");
    assert_eq!(sender_names(&tree), Ok(vec!["shared".to_owned()]));
    assert!(matches!(tree.item("kr_sender", "shared"), Lookup::Found(_)));
    assert_eq!(tree.item("kr_sender", "tested"), Lookup::Absent);
    // A declaration that reaches the file it is in ends the reading.
    let folder = small_tree(&format!(
        "#[cfg(unix)]\n#[path = \"lib.rs\"]\nmod again;\n{SENDS}"
    ));
    assert_eq!(
        sender_names(&tree_at(folder.path()).expect("the tree")),
        Ok(vec!["sends".to_owned()])
    );
}

#[test]
fn a_macro_use_on_an_extern_crate_is_refused_where_a_configuration_without_test_builds_it() {
    let at = "crates/kr-sender/src/lib.rs";
    for lib in [
        "#[macro_use]\nextern crate kr_protocol;",
        "#[cfg_attr(unix, macro_use)]\nextern crate kr_protocol;",
        "#[cfg_attr(unix, cfg_attr(not(test), macro_use))]\nextern crate kr_protocol;",
        "#[macro_use]\nextern crate kr_protocol as proto;",
        "mod inner { #[macro_use] extern crate kr_protocol; }",
    ] {
        assert_eq!(
            read_names(&format!("{lib}\n"), &[]),
            Err(format!(
                "{at}: the scan does not read #[macro_use] on extern crate"
            )),
            "{lib}"
        );
    }
    for lib in [
        "extern crate kr_protocol;",
        "#[cfg(test)]\n#[macro_use]\nextern crate kr_protocol;",
        "#[cfg_attr(test, macro_use)]\nextern crate kr_protocol;",
        "#[cfg_attr(unix, cfg_attr(test, macro_use))]\nextern crate kr_protocol;",
        "#[allow(unused)]\nextern crate kr_protocol;",
    ] {
        assert_eq!(
            read_names(&format!("{lib}\n"), &[]),
            Ok(Vec::<String>::new()),
            "{lib}"
        );
    }
}

#[test]
fn a_raw_identifier_is_the_name_it_stands_for_in_every_rule_that_reads_a_name() {
    let at = "crates/kr-sender/src/lib.rs";
    // R1: a rename of a name the scan reads, written raw on either side.
    for import in [
        "use kr_protocol::r#MutationRequest as Request;",
        "use kr_protocol::MutationRequest as r#Request;",
        "use kr_protocol::r#Method as M;",
        "extern crate r#kr_protocol as r#Method;",
    ] {
        let (scan, _) = scanned(&format!("{import}\n"), &[]);
        assert!(
            matches!(&scan, Err(text) if text.starts_with(&format!("{at}: the scan does not read "))
                && text.contains(" under another name (as ")),
            "{import}: {scan:?}"
        );
    }
    // R2: a type alias of either type, written raw.
    assert_eq!(
        read_names("type Request = r#MutationRequest;\n", &[]),
        Err(format!(
            "{at}: the scan does not read a type alias of MutationRequest (Request)"
        ))
    );
    assert_eq!(
        read_names("type r#Request = kr_protocol::r#ActionTarget;\n", &[]),
        Err(format!(
            "{at}: the scan does not read a type alias of ActionTarget (Request)"
        ))
    );
    // R2: a type in parentheses is the same type.
    for alias in [
        "type Request = (MutationRequest);",
        "type Request = ((kr_protocol::ActionTarget));",
    ] {
        let (scan, _) = scanned(&format!("{alias}\n"), &[]);
        assert!(
            matches!(&scan, Err(text) if text.starts_with(&format!("{at}: the scan does not read a type alias of "))),
            "{alias}: {scan:?}"
        );
    }
    // X4 and the form checks: `include!` and `macro_rules!` written raw are the same macros.
    for lib in [
        "fn f() { r#include!(\"x.rs\"); }",
        "macro_rules! m { () => { r#include!(\"x.rs\"); }; }",
    ] {
        let (scan, _) = scanned(&format!("{lib}\n"), &[]);
        assert_eq!(
            scan,
            Err(format!("{at}: the scan does not read include!")),
            "{lib}"
        );
    }
    let (scan, _) = scanned("m!{ macro_rules! r#inner { () => {}; } }\n", &[]);
    assert!(
        matches!(&scan, Err(text) if text.contains("macro_rules! inner in the tokens of m!")),
        "{scan:?}"
    );
    // R3: a raw call of a macro the crate defines is the crate's own.
    assert_eq!(
        read_names(
            "macro_rules! mine { () => {}; }\nr#mine!();\nmod x { r#mine!(); }\n",
            &[]
        ),
        Ok(Vec::<String>::new())
    );
}

#[test]
fn a_place_no_configuration_without_test_builds_is_not_read_by_the_inventory_at_any_depth() {
    let at = "crates/kr-sender/src/lib.rs";
    // The children of a disabled impl, enum, variant or field raise no refusal.
    for lib in [
        "#[cfg(test)]\nimpl S { foreign::generate!(); }",
        "#[cfg(test)]\nenum E { A([u8; include!(\"n.rs\")]) }",
        "enum E { #[cfg(test)] A([u8; include!(\"n.rs\")]), B }",
        "struct S { #[cfg(test)] f: [u8; include!(\"n.rs\")] }",
        "#[cfg(test)]\nimpl S { type A = kr_protocol::MutationRequest; }",
        "enum E { #[cfg(test)] A = include!(\"n.rs\"), B }",
    ] {
        assert_eq!(
            read_names(&format!("{lib}\n"), &[]),
            Ok(Vec::<String>::new()),
            "{lib}"
        );
    }
    // The same places, enabled, are refused.
    for (lib, text) in [
        (
            "impl S { foreign::generate!(); }",
            "generate! is called at item position",
        ),
        (
            "enum E { A([u8; include!(\"n.rs\")]) }",
            "the scan does not read include!",
        ),
        (
            "enum E { #[cfg(unix)] A([u8; include!(\"n.rs\")]) }",
            "the scan does not read include!",
        ),
        (
            "struct S { f: [u8; include!(\"n.rs\")] }",
            "the scan does not read include!",
        ),
    ] {
        let (scan, _) = scanned(&format!("{lib}\n"), &[]);
        assert!(
            matches!(&scan, Err(error) if error.starts_with(&format!("{at}: ")) && error.contains(text)),
            "{lib}: {scan:?}"
        );
    }
}

#[test]
fn a_definition_named_action_right_is_refused_in_a_crate_the_scan_reads_where_a_build_without_test_has_it()
 {
    let at = "crates/kr-sender/src/lib.rs";
    for (lib, kind) in [
        (
            "type ActionRight = kr_protocol::method::Method;",
            "type alias",
        ),
        (
            "mod ActionRight { pub use kr_protocol::method::Method::*; }",
            "module",
        ),
        ("enum ActionRight { A }", "enum"),
        ("struct ActionRight;", "struct"),
        ("union ActionRight { a: u8 }", "union"),
        ("trait ActionRight {}", "trait"),
        ("type r#ActionRight = u8;", "type alias"),
    ] {
        assert_eq!(
            read_names(&format!("{lib}\n"), &[]),
            Err(format!(
                "{at}: the scan does not read a {kind} named ActionRight"
            )),
            "{lib}"
        );
    }
    for lib in [
        "#[cfg(test)]\nenum ActionRight { A }",
        "use kr_protocol::rights::ActionRight;",
        "fn f() { let _ = ActionRight::AgentTurnCancel; }",
        "enum Other { ActionRight }",
        "struct S { ActionRight: u8 }",
    ] {
        assert!(read_names(&format!("{lib}\n"), &[]).is_ok(), "{lib}");
    }
}
