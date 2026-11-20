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
        ("#[cfg(any(all(unix, not(target_os = \"macos\")), test))]", true),
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
        ("#[cfg_attr(not(debug_assertions), windows_subsystem = \"windows\")]", true),
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
            "{at}: thing! is called at item position, is not defined in kr_sender and is not one the scan accepts"
        ),
    );
    // A `use` of the variants by glob, or of `Method` under another name.
    for import in [
        "use kr_protocol::Method::*;",
        "use kr_protocol::Method as M;",
        "use kr_protocol::Method::{self as M};",
        "fn f() { use kr_protocol::Method::*; }",
        // An alias of `Method`, and a variant named through `Self` in an impl for `Method`.
        "type M = Method;",
        "type M = kr_protocol::Method;",
        "impl Local for Method { fn f() { let _ = Self::AgentTurnCancel; } }",
        "impl Local for kr_protocol::Method { fn f() { match 1 { _ => Self::PluginActionInvoke }; } }",
        // A variant named through the type in angle brackets.
        "fn f() { let _ = <Method>::AgentTurnCancel; }",
        "fn f() { match 1 { _ => <kr_protocol::Method>::PluginActionInvoke }; }",
    ] {
        let (scan, _) = scanned(&format!("{import}\n"), &[]);
        assert_eq!(
            scan,
            Err(format!(
                "{at}: a use of Method::* or of Method under another name; the scan reads Method::<Variant> only"
            )),
            "{import}"
        );
    }
    // `Self::<name>` in an impl for another type or for `Method` with a name that is no variant, and
    // an alias of another type, are not those forms.
    for lib in [
        "impl Local for Method { fn f() { let _ = Self::Unrelated; } }",
        "impl Local for Other { fn f() { let _ = Self::AgentTurnCancel; } }",
        "type M = Other;",
        "fn f() { let _ = <Other>::AgentTurnCancel; }",
        "fn f() { let _ = <Method as std::str::FromStr>::from_str; }",
    ] {
        assert_eq!(
            read_names(&format!("{lib}\n"), &[]),
            Ok(Vec::<String>::new()),
            "{lib}"
        );
    }
    // An enum named `Method` in a crate that is not the protocol's is no exemption, and the protocol
    // crate, which defines `Method` and names its own variants, is not read as a sender.
    let definition = "pub enum Method { AgentTurnCancel }\nuse Method::*;\ntype M = Method;\nimpl Method { fn f() -> Self { Self::AgentTurnCancel } }\n";
    assert_eq!(
        read_names(&format!("mod local {{ {definition} }}\n"), &[]),
        Err(format!(
            "{at}: a use of Method::* or of Method under another name; the scan reads Method::<Variant> only"
        ))
    );
    let folder = small_tree("pub fn quiet() {}\n");
    write(folder.path(), "crates/kr-protocol/src/lib.rs", definition);
    let tree = tree_at(folder.path()).expect("the tree");
    assert_eq!(
        tree.sightings(&|krate| krate == "kr_protocol")
            .map(|found| found.len()),
        Ok(0)
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
    let folder = small_tree("#[cfg(all(test, unix))]\nmod only_by_test;\n#[cfg(unix)]\nmod by_unix;\n");
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
    let tree = tree_at(&inner).expect("the tree");
    assert_eq!(
        sender_names(&tree),
        Err(format!(
            "{0}: the scan does not read a path through a link or outside the checkout (it is {0})",
            escaped.display()
        ))
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
            "crates/kr-sender/src/lib.rs: the scan does not read a path through a link or outside the checkout ({} is a link)",
            root.join("crates/kr-sender/src").join(link).display()
        )
    };
    let folder = prepare("link/../chosen.rs");
    let tree = tree_at(folder.path()).expect("the tree");
    let text = refused(folder.path(), "link");
    assert_eq!(sender_names(&tree), Err(text.clone()));
    assert_eq!(tree.item("kr_sender", "lexical"), Lookup::Failed(text));
    // The same file by the cancelled path and by the file system is refused all the same.
    let folder = prepare("sibling/../chosen.rs");
    assert_eq!(
        sender_names(&tree_at(folder.path()).expect("the tree")),
        Err(refused(folder.path(), "sibling"))
    );
    // A file that is a link, and a link at the end of the path.
    let folder = prepare("chosen.rs");
    let source = folder.path().join("crates/kr-sender/src");
    std::fs::rename(source.join("chosen.rs"), source.join("real.rs")).expect("a rename");
    std::os::unix::fs::symlink(source.join("real.rs"), source.join("chosen.rs")).expect("a link");
    assert_eq!(
        sender_names(&tree_at(folder.path()).expect("the tree")),
        Err(refused(folder.path(), "chosen.rs"))
    );
    // The same step up after a folder that is no link is read as the cancelled path.
    let folder = prepare("deep/../chosen.rs");
    assert_eq!(
        sender_names(&tree_at(folder.path()).expect("the tree")),
        Ok(vec!["lexical".to_owned()])
    );
    // After a folder that is not there it finds no file, as rustc finds none.
    let folder = prepare("gone/../chosen.rs");
    let root = std::fs::canonicalize(folder.path()).expect("a path");
    assert_eq!(
        sender_names(&tree_at(folder.path()).expect("the tree")),
        Err(
            "crates/kr-sender/src/lib.rs: mod chosen is at no file the scan can find (tried crates/kr-sender/src/gone/../chosen.rs)"
                .to_owned()
        ),
        "{}",
        root.display()
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
            format!("use kr_protocol::Method::*;\n{existing}"),
            "crates/kr-sender/src/lib.rs: a use of Method::* or of Method under another name; the scan reads Method::<Variant> only",
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
    // A call with a sighting to a macro that another crate exports: refused where that crate is in
    // the tree's scope, read where it is not.
    let folder = small_tree(&format!(
        "fn f() {{ shared!(Method::AgentTurnCancel); }}\n{existing}"
    ));
    write(
        folder.path(),
        "crates/kr-worker/src/lib.rs",
        "#[macro_export]\nmacro_rules! shared { ($m:expr) => { $m }; }\n",
    );
    let text = "kr_sender: shared! is called with a sighting and kr_worker exports it; the scan does not follow it across crates";
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
    // by a `use` line that gives the name (with a rename).
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
        "use wasmtime::component;\ncomponent::bindgen!({ path: \"x.wit\" });",
        "use kr_client::{debug_fields as shown};\nshown!(E { a });",
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
}

#[test]
fn an_item_position_macro_of_another_crate_that_nothing_accepts_is_refused() {
    let text = |name: &str| {
        format!(
            "crates/kr-sender/src/lib.rs: {name}! is called at item position, is not defined in kr_sender and is not one the scan accepts"
        )
    };
    for (lib, name) in [
        ("tokio::unlisted! { static X: u8 = 0; }", "unlisted"),
        // A family name from a provider that is not its own, bare where it has no bare form, and
        // through an import that names another provider or a glob.
        ("foreign::bindgen!({});", "bindgen"),
        ("tokio::bindgen!({});", "bindgen"),
        ("bindgen!({});", "bindgen"),
        ("task_local! { static X: u8; }", "task_local"),
        ("std::task_local! { static X: u8; }", "task_local"),
        (
            "foreign::thread_local! { static X: u8 = 0; }",
            "thread_local",
        ),
        ("json_schema!({});", "json_schema"),
        ("use schemars::*;\njson_schema!({});", "json_schema"),
        (
            "use foreign::json_schema;\njson_schema!({});",
            "json_schema",
        ),
        ("kr_worker::debug_fields!(E { a });", "debug_fields"),
        // The crate's own prefix, or one of its modules, names a macro the crate defines, and not
        // one that a `use` or a re-export brought in from elsewhere.
        (
            "use foreign::generate as new_items;\ncrate::new_items!();\n",
            "new_items",
        ),
        (
            "use foreign::generate;\ncrate::generate!();\n",
            "generate",
        ),
        ("mod bridge { pub use foreign::*; }\nbridge::generate!();\n", "generate"),
        ("macro_rules! m { () => { crate::generate!(); }; }\nm!();\n", "generate"),
        // A macro of the crate's own name behind another crate's path is that crate's macro.
        (
            "macro_rules! mine { () => {}; }\nforeign::mine! {}\n",
            "mine",
        ),
        // The transcribers of a definition, at any depth.
        (
            "macro_rules! m { () => { other::generate!(); }; }\nm!();\n",
            "generate",
        ),
        (
            "macro_rules! m { () => { generate!(); }; }\nm!();\n",
            "generate",
        ),
        (
            "macro_rules! m { () => { vec![other::generate!()]; }; }\n",
            "generate",
        ),
        (
            "fn f() { macro_rules! local { () => { other::generate!(); }; } }\n",
            "generate",
        ),
    ] {
        let (scan, lookup) = scanned(lib, &[]);
        assert_eq!(scan, Err(text(name)), "{lib}");
        assert_eq!(lookup, Lookup::Failed(text(name)), "{lib}");
    }
    // A name that one file imports from the accepted provider and another from a different one is
    // refused: the call is read as each of them.
    let (scan, _) = scanned(
        "mod a;\nmod b;\n",
        &[
            (
                "src/a.rs",
                "use schemars::json_schema;\njson_schema!({});\n",
            ),
            ("src/b.rs", "use foreign::json_schema;\n"),
        ],
    );
    assert_eq!(
        scan,
        Err("crates/kr-sender/src/a.rs: json_schema! is called at item position, is not defined in kr_sender and is not one the scan accepts".to_owned())
    );
}

#[test]
fn a_macro_called_through_a_metavariable_or_exported_to_a_crate_the_scan_reads_is_refused() {
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
    // A call with a sighting to a macro another crate of the scan exports.
    let folder = small_tree("fn f() { shared!(Method::AgentTurnCancel); }\n");
    write(
        folder.path(),
        "crates/kr-worker/src/lib.rs",
        "#[macro_export]\nmacro_rules! shared { ($m:expr) => { $m }; }\n",
    );
    let tree = tree_at(folder.path()).expect("the tree");
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
        "fn f() { let _ = Method::AgentTurnSteer; shared!(1); }\n",
    );
    let tree = tree_at(folder.path()).expect("the tree");
    assert_eq!(tree.sightings(&|_| true).map(|found| found.len()), Ok(1));
    // The refusal over the crates, for a macro the other crate exports under `name`.
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
    let refused = |name: &str| {
        Err(format!(
            "kr_sender: {name}! is called with a sighting and kr_worker exports it; the scan does not follow it across crates"
        ))
    };
    // A call reached only through the transcribers of a macro that is expanded: `fwd` is called
    // with the sighting, and what it calls is the other crate's.
    let lib = "use schemars::json_schema;\nmacro_rules! fwd { ($x:expr) => { json_schema!($x) }; }\nfn f() { fwd!(Method::AgentTurnCancel); }\n";
    assert_eq!(across(lib, "json_schema"), refused("json_schema"));
    // The same macro that nothing calls with a sighting is not followed.
    let lib = "use schemars::json_schema;\nmacro_rules! fwd { ($x:expr) => { json_schema!($x) }; }\nfn f() { fwd!(1); let _ = Method::AgentTurnSteer; }\n";
    assert_eq!(across(lib, "json_schema"), Ok(1));
    // A path of the other crate names its macro whatever this crate defines under the same name;
    // a bare call is this crate's own.
    let lib = "macro_rules! shared { ($m:expr) => { $m }; }\nfn f() { kr_worker::shared!(Method::AgentTurnCancel); }\n";
    assert_eq!(across(lib, "shared"), refused("shared"));
    let lib = "macro_rules! shared { ($m:expr) => { $m }; }\nfn f() { shared!(Method::AgentTurnCancel); }\n";
    assert_eq!(across(lib, "shared"), Ok(2));
    let lib = "macro_rules! shared { ($m:expr) => { $m }; }\nfn f() { crate::shared!(Method::AgentTurnCancel); }\n";
    assert_eq!(across(lib, "shared"), Ok(2));
    // A transcriber that calls the other crate's macro by a path, where this crate defines one of the
    // same name: what an expanded macro calls through a path is the other crate's.
    let lib = "macro_rules! json_schema { ($m:expr) => { $m }; }\nmacro_rules! fwd { ($x:expr) => { schemars::json_schema!($x) }; }\nfn f() { fwd!(Method::AgentTurnCancel); }\n";
    assert_eq!(across(lib, "json_schema"), refused("json_schema"));
    // A call through the name a `use` gives the other crate's macro, in a call and in a transcriber.
    let renamed = Err(
        "kr_sender: shared! is called with a sighting (imported as renamed) and kr_worker exports it; the scan does not follow it across crates"
            .to_owned(),
    );
    let lib = "use kr_worker::shared as renamed;\nfn f() { renamed!(Method::AgentTurnCancel); }\n";
    assert_eq!(across(lib, "shared"), renamed);
    // The same name in a transcriber is a call of another crate's macro that nothing accepts.
    let lib = "use kr_worker::shared as renamed;\nmacro_rules! fwd { ($x:expr) => { renamed!($x) }; }\nfn f() { fwd!(Method::AgentTurnCancel); }\n";
    assert_eq!(
        across(lib, "shared"),
        Err("crates/kr-sender/src/lib.rs: renamed! is called at item position, is not defined in kr_sender and is not one the scan accepts".to_owned())
    );
    // A name that is no rename of the other crate's macro is not that macro.
    let lib = "use kr_worker::other as renamed;\nfn f() { renamed!(Method::AgentTurnCancel); }\n";
    assert_eq!(across(lib, "shared"), Ok(1));
    // A call at item position by a path, with a sighting in its arguments.
    let lib = "schemars::json_schema!({ \"x\": \"agent.turn.cancel\" });\nmacro_rules! json_schema { ($m:expr) => { $m }; }\n";
    assert_eq!(across(lib, "json_schema"), refused("json_schema"));
    // The same call whose arguments begin with a name, which the scan takes for the item it defines:
    // the call is then the one place that tells the scan the macro is the other crate's.
    let lib = "schemars::json_schema!(Holder { \"x\": \"agent.turn.cancel\" });\nmacro_rules! json_schema { ($m:expr) => { $m }; }\n";
    assert_eq!(across(lib, "json_schema"), refused("json_schema"));
}

#[test]
fn a_macro_defined_in_a_function_body_is_a_macro_of_its_own() {
    use SightKind::{Expands, Names};
    let folder = small_tree(
        "fn f() {\n    macro_rules! inner { ($m:expr) => { $m }; }\n    inner!(Method::AgentTurnCancel);\n}\nfn g() {\n    macro_rules! holds { () => { Method::AgentTurnSteer }; }\n    #[cfg(test)]\n    macro_rules! gone { () => {}; }\n}\n",
    );
    let tree = tree_at(folder.path()).expect("the tree");
    let found = tree
        .sightings(&|krate| krate == "kr_sender")
        .map(|found| super::walker_cases::names(&found, "kr_sender"));
    assert_eq!(
        found,
        Ok(BTreeMap::from([
            ("f".to_owned(), vec![Names]),
            ("g".to_owned(), vec![Names]),
            ("macro:holds".to_owned(), vec![Names]),
            ("macro:inner".to_owned(), vec![Expands]),
        ]))
    );
    // Its rules are an item, whose source holds the definition; one that no build holds is not.
    let held = tree
        .source("kr_sender", "macro:inner")
        .is_ok_and(|found| found.is_some_and(|source| source.text.contains("macro_rules")));
    assert!(held, "the source of macro:inner holds its definition");
    assert!(matches!(
        tree.item("kr_sender", "macro:inner"),
        Lookup::Found(_)
    ));
    assert_eq!(tree.item("kr_sender", "macro:gone"), Lookup::Absent);
}

#[test]
fn a_cfg_attr_that_adds_macro_export_counts_where_the_predicate_is_not_false() {
    // The other crate exports `shared` where the attribute is written, or a `cfg_attr` that is not
    // false adds it, and a call with a sighting to a macro it exports is refused.
    let call = |attribute: &str| {
        let folder = small_tree("fn f() { shared!(Method::AgentTurnCancel); }\n");
        write(
            folder.path(),
            "crates/kr-worker/src/lib.rs",
            &format!("{attribute}\nmacro_rules! shared {{ ($m:expr) => {{ $m }}; }}\n"),
        );
        let tree = tree_at(folder.path()).expect("the tree");
        tree.sightings(&|_| true).map(|found| found.len())
    };
    let refused = Err(
        "kr_sender: shared! is called with a sighting and kr_worker exports it; the scan does not follow it across crates"
            .to_owned(),
    );
    for attribute in [
        "#[macro_export]",
        "#[cfg_attr(unix, macro_export)]",
        "#[cfg_attr(not(test), macro_export)]",
        "#[cfg_attr(unix, cfg_attr(not(test), macro_export))]",
        "#[cfg_attr(windows, cfg_attr(unix, macro_export))]",
        "#[cfg_attr(some_atom, macro_export)]",
    ] {
        assert_eq!(call(attribute), refused, "{attribute}");
    }
    for attribute in [
        "",
        "#[cfg_attr(test, macro_export)]",
        "#[cfg_attr(all(unix, test), macro_export)]",
        "#[cfg_attr(unix, cfg_attr(test, macro_export))]",
        "#[cfg_attr(unix, allow(unused))]",
    ] {
        assert_eq!(call(attribute), Ok(1), "{attribute}");
    }
    // A predicate the rule cannot read is its error.
    assert_eq!(
        call("#[cfg_attr(not(unix, windows), macro_export)]"),
        Err("crates/kr-worker/src/lib.rs: the scan cannot read the condition not (unix , windows)".to_owned())
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
    let lib = format!(
        "{callees}macro_rules! m {{ () => {{ callee_a!() }}; }}\nmod child;\n{user}"
    );
    let child = [("src/child.rs", "macro_rules! m { () => { callee_b!() }; }\n")];
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
