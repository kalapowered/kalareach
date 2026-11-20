//! The cases of the condition rule and of the module inventory.

use super::condition::Condition;
use super::walker::{Lookup, Tree};
use super::walker_cases::small_tree;

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
        // Several attributes are one conjunction.
        ("#[cfg(unix)] #[cfg(windows)]", false),
        ("#[cfg(unix)] #[cfg(not(target_os = \"linux\"))]", true),
        (
            "#[cfg_attr(not(debug_assertions), windows_subsystem = \"windows\")]",
            true,
        ),
        ("#[cfg_attr(test, derive(Debug))]", true),
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
