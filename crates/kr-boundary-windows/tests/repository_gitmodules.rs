//! The classifier of a `.gitmodules` listing: the framing and the bounds of a configuration
//! listing and a table of four keys.

use kr_boundary_windows::frame::invocation::RefusedKind;
use kr_boundary_windows::repository::config::{
    Limits, RULE_LISTING_TOO_LARGE, RULE_RECORD_KEY, RULE_RECORD_TOO_LARGE,
    RULE_SUBSECTION_TOO_LARGE, RULE_TOO_MANY_RECORDS, RULE_TRUNCATED, RULE_UNLISTED,
    RULE_URL_HELPER, RULE_VALUE, classify_gitmodules,
};

type Record<'a> = (&'a str, Option<&'a str>);

fn listing(records: &[Record]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (key, value) in records {
        bytes.extend_from_slice(key.as_bytes());
        if let Some(value) = value {
            bytes.push(b'\n');
            bytes.extend_from_slice(value.as_bytes());
        }
        bytes.push(0);
    }
    bytes
}

fn admitted(records: &[Record]) {
    classify_gitmodules(&listing(records), &Limits::default())
        .unwrap_or_else(|refusal| panic!("{records:?}: {refusal}"));
}

fn rule(records: &[Record]) -> &'static str {
    rule_of(&listing(records), &Limits::default())
}

fn rule_of(bytes: &[u8], limits: &Limits) -> &'static str {
    let refusal = classify_gitmodules(bytes, limits).expect_err("a refusal");
    assert_eq!(refusal.kind, RefusedKind::Configuration, "{refusal}");
    refusal.rule
}

#[test]
fn an_empty_listing_and_a_listing_of_all_four_keys_are_admitted() {
    assert!(classify_gitmodules(b"", &Limits::default()).is_ok());
    admitted(&[
        ("submodule.vendor.path", Some("vendor/lib")),
        ("submodule.vendor.url", Some("https://example.com/lib.git")),
        ("submodule.vendor.branch", Some("release/1.0")),
        ("submodule.vendor.ignore", Some("dirty")),
    ]);
    // Each key alone, for several submodules, in any case of the section and the variable.
    admitted(&[
        ("submodule.a.path", Some("a")),
        ("submodule.b.url", Some("../b.git")),
        ("Submodule.c.BRANCH", Some("main")),
        ("SUBMODULE.d.Ignore", Some("none")),
    ]);
    // The name of a submodule is text: dots, slashes and spaces are part of it.
    admitted(&[
        ("submodule.a.b.path", Some("a")),
        (
            "submodule.dir/sub module.url",
            Some("https://example.com/x.git"),
        ),
    ]);
}

#[test]
fn each_value_of_ignore_is_admitted_and_no_other() {
    for value in ["none", "untracked", "dirty", "all"] {
        admitted(&[("submodule.a.ignore", Some(value))]);
    }
    for value in ["", "some", "alls", "dirt", "true", "1", "untracked dirty"] {
        assert_eq!(
            rule(&[("submodule.a.ignore", Some(value))]),
            RULE_VALUE,
            "{value:?}"
        );
    }
}

#[test]
fn an_address_is_text_that_names_no_transport_helper() {
    for url in [
        "https://example.com/a.git",
        "ssh://git@example.com/a.git",
        "git@example.com:org/a.git",
        "../sibling.git",
        "./a",
        "C:\\repos\\a",
        "C:/repos/a",
        "/srv/git/a.git",
        "file:///srv/git/a.git",
    ] {
        admitted(&[("submodule.a.url", Some(url))]);
    }
    for url in [
        "ext::sh -c x",
        "x::y",
        "fd::17",
        "a+b.c::d",
        "::x",
        "http::https://a/b",
    ] {
        assert_eq!(
            rule(&[("submodule.a.url", Some(url))]),
            RULE_URL_HELPER,
            "{url:?}"
        );
    }
    for url in ["https://a\u{1}b", "https://a\nb", "a\u{7f}"] {
        assert_eq!(
            rule(&[("submodule.a.url", Some(url))]),
            RULE_VALUE,
            "{url:?}"
        );
    }
}

#[test]
fn a_path_is_a_path_of_the_tree() {
    for path in ["lib", "vendor/lib", "a b/c", "x.y", "a[1]"] {
        admitted(&[("submodule.a.path", Some(path))]);
    }
    for path in [
        "",
        "/abs",
        "a/",
        "a//b",
        "a\\b",
        "../x",
        "a/../b",
        "C:x",
        "a:b",
        "a/.git",
        ".git",
        "git~1",
        "con",
        "a/nul.txt",
        "a.",
        "a ",
        "a*",
        "a\u{1}b",
    ] {
        assert_eq!(
            rule(&[("submodule.a.path", Some(path))]),
            RULE_VALUE,
            "{path:?}"
        );
    }
    let long = "d/".repeat(120) + "x";
    assert_eq!(long.len(), 241);
    assert_eq!(rule(&[("submodule.a.path", Some(&long))]), RULE_VALUE);
    let deep = vec!["d"; 33].join("/");
    assert_eq!(rule(&[("submodule.a.path", Some(&deep))]), RULE_VALUE);
    admitted(&[("submodule.a.path", Some(&vec!["d"; 32].join("/")))]);
}

#[test]
fn a_branch_is_a_branch_name() {
    for branch in ["main", "release/1.0", "a-b_c", "0"] {
        admitted(&[("submodule.a.branch", Some(branch))]);
    }
    for branch in [
        "",
        ".",
        "a..b",
        "-x",
        "a b",
        "a.lock",
        "a/",
        "/a",
        "a@{1}",
        "refs/heads/a:b",
    ] {
        assert_eq!(
            rule(&[("submodule.a.branch", Some(branch))]),
            RULE_VALUE,
            "{branch:?}"
        );
    }
}

#[test]
fn a_key_with_no_value_is_refused_for_each_of_the_four() {
    for key in [
        "submodule.a.path",
        "submodule.a.url",
        "submodule.a.branch",
        "submodule.a.ignore",
    ] {
        assert_eq!(rule(&[(key, None)]), RULE_VALUE, "{key}");
    }
}

#[test]
fn every_other_key_refuses_the_repository_by_name() {
    for key in [
        "submodule.a.update",
        "submodule.a.fetchRecurseSubmodules",
        "submodule.a.shallow",
        "submodule.a.active",
        "submodule.a.recurse",
        "submodule.a.unknown",
        "submodule.a.pathx",
        "submodule.a.URLS",
        "submodule.path",
        "submodule.url",
        "submodule.recurse",
        "core.symlinks",
        "core.bare",
        "include.path",
        "includeIf.gitdir:x.path",
        "url.https://x/.insteadOf",
        "remote.origin.url",
        "branch.main.remote",
        "filter.lfs.clean",
        "user.name",
        "diff.x.textconv",
    ] {
        let refusal =
            classify_gitmodules(&listing(&[(key, Some("x"))]), &Limits::default()).unwrap_err();
        assert_eq!(refusal.kind, RefusedKind::Configuration, "{key}");
        assert_eq!(refusal.rule, RULE_UNLISTED, "{key}");
        // The refusal names the key, and says nothing of the value.
        assert!(refusal.detail().starts_with(key), "{}", refusal.detail());
    }
    // A listing of good keys is refused for one other key, wherever it stands.
    let good = ("submodule.a.path", Some("a"));
    let other = ("submodule.a.update", Some("checkout"));
    assert_eq!(rule(&[other, good]), RULE_UNLISTED);
    assert_eq!(rule(&[good, other]), RULE_UNLISTED);
    assert_eq!(rule(&[good, other, good]), RULE_UNLISTED);
}

#[test]
fn a_refusal_never_repeats_a_value() {
    for records in [
        [("submodule.a.url", Some("ext::SECRET-VALUE"))],
        [("submodule.a.path", Some("SECRET-VALUE:"))],
        [("submodule.a.ignore", Some("SECRET-VALUE"))],
        [("submodule.a.update", Some("SECRET-VALUE"))],
    ] {
        let refusal = classify_gitmodules(&listing(&records), &Limits::default()).unwrap_err();
        assert!(
            !refusal.detail().contains("SECRET-VALUE"),
            "{}",
            refusal.detail()
        );
        assert!(refusal.detail().is_ascii());
    }
}

#[test]
fn the_framing_is_the_one_of_a_configuration_listing() {
    let one = listing(&[("submodule.a.path", Some("a"))]);
    let mut cut = one.clone();
    cut.pop();
    assert_eq!(rule_of(&cut, &Limits::default()), RULE_TRUNCATED);
    assert_eq!(rule_of(b"\0", &Limits::default()), RULE_RECORD_KEY);
    assert_eq!(rule_of(b"nokey\0", &Limits::default()), RULE_RECORD_KEY);
    assert_eq!(
        rule_of(b"submodule.path\0", &Limits::default()),
        RULE_UNLISTED
    );
    assert_eq!(
        rule_of(b"\xff.a.path\nx\0", &Limits::default()),
        RULE_RECORD_KEY
    );
    assert_eq!(
        rule_of(b"submodule.a.path\x01\nx\0", &Limits::default()),
        RULE_RECORD_KEY
    );
    assert_eq!(
        rule_of(b"submodule..path\nx\0", &Limits::default()),
        RULE_RECORD_KEY
    );
    // A value that holds a newline is one value, split at the first.
    assert_eq!(
        rule_of(b"submodule.a.path\nx\ny\0", &Limits::default()),
        RULE_VALUE
    );
}

#[test]
fn the_bounds_are_the_limits_and_are_checked_before_any_key() {
    let default = Limits::default();
    assert_eq!(
        (
            default.listing_bytes,
            default.records,
            default.record_bytes,
            default.subsection_bytes
        ),
        (1_048_576, 4096, 8192, 256)
    );
    // The records: 4,096 are the limit and the next is over it, though the key is not admitted.
    let record = listing(&[("submodule.a.ignore", Some("all"))]);
    let at = record.repeat(4096);
    assert!(classify_gitmodules(&at, &default).is_ok());
    let over = record.repeat(4097);
    assert_eq!(rule_of(&over, &default), RULE_TOO_MANY_RECORDS);
    let bad = listing(&[("core.bare", Some("true"))]).repeat(4097);
    assert_eq!(rule_of(&bad, &default), RULE_TOO_MANY_RECORDS);
    // The bytes of the listing.
    let tight = Limits {
        listing_bytes: record.len(),
        ..default
    };
    assert!(classify_gitmodules(&record, &tight).is_ok());
    assert_eq!(rule_of(&record.repeat(2), &tight), RULE_LISTING_TOO_LARGE);
    assert_eq!(
        rule_of(&vec![b'x'; 1_048_577], &default),
        RULE_LISTING_TOO_LARGE
    );
    // One record: 8,192 bytes is the limit.
    let url = |len: usize| {
        let key = "submodule.a.url\n";
        listing(&[(key.trim_end(), Some(&"u".repeat(len - key.len())))])
    };
    let at = url(8192);
    assert_eq!(at.len(), 8193);
    assert!(classify_gitmodules(&at, &default).is_ok());
    assert_eq!(rule_of(&url(8193), &default), RULE_RECORD_TOO_LARGE);
    // The name of a submodule: 256 bytes are the limit.
    let name = |len: usize| format!("submodule.{}.path", "n".repeat(len));
    admitted(&[(name(256).as_str(), Some("a"))]);
    assert_eq!(
        rule(&[(name(257).as_str(), Some("a"))]),
        RULE_SUBSECTION_TOO_LARGE
    );
}
