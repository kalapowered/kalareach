//! The configuration classifier against listings of `git config --list --null`: the listings that
//! Git writes, and the ones a hostile repository could make it write.
//!
//! Three golden listings are written by hand from Git's documented defaults for Windows and for the
//! values the table admits (`written-by-hand-*`); one is a recording of `git init` made with
//! Apple's Git 2.50.1 on macOS (`macos-git-2.50.1-init.listing`). A recording of `init` and `clone`
//! on the Git that Windows hosts use is still to be added.

use kr_boundary_windows::frame::invocation::RefusedKind;
use kr_boundary_windows::repository::config::{
    AutoCrlf, ConfigFacts, Limits, ObjectFormat, RULE_BARE, RULE_EXTENSION, RULE_INCLUDE,
    RULE_LISTING_TOO_LARGE, RULE_LOCATION, RULE_PROGRAM, RULE_RECORD_KEY, RULE_RECORD_TOO_LARGE,
    RULE_SUBSECTION_TOO_LARGE, RULE_SYMLINKS, RULE_TOO_MANY_RECORDS, RULE_TRANSPORT,
    RULE_TRUNCATED, RULE_UNLISTED, RULE_URL_HELPER, RULE_VALUE, RULE_WORKTREE_CONFIG,
    classify_config,
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

fn classify(records: &[Record]) -> Result<ConfigFacts, kr_boundary_windows::refusal::Refusal> {
    classify_config(&listing(records), &Limits::default())
}

fn facts(records: &[Record]) -> ConfigFacts {
    classify(records).unwrap_or_else(|refusal| panic!("{records:?}: {refusal}"))
}

fn rule(records: &[Record]) -> &'static str {
    let refusal = classify(records).expect_err(&format!("{records:?}"));
    assert_eq!(refusal.kind, RefusedKind::Configuration, "{refusal}");
    refusal.rule
}

fn rule_of_bytes(bytes: &[u8]) -> &'static str {
    let refusal = classify_config(bytes, &Limits::default()).expect_err("a refusal");
    assert_eq!(refusal.kind, RefusedKind::Configuration, "{refusal}");
    refusal.rule
}

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/config/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn the_limits_are_the_bounds_of_the_reader() {
    let limits = Limits::default();
    assert_eq!(limits.listing_bytes, 1_048_576);
    assert_eq!(limits.records, 4096);
    assert_eq!(limits.record_bytes, 8192);
    assert_eq!(limits.subsection_bytes, 256);
}

#[test]
fn golden_listings_are_admitted_with_the_facts_they_hold() {
    let limits = Limits::default();
    let recorded = classify_config(&fixture("macos-git-2.50.1-init.listing"), &limits).unwrap();
    assert_eq!(recorded, ConfigFacts::default());

    let init = classify_config(&fixture("written-by-hand-windows-init.listing"), &limits).unwrap();
    assert_eq!(
        init,
        ConfigFacts {
            symlinks_local: Some(false),
            ..ConfigFacts::default()
        }
    );

    let clone =
        classify_config(&fixture("written-by-hand-windows-clone.listing"), &limits).unwrap();
    assert_eq!(
        clone,
        ConfigFacts {
            symlinks_local: Some(false),
            remotes: vec!["origin".to_owned()],
            ..ConfigFacts::default()
        }
    );

    let all = classify_config(
        &fixture("written-by-hand-everything-admitted.listing"),
        &limits,
    )
    .unwrap();
    assert_eq!(
        all,
        ConfigFacts {
            object_format: ObjectFormat::Sha1,
            symlinks_local: Some(false),
            autocrlf_local: Some(AutoCrlf::Input),
            remotes: vec!["origin".to_owned(), "upstream".to_owned()],
            sparse: true,
        }
    );
}

#[test]
fn an_empty_listing_is_a_valid_listing_with_no_records() {
    assert_eq!(
        classify_config(b"", &Limits::default()).unwrap(),
        ConfigFacts::default()
    );
    assert_eq!(ConfigFacts::default().object_format, ObjectFormat::Sha1);
    assert_eq!(ConfigFacts::default().symlinks_local, None);
    assert_eq!(ConfigFacts::default().autocrlf_local, None);
    assert!(ConfigFacts::default().remotes.is_empty());
    assert!(!ConfigFacts::default().sparse);
}

#[test]
fn where_a_key_repeats_the_last_value_is_the_fact() {
    assert_eq!(
        facts(&[
            ("core.autocrlf", Some("true")),
            ("core.autocrlf", Some("input"))
        ])
        .autocrlf_local,
        Some(AutoCrlf::Input)
    );
    for (value, expected) in [
        ("true", AutoCrlf::True),
        ("False", AutoCrlf::False),
        ("INPUT", AutoCrlf::Input),
    ] {
        assert_eq!(
            facts(&[("core.autocrlf", Some(value))]).autocrlf_local,
            Some(expected)
        );
    }
    assert!(
        !facts(&[
            ("core.sparsecheckout", Some("true")),
            ("core.sparsecheckout", Some("false"))
        ])
        .sparse
    );
    assert!(facts(&[("core.sparsecheckout", None)]).sparse);
    assert!(facts(&[("core.sparsecheckout", Some("yes"))]).sparse);
    assert!(facts(&[("core.sparsecheckout", Some("1"))]).sparse);
    assert!(!facts(&[("core.sparsecheckout", Some("off"))]).sparse);
    assert!(!facts(&[("core.sparsecheckout", Some("0"))]).sparse);
    // Another key that holds a boolean sets no fact.
    assert!(!facts(&[("core.sparsecheckoutcone", Some("true"))]).sparse);
    assert_eq!(
        facts(&[
            ("core.symlinks", Some("false")),
            ("core.symlinks", Some("false"))
        ])
        .symlinks_local,
        Some(false)
    );
}

#[test]
fn remotes_come_from_the_subsections_of_the_remote_keys() {
    let all = facts(&[
        ("remote.zed.url", Some("https://example.com/z.git")),
        (
            "remote.alpha.fetch",
            Some("+refs/heads/*:refs/remotes/alpha/*"),
        ),
        ("remote.zed.fetch", Some("+refs/heads/*:refs/remotes/zed/*")),
        ("remote.Alpha.url", Some("https://example.com/a.git")),
        ("remote.a.b.url", Some("https://example.com/ab.git")),
    ]);
    assert_eq!(all.remotes, ["Alpha", "a.b", "alpha", "zed"]);
    assert!(
        facts(&[("branch.main.remote", Some("origin"))])
            .remotes
            .is_empty()
    );
}

#[test]
fn section_and_variable_names_compare_without_case_and_subsections_with_it() {
    let facts = facts(&[
        ("CORE.AutoCRLF", Some("true")),
        ("Core.SparseCheckout", Some("true")),
        ("REMOTE.Origin.URL", Some("https://example.com/o.git")),
        ("Remote.origin.url", Some("https://example.com/o.git")),
    ]);
    assert_eq!(facts.autocrlf_local, Some(AutoCrlf::True));
    assert!(facts.sparse);
    assert_eq!(facts.remotes, ["Origin", "origin"]);
    // A subsection decides whether a key is the table's: `Core` and `core` are one section, but
    // `user` takes no subsection at all.
    assert_eq!(rule(&[("user.Someone.name", Some("x"))]), RULE_UNLISTED);
    assert_eq!(
        rule(&[("remote.url", Some("https://example.com/o.git"))]),
        RULE_UNLISTED
    );
}

/// For one key: values that are admitted, and values that are not, with the rule that refuses.
struct Case {
    key: &'static str,
    admitted: &'static [Option<&'static str>],
    refused: &'static [Option<&'static str>],
    rule: &'static str,
}

const BOOLEAN: &[Option<&str>] = &[
    None,
    Some("true"),
    Some("false"),
    Some("yes"),
    Some("no"),
    Some("on"),
    Some("off"),
    Some("1"),
    Some("0"),
    Some("TRUE"),
    Some("Yes"),
    Some("oFF"),
];
const NOT_BOOLEAN: &[Option<&str>] = &[
    Some(""),
    Some("2"),
    Some("-1"),
    Some("maybe"),
    Some("truee"),
    Some(" true"),
    Some("true "),
    Some("true\nfalse"),
    Some("tr\u{fc}e"),
    Some("ON1"),
];

fn boolean(key: &'static str) -> Case {
    Case {
        key,
        admitted: BOOLEAN,
        refused: NOT_BOOLEAN,
        rule: RULE_VALUE,
    }
}

#[test]
fn every_admitted_key_takes_the_values_of_its_type_and_no_others() {
    let mut cases = vec![
        Case {
            key: "core.repositoryformatversion",
            admitted: &[Some("0"), Some("1")],
            refused: &[
                None,
                Some(""),
                Some("2"),
                Some("01"),
                Some("-1"),
                Some("one"),
                Some("0 "),
            ],
            rule: RULE_VALUE,
        },
        Case {
            key: "core.symlinks",
            admitted: &[Some("false"), Some("False")],
            refused: &[
                None,
                Some(""),
                Some("true"),
                Some("yes"),
                Some("0"),
                Some("input"),
            ],
            rule: RULE_SYMLINKS,
        },
        Case {
            key: "core.logallrefupdates",
            admitted: &[
                None,
                Some("true"),
                Some("false"),
                Some("always"),
                Some("ALWAYS"),
                Some("1"),
            ],
            refused: &[Some(""), Some("sometimes"), Some("alway"), Some("2")],
            rule: RULE_VALUE,
        },
        Case {
            key: "core.bare",
            admitted: &[Some("false"), Some("FALSE")],
            refused: &[None, Some(""), Some("true"), Some("1"), Some("yes")],
            rule: RULE_BARE,
        },
        Case {
            key: "core.autocrlf",
            admitted: &[Some("true"), Some("false"), Some("input"), Some("Input")],
            refused: &[
                None,
                Some(""),
                Some("auto"),
                Some("yes"),
                Some("1"),
                Some("inputs"),
            ],
            rule: RULE_VALUE,
        },
        Case {
            key: "core.eol",
            admitted: &[Some("lf"), Some("crlf"), Some("native"), Some("LF")],
            refused: &[None, Some(""), Some("cr"), Some("true"), Some("lf ")],
            rule: RULE_VALUE,
        },
        Case {
            key: "core.safecrlf",
            admitted: &[Some("true"), Some("false"), Some("warn"), Some("WARN")],
            refused: &[None, Some(""), Some("yes"), Some("input"), Some("warning")],
            rule: RULE_VALUE,
        },
        Case {
            key: "core.protectntfs",
            admitted: &[Some("true"), Some("TRUE")],
            refused: &[None, Some(""), Some("false"), Some("yes"), Some("1")],
            rule: RULE_VALUE,
        },
        Case {
            key: "core.protecthfs",
            admitted: &[Some("true")],
            refused: &[None, Some(""), Some("false"), Some("on")],
            rule: RULE_VALUE,
        },
        Case {
            key: "extensions.objectformat",
            admitted: &[Some("sha1"), Some("SHA1")],
            refused: &[None, Some(""), Some("sha256"), Some("sha-1"), Some("sha1 ")],
            rule: RULE_EXTENSION,
        },
        Case {
            key: "extensions.refstorage",
            admitted: &[Some("files")],
            refused: &[None, Some(""), Some("reftable"), Some("file")],
            rule: RULE_EXTENSION,
        },
        Case {
            key: "user.name",
            admitted: &[
                Some("A Person"),
                Some(""),
                Some("\u{e9}milie"),
                Some("a=b # c"),
            ],
            refused: &[
                None,
                Some("two\nlines"),
                Some("tab\there"),
                Some("esc\u{1b}x"),
                Some("\u{7f}"),
            ],
            rule: RULE_VALUE,
        },
        Case {
            key: "user.email",
            admitted: &[Some("person@example.com"), Some("")],
            refused: &[None, Some("a@b\nc@d"), Some("a@b\r")],
            rule: RULE_VALUE,
        },
        Case {
            key: "remote.origin.url",
            admitted: &[
                Some("https://example.com/a/b.git"),
                Some("ssh://git@example.com/a/b.git"),
                Some("git@example.com:a/b.git"),
                Some("C:\\work\\repo"),
                Some("../relative/repo"),
                Some("https://[::1]/repo.git"),
                Some("file:///srv/repo"),
                Some("a b"),
            ],
            refused: &[None, Some("two\nlines"), Some("a\tb")],
            rule: RULE_VALUE,
        },
        Case {
            key: "remote.origin.url",
            admitted: &[],
            refused: &[
                Some("ext::sh -c touch% /tmp/x"),
                Some("fd::5"),
                Some("foo::bar"),
                Some("a+b.c-d::x"),
                Some("0::x"),
                Some("::x"),
                Some("https::x"),
                Some("ext::"),
                Some("-x::y"),
                Some(".x::y"),
                Some("+x::y"),
            ],
            rule: RULE_URL_HELPER,
        },
        Case {
            key: "submodule.vendor.url",
            admitted: &[Some("https://example.com/v.git"), Some("../v")],
            refused: &[None, Some("a\nb")],
            rule: RULE_VALUE,
        },
        Case {
            key: "submodule.vendor.url",
            admitted: &[],
            refused: &[Some("ext::sh -c x"), Some("foo::bar")],
            rule: RULE_URL_HELPER,
        },
        Case {
            key: "remote.origin.fetch",
            admitted: &[
                Some("+refs/heads/*:refs/remotes/origin/*"),
                Some("refs/heads/*:refs/remotes/origin/*"),
                Some("refs/heads/main:refs/remotes/origin/main"),
                Some("+refs/heads/a-b_c.d/*:refs/remotes/o.1/*"),
            ],
            refused: &[
                None,
                Some(""),
                Some("refs/heads/*"),
                Some("+"),
                Some("+:"),
                Some(":refs/x"),
                Some("refs/x:"),
                Some("a:b:c"),
                Some("++refs/heads/*:refs/x"),
                Some("^refs/heads/x"),
                Some("refs/heads/ a:b"),
                Some("refs/heads/a:b "),
                Some("refs/h\u{e9}ads/*:refs/x/*"),
                Some("refs/heads/*:refs/remotes/o/*\n"),
                Some("refs/heads/%x:refs/x"),
                Some("refs/heads/[a]:refs/x"),
            ],
            rule: RULE_VALUE,
        },
        Case {
            key: "branch.main.remote",
            admitted: &[Some("origin"), Some("up/stream"), Some("a-b_c.d")],
            refused: &[
                None,
                Some(""),
                Some("."),
                Some("-x"),
                Some("a b"),
                Some("a..b"),
                Some("a/"),
            ],
            rule: RULE_VALUE,
        },
        Case {
            key: "branch.main.merge",
            admitted: &[Some("refs/heads/main"), Some("refs/heads/feature/x-1")],
            refused: &[
                None,
                Some(""),
                Some("main"),
                Some("refs/heads/"),
                Some("refs/tags/v1"),
                Some("refs/remotes/origin/main"),
                Some("refs/heads/a..b"),
                Some("refs/heads/a b"),
                Some("HEAD"),
            ],
            rule: RULE_VALUE,
        },
    ];
    for key in [
        "core.filemode",
        "core.ignorecase",
        "core.precomposeunicode",
        "core.longpaths",
        "core.trustctime",
        "core.quotepath",
        "core.preloadindex",
        "core.fscache",
        "core.sparsecheckout",
        "core.sparsecheckoutcone",
        "submodule.vendor.active",
    ] {
        cases.push(boolean(key));
    }
    for case in &cases {
        for value in case.admitted {
            if let Err(refusal) = classify(&[(case.key, *value)]) {
                panic!("{} = {value:?} was refused: {refusal}", case.key);
            }
        }
        for value in case.refused {
            assert_eq!(
                rule(&[(case.key, *value)]),
                case.rule,
                "{} = {value:?}",
                case.key
            );
        }
    }
}

#[test]
fn a_key_that_is_not_in_the_table_is_refused_by_the_family_it_belongs_to() {
    let keys: &[(&str, &str)] = &[
        // Includes.
        ("include.path", RULE_INCLUDE),
        ("includeIf.gitdir:/work/.path", RULE_INCLUDE),
        ("includeif.onbranch:main.path", RULE_INCLUDE),
        ("INCLUDE.PATH", RULE_INCLUDE),
        // Names of programs.
        ("core.fsmonitor", RULE_PROGRAM),
        ("core.hooksPath", RULE_PROGRAM),
        ("core.sshCommand", RULE_PROGRAM),
        ("core.askPass", RULE_PROGRAM),
        ("core.editor", RULE_PROGRAM),
        ("core.pager", RULE_PROGRAM),
        ("core.gitProxy", RULE_PROGRAM),
        ("core.alternateRefsCommand", RULE_PROGRAM),
        ("alias.co", RULE_PROGRAM),
        ("alias.x.y", RULE_PROGRAM),
        ("filter.lfs.clean", RULE_PROGRAM),
        ("filter.lfs.smudge", RULE_PROGRAM),
        ("filter.lfs.required", RULE_PROGRAM),
        ("diff.external", RULE_PROGRAM),
        ("diff.word.textconv", RULE_PROGRAM),
        ("merge.tool", RULE_PROGRAM),
        ("merge.ours.driver", RULE_PROGRAM),
        ("mergetool.x.cmd", RULE_PROGRAM),
        ("difftool.x.cmd", RULE_PROGRAM),
        ("credential.helper", RULE_PROGRAM),
        ("credential.https://example.com.helper", RULE_PROGRAM),
        ("gpg.program", RULE_PROGRAM),
        ("gpg.format", RULE_PROGRAM),
        ("trailer.x.cmd", RULE_PROGRAM),
        ("pager.log", RULE_PROGRAM),
        ("sequence.editor", RULE_PROGRAM),
        ("lfs.url", RULE_PROGRAM),
        ("submodule.vendor.update", RULE_PROGRAM),
        // Names of other locations.
        ("core.worktree", RULE_LOCATION),
        ("core.attributesFile", RULE_LOCATION),
        ("core.excludesFile", RULE_LOCATION),
        ("url.https://example.com/.insteadOf", RULE_LOCATION),
        ("mailmap.file", RULE_LOCATION),
        ("mailmap.blob", RULE_LOCATION),
        ("safe.directory", RULE_LOCATION),
        ("init.templateDir", RULE_LOCATION),
        ("commit.template", RULE_LOCATION),
        // Connecting to another computer.
        ("http.proxy", RULE_TRANSPORT),
        ("http.sslBackend", RULE_TRANSPORT),
        ("protocol.allow", RULE_TRANSPORT),
        ("uploadpack.packObjectsHook", RULE_TRANSPORT),
        ("receive.denyCurrentBranch", RULE_TRANSPORT),
        ("transfer.fsckObjects", RULE_TRANSPORT),
        ("fetch.prune", RULE_TRANSPORT),
        ("pull.rebase", RULE_TRANSPORT),
        ("push.default", RULE_TRANSPORT),
        ("remote.origin.uploadpack", RULE_TRANSPORT),
        ("remote.origin.receivepack", RULE_TRANSPORT),
        ("remote.origin.vcs", RULE_TRANSPORT),
        ("remote.origin.proxy", RULE_TRANSPORT),
        ("remote.origin.pushurl", RULE_TRANSPORT),
        ("remote.origin.promisor", RULE_TRANSPORT),
        ("remote.origin.partialclonefilter", RULE_TRANSPORT),
        ("remote.origin.tagopt", RULE_TRANSPORT),
        ("remote.origin.mirror", RULE_TRANSPORT),
        // Extensions.
        ("extensions.worktreeConfig", RULE_WORKTREE_CONFIG),
        ("extensions.worktreeconfig", RULE_WORKTREE_CONFIG),
        ("extensions.partialClone", RULE_EXTENSION),
        ("extensions.compatObjectFormat", RULE_EXTENSION),
        ("extensions.preciousObjects", RULE_EXTENSION),
        ("extensions.noop", RULE_EXTENSION),
        ("extensions.somethingNew", RULE_EXTENSION),
        // The rest of the named list, and anything else.
        ("core.untrackedCache", RULE_UNLISTED),
        ("core.splitIndex", RULE_UNLISTED),
        ("splitIndex.maxPercentChange", RULE_UNLISTED),
        ("index.sparse", RULE_UNLISTED),
        ("index.version", RULE_UNLISTED),
        ("gc.auto", RULE_UNLISTED),
        ("maintenance.auto", RULE_UNLISTED),
        ("notes.rewriteRef", RULE_UNLISTED),
        ("log.mailmap", RULE_UNLISTED),
        ("core.compression", RULE_UNLISTED),
        ("core.unknownKey", RULE_UNLISTED),
        ("branch.main.rebase", RULE_UNLISTED),
        ("branch.main.pushRemote", RULE_UNLISTED),
        ("submodule.vendor.path", RULE_UNLISTED),
        ("submodule.recurse", RULE_UNLISTED),
        ("user.signingkey", RULE_UNLISTED),
        ("user.useConfigOnly", RULE_UNLISTED),
        ("commit.gpgsign", RULE_UNLISTED),
        ("init.defaultBranch", RULE_UNLISTED),
        ("kr.evil", RULE_UNLISTED),
        ("foo.bar", RULE_UNLISTED),
        ("core.bare.x", RULE_UNLISTED),
        ("user.x.name", RULE_UNLISTED),
    ];
    for (key, expected) in keys {
        for value in [Some("x"), None, Some("")] {
            assert_eq!(rule(&[(key, value)]), *expected, "{key} = {value:?}");
        }
    }
    // Any record outside the table refuses the listing, wherever it stands in it.
    let mut records = vec![("core.bare", Some("false")); 50];
    records.push(("core.fsmonitor", Some("evil")));
    records.push(("core.bare", Some("false")));
    assert_eq!(rule(&records), RULE_PROGRAM);
}

#[test]
fn a_refusal_names_the_key_cut_and_cleaned_and_never_the_value() {
    let refusal = classify(&[("core.sshCommand", Some("secret-value-xyz"))]).unwrap_err();
    assert!(refusal.detail().contains("core.sshCommand"), "{refusal}");
    assert!(!refusal.detail().contains("secret"), "{refusal}");
    assert!(refusal.to_string().starts_with("configuration: "));

    let long = format!("zzz.{}", "k".repeat(500));
    let refusal = classify(&[(&long, Some("v"))]).unwrap_err();
    assert_eq!(refusal.rule, RULE_UNLISTED);
    assert!(refusal.detail().contains(&long[..120]), "{refusal}");
    assert!(!refusal.detail().contains(&long[..121]), "{refusal}");

    let refusal = classify_config(b"zzz.a\x01b\xffc\n1\0", &Limits::default()).unwrap_err();
    assert_eq!(refusal.rule, RULE_RECORD_KEY);
    assert!(refusal.detail().is_ascii());
    let refusal = classify(&[("zzz.sub\u{e9}.name", Some("1"))]).unwrap_err();
    assert_eq!(refusal.rule, RULE_UNLISTED);
    assert!(refusal.detail().is_ascii(), "{refusal}");
    assert!(refusal.detail().contains("zzz.sub??.name"), "{refusal}");

    let refusal = classify(&[("core.autocrlf", Some("secret-value-xyz"))]).unwrap_err();
    assert!(refusal.detail().contains("core.autocrlf"), "{refusal}");
    assert!(!refusal.detail().contains("secret"), "{refusal}");
}

#[test]
fn a_listing_is_framed_by_nul_and_a_record_splits_at_its_first_newline() {
    // No newline: the key has no value. A newline with nothing after it: an empty value.
    assert!(facts(&[("core.sparsecheckout", None)]).sparse);
    assert_eq!(rule(&[("core.sparsecheckout", Some(""))]), RULE_VALUE);
    assert_eq!(rule(&[("core.autocrlf", None)]), RULE_VALUE);
    // A value may hold newlines, and the key is what comes before the first.
    assert_eq!(rule(&[("user.name", Some("a\nb"))]), RULE_VALUE);
    assert_eq!(
        rule_of_bytes(b"core.fsmonitor\nx\0core.bare\nfalse\0"),
        RULE_PROGRAM
    );
    assert_eq!(
        rule_of_bytes(b"core.bare\nfalse\ncore.fsmonitor\nx\0"),
        RULE_BARE
    );
    // The listing's last byte must be the NUL that ends its last record.
    assert_eq!(rule_of_bytes(b"core.bare\nfalse"), RULE_TRUNCATED);
    assert_eq!(
        rule_of_bytes(b"core.bare\nfalse\0core.filemode\ntrue"),
        RULE_TRUNCATED
    );
    assert_eq!(rule_of_bytes(b"core.bare"), RULE_TRUNCATED);
    assert_eq!(rule_of_bytes(b"\n"), RULE_TRUNCATED);
}

#[test]
fn a_record_without_a_usable_key_is_refused() {
    for bytes in [
        &b"\0"[..],
        b"\0\0",
        b"core.bare\nfalse\0\0",
        b"\0core.bare\nfalse\0",
        b"\nfalse\0",
        b"\n\0",
        b"core\0",
        b"core\nfalse\0",
        b".filemode\0",
        b"core.\0",
        b"core..filemode\ntrue\0",
        b"remote..url\nhttps://example.com\0",
        b"core.file\x01mode\ntrue\0",
        b"core.file\tmode\ntrue\0",
        b"core.file\x7fmode\ntrue\0",
        b"core.file\xffmode\ntrue\0",
        b"core.fi le\ntrue\0",
        b"co re.filemode\ntrue\0",
        b"core.file=mode\ntrue\0",
        b"core.1filemode\ntrue\0",
    ] {
        assert_eq!(
            rule_of_bytes(bytes),
            RULE_RECORD_KEY,
            "{:?}",
            String::from_utf8_lossy(bytes)
        );
    }
}

#[test]
fn a_value_that_is_not_text_is_refused_where_the_key_is_admitted() {
    assert_eq!(rule_of_bytes(b"user.name\n\xff\xfe\0"), RULE_VALUE);
    assert_eq!(rule_of_bytes(b"core.autocrlf\ntr\xffue\0"), RULE_VALUE);
    assert_eq!(rule_of_bytes(b"core.bare\nfal\xffse\0"), RULE_BARE);
}

fn repeated(count: usize) -> Vec<u8> {
    listing(&vec![("core.bare", Some("false")); count])
}

#[test]
fn the_listing_may_take_a_megabyte_and_no_more() {
    // 128 records of 8,192 bytes with their NULs fill the limit exactly.
    let value = "v".repeat(8192 - 1 - "user.name\n".len());
    let mut at = Vec::new();
    for _ in 0..128 {
        at.extend_from_slice(&listing(&[("user.name", Some(&value))]));
    }
    assert_eq!(at.len(), 1_048_576);
    assert!(classify_config(&at, &Limits::default()).is_ok());
    // One byte more is refused first: as the listing, before its framing or its records are read.
    let mut over = at.clone();
    over.pop();
    over.extend_from_slice(b"v\0");
    assert_eq!(over.len(), 1_048_577);
    assert_eq!(rule_of_bytes(&over), RULE_LISTING_TOO_LARGE);
    let junk = vec![b'A'; 3 * 1024 * 1024];
    assert_eq!(rule_of_bytes(&junk), RULE_LISTING_TOO_LARGE);
    let small = Limits {
        listing_bytes: repeated(3).len(),
        ..Limits::default()
    };
    assert!(classify_config(&repeated(3), &small).is_ok());
    assert_eq!(
        classify_config(&repeated(4), &small).unwrap_err().rule,
        RULE_LISTING_TOO_LARGE
    );
}

#[test]
fn the_listing_may_hold_so_many_records_and_no_more() {
    let records = Limits::default().records;
    assert!(classify_config(&repeated(records), &Limits::default()).is_ok());
    assert_eq!(rule_of_bytes(&repeated(records + 1)), RULE_TOO_MANY_RECORDS);
    // The count is checked before any record is read: these are all refused keys.
    let bad = listing(&vec![("core.fsmonitor", Some("x")); records + 1]);
    assert_eq!(rule_of_bytes(&bad), RULE_TOO_MANY_RECORDS);
    let empty = vec![0_u8; records + 1];
    assert_eq!(rule_of_bytes(&empty), RULE_TOO_MANY_RECORDS);
    let small = Limits {
        records: 2,
        ..Limits::default()
    };
    assert!(classify_config(&repeated(2), &small).is_ok());
    assert_eq!(
        classify_config(&repeated(3), &small).unwrap_err().rule,
        RULE_TOO_MANY_RECORDS
    );
}

#[test]
fn a_record_may_take_so_many_bytes_and_no_more() {
    let at = "v".repeat(8192 - "user.name\n".len());
    assert!(classify(&[("user.name", Some(&at))]).is_ok());
    let over = "v".repeat(8192 - "user.name\n".len() + 1);
    assert_eq!(rule(&[("user.name", Some(&over))]), RULE_RECORD_TOO_LARGE);
    // Before any record is read: this one would be refused as a key if it were looked at.
    let key = format!("zzz.{}", "k".repeat(8300));
    assert_eq!(rule(&[(&key, None)]), RULE_RECORD_TOO_LARGE);
    // The bound counts the key, the newline and the value, and not the NUL.
    let key = format!("zzz.{}", "k".repeat(8192 - 4));
    assert_eq!(rule(&[(&key, None)]), RULE_UNLISTED);
    assert_eq!(rule(&[(&format!("{key}k"), None)]), RULE_RECORD_TOO_LARGE);
    let small = Limits {
        record_bytes: 20,
        ..Limits::default()
    };
    let bytes = listing(&[("user.name", Some("0123456789"))]);
    assert!(classify_config(&bytes, &small).is_ok());
    let bytes = listing(&[("user.name", Some("01234567890"))]);
    assert_eq!(
        classify_config(&bytes, &small).unwrap_err().rule,
        RULE_RECORD_TOO_LARGE
    );
    // A later record that is over is found even when an earlier one would be refused: the lengths
    // are all checked first.
    let mut bytes = listing(&[("core.fsmonitor", Some("x"))]);
    bytes.extend_from_slice(&listing(&[("user.name", Some(&over))]));
    assert_eq!(rule_of_bytes(&bytes), RULE_RECORD_TOO_LARGE);
}

#[test]
fn the_subsection_of_a_key_may_take_so_many_bytes_and_no_more() {
    let at = "s".repeat(256);
    let facts = facts(&[(
        &format!("remote.{at}.url"),
        Some("https://example.com/a.git"),
    )]);
    assert_eq!(facts.remotes, [at.as_str()]);
    let over = "s".repeat(257);
    assert_eq!(
        rule(&[(
            &format!("remote.{over}.url"),
            Some("https://example.com/a.git")
        )]),
        RULE_SUBSECTION_TOO_LARGE
    );
    // Dots and other characters inside it count as bytes.
    let dotted = format!("{}.{}", "a".repeat(127), "b".repeat(128));
    assert!(
        classify(&[(
            &format!("remote.{dotted}.url"),
            Some("https://example.com/a.git")
        )])
        .is_ok()
    );
    assert_eq!(
        rule(&[(
            &format!("remote.{dotted}x.url"),
            Some("https://example.com/a.git")
        )]),
        RULE_SUBSECTION_TOO_LARGE
    );
    let multibyte = "\u{e9}".repeat(128);
    assert!(
        classify(&[(
            &format!("remote.{multibyte}.url"),
            Some("https://example.com/a.git")
        )])
        .is_ok()
    );
    assert_eq!(
        rule(&[(
            &format!("remote.{multibyte}x.url"),
            Some("https://example.com/a.git")
        )]),
        RULE_SUBSECTION_TOO_LARGE
    );
    // The bound holds for a key of any family, so a refused one is not a way to carry a long name.
    assert_eq!(
        rule(&[(&format!("credential.{over}.helper"), Some("x"))]),
        RULE_SUBSECTION_TOO_LARGE
    );
    let small = Limits {
        subsection_bytes: 3,
        ..Limits::default()
    };
    let bytes = listing(&[("remote.abc.url", Some("https://example.com/a.git"))]);
    assert!(classify_config(&bytes, &small).is_ok());
    let bytes = listing(&[("remote.abcd.url", Some("https://example.com/a.git"))]);
    assert_eq!(
        classify_config(&bytes, &small).unwrap_err().rule,
        RULE_SUBSECTION_TOO_LARGE
    );
}
