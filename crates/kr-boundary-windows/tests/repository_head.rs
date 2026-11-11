//! The grammar of a repository's `HEAD` and of the names it holds, against the bytes Git writes and
//! the bytes a hostile repository could put there.

use kr_boundary_windows::frame::invocation::{MAX_NAME_BYTES, RefusedKind};
use kr_boundary_windows::names::{is_branch_name, is_oid};
use kr_boundary_windows::repository::head::{HeadKind, check_head};

const OID: &str = "0123456789abcdef0123456789abcdef01234567";

fn branch(name: &str) -> HeadKind {
    HeadKind::Branch {
        name: name.to_owned(),
    }
}

fn refused(bytes: &[u8]) -> &'static str {
    let refusal = check_head(bytes).expect_err(&format!("{:?}", String::from_utf8_lossy(bytes)));
    assert_eq!(refusal.kind, RefusedKind::Repository, "{refusal}");
    refusal.rule
}

#[test]
fn a_symbolic_reference_to_a_branch_is_read_as_git_writes_it() {
    assert_eq!(
        check_head(b"ref: refs/heads/main\n").unwrap(),
        branch("main")
    );
    // Git writes the newline; a file without one is read the same.
    assert_eq!(check_head(b"ref: refs/heads/main").unwrap(), branch("main"));
    assert_eq!(
        check_head(b"ref: refs/heads/feature/x-1.2_y\n").unwrap(),
        branch("feature/x-1.2_y")
    );
    assert_eq!(check_head(b"ref: refs/heads/0\n").unwrap(), branch("0"));
}

#[test]
fn a_detached_head_is_an_object_identifier_in_lowercase_hexadecimal() {
    let detached = HeadKind::Detached {
        oid: OID.to_owned(),
    };
    assert_eq!(check_head(format!("{OID}\n").as_bytes()).unwrap(), detached);
    assert_eq!(check_head(OID.as_bytes()).unwrap(), detached);
}

#[test]
fn a_branch_name_may_be_as_long_as_the_limit_and_no_longer() {
    let at = "a".repeat(MAX_NAME_BYTES);
    assert_eq!(
        check_head(format!("ref: refs/heads/{at}\n").as_bytes()).unwrap(),
        branch(&at)
    );
    let over = "a".repeat(MAX_NAME_BYTES + 1);
    assert_eq!(
        refused(format!("ref: refs/heads/{over}\n").as_bytes()),
        "head-name"
    );
}

#[test]
fn a_reference_outside_the_branches_is_refused_by_name() {
    for target in [
        "refs/tags/v1",
        "refs/remotes/origin/main",
        "refs/heads",
        "refs/replace/x",
        "refs/stash",
        "HEAD",
        "ORIG_HEAD",
        "main",
        "/refs/heads/main",
        "refs/HEADS/main",
        "REFS/heads/main",
        "",
    ] {
        assert_eq!(
            refused(format!("ref: {target}\n").as_bytes()),
            "head-reference",
            "{target:?}"
        );
    }
}

#[test]
fn a_branch_name_outside_the_grammar_is_refused_by_name() {
    for name in [
        "", "a..b", "a//b", "a/", "/a", "a.", ".a", "-a", "a/.b", "a/-b", "a.lock", "a/b.lock",
        "a.lock/b", "a b", "a\tb", "a@{1}", "a@b", "@", "a:b", "a~1", "a^", "a?b", "a*b", "a[b",
        "a\\b", "\u{e9}", "a\u{e9}",
    ] {
        assert_eq!(
            refused(format!("ref: refs/heads/{name}\n").as_bytes()),
            "head-name",
            "{name:?}"
        );
    }
}

#[test]
fn any_other_form_of_head_is_refused_by_name() {
    // Not a symbolic reference with the single space Git writes, and not an identifier.
    let form: &[&[u8]] = &[
        b"",
        b"\n",
        b"ref:\n",
        b"ref:refs/heads/main\n",
        b"Ref: refs/heads/main\n",
        b"refs/heads/main\n",
        b"\n ref: refs/heads/main\n",
        b"0123456789ABCDEF0123456789ABCDEF01234567\n",
        b"0123456789abcdef0123456789abcdef0123456\n",
        b"0123456789abcdef0123456789abcdef012345678\n",
        b"0123456789abcdef0123456789abcdef01234567\n\n",
        b"0123456789abcdef0123456789abcdef01234567 \n",
        b"0123456789abcdef0123456789abcdef01234567\r\n",
        b"0123456789abcdef0123456789abcdef0123456g\n",
        b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        b"abc123\n",
        b"HEAD\n",
        b"gitdir: ../elsewhere\n",
    ];
    for bytes in form {
        assert_eq!(
            refused(bytes),
            "head-form",
            "{:?}",
            String::from_utf8_lossy(bytes)
        );
    }
    // A very long file with no symbolic reference in it is a form that is not one.
    assert_eq!(refused(&vec![b'a'; 1 << 20]), "head-form");

    // Whatever follows `ref: ` is read as the target, so the characters Git trims are refused
    // there, as is every byte that is not in the grammar.
    let reference: &[&[u8]] = &[b"ref: \n", b"ref:  refs/heads/main\n"];
    for bytes in reference {
        assert_eq!(refused(bytes), "head-reference");
    }
    let name: &[&[u8]] = &[
        b"ref: refs/heads/main \n",
        b"ref: refs/heads/main\r\n",
        b"ref: refs/heads/main\n\n",
        b"ref: refs/heads/main\nextra\n",
        b"ref: refs/heads/main\0",
        b"ref: refs/heads/ma\0in\n",
        b"ref: refs/heads/main\xff\n",
    ];
    for bytes in name {
        assert_eq!(
            refused(bytes),
            "head-name",
            "{:?}",
            String::from_utf8_lossy(bytes)
        );
    }
    let mut long = b"ref: refs/heads/".to_vec();
    long.extend(vec![b'a'; 1 << 20]);
    assert_eq!(refused(&long), "head-name");
}

#[test]
fn a_refusal_names_the_rule_and_never_what_head_held() {
    for bytes in [
        &b"ref: refs/heads/a b/secret-token-in-a-name\n"[..],
        b"ref: refs/tags/secret-token-in-a-name\n",
        b"secret-token-in-a-name\n",
    ] {
        let refusal = check_head(bytes).unwrap_err();
        assert!(!refusal.detail().contains("secret"), "{refusal}");
        assert!(refusal.detail().starts_with("HEAD"), "{refusal}");
        assert!(refusal.to_string().starts_with("repository: HEAD"));
    }
}

#[test]
fn the_branch_name_grammar_is_the_one_the_tables_use() {
    for name in [
        "main",
        "a",
        "0",
        "A-b_c.d",
        "feature/x",
        "a/b/c/d",
        "release-1.2.3",
        "a.b",
        "lock",
        "a.lockx",
        "a/locked",
        "x.lock.y",
        // Near a device name, and not one.
        "console",
        "nul1",
        "com10",
        "comx",
        "con1",
        "aux1",
        "conin",
        "a/communal/b",
        "prn_x",
        "xnul",
    ] {
        assert!(is_branch_name(name), "{name:?}");
    }
    assert!(is_branch_name(&"a".repeat(MAX_NAME_BYTES)));
    assert!(!is_branch_name(&"a".repeat(MAX_NAME_BYTES + 1)));
    assert!(is_branch_name(&format!(
        "{}/{}",
        "a".repeat(99),
        "b".repeat(100)
    )));
    for name in [
        "", "/", "//", "a//b", "/a", "a/", "a.", ".a", "-a", "_a", "a/.b", "a..b", "a.lock",
        "a/b.lock", "a b", "a@{u}", "a@b", "@", "a:b", "a\\b", "a\n", "\u{e9}",
    ] {
        assert!(!is_branch_name(name), "{name:?}");
    }
}

#[test]
fn a_component_that_windows_reads_as_a_device_is_no_branch_name() {
    // On Windows the file of `refs/heads/com1`, and its `.lock` file, are device paths. A name is
    // refused by the rule of the path grammar: the text before the first dot is a device, in any
    // case.
    for name in [
        "nul",
        "con",
        "prn",
        "aux",
        "NUL",
        "Con",
        "AuX",
        "com0",
        "com1",
        "COM9",
        "lpt0",
        "lpt1",
        "LPT9",
        "aux.x",
        "con.tar.gz",
        "nul.txt",
        "a/nul",
        "a/nul/b",
        "nul/a",
        "x/com1.txt",
        "a/b/LPT3.log",
        "feature/aux",
    ] {
        assert!(!is_branch_name(name), "{name:?}");
    }
}

#[test]
fn a_head_that_names_a_device_is_refused_as_a_name() {
    for name in ["nul", "com1", "a/aux.x"] {
        let bytes = format!("ref: refs/heads/{name}\n");
        assert_eq!(refused(bytes.as_bytes()), "head-name", "{name}");
    }
}

#[test]
fn an_object_identifier_is_forty_lowercase_hexadecimal_digits() {
    assert!(is_oid(OID));
    assert!(is_oid(&"0".repeat(40)));
    assert!(is_oid(&"f".repeat(40)));
    for text in [
        "",
        &OID[..39],
        &format!("{OID}0"),
        &OID.to_uppercase(),
        &format!("{}g", &OID[..39]),
        &format!(" {}", &OID[..39]),
        &"0".repeat(64),
    ] {
        assert!(!is_oid(text), "{text:?}");
    }
}
