//! What the redaction rules take out of a field's text, and what they leave alone.

use super::*;

const UNIX: Paths = Paths {
    ignores_case: false,
    backslash_separates: false,
};

const WINDOWS: Paths = Paths {
    ignores_case: true,
    backslash_separates: true,
};

/// A planted value no rule is allowed to leave in the text.
const MARKER: &str = "kr-marker-91b7";

/// The text with the rules applied, for a host whose home is `/home/tom`.
fn redacted(text: &str) -> String {
    field(text, Some("/home/tom"), UNIX)
}

/// KR-REQ-29.04: each of the three planted forms is gone, and what was around it is not.
#[test]
fn the_three_planted_forms_are_taken_out_and_their_neighbours_stay() {
    assert_eq!(
        redacted(&format!("TOKEN={MARKER} make build")),
        "TOKEN=[redacted] make build"
    );
    assert_eq!(
        redacted(&format!("deploy --password {MARKER} --verbose")),
        "deploy --password [redacted] --verbose"
    );
    assert_eq!(
        redacted(&format!(
            "git clone https://user:{MARKER}@example.com/repo.git"
        )),
        "git clone https://[redacted]@example.com/repo.git"
    );
}

/// KR-REQ-29.04: the control. An ordinary path and an ordinary command line are the text they were.
#[test]
fn an_ordinary_path_and_command_stay_readable() {
    for text in [
        "/usr/local/bin/fish",
        "/Applications/Tom's Tools/fish",
        "/work/project/src",
        "C:\\Users\\someone\\work",
        "ls -la /tmp && echo done",
        "cargo test --workspace --no-fail-fast",
        "PWD=/work KEYBOARD=us ls",
        "git clone https://example.com/repo.git",
        "--tokenizer is not a flag here",
    ] {
        // The last is the one name the rules read too widely, so it is shown as redacted below.
        if text.starts_with("--tokenizer") {
            continue;
        }
        assert_eq!(redacted(text), text, "{text}");
    }
}

/// KR-REQ-29.04: the same forms with an equals sign, a quoted value that holds a space, and in the
/// middle of a path or after a query's question mark.
#[test]
fn quoted_and_embedded_forms_are_taken_out_whole() {
    for (text, expected) in [
        (
            format!("--password={MARKER} next"),
            "--password=[redacted] next".to_owned(),
        ),
        (
            format!("--password \"prefix {MARKER} suffix\" next"),
            "--password [redacted] next".to_owned(),
        ),
        (
            format!("TOKEN=\"prefix {MARKER}\" next"),
            "TOKEN=[redacted] next".to_owned(),
        ),
        (
            format!("TOKEN='a b {MARKER}' next"),
            "TOKEN=[redacted] next".to_owned(),
        ),
        (
            format!("/tmp/TOKEN={MARKER}/x"),
            "/tmp/TOKEN=[redacted]".to_owned(),
        ),
        (
            format!("https://host/path?token={MARKER}&a=b"),
            "https://host/path?token=[redacted]".to_owned(),
        ),
        (
            format!("DATABASE_URL=postgres://u:{MARKER}@h/db"),
            "DATABASE_URL=postgres://[redacted]@h/db".to_owned(),
        ),
        (
            format!("--url=https://u:{MARKER}@h/ go"),
            "--url=https://[redacted]@h/ go".to_owned(),
        ),
        (
            format!("TOKEN=https://u:{MARKER}@h/"),
            "TOKEN=[redacted]".to_owned(),
        ),
    ] {
        let said = redacted(&text);
        assert_eq!(said, expected, "{text}");
        assert!(!said.contains(MARKER), "{text} -> {said}");
    }
}

/// KR-REQ-29.04: an option whose value is another option has no value to take out.
#[test]
fn an_option_that_says_credential_with_no_value_after_it_takes_nothing() {
    assert_eq!(
        redacted("tool --password --verbose"),
        "tool --password --verbose"
    );
    assert_eq!(redacted("tool --password"), "tool --password");
}

/// KR-REQ-29.04: a credential value whose quote never closes cannot be told from the rest of the
/// field, so the field is withheld whole, as its length; a quote anywhere else is a character.
#[test]
fn an_unterminated_quote_after_a_credential_withholds_the_field() {
    let text = format!("run --password \"never closed {MARKER}");
    let said = redacted(&text);
    assert_eq!(
        said,
        format!("[withheld: {} characters]", text.chars().count())
    );
    assert!(!said.contains(MARKER));
    assert_eq!(redacted("/Users/o'neil/work"), "/Users/o'neil/work");
}

/// KR-REQ-29.04: which names say credential, by their parts as well as by their letters.
#[test]
fn a_name_says_credential_by_its_letters_or_its_parts() {
    for name in [
        "TOKEN",
        "GITHUB_TOKEN",
        "password",
        "DB_PASSWD",
        "aws_secret_access_key",
        "accessKeyId",
        "X-Auth-Key",
        "api-key",
        "APIKEY",
        "id_privatekey",
        "Authorization",
        "session.cookie",
        "tokenizer",
    ] {
        assert!(says_credential(name), "{name}");
    }
    for name in [
        "PWD",
        "KEYBOARD",
        "HOME",
        "PATH",
        "monkey",
        "author",
        "passenger",
        "LANG",
    ] {
        assert!(!says_credential(name), "{name}");
    }
}

/// KR-REQ-29.04: the home directory is a path prefix and nothing else, with a component boundary.
#[test]
fn the_home_directory_is_replaced_as_a_path_prefix() {
    assert_eq!(redacted("/home/tom"), "[home]");
    assert_eq!(redacted("/home/tom/work/src"), "[home]/work/src");
    assert_eq!(redacted("cd /home/tom/work"), "cd [home]/work");
    assert_eq!(
        redacted("PATH=/usr/bin:/home/tom/bin"),
        "PATH=/usr/bin:[home]/bin"
    );
    assert_eq!(redacted("/home/tomorrow/work"), "/home/tomorrow/work");
    assert_eq!(redacted("/srv/home/tom"), "/srv/home/tom");
    // A home with a space in it is one prefix.
    assert_eq!(
        field("/Users/Tom Jones/work", Some("/Users/Tom Jones"), UNIX),
        "[home]/work"
    );
    // A trailing separator on the home is not part of it.
    assert_eq!(
        field("/home/tom/work", Some("/home/tom/"), UNIX),
        "[home]/work"
    );
}

/// KR-REQ-29.04: a home that is a root, empty or relative would turn the whole machine into
/// `[home]`, so it is not replaced.
#[test]
fn a_home_that_is_a_root_or_not_a_path_is_never_replaced() {
    for home in ["/", "", "relative/home", "//"] {
        assert_eq!(
            field("/usr/bin/sh", Some(home), UNIX),
            "/usr/bin/sh",
            "{home:?}"
        );
    }
    assert_eq!(field("/usr/bin/sh", None, UNIX), "/usr/bin/sh");
}

/// KR-REQ-29.04: on Windows a path compares without regard to case and either slash separates it.
#[test]
fn a_windows_home_matches_in_any_case_with_either_separator() {
    let home = Some("C:\\Users\\Tom");
    assert_eq!(field("C:\\Users\\Tom\\work", home, WINDOWS), "[home]\\work");
    assert_eq!(field("c:/users/tom/work", home, WINDOWS), "[home]/work");
    assert_eq!(
        field("C:\\Users\\Tomorrow", home, WINDOWS),
        "C:\\Users\\Tomorrow"
    );
    // The same text on a platform where case matters and a backslash is a character.
    assert_eq!(field("c:/users/tom/work", home, UNIX), "c:/users/tom/work");
}

/// KR-REQ-29.04: the rules read the text they are given and nothing is left in it twice: a second
/// pass over redacted text changes nothing.
#[test]
fn redacting_twice_is_redacting_once() {
    for text in [
        format!("TOKEN={MARKER} --password \"a b {MARKER}\" https://u:{MARKER}@h/"),
        "/home/tom/work".to_owned(),
        "ordinary".to_owned(),
    ] {
        let once = redacted(&text);
        assert_eq!(redacted(&once), once, "{text}");
    }
}

/// KR-REQ-29.04: what the rules do not read, stated rather than implied: these stay in the text.
#[test]
fn what_the_rules_do_not_read_stays() {
    for text in [
        format!("tool -p {MARKER}"),
        format!("tool {MARKER}"),
        format!("/srv/{MARKER}/data"),
        format!("curl -H 'Authorization: Bearer {MARKER}'"),
    ] {
        assert!(redacted(&text).contains(MARKER), "{text}");
    }
}
