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
        "curl \"https://example.com/a?b=c\" 'user@example.com'",
    ] {
        assert_eq!(redacted(text), text, "{text}");
    }
}

/// KR-REQ-29.04: the one place the name list reads too widely, stated: `tokenizer` says credential,
/// so what follows it goes.
#[test]
fn a_name_the_list_reads_too_widely_is_redacted_too() {
    assert_eq!(
        redacted("run --tokenizer fast now"),
        "run --tokenizer [redacted] now"
    );
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

/// KR-REQ-29.04: a credential value that holds another credential name with a quoted value is one
/// span, replaced whole: nothing of the quoted part is left after the earlier span's end.
#[test]
fn overlapping_credentials_are_replaced_as_one() {
    for (text, expected) in [
        (
            format!("run --password TOKEN=\"prefix {MARKER}\" next"),
            "run --password [redacted] next".to_owned(),
        ),
        (
            format!("AUTH_OPTS=--token=\"x {MARKER}\" next"),
            "AUTH_OPTS=[redacted] next".to_owned(),
        ),
        (
            format!("/tmp/TOKEN=a,SECRET=\"b {MARKER} d\" tail"),
            "/tmp/TOKEN=[redacted] tail".to_owned(),
        ),
        (
            format!("TOKEN=a SECRET={MARKER} PASSWORD='b {MARKER}'"),
            "TOKEN=[redacted] SECRET=[redacted] PASSWORD=[redacted]".to_owned(),
        ),
    ] {
        let said = redacted(&text);
        assert_eq!(said, expected, "{text}");
        assert!(!said.contains(MARKER), "{said}");
    }
}

/// KR-REQ-29.04: a value is read as a shell reads a word: a quote in the middle of it, and a quote
/// escaped inside it, keep the words after them in the value; a quote that never closes withholds the
/// field.
#[test]
fn a_value_is_read_as_a_shell_word() {
    for (text, expected) in [
        (
            format!("TOKEN=abc\"d {MARKER}\" next"),
            "TOKEN=[redacted] next".to_owned(),
        ),
        (
            format!("PASSWORD='it'\\''s {MARKER}' next"),
            "PASSWORD=[redacted] next".to_owned(),
        ),
        (
            format!("--secret a\\ b{MARKER} next"),
            "--secret [redacted] next".to_owned(),
        ),
        (
            format!("SECRET=\"a \\\" {MARKER}\" next"),
            "SECRET=[redacted] next".to_owned(),
        ),
    ] {
        let said = redacted(&text);
        assert_eq!(said, expected, "{text}");
        assert!(!said.contains(MARKER), "{said}");
    }
    let unclosed = format!("TOKEN=abc\"d {MARKER}");
    assert_eq!(
        redacted(&unclosed),
        format!("[withheld: {} characters]", unclosed.chars().count())
    );
}

/// KR-REQ-29.04: a field with a quote before a credential's value is withheld. A quote is a quote
/// or a character of a name (`Tom's`, `Rock 'n Roll`) and the text cannot say which; a quote before
/// the value can surround it up to a later quote, or up to the end of the text when nothing closes
/// it, so no reading of the quotes is trusted to end the value. Every input here is one that a
/// reading of the quotes left a marker in the text for: the quoted-argument forms of `docker -e`,
/// `env` and `sh -c`, apostrophes in a path before a credential, quotes of the other kind, an
/// escaped quote, the quote at a boundary, a quote that is never closed and a value that starts
/// with whitespace.
#[test]
fn a_quote_before_a_credential_value_withholds_the_field() {
    for text in [
        // The whole assignment is a quoted argument.
        format!("docker run -e \"PASSWORD=two {MARKER}\" img"),
        format!("env 'TOKEN=a {MARKER}' cmd"),
        format!("tool \"--password=a {MARKER}\" next"),
        format!("tool \"--password={MARKER}\" next"),
        format!("env 'TOKEN=it'\\''s {MARKER}' cmd"),
        format!("env 'TOKEN=it'\"'\"'s {MARKER}' cmd"),
        format!("-e \"PASSWORD=\"{MARKER} img"),
        format!("-e \"PASSWORD=\"{MARKER}"),
        format!("env 'TOKEN=a'{MARKER}"),
        format!("env \"TOKEN={MARKER}\" keep \"two words\""),
        format!("curl \"https://h/a?token={MARKER}\" next"),
        // The script of `sh -c`, with escaped quotes and quotes of the other kind inside.
        format!("sh -c \"A=1 SECRET=a\\\" {MARKER} B=2\" tail"),
        format!("sh -c \"export SECRET=\\\"two {MARKER}\\\"\""),
        format!("sh -c \"env 'TOKEN=a {MARKER}' cmd\" tail"),
        format!("sh -c \"tool --password \\\"a {MARKER}\\\"\" tail"),
        format!("sh -c \"tool --password {MARKER}\""),
        // An apostrophe in a path before the credential, with a later quote or none.
        format!("/Users/Tom's Tools/o'neil/run TOKEN='abc {MARKER} def'"),
        format!("/Users/Tom's Tools/o'neil/run --password 'abc {MARKER}'"),
        format!("/Users/Tom's Tools/run TOKEN='abc {MARKER} def'"),
        format!("/Users/Tom's x \"PASSWORD=a {MARKER}\" y/o'neil"),
        format!("/Users/Tom's x TOKEN='abc {MARKER}' y/o'neil"),
        format!("/Users/Tom's x --password 'abc {MARKER}' y/o'neil"),
        format!("/Users/Tom's x TOKEN=a'b {MARKER}'c y/o'neil"),
        format!("/Users/Tom's x TOKEN=abc' {MARKER} y/o"),
        format!("/Users/Tom's x TOKEN=' {MARKER} y/o"),
        format!("/Users/Tom's x --password abc' {MARKER} y/o"),
        format!("/Users/Tom's x TOKEN=abc {MARKER} y/o'neil"),
        format!("/Users/o'neil/x's TOKEN=a{MARKER}"),
        format!("/Users/o'neil/x's --password {MARKER}"),
        // The apostrophe that a later quote closes is the opening quote of the argument.
        format!("/Users/Tom's x 'TOKEN=abc {MARKER}' z/o'neil"),
        format!("/Users/Tom's x 'tool --password abc {MARKER}' z/o'neil"),
        format!("/Users/Tom's \"x o'neil TOKEN=abc {MARKER}\" z a\"b"),
        format!("a\"b x \"TOKEN=abc {MARKER}\" c\"d"),
        format!("a\"b TOKEN=x {MARKER}\""),
        format!("echo prefix\" TOKEN=abc {MARKER}\" tail"),
        // A word-start apostrophe in a path, and a quote right at the end of the value.
        format!("/tmp/Rock 'n Roll/run TOKEN='abc {MARKER}' y/o'neil"),
        format!("/tmp/Rock 'n Roll/run --password 'abc {MARKER}' y/o'neil"),
        format!("/tmp/Rock 'n Roll/run TOKEN=abc' {MARKER}/y"),
        format!("/tmp/Rock 'n Roll/run TOKEN=' {MARKER}/y"),
        // A quote before the value that nothing closes: a truncated command.
        format!("/Users/Tom's/run 'TOKEN=abc {MARKER}"),
        format!("/tmp/Rock 'n Roll/run 'TOKEN=abc {MARKER}"),
        format!("/Users/Tom's/o'neil/run TOKEN=abc {MARKER}"),
        format!("FOO=\"a b\" TOKEN=x {MARKER} cmd"),
        // A value that starts with whitespace, in a quote that never closes.
        format!("sh -c \"TOKEN= {MARKER}"),
        format!("docker run -e \"PASSWORD= {MARKER}"),
        format!("env 'TOKEN= {MARKER}"),
        // An escaped quote before the value and the value's own quotes.
        format!("\\\"TOKEN=\"abc {MARKER}\""),
    ] {
        let said = redacted(&text);
        assert_eq!(
            said,
            format!("[withheld: {} characters]", text.chars().count()),
            "{text}"
        );
        assert!(!said.contains(MARKER), "{said}");
    }
    // A quote never closed after the value withholds the field, with a quote before it or not.
    let unclosed = format!("run -e \"PASSWORD=two {MARKER}");
    assert_eq!(
        redacted(&unclosed),
        format!("[withheld: {} characters]", unclosed.chars().count())
    );
}

/// KR-REQ-29.04: the controls of the rule above. With no quote before a value, nothing can
/// surround it and it is read as a word, and the text around it is as it was: the value's own
/// quotes, a quote after it, a name that holds no credential, a quote with no credential in the
/// field.
#[test]
fn a_value_with_no_quote_before_it_is_replaced_and_its_neighbours_stay() {
    for (text, expected) in [
        (
            format!("TOKEN='a b {MARKER}' next \"x\""),
            "TOKEN=[redacted] next \"x\"".to_owned(),
        ),
        (
            format!("--password 'abc {MARKER}' and 'next'"),
            "--password [redacted] and 'next'".to_owned(),
        ),
        (
            format!("run TOKEN={MARKER} 'next arg'"),
            "run TOKEN=[redacted] 'next arg'".to_owned(),
        ),
        (
            format!("git commit --password {MARKER} -m \"x y\""),
            "git commit --password [redacted] -m \"x y\"".to_owned(),
        ),
        (
            format!("TOKEN={MARKER} /Users/Tom's x/o'neil"),
            "TOKEN=[redacted] /Users/Tom's x/o'neil".to_owned(),
        ),
    ] {
        let said = redacted(&text);
        assert_eq!(said, expected, "{text}");
        assert!(!said.contains(MARKER), "{said}");
    }
    // An apostrophe nothing closes, with a credential in the text, withholds the field whether or
    // not a quote comes before the value; without a credential the text is untouched.
    let open = format!("/Users/Tom's Tools/run TOKEN={MARKER}");
    assert_eq!(
        redacted(&open),
        format!("[withheld: {} characters]", open.chars().count())
    );
    assert_eq!(redacted("/Users/Tom's Tools/run"), "/Users/Tom's Tools/run");
    assert_eq!(redacted("echo 'a' \"b\""), "echo 'a' \"b\"");
}

/// KR-REQ-29.04: a quote in the home directory is a quote before the credential that follows it,
/// even though the home is replaced: whether the field is withheld is decided in the text as it was
/// written.
#[test]
fn a_quote_in_the_home_directory_is_a_quote_before_the_credential() {
    for text in [
        format!("'/home/o'neil' TOKEN=abc {MARKER}"),
        format!("/home/o'neil/run TOKEN=abc {MARKER}\\' next"),
        format!("/home/o'neil/run --password abc {MARKER} tail'"),
    ] {
        let said = field(&text, Some("/home/o'neil"), UNIX);
        assert_eq!(
            said,
            format!("[withheld: {} characters]", text.chars().count()),
            "{text}"
        );
    }
    // With no credential the home is replaced as before, apostrophe and all.
    assert_eq!(
        field("/home/o'neil/work", Some("/home/o'neil"), UNIX),
        "[home]/work"
    );
}

/// KR-REQ-29.04: a credential whose value starts in the home directory does not cut the home in two:
/// which spans are replaced is read in the text with the home replaced, so no part of a home that
/// holds a space, or a credential, stays in the text.
#[test]
fn a_credential_value_that_starts_in_the_home_directory_leaves_no_part_of_it() {
    for (home, paths, text, expected) in [
        (
            "/home/john smith",
            UNIX,
            format!("TOKEN=/home/john smith/{MARKER}"),
            "TOKEN=[redacted]",
        ),
        (
            "C:\\Users\\John Smith",
            WINDOWS,
            format!("tool --auth-sock C:\\Users\\John Smith\\.ssh\\{MARKER}"),
            "tool --auth-sock [redacted]",
        ),
        (
            "C:\\Users\\John Smith",
            WINDOWS,
            format!("--token C:\\Users\\John Smith\\{MARKER}"),
            "--token [redacted]",
        ),
        // A home that holds an assignment: the home is replaced whole.
        (
            "/Users/Alice TOKEN=x",
            UNIX,
            "/Users/Alice TOKEN=x/work".to_owned(),
            "[home]/work",
        ),
    ] {
        let said = field(&text, Some(home), paths);
        assert_eq!(said, expected, "{text}");
        assert!(!said.contains(MARKER), "{said}");
        assert!(!said.contains("Smith") && !said.contains("Alice"), "{said}");
    }
}

/// Where the word that holds the value starting at `start` ends when each quote character before
/// `start` is a quote (`structural`) or an ordinary character, as a shell reads the quotes that are
/// quotes: at the first whitespace outside a quote, with a backslash escaping the next character
/// outside single quotes; a quote that is open at the end of the text runs the word to the end of
/// it. Every quote character at or after `start` is a quote. With it, the offset of the quote that
/// closes the argument the value is in, when one does.
fn word_end_when(text: &str, start: usize, structural: &[bool]) -> (usize, Option<usize>) {
    let characters: Vec<(usize, char)> = text.char_indices().collect();
    let mut ordinal = 0;
    let mut open: Option<(char, usize)> = None;
    let mut closing = None;
    let mut index = 0;
    let quote_character = |ordinal: &mut usize, offset: usize, character: char| {
        let is_quote = matches!(character, '\'' | '"');
        let quote = is_quote && (offset >= start || structural[*ordinal]);
        if is_quote && offset < start {
            *ordinal += 1;
        }
        quote
    };
    while index < characters.len() {
        let (offset, character) = characters[index];
        let quote_here = quote_character(&mut ordinal, offset, character);
        match open {
            Some((quote, opened)) => {
                if quote_here && character == quote {
                    open = None;
                    if offset >= start && opened < start {
                        closing = Some(offset);
                    }
                } else if quote == '"' && character == '\\' {
                    index += 1;
                    if let Some(&(next_offset, next)) = characters.get(index) {
                        quote_character(&mut ordinal, next_offset, next);
                    }
                }
            }
            None => {
                if quote_here {
                    open = Some((character, offset));
                } else if character == '\\' {
                    index += 1;
                    if let Some(&(next_offset, next)) = characters.get(index) {
                        quote_character(&mut ordinal, next_offset, next);
                    }
                } else if matches!(character, ' ' | '\t' | '\n') && offset >= start {
                    return (offset, closing);
                }
            }
        }
        index += 1;
    }
    (text.len(), closing)
}

/// KR-REQ-29.04: no reading of the quotes before a value leaves it in the text. A quote before a
/// credential is a quote or a character of a path (`Tom's`, `Rock 'n Roll`), and the text cannot
/// say which. So for every text built from quotes, backslashes, spaces and letters with one
/// credential in it, and for every way of reading each quote character before the credential as a
/// quote or as an ordinary character, the value that reading gives is replaced whole, or the field
/// is withheld. A reading that leaves a quote open runs the value to the end of the text. The check
/// tries every reading; it does not name the inputs a reviewer found. Quotes in the value itself
/// are read as a shell reads them.
#[test]
fn no_reading_of_the_quotes_before_a_value_leaves_it_in_the_text() {
    const PIECES: [&str; 7] = ["a", "b", " ", "'", "\"", "\\", "  "];
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move |bound: usize| {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(seed >> 33).unwrap_or(0) % bound
    };
    let mut readings = 0_u64;
    let mut leaks = Vec::new();
    for _ in 0..400_000 {
        let length = 4 + next(9);
        let mut pieces: Vec<&str> = (0..length).map(|_| PIECES[next(PIECES.len())]).collect();
        let credential = if next(2) == 0 {
            "TOKEN="
        } else {
            "--password "
        };
        pieces.insert(next(pieces.len() + 1), credential);
        let text = pieces.concat();
        let at = text.find(credential).expect("the credential was inserted");
        // The option form is read at the start of a word.
        if credential == "--password "
            && text[..at]
                .chars()
                .next_back()
                .is_some_and(|before| !before.is_whitespace())
        {
            continue;
        }
        let said = redacted(&text);
        if said.starts_with("[withheld: ") {
            continue;
        }
        let replaced_to = said
            .find(REDACTED)
            .map(|position| text.len() - said[position + REDACTED.len()..].len());
        // The value of an option starts after the whitespace that follows its name, and a reading
        // may take that whitespace into the value. An assignment's value starts at the `=`: with
        // whitespace right after it the value is empty.
        let after = at + credential.len();
        let skipped = after + text[after..].len() - text[after..].trim_start().len();
        let starts = if credential == "TOKEN=" {
            vec![after]
        } else {
            vec![after, skipped]
        };
        for start in starts {
            // Nothing replaced means nothing taken as a value: it ends where it starts.
            let kept = replaced_to.unwrap_or(start);
            let before = text[..start]
                .chars()
                .filter(|c| matches!(c, '\'' | '"'))
                .count();
            for mask in 0..(1_u32 << before) {
                let structural: Vec<bool> = (0..before).map(|bit| mask >> bit & 1 == 1).collect();
                let (end, closing) = word_end_when(&text, start, &structural);
                readings += 1;
                // The quote that closes the argument the credential is in is not part of the value.
                let required = match closing {
                    Some(offset) if offset + 1 == end => offset,
                    _ => end,
                };
                // Whitespace left after the value is not a secret.
                if kept < required && !text[kept..required].trim().is_empty() {
                    leaks.push(format!(
                        "{text:?} -> {said:?} (reading {mask:b} from {start}: value to {required})"
                    ));
                }
            }
        }
    }
    assert!(readings > 150_000, "the check made {readings} readings");
    assert!(
        leaks.is_empty(),
        "{} leaks, first: {:?}",
        leaks.len(),
        &leaks[..leaks.len().min(5)]
    );
}

/// KR-REQ-29.04: a no-break space is a character of its word, as it is to a shell: a value that
/// holds one is replaced to the end of the word.
#[test]
fn a_no_break_space_does_not_end_a_value() {
    let text = format!("TOKEN=a\u{a0}{MARKER} next");
    assert_eq!(redacted(&text), "TOKEN=[redacted] next");
}

/// KR-REQ-29.04: only the space, tab and newline a shell splits on end a value: a carriage return
/// is a character of its word, so what follows it is still the value.
#[test]
fn a_carriage_return_does_not_end_a_value() {
    let text = format!("TOKEN=abc\r{MARKER} next");
    assert_eq!(redacted(&text), "TOKEN=[redacted] next");
}

/// KR-REQ-29.04: the merge of overlapping spans, on spans made by hand, because a shell-word reading
/// makes the scanners' own spans nest: a later span that ends inside, at, or after the end of an
/// earlier one, spans that only touch, and spans in any order.
#[test]
fn spans_are_merged_whatever_their_order_and_overlap() {
    let text = "0123456789abcdefghij";
    let span = |start, end, with| Span { start, end, with };
    for (spans, expected) in [
        (vec![span(2, 6, "A")], "01A6789abcdefghij"),
        (vec![span(2, 6, "A"), span(4, 9, "B")], "01A9abcdefghij"),
        (vec![span(4, 9, "B"), span(2, 6, "A")], "01A9abcdefghij"),
        (vec![span(2, 8, "A"), span(4, 6, "B")], "01A89abcdefghij"),
        (vec![span(2, 6, "A"), span(2, 6, "B")], "01A6789abcdefghij"),
        (vec![span(2, 6, "A"), span(6, 9, "B")], "01AB9abcdefghij"),
        (
            vec![span(0, 3, "A"), span(10, 12, "B")],
            "A3456789Bcdefghij",
        ),
        (
            vec![span(2, 4, "A"), span(3, 12, "B"), span(11, 15, "C")],
            "01Afghij",
        ),
        (Vec::new(), text),
    ] {
        let count = spans.len();
        assert_eq!(replace_spans(text, spans), expected, "{count} spans");
    }
}

/// KR-REQ-29.04: an apostrophe is a valid character of URL user information, and a quote around the
/// whole argument is not part of it: both forms lose the user information, and a URL with none keeps
/// its text, quotes and all.
#[test]
fn user_information_with_an_apostrophe_is_taken_out_inside_quotes() {
    for (text, expected) in [
        (
            format!("--url=\"https://o'neil:{MARKER}@host/\""),
            "--url=\"https://[redacted]@host/\"".to_owned(),
        ),
        (
            format!("'https://user:{MARKER}@host'"),
            "'https://[redacted]@host'".to_owned(),
        ),
        (
            format!("\"https://user:{MARKER}@host:8443/x?y=z\""),
            "\"https://[redacted]@host:8443/x?y=z\"".to_owned(),
        ),
        // The form Windows proxies are written in: a backslash is part of the user information.
        (
            format!("http_proxy=http://CORP\\alice:{MARKER}@proxy:8080"),
            "http_proxy=http://[redacted]@proxy:8080".to_owned(),
        ),
    ] {
        let said = redacted(&text);
        assert_eq!(said, expected, "{text}");
        assert!(!said.contains(MARKER), "{said}");
    }
    assert_eq!(
        redacted("\"https://host/a?mail=x@y.z\""),
        "\"https://host/a?mail=x@y.z\""
    );
}

/// KR-REQ-29.04: a run of capitals ends before the capital a lower-case letter follows, so
/// `HTTPAuth` and `SSHKey` say credential, and a name that only looks like one does not.
#[test]
fn a_name_is_split_before_the_last_capital_of_a_run() {
    for name in [
        "HTTPAuth",
        "SSHKey",
        "xAuthKey",
        "OAuthToken",
        "DB_PASS",
        "dbPass",
    ] {
        assert!(says_credential(name), "{name}");
    }
    for name in [
        "HTTPS",
        "HTTPHost",
        "PASSENGER",
        "Keyboard",
        "AUTHOR",
        "monkeyTime",
    ] {
        assert!(!says_credential(name), "{name}");
    }
    assert_eq!(parts("HTTPAuth"), ["http", "auth"]);
    assert_eq!(parts("accessKeyId"), ["access", "key", "id"]);
}

/// KR-REQ-29.04: on Windows the verbatim prefix before a drive does not hide the home directory,
/// `;` separates values as `:` does, and a drive's own root is a root and is never replaced.
#[test]
fn windows_paths_the_home_directory_can_sit_in() {
    let home = Some("C:\\Users\\Tom");
    assert_eq!(
        field("\\\\?\\C:\\Users\\Tom\\work", home, WINDOWS),
        "\\\\?\\[home]\\work"
    );
    assert_eq!(
        field("PATH=C:\\bin;C:\\Users\\Tom\\bin", home, WINDOWS),
        "PATH=C:\\bin;[home]\\bin"
    );
    for root in ["C:\\", "C:", "D:/"] {
        assert_eq!(
            field("C:\\Windows\\System32", Some(root), WINDOWS),
            "C:\\Windows\\System32",
            "{root}"
        );
    }
    // Case folds beyond ASCII where the platform folds case.
    assert_eq!(
        field(
            "c:\\users\\\u{c9}milie\\x",
            Some("C:\\Users\\\u{e9}milie"),
            WINDOWS
        ),
        "[home]\\x"
    );
    assert_eq!(
        field(
            "c:\\users\\\u{c9}milie\\x",
            Some("C:\\Users\\\u{e9}milie"),
            UNIX
        ),
        "c:\\users\\\u{c9}milie\\x"
    );
    // The two lower-case sigmas are one letter to the file system, and so is the Kelvin sign and
    // `k`: a match under either folding is a match.
    for (text, home) in [
        ("c:\\users\\\u{3c2}\\work", "C:\\Users\\\u{3a3}"),
        ("c:\\users\\\u{3c3}\\work", "C:\\Users\\\u{3a3}"),
        ("c:\\users\\k\\work", "C:\\Users\\\u{212a}"),
    ] {
        assert_eq!(field(text, Some(home), WINDOWS), "[home]\\work", "{text}");
    }
}

/// KR-REQ-29.04: hostile text never panics a rule: every cut falls on a character boundary and
/// every position is in range, whatever the characters are.
#[test]
fn hostile_and_non_ascii_text_is_handled_without_a_panic() {
    for text in [
        "",
        "=",
        "==",
        "--",
        "-- ",
        "TOKEN=",
        "TOKEN=\"",
        "TOKEN='",
        "--password",
        "--password ",
        "://",
        "://@",
        "https://@",
        "https://@@@/",
        "\u{e9}TOKEN=\u{e9}\u{e9}",
        "TOKEN=\u{202e}\u{200b}x y",
        "--p\u{e4}ssword x",
        "\u{1f600}=\u{1f600} --token \u{1f600}",
        "/home/tom\u{301}/x",
        "[home]/[redacted]@[withheld",
    ] {
        let said = redacted(text);
        assert!(!said.contains(MARKER), "{text:?}");
        let again = redacted(&said);
        assert_eq!(again, said, "{text:?}: redacting twice is redacting once");
    }
}
