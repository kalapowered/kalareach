//! Quoting one word for one shell.
//!
//! The host writes a word into a shell's startup file, and it must reach that shell as the one
//! word the host named. Single quotes do that in every shell here, and what differs is the
//! embedded quote: Bourne-family shells and Zsh close the string, escape a quote and open it again
//! (`'\''`); Fish escapes `\` and `'` with a backslash; PowerShell doubles each of the five
//! characters it reads as a single quote.
//!
//! A launch is not quoted here. The reader that installs it quotes the argument vector the caller
//! named, on the reader's own thread, in its own language, so a second quoting in the host would
//! be one more place for the two to differ.

use crate::contract::qualification::ShellKind;

/// Returns one argument as a single literal word in this shell.
#[must_use]
pub fn quote(kind: ShellKind, argument: &str) -> String {
    if !argument.is_empty() && argument.chars().all(|character| is_bare(kind, character)) {
        return argument.to_owned();
    }
    match kind {
        // A single-quoted string in a Bourne-family shell and in Zsh is entirely literal, including
        // backslashes and newlines. The one character it cannot hold is the quote itself, which is
        // written by closing the string, escaping a quote and opening it again.
        ShellKind::Zsh | ShellKind::Bash => format!("'{}'", argument.replace('\'', r"'\''")),
        // Fish's single quotes are literal except for `\` and `'`, both of which it escapes with a
        // backslash.
        ShellKind::Fish => format!("'{}'", argument.replace('\\', r"\\").replace('\'', r"\'")),
        // PowerShell's single-quoted string is literal, and an embedded quote is doubled. Five
        // characters are quotes to it: the ASCII one and the four typographic ones, and each ends
        // the string unless it is written twice.
        ShellKind::PowerShell => {
            let mut quoted = String::with_capacity(argument.len() + 2);
            quoted.push('\'');
            for character in argument.chars() {
                quoted.push(character);
                if is_powershell_quote(character) {
                    quoted.push(character);
                }
            }
            quoted.push('\'');
            quoted
        }
    }
}

/// Whether PowerShell reads this character as a single quote: U+0027 and the four typographic
/// single quotes U+2018, U+2019, U+201A and U+201B.
const fn is_powershell_quote(character: char) -> bool {
    matches!(
        character,
        '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}'
    )
}

/// Returns true for a character that needs no quoting in this shell.
///
/// The set is the same everywhere but for two characters in PowerShell. `@` at the start of a word
/// is splatting: `@payload` there is the contents of `$payload` rather than the two-character word
/// the person typed. `,` is the array operator: `a,b` there is a list of two words, and a path
/// with a comma in it is two arguments, or a command name cut short. A word that is not preserved
/// literally is not the argument vector the caller named.
const fn is_bare(kind: ShellKind, character: char) -> bool {
    if matches!(kind, ShellKind::PowerShell) && matches!(character, '@' | ',') {
        return false;
    }
    character.is_ascii_alphanumeric()
        || matches!(
            character,
            '.' | ',' | '_' | '+' | ':' | '@' | '%' | '/' | '-'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_argument_vector_stays_literal_in_every_shell() {
        let awkward = [
            "plain",
            "with space",
            "it's",
            "a\"b",
            "back\\slash",
            "$(rm -rf /)",
            "`id`",
            "new\nline",
            "*",
            "",
            "héllo wörld",
            ";",
            "&&",
            "|",
            ">",
        ];
        for kind in ShellKind::ALL {
            for argument in awkward {
                let quoted = quote(*kind, argument);
                assert!(
                    !quoted.is_empty(),
                    "{kind}: an empty argument still occupies a word"
                );
                // Nothing is ever expanded on the way in: the metacharacters are inside a quoted
                // string rather than at the top level.
                if argument.contains(['$', '`', '*', ';', '&', '|', '>', ' ']) {
                    assert!(
                        quoted.starts_with('\'') && quoted.ends_with('\''),
                        "{kind} left {argument:?} unquoted as {quoted:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn each_shell_escapes_its_own_quote_its_own_way() {
        assert_eq!(quote(ShellKind::Zsh, "it's"), r"'it'\''s'");
        assert_eq!(quote(ShellKind::Bash, "it's"), r"'it'\''s'");
        assert_eq!(quote(ShellKind::Fish, "it's"), r"'it\'s'");
        assert_eq!(quote(ShellKind::PowerShell, "it's"), "'it''s'");
        assert_eq!(quote(ShellKind::Fish, r"a\b"), r"'a\\b'");
        assert_eq!(quote(ShellKind::Bash, r"a\b"), r"'a\b'");
    }

    /// KR-REQ-23.54: PowerShell reads U+2018, U+2019, U+201A and U+201B as single quotes, so each
    /// is doubled like the ASCII one, and a word holding one cannot end its own string.
    #[test]
    fn powershell_doubles_every_character_it_reads_as_a_single_quote() {
        for quote_mark in ['\'', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'] {
            assert_eq!(
                quote(ShellKind::PowerShell, &format!("a{quote_mark}b")),
                format!("'a{quote_mark}{quote_mark}b'"),
                "{quote_mark:?}"
            );
        }
        assert_eq!(
            quote(ShellKind::PowerShell, "x\u{2019}; Write-Output y; \u{2019}"),
            "'x\u{2019}\u{2019}; Write-Output y; \u{2019}\u{2019}'"
        );
        // The other three shells read the typographic ones as ordinary characters.
        for kind in [ShellKind::Zsh, ShellKind::Bash, ShellKind::Fish] {
            assert_eq!(quote(kind, "it\u{2019}s"), "'it\u{2019}s'");
        }
    }

    /// KR-REQ-23.54: a word PowerShell would read as splatting is quoted rather than left bare.
    #[test]
    fn powershell_quotes_a_word_it_would_otherwise_expand() {
        assert_eq!(quote(ShellKind::PowerShell, "@payload"), "'@payload'");
        assert_eq!(quote(ShellKind::PowerShell, "a@b"), "'a@b'");
        // And so is a word PowerShell would read as a list.
        assert_eq!(
            quote(ShellKind::PowerShell, "/Users/a,b/x.ps1"),
            "'/Users/a,b/x.ps1'"
        );
        // The other three read `@` and `,` as ordinary characters, so nothing about them changes.
        for kind in [ShellKind::Zsh, ShellKind::Bash, ShellKind::Fish] {
            assert_eq!(quote(kind, "@payload"), "@payload");
            assert_eq!(quote(kind, "a,b"), "a,b");
        }
    }

    #[test]
    fn an_empty_argument_is_still_one_word() {
        for kind in ShellKind::ALL {
            let quoted = quote(*kind, "");
            assert_eq!(quoted, "''", "{kind}");
        }
    }
}
