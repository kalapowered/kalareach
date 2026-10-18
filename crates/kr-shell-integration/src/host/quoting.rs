//! Quoting one word for one shell.
//!
//! The host writes a word into a shell's startup file, and it must reach that shell as the one
//! word the host named. Single quotes do that in every shell here, and what differs is the
//! embedded quote: Bourne-family shells and Zsh close the string, escape a quote and open it again
//! (`'\''`); Fish escapes `\` and `'` with a backslash; PowerShell doubles the quote.
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
        // PowerShell's single-quoted string is literal, and an embedded quote is doubled.
        ShellKind::PowerShell => format!("'{}'", argument.replace('\'', "''")),
    }
}

/// Returns true for a character that needs no quoting in this shell.
///
/// The set is the same everywhere but for `@`, which PowerShell reads at the start of a word as
/// splatting: `@payload` there is the contents of `$payload` rather than the two-character word
/// the person typed, and a word that is not preserved literally is not the argument vector the
/// caller named.
const fn is_bare(kind: ShellKind, character: char) -> bool {
    if matches!(kind, ShellKind::PowerShell) && character == '@' {
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

    /// KR-REQ-23.54: a word PowerShell would read as splatting is quoted rather than left bare.
    #[test]
    fn powershell_quotes_a_word_it_would_otherwise_expand() {
        assert_eq!(quote(ShellKind::PowerShell, "@payload"), "'@payload'");
        assert_eq!(quote(ShellKind::PowerShell, "a@b"), "'a@b'");
        // The other three read `@` as an ordinary character, so nothing about them changes.
        for kind in [ShellKind::Zsh, ShellKind::Bash, ShellKind::Fish] {
            assert_eq!(quote(kind, "@payload"), "@payload");
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
