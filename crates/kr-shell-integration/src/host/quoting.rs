//! Turning a launch into the exact text one shell's editor will hold.
//!
//! Two rules decide everything here. The argument vector is preserved literally: every argument the
//! caller named is one word to the shell, whatever it contains. And `eval` is never used: the text
//! that reaches the editor is the command itself, so what the person sees on the line is what runs.
//!
//! The quoting is per shell because the languages differ. Bourne-family shells and Zsh take single
//! quotes with `'\''` for an embedded quote; Fish takes single quotes and escapes `\` and `'`;
//! PowerShell takes single quotes and doubles an embedded one. A command the caller has already
//! quoted for its target shell is passed through untouched, because it is already the exact text to
//! run.

use kr_protocol::root::LaunchCommand;

use crate::contract::qualification::ShellKind;

/// Returns the text a launch installs in this shell's editor.
///
/// # Examples
///
/// ```
/// use kr_protocol::root::LaunchCommand;
/// use kr_shell_integration::contract::qualification::ShellKind;
/// use kr_shell_integration::host::quoting::install_text;
///
/// let command = LaunchCommand::Arguments(vec![
///     "git".to_owned(),
///     "commit".to_owned(),
///     "-m".to_owned(),
///     "it's done".to_owned(),
/// ]);
/// assert_eq!(
///     install_text(ShellKind::Zsh, &command),
///     r"git commit -m 'it'\''s done'"
/// );
/// assert_eq!(
///     install_text(ShellKind::PowerShell, &command),
///     "git commit -m 'it''s done'"
/// );
/// ```
#[must_use]
pub fn install_text(kind: ShellKind, command: &LaunchCommand) -> String {
    match command {
        // Already the exact text to run, in that shell's own language. Quoting it again would
        // change what it means.
        LaunchCommand::QuotedCommand(text) => text.clone(),
        LaunchCommand::Arguments(arguments) => arguments
            .iter()
            .map(|argument| quote(kind, argument))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

/// Returns one argument as a single literal word in this shell.
#[must_use]
pub fn quote(kind: ShellKind, argument: &str) -> String {
    if !argument.is_empty() && argument.chars().all(is_bare) {
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

/// Returns true for a character that needs no quoting in any of the four shells.
const fn is_bare(character: char) -> bool {
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
    fn nothing_is_wrapped_in_eval() {
        let command = LaunchCommand::Arguments(vec!["ls".to_owned(), "-la".to_owned()]);
        for kind in ShellKind::ALL {
            let text = install_text(*kind, &command);
            assert_eq!(text, "ls -la");
            assert!(!text.contains("eval"), "{kind} used eval");
            assert!(!text.contains("Invoke-Expression"), "{kind} used eval");
        }
    }

    #[test]
    fn a_quoted_command_is_installed_exactly_as_it_was_given() {
        let command = LaunchCommand::QuotedCommand("git log --oneline | head -20".to_owned());
        for kind in ShellKind::ALL {
            assert_eq!(
                install_text(*kind, &command),
                "git log --oneline | head -20"
            );
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

    #[test]
    fn an_empty_argument_is_still_one_word() {
        for kind in ShellKind::ALL {
            let quoted = quote(*kind, "");
            assert_eq!(quoted, "''", "{kind}");
        }
    }
}
