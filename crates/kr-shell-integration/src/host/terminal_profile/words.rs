//! The command a profile runs, as the text an emulator splits into words again.
//!
//! A profile holds its command as one string, and the emulator splits it itself. Quoting is
//! therefore two layers: the file or setting's own syntax, which the writer for it handles, and the
//! emulator's parse of the command string, which is here. Single quotes keep every character
//! literal to the parsers that read a shell's words (Konsole's, iTerm2's, GNOME's
//! `g_shell_parse_argv`, and a shell itself), and Windows has its own rules for a command line.

use crate::contract::qualification::ShellKind;
use crate::host::quoting::quote;

/// The vector as one string that a parser of shell words splits back into it.
#[must_use]
pub fn shell_words(vector: &[String]) -> String {
    vector
        .iter()
        .map(|word| quote(ShellKind::Bash, word))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The vector as one Windows command line, quoted the way the standard argument parser of a
/// Windows program reads it back: a word with a space, a tab or a quote in it, or no characters at
/// all, is wrapped in double quotes; a quote in it is escaped with a backslash; the backslashes
/// that come before a quote, and those at the end of a wrapped word, are doubled.
#[must_use]
pub fn command_line(vector: &[String]) -> String {
    vector
        .iter()
        .map(|word| windows_word(word))
        .collect::<Vec<_>>()
        .join(" ")
}

/// One word of a Windows command line.
fn windows_word(word: &str) -> String {
    if !word.is_empty() && !word.contains([' ', '\t', '\n', '\u{b}', '"']) {
        return word.to_owned();
    }
    let mut quoted = String::with_capacity(word.len() + 2);
    quoted.push('"');
    let mut backslashes = 0_usize;
    for character in word.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                // The backslashes before a quote are doubled, and the quote is escaped.
                quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            other => {
                quoted.extend(std::iter::repeat_n('\\', backslashes));
                quoted.push(other);
                backslashes = 0;
            }
        }
    }
    // Backslashes at the end of the word would escape the closing quote.
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

/// Whether Konsole would expand something in `word` before it ran: a variable, or a leading `~`.
///
/// A profile cannot say that such a word is literal, so a command that holds one is not written.
#[must_use]
pub fn konsole_would_expand(word: &str) -> bool {
    word.contains('$') || word.starts_with('~')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector(kr: &str) -> Vec<String> {
        [kr, "new", "--attach", "--hold-on-failure"]
            .map(str::to_owned)
            .to_vec()
    }

    /// The words the quoting produces, for paths the macOS store has (a space) and the characters
    /// that a shell's parser treats as its own.
    #[test]
    fn shell_words_quote_the_characters_a_parser_reads_as_its_own() {
        for (kr, expected) in [
            (
                "/opt/kr/bin/kr",
                "/opt/kr/bin/kr new --attach --hold-on-failure",
            ),
            (
                "/Users/a b/Library/Application Support/kr/current/bin/kr",
                "'/Users/a b/Library/Application Support/kr/current/bin/kr' new --attach --hold-on-failure",
            ),
            (
                "/o'brien/kr",
                r"'/o'\''brien/kr' new --attach --hold-on-failure",
            ),
            (r#"/a"b/kr"#, r#"'/a"b/kr' new --attach --hold-on-failure"#),
            (r"/a\b/kr", r"'/a\b/kr' new --attach --hold-on-failure"),
            ("/a$b/kr", "'/a$b/kr' new --attach --hold-on-failure"),
            (
                "/caf\u{e9}/kr",
                "'/caf\u{e9}/kr' new --attach --hold-on-failure",
            ),
        ] {
            assert_eq!(shell_words(&vector(kr)), expected, "{kr}");
        }
    }

    /// A Windows command line, quoted for the standard argument parser.
    #[test]
    fn a_windows_command_line_is_quoted_for_the_standard_parser() {
        for (kr, expected) in [
            (
                r"C:\Users\a\kr.exe",
                r"C:\Users\a\kr.exe new --attach --hold-on-failure",
            ),
            (
                r"C:\Program Files\kr\kr.exe",
                r#""C:\Program Files\kr\kr.exe" new --attach --hold-on-failure"#,
            ),
            (
                r#"C:\a "b"\kr.exe"#,
                r#""C:\a \"b\"\kr.exe" new --attach --hold-on-failure"#,
            ),
            (
                r"C:\dir with space\",
                r#""C:\dir with space\\" new --attach --hold-on-failure"#,
            ),
        ] {
            assert_eq!(command_line(&vector(kr)), expected, "{kr}");
        }
    }

    /// Konsole expands a variable and a leading `~` in what it runs.
    #[test]
    fn konsole_expands_a_variable_and_a_leading_tilde() {
        assert!(konsole_would_expand("/a/$HOME/kr"));
        assert!(konsole_would_expand("~/kr"));
        assert!(!konsole_would_expand("/a/~/kr"));
        assert!(!konsole_would_expand("/Users/a b/kr"));
    }
}
