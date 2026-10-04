//! The forwarder a package registers, written by the host.
//!
//! A package that has an application start the KalaReach forwarder, `kr-hook`, cannot know where
//! the host installed it, and an application that finds the forwarder by its bare name looks in
//! its own working directory first on some platforms, so a program planted there would run in its
//! place. The package therefore writes [`PLACEHOLDER`] where it runs the forwarder, and the host
//! writes the installed forwarder's absolute path in its place, quoted for where it stands:
//!
//! * `"command": "{kr_hook}"`, with the arguments in a list beside it, is an executable named
//!   whole. The path is written as the text of a JSON string and nothing else, because the
//!   application starts the program directly and reads no shell syntax.
//! * `"command": "{kr_hook} gemini-cli hook"` is a line a POSIX shell runs. The path is written as
//!   one word in single quotes, an apostrophe inside it as `'\''`, and then as the text of a JSON
//!   string, so the shell reads the path as one word whatever characters it holds.
//!
//! The placeholder stands at the start of a JSON string and nowhere else: a package that writes it
//! in the middle of a word, or after anything but an opening quotation mark, has written something
//! the host cannot replace without guessing what it means, and the host refuses it. The same
//! function serves a registration file and a flag whose value is a JSON document (Qoder CLI's
//! inline settings), since in both the placeholder stands inside a JSON string.

use std::path::Path;

/// The text a package writes where it runs the forwarder.
pub const PLACEHOLDER: &str = "{kr_hook}";

/// Why a text could not be written with the forwarder's path.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExpandError {
    /// The forwarder's path is not text, so it cannot be written into a document.
    #[error("the installed forwarder's path is not text")]
    NotText,
    /// There is no installed forwarder to write.
    #[error("this installation has no forwarder to write where the package runs it")]
    NoForwarder,
    /// The placeholder stands somewhere the host cannot replace it.
    #[error(
        "{PLACEHOLDER} stands at byte {at}, which is not the start of a JSON string followed by \
         the end of that string or a space"
    )]
    Misplaced {
        /// Where the placeholder starts, in bytes.
        at: usize,
    },
}

/// Returns true when `text` holds the placeholder.
#[must_use]
pub fn mentions(text: &str) -> bool {
    text.contains(PLACEHOLDER)
}

/// Returns `text` with every placeholder replaced by `forwarder`, quoted for where it stands.
///
/// A text that holds no placeholder is returned as it is.
///
/// # Errors
///
/// Returns [`ExpandError::NotText`] when `forwarder` is not text, and [`ExpandError::Misplaced`]
/// for a placeholder that is not at the start of a JSON string, followed by the end of that string
/// or a space.
pub fn expand(text: &str, forwarder: &Path) -> Result<String, ExpandError> {
    if !mentions(text) {
        return Ok(text.to_owned());
    }
    let path = forwarder.to_str().ok_or(ExpandError::NotText)?;
    let exec = json_text(path);
    let shell = json_text(&posix_word(path));
    let mut expanded = String::with_capacity(text.len() + exec.len());
    let mut rest = text;
    let mut consumed = 0;
    while let Some(offset) = rest.find(PLACEHOLDER) {
        let at = consumed + offset;
        let before = &rest[..offset];
        let after = &rest[offset + PLACEHOLDER.len()..];
        // The start of a string: an opening quotation mark that is not itself the end of a
        // backslash escape. In a document these two are the only places this host writes a path.
        let opens = before.ends_with('"') && !escaped(&text[..at - 1]);
        let form = match after.chars().next() {
            Some('"') => Some(&exec),
            Some(' ') => Some(&shell),
            _ => None,
        };
        let Some(form) = form.filter(|_| opens) else {
            return Err(ExpandError::Misplaced { at });
        };
        expanded.push_str(before);
        expanded.push_str(form);
        rest = after;
        consumed = at + PLACEHOLDER.len();
    }
    expanded.push_str(rest);
    Ok(expanded)
}

/// Returns true when the character after `before` is escaped by an odd run of backslashes ending
/// `before`.
fn escaped(before: &str) -> bool {
    before
        .bytes()
        .rev()
        .take_while(|byte| *byte == b'\\')
        .count()
        % 2
        == 1
}

/// Returns `flags` with every placeholder replaced by the forwarder's path, as [`expand`] does for
/// each one.
///
/// A host that has no forwarder to write refuses a flag that names one; a flag that does not is
/// returned as it is, so an integration that never needed the forwarder does not wait for one.
///
/// # Errors
///
/// Returns [`ExpandError::NoForwarder`] when a flag holds the placeholder and `forwarder` is
/// `None`, and what [`expand`] returns otherwise.
pub fn expand_flags(
    flags: &[String],
    forwarder: Option<&Path>,
) -> Result<Vec<String>, ExpandError> {
    flags
        .iter()
        .map(|flag| {
            if !mentions(flag) {
                return Ok(flag.clone());
            }
            expand(flag, forwarder.ok_or(ExpandError::NoForwarder)?)
        })
        .collect()
}

/// Writes `text` as the inside of a JSON string.
fn json_text(text: &str) -> String {
    let quoted = serde_json::to_string(text).unwrap_or_default();
    quoted
        .strip_prefix('"')
        .and_then(|inside| inside.strip_suffix('"'))
        .unwrap_or_default()
        .to_owned()
}

/// Writes `text` as one word a POSIX shell reads as itself: in single quotes, an apostrophe inside
/// them closed, escaped and opened again.
#[must_use]
pub fn posix_word(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Paths a person's machine can have: spaces, a drive and backslashes, an apostrophe, a
    /// dollar sign, a backtick, an ampersand, a percent sign, a semicolon, a double quotation mark,
    /// a newline, non-ASCII text, and the shapes an attacker would pick to end a quotation early.
    const PATHS: &[&str] = &[
        "/usr/local/kalareach/current/bin/kr-hook",
        "/Users/some one/Library/Application Support/KalaReach/current/bin/kr-hook",
        r"C:\Program Files\KalaReach\current\bin\kr-hook.exe",
        r"C:\Users\O'Brien\AppData\Local\KalaReach\bin\kr-hook.exe",
        "/home/me/it's here/kr-hook",
        "/home/me/$HOME/`id`/kr-hook",
        "/home/me/a&b;c|d>e<f/kr-hook",
        r"C:\100%\^caret\kr-hook.exe",
        "/home/me/a\"b/kr-hook",
        "/home/me/a\nb/kr-hook",
        "/home/me/\u{e9}\u{4e2d}\u{1f600}/kr-hook",
        "/tmp/x'; touch /tmp/planted; '/kr-hook",
        r"\\server\share\kr-hook.exe",
        r"C:\a\\b\kr-hook.exe",
    ];

    fn decoded(json: &str) -> serde_json::Value {
        serde_json::from_str(json).expect("the expansion is JSON")
    }

    #[test]
    fn a_command_written_whole_decodes_to_the_path() {
        for path in PATHS {
            let template = r#"{"command": "{kr_hook}", "args": ["claude-code", "hook"]}"#;
            let expanded = expand(template, Path::new(path)).expect("expands");
            assert_eq!(decoded(&expanded)["command"], *path, "{path}");
            assert_eq!(
                decoded(&expanded)["args"],
                serde_json::json!(["claude-code", "hook"]),
                "{path}"
            );
        }
    }

    #[test]
    fn a_shell_line_decodes_to_the_path_as_one_word_and_the_rest_as_it_was() {
        for path in PATHS {
            let template = r#"{"command": "{kr_hook} gemini-cli hook", "timeout": 5000}"#;
            let expanded = expand(template, Path::new(path)).expect("expands");
            let line = decoded(&expanded)["command"]
                .as_str()
                .expect("a line")
                .to_owned();
            assert_eq!(
                line,
                format!("{} gemini-cli hook", posix_word(path)),
                "{path}"
            );
            assert_eq!(decoded(&expanded)["timeout"], 5000);
        }
    }

    #[test]
    fn a_flag_that_is_a_json_document_is_written_the_same_way() {
        let flag = r#"{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"{kr_hook}","args":["qoder-cli","hook"],"timeout":5}]}]}}"#;
        for path in PATHS {
            let expanded = expand(flag, Path::new(path)).expect("expands");
            let document = decoded(&expanded);
            assert_eq!(
                document["hooks"]["SessionStart"][0]["hooks"][0]["command"], *path,
                "{path}"
            );
        }
    }

    #[test]
    fn every_placeholder_of_a_document_is_replaced() {
        let template =
            r#"{"a": {"command": "{kr_hook}"}, "b": {"command": "{kr_hook}"}, "c": "{kr_hook} x"}"#;
        let expanded = expand(template, Path::new("/opt/kr-hook")).expect("expands");
        assert!(!mentions(&expanded), "{expanded}");
        assert_eq!(decoded(&expanded)["b"]["command"], "/opt/kr-hook");
        assert_eq!(decoded(&expanded)["c"], "'/opt/kr-hook' x");
    }

    #[test]
    fn a_text_without_the_placeholder_is_returned_as_it_is() {
        let text = "{\n  \"command\": \"kr-hook\"\n}\n";
        assert_eq!(expand(text, Path::new("/opt/kr-hook")).as_deref(), Ok(text));
    }

    #[test]
    fn a_placeholder_anywhere_else_is_refused() {
        for template in [
            r#"{"command": "x{kr_hook}"}"#,
            r#"{"command": "{kr_hook}x"}"#,
            r#"{"command": "a {kr_hook}"}"#,
            r#"{"command": "{kr_hook}{kr_hook}"}"#,
            r#"{"command": "\"{kr_hook}\""}"#,
            r#"{"command": "{kr_hook}\t"}"#,
            "{kr_hook}",
            r#"{"command": ["{kr_hook}", "hook"], "x": {kr_hook}}"#,
        ] {
            assert!(
                matches!(
                    expand(template, Path::new("/opt/kr-hook")),
                    Err(ExpandError::Misplaced { .. })
                ),
                "{template}"
            );
        }
    }

    #[test]
    fn the_error_names_where_the_first_misplaced_placeholder_is() {
        let template = r#"{"a": "{kr_hook}", "b": "x{kr_hook}"}"#;
        assert_eq!(
            expand(template, Path::new("/opt/kr-hook")),
            Err(ExpandError::Misplaced {
                at: template.rfind(PLACEHOLDER).expect("present")
            })
        );
    }

    #[test]
    fn flags_are_expanded_one_by_one_and_a_missing_forwarder_is_refused_only_where_one_is_named() {
        let flags = vec![
            "--settings".to_owned(),
            r#"{"command":"{kr_hook}"}"#.to_owned(),
            "--other".to_owned(),
        ];
        assert_eq!(
            expand_flags(&flags, Some(Path::new("/opt/kr hook"))),
            Ok(vec![
                "--settings".to_owned(),
                r#"{"command":"/opt/kr hook"}"#.to_owned(),
                "--other".to_owned(),
            ])
        );
        assert_eq!(expand_flags(&flags, None), Err(ExpandError::NoForwarder));
        assert_eq!(
            expand_flags(&flags[..1], None),
            Ok(vec!["--settings".to_owned()]),
            "flags that name no forwarder need none"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_text_is_refused() {
        use std::os::unix::ffi::OsStrExt as _;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"/opt/\xff/kr-hook"));
        assert_eq!(
            expand(r#"{"command": "{kr_hook}"}"#, path),
            Err(ExpandError::NotText)
        );
    }
}
