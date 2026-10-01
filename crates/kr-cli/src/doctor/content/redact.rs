//! The rules that take what looks like a credential out of a session's text before the text is
//! shown or written.
//!
//! Section 29 asks for a preview and a redaction check before a real-content capture is exported,
//! and says that a filter is not a guarantee that no secret remains. These rules are that filter,
//! and they are written to be read: what each one takes out, and what it does not, is in this file
//! and in the preview a person sees before anything is written.
//!
//! One scanner reads a field's text and replaces spans of it; every other character is left as it
//! was, so a path with spaces, an apostrophe or a backslash comes back unchanged. The home
//! directory is replaced first, over the whole field. Then:
//!
//! * **Assignments.** A name, then `=`, then a value: when the name says credential, the value
//!   becomes `[redacted]`. The name is the run of letters, digits, `_`, `.` and `-` before the
//!   `=`, wherever the `=` is: `TOKEN=x`, `--password=x`, `?token=x` and `/tmp/TOKEN=x` all
//!   match. The value is read as a shell reads a word: it runs to the first whitespace that is not
//!   inside a quote and not escaped, so `abc"d e"` and `'it'\''s here'` are one value each.
//! * **Options.** `--option value`, where the option says credential and no `=` follows it: the
//!   next word becomes `[redacted]`, unless it is another `--option`. Short options are not
//!   covered: `-p` is a port as often as it is a password.
//! * **URL user information.** Each `scheme://user:password@host` has what is before the `@` of
//!   its authority replaced, wherever in the text it sits, inside a value or not.
//!
//! A value with a quote that never closes cannot be told apart from the rest of the field, so the
//! whole field is withheld, as its length.
//!
//! # What a name says
//!
//! A name says credential when its letters, run together, contain `password`, `passwd`,
//! `passphrase`, `secret`, `token`, `credential`, `apikey`, `privatekey` or `bearer`, or when one of
//! its parts is `pass`, `auth`, `authorization`, `key` or `cookie`. Parts are split at every
//! character that is not a letter or a digit, between a lower-case letter or a digit and an
//! upper-case letter, and before the last capital of a run of capitals, so `accessKeyId`,
//! `X-Auth-Key`, `S3Key` and `HTTPAuth` match and `KEYBOARD` and `PWD` do not. The list errs wide:
//! `tokenizer` matches too.
//!
//! # What it does not do
//!
//! It does not find a credential by its value. A secret that is a positional word, a plain path
//! component, the value of `-p` or `-u user:password`, the text of a `-H "Authorization: ..."`, a
//! part of a connection string whose name is not on the list, a password with an unescaped `/`, `?`
//! or `#` in a URL, or a name nobody listed stays in the text. So does a user name anywhere in a path but the home directory's. The preview shows
//! everything that will be written, and a person can leave a session out.

use std::borrow::Cow;

/// The name of these rules, recorded in the file and in the bundle's manifest.
pub const RULES: &str = "session-content-1";

/// What takes a value's place.
const REDACTED: &str = "[redacted]";

/// What takes the place of a home directory.
const HOME: &str = "[home]";

/// How a platform spells and compares paths, for finding the home directory in a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Paths {
    /// Whether upper and lower case letters are the same letter.
    pub ignores_case: bool,
    /// Whether `\` separates the parts of a path as `/` does.
    pub backslash_separates: bool,
}

impl Paths {
    /// This platform's.
    #[must_use]
    pub const fn here() -> Self {
        Self {
            ignores_case: cfg!(any(target_os = "macos", windows)),
            backslash_separates: cfg!(windows),
        }
    }

    fn same(self, a: char, b: char) -> bool {
        a == b
            || (self.ignores_case && a.to_lowercase().eq(b.to_lowercase()))
            || (self.backslash_separates && self.separates(a) && self.separates(b))
    }

    const fn separates(self, character: char) -> bool {
        character == '/' || (self.backslash_separates && character == '\\')
    }
}

/// Redacts one field's text: its home directory, and each credential its text spells.
#[must_use]
pub fn field(text: &str, home: Option<&str>, paths: Paths) -> String {
    let homed = home.map_or(Cow::Borrowed(text), |home| {
        Cow::Owned(replace_home(text, home, paths))
    });
    credentials(&homed)
        .unwrap_or_else(|| format!("[withheld: {} characters]", text.chars().count()))
}

/// Replaces each place `home` is a path's start with [`HOME`].
///
/// A home is skipped when it is empty, a root, or not an absolute path: replacing `/` would turn
/// every path of the machine into `[home]` followed by itself.
fn replace_home(text: &str, home: &str, paths: Paths) -> String {
    let home = home.trim_end_matches(|character| paths.separates(character));
    // A drive's own root (`C:`) is a root like `/`, so a drive needs a directory after it.
    let drive = home.chars().nth(1) == Some(':') && home.chars().count() > 2;
    let absolute =
        home.starts_with('/') || (paths.backslash_separates && (home.starts_with('\\') || drive));
    if home.is_empty() || !absolute || !home.chars().any(char::is_alphanumeric) {
        return text.to_owned();
    }
    let home: Vec<char> = home.chars().collect();
    let characters: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while at < characters.len() {
        // A path starts at the field's start, after whitespace, a quote or a separator of values
        // (`=`, `:` or `;`), or after the verbatim prefix Windows puts before a drive.
        let verbatim = paths.backslash_separates
            && at >= 4
            && matches!(characters[at - 4..at], ['\\', '\\', '?' | '.', '\\']);
        let starts = at == 0
            || verbatim
            || characters.get(at - 1).is_some_and(|before| {
                before.is_whitespace() || matches!(before, '=' | ':' | ';' | '"' | '\'')
            });
        let end = at + home.len();
        let matches = starts
            && end <= characters.len()
            && home
                .iter()
                .zip(&characters[at..end])
                .all(|(wanted, found)| paths.same(*wanted, *found))
            && characters.get(end).is_none_or(|after| {
                after.is_whitespace()
                    || paths.separates(*after)
                    || matches!(after, ':' | ';' | '"' | '\'')
            });
        if matches {
            out.push_str(HOME);
            at = end;
        } else {
            out.push(characters[at]);
            at += 1;
        }
    }
    out
}

/// One span of the text and what replaces it.
struct Span {
    start: usize,
    end: usize,
    with: &'static str,
}

/// Replaces each credential `text` spells, or says it cannot: `None` when a credential's value
/// starts with a quote that never closes.
fn credentials(text: &str) -> Option<String> {
    let mut spans = Vec::new();
    userinfo(text, &mut spans);
    assignments(text, &mut spans)?;
    options(text, &mut spans)?;
    // The earliest span first. A span that starts inside one already taken is part of it: the
    // region the first one replaces grows to the end of the later one, so a credential value that
    // holds another credential name, and a quoted value that runs past the end of the word an
    // earlier rule stopped at, are replaced whole and nothing of either is left behind.
    spans.sort_by_key(|span| (span.start, span.end));
    let mut out = String::with_capacity(text.len());
    let mut taken = 0;
    let mut pending: Option<Span> = None;
    for span in spans {
        match pending.as_mut() {
            Some(region) if span.start < region.end => region.end = region.end.max(span.end),
            _ => {
                if let Some(region) = pending.take() {
                    out.push_str(&text[taken..region.start]);
                    out.push_str(region.with);
                    taken = region.end;
                }
                pending = Some(span);
            }
        }
    }
    if let Some(region) = pending {
        out.push_str(&text[taken..region.start]);
        out.push_str(region.with);
        taken = region.end;
    }
    out.push_str(&text[taken..]);
    Some(out)
}

/// Each `scheme://` authority's user information, with its `@`.
fn userinfo(text: &str, spans: &mut Vec<Span>) {
    for (at, _) in text.match_indices("://") {
        let start = at + 3;
        // An authority ends at the first `/`, `?` or `#`, or at whitespace. A quote does not end
        // it: an apostrophe is a valid character of user information, and a quote that closes the
        // argument the URL is in comes after the host, so it is never between the user information
        // and its `@`. A backslash does not end it either: `DOMAIN\user:password@proxy` is user
        // information in the form Windows proxies are written in.
        let end = text[start..]
            .find(|character: char| {
                matches!(character, '/' | '?' | '#') || character.is_whitespace()
            })
            .map_or(text.len(), |offset| start + offset);
        if let Some(last) = text[start..end].rfind('@') {
            spans.push(Span {
                start,
                end: start + last + 1,
                with: "[redacted]@",
            });
        }
    }
}

/// The value after each `=` whose name says credential.
fn assignments(text: &str, spans: &mut Vec<Span>) -> Option<()> {
    for (equals, _) in text.match_indices('=') {
        let name = text[..equals]
            .chars()
            .rev()
            .take_while(|character| is_name_character(*character))
            .count();
        let name = &text[equals - name..equals];
        if name.is_empty() || !says_credential(name) {
            continue;
        }
        let start = equals + 1;
        let end = value_end(text, start)?;
        if end > start {
            spans.push(Span {
                start,
                end,
                with: REDACTED,
            });
        }
    }
    Some(())
}

/// The next word after each `--option` whose name says credential and is not followed by `=`.
fn options(text: &str, spans: &mut Vec<Span>) -> Option<()> {
    for (at, _) in text.match_indices("--") {
        let starts_a_word = text[..at]
            .chars()
            .next_back()
            .is_none_or(|before| before.is_whitespace() || matches!(before, '/' | '\\'));
        if !starts_a_word {
            continue;
        }
        let name_end = text[at + 2..]
            .find(|character: char| !is_name_character(character))
            .map_or(text.len(), |offset| at + 2 + offset);
        let name = &text[at + 2..name_end];
        // Followed by `=` is an assignment, which has been read already.
        if name.is_empty()
            || !says_credential(name)
            || !text[name_end..]
                .chars()
                .next()
                .is_some_and(char::is_whitespace)
        {
            continue;
        }
        let start = name_end
            + text[name_end..]
                .find(|character: char| !character.is_whitespace())
                .unwrap_or(text.len() - name_end);
        if start >= text.len() || text[start..].starts_with("--") {
            continue;
        }
        let end = value_end(text, start)?;
        spans.push(Span {
            start,
            end,
            with: REDACTED,
        });
    }
    Some(())
}

/// Where a value that starts at `start` ends, read as a shell reads a word: at the first whitespace
/// that is not inside a quote and not escaped, so `abc"d e"` and `'it'\''s here'` are one value
/// each. `None` when a quote never closes: the rest of the field cannot be told from the value.
fn value_end(text: &str, start: usize) -> Option<usize> {
    let mut quote: Option<char> = None;
    let mut characters = text[start..].char_indices();
    while let Some((offset, character)) = characters.next() {
        match quote {
            Some(open) if character == open => quote = None,
            // Inside double quotes a backslash escapes the next character; inside single quotes it
            // is a character.
            Some('"') if character == '\\' => {
                characters.next();
            }
            Some(_) => {}
            None if character.is_whitespace() => return Some(start + offset),
            None if matches!(character, '"' | '\'') => quote = Some(character),
            None if character == '\\' => {
                characters.next();
            }
            None => {}
        }
    }
    quote.is_none().then_some(text.len())
}

/// Whether a character can be part of the name of an assignment or an option.
const fn is_name_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-')
}

/// Whether a name says credential: see the module's description.
fn says_credential(name: &str) -> bool {
    const CONTAINS: [&str; 9] = [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "credential",
        "apikey",
        "privatekey",
        "bearer",
    ];
    const PARTS: [&str; 5] = ["pass", "auth", "authorization", "key", "cookie"];

    let squashed: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect();
    CONTAINS.iter().any(|word| squashed.contains(word))
        || parts(name)
            .iter()
            .any(|part| PARTS.contains(&part.as_str()))
}

/// A name's parts, lower-cased: split at every character that is not a letter or a digit, between a
/// lower-case letter or a digit and an upper-case letter, and before the last capital of a run of capitals that a
/// lower-case letter follows (`HTTPAuth` is `http` and `auth`).
fn parts(name: &str) -> Vec<String> {
    let characters: Vec<char> = name.chars().collect();
    let mut parts = Vec::new();
    let mut part = String::new();
    for (index, character) in characters.iter().copied().enumerate() {
        if !character.is_ascii_alphanumeric() {
            if !part.is_empty() {
                parts.push(std::mem::take(&mut part));
            }
            continue;
        }
        if let Some(previous) = index.checked_sub(1).map(|before| characters[before])
            && !part.is_empty()
        {
            let lower_then_upper = (previous.is_ascii_lowercase() || previous.is_ascii_digit())
                && character.is_ascii_uppercase();
            let end_of_a_run = previous.is_ascii_uppercase()
                && character.is_ascii_uppercase()
                && characters
                    .get(index + 1)
                    .is_some_and(char::is_ascii_lowercase);
            if lower_then_upper || end_of_a_run {
                parts.push(std::mem::take(&mut part));
            }
        }
        part.push(character.to_ascii_lowercase());
    }
    if !part.is_empty() {
        parts.push(part);
    }
    parts
}

#[cfg(test)]
mod tests;
