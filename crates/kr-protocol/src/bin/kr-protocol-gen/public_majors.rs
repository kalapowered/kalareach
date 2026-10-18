//! The table of public majors, read out of the source of `hello.rs` as a retained record.
//!
//! A retained level records the table its release listed (`retained/<level>/PUBLIC_MAJORS`): a line
//! per major, `major=.. versions=.. replaced=.. supported_until=.. retired=..` (a day, or `-`), and
//! the digest of the table item's source with its comments and layout taken out. The reader is
//! strict. It knows the shape `kr-protocol` writes the table in and nothing else, and a source it
//! does not understand is an error, never a table with rows left out or a release with no table.
//!
//! This file is also read by the `kr-cli` test that compares a record with the tree of the release
//! it was cut from, so it uses nothing but the standard library and `kr_cbor`.

const START: &str = "pub const PUBLIC_MAJORS: &[PublicMajor] = &[";
const PROTOCOL_DECLARATION: &str = "pub const PROTOCOL_VERSION: ProtocolVersion = ";

/// The record of the table in `source`, or none where the source has no table at all.
///
/// # Errors
///
/// Returns why when the source names the table in a form this reader does not read, or the table
/// is not a list of `PublicMajor { .. }` literals of the five known fields with known values.
pub fn record_of(source: &str) -> Result<Option<String>, String> {
    // Comments are taken out before anything is looked for, so a bracket or a declaration inside
    // one is neither the end of the table nor the table.
    let code = without_comments(source)?;
    let outside = masked(&code);
    if !outside.contains("PUBLIC_MAJORS") {
        return Ok(None);
    }
    if outside.matches(START).count() != 1 || outside.matches("PUBLIC_MAJORS:").count() != 1 {
        return Err(
            "PUBLIC_MAJORS is named in a form this reader does not read (it reads exactly one \
             `pub const PUBLIC_MAJORS: &[PublicMajor] = &[ .. ];`)"
                .to_owned(),
        );
    }
    let start = outside.find(START).ok_or("no table")?;
    let inside = start + START.len();
    let length = closing(&code[inside..], '[', ']').ok_or("the table does not end")?;
    let after = code[inside + length + 1..].trim_start();
    if !after.starts_with(';') {
        return Err("the table is followed by something other than `;`".to_owned());
    }
    let item_end = inside + length + 1 + (code[inside + length + 1..].len() - after.len()) + 1;
    let item = squeeze(&code[start..item_end]);
    let body = squeeze(&code[inside..inside + length]);
    let mut rows = Vec::new();
    for entry in split_top(&body) {
        rows.push(row_of(&code, entry)?);
    }
    if rows.is_empty() {
        return Err("the table has no row".to_owned());
    }
    let mut seen = Vec::new();
    let mut record = String::new();
    for row in &rows {
        if seen.contains(&row.major) {
            return Err(format!("major {} is in the table twice", row.major));
        }
        seen.push(row.major);
        record.push_str(&format!(
            "major={} versions={} replaced={} supported_until={} retired={}\n",
            row.major,
            row.versions.join(","),
            row.replaced,
            row.supported_until,
            row.retired,
        ));
    }
    let digest: String = kr_cbor::sha256(item.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    record.push_str(&format!("digest={digest}\n"));
    Ok(Some(record))
}

/// The record a release has whose source lists no table: the one major it negotiates, from the
/// protocol version it implements, not replaced. A level cut from such a release records this.
///
/// # Errors
///
/// Returns why when the source states no protocol version this reader knows.
pub fn record_without_a_table(source: &str) -> Result<String, String> {
    let code = without_comments(source)?;
    let version = version_of(&code, "PROTOCOL_VERSION")?;
    let major = version
        .split('.')
        .next()
        .ok_or("a protocol version has a major")?;
    Ok(format!(
        "major={major} versions={version} replaced=- supported_until=- retired=false\n"
    ))
}

/// `code` with the inside of every string and character literal replaced by `x`, byte for byte, so
/// that where a declaration is can be found without taking one that a string holds for one.
fn masked(code: &str) -> String {
    let characters: Vec<char> = code.chars().collect();
    let mut out = String::with_capacity(code.len());
    let (mut index, mut quoted) = (0, false);
    while index < characters.len() {
        let here = characters[index];
        if quoted {
            if here == '\\' {
                out.push('x');
                if let Some(escaped) = characters.get(index + 1) {
                    out.extend(std::iter::repeat_n('x', escaped.len_utf8()));
                    index += 1;
                }
            } else if here == '"' {
                quoted = false;
                out.push('"');
            } else {
                out.extend(std::iter::repeat_n('x', here.len_utf8()));
            }
        } else if here == '"' {
            quoted = true;
            out.push('"');
        } else if here == '\'' && characters.get(index + 2) == Some(&'\'') {
            out.push_str("'x'");
            index += 2;
        } else {
            out.push(here);
        }
        index += 1;
    }
    out
}

/// `source` without its `//` and `/* */` comments; text between double quotes is left alone.
fn without_comments(source: &str) -> Result<String, String> {
    let characters: Vec<char> = source.chars().collect();
    let mut kept = String::with_capacity(source.len());
    let (mut index, mut quoted) = (0, false);
    while index < characters.len() {
        let here = characters[index];
        let next = characters.get(index + 1).copied();
        if quoted {
            kept.push(here);
            if here == '\\' {
                if let Some(escaped) = next {
                    kept.push(escaped);
                    index += 1;
                }
            } else if here == '"' {
                quoted = false;
            }
        } else if here == '\'' && characters.get(index + 2) == Some(&'\'') {
            kept.extend(&characters[index..index + 3]);
            index += 3;
            continue;
        } else if here == '"' {
            quoted = true;
            kept.push(here);
        } else if here == '/' && next == Some('/') {
            while index < characters.len() && characters[index] != '\n' {
                index += 1;
            }
            continue;
        } else if here == '/' && next == Some('*') {
            let mut depth = 1;
            index += 2;
            while depth > 0 {
                match (characters.get(index), characters.get(index + 1)) {
                    (Some('/'), Some('*')) => {
                        depth += 1;
                        index += 2;
                    }
                    (Some('*'), Some('/')) => {
                        depth -= 1;
                        index += 2;
                    }
                    (Some(_), _) => index += 1,
                    (None, _) => return Err("a block comment does not end".to_owned()),
                }
            }
            kept.push(' ');
            continue;
        } else {
            kept.push(here);
        }
        index += 1;
    }
    Ok(kept)
}

struct Row {
    major: u16,
    versions: Vec<String>,
    replaced: String,
    supported_until: String,
    retired: bool,
}

fn row_of(source: &str, entry: &str) -> Result<Row, String> {
    let literal = entry
        .strip_prefix("PublicMajor {")
        .and_then(|rest| rest.strip_suffix('}'))
        .ok_or_else(|| format!("an entry that is not a `PublicMajor {{ .. }}` literal: {entry}"))?;
    if literal.contains(['{', '}']) {
        return Err(format!("braces in a row: {entry}"));
    }
    let (mut major, mut versions, mut replaced, mut supported_until, mut retired) =
        (None, None, None, None, None);
    for field in split_top(literal) {
        let (name, value) = field
            .split_once(':')
            .ok_or_else(|| format!("a field without a name: {field}"))?;
        let value = value.trim();
        let taken = match name.trim() {
            "major" => major
                .replace(
                    value
                        .parse::<u16>()
                        .map_err(|e| format!("major {value}: {e}"))?,
                )
                .is_some(),
            "versions" => versions.replace(versions_of(source, value)?).is_some(),
            "replaced" => replaced.replace(day_of(value)?).is_some(),
            "supported_until" => supported_until.replace(day_of(value)?).is_some(),
            "retired" => retired
                .replace(match value {
                    "true" => true,
                    "false" => false,
                    other => return Err(format!("retired is {other}, not true or false")),
                })
                .is_some(),
            other => return Err(format!("a field this reader does not know: {other}")),
        };
        if taken {
            return Err(format!("a field twice in a row: {field}"));
        }
    }
    Ok(Row {
        major: major.ok_or("a row has no major")?,
        versions: versions.ok_or("a row has no versions")?,
        replaced: replaced.ok_or("a row has no replaced")?,
        supported_until: supported_until.ok_or("a row has no supported_until")?,
        retired: retired.ok_or("a row has no retired")?,
    })
}

/// `&[ProtocolVersion::new(1, 0), PROTOCOL_VERSION]` as `["1.0", "1.0"]`.
fn versions_of(source: &str, value: &str) -> Result<Vec<String>, String> {
    let list = value
        .strip_prefix("&[")
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or_else(|| format!("versions is not a list: {value}"))?;
    let versions: Vec<String> = split_top(list)
        .into_iter()
        .map(|entry| version_of(source, entry))
        .collect::<Result<_, _>>()?;
    if versions.is_empty() {
        return Err("a row lists no version".to_owned());
    }
    Ok(versions)
}

/// The build's own constant, or `ProtocolVersion::new(major, minor)` with two numbers.
fn version_of(source: &str, entry: &str) -> Result<String, String> {
    let call = if entry == "PROTOCOL_VERSION" {
        let outside = masked(source);
        if outside.matches(PROTOCOL_DECLARATION).count() != 1 {
            return Err("PROTOCOL_VERSION is not declared exactly once in the source".to_owned());
        }
        let at = outside
            .find(PROTOCOL_DECLARATION)
            .ok_or("PROTOCOL_VERSION is not declared in the source")?
            + PROTOCOL_DECLARATION.len();
        squeeze(source[at..].split(';').next().unwrap_or_default())
    } else {
        entry.to_owned()
    };
    let numbers = call
        .strip_prefix("ProtocolVersion::new(")
        .and_then(|rest| rest.strip_suffix(')'))
        .ok_or_else(|| format!("a version this reader does not know: {entry}"))?;
    let (major, minor) = numbers
        .split_once(',')
        .ok_or_else(|| format!("a version: {entry}"))?;
    let (major, minor) = (
        major
            .trim()
            .parse::<u16>()
            .map_err(|e| format!("{entry}: {e}"))?,
        minor
            .trim()
            .parse::<u16>()
            .map_err(|e| format!("{entry}: {e}"))?,
    );
    Ok(format!("{major}.{minor}"))
}

/// `None` is `-`, and `Some("YYYY-MM-DD")` is the day.
fn day_of(value: &str) -> Result<String, String> {
    if value == "None" {
        return Ok("-".to_owned());
    }
    let day = value
        .strip_prefix("Some(\"")
        .and_then(|rest| rest.strip_suffix("\")"))
        .ok_or_else(|| format!("a day this reader does not know: {value}"))?;
    let shaped = day.len() == 10
        && day.char_indices().all(|(index, character)| match index {
            4 | 7 => character == '-',
            _ => character.is_ascii_digit(),
        });
    if shaped {
        Ok(day.to_owned())
    } else {
        Err(format!("a day that is not YYYY-MM-DD: {day}"))
    }
}

/// `text` with its whitespace collapsed to single spaces.
fn squeeze(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The length of `text` up to the bracket that closes the one before it, `open` and `close` taken
/// in pairs and text between double quotes passed over.
fn closing(text: &str, open: char, close: char) -> Option<usize> {
    let (mut depth, mut quoted) = (0_usize, false);
    for (index, character) in text.char_indices() {
        match character {
            '"' => quoted = !quoted,
            _ if quoted => {}
            _ if character == open => depth += 1,
            _ if character == close => {
                if depth == 0 {
                    return Some(index);
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    None
}

/// `text` split at the commas that are not inside brackets or quotes, empty parts left out.
fn split_top(text: &str) -> Vec<&str> {
    let (mut depth, mut quoted, mut from) = (0_usize, false, 0);
    let mut parts = Vec::new();
    for (index, character) in text.char_indices() {
        match character {
            '"' => quoted = !quoted,
            _ if quoted => {}
            '[' | '(' | '{' => depth += 1,
            ']' | ')' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&text[from..index]);
                from = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[from..]);
    parts
        .into_iter()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect()
}
