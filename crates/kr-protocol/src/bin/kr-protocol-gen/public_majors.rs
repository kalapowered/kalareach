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
    if !source.contains("PUBLIC_MAJORS") {
        return Ok(None);
    }
    let start = source.find(START).ok_or(
        "PUBLIC_MAJORS is named in a form this reader does not read (it reads `pub const \
         PUBLIC_MAJORS: &[PublicMajor] = &[ .. ];`)",
    )?;
    let inside = start + START.len();
    let length = closing(&source[inside..], '[', ']').ok_or("the table does not end")?;
    let after = source[inside + length + 1..].trim_start();
    if !after.starts_with(';') {
        return Err("the table is followed by something other than `;`".to_owned());
    }
    let item_end = inside + length + 1 + (source[inside + length + 1..].len() - after.len()) + 1;
    let item = plain(&source[start..item_end]);
    if item.contains("/*") {
        return Err("a block comment in the table".to_owned());
    }
    let body = plain(&source[inside..inside + length]);
    let mut rows = Vec::new();
    for entry in split_top(&body) {
        rows.push(row_of(source, entry)?);
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
        let rest = source
            .split(PROTOCOL_DECLARATION)
            .nth(1)
            .ok_or("PROTOCOL_VERSION is not declared in the source")?;
        plain(rest.split(';').next().unwrap_or_default())
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

/// `text` without its `//` comments and with its whitespace collapsed to single spaces.
fn plain(text: &str) -> String {
    let mut kept = String::new();
    for line in text.lines() {
        let mut quoted = false;
        let mut end = line.len();
        let mut previous = ' ';
        for (index, character) in line.char_indices() {
            if character == '"' {
                quoted = !quoted;
            }
            if !quoted && character == '/' && previous == '/' {
                end = index - 1;
                break;
            }
            previous = character;
        }
        kept.push_str(&line[..end]);
        kept.push(' ');
    }
    kept.split_whitespace().collect::<Vec<_>>().join(" ")
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
