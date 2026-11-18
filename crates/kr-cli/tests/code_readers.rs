//! The roster of every reader of a kept protocol error code, and the scan that holds it.
//!
//! A store keeps an error code as its wire word, and a code that the protocol gains raises no
//! store's version. In exchange, every reader of a kept code has one declared reading of a word
//! that it does not know: never absent, never a success, never a new claim or a repeated effect,
//! never a definite refusal under another code. The outcome is unknown, with the record kept.
//! `stored_formats/code_readers.txt` names each reader, its reading and the case that holds it.
//!
//! This scan reads the product source as text. It starts nothing and runs on every platform. It
//! fails when
//!
//! - a call that turns text into a code (`ErrorCode::from_wire(`, `ErrorCode::from_str(`,
//!   `parse::<ErrorCode>(`, or a `.parse()` whose neighbouring lines name `ErrorCode`) stands in a
//!   function that no row names, or in a number of places that differs from the row's;
//! - a struct or enum that derives `Deserialize` and has the code, `ProtocolError`, or any such
//!   type that already holds one, as a direct member, is in no row;
//! - a row names a call or a type that is gone, or a case that does not exist in the file it names.
//!
//! What it reads: `crates/*/src` and every `src` folder under `apps`, minus tests, benches,
//! examples, modules declared `#[cfg(test)]`, and items under `#[cfg(test)]`, with comments and
//! the inside of string literals blanked.
//!
//! What it cannot see: a code that reaches a store as text through another function or a string
//! match; a hand-written decoder (a `Deserialize` impl or a visitor); a type that is held by a
//! name two types share (a name two crates share counts for both, so there are more rows and never
//! fewer); a call made by a macro; a type alias; a use that renames `ErrorCode`; Rust outside the
//! folders above. A row that says a place keeps nothing is the author's claim, which the scan does
//! not prove.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The folder the scan reads, and the roster inside it. A planted run points this at a copy.
const ROOT_VARIABLE: &str = "KR_CODE_READERS_ROOT";
const ROSTER_PATH: &str = "crates/kr-cli/tests/stored_formats/code_readers.txt";

fn root() -> PathBuf {
    std::env::var_os(ROOT_VARIABLE).map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
        PathBuf::from,
    )
}

/// One file of product source.
struct Source {
    /// The path from the root, with `/` between its parts.
    path: String,
    /// The text as it is written.
    raw: String,
    /// The text with comments, literals and test-only items blanked, byte for byte the same length.
    code: Vec<u8>,
}

const fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Replaces the bytes of `from..to` by spaces, and keeps the newlines.
fn blank_span(code: &mut [u8], from: usize, to: usize) {
    let to = to.min(code.len());
    for byte in &mut code[from..to] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

/// Blanks comments and the inside of string and character literals.
fn blank_literals(source: &str) -> Vec<u8> {
    let bytes = source.as_bytes();
    let mut code = bytes.to_vec();
    let length = bytes.len();
    let mut at = 0;
    while at < length {
        match bytes[at] {
            b'/' if bytes.get(at + 1) == Some(&b'/') => {
                let end = bytes[at..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(length, |offset| at + offset);
                blank_span(&mut code, at, end);
                at = end;
            }
            b'/' if bytes.get(at + 1) == Some(&b'*') => {
                let mut depth = 0;
                let mut end = at;
                while end < length {
                    if bytes[end..].starts_with(b"/*") {
                        depth += 1;
                        end += 2;
                    } else if bytes[end..].starts_with(b"*/") {
                        depth -= 1;
                        end += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        end += 1;
                    }
                }
                blank_span(&mut code, at, end);
                at = end;
            }
            b'r' if at == 0
                || !is_word(bytes[at - 1])
                || (bytes[at - 1] == b'b' && (at < 2 || !is_word(bytes[at - 2]))) =>
            {
                let mut hashes = 0;
                while bytes.get(at + 1 + hashes) == Some(&b'#') {
                    hashes += 1;
                }
                if bytes.get(at + 1 + hashes) == Some(&b'"') {
                    let start = at + 2 + hashes;
                    let mut closing = vec![b'"'];
                    closing.extend(std::iter::repeat_n(b'#', hashes));
                    let end = bytes[start..]
                        .windows(closing.len())
                        .position(|window| window == closing.as_slice())
                        .map_or(length, |offset| start + offset);
                    blank_span(&mut code, start, end);
                    at = (end + closing.len()).min(length);
                } else {
                    at += 1;
                }
            }
            b'"' => {
                let mut end = at + 1;
                while end < length && bytes[end] != b'"' {
                    end += if bytes[end] == b'\\' { 2 } else { 1 };
                }
                blank_span(&mut code, at + 1, end);
                at = (end + 1).min(length);
            }
            b'\'' => {
                // A character literal, or a lifetime, which has no closing quote.
                let literal_end = if bytes.get(at + 1) == Some(&b'\\') {
                    bytes[at + 2..]
                        .iter()
                        .take(12)
                        .position(|byte| *byte == b'\'')
                        .map(|offset| at + 2 + offset)
                } else {
                    bytes[at + 1..]
                        .iter()
                        .take(5)
                        .position(|byte| *byte == b'\'')
                        .map(|offset| at + 1 + offset)
                        .filter(|end| *end > at + 1)
                };
                if let Some(end) = literal_end {
                    blank_span(&mut code, at + 1, end);
                    at = end + 1;
                } else {
                    at += 1;
                }
            }
            _ => at += 1,
        }
    }
    code
}

/// Returns the index just past the bracket that closes the one at `open`.
fn closing(code: &[u8], open: usize) -> usize {
    let mut depth = 0_i32;
    for (offset, byte) in code[open..].iter().enumerate() {
        match byte {
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return open + offset + 1;
                }
            }
            _ => {}
        }
    }
    code.len()
}

/// Finds `word` as a whole word at or after `from`.
fn find_word(code: &[u8], word: &str, from: usize) -> Option<usize> {
    let word = word.as_bytes();
    let mut at = from;
    while at + word.len() <= code.len() {
        let found = code[at..]
            .windows(word.len())
            .position(|window| window == word)?
            + at;
        let before = found == 0 || !is_word(code[found - 1]);
        let after = code
            .get(found + word.len())
            .is_none_or(|byte| !is_word(*byte));
        if before && after {
            return Some(found);
        }
        at = found + 1;
    }
    None
}

fn skip_space(code: &[u8], mut at: usize) -> usize {
    while code.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    at
}

fn word_at(code: &[u8], at: usize) -> &str {
    let end = code[at..]
        .iter()
        .position(|byte| !is_word(*byte))
        .map_or(code.len(), |offset| at + offset);
    std::str::from_utf8(&code[at..end]).unwrap_or("")
}

/// Blanks every item that a `cfg(test)` attribute gates.
fn blank_test_items(code: &mut [u8]) {
    for marker in ["#[cfg(test)]", "#[cfg(all(test"] {
        let mut from = 0;
        while let Some(offset) = code[from..]
            .windows(marker.len())
            .position(|window| window == marker.as_bytes())
        {
            let start = from + offset;
            let mut at = closing(code, start + 1);
            // Further attributes, then the item: to its `;` or past its braces.
            loop {
                at = skip_space(code, at);
                if code[at..].starts_with(b"#[") {
                    at = closing(code, at + 1);
                } else {
                    break;
                }
            }
            let mut depth = 0_i32;
            let mut end = at;
            while end < code.len() {
                match code[end] {
                    b'(' | b'[' => depth += 1,
                    b')' | b']' => depth -= 1,
                    b';' if depth == 0 => {
                        end += 1;
                        break;
                    }
                    b'{' if depth == 0 => {
                        end = closing(code, end);
                        break;
                    }
                    _ => {}
                }
                end += 1;
            }
            blank_span(code, start, end);
            from = start + 1;
        }
    }
}

/// The modules that `#[cfg(test)] mod name;` puts in files of their own, as the paths they live at.
fn test_modules(path: &str, raw: &str) -> Vec<String> {
    let code = blank_literals(raw);
    let folder = path.rsplit_once('/').map_or("", |(folder, _)| folder);
    let stem = path
        .rsplit_once('/')
        .map_or(path, |(_, file)| file)
        .trim_end_matches(".rs");
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(offset) = code[from..]
        .windows(12)
        .position(|window| window == b"#[cfg(test)]")
    {
        let mut at = skip_space(&code, from + offset + 12);
        from += offset + 12;
        if code[at..].starts_with(b"pub ") {
            at = skip_space(&code, at + 4);
        }
        if code[at..].starts_with(b"mod ") {
            let name = word_at(&code, skip_space(&code, at + 4));
            if code[skip_space(&code, at + 4) + name.len()..].starts_with(b";") {
                for base in [folder.to_owned(), format!("{folder}/{stem}")] {
                    found.push(format!("{base}/{name}.rs"));
                    found.push(format!("{base}/{name}/mod.rs"));
                }
            }
        }
    }
    found
}

fn walk(folder: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !matches!(
                name.as_ref(),
                "target" | "node_modules" | ".git" | "tests" | "benches" | "examples"
            ) {
                walk(&path, files);
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn product_sources(root: &Path) -> Vec<Source> {
    let mut found = Vec::new();
    let crates = std::fs::read_dir(root.join("crates"))
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path().join("src"))
                .collect()
        })
        .unwrap_or_else(|_| Vec::<PathBuf>::new());
    for source_folder in crates {
        walk(&source_folder, &mut found);
    }
    let mut apps = Vec::new();
    walk(&root.join("apps"), &mut apps);
    found.extend(apps.into_iter().filter(|path| {
        path.strip_prefix(root)
            .is_ok_and(|relative| relative.components().any(|part| part.as_os_str() == "src"))
    }));
    let mut sources: Vec<Source> = found
        .into_iter()
        .filter_map(|path| {
            let relative = path
                .strip_prefix(root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            let raw = std::fs::read_to_string(&path).ok()?;
            Some(Source {
                path: relative,
                raw,
                code: Vec::new(),
            })
        })
        .collect();
    let test_only: BTreeSet<String> = sources
        .iter()
        .flat_map(|source| test_modules(&source.path, &source.raw))
        .collect();
    sources.retain(|source| !test_only.contains(&source.path));
    for source in &mut sources {
        source.code = blank_literals(&source.raw);
        blank_test_items(&mut source.code);
    }
    sources
}

/// Every function of a source, as its name and the range of its body.
fn functions(code: &[u8]) -> Vec<(String, usize, usize)> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(at) = find_word(code, "fn", from) {
        from = at + 2;
        let name_at = skip_space(code, at + 2);
        let name = word_at(code, name_at);
        if name.is_empty() || name_at == at + 2 {
            continue;
        }
        let mut depth = 0_i32;
        let mut cursor = name_at + name.len();
        while cursor < code.len() {
            match code[cursor] {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                b'{' if depth == 0 => {
                    found.push((name.to_owned(), cursor, closing(code, cursor)));
                    break;
                }
                b';' if depth == 0 => break,
                _ => {}
            }
            cursor += 1;
        }
    }
    found
}

/// The places in a source where text becomes a code, each as the function it stands in.
fn read_sites(source: &Source) -> Vec<String> {
    let code = &source.code;
    let functions = functions(code);
    let mut positions = Vec::new();
    for needle in ["ErrorCode::from_wire(", "ErrorCode::from_str("] {
        let mut from = 0;
        while let Some(offset) = code[from..]
            .windows(needle.len())
            .position(|window| window == needle.as_bytes())
        {
            positions.push(from + offset);
            from += offset + 1;
        }
    }
    let mut from = 0;
    while let Some(offset) = code[from..]
        .windows(8)
        .position(|window| window == b"parse::<")
    {
        let start = from + offset + 8;
        from = start;
        let end = code[start..]
            .iter()
            .position(|byte| *byte == b'>')
            .map_or(start, |length| start + length);
        let named = String::from_utf8_lossy(&code[start..end]);
        if named.rsplit("::").next().map(str::trim) == Some("ErrorCode") {
            positions.push(start);
        }
    }
    let lines: Vec<usize> = std::iter::once(0)
        .chain(
            code.iter()
                .enumerate()
                .filter(|(_, byte)| **byte == b'\n')
                .map(|(at, _)| at + 1),
        )
        .collect();
    let mut from = 0;
    while let Some(offset) = code[from..]
        .windows(8)
        .position(|window| window == b".parse()")
    {
        let at = from + offset;
        from = at + 1;
        let line = lines.partition_point(|start| *start <= at) - 1;
        let first = lines[line.saturating_sub(2)];
        let last = lines.get(line + 4).copied().unwrap_or(code.len());
        if find_word(&code[first..last], "ErrorCode", 0).is_some() {
            positions.push(at);
        }
    }
    positions
        .into_iter()
        .map(|at| {
            let inside = functions
                .iter()
                .filter(|(_, start, end)| *start <= at && at < *end)
                .min_by_key(|(_, start, end)| end - start)
                .map_or("<module>", |(name, _, _)| name.as_str());
            inside.to_owned()
        })
        .collect()
}

/// A struct or enum that derives `Deserialize`, with the words of its members.
struct Held {
    path: String,
    name: String,
    members: BTreeSet<String>,
}

fn deserialising_types(source: &Source) -> Vec<Held> {
    let code = &source.code;
    let mut found = Vec::new();
    for keyword in ["struct", "enum"] {
        let mut from = 0;
        while let Some(at) = find_word(code, keyword, from) {
            from = at + keyword.len();
            let name_at = skip_space(code, at + keyword.len());
            let name = word_at(code, name_at);
            if name.is_empty() || name_at == from {
                continue;
            }
            // The attributes and the visibility stand between the previous item and this one.
            let boundary = code[..at]
                .iter()
                .rposition(|byte| matches!(byte, b';' | b'}' | b'{'))
                .map_or(0, |at| at + 1);
            if find_word(&code[boundary..at], "Deserialize", 0).is_none() {
                continue;
            }
            let mut cursor = name_at + name.len();
            let mut depth = 0_i32;
            let body = loop {
                let Some(byte) = code.get(cursor) else {
                    break None;
                };
                match byte {
                    b'<' => depth += 1,
                    b'>' => depth -= 1,
                    b'{' | b'(' if depth <= 0 => break Some((cursor, closing(code, cursor))),
                    b';' if depth <= 0 => break None,
                    _ => {}
                }
                cursor += 1;
            };
            let Some((open, end)) = body else {
                continue;
            };
            let mut members = BTreeSet::new();
            let mut word_from = open;
            while word_from < end {
                if is_word(code[word_from]) && (word_from == 0 || !is_word(code[word_from - 1])) {
                    let word = word_at(code, word_from);
                    let after = word_from + word.len();
                    if !code[after..].starts_with(b"::") {
                        members.insert(word.to_owned());
                    }
                    word_from = after;
                } else {
                    word_from += 1;
                }
            }
            found.push(Held {
                path: source.path.clone(),
                name: name.to_owned(),
                members,
            });
        }
    }
    found
}

/// Every type that holds a code at any depth, as its file and name.
fn holders(sources: &[Source]) -> BTreeSet<(String, String)> {
    let held: Vec<Held> = sources.iter().flat_map(deserialising_types).collect();
    let mut names: BTreeSet<String> = ["ErrorCode", "ProtocolError"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let mut rows = BTreeSet::new();
    loop {
        let before = rows.len();
        for item in &held {
            if item.name != "ErrorCode" && item.members.iter().any(|member| names.contains(member))
            {
                rows.insert((item.path.clone(), item.name.clone()));
                names.insert(item.name.clone());
            }
        }
        if rows.len() == before {
            return rows;
        }
    }
}

/// One row of the roster.
struct Row {
    kind: String,
    class: String,
    file: String,
    names: Vec<String>,
    sites: Option<usize>,
    case: String,
    text: String,
}

fn parse_roster(roster: &str) -> (Vec<Row>, Vec<String>) {
    let mut rows = Vec::new();
    let mut failures = Vec::new();
    for (number, line) in roster.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(" | ").map(str::trim).collect();
        if fields.len() != 9 || fields.iter().any(|field| field.is_empty()) {
            failures.push(format!(
                "roster line {}: a row has nine fields (kind, class, place, file, names, sites, how, reading, case), none empty",
                number + 1
            ));
            continue;
        }
        let kind = fields[0];
        let class = fields[1];
        let sites = fields[5].parse::<usize>().ok();
        let well_formed = matches!(kind, "site" | "type")
            && matches!(class, "stored" | "wire" | "not-code")
            && (kind == "type") == sites.is_none()
            && (class == "stored") == (fields[8] != "-");
        if !well_formed {
            failures.push(format!(
                "roster line {}: a site row has a count of sites and a type row has `-`; a stored row names its case and any other class has `-`",
                number + 1
            ));
            continue;
        }
        rows.push(Row {
            kind: kind.to_owned(),
            class: class.to_owned(),
            file: fields[3].to_owned(),
            names: fields[4]
                .split(',')
                .map(|name| name.trim().to_owned())
                .collect(),
            sites,
            case: fields[8].to_owned(),
            text: fields[2].to_owned(),
        });
    }
    (rows, failures)
}

/// Whether a case `crate::target::name` exists: a function of that name in the target's file, or
/// anywhere in the crate's `src` for the target `lib`.
fn case_exists(root: &Path, sources: &[Source], case: &str) -> Result<(), String> {
    let parts: Vec<&str> = case.split("::").collect();
    let [package, target, name] = parts.as_slice() else {
        return Err(format!("case `{case}` is not written crate::target::name"));
    };
    let holds = |text: &str| {
        let bytes = text.as_bytes();
        find_word(bytes, name, 0).is_some_and(|_| {
            let mut from = 0;
            while let Some(at) = find_word(bytes, name, from) {
                if text[..at].trim_end().ends_with("fn") {
                    return true;
                }
                from = at + 1;
            }
            false
        })
    };
    if *target == "lib" {
        let prefix = format!("crates/{package}/src/");
        return if sources
            .iter()
            .any(|source| source.path.starts_with(&prefix) && holds(&source.raw))
        {
            Ok(())
        } else {
            Err(format!(
                "case `{case}` is in no source of crates/{package}/src"
            ))
        };
    }
    let candidates = [
        root.join(format!("crates/{package}/tests/{target}.rs")),
        root.join(format!("crates/{package}/tests/{target}/main.rs")),
    ];
    let Some(text) = candidates
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
    else {
        return Err(format!(
            "case `{case}`: crates/{package}/tests/{target}.rs does not exist"
        ));
    };
    if holds(&text) {
        Ok(())
    } else {
        Err(format!(
            "case `{case}`: crates/{package}/tests/{target}.rs has no function {name}"
        ))
    }
}

/// Everything that is wrong between the tree and the roster, as lines a person can act on.
fn failures(root: &Path, roster: &str) -> Vec<String> {
    let (rows, mut failures) = parse_roster(roster);
    let sources = product_sources(root);

    let mut found: BTreeMap<(String, String), usize> = BTreeMap::new();
    for source in &sources {
        for function in read_sites(source) {
            *found.entry((source.path.clone(), function)).or_default() += 1;
        }
    }
    let mut named: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut named_types: BTreeSet<(String, String)> = BTreeSet::new();
    for row in &rows {
        for name in &row.names {
            if row.kind == "site" {
                let key = (row.file.clone(), name.clone());
                if named.insert(key, row.sites.unwrap_or(0)).is_some() {
                    failures.push(format!("{}: {name} is named by two rows", row.file));
                }
            } else if !named_types.insert((row.file.clone(), name.clone())) {
                failures.push(format!("{}: type {name} is named by two rows", row.file));
            }
        }
    }
    for ((file, function), count) in &found {
        match named.get(&(file.clone(), function.clone())) {
            None => failures.push(format!(
                "{file}: fn {function} turns text into an error code {count} time(s) and no row names it"
            )),
            Some(declared) if declared != count => failures.push(format!(
                "{file}: fn {function} turns text into an error code {count} time(s) and its row says {declared}"
            )),
            Some(_) => {}
        }
    }
    for (file, function) in named.keys() {
        if !found.contains_key(&(file.clone(), function.clone())) {
            failures.push(format!(
                "a row names fn {function} of {file}, which no longer turns text into an error code"
            ));
        }
    }
    let held = holders(&sources);
    for (file, name) in &held {
        if !named_types.contains(&(file.clone(), name.clone())) {
            failures.push(format!(
                "{file}: type {name} holds an error code and derives Deserialize, and no row names it"
            ));
        }
    }
    for (file, name) in &named_types {
        if !held.contains(&(file.clone(), name.clone())) {
            failures.push(format!(
                "a row names type {name} of {file}, which holds no error code"
            ));
        }
    }
    for row in rows.iter().filter(|row| row.class == "stored") {
        if let Err(missing) = case_exists(root, &sources, &row.case) {
            failures.push(format!("row `{}`: {missing}", row.text));
        }
    }
    failures
}

#[test]
fn every_reader_of_a_kept_error_code_is_in_the_roster_with_a_case_that_exists() {
    let root = root();
    let roster = std::fs::read_to_string(root.join(ROSTER_PATH)).expect("the roster reads");
    let wrong = failures(&root, &roster);
    assert!(
        wrong.is_empty(),
        "the roster and the product source disagree:\n{}",
        wrong.join("\n")
    );
}

/// A small tree with one reader of each kind, and the roster that names it.
mod planted {
    use super::*;

    const STORE: &str = r#"
use kr_protocol::error::ErrorCode;

/// A comment that says ErrorCode::from_wire(word) does not count.
pub fn read(word: &str) -> Option<ErrorCode> {
    let _ = "ErrorCode::from_wire(not a call)";
    ErrorCode::from_wire(word)
}

#[derive(serde::Deserialize)]
pub struct Kept {
    code: ErrorCode,
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_test_may_parse_a_code() {
        let _ = ErrorCode::from_wire("X");
    }
}
"#;

    const CASES: &str = "#[test]\nfn the_case() {}\n";

    const ROSTER: &str = "\
# a header
site | stored | the demo store | crates/kr-demo/src/store.rs | read | 1 | from_wire | unknown outcome | kr-demo::kept::the_case
type | stored | the demo store | crates/kr-demo/src/store.rs | Kept | - | a member | unknown outcome | kr-demo::kept::the_case
";

    fn tree(store: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("a folder");
        for (path, text) in [
            ("crates/kr-demo/src/store.rs", store),
            ("crates/kr-demo/tests/kept.rs", CASES),
        ] {
            let path = root.path().join(path);
            std::fs::create_dir_all(path.parent().expect("a folder")).expect("makes the folder");
            std::fs::write(path, text).expect("writes");
        }
        root
    }

    fn wrong(store: &str, roster: &str) -> String {
        failures(tree(store).path(), roster).join("\n")
    }

    #[test]
    fn a_tree_and_a_roster_that_agree_have_nothing_wrong() {
        assert_eq!(wrong(STORE, ROSTER), "");
    }

    #[test]
    fn a_new_call_that_no_row_names_is_refused() {
        let more = format!(
            "{STORE}\npub fn another(word: &str) {{ let _ = ErrorCode::from_wire(word); }}\n"
        );
        let said = wrong(&more, ROSTER);
        assert!(
            said.contains("fn another turns text into an error code 1 time(s) and no row names it"),
            "{said}"
        );
        // A second call in a function that a row names is a different count.
        let twice = STORE.replace(
            "    ErrorCode::from_wire(word)\n",
            "    let _ = ErrorCode::from_wire(word);\n    ErrorCode::from_wire(word)\n",
        );
        let said = wrong(&twice, ROSTER);
        assert!(
            said.contains("fn read turns text into an error code 2 time(s) and its row says 1"),
            "{said}"
        );
        // A parse whose type is inferred from a code beside it is a call too.
        let inferred = format!(
            "{STORE}\npub fn quiet(word: &str) -> ErrorCode {{\n    word.parse().unwrap_or(ErrorCode::OutcomeUnknown)\n}}\n"
        );
        let said = wrong(&inferred, ROSTER);
        assert!(
            said.contains("fn quiet turns text into an error code 1 time(s)"),
            "{said}"
        );
    }

    #[test]
    fn a_row_whose_call_is_gone_is_refused() {
        let gone = STORE.replace("ErrorCode::from_wire(word)\n}", "None\n}");
        let said = wrong(&gone, ROSTER);
        assert!(
            said.contains("a row names fn read of crates/kr-demo/src/store.rs, which no longer turns text into an error code"),
            "{said}"
        );
    }

    #[test]
    fn a_new_type_that_holds_a_code_and_no_row_names_is_refused() {
        let more = format!(
            "{STORE}\n#[derive(Clone, serde::Deserialize)]\npub struct Fresh {{\n    code: Option<ErrorCode>,\n}}\n\
             #[derive(serde::Deserialize)]\npub struct Wraps {{\n    inner: Fresh,\n}}\n\
             #[derive(serde::Serialize)]\npub struct Sent {{\n    code: ErrorCode,\n}}\n"
        );
        let said = wrong(&more, ROSTER);
        assert!(
            said.contains(
                "type Fresh holds an error code and derives Deserialize, and no row names it"
            ),
            "{said}"
        );
        assert!(
            said.contains("type Wraps holds an error code"),
            "a holder of a holder is one too: {said}"
        );
        assert!(
            !said.contains("type Sent"),
            "a type that is never read back is not one: {said}"
        );
    }

    #[test]
    fn a_row_whose_case_does_not_exist_is_refused() {
        let said = wrong(
            STORE,
            &ROSTER.replace("kept::the_case", "kept::does_not_exist"),
        );
        assert!(
            said.contains("crates/kr-demo/tests/kept.rs has no function does_not_exist"),
            "{said}"
        );
        let said = wrong(
            STORE,
            &ROSTER.replace("kr-demo::kept::the_case", "kr-demo::absent::the_case"),
        );
        assert!(
            said.contains("crates/kr-demo/tests/absent.rs does not exist"),
            "{said}"
        );
        let said = wrong(
            STORE,
            &ROSTER.replace(
                "kr-demo::kept::the_case",
                "kr-demo::lib::a_test_may_parse_a_code",
            ),
        );
        assert_eq!(
            said, "",
            "a case inside a test-only module of the crate's source exists as a function"
        );
        let said = wrong(
            STORE,
            &ROSTER.replace("kr-demo::kept::the_case", "kr-demo::lib::no_such_unit_case"),
        );
        assert!(
            said.contains("is in no source of crates/kr-demo/src"),
            "{said}"
        );
    }
}
