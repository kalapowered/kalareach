//! Every place that makes a value of the local protocol's error, named.
//!
//! `IpcError::comes_from` says where a failure comes from by its variant. A variant is made in
//! many places, and a place can make a value that does not come from where its variant usually
//! does. `error_makers.txt` lists every such place of the production sources under `crates` and
//! `apps`: the file, the owner (the function, with the type of its `impl` block), the variant, how
//! many times it is made there, what makes it there, its true source, and which calls of a control
//! connection can return it. The first case reads the sources again and fails for a maker with no
//! row and for a row with no maker, naming each. The second case holds the roster's claim about the
//! function: for every variant that a control connection can return, the function's answer for a
//! sample of the variant is the answer that the row says it gives.
//!
//! How the scan tells a construction from a match arm. It blanks comments, string and character
//! literals and every `#[cfg(test)]` item, then finds each `IpcError::Variant` and, inside an
//! `impl` of `IpcError`, each `Self::Variant`. A call of the constructors `io`, `socket` and
//! `stream` is a maker of `Io` and of `Socket`. An occurrence is a pattern, and not a maker, when
//! the token after it (and after its braces or parentheses, and any closing parentheses and commas) is `=>`,
//! `|`, `=` or `if`. An occurrence inside the arguments of any macro (`matches!`, `assert!`,
//! `format!`, `vec!`, a `macro_rules!` body, the delimiters that follow `name!`) is not classified:
//! the scan cannot tell what the macro does with it, so it counts as a maker and a row names it.
//! The row's source is the true source where the occurrence makes a value, and `pattern` where a
//! person read it as a pattern (a `matches!` that tests a value and makes none). A conversion is a
//! maker where it is written: each `impl .. for IpcError` that names a variant, and each `#[from]`
//! in the enum.
//!
//! What it cannot see:
//!
//! - where a conversion is used: a `?`, an `.into()` or a `map_err(Into::into)` that turns another
//!   error into one of these makes a value at the conversion's place, and the roster names that
//!   place only, with the sites of use in its note;
//! - a construction that a macro itself writes (inside its own definition's expansion), and a type
//!   alias or an import that renames `IpcError`;
//! - a pattern outside a macro that none of the tokens above ends: it counts as a maker and a row
//!   names it, so the scan errs toward asking;
//! - the code of a test build: a `#[cfg(test)]` item, a file under `tests`, and the `testing`
//!   feature's own helpers are not makers that a control connection returns;
//! - two functions of one name in one `impl` type of one file (the unix and the Windows module of
//!   `endpoint.rs` each have a `Connection::connect`): their makes are counted together;
//! - what the call graph reaches: the last column of a row is a person's read of the calls from
//!   `LocalClient::connect_listing`, `request` and the read and write of frames, held against the
//!   function only through the second case.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_ipc::IpcError;
use kr_ipc::error::ErrorSource;

/// The directories the reading covers, under the workspace's root.
const ROOTS: [&str; 2] = ["crates", "apps"];

/// The variants of the error.
const VARIANTS: [&str; 22] = [
    "Io",
    "Socket",
    "DirectoryNotOwnerOnly",
    "DirectoryAccessRefused",
    "SocketPathTooLong",
    "PeerRejected",
    "PeerUnknown",
    "PeerAccountRejected",
    "Frame",
    "PeerClosed",
    "TruncatedFrame",
    "UnexpectedMessage",
    "VersionMismatch",
    "HostRefused",
    "EnvironmentPrefixCollision",
    "UntrustedFile",
    "RightNotForwarded",
    "UnretainedLevel",
    "NotInLevel",
    "OutsideLevel",
    "LinkFenced",
    "IdentityUnavailable",
];

/// The constructors that make a variant, as they are called.
const CONSTRUCTORS: [(&str, &str); 3] = [("io", "Io"), ("socket", "Socket"), ("stream", "Socket")];

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// One place that makes a variant: the file, the owner and the variant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Place {
    file: String,
    owner: String,
    variant: String,
}

impl Place {
    fn said(&self) -> String {
        format!("{} | {} | {}", self.file, self.owner, self.variant)
    }
}

/// Blanks comments, string and character literals: what remains is code, with its lines and
/// columns where they were.
fn code_of(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut code = bytes.to_vec();
    let blank = |code: &mut Vec<u8>, from: usize, to: usize| {
        for byte in &mut code[from..to] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        if rest.starts_with(b"//") {
            let end = rest
                .iter()
                .position(|b| *b == b'\n')
                .map_or(bytes.len(), |p| i + p);
            blank(&mut code, i, end);
            i = end;
        } else if rest.starts_with(b"/*") {
            let mut depth = 1;
            let mut j = i + 2;
            while j < bytes.len() && depth > 0 {
                if bytes[j..].starts_with(b"/*") {
                    depth += 1;
                    j += 2;
                } else if bytes[j..].starts_with(b"*/") {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut code, i, j);
            i = j;
        } else if rest[0] == b'r'
            && (i == 0 || !is_word(bytes[i - 1]))
            && rest[1..].iter().find(|b| **b != b'#') == Some(&b'"')
        {
            let hashes = rest[1..].iter().take_while(|b| **b == b'#').count();
            let mut end_mark = vec![b'"'];
            end_mark.extend(std::iter::repeat_n(b'#', hashes));
            let from = i + 2 + hashes;
            let end = bytes[from..]
                .windows(end_mark.len())
                .position(|w| w == end_mark.as_slice())
                .map_or(bytes.len(), |p| from + p + end_mark.len());
            blank(&mut code, i, end);
            i = end;
        } else if rest[0] == b'"' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'"' {
                j += if bytes[j] == b'\\' { 2 } else { 1 };
            }
            let end = (j + 1).min(bytes.len());
            blank(&mut code, i, end);
            i = end;
        } else if rest[0] == b'\'' {
            // A character literal is `'x'` or `'\..'`; a lifetime is `'a` with no closing quote.
            let escaped = rest.get(1) == Some(&b'\\');
            let close = if escaped {
                rest[2..].iter().position(|b| *b == b'\'').map(|p| p + 2)
            } else {
                (rest.get(2) == Some(&b'\'')).then_some(2)
            };
            if let Some(close) = close {
                blank(&mut code, i, i + close + 1);
                i += close + 1;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    code
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The end of the balanced group that opens at `at` (a `{`, `(` or `[`), or the end of the text.
fn group_end(code: &[u8], at: usize) -> usize {
    let (open, close) = match code[at] {
        b'{' => (b'{', b'}'),
        b'(' => (b'(', b')'),
        _ => (b'[', b']'),
    };
    let mut depth = 0usize;
    for (offset, byte) in code[at..].iter().enumerate() {
        if *byte == open {
            depth += 1;
        } else if *byte == close {
            depth -= 1;
            if depth == 0 {
                return at + offset + 1;
            }
        }
    }
    code.len()
}

/// What a `cfg` condition is where the test configuration is off and every other condition is not
/// known.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Truth {
    False,
    True,
    Unknown,
}

/// The parts of `list`, split at the commas that stand outside every parenthesis.
fn top_level_parts(list: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut from) = (0usize, 0usize);
    for (at, character) in list.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&list[from..at]);
                from = at + 1;
            }
            _ => {}
        }
    }
    parts.push(&list[from..]);
    parts
}

/// What the condition `condition` of a `cfg` is where the test configuration is off: `test` is
/// false, `not`, `all` and `any` combine, and every other condition (`unix`, a feature, a target)
/// is not known. An item is test code only where its condition is false here.
fn cfg_truth(condition: &str) -> Truth {
    let condition = condition.trim();
    let arguments = |name: &str| {
        condition
            .strip_prefix(name)
            .and_then(|rest| rest.trim_start().strip_prefix('('))
            .and_then(|rest| rest.trim_end().strip_suffix(')'))
    };
    if condition == "test" {
        return Truth::False;
    }
    if let Some(inner) = arguments("not") {
        return match cfg_truth(inner) {
            Truth::False => Truth::True,
            Truth::True => Truth::False,
            Truth::Unknown => Truth::Unknown,
        };
    }
    if let Some(inner) = arguments("all") {
        let parts: Vec<Truth> = top_level_parts(inner).into_iter().map(cfg_truth).collect();
        return if parts.contains(&Truth::False) {
            Truth::False
        } else if parts.iter().all(|part| *part == Truth::True) {
            Truth::True
        } else {
            Truth::Unknown
        };
    }
    if let Some(inner) = arguments("any") {
        let parts: Vec<Truth> = top_level_parts(inner).into_iter().map(cfg_truth).collect();
        return if parts.contains(&Truth::True) {
            Truth::True
        } else if parts.iter().all(|part| *part == Truth::False) {
            Truth::False
        } else {
            Truth::Unknown
        };
    }
    Truth::Unknown
}

/// The attributes `#[cfg(..)]` of `code` whose condition is the test configuration alone, that is
/// false where the test configuration is off (`test`, `all(test, unix)`): where each ends, and where
/// it starts. An item under `any(test, unix)` is production code on unix and stays.
fn test_attributes(code: &[u8]) -> Vec<(usize, usize)> {
    let mark = b"#[cfg(";
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(at) = code[from..].windows(mark.len()).position(|w| w == mark) {
        let start = from + at;
        let end = group_end(code, start + 1);
        let text = String::from_utf8_lossy(&code[start..end]).into_owned();
        let condition = text
            .strip_prefix("#[cfg(")
            .and_then(|rest| rest.strip_suffix(")]"))
            .unwrap_or("");
        if cfg_truth(condition) == Truth::False {
            found.push((start, end));
        }
        from = end;
    }
    found
}

/// Blanks every item that a test attribute marks: from the attribute to the end of the item's
/// braces, or to its semicolon.
fn without_tests(code: &mut [u8]) {
    for (start, attribute_end) in test_attributes(code) {
        let mut at = attribute_end;
        while at < code.len() && code[at] != b'{' && code[at] != b';' {
            at += 1;
        }
        let end = if at < code.len() && code[at] == b'{' {
            group_end(code, at)
        } else {
            (at + 1).min(code.len())
        };
        for byte in &mut code[start..end] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
}

/// The module files that a test attribute gates in `file`: the paths, without `.rs`, of each
/// `#[cfg(test)] mod name;` of the file. A file at one of them, or below it, is test code.
fn gated_modules(file: &str, text: &str) -> Vec<String> {
    let code = code_of(text);
    let stem = Path::new(file)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let directory = Path::new(file).parent().unwrap_or(Path::new(""));
    let base = if ["mod", "lib", "main"].contains(&stem) {
        directory.to_path_buf()
    } else {
        directory.join(stem)
    };
    let mut gated = Vec::new();
    for (_, mut at) in test_attributes(&code) {
        loop {
            at = skip_space(&code, at);
            if code[at..].starts_with(b"#[") {
                at = group_end(&code, at + 1);
            } else {
                break;
            }
        }
        let after_pub = if code[at..].starts_with(b"pub(") {
            skip_space(&code, group_end(&code, at + 3))
        } else if code[at..].starts_with(b"pub ") {
            at + 4
        } else {
            at
        };
        if code[after_pub..].starts_with(b"mod ") {
            let (name, end) = word_at(&code, skip_space(&code, after_pub + 4));
            if code.get(skip_space(&code, end)) == Some(&b';') {
                gated.push(base.join(name).to_string_lossy().replace('\\', "/"));
            }
        }
    }
    gated
}

/// The word that starts at `at`, and where it ends.
fn word_at(code: &[u8], at: usize) -> (&str, usize) {
    let mut end = at;
    while end < code.len() && is_word(code[end]) {
        end += 1;
    }
    (std::str::from_utf8(&code[at..end]).unwrap_or(""), end)
}

fn skip_space(code: &[u8], mut at: usize) -> usize {
    while at < code.len() && code[at].is_ascii_whitespace() {
        at += 1;
    }
    at
}

/// The type that an `impl` block is for: the type after `for`, or the type itself.
fn impl_type(code: &[u8], after_keyword: usize) -> String {
    let mut end = after_keyword;
    while end < code.len() && code[end] != b'{' && code[end] != b';' {
        end += 1;
    }
    let header = String::from_utf8_lossy(&code[after_keyword..end]).into_owned();
    let mut header = header.trim();
    if header.starts_with('<') {
        let mut depth = 0usize;
        for (at, c) in header.char_indices() {
            match c {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        header = header[at + 1..].trim();
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    let header = header.rsplit(" for ").next().unwrap_or(header).trim();
    let name: String = header
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
        .collect();
    name.rsplit("::").next().unwrap_or("").to_owned()
}

/// Whether the occurrence of a variant that spans `start..end` is a pattern: what follows it (past
/// its group and any closing parentheses) is `=>`, `|`, `=` or `if`. The caller has already
/// excluded an occurrence inside a macro's arguments, which this cannot classify.
fn is_pattern(code: &[u8], end: usize) -> bool {
    let mut after = skip_space(code, end);
    if after < code.len() && (code[after] == b'{' || code[after] == b'(') {
        after = skip_space(code, group_end(code, after));
    }
    while after < code.len() && (code[after] == b')' || code[after] == b',') {
        after = skip_space(code, after + 1);
    }
    let next = &code[after.min(code.len())..];
    next.starts_with(b"=>")
        || next.starts_with(b"if ")
        || (next.starts_with(b"|") && !next.starts_with(b"||"))
        || (next.starts_with(b"=") && !next.starts_with(b"=="))
}

/// Whether the delimiter that opens at `open` begins the arguments of a macro: `name!(`, `name![`,
/// `name!{`, or the body of `macro_rules! name {`.
fn opens_a_macro(code: &[u8], open: usize) -> bool {
    let mut at = open;
    while at > 0 && code[at - 1].is_ascii_whitespace() {
        at -= 1;
    }
    if at > 0 && code[at - 1] == b'!' {
        return at > 1 && is_word(code[at - 2]);
    }
    let mut start = at;
    while start > 0 && is_word(code[start - 1]) {
        start -= 1;
    }
    if start == at {
        return false;
    }
    while start > 0 && code[start - 1].is_ascii_whitespace() {
        start -= 1;
    }
    start > 0 && code[start - 1] == b'!' && code[..start - 1].ends_with(b"macro_rules")
}

/// Whether `at` stands inside the arguments of a macro: some delimiter that encloses it opens one.
/// The scan cannot tell what a macro does with what is inside, so an occurrence there is not
/// classified: it counts as a maker, and a row names it.
fn in_macro_arguments(code: &[u8], at: usize) -> bool {
    let mut closed = 0usize;
    for index in (0..at).rev() {
        match code[index] {
            b')' | b']' | b'}' => closed += 1,
            b'(' | b'[' | b'{' => {
                if closed > 0 {
                    closed -= 1;
                } else if opens_a_macro(code, index) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// A scope that a `{` opened: a function (its name) or an `impl` (its type).
enum Scope {
    Function(String),
    Impl(String),
}

/// What an occurrence of `IpcError::name` or `Self::name` makes, where it makes one.
fn made_by(code: &[u8], name: &str, end: usize) -> Option<&'static str> {
    if let Some(variant) = VARIANTS.iter().copied().find(|variant| *variant == name) {
        return Some(variant);
    }
    let called = code.get(skip_space(code, end)) == Some(&b'(');
    CONSTRUCTORS
        .iter()
        .find(|(constructor, _)| called && *constructor == name)
        .map(|(_, variant)| *variant)
}

/// The makers of one file's text, by place, with how many times each is made there.
fn makers_in(file: &str, text: &str) -> BTreeMap<Place, usize> {
    let mut code = code_of(text);
    without_tests(&mut code);
    let mut found = BTreeMap::new();
    let mut scopes: Vec<(usize, Scope)> = Vec::new();
    let mut pending: Option<Scope> = None;
    let mut depth = 0usize;
    let enum_body = enum_body(&code);
    let mut i = 0;
    while i < code.len() {
        let byte = code[i];
        if byte == b'{' {
            depth += 1;
            if let Some(scope) = pending.take() {
                scopes.push((depth, scope));
            }
        } else if byte == b'}' {
            while scopes.last().is_some_and(|(at, _)| *at == depth) {
                scopes.pop();
            }
            depth = depth.saturating_sub(1);
        } else if byte == b';' {
            pending = None;
        } else if is_word(byte) && (i == 0 || !is_word(code[i - 1])) {
            let (word, end) = word_at(&code, i);
            let at_item = code[..i]
                .iter()
                .rev()
                .find(|b| !b.is_ascii_whitespace())
                .is_none_or(|b| b"}{;]".contains(b));
            match word {
                "fn" => {
                    let (name, _) = word_at(&code, skip_space(&code, end));
                    if !name.is_empty() {
                        pending = Some(Scope::Function(name.to_owned()));
                    }
                }
                "impl" if at_item => pending = Some(Scope::Impl(impl_type(&code, end))),
                "IpcError" | "Self" => {
                    if let Some(place) = occurrence(&code, i, end, word, &scopes, file) {
                        *found.entry(place).or_insert(0) += 1;
                    }
                }
                _ => {}
            }
            i = end;
            continue;
        } else if code[i..].starts_with(b"#[from]")
            && let Some((from, to)) = enum_body
            && (from..to).contains(&i)
            && let Some(variant) = variant_before(&code, i)
        {
            let place = Place {
                file: file.to_owned(),
                owner: "IpcError::#[from]".to_owned(),
                variant,
            };
            *found.entry(place).or_insert(0) += 1;
        }
        i += 1;
    }
    found
}

/// The place that the word at `start..end` (`IpcError` or `Self`) makes, when it makes one.
fn occurrence(
    code: &[u8],
    start: usize,
    end: usize,
    word: &str,
    scopes: &[(usize, Scope)],
    file: &str,
) -> Option<Place> {
    let in_error = scopes
        .iter()
        .any(|(_, scope)| matches!(scope, Scope::Impl(name) if name == "IpcError"));
    if (word == "Self" && !in_error) || !code[end..].starts_with(b"::") {
        return None;
    }
    let (name, name_end) = word_at(code, end + 2);
    let variant = made_by(code, name, name_end)?;
    let is_constructor = name.chars().next().is_some_and(char::is_lowercase);
    if !is_constructor && !in_macro_arguments(code, start) && is_pattern(code, name_end) {
        return None;
    }
    let function = scopes.iter().rev().find_map(|(_, scope)| match scope {
        Scope::Function(name) => Some(name.as_str()),
        Scope::Impl(_) => None,
    });
    let owner_type = scopes.iter().rev().find_map(|(_, scope)| match scope {
        Scope::Impl(name) => Some(name.as_str()),
        Scope::Function(_) => None,
    });
    let owner = match (owner_type, function) {
        (Some(owner_type), Some(function)) => format!("{owner_type}::{function}"),
        (None, Some(function)) => function.to_owned(),
        (_, None) => "-".to_owned(),
    };
    Some(Place {
        file: file.to_owned(),
        owner,
        variant: variant.to_owned(),
    })
}

/// The span of the body of `enum IpcError`, where the file has it.
fn enum_body(code: &[u8]) -> Option<(usize, usize)> {
    let mark = b"enum IpcError";
    let at = code.windows(mark.len()).position(|w| w == mark)?;
    let open = at + code[at..].iter().position(|b| *b == b'{')?;
    Some((open, group_end(code, open)))
}

/// The variant whose parenthesis holds the attribute at `at`.
fn variant_before(code: &[u8], at: usize) -> Option<String> {
    let mut end = at;
    while end > 0 && code[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end == 0 || code[end - 1] != b'(' {
        return None;
    }
    let close = end - 1;
    let mut start = close;
    while start > 0 && is_word(code[start - 1]) {
        start -= 1;
    }
    Some(String::from_utf8_lossy(&code[start..close]).into_owned())
}

/// Every `.rs` file of the production sources under `roots`, as (path from `root`, text).
fn sources(root: &Path, roots: &[&str]) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut pending: Vec<PathBuf> = roots.iter().map(|name| root.join(name)).collect();
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if ![
                    "target",
                    "node_modules",
                    "tests",
                    "benches",
                    "examples",
                    ".git",
                ]
                .contains(&name.as_str())
                {
                    pending.push(path);
                }
            } else if name.ends_with(".rs") && name != "tests.rs" {
                let relative = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                if relative.contains("/src/")
                    && let Ok(text) = std::fs::read_to_string(&path)
                {
                    found.push((relative, text));
                }
            }
        }
    }
    found.sort();
    found
}

/// The makers of every file in `files`.
fn makers(files: &[(String, String)]) -> BTreeMap<Place, usize> {
    let mut all = BTreeMap::new();
    let gated: Vec<String> = files
        .iter()
        .flat_map(|(file, text)| gated_modules(file, text))
        .collect();
    for (file, text) in files {
        let stem = file.strip_suffix(".rs").unwrap_or(file);
        if gated
            .iter()
            .any(|prefix| stem == prefix || stem.starts_with(&format!("{prefix}/")))
        {
            continue;
        }
        if text.contains("IpcError") || text.contains("impl From") {
            all.extend(makers_in(file, text));
        }
    }
    all
}

/// One row of the roster.
#[derive(Clone, Debug)]
struct Row {
    place: Place,
    count: usize,
    what: String,
    source: String,
    control: String,
    function: String,
}

/// Reads the roster: lines of `file | owner | variant | n | what | source | control | function`.
fn roster(text: &str) -> Result<Vec<Row>, String> {
    let mut rows = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.split("   # ").next().unwrap_or("").trim();
        let cells: Vec<&str> = line.split(" | ").map(str::trim).collect();
        let [file, owner, variant, count, what, source, control, function] = cells[..] else {
            return Err(format!("line {}: {} cells, not 8", number + 1, cells.len()));
        };
        let count = count
            .parse()
            .map_err(|_| format!("line {}: n is no number", number + 1))?;
        if !["own", "arrived", "connect", "stream", "conversion", "macro"].contains(&what) {
            return Err(format!(
                "line {}: what `{what}` is none of the six",
                number + 1
            ));
        }
        if ![
            "reply",
            "closure",
            "own",
            "by-kind",
            "closure+own",
            "pattern",
        ]
        .contains(&source)
        {
            return Err(format!(
                "line {}: source `{source}` is none of the six",
                number + 1
            ));
        }
        if source == "pattern" {
            if what != "macro" || control != "-" || function != "-" {
                return Err(format!(
                    "line {}: a pattern is read in a macro's arguments and makes no value, so its what is macro and its control and function are -",
                    number + 1
                ));
            }
        } else if !["agrees", "differs", "by-kind"].contains(&function) {
            return Err(format!(
                "line {}: function `{function}` is none of the three",
                number + 1
            ));
        }
        rows.push(Row {
            place: Place {
                file: file.to_owned(),
                owner: owner.to_owned(),
                variant: variant.to_owned(),
            },
            count,
            what: what.to_owned(),
            source: source.to_owned(),
            control: control.to_owned(),
            function: function.to_owned(),
        });
    }
    Ok(rows)
}

/// What differs between the makers found and the rows: a maker with no row, a row with no maker,
/// and a count that differs. Empty where they hold each other.
fn differences(found: &BTreeMap<Place, usize>, rows: &[Row]) -> Vec<String> {
    let mut said = Vec::new();
    let listed: BTreeMap<&Place, usize> = rows.iter().map(|row| (&row.place, row.count)).collect();
    for (place, count) in found {
        match listed.get(place) {
            None => said.push(format!(
                "a maker with no row: {} (made {count} times)",
                place.said()
            )),
            Some(rows_count) if rows_count != count => said.push(format!(
                "{}: made {count} times, the row says {rows_count}",
                place.said()
            )),
            Some(_) => {}
        }
    }
    for place in listed.keys() {
        if !found.contains_key(*place) {
            said.push(format!("a row with no maker: {}", place.said()));
        }
    }
    said
}

fn roster_text() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/error_makers.txt"))
        .expect("the roster is beside this test")
}

/// The makers of the workspace, row by row, as the roster writes them with no classification.
#[test]
fn every_maker_has_a_row_and_every_row_a_maker() {
    let files = sources(&repository(), &ROOTS);
    let found = makers(&files);
    if std::env::var_os("KR_ERROR_MAKERS_PRINT").is_some() {
        for (place, count) in &found {
            println!("MAKER {} | {count}", place.said());
        }
    }
    let rows = roster(&roster_text()).expect("the roster reads");
    let said = differences(&found, &rows);
    assert!(
        said.is_empty(),
        "the roster and the sources differ:\n{}",
        said.join("\n")
    );
}

/// The scan fails for a planted maker with no row, for a planted row with no maker, and for a
/// count that changed, and it keeps a construction apart from a match arm.
#[test]
fn the_scan_names_a_maker_with_no_row_and_a_row_with_no_maker() {
    let text = "\
impl Client {
    fn greet(&self) -> Result<(), IpcError> {
        Err(IpcError::PeerClosed)
    }
    fn tell(&self, error: &IpcError) -> bool {
        // IpcError::HostRefused { detail } in a comment, and \"IpcError::LinkFenced\" in a string.
        match error {
            IpcError::PeerClosed | IpcError::TruncatedFrame { .. } => true,
            IpcError::Frame(_) if self.ready() => false,
            _ => false,
        }
    }
}
#[cfg(test)]
mod tests {
    fn planted() -> IpcError {
        IpcError::UnexpectedMessage(\"a test's own\")
    }
}
";
    let files = vec![("crates/x/src/client.rs".to_owned(), text.to_owned())];
    let found = makers(&files);
    let places: Vec<String> = found.keys().map(Place::said).collect();
    assert_eq!(
        places,
        vec!["crates/x/src/client.rs | Client::greet | PeerClosed"]
    );

    let row = |owner: &str, variant: &str, count: usize| Row {
        place: Place {
            file: "crates/x/src/client.rs".to_owned(),
            owner: owner.to_owned(),
            variant: variant.to_owned(),
        },
        count,
        what: "own".to_owned(),
        source: "own".to_owned(),
        control: "-".to_owned(),
        function: "agrees".to_owned(),
    };
    assert!(differences(&found, &[row("Client::greet", "PeerClosed", 1)]).is_empty());
    let said = differences(&found, &[]);
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].starts_with(
            "a maker with no row: crates/x/src/client.rs | Client::greet | PeerClosed"
        ),
        "{said:?}"
    );
    let said = differences(
        &found,
        &[
            row("Client::greet", "PeerClosed", 1),
            row("Client::tell", "Frame", 1),
        ],
    );
    assert_eq!(
        said,
        vec!["a row with no maker: crates/x/src/client.rs | Client::tell | Frame"]
    );
    let said = differences(&found, &[row("Client::greet", "PeerClosed", 2)]);
    assert_eq!(
        said,
        vec!["crates/x/src/client.rs | Client::greet | PeerClosed: made 1 times, the row says 2"]
    );

    let planted = format!(
        "{text}\nimpl Client {{\n    fn more(&self) -> IpcError {{\n        IpcError::socket(\"x\", e)\n    }}\n}}\n"
    );
    let found = makers(&[("crates/x/src/client.rs".to_owned(), planted)]);
    let said = differences(&found, &[row("Client::greet", "PeerClosed", 1)]);
    assert_eq!(
        said,
        vec!["a maker with no row: crates/x/src/client.rs | Client::more | Socket (made 1 times)"]
    );
}

/// An occurrence inside a macro's arguments is not classified by the scan and counts as a maker: a
/// `matches!` that tests a value, an `assert!`, a `format!` and the body of a `macro_rules!` are
/// named, with the count of occurrences there. The delimiters of an earlier macro do not reach
/// across its end: a construction in the block after `if matches!(flag, true)` is a maker of its
/// own function, and so is one in a closure that no macro encloses.
#[test]
fn an_occurrence_inside_a_macro_is_a_maker_and_one_after_a_macro_is_read_for_itself() {
    let text = "\
impl Client {
    fn after_a_macro(&self, flag: bool) -> Result<(), IpcError> {
        if matches!(flag, true) {
            return Err(IpcError::PeerClosed);
        }
        Ok(())
    }
    fn tests_a_value(&self, error: &IpcError) -> bool {
        matches!(error, IpcError::TruncatedFrame { .. } | IpcError::PeerClosed)
    }
    fn names_one(&self, error: &IpcError) {
        assert!(!matches!(error, IpcError::HostRefused { .. }), \"{}\", IpcError::LinkFenced { detail: String::new() });
    }
    fn in_a_loop(&self) -> Result<(), IpcError> {
        let again = vec![1, 2].into_iter().map(|_| IpcError::UnexpectedMessage(\"x\")).count();
        Err(IpcError::NotInLevel(String::new()))
    }
}
macro_rules! make {
    () => {
        IpcError::OutsideLevel(String::new())
    };
}
";
    let found = makers(&[("crates/x/src/client.rs".to_owned(), text.to_owned())]);
    let places: Vec<String> = found
        .iter()
        .map(|(place, count)| format!("{} x{count}", place.said()))
        .collect();
    assert_eq!(
        places,
        vec![
            "crates/x/src/client.rs | - | OutsideLevel x1",
            "crates/x/src/client.rs | Client::after_a_macro | PeerClosed x1",
            "crates/x/src/client.rs | Client::in_a_loop | NotInLevel x1",
            "crates/x/src/client.rs | Client::in_a_loop | UnexpectedMessage x1",
            "crates/x/src/client.rs | Client::names_one | HostRefused x1",
            "crates/x/src/client.rs | Client::names_one | LinkFenced x1",
            "crates/x/src/client.rs | Client::tests_a_value | PeerClosed x1",
            "crates/x/src/client.rs | Client::tests_a_value | TruncatedFrame x1",
        ]
    );
}

/// A sample of a variant, in the kinds of failure that a maker of the given class (`what`) can give.
fn sample(variant: &str, what: &str) -> Vec<IpcError> {
    let socket = |kind| IpcError::socket("a sample", std::io::Error::from(kind));
    match variant {
        "Socket" => match what {
            "connect" => vec![
                socket(std::io::ErrorKind::NotFound),
                socket(std::io::ErrorKind::ConnectionRefused),
                socket(std::io::ErrorKind::TimedOut),
            ],
            "stream" => vec![
                socket(std::io::ErrorKind::TimedOut),
                socket(std::io::ErrorKind::Other),
            ],
            _ => vec![socket(std::io::ErrorKind::Other)],
        },
        "PeerClosed" => vec![IpcError::PeerClosed],
        "PeerUnknown" => vec![IpcError::PeerUnknown {
            source: std::io::Error::other("a sample"),
        }],
        "PeerRejected" => vec![IpcError::PeerRejected {
            peer_uid: 1,
            owner_uid: 2,
        }],
        "PeerAccountRejected" => vec![IpcError::PeerAccountRejected {
            detail: "a sample".to_owned(),
        }],
        "TruncatedFrame" => vec![IpcError::TruncatedFrame {
            received: 1,
            expected: 2,
        }],
        "Frame" => vec![IpcError::Frame(
            kr_protocol::frame::FrameError::EmptyPayload,
        )],
        "UnexpectedMessage" => vec![IpcError::UnexpectedMessage("a sample")],
        "VersionMismatch" => vec![IpcError::VersionMismatch {
            host: "1".to_owned(),
            offered: "2".to_owned(),
        }],
        "HostRefused" => vec![IpcError::HostRefused {
            detail: "a sample".to_owned(),
        }],
        "LinkFenced" => vec![IpcError::LinkFenced {
            detail: "a sample".to_owned(),
        }],
        "NotInLevel" => vec![IpcError::NotInLevel("a sample".to_owned())],
        "OutsideLevel" => vec![IpcError::OutsideLevel("a sample".to_owned())],
        "IdentityUnavailable" => vec![IpcError::IdentityUnavailable {
            what: "a sample",
            detail: "a sample".to_owned(),
        }],
        other => {
            panic!("a control connection can return {other}, and this case has no sample of it")
        }
    }
}

fn said_source(source: ErrorSource) -> &'static str {
    match source {
        ErrorSource::Reply => "reply",
        ErrorSource::Closure => "closure",
        ErrorSource::OwnFault => "own",
    }
}

/// An item that stands under a `cfg` condition is left out of the scan only where its condition is
/// the test configuration alone: `test`, or `all` of it with others. An item under `any(test, unix)`
/// or `any(test, windows)` is production code on that platform and its makers stand in the roster, as
/// one under `unix`, `not(test)` or a feature does.
#[test]
fn an_item_is_left_out_only_where_its_condition_is_the_test_configuration_alone() {
    let text = "\
#[cfg(test)]
fn only_in_tests() -> IpcError { IpcError::OutsideLevel(String::new()) }
#[cfg(all(test, unix))]
fn only_in_tests_on_unix() -> IpcError { IpcError::OutsideLevel(String::new()) }
#[cfg(all(unix, test))]
fn only_in_tests_on_unix_too() -> IpcError { IpcError::OutsideLevel(String::new()) }
#[cfg(any(test, unix))]
fn in_tests_and_on_unix() -> IpcError { IpcError::PeerClosed }
#[cfg(any(windows, test))]
fn in_tests_and_on_windows() -> IpcError { IpcError::UnexpectedMessage(\"x\") }
#[cfg(not(test))]
fn outside_tests() -> IpcError { IpcError::NotInLevel(String::new()) }
#[cfg(unix)]
fn on_unix() -> IpcError { IpcError::NotInLevel(String::new()) }
";
    let found = makers(&[("crates/x/src/client.rs".to_owned(), text.to_owned())]);
    let owners: Vec<String> = found.keys().map(|place| place.said()).collect();
    let want = [
        "crates/x/src/client.rs | in_tests_and_on_unix | PeerClosed",
        "crates/x/src/client.rs | in_tests_and_on_windows | UnexpectedMessage",
        "crates/x/src/client.rs | on_unix | NotInLevel",
        "crates/x/src/client.rs | outside_tests | NotInLevel",
    ];
    assert_eq!(owners, want);
}

/// For every row that a control connection can return, the row's `function` cell says whether the
/// function's answer for the variant is the row's source, and the function's answers show it.
#[test]
fn the_function_answers_the_roster_for_what_a_control_connection_returns() {
    let rows = roster(&roster_text()).expect("the roster reads");
    for row in rows.iter().filter(|row| row.control != "-") {
        let answers: Vec<&str> = sample(&row.place.variant, &row.what)
            .iter()
            .map(|error| said_source(error.comes_from()))
            .collect();
        let uniform = answers.iter().all(|answer| *answer == answers[0]);
        let claimed = match row.function.as_str() {
            "by-kind" => !uniform && row.source == "closure+own",
            "agrees" => uniform && answers[0] == row.source,
            _ => uniform && answers[0] != row.source,
        };
        assert!(
            claimed,
            "{}: the row says source {}, function {}; the function answers {answers:?}",
            row.place.said(),
            row.source,
            row.function
        );
    }
}
