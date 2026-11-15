//! The roster: the checked-in table of every start in the daemon's process, and its comparison
//! with what a scan finds.
//!
//! One line of `spawn_sites.txt` is one row, with eight columns between `|` marks:
//!
//! `file | function | form | callee | count | class | task | note`
//!
//! A row stands for `count` starts that share the file, the function, the form and the callee.
//! A line that begins with `helper` names a function of this code that starts a task running one
//! of its own parameters, and has the columns `helper | name | scope | note`: each call of that
//! name in a file under `scope` (a file or a folder) is a start, keyed by the argument at the
//! parameter's place. A line that begins with `names` is a path of a watched crate that the daemon's
//! code names, `names | path`. Blank lines and lines that begin with `#` are comments.
//!
//! A row of class `joined` whose start is not awaited where it stands carries a marker in its note,
//! `join(function on name)`: the function of the same file that awaits the handle, and the name the
//! handle has there. The comparison checks that the source still awaits it. Where the marker's
//! function is the one that holds the start, the start's own handle (`let name = start(..)`) must be
//! the name that is awaited, in the scope where that name is bound, so that a second handle of the
//! same name in another scope does not stand for it. Where the function is another one, which the
//! handle is handed to, it checks that the source awaits that name in that function.
//!
//! A row of class `request` begins its note with its bound, `bound(form at path:line)`, and then
//! says it in words. The form is one of five (`FORMS`), and the place is a line of a file of the
//! tree that holds what the form names, which `bound_problems` checks against the source. The check
//! reads the line's words, not a parse: it does not see whether the `.await` is the task's handle's,
//! whether the `JoinSet` is the one the task goes into, whether the `Drop` aborts the task, whether
//! the receive is in every wait of the task, or a line inside a block comment or a multi-line string.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::scan::{Files, Scan, Start};

/// What a start is, for the way a task supervisor treats it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// A task that lives as long as the daemon and that the supervisor must take.
    SupervisedLater,
    /// Work that ends with the request, connection, session or owner that started it.
    Request,
    /// A start whose handle its starter awaits. A start that is awaited where it stands is always
    /// this class.
    Joined,
    /// A task of a linked crate.
    OtherCrate,
    /// A start in code that only a test build compiles in (a test module or the `testing`
    /// feature). Every such start is this class.
    Test,
}

impl Class {
    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "supervised-later" => Self::SupervisedLater,
            "request" => Self::Request,
            "joined" => Self::Joined,
            "other_crate" => Self::OtherCrate,
            "test" => Self::Test,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::SupervisedLater => "supervised-later",
            Self::Request => "request",
            Self::Joined => "joined",
            Self::OtherCrate => "other_crate",
            Self::Test => "test",
        }
    }
}

type Key = (String, String, String, String);

#[derive(Clone, Debug)]
pub struct Row {
    pub file: String,
    pub function: String,
    pub form: String,
    pub callee: String,
    pub count: usize,
    pub class: Class,
    pub task: Option<u32>,
    pub note: String,
    /// Where the handle of the start is awaited, from the note's marker: a function of the same
    /// file and the handle's name there.
    pub join: Option<(String, String)>,
}

impl Row {
    pub fn key(&self) -> Key {
        (
            self.file.clone(),
            self.function.clone(),
            self.form.clone(),
            self.callee.clone(),
        )
    }
}

#[derive(Clone, Debug)]
pub struct Helper {
    pub name: String,
    /// The file or folder that the helper is defined in and that its calls are looked for under.
    pub scope: String,
}

#[derive(Debug, Default)]
pub struct Roster {
    pub rows: Vec<Row>,
    pub helpers: Vec<Helper>,
    /// The paths of the watched crates that the daemon's code names.
    pub names: Vec<String>,
}

impl Roster {
    pub fn helper_scopes(&self) -> Vec<(String, String)> {
        self.helpers
            .iter()
            .map(|helper| (helper.name.clone(), helper.scope.clone()))
            .collect()
    }
}

pub fn parse(text: &str) -> Result<Roster, String> {
    let mut roster = Roster::default();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let columns: Vec<&str> = line.split('|').map(str::trim).collect();
        if columns[0] == "names" {
            let [_, path] = columns[..] else {
                return Err(format!("line {number}: a names line has two columns"));
            };
            roster.names.push(path.to_string());
            continue;
        }
        if columns[0] == "helper" {
            let [_, name, scope, _note] = columns[..] else {
                return Err(format!("line {number}: a helper line has four columns"));
            };
            roster.helpers.push(Helper {
                name: name.to_string(),
                scope: scope.to_string(),
            });
            continue;
        }
        let [file, function, form, callee, count, class, task, note] = columns[..] else {
            return Err(format!(
                "line {number}: a row has eight columns, this one has {}",
                columns.len()
            ));
        };
        let count: usize = count
            .parse()
            .map_err(|_| format!("line {number}: the count `{count}` is not a number"))?;
        if count == 0 {
            return Err(format!(
                "line {number}: a row stands for at least one start"
            ));
        }
        let class = Class::parse(class)
            .ok_or_else(|| format!("line {number}: `{class}` is not a class"))?;
        let task =
            match task {
                "-" => None,
                text => Some(text.parse().map_err(|_| {
                    format!("line {number}: the task number `{text}` is not a number")
                })?),
            };
        if class == Class::SupervisedLater && task.is_none() {
            return Err(format!(
                "line {number}: a supervised-later row names its task number"
            ));
        }
        let join = join_marker(note).map_err(|why| format!("line {number}: {why}"))?;
        roster.rows.push(Row {
            file: file.to_string(),
            function: function.to_string(),
            form: form.to_string(),
            callee: callee.to_string(),
            count,
            class,
            task,
            note: note.to_string(),
            join,
        });
    }
    let mut paths = BTreeSet::new();
    for path in &roster.names {
        if !paths.insert(path) {
            return Err(format!("the path {path} is listed twice"));
        }
    }
    let mut keys = BTreeSet::new();
    for row in &roster.rows {
        if !keys.insert(row.key()) {
            return Err(format!(
                "two rows share {} | {} | {} | {}: join them and add their counts",
                row.file, row.function, row.form, row.callee
            ));
        }
    }
    Ok(roster)
}

/// The marker `join(function on name)` in a note: where the handle of a start is awaited.
fn join_marker(note: &str) -> Result<Option<(String, String)>, String> {
    let Some(at) = note.find("join(") else {
        return Ok(None);
    };
    let inside = &note[at + "join(".len()..];
    let Some(end) = inside.find(')') else {
        return Err("a join marker is not closed".to_string());
    };
    match inside[..end].split_once(" on ") {
        Some((function, name)) if !function.trim().is_empty() && !name.trim().is_empty() => {
            Ok(Some((function.trim().to_string(), name.trim().to_string())))
        }
        _ => Err("a join marker is `join(function on name)`".to_string()),
    }
}

/// A start as a line of the roster, for a person to complete and add.
pub fn line_of(key: &Key, count: usize) -> String {
    format!(
        "{} | {} | {} | {} | {count} | ? | - | ?",
        key.0, key.1, key.2, key.3
    )
}

/// What the starts that share one key have in common.
struct Found<'a> {
    count: usize,
    all_at_once: bool,
    all_unshipped: bool,
    starts: Vec<&'a Start>,
}

/// Everything that makes the roster and a scan disagree, one sentence each. Empty when they agree.
pub fn disagreements(roster: &Roster, scan: &Scan) -> Vec<String> {
    let mut problems = Vec::new();

    let mut found: BTreeMap<Key, Found> = BTreeMap::new();
    for start in &scan.starts {
        let entry = found.entry(Start::key(start)).or_insert(Found {
            count: 0,
            all_at_once: true,
            all_unshipped: true,
            starts: Vec::new(),
        });
        entry.count += 1;
        entry.all_at_once &= start.at_once;
        entry.all_unshipped &= start.unshipped;
        entry.starts.push(start);
    }
    let listed: BTreeMap<Key, &Row> = roster.rows.iter().map(|row| (row.key(), row)).collect();

    for (key, start) in &found {
        let Some(row) = listed.get(key) else {
            problems.push(format!(
                "a start that no row names ({}): add `{}`",
                start.count,
                line_of(key, start.count)
            ));
            continue;
        };
        let describe = format!("{} | {} | {} | {}", key.0, key.1, key.2, key.3);
        if row.count != start.count {
            problems.push(format!(
                "the roster says {} start(s) and the source has {} of: {describe}",
                row.count, start.count
            ));
        }
        if start.all_unshipped && row.class != Class::Test {
            problems.push(format!(
                "a start that only a test build compiles in is class test, and this row says {}: {describe}",
                row.class.name()
            ));
        }
        if row.class == Class::Test && !start.all_unshipped {
            problems.push(format!(
                "a row of class test has a start that a shipped build compiles in: {describe}"
            ));
        }
        if start.all_at_once && !start.all_unshipped && row.class != Class::Joined {
            problems.push(format!(
                "a start that is awaited where it stands is class joined, and this row says {}: {describe}",
                row.class.name()
            ));
        }
        if row.class == Class::Joined && !start.all_at_once && !start.all_unshipped {
            match &row.join {
                None => problems.push(format!(
                    "a row of class joined whose start is not awaited where it stands names where it is joined: add `join(<function> on <name>)` to its note: {describe}"
                )),
                Some((function, name)) => {
                    // Each start that is not awaited where it stands is joined as the marker says.
                    let joined = start.starts.iter().filter(|each| !each.at_once).all(|each| {
                        if each.function == *function {
                            each.handle.as_deref() == Some(name.as_str())
                                && scan.joined.contains(&each.id)
                        } else {
                            scan.awaits
                                .contains(&(key.0.clone(), function.clone(), name.clone()))
                        }
                    });
                    if !joined {
                        problems.push(format!(
                            "the row says the handle is awaited as `{name}` in {function}, and the source does not await it there: {describe}"
                        ));
                    }
                }
            }
        }
        if row.class != Class::Joined && row.join.is_some() {
            problems.push(format!(
                "only a row of class joined has a join marker, and this row says {}: {describe}",
                row.class.name()
            ));
        }
    }
    for (key, row) in &listed {
        if !found.contains_key(key) {
            problems.push(format!(
                "a row with no start in the source ({}): {} | {} | {} | {} ({})",
                row.count, key.0, key.1, key.2, key.3, row.note
            ));
        }
    }

    for shape in &scan.helper_shapes {
        if !roster
            .helpers
            .iter()
            .any(|helper| helper.name == shape.name && shape.file.starts_with(&helper.scope))
        {
            problems.push(format!(
                "`{}` in {} starts a task that runs its own parameter, and no helper line names it: add `helper | {} | {} | <what it starts>`",
                shape.name, shape.file, shape.name, shape.file
            ));
        }
    }
    for helper in &roster.helpers {
        let defined = scan
            .helper_shapes
            .iter()
            .any(|shape| shape.name == helper.name && shape.file.starts_with(&helper.scope));
        if !defined {
            problems.push(format!(
                "the helper `{}` is not a function under {} that starts a task running its own parameter",
                helper.name, helper.scope
            ));
        }
    }
    let listed: BTreeSet<&String> = roster.names.iter().collect();
    for path in &scan.named {
        if !listed.contains(path) {
            problems.push(format!(
                "the daemon's code names {path} and the roster does not list it: add `names | {path}` once its starts have rows"
            ));
        }
    }
    for path in &roster.names {
        if !scan.named.contains(path) {
            problems.push(format!(
                "the roster lists {path} and the daemon's code no longer names it"
            ));
        }
    }
    problems
}

/// The five forms in which a `request` row names the bound of its task, each with the words of the
/// line that its place must hold.
///
/// * `await`: the handle is awaited by a future that no deadline, branch or drop can leave; the
///   place is the await's line, which holds `.await`.
/// * `owned-set`: the task goes into a set that its owner aborts when it is dropped; the place is the
///   set's declaration, which holds `JoinSet` and is no `use`.
/// * `guard`: a guard whose drop aborts the task; the place is the guard's `Drop`, a line that holds
///   `impl .. Drop for ..`.
/// * `connection-guard`: the connection's own guard; the place is the guard's `Drop`, as for `guard`,
///   and the guard's type has `Connection` in its name.
/// * `channel`: the owner's end of a channel that the task reads in every wait, so that the owner's
///   dropping it ends the task at its next poll; the place is the task's read of that end, a line that
///   holds a method call `recv`, `poll_recv`, `recv_many`, `try_recv`, `blocking_recv`, `closed` or
///   `changed`.
pub const FORMS: [&str; 5] = ["await", "owned-set", "guard", "connection-guard", "channel"];

const RECEIVES: [&str; 7] = [
    "recv",
    "poll_recv",
    "recv_many",
    "try_recv",
    "blocking_recv",
    "closed",
    "changed",
];

/// The words of one line of source: its names, numbers and marks one by one, with a comment that
/// runs to the end of the line and the inside of a string or a character left out.
fn words(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut words = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        let here = chars[at];
        if here == '/' && chars.get(at + 1) == Some(&'/') {
            break;
        }
        if here == '"' {
            at += 1;
            while at < chars.len() && chars[at] != '"' {
                at += if chars[at] == '\\' { 2 } else { 1 };
            }
            at += 1;
            words.push("\"\"".to_string());
            continue;
        }
        if here == '\'' && chars.get(at + 1) == Some(&'\\') {
            at += 2;
            while at < chars.len() && chars[at] != '\'' {
                at += 1;
            }
            at += 1;
            words.push("''".to_string());
            continue;
        }
        if here == '\'' && chars.get(at + 2) == Some(&'\'') {
            at += 3;
            words.push("''".to_string());
            continue;
        }
        if here.is_alphanumeric() || here == '_' {
            let start = at;
            while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
                at += 1;
            }
            words.push(chars[start..at].iter().collect());
            continue;
        }
        if !here.is_whitespace() {
            words.push(here.to_string());
        }
        at += 1;
    }
    words
}

/// The type that an `impl .. Drop for ..` of the line is for.
fn dropped_type(words: &[String]) -> Option<&str> {
    let start = words.iter().position(|word| word == "impl")?;
    let at = words[start..]
        .windows(3)
        .position(|window| window[0] == "Drop" && window[1] == "for")?;
    words.get(start + at + 2).map(String::as_str)
}

/// Whether a line holds what a form's place must hold.
fn holds(form: &str, line: &str) -> bool {
    let words = words(line);
    match form {
        "await" => words
            .windows(2)
            .any(|pair| pair[0] == "." && pair[1] == "await"),
        "owned-set" => {
            words.first().is_none_or(|first| first != "use")
                && words.iter().any(|word| word == "JoinSet")
        }
        "guard" => dropped_type(&words).is_some(),
        "connection-guard" => dropped_type(&words).is_some_and(|name| name.contains("Connection")),
        "channel" => words
            .windows(2)
            .any(|pair| pair[0] == "." && RECEIVES.contains(&pair[1].as_str())),
        _ => false,
    }
}

/// What a `request` row's note says of its bound: `bound(form at path:line)` at the start of the note.
fn bound_marker(note: &str) -> Result<Option<(&str, &str)>, String> {
    let Some(inside) = note.strip_prefix("bound(") else {
        return Ok(None);
    };
    let Some((inside, _)) = inside.split_once(')') else {
        return Err("a bound marker is not closed".to_string());
    };
    match inside.split_once(" at ") {
        Some((form, place)) => Ok(Some((form.trim(), place.trim()))),
        None => Err("a bound marker is `bound(form at path:line)`".to_string()),
    }
}

/// Everything that is wrong with the bounds of the roster's rows, one sentence each. A row of class
/// `request` begins its note with `bound(form at path:line)`: the form is one of the five of `FORMS`,
/// and the place is a line of a file of the tree that holds what the form names. A row of another
/// class has no bound marker. Empty when every bound holds.
pub fn bound_problems(roster: &Roster, files: &dyn Files) -> Vec<String> {
    let mut problems = Vec::new();
    for row in &roster.rows {
        let describe = format!(
            "{} | {} | {} | {}",
            row.file, row.function, row.form, row.callee
        );
        let marker = bound_marker(&row.note);
        if row.class != Class::Request {
            if !matches!(marker, Ok(None)) {
                problems.push(format!(
                    "only a row of class request names a bound, and this row says {}: {describe}",
                    row.class.name()
                ));
            }
            continue;
        }
        let (form, place) = match marker {
            Err(why) => {
                problems.push(format!("{why}: {describe}"));
                continue;
            }
            Ok(None) => {
                problems.push(format!(
                    "a row of class request begins its note with `bound(form at path:line)`: {describe}"
                ));
                continue;
            }
            Ok(Some(bound)) => bound,
        };
        if !FORMS.contains(&form) {
            problems.push(format!(
                "the bound's form `{form}` is none of {}: {describe}",
                FORMS.join(", ")
            ));
            continue;
        }
        let Some((path, line)) = place.rsplit_once(':').and_then(|(path, line)| {
            Some((path, line.parse::<usize>().ok().filter(|line| *line > 0)?))
        }) else {
            problems.push(format!(
                "the bound's place `{place}` is no `path:line`: {describe}"
            ));
            continue;
        };
        let Some(text) = files.read(Path::new(path)) else {
            problems.push(format!(
                "the bound's place names {path}, which is no file of the tree: {describe}"
            ));
            continue;
        };
        let Some(held) = text.lines().nth(line - 1) else {
            problems.push(format!(
                "the bound's place is line {line} of {path}, which has {} lines: {describe}",
                text.lines().count()
            ));
            continue;
        };
        if !holds(form, held) {
            problems.push(format!(
                "the line at {path}:{line} does not hold what the form `{form}` names ({}): {describe}",
                held.trim()
            ));
        }
    }
    problems
}
