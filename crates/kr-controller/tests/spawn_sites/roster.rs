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

use std::collections::{BTreeMap, BTreeSet};

use super::scan::{Scan, Start};

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
