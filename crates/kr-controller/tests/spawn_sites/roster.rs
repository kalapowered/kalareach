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
//! name in a file under `scope` (a file or a folder) is a start. Blank lines and lines that begin
//! with `#` are comments.

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
        roster.rows.push(Row {
            file: file.to_string(),
            function: function.to_string(),
            form: form.to_string(),
            callee: callee.to_string(),
            count,
            class,
            task,
            note: note.to_string(),
        });
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

/// A start as a line of the roster, for a person to complete and add.
pub fn line_of(key: &Key, count: usize) -> String {
    format!(
        "{} | {} | {} | {} | {count} | ? | - | ?",
        key.0, key.1, key.2, key.3
    )
}

/// What the starts that share one key have in common.
struct Found {
    count: usize,
    all_at_once: bool,
    all_unshipped: bool,
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
        });
        entry.count += 1;
        entry.all_at_once &= start.at_once;
        entry.all_unshipped &= start.unshipped;
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
    problems
}
