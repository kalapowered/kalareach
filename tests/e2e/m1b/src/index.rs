//! The output-time indexes of a run's sessions, compared by meaning through copies. The live file is
//! never opened: its main file and its `-wal` are copied twice into a directory outside both host
//! roots, a copy is used only when two successive copies are equal, and the copy is opened by H
//! with a connection of its own.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kr_worker::output_times::{MAX_ROWS, VERSION};
use rusqlite::{Connection, OpenFlags};

use crate::compare::{Layout, Refusal};
use crate::run::open_file_below;
use crate::tree::{Kind, Record};
use crate::worker::Place;

/// How many times the copies are made before the look gives up: the worker's maintenance pass can
/// write the index between two copies.
const TRIES: usize = 5;

/// How long between two tries.
const BETWEEN_TRIES: Duration = Duration::from_millis(100);

/// One row of an index: the output between `start` and `end`, the time it was seen and whether
/// that time was proven.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mark {
    /// The first cursor.
    pub start: i64,
    /// The cursor after the last.
    pub end: i64,
    /// The time the worker gives the row, in milliseconds.
    pub at_ms: i64,
    /// Whether the worker proved the time.
    pub proven: i64,
}

/// What an index holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rows {
    /// The schema versions in `times_schema`.
    pub versions: Vec<i64>,
    /// The rows of `marks`, by start.
    pub marks: Vec<Mark>,
}

/// What a look at the indexes found, by session: the rows, none where there is no index, or why the
/// index could not be read.
#[derive(Clone, Debug, Default)]
pub struct Looked {
    /// Each session's index.
    pub indexes: BTreeMap<String, Result<Option<Rows>, String>>,
}

/// The index of `session` below the state directory, relative to the run's directory.
fn index_path(layout: &Layout, session: &str) -> PathBuf {
    layout
        .state_dir
        .join("output-times")
        .join(format!("{session}.sqlite"))
}

/// The bytes of the file at `relative`, through the run's handles, or `None` where it is not there.
fn bytes_of(place: Place<'_>, relative: &Path) -> Result<Option<Vec<u8>>, String> {
    let Some(file) = open_file_below(place.root, place.pin, relative)
        .map_err(|why| format!("{}: {why}", relative.display()))?
    else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::fs::File::from(file), &mut bytes)
        .map_err(|why| format!("{}: {why}", relative.display()))?;
    Ok(Some(bytes))
}

type Copies = (Vec<u8>, Option<Vec<u8>>);

/// The main file and the `-wal` of the index at `relative`, copied twice and equal, or why not.
fn equal_copies(place: Place<'_>, relative: &Path) -> Result<Option<Copies>, String> {
    let wal = PathBuf::from(format!("{}-wal", relative.display()));
    let (main, wal) = settled(|| Ok((bytes_of(place, relative)?, bytes_of(place, &wal)?)))?;
    Ok(main.map(|main| (main, wal)))
}

/// Makes copies with `copy` until two successive ones are equal, and gives up after [`TRIES`].
fn settled<T: PartialEq>(mut copy: impl FnMut() -> Result<T, String>) -> Result<T, String> {
    for attempt in 0..TRIES {
        let first = copy()?;
        let second = copy()?;
        if first == second {
            return Ok(first);
        }
        if attempt + 1 < TRIES {
            std::thread::sleep(BETWEEN_TRIES);
        }
    }
    Err(format!(
        "its copies did not become equal within {TRIES} tries"
    ))
}

/// Reads the rows of the copy that `main` and `wal` make in `directory`, with a connection of H's
/// own.
fn rows_of(directory: &Path, main: &[u8], wal: Option<&[u8]>) -> Result<Rows, String> {
    let said = |why: &dyn std::fmt::Display| why.to_string();
    std::fs::create_dir_all(directory).map_err(|why| said(&why))?;
    let path = directory.join("index.sqlite");
    for stale in ["index.sqlite", "index.sqlite-wal", "index.sqlite-shm"] {
        let _ = std::fs::remove_file(directory.join(stale));
    }
    std::fs::write(&path, main).map_err(|why| said(&why))?;
    if let Some(wal) = wal {
        std::fs::write(directory.join("index.sqlite-wal"), wal).map_err(|why| said(&why))?;
    }
    let connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|why| said(&why))?;
    let versions = connection
        .prepare("SELECT version FROM times_schema")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, i64>(0))?
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|why| said(&why))?;
    let marks = connection
        .prepare("SELECT start, end, at_ms, proven FROM marks ORDER BY start")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| {
                    Ok(Mark {
                        start: row.get(0)?,
                        end: row.get(1)?,
                        at_ms: row.get(2)?,
                        proven: row.get(3)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|why| said(&why))?;
    Ok(Rows { versions, marks })
}

/// Looks at the indexes of `sessions`: each copied twice outside both roots, in `copies`, and read.
#[must_use]
pub fn look(layout: &Layout, place: Place<'_>, copies: &Path, sessions: &[String]) -> Looked {
    let mut looked = Looked::default();
    for session in sessions {
        let found = equal_copies(place, &index_path(layout, session)).and_then(|copied| {
            copied
                .map(|(main, wal)| rows_of(&copies.join(session), &main, wal.as_deref()))
                .transpose()
        });
        looked.indexes.insert(session.clone(), found);
    }
    looked
}

/// The sessions whose spool or index `record` holds.
#[must_use]
pub fn sessions_of(layout: &Layout, record: &Record) -> Vec<String> {
    let mut sessions: Vec<String> = Vec::new();
    for (path, entry) in record.entries() {
        let name = path
            .parent()
            .filter(|parent| *parent == layout.state_dir.join("spool"))
            .and(path.file_name())
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".log"))
            .filter(|_| entry.kind == Kind::Directory)
            .or_else(|| {
                path.parent()
                    .filter(|parent| *parent == layout.state_dir.join("output-times"))
                    .and(path.file_name())
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_suffix(".sqlite"))
            });
        if let Some(name) = name
            && !sessions.iter().any(|known| known == name)
        {
            sessions.push(name.to_owned());
        }
    }
    sessions
}

/// The first cursor of the oldest segment of `session`'s spool in `record`.
fn oldest_segment(layout: &Layout, record: &Record, session: &str) -> Option<u64> {
    let directory = layout
        .state_dir
        .join("spool")
        .join(format!("{session}.log"));
    record
        .entries()
        .filter(|(path, entry)| {
            path.parent() == Some(directory.as_path()) && entry.kind == Kind::File
        })
        .filter_map(|(path, _)| {
            path.file_name()?
                .to_str()?
                .strip_suffix(".out")?
                .parse::<u64>()
                .ok()
        })
        .min()
}

/// Compares the indexes `now` with `base`. `record` is the record of the tree made after the look
/// that gave `now`, so that a segment that a later pass dropped is not taken as the oldest;
/// `limit_ms` is the limit the clock floor's check gives, which a new row's time may not pass.
#[must_use]
pub fn compare(
    layout: &Layout,
    base: &Looked,
    now: &Looked,
    record: &Record,
    limit_ms: u64,
) -> Vec<Refusal> {
    let mut refused = Vec::new();
    for (session, found) in &now.indexes {
        let path = index_path(layout, session);
        let mut refuse = |why: String| {
            refused.push(Refusal {
                path: path.clone(),
                said: why,
            });
        };
        let rows = match found {
            Ok(Some(rows)) => rows,
            Ok(None) => continue,
            Err(why) => {
                refuse(format!(
                    "the output-time index of {session} cannot be read: {why}"
                ));
                continue;
            }
        };
        let before = base
            .indexes
            .get(session)
            .and_then(|found| found.as_ref().ok())
            .and_then(Option::as_ref);
        let expected = before.map_or_else(|| vec![VERSION], |before| before.versions.clone());
        if rows.versions != expected {
            refuse(format!(
                "the output-time index of {session} has the schema versions {:?}, not {expected:?}",
                rows.versions
            ));
        }
        let oldest = oldest_segment(layout, record, session);
        let newest_recorded = before.and_then(|before| before.marks.last().map(|mark| mark.start));
        for was in before.map_or(&[][..], |before| &before.marks[..]) {
            match rows.marks.iter().find(|mark| mark.start == was.start) {
                Some(mark) if mark == was => {}
                Some(mark)
                    if Some(was.start) == newest_recorded
                        && (mark.at_ms, mark.proven) == (was.at_ms, was.proven)
                        && mark.end >= was.end => {}
                Some(_) => refuse(format!(
                    "the output-time index of {session} changed the row {}..{}, which only its newest recorded row may do, and only by growing its end",
                    was.start, was.end
                )),
                None => match oldest {
                    Some(oldest) if was.end <= i64::try_from(oldest).unwrap_or(i64::MAX) => {}
                    Some(oldest) => refuse(format!(
                        "the output-time index of {session} lost the row {}..{}, which is above the start of the oldest segment still in the spool, {oldest}",
                        was.start, was.end
                    )),
                    None => refuse(format!(
                        "the output-time index of {session} lost the row {}..{}, and no segment is left in the spool",
                        was.start, was.end
                    )),
                },
            }
        }
        let mut previous_end: Option<i64> = None;
        for mark in &rows.marks {
            let is_new = !before
                .is_some_and(|before| before.marks.iter().any(|was| was.start == mark.start));
            if is_new {
                if previous_end.is_some_and(|end| mark.start < end) || !matches!(mark.proven, 0 | 1)
                {
                    refuse(format!(
                        "the output-time index of {session} has a new row {}..{} that starts before the end of the row before it, or has a proven value other than 0 or 1",
                        mark.start, mark.end
                    ));
                }
                let at = u64::try_from(mark.at_ms).unwrap_or(u64::MAX);
                if at > limit_ms {
                    refuse(format!(
                        "the output-time index of {session} has a new row with the time {at}, {} ms above the limit {limit_ms}",
                        at - limit_ms
                    ));
                }
            }
            previous_end = Some(mark.end);
        }
        if rows.marks.len() > MAX_ROWS {
            refuse(format!(
                "the output-time index of {session} holds {} rows, above the most the worker keeps, {MAX_ROWS}",
                rows.marks.len()
            ));
        }
    }
    refused
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compare::tests::{World, world};

    const LIMIT: u64 = 1_000;

    type Case = (&'static str, Option<u64>, Vec<i64>, Vec<Mark>, &'static str);

    fn mark(start: i64, end: i64, at_ms: i64, proven: i64) -> Mark {
        Mark {
            start,
            end,
            at_ms,
            proven,
        }
    }

    fn looked(versions: &[i64], marks: &[Mark]) -> Looked {
        let mut looked = Looked::default();
        looked.indexes.insert(
            "s1".to_owned(),
            Ok(Some(Rows {
                versions: versions.to_vec(),
                marks: marks.to_vec(),
            })),
        );
        looked
    }

    fn recorded() -> Vec<Mark> {
        vec![
            mark(0, 10, 100, 1),
            mark(10, 20, 200, 1),
            mark(20, 25, 300, 0),
        ]
    }

    /// The compare of `now` with the recorded rows, over a spool whose oldest segment starts at
    /// `oldest` (none where the spool holds no segment).
    fn refused(world: &World, oldest: Option<u64>, versions: &[i64], now: &[Mark]) -> Vec<String> {
        if let Some(oldest) = oldest {
            world.put(
                &world.state(&format!("spool/s1.log/{oldest:020}.out")),
                b"x",
            );
        }
        std::fs::create_dir_all(world.state("spool/s1.log")).expect("a spool");
        compare(
            &world.layout,
            &looked(&[VERSION], &recorded()),
            &looked(versions, now),
            &world.record(),
            LIMIT,
        )
        .iter()
        .map(ToString::to_string)
        .collect()
    }

    /// A maintenance pass is not refused: the newest row grows, rows at or below the oldest segment
    /// are pruned, and a new row follows the last.
    #[test]
    fn a_maintenance_pass_is_not_refused() {
        let kept = world("index-pass");
        let mut now = recorded();
        now[2] = mark(20, 30, 300, 0);
        now.push(mark(30, 40, 310, 1));
        now.remove(0);
        assert_eq!(
            refused(&kept, Some(10), &[VERSION], &now),
            Vec::<String>::new()
        );
        kept.clean();
        let pruned = world("index-pass-pruned");
        let pruned_all = vec![mark(20, 25, 300, 0)];
        assert_eq!(
            refused(&pruned, Some(20), &[VERSION], &pruned_all),
            Vec::<String>::new()
        );
        pruned.clean();
    }

    /// A past row changed, a row the newest recorded one may not change, a row gone above the oldest
    /// segment, a row gone with no segment left, another schema version, a new row past the limit,
    /// a new row that starts early or has another proven value, and too many rows are refused.
    #[test]
    fn a_changed_past_row_a_lost_row_and_a_bad_new_row_are_refused() {
        let cases: Vec<Case> = {
            let mut changed = recorded();
            changed[1] = mark(10, 20, 999, 1);
            let mut newest_time = recorded();
            newest_time[2] = mark(20, 25, 301, 0);
            let mut newest_end = recorded();
            newest_end[2] = mark(20, 24, 300, 0);
            let mut lost = recorded();
            lost.remove(1);
            let mut early = recorded();
            early.push(mark(22, 30, 310, 1));
            let mut unproven = recorded();
            unproven.push(mark(25, 30, 310, 2));
            let mut late = recorded();
            late.push(mark(25, 30, 1_001, 1));
            let many = (0..=i64::try_from(MAX_ROWS).expect("a count"))
                .map(|start| mark(start * 10, start * 10 + 10, 100, 1))
                .collect();
            vec![
                (
                    "past-row",
                    Some(0),
                    vec![VERSION],
                    changed,
                    "which only its newest recorded row may do, and only by growing its end",
                ),
                (
                    "newest-time",
                    Some(0),
                    vec![VERSION],
                    newest_time,
                    "which only its newest recorded row may do, and only by growing its end",
                ),
                (
                    "newest-end",
                    Some(0),
                    vec![VERSION],
                    newest_end,
                    "which only its newest recorded row may do, and only by growing its end",
                ),
                (
                    "lost-above-oldest",
                    Some(10),
                    vec![VERSION],
                    lost.clone(),
                    "which is above the start of the oldest segment still in the spool, 10",
                ),
                (
                    "lost-no-segment",
                    None,
                    vec![VERSION],
                    lost,
                    "and no segment is left in the spool",
                ),
                (
                    "version",
                    Some(0),
                    vec![2],
                    recorded(),
                    "has the schema versions [2], not [1]",
                ),
                (
                    "early-row",
                    Some(0),
                    vec![VERSION],
                    early,
                    "that starts before the end of the row before it, or has a proven value other than 0 or 1",
                ),
                (
                    "proven",
                    Some(0),
                    vec![VERSION],
                    unproven,
                    "that starts before the end of the row before it, or has a proven value other than 0 or 1",
                ),
                (
                    "past-the-limit",
                    Some(0),
                    vec![VERSION],
                    late,
                    "1 ms above the limit 1000",
                ),
                (
                    "too-many",
                    Some(0),
                    vec![VERSION],
                    many,
                    "above the most the worker keeps, 100000",
                ),
            ]
        };
        for (name, oldest, versions, now, why) in cases {
            let world = world(name);
            let refused = refused(&world, oldest, &versions, &now);
            assert!(
                refused.iter().any(|line| line.contains(why)),
                "{name}: expected {why:?} in {refused:#?}"
            );
            world.clean();
        }
    }

    /// An index that the record does not hold must hold the schema version the worker writes.
    #[test]
    fn a_new_index_holds_the_schema_version_the_worker_writes() {
        let world = world("index-new");
        let compared = |versions: &[i64]| {
            compare(
                &world.layout,
                &Looked::default(),
                &looked(versions, &[mark(0, 10, 100, 1)]),
                &world.record(),
                LIMIT,
            )
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
        };
        assert_eq!(compared(&[VERSION]), Vec::<String>::new());
        let refused = compared(&[VERSION + 1]);
        assert_eq!(refused.len(), 1, "{refused:#?}");
        assert!(
            refused[0].ends_with("has the schema versions [2], not [1]"),
            "{refused:#?}"
        );
        world.clean();
    }

    /// Copies are used only when two successive ones are equal, and the look says how many tries it
    /// made when they never are.
    #[test]
    fn copies_are_used_only_when_two_successive_ones_are_equal() {
        let mut count = 0;
        let never = settled(|| {
            count += 1;
            Ok(count)
        });
        assert_eq!(
            never,
            Err(format!(
                "its copies did not become equal within {TRIES} tries"
            ))
        );
        let mut count = 0;
        let later = settled(|| {
            count += 1;
            Ok(count.min(3))
        });
        assert_eq!(later, Ok(3));
        assert_eq!(
            settled::<u8>(|| Err("gone".to_owned())),
            Err("gone".to_owned())
        );
    }

    /// An index that is read as the worker made it gives its rows, an absent one gives none, and a
    /// file that is no database gives why.
    #[test]
    fn the_index_is_read_through_copies_and_an_unreadable_one_says_why() {
        let world = world("index-look");
        let path = world.state("output-times/s1.sqlite");
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        {
            let connection = Connection::open(&path).expect("an index");
            connection
                .execute_batch(
                    "PRAGMA journal_mode = WAL;
                     CREATE TABLE times_schema (version INTEGER NOT NULL);
                     INSERT INTO times_schema (version) VALUES (1);
                     CREATE TABLE marks (start INTEGER PRIMARY KEY, end INTEGER NOT NULL,
                         at_ms INTEGER NOT NULL, proven INTEGER NOT NULL) WITHOUT ROWID;
                     INSERT INTO marks VALUES (0, 10, 100, 1);
                     INSERT INTO marks VALUES (10, 20, 200, 0);",
                )
                .expect("rows");
            std::mem::forget(connection);
        }
        let place = Place {
            root: &world.root,
            pin: &world.pin,
        };
        let copies = world.root.join("i");
        let sessions = ["s1".to_owned(), "none".to_owned()];
        let found = look(&world.layout, place, &copies, &sessions);
        assert_eq!(
            found.indexes["s1"],
            Ok(Some(Rows {
                versions: vec![1],
                marks: vec![mark(0, 10, 100, 1), mark(10, 20, 200, 0)],
            }))
        );
        assert_eq!(found.indexes["none"], Ok(None));
        let garbage = world.state("output-times/s2.sqlite");
        std::fs::write(&garbage, b"not a database at all").expect("a file");
        let found = look(&world.layout, place, &copies, &["s2".to_owned()]);
        assert!(found.indexes["s2"].is_err(), "{:?}", found.indexes);
        world.clean();
    }
}
