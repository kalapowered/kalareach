//! The tables of the session journals, compared between the kill and the attempt. A journal is read
//! through copies, as the output-time indexes are, and each table is held by a digest of its rows.
//! The worker's maintenance pass commits to the journal while no daemon runs, so the tables it
//! writes then ([`WORKER_TABLES`]) are not compared; every other table must be as it was at the
//! kill, since the daemon is dead and the agent's request, binding and instance were made before
//! the kill.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rusqlite::Connection;
use rusqlite::types::ValueRef;

use crate::compare::{Layout, Refusal};
use crate::copies::Copies;
use crate::index::equal_copies;
use crate::tree::{Kind, Record};
use crate::worker::Place;

/// Whether the check runs on a real agent's tree. A real agent may write tables of the broker
/// between the kill and the attempt, for example through a hook, which a stand-in run does not,
/// so the check stays off for real legs until a real run has produced its table set.
pub const ON_FOR_REAL_LEGS: bool = false;

/// Whether the check runs for a leg whose agent is the harness's own stand-in (`stand_in`) or a real
/// one.
#[must_use]
pub const fn applies(stand_in: bool) -> bool {
    stand_in || ON_FOR_REAL_LEGS
}

/// The tables of a session journal that the worker changes between the kill and the attempt,
/// from the survey of a stand-in run.
pub const WORKER_TABLES: &[&str] = &["owned_processes"];

/// The digest of each table of each session's journal, or why a journal could not be read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tables {
    /// Each session's tables by name.
    pub journals: BTreeMap<String, Result<BTreeMap<String, [u8; 32]>, String>>,
}

fn journal_path(layout: &Layout, session: &str) -> PathBuf {
    layout
        .state_dir
        .join("sessions")
        .join(format!("session-{session}.sqlite"))
}

/// Every table of the copy `connection` is open on, by a digest of its rows in the order of their
/// columns.
fn digests_of(connection: &Connection) -> Result<BTreeMap<String, [u8; 32]>, String> {
    let said = |why: &dyn std::fmt::Display| why.to_string();
    let names = connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|why| said(&why))?;
    let mut digests = BTreeMap::new();
    for name in names {
        let quoted = name.replace('"', "\"\"");
        let columns = connection
            .prepare(&format!("SELECT * FROM \"{quoted}\" LIMIT 0"))
            .map_err(|why| said(&why))?
            .column_count();
        let order = (1..=columns)
            .map(|column| column.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let mut statement = connection
            .prepare(&format!("SELECT * FROM \"{quoted}\" ORDER BY {order}"))
            .map_err(|why| said(&why))?;
        let mut rows = statement.query([]).map_err(|why| said(&why))?;
        let mut bytes = Vec::new();
        while let Some(row) = rows.next().map_err(|why| said(&why))? {
            for column in 0..columns {
                match row.get_ref(column).map_err(|why| said(&why))? {
                    ValueRef::Null => bytes.push(0),
                    ValueRef::Integer(value) => {
                        bytes.push(1);
                        bytes.extend_from_slice(&value.to_be_bytes());
                    }
                    ValueRef::Real(value) => {
                        bytes.push(2);
                        bytes.extend_from_slice(&value.to_be_bytes());
                    }
                    ValueRef::Text(text) => {
                        bytes.push(3);
                        bytes.extend_from_slice(&(text.len() as u64).to_be_bytes());
                        bytes.extend_from_slice(text);
                    }
                    ValueRef::Blob(blob) => {
                        bytes.push(4);
                        bytes.extend_from_slice(&(blob.len() as u64).to_be_bytes());
                        bytes.extend_from_slice(blob);
                    }
                }
            }
            bytes.push(0xff);
        }
        digests.insert(name, kr_cbor::sha256(&bytes));
    }
    Ok(digests)
}

/// The sessions whose journal `record` holds.
#[must_use]
pub fn sessions_of(layout: &Layout, record: &Record) -> Vec<String> {
    let directory = layout.state_dir.join("sessions");
    record
        .entries()
        .filter(|(path, entry)| {
            path.parent() == Some(directory.as_path()) && entry.kind == Kind::File
        })
        .filter_map(|(path, _)| {
            let name = path.file_name()?.to_str()?;
            name.strip_prefix("session-")?
                .strip_suffix(".sqlite")
                .map(str::to_owned)
        })
        .collect()
}

/// Looks at the journals of `sessions`, each through copies in the directory `copies` keeps.
#[must_use]
pub fn look(layout: &Layout, place: Place<'_>, copies: &Copies, sessions: &[String]) -> Tables {
    let mut tables = Tables::default();
    for session in sessions {
        let found = equal_copies(place, &journal_path(layout, session)).and_then(|copied| {
            let (main, wal) = copied.ok_or_else(|| "it is not there".to_owned())?;
            copies.read(
                &format!("journal-{session}"),
                "journal.sqlite",
                &main,
                wal.as_deref(),
                digests_of,
            )
        });
        tables.journals.insert(session.clone(), found);
    }
    tables
}

/// Every table that is not as it was between `before` and `now`, by session and name: changed,
/// appeared or gone. A journal that either look could not read has none.
#[must_use]
pub fn changed(before: &Tables, now: &Tables) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for (session, now) in &now.journals {
        let (Some(Ok(was)), Ok(tables)) = (before.journals.get(session), now) else {
            continue;
        };
        let mut names: Vec<&String> = was.keys().chain(tables.keys()).collect();
        names.sort();
        names.dedup();
        for name in names {
            if was.get(name) != tables.get(name) {
                found.push((session.clone(), name.clone()));
            }
        }
    }
    found
}

/// Compares the journals `now` with `before`, and returns each journal that cannot be read and
/// each table that is not a table of the worker's and is not as it was.
#[must_use]
pub fn compare(layout: &Layout, before: &Tables, now: &Tables) -> Vec<Refusal> {
    let mut refused = Vec::new();
    for (session, found) in &now.journals {
        if let Err(why) = found {
            refused.push(Refusal {
                path: journal_path(layout, session),
                said: format!("the session journal of {session} cannot be read: {why}"),
            });
        }
    }
    for (session, name) in changed(before, now) {
        if !WORKER_TABLES.contains(&name.as_str()) {
            refused.push(Refusal {
                path: journal_path(layout, &session),
                said: format!(
                    "the journal table {name} of {session} changed, appeared or is gone between the kill and the attempt"
                ),
            });
        }
    }
    refused
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;
    use crate::compare::tests::{World, world};

    const T2: &str = "changed, appeared or is gone between the kill and the attempt";

    fn journal(world: &World) -> PathBuf {
        world.state("sessions/session-a1.sqlite")
    }

    /// Runs `statements` on the journal of the session `a1`, making it where it is not there.
    fn write(world: &World, statements: &str) {
        let path = journal(world);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        Connection::open(&path)
            .expect("a journal")
            .execute_batch(statements)
            .expect("rows");
    }

    fn look_at(world: &World) -> Tables {
        let place = Place {
            root: &world.root,
            pin: &world.pin,
        };
        let copies = Copies::make().expect("a directory for the copies");
        look(&world.layout, place, &copies, &["a1".to_owned()])
    }

    fn lines(refused: Vec<Refusal>) -> Vec<String> {
        refused.iter().map(ToString::to_string).collect()
    }

    const SETUP: &str = "CREATE TABLE requests (id INTEGER PRIMARY KEY, body TEXT);
        CREATE TABLE bindings (id INTEGER PRIMARY KEY, revision INTEGER);
        INSERT INTO bindings VALUES (1, 1);";

    /// A table changed after the kill is refused by name; the tables the agent's request, binding
    /// and instance changed before the kill are not compared; a table that appears or is gone is
    /// refused too.
    #[test]
    fn a_table_changed_after_the_kill_is_refused_and_one_changed_before_it_is_not() {
        let world = world("tables-interval");
        write(&world, SETUP);
        let started = look_at(&world);
        write(
            &world,
            "INSERT INTO requests VALUES (1, 'pending'); UPDATE bindings SET revision = 2;",
        );
        let killed = look_at(&world);
        assert_eq!(
            changed(&started, &killed),
            vec![
                ("a1".to_owned(), "bindings".to_owned()),
                ("a1".to_owned(), "requests".to_owned())
            ]
        );
        assert_eq!(
            lines(compare(&world.layout, &killed, &look_at(&world))),
            Vec::<String>::new()
        );
        write(&world, "UPDATE bindings SET revision = 3;");
        assert_eq!(
            lines(compare(&world.layout, &killed, &look_at(&world))),
            vec![format!("the journal table bindings of a1 {T2}")]
        );
        write(
            &world,
            "CREATE TABLE extra (id INTEGER); DROP TABLE requests;",
        );
        let refused = lines(compare(&world.layout, &killed, &look_at(&world)));
        assert_eq!(
            refused,
            vec![
                format!("the journal table bindings of a1 {T2}"),
                format!("the journal table extra of a1 {T2}"),
                format!("the journal table requests of a1 {T2}"),
            ]
        );
        world.clean();
    }

    /// A table the worker's maintenance pass writes may change between the kill and the attempt,
    /// and no other table of the same journal may.
    #[test]
    fn the_table_the_worker_writes_may_change_after_the_kill_and_no_other_may() {
        let world = world("tables-worker");
        write(
            &world,
            &format!("{SETUP} CREATE TABLE owned_processes (id INTEGER PRIMARY KEY, pid INTEGER);"),
        );
        let killed = look_at(&world);
        write(&world, "INSERT INTO owned_processes VALUES (1, 4242);");
        let attempt = look_at(&world);
        assert_eq!(
            changed(&killed, &attempt),
            vec![("a1".to_owned(), "owned_processes".to_owned())]
        );
        assert_eq!(
            lines(compare(&world.layout, &killed, &attempt)),
            Vec::<String>::new()
        );
        write(&world, "UPDATE bindings SET revision = 9;");
        assert_eq!(
            lines(compare(&world.layout, &killed, &look_at(&world))),
            vec![format!("the journal table bindings of a1 {T2}")]
        );
        world.clean();
    }

    /// A journal that is no database and one that is gone give why, at either look.
    #[test]
    fn a_journal_that_cannot_be_read_is_refused_with_why() {
        let world = world("tables-unreadable");
        write(&world, SETUP);
        let killed = look_at(&world);
        std::fs::write(journal(&world), b"not a database at all").expect("a file");
        let refused = lines(compare(&world.layout, &killed, &look_at(&world)));
        assert_eq!(refused.len(), 1, "{refused:#?}");
        assert!(
            refused[0].starts_with("the session journal of a1 cannot be read: "),
            "{refused:#?}"
        );
        std::fs::remove_file(journal(&world)).expect("removed");
        assert_eq!(
            lines(compare(&world.layout, &killed, &look_at(&world))),
            vec!["the session journal of a1 cannot be read: it is not there".to_owned()]
        );
        world.clean();
    }

    /// The sessions are those whose journal the record holds, by the journal's name.
    #[test]
    fn the_sessions_are_those_of_the_journals_in_the_record() {
        let world = world("tables-sessions");
        write(&world, SETUP);
        world.put(&world.state("sessions/session-b2.sqlite"), b"x");
        world.put(&world.state("sessions/session-b2.sqlite-wal"), b"x");
        world.put(&world.state("sessions/other"), b"x");
        let mut found = sessions_of(&world.layout, &world.record());
        found.sort();
        assert_eq!(found, vec!["a1".to_owned(), "b2".to_owned()]);
        world.clean();
    }

    /// The check runs on the harness's own stand-in and not on a real agent's tree.
    #[test]
    fn the_check_runs_on_the_stand_in_and_not_on_a_real_agents_tree() {
        assert!(applies(true));
        assert!(!applies(false));
    }
}
