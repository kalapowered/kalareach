//! A read-only view of an agent's conversations as files of JSON lines.
//!
//! The conversation checks read what an agent wrote as files of JSON lines. An agent that keeps its
//! conversations in a database has no such file, so a part reads a mirror instead: the entry's
//! query, a `SELECT` over the agent's own database, returns one row for each line of a conversation,
//! in the order the lines are to be read, with the conversation's identifier in the first column and
//! the line, JSON on one line, in the second. [`export`] writes one file for each conversation, whole
//! and by rename, so a reader sees the whole file as of one moment; a file whose lines did not change
//! is left alone, so its length, time and inode say so too.
//!
//! The database is opened read-only and the statement must not write, so the mirror changes nothing
//! of the agent's. [`Mirroring`] repeats the export while a part runs, so the waits that poll
//! the files see the agent's conversation as it grows, and exports once more, whole, when the
//! part's processes have ended.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

/// The directory of the run's own that holds the mirror's files.
pub const DIRECTORY: &str = "conversation-mirror";

/// How long a mirroring thread waits between exports.
const INTERVAL: Duration = Duration::from_millis(100);

/// How long a read waits for the agent's own writes before it fails: the database is in
/// write-ahead mode, which readers rarely wait on.
const BUSY: Duration = Duration::from_secs(2);

/// Whether `session` can name a mirror file: letters, digits, `_` and `-`, and not empty.
fn file_safe(session: &str) -> bool {
    !session.is_empty()
        && session
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

/// Runs `query` against `database`, read-only, and writes each conversation it returns to
/// `directory/<identifier>.jsonl`. A database that is not there yet has no conversations: nothing is
/// written. Returns how many conversations the query returned.
///
/// # Errors
///
/// Returns why the export could not be made: the database could not be read, the statement writes,
/// a row is not two texts, an identifier cannot name a file, or a file could not be written.
pub fn export(database: &Path, query: &str, directory: &Path) -> Result<usize, String> {
    if !database.is_file() {
        return Ok(0);
    }
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("the agent's database cannot be opened: {error}"))?;
    connection
        .busy_timeout(BUSY)
        .map_err(|error| format!("the agent's database: {error}"))?;
    let mut statement = connection
        .prepare(query)
        .map_err(|error| format!("the mirror's query: {error}"))?;
    if !statement.readonly() {
        return Err("the mirror's query writes".to_owned());
    }
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| format!("the mirror's query: {error}"))?;
    let mut sessions: BTreeMap<String, String> = BTreeMap::new();
    for row in rows {
        let (session, line) = row.map_err(|error| format!("the mirror's query: {error}"))?;
        if !file_safe(&session) {
            return Err("a conversation's identifier cannot name a file".to_owned());
        }
        if line.contains('\n') {
            return Err("a line of a conversation holds a line end".to_owned());
        }
        let text = sessions.entry(session).or_default();
        text.push_str(&line);
        text.push('\n');
    }
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    for (session, text) in &sessions {
        let path = directory.join(format!("{session}.jsonl"));
        if std::fs::read(&path).is_ok_and(|bytes| bytes == text.as_bytes()) {
            continue;
        }
        let temporary = directory.join(format!(".{session}.jsonl.tmp"));
        std::fs::write(&temporary, text)
            .and_then(|()| std::fs::rename(&temporary, &path))
            .map_err(|error| format!("{}: {error}", path.display()))?;
    }
    Ok(sessions.len())
}

/// A thread that exports a mirror again and again until it is finished.
pub struct Mirroring {
    database: PathBuf,
    query: String,
    directory: PathBuf,
    stop: Arc<AtomicBool>,
    last: Arc<Mutex<Option<String>>>,
    thread: Option<JoinHandle<()>>,
}

impl Mirroring {
    /// Starts exporting `query` over `database` into `directory` every 100 ms.
    #[must_use]
    pub fn start(database: PathBuf, query: String, directory: PathBuf) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let last = Arc::new(Mutex::new(None));
        let thread = {
            let (database, query, directory) = (database.clone(), query.clone(), directory.clone());
            let (stop, last) = (Arc::clone(&stop), Arc::clone(&last));
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let made = export(&database, &query, &directory);
                    *last.lock().unwrap_or_else(PoisonError::into_inner) = made.err();
                    std::thread::sleep(INTERVAL);
                }
            })
        };
        Self {
            database,
            query,
            directory,
            stop,
            last,
            thread: Some(thread),
        }
    }

    /// The most recent export's failure, where it failed: a read that waited on the agent's own
    /// write fails and is made again, so this says something only when a later export did not mend it.
    #[must_use]
    pub fn failing(&self) -> Option<String> {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Stops the thread and exports once more, whole, which is the mirror a reader afterwards sees.
    ///
    /// # Errors
    ///
    /// Returns why that last export could not be made.
    pub fn finish(mut self) -> Result<usize, String> {
        self.halt();
        export(&self.database, &self.query, &self.directory)
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Mirroring {
    fn drop(&mut self) {
        self.halt();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database of this test's own, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "kr-mirror-{name}-{}-{}",
                std::process::id(),
                kr_ipc::new_uuid()
            ));
            std::fs::create_dir_all(&path).expect("a directory");
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A toy of the part of an agent's database a mirror reads: messages and their parts.
    fn toy(path: &Path) -> Connection {
        let connection = Connection::open(path).expect("a database");
        connection
            .execute_batch(
                "CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, created INTEGER NOT NULL, data TEXT NOT NULL);
                 CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, updated INTEGER NOT NULL, data TEXT NOT NULL);",
            )
            .expect("the tables");
        connection
    }

    const QUERY: &str = "SELECT session_id AS session, json_object('role', json_extract(data, '$.role'), 'kind', 'message', 'id', id) AS line FROM message \
                         UNION ALL SELECT session_id, json_object('role', 'user', 'kind', 'text', 'text', json_extract(data, '$.text')) FROM part \
                         ORDER BY 1, 2";

    #[test]
    fn a_database_that_is_not_there_yet_has_no_conversations() {
        let scratch = Scratch::new("absent");
        assert_eq!(
            export(&scratch.0.join("none.db"), QUERY, &scratch.0.join("out")),
            Ok(0)
        );
        assert!(!scratch.0.join("out").exists());
    }

    /// One file for each conversation, each line one row, whole; and a second export that finds the
    /// same rows leaves the file as it was.
    #[test]
    fn each_conversation_is_a_file_of_its_rows_and_an_unchanged_one_is_left_alone() {
        let scratch = Scratch::new("files");
        let database = scratch.0.join("agent.db");
        let connection = toy(&database);
        connection
            .execute_batch(
                "INSERT INTO message VALUES ('m1', 'ses_a', 1, '{\"role\":\"user\"}'), ('m2', 'ses_b', 2, '{\"role\":\"assistant\"}');
                 INSERT INTO part VALUES ('p1', 'm1', 'ses_a', 1, '{\"text\":\"what is 1 plus 1\"}');",
            )
            .expect("rows");
        let directory = scratch.0.join("out");
        assert_eq!(export(&database, QUERY, &directory), Ok(2));
        let first = std::fs::read_to_string(directory.join("ses_a.jsonl")).expect("a file");
        let lines: Vec<&str> = first.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(
            lines
                .iter()
                .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
        );
        assert!(first.contains("\"text\":\"what is 1 plus 1\""));
        assert_eq!(
            std::fs::read_to_string(directory.join("ses_b.jsonl"))
                .expect("a file")
                .lines()
                .count(),
            1
        );
        let before = std::fs::metadata(directory.join("ses_a.jsonl")).expect("metadata");
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(export(&database, QUERY, &directory), Ok(2));
        let after = std::fs::metadata(directory.join("ses_a.jsonl")).expect("metadata");
        assert_eq!(
            (
                before.modified().ok(),
                std::os::unix::fs::MetadataExt::ino(&before)
            ),
            (
                after.modified().ok(),
                std::os::unix::fs::MetadataExt::ino(&after)
            ),
            "a file whose rows did not change is not written again"
        );
        // A row added since shows in a whole new file.
        connection
            .execute(
                "INSERT INTO part VALUES ('p2', 'm1', 'ses_a', 3, '{\"text\":\"and 2\"}')",
                [],
            )
            .expect("a row");
        assert_eq!(export(&database, QUERY, &directory), Ok(2));
        assert_eq!(
            std::fs::read_to_string(directory.join("ses_a.jsonl"))
                .expect("a file")
                .lines()
                .count(),
            3
        );
    }

    /// The mirror writes nothing of the agent's: a statement that writes is refused, and so is an
    /// identifier that cannot name a file.
    #[test]
    fn a_statement_that_writes_and_an_identifier_that_is_no_file_name_are_refused() {
        let scratch = Scratch::new("refused");
        let database = scratch.0.join("agent.db");
        let connection = toy(&database);
        connection
            .execute_batch(
                "INSERT INTO message VALUES ('m1', '../escape', 1, '{\"role\":\"user\"}');",
            )
            .expect("a row");
        let directory = scratch.0.join("out");
        let refused = export(&database, QUERY, &directory).expect_err("an identifier with a slash");
        assert!(refused.contains("cannot name a file"), "{refused}");
        assert!(!scratch.0.join("escape.jsonl").exists());
        let writes = export(
            &database,
            "DELETE FROM message RETURNING session_id, id",
            &directory,
        )
        .expect_err("a statement that writes");
        assert!(
            writes.contains("writes")
                || writes.contains("readonly")
                || writes.contains("read-only"),
            "{writes}"
        );
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM message", [], |row| row.get(0))
            .expect("a count");
        assert_eq!(count, 1, "nothing was deleted");
    }

    /// The thread keeps the files current while it runs and `finish` leaves the whole mirror.
    #[test]
    fn the_thread_follows_the_database_and_finishes_with_a_whole_export() {
        let scratch = Scratch::new("thread");
        let database = scratch.0.join("agent.db");
        let directory = scratch.0.join("out");
        let mirroring = Mirroring::start(database.clone(), QUERY.to_owned(), directory.clone());
        std::thread::sleep(Duration::from_millis(250));
        assert!(
            !directory.exists(),
            "nothing before the agent has a database"
        );
        let connection = toy(&database);
        connection
            .execute(
                "INSERT INTO message VALUES ('m1', 'ses_a', 1, '{\"role\":\"user\"}')",
                [],
            )
            .expect("a row");
        let started = std::time::Instant::now();
        while !directory.join("ses_a.jsonl").is_file() && started.elapsed() < Duration::from_secs(5)
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            directory.join("ses_a.jsonl").is_file(),
            "the thread exported it"
        );
        assert_eq!(mirroring.failing(), None);
        connection
            .execute(
                "INSERT INTO message VALUES ('m2', 'ses_a', 2, '{\"role\":\"assistant\"}')",
                [],
            )
            .expect("a row");
        assert_eq!(mirroring.finish(), Ok(1));
        assert_eq!(
            std::fs::read_to_string(directory.join("ses_a.jsonl"))
                .expect("a file")
                .lines()
                .count(),
            2,
            "the last row is in the whole export"
        );
    }
}
