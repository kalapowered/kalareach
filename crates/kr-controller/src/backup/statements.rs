//! The boundary every statement of the backup store crosses.
//!
//! One rule holds for the whole store: **no statement of it replaces or deletes a row as a side
//! effect of an insert.** A `REPLACE` conflict clause is the only way SQL asks for that, and this
//! is where it is refused.
//!
//! The refusal is not a habit of the code that writes statements. [`Statement`] is what SQLite is
//! spoken to with, and making one goes through the check: [`sql`] runs it where the compiler can
//! see the answer, so a statement that broke the rule would not build. [`Database`] and
//! [`Writing`] hold the connection and the transaction and hand neither out, and their calls take
//! a [`Statement`] and will not take text, so this file is the only place in the module where a
//! statement can reach SQLite at all.

use std::path::Path;

use rusqlite::{Connection, Params, Row, TransactionBehavior};

/// A statement the backup store may execute.
///
/// It holds no `REPLACE` conflict clause: [`Statement::checked`] is the only way to make one and
/// that is what it checks, and [`sql`] calls it where the compiler can see the answer.
#[derive(Clone, Copy)]
pub(super) struct Statement(&'static str);

impl Statement {
    /// Checks one statement and wraps it.
    ///
    /// Called from a constant, as [`sql`] calls it, a statement that holds the clause fails the
    /// build. Called anywhere else, it refuses the statement rather than letting it through.
    pub(super) const fn checked(text: &'static str) -> Self {
        assert!(
            holds_no_replacement(text),
            "a statement of the backup store resolves a conflict by deleting the row it collided \
             with"
        );
        Self(text)
    }
}

/// Makes the one kind of statement this store can execute, where the compiler can see the answer.
///
/// The check reads the statement the compiler makes, not the text somebody typed. An escape, a
/// join of two halves, a comment between the words: whatever spells the clause, the statement that
/// comes out of it holds the word, and the word is what is refused. A statement assembled while
/// the program runs is refused a step earlier, because it is not a constant and this will not take
/// one.
macro_rules! sql {
    ($statement:expr) => {
        const { $crate::backup::statements::Statement::checked($statement) }
    };
}

pub(super) use sql;

/// Whether one statement is free of the `REPLACE` conflict clause.
///
/// `REPLACE INTO`, `INSERT OR REPLACE`, `UPDATE OR REPLACE` and a table's `ON CONFLICT REPLACE`
/// policy are the four ways SQL asks for a conflict to be resolved by deleting the row it collided
/// with, and all four spell the same word. So the word itself is what is refused, in any case and
/// wherever it falls, as long as it stands as a word: `an_obligation_is_never_replaced` is a
/// trigger's name and reads as `replaced`, which is a different word and passes. The store has no
/// use for the word in any other sense, so refusing all of them costs it nothing.
pub(super) const fn holds_no_replacement(statement: &str) -> bool {
    const CLAUSE: &[u8] = b"REPLACE";
    let bytes = statement.as_bytes();
    let mut start = 0;
    while start + CLAUSE.len() <= bytes.len() {
        let mut matched = 0;
        while matched < CLAUSE.len() && upper(bytes[start + matched]) == CLAUSE[matched] {
            matched += 1;
        }
        let before = if start == 0 { b' ' } else { bytes[start - 1] };
        let after = if start + CLAUSE.len() == bytes.len() {
            b' '
        } else {
            bytes[start + CLAUSE.len()]
        };
        if matched == CLAUSE.len() && !part_of_a_word(before) && !part_of_a_word(after) {
            return false;
        }
        start += 1;
    }
    true
}

const fn upper(byte: u8) -> u8 {
    if byte.is_ascii_lowercase() {
        byte - 32
    } else {
        byte
    }
}

const fn part_of_a_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// What anything of this store reads with, inside a transaction or outside one.
///
/// Both calls take a checked statement and neither names a connection or returns one, so what a
/// holder of one of these can do to the database is whatever the statement it was given says. It
/// is named for what this store asks of it, not for a guarantee that a statement only reads: a
/// checked statement that writes and returns rows would go through here as readily.
pub(super) trait Reads {
    /// Reads one row.
    fn read_one<T, P, F>(&self, statement: Statement, params: P, read: F) -> rusqlite::Result<T>
    where
        P: Params,
        F: FnOnce(&Row<'_>) -> rusqlite::Result<T>;

    /// Prepares one statement, for a read of more than one row.
    ///
    /// What comes back reads and runs the statement it was prepared from and takes no other, so
    /// the check has already read everything it can do.
    fn prepared(&self, statement: Statement) -> rusqlite::Result<rusqlite::Statement<'_>>;
}

/// The backup store's database, and the only thing in the module that holds a connection.
///
/// It hands the connection to nobody. Everything the store does with SQLite it does through the
/// calls here and on [`Writing`], each of which takes a [`Statement`], so there is no route by
/// which a statement the check has not read reaches the database.
#[derive(Debug)]
pub(super) struct Database {
    connection: Connection,
}

impl Database {
    /// Opens the database one host keeps its backup accounting in.
    pub(super) fn open(path: &Path) -> rusqlite::Result<Self> {
        Self::configured(Connection::open(path)?)
    }

    /// Opens one that exists only for the life of this process.
    pub(super) fn in_memory() -> rusqlite::Result<Self> {
        Self::configured(Connection::open_in_memory()?)
    }

    /// The settings every connection of this store is opened under.
    ///
    /// Writes reach the disk before a call returns, foreign keys are enforced, and recursive
    /// triggers are on: SQLite runs the delete rules for a delete that conflict resolution causes
    /// only with that last one, so a statement that reached this database by any other route still
    /// meets the rules that guard a delete rather than slipping under them.
    fn configured(connection: Connection) -> rusqlite::Result<Self> {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "recursive_triggers", "ON")?;
        Ok(Self { connection })
    }

    /// Refuses or admits writes on this connection, for a caller that is only reading.
    pub(super) fn set_query_only(&mut self, query_only: bool) -> rusqlite::Result<()> {
        self.connection
            .pragma_update(None, "query_only", if query_only { "ON" } else { "OFF" })
    }

    /// Begins a transaction that takes the write lock at once.
    ///
    /// Immediate, so two hosts' transactions cannot both read and then find one of them cannot
    /// write. Dropping it rolls back; only [`Writing::commit`] keeps what it did.
    pub(super) fn writing(&mut self) -> rusqlite::Result<Writing<'_>> {
        Ok(Writing {
            transaction: self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?,
        })
    }

    /// Runs one statement and returns how many rows it changed.
    pub(super) fn run(&self, statement: Statement, params: impl Params) -> rusqlite::Result<usize> {
        self.connection.execute(statement.0, params)
    }

    /// Runs the statements of one script, which is how a store is created.
    pub(super) fn run_script(&self, statement: Statement) -> rusqlite::Result<()> {
        self.connection.execute_batch(statement.0)
    }
}

/// One transaction of the backup store, which is where every change it makes happens.
pub(super) struct Writing<'a> {
    transaction: rusqlite::Transaction<'a>,
}

impl Writing<'_> {
    /// Keeps everything this transaction did.
    pub(super) fn commit(self) -> rusqlite::Result<()> {
        self.transaction.commit()
    }

    /// The identifier SQLite gave the row this transaction inserted last.
    pub(super) fn last_inserted(&self) -> i64 {
        self.transaction.last_insert_rowid()
    }

    /// Runs one statement and returns how many rows it changed.
    pub(super) fn run(&self, statement: Statement, params: impl Params) -> rusqlite::Result<usize> {
        self.transaction.execute(statement.0, params)
    }

    /// Runs the statements of one script, which is how a store is created.
    pub(super) fn run_script(&self, statement: Statement) -> rusqlite::Result<()> {
        self.transaction.execute_batch(statement.0)
    }
}

impl Reads for Database {
    fn read_one<T, P, F>(&self, statement: Statement, params: P, read: F) -> rusqlite::Result<T>
    where
        P: Params,
        F: FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    {
        self.connection.query_row(statement.0, params, read)
    }

    fn prepared(&self, statement: Statement) -> rusqlite::Result<rusqlite::Statement<'_>> {
        self.connection.prepare(statement.0)
    }
}

impl Reads for Writing<'_> {
    fn read_one<T, P, F>(&self, statement: Statement, params: P, read: F) -> rusqlite::Result<T>
    where
        P: Params,
        F: FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    {
        self.transaction.query_row(statement.0, params, read)
    }

    fn prepared(&self, statement: Statement) -> rusqlite::Result<rusqlite::Statement<'_>> {
        self.transaction.prepare(statement.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{Statement, holds_no_replacement};

    /// The word a statement must not hold, in every spelling that still spells it.
    ///
    /// Where `sql!` makes a statement the check runs in a constant, so one that failed it would
    /// not build and no test could reach it. What is tested here is the reading itself: that it
    /// finds the word wherever it falls and in whatever case, and that it does not mistake the
    /// word this store's own triggers are named after for it.
    #[test]
    fn a_statement_that_replaces_a_row_it_collides_with_is_the_one_thing_refused() {
        for statement in [
            "INSERT OR REPLACE INTO outbox (sequence) VALUES (1)",
            "insert or replace into outbox (sequence) values (1)",
            "InSeRt Or RePlAcE INTO outbox (sequence) VALUES (1)",
            "REPLACE INTO outbox (sequence) VALUES (1)",
            "UPDATE OR REPLACE outbox SET sequence = 1",
            "SELECT 1;REPLACE INTO outbox (sequence) VALUES (1)",
            "INSERT OR/**/REPLACE INTO outbox (sequence) VALUES (1)",
            "INSERT OR\nREPLACE INTO outbox (sequence) VALUES (1)",
            "CREATE TABLE t (a INTEGER, UNIQUE (a) ON CONFLICT REPLACE)",
            "replace",
        ] {
            assert!(
                !holds_no_replacement(statement),
                "`{statement}` resolves a conflict by deleting the row it collided with"
            );
        }
        for statement in [
            "",
            "INSERT INTO outbox (sequence) VALUES (1)",
            "INSERT INTO privacy_obligations (id) SELECT 1 WHERE NOT EXISTS (SELECT 1)",
            "SELECT 1 FROM outbox WHERE step = 'replaced'",
            "SELECT 1 FROM outbox WHERE step = 'unreplace'",
            "CREATE TRIGGER an_obligation_is_never_replaced BEFORE INSERT ON privacy_obligations \
             BEGIN SELECT RAISE(ABORT, 'no'); END",
        ] {
            assert!(
                holds_no_replacement(statement),
                "`{statement}` holds no such clause and is refused all the same"
            );
        }
    }

    /// Making a statement is the check, wherever it is made from.
    #[test]
    #[should_panic(expected = "resolves a conflict by deleting the row it collided with")]
    fn a_statement_made_outside_a_constant_is_checked_all_the_same() {
        let _ = Statement::checked("REPLACE INTO writers VALUES (?1, ?2, ?3, NULL)");
    }
}
