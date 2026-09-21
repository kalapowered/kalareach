//! The boundary every statement of the backup store crosses.
//!
//! One rule holds for the whole store: **no statement of it replaces or deletes a row as a side
//! effect of an insert.** A `REPLACE` conflict clause is the only way SQL asks for that, and this
//! is where it is refused.
//!
//! The refusal is not a habit of the code that writes statements. [`Statement`] is what SQLite is
//! spoken to with here, [`sql`] is the only way to make one, and it checks the statement where the
//! compiler can see the answer, so a statement that broke the rule would not build. rusqlite takes
//! a `&str` and will not take a [`Statement`]; the calls below take a [`Statement`] and will not
//! take a `&str`. The module's other files hold no call to SQLite at all.

use rusqlite::{Connection, Params, Row};

/// A statement the backup store may execute.
///
/// It holds no `REPLACE` conflict clause, because [`sql`] is the only thing that makes one and
/// that is what [`sql`] checks.
#[derive(Clone, Copy)]
pub(super) struct Statement(&'static str);

impl Statement {
    /// Wraps a statement that has passed the check. [`sql`] is what calls this.
    pub(super) const fn checked(text: &'static str) -> Self {
        Self(text)
    }
}

/// Makes the one kind of statement this store can execute, and refuses any other.
///
/// The check reads the statement the compiler makes, not the text somebody typed. An escape, a
/// join of two halves, a comment between the words: whatever spells the clause, the statement that
/// comes out of it holds the word, and the word is what is refused. A statement assembled while
/// the program runs is refused a step earlier, because a `String` is not a constant and this will
/// not take one.
macro_rules! sql {
    ($statement:expr) => {{
        const STATEMENT: &str = $statement;
        const _: () = assert!(
            $crate::backup::statements::holds_no_replacement(STATEMENT),
            "a statement of the backup store resolves a conflict by deleting the row it collided \
             with"
        );
        $crate::backup::statements::Statement::checked(STATEMENT)
    }};
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

/// What the backup store does with a statement, and the only place SQLite is spoken to.
///
/// Each call takes a [`Statement`], so the statement it runs is one the check above has read.
/// Each returns what rusqlite returns, so a caller decides for itself what a failure means and
/// whether a missing row is an answer.
pub(super) trait Execute {
    /// The connection underneath. Only the calls below use it.
    fn sqlite(&self) -> &Connection;

    /// Runs one statement and returns how many rows it changed.
    fn run(&self, statement: Statement, params: impl Params) -> rusqlite::Result<usize> {
        self.sqlite().execute(statement.0, params)
    }

    /// Runs the statements of one script, which is how a store is created.
    fn run_script(&self, statement: Statement) -> rusqlite::Result<()> {
        self.sqlite().execute_batch(statement.0)
    }

    /// Reads one row.
    fn read_one<T, P, F>(&self, statement: Statement, params: P, read: F) -> rusqlite::Result<T>
    where
        P: Params,
        F: FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    {
        self.sqlite().query_row(statement.0, params, read)
    }

    /// Prepares one statement, for a read of more than one row.
    fn prepared(&self, statement: Statement) -> rusqlite::Result<rusqlite::Statement<'_>> {
        self.sqlite().prepare(statement.0)
    }
}

impl Execute for Connection {
    fn sqlite(&self) -> &Connection {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::holds_no_replacement;

    /// The word a statement must not hold, in every spelling that still spells it.
    ///
    /// The check runs where the compiler can see the answer, so a statement that failed it would
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
}
