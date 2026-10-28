//! What this host read out of the test reports a suite wrote, kept where a restart finds it.
//!
//! A report is bound to the result of the run it came from: it names the run, the declared output
//! it was read from and the digest of that file, which the run's result records as an output
//! reference. The change-set service owns the result; this store owns only what was read out of a
//! file, and a row here that the result does not vouch for is never served.
//!
//! The record is a database of its own, and not a table of the change-set store: that store's
//! schema is one every release before this one has to be able to read, and a report nothing before
//! this release asks for is not a reason to move it. A release that does not name this file leaves
//! it alone and records its results without a report, and a host rolled back to it loses nothing
//! it protected: the reports are an account of what a suite wrote, not a restriction.
//!
//! A row is kept for as long as the run's result is: a result is never deleted while the version it
//! names exists, so the store forgets a run only when the change-set store holds no result for it
//! (a change-set store restored from an older copy while this file was kept).

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use kr_protocol::ids::MaterialisationId;
use kr_protocol::scalars::Uuid;
use kr_protocol::test_report::TestReport;
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{ControllerError, Result};

/// The file the environment's reports live in.
pub const TEST_REPORTS_RECORD: &str = "test-reports.sqlite3";

/// The schema version this build reads and writes.
pub const SCHEMA_VERSION: i64 = 1;

/// The oldest schema version this build opens: it reads no other.
pub const OLDEST_SCHEMA_VERSION: i64 = SCHEMA_VERSION;

/// The reports this host read, by the run they came from.
#[derive(Debug)]
pub struct Reports {
    connection: Mutex<Connection>,
}

impl Reports {
    /// Opens the record in `state_dir`.
    ///
    /// A database that holds a schema this build does not read is refused before anything is
    /// written to it.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be opened, or holds a schema this build does not read.
    pub fn open(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir).map_err(ControllerError::registry)?;
        let connection =
            kr_flush::release::open_connection(&state_dir.join(TEST_REPORTS_RECORD), None)
                .map_err(|error| ControllerError::registry(kr_flush::release::describe(&error)))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(ControllerError::registry)?;
        // The version is read before anything is written, so a database of a newer build is left
        // exactly as it is.
        let has_version_table: bool = connection
            .query_row(
                "SELECT count(*) > 0 FROM sqlite_master
                 WHERE type = 'table' AND name = 'test_reports_schema'",
                [],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let version: Option<i64> = if has_version_table {
            connection
                .query_row("SELECT version FROM test_reports_schema", [], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(ControllerError::registry)?
        } else {
            None
        };
        if let Some(found) = version
            && found != SCHEMA_VERSION
        {
            return Err(ControllerError::registry(format!(
                "the record of test reports is at schema {found} and this build reads \
                 {SCHEMA_VERSION}"
            )));
        }
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 CREATE TABLE IF NOT EXISTS test_reports_schema (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS test_reports (
                     materialisation_id BLOB NOT NULL,
                     output_path        TEXT NOT NULL,
                     output_digest      BLOB NOT NULL,
                     recorded_at_ms     INTEGER NOT NULL CHECK (recorded_at_ms >= 0),
                     record             TEXT NOT NULL,
                     PRIMARY KEY (materialisation_id, output_path)
                 );",
            )
            .map_err(ControllerError::registry)?;
        if version.is_none() {
            connection
                .execute(
                    "INSERT INTO test_reports_schema (version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )
                .map_err(ControllerError::registry)?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn with<T>(&self, body: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        body(&connection).map_err(ControllerError::registry)
    }

    /// Writes down what was read out of one declared output of one run. A report already held for
    /// that output of that run is replaced.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written.
    pub fn record(&self, report: &TestReport) -> Result<()> {
        let text = serde_json::to_string(report).map_err(ControllerError::registry)?;
        self.with(|connection| {
            connection.execute(
                "INSERT OR REPLACE INTO test_reports
                     (materialisation_id, output_path, output_digest, recorded_at_ms, record)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    report.materialisation_id.get().as_bytes().as_slice(),
                    report.output_path,
                    report.output_digest.as_bytes().as_slice(),
                    i64::try_from(report.recorded_at_ms.get()).unwrap_or(i64::MAX),
                    text,
                ],
            )?;
            Ok(())
        })
    }

    /// Every report held for one run, by the path of the output it was read from.
    ///
    /// A row that cannot be read is an error, never a missing report: it is a database this build
    /// did not write.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read, or holds a row it cannot read.
    pub fn of_run(&self, materialisation_id: MaterialisationId) -> Result<Vec<TestReport>> {
        let rows: Vec<String> = self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT record FROM test_reports WHERE materialisation_id = ?1
                 ORDER BY output_path",
            )?;
            statement
                .query_map(
                    params![materialisation_id.get().as_bytes().as_slice()],
                    |row| row.get(0),
                )?
                .collect()
        })?;
        rows.iter()
            .map(|text| {
                serde_json::from_str::<TestReport>(text).map_err(|_| {
                    ControllerError::registry(
                        "the record of test reports holds a report it cannot read",
                    )
                })
            })
            .collect()
    }

    /// The runs the record holds a report for.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read, or holds an identifier it cannot read.
    pub fn runs(&self) -> Result<Vec<MaterialisationId>> {
        let rows: Vec<Vec<u8>> = self.with(|connection| {
            let mut statement =
                connection.prepare("SELECT DISTINCT materialisation_id FROM test_reports")?;
            statement.query_map([], |row| row.get(0))?.collect()
        })?;
        rows.into_iter()
            .map(|bytes| {
                let bytes: [u8; kr_protocol::scalars::UUID_LEN] =
                    bytes.try_into().map_err(|_| {
                        ControllerError::registry(
                            "the record of test reports holds a bad run identifier",
                        )
                    })?;
                Ok(MaterialisationId::new(Uuid::from_bytes(bytes)))
            })
            .collect()
    }

    /// Lets go of every report held for one run, and says how many that was.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be written.
    pub fn forget_run(&self, materialisation_id: MaterialisationId) -> Result<usize> {
        self.with(|connection| {
            connection.execute(
                "DELETE FROM test_reports WHERE materialisation_id = ?1",
                params![materialisation_id.get().as_bytes().as_slice()],
            )
        })
    }

    /// Lets go of every report whose run is not among `runs_with_a_result`, the runs the
    /// change-set store holds a result for, and says how many runs that was.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read or written.
    pub fn forget_runs_without_a_result(
        &self,
        runs_with_a_result: &std::collections::HashSet<MaterialisationId>,
    ) -> Result<usize> {
        let mut forgotten = 0;
        for run in self.runs()? {
            if !runs_with_a_result.contains(&run) {
                self.forget_run(run)?;
                forgotten += 1;
            }
        }
        Ok(forgotten)
    }
}
