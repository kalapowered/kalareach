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

/// The schema version a record holds, or nothing when it holds none yet. A schema this build does
/// not read is an error.
fn schema_of(connection: &Connection) -> Result<Option<i64>> {
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
            "the record of test reports is at schema {found} and this build reads {SCHEMA_VERSION}"
        )));
    }
    Ok(version)
}

/// Every run a record holds a report for. A row that names no run this build can read is an error.
fn run_identifiers(connection: &Connection) -> Result<Vec<MaterialisationId>> {
    let has_table: bool = connection
        .query_row(
            "SELECT count(*) > 0 FROM sqlite_master
             WHERE type = 'table' AND name = 'test_reports'",
            [],
            |row| row.get(0),
        )
        .map_err(ControllerError::registry)?;
    if !has_table {
        return Ok(Vec::new());
    }
    let rows: Vec<Vec<u8>> = {
        let mut statement = connection
            .prepare("SELECT DISTINCT materialisation_id FROM test_reports")
            .map_err(ControllerError::registry)?;
        statement
            .query_map([], |row| row.get(0))
            .map_err(ControllerError::registry)?
            .collect::<rusqlite::Result<_>>()
            .map_err(ControllerError::registry)?
    };
    rows.into_iter()
        .map(|bytes| {
            let bytes: [u8; kr_protocol::scalars::UUID_LEN] = bytes.try_into().map_err(|_| {
                ControllerError::registry("the record of test reports holds a bad run identifier")
            })?;
            Ok(MaterialisationId::new(Uuid::from_bytes(bytes)))
        })
        .collect()
}

impl Reports {
    /// Opens the record in `state_dir`.
    ///
    /// A record that is already there is looked at first through a connection that cannot write,
    /// and is refused, with the file exactly as it was, when it holds a schema this build does
    /// not read or a row that names no run. Opening for writing changes a file that is not in
    /// write-ahead mode, and closing a writer folds a pending log into the file, so a record
    /// this build refuses is never opened that way.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be opened, or is a record this build does not read.
    pub fn open(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir).map_err(ControllerError::registry)?;
        let path = state_dir.join(TEST_REPORTS_RECORD);
        if path.try_exists().map_err(ControllerError::registry)? {
            let looked_at = kr_flush::release::open_connection(
                &path,
                Some(
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                ),
            )
            .map_err(|error| ControllerError::registry(kr_flush::release::describe(&error)))?;
            looked_at
                .busy_timeout(std::time::Duration::from_secs(5))
                .map_err(ControllerError::registry)?;
            schema_of(&looked_at)?;
            run_identifiers(&looked_at)?;
        }
        let connection = kr_flush::release::open_connection(&path, None)
            .map_err(|error| ControllerError::registry(kr_flush::release::describe(&error)))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(ControllerError::registry)?;
        let version = schema_of(&connection)?;
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

    /// Opens the record in `state_dir` for a daemon that starts whether it can or not, and lets go
    /// of the reports whose run is not among the runs `runs_with_a_result` answers for.
    ///
    /// A record that cannot be used (a file that is not a database, a schema this build does not
    /// read, a row that names no run) restricts nothing, so its closed side is no report and not
    /// no daemon: the failure is said once on the daemon's standard error with the file's path,
    /// the file is left exactly as it is for the release that can read it, and nothing is kept in
    /// it or answered from it. `runs_with_a_result` is asked only when the record holds a report;
    /// when it cannot answer, the reports stay, and none is served that a result does not vouch
    /// for.
    #[must_use]
    pub fn open_for_a_daemon(
        state_dir: &Path,
        runs_with_a_result: impl FnOnce() -> std::result::Result<
            std::collections::HashSet<MaterialisationId>,
            String,
        >,
    ) -> Option<Self> {
        let said = |what: &str, why: &dyn std::fmt::Display| {
            eprintln!(
                "kr-controller: the record of test reports at {} {what}: {}",
                state_dir.join(TEST_REPORTS_RECORD).display(),
                kr_project::git::redact(&why.to_string())
            );
        };
        let reports = match Self::open(state_dir) {
            Ok(reports) => reports,
            Err(error) => {
                said(
                    "cannot be used and is left as it is; no report is kept or answered",
                    &error,
                );
                return None;
            }
        };
        let runs = match reports.runs() {
            Ok(runs) => runs,
            Err(error) => {
                said(
                    "cannot be read and is left as it is; no report is kept or answered",
                    &error,
                );
                return None;
            }
        };
        if runs.is_empty() {
            return Some(reports);
        }
        match runs_with_a_result() {
            Ok(held) => {
                if let Err(error) = reports.forget_runs_without_a_result(&held) {
                    said(
                        "could not let go of the reports of runs that left no result",
                        &error,
                    );
                }
            }
            Err(why) => said(
                "keeps its reports, since the results they belong to could not be listed",
                &why,
            ),
        }
        Some(reports)
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
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        run_identifiers(&connection)
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
