//! The content-bearing export of a support bundle: which sessions it may hold, and what it says
//! about the ones it leaves out.
//!
//! Section 29: "Any real-content capture is opt-in, excludes private sessions and requires a
//! preview/redaction check before export". The flag is the opt-in. This module is the exclusion.
//!
//! # What is private
//!
//! Privacy mode is one switch for an environment, with a generation that every change advances,
//! and no session carries a flag of its own. So a session is private when
//!
//! * privacy mode is on, whatever the session: every session of the environment is private while
//!   it is, live or closed, including one created after it went on; or
//! * the host lists it among the sessions that still owe privacy cleanup, whatever the switch says
//!   now. A session whose worker ended before it said its cleanup was complete stays on that list
//!   after privacy mode is turned off, because what it kept is the archive's and nothing removes
//!   it.
//!
//! Nothing else is private. Turning privacy mode off starts new retention from that point, so a
//! session that ran through a private interval and owes nothing now is not. That includes one
//! created while privacy mode was on and finished its cleanup: the host reports it complete, and
//! this export takes the host's word.
//!
//! # How it is read
//!
//! This is a client reading the host: the file is the person's own, on their own machine, and no
//! daemon authority is crossed. What a client can promise is a bracket. Privacy mode is read, then
//! the sessions, then privacy mode again. Privacy mode on at either read, or a generation that
//! moved between them, leaves every session out, and the person runs the command again; no session
//! is exported on a reading that straddled a change. A read that fails fails the command, and
//! nothing is written.
//!
//! The bracket narrows the window and does not close it. Privacy mode can be turned on after the
//! last read and before the file is written, and what has been written cannot be recalled. That is
//! the same limit privacy mode states about what had already left the host.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::ids::{EnvironmentId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::privacy::{PrivacyReport, PrivacyStatusParams};
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    ClosureReason, Durability, OwnershipCoverage, SessionListParams, SessionListResult,
    SessionState, SessionSummary, ShellMode,
};
use serde::Serialize;

use super::bundle::{self, Content};
use crate::error::{CliError, Result};

/// What the export reads of the host: where privacy mode stands, and the sessions.
///
/// The command line's own connection implements it. It is a trait so that a reading can be held
/// between its two privacy reads, and so that a read that fails can be made to.
pub trait Host {
    /// Where privacy mode stands for the environment this connection reaches.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal, a transport failure, or an answer that is not a report.
    fn privacy(&mut self) -> impl Future<Output = Result<PrivacyReport>>;

    /// Every session of `environment_id`, the ones that have closed included.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal, a transport failure, or an answer that is not a session list.
    fn sessions(
        &mut self,
        environment_id: EnvironmentId,
    ) -> impl Future<Output = Result<SessionListResult>>;
}

impl Host for kr_ipc::client::LocalClient {
    async fn privacy(&mut self) -> Result<PrivacyReport> {
        self.request(Method::PrivacyStatus, &PrivacyStatusParams {})
            .await
            .map_err(CliError::Ipc)?
            .map_err(CliError::Refused)?
            .to_typed()
            .map_err(|error| {
                CliError::Other(shown!(
                    "the host's privacy state could not be read, so no content was exported: {}",
                    Shown::cbor(&error)
                ))
            })
    }

    async fn sessions(&mut self, environment_id: EnvironmentId) -> Result<SessionListResult> {
        self.request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::some(environment_id),
                include_closed: true,
            },
        )
        .await
        .map_err(CliError::Ipc)?
        .map_err(CliError::Refused)?
        .to_typed()
        .map_err(|error| {
            CliError::Other(shown!(
                "the host's session list could not be read: {}",
                Shown::cbor(&error)
            ))
        })
    }
}

/// Why a session is not in the export.
///
/// The order is the order a session's reason is chosen in, and the order the reasons are said in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Why {
    /// Privacy mode is on.
    PrivacyOn,
    /// Privacy mode changed while the sessions were read, so no reading of them can be trusted.
    Moved,
    /// The host lists it among the sessions that still owe privacy cleanup.
    OwesCleanup,
}

impl Why {
    /// The reason in words, as the preview and the manifest say it.
    #[must_use]
    pub const fn said(self) -> &'static str {
        match self {
            Self::PrivacyOn => "privacy mode is on",
            Self::Moved => "privacy mode changed while the sessions were read",
            Self::OwesCleanup => "it still owes the cleanup privacy mode asked for",
        }
    }

    /// The reason as a closed word, for a script.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PrivacyOn => "privacy_mode_on",
            Self::Moved => "privacy_mode_changed",
            Self::OwesCleanup => "owes_privacy_cleanup",
        }
    }
}

/// One session the host listed, and the reason it is left out when it is.
pub struct Listed {
    summary: SessionSummary,
    why: Option<Why>,
}

kr_client::debug_as_name!(Listed);

/// What the host said, after the privacy rule has been applied to each session.
pub struct Reading {
    listed: Vec<Listed>,
}

kr_client::debug_as_name!(Reading);

/// Reads the sessions of `environment_id` and decides which of them are private.
///
/// # Errors
///
/// Returns the failure of whichever read failed. Nothing is exported from a reading that failed.
pub async fn read(host: &mut impl Host, environment_id: EnvironmentId) -> Result<Reading> {
    let before = host.privacy().await?;
    let sessions = host.sessions(environment_id).await?;
    let after = host.privacy().await?;
    Ok(Reading {
        listed: select(&before, sessions.sessions, &after),
    })
}

/// Applies the privacy rule to `sessions`, which were read between `before` and `after`.
#[must_use]
pub fn select(
    before: &PrivacyReport,
    sessions: Vec<SessionSummary>,
    after: &PrivacyReport,
) -> Vec<Listed> {
    // Every session while privacy mode is on at either read. A generation that moved with the mode
    // off at both ends means privacy mode was on and off again in between, which no list read
    // across it can be told from one read after it.
    let all = if before.enabled || after.enabled {
        Some(Why::PrivacyOn)
    } else if before.generation != after.generation {
        Some(Why::Moved)
    } else {
        None
    };
    // The sessions still owing cleanup, whatever the switch says: the union of the two reads, so a
    // session either of them lists is left out.
    let owing: BTreeSet<SessionId> = before
        .sessions
        .iter()
        .chain(&after.sessions)
        .map(|owed| owed.session_id)
        .collect();
    sessions
        .into_iter()
        .map(|summary| {
            let why = all.or_else(|| {
                owing
                    .contains(&summary.session_id)
                    .then_some(Why::OwesCleanup)
            });
            Listed { summary, why }
        })
        .collect()
}

/// The file `content/sessions.json` holds.
#[derive(Serialize)]
struct Record {
    sessions: Vec<SessionRecord>,
}

/// One session in the file: who it is, where and how it ran, and how it ended.
#[derive(Serialize)]
struct SessionRecord {
    session_id: String,
    display_number: u64,
    state: SessionState,
    shell_mode: ShellMode,
    worker_profile: kr_protocol::identity::WorkerProfile,
    created_at_ms: u64,
    shell: String,
    cwd: String,
    closure: Option<ClosureOut>,
}

/// How a closed session ended. Which processes it stopped and what survived are counted and not
/// named: their names are text, and a count is what a person reading the file needs.
#[derive(Serialize)]
struct ClosureOut {
    reason: ClosureReason,
    root_exit_code: Option<u64>,
    root_signal: Option<String>,
    closed_at_ms: u64,
    ownership_coverage: OwnershipCoverage,
    durability: Durability,
    terminated_count: u64,
    surviving_count: u64,
}

impl SessionRecord {
    fn of(summary: &SessionSummary) -> Self {
        Self {
            session_id: summary.session_id.to_string(),
            display_number: summary.display_number.get(),
            state: summary.state,
            shell_mode: summary.shell_mode,
            worker_profile: summary.worker_profile,
            created_at_ms: summary.created_at_ms.get(),
            shell: summary.shell_path.clone(),
            cwd: summary.cwd.clone(),
            closure: summary.closure.as_ref().map(|closure| ClosureOut {
                reason: closure.reason,
                root_exit_code: closure.root_exit_code.as_ref().map(|code| code.get()),
                root_signal: closure.root_signal.as_ref().cloned(),
                closed_at_ms: closure.closed_at_ms.get(),
                ownership_coverage: closure.ownership_coverage,
                durability: closure.durability,
                terminated_count: closure.terminated.len() as u64,
                surviving_count: closure.surviving.len() as u64,
            }),
        }
    }
}

/// The export, composed: the entry to write and what was left out of it.
pub struct Composed {
    content: Content,
    left_out: Vec<(Why, u64)>,
}

kr_client::debug_as_name!(Composed);

impl Composed {
    /// The entry the bundle would carry.
    #[must_use]
    pub fn into_content(self) -> Content {
        self.content
    }

    /// How many sessions were left out for each reason, in the order the reasons are said in.
    #[must_use]
    pub fn left_out(&self) -> &[(Why, u64)] {
        &self.left_out
    }
}

/// Composes the export from what was read.
///
/// # Errors
///
/// Returns an error when the file cannot be serialised.
pub fn compose(reading: &Reading) -> Result<Composed> {
    let mut left_out: BTreeMap<Why, u64> = BTreeMap::new();
    let mut kept = Vec::new();
    for listed in &reading.listed {
        match listed.why {
            Some(why) => *left_out.entry(why).or_default() += 1,
            None => kept.push(SessionRecord::of(&listed.summary)),
        }
    }
    let count = kept.len() as u64;
    let bytes = serde_json::to_vec_pretty(&Record { sessions: kept }).map_err(|error| {
        CliError::Other(shown!(
            "this export could not be written: {}",
            Shown::json(&error)
        ))
    })?;
    let left_out: Vec<(Why, u64)> = left_out.into_iter().collect();
    Ok(Composed {
        content: Content {
            entry: bundle::SESSIONS_ENTRY,
            describes: describes(count, &left_out),
            bytes,
        },
        left_out,
    })
}

/// What the entry holds, in the words the command prints and the manifest records.
fn describes(kept: u64, left_out: &[(Why, u64)]) -> Sentence {
    let mut sentence = Sentence::new()
        .stated("the shell, working directory and closure of ")
        .number(kept)
        .stated(plural(kept));
    for (why, count) in left_out {
        sentence = sentence
            .stated("; ")
            .number(*count)
            .stated(plural(*count))
            .stated(" left out: ")
            .stated(why.said());
    }
    sentence
}

/// " session" or " sessions", for a count.
const fn plural(count: u64) -> &'static str {
    if count == 1 { " session" } else { " sessions" }
}

#[cfg(test)]
mod tests;
