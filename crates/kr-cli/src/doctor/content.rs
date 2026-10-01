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
//! last read and before the preview is printed or the file is written, and what has been printed or
//! written cannot be recalled. That is the same limit privacy mode states about what had already
//! left the host.
//!
//! # What is shown, and what is written
//!
//! The content is composed once, with the credentials the [`redact`] rules find taken out, and it
//! is printed in full before anything is written, with a digest of exactly what would be written.
//! Writing needs an [`Approved`], which exists only when the content composed at that moment has
//! the digest the person was shown: they confirmed it at a terminal, or they ran the command again
//! with `--confirm-content` and the digest a `--preview` run printed. Nothing that was not printed
//! can be written, and a content that changed between the two is refused, never written.
//! "Every content-bearing byte was shown" is what the digest says; the diagnostics and the report
//! in the bundle are not content.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::{BufRead as _, Read as _};

use kr_cbor::CanonicalValue;
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

pub mod redact;

use super::bundle::{self, Content};
use crate::error::{CliError, Result};
use crate::output::{Asked, Line, Request};
use crate::stdout_line;

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
    /// The person asked for it to be left out.
    Dropped,
}

impl Why {
    /// The reason in words, as the preview and the manifest say it.
    #[must_use]
    pub const fn said(self) -> &'static str {
        match self {
            Self::PrivacyOn => "privacy mode is on",
            Self::Moved => {
                "privacy mode changed while the sessions were read (run the command again)"
            }
            Self::OwesCleanup => "privacy cleanup is still owed",
            Self::Dropped => "it was left out by choice",
        }
    }

    /// The reason as a closed word, for a script.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PrivacyOn => "privacy_mode_on",
            Self::Moved => "privacy_mode_changed",
            Self::OwesCleanup => "owes_privacy_cleanup",
            Self::Dropped => "left_out_by_choice",
        }
    }
}

/// One session the host listed, and the reason it is left out when it is.
pub(crate) struct Listed {
    summary: SessionSummary,
    why: Option<Why>,
}

kr_client::debug_as_name!(Listed);

/// What the host said, after the privacy rule has been applied to each session.
pub(crate) struct Reading {
    listed: Vec<Listed>,
}

kr_client::debug_as_name!(Reading);

impl Reading {
    /// Whether the host listed this session.
    #[must_use]
    pub(crate) fn knows(&self, session_id: SessionId) -> bool {
        self.listed
            .iter()
            .any(|listed| listed.summary.session_id == session_id)
    }
}

/// Reads the sessions of `environment_id` and decides which of them are private.
///
/// # Errors
///
/// Returns the failure of whichever read failed. Nothing is exported from a reading that failed.
pub(crate) async fn read(host: &mut impl Host, environment_id: EnvironmentId) -> Result<Reading> {
    let before = host.privacy().await?;
    let sessions = host.sessions(environment_id).await?;
    let after = host.privacy().await?;
    Ok(Reading {
        listed: select(&before, sessions.sessions, &after),
    })
}

/// Applies the privacy rule to `sessions`, which were read between `before` and `after`.
#[must_use]
pub(crate) fn select(
    before: &PrivacyReport,
    sessions: Vec<SessionSummary>,
    after: &PrivacyReport,
) -> Vec<Listed> {
    // Every session, when privacy mode is on now or was on, or changed, while the list was read.
    // It is on now when the second read says so. Otherwise a mode that was on at the first read, or
    // a generation that moved with the mode off at both ends, means it was turned off, or on and
    // off again, in between; no list read across a change can be told from one read after it.
    let all = if after.enabled {
        Some(Why::PrivacyOn)
    } else if before.enabled || before.generation != after.generation {
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

/// How a field's text is redacted on this host: whose home directory it names, and how its paths
/// spell and compare.
#[derive(Clone, PartialEq, Eq)]
pub struct Rules {
    home: Option<String>,
    paths: redact::Paths,
}

kr_client::debug_as_name!(Rules);

impl Rules {
    /// This host's own: the home directory of the user running the command.
    #[must_use]
    pub fn here() -> Self {
        let variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        Self {
            home: std::env::var_os(variable).and_then(|home| home.into_string().ok()),
            paths: redact::Paths::here(),
        }
    }

    /// Rules for a home directory and a way of spelling paths, for a test.
    #[must_use]
    pub const fn new(home: Option<String>, paths: redact::Paths) -> Self {
        Self { home, paths }
    }

    fn field(&self, text: &str) -> String {
        redact::field(text, self.home.as_deref(), self.paths)
    }
}

/// The file `content/sessions.json` holds.
#[derive(Serialize)]
struct Record {
    /// The rules that took the credentials out, so a reader knows what was done to the text.
    redaction: &'static str,
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
    fn of(summary: &SessionSummary, rules: &Rules) -> Self {
        Self {
            session_id: summary.session_id.to_string(),
            display_number: summary.display_number.get(),
            state: summary.state,
            shell_mode: summary.shell_mode,
            worker_profile: summary.worker_profile,
            created_at_ms: summary.created_at_ms.get(),
            shell: rules.field(&summary.shell_path),
            cwd: rules.field(&summary.cwd),
            closure: summary.closure.as_ref().map(|closure| ClosureOut {
                reason: closure.reason,
                root_exit_code: closure.root_exit_code.as_ref().map(|code| code.get()),
                root_signal: closure
                    .root_signal
                    .as_ref()
                    .map(|signal| rules.field(signal)),
                closed_at_ms: closure.closed_at_ms.get(),
                ownership_coverage: closure.ownership_coverage,
                durability: closure.durability,
                terminated_count: closure.terminated.len() as u64,
                surviving_count: closure.surviving.len() as u64,
            }),
        }
    }
}

/// The digest of what would be written: the SHA-256 of the entry's name and bytes and of how many
/// sessions were left out for each reason, under a domain of its own.
///
/// The reasons are in it because a person who confirms is confirming what was left out as well as
/// what is in, and they are in a fixed order with their counts as numbers, so two different
/// exports cannot have one digest.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Digest([u8; 32]);

kr_client::debug_as_name!(Digest);

impl Digest {
    /// Reads a digest as the preview prints it: 64 hexadecimal digits, in either case.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in text.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(pair).ok()?;
            bytes[index] = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// The digest as 64 lower-case hexadecimal digits.
    #[must_use]
    pub fn hex(&self) -> String {
        use std::fmt::Write as _;

        self.0
            .iter()
            .fold(String::with_capacity(64), |mut text, byte| {
                let _ = write!(text, "{byte:02x}");
                text
            })
    }

    /// The digest as four numbers, for a sentence a manifest carries.
    fn words(&self) -> [u64; 4] {
        let mut words = [0_u64; 4];
        for (word, chunk) in words.iter_mut().zip(self.0.chunks(8)) {
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(chunk);
            *word = u64::from_be_bytes(bytes);
        }
        words
    }

    fn of(entry: &str, bytes: &[u8], left_out: &[(Why, u64)]) -> Result<Self> {
        let refused = |error: kr_cbor::CborError| {
            CliError::Other(shown!(
                "the content could not be summed up: {}",
                Shown::cbor(&error)
            ))
        };
        let entries = CanonicalValue::Array(vec![CanonicalValue::Array(vec![
            CanonicalValue::text(entry),
            CanonicalValue::bytes(bytes),
        ])]);
        let reasons = left_out
            .iter()
            .map(|(why, count)| {
                Ok(CanonicalValue::Array(vec![
                    CanonicalValue::text(why.code()),
                    CanonicalValue::integer(i128::from(*count))?,
                ]))
            })
            .collect::<std::result::Result<Vec<_>, kr_cbor::CborError>>()
            .map_err(refused)?;
        kr_cbor::signing_digest(
            "kalareach/support-bundle-content/1",
            vec![entries, CanonicalValue::Array(reasons)],
        )
        .map(Self)
        .map_err(refused)
    }
}

/// The export, composed: the entry to write, what was left out of it, and what is shown.
///
/// A composed export approves nothing by itself: approval is private to the export, which makes it
/// only after the preview has printed.
///
/// ```compile_fail
/// fn forge(composed: kr_cli::doctor::content::Composed) {
///     let digest = composed.digest();
///     let _approved = composed.approve(&digest);
/// }
/// ```
pub struct Composed {
    content: Content,
    text: String,
    left_out: Vec<(Why, u64)>,
    kept: Vec<SessionId>,
    digest: Digest,
}

kr_client::debug_as_name!(Composed);

impl Composed {
    /// How many sessions were left out for each reason, in the order the reasons are said in.
    #[must_use]
    pub fn left_out(&self) -> &[(Why, u64)] {
        &self.left_out
    }

    /// The digest of what would be written.
    #[must_use]
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// The sessions the content names.
    #[must_use]
    pub fn kept(&self) -> &[SessionId] {
        &self.kept
    }

    /// The content as it would be written: the text the preview prints.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// What the person is shown before anything is written.
    #[must_use]
    fn preview(&self) -> Preview {
        let mut lines = vec![
            stdout_line!("--include-content adds the content-bearing diagnostic export:"),
            stdout_line!("{}", self.content.describe()),
            stdout_line!(
                "Redacted by the rules {}, and shown here exactly as it will be written:",
                redact::RULES
            ),
        ];
        lines.extend(
            self.text
                .lines()
                .map(|line| stdout_line!("    {}", Asked::text(Request::Export, line))),
        );
        lines.push(stdout_line!(
            "Digest {}",
            crate::shown::hex_digest(&self.digest.hex())
        ));
        lines.push(stdout_line!(
            "A filter is not a guarantee that no secret remains. The rules take out credentials \
             written as NAME=value, as --option value and as user:password@host in a URL, and \
             the home directory of the user running this command. A secret anywhere else stays in \
             the text, and so does a user name elsewhere in a path."
        ));
        lines.push(stdout_line!(
            "Privacy mode turned on after the host was last read does not stop this preview or \
             the write, and turned on after this preview is printed or the bundle is written \
             cannot recall either. A session that was created while privacy mode was on and has \
             finished its cleanup is in the content once privacy mode is off."
        ));
        lines.push(stdout_line!(
            "This preview is ordinary terminal output: in a KalaReach session it becomes that \
             session's output, which the host and any device viewing the session can read."
        ));
        Preview { lines }
    }

    /// Approves this content for writing, when it is the content `shown` is the digest of.
    ///
    /// # Errors
    ///
    /// Returns an error when the content composed now is not the content that was shown: nothing
    /// is approved, and nothing is written.
    fn approve(&self, shown: &Digest) -> Result<Approved> {
        if self.digest != *shown {
            return Err(changed());
        }
        Ok(Approved {
            content: self.content.clone(),
        })
    }
}

/// The failure of a content that is not the one that was shown.
fn changed() -> CliError {
    CliError::Other(Shown::said(
        "the content is not what was shown: the host's sessions or privacy mode changed, so \
         nothing was written; run the command again",
    ))
}

/// What a person is shown of an export before anything is written.
///
/// It holds the person's own content, so it has no `Debug` and no `Display`, and only this module
/// builds one: the one way it reaches standard error is [`crate::report::show_preview`].
///
/// ```compile_fail
/// fn needs_debug<T: std::fmt::Debug>() {}
/// needs_debug::<kr_cli::doctor::content::Preview>();
/// ```
pub struct Preview {
    lines: Vec<Line>,
}

impl Preview {
    /// The lines to print, in order.
    #[must_use]
    pub fn lines(&self) -> &[Line] {
        &self.lines
    }
}

/// An export that may be written: it was composed, shown, and is the content a person was shown.
///
/// Only the export makes one, after it has printed the content and compared its digest, so nothing
/// that was not shown can reach the archive:
///
/// ```compile_fail
/// fn forge(content: kr_cli::doctor::bundle::Content) -> kr_cli::doctor::content::Approved {
///     kr_cli::doctor::content::Approved { content }
/// }
/// ```
pub struct Approved {
    content: Content,
}

kr_client::debug_as_name!(Approved);

impl Approved {
    /// The entry to write.
    pub(super) const fn content(&self) -> &Content {
        &self.content
    }

    /// An approval of `content` for a test of the archive's own: no export has shown it.
    #[cfg(test)]
    pub(crate) const fn for_test(content: Content) -> Self {
        Self { content }
    }
}

/// Composes the export from what was read, leaving out `exclude` as well.
///
/// # Errors
///
/// Returns an error when the content cannot be serialised or summed up.
pub(crate) fn compose(reading: &Reading, exclude: &[SessionId], rules: &Rules) -> Result<Composed> {
    let mut left_out: BTreeMap<Why, u64> = BTreeMap::new();
    let mut records = Vec::new();
    let mut kept = Vec::new();
    for listed in &reading.listed {
        let why = listed.why.or_else(|| {
            exclude
                .contains(&listed.summary.session_id)
                .then_some(Why::Dropped)
        });
        match why {
            Some(why) => *left_out.entry(why).or_default() += 1,
            None => {
                records.push(SessionRecord::of(&listed.summary, rules));
                kept.push(listed.summary.session_id);
            }
        }
    }
    let count = records.len() as u64;
    let text = serde_json::to_string_pretty(&Record {
        redaction: redact::RULES,
        sessions: records,
    })
    .map_err(|error| {
        CliError::Other(shown!(
            "this export could not be written: {}",
            Shown::json(&error)
        ))
    })?;
    let text = visible(&text);
    let left_out: Vec<(Why, u64)> = left_out.into_iter().collect();
    let digest = Digest::of(bundle::SESSIONS_ENTRY, text.as_bytes(), &left_out)?;
    Ok(Composed {
        content: Content::new(
            bundle::SESSIONS_ENTRY,
            describes(count, &left_out, &digest),
            text.clone().into_bytes(),
        ),
        text,
        left_out,
        kept,
        digest,
    })
}

/// Writes every character that would change what a terminal shows, or show nothing, as an escape, so
/// the text on the screen is the text in the file. serde_json writes the control characters below
/// U+0020 as escapes already; it writes these as themselves, and they are only ever inside a string.
/// A character outside the basic plane is written as the surrogate pair JSON spells it with.
fn visible(text: &str) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        if hides(character) {
            let mut units = [0_u16; 2];
            for unit in character.encode_utf16(&mut units) {
                let _ = write!(out, "\\u{unit:04x}");
            }
        } else {
            out.push(character);
        }
    }
    out
}

/// Whether a character can hide or reorder text on a terminal: delete and the C1 controls, the line
/// and paragraph separators, the Arabic number signs, and every default-ignorable code point (the
/// soft hyphen, the combining grapheme joiner, the Arabic letter mark, the Hangul and Khmer fillers,
/// the Mongolian selectors, the zero-width and directional marks and overrides, the invisible
/// operators, the variation selectors, the byte order mark, the interlinear and musical format
/// characters and the tag characters).
const fn hides(character: char) -> bool {
    matches!(
        character,
        '\u{007f}'..='\u{009f}'
            | '\u{00ad}'
            | '\u{034f}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061c}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08e2}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

/// What the entry holds, in the words the command prints and the manifest records.
fn describes(kept: u64, left_out: &[(Why, u64)], digest: &Digest) -> Sentence {
    let [first, second, third, fourth] = digest.words();
    let mut sentence = Sentence::new()
        .stated("the shell, working directory and closure of ")
        .number(kept)
        .stated(plural(kept))
        .stated(", redacted by ")
        .stated(redact::RULES)
        .stated(" and printed before it was written (digest ")
        .hexadecimal(first)
        .hexadecimal(second)
        .hexadecimal(third)
        .hexadecimal(fourth)
        .stated(")");
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

/// What the person asked of this export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Print the content and its digest, and write nothing.
    Preview,
    /// Write the content only when it has this digest.
    Confirmed(Digest),
    /// Print the content, and ask at the terminal whether to write it.
    Ask,
}

/// What the export did: the content it composed and, when it may be written, the approval.
pub struct Exported {
    composed: Composed,
    approved: Option<Approved>,
}

kr_client::debug_as_name!(Exported);

impl Exported {
    /// The content that was composed and shown.
    #[must_use]
    pub const fn composed(&self) -> &Composed {
        &self.composed
    }

    /// The approval to write it, when there is one: none for a preview.
    #[must_use]
    pub const fn approved(&self) -> Option<&Approved> {
        self.approved.as_ref()
    }
}

/// Reads, composes, shows and, where the person confirms it, approves the content export.
///
/// The preview is printed on the error stream by [`crate::report::show_preview`] and the question
/// is put at the terminal by [`ask_at_terminal`]; nothing else can stand in for either, because an
/// approval is made only after the first has printed the content. A person who answers anything but
/// yes or the identifier of a session in the content has declined, and a content that is not the
/// content they were shown is never approved.
///
/// # Errors
///
/// Returns an error when the host cannot be read, when `exclude` names a session the host did not
/// list, when the preview cannot be printed, when the person declines, and when the content is not
/// the content that was shown.
pub async fn export(
    host: &mut impl Host,
    environment_id: EnvironmentId,
    decision: Decision,
    exclude: Vec<SessionId>,
    rules: &Rules,
) -> Result<Exported> {
    export_with(
        host,
        environment_id,
        decision,
        exclude,
        rules,
        &mut crate::report::show_preview,
        &mut ask_at_terminal,
    )
    .await
}

/// [`export`] with its two ways of reaching the person given: the crate's own tests hold what was
/// printed and asked, and make each fail.
pub(crate) async fn export_with(
    host: &mut impl Host,
    environment_id: EnvironmentId,
    decision: Decision,
    mut exclude: Vec<SessionId>,
    rules: &Rules,
    show: &mut dyn FnMut(&Preview) -> Result<()>,
    ask: &mut dyn FnMut(&Shown) -> Result<Option<String>>,
) -> Result<Exported> {
    // What was named on the command line has to be a session the host lists. A session a person
    // dropped at the question was listed a moment ago, and is no cause for a usage failure if the
    // host no longer lists it.
    let mut named_by_the_command = true;
    loop {
        let reading = read(host, environment_id).await?;
        if named_by_the_command && exclude.iter().any(|id| !reading.knows(*id)) {
            return Err(CliError::Usage(Shown::said(
                "--exclude-session names a session this environment did not list",
            )));
        }
        named_by_the_command = false;
        let composed = compose(&reading, &exclude, rules)?;
        match decision {
            Decision::Preview => {
                show(&composed.preview())?;
                return Ok(Exported {
                    composed,
                    approved: None,
                });
            }
            Decision::Confirmed(digest) => {
                // Before anything is printed: content that is not what was confirmed is not shown
                // to a log that was only asked for the content the person already saw.
                if composed.digest != digest {
                    return Err(changed());
                }
                show(&composed.preview())?;
                let approved = composed.approve(&digest)?;
                return Ok(Exported {
                    composed,
                    approved: Some(approved),
                });
            }
            Decision::Ask => {
                show(&composed.preview())?;
                match answer(&composed, ask)? {
                    Answer::Write => {
                        // Read again: what was shown some time ago is written only when the host
                        // still says the same, so a pause at the question cannot export a session
                        // that became private meanwhile.
                        let fresh = compose(&read(host, environment_id).await?, &exclude, rules)?;
                        let shown = composed.digest;
                        let approved = fresh.approve(&shown)?;
                        return Ok(Exported {
                            composed,
                            approved: Some(approved),
                        });
                    }
                    Answer::Drop(session) => exclude.push(session),
                }
            }
        }
    }
}

/// What a person answered.
enum Answer {
    /// Write the bundle with the content that was shown.
    Write,
    /// Leave this session out, and show the content again.
    Drop(SessionId),
}

/// Asks until the person says yes, names a session in the content, or declines.
fn answer(
    composed: &Composed,
    ask: &mut dyn FnMut(&Shown) -> Result<Option<String>>,
) -> Result<Answer> {
    let mut question = Shown::said(
        "Type yes to write the bundle with this content, the identifier of a session above to \
         leave it out, or anything else to stop:",
    );
    loop {
        let Some(typed) = ask(&question)? else {
            return Err(declined());
        };
        let typed = typed.trim();
        if typed.eq_ignore_ascii_case("yes") {
            return Ok(Answer::Write);
        }
        let Ok(session) = typed.parse::<SessionId>() else {
            return Err(declined());
        };
        if composed.kept.contains(&session) {
            return Ok(Answer::Drop(session));
        }
        question = Shown::said(
            "That is not the identifier of a session in this content. Type yes to write the \
             bundle, the identifier of a session above to leave it out, or anything else to stop:",
        );
    }
}

/// The failure of a person who did not approve the content.
fn declined() -> CliError {
    CliError::Other(Shown::said(
        "the content was not approved, so nothing was written",
    ))
}

/// Puts a question to the person at the terminal and reads their answer: the question on the error
/// stream, the answer from standard input. `None` at the end of the input.
///
/// # Errors
///
/// Returns an error when the answer cannot be read.
pub fn ask_at_terminal(question: &Shown) -> Result<Option<String>> {
    crate::report::say(question);
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .take(4096)
        .read_line(&mut line)
        .map_err(|error| {
            CliError::Terminal(shown!(
                "your answer could not be read: {}",
                Shown::io(&error)
            ))
        })?;
    Ok((read > 0).then_some(line))
}

#[cfg(test)]
mod tests;
