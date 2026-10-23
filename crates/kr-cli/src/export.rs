//! `kr export`: one closed session's retained output, written to a file the person names.
//!
//! What a host keeps of a session is the raw terminal output its program wrote, before anything
//! decided what the bytes meant. They carry whatever the program asked a terminal to do: write the
//! clipboard, raise a notification, ask what the terminal is. An export that wrote them as they were
//! kept would hand every reader of the file a stream that does those things again to whoever
//! replays it. So the output is read through the terminal engine that read it the first time, and
//! the file carries only the spans of it the engine clears for a terminal to draw. What the engine
//! dropped is counted by what it was, and the count is in the file.
//!
//! The same code serves a session on this host and one in an enrolled environment, because both are
//! reached through a [`Link`]: the daemon that holds the archive is asked the same questions either
//! way.
//!
//! Three rules decide what is read and what is written.
//!
//! * **Privacy mode fences the read.** No session of an environment whose privacy mode is on is
//!   exported, and neither is one that still owes the cleanup privacy mode asked for. The mode is
//!   read before the first page of output and after the last, and an export during which it changed
//!   writes nothing.
//! * **Nothing is written until the whole read has passed.** The file is made new, beside its final
//!   name, and given its name without replacing anything: an existing file, or a link to one, is
//!   refused, and a failure leaves no partial file. Its mode is 0600 on Unix. On Windows it takes
//!   the access list of the folder the person named, which is theirs to choose.
//! * **The file says what it does not hold.** The archive keeps the session's last size and not the
//!   sizes before it, a piece of output may have no recorded time, and it can have lost a range;
//!   each is declared.
//!
//! The file is one JSON document, or an asciicast recording when the person asks for one. In the
//! document a position in the output and a time are written as decimal strings, as the protocol
//! writes every 64-bit value, so a reader that holds numbers as floating point does not lose their
//! last digits; output bytes are base64url text, unpadded. The recording is asciicast v2, with its
//! events at the times the output was written.

use std::path::Path;

use kr_client::session_export::{self, Bounds, Form, PageSource, Stop};
use kr_client::shown;
use kr_client::shown::{Said, Shown};
use kr_protocol::envelope::ParamsValue;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::SessionId;
use kr_protocol::method::Method;
use kr_protocol::privacy::{PrivacyReport, PrivacyStatusParams};
use kr_protocol::recovery::{
    HistoryPageParams, HistoryPageResult, HistoryTimesParams, HistoryTimesResult,
};
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::session::{SessionListParams, SessionListResult, SessionState, SessionSummary};

use crate::bridge::link::Link;
use crate::error::{CliError, Result};
use crate::resolve::SessionSelector;

/// How much retained output an export reads unless the person says otherwise.
pub const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// The most the file may hold, which is the most a backup accepts of one session. An export that
/// would pass it keeps the start of the output and says it left the rest.
pub const MAX_FILE_BYTES: u64 = kr_crypto::backup::MAX_SESSION_MEMBER_BYTES;

/// What a read of one session produced, before any file exists.
pub struct Exported {
    document: Vec<u8>,
    /// What the file holds, for the command to say.
    pub summary: Summary,
}

kr_client::debug_as_name!(Exported);

/// What an export holds, in numbers a person can read at a glance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// The session.
    pub session_id: SessionId,
    /// The number it is listed under in its environment.
    pub display_number: u64,
    /// How many bytes of retained output were read.
    pub bytes_read: u64,
    /// How many of those bytes the file carries.
    pub bytes_carried: u64,
    /// How many of the bytes carried have no recorded time.
    pub bytes_untimed: u64,
    /// How many ranges of output the archive no longer holds.
    pub gaps: usize,
    /// Whether the read stopped at a bound, the bytes read or the size of the file, with output left.
    pub truncated: bool,
    /// What the file declares it does not hold, by kind.
    pub omissions: Vec<&'static str>,
}

/// Refuses a bound of no bytes, which names nothing to read.
///
/// The command asks this before it reaches an environment, so a mistake in the arguments starts and
/// asks nothing.
///
/// # Errors
///
/// Returns a usage failure when `max_bytes` is zero.
pub fn check_bound(max_bytes: u64) -> Result<()> {
    if max_bytes == 0 {
        return Err(CliError::Usage(Shown::said(
            "--max-bytes names how much retained output to read, and an export reads at least one \
             byte",
        )));
    }
    Ok(())
}

/// Reads one closed session's retained output and composes the export of it.
///
/// Nothing is written: the file is made by [`write`] once this has passed.
///
/// # Errors
///
/// Returns `UNKNOWN_SESSION` for a session the daemon does not hold, a refusal for one that has not
/// closed or whose worker the daemon has not seen end, and a refusal naming privacy mode when it is
/// on, when the session still owes its cleanup, or when it changed during the read. Returns the
/// daemon's refusal or a transport failure otherwise.
pub async fn read<L: Link>(
    link: &mut L,
    selector: &SessionSelector,
    max_bytes: u64,
    exported_at_ms: u64,
    form: Form,
) -> Result<Exported> {
    check_bound(max_bytes)?;
    let listed: SessionListResult = ask(
        link,
        Method::SessionList,
        &SessionListParams {
            environment_id: Nullable::null(),
            include_closed: true,
        },
    )
    .await?;
    let found = listed.sessions.into_iter().find(|summary| match selector {
        SessionSelector::Display(number) => summary.display_number.get() == *number,
        SessionSelector::Identifier(session_id) => summary.session_id == *session_id,
    });
    let Some(session) = found else {
        return Err(CliError::UnknownSession(selector.said()));
    };
    if session.state != SessionState::Closed {
        return Err(CliError::Unfinished {
            code: ErrorCode::ResourceUnavailable,
            message: shown!(
                "session {} has not closed, and a session is exported after it closes: its \
                 output is read from the archive of a session that has ended",
                session.display_number.get()
            ),
        });
    }

    let before: PrivacyReport = ask(link, Method::PrivacyStatus, &PrivacyStatusParams {}).await?;
    fence(&before, &session)?;

    let composed = session_export::compose(
        &mut Pages {
            link,
            session_id: session.session_id,
        },
        &session,
        Bounds {
            max_read_bytes: max_bytes,
            max_document_bytes: MAX_FILE_BYTES,
            max_chunks: session_export::MAX_CHUNKS,
            form,
        },
        0,
        exported_at_ms,
    )
    .await
    .map_err(|stop| match stop {
        Stop::Source(error) => error,
        Stop::Engine => CliError::Other(Shown::said(
            "the terminal engine could not be made for the session's size",
        )),
        Stop::Document => CliError::Other(Shown::said(
            "the export could not be written out as a document",
        )),
        // The host's words for why are its own and are not put on a person's terminal.
        Stop::Untimed(_) => CliError::Unfinished {
            code: ErrorCode::ResourceUnavailable,
            message: shown!(
                "no recording can be made of session {}, because the host has no record of when \
                 any of its output was written; the semantic JSON export of it can be made",
                session.display_number.get()
            ),
        },
    })?;

    let after: PrivacyReport = ask(link, Method::PrivacyStatus, &PrivacyStatusParams {}).await?;
    fence(&after, &session)?;
    if after.generation != before.generation {
        return Err(CliError::Unfinished {
            code: ErrorCode::ResourceUnavailable,
            message: Shown::said(
                "privacy mode changed while the output was being read, so nothing was written; \
                 export again",
            ),
        });
    }

    Ok(Exported {
        document: composed.document,
        summary: Summary {
            session_id: session.session_id,
            display_number: session.display_number.get(),
            bytes_read: composed.bytes_read,
            bytes_carried: composed.bytes_carried,
            bytes_untimed: composed.bytes_untimed,
            gaps: composed.gaps,
            truncated: composed.truncated,
            omissions: composed.omissions,
        },
    })
}

/// Refuses a session privacy mode keeps from an export.
///
/// Privacy mode is one switch for the whole environment, so while it is on every session is private,
/// closed ones included. A session that still owes cleanup is private whatever the switch says now:
/// what its worker retained is not known to be gone.
fn fence(report: &PrivacyReport, session: &SessionSummary) -> Result<()> {
    if report.enabled {
        return Err(refused(shown!(
            "privacy mode is on in this environment, so session {} is not exported; nothing is \
             exported while it is on",
            session.display_number.get()
        )));
    }
    if report
        .sessions
        .iter()
        .any(|owing| owing.session_id == session.session_id)
    {
        return Err(refused(shown!(
            "session {} still owes the cleanup privacy mode asked for, so what it retained is not \
             exported; `kr privacy status` says where the cleanup stands",
            session.display_number.get()
        )));
    }
    Ok(())
}

fn refused(message: Shown) -> CliError {
    CliError::refused_in_its_own_words(ErrorCode::PermissionDenied, message)
}

/// The pages of one session's retained output, asked of the daemon over a link.
struct Pages<'a, L> {
    link: &'a mut L,
    session_id: SessionId,
}

impl<L: Link> PageSource for Pages<'_, L> {
    type Error = CliError;

    async fn page(&mut self, from_cursor: u64, max_bytes: u64) -> Result<HistoryPageResult> {
        page(self.link, self.session_id, from_cursor, max_bytes).await
    }

    /// Asks the daemon when the output between two cursors was written.
    ///
    /// A daemon of a release before the times were kept does not list the method, and refuses it as
    /// it refuses any method it does not list: `PERMISSION_DENIED`. A grant that has lost its right
    /// is refused with the same code. The two are told apart by asking for the same session's
    /// output once more, which asks for the same right: where that is answered, the daemon does not
    /// know the method, and its output carries no time; where it is refused too, the refusal is the
    /// daemon's own and is returned as it is. Any other refusal of this read is returned as it is.
    async fn times(&mut self, from_cursor: u64, to_cursor: u64) -> Result<HistoryTimesResult> {
        let params = HistoryTimesParams {
            session_id: self.session_id,
            from_cursor: U64::new(from_cursor),
            to_cursor: U64::new(to_cursor),
        };
        match self.link.request(Method::HistoryTimes, &params).await? {
            Err(refusal) if refusal.code == ErrorCode::PermissionDenied => {
                match page(self.link, self.session_id, from_cursor, 1).await {
                    Ok(_) => Ok(HistoryTimesResult {
                        intervals: Vec::new(),
                        next_cursor: U64::new(to_cursor),
                        complete: true,
                        unavailable: Nullable::some(
                            "the daemon of this environment is of a release that does not record \
                             when output is produced"
                                .to_owned(),
                        ),
                    }),
                    Err(_) => decode(Err(refusal)),
                }
            }
            answer => decode(answer),
        }
    }
}

/// Asks for one page of retained output.
async fn page<L: Link>(
    link: &mut L,
    session_id: SessionId,
    from_cursor: u64,
    max_bytes: u64,
) -> Result<HistoryPageResult> {
    ask(
        link,
        Method::HistoryPage,
        &HistoryPageParams {
            session_id,
            from_cursor: U64::new(from_cursor),
            max_bytes: U64::new(max_bytes),
        },
    )
    .await
}

/// Calls a read and decodes the answer as the type it should be.
async fn ask<L: Link, T: kr_protocol::wire::WireMessage>(
    link: &mut L,
    method: Method,
    params: &(impl serde::Serialize + ?Sized),
) -> Result<T> {
    let answer = link.request(method, params).await?;
    decode(answer)
}

fn decode<T: kr_protocol::wire::WireMessage>(answer: crate::bridge::link::Answer) -> Result<T> {
    let value: ParamsValue = answer.map_err(CliError::Refused)?;
    value.to_typed().map_err(|error| {
        CliError::Other(shown!(
            "the daemon's answer could not be read: {}",
            Shown::cbor(&error)
        ))
    })
}

/// Refuses an output name that is already taken, before anything is read.
///
/// [`write`] refuses it again where the file is made, which is the check that holds: a name taken
/// between the two is still refused there.
///
/// # Errors
///
/// Returns a usage failure when something, a link included, is already at `path`.
pub fn refuse_existing(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(taken(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CliError::Ipc(kr_ipc::IpcError::io("check", path, error))),
    }
}

fn taken(path: &Path) -> CliError {
    CliError::Usage(shown!(
        "{} already exists; an export never replaces a file or writes through a link, so name one \
         that is not there",
        crate::shown::named(path)
    ))
}

/// Writes the export to `path`: new, and complete or not there.
///
/// The bytes are written to a file beside it and given the name without replacing anything, so a
/// reader never finds a partial file and a name taken in the meantime is refused. The file's mode is
/// 0600 on Unix; on Windows it takes the access list of the folder it is in.
///
/// # Errors
///
/// Returns a usage failure when something is at `path`, and the failure to write otherwise. A
/// failure leaves nothing at `path`.
pub fn write(path: &Path, exported: &Exported) -> Result<()> {
    // A bare file name has no directory to flush once the file is in place, so the name is made
    // whole first: where the file goes is where the command was run.
    let whole = std::path::absolute(path)
        .map_err(|error| CliError::Ipc(kr_ipc::IpcError::io("resolve", path, error)))?;
    kr_ipc::paths::create_new_owner_only_file(&whole, &exported.document).map_err(|error| {
        match &error {
            kr_ipc::IpcError::Io { source, .. }
                if source.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                taken(path)
            }
            _ => CliError::Ipc(error),
        }
    })
}

#[cfg(test)]
mod tests;
