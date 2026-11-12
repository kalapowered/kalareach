//! A connection that was not opened means one thing to every dialer, and one function gives it.
//!
//! The host refuses a connection it cannot take with the code it also uses for a supervision, for
//! work in another session and for a resource that is short, and it refuses a connection at its
//! admission for reasons that are not its bound (an authority withdrawn since the handshake, a
//! daemon that has stopped while its listener accepts). A code or a refusal's words say nothing of
//! which of these it is, so no dialer chooses what a person reads, or what it does next, from them.
//! The cause is made in `connection::Unopened::of_link`, `Unopened::of_connection`,
//! `Unopened::of_kept_refusal` and `Unopened::of_refused_connection`, and every dialer reads the
//! cause: the host's bound (the host cannot take another connection for now), a connection refused
//! at its admission for another reason (lost, with the host's words as the reason), a refusal at the
//! handshake (the host's decision about this device) and a refusal of a request (that request's own
//! refusal).
//!
//! This reads the source of every file of the companion's native side outside its test modules, and
//! fails, naming the file, the function and the line, at each of these unless `EXCEPTIONS` lists it
//! with its reason:
//!
//! - a read of a protocol error's code that is not the code passed on as the first argument of a
//!   constructor: a comparison, a `match` or a match arm, the code as text (`as_str()`,
//!   `to_string()` or its wire name), its retry category, or any other use of `.code`;
//! - a refusal's words compared, searched or matched, from a receiver of any name (`.message`, or an
//!   error's `to_string()`), with the search on the same line or on the next;
//! - a handling of a refused connection: the link errors that carry a host's refusal of a
//!   connection (`LinkError::Refused`, `LinkError::ConnectionRefused`) and the cause that names it
//!   (`Asked::Connection`), which only the functions above handle;
//! - the client's accessor of the refusal that a connection kept (`connection_refusal(`), which is
//!   asked for in `connection.rs` and nowhere else. No exception excuses it.
//!
//! An exception names one file, one function, one needle and how many lines of that function it
//! excuses, and says why. It ends where its function ends: a line stands in the function whose
//! braces hold it. Where a file holds two functions of one name the exception names the type of the
//! `impl` too (`Type::name`, and `(free)::name` for a function that is in no `impl`). A line that is
//! not excused, an exception that excuses more or fewer lines than it names, and one that excuses
//! none, each fail the case. Comments (line, doc and block) and the contents of string and character
//! literals are not read as code; only a code's wire name is looked for in a literal. The rule has
//! cases of its own: the forms that must fail, and the honest forms that must pass.
//!
//! **What a rule over source text cannot see**, and does not try to:
//!
//! - a code that is read under another name or after a `use` that renames or imports the variants
//!   (`use ErrorCode as Code`, `use ErrorCode::*`), or that is handed to a function through a
//!   variable (`transient(code)`), so that the text names neither `.code` nor `ErrorCode::`;
//! - words passed on through a variable (`let words = &refusal.message; words.contains(..)`);
//! - a variant that is imported without its type's name. This arm cannot be written either:
//!   `ConnectionRefused(refusal) => Unopened::NotAdmitted(refusal.into())`, because
//!   `Unopened::NotAdmitted` holds the host's words (`connection::HostWords`) and no conversion from
//!   a refusal into them exists, so only `Unopened::of_refused_connection` makes that cause, and the
//!   compiler, not this rule, keeps it so.
//!
//! A reading of these forms is found by review of the change that adds it, and by the compiler where
//! the cause's types forbid it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_protocol::error::ErrorCode;

/// The file that makes the cause, the type whose functions in it read a host's refusal of a
/// connection so that no other place does, and those functions.
const HOME: (&str, &str, [&str; 5]) = (
    "connection.rs",
    "Unopened",
    [
        "of_link",
        "of_connection",
        "of_kept_refusal",
        "of_refused_connection",
        "refusal_kept_by",
    ],
);

const COMPARED: &str = "a code compared";
const MATCHED: &str = "a code matched";
const USED: &str = "a use of .code";
const AS_TEXT: &str = "a code as text";
const CATEGORY: &str = "a code's retry category";
const WORDS: &str = "words compared or searched";

/// The client's accessor of the refusal that a connection kept. It is asked for in `HOME`'s file
/// and nowhere else, and no exception excuses it.
const ACCESSOR: &str = "connection_refusal(";

/// The handling of a refused connection that only the functions of `HOME` do, each its own needle.
const HANDLING: [&str; 5] = [
    "LinkError::Refused",
    "LinkError::ConnectionRefused",
    "Asked::Connection",
    "of_refused_connection(",
    "of_kept_refusal(",
];

/// What searches or compares words when it follows an error's `.message`.
const WORD_READS: [&str; 10] = [
    "==",
    "!=",
    ".contains(",
    ".starts_with(",
    ".ends_with(",
    ".find(",
    ".matches(",
    ".as_str()",
    ".to_lowercase(",
    ".eq(",
];

/// What searches or compares an error's text when it follows `.to_string()`.
const TEXT_READS: [&str; 5] = [".contains(", ".starts_with(", ".ends_with(", "==", "!="];

/// A read of a code or of words, or a handling of a refused connection, that the rule objects to.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Hit {
    file: String,
    /// The function the line stands in, or none outside any function.
    function: String,
    /// The type of the `impl` the function stands in, or none.
    owner: String,
    /// Whether another function of the file has the same name in another `impl`, so that an
    /// exception names the type too (`Type::name`).
    shared: bool,
    needle: &'static str,
    line: usize,
    text: String,
}

/// A place that reads a code or words, or handles a refused connection, and may: the file, the
/// function, the needle, how many of its lines, and why it is no choice of what a person reads or
/// of what a dialer does about a connection that was not opened.
struct Exception {
    file: &'static str,
    function: &'static str,
    needle: &'static str,
    lines: usize,
    reason: &'static str,
}

/// Every place outside `HOME` that reads a code or words or handles a refused connection, and why it
/// does not decide what a connection that was not opened means.
const EXCEPTIONS: [Exception; 61] = [
    Exception {
        file: "account/mod.rs",
        function: "usage",
        needle: COMPARED,
        lines: 1,
        reason: "the refusal of the account usage request, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "agent.rs",
        function: "agents",
        needle: COMPARED,
        lines: 2,
        reason: "the refusal of the agents read, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "agent.rs",
        function: "lets_the_snapshot_go",
        needle: COMPARED,
        lines: 1,
        reason: "the refusal of a snapshot read that asks for a resync, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "commands.rs",
        function: "voice_allow",
        needle: WORDS,
        lines: 1,
        reason: "compares the text of an environment identifier with another's; it reads no refusal's words",
    },
    Exception {
        file: "settings/drafts.rs",
        function: "keep_copies_listed",
        needle: WORDS,
        lines: 1,
        reason: "compares the text of a draft's identifier with a listed one; it reads no refusal's words",
    },
    Exception {
        file: "settings/drafts.rs",
        function: "proven_host",
        needle: WORDS,
        lines: 1,
        reason: "compares the text of a session identifier with a record's; it reads no refusal's words",
    },
    Exception {
        file: "settings/sync/members.rs",
        function: "join_in_a_step",
        needle: WORDS,
        lines: 1,
        reason: "compares the text of a collection identifier with a reference; it reads no refusal's words",
    },
    Exception {
        file: "connection.rs",
        function: "for_now",
        needle: USED,
        lines: 1,
        reason: "whether a refusal of a request is for now, for the callers that wait; a connection that was not opened says it through its cause",
    },
    Exception {
        file: "connection.rs",
        function: "open",
        needle: "Asked::Connection",
        lines: 1,
        reason: "this device ended the connection for the account's sake before the host was asked anything, and the words are the account's; no refusal of the host's is read",
    },
    Exception {
        file: "connection.rs",
        function: "opening_refused",
        needle: COMPARED,
        lines: 1,
        reason: "a refusal of the request that opens the connection for the host alone: a host of an earlier build refuses an unlisted method with the transport's own constant, and only that refusal is told to be updated",
    },
    Exception {
        file: "connection.rs",
        function: "opening_refused",
        needle: WORDS,
        lines: 1,
        reason: "a refusal of the request that opens the connection for the host alone: a host of an earlier build refuses an unlisted method with the transport's own constant, and only that refusal is told to be updated",
    },
    Exception {
        file: "device/mod.rs",
        function: "start_held",
        needle: USED,
        lines: 1,
        reason: "the pairing code's own text, which is no protocol error's code",
    },
    Exception {
        file: "device_probe.rs",
        function: "after_unlocking",
        needle: WORDS,
        lines: 1,
        reason: "the probe's own check that this device's store says it is locked, which is no refusal of a host",
    },
    Exception {
        file: "error.rs",
        function: "fmt",
        needle: AS_TEXT,
        lines: 1,
        reason: "prints the code's name before the words of the error it belongs to; it chooses nothing from it",
    },
    Exception {
        file: "error.rs",
        function: "from",
        needle: CATEGORY,
        lines: 1,
        reason: "gives a command error the retry hint of the code it carries; it chooses no words",
    },
    Exception {
        file: "error.rs",
        function: "from",
        needle: USED,
        lines: 1,
        reason: "gives a command error the retry hint of the code it carries; it chooses no words",
    },
    Exception {
        file: "error.rs",
        function: "new",
        needle: CATEGORY,
        lines: 1,
        reason: "gives a command error the retry hint of the code it is made with; it chooses no words",
    },
    Exception {
        file: "error.rs",
        function: "stated",
        needle: CATEGORY,
        lines: 1,
        reason: "gives a command error the retry hint of the code it is made with; it chooses no words",
    },
    Exception {
        file: "inbox.rs",
        function: "Missed::from",
        needle: "Asked::Connection",
        lines: 1,
        reason: "tells the causes that are no refusal of a request, the host's bound and this computer's budget, as the visit's refusal in their own words; it reads no code",
    },
    Exception {
        file: "inbox.rs",
        function: "pages",
        needle: COMPARED,
        lines: 1,
        reason: "the refusal of an inbox page, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "inbox.rs",
        function: "present",
        needle: "Asked::Connection",
        lines: 1,
        reason: "names the visit's refusal as that of the connection; it chooses no words",
    },
    Exception {
        file: "inbox.rs",
        function: "present",
        needle: "LinkError::Refused",
        lines: 1,
        reason: "a refusal at the handshake is the host's decision about this device, and is the visit's refusal with its words, as before a host's refusal of a connection was read",
    },
    Exception {
        file: "inbox.rs",
        function: "read_host",
        needle: "Asked::Connection",
        lines: 1,
        reason: "this device ended the connection for the account's sake, and the words are the account's",
    },
    Exception {
        file: "inbox.rs",
        function: "read_kept",
        needle: USED,
        lines: 1,
        reason: "decides whether to present the lease again over a connection that is open; it chooses no words",
    },
    Exception {
        file: "mailbox.rs",
        function: "service_stopped",
        needle: MATCHED,
        lines: 2,
        reason: "the refusal of a request to the sync service, which says whether the service is stopped; the service is no paired host",
    },
    Exception {
        file: "push.rs",
        function: "gateway_words",
        needle: MATCHED,
        lines: 4,
        reason: "the push gateway's own answer to a registration, told in the gateway's words; the gateway is no paired host",
    },
    Exception {
        file: "questions.rs",
        function: "link",
        needle: COMPARED,
        lines: 1,
        reason: "the refusal of a question request, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "questions.rs",
        function: "link",
        needle: MATCHED,
        lines: 1,
        reason: "the refusal of a question request, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "questions.rs",
        function: "link",
        needle: USED,
        lines: 1,
        reason: "the refusal of a question request, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "questions.rs",
        function: "send",
        needle: MATCHED,
        lines: 1,
        reason: "the refusal of an answer to a question, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "questions.rs",
        function: "send",
        needle: USED,
        lines: 1,
        reason: "the refusal of an answer to a question, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "questions.rs",
        function: "session_ended",
        needle: COMPARED,
        lines: 2,
        reason: "the refusal of a read of a session's questions, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "questions.rs",
        function: "(free)::settle",
        needle: COMPARED,
        lines: 1,
        reason: "the refusal of a read of a session's questions, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "revocation.rs",
        function: "nothing_was_stored",
        needle: AS_TEXT,
        lines: 1,
        reason: "tells from a revocation request's own outcome code whether the revocation was stored; it reads no connection's refusal",
    },
    Exception {
        file: "revocation.rs",
        function: "revoke",
        needle: WORDS,
        lines: 1,
        reason: "ends the host's own words with a full stop before this computer's words follow; it chooses no words from them",
    },
    Exception {
        file: "settings/connected.rs",
        function: "holds",
        needle: MATCHED,
        lines: 3,
        reason: "the refusal of the session read that a draft check asks, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "settings/connected.rs",
        function: "listing_of",
        needle: USED,
        lines: 1,
        reason: "the code of a refusal of the device list request itself, which is the host's answer about its devices; a refusal of the connection is told by its cause before this",
    },
    Exception {
        file: "settings/connected.rs",
        function: "of_link",
        needle: "LinkError::Refused",
        lines: 1,
        reason: "a refusal at the handshake is the host's decision about this device, answered by its code about listing as on main: only a refusal to list the host's devices to this computer is an answer about them; it reads no refusal of a connection that was admitted",
    },
    Exception {
        file: "settings/connected.rs",
        function: "of_link",
        needle: USED,
        lines: 1,
        reason: "a refusal at the handshake is the host's decision about this device, answered by its code about listing as on main: only a refusal to list the host's devices to this computer is an answer about them; it reads no refusal of a connection that was admitted",
    },
    Exception {
        file: "settings/connected.rs",
        function: "of_refusal",
        needle: COMPARED,
        lines: 1,
        reason: "reads the code of a refusal of the device list request: only the refusal to list the host's devices to this computer is an answer about them",
    },
    Exception {
        file: "settings/sync.rs",
        function: "agree",
        needle: COMPARED,
        lines: 4,
        reason: "the refusal of a settings sync request, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "settings/sync.rs",
        function: "finish_reseal",
        needle: COMPARED,
        lines: 1,
        reason: "the refusal of a settings sync request, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "settings/sync.rs",
        function: "publish_change",
        needle: COMPARED,
        lines: 1,
        reason: "the refusal of a settings sync request, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "settings/sync.rs",
        function: "sync_failure",
        needle: CATEGORY,
        lines: 1,
        reason: "carries the code and the retry hint of a settings sync failure to the page; it chooses no words",
    },
    Exception {
        file: "settings/sync.rs",
        function: "sync_failure",
        needle: USED,
        lines: 1,
        reason: "carries the code and the retry hint of a settings sync failure to the page; it chooses no words",
    },
    Exception {
        file: "settings/sync/fence.rs",
        function: "raise",
        needle: WORDS,
        lines: 1,
        reason: "ends the host's own words with a full stop before this computer's words follow; it chooses no words from them",
    },
    Exception {
        file: "standing.rs",
        function: "keep",
        needle: USED,
        lines: 4,
        reason: "decides whether a refusal of the opening's request or at the handshake is told only once a second ask agrees, and carries its code to the next ask; the words a refusal ends with are the host's own",
    },
    Exception {
        file: "standing.rs",
        function: "recheck",
        needle: USED,
        lines: 4,
        reason: "decides whether a refusal of the request on an open link is told only once a second ask agrees, and carries its code to the next ask; the words a refusal ends with are the host's own",
    },
    Exception {
        file: "standing.rs",
        function: "transient",
        needle: COMPARED,
        lines: 1,
        reason: "the reading of the code of a refusal of a request as for now, whose callers decide whether an opening waits",
    },
    Exception {
        file: "standing.rs",
        function: "transient",
        needle: CATEGORY,
        lines: 1,
        reason: "the reading of the code of a refusal of a request as for now, whose callers decide whether an opening waits",
    },
    Exception {
        file: "terminal/input.rs",
        function: "answered",
        needle: COMPARED,
        lines: 1,
        reason: "the refusal of an input lease request, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "terminal/input.rs",
        function: "ended_by",
        needle: COMPARED,
        lines: 1,
        reason: "the refusal of an input lease request, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "terminal/input.rs",
        function: "refused_take",
        needle: COMPARED,
        lines: 1,
        reason: "the refusal of an input lease request, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "terminal/view.rs",
        function: "launch_read_step",
        needle: COMPARED,
        lines: 2,
        reason: "the refusal of the launch surface read, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "terminal/view.rs",
        function: "launch_read_step",
        needle: MATCHED,
        lines: 1,
        reason: "the refusal of the launch surface read, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "terminal/view.rs",
        function: "launch_read_step",
        needle: USED,
        lines: 1,
        reason: "the refusal of the launch surface read, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "terminal/view.rs",
        function: "open_paired",
        needle: "of_kept_refusal(",
        lines: 1,
        reason: "hands the refusal that the view's wire kept to the one function that tells a refusal of a connection from a refusal of a request",
    },
    Exception {
        file: "terminal/view.rs",
        function: "response",
        needle: USED,
        lines: 1,
        reason: "the refusal of a request of the view, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "voice/host.rs",
        function: "revoke",
        needle: COMPARED,
        lines: 1,
        reason: "the refusal of the revocation of a voice session, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
    Exception {
        file: "voice/owner.rs",
        function: "plain_words",
        needle: AS_TEXT,
        lines: 1,
        reason: "strips the code's name that a host's message begins with, so that a person reads the words; it chooses nothing from the code",
    },
    Exception {
        file: "voice/owner.rs",
        function: "pre_check",
        needle: COMPARED,
        lines: 1,
        reason: "the refusal of the voice pre-check, answered on a connection that is open; it decides nothing about a connection that was not opened",
    },
];

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every source file under `directory`, as its path relative to `root` and its text.
fn sources(root: &Path, directory: &Path, found: &mut Vec<(String, String)>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(directory)
        .expect("the source can be listed")
        .map(|entry| entry.expect("an entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            sources(root, &path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let name = path
                .strip_prefix(root)
                .expect("under the source")
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{name} could not be read: {error}"));
            found.push((name, text));
        }
    }
}

/// One line of the product's source, as the rule reads it.
struct Line {
    number: usize,
    /// The line without its comments and without the contents of its string and character literals.
    code: String,
    /// The line without its comments and with its literals, where a code's wire name is looked for.
    text: String,
}

/// Where the quoted text that starts at `start` (a `quote`) ends: the index after its closing quote.
fn after_quoted(chars: &[char], start: usize, quote: char) -> usize {
    let mut at = start + 1;
    while at < chars.len() {
        match chars[at] {
            '\\' => at += 2,
            character if character == quote => return at + 1,
            _ => at += 1,
        }
    }
    chars.len()
}

/// `text` without its comments (line, doc and block comments, the block ones nested) and, unless
/// `keep_literals`, without the contents of its string and character literals, with every line
/// break kept so that the numbers of the lines stay.
fn stripped(text: &str, keep_literals: bool) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while at < chars.len() {
        let next = chars.get(at + 1).copied();
        match (chars[at], next) {
            ('/', Some('/')) => {
                while at < chars.len() && chars[at] != '\n' {
                    at += 1;
                }
            }
            ('/', Some('*')) => {
                let mut depth = 0_usize;
                while at < chars.len() {
                    match (chars[at], chars.get(at + 1).copied()) {
                        ('/', Some('*')) => {
                            depth += 1;
                            at += 2;
                        }
                        ('*', Some('/')) => {
                            depth -= 1;
                            at += 2;
                            if depth == 0 {
                                break;
                            }
                        }
                        ('\n', _) => {
                            out.push('\n');
                            at += 1;
                        }
                        _ => at += 1,
                    }
                }
                out.push(' ');
            }
            ('r', Some('"' | '#'))
                if !at
                    .checked_sub(1)
                    .is_some_and(|before| is_word(chars[before])) =>
            {
                let hashes = chars[at + 1..].iter().take_while(|c| **c == '#').count();
                if chars.get(at + 1 + hashes) != Some(&'"') {
                    out.push('r');
                    at += 1;
                    continue;
                }
                let body = at + 2 + hashes;
                let closing: Vec<char> = std::iter::once('"')
                    .chain(std::iter::repeat_n('#', hashes))
                    .collect();
                let end = (body..chars.len())
                    .find(|from| chars[*from..].starts_with(&closing))
                    .map_or(chars.len(), |from| from + closing.len());
                let literal: String = chars[at..end].iter().collect();
                if keep_literals {
                    out.push_str(&literal);
                } else {
                    out.push_str("\"\"");
                    out.extend(literal.chars().filter(|c| *c == '\n'));
                }
                at = end;
            }
            ('"', _) => {
                let end = after_quoted(&chars, at, '"');
                let literal: String = chars[at..end.min(chars.len())].iter().collect();
                if keep_literals {
                    out.push_str(&literal);
                } else {
                    out.push_str("\"\"");
                    out.extend(literal.chars().filter(|c| *c == '\n'));
                }
                at = end;
            }
            ('\'', _) => {
                // A character literal, or the start of a lifetime.
                let end = match (next, chars.get(at + 2).copied()) {
                    (Some('\\'), _) => Some(after_quoted(&chars, at, '\'')),
                    (Some(_), Some('\'')) => Some(at + 3),
                    _ => None,
                };
                match end {
                    Some(end) => {
                        let literal: String = chars[at..end.min(chars.len())].iter().collect();
                        out.push_str(if keep_literals { &literal } else { "' '" });
                        at = end;
                    }
                    None => {
                        out.push('\'');
                        at += 1;
                    }
                }
            }
            (character, _) => {
                out.push(character);
                at += 1;
            }
        }
    }
    out
}

/// The lines of `text` that the product runs, with their numbers, without their comments, and
/// without the contents of their string literals. A test module (`#[cfg(test)]` on a `mod`, closed
/// by a `}` in the first column) is left out wherever it stands, and a `#[cfg(test)]` on anything
/// else leaves the scan where it is.
fn code_lines(text: &str) -> Vec<Line> {
    let code: Vec<String> = stripped(text, false).lines().map(str::to_owned).collect();
    let literal: Vec<String> = stripped(text, true).lines().map(str::to_owned).collect();
    let mut kept = Vec::new();
    let mut index = 0;
    while index < code.len() {
        let line = &code[index];
        if line.trim_end() == "#[cfg(test)]" {
            let mut item = index + 1;
            while code
                .get(item)
                .is_some_and(|next| next.trim_start().starts_with("#["))
            {
                item += 1;
            }
            let is_module = code.get(item).is_some_and(|next| {
                next.trim_start_matches("pub ").starts_with("mod ")
                    && next.trim_end().ends_with('{')
            });
            if is_module {
                while item < code.len() && code[item].trim_end() != "}" {
                    item += 1;
                }
                index = item + 1;
            } else {
                index += 1;
            }
            continue;
        }
        index += 1;
        if !line.trim().is_empty() {
            kept.push(Line {
                number: index,
                code: line.clone(),
                text: literal.get(index - 1).cloned().unwrap_or_default(),
            });
        }
    }
    kept
}

/// The name of the function a line declares, if it declares one.
fn function_named(line: &str) -> Option<String> {
    let mut rest = line.trim_start();
    loop {
        let before = rest;
        // A visibility that names a path: `pub(in crate::settings) `.
        if let Some(path) = rest.strip_prefix("pub(in ")
            && let Some((_, after)) = path.split_once(") ")
        {
            rest = after;
        }
        for prefix in [
            "pub(crate) ",
            "pub(super) ",
            "pub ",
            "const ",
            "async ",
            "unsafe ",
        ] {
            rest = rest.strip_prefix(prefix).unwrap_or(rest);
        }
        if rest == before {
            break;
        }
    }
    let name: String = rest
        .strip_prefix("fn ")?
        .chars()
        .take_while(|character| character.is_alphanumeric() || *character == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

fn is_word(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// The places in `line` where `field` (`.code`, `.message`) is read as a field or as a method
/// without arguments, as the start of the receiver's expression and the end of the field.
fn fields(line: &str, field: &str) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(offset) = line[from..].find(field) {
        let at = from + offset;
        let mut end = at + field.len();
        from = end;
        // A field has a receiver before its dot, and its name ends there.
        let has_receiver = line[..at]
            .chars()
            .next_back()
            .is_some_and(|before| is_word(before) || before == ')');
        if !has_receiver || line[end..].chars().next().is_some_and(is_word) {
            continue;
        }
        if line[end..].starts_with("()") {
            end += 2;
        }
        let start = receiver_start(&line[..at], '.');
        found.push((start, end));
    }
    found
}

/// Where the expression that ends `text` begins: the run of words, and of `joiner`, at its end.
fn receiver_start(text: &str, joiner: char) -> usize {
    text.char_indices()
        .rev()
        .find(|(_, character)| !(is_word(*character) || *character == joiner))
        .map_or(0, |(index, character)| index + character.len_utf8())
}

/// The places in `line` where a variant of `ErrorCode` is named, as the start of its path and the
/// end of its name.
fn variants(line: &str) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(offset) = line[from..].find("ErrorCode::") {
        let at = from + offset;
        let name = at + "ErrorCode::".len();
        let end = name
            + line[name..]
                .find(|character: char| !is_word(character))
                .unwrap_or(line.len() - name);
        from = end;
        let start = receiver_start(&line[..at], ':');
        found.push((start, end));
    }
    found
}

/// Whether a token that starts at `start` is the code passed on as the first argument of a
/// constructor, which reads no error: it follows `new(` or `stated(` on this line, or alone on its
/// line after one, and a comma follows it.
fn is_passed_on(line: &str, previous: &str, start: usize, end: usize) -> bool {
    let before = line[..start].trim_end();
    let opened = before.ends_with("new(")
        || before.ends_with("stated(")
        || (before.is_empty()
            && (previous.trim_end().ends_with("new(") || previous.trim_end().ends_with("stated(")));
    opened && line[end..].trim_start().starts_with(',')
}

/// What follows a field or a call on `line`, read through the end of the line: the rest of the line,
/// and the start of the next one when the rest is empty, so a search that stands on the next line
/// counts.
fn continued<'a>(rest: &'a str, next: &'a str) -> &'a str {
    let rest = rest.trim_start();
    if rest.is_empty() {
        next.trim_start()
    } else {
        rest
    }
}

/// What `line` reads of a code or of words, or handles of a refused connection. `code` is the line
/// without its comments and literals, `text` the line with its literals (where a code's wire name
/// stands), `previous` and `next` the lines around it.
fn needles(code: &str, text: &str, previous: &str, next: &str) -> Vec<&'static str> {
    let line = code;
    let mut found: Vec<&'static str> = Vec::new();
    let mut note = |needle: &'static str| {
        if !found.contains(&needle) {
            found.push(needle);
        }
    };
    for (start, end) in fields(line, ".code") {
        if is_passed_on(line, previous, start, end) {
            continue;
        }
        let (before, after) = (line[..start].trim_end(), line[end..].trim_start());
        if before.ends_with("==")
            || before.ends_with("!=")
            || after.starts_with("==")
            || after.starts_with("!=")
        {
            note(COMPARED);
        } else if before.ends_with("match")
            || after.starts_with('{')
            || (line.contains("matches!(") && after.starts_with(','))
        {
            note(MATCHED);
        } else if after.starts_with(".as_str()") || after.starts_with(".to_string()") {
            note(AS_TEXT);
        } else if after.starts_with(".retry_category(") {
            note(CATEGORY);
        } else {
            note(USED);
        }
    }
    for (start, end) in variants(line) {
        if is_passed_on(line, previous, start, end) {
            continue;
        }
        let (before, after) = (line[..start].trim_end(), line[end..].trim_start());
        if before.ends_with("==")
            || before.ends_with("!=")
            || after.starts_with("==")
            || after.starts_with("!=")
        {
            note(COMPARED);
        } else if after.starts_with("=>")
            || (after.starts_with('|') && !after.starts_with("||"))
            || after.starts_with("if ")
        {
            note(MATCHED);
        }
    }
    if line.contains("code.as_str()") || line.contains("code.to_string()") {
        note(AS_TEXT);
    }
    if line.contains("retry_category(") {
        note(CATEGORY);
    }
    if ErrorCode::ALL
        .iter()
        .any(|code| text.contains(&format!("\"{}\"", code.as_str())))
    {
        note(AS_TEXT);
    }
    // Words, from a receiver of any name: a refusal's `.message`, compared, searched or matched, on
    // this line or with the search on the next.
    for (start, end) in fields(line, ".message") {
        let before = line[..start].trim_end();
        let after = continued(&line[end..], next);
        if before.ends_with("==")
            || before.ends_with("!=")
            || before.ends_with("match")
            || after.starts_with('{')
            || (line.contains("matches!(") && after.starts_with(','))
            || WORD_READS.iter().any(|read| after.starts_with(read))
        {
            note(WORDS);
        }
    }
    // An error's own text, searched or compared, from a receiver of any name.
    let mut from = 0;
    while let Some(offset) = line[from..].find(".to_string()") {
        let at = from + offset;
        let end = at + ".to_string()".len();
        from = end;
        let before = line[..receiver_start(&line[..at], '.')].trim_end();
        let after = continued(&line[end..], next);
        if TEXT_READS.iter().any(|read| after.starts_with(read))
            || before.ends_with("==")
            || before.ends_with("!=")
            || before.ends_with("match")
        {
            note(WORDS);
        }
    }
    if line.contains(ACCESSOR) {
        note(ACCESSOR);
    }
    for needle in HANDLING {
        if line.contains(needle) {
            note(needle);
        }
    }
    found
}

/// What a pair of braces holds that gives a line its function and its `impl`.
enum Scope {
    Impl(String),
    Function(String),
}

/// The type an `impl` header on `line` is for, when it is one.
fn impl_type(line: &str) -> Option<String> {
    let rest = line.trim_start().strip_prefix("impl")?;
    if !rest.starts_with(|character: char| character == '<' || character.is_whitespace()) {
        return None;
    }
    let mut rest = rest.trim_start();
    if rest.starts_with('<') {
        let mut depth = 0_usize;
        let end = rest.char_indices().find_map(|(index, character)| {
            match character {
                '<' => depth += 1,
                '>' => depth -= 1,
                _ => {}
            }
            (depth == 0).then_some(index + 1)
        })?;
        rest = rest[end..].trim_start();
    }
    let target = rest.split_once(" for ").map_or(rest, |(_, target)| target);
    let path: String = target
        .trim_start()
        .chars()
        .take_while(|character| is_word(*character) || *character == ':')
        .collect();
    path.rsplit("::")
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

/// Every read of a code or of words, and every handling of a refused connection, that `text` holds
/// outside its test modules, outside the functions that are `HOME`'s when `file` is. A line stands
/// in the function whose braces hold it, and no longer: where a function ends its exceptions end.
fn scan(file: &str, text: &str) -> Vec<Hit> {
    let lines = code_lines(text);
    let mut hits = Vec::new();
    let mut declared: Vec<(String, String)> = Vec::new();
    let mut scopes: Vec<(Scope, i32)> = Vec::new();
    let mut pending: Option<Scope> = None;
    let (mut depth, mut parens) = (0_i32, 0_i32);
    let owner_in = |scopes: &[(Scope, i32)]| {
        scopes
            .iter()
            .rev()
            .find_map(|(scope, _)| match scope {
                Scope::Impl(owner) => Some(owner.clone()),
                Scope::Function(_) => None,
            })
            .unwrap_or_default()
    };
    let function_in = |scopes: &[(Scope, i32)]| {
        scopes
            .iter()
            .rev()
            .find_map(|(scope, _)| match scope {
                Scope::Function(name) => Some(name.clone()),
                Scope::Impl(_) => None,
            })
            .unwrap_or_default()
    };
    let mut previous = "";
    for (position, line) in lines.iter().enumerate() {
        if let Some(name) = function_named(&line.code) {
            declared.push((owner_in(&scopes), name.clone()));
            pending = Some(Scope::Function(name));
            parens = 0;
        } else if pending.is_none()
            && let Some(owner) = impl_type(&line.code)
        {
            pending = Some(Scope::Impl(owner));
            parens = 0;
        }
        let mut function = match &pending {
            Some(Scope::Function(name)) => name.clone(),
            _ => function_in(&scopes),
        };
        let mut owner = owner_in(&scopes);
        for character in line.code.chars() {
            match character {
                '(' | '[' => parens += 1,
                ')' | ']' => parens -= 1,
                ';' if parens <= 0 => pending = None,
                '{' => {
                    depth += 1;
                    if let Some(scope) = pending.take() {
                        scopes.push((scope, depth));
                        function = function_in(&scopes);
                        owner = owner_in(&scopes);
                    }
                }
                '}' => {
                    if scopes.last().is_some_and(|(_, inside)| *inside == depth) {
                        scopes.pop();
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        let next = lines
            .get(position + 1)
            .map_or("", |next| next.code.as_str());
        for needle in needles(&line.code, &line.text, previous, next) {
            hits.push(Hit {
                file: file.to_owned(),
                function: function.clone(),
                owner: owner.clone(),
                shared: false,
                needle,
                line: line.number,
                text: line.code.trim().to_owned(),
            });
        }
        previous = &line.code;
    }
    for hit in &mut hits {
        let mut owners: Vec<&String> = declared
            .iter()
            .filter(|(_, name)| *name == hit.function)
            .map(|(owner, _)| owner)
            .collect();
        owners.sort();
        owners.dedup();
        hit.shared = owners.len() > 1;
    }
    hits.retain(|hit| {
        let home = hit.file == HOME.0;
        !(home && hit.owner == HOME.1 && HOME.2.contains(&hit.function.as_str()))
            && !(home && hit.needle == ACCESSOR)
    });
    hits
}

/// The name an exception gives a hit's function: the bare name, and the type too where the file
/// holds two functions of that name.
fn named_function(hit: &Hit) -> String {
    if hit.shared && hit.owner.is_empty() {
        format!("(free)::{}", hit.function)
    } else if hit.shared {
        format!("{}::{}", hit.owner, hit.function)
    } else {
        hit.function.clone()
    }
}

/// What is wrong with `hits` against `exceptions`: a place that no exception excuses, an exception
/// that excuses a different number of lines than the place has, and an exception that matches none.
fn problems(hits: &[Hit], exceptions: &[Exception]) -> Vec<String> {
    let mut places: BTreeMap<(&str, String, &str), Vec<&Hit>> = BTreeMap::new();
    for hit in hits {
        places
            .entry((&hit.file, named_function(hit), hit.needle))
            .or_default()
            .push(hit);
    }
    let mut found = Vec::new();
    for ((file, function, needle), lines) in &places {
        let excuse = exceptions.iter().find(|exception| {
            (exception.file, exception.function, exception.needle)
                == (*file, function.as_str(), *needle)
                && *needle != ACCESSOR
        });
        let shown = lines
            .iter()
            .map(|hit| format!("{}: {}", hit.line, hit.text))
            .collect::<Vec<_>>()
            .join("; ");
        match excuse {
            None => found.push(format!("{file} `{function}` {needle}: {shown}")),
            Some(exception) if exception.lines != lines.len() => found.push(format!(
                "{file} `{function}` {needle}: the exception excuses {} lines and the function has {}: {shown}",
                exception.lines,
                lines.len()
            )),
            Some(_) => {}
        }
    }
    for exception in exceptions {
        if !places.contains_key(&(
            exception.file,
            exception.function.to_owned(),
            exception.needle,
        )) {
            found.push(format!(
                "{} `{}` {}: the exception matches no line ({})",
                exception.file, exception.function, exception.needle, exception.reason
            ));
        }
    }
    found
}

/// KR-REQ-19.08: no file of the companion's native side reads a code or words, or handles a refused
/// connection, outside the functions that give a connection that was not opened its cause, except
/// the places `EXCEPTIONS` lists.
#[test]
fn no_source_file_reads_a_refusal_to_decide_what_a_connection_that_was_not_opened_means() {
    let root = source();
    let mut files = Vec::new();
    sources(&root, &root, &mut files);
    let hits: Vec<Hit> = files
        .iter()
        .flat_map(|(name, text)| scan(name, text))
        .collect();
    let wrong = problems(&hits, &EXCEPTIONS);
    assert!(
        wrong.is_empty(),
        "a connection that was not opened is told from its cause (`connection::Unopened`), and \
         these places read a code or words, or handle a refused connection, instead:\n{}",
        wrong.join("\n")
    );
}

/// KR-REQ-19.08: the rule reads every source file, and the functions that it leaves out of its
/// reading are the ones that make the cause.
#[test]
fn the_rule_reads_every_source_file_and_leaves_out_only_the_functions_that_make_the_cause() {
    let root = source();
    let mut files = Vec::new();
    sources(&root, &root, &mut files);
    let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
    for expected in [
        "connection.rs",
        "error.rs",
        "lease.rs",
        "settings/connected.rs",
        "standing.rs",
        "terminal/view.rs",
        "terminal/wire.rs",
        "voice/owner.rs",
    ] {
        assert!(names.contains(&expected), "{expected} is read");
    }
    assert!(files.len() > 60, "{} files are read", files.len());
    let (_, home) = files
        .iter()
        .find(|(name, _)| name == HOME.0)
        .expect("the file that makes the cause");
    let declared: Vec<String> = code_lines(home)
        .iter()
        .filter_map(|line| function_named(&line.code))
        .collect();
    for function in HOME.2 {
        assert!(
            declared.iter().any(|name| name == function),
            "{function} makes the cause in {}",
            HOME.0
        );
    }
}

/// What a snippet reads, as the needles of the places it holds.
fn read_by(snippet: &str) -> Vec<&'static str> {
    let mut found: Vec<&'static str> = scan("snippet.rs", snippet)
        .iter()
        .map(|hit| hit.needle)
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

/// KR-REQ-19.08: each form that chooses what a person reads, or what a dialer does, from a code or
/// from words, or handles a refused connection, is found, wherever the snippet stands.
#[test]
fn the_forms_that_read_a_refusal_fail_the_rule() {
    let fails = [
        (
            "fn a(refusal: Refusal) -> bool { refusal.code == ErrorCode::PermissionDenied }",
            COMPARED,
        ),
        (
            "fn a(refusal: Refusal) -> bool { ErrorCode::PermissionDenied != refusal.code }",
            COMPARED,
        ),
        (
            "fn a(refusal: Refusal) -> bool {\n    match refusal.code {\n        _ => true,\n    }\n}",
            MATCHED,
        ),
        (
            "fn a(code: ErrorCode) -> Words {\n    match code {\n        ErrorCode::ResourceUnavailable => Words::new(\"full\"),\n        _ => Words::new(\"no\"),\n    }\n}",
            MATCHED,
        ),
        (
            "fn a(refusal: Refusal) -> bool { matches!(refusal.code, ErrorCode::HostNotConfigured) }",
            MATCHED,
        ),
        (
            "fn a(refusal: Refusal) -> bool { refusal.code.as_str() == \"RESOURCE_UNAVAILABLE\" }",
            AS_TEXT,
        ),
        (
            "fn a(refusal: Refusal) -> String { refusal.code.to_string() }",
            AS_TEXT,
        ),
        (
            "fn a(code: ErrorCode) -> String { code.as_str().to_owned() }",
            AS_TEXT,
        ),
        ("const FULL: &str = \"RESOURCE_UNAVAILABLE\";", AS_TEXT),
        (
            "fn a(refusal: Refusal) -> bool { refusal.code.retry_category() == RetryCategory::Transient }",
            CATEGORY,
        ),
        (
            "fn a(refusal: Refusal) -> Listing { Listing::of_refusal(refusal.code) }",
            USED,
        ),
        (
            "fn a(error: Error) -> bool { error.code() != ErrorCode::InvalidArgument }",
            COMPARED,
        ),
        (
            "fn a(refusal: Refusal) -> bool { refusal.message.contains(\"full\") }",
            WORDS,
        ),
        (
            "fn a(refusal: Refusal) -> bool { refusal.message == \"the host is full\" }",
            WORDS,
        ),
        (
            "fn a(refusal: Refusal) -> bool { \"the host is full\" == refusal.message }",
            WORDS,
        ),
        (
            "fn a(refusal: Refusal) -> bool { refusal.message.as_str() == \"x\" }",
            WORDS,
        ),
        (
            "fn a(error: Error) -> bool { error.to_string().contains(\"full\") }",
            WORDS,
        ),
        (
            "fn a(error: Error) -> bool { error.message().starts_with(\"no\") }",
            WORDS,
        ),
        (
            "fn a(session: &Session) -> Option<ProtocolError> { session.connection_refusal() }",
            ACCESSOR,
        ),
        (
            "fn a(error: LinkError) { match error { LinkError::ConnectionRefused(refusal) => drop(refusal), _ => {} } }",
            "LinkError::ConnectionRefused",
        ),
        (
            "fn a(error: LinkError) { match error { LinkError::Refused(refusal) => drop(refusal), _ => {} } }",
            "LinkError::Refused",
        ),
        (
            "fn a(unopened: Unopened) -> bool { matches!(unopened, Unopened::Refused(Asked::Connection, _)) }",
            "Asked::Connection",
        ),
        (
            "fn a(refusal: ProtocolError) -> Unopened { Unopened::of_refused_connection(refusal) }",
            "of_refused_connection(",
        ),
    ];
    for (snippet, needle) in fails {
        assert!(
            read_by(snippet).contains(&needle),
            "the rule does not find `{needle}` in:\n{snippet}"
        );
    }
}

/// KR-REQ-19.08: a helper that stands in a file that has nothing to do with dialing, or that follows
/// a `#[cfg(test)]` that is no test module, is read as the rest of the source is, and a test module
/// hides nothing else.
#[test]
fn the_rule_reads_the_whole_of_a_file_outside_its_test_modules() {
    let helper = "impl Error {\n    fn is_full(&self) -> bool {\n        self.code == ErrorCode::ResourceUnavailable\n    }\n}\n";
    assert_eq!(read_by(helper), [COMPARED]);

    let after_a_test_item = "#[cfg(test)]\nuse tests_only::Thing;\n\nfn later(refusal: Refusal) -> bool {\n    refusal.code == ErrorCode::PermissionDenied\n}\n";
    assert_eq!(read_by(after_a_test_item), [COMPARED]);

    let after_a_test_module = "#[cfg(test)]\nmod tests {\n    fn t() {\n        assert_eq!(x.code, ErrorCode::A);\n    }\n}\n\nfn later(refusal: Refusal) -> bool {\n    refusal.code == ErrorCode::PermissionDenied\n}\n";
    let hits = scan("snippet.rs", after_a_test_module);
    assert_eq!(
        hits.iter().map(|hit| hit.line).collect::<Vec<_>>(),
        [9],
        "{hits:?}"
    );

    let only_in_the_tests = "fn product() {}\n\n#[cfg(test)]\nmod tests {\n    fn t(refusal: Refusal) {\n        assert!(refusal.code == ErrorCode::A);\n        assert!(refusal.message.contains(\"x\"));\n    }\n}\n";
    assert!(read_by(only_in_the_tests).is_empty());
}

/// KR-REQ-19.08: the constructions that name a code and read no error pass, and so do comments and
/// the causes themselves.
#[test]
fn the_honest_forms_pass_the_rule() {
    let passes = [
        "fn a() -> CommandError { CommandError::stated(ErrorCode::ResourceUnavailable, \"words\") }",
        "fn a() -> CommandError {\n    CommandError::stated(\n        ErrorCode::ResourceUnavailable,\n        \"words\",\n    )\n}",
        "fn a() -> ProtocolError { ProtocolError::new(ErrorCode::PermissionDenied, \"no\") }",
        "fn a(error: Lease) -> ProtocolError { ProtocolError::new(error.code(), error.to_string()) }",
        "fn a(error: ProtocolError) -> CommandError { Self::new(error.code, error.message) }",
        "fn a(error: LinkError) -> Unopened { Unopened::of_link(error) }",
        "fn a(unopened: &Unopened) -> bool { unopened.for_now() }",
        "fn a(words: HostWords) -> Unopened { Unopened::NotAdmitted(words) }",
        "fn a(refusal: ProtocolError) -> String { format!(\"the host said: {}\", refusal.message) }",
        "fn a(refusal: &ProtocolError) -> String { refusal.message.clone() }",
        "fn a(refusal: &ProtocolError) -> String { refusal.message.to_owned() }",
        "// refusal.code == ErrorCode::PermissionDenied\nfn a() {}",
        "/// match refusal.code { ErrorCode::ResourceUnavailable => 1 }\nfn a() {}",
        "fn a() { let code = ErrorCode::ResourceUnavailable; drop(code); }",
        "fn a(kind: std::io::ErrorKind) -> bool { kind == std::io::ErrorKind::ConnectionRefused }",
        "fn a(name: &str) -> bool { name == \"HTTPS_PROXY\" }",
    ];
    for snippet in passes {
        assert!(
            read_by(snippet).is_empty(),
            "the rule objects to an honest form: {:?}\n{snippet}",
            read_by(snippet)
        );
    }
}

/// KR-REQ-19.08: the client's accessor of a connection's kept refusal is asked for in the file that
/// makes the cause and nowhere else, and no exception excuses it.
#[test]
fn the_accessor_of_a_connections_kept_refusal_is_asked_for_in_one_file_only() {
    let asked =
        "fn a(session: &Session) -> Option<ProtocolError> {\n    session.connection_refusal()\n}\n";
    for file in [
        "lease.rs",
        "terminal/view.rs",
        "terminal/wire.rs",
        "anything.rs",
    ] {
        let hits = scan(file, asked);
        assert_eq!(
            hits.iter().map(|hit| hit.needle).collect::<Vec<_>>(),
            [ACCESSOR],
            "{file}"
        );
    }
    let defined = "impl Wire {\n    fn connection_refusal(&self) -> Option<ProtocolError> {\n        None\n    }\n}\n";
    assert_eq!(
        scan("terminal/wire.rs", defined)
            .iter()
            .map(|hit| hit.needle)
            .collect::<Vec<_>>(),
        [ACCESSOR],
        "a function of that name is the accessor's name too"
    );
    assert!(
        scan(HOME.0, asked).is_empty(),
        "the file that makes the cause asks for it"
    );

    let hits = scan("lease.rs", asked);
    let excuse = [Exception {
        file: "lease.rs",
        function: "a",
        needle: ACCESSOR,
        lines: 1,
        reason: "a test",
    }];
    assert_eq!(
        problems(&hits, &excuse).len(),
        1,
        "an exception for it excuses nothing"
    );
    assert!(
        EXCEPTIONS
            .iter()
            .all(|exception| exception.needle != ACCESSOR),
        "no exception holds the accessor"
    );
}

/// KR-REQ-19.08: words compared, searched or matched are found from a receiver of any name, with the
/// search on the line after the field or the call.
#[test]
fn words_are_found_from_a_receiver_of_any_name_and_across_a_line_end() {
    let fails = [
        "fn decides(e: &ProtocolError) -> bool {\n    e.to_string().contains(\"withdrawn\")\n}\n",
        "fn decides(x: &ProtocolError) -> bool {\n    x.to_string() == \"the host withdrew it\"\n}\n",
        "fn decides(x: &ProtocolError) -> bool {\n    \"the host withdrew it\" == x.to_string()\n}\n",
        "fn decides(e: &ProtocolError) -> bool {\n    e.to_string()\n        .starts_with(\"no\")\n}\n",
        "fn decides(r: &ProtocolError) -> bool {\n    r.message\n        .contains(\"withdrawn\")\n}\n",
        "fn decides(r: &ProtocolError) -> bool {\n    q.message.ends_with(\"x\") || r.message\n        == \"y\"\n}\n",
        "fn decides(m: &ProtocolError) -> u8 {\n    match m.message.as_str() {\n        _ => 1,\n    }\n}\n",
        "fn decides(m: &ProtocolError) -> u8 {\n    match m.message {\n        _ => 1,\n    }\n}\n",
    ];
    for snippet in fails {
        assert_eq!(
            read_by(snippet),
            [WORDS],
            "the rule does not find the words in:\n{snippet}"
        );
    }
    let passes = [
        "fn a(e: &ProtocolError) -> String { e.to_string() }\n",
        "fn a(e: &ProtocolError) -> String {\n    format!(\"the host said {}\", e.message)\n}\n",
        "fn a(r: &ProtocolError) -> String {\n    r.message\n        .clone()\n}\n",
    ];
    for snippet in passes {
        assert!(
            read_by(snippet).is_empty(),
            "the rule objects to:\n{snippet}"
        );
    }
}

/// KR-REQ-19.08: an exception ends where its function ends. A line after the function stands in no
/// function, a line inside it stands in it whatever blocks it holds, and a function whose visibility
/// names a path is the function.
#[test]
fn an_exception_ends_where_its_function_ends() {
    let after = "fn a(r: Refusal) -> bool {\n    r.code == ErrorCode::A\n}\n\nimpl Thing {\n    const LATER: bool = r.code == ErrorCode::B;\n}\n";
    let hits = scan("snippet.rs", after);
    assert_eq!(
        hits.iter()
            .map(|hit| hit.function.as_str())
            .collect::<Vec<_>>(),
        ["a", ""],
        "{hits:?}"
    );
    let excuse = [Exception {
        file: "snippet.rs",
        function: "a",
        needle: COMPARED,
        lines: 1,
        reason: "a test",
    }];
    let wrong = problems(&hits, &excuse);
    assert_eq!(wrong.len(), 1, "{wrong:?}");
    assert!(
        wrong[0].contains("LATER"),
        "the line after the function stays found: {wrong:?}"
    );

    let blocks = "fn a(r: Refusal) {\n    if x {\n        y();\n    }\n    let _ = r.code == ErrorCode::A;\n}\n";
    assert_eq!(scan("snippet.rs", blocks)[0].function, "a");

    let path = "fn first() {}\npub(in crate::settings) fn second(r: Refusal) -> bool {\n    r.code == ErrorCode::A\n}\n";
    assert_eq!(scan("snippet.rs", path)[0].function, "second");

    let signature = "fn a<T>(\n    r: Refusal,\n    other: [u8; 4],\n) -> bool\nwhere\n    T: Copy,\n{\n    r.code == ErrorCode::A\n}\n";
    assert_eq!(scan("snippet.rs", signature)[0].function, "a");
}

/// KR-REQ-19.08: where a file holds two functions of one name, an exception names the type of the
/// `impl` too, and a bare name excuses neither.
#[test]
fn two_functions_of_one_name_in_a_file_are_excused_by_their_types() {
    let snippet = "impl A {\n    fn of(r: Refusal) -> bool {\n        r.code == ErrorCode::A\n    }\n}\n\nimpl B {\n    fn of(r: Refusal) -> bool {\n        r.code == ErrorCode::B\n    }\n}\n\nfn of(r: Refusal) -> bool {\n    r.code == ErrorCode::C\n}\n";
    let hits = scan("snippet.rs", snippet);
    let excuse = |function| Exception {
        file: "snippet.rs",
        function,
        needle: COMPARED,
        lines: 1,
        reason: "a test",
    };
    assert!(
        problems(
            &hits,
            &[excuse("A::of"), excuse("B::of"), excuse("(free)::of")]
        )
        .is_empty()
    );
    let bare = problems(&hits, &[excuse("of")]);
    assert_eq!(
        bare.len(),
        4,
        "three places stay found and the bare name is stale: {bare:?}"
    );
    let one = problems(&hits, &[excuse("A::of"), excuse("(free)::of")]);
    assert_eq!(one.len(), 1, "{one:?}");
    assert!(one[0].contains("B::of"), "{one:?}");
}

/// KR-REQ-19.08: comments (line, doc and block, nested) and string and character literals are not
/// read as code, a brace in a character literal ends no function, and a code's wire name in a literal
/// is still found.
#[test]
fn comments_and_literals_are_not_read_as_code() {
    let passes = [
        "/* refusal.code == ErrorCode::PermissionDenied */\nfn a() {}\n",
        "/*\n * match refusal.code {\n *     ErrorCode::ResourceUnavailable => 1,\n * }\n */\nfn a() {}\n",
        "/* outer /* inner */ refusal.code == ErrorCode::PermissionDenied */\nfn a() {}\n",
        "fn a() -> &'static str { \"refusal.code == ErrorCode::PermissionDenied\" }\n",
        "fn a() -> &'static str { \"refusal.message.contains(x)\" }\n",
        "fn a() -> &'static str {\n    \"a literal over\n     two lines: e.to_string().contains(x)\"\n}\n",
        "fn a() -> &'static str { r#\"e.to_string().contains(\"x\")\"# }\n",
        "fn a(c: char) -> bool { c == '\"' || c == '\\'' }\n",
    ];
    for snippet in passes {
        assert!(
            read_by(snippet).is_empty(),
            "the rule objects to:\n{snippet}"
        );
    }
    let braces = "fn a(c: char) -> bool { c == '{' }\n\nfn b(r: Refusal) -> bool {\n    r.code == ErrorCode::A\n}\n";
    let hits = scan("snippet.rs", braces);
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].function, "b");
    assert_eq!(
        read_by("const FULL: &str = \"RESOURCE_UNAVAILABLE\";\n"),
        [AS_TEXT],
        "a code's wire name in a literal is found"
    );
    let after_a_comment = "/* refusal.code == ErrorCode::PermissionDenied */ fn a(r: Refusal) -> bool { r.code == ErrorCode::A }\n";
    assert_eq!(
        read_by(after_a_comment),
        [COMPARED],
        "code after a block comment is read"
    );
}

/// KR-REQ-19.08: an exception excuses the needle, the function and the number of lines it names and
/// nothing else, and one that excuses nothing is stale.
#[test]
fn an_exception_excuses_one_needle_in_one_function() {
    let snippet = "fn a(refusal: Refusal) -> bool {\n    refusal.code == ErrorCode::PermissionDenied && refusal.message.contains(\"x\")\n}\n\nfn b(refusal: Refusal) -> bool {\n    refusal.code == ErrorCode::PermissionDenied\n}\n";
    let hits = scan("snippet.rs", snippet);
    let excuse = |file, function, needle, lines| Exception {
        file,
        function,
        needle,
        lines,
        reason: "a test",
    };

    let both = [
        excuse("snippet.rs", "a", COMPARED, 1),
        excuse("snippet.rs", "a", WORDS, 1),
        excuse("snippet.rs", "b", COMPARED, 1),
    ];
    assert!(problems(&hits, &both).is_empty());

    let one_needle = [
        excuse("snippet.rs", "a", COMPARED, 1),
        excuse("snippet.rs", "b", COMPARED, 1),
    ];
    let wrong = problems(&hits, &one_needle);
    assert_eq!(wrong.len(), 1, "{wrong:?}");
    assert!(wrong[0].contains(WORDS), "the words stay found: {wrong:?}");

    let one_function = [
        excuse("snippet.rs", "a", COMPARED, 1),
        excuse("snippet.rs", "a", WORDS, 1),
    ];
    let wrong = problems(&hits, &one_function);
    assert_eq!(wrong.len(), 1, "{wrong:?}");
    assert!(
        wrong[0].contains("`b`"),
        "the other function stays found: {wrong:?}"
    );

    let too_few = [
        excuse("snippet.rs", "a", COMPARED, 2),
        excuse("snippet.rs", "a", WORDS, 1),
        excuse("snippet.rs", "b", COMPARED, 1),
    ];
    assert_eq!(problems(&hits, &too_few).len(), 1);

    let stale = [
        excuse("snippet.rs", "a", COMPARED, 1),
        excuse("snippet.rs", "a", WORDS, 1),
        excuse("snippet.rs", "b", COMPARED, 1),
        excuse("snippet.rs", "c", COMPARED, 1),
    ];
    let wrong = problems(&hits, &stale);
    assert_eq!(wrong.len(), 1, "{wrong:?}");
    assert!(wrong[0].contains("matches no line"), "{wrong:?}");
}
