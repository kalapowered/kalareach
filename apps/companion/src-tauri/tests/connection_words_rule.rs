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
//! - a refusal's words compared or searched (`.message ==`, `.message.contains(..)`, an error's
//!   `to_string()` searched, and the like);
//! - a handling of a refused connection: the refusal a session or a wire kept
//!   (`connection_refusal(`), the link errors that carry a host's refusal of a connection
//!   (`LinkError::Refused`, `LinkError::ConnectionRefused`) and the cause that names it
//!   (`Asked::Connection`), which only the functions above handle.
//!
//! An exception names one file, one function, one needle and how many lines of that function it
//! excuses, and says why: a line that is not excused, an exception that excuses more or fewer lines
//! than it names, and one that excuses none, each fail the case. The rule has cases of its own: the
//! forms that must fail, and the honest forms that must pass.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_protocol::error::ErrorCode;

/// The file that makes the cause, and the functions in it that read a host's refusal of a connection
/// so that no other place does.
const HOME: (&str, [&str; 4]) = (
    "connection.rs",
    [
        "of_link",
        "of_connection",
        "of_kept_refusal",
        "of_refused_connection",
    ],
);

const COMPARED: &str = "a code compared";
const MATCHED: &str = "a code matched";
const USED: &str = "a use of .code";
const AS_TEXT: &str = "a code as text";
const CATEGORY: &str = "a code's retry category";
const WORDS: &str = "words compared or searched";

/// The handling of a refused connection that only the functions of `HOME` do, each its own needle.
const HANDLING: [&str; 6] = [
    "connection_refusal(",
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

/// What a receiver is called when it is an error, a refusal or a cause, so that its `to_string()`
/// is an error's text and not an identifier's.
const ERROR_NAMES: [&str; 8] = [
    "error", "refus", "failure", "cause", "unopened", "reason", "problem", "stop",
];

/// What searches or compares an error's text when it follows `.to_string()`.
const TEXT_READS: [&str; 5] = [".contains(", ".starts_with(", ".ends_with(", " ==", " !="];

/// A read of a code or of words, or a handling of a refused connection, that the rule objects to.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Hit {
    file: String,
    function: String,
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
        function: "from",
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
        file: "lease.rs",
        function: "failed_on",
        needle: "LinkError::ConnectionRefused",
        lines: 1,
        reason: "carries the refusal that the session kept to its cause (`Unopened::of_link`) at every stop of the lease's keeper; it reads no code or words",
    },
    Exception {
        file: "lease.rs",
        function: "failed_on",
        needle: "connection_refusal(",
        lines: 1,
        reason: "carries the refusal that the session kept to its cause (`Unopened::of_link`) at every stop of the lease's keeper; it reads no code or words",
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
        function: "settle",
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
        reason: "a refusal at the handshake is answered by its code about listing, as before a host's refusal of a connection was read: only a refusal to list the host's devices to this computer is an answer about them",
    },
    Exception {
        file: "settings/connected.rs",
        function: "of_link",
        needle: USED,
        lines: 1,
        reason: "a refusal at the handshake is answered by its code about listing, as before a host's refusal of a connection was read: only a refusal to list the host's devices to this computer is an answer about them",
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
        function: "change",
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
        needle: "connection_refusal(",
        lines: 1,
        reason: "hands the refusal that the view's wire kept to the one function that tells a refusal of a connection from a refusal of a request",
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
        file: "terminal/wire.rs",
        function: "connection_refusal",
        needle: "connection_refusal(",
        lines: 1,
        reason: "the wire's own record of the host's refusal of the connection, which only the view's opening hands to the one function that gives it its meaning",
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

/// The lines of `text` that the product runs, with their numbers and without their comments. A test
/// module (`#[cfg(test)]` on a `mod`, closed by a `}` in the first column) is left out wherever it
/// stands, and a `#[cfg(test)]` on anything else leaves the scan where it is.
fn code_lines(text: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut kept = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if line.trim_end() == "#[cfg(test)]" {
            let mut item = index + 1;
            while lines
                .get(item)
                .is_some_and(|next| next.trim_start().starts_with("#["))
            {
                item += 1;
            }
            let is_module = lines.get(item).is_some_and(|next| {
                next.trim_start_matches("pub ").starts_with("mod ") && next.ends_with('{')
            });
            if is_module {
                while item < lines.len() && lines[item] != "}" {
                    item += 1;
                }
                index = item + 1;
            } else {
                index += 1;
            }
            continue;
        }
        index += 1;
        if line.trim_start().starts_with("//") {
            continue;
        }
        let code = line.split(" // ").next().unwrap_or(line);
        kept.push((index, code.to_owned()));
    }
    kept
}

/// The name of the function a line declares, if it declares one.
fn function_named(line: &str) -> Option<String> {
    let mut rest = line.trim_start();
    loop {
        let before = rest;
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

/// What `line` reads of a code or of words, or handles of a refused connection.
fn needles(line: &str, previous: &str) -> Vec<&'static str> {
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
        .any(|code| line.contains(&format!("\"{}\"", code.as_str())))
    {
        note(AS_TEXT);
    }
    for (start, end) in fields(line, ".message") {
        let (before, after) = (line[..start].trim_end(), line[end..].trim_start());
        if before.ends_with("==")
            || before.ends_with("!=")
            || WORD_READS.iter().any(|read| after.starts_with(read))
        {
            note(WORDS);
        }
    }
    // An error's own text, searched or compared: the receiver names an error, a refusal or a cause.
    if let Some(at) = line.find(".to_string()") {
        let after = &line[at + ".to_string()".len()..];
        let receiver = &line[receiver_start(&line[..at], '.')..at];
        if TEXT_READS.iter().any(|read| after.starts_with(read))
            && ERROR_NAMES.iter().any(|name| receiver.contains(name))
        {
            note(WORDS);
        }
    }
    for needle in HANDLING {
        if line.contains(needle) {
            note(needle);
        }
    }
    found
}

/// Every read of a code or of words, and every handling of a refused connection, that `text` holds
/// outside its test modules, outside the functions that are `HOME`'s when `file` is.
fn scan(file: &str, text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut function = String::new();
    let mut previous = String::new();
    for (number, line) in code_lines(text) {
        if let Some(name) = function_named(&line) {
            function = name;
        }
        for needle in needles(&line, &previous) {
            hits.push(Hit {
                file: file.to_owned(),
                function: function.clone(),
                needle,
                line: number,
                text: line.trim().to_owned(),
            });
        }
        previous = line;
    }
    hits.retain(|hit| !(hit.file == HOME.0 && HOME.1.contains(&hit.function.as_str())));
    hits
}

/// What is wrong with `hits` against `exceptions`: a place that no exception excuses, an exception
/// that excuses a different number of lines than the place has, and an exception that matches none.
fn problems(hits: &[Hit], exceptions: &[Exception]) -> Vec<String> {
    let mut places: BTreeMap<(&str, &str, &str), Vec<&Hit>> = BTreeMap::new();
    for hit in hits {
        places
            .entry((&hit.file, &hit.function, hit.needle))
            .or_default()
            .push(hit);
    }
    let mut found = Vec::new();
    for ((file, function, needle), lines) in &places {
        let excuse = exceptions.iter().find(|exception| {
            (exception.file, exception.function, exception.needle) == (*file, *function, *needle)
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
        if !places.contains_key(&(exception.file, exception.function, exception.needle)) {
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
        .filter_map(|(_, line)| function_named(line))
        .collect();
    for function in HOME.1 {
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
            "connection_refusal(",
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
        "fn a(error: CommandError) -> Unopened { Unopened::NotAdmitted(error) }",
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
