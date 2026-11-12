//! What a person is told about a connection that was not opened comes from the cause, never from an
//! error's code or words.
//!
//! The host refuses a connection it cannot take with the code it also uses for a supervision, for
//! work in another session and for a resource that is short, and a host that did not answer is told
//! with it too, so a code says nothing of which of these it is. The cause is made where it is known,
//! in `connection::Unopened::of_link` and `Unopened::of_connection` (which share
//! `Unopened::of_refused_connection`, the one place that reads the host's bound from a refusal), and
//! every dialer reads the cause. A dialer that chose its words from a code or from a refusal's text
//! would tell some cause as another, such as a host that could not be reached when it was full, or
//! one that was full when it refused for another reason.
//!
//! This reads the source of every module that dials a paired host and fails, naming the place, at a
//! line that reads a refusal's code for the capacity cause or for "for now", or tests a refusal's
//! words, unless the line is listed below with its reason. Test code is not read.

use std::path::{Path, PathBuf};

/// The modules that tell a person about a connection that was not opened. A module under `src`
/// that names a dialing call and is not here fails, so a new dialer is read as these are.
const MODULES: [&str; 15] = [
    "connection.rs",
    "hosts.rs",
    "inbox.rs",
    "lease.rs",
    "owner.rs",
    "places.rs",
    "push.rs",
    "revocation.rs",
    "settings/connected.rs",
    "sharing.rs",
    "standing.rs",
    "terminal/view.rs",
    "terminal/wire.rs",
    "voice/host.rs",
    "voice/owner.rs",
];

/// What marks a module as one that dials a paired host.
const DIALING: [&str; 6] = [
    "Unopened",
    "LinkError",
    "connect_paired",
    "visit_paired",
    ".another()",
    "Connection::paired",
];

/// What a line may not do, each with the reason it is the cause's to do and nobody else's.
const NEEDLES: [(&str, &str); 8] = [
    (
        "ResourceUnavailable",
        "the code that stands for the host's bound and for causes that are not it",
    ),
    (
        "transient(",
        "the code's reading as for now, which a person's words follow from the cause",
    ),
    (
        ".message.contains(",
        "a refusal's words are the host's to say, not to read",
    ),
    (
        ".message.starts_with(",
        "a refusal's words are the host's to say, not to read",
    ),
    (
        ".message.ends_with(",
        "a refusal's words are the host's to say, not to read",
    ),
    (
        ".message ==",
        "a refusal's words are the host's to say, not to read",
    ),
    (
        "lease_is_refused(",
        "the lease's refusal is read from a code and words",
    ),
    (
        "is_no_room",
        "no dialer chooses words for capacity from a code",
    ),
];

/// A line that reads a code or words and may: the module, a part of the line, and why.
struct Exception {
    module: &'static str,
    line: &'static str,
    reason: &'static str,
}

/// Every line outside the two places that make the cause that reads a code or words, and why it
/// does not choose words for a connection that was not opened. A line that is not here fails.
const EXCEPTIONS: [Exception; 7] = [
    Exception {
        module: "connection.rs",
        line: "refusal.code == kr_protocol::error::ErrorCode::ResourceUnavailable",
        reason: "the one place that reads the host's bound from a refusal of the connection, reached \
                 from the two places that make the cause",
    },
    Exception {
        module: "connection.rs",
        line: "refusal.message == kr_transport::actor::METHOD_NOT_AVAILABLE",
        reason: "a host of an earlier build refuses an unlisted method with the transport's own \
                 constant, and only that refusal of the request that opens the connection for the \
                 host alone is told to be updated; no capacity is read",
    },
    Exception {
        module: "connection.rs",
        line: "transient(",
        reason: "whether a cause is for now, as a typed answer for the callers that decide whether \
                 to wait or to refuse; the words come from the cause",
    },
    Exception {
        module: "inbox.rs",
        line: "lease_is_refused(refusal.code, &refusal.message)",
        reason: "decides whether to present the lease again over a connection that is open; it \
                 chooses no words",
    },
    Exception {
        module: "revocation.rs",
        line: "error.message.ends_with('.')",
        reason: "ends the host's own words with a full stop before this computer's words follow; it \
                 chooses no words from them",
    },
    Exception {
        module: "standing.rs",
        line: "fn transient(",
        reason: "the reading of a code as for now, whose callers decide whether an opening waits",
    },
    Exception {
        module: "standing.rs",
        line: "!transient(refusal.code)",
        reason: "decides whether a refusal ends the opening or is asked again, and carries the \
                 refusal's code to the next ask; the words a refusal ends with are the host's own",
    },
];

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The lines of a module outside its test code and its comments, with their numbers.
fn code_of(path: &Path) -> Vec<(usize, String)> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} could not be read: {error}", path.display()));
    let mut lines = Vec::new();
    for (number, line) in text.lines().enumerate() {
        if line.starts_with("#[cfg(test)]") {
            break;
        }
        let code = line.split(" // ").next().unwrap_or(line);
        if code.trim_start().starts_with("//") {
            continue;
        }
        lines.push((number + 1, code.to_owned()));
    }
    lines
}

/// Whether `line` makes a value with the code, which reads no error: the code is an argument of a
/// constructor on this line or the one before it.
fn constructs(line: &str, before: &str) -> bool {
    line.contains("::new(")
        || line.contains("::unavailable(")
        || before.trim_end().ends_with("new(")
}

/// The files under `directory` whose text holds a mark of dialing, relative to `root`.
fn dialers(root: &Path, directory: &Path, found: &mut Vec<String>) {
    for entry in std::fs::read_dir(directory).expect("the source can be listed") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            dialers(root, &path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let (text, name) = (
                std::fs::read_to_string(&path).expect("a source file"),
                path.strip_prefix(root)
                    .expect("under the source")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
            let code: Vec<&str> = text
                .lines()
                .take_while(|line| !line.starts_with("#[cfg(test)]"))
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect();
            if code
                .iter()
                .any(|line| DIALING.iter().any(|mark| line.contains(mark)))
            {
                found.push(name);
            }
        }
    }
}

/// KR-REQ-19.08: no line of a module that dials a paired host chooses what a person is told about a
/// connection that was not opened from a refusal's code or words, except the lines this lists.
#[test]
fn no_words_about_a_connection_that_was_not_opened_are_chosen_from_an_errors_code_or_words() {
    let mut unlisted = Vec::new();
    let mut used = [false; EXCEPTIONS.len()];
    for module in MODULES {
        let lines = code_of(&source().join(module));
        let mut before = String::new();
        for (number, line) in &lines {
            for (needle, why) in NEEDLES {
                if !line.contains(needle) {
                    continue;
                }
                if needle == "ResourceUnavailable" && constructs(line, &before) {
                    continue;
                }
                let excused = EXCEPTIONS.iter().enumerate().find(|(_, exception)| {
                    exception.module == module && line.contains(exception.line)
                });
                match excused {
                    Some((index, _)) => used[index] = true,
                    None => unlisted.push(format!("{module}:{number}: {} ({why})", line.trim())),
                }
            }
            before.clone_from(line);
        }
    }
    assert!(
        unlisted.is_empty(),
        "a connection that was not opened is told from its cause (`connection::Unopened`), and \
         these lines read a code or words instead:\n{}",
        unlisted.join("\n")
    );
    let stale: Vec<String> = EXCEPTIONS
        .iter()
        .zip(used)
        .filter(|(_, used)| !used)
        .map(|(exception, _)| {
            format!(
                "{}: {} ({})",
                exception.module, exception.line, exception.reason
            )
        })
        .collect();
    assert!(
        stale.is_empty(),
        "these exceptions match no line any more, so they are removed:\n{}",
        stale.join("\n")
    );
}

/// KR-REQ-19.08: every module that dials a paired host is read by the case above.
#[test]
fn every_module_that_dials_a_paired_host_is_read_by_the_rule() {
    let root = source();
    let mut found = Vec::new();
    dialers(&root, &root, &mut found);
    found.sort();
    let unread: Vec<&String> = found
        .iter()
        .filter(|name| !MODULES.contains(&name.as_str()))
        .collect();
    assert!(
        unread.is_empty(),
        "these modules dial a paired host and are not named by the rule: {unread:?}"
    );
}
