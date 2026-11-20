//! Why a bind of a local endpoint was refused, and the words that say it.
//!
//! The refusal is read from the evidence of the bind itself: what stands at the address, what
//! answered a probe, what a lock says. Each class has one set of words, written here once. The
//! host, the gateway and the daemon's log say them as a `String` through [`ListenRefusal::said`];
//! the command line says the same words through its own `Shown` type, which fills the template
//! [`ListenRefusal::words`] returns with the parts [`ListenRefusal::parts`] lists, so no text that
//! arrived is ever shown.
//!
//! The words never direct a removal from a refused connect alone: "move it away" is said only of
//! an object a person can see and identify, or after a check the sentence names.

/// What stands at an endpoint address that is not a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link.
    Link,
    /// Anything else that is not a socket: a pipe, a device.
    Other,
}

impl ObjectKind {
    /// The kind of an object from its metadata, read without following a link.
    #[must_use]
    pub fn of(file_type: std::fs::FileType) -> Self {
        if file_type.is_symlink() {
            Self::Link
        } else if file_type.is_dir() {
            Self::Directory
        } else if file_type.is_file() {
            Self::File
        } else {
            Self::Other
        }
    }

    /// The words that name it in a sentence.
    #[must_use]
    pub const fn phrase(self) -> &'static str {
        match self {
            Self::File => "a file",
            Self::Directory => "a directory",
            Self::Link => "a link",
            Self::Other => "something that is not a socket",
        }
    }
}

/// The step of a bind that failed for a reason the other classes do not name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenStep {
    /// Looking at what stands at the address.
    Inspect,
    /// Asking whether anything listens there.
    Probe,
    /// Taking the listener's lock.
    Lock,
    /// The bind itself.
    Bind,
    /// Restricting the socket to its owner.
    Permissions,
}

impl ListenStep {
    /// The step's one word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Probe => "probe",
            Self::Lock => "lock",
            Self::Bind => "bind",
            Self::Permissions => "permissions",
        }
    }
}

/// Why an endpoint could not be bound.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListenRefusal {
    /// Something that is not a socket stands at the address. Nothing was removed.
    NotASocket {
        /// What it is.
        object: ObjectKind,
    },
    /// A listener answered, or its queue was full: a listener exists.
    Held {
        /// The process behind the connection, where the kernel gave it.
        pid: Option<u32>,
    },
    /// A connect was refused while the listener's lock file is held: a listener of this release
    /// is likely, and none was verified.
    LockHeld,
    /// A connect was refused and what was left cannot show that the socket's listener ended.
    /// Nothing was removed.
    Unanswered,
    /// The socket was left by a listener that ended, and removing it failed.
    NotRemoved {
        /// The operating system's error number.
        os: i32,
    },
    /// The pipe name exists and the system does not say whose it is (Windows).
    NameTaken,
    /// A socket already occupies the address of a directory that is new for this launch.
    Occupied,
    /// A step failed for a reason of the system's.
    Other {
        /// The step.
        operation: ListenStep,
        /// The operating system's error number, where the failure had one.
        os: Option<i32>,
    },
}

/// A part of a sentence that is not the address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// Fixed words.
    Words(&'static str),
    /// A number: a process identifier.
    Number(u64),
    /// An operating system error number, said as [`os_reason`] says it.
    Os(i32),
}

/// The words of one class: a template with a bare `{}` for the address and then one for each part,
/// and the words that join an instruction to follow, when the class has one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Words {
    /// The sentence without any instruction to follow.
    pub template: &'static str,
    /// What goes between the sentence and the words that tell the person what to do next, or
    /// `None` where the class gives no such instruction.
    pub joiner: Option<&'static str>,
}

impl ListenRefusal {
    /// The words of the class.
    #[must_use]
    pub const fn words(&self) -> Words {
        match self {
            Self::NotASocket { .. } => Words {
                template: "{}: it holds {}; kr does not remove what it did not make; if you do not need it, move it away",
                joiner: Some(", then "),
            },
            Self::Held { pid: Some(_) } => Words {
                template: "{}: a running listener that process {} started holds it; run lsof on it to see which program holds it now, stop that program",
                joiner: Some(", then "),
            },
            Self::Held { pid: None } => Words {
                template: "{}: a running listener holds it, and kr cannot name its process; run lsof on it to see which program holds it, stop that program",
                joiner: Some(", then "),
            },
            Self::LockHeld => Words {
                template: "{}: its lock file, the same name with .live added, is held and kr cannot verify a listener on it; run lsof on both, stop the program lsof names, if any",
                joiner: Some(", then "),
            },
            Self::Unanswered => Words {
                template: "{}: kr cannot tell whether a program still holds it; run lsof on it to see, and move it away only if none does",
                joiner: Some("; then "),
            },
            Self::NotRemoved { .. } => Words {
                template: "{}: kr could not remove it ({}); clear that cause",
                joiner: Some(", then "),
            },
            Self::NameTaken => Words {
                template: "{}: the pipe is already in use by another program, or another account made it first, and kr cannot name the holder",
                joiner: Some("; "),
            },
            Self::Occupied => Words {
                template: "{}: a socket already occupies it",
                joiner: Some("; "),
            },
            Self::Other { os: Some(_), .. } => Words {
                template: "{}: the {} step failed ({})",
                joiner: None,
            },
            Self::Other { os: None, .. } => Words {
                template: "{}: the {} step failed",
                joiner: None,
            },
        }
    }

    /// The parts that follow the address in the template, in order.
    #[must_use]
    pub fn parts(&self) -> Vec<Part> {
        match self {
            Self::NotASocket { object } => vec![Part::Words(object.phrase())],
            Self::Held { pid: Some(pid) } => vec![Part::Number(u64::from(*pid))],
            Self::Held { pid: None }
            | Self::LockHeld
            | Self::Unanswered
            | Self::NameTaken
            | Self::Occupied => Vec::new(),
            Self::NotRemoved { os } => vec![Part::Os(*os)],
            Self::Other {
                operation,
                os: Some(os),
            } => vec![Part::Words(operation.word()), Part::Os(*os)],
            Self::Other {
                operation,
                os: None,
            } => vec![Part::Words(operation.word())],
        }
    }

    /// The error code a caller reports: a thing that is not a socket is a refusal to act on what
    /// is there, and every other class is a resource that cannot be had now.
    #[must_use]
    pub const fn is_refusal_to_act(&self) -> bool {
        matches!(self, Self::NotASocket { .. })
    }

    /// The sentence for the address, as the host, the gateway and the daemon's log say it: the
    /// class's words and no instruction to follow.
    #[must_use]
    pub fn said(&self, endpoint: &str) -> String {
        let words = self.words();
        fill(words.template, endpoint, &self.parts())
    }

    /// The sentence followed by an instruction the caller words, joined as the class joins it. A
    /// class that gives no instruction says its sentence alone.
    #[must_use]
    pub fn said_then(&self, endpoint: &str, then: &str) -> String {
        let sentence = self.said(endpoint);
        match self.words().joiner {
            Some(joiner) => format!("{sentence}{joiner}{then}"),
            None => sentence,
        }
    }
}

/// What an operating system error number says: the kind of error and the number, as the command
/// line's reducer of an I/O failure says it.
#[must_use]
pub fn os_reason(os: i32) -> String {
    format!(
        "{} (os error {os})",
        std::io::Error::from_raw_os_error(os).kind()
    )
}

/// Fills the template's bare `{}` with the address and then each part, in order.
fn fill(template: &str, endpoint: &str, parts: &[Part]) -> String {
    let mut text = String::with_capacity(template.len() + endpoint.len() + 32);
    let mut next = 0_usize;
    let mut characters = template.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '{' && characters.peek() == Some(&'}') {
            characters.next();
            if next == 0 {
                text.push_str(endpoint);
            } else if let Some(part) = parts.get(next - 1) {
                match part {
                    Part::Words(words) => text.push_str(words),
                    Part::Number(number) => text.push_str(&number.to_string()),
                    Part::Os(os) => text.push_str(&os_reason(*os)),
                }
            }
            next += 1;
        } else {
            text.push(character);
        }
    }
    text
}

/// Which of the control daemon's three local endpoints a bind was for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenRole {
    /// The endpoint clients send commands to.
    Control,
    /// The endpoint workers and plugin hosts report in on.
    Rendezvous,
    /// The endpoint attachment chunks are sent on.
    Transfer,
}

impl ListenRole {
    /// Every role, in the order the daemon binds them.
    pub const ALL: [Self; 3] = [Self::Rendezvous, Self::Control, Self::Transfer];

    /// The role's one word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Rendezvous => "rendezvous",
            Self::Transfer => "transfer",
        }
    }

    fn from_word(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.word() == word)
    }
}

/// What every line the daemon writes for a refused bind begins with.
pub const LISTEN_LINE_PREFIX: &str = "kr-controller: cannot listen ";

/// The longest human tail of a listen line, in bytes.
const LISTEN_TAIL_BOUND: usize = 200;

/// The one line a control daemon writes to its log when it cannot bind one of its endpoints, and
/// that the command line that started it reads back.
///
/// `kr-controller: cannot listen role=<role> class=<class> object=<kind|-> pid=<n|-> os=<n|->
/// op=<step|-> path=<encoded path> daemon=<own pid> -- <human tail>`. The keys come in this order
/// and each class fills only the keys its row of the table lists; the path is percent-encoded
/// outside `[A-Za-z0-9/._-]`, so no byte of it can split the record. The tail is for a person
/// reading the log and is never read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenLine {
    /// The endpoint.
    pub role: ListenRole,
    /// Why the bind was refused.
    pub refusal: ListenRefusal,
    /// The endpoint's path, as text.
    pub path: String,
    /// The process that wrote the line.
    pub daemon: u32,
}

impl ListenLine {
    /// The line for this refusal, with a human tail made of `tail`: one line, controls replaced and
    /// at most 200 bytes. `None` for a class the daemon's own binds cannot give.
    #[must_use]
    pub fn written(&self, tail: &str) -> Option<String> {
        let (class, object, pid, os, op) = match &self.refusal {
            ListenRefusal::NotASocket { object } => {
                ("not_a_socket", object_word(*object), None, None, "-")
            }
            ListenRefusal::Held { pid } => ("held", "-", pid.map(u64::from), None, "-"),
            ListenRefusal::LockHeld => ("lock_held", "-", None, None, "-"),
            ListenRefusal::Unanswered => ("unanswered", "-", None, None, "-"),
            ListenRefusal::NameTaken => ("name_taken", "-", None, None, "-"),
            ListenRefusal::NotRemoved { os } => ("not_removed", "-", None, Some(*os), "-"),
            ListenRefusal::Other { operation, os } => ("other", "-", None, *os, operation.word()),
            ListenRefusal::Occupied => return None,
        };
        let number = |value: Option<String>| value.unwrap_or_else(|| "-".to_owned());
        let mut tail: String = tail
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect();
        if tail.len() > LISTEN_TAIL_BOUND {
            let mut end = LISTEN_TAIL_BOUND;
            while !tail.is_char_boundary(end) {
                end -= 1;
            }
            tail.truncate(end);
        }
        Some(format!(
            "{LISTEN_LINE_PREFIX}role={} class={class} object={object} pid={} os={} op={op} \
             path={} daemon={} -- {tail}",
            self.role.word(),
            number(pid.map(|pid| pid.to_string())),
            number(os.map(|os| os.to_string())),
            encode_path(&self.path),
            self.daemon,
        ))
    }

    /// The record a line holds, or `None` for a line that is not exactly the grammar: an unknown
    /// role or class, keys out of order or repeated or missing, a key that its class does not
    /// take, a number that is not plain digits, or a path that is not canonically encoded.
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        let rest = line.strip_prefix(LISTEN_LINE_PREFIX)?;
        let fields = rest
            .split_once(" -- ")
            .map_or(rest, |(fields, _tail)| fields);
        let mut values = Vec::with_capacity(8);
        for (token, key) in fields.split(' ').zip(Self::KEYS) {
            values.push(token.strip_prefix(key)?.strip_prefix('=')?);
        }
        if values.len() != Self::KEYS.len() || fields.split(' ').count() != Self::KEYS.len() {
            return None;
        }
        let [role, class, object, pid, os, op, path, daemon] = values[..] else {
            return None;
        };
        let role = ListenRole::from_word(role)?;
        let number = |text: &str| {
            (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| text.parse::<u32>().ok())
                .flatten()
        };
        let none = |text: &str| (text == "-").then_some(());
        let optional = |text: &str| match text {
            "-" => Some(None),
            other => number(other).map(Some),
        };
        let refusal = match class {
            "not_a_socket" => {
                none(pid)?;
                none(os)?;
                none(op)?;
                ListenRefusal::NotASocket {
                    object: object_from_word(object)?,
                }
            }
            "held" => {
                none(object)?;
                none(os)?;
                none(op)?;
                ListenRefusal::Held {
                    pid: optional(pid)?,
                }
            }
            "lock_held" | "unanswered" | "name_taken" => {
                none(object)?;
                none(pid)?;
                none(os)?;
                none(op)?;
                match class {
                    "lock_held" => ListenRefusal::LockHeld,
                    "unanswered" => ListenRefusal::Unanswered,
                    _ => ListenRefusal::NameTaken,
                }
            }
            "not_removed" => {
                none(object)?;
                none(pid)?;
                none(op)?;
                ListenRefusal::NotRemoved {
                    os: i32::try_from(number(os)?).ok()?,
                }
            }
            "other" => {
                none(object)?;
                none(pid)?;
                ListenRefusal::Other {
                    operation: [
                        ListenStep::Inspect,
                        ListenStep::Probe,
                        ListenStep::Lock,
                        ListenStep::Bind,
                        ListenStep::Permissions,
                    ]
                    .into_iter()
                    .find(|step| step.word() == op)?,
                    os: optional(os)?.and_then(|os| i32::try_from(os).ok()),
                }
            }
            _ => return None,
        };
        Some(Self {
            role,
            refusal,
            path: decode_path(path)?,
            daemon: number(daemon)?,
        })
    }

    const KEYS: [&'static str; 8] = [
        "role", "class", "object", "pid", "os", "op", "path", "daemon",
    ];
}

const fn object_word(object: ObjectKind) -> &'static str {
    match object {
        ObjectKind::File => "file",
        ObjectKind::Directory => "directory",
        ObjectKind::Link => "link",
        ObjectKind::Other => "other",
    }
}

fn object_from_word(word: &str) -> Option<ObjectKind> {
    [
        ObjectKind::File,
        ObjectKind::Directory,
        ObjectKind::Link,
        ObjectKind::Other,
    ]
    .into_iter()
    .find(|object| object_word(*object) == word)
}

/// `path` with every byte outside `[A-Za-z0-9/._-]` written as `%` and two upper-case hexadecimal
/// digits.
fn encode_path(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// The path an encoding stands for, or `None` for text that [`encode_path`] would not have made.
fn decode_path(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        if byte == b'%' {
            let pair = bytes.get(at + 1..at + 3)?;
            if !pair
                .iter()
                .all(|digit| digit.is_ascii_digit() || (b'A'..=b'F').contains(digit))
            {
                return None;
            }
            decoded.push(u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?);
            at += 3;
        } else if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-') {
            decoded.push(byte);
            at += 1;
        } else {
            return None;
        }
    }
    let path = String::from_utf8(decoded).ok()?;
    // A byte that needed no encoding and was encoded is not what the writer makes.
    (encode_path(&path) == text).then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_class() -> Vec<ListenRefusal> {
        let mut all = vec![
            ListenRefusal::Held { pid: Some(4242) },
            ListenRefusal::Held { pid: None },
            ListenRefusal::LockHeld,
            ListenRefusal::Unanswered,
            ListenRefusal::NotRemoved { os: 13 },
            ListenRefusal::NameTaken,
            ListenRefusal::Occupied,
            ListenRefusal::Other {
                operation: ListenStep::Lock,
                os: None,
            },
        ];
        for object in [
            ObjectKind::File,
            ObjectKind::Directory,
            ObjectKind::Link,
            ObjectKind::Other,
        ] {
            all.push(ListenRefusal::NotASocket { object });
        }
        for operation in [
            ListenStep::Inspect,
            ListenStep::Probe,
            ListenStep::Lock,
            ListenStep::Bind,
            ListenStep::Permissions,
        ] {
            all.push(ListenRefusal::Other {
                operation,
                os: Some(2),
            });
        }
        all
    }

    /// Every template has one hole for the address and one for each part, so no class says a hole
    /// open or leaves a part out.
    #[test]
    fn every_class_fills_every_hole_of_its_template() {
        for refusal in every_class() {
            let words = refusal.words();
            let holes = words.template.matches("{}").count();
            assert_eq!(
                holes,
                1 + refusal.parts().len(),
                "{refusal:?}: {}",
                words.template
            );
            let said = refusal.said("/run/p3.sock");
            assert!(said.starts_with("/run/p3.sock: "), "{said}");
            assert!(!said.contains("{}"), "{said}");
        }
    }

    /// The words that tell a person to remove something are said for an object a person can see
    /// and for a check the sentence names, and for no other class.
    #[test]
    fn only_a_thing_that_is_not_a_socket_says_to_move_it_away_without_a_check() {
        for refusal in every_class() {
            let said = refusal.said("/run/p3.sock");
            let moves = said.contains("move it away");
            match refusal {
                ListenRefusal::NotASocket { .. } => {
                    assert!(moves && said.contains("if you do not need it"), "{said}");
                }
                ListenRefusal::Unanswered => {
                    assert!(
                        moves
                            && said.contains(
                                "run lsof on it to see, and move it away only if none does"
                            ),
                        "{said}"
                    );
                }
                _ => assert!(!moves && !said.contains("remove it away"), "{said}"),
            }
            assert!(
                !said.contains("then"),
                "the host form has no instruction: {said}"
            );
        }
    }

    /// The instruction a caller adds is joined as the class joins it, and a class with none says
    /// its sentence alone.
    #[test]
    fn the_instruction_is_joined_as_each_class_joins_it() {
        let again = "run the command again";
        assert_eq!(
            ListenRefusal::Unanswered.said_then("/p", again),
            format!("{}; then {again}", ListenRefusal::Unanswered.said("/p"))
        );
        assert_eq!(
            ListenRefusal::Occupied.said_then("/p", again),
            "/p: a socket already occupies it; run the command again"
        );
        assert_eq!(
            ListenRefusal::NameTaken.said_then("/p", again),
            format!("{}; {again}", ListenRefusal::NameTaken.said("/p"))
        );
        let other = ListenRefusal::Other {
            operation: ListenStep::Bind,
            os: Some(98),
        };
        assert_eq!(other.said_then("/p", again), other.said("/p"));
        assert_eq!(
            other.said("/p"),
            format!("/p: the bind step failed ({})", os_reason(98))
        );
    }

    /// The longest class at the longest path leaves the host's bound of 400 bytes room for its
    /// own opening words.
    #[test]
    fn the_longest_class_fits_the_host_bound_at_the_longest_path() {
        let path = "p".repeat(107);
        for refusal in every_class() {
            let said = refusal.said(&path);
            assert!(
                said.len() + "the plugin host could not listen on ".len() <= 400,
                "{said}"
            );
        }
    }

    fn every_refusal() -> Vec<ListenRefusal> {
        let mut all = vec![
            ListenRefusal::Held { pid: Some(41) },
            ListenRefusal::Held { pid: None },
            ListenRefusal::LockHeld,
            ListenRefusal::Unanswered,
            ListenRefusal::NameTaken,
            ListenRefusal::NotRemoved { os: 13 },
        ];
        for object in [
            ObjectKind::File,
            ObjectKind::Directory,
            ObjectKind::Link,
            ObjectKind::Other,
        ] {
            all.push(ListenRefusal::NotASocket { object });
        }
        for operation in [
            ListenStep::Inspect,
            ListenStep::Probe,
            ListenStep::Lock,
            ListenStep::Bind,
            ListenStep::Permissions,
        ] {
            all.push(ListenRefusal::Other {
                operation,
                os: Some(2),
            });
            all.push(ListenRefusal::Other {
                operation,
                os: None,
            });
        }
        all
    }

    /// Every role, every class and every awkward path goes through the writer and the parser and
    /// comes back as it was.
    #[test]
    fn the_listen_line_round_trips_for_every_role_and_class() {
        for role in ListenRole::ALL {
            for refusal in every_refusal() {
                for path in [
                    "/run/user/1000/kr/c.sock",
                    "/tmp/a line\nbreak/c.sock",
                    "/tmp/a b=c%d/\u{e9}\u{4e2d}.sock",
                ] {
                    let line = ListenLine {
                        role,
                        refusal: refusal.clone(),
                        path: path.to_owned(),
                        daemon: 4242,
                    };
                    let written = line.written("a tail\nof text").expect("a line");
                    assert!(!written.contains('\n'), "{written:?}");
                    assert_eq!(ListenLine::parse(&written), Some(line), "{written}");
                }
            }
        }
        assert!(
            ListenLine {
                role: ListenRole::Control,
                refusal: ListenRefusal::Occupied,
                path: "/x".to_owned(),
                daemon: 1,
            }
            .written("")
            .is_none()
        );
    }

    /// A line outside the grammar is not a record: an unknown role or class, keys out of order,
    /// repeated or extra, a key its class does not take, a number that is not digits and a path
    /// that is not the writer's encoding.
    #[test]
    fn a_line_outside_the_grammar_is_refused() {
        let good = ListenLine {
            role: ListenRole::Rendezvous,
            refusal: ListenRefusal::Held { pid: Some(7) },
            path: "/r.sock".to_owned(),
            daemon: 9,
        }
        .written("tail")
        .expect("a line");
        assert!(ListenLine::parse(&good).is_some());
        let changed = |from: &str, to: &str| good.replacen(from, to, 1);
        for bad in [
            changed("role=rendezvous", "role=gateway"),
            changed("class=held", "class=gone"),
            changed("pid=7", "pid=seven"),
            changed("pid=7", "pid=+7"),
            changed("object=-", "object=file"),
            changed("os=-", "os=1"),
            changed("op=-", "op=bind"),
            changed("path=/r.sock", "path=/r sock"),
            changed("path=/r.sock", "path=%2fr.sock"),
            changed("path=/r.sock", "path=%41r.sock"),
            changed("daemon=9", "daemon=9 daemon=9"),
            changed("role=rendezvous class=held", "class=held role=rendezvous"),
            good.replacen("kr-controller: ", "kr-controller:  ", 1),
            good.split(" -- ")
                .next()
                .expect("fields")
                .replacen(" path=/r.sock", "", 1),
            "kr-controller: cannot listen".to_owned(),
        ] {
            assert_eq!(ListenLine::parse(&bad), None, "{bad}");
        }
        // The tail is for a person and is not read.
        assert!(ListenLine::parse(&good.replace(" -- tail", "")).is_some());
        assert_eq!(
            ListenLine::parse(&good.replace(" -- tail", " -- anything at all")),
            ListenLine::parse(&good)
        );
    }

    /// A tail is one line of at most 200 bytes with its controls replaced.
    #[test]
    fn a_tail_is_one_bounded_line() {
        let line = ListenLine {
            role: ListenRole::Transfer,
            refusal: ListenRefusal::Unanswered,
            path: "/t.sock".to_owned(),
            daemon: 1,
        }
        .written(&format!("{}\r\n", "\u{e9}".repeat(300)))
        .expect("a line");
        let tail = line.split_once(" -- ").expect("a tail").1;
        assert!(
            tail.len() <= 200 && !tail.contains(['\r', '\n']),
            "{tail:?}"
        );
    }
}
