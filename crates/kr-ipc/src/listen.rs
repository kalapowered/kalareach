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
}
