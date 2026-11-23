//! What a person reads when a refresh could not open a bridge, or opened one that did not answer.
//!
//! A refusal's own sentence ([`Refusal`]'s `Display`) carries what the operating system and the
//! destination said, so it is for this host's own logs and for the errors it raises. This is the
//! sentence the refresh answers with, and it leaves the host in an
//! [`EnvironmentRefreshResult`](kr_protocol::identity::EnvironmentRefreshResult). It names the
//! step the host ran for the environment, by its role and then by its program (the container
//! runtime (podman), the SSH client (ssh), the WSL launcher (wsl.exe)), and how that went: it was
//! not found, it could not be started, it ended with a code, a signal ended it, it said nothing
//! within its bound, its answer could not be read, or the environment refused.
//! It is composed of words written in this source, numbers, the closed words this build defines,
//! and the class and length of everything that arrived, so the operating system's message and the
//! destination's own words are never in it.

use kr_protocol::hello::{PACKAGE_VERSION, PackageVersion};
use kr_protocol::hostinfo::export::{ContentClass, Sentence};
use kr_protocol::identity::{EnvironmentAccess, connection_step};
use kr_protocol::ids::EnvironmentId;

use crate::bridge::invoke::{HelperEnd, Refusal};
use crate::bridge::launch::{self, LaunchError};

/// How far a bridge got before it was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// The destination had not acknowledged the opening.
    Opening,
    /// The destination had acknowledged the opening, and the read that follows it was refused.
    Read,
}

/// Returns the sentence that says why a bridge to an environment of `access` did not answer, from
/// the stage it was refused at.
#[must_use]
pub fn of(refusal: &Refusal, access: EnvironmentAccess, stage: Stage) -> Sentence {
    let program = || Sentence::new().stated(connection_step(launch::program_of(access)));
    // What most of the causes that follow an answer say first: the helper ran, and what answered
    // is the matter.
    let ran = || program().stated(" ran, and the environment that answered ");
    match refusal {
        Refusal::NetworkActor { ingress } => Sentence::new()
            .stated(
                "a process bridge carries locally authenticated invocations only, and this \
                 request arrived as ",
            )
            .stated(ingress.as_str())
            .stated("; reach that environment through its own paired endpoint"),
        Refusal::AlreadyBridged => {
            Sentence::new().stated("a request crosses at most one process bridge")
        }
        Refusal::Launch(LaunchError::NotAProcessBridge { access }) => {
            Sentence::new().stated(access.as_str()).stated(
                " is not reached by a process bridge; an SSH user runs the command line on the \
                 destination host and a paired host is reached through its own endpoint",
            )
        }
        Refusal::Launch(LaunchError::Incomplete(error)) => Sentence::new()
            .stated("no helper was started, because ")
            .stated(error.describe()),
        Refusal::NotStarted {
            not_found: true, ..
        } => program().stated(" was not found"),
        Refusal::NotStarted { detail, .. } => program()
            .stated(" could not be started: ")
            .withheld(ContentClass::Message, detail),
        Refusal::Stream { helper, .. } => {
            let before = match stage {
                Stage::Opening => " before the environment answered",
                Stage::Read => {
                    " after the environment acknowledged the bridge, before it answered the read"
                }
            };
            match helper {
                Some(HelperEnd::Exited(code)) => program()
                    .stated(" ended with exit code ")
                    .number(u64::from(u32::from_ne_bytes(code.to_ne_bytes())))
                    .stated(before),
                Some(HelperEnd::Signalled(signal)) => program()
                    .stated(" was ended by signal ")
                    .number(u64::from(u32::from_ne_bytes(signal.to_ne_bytes())))
                    .stated(before),
                Some(HelperEnd::Unaccounted) | None => {
                    program().stated(" ended the connection").stated(before)
                }
            }
        }
        Refusal::Unreadable { detail } => ran()
            .stated("wrote a frame this host cannot read (")
            .withheld(ContentClass::Message, detail)
            .stated(")"),
        Refusal::NotAnAcknowledgement => match stage {
            Stage::Opening => program().stated(
                " ran, and the environment's first frame was not an acknowledgement of the opening",
            ),
            Stage::Read => program().stated(
                " ran, and the environment answered the read with something that is not an answer",
            ),
        },
        Refusal::ProtocolMajor {
            destination,
            invoker,
        } => ran()
            .stated("speaks protocol major ")
            .number(u64::from(*destination))
            .stated(", and this host speaks ")
            .number(u64::from(*invoker)),
        Refusal::WrongRole { expected, answered } => ran()
            .stated("is the ")
            .stated(answered.as_str())
            .stated(", where the opening asked for the ")
            .stated(expected.as_str()),
        Refusal::IdentityMismatch { enrolled, answered } => ran()
            .stated("is environment ")
            .identifier(answered)
            .stated(", and the enrolment names environment ")
            .identifier(enrolled)
            .stated(
                "; enrol the environment that is installed there rather than reusing this record",
            ),
        Refusal::Destination(error) => program()
            .stated(match stage {
                Stage::Opening => " ran, and the environment refused the bridge: ",
                Stage::Read => " ran, and the environment answered the read with an error: ",
            })
            .stated(error.code.as_str())
            .stated(" (")
            .withheld(ContentClass::Message, &error.message)
            .stated(")"),
        Refusal::SessionClosed => Sentence::new().stated("that session is closed"),
        Refusal::Silent { waited } => program()
            .stated(" said nothing for ")
            .number(waited.as_secs())
            .stated(" seconds, so it was ended"),
        Refusal::UserMismatch { enrolled, answered } => program()
            .stated(" ran, and the helper that answered ran as ")
            .withheld(ContentClass::Name, answered)
            .stated(", not as the user ")
            .withheld(ContentClass::Name, enrolled)
            .stated(" the enrolment names"),
        Refusal::OwnEnvironment => ran().stated(
            "is this host's own environment, so it is not another one: a socket forwarded from \
             here does not register an environment",
        ),
        Refusal::Level { destination } => match destination {
            Some(build) => version(
                version(
                    ran()
                        .stated("runs ")
                        .withheld(ContentClass::Name, build.build_id.as_str())
                        .stated(" with protocol "),
                    build.protocol_version,
                )
                .stated(", and this host speaks protocol "),
                PACKAGE_VERSION,
            )
            .stated(": update kr in the destination or here so both are of one release"),
            None => version(
                ran().stated(
                    "is of a build that states no protocol version, and this host speaks \
                     protocol ",
                ),
                PACKAGE_VERSION,
            )
            .stated(": update kr in the destination"),
        },
        Refusal::Backlog { limit } => ran()
            .stated("sent more than ")
            .number(u64::try_from(*limit).unwrap_or(u64::MAX))
            .stated(" bytes this host had not yet been asked for, so the bridge was ended"),
        Refusal::Unkillable { pid, detail, .. } => {
            let named = match pid {
                Some(pid) => program().stated(" process ").number(u64::from(*pid)),
                None => program(),
            };
            named
                .stated(" could not be ended: ")
                .withheld(ContentClass::Message, detail)
                .stated("; it may still be running, and this host no longer waits for it")
        }
    }
}

/// Returns the sentence for an access class that no process bridge reaches.
#[must_use]
pub fn not_a_process_bridge(access: EnvironmentAccess) -> Sentence {
    Sentence::new()
        .stated(access.as_str())
        .stated(" is not reached by a process bridge, so none was opened")
}

/// Returns the sentence for an environment that is not running, which no bridge is opened to.
#[must_use]
pub fn not_running() -> Sentence {
    Sentence::new().stated(
        "no bridge was opened, because this environment is not running; refresh with --start to \
         start it",
    )
}

/// Returns the sentence for a bridge that was not opened for a reason the host's own error gives.
#[must_use]
pub fn not_opened(reason: &str) -> Sentence {
    Sentence::new()
        .stated("no bridge was opened, because ")
        .withheld(ContentClass::Message, reason)
}

/// Returns the sentence for a destination that answered on its own local channel, `over_ssh` when
/// the helper there was asked once and no request crossed ssh.
#[must_use]
pub fn answered(environment: &EnvironmentId, user: &str, over_ssh: bool) -> Sentence {
    Sentence::new()
        .stated("environment ")
        .identifier(environment)
        .stated(" answered as ")
        .withheld(ContentClass::Name, user)
        .stated(if over_ssh {
            " on the helper installed there, over ssh; no request crosses ssh"
        } else {
            " over its own local channel"
        })
}

/// Returns the sentence for an answer that is of no use because the record it was asked for
/// changed while the bridge was open, `over_ssh` for a helper that was asked once over ssh.
#[must_use]
pub fn record_changed(over_ssh: bool) -> Sentence {
    Sentence::new().stated(if over_ssh {
        "this environment's record changed while its helper was asked, so what answered says \
         nothing about what is recorded now"
    } else {
        "this environment's record changed while the bridge was open, so what answered says \
         nothing about what is recorded now"
    })
}

/// Returns the sentence for a bridge that answered and whose answer could not be recorded.
#[must_use]
pub fn answered_not_recorded(reason: &str) -> Sentence {
    Sentence::new()
        .stated("the bridge answered, and this host did not record that, because ")
        .withheld(ContentClass::Message, reason)
}

/// Appends that a refusal could not be recorded either, for the reason the host's own error gives.
#[must_use]
pub fn and_not_recorded(sentence: Sentence, reason: &str) -> Sentence {
    sentence
        .stated("; and this host did not record that, because ")
        .withheld(ContentClass::Message, reason)
}

/// Appends a protocol version as its three numbers.
fn version(sentence: Sentence, version: PackageVersion) -> Sentence {
    sentence
        .number(u64::from(version.major))
        .stated(".")
        .number(u64::from(version.minor))
        .stated(".")
        .number(u64::from(version.patch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::actor::ActorIngress;
    use kr_protocol::error::{ErrorCode, ProtocolError};
    use kr_protocol::hello::PackageVersion;
    use kr_protocol::identity::is_composed_connection;
    use kr_protocol::ids::{BuildId, EnvironmentId};
    use kr_protocol::local::{LocalBuild, LocalRole};
    use kr_protocol::scalars::Uuid;

    /// What a destination, the operating system or the enrolment's owner wrote. None of it may be
    /// in a sentence.
    const ARRIVED: &str = "kr-test-arrived-text";

    fn environment(byte: u8) -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([byte; 16]))
    }

    /// KR-REQ-18.11, the part about connection diagnostics: every refusal a bridge can end in has
    /// a sentence that names the program the host ran for the environment and what went wrong, and
    /// gives everything that arrived (the operating system's message, a destination's own words,
    /// the names of a user and a build) as its class and length. The same table is the one a
    /// person's lines are checked against.
    #[test]
    fn every_refusal_is_told_with_its_program_and_without_what_arrived() {
        let level = |destination| Refusal::Level { destination };
        let table: Vec<(Refusal, String)> = vec![
            (
                Refusal::NetworkActor {
                    ingress: ActorIngress::PairedDevice,
                },
                "a process bridge carries locally authenticated invocations only, and this \
                 request arrived as paired_device; reach that environment through its own \
                 paired endpoint"
                    .to_owned(),
            ),
            (
                Refusal::AlreadyBridged,
                "a request crosses at most one process bridge".to_owned(),
            ),
            (
                Refusal::Launch(LaunchError::NotAProcessBridge {
                    access: EnvironmentAccess::PairedHost,
                }),
                "paired_host is not reached by a process bridge; an SSH user runs the command \
                 line on the destination host and a paired host is reached through its own \
                 endpoint"
                    .to_owned(),
            ),
            (
                Refusal::Launch(LaunchError::Incomplete(
                    kr_protocol::identity::EnrolmentError::EmptyUser,
                )),
                "no helper was started, because an enrolment carries the operating-system user \
                 it runs as"
                    .to_owned(),
            ),
            (
                Refusal::NotStarted {
                    program: "podman".to_owned(),
                    detail: ARRIVED.to_owned(),
                    not_found: false,
                },
                format!(
                    "the container runtime (podman) could not be started: [message withheld, {} bytes]",
                    ARRIVED.len()
                ),
            ),
            (
                Refusal::Stream {
                    detail: ARRIVED.to_owned(),
                    helper: Some(HelperEnd::Exited(125)),
                },
                "the container runtime (podman) ended with exit code 125 before the environment answered".to_owned(),
            ),
            (
                Refusal::Stream {
                    detail: ARRIVED.to_owned(),
                    helper: Some(HelperEnd::Signalled(9)),
                },
                "the container runtime (podman) was ended by signal 9 before the environment answered".to_owned(),
            ),
            (
                Refusal::Stream {
                    detail: ARRIVED.to_owned(),
                    helper: Some(HelperEnd::Unaccounted),
                },
                "the container runtime (podman) ended the connection before the environment answered".to_owned(),
            ),
            (
                Refusal::Stream {
                    detail: ARRIVED.to_owned(),
                    helper: None,
                },
                "the container runtime (podman) ended the connection before the environment answered".to_owned(),
            ),
            (
                Refusal::Unreadable {
                    detail: ARRIVED.to_owned(),
                },
                format!(
                    "the container runtime (podman) ran, and the environment that answered wrote a frame this host \
                     cannot read ([message withheld, {} bytes])",
                    ARRIVED.len()
                ),
            ),
            (
                Refusal::NotAnAcknowledgement,
                "the container runtime (podman) ran, and the environment's first frame was not an acknowledgement of the \
                 opening"
                    .to_owned(),
            ),
            (
                Refusal::ProtocolMajor {
                    destination: 9,
                    invoker: 0,
                },
                "the container runtime (podman) ran, and the environment that answered speaks protocol major 9, and \
                 this host speaks 0"
                    .to_owned(),
            ),
            (
                Refusal::WrongRole {
                    expected: LocalRole::Controller,
                    answered: LocalRole::Worker,
                },
                format!(
                    "the container runtime (podman) ran, and the environment that answered is the {}, where the opening \
                     asked for the {}",
                    LocalRole::Worker.as_str(),
                    LocalRole::Controller.as_str()
                ),
            ),
            (
                Refusal::IdentityMismatch {
                    enrolled: environment(1),
                    answered: environment(2),
                },
                format!(
                    "the container runtime (podman) ran, and the environment that answered is environment {}, and the \
                     enrolment names environment {}; enrol the environment that is installed \
                     there rather than reusing this record",
                    environment(2),
                    environment(1)
                ),
            ),
            (
                Refusal::Destination(ProtocolError::new(ErrorCode::PermissionDenied, ARRIVED)),
                format!(
                    "the container runtime (podman) ran, and the environment refused the bridge: PERMISSION_DENIED \
                     ([message withheld, {} bytes])",
                    ARRIVED.len()
                ),
            ),
            (Refusal::SessionClosed, "that session is closed".to_owned()),
            (
                Refusal::Silent {
                    waited: std::time::Duration::from_secs(20),
                },
                "the container runtime (podman) said nothing for 20 seconds, so it was ended".to_owned(),
            ),
            (
                Refusal::UserMismatch {
                    enrolled: ARRIVED.to_owned(),
                    answered: "another".to_owned(),
                },
                format!(
                    "the container runtime (podman) ran, and the helper that answered ran as [name withheld, 7 bytes], not \
                     as the user [name withheld, {} bytes] the enrolment names",
                    ARRIVED.len()
                ),
            ),
            (
                Refusal::OwnEnvironment,
                "the container runtime (podman) ran, and the environment that answered is this host's own environment, \
                 so it is not another one: a socket forwarded from here does not register an \
                 environment"
                    .to_owned(),
            ),
            (
                level(Some(LocalBuild {
                    build_id: BuildId::new(ARRIVED).expect("a build"),
                    protocol_version: PackageVersion {
                        major: 0,
                        minor: 1,
                        patch: 2,
                    },
                })),
                format!(
                    "the container runtime (podman) ran, and the environment that answered runs [name withheld, {} \
                     bytes] with protocol 0.1.2, and this host speaks protocol {}.{}.{}: update \
                     kr in the destination or here so both are of one release",
                    ARRIVED.len(),
                    PACKAGE_VERSION.major,
                    PACKAGE_VERSION.minor,
                    PACKAGE_VERSION.patch
                ),
            ),
            (
                level(None),
                format!(
                    "the container runtime (podman) ran, and the environment that answered is of a build that states no \
                     protocol version, and this host speaks protocol {}.{}.{}: update kr in the \
                     destination",
                    PACKAGE_VERSION.major, PACKAGE_VERSION.minor, PACKAGE_VERSION.patch
                ),
            ),
            (
                Refusal::Backlog { limit: 1_048_576 },
                "the container runtime (podman) ran, and the environment that answered sent more than 1048576 bytes \
                 this host had not yet been asked for, so the bridge was ended"
                    .to_owned(),
            ),
            (
                Refusal::Unkillable {
                    program: "podman".to_owned(),
                    pid: Some(4242),
                    detail: ARRIVED.to_owned(),
                    answered: false,
                },
                format!(
                    "the container runtime (podman) process 4242 could not be ended: [message withheld, {} bytes]; it \
                     may still be running, and this host no longer waits for it",
                    ARRIVED.len()
                ),
            ),
            (
                Refusal::Unkillable {
                    program: "podman".to_owned(),
                    pid: None,
                    detail: ARRIVED.to_owned(),
                    answered: true,
                },
                format!(
                    "the container runtime (podman) could not be ended: [message withheld, {} bytes]; it may still be \
                     running, and this host no longer waits for it",
                    ARRIVED.len()
                ),
            ),
        ];
        for (refusal, expected) in table {
            let said = of(&refusal, EnvironmentAccess::Container, Stage::Opening);
            assert_eq!(said.as_str(), expected, "{refusal:?}");
            assert!(is_composed_connection(said.as_str()), "{refusal:?}: {said}");
            assert!(!said.as_str().contains(ARRIVED), "{refusal:?}: {said}");
        }
    }

    /// KR-REQ-18.11, the part about connection diagnostics: each access class names its own step
    /// by its role and then by the program this build starts for it, and an access class with no
    /// program says so in the same place.
    #[test]
    fn each_access_class_names_the_step_the_host_runs_for_it() {
        let ended = Refusal::Stream {
            detail: ARRIVED.to_owned(),
            helper: Some(HelperEnd::Exited(255)),
        };
        for (access, step) in [
            (EnvironmentAccess::SshHost, "the SSH client (ssh)"),
            (
                EnvironmentAccess::Container,
                "the container runtime (podman)",
            ),
            (
                EnvironmentAccess::WslDistribution,
                "the WSL launcher (wsl.exe)",
            ),
            (EnvironmentAccess::PairedHost, "the helper program"),
        ] {
            assert_eq!(
                of(&ended, access, Stage::Opening).as_str(),
                format!("{step} ended with exit code 255 before the environment answered")
            );
        }
    }

    /// KR-REQ-18.11, the part about connection diagnostics: once the destination has acknowledged
    /// the opening, a helper that ends, an error answer to the read and a frame that is not an
    /// answer are told as what happened to the read, and not as a bridge that was not opened.
    #[test]
    fn a_refusal_of_the_read_is_told_as_one_after_the_acknowledgement() {
        let after = " after the environment acknowledged the bridge, before it answered the read";
        for (refusal, expected) in [
            (
                Refusal::Stream {
                    detail: ARRIVED.to_owned(),
                    helper: Some(HelperEnd::Exited(125)),
                },
                format!("the container runtime (podman) ended with exit code 125{after}"),
            ),
            (
                Refusal::Stream {
                    detail: ARRIVED.to_owned(),
                    helper: Some(HelperEnd::Signalled(9)),
                },
                format!("the container runtime (podman) was ended by signal 9{after}"),
            ),
            (
                Refusal::Stream {
                    detail: ARRIVED.to_owned(),
                    helper: Some(HelperEnd::Unaccounted),
                },
                format!("the container runtime (podman) ended the connection{after}"),
            ),
            (
                Refusal::Destination(ProtocolError::new(ErrorCode::PermissionDenied, ARRIVED)),
                format!(
                    "the container runtime (podman) ran, and the environment answered the read with an error: \
                     PERMISSION_DENIED ([message withheld, {} bytes])",
                    ARRIVED.len()
                ),
            ),
            (
                Refusal::NotAnAcknowledgement,
                "the container runtime (podman) ran, and the environment answered the read with something that is not an \
                 answer"
                    .to_owned(),
            ),
        ] {
            let said = of(&refusal, EnvironmentAccess::Container, Stage::Read);
            assert_eq!(said.as_str(), expected, "{refusal:?}");
            assert!(is_composed_connection(said.as_str()), "{refusal:?}: {said}");
            assert!(!said.as_str().contains(ARRIVED), "{refusal:?}: {said}");
        }
    }

    /// KR-REQ-18.11, the part about connection diagnostics: every sentence the host composes for
    /// what opening a bridge did, the ones that are not a refusal of it included, is one the
    /// command line recognises, with each program the host names.
    #[test]
    fn every_sentence_the_host_composes_is_one_the_command_line_recognises() {
        let ended = Refusal::Stream {
            detail: ARRIVED.to_owned(),
            helper: Some(HelperEnd::Exited(1)),
        };
        let mut sentences = vec![
            not_a_process_bridge(EnvironmentAccess::PairedHost),
            not_running(),
            not_opened(ARRIVED),
            answered(&environment(3), ARRIVED, false),
            answered(&environment(3), ARRIVED, true),
            record_changed(false),
            record_changed(true),
            answered_not_recorded(ARRIVED),
            and_not_recorded(
                of(&ended, EnvironmentAccess::Container, Stage::Read),
                ARRIVED,
            ),
        ];
        for access in [
            EnvironmentAccess::SshHost,
            EnvironmentAccess::Container,
            EnvironmentAccess::WslDistribution,
            EnvironmentAccess::PairedHost,
        ] {
            sentences.push(of(&ended, access, Stage::Opening));
        }
        for error in kr_protocol::identity::EnrolmentError::ALL {
            sentences.push(of(
                &Refusal::Launch(LaunchError::Incomplete(error)),
                EnvironmentAccess::Container,
                Stage::Opening,
            ));
        }
        for sentence in sentences {
            assert!(is_composed_connection(sentence.as_str()), "{sentence}");
            assert!(!sentence.as_str().contains(ARRIVED), "{sentence}");
        }
    }
}
