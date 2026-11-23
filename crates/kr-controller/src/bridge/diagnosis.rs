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
use crate::bridge::platform::{Step, StepFailure};

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
                // The container runtime ends with 125, and `ssh` with 255, when they themselves fail.
                // Any other code is the helper's own, which the program passes through.
                Some(HelperEnd::Exited(code)) => {
                    let ended = match whose(access, *code, stage) {
                        Code::Program => program().stated(" ended with exit code "),
                        Code::Helper => {
                            program().stated(" ran, and the helper ended with exit code ")
                        }
                        // The helper was never run, so the code is not one it ended with.
                        Code::NotRun => {
                            return program()
                                .stated(" ran, and the helper could not be run")
                                .stated(before);
                        }
                    };
                    ended
                        .number(u64::from(u32::from_ne_bytes(code.to_ne_bytes())))
                        .stated(before)
                }
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
        Refusal::SessionClosed => {
            program().stated(" ran, and the environment says that session is closed")
        }
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

/// Whose end an exit code of the program that carries a helper tells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Code {
    /// The program's own: it is the program that failed.
    Program,
    /// The helper's, which the program passes on.
    Helper,
    /// The helper was never run.
    NotRun,
}

/// Returns whose end `code` tells, for a helper that ended before the environment answered
/// ([`Stage::Opening`]) or after it acknowledged the bridge ([`Stage::Read`]).
///
/// The container runtime ends with 125, and `ssh` with 255, when they themselves fail, and every
/// other code is the helper's, which they pass on. The shell that starts a program ends with 127
/// when it cannot find it and with 126 when it cannot run it, and the program passes those on
/// too: before the acknowledgement they say that the helper never ran. `wsl.exe` passes on the code
/// of what it runs, and states none that is its own that this host can tell apart: before the
/// acknowledgement every code is told as the launcher's, and after it, when the helper has run, as
/// the helper's.
const fn whose(access: EnvironmentAccess, code: i32, stage: Stage) -> Code {
    if matches!(stage, Stage::Opening) && (code == 126 || code == 127) {
        return Code::NotRun;
    }
    match (access, stage) {
        (EnvironmentAccess::Container, _) => {
            if code == 125 {
                Code::Program
            } else {
                Code::Helper
            }
        }
        (EnvironmentAccess::SshHost, _) => {
            if code == 255 {
                Code::Program
            } else {
                Code::Helper
            }
        }
        (EnvironmentAccess::WslDistribution, Stage::Read) => Code::Helper,
        _ => Code::Program,
    }
}

/// Returns the sentence for a step of a refresh that asks the platform, the look at whether the
/// environment runs or its start, and failed: the step by its role, and how it failed. What the
/// program printed and what the operating system said are not in it, except as a class and length.
#[must_use]
pub fn platform(access: EnvironmentAccess, step: Step, failure: &StepFailure) -> Sentence {
    let program = Sentence::new().stated(connection_step(launch::program_of(access)));
    let asked = match step {
        Step::Look => "when asked whether the environment is running",
        Step::Start => "when asked to start the environment",
    };
    match failure {
        StepFailure::NotFound => program.stated(" was not found"),
        StepFailure::NotStarted { message } => program
            .stated(" could not be started: ")
            .withheld(ContentClass::Message, message),
        StepFailure::Exited(code) => program
            .stated(" ended with exit code ")
            .number(u64::from(u32::from_ne_bytes(code.to_ne_bytes())))
            .stated(" ")
            .stated(asked),
        StepFailure::Signalled(signal) => program
            .stated(" was ended by signal ")
            .number(u64::from(u32::from_ne_bytes(signal.to_ne_bytes())))
            .stated(" ")
            .stated(asked),
        StepFailure::NoAnswer { seconds, ended } => program
            .stated(" did not answer within ")
            .number(*seconds)
            .stated(" seconds ")
            .stated(asked)
            .stated(if *ended {
                ", so it was ended"
            } else {
                ", and it could not be ended"
            }),
        StepFailure::Unread { message } => program
            .stated(" ran, and this host could not read what it printed ")
            .stated(asked)
            .stated(": ")
            .withheld(ContentClass::Message, message),
        StepFailure::NotWaited { message } => program
            .stated(" could not be waited for ")
            .stated(asked)
            .stated(": ")
            .withheld(ContentClass::Message, message),
        StepFailure::Unreadable => program
            .stated(" gave an answer that could not be read ")
            .stated(asked),
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
            (
                Refusal::SessionClosed,
                "the container runtime (podman) ran, and the environment says that session is \
                 closed"
                    .to_owned(),
            ),
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
        let ended = |code| Refusal::Stream {
            detail: ARRIVED.to_owned(),
            helper: Some(HelperEnd::Exited(code)),
        };
        for (access, step, code) in [
            (EnvironmentAccess::SshHost, "the SSH client (ssh)", 255),
            (
                EnvironmentAccess::Container,
                "the container runtime (podman)",
                125,
            ),
            (
                EnvironmentAccess::WslDistribution,
                "the WSL launcher (wsl.exe)",
                255,
            ),
            (EnvironmentAccess::PairedHost, "the helper program", 255),
        ] {
            assert_eq!(
                of(&ended(code), access, Stage::Opening).as_str(),
                format!("{step} ended with exit code {code} before the environment answered")
            );
        }
    }

    /// KR-REQ-18.11, the part about connection diagnostics: the container runtime ends with 125 and
    /// `ssh` with 255 when they themselves fail, and any other code is the helper's, which the
    /// program passes through, except the 126 and 127 of a shell that could not run the helper:
    /// before the acknowledgement those say that the helper never ran. `wsl.exe` has no code of its
    /// own: before the acknowledgement its codes are told as the launcher's, and after it as the
    /// helper's. The sentence says whose each is, and never that a helper that never ran ended.
    #[test]
    fn an_exit_code_is_told_as_the_programs_own_or_as_the_helpers_or_as_a_helper_that_never_ran() {
        let ended = |code| Refusal::Stream {
            detail: ARRIVED.to_owned(),
            helper: Some(HelperEnd::Exited(code)),
        };
        let before = " before the environment answered";
        let after = " after the environment acknowledged the bridge, before it answered the read";
        for (access, step, own, helpers) in [
            (
                EnvironmentAccess::Container,
                "the container runtime (podman)",
                125,
                3,
            ),
            (EnvironmentAccess::SshHost, "the SSH client (ssh)", 255, 1),
        ] {
            let said = |code, stage| of(&ended(code), access, stage);
            assert_eq!(
                said(own, Stage::Opening).as_str(),
                format!("{step} ended with exit code {own}{before}")
            );
            assert_eq!(
                said(helpers, Stage::Opening).as_str(),
                format!("{step} ran, and the helper ended with exit code {helpers}{before}")
            );
            assert_eq!(
                said(own, Stage::Read).as_str(),
                format!("{step} ended with exit code {own}{after}")
            );
            assert_eq!(
                said(helpers, Stage::Read).as_str(),
                format!("{step} ran, and the helper ended with exit code {helpers}{after}")
            );
            // The shell's 126 and 127 before the acknowledgement: the helper was never run. After
            // it the helper has run, and a code is its own.
            for code in [126, 127] {
                let not_run = said(code, Stage::Opening);
                assert_eq!(
                    not_run.as_str(),
                    format!("{step} ran, and the helper could not be run{before}")
                );
                assert!(is_composed_connection(not_run.as_str()), "{not_run}");
                assert_eq!(
                    said(code, Stage::Read).as_str(),
                    format!("{step} ran, and the helper ended with exit code {code}{after}")
                );
            }
            for stage in [Stage::Opening, Stage::Read] {
                for code in [own, helpers] {
                    let said = said(code, stage);
                    assert!(is_composed_connection(said.as_str()), "{said}");
                }
            }
        }
        // `wsl.exe`: the launcher's before the acknowledgement, the helper's after it.
        let access = EnvironmentAccess::WslDistribution;
        let step = "the WSL launcher (wsl.exe)";
        for code in [1, 255] {
            assert_eq!(
                of(&ended(code), access, Stage::Opening).as_str(),
                format!("{step} ended with exit code {code}{before}")
            );
            let read = of(&ended(code), access, Stage::Read);
            assert_eq!(
                read.as_str(),
                format!("{step} ran, and the helper ended with exit code {code}{after}")
            );
            assert!(is_composed_connection(read.as_str()), "{read}");
        }
        assert_eq!(
            of(&ended(127), access, Stage::Opening).as_str(),
            format!("{step} ran, and the helper could not be run{before}")
        );
    }

    /// KR-REQ-18.11, the part about connection diagnostics: each step of a refresh that asks the
    /// platform, the look and the start, is told by its role and by one class of failure, with the
    /// operating system's message as its class and length and none of what the program printed.
    #[test]
    fn a_platform_step_that_failed_is_told_by_its_role_and_its_class() {
        let access = EnvironmentAccess::Container;
        let step = "the container runtime (podman)";
        for (look, asked) in [
            (Step::Look, "when asked whether the environment is running"),
            (Step::Start, "when asked to start the environment"),
        ] {
            for (failure, expected) in [
                (StepFailure::NotFound, format!("{step} was not found")),
                (
                    StepFailure::NotStarted {
                        message: ARRIVED.to_owned(),
                    },
                    format!(
                        "{step} could not be started: [message withheld, {} bytes]",
                        ARRIVED.len()
                    ),
                ),
                (
                    StepFailure::Exited(125),
                    format!("{step} ended with exit code 125 {asked}"),
                ),
                (
                    StepFailure::Signalled(9),
                    format!("{step} was ended by signal 9 {asked}"),
                ),
                (
                    StepFailure::NoAnswer {
                        seconds: 60,
                        ended: true,
                    },
                    format!("{step} did not answer within 60 seconds {asked}, so it was ended"),
                ),
                (
                    StepFailure::NoAnswer {
                        seconds: 60,
                        ended: false,
                    },
                    format!(
                        "{step} did not answer within 60 seconds {asked}, and it could not be ended"
                    ),
                ),
                (
                    StepFailure::Unread {
                        message: ARRIVED.to_owned(),
                    },
                    format!(
                        "{step} ran, and this host could not read what it printed {asked}: \
                         [message withheld, {} bytes]",
                        ARRIVED.len()
                    ),
                ),
                (
                    StepFailure::NotWaited {
                        message: ARRIVED.to_owned(),
                    },
                    format!(
                        "{step} could not be waited for {asked}: [message withheld, {} bytes]",
                        ARRIVED.len()
                    ),
                ),
            ] {
                let said = platform(access, look, &failure);
                assert_eq!(said.as_str(), expected, "{failure:?}");
                assert!(is_composed_connection(said.as_str()), "{said}");
                assert!(!said.as_str().contains(ARRIVED), "{said}");
            }
        }
        // A start reads no answer, so only the look has an answer that cannot be read.
        let said = platform(access, Step::Look, &StepFailure::Unreadable);
        assert_eq!(
            said.as_str(),
            format!(
                "{step} gave an answer that could not be read when asked whether the environment is running"
            )
        );
        assert!(is_composed_connection(said.as_str()), "{said}");
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
