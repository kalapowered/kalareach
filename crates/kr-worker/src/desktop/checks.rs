//! A worker's performance of the disclosed checks at the control daemon's request.
//!
//! The checks run in a session's own worker because that is the context an agent has: a platform
//! grants a screen image or the accessibility tree to a signed program, and the daemon and a worker
//! are different programs. The daemon asks over a connection of its own and the worker answers with
//! one record for each check it performed, built by [`probe`].
//!
//! Which checks are performed is decided by [`probe::performable`] from the worker's own desktop
//! context, never from the request: the request names no check, only the file the read check is
//! to read. Each run has a private directory of its own for the working files of the checks, which
//! is removed when the run ends, so two runs never meet over a file.

use std::path::{Path, PathBuf};

use kr_protocol::desktop::{
    CapabilitySubject, DesktopChecksAnswer, DesktopChecksRequest, DesktopContext,
    MAX_AUTHORISED_FILE_BYTES,
};
use kr_protocol::ids::{CapabilityRevision, SessionId};
use kr_protocol::scalars::Nullable;

use super::probe::{self, Facilities, Plan};

/// Why a request was not performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The nominated file is not an absolute path of a bounded length.
    NotAnAbsolutePath,
    /// The directory the run's working files go in could not be made.
    NoWorkingDirectory,
}

impl Refusal {
    /// What a person is told.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::NotAnAbsolutePath => {
                "the file to read has to be an absolute path of at most 4096 bytes"
            }
            Self::NoWorkingDirectory => "the checks could not make a directory of their own",
        }
    }
}

/// Performs the checks this worker's context can perform, and answers with their records.
///
/// `scratch` is the directory a private directory for this run is made in. It is made owner-only,
/// under a name no other run has, and removed whatever the run came to.
///
/// # Errors
///
/// Returns [`Refusal::NotAnAbsolutePath`] for a nominated file that is not an absolute path of a
/// bounded length, and [`Refusal::NoWorkingDirectory`] when the run's directory cannot be made.
pub fn perform(
    request: &DesktopChecksRequest,
    session_id: SessionId,
    desktop: &DesktopContext,
    scratch: &Path,
    facilities: &dyn Facilities,
) -> Result<DesktopChecksAnswer, Refusal> {
    let authorised_file = match request.authorised_file.as_ref() {
        None => None,
        Some(text) => {
            let path = PathBuf::from(text);
            if text.len() > MAX_AUTHORISED_FILE_BYTES || !path.is_absolute() {
                return Err(Refusal::NotAnAbsolutePath);
            }
            Some(path)
        }
    };
    // A name of its own for every run, whatever the daemon numbered the request: a directory an
    // earlier run could not remove is never the one a later run has to make.
    let directory = scratch.join(format!(
        "kr-checks-{}-{}",
        std::process::id(),
        kr_ipc::new_uuid()
    ));
    make_private_directory(&directory)?;
    let plan = Plan {
        authorised_file,
        scratch: directory.clone(),
        isolated: None,
    };
    let subject = CapabilitySubject {
        environment_id: request.environment_id,
        desktop_session_id: desktop.desktop_session_id.clone(),
        session_id: Nullable::some(session_id),
        application: Nullable::null(),
        terminal: Nullable::null(),
    };
    let records = probe::report(
        &probe::performable(desktop),
        &subject,
        desktop,
        // The control daemon stamps the revision it holds on every record it publishes.
        CapabilityRevision::new(0),
        &plan,
        facilities,
    );
    // Whatever a check left behind is the check's to report, and it has. A directory that cannot
    // be removed is left for the next sweep of the temporary directory.
    let _ = std::fs::remove_dir_all(&directory);
    Ok(DesktopChecksAnswer {
        request_id: request.request_id,
        session_id,
        records,
    })
}

/// Whether a run of the checks is being performed: one at a time, whichever connection asks.
///
/// The checks take a screen image and start an application, and two of them at once would meet
/// over the same facilities. A run holds the [`RunGuard`] until it ends, wherever it ends: the
/// connection that asked can go while the run goes on, and the next request still finds it busy.
#[derive(Debug, Default)]
pub struct OneRun(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl OneRun {
    /// Begins a run, or returns nothing when one is being performed.
    #[must_use]
    pub fn begin(&self) -> Option<RunGuard> {
        let was_running = self.0.swap(true, std::sync::atomic::Ordering::SeqCst);
        (!was_running).then(|| RunGuard(std::sync::Arc::clone(&self.0)))
    }
}

/// A run in progress, which ends when this is dropped.
#[derive(Debug)]
pub struct RunGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for RunGuard {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Makes a directory only this user can enter, and fails if it is already there.
fn make_private_directory(directory: &Path) -> Result<(), Refusal> {
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt as _;

        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    // A directory made in a user's own temporary directory is that user's alone by default.
    #[cfg(not(unix))]
    let builder = std::fs::DirBuilder::new();
    builder
        .create(directory)
        .map_err(|_| Refusal::NoWorkingDirectory)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use kr_protocol::desktop::{
        CapabilityState, ContainerEnvironment, DesktopAvailability, DesktopGenerationSource,
        DesktopSessionKind, DisplayServer, capabilities,
    };
    use kr_protocol::identity::{BootIdentity, BootIdentitySource, WorkerProfile};
    use kr_protocol::ids::{DesktopSessionId, EnvironmentId, RequestId};
    use kr_protocol::scalars::{Bytes, U64, Uuid};

    use super::super::probe::{Check, Outcome, Ran};
    use super::*;

    /// A stand-in that records which checks it was asked to perform and answers each as performed.
    #[derive(Default)]
    struct Recording(Mutex<Vec<Check>>);

    impl Facilities for Recording {
        fn perform(&self, check: Check, plan: &Plan) -> Ran {
            self.0.lock().expect("the record").push(check);
            // The run's directory is there while a check runs, and nobody else can enter it.
            assert!(plan.scratch.is_dir(), "{}", plan.scratch.display());
            Ran {
                check,
                facility: None,
                outcome: Outcome::Performed {
                    detail: kr_protocol::hostinfo::export::Sentence::new().stated("it ran"),
                },
            }
        }
    }

    fn desktop(graphic_access: bool) -> DesktopContext {
        DesktopContext {
            desktop_session_id: Nullable::some(
                DesktopSessionId::new(
                    "macos_security_session:user=someone:uid=501:session=1:generation=2:boot=abcd",
                )
                .expect("a desktop name"),
            ),
            kind: DesktopSessionKind::MacosSecuritySession,
            platform_session: Nullable::some("1".to_owned()),
            login_generation: Nullable::some(U64::new(2)),
            generation_source: DesktopGenerationSource::MacosSessionCreator,
            os_user: "someone".to_owned(),
            uid: Nullable::some(U64::new(501)),
            boot_identity: BootIdentity {
                source: BootIdentitySource::MacosBootSessionUuid,
                value: Bytes::new(vec![0xab, 0xcd]),
            },
            graphic_access,
            remote: false,
            availability: DesktopAvailability::Available,
            container: ContainerEnvironment::Host,
            display_server: DisplayServer::Quartz,
            compositor: Nullable::some("Aqua".to_owned()),
            worker_profile: if graphic_access {
                WorkerProfile::DesktopBound
            } else {
                WorkerProfile::HeadlessUser
            },
        }
    }

    fn request(file: Option<&str>) -> DesktopChecksRequest {
        DesktopChecksRequest {
            request_id: RequestId::new(7),
            environment_id: EnvironmentId::new(Uuid::from_bytes([3; 16])),
            authorised_file: Nullable(file.map(str::to_owned)),
        }
    }

    fn session() -> SessionId {
        SessionId::new(Uuid::from_bytes([9; 16]))
    }

    #[test]
    fn a_context_without_graphic_access_is_asked_for_the_file_read_alone() {
        let scratch = std::env::temp_dir().join(format!("kr-checks-test-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).expect("a directory of this test's own");
        let facilities = Recording::default();
        // Nominated by a path that is absolute on every platform. The stand-in reads nothing, so
        // the file need not exist.
        let nominated = scratch.join("nominated.txt").display().to_string();
        let answer = perform(
            &request(Some(&nominated)),
            session(),
            &desktop(false),
            &scratch,
            &facilities,
        )
        .expect("the checks are performed");
        assert_eq!(
            *facilities.0.lock().expect("the record"),
            vec![Check::AuthorisedFileRead],
            "no check that acts on a desktop is asked in a context with no desktop"
        );
        assert_eq!(answer.records.len(), 1);
        let record = &answer.records[0];
        assert_eq!(
            record.capability.as_str(),
            capabilities::AUTHORISED_FILE_READ
        );
        assert_eq!(record.state, CapabilityState::QualifiedAvailable);
        assert_eq!(
            record.subject.session_id.as_ref(),
            Some(&session()),
            "the record names the session whose worker performed the check"
        );
        assert_eq!(answer.session_id, session());
        assert_eq!(answer.request_id, RequestId::new(7));
        assert!(
            std::fs::read_dir(&scratch)
                .expect("the directory")
                .next()
                .is_none(),
            "the run's own directory is gone"
        );
        std::fs::remove_dir_all(&scratch).expect("this test's own directory");
    }

    #[test]
    fn one_run_at_a_time_and_a_run_that_ends_however_it_ends_frees_the_next() {
        let gate = OneRun::default();
        let first = gate.begin().expect("the first run begins");
        assert!(gate.begin().is_none(), "a second begins beside the first");
        drop(first);
        assert!(gate.begin().is_some(), "the next run begins once one ended");
        // A run that panics ends too, because the guard goes with the thread's unwinding.
        let panicking = gate.begin().expect("a run begins");
        let ended = std::thread::spawn(move || {
            let _held = panicking;
            panic!("a check that panics");
        })
        .join();
        assert!(ended.is_err());
        assert!(
            gate.begin().is_some(),
            "a run that panicked does not hold the gate"
        );
    }

    /// A run whose directory could not be removed leaves it where it was. The next run, which the
    /// daemon numbers the same, makes a directory of its own.
    #[cfg(unix)]
    #[test]
    fn a_directory_an_earlier_run_could_not_remove_does_not_stop_the_next_run() {
        use std::os::unix::fs::PermissionsExt as _;

        struct Leaving;
        impl Facilities for Leaving {
            fn perform(&self, check: Check, plan: &Plan) -> Ran {
                std::fs::write(plan.scratch.join("left"), b"a check's file").expect("a file");
                // Nothing can be removed from a directory that cannot be written to.
                std::fs::set_permissions(&plan.scratch, std::fs::Permissions::from_mode(0o500))
                    .expect("the directory is made read-only");
                Ran {
                    check,
                    facility: None,
                    outcome: Outcome::NotAttempted {
                        detail: kr_protocol::hostinfo::export::Sentence::new().stated("left"),
                    },
                }
            }
        }

        let scratch = std::env::temp_dir().join(format!("kr-checks-left-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&scratch).expect("a directory of this test's own");
        perform(
            &request(None),
            session(),
            &desktop(false),
            &scratch,
            &Leaving,
        )
        .expect("the first run is performed");
        let facilities = Recording::default();
        let second = perform(
            &request(None),
            session(),
            &desktop(false),
            &scratch,
            &facilities,
        );
        // Put back what the first run took away, so this test's directory can go.
        for entry in std::fs::read_dir(&scratch).expect("the directory") {
            let entry = entry.expect("an entry").path();
            let _ = std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o700));
        }
        std::fs::remove_dir_all(&scratch).expect("this test's own directory");
        second.expect("the next run makes a directory of its own");
    }

    #[test]
    fn a_relative_or_overlong_file_is_refused_before_anything_runs() {
        let scratch = std::env::temp_dir();
        let facilities = Recording::default();
        for file in [
            "relative/path",
            "",
            &format!("/{}", "a".repeat(MAX_AUTHORISED_FILE_BYTES)),
        ] {
            assert_eq!(
                perform(
                    &request(Some(file)),
                    session(),
                    &desktop(false),
                    &scratch,
                    &facilities
                )
                .expect_err("not a path the read check takes"),
                Refusal::NotAnAbsolutePath
            );
        }
        assert!(facilities.0.lock().expect("the record").is_empty());
    }
}
