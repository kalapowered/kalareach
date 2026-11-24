//! The Wayland screen-copy protocol route: one image of every output, asked of the compositor.
//!
//! `grim` asks the compositor for its outputs through the screen-copy protocol that the wlroots
//! family of compositors implements, and writes them as one PNG. The route exists for a compositor
//! in that family and a `grim` on the search path, and for nothing else: the compositor's name only
//! selects the row, and an image that passes the payload rules is what establishes anything. A
//! compositor outside the family, Weston among them, has no row, so no check runs against it and
//! the platform's own record stands with its words that no route is established.
//!
//! No step here reads a version. A tool that cannot perform the operation says so in its own
//! words, and those words decide: `grim` against a compositor with no screen-copy protocol prints
//! that the compositor does not support it and exits with a failure, which is an operation the tool
//! cannot perform, apart from any other failure. The tool's own file is digested by the caller, so a
//! replaced `grim` is a changed identity.

use std::ffi::OsStr;
use std::path::Path;

use kr_protocol::desktop::{DesktopContext, DisplayServer};
use kr_protocol::hostinfo::export::{ContentClass, Sentence};

use super::capability::{installed_in, wlroots};
use super::payload;
use super::probe::{
    Check, Exit, Outcome, Plan, Ran, Setting, bounded_with, failed, judge, read_within,
};
use super::routes::{Asking, Operation, Program, Route};

/// The screen-copy protocol route.
///
/// Some compositors ask before a program may copy the screen, so a check on this route that did not
/// answer says it may have been waiting for that, and never that a grant is missing.
pub(super) const SCREEN_COPY: Route = Route {
    name: "wayland-screen-copy",
    asking: Asking::Maybe,
};

/// The program that performs the route, by the name it is looked for under.
const TOOL: &str = "grim";

/// What `grim` prints, and exits with a failure, when the compositor has no screen-copy protocol.
const MISSING_PROTOCOL: &str = "compositor doesn't support wlr-screencopy-unstable-v1";

/// The file the tool is asked to write, in the check's own directory.
const IMAGE: &str = "screen-image-check.png";

/// Resolves a check to this route where there is one: the screen image on a Wayland desktop whose
/// compositor is in the wlroots family.
///
/// A program that is not installed is a route whose program is absent, which the facility reports
/// as a missing installation. `grimblast` and every other tool have no row.
pub(super) fn resolve(
    check: Check,
    desktop: &DesktopContext,
    search: Option<&OsStr>,
) -> Option<Operation> {
    (check == Check::ScreenImage
        && desktop.display_server == DisplayServer::Wayland
        && in_the_family(desktop))
    .then(|| Operation {
        check,
        route: SCREEN_COPY,
        // A bare name has no path to keep for a record of a program that is not installed.
        program: installed_in(TOOL, search).map_or(Program::Absent(None), Program::Tool),
        target: None,
    })
}

/// Whether the compositor the context names is one the screen-copy protocol is known to be there
/// for. The class selects the row and is never a success.
fn in_the_family(desktop: &DesktopContext) -> bool {
    desktop
        .compositor
        .as_ref()
        .is_some_and(|name| wlroots(&name.to_ascii_lowercase()))
}

/// Whether an operation is this route's.
pub(super) fn performs(operation: &Operation) -> bool {
    operation.route == SCREEN_COPY
}

/// Performs the route's operation.
pub(super) fn perform(
    check: Check,
    plan: &Plan,
    setting: &Setting<'_>,
    operation: &Operation,
) -> Ran {
    let Program::Tool(tool) = &operation.program else {
        return Ran {
            check,
            facility: operation.program.named_path().map(str::to_owned),
            outcome: Outcome::FacilityMissing,
        };
    };
    screen_copy(check, plan, setting, tool)
}

/// Asks the compositor for one image of every output, measures it and keeps nothing.
///
/// The tool writes to a file, so the image goes into this check's own directory, is read into
/// memory, measured against the payload rules and removed before the check answers, whichever way
/// it went. The tool acts on the display this worker's own variables name, and on none that the
/// worker lacks.
fn screen_copy(check: Check, plan: &Plan, setting: &Setting<'_>, tool: &str) -> Ran {
    let image = plan.scratch.join(IMAGE);
    // A file from before is not this run's image.
    let _ = std::fs::remove_file(&image);
    let variables = setting.variables;
    let ran = bounded_with(
        check,
        tool,
        &[&image.to_string_lossy()],
        &[
            ("WAYLAND_DISPLAY", variables.wayland_display.as_deref()),
            ("XDG_RUNTIME_DIR", variables.runtime_dir.as_deref()),
        ],
        plan,
        setting.deadline,
    );
    let outcome = match ran.exit {
        Exit::Succeeded(_) => match read_within(&image, setting.deadline) {
            // The image could not be read before the check's time ran out.
            None => Outcome::TimedOut,
            Some(bytes) => match payload::png(&bytes) {
                Ok(_) => Outcome::Performed {
                    detail: Sentence::new()
                        .stated("it read a ")
                        .number(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                        .stated("-byte image of every output into memory and kept none of it"),
                },
                Err(fault) => Outcome::NotAttempted {
                    detail: fault.left_no_usable_image(),
                },
            },
        },
        // The tool's own words for a compositor that does not have the protocol. That is an
        // operation the tool cannot perform here, which no installation and no permission changes.
        Exit::Failed(said) if said.contains(MISSING_PROTOCOL) => Outcome::Unsupported {
            detail: no_protocol(setting.desktop, &said),
        },
        Exit::Failed(said) => Outcome::NotAttempted {
            detail: failed(&said),
        },
        Exit::Unfinished(outcome) => outcome,
    };
    // Removed whatever happened: an image outliving the check is the one thing this must not leave
    // behind, and a removal that failed is said rather than passed over.
    let removal = match std::fs::remove_file(&image) {
        Ok(()) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => Some(error.to_string()),
    };
    Ran {
        check,
        facility: ran.facility,
        outcome: match removal {
            None => outcome,
            Some(error) => left(outcome, &image, &error),
        },
    }
}

/// What the tool said about a compositor that has no screen-copy protocol, naming the compositor
/// by its class and length and the tool's words the same way.
fn no_protocol(desktop: &DesktopContext, said: &str) -> Sentence {
    let mut detail = Sentence::new().stated("the screen-copy tool said that this compositor");
    if let Some(name) = desktop.compositor.as_ref() {
        detail = detail
            .stated(", ")
            .withheld(ContentClass::Name, name)
            .stated(",");
    }
    detail
        .stated(" does not support the screen-copy protocol it asks for: ")
        .withheld(ContentClass::Message, said)
}

/// An outcome with the image the check could not remove said as part of it.
fn left(outcome: Outcome, image: &Path, error: &str) -> Outcome {
    let behind = |detail: Sentence| {
        detail
            .stated(", and it could not remove ")
            .path(image)
            .stated(": ")
            .withheld(ContentClass::Message, error)
    };
    match outcome {
        Outcome::Performed { detail } => Outcome::Performed {
            detail: behind(detail),
        },
        Outcome::Unsupported { detail } => Outcome::Unsupported {
            detail: behind(detail),
        },
        Outcome::NotAttempted { detail } => Outcome::NotAttempted {
            detail: behind(detail),
        },
        // An outcome with no words of its own is said in the words its judgement gives it.
        other => Outcome::NotAttempted {
            detail: behind(
                judge(Check::ScreenImage, &other, SCREEN_COPY.asking)
                    .2
                    .unwrap_or_default(),
            ),
        },
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::time::Duration;

    use kr_protocol::desktop::{
        CapabilityEvidenceSource, CapabilityRecord, CapabilityState, CapabilitySubject,
        ContainerEnvironment, DesktopAvailability, DesktopGenerationSource, DesktopSessionKind,
    };
    use kr_protocol::identity::{BootIdentity, BootIdentitySource, WorkerProfile};
    use kr_protocol::ids::{CapabilityRevision, DesktopSessionId, EnvironmentId, SessionId};
    use kr_protocol::scalars::{Bytes, Nullable, U64, Uuid};

    use super::super::payload::{self, tests::whole};
    use super::super::probe::{self, Deadline, Facilities as _, Platform};
    use super::super::routes::{Surroundings, Variables};
    use super::*;

    /// A folder of a case's own, removed with it whatever came of the case.
    struct Folder(PathBuf);

    impl Folder {
        fn new() -> Self {
            Self::under(&std::env::temp_dir().join(format!("kr-wayland-{}", kr_ipc::new_uuid())))
        }

        /// A runtime folder for a compositor, whose socket names a path of a hundred bytes cannot
        /// hold: a short name directly under `/tmp`.
        #[cfg(target_os = "linux")]
        fn runtime() -> Self {
            let unique = kr_ipc::new_uuid().to_string();
            Self::under(&Path::new("/tmp").join(format!("kr-wl-{}", &unique[..8])))
        }

        fn under(path: &Path) -> Self {
            let path = path.to_path_buf();
            std::fs::create_dir_all(&path).expect("a folder");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("owner only");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, bytes).expect("a file");
            path
        }

        /// A program of the case's own, which stands in for `grim`.
        fn program(&self, name: &str, body: &str) -> PathBuf {
            let path = self.file(
                name,
                format!("#!/bin/sh\nif [ \"$1\" = --ready ]; then exit 0; fi\n{body}\n").as_bytes(),
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("a program");
            // A child that another case started while this file was open for writing holds it
            // until that child has started its own program, and a file held that way cannot be
            // run. It is run once here, to nothing, until it can be.
            loop {
                match std::process::Command::new(&path).arg("--ready").status() {
                    Ok(_) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("a stand-in that does not run: {error}"),
                }
            }
            path
        }

        /// A program that writes the bytes it is given as the image it was asked for.
        fn writes(&self, name: &str, image: &[u8]) -> PathBuf {
            let payload = self.file(&format!("{name}.payload"), image);
            self.program(name, &format!("cp '{}' \"$1\"", payload.display()))
        }
    }

    impl Drop for Folder {
        fn drop(&mut self) {
            // A case that made a folder unwritable gives it back before it is removed.
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A Linux desktop of the case's own, on Wayland, running the compositor named.
    fn desktop(compositor: Option<&str>) -> DesktopContext {
        DesktopContext {
            desktop_session_id: Nullable::some(
                DesktopSessionId::new("test:uid=1:session=1:generation=1:boot=00").expect("a name"),
            ),
            kind: DesktopSessionKind::LinuxLogind,
            platform_session: Nullable::some("1".to_owned()),
            login_generation: Nullable::some(U64::new(1)),
            generation_source: DesktopGenerationSource::LinuxSessionLeader,
            os_user: "someone".to_owned(),
            uid: Nullable::some(U64::new(1_000)),
            boot_identity: BootIdentity {
                source: BootIdentitySource::LinuxBootId,
                value: Bytes::new(vec![0]),
            },
            graphic_access: true,
            remote: false,
            availability: DesktopAvailability::Available,
            container: ContainerEnvironment::Host,
            display_server: DisplayServer::Wayland,
            compositor: Nullable(compositor.map(str::to_owned)),
            worker_profile: WorkerProfile::DesktopBound,
        }
    }

    fn subject() -> CapabilitySubject {
        CapabilitySubject {
            environment_id: EnvironmentId::new(Uuid::from_bytes([7; 16])),
            desktop_session_id: Nullable::null(),
            session_id: Nullable::<SessionId>::null(),
            application: Nullable::null(),
            terminal: Nullable::null(),
        }
    }

    /// The worker's own variables, with a search path and no session bus.
    fn variables(search: &Path) -> Variables {
        Variables {
            wayland_display: Some("wayland-1".to_owned()),
            runtime_dir: Some("/run/user/1000".to_owned()),
            search: Some(search.as_os_str().to_owned()),
            ..Variables::default()
        }
    }

    /// The screen image check, asked of a worker that holds this desktop and these variables.
    fn asked(
        desktop: &DesktopContext,
        variables: Variables,
        scratch: &Path,
    ) -> Vec<CapabilityRecord> {
        let surroundings = Surroundings {
            desktop: desktop.clone(),
            variables,
        };
        let source = |_: &Deadline| surroundings.clone();
        probe::report(
            &surroundings,
            &[Check::ScreenImage],
            &subject(),
            &source,
            CapabilityRevision::new(3),
            &Plan::in_directory(scratch),
            &Platform,
        )
    }

    fn only(mut records: Vec<CapabilityRecord>) -> CapabilityRecord {
        assert_eq!(records.len(), 1, "one record: {records:?}");
        records.remove(0)
    }

    fn reason(record: &CapabilityRecord) -> String {
        record
            .disabled_reason
            .as_ref()
            .map(Sentence::as_str)
            .expect("a reason")
            .to_owned()
    }

    fn left_in(scratch: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(scratch)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    const FAMILY: [&str; 6] = ["sway", "river", "hyprland", "wayfire", "labwc", "niri"];

    /// KR-REQ-03.29, LP-1: the row exists for a compositor in the family and for `grim`, and for
    /// nothing else. A compositor outside the family, Weston among them, resolves no operation
    /// whatever the search path holds, and a tool that is not `grim` has no row.
    #[test]
    fn the_row_is_the_family_and_grim_and_nothing_else() {
        let tools = Folder::new();
        let grim = tools.program("grim", "exit 0");
        let only_grimblast = Folder::new();
        only_grimblast.program("grimblast", "exit 0");
        let empty = Folder::new();
        for name in FAMILY.into_iter().chain(["Sway", "Hyprland"]) {
            let operation = resolve(
                Check::ScreenImage,
                &desktop(Some(name)),
                Some(tools.path().as_os_str()),
            )
            .unwrap_or_else(|| panic!("a row for {name}"));
            assert_eq!(operation.route, SCREEN_COPY);
            assert_eq!(operation.program, Program::Tool(grim.display().to_string()));
        }
        // Outside the family, with `grim` installed, there is no row.
        for compositor in [Some("weston"), Some("gnome"), Some("kde"), Some(""), None] {
            assert_eq!(
                resolve(
                    Check::ScreenImage,
                    &desktop(compositor),
                    Some(tools.path().as_os_str())
                ),
                None,
                "no row for {compositor:?}"
            );
        }
        // In the family, a tool that is not installed is an absent program, and `grimblast`, which
        // is installed, is no row of this route.
        for search in [
            Some(empty.path().as_os_str()),
            Some(only_grimblast.path().as_os_str()),
            None,
        ] {
            let operation = resolve(Check::ScreenImage, &desktop(Some("sway")), search)
                .expect("a row whose program is absent");
            assert_eq!(operation.program, Program::Absent(None));
        }
        // Another check, and another display server, have none.
        assert_eq!(
            resolve(
                Check::AccessibleElement,
                &desktop(Some("sway")),
                Some(tools.path().as_os_str())
            ),
            None
        );
        let mut x11 = desktop(Some("sway"));
        x11.display_server = DisplayServer::X11;
        assert_eq!(
            resolve(Check::ScreenImage, &x11, Some(tools.path().as_os_str())),
            None
        );
    }

    /// KR-REQ-03.29, LP-2: a tool that prints the words for a missing screen-copy protocol, in a
    /// compositor of the family, is an operation it cannot perform: the state is incompatible, said
    /// by the compositor's class and length. Any other failure is a check that established nothing.
    /// The same holds after a route that worked loses the protocol.
    #[test]
    fn a_missing_protocol_is_incompatible_and_any_other_failure_is_not() {
        let tools = Folder::new();
        let scratch = Folder::new();
        tools.program(
            "grim",
            "echo \"compositor doesn't support wlr-screencopy-unstable-v1\" >&2\nexit 1",
        );
        let record = only(asked(
            &desktop(Some("sway")),
            variables(tools.path()),
            scratch.path(),
        ));
        assert_eq!(record.state, CapabilityState::Incompatible);
        assert_eq!(
            record.evidence_source,
            CapabilityEvidenceSource::DisclosedProbe
        );
        let said = reason(&record);
        assert!(
            said.contains("does not support the screen-copy protocol it asks for"),
            "{said}"
        );
        assert!(
            !said.contains("wlr-screencopy"),
            "the words are not repeated: {said}"
        );
        assert!(
            !said.contains("sway"),
            "the compositor is said by class: {said}"
        );
        assert!(
            said.contains("another tool or route may still work"),
            "{said}"
        );

        // Any other non-zero exit, with whatever words, is a check that established nothing.
        for body in [
            "echo 'failed to create display' >&2\nexit 1",
            "echo \"compositor doesn't support wlr-screencopy-unstable-v2\" >&2\nexit 1",
            "exit 3",
        ] {
            let other = Folder::new();
            other.program("grim", body);
            let record = only(asked(
                &desktop(Some("sway")),
                variables(other.path()),
                scratch.path(),
            ));
            assert_eq!(
                record.state,
                CapabilityState::TemporarilyUnavailable,
                "{body}"
            );
            assert_eq!(
                record.evidence_source,
                CapabilityEvidenceSource::DisclosedProbe
            );
            assert!(
                reason(&record).contains("this check established nothing"),
                "{}",
                reason(&record)
            );
        }

        // A route that worked and then lost the protocol: the same program, a second run.
        let route = Folder::new();
        let image = route.file("image.png", &whole(1280, 720));
        route.program(
            "grim",
            &format!(
                "if [ -e '{marker}' ]; then\n  echo \"compositor doesn't support \
                 wlr-screencopy-unstable-v1\" >&2\n  exit 1\nfi\n: > '{marker}'\ncp '{image}' \"$1\"",
                marker = route.path().join("ran").display(),
                image = image.display(),
            ),
        );
        let first = only(asked(
            &desktop(Some("sway")),
            variables(route.path()),
            scratch.path(),
        ));
        assert_eq!(first.state, CapabilityState::QualifiedAvailable);
        let second = only(asked(
            &desktop(Some("sway")),
            variables(route.path()),
            scratch.path(),
        ));
        assert_eq!(second.state, CapabilityState::Incompatible);
    }

    /// KR-REQ-03.29, LP-3: an image is accepted only as a whole PNG, and is removed from the
    /// check's own directory whatever came of it. A header alone, a payload that stops short, a
    /// file of another format, an empty file and no file establish nothing, and a removal that
    /// failed is said. The case gives the facility a scratch directory of its own.
    #[test]
    fn an_image_counts_only_as_a_whole_png_and_is_removed() {
        let whole_png = whole(1280, 720);
        let header_only = whole_png[..8 + 25].to_vec();
        let cut_short = whole_png[..whole_png.len() - 20].to_vec();
        let wanted = |fault: payload::Fault| format!("left no usable image: {}", fault.words());
        let cases: [(&str, Vec<u8>, Option<String>); 6] = [
            ("a whole image", whole_png.clone(), None),
            (
                "a header alone",
                header_only,
                Some(wanted(payload::Fault::CutShort)),
            ),
            (
                "a payload that stops short",
                cut_short,
                Some(wanted(payload::Fault::CutShort)),
            ),
            (
                "another format",
                b"%!PS-Adobe-3.0\n%%Creator: (ImageMagick)\n".to_vec(),
                Some(wanted(payload::Fault::NotThisFormat)),
            ),
            (
                "an empty file",
                Vec::new(),
                Some(wanted(payload::Fault::Empty)),
            ),
            (
                "a signature and nothing else",
                whole_png[..8].to_vec(),
                Some(wanted(payload::Fault::CutShort)),
            ),
        ];
        for (name, image, failure) in cases {
            let tools = Folder::new();
            let scratch = Folder::new();
            tools.writes("grim", &image);
            let record = only(asked(
                &desktop(Some("sway")),
                variables(tools.path()),
                scratch.path(),
            ));
            match failure {
                None => {
                    assert_eq!(record.state, CapabilityState::QualifiedAvailable, "{name}");
                    assert!(
                        reason(&record).contains("-byte image of every output into memory"),
                        "{name}: {}",
                        reason(&record)
                    );
                }
                Some(failure) => {
                    assert_eq!(
                        record.state,
                        CapabilityState::TemporarilyUnavailable,
                        "{name}: {}",
                        reason(&record)
                    );
                    assert!(
                        reason(&record).contains(&failure),
                        "{name}: {}",
                        reason(&record)
                    );
                }
            }
            assert_eq!(left_in(scratch.path()), Vec::<String>::new(), "{name}");
        }
        // No file at all.
        let tools = Folder::new();
        let scratch = Folder::new();
        tools.program("grim", "exit 0");
        let record = only(asked(
            &desktop(Some("sway")),
            variables(tools.path()),
            scratch.path(),
        ));
        assert_eq!(record.state, CapabilityState::TemporarilyUnavailable);
        assert!(reason(&record).contains(&wanted(payload::Fault::Empty)));

        // A removal that fails is said, whether or not the image was whole: the tool makes the
        // directory unwritable after it writes.
        let tools = Folder::new();
        let scratch = Folder::new();
        let image = tools.file("image.png", &whole_png);
        tools.program(
            "grim",
            &format!(
                "cp '{}' \"$1\"\nchmod 555 \"$(dirname \"$1\")\"",
                image.display()
            ),
        );
        let record = only(asked(
            &desktop(Some("sway")),
            variables(tools.path()),
            scratch.path(),
        ));
        assert_eq!(record.state, CapabilityState::QualifiedAvailable);
        assert!(
            reason(&record).contains(", and it could not remove "),
            "{}",
            reason(&record)
        );
    }

    /// KR-REQ-03.29, LP-4: a route on which a compositor may ask the person says that, claims no
    /// prompt, and does not say that a permission the operating system asks about looks like this.
    #[test]
    fn the_words_for_an_unanswered_route_carry_the_caveat_and_claim_no_prompt() {
        let tools = Folder::new();
        let scratch = Folder::new();
        tools.program("grim", "sleep 30");
        let operation = resolve(
            Check::ScreenImage,
            &desktop(Some("sway")),
            Some(tools.path().as_os_str()),
        )
        .expect("a row");
        let deadline = Deadline::after(Duration::from_millis(400));
        let surroundings = Surroundings {
            desktop: desktop(Some("sway")),
            variables: variables(tools.path()),
        };
        let ran = Platform.perform(
            Check::ScreenImage,
            &Plan::in_directory(scratch.path()),
            &Setting {
                desktop: &surroundings.desktop,
                variables: &surroundings.variables,
                operation: Some(&operation),
                deadline: &deadline,
            },
        );
        assert!(
            matches!(ran.outcome, Outcome::NotAnswered { stopped: true, .. }),
            "{:?}",
            ran.outcome
        );
        let record = probe::record(
            &ran,
            &operation.route,
            &subject(),
            WorkerProfile::DesktopBound,
            CapabilityRevision::new(3),
            kr_ipc::now_ms(),
            None,
        )
        .expect("a record");
        let said = reason(&record);
        assert!(
            said.contains("Some compositors ask before a program may copy the screen"),
            "{said}"
        );
        assert!(
            said.contains("Nothing on this desktop is known to ask"),
            "{said}"
        );
        assert!(!said.contains("looks exactly like this"), "{said}");
        assert!(!said.contains("signed application"), "{said}");
    }

    /// KR-REQ-03.29, LP-5, the legs that need no compositor: with `grim` on the search path and a
    /// session with no bus, the check performs; with `grim` off the search path it is a missing
    /// installation, and no portal or other row stands in for it. A compositor outside the family,
    /// Weston among them, has no operation and no record, and `grim` is not run against it.
    #[test]
    fn grim_on_the_search_path_performs_and_off_it_is_missing_and_weston_has_no_record() {
        let tools = Folder::new();
        let empty = Folder::new();
        let scratch = Folder::new();
        let ran = tools.file("ran", b"");
        let _ = std::fs::remove_file(&ran);
        let image = tools.file("image.png", &whole(1280, 720));
        tools.program(
            "grim",
            &format!(": > '{}'\ncp '{}' \"$1\"", ran.display(), image.display()),
        );

        let present = only(asked(
            &desktop(Some("sway")),
            variables(tools.path()),
            scratch.path(),
        ));
        assert_eq!(present.state, CapabilityState::QualifiedAvailable);
        assert!(ran.exists(), "the tool ran");
        // The record names the program that ran, by its file's digest, and the route it took.
        assert!(present.identity.binary.as_ref().is_some(), "the program");
        assert!(present.identity.version.as_ref().is_some(), "its digest");
        assert_eq!(
            present.identity.schema.as_ref().map(String::as_str),
            Some("wayland-screen-copy")
        );
        let _ = std::fs::remove_file(&ran);

        let absent = only(asked(
            &desktop(Some("sway")),
            variables(empty.path()),
            scratch.path(),
        ));
        assert_eq!(absent.state, CapabilityState::MissingInstallation);
        assert_eq!(
            absent.evidence_source,
            CapabilityEvidenceSource::PlatformQuery
        );
        assert_eq!(
            reason(&absent),
            "the tool this check runs is not installed, so nothing was run"
        );
        assert!(!ran.exists(), "nothing ran");

        let weston = asked(
            &desktop(Some("weston")),
            variables(tools.path()),
            scratch.path(),
        );
        assert!(weston.is_empty(), "no record: {weston:?}");
        assert!(!ran.exists(), "grim is not run against weston");
    }

    /// KR-REQ-03.29, LP-6: the tool acts on the display the worker's own variables name and on none
    /// that the worker lacks: a variable the worker holds reaches it as it is, and one the worker
    /// does not hold is not inherited from whatever process started the worker.
    #[test]
    fn the_tool_acts_on_the_display_the_workers_own_variables_name() {
        let tools = Folder::new();
        let scratch = Folder::new();
        let seen = tools.path().join("seen");
        let image = tools.file("image.png", &whole(1280, 720));
        tools.program(
            "grim",
            &format!(
                "echo \"${{WAYLAND_DISPLAY-unset}}|${{XDG_RUNTIME_DIR-unset}}\" > '{}'\ncp '{}' \"$1\"",
                seen.display(),
                image.display()
            ),
        );
        let mut held = variables(tools.path());
        only(asked(&desktop(Some("sway")), held.clone(), scratch.path()));
        assert_eq!(
            std::fs::read_to_string(&seen).expect("what it saw").trim(),
            "wayland-1|/run/user/1000"
        );
        held.wayland_display = None;
        held.runtime_dir = None;
        only(asked(&desktop(Some("sway")), held, scratch.path()));
        assert_eq!(
            std::fs::read_to_string(&seen).expect("what it saw").trim(),
            "unset|unset"
        );
    }

    /// KR-REQ-03.29, LP-5, the real leg: a headless sway and the real `grim` on a runner's facts
    /// (`WLR_RENDERER=pixman`, the socket read from the runtime folder, one output of 1280 by 720)
    /// give an image the check performs, and the file `grim` writes for itself is a whole PNG of
    /// that size. It needs `sway` and `grim` and fails with a reason beginning "not run" where
    /// they are not installed, so it never reads as passed.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs sway and grim: run where they are installed"]
    fn a_headless_sway_and_grim_perform_the_screen_copy() {
        let search = std::env::var_os("PATH").unwrap_or_default();
        let find = |program: &str| {
            installed_in(program, Some(search.as_os_str()))
                .unwrap_or_else(|| panic!("not run: {program} is not installed on this host"))
        };
        let sway = find("sway");
        let grim = find("grim");
        let runtime = Folder::runtime();
        let scratch = Folder::new();
        let config = runtime.file("config", b"");
        let log = std::fs::File::create(runtime.path().join("sway.log")).expect("a log");
        let mut compositor = std::process::Command::new(&sway)
            .arg("-c")
            .arg(&config)
            .env("XDG_RUNTIME_DIR", runtime.path())
            .env("WLR_BACKENDS", "headless")
            .env("WLR_RENDERER", "pixman")
            .env("WLR_LIBINPUT_NO_DEVICES", "1")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("DISPLAY")
            .env_remove("SWAYSOCK")
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("a log"))
            .stderr(log)
            .spawn()
            .expect("sway starts");
        // The display socket is read from the runtime folder: a name `wayland-` and a number.
        let socket = {
            let started = std::time::Instant::now();
            loop {
                let found = std::fs::read_dir(runtime.path())
                    .expect("the folder")
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .find(|name| {
                        name.strip_prefix("wayland-").is_some_and(|rest| {
                            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
                        })
                    });
                if let Some(found) = found {
                    break found;
                }
                if started.elapsed() > Duration::from_secs(20)
                    || compositor.try_wait().expect("a wait").is_some()
                {
                    let _ = compositor.kill();
                    let _ = compositor.wait();
                    panic!(
                        "not run: sway made no display socket: {}",
                        std::fs::read_to_string(runtime.path().join("sway.log"))
                            .unwrap_or_default()
                    );
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        let mut variables = variables(Path::new("/nonexistent"));
        variables.search = Some(search.clone());
        variables.wayland_display = Some(socket.clone());
        variables.runtime_dir = Some(runtime.path().display().to_string());
        let records = asked(&desktop(Some("sway")), variables, scratch.path());
        // What `grim` writes for itself, read with the same rules.
        let own = runtime.path().join("own.png");
        let own_run = std::process::Command::new(&grim)
            .arg(&own)
            .env("XDG_RUNTIME_DIR", runtime.path())
            .env("WAYLAND_DISPLAY", &socket)
            .output()
            .expect("grim runs");
        let measured = std::fs::read(&own).map(|bytes| payload::png(&bytes));
        let _ = compositor.kill();
        let _ = compositor.wait();
        let record = only(records);
        assert_eq!(
            record.state,
            CapabilityState::QualifiedAvailable,
            "{}",
            record
                .disabled_reason
                .as_ref()
                .map_or("", |said| said.as_str())
        );
        assert!(own_run.status.success(), "{own_run:?}");
        assert_eq!(
            measured.expect("a file"),
            Ok(payload::Png {
                width: 1280,
                height: 720
            })
        );
        assert_eq!(left_in(scratch.path()), Vec::<String>::new());
    }
}
