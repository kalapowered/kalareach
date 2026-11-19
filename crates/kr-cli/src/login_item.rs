//! The login item that starts the control daemon when a person logs in to a graphical session:
//! `kr host login-item status`, `install` and `remove`.
//!
//! A launch agent file on macOS and an autostart entry on Linux. It is offered apart from the
//! headless host `kr host startup` chooses, the shell startup entry and the terminal profile: they
//! share the daemon program and the environment's roots, and nothing else. kr never asks the
//! system's service manager anything and never starts or ends a daemon here.
//!
//! The record in the environment's state directory names every path a step can leave before the
//! step makes it, so a stop at any point leaves a state the next run settles.

use kr_ipc::install::Written;
use kr_ipc::paths::HostPaths;

use crate::cli::LoginItemCommand;
use crate::error::{CliError, Result};
use crate::report::Completion;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod record;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod render;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod steps;
#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests;

/// The record, as a release's manifest lists it and at the version this build writes it.
pub const WRITTEN: Written = Written {
    store: "desktop-host-login",
    version: 1,
};

/// The file in an environment's state directory that records the login item kr wrote.
pub const RECORD_FILE: &str = "desktop-host-login.json";

/// The file in an environment's state directory whose lock install and removal hold.
pub const LOCK_FILE: &str = "desktop-host-login.lock";

/// Said when this system has no writer for the login item.
const NO_WRITER: &str =
    "the login item is written on macOS and Linux; this system has no writer for it";

/// Refuses on a system that is not macOS or Linux, before anything is read or selected.
///
/// # Errors
///
/// Returns [`CliError::Usage`] on any other system.
pub fn refuse_without_a_writer() -> Result<()> {
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        Ok(())
    } else {
        Err(CliError::Usage(kr_client::shown::Shown::said(NO_WRITER)))
    }
}

/// Runs one `kr host login-item` step.
///
/// # Errors
///
/// Returns what the step failed with.
pub fn run(paths: &HostPaths, command: &LoginItemCommand, json: bool) -> Result<Completion> {
    refuse_without_a_writer()?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let ended = match command {
            LoginItemCommand::Status => writer::status(paths, json),
            LoginItemCommand::Install => writer::install(paths, json),
            LoginItemCommand::Remove => writer::remove(paths, json),
        };
        match ended {
            // The document already says what failed, beside what the settling did: a second
            // document for the same failure would give a reader two to reconcile.
            Err(error) if writer::reported() => Ok(Completion::Reported(error)),
            other => other.map(|()| Completion::Done),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (paths, command, json);
        Err(CliError::Usage(kr_client::shown::Shown::said(NO_WRITER)))
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod writer {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use kr_client::shown;
    use kr_client::shown::Shown;
    use kr_ipc::paths::{EnvironmentPaths, HostPaths};

    use super::record::{self, Operation, Record};
    use super::render::{self, Kind, Parts};
    use super::steps::{self, Event, Mode, Run, Settled, Tail};
    use super::{LOCK_FILE, RECORD_FILE, WRITTEN};
    use crate::error::{CliError, Result};
    use crate::output::{self, Document};
    use crate::report;

    const LABEL_PREFIX: &str = "kr-desktop-host-";
    const LOCK_WAIT: Duration = Duration::from_secs(60);
    const LOCK_HOLDS: &str = "sets up or removes this environment's login item";

    #[cfg(target_os = "macos")]
    const HOME_VARIABLE: &str = "HOME";
    #[cfg(target_os = "linux")]
    const HOME_VARIABLE: &str = "XDG_CONFIG_HOME or HOME";

    /// The login item's lock: its own type, so the service start's lock cannot stand in for it.
    struct LoginLock(#[allow(dead_code)] crate::service_manager::Lock);

    fn lock(environment: &EnvironmentPaths) -> Result<LoginLock> {
        crate::service_manager::Lock::take_within(environment, LOCK_FILE, LOCK_HOLDS, LOCK_WAIT)
            .map(LoginLock)
            .map_err(CliError::HostUnavailable)
    }

    fn label(environment: &EnvironmentPaths) -> String {
        format!("{LABEL_PREFIX}{}", environment.environment_id())
    }

    fn record_said(environment: &EnvironmentPaths) -> Shown {
        Shown::within(environment.state_dir(), RECORD_FILE)
    }

    /// The directory the login item's file is in, from the shell's own variables.
    fn directory(kind: Kind) -> Result<PathBuf> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|home| home.is_absolute())
            .ok_or_else(|| {
                CliError::Usage(Shown::said(
                    "the login item cannot be placed: HOME is not set to an absolute path",
                ))
            })?;
        Ok(match kind {
            Kind::LaunchAgent => home.join("Library").join(kind.directory()),
            Kind::AutostartEntry => std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .filter(|base| base.is_absolute())
                .unwrap_or_else(|| home.join(".config"))
                .join(kind.directory()),
        })
    }

    fn cannot_hold(path: &str, kind: Kind) -> CliError {
        let path = Shown::root(Path::new(path));
        CliError::Usage(match kind {
            Kind::LaunchAgent => shown!(
                "a path in the login item cannot be written into a property list exactly: {}; \
                 nothing was written",
                path
            ),
            Kind::AutostartEntry => shown!(
                "a path in the login item cannot be written into a desktop entry exactly: {}; \
                 nothing was written",
                path
            ),
        })
    }

    /// The control daemon this login item starts, which must be there and be executable.
    fn controller() -> Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt as _;

        let program = crate::startup::daemon_program().map_err(|error| {
            use kr_client::shown::Said as _;
            CliError::HostUnavailable(shown!(
                "the login item names the control daemon installed beside this command, and \
                 where this command is installed could not be read: {}",
                error.said()
            ))
        })?;
        match std::fs::metadata(&program) {
            Ok(metadata) if metadata.is_file() => {
                if metadata.permissions().mode() & 0o111 == 0 {
                    return Err(CliError::Usage(shown!(
                        "the control daemon at {} is not executable; fix that, then run kr host \
                         login-item install again",
                        Shown::root(&program)
                    )));
                }
                Ok(program)
            }
            _ => Err(CliError::Usage(shown!(
                "the control daemon is not at {}; install the KalaReach host package, run kr from \
                 that installation, and run kr host login-item install again",
                Shown::root(&program)
            ))),
        }
    }

    /// What the file holds for `environment`, or the path it cannot hold.
    fn contents(
        environment: &EnvironmentPaths,
        program: &Path,
        label: &str,
        kind: Kind,
    ) -> Result<String> {
        let log = environment.state_dir().join(crate::startup::LOG_FILE);
        let text = |path| text_of(path, kind);
        let parts = Parts {
            label,
            program: text(program)?,
            runtime_root: text(environment.runtime_root())?,
            state_root: text(environment.state_root())?,
            state_dir: text(environment.state_dir())?,
            log: text(&log)?,
        };
        render::render(kind, &parts).map_err(|refused| cannot_hold(&refused.path, refused.kind))
    }

    /// The file this installation writes, and what it holds; the bytes are none when this
    /// installation cannot say what it would write.
    struct Derived {
        label: String,
        file: PathBuf,
        expected: Option<String>,
    }

    fn derived_for(environment: &EnvironmentPaths, kind: Kind, strict: bool) -> Result<Derived> {
        let label = label(environment);
        let file = directory(kind)?.join(format!("{label}.{}", kind.extension()));
        let program = if strict {
            controller().map(Some)?
        } else {
            crate::startup::daemon_program().ok()
        };
        let expected = match program {
            Some(program) if strict => Some(contents(environment, &program, &label, kind)?),
            Some(program) => contents(environment, &program, &label, kind).ok(),
            None => None,
        };
        Ok(Derived {
            label,
            file,
            expected,
        })
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        None,
        Installed,
        Gone,
        Changed,
        Foreign,
        Outdated,
        Unrecorded,
        Elsewhere,
    }

    impl State {
        const fn word(self) -> &'static str {
            match self {
                Self::None => "none",
                Self::Installed => "installed",
                Self::Gone => "gone",
                Self::Changed => "changed",
                Self::Foreign => "foreign",
                Self::Outdated => "outdated",
                Self::Unrecorded => "unrecorded",
                Self::Elsewhere => "elsewhere",
            }
        }
    }

    fn state_of(record: Option<&Record>, file: &Path, expected: Option<&str>) -> State {
        use steps::Disk;

        match record {
            None => match steps::disk(file) {
                Disk::Missing => State::None,
                Disk::Bytes(bytes) if Some(bytes.as_slice()) == expected.map(str::as_bytes) => {
                    State::Unrecorded
                }
                _ => State::Foreign,
            },
            Some(record) if record.path != file => State::Elsewhere,
            Some(record) => match steps::disk(file) {
                Disk::Missing => State::Gone,
                Disk::Bytes(bytes) if record.vouches_for(&bytes) => {
                    if expected.is_none_or(|expected| expected.as_bytes() == bytes.as_slice()) {
                        State::Installed
                    } else {
                        State::Outdated
                    }
                }
                _ => State::Changed,
            },
        }
    }

    fn pending_clause(pending: Option<Operation>, state: State) -> Option<&'static str> {
        Some(match (pending?, state) {
            (Operation::Remove, _) => {
                "an earlier kr host login-item remove did not finish: kr host login-item remove \
                 finishes it"
            }
            (_, State::Changed) => {
                "an earlier kr host login-item install did not finish: kr host login-item remove \
                 takes out what it left and leaves the file"
            }
            (_, State::Outdated | State::Elsewhere) => {
                "an earlier kr host login-item install did not finish: kr host login-item remove \
                 takes out what it left"
            }
            _ => {
                "an earlier kr host login-item install did not finish: kr host login-item install \
                 finishes it, or kr host login-item remove takes out what it left"
            }
        })
    }

    fn status_said(state: State, file: &Path, record: &Shown, pending: Option<Operation>) -> Shown {
        let file = Shown::root(file);
        let line = match state {
            State::None => shown!(
                "login item: none: kr has no record of a login item for this environment, and \
                 there is no file at {}; kr host login-item install writes one",
                file
            ),
            #[cfg(target_os = "macos")]
            State::Installed => shown!(
                "login item: installed: {} is there as kr wrote it, and is meant to start the \
                 control daemon at your next login; whether macOS runs it depends on its own \
                 switch for login items, which kr cannot read, and on whether another daemon \
                 already serves this environment",
                file
            ),
            #[cfg(target_os = "linux")]
            State::Installed => shown!(
                "login item: installed: {} is there as kr wrote it, and is meant to start the \
                 control daemon at your next login on a desktop that runs autostart entries, \
                 unless another daemon already serves this environment; a systemd user manager \
                 reads a new entry only when it reloads, which systemctl --user daemon-reload does",
                file
            ),
            State::Gone => shown!(
                "login item: the record {} names {}, and the file is gone; kr host login-item \
                 remove drops the record, and kr host login-item install writes the file again",
                *record,
                file
            ),
            State::Changed => shown!(
                "login item: {} was changed after kr wrote it, so it is no longer kr's to \
                 replace or remove; kr host login-item remove drops kr's record and leaves the \
                 file, which may still start a daemon when you log in",
                file
            ),
            State::Foreign => shown!(
                "login item: {} is not what this installation of kr writes, and kr has no record \
                 of writing it, so kr leaves it as it is and does not write over it",
                file
            ),
            State::Outdated => shown!(
                "login item: {} is as kr wrote it, but this installation of kr writes it \
                 differently now; kr host login-item remove takes it out, and kr host login-item \
                 install then writes this installation's",
                file
            ),
            State::Unrecorded => shown!(
                "login item: {} is exactly what this installation of kr writes, and kr has no \
                 record of writing it; kr host login-item install records it and leaves the file \
                 as it is",
                file
            ),
            State::Elsewhere => shown!(
                "login item: the file the record {} names is not {}, where this command puts \
                 this environment's login item under {}; kr host login-item remove takes out the \
                 recorded file if it is as kr wrote it, and kr host login-item install then \
                 writes {}",
                *record,
                file,
                HOME_VARIABLE,
                file
            ),
        };
        match pending_clause(pending, state) {
            Some(clause) => shown!("{}; {}", line, clause),
            None => line,
        }
    }

    const NO_IDENTITY: &str = "login item: none: kr has no record of a login item for this \
                               environment, and this environment has no identity yet, so kr has \
                               no file to name; kr host login-item install writes one";

    fn document(
        state: State,
        file: Option<&Path>,
        recorded: bool,
        pending: Option<Operation>,
        actions: Option<Vec<&'static str>>,
    ) -> Document {
        let mut document = Document::new()
            .with("state", state.word())
            .with("file", file.map(Shown::root))
            .with("recorded", recorded)
            .with("pending", pending.map(Operation::word));
        #[cfg(target_os = "macos")]
        {
            document.set("system_switch", "not_read");
        }
        if let Some(actions) = actions {
            document.set("actions", actions);
        }
        document
    }

    /// Prints what a command did and the state it leaves.
    fn finish(
        json: bool,
        lines: &[(&'static str, Shown)],
        state: State,
        derived: &Derived,
        record: Option<&Record>,
        record_said: &Shown,
    ) {
        emit(json, lines, state, derived, record);
        if !json {
            let pending = record.and_then(|record| record.pending.as_ref().map(|p| p.operation));
            output::say(&status_said(state, &derived.file, record_said, pending));
        }
    }

    /// The document of what a command did and the state it leaves.
    fn document_of(
        lines: &[(&'static str, Shown)],
        state: State,
        derived: &Derived,
        record: Option<&Record>,
    ) -> Document {
        let pending = record.and_then(|record| record.pending.as_ref().map(|p| p.operation));
        let actions = lines
            .iter()
            .map(|(word, _)| *word)
            .filter(|word| *word != "notice")
            .collect();
        document(
            state,
            Some(&derived.file),
            record.is_some(),
            pending,
            Some(actions),
        )
    }

    /// Prints what a command did: its document, or one line for each thing it did.
    fn emit(
        json: bool,
        lines: &[(&'static str, Shown)],
        state: State,
        derived: &Derived,
        record: Option<&Record>,
    ) {
        if json {
            output::document(&document_of(lines, state, derived, record));
            return;
        }
        for (_, line) in lines {
            output::say(line);
        }
    }

    /// Whether this command wrote its failure into its document, which then stands as its one
    /// result.
    static REPORTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    pub(super) fn reported() -> bool {
        REPORTED.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Hands `error` back after telling what the settling before it did, which the record no
    /// longer says: a leftover it took out or left would otherwise be named nowhere.
    fn carried(
        json: bool,
        lines: &[(&'static str, Shown)],
        derived: &Derived,
        read: &dyn Fn() -> Result<Option<Record>>,
        error: CliError,
    ) -> CliError {
        if !lines.is_empty() {
            let record = read().ok().flatten();
            let state = state_of(record.as_ref(), &derived.file, derived.expected.as_deref());
            if json {
                let document = document_of(lines, state, derived, record.as_ref());
                output::document(&report::with_failure(document, &error));
                REPORTED.store(true, std::sync::atomic::Ordering::Relaxed);
            } else {
                emit(false, lines, state, derived, record.as_ref());
            }
        }
        error
    }

    /// A path as a sentence says it: whole where it is beside the file kr derives, and by the
    /// record that names it otherwise.
    fn said_path(path: &Path, derived: &Path, recorded: &Path, record: &Shown) -> Shown {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if recorded == derived {
            Shown::root(path)
        } else if name.ends_with(".kr-moving") {
            shown!(
                "a file beside the file the record {} names, under a name that ends in .kr-moving",
                *record
            )
        } else if name.ends_with(".kr-staging") {
            shown!(
                "a file beside the file the record {} names, under a name that ends in \
                 .kr-staging",
                *record
            )
        } else {
            shown!("the file the record {} names", *record)
        }
    }

    fn event_lines(
        events: &[Event],
        derived: &Path,
        recorded: &Path,
        record: &Shown,
    ) -> Vec<(&'static str, Shown)> {
        let said = |path: &Path| said_path(path, derived, recorded, record);
        events
            .iter()
            .map(|event| match event {
                Event::Removed(path) => {
                    let word = if path == recorded {
                        "removed_file"
                    } else {
                        "removed_aside"
                    };
                    (word, shown!("removed {}", said(path)))
                }
                Event::Left(path) => (
                    "left_leftover",
                    shown!("left {}: it does not hold what kr wrote", said(path)),
                ),
                Event::LeftFile => (
                    "left_file",
                    shown!(
                        "left {}: it was changed after kr wrote it, so it is no longer kr's to \
                         remove; kr dropped its record, and the file may still start a daemon \
                         when you log in",
                        said(recorded)
                    ),
                ),
                Event::AsideStays(aside) => (
                    "aside_stays",
                    shown!(
                        "left {}: {} holds another file now, so the file kr moved aside could not \
                         go back; kr dropped its record",
                        said(aside),
                        said(recorded)
                    ),
                ),
            })
            .collect()
    }

    fn failed(
        failure: steps::Failure,
        operation: Operation,
        derived: &Path,
        recorded: &Path,
        record: &Shown,
    ) -> CliError {
        let error = failure.error.said();
        CliError::Other(match failure.tail {
            Tail::TookBack => shown!("{}; kr took back its record and wrote no file", error),
            Tail::InPlace => shown!(
                "{}; the new file is in place; run kr host login-item install again to finish",
                error
            ),
            Tail::KeptNamed(path) => shown!(
                "{}; kr kept its record, which names {}: it does not hold what kr wrote",
                error,
                said_path(&path, derived, recorded, record)
            ),
            Tail::Unfinished if operation == Operation::Remove => {
                shown!("{}; run kr host login-item remove again to finish", error)
            }
            Tail::Unfinished => {
                shown!("{}; run kr host login-item install again to finish", error)
            }
        })
    }

    fn run_paths(environment: &EnvironmentPaths, file: &Path) -> steps::Paths {
        steps::Paths {
            record: record::path(environment.state_dir()),
            file: file.to_owned(),
            aside: record::beside(file, "kr-moving"),
            staging: record::beside(file, "kr-staging"),
        }
    }

    /// What a command did that a person is told of: a word for the document, and the line.
    type Lines = Vec<(&'static str, Shown)>;

    /// Finishes what an earlier run began, when the record says one did not finish. A failure
    /// hands back what the settling had done before it.
    fn settle(
        environment: &EnvironmentPaths,
        derived: &Derived,
        kind: Kind,
        record: Record,
        mode: Mode,
        said: &Shown,
    ) -> std::result::Result<(Settled, Lines), Box<(CliError, Lines)>> {
        let mut run = Run::new(
            run_paths(environment, &record.path),
            kind,
            &derived.label,
            "",
            Some(record.clone()),
        );
        let settled = steps::settle(&mut run, &record, mode);
        let mut lines = event_lines(&run.events, &derived.file, &record.path, said);
        let settled = match settled {
            Ok(settled) => settled,
            Err(error) => {
                let error = CliError::Other(shown!(
                    "{}; run kr host login-item {} again to finish",
                    error.said(),
                    if mode == Mode::Install {
                        "install"
                    } else {
                        "remove"
                    }
                ));
                return Err(Box::new((error, lines)));
            }
        };
        if settled == Settled::Done {
            let operation = record.pending.as_ref().map(|pending| pending.operation);
            lines.push((
                "settled",
                match (mode, operation) {
                    (Mode::Remove, Some(Operation::Remove)) => {
                        shown!("finished what an earlier kr host login-item remove began")
                    }
                    (Mode::Install, Some(Operation::Remove)) => {
                        shown!("took back what an earlier kr host login-item remove began")
                    }
                    (Mode::Remove, _) => {
                        shown!("took out what an earlier kr host login-item install began")
                    }
                    (Mode::Install, _) => {
                        shown!("finished what an earlier kr host login-item install began")
                    }
                },
            ));
        }
        Ok((settled, lines))
    }

    pub(super) fn status(paths: &HostPaths, json: bool) -> Result<()> {
        let kind = Kind::current();
        let Some(id) = paths.recorded_environment_id().map_err(CliError::Ipc)? else {
            if json {
                output::document(&document(State::None, None, false, None, None));
            } else {
                output::say(&Shown::said(NO_IDENTITY));
            }
            return Ok(());
        };
        let environment = paths.environment(id);
        let derived = derived_for(&environment, kind, false)?;
        let said = record_said(&environment);
        let record = record::read(environment.state_dir(), kind, &derived.label, &said)
            .map_err(CliError::Usage)?;
        let state = state_of(record.as_ref(), &derived.file, derived.expected.as_deref());
        finish(json, &[], state, &derived, record.as_ref(), &said);
        Ok(())
    }

    pub(super) fn install(paths: &HostPaths, json: bool) -> Result<()> {
        let kind = Kind::current();
        // Everything that can refuse comes before the identity, the state directory or any file.
        text_of(&directory(kind)?, kind)?;
        let program = controller()?;
        let probe = Parts {
            label: "kr-desktop-host-x",
            program: text_of(&program, kind)?,
            runtime_root: text_of(paths.runtime_root(), kind)?,
            state_root: text_of(paths.state_root(), kind)?,
            state_dir: text_of(paths.state_root(), kind)?,
            log: text_of(paths.state_root(), kind)?,
        };
        render::render(kind, &probe).map_err(|refused| cannot_hold(&refused.path, refused.kind))?;
        let id = paths.open_environment_id().map_err(CliError::Ipc)?;
        let environment = paths.environment(id);
        let derived = derived_for(&environment, kind, true)?;
        let expected = derived.expected.clone().unwrap_or_default();
        let writers = crate::barrier::hold_in(&environment)?;
        let permit = crate::barrier::permit(&writers, &WRITTEN)?;
        permit.require(&WRITTEN)?;
        environment.create_state_dir().map_err(CliError::Ipc)?;
        let _lock = lock(&environment)?;
        let said = record_said(&environment);
        let read = || {
            record::read(environment.state_dir(), kind, &derived.label, &said)
                .map_err(CliError::Usage)
        };
        let mut record = read()?;
        let mut lines = Lines::new();
        if let Some(pending) = record.clone().filter(|record| record.pending.is_some()) {
            let recorded = pending.path.clone();
            let (settled, more) =
                settle(&environment, &derived, kind, pending, Mode::Install, &said).map_err(
                    |stopped| {
                        let (error, more) = *stopped;
                        carried(json, &more, &derived, &read, error)
                    },
                )?;
            lines.extend(more);
            if settled == Settled::Changed {
                let error = refusal_changed(&recorded);
                return Err(carried(json, &lines, &derived, &read, error));
            }
            record = read()?;
        }
        let state = state_of(record.as_ref(), &derived.file, Some(&expected));
        let refused = |lines: &Lines, error: CliError| carried(json, lines, &derived, &read, error);
        match state {
            State::Foreign => {
                return Err(refused(
                    &lines,
                    CliError::Usage(shown!(
                        "the login item file {} is not what this installation of kr writes, and kr has \
                 no record of writing it, so kr does not replace it; move it aside and run kr \
                 host login-item install again",
                        Shown::root(&derived.file)
                    )),
                ));
            }
            State::Changed => return Err(refused(&lines, refusal_changed(&derived.file))),
            State::Elsewhere => {
                return Err(refused(
                    &lines,
                    CliError::Usage(shown!(
                        "kr wrote this environment's login item at the file the record {} names, not at \
                 {}, where this command would write it; run kr host login-item remove first, \
                 which takes out the recorded file if it is as kr wrote it",
                        said,
                        Shown::root(&derived.file)
                    )),
                ));
            }
            State::Outdated => {
                return Err(refused(
                    &lines,
                    CliError::Usage(shown!(
                        "the login item file {} is as kr wrote it, but this installation of kr writes it \
                 differently now; run kr host login-item remove first, then run kr host \
                 login-item install again",
                        Shown::root(&derived.file)
                    )),
                ));
            }
            State::Installed => lines.push((
                "already_installed",
                shown!(
                    "login item: already installed: {} is what kr wrote",
                    Shown::root(&derived.file)
                ),
            )),
            State::Unrecorded => {
                let adopted = Record::clean(kind, &derived.label, &derived.file, &expected);
                let paths = run_paths(&environment, &derived.file);
                let bytes = adopted.bytes().map_err(|error| {
                    refused(
                        &lines,
                        CliError::Other(
                            steps::StepError {
                                doing: steps::Doing::Recording,
                                cause: steps::Cause::Io(error),
                            }
                            .said(),
                        ),
                    )
                })?;
                kr_ipc::paths::write_owner_only_file(&paths.record, &bytes)
                    .map_err(CliError::Ipc)?;
                lines.push((
                    "adopted",
                    shown!(
                        "recorded {}, which is what this installation writes; no byte of it \
                         changed",
                        Shown::root(&derived.file)
                    ),
                ));
                lines.push(("installed", installed_said(&derived.file)));
            }
            State::None | State::Gone => {
                let mut run = Run::new(
                    run_paths(&environment, &derived.file),
                    kind,
                    &derived.label,
                    &expected,
                    record.clone(),
                );
                if let Err(error) = steps::run_all(&mut run, &steps::PUBLISH) {
                    let failure = steps::fail(&mut run, Operation::Publish, error);
                    let error = failed(
                        failure,
                        Operation::Publish,
                        &derived.file,
                        &derived.file,
                        &said,
                    );
                    return Err(refused(&lines, error));
                }
                lines.push(("installed", installed_said(&derived.file)));
            }
        }
        let record = read()?;
        let state = state_of(record.as_ref(), &derived.file, Some(&expected));
        if json {
            finish(json, &lines, state, &derived, record.as_ref(), &said);
        } else {
            for (_, line) in &lines {
                output::say(line);
            }
        }
        Ok(())
    }

    fn text_of(path: &Path, kind: Kind) -> Result<&str> {
        render::text(path).ok_or_else(|| cannot_hold(&path.to_string_lossy(), kind))
    }

    fn refusal_changed(file: &Path) -> CliError {
        CliError::Usage(shown!(
            "the login item file {} was changed after kr wrote it, so kr does not replace it; \
             run kr host login-item remove, which leaves it, then move it aside and run kr host \
             login-item install again",
            Shown::root(file)
        ))
    }

    #[cfg(target_os = "macos")]
    fn installed_said(file: &Path) -> Shown {
        shown!(
            "login item: installed: {} is in place for your next login; nothing was started now, \
             and kr host startup still chooses how the command kr new starts the daemon",
            Shown::root(file)
        )
    }

    #[cfg(target_os = "linux")]
    fn installed_said(file: &Path) -> Shown {
        shown!(
            "login item: installed: {} is in place for your next login; nothing was started now, \
             and kr host startup still chooses how the command kr new starts the daemon; if a \
             systemd user manager runs your autostart entries, systemctl --user daemon-reload \
             makes it read this entry",
            Shown::root(file)
        )
    }

    #[cfg(target_os = "macos")]
    fn removal_notice() -> Shown {
        Shown::said(
            "removing the login item does not end a daemon that is running; kr host stop ends it",
        )
    }

    #[cfg(target_os = "linux")]
    fn removal_notice() -> Shown {
        Shown::said(
            "removing the login item does not end a daemon that is running; kr host stop ends \
             it; if a systemd user manager runs your autostart entries, systemctl --user \
             daemon-reload makes it forget the entry",
        )
    }

    pub(super) fn remove(paths: &HostPaths, json: bool) -> Result<()> {
        let kind = Kind::current();
        directory(kind)?;
        let Some(id) = paths.recorded_environment_id().map_err(CliError::Ipc)? else {
            if json {
                output::document(&document(
                    State::None,
                    None,
                    false,
                    None,
                    Some(vec!["nothing_to_remove"]),
                ));
            } else {
                output::say(&Shown::said(
                    "nothing of the login item's to remove: kr has no record of one for this \
                     environment",
                ));
                output::say(&Shown::said(NO_IDENTITY));
            }
            return Ok(());
        };
        let environment = paths.environment(id);
        let derived = derived_for(&environment, kind, false)?;
        let said = record_said(&environment);
        let read = || {
            if environment.state_dir().is_dir() {
                record::read(environment.state_dir(), kind, &derived.label, &said)
                    .map_err(CliError::Usage)
            } else {
                Ok(None)
            }
        };
        let nothing = |said: &Shown| {
            let state = state_of(None, &derived.file, derived.expected.as_deref());
            let lines = [(
                "nothing_to_remove",
                Shown::said(
                    "nothing of the login item's to remove: kr has no record of one for this \
                     environment",
                ),
            )];
            finish(json, &lines, state, &derived, None, said);
        };
        if read()?.is_none() {
            nothing(&said);
            return Ok(());
        }
        let writers = crate::barrier::hold_in(&environment)?;
        let permit = crate::barrier::permit(&writers, &WRITTEN)?;
        permit.require(&WRITTEN)?;
        let _lock = lock(&environment)?;
        let Some(mut record) = read()? else {
            nothing(&said);
            return Ok(());
        };
        let mut lines = Lines::new();
        if record.pending.is_some() {
            let (_, more) = settle(&environment, &derived, kind, record, Mode::Remove, &said)
                .map_err(|stopped| {
                    let (error, more) = *stopped;
                    carried(json, &more, &derived, &read, error)
                })?;
            lines.extend(more);
            record = read()?.ok_or_else(|| {
                carried(
                    json,
                    &lines,
                    &derived,
                    &read,
                    CliError::Other(Shown::said(
                        "the record was taken away while kr was removing",
                    )),
                )
            })?;
        }
        let recorded = record.path.clone();
        let mut run = Run::new(
            run_paths(&environment, &recorded),
            kind,
            &derived.label,
            "",
            Some(record.clone()),
        );
        if let Err(error) = steps::run_all(&mut run, &steps::REMOVE) {
            let failure = steps::fail(&mut run, Operation::Remove, error);
            let error = failed(failure, Operation::Remove, &derived.file, &recorded, &said);
            let mut lines = lines;
            lines.extend(event_lines(&run.events, &derived.file, &recorded, &said));
            return Err(carried(json, &lines, &derived, &read, error));
        }
        lines.extend(event_lines(&run.events, &derived.file, &recorded, &said));
        lines.push((
            "removed_record",
            shown!(
                "removed {}",
                Shown::within(environment.state_dir(), RECORD_FILE)
            ),
        ));
        lines.push(("notice", removal_notice()));
        let state = state_of(None, &derived.file, derived.expected.as_deref());
        finish(json, &lines, state, &derived, None, &said);
        Ok(())
    }
}
