//! `kr host terminal-profile`: show, add and take out the optional terminal profile.
//!
//! The profile is one named `KalaReach` in one terminal application's own profile mechanism, whose
//! command is `kr new --attach --hold-on-failure`, so each window or tab opened through it is a
//! session of its own. It is available and never made the application's default. This command
//! reaches no daemon and never writes a shell startup file, a service definition or a login item:
//! installing one offer never installs another.

use std::path::{Path, PathBuf};

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::paths::HostPaths;
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::host::startup::{EntryInPlace, EntryRecord};
use kr_shell_integration::host::terminal_profile;
use kr_shell_integration::host::terminal_profile::record::{
    PROFILE_WRITTEN, ProfileRecord, RecordError, Wrote,
};
use kr_shell_integration::host::terminal_profile::{
    Place, ProfileError, ProfileHome, ProfileTerminal, Removed, Standing,
};

use crate::cli::{
    TerminalProfileArguments, TerminalProfileCommand, TerminalProfileInstall, TerminalProfileRemove,
};
use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Request};
use crate::report::Completion;
use crate::stdout_line;

/// What a profile's command runs after the program: the options that make each window a session of
/// its own and keep it open on a failure.
const ARGUMENTS: [&str; 3] = ["new", "--attach", "--hold-on-failure"];

/// The terminal applications this command refuses by name, each with its reason.
const REFUSED: [(&str, &str); 7] = [
    ("xfce4-terminal", "it has no profiles"),
    ("xterm", "it has no profiles"),
    (
        "Alacritty",
        "its configuration is one file with no list of profiles",
    ),
    (
        "kitty",
        "its configuration is one file with no list of profiles",
    ),
    ("Ghostty", "its configuration is a file of the person's own"),
    (
        "WezTerm",
        "its configuration is a script of the person's own",
    ),
    (
        "VS Code's terminal",
        "its profiles are the editor's settings",
    ),
];

/// Runs the command.
///
/// # Errors
///
/// Returns a usage failure for a terminal application this platform has no profile for or that is
/// not installed, a refusal to write over a file that is not kr's, and a resource failure when the
/// record or a file cannot be used. A removal that took some profiles out and could not take out
/// another has written its result already, and says so in the completion it returns.
pub fn run(
    paths: &HostPaths,
    arguments: &TerminalProfileArguments,
    json: bool,
) -> Result<Completion> {
    let record = ProfileRecord::in_state_directory(paths.state_root());
    match &arguments.command {
        TerminalProfileCommand::Status => status(paths, &record, json).map(|()| Completion::Done),
        TerminalProfileCommand::Install(install) => {
            install_profile(paths, &record, install, json).map(|()| Completion::Done)
        }
        TerminalProfileCommand::Remove(remove) => remove_profiles(paths, &record, remove, json),
    }
}

/// The places this person's terminal applications keep their profiles in.
fn this_user() -> Result<ProfileHome> {
    ProfileHome::of_this_user().map_err(|error| CliError::Usage(Shown::said(error.said())))
}

/// The argument vector a profile runs: this installation's own `kr`, through the store's
/// `current` where it is a release of one, so an update keeps what the profile names. The release
/// this process is would be gone once an update replaced it, which a window opened later must
/// not meet, so the program named is the one an update replaces (`stable`), not this release's own.
fn command() -> Result<Vec<String>> {
    let running = kr_ipc::install::this_process()
        .map_err(|error| CliError::Other(crate::update::said(error)))?;
    let program = running.stable(kr_ipc::install::Program::Kr);
    let program = program.to_str().ok_or_else(|| {
        CliError::Usage(shown!(
            "{} is not text, which a terminal application's profile cannot name",
            Shown::root(&program)
        ))
    })?;
    Ok(std::iter::once(program.to_owned())
        .chain(ARGUMENTS.map(str::to_owned))
        .collect())
}

/// A profile's command as a person is shown it: the program, then the options. Only a command that
/// is the one this build writes is shown whole; any other is shown as another command.
fn command_shown(command: &[String]) -> Shown {
    match command.split_first() {
        Some((program, rest)) if rest == ARGUMENTS => shown!(
            "{} {}",
            Shown::root(Path::new(program)),
            Shown::joined(ARGUMENTS.map(Shown::said), " ")
        ),
        _ => Shown::said("a command of another kind"),
    }
}

/// The same, for a script: the program and each option as a word.
fn command_words(command: &[String]) -> Vec<Shown> {
    match command.split_first() {
        Some((program, rest)) if rest == ARGUMENTS => {
            std::iter::once(Shown::root(Path::new(program)))
                .chain(ARGUMENTS.map(Shown::said))
                .collect()
        }
        _ => Vec::new(),
    }
}

/// What a terminal application's own menus call the way to choose a profile, and the command that
/// opens a window with it.
const fn how_to_choose(terminal: ProfileTerminal) -> &'static str {
    match terminal {
        ProfileTerminal::Konsole => {
            "open a window with `konsole --profile KalaReach`, or choose KalaReach in Konsole's \
             menus"
        }
        ProfileTerminal::Iterm2 => "choose KalaReach in iTerm2's Profiles menu",
        ProfileTerminal::AppleTerminal => "choose KalaReach in Terminal's Shell menu, New Window",
        ProfileTerminal::GnomeTerminal => {
            "open a window with `gnome-terminal --profile=KalaReach`, or choose KalaReach in \
             GNOME Terminal's File menu"
        }
        ProfileTerminal::Ptyxis => {
            "choose KalaReach in Ptyxis's new-tab menu, or open a tab with `ptyxis \
             --tab-with-profile=<identifier>`, the identifier being the last part of the path above"
        }
        ProfileTerminal::WindowsTerminal => {
            "open a window with `wt -p KalaReach`, or choose KalaReach in the new-tab menu"
        }
    }
}

/// Where each terminal application's own control makes a profile its default.
const fn how_to_make_default(terminal: ProfileTerminal) -> &'static str {
    match terminal {
        ProfileTerminal::Konsole => "Konsole, Settings, Manage Profiles, Set as Default",
        ProfileTerminal::Iterm2 => "iTerm2, Settings, Profiles, Other Actions, Set as Default",
        ProfileTerminal::AppleTerminal => "Terminal, Settings, Profiles, Default",
        ProfileTerminal::GnomeTerminal => {
            "GNOME Terminal, Preferences, the profile's menu, Set as default"
        }
        ProfileTerminal::Ptyxis => "Ptyxis, Preferences, Profiles, Set as default",
        ProfileTerminal::WindowsTerminal => "Windows Terminal, Settings, Startup, Default profile",
    }
}

/// Says what the profile writes, for a person.
fn say_place(place: Place<'_>) {
    match place {
        Place::File(file) => output::say(&shown!("  where: {}", Shown::root(file))),
        Place::Settings { schema, path } => output::line(&stdout_line!(
            "  where: the settings of {} at {}",
            Asked::text(Request::TerminalProfile, schema),
            Asked::text(Request::TerminalProfile, path)
        )),
        Place::Preferences { domain, key, entry } => output::line(&stdout_line!(
            "  where: the {} entry {} of the preferences of {}",
            Asked::text(Request::TerminalProfile, key),
            Asked::text(Request::TerminalProfile, entry),
            Asked::text(Request::TerminalProfile, domain)
        )),
    }
}

/// Adds what the profile writes to a document for a script.
fn json_place(document: Document, place: Place<'_>) -> Document {
    match place {
        Place::File(file) => document.with("file", Shown::root(file)),
        Place::Settings { schema, path } => document.with(
            "settings",
            Document::new()
                .with("schema", Asked::text(Request::TerminalProfile, schema))
                .with("path", Asked::text(Request::TerminalProfile, path)),
        ),
        Place::Preferences { domain, key, entry } => document.with(
            "preferences",
            Document::new()
                .with("domain", Asked::text(Request::TerminalProfile, domain))
                .with("key", Asked::text(Request::TerminalProfile, key))
                .with("entry", Asked::text(Request::TerminalProfile, entry)),
        ),
    }
}

/// The words for a profile's state.
const fn standing_word(standing: Standing) -> &'static str {
    match standing {
        Standing::Matches => "matches",
        Standing::Changed => "changed",
        Standing::Missing => "missing",
        Standing::Unlisted => "unlisted",
        Standing::Unreadable => "unreadable",
    }
}

/// The state of one application's profile, in one word.
fn state_word(status: &terminal_profile::Status) -> &'static str {
    match (&status.recorded, status.standing) {
        (None, _) if status.foreign => "foreign",
        (None, _) => "none",
        (Some(_), _) if status.default => "default",
        (Some(_), Some(standing)) => standing_word(standing),
        (Some(_), None) => "none",
    }
}

/// What a window opened through the profile needs to find ready, as far as it can be read with no
/// daemon.
struct Readiness {
    /// The shell the next session would launch, and whether it has the startup entry that opens
    /// the bridge.
    shell: Option<(ShellKind, EntryInPlace)>,
    /// How `kr new` starts the control daemon when none runs, when one is chosen.
    start: Option<&'static str>,
}

/// Reads what needs no daemon: the startup entry of the shell this person has, and the choice of
/// how the control daemon is started.
fn readiness(paths: &HostPaths) -> Readiness {
    let shell = std::env::var_os("SHELL")
        .map(PathBuf::from)
        .and_then(|shell| shell.file_name().map(std::ffi::OsStr::to_os_string))
        .and_then(|name| name.into_string().ok())
        .and_then(|name| {
            let name = if name == "pwsh" { "powershell" } else { &name };
            ShellKind::ALL
                .iter()
                .copied()
                .find(|kind| kind.as_str() == name)
        })
        .map(|kind| {
            let record = EntryRecord::in_state_directory(paths.state_root());
            (kind, record.opening_entry(kind))
        });
    let start = crate::resolve::select(paths, None)
        .ok()
        .and_then(|environment| crate::startup::Chosen::read(&environment.paths).controller)
        .map(kr_protocol::hostinfo::configuration::ControllerStartup::as_str);
    Readiness { shell, start }
}

impl Readiness {
    /// The lines a person is shown.
    fn say(&self) {
        output::say(&Shown::said(
            "a window opened through the profile creates a session only if these are ready:",
        ));
        match &self.shell {
            Some((kind, EntryInPlace::Yes)) => output::say(&shown!(
                "  the {} startup entry: installed",
                Shown::said(kind.as_str())
            )),
            Some((kind, EntryInPlace::No)) => output::say(&shown!(
                "  the {} startup entry: not installed; run kr shell install",
                Shown::said(kind.as_str())
            )),
            Some((kind, EntryInPlace::Unknown)) => output::say(&shown!(
                "  the {} startup entry: its record could not be read; run kr shell status",
                Shown::said(kind.as_str())
            )),
            None => output::say(&Shown::said(
                "  the startup entry: your shell is not one KalaReach qualifies, so a managed \
                 session cannot start in it; kr host shell-mode --set native_compat makes new \
                 sessions use the shell as it is",
            )),
        }
        match self.start {
            Some(chosen) => output::say(&shown!(
                "  starting the control daemon: {}",
                Shown::said(chosen)
            )),
            None => output::say(&Shown::said(
                "  starting the control daemon: none chosen, so a window finds none running and \
                 says so; run kr host startup --set standalone",
            )),
        }
        output::say(&Shown::said(
            "  anything a running daemon holds is read by kr doctor",
        ));
    }

    /// The same, for a script.
    fn json(&self) -> Document {
        Document::new()
            .with("shell", self.shell.as_ref().map(|(kind, _)| kind.as_str()))
            .with(
                "shell_entry",
                self.shell.as_ref().map(|(_, entry)| match entry {
                    EntryInPlace::Yes => "installed",
                    EntryInPlace::No => "not_installed",
                    EntryInPlace::Unknown => "unknown",
                }),
            )
            .with("daemon_start", self.start)
    }
}

/// Shows what each terminal application this platform has a profile for holds. Nothing is written.
fn status(paths: &HostPaths, record: &ProfileRecord, json: bool) -> Result<()> {
    let home = &this_user()?;
    let recorded = record
        .profiles()
        .map_err(|error| record_failure(record, &error))?;
    let statuses: Vec<terminal_profile::Status> = ProfileTerminal::on_this_platform()
        .iter()
        .map(|terminal| {
            let recorded = recorded
                .iter()
                .find(|profile| profile.terminal == *terminal)
                .cloned();
            terminal_profile::status(*terminal, home, recorded)
        })
        .collect();
    let readiness = readiness(paths);
    if json {
        output::document(
            &Document::new()
                .with("ok", true)
                .with(
                    "terminals",
                    statuses.iter().map(status_json).collect::<Vec<_>>(),
                )
                .with(
                    "no_profile_to_add_to",
                    REFUSED
                        .iter()
                        .map(|(name, why)| {
                            Document::new().with("terminal", *name).with("why", *why)
                        })
                        .collect::<Vec<_>>(),
                )
                .with("readiness", readiness.json()),
        );
        return Ok(());
    }
    if statuses.is_empty() {
        output::say(&Shown::said(
            "this platform has no terminal application kr writes a profile for yet",
        ));
    }
    for status in &statuses {
        output::say(&status_line(status));
        match status.recorded.as_ref().map(|recorded| &recorded.wrote) {
            Some(Wrote::File(wrote)) => {
                if let Ok(file) = wrote.file() {
                    output::say(&shown!("  file: {}", Shown::root(&file)));
                }
            }
            Some(Wrote::Settings(wrote)) => output::line(&stdout_line!(
                "  settings: {} at {}",
                Asked::text(Request::TerminalProfile, &wrote.schema),
                Asked::text(Request::TerminalProfile, &wrote.path)
            )),
            Some(Wrote::Preferences(wrote)) => output::line(&stdout_line!(
                "  preferences: the {} entry {} of {}",
                Asked::text(Request::TerminalProfile, &wrote.key),
                Asked::text(Request::TerminalProfile, &wrote.entry),
                Asked::text(Request::TerminalProfile, &wrote.domain)
            )),
            None => {}
        }
    }
    output::say(&shown!(
        "no profile can be added to: {}",
        Shown::joined(
            REFUSED.map(|(name, why)| shown!("{} ({})", Shown::said(name), Shown::said(why))),
            ", "
        )
    ));
    readiness.say();
    Ok(())
}

/// One terminal application's state, as a sentence.
fn status_line(status: &terminal_profile::Status) -> Shown {
    let name = Shown::said(status.terminal.name());
    if !status.present && status.recorded.is_none() {
        return shown!("{}: not installed", name);
    }
    let installed = if status.present {
        Shown::said("installed")
    } else {
        Shown::said("not installed")
    };
    let state = match state_word(status) {
        "foreign" => {
            Shown::said("a KalaReach profile is there that kr did not write, and is left alone")
        }
        "none" => Shown::said("no profile written"),
        "matches" => Shown::said("the profile is written and unchanged"),
        "changed" => Shown::said("the profile was changed after kr wrote it"),
        "missing" => Shown::said("the profile kr wrote is gone"),
        "unlisted" => Shown::said(
            "the profile's settings are written, but it is not in the list the application \
             reads its profiles from; install puts it back",
        ),
        "unreadable" => Shown::said(
            "the profile could not be read, because the program that reads it did not answer",
        ),
        _ => Shown::said("the profile is this terminal application's default"),
    };
    shown!("{}: {}; {}", name, installed, state)
}

/// One terminal application's state, for a script.
fn status_json(status: &terminal_profile::Status) -> Document {
    let mut document = Document::new()
        .with("terminal", status.terminal.id())
        .with("name", status.terminal.name())
        .with("installed", status.present)
        .with("profile", state_word(status));
    if let Some(recorded) = &status.recorded {
        document.set("command", command_words(&recorded.command));
        match &recorded.wrote {
            Wrote::File(wrote) => {
                if let Ok(file) = wrote.file() {
                    document.set("file", Shown::root(&file));
                }
            }
            Wrote::Settings(wrote) => document.set(
                "settings",
                Document::new()
                    .with(
                        "schema",
                        Asked::text(Request::TerminalProfile, &wrote.schema),
                    )
                    .with("path", Asked::text(Request::TerminalProfile, &wrote.path)),
            ),
            Wrote::Preferences(wrote) => document.set(
                "preferences",
                Document::new()
                    .with(
                        "domain",
                        Asked::text(Request::TerminalProfile, &wrote.domain),
                    )
                    .with("key", Asked::text(Request::TerminalProfile, &wrote.key))
                    .with("entry", Asked::text(Request::TerminalProfile, &wrote.entry)),
            ),
        }
    }
    document
}

/// Finds the terminal application a person named, and refuses what this platform has no profile
/// for.
fn named(text: &str) -> Result<ProfileTerminal> {
    let available = || {
        Shown::joined(
            ProfileTerminal::on_this_platform()
                .iter()
                .map(|terminal| Shown::said(terminal.id())),
            ", ",
        )
    };
    let terminal = ProfileTerminal::from_id(text).ok_or_else(|| {
        CliError::Usage(shown!(
            "the terminal application given is not one kr writes a profile for; this platform has: {}",
            available()
        ))
    })?;
    if ProfileTerminal::on_this_platform().contains(&terminal) {
        Ok(terminal)
    } else {
        Err(CliError::Usage(shown!(
            "{} is not on this platform's list of terminal applications kr writes a profile for: {}",
            Shown::said(terminal.name()),
            available()
        )))
    }
}

/// Writes the profile for one terminal application, or says what it would write.
fn install_profile(
    paths: &HostPaths,
    record: &ProfileRecord,
    arguments: &TerminalProfileInstall,
    json: bool,
) -> Result<()> {
    let terminal = named(&arguments.terminal)?;
    let home = &this_user()?;
    let command = command()?;
    // An application that is not there is refused before anything is held or written.
    if !terminal_profile::is_present(terminal, home) {
        return Err(failure(&ProfileError::NotInstalled(terminal), home));
    }
    // The person's own Terminal rewrites its preferences when it ends, and what an outside write
    // does while it runs is not known: a dry run says what it would write, and a real install waits
    // until Terminal is not running.
    if !arguments.dry_run && terminal_profile::is_running(terminal) {
        return Err(failure(&ProfileError::Running(terminal), home));
    }
    let plan = if arguments.dry_run {
        let recorded = record
            .profiles()
            .map_err(|error| record_failure(record, &error))?
            .into_iter()
            .find(|profile| profile.terminal == terminal);
        terminal_profile::plan(terminal, home, &command, recorded.as_ref())
            .map_err(|error| failure(&error, home))?
    } else {
        // The writers' lock and the permit for the record before anything is written, so a
        // release that reads the record at another version refuses the install, with nothing
        // written; the record is held until the profile is, so a removal run at the same time
        // waits for the whole install.
        let writers = crate::barrier::hold(paths)?;
        let permit = crate::barrier::permit(&writers, &PROFILE_WRITTEN)?;
        let held = record
            .hold(&permit)
            .map_err(|error| record_failure(record, &error))?;
        let recorded = held
            .profile(terminal)
            .map_err(|error| record_failure(record, &error))?;
        let plan = terminal_profile::plan(terminal, home, &command, recorded.as_ref())
            .map_err(|error| failure(&error, home))?;
        terminal_profile::install(&held, &plan).map_err(|error| failure(&error, home))?;
        plan
    };
    let readiness = readiness(paths);
    if json {
        output::document(
            &json_place(
                Document::new()
                    .with("ok", true)
                    .with("terminal", terminal.id())
                    .with("dry_run", arguments.dry_run),
                plan.place(),
            )
            .with("command", command_words(&plan.command))
            .with("default", false)
            .with("roots_from_environment", roots_from_environment())
            .with("readiness", readiness.json()),
        );
        return Ok(());
    }
    let name = Shown::said(terminal.name());
    output::say(&if arguments.dry_run {
        shown!("would write the KalaReach profile for {}", name)
    } else {
        shown!("wrote the KalaReach profile for {}", name)
    });
    say_place(plan.place());
    output::say(&shown!("  command: {}", command_shown(&plan.command)));
    output::say(&shown!(
        "  unchanged: {}'s other profiles and its default, and your shell startup files",
        name
    ));
    output::say(&shown!(
        "  choose it: {}",
        Shown::said(how_to_choose(terminal))
    ));
    output::say(&shown!(
        "  make it the default there: {}",
        Shown::said(how_to_make_default(terminal))
    ));
    output::say(&Shown::said(
        "  a window closes when its session ends, and the session goes on running when the window \
         is closed first: a profile that is the default starts a session for each window",
    ));
    if roots_from_environment() {
        output::say(&Shown::said(
            "  KR_STATE_DIR or KR_RUNTIME_DIR is set here, and a window opened through the profile \
             does not have it: that window uses the default roots, and remove finds this record \
             only with the same variable set",
        ));
    }
    readiness.say();
    Ok(())
}

/// Whether this run's own roots come from the environment, which a window the emulator opens does
/// not have.
fn roots_from_environment() -> bool {
    ["KR_STATE_DIR", "KR_RUNTIME_DIR"]
        .iter()
        .any(|name| std::env::var_os(name).is_some())
}

/// Takes out the profiles the record names, for one terminal application or for every one.
fn remove_profiles(
    paths: &HostPaths,
    record: &ProfileRecord,
    arguments: &TerminalProfileRemove,
    json: bool,
) -> Result<Completion> {
    let only = arguments
        .terminal
        .as_deref()
        .map(|text| {
            ProfileTerminal::from_id(text).ok_or_else(|| {
                CliError::Usage(Shown::said(
                    "the terminal application given is not one kr writes a profile for",
                ))
            })
        })
        .transpose()?;
    // The writers' lock and the permit for the record come before anything else is done, so a
    // release that reads the record at another version refuses the removal with nothing touched.
    let writers = (!arguments.dry_run)
        .then(|| crate::barrier::hold(paths))
        .transpose()?;
    let permit = writers
        .as_ref()
        .map(|writers| crate::barrier::permit(writers, &PROFILE_WRITTEN))
        .transpose()?;
    let home = &this_user()?;
    let results: Vec<(
        ProfileTerminal,
        std::result::Result<RemovalReport, ProfileError>,
    )> = if let Some(permit) = &permit {
        let held = record
            .hold(permit)
            .map_err(|error| record_failure(record, &error))?;
        let recorded = held
            .profiles()
            .map_err(|error| record_failure(record, &error))?;
        recorded
            .iter()
            .filter(|profile| only.is_none_or(|only| only == profile.terminal))
            .map(|profile| {
                let removed = if terminal_profile::is_running(profile.terminal) {
                    Err(ProfileError::Running(profile.terminal))
                } else {
                    terminal_profile::remove(&held, profile.terminal, home)
                };
                (profile.terminal, removed.map(RemovalReport::Did))
            })
            .collect()
    } else {
        let recorded = record
            .profiles()
            .map_err(|error| record_failure(record, &error))?;
        recorded
            .iter()
            .filter(|profile| only.is_none_or(|only| only == profile.terminal))
            .map(|profile| {
                let status =
                    terminal_profile::status(profile.terminal, home, Some(profile.clone()));
                (profile.terminal, Ok(RemovalReport::Would(status)))
            })
            .collect()
    };
    if json {
        let mut failed = None;
        let documents = results
            .iter()
            .map(|(terminal, result)| {
                let document = Document::new().with("terminal", terminal.id());
                match result {
                    Ok(report) => report.json(document),
                    Err(error) => {
                        let error = failure(error, home);
                        let document = document
                            .with("result", "failed")
                            .with("code", output::said(&error.code()))
                            .with("message", error.machine_message())
                            .with("exit_code", error.exit_code());
                        failed.get_or_insert(error);
                        document
                    }
                }
            })
            .collect::<Vec<_>>();
        output::document(
            &Document::new()
                .with("ok", failed.is_none())
                .with("dry_run", arguments.dry_run)
                .with("profiles", documents),
        );
        // The document is the result: a failure is reported by the exit status alone.
        return Ok(failed.map_or(Completion::Done, Completion::Reported));
    }
    if results.is_empty() {
        output::say(&Shown::said(
            "no terminal profile is recorded; nothing to remove",
        ));
    }
    let mut failed = None;
    for (terminal, result) in &results {
        match result {
            Ok(report) => output::say(&report.say(*terminal)),
            Err(error) => {
                let error = failure(error, home);
                output::say(&shown!(
                    "{}: not removed, and the record keeps it: {}",
                    Shown::said(terminal.name()),
                    error.machine_message()
                ));
                failed.get_or_insert(error);
            }
        }
    }
    Ok(failed.map_or(Completion::Done, Completion::Reported))
}

/// What a removal, or a dry run of one, came to for one profile.
enum RemovalReport {
    /// What a removal would do, from the profile's state now.
    Would(terminal_profile::Status),
    /// What a removal did.
    Did(Removed),
}

impl RemovalReport {
    /// A sentence for a person.
    fn say(&self, terminal: ProfileTerminal) -> Shown {
        let name = Shown::said(terminal.name());
        match self {
            Self::Would(status) => match (status.standing, status.default) {
                _ if !status.default_known => shown!(
                    "{}: whether the profile is the application's default could not be read; a \
                     removal would stop and keep the record",
                    name
                ),
                (_, true) => shown!(
                    "{}: would leave the profile, which is the application's default",
                    name
                ),
                (Some(Standing::Matches), _) => shown!("{}: would remove the profile", name),
                (Some(Standing::Missing), _) => {
                    shown!("{}: the profile is already gone; would forget it", name)
                }
                (Some(Standing::Unlisted), _) => shown!(
                    "{}: the profile is not in the application's list; would take out its settings",
                    name
                ),
                (Some(Standing::Unreadable), _) => shown!(
                    "{}: the profile could not be read; would take nothing out and keep the record",
                    name
                ),
                _ => shown!(
                    "{}: the profile was changed after kr wrote it; would leave it and forget it",
                    name
                ),
            },
            Self::Did(Removed::NotRecorded) => shown!("{}: no profile is recorded", name),
            Self::Did(Removed::Removed) => shown!("{}: removed the profile", name),
            Self::Did(Removed::AlreadyGone) => {
                shown!("{}: the profile was already gone", name)
            }
            Self::Did(Removed::Changed { left_at }) => shown!(
                "{}: left the profile at {}: it was changed after kr wrote it, so it is no longer \
                 kr's to remove",
                name,
                Shown::root(Path::new(left_at))
            ),
            Self::Did(Removed::Default) => shown!(
                "{}: left the profile, which is the application's default; choose another default \
                 there first, and the remove command takes it out",
                name
            ),
        }
    }

    /// The same, for a script.
    fn json(&self, document: Document) -> Document {
        match self {
            Self::Would(status) => document.with("result", state_word(status)),
            Self::Did(Removed::NotRecorded) => document.with("result", "not_recorded"),
            Self::Did(Removed::Removed) => document.with("result", "removed"),
            Self::Did(Removed::AlreadyGone) => document.with("result", "already_gone"),
            Self::Did(Removed::Changed { left_at }) => document
                .with("result", "left_changed")
                .with("left", Asked::text(Request::TerminalProfile, left_at)),
            Self::Did(Removed::Default) => document.with("result", "left_default"),
        }
    }
}

/// What a failure of the record says: where it is, and what to do about one that is not a record.
fn record_failure(record: &ProfileRecord, error: &RecordError) -> CliError {
    match error {
        RecordError::Store(error) => CliError::Other(shown!(
            "the record of the terminal profiles kr host terminal-profile wrote, {}: {}",
            Shown::root(record.path()),
            Shown::ipc(error)
        )),
        RecordError::NotARecord => CliError::Other(shown!(
            "{} is not a record of terminal profiles this build reads; move it aside, and kr host \
             terminal-profile records the profiles it writes again",
            Shown::root(record.path())
        )),
        RecordError::Later { found } => CliError::Other(shown!(
            "{} is a record of format {}, which a later release of kr wrote and this one does not \
             read; it was left as it was",
            Shown::root(record.path()),
            *found
        )),
        RecordError::Barred(refused) => CliError::from(refused),
    }
}

/// Says why a profile was not written or taken out.
fn failure(error: &ProfileError, home: &ProfileHome) -> CliError {
    match error {
        ProfileError::NotInstalled(terminal) => {
            let installed: Vec<Shown> = ProfileTerminal::on_this_platform()
                .iter()
                .filter(|other| terminal_profile::is_present(**other, home))
                .map(|other| Shown::said(other.name()))
                .collect();
            if installed.is_empty() {
                CliError::TerminalUnavailable(shown!(
                    "{} is not installed here, and none of the terminal applications kr writes a \
                     profile for is; nothing was written",
                    Shown::said(terminal.name())
                ))
            } else {
                CliError::TerminalUnavailable(shown!(
                    "{} is not installed here; installed: {}; nothing was written",
                    Shown::said(terminal.name()),
                    Shown::joined(installed, ", ")
                ))
            }
        }
        ProfileError::NotOnThisPlatform(terminal) => CliError::Usage(shown!(
            "{} has no profile this platform writes",
            Shown::said(terminal.name())
        )),
        ProfileError::Foreign { place } => CliError::Usage(shown!(
            "{} is there and kr did not write it, so it was left alone and nothing was written",
            Shown::root(place)
        )),
        ProfileError::Changed { place } => CliError::Usage(shown!(
            "{} was changed after kr wrote it, so it is no longer kr's to replace; nothing was \
             written. Remove it with kr host terminal-profile remove, which leaves it as it is \
             now, or move it aside",
            Shown::root(place)
        )),
        ProfileError::KonsoleExpands { word } => CliError::Usage(shown!(
            "Konsole expands a $ and a leading ~ in a profile's command, so it cannot run {}; \
             nothing was written",
            Shown::root(word)
        )),
        ProfileError::Outside(terminal) => CliError::Usage(shown!(
            "the record names {}'s profile outside the home this run is confined to, so it was \
             left alone and nothing was written",
            Shown::said(terminal.name())
        )),
        ProfileError::RecordedElsewhere { terminal, recorded } => CliError::Usage(shown!(
            "the record names {}'s profile at {}, not where this install writes it; run kr host \
             terminal-profile remove first",
            Shown::said(terminal.name()),
            Shown::root(recorded)
        )),
        ProfileError::RecordedOtherwise(terminal) => CliError::Usage(shown!(
            "the record names {}'s profile as another kind of write than this platform makes; \
             run kr host terminal-profile remove first",
            Shown::said(terminal.name())
        )),
        ProfileError::Running(terminal) => CliError::Usage(shown!(
            "{} is running, and what an outside change to its preferences does while it runs is \
             not known; quit {}, and run this from another application or an SSH session. Nothing \
             was changed",
            Shown::said(terminal.name()),
            Shown::said(terminal.name())
        )),
        ProfileError::NoProfiles(terminal) => CliError::Usage(shown!(
            "{}'s preferences hold no profile to copy, so there is nothing to base the KalaReach \
             profile on; open {} once and run this again. Nothing was written",
            Shown::said(terminal.name()),
            Shown::said(terminal.name())
        )),
        ProfileError::ToolMissing(terminal) => CliError::Usage(shown!(
            "{} keeps its profiles in the settings database, and gsettings is not installed; \
             nothing was written",
            Shown::said(terminal.name())
        )),
        ProfileError::ToolFailed { terminal, status } => {
            let tool = if *terminal == ProfileTerminal::AppleTerminal {
                "defaults or plutil"
            } else {
                "gsettings"
            };
            CliError::Other(match status {
                Some(status) => shown!(
                    "{} failed (exit status {}) while kr read or wrote {}'s profile",
                    Shown::said(tool),
                    *status,
                    Shown::said(terminal.name())
                ),
                None => shown!(
                    "{} failed or gave no answer while kr read or wrote {}'s profile; what is \
                     recorded is kept",
                    Shown::said(tool),
                    Shown::said(terminal.name())
                ),
            })
        }
        ProfileError::DefaultUnknown { terminal, place } => CliError::Other(shown!(
            "{} does not read, so which profile {} opens by default is not known and the profile \
             was left; correct or move aside that file, and run this again",
            Shown::root(place),
            Shown::said(terminal.name())
        )),
        ProfileError::SchemaAbsent(terminal) => CliError::Usage(shown!(
            "{}'s settings schema is not installed, so its profiles cannot be read or written, and \
             what was recorded is kept; install the application again to run this, or take the \
             profile's settings out of the settings database by hand",
            Shown::said(terminal.name())
        )),
        ProfileError::NoDefaultProfile(terminal) => CliError::Usage(shown!(
            "{} has no default profile in its list of profiles, and a profile written into a list \
             like that could become its default; open {} once, then run this again; nothing was \
             written",
            Shown::said(terminal.name()),
            Shown::said(terminal.name())
        )),
        ProfileError::ForeignProfile(terminal) => CliError::Usage(shown!(
            "{} has a profile named KalaReach that kr did not write, which would make choosing it \
             by name ambiguous; nothing was written",
            Shown::said(terminal.name())
        )),
        ProfileError::NotPersisted(terminal) => CliError::Usage(shown!(
            "{}'s settings did not keep what kr wrote or reset, which is what a session with no \
             settings service does; run this in a desktop session. What kr could not put back is \
             kept in its record, and kr host terminal-profile remove takes it out",
            Shown::said(terminal.name())
        )),
        ProfileError::Changing(terminal) => CliError::Other(shown!(
            "{}'s profile changed while kr was writing it, so kr stopped; what is recorded is \
             kept, and running this again tries again",
            Shown::said(terminal.name())
        )),
        ProfileError::ListBusy(terminal) => CliError::Other(shown!(
            "{}'s list of profiles changed each time kr tried to write it, so whether the profile is \
             in it is not known: kr host terminal-profile status says, and running this again \
             tries again",
            Shown::said(terminal.name())
        )),
        ProfileError::Io { place, source } => {
            CliError::Other(shown!("{}: {}", Shown::root(place), Shown::io(source)))
        }
        ProfileError::Record(error) => CliError::Other(match error {
            RecordError::Store(error) => shown!(
                "the record of the terminal profiles kr host terminal-profile wrote: {}",
                Shown::ipc(error)
            ),
            RecordError::NotARecord | RecordError::Later { .. } => Shown::said(
                "the record of the terminal profiles kr host terminal-profile wrote cannot be used",
            ),
            RecordError::Barred(refused) => return CliError::from(refused),
        }),
    }
}
