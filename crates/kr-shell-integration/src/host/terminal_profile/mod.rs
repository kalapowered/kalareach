//! The optional terminal profile: one profile named `KalaReach` in one terminal emulator's own
//! profile mechanism, whose command is `kr new --attach --hold-on-failure`, so that each window or
//! tab opened through it is a session of its own.
//!
//! The profile is available and is never made the emulator's default, and nothing here writes a
//! shell startup file. What an install wrote is kept in a record of its own ([`record`]) that is
//! written before the profile, and removal works from that record alone.

pub mod record;
pub mod words;

mod apple;
mod files;
mod gsettings;
mod iterm2;
mod konsole;
mod preferences;
mod windows_terminal;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use record::{FileWrote, HeldProfiles, RecordError, RecordedProfile, Wrote};

/// The name every profile is given.
pub const PROFILE_NAME: &str = "KalaReach";

pub use gsettings::Gsettings;

/// A terminal emulator a profile can be written into.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProfileTerminal {
    /// iTerm2 (macOS): a Dynamic Profiles file.
    #[serde(rename = "iterm2")]
    Iterm2,
    /// Terminal.app (macOS): an entry of its `Window Settings` preference.
    #[serde(rename = "apple-terminal")]
    AppleTerminal,
    /// GNOME Terminal (Linux): gsettings.
    #[serde(rename = "gnome-terminal")]
    GnomeTerminal,
    /// Ptyxis (Linux): gsettings.
    #[serde(rename = "ptyxis")]
    Ptyxis,
    /// Konsole (Linux): a profile file.
    #[serde(rename = "konsole")]
    Konsole,
    /// Windows Terminal (Windows): a fragment file.
    #[serde(rename = "windows-terminal")]
    WindowsTerminal,
}

impl ProfileTerminal {
    /// Every emulator, in the order they are listed.
    pub const ALL: [Self; 6] = [
        Self::Iterm2,
        Self::AppleTerminal,
        Self::GnomeTerminal,
        Self::Ptyxis,
        Self::Konsole,
        Self::WindowsTerminal,
    ];

    /// The identifier a person names it by: the one `kr host terminal` prints where it prints one.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Iterm2 => "iterm2",
            Self::AppleTerminal => "apple-terminal",
            Self::GnomeTerminal => "gnome-terminal",
            Self::Ptyxis => "ptyxis",
            Self::Konsole => "konsole",
            Self::WindowsTerminal => "windows-terminal",
        }
    }

    /// The emulator a person's identifier names, or `None` for any other text.
    #[must_use]
    pub fn from_id(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|terminal| terminal.id() == text)
    }
}

impl ProfileTerminal {
    /// The emulators a profile can be written into on this platform, in the order they are listed.
    #[must_use]
    pub const fn on_this_platform() -> &'static [Self] {
        #[cfg(target_os = "linux")]
        {
            &[Self::GnomeTerminal, Self::Ptyxis, Self::Konsole]
        }
        #[cfg(target_os = "macos")]
        {
            &[Self::Iterm2, Self::AppleTerminal]
        }
        #[cfg(windows)]
        {
            &[Self::WindowsTerminal]
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            &[]
        }
    }

    /// The name a person knows the emulator by.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Iterm2 => "iTerm2",
            Self::AppleTerminal => "Terminal",
            Self::GnomeTerminal => "GNOME Terminal",
            Self::Ptyxis => "Ptyxis",
            Self::Konsole => "Konsole",
            Self::WindowsTerminal => "Windows Terminal",
        }
    }
}

/// The places a profile is written and read from, for one person: their home and the places the
/// emulators keep their files under it. A test names a directory of its own for each.
#[derive(Clone, Debug)]
pub struct ProfileHome {
    /// The person's home directory.
    pub home: PathBuf,
    /// The data home (`XDG_DATA_HOME`, else `~/.local/share`).
    pub data_home: PathBuf,
    /// The configuration home (`XDG_CONFIG_HOME`, else `~/.config`).
    pub config_home: PathBuf,
    /// Where macOS applications keep their files (`~/Library/Application Support`).
    pub application_support: PathBuf,
    /// The local application data folder (`%LOCALAPPDATA%`), where there is one.
    pub local_app_data: Option<PathBuf>,
    /// The directories programs are found in.
    pub programs: Vec<PathBuf>,
    /// The folders macOS applications are found in.
    pub applications: Vec<PathBuf>,
    /// iTerm2's preferences: the domain, or the path of a file standing in for it.
    pub iterm_preferences: String,
    /// Terminal's preferences: the domain, or the path of a file standing in for it.
    pub terminal_preferences: String,
    /// How the settings database is reached for the applications that keep profiles in it.
    pub settings: gsettings::Gsettings,
}

impl ProfileHome {
    /// This user's places, from the environment, or `None` when there is no absolute home.
    #[must_use]
    pub fn of_this_user() -> Option<Self> {
        let absolute = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
        };
        let home = absolute("HOME").or_else(|| absolute("USERPROFILE"))?;
        Some(Self {
            data_home: absolute("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share")),
            config_home: absolute("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config")),
            application_support: home.join("Library").join("Application Support"),
            local_app_data: absolute("LOCALAPPDATA"),
            programs: std::env::var_os("PATH")
                .map(|path| std::env::split_paths(&path).collect())
                .unwrap_or_default(),
            applications: vec![
                PathBuf::from("/Applications"),
                PathBuf::from("/System/Applications/Utilities"),
                home.join("Applications"),
            ],
            iterm_preferences: "com.googlecode.iterm2".to_owned(),
            terminal_preferences: "com.apple.Terminal".to_owned(),
            settings: gsettings::Gsettings::of_this_session(),
            home,
        })
    }

    /// The places under a home directory of its own, with programs found in `programs`. Its
    /// applications are the ones in the home's `Applications` folder, and the preferences it names
    /// are files in the home, so nothing here reaches the person's own.
    #[must_use]
    pub fn under(home: &Path, programs: Vec<PathBuf>) -> Self {
        Self {
            home: home.to_path_buf(),
            data_home: home.join(".local/share"),
            config_home: home.join(".config"),
            application_support: home.join("Library").join("Application Support"),
            local_app_data: Some(home.join("AppData").join("Local")),
            programs,
            applications: vec![home.join("Applications")],
            iterm_preferences: home
                .join("Library")
                .join("Preferences")
                .join("com.googlecode.iterm2")
                .display()
                .to_string(),
            terminal_preferences: home
                .join("Library")
                .join("Preferences")
                .join("com.apple.Terminal")
                .display()
                .to_string(),
            // A keyfile of the home's own, so nothing here reaches the person's settings.
            settings: gsettings::Gsettings {
                program: PathBuf::from("gsettings"),
                environment: vec![
                    ("GSETTINGS_BACKEND".to_owned(), "keyfile".to_owned()),
                    (
                        "XDG_CONFIG_HOME".to_owned(),
                        home.join(".config").display().to_string(),
                    ),
                    ("HOME".to_owned(), home.display().to_string()),
                ],
            },
        }
    }

    /// Whether a program of this name is in one of the directories programs are found in.
    #[must_use]
    pub fn has_program(&self, name: &str) -> bool {
        self.programs
            .iter()
            .any(|directory| directory.join(name).is_file())
    }

    /// Whether an application of this name is in one of the folders applications are found in.
    #[must_use]
    pub fn has_application(&self, name: &str) -> bool {
        self.applications
            .iter()
            .any(|directory| directory.join(name).is_dir())
    }
}

/// Why a profile was not written or taken out.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    /// The emulator is not installed.
    #[error("{} is not installed here", .0.name())]
    NotInstalled(ProfileTerminal),
    /// This platform has no profile to write for the emulator.
    #[error("{} has no profile this platform writes", .0.name())]
    NotOnThisPlatform(ProfileTerminal),
    /// A file is at the profile's place that this kr did not write.
    #[error("{} is there and kr did not write it; it was left alone", .place.display())]
    Foreign {
        /// What is there.
        place: PathBuf,
    },
    /// The profile the record names was changed after kr wrote it.
    #[error("{} was changed after kr wrote it, so it is no longer kr's to replace", .place.display())]
    Changed {
        /// What was changed.
        place: PathBuf,
    },
    /// Konsole expands a `$` and a leading `~` in a profile's command, and the command has one.
    #[error("Konsole expands a $ and a leading ~ in a profile's command, so it cannot run {}", .word.display())]
    KonsoleExpands {
        /// The word.
        word: PathBuf,
    },
    /// The record names a profile for the emulator that is not where this install writes it.
    #[error("the record names {}'s profile at {}, not where this install writes it", .terminal.name(), .recorded.display())]
    RecordedElsewhere {
        /// The emulator.
        terminal: ProfileTerminal,
        /// Where the record says it is.
        recorded: PathBuf,
    },
    /// The record names a profile for the emulator that is not of the kind this install writes.
    #[error("the record names {}'s profile as another kind of write than this platform makes", .0.name())]
    RecordedOtherwise(ProfileTerminal),
    /// The person's own Terminal is running, and an outside write to its preferences while it does
    /// is not one anything is known to survive.
    #[error("{} is running", .0.name())]
    Running(ProfileTerminal),
    /// There is no profile to copy: the preferences hold no dictionary of profiles, or none that
    /// kr can copy.
    #[error("{} has no profile in its preferences to copy", .0.name())]
    NoProfiles(ProfileTerminal),
    /// The settings program is not there.
    #[error("{} keeps its profiles in the settings database, and gsettings is not there", .0.name())]
    ToolMissing(ProfileTerminal),
    /// The settings program failed.
    #[error("gsettings failed for {}", .terminal.name())]
    ToolFailed {
        /// The emulator.
        terminal: ProfileTerminal,
        /// The exit status, where there was one.
        status: Option<i32>,
    },
    /// The schema the profile is written to is not installed.
    #[error("{}'s settings schema is not installed", .0.name())]
    SchemaAbsent(ProfileTerminal),
    /// The list of profiles names no default, or its default is not in it.
    #[error("{} has no default profile in its list of profiles", .0.name())]
    NoDefaultProfile(ProfileTerminal),
    /// A profile named like this one is in the list and kr did not write it.
    #[error("{} has a profile named KalaReach that kr did not write", .0.name())]
    ForeignProfile(ProfileTerminal),
    /// A write did not outlast the process that made it.
    #[error("{}'s settings did not keep a write; there is no settings service in this session", .0.name())]
    NotPersisted(ProfileTerminal),
    /// The list of profiles changed under every attempt to write it.
    #[error("{}'s list of profiles kept changing while it was written", .0.name())]
    ListBusy(ProfileTerminal),
    /// A file could not be read or written.
    #[error("{}: {source}", .place.display())]
    Io {
        /// The file.
        place: PathBuf,
        /// What failed.
        #[source]
        source: std::io::Error,
    },
    /// The record could not be used.
    #[error(transparent)]
    Record(#[from] RecordError),
}

impl ProfileError {
    fn io(place: &Path, source: std::io::Error) -> Self {
        Self::Io {
            place: place.to_path_buf(),
            source,
        }
    }
}

/// Whether `terminal` is installed.
#[must_use]
pub fn is_present(terminal: ProfileTerminal, home: &ProfileHome) -> bool {
    match terminal {
        ProfileTerminal::Konsole => konsole::present(home),
        ProfileTerminal::Iterm2 => iterm2::present(home),
        ProfileTerminal::WindowsTerminal => windows_terminal::present(home),
        ProfileTerminal::GnomeTerminal => home.has_program("gnome-terminal"),
        ProfileTerminal::Ptyxis => home.has_program("ptyxis"),
        ProfileTerminal::AppleTerminal => apple::present(home),
    }
}

/// Whether the person's own application is running, which it must not be for a write to its
/// preferences.
#[must_use]
pub fn is_running(terminal: ProfileTerminal) -> bool {
    terminal == ProfileTerminal::AppleTerminal && apple::is_running()
}

/// What an install of one profile would write, worked out before anything is written.
#[derive(Clone, Debug)]
pub struct Plan {
    /// The emulator.
    pub terminal: ProfileTerminal,
    /// The argument vector the profile runs.
    pub command: Vec<String>,
    /// What the record is told the install intends to write.
    pub wrote: Wrote,
    /// How it is written.
    how: How,
}

/// What a plan writes, as a person is told it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place<'a> {
    /// A file.
    File(&'a Path),
    /// Keys of a settings schema, at a path.
    Settings {
        /// The schema.
        schema: &'a str,
        /// The path of the profile's keys.
        path: &'a str,
    },
    /// An entry of a dictionary in an application's preferences.
    Preferences {
        /// The preferences' domain.
        domain: &'a str,
        /// The key of the dictionary.
        key: &'a str,
        /// The entry's name in it.
        entry: &'a str,
    },
}

impl Plan {
    /// What the install writes.
    #[must_use]
    pub fn place(&self) -> Place<'_> {
        match &self.how {
            How::File { destination, .. } => Place::File(destination),
            How::Settings(plan) => Place::Settings {
                schema: &plan.wrote.schema,
                path: &plan.wrote.path,
            },
            How::Preferences(plan) => Place::Preferences {
                domain: &plan.domain,
                key: &plan.wrote.key,
                entry: &plan.wrote.entry,
            },
        }
    }
}

/// How a plan is carried out.
#[derive(Clone, Debug)]
enum How {
    /// A file, published whole.
    File {
        destination: PathBuf,
        staging: PathBuf,
        text: String,
        made: Vec<PathBuf>,
        replace: bool,
    },
    /// Keys of a settings schema, and a place in a shared list.
    Settings(Box<gsettings::SettingsPlan>),
    /// An entry of a preferences dictionary.
    Preferences(Box<apple::PreferencesPlan>),
}

/// Works out what installing `terminal`'s profile with `command` would write, and refuses what it
/// must not write over. `recorded` is what the record names for the emulator now.
///
/// Nothing is written: this is the whole of a dry run.
///
/// # Errors
///
/// Returns why the profile is not written.
pub fn plan(
    terminal: ProfileTerminal,
    home: &ProfileHome,
    command: &[String],
    recorded: Option<&RecordedProfile>,
) -> Result<Plan, ProfileError> {
    if !is_present(terminal, home) {
        return Err(ProfileError::NotInstalled(terminal));
    }
    match terminal {
        ProfileTerminal::Konsole => plan_file(
            terminal,
            &konsole::profile_path(home),
            &konsole::watched(home),
            konsole::profile_text(command)?,
            command,
            recorded,
        ),
        ProfileTerminal::Iterm2 => {
            let destination = iterm2::profile_path(home);
            // A profile written again is the same profile to iTerm2: the identifier the file holds
            // is kept, when it is the file kr wrote.
            let guid = match recorded.map(|profile| &profile.wrote) {
                Some(Wrote::File(wrote))
                    if files::presence(&destination)
                        == files::Presence::File(wrote.sha256.clone()) =>
                {
                    std::fs::read_to_string(&destination)
                        .ok()
                        .and_then(|text| iterm2::guid_in(&text))
                }
                _ => None,
            }
            .unwrap_or_else(iterm2::new_guid);
            plan_file(
                terminal,
                &destination,
                &iterm2::watched(home),
                iterm2::profile_text(command, &guid),
                command,
                recorded,
            )
        }
        ProfileTerminal::WindowsTerminal => {
            let (Some(destination), Some(watched)) = (
                windows_terminal::profile_path(home),
                windows_terminal::watched(home),
            ) else {
                return Err(ProfileError::NotOnThisPlatform(terminal));
            };
            plan_file(
                terminal,
                &destination,
                &watched,
                windows_terminal::profile_text(command),
                command,
                recorded,
            )
        }
        ProfileTerminal::GnomeTerminal | ProfileTerminal::Ptyxis => {
            let spec = settings_spec(terminal)?;
            let earlier = match recorded.map(|profile| &profile.wrote) {
                Some(Wrote::Settings(wrote)) => Some(wrote),
                Some(_) => return Err(ProfileError::RecordedOtherwise(terminal)),
                None => None,
            };
            let plan =
                gsettings::plan(&home.settings, spec, &words::shell_words(command), earlier)?;
            // A profile that was changed after kr wrote it is not kr's to write over.
            if let Some(earlier) = earlier
                && gsettings::read(&home.settings, spec, earlier) == gsettings::Reading::Changed
            {
                return Err(ProfileError::Changed {
                    place: PathBuf::from(&earlier.path),
                });
            }
            Ok(Plan {
                terminal,
                command: command.to_vec(),
                wrote: Wrote::Settings(plan.wrote.clone()),
                how: How::Settings(Box::new(plan)),
            })
        }
        ProfileTerminal::AppleTerminal => {
            let earlier = match recorded.map(|profile| &profile.wrote) {
                Some(Wrote::Preferences(wrote)) => Some(wrote),
                Some(_) => return Err(ProfileError::RecordedOtherwise(terminal)),
                None => None,
            };
            let plan = apple::plan(home, &words::shell_words(command), earlier)?;
            Ok(Plan {
                terminal,
                command: command.to_vec(),
                wrote: Wrote::Preferences(plan.wrote.clone()),
                how: How::Preferences(Box::new(plan)),
            })
        }
    }
}

/// The settings layout of an application that keeps its profiles there.
fn settings_spec(terminal: ProfileTerminal) -> Result<gsettings::Spec, ProfileError> {
    match terminal {
        ProfileTerminal::GnomeTerminal => Ok(gsettings::GNOME),
        ProfileTerminal::Ptyxis => Ok(gsettings::PTYXIS),
        _ => Err(ProfileError::NotOnThisPlatform(terminal)),
    }
}

/// The plan of a profile that is one file in a directory the emulator watches.
fn plan_file(
    terminal: ProfileTerminal,
    destination: &Path,
    watched: &Path,
    text: String,
    command: &[String],
    recorded: Option<&RecordedProfile>,
) -> Result<Plan, ProfileError> {
    let place = destination.to_path_buf();
    let staging = watched
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| ProfileError::io(destination, std::io::ErrorKind::NotFound.into()))?;
    let earlier = match recorded.map(|profile| &profile.wrote) {
        Some(Wrote::File(wrote)) => Some(wrote),
        Some(_) => return Err(ProfileError::RecordedOtherwise(terminal)),
        None => None,
    };
    let (replace, made) = match (earlier, files::presence(destination)) {
        // Nothing the record names is there, and something is: it is not kr's.
        (None, files::Presence::File(_) | files::Presence::Other) => {
            return Err(ProfileError::Foreign { place });
        }
        (None, files::Presence::Missing) => {
            (false, files::missing_directories(&parent_of(destination)))
        }
        (Some(earlier), presence) => {
            let recorded_file = earlier.file()?;
            if recorded_file != destination {
                return Err(ProfileError::RecordedElsewhere {
                    terminal,
                    recorded: recorded_file,
                });
            }
            match presence {
                files::Presence::File(sha) if sha == earlier.sha256 => {
                    (true, earlier.made_directories()?)
                }
                files::Presence::File(_) | files::Presence::Other => {
                    return Err(ProfileError::Changed { place });
                }
                // Gone since: written again, and the directories it needed are made again.
                files::Presence::Missing => {
                    (false, files::missing_directories(&parent_of(destination)))
                }
            }
        }
    };
    let wrote = Wrote::File(FileWrote::intending(destination, &text, &made));
    Ok(Plan {
        terminal,
        command: command.to_vec(),
        wrote,
        how: How::File {
            destination: destination.to_path_buf(),
            staging,
            text,
            made,
            replace,
        },
    })
}

/// The directory a file is in.
fn parent_of(path: &Path) -> PathBuf {
    path.parent().map_or_else(PathBuf::new, Path::to_path_buf)
}

/// Installs the profile `plan` describes: the record is told first, then the profile is written,
/// and a write that fails takes the record's entry back.
///
/// # Errors
///
/// Returns the failure of the record or of the write.
pub fn install(held: &HeldProfiles<'_>, plan: &Plan) -> Result<(), ProfileError> {
    let before = held.profile(plan.terminal)?;
    held.put(RecordedProfile {
        terminal: plan.terminal,
        command: plan.command.clone(),
        wrote: plan.wrote.clone(),
    })?;
    if let Err((error, left_over)) = write(plan) {
        // What the write could not take back stays recorded, so that a removal can finish the job.
        if !left_over {
            match before {
                Some(profile) => held.put(profile)?,
                None => held.forget(plan.terminal)?,
            }
        }
        return Err(error);
    }
    Ok(())
}

/// Carries out a plan. A failure says whether anything may be left that the write could not take
/// back.
fn write(plan: &Plan) -> Result<(), (ProfileError, bool)> {
    match &plan.how {
        How::File {
            destination,
            staging,
            text,
            made,
            replace,
        } => files::publish(destination, staging, text, made, *replace)
            .map_err(|error| (ProfileError::io(destination, error), false)),
        How::Settings(plan) => gsettings::write(plan),
        How::Preferences(plan) => apple::write(plan).map_err(|error| (error, false)),
    }
}

/// Where a recorded profile stands against what is there now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// It is there and holds what was written.
    Matches,
    /// It is there and holds something else.
    Changed,
    /// It is not there.
    Missing,
}

/// What `status` knows of one emulator.
#[derive(Clone, Debug)]
pub struct Status {
    /// The emulator.
    pub terminal: ProfileTerminal,
    /// Whether it is installed.
    pub present: bool,
    /// What the record names for it, if anything.
    pub recorded: Option<RecordedProfile>,
    /// Where the recorded profile stands, when one is recorded.
    pub standing: Option<Standing>,
    /// Whether something is at the profile's place that the record does not name.
    pub foreign: bool,
    /// Whether the recorded profile is the emulator's default.
    pub default: bool,
}

/// Reads the state of `terminal`'s profile. It writes nothing and holds nothing.
#[must_use]
pub fn status(
    terminal: ProfileTerminal,
    home: &ProfileHome,
    recorded: Option<RecordedProfile>,
) -> Status {
    let standing = recorded.as_ref().map(|profile| standing(profile, home));
    let foreign = recorded.is_none()
        && (profile_path(terminal, home)
            .is_some_and(|path| files::presence(&path) != files::Presence::Missing)
            || settings_spec(terminal).is_ok_and(|spec| {
                is_present(terminal, home) && gsettings::foreign(&home.settings, spec)
            })
            || (terminal == ProfileTerminal::AppleTerminal && apple::foreign(home)));
    let default = recorded
        .as_ref()
        .is_some_and(|profile| is_default(terminal, home, profile));
    Status {
        terminal,
        present: is_present(terminal, home),
        recorded,
        standing,
        foreign,
        default,
    }
}

/// Where a recorded profile stands.
fn standing(profile: &RecordedProfile, home: &ProfileHome) -> Standing {
    match &profile.wrote {
        Wrote::File(wrote) => match wrote.file().map(|file| files::presence(&file)) {
            Ok(files::Presence::Missing) => Standing::Missing,
            Ok(files::Presence::File(sha)) if sha == wrote.sha256 => Standing::Matches,
            _ => Standing::Changed,
        },
        Wrote::Settings(wrote) => settings_spec(profile.terminal).map_or(
            Standing::Changed,
            |spec| match gsettings::read(&home.settings, spec, wrote) {
                gsettings::Reading::Unchanged { .. } => Standing::Matches,
                gsettings::Reading::Gone => Standing::Missing,
                gsettings::Reading::Changed => Standing::Changed,
            },
        ),
        Wrote::Preferences(wrote) => match apple::reading(&wrote.domain, wrote) {
            apple::Reading::Matches => Standing::Matches,
            apple::Reading::Changed => Standing::Changed,
            apple::Reading::Missing => Standing::Missing,
        },
    }
}

/// Where a terminal application's profile file is, for those whose profile is a file.
fn profile_path(terminal: ProfileTerminal, home: &ProfileHome) -> Option<PathBuf> {
    match terminal {
        ProfileTerminal::Konsole => Some(konsole::profile_path(home)),
        ProfileTerminal::Iterm2 => Some(iterm2::profile_path(home)),
        ProfileTerminal::WindowsTerminal => windows_terminal::profile_path(home),
        _ => None,
    }
}

/// Whether the recorded profile is the emulator's default.
fn is_default(terminal: ProfileTerminal, home: &ProfileHome, profile: &RecordedProfile) -> bool {
    match terminal {
        ProfileTerminal::Konsole => konsole::is_default(home),
        ProfileTerminal::Iterm2 => match &profile.wrote {
            Wrote::File(wrote) => wrote
                .file()
                .ok()
                .and_then(|file| std::fs::read_to_string(file).ok())
                .and_then(|text| iterm2::guid_in(&text))
                .is_some_and(|guid| iterm2::is_default(home, &guid)),
            _ => false,
        },
        ProfileTerminal::WindowsTerminal => windows_terminal::is_default(home),
        ProfileTerminal::GnomeTerminal | ProfileTerminal::Ptyxis => match &profile.wrote {
            Wrote::Settings(wrote) => settings_spec(terminal)
                .is_ok_and(|spec| gsettings::is_default(&home.settings, spec, wrote)),
            _ => false,
        },
        ProfileTerminal::AppleTerminal => match &profile.wrote {
            Wrote::Preferences(wrote) => apple::is_default(&wrote.domain, wrote),
            _ => false,
        },
    }
}

/// What a removal came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Removed {
    /// The record named nothing for the emulator.
    NotRecorded,
    /// The profile is taken out.
    Removed,
    /// The profile was already gone.
    AlreadyGone,
    /// The profile was changed after kr wrote it. It is left, and the record forgets it.
    Changed {
        /// Where the changed profile is.
        left_at: String,
    },
    /// The profile is the emulator's default. It is left and the record keeps it.
    Default,
}

/// Takes `terminal`'s profile out, working from the record alone.
///
/// # Errors
///
/// Returns the failure of the record or of the removal; the record keeps the entry then.
pub fn remove(
    held: &HeldProfiles<'_>,
    terminal: ProfileTerminal,
    home: &ProfileHome,
) -> Result<Removed, ProfileError> {
    let Some(profile) = held.profile(terminal)? else {
        return Ok(Removed::NotRecorded);
    };
    let removed = match &profile.wrote {
        Wrote::File(wrote) => {
            let destination = wrote.file()?;
            if standing(&profile, home) != Standing::Missing && is_default(terminal, home, &profile)
            {
                return Ok(Removed::Default);
            }
            let staging = match terminal {
                ProfileTerminal::Konsole => konsole::staging(&destination),
                ProfileTerminal::Iterm2 => iterm2::staging(&destination),
                ProfileTerminal::WindowsTerminal => windows_terminal::staging(&destination),
                _ => None,
            }
            .ok_or_else(|| ProfileError::io(&destination, std::io::ErrorKind::NotFound.into()))?;
            match files::remove_if_unchanged(
                &destination,
                &staging,
                &wrote.sha256,
                &wrote.made_directories()?,
            )
            .map_err(|error| ProfileError::io(&destination, error))?
            {
                files::Removal::Gone => Removed::AlreadyGone,
                files::Removal::Removed => Removed::Removed,
                files::Removal::Changed { left_at, .. } => Removed::Changed {
                    left_at: left_at.display().to_string(),
                },
            }
        }
        Wrote::Settings(wrote) => {
            let spec = settings_spec(terminal)?;
            let reading = gsettings::read(&home.settings, spec, wrote);
            if reading != gsettings::Reading::Gone && is_default(terminal, home, &profile) {
                return Ok(Removed::Default);
            }
            match reading {
                gsettings::Reading::Gone => Removed::AlreadyGone,
                gsettings::Reading::Unchanged { .. } => {
                    gsettings::take_out(&home.settings, spec, wrote)?;
                    Removed::Removed
                }
                gsettings::Reading::Changed => Removed::Changed {
                    left_at: wrote.path.clone(),
                },
            }
        }
        Wrote::Preferences(wrote) => {
            if apple::reading(&wrote.domain, wrote) != apple::Reading::Missing
                && is_default(terminal, home, &profile)
            {
                return Ok(Removed::Default);
            }
            match apple::reading(&wrote.domain, wrote) {
                apple::Reading::Missing => Removed::AlreadyGone,
                apple::Reading::Matches => {
                    apple::take_out(&wrote.domain)?;
                    Removed::Removed
                }
                apple::Reading::Changed => Removed::Changed {
                    left_at: format!("{}.{}", wrote.key, wrote.entry),
                },
            }
        }
    };
    held.forget(terminal)?;
    Ok(removed)
}
