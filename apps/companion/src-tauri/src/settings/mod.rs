//! The person's settings, kept on this computer and, when the person turns it on, in step with
//! their other devices.
//!
//! # One source
//!
//! The colour mode is the first setting, and it lives here and nowhere else: the WebView holds no
//! copy of its own to disagree with. The window is opened with the mode already in its document
//! ([`LocalSettings::initial_script`]), so a dark window never paints white, and every change goes
//! through a command that writes the file before anything else happens. The page keeps nothing in
//! the WebView's storage.
//!
//! # Settings sync
//!
//! [`sync`] keeps the same settings in an encrypted collection at the sync service. It is off until
//! the person turns it on, and it never decides between two devices by which clock was ahead: a
//! device that has changed a setting since it last agreed with the service keeps its own value
//! until the person has chosen. See that module for the rules.
//!
//! What a synchronised setting is: text, a number or a switch, kept in an object that holds
//! nothing else. No setting here is a host's grant or a revocation, and no code here can reach one.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use kr_ipc::paths::{read_owner_only_file, write_owner_only_file};
use serde::{Deserialize, Serialize};

use crate::error::{CommandError, Result};

pub mod sync;

pub use sync::{SettingsSync, SyncParts, SyncState, SyncView};

/// The event the backend publishes the settings on, as a [`SettingsView`].
pub const SETTINGS_EVENT: &str = "kr://settings";

/// The file the settings are kept in, in the application's data directory.
pub const FILE: &str = "settings.json";

/// The most the file may hold, in bytes. It is a few lines of text.
const LIMIT: u64 = 16 * 1024;

/// The name of the page-visible global the settings are put on before the page's first script.
const GLOBAL: &str = "kalareachSettings";

/// How the window is coloured: light, dark, or whatever the device is set to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColourMode {
    /// Always light.
    Light,
    /// Always dark.
    Dark,
    /// Follow the device.
    #[default]
    System,
}

impl ColourMode {
    /// The word the mode is kept and synchronised under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
            Self::System => "system",
        }
    }

    /// The mode a word names, when it names one.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        match word {
            "light" => Some(Self::Light),
            "dark" => Some(Self::Dark),
            "system" => Some(Self::System),
            _ => None,
        }
    }
}

/// What the file holds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Kept {
    /// The format of this file.
    version: u32,
    /// The mode the person chose, or nothing while they have not chosen one.
    colour_mode: Option<ColourMode>,
}

impl Kept {
    const VERSION: u32 = 1;
}

/// The settings kept on this computer.
#[derive(Debug)]
pub struct LocalSettings {
    file: PathBuf,
    kept: Mutex<Kept>,
    /// Held from the moment a change is written to the moment it is the one in memory, so that
    /// two changes made together leave the file and this run saying the same thing.
    keeping: Mutex<()>,
}

impl LocalSettings {
    /// The settings kept under `data`, or none when the file is not there or is not one this
    /// build reads.
    ///
    /// A file this build will not read (a link, another owner's, wider than owner-only, text that
    /// is not settings, a version it does not know) is not trusted as the person's choice: the
    /// device's own setting stands and the log says why. The file is not touched, so a newer build
    /// still finds what it wrote.
    #[must_use]
    pub fn open(data: &Path) -> Self {
        let file = data.join(FILE);
        let kept = match read_owner_only_file(&file, LIMIT) {
            Ok(None) => Kept::default(),
            Ok(Some(bytes)) => match serde_json::from_slice::<Kept>(&bytes) {
                Ok(kept) if kept.version == Kept::VERSION => kept,
                Ok(_) => {
                    tracing::warn!("the settings file is of a version this build does not read");
                    Kept::default()
                }
                Err(error) => {
                    tracing::warn!(%error, "the settings file is not one this build reads");
                    Kept::default()
                }
            },
            Err(error) => {
                tracing::warn!(%error, "the settings file could not be read");
                Kept::default()
            }
        };
        Self {
            file,
            kept: Mutex::new(kept),
            keeping: Mutex::new(()),
        }
    }

    /// The colour mode the window is shown in: the one the person chose, or the device's.
    #[must_use]
    pub fn colour_mode(&self) -> ColourMode {
        self.chosen_colour_mode().unwrap_or_default()
    }

    /// The colour mode the person chose, when they have.
    #[must_use]
    pub fn chosen_colour_mode(&self) -> Option<ColourMode> {
        self.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .colour_mode
    }

    /// Keeps the person's choice of colour mode.
    ///
    /// The file is replaced whole and flushed before this returns, so a choice the page was told
    /// about is a choice the next start finds.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the choice cannot be kept, and then the earlier choice
    /// stands in this run.
    pub fn set_colour_mode(&self, mode: ColourMode) -> Result<()> {
        let _keeping = self.keeping.lock().unwrap_or_else(PoisonError::into_inner);
        let mut next = self
            .kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        next.version = Kept::VERSION;
        next.colour_mode = Some(mode);
        let text = serde_json::to_vec_pretty(&next).map_err(|error| {
            CommandError::local_failure(format!("the settings could not be written: {error}"))
        })?;
        write_owner_only_file(&self.file, &text).map_err(|error| {
            CommandError::local_failure(format!(
                "the settings could not be kept on this computer: {error}"
            ))
        })?;
        *self.kept.lock().unwrap_or_else(PoisonError::into_inner) = next;
        Ok(())
    }

    /// The script that puts the settings in the window's document before the page's own scripts
    /// run.
    ///
    /// It carries the mode and nothing else, as data the page reads and never code the page runs.
    #[must_use]
    pub fn initial_script(&self) -> String {
        let initial = serde_json::json!({ "colour_mode": self.colour_mode() });
        format!(
            "Object.defineProperty(window, '{GLOBAL}', {{ value: Object.freeze({initial}), \
             configurable: false, enumerable: false, writable: false }});"
        )
    }
}

/// What the page is shown of the settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SettingsView {
    /// The colour mode the window is shown in.
    pub colour_mode: ColourMode,
    /// Where settings sync stands.
    pub sync: SyncView,
}

/// Tells the page that what it shows of the settings has changed.
///
/// The backend sets what telling means once, when the window exists; until then a change has
/// nobody to tell, and the page reads the settings when it opens.
#[derive(Default)]
pub struct Told(OnceLock<Box<dyn Fn() + Send + Sync>>);

impl std::fmt::Debug for Told {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Told").finish_non_exhaustive()
    }
}

impl Told {
    /// Sets what telling does. Only the first call has an effect.
    pub fn by(&self, tell: impl Fn() + Send + Sync + 'static) {
        let _ = self.0.set(Box::new(tell));
    }

    pub(crate) fn tell(&self) {
        if let Some(tell) = self.0.get() {
            tell();
        }
    }
}

/// The settings of this computer: the file, and settings sync once this computer can take part.
#[derive(Debug)]
pub struct Settings {
    local: Arc<LocalSettings>,
    sync: OnceLock<SettingsSync>,
    told: Arc<Told>,
}

impl Settings {
    /// The settings kept under `data`.
    #[must_use]
    pub fn open(data: &Path) -> Self {
        Self {
            local: Arc::new(LocalSettings::open(data)),
            sync: OnceLock::new(),
            told: Arc::new(Told::default()),
        }
    }

    /// The settings file.
    #[must_use]
    pub fn local(&self) -> &LocalSettings {
        &self.local
    }

    /// What telling the page does.
    #[must_use]
    pub fn told(&self) -> &Told {
        &self.told
    }

    /// Lets this computer take part in settings sync, over the records kept under `data`.
    ///
    /// # Errors
    ///
    /// Returns a local failure when sync's directory cannot be made.
    pub fn take_part(&self, data: &Path, parts: SyncParts) -> Result<()> {
        let sync =
            SettingsSync::open(data, Arc::clone(&self.local), parts, Arc::clone(&self.told))?;
        let _ = self.sync.set(sync);
        Ok(())
    }

    /// What the page is shown. Nothing is sent.
    #[must_use]
    pub fn view(&self) -> SettingsView {
        SettingsView {
            colour_mode: self.local.colour_mode(),
            sync: self
                .sync
                .get()
                .map_or_else(SyncView::unavailable, SettingsSync::view),
        }
    }

    /// Keeps the person's choice of colour mode, and when sync is on, sends it.
    ///
    /// The choice is kept before anything is sent, and a service that cannot be reached is not a
    /// failure of the choice: the view says what the last step could not do.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the choice cannot be kept on this computer.
    pub async fn set_colour_mode(&self, mode: ColourMode) -> Result<SettingsView> {
        self.local.set_colour_mode(mode)?;
        self.told.tell();
        if let Some(sync) = self.sync.get() {
            let _ = sync.catch_up().await;
        }
        Ok(self.view())
    }

    /// Turns settings sync on.
    ///
    /// # Errors
    ///
    /// Returns a local failure when this computer's keys could not be opened, and otherwise what
    /// stopped the start. The start goes on from where it stopped the next time.
    pub async fn sync_turn_on(&self) -> Result<SettingsView> {
        let Some(sync) = self.sync.get() else {
            return Err(CommandError::local_failure(
                "this computer's keys could not be opened, so it cannot take part in settings sync",
            ));
        };
        sync.turn_on().await?;
        Ok(self.view())
    }

    /// Brings this computer and the sync service to the same settings, when sync is on.
    ///
    /// # Errors
    ///
    /// Returns what stopped the step.
    pub async fn sync_now(&self) -> Result<SettingsView> {
        if let Some(sync) = self.sync.get() {
            sync.catch_up().await?;
        }
        Ok(self.view())
    }
}
