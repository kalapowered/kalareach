//! Restoring the settings saved with the recovery bundle, with the kit alone.
//!
//! A new device has no recovery record, no bundle store and no account it can name beforehand: it
//! has the kit the person saved. The kit opens the bundle at the service it names, or in an export
//! file the person saved with no network, and only the settings member is read out of it. What
//! comes back is values, and they are put on this device by the same compare-and-swap the settings
//! file keeps for every other writer: a device that has already chosen is not replaced, nor one
//! whose settings file cannot be read, and the person is told which it was.
//!
//! The page asks for a restore and names nothing. This process raises the open panels, reads the
//! kit and the export file from the paths they return, and holds the seed only as long as the
//! restore runs: the kit is cleared when it is dropped. The page is told no path, no locator and
//! no key, only what the restore came to.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_client::pairing::BoxFuture;
use kr_client::recovery::{
    AccountSource, ExportSource, FilesRestore, MAX_EXPORT_BYTES, MAX_RECOVERY_KIT_BYTES,
    OfflineExport, RecoveryError, RestoreError, RestoreSource, SavedSettings, parse_kit,
};
use kr_client::services::account::AccountTokenSource;
use kr_client::services::{HttpDeadlines, HttpService, managed_response_limits};
use kr_protocol::archive::RecoveryKit;
use kr_protocol::service::GatewayOrigin;
use serde::Serialize;
use zeroize::Zeroizing;

use super::{Named, Recovery, refuse_if_blocked, said, said_by_restore};
use crate::account::Account;
use crate::error::{CommandError, Result};
use crate::settings::{COLOUR_MODE, ColourMode, LocalSettings, Settings};

/// The title of the panel that chooses the kit.
pub const KIT_PANEL: &str = "Choose your recovery kit";

/// The title of the panel that chooses an exported bundle file.
pub const EXPORT_PANEL: &str = "Choose your exported bundle file";

/// What a restore of the saved settings came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SettingsRestored {
    /// The settings are back on this device.
    Restored {
        /// When the bundle was last written. Changes made on the device that saved it after that
        /// are not in it.
        bundle_written_at_ms: u64,
    },
    /// This device has chosen settings of its own, so nothing was replaced.
    AlreadyChosen,
    /// This device's settings file cannot be read, so nothing was changed.
    FileUnreadable,
    /// The bundle holds no saved settings.
    NoneSaved,
    /// The bundle opened, and the settings saved with it cannot be used on this device.
    Unusable,
    /// The bundle opened, and this version cannot read it: a later version may have written it.
    NeedsNewer,
    /// The person closed a panel, so nothing was read.
    Cancelled,
}

/// Where the person chooses a file: the platform's open panels, which this process raises. A test
/// answers for the person.
pub trait OpenPanels: Send + Sync {
    /// Shows an open panel titled `title` and returns the file the person chose, or none when they
    /// closed it.
    fn choose(&self, title: &'static str) -> BoxFuture<'_, Result<Option<PathBuf>>>;
}

/// The platform's own open panel, modal to the application's window.
#[derive(Debug)]
pub struct NativePanels<R: tauri::Runtime> {
    app: tauri::AppHandle<R>,
}

impl<R: tauri::Runtime> NativePanels<R> {
    /// The panels of `app`.
    #[must_use]
    pub const fn new(app: tauri::AppHandle<R>) -> Self {
        Self { app }
    }
}

impl<R: tauri::Runtime> OpenPanels for NativePanels<R> {
    fn choose(&self, title: &'static str) -> BoxFuture<'_, Result<Option<PathBuf>>> {
        use tauri_plugin_dialog::DialogExt as _;

        Box::pin(async move {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            self.app
                .dialog()
                .file()
                .set_title(title)
                .pick_file(move |path| {
                    let _ = sender.send(path);
                });
            let chosen = receiver
                .await
                .map_err(|_| CommandError::local_failure("the open dialog did not answer"))?;
            chosen
                .map(|path| {
                    path.into_path().map_err(|error| {
                        CommandError::invalid(format!("that file is not a path: {error}"))
                    })
                })
                .transpose()
        })
    }
}

impl Recovery {
    /// A source that reads the bundle at the service the kit names, with `account`'s sign-in.
    ///
    /// # Errors
    ///
    /// Refuses when the kit names no service this device can reach, or the account is not signed
    /// in there, and returns a local failure when the transport cannot be made.
    pub fn account_source_for(
        &self,
        account: &Account,
        kit: &RecoveryKit,
    ) -> Result<Arc<dyn RestoreSource>> {
        // A kit that parsed names at least one service; an empty name is refused as any other
        // text that is no origin is.
        let origin = GatewayOrigin::new(kit.service_origins.first().map_or("", String::as_str))
            .map_err(|error| {
                CommandError::refused(format!(
                    "the service the kit names is not one this device can reach: {error}"
                ))
            })?;
        refuse_if_blocked(account, &origin, Named::ByKit)?;
        let http = HttpService::with(
            origin.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .map_err(|error| {
            CommandError::local_failure(format!(
                "this device cannot reach the service the kit names: {error}"
            ))
        })?;
        let tokens: Arc<dyn AccountTokenSource> = account.tokens();
        Ok(Arc::new(AccountSource::new(
            origin,
            Arc::new(http),
            Arc::clone(&self.signer),
            tokens,
        )))
    }

    /// Asks the person for a recovery kit, and for an exported bundle file when `from_file`, and
    /// puts the settings saved in the bundle on this device where it has chosen nothing. A restore
    /// that puts them back tells the window, as any other change to the settings does, so that the
    /// window shows the restored mode at once.
    ///
    /// # Errors
    ///
    /// Returns the failures a restore of the bundle has (a kit that does not open it, a service
    /// that cannot be reached, a bundle that does not authenticate, a file that is not what it is
    /// said to be). A bundle that opens and holds nothing usable is an answer, not a failure, and a
    /// closed panel is [`SettingsRestored::Cancelled`].
    pub async fn restore_settings_with(
        &self,
        panels: &dyn OpenPanels,
        account: &Account,
        settings: &Settings,
        from_file: bool,
    ) -> Result<SettingsRestored> {
        let Some(kit_path) = panels.choose(KIT_PANEL).await? else {
            return Ok(SettingsRestored::Cancelled);
        };
        let kit = read_kit(&kit_path)?;
        let source = if from_file {
            let Some(export_path) = panels.choose(EXPORT_PANEL).await? else {
                return Ok(SettingsRestored::Cancelled);
            };
            file_source(&export_path)?
        } else {
            self.account_source_for(account, &kit)?
        };
        let restored = restore_settings(kit, source, settings.local()).await?;
        if matches!(restored, SettingsRestored::Restored { .. }) {
            settings.told().tell();
        }
        Ok(restored)
    }
}

/// Reads a kit from the file the person chose: a regular file, and text of at most a kit's size.
/// What is read is cleared when it is dropped.
fn read_kit(path: &Path) -> Result<RecoveryKit> {
    let unreadable = || CommandError::invalid("the kit file could not be read");
    let metadata = std::fs::symlink_metadata(path).map_err(|_| unreadable())?;
    if !metadata.is_file() {
        return Err(unreadable());
    }
    // One byte past the kit's size, so that a file over it is read as over it.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_RECOVERY_KIT_BYTES + 1));
    std::fs::File::open(path)
        .and_then(|file| {
            file.take(u64::try_from(MAX_RECOVERY_KIT_BYTES).unwrap_or(u64::MAX) + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|_| unreadable())?;
    let text = std::str::from_utf8(&bytes).map_err(|_| unreadable())?;
    parse_kit(text).map_err(said)
}

/// A source that reads the bundle from the export file the person chose, with no account and no
/// network: a regular file, no larger than an export is, and an export in the format this release
/// reads.
fn file_source(path: &Path) -> Result<Arc<dyn RestoreSource>> {
    let unreadable = || CommandError::invalid("the export file could not be read");
    let metadata = std::fs::symlink_metadata(path).map_err(|_| unreadable())?;
    if !metadata.is_file() {
        return Err(unreadable());
    }
    // The cap leaves room for the bundle and the file's own framing beside the archive.
    let limit = MAX_EXPORT_BYTES + 1024 * 1024;
    if metadata.len() > limit {
        return Err(CommandError::too_large(
            "the export file is larger than an export is",
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    std::fs::File::open(path)
        .and_then(|file| file.take(limit).read_to_end(&mut bytes))
        .map_err(|_| unreadable())?;
    let export = OfflineExport::from_canonical_slice(&bytes).map_err(|error| match error {
        RecoveryError::UnsupportedExport => CommandError::invalid(
            "that file is an offline export in a format this release does not read",
        ),
        _ => CommandError::invalid("that file is not an offline export"),
    })?;
    Ok(Arc::new(ExportSource::new(export)))
}

/// Reads the saved settings out of the bundle `source` gives, with `kit`, and puts them on `local`
/// where this device has chosen nothing.
///
/// # Errors
///
/// Returns the failures a restore of the bundle has; a bundle that opens and holds nothing usable
/// is an answer, not a failure.
pub async fn restore_settings(
    kit: RecoveryKit,
    source: Arc<dyn RestoreSource>,
    local: &LocalSettings,
) -> Result<SettingsRestored> {
    settings_restored(local, FilesRestore::settings(kit, source).await)
}

/// What reading the saved settings came to, put on `local`: the one place a restore writes.
///
/// # Errors
///
/// Returns a failure of the restore that is not about the settings, and a local failure when the
/// settings file cannot be written.
pub fn settings_restored(
    local: &LocalSettings,
    found: std::result::Result<SavedSettings, RestoreError>,
) -> Result<SettingsRestored> {
    match found {
        Ok(SavedSettings::NoneSaved) => Ok(SettingsRestored::NoneSaved),
        Ok(SavedSettings::Found {
            settings,
            bundle_written_at_ms,
        }) => {
            let Some(mode) = settings.get(COLOUR_MODE).and_then(ColourMode::from_setting) else {
                // A member that holds values this build does not read is saved settings it cannot
                // use, not an empty bundle.
                return Ok(if settings.is_empty() {
                    SettingsRestored::NoneSaved
                } else {
                    SettingsRestored::Unusable
                });
            };
            // Nothing chosen is the only thing a restore replaces, and the comparison and the
            // write are one act, so a choice made while the bundle was being read is kept.
            if local.replace_colour_mode(None, mode)? {
                Ok(SettingsRestored::Restored {
                    bundle_written_at_ms: bundle_written_at_ms.get(),
                })
            } else if local.for_backup() == kr_client::recovery::LocalSettings::Unreadable {
                Ok(SettingsRestored::FileUnreadable)
            } else {
                Ok(SettingsRestored::AlreadyChosen)
            }
        }
        Err(RestoreError::Recovery(cause)) => match *cause {
            RecoveryError::SettingsUnusable { .. } => Ok(SettingsRestored::Unusable),
            RecoveryError::BundleNeedsANewerKr => Ok(SettingsRestored::NeedsNewer),
            other => Err(said(other)),
        },
        Err(other) => Err(said_by_restore(other)),
    }
}
