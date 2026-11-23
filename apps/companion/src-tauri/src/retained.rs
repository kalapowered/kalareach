//! Deleting a copy that left the host, at the computer the host runs on.
//!
//! Privacy mode lists what had already left the host and does not erase it. A copy that the host
//! can ask for the removal of is deleted by the person's own action, and the page is not that
//! action: it names a copy and cannot confirm. The confirmation is a native dialog this process
//! raises and answers, so a page that is compromised, or mistaken, cannot delete anything.
//!
//! There are three kinds of copy. What the host sent (its backup archives) is deleted by asking the
//! host, which asks the service. What this application's own sync sent (settings and drafts the
//! sync service refused and kept a copy of) is deleted by asking the sync service, with no host in
//! between. The settings saved with this computer's recovery bundle are removed by writing the
//! bundle without them, with no host in between either; the bundle and its keys stay. All go
//! through the same ceremony of three commands, and the page supplies no method and no parameter
//! of one:
//!
//! * **Ask.** The page names a copy by the reference it is listed under. This process reads the
//!   lists again, requires exactly one entry with that reference and requires it to be deletable,
//!   then shows the dialog and waits for the person's answer. A yes mints a token, bound to the
//!   copy's reference and, for a host's copy, to the host's environment and the privacy generation
//!   the list was read at. A no mints nothing.
//! * **Finish.** The token is single-use: finishing takes it, so finishing again, after a cancel,
//!   after it expired or with a token this process never minted is refused. The list is read once
//!   more and must still hold the same one deletable copy, at the same privacy generation for a
//!   host's. Only then is the deletion asked, and the page is told whether the service confirmed it.
//! * **Cancel.** The token is dropped.
//!
//! A native dialog is the trusted local owner's confirmation at this computer. It is not a
//! cryptographic proof that a person is present, and nothing here claims it is. A host's copy is
//! deleted only at the computer the host runs on: a phone, and a host this device is paired with,
//! show the list and offer nothing, because the host serves the deletion on the owner's own socket
//! only.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use kr_client::pairing::BoxFuture;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::EnvironmentId;
use kr_protocol::method::Method;
use kr_protocol::privacy::{
    PrivacyExported, PrivacyReport, PrivacyRetainedDeleteParams, PrivacyRetainedDeleteResult,
    PrivacyStatusParams,
};
use kr_protocol::scalars::TimestampMs;
use serde::Serialize;

use crate::commands::{MUTATION_TTL, NoPreconditions};
use crate::connection::{Connection, Standing};
use crate::error::{CommandError, Result};
use crate::recovery::SettingsRemoved;
use crate::settings::Settings;

/// How long a token lives: long enough to read the page and press the button, short enough that a
/// confirmation does not outlast the moment it was given for.
pub const TOKEN_LIFETIME: Duration = Duration::from_secs(120);

/// The most characters of the host's words a dialog repeats.
const MOST_SHOWN: usize = 160;

/// The reference the settings saved with the recovery bundle are listed and removed under.
pub const SETTINGS_REFERENCE: &str = "settings-saved";

/// What the page and the dialog call the settings saved with the recovery bundle.
pub const SETTINGS_KIND: &str = "Settings saved with your recovery bundle";

/// What removing them asks, in this application's words, and what it leaves alone.
const SETTINGS_WORDS: &str = "This removes your saved settings from your recovery bundle. Your \
    recovery bundle and its keys stay. Copies you exported, and copies your service's providers \
    keep, are not changed.";

/// What the bundle holds none of, said when the page asks to remove them.
pub const NO_SAVED_SETTINGS: &str = "Your recovery bundle holds no saved settings.";

/// The settings saved with the recovery bundle, as the retained flow lists and removes them. The
/// application's is [`NativeSavedSettings`]; a test stands in for it.
pub trait SavedSettings: Send + Sync {
    /// When the bundle was last written, if it holds saved settings now. A read of the service.
    fn listed(&self) -> BoxFuture<'_, Result<Option<TimestampMs>>>;

    /// Turns saving off and takes the settings out of the bundle.
    fn remove(&self) -> BoxFuture<'_, Result<SettingsRemoved>>;
}

/// The answer to the dialog, which this process asks for. The application's is the platform's
/// native dialog; a test answers for the person.
pub trait Confirm: Send + Sync {
    /// Shows `question` to the person and returns whether they said yes.
    fn confirm(&self, question: Question) -> BoxFuture<'_, bool>;
}

/// What the dialog says, in this process's own words and the host's, kept apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// What the copy is, as the host lists it.
    pub kind: String,
    /// How the host names the copy.
    pub reference: String,
    /// What the deletion asks, in this application's words.
    pub words: String,
    /// The dialog's title.
    pub title: String,
    /// The label of the first button, which Return answers: the one that does nothing.
    pub decline: String,
    /// The label of the one button that confirms.
    pub confirm: String,
}

impl Question {
    /// A question about a copy that is deleted.
    fn deletion(kind: String, reference: String, words: String) -> Self {
        Self {
            kind,
            reference,
            words,
            title: "Delete this copy?".to_owned(),
            decline: DONT_DELETE.to_owned(),
            confirm: DELETE.to_owned(),
        }
    }
}

/// What a copy is bound to between the person's yes and the deletion.
#[derive(Debug)]
struct Pending {
    reference: String,
    bound: Bound,
    expires: Instant,
}

/// Whose copy it is, and what the person's yes holds still until the deletion.
#[derive(Debug)]
enum Bound {
    /// A copy the host lists: the host it was asked of and the privacy generation of the list.
    Host {
        environment_id: EnvironmentId,
        privacy_generation: u64,
    },
    /// A copy this application's own sync lists. Its reference names one copy of this computer.
    Sync,
    /// The settings saved with this computer's recovery bundle.
    Settings,
}

/// The confirmations that are waiting for their deletion.
pub struct Deletions {
    pending: Mutex<BTreeMap<String, Pending>>,
    lifetime: Duration,
    saved: OnceLock<Arc<dyn SavedSettings>>,
}

impl std::fmt::Debug for Deletions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Deletions")
            .field("pending", &self.pending)
            .field("lifetime", &self.lifetime)
            .field("saved", &self.saved.get().is_some())
            .finish()
    }
}

impl Default for Deletions {
    fn default() -> Self {
        Self::with_lifetime(TOKEN_LIFETIME)
    }
}

/// What the page is told of an ask.
#[derive(Debug, Serialize)]
pub struct Asked {
    /// Whether the person said yes. A no leaves nothing behind.
    pub confirmed: bool,
    /// The token to finish with, when they did.
    pub token: Option<String>,
    /// How long the token lasts, in milliseconds.
    pub lasts_ms: u64,
}

/// What the page is told of a finished deletion.
#[derive(Debug, Serialize)]
pub struct Finished {
    /// True once the service confirmed it holds the copy no longer, and false while the request is
    /// made and not confirmed.
    pub deleted: bool,
    /// Where privacy mode stands after the request, for a copy the host listed.
    pub report: Option<PrivacyReport>,
}

impl Deletions {
    /// Confirmations that last `lifetime`, which a test makes short.
    #[must_use]
    pub fn with_lifetime(lifetime: Duration) -> Self {
        Self {
            pending: Mutex::default(),
            lifetime,
            saved: OnceLock::new(),
        }
    }

    /// Gives the flow the settings saved with the recovery bundle to list and remove.
    pub fn saved_settings_from(&self, saved: Arc<dyn SavedSettings>) {
        let _ = self.saved.set(saved);
    }

    fn saved(&self) -> Result<&Arc<dyn SavedSettings>> {
        self.saved.get().ok_or_else(|| {
            CommandError::local_failure("this computer's recovery records could not be opened")
        })
    }

    /// The question for the saved settings, when the bundle holds some.
    async fn settings_question(&self) -> Result<(Question, Bound)> {
        if self.saved()?.listed().await?.is_none() {
            return Err(CommandError::invalid(NO_SAVED_SETTINGS));
        }
        Ok((
            Question {
                kind: SETTINGS_KIND.to_owned(),
                // The reference is the page's handle for the row, not words for the dialog.
                reference: String::new(),
                words: SETTINGS_WORDS.to_owned(),
                title: "Remove your saved settings?".to_owned(),
                decline: DONT_REMOVE.to_owned(),
                confirm: REMOVE.to_owned(),
            },
            Bound::Settings,
        ))
    }

    fn held(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Pending>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Asks the person whether to delete the copy listed under `reference`.
    ///
    /// # Errors
    ///
    /// Refuses when no one copy is listed under the reference, when the copy is not one that can be
    /// asked the removal of, and, for a copy the host lists, when this application is not connected
    /// to the host on this computer.
    pub async fn ask(
        &self,
        host: Option<&Connection>,
        settings: &Settings,
        confirm: &dyn Confirm,
        reference: &str,
    ) -> Result<Asked> {
        let (question, bound) = if reference == SETTINGS_REFERENCE {
            self.settings_question().await?
        } else if let Some(copy) = the_deletable_sync_copy(settings, reference)? {
            (
                Question::deletion(
                    shown(&copy.kind),
                    shown(&copy.reference),
                    "KalaReach asks the sync service to delete this copy of a change that \
                     this computer sent and the service did not apply. Nothing restores it \
                     afterwards."
                        .to_owned(),
                ),
                Bound::Sync,
            )
        } else {
            let connection = require_this_computers_host(host)?;
            let report = read_report(connection).await?;
            let copy = the_deletable_copy(&report, reference)?;
            let words = if copy.kind == "notification" {
                "KalaReach asks the notification gateway to delete what it still holds for this \
                 notification, and a queued one is not sent. It does not recall a notification a \
                 provider already accepted, or one a device already holds."
            } else {
                "KalaReach asks the service that holds this copy to delete it. Nothing \
                 restores from it afterwards. If it is the newest backup this host made, \
                 no restore works until this host makes its next one, which it does once \
                 privacy mode is off."
            };
            (
                Question::deletion(shown(&copy.kind), shown(&copy.reference), words.to_owned()),
                Bound::Host {
                    environment_id: connection.environment_id(),
                    privacy_generation: report.generation.get(),
                },
            )
        };
        let reference = reference.to_owned();
        if !confirm.confirm(question).await {
            return Ok(Asked {
                confirmed: false,
                token: None,
                lasts_ms: 0,
            });
        }
        let token = format!("{}-{}", kr_ipc::new_uuid(), kr_ipc::new_uuid());
        let now = Instant::now();
        let mut held = self.held();
        held.retain(|_, pending| pending.expires > now);
        held.insert(
            token.clone(),
            Pending {
                reference,
                bound,
                expires: now + self.lifetime,
            },
        );
        Ok(Asked {
            confirmed: true,
            token: Some(token),
            lasts_ms: u64::try_from(self.lifetime.as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// Asks for the deletion of the copy the person said yes to.
    ///
    /// # Errors
    ///
    /// Refuses a token that is unknown, spent, cancelled or past its time, and a list that no
    /// longer holds that one copy as deletable (for a host's copy, at the privacy generation it was
    /// confirmed at).
    pub async fn finish(
        &self,
        host: Option<&Connection>,
        settings: &Settings,
        token: &str,
    ) -> Result<Finished> {
        // The token is taken before anything else is read: it works once, whatever comes of it.
        let taken = self.held().remove(token);
        let Some(pending) = taken.filter(|pending| pending.expires > Instant::now()) else {
            return Err(CommandError::refused(
                "that confirmation has been used, cancelled or has run out; ask again",
            ));
        };
        match pending.bound {
            Bound::Sync => Ok(Finished {
                deleted: settings.drop_sync_copy(&pending.reference).await?,
                report: None,
            }),
            // The person's yes is for this one removal: it turns saving off before anything is
            // sent, takes the member out by the bundle's own compare-and-swap, and says plainly
            // when the service did not confirm it.
            Bound::Settings => Ok(Finished {
                deleted: matches!(self.saved()?.remove().await?, SettingsRemoved::Removed),
                report: None,
            }),
            Bound::Host {
                environment_id,
                privacy_generation,
            } => {
                let connection = require_this_computers_host(host)?;
                if connection.environment_id() != environment_id {
                    return Err(CommandError::refused(
                        "this application is connected to another host than the one that was \
                         asked; ask again",
                    ));
                }
                let report = read_report(connection).await?;
                if report.generation.get() != privacy_generation {
                    return Err(CommandError::refused(
                        "privacy mode changed since you were asked; ask again",
                    ));
                }
                let copy = the_deletable_copy(&report, &pending.reference)?;
                let params = PrivacyRetainedDeleteParams {
                    reference: copy.reference.clone(),
                };
                let settled = connection
                    .session()
                    .mutate(
                        Method::PrivacyRetainedDelete,
                        ActionTarget::environment(connection.environment_id()),
                        None,
                        &NoPreconditions {},
                        &params,
                        MUTATION_TTL,
                    )
                    .await?;
                let kr_client::Settled::Result(value) = settled else {
                    return Err(CommandError::local_failure(
                        "the host answered the deletion with a receipt, which that method does \
                         not give",
                    ));
                };
                let result: PrivacyRetainedDeleteResult = value.to_typed().map_err(|error| {
                    CommandError::local_failure(format!(
                        "the host's answer was not the method's own result: {error}"
                    ))
                })?;
                Ok(Finished {
                    deleted: result.deleted,
                    report: Some(result.report),
                })
            }
        }
    }

    /// Drops a confirmation without using it. Dropping one that is not held is no error.
    pub fn cancel(&self, token: &str) {
        self.held().remove(token);
    }
}

/// The connection, when it is to the host on this computer, over its own socket.
fn require_this_computers_host(connection: Option<&Connection>) -> Result<&Connection> {
    match connection {
        Some(connection) if matches!(connection.standing(), Standing::Owner) => Ok(connection),
        Some(_) => Err(CommandError::refused(
            "a copy that left the host is deleted at the computer the host runs on, and this \
             application is connected to another host",
        )),
        None => Err(CommandError::refused(
            "a copy that left the host is deleted at the computer the host runs on, and this \
             application is not connected to it",
        )),
    }
}

async fn read_report(connection: &Connection) -> Result<PrivacyReport> {
    Ok(connection
        .session()
        .read(Method::PrivacyStatus, &PrivacyStatusParams {})
        .await?)
}

/// The one copy the host lists under `reference` as deletable.
fn the_deletable_copy<'a>(
    report: &'a PrivacyReport,
    reference: &str,
) -> Result<&'a PrivacyExported> {
    let mut named = report
        .exported
        .iter()
        .filter(|copy| copy.reference == reference);
    let (Some(copy), None) = (named.next(), named.next()) else {
        return Err(CommandError::invalid(
            "the host lists no one copy under that reference",
        ));
    };
    if !copy.deletable {
        return Err(CommandError::refused(
            "the host has no way to ask for the removal of that copy",
        ));
    }
    Ok(copy)
}

/// The one copy this application's own sync lists under `reference`, when it lists one, and that
/// copy is one it can ask the service to drop.
fn the_deletable_sync_copy(
    settings: &Settings,
    reference: &str,
) -> Result<Option<crate::settings::SyncCopy>> {
    // A sync store that cannot be read lists nothing, so it never stands in the way of a copy the
    // host lists.
    let Ok(copies) = settings.sync_copies() else {
        return Ok(None);
    };
    let mut named = copies
        .into_iter()
        .filter(|copy| copy.reference == reference);
    let Some(copy) = named.next() else {
        return Ok(None);
    };
    if named.next().is_some() {
        return Err(CommandError::invalid(
            "this computer lists more than one copy under that reference",
        ));
    }
    if !copy.deletable {
        return Err(CommandError::refused(
            "this computer cannot ask the sync service to drop that copy now: its sync is off, or \
             the record of it cannot be read",
        ));
    }
    Ok(Some(copy))
}

/// The host's words as a dialog repeats them: printable, on one line, and short.
fn shown(text: &str) -> String {
    let printable: String = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let collapsed = printable.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut kept: String = collapsed.chars().take(MOST_SHOWN).collect();
    if collapsed.chars().count() > MOST_SHOWN {
        kept.push('…');
    }
    kept
}

/// The labels of the dialog's three buttons, in the order the platform adds them: the question's
/// own first and confirming labels, and [`CANCEL`].
///
/// The first button is the one a press of Return answers on macOS and the one a Windows task
/// dialog starts on, and the last is the one Escape answers and the one a dialog that could not be
/// shown is taken to have. Confirming is neither: a second press of Return on the page's button,
/// or a dialog that was dismissed, answers no.
///
/// The three-button layout is the platform's own only where the dialog library draws custom labels:
/// on Windows that is a task dialog, which the library builds with version 6 of the common controls
/// (the dialog plugin turns that feature on). A message box would show Yes, No and Cancel and give
/// the middle label for No, so a build without the feature must not use this layout.
const CANCEL: &str = "Cancel";

/// The labels of the dialog for a copy that is deleted.
const DONT_DELETE: &str = "Don't delete";
const DELETE: &str = "Delete";

/// The labels of the dialog for the saved settings, which the bundle's removal of them does not
/// delete a copy of.
const DONT_REMOVE: &str = "Don't remove";
const REMOVE: &str = "Remove";

/// The buttons of a dialog whose first label is `decline` and whose confirming label is `confirm`.
fn buttons(decline: &str, confirm: &str) -> tauri_plugin_dialog::MessageDialogButtons {
    tauri_plugin_dialog::MessageDialogButtons::YesNoCancelCustom(
        decline.to_owned(),
        confirm.to_owned(),
        CANCEL.to_owned(),
    )
}

/// Whether the dialog's answer is the person confirming: the confirming button's own label, and
/// nothing else the platform can answer with.
fn is_confirmed(answer: &tauri_plugin_dialog::MessageDialogResult, confirm: &str) -> bool {
    matches!(answer, tauri_plugin_dialog::MessageDialogResult::Custom(label) if label == confirm)
}

/// The dialog this application shows: the platform's own alert, modal to the application's window.
#[derive(Debug)]
pub struct NativeConfirm<R: tauri::Runtime> {
    app: tauri::AppHandle<R>,
}

impl<R: tauri::Runtime> NativeConfirm<R> {
    /// The dialog of `app`.
    #[must_use]
    pub const fn new(app: tauri::AppHandle<R>) -> Self {
        Self { app }
    }
}

impl<R: tauri::Runtime> Confirm for NativeConfirm<R> {
    fn confirm(&self, question: Question) -> BoxFuture<'_, bool> {
        use tauri_plugin_dialog::{DialogExt as _, MessageDialogKind};

        Box::pin(async move {
            let (answered, answer) = tokio::sync::oneshot::channel();
            let named = if question.reference.is_empty() {
                question.kind.clone()
            } else {
                format!("{}\n{}", question.kind, question.reference)
            };
            let dialog = self
                .app
                .dialog()
                .message(format!("{}\n\n{named}", question.words))
                .title(question.title.as_str())
                .kind(MessageDialogKind::Warning)
                .buttons(buttons(&question.decline, &question.confirm));
            // The alert belongs to the application's window and is modal to it, so the question is
            // answered before anything else is done there.
            #[cfg(desktop)]
            let dialog = match tauri::Manager::get_webview_window(&self.app, "main") {
                Some(window) => dialog.parent(&window),
                None => dialog,
            };
            let confirm = question.confirm;
            dialog.show_with_result(move |answer| {
                let _ = answered.send(is_confirmed(&answer, &confirm));
            });
            answer.await.unwrap_or(false)
        })
    }
}

/// The settings saved with this computer's recovery bundle, as the application lists and removes
/// them: through its recovery and the account it is signed in with.
#[derive(Debug)]
pub struct NativeSavedSettings<R: tauri::Runtime> {
    app: tauri::AppHandle<R>,
}

impl<R: tauri::Runtime> NativeSavedSettings<R> {
    /// The saved settings of `app`.
    #[must_use]
    pub const fn new(app: tauri::AppHandle<R>) -> Self {
        Self { app }
    }

    async fn parts(
        &self,
    ) -> Result<(Arc<crate::recovery::Recovery>, Arc<crate::account::Account>)> {
        use tauri::Manager as _;

        let recovery = self.app.state::<crate::AppState>().recovery()?;
        let account = self
            .app
            .state::<crate::account::AccountSlot>()
            .get()
            .await
            .cloned()?;
        Ok((recovery, account))
    }
}

impl<R: tauri::Runtime> SavedSettings for NativeSavedSettings<R> {
    fn listed(&self) -> BoxFuture<'_, Result<Option<TimestampMs>>> {
        Box::pin(async move {
            let (recovery, account) = self.parts().await?;
            recovery.saved_settings_listed(&account).await
        })
    }

    fn remove(&self) -> BoxFuture<'_, Result<SettingsRemoved>> {
        Box::pin(async move {
            let (recovery, account) = self.parts().await?;
            recovery.remove_saved_settings(&account).await
        })
    }
}

#[cfg(test)]
mod tests {
    use tauri_plugin_dialog::{MessageDialogButtons, MessageDialogResult};

    use super::{CANCEL, DELETE, DONT_DELETE, DONT_REMOVE, REMOVE, buttons, is_confirmed};

    /// The dialog's default and its dismissal are safe: the button Return answers, and the one
    /// Escape and a dialog that could not be shown answer, do not confirm, and only the confirming
    /// button's own label does, for the deletion of a copy and for the removal of the saved
    /// settings alike.
    #[test]
    fn only_the_confirming_button_confirms_and_it_is_neither_the_default_nor_the_dismissal() {
        for (decline, confirm) in [(DONT_DELETE, DELETE), (DONT_REMOVE, REMOVE)] {
            let MessageDialogButtons::YesNoCancelCustom(first, second, last) =
                buttons(decline, confirm)
            else {
                panic!("the dialog has three buttons");
            };
            assert_eq!(
                [first.as_str(), second.as_str(), last.as_str()],
                [decline, confirm, CANCEL]
            );
            assert_eq!(second, confirm, "the confirming button is the middle one");
            for answered in [
                MessageDialogResult::Custom(first),
                MessageDialogResult::Custom(last),
                MessageDialogResult::Cancel,
                MessageDialogResult::Ok,
                MessageDialogResult::Yes,
                MessageDialogResult::No,
            ] {
                assert!(!is_confirmed(&answered, confirm), "{answered:?} confirms");
            }
            assert!(is_confirmed(&MessageDialogResult::Custom(second), confirm));
        }
    }
}
