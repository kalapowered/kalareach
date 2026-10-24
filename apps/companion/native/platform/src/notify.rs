//! A phone's notification services, asked of its native half.
//!
//! What only the platform can say or do about notifications, and nothing of what to do about it:
//! whether the person allowed them, the registration token the provider gave this installation,
//! the record of the registration being waited for, the limited key store a receiver reads, and
//! whether the application was opened by a tap on a notification. The decisions are the
//! application's, in Rust, where the host's tests reach them.
//!
//! The native half keeps the pending record and the limited store where a receiver can reach them
//! without the application running (a receiver the system starts for one message has no interface,
//! no WebView and no Tauri runtime), so the application writes and reads them through these calls
//! and the receiver reads them itself.
//!
//! Only a phone has these. On a computer every call says so.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Runtime};
use zeroize::Zeroizing;

use crate::PlatformError;
use crate::push::PendingRegistration;

/// Where the person's answer to the system's notification question stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// The person agreed (a provisional or ephemeral grant counts).
    Granted,
    /// The person said no, or took a yes back.
    Denied,
    /// The person has not been asked, or the answer cannot be read.
    Unknown,
}

#[derive(Deserialize)]
struct PermissionAnswer {
    state: Permission,
}

#[derive(Deserialize)]
struct TokenAnswer {
    token: Option<String>,
}

#[derive(Deserialize)]
struct RecordAnswer {
    record: Option<PendingRegistration>,
}

#[derive(Deserialize)]
struct RouteAnswer {
    route: Option<String>,
}

#[derive(Serialize)]
struct Record<'a> {
    record: &'a PendingRegistration,
}

/// The keys a receiver may open a notification preview with, and nothing else.
///
/// The set is handed over whole each time it changes ([`preview_keys`]), and the receivers' store is
/// made equal to it: a host turned off is not in it, and a seed is in it only while some host that
/// may use it is.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PreviewKeys {
    /// This device's preview seeds, each with the identifier of its public half, which is what a
    /// sealed preview names its recipient by.
    pub recipients: Vec<RecipientKey>,
    /// The preview public key of each host that may seal a preview to this device, with the
    /// identifier a sealed preview names its sender by.
    pub senders: Vec<SenderKey>,
}

impl std::fmt::Debug for PreviewKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A seed is a secret and is never printed.
        formatter
            .debug_struct("PreviewKeys")
            .field("recipients", &self.recipients.len())
            .field("senders", &self.senders.len())
            .finish()
    }
}

/// One preview seed of this device.
#[derive(Clone, PartialEq, Eq)]
pub struct RecipientKey {
    /// The identifier of the seed's public half.
    pub id: [u8; 32],
    /// The seed.
    pub seed: Zeroizing<Vec<u8>>,
}

/// The preview public key of one host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderKey {
    /// The key's identifier.
    pub id: [u8; 32],
    /// The key.
    pub key: [u8; 32],
}

#[derive(Serialize)]
struct KeysArguments {
    recipients: Vec<RecipientItem>,
    senders: Vec<SenderItem>,
}

#[derive(Serialize)]
struct RecipientItem {
    id: String,
    seed: String,
}

#[derive(Serialize)]
struct SenderItem {
    id: String,
    key: String,
}

#[cfg(mobile)]
async fn call<R: Runtime, T: serde::de::DeserializeOwned>(
    app: &AppHandle<R>,
    method: &str,
    arguments: impl Serialize,
) -> Result<T, PlatformError> {
    use tauri::Manager as _;

    app.state::<crate::Platform<R>>()
        .call(method, arguments)
        .await
}

#[cfg(not(mobile))]
async fn call<R: Runtime, T: serde::de::DeserializeOwned>(
    _app: &AppHandle<R>,
    _method: &str,
    _arguments: impl Serialize,
) -> Result<T, PlatformError> {
    Err(PlatformError::new("notifications are a phone's"))
}

/// Where the person's answer stands, read without asking.
///
/// # Errors
///
/// Returns an error when the platform cannot be asked, and on a computer.
pub async fn permission<R: Runtime>(app: &AppHandle<R>) -> Result<Permission, PlatformError> {
    call::<R, PermissionAnswer>(app, "pushPermission", ())
        .await
        .map(|answer| answer.state)
}

/// Asks the person, when they have not answered, and says where their answer stands once they
/// have.
///
/// # Errors
///
/// Returns an error when the platform cannot ask, and on a computer.
pub async fn ask_permission<R: Runtime>(app: &AppHandle<R>) -> Result<Permission, PlatformError> {
    call::<R, PermissionAnswer>(app, "pushAskPermission", ())
        .await
        .map(|answer| answer.state)
}

/// The registration token the provider gave this installation, when it has given one.
///
/// A token is a delivery capability: whoever holds one can have a message delivered to this phone.
/// It goes to the gateway in one request and is never logged.
///
/// # Errors
///
/// Returns an error when the platform cannot be asked, and on a computer.
pub async fn token<R: Runtime>(app: &AppHandle<R>) -> Result<Option<String>, PlatformError> {
    call::<R, TokenAnswer>(app, "pushToken", ())
        .await
        .map(|answer| answer.token)
}

/// Replaces the record of the registration being waited for, which supersedes the one before.
///
/// # Errors
///
/// Returns an error when the platform cannot keep it, and on a computer.
pub async fn pending_set<R: Runtime>(
    app: &AppHandle<R>,
    record: &PendingRegistration,
) -> Result<(), PlatformError> {
    call::<R, serde_json::Value>(app, "pushPendingSet", Record { record })
        .await
        .map(|_| ())
}

/// The record of the registration being waited for, as it stands now: a record whose deadline has
/// passed reads as expired.
///
/// # Errors
///
/// Returns an error when the platform cannot read it, and on a computer.
pub async fn pending_get<R: Runtime>(
    app: &AppHandle<R>,
) -> Result<Option<PendingRegistration>, PlatformError> {
    call::<R, RecordAnswer>(app, "pushPendingGet", ())
        .await
        .map(|answer| answer.record)
}

/// Removes the record of the registration being waited for.
///
/// # Errors
///
/// Returns an error when the platform cannot remove it, and on a computer.
pub async fn pending_clear<R: Runtime>(app: &AppHandle<R>) -> Result<(), PlatformError> {
    call::<R, serde_json::Value>(app, "pushPendingClear", ())
        .await
        .map(|_| ())
}

/// Makes the store a receiver reads hold exactly `keys`: whatever it held before and is not in
/// `keys` is removed, and the rest is filed or replaced.
///
/// The store is the limited one: the keys that open a notification preview and nothing else. Each
/// seed is the item this application's secure store keeps under the key's device-key name.
///
/// # Errors
///
/// Returns an error when the platform cannot file them, and on a computer.
pub async fn preview_keys<R: Runtime>(
    app: &AppHandle<R>,
    keys: &PreviewKeys,
) -> Result<(), PlatformError> {
    let encoder = base64::engine::general_purpose::STANDARD;
    call::<R, serde_json::Value>(
        app,
        "pushPreviewKeys",
        KeysArguments {
            recipients: keys
                .recipients
                .iter()
                .map(|recipient| RecipientItem {
                    id: encoder.encode(recipient.id),
                    seed: encoder.encode(recipient.seed.as_slice()),
                })
                .collect(),
            senders: keys
                .senders
                .iter()
                .map(|sender| SenderItem {
                    id: encoder.encode(sender.id),
                    key: encoder.encode(sender.key),
                })
                .collect(),
        },
    )
    .await
    .map(|_| ())
}

/// The screen the application was opened on by a tap on a notification, once: asking clears it.
///
/// # Errors
///
/// Returns an error when the platform cannot be asked, and on a computer.
pub async fn route<R: Runtime>(app: &AppHandle<R>) -> Result<Option<String>, PlatformError> {
    call::<R, RouteAnswer>(app, "pushRoute", ())
        .await
        .map(|answer| answer.route)
}
