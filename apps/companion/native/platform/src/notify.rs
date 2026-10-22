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
struct ChangedAnswer {
    changed: bool,
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

#[derive(Serialize)]
struct LimitedKey {
    recipient_key_id: String,
    seed: String,
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

/// Whether the provider gave this installation another token since the last time this was asked.
/// Asking clears it.
///
/// # Errors
///
/// Returns an error when the platform cannot be asked, and on a computer.
pub async fn token_changed<R: Runtime>(app: &AppHandle<R>) -> Result<bool, PlatformError> {
    call::<R, ChangedAnswer>(app, "pushTokenChanged", ())
        .await
        .map(|answer| answer.changed)
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

/// Files the notification-preview key in the store a receiver reads, under the identifier of its
/// public key, replacing any earlier one under that identifier.
///
/// The store is the limited one: the key that opens a notification preview and nothing else. The
/// seed is the item this application's secure store keeps under the key's device-key name.
///
/// # Errors
///
/// Returns an error when the platform cannot file it, and on a computer.
pub async fn limited_key<R: Runtime>(
    app: &AppHandle<R>,
    recipient_key_id: &[u8; 32],
    seed: &[u8],
) -> Result<(), PlatformError> {
    let encoder = base64::engine::general_purpose::STANDARD;
    call::<R, serde_json::Value>(
        app,
        "pushLimitedKey",
        LimitedKey {
            recipient_key_id: encoder.encode(recipient_key_id),
            seed: encoder.encode(seed),
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
