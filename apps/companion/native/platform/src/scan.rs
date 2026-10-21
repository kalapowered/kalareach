//! Reading a QR code from the camera or from a picture.
//!
//! A direct invitation's QR code holds the invitation's whole secret, so it is read in native code
//! and the text goes from the phone's own half to Rust and no further than native code: the page is
//! told that an invitation was found, never what it says. The camera shows its own full-screen
//! scanner, and the picture comes from the system's picker, which hands this application only the
//! picture the person chose.
//!
//! Both decode with the platform's own detector (Vision on iOS, ZXing on Android) and answer one of
//! four things: the text of the code, that the person closed the scanner or the picker, that the
//! picture shows no code, or that the camera is not allowed.
//!
//! Only phones read a code. A desktop answers that it offers neither source.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Runtime};
use zeroize::Zeroizing;

use crate::PlatformError;

/// What reading a code came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Scan {
    /// The text of the code. It clears itself when it is dropped.
    Text(Zeroizing<String>),
    /// The person closed the scanner or the picker without choosing.
    Cancelled,
    /// The picture the person chose shows no QR code.
    NoCode,
    /// The camera is not allowed to this application.
    CameraDenied,
}

/// Which sources this device reads a code from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Sources {
    /// The device has a camera the scanner can use.
    pub camera: bool,
    /// The device offers a picker for pictures.
    pub photo: bool,
}

/// What the native half answers to a request to read a code.
#[derive(Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum Answer {
    Text { text: String },
    Cancelled,
    NoCode,
    CameraDenied,
}

impl From<Answer> for Scan {
    fn from(answer: Answer) -> Self {
        match answer {
            Answer::Text { text } => Self::Text(Zeroizing::new(text)),
            Answer::Cancelled => Self::Cancelled,
            Answer::NoCode => Self::NoCode,
            Answer::CameraDenied => Self::CameraDenied,
        }
    }
}

/// Which sources this device reads a code from.
///
/// It is asked of the native half without waiting on the thread that asks: a native command arrives
/// on the application's main thread on Android, which a caller there must not hold.
pub async fn sources<R: Runtime>(app: &AppHandle<R>) -> Sources {
    #[cfg(mobile)]
    {
        use tauri::Manager as _;

        let platform = app.state::<crate::Platform<R>>();
        platform
            .call::<Sources>("scanSources", ())
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "the platform was not asked what it can scan");
                Sources::default()
            })
    }
    #[cfg(not(mobile))]
    {
        let _ = app;
        Sources::default()
    }
}

/// Shows the scanner and answers when it closes: with the code it read, or without one.
///
/// # Errors
///
/// Returns an error when the platform cannot show the scanner, or when this device has no scanner.
pub async fn camera<R: Runtime>(app: &AppHandle<R>) -> Result<Scan, PlatformError> {
    ask(app, "scanCamera").await
}

/// Shows the system's picker and answers with the code in the picture the person chose, or without
/// one.
///
/// # Errors
///
/// Returns an error when the platform cannot show the picker, or when this device has none.
pub async fn photo<R: Runtime>(app: &AppHandle<R>) -> Result<Scan, PlatformError> {
    ask(app, "scanPhoto").await
}

/// Opens this application's own page in the system's settings, where the camera is allowed.
///
/// # Errors
///
/// Returns an error when the platform cannot open it, or when there is no such page.
pub async fn open_settings<R: Runtime>(app: &AppHandle<R>) -> Result<(), PlatformError> {
    #[cfg(mobile)]
    {
        use tauri::Manager as _;

        let platform = app.state::<crate::Platform<R>>();
        let _: serde_json::Value = platform.call("openSettings", ()).await?;
        Ok(())
    }
    #[cfg(not(mobile))]
    {
        let _ = app;
        Err(PlatformError::new(
            "this device has no settings page to open",
        ))
    }
}

#[cfg(mobile)]
async fn ask<R: Runtime>(app: &AppHandle<R>, method: &str) -> Result<Scan, PlatformError> {
    use tauri::Manager as _;

    let platform = app.state::<crate::Platform<R>>();
    let answer: Answer = platform.call(method, ()).await?;
    Ok(answer.into())
}

#[cfg(not(mobile))]
#[allow(clippy::unused_async)]
async fn ask<R: Runtime>(_app: &AppHandle<R>, _method: &str) -> Result<Scan, PlatformError> {
    Err(PlatformError::new("this device reads no QR code"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the native halves send is what this module reads: the four answers and nothing else.
    #[test]
    fn the_four_answers_the_native_halves_send_are_read() {
        let read = |text: &str| -> Scan {
            serde_json::from_str::<Answer>(text)
                .expect("an answer")
                .into()
        };
        assert_eq!(
            read(r#"{"outcome":"text","text":"abc"}"#),
            Scan::Text(Zeroizing::new("abc".to_owned()))
        );
        assert_eq!(read(r#"{"outcome":"cancelled"}"#), Scan::Cancelled);
        assert_eq!(read(r#"{"outcome":"no_code"}"#), Scan::NoCode);
        assert_eq!(read(r#"{"outcome":"camera_denied"}"#), Scan::CameraDenied);
        assert!(serde_json::from_str::<Answer>(r#"{"outcome":"text"}"#).is_err());
        assert!(serde_json::from_str::<Answer>(r#"{"outcome":"other"}"#).is_err());
    }
}
