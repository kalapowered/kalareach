//! Whether the person who owns a phone is in front of it now, asked of the phone's own ceremony.
//!
//! The ceremony is the operating system's dialog, never a screen of this application: Face ID,
//! Touch ID or the passcode on an iPhone, and the biometric prompt (a strong biometric, or the
//! screen lock) on an Android phone. A click the page or desktop automation can synthesise may open
//! it and cannot complete it. This module asks the native half which ceremony the phone offers and
//! runs it; what a confirmation lets the application sign is decided elsewhere.
//!
//! Only phones answer. A desktop has its own ceremonies in the application, and here offers none.

use std::time::Duration;

use serde::Deserialize;
use tauri::{AppHandle, Runtime};

#[cfg(mobile)]
use serde::Serialize;

/// Which ceremony a phone offers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Face ID.
    FaceId,
    /// Touch ID.
    TouchId,
    /// The passcode of an iPhone or iPad with no biometric set up.
    Passcode,
    /// A strong biometric on an Android phone.
    Biometric,
    /// The screen lock of an Android phone with no strong biometric set up.
    ScreenLock,
    /// None: this phone cannot check that its owner is in front of it.
    #[default]
    None,
}

/// What the ceremony answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The person completed it.
    Confirmed,
    /// The person declined, cancelled or failed it, or it was not answered in time.
    NotConfirmed,
    /// The phone has no ceremony to run.
    Unavailable,
}

/// What the native half answers about the ceremony the phone offers.
#[cfg(any(mobile, test))]
#[derive(Deserialize)]
struct KindAnswer {
    kind: Kind,
}

/// What the native half answers to a request to run the ceremony.
#[cfg(any(mobile, test))]
#[derive(Deserialize)]
struct OutcomeAnswer {
    outcome: Outcome,
}

/// Which ceremony this phone offers. A phone that cannot say offers none.
pub async fn kind<R: Runtime>(app: &AppHandle<R>) -> Kind {
    #[cfg(mobile)]
    {
        use tauri::Manager as _;

        let platform = app.state::<crate::Platform<R>>();
        platform
            .call::<KindAnswer>("presenceKind", ())
            .await
            .map_or_else(
                |error| {
                    tracing::warn!(%error, "the platform was not asked which ceremony it offers");
                    Kind::None
                },
                |answer| answer.kind,
            )
    }
    #[cfg(not(mobile))]
    {
        let _ = app;
        Kind::None
    }
}

/// Runs the phone's ceremony for `reason`, and ends it when `within` passes: the dialog is dismissed
/// and the answer is that the person did not confirm.
pub async fn verify<R: Runtime>(app: &AppHandle<R>, reason: &str, within: Duration) -> Outcome {
    #[cfg(mobile)]
    {
        use tauri::Manager as _;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Request<'a> {
            reason: &'a str,
            within_ms: u64,
        }

        let platform = app.state::<crate::Platform<R>>();
        let request = Request {
            reason,
            within_ms: u64::try_from(within.as_millis()).unwrap_or(u64::MAX),
        };
        platform
            .call::<OutcomeAnswer>("presence", request)
            .await
            .map_or_else(
                |error| {
                    tracing::warn!(%error, "the platform's ceremony could not be run");
                    Outcome::NotConfirmed
                },
                |answer| answer.outcome,
            )
    }
    #[cfg(not(mobile))]
    {
        let _ = (app, reason, within);
        Outcome::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the native halves send is what this module reads: the kinds a phone offers and the three
    /// answers, and nothing else.
    #[test]
    fn the_native_answers_are_read() {
        let kind = |text: &str| serde_json::from_str::<KindAnswer>(text).map(|each| each.kind);
        assert_eq!(kind(r#"{"kind":"face_id"}"#).ok(), Some(Kind::FaceId));
        assert_eq!(kind(r#"{"kind":"touch_id"}"#).ok(), Some(Kind::TouchId));
        assert_eq!(kind(r#"{"kind":"passcode"}"#).ok(), Some(Kind::Passcode));
        assert_eq!(kind(r#"{"kind":"biometric"}"#).ok(), Some(Kind::Biometric));
        assert_eq!(
            kind(r#"{"kind":"screen_lock"}"#).ok(),
            Some(Kind::ScreenLock)
        );
        assert_eq!(kind(r#"{"kind":"none"}"#).ok(), Some(Kind::None));
        assert!(kind(r#"{"kind":"iris"}"#).is_err());
        let outcome =
            |text: &str| serde_json::from_str::<OutcomeAnswer>(text).map(|each| each.outcome);
        assert_eq!(
            outcome(r#"{"outcome":"confirmed"}"#).ok(),
            Some(Outcome::Confirmed)
        );
        assert_eq!(
            outcome(r#"{"outcome":"not_confirmed"}"#).ok(),
            Some(Outcome::NotConfirmed)
        );
        assert_eq!(
            outcome(r#"{"outcome":"unavailable"}"#).ok(),
            Some(Outcome::Unavailable)
        );
        assert!(outcome(r#"{"outcome":"yes"}"#).is_err());
    }
}
