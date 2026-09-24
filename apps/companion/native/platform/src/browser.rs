//! The browser-backed session a sign-in hands its ceremony to on a phone.
//!
//! * iOS: `ASWebAuthenticationSession`, ephemeral, with an HTTPS callback from iOS 17.4 and a
//!   private-use scheme callback before it. The session catches the navigation to its callback
//!   itself and hands the address to its completion, once.
//! * Android: the default browser's Auth Tab when it has one, which checks the application
//!   against the domain's Digital Asset Links and returns the address as an activity result, once.
//!   Otherwise a Custom Tab, whose answer can reach the application only as a verified link; that
//!   is offered only where the link is verified and allowed to open the application.
//!
//! The native halves report facts: what the device can do, and each result in its own terms. This
//! module decides what those facts mean ([`mode`], [`android_availability`], [`event`]), so the
//! decisions are tested on the host, and it drives the native halves through [`crate::Platform`].
//! Every result carries the attempt it belongs to, and the caller drops one for another attempt.

use serde::{Deserialize, Serialize};

/// What the native half reports about the device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// iOS: whether the authentication session takes an HTTPS callback (iOS 17.4 and later).
    pub https_callback: Option<bool>,
    /// iOS: the private keychain group the build wrote into `Info.plist`.
    pub private_keychain_group: Option<String>,
    /// Android: the platform's API level.
    pub sdk: Option<u32>,
    /// Android: whether the default browser offers Auth Tab.
    pub auth_tab: Option<bool>,
    /// Android: whether the default browser offers Custom Tabs at all.
    pub custom_tabs: Option<bool>,
    /// Android 12 and later: whether the application's link to the service's host is verified.
    pub link_verified: Option<bool>,
    /// Android 12 and later: whether the person lets the application open its links.
    pub link_handling_allowed: Option<bool>,
}

/// How one attempt's ceremony is carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    /// iOS's session, answered on the HTTPS callback.
    SessionHttps,
    /// iOS's session, answered on the private-use scheme.
    SessionScheme,
    /// Android's Auth Tab, answered on the HTTPS redirect.
    AuthTab,
    /// A Custom Tab, answered by a verified link the system hands the application.
    CustomTab,
}

impl Mode {
    /// Whether this mode delivers one result and ends, or can deliver more.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::CustomTab)
    }

    /// Whether the answer comes back on the private-use scheme rather than on HTTPS.
    #[must_use]
    pub const fn uses_private_scheme(self) -> bool {
        matches!(self, Self::SessionScheme)
    }
}

/// Why this device cannot carry a sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unavailable {
    /// No browser here can return the answer to the application.
    NoReturningBrowser,
    /// The link is verified, but the person has turned off opening supported links.
    LinkHandlingOff,
}

/// The iOS session's callback, from whether the system takes an HTTPS one.
#[must_use]
pub const fn mode(https_callback: bool) -> Mode {
    if https_callback {
        Mode::SessionHttps
    } else {
        Mode::SessionScheme
    }
}

/// The API level from which Android answers whether a link is verified.
const DOMAIN_VERIFICATION_SDK: u32 = 31;

/// How an Android device carries a sign-in, or why it cannot.
///
/// # Errors
///
/// Returns why not, when no browser here could return the answer.
pub fn android_availability(facts: &Capabilities) -> Result<Mode, Unavailable> {
    if facts.auth_tab == Some(true) {
        return Ok(Mode::AuthTab);
    }
    if facts.custom_tabs != Some(true) {
        return Err(Unavailable::NoReturningBrowser);
    }
    if facts.sdk.is_some_and(|sdk| sdk >= DOMAIN_VERIFICATION_SDK) {
        if facts.link_verified != Some(true) {
            return Err(Unavailable::NoReturningBrowser);
        }
        if facts.link_handling_allowed != Some(true) {
            return Err(Unavailable::LinkHandlingOff);
        }
    }
    Ok(Mode::CustomTab)
}

/// What one attempt asks the native half to open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRequest {
    /// The attempt, as a decimal string, which every result carries back.
    pub attempt: String,
    /// The address the browser opens.
    pub url: String,
    /// How the ceremony is carried.
    pub mode: Mode,
    /// The HTTPS callback's host.
    pub https_host: String,
    /// The HTTPS callback's path.
    pub https_path: String,
    /// The private-use callback's scheme.
    pub scheme: String,
}

/// One result, as the native half reported it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawEvent {
    /// The attempt it belongs to.
    pub attempt: String,
    /// `redirected` or `ended` from iOS; `result`, `link` or `closed` from Android; `cancelled`
    /// when the application ended the attempt itself.
    pub kind: String,
    /// The address that came back, when one did.
    pub url: Option<String>,
    /// iOS: the error's domain.
    pub domain: Option<String>,
    /// iOS: the error's code. Android: the activity result's code.
    pub code: Option<i64>,
    /// iOS: the error's failure reason, when it gave one.
    pub reason: Option<String>,
}

/// What one result means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// An address came back; the caller checks it.
    Answer(String),
    /// The person, or the application, ended the ceremony.
    Cancelled,
    /// A Custom Tab closed without an answer: a cancel, or a browser that kept the answer.
    TabClosed,
    /// The system would not return the answer to this application: the association (iOS) or the
    /// Digital Asset Links check (Android) failed.
    CouldNotReturn,
    /// Anything else the platform reported.
    Failed,
}

/// The iOS session's error domain.
const SESSION_ERROR_DOMAIN: &str = "com.apple.AuthenticationServices.WebAuthenticationSession";

/// The iOS session's "cancelled login" code, which both a person's cancel and a failed association
/// end with; only the failed association gives a reason.
const SESSION_CANCELLED: i64 = 1;

/// Android's activity result codes, as Auth Tab uses them.
const RESULT_OK: i64 = -1;
const RESULT_CANCELED: i64 = 0;
const RESULT_VERIFICATION_FAILED: i64 = 2;
const RESULT_VERIFICATION_TIMED_OUT: i64 = 3;

/// What one reported result means.
#[must_use]
pub fn event(raw: &RawEvent) -> SessionEvent {
    match raw.kind.as_str() {
        "redirected" | "link" => raw
            .url
            .clone()
            .map_or(SessionEvent::Failed, SessionEvent::Answer),
        "ended" => {
            if raw.domain.as_deref() == Some(SESSION_ERROR_DOMAIN)
                && raw.code == Some(SESSION_CANCELLED)
            {
                if raw
                    .reason
                    .as_deref()
                    .is_some_and(|reason| !reason.is_empty())
                {
                    SessionEvent::CouldNotReturn
                } else {
                    SessionEvent::Cancelled
                }
            } else {
                SessionEvent::Failed
            }
        }
        "result" => match raw.code {
            Some(RESULT_OK) => raw
                .url
                .clone()
                .map_or(SessionEvent::Failed, SessionEvent::Answer),
            Some(RESULT_CANCELED) => SessionEvent::Cancelled,
            Some(RESULT_VERIFICATION_FAILED | RESULT_VERIFICATION_TIMED_OUT) => {
                SessionEvent::CouldNotReturn
            }
            _ => SessionEvent::Failed,
        },
        "closed" => SessionEvent::TabClosed,
        "cancelled" => SessionEvent::Cancelled,
        _ => SessionEvent::Failed,
    }
}

#[cfg(mobile)]
impl<R: tauri::Runtime> crate::Platform<R> {
    /// What this device can do.
    ///
    /// # Errors
    ///
    /// Returns an error when the native half cannot be asked.
    pub async fn capabilities(&self) -> Result<Capabilities, crate::PlatformError> {
        self.call("capabilities", ()).await
    }

    /// Opens the ceremony and waits for its first result.
    ///
    /// # Errors
    ///
    /// Returns an error when the native half cannot be asked.
    pub async fn authenticate(
        &self,
        request: &SessionRequest,
    ) -> Result<RawEvent, crate::PlatformError> {
        self.call("authenticate", request).await
    }

    /// Waits for the next result of a Custom Tab attempt.
    ///
    /// # Errors
    ///
    /// Returns an error when the native half cannot be asked.
    pub async fn next_event(&self, attempt: &str) -> Result<RawEvent, crate::PlatformError> {
        #[derive(Serialize)]
        struct Attempt<'a> {
            attempt: &'a str,
        }
        self.call("nextEvent", Attempt { attempt }).await
    }

    /// Ends the attempt: the sheet or tab is dismissed, and a waiting call is answered.
    ///
    /// # Errors
    ///
    /// Returns an error when the native half cannot be asked.
    pub async fn cancel(&self, attempt: &str) -> Result<(), crate::PlatformError> {
        #[derive(Serialize)]
        struct Attempt<'a> {
            attempt: &'a str,
        }
        self.call::<serde_json::Value>("cancel", Attempt { attempt })
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ios_before_17_4_is_answered_on_the_private_scheme() {
        assert_eq!(mode(true), Mode::SessionHttps);
        assert_eq!(mode(false), Mode::SessionScheme);
        assert!(Mode::SessionScheme.uses_private_scheme());
        assert!(!Mode::SessionHttps.uses_private_scheme());
        assert!(Mode::SessionHttps.is_terminal() && Mode::AuthTab.is_terminal());
        assert!(!Mode::CustomTab.is_terminal());
    }

    fn android(sdk: u32, auth_tab: bool, verified: bool, allowed: bool) -> Capabilities {
        Capabilities {
            sdk: Some(sdk),
            auth_tab: Some(auth_tab),
            custom_tabs: Some(true),
            link_verified: Some(verified),
            link_handling_allowed: Some(allowed),
            ..Capabilities::default()
        }
    }

    /// Auth Tab first; a Custom Tab only where the verified link may open the application.
    #[test]
    fn android_offers_the_fallback_only_where_the_link_can_return() {
        assert_eq!(
            android_availability(&android(36, true, false, false)),
            Ok(Mode::AuthTab)
        );
        assert_eq!(
            android_availability(&android(36, false, true, true)),
            Ok(Mode::CustomTab)
        );
        assert_eq!(
            android_availability(&android(36, false, true, false)),
            Err(Unavailable::LinkHandlingOff),
            "verified, but the person turned off opening supported links"
        );
        assert_eq!(
            android_availability(&android(36, false, false, true)),
            Err(Unavailable::NoReturningBrowser)
        );
        // Android 10 and 11 cannot be asked, so the fallback is offered.
        assert_eq!(
            android_availability(&android(29, false, false, false)),
            Ok(Mode::CustomTab)
        );
        let mut no_tabs = android(36, false, true, true);
        no_tabs.custom_tabs = Some(false);
        assert_eq!(
            android_availability(&no_tabs),
            Err(Unavailable::NoReturningBrowser)
        );
    }

    fn raw(kind: &str) -> RawEvent {
        RawEvent {
            attempt: "7".to_owned(),
            kind: kind.to_owned(),
            ..RawEvent::default()
        }
    }

    /// iOS ends a failed association and a person's cancel with the same code; only the failed
    /// association gives a reason.
    #[test]
    fn an_ios_ending_with_a_reason_is_a_failed_association_and_without_one_a_cancel() {
        let mut ended = raw("ended");
        ended.domain = Some(SESSION_ERROR_DOMAIN.to_owned());
        ended.code = Some(1);
        assert_eq!(event(&ended), SessionEvent::Cancelled);
        ended.reason = Some(
            "Application is not associated with domain reach.kala.to. Using HTTPS callbacks \
             requires Associated Domains using the `webcredentials` service type"
                .to_owned(),
        );
        assert_eq!(event(&ended), SessionEvent::CouldNotReturn);
        ended.code = Some(2);
        assert_eq!(event(&ended), SessionEvent::Failed);
        let mut redirected = raw("redirected");
        redirected.url = Some("to.kala.reach:/oauth/callback?code=x".to_owned());
        assert_eq!(
            event(&redirected),
            SessionEvent::Answer("to.kala.reach:/oauth/callback?code=x".to_owned())
        );
    }

    #[test]
    fn an_auth_tab_result_is_read_by_its_code() {
        let mut result = raw("result");
        result.code = Some(-1);
        result.url = Some("https://reach.kala.to/app/oauth/callback?code=x".to_owned());
        assert!(matches!(event(&result), SessionEvent::Answer(_)));
        result.url = None;
        assert_eq!(
            event(&result),
            SessionEvent::Failed,
            "no address, no answer"
        );
        result.code = Some(0);
        assert_eq!(event(&result), SessionEvent::Cancelled);
        result.code = Some(2);
        assert_eq!(event(&result), SessionEvent::CouldNotReturn);
        result.code = Some(3);
        assert_eq!(event(&result), SessionEvent::CouldNotReturn);
        result.code = Some(-2);
        assert_eq!(event(&result), SessionEvent::Failed);
        assert_eq!(event(&raw("closed")), SessionEvent::TabClosed);
        let mut link = raw("link");
        link.url = Some("https://reach.kala.to/app/oauth/callback?code=x".to_owned());
        assert!(matches!(event(&link), SessionEvent::Answer(_)));
        assert_eq!(event(&raw("cancelled")), SessionEvent::Cancelled);
        assert_eq!(event(&raw("anything else")), SessionEvent::Failed);
    }
}
