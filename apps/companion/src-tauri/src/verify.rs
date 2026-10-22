//! The owner's user-verification ceremony, drawn by the platform.
//!
//! Section 10 wants a protected native ceremony on the unlocked owner device for a rights-enlarging
//! action, and says plainly what will not do: a click that desktop automation can synthesise is not
//! proof that a person was present. So the ceremony is never a dialog this application draws. On
//! macOS it is `LAContext`, whose reason is the one-line description the dialog prints: Touch ID,
//! or the password on a Mac without it. On Windows it is Windows Hello, through
//! `UserConsentVerifier` for this application's window, whose message is the same line. On a phone
//! the platform plugin's native half runs it: Face ID, Touch ID or the passcode on an iPhone, and
//! the biometric prompt on an Android phone. Other platforms have none here, and a device without
//! one signs nothing.
//!
//! Every ceremony is bounded by the challenge's remaining lifetime: at the bound the platform's
//! dialog is dismissed (`LAContext::invalidate`, `IAsyncOperation::Cancel`) and the answer is "not
//! confirmed", and an answer that arrives after that is discarded. What this module returns is only
//! whether the person confirmed; kr-client decides what that lets it sign.

use std::sync::Arc;
use std::time::Duration;

use kr_client::pairing::BoxFuture;
use kr_client::pairing::owner::{Ceremony, CeremonyKind, CeremonyOutcome};

/// The ceremony this computer offers. On Windows it belongs to `window`, so the dialog is that
/// window's.
#[must_use]
pub fn platform_ceremony<R: tauri::Runtime>(
    window: Option<tauri::WebviewWindow<R>>,
) -> Arc<dyn Ceremony> {
    #[cfg(target_os = "macos")]
    {
        let _ = window;
        Arc::new(mac::LocalAuthentication)
    }
    #[cfg(target_os = "windows")]
    {
        match window.and_then(|window| window.hwnd().ok()) {
            Some(hwnd) => Arc::new(hello::WindowsHello::for_window(hwnd)),
            None => Arc::new(NoCeremony),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = window;
        Arc::new(NoCeremony)
    }
}

/// The ceremony that answers the pairing owner's confirmations. On a phone it is the phone's own;
/// elsewhere it is [`platform_ceremony`].
///
/// A phone's ceremony belongs to the confirmations screen and to nothing else: a revocation and a
/// settings change keep [`NoCeremony`] there, since the phone draws no screen for either.
#[must_use]
pub fn pairing_ceremony<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Arc<dyn Ceremony> {
    #[cfg(mobile)]
    {
        Arc::new(phone::Presence::start(app.clone()))
    }
    #[cfg(not(mobile))]
    {
        use tauri::Manager as _;

        platform_ceremony(app.get_webview_window("main"))
    }
}

/// A device with no ceremony: it confirms nothing and says so.
#[derive(Debug)]
pub struct NoCeremony;

impl Ceremony for NoCeremony {
    fn kind(&self) -> CeremonyKind {
        CeremonyKind::None
    }

    fn verify<'a>(&'a self, _reason: &'a str, _within: Duration) -> BoxFuture<'a, CeremonyOutcome> {
        Box::pin(async { CeremonyOutcome::Unavailable })
    }
}

/// A phone's ceremony, run by the platform plugin's native half.
#[cfg(mobile)]
mod phone {
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use companion_platform::presence::{self, Kind, Outcome};
    use kr_client::pairing::BoxFuture;
    use kr_client::pairing::owner::{Ceremony, CeremonyKind, CeremonyOutcome};
    use tauri::{AppHandle, Runtime};

    /// How long an answer about which ceremony the phone offers is trusted. The person can set up
    /// or remove a face, a fingerprint or a screen lock in Settings while this runs.
    const FRESH: Duration = Duration::from_secs(5);

    /// How long past the time a ceremony is given the native half is waited on. The native half
    /// ends its prompt when the time is up and answers; if its answer is lost, the review would
    /// keep the connection and leave every button disabled, so it ends here instead.
    const NATIVE_MARGIN: Duration = Duration::from_secs(5);

    /// What was last read about the ceremony, and whether another read is under way.
    struct Cache {
        kind: CeremonyKind,
        read_at: Option<Instant>,
        reading: bool,
    }

    /// The phone's own ceremony. Which one it is is asked of the native half, which answers on its
    /// own time, so [`Ceremony::kind`] answers from what was read last and starts a new read once
    /// that is stale.
    pub struct Presence<R: Runtime> {
        app: AppHandle<R>,
        cache: Arc<Mutex<Cache>>,
    }

    impl<R: Runtime> Presence<R> {
        /// The phone's ceremony, with the first read of which one it is already under way.
        pub fn start(app: AppHandle<R>) -> Self {
            let presence = Self {
                app,
                cache: Arc::new(Mutex::new(Cache {
                    kind: CeremonyKind::None,
                    read_at: None,
                    reading: false,
                })),
            };
            presence.refresh();
            presence
        }

        /// Reads which ceremony the phone offers, unless a read is under way.
        fn refresh(&self) {
            {
                let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
                if cache.reading {
                    return;
                }
                cache.reading = true;
            }
            let app = self.app.clone();
            let cache = Arc::clone(&self.cache);
            tauri::async_runtime::spawn(async move {
                let kind = ceremony_kind(presence::kind(&app).await);
                let mut cache = cache.lock().unwrap_or_else(PoisonError::into_inner);
                cache.kind = kind;
                cache.read_at = Some(Instant::now());
                cache.reading = false;
            });
        }
    }

    impl<R: Runtime> std::fmt::Debug for Presence<R> {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("Presence")
        }
    }

    /// The kind the page and the interface name a ceremony by.
    const fn ceremony_kind(kind: Kind) -> CeremonyKind {
        match kind {
            Kind::FaceId => CeremonyKind::FaceId,
            Kind::TouchId => CeremonyKind::TouchId,
            Kind::Passcode => CeremonyKind::Passcode,
            Kind::Biometric => CeremonyKind::Biometric,
            Kind::ScreenLock => CeremonyKind::ScreenLock,
            Kind::None => CeremonyKind::None,
        }
    }

    impl<R: Runtime> Ceremony for Presence<R> {
        fn kind(&self) -> CeremonyKind {
            let (kind, stale) = {
                let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
                (
                    cache.kind,
                    cache.read_at.is_none_or(|at| at.elapsed() >= FRESH),
                )
            };
            if stale {
                self.refresh();
            }
            kind
        }

        fn verify<'a>(
            &'a self,
            reason: &'a str,
            within: Duration,
        ) -> BoxFuture<'a, CeremonyOutcome> {
            Box::pin(async move {
                let outcome = tokio::time::timeout(
                    within.saturating_add(NATIVE_MARGIN),
                    presence::verify(&self.app, reason, within),
                )
                .await
                .unwrap_or(Outcome::NotConfirmed);
                // What the person did may have changed what the phone offers.
                self.refresh();
                match outcome {
                    Outcome::Confirmed => CeremonyOutcome::Confirmed,
                    Outcome::NotConfirmed => CeremonyOutcome::NotConfirmed,
                    Outcome::Unavailable => CeremonyOutcome::Unavailable,
                }
            })
        }
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use std::time::Duration;

    use kr_client::pairing::BoxFuture;
    use kr_client::pairing::owner::{Ceremony, CeremonyKind, CeremonyOutcome};

    /// macOS's `LocalAuthentication`.
    #[derive(Debug)]
    pub struct LocalAuthentication;

    /// What this module asks `LAContext`.
    enum Question<'a> {
        /// Which ceremony the Mac offers.
        Kind,
        /// Whether the person confirms `reason`, answered within `within`.
        Verify { reason: &'a str, within: Duration },
    }

    enum Answer {
        Kind(CeremonyKind),
        Outcome(CeremonyOutcome),
    }

    impl Ceremony for LocalAuthentication {
        fn kind(&self) -> CeremonyKind {
            match ask(Question::Kind) {
                Answer::Kind(kind) => kind,
                Answer::Outcome(_) => CeremonyKind::None,
            }
        }

        fn verify<'a>(
            &'a self,
            reason: &'a str,
            within: Duration,
        ) -> BoxFuture<'a, CeremonyOutcome> {
            let reason = reason.to_owned();
            Box::pin(async move {
                // The platform's window may stay up for as long as the person takes, so the
                // evaluation waits on a blocking thread rather than a command's.
                tokio::task::spawn_blocking(move || {
                    match ask(Question::Verify {
                        reason: &reason,
                        within,
                    }) {
                        Answer::Outcome(outcome) => outcome,
                        Answer::Kind(_) => CeremonyOutcome::NotConfirmed,
                    }
                })
                .await
                .unwrap_or(CeremonyOutcome::NotConfirmed)
            })
        }
    }

    #[expect(
        unsafe_code,
        reason = "the user-verification ceremony is a call into Apple's LocalAuthentication \
                  runtime; on macOS this is the only function in this crate that leaves safe Rust"
    )]
    fn ask(question: Question<'_>) -> Answer {
        use objc2_foundation::NSString;
        use objc2_local_authentication::{LAContext, LAPolicy};

        let context = unsafe { LAContext::new() };
        match question {
            // `canEvaluatePolicy` tells a Mac with no ceremony apart from a person who declined
            // one, which is what lets the interface send the person to another owner device.
            Question::Kind => {
                if unsafe {
                    context
                        .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
                }
                .is_ok()
                {
                    Answer::Kind(CeremonyKind::TouchId)
                } else if unsafe {
                    context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication)
                }
                .is_ok()
                {
                    Answer::Kind(CeremonyKind::Password)
                } else {
                    Answer::Kind(CeremonyKind::None)
                }
            }
            Question::Verify { reason, within } => {
                let policy = LAPolicy::DeviceOwnerAuthentication;
                if unsafe { context.canEvaluatePolicy_error(policy) }.is_err() {
                    return Answer::Outcome(CeremonyOutcome::Unavailable);
                }
                let (sender, receiver) = std::sync::mpsc::channel();
                let handler = block2::RcBlock::new(
                    move |success: objc2::runtime::Bool, _error: *mut objc2_foundation::NSError| {
                        let _ = sender.send(success.as_bool());
                    },
                );
                unsafe {
                    context.evaluatePolicy_localizedReason_reply(
                        policy,
                        &NSString::from_str(reason),
                        &handler,
                    );
                }
                match receiver.recv_timeout(within) {
                    Ok(true) => Answer::Outcome(CeremonyOutcome::Confirmed),
                    Ok(false) => Answer::Outcome(CeremonyOutcome::NotConfirmed),
                    // The challenge's time ran out: the platform's dialog goes, and a late reply
                    // lands on a closed channel.
                    Err(_) => {
                        unsafe { context.invalidate() };
                        Answer::Outcome(CeremonyOutcome::NotConfirmed)
                    }
                }
            }
        }
    }
}

/// Windows Hello, for a window of this process.
#[cfg(target_os = "windows")]
pub mod hello {
    use std::future::IntoFuture as _;
    use std::time::Duration;

    use kr_client::pairing::BoxFuture;
    use kr_client::pairing::owner::{Ceremony, CeremonyKind, CeremonyOutcome};
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
    use windows::core::HSTRING;
    use windows_future::IAsyncOperation;

    /// Windows Hello, for one window.
    #[derive(Debug)]
    pub struct WindowsHello {
        window: isize,
    }

    impl WindowsHello {
        /// Windows Hello for the window `hwnd`.
        pub fn for_window(hwnd: HWND) -> Self {
            Self {
                window: hwnd.0 as isize,
            }
        }
    }

    impl Ceremony for WindowsHello {
        fn kind(&self) -> CeremonyKind {
            let availability =
                UserConsentVerifier::CheckAvailabilityAsync().and_then(|operation| operation.get());
            match availability {
                Ok(UserConsentVerifierAvailability::Available) => CeremonyKind::WindowsHello,
                _ => CeremonyKind::None,
            }
        }

        fn verify<'a>(
            &'a self,
            reason: &'a str,
            within: Duration,
        ) -> BoxFuture<'a, CeremonyOutcome> {
            Box::pin(async move {
                let Ok(operation) = request(self.window, reason) else {
                    return CeremonyOutcome::Unavailable;
                };
                match tokio::time::timeout(within, operation.clone().into_future()).await {
                    Ok(Ok(UserConsentVerificationResult::Verified)) => CeremonyOutcome::Confirmed,
                    Ok(Ok(
                        UserConsentVerificationResult::DeviceNotPresent
                        | UserConsentVerificationResult::NotConfiguredForUser
                        | UserConsentVerificationResult::DisabledByPolicy,
                    )) => CeremonyOutcome::Unavailable,
                    // Cancelled, retries used, the device busy, or an answer Windows could not
                    // give: not confirmed.
                    Ok(_) => CeremonyOutcome::NotConfirmed,
                    // The challenge's time ran out: Windows Hello's dialog is cancelled, and a late
                    // answer is never read.
                    Err(_) => {
                        let _ = operation.Cancel();
                        CeremonyOutcome::NotConfirmed
                    }
                }
            })
        }
    }

    #[expect(
        unsafe_code,
        reason = "Windows Hello for a window is a COM interop call; on Windows this is the only \
                  function in this crate that leaves safe Rust"
    )]
    fn request(
        window: isize,
        reason: &str,
    ) -> windows::core::Result<IAsyncOperation<UserConsentVerificationResult>> {
        let interop = windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
        unsafe {
            interop.RequestVerificationForWindowAsync(
                HWND(window as *mut core::ffi::c_void),
                &HSTRING::from(reason),
            )
        }
    }
}
