//! The companion's native platform services, shared by every feature that needs them.
//!
//! Ten services, each a mechanism with no feature's policy in it:
//!
//! * [`secrets`]: the one secure store the companion keeps secrets in. The Keychain on macOS and
//!   iOS, the Credential Manager on Windows, the Secret Service on Linux, and on Android files
//!   sealed under a non-exportable Keystore key. An account's tokens and a device's keys both live
//!   here, and nothing writes a second store.
//! * [`backup`]: marking a directory as not to be backed up, on the systems whose backup would carry
//!   a record without the key it was made beside.
//! * [`protection`]: whether the device's protected data can be read yet, and the system's word
//!   when it can. iOS holds an application's files and keychain items back from a restart until the
//!   first unlock.
//! * [`presence`]: whether the phone's owner is in front of it now, asked of the ceremony the
//!   operating system draws: Face ID, Touch ID or the passcode, and Android's biometric prompt.
//! * [`scan`]: reading a QR code from the phone's camera or from a picture, in native code, so that an
//!   invitation's secret goes no further than native code.
//! * [`browser`]: the browser-backed session a sign-in hands its ceremony to on a phone: iOS's
//!   authentication session, and Android's Auth Tab or a Custom Tab with a verified link.
//! * [`notify`]: what only the platform can say or do about notifications: whether the person
//!   allowed them, the provider's registration token, the record of the registration being waited
//!   for, the limited key store a receiver reads, and a tap on a notification.
//! * [`push`]: a push receiver's answer to a registration challenge, decided and signed by one
//!   function over the installation's own key, so that the receiver runs with no interface and no
//!   JavaScript and signs nothing but that answer.
//! * [`call`]: the voice call that native code holds (capture, playback and the media connection),
//!   the commands that reach it and the news it sends back.
//! * the Android TLS verifier's start: the platform verifier the HTTPS client uses needs the JVM
//!   and the application context before its first connection, and the plugin's Kotlin half hands
//!   them over when it loads.
//!
//! The native halves are this crate's Swift package (`ios/`) and Android library (`android/`),
//! registered with Tauri as one plugin. They report facts; the decisions are taken here, in Rust,
//! where the host's tests reach them.

use tauri::plugin::{Builder, TauriPlugin};
use tauri::{Manager as _, Runtime};

pub mod backup;
pub mod browser;
pub mod call;
pub mod notify;
pub mod presence;
pub mod protection;
pub mod push;
pub mod scan;
pub mod secrets;
#[cfg(target_os = "android")]
mod tls;

/// The plugin's name.
pub const NAME: &str = "companion-platform";

/// A platform service that could not do what it was asked.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PlatformError(pub String);

impl PlatformError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// What the plugin holds: the handle to its native halves, on a phone.
pub struct Platform<R: Runtime> {
    #[cfg(mobile)]
    handle: tauri::plugin::PluginHandle<R>,
    #[cfg(not(mobile))]
    _runtime: std::marker::PhantomData<fn() -> R>,
}

#[cfg(mobile)]
impl<R: Runtime> Platform<R> {
    /// Calls one of the native methods and reads its answer. The call runs to its end whatever the
    /// caller does ([`to_its_end`]).
    async fn call<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        method: &str,
        arguments: impl serde::Serialize,
    ) -> Result<T, PlatformError> {
        let arguments = serde_json::to_value(arguments).map_err(|error| {
            PlatformError::new(format!("the platform's {method} failed: {error}"))
        })?;
        let handle = self.handle.clone();
        let named = method.to_owned();
        to_its_end(async move {
            handle
                .run_mobile_plugin_async::<T>(&named, arguments)
                .await
                .map_err(|error| {
                    PlatformError::new(format!("the platform's {named} failed: {error}"))
                })
        })
        .await?
    }

    /// Calls one of the native methods from a thread that may wait for it. The thread the platform
    /// starts the application on is one: the plugin answers on a queue of its own. Only the iOS
    /// store opens this way; Android's store calls its native half through the handle it keeps.
    #[cfg(target_os = "ios")]
    fn call_blocking<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        arguments: impl serde::Serialize,
    ) -> Result<T, PlatformError> {
        self.handle
            .run_mobile_plugin(method, arguments)
            .map_err(|error| PlatformError::new(format!("the platform's {method} failed: {error}")))
    }
}

/// Runs `call` to its end even when the caller stops waiting for it.
///
/// Tauri hands the answer of a native command to a callback that unwraps the send on the channel
/// the caller waits on. A caller that is dropped (a timeout, a run that was cancelled) takes the
/// channel with it, and the native answer, when it comes, panics in a callback the native side
/// called into, which ends the process. So the call is moved to a task of its own, which keeps the
/// channel until the answer comes; a caller that left finds its answer discarded.
///
/// The caller makes the first poll, which is the one that sends the command: commands reach the
/// platform in the order callers ask, whatever the task below is doing, so a set of keys asked for
/// later is never sent before one asked for earlier.
///
/// # Errors
///
/// Returns an error when the first poll panics, as Tauri's does on Android when no activity is
/// registered to send the command to: nothing went out, so no answer follows. It returns an error
/// too when the task itself is lost.
#[cfg(any(mobile, test))]
async fn to_its_end<T: Send + 'static>(
    call: impl std::future::Future<Output = T> + Send + 'static,
) -> Result<T, PlatformError> {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::task::Poll;

    let mut call = Box::pin(call);
    let first = std::future::poll_fn(|context| {
        Poll::Ready(catch_unwind(AssertUnwindSafe(|| {
            call.as_mut().poll(context)
        })))
    })
    .await;
    match first {
        Ok(Poll::Ready(answer)) => return Ok(answer),
        Ok(Poll::Pending) => {}
        Err(panic) => {
            let said = panic
                .downcast_ref::<&str>()
                .map(|said| (*said).to_owned())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "it panicked".to_owned());
            return Err(PlatformError::new(format!(
                "the platform's call failed: {said}"
            )));
        }
    }
    tauri::async_runtime::spawn(call)
        .await
        .map_err(|error| PlatformError::new(format!("the platform's call was lost: {error}")))
}

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_companion_platform);

/// The plugin. Register it before anything asks for a store or a session.
#[must_use]
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new(NAME)
        .setup(|app, api| {
            #[cfg(target_os = "android")]
            let handle = api.register_android_plugin("to.kala.reach.platform", "PlatformPlugin")?;
            #[cfg(target_os = "ios")]
            let handle = api.register_ios_plugin(init_plugin_companion_platform)?;
            #[cfg(not(mobile))]
            let _ = api;
            app.manage(Platform::<R> {
                #[cfg(mobile)]
                handle,
                #[cfg(not(mobile))]
                _runtime: std::marker::PhantomData,
            });
            Ok(())
        })
        .build()
}

#[cfg(test)]
mod tests {
    use super::to_its_end;

    /// Says, when it is dropped, whether the call it belonged to had answered.
    struct Report {
        answered: bool,
        to: Option<tokio::sync::oneshot::Sender<bool>>,
    }

    impl Drop for Report {
        fn drop(&mut self) {
            if let Some(to) = self.to.take() {
                let _ = to.send(self.answered);
            }
        }
    }

    /// A native call that is dropped before it answers makes Tauri's callback panic when the answer
    /// comes, so a caller that stops waiting (a timeout, a cancelled run) must leave the call to its
    /// end: it is not dropped before it answers, and a caller that stays gets the answer.
    #[tokio::test]
    async fn a_call_whose_caller_stops_waiting_runs_to_its_answer() {
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let (report, reported) = tokio::sync::oneshot::channel::<bool>();
        let call = async move {
            let mut guard = Report {
                answered: false,
                to: Some(report),
            };
            let _ = gate.await;
            guard.answered = true;
            7_u8
        };
        let mut waiting = Box::pin(to_its_end(call));
        // The caller polls once, which starts the call, and then stops waiting.
        tokio::select! {
            biased;
            _ = &mut waiting => unreachable!("the call cannot have answered"),
            () = std::future::ready(()) => {}
        }
        drop(waiting);

        release.send(()).expect("the call is still waiting");
        assert!(
            reported.await.expect("the call ended"),
            "the call was dropped before it answered"
        );
        assert_eq!(to_its_end(async { 7_u8 }).await.expect("an answer"), 7);
    }

    /// Commands must reach the platform in the order callers ask, so the poll that sends a command is
    /// the caller's own: a task started for it could be run after a command asked for later.
    #[tokio::test]
    async fn a_call_is_first_polled_in_the_turn_of_its_caller() {
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let polled_on = std::sync::Arc::new(std::sync::Mutex::new(None));
        let seen = std::sync::Arc::clone(&polled_on);
        let call = async move {
            seen.lock()
                .expect("the thread of the first poll")
                .get_or_insert(std::thread::current().id());
            let _ = gate.await;
        };
        let mut waiting = Box::pin(to_its_end(call));
        tokio::select! {
            biased;
            _ = &mut waiting => unreachable!("the call cannot have answered"),
            () = std::future::ready(()) => {}
        }

        assert_eq!(
            *polled_on.lock().expect("the thread of the first poll"),
            Some(std::thread::current().id()),
            "the command was not sent in the caller's turn"
        );
        drop(waiting);
        let _ = release.send(());
    }

    /// The first poll is the caller's, and on Android Tauri's send panics there when no activity is
    /// registered: the caller gets that as the platform's error, as it did when a task of its own
    /// caught the panic, and does not unwind with it.
    #[tokio::test]
    async fn a_call_that_panics_in_its_first_poll_is_the_platforms_error() {
        let call =
            std::future::poll_fn(|_| -> std::task::Poll<u8> { panic!("no available activity") });
        let error = to_its_end(call)
            .await
            .expect_err("the call never went out, so it has no answer");
        assert!(error.0.contains("no available activity"), "{error}");
    }
}
