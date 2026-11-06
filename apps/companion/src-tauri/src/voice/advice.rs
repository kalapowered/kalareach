//! The voice service's advice of the person's mute.
//!
//! The microphone's mute is native code's own, and it takes effect with no service to tell: the
//! page's mute, the lock screen's pause and the notification's toggle all end in the same native
//! state. What the service is told is advice to the provider, so that the model knows the person
//! is not speaking, and it has to follow that state whichever control changed it, and in order.
//!
//! One task keeps it. It is woken whenever the mute may have changed, reads the state native code
//! holds, and tells the service when that differs from what the service last accepted. It sits
//! off the owner's loop because a request to a service that holds no socket can wait for the
//! absent window, and the person's mute never waits for it. A wake while a request waits is kept
//! and read afterwards, so the service ends up told the newest state and never an older one after
//! it. A request that failed is tried again at the next wake, and the owner wakes it when the
//! control attaches again.

use std::sync::Arc;

use companion_platform::call::CallPlatform;
use kr_client::services::voice::VoiceCommand;
use kr_client::services::voice_control::{SendError, VoiceControl};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// The task that tells the voice service the person's mute, until it is dropped.
pub(super) struct MuteAdvice {
    wake: Arc<Notify>,
    task: JoinHandle<()>,
}

impl MuteAdvice {
    /// Starts the task for a call whose control is open. The service starts a call unmuted.
    pub(super) fn start(platform: Arc<dyn CallPlatform>, control: VoiceControl) -> Self {
        let wake = Arc::new(Notify::new());
        let waiting = Arc::clone(&wake);
        let task = tokio::spawn(async move {
            // The service starts a call unmuted.
            let mut told = Some(false);
            loop {
                waiting.notified().await;
                let Ok(held) = platform.held().await else {
                    continue;
                };
                let muted = held.microphone_muted;
                if told == Some(muted) {
                    continue;
                }
                let command = if muted {
                    VoiceCommand::Mute
                } else {
                    VoiceCommand::Unmute
                };
                let sent = control.send(command, None, None).await;
                told = told_after(told, muted, &sent);
            }
        });
        Self { wake, task }
    }

    /// The mute may have changed: the task reads it and tells the service if it differs.
    pub(super) fn changed(&self) {
        self.wake.notify_one();
    }

    /// A handle that wakes the task from another task.
    pub(super) fn waker(&self) -> Arc<Notify> {
        Arc::clone(&self.wake)
    }
}

/// What the service holds of the mute after a request for `muted`: that, once it accepted it;
/// unknown, when the request may have reached it and was never answered, so that the next wake
/// tells it whatever the person then wants, including what it was last known to hold; and what it
/// held before, when the request did not reach it or it refused it.
fn told_after<T>(told: Option<bool>, muted: bool, sent: &Result<T, SendError>) -> Option<bool> {
    match sent {
        Ok(_) => Some(muted),
        Err(SendError::Lost | SendError::Unanswered) => None,
        Err(_) => told,
    }
}

impl Drop for MuteAdvice {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request that may have reached the service and was never answered leaves what it holds
    /// unknown, so a later wish for the state it was last known to hold is still told. One that did
    /// not reach it, or that it refused, changes nothing, and an accepted one is the new state.
    #[test]
    fn an_unanswered_request_leaves_the_services_mute_unknown() {
        let unanswered: Result<(), SendError> = Err(SendError::Unanswered);
        let told = told_after(Some(false), true, &unanswered);
        assert_eq!(told, None, "the mute may or may not have been taken");
        assert_ne!(told, Some(false), "an unmute is told after it");

        let lost: Result<(), SendError> = Err(SendError::Lost);
        assert_eq!(told_after(Some(false), true, &lost), None);
        let not_sent: Result<(), SendError> = Err(SendError::NotSent);
        assert_eq!(told_after(Some(false), true, &not_sent), Some(false));
        assert_eq!(told_after(Some(true), false, &Ok(())), Some(false));
    }
}
