//! The voice service's advice of the person's mute.
//!
//! The microphone's mute is native code's own, and it takes effect with no service to tell: the
//! page's mute, the lock screen's pause and the notification's toggle all end in the same native
//! state. What the service is told is advice to the provider, so that the model knows the person
//! is not speaking, and it has to follow that state whichever control changed it, and in order.
//!
//! One task keeps it. It is woken whenever the mute may have changed, reads the state native code
//! holds, and tells the service when that differs from the state it last asked for. A request the
//! service never answered may have reached the provider, so its state counts as asked for: the
//! same state is not asked for a second time, and a different one still is. It sits off the
//! owner's loop because a request to a service that holds no socket can wait for the absent
//! window, and the person's mute never waits for it. A wake while a request waits is kept and read
//! afterwards, so the service ends up told the newest state and never an older one after it. A
//! request that was not sent, or that the service refused, is tried again at the next wake, and
//! the owner wakes it when the control attaches again.

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
            // The state the service was last asked to hold. It starts a call unmuted.
            let mut asked = false;
            loop {
                waiting.notified().await;
                let Ok(held) = platform.held().await else {
                    continue;
                };
                let muted = held.microphone_muted;
                if asked == muted {
                    continue;
                }
                let command = if muted {
                    VoiceCommand::Mute
                } else {
                    VoiceCommand::Unmute
                };
                let sent = control.send(command, None, None).await;
                asked = asked_after(asked, muted, &sent);
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

/// The state the service has been asked to hold after a request for `muted`: that, once the
/// request was accepted, and also when it may have reached the service and was never answered,
/// because asking again as a new request could give the provider the same advice twice (a
/// different state is still asked for); and what it was before, when the request did not reach the
/// service or the service refused it, so that the next wake asks again.
fn asked_after<T>(asked: bool, muted: bool, sent: &Result<T, SendError>) -> bool {
    match sent {
        Ok(_) | Err(SendError::Lost | SendError::Unanswered) => muted,
        Err(_) => asked,
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

    /// A request that may have reached the service and was never answered is not made again: the
    /// state it asked for stays what the task holds, so the same mute is not asked for a second
    /// time under a new identifier, and a different one, the unmute, still goes. One that did not
    /// reach the service, or that it refused, changes nothing, and an accepted one is the new state.
    #[test]
    fn an_unanswered_mute_is_not_asked_for_again_and_an_unmute_still_is() {
        let unanswered: Result<(), SendError> = Err(SendError::Unanswered);
        let lost: Result<(), SendError> = Err(SendError::Lost);
        for outcome in [&unanswered, &lost] {
            // The person mutes and the request is never answered. The task sends only while the
            // state asked for differs from the person's mute, so a later wake with the mute still
            // on sends nothing, and the person's unmute differs and is sent.
            let (mute, unmute) = (true, false);
            let asked = asked_after(unmute, mute, outcome);
            assert_eq!(asked, mute, "the mute was asked for, whatever became of it");
            assert_ne!(asked, unmute, "an unmute differs from it and is asked for");
            assert_eq!(asked_after(asked, unmute, outcome), unmute);
        }
        // A request that was never sent, or that the service refused, asks for nothing: the next
        // wake sends it again.
        let not_sent: Result<(), SendError> = Err(SendError::NotSent);
        assert!(!asked_after(false, true, &not_sent));
        assert!(!asked_after(true, false, &Ok(())));
    }
}
