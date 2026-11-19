//! Where the host's sender stands with a call's opening context, kept apart from the order in which
//! the host's reply and its news arrive: the send's identity is the owner's own and exists before
//! anything is written, so news that names it applies whenever it comes, and a state the news gave
//! is never replaced by a reply that was late.

use kr_protocol::ids::ActionId;
use kr_protocol::voice_host::{VoiceContextState, VoiceContextStop};

/// How far the host's sender has got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ContextProgress {
    /// More appends are to come: `appended` of `of` so far. `of` is not known until the host's reply
    /// or its news says it.
    Sending { appended: u32, of: u32 },
    /// Every append was acknowledged.
    Done,
    /// The send stopped after `appended` of its `of` appends and is not resumed, and when
    /// `unconfirmed` is not zero the provider did not say whether it took the next.
    Stopped {
        stopped_by: VoiceContextStop,
        appended: u32,
        of: u32,
        unconfirmed: u32,
    },
}

/// The context send a host's sender is running for a call.
#[derive(Debug)]
pub(super) struct ContextSend {
    /// The `voice.context.send` that began it, which the host's news about it names.
    action_id: ActionId,
    progress: ContextProgress,
}

impl ContextSend {
    /// A send that is about to be asked for under `action_id`.
    pub(super) const fn begun(action_id: ActionId) -> Self {
        Self {
            action_id,
            progress: ContextProgress::Sending { appended: 0, of: 0 },
        }
    }

    pub(super) const fn action_id(&self) -> ActionId {
        self.action_id
    }

    pub(super) const fn progress(&self) -> ContextProgress {
        self.progress
    }

    /// Whether the send has finished or stopped: nothing more is to come of it.
    pub(super) const fn is_over(&self) -> bool {
        !matches!(self.progress, ContextProgress::Sending { .. })
    }

    /// The host's reply to the request: its sender will write `appends` appends. A state the news
    /// already gave stays, and so does a count the news already gave.
    pub(super) fn queued(&mut self, appends: u32) {
        if let ContextProgress::Sending { of, .. } = &mut self.progress {
            *of = (*of).max(appends);
        }
    }

    /// The host's news about a send. News about another send is not about this one, and news about
    /// a send that is over changes nothing. Says the new progress when this changed it.
    pub(super) fn news(
        &mut self,
        action_id: ActionId,
        appended: u32,
        of: u32,
        unconfirmed: u32,
        state: VoiceContextState,
    ) -> Option<ContextProgress> {
        if action_id != self.action_id || self.is_over() {
            return None;
        }
        self.progress = match state {
            VoiceContextState::Sending => ContextProgress::Sending { appended, of },
            VoiceContextState::Done => ContextProgress::Done,
            VoiceContextState::Stopped { stopped_by } => ContextProgress::Stopped {
                stopped_by,
                appended,
                of,
                unconfirmed,
            },
        };
        Some(self.progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> ActionId {
        ActionId::new(kr_ipc::new_uuid())
    }

    /// News that comes before the host's reply applies, and the reply that comes after a state the
    /// news gave changes nothing of it.
    #[test]
    fn news_before_the_reply_applies_and_a_late_reply_does_not_replace_a_state() {
        let ours = id();
        let mut send = ContextSend::begun(ours);
        assert_eq!(
            send.news(ours, 2, 5, 0, VoiceContextState::Sending),
            Some(ContextProgress::Sending { appended: 2, of: 5 })
        );
        send.queued(3);
        assert_eq!(
            send.progress(),
            ContextProgress::Sending { appended: 2, of: 5 },
            "a reply does not lower what the news said"
        );
        assert_eq!(
            send.news(ours, 5, 5, 0, VoiceContextState::Done),
            Some(ContextProgress::Done)
        );
        send.queued(5);
        assert!(send.is_over(), "a late reply does not make a finished send run again");
        assert_eq!(send.progress(), ContextProgress::Done);
    }

    /// A send is over once it stopped: later news for it, and a late reply, change nothing, and the
    /// news of another send is not about this one.
    #[test]
    fn a_stopped_send_stays_stopped_and_another_sends_news_is_not_its_own() {
        let (ours, other) = (id(), id());
        let mut send = ContextSend::begun(ours);
        assert_eq!(send.news(other, 1, 1, 0, VoiceContextState::Done), None);
        let stopped = ContextProgress::Stopped {
            stopped_by: VoiceContextStop::SidebandLost,
            appended: 1,
            of: 3,
            unconfirmed: 1,
        };
        assert_eq!(
            send.news(
                ours,
                1,
                3,
                1,
                VoiceContextState::Stopped {
                    stopped_by: VoiceContextStop::SidebandLost
                }
            ),
            Some(stopped)
        );
        send.queued(3);
        assert_eq!(send.news(ours, 3, 3, 0, VoiceContextState::Done), None);
        assert_eq!(send.progress(), stopped);
    }
}
