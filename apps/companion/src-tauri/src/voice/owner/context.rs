//! Where the host's sender stands with a call's opening context, kept apart from the order in which
//! the host's reply and its news arrive: the send's identity is the owner's own and exists before
//! anything is written, so news that names it applies whenever it comes, and a state the news gave
//! is never replaced by a reply that was late.

use kr_protocol::ids::ActionId;
use kr_protocol::voice_host::{VoiceContextState, VoiceContextStop};

use super::super::view::ContextView;

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

impl ContextProgress {
    /// What the screen shows of the send, in words for a person.
    pub(super) fn view(&self) -> ContextView {
        match *self {
            Self::Sending { appended, of } => ContextView {
                state: "sending".to_owned(),
                appended,
                of,
                unconfirmed: 0,
                stopped_by: None,
                words: if of == 0 {
                    "The host is giving this call the context of its session.".to_owned()
                } else {
                    format!(
                        "The host is giving this call the context of its session: {appended} of {of} parts so far."
                    )
                },
            },
            Self::Done => ContextView {
                state: "done".to_owned(),
                appended: 0,
                of: 0,
                unconfirmed: 0,
                stopped_by: None,
                words: "The host gave this call the context of its session.".to_owned(),
            },
            Self::Stopped {
                stopped_by,
                appended,
                of,
                unconfirmed,
            } => ContextView {
                state: "stopped".to_owned(),
                appended,
                of,
                unconfirmed,
                stopped_by: Some(stop_word(stopped_by).to_owned()),
                words: format!(
                    "The host stopped giving this call the context of its session after {appended} of {of} parts, {}.{}",
                    stopped_because(stopped_by),
                    if unconfirmed > 0 {
                        " It did not learn whether OpenAI took the next part."
                    } else {
                        ""
                    }
                ),
            },
        }
    }
}

/// What stopped the send, as the word the screen branches on.
const fn stop_word(stopped_by: VoiceContextStop) -> &'static str {
    match stopped_by {
        VoiceContextStop::Stop => "stop",
        VoiceContextStop::Revocation => "revocation",
        VoiceContextStop::Grant => "grant",
        VoiceContextStop::History => "history",
        VoiceContextStop::Privacy => "privacy",
        VoiceContextStop::Deadline => "deadline",
        VoiceContextStop::SidebandLost => "sideband_lost",
        VoiceContextStop::ProviderRefused => "provider_refused",
    }
}

/// Why the host stopped sending the context, as a clause that follows the counts.
const fn stopped_because(stopped_by: VoiceContextStop) -> &'static str {
    match stopped_by {
        VoiceContextStop::Stop => "because the call was stopped",
        VoiceContextStop::Revocation => "because this device's grant for the call was revoked",
        VoiceContextStop::Grant => "because a grant this call needs for the session ended",
        VoiceContextStop::History => "because the history the host may share was narrowed",
        VoiceContextStop::Privacy => "because privacy mode changed",
        VoiceContextStop::Deadline => "because the call reached its time limit",
        VoiceContextStop::SidebandLost => "because the host lost its connection to OpenAI",
        VoiceContextStop::ProviderRefused => "because OpenAI refused part of it",
    }
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
    /// already gave stays, and so does a count the news already gave. Says whether it changed
    /// what the send shows.
    pub(super) fn queued(&mut self, appends: u32) -> bool {
        if let ContextProgress::Sending { of, .. } = &mut self.progress
            && appends > *of
        {
            *of = appends;
            return true;
        }
        false
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
        assert!(
            send.is_over(),
            "a late reply does not make a finished send run again"
        );
        assert_eq!(send.progress(), ContextProgress::Done);
    }

    /// The words shown are one for each state and one for each cause, with the counts.
    #[test]
    fn the_shown_words_are_one_for_each_state_and_one_for_each_cause() {
        let words = |progress: ContextProgress| progress.view().words;
        assert_eq!(
            words(ContextProgress::Sending { appended: 0, of: 0 }),
            "The host is giving this call the context of its session."
        );
        assert_eq!(
            words(ContextProgress::Sending { appended: 2, of: 5 }),
            "The host is giving this call the context of its session: 2 of 5 parts so far."
        );
        assert_eq!(
            words(ContextProgress::Done),
            "The host gave this call the context of its session."
        );
        for (stopped_by, because) in [
            (VoiceContextStop::Stop, "because the call was stopped"),
            (
                VoiceContextStop::Revocation,
                "because this device's grant for the call was revoked",
            ),
            (
                VoiceContextStop::Grant,
                "because a grant this call needs for the session ended",
            ),
            (
                VoiceContextStop::History,
                "because the history the host may share was narrowed",
            ),
            (VoiceContextStop::Privacy, "because privacy mode changed"),
            (
                VoiceContextStop::Deadline,
                "because the call reached its time limit",
            ),
            (
                VoiceContextStop::SidebandLost,
                "because the host lost its connection to OpenAI",
            ),
            (
                VoiceContextStop::ProviderRefused,
                "because OpenAI refused part of it",
            ),
        ] {
            assert_eq!(
                words(ContextProgress::Stopped {
                    stopped_by,
                    appended: 2,
                    of: 5,
                    unconfirmed: 0
                }),
                format!(
                    "The host stopped giving this call the context of its session after 2 of 5 parts, {because}."
                )
            );
        }
        assert_eq!(
            words(ContextProgress::Stopped {
                stopped_by: VoiceContextStop::SidebandLost,
                appended: 1,
                of: 3,
                unconfirmed: 1
            }),
            "The host stopped giving this call the context of its session after 1 of 3 parts, because the host lost its connection to OpenAI. It did not learn whether OpenAI took the next part."
        );
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
