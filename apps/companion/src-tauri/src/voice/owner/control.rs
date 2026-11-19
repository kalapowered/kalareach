//! What an owner holds of a call's control, whichever way the call is controlled.
//!
//! A managed call is controlled over a socket this device opens to the voice service, and its model
//! hears what the device writes there. A call on the host owner's own key is controlled through the
//! host, which holds the provider's side of it and writes the words itself. The owner decides which
//! sentence goes to the model and when, and this seam is the one place that knows how the sentence
//! gets there.

use kr_client::services::voice::VoiceCommand;
use kr_client::services::voice_control::{ControlEvents, ControlNews, SendError, VoiceControl};
use kr_protocol::voice_host::VoiceNote;

use crate::voice::host_control::{HostControl, HostEvents, HostNews, HostSendError};

/// What the model is told: a fixed sentence, and for a performed request the summary that follows
/// it on a managed call. On a call the host controls the host takes the summary from its own record.
pub(in crate::voice) struct Said {
    pub(in crate::voice) note: VoiceNote,
    pub(in crate::voice) summary: Option<String>,
}

impl From<VoiceNote> for Said {
    fn from(note: VoiceNote) -> Self {
        Self {
            note,
            summary: None,
        }
    }
}

impl Said {
    /// The words a managed control writes: the table's sentence, and the summary after it.
    pub(in crate::voice) fn managed_words(&self) -> String {
        match &self.summary {
            Some(summary) => format!("{} {summary}", self.note.words()),
            None => self.note.words().to_owned(),
        }
    }
}

/// The command a managed control writes a note as: instructions without a delegation, commentary
/// with one.
fn managed_command(delegation: Option<&str>) -> VoiceCommand {
    if delegation.is_some() {
        VoiceCommand::Commentary
    } else {
        VoiceCommand::Instructions
    }
}

/// How far a request for the person's mute got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::voice) enum Reached {
    /// The control took it.
    Told,
    /// It may have reached the call, and nothing came back: asking again could give the provider
    /// the same advice twice.
    Maybe,
    /// It did not reach the call, or was refused.
    NotTold,
}

/// A call's control, from the side that uses it. Cheap to clone.
#[derive(Clone)]
pub(in crate::voice) enum CallControl {
    /// The socket to the voice service.
    Managed(VoiceControl),
    /// The host's methods.
    Host(HostControl),
}

impl CallControl {
    /// Tells the model `said`, about `delegation` when it is about one, and says whether it was
    /// told. A sentence that only the managed control writes (what a device says of its own path to
    /// the host) is not sent on a call the host controls: the host writes the only model sentences
    /// there.
    pub(in crate::voice) async fn tell(&self, said: &Said, delegation: Option<&str>) -> bool {
        match self {
            Self::Managed(control) => control
                .send(
                    managed_command(delegation),
                    delegation,
                    Some(&said.managed_words()),
                )
                .await
                .is_ok(),
            Self::Host(control) => {
                if said.note.is_for_the_managed_control_only() {
                    return false;
                }
                control.note(said.note, delegation).await.is_ok()
            }
        }
    }

    /// Tells the call the person's microphone state, as advice to the provider.
    pub(in crate::voice) async fn advise_mute(&self, muted: bool) -> Reached {
        match self {
            Self::Managed(control) => {
                let command = if muted {
                    VoiceCommand::Mute
                } else {
                    VoiceCommand::Unmute
                };
                match control.send(command, None, None).await {
                    Ok(_) => Reached::Told,
                    Err(SendError::Lost | SendError::Unanswered) => Reached::Maybe,
                    Err(_) => Reached::NotTold,
                }
            }
            Self::Host(control) => match control.mute(muted).await {
                Ok(()) => Reached::Told,
                Err(HostSendError::Unanswered) => Reached::Maybe,
                Err(HostSendError::NotSent | HostSendError::Refused(_)) => Reached::NotTold,
            },
        }
    }

    /// Ends the control without closing the call.
    pub(in crate::voice) fn stop(&self) {
        match self {
            Self::Managed(control) => control.stop(),
            Self::Host(control) => control.stop(),
        }
    }
}

/// What a control tells its owner.
pub(in crate::voice) enum ControlFeed {
    Managed(ControlEvents),
    Host(HostEvents),
}

/// A piece of a control's news.
pub(in crate::voice) enum CallNews {
    /// What the voice service's socket told.
    Service(ControlNews),
    /// What the host's heartbeat told.
    Host(HostNews),
}

impl ControlFeed {
    /// The next piece of news, or nothing once the control is over and everything it told has been
    /// read.
    pub(in crate::voice) async fn next(&mut self) -> Option<CallNews> {
        match self {
            Self::Managed(events) => events.next().await.map(CallNews::Service),
            Self::Host(events) => events.next().await.map(CallNews::Host),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use kr_protocol::ids::{ActionId, VoiceSessionId};
    use kr_protocol::voice_host::{
        VoiceContextSendParams, VoiceContextSendResult, VoiceControlArm, VoiceControlParams,
        VoiceControlResult, VoiceHostCallState,
    };

    use super::*;
    use crate::voice::host_control::{HostLimits, HostLink, LinkError, LinkFuture};

    /// A host that records the arms it is written, takes the notes and the mute, and answers a
    /// heartbeat with an open call.
    struct Recording {
        arms: Mutex<Vec<VoiceControlArm>>,
        refuse_writes: bool,
    }

    impl HostLink for Recording {
        fn control<'a>(
            &'a self,
            _action_id: ActionId,
            params: &'a VoiceControlParams,
        ) -> LinkFuture<'a, VoiceControlResult> {
            self.arms
                .lock()
                .expect("the record")
                .push(params.arm.clone());
            let refuse = self.refuse_writes;
            let answer = match &params.arm {
                VoiceControlArm::Heartbeat { .. } => Ok(VoiceControlResult::Heartbeat {
                    state: VoiceHostCallState::Open,
                    remaining_seconds: 100,
                    news: Vec::new(),
                    dropped: false,
                }),
                _ if refuse => Err(LinkError::NotSent),
                _ => Ok(VoiceControlResult::Admitted {
                    note: kr_protocol::scalars::Nullable::null(),
                }),
            };
            Box::pin(async move { answer })
        }

        fn send_context<'a>(
            &'a self,
            _action_id: ActionId,
            _params: &'a VoiceContextSendParams,
        ) -> LinkFuture<'a, VoiceContextSendResult> {
            Box::pin(async { Err(LinkError::NotSent) })
        }
    }

    fn host_control(link: Arc<Recording>) -> CallControl {
        let (control, _events) = HostControl::open(
            link,
            VoiceSessionId::new(kr_ipc::new_uuid()),
            HostLimits {
                beat: Duration::from_secs(3_600),
                miss_after: Duration::from_secs(10),
                silent_after: Duration::from_secs(7_200),
                within: Duration::from_secs(20),
            },
        );
        CallControl::Host(control)
    }

    fn notes_written(link: &Recording) -> Vec<(VoiceNote, Option<String>)> {
        link.arms
            .lock()
            .expect("the record")
            .iter()
            .filter_map(|arm| match arm {
                VoiceControlArm::Note {
                    note,
                    delegation_id,
                } => Some((
                    *note,
                    delegation_id.as_ref().map(|id| id.as_str().to_owned()),
                )),
                _ => None,
            })
            .collect()
    }

    /// Every sentence the device owes the model reaches the host as its note, for the delegation it
    /// is about; the three the device only says on a managed call are never written to the host,
    /// which writes the only model sentences of a call it controls.
    #[tokio::test(start_paused = true)]
    async fn every_note_the_device_tells_reaches_the_host_as_that_note_and_the_managed_only_are_not_sent()
     {
        let link = Arc::new(Recording {
            arms: Mutex::new(Vec::new()),
            refuse_writes: false,
        });
        let control = host_control(Arc::clone(&link));
        let mut expected = Vec::new();
        for note in VoiceNote::ALL {
            let delegation = note.is_about_a_delegation().then_some("d-1");
            let told = control.tell(&Said::from(note), delegation).await;
            if note.is_for_the_managed_control_only() {
                assert!(!told, "{note} is the managed control's alone");
            } else {
                assert!(told, "{note} was not taken by the host");
                expected.push((note, delegation.map(str::to_owned)));
            }
        }
        assert_eq!(notes_written(&link), expected);
        assert_eq!(expected.len(), 18);
        control.stop();
    }

    /// The managed control's frames are what they were before the sentences moved to one table: each
    /// note is written as the base wrote it, instructions without a delegation and commentary with
    /// one, in the table's words, and a performed request has its summary after its sentence.
    #[test]
    fn the_managed_words_and_command_of_each_note_are_what_they_were() {
        for note in VoiceNote::ALL {
            assert_eq!(Said::from(note).managed_words(), note.words());
            assert_eq!(managed_command(None), VoiceCommand::Instructions);
            assert_eq!(managed_command(Some("d-1")), VoiceCommand::Commentary);
        }
        let performed = Said {
            note: VoiceNote::DelegationPerformed,
            summary: Some("Read the status.".to_owned()),
        };
        assert_eq!(
            performed.managed_words(),
            format!(
                "{} Read the status.",
                VoiceNote::DelegationPerformed.words()
            )
        );
    }

    /// A performed request is told by its note alone: the host takes the summary from its own record,
    /// so nothing of the summary a managed call writes after the sentence is sent to the host.
    #[tokio::test(start_paused = true)]
    async fn a_performed_note_carries_no_summary_to_the_host() {
        let link = Arc::new(Recording {
            arms: Mutex::new(Vec::new()),
            refuse_writes: false,
        });
        let control = host_control(Arc::clone(&link));
        let said = Said {
            note: VoiceNote::DelegationPerformed,
            summary: Some("a summary the host must not take from this device".to_owned()),
        };
        assert!(control.tell(&said, Some("d-1")).await);
        assert_eq!(
            notes_written(&link),
            [(VoiceNote::DelegationPerformed, Some("d-1".to_owned()))]
        );
        let arms = format!("{:?}", link.arms.lock().expect("the record"));
        assert!(
            !arms.contains("summary the host must not take"),
            "the summary reached the host: {arms}"
        );
        control.stop();
        assert_eq!(
            said.managed_words(),
            format!(
                "{} a summary the host must not take from this device",
                VoiceNote::DelegationPerformed.words()
            ),
            "a managed control writes the sentence and the summary after it"
        );
    }

    /// The person's mute is reported by how far it got, as the advice task needs it: taken, refused
    /// or never sent.
    #[tokio::test(start_paused = true)]
    async fn the_mute_advice_is_reported_by_how_far_it_got() {
        let taken = Arc::new(Recording {
            arms: Mutex::new(Vec::new()),
            refuse_writes: false,
        });
        let control = host_control(Arc::clone(&taken));
        assert_eq!(control.advise_mute(true).await, Reached::Told);
        control.stop();

        let refused = Arc::new(Recording {
            arms: Mutex::new(Vec::new()),
            refuse_writes: true,
        });
        let control = host_control(refused);
        assert_eq!(control.advise_mute(true).await, Reached::NotTold);
        control.stop();
    }
}
