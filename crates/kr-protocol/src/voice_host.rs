//! The host's half of a call that runs on the owner's own provider account.
//!
//! On a managed call the paired device keeps a control socket open to the managed service. On a
//! call on the owner's own key there is no such service: this host holds the provider's side
//! channel itself, so the device reaches it through two methods on the ordinary write path.
//!
//! * `voice.control` carries the four things a device owes the call: a heartbeat that says the
//!   phone is still there, a mute, a fixed sentence for the model (a [`VoiceNote`]) and the
//!   question whether the host heard a delegation. Only the heartbeat is answered with the
//!   state of the call and the news since the device last heard; its claim is given back after the
//!   answer, so a heartbeat is never kept.
//! * `voice.context.send` hands the host a selection of context to write to the model.
//!
//! The device decides which sentence goes and when; the host writes the words. Every sentence a
//! device can ask for is a [`VoiceNote`] variant with its words in [`VoiceNote::words`], and the
//! device never sends text for the model.

use core::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{ActionId, VoiceSessionId};
use crate::scalars::{CanonicalSet, Nullable, U64};
use crate::voice::{VoiceContextClass, VoiceDelegationId};

/// Seconds between the heartbeats a device owes a call on the host's own key.
pub const HOST_HEARTBEAT_SECONDS: u32 = 20;

/// Seconds without a heartbeat after which the host begins to close the call.
pub const HOST_CLIENT_ABSENT_SECONDS: u32 = 120;

/// The most news items the host keeps for one call.
pub const HOST_NEWS_LIMIT: usize = 64;

/// How long `heard` waits, at most, for the host's own side channel to have heard a delegation.
pub const HOST_HEARD_WAIT_MS: u64 = 5_000;

/// The most bytes of words the host writes to the model for one delegation's result: the lead-in
/// and the host's own summary together.
pub const HOST_PERFORMED_WORDS_BYTES: usize = 500;

/* -------------------------------------------------------------------------- */
/* The notes                                                                    */
/* -------------------------------------------------------------------------- */

/// A sentence the device owes the model, by name.
///
/// One variant for each fixed sentence the device tells the model today. The words are the host's:
/// a device that names a variant cannot change what the model is told.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum VoiceNote {
    /// host actions available.
    HostActionsAvailable,
    /// host actions unavailable.
    HostActionsUnavailable,
    /// speech tainted.
    SpeechTainted,
    /// delegation refused.
    DelegationRefused,
    /// delegation not sent.
    DelegationNotSent,
    /// delegation unknown.
    DelegationUnknown,
    /// delegation admitted.
    DelegationAdmitted,
    /// delegation confirmation.
    DelegationConfirmation,
    /// delegation not confirmed.
    DelegationNotConfirmed,
    /// delegation no ceremony.
    DelegationNoCeremony,
    /// delegation challenge mismatch.
    DelegationChallengeMismatch,
    /// delegation confirmation expired.
    DelegationConfirmationExpired,
    /// delegation session not named.
    DelegationSessionNotNamed,
    /// delegation confirmation dropped.
    DelegationConfirmationDropped,
    /// delegation host refused.
    DelegationHostRefused,
    /// delegation late.
    DelegationLate,
    /// delegation performed.
    DelegationPerformed,
    /// nothing was done.
    NothingWasDone,
    /// host lost.
    HostLost,
    /// host back.
    HostBack,
    /// host back accepting.
    HostBackAccepting,
}

/// Where a note stands in the life of a delegation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotePhase {
    /// About the call, not about a delegation.
    Call,
    /// About a delegation that is not settled: a challenge was put to the person or the result is
    /// not known. A final note may follow it.
    NonFinal,
    /// About a delegation that is settled. Nothing follows it.
    Final,
}

impl VoiceNote {
    /// Every note, in declaration order.
    pub const ALL: [Self; 21] = [
        Self::HostActionsAvailable,
        Self::HostActionsUnavailable,
        Self::SpeechTainted,
        Self::DelegationRefused,
        Self::DelegationNotSent,
        Self::DelegationUnknown,
        Self::DelegationAdmitted,
        Self::DelegationConfirmation,
        Self::DelegationNotConfirmed,
        Self::DelegationNoCeremony,
        Self::DelegationChallengeMismatch,
        Self::DelegationConfirmationExpired,
        Self::DelegationSessionNotNamed,
        Self::DelegationConfirmationDropped,
        Self::DelegationHostRefused,
        Self::DelegationLate,
        Self::DelegationPerformed,
        Self::NothingWasDone,
        Self::HostLost,
        Self::HostBack,
        Self::HostBackAccepting,
    ];

    /// The words the model is told, exactly. For [`Self::DelegationPerformed`] they are the
    /// lead-in: the host adds its own bounded summary after them.
    #[must_use]
    pub const fn words(self) -> &'static str {
        match self {
            Self::HostActionsAvailable => {
                "The phone can ask the person's computer to read some things when the person says so clearly. What you are told about each such request is all that is known of it: do not say or imply that anything was done that you were not told was done."
            }
            Self::HostActionsUnavailable => {
                "In this version the phone cannot act on the person's computer. If the person asks for something to be done there, say that nothing can be done from this call. Do not say or imply that anything was done."
            }
            Self::SpeechTainted => {
                "This call can no longer act on what the person says: part of it may not have been heard or recorded here. Nothing is done on the person's computer from this call. Say so if asked."
            }
            Self::DelegationRefused => {
                "Nothing was done on the person's computer: what was said could not be used as a request. Say so, and ask the person to say it again."
            }
            Self::DelegationNotSent => {
                "Nothing was done on the person's computer: the request was not sent. Say so, and ask the person to say it again."
            }
            Self::DelegationUnknown => {
                "It is not known whether this was done on the person's computer. Do not say it was done and do not say it was not. Say that it is not known."
            }
            Self::DelegationAdmitted => {
                "The person's computer accepted the request. Whether it was carried out is not known. Do not say it was done."
            }
            Self::DelegationConfirmation => {
                "This needs the person's confirmation on the phone's unlocked screen, which the phone is asking for now. Nothing was done yet. Do not say it was done."
            }
            Self::DelegationNotConfirmed => {
                "The person did not confirm it on the phone, so nothing was done. Say so, and say it can be asked for again."
            }
            Self::DelegationNoCeremony => {
                "Nothing was done: this phone cannot ask the person to confirm on its unlocked screen. Say so."
            }
            Self::DelegationChallengeMismatch => {
                "Nothing was done: what the computer asked the person to confirm was not what was said, so the person was not asked. Say so, and ask the person to say it again."
            }
            Self::DelegationConfirmationExpired => {
                "Nothing was done: this phone's clock says the confirmation ran out. Say so, and ask the person to say it again."
            }
            Self::DelegationSessionNotNamed => {
                "Nothing was done: this phone could not read the session's number from the person's computer, so the person was not asked. Say so, and ask the person to say it again."
            }
            Self::DelegationConfirmationDropped => {
                "Nothing was done: the confirmation was not sent. Say so, and ask the person to say it again."
            }
            Self::DelegationHostRefused => {
                "The person's computer refused the request. Nothing was done. Say so."
            }
            Self::DelegationLate => {
                "More was said that belongs to this request after it was read, so the request is not carried out. Say so, and ask the person to say it again."
            }
            Self::DelegationPerformed => "The person's computer read it. Say what it reports:",
            Self::NothingWasDone => {
                "Nothing was done on the person's computer: this version does not act on spoken requests. Say so."
            }
            Self::HostLost => {
                "The phone has lost contact with the person's computer. The call goes on, but nothing can be read from or done on the computer until it is back. Do not say or imply that anything was done there."
            }
            Self::HostBack => {
                "The phone is in contact with the person's computer again. Nothing was done there while it was away."
            }
            Self::HostBackAccepting => "The phone is in contact with the person's computer again.",
        }
    }

    /// The stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostActionsAvailable => "host_actions_available",
            Self::HostActionsUnavailable => "host_actions_unavailable",
            Self::SpeechTainted => "speech_tainted",
            Self::DelegationRefused => "delegation_refused",
            Self::DelegationNotSent => "delegation_not_sent",
            Self::DelegationUnknown => "delegation_unknown",
            Self::DelegationAdmitted => "delegation_admitted",
            Self::DelegationConfirmation => "delegation_confirmation",
            Self::DelegationNotConfirmed => "delegation_not_confirmed",
            Self::DelegationNoCeremony => "delegation_no_ceremony",
            Self::DelegationChallengeMismatch => "delegation_challenge_mismatch",
            Self::DelegationConfirmationExpired => "delegation_confirmation_expired",
            Self::DelegationSessionNotNamed => "delegation_session_not_named",
            Self::DelegationConfirmationDropped => "delegation_confirmation_dropped",
            Self::DelegationHostRefused => "delegation_host_refused",
            Self::DelegationLate => "delegation_late",
            Self::DelegationPerformed => "delegation_performed",
            Self::NothingWasDone => "nothing_was_done",
            Self::HostLost => "host_lost",
            Self::HostBack => "host_back",
            Self::HostBackAccepting => "host_back_accepting",
        }
    }

    /// Where the note stands in a delegation's life.
    #[must_use]
    pub const fn phase(self) -> NotePhase {
        match self {
            Self::HostActionsAvailable
            | Self::HostActionsUnavailable
            | Self::SpeechTainted
            | Self::HostLost
            | Self::HostBack
            | Self::HostBackAccepting => NotePhase::Call,
            Self::DelegationUnknown | Self::DelegationConfirmation => NotePhase::NonFinal,
            Self::DelegationRefused
            | Self::DelegationNotSent
            | Self::DelegationAdmitted
            | Self::DelegationNotConfirmed
            | Self::DelegationNoCeremony
            | Self::DelegationChallengeMismatch
            | Self::DelegationConfirmationExpired
            | Self::DelegationSessionNotNamed
            | Self::DelegationConfirmationDropped
            | Self::DelegationHostRefused
            | Self::DelegationLate
            | Self::DelegationPerformed
            | Self::NothingWasDone => NotePhase::Final,
        }
    }

    /// Whether the note is about one delegation and so names it.
    #[must_use]
    pub const fn is_about_a_delegation(self) -> bool {
        !matches!(self.phase(), NotePhase::Call)
    }

    /// Whether the note goes to the model both as an instruction and as commentary.
    #[must_use]
    pub const fn goes_both_ways(self) -> bool {
        matches!(self, Self::SpeechTainted)
    }

    /// Whether the note is one the host refuses on a call it holds. These three tell the model
    /// about the phone's own contact with the host: the host writes its own [`HostNote`] when it
    /// loses or regains the phone, so a device never asks for one. They are for a managed call's
    /// control socket.
    #[must_use]
    pub const fn is_for_the_managed_control_only(self) -> bool {
        matches!(
            self,
            Self::HostLost | Self::HostBack | Self::HostBackAccepting
        )
    }
}

impl fmt::Display for VoiceNote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A sentence the host itself writes to the model about the phone's contact with it. A device
/// cannot ask for one: no wire type names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostNote {
    /// Two heartbeats in a row went unanswered.
    PhoneSilent,
    /// The next request came.
    PhoneBack,
}

impl HostNote {
    /// The words the model is told, exactly.
    #[must_use]
    pub const fn words(self) -> &'static str {
        match self {
            Self::PhoneSilent => {
                "The phone has not been heard from for a while, so it may not hear you or act on \
                 anything you say. Do not promise that anything will be done on the person's \
                 computer until the phone is back."
            }
            Self::PhoneBack => {
                "The phone is in contact with the host again. Nothing was done on the person's \
                 computer while it was away unless the host told you so."
            }
        }
    }
}

/* -------------------------------------------------------------------------- */
/* voice.control                                                                 */
/* -------------------------------------------------------------------------- */

/// Parameters of `voice.control`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceControlParams {
    /// The voice session the device is controlling. It is bound to the device that started it.
    pub voice_session_id: VoiceSessionId,
    /// What the device asks.
    pub arm: VoiceControlArm,
}

/// What a `voice.control` asks for.
///
/// Named by the arm, as every variant union in this protocol is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum VoiceControlArm {
    /// The phone is still there. Sent every [`HOST_HEARTBEAT_SECONDS`] under a fresh action
    /// identifier; answered with the call's state and the news since `after_seq`, and never kept.
    Heartbeat {
        /// The last news item this device received, or zero.
        after_seq: U64,
    },
    /// The person muted or unmuted the microphone.
    Mute {
        /// Whether the microphone is muted.
        muted: bool,
    },
    /// A fixed sentence is owed to the model.
    Note {
        /// Which sentence.
        note: VoiceNote,
        /// The delegation it is about, for a note about a delegation.
        delegation_id: Nullable<VoiceDelegationId>,
    },
    /// The data channel delivered a delegation: has the host's own side channel heard it?
    Heard {
        /// The provider's identifier for the delegation.
        delegation_id: VoiceDelegationId,
    },
}

/// The answer to `voice.control`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum VoiceControlResult {
    /// The answer to a heartbeat. Never kept.
    Heartbeat {
        /// Where the call stands.
        state: VoiceHostCallState,
        /// Seconds until the call's own deadline, or zero.
        remaining_seconds: u32,
        /// News since `after_seq`, oldest first.
        news: Vec<VoiceNews>,
        /// The news queue overflowed since the device last heard: the call's outcomes are not
        /// all known.
        dropped: bool,
    },
    /// The host took the mute or the note. A note names itself in the answer so a repeat can be
    /// read without the request. Proves admission to the host's writer, not provider execution.
    Admitted {
        /// The note the host took, for a note.
        note: Nullable<VoiceNote>,
    },
    /// The host's own side channel heard the delegation.
    Heard {
        /// Where in the call it was heard, in milliseconds.
        offset_ms: U64,
    },
    /// The host's own side channel has not heard the delegation. Ask again under a new action.
    NotHeard,
    /// The host did not take it.
    Refused {
        /// Why.
        reason: VoiceHostRefusal,
    },
}

/// Why the host did not take a control or a context send. Closed.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum VoiceHostRefusal {
    /// The host holds no such call, or no longer holds it.
    UnknownCall,
    /// The call is another device's.
    NotThisDevice,
    /// The call is closing.
    Closing,
    /// The host's side channel is not ready, or its deadline has passed.
    NotReady,
    /// The call's rate limit.
    Rate,
    /// The words or the selection are larger than a call carries.
    TooLarge,
    /// The host holds no record of this delegation.
    UnknownDelegation,
    /// The host already told the model this.
    AlreadyTold,
    /// The host's record of the delegation does not support this note.
    NotSupportedByRecord,
    /// The grant, or the history bound, no longer allows it.
    OutsideGrant,
    /// The provider refused the write.
    ProviderRefused,
    /// The host's side channel was lost.
    SidebandLost,
    /// Privacy mode moved.
    Privacy,
    /// A context send is already running.
    Busy,
}

impl VoiceHostRefusal {
    /// The stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownCall => "unknown_call",
            Self::NotThisDevice => "not_this_device",
            Self::Closing => "closing",
            Self::NotReady => "not_ready",
            Self::Rate => "rate",
            Self::TooLarge => "too_large",
            Self::UnknownDelegation => "unknown_delegation",
            Self::AlreadyTold => "already_told",
            Self::NotSupportedByRecord => "not_supported_by_record",
            Self::OutsideGrant => "outside_grant",
            Self::ProviderRefused => "provider_refused",
            Self::SidebandLost => "sideband_lost",
            Self::Privacy => "privacy",
            Self::Busy => "busy",
        }
    }
}

impl fmt::Display for VoiceHostRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Where a call on the host's own key stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum VoiceHostCallState {
    /// The host's side channel is ready and the call is within its deadline.
    Open,
    /// The host lost its side channel and is attaching again. Control writes wait.
    Recovering,
    /// The host began to close the call.
    Closing,
    /// The call is over, and why.
    Closed {
        /// What ended it.
        reason: VoiceEndReason,
    },
}

/// What ended a call on the host's own key.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum VoiceEndReason {
    /// The device or the owner stopped it.
    Stop,
    /// The call reached its deadline.
    Deadline,
    /// The call's grant, or the device, was revoked.
    Revocation,
    /// The provider said the session was closed.
    ProviderClosed,
    /// The phone was not heard from for two minutes.
    Silence,
    /// The owner removed the key.
    CredentialRemoved,
    /// The host lost the provider's side channel and could not get it back.
    SidebandLost,
}

impl VoiceEndReason {
    /// The stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Deadline => "deadline",
            Self::Revocation => "revocation",
            Self::ProviderClosed => "provider_closed",
            Self::Silence => "silence",
            Self::CredentialRemoved => "credential_removed",
            Self::SidebandLost => "sideband_lost",
        }
    }
}

/// One item of the news a heartbeat carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceNews {
    /// Its place in the call's news; the device acknowledges it with `after_seq`.
    pub seq: U64,
    /// What happened.
    pub item: VoiceNewsItem,
}

/// What happened on the host that the device needs to know. Carries states, offsets and counts
/// and no content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum VoiceNewsItem {
    /// The host's side channel heard a delegation.
    Delegation {
        /// The provider's identifier for it.
        delegation_id: VoiceDelegationId,
        /// Where in the call.
        offset_ms: U64,
    },
    /// The provider refused a write the host had already admitted.
    LateRefusal {
        /// The action the write came from.
        action_id: ActionId,
        /// Why.
        reason: VoiceHostRefusal,
    },
    /// Progress of a context send.
    Context {
        /// The `voice.context.send` that began the send, so two sends are never confused.
        action_id: ActionId,
        /// Appends the provider acknowledged.
        appended: u32,
        /// Appends the send holds.
        of: u32,
        /// Appends written whose acknowledgement never came: never sent again.
        unconfirmed: u32,
        /// Where the send stands.
        state: VoiceContextState,
    },
    /// The call ended.
    Ended {
        /// What ended it.
        reason: VoiceEndReason,
    },
}

/// Where a context send stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum VoiceContextState {
    /// More appends are to come.
    Sending,
    /// Every append was acknowledged.
    Done,
    /// The send stopped and is not resumed.
    Stopped {
        /// What stopped it.
        stopped_by: VoiceContextStop,
    },
}

/// What stopped a context send.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum VoiceContextStop {
    /// The call was stopped.
    Stop,
    /// The device or the call's grant was revoked.
    Revocation,
    /// A grant no longer reaches the session.
    Grant,
    /// The history bound narrowed.
    History,
    /// Privacy mode moved.
    Privacy,
    /// The call's deadline passed.
    Deadline,
    /// The host's side channel was lost.
    SidebandLost,
}

/* -------------------------------------------------------------------------- */
/* voice.context.send                                                           */
/* -------------------------------------------------------------------------- */

/// Parameters of `voice.context.send`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceContextSendParams {
    /// The voice session the context is for.
    pub voice_session_id: VoiceSessionId,
    /// The session the context is about.
    pub session_id: crate::ids::SessionId,
    /// Content classes the person selected on top of the default.
    pub selected: CanonicalSet<VoiceContextClass>,
    /// The delegation the context belongs to, or null for the call's own opening context.
    pub delegation_id: Nullable<VoiceDelegationId>,
}

/// The answer to `voice.context.send`, given at once: progress arrives as news.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum VoiceContextSendResult {
    /// The host's sender took the selection. Proves admission to the sender, not provider
    /// execution.
    Queued {
        /// How many appends the sender will write: the selection split into appends, which is
        /// refused whole when it needs more than a call carries.
        appends: u32,
    },
    /// The host did not take it.
    Refused {
        /// Why.
        reason: VoiceHostRefusal,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_note_has_its_own_words_and_its_own_wire_name() {
        let mut words = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        for note in VoiceNote::ALL {
            assert!(words.insert(note.words()), "{note} repeats another's words");
            assert!(names.insert(note.as_str()), "{note} repeats a name");
            assert!(!note.words().is_empty());
        }
        assert_eq!(words.len(), 21);
    }

    #[test]
    fn a_note_about_a_delegation_names_one_and_a_call_note_does_not() {
        for note in VoiceNote::ALL {
            let about = !matches!(note.phase(), NotePhase::Call);
            assert_eq!(note.is_about_a_delegation(), about);
        }
        assert_eq!(VoiceNote::DelegationUnknown.phase(), NotePhase::NonFinal);
        assert_eq!(
            VoiceNote::DelegationConfirmation.phase(),
            NotePhase::NonFinal
        );
        assert_eq!(VoiceNote::DelegationPerformed.phase(), NotePhase::Final);
        assert!(VoiceNote::SpeechTainted.goes_both_ways());
        assert!(!VoiceNote::DelegationLate.goes_both_ways());
    }

    #[test]
    fn the_hosts_own_two_notes_are_not_a_device_note() {
        for note in VoiceNote::ALL {
            let host = [HostNote::PhoneSilent.words(), HostNote::PhoneBack.words()];
            assert!(!host.contains(&note.words()));
            assert!(!matches!(note.as_str(), "phone_silent" | "phone_back"));
        }
        assert!(
            serde_json::from_str::<VoiceNote>("\"phone_silent\"").is_err(),
            "a device cannot name the host's own note"
        );
    }

    #[test]
    fn a_refusal_reason_is_one_of_fourteen_stable_words() {
        let all = [
            VoiceHostRefusal::UnknownCall,
            VoiceHostRefusal::NotThisDevice,
            VoiceHostRefusal::Closing,
            VoiceHostRefusal::NotReady,
            VoiceHostRefusal::Rate,
            VoiceHostRefusal::TooLarge,
            VoiceHostRefusal::UnknownDelegation,
            VoiceHostRefusal::AlreadyTold,
            VoiceHostRefusal::NotSupportedByRecord,
            VoiceHostRefusal::OutsideGrant,
            VoiceHostRefusal::ProviderRefused,
            VoiceHostRefusal::SidebandLost,
            VoiceHostRefusal::Privacy,
            VoiceHostRefusal::Busy,
        ];
        for reason in all {
            let json = serde_json::to_string(&reason).expect("a reason serialises");
            assert_eq!(json, format!("\"{}\"", reason.as_str()));
        }
    }
}
