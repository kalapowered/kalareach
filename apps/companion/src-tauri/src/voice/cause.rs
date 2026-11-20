//! Why a call ends, and what a person is told about it.

use kr_client::services::voice_control::ControlEnd;
use kr_protocol::voice_host::{HOST_CLIENT_ABSENT_SECONDS, VoiceEndReason, VoiceProviderClose};

use super::host_control::{CloseWord, HostEnding};
use super::view::HostEnd;

/// What a person is told when a call on the host's own key has ended on this phone and the stop did
/// not reach the host, so the host was not asked: the host's own absence rule decides when it
/// closes the call, and the call may be charged until then.
pub(super) const LEFT_TO_HOST: &str = "The call has ended on this phone. This host starts closing \
    the call at OpenAI two minutes after it last heard from this phone; if it cannot confirm \
    that, the call may keep running on your OpenAI account until OpenAI ends it.";

/// What a person is told when a call on the host's own key has ended and the host did not confirm
/// that it closed the call, whether it lost its connection to OpenAI or its hang-up was not
/// confirmed.
pub(super) const HOST_UNCONFIRMED: &str = "The call has ended on this phone. The host could not \
    confirm that OpenAI closed the call, so the call may keep running on your OpenAI account until \
    OpenAI ends it.";

/// What a person is told when a call on the host's own key has ended and the host never told this
/// phone that OpenAI closed the call, though the host was asked: it holds no such call, it refused
/// the stop, or the stop may not have reached it.
pub(super) const HOST_UNHEARD: &str = "The call has ended on this phone. This phone did not hear \
    from the host that OpenAI closed the call, so the call may keep running on your OpenAI \
    account until OpenAI ends it.";

/// What a person is told when this phone could not find the call at the host and the host has since
/// said that OpenAI closed it.
pub(super) const HOST_FOUND_CLOSED: &str = "This phone could not find the call at the host, so the \
    call ended on this phone. The host has since said that OpenAI closed the call.";

/// What a person is told when this phone heard nothing from the host for as long as the host waits
/// before it closes a call, and the host has since said that the call is over: in its answer to the
/// stop, in the news this phone read while the call closed, or in its final status.
pub(super) const HOST_SILENT_SETTLED: &str = "This phone heard nothing from the host for two \
    minutes, so the call ended on this phone. The host has since said that the call is over.";

// The sentences above and below say "two minutes" for the bound the host's absence rule and this
// phone's silence end share, and the words stay true only while that bound is two minutes.
const _: () = assert!(HOST_CLIENT_ABSENT_SECONDS == 120);

/// Why a call is ending.
#[derive(Clone, Debug)]
pub enum Cause {
    /// The person ended it, or gave up on a start that was under way.
    Requested,
    /// Native code said the call ended: the notification's stop, the system, the call's own
    /// deadline, or a connection that failed.
    NativeEnded,
    /// The media connection failed.
    NativeFailed,
    /// Native code no longer holds the call, which the news did not say.
    NativeGone,
    /// Native code stopped answering.
    NativeSilent,
    /// The voice service's control ended.
    Control(ControlEnd),
    /// The host's control of a call on its own key ended.
    Host(HostEnding),
    /// The call reached the moment the host said it closes.
    Deadline,
    /// The account on this device was signed out or replaced.
    AccountChanged,
    /// This device no longer holds the pairing with the host the call belongs to.
    HostForgotten,
    /// The person chose another host while the call ran.
    HostChanged,
    /// A step of the setup after the host created the call did not work.
    Step(String),
    /// The host named a voice service other than the one this device's account is signed in at.
    ForeignService,
}

impl Cause {
    /// The word the screen branches on.
    pub fn word(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::NativeEnded => "native_ended",
            Self::NativeFailed => "native_failed",
            Self::NativeGone => "native_gone",
            Self::NativeSilent => "native_silent",
            Self::Control(end) => match end {
                ControlEnd::Closed { .. } => "service_closed",
                ControlEnd::NoSuchCall => "no_such_call",
                ControlEnd::NotAuthorised => "not_authorised",
                ControlEnd::NoToken => "no_token",
                ControlEnd::Refused(_) => "service_refused",
                ControlEnd::Misconfigured => "service_misconfigured",
                ControlEnd::Unreachable => "service_unreachable",
            },
            Self::Host(end) => match end {
                HostEnding::Reason {
                    reason: VoiceEndReason::Deadline,
                    ..
                } => "deadline",
                HostEnding::Reason {
                    reason: VoiceEndReason::Stop,
                    ..
                } => "host_stopped",
                HostEnding::Reason {
                    reason: VoiceEndReason::Revocation,
                    ..
                } => "host_revoked",
                HostEnding::Reason {
                    reason: VoiceEndReason::ProviderClosed,
                    ..
                } => "provider_closed",
                HostEnding::Reason {
                    reason: VoiceEndReason::Silence,
                    ..
                } => "host_silence",
                HostEnding::Reason {
                    reason: VoiceEndReason::CredentialRemoved,
                    ..
                } => "key_removed",
                HostEnding::Reason {
                    reason: VoiceEndReason::SidebandLost,
                    ..
                } => "host_sideband_lost",
                HostEnding::NotKnown(_) => "host_lost_call",
                HostEnding::Silent => "host_silent",
            },
            Self::Deadline => "deadline",
            Self::AccountChanged => "account_changed",
            Self::HostForgotten => "host_forgotten",
            Self::HostChanged => "host_changed",
            Self::Step(_) => "step_failed",
            Self::ForeignService => "foreign_service",
        }
    }

    /// What a person is told.
    pub fn words(&self) -> String {
        match self {
            Self::Requested => "You ended the call.".to_owned(),
            Self::NativeEnded => {
                "The call ended on this device: from its notification, by the system, or at its \
                 time limit."
                    .to_owned()
            }
            Self::NativeFailed => "The connection to the voice provider failed.".to_owned(),
            Self::NativeGone => "This device no longer holds the call.".to_owned(),
            Self::NativeSilent => {
                "This device's call stopped answering, so the call was ended.".to_owned()
            }
            Self::Control(end) => match end {
                ControlEnd::Closed { .. } => "The voice service closed the call.".to_owned(),
                ControlEnd::NoSuchCall => {
                    "This voice service has no such call for this account. It may be another \
                     account's call, or a call the service no longer has."
                        .to_owned()
                }
                ControlEnd::NotAuthorised => {
                    "The voice service did not accept this device's account, so the call was \
                     ended."
                        .to_owned()
                }
                ControlEnd::NoToken => {
                    "This device could not get its account's voice token, so the call was ended."
                        .to_owned()
                }
                ControlEnd::Refused(_) => {
                    "The voice service refused this device's connection, so the call was ended."
                        .to_owned()
                }
                ControlEnd::Misconfigured => {
                    "The voice service's address could not be opened, so the call was ended."
                        .to_owned()
                }
                ControlEnd::Unreachable => {
                    "The voice service could not be reached for two minutes, so the call was \
                     ended."
                        .to_owned()
                }
            },
            Self::Host(end) => match end {
                HostEnding::Reason {
                    reason: VoiceEndReason::Deadline,
                    ..
                } => "The call reached its time limit.".to_owned(),
                HostEnding::Reason {
                    reason: VoiceEndReason::Stop,
                    ..
                } => "The host ended the call.".to_owned(),
                HostEnding::Reason {
                    reason: VoiceEndReason::Revocation,
                    ..
                } => "The host ended the call because this device's grant for it was revoked."
                    .to_owned(),
                HostEnding::Reason {
                    reason: VoiceEndReason::ProviderClosed,
                    provider_close: VoiceProviderClose::Unconfirmed,
                } => "The host's connection to the call at OpenAI ended.".to_owned(),
                HostEnding::Reason {
                    reason: VoiceEndReason::ProviderClosed,
                    ..
                } => "OpenAI closed the call.".to_owned(),
                HostEnding::Reason {
                    reason: VoiceEndReason::Silence,
                    ..
                } => "The host ended the call because it had not heard from this device for two \
                     minutes."
                    .to_owned(),
                HostEnding::Reason {
                    reason: VoiceEndReason::CredentialRemoved,
                    ..
                } => "The OpenAI key on the host was removed, so the call was ended.".to_owned(),
                HostEnding::Reason {
                    reason: VoiceEndReason::SidebandLost,
                    ..
                } => {
                    "The host lost its connection to OpenAI and could not restore it, so the call \
                     was ended."
                        .to_owned()
                }
                HostEnding::NotKnown(_) | HostEnding::Silent => HOST_UNHEARD.to_owned(),
            },
            Self::Deadline => "The call reached its time limit.".to_owned(),
            Self::AccountChanged => {
                "The account on this device changed, so the call was ended.".to_owned()
            }
            Self::HostForgotten => {
                "This device no longer holds the pairing with the host the call belongs to, so \
                 the call was ended."
                    .to_owned()
            }
            Self::HostChanged => {
                "You chose another host while the call was running, so the call was ended. A call \
                 belongs to the host that made it."
                    .to_owned()
            }
            Self::Step(why) => format!("The call could not be set up on this device: {why}"),
            Self::ForeignService => {
                "The host named a voice service other than the one this device's account is \
                 signed in at, so this device presented no token there and ended the call."
                    .to_owned()
            }
        }
    }

    /// What a person is told where another sentence follows these words. Each cause is a sentence of
    /// its own but a setup clause: that clause stands inside the sentence "The call could not be set
    /// up on this device: ..." and has no full stop of its own, so one is added where a sentence
    /// follows it.
    pub fn sentence(&self) -> String {
        let words = self.words();
        match self {
            Self::Step(_) if !words.ends_with(['.', '!', '?']) => format!("{words}."),
            _ => words,
        }
    }

    /// Whether the voice service closed the call itself, so asking it to again is not needed.
    pub const fn service_closed(&self) -> bool {
        matches!(self, Self::Control(ControlEnd::Closed { .. }))
    }
}

/// Whether a call on the host's own key is closed: the host said OpenAI confirmed the close, in the
/// news that ended the call or in its final status, or its answer to this phone's stop did. The
/// cause of the end never enters. This is the one place where an end is read as confirmed or not.
pub(super) fn host_closed_the_call(word: CloseWord, host_end: &HostEnd) -> bool {
    word == CloseWord::Confirmed || host_end.confirms_closure()
}

/// What a call on the host's own key is left to, in words, when the host did not say it closed
/// it, by what this phone heard and what the stop came to; nothing when the call is closed.
/// `may_have_reached` says whether the stop may have reached the host, which a stop that was not
/// sent never did.
pub(super) fn unsettled_words(
    word: CloseWord,
    host_end: &HostEnd,
    may_have_reached: bool,
) -> Option<&'static str> {
    if host_closed_the_call(word, host_end) {
        return None;
    }
    Some(match (word, host_end) {
        // The host said it could not confirm, or answered the stop and confirmed nothing.
        (CloseWord::Unconfirmed, _) | (_, HostEnd::Revoked { .. }) => HOST_UNCONFIRMED,
        // The host was asked and said nothing of the close.
        (_, HostEnd::NotHeld { .. } | HostEnd::Refused { .. }) => HOST_UNHEARD,
        (_, HostEnd::NotTold { .. }) if may_have_reached => HOST_UNHEARD,
        // The host was not asked: its own rule about a phone it has not heard from decides.
        _ => LEFT_TO_HOST,
    })
}
