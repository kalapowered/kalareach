//! Why a call ends, and what a person is told about it.

use kr_client::services::voice_control::ControlEnd;

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
    /// The control ended.
    Control(ControlEnd),
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

    /// Whether the voice service closed the call itself, so asking it to again is not needed.
    pub const fn service_closed(&self) -> bool {
        matches!(self, Self::Control(ControlEnd::Closed { .. }))
    }
}
