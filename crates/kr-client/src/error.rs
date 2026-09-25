//! What can go wrong for a client.

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::method::{Method, MethodVersion};

use crate::retry::{Decision, Failure, RequestClass, UserAction};
use crate::shown::{Said, Shown};

/// A client failure.
///
/// What it says is a [`Shown`], so no rendering of it carries what a host, a service or a file
/// sent: [`Said`] is its `Display` and its `Debug`. Four variants hold another crate's value,
/// because other crates build them and match on what is inside ([`Self::Transport`],
/// [`Self::Ipc`], [`Self::Host`] and [`Self::Refused`]); each is rendered through its reducer or
/// door and none is this error's `source()`, so a logger that walks a source chain meets only what
/// this rendering says.
#[non_exhaustive]
pub enum ClientError {
    /// The transport failed.
    Transport(kr_transport::TransportError),
    /// The local socket or named pipe failed.
    Ipc(kr_ipc::IpcError),
    /// The host answered with an error.
    Host(ProtocolError),
    /// A managed service refused the request.
    ///
    /// The refusal is the protocol error a caller branches on, and the delay beside it is what the
    /// service asked for, in seconds, when it said. It is separate from [`Self::Host`] for two
    /// reasons. Honouring a stated delay is the difference between backing off and being refused
    /// again, and a delay inside a message is a delay nothing can act on. And a service knows more
    /// about its own refusal than the required code set can carry: section 23 has one
    /// `PERMISSION_DENIED`, and a service uses it both for a caller that is not signed in and for
    /// an account that may not do this, so it says which by carrying the action. A service refusal
    /// is therefore this variant whether or not it named a delay.
    Refused {
        /// What the service said was wrong.
        error: ProtocolError,
        /// Seconds to wait before sending the same request again, when the service said.
        retry_after_seconds: Option<u64>,
        /// What a person does about it.
        ///
        /// The service classifies its own refusal, because it is the only thing that can. Section
        /// 23's required codes have one `PERMISSION_DENIED`, and a service uses it both for a
        /// caller that is not signed in and for an account that may not do this; the code cannot
        /// carry the difference and the service already knows it.
        action: UserAction,
    },
    /// A value could not be encoded or decoded as KR-CBOR-1.
    ///
    /// It holds what [`Shown::cbor`] says of the failure, which is how every KR-CBOR-1 failure
    /// becomes this: the conversion reduces it, so `?` cannot carry a decoder's own words.
    Cbor(Shown),
    /// The method's registry entry forbids this call shape.
    WrongEffect {
        /// The method that was called.
        method: Method,
        /// What the registry says it is.
        expected: &'static str,
        /// How it was called.
        actual: &'static str,
    },
    /// This build does not implement the method at that version.
    UnsupportedVersion {
        /// The method that was called.
        method: Method,
        /// The version this build implements.
        supported: MethodVersion,
        /// The version that was asked for.
        requested: MethodVersion,
    },
    /// The connection already has as many outstanding mutations as it is allowed.
    TooManyOutstandingMutations {
        /// The negotiated bound.
        limit: usize,
    },
    /// This client already holds as many unresolved actions as it will track.
    ///
    /// An unresolved action is never forgotten, so a client that cannot reach its host eventually
    /// stops submitting rather than accumulating uncertainty without bound.
    TooManyUnresolvedActions {
        /// The bound.
        limit: usize,
    },
    /// The host has not issued an action window for this connection.
    NoActionWindow,
    /// The connection ended before the request was answered.
    ConnectionEnded,
    /// The connection ended after a mutation was sent, so its outcome is unknown.
    ///
    /// The action identifier is named because section 9 forbids dispatching it again: the client
    /// asks the host what became of this action, and shows the user that the outcome is uncertain.
    /// It never submits the same intent under a new identifier to find out.
    SubmissionUncertain {
        /// The action whose outcome is unknown.
        action_id: kr_protocol::ids::ActionId,
    },
    /// The host requires a fresh snapshot before it will serve this stream again.
    ResyncRequired,
    /// No implementation of a managed service is configured.
    ServiceNotConfigured(&'static str),
    /// This device's draft store refused.
    ///
    /// Boxed because it carries a path and an operating-system failure, which would otherwise make
    /// every client failure as large as the largest one.
    Draft(Box<crate::drafts::DraftError>),
}

impl ClientError {
    /// Returns the stable code a caller reacts to.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Host(error) | Self::Refused { error, .. } => error.code,
            Self::Transport(error) => error.to_protocol_error().code,
            Self::Ipc(error) => error.to_protocol_error().code,
            Self::Cbor(_) | Self::WrongEffect { .. } => ErrorCode::InvalidArgument,
            Self::UnsupportedVersion { .. } => ErrorCode::UnsupportedSchema,
            Self::TooManyOutstandingMutations { .. }
            | Self::TooManyUnresolvedActions { .. }
            | Self::NoActionWindow => ErrorCode::ResourceUnavailable,
            Self::ConnectionEnded => ErrorCode::ResourceUnavailable,
            Self::SubmissionUncertain { .. } => ErrorCode::OutcomeUnknown,
            Self::ResyncRequired => ErrorCode::ResyncRequired,
            Self::ServiceNotConfigured(_) => ErrorCode::HostNotConfigured,
            Self::Draft(error) => error.code(),
        }
    }

    /// Returns what the retry policy makes of this failure for a request of `class`.
    ///
    /// This is how a caller reaches the policy for everything the library does not retry itself:
    /// the recovery step, and the direct action a user interface offers instead of the code. The
    /// action is [`Self::user_action`]'s, so a caller reading the decision and a caller reading the
    /// action are told the same thing.
    #[must_use]
    pub fn decision(&self, class: RequestClass) -> Decision {
        let retry_after = match self {
            Self::Refused {
                retry_after_seconds,
                ..
            } => retry_after_seconds.map(std::time::Duration::from_secs),
            _ => None,
        };
        let mut decision = crate::retry::decision(
            Failure {
                code: self.code(),
                retry_after,
            },
            class,
        );
        decision.action = self.user_action();
        decision
    }

    /// Returns the direct action a user interface offers for this failure.
    ///
    /// Section 23: the interface translates a code into a direct action and does not display raw
    /// protocol internals by default. The plain message is still there for a log or a details view.
    ///
    /// Most failures are translated by the code alone. The two that are not are the ones whose
    /// refuser knows more than its code can say: a managed service classifies its own refusal, and
    /// this device's draft store has its own answers, because a draft that will not fit is not a
    /// reason to update the application.
    #[must_use]
    pub fn user_action(&self) -> UserAction {
        match self {
            Self::Refused { action, .. } => *action,
            Self::Draft(error) => error.user_action(),
            other => crate::retry::user_action(other.code()),
        }
    }
}

impl From<ProtocolError> for ClientError {
    fn from(error: ProtocolError) -> Self {
        if error.code == ErrorCode::ResyncRequired {
            Self::ResyncRequired
        } else {
            Self::Host(error)
        }
    }
}

impl From<kr_transport::TransportError> for ClientError {
    fn from(error: kr_transport::TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<kr_ipc::IpcError> for ClientError {
    fn from(error: kr_ipc::IpcError) -> Self {
        Self::Ipc(error)
    }
}

/// A KR-CBOR-1 failure becomes what [`Shown::cbor`] says of it, and nothing else of it is kept.
impl From<kr_cbor::CborError> for ClientError {
    fn from(error: kr_cbor::CborError) -> Self {
        Self::Cbor(Shown::cbor(&error))
    }
}

impl Said for ClientError {
    fn said(&self) -> Shown {
        match self {
            Self::Transport(error) => Shown::transport(error),
            Self::Ipc(error) => Shown::ipc(error),
            Self::Host(error) => crate::shown!("{}: {}", error.code, Shown::protocol(error)),
            Self::Refused {
                error,
                retry_after_seconds,
                ..
            } => match retry_after_seconds {
                Some(seconds) => crate::shown!(
                    "{}: {} (retry after {}s)",
                    error.code,
                    Shown::protocol(error),
                    *seconds
                ),
                None => crate::shown!("{}: {}", error.code, Shown::protocol(error)),
            },
            Self::Cbor(fault) => crate::shown!("the message was not canonical: {}", *fault),
            Self::WrongEffect {
                method,
                expected,
                actual,
            } => crate::shown!(
                "{} is a {} and cannot be called as a {}",
                *method,
                *expected,
                *actual
            ),
            Self::UnsupportedVersion {
                method,
                supported,
                requested,
            } => crate::shown!("{} is version {}, not {}", *method, *supported, *requested),
            Self::TooManyOutstandingMutations { limit } => {
                crate::shown!("{} mutations are already outstanding", *limit)
            }
            Self::TooManyUnresolvedActions { limit } => {
                crate::shown!("{} actions are already unresolved", *limit)
            }
            Self::NoActionWindow => Shown::said("no action window is current"),
            Self::ConnectionEnded => {
                Shown::said("the connection ended before the request was answered")
            }
            Self::SubmissionUncertain { action_id } => crate::shown!(
                "the outcome of action {} is unknown: the connection ended after it was sent",
                *action_id
            ),
            Self::ResyncRequired => Shown::said("the host requires a resynchronisation"),
            Self::ServiceNotConfigured(what) => {
                crate::shown!("no managed service is configured for {}", *what)
            }
            Self::Draft(error) => crate::shown!("{}", **error),
        }
    }
}

crate::display_as_said!(ClientError);
crate::debug_as_display!(ClientError);

/// No variant is this error's `source()`: what each says is in its own rendering, and the values
/// three of them hold are another crate's, whose own rendering is what this one exists to keep
/// out of a log.
impl std::error::Error for ClientError {}

/// A refusal this library makes itself, with the code a caller reacts to and what it says.
///
/// The one place a protocol error is built from text in this library and the command line, so the
/// message of every refusal either crate makes is a [`Shown`].
#[must_use]
pub fn refusal(code: ErrorCode, message: Shown) -> ProtocolError {
    ProtocolError::new(code, message.into_string())
}

impl ClientError {
    /// A refusal this library makes itself, as a client failure.
    #[must_use]
    pub fn refusal(code: ErrorCode, message: Shown) -> Self {
        Self::Host(refusal(code, message))
    }
}

/// The result of a client operation.
pub type Result<T> = std::result::Result<T, ClientError>;
