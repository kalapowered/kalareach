//! What the control daemon can fail with, and the protocol code each failure is reported under.

use kr_protocol::error::{ErrorCode, ProtocolError};

/// A control-daemon failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ControllerError {
    /// The registry could not be read or written.
    #[error("the environment registry is unavailable: {detail}")]
    RegistryUnavailable {
        /// What went wrong.
        detail: String,
    },
    /// Another controller already holds this environment.
    #[error("another control daemon already owns environment {environment}")]
    AlreadyRunning {
        /// The environment.
        environment: String,
    },
    /// The environment has reached its admission limit.
    #[error("environment {environment} already has {live} of {limit} sessions")]
    SessionLimit {
        /// The environment.
        environment: String,
        /// How many sessions are live or creating.
        live: u64,
        /// The configured limit.
        limit: u64,
    },
    /// The host cannot hold another session: a resource a create needs is short.
    ///
    /// Reported before a reservation is recorded and before anything is spawned.
    #[error("this host cannot start another session, short of {resource}: {detail}")]
    ResourceShort {
        /// Which resource: `storage`, `terminals` or `processes`.
        resource: &'static str,
        /// What was found and what a create needs.
        detail: String,
    },
    /// A configuration edit was refused.
    ///
    /// An edit is validated before a revision is applied, so this is what a caller is told
    /// instead of a document that was written and then found to be wrong.
    #[error("this configuration edit was refused: {0}")]
    Configuration(String),
    /// A worker could not be started.
    #[error("could not start a worker: {detail}")]
    Supervision {
        /// What went wrong.
        detail: String,
    },
    /// A daemon was not started in the login session an earlier daemon's work still runs in.
    #[error("{detail}")]
    WorkInAnotherSession {
        /// What was found and what to do about it.
        detail: String,
    },
    /// A worker did not present a valid startup claim.
    #[error("the worker's startup claim was refused: {detail}")]
    RendezvousRefused {
        /// What went wrong.
        detail: String,
    },
    /// The named session is not in this environment.
    #[error("no session {session}")]
    UnknownSession {
        /// The identifier that was named.
        session: String,
    },
    /// The session has closed.
    #[error("session {session} has closed")]
    SessionClosed {
        /// The identifier that was named.
        session: String,
    },
    /// The managed shell integration this request asked for is not available.
    #[error("{0}")]
    ShellIntegrationUnsupported(String),
    /// The freshness window this request is bound to admits nothing here: it is unknown, belongs to
    /// another connection or boot, or has expired on the connection that issued it. A first
    /// admission is refused for it, and an exact repeat of an action this host holds a claim or a
    /// record for is answered from that instead.
    #[error("{detail}")]
    WindowExpired {
        /// What went wrong.
        detail: String,
    },
    /// A create token was reused with a different request.
    #[error("create token {token} was already used with a different request")]
    IdConflict {
        /// The token that was reused.
        token: String,
    },
    /// The caller's authority does not reach this operation.
    #[error("{detail}")]
    PermissionDenied {
        /// What went wrong.
        detail: String,
    },
    /// The method is not reachable from this caller.
    #[error("{method} is not reachable from a local caller")]
    NotListed {
        /// The method that was named.
        method: String,
    },
    /// The request is not valid.
    #[error("{0}")]
    InvalidArgument(String),
    /// A file this daemon had to read or write could not be reached.
    #[error("could not {operation}: {detail}")]
    Storage {
        /// What was being attempted.
        operation: &'static str,
        /// What went wrong.
        detail: String,
    },
    /// What became of the action is not known.
    ///
    /// Section 9 makes this its own answer rather than a failure: the intent may have been
    /// dispatched, so nothing may report it as refused and nothing may retry it automatically.
    #[error("{detail}")]
    Uncertain {
        /// What is not known.
        detail: String,
    },
    /// This host's clock cannot currently say whether something has expired.
    ///
    /// The wall clock is behind a moment this host has already recorded, by more than a
    /// correction accounts for. Section 9 does not let a host decide an expiry in the caller's
    /// favour on a clock it cannot trust.
    #[error("{detail}")]
    ClockUntrusted {
        /// What is wrong with the clock.
        detail: String,
    },
    /// A subject this daemon forwarded to refused the request, in its own words.
    ///
    /// The code is the subject's. A worker that refuses a reused action identifier with
    /// `ID_CONFLICT`, or expired authority with `PERMISSION_DENIED`, is telling the caller
    /// something section 9 gives a defined meaning; reporting all of it as an invalid argument
    /// would throw that away.
    #[error("{detail}")]
    Refused {
        /// The subject's own code.
        code: ErrorCode,
        /// The subject's own words.
        detail: String,
    },
    /// Local IPC failed.
    #[error("{0}")]
    Ipc(#[from] kr_ipc::IpcError),
    /// The directory a session works in could not be made.
    ///
    /// It is reported under the code of what failed, and says which directory it was before it
    /// says why, so that a message cut at the first path still tells a person what failed.
    #[error("the host could not make the session's directory: {0}")]
    SessionDirectory(#[source] kr_ipc::IpcError),
    /// A proof failed.
    #[error("{0}")]
    Verification(#[from] kr_ipc::verify::VerificationError),
    /// The host is not configured for this operation.
    #[error("{0}")]
    NotConfigured(String),
}

impl ControllerError {
    /// Builds a registry failure.
    pub fn registry(error: impl std::fmt::Display) -> Self {
        Self::RegistryUnavailable {
            detail: error.to_string(),
        }
    }

    /// Builds a supervision failure.
    pub fn supervision(detail: impl std::fmt::Display) -> Self {
        Self::Supervision {
            detail: detail.to_string(),
        }
    }

    /// Builds the refusal to start in a login session other than the one the environment's work
    /// runs in.
    pub fn work_in_another_session(detail: impl std::fmt::Display) -> Self {
        Self::WorkInAnotherSession {
            detail: detail.to_string(),
        }
    }

    /// Builds a refusal from what a subject answered.
    #[must_use]
    pub fn refused(error: &ProtocolError) -> Self {
        Self::Refused {
            code: error.code,
            detail: error.message.clone(),
        }
    }

    /// What a repeat of an action is told while the attempt that claimed it is still running.
    ///
    /// That attempt carries the action out, or has, so a transient word, which says nothing took
    /// effect, would be false: what became of the action is not known yet, and the caller asks
    /// again under the same identifier for the answer.
    #[must_use]
    pub fn attempt_still_running() -> Self {
        Self::Uncertain {
            detail: "another attempt under this action identifier has not finished, so what \
                     became of the action is not known yet"
                .to_owned(),
        }
    }

    /// What a repeat of an action is told when this host holds the claim of its first attempt and no
    /// record of what the attempt came to.
    ///
    /// A claim with no outcome is an attempt that is still carrying the action out, or one that
    /// ended without recording what it did, and the host cannot tell which. The action is not
    /// performed again either way. The repeat is not promised an answer now: asking again under the
    /// same action gives the record once the claim is settled, which a running attempt does when it
    /// ends, and the daemon does for a claim left unrecorded when it next starts.
    #[must_use]
    pub fn claim_without_outcome() -> Self {
        Self::Uncertain {
            detail: "this host holds the claim of an earlier attempt at this action and no record \
                     of what it came to: that attempt is still running, or it ended without \
                     recording what it did, and the host cannot tell which; the action is not \
                     performed again, and asking again under the same action gives the record \
                     once the claim is settled, which a running attempt does when it ends and \
                     this host does for an unrecorded one when it next starts"
                .to_owned(),
        }
    }

    /// What a repeat of an action is told when the record of its first attempt cannot be read.
    ///
    /// `records` names what this host keeps the record in. A record that cannot be read is not one
    /// that is absent: an earlier attempt may have carried the action out, so the repeat is neither
    /// performed nor refused for something it did not do, and the caller asks again under the same
    /// identifier for the answer once the record can be read.
    #[must_use]
    pub fn record_unreadable(records: &str) -> Self {
        Self::Uncertain {
            detail: format!(
                "this host's record of its {records} cannot be read now, so whether an earlier \
                 attempt at this action was carried out is not known; asking again under the \
                 same action says what it did once the record can be read"
            ),
        }
    }

    /// What a repeat of an action is told of the failure of the read of its first attempt's record.
    ///
    /// A store that cannot be read is [`Self::record_unreadable`]: a transient word would say that
    /// nothing took effect, and an earlier attempt may have carried the action out. Any other
    /// failure is this host's word about the action, such as a reused identifier, and is told as it
    /// is.
    #[must_use]
    pub fn found_unreadable(self, records: &str) -> Self {
        if self.code() == ErrorCode::StorageUnavailable {
            Self::record_unreadable(records)
        } else {
            self
        }
    }

    /// What an action is told when the service refused it, this host could not record the refusal,
    /// no record of the action can be read, and another copy of the action may have been performed.
    ///
    /// A refusal that cannot be written down is not told as a definite one: it can be a word about
    /// what another copy of the action did, and a client takes a definite refusal for the host's
    /// word that nothing was done. A transient word would say the same.
    #[must_use]
    pub fn refusal_not_recorded() -> ProtocolError {
        ProtocolError::new(
            ErrorCode::OutcomeUnknown,
            "this request was refused and this host could not record the refusal; whether another \
             attempt at this action was carried out is not known",
        )
    }

    /// What a repeat is told of the failure of the read of its first attempt's record, on a path
    /// that answers in wire errors.
    ///
    /// As [`Self::found_unreadable`], for a service whose own errors have already become the wire's.
    /// A reused identifier and every other word the service decided keep their codes.
    #[must_use]
    pub fn found_unreadable_on_the_wire(error: ProtocolError, records: &str) -> ProtocolError {
        if error.code == ErrorCode::StorageUnavailable {
            Self::record_unreadable(records).to_protocol_error()
        } else {
            error
        }
    }

    /// Builds a rendezvous refusal.
    pub fn rendezvous(detail: impl std::fmt::Display) -> Self {
        Self::RendezvousRefused {
            detail: detail.to_string(),
        }
    }

    /// Returns the stable protocol code this failure is reported under.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::RegistryUnavailable { .. } | Self::Storage { .. } => {
                ErrorCode::StorageUnavailable
            }
            Self::AlreadyRunning { .. } => ErrorCode::ResourceUnavailable,
            Self::SessionLimit { .. } => ErrorCode::SessionLimit,
            Self::Supervision { .. }
            | Self::WorkInAnotherSession { .. }
            | Self::ResourceShort { .. } => ErrorCode::ResourceUnavailable,
            Self::RendezvousRefused { .. } | Self::Verification(_) | Self::WindowExpired { .. } => {
                ErrorCode::PermissionDenied
            }
            Self::UnknownSession { .. } => ErrorCode::UnknownSession,
            Self::SessionClosed { .. } => ErrorCode::SessionClosed,
            Self::IdConflict { .. } => ErrorCode::IdConflict,
            Self::NotListed { .. } | Self::PermissionDenied { .. } => ErrorCode::PermissionDenied,
            Self::InvalidArgument(_) | Self::Configuration(_) => ErrorCode::InvalidArgument,
            Self::Uncertain { .. } => ErrorCode::OutcomeUnknown,
            Self::ClockUntrusted { .. } => ErrorCode::ClockUntrusted,
            Self::Refused { code, .. } => *code,
            Self::ShellIntegrationUnsupported(_) => ErrorCode::ShellIntegrationUnsupported,
            Self::Ipc(error) | Self::SessionDirectory(error) => error.code(),
            Self::NotConfigured(_) => ErrorCode::HostNotConfigured,
        }
    }

    /// Renders the failure as a protocol error a client can be given.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        ProtocolError::new(self.code(), self.to_string())
    }
}

/// The result of a control-daemon operation.
pub type Result<T> = std::result::Result<T, ControllerError>;
