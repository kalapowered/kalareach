//! What local IPC can fail with, and how each failure reaches a client.
//!
//! Every variant maps to one stable protocol error code. The mapping lives here so a caller never
//! invents a code for a condition the transport already names.

use std::path::PathBuf;

use kr_protocol::error::{ErrorCode, ProtocolError};

/// A local IPC failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IpcError {
    /// A directory or file operation failed.
    #[error("{operation} {path}: {source}")]
    Io {
        /// What was being attempted.
        operation: &'static str,
        /// The path involved.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A socket operation failed.
    #[error("{operation}: {source}")]
    Socket {
        /// What was being attempted.
        operation: &'static str,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A directory that must be owner-only was not.
    #[error(
        "{path} must be owned by user {expected_uid} with mode 0700, found owner {found_uid} and mode {found_mode:04o}"
    )]
    DirectoryNotOwnerOnly {
        /// The directory.
        path: PathBuf,
        /// The user that must own it.
        expected_uid: u32,
        /// The user that does own it.
        found_uid: u32,
        /// The permission bits it carries.
        found_mode: u32,
    },
    /// A computed socket path exceeded what the platform's address family allows.
    #[error("socket path {path} is {len} bytes, over the {limit}-byte platform limit")]
    SocketPathTooLong {
        /// The path.
        path: PathBuf,
        /// Its length in bytes.
        len: usize,
        /// The platform limit.
        limit: usize,
    },
    /// The connecting process is not the user this endpoint belongs to.
    #[error("peer user {peer_uid} may not use an endpoint owned by user {owner_uid}")]
    PeerRejected {
        /// The user that connected.
        peer_uid: u32,
        /// The user that owns the endpoint.
        owner_uid: u32,
    },
    /// The platform could not report the peer's credentials, so the caller is unauthenticated.
    #[error("the operating system did not report the peer's credentials: {source}")]
    PeerUnknown {
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A frame was larger than its stream permits, malformed, or not canonical.
    #[error("frame: {0}")]
    Frame(#[from] kr_protocol::frame::FrameError),
    /// The peer closed the connection.
    #[error("the peer closed the connection")]
    PeerClosed,
    /// The peer sent a message the endpoint's role does not accept.
    #[error("unexpected message: {0}")]
    UnexpectedMessage(&'static str),
    /// Version negotiation failed.
    #[error("no shared protocol major: this host speaks {host}, the peer offered {offered}")]
    VersionMismatch {
        /// What this host speaks.
        host: String,
        /// What the peer offered.
        offered: String,
    },
    /// Two environments whose identities share a directory prefix tried to use one directory.
    #[error("{path} belongs to environment {holder}, not {requested}")]
    EnvironmentPrefixCollision {
        /// The directory.
        path: PathBuf,
        /// The environment that owns it.
        holder: String,
        /// The environment that asked for it.
        requested: String,
    },
    /// The stream ended part way through a frame.
    #[error("the stream ended after {received} of {expected} bytes of a frame")]
    TruncatedFrame {
        /// Bytes received.
        received: usize,
        /// Bytes the frame declared.
        expected: usize,
    },
    /// A published file is not one this host may act on.
    #[error("{path}: {reason}")]
    UntrustedFile {
        /// The file.
        path: PathBuf,
        /// Why it is not trustworthy.
        reason: &'static str,
    },
    /// A host identity could not be read from the operating system.
    #[error("{what}: {detail}")]
    IdentityUnavailable {
        /// Which identity.
        what: &'static str,
        /// Why it could not be read.
        detail: String,
    },
}

impl IpcError {
    /// Builds a filesystem failure.
    pub fn io(operation: &'static str, path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    /// Builds a socket failure.
    #[must_use]
    pub const fn socket(operation: &'static str, source: std::io::Error) -> Self {
        Self::Socket { operation, source }
    }

    /// Returns the stable protocol code this failure is reported under.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Io { .. } | Self::Socket { .. } | Self::IdentityUnavailable { .. } => {
                ErrorCode::ResourceUnavailable
            }
            Self::DirectoryNotOwnerOnly { .. }
            | Self::PeerRejected { .. }
            | Self::UntrustedFile { .. } => ErrorCode::PermissionDenied,
            Self::EnvironmentPrefixCollision { .. } => ErrorCode::EnvironmentUnavailable,
            Self::PeerUnknown { .. } => ErrorCode::PermissionDenied,
            Self::SocketPathTooLong { .. } => ErrorCode::HostNotConfigured,
            Self::Frame(_) | Self::UnexpectedMessage(_) | Self::TruncatedFrame { .. } => {
                ErrorCode::InvalidArgument
            }
            Self::PeerClosed => ErrorCode::ResourceUnavailable,
            Self::VersionMismatch { .. } => ErrorCode::UnsupportedSchema,
        }
    }

    /// Renders the failure as a protocol error a client can be given.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        ProtocolError::new(self.code(), self.to_string())
    }
}

/// The result of a local IPC operation.
pub type Result<T> = std::result::Result<T, IpcError>;
