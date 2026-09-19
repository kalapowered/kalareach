//! What can go wrong, and the one place each failure is named.

/// A failure in the attention engine or its feature store.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The host holds no version of the subject a review names.
    #[error("no review subject {subject}")]
    UnknownReviewSubject {
        /// The subject, in its stored form.
        subject: String,
    },
    /// The version a review acknowledgement names is beyond the one the host holds.
    #[error("review subject {subject} is at version {current}, not {version}")]
    UnknownReviewVersion {
        /// The subject, in its stored form.
        subject: String,
        /// The version that was acknowledged.
        version: u64,
        /// The version the host holds.
        current: u64,
    },
    /// The feature store could not be read or written.
    #[error("the attention feature store is unavailable: {detail}")]
    StoreUnavailable {
        /// What the store reported.
        detail: String,
    },
    /// A stored row could not be read back as the value it was written from.
    #[error("the attention feature store holds a {field} this build cannot read")]
    StoreUnreadable {
        /// Which column.
        field: &'static str,
    },
}

/// The result of an attention operation.
pub type Result<T> = std::result::Result<T, Error>;

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::StoreUnavailable {
            detail: error.to_string(),
        }
    }
}
