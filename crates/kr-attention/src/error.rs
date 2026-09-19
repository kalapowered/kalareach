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
    /// One more actor than this session's feature store admits.
    #[error("this session's attention store holds {bound} actors, which is its bound")]
    TooManyActors {
        /// The bound.
        bound: usize,
    },
    /// A page continues after a key that is no longer in the inbox it was read from.
    #[error("the inbox no longer holds {key}, so a page cannot continue after it")]
    UnknownContinuation {
        /// The key the page named.
        key: String,
    },
    /// The feature store could not be read or written.
    #[error("the attention feature store is unavailable ({kind}): {detail}")]
    StoreUnavailable {
        /// What kind of failure it was, classified from the store's own result code.
        kind: StoreFault,
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

/// What kind of failure the feature store reported.
///
/// It is classified from the store's own result code rather than from the text of its message, for
/// the same reason the session journal classifies its own: a message is prose and a code is a
/// fact, and a caller deciding what to do about a full disk cannot be reading English to find out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreFault {
    /// There is no room left for the write.
    Full,
    /// The stored pages do not check out.
    Corrupt,
    /// The file is not a store of this kind at all.
    NotAStore,
    /// Anything else, including an ordinary input or output failure.
    Other,
}

impl core::fmt::Display for StoreFault {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Full => "full",
            Self::Corrupt => "corrupt",
            Self::NotAStore => "not a store",
            Self::Other => "other",
        })
    }
}

/// The result of an attention operation.
pub type Result<T> = std::result::Result<T, Error>;

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        let kind = match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DiskFull) => StoreFault::Full,
            Some(rusqlite::ErrorCode::DatabaseCorrupt) => StoreFault::Corrupt,
            Some(rusqlite::ErrorCode::NotADatabase) => StoreFault::NotAStore,
            _ => StoreFault::Other,
        };
        Self::StoreUnavailable {
            kind,
            detail: error.to_string(),
        }
    }
}
