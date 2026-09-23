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
    /// One more actor than this feature store admits.
    #[error("this attention store holds {bound} actors, which is its bound")]
    TooManyActors {
        /// The bound.
        bound: usize,
    },
    /// A page continues after a key or subject this caller cannot be shown.
    ///
    /// One the store no longer holds and one outside the caller's scope are answered alike, so a
    /// continuation cannot be used to find out what exists beyond what a caller may see.
    #[error("{key} is not one this caller holds, so a page cannot continue after it")]
    UnknownContinuation {
        /// The key the page named.
        key: String,
    },
    /// An acknowledgement named a revision the item has not reached.
    ///
    /// Revisions come from the host and only go forward, so a caller cannot have seen one past the
    /// item's own. The whole acknowledgement is refused before anything is written.
    #[error("{key} is at revision {current}, not {revision}")]
    RevisionAhead {
        /// The item's key.
        key: String,
        /// The revision the caller named.
        revision: u64,
        /// The revision the item is at.
        current: u64,
    },
    /// An action identifier was used again with a different request.
    #[error("action {action} was already used with a different request")]
    ActionConflict {
        /// The action identifier.
        action: String,
    },
    /// Another live owner already holds this feature store.
    #[error("process {process} holds this attention feature store")]
    StoreHeld {
        /// The process whose claim stands.
        process: u64,
    },
    /// The claim this owner writes under is no longer the one on the store.
    ///
    /// Its state is what it held before the store was taken, and writing that back would replace
    /// whatever the owner that took it has done since. It writes no more, and the store is read
    /// again by whoever opens it next.
    #[error("this attention feature store is no longer this owner's to write")]
    StoreTaken,
    /// More than one name reaches the file this feature store is in.
    ///
    /// A database is journalled under the name it was opened by, so one file with two names can be
    /// journalled twice over by two processes that never see each other's work.
    #[error(
        "{names} names reach this attention feature store's file, and one is the most it can have"
    )]
    StoreAliased {
        /// How many names reach the file.
        names: u64,
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
