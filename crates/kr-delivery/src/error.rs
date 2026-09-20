//! What this crate fails with, and what each failure tells a caller to do next.

/// What went wrong.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    /// The delivery journal could not be read or written.
    ///
    /// Section 24 refuses a durable mutation before dispatch rather than dispatching without a
    /// record of it, so this stops a send rather than being logged past.
    #[error("the delivery journal is unavailable: {0}")]
    JournalUnavailable(String),
    /// The journal holds a value this build cannot read.
    ///
    /// It is separate from unavailable because the two lead to opposite conclusions: an
    /// unavailable store may work on the next call, and a store this build cannot read will not.
    #[error("the delivery journal holds something this build cannot read: {0}")]
    JournalUnreadable(&'static str),
    /// A notification was offered for an underlying event this journal has not taken.
    ///
    /// Section 16 writes the underlying event first. A producer that reaches this has tried to
    /// send beside the event rather than from it.
    #[error("no underlying event named {0} has been taken, so nothing can be produced from it")]
    NoUnderlyingEvent(String),
    /// The destination is not configured, or is configured and not enabled.
    #[error("no enabled destination named {0}")]
    NoDestination(String),
    /// The destination has no explicit rule or grant admitting this content.
    ///
    /// Section 25 requires a configured destination **and** an explicit rule or grant before
    /// content leaves. Configuration alone is not authority.
    #[error("{0} has no explicit rule or grant admitting this content")]
    NotAuthorised(String),
    /// The preview plaintext is over section 16's 1,800-byte bound.
    #[error(
        "a preview carries {actual} bytes of text and inner metadata, over the {limit}-byte bound"
    )]
    PreviewTooLarge {
        /// The bound, in bytes.
        limit: u64,
        /// What was offered, in bytes.
        actual: u64,
    },
    /// The built provider payload is at or over section 16's 3,500-byte bound.
    ///
    /// It is measured after encryption and base64 rather than estimated from an expansion ratio,
    /// and the excess moves to a referenced encrypted object.
    #[error("a provider payload of {actual} bytes is not below the {limit}-byte bound")]
    PayloadTooLarge {
        /// The bound, in bytes.
        limit: u64,
        /// What the built payload measured, in bytes.
        actual: u64,
    },
    /// The expiry is absent, already past, or further ahead than the gateway admits.
    #[error("{0}")]
    Expiry(&'static str),
    /// The destination has no usable `notification_preview` key.
    #[error("{0}")]
    NoPreviewKey(&'static str),
    /// Sealing or opening a preview failed.
    #[error("a notification preview could not be sealed: {0}")]
    Crypto(#[from] kr_crypto::CryptoError),
    /// A value could not be represented in KR-CBOR-1.
    #[error("a delivery record could not be encoded: {0}")]
    Encoding(String),
    /// A source this producer consumes could not be read or acknowledged.
    ///
    /// The attention store and a worker's journal are other crates' stores. A failure in one of
    /// them stops this pass rather than being absorbed: an announcement that was taken and not
    /// settled is offered again, and that is the behaviour the sources are built for.
    #[error("a delivery source could not be read: {0}")]
    Source(String),
    /// Privacy mode is fencing this environment's content-bearing outboxes.
    ///
    /// Section 24 fences them *at once*, so a send offered after the fence is refused rather than
    /// queued behind it.
    #[error("privacy mode has fenced this environment's delivery outbox")]
    Fenced,
    /// A result was produced under a generation that is not the one in force.
    #[error(
        "a result produced under generation {produced_under} is not publishable under {in_force}"
    )]
    LateResult {
        /// The generation the result was produced under.
        produced_under: u64,
        /// The generation in force now.
        in_force: u64,
    },
}

/// What this crate returns.
pub type Result<T> = std::result::Result<T, DeliveryError>;

impl DeliveryError {
    /// True when this error represents a transient storage or source disruption
    /// rather than a permanent refusal of the notification.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::JournalUnavailable(_) | Self::Source(_))
    }
}

impl From<rusqlite::Error> for DeliveryError {
    fn from(error: rusqlite::Error) -> Self {
        Self::JournalUnavailable(error.to_string())
    }
}

impl From<kr_cbor::CborError> for DeliveryError {
    fn from(error: kr_cbor::CborError) -> Self {
        Self::Encoding(error.to_string())
    }
}
