//! What the pure modules answer when they refuse: the kind of refusal a client sees, the name of
//! the rule that refused and a short text for a person.
//!
//! The text is printable ASCII of at most [`MAX_DETAIL_BYTES`] bytes. A module that has to name
//! something a repository supplied, such as a configuration key, cuts and cleans it first; a module
//! that scans files names the rule and never what the file held.

use std::fmt;

use crate::frame::invocation::{InvocationReply, MAX_DETAIL_BYTES, RefusedKind, printable};

/// A refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// What the client is told the refusal is about.
    pub kind: RefusedKind,
    /// The rule that refused, a stable name for cases and documents.
    pub rule: &'static str,
    detail: String,
}

impl Refusal {
    /// A refusal. The detail is made printable and cut to [`MAX_DETAIL_BYTES`].
    #[must_use]
    pub fn new(kind: RefusedKind, rule: &'static str, detail: &str) -> Self {
        Self {
            kind,
            rule,
            detail: printable(detail, MAX_DETAIL_BYTES),
        }
    }

    /// The text for a person.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// The reply that carries this refusal to the client.
    #[must_use]
    pub fn into_reply(self) -> InvocationReply {
        InvocationReply::Refused {
            kind: self.kind,
            detail: self.detail,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for Refusal {}
