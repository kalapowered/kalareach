//! Resource limits checked before any allocation.
//!
//! Section 23 requires object depth, count and length limits to apply *before* allocation. The
//! decoder therefore validates a declared length against both the configured limit and the number
//! of bytes actually left in the input before it reserves any capacity.

/// Configured bounds for one decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum length of the complete encoded message.
    pub max_message_len: usize,
    /// Maximum nesting depth. A top-level scalar has depth 1.
    pub max_depth: usize,
    /// Maximum number of values in the whole message, counting every scalar, array, map and key.
    pub max_items: usize,
    /// Maximum number of members in one array or map.
    pub max_collection_len: usize,
    /// Maximum length in bytes of one byte string.
    pub max_bytes_len: usize,
    /// Maximum length in bytes of one text string.
    pub max_text_len: usize,
}

impl Limits {
    /// Default bounds: 1 MiB message, depth 32, 65 536 items, 4 096 members, 1 MiB strings.
    ///
    /// The message bound matches the protocol's 1 MiB control-frame limit (section 9). Callers
    /// that frame smaller or larger payloads override `max_message_len` and the string bounds.
    pub const DEFAULT: Self = Self {
        max_message_len: 1 << 20,
        max_depth: 32,
        max_items: 65_536,
        max_collection_len: 4_096,
        max_bytes_len: 1 << 20,
        max_text_len: 1 << 20,
    };

    /// Returns the default bounds with `max_message_len` replaced.
    #[must_use]
    pub const fn with_max_message_len(mut self, max_message_len: usize) -> Self {
        self.max_message_len = max_message_len;
        self
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
