//! Byte spans in the session's output stream, and the storage that keeps original bytes.
//!
//! Section 8 requires the lexer to retain original byte spans. Spans are absolute offsets into the
//! session's output stream, so they stay meaningful across the arbitrary read boundaries a PTY
//! hands us and they name the same positions as the monotonically increasing output cursor used by
//! snapshots and deltas.

use core::fmt;

/// Bytes kept inline when a sequence is short enough, on the heap otherwise.
const INLINE: usize = 32;

/// A half-open range of the session output stream.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSpan {
    start: u64,
    end: u64,
}

impl ByteSpan {
    /// Builds a span from its absolute start offset and length.
    #[must_use]
    pub const fn new(start: u64, len: u64) -> Self {
        Self {
            start,
            end: start.saturating_add(len),
        }
    }

    /// Absolute offset of the first byte.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Absolute offset one past the last byte.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Number of bytes covered.
    #[must_use]
    pub const fn len(self) -> u64 {
        self.end - self.start
    }

    /// Whether the span covers no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// Whether `other` starts exactly where this span ends.
    #[must_use]
    pub const fn adjoins(self, other: Self) -> bool {
        self.end == other.start
    }

    /// Joins two adjoining spans.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        Self {
            start: self.start,
            end: other.end,
        }
    }
}

impl fmt::Debug for ByteSpan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

/// The original bytes of one lexed sequence.
///
/// A control sequence is almost always shorter than [`INLINE`] bytes, so the common case costs no
/// allocation; a long text run or a long control string spills to the heap. The distinction is
/// invisible through [`AsRef`].
#[derive(Clone, PartialEq, Eq)]
pub enum SeqBytes {
    /// Short content held inline.
    Inline {
        /// The fixed-size buffer; only the first `len` bytes are meaningful.
        buf: [u8; INLINE],
        /// Number of meaningful bytes.
        len: u8,
    },
    /// Longer content held on the heap.
    Heap(Vec<u8>),
}

impl SeqBytes {
    /// An empty byte string.
    #[must_use]
    pub const fn empty() -> Self {
        Self::Inline {
            buf: [0; INLINE],
            len: 0,
        }
    }

    /// Copies `bytes` into inline or heap storage.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        if bytes.len() <= INLINE {
            let mut buf = [0u8; INLINE];
            buf[..bytes.len()].copy_from_slice(bytes);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the branch guarantees bytes.len() <= INLINE, which is 32"
            )]
            Self::Inline {
                buf,
                len: bytes.len() as u8,
            }
        } else {
            Self::Heap(bytes.to_vec())
        }
    }

    /// Takes ownership of an existing buffer without copying when it is long.
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        if bytes.len() <= INLINE {
            Self::new(&bytes)
        } else {
            Self::Heap(bytes)
        }
    }

    /// Number of bytes held.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Inline { len, .. } => usize::from(*len),
            Self::Heap(v) => v.len(),
        }
    }

    /// Whether no bytes are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AsRef<[u8]> for SeqBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Inline { buf, len } => &buf[..usize::from(*len)],
            Self::Heap(v) => v.as_slice(),
        }
    }
}

impl fmt::Debug for SeqBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", EscapedBytes(self.as_ref()))
    }
}

/// Wraps a byte slice so `{:?}` prints control bytes as readable escapes.
pub struct EscapedBytes<'a>(pub &'a [u8]);

impl fmt::Debug for EscapedBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;
        for &b in self.0 {
            match b {
                0x1b => f.write_str("\\e")?,
                b'\n' => f.write_str("\\n")?,
                b'\r' => f.write_str("\\r")?,
                b'\t' => f.write_str("\\t")?,
                b'"' => f.write_str("\\\"")?,
                b'\\' => f.write_str("\\\\")?,
                0x20..=0x7e => fmt::Write::write_char(f, char::from(b))?,
                other => write!(f, "\\x{other:02x}")?,
            }
        }
        f.write_str("\"")
    }
}
