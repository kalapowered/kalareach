//! Why a release tree is not assembled, checked or signed, and the small helpers its checks share.

use std::fmt::Write as _;
use std::path::Path;

use kr_protocol::scalars::Digest256;
use sha2::{Digest as _, Sha256};

/// A refusal to assemble, check or sign a release, in words a person building one can act on.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Refusal(pub String);

/// The result of a step that can refuse.
pub type Result<T> = std::result::Result<T, Refusal>;

/// Refuses with a message, which is the step's result.
macro_rules! refuse {
    ($($argument:tt)*) => {
        return Err($crate::refusal::Refusal(format!($($argument)*)))
    };
}
pub(crate) use refuse;

/// The refusal for a file or directory that could not be read.
pub(crate) fn unreadable(path: &Path, error: &std::io::Error) -> Refusal {
    Refusal(format!("{} cannot be read: {error}", path.display()))
}

/// Reads a whole file.
pub(crate) fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| unreadable(path, &error))
}

/// Reads a whole file as text.
pub(crate) fn read_text(path: &Path) -> Result<String> {
    String::from_utf8(read(path)?).map_err(|_| Refusal(format!("{} is not text", path.display())))
}

/// Reads a JSON document.
pub(crate) fn read_json(path: &Path) -> Result<serde_json::Value> {
    serde_json::from_slice(&read(path)?)
        .map_err(|error| Refusal(format!("{} is not JSON: {error}", path.display())))
}

/// The SHA-256 digest of some bytes.
pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The SHA-256 digest of a file, read once.
pub(crate) fn digest_file(path: &Path) -> Result<[u8; 32]> {
    Ok(digest(&read(path)?))
}

/// Lower-case hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// A digest written as 64 lower-case hexadecimal digits.
pub(crate) fn digest_from_hex(text: &str) -> Result<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        refuse!("`{text}` is not a SHA-256 digest");
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in bytes.chunks(2).enumerate() {
        let high = nibble(pair[0]);
        let low = nibble(pair[1]);
        match (high, low) {
            (Some(high), Some(low)) => digest[index] = high << 4 | low,
            _ => refuse!("`{text}` is not a SHA-256 digest"),
        }
    }
    Ok(digest)
}

const fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// A digest as the manifest writes it.
pub(crate) const fn scalar(digest: [u8; 32]) -> Digest256 {
    Digest256::from_bytes(digest)
}
