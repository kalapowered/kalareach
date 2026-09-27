//! What protects the weights: a downloaded file is used only when it is the file its signed
//! profile records.
//!
//! The profile names the size and the SHA-256 of every file it needs. [`verify_file`] reads both
//! from one open handle and refuses on either, and a download that does not match is not used.
//! That is the check that stands between this product and a substituted model, and it is the same
//! check whatever the profile came from.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use kr_describe::error::{DescribeError, Result};
use kr_describe::profile::Asset;
use sha2::{Digest, Sha256};

/// How many bytes an asset digest reads at a time.
///
/// A model file is gigabytes. It is hashed in fixed blocks so verifying one costs a buffer rather
/// than the file, on the 8 GiB host section 22 keeps supporting.
const DIGEST_BLOCK_BYTES: usize = 1 << 20;

/// Verifies a downloaded file against the asset's recorded size and digest.
///
/// The file is opened once and both the size and the digest come from that one handle, so there
/// is no window in which the name could be made to reach a different file between the two
/// questions. Neither answer is a warning: a file that fails either is not the file the profile
/// was qualified against, and nothing loads it.
///
/// What this cannot do is hand the caller the handle it verified, so a loader that opens the path
/// again is trusting that nothing replaced the file in between. Where the cache is the owner's own
/// directory that is the trust the cache already needs.
///
/// # Errors
///
/// Returns [`DescribeError::AssetSizeMismatch`] or [`DescribeError::AssetDigestMismatch`] when the
/// file is not the recorded one, and [`DescribeError::AssetUnreadable`] when it cannot be read at
/// all.
pub fn verify_file(asset: &Asset, path: &Path) -> Result<()> {
    verify_file_unless(asset, path, || false).map(|_| ())
}

/// Verifies a downloaded file as [`verify_file`] does, stopping between blocks when `stop` says to.
///
/// It answers `Ok(false)` when it stopped, having decided nothing about the file. A load that is
/// cancelled while its weights are being checked stops within one block rather than after
/// gigabytes.
///
/// # Errors
///
/// As [`verify_file`].
pub fn verify_file_unless(asset: &Asset, path: &Path, stop: impl Fn() -> bool) -> Result<bool> {
    let unreadable = |error: std::io::Error| DescribeError::AssetUnreadable {
        file: asset.file_name.clone(),
        detail: error.to_string(),
    };
    let mut file = File::open(path).map_err(unreadable)?;
    let found_bytes = file.metadata().map_err(unreadable)?.len();
    if found_bytes != asset.bytes {
        return Err(DescribeError::AssetSizeMismatch {
            file: asset.file_name.clone(),
            expected: asset.bytes,
            found: found_bytes,
        });
    }
    let mut hasher = Sha256::new();
    let mut block = vec![0_u8; DIGEST_BLOCK_BYTES];
    loop {
        if stop() {
            return Ok(false);
        }
        let read = file.read(&mut block).map_err(unreadable)?;
        if read == 0 {
            break;
        }
        hasher.update(&block[..read]);
    }
    let found = hex_of(&hasher.finalize());
    if found != asset.sha256 {
        return Err(DescribeError::AssetDigestMismatch {
            file: asset.file_name.clone(),
            expected: asset.sha256.clone(),
            found,
        });
    }
    Ok(true)
}

/// Renders bytes as lowercase hexadecimal, which is how a profile records a digest.
fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}
