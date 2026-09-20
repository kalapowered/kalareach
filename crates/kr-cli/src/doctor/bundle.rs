//! The support bundle `kr doctor --bundle` writes.
//!
//! Section 26: "Support bundles show software versions, capabilities and redacted errors. A user
//! explicitly selects any content-bearing diagnostic export." Both halves are here.
//!
//! * The bundle itself carries the software versions, the capability evidence, the diagnostics and
//!   the effective configuration. Every one of those is redacted on the way in by
//!   [`kr_protocol::hostinfo::SupportBundle::new`], so a credential in a path, a command line or a
//!   library's error message does not reach the file.
//! * Nothing content-bearing is in it. Terminal output, prompts, attachment filenames, shell
//!   command lines and working directories arrive only through [`Content`], which exists only when
//!   the person gave `--include-content` on the command line. That flag is the explicit selection
//!   section 26 asks for, and [`Content::describe`] is what the command prints before it writes
//!   anything, so the person sees what they selected while they can still stop.
//!
//! # The archive
//!
//! One uncompressed POSIX `ustar` archive, which `tar -tf` lists and every archiver opens. It is
//! built in memory and written owner-only in one atomic replacement, because a bundle half-written
//! into a path a person is about to attach to a message is worse than no bundle.

use std::path::Path;

use kr_protocol::hostinfo::{ContentExport, SupportBundle};

use crate::error::{CliError, Result};

/// The manifest inside every bundle.
pub const MANIFEST: &str = "manifest.json";

/// The readable diagnostics inside every bundle.
pub const REPORT: &str = "report.txt";

/// The prefix every content-bearing entry sits under.
pub const CONTENT_PREFIX: &str = "content/";

/// One content-bearing entry a person selected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Content {
    /// The entry's name inside the archive, under [`CONTENT_PREFIX`].
    pub entry: String,
    /// What it holds, in the words the command prints before it writes.
    pub describes: String,
    /// The bytes.
    pub bytes: Vec<u8>,
}

impl Content {
    /// The sentence the command prints before writing a bundle that will carry this.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("  {}: {}", self.entry, self.describes)
    }
}

/// Writes one support bundle.
///
/// `content` is empty unless the person explicitly selected a content-bearing export, and the
/// bundle records what that selection was so a reader of the file can see it too.
///
/// # Errors
///
/// Returns an error when the archive cannot be written to `path`.
pub fn write(path: &Path, bundle: &SupportBundle, content: &[Content], report: &str) -> Result<()> {
    // A bare file name has no parent directory, and the atomic replacement needs one to write its
    // temporary file into and to flush afterwards. Resolving it here is what makes
    // `kr doctor --bundle support.tar` work from a terminal the way a person expects.
    let path = &if path
        .parent()
        .is_some_and(|parent| parent.as_os_str().is_empty())
    {
        std::env::current_dir()
            .map_err(|error| {
                CliError::Other(format!(
                    "this bundle's destination could not be resolved: {error}"
                ))
            })?
            .join(path)
    } else {
        path.to_path_buf()
    };
    let bundle = if content.is_empty() {
        bundle.clone()
    } else {
        bundle.clone().with_content(ContentExport {
            includes: content
                .iter()
                .map(|entry| entry.describes.clone())
                .collect(),
            entries: content.iter().map(|entry| entry.entry.clone()).collect(),
        })
    };
    let manifest = serde_json::to_vec_pretty(&bundle)
        .map_err(|error| CliError::Other(format!("this bundle could not be written: {error}")))?;
    let mut archive = Archive::new();
    archive.file(MANIFEST, &manifest)?;
    archive.file(REPORT, report.as_bytes())?;
    for entry in content {
        archive.file(&entry.entry, &entry.bytes)?;
    }
    kr_ipc::paths::write_owner_only_file(path, &archive.finish()).map_err(CliError::Ipc)
}

/// A POSIX `ustar` archive, built in memory.
struct Archive {
    bytes: Vec<u8>,
}

/// One tar block.
const BLOCK: usize = 512;

/// The largest entry the header's eleven-digit octal size field can express.
const MAX_ENTRY_LEN: u64 = 8u64.pow(11) - 1;

impl Archive {
    const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Appends one regular file.
    ///
    /// A name the header cannot carry, or a size its octal field cannot express, is refused rather
    /// than truncated. Every name this writes is one of the constants above or a short entry
    /// beneath them, so neither happens; an archive that silently renamed or mis-sized an entry
    /// would be one a person could not trust, and refusing is cheaper than a reader finding out.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is longer than the header's hundred bytes or the contents
    /// are larger than the size field holds.
    fn file(&mut self, name: &str, contents: &[u8]) -> Result<()> {
        let mut header = [0u8; BLOCK];
        let bytes = name.as_bytes();
        if bytes.len() > 100 {
            return Err(CliError::Other(format!(
                "{name} is longer than an archive entry name may be"
            )));
        }
        if contents.len() as u64 > MAX_ENTRY_LEN {
            return Err(CliError::Other(format!(
                "{name} is larger than an archive entry may be"
            )));
        }
        header[..bytes.len()].copy_from_slice(bytes);
        write_octal(&mut header[100..108], 0o600, 7);
        write_octal(&mut header[108..116], 0, 7);
        write_octal(&mut header[116..124], 0, 7);
        write_octal(&mut header[124..136], contents.len() as u64, 11);
        // A fixed modification time. A bundle is about a host rather than about the moment its
        // archive was assembled, the manifest already carries when it was made, and a fixed time
        // is what lets two bundles of the same host be compared byte for byte.
        write_octal(&mut header[136..148], 0, 11);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        write_octal(&mut header[148..154], u64::from(checksum), 6);
        header[154] = 0;
        header[155] = b' ';
        self.bytes.extend_from_slice(&header);
        self.bytes.extend_from_slice(contents);
        let remainder = contents.len() % BLOCK;
        if remainder != 0 {
            self.bytes.resize(self.bytes.len() + BLOCK - remainder, 0);
        }
        Ok(())
    }

    /// Returns the finished archive, with the two empty blocks that end one.
    fn finish(mut self) -> Vec<u8> {
        self.bytes.resize(self.bytes.len() + 2 * BLOCK, 0);
        self.bytes
    }
}

/// Writes one octal header field: `digits` digits, then a terminator.
fn write_octal(field: &mut [u8], value: u64, digits: usize) {
    let text = format!("{value:0digits$o}");
    let bytes = text.as_bytes();
    let taken = bytes.len().min(digits);
    field[..taken].copy_from_slice(&bytes[bytes.len() - taken..]);
    if digits < field.len() {
        field[digits] = 0;
    }
}
