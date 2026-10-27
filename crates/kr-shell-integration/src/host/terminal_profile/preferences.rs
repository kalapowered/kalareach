//! Preferences read through macOS's `defaults`.
//!
//! A domain is either a preference domain's name or the absolute path of a preferences file, which
//! `defaults` takes in its place; a test addresses a file of its own that way, because the person's
//! own domains are not reachable from a scratch home.

use std::io::Write as _;
use std::process::{Command, Stdio};

/// The program that reads and writes preferences.
const DEFAULTS: &str = "/usr/bin/defaults";

/// The program that reads one value out of a property list.
const PLUTIL: &str = "/usr/bin/plutil";

/// One string preference: `Ok(None)` where the domain or the key is not there, or where there is no
/// `defaults` to ask (a platform that is not macOS has no such preferences), and an error where a
/// program that is there did not answer, which is not an answer.
///
/// # Errors
///
/// Returns why the preference could not be read.
pub(super) fn read_string(domain: &str, key: &str) -> std::io::Result<Option<String>> {
    let exported = match Command::new(DEFAULTS)
        .args(["export", domain, "-"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => output.stdout,
        Ok(_) => return Err(std::io::Error::other("defaults did not export the domain")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut child = Command::new(PLUTIL)
        .args(["-extract", key, "raw", "-o", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(&exported);
    }
    let output = child.wait_with_output()?;
    match output.status.code() {
        Some(0) => Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        )),
        // `plutil` says there is no such key with this status and no other.
        Some(1) => Ok(None),
        _ => Err(std::io::Error::other("plutil did not answer")),
    }
}
