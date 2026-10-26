//! Preferences read through macOS's `defaults`.
//!
//! A domain is either a preference domain's name or the absolute path of a preferences file, which
//! `defaults` takes in its place; a test addresses a file of its own that way, because the person's
//! own domains are not reachable from a scratch home.

use std::process::{Command, Stdio};

/// The program that reads and writes preferences.
const DEFAULTS: &str = "/usr/bin/defaults";

/// One string preference, or `None` where there is no `defaults`, the domain is not there or the key
/// is not.
#[must_use]
pub(super) fn read_string(domain: &str, key: &str) -> Option<String> {
    let output = Command::new(DEFAULTS)
        .args(["read", domain, key])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
