//! The key of the cargo cache the landing workflow restores: a cache built on one runner image is
//! never restored on another.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// The three parts of the key `scripts/cargo-cache-key.sh` prints, with the runner image variables
/// as given: set to a value, or removed from the environment where `None`.
fn key(image_os: Option<&str>, image_version: Option<&str>) -> [String; 3] {
    let mut command = Command::new("bash");
    command
        .arg("scripts/cargo-cache-key.sh")
        .current_dir(repository())
        .env_remove("ImageOS")
        .env_remove("ImageVersion");
    if let Some(value) = image_os {
        command.env("ImageOS", value);
    }
    if let Some(value) = image_version {
        command.env("ImageVersion", value);
    }
    let output = command.output().expect("bash runs the script");
    assert!(
        output.status.success(),
        "the script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed = String::from_utf8(output.stdout).expect("the key is text");
    let parts: Vec<&str> = printed.trim().splitn(4, '-').collect();
    // `<settings>-<year>-W<week>-<dependencies>`: the week is two words of the ISO date.
    assert_eq!(
        parts.len(),
        4,
        "a settings part, a week and a dependencies part: {printed}"
    );
    [
        parts[0].to_owned(),
        format!("{}-{}", parts[1], parts[2]),
        parts[3].to_owned(),
    ]
}

/// A cache built on one runner image is not restored on another, by its exact key or by the prefix
/// a restore falls back to, which is the settings part: the part changes with the image's release
/// and with its operating system, and the other parts of the key stay as they are.
#[test]
fn a_cache_built_on_one_runner_image_is_never_restored_on_another() {
    let old = key(Some("macos15"), Some("20260907.0337.1"));
    let again = key(Some("macos15"), Some("20260907.0337.1"));
    let newer = key(Some("macos15"), Some("20261028.0489.1"));
    let other = key(Some("ubuntu24"), Some("20260907.0337.1"));
    assert_eq!(old[0], again[0], "one image has one key");
    assert_ne!(old[0], newer[0], "another release of the image");
    assert_ne!(old[0], other[0], "another operating system");
    assert_ne!(newer[0], other[0]);
    // The dependencies part is the lock file's alone; the week part is not compared, since a test
    // that runs over the turn of a week sees two.
    assert_eq!(old[2], newer[2]);
    assert_eq!(old[2], other[2]);
    assert!(old[0].len() == 16 && old[0].bytes().all(|byte| byte.is_ascii_hexdigit()));
}

/// Where the variables are not set, or are empty, the key says so and does not take the machine
/// for a hosted runner: it is a key of its own, and an empty value is the same as none.
#[test]
fn a_machine_that_is_not_a_hosted_runner_has_a_key_of_its_own() {
    let none = key(None, None);
    let empty = key(Some(""), Some(""));
    let hosted = key(Some("macos15"), Some("20260907.0337.1"));
    let half = key(Some("macos15"), None);
    assert_eq!(none[0], empty[0], "an empty value is no value");
    assert_ne!(none[0], hosted[0]);
    assert_ne!(none[0], half[0], "one variable is not both");
    assert_ne!(half[0], hosted[0]);
}
