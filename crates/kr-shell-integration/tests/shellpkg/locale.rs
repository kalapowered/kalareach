//! The locale a package's shell runs in.
//!
//! An editor draws a changed line differently in a byte locale and in a multibyte one: Readline
//! rewrites the characters it has to move over in the first, and moves the cursor over them with a
//! control sequence in the second. People run the product under UTF-8, and a hosted runner can
//! carry a locale of its own, so a case that depends on how the editor draws names its locale
//! instead of taking the one the run inherits, and runs under each.

use std::io::Write;
use std::process::Command;

use kr_shell_integration::contract::qualification::ShellKind;

use super::{Package, Session};

/// The locale a session's shell runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Locale {
    /// The C locale, in which the editor works on bytes.
    Bytes,
    /// A UTF-8 locale, in which the editor works on characters.
    Utf8,
}

impl Locale {
    /// The locales a case that depends on how the editor draws runs under, in this order.
    pub const BOTH: [Self; 2] = [Self::Bytes, Self::Utf8];

    /// What a log calls this locale.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Bytes => "byte",
            Self::Utf8 => "UTF-8",
        }
    }

    /// The name this platform gives the locale, or nothing where it has none.
    ///
    /// A name counts when `locale charmap` says UTF-8 under it, because a name the platform does
    /// not know falls back to the C locale without a word and a run under it would be a byte run
    /// that says it is not.
    #[must_use]
    pub fn name_here(self) -> Option<&'static str> {
        match self {
            Self::Bytes => Some("C"),
            Self::Utf8 => {
                let candidates: &[&str] = if cfg!(target_os = "macos") {
                    &["en_US.UTF-8"]
                } else {
                    &["C.UTF-8", "en_US.UTF-8"]
                };
                candidates
                    .iter()
                    .copied()
                    .find(|name| charmap_under(name).as_deref() == Some("UTF-8"))
            }
        }
    }
}

/// The character set `locale charmap` reports under `LC_ALL=name`.
fn charmap_under(name: &str) -> Option<String> {
    let output = Command::new("locale")
        .arg("charmap")
        .env("LC_ALL", name)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Writes a line to the run's log, past the capture that keeps the output of a passing case.
fn say(line: &str) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

/// Runs `body` once under each locale this platform has, with that locale's name, and says in the
/// log which locale each run used and which one the platform lacks.
///
/// A platform without a UTF-8 locale gets no run under it, and the log says so by the platform's
/// name; a case that stays quiet about a run it did not make would pass as if it had made it.
pub fn in_each_locale(kind: ShellKind, case: &str, mut body: impl FnMut(&str)) {
    for locale in Locale::BOTH {
        match locale.name_here() {
            Some(name) => {
                say(&format!(
                    "{case} ({kind:?}): run under the {} locale {name}",
                    locale.label()
                ));
                body(name);
            }
            None => say(&format!(
                "{case} ({kind:?}): {} has no {} locale, so the run under it is not made",
                std::env::consts::OS,
                locale.label()
            )),
        }
    }
}

impl Session {
    /// Starts the packaged shell under the locale `name`, whatever locale the run inherited, and
    /// completes the handshake.
    ///
    /// # Panics
    ///
    /// Panics as [`Session::start`] does.
    #[must_use]
    pub fn start_in_locale(package: &Package, name: &str) -> Self {
        Self::start_with(
            package,
            &[
                ("LANG".to_owned(), name.to_owned()),
                ("LC_ALL".to_owned(), name.to_owned()),
            ],
        )
    }
}
