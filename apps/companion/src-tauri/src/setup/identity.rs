//! The identity an operating system records a permission against.
//!
//! On macOS a privacy grant belongs to a signed application, not to a path and not to a person.
//! Two consequences run through the whole of setup. A grant given to one identity does nothing for
//! another, so an application whose identity moves between launches asks for the same permissions
//! again every time. And a grant reaches a process when it starts, so an application that was
//! running when the grant was given is still running without it.
//!
//! That is why setup checks this first. Guiding somebody through four settings panes and then
//! discovering the grants were recorded against a build directory is a waste of their afternoon.
//!
//! # What this reads, and what it does not
//!
//! It reads the bundle identity this build declares, the executable this process is running from,
//! and where that executable sits. It does not read the code signature: doing that from inside the
//! process means calling into the platform's security framework, which needs unsafe code, and this
//! crate allows that in exactly one place for a different reason. So the report says what it
//! establishes — this is the identity a grant would be recorded against, and here is whether it is
//! one that stays the same — and says plainly that the signature itself was not read.

use serde::Serialize;

/// What the operating system would record a permission against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Identity {
    /// The bundle identifier this build declares. This is the name a grant is filed under.
    pub application_id: String,
    /// The version this build declares.
    pub application_version: String,
    /// The executable this process is running from.
    pub executable: Option<String>,
    /// Whether that executable sits inside an application bundle.
    pub bundled: bool,
    /// Whether the identity is the same on the next launch.
    pub stable: bool,
    /// Why it is not, when it is not.
    pub instability: Option<String>,
    /// What this check did not establish, always stated.
    pub unverified: String,
    /// The host build this application is in contact with, where it is in contact with one.
    pub helper_build: Option<String>,
    /// The environment that host owns.
    pub helper_environment: Option<String>,
}

/// What this check never establishes, in the words the assistant shows.
const UNVERIFIED: &str = "This reads the identity a grant is filed under. It does not read the \
                          code signature itself, and no check here can tell you a permission has \
                          been granted: on this platform the only way to establish that is to \
                          perform the operation the permission guards.";

/// Reads the identity of this application.
///
/// `helper` is the host build this application is in contact with, where it is in contact with
/// one, and the environment that host owns. Both are absent when there is no host, which is an
/// ordinary state at first start rather than a failure.
#[must_use]
pub fn read(
    application_id: &str,
    application_version: &str,
    helper: Option<(String, String)>,
) -> Identity {
    let executable = std::env::current_exe()
        .ok()
        .map(|path| path.display().to_string());
    let bundled = executable.as_deref().is_some_and(inside_bundle);
    let instability = executable
        .as_deref()
        .and_then(|path| unstable(path, bundled));
    let (helper_build, helper_environment) = match helper {
        Some((build, environment)) => (Some(build), Some(environment)),
        None => (None, None),
    };
    Identity {
        application_id: application_id.to_owned(),
        application_version: application_version.to_owned(),
        executable,
        bundled,
        stable: instability.is_none(),
        instability,
        unverified: UNVERIFIED.to_owned(),
        helper_build,
        helper_environment,
    }
}

/// Whether an executable sits inside an application bundle.
#[must_use]
pub fn inside_bundle(executable: &str) -> bool {
    executable.contains(".app/Contents/MacOS/")
}

/// Why this executable's identity would not be the same on the next launch.
///
/// Two answers, and each says what the person can do about it. An executable that is not in a
/// bundle has no bundle identity for the platform to file a grant under at all, so the grant goes
/// to whatever the platform makes of the bare binary and a rebuild replaces it. An executable in a
/// bundle inside a build directory is a bundle the next build overwrites, which is the same
/// problem wearing the right shape.
#[must_use]
pub fn unstable(executable: &str, bundled: bool) -> Option<String> {
    if !bundled {
        return Some(format!(
            "This build is running from {executable}, which is not an application bundle. A \
             permission the operating system grants is recorded against a signed application, so \
             a grant given to this build is given to this file and a rebuild replaces it. Install \
             the application before granting anything."
        ));
    }
    for directory in BUILD_DIRECTORIES {
        if executable.contains(directory) {
            return Some(format!(
                "This build is running from {executable}, which is inside a build directory. The \
                 next build writes a new bundle there and the operating system treats it as a \
                 different application, so every grant given now has to be given again. Install \
                 the application before granting anything."
            ));
        }
    }
    None
}

/// Path fragments that say a bundle is a build product rather than an installation.
const BUILD_DIRECTORIES: &[&str] = &["/target/", "/build/", "/DerivedData/", "/dist/"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_installed_bundle_keeps_its_identity() {
        let path = "/Applications/KalaReach.app/Contents/MacOS/kalareach-companion";
        assert!(inside_bundle(path));
        assert_eq!(unstable(path, true), None);
    }

    #[test]
    fn a_bare_binary_has_no_identity_to_file_a_grant_under() {
        let path = "/Users/someone/work/target/debug/kalareach-companion";
        assert!(!inside_bundle(path));
        let said = unstable(path, false).expect("a bare binary is not stable");
        assert!(said.contains("not an application bundle"));
        assert!(said.contains("Install the application before granting anything."));
    }

    #[test]
    fn a_bundle_in_a_build_directory_is_replaced_by_the_next_build() {
        let path = "/Users/someone/work/target/debug/bundle/macos/KalaReach.app/Contents/MacOS/x";
        assert!(inside_bundle(path));
        let said = unstable(path, true).expect("a build product is not stable");
        assert!(said.contains("inside a build directory"));
    }

    #[test]
    fn the_report_always_says_what_it_did_not_establish() {
        let identity = read("to.kala.companion", "0.1.0", None);
        assert_eq!(identity.application_id, "to.kala.companion");
        assert!(
            identity
                .unverified
                .contains("does not read the code signature")
        );
        assert!(
            identity.unverified.contains("perform the operation"),
            "the ceiling is stated wherever the identity is shown"
        );
        assert_eq!(identity.helper_build, None);
    }

    #[test]
    fn the_helper_is_the_host_this_application_is_in_contact_with() {
        let identity = read(
            "to.kala.companion",
            "0.1.0",
            Some(("build-7".to_owned(), "env-1".to_owned())),
        );
        assert_eq!(identity.helper_build.as_deref(), Some("build-7"));
        assert_eq!(identity.helper_environment.as_deref(), Some("env-1"));
    }
}
