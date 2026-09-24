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
//! # What this reads
//!
//! The bundle identity this build declares, the executable this process is running from, where
//! that executable sits, and the signature on it, read through the platform's own signing tool
//! against that exact path. A signature that names no authority is one the operating system will
//! not recognise again after a rebuild, which is the whole of why setup asks: an ad-hoc signature
//! changes with every build and every grant given to it goes with the old one.
//!
//! What it does not establish is that a permission has been granted. Nothing can, short of
//! performing the operation the permission guards, and the report says so wherever it is shown.

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
    /// The signing identity on that executable, as the platform's own tool names it.
    pub signature: Signature,
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

/// The signature on an executable, as the platform reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Signature {
    /// Whether the platform read a signature at all.
    pub read: bool,
    /// The authority that signed it, where there is one. Absent for an ad-hoc signature.
    pub authority: Option<String>,
    /// The team the signature belongs to, where the signature carries one.
    pub team: Option<String>,
    /// The identifier the signature seals, which is what a grant is filed under.
    pub identifier: Option<String>,
    /// Whether the signature is ad-hoc, which is one this machine made and nobody else can check.
    pub ad_hoc: bool,
    /// Whether the platform verified the signature against what it seals, rather than only reading
    /// it. A bundle whose contents were changed after it was signed fails this.
    pub valid: bool,
    /// What the platform said, where it would not answer.
    pub refusal: Option<String>,
}

impl Signature {
    /// A signature nobody read.
    #[must_use]
    pub fn unread(refusal: impl Into<String>) -> Self {
        Self {
            read: false,
            authority: None,
            team: None,
            identifier: None,
            ad_hoc: false,
            valid: false,
            refusal: Some(refusal.into()),
        }
    }

    /// Whether this signature is one the operating system recognises again after a rebuild.
    #[must_use]
    pub fn is_durable(&self) -> bool {
        self.read && self.valid && !self.ad_hoc && self.authority.is_some()
    }
}

/// What this check never establishes, in the words the assistant shows.
const UNVERIFIED: &str = "This reads the identity a grant is filed under, and the signature on it. \
                          It cannot tell you a permission has been granted: on this platform the \
                          only way to establish that is to perform the operation the permission \
                          guards.";

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
    let signature = executable.as_deref().map_or_else(
        || Signature::unread("this application could not read its own path"),
        read_signature,
    );
    let instability = match executable.as_deref() {
        Some(path) => unstable(path, bundled, &signature),
        // An application that cannot say which file it is cannot say what a grant would be filed
        // under either, and that is the least stable answer there is.
        None => Some(
            "This application could not read its own path, so what the operating system would \
             file a grant under is not established here."
                .to_owned(),
        ),
    };
    let (helper_build, helper_environment) = match helper {
        Some((build, environment)) => (Some(build), Some(environment)),
        None => (None, None),
    };
    Identity {
        application_id: application_id.to_owned(),
        application_version: application_version.to_owned(),
        executable,
        bundled,
        signature,
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
/// Three answers, and each says what the person can do about it.
///
/// A signature no authority stands behind is the one that matters most, and it is the one a path
/// cannot show. An ad-hoc signature is one this machine made for this file; the operating system
/// files a grant against it, and the next build gets a different one. A signature from a
/// development or distribution authority stays the same across builds, which is what makes a grant
/// given today still a grant tomorrow.
///
/// A bundle is the second. An executable that is not in one has no bundle identity for the
/// platform to file anything under, and one inside a build directory is a bundle the next build
/// overwrites.
#[must_use]
pub fn unstable(executable: &str, bundled: bool, signature: &Signature) -> Option<String> {
    if !signature.read {
        return Some(format!(
            "The signature on {executable} could not be read{}. A permission the operating system \
             grants is filed against a signed application, so what a grant given now would be \
             filed under is not established.",
            signature
                .refusal
                .as_deref()
                .map_or_else(String::new, |said| format!(": {said}"))
        ));
    }
    if !signature.valid {
        return Some(format!(
            "The operating system did not verify {executable} against the signature it carries. A \
             bundle whose contents changed after it was signed is one the platform treats as a \
             different application, so a grant given now may not be there next time. Install a \
             signed build before granting anything."
        ));
    }
    if signature.ad_hoc || signature.authority.is_none() {
        return Some(format!(
            "{executable} carries an ad-hoc signature, which is one this machine made for this \
             file and nothing else can vouch for. The operating system files a grant against it, \
             and the next build of this application carries a different one, so every grant given \
             now has to be given again. Install a signed build before granting anything."
        ));
    }
    if !bundled {
        return Some(format!(
            "This build is running from {executable}, which is not an application bundle, so \
             there is no bundle identity for a grant to be filed under. Install the application \
             before granting anything."
        ));
    }
    for directory in BUILD_DIRECTORIES {
        if executable.contains(directory) {
            return Some(format!(
                "This build is running from {executable}, which is inside a build directory. The \
                 next build writes a new bundle there, so a grant given now belongs to a bundle \
                 that will have been replaced. Install the application before granting anything."
            ));
        }
    }
    None
}

/// Reads the signature on one executable, through the platform's own signing tool.
///
/// The tool is run with an argument vector against one path, its output is read, and nothing else
/// happens. On a platform with no such tool the answer says the signature was not read, which is
/// what it is.
#[must_use]
pub fn read_signature(executable: &str) -> Signature {
    if !cfg!(target_os = "macos") {
        return Signature::unread("this platform has no signing tool this application reads");
    }
    if !std::path::Path::new(SIGNING_TOOL).is_file() {
        return Signature::unread("the platform's signing tool is not installed");
    }
    // On a thread, with a deadline. The signing tool talks to the platform's own services, and a
    // setup screen that could not answer because one of those was busy would be a worse answer
    // than one that says the signature was not read.
    let (sender, receiver) = std::sync::mpsc::channel();
    let owned = executable.to_owned();
    std::thread::spawn(move || {
        let _ = sender.send(
            std::process::Command::new(SIGNING_TOOL)
                .args(["-d", "--verbose=2", &owned])
                .stdin(std::process::Stdio::null())
                .output(),
        );
    });
    let Ok(answered) = receiver.recv_timeout(SIGNING_BOUND) else {
        return Signature::unread("the platform's signing tool did not answer");
    };
    let Ok(output) = answered else {
        return Signature::unread("the platform's signing tool could not be run");
    };
    // The tool prints its description on the error stream, which is where these fields are.
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    if !output.status.success() {
        return Signature::unread(first_line(&said));
    }
    Signature {
        read: true,
        authority: field(&said, "Authority="),
        team: field(&said, "TeamIdentifier=").filter(|team| team != "not set"),
        identifier: field(&said, "Identifier="),
        ad_hoc: is_ad_hoc(&said),
        // Reading a signature is not checking it. This is the second question, and the one that
        // catches a bundle whose contents changed after it was signed.
        valid: verifies(executable),
        refusal: None,
    }
}

/// Whether the platform verifies this executable against the signature it carries.
///
/// `--strict` refuses the leniencies the tool would otherwise allow, and `--deep` reaches the
/// bundle's own contents rather than stopping at its outermost seal. A tool that does not answer
/// inside its allowance is a signature this host has not verified.
fn verifies(executable: &str) -> bool {
    let (sender, receiver) = std::sync::mpsc::channel();
    let owned = executable.to_owned();
    std::thread::spawn(move || {
        let _ = sender.send(
            std::process::Command::new(SIGNING_TOOL)
                .args(["--verify", "--deep", "--strict", &owned])
                .stdin(std::process::Stdio::null())
                .output(),
        );
    });
    receiver
        .recv_timeout(SIGNING_BOUND)
        .ok()
        .and_then(Result::ok)
        .is_some_and(|output| output.status.success())
}

/// How long the signing tool is given before the report says the signature was not read.
const SIGNING_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// Whether the tool's description says this signature is ad-hoc.
///
/// The two fields that say so, and nothing else. Looking for the word anywhere in the description
/// would find it in the path of an application that happens to live in a directory called `adhoc`,
/// and telling somebody to install a signed build of the signed build they have is not a message
/// worth shipping.
fn is_ad_hoc(said: &str) -> bool {
    if field(said, "Signature=").is_some_and(|value| value.contains("adhoc")) {
        return true;
    }
    said.lines()
        .filter(|line| line.trim_start().starts_with("CodeDirectory "))
        .any(|line| {
            line.split_whitespace()
                .find_map(|word| word.strip_prefix("flags="))
                .is_some_and(|flags| flags.contains("adhoc"))
        })
}

/// The platform's own signing tool.
const SIGNING_TOOL: &str = "/usr/bin/codesign";

/// The first value of one field of the tool's description.
fn field(said: &str, name: &str) -> Option<String> {
    said.lines()
        .find_map(|line| line.strip_prefix(name))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// The first line of what a tool said, for a message a person reads.
fn first_line(said: &str) -> String {
    said.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("it said nothing")
        .to_owned()
}

/// Path fragments that say a bundle is a build product rather than an installation.
const BUILD_DIRECTORIES: &[&str] = &["/target/", "/build/", "/DerivedData/", "/dist/"];

#[cfg(test)]
mod tests {
    use super::*;

    /// A signature an authority stands behind.
    fn signed() -> Signature {
        Signature {
            read: true,
            authority: Some("Developer ID Application: Kala".to_owned()),
            team: Some("ABCDE12345".to_owned()),
            identifier: Some("to.kala.reach".to_owned()),
            ad_hoc: false,
            valid: true,
            refusal: None,
        }
    }

    #[test]
    fn a_signature_the_platform_would_not_verify_is_not_stable() {
        let unverified = Signature {
            valid: false,
            ..signed()
        };
        assert!(!unverified.is_durable());
        let said = unstable(
            "/Applications/KalaReach.app/Contents/MacOS/kalareach-companion",
            true,
            &unverified,
        )
        .expect("a signature the platform did not verify is not stable");
        assert!(said.contains("did not verify"));
        assert!(said.contains("changed after it was signed"));
    }

    #[test]
    fn an_installed_signed_bundle_keeps_its_identity() {
        let path = "/Applications/KalaReach.app/Contents/MacOS/kalareach-companion";
        assert!(inside_bundle(path));
        assert!(signed().is_durable());
        assert_eq!(unstable(path, true, &signed()), None);
    }

    #[test]
    fn an_ad_hoc_signature_is_the_first_thing_reported() {
        let ad_hoc = Signature {
            ad_hoc: true,
            authority: None,
            ..signed()
        };
        assert!(!ad_hoc.is_durable());
        // Even from an installed bundle, because the signature is what a grant is filed against.
        let said = unstable(
            "/Applications/KalaReach.app/Contents/MacOS/kalareach-companion",
            true,
            &ad_hoc,
        )
        .expect("an ad-hoc signature is not stable");
        assert!(said.contains("ad-hoc signature"));
        assert!(said.contains("Install a signed build before granting anything."));
    }

    #[test]
    fn a_signature_nobody_read_establishes_nothing() {
        let unread = Signature::unread("it would not say");
        assert!(!unread.is_durable());
        let said = unstable("/Applications/K.app/Contents/MacOS/k", true, &unread)
            .expect("an unread signature is not stable");
        assert!(said.contains("could not be read"));
        assert!(said.contains("it would not say"));
    }

    #[test]
    fn a_bare_binary_has_no_identity_to_file_a_grant_under() {
        let path = "/Users/someone/work/build/kalareach-companion";
        assert!(!inside_bundle(path));
        let said = unstable(path, false, &signed()).expect("a bare binary is not stable");
        assert!(said.contains("not an application bundle"));
        assert!(said.contains("Install the application before granting anything."));
    }

    #[test]
    fn a_bundle_in_a_build_directory_is_replaced_by_the_next_build() {
        let path = "/Users/someone/work/target/debug/bundle/macos/KalaReach.app/Contents/MacOS/x";
        assert!(inside_bundle(path));
        let said = unstable(path, true, &signed()).expect("a build product is not stable");
        assert!(said.contains("inside a build directory"));
    }

    #[test]
    fn an_ad_hoc_signature_is_read_from_the_fields_that_say_so_and_not_from_the_path() {
        assert!(is_ad_hoc("Signature=adhoc\n"));
        assert!(is_ad_hoc(
            "CodeDirectory v=20400 size=448061 flags=0x20002(adhoc,linker-signed) hashes=1\n"
        ));
        assert!(
            !is_ad_hoc(
                "Executable=/Applications/adhoc/KalaReach.app/Contents/MacOS/k\nSignature size=4567\n"
            ),
            "a directory called adhoc is not a signature"
        );
        assert!(!is_ad_hoc(
            "Signature size=4567\nAuthority=Developer ID Application\n"
        ));
    }

    #[test]
    fn the_signature_of_this_test_binary_is_read_from_the_platform() {
        let path = std::env::current_exe().expect("this test has a path");
        let signature = read_signature(&path.display().to_string());
        if cfg!(target_os = "macos") {
            assert!(signature.read, "{:?}", signature.refusal);
            assert!(
                signature.identifier.is_some(),
                "a signature seals an identifier"
            );
        } else {
            assert!(!signature.read);
        }
    }

    #[test]
    fn the_report_always_says_what_it_did_not_establish() {
        let identity = read("to.kala.companion", "0.1.0", None);
        assert_eq!(identity.application_id, "to.kala.companion");
        assert!(identity.unverified.contains("cannot tell you a permission"));
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
