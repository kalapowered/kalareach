//! Another filesystem where one was, for the tests of every service that records a directory.
//!
//! What a recorded directory is refused for is a different filesystem at the place it was recorded
//! that gives the directory there the numbers the recorded one had: a filesystem attached in place
//! of another one that was detached is given the device number the first had, and one built in the
//! same order gives its directories the same inodes. A test puts a filesystem at a path of its own
//! with [`Volume`], takes it off, puts a new one there and shows what a service that recorded a
//! directory on the first makes of the second.
//!
//! On Linux a tmpfs is mounted inside a user and mount namespace of this account's own, which
//! Ubuntu 24.04 and later deny an unprivileged account unless the restriction is lifted. The cases
//! that need it are ignored in an ordinary run, and the `rust` job of the landing workflow lifts
//! the restriction on its runner and runs them. A host that gives no such namespace fails the case
//! and says so, because a case that returned early would be counted as one that passed. On macOS a
//! disk image is attached and detached with `hdiutil`.

use std::path::{Path, PathBuf};

/// Set in the environment of the half of a case that runs inside the mount namespace.
#[cfg(target_os = "linux")]
const IN_NAMESPACE: &str = "KR_VOLUME_CASE_IN_NAMESPACE";

/// What the half inside the namespace exits with when the host would not attach a filesystem.
#[cfg(target_os = "linux")]
const NOT_EXERCISED: i32 = 42;

/// Runs `body` where this host can attach and detach a filesystem: directly on macOS, and on
/// Linux inside a mount namespace of this account's own, which `test` names so the test binary can
/// be started again inside it.
///
/// # Panics
///
/// Panics, with what the host answered, where it gives no way to attach a filesystem.
pub fn with_volumes(test: &str, body: fn()) {
    #[cfg(target_os = "macos")]
    {
        let _ = test;
        body();
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os(IN_NAMESPACE).is_some() {
            body();
            return;
        }
        let status = namespace_launcher()
            .command()
            .arg(std::env::current_exe().expect("the test binary"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "--include-ignored",
                test,
            ])
            .env(IN_NAMESPACE, "1")
            .status()
            .expect("the test binary runs inside a mount namespace");
        assert_ne!(
            status.code(),
            Some(NOT_EXERCISED),
            "this namespace would not mount a filesystem, so this check did not run"
        );
        assert!(
            status.success(),
            "the case inside the namespace failed: {status}"
        );
    }
}

/// How a program is started inside a user and mount namespace of this account's own.
#[cfg(target_os = "linux")]
enum Launcher {
    /// `unshare -r -m`, which the host allows where its restriction on unprivileged user
    /// namespaces is lifted.
    Unshare,
    /// `podman unshare`, which enters a namespace through the setuid id-mapping helpers where the
    /// restriction stands.
    Podman,
}

#[cfg(target_os = "linux")]
impl Launcher {
    fn command(&self) -> std::process::Command {
        match self {
            Self::Unshare => {
                let mut command = std::process::Command::new("unshare");
                command.args(["-r", "-m", "--"]);
                command
            }
            Self::Podman => {
                let mut command = std::process::Command::new("podman");
                command.arg("unshare");
                command
            }
        }
    }
}

/// Returns the way this host starts a program in a namespace it may mount in, and panics, with
/// what the host answered, where there is none.
#[cfg(target_os = "linux")]
fn namespace_launcher() -> Launcher {
    let mut refused = Vec::new();
    for launcher in [Launcher::Unshare, Launcher::Podman] {
        match launcher.command().arg("true").output() {
            Ok(probe) if probe.status.success() => return launcher,
            Ok(probe) => refused.push(String::from_utf8_lossy(&probe.stderr).trim().to_owned()),
            Err(error) => refused.push(error.to_string()),
        }
    }
    panic!(
        "this host does not give this account a mount namespace, so this check cannot run here: \
         {}",
        refused.join("; ")
    );
}

/// Ends a case whose host would not attach a filesystem, as a failure rather than as a check that
/// passed: on Linux the namespace's exit code, which the half outside it turns into that failure,
/// and on macOS the failure itself.
///
/// # Panics
///
/// Panics on macOS, and ends the process on Linux.
pub fn not_attachable() -> ! {
    #[cfg(target_os = "linux")]
    std::process::exit(NOT_EXERCISED);
    #[cfg(not(target_os = "linux"))]
    panic!("this host would not attach a filesystem, so this check cannot run here");
}

/// A filesystem attached at a path.
///
/// A case takes it off with [`Self::detach`], which fails the case when the filesystem stays
/// attached. Dropping it takes it off as well as it can, which is what a case that failed first
/// leaves behind.
#[derive(Debug)]
pub struct Volume {
    at: PathBuf,
    attached: bool,
}

impl Volume {
    /// Attaches a new, empty filesystem at `at`, a directory that exists, or returns `None` where
    /// this host will not. `scratch` is where an image is kept, on the filesystem the case runs
    /// on, and `tag` keeps one image's name from another's.
    #[must_use]
    pub fn attach(at: &Path, scratch: &Path, tag: &str) -> Option<Self> {
        attach_new(at, scratch, tag).then(|| Self {
            at: at.to_path_buf(),
            attached: true,
        })
    }

    /// Takes this filesystem off and attaches another, new and empty, at the same path.
    ///
    /// # Panics
    ///
    /// Panics when this filesystem stays attached.
    #[must_use]
    pub fn replace(self, scratch: &Path, tag: &str) -> Option<Self> {
        let at = self.at.clone();
        self.detach();
        Self::attach(&at, scratch, tag)
    }

    /// Takes this filesystem off.
    ///
    /// # Panics
    ///
    /// Panics when it stays attached, so a case does not pass while it leaves one behind.
    pub fn detach(mut self) {
        self.attached = false;
        assert!(
            detach(&self.at),
            "the filesystem attached at {} was not detached",
            self.at.display()
        );
    }

    /// Returns where it is attached.
    #[must_use]
    pub fn at(&self) -> &Path {
        &self.at
    }
}

impl Drop for Volume {
    fn drop(&mut self) {
        if self.attached {
            let _ = detach(&self.at);
        }
    }
}

/// Copies `from`, a directory, into `into`, keeping its modes and what it holds.
///
/// This is what puts a service's whole state, its journal included, on a new filesystem: the
/// state of one filesystem as another one holds it.
///
/// # Panics
///
/// Panics when the copy fails.
pub fn copy_tree(from: &Path, into: &Path) {
    let status = std::process::Command::new("cp")
        .arg("-a")
        .arg(from)
        .arg(into)
        .status()
        .expect("cp runs");
    assert!(status.success(), "the tree was copied: {status}");
}

#[cfg(target_os = "linux")]
fn attach_new(at: &Path, _scratch: &Path, _tag: &str) -> bool {
    // A new tmpfs for every attachment: its own filesystem id and, in this namespace, the device
    // number the last one had.
    std::process::Command::new("mount")
        .args(["-t", "tmpfs", "-o", "mode=0700", "tmpfs"])
        .arg(at)
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "linux")]
fn detach(at: &Path) -> bool {
    // Lazily, so that a handle a case still holds does not keep the path from being given a new
    // filesystem.
    std::process::Command::new("umount")
        .arg("-l")
        .arg(at)
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "macos")]
fn attach_new(at: &Path, scratch: &Path, tag: &str) -> bool {
    let image = scratch.join(format!("volume-{tag}.dmg"));
    let made = std::process::Command::new("/usr/bin/hdiutil")
        .args([
            "create", "-size", "8m", "-fs", "HFS+", "-volname", "volume", "-quiet",
        ])
        .arg(&image)
        .status();
    if !made.is_ok_and(|status| status.success()) {
        return false;
    }
    let attached = std::process::Command::new("/usr/bin/hdiutil")
        .args([
            "attach",
            "-nobrowse",
            "-noverify",
            "-noautoopen",
            "-quiet",
            "-mountpoint",
        ])
        .arg(at)
        .arg(&image)
        .status()
        .is_ok_and(|status| status.success());
    // Owner-only, as the root of the filesystem a tmpfs is given on Linux and as a staging
    // directory is made: a volume's root is open to everyone, and a removal that checks who may
    // change a directory would refuse it for that reason and not for the one a case is about.
    if attached {
        use std::os::unix::fs::PermissionsExt as _;

        let _ = std::fs::set_permissions(at, std::fs::Permissions::from_mode(0o700));
    }
    attached
}

#[cfg(target_os = "macos")]
fn detach(at: &Path) -> bool {
    std::process::Command::new("/usr/bin/hdiutil")
        .args(["detach", "-force", "-quiet"])
        .arg(at)
        .status()
        .is_ok_and(|status| status.success())
}
