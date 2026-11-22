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
//!
//! A disk image on macOS is made so that nothing indexes it, and is detached by asking, by its
//! disk, until the system lets the disk go: a case holds handles on its volume when it detaches
//! it, as the cases are about what is open there, so the detach is forced, and a forced detach
//! unmounts the volume and then can fail to eject the disk when something else holds the disk's
//! device open, which leaves the image attached with nothing mounted from it.

use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

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

    /// Binds the directory `source` over `at`, a directory that exists, so that `at` shows
    /// `source` and `..` from it leads to the directory `at` is in. The bound directory is on the
    /// filesystem it is a directory of: it has that filesystem's device number and its own mount.
    /// Returns `None` where this host will not.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn bind(source: &Path, at: &Path) -> Option<Self> {
        std::process::Command::new("mount")
            .arg("--bind")
            .arg(source)
            .arg(at)
            .status()
            .is_ok_and(|status| status.success())
            .then(|| Self {
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
        if let Err(said) = detach(&self.at) {
            panic!(
                "the filesystem attached at {} was not detached: {said}",
                self.at.display()
            );
        }
    }

    /// Returns where it is attached.
    #[must_use]
    pub fn at(&self) -> &Path {
        &self.at
    }
}

impl Drop for Volume {
    fn drop(&mut self) {
        if !self.attached {
            return;
        }
        if let Err(said) = detach(&self.at) {
            let report = format!(
                "the filesystem attached at {} was not detached: {said}",
                self.at.display()
            );
            // A second panic while the first unwinds would abort the whole test binary, so a case
            // that has already failed says it here instead.
            if std::thread::panicking() {
                eprintln!("{report}");
            } else {
                panic!("{report}");
            }
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
fn detach(at: &Path) -> Result<(), String> {
    // Lazily, so that a handle a case still holds does not keep the path from being given a new
    // filesystem.
    let ended = std::process::Command::new("umount")
        .arg("-l")
        .arg(at)
        .output()
        .map_err(|error| format!("umount could not be run: {error}"))?;
    if ended.status.success() {
        Ok(())
    } else {
        Err(format!(
            "umount ended with {}: {}",
            ended.status,
            String::from_utf8_lossy(&ended.stderr).trim()
        ))
    }
}

/// The name of the file that keeps the system's indexer from reading a volume that holds it.
#[cfg(target_os = "macos")]
const NEVER_INDEXED: &str = ".metadata_never_index";

/// Makes the directory `name` in `parent`, holding what a volume made from it is given so that
/// nothing indexes it, and returns it.
///
/// The indexer is told by a file at the root of the volume, and it looks for it when the volume is
/// attached, so the file has to be in the image already: written after the attach, it comes too
/// late for an indexer that began at once. An image is made from this directory with
/// `hdiutil create -srcfolder`, in the read and write format, which that option does not make
/// unless it is asked to.
///
/// # Panics
///
/// Panics when the directory cannot be made.
#[cfg(target_os = "macos")]
#[must_use]
pub fn never_indexed_contents(parent: &Path, name: &str) -> PathBuf {
    let contents = parent.join(name);
    std::fs::create_dir_all(&contents).expect("the contents of a volume nothing indexes");
    std::fs::write(contents.join(NEVER_INDEXED), b"").expect("the file that keeps it unindexed");
    contents
}

#[cfg(target_os = "macos")]
fn attach_new(at: &Path, scratch: &Path, tag: &str) -> bool {
    let image = scratch.join(format!("volume-{tag}.dmg"));
    let contents = never_indexed_contents(scratch, &format!("volume-{tag}-contents"));
    let made = std::process::Command::new("/usr/bin/hdiutil")
        .args([
            "create",
            "-size",
            "8m",
            "-fs",
            "HFS+",
            "-volname",
            "volume",
            "-format",
            "UDRW",
            "-quiet",
            "-srcfolder",
        ])
        .arg(&contents)
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

/// How long a detach asks for a disk to be let go of before the volume is taken for stuck.
///
/// It decides nothing about a disk that is let go of, which is detached when it is. It ends the
/// wait for one that is held for good.
#[cfg(target_os = "macos")]
const DETACH_PATIENCE: Duration = Duration::from_secs(120);

/// How long a detach waits before it asks again.
#[cfg(target_os = "macos")]
const DETACH_ASKS_AGAIN: Duration = Duration::from_millis(100);

#[cfg(target_os = "macos")]
fn detach(at: &Path) -> Result<(), String> {
    detach_attached(at)
}

/// Takes the disk image attached at `at` off, as a case's volume is taken off, and returns why it
/// did not come off.
///
/// # Errors
///
/// Returns why the disk did not come off, as [`detach_observed`] does.
#[cfg(target_os = "macos")]
pub fn detach_attached(at: &Path) -> Result<(), String> {
    detach_observed(at, DETACH_PATIENCE, |_| {})
}

/// Takes the disk image attached at `at` off, asking again for as long as the system refuses, and
/// returns why it did not come off.
///
/// The detach is forced, by the disk the volume is on: a case holds handles on its volume, and a
/// plain detach could not take it off while it does. A forced detach unmounts the volume and then
/// ejects the disk, and where something else has the disk's device open the eject is refused with
/// the volume already unmounted and the image still attached. A detach by the mount point asked
/// again would find nothing mounted, so the disk, which names the image whether or not anything is
/// mounted from it, is what is asked about, until the system lets it go. The first refusal is said
/// on standard error, with what the tool said, so that a run which needed the wait shows it.
///
/// `refused` is told what the tool said at each refusal. The first refusal and the final error
/// also say what holds the volume and its disk: the processes `lsof` shows with a file or the
/// disk's device open, and the process that serves the image. Each question that takes is let
/// run for ten seconds at most and is then ended. The holders are only named: the detach does
/// not wait for one to let go beyond `patience`, and does not end one.
///
/// # Errors
///
/// Returns what the tool last said, and what holds the disk, when the disk is still attached after
/// `patience`, or why the disk could not be named.
#[cfg(target_os = "macos")]
pub fn detach_observed(
    at: &Path,
    patience: Duration,
    refused: impl FnMut(&str),
) -> Result<(), String> {
    let disk = disk_of(at)?;
    detach_disk(at, &disk, patience, refused)
}

/// Takes the disk `disk`, which a volume was mounted at `at` from, off, as [`detach_observed`]
/// does once it has named the disk. It is asked again when a detach was refused after the volume
/// was unmounted, and the image stayed attached with nothing mounted from it.
///
/// # Errors
///
/// Returns what the tool last said, and what holds the disk, when the disk is still attached after
/// `patience`.
#[cfg(target_os = "macos")]
pub fn detach_disk(
    at: &Path,
    disk: &str,
    patience: Duration,
    mut refused: impl FnMut(&str),
) -> Result<(), String> {
    let until = Instant::now() + patience;
    let mut said_so = false;
    loop {
        // A refusal can come after the disk went, and the system can give its name to the next
        // image: a name asked about again is asked about only while the device is still there.
        if !Path::new(disk).exists() {
            return Ok(());
        }
        let ended = std::process::Command::new("/usr/bin/hdiutil")
            .args(["detach", "-force"])
            .arg(disk)
            .output()
            .map_err(|error| format!("hdiutil could not be run: {error}"))?;
        if ended.status.success() {
            return Ok(());
        }
        let said = format!(
            "hdiutil ended with {}: {}",
            ended.status,
            String::from_utf8_lossy(&ended.stderr).trim()
        );
        refused(&said);
        if !said_so {
            eprintln!(
                "the volume at {} was forced off and {disk} was still held ({said}); asking again \
                 until the system lets it go; {}",
                at.display(),
                holders_of(at, disk)
            );
            said_so = true;
        }
        if Instant::now() >= until {
            return Err(format!(
                "{disk} stayed attached for {patience:?} after the detach was forced ({said}); {}",
                holders_of(at, disk)
            ));
        }
        std::thread::sleep(DETACH_ASKS_AGAIN);
    }
}

/// How long a question about what holds a disk is let run before it is ended.
#[cfg(target_os = "macos")]
const HOLDER_QUERY_LIMIT: Duration = Duration::from_secs(10);

/// How many holders a report names, and how many of the files each has open.
#[cfg(target_os = "macos")]
const HOLDERS_NAMED: usize = 5;
#[cfg(target_os = "macos")]
const FILES_NAMED: usize = 3;

/// A process with files open on a volume or its disk, as `lsof` lists it.
#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, Eq)]
struct Holder {
    pid: String,
    command: String,
    files: Vec<String>,
}

/// The processes an `lsof -F pcn` listing shows, in the order it gives them, each with the files
/// it has open that the listing names.
#[cfg(target_os = "macos")]
fn holders_in(listing: &str) -> Vec<Holder> {
    let mut holders: Vec<Holder> = Vec::new();
    for line in listing.lines() {
        let mut characters = line.chars();
        let Some(field) = characters.next() else {
            continue;
        };
        let value = characters.as_str();
        match (field, holders.last_mut()) {
            ('p', _) => holders.push(Holder {
                pid: value.to_owned(),
                command: String::new(),
                files: Vec::new(),
            }),
            ('c', Some(holder)) => value.clone_into(&mut holder.command),
            ('n', Some(holder)) if !holder.files.iter().any(|file| file == value) => {
                holder.files.push(value.to_owned());
            }
            _ => {}
        }
    }
    holders
}

/// The devices an `hdiutil info` listing shows for the image `disk` belongs to, and the processes
/// it shows serving that image.
///
/// The listing has one block for each image, after a line of equals signs: its path and its
/// process, then its devices, each at the start of a line. A block is the image's when one of its
/// devices is the disk or a part of it.
#[cfg(target_os = "macos")]
fn image_of(listing: &str, disk: &str) -> (Vec<String>, Vec<String>) {
    let of_the_disk = |device: &str| {
        device == disk
            || device
                .strip_prefix(disk)
                .is_some_and(|rest| rest.starts_with('s'))
    };
    let mut found = (Vec::new(), Vec::new());
    let mut block: (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let mut ended = |block: &mut (Vec<String>, Vec<String>)| {
        let finished = std::mem::take(block);
        if finished.0.iter().any(|device| of_the_disk(device)) {
            found.0.extend(finished.0);
            found.1.extend(finished.1);
        }
    };
    for line in listing.lines() {
        if line.starts_with("====") {
            ended(&mut block);
        } else if let Some(device) = line
            .split_whitespace()
            .next()
            .filter(|word| word.starts_with("/dev/disk"))
        {
            block.0.push(device.to_owned());
        } else if let Some((key, value)) = line.split_once(':')
            && key.trim() == "process ID"
        {
            block.1.push(value.trim().to_owned());
        }
    }
    ended(&mut block);
    found
}

/// Runs `program` and returns what it wrote, or why that could not be had. It is let run for
/// [`HOLDER_QUERY_LIMIT`], then ended through its own handle, and is not waited for after that:
/// a program the system has stopped answering for does not hold the case.
#[cfg(target_os = "macos")]
fn asked(program: &str, arguments: &[std::ffi::OsString]) -> Result<String, String> {
    use std::io::Read as _;
    use std::process::Stdio;

    let mut child = std::process::Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("{program} could not be run: {error}"))?;
    let mut output = child.stdout.take().expect("the output is piped");
    let (written, written_text) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = Vec::new();
        let _ = output.read_to_end(&mut text);
        let _ = written.send(text);
    });
    let until = Instant::now() + HOLDER_QUERY_LIMIT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                return Err(format!(
                    "{program} did not answer within {HOLDER_QUERY_LIMIT:?} and was ended"
                ));
            }
            Err(error) => return Err(format!("{program} could not be waited for: {error}")),
        }
    }
    written_text
        .recv_timeout(Duration::from_secs(2))
        .map(|text| String::from_utf8_lossy(&text).into_owned())
        .map_err(|_| format!("what {program} wrote could not be read"))
}

/// Says what holds the volume mounted at `at` and the disk `disk` it is on: each process `lsof`
/// shows with a file open on either, and each process `hdiutil info` shows serving the image.
///
/// A volume the system will not let go of is held by a process that has a file or the disk's
/// device open, or by the process that serves the image. A report that names it shows what the
/// case, or the machine, did to leave the volume held. Each question is bounded, and one that
/// cannot be answered is said so in its place.
#[cfg(target_os = "macos")]
fn holders_of(at: &Path, disk: &str) -> String {
    use std::ffi::OsString;

    let info = asked("/usr/bin/hdiutil", &["info".into()]);
    let (devices, servers) = info
        .as_deref()
        .map(|listing| image_of(listing, disk))
        .unwrap_or_default();
    // The disk is asked about by its own name when the listing did not give the image's devices.
    let devices = if devices.is_empty() {
        vec![disk.to_owned()]
    } else {
        devices
    };
    let mut names: Vec<OsString> = ["-nP", "-F", "pcn", "--"].map(OsString::from).to_vec();
    if at.exists() {
        names.push(at.into());
    }
    for device in &devices {
        names.push(device.into());
        names.push(device.replacen("/dev/disk", "/dev/rdisk", 1).into());
    }
    let holding = match asked("/usr/sbin/lsof", &names) {
        Ok(listing) => {
            let holders = holders_in(&listing);
            if holders.is_empty() {
                format!(
                    "lsof shows no process with a file open on {} or on {disk}",
                    at.display()
                )
            } else {
                let mut named: Vec<String> = holders
                    .iter()
                    .take(HOLDERS_NAMED)
                    .map(|holder| {
                        let files: Vec<&str> = holder
                            .files
                            .iter()
                            .take(FILES_NAMED)
                            .map(String::as_str)
                            .collect();
                        format!(
                            "process {} ({}) has {} open",
                            holder.pid,
                            holder.command,
                            files.join(", ")
                        )
                    })
                    .collect();
                if holders.len() > HOLDERS_NAMED {
                    named.push(format!("{} more", holders.len() - HOLDERS_NAMED));
                }
                named.join("; ")
            }
        }
        Err(why) => format!("what holds it could not be read from lsof ({why})"),
    };
    let serving = match (&info, servers.as_slice()) {
        (Err(why), _) => format!("hdiutil info could not be read ({why})"),
        (Ok(_), []) => "hdiutil info shows no process serving the image".to_owned(),
        (Ok(_), servers) => {
            let named: Vec<String> = servers
                .iter()
                .map(|pid| {
                    let name = asked(
                        "/bin/ps",
                        &["-o".into(), "comm=".into(), "-p".into(), pid.into()],
                    )
                    .map(|text| text.trim().to_owned())
                    .unwrap_or_default();
                    format!("{pid} ({name})")
                })
                .collect();
            format!(
                "hdiutil info shows the image served by process {}",
                named.join(", ")
            )
        }
    };
    format!("{holding}; {serving}")
}

/// Returns the whole disk (`/dev/diskN`) the volume mounted at `at` is on.
///
/// # Errors
///
/// Returns why the mounts could not be read, or that nothing is mounted at `at`.
#[cfg(target_os = "macos")]
pub fn disk_of(at: &Path) -> Result<String, String> {
    let resolved = std::fs::canonicalize(at)
        .map_err(|error| format!("{} could not be resolved: {error}", at.display()))?;
    let listing = std::process::Command::new("/sbin/mount")
        .output()
        .map_err(|error| format!("mount could not be run: {error}"))?;
    disk_in(&String::from_utf8_lossy(&listing.stdout), &resolved)
        .ok_or_else(|| format!("nothing is mounted at {}", resolved.display()))
}

/// Returns the whole disk of the volume `listing`, as `mount` prints it, shows mounted at `at`.
#[cfg(target_os = "macos")]
fn disk_in(listing: &str, at: &Path) -> Option<String> {
    let place = format!(" on {} (", at.display());
    listing.lines().find_map(|line| {
        let (device, _) = line.split_once(&place)?;
        let number: String = device
            .strip_prefix("/dev/disk")?
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        (!number.is_empty()).then(|| format!("/dev/disk{number}"))
    })
}

#[cfg(test)]
mod tests {
    use super::Volume;

    /// What a panic said, as text.
    fn said(panic: &(dyn std::any::Any + Send)) -> String {
        panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
            .unwrap_or_default()
    }

    /// A filesystem that does not come off fails the case that attached it, and a case that is
    /// already failing says so on standard error and ends with its own failure.
    #[test]
    fn a_volume_that_does_not_detach_fails_the_case_that_attached_it() {
        // Nothing is attached at this directory, so there is nothing to take off.
        let nothing = crate::testing::PrivateTempDir::create();
        let ended = std::panic::catch_unwind(|| {
            drop(Volume {
                at: nothing.path().to_path_buf(),
                attached: true,
            });
        });
        let ended = said(&*ended.expect_err("the volume fails the case that holds it"));
        assert!(ended.contains("was not detached"), "{ended}");
        let failing = std::panic::catch_unwind(|| {
            let _volume = Volume {
                at: nothing.path().to_path_buf(),
                attached: true,
            };
            panic!("the case's own failure");
        });
        assert_eq!(
            said(&*failing.expect_err("the case fails")),
            "the case's own failure"
        );
    }

    /// A listing of what `lsof -F pcn` shows gives each process by number and name, with the files it
    /// has open, once each.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_processes_with_files_open_are_read_from_lsof_field_output() {
        let listing = "p101\ncsleep\nfcwd\nn/volumes/a\nftxt\nn/volumes/a/log\nftxt\nn/volumes/a/log\n\
                       p202\ncgit\nf3\nn/dev/disk15\n";
        let holders = super::holders_in(listing);
        assert_eq!(
            holders,
            vec![
                super::Holder {
                    pid: "101".to_owned(),
                    command: "sleep".to_owned(),
                    files: vec!["/volumes/a".to_owned(), "/volumes/a/log".to_owned()],
                },
                super::Holder {
                    pid: "202".to_owned(),
                    command: "git".to_owned(),
                    files: vec!["/dev/disk15".to_owned()],
                },
            ]
        );
        assert!(super::holders_in("").is_empty());
    }

    /// An `hdiutil info` listing gives, for the image a disk belongs to, the devices of that image
    /// and the process serving it, and nothing of the other images.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_image_of_a_disk_and_its_process_are_read_from_hdiutil_info() {
        let listing = "framework       : 600\n\
                       ================================================\n\
                       image-path      : /tmp/one.dmg\n\
                       process ID      : 41\n\
                       /dev/disk14         \tGUID_partition_scheme\n\
                       /dev/disk14s1       \tApple_APFS\n\
                       /dev/disk15         \tEF57347C-0000-11AA-AA11-00306543ECAC\n\
                       /dev/disk15s1       \t41504653-0000-11AA-AA11-00306543ECAC\t/tmp/mount\n\
                       ================================================\n\
                       image-path      : /tmp/two.dmg\n\
                       process ID      : 52\n\
                       /dev/disk1          \tGUID_partition_scheme\n\
                       /dev/disk1s1        \tApple_HFS\t/tmp/other\n";
        let (devices, servers) = super::image_of(listing, "/dev/disk15");
        assert_eq!(
            devices,
            [
                "/dev/disk14",
                "/dev/disk14s1",
                "/dev/disk15",
                "/dev/disk15s1"
            ]
        );
        assert_eq!(servers, ["41"]);
        // A disk whose number only begins the same is not the same disk.
        let (devices, servers) = super::image_of(listing, "/dev/disk1");
        assert_eq!(devices, ["/dev/disk1", "/dev/disk1s1"]);
        assert_eq!(servers, ["52"]);
        assert_eq!(
            super::image_of(listing, "/dev/disk99"),
            (Vec::new(), Vec::new())
        );
    }
}
