//! Where the stand-in writes the record of a turn: inside the run it was started in, and nowhere
//! else.
//!
//! The run's root is the directory that the run's temporary directory (`TMPDIR`) lies in. It must
//! carry the mark that only a run has: its name is `krm-` and eight lowercase hexadecimal digits,
//! and its mode is `0700`. The agent folder (`CODEX_HOME`) must be an absolute path with no `..`
//! part, inside that root. The root's own path is opened one part at a time from `/` with no link
//! followed, and every directory below it, the folder's own parts and the record's, is opened the
//! same way and must lie on the root's device. The record file is opened with no link followed,
//! without blocking, and checked after: it must be a regular file with one name on the root's
//! device.
//! Anything else writes nothing.

use std::ffi::OsStr;
use std::io::Write as _;
use std::path::{Component, Path};

use rustix::fs::{Mode, OFlags};

/// Whether `path` is absolute and made of plain names: no `..` and no `.` part.
fn is_plain_and_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

/// Whether `root` has the mark that only a run's root has: its name is `krm-` and eight lowercase
/// hexadecimal digits.
fn has_a_runs_name(root: &Path) -> bool {
    root.file_name()
        .and_then(OsStr::to_str)
        .and_then(|name| name.strip_prefix("krm-"))
        .is_some_and(|digits| {
            digits.len() == 8
                && digits
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// Opens the root's own path one part at a time, from `/` or, where it is not absolute, from the
/// directory the process is in, each part with no link followed, and returns the root with what
/// the system says of it.
fn opens_root(root: &Path) -> Result<(std::os::fd::OwnedFd, rustix::fs::Stat), String> {
    let start = if root.is_absolute() { "/" } else { "." };
    let mut directory = rustix::fs::open(
        start,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("the start of the run's root cannot be opened: {error}"))?;
    for part in root.components() {
        if let Component::Normal(name) = part {
            directory = rustix::fs::openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| {
                format!("a part of the run's root path is a link or not a directory: {error}")
            })?;
        }
    }
    let status = rustix::fs::fstat(&directory)
        .map_err(|error| format!("the run's root cannot be looked at: {error}"))?;
    Ok((directory, status))
}

/// Opens the directory `name` of `directory`, which is made if it is not there, with no link
/// followed: a link, or anything that is not a directory, is refused, and so is a directory on
/// another device than `device`, as a volume mounted there would be.
fn opens_part(
    directory: &std::os::fd::OwnedFd,
    name: &OsStr,
    device: rustix::fs::Dev,
) -> Result<std::os::fd::OwnedFd, String> {
    match rustix::fs::mkdirat(directory, name, Mode::RWXU) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => {
            return Err(format!(
                "a part of the record's place cannot be made: {error}"
            ));
        }
    }
    let opened = rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        format!("a part of the record's place is a link or not a directory: {error}")
    })?;
    let status = rustix::fs::fstat(&opened)
        .map_err(|error| format!("a part of the record's place cannot be looked at: {error}"))?;
    if status.st_dev != device {
        return Err(
            "a part of the record's place lies on another device than the run's root".to_owned(),
        );
    }
    Ok(opened)
}

/// Appends `bytes` to the file `file` in the directory made of `below`, parts below the agent folder
/// `home`, where `home` lies inside the run's root: the directory `temporary` lies in.
///
/// # Errors
///
/// Returns why nothing was written: the run's temporary directory or the agent folder is not
/// absolute or has a `..` part, the folder is not inside the run's root, a part of the place is a
/// link or not a directory, or the record file is a link or has more than one name.
pub fn appends(
    home: &OsStr,
    temporary: Option<&OsStr>,
    below: &[&str],
    file: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let home = Path::new(home);
    let temporary = Path::new(
        temporary.ok_or("the run's temporary directory is not named, so the run is not known")?,
    );
    for (what, path) in [
        ("the run's temporary directory", temporary),
        ("the agent folder", home),
    ] {
        if !is_plain_and_absolute(path) {
            return Err(format!("{what} is not an absolute path of plain names"));
        }
    }
    let root = temporary
        .parent()
        .filter(|root| root.file_name().is_some())
        .ok_or("the run's temporary directory lies in no run's root")?;
    let inside = home
        .strip_prefix(root)
        .map_err(|_| "the agent folder is not inside the run's root".to_owned())?;
    for part in below.iter().chain(&[file]) {
        if part.is_empty() || part.contains('/') || *part == "." || *part == ".." {
            return Err(format!("{part:?} is not a plain name"));
        }
    }
    if !has_a_runs_name(root) {
        return Err("the run's root has not the name only a run's root has".to_owned());
    }
    let (mut directory, root_status) = opens_root(root)?;
    if root_status.st_mode & 0o777 != 0o700 {
        return Err("the run's root has not the mode only a run's root has".to_owned());
    }
    for part in inside
        .components()
        .map(Component::as_os_str)
        .chain(below.iter().map(OsStr::new))
    {
        directory = opens_part(&directory, part, root_status.st_dev)?;
    }
    opens_record(&directory, file, root_status.st_dev)?
        .write_all(bytes)
        .map_err(|error| format!("the record file cannot be written: {error}"))
}

/// The record file `file` in `directory`, opened to be appended to: with no link followed and
/// without blocking (a pipe at its name must not hold the writer), and then looked at through the
/// handle, so that what was opened is what is checked. It must be a regular file with one name on
/// the device `device`, the run's root's, as every directory above it is.
fn opens_record(
    directory: &std::os::fd::OwnedFd,
    file: &str,
    device: rustix::fs::Dev,
) -> Result<std::fs::File, String> {
    let handle = rustix::fs::openat(
        directory,
        file,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::APPEND
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|error| format!("the record file is a link or cannot be opened: {error}"))?;
    let status = rustix::fs::fstat(&handle)
        .map_err(|error| format!("the record file cannot be looked at: {error}"))?;
    if status.st_nlink != 1
        || rustix::fs::FileType::from_raw_mode(status.st_mode) != rustix::fs::FileType::RegularFile
    {
        return Err("the record file is not a regular file with one name".to_owned());
    }
    if status.st_dev != device {
        return Err("the record file lies on another device than the run's root".to_owned());
    }
    Ok(std::fs::File::from(handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    /// A run's root and its temporary directory, in a directory of its own.
    fn a_run(name: &str) -> (PathBuf, PathBuf) {
        let base =
            std::env::temp_dir().join(format!("kr-stand-in-record-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("krm-0a1b2c3d");
        std::fs::create_dir_all(root.join("tmp")).expect("a run");
        std::fs::create_dir_all(root.join("agent-config")).expect("an agent folder");
        std::fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("the mode of a run's root");
        (std::fs::canonicalize(&root).expect("a root"), base)
    }

    fn appends_in(home: &Path, temporary: Option<&Path>) -> Result<(), String> {
        appends(
            home.as_os_str(),
            temporary.map(Path::as_os_str),
            &["sessions", "2026", "11", "11"],
            "rollout-t.jsonl",
            b"{}\n",
        )
    }

    #[test]
    fn a_record_is_written_inside_the_run_below_the_agent_folder() {
        let (root, base) = a_run("inside");
        let home = root.join("agent-config");
        appends_in(&home, Some(&root.join("tmp"))).expect("written");
        appends_in(&home, Some(&root.join("tmp"))).expect("appended");
        let record = home.join("sessions/2026/11/11/rollout-t.jsonl");
        assert_eq!(
            std::fs::read_to_string(record).expect("a record"),
            "{}\n{}\n"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn nothing_is_written_where_the_agent_folder_is_not_a_plain_absolute_path_inside_the_run() {
        let (root, base) = a_run("refused");
        let temporary = root.join("tmp");
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).expect("an outside directory");
        let written = |place: &Path| place.join("sessions").exists();
        // No run is named.
        assert!(appends_in(&root.join("agent-config"), None).is_err());
        assert!(!written(&root.join("agent-config")));
        // A relative or an empty agent folder resolves from the directory the process is in.
        assert!(appends_in(Path::new("agent-config"), Some(&temporary)).is_err());
        assert!(appends_in(Path::new(""), Some(&temporary)).is_err());
        // A `..` part: the folder only seems to be inside the run.
        let sideways = root.join("agent-config/../../outside");
        assert!(appends_in(&sideways, Some(&temporary)).is_err());
        assert!(!written(&outside), "nothing was written outside the run");
        // An absolute folder outside the run's root.
        assert!(appends_in(&outside, Some(&temporary)).is_err());
        assert!(!written(&outside), "nothing was written outside the run");
        // A temporary directory that is not plain, or that lies in no root.
        let dotted = root.join("tmp/../tmp");
        assert!(appends_in(&root.join("agent-config"), Some(&dotted)).is_err());
        assert!(appends_in(&root.join("agent-config"), Some(Path::new("/"))).is_err());
        assert!(appends_in(&root.join("agent-config"), Some(Path::new("tmp"))).is_err());
        // A temporary directory directly below `/`: the run's root would be every directory there is.
        assert!(appends_in(&root.join("agent-config"), Some(Path::new("/tmp"))).is_err());
        assert!(!written(&root.join("agent-config")), "nothing was written");
        // Both relative: the run's root would be a directory of the directory the process is in.
        let previous = std::env::current_dir().expect("a directory");
        std::env::set_current_dir(&base).expect("the directory the run is in");
        let relative = appends_in(
            Path::new("krm-0a1b2c3d/agent-config"),
            Some(Path::new("krm-0a1b2c3d/tmp")),
        );
        std::env::set_current_dir(previous).expect("back where it was");
        assert!(relative.is_err(), "a relative run is refused");
        assert!(!written(&root.join("agent-config")), "nothing was written");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn no_link_is_followed_to_a_place_outside_the_run() {
        let (root, base) = a_run("links");
        let temporary = root.join("tmp");
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).expect("an outside directory");
        let home = root.join("agent-config");
        // The record's own directory is a link to a directory outside the run.
        symlink(&outside, home.join("sessions")).expect("a link");
        assert!(appends_in(&home, Some(&temporary)).is_err());
        assert_eq!(std::fs::read_dir(&outside).expect("a directory").count(), 0);
        std::fs::remove_file(home.join("sessions")).expect("removed");
        // The agent folder is a link to a directory outside the run.
        std::fs::remove_dir_all(&home).expect("removed");
        symlink(&outside, &home).expect("a link");
        assert!(appends_in(&home, Some(&temporary)).is_err());
        assert_eq!(std::fs::read_dir(&outside).expect("a directory").count(), 0);
        std::fs::remove_file(&home).expect("removed");
        std::fs::create_dir_all(&home).expect("an agent folder");
        // The record file is a link to a file outside the run.
        let place = home.join("sessions/2026/11/11");
        std::fs::create_dir_all(&place).expect("a place");
        std::fs::write(outside.join("theirs"), "kept").expect("a file");
        symlink(outside.join("theirs"), place.join("rollout-t.jsonl")).expect("a link");
        assert!(appends_in(&home, Some(&temporary)).is_err());
        assert_eq!(
            std::fs::read_to_string(outside.join("theirs")).expect("a file"),
            "kept"
        );
        std::fs::remove_file(place.join("rollout-t.jsonl")).expect("removed");
        // The record file has a second name, which may be a file outside the run.
        std::fs::hard_link(outside.join("theirs"), place.join("rollout-t.jsonl")).expect("a link");
        assert!(appends_in(&home, Some(&temporary)).is_err());
        assert_eq!(
            std::fs::read_to_string(outside.join("theirs")).expect("a file"),
            "kept"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn nothing_is_written_where_the_root_has_not_the_mark_only_a_run_has() {
        let (root, base) = a_run("mark");
        let home = root.join("agent-config");
        // A root with another name: a directory of a person that holds a `tmp` and a folder.
        let canonical_base = root.parent().expect("a base").to_path_buf();
        let other = canonical_base.join("work");
        std::fs::create_dir_all(other.join("tmp")).expect("a directory");
        std::fs::create_dir_all(other.join("agent-config")).expect("a folder");
        std::fs::set_permissions(&other, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("the mode");
        assert!(appends_in(&other.join("agent-config"), Some(&other.join("tmp"))).is_err());
        assert!(!other.join("agent-config/sessions").exists());
        // The name of a run's root and another mode.
        std::fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("the mode");
        assert!(appends_in(&home, Some(&root.join("tmp"))).is_err());
        assert!(!home.join("sessions").exists());
        std::fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("the mode");
        appends_in(&home, Some(&root.join("tmp"))).expect("written where the mark is");
        // Names that only look like it.
        for name in [
            "krm-0A1B2C3D",
            "krm-0a1b2c3",
            "krm-0a1b2c3d4",
            "krm-0a1b2c3g",
            "run-0a1b2c3d",
        ] {
            let looks = canonical_base.join(name);
            std::fs::create_dir_all(looks.join("tmp")).expect("a directory");
            std::fs::create_dir_all(looks.join("agent-config")).expect("a folder");
            std::fs::set_permissions(&looks, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .expect("the mode");
            assert!(
                appends_in(&looks.join("agent-config"), Some(&looks.join("tmp"))).is_err(),
                "{name}"
            );
        }
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn the_roots_own_path_is_opened_with_no_link_followed_and_no_part_on_another_device() {
        let (root, base) = a_run("path");
        // A link above the root: the root is reached through it.
        let through = base.join("through");
        std::os::unix::fs::symlink(&base, &through).expect("a link");
        let name = root.file_name().expect("a name").to_owned();
        let linked = through.join(&name);
        assert!(
            appends_in(&linked.join("agent-config"), Some(&linked.join("tmp"))).is_err(),
            "a link in the root's own path is not followed"
        );
        assert!(!root.join("agent-config/sessions").exists());
        // A part on another device than the root's: the check that the parts are on the root's
        // device refuses what it is told is another device.
        let (directory, status) = opens_root(&root).expect("the root");
        assert!(opens_part(&directory, OsStr::new("agent-config"), status.st_dev).is_ok());
        assert!(
            opens_part(&directory, OsStr::new("agent-config"), status.st_dev + 1).is_err(),
            "another device is refused"
        );
        // The record file itself on another device than the root's: refused, and nothing written.
        let (directory, status) = opens_root(&root).expect("the root");
        let place =
            opens_part(&directory, OsStr::new("agent-config"), status.st_dev).expect("a place");
        assert!(opens_record(&place, "rollout-t.jsonl", status.st_dev).is_ok());
        assert!(
            opens_record(&place, "rollout-t.jsonl", status.st_dev + 1).is_err(),
            "a file on another device is refused"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn a_pipe_at_the_records_name_does_not_hold_the_writer() {
        let (root, base) = a_run("pipe");
        let home = root.join("agent-config");
        let place = home.join("sessions/2026/11/11");
        std::fs::create_dir_all(&place).expect("a place");
        let made = std::process::Command::new("/usr/bin/mkfifo")
            .arg(place.join("rollout-t.jsonl"))
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "a pipe is made");
        let (sent, received) = std::sync::mpsc::channel();
        let temporary = root.join("tmp");
        std::thread::spawn(move || {
            let _ = sent.send(appends_in(&home, Some(&temporary)));
        });
        let result = received
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the writer was held by a pipe at the record's name");
        assert!(result.is_err(), "a pipe is not a record");
        let _ = std::fs::remove_dir_all(base);
    }
}
