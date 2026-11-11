//! Where the stand-in writes the record of a turn: inside the run it was started in, and nowhere
//! else.
//!
//! The run's root is the directory that the run's temporary directory (`TMPDIR`) lies in. The agent
//! folder (`CODEX_HOME`) must be an absolute path with no `..` part, inside that root. The root is
//! opened, and every directory below it, the folder's own parts and the record's, is opened one part
//! at a time relative to the one before, with no link followed; the record file is opened with no
//! link followed and must have one name. Anything else writes nothing.

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

/// Opens the directory `name` of `directory`, which is made if it is not there, with no link
/// followed: a link, or anything that is not a directory, is refused.
fn opens_part(
    directory: &std::os::fd::OwnedFd,
    name: &OsStr,
) -> Result<std::os::fd::OwnedFd, String> {
    match rustix::fs::mkdirat(directory, name, Mode::RWXU) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => {
            return Err(format!(
                "a part of the record's place cannot be made: {error}"
            ));
        }
    }
    rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("a part of the record's place is a link or not a directory: {error}"))
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
    let mut directory = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("the run's root cannot be opened: {error}"))?;
    for part in inside
        .components()
        .map(Component::as_os_str)
        .chain(below.iter().map(OsStr::new))
    {
        directory = opens_part(&directory, part)?;
    }
    let handle = rustix::fs::openat(
        &directory,
        file,
        OFlags::WRONLY | OFlags::CREATE | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::CLOEXEC,
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
    std::fs::File::from(handle)
        .write_all(bytes)
        .map_err(|error| format!("the record file cannot be written: {error}"))
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
        let root = base.join("run");
        std::fs::create_dir_all(root.join("tmp")).expect("a run");
        std::fs::create_dir_all(root.join("agent-config")).expect("an agent folder");
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
        let relative = appends_in(Path::new("run/agent-config"), Some(Path::new("run/tmp")));
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
}
