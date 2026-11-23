//! The record writer's checks on Windows, where a file's links, device and mode are read another
//! way.
//!
//! The Unix writer opens the run's root and each directory below it from the one above with no
//! link followed, and looks at each through its descriptor. Here the root is opened as itself (a
//! junction or a symbolic link is the point and not what it names), each directory below is opened
//! from the handle of the one above, and each is looked at through its handle: a reparse point is
//! refused, so is a directory on another volume, and so is a file that is not a plain file with one
//! name. Where the Unix writer reads the mode of the root, this one reads its access list through
//! the handle and refuses a list that names an account the host does not trust, as the host does
//! for its own private directories. The record file is made with an owner-only protected list, and
//! the file at its name is compared by volume and index before the write and after it, so a name
//! that was swapped for another file in between is found.
//!
//! The parts of the root's own path above the root are not walked: a profile's folders may be
//! redirected, and the root's mark and list are what say it is a run's.

#![expect(
    unsafe_code,
    reason = "reading a file's attributes, links and identity through its handle has no safe form"
)]

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsHandle as _, AsRawHandle as _};
use std::path::Path;

use kr_ipc::paths::{
    AccessListRefusal, check_access_list, open_child, protect_with_owner_only_list,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    GetFileInformationByHandle, READ_CONTROL, SYNCHRONIZE, WRITE_DAC,
};

/// What a handle says of its file.
struct Reading {
    attributes: u32,
    links: u32,
    /// The volume's serial number and the file's index on it: the file, whatever its name.
    identity: (u32, u64),
}

/// Reads what the open handle says of its file.
fn read(file: &File) -> Result<Reading, String> {
    // SAFETY: all zeroes is a valid state of the structure, which the call then fills.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open for the call and the structure is a local.
    let read = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) };
    if read == 0 {
        return Err(format!(
            "a file cannot be looked at: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(Reading {
        attributes: information.dwFileAttributes,
        links: information.nNumberOfLinks,
        identity: (
            information.dwVolumeSerialNumber,
            u64::from(information.nFileIndexHigh) << 32 | u64::from(information.nFileIndexLow),
        ),
    })
}

/// The text of a refusal of an access list.
fn refused(refusal: AccessListRefusal) -> String {
    match refusal {
        AccessListRefusal::Unreadable(why) | AccessListRefusal::Policy(why) => why,
    }
}

/// The directory `path` as itself, with the rights to read its attributes and its list.
fn opens_directory(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | FILE_TRAVERSE | READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Opens the directory `name` of `directory`, which lies at `path` and is made if it is not there:
/// a link, anything that is not a directory and a directory on another volume than `volume` are
/// refused.
fn opens_part(directory: &File, path: &Path, name: &OsStr, volume: u32) -> Result<File, String> {
    let from_the_handle = || {
        open_child(directory.as_handle(), name)
            .map_err(|error| format!("a part of the record's place cannot be opened: {error}"))
    };
    let opened = match from_the_handle()? {
        Some(opened) => opened,
        None => {
            match std::fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "a part of the record's place cannot be made: {error}"
                    ));
                }
            }
            from_the_handle()?.ok_or("a part of the record's place is gone after it was made")?
        }
    };
    let reading = read(&opened)?;
    if reading.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || reading.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err("a part of the record's place is a link or not a directory".to_owned());
    }
    if reading.identity.0 != volume {
        return Err(
            "a part of the record's place lies on another volume than the run's root".to_owned(),
        );
    }
    Ok(opened)
}

/// The identity of the file at `name` in `directory`, opened from the directory's handle with no
/// link followed.
fn named(directory: &File, name: &str) -> Result<(u32, u64), String> {
    let file = open_child(directory.as_handle(), OsStr::new(name))
        .map_err(|error| format!("the record file cannot be opened by its name: {error}"))?
        .ok_or("the record file has no name any more")?;
    Ok(read(&file)?.identity)
}

/// Writes `bytes` to the end of the record file `file` in `directory`, which lies at `place`, made
/// with a protected list that names its owner and nothing else if it is not there.
fn appends_to_record(
    directory: &File,
    place: &Path,
    file: &str,
    volume: u32,
    bytes: &[u8],
) -> Result<(), String> {
    let path = place.join(file);
    let there = open_child(directory.as_handle(), OsStr::new(file))
        .map_err(|error| format!("the record file cannot be opened: {error}"))?
        .is_some();
    if !there {
        let made = OpenOptions::new()
            .access_mode(FILE_APPEND_DATA | WRITE_DAC | SYNCHRONIZE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path);
        match made {
            Ok(made) => protect_with_owner_only_list(made.as_handle())
                .map_err(|error| format!("the record file cannot be given its list: {error}"))?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("the record file cannot be made: {error}")),
        }
    }
    let mut record = OpenOptions::new()
        .access_mode(FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)
        .map_err(|error| format!("the record file is a link or cannot be opened: {error}"))?;
    let reading = read(&record)?;
    if reading.attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || reading.links != 1
    {
        return Err("the record file is not a regular file with one name".to_owned());
    }
    if reading.identity.0 != volume {
        return Err("the record file lies on another volume than the run's root".to_owned());
    }
    check_access_list(record.as_handle(), "the record file", true).map_err(refused)?;
    if named(directory, file)? != reading.identity {
        return Err(
            "the name of the record file leads to another file than the one opened".to_owned(),
        );
    }
    record
        .write_all(bytes)
        .map_err(|error| format!("the record file cannot be written: {error}"))?;
    if named(directory, file)? != reading.identity {
        return Err("the file at the record's name was swapped while it was written".to_owned());
    }
    Ok(())
}

/// Appends `bytes` to the record file `file` in the directory made of `inside`, the parts of the
/// agent folder below the run's root `root`, and `below`.
pub fn writes(
    root: &Path,
    inside: &Path,
    below: &[&str],
    file: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let root_directory = opens_directory(root)
        .map_err(|error| format!("the run's root cannot be opened as itself: {error}"))?;
    let reading = read(&root_directory)?;
    if reading.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || reading.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err("the run's root is a link or not a directory".to_owned());
    }
    check_access_list(root_directory.as_handle(), "the run's root", true).map_err(|refusal| {
        format!(
            "the run's root has not the list only a run's root has: {}",
            refused(refusal)
        )
    })?;
    let volume = reading.identity.0;
    let mut directory = root_directory;
    let mut place = root.to_path_buf();
    for part in inside
        .components()
        .map(std::path::Component::as_os_str)
        .chain(below.iter().map(OsStr::new))
    {
        place.push(part);
        directory = opens_part(&directory, &place, part, volume)?;
    }
    appends_to_record(&directory, &place, file, volume, bytes)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// A run's root and its temporary directory, in a directory of its own, and that directory.
    fn a_run(name: &str) -> (PathBuf, PathBuf) {
        let base =
            std::env::temp_dir().join(format!("kr-stand-in-record-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("a directory");
        let root = base.join("krm-0a1b2c3d");
        kr_ipc::paths::create_private_directory(&root).expect("a run's root");
        std::fs::create_dir_all(root.join("tmp")).expect("a run");
        std::fs::create_dir_all(root.join("agent-config")).expect("an agent folder");
        (std::fs::canonicalize(&root).expect("a root"), base)
    }

    fn appends_in(home: &Path, temporary: Option<&Path>) -> Result<(), String> {
        super::super::appends(
            home.as_os_str(),
            temporary.map(Path::as_os_str),
            &["sessions", "2026", "11", "11"],
            "rollout-t.jsonl",
            b"{}\n",
        )
    }

    /// Makes a junction at `link` to `target`, which needs no right a standard account lacks.
    fn junction(link: &Path, target: &Path) {
        let made = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .expect("cmd runs");
        assert!(made.status.success(), "{made:?}");
    }

    #[test]
    fn a_record_is_written_inside_the_run_below_the_agent_folder() {
        let (root, base) = a_run("inside");
        let home = root.join("agent-config");
        appends_in(&home, Some(&root.join("tmp"))).expect("written");
        appends_in(&home, Some(&root.join("tmp"))).expect("appended");
        let record = home.join(r"sessions\2026\11\11\rollout-t.jsonl");
        assert_eq!(
            std::fs::read_to_string(record).expect("a record"),
            "{}\n{}\n"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn nothing_is_written_where_the_agent_folder_is_not_a_plain_absolute_path_inside_the_run() {
        let (root, base) = a_run("plain");
        let temporary = root.join("tmp");
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).expect("a directory outside the run");
        for (what, home) in [
            ("relative", PathBuf::from("agent-config")),
            ("with a .. part", root.join(r"agent-config\..\..\outside")),
            ("outside the run", outside.clone()),
            ("on a share", PathBuf::from(r"\\server\share\agent-config")),
            ("with no drive", PathBuf::from(r"\agent-config")),
        ] {
            assert!(
                appends_in(&home, Some(&temporary)).is_err(),
                "an agent folder {what} is refused"
            );
        }
        assert!(
            appends_in(&root.join("agent-config"), None).is_err(),
            "a run with no temporary directory is not known"
        );
        assert_eq!(std::fs::read_dir(&outside).expect("listed").count(), 0);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn no_reparse_point_is_followed_to_a_place_outside_the_run() {
        let (root, base) = a_run("reparse");
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).expect("a directory outside the run");
        // The agent folder is a junction to a place outside the run.
        std::fs::remove_dir(root.join("agent-config")).expect("removed");
        junction(&root.join("agent-config"), &outside);
        let refused = appends_in(&root.join("agent-config"), Some(&root.join("tmp")));
        assert!(refused.is_err(), "{refused:?}");
        assert_eq!(std::fs::read_dir(&outside).expect("listed").count(), 0);
        // A part below the agent folder is a junction.
        std::fs::remove_dir(root.join("agent-config")).expect("the junction goes");
        std::fs::create_dir_all(root.join(r"agent-config\sessions")).expect("a folder");
        std::fs::remove_dir(root.join(r"agent-config\sessions")).expect("removed");
        junction(&root.join(r"agent-config\sessions"), &outside);
        let refused = appends_in(&root.join("agent-config"), Some(&root.join("tmp")));
        assert!(refused.is_err(), "{refused:?}");
        assert_eq!(std::fs::read_dir(&outside).expect("listed").count(), 0);
        // The run's root is a junction to a run.
        let linked = base.join("krm-1e2d3c4b");
        junction(&linked, &root);
        let refused = appends_in(&linked.join("agent-config"), Some(&linked.join("tmp")));
        assert!(refused.is_err(), "{refused:?}");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn nothing_is_written_where_the_root_has_not_the_mark_only_a_run_has() {
        let (root, base) = a_run("mark");
        // Another name.
        let other = base.join("run-0a1b2c3d");
        std::fs::rename(&root, &other).expect("renamed");
        let other = std::fs::canonicalize(&other).expect("a root");
        let refused = appends_in(&other.join("agent-config"), Some(&other.join("tmp")));
        assert!(refused.is_err(), "{refused:?}");
        let _ = std::fs::remove_dir_all(&base);
        // A list that names an account other than the owner's, SYSTEM and Administrators.
        let (root, base) = a_run("list");
        let home = root.join("agent-config");
        appends_in(&home, Some(&root.join("tmp"))).expect("a run's root is written to");
        let granted = std::process::Command::new("icacls.exe")
            .arg(&root)
            .args(["/grant", "*S-1-1-0:(R)"])
            .output()
            .expect("icacls runs");
        assert!(granted.status.success(), "{granted:?}");
        let refused = appends_in(&home, Some(&root.join("tmp")));
        assert!(refused.is_err(), "{refused:?}");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn a_record_file_with_two_names_is_not_written() {
        let (root, base) = a_run("names");
        let home = root.join("agent-config");
        appends_in(&home, Some(&root.join("tmp"))).expect("written");
        let record = home.join(r"sessions\2026\11\11\rollout-t.jsonl");
        std::fs::hard_link(&record, record.with_file_name("second-name")).expect("a link");
        let refused = appends_in(&home, Some(&root.join("tmp")));
        assert!(refused.is_err(), "{refused:?}");
        assert_eq!(std::fs::read_to_string(&record).expect("a record"), "{}\n");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn the_record_file_carries_a_protected_list_that_names_its_owner_and_nothing_else() {
        let (root, base) = a_run("list-of-the-file");
        let home = root.join("agent-config");
        appends_in(&home, Some(&root.join("tmp"))).expect("written");
        let record = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(home.join(r"sessions\2026\11\11\rollout-t.jsonl"))
            .expect("the record opens");
        check_access_list(record.as_handle(), "the record file", true).expect("a protected list");
        drop(record);
        let _ = std::fs::remove_dir_all(base);
    }
}
