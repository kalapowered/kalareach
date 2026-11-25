//! The directory in which the harness reads the databases of a run through copies. The agent runs
//! in the same account as the harness and can replace anything below the run, so the copies are
//! made in a directory of the harness's own, made by it beside the run's directory and pinned from
//! the handle it was opened by. Every use reaches the directory through that pin with no link
//! followed, refuses a directory or an entry that is not as the harness left it before anything is
//! removed or written, and writes and removes by the directory's handle.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use rusqlite::{Connection, OpenFlags};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};

use crate::run::{
    Refusal, Removal, RootPin, current_place, directory_below, make_root, one_name, open_directory,
    remove_run_directory, run_base,
};

/// The directory of the copies: made by the harness, pinned, and removed when it is dropped.
#[derive(Debug)]
pub struct Copies {
    root: PathBuf,
    pin: RootPin,
    /// The directories the harness made in it, by name, with their device and inode.
    made: Mutex<BTreeMap<String, (i128, i128)>>,
}

impl Copies {
    /// Makes the directory of the copies, below the directory a run is made below, and pins it.
    ///
    /// # Errors
    ///
    /// Returns why the directory was not made or is not the directory that was made.
    pub fn make() -> Result<Self, String> {
        let (root, pin) = make_root(
            &run_base(),
            &mut || kr_ipc::new_uuid().to_string(),
            &mut |_| {},
        )
        .map_err(|why| format!("the directory for the database copies: {why}"))?;
        Ok(Self {
            root,
            pin,
            made: Mutex::new(BTreeMap::new()),
        })
    }

    /// Copies `main` and, where there is one, `wal` into the directory of `database`, which the
    /// harness makes the first time, and gives `read` a connection to the copy of `file`.
    ///
    /// The directory is reached through the pin and must be what the harness made, owner-only; it
    /// may hold only the files of a copy, each a regular file of the account with one name, and
    /// otherwise nothing is removed or written. The copy is made by exclusive creation through the
    /// directory's handle and opened with no link followed at its own name. The directory is
    /// checked again after the read, and its files are removed.
    ///
    /// # Errors
    ///
    /// Returns why the directory or a file in it is not as the harness left it, or the copy could
    /// not be written or read.
    pub fn read<T>(
        &self,
        database: &str,
        file: &str,
        main: &[u8],
        wal: Option<&[u8]>,
        read: impl FnOnce(&Connection) -> Result<T, String>,
    ) -> Result<T, String> {
        self.read_by(database, file, main, wal, &mut |_| {}, read)
    }

    /// [`Copies::read`] with a hook that is called just before the copy is opened and is given the
    /// copy's place, where a test changes what is there.
    pub(crate) fn read_by<T>(
        &self,
        database: &str,
        file: &str,
        main: &[u8],
        wal: Option<&[u8]>,
        before_open: &mut dyn FnMut(&Path),
        read: impl FnOnce(&Connection) -> Result<T, String>,
    ) -> Result<T, String> {
        let database = one_name(database)?;
        let file = one_name(file)?;
        let names = [
            file.clone(),
            format!("{file}-wal"),
            format!("{file}-shm"),
            format!("{file}-journal"),
        ];
        let directory = self.directory(&database)?;
        clear(&directory, &names)?;
        write(&directory, &file, main)?;
        if let Some(wal) = wal {
            write(&directory, &format!("{file}-wal"), wal)?;
        }
        let path = current_place(&directory)
            .ok_or_else(|| "the system names no place for the copies' directory".to_owned())?
            .join(&file);
        before_open(&path);
        let found = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|why| why.to_string())
        .and_then(|connection| read(&connection));
        // The directory is reached again from the pin: a link or another directory put in its
        // place while the copy was read is refused, and what was read is not used.
        self.directory(&database)
            .map_err(|why| format!("after the copy was read: {why}"))?;
        clear(&directory, &names).map_err(|why| format!("after the copy was read: {why}"))?;
        found
    }

    /// The handle of the directory for `database`: made the first time and only then, reached from
    /// the pin with no link followed, and checked to be the directory that was made and owner-only.
    fn directory(&self, database: &str) -> Result<std::os::fd::OwnedFd, String> {
        let said = |why: &dyn std::fmt::Display| {
            format!("the copies' directory for {database} is not as the harness made it: {why}")
        };
        let mut made = self.made.lock().unwrap_or_else(PoisonError::into_inner);
        let known = made.get(database).copied();
        let handle = match (
            directory_below(&self.root, &self.pin, Path::new(database)),
            known,
        ) {
            (Ok(handle), Some(_)) => handle,
            (Ok(_), None) => return Err(said(&"the harness did not make it")),
            (Err(Refusal::Missing), None) => {
                let root = open_directory(&self.root).map_err(|why| said(&why))?;
                if !self.pin.holds(&root) {
                    return Err(said(&Refusal::RootChanged));
                }
                rustix::fs::mkdirat(&root, database, Mode::from_raw_mode(0o700))
                    .map_err(|why| said(&why))?;
                let handle = directory_below(&self.root, &self.pin, Path::new(database))
                    .map_err(|why| said(&why))?;
                made.insert(database.to_owned(), object_of(&handle)?);
                handle
            }
            (Err(Refusal::Missing), Some(_)) => return Err(said(&"it is gone")),
            (Err(why), _) => return Err(said(&why)),
        };
        if known.is_some_and(|was| Ok(was) != object_of(&handle)) {
            return Err(said(&"it is another directory"));
        }
        let stat = rustix::fs::fstat(&handle).map_err(|why| said(&why))?;
        if stat.st_uid != rustix::process::getuid().as_raw() || stat.st_mode & 0o077 != 0 {
            return Err(said(&"it is not owner-only"));
        }
        Ok(handle)
    }
}

impl Drop for Copies {
    fn drop(&mut self) {
        if let Removal::Left(why) = remove_run_directory(&self.root, &self.pin) {
            eprintln!("the directory of the database copies is left in place: {why}");
        }
    }
}

/// The device and inode of the directory `handle` is open on.
fn object_of(handle: &std::os::fd::OwnedFd) -> Result<(i128, i128), String> {
    let stat = rustix::fs::fstat(handle).map_err(|why| why.to_string())?;
    Ok((i128::from(stat.st_dev), i128::from(stat.st_ino)))
}

/// The names in the directory `handle`, listed through a handle of their own so that the listing
/// starts at the first entry.
fn listed(handle: &std::os::fd::OwnedFd) -> Result<Vec<String>, String> {
    let fresh = rustix::fs::openat(
        handle,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|why| format!("the copies' directory cannot be listed: {why}"))?;
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(&fresh)
        .map_err(|why| format!("the copies' directory cannot be listed: {why}"))?
    {
        let entry =
            entry.map_err(|why| format!("the copies' directory cannot be listed: {why}"))?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push(String::from_utf8_lossy(name).into_owned());
        }
    }
    Ok(names)
}

/// Removes the copies in `directory`, after every entry has been shown to be one of `names` and a
/// regular file of the account with one name: where one is not, nothing is removed.
fn clear(directory: &std::os::fd::OwnedFd, names: &[String]) -> Result<(), String> {
    let found = listed(directory)?;
    let uid = rustix::process::getuid().as_raw();
    for name in &found {
        if !names.contains(name) {
            return Err(format!(
                "the copies' directory holds {name}, which the harness did not put there"
            ));
        }
        let stat = rustix::fs::statat(directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|why| format!("the copies' {name} cannot be looked at: {why}"))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_nlink != 1
            || stat.st_uid != uid
        {
            return Err(format!(
                "the copies' {name} is not a regular file of the account with one name"
            ));
        }
    }
    for name in &found {
        rustix::fs::unlinkat(directory, name.as_str(), AtFlags::empty())
            .map_err(|why| format!("the copies' {name} cannot be removed: {why}"))?;
    }
    Ok(())
}

/// Makes the file `name` in `directory` with `bytes`: it must not be there, and no link is
/// followed at its name.
fn write(directory: &std::os::fd::OwnedFd, name: &str, bytes: &[u8]) -> Result<(), String> {
    let made = rustix::fs::openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|why| format!("the copy {name} is not made: {why}"))?;
    std::fs::File::from(made)
        .write_all(bytes)
        .map_err(|why| format!("the copy {name} is not written: {why}"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    const LEFT: &[u8] = b"left by the agent";

    /// A scratch directory of this test's own.
    fn scratch() -> PathBuf {
        let directory = std::fs::canonicalize(std::env::temp_dir())
            .expect("the temporary directory")
            .join(format!(
                "kc-copies-{}",
                &kr_ipc::new_uuid().to_string()[..8]
            ));
        std::fs::create_dir_all(&directory).expect("a scratch directory");
        directory
    }

    /// The bytes of a database with one table that holds the row 7.
    fn database() -> Vec<u8> {
        let directory = scratch();
        let path = directory.join("db.sqlite");
        Connection::open(&path)
            .expect("a database")
            .execute_batch("CREATE TABLE t (n INTEGER); INSERT INTO t VALUES (7);")
            .expect("a row");
        let bytes = std::fs::read(&path).expect("the database's bytes");
        std::fs::remove_dir_all(&directory).expect("clean up");
        bytes
    }

    fn row(connection: &Connection) -> Result<i64, String> {
        connection
            .query_row("SELECT n FROM t", [], |row| row.get(0))
            .map_err(|why| why.to_string())
    }

    /// The names in `directory`, sorted.
    fn names_in(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(directory)
            .expect("a directory")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    /// A directory outside the copies that holds a file of the agent's for each of `names`.
    fn elsewhere(names: &[&str]) -> PathBuf {
        let directory = scratch();
        for name in names {
            std::fs::write(directory.join(name), LEFT).expect("a file");
        }
        directory
    }

    fn untouched(directory: &Path, names: &[&str]) {
        assert_eq!(
            names_in(directory),
            names.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "nothing was made or removed outside the harness's directory"
        );
        for name in names {
            assert_eq!(
                std::fs::read(directory.join(name)).ok().as_deref(),
                Some(LEFT),
                "{name} outside the harness's directory is as the agent left it"
            );
        }
    }

    /// A first read makes the directory of the database.
    fn made(copies: &Copies, main: &[u8]) {
        assert_eq!(
            copies.read("db", "index.sqlite", main, None, row),
            Ok(7),
            "a first read"
        );
    }

    /// The directory of the copies is owner-only, a copy is read through a connection of its own,
    /// the directory the copy was in is left empty, and dropping the copies removes everything.
    #[test]
    fn a_copy_is_read_and_its_directory_is_left_empty_and_removed_with_the_copies() {
        let copies = Copies::make().expect("a directory for the copies");
        let root = copies.root.clone();
        made(&copies, &database());
        assert_eq!(names_in(&root.join("db")), Vec::<String>::new());
        for directory in [&root, &root.join("db")] {
            assert_eq!(
                std::fs::metadata(directory)
                    .expect("a directory")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700,
                "the directories of the copies are owner-only"
            );
        }
        drop(copies);
        assert!(
            !root.exists(),
            "the copies' directory is removed with the copies"
        );
    }

    /// A link where the directory of a database was made is not followed: the read is refused and
    /// nothing outside is removed or written.
    #[test]
    fn a_link_in_the_place_of_a_directory_of_copies_is_refused_and_nothing_outside_is_changed() {
        let copies = Copies::make().expect("a directory for the copies");
        let main = database();
        made(&copies, &main);
        let outside = elsewhere(&["index.sqlite", "index.sqlite-wal", "index.sqlite-shm"]);
        std::fs::remove_dir(copies.root.join("db")).expect("the empty directory goes");
        std::os::unix::fs::symlink(&outside, copies.root.join("db")).expect("a link");
        let refused = copies
            .read("db", "index.sqlite", &main, None, row)
            .expect_err("a read through a link is refused");
        assert!(
            refused.contains("not as the harness made it"),
            "the refusal says why: {refused}"
        );
        untouched(
            &outside,
            &["index.sqlite", "index.sqlite-shm", "index.sqlite-wal"],
        );
        std::fs::remove_dir_all(&outside).expect("clean up");
    }

    /// A directory that the harness did not make, at the name of one it did not make yet or in the
    /// place of one it made, is refused, and what it holds is not removed.
    #[test]
    fn a_directory_that_the_harness_did_not_make_is_refused_and_what_it_holds_stays() {
        let copies = Copies::make().expect("a directory for the copies");
        let main = database();
        let before = copies.root.join("early");
        std::fs::create_dir(&before).expect("a directory made first");
        std::fs::set_permissions(&before, std::fs::Permissions::from_mode(0o700)).expect("mode");
        std::fs::write(before.join("index.sqlite"), LEFT).expect("a file");
        let refused = copies
            .read("early", "index.sqlite", &main, None, row)
            .expect_err("a directory the harness did not make is refused");
        assert!(refused.contains("the harness did not make it"), "{refused}");
        untouched(&before, &["index.sqlite"]);
        made(&copies, &main);
        let place = copies.root.join("db");
        std::fs::rename(&place, copies.root.join("db-moved")).expect("moved away");
        std::fs::create_dir(&place).expect("another directory");
        std::fs::set_permissions(&place, std::fs::Permissions::from_mode(0o700)).expect("mode");
        std::fs::write(place.join("index.sqlite"), LEFT).expect("a file");
        let refused = copies
            .read("db", "index.sqlite", &main, None, row)
            .expect_err("another directory in the place of the one made is refused");
        assert!(refused.contains("it is another directory"), "{refused}");
        untouched(&place, &["index.sqlite"]);
    }

    /// An entry in a directory of copies that is not a copy's own name, and a copy's name that is a
    /// link or has a second name, are refused before anything in the directory is removed.
    #[test]
    fn an_entry_that_is_not_a_copy_is_refused_before_anything_is_removed() {
        let copies = Copies::make().expect("a directory for the copies");
        let main = database();
        made(&copies, &main);
        let place = copies.root.join("db");
        let outside = elsewhere(&["target"]);
        std::fs::write(place.join("index.sqlite"), b"stale").expect("a stale copy");
        for name in ["other", "index.sqlite-wal", "index.sqlite-shm"] {
            let path = place.join(name);
            match name {
                "other" => std::fs::write(&path, LEFT).expect("a file"),
                "index.sqlite-wal" => {
                    std::os::unix::fs::symlink(outside.join("target"), &path).expect("a link");
                }
                _ => std::fs::hard_link(outside.join("target"), &path).expect("a second name"),
            }
            let refused = copies
                .read("db", "index.sqlite", &main, None, row)
                .expect_err("the entry is refused");
            assert!(
                refused.contains(name),
                "the refusal names {name}: {refused}"
            );
            assert_eq!(
                std::fs::read(place.join("index.sqlite")).ok().as_deref(),
                Some(&b"stale"[..]),
                "the stale copy was not removed beside {name}"
            );
            std::fs::remove_file(place.join(name)).expect("the entry goes");
        }
        untouched(&outside, &["target"]);
        std::fs::remove_dir_all(&outside).expect("clean up");
    }

    /// The copy is opened with no link followed at its own name: a link put there after the copy
    /// was written is not opened, whatever it names.
    #[test]
    fn a_link_put_at_the_name_of_the_copy_before_it_is_opened_is_not_followed() {
        let copies = Copies::make().expect("a directory for the copies");
        let main = database();
        let outside = scratch();
        std::fs::write(outside.join("other.sqlite"), &main).expect("another database");
        let mut read = false;
        let refused = copies.read_by(
            "db",
            "index.sqlite",
            &main,
            None,
            &mut |path| {
                std::fs::remove_file(path).expect("the copy goes");
                std::os::unix::fs::symlink(outside.join("other.sqlite"), path).expect("a link");
            },
            |connection| {
                read = true;
                row(connection)
            },
        );
        assert!(refused.is_err(), "the read is refused: {refused:?}");
        assert!(!read, "the database a link names was read");
        assert_eq!(
            names_in(&outside),
            ["other.sqlite"],
            "nothing was made beside the database the link names"
        );
        assert_eq!(
            std::fs::read(outside.join("other.sqlite")).expect("the database"),
            main,
            "the database the link names is as it was"
        );
        std::fs::remove_dir_all(&outside).expect("clean up");
    }

    /// A directory that is not the one the harness made at the copies' own place, moved there while
    /// the harness's own is beside it, is refused and nothing in it is removed or written.
    #[test]
    fn a_directory_in_the_place_of_the_copies_directory_is_refused() {
        let copies = Copies::make().expect("a directory for the copies");
        let main = database();
        made(&copies, &main);
        let moved = copies.root.with_extension("moved");
        std::fs::rename(&copies.root, &moved).expect("moved away");
        std::fs::create_dir(&copies.root).expect("another directory");
        std::fs::set_permissions(&copies.root, std::fs::Permissions::from_mode(0o700))
            .expect("mode");
        std::fs::create_dir(copies.root.join("db")).expect("a directory of copies");
        std::fs::write(copies.root.join("db/index.sqlite"), LEFT).expect("a file");
        let refused = copies
            .read("db", "index.sqlite", &main, None, row)
            .expect_err("another directory at the place is refused");
        assert!(
            refused.contains("the run's directory is not the directory the run made"),
            "the refusal says the pinned directory is not there: {refused}"
        );
        untouched(&copies.root.join("db"), &["index.sqlite"]);
        std::fs::remove_dir_all(&copies.root).expect("the other directory goes");
        std::fs::rename(&moved, &copies.root).expect("moved back");
    }
}
