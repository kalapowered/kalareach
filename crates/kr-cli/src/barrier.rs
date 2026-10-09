//! The lock a command takes before it writes a record that is stamped with a version.
//!
//! An update checks that the release it switches to can read every store, and then switches. A
//! command that writes a stored record between the two could write a version that release cannot
//! read. So a command holds the writers' lock of its store, shared, from before it asks for its
//! permit to the end of its last versioned write ([`kr_ipc::install::hold_writers`]), and an update
//! holds it exclusively from before it checks the stores until it has switched. A command that
//! finds an update holding it says so, once, and waits; if the update still holds it after
//! [`WRITERS_WAIT_SECONDS`] seconds the command is refused with exit 9, and run again it writes. A
//! command is judged by the release `current` names once the lock is its own: a store that release
//! lists is written only at the version it says its programs write.

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::install::{InstallError, Permit, WRITERS_WAIT_SECONDS, WriteRefused, Writers, Written};

use crate::error::{CliError, Result};

/// Holds the writers' lock of this program's store, shared. The hold ends when the value is
/// dropped, so a command drops it at its last versioned write, before it asks a daemon anything.
///
/// # Errors
///
/// Returns [`CliError::UpdateDeferred`] when an update held the lock for the whole wait, and
/// [`CliError::Other`] when the lock cannot be used or the release `current` names cannot be read.
pub fn hold() -> Result<Writers> {
    kr_ipc::install::hold_writers(&mut || {
        crate::report::say(&shown!(
            "an update of this host is switching releases; this command waits for it, for up to \
             {} seconds",
            WRITERS_WAIT_SECONDS
        ));
    })
    .map_err(CliError::from)
}

/// Asks for the permit to write `record`, at the version this program writes it at.
///
/// # Errors
///
/// Returns [`CliError::Other`], naming both versions, when the release `current` names lists the
/// record at another.
pub fn permit<'a>(writers: &'a Writers, record: &Written) -> Result<Permit<'a>> {
    writers.permit(record).map_err(CliError::from)
}

impl From<WriteRefused> for CliError {
    fn from(refused: WriteRefused) -> Self {
        Self::from(&refused)
    }
}

impl From<&WriteRefused> for CliError {
    fn from(refused: &WriteRefused) -> Self {
        match refused {
            WriteRefused::Switching => Self::UpdateDeferred(shown!(
                "an update of this host is switching releases, and this command waited {} seconds \
                 for it; run it again once the update has finished",
                WRITERS_WAIT_SECONDS
            )),
            WriteRefused::Store(error) => Self::Other(shown!(
                "nothing was written, because the store of releases could not be used: {}{}",
                crate::update::said(error),
                match error {
                    // A pinned program of another release meets a manifest it does not read.
                    InstallError::Manifest { .. } =>
                        Shown::said("; run the command again with the kr of the current release"),
                    _ => Shown::said(""),
                }
            )),
            WriteRefused::Process(error) => Self::Other(crate::update::said(error)),
            WriteRefused::NotWhatCurrentReads {
                store,
                writes,
                reads,
                current,
                own,
            } => {
                let run = match own {
                    Some(own) if own != current => shown!(
                        "this kr is of release {}; run the command again with the kr of the \
                         current release",
                        crate::shown::release(own)
                    ),
                    _ => Shown::said(
                        "the programs of that release write another version than its manifest \
                         lists",
                    ),
                };
                Self::Other(shown!(
                    "nothing was written: the current release {} lists {} at version {}, and this \
                     kr writes version {}; {}",
                    crate::shown::release(current),
                    crate::shown::store_name(store),
                    *reads,
                    *writes,
                    run
                ))
            }
            WriteRefused::WrongRecord { permitted, record } => Self::Other(shown!(
                "nothing was written: the permit given was for {}, and the record is {}",
                crate::shown::store_name(permitted),
                crate::shown::store_name(record)
            )),
        }
    }
}

/// A store of a test's own, for the tests of the writers that ask for a permit.
#[cfg(all(test, unix))]
pub(crate) mod testing {
    use kr_ipc::install::{Store, Writers};
    use kr_protocol::update::ReleaseName;

    /// A store whose current release lists each of `stores` at the version given, and the writers'
    /// lock held shared on it, as a command of that store holds it. The store goes with this.
    pub(crate) struct Listing {
        _directory: tempfile::TempDir,
        pub(crate) writers: Writers,
    }

    impl Listing {
        pub(crate) fn of(stores: &[(&str, u32)]) -> Self {
            let directory = tempfile::tempdir().expect("a directory");
            let store = Store::at(directory.path().join("host"));
            store.create_directories().expect("the store's directories");
            std::fs::write(store.record(), b"{}\n").expect("the store's record");
            let release = ReleaseName::new("0.1.0+aaaaaaaaaaaa").expect("a release name");
            let release_directory = store.release_directory(&release);
            std::fs::create_dir_all(&release_directory).expect("the release");
            let listed: Vec<_> = stores
                .iter()
                .map(|(name, version)| {
                    serde_json::json!({
                        "store": name,
                        "scope": "state_root",
                        "path": format!("{name}.json"),
                        "recording": { "kind": "json_member", "member": "version", "absent": 0 },
                        "version": version,
                        "migrates_from": 0,
                    })
                })
                .collect();
            let manifest = serde_json::json!({
                "signed": {
                    "_type": "kalareach-release",
                    "release": release,
                    "sequence": "1",
                    "commit": "4254aa6e62e585478ff8dcff5518f23c7263f4ce",
                    "target": "aarch64-apple-darwin",
                    "os_floor": { "system": "macos", "version": "14.0" },
                    "protocol_version": { "major": 0, "minor": 48, "patch": 0 },
                    "public_majors": [1],
                    "retained_levels": ["0.48"],
                    "shells": [],
                    "stores": listed,
                    "files": [],
                },
                "signatures": [],
            });
            std::fs::write(store.manifest(&release), manifest.to_string()).expect("the manifest");
            let update = store
                .try_lock_update()
                .expect("locks")
                .expect("nothing else updates");
            let install = store
                .try_lock_install()
                .expect("locks")
                .expect("nothing starts a daemon");
            let exclusive = store
                .try_lock_writers()
                .expect("locks")
                .expect("no command is writing");
            store
                .switch(&release, &update, &install, &exclusive)
                .expect("the release is current");
            drop(exclusive);
            let writers = store
                .hold_writers(
                    Some(&release),
                    std::time::Duration::from_secs(1),
                    &mut || {},
                )
                .expect("holds");
            Self {
                _directory: directory,
                writers,
            }
        }
    }
}
