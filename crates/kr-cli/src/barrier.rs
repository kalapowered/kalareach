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
use kr_ipc::install::{Permit, WRITERS_WAIT_SECONDS, WriteRefused, Writers, Written};

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
        match refused {
            WriteRefused::Switching => Self::UpdateDeferred(shown!(
                "an update of this host is switching releases, and this command waited {} seconds \
                 for it; run it again once the update has finished",
                WRITERS_WAIT_SECONDS
            )),
            WriteRefused::Store(error) => Self::Other(shown!(
                "nothing was written, because the store of releases could not be used: {}",
                crate::update::said(&error)
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
                        crate::shown::release(&own)
                    ),
                    _ => Shown::said(
                        "the programs of that release write another version than its manifest \
                         lists",
                    ),
                };
                Self::Other(shown!(
                    "nothing was written: the current release {} lists {} at version {}, and this \
                     kr writes version {}; {}",
                    crate::shown::release(&current),
                    crate::shown::store_name(store),
                    reads,
                    writes,
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
