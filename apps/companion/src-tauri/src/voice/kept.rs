//! What a phone keeps of its voice calls from one launch to the next.
//!
//! Two things outlive the process. What a call left owed (a grant the host may still hold open, a
//! start it never answered) lasts until the moment the grant ends by itself, and a person who
//! closes and opens the application inside that time must still be told. And the voice service's
//! answer on a call's control that it had no such call for this account is remembered until a
//! call's control attaches again, and counts only for the same host, account and service. Both are
//! in one small file in the application's data directory, replaced as a whole: written to a name of
//! its own, flushed, renamed over the old one, and the directory flushed, so a crash leaves the old
//! file or the new one and nothing between.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_protocol::ids::{DeviceId, EnvironmentId};
use serde::{Deserialize, Serialize};

use super::NoteKey;
use super::view::OwedView;

/// The name of the file.
const FILE: &str = "voice-kept.json";

/// The version of the file's layout.
const VERSION: u8 = 1;

/// What is kept: the entries still owed and the note.
#[derive(Clone, Debug, Default)]
pub struct KeptVoice {
    /// What the calls left owed.
    pub owed: Vec<OwedView>,
    /// The voice service's answer that it had no such call, and the host, account and service it
    /// was about.
    pub note: Option<NoteKey>,
}

/// One entry as the file holds it. The host's identity is kept beside what the page is shown, and
/// is never sent to the page.
#[derive(Serialize, Deserialize)]
struct Entry {
    kind: String,
    words: String,
    action_id: Option<String>,
    voice_session_id: Option<String>,
    until_ms: u64,
    host_reference: String,
    host_name: String,
    host_device_id: Option<DeviceId>,
    environment_id: Option<EnvironmentId>,
}

/// The file as a whole.
#[derive(Serialize, Deserialize)]
struct Document {
    version: u8,
    owed: Vec<Entry>,
    note: Option<NoteKey>,
}

/// Where a phone keeps what outlives a launch, or nowhere.
pub struct Kept {
    directory: Option<PathBuf>,
    /// One writer at a time within this process.
    gate: Mutex<()>,
}

impl Kept {
    /// A place in `directory`, which the platform gives this application for its own files.
    #[must_use]
    pub fn at(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: Some(directory.into()),
            gate: Mutex::new(()),
        }
    }

    /// No place: nothing is kept, and what a launch finds is nothing. For a device whose data
    /// directory cannot be found.
    #[must_use]
    pub const fn nowhere() -> Self {
        Self {
            directory: None,
            gate: Mutex::new(()),
        }
    }

    /// What is kept, without what has lapsed by `now_ms`. A file that is missing, or is not this
    /// layout, is nothing kept, and a file that is not this layout says so in the log: a record that
    /// is not there must not stop a call from starting.
    ///
    /// # Errors
    ///
    /// Returns why the system refused the read. A file that cannot be read is not a file that is not
    /// there: what it holds is not known, and a phone started before its first unlock cannot read
    /// the files of its own directory. A caller that gets this reads again before it uses what is
    /// kept, and writes nothing over the file until it has. Every error but a missing file counts:
    /// the kinds a platform gives for a file it keeps locked differ, and the next read decides.
    pub fn read(&self, now_ms: u64) -> std::io::Result<KeptVoice> {
        let Some(directory) = &self.directory else {
            return Ok(KeptVoice::default());
        };
        // A file staged by a process that ended before it was put in place is one nothing will
        // finish: this process is the file's only writer, and it has not written yet.
        if let Ok(entries) = std::fs::read_dir(directory) {
            for entry in entries.flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("voice-kept.staged-")
                {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        let bytes = match std::fs::read(directory.join(FILE)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(KeptVoice::default());
            }
            Err(error) => return Err(error),
        };
        let document = match serde_json::from_slice::<Document>(&bytes) {
            Ok(document) if document.version == VERSION => document,
            _ => {
                tracing::warn!(
                    "the record of what a voice call left owed is not one this build reads"
                );
                return Ok(KeptVoice::default());
            }
        };
        Ok(KeptVoice {
            owed: document
                .owed
                .into_iter()
                .filter(|entry| entry.until_ms > now_ms)
                .map(|entry| OwedView {
                    kind: entry.kind,
                    words: entry.words,
                    action_id: entry.action_id,
                    voice_session_id: entry.voice_session_id,
                    until_ms: entry.until_ms,
                    host_reference: entry.host_reference,
                    host_name: entry.host_name,
                    host: entry.host_device_id.zip(entry.environment_id),
                })
                .collect(),
            note: document.note,
        })
    }

    /// Replaces what is kept with `kept`.
    ///
    /// # Errors
    ///
    /// Returns why the file could not be put in place. A failure before the rename leaves what was
    /// kept before as it was; a failure to flush the directory after it leaves the new file in
    /// place, whose survival of a crash is then not known.
    pub fn write(&self, kept: &KeptVoice) -> std::io::Result<()> {
        static STAGED: AtomicU64 = AtomicU64::new(0);
        let Some(directory) = &self.directory else {
            return Ok(());
        };
        let _gate = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::fs::create_dir_all(directory)?;
        let document = Document {
            version: VERSION,
            owed: kept
                .owed
                .iter()
                .map(|owed| Entry {
                    kind: owed.kind.clone(),
                    words: owed.words.clone(),
                    action_id: owed.action_id.clone(),
                    voice_session_id: owed.voice_session_id.clone(),
                    until_ms: owed.until_ms,
                    host_reference: owed.host_reference.clone(),
                    host_name: owed.host_name.clone(),
                    host_device_id: owed.host.map(|(host, _)| host),
                    environment_id: owed.host.map(|(_, environment)| environment),
                })
                .collect(),
            note: kept.note.clone(),
        };
        let bytes = serde_json::to_vec(&document).map_err(std::io::Error::other)?;
        let file = directory.join(FILE);
        let staged = staged_name(&file, STAGED.fetch_add(1, Ordering::Relaxed));
        let result = (|| {
            let mut written = std::fs::File::create(&staged)?;
            written.write_all(&bytes)?;
            written.sync_all()?;
            kr_flush::retry_while_held(|| std::fs::rename(&staged, &file))?;
            kr_flush::flush_directory(directory, kr_flush::NameKind::File)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&staged);
        }
        result
    }
}

/// The name a file is staged under before it is put in place.
fn staged_name(file: &Path, count: u64) -> PathBuf {
    file.with_extension(format!("staged-{}-{count}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file the system refuses to read is not a file that is not there: the first is read again,
    /// the second holds nothing, and so does one that is not this layout.
    #[cfg(unix)]
    #[test]
    fn a_file_the_system_refuses_to_read_is_told_apart_from_one_that_is_not_there() {
        let directory = tempfile::tempdir().expect("a directory");
        let kept = Kept::at(directory.path());
        assert!(
            kept.read(0)
                .expect("a file that is not there is nothing kept")
                .owed
                .is_empty()
        );

        // A link that leads back to itself cannot be opened by anyone.
        let file = directory.path().join(FILE);
        std::os::unix::fs::symlink(&file, &file).expect("a link");
        let refused = kept
            .read(0)
            .expect_err("a refused read is not nothing kept");
        assert_ne!(refused.kind(), std::io::ErrorKind::NotFound);

        std::fs::remove_file(&file).expect("the link goes");
        std::fs::write(&file, b"not a record").expect("a file");
        assert!(
            kept.read(0)
                .expect("a file that is not this layout is nothing kept")
                .owed
                .is_empty()
        );
    }
}
