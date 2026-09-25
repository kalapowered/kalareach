//! Reading and editing this host's configuration from the command line.
//!
//! Section 23's host-and-environment group is `host.info`, `environment.list`,
//! `environment.capabilities` and `host.doctor`: four reads and no host-settings mutation. So a
//! command that changes a setting writes this user's own configuration document itself, and the
//! daemon reads the choice the next time it asks itself the question.
//!
//! Writing it here does not mean deciding here. The schema, the validation and the revision rule
//! are [`kr_protocol::hostinfo::configuration`]'s, the same ones the daemon applies, so a setting
//! written from the command line and one written by the host are the same edit.

use std::path::PathBuf;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::hostinfo::configuration::{self, Change};

use crate::error::{CliError, Result};

/// Returns where this environment's configuration document is.
#[must_use]
pub fn document_path(paths: &EnvironmentPaths) -> PathBuf {
    configuration::document_path(
        paths.state_dir(),
        paths.state_root(),
        paths.environment_id(),
    )
}

/// Reads this environment's configuration document, bounded and owner-only.
#[must_use]
pub fn load(paths: &EnvironmentPaths) -> configuration::Loaded {
    let path = document_path(paths);
    match configuration::read_file(&path, configuration::MAX_LEN) {
        Ok(bytes) => configuration::load(bytes.as_deref()),
        Err(error) => configuration::unreadable(error),
    }
}

/// Refuses a change this environment's configuration document would refuse, with nothing written.
///
/// For a command that has something to do before the edit and must not do it for an edit that
/// will be refused. [`apply`] validates again at the moment it writes.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the edit would be refused.
pub fn validate(paths: &EnvironmentPaths, change: &Change) -> Result<()> {
    configuration::edit(&load(paths), change)
        .map(|_| ())
        .map_err(|refused| refusal(&refused))
}

/// Applies one validated change to this environment's configuration document.
///
/// Validate, then check the revision again at the last moment, then write. A document at a version
/// this build does not know, or one another writer moved while this edit was being prepared, is
/// refused with nothing written.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the edit is refused, and [`CliError::Ipc`] when the
/// environment's directories cannot be made or checked, or the document cannot be written.
pub fn apply(paths: &EnvironmentPaths, change: &Change) -> Result<u64> {
    // An edit is a first use of the environment as much as a daemon's start is: on a host where no
    // daemon has run yet, the state directory the lock lives in does not exist. It is made here,
    // owner-only and checked, exactly as a daemon makes it.
    paths.create()?;
    // The same lock the host takes, so a setting written here and one written by the daemon are
    // one edit at a time rather than two writers racing for the same revision.
    // The lock's own sentence names the directory it could not lock and why; this says the same
    // of the directory this command was given, without repeating a library's text.
    let held = configuration::lock(paths.state_dir()).map_err(|_| {
        CliError::Usage(shown!(
            "the configuration lock in {} is held by another writer or could not be taken",
            Shown::root(paths.state_dir())
        ))
    })?;
    let edited = configuration::edit(&load(paths), change).map_err(|refused| refusal(&refused))?;
    configuration::still_current(&edited, &load(paths)).map_err(|refused| refusal(&refused))?;
    let path = document_path(paths);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    kr_ipc::paths::write_owner_only_file(&path, edited.contents.as_bytes())
        .map_err(CliError::Ipc)?;
    drop(held);
    Ok(edited.revision)
}

/// What a refused edit says: the configuration's own sentences, as its export rule says them.
fn refusal(refused: &configuration::EditRefused) -> CliError {
    CliError::Usage(match refused {
        configuration::EditRefused::NotOurs(sentence) => Shown::sentence(sentence),
        configuration::EditRefused::Invalid(sentences) => {
            Shown::joined(sentences.iter().map(Shown::sentence), "; ")
        }
        configuration::EditRefused::Busy(_) => {
            Shown::said("another writer is applying an edit to this configuration")
        }
    })
}

#[cfg(test)]
mod tests {
    use kr_protocol::hostinfo::export::Sentence;

    use super::*;
    use crate::shown::marker::{MARKER, assert_unmarked, failure_renderings};

    /// A refused edit says the configuration's own sentences, and a sentence that arrived from a
    /// document rather than being composed here is said by its class and length.
    #[test]
    fn a_refused_edit_does_not_repeat_a_sentence_that_arrived() {
        let arrived: Sentence =
            serde_json::from_value(serde_json::json!(MARKER)).expect("a sentence on the wire");
        for refused in [
            configuration::EditRefused::NotOurs(arrived.clone()),
            configuration::EditRefused::Invalid(vec![arrived.clone()]),
            configuration::EditRefused::Busy(MARKER.to_owned()),
        ] {
            // The negative control: the refusal's own text, which the command reported whole,
            // repeats it.
            assert!(refused.to_string().contains(MARKER), "{refused}");
            assert_unmarked("a refused edit", &failure_renderings(refusal(&refused)));
        }
        let composed = Sentence::new()
            .stated("this document is at version ")
            .number(99);
        assert_eq!(
            refusal(&configuration::EditRefused::NotOurs(composed)).to_string(),
            "this document is at version 99"
        );
    }
}
