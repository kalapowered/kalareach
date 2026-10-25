//! The claim a host makes on a saved conversation, across every session of the user.
//!
//! A session's broker knows only the executions of its own session, so two sessions could each
//! start a server against one saved conversation. Section 12 forbids a second agent process
//! against it. The claim that closes the gap is an operating-system lock on a file that all the
//! user's workers share: one file for each conversation, named by a digest of the word the
//! conversation is known by, in the state root ([`HostPaths::conversation_claims_dir`]). The
//! daemon is no party to it. A worker that holds the lock holds the conversation, the kernel lets
//! go of the lock with the worker, and a worker that cannot take it refuses the launch before
//! anything is started.
//!
//! Workers of different builds run side by side after an update, so what they must agree on is a
//! contract and not a private detail: the directory (`conversation-claims-1`), the file name (the
//! lower-case hexadecimal SHA-256 of the word's UTF-8 bytes and `.lock`), and the lock (an
//! exclusive lock on the whole of the file, taken without waiting). A build that changed any of
//! them would take both forms for as long as the workers of an earlier build can run.
//!
//! The files are empty and are never removed: removing one while a claimant has opened it and not
//! yet locked it would give two claimants two files. A sweep needs the claimant to check, once it
//! holds the lock, that the path still names the file it locked.

use kr_ipc::paths::HostPaths;
use sha2::{Digest, Sha256};
use std::fs::{File, TryLockError};

/// Where the claims on saved conversations are made.
#[derive(Clone, Debug)]
pub struct HostClaims {
    /// The roots the claims directory is made below and checked against, and its path.
    paths: HostPaths,
}

/// Why a claim was not made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimRefusal {
    /// A worker of this user, in this session or another, holds the conversation.
    Held,
    /// The claim could not be made at all: the directory or the file could not be made or opened,
    /// or the operating system would not lock it. Nothing says that no one holds the conversation,
    /// so the caller treats it as held.
    Unavailable(String),
}

/// A conversation this worker holds: the lock on its file, held until this is dropped.
///
/// Dropping it lets go of the lock at once. A copy of the descriptor that a child process made
/// keeps the open file description, and so the lock, alive after the parent closes its own, so
/// the lock is released and not left to the close.
#[derive(Debug)]
pub struct HostClaim {
    file: File,
}

impl Drop for HostClaim {
    fn drop(&mut self) {
        let _ = kr_flush::lock::release(&self.file);
    }
}

impl HostClaims {
    /// The claims of the user whose roots are `paths`.
    #[must_use]
    pub fn new(paths: &HostPaths) -> Self {
        Self {
            paths: paths.clone(),
        }
    }

    /// The name of the lock file of the conversation known as `word`: the lower-case hexadecimal
    /// SHA-256 of the word's bytes, and `.lock`.
    ///
    /// A word is typed text, or an identifier an application reports, and may hold a separator
    /// or a name the file system refuses, so the file is named by its digest.
    #[must_use]
    pub fn file_name(word: &str) -> String {
        use std::fmt::Write as _;

        let digest = Sha256::digest(word.as_bytes());
        let mut name = String::with_capacity(digest.len() * 2 + ".lock".len());
        for byte in digest {
            let _ = write!(name, "{byte:02x}");
        }
        name.push_str(".lock");
        name
    }

    /// Takes the claim on the conversation known as `word`, if no one holds it, without waiting.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimRefusal::Held`] when another description of the file holds the lock, and
    /// [`ClaimRefusal::Unavailable`] when the directory or the file cannot be made or opened or
    /// the lock cannot be taken.
    pub fn take(&self, word: &str) -> Result<HostClaim, ClaimRefusal> {
        let unavailable = |detail: String| ClaimRefusal::Unavailable(detail);
        kr_ipc::paths::create_private_tree(
            self.paths.state_root(),
            &self.paths.conversation_claims_dir(),
        )
        .map_err(|error| unavailable(error.to_string()))?;
        let path = self.paths.conversation_claim_path(&Self::file_name(word));
        let file = kr_ipc::paths::open_lock_file(&path)
            .map_err(|error| unavailable(format!("{}: {error}", path.display())))?;
        match kr_flush::lock::try_exclusive(&file) {
            Ok(()) => Ok(HostClaim { file }),
            Err(TryLockError::WouldBlock) => Err(ClaimRefusal::Held),
            Err(TryLockError::Error(error)) => {
                Err(unavailable(format!("{}: {error}", path.display())))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims_in(temp: &tempfile::TempDir) -> HostClaims {
        let paths =
            HostPaths::new(temp.path().join("run"), temp.path().join("state")).expect("the roots");
        HostClaims::new(&paths)
    }

    /// The names the lock files have, held to fixed values: workers of different builds that run
    /// side by side must open the same file for the same conversation. The words are an
    /// identifier a person types, a name with a space and a letter outside ASCII, the longest word
    /// a launch names, and the identifier a stream reports for a thread.
    #[test]
    fn a_conversation_is_known_by_the_same_file_to_every_build() {
        let longest = "a".repeat(256);
        for (word, name) in [
            (
                "thread-7",
                "7369a510fb91d7dbab5074391bb95b5d9609b3e603177dfc64f91175890a5fca.lock",
            ),
            (
                "projet été",
                "f87183bce11dc0c98e2e7ef59c2458d74a20abb852c4c20063c34d83d7ad5af7.lock",
            ),
            (
                longest.as_str(),
                "02d7160d77e18c6447be80c2e355c7ed4388545271702c50253b0914c65ce5fe.lock",
            ),
            (
                "019d2b4e-6a3c-7f10-8c5e-3b2f1a9d4e77",
                "781f7bfcb647aa12fa040e3e76a1cc845cac3d4d802eadd5744a332e228c61c9.lock",
            ),
        ] {
            assert_eq!(HostClaims::file_name(word), name, "the file of {word:?}");
        }
    }

    #[test]
    fn a_second_claim_on_a_conversation_is_refused_until_the_first_is_dropped() {
        let temp = tempfile::tempdir().expect("a directory");
        // Two handles, as two workers have.
        let (first, second) = (claims_in(&temp), claims_in(&temp));
        let held = first.take("thread-7").expect("the first claim");
        assert_eq!(second.take("thread-7").unwrap_err(), ClaimRefusal::Held);
        second
            .take("thread-8")
            .expect("another conversation is another file");
        drop(held);
        second
            .take("thread-7")
            .expect("the conversation is free once its claim is dropped");
    }

    /// A copy of the descriptor in a child that is still running keeps the open file description
    /// alive. The claim is released and not left to the close, so it does not outlive its drop.
    #[cfg(unix)]
    #[test]
    fn a_claim_does_not_outlive_its_drop_in_a_child_that_copied_the_descriptor() {
        let temp = tempfile::tempdir().expect("a directory");
        let claims = claims_in(&temp);
        let held = claims.take("thread-7").expect("the claim");
        // The child's standard input is a duplicate of the lock file's descriptor.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .stdin(std::process::Stdio::from(
                held.file.try_clone().expect("a copy of the descriptor"),
            ))
            .spawn()
            .expect("a child that holds a copy");
        drop(held);
        let retaken = claims.take("thread-7");
        let _ = child.kill();
        let _ = child.wait();
        retaken.expect("the claim was released while the child still held a copy");
    }

    #[test]
    fn a_directory_that_cannot_be_made_is_unavailable_and_not_held() {
        let temp = tempfile::tempdir().expect("a directory");
        let claims = claims_in(&temp);
        // A file where the claims directory is to be, in a state root that is as it should be.
        let state = temp.path().join("state");
        kr_ipc::paths::create_private_tree(&state, &state).expect("the state root");
        std::fs::write(state.join("conversation-claims-1"), b"")
            .expect("a file in the directory's place");
        assert!(matches!(
            claims.take("thread-7"),
            Err(ClaimRefusal::Unavailable(_))
        ));
    }
}
