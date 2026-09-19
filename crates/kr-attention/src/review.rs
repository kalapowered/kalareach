//! Review state: one actor's acknowledgement, bound to the version it was made against.
//!
//! Section 14 is the whole of the contract here. A review acknowledgement binds a version;
//! promotion is a separate authorised action. So this module holds two things and nothing else:
//! the version the host currently has of each subject, and which version each actor has said it
//! read. From those two, whether review work is outstanding follows.
//!
//! # What is deliberately absent
//!
//! There is no operation here that writes a file, applies a patch, moves a branch or approves a
//! command. Marking a review complete changes a row in this module and nothing else in the
//! product. That is not a policy the caller has to observe; it is the whole of what the type can
//! express.
//!
//! # New changes are new review work
//!
//! An acknowledgement names the version it was made against. When the host records a later
//! version, the earlier acknowledgement still stands for the version it covered, and the subject
//! is outstanding again. An acknowledgement is never carried forward onto a version nobody read.

use std::collections::BTreeMap;

use kr_protocol::attention::{ReviewState, ReviewSubject};
use kr_protocol::ids::{ActorId, SessionId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};

use crate::error::{Error, Result};

/// Returns the canonical key one subject is stored under.
///
/// The key is derived from the subject's identity alone, never from a version, so a subject keeps
/// one row as its versions move.
#[must_use]
pub fn subject_key(subject: &ReviewSubject) -> String {
    match subject {
        ReviewSubject::CompletedTurn {
            session_id,
            turn_id,
        } => format!("turn|{session_id}|{turn_id}"),
        ReviewSubject::ChangeSet {
            session_id,
            change_set_id,
        } => format!("changeset|{session_id}|{change_set_id}"),
    }
}

/// Returns the session a subject belongs to.
#[must_use]
pub const fn subject_session(subject: &ReviewSubject) -> SessionId {
    match subject {
        ReviewSubject::CompletedTurn { session_id, .. }
        | ReviewSubject::ChangeSet { session_id, .. } => *session_id,
    }
}

/// One subject, at the version the host holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject {
    /// What it is.
    pub subject: ReviewSubject,
    /// The version the host currently holds.
    pub version: u64,
    /// When that version was recorded.
    pub at_ms: TimestampMs,
}

/// One actor's acknowledgement of one subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReviewAck {
    /// The version the actor said it read.
    pub version: u64,
    /// When it said so.
    pub at_ms: TimestampMs,
}

/// Review state for every subject this session knows about.
#[derive(Clone, Debug, Default)]
pub struct Reviews {
    subjects: BTreeMap<String, Subject>,
    acks: BTreeMap<ActorId, BTreeMap<String, ReviewAck>>,
}

impl Reviews {
    /// Builds empty review state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the version the host now holds of one subject.
    ///
    /// The version only moves forward. A producer that reports an older version is reporting
    /// something it read late, and letting it move the current version backwards would turn an
    /// outstanding review into a satisfied one.
    ///
    /// Returns true when the version moved, which is when new review work exists.
    pub fn record_version(
        &mut self,
        subject: ReviewSubject,
        version: u64,
        at_ms: TimestampMs,
    ) -> bool {
        let key = subject_key(&subject);
        match self.subjects.get_mut(&key) {
            Some(existing) if existing.version >= version => false,
            Some(existing) => {
                existing.version = version;
                existing.at_ms = at_ms;
                existing.subject = subject;
                true
            }
            None => {
                self.subjects.insert(
                    key,
                    Subject {
                        subject,
                        version,
                        at_ms,
                    },
                );
                true
            }
        }
    }

    /// Records that one actor read one subject at one version.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownReviewSubject`] when the host holds no version of the subject, and
    /// [`Error::UnknownReviewVersion`] when the version is beyond the one it holds. Acknowledging
    /// a version nobody produced would close review work that was never presented.
    pub fn acknowledge(
        &mut self,
        actor: &ActorId,
        subject: &ReviewSubject,
        version: u64,
        at_ms: TimestampMs,
    ) -> Result<ReviewState> {
        let key = subject_key(subject);
        let held = self
            .subjects
            .get(&key)
            .ok_or_else(|| Error::UnknownReviewSubject {
                subject: key.clone(),
            })?;
        if version > held.version {
            return Err(Error::UnknownReviewVersion {
                subject: key,
                version,
                current: held.version,
            });
        }
        let entry = self.acks.entry(actor.clone()).or_default();
        let record = entry
            .entry(key.clone())
            .or_insert(ReviewAck { version, at_ms });
        // An acknowledgement of an older version than one already recorded is not a retreat. The
        // actor has read both, and the furthest it has read is what decides whether work remains.
        if version >= record.version {
            record.version = version;
            record.at_ms = at_ms;
        }
        Ok(self
            .state_of(actor, &key)
            .expect("the subject was just read"))
    }

    /// Returns one actor's state for one subject.
    #[must_use]
    pub fn state(&self, actor: &ActorId, subject: &ReviewSubject) -> Option<ReviewState> {
        self.state_of(actor, &subject_key(subject))
    }

    /// Returns one actor's state for every subject in one session, oldest first.
    #[must_use]
    pub fn states(&self, actor: &ActorId, session_id: SessionId) -> Vec<ReviewState> {
        let mut states: Vec<_> = self
            .subjects
            .iter()
            .filter(|(_, held)| subject_session(&held.subject) == session_id)
            .filter_map(|(key, _)| self.state_of(actor, key))
            .collect();
        states.sort_by_key(|state| state.current_version.get());
        states
    }

    /// Returns every subject the host holds a version of.
    pub fn subjects(&self) -> impl Iterator<Item = &Subject> {
        self.subjects.values()
    }

    /// Returns one actor's acknowledgements.
    #[must_use]
    pub fn acknowledgements(&self, actor: &ActorId) -> Option<&BTreeMap<String, ReviewAck>> {
        self.acks.get(actor)
    }

    /// Returns every actor's acknowledgements.
    #[must_use]
    pub const fn all_acknowledgements(&self) -> &BTreeMap<ActorId, BTreeMap<String, ReviewAck>> {
        &self.acks
    }

    /// Installs restored state.
    pub(crate) fn install(
        &mut self,
        subjects: BTreeMap<String, Subject>,
        acks: BTreeMap<ActorId, BTreeMap<String, ReviewAck>>,
    ) {
        self.subjects = subjects;
        self.acks = acks;
    }

    fn state_of(&self, actor: &ActorId, key: &str) -> Option<ReviewState> {
        let held = self.subjects.get(key)?;
        let ack = self.acks.get(actor).and_then(|acks| acks.get(key));
        Some(ReviewState {
            subject: held.subject.clone(),
            current_version: U64::new(held.version),
            acknowledged_version: Nullable(ack.map(|ack| U64::new(ack.version))),
            acknowledged_at_ms: Nullable(ack.map(|ack| ack.at_ms)),
            outstanding: ack.is_none_or(|ack| ack.version < held.version),
        })
    }
}
