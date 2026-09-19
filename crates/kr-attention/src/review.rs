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
//!
//! # Nothing here is retention's to take
//!
//! Both halves of this module are authoritative. A subject nobody has acknowledged is outstanding
//! review work, and deleting it answers that there is none; a subject somebody has acknowledged is
//! that actor's own record of what they read, and nothing can reconstruct it from the events,
//! because the cursor that consumed them has already moved. So the table keeps what it is told and
//! [`Reviews::states_page`] is what bounds the answer instead.

use std::collections::BTreeMap;

use kr_protocol::attention::{MAX_REVIEW_SUBJECTS, ReviewState, ReviewSubject};
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
    /// Where it stands in the order the host first heard of it.
    ///
    /// It is set once, when the subject is first recorded, and never moves again. A page continues
    /// by it rather than by the recorded moment, because a new version changes the moment: a
    /// subject that moved ahead of the one a client is continuing after would be served twice, and
    /// one that moved behind it would never be served at all.
    pub sequence: u64,
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
    next_sequence: u64,
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
                let sequence = self.next_sequence;
                self.next_sequence = self.next_sequence.saturating_add(1);
                self.subjects.insert(
                    key,
                    Subject {
                        subject,
                        version,
                        at_ms,
                        sequence,
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

    /// Returns the version the host holds of one subject, when it holds one.
    #[must_use]
    pub fn version_of(&self, subject: &ReviewSubject) -> Option<u64> {
        self.subjects
            .get(&subject_key(subject))
            .map(|held| held.version)
    }

    /// Returns one actor's state for one subject.
    #[must_use]
    pub fn state(&self, actor: &ActorId, subject: &ReviewSubject) -> Option<ReviewState> {
        self.state_of(actor, &subject_key(subject))
    }

    /// Returns one page of one actor's state for one session, oldest first.
    ///
    /// The table keeps every subject it is told about, so it has no bound a response could rely
    /// on. The page is what is bounded: a caller asks for at most [`MAX_REVIEW_SUBJECTS`] and
    /// continues after the last subject it was given, in an order that does not move under it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownContinuation`] when `after` names a subject this session no longer
    /// holds, because a page that silently restarted would look like the end of the list.
    pub fn states_page(
        &self,
        actor: &ActorId,
        session_id: SessionId,
        after: Option<&ReviewSubject>,
        max: u64,
    ) -> Result<(Vec<ReviewState>, bool)> {
        let ordered = self.ordered(session_id);
        let start = match after {
            None => 0,
            Some(subject) => {
                let key = subject_key(subject);
                let at = ordered
                    .iter()
                    .position(|held| *held == key)
                    .ok_or(Error::UnknownContinuation { key })?;
                at.saturating_add(1)
            }
        };
        let bound = usize::try_from(max.clamp(1, MAX_REVIEW_SUBJECTS)).unwrap_or(1);
        let page: Vec<_> = ordered
            .iter()
            .skip(start)
            .take(bound)
            .filter_map(|key| self.state_of(actor, key))
            .collect();
        let more = ordered.len() > start.saturating_add(page.len());
        Ok((page, more))
    }

    /// Returns the keys of one session's subjects, in the order the host first heard of them.
    ///
    /// The order never changes once a subject is in it, which is what makes a page continuable: a
    /// later version moves a subject's recorded moment but not its place here.
    fn ordered(&self, session_id: SessionId) -> Vec<String> {
        let mut keys: Vec<_> = self
            .subjects
            .iter()
            .filter(|(_, held)| subject_session(&held.subject) == session_id)
            .map(|(key, held)| (held.sequence, key.clone()))
            .collect();
        keys.sort();
        keys.into_iter().map(|(_, key)| key).collect()
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
        self.next_sequence = subjects
            .values()
            .map(|held| held.sequence.saturating_add(1))
            .max()
            .unwrap_or_default();
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
