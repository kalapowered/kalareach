//! The subjects items are keyed on, built so that two different conditions never share one.
//!
//! An item's key is derived from its rule and a subject ([`crate::key`]), and two conditions with
//! the same rule and the same subject are one item. So a subject is built here and nowhere else,
//! under one rule that makes a collision between two different conditions impossible:
//!
//! 1. A subject starts with a word naming its form, and no two forms share a word.
//! 2. Every part after that word but the last has a written form of its own that never holds the
//!    separator: an identifier with one written form, a number, an origin or a source.
//! 3. Only the last part may be free text: an upstream request identifier, a plugin identifier, a
//!    command line, an application's own notice identifier. It may hold anything, the separator
//!    included.
//!
//! Read from the left, a subject gives back its form and then each part exactly, with the free text
//! as whatever is left, so two subjects are equal only when their form and every part are. The
//! types hold the rule: a part that is not last must be [`Fixed`], which only the fixed-form types
//! are, and the free part ends the subject, which takes no part after it.

use core::fmt::Write as _;

use kr_protocol::attention::AttentionSource;
use kr_protocol::ids::{CausalRootId, QuestionId, SessionId, WorkflowId};

use crate::event::{EventCursor, Fingerprint, Origin};

/// What separates the parts of a subject.
const SEPARATOR: char = '|';

/// The forms a subject takes, each named by its own word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    Approval,
    Question,
    Command,
    Turn,
    Adapter,
    Host,
    NoticeId,
    NoticeFingerprint,
    NoticeRecord,
    Workflow,
    Chain,
}

impl Form {
    #[cfg(test)]
    const ALL: [Self; 11] = [
        Self::Approval,
        Self::Question,
        Self::Command,
        Self::Turn,
        Self::Adapter,
        Self::Host,
        Self::NoticeId,
        Self::NoticeFingerprint,
        Self::NoticeRecord,
        Self::Workflow,
        Self::Chain,
    ];

    const fn word(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Question => "question",
            Self::Command => "command",
            Self::Turn => "turn",
            Self::Adapter => "adapter",
            Self::Host => "host",
            Self::NoticeId => "notice_id",
            Self::NoticeFingerprint => "notice_fingerprint",
            Self::NoticeRecord => "notice_record",
            Self::Workflow => "workflow",
            Self::Chain => "chain",
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

/// A part of a subject with a written form of its own that never holds the separator.
///
/// Sealed: only the types below have such a form, and a free-text type cannot be passed where a
/// fixed part belongs.
pub trait Fixed: sealed::Sealed {
    /// Writes the part.
    fn write_to(&self, out: &mut String);
}

macro_rules! fixed_by_display {
    ($($name:ty),* $(,)?) => {
        $(
            impl sealed::Sealed for $name {}
            impl Fixed for $name {
                fn write_to(&self, out: &mut String) {
                    let _ = write!(out, "{self}");
                }
            }
        )*
    };
}

// A UUID is written in its one hyphenated form, a number in decimals, an origin as the
// environment's word or its session's UUID, and a source as its wire word.
fixed_by_display!(SessionId, QuestionId, WorkflowId, CausalRootId, u64, Origin);

impl sealed::Sealed for AttentionSource {}
impl Fixed for AttentionSource {
    fn write_to(&self, out: &mut String) {
        out.push_str(self.as_str());
    }
}

impl sealed::Sealed for Fingerprint {}
impl Fixed for Fingerprint {
    fn write_to(&self, out: &mut String) {
        out.push_str(&self.to_hex());
    }
}

/// A subject being built: its form, then its fixed parts.
///
/// It ends either with the one free part, [`Builder::last`], or with none, [`Builder::done`]; both
/// give a [`Subject`], which takes no more parts, so no subject can hold two free parts.
struct Builder(String);

impl Builder {
    fn of(form: Form) -> Self {
        Self(form.word().to_owned())
    }

    fn then(mut self, part: &impl Fixed) -> Self {
        self.0.push(SEPARATOR);
        let start = self.0.len();
        part.write_to(&mut self.0);
        debug_assert!(
            !self.0[start..].contains(SEPARATOR),
            "a fixed part never holds the separator"
        );
        self
    }

    fn last(mut self, part: &impl core::fmt::Display) -> Subject {
        self.0.push(SEPARATOR);
        let _ = write!(self.0, "{part}");
        Subject(self.0)
    }

    fn done(self) -> Subject {
        Subject(self.0)
    }
}

/// The subject one condition is keyed on.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subject(String);

impl Subject {
    /// Returns the subject as the text a key is derived from.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A pending approval: the session it waits in, then the upstream request identifier, which is
    /// the connector's own and not unique across sessions.
    #[must_use]
    pub fn approval(session_id: SessionId, request_id: &impl core::fmt::Display) -> Self {
        Builder::of(Form::Approval)
            .then(&session_id)
            .last(request_id)
    }

    /// A pending question and its idle reminder.
    #[must_use]
    pub fn question(question_id: QuestionId) -> Self {
        Builder::of(Form::Question).then(&question_id).done()
    }

    /// A failed command in one session.
    #[must_use]
    pub fn command(session_id: SessionId, command: &str) -> Self {
        Builder::of(Form::Command).then(&session_id).last(&command)
    }

    /// A completed turn waiting for review in one session.
    #[must_use]
    pub fn turn(session_id: SessionId, turn_id: &impl core::fmt::Display) -> Self {
        Builder::of(Form::Turn).then(&session_id).last(turn_id)
    }

    /// An adapter's failure, within the origin that reported it.
    ///
    /// One adapter can fail for two sessions at once, and each session's failure is its own: a
    /// device that sees one session is shown that session's, and its recovery ends that one.
    #[must_use]
    pub fn adapter(origin: Origin, plugin_id: &impl core::fmt::Display) -> Self {
        Builder::of(Form::Adapter).then(&origin).last(plugin_id)
    }

    /// Lost contact with the host, of which there is one.
    #[must_use]
    pub fn host() -> Self {
        Builder::of(Form::Host).done()
    }

    /// An application's notice that carries its own identifier.
    #[must_use]
    pub fn notice_id(session_id: SessionId, id: &str) -> Self {
        Builder::of(Form::NoticeId).then(&session_id).last(&id)
    }

    /// An application's notice known by what it says, through its record owner's fingerprint.
    #[must_use]
    pub fn notice_fingerprint(session_id: SessionId, fingerprint: &Fingerprint) -> Self {
        Builder::of(Form::NoticeFingerprint)
            .then(&session_id)
            .then(fingerprint)
            .done()
    }

    /// An application's notice with neither an identifier nor a fingerprint: its own record.
    #[must_use]
    pub fn notice_record(session_id: SessionId, record: &EventCursor) -> Self {
        Builder::of(Form::NoticeRecord)
            .then(&session_id)
            .then(&record.origin)
            .then(&record.source)
            .then(&record.sequence)
            .done()
    }

    /// A workflow revision paused by its own limits.
    #[must_use]
    pub fn workflow(workflow_id: WorkflowId, revision: u64) -> Self {
        Builder::of(Form::Workflow)
            .then(&workflow_id)
            .then(&revision)
            .done()
    }

    /// A causal chain paused because it ran out of budget.
    #[must_use]
    pub fn chain(causal_root_id: CausalRootId) -> Self {
        Builder::of(Form::Chain).then(&causal_root_id).done()
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::scalars::Uuid;

    use super::*;

    fn session(byte: u8) -> SessionId {
        SessionId::new(Uuid::from_bytes([byte; 16]))
    }

    #[test]
    fn every_form_has_a_word_of_its_own_that_never_holds_the_separator() {
        let words: Vec<&str> = Form::ALL.iter().map(|form| form.word()).collect();
        for (index, word) in words.iter().enumerate() {
            assert!(!word.contains(SEPARATOR));
            assert!(!words[index + 1..].contains(word), "{word} is used twice");
        }
    }

    #[test]
    fn an_environment_report_and_a_session_report_never_share_a_subject() {
        // An environment report for an adapter whose identifier starts with a session's, and that
        // session's own report for the rest of it.
        let named = session(1);
        let environment = Subject::adapter(Origin::Environment, &format!("{named}|git"));
        let in_session = Subject::adapter(Origin::Session(named), &"git");
        assert_ne!(environment, in_session);
        assert_ne!(
            Subject::adapter(Origin::Session(session(1)), &"git"),
            Subject::adapter(Origin::Session(session(2)), &"git")
        );
    }

    #[test]
    fn free_text_holding_the_separator_never_reaches_another_condition() {
        let one = session(1);
        let two = session(2);
        // The free part can hold anything, and what comes after the fixed parts is still only it.
        assert_ne!(
            Subject::approval(one, &format!("{two}|req-1")),
            Subject::approval(two, &"req-1")
        );
        assert_ne!(
            Subject::notice_id(one, "fingerprint|00"),
            Subject::notice_fingerprint(one, &Fingerprint::from_bytes([0; 32]))
        );
        assert_ne!(Subject::command(one, "turn"), Subject::turn(one, &"turn"));
        assert_ne!(
            Subject::notice_record(
                one,
                &EventCursor::in_session(one, AttentionSource::HostEvents, 7)
            ),
            Subject::notice_record(
                one,
                &EventCursor::in_session(two, AttentionSource::HostEvents, 7)
            )
        );
    }
}
