//! The question ledger: what an agent asks, and what a person answers.
//!
//! One worker owns the questions of one session, because the worker is what knows the session is
//! still running and what the processes inside it are. Everything here is reached over the
//! worker's private socket, and the two surfaces on it are kept apart:
//!
//! | Surface | Methods | Who may use it |
//! | --- | --- | --- |
//! | Source | `question.create`, `question.read_own`, `question.cancel_own`, `alert.create` | A helper the worker has bound to this session, holding the token for that question |
//! | Answering | `question.read`, `question.answer`, `question.cancel` | A local owner or a paired actor with the rights for this session |
//!
//! Source ownership never becomes a human answer: the four source methods cannot answer anything,
//! and the three answering methods do not need the caller token. That separation is section 11's,
//! and it is the reason an agent cannot resolve its own question.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`binding`] | Binding a calling process to this session, from what the kernel says |
//! | [`store`] | The durable ledger: states, revisions, de-duplication and expiry |
//! | [`token`] | Issuing, sealing and checking the per-question caller token |
//! | [`error`] | The failures above, each mapped to one stable protocol code |

pub mod binding;
pub mod error;
pub mod store;
pub mod token;

use std::sync::Mutex;

use kr_protocol::ids::{ActorId, DeviceId, SessionEpoch, SessionId};
use kr_protocol::question::{
    AlertCreateParams, AlertCreateResult, MAX_ALERT_TEXT_BYTES, Question, QuestionAnswer,
    QuestionAnswerParams, QuestionCancelOwnParams, QuestionCancelParams, QuestionCreateParams,
    QuestionCreateResult, QuestionEvent, QuestionEventKind, QuestionOwnResult,
    QuestionReadOwnParams, QuestionReadParams, QuestionReadResult, QuestionResolveResult,
    QuestionState, bounded_expiry, build_choices, check_answer, check_text,
};

pub use crate::questions::binding::{SessionBoundary, VerifiedSource};
pub use crate::questions::error::{QuestionError, Result, SETUP_INSTRUCTION};
pub use crate::questions::store::Now;

use crate::questions::store::{Resolved, Store};

/// The session's questions, and the waiters watching them.
#[derive(Debug)]
pub struct Questions {
    store: Mutex<Store>,
    /// Woken whenever any question changes.
    ///
    /// A long poll is a subscription, not a held transaction: a waiter sleeps here and re-reads
    /// the question it cares about when it wakes, so nothing holds the ledger open while a person
    /// thinks.
    changed: tokio::sync::Notify,
}

impl Questions {
    /// Opens the ledger for one session.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unavailable`] when the ledger cannot be opened.
    pub fn open(
        journal_path: Option<&std::path::Path>,
        session_id: SessionId,
        session_epoch: SessionEpoch,
    ) -> Result<Self> {
        Ok(Self {
            store: Mutex::new(Store::open(journal_path, session_id, session_epoch)?),
            changed: tokio::sync::Notify::new(),
        })
    }

    /// Creates a question for a bound source, or returns the one an exact duplicate created.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Invalid`] when the form breaks the contract,
    /// [`QuestionError::IdConflict`] when the request identifier was reused with a different
    /// payload, and [`QuestionError::Unavailable`] when the ledger cannot be written.
    pub fn create(
        &self,
        source: &VerifiedSource,
        params: &QuestionCreateParams,
        now: Now,
    ) -> Result<(QuestionCreateResult, Vec<QuestionEvent>)> {
        check_text(params)?;
        let choices = build_choices(params.kind, &params.choices)?;
        let expiry = bounded_expiry(params.requested_expiry_ms.as_ref().copied()).get();
        let mut store = self.locked()?;
        let mut events = expiry_events(store.expire_due(now)?, now);
        let header = store.source_header(source, params.agent_name.as_ref().cloned(), now)?;
        let created = store.create(source, &header, params, &choices, expiry, now)?;
        if !created.deduplicated {
            events.push(QuestionEvent {
                kind: QuestionEventKind::Created,
                question: created.question.clone(),
                pending_since_ms: created.question.created_at_ms,
                recorded_at_ms: now.utc_ms,
            });
        }
        drop(store);
        self.changed.notify_waiters();
        Ok((
            QuestionCreateResult {
                question: created.question,
                caller_token: created.caller_token,
                deduplicated: created.deduplicated,
            },
            events,
        ))
    }

    /// Checks everything a creation can be refused for, before anything durable happens.
    ///
    /// The worker calls this inside the serial path and *before* it commits a dispatch marker. A
    /// refusal recorded after that marker would say the effect might have happened, and for a
    /// malformed form, an unbound caller or a reused request identifier nothing happened at all.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Invalid`] for a form that breaks the contract and
    /// [`QuestionError::IdConflict`] for a request identifier that already carries a different
    /// payload.
    pub fn check_create(
        &self,
        source: &VerifiedSource,
        params: &QuestionCreateParams,
    ) -> Result<()> {
        check_text(params)?;
        let choices = build_choices(params.kind, &params.choices)?;
        self.locked()?
            .check_request(&source.key(), params, &choices)
    }

    /// Checks that a question can still be resolved, and that the answer fits its form.
    ///
    /// Called for the same reason as [`Self::check_create`]: an answer to a question somebody else
    /// has already answered is a refusal, not an uncertain outcome.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Resolved`], [`QuestionError::Expired`],
    /// [`QuestionError::StaleRevision`] or [`QuestionError::Invalid`].
    pub fn check_resolvable(
        &self,
        question_id: kr_protocol::ids::QuestionId,
        expected: kr_protocol::ids::QuestionRevision,
        answer: Option<&QuestionAnswer>,
        now: Now,
    ) -> Result<()> {
        let mut store = self.locked()?;
        store.expire_due(now)?;
        let question = store.read(question_id)?;
        if let Some(answer) = answer {
            check_answer(&question, answer)?;
        }
        match question.state {
            QuestionState::Expired => Err(QuestionError::Expired {
                at_ms: question
                    .resolved_at_ms
                    .as_ref()
                    .map_or_else(|| question.expires_at_ms.get(), |at| at.get()),
            }),
            QuestionState::Answered | QuestionState::Cancelled => Err(QuestionError::Resolved {
                state: question.state,
            }),
            QuestionState::Pending if question.revision != expected => {
                Err(QuestionError::StaleRevision {
                    named: expected.get(),
                    current: question.revision.get(),
                })
            }
            QuestionState::Pending => Ok(()),
        }
    }

    /// Checks that the source of this call still owns the question it names.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::TokenRejected`] when the token or the application does not match.
    pub fn check_own(
        &self,
        source: &VerifiedSource,
        question_id: kr_protocol::ids::QuestionId,
        caller_token: &kr_protocol::question::CallerToken,
    ) -> Result<()> {
        let store = self.locked()?;
        let row = store.read_row(question_id)?;
        store.check_token(&row, source, caller_token)
    }

    /// Reads one question back to the source that created it.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::TokenRejected`] when the token or the application does not match,
    /// and [`QuestionError::Unknown`] when this session has no such question.
    pub fn read_own(
        &self,
        source: &VerifiedSource,
        params: &QuestionReadOwnParams,
        now: Now,
    ) -> Result<(QuestionOwnResult, Vec<QuestionEvent>)> {
        let mut store = self.locked()?;
        let events = expiry_events(store.expire_due(now)?, now);
        let row = store.read_row(params.question_id)?;
        store.check_token(&row, source, &params.caller_token)?;
        Ok((
            QuestionOwnResult {
                question: row.question,
            },
            events,
        ))
    }

    /// Cancels a question the source created.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::TokenRejected`] when the token or the application does not match,
    /// and [`QuestionError::Resolved`] or [`QuestionError::Expired`] when the question is no
    /// longer pending.
    pub fn cancel_own(
        &self,
        source: &VerifiedSource,
        params: &QuestionCancelOwnParams,
        now: Now,
    ) -> Result<(QuestionOwnResult, Vec<QuestionEvent>)> {
        let mut store = self.locked()?;
        let mut events = expiry_events(store.expire_due(now)?, now);
        let row = store.read_row(params.question_id)?;
        store.check_token(&row, source, &params.caller_token)?;
        let resolved = store.cancel(params.question_id, row.question.revision, now)?;
        events.push(event(QuestionEventKind::Cancelled, &resolved, now));
        let question = resolved.question;
        drop(store);
        self.changed.notify_waiters();
        Ok((QuestionOwnResult { question }, events))
    }

    /// Raises an alert from a bound source.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::InvalidArgument`] when a field is empty or over-long, and
    /// [`QuestionError::IdConflict`] when the de-duplication identifier was reused with different
    /// text.
    pub fn alert(
        &self,
        source: &VerifiedSource,
        params: &AlertCreateParams,
        now: Now,
    ) -> Result<AlertCreateResult> {
        if params.dedup_id.trim().is_empty() || params.dedup_id.len() > 256 {
            return Err(QuestionError::InvalidArgument(
                "a de-duplication identifier is 1 to 256 bytes of text".to_owned(),
            ));
        }
        if params.text.trim().is_empty() || params.text.len() > MAX_ALERT_TEXT_BYTES {
            return Err(QuestionError::InvalidArgument(format!(
                "an alert carries 1 to {MAX_ALERT_TEXT_BYTES} bytes of text"
            )));
        }
        let mut store = self.locked()?;
        let header = store.source_header(source, params.agent_name.as_ref().cloned(), now)?;
        let (alert, deduplicated) = store.alert(source, &header, params, now)?;
        Ok(AlertCreateResult {
            alert,
            deduplicated,
        })
    }

    /// Reads the questions an answering actor may see.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unknown`] when a named question is not this session's.
    pub fn read(
        &self,
        params: &QuestionReadParams,
        now: Now,
    ) -> Result<(QuestionReadResult, Vec<QuestionEvent>)> {
        let mut store = self.locked()?;
        let events = expiry_events(store.expire_due(now)?, now);
        let questions = match params.question_id.as_ref() {
            Some(question_id) => vec![store.read(*question_id)?],
            None => store.list(params.include_resolved)?,
        };
        Ok((QuestionReadResult { questions }, events))
    }

    /// Answers a question on behalf of a verified actor.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Resolved`] when another client answered first,
    /// [`QuestionError::Expired`] when its deadline passed, and [`QuestionError::StaleRevision`]
    /// when the actor answered a revision that is no longer current.
    pub fn answer(
        &self,
        actor_id: &ActorId,
        device_id: Option<DeviceId>,
        params: &QuestionAnswerParams,
        now: Now,
    ) -> Result<(QuestionResolveResult, Vec<QuestionEvent>)> {
        let mut store = self.locked()?;
        let mut events = expiry_events(store.expire_due(now)?, now);
        let question = store.read(params.question_id)?;
        check_answer(&question, &params.answer)?;
        let resolved = store.answer(
            params.question_id,
            params.expected_revision,
            &params.answer,
            actor_id,
            device_id,
            now,
        )?;
        events.push(event(QuestionEventKind::Answered, &resolved, now));
        let question = resolved.question;
        drop(store);
        self.changed.notify_waiters();
        Ok((QuestionResolveResult { question }, events))
    }

    /// Cancels a question from the answering surface.
    ///
    /// # Errors
    ///
    /// As [`Self::answer`].
    pub fn cancel(
        &self,
        params: &QuestionCancelParams,
        now: Now,
    ) -> Result<(QuestionResolveResult, Vec<QuestionEvent>)> {
        let mut store = self.locked()?;
        let mut events = expiry_events(store.expire_due(now)?, now);
        let resolved = store.cancel(params.question_id, params.expected_revision, now)?;
        events.push(event(QuestionEventKind::Cancelled, &resolved, now));
        let question = resolved.question;
        drop(store);
        self.changed.notify_waiters();
        Ok((QuestionResolveResult { question }, events))
    }

    /// Expires whatever is due, and returns the transitions that happened.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unavailable`] when the ledger cannot be written.
    pub fn sweep(&self, now: Now) -> Result<Vec<QuestionEvent>> {
        let mut store = self.locked()?;
        let events = expiry_events(store.expire_due(now)?, now);
        drop(store);
        if !events.is_empty() {
            self.changed.notify_waiters();
        }
        Ok(events)
    }

    /// Returns one question without checking any token, for the answering surface.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unknown`] when this session has no such question.
    pub fn question(&self, question_id: kr_protocol::ids::QuestionId) -> Result<Question> {
        self.locked()?.read(question_id)
    }

    /// Waits until something changes, or until the bound passes.
    ///
    /// The bound is the caller's, and the wait ends early on any change: a waiter re-reads what it
    /// cares about and waits again if it was somebody else's question that moved. Nothing here
    /// notifies a person a second time, and nothing recreates a question.
    pub async fn wait_for_change(&self, within: std::time::Duration) {
        let _ = tokio::time::timeout(within, self.subscribe()).await;
    }

    /// Takes a subscription that will fire on the next change.
    ///
    /// A caller that means to read the state and then wait takes this *first*: a change between
    /// the read and the wait is then delivered to a subscription that already exists, rather than
    /// happening in the gap between them.
    pub fn subscribe(&self) -> impl std::future::Future<Output = ()> + '_ {
        self.changed.notified()
    }

    /// Returns the transitions recorded after this cursor, oldest first.
    ///
    /// This is the feed the attention engine reads. It is durable and sequenced, so a consumer
    /// that restarts resumes from its own cursor rather than from whatever is pending now.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unavailable`] when the ledger cannot be read.
    pub fn events_since(&self, cursor: u64, limit: usize) -> Result<Vec<(u64, QuestionEvent)>> {
        self.locked()?.events_since(cursor, limit)
    }

    /// Returns the alerts this session has raised, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unavailable`] when the ledger cannot be read.
    pub fn alerts(&self) -> Result<Vec<kr_protocol::question::Alert>> {
        self.locked()?.alerts()
    }

    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Store>> {
        self.store
            .lock()
            .map_err(|_| QuestionError::unavailable("the question ledger is poisoned"))
    }
}

/// Renders a resolution as an attention event.
fn event(kind: QuestionEventKind, resolved: &Resolved, now: Now) -> QuestionEvent {
    QuestionEvent {
        kind,
        question: resolved.question.clone(),
        pending_since_ms: resolved.pending_since_ms,
        recorded_at_ms: now.utc_ms,
    }
}

fn expiry_events(expired: Vec<Resolved>, now: Now) -> Vec<QuestionEvent> {
    expired
        .iter()
        .map(|resolved| event(QuestionEventKind::Expired, resolved, now))
        .collect()
}

/// Returns whether an answer would be refused for naming a state that has already been reached.
#[must_use]
pub fn already_resolved(question: &Question) -> Option<QuestionState> {
    question.state.is_resolved().then_some(question.state)
}

/// Returns the answer a question carries, if any.
#[must_use]
pub fn answer_of(question: &Question) -> Option<&QuestionAnswer> {
    question.answer.as_ref().map(|record| &record.answer)
}

#[cfg(test)]
mod tests {
    use kr_protocol::ids::ConnectionId;
    use kr_protocol::question::{QuestionKind, QuestionState};
    use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

    use super::*;

    fn session() -> SessionId {
        SessionId::new(Uuid::from_bytes([5; 16]))
    }

    /// A source that is this test process, so its questions outlive their creation.
    ///
    /// A question ends with the application that asked it, and a fabricated process is one the
    /// kernel says has already gone.
    fn source() -> VerifiedSource {
        VerifiedSource {
            process: kr_ipc::identity::process_start_identity(std::process::id())
                .expect("this process's start identity"),
            executable: Some("/usr/bin/agent".to_owned()),
            session_member: true,
            ancestry: true,
            launch_channel: false,
            connection_id: ConnectionId::new(Uuid::from_bytes([1; 16])),
        }
    }

    fn now(utc: u64) -> Now {
        Now {
            utc_ms: TimestampMs::new(utc),
            boot_ms: utc,
        }
    }

    fn questions() -> Questions {
        Questions::open(None, session(), SessionEpoch::V1).expect("a ledger")
    }

    fn select_params() -> QuestionCreateParams {
        QuestionCreateParams {
            session_id: session(),
            request_id: "r-1".to_owned(),
            agent_name: Nullable::some("an agent".to_owned()),
            context: "two ways to do it".to_owned(),
            question: "which one?".to_owned(),
            kind: QuestionKind::Select,
            choices: vec![
                kr_protocol::question::QuestionChoice {
                    choice_id: "left".to_owned(),
                    label: "Left".to_owned(),
                },
                kr_protocol::question::QuestionChoice {
                    choice_id: "right".to_owned(),
                    label: "Right".to_owned(),
                },
            ],
            requested_expiry_ms: Nullable::null(),
            wait_ms: Nullable::null(),
        }
    }

    #[test]
    fn a_created_question_emits_one_event_and_a_duplicate_emits_none() {
        let questions = questions();
        let (first, events) = questions
            .create(&source(), &select_params(), now(1_000))
            .expect("created");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, QuestionEventKind::Created);
        assert_eq!(events[0].pending_since_ms, TimestampMs::new(1_000));
        let (second, events) = questions
            .create(&source(), &select_params(), now(2_000))
            .expect("deduplicated");
        assert!(events.is_empty());
        assert!(second.deduplicated);
        assert_eq!(first.question.question_id, second.question.question_id);
    }

    #[test]
    fn a_select_always_offers_the_free_text_option() {
        let questions = questions();
        let (created, _) = questions
            .create(&source(), &select_params(), now(1_000))
            .expect("created");
        let identifiers: Vec<&str> = created
            .question
            .choices
            .iter()
            .map(|choice| choice.choice_id.as_str())
            .collect();
        assert_eq!(
            identifiers,
            vec![
                "left",
                "right",
                kr_protocol::question::SOMETHING_ELSE_CHOICE
            ]
        );
    }

    #[test]
    fn a_free_text_answer_reaches_the_source_as_free_text() {
        let questions = questions();
        let (created, _) = questions
            .create(&source(), &select_params(), now(1_000))
            .expect("created");
        let (answered, events) = questions
            .answer(
                &ActorId::new("local:501").expect("a principal"),
                None,
                &QuestionAnswerParams {
                    session_id: session(),
                    question_id: created.question.question_id,
                    expected_revision: created.question.revision,
                    answer: QuestionAnswer::Other {
                        text: "a third way".to_owned(),
                    },
                },
                now(2_000),
            )
            .expect("answered");
        assert_eq!(answered.question.state, QuestionState::Answered);
        assert_eq!(
            events.last().expect("an event").kind,
            QuestionEventKind::Answered
        );
        let (own, _) = questions
            .read_own(
                &source(),
                &QuestionReadOwnParams {
                    session_id: session(),
                    question_id: created.question.question_id,
                    caller_token: created.caller_token,
                    wait_ms: Nullable::null(),
                },
                now(2_100),
            )
            .expect("read");
        assert_eq!(
            answer_of(&own.question),
            Some(&QuestionAnswer::Other {
                text: "a third way".to_owned()
            })
        );
    }

    #[test]
    fn an_answer_for_the_wrong_form_is_refused_before_anything_changes() {
        let questions = questions();
        let (created, _) = questions
            .create(&source(), &select_params(), now(1_000))
            .expect("created");
        let error = questions
            .answer(
                &ActorId::new("local:501").expect("a principal"),
                None,
                &QuestionAnswerParams {
                    session_id: session(),
                    question_id: created.question.question_id,
                    expected_revision: created.question.revision,
                    answer: QuestionAnswer::Decision { decided: true },
                },
                now(2_000),
            )
            .expect_err("refused");
        assert_eq!(error.code(), kr_protocol::error::ErrorCode::InvalidArgument);
        assert_eq!(
            questions
                .question(created.question.question_id)
                .expect("still there")
                .state,
            QuestionState::Pending
        );
    }

    #[test]
    fn an_expiry_reaches_the_feed_even_when_the_read_that_found_it_fails() {
        let questions = questions();
        // A source the kernel says has already gone, so its question expires with its binding.
        let gone = VerifiedSource {
            process: kr_protocol::identity::ProcessStartIdentity::new(
                7,
                kr_protocol::identity::ProcessStartSource::LinuxProcStat,
                11,
            ),
            executable: None,
            session_member: true,
            ancestry: false,
            launch_channel: false,
            connection_id: ConnectionId::new(Uuid::from_bytes([9; 16])),
        };
        questions
            .create(&gone, &select_params(), now(1_000))
            .expect("created");
        // A read for a question that does not exist. It expires what is due on its way in and then
        // fails, and the transition it made has to survive that failure.
        let error = questions
            .read_own(
                &gone,
                &QuestionReadOwnParams {
                    session_id: session(),
                    question_id: kr_protocol::ids::QuestionId::new(Uuid::from_bytes([8; 16])),
                    caller_token: kr_protocol::question::CallerToken::new(vec![0; 32]),
                    wait_ms: Nullable::null(),
                },
                now(2_000),
            )
            .expect_err("no such question");
        assert_eq!(
            error.code(),
            kr_protocol::error::ErrorCode::PermissionDenied
        );
        let events = questions.events_since(0, 16).expect("the feed");
        assert!(
            events
                .iter()
                .any(|(_, event)| event.kind == QuestionEventKind::Expired),
            "the expiry is in the feed: {events:?}"
        );
    }

    #[test]
    fn every_transition_reaches_the_feed_in_order() {
        let questions = questions();
        let (created, _) = questions
            .create(&source(), &select_params(), now(1_000))
            .expect("created");
        questions
            .answer(
                &ActorId::new("local:501").expect("a principal"),
                None,
                &QuestionAnswerParams {
                    session_id: session(),
                    question_id: created.question.question_id,
                    expected_revision: created.question.revision,
                    answer: QuestionAnswer::Choice {
                        choice_id: "left".to_owned(),
                    },
                },
                now(2_000),
            )
            .expect("answered");
        let events = questions.events_since(0, 16).expect("the feed");
        let kinds: Vec<QuestionEventKind> = events.iter().map(|(_, event)| event.kind).collect();
        assert_eq!(
            kinds,
            vec![QuestionEventKind::Created, QuestionEventKind::Answered]
        );
        // The idle reminder measures from the moment the question became pending, and every event
        // carries it.
        assert!(
            events
                .iter()
                .all(|(_, event)| event.pending_since_ms == TimestampMs::new(1_000))
        );
        let after_first = events[0].0;
        assert_eq!(
            questions
                .events_since(after_first, 16)
                .expect("the feed")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_wait_ends_when_a_question_is_answered() {
        let questions = std::sync::Arc::new(questions());
        let (created, _) = questions
            .create(&source(), &select_params(), now(1_000))
            .expect("created");
        let waiting = std::sync::Arc::clone(&questions);
        let waiter = tokio::spawn(async move {
            waiting
                .wait_for_change(std::time::Duration::from_secs(10))
                .await;
        });
        // Give the waiter a turn to register before the answer wakes it.
        tokio::task::yield_now().await;
        questions
            .answer(
                &ActorId::new("local:501").expect("a principal"),
                None,
                &QuestionAnswerParams {
                    session_id: session(),
                    question_id: created.question.question_id,
                    expected_revision: created.question.revision,
                    answer: QuestionAnswer::Choice {
                        choice_id: "left".to_owned(),
                    },
                },
                now(2_000),
            )
            .expect("answered");
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("the wait ended")
            .expect("the waiter finished");
    }
}
