//! What the store of kept answers and their sends keeps through a crash and through a second
//! command, against a record of sends written beside each answer.
//!
//! A test stop ends a write where a crash would, leaving exactly what is on disk then; the cases
//! then ask the library what it makes of it.

use std::sync::Mutex;

use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActionId, ActorId, ApplicationInstanceId, ConnectionId, EnvironmentId, QuestionId,
    QuestionRevision, SessionEpoch, SessionId,
};
use kr_protocol::method::MethodVersion;
use kr_protocol::question::{
    Question, QuestionAnswer, QuestionAnswerParams, QuestionChoice, QuestionKind,
    QuestionResolveResult, QuestionSource, QuestionState,
};
use kr_protocol::receipt::{Receipt, ReceiptState};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};

use super::{
    AnswerDraft, AnswerDrafts, AnswerError, AnswerFailure, Dispatch, Keeper, Leave, QuestionHost,
    Reconciled, Settled, reconcile,
};
use crate::error::ClientError;
use crate::sends::{self, Stop};
use crate::shown::Shown;

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn target() -> ActionTarget {
    ActionTarget {
        environment_id: EnvironmentId::new(Uuid::from_bytes([2; 16])),
        session_id: Nullable::some(session()),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

fn question(byte: u8) -> Question {
    Question {
        question_id: QuestionId::new(Uuid::from_bytes([byte; 16])),
        revision: QuestionRevision::new(1),
        state: QuestionState::Pending,
        session_id: session(),
        session_epoch: SessionEpoch::V1,
        kind: QuestionKind::Confirm,
        context: "two tests fail".to_owned(),
        question: "push anyway?".to_owned(),
        choices: vec![QuestionChoice::something_else()],
        source: QuestionSource {
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
            process: ProcessStartIdentity::new(42, ProcessStartSource::LinuxProcStat, 7),
            executable: Nullable::some("/usr/bin/some-agent".to_owned()),
            agent_label: Nullable::null(),
            connection_id: ConnectionId::new(Uuid::from_bytes([4; 16])),
            launch_channel: false,
            session_member: true,
            ancestry: true,
            agent_binding_revision: Nullable::null(),
        },
        created_at_ms: TimestampMs::new(1_000),
        expires_at_ms: TimestampMs::new(86_401_000),
        answer: Nullable::null(),
        resolved_at_ms: Nullable::null(),
    }
}

fn action(byte: u8) -> ActionId {
    ActionId::new(Uuid::from_bytes([byte; 16]))
}

fn draft(asked: &Question, decided: bool) -> AnswerDraft {
    AnswerDraft {
        version: super::ANSWER_FORMAT,
        target: target(),
        session_id: asked.session_id,
        question_id: asked.question_id,
        question_revision: asked.revision,
        answer: QuestionAnswer::Decision { decided },
        drafted_at_ms: TimestampMs::new(5_000),
    }
}

/// A client outside a store, which holds nothing and may write any record.
fn with_leave<R>(work: impl FnOnce(&Leave<'_>) -> R) -> R {
    let writers = kr_ipc::install::hold_writers(
        &kr_ipc::install::Writing::in_roots(std::env::temp_dir(), std::env::temp_dir()),
        &mut || {},
    )
    .expect("a client outside a store holds nothing");
    let leave = Leave {
        answers: writers.permit(&super::WRITTEN).expect("permitted"),
        sends: writers.permit(&sends::WRITTEN).expect("permitted"),
    };
    work(&leave)
}

struct Hold;

impl Keeper for Hold {
    fn keep<R>(&self, work: impl FnOnce(&Leave<'_>) -> R) -> Result<R, Shown> {
        Ok(with_leave(work))
    }
}

fn store() -> (tempfile::TempDir, AnswerDrafts) {
    let directory = tempfile::TempDir::new().expect("a directory");
    let drafts = AnswerDrafts::open(directory.path().join("answers")).expect("the store opens");
    (directory, drafts)
}

/// Records `draft` with `sends` carried and `send` added, as an attempt does before it sends.
fn begin(
    drafts: &AnswerDrafts,
    draft: &AnswerDraft,
    carried: &[ActionId],
    send: ActionId,
) -> Result<Digest256, AnswerError> {
    let basis = drafts.basis(draft.question_id).expect("the pair reads");
    with_leave(|leave| drafts.begin(draft, &basis, carried, send, leave))
}

/// The host as a worker keeps receipts, with no way to send.
struct Journal {
    questions: Mutex<Vec<Question>>,
    receipts: Mutex<Vec<(ActionId, ReceiptState)>>,
}

impl Journal {
    fn with(questions: Vec<Question>, receipts: Vec<(ActionId, ReceiptState)>) -> Self {
        Self {
            questions: Mutex::new(questions),
            receipts: Mutex::new(receipts),
        }
    }
}

impl QuestionHost for Journal {
    fn questions(
        &self,
        _session_id: SessionId,
    ) -> impl Future<Output = Result<Vec<Question>, ClientError>> + Send {
        let found = self.questions.lock().expect("the lock").clone();
        async move { Ok(found) }
    }

    fn answer(
        &self,
        _target: ActionTarget,
        _params: QuestionAnswerParams,
        _dispatch: Dispatch,
    ) -> impl Future<Output = Result<QuestionResolveResult, AnswerFailure>> + Send {
        async move { Err(AnswerFailure::unwritten(ClientError::ConnectionEnded)) }
    }

    fn receipt(
        &self,
        _session_id: SessionId,
        action_id: ActionId,
    ) -> impl Future<Output = Result<Receipt, ClientError>> + Send {
        let found = self
            .receipts
            .lock()
            .expect("the lock")
            .iter()
            .find(|(id, _)| *id == action_id)
            .map(|(_, state)| *state);
        let outcome = match found {
            Some(state) => Ok(Receipt {
                action_id,
                actor_id: ActorId::new("local:1").expect("a principal"),
                method: kr_protocol::method::Method::QuestionAnswer.into(),
                method_version: MethodVersion::V1,
                revision: U64::new(3),
                state,
                reason: Nullable::null(),
                payload_digest: Digest256::from_bytes([0; 32]),
                accepted_deadline_ms: Nullable::null(),
                error: Nullable::null(),
                error_withheld: false,
                updated_at_ms: TimestampMs::new(7),
            }),
            None => Err(ClientError::Host(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!("no receipt for action {action_id}"),
            ))),
        };
        async move { outcome }
    }

    fn session_ended(
        &self,
        _session_id: SessionId,
    ) -> impl Future<Output = Result<bool, ClientError>> + Send {
        async move { Ok(false) }
    }
}

fn files(drafts: &AnswerDrafts) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(&drafts.directory)
        .expect("lists")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name != "answers.lock")
        .collect();
    names.sort();
    names
}

/// A record is written with its answer, read back bound to it, and removed with it.
#[test]
fn a_record_of_sends_is_written_with_its_answer_read_back_and_removed_with_it() {
    let (_directory, drafts) = store();
    let asked = question(5);
    let kept = draft(&asked, true);
    begin(&drafts, &kept, &[], action(9)).expect("recorded");
    assert_eq!(
        files(&drafts),
        vec![
            format!("{}.answer", asked.question_id),
            format!("{}.send", asked.question_id)
        ]
    );
    let (read, basis) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("kept");
    assert_eq!(read, kept);
    assert_eq!(basis.sends(), [action(9)]);
    assert!(
        drafts
            .remove_if_unchanged(asked.question_id, &basis)
            .expect("removes")
    );
    assert!(files(&drafts).is_empty());
}

/// A record names the answer it is valid for by a digest of the answer's bytes: an answer changed
/// from outside the store, as an older release would, leaves a record that describes no row, which
/// a reconcile sweeps before it reads any worker.
#[tokio::test]
async fn a_record_that_names_no_answer_on_disk_is_ignored_and_swept() {
    let (_directory, drafts) = store();
    let asked = question(5);
    begin(&drafts, &draft(&asked, true), &[], action(9)).expect("recorded");
    // The answer is replaced, as a release that lists the answers alone replaces it.
    let other = AnswerDraft {
        answer: QuestionAnswer::Decision { decided: false },
        ..draft(&asked, true)
    };
    let kept = AnswerDraft {
        version: super::ANSWER_FORMAT,
        ..other
    };
    std::fs::write(
        drafts.path(asked.question_id),
        kr_cbor::to_canonical_vec(&kept).expect("encodes"),
    )
    .expect("written");
    let (_, basis) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("kept");
    assert!(
        basis.sends().is_empty(),
        "the record describes another answer"
    );

    let host = Journal::with(vec![asked.clone()], Vec::new());
    let reconciled = reconcile(&host, &drafts).await.expect("reconciles");
    assert!(matches!(
        reconciled.as_slice(),
        [Reconciled::Offered { earlier, .. }] if earlier.is_empty()
    ));
    assert_eq!(
        files(&drafts),
        vec![format!("{}.answer", asked.question_id)]
    );
}

/// A record that cannot be read, is of a later format, or holds contents this build did not write
/// closes the answer it sits beside: the answer is neither listed nor replaced, and the failure
/// names the record.
#[test]
fn a_record_that_cannot_be_read_closes_its_answer() {
    use kr_cbor::{CanonicalMap, CanonicalValue};

    let (_directory, drafts) = store();
    let asked = question(5);
    begin(&drafts, &draft(&asked, true), &[], action(9)).expect("recorded");
    let path = drafts.record_path(asked.question_id);
    let record = |version: i128, sends: usize| {
        let mut map = CanonicalMap::new();
        map.insert(
            "version".to_owned(),
            CanonicalValue::integer(version).expect("an integer"),
        )
        .expect("a key");
        map.insert(
            "draft".to_owned(),
            kr_cbor::to_canonical_value(&vec![Digest256::from_bytes([1; 32])]).expect("encodes"),
        )
        .expect("a key");
        map.insert(
            "sends".to_owned(),
            kr_cbor::to_canonical_value(&vec![action(1); sends]).expect("encodes"),
        )
        .expect("a key");
        map.insert(
            "sent_at_ms".to_owned(),
            CanonicalValue::integer(1).expect("an integer"),
        )
        .expect("a key");
        kr_cbor::encode(&CanonicalValue::Map(map))
    };
    for (what, bytes) in [
        ("not a record", b"not a record".to_vec()),
        ("a later format", record(2, 1)),
        ("version 1 with no sends", record(1, 0)),
        ("version 1 with a send named twice", record(1, 2)),
    ] {
        std::fs::write(&path, &bytes).expect("planted");
        assert!(
            matches!(drafts.entries(), Err(AnswerError::Unreadable { .. })),
            "{what} is not read"
        );
        let refused = begin_error(&drafts, &draft(&asked, false), &[], action(8));
        assert!(
            matches!(refused, AnswerError::Unreadable { .. }),
            "{what} is not replaced: {refused}"
        );
        assert_eq!(
            std::fs::read(&path).expect("reads"),
            bytes,
            "{what} is left as it is"
        );
    }
}

fn begin_error(
    drafts: &AnswerDrafts,
    draft: &AnswerDraft,
    carried: &[ActionId],
    send: ActionId,
) -> AnswerError {
    match drafts.basis(draft.question_id) {
        Err(error) => error,
        Ok(basis) => with_leave(|leave| drafts.begin(draft, &basis, carried, send, leave))
            .expect_err("refused"),
    }
}

/// With eight sends not settled a ninth is refused: nothing is written.
#[test]
fn a_ninth_unsettled_send_is_refused_and_nothing_is_written() {
    let (_directory, drafts) = store();
    let asked = question(5);
    let kept = draft(&asked, true);
    let eight: Vec<ActionId> = (1..=8).map(action).collect();
    let mut carried = Vec::new();
    for send in &eight {
        begin(&drafts, &kept, &carried, *send).expect("recorded");
        carried.push(*send);
    }
    let before = std::fs::read(drafts.record_path(asked.question_id)).expect("reads");
    let refused = begin_error(&drafts, &kept, &carried, action(9));
    assert!(matches!(refused, AnswerError::Full), "{refused}");
    assert_eq!(
        std::fs::read(drafts.record_path(asked.question_id)).expect("reads"),
        before
    );
}

/// Whatever step of replacing an answer a crash ends at, the record on disk matches the answer on
/// disk and still names the send that was Unknown, and names no send that never went out; a
/// reconcile then offers the answer with that send as the one a new send quotes.
#[tokio::test]
async fn a_crash_at_any_step_of_a_replacement_forgets_no_earlier_send() {
    for (stop, replaced) in [(Stop::AfterCarry, false), (Stop::AfterDraft, true)] {
        let (_directory, drafts) = store();
        let asked = question(5);
        let first = draft(&asked, true);
        let second = draft(&asked, false);
        begin(&drafts, &first, &[], action(1)).expect("recorded");
        let host = Journal::with(
            vec![asked.clone()],
            vec![(action(1), ReceiptState::Unknown)],
        );

        sends::stop_at(Some(stop));
        let stopped = begin_error(&drafts, &second, &[action(1)], action(2));
        assert!(
            matches!(stopped, AnswerError::Store { .. }),
            "{stop:?}: {stopped}"
        );

        let (on_disk, basis) = drafts
            .entry(asked.question_id)
            .expect("reads")
            .expect("kept");
        assert_eq!(
            on_disk,
            if replaced {
                second.clone()
            } else {
                first.clone()
            },
            "{stop:?}"
        );
        assert_eq!(
            basis.sends(),
            [action(1)],
            "{stop:?}: the send is still named, the new one is not"
        );

        let reconciled = reconcile(&host, &drafts).await.expect("reconciles");
        let [Reconciled::Offered { earlier, .. }] = reconciled.as_slice() else {
            panic!("{stop:?}: offered, got {reconciled:?}");
        };
        assert_eq!(
            earlier.quote().map(|quote| quote.action_id),
            Some(action(1)),
            "{stop:?}"
        );
    }

    // A replacement that completes names the earlier send and the new one.
    let (_directory, drafts) = store();
    let asked = question(5);
    begin(&drafts, &draft(&asked, true), &[], action(1)).expect("recorded");
    begin(&drafts, &draft(&asked, false), &[action(1)], action(2)).expect("recorded");
    let (_, basis) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("kept");
    assert_eq!(basis.sends(), [action(1), action(2)]);
}

/// A removal that a crash ends between the answer and its record leaves a record that describes no
/// row, which a reconcile sweeps.
#[tokio::test]
async fn a_crash_between_the_two_removals_leaves_an_inert_record_that_is_swept() {
    let (_directory, drafts) = store();
    let asked = question(5);
    begin(&drafts, &draft(&asked, true), &[], action(1)).expect("recorded");
    let (_, basis) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("kept");

    sends::stop_at(Some(Stop::AfterDraftRemoved));
    let stopped = drafts
        .remove_if_unchanged(asked.question_id, &basis)
        .expect_err("stopped");
    assert!(matches!(stopped, AnswerError::Store { .. }), "{stopped}");
    assert_eq!(files(&drafts), vec![format!("{}.send", asked.question_id)]);
    assert!(drafts.drafts().expect("reads").is_empty());

    let host = Journal::with(vec![asked], Vec::new());
    assert!(
        reconcile(&host, &drafts)
            .await
            .expect("reconciles")
            .is_empty()
    );
    assert!(files(&drafts).is_empty(), "the record was swept");
}

/// A command that decided from a reading of the pair changes nothing once another command has
/// replaced the answer: a replacement stored meanwhile stays, whether the first command records,
/// begins, removes after a result or settles.
#[test]
fn a_replacement_stored_meanwhile_is_never_taken_by_a_command_that_read_before() {
    let (_directory, drafts) = store();
    let asked = question(5);
    let first = draft(&asked, true);
    let digest = begin(&drafts, &first, &[], action(1)).expect("recorded");
    let (_, read) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("kept");

    // The other command stores its replacement.
    let second = draft(&asked, false);
    begin(&drafts, &second, &[action(1)], action(2)).expect("recorded");

    let refused = with_leave(|leave| drafts.begin(&first, &read, &[action(1)], action(3), leave))
        .expect_err("stale");
    assert!(matches!(refused, AnswerError::Changed), "{refused}");
    let refused = with_leave(|leave| {
        drafts.record_send(asked.question_id, &read, &[action(1)], action(3), leave)
    })
    .expect_err("stale");
    assert!(matches!(refused, AnswerError::Changed), "{refused}");
    // A result for the first answer removes nothing of the second.
    drafts
        .remove_after_result(asked.question_id, digest)
        .expect("compared");
    // Nor does a retirement, nor a settling of the first answer's send.
    assert!(
        !drafts
            .remove_if_unchanged(asked.question_id, &read)
            .expect("compared")
    );
    let settled =
        with_leave(|leave| drafts.settle(asked.question_id, digest, &[action(1)], true, leave))
            .expect("compared");
    assert_eq!(settled, Settled::Changed);
    let (kept, basis) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("kept");
    assert_eq!(kept, second);
    assert_eq!(basis.sends(), [action(1), action(2)]);
}

/// A second command that recorded a send of the same answer meanwhile keeps it: a settling drops
/// only the identifiers it holds proof of and leaves the pair, and a retirement decided from the
/// earlier reading removes nothing.
#[test]
fn a_send_another_command_recorded_meanwhile_stays_in_the_record() {
    let (_directory, drafts) = store();
    let asked = question(5);
    let kept = draft(&asked, true);
    let digest = begin(&drafts, &kept, &[], action(1)).expect("recorded");
    let (_, read) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("kept");

    // The other command records its own send of the same answer.
    with_leave(|leave| {
        drafts.record_send(asked.question_id, &read, &[action(1)], action(2), leave)
    })
    .expect("recorded");

    // The first command was refused for its send and settles it. The pair stays.
    let settled =
        with_leave(|leave| drafts.settle(asked.question_id, digest, &[action(1)], true, leave))
            .expect("settled");
    assert_eq!(settled, Settled::Kept);
    let (_, now) = drafts
        .entry(asked.question_id)
        .expect("reads")
        .expect("kept");
    assert_eq!(now.sends(), [action(2)]);

    // A retirement decided from the first reading removes nothing.
    assert!(
        !drafts
            .remove_if_unchanged(asked.question_id, &read)
            .expect("compared")
    );
    assert_eq!(files(&drafts).len(), 2);

    // The other command's send is settled in its turn, and the pair goes with it.
    let removed =
        with_leave(|leave| drafts.settle(asked.question_id, digest, &[action(2)], true, leave))
            .expect("settled");
    assert_eq!(removed, Settled::Removed);
    assert!(files(&drafts).is_empty());
}
