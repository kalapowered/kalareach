//! Section 11's question contract, against the worker's ledger on a real journal.
//!
//! The ledger is what a session's worker keeps its agents' questions in: a SQLite journal on disk,
//! written in full-durability mode, with the caller token held as a keyed tag and a sealed copy
//! whose key lives only in the worker's memory. These tests open that ledger on a journal in a
//! temporary directory, act as the verified application and as the person answering, and read the
//! journal back through a second connection, which is what a restarted worker would see.

use std::path::Path;

use kr_crypto::secret::SymmetricKey;
use kr_protocol::error::ErrorCode;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    ActorId, ConnectionId, DeviceId, QuestionId, QuestionRevision, SessionEpoch, SessionId,
};
use kr_protocol::question::{
    AlertCreateParams, AlertSeverity, CallerToken, DEFAULT_EXPIRY, MAX_EXPIRY, QuestionAnswer,
    QuestionAnswerParams, QuestionCancelOwnParams, QuestionCancelParams, QuestionCreateParams,
    QuestionEventKind, QuestionKind, QuestionReadOwnParams, QuestionReadParams, QuestionState,
};
use kr_protocol::scalars::{DurationMs, Nullable, TimestampMs, Uuid};
use kr_worker::questions::store::Store;
use kr_worker::questions::{Now, Questions, VerifiedSource, token};

fn now(utc_ms: u64) -> Now {
    Now {
        utc_ms: TimestampMs::new(utc_ms),
        boot_ms: utc_ms,
    }
}

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([5; 16]))
}

/// This test process, calling on connection `connection`: an application that is alive for as
/// long as the test is.
fn source(connection: u8) -> VerifiedSource {
    VerifiedSource {
        process: kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        executable: Some("kr-test-agent".to_owned()),
        session_member: true,
        ancestry: true,
        launch_channel: false,
        connection_id: ConnectionId::new(Uuid::from_bytes([connection; 16])),
    }
}

/// A later execution: the same process identifier and the same name, but another start value.
fn later_execution() -> VerifiedSource {
    let mut source = source(9);
    let process = source.process.clone();
    source.process = ProcessStartIdentity::new(
        process.pid.get(),
        process.source,
        process.start_value.get() + 1,
    );
    source
}

fn ask(request_id: &str, kind: QuestionKind) -> QuestionCreateParams {
    QuestionCreateParams {
        session_id: session(),
        request_id: request_id.to_owned(),
        agent_name: Nullable::some("kr-test-agent".to_owned()),
        context: "The build finished with two failing tests.".to_owned(),
        question: "Push the branch anyway?".to_owned(),
        kind,
        choices: Vec::new(),
        requested_expiry_ms: Nullable::null(),
        wait_ms: Nullable::null(),
    }
}

fn person() -> ActorId {
    ActorId::new("local:501").expect("a principal")
}

fn answer(
    question_id: QuestionId,
    revision: QuestionRevision,
    decided: bool,
) -> QuestionAnswerParams {
    QuestionAnswerParams {
        session_id: session(),
        question_id,
        expected_revision: revision,
        answer: QuestionAnswer::Decision { decided },
    }
}

fn read_own(question_id: QuestionId, caller_token: &CallerToken) -> QuestionReadOwnParams {
    QuestionReadOwnParams {
        session_id: session(),
        question_id,
        caller_token: CallerToken::new(caller_token.as_slice().to_vec()),
        wait_ms: Nullable::null(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The journal and its write-ahead companions, as bytes.
fn journal_bytes(journal: &Path) -> Vec<Vec<u8>> {
    ["", "-wal", "-shm"]
        .iter()
        .filter_map(|suffix| std::fs::read(format!("{}{suffix}", journal.display())).ok())
        .collect()
}

/// KR-REQ-11.56: the caller token is in no question event, no attention input a notification or
/// push is built from, no read a person's client receives, no debug rendering and no byte of the
/// journal a backup is made from; the journal keeps only a keyed tag and a sealed copy under a key
/// the worker holds in memory; and when that worker's ledger ends, which is where a question's
/// source access ends, the token is gone: a ledger opened on the same journal afterwards neither
/// accepts it nor recovers it for an exact retry.
#[test]
fn the_caller_token_is_in_no_event_record_or_log_and_ends_with_the_workers_key() {
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let journal = directory.path().join("journal.sqlite");
    let questions = Questions::open(Some(journal.as_path()), session(), SessionEpoch::V1)
        .expect("the ledger opens");
    let params = ask("push-anyway", QuestionKind::Confirm);
    let (created, _) = questions
        .create(&source(1), &params, now(1_000))
        .expect("the agent asks");
    let token = created.caller_token.as_slice().to_vec();
    let question_id = created.question.question_id;
    questions
        .answer(
            &person(),
            None,
            &answer(question_id, created.question.revision, true),
            now(2_000),
        )
        .expect("the person answers");

    // Every event the ledger fed onward, in both of its encodings, and the attention record built
    // from it, which is what notifications and push previews are made from.
    let feed = questions.events_since(0, 64).expect("the feed reads");
    assert_eq!(
        feed.iter().map(|(_, event)| event.kind).collect::<Vec<_>>(),
        [QuestionEventKind::Created, QuestionEventKind::Answered]
    );
    for (sequence, event) in &feed {
        let json = serde_json::to_string(event).expect("an event serialises");
        assert!(!json.contains(&hex(&token)), "{json}");
        let cbor = kr_cbor::to_canonical_vec(event).expect("an event encodes");
        assert!(!contains(&cbor, &token));
        let record = kr_worker::attention_source::question_record(*sequence, event, true);
        let json = serde_json::to_string(&record).expect("a record serialises");
        assert!(!json.contains(&hex(&token)), "{json}");
        let cbor = kr_cbor::to_canonical_vec(&record).expect("a record encodes");
        assert!(!contains(&cbor, &token));
        assert_eq!(record.question_id, question_id);
        match record.kind {
            QuestionEventKind::Created => {
                assert_eq!(record.text.0.as_deref(), Some(params.question.as_str()));
            }
            QuestionEventKind::Answered => assert!(record.text.0.is_none()),
            other => panic!("a question event became {other:?}"),
        }
    }

    // What a person's client reads, and what a log line would print.
    let (read, _) = questions
        .read(
            &QuestionReadParams {
                session_id: session(),
                question_id: Nullable::null(),
                include_resolved: true,
            },
            now(2_100),
        )
        .expect("the answering surface reads");
    assert!(
        !serde_json::to_string(&read)
            .expect("serialises")
            .contains(&hex(&token))
    );
    let printed = format!("{created:?}");
    assert!(printed.contains("CallerToken(redacted)"), "{printed}");
    assert!(!printed.contains(&hex(&token)));

    // The journal, which is everything a backup of this session could be made from.
    for bytes in journal_bytes(&journal) {
        assert!(!contains(&bytes, &token), "the token is on disk");
        assert!(!contains(&bytes, hex(&token).as_bytes()));
    }

    // What the journal does keep: a 32-byte keyed tag and a sealed copy, neither of them the token.
    let reopened = Store::open(Some(journal.as_path()), session(), SessionEpoch::V1)
        .expect("a second connection");
    let row = reopened.read_row(question_id).expect("the row");
    assert_eq!(row.token_tag.len(), 32);
    assert_ne!(row.token_tag, token);
    assert!(!contains(&row.token_sealed, &token));

    // While the ledger that issued it is open, the token works: it reads its own question.
    questions
        .read_own(
            &source(1),
            &read_own(question_id, &created.caller_token),
            now(2_200),
        )
        .expect("the issuing ledger accepts its own token");

    // The worker's key is in its memory only. Under any other key, which is all a restarted worker
    // or a reader of the file holds, the sealed copy does not open and the token does not verify.
    let other = SymmetricKey::random().expect("a key");
    assert!(token::unseal(&other, question_id, &row.token_nonce, &row.token_sealed).is_err());
    assert!(token::verify(&other, question_id, &created.caller_token, &row.token_tag).is_err());

    // The ledger that issued the token ends, and its key with it. What is left is the journal, and
    // a ledger opened on it afterwards turns the same application's token away and cannot give the
    // token back to an exact retry of the creation.
    drop(questions);
    let restarted = Questions::open(Some(journal.as_path()), session(), SessionEpoch::V1)
        .expect("the ledger reopens");
    let refused = restarted
        .read_own(
            &source(1),
            &read_own(question_id, &created.caller_token),
            now(3_000),
        )
        .expect_err("the token ended with the ledger that issued it");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    assert!(
        restarted.create(&source(1), &params, now(3_000)).is_err(),
        "an exact retry cannot recover the token from the journal"
    );
    for bytes in journal_bytes(&journal) {
        assert!(!contains(&bytes, &token), "the token is on disk");
    }
}

/// KR-REQ-11.58: waiting on and cancelling a question need both its caller token and the verified
/// application that created it; a changed payload under a used request identifier is `ID_CONFLICT`
/// and an identical one returns the same question with the same token.
#[test]
fn waiting_and_cancelling_need_the_token_and_the_application_that_asked() {
    let questions = Questions::open(None, session(), SessionEpoch::V1).expect("the ledger opens");
    let (first, _) = questions
        .create(&source(1), &ask("first", QuestionKind::Confirm), now(1_000))
        .expect("the agent asks");
    let (second, _) = questions
        .create(
            &source(1),
            &ask("second", QuestionKind::Confirm),
            now(1_000),
        )
        .expect("and asks again");
    let question_id = first.question.question_id;

    // The right application with the wrong question's token: refused for a wait and for a cancel.
    let refused = questions
        .read_own(
            &source(1),
            &read_own(question_id, &second.caller_token),
            now(1_100),
        )
        .expect_err("another question's token");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    let refused = questions
        .cancel_own(
            &source(1),
            &QuestionCancelOwnParams {
                session_id: session(),
                question_id,
                caller_token: CallerToken::new(second.caller_token.as_slice().to_vec()),
            },
            now(1_100),
        )
        .expect_err("another question's token");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);

    // The right token from another application: refused for both as well.
    let refused = questions
        .read_own(
            &later_execution(),
            &read_own(question_id, &first.caller_token),
            now(1_100),
        )
        .expect_err("another application");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    let refused = questions
        .cancel_own(
            &later_execution(),
            &QuestionCancelOwnParams {
                session_id: session(),
                question_id,
                caller_token: CallerToken::new(first.caller_token.as_slice().to_vec()),
            },
            now(1_100),
        )
        .expect_err("another application");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        questions.question(question_id).expect("reads").state,
        QuestionState::Pending,
        "nothing a refused caller did changed the question"
    );

    // Both together: the wait reads it and the cancel ends it.
    let (own, _) = questions
        .read_own(
            &source(1),
            &read_own(question_id, &first.caller_token),
            now(1_200),
        )
        .expect("the token and the application together");
    assert_eq!(own.question.question_id, question_id);
    let (cancelled, _) = questions
        .cancel_own(
            &source(1),
            &QuestionCancelOwnParams {
                session_id: session(),
                question_id,
                caller_token: CallerToken::new(first.caller_token.as_slice().to_vec()),
            },
            now(1_300),
        )
        .expect("cancels");
    assert_eq!(cancelled.question.state, QuestionState::Cancelled);

    // The same request identifier: the same payload is the same question and the same token, a
    // changed one is a conflict.
    let (again, _) = questions
        .create(
            &source(1),
            &ask("second", QuestionKind::Confirm),
            now(1_400),
        )
        .expect("an exact retry");
    assert!(again.deduplicated);
    assert_eq!(again.question.question_id, second.question.question_id);
    assert_eq!(
        again.caller_token.as_slice(),
        second.caller_token.as_slice()
    );
    let mut changed = ask("second", QuestionKind::Confirm);
    changed.question = "Push the branch and the tags anyway?".to_owned();
    let conflict = questions
        .create(&source(1), &changed, now(1_500))
        .expect_err("a changed payload");
    assert_eq!(conflict.code(), ErrorCode::IdConflict);
}

/// KR-REQ-11.60: `pending` moves to `answered`, `cancelled` or `expired` and the move is durable;
/// of two answers from two connections to the journal exactly one wins, and the answer stored is
/// that one's; the answer carries the actor, the device, the time and the revision it answered;
/// the method table requires `question.respond` for answering and cancelling; a question nobody
/// acts on stays pending, because dismissing a form is no transition at all; and cancellation and
/// expiry are separate states.
#[test]
fn a_transition_persists_the_first_answer_wins_and_cancellation_and_expiry_stay_apart() {
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let journal = directory.path().join("journal.sqlite");
    let questions = Questions::open(Some(journal.as_path()), session(), SessionEpoch::V1)
        .expect("the ledger opens");
    let (answered, _) = questions
        .create(
            &source(1),
            &ask("answer-me", QuestionKind::Confirm),
            now(1_000),
        )
        .expect("asks");
    let (cancelled, _) = questions
        .create(
            &source(1),
            &ask("cancel-me", QuestionKind::Confirm),
            now(1_000),
        )
        .expect("asks");
    let mut short = ask("let-me-expire", QuestionKind::Confirm);
    short.requested_expiry_ms = Nullable::some(DurationMs::new(60_000));
    let (expiring, _) = questions
        .create(&source(1), &short, now(1_000))
        .expect("asks");
    let (untouched, _) = questions
        .create(
            &source(1),
            &ask("leave-me", QuestionKind::Confirm),
            now(1_000),
        )
        .expect("asks");

    // Two clients, two connections to the same journal, the same revision, at once.
    let id = answered.question.question_id;
    let revision = answered.question.revision;
    let device = DeviceId::new(Uuid::from_bytes([7; 16]));
    let outcomes: Vec<_> = [true, false]
        .into_iter()
        .map(|decided| {
            let journal = journal.clone();
            std::thread::spawn(move || {
                let mut store = Store::open(Some(journal.as_path()), session(), SessionEpoch::V1)
                    .expect("connects");
                store
                    .answer(
                        id,
                        revision,
                        &QuestionAnswer::Decision { decided },
                        &person(),
                        Some(device),
                        now(2_000),
                    )
                    .map(|resolved| (decided, resolved.question.state))
                    .map_err(|error| error.code())
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|handle| handle.join().expect("the answering thread"))
        .collect();
    let winners: Vec<(bool, QuestionState)> = outcomes
        .iter()
        .filter_map(|outcome| outcome.as_ref().ok().copied())
        .collect();
    assert_eq!(winners.len(), 1, "exactly one answer won: {outcomes:?}");
    assert_eq!(winners[0].1, QuestionState::Answered);
    assert!(
        outcomes.contains(&Err(ErrorCode::QuestionResolved)),
        "{outcomes:?}"
    );

    questions
        .cancel(
            &QuestionCancelParams {
                session_id: session(),
                question_id: cancelled.question.question_id,
                expected_revision: cancelled.question.revision,
            },
            now(2_000),
        )
        .expect("cancels");
    let swept = questions.sweep(now(1_000 + 60_001)).expect("sweeps");
    assert_eq!(
        swept
            .iter()
            .map(|event| (event.kind, event.question.question_id))
            .collect::<Vec<_>>(),
        [(QuestionEventKind::Expired, expiring.question.question_id)],
        "only the question whose deadline passed expires; the cancelled one stays cancelled"
    );

    // A fresh connection reads every state back from the journal.
    let reopened = Store::open(Some(journal.as_path()), session(), SessionEpoch::V1)
        .expect("a second connection");
    let stored = reopened.read(id).expect("the answered question");
    assert_eq!(stored.state, QuestionState::Answered);
    let record = stored.answer.as_ref().expect("the answer");
    assert_eq!(
        record.answer,
        QuestionAnswer::Decision {
            decided: winners[0].0
        },
        "the stored answer is the one whose call succeeded, not the one that was turned away"
    );
    assert_eq!(record.actor_id, person());
    assert_eq!(record.device_id.as_ref(), Some(&device));
    assert_eq!(record.question_revision, revision);
    assert_eq!(record.answered_at_ms, TimestampMs::new(2_000));
    assert_eq!(
        reopened
            .read(cancelled.question.question_id)
            .expect("reads")
            .state,
        QuestionState::Cancelled
    );
    assert_eq!(
        reopened
            .read(expiring.question.question_id)
            .expect("reads")
            .state,
        QuestionState::Expired
    );
    let left = reopened
        .read(untouched.question.question_id)
        .expect("reads");
    assert_eq!(left.state, QuestionState::Pending);
    assert_eq!(left.revision, untouched.question.revision);

    // The method table requires `question.respond` for answering and cancelling and
    // `session.view` for reading.
    use kr_protocol::authority::RequiredAuthority;
    use kr_protocol::rights::ActionRight;
    let rights = |name: &str| -> Vec<RequiredAuthority> {
        kr_protocol::method::lookup(name)
            .unwrap_or_else(|| panic!("{name} is listed"))
            .required_rights
            .iter()
            .map(|required| required.authority)
            .collect()
    };
    for name in ["question.answer", "question.cancel"] {
        assert_eq!(
            rights(name),
            [RequiredAuthority::Right {
                right: ActionRight::QuestionRespond
            }],
            "{name}"
        );
    }
    assert_eq!(
        rights("question.read"),
        [RequiredAuthority::Right {
            right: ActionRight::SessionView
        }]
    );
}

/// KR-REQ-11.62: with no expiry asked for, a question lasts a day, and it never lasts longer; the
/// identity header of an application no bridge describes carries no agent binding revision, so the
/// question is application-scoped and no thread-switch detection is claimed; the same application
/// reads its question again on a new connection after a disconnect; and a later execution under
/// the same name and the same process identifier is refused the old question and, asking with the
/// same request identifier, is given a new question rather than the old decision.
#[test]
fn a_question_is_the_applications_for_a_day_and_a_later_execution_inherits_nothing() {
    let questions = Questions::open(None, session(), SessionEpoch::V1).expect("the ledger opens");
    let (created, _) = questions
        .create(
            &source(1),
            &ask("push-anyway", QuestionKind::Confirm),
            now(1_000),
        )
        .expect("asks");
    assert_eq!(
        created.question.expires_at_ms.get() - created.question.created_at_ms.get(),
        DEFAULT_EXPIRY.get()
    );
    assert_eq!(DEFAULT_EXPIRY.get(), 24 * 60 * 60 * 1000);
    let mut greedy = ask("keep-it-open", QuestionKind::Confirm);
    greedy.requested_expiry_ms = Nullable::some(DurationMs::new(MAX_EXPIRY.get() * 7));
    let (capped, _) = questions
        .create(&source(1), &greedy, now(1_000))
        .expect("asks");
    assert_eq!(
        capped.question.expires_at_ms.get() - capped.question.created_at_ms.get(),
        MAX_EXPIRY.get(),
        "a longer expiry is cut to the day"
    );

    assert!(
        created
            .question
            .source
            .agent_binding_revision
            .as_ref()
            .is_none(),
        "no bridge supplied a binding revision, so none is claimed"
    );

    // A short disconnect: the same application, a new connection, the same token.
    let (own, _) = questions
        .read_own(
            &source(2),
            &read_own(created.question.question_id, &created.caller_token),
            now(1_500),
        )
        .expect("the same application reads its question after reconnecting");
    assert_eq!(own.question.question_id, created.question.question_id);

    // A later execution that reuses the name, and even the process identifier.
    let refused = questions
        .read_own(
            &later_execution(),
            &read_own(created.question.question_id, &created.caller_token),
            now(1_500),
        )
        .expect_err("a later execution");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    let (fresh, _) = questions
        .create(
            &later_execution(),
            &ask("push-anyway", QuestionKind::Confirm),
            now(1_600),
        )
        .expect("a later execution asks under the old request identifier");
    assert!(!fresh.deduplicated);
    assert_ne!(fresh.question.question_id, created.question.question_id);
    assert_ne!(
        fresh.caller_token.as_slice(),
        created.caller_token.as_slice()
    );
}

/// KR-REQ-11.62: a question ends with the application that asked it, before its day is up.
#[cfg(unix)]
#[test]
fn a_question_ends_when_the_application_that_asked_it_exits() {
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("60")
        .current_dir(std::env::temp_dir())
        .spawn()
        .expect("starts an application");
    let pid = child.id();
    let mut application = source(3);
    application.process =
        kr_ipc::identity::process_start_identity(pid).expect("the application's identity");
    let questions = Questions::open(None, session(), SessionEpoch::V1).expect("the ledger opens");
    let (created, _) = questions
        .create(
            &application,
            &ask("while-you-run", QuestionKind::Confirm),
            now(1_000),
        )
        .expect("asks");
    assert!(
        questions.sweep(now(2_000)).expect("sweeps").is_empty(),
        "a running application keeps its question"
    );

    child
        .kill()
        .expect("ends the application this test started");
    child.wait().expect("reaps it");
    let swept = questions.sweep(now(3_000)).expect("sweeps");
    assert_eq!(swept.len(), 1, "the question went with its application");
    assert_eq!(swept[0].question.question_id, created.question.question_id);
    assert_eq!(swept[0].question.state, QuestionState::Expired);
}

/// KR-REQ-11.63: an answer goes back to the source only through a read that presents that
/// question's own caller token: a question identifier with no token, with a token of the same
/// length that was never issued, or with another question's token retrieves nothing.
#[test]
fn a_question_identifier_alone_retrieves_no_answer() {
    let questions = Questions::open(None, session(), SessionEpoch::V1).expect("the ledger opens");
    let (asked, _) = questions
        .create(&source(1), &ask("mine", QuestionKind::Confirm), now(1_000))
        .expect("asks");
    let (other, _) = questions
        .create(
            &source(1),
            &ask("theirs", QuestionKind::Confirm),
            now(1_000),
        )
        .expect("asks");
    let question_id = asked.question.question_id;
    questions
        .answer(
            &person(),
            None,
            &answer(question_id, asked.question.revision, true),
            now(2_000),
        )
        .expect("answers");

    for presented in [
        CallerToken::new(Vec::new()),
        CallerToken::new(vec![0; kr_protocol::question::CALLER_TOKEN_BYTES]),
        CallerToken::new(other.caller_token.as_slice().to_vec()),
    ] {
        let refused = questions
            .read_own(&source(1), &read_own(question_id, &presented), now(2_100))
            .expect_err("no answer without the question's own token");
        assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    }
    let (own, _) = questions
        .read_own(
            &source(1),
            &read_own(question_id, &asked.caller_token),
            now(2_100),
        )
        .expect("the question's own token");
    assert_eq!(
        own.question
            .answer
            .as_ref()
            .map(|record| record.answer.clone()),
        Some(QuestionAnswer::Decision { decided: true })
    );
}

/// KR-REQ-11.64: answering yes resolves the question and does nothing else: the only transition is
/// the question's own, the attention record it produces is the question's resolution and never an
/// approval, and the answer record names the answer, the actor and the revision and no approval or
/// grant.
#[test]
fn a_yes_resolves_the_question_and_raises_no_approval() {
    let questions = Questions::open(None, session(), SessionEpoch::V1).expect("the ledger opens");
    let (asked, _) = questions
        .create(
            &source(1),
            &ask("delete-branch", QuestionKind::Confirm),
            now(1_000),
        )
        .expect("asks");
    let before = questions.events_since(0, 64).expect("the feed").len();
    let (resolved, events) = questions
        .answer(
            &person(),
            None,
            &answer(asked.question.question_id, asked.question.revision, true),
            now(2_000),
        )
        .expect("answers yes");
    assert_eq!(resolved.question.state, QuestionState::Answered);
    assert_eq!(
        events.iter().map(|event| event.kind).collect::<Vec<_>>(),
        [QuestionEventKind::Answered]
    );
    let feed = questions.events_since(0, 64).expect("the feed");
    assert_eq!(feed.len(), before + 1, "one transition, the question's own");
    for (sequence, event) in &feed {
        let kind = kr_worker::attention_source::question_record(*sequence, event, true).kind;
        assert!(
            matches!(
                kind,
                QuestionEventKind::Created | QuestionEventKind::Answered
            ),
            "an answer raised {kind:?}"
        );
    }
    let record = serde_json::to_value(resolved.question.answer.as_ref().expect("the answer"))
        .expect("serialises");
    let mut fields: Vec<&str> = record
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "actor_id",
            "answer",
            "answered_at_ms",
            "device_id",
            "question_revision"
        ]
    );
}

/// KR-REQ-11.65: an alert carries its de-duplication identifier, the caller's label, its text, its
/// severity and an optional safe session link; it creates no question and hands back no token, and
/// a repeat under the same identifier raises nothing new.
#[test]
fn an_alert_carries_its_identifier_label_text_severity_and_link_and_asks_nothing() {
    let questions = Questions::open(None, session(), SessionEpoch::V1).expect("the ledger opens");
    let params = AlertCreateParams {
        session_id: session(),
        dedup_id: "build-failed".to_owned(),
        agent_name: Nullable::some("kr-test-agent".to_owned()),
        text: "The build failed on the release branch.".to_owned(),
        severity: AlertSeverity::Error,
        safe_session_link: Nullable::some("kalareach://session/build".to_owned()),
    };
    let first = questions
        .alert(&source(1), &params, now(1_000))
        .expect("raises");
    assert!(!first.deduplicated);
    let alert = &first.alert;
    assert_eq!(alert.dedup_id, "build-failed");
    assert_eq!(
        alert.source.agent_label.as_ref().map(String::as_str),
        Some("kr-test-agent")
    );
    assert_eq!(alert.text, params.text);
    assert_eq!(alert.severity, AlertSeverity::Error);
    assert_eq!(
        alert.safe_session_link.as_ref().map(String::as_str),
        Some("kalareach://session/build")
    );
    let value = serde_json::to_value(&first).expect("serialises");
    assert!(
        value.get("caller_token").is_none(),
        "an alert hands back no token"
    );

    let without_link = AlertCreateParams {
        dedup_id: "tests-passed".to_owned(),
        safe_session_link: Nullable::null(),
        severity: AlertSeverity::Info,
        ..params.clone()
    };
    let second = questions
        .alert(&source(1), &without_link, now(1_100))
        .expect("the link is optional");
    assert!(second.alert.safe_session_link.as_ref().is_none());

    let repeated = questions
        .alert(&source(1), &params, now(1_200))
        .expect("repeats");
    assert!(repeated.deduplicated);
    assert_eq!(questions.alerts().expect("reads").len(), 2);
    let (read, _) = questions
        .read(
            &QuestionReadParams {
                session_id: session(),
                question_id: Nullable::null(),
                include_resolved: true,
            },
            now(1_300),
        )
        .expect("reads");
    assert!(read.questions.is_empty(), "an alert is not a question");
}
