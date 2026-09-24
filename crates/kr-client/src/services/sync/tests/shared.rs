//! The calls about a collection two or more devices share, and what the client makes of every
//! answer the service can give them.
//!
//! Two services answer here. The scripted one from the parent module records each request whole
//! and answers what a test told it to, which holds each member's mapping to the contract. The
//! other, [`Contract`], keeps the contract itself for writes, status queries and fences in a shared
//! collection: receipts under request identities, fences, who the collection's key records list,
//! and key epochs, decided in the service's own order. The two tests about a retired epoch run
//! against it, because what they prove is how this client's requests meet that order. It checks no
//! signature; the deployed legs hold the client to the service itself.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::sync::membership::{
    CollectionRef, KeyRecordService, KeyRecords, RecordAt, RekeyAnswer, RekeyFence, RekeyStatus,
};
use kr_crypto::envelope::{
    CollectionRecipient, CollectionRecordDraft, issue_collection_key_record,
};
use kr_crypto::keys::{AuthorisationKeyPair, DeviceKeys};
use kr_protocol::collection_keys::CollectionKeyRecord;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{InstallationId, SyncKeyEpoch, SyncKeyRecordRevision};
use kr_protocol::scalars::Digest256;
use kr_protocol::service::{ServiceRequestSignature, installation_id};

/* -------------------------------------------------------------------------- */
/* Shapes                                                                      */
/* -------------------------------------------------------------------------- */

fn installation(seed: u8) -> InstallationId {
    InstallationId::new(identity(seed))
}

fn shared_collection(home: InstallationId, seed: u8) -> CollectionRef {
    CollectionRef {
        home,
        collection_id: SyncCollectionId::new(identity(seed)),
    }
}

/// A real key record of `collection` at `revision` and `epoch`, issued by a fresh device that is
/// its only member.
fn record(collection: &CollectionRef, revision: u64, epoch: u64) -> CollectionKeyRecord {
    let issuer = DeviceKeys::generate().expect("device keys");
    let draft = CollectionRecordDraft {
        collection_id: collection.collection_id,
        home: collection.home,
        key_epoch: SyncKeyEpoch::new(epoch),
        revision: SyncKeyRecordRevision::new(revision),
        previous: (revision > 1).then(|| Digest256::from_bytes([0x44; 32])),
        issued_at_ms: TimestampMs::new(1_780_000_000_000),
        members: vec![CollectionRecipient {
            authorisation: *issuer.authorisation.public(),
            stored_envelope: *issuer.stored_envelope.public(),
        }],
    };
    issue_collection_key_record(
        &issuer.authorisation,
        &issuer.stored_envelope,
        &draft,
        &Secret::from_bytes([0x5c; 32]),
    )
    .expect("a record")
}

/// The same record under another revision. Its signature no longer holds, which this client does
/// not check: the reader of the records does.
fn at_revision(record: &CollectionKeyRecord, revision: u64) -> CollectionKeyRecord {
    let mut moved = record.clone();
    moved.payload.revision = SyncKeyRecordRevision::new(revision);
    moved
}

/// A page of key records, as a read of them is answered.
fn keys_page(records: &[CollectionKeyRecord], more: bool, newest: KeyHead) -> serde_json::Value {
    serde_json::json!({
        "records": records
            .iter()
            .map(|record| serde_json::to_value(record).expect("a record"))
            .collect::<Vec<_>>(),
        "more": more,
        "key_revision": newest.revision.to_string(),
        "key_epoch": newest.epoch.to_string(),
        "recovery_id": newest.recovery.map(|recovery| recovery.to_string()),
    })
}

/// A refusal the service named, with members beside its code.
fn refusal_with(status: u16, code: &str, members: serde_json::Value) -> ServiceHttpAnswer {
    let mut error = serde_json::json!({ "code": code, "message": "refused" });
    if let (Some(error), Some(members)) = (error.as_object_mut(), members.as_object()) {
        error.extend(members.clone());
    }
    ServiceHttpAnswer {
        status,
        body: serde_json::to_vec(&serde_json::json!({ "ok": false, "error": error }))
            .expect("a refusal"),
    }
}

/// A successful envelope around `data`.
fn answered(data: serde_json::Value) -> ServiceHttpAnswer {
    ServiceHttpAnswer {
        status: 200,
        body: serde_json::to_vec(&serde_json::json!({ "ok": true, "data": data }))
            .expect("an answer"),
    }
}

/// What a status query or a fence is answered with about a receipt that recorded `outcome`.
fn receipt_status(
    request: Uuid,
    state: &str,
    outcome: &str,
    head: Option<KeyHead>,
    never_ran: bool,
) -> serde_json::Value {
    let mut answer = status(request, state, never_ran);
    answer["outcome"] = serde_json::Value::String(outcome.to_owned());
    if let Some(head) = head {
        answer["key_epoch"] = serde_json::Value::String(head.epoch.to_string());
        answer["key_revision"] = serde_json::Value::String(head.revision.to_string());
    }
    answer
}

/// What a comparison of a shared collection is answered with.
fn compared_shared(
    objects: &[(Uuid, SyncRevision, u64, u64)],
    copies: &[(u64, Uuid, Uuid, u64)],
    more: bool,
    next: u64,
    head: KeyHead,
) -> serde_json::Value {
    serde_json::json!({
        "changed": [],
        "removed": [],
        "revisions": objects
            .iter()
            .map(|(object, revision, write_sequence, epoch)| serde_json::json!({
                "object_id": object.to_string(),
                "revision": revision.to_string(),
                "write_sequence": write_sequence.to_string(),
                "key_epoch": epoch.to_string(),
            }))
            .collect::<Vec<_>>(),
        "conflicts": copies
            .iter()
            .map(|(sequence, conflict, object, epoch)| serde_json::json!({
                "sequence": sequence.to_string(),
                "conflict_id": conflict.to_string(),
                "kind": "settings",
                "object_id": object.to_string(),
                "expected_revision": null,
                "current_revision": revision(0x31).to_string(),
                "current_write_sequence": "2",
                "key_epoch": epoch.to_string(),
                "object": sealed(b"a refused write"),
                "recorded_at": "2026-09-24T10:00:00.000Z",
            }))
            .collect::<Vec<_>>(),
        "next_conflicts_after_sequence": next.to_string(),
        "more_conflicts": more,
        "key_epoch": head.epoch.to_string(),
        "key_revision": head.revision.to_string(),
        "recovery_id": head.recovery.map(|recovery| recovery.to_string()),
        "stored": usage(),
    })
}

/// The code a refusal became.
fn code_of(error: &ClientError) -> ErrorCode {
    error.code()
}

/// A budget of pages.
fn budget(pages: usize) -> std::num::NonZeroUsize {
    std::num::NonZeroUsize::new(pages).expect("a budget of at least one page")
}

/* -------------------------------------------------------------------------- */
/* Each member's mapping and refusal: key records                              */
/* -------------------------------------------------------------------------- */

#[tokio::test]
async fn a_read_of_key_records_names_the_home_and_follows_every_page_to_the_newest() {
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let first = record(&collection, 1, 0);
    let chain = [
        first.clone(),
        at_revision(&first, 2),
        at_revision(&first, 3),
    ];
    let head = KeyHead {
        epoch: 0,
        revision: 3,
        recovery: None,
    };
    recorder.answering(vec![
        keys_page(&chain[..2], true, head),
        keys_page(&chain[2..], false, head),
    ]);

    let read = client
        .records_after(&collection, 0)
        .await
        .expect("the records");
    assert_eq!(
        read,
        KeyRecords::Records {
            records: chain.to_vec(),
            recovery: None
        }
    );
    assert_eq!(recorder.requests(), 2, "one request a page, to the newest");
    let sent = recorder.last_body();
    assert_eq!(
        sent["keys"]["after_revision"], "2",
        "from the last record read"
    );
    assert_eq!(sent["keys"]["home"], collection.home.to_string());
    assert_eq!(
        sent["keys"]["collection_id"],
        collection.collection_id.to_string()
    );
    assert_eq!(
        sent["keys"].as_object().expect("members").len(),
        3,
        "a read of key records carries the collection, its home and the revision"
    );
}

#[tokio::test]
async fn a_collection_that_does_not_list_this_device_answers_key_reads_as_absent() {
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);

    recorder.answering_with(vec![refusal(404, "COLLECTION_ABSENT", "not a member")]);
    assert_eq!(
        client
            .records_after(&collection, 3)
            .await
            .expect("an answer"),
        KeyRecords::Absent
    );
    assert_eq!(
        client.record_at(&collection, 4).await.expect("an answer"),
        RecordAt::Absent
    );

    // A collection no record has claimed answers its home no records at revision nought.
    recorder.answering(vec![serde_json::json!({
        "records": [],
        "more": false,
        "key_revision": "0",
        "key_epoch": null,
        "recovery_id": null,
    })]);
    assert_eq!(
        client
            .records_after(&collection, 0)
            .await
            .expect("an answer"),
        KeyRecords::Records {
            records: Vec::new(),
            recovery: None
        }
    );
    assert_eq!(
        client.record_at(&collection, 1).await.expect("an answer"),
        RecordAt::Missing { recovery: None }
    );

    // The record at one revision is the first of the records after the one before it.
    let at_four = at_revision(&record(&collection, 2, 1), 4);
    recorder.answering(vec![keys_page(
        std::slice::from_ref(&at_four),
        false,
        KeyHead {
            epoch: 1,
            revision: 4,
            recovery: None,
        },
    )]);
    assert_eq!(
        client.record_at(&collection, 4).await.expect("an answer"),
        RecordAt::Record {
            record: at_four,
            recovery: None
        }
    );
    assert_eq!(recorder.last_body()["keys"]["after_revision"], "3");

    // Revisions count from one, so the record at nought is not asked for.
    let before = recorder.requests();
    assert!(client.record_at(&collection, 0).await.is_err());
    assert_eq!(recorder.requests(), before);

    // Any other refusal is the error the service named.
    recorder.answering_with(vec![refusal(400, "INVALID_ARGUMENT", "a bad revision")]);
    let refused = client
        .records_after(&collection, 0)
        .await
        .expect_err("a refusal");
    assert_eq!(code_of(&refused), ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn a_read_of_key_records_ends_when_a_page_does_not_move_on_or_the_bound_is_passed() {
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let one = record(&collection, 1, 0);
    let head = KeyHead {
        epoch: 0,
        revision: 9,
        recovery: None,
    };

    // A page that claims more and does not move the cursor on ends the read with what was
    // answered: whether it follows is the reader's to decide.
    recorder.answering(vec![keys_page(&[at_revision(&one, 3)], true, head)]);
    assert_eq!(
        client
            .records_after(&collection, 5)
            .await
            .expect("an answer"),
        KeyRecords::Records {
            records: vec![at_revision(&one, 3)],
            recovery: None
        }
    );
    assert_eq!(recorder.requests(), 1);
    recorder.answering(vec![keys_page(&[], true, head)]);
    assert_eq!(
        client
            .records_after(&collection, 5)
            .await
            .expect("an answer"),
        KeyRecords::Records {
            records: Vec::new(),
            recovery: None
        }
    );
    assert_eq!(recorder.requests(), 2);

    // A service that keeps moving on past the bound is not followed further.
    let page = 16_u64;
    let pages = u64::try_from(MAX_KEY_RECORDS_READ).expect("a bound") / page + 2;
    recorder.answering(
        (0..pages)
            .map(|index| {
                let records: Vec<_> = (1..=page)
                    .map(|offset| at_revision(&one, index * page + offset))
                    .collect();
                keys_page(&records, true, head)
            })
            .collect(),
    );
    let refused = client
        .records_after(&collection, 0)
        .await
        .expect_err("past the bound");
    assert_eq!(code_of(&refused), ErrorCode::OutcomeUnknown);
}

#[tokio::test]
async fn the_offer_of_a_key_record_carries_its_identity_home_and_record_and_its_answer() {
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let offered = record(&collection, 2, 1);
    let request = identity(0x51);
    let signed_at = now_ms() - 1_000;

    recorder.answering(vec![serde_json::json!({
        "state": "applied",
        "key_revision": "2",
        "key_epoch": "1",
        "recovery_id": null,
    })]);
    assert_eq!(
        client
            .rekey(&collection, request, signed_at, &offered)
            .await
            .expect("an answer"),
        RekeyAnswer::Applied {
            revision: 2,
            recovery: None
        }
    );
    let sent = recorder.last();
    assert_eq!(
        sent["signature"]["payload"]["signed_at_ms"],
        serde_json::to_value(TimestampMs::new(signed_at)).expect("an instant"),
        "the instant the caller recorded"
    );
    let rekey = &sent["body"]["rekey"];
    assert_eq!(rekey["request_id"], request.to_string());
    assert_eq!(rekey["collection_id"], collection.collection_id.to_string());
    assert_eq!(rekey["home"], collection.home.to_string());
    assert_eq!(
        rekey["record"],
        serde_json::to_value(&offered).expect("the record"),
        "the record as it was signed, field for field"
    );
    assert_eq!(rekey.as_object().expect("members").len(), 4);

    // A refusal is an answer, naming the revision the collection holds.
    recorder.answering(vec![serde_json::json!({
        "state": "refused",
        "key_revision": "5",
        "key_epoch": "3",
        "recovery_id": null,
    })]);
    assert_eq!(
        client
            .rekey(&collection, request, signed_at, &offered)
            .await
            .expect("an answer"),
        RekeyAnswer::Refused {
            revision: 5,
            recovery: None
        }
    );

    // A record applied at another revision than its own is not an answer this client reads.
    recorder.answering(vec![serde_json::json!({
        "state": "applied",
        "key_revision": "3",
        "key_epoch": "1",
        "recovery_id": null,
    })]);
    let contrary = client
        .rekey(&collection, request, signed_at, &offered)
        .await
        .expect_err("applied elsewhere");
    assert_eq!(code_of(&contrary), ErrorCode::OutcomeUnknown);

    // The refusals about the identity and the caller are errors, which settle by status and fence.
    for (status, code, expected) in [
        (409, "ID_CONFLICT", ErrorCode::IdConflict),
        (409, "REQUEST_FENCED", ErrorCode::PermissionDenied),
        (404, "COLLECTION_ABSENT", ErrorCode::UnknownSession),
    ] {
        recorder.answering_with(vec![refusal(status, code, "refused")]);
        let refused = client
            .rekey(&collection, request, signed_at, &offered)
            .await
            .expect_err("a refusal");
        assert_eq!(code_of(&refused), expected, "{code}");
    }
}

#[tokio::test]
async fn every_shared_answer_names_the_history_of_its_revisions() {
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let restored = super::put_back_by(0xb0);
    let head = KeyHead {
        epoch: 4,
        revision: 6,
        recovery: Some(restored),
    };

    // A write, and the head its answer names, are both places in the restored history.
    let mut written = exchanged(
        "written",
        summary(identity(7), revision(9), "4"),
        Some(revision(9)),
        "4",
        serde_json::Value::Null,
    );
    written["key_epoch"] = "4".into();
    written["key_revision"] = "6".into();
    recorder.answering(vec![super::under(written, restored)]);
    let sealed = published(&sealed(b"theme=dark"));
    assert_eq!(
        client
            .exchange_shared(
                &collection,
                &settings_of(identity(7)),
                4,
                identity(8),
                now_ms(),
                None,
                &sealed,
            )
            .await
            .expect("an answer"),
        Keyed::Answered {
            answer: SyncExchanged::Applied {
                position: SyncPosition::at(4, revision(9), Some(restored)),
            },
            head: Some(head),
        }
    );

    // A retired epoch names the head's history beside it.
    recorder.answering_with(vec![retired(head)]);
    assert_eq!(
        client
            .exchange_shared(
                &collection,
                &settings_of(identity(7)),
                3,
                identity(9),
                now_ms(),
                None,
                &sealed,
            )
            .await
            .expect("an answer"),
        Keyed::Retired { head }
    );

    // Each entry of a membership listing names the history its revision is in, as the index last
    // heard it, and entries of one listing may name different ones.
    recorder.answering(vec![serde_json::json!({
        "memberships": [
            {
                "home": installation(0x41).to_string(),
                "collection_id": identity(0x42).to_string(),
                "key_revision": "3",
                "key_epoch": "1",
                "recovery_id": restored.to_string(),
            },
            {
                "home": installation(0x41).to_string(),
                "collection_id": identity(0x43).to_string(),
                "key_revision": "5",
                "key_epoch": "2",
                "recovery_id": null,
            },
        ],
        "more": false,
        "next_after": null,
    })]);
    let listed = client.memberships().await.expect("the listing");
    assert_eq!(listed[0].head.recovery, Some(restored));
    assert_eq!(listed[1].head.recovery, None);
}

#[tokio::test]
async fn every_key_record_answer_names_the_history_it_is_in() {
    // A read of key records, the record at one revision, the offer of a record, and the status
    // and fence of an offer each name the history of the collection that answered, so the
    // reconciler can hold each of them to the history its records were read in.
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let restored = super::put_back_by(0xb0);
    let first = record(&collection, 1, 0);
    let head = KeyHead {
        epoch: 0,
        revision: 1,
        recovery: Some(restored),
    };
    recorder.answering(vec![
        keys_page(std::slice::from_ref(&first), false, head),
        keys_page(std::slice::from_ref(&first), false, head),
        keys_page(&[], false, head),
    ]);
    assert_eq!(
        client
            .records_after(&collection, 0)
            .await
            .expect("the records"),
        KeyRecords::Records {
            records: vec![first.clone()],
            recovery: Some(restored)
        }
    );
    assert_eq!(
        client.record_at(&collection, 1).await.expect("the record"),
        RecordAt::Record {
            record: first,
            recovery: Some(restored)
        }
    );
    assert_eq!(
        client.record_at(&collection, 2).await.expect("no record"),
        RecordAt::Missing {
            recovery: Some(restored)
        }
    );

    let offered = record(&collection, 2, 1);
    let request = identity(0x51);
    let offer = |state: &str, revision: &str, epoch: &str| {
        super::under(
            serde_json::json!({
                "state": state,
                "key_revision": revision,
                "key_epoch": epoch,
                "recovery_id": null,
            }),
            restored,
        )
    };
    recorder.answering(vec![offer("applied", "2", "1"), offer("refused", "5", "3")]);
    assert_eq!(
        client
            .rekey(&collection, request, now_ms(), &offered)
            .await
            .expect("an answer"),
        RekeyAnswer::Applied {
            revision: 2,
            recovery: Some(restored)
        }
    );
    assert_eq!(
        client
            .rekey(&collection, request, now_ms(), &offered)
            .await
            .expect("an answer"),
        RekeyAnswer::Refused {
            revision: 5,
            recovery: Some(restored)
        }
    );

    // A receipt the archive brought back is answered in the history that brought it back, and a
    // fence of an offer signed before the restore cannot say it never ran.
    let recorded = Some(KeyHead {
        epoch: 1,
        revision: 2,
        recovery: Some(restored),
    });
    let receipts = || {
        vec![
            super::under(
                receipt_status(request, "applied", "rekeyed", recorded, false),
                restored,
            ),
            super::under(
                receipt_status(request, "refused", "rekey_refused", recorded, false),
                restored,
            ),
            super::under(
                receipt_status(request, "fenced", "fenced", None, false),
                restored,
            ),
        ]
    };
    let mut statuses = receipts();
    statuses.push(super::under(status(request, "unknown", false), restored));
    recorder.answering(statuses);
    let mut answered = Vec::new();
    for _ in 0..4 {
        answered.push(
            client
                .rekey_status(&collection, request)
                .await
                .expect("an answer"),
        );
    }
    assert_eq!(
        answered,
        [
            RekeyStatus::Applied {
                revision: 2,
                recovery: Some(restored)
            },
            RekeyStatus::Refused {
                revision: 2,
                recovery: Some(restored)
            },
            RekeyStatus::Fenced {
                never_ran: false,
                recovery: Some(restored)
            },
            RekeyStatus::Unknown {
                recovery: Some(restored)
            },
        ]
    );
    recorder.answering(receipts());
    let (first_signed, last_signed) = (now_ms() - 2_000, now_ms() - 1_000);
    let mut fenced = Vec::new();
    for _ in 0..3 {
        fenced.push(
            client
                .rekey_fence(&collection, request, first_signed, last_signed)
                .await
                .expect("an answer"),
        );
    }
    assert_eq!(
        fenced,
        [
            RekeyFence::Applied {
                revision: 2,
                recovery: Some(restored)
            },
            RekeyFence::Refused {
                revision: 2,
                recovery: Some(restored)
            },
            RekeyFence::Fenced {
                never_ran: false,
                recovery: Some(restored)
            },
        ]
    );
}

#[tokio::test]
async fn a_read_that_meets_a_restore_between_its_pages_is_not_one_this_client_follows() {
    // Places compare only under one history, so pages of one read that name two histories would
    // join a chain, a listing of objects or a run of copies from both. Such a read is declined, and
    // asking again reads one history whole.
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let restored = super::put_back_by(0xb0);
    let first = record(&collection, 1, 0);
    let before = KeyHead {
        epoch: 0,
        revision: 3,
        recovery: None,
    };
    let after = KeyHead {
        recovery: Some(restored),
        ..before
    };
    recorder.answering(vec![
        keys_page(std::slice::from_ref(&first), true, before),
        keys_page(&[at_revision(&first, 2)], false, after),
    ]);
    assert_eq!(
        code_of(
            &client
                .records_after(&collection, 0)
                .await
                .expect_err("a chain from two histories")
        ),
        ErrorCode::OutcomeUnknown
    );

    // A comparison's pages, which follow until nothing listed is missing.
    let object = identity(0x61);
    let page = |head: KeyHead| {
        let mut page = compared_shared(&[(object, revision(0x62), 1, 0)], &[], false, 0, head);
        page["changed"] = serde_json::json!([]);
        page
    };
    let mut brought = page(after);
    brought["changed"] = serde_json::json!([{
        "kind": "settings",
        "object_id": object.to_string(),
        "revision": revision(0x62).to_string(),
        "write_sequence": "1",
        "key_epoch": "0",
        "object": sealed(b"theme=dark"),
        "updated_at": "2026-09-24T10:00:00.000Z",
    }]);
    recorder.answering(vec![page(before), brought]);
    assert_eq!(
        code_of(
            &client
                .compare_shared(&collection, &[], false, None)
                .await
                .expect_err("a comparison from two histories")
        ),
        ErrorCode::OutcomeUnknown
    );

    // An inventory continued from a read in one history takes no page from another.
    recorder.answering(vec![compared_shared(
        &[(object, revision(0x62), 1, 0)],
        &[(1, identity(0x71), object, 0)],
        true,
        1,
        before,
    )]);
    let started = client
        .inventory(&collection, None, budget(1))
        .await
        .expect("an answer")
        .expect("a member");
    assert!(!started.is_complete());
    assert_eq!(started.recovery, None);
    recorder.answering(vec![compared_shared(
        &[(object, revision(0x62), 1, 0)],
        &[(2, identity(0x72), object, 0)],
        false,
        2,
        after,
    )]);
    assert_eq!(
        code_of(
            &client
                .inventory(&collection, Some(started), budget(1))
                .await
                .expect_err("copies from two histories")
        ),
        ErrorCode::OutcomeUnknown
    );
}

#[tokio::test]
async fn a_shared_answer_that_leaves_out_its_recovery_is_not_one_this_client_reads() {
    // A key record's revision is a place in the collection's history as much as an object's write
    // is, so every answer naming one names the history too: a read of the records, the answer to
    // an offer, each entry of a membership listing, and a write refused for a retired epoch. One
    // without it is declined as any answer missing a required member is.
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let first = record(&collection, 1, 0);
    let head = KeyHead {
        epoch: 0,
        revision: 1,
        recovery: None,
    };

    recorder.answering(vec![super::without_recovery(keys_page(
        std::slice::from_ref(&first),
        false,
        head,
    ))]);
    assert_eq!(
        code_of(
            &client
                .records_after(&collection, 0)
                .await
                .expect_err("a read of the records")
        ),
        ErrorCode::OutcomeUnknown
    );
    assert_eq!(
        code_of(
            &client
                .record_at(&collection, 1)
                .await
                .expect_err("a read of one record")
        ),
        ErrorCode::OutcomeUnknown
    );

    let offered = record(&collection, 2, 1);
    for answer in [
        serde_json::json!({ "state": "applied", "key_revision": "2", "key_epoch": "1" }),
        serde_json::json!({ "state": "refused", "key_revision": "5", "key_epoch": "3" }),
    ] {
        recorder.answering(vec![answer]);
        assert_eq!(
            code_of(
                &client
                    .rekey(&collection, identity(0x51), now_ms(), &offered)
                    .await
                    .expect_err("an answer to an offer")
            ),
            ErrorCode::OutcomeUnknown
        );
    }

    recorder.answering(vec![serde_json::json!({
        "memberships": [{
            "home": installation(0x41).to_string(),
            "collection_id": identity(0x42).to_string(),
            "key_revision": "3",
            "key_epoch": "1",
        }],
        "more": false,
        "next_after": null,
    })]);
    assert_eq!(
        code_of(&client.memberships().await.expect_err("an entry")),
        ErrorCode::OutcomeUnknown
    );

    recorder.answering_with(vec![refusal_with(
        409,
        "KEY_EPOCH_RETIRED",
        serde_json::json!({ "key_epoch": "5", "key_revision": "7" }),
    )]);
    assert_eq!(
        code_of(
            &client
                .exchange_shared(
                    &collection,
                    &settings_of(identity(7)),
                    4,
                    identity(8),
                    now_ms(),
                    None,
                    &published(&sealed(b"theme=dark")),
                )
                .await
                .expect_err("a retired epoch names the head's history")
        ),
        ErrorCode::OutcomeUnknown
    );
}

/// A key record travels as the JSON the published vectors give it, which is the form the service
/// reads and keeps, and a read of the records hands back the record that was offered.
#[tokio::test]
async fn a_key_record_travels_in_the_json_form_the_vectors_publish() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/crypto/collection-keys.json");
    let text = std::fs::read_to_string(&path).expect("the collection key fixture");
    let fixture: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    let vectors = fixture["records"].as_array().expect("the records");
    assert!(!vectors.is_empty());

    for vector in vectors {
        let published = vector["record_json"].clone();
        let offered: CollectionKeyRecord =
            serde_json::from_value(published.clone()).expect("a record the vectors publish");
        let collection = CollectionRef {
            home: offered.payload.home,
            collection_id: offered.payload.collection_id,
        };
        let head = KeyHead {
            epoch: offered.payload.key_epoch.get(),
            revision: offered.payload.revision.get(),
            recovery: None,
        };
        let (client, recorder) = sync_client();
        recorder.answering(vec![serde_json::json!({
            "state": "applied",
            "key_revision": head.revision.to_string(),
            "key_epoch": head.epoch.to_string(),
            "recovery_id": null,
        })]);
        assert_eq!(
            client
                .rekey(&collection, identity(0x51), now_ms(), &offered)
                .await
                .expect("an answer"),
            RekeyAnswer::Applied {
                revision: head.revision,
                recovery: None
            }
        );
        assert_eq!(
            recorder.last_body()["rekey"]["record"],
            published,
            "field for field, as the vectors publish it"
        );

        recorder.answering(vec![keys_page(std::slice::from_ref(&offered), false, head)]);
        assert_eq!(
            client
                .records_after(&collection, head.revision - 1)
                .await
                .expect("an answer"),
            KeyRecords::Records {
                records: vec![offered],
                recovery: None
            }
        );
    }
}

#[tokio::test]
async fn a_key_record_the_service_would_refuse_never_leaves_this_device() {
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let signed_at = now_ms();

    let elsewhere = record(&shared_collection(installation(0x41), 0x43), 2, 1);
    let other_home = record(&shared_collection(installation(0x44), 0x42), 2, 1);
    let mut no_members = record(&collection, 2, 1);
    no_members.payload.members.clear();
    // Counters the service compares exactly and no further, in the revision and in the epoch.
    let past_revision = record(&collection, MAX_SYNC_COUNTER + 1, 1);
    let past_epoch = record(&collection, 2, MAX_SYNC_COUNTER + 1);
    for offered in [elsewhere, other_home, no_members, past_revision, past_epoch] {
        let refused = client
            .rekey(&collection, identity(0x51), signed_at, &offered)
            .await
            .expect_err("refused here");
        assert_eq!(code_of(&refused), ErrorCode::InvalidArgument);
    }
    assert_eq!(recorder.requests(), 0, "nothing was sent");
}

#[tokio::test]
async fn the_status_and_fence_of_a_key_record_offer_read_what_its_receipt_recorded() {
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let request = identity(0x52);
    let head = Some(KeyHead {
        epoch: 1,
        revision: 2,
        recovery: None,
    });

    recorder.answering(vec![
        receipt_status(request, "applied", "rekeyed", head, false),
        receipt_status(request, "refused", "rekey_refused", head, false),
        receipt_status(request, "fenced", "fenced", None, true),
        status(request, "unknown", false),
    ]);
    assert_eq!(
        client
            .rekey_status(&collection, request)
            .await
            .expect("an answer"),
        RekeyStatus::Applied {
            revision: 2,
            recovery: None
        }
    );
    let sent = recorder.last_body();
    assert_eq!(sent["status"]["home"], collection.home.to_string());
    assert_eq!(sent["status"]["request_id"], request.to_string());
    assert_eq!(
        client
            .rekey_status(&collection, request)
            .await
            .expect("an answer"),
        RekeyStatus::Refused {
            revision: 2,
            recovery: None
        }
    );
    assert_eq!(
        client
            .rekey_status(&collection, request)
            .await
            .expect("an answer"),
        RekeyStatus::Fenced {
            never_ran: true,
            recovery: None
        }
    );
    assert_eq!(
        client
            .rekey_status(&collection, request)
            .await
            .expect("an answer"),
        RekeyStatus::Unknown { recovery: None }
    );

    recorder.answering(vec![
        receipt_status(request, "applied", "rekeyed", head, false),
        receipt_status(request, "refused", "rekey_refused", head, false),
        receipt_status(request, "fenced", "fenced", None, false),
    ]);
    let first = now_ms() - 2_000;
    let last = now_ms() - 1_000;
    assert_eq!(
        client
            .rekey_fence(&collection, request, first, last)
            .await
            .expect("an answer"),
        RekeyFence::Applied {
            revision: 2,
            recovery: None
        }
    );
    let sent = recorder.last_body();
    assert_eq!(sent["fence"]["home"], collection.home.to_string());
    assert_eq!(sent["fence"]["first_signed_at_ms"], first.to_string());
    assert_eq!(sent["fence"]["last_signed_at_ms"], last.to_string());
    assert_eq!(
        client
            .rekey_fence(&collection, request, first, last)
            .await
            .expect("an answer"),
        RekeyFence::Refused {
            revision: 2,
            recovery: None
        }
    );
    assert_eq!(
        client
            .rekey_fence(&collection, request, first, last)
            .await
            .expect("an answer"),
        RekeyFence::Fenced {
            never_ran: false,
            recovery: None
        }
    );

    // What an offer's identity cannot be answered: a fence that does not know, a write's outcome,
    // a state its outcome is not answered as, and an offer's outcome that names no revision.
    let mut no_revision = receipt_status(request, "applied", "rekeyed", None, false);
    no_revision["key_epoch"] = serde_json::Value::String("1".to_owned());
    for (answer, fence) in [
        (status(request, "unknown", false), true),
        (
            receipt_status(request, "applied", "written", head, false),
            false,
        ),
        (
            receipt_status(request, "retired", "retired", head, false),
            false,
        ),
        (status(request, "applied", false), false),
        (
            receipt_status(request, "refused", "rekeyed", head, false),
            false,
        ),
        (no_revision, false),
    ] {
        recorder.answering(vec![answer.clone()]);
        let refused = if fence {
            client
                .rekey_fence(&collection, request, first, last)
                .await
                .expect_err("not an answer")
        } else {
            client
                .rekey_status(&collection, request)
                .await
                .expect_err("not an answer")
        };
        assert_eq!(code_of(&refused), ErrorCode::OutcomeUnknown, "{answer}");
    }
}

/* -------------------------------------------------------------------------- */
/* Each member's mapping and refusal: memberships, inventory, writes           */
/* -------------------------------------------------------------------------- */

#[tokio::test]
async fn a_membership_listing_follows_every_page_to_the_end() {
    let (client, recorder) = sync_client();
    let entry = |home: u8, collection: u8, revision: u64, epoch: u64| {
        serde_json::json!({
            "home": installation(home).to_string(),
            "collection_id": identity(collection).to_string(),
            "key_revision": revision.to_string(),
            "key_epoch": epoch.to_string(),
            "recovery_id": null,
        })
    };
    let cursor = |home: u8, collection: u8| format!("{}/{}", identity(home), identity(collection));
    recorder.answering(vec![
        serde_json::json!({
            "memberships": [entry(0x41, 0x42, 3, 1), entry(0x41, 0x43, 1, 0)],
            "more": true,
            "next_after": cursor(0x41, 0x43),
        }),
        serde_json::json!({
            "memberships": [entry(0x45, 0x46, 7, 2)],
            "more": false,
            "next_after": cursor(0x45, 0x46),
        }),
    ]);

    let listed = client.memberships().await.expect("the listing");
    assert_eq!(
        listed,
        vec![
            MembershipListing {
                collection: shared_collection(installation(0x41), 0x42),
                head: KeyHead {
                    epoch: 1,
                    revision: 3,
                    recovery: None
                },
            },
            MembershipListing {
                collection: shared_collection(installation(0x41), 0x43),
                head: KeyHead {
                    epoch: 0,
                    revision: 1,
                    recovery: None
                },
            },
            MembershipListing {
                collection: shared_collection(installation(0x45), 0x46),
                head: KeyHead {
                    epoch: 2,
                    revision: 7,
                    recovery: None
                },
            },
        ]
    );
    assert_eq!(recorder.requests(), 2);
    assert_eq!(
        recorder.last_body()["memberships"]["after"],
        cursor(0x41, 0x43)
    );

    // More with no cursor, and a cursor that does not move on, are not followed.
    for page in [
        serde_json::json!({ "memberships": [entry(0x41, 0x42, 3, 1)], "more": true, "next_after": null }),
        serde_json::json!({ "memberships": [], "more": true, "next_after": cursor(0x41, 0x42) }),
    ] {
        recorder.answering(vec![page]);
        let refused = client.memberships().await.expect_err("not followed");
        assert_eq!(code_of(&refused), ErrorCode::OutcomeUnknown);
    }
    recorder.answering(vec![serde_json::json!({
        "memberships": [entry(0x41, 0x42, 3, 1)],
        "more": true,
        "next_after": cursor(0x41, 0x42),
    })]);
    let refused = client.memberships().await.expect_err("not followed");
    assert_eq!(code_of(&refused), ErrorCode::OutcomeUnknown);
}

/// The inventory's pages: every object with its epoch, and every copy to the end of the cursor.
#[tokio::test]
async fn an_inventory_reads_every_object_and_every_copy_with_its_epoch_to_the_end() {
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let head = KeyHead {
        epoch: 2,
        revision: 3,
        recovery: None,
    };
    let (first, second) = (identity(0x61), identity(0x62));
    recorder.answering(vec![
        compared_shared(
            &[
                (first, revision(0x71), 4, 1),
                (second, revision(0x72), 2, 2),
            ],
            &[
                (1, identity(0x81), first, 1),
                (2, identity(0x82), second, 2),
            ],
            true,
            2,
            head,
        ),
        compared_shared(
            &[
                (first, revision(0x73), 5, 2),
                (second, revision(0x72), 2, 2),
            ],
            &[(3, identity(0x83), first, 1)],
            false,
            3,
            head,
        ),
    ]);

    let inventory = client
        .inventory(&collection, None, budget(16))
        .await
        .expect("an answer")
        .expect("a member");
    assert!(inventory.is_complete());
    assert_eq!(inventory.head, Some(head));
    assert_eq!(
        inventory.objects,
        vec![
            InventoryObject {
                object_id: SyncObjectId::new(first),
                position: SyncPosition::at(5, revision(0x73), None),
                epoch: Some(2),
            },
            InventoryObject {
                object_id: SyncObjectId::new(second),
                position: SyncPosition::at(2, revision(0x72), None),
                epoch: Some(2),
            },
        ],
        "the objects as the last page found them"
    );
    assert_eq!(
        inventory
            .copies
            .iter()
            .map(|copy| (copy.sequence, copy.epoch))
            .collect::<Vec<_>>(),
        vec![(1, Some(1)), (2, Some(2)), (3, Some(1))],
        "every copy, to the end of the cursor"
    );
    assert_eq!(inventory.epochs(), BTreeSet::from([1, 2]));
    assert!(inventory.may_hold_epoch(1), "copies under epoch 1 remain");
    assert!(!inventory.may_hold_epoch(0));

    assert_eq!(recorder.requests(), 2);
    let sent = recorder.last_body();
    let compare = &sent["compare"];
    assert_eq!(compare["home"], collection.home.to_string());
    assert_eq!(compare["with_conflicts"], true);
    assert_eq!(compare["conflicts_after_sequence"], "2");
    assert_eq!(
        compare["known"],
        serde_json::json!([
            { "object_id": first.to_string(), "revision": revision(0x71).to_string() },
            { "object_id": second.to_string(), "revision": revision(0x72).to_string() },
        ]),
        "the objects already read, so their content is not sent again"
    );

    // A collection that does not list this device.
    recorder.answering_with(vec![refusal(404, "COLLECTION_ABSENT", "not a member")]);
    assert_eq!(
        client
            .inventory(&collection, None, budget(16))
            .await
            .expect("an answer"),
        None
    );

    // Pages this client does not follow: a cursor that does not move on, more behind an empty
    // page, an object with no epoch or one after the collection's, and a copy behind the cursor.
    let mut no_epoch = compared_shared(&[(first, revision(0x71), 4, 1)], &[], false, 0, head);
    no_epoch["revisions"][0]
        .as_object_mut()
        .expect("members")
        .remove("key_epoch");
    for pages in [
        vec![
            compared_shared(&[], &[(1, identity(0x81), first, 1)], true, 1, head),
            compared_shared(&[], &[(2, identity(0x82), first, 1)], true, 1, head),
        ],
        vec![compared_shared(&[], &[], true, 4, head)],
        vec![no_epoch],
        vec![compared_shared(
            &[(first, revision(0x71), 4, 3)],
            &[],
            false,
            0,
            head,
        )],
        vec![
            compared_shared(&[], &[(4, identity(0x81), first, 1)], true, 4, head),
            compared_shared(&[], &[(4, identity(0x82), first, 1)], false, 4, head),
        ],
    ] {
        recorder.answering(pages);
        let refused = client
            .inventory(&collection, None, budget(16))
            .await
            .expect_err("not followed");
        assert_eq!(code_of(&refused), ErrorCode::OutcomeUnknown);
    }
}

#[tokio::test]
async fn a_shared_write_names_its_home_and_epoch_and_reads_both_answering_refusals() {
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let object = identity(7);
    let request = identity(8);
    let signed_at = now_ms() - 1_000;
    let sealed_object = sealed(b"theme=dark");
    let mut written = exchanged(
        "written",
        summary(object, revision(9), "4"),
        Some(revision(9)),
        "4",
        serde_json::Value::Null,
    );
    written["key_epoch"] = serde_json::Value::String("4".to_owned());
    written["key_revision"] = serde_json::Value::String("6".to_owned());
    recorder.answering(vec![written.clone()]);

    let write = |epoch: u64| {
        let client = client.clone();
        let sealed = published(&sealed_object);
        async move {
            client
                .exchange_shared(
                    &collection,
                    &settings_of(object),
                    epoch,
                    request,
                    signed_at,
                    None,
                    &sealed,
                )
                .await
        }
    };

    assert_eq!(
        write(4).await.expect("an answer"),
        Keyed::Answered {
            answer: SyncExchanged::Applied {
                position: SyncPosition::at(4, revision(9), None),
            },
            head: Some(KeyHead {
                epoch: 4,
                revision: 6,
                recovery: None
            }),
        }
    );
    let sent = recorder.last();
    assert_eq!(
        sent["signature"]["payload"]["signed_at_ms"],
        serde_json::to_value(TimestampMs::new(signed_at)).expect("an instant")
    );
    let exchange = &sent["body"]["exchange"];
    assert_eq!(
        exchange["collection_id"],
        collection.collection_id.to_string(),
        "the shared collection, not the object"
    );
    assert_eq!(exchange["object_id"], object.to_string());
    assert_eq!(exchange["home"], collection.home.to_string());
    assert_eq!(exchange["key_epoch"], "4");
    assert_eq!(exchange.as_object().expect("members").len(), 8);

    // A write under a retired epoch is an answer naming the collection's head.
    recorder.answering_with(vec![refusal_with(
        409,
        "KEY_EPOCH_RETIRED",
        serde_json::json!({ "key_epoch": "5", "key_revision": "7", "recovery_id": null }),
    )]);
    assert_eq!(
        write(4).await.expect("an answer"),
        Keyed::Retired {
            head: KeyHead {
                epoch: 5,
                revision: 7,
                recovery: None
            }
        }
    );
    // A collection that does not list this device is an answer too.
    recorder.answering_with(vec![refusal(404, "COLLECTION_ABSENT", "not a member")]);
    assert_eq!(write(4).await.expect("an answer"), Keyed::Absent);

    // A retired refusal that does not name the head or names it twice, an answer naming an epoch
    // without its revision, and the other refusals are not answers.
    let mut half_head = written.clone();
    half_head
        .as_object_mut()
        .expect("members")
        .remove("key_revision");
    for (answer, expected) in [
        (
            refusal(409, "KEY_EPOCH_RETIRED", "retired"),
            ErrorCode::OutcomeUnknown,
        ),
        (
            ServiceHttpAnswer {
                status: 409,
                body: br#"{"ok":false,"error":{"code":"KEY_EPOCH_RETIRED","message":"retired","key_epoch":"1","key_epoch":"9","key_revision":"2"}}"#.to_vec(),
            },
            ErrorCode::OutcomeUnknown,
        ),
        (answered(half_head), ErrorCode::OutcomeUnknown),
        (refusal(409, "ID_CONFLICT", "reused"), ErrorCode::IdConflict),
        (
            refusal(409, "REQUEST_FENCED", "fenced"),
            ErrorCode::PermissionDenied,
        ),
        (
            refusal(400, "INVALID_ARGUMENT", "an epoch ahead"),
            ErrorCode::InvalidArgument,
        ),
    ] {
        recorder.answering_with(vec![answer]);
        let refused = write(4).await.expect_err("not an answer");
        assert_eq!(code_of(&refused), expected);
    }

    // An epoch past what the service compares exactly never leaves this device.
    let before = recorder.requests();
    assert!(write(MAX_SYNC_COUNTER + 1).await.is_err());
    assert_eq!(recorder.requests(), before);
}

#[tokio::test]
async fn a_shared_comparison_and_resolution_name_the_home_and_read_each_epoch() {
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let object = identity(0x61);
    let head = KeyHead {
        epoch: 2,
        revision: 3,
        recovery: None,
    };
    let mut page = compared_shared(
        &[(object, revision(0x71), 4, 2)],
        &[(1, identity(0x81), object, 1)],
        false,
        1,
        head,
    );
    page["changed"] = serde_json::json!([{
        "kind": "settings",
        "object_id": object.to_string(),
        "revision": revision(0x71).to_string(),
        "write_sequence": "4",
        "key_epoch": "2",
        "object": sealed(b"theme=dark"),
        "updated_at": "2026-09-24T10:00:00.000Z",
    }]);
    recorder.answering(vec![page]);

    let compared = client
        .compare_shared(&collection, &[], true, None)
        .await
        .expect("an answer")
        .expect("a member");
    assert_eq!(compared.head, Some(head));
    assert_eq!(compared.objects[0].epoch, Some(2));
    assert_eq!(compared.copies[0].epoch, Some(1));
    let sent = recorder.last_body();
    assert_eq!(sent["compare"]["home"], collection.home.to_string());
    assert_eq!(
        sent["compare"]["collection_id"],
        collection.collection_id.to_string()
    );

    recorder.answering(vec![
        serde_json::json!({ "resolved": "1", "stored": usage() }),
    ]);
    assert_eq!(
        client
            .resolve_shared(&collection, SyncConflictId::new(identity(0x81)))
            .await
            .expect("an answer"),
        Some(true)
    );
    assert_eq!(
        recorder.last_body()["resolve"]["home"],
        collection.home.to_string()
    );

    recorder.answering_with(vec![refusal(404, "COLLECTION_ABSENT", "not a member")]);
    assert_eq!(
        client
            .compare_shared(&collection, &[], false, None)
            .await
            .expect("an answer"),
        None
    );
    assert_eq!(
        client
            .resolve_shared(&collection, SyncConflictId::new(identity(0x81)))
            .await
            .expect("an answer"),
        None
    );
}

/// A collection only its home writes names no epoch, so neither shared answer is one for it: each
/// stays the error the service named, and a retired state is not an answer to such a request.
#[tokio::test]
async fn a_collection_only_its_home_writes_reads_neither_shared_refusal_as_an_answer() {
    let (client, recorder) = sync_client();
    let object = identity(7);
    let sealed_object = sealed(b"theme=dark");

    for (answer, code, action) in [
        (
            refusal_with(
                409,
                "KEY_EPOCH_RETIRED",
                serde_json::json!({ "key_epoch": "1", "key_revision": "2", "recovery_id": null }),
            ),
            ErrorCode::ResyncRequired,
            UserAction::Resync,
        ),
        (
            refusal(404, "COLLECTION_ABSENT", "not a member"),
            ErrorCode::UnknownSession,
            UserAction::Nothing,
        ),
    ] {
        recorder.answering_with(vec![answer]);
        let refused = client
            .compare_exchange(
                &settings_of(object),
                identity(8),
                now_ms(),
                None,
                &published(&sealed_object),
            )
            .await
            .expect_err("an error here");
        assert_eq!(refused.code(), code);
        assert_eq!(refused.user_action(), action);
    }
    let exchange = &recorder.last_body()["exchange"];
    assert!(exchange.get("home").is_none() && exchange.get("key_epoch").is_none());

    recorder.answering(vec![receipt_status(
        identity(8),
        "retired",
        "retired",
        Some(KeyHead {
            epoch: 1,
            revision: 2,
            recovery: None,
        }),
        false,
    )]);
    let status = client
        .request_status(&settings_of(object), identity(8))
        .await
        .expect_err("not an answer here");
    assert_eq!(status.code(), ErrorCode::OutcomeUnknown);
    let fence = client
        .fence_request(&settings_of(object), identity(8), now_ms(), now_ms())
        .await
        .expect_err("not an answer here");
    assert_eq!(fence.code(), ErrorCode::OutcomeUnknown);
}

/// A page of a shared comparison carrying `changed` objects, and naming `listed` as every object
/// the collection holds.
fn object_page(
    changed: &[u64],
    listed: &[u64],
    sealed_object: &serde_json::Value,
) -> serde_json::Value {
    let head = KeyHead {
        epoch: 1,
        revision: 2,
        recovery: None,
    };
    let object = |index: u64| {
        Uuid::from_bytes([
            u8::try_from(index / 256).expect("a byte"),
            u8::try_from(index % 256).expect("a byte"),
            0,
            0,
            0,
            0,
            0x40,
            0,
            0x80,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
        ])
    };
    let revision_of = |index: u64| {
        SyncRevision::new(Uuid::from_bytes([
            u8::try_from(index % 256).expect("a byte"),
            0x7a,
            0,
            0,
            0,
            0,
            0x40,
            0,
            0x80,
            0,
            0,
            0,
            0,
            0,
            0,
            2,
        ]))
    };
    let mut page = compared_shared(
        &listed
            .iter()
            .map(|index| (object(*index), revision_of(*index), 1, 1))
            .collect::<Vec<_>>(),
        &[],
        false,
        0,
        head,
    );
    page["changed"] = serde_json::Value::Array(
        changed
            .iter()
            .map(|index| {
                serde_json::json!({
                    "kind": "settings",
                    "object_id": object(*index).to_string(),
                    "revision": revision_of(*index).to_string(),
                    "write_sequence": "1",
                    "key_epoch": "1",
                    "object": sealed_object,
                    "updated_at": "2026-09-24T10:00:00.000Z",
                })
            })
            .collect(),
    );
    page
}

/// A shared collection holds up to 256 objects and the service answers 64 at a time, so a
/// comparison follows the pages, naming what each brought as held, until nothing it lists is
/// missing; what the reader already holds is named from the first page on and never sent.
#[tokio::test]
async fn a_shared_comparison_follows_every_page_of_objects_the_reader_lacks() {
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let sealed_object = serde_json::to_value(sealed(b"theme=dark")).expect("an object");
    let listed: Vec<u64> = (0..65).collect();

    recorder.answering(vec![
        object_page(&listed[..64], &listed, &sealed_object),
        object_page(&listed[64..], &listed, &sealed_object),
    ]);
    let compared = client
        .compare_shared(&collection, &[], false, None)
        .await
        .expect("an answer")
        .expect("a member");
    assert_eq!(
        compared.objects.len(),
        65,
        "every object, across both pages"
    );
    assert_eq!(recorder.requests(), 2);
    let second = recorder.last_body();
    assert_eq!(
        second["compare"]["known"].as_array().expect("known").len(),
        64,
        "the second page names the objects the first brought"
    );
    assert_eq!(second["compare"]["with_conflicts"], false);

    // What the reader holds is named from the first request on, and the answer leaves it out.
    let held: Vec<KnownRevision> = compared.objects[..10]
        .iter()
        .map(|object| KnownRevision {
            object_id: object.object_id,
            revision: object.position.revision.0.expect("a revision"),
        })
        .collect();
    recorder.answering(vec![object_page(&listed[10..], &listed, &sealed_object)]);
    let compared = client
        .compare_shared(&collection, &held, false, None)
        .await
        .expect("an answer")
        .expect("a member");
    assert_eq!(compared.objects.len(), 55);
    assert_eq!(recorder.requests(), 3, "one page was enough");
    assert_eq!(
        recorder.last_body()["compare"]["known"],
        serde_json::to_value(&held).expect("known")
    );

    // A reader may name one object many times, as the service reads a list; each object is named
    // once, so the requests stay within what the service reads.
    let one = vec![held[0]; MAX_KNOWN_REVISIONS];
    let wider: Vec<u64> = (0..66).collect();
    recorder.answering(vec![
        object_page(&wider[1..65], &wider, &sealed_object),
        object_page(&wider[65..], &wider, &sealed_object),
    ]);
    let before = recorder.requests();
    let compared = client
        .compare_shared(&collection, &one, false, None)
        .await
        .expect("an answer")
        .expect("a member");
    assert_eq!(compared.objects.len(), 65);
    assert_eq!(recorder.requests() - before, 2);
    assert_eq!(
        recorder.last_body()["compare"]["known"]
            .as_array()
            .expect("known")
            .len(),
        65,
        "the object held and the sixty-four the first page brought, each once"
    );

    // A page that brings nothing while an object is missing, and a collection that keeps moving,
    // are not followed; nor is a reader naming more than the service reads.
    recorder.answering(vec![object_page(&[], &listed, &sealed_object)]);
    let refused = client
        .compare_shared(&collection, &[], false, None)
        .await
        .expect_err("not followed");
    assert_eq!(code_of(&refused), ErrorCode::OutcomeUnknown);
    recorder.answering(vec![object_page(&[0], &[0, 1], &sealed_object)]);
    let before = recorder.requests();
    let refused = client
        .compare_shared(&collection, &[], false, None)
        .await
        .expect_err("not followed");
    assert_eq!(code_of(&refused), ErrorCode::OutcomeUnknown);
    assert_eq!(recorder.requests() - before, MAX_COMPARISON_PAGES);
    let too_many = vec![held[0]; MAX_KNOWN_REVISIONS + 1];
    let before = recorder.requests();
    assert!(
        client
            .compare_shared(&collection, &too_many, false, None)
            .await
            .is_err()
    );
    assert_eq!(recorder.requests(), before, "nothing was sent");
}

/// A page of a shared comparison built from explicit objects: `changed` brought with content,
/// `removed` with the place their removal took, and `listed` as every object the collection holds.
fn fold_page(
    changed: &[(Uuid, SyncRevision)],
    removed: &[(Uuid, u64)],
    listed: &[(Uuid, SyncRevision)],
) -> serde_json::Value {
    let sealed_object = serde_json::to_value(sealed(b"theme=dark")).expect("an object");
    let mut page = compared_shared(
        &listed
            .iter()
            .map(|(object, revision)| (*object, *revision, 1, 1))
            .collect::<Vec<_>>(),
        &[],
        false,
        0,
        KeyHead {
            epoch: 1,
            revision: 2,
            recovery: None,
        },
    );
    page["changed"] = changed
        .iter()
        .map(|(object, revision)| {
            serde_json::json!({
                "kind": "settings",
                "object_id": object.to_string(),
                "revision": revision.to_string(),
                "write_sequence": "1",
                "key_epoch": "1",
                "object": sealed_object,
                "updated_at": "2026-09-24T10:00:00.000Z",
            })
        })
        .collect();
    page["removed"] = removed
        .iter()
        .map(|(object, write_sequence)| {
            serde_json::json!({
                "object_id": object.to_string(),
                "write_sequence": write_sequence.to_string(),
            })
        })
        .collect();
    page
}

/// A shared comparison over several pages is one answer: an object the reader held that the
/// collection removed comes back as removed, with the place its removal took; an object removed
/// between two pages is removed in the answer; one written again after that is the object again;
/// and an object the pages brought that the collection stops listing without any page saying it
/// went is not an answer this client follows.
#[tokio::test]
async fn a_shared_comparison_folds_removals_and_later_words_across_pages() {
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let (a, b, c, x, y) = (
        identity(0x91),
        identity(0x92),
        identity(0x93),
        identity(0x94),
        identity(0x95),
    );
    let (ra, rb, rc, rx, ry, ra2) = (
        revision(0xa1),
        revision(0xa2),
        revision(0xa3),
        revision(0xa4),
        revision(0xa5),
        revision(0xa6),
    );

    // Held and since removed, and one the collection never held.
    recorder.answering(vec![fold_page(&[(b, rb)], &[(a, 5), (c, 0)], &[(b, rb)])]);
    let compared = client
        .compare_shared(
            &collection,
            &[
                KnownRevision {
                    object_id: SyncObjectId::new(a),
                    revision: ra,
                },
                KnownRevision {
                    object_id: SyncObjectId::new(c),
                    revision: rc,
                },
            ],
            false,
            None,
        )
        .await
        .expect("an answer")
        .expect("a member");
    assert_eq!(
        compared.removed,
        vec![
            SyncRemoved {
                object_id: SyncObjectId::new(a),
                position: Some(SyncPosition::removed_at(5, None)),
            },
            SyncRemoved {
                object_id: SyncObjectId::new(c),
                position: None,
            },
        ]
    );
    assert_eq!(compared.objects.len(), 1);

    // Removed between two pages.
    recorder.answering(vec![
        fold_page(&[(a, ra), (b, rb)], &[], &[(a, ra), (b, rb), (c, rc)]),
        fold_page(&[(c, rc)], &[(a, 7)], &[(b, rb), (c, rc)]),
    ]);
    let compared = client
        .compare_shared(&collection, &[], false, None)
        .await
        .expect("an answer")
        .expect("a member");
    assert_eq!(
        compared
            .objects
            .iter()
            .map(|object| object.object_id)
            .collect::<Vec<_>>(),
        vec![SyncObjectId::new(b), SyncObjectId::new(c)]
    );
    assert_eq!(
        compared.removed,
        vec![SyncRemoved {
            object_id: SyncObjectId::new(a),
            position: Some(SyncPosition::removed_at(7, None)),
        }]
    );

    // Removed, then written again: the later word is the object.
    recorder.answering(vec![
        fold_page(&[(a, ra)], &[], &[(a, ra), (x, rx), (y, ry)]),
        fold_page(&[(x, rx)], &[(a, 3)], &[(x, rx), (y, ry)]),
        fold_page(&[(a, ra2), (y, ry)], &[], &[(a, ra2), (x, rx), (y, ry)]),
    ]);
    let compared = client
        .compare_shared(&collection, &[], false, None)
        .await
        .expect("an answer")
        .expect("a member");
    assert!(compared.removed.is_empty());
    let brought: Vec<_> = compared
        .objects
        .iter()
        .map(|object| (object.object_id, object.position.revision.0))
        .collect();
    assert!(brought.contains(&(SyncObjectId::new(a), Some(ra2))));
    assert_eq!(brought.len(), 3);

    // Brought, then no longer listed, with no page saying it went.
    recorder.answering(vec![
        fold_page(&[(a, ra)], &[], &[(a, ra), (b, rb)]),
        fold_page(&[(b, rb)], &[], &[(b, rb)]),
    ]);
    let refused = client
        .compare_shared(&collection, &[], false, None)
        .await
        .expect_err("not followed");
    assert_eq!(code_of(&refused), ErrorCode::OutcomeUnknown);
}

/// Copies outlive the objects they were refused against, so an inventory has no bound on how many
/// it may meet. It reads under the caller's budget of pages, says where it stopped, and continues
/// from there when asked, until it reaches the end; until then it cannot show an epoch unused.
#[tokio::test]
async fn an_inventory_reads_under_a_budget_and_resumes_past_two_thousand_copies() {
    let (client, recorder) = sync_client();
    let collection = shared_collection(installation(0x41), 0x42);
    let head = KeyHead {
        epoch: 2,
        revision: 3,
        recovery: None,
    };
    let live = identity(0x61);
    let pages: u64 = 34;
    let per_page: u64 = 64;
    let copy = |sequence: u64| {
        // Each copy is of an object identity the collection no longer holds.
        let historical = Uuid::from_bytes([
            u8::try_from(sequence / 256).expect("a byte"),
            u8::try_from(sequence % 256).expect("a byte"),
            0x11,
            0x11,
            0,
            0,
            0x40,
            0,
            0x80,
            0,
            0,
            0,
            0,
            0,
            0,
            3,
        ]);
        (sequence, historical, historical, 1)
    };
    recorder.answering(
        (0..pages)
            .map(|page| {
                let copies: Vec<_> = (page * per_page + 1..=(page + 1) * per_page)
                    .map(copy)
                    .collect();
                compared_shared(
                    &[(live, revision(0x71), 4, 2)],
                    &copies,
                    page + 1 < pages,
                    (page + 1) * per_page,
                    head,
                )
            })
            .collect(),
    );

    let mut inventory = client
        .inventory(&collection, None, budget(10))
        .await
        .expect("an answer")
        .expect("a member");
    assert!(!inventory.is_complete());
    assert_eq!(inventory.copies.len(), 640);
    assert_eq!(inventory.resume_after, Some(640));
    assert!(
        inventory.may_hold_epoch(0),
        "a read that stopped short cannot show an epoch unused"
    );
    let mut calls = 1;
    while !inventory.is_complete() {
        inventory = client
            .inventory(&collection, Some(inventory), budget(10))
            .await
            .expect("an answer")
            .expect("a member");
        calls += 1;
    }
    assert_eq!(calls, 4);
    assert_eq!(
        inventory.copies.len(),
        usize::try_from(pages * per_page).expect("a count")
    );
    assert!(inventory.copies.len() > 2048);
    assert_eq!(
        recorder.requests(),
        usize::try_from(pages).expect("a count")
    );
    assert_eq!(inventory.epochs(), BTreeSet::from([1, 2]));
    assert!(!inventory.may_hold_epoch(0));
    let last = recorder.last_body();
    assert_eq!(
        last["compare"]["conflicts_after_sequence"],
        (33 * per_page).to_string()
    );
    assert_eq!(
        last["compare"]["known"],
        serde_json::json!([{ "object_id": live.to_string(), "revision": revision(0x71).to_string() }]),
        "the objects already read are named, so their content is not sent again"
    );

    // An inventory that reached the end has nothing to continue.
    let before = recorder.requests();
    let done = client
        .inventory(&collection, Some(inventory.clone()), budget(10))
        .await
        .expect("an answer")
        .expect("a member");
    assert_eq!(done, inventory);
    assert_eq!(recorder.requests(), before);
}

/* -------------------------------------------------------------------------- */
/* The contract                                                                */
/* -------------------------------------------------------------------------- */

/// What one receipt recorded.
#[derive(Clone, Debug)]
struct Receipt {
    /// What the write asked, less its identity and its home: an exact retry asks the same.
    digest: serde_json::Value,
    /// What the service recorded it did.
    outcome: &'static str,
    /// What an exact retry of a write is answered again.
    answer: Option<serde_json::Value>,
    /// The epoch and revision the answer named.
    head: Option<KeyHead>,
    current_revision: Option<String>,
    current_write_sequence: Option<String>,
    never_ran: bool,
    recorded_at_ms: u64,
}

/// One object a shared collection holds.
#[derive(Clone, Debug)]
struct Held {
    revision: String,
    write_sequence: u64,
}

/// One shared collection, as its own object keeps it.
#[derive(Debug, Default)]
struct SharedState {
    /// Each record's epoch and the installations it lists, from revision one.
    records: Vec<(u64, BTreeSet<InstallationId>)>,
    objects: BTreeMap<String, Held>,
    receipts: BTreeMap<(InstallationId, String), Receipt>,
    /// The highest instant any receipt it removed was recorded at.
    swept_through_ms: u64,
    /// Revisions it gives writes, counted so each is new.
    revisions: u8,
}

/// Where a caller stands with one collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    Member,
    Former,
    Stranger,
}

impl SharedState {
    fn head(&self) -> KeyHead {
        let (epoch, _) = self.records.last().expect("a claimed collection");
        KeyHead {
            epoch: *epoch,
            revision: u64::try_from(self.records.len()).expect("a revision"),
            recovery: None,
        }
    }

    fn standing(&self, caller: InstallationId) -> Standing {
        match self.records.last() {
            Some((_, newest)) if newest.contains(&caller) => Standing::Member,
            _ if self
                .records
                .iter()
                .any(|(_, listed)| listed.contains(&caller)) =>
            {
                Standing::Former
            }
            _ => Standing::Stranger,
        }
    }

    /// The answer a status query and a fence give about one receipt.
    fn answer(request: &str, receipt: &Receipt) -> serde_json::Value {
        let state = match receipt.outcome {
            "written" | "removed" | "rekeyed" => "applied",
            "conflict" | "rekey_refused" => "refused",
            "retired" => "retired",
            _ => "fenced",
        };
        let mut answer = serde_json::json!({
            "request_id": request,
            "state": state,
            "never_ran": receipt.never_ran,
            "outcome": receipt.outcome,
            "record": null,
            "current_revision": receipt.current_revision,
            "current_write_sequence": receipt.current_write_sequence,
            "conflict_id": null,
            "recovery_id": null,
            "recorded_at": "2026-09-24T10:00:00.000Z",
        });
        if let Some(head) = receipt.head {
            answer["key_epoch"] = serde_json::Value::String(head.epoch.to_string());
            answer["key_revision"] = serde_json::Value::String(head.revision.to_string());
        }
        answer
    }
}

/// The service's contract for writes, status queries and fences in shared collections.
#[derive(Debug, Default)]
struct Contract {
    collections: Mutex<BTreeMap<(InstallationId, SyncCollectionId), SharedState>>,
    /// Each request's body, as the service read it.
    sent: Mutex<Vec<serde_json::Value>>,
}

impl Contract {
    /// A collection its home claimed, listing `members` at the first epoch.
    fn claim(&self, collection: &CollectionRef, members: &[InstallationId]) {
        self.collections.lock().expect("the collections").insert(
            (collection.home, collection.collection_id),
            SharedState {
                records: vec![(0, members.iter().copied().collect())],
                ..SharedState::default()
            },
        );
    }

    /// A member's record moves the collection to a fresh key, listing `members`.
    fn rotate(&self, collection: &CollectionRef, members: &[InstallationId]) {
        let mut collections = self.collections.lock().expect("the collections");
        let state = collections
            .get_mut(&(collection.home, collection.collection_id))
            .expect("the collection");
        let epoch = state.head().epoch + 1;
        state
            .records
            .push((epoch, members.iter().copied().collect()));
    }

    /// The collection's retention passes one receipt, which the sweep removes and accounts for.
    fn expire(&self, collection: &CollectionRef, caller: InstallationId, request: Uuid) {
        let mut collections = self.collections.lock().expect("the collections");
        let state = collections
            .get_mut(&(collection.home, collection.collection_id))
            .expect("the collection");
        let receipt = state
            .receipts
            .remove(&(caller, request.to_string()))
            .expect("a receipt");
        state.swept_through_ms = state.swept_through_ms.max(receipt.recorded_at_ms);
    }

    fn bodies(&self) -> Vec<serde_json::Value> {
        self.sent.lock().expect("what was sent").clone()
    }

    /// Answers one request as the collection object does.
    fn take(
        &self,
        caller: InstallationId,
        at_ms: u64,
        body: &serde_json::Value,
    ) -> ServiceHttpAnswer {
        let (member, asked) = body
            .as_object()
            .and_then(|members| members.iter().next())
            .expect("one member");
        let home = asked["home"].as_str().map_or(caller, |home| {
            InstallationId::new(home.parse().expect("a home"))
        });
        let collection_id = SyncCollectionId::new(
            asked["collection_id"]
                .as_str()
                .expect("a collection")
                .parse()
                .expect("an identity"),
        );
        let request = asked["request_id"]
            .as_str()
            .expect("an identity")
            .to_owned();
        let mut collections = self.collections.lock().expect("the collections");
        let Some(state) = collections.get_mut(&(home, collection_id)) else {
            return absent();
        };
        let standing = state.standing(caller);
        if standing == Standing::Stranger {
            return absent();
        }
        let held = state.receipts.get(&(caller, request.clone())).cloned();
        match member.as_str() {
            "exchange" => Self::exchange(state, caller, standing, at_ms, asked, &request, held),
            "status" => held.map_or_else(
                || {
                    answered(status(
                        request.parse().expect("an identity"),
                        "unknown",
                        false,
                    ))
                },
                |receipt| answered(SharedState::answer(&request, &receipt)),
            ),
            "fence" => {
                if let Some(receipt) = held {
                    return answered(SharedState::answer(&request, &receipt));
                }
                let first: u64 = asked["first_signed_at_ms"]
                    .as_str()
                    .expect("an instant")
                    .parse()
                    .expect("a number");
                let never_ran =
                    state.swept_through_ms < first.saturating_sub(SERVICE_REQUEST_FRESHNESS_MS);
                let receipt = Receipt {
                    digest: serde_json::Value::Null,
                    outcome: "fenced",
                    answer: None,
                    head: None,
                    current_revision: None,
                    current_write_sequence: None,
                    never_ran,
                    recorded_at_ms: at_ms,
                };
                state
                    .receipts
                    .insert((caller, request.clone()), receipt.clone());
                answered(SharedState::answer(&request, &receipt))
            }
            other => panic!("this contract answers writes, status queries and fences, not {other}"),
        }
    }

    /// One write, in the service's order: a receipt for the identity, a fence, who is asking, the
    /// epoch, and then the comparison.
    fn exchange(
        state: &mut SharedState,
        caller: InstallationId,
        standing: Standing,
        at_ms: u64,
        asked: &serde_json::Value,
        request: &str,
        held: Option<Receipt>,
    ) -> ServiceHttpAnswer {
        let digest = serde_json::json!({
            "collection_id": asked["collection_id"],
            "kind": asked["kind"],
            "object_id": asked["object_id"],
            "expected_revision": asked["expected_revision"],
            "object": asked["object"],
            "key_epoch": asked["key_epoch"],
        });
        if let Some(receipt) = held {
            if receipt.outcome == "fenced" {
                return refusal(409, "REQUEST_FENCED", "fenced");
            }
            if receipt.digest != digest {
                return refusal(409, "ID_CONFLICT", "another request wore that identity");
            }
            if receipt.outcome == "retired" {
                return retired(receipt.head.expect("the head it named"));
            }
            return answered(receipt.answer.expect("the answer it was given"));
        }
        if standing != Standing::Member {
            return absent();
        }
        let head = state.head();
        let epoch: u64 = asked["key_epoch"]
            .as_str()
            .expect("an epoch in a claimed collection")
            .parse()
            .expect("a number");
        if epoch > head.epoch {
            return refusal(
                400,
                "INVALID_ARGUMENT",
                "an epoch ahead of the collection's",
            );
        }
        if epoch < head.epoch {
            state.receipts.insert(
                (caller, request.to_owned()),
                Receipt {
                    digest,
                    outcome: "retired",
                    answer: None,
                    head: Some(head),
                    current_revision: None,
                    current_write_sequence: None,
                    never_ran: false,
                    recorded_at_ms: at_ms,
                },
            );
            return retired(head);
        }
        let object = asked["object_id"].as_str().expect("an object").to_owned();
        let current = state.objects.get(&object).cloned();
        let expected = asked["expected_revision"].as_str().map(str::to_owned);
        if current.as_ref().map(|held| held.revision.clone()) != expected {
            let (revision, write_sequence) =
                current.map_or((None, 0), |held| (Some(held.revision), held.write_sequence));
            let answer = serde_json::json!({
                "state": "conflict",
                "record": null,
                "current_revision": revision,
                "current_write_sequence": write_sequence.to_string(),
                "conflict": null,
                "key_epoch": head.epoch.to_string(),
                "key_revision": head.revision.to_string(),
                "recovery_id": null,
                "stored": usage(),
            });
            state.receipts.insert(
                (caller, request.to_owned()),
                Receipt {
                    digest,
                    outcome: "conflict",
                    answer: Some(answer.clone()),
                    head: Some(head),
                    current_revision: revision,
                    current_write_sequence: Some(write_sequence.to_string()),
                    never_ran: false,
                    recorded_at_ms: at_ms,
                },
            );
            return answered(answer);
        }
        state.revisions += 1;
        let written = Held {
            revision: revision(0xa0 + state.revisions).to_string(),
            write_sequence: current.map_or(1, |held| held.write_sequence + 1),
        };
        state.objects.insert(object.clone(), written.clone());
        let answer = serde_json::json!({
            "state": "written",
            "record": {
                "kind": asked["kind"],
                "object_id": object,
                "revision": written.revision,
                "write_sequence": written.write_sequence.to_string(),
                "key_epoch": epoch.to_string(),
                "updated_at": "2026-09-24T10:00:00.000Z",
                "bytes": "1320",
            },
            "current_revision": written.revision,
            "current_write_sequence": written.write_sequence.to_string(),
            "conflict": null,
            "key_epoch": head.epoch.to_string(),
            "key_revision": head.revision.to_string(),
            "recovery_id": null,
            "stored": usage(),
        });
        state.receipts.insert(
            (caller, request.to_owned()),
            Receipt {
                digest,
                outcome: "written",
                answer: Some(answer.clone()),
                head: Some(head),
                current_revision: Some(written.revision.clone()),
                current_write_sequence: Some(written.write_sequence.to_string()),
                never_ran: false,
                recorded_at_ms: at_ms,
            },
        );
        answered(answer)
    }
}

impl ServiceHttp for Contract {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        let request: serde_json::Value = serde_json::from_slice(body).expect("a signed request");
        let signature: ServiceRequestSignature =
            serde_json::from_value(request["signature"].clone()).expect("a credential");
        self.sent
            .lock()
            .expect("what was sent")
            .push(request["body"].clone());
        let answer = self.take(
            installation_id(&signature.public_key),
            signature.payload.signed_at_ms.get(),
            &request["body"],
        );
        Box::pin(async move { Ok(answer) })
    }
}

/// What the service answers a caller its collection does not admit, and a collection nobody made.
fn absent() -> ServiceHttpAnswer {
    refusal(
        404,
        "COLLECTION_ABSENT",
        "That collection does not exist, or this installation is not one of its members.",
    )
}

/// The refusal of a write under a retired epoch, naming the collection's head.
fn retired(head: KeyHead) -> ServiceHttpAnswer {
    refusal_with(
        409,
        "KEY_EPOCH_RETIRED",
        serde_json::json!({
            "key_epoch": head.epoch.to_string(),
            "key_revision": head.revision.to_string(),
            "recovery_id": head.recovery.map(|recovery| recovery.to_string()),
        }),
    )
}

/// One device of a shared collection, with its own key and its own client to the contract.
struct Member {
    installation: InstallationId,
    client: ManagedSyncService,
}

impl Member {
    fn of(contract: &Arc<Contract>) -> Self {
        let pair = AuthorisationKeyPair::generate().expect("a key pair");
        Self {
            installation: installation_id(pair.public()),
            client: ManagedSyncService::new(
                GatewayOrigin::new("https://reach.kala.to").expect("an origin"),
                Arc::clone(contract) as Arc<_>,
                Arc::new(Device { pair }) as Arc<_>,
            ),
        }
    }

    /// One attempt at a write of `object` under `epoch`, signed now.
    async fn write(
        &self,
        collection: &CollectionRef,
        object: Uuid,
        epoch: u64,
        request: Uuid,
        ciphertext: &[u8],
    ) -> Keyed<SyncExchanged> {
        self.client
            .exchange_shared(
                collection,
                &settings_of(object),
                epoch,
                request,
                now_ms(),
                None,
                ciphertext,
            )
            .await
            .expect("an answer")
    }
}

/* -------------------------------------------------------------------------- */
/* A retired epoch                                                             */
/* -------------------------------------------------------------------------- */

/// A write that applied under an epoch the collection has since retired is answered from its
/// receipt when it is retried: the service reads the receipt before the epoch, and this client
/// retries with the document the first attempt sent, epoch included. A new identity under that
/// epoch meets the retired refusal, and the same identity relabelled with the current epoch is
/// other content under a used identity.
#[tokio::test]
async fn a_retry_of_an_applied_write_gets_its_receipt_not_a_retired_refusal() {
    let contract = Arc::new(Contract::default());
    let writer = Member::of(&contract);
    let other = Member::of(&contract);
    let collection = CollectionRef {
        home: writer.installation,
        collection_id: SyncCollectionId::new(identity(0x42)),
    };
    contract.claim(&collection, &[writer.installation, other.installation]);
    let object = identity(0x61);
    let request = identity(0x62);
    let ciphertext = published(&sealed(b"theme=dark"));

    let first = writer
        .write(&collection, object, 0, request, &ciphertext)
        .await;
    let Keyed::Answered {
        answer: SyncExchanged::Applied { position },
        head: Some(head),
    } = first
    else {
        panic!("the first attempt applied: {first:?}");
    };
    assert_eq!(
        head,
        KeyHead {
            epoch: 0,
            revision: 1,
            recovery: None
        }
    );

    // Another member removes a device, and the collection moves to a fresh key.
    contract.rotate(&collection, &[writer.installation, other.installation]);

    // The answer to the first attempt was lost; the retry names the epoch it named.
    let retried = writer
        .write(&collection, object, 0, request, &ciphertext)
        .await;
    assert_eq!(
        retried,
        Keyed::Answered {
            answer: SyncExchanged::Applied { position },
            head: Some(head),
        },
        "the receipt's answer, as the first attempt was given it"
    );
    let bodies = contract.bodies();
    assert_eq!(
        bodies[0], bodies[1],
        "the retry is the first attempt's document"
    );

    // A new write under the retired epoch meets the refusal, which names the collection's head.
    assert_eq!(
        writer
            .write(&collection, object, 0, identity(0x63), &ciphertext)
            .await,
        Keyed::Retired {
            head: KeyHead {
                epoch: 1,
                revision: 2,
                recovery: None
            }
        }
    );

    // The epoch is part of what a retry asks: the same identity under the current epoch is other
    // content, and it is refused as such rather than applied again.
    let relabelled = writer
        .client
        .exchange_shared(
            &collection,
            &settings_of(object),
            1,
            request,
            now_ms(),
            None,
            &ciphertext,
        )
        .await
        .expect_err("another request under a used identity");
    assert_eq!(relabelled.code(), ErrorCode::IdConflict);
}

/// The exchange, the status query and the fence answer a write refused for a retired epoch the
/// same way: retired, naming the head the refusal named. So does a member removed after it sent
/// the write, whose new requests meet a collection that no longer lists it. Once the receipt has
/// passed the service's retention, the status query no longer knows the request, and the fence
/// cannot say that nothing ran: the sweep reached past the instant the attempt was signed at.
#[tokio::test]
async fn exchange_status_and_fence_agree_on_a_retired_request() {
    let contract = Arc::new(Contract::default());
    let home = Member::of(&contract);
    let removed = Member::of(&contract);
    let collection = CollectionRef {
        home: home.installation,
        collection_id: SyncCollectionId::new(identity(0x42)),
    };
    contract.claim(&collection, &[home.installation, removed.installation]);
    contract.rotate(&collection, &[home.installation, removed.installation]);
    let retired_at = KeyHead {
        epoch: 1,
        revision: 2,
        recovery: None,
    };
    let ciphertext = published(&sealed(b"theme=dark"));

    // Both members write under the epoch the collection has retired.
    let (home_request, removed_request) = (identity(0x71), identity(0x72));
    let home_signed = now_ms();
    for (member, request) in [(&home, home_request), (&removed, removed_request)] {
        assert_eq!(
            member
                .write(&collection, identity(0x61), 0, request, &ciphertext)
                .await,
            Keyed::Retired { head: retired_at }
        );
    }

    // One of them is removed after it dispatched.
    contract.rotate(&collection, &[home.installation]);

    for (member, request) in [(&home, home_request), (&removed, removed_request)] {
        assert_eq!(
            member
                .client
                .status_shared(&collection, request)
                .await
                .expect("an answer"),
            Keyed::Retired { head: retired_at },
            "the status query names the head the refusal named"
        );
        assert_eq!(
            member
                .client
                .fence_shared(&collection, request, home_signed, now_ms())
                .await
                .expect("an answer"),
            Keyed::Retired { head: retired_at },
            "and so does the fence, which leaves the receipt as it was"
        );
        // An exact retry is answered from the receipt too, whoever the collection lists now.
        assert_eq!(
            member
                .write(&collection, identity(0x61), 0, request, &ciphertext)
                .await,
            Keyed::Retired { head: retired_at }
        );
    }

    // The removed member's new write meets a collection that does not list it.
    assert_eq!(
        removed
            .write(&collection, identity(0x61), 2, identity(0x73), &ciphertext)
            .await,
        Keyed::Absent
    );
    // A device no record of the collection has listed learns nothing about any request in it.
    let stranger = Member::of(&contract);
    assert_eq!(
        stranger
            .client
            .status_shared(&collection, home_request)
            .await
            .expect("an answer"),
        Keyed::Absent
    );

    // A fence of an identity nothing was recorded for, with nothing swept, says it never ran.
    assert_eq!(
        home.client
            .fence_shared(&collection, identity(0x74), now_ms(), now_ms())
            .await
            .expect("an answer"),
        Keyed::Answered {
            answer: SyncRequestFence::Fenced {
                never_ran: true,
                recovery: None,
            },
            head: None,
        }
    );

    // The retention passes the retired receipt. The status query no longer knows the request, and
    // the fence cannot say it never ran, because the sweep reached the instant it was recorded at.
    contract.expire(&collection, home.installation, home_request);
    assert_eq!(
        home.client
            .status_shared(&collection, home_request)
            .await
            .expect("an answer"),
        Keyed::Answered {
            answer: SyncRequestStatus::Unknown { recovery: None },
            head: None,
        }
    );
    let fenced = Keyed::Answered {
        answer: SyncRequestFence::Fenced {
            never_ran: false,
            recovery: None,
        },
        head: None,
    };
    assert_eq!(
        home.client
            .fence_shared(&collection, home_request, home_signed, now_ms())
            .await
            .expect("an answer"),
        fenced
    );
    assert_eq!(
        home.client
            .status_shared(&collection, home_request)
            .await
            .expect("an answer"),
        Keyed::Answered {
            answer: SyncRequestStatus::Fenced {
                never_ran: false,
                recovery: None,
            },
            head: None,
        },
        "the status query repeats what the fence recorded"
    );
}
