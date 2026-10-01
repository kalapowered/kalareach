//! What a host's admission is asked inside the service's own lock.
//!
//! The service takes its own lock and opens its own transaction after whatever the host checked
//! before it was called. Each mutation that begins an effect asks the host again, under that lock,
//! before its first write, and runs the commit that makes the effect durable through the host. A
//! host that answers no at either place leaves the store as it was and nothing visible in the
//! staging area, under its own refusal. (A chunk's bytes are written into the incomplete file
//! before its row is committed, so a host that answers no at the commit leaves bytes there that no
//! row names.)
//!
//! The hook here is the host's side: it can be made to refuse when asked, or to stand when asked
//! and refuse when the commit is run, which is a withdrawal landing between the two.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{DeviceId, DraftRevision, SessionId, TransferId};
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::transfer::{
    AgentDraftAddAttachmentParams, AttachmentContribution, DraftCreateParams, DraftUpdateParams,
    InsertionMethod, UploadBeginParams, UploadCancelParams, UploadChunkParams, UploadState,
    UploadStatusParams,
};
use kr_transfer::TransferError;
use kr_transfer::service::{Action, Admission, AdmissionHook};
use support::{Harness, chunk_of, digest, pattern};

/// Where the host's answer turns to no.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refuses {
    /// It stands for everything: the control.
    Never,
    /// It refuses when asked, before the first write.
    WhenAsked,
    /// It stands when asked and refuses when the commit is run.
    AtTheCommit,
}

/// The host's side of the admission, counting what it was asked.
#[derive(Debug)]
struct Host {
    refuses: Refuses,
    asked: AtomicUsize,
    committed: AtomicUsize,
    refused_commit: AtomicBool,
}

impl Host {
    fn new(refuses: Refuses) -> Arc<Self> {
        Arc::new(Self {
            refuses,
            asked: AtomicUsize::new(0),
            committed: AtomicUsize::new(0),
            refused_commit: AtomicBool::new(false),
        })
    }

    fn refusal() -> ProtocolError {
        ProtocolError::new(
            ErrorCode::PermissionDenied,
            "the authority this action was admitted under has been withdrawn",
        )
    }
}

impl AdmissionHook for Host {
    fn ask(&self) -> Result<(), ProtocolError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        if self.refuses == Refuses::WhenAsked {
            return Err(Self::refusal());
        }
        Ok(())
    }

    fn run(&self, commit: &mut dyn FnMut()) -> Result<(), ProtocolError> {
        if self.refuses == Refuses::AtTheCommit {
            self.refused_commit.store(true, Ordering::SeqCst);
            return Err(Self::refusal());
        }
        commit();
        self.committed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// An action for `method` whose payload is `payload`, under `host`.
fn action(harness: &Harness, method: &str, payload: &[u8], host: &Arc<Host>) -> Action {
    Action {
        actor_id: harness.actor.clone(),
        action_id: kr_ipc::new_uuid(),
        method: method.to_owned(),
        payload_digest: digest(payload),
        admission: Admission::new(Arc::clone(host) as Arc<dyn AdmissionHook>),
    }
}

/// The two ways the host's answer turns to no.
const REFUSALS: [Refuses; 2] = [Refuses::WhenAsked, Refuses::AtTheCommit];

/// Asserts `outcome` is the host's own refusal, reported under the host's own code and kept as
/// nothing.
fn assert_not_admitted<T: std::fmt::Debug>(
    outcome: Result<T, TransferError>,
    refuses: Refuses,
    host: &Host,
) {
    let error = outcome.expect_err("a refused admission performs nothing");
    assert!(
        matches!(error, TransferError::NotAdmitted(_)),
        "{refuses:?}: {error:?}"
    );
    assert_eq!(error.code(), ErrorCode::PermissionDenied, "{refuses:?}");
    assert!(
        error.to_string().contains("withdrawn"),
        "{refuses:?}: the host's own words: {error}"
    );
    assert_eq!(host.committed.load(Ordering::SeqCst), 0, "{refuses:?}");
}

fn begin_params(harness: &Harness, bytes: &[u8]) -> UploadBeginParams {
    UploadBeginParams {
        environment_id: harness.environment_id(),
        session_id: Nullable::null(),
        device_id: Nullable::null(),
        declared_byte_len: U64::new(bytes.len() as u64),
        declared_digest: digest(bytes),
        declared_media_type: "application/octet-stream".to_owned(),
        original_file_name: "notes.bin".to_owned(),
    }
}

/// The staging files an environment holds, complete and incomplete.
fn staged_files(harness: &Harness) -> usize {
    [
        harness.service.staging().incomplete().display_path(),
        harness.service.staging().complete().display_path(),
    ]
    .iter()
    .map(|directory| {
        std::fs::read_dir(directory)
            .map(|entries| entries.count())
            .unwrap_or(0)
    })
    .sum()
}

/// KR-REQ-09.09: `upload.begin` reserves nothing and creates no staging file when the host's
/// answer is no inside the service's lock, whether it is asked before the first write or when the
/// commit runs. The control: it stands, and the reservation and the file are made.
#[test]
fn an_upload_begin_the_host_refuses_inside_the_lock_writes_nothing() {
    for refuses in REFUSALS {
        let harness = Harness::create();
        let bytes = pattern(4096);
        let host = Host::new(refuses);
        let outcome = harness.service.upload_begin(
            &harness.actor,
            &begin_params(&harness, &bytes),
            Some(&action(&harness, "upload.begin", &bytes, &host)),
        );
        assert_not_admitted(outcome, refuses, &host);
        assert_eq!(
            harness.service.staged_byte_len().expect("the total"),
            0,
            "{refuses:?}: nothing is reserved"
        );
        assert_eq!(
            staged_files(&harness),
            0,
            "{refuses:?}: the staging file the first write made is removed with the refusal"
        );
    }

    let harness = Harness::create();
    let bytes = pattern(4096);
    let host = Host::new(Refuses::Never);
    harness
        .service
        .upload_begin(
            &harness.actor,
            &begin_params(&harness, &bytes),
            Some(&action(&harness, "upload.begin", &bytes, &host)),
        )
        .expect("under an admission that stands the upload is reserved");
    assert_eq!(harness.service.staged_byte_len().expect("the total"), 4096);
    assert_eq!(staged_files(&harness), 1);
    assert_eq!(host.committed.load(Ordering::SeqCst), 1);
}

/// KR-REQ-09.09: `upload.chunk` writes no row, and invalidates nothing, when the host's answer is no
/// inside the lock. The control: the chunk is recorded under an admission that stands.
#[test]
fn an_upload_chunk_the_host_refuses_inside_the_lock_records_nothing() {
    for refuses in REFUSALS {
        let harness = Harness::create();
        let bytes = pattern(4096);
        let begun = harness
            .begin(&bytes, "application/octet-stream", "notes.bin")
            .expect("reserves the upload");
        let host = Host::new(refuses);
        let (chunk, payload) = chunk_of(&bytes, 0);
        let outcome = harness.service.upload_chunk(
            &harness.actor,
            &UploadChunkParams {
                transfer_id: begun.transfer_id,
                chunk,
                bytes: payload,
            },
            Some(&action(&harness, "upload.chunk", &bytes, &host)),
        );
        assert_not_admitted(outcome, refuses, &host);
        let status = harness
            .service
            .upload_status(
                &harness.actor,
                &UploadStatusParams {
                    transfer_id: begun.transfer_id,
                },
            )
            .expect("reads the status");
        assert_eq!(status.received_byte_len, U64::ZERO, "{refuses:?}");
        assert_eq!(status.state, UploadState::Receiving, "{refuses:?}");
    }

    let harness = Harness::create();
    let bytes = pattern(4096);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    let host = Host::new(Refuses::Never);
    harness
        .send_as(
            begun.transfer_id,
            &bytes,
            0,
            Some(&action(&harness, "upload.chunk", &bytes, &host)),
        )
        .expect("under an admission that stands the chunk is recorded");
    assert_eq!(host.committed.load(Ordering::SeqCst), 1);
}

/// KR-REQ-09.09: a chunk that conflicts with the one already recorded invalidates the upload only
/// under an admission that stands: a host that answers no leaves the upload receiving.
#[test]
fn a_conflicting_chunk_the_host_refuses_invalidates_nothing() {
    for refuses in REFUSALS {
        let harness = Harness::create();
        let bytes = pattern(4096);
        let begun = harness
            .begin(&bytes, "application/octet-stream", "notes.bin")
            .expect("reserves the upload");
        harness
            .send(begun.transfer_id, &bytes, 0)
            .expect("the first chunk is recorded");
        // The same position with other content, whose bytes match their own descriptor.
        let other = pattern(4096)
            .into_iter()
            .map(|byte| byte.wrapping_add(1))
            .collect::<Vec<_>>();
        let (chunk, payload) = chunk_of(&other, 0);
        let host = Host::new(refuses);
        let outcome = harness.service.upload_chunk(
            &harness.actor,
            &UploadChunkParams {
                transfer_id: begun.transfer_id,
                chunk,
                bytes: payload,
            },
            Some(&action(&harness, "upload.chunk", &other, &host)),
        );
        assert_not_admitted(outcome, refuses, &host);
        let status = harness
            .service
            .upload_status(
                &harness.actor,
                &UploadStatusParams {
                    transfer_id: begun.transfer_id,
                },
            )
            .expect("reads the status");
        assert_eq!(status.state, UploadState::Receiving, "{refuses:?}");
    }
}

/// KR-REQ-09.09: an upload past its expiry is marked expired by a chunk or a finish only under an
/// admission that stands, whether the host's answer is no when it is asked or when the expiry's
/// commit runs. The control: under one that stands the call finds the expiry, writes it through the
/// host, and refuses as an upload that has ended.
#[test]
fn an_expiry_a_call_finds_is_written_only_under_an_admission_that_stands() {
    for method in ["upload.chunk", "upload.finish"] {
        for refuses in REFUSALS {
            let harness = Harness::create();
            let bytes = pattern(4096);
            let begun = harness
                .begin(&bytes, "application/octet-stream", "notes.bin")
                .expect("reserves the upload");
            harness
                .send_all(begun.transfer_id, &bytes)
                .expect("sends every chunk");
            harness
                .clock
                .advance(kr_protocol::transfer::UNFINISHED_UPLOAD_LIFETIME.get());
            let host = Host::new(refuses);
            let performed = action(&harness, method, &bytes, &host);
            let outcome = if method == "upload.chunk" {
                harness
                    .send_as(begun.transfer_id, &bytes, 0, Some(&performed))
                    .map(|_| ())
            } else {
                harness
                    .finish_as(begun.transfer_id, &bytes, Some(&performed))
                    .map(|_| ())
            };
            assert_not_admitted(outcome, refuses, &host);
            let status = harness
                .service
                .upload_status(
                    &harness.actor,
                    &UploadStatusParams {
                        transfer_id: begun.transfer_id,
                    },
                )
                .expect("reads the status");
            assert_eq!(
                status.state,
                UploadState::Receiving,
                "{method} {refuses:?}: the expiry is not written"
            );
        }

        let harness = Harness::create();
        let bytes = pattern(4096);
        let begun = harness
            .begin(&bytes, "application/octet-stream", "notes.bin")
            .expect("reserves the upload");
        harness
            .send_all(begun.transfer_id, &bytes)
            .expect("sends every chunk");
        harness
            .clock
            .advance(kr_protocol::transfer::UNFINISHED_UPLOAD_LIFETIME.get());
        let host = Host::new(Refuses::Never);
        let performed = action(&harness, method, &bytes, &host);
        let error = if method == "upload.chunk" {
            harness
                .send_as(begun.transfer_id, &bytes, 0, Some(&performed))
                .expect_err("an expired upload takes no chunk")
        } else {
            harness
                .finish_as(begun.transfer_id, &bytes, Some(&performed))
                .expect_err("an expired upload is not finished")
        };
        assert!(
            matches!(error, TransferError::WrongState { .. }),
            "{method}: {error:?}"
        );
        assert_eq!(
            host.committed.load(Ordering::SeqCst),
            1,
            "{method}: the expiry was written through the host"
        );
        let status = harness
            .service
            .upload_status(
                &harness.actor,
                &UploadStatusParams {
                    transfer_id: begun.transfer_id,
                },
            )
            .expect("reads the status");
        assert_eq!(status.state, UploadState::Expired, "{method}");
    }
}

/// KR-REQ-09.09: `upload.finish` publishes nothing and claims nothing when the host's answer is no
/// inside the lock, and an upload whose bytes do not verify is not invalidated by an action the
/// host no longer admits. The control: under an admission that stands the handle is published.
#[test]
fn an_upload_finish_the_host_refuses_inside_the_lock_publishes_nothing() {
    for refuses in REFUSALS {
        let harness = Harness::create();
        let bytes = pattern(4096);
        let begun = harness
            .begin(&bytes, "application/octet-stream", "notes.bin")
            .expect("reserves the upload");
        harness
            .send_all(begun.transfer_id, &bytes)
            .expect("sends every chunk");
        let host = Host::new(refuses);
        let outcome = harness.finish_as(
            begun.transfer_id,
            &bytes,
            Some(&action(&harness, "upload.finish", &bytes, &host)),
        );
        assert_not_admitted(outcome, refuses, &host);
        let status = harness
            .service
            .upload_status(
                &harness.actor,
                &UploadStatusParams {
                    transfer_id: begun.transfer_id,
                },
            )
            .expect("reads the status");
        assert_eq!(status.state, UploadState::Receiving, "{refuses:?}");
        assert!(
            !status.handle.is_present(),
            "{refuses:?}: no handle is published"
        );
    }

    let harness = Harness::create();
    let bytes = pattern(4096);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends every chunk");
    let host = Host::new(Refuses::Never);
    harness
        .finish_as(
            begun.transfer_id,
            &bytes,
            Some(&action(&harness, "upload.finish", &bytes, &host)),
        )
        .expect("under an admission that stands the handle is published");
}

/// KR-REQ-09.09: the invalidation an upload that does not verify gets is this action's effect, and
/// is made only under an admission that stands. A host that answers no leaves the upload receiving,
/// to be finished under an admission that stands; the control invalidates it.
#[test]
fn an_invalidation_the_host_refuses_leaves_the_upload_receiving() {
    // Overwrites the staged bytes where they lie, so the whole-file verification fails.
    let corrupted = |harness: &Harness, transfer_id: TransferId| {
        let storage = kr_transfer::StorageName::derive(transfer_id, "notes.bin");
        let path = harness
            .service
            .staging()
            .incomplete()
            .display_path()
            .join(storage.incomplete().expect("the staged name").as_str());
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("opens the staged bytes");
        std::io::Write::write_all(&mut file, &[0xff; 64]).expect("overwrites the bytes");
    };
    for refuses in REFUSALS {
        let harness = Harness::create();
        let bytes = pattern(4096);
        let begun = harness
            .begin(&bytes, "application/octet-stream", "notes.bin")
            .expect("reserves the upload");
        harness
            .send_all(begun.transfer_id, &bytes)
            .expect("sends every chunk");
        corrupted(&harness, begun.transfer_id);
        let host = Host::new(refuses);
        let outcome = harness.finish_as(
            begun.transfer_id,
            &bytes,
            Some(&action(&harness, "upload.finish", &bytes, &host)),
        );
        // Under `WhenAsked` the host answers no before anything is read; under `AtTheCommit` it
        // is the invalidation's commit that is refused, so the upload is not closed either way.
        assert_not_admitted(outcome, refuses, &host);
        let status = harness
            .service
            .upload_status(
                &harness.actor,
                &UploadStatusParams {
                    transfer_id: begun.transfer_id,
                },
            )
            .expect("reads the status");
        assert_eq!(status.state, UploadState::Receiving, "{refuses:?}");
    }

    let harness = Harness::create();
    let bytes = pattern(4096);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends every chunk");
    corrupted(&harness, begun.transfer_id);
    let host = Host::new(Refuses::Never);
    let outcome = harness.finish_as(
        begun.transfer_id,
        &bytes,
        Some(&action(&harness, "upload.finish", &bytes, &host)),
    );
    assert!(
        matches!(outcome, Err(TransferError::Integrity { .. })),
        "{outcome:?}"
    );
    let status = harness
        .service
        .upload_status(
            &harness.actor,
            &UploadStatusParams {
                transfer_id: begun.transfer_id,
            },
        )
        .expect("reads the status");
    assert_eq!(
        status.state,
        UploadState::Invalidated,
        "under an admission that stands the upload that does not verify is invalidated"
    );
}

/// KR-REQ-09.09: `upload.cancel` closes nothing when the host's answer is no inside the lock. The
/// control: under an admission that stands the upload is cancelled.
#[test]
fn an_upload_cancel_the_host_refuses_inside_the_lock_closes_nothing() {
    for refuses in REFUSALS {
        let harness = Harness::create();
        let bytes = pattern(4096);
        let begun = harness
            .begin(&bytes, "application/octet-stream", "notes.bin")
            .expect("reserves the upload");
        let host = Host::new(refuses);
        let outcome = harness.service.upload_cancel(
            &harness.actor,
            &UploadCancelParams {
                transfer_id: begun.transfer_id,
            },
            Some(&action(&harness, "upload.cancel", &bytes, &host)),
        );
        assert_not_admitted(outcome, refuses, &host);
        let status = harness
            .service
            .upload_status(
                &harness.actor,
                &UploadStatusParams {
                    transfer_id: begun.transfer_id,
                },
            )
            .expect("reads the status");
        assert_eq!(status.state, UploadState::Receiving, "{refuses:?}");
        assert_eq!(
            harness.service.staged_byte_len().expect("the total"),
            4096,
            "{refuses:?}: the reservation is still charged"
        );
    }

    let harness = Harness::create();
    let bytes = pattern(4096);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    let host = Host::new(Refuses::Never);
    harness
        .cancel_as(
            begun.transfer_id,
            Some(&action(&harness, "upload.cancel", &bytes, &host)),
        )
        .expect("under an admission that stands the upload is cancelled");
}

fn draft_params(harness: &Harness) -> DraftCreateParams {
    DraftCreateParams {
        environment_id: harness.environment_id(),
        device_id: Nullable::some(DeviceId::new(Uuid::from_bytes([8; 16]))),
        session_id: Nullable::some(SessionId::new(Uuid::from_bytes([9; 16]))),
        application_instance_id: Nullable::null(),
        text: "have a look at this".to_owned(),
    }
}

/// KR-REQ-09.09: `draft.create`, `draft.update` and `agent.draft.add_attachment` write nothing when
/// the host's answer is no inside the lock. The control: each is written under an admission that
/// stands.
#[test]
fn a_draft_write_the_host_refuses_inside_the_lock_changes_nothing() {
    for refuses in REFUSALS {
        let harness = Harness::create();
        let host = Host::new(refuses);
        let created = harness.service.draft_create(
            &harness.actor,
            &draft_params(&harness),
            Some(&action(&harness, "draft.create", b"create", &host)),
        );
        assert_not_admitted(created, refuses, &host);

        // A draft that exists, to update and to bind an attachment to.
        let existing = harness
            .service
            .draft_create(&harness.actor, &draft_params(&harness), None)
            .expect("creates the draft")
            .draft;
        let handle = harness.publish(&pattern(2048), "image/png", "photo.png");
        let host = Host::new(refuses);
        let updated = harness.service.draft_update(
            &harness.actor,
            &DraftUpdateParams {
                draft_id: existing.draft_id,
                expected_revision: existing.revision,
                text: "other words".to_owned(),
            },
            Some(&action(&harness, "draft.update", b"update", &host)),
        );
        assert_not_admitted(updated, refuses, &host);
        let host = Host::new(refuses);
        let bound = harness.service.draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: existing.draft_id,
                expected_revision: existing.revision,
                transfer_id: handle.transfer_id,
                contribution: AttachmentContribution {
                    operation_id: "attach".to_owned(),
                    accepted_media_types: vec![handle.declared_media_type.clone()],
                    max_byte_len: U64::new(1024 * 1024),
                    max_count: U64::new(4),
                    insertion_method: InsertionMethod::TypedSubmission,
                    external_destination: Nullable::null(),
                    model_media_capability: false,
                },
            },
            Some(&action(
                &harness,
                "agent.draft.add_attachment",
                b"bind",
                &host,
            )),
        );
        assert_not_admitted(bound, refuses, &host);

        let read = harness
            .service
            .draft(&harness.actor, existing.draft_id)
            .expect("reads the draft");
        assert_eq!(read.revision, DraftRevision::new(1), "{refuses:?}");
        assert_eq!(read.text, "have a look at this", "{refuses:?}");
        assert!(read.attachments.is_empty(), "{refuses:?}");
    }

    let harness = Harness::create();
    let host = Host::new(Refuses::Never);
    harness
        .service
        .draft_create(
            &harness.actor,
            &draft_params(&harness),
            Some(&action(&harness, "draft.create", b"create", &host)),
        )
        .expect("under an admission that stands the draft is created");
    assert_eq!(host.committed.load(Ordering::SeqCst), 1);
}

/// An answer a call already holds is not a new effect and is not asked about: a repeat of a
/// completed action is answered from its record whatever the host now says, and the host is not
/// asked.
#[test]
fn a_repeat_answered_from_its_record_asks_the_host_nothing() {
    let harness = Harness::create();
    let bytes = pattern(4096);

    // `upload.begin`, then the same action again under a host that now answers no.
    let first = Host::new(Refuses::Never);
    let performed = action(&harness, "upload.begin", &bytes, &first);
    let begun = harness
        .service
        .upload_begin(
            &harness.actor,
            &begin_params(&harness, &bytes),
            Some(&performed),
        )
        .expect("the upload is reserved");
    let refusing = Host::new(Refuses::WhenAsked);
    let repeat = Action {
        admission: Admission::new(Arc::clone(&refusing) as Arc<dyn AdmissionHook>),
        ..performed
    };
    let again = harness
        .service
        .upload_begin(
            &harness.actor,
            &begin_params(&harness, &bytes),
            Some(&repeat),
        )
        .expect("the repeat is answered from the record");
    assert_eq!(again, begun, "one action, one answer");
    assert_eq!(
        refusing.asked.load(Ordering::SeqCst),
        0,
        "the host was asked nothing"
    );

    // `draft.create`, the same.
    let first = Host::new(Refuses::Never);
    let performed = action(&harness, "draft.create", b"create", &first);
    let created = harness
        .service
        .draft_create(&harness.actor, &draft_params(&harness), Some(&performed))
        .expect("the draft is created");
    let refusing = Host::new(Refuses::WhenAsked);
    let repeat = Action {
        admission: Admission::new(Arc::clone(&refusing) as Arc<dyn AdmissionHook>),
        ..performed
    };
    let again = harness
        .service
        .draft_create(&harness.actor, &draft_params(&harness), Some(&repeat))
        .expect("the repeat is answered from the record");
    assert_eq!(again, created, "one action, one answer");
    assert_eq!(
        refusing.asked.load(Ordering::SeqCst),
        0,
        "the host was asked nothing"
    );
}
