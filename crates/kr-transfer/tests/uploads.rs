//! Uploads: bounded chunks, integrity, resumption, quotas, storage layout and expiry.
//!
//! Requirement rows closed here: KR-REQ-14.01, KR-REQ-14.02, KR-REQ-14.07, KR-REQ-14.08,
//! KR-REQ-14.09, KR-REQ-14.10, KR-REQ-14.11, KR-REQ-14.12 and KR-REQ-24.09.

mod support;

use std::sync::Arc;

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{EnvironmentId, SessionId, TransferId};
use kr_protocol::limits::{
    DEFAULT_MAX_CONCURRENT_TRANSFERS, DEFAULT_MAX_STAGED_UPLOAD_LEN, DEFAULT_MAX_UPLOAD_FILE_LEN,
    UPLOAD_CHUNK_LEN,
};
use kr_protocol::scalars::{Bytes, Digest256, Nullable, U64, Uuid};
use kr_protocol::transfer::{
    ChunkBitmap, ChunkDescriptor, UNFINISHED_UPLOAD_LIFETIME, UNUSED_ATTACHMENT_LIFETIME,
    UploadBeginParams, UploadCancelParams, UploadChunkParams, UploadFinishParams, UploadState,
    UploadStatusParams,
};
use kr_transfer::store::Limits;
use kr_transfer::{ManualClock, RetainEverything, TransferService};
use support::{Harness, chunk_of, digest, pattern};

/// KR-REQ-14.08: `upload.begin` reserves the declared size and reports the documented defaults.
#[test]
fn begin_reserves_the_declared_size_under_the_documented_defaults() {
    let harness = Harness::create();
    assert_eq!(
        harness.service.limits().expect("reads the limits"),
        Limits {
            max_file_len: 2 * 1024 * 1024 * 1024,
            max_staged_len: 8 * 1024 * 1024 * 1024,
            max_concurrent_transfers: 2,
        },
        "the defaults are 2 GiB per file, 8 GiB staged per environment and two transfers"
    );
    assert_eq!(DEFAULT_MAX_UPLOAD_FILE_LEN, 2 * 1024 * 1024 * 1024);
    assert_eq!(DEFAULT_MAX_STAGED_UPLOAD_LEN, 8 * 1024 * 1024 * 1024);
    assert_eq!(DEFAULT_MAX_CONCURRENT_TRANSFERS, 2);

    let bytes = pattern(3 * UPLOAD_CHUNK_LEN / 2);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    assert_eq!(begun.layout.chunk_len, U64::new(UPLOAD_CHUNK_LEN as u64));
    assert_eq!(begun.layout.chunk_count, U64::new(2));
    assert_eq!(
        begun.layout.last_chunk_len,
        U64::new((UPLOAD_CHUNK_LEN / 2) as u64)
    );
    assert_eq!(
        begun.staged_byte_len,
        U64::new(bytes.len() as u64),
        "the declared size is charged before a byte arrives"
    );
    assert_eq!(begun.staged_byte_limit, U64::new(8 * 1024 * 1024 * 1024));
    let bitmap = ChunkBitmap::decode(&begun.received_chunks, begun.layout.chunk_count.get())
        .expect("a bitmap for this layout");
    assert_eq!(bitmap.received(), 0, "the bitmap starts empty");
    assert_eq!(
        begun.expires_at_ms.get(),
        support::START_MS + UNFINISHED_UPLOAD_LIFETIME.get(),
        "an unfinished upload expires after twenty-four hours"
    );
}

/// KR-REQ-14.08: a file above the environment's per-file limit is refused before anything is
/// staged.
#[test]
fn a_file_above_the_per_file_limit_is_refused() {
    let harness = Harness::create();
    harness.set_limits(Limits {
        max_file_len: 8,
        ..Limits::default()
    });
    let refusal = harness
        .begin(&pattern(9), "application/octet-stream", "big.bin")
        .expect_err("refuses the reservation");
    assert_eq!(refusal.code(), ErrorCode::QuotaExceeded);
    assert_eq!(
        harness.service.staged_byte_len().expect("reads the total"),
        0
    );
}

/// KR-REQ-14.08: the environment's staged total is a ceiling, and a released reservation frees it.
#[test]
fn the_environments_staged_total_is_a_ceiling_a_cancellation_frees() {
    let harness = Harness::create();
    harness.set_limits(Limits {
        max_file_len: 1024,
        max_staged_len: 100,
        max_concurrent_transfers: 8,
    });
    let first = harness
        .begin(&pattern(60), "application/octet-stream", "a.bin")
        .expect("reserves the first");
    let refusal = harness
        .begin(&pattern(60), "application/octet-stream", "b.bin")
        .expect_err("refuses the second");
    assert_eq!(refusal.code(), ErrorCode::QuotaExceeded);
    harness
        .service
        .upload_cancel(
            &harness.actor,
            &UploadCancelParams {
                transfer_id: first.transfer_id,
            },
        )
        .expect("cancels the first");
    harness
        .begin(&pattern(60), "application/octet-stream", "b.bin")
        .expect("the released reservation is available again");
}

/// KR-REQ-14.08: two concurrent transfers per device, and the ceiling is transient.
#[test]
fn a_device_holds_two_concurrent_transfers_and_no_more() {
    let harness = Harness::create();
    let bytes = pattern(16);
    let first = harness
        .begin(&bytes, "application/octet-stream", "a.bin")
        .expect("reserves the first");
    let _second = harness
        .begin(&bytes, "application/octet-stream", "b.bin")
        .expect("reserves the second");
    let refusal = harness
        .begin(&bytes, "application/octet-stream", "c.bin")
        .expect_err("refuses the third");
    assert_eq!(refusal.code(), ErrorCode::ResourceUnavailable);
    assert_eq!(
        refusal.code().retry_category(),
        kr_protocol::error::RetryCategory::Transient,
        "a concurrency ceiling clears when a transfer finishes"
    );
    harness
        .send_all(first.transfer_id, &bytes)
        .expect("sends the first");
    harness
        .finish(first.transfer_id, &bytes)
        .expect("publishes the first");
    harness
        .begin(&bytes, "application/octet-stream", "c.bin")
        .expect("a finished transfer frees the slot");
}

/// KR-REQ-14.02: chunks are bounded, verified and kept apart from completed files.
#[test]
fn bounded_chunks_are_verified_and_kept_apart_from_completed_files() {
    let harness = Harness::create();
    let bytes = pattern(UPLOAD_CHUNK_LEN + 4096);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    let incomplete = harness
        .service
        .staging()
        .incomplete()
        .display_path()
        .to_path_buf();
    let complete = harness
        .service
        .staging()
        .complete()
        .display_path()
        .to_path_buf();
    assert_ne!(incomplete, complete, "two directories, not one");

    harness
        .send(begun.transfer_id, &bytes, 0)
        .expect("sends the first chunk");
    assert_eq!(
        std::fs::read_dir(&incomplete)
            .expect("reads the incomplete area")
            .count(),
        1,
        "the partial payload is in the incomplete area"
    );
    assert_eq!(
        std::fs::read_dir(&complete)
            .expect("reads the completed area")
            .count(),
        0,
        "nothing is in the completed area until it is verified"
    );

    harness
        .send(begun.transfer_id, &bytes, 1)
        .expect("sends the last chunk");
    let finished = harness
        .finish(begun.transfer_id, &bytes)
        .expect("publishes the attachment");
    assert!(!finished.already_published);
    assert_eq!(
        std::fs::read_dir(&incomplete)
            .expect("reads the incomplete area")
            .count(),
        0,
        "the payload left the incomplete area"
    );
    assert_eq!(
        std::fs::read_dir(&complete)
            .expect("reads the completed area")
            .count(),
        1,
        "and is in the completed area"
    );
    assert_eq!(finished.handle.byte_len, U64::new(bytes.len() as u64));
    assert_eq!(finished.handle.content_digest, digest(&bytes));
}

/// KR-REQ-14.09: a chunk that does not match its own digest is refused and the upload survives.
#[test]
fn a_chunk_that_does_not_match_its_digest_is_refused_without_ending_the_upload() {
    let harness = Harness::create();
    let bytes = pattern(64);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    let (chunk, _) = chunk_of(&bytes, 0);
    let refusal = harness
        .service
        .upload_chunk(
            &harness.actor,
            &UploadChunkParams {
                transfer_id: begun.transfer_id,
                chunk,
                bytes: Bytes::new(vec![9; bytes.len()]),
            },
        )
        .expect_err("refuses the chunk");
    assert_eq!(refusal.code(), ErrorCode::AttachmentIntegrity);
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
        "a transmission fault is the caller's to retry"
    );
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("the retry is accepted");
    harness
        .finish(begun.transfer_id, &bytes)
        .expect("publishes the attachment");
}

/// KR-REQ-14.09: a matching duplicate is acknowledged and a conflicting one invalidates.
#[test]
fn a_matching_duplicate_is_acknowledged_and_a_conflicting_one_invalidates_the_upload() {
    let harness = Harness::create();
    let bytes = pattern(128);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    let (chunk, payload) = chunk_of(&bytes, 0);
    let first = harness
        .service
        .upload_chunk(
            &harness.actor,
            &UploadChunkParams {
                transfer_id: begun.transfer_id,
                chunk,
                bytes: payload.clone(),
            },
        )
        .expect("accepts the chunk");
    assert!(!first.duplicate);
    let again = harness
        .service
        .upload_chunk(
            &harness.actor,
            &UploadChunkParams {
                transfer_id: begun.transfer_id,
                chunk,
                bytes: payload,
            },
        )
        .expect("acknowledges the duplicate");
    assert!(again.duplicate, "a matching duplicate is acknowledged");

    let other = pattern(128)
        .iter()
        .map(|byte| byte ^ 0xff)
        .collect::<Vec<_>>();
    let (conflicting, conflicting_bytes) = chunk_of(&other, 0);
    let refusal = harness
        .service
        .upload_chunk(
            &harness.actor,
            &UploadChunkParams {
                transfer_id: begun.transfer_id,
                chunk: conflicting,
                bytes: conflicting_bytes,
            },
        )
        .expect_err("refuses the conflicting duplicate");
    assert_eq!(refusal.code(), ErrorCode::AttachmentIntegrity);
    let status = harness
        .service
        .upload_status(
            &harness.actor,
            &UploadStatusParams {
                transfer_id: begun.transfer_id,
            },
        )
        .expect("reads the status");
    assert_eq!(status.state, UploadState::Invalidated);
    assert!(status.invalid_reason.is_present());
    assert!(
        harness.finish(begun.transfer_id, &bytes).is_err(),
        "an invalidated upload cannot be finished"
    );
    assert_eq!(
        harness.service.staged_byte_len().expect("reads the total"),
        0,
        "its reservation is released"
    );
}

/// KR-REQ-14.09: a chunk whose length is not the layout's is refused.
#[test]
fn a_chunk_of_the_wrong_length_or_index_is_refused() {
    let harness = Harness::create();
    let bytes = pattern(64);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    let short = Bytes::new(bytes[..32].to_vec());
    let refusal = harness
        .service
        .upload_chunk(
            &harness.actor,
            &UploadChunkParams {
                transfer_id: begun.transfer_id,
                chunk: ChunkDescriptor {
                    index: U64::new(0),
                    byte_len: U64::new(32),
                    digest: digest(short.as_slice()),
                },
                bytes: short,
            },
        )
        .expect_err("refuses the wrong length");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    let (chunk, payload) = chunk_of(&bytes, 0);
    let refusal = harness
        .service
        .upload_chunk(
            &harness.actor,
            &UploadChunkParams {
                transfer_id: begun.transfer_id,
                chunk: ChunkDescriptor {
                    index: U64::new(7),
                    ..chunk
                },
                bytes: payload,
            },
        )
        .expect_err("refuses an index the layout does not have");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
}

/// KR-REQ-14.09: `upload.finish` verifies the whole-file digest and size before publishing.
#[test]
fn finish_verifies_the_whole_file_before_it_publishes() {
    let harness = Harness::create();
    let bytes = pattern(96);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    let missing = harness
        .finish(begun.transfer_id, &bytes)
        .expect_err("refuses an upload with no chunks");
    assert_eq!(missing.code(), ErrorCode::ResourceUnavailable);
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends every chunk");

    // A different declared digest is a changed source, not a different opinion about these bytes.
    let changed = harness
        .service
        .upload_finish(
            &harness.actor,
            &UploadFinishParams {
                transfer_id: begun.transfer_id,
                declared_byte_len: U64::new(bytes.len() as u64),
                declared_digest: Digest256::from_bytes([3; 32]),
            },
        )
        .expect_err("refuses a changed declaration");
    assert_eq!(changed.code(), ErrorCode::SourceChanged);
    harness
        .finish(begun.transfer_id, &bytes)
        .expect("publishes on the original declaration");
}

/// KR-REQ-14.09: a payload whose bytes were changed underneath the host fails verification.
#[test]
fn a_payload_changed_underneath_the_host_fails_verification_and_invalidates() {
    let harness = Harness::create();
    let bytes = pattern(96);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends every chunk");
    // Another writer under the same account: exactly what the authority model says it does not
    // exclude. The whole-file verification is what catches it.
    let staged = std::fs::read_dir(harness.service.staging().incomplete().display_path())
        .expect("reads the incomplete area")
        .next()
        .expect("one staged payload")
        .expect("a directory entry")
        .path();
    std::fs::write(&staged, vec![0; bytes.len()]).expect("overwrites the payload");
    let refusal = harness
        .finish(begun.transfer_id, &bytes)
        .expect_err("refuses to publish");
    assert_eq!(refusal.code(), ErrorCode::AttachmentIntegrity);
    let status = harness
        .service
        .upload_status(
            &harness.actor,
            &UploadStatusParams {
                transfer_id: begun.transfer_id,
            },
        )
        .expect("reads the status");
    assert_eq!(status.state, UploadState::Invalidated);
}

/// KR-REQ-14.10: a payload file is created exclusively, owner-only, never executable, and its
/// name comes from the transfer rather than from the client.
#[test]
fn a_payload_file_is_created_exclusively_owner_only_and_never_executable() {
    let harness = Harness::create();
    let bytes = pattern(32);
    let handle = harness.publish(&bytes, "image/png", "../../etc/pass wd.PNG");
    let complete = harness.service.staging().complete().display_path();
    let entries: Vec<_> = std::fs::read_dir(complete)
        .expect("reads the completed area")
        .map(|entry| entry.expect("a directory entry").file_name())
        .collect();
    assert_eq!(entries.len(), 1);
    let name = entries[0].to_string_lossy().to_string();
    assert!(
        !name.contains("etc") && !name.contains("..") && !name.contains(' '),
        "the storage name was {name}"
    );
    assert!(
        name.ends_with(".png"),
        "a validated extension is retained: {name}"
    );
    assert!(
        name.starts_with(
            &handle
                .transfer_id
                .get()
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ),
        "the name is derived from the transfer identifier: {name}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = std::fs::metadata(complete.join(&name))
            .expect("the published payload exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "mode was {mode:o}");
        assert_eq!(mode & 0o111, 0, "no executable bit");

        let directory = std::fs::metadata(complete)
            .expect("the completed area exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory, 0o700, "the staging area is owner-only");
    }
}

/// KR-REQ-14.10: the staging area lives under the environment's state directory with a random
/// name, and reopening the service finds the same one.
#[test]
fn the_staging_area_is_a_private_random_directory_under_the_environment_state_directory() {
    let harness = Harness::create();
    let state = harness.host.environment().state_dir().to_path_buf();
    let complete = harness
        .service
        .staging()
        .complete()
        .display_path()
        .to_path_buf();
    assert!(complete.starts_with(&state));
    let staging = complete
        .parent()
        .expect("a staging directory")
        .file_name()
        .expect("a name")
        .to_string_lossy()
        .to_string();
    assert_eq!(staging.len(), 32);
    assert!(staging.bytes().all(|byte| byte.is_ascii_hexdigit()));

    // A second service on the same environment keeps the directory the first one recorded.
    let clock = Arc::new(ManualClock::new(support::START_MS));
    let again = TransferService::with_clock(&harness.host.environment(), clock as Arc<_>)
        .expect("a second service");
    assert_eq!(
        again.staging().complete().identity(),
        harness.service.staging().complete().identity(),
        "the recorded staging directory is never replaced"
    );
}

/// KR-REQ-14.12: an interrupted upload resumes from verified chunk status under the same
/// identifier, and a lost reply to `upload.finish` is resolved through status.
#[test]
fn an_interrupted_upload_resumes_by_identifier_and_a_lost_finish_reply_resolves_through_status() {
    let harness = Harness::create();
    let bytes = pattern(UPLOAD_CHUNK_LEN + 512);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    harness
        .send(begun.transfer_id, &bytes, 1)
        .expect("sends the last chunk first");

    let status = harness
        .service
        .upload_status(
            &harness.actor,
            &UploadStatusParams {
                transfer_id: begun.transfer_id,
            },
        )
        .expect("reads the status");
    let bitmap = ChunkBitmap::decode(&status.received_chunks, status.layout.chunk_count.get())
        .expect("a bitmap for this layout");
    assert_eq!(
        bitmap.missing(),
        vec![0],
        "status says what is still needed"
    );
    assert_eq!(status.received_byte_len, U64::new(512));
    assert!(status.handle.as_ref().is_none());

    harness
        .send(begun.transfer_id, &bytes, 0)
        .expect("sends what status asked for");
    let published = harness
        .finish(begun.transfer_id, &bytes)
        .expect("publishes the attachment");
    assert!(!published.already_published);

    // The reply was lost. Status answers with the handle, and a repeated finish returns the same
    // one rather than producing a second file.
    let status = harness
        .service
        .upload_status(
            &harness.actor,
            &UploadStatusParams {
                transfer_id: begun.transfer_id,
            },
        )
        .expect("reads the status");
    assert_eq!(status.state, UploadState::Published);
    assert_eq!(
        status
            .handle
            .as_ref()
            .expect("a published handle")
            .transfer_id,
        published.handle.transfer_id
    );
    let again = harness
        .finish(begun.transfer_id, &bytes)
        .expect("answers the repeat");
    assert!(again.already_published);
    assert_eq!(again.handle.content_digest, published.handle.content_digest);
    assert_eq!(
        std::fs::read_dir(harness.service.staging().complete().display_path())
            .expect("reads the completed area")
            .count(),
        1,
        "no second file was published"
    );
}

/// KR-REQ-14.07: every one of the seven methods returns an opaque handle or identifier, and never
/// a host path the client supplied.
#[test]
fn the_transfer_methods_return_opaque_identifiers_and_never_a_client_path() {
    let harness = Harness::create();
    let bytes = pattern(48);
    let path_shaped = "/Users/someone/secret/photo.png";
    let begun = harness
        .begin(&bytes, "image/png", path_shaped)
        .expect("reserves the upload");
    let chunked = harness
        .service
        .upload_chunk(&harness.actor, &{
            let (chunk, payload) = chunk_of(&bytes, 0);
            UploadChunkParams {
                transfer_id: begun.transfer_id,
                chunk,
                bytes: payload,
            }
        })
        .expect("accepts the chunk");
    let status = harness
        .service
        .upload_status(
            &harness.actor,
            &UploadStatusParams {
                transfer_id: begun.transfer_id,
            },
        )
        .expect("reads the status");
    let finished = harness
        .finish(begun.transfer_id, &bytes)
        .expect("publishes the attachment");

    // Every one of the seven results is encoded and searched for the path the client sent. A CBOR
    // text string holds its bytes literally, so a path anywhere in a result would show up here.
    // The published handle is searched with its original filename removed, because that field is
    // metadata the protocol returns as it arrived.
    let needle = b"/Users/someone/secret";
    let mut scrubbed = finished.clone();
    scrubbed.handle.original_file_name = String::new();

    let download = harness
        .service
        .download_begin(
            &harness.actor,
            &kr_protocol::transfer::DownloadBeginParams {
                environment_id: harness.environment_id(),
                resume_transfer_id: Nullable::null(),
                source: Nullable::some(kr_protocol::transfer::DownloadSource::Attachment {
                    transfer_id: finished.handle.transfer_id,
                }),
                device_id: Nullable::null(),
            },
        )
        .expect("opens the source");
    let chunk = harness
        .service
        .download_chunk(
            &harness.actor,
            &kr_protocol::transfer::DownloadChunkParams {
                transfer_id: download.transfer_id,
                index: U64::new(0),
            },
        )
        .expect("reads the chunk");

    // A second upload, cancelled, so the seventh result is a real one.
    let spare = harness
        .begin(&bytes, "image/png", path_shaped)
        .expect("reserves another upload");
    let cancelled = harness
        .service
        .upload_cancel(
            &harness.actor,
            &UploadCancelParams {
                transfer_id: spare.transfer_id,
            },
        )
        .expect("cancels it");

    for (what, encoded) in [
        (
            "upload.begin",
            kr_cbor::to_canonical_vec(&begun).expect("encodes"),
        ),
        (
            "upload.status",
            kr_cbor::to_canonical_vec(&status).expect("encodes"),
        ),
        (
            "upload.chunk",
            kr_cbor::to_canonical_vec(&chunked).expect("encodes"),
        ),
        (
            "upload.finish",
            kr_cbor::to_canonical_vec(&scrubbed).expect("encodes"),
        ),
        (
            "upload.cancel",
            kr_cbor::to_canonical_vec(&cancelled).expect("encodes"),
        ),
        (
            "download.begin",
            kr_cbor::to_canonical_vec(&download).expect("encodes"),
        ),
        (
            "download.chunk",
            kr_cbor::to_canonical_vec(&chunk).expect("encodes"),
        ),
    ] {
        assert!(
            !encoded.windows(needle.len()).any(|window| window == needle),
            "{what} carried a client path"
        );
    }
    assert_eq!(
        finished.handle.original_file_name, path_shaped,
        "the original name is the one field that is metadata, returned as it arrived"
    );

    let refusal = harness
        .service
        .upload_cancel(
            &harness.actor,
            &UploadCancelParams {
                transfer_id: begun.transfer_id,
            },
        )
        .expect_err("a published attachment is not cancelled");
    assert_eq!(refusal.code(), ErrorCode::ResourceUnavailable);
}

/// KR-REQ-14.01: an upload binds to one environment and session, and identifiers from another
/// environment mean nothing here.
#[test]
fn an_upload_binds_to_its_environment_and_session_and_never_aliases_another() {
    let harness = Harness::create();
    let session_id = SessionId::new(Uuid::from_bytes([4; 16]));
    let bytes = pattern(24);
    let begun = harness
        .begin_for(
            &bytes,
            "application/octet-stream",
            "notes.bin",
            Nullable::some(session_id),
        )
        .expect("reserves the upload");
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends every chunk");
    let handle = harness
        .finish(begun.transfer_id, &bytes)
        .expect("publishes the attachment")
        .handle;
    assert_eq!(handle.environment_id, harness.environment_id());
    assert_eq!(handle.session_id.as_ref(), Some(&session_id));

    let elsewhere = EnvironmentId::new(Uuid::from_bytes([200; 16]));
    let refusal = harness
        .service
        .upload_begin(
            &harness.actor,
            &UploadBeginParams {
                environment_id: elsewhere,
                session_id: Nullable::null(),
                device_id: Nullable::null(),
                declared_byte_len: U64::new(bytes.len() as u64),
                declared_digest: digest(&bytes),
                declared_media_type: "application/octet-stream".to_owned(),
                original_file_name: "notes.bin".to_owned(),
            },
            None,
        )
        .expect_err("refuses another environment");
    assert_eq!(refusal.code(), ErrorCode::EnvironmentUnavailable);

    // A second environment on the same host has its own store, its own staging area and no sight
    // of this one's transfers: a Windows path and a WSL path are two of these, never one.
    let other = Harness::create();
    assert_ne!(other.environment_id(), harness.environment_id());
    let across = other
        .service
        .upload_status(
            &other.actor,
            &UploadStatusParams {
                transfer_id: handle.transfer_id,
            },
        )
        .expect_err("the identifier means nothing there");
    assert_eq!(across.code(), ErrorCode::InvalidArgument);
    assert_ne!(
        other.service.staging().complete().identity(),
        harness.service.staging().complete().identity()
    );
}

/// KR-REQ-14.07: an upload belongs to the principal that began it, and another principal's
/// transfer is refused exactly as one that does not exist is.
#[test]
fn another_principal_cannot_continue_or_read_an_upload() {
    let harness = Harness::create();
    let bytes = pattern(24);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends every chunk");
    harness
        .finish(begun.transfer_id, &bytes)
        .expect("publishes the attachment");
    let other = kr_protocol::ids::ActorId::new("local:someone-else").expect("a valid principal");
    let absent = TransferId::new(Uuid::from_bytes([222; 16]));

    let refused = harness
        .service
        .upload_status(
            &other,
            &UploadStatusParams {
                transfer_id: begun.transfer_id,
            },
        )
        .expect_err("refuses another principal");
    let unknown = harness
        .service
        .upload_status(
            &other,
            &UploadStatusParams {
                transfer_id: absent,
            },
        )
        .expect_err("refuses an identifier that names nothing");
    assert_eq!(
        refused.code(),
        unknown.code(),
        "the refusal is never a signal that the identifier exists"
    );
    assert_eq!(refused.to_string(), unknown_shape(begun.transfer_id));

    // The published handle is not reachable by another principal either.
    assert_eq!(
        harness
            .service
            .attachment_handle(&other, begun.transfer_id)
            .expect_err("refuses another principal")
            .code(),
        unknown.code()
    );
    harness
        .service
        .attachment_handle(&harness.actor, begun.transfer_id)
        .expect("its own principal reaches it");
}

fn unknown_shape(transfer_id: TransferId) -> String {
    format!("no transfer {transfer_id}")
}

/// KR-REQ-14.11: an unfinished upload expires after twenty-four hours and a completed but unused
/// attachment after seven days; a submitted one follows the session's retention.
#[test]
fn expiry_runs_at_twenty_four_hours_seven_days_and_the_session_retention() {
    let harness = Harness::create();
    let bytes = pattern(32);
    let unfinished = harness
        .begin(&bytes, "application/octet-stream", "abandoned.bin")
        .expect("reserves the upload");
    harness
        .send(unfinished.transfer_id, &bytes, 0)
        .expect("sends a chunk and stops");
    let unused = harness.publish(&bytes, "application/octet-stream", "unused.bin");

    harness.clock.advance(UNFINISHED_UPLOAD_LIFETIME.get() - 1);
    let sweep = harness
        .service
        .sweep(&RetainEverything)
        .expect("runs a sweep");
    assert_eq!(sweep.expired_uploads, 0, "one millisecond short");

    harness.clock.advance(1);
    let sweep = harness
        .service
        .sweep(&RetainEverything)
        .expect("runs a sweep");
    assert_eq!(sweep.expired_uploads, 1);
    assert_eq!(sweep.expired_attachments, 0, "seven days have not passed");
    assert_eq!(
        std::fs::read_dir(harness.service.staging().incomplete().display_path())
            .expect("reads the incomplete area")
            .count(),
        0,
        "the abandoned payload is gone"
    );

    harness
        .clock
        .set(support::START_MS + UNUSED_ATTACHMENT_LIFETIME.get());
    let sweep = harness
        .service
        .sweep(&RetainEverything)
        .expect("runs a sweep");
    assert_eq!(sweep.expired_attachments, 1);
    assert!(
        harness
            .service
            .attachment_handle(&harness.actor, unused.transfer_id)
            .is_err(),
        "an expired attachment has no handle"
    );
    assert_eq!(
        std::fs::read_dir(harness.service.staging().complete().display_path())
            .expect("reads the completed area")
            .count(),
        0,
        "and its payload is gone"
    );
}

/// KR-REQ-14.11: a submitted attachment outlives the seven-day window while its session is
/// retained, and goes when the session's retention ends.
#[test]
fn a_submitted_attachment_follows_its_sessions_retention() {
    struct Retains(bool);
    impl kr_transfer::SessionRetention for Retains {
        fn retains(&self, _session_id: SessionId) -> bool {
            self.0
        }
    }

    let harness = Harness::create();
    let session_id = SessionId::new(Uuid::from_bytes([11; 16]));
    let bytes = pattern(32);
    let begun = harness
        .begin_for(
            &bytes,
            "application/octet-stream",
            "submitted.bin",
            Nullable::some(session_id),
        )
        .expect("reserves the upload");
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends every chunk");
    let handle = harness
        .finish(begun.transfer_id, &bytes)
        .expect("publishes the attachment")
        .handle;
    let draft = harness
        .service
        .draft_create(
            &harness.actor,
            &kr_protocol::transfer::DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::some(session_id),
                application_instance_id: Nullable::null(),
                text: "look at this".to_owned(),
            },
            None,
        )
        .expect("creates the draft")
        .draft;
    harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &kr_protocol::transfer::AgentDraftAddAttachmentParams {
                draft_id: draft.draft_id,
                expected_revision: draft.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle),
            },
            None,
        )
        .expect("binds the attachment");
    harness
        .service
        .mark_submitted(&harness.actor, draft.draft_id)
        .expect("records the submission");

    harness
        .clock
        .set(support::START_MS + UNUSED_ATTACHMENT_LIFETIME.get() + 1);
    let sweep = harness.service.sweep(&Retains(true)).expect("runs a sweep");
    assert_eq!(
        sweep.expired_attachments, 0,
        "a retained session keeps what was submitted to it"
    );
    harness
        .service
        .attachment_handle(&harness.actor, handle.transfer_id)
        .expect("the handle is still there");

    let sweep = harness
        .service
        .sweep(&Retains(false))
        .expect("runs a sweep");
    assert_eq!(sweep.expired_attachments, 1);
}

/// KR-REQ-14.11: a session whose retention ends *before* the seven-day window takes what was
/// submitted to it with it.
#[test]
fn a_session_retention_that_ends_early_expires_what_was_submitted_to_it() {
    struct Retains(bool);
    impl kr_transfer::SessionRetention for Retains {
        fn retains(&self, _session_id: SessionId) -> bool {
            self.0
        }
    }

    let harness = Harness::create();
    let session_id = SessionId::new(Uuid::from_bytes([12; 16]));
    let bytes = pattern(32);
    let begun = harness
        .begin_for(
            &bytes,
            "application/octet-stream",
            "submitted.bin",
            Nullable::some(session_id),
        )
        .expect("reserves the upload");
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends every chunk");
    let handle = harness
        .finish(begun.transfer_id, &bytes)
        .expect("publishes the attachment")
        .handle;
    assert_eq!(
        handle.expires_at_ms.get(),
        support::START_MS + UNUSED_ATTACHMENT_LIFETIME.get(),
        "an unsubmitted attachment carries the seven-day window"
    );
    let draft = harness
        .service
        .draft_create(
            &harness.actor,
            &kr_protocol::transfer::DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::some(session_id),
                application_instance_id: Nullable::null(),
                text: "look at this".to_owned(),
            },
            None,
        )
        .expect("creates the draft")
        .draft;
    harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &kr_protocol::transfer::AgentDraftAddAttachmentParams {
                draft_id: draft.draft_id,
                expected_revision: draft.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle),
            },
            None,
        )
        .expect("binds the attachment");
    harness
        .service
        .mark_submitted(&harness.actor, draft.draft_id)
        .expect("records the submission");

    // One hour later, long before seven days, the session's retention ends.
    harness.clock.advance(60 * 60 * 1000);
    let sweep = harness
        .service
        .sweep(&Retains(false))
        .expect("runs a sweep");
    assert_eq!(
        sweep.expired_attachments, 1,
        "a submitted attachment follows its session, not its own deadline"
    );
    assert!(
        harness
            .service
            .attachment_handle(&harness.actor, handle.transfer_id)
            .is_err()
    );
    assert_eq!(
        std::fs::read_dir(harness.service.staging().complete().display_path())
            .expect("reads the completed area")
            .count(),
        0
    );
    assert_eq!(harness.service.staged_byte_len().expect("reads"), 0);
}

/// KR-REQ-14.10: a staging directory replaced at the same name is refused rather than used.
#[test]
fn a_replaced_staging_directory_is_refused() {
    let host = kr_ipc::testing::TempHost::create();
    let staging = {
        let clock = Arc::new(ManualClock::new(support::START_MS));
        let service = TransferService::with_clock(&host.environment(), clock as Arc<_>)
            .expect("a transfer service");
        service
            .staging()
            .complete()
            .display_path()
            .parent()
            .expect("a staging directory")
            .to_path_buf()
    };
    // Reopening the same environment finds the same object and is accepted.
    {
        let clock = Arc::new(ManualClock::new(support::START_MS));
        TransferService::with_clock(&host.environment(), clock as Arc<_>)
            .expect("the recorded staging directory is accepted");
    }
    // Something replaces the staging directory with a different one under the same name.
    std::fs::rename(&staging, staging.with_extension("moved")).expect("moves it aside");
    std::fs::create_dir(&staging).expect("creates a different directory");
    let clock = Arc::new(ManualClock::new(support::START_MS));
    let refusal = TransferService::with_clock(&host.environment(), clock as Arc<_>)
        .expect_err("refuses a staging directory that is not the recorded object");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
}

/// KR-REQ-24.09, KR-REQ-14.12: a daemon that dies mid-publish resolves the transfer by
/// identifier, and the completed file's identity and bytes survive.
///
/// The daemon is ended the way its process exiting would end it: the service is dropped, its
/// journal connection with it, and a replacement opens the same environment. The interrupted
/// publish is written through the journal itself, because the service that would have finished the
/// move is gone.
#[test]
fn a_restart_mid_publish_resolves_by_identifier_without_losing_the_completed_file() {
    let host = kr_ipc::testing::TempHost::create();
    let bytes = pattern(64);
    let actor = kr_protocol::ids::ActorId::new("local:transfer-test").expect("a valid principal");
    let expected = digest(&bytes);
    let transfer_id: TransferId;
    let payload_identity: kr_transfer::ObjectIdentity;
    let staged_path: std::path::PathBuf;
    {
        let clock = Arc::new(ManualClock::new(support::START_MS));
        let service = TransferService::with_clock(&host.environment(), clock as Arc<_>)
            .expect("a transfer service");
        let begun = service
            .upload_begin(
                &actor,
                &UploadBeginParams {
                    environment_id: host.environment_id(),
                    session_id: Nullable::null(),
                    device_id: Nullable::null(),
                    declared_byte_len: U64::new(bytes.len() as u64),
                    declared_digest: expected,
                    declared_media_type: "application/octet-stream".to_owned(),
                    original_file_name: "notes.bin".to_owned(),
                },
                None,
            )
            .expect("reserves the upload");
        transfer_id = begun.transfer_id;
        let (chunk, payload) = chunk_of(&bytes, 0);
        service
            .upload_chunk(
                &actor,
                &UploadChunkParams {
                    transfer_id,
                    chunk,
                    bytes: payload,
                },
            )
            .expect("accepts the chunk");
        staged_path = std::fs::read_dir(service.staging().incomplete().display_path())
            .expect("reads the incomplete area")
            .next()
            .expect("one staged payload")
            .expect("a directory entry")
            .path();
        payload_identity = identity_of(&staged_path);
        // The daemon dies here. Nothing else runs in this process for this environment.
    }
    // The publish is interrupted between its two commits: the verification is durable, carrying
    // the identity of the object it verified, and the payload is still under its incomplete name.
    interrupt_publish(&host, transfer_id, expected, payload_identity);

    let clock = Arc::new(ManualClock::new(support::START_MS + 5_000));
    let service = TransferService::with_clock(&host.environment(), clock as Arc<_>)
        .expect("a replacement service");
    let status = service
        .upload_status(&actor, &UploadStatusParams { transfer_id })
        .expect("reads the status");
    assert_eq!(status.state, UploadState::Publishing);
    let recovery = service.recover().expect("recovers");
    assert_eq!(recovery.completed_publications, 1);
    assert_eq!(recovery.unresolved_publications, 0);

    let handle = service
        .attachment_handle(&actor, transfer_id)
        .expect("the completed file has a handle");
    assert_eq!(
        handle.content_digest, expected,
        "the completed file's identity is unchanged"
    );
    let published = std::fs::read_dir(service.staging().complete().display_path())
        .expect("reads the completed area")
        .next()
        .expect("one published payload")
        .expect("a directory entry")
        .path();
    assert_eq!(
        std::fs::read(&published).expect("reads the payload"),
        bytes,
        "the bytes are the ones that were verified"
    );
    assert_eq!(
        identity_of(&published),
        payload_identity,
        "and the object is the one that was verified, not a replacement of the same length"
    );
    assert_eq!(
        std::fs::read_dir(service.staging().incomplete().display_path())
            .expect("reads the incomplete area")
            .count(),
        0
    );
    // A second recovery pass changes nothing: the publish is already resolved.
    assert_eq!(
        service.recover().expect("recovers again"),
        kr_transfer::Recovery::default()
    );
}

/// KR-REQ-24.09: a verified publication whose payload was replaced is refused rather than
/// published, and one whose payload is gone is invalidated.
#[test]
fn a_replaced_or_missing_payload_is_never_published() {
    let host = kr_ipc::testing::TempHost::create();
    let bytes = pattern(64);
    let actor = kr_protocol::ids::ActorId::new("local:transfer-test").expect("a valid principal");
    let expected = digest(&bytes);
    let clock = Arc::new(ManualClock::new(support::START_MS));
    let service = TransferService::with_clock(&host.environment(), clock as Arc<_>)
        .expect("a transfer service");
    let begun = service
        .upload_begin(
            &actor,
            &UploadBeginParams {
                environment_id: host.environment_id(),
                session_id: Nullable::null(),
                device_id: Nullable::null(),
                declared_byte_len: U64::new(bytes.len() as u64),
                declared_digest: expected,
                declared_media_type: "application/octet-stream".to_owned(),
                original_file_name: "notes.bin".to_owned(),
            },
            None,
        )
        .expect("reserves the upload");
    let (chunk, payload) = chunk_of(&bytes, 0);
    service
        .upload_chunk(
            &actor,
            &UploadChunkParams {
                transfer_id: begun.transfer_id,
                chunk,
                bytes: payload,
            },
        )
        .expect("accepts the chunk");
    let staged = std::fs::read_dir(service.staging().incomplete().display_path())
        .expect("reads the incomplete area")
        .next()
        .expect("one staged payload")
        .expect("a directory entry")
        .path();
    let verified = identity_of(&staged);
    interrupt_publish(&host, begun.transfer_id, expected, verified);

    // Another writer replaces the payload with a file of the same length. Recovery finds an object
    // that is not the one that was verified, so nothing is published.
    std::fs::remove_file(&staged).expect("removes the payload");
    std::fs::write(&staged, vec![0_u8; bytes.len()]).expect("writes a replacement");
    assert_ne!(identity_of(&staged), verified);
    let recovery = service.recover().expect("recovers");
    assert_eq!(recovery.completed_publications, 0);
    assert_eq!(recovery.unresolved_publications, 1);
    let status = service
        .upload_status(
            &actor,
            &UploadStatusParams {
                transfer_id: begun.transfer_id,
            },
        )
        .expect("reads the status");
    assert_eq!(status.state, UploadState::Invalidated);
    assert!(status.handle.as_ref().is_none());
    assert_eq!(
        std::fs::read_dir(service.staging().complete().display_path())
            .expect("reads the completed area")
            .count(),
        0,
        "nothing reached the completed area"
    );
    // The invalidated upload's payload is removed and its bytes released.
    assert_eq!(service.staged_byte_len().expect("reads the total"), 0);
}

/// KR-REQ-24.09: a payload a closed upload left behind is removed by the next recovery pass, and
/// its bytes stay charged until it is.
#[test]
fn a_payload_a_closed_upload_left_behind_is_removed_by_recovery() {
    let harness = Harness::create();
    let bytes = pattern(64);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "abandoned.bin")
        .expect("reserves the upload");
    harness
        .send(begun.transfer_id, &bytes, 0)
        .expect("sends the chunk");
    let staged = std::fs::read_dir(harness.service.staging().incomplete().display_path())
        .expect("reads the incomplete area")
        .next()
        .expect("one staged payload")
        .expect("a directory entry")
        .path();

    // The row is closed through the journal, which is the state a daemon that died between the
    // commit and the unlink leaves behind.
    {
        let mut store = kr_transfer::Store::open(
            kr_transfer::StagingArea::store_path(&harness.host.environment()),
            harness.host.environment_id(),
        )
        .expect("opens the journal");
        store
            .close_upload(
                begun.transfer_id,
                UploadState::Cancelled,
                None,
                kr_protocol::scalars::TimestampMs::new(support::START_MS + 1),
            )
            .expect("closes the row");
    }
    assert!(staged.exists(), "the payload is still there");
    assert_eq!(
        harness.service.staged_byte_len().expect("reads the total"),
        bytes.len() as u64,
        "and its bytes are still charged"
    );

    let recovery = harness.service.recover().expect("recovers");
    assert_eq!(recovery.removed_payloads, 1);
    assert_eq!(recovery.unremovable_payloads, 0);
    assert!(!staged.exists(), "the payload is gone");
    assert_eq!(
        harness.service.staged_byte_len().expect("reads the total"),
        0,
        "and its bytes are released"
    );
    assert_eq!(
        harness
            .service
            .recover()
            .expect("recovers again")
            .removed_payloads,
        0
    );
}

/// Records an interrupted publication in the journal, exactly as the service would have.
fn interrupt_publish(
    host: &kr_ipc::testing::TempHost,
    transfer_id: TransferId,
    digest: Digest256,
    payload_identity: kr_transfer::ObjectIdentity,
) {
    let mut store = kr_transfer::Store::open(
        kr_transfer::StagingArea::store_path(&host.environment()),
        host.environment_id(),
    )
    .expect("opens the journal");
    store
        .begin_publish(
            transfer_id,
            digest,
            payload_identity,
            None,
            None,
            kr_protocol::scalars::TimestampMs::new(support::START_MS + 1),
        )
        .expect("records the verification");
}

/// Returns a file's stable filesystem identity.
fn identity_of(path: &std::path::Path) -> kr_transfer::ObjectIdentity {
    let metadata = std::fs::metadata(path).expect("the file exists");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        kr_transfer::ObjectIdentity {
            device: metadata.dev(),
            file_id: metadata.ino(),
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        kr_transfer::ObjectIdentity {
            device: u64::from(
                metadata
                    .volume_serial_number()
                    .expect("an identity from an opened file"),
            ),
            file_id: metadata
                .file_index()
                .expect("an identity from an opened file"),
        }
    }
}

fn contribution(
    handle: &kr_protocol::transfer::AttachmentHandle,
) -> kr_protocol::transfer::AttachmentContribution {
    kr_protocol::transfer::AttachmentContribution {
        operation_id: "attach".to_owned(),
        accepted_media_types: vec![handle.declared_media_type.clone()],
        max_byte_len: U64::new(1024 * 1024),
        max_count: U64::new(4),
        insertion_method: kr_protocol::transfer::InsertionMethod::TypedSubmission,
        external_destination: Nullable::null(),
        model_media_capability: false,
    }
}
