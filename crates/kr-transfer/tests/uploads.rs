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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
        .upload_chunk(
            &harness.actor,
            &{
                let (chunk, payload) = chunk_of(&bytes, 0);
                UploadChunkParams {
                    transfer_id: begun.transfer_id,
                    chunk,
                    bytes: payload,
                }
            },
            None,
        )
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
            None,
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
            None,
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
                None,
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
    interrupt_publish(&host, transfer_id, expected, payload_identity, None);

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
    let harness = Harness::create();
    let bytes = pattern(64);
    let (transfer_id, staged) = interrupted_publication(&harness, &bytes, "notes.bin", None);

    // Another writer replaces the payload with a file of the same length. Whether the replacement
    // is an object the filesystem gives a new identifier or one it gives the identifier the
    // removal has just freed is the filesystem's to decide, and the outcome is the same either
    // way: these are not the bytes that were verified, so no handle is published over them.
    std::fs::remove_file(&staged).expect("removes the payload");
    std::fs::write(&staged, vec![0_u8; bytes.len()]).expect("writes a replacement");

    let recovery = harness.service.recover().expect("recovers");
    assert_publication_invalidated(&harness, transfer_id, recovery);
}

/// KR-REQ-24.09: a verified publication whose payload was rewritten where it lies is invalidated
/// rather than published.
///
/// This is the same case as the replacement above on a filesystem that reuses a freed file
/// identifier, and here it happens on every filesystem: the payload is opened and overwritten in
/// place, so the device and the file number are exactly the ones the publication recorded and only
/// the bytes differ. Identity is the cheap first gate; the digest is what decides.
#[test]
fn a_payload_rewritten_in_place_is_invalidated_rather_than_published() {
    let harness = Harness::create();
    let bytes = pattern(64);
    let (transfer_id, staged) = interrupted_publication(&harness, &bytes, "notes.bin", None);
    let verified = identity_of(&staged);

    rewrite_in_place(&staged, bytes.len());
    assert_eq!(
        identity_of(&staged),
        verified,
        "an overwrite in place leaves the object's identity exactly as it was"
    );

    let recovery = harness.service.recover().expect("recovers");
    let reason = harness
        .service
        .upload_status(&harness.actor, &UploadStatusParams { transfer_id })
        .expect("reads the status")
        .invalid_reason;
    assert!(
        reason
            .as_ref()
            .is_some_and(|reason| reason.contains("different digest")),
        "the digest is what decided it, and the row said {:?}",
        reason.as_ref()
    );
    assert_publication_invalidated(&harness, transfer_id, recovery);
}

/// KR-REQ-24.09: a publication whose payload reached its published name before the journal caught
/// up is invalidated too, when the bytes under that name are not the ones that were verified.
///
/// The other state an interrupted publish leaves: the move landed and the commit behind it did not.
#[test]
fn a_published_name_holding_altered_bytes_is_invalidated() {
    let harness = Harness::create();
    let bytes = pattern(64);
    let (transfer_id, staged) = interrupted_publication(&harness, &bytes, "moved.bin", None);
    let (_, published) = payload_paths(&harness, transfer_id, "moved.bin");
    std::fs::rename(&staged, &published).expect("the move that the second commit never recorded");
    let verified = identity_of(&published);

    rewrite_in_place(&published, bytes.len());
    assert_eq!(
        identity_of(&published),
        verified,
        "a rename and an overwrite in place both leave the object's identity as it was"
    );

    let recovery = harness.service.recover().expect("recovers");
    assert_publication_invalidated(&harness, transfer_id, recovery);
}

/// KR-REQ-24.09, KR-REQ-14.12: a publication that ends invalidated answers the action that claimed
/// it, so every copy of that action is told what happened rather than being refused for the state
/// the invalidation left behind.
#[test]
fn an_invalidated_publication_answers_the_action_that_claimed_it() {
    let harness = Harness::create();
    let bytes = pattern(64);
    let claim = action(&harness, "upload.finish", &bytes);
    let (transfer_id, staged) =
        interrupted_publication(&harness, &bytes, "notes.bin", Some(&claim));
    rewrite_in_place(&staged, bytes.len());

    // The retried finish resolves the publication its own action claimed, finds bytes that are not
    // the verified ones, and says so.
    let refusal = harness
        .finish_as(transfer_id, &bytes, Some(&claim))
        .expect_err("refuses to publish bytes that were never verified");
    assert_eq!(refusal.code(), ErrorCode::AttachmentIntegrity);

    // A copy of that action arriving before any recovery pass is owed the same answer, word for
    // word, rather than a refusal for the state the invalidation left behind.
    let repeat = harness
        .finish_as(transfer_id, &bytes, Some(&claim))
        .expect_err("answers the repeat from the record");
    assert_eq!(repeat.code(), refusal.code());
    assert_eq!(repeat.to_string(), refusal.to_string());

    // The claim is answered, so recovery has nothing left to settle, and a copy that arrives after
    // it is answered the same way again.
    assert_eq!(
        harness.service.recover().expect("recovers"),
        kr_transfer::Recovery::default(),
        "the refusal left nothing for a recovery pass to resolve"
    );
    let afterwards = harness
        .finish_as(transfer_id, &bytes, Some(&claim))
        .expect_err("answers a later copy the same way");
    assert_eq!(afterwards.code(), refusal.code());
    assert_eq!(afterwards.to_string(), refusal.to_string());

    // And a caller with no action of its own is told the same thing, not the bare state.
    let fresh = harness
        .finish_as(transfer_id, &bytes, None)
        .expect_err("refuses an upload that ended without publishing");
    assert_eq!(fresh.code(), refusal.code());
    assert_eq!(fresh.to_string(), refusal.to_string());

    // So is one under an action of its own, which has nothing to record against: its refusal
    // matches no claim, and the answer it keeps is the one it computed.
    let another = harness
        .finish_as(
            transfer_id,
            &bytes,
            Some(&action(&harness, "upload.finish", &bytes)),
        )
        .expect_err("refuses a different action the same way");
    assert_eq!(another.code(), refusal.code());
    assert_eq!(another.to_string(), refusal.to_string());
}

/// KR-REQ-14.12, KR-REQ-24.09: an upload the sweep expired answers its open claim once, and the
/// recovery pass behind the sweep does not answer it again.
///
/// The interleaving this reproduces: the sweep closes the row and releases the journal before it
/// resolves the claims, and a retried finish arrives in that window. Whatever the retry is told has
/// to be what every later copy of its action is told.
#[test]
fn an_expired_publication_answers_its_claim_once() {
    let harness = Harness::create();
    let bytes = pattern(64);
    let claim = action(&harness, "upload.finish", &bytes);
    let (transfer_id, _) = interrupted_publication(&harness, &bytes, "notes.bin", Some(&claim));

    // The sweep's first commit, through the journal: the row is closed and its claim is still open,
    // which is exactly what a retry can find between the sweep's two steps.
    {
        let mut store = kr_transfer::Store::open(
            kr_transfer::StagingArea::store_path(&harness.host.environment()),
            harness.host.environment_id(),
        )
        .expect("opens the journal");
        store
            .close_upload(
                transfer_id,
                UploadState::Expired,
                Some("this upload was unfinished for longer than its expiry"),
                kr_protocol::scalars::TimestampMs::new(support::START_MS + 2),
                None,
            )
            .expect("closes the row");
    }

    let refusal = harness
        .finish_as(transfer_id, &bytes, Some(&claim))
        .expect_err("refuses an upload that ended before it published");
    assert_eq!(refusal.code(), ErrorCode::ResourceUnavailable);

    // The pass behind the sweep finds the claim answered and leaves it alone.
    let recovery = harness.service.recover().expect("recovers");
    assert_eq!(
        recovery.resolved_claims, 0,
        "the claim was answered when the retry was refused"
    );
    let afterwards = harness
        .finish_as(transfer_id, &bytes, Some(&claim))
        .expect_err("answers a copy of that action from the record");
    assert_eq!(afterwards.code(), refusal.code());
    assert_eq!(afterwards.to_string(), refusal.to_string());
}

/// KR-REQ-14.12, KR-REQ-24.09: two concurrent copies of one finish action on a publication that
/// cannot be resolved are refused identically, whichever of them invalidates it.
///
/// Which copy settles the action, and whether the other reaches the record or the state first, is
/// the machine's to decide. That they agree is not.
#[test]
fn two_concurrent_copies_of_one_finish_action_are_refused_the_same_way() {
    // Repeated, because the interleaving is what this is about: one copy can settle the action
    // between the other reading the record and answering from the state it then finds.
    for _ in 0..6 {
        let harness = Harness::create();
        let bytes = pattern(64);
        let claim = action(&harness, "upload.finish", &bytes);
        let (transfer_id, staged) =
            interrupted_publication(&harness, &bytes, "notes.bin", Some(&claim));
        rewrite_in_place(&staged, bytes.len());

        let refusals: Vec<_> = std::thread::scope(|threads| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let harness = &harness;
                    let claim = &claim;
                    let bytes = bytes.as_slice();
                    threads.spawn(move || harness.finish_as(transfer_id, bytes, Some(claim)))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("the thread did not panic"))
                .collect()
        });

        for refusal in &refusals {
            let refusal = refusal
                .as_ref()
                .expect_err("neither copy publishes bytes that were never verified");
            assert_eq!(refusal.code(), ErrorCode::AttachmentIntegrity);
            assert_eq!(
                refusal.to_string(),
                refusals[0]
                    .as_ref()
                    .expect_err("the first copy was refused too")
                    .to_string(),
                "both copies of one action were told the same thing"
            );
        }
        assert_eq!(
            std::fs::read_dir(harness.service.staging().complete().display_path())
                .expect("reads the completed area")
                .count(),
            0,
            "and nothing reached the completed area"
        );
    }
}

/// KR-REQ-24.09: an interrupted publication that cannot be resolved does not stop the recovery
/// pass, so the rows behind it are resolved rather than waiting for a start that never gets past
/// this one.
#[test]
fn a_publication_behind_an_invalidated_one_is_still_resolved() {
    let harness = Harness::create();
    let rewritten_bytes = pattern(64);
    let intact_bytes = pattern(128);
    let (rewritten, rewritten_path) =
        interrupted_publication(&harness, &rewritten_bytes, "rewritten.bin", None);
    // Reserved a millisecond later, so the pass reaches it after the one it must not stop on:
    // pending publications are resolved in the order they were created.
    harness.clock.advance(1);
    let (intact, _) = interrupted_publication(&harness, &intact_bytes, "intact.bin", None);

    rewrite_in_place(&rewritten_path, rewritten_bytes.len());

    let recovery = harness.service.recover().expect("recovers");
    assert_eq!(
        recovery.completed_publications, 1,
        "the intact publication completed in the same pass"
    );
    assert_eq!(recovery.unresolved_publications, 1);
    assert_eq!(
        harness
            .service
            .attachment_handle(&harness.actor, intact)
            .expect("the intact publication has a handle")
            .content_digest,
        digest(&intact_bytes)
    );
    assert!(
        harness
            .service
            .upload_status(
                &harness.actor,
                &UploadStatusParams {
                    transfer_id: rewritten
                },
            )
            .expect("reads the invalidated row's status")
            .handle
            .as_ref()
            .is_none(),
        "and the one that could not be resolved has no handle"
    );
    assert_eq!(
        harness.service.staged_byte_len().expect("reads the total"),
        intact_bytes.len() as u64,
        "only the published attachment's bytes stay charged"
    );
    // The second pass has nothing to resolve: one row is published and the other is terminal.
    assert_eq!(
        harness.service.recover().expect("recovers again"),
        kr_transfer::Recovery::default()
    );
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
                None,
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

/// Stages one chunk and records the publication's intent, which is what an interrupted publish
/// leaves behind: a durable verification carrying the identity of the object it was made against,
/// and the payload still under its incomplete name. `claimed_by` records the claim a publication
/// made under an action carries, the way `upload.finish` does.
///
/// Returns the transfer and the path of its payload.
fn interrupted_publication(
    harness: &Harness,
    bytes: &[u8],
    original_file_name: &str,
    claimed_by: Option<&kr_transfer::service::Action>,
) -> (TransferId, std::path::PathBuf) {
    let begun = harness
        .begin(bytes, "application/octet-stream", original_file_name)
        .expect("reserves the upload");
    harness
        .send(begun.transfer_id, bytes, 0)
        .expect("sends the chunk");
    let (staged, _) = payload_paths(harness, begun.transfer_id, original_file_name);
    interrupt_publish(
        &harness.host,
        begun.transfer_id,
        digest(bytes),
        identity_of(&staged),
        claimed_by,
    );
    (begun.transfer_id, staged)
}

/// The two paths one transfer's payload can be under: its incomplete name and its published name.
///
/// Derived rather than listed, so a test with more than one staged payload knows which is which.
fn payload_paths(
    harness: &Harness,
    transfer_id: TransferId,
    original_file_name: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let storage = kr_transfer::StorageName::derive(transfer_id, original_file_name);
    (
        harness.service.staging().incomplete().display_path().join(
            storage
                .incomplete()
                .expect("the payload's staged name")
                .as_str(),
        ),
        harness.service.staging().complete().display_path().join(
            storage
                .published()
                .expect("the payload's published name")
                .as_str(),
        ),
    )
}

/// Overwrites every byte of a file where it lies, which no filesystem can answer for with a new
/// identity: the device and the file number are the ones the object already had.
fn rewrite_in_place(path: &std::path::Path, byte_len: usize) {
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("opens the payload where it lies");
    file.write_all(&vec![0xA5_u8; byte_len])
        .expect("overwrites every byte of it");
    file.sync_all().expect("flushes the overwrite");
}

/// Asserts everything an invalidated publication leaves behind, whichever way it was invalidated.
///
/// The outcomes are the same on every filesystem: the pass resolved this row and published nothing,
/// the row is invalidated with its reason recorded, no handle names it, neither staging area holds
/// a payload, its bytes are released, and a second pass finds nothing left to do.
fn assert_publication_invalidated(
    harness: &Harness,
    transfer_id: TransferId,
    recovery: kr_transfer::Recovery,
) {
    assert_eq!(recovery.completed_publications, 0, "nothing was published");
    assert_eq!(recovery.unresolved_publications, 1);
    assert_eq!(
        (
            recovery.removed_payloads,
            recovery.unremovable_payloads,
            recovery.orphans_removed
        ),
        (0, 0, 0),
        "the invalidation discarded the payload itself, leaving nothing for the cleanup retry"
    );
    let status = harness
        .service
        .upload_status(&harness.actor, &UploadStatusParams { transfer_id })
        .expect("reads the status");
    assert_eq!(status.state, UploadState::Invalidated);
    assert!(status.handle.as_ref().is_none(), "no handle names it");
    assert!(
        status
            .invalid_reason
            .as_ref()
            .is_some_and(|reason| reason.contains("verified")),
        "the row says the payload is not what was verified, and it said {:?}",
        status.invalid_reason.as_ref()
    );
    for area in [
        harness.service.staging().incomplete().display_path(),
        harness.service.staging().complete().display_path(),
    ] {
        assert_eq!(
            std::fs::read_dir(area)
                .expect("reads a staging area")
                .count(),
            0,
            "neither name holds a payload afterwards"
        );
    }
    assert_eq!(
        harness.service.staged_byte_len().expect("reads the total"),
        0,
        "and its bytes are released"
    );
    assert_eq!(
        harness.service.recover().expect("recovers again"),
        kr_transfer::Recovery::default(),
        "a second pass changes nothing"
    );
}

/// Records an interrupted publication in the journal, exactly as the service would have.
fn interrupt_publish(
    host: &kr_ipc::testing::TempHost,
    transfer_id: TransferId,
    digest: Digest256,
    payload_identity: kr_transfer::ObjectIdentity,
    claimed_by: Option<&kr_transfer::service::Action>,
) {
    let recorded_at_ms = kr_protocol::scalars::TimestampMs::new(support::START_MS + 1);
    // The claim a publication commits with its intent: the transfer it acts on and no result,
    // because the handle does not exist until the second commit fills it in.
    let claim = claimed_by.map(|action| kr_transfer::store::RetainedAction {
        actor_id: action.actor_id.clone(),
        action_id: action.action_id,
        method: action.method.clone(),
        payload_digest: action.payload_digest,
        subject: Some(transfer_id),
        result: None,
        recorded_at_ms,
    });
    let mut store = kr_transfer::Store::open(
        kr_transfer::StagingArea::store_path(&host.environment()),
        host.environment_id(),
    )
    .expect("opens the journal");
    store
        .begin_publish(
            transfer_id,
            &kr_transfer::store::Publication {
                content_digest: digest,
                payload_identity,
                preview: None,
                preview_unavailable: None,
            },
            recorded_at_ms,
            claim.as_ref(),
        )
        .expect("records the verification");
}

/// Returns a file's stable filesystem identity.
///
/// Read the way the service reads it: through an opened directory, which is the only form Windows
/// answers a file identity for.
fn identity_of(path: &std::path::Path) -> kr_transfer::ObjectIdentity {
    use cap_fs_ext::MetadataExt as _;

    let parent = path.parent().expect("the payload has a parent");
    let name = path.file_name().expect("the payload has a name");
    let directory = cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())
        .expect("opens the directory the payload is in");
    let metadata = directory.metadata(name).expect("the file exists");
    kr_transfer::ObjectIdentity {
        device: metadata.dev(),
        file_id: metadata.ino(),
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

/// KR-REQ-14.11: an expiry sweep that runs while a publication is unresolved closes exactly one of
/// them, and whichever wins leaves no bytes charged and no payload behind.
#[test]
fn a_sweep_during_an_unresolved_publication_leaves_no_charged_bytes() {
    let host = kr_ipc::testing::TempHost::create();
    let bytes = pattern(1024);
    let actor = kr_protocol::ids::ActorId::new("local:transfer-test").expect("a valid principal");
    let expected = digest(&bytes);
    let transfer_id: TransferId;
    let payload_identity: kr_transfer::ObjectIdentity;
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
                None,
            )
            .expect("accepts the chunk");
        let staged = std::fs::read_dir(service.staging().incomplete().display_path())
            .expect("reads the incomplete area")
            .next()
            .expect("one staged payload")
            .expect("a directory entry")
            .path();
        payload_identity = identity_of(&staged);
    }
    // The publish is durable and unresolved, and the clock then passes the twenty-four-hour
    // window, so the sweep and the publication both have a claim on this row.
    interrupt_publish(&host, transfer_id, expected, payload_identity, None);
    let clock = Arc::new(ManualClock::new(
        support::START_MS + kr_protocol::transfer::UNFINISHED_UPLOAD_LIFETIME.get() + 1,
    ));
    let service = TransferService::with_clock(&host.environment(), Arc::clone(&clock) as Arc<_>)
        .expect("a replacement service");

    let sweep = service
        .sweep(&RetainEverything)
        .expect("the sweep runs against a publishing row");
    let recovery = service.recover().expect("recovery runs after it");

    let status = service
        .upload_status(&actor, &UploadStatusParams { transfer_id })
        .expect("reads the status");
    assert!(
        matches!(status.state, UploadState::Published | UploadState::Expired),
        "the row is closed one way or the other, and was {:?}",
        status.state
    );
    assert_eq!(
        sweep.expired_uploads + recovery.completed_publications,
        1,
        "exactly one of the two closed it"
    );
    if status.state == UploadState::Expired {
        assert_eq!(
            service.staged_byte_len().expect("reads the total"),
            0,
            "an expired upload charges nothing"
        );
        assert_eq!(
            std::fs::read_dir(service.staging().incomplete().display_path())
                .expect("reads the incomplete area")
                .count()
                + std::fs::read_dir(service.staging().complete().display_path())
                    .expect("reads the completed area")
                    .count(),
            0,
            "and leaves no payload behind"
        );
    } else {
        assert_eq!(
            service
                .attachment_handle(&actor, transfer_id)
                .expect("a published attachment has a handle")
                .content_digest,
            expected
        );
    }
}

/// KR-REQ-14.11: a cancellation that arrives on a transfer whose publish is already durable
/// releases the reservation and removes the payload under both of its names.
#[test]
fn a_cancellation_during_a_publication_releases_the_payload_and_the_bytes() {
    let host = kr_ipc::testing::TempHost::create();
    let bytes = pattern(2048);
    let actor = kr_protocol::ids::ActorId::new("local:transfer-test").expect("a valid principal");
    let expected = digest(&bytes);
    let transfer_id: TransferId;
    let payload_identity: kr_transfer::ObjectIdentity;
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
                None,
            )
            .expect("accepts the chunk");
        let staged = std::fs::read_dir(service.staging().incomplete().display_path())
            .expect("reads the incomplete area")
            .next()
            .expect("one staged payload")
            .expect("a directory entry")
            .path();
        payload_identity = identity_of(&staged);
    }
    interrupt_publish(&host, transfer_id, expected, payload_identity, None);
    let clock = Arc::new(ManualClock::new(support::START_MS + 10));
    let service = TransferService::with_clock(&host.environment(), clock as Arc<_>)
        .expect("a replacement service");

    let cancelled = service
        .upload_cancel(&actor, &UploadCancelParams { transfer_id }, None)
        .expect("cancels the publishing transfer");

    assert_eq!(cancelled.state, UploadState::Cancelled);
    assert_eq!(cancelled.released_byte_len, U64::new(bytes.len() as u64));
    assert_eq!(
        service.staged_byte_len().expect("reads the total"),
        0,
        "a cancellation releases the bytes it charged"
    );
    for area in [
        service.staging().incomplete().display_path(),
        service.staging().complete().display_path(),
    ] {
        assert_eq!(
            std::fs::read_dir(area)
                .expect("reads a staging area")
                .count(),
            0,
            "neither name holds a payload afterwards"
        );
    }
    // And the recovery that follows finds nothing to resolve, because the row is closed.
    assert_eq!(
        service.recover().expect("recovers"),
        kr_transfer::Recovery::default()
    );
}

/// KR-REQ-14.08: two threads that reserve at the environment's ceiling admit exactly one of them,
/// and the ceiling is never exceeded.
#[test]
fn two_threads_that_reserve_at_the_ceiling_admit_exactly_one() {
    let harness = Harness::create();
    let bytes = pattern(4096);
    // Room for exactly one of the two reservations.
    harness.set_limits(Limits {
        max_file_len: 4096,
        max_staged_len: 4096,
        max_concurrent_transfers: 8,
    });

    let outcomes: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    harness
                        .begin(&bytes, "application/octet-stream", "notes.bin")
                        .map(|begun| begun.transfer_id)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("the thread did not panic"))
            .collect()
    });

    let admitted: Vec<_> = outcomes
        .iter()
        .filter_map(|outcome| outcome.as_ref().ok())
        .collect();
    let refused: Vec<_> = outcomes
        .iter()
        .filter_map(|outcome| outcome.as_ref().err())
        .collect();
    assert_eq!(admitted.len(), 1, "exactly one reservation is admitted");
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].code(), ErrorCode::QuotaExceeded);
    assert_eq!(
        harness.service.staged_byte_len().expect("reads the total"),
        4096,
        "the charged total is the one reservation, not both"
    );
}

/// KR-REQ-24.09: a published payload replaced underneath the host is never served to a download.
#[test]
fn a_replaced_payload_is_never_served_to_a_download() {
    let harness = Harness::create();
    let bytes = pattern(4096);
    let handle = harness.publish(&bytes, "application/octet-stream", "notes.bin");
    let published = std::fs::read_dir(harness.service.staging().complete().display_path())
        .expect("reads the completed area")
        .next()
        .expect("one published payload")
        .expect("a directory entry")
        .path();

    // A different object of the same length takes the same name, which is what an interfering
    // process that ran as this user could do.
    let replacement = published.with_extension("replacement");
    std::fs::write(&replacement, pattern(4096)).expect("writes the replacement");
    std::fs::rename(&replacement, &published).expect("replaces the payload");

    let refusal = harness
        .service
        .download_begin(
            &harness.actor,
            &kr_protocol::transfer::DownloadBeginParams {
                environment_id: harness.environment_id(),
                resume_transfer_id: Nullable::null(),
                source: Nullable::some(kr_protocol::transfer::DownloadSource::Attachment {
                    transfer_id: handle.transfer_id,
                }),
                device_id: Nullable::null(),
            },
        )
        .expect_err("refuses to serve a replaced payload");
    assert!(
        matches!(
            refusal.code(),
            ErrorCode::SourceChanged | ErrorCode::AttachmentIntegrity | ErrorCode::PermissionDenied
        ),
        "the refusal names the change rather than serving the bytes: {refusal}"
    );
}

/// KR-REQ-14.11, KR-REQ-23.41: an attachment uploaded without a session takes the session of the
/// draft it is bound to, and a draft for another session cannot then take it.
#[test]
fn an_attachment_bound_to_a_session_draft_becomes_that_sessions() {
    let harness = Harness::create();
    let bytes = pattern(256);
    let handle = harness.publish(&bytes, "application/octet-stream", "notes.bin");
    assert_eq!(
        handle.session_id,
        Nullable::null(),
        "it was uploaded without one"
    );
    let first = SessionId::new(Uuid::from_bytes([21; 16]));
    let second = SessionId::new(Uuid::from_bytes([22; 16]));
    let draft = harness
        .service
        .draft_create(
            &harness.actor,
            &kr_protocol::transfer::DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::some(first),
                application_instance_id: Nullable::null(),
                text: "for the first session".to_owned(),
            },
            None,
        )
        .expect("creates the first draft")
        .draft;

    harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &kr_protocol::transfer::AgentDraftAddAttachmentParams {
                draft_id: draft.draft_id,
                transfer_id: handle.transfer_id,
                expected_revision: draft.revision,
                contribution: contribution(&handle),
            },
            None,
        )
        .expect("binds the attachment to the first session's draft");

    // The attachment now belongs to that session, which is what its retention will follow.
    assert_eq!(
        harness
            .service
            .attachment_handle(&harness.actor, handle.transfer_id)
            .expect("reads the handle")
            .session_id,
        Nullable::some(first)
    );

    // A draft for another session cannot take it.
    let elsewhere = harness
        .service
        .draft_create(
            &harness.actor,
            &kr_protocol::transfer::DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::some(second),
                application_instance_id: Nullable::null(),
                text: "for the second session".to_owned(),
            },
            None,
        )
        .expect("creates the second draft")
        .draft;
    let refusal = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &kr_protocol::transfer::AgentDraftAddAttachmentParams {
                draft_id: elsewhere.draft_id,
                transfer_id: handle.transfer_id,
                expected_revision: elsewhere.revision,
                contribution: contribution(&handle),
            },
            None,
        )
        .expect_err("the attachment is already another session's");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
}

/// KR-REQ-23.41: a draft whose reply would not fit the frame that carries it is refused, and the
/// draft is left as it was.
#[test]
fn a_draft_too_large_to_send_is_refused_before_it_is_written() {
    let harness = Harness::create();
    let draft = harness
        .service
        .draft_create(
            &harness.actor,
            &kr_protocol::transfer::DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::null(),
                application_instance_id: Nullable::null(),
                text: "short enough".to_owned(),
            },
            None,
        )
        .expect("creates the draft")
        .draft;

    let refusal = harness
        .service
        .draft_update(
            &harness.actor,
            &kr_protocol::transfer::DraftUpdateParams {
                draft_id: draft.draft_id,
                expected_revision: draft.revision,
                text: "x".repeat(
                    usize::try_from(kr_protocol::transfer::MAX_TRANSFER_RESULT_BYTES).unwrap_or(0)
                        + 1,
                ),
            },
            None,
        )
        .expect_err("a reply that large cannot be sent");

    assert_eq!(refusal.code(), ErrorCode::QuotaExceeded);
    let unchanged = harness
        .service
        .draft(&harness.actor, draft.draft_id)
        .expect("reads the draft");
    assert_eq!(unchanged.revision, draft.revision);
    assert_eq!(unchanged.text, "short enough");
}

/// Builds the action two concurrent copies of one request share.
fn action(harness: &Harness, method: &str, payload: &[u8]) -> kr_transfer::service::Action {
    kr_transfer::service::Action {
        actor_id: harness.actor.clone(),
        action_id: kr_ipc::new_uuid(),
        method: method.to_owned(),
        payload_digest: digest(payload),
    }
}

/// KR-REQ-14.07, KR-REQ-24.09: two concurrent copies of one `upload.chunk` are arbitrated where
/// the chunk is written, so they answer the same and only one row is written.
#[test]
fn two_concurrent_copies_of_one_chunk_action_answer_the_same() {
    let harness = Harness::create();
    let bytes = pattern(4096);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    let action = action(&harness, "upload.chunk", &bytes);

    let outcomes: Vec<_> = std::thread::scope(|threads| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let harness = &harness;
                let action = &action;
                let bytes = bytes.as_slice();
                threads.spawn(move || harness.send_as(begun.transfer_id, bytes, 0, Some(action)))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("the thread did not panic"))
            .collect()
    });

    let answers: Vec<_> = outcomes
        .into_iter()
        .map(|outcome| outcome.expect("both copies of one action are answered"))
        .collect();
    assert_eq!(
        answers[0], answers[1],
        "one action, one answer: {answers:?}"
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
        status.received_byte_len,
        U64::new(bytes.len() as u64),
        "the bytes are counted once"
    );
    let bitmap = ChunkBitmap::decode(&status.received_chunks, status.layout.chunk_count.get())
        .expect("a bitmap for this layout");
    assert!(bitmap.is_complete());
}

/// KR-REQ-14.07, KR-REQ-24.09: two concurrent copies of one `upload.finish` publish one file and
/// name the same handle.
#[test]
fn two_concurrent_copies_of_one_finish_action_publish_once() {
    let harness = Harness::create();
    let bytes = pattern(4096);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends every chunk");
    let action = action(&harness, "upload.finish", &bytes);

    let outcomes: Vec<_> = std::thread::scope(|threads| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let harness = &harness;
                let action = &action;
                let bytes = bytes.as_slice();
                threads.spawn(move || harness.finish_as(begun.transfer_id, bytes, Some(action)))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("the thread did not panic"))
            .collect()
    });

    // A publication is two commits and the claim belongs to the first, so a copy that arrives
    // between them is owed `OUTCOME_UNKNOWN` rather than a guess. What must never happen is two
    // different answers, or two published files.
    let mut answers = Vec::new();
    for outcome in outcomes {
        match outcome {
            Ok(answer) => answers.push(answer),
            Err(error) => assert_eq!(
                error.code(),
                ErrorCode::OutcomeUnknown,
                "a copy that lost the claim is told the outcome is not recorded yet, not {error}"
            ),
        }
    }
    assert!(!answers.is_empty(), "one copy of the action published it");
    for answer in &answers {
        assert_eq!(
            answer, &answers[0],
            "every copy that was answered got the same answer"
        );
    }
    assert_eq!(answers[0].handle.content_digest, digest(&bytes));

    // And the action is settled: a repeat now is answered from the record, with the same result.
    let repeated = harness
        .finish_as(begun.transfer_id, &bytes, Some(&action))
        .expect("the repeat is answered");
    assert_eq!(repeated, answers[0], "one action, one answer");
    assert_eq!(
        std::fs::read_dir(harness.service.staging().complete().display_path())
            .expect("reads the completed area")
            .count(),
        1,
        "one action published one file"
    );
    assert_eq!(
        std::fs::read_dir(harness.service.staging().incomplete().display_path())
            .expect("reads the incomplete area")
            .count(),
        0
    );
}

/// KR-REQ-14.07, KR-REQ-24.09: two concurrent copies of one `upload.cancel` release the
/// reservation once and report the same released length.
#[test]
fn two_concurrent_copies_of_one_cancel_action_release_once() {
    let harness = Harness::create();
    let bytes = pattern(8192);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "notes.bin")
        .expect("reserves the upload");
    harness
        .send(begun.transfer_id, &bytes, 0)
        .expect("sends a chunk");
    let action = action(&harness, "upload.cancel", &bytes);

    let outcomes: Vec<_> = std::thread::scope(|threads| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let harness = &harness;
                let action = &action;
                threads.spawn(move || harness.cancel_as(begun.transfer_id, Some(action)))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("the thread did not panic"))
            .collect()
    });

    // A cancellation closes the row and then removes the payload, and its result is recorded only
    // once the bytes are actually released. A copy that arrives in between is owed
    // `OUTCOME_UNKNOWN`.
    let mut answers = Vec::new();
    for outcome in outcomes {
        match outcome {
            Ok(answer) => answers.push(answer),
            Err(error) => assert_eq!(
                error.code(),
                ErrorCode::OutcomeUnknown,
                "a copy that lost the claim is told the outcome is not recorded yet, not {error}"
            ),
        }
    }
    assert!(!answers.is_empty(), "one copy of the action cancelled it");
    for answer in &answers {
        assert_eq!(answer, &answers[0], "one action, one answer");
    }
    assert_eq!(
        answers[0].released_byte_len,
        U64::new(bytes.len() as u64),
        "the reservation is reported released once, not twice"
    );
    let repeated = harness
        .cancel_as(begun.transfer_id, Some(&action))
        .expect("the repeat is answered");
    assert_eq!(repeated, answers[0], "and the repeat is answered the same");
    assert_eq!(
        harness.service.staged_byte_len().expect("reads the total"),
        0,
        "and the bytes are released exactly once"
    );
    assert_eq!(
        std::fs::read_dir(harness.service.staging().incomplete().display_path())
            .expect("reads the incomplete area")
            .count(),
        0
    );
}

/// KR-REQ-24.09: a publication another copy of this action began is finished, not refused.
///
/// One copy reads a row that still takes chunks; another claims it and moves it to publishing
/// before the first reaches the lock. The first is owed the attachment, and was refused as
/// unavailable until the state it now finds is the one it answers from.
#[test]
fn upload_finish_transition_to_publishing_before_lock_resolves_and_succeeds() {
    let harness = Harness::create();
    let bytes = pattern(256);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "race_publishing.bin")
        .expect("reserves upload");
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends chunks");
    let transfer_id = begun.transfer_id;

    let (staged_path, _) = payload_paths(&harness, transfer_id, "race_publishing.bin");
    let bytes_copy = bytes.clone();
    harness.service.set_finish_race_hook(move |store, tid| {
        if tid == transfer_id {
            let staged_id = identity_of(&staged_path);
            store
                .begin_publish(
                    tid,
                    &kr_transfer::store::Publication {
                        content_digest: digest(&bytes_copy),
                        payload_identity: staged_id,
                        preview: None,
                        preview_unavailable: None,
                    },
                    kr_protocol::scalars::TimestampMs::new(support::START_MS + 1),
                    None,
                )
                .expect("records intent to publish");
        }
    });

    // upload_finish starts while state is Incomplete, initial check sees Incomplete, then hook
    // moves it to Publishing before the lock. It must resolve and succeed, not fail as unavailable.
    let result = harness
        .finish_as(transfer_id, &bytes, None)
        .expect("upload_finish on Publishing transition resolves and succeeds");
    assert_eq!(result.handle.content_digest, digest(&bytes));

    let status = harness
        .service
        .upload_status(&harness.actor, &UploadStatusParams { transfer_id })
        .expect("reads status");
    assert_eq!(status.state, UploadState::Published);
    harness.service.clear_finish_race_hook();
}

/// KR-REQ-24.09: an attachment another copy of this action published is answered with its handle.
///
/// The same interleaving one step further on: the other copy has finished publishing by the time
/// this one reaches the lock, and what is there is the attachment rather than a refusal.
#[test]
fn upload_finish_transition_to_published_before_lock_returns_handle() {
    let harness = Harness::create();
    let bytes = pattern(256);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "race_published.bin")
        .expect("reserves upload");
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends chunks");
    let transfer_id = begun.transfer_id;

    let (staged_path, published_path) = payload_paths(&harness, transfer_id, "race_published.bin");
    let bytes_copy = bytes.clone();
    harness.service.set_finish_race_hook(move |store, tid| {
        if tid == transfer_id {
            std::fs::rename(&staged_path, &published_path).expect("moves to complete");
            let published_id = identity_of(&published_path);
            store
                .begin_publish(
                    tid,
                    &kr_transfer::store::Publication {
                        content_digest: digest(&bytes_copy),
                        payload_identity: published_id,
                        preview: None,
                        preview_unavailable: None,
                    },
                    kr_protocol::scalars::TimestampMs::new(support::START_MS + 1),
                    None,
                )
                .expect("records begin publish");
            store
                .complete_publish(
                    tid,
                    kr_protocol::scalars::TimestampMs::new(support::START_MS + 10),
                    kr_protocol::scalars::TimestampMs::new(support::START_MS + 100_000),
                )
                .expect("records complete publish");
        }
    });

    // upload_finish starts while state is Incomplete, initial check sees Incomplete, then hook
    // publishes the upload before the lock. It must return already_published: true, not fail as unavailable.
    let result = harness
        .finish_as(transfer_id, &bytes, None)
        .expect("second finish on Published upload succeeds");
    assert!(result.already_published);
    assert_eq!(result.handle.content_digest, digest(&bytes));
    harness.service.clear_finish_race_hook();
}

/// KR-REQ-24.09: a publication that began while this copy was reading the file is finished.
///
/// Verifying a file takes long enough for another copy to claim the publication, and the state
/// this copy finds when it comes back is the one it answers from.
#[test]
fn upload_finish_transition_to_publishing_after_verification_resolves() {
    let harness = Harness::create();
    let bytes = pattern(256);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "race_post_verify.bin")
        .expect("reserves upload");
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends chunks");
    let transfer_id = begun.transfer_id;

    let (staged_path, _) = payload_paths(&harness, transfer_id, "race_post_verify.bin");
    let bytes_copy = bytes.clone();
    harness
        .service
        .set_post_verification_race_hook(move |store, tid| {
            if tid == transfer_id {
                let staged_id = identity_of(&staged_path);
                store
                    .begin_publish(
                        tid,
                        &kr_transfer::store::Publication {
                            content_digest: digest(&bytes_copy),
                            payload_identity: staged_id,
                            preview: None,
                            preview_unavailable: None,
                        },
                        kr_protocol::scalars::TimestampMs::new(support::START_MS + 1),
                        None,
                    )
                    .expect("records intent to publish");
            }
        });

    // upload_finish verifies file, but before taking lock another caller moved state to Publishing.
    // It must resolve and succeed, not fail with WrongState / ResourceUnavailable.
    let result = harness
        .finish_as(transfer_id, &bytes, None)
        .expect("upload_finish on post-verification Publishing resolves and succeeds");
    assert_eq!(result.handle.content_digest, digest(&bytes));

    let status = harness
        .service
        .upload_status(&harness.actor, &UploadStatusParams { transfer_id })
        .expect("reads status");
    assert_eq!(status.state, UploadState::Published);
    harness.service.clear_post_verification_race_hook();
}

/// KR-REQ-24.09: an expiry is answered as an expiry, whichever path settles it.
///
/// An upload that ran out of time is not an upload whose bytes were tampered with, and the claim
/// recovery settles is owed the same code the live check and the refusal give it.
#[test]
fn an_expired_upload_claim_settled_by_recovery_unifies_as_resource_unavailable() {
    let harness = Harness::create();
    let bytes = pattern(64);
    let claim = action(&harness, "upload.finish", &bytes);
    let (transfer_id, _) =
        interrupted_publication(&harness, &bytes, "expired_claim.bin", Some(&claim));

    // Close the upload as Expired directly in the store, simulating expiry with claim still open.
    {
        let mut store = kr_transfer::Store::open(
            kr_transfer::StagingArea::store_path(&harness.host.environment()),
            harness.host.environment_id(),
        )
        .expect("opens store");
        store
            .close_upload(
                transfer_id,
                UploadState::Expired,
                Some("upload expired before finish completed"),
                kr_protocol::scalars::TimestampMs::new(support::START_MS + 5),
                None,
            )
            .expect("closes upload as expired");
    }

    // Run recovery which calls resolve_claims() to settle the open claim.
    let recovery = harness.service.recover().expect("recovery runs");
    assert_eq!(
        recovery.resolved_claims, 1,
        "the expired upload's claim was settled by recovery"
    );

    // Reading the settled claim via finish_as must return ErrorCode::ResourceUnavailable,
    // unifying with check_live and publication_refusal.
    let refusal = harness
        .finish_as(transfer_id, &bytes, Some(&claim))
        .expect_err("reading the settled expired claim returns refusal");
    assert_eq!(
        refusal.code(),
        ErrorCode::ResourceUnavailable,
        "expired claim settlement unifies to ResourceUnavailable"
    );
}

/// KR-REQ-24.09: a copy of one action that finds the payload gone is answered by the row, not by
/// the open that failed.
///
/// This is the interleaving the two above leave open. One copy of `upload.finish` reads a row that
/// still takes chunks and goes on to verify the staged file; another copy claims the publication
/// and renames the payload to its published name in the window before that read. The first copy's
/// open then fails, and its claim carries no answer yet, because the copy that made it has not
/// recorded one. The row says the attachment was published, and that is what this copy is owed:
/// answering with the open's failure would refuse a publication that succeeded.
#[test]
fn a_copy_of_one_finish_action_that_finds_the_payload_gone_is_answered_by_the_row() {
    let harness = Harness::create();
    let bytes = pattern(256);
    let begun = harness
        .begin(&bytes, "application/octet-stream", "claimed_race.bin")
        .expect("reserves upload");
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends chunks");
    let transfer_id = begun.transfer_id;
    let claim = action(&harness, "upload.finish", &bytes);

    let (staged_path, published_path) = payload_paths(&harness, transfer_id, "claimed_race.bin");
    let bytes_copy = bytes.clone();
    // The claim a publication commits with its intent: the transfer it acts on and no result,
    // because the handle does not exist until the second commit fills it in.
    let claim_copy = kr_transfer::store::RetainedAction {
        actor_id: claim.actor_id.clone(),
        action_id: claim.action_id,
        method: claim.method.clone(),
        payload_digest: claim.payload_digest,
        subject: Some(transfer_id),
        result: None,
        recorded_at_ms: kr_protocol::scalars::TimestampMs::new(support::START_MS + 1),
    };
    harness
        .service
        .set_staged_open_race_hook(move |store, tid| {
            if tid == transfer_id {
                // What the other copy of this action does: it publishes the payload under the claim
                // the two share, and it has not recorded the result yet.
                std::fs::rename(&staged_path, &published_path).expect("moves to complete");
                store
                    .begin_publish(
                        tid,
                        &kr_transfer::store::Publication {
                            content_digest: digest(&bytes_copy),
                            payload_identity: identity_of(&published_path),
                            preview: None,
                            preview_unavailable: None,
                        },
                        kr_protocol::scalars::TimestampMs::new(support::START_MS + 1),
                        Some(&claim_copy),
                    )
                    .expect("records intent to publish");
                store
                    .complete_publish(
                        tid,
                        kr_protocol::scalars::TimestampMs::new(support::START_MS + 10),
                        kr_protocol::scalars::TimestampMs::new(support::START_MS + 100_000),
                    )
                    .expect("records the publication");
            }
        });

    let result = harness
        .finish_as(transfer_id, &bytes, Some(&claim))
        .expect("the copy whose open failed is answered with the attachment");
    harness.service.clear_staged_open_race_hook();
    assert_eq!(result.handle.content_digest, digest(&bytes));
    assert!(
        !result.already_published,
        "the claim is this action's, so this action published the attachment"
    );

    let status = harness
        .service
        .upload_status(&harness.actor, &UploadStatusParams { transfer_id })
        .expect("reads status");
    assert_eq!(status.state, UploadState::Published);

    // The claim now carries the answer, so a repeat of the action reads it rather than publishing
    // a second time.
    let repeat = harness
        .finish_as(transfer_id, &bytes, Some(&claim))
        .expect("the repeat reads the recorded answer");
    assert_eq!(repeat.handle.content_digest, result.handle.content_digest);
}
