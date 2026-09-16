//! KR-ACC-019: partial uploads, quota failure, environment boundaries, symbolic links and
//! reparse points, and concurrent file changes, in one run.
//!
//! One test, five conditions, in the order a reviewer reads them from the acceptance table. Each
//! step asserts both what the host refused and what it kept: a refusal that lost the user's work
//! would satisfy the letter of the row and none of its point.

mod support;

use kr_protocol::error::ErrorCode;
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::transfer::{
    ChunkBitmap, DownloadBeginParams, DownloadChunkParams, DownloadSource, UploadState,
    UploadStatusParams,
};
use kr_transfer::store::Limits;
use support::{Harness, digest, pattern};

#[test]
fn partial_uploads_quotas_environments_links_and_concurrent_changes() {
    let harness = Harness::create();

    // ---- 1. A partial upload -------------------------------------------------------------
    //
    // Two chunks are declared and one arrives. The host says what is missing, refuses to publish,
    // and keeps everything already verified.
    let bytes = pattern(kr_protocol::limits::UPLOAD_CHUNK_LEN + 2048);
    let partial = harness
        .begin(&bytes, "application/octet-stream", "half-sent.bin")
        .expect("reserves the upload");
    harness
        .send(partial.transfer_id, &bytes, 0)
        .expect("sends the first chunk");
    let refusal = harness
        .finish(partial.transfer_id, &bytes)
        .expect_err("refuses to publish a partial upload");
    assert_eq!(refusal.code(), ErrorCode::ResourceUnavailable);
    let status = harness
        .service
        .upload_status(
            &harness.actor,
            &UploadStatusParams {
                transfer_id: partial.transfer_id,
            },
        )
        .expect("reads the status");
    assert_eq!(status.state, UploadState::Receiving);
    let bitmap = ChunkBitmap::decode(&status.received_chunks, status.layout.chunk_count.get())
        .expect("a bitmap for this layout");
    assert_eq!(
        bitmap.missing(),
        vec![1],
        "status names what is still needed"
    );
    assert_eq!(
        status.received_byte_len,
        U64::new(kr_protocol::limits::UPLOAD_CHUNK_LEN as u64),
        "the verified chunk is still staged"
    );
    // The missing chunk is sent and the same identifier publishes.
    harness
        .send(partial.transfer_id, &bytes, 1)
        .expect("sends what status asked for");
    let published = harness
        .finish(partial.transfer_id, &bytes)
        .expect("publishes under the same identifier")
        .handle;
    assert_eq!(published.transfer_id, partial.transfer_id);
    assert_eq!(published.content_digest, digest(&bytes));

    // ---- 2. Quota failure ----------------------------------------------------------------
    //
    // The environment's staged ceiling refuses a reservation without touching what is already
    // staged, and a released reservation frees the room again.
    let staged = harness.service.staged_byte_len().expect("reads the total");
    harness.set_limits(Limits {
        max_file_len: 8 * 1024,
        max_staged_len: staged + 4096,
        max_concurrent_transfers: 8,
    });
    let fits = harness
        .begin(&pattern(4096), "application/octet-stream", "fits.bin")
        .expect("reserves what fits");
    let over = harness
        .begin(&pattern(4096), "application/octet-stream", "over.bin")
        .expect_err("refuses what does not");
    assert_eq!(over.code(), ErrorCode::QuotaExceeded);
    assert_eq!(
        over.code().retry_category(),
        kr_protocol::error::RetryCategory::NoRetry,
        "a byte quota is not something to retry into"
    );
    harness
        .service
        .attachment_handle(&harness.actor, published.transfer_id)
        .expect("the published attachment is untouched by the refusal");
    harness
        .service
        .upload_cancel(
            &harness.actor,
            &kr_protocol::transfer::UploadCancelParams {
                transfer_id: fits.transfer_id,
            },
            None,
        )
        .expect("cancels the reservation");
    let freed = harness
        .begin(&pattern(4096), "application/octet-stream", "over.bin")
        .expect("the released room is available again");
    harness
        .service
        .upload_cancel(
            &harness.actor,
            &kr_protocol::transfer::UploadCancelParams {
                transfer_id: freed.transfer_id,
            },
            None,
        )
        .expect("releases it again");
    harness.set_limits(Limits::default());

    // A per-file ceiling above the environment's own is still refused per file.
    harness.set_limits(Limits {
        max_file_len: 1024,
        ..Limits::default()
    });
    let too_large = harness
        .begin(&pattern(2048), "application/octet-stream", "big.bin")
        .expect_err("refuses a file above the per-file ceiling");
    assert_eq!(too_large.code(), ErrorCode::QuotaExceeded);
    harness.set_limits(Limits::default());

    // ---- 3. Environment boundaries -------------------------------------------------------
    //
    // A second environment on the same host has its own store, its own staging area, and no sight
    // of this one's transfers. A Windows path and a WSL path are two of these, never one.
    let elsewhere = Harness::create();
    assert_ne!(elsewhere.environment_id(), harness.environment_id());
    assert_ne!(
        elsewhere.service.staging().complete().identity(),
        harness.service.staging().complete().identity()
    );
    let across = elsewhere
        .service
        .upload_status(
            &elsewhere.actor,
            &UploadStatusParams {
                transfer_id: published.transfer_id,
            },
        )
        .expect_err("a handle from another environment names nothing here");
    assert_eq!(across.code(), ErrorCode::InvalidArgument);
    let wrong_environment = harness
        .service
        .download_begin(
            &harness.actor,
            &DownloadBeginParams {
                environment_id: elsewhere.environment_id(),
                resume_transfer_id: Nullable::null(),
                source: Nullable::some(DownloadSource::Attachment {
                    transfer_id: published.transfer_id,
                }),
                device_id: Nullable::null(),
            },
        )
        .expect_err("refuses a request that names another environment");
    assert_eq!(wrong_environment.code(), ErrorCode::EnvironmentUnavailable);

    // ---- 4. Symbolic links and reparse points --------------------------------------------
    //
    // A read scope resolves through an opened directory handle. A component that is a link is
    // refused rather than followed, and the tree outside the scope is never read.
    let tree = tempfile::tempdir().expect("a temporary directory");
    let outside = tempfile::tempdir().expect("a second temporary directory");
    std::fs::write(outside.path().join("secret.txt"), b"outside the scope")
        .expect("writes the file outside");
    std::fs::write(tree.path().join("notes.txt"), pattern(512)).expect("writes the source");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            tree.path().join("escaping-file"),
        )
        .expect("links out of the scope");
        std::os::unix::fs::symlink(outside.path(), tree.path().join("escaping-directory"))
            .expect("links a directory out of the scope");
    }
    let scope = harness
        .service
        .register_scope("an acceptance tree", tree.path())
        .expect("registers the scope");
    for name in [
        "../secret.txt",
        "/etc/passwd",
        "notes.txt/../../secret.txt",
        "NUL",
        #[cfg(unix)]
        "escaping-file",
        #[cfg(unix)]
        "escaping-directory/secret.txt",
    ] {
        let refusal = harness
            .service
            .download_begin(
                &harness.actor,
                &DownloadBeginParams {
                    environment_id: harness.environment_id(),
                    resume_transfer_id: Nullable::null(),
                    source: Nullable::some(DownloadSource::Scope {
                        scope_id: scope,
                        relative_path: name.to_owned(),
                    }),
                    device_id: Nullable::null(),
                },
            )
            .expect_err("refuses a name that leaves the scope");
        assert_eq!(
            refusal.code(),
            ErrorCode::PermissionDenied,
            "{name} should be a permission refusal"
        );
    }
    assert_eq!(
        std::fs::read_to_string(outside.path().join("secret.txt")).expect("still there"),
        "outside the scope",
        "nothing outside the scope was read or written"
    );
    // The name inside the scope resolves.
    let inside = harness
        .service
        .download_begin(
            &harness.actor,
            &DownloadBeginParams {
                environment_id: harness.environment_id(),
                resume_transfer_id: Nullable::null(),
                source: Nullable::some(DownloadSource::Scope {
                    scope_id: scope,
                    relative_path: "notes.txt".to_owned(),
                }),
                device_id: Nullable::null(),
            },
        )
        .expect("stages the source inside the scope");

    // ---- 5. Concurrent file changes ------------------------------------------------------
    //
    // The source is rewritten while the snapshot exists. The snapshot keeps serving the revision it
    // captured, a new snapshot captures the new revision, and neither mixes with the other.
    let replacement = pattern(768);
    std::fs::write(tree.path().join("notes.txt"), &replacement).expect("rewrites the source");
    let served = harness
        .service
        .download_chunk(
            &harness.actor,
            &DownloadChunkParams {
                transfer_id: inside.transfer_id,
                index: U64::new(0),
            },
        )
        .expect("reads the captured revision");
    assert_eq!(served.bytes.as_slice(), pattern(512).as_slice());
    assert_eq!(served.chunk.digest, digest(&pattern(512)));
    let after = harness
        .service
        .download_begin(
            &harness.actor,
            &DownloadBeginParams {
                environment_id: harness.environment_id(),
                resume_transfer_id: Nullable::null(),
                source: Nullable::some(DownloadSource::Scope {
                    scope_id: scope,
                    relative_path: "notes.txt".to_owned(),
                }),
                device_id: Nullable::null(),
            },
        )
        .expect("stages the new revision");
    assert_ne!(after.transfer_id, inside.transfer_id);
    assert_eq!(after.content_digest, digest(&replacement));
    assert_ne!(after.content_digest, inside.content_digest);

    // Revoking the scope stops further bytes from both of them at once.
    harness
        .service
        .revoke_scope(scope)
        .expect("revokes the scope");
    for transfer in [inside.transfer_id, after.transfer_id] {
        let refusal = harness
            .service
            .download_chunk(
                &harness.actor,
                &DownloadChunkParams {
                    transfer_id: transfer,
                    index: U64::new(0),
                },
            )
            .expect_err("refuses after the revocation");
        assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    }

    // And the completed upload from step one is still exactly what it was.
    let handle = harness
        .service
        .attachment_handle(&harness.actor, published.transfer_id)
        .expect("the attachment survived every refusal");
    assert_eq!(handle.content_digest, digest(&bytes));
    assert_eq!(handle.byte_len, U64::new(bytes.len() as u64));
}
