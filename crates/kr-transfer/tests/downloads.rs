//! Verified downloads: immutable sources, bounded snapshots, resumption and the client's publish.
//!
//! Requirement rows closed here: KR-REQ-14.14, KR-REQ-14.15 and KR-REQ-14.16.

mod support;

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::TransferId;
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::transfer::{
    DOWNLOAD_SNAPSHOT_LIFETIME, DownloadBeginParams, DownloadChunkParams, DownloadImmutability,
    DownloadPlacement, DownloadSource,
};
use kr_transfer::store::Limits;
use kr_transfer::{AuthorisedDirectory, DownloadWriter, RetainEverything};
use support::{Harness, digest, pattern};

fn source_tree() -> tempfile::TempDir {
    tempfile::tempdir().expect("a temporary directory")
}

/// KR-REQ-14.15: a published attachment is already an immutable revision, and is read in place
/// with its transfer identity, size, whole-file digest, chunk layout and expiry.
#[test]
fn a_published_attachment_is_an_immutable_source_read_in_place() {
    let harness = Harness::create();
    let bytes = pattern(4096);
    let handle = harness.publish(&bytes, "application/octet-stream", "notes.bin");
    let staged_before = harness.service.staged_byte_len().expect("reads the total");

    let begun = harness
        .service
        .download_begin(
            &harness.actor,
            &DownloadBeginParams {
                environment_id: harness.environment_id(),
                resume_transfer_id: Nullable::null(),
                source: Nullable::some(DownloadSource::Attachment {
                    transfer_id: handle.transfer_id,
                }),
                device_id: Nullable::null(),
            },
        )
        .expect("opens the source");
    assert_eq!(begun.immutability, DownloadImmutability::ImmutableSource);
    assert_eq!(begun.byte_len, U64::new(bytes.len() as u64));
    assert_eq!(begun.content_digest, digest(&bytes));
    assert_eq!(begun.layout.chunk_count, U64::new(1));
    assert_eq!(begun.chunks.len(), 1);
    assert_eq!(begun.chunks[0].byte_len, U64::new(bytes.len() as u64));
    assert!(!begun.resumed);
    assert_eq!(
        begun.expires_at_ms.get(),
        support::START_MS + DOWNLOAD_SNAPSHOT_LIFETIME.get()
    );
    assert_ne!(
        begun.transfer_id, handle.transfer_id,
        "a download has its own identity"
    );
    assert_eq!(
        harness.service.staged_byte_len().expect("reads the total"),
        staged_before,
        "reading an attachment in place stages no second copy"
    );
}

/// KR-REQ-14.16: every chunk carries its index, length and digest, and the digest is checked
/// against the bytes each time.
#[test]
fn every_chunk_carries_its_index_length_and_digest() {
    let harness = Harness::create();
    let bytes = pattern(4096);
    let handle = harness.publish(&bytes, "application/octet-stream", "notes.bin");
    let begun = harness
        .service
        .download_begin(
            &harness.actor,
            &DownloadBeginParams {
                environment_id: harness.environment_id(),
                resume_transfer_id: Nullable::null(),
                source: Nullable::some(DownloadSource::Attachment {
                    transfer_id: handle.transfer_id,
                }),
                device_id: Nullable::null(),
            },
        )
        .expect("opens the source");
    let chunk = harness
        .service
        .download_chunk(
            &harness.actor,
            &DownloadChunkParams {
                transfer_id: begun.transfer_id,
                index: U64::new(0),
            },
        )
        .expect("reads the chunk");
    assert_eq!(chunk.chunk.index, U64::new(0));
    assert_eq!(chunk.chunk.byte_len, U64::new(bytes.len() as u64));
    assert_eq!(chunk.chunk.digest, digest(&bytes));
    assert_eq!(chunk.bytes.as_slice(), bytes.as_slice());

    let refusal = harness
        .service
        .download_chunk(
            &harness.actor,
            &DownloadChunkParams {
                transfer_id: begun.transfer_id,
                index: U64::new(9),
            },
        )
        .expect_err("refuses an index the layout does not have");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
}

/// KR-REQ-14.15: a concurrently writable source is staged as a bounded immutable snapshot, and an
/// open handle alone is never taken as immutability.
#[test]
fn a_writable_source_is_staged_rather_than_trusted() {
    let harness = Harness::create();
    let tree = source_tree();
    let bytes = pattern(8192);
    std::fs::write(tree.path().join("notes.txt"), &bytes).expect("writes the source");
    let scope = harness
        .service
        .register_scope("a review tree", tree.path())
        .expect("registers the scope");

    let begun = harness
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
        .expect("stages the snapshot");
    assert_eq!(begun.immutability, DownloadImmutability::StagedSnapshot);
    assert_eq!(begun.content_digest, digest(&bytes));
    assert_eq!(
        harness.service.staged_byte_len().expect("reads the total"),
        bytes.len() as u64,
        "a snapshot occupies the environment's own budget"
    );

    // The source is then rewritten. The snapshot keeps serving the revision it captured.
    let replacement = pattern(8192)
        .iter()
        .map(|byte| byte ^ 0xff)
        .collect::<Vec<_>>();
    std::fs::write(tree.path().join("notes.txt"), &replacement).expect("rewrites the source");
    let chunk = harness
        .service
        .download_chunk(
            &harness.actor,
            &DownloadChunkParams {
                transfer_id: begun.transfer_id,
                index: U64::new(0),
            },
        )
        .expect("reads the chunk");
    assert_eq!(
        chunk.bytes.as_slice(),
        bytes.as_slice(),
        "the snapshot is the revision it captured, not what the source says now"
    );
}

/// KR-REQ-14.15: two revisions of one source are two snapshots, and nothing ever combines them.
///
/// The in-flight case is asserted as an invariant rather than forced: the loop below replaces the
/// source while snapshots are staged, and whatever this machine produces must be either one whole
/// revision or an explicit refusal. The identity comparison the staging makes is covered on its own
/// in `authority::tests`.
#[test]
fn two_revisions_of_a_source_are_two_snapshots_and_never_a_mixture() {
    let harness = Harness::create();
    let tree = source_tree();
    let path = tree.path().join("notes.txt");
    let first = pattern(4096);
    std::fs::write(&path, &first).expect("writes the first revision");
    let scope = harness
        .service
        .register_scope("a review tree", tree.path())
        .expect("registers the scope");
    let begin = |harness: &Harness| {
        harness.service.download_begin(
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
    };

    let a = begin(&harness).expect("stages the first revision");
    // An editor's atomic save: a different file is renamed over the name. The source's stable
    // identity changes, which is what the staging compares.
    let second = pattern(6144);
    let side = tree.path().join("notes.next");
    std::fs::write(&side, &second).expect("writes the second revision");
    std::fs::rename(&side, &path).expect("replaces the source");
    let b = begin(&harness).expect("stages the second revision");

    assert_ne!(a.transfer_id, b.transfer_id);
    assert_eq!(a.content_digest, digest(&first));
    assert_eq!(b.content_digest, digest(&second));
    assert_ne!(a.content_digest, b.content_digest);
    for (transfer, expected) in [(&a, &first), (&b, &second)] {
        let mut assembled = Vec::new();
        for index in 0..transfer.layout.chunk_count.get() {
            let chunk = harness
                .service
                .download_chunk(
                    &harness.actor,
                    &DownloadChunkParams {
                        transfer_id: transfer.transfer_id,
                        index: U64::new(index),
                    },
                )
                .expect("reads the chunk");
            assert_eq!(chunk.chunk.digest, digest(chunk.bytes.as_slice()));
            assembled.extend_from_slice(chunk.bytes.as_slice());
        }
        assert_eq!(
            assembled.as_slice(),
            expected.as_slice(),
            "a snapshot serves one revision from end to end"
        );
        assert_eq!(digest(&assembled), transfer.content_digest);
    }
    harness
        .service
        .download_release(&harness.actor, a.transfer_id)
        .expect("releases the first");
    harness
        .service
        .download_release(&harness.actor, b.transfer_id)
        .expect("releases the second");

    // The in-flight replacement. Every outcome is checked; none may be a mixture.
    let writer = std::thread::spawn({
        let path = path.clone();
        let tree = tree.path().to_path_buf();
        move || {
            for round in 0..300_u32 {
                let side = tree.join(format!("notes.{round}"));
                let body = pattern(4096 + (round as usize % 7) * 512);
                if std::fs::write(&side, &body).is_ok() {
                    let _ = std::fs::rename(&side, &path);
                }
                std::thread::sleep(std::time::Duration::from_micros(100));
            }
        }
    });
    let mut captured = 0_u32;
    for _ in 0..60 {
        match begin(&harness) {
            Ok(transfer) => {
                captured += 1;
                let mut assembled = Vec::new();
                let mut served = true;
                for index in 0..transfer.layout.chunk_count.get() {
                    match harness.service.download_chunk(
                        &harness.actor,
                        &DownloadChunkParams {
                            transfer_id: transfer.transfer_id,
                            index: U64::new(index),
                        },
                    ) {
                        Ok(chunk) => {
                            assert_eq!(chunk.chunk.digest, digest(chunk.bytes.as_slice()));
                            assembled.extend_from_slice(chunk.bytes.as_slice());
                        }
                        Err(_) => served = false,
                    }
                }
                if served {
                    assert_eq!(
                        digest(&assembled),
                        transfer.content_digest,
                        "a snapshot never combines two revisions"
                    );
                }
                let _ = harness
                    .service
                    .download_release(&harness.actor, transfer.transfer_id);
            }
            Err(error) => assert!(
                matches!(
                    error.code(),
                    ErrorCode::SourceChanged | ErrorCode::PermissionDenied
                ),
                "a change under the staging is reported explicitly: {error}"
            ),
        }
    }
    writer.join().expect("the writer finishes");
    assert!(captured > 0, "at least one snapshot was taken");
}

/// KR-REQ-14.15: a source above the environment's per-file bound is refused before it is copied.
#[test]
fn a_source_above_the_per_file_bound_is_refused_before_it_is_copied() {
    let harness = Harness::create();
    let tree = source_tree();
    std::fs::write(tree.path().join("notes.txt"), pattern(4096)).expect("writes the source");
    let scope = harness
        .service
        .register_scope("a review tree", tree.path())
        .expect("registers the scope");
    harness.set_limits(Limits {
        max_file_len: 1024,
        ..Limits::default()
    });
    let refusal = harness
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
        .expect_err("refuses a source above the bound");
    assert_eq!(refusal.code(), ErrorCode::QuotaExceeded);
    assert_eq!(
        std::fs::read_dir(harness.service.staging().snapshots().display_path())
            .expect("reads the snapshot area")
            .count(),
        0,
        "nothing was staged"
    );
}

/// KR-REQ-14.15: a resumed transfer keeps the same immutable identity, and a missing or released
/// snapshot is refused rather than replaced.
#[test]
fn a_resumed_transfer_keeps_its_identity_and_a_released_one_is_refused() {
    let harness = Harness::create();
    let tree = source_tree();
    let bytes = pattern(4096);
    std::fs::write(tree.path().join("notes.txt"), &bytes).expect("writes the source");
    let scope = harness
        .service
        .register_scope("a review tree", tree.path())
        .expect("registers the scope");
    let begun = harness
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
        .expect("stages the snapshot");
    let resumed = harness
        .service
        .download_begin(
            &harness.actor,
            &DownloadBeginParams {
                environment_id: harness.environment_id(),
                resume_transfer_id: Nullable::some(begun.transfer_id),
                source: Nullable::null(),
                device_id: Nullable::null(),
            },
        )
        .expect("resumes the same snapshot");
    assert!(resumed.resumed);
    assert_eq!(resumed.transfer_id, begun.transfer_id);
    assert_eq!(resumed.content_digest, begun.content_digest);
    assert_eq!(resumed.chunks, begun.chunks);
    assert_eq!(resumed.expires_at_ms, begun.expires_at_ms);

    harness
        .service
        .download_release(&harness.actor, begun.transfer_id)
        .expect("releases it");
    let refusal = harness
        .service
        .download_begin(
            &harness.actor,
            &DownloadBeginParams {
                environment_id: harness.environment_id(),
                resume_transfer_id: Nullable::some(begun.transfer_id),
                source: Nullable::null(),
                device_id: Nullable::null(),
            },
        )
        .expect_err("refuses a released snapshot");
    assert_eq!(refusal.code(), ErrorCode::SourceChanged);

    let unknown = harness
        .service
        .download_begin(
            &harness.actor,
            &DownloadBeginParams {
                environment_id: harness.environment_id(),
                resume_transfer_id: Nullable::some(TransferId::new(Uuid::from_bytes([77; 16]))),
                source: Nullable::null(),
                device_id: Nullable::null(),
            },
        )
        .expect_err("refuses an identifier that names nothing");
    assert_eq!(unknown.code(), ErrorCode::InvalidArgument);
}

/// KR-REQ-14.15: an expired snapshot is refused and its bytes are released rather than silently
/// replaced.
#[test]
fn an_expired_snapshot_is_refused_and_released() {
    let harness = Harness::create();
    let tree = source_tree();
    let bytes = pattern(4096);
    std::fs::write(tree.path().join("notes.txt"), &bytes).expect("writes the source");
    let scope = harness
        .service
        .register_scope("a review tree", tree.path())
        .expect("registers the scope");
    let begun = harness
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
        .expect("stages the snapshot");
    assert_eq!(
        harness.service.staged_byte_len().expect("reads the total"),
        bytes.len() as u64
    );
    harness.clock.advance(DOWNLOAD_SNAPSHOT_LIFETIME.get());
    let refusal = harness
        .service
        .download_chunk(
            &harness.actor,
            &DownloadChunkParams {
                transfer_id: begun.transfer_id,
                index: U64::new(0),
            },
        )
        .expect_err("refuses an expired snapshot");
    assert_eq!(refusal.code(), ErrorCode::SourceChanged);
    assert_eq!(
        harness.service.staged_byte_len().expect("reads the total"),
        0,
        "its bytes are released"
    );
    assert_eq!(
        std::fs::read_dir(harness.service.staging().snapshots().display_path())
            .expect("reads the snapshot area")
            .count(),
        0
    );
}

/// KR-REQ-14.16: revoking read authority stops further bytes at once.
#[test]
fn revoking_read_authority_stops_further_bytes() {
    let harness = Harness::create();
    let tree = source_tree();
    let bytes = pattern(4096);
    std::fs::write(tree.path().join("notes.txt"), &bytes).expect("writes the source");
    let scope = harness
        .service
        .register_scope("a review tree", tree.path())
        .expect("registers the scope");
    let begun = harness
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
        .expect("stages the snapshot");
    harness
        .service
        .download_chunk(
            &harness.actor,
            &DownloadChunkParams {
                transfer_id: begun.transfer_id,
                index: U64::new(0),
            },
        )
        .expect("reads a chunk while the scope holds");
    harness
        .service
        .revoke_scope(scope)
        .expect("revokes the scope");
    let refusal = harness
        .service
        .download_chunk(
            &harness.actor,
            &DownloadChunkParams {
                transfer_id: begun.transfer_id,
                index: U64::new(0),
            },
        )
        .expect_err("refuses after the revocation");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
}

/// KR-REQ-14.16: an attachment whose retention ended stops serving bytes to an open transfer.
#[test]
fn an_expired_attachment_stops_serving_an_open_transfer() {
    let harness = Harness::create();
    let bytes = pattern(1024);
    let handle = harness.publish(&bytes, "application/octet-stream", "notes.bin");
    // The clock is moved to the attachment's own expiry before the transfer is opened, so the
    // snapshot is the fresher of the two and the attachment is what runs out.
    harness
        .clock
        .set(support::START_MS + kr_protocol::transfer::UNUSED_ATTACHMENT_LIFETIME.get());
    let begun = harness
        .service
        .download_begin(
            &harness.actor,
            &DownloadBeginParams {
                environment_id: harness.environment_id(),
                resume_transfer_id: Nullable::null(),
                source: Nullable::some(DownloadSource::Attachment {
                    transfer_id: handle.transfer_id,
                }),
                device_id: Nullable::null(),
            },
        )
        .expect("opens the source");
    harness
        .service
        .download_chunk(
            &harness.actor,
            &DownloadChunkParams {
                transfer_id: begun.transfer_id,
                index: U64::new(0),
            },
        )
        .expect("reads a chunk while the attachment holds");
    let sweep = harness
        .service
        .sweep(&RetainEverything)
        .expect("runs a sweep");
    assert_eq!(sweep.expired_attachments, 1);
    let refusal = harness
        .service
        .download_chunk(
            &harness.actor,
            &DownloadChunkParams {
                transfer_id: begun.transfer_id,
                index: U64::new(0),
            },
        )
        .expect_err("refuses after the attachment expired");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
}

/// KR-REQ-14.16: the client verifies every chunk, the total size and the whole-file digest, writes
/// through a temporary file, and never overwrites its destination without an explicit action.
#[test]
fn a_client_publishes_through_a_temporary_file_and_never_overwrites_by_default() {
    let harness = Harness::create();
    let bytes = pattern(2048);
    let handle = harness.publish(&bytes, "application/octet-stream", "notes.bin");
    let destination_tree = source_tree();
    let destination =
        AuthorisedDirectory::open_root(harness.environment_id(), destination_tree.path())
            .expect("opens the destination");
    let placement = |transfer_id, allow_overwrite| DownloadPlacement {
        transfer_id,
        destination_name: "notes.bin".to_owned(),
        byte_len: U64::new(bytes.len() as u64),
        content_digest: digest(&bytes),
        allow_overwrite,
    };

    let begun = harness
        .service
        .download_begin(
            &harness.actor,
            &DownloadBeginParams {
                environment_id: harness.environment_id(),
                resume_transfer_id: Nullable::null(),
                source: Nullable::some(DownloadSource::Attachment {
                    transfer_id: handle.transfer_id,
                }),
                device_id: Nullable::null(),
            },
        )
        .expect("opens the source");

    let written = kr_transfer::publish_transfer(
        &harness.service,
        &harness.actor,
        &destination,
        &placement(begun.transfer_id, false),
    )
    .expect("publishes the download");
    assert_eq!(written, bytes.len() as u64);
    assert_eq!(
        std::fs::read(destination_tree.path().join("notes.bin")).expect("reads the destination"),
        bytes
    );
    assert_eq!(
        std::fs::read_dir(destination_tree.path())
            .expect("reads the destination")
            .count(),
        1,
        "no temporary file is left behind"
    );

    // The destination now exists. Publishing again is refused without the explicit action.
    let refusal = kr_transfer::publish_transfer(
        &harness.service,
        &harness.actor,
        &destination,
        &placement(begun.transfer_id, false),
    )
    .expect_err("refuses to overwrite");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        std::fs::read_dir(destination_tree.path())
            .expect("reads the destination")
            .count(),
        1,
        "the refusal leaves no partial file"
    );

    // With the user's explicit overwrite action it replaces the destination.
    kr_transfer::publish_transfer(
        &harness.service,
        &harness.actor,
        &destination,
        &placement(begun.transfer_id, true),
    )
    .expect("publishes with the explicit overwrite");
    assert_eq!(
        std::fs::read(destination_tree.path().join("notes.bin")).expect("reads the destination"),
        bytes
    );
}

/// KR-REQ-14.16: a conflicting duplicate chunk fails integrity, and a size or digest that does not
/// match the transfer stops the publish.
#[test]
fn a_client_refuses_a_conflicting_duplicate_and_a_mismatched_whole_file() {
    let harness = Harness::create();
    let bytes = pattern(2048);
    let destination_tree = source_tree();
    let destination =
        AuthorisedDirectory::open_root(harness.environment_id(), destination_tree.path())
            .expect("opens the destination");
    let placement = DownloadPlacement {
        transfer_id: TransferId::new(Uuid::from_bytes([5; 16])),
        destination_name: "notes.bin".to_owned(),
        byte_len: U64::new(bytes.len() as u64),
        content_digest: digest(&bytes),
        allow_overwrite: false,
    };
    let (chunk, payload) = support::chunk_of(&bytes, 0);

    {
        let mut writer = DownloadWriter::open(&destination, &placement).expect("opens the writer");
        // A chunk whose bytes do not match its descriptor never reaches the file.
        let refusal = writer
            .write_chunk(&chunk, &vec![0; bytes.len()])
            .expect_err("refuses the chunk");
        assert_eq!(refusal.code(), ErrorCode::AttachmentIntegrity);
        writer
            .write_chunk(&chunk, payload.as_slice())
            .expect("accepts the chunk");
        // The same bytes again are harmless.
        writer
            .write_chunk(&chunk, payload.as_slice())
            .expect("acknowledges the duplicate");
        // Different bytes claiming the same position are not.
        let other = bytes.iter().map(|byte| byte ^ 0xff).collect::<Vec<_>>();
        let (conflicting, conflicting_bytes) = support::chunk_of(&other, 0);
        let refusal = writer
            .write_chunk(&conflicting, conflicting_bytes.as_slice())
            .expect_err("refuses the conflicting duplicate");
        assert_eq!(refusal.code(), ErrorCode::AttachmentIntegrity);
        writer.publish().expect("publishes the verified download");
    }
    assert_eq!(
        std::fs::read(destination_tree.path().join("notes.bin")).expect("reads the destination"),
        bytes
    );

    // A whole-file digest that does not match the transfer stops the publish, and the temporary
    // file goes with it.
    let wrong = DownloadPlacement {
        destination_name: "other.bin".to_owned(),
        content_digest: digest(b"something else"),
        ..placement.clone()
    };
    let mut writer = DownloadWriter::open(&destination, &wrong).expect("opens the writer");
    writer
        .write_chunk(&chunk, payload.as_slice())
        .expect("accepts the chunk");
    let refusal = writer.publish().expect_err("refuses the publish");
    assert_eq!(refusal.code(), ErrorCode::AttachmentIntegrity);
    assert!(!destination_tree.path().join("other.bin").exists());
    assert_eq!(
        std::fs::read_dir(destination_tree.path())
            .expect("reads the destination")
            .count(),
        1,
        "nothing partial is left in the destination"
    );
}

/// KR-REQ-14.16: an incomplete download is never published, and abandoning one leaves nothing.
#[test]
fn an_incomplete_download_is_never_published() {
    let harness = Harness::create();
    let bytes = pattern(kr_protocol::limits::UPLOAD_CHUNK_LEN + 1024);
    let destination_tree = source_tree();
    let destination =
        AuthorisedDirectory::open_root(harness.environment_id(), destination_tree.path())
            .expect("opens the destination");
    let placement = DownloadPlacement {
        transfer_id: TransferId::new(Uuid::from_bytes([5; 16])),
        destination_name: "notes.bin".to_owned(),
        byte_len: U64::new(bytes.len() as u64),
        content_digest: digest(&bytes),
        allow_overwrite: false,
    };
    let mut writer = DownloadWriter::open(&destination, &placement).expect("opens the writer");
    let (chunk, payload) = support::chunk_of(&bytes, 0);
    writer
        .write_chunk(&chunk, payload.as_slice())
        .expect("accepts the first chunk");
    assert_eq!(writer.received().missing(), vec![1]);
    let refusal = writer
        .publish()
        .expect_err("refuses an incomplete download");
    assert_eq!(refusal.code(), ErrorCode::ResourceUnavailable);
    assert!(!destination_tree.path().join("notes.bin").exists());
    assert_eq!(
        std::fs::read_dir(destination_tree.path())
            .expect("reads the destination")
            .count(),
        0,
        "the dropped writer removed its temporary file"
    );
}

/// KR-REQ-14.14: a staged upload stays outside every repository, and an adapter reaches it through
/// a narrow read grant rather than a widened sandbox.
#[test]
fn an_upload_stays_outside_repositories_and_is_reached_through_a_narrow_grant() {
    let harness = Harness::create();
    let bytes = pattern(512);
    let handle = harness.publish(&bytes, "image/png", "photo.png");
    let staged = harness.service.staging().complete().display_path();
    assert!(
        !kr_transfer::staging::inside_repository(staged),
        "the staging area is not inside a repository working tree"
    );
    assert!(
        staged.starts_with(harness.host.environment().state_dir()),
        "it is inside the environment's own state directory"
    );

    let draft = harness
        .service
        .draft_create(
            &harness.actor,
            &kr_protocol::transfer::DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::null(),
                application_instance_id: Nullable::null(),
                text: "look".to_owned(),
            },
        )
        .expect("creates the draft")
        .draft;
    let bound = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &kr_protocol::transfer::AgentDraftAddAttachmentParams {
                draft_id: draft.draft_id,
                expected_revision: draft.revision,
                transfer_id: handle.transfer_id,
                contribution: kr_protocol::transfer::AttachmentContribution {
                    operation_id: "attach".to_owned(),
                    accepted_media_types: vec!["image/png".to_owned()],
                    max_byte_len: U64::new(1024 * 1024),
                    max_count: U64::new(1),
                    insertion_method:
                        kr_protocol::transfer::InsertionMethod::ManualTerminalWorkflow,
                    external_destination: Nullable::null(),
                    model_media_capability: false,
                },
            },
        )
        .expect("binds the attachment");
    let grant = bound
        .attachment
        .read_grant
        .as_ref()
        .expect("a manual workflow needs a readable path");
    assert_eq!(grant.transfer_id, handle.transfer_id);
    assert_eq!(grant.environment_id, harness.environment_id());
    let path = std::path::Path::new(&grant.host_path);
    assert!(path.starts_with(staged), "the grant names the staged file");
    assert!(!kr_transfer::staging::inside_repository(path));
    harness
        .service
        .read_grant(grant.grant_id)
        .expect("the grant resolves while it holds");

    // A typed submission needs no readable path and is given none.
    let typed_handle = harness.publish(&pattern(256), "image/png", "second.png");
    let bound = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &kr_protocol::transfer::AgentDraftAddAttachmentParams {
                draft_id: draft.draft_id,
                expected_revision: bound.draft.revision,
                transfer_id: typed_handle.transfer_id,
                contribution: kr_protocol::transfer::AttachmentContribution {
                    operation_id: "attach".to_owned(),
                    accepted_media_types: vec!["image/png".to_owned()],
                    max_byte_len: U64::new(1024 * 1024),
                    max_count: U64::new(4),
                    insertion_method: kr_protocol::transfer::InsertionMethod::TypedSubmission,
                    external_destination: Nullable::null(),
                    model_media_capability: false,
                },
            },
        )
        .expect("binds the second attachment");
    assert!(
        bound.attachment.read_grant.as_ref().is_none(),
        "a typed submission is given no path at all"
    );
}
