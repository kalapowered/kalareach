//! Section 24's privacy mode: the generation, what it disables, what it fences and cancels, what
//! it reconciles before it reports complete, and what it keeps and shows rather than erases.
//!
//! The contract is one trait, so the tests are about the trait as much as about any subsystem:
//! what matters is that every part of the host answers the same four questions, and that privacy
//! mode's answer to a person depends on all of them rather than on the first one that replied.
//!
//! The test that matters most is the last one in each section: privacy is enabled while upload,
//! notification and inference work is in flight, which is the case section 24 names by name.

use kr_protocol::scalars::TimestampMs;
use kr_worker::privacy::subsystems::{Recording, exported};
use kr_worker::privacy::{
    BackupOutbox, Completion, DescriptionInference, Disabled, PrivacyGeneration, PrivacyMode,
    PrivacySubsystem, ReceiptMetadata, RetainedHistory, SyncOutbox, TransferPreviews,
};

/// A host with every subsystem privacy mode reaches, each holding work.
fn busy_host() -> PrivacyMode {
    PrivacyMode::new(vec![
        Box::new(RetainedHistory::new(8 * 1024 * 1024)),
        Box::new(ReceiptMetadata::new(2)),
        // Two decoded previews retained, three insertions admitted and not sent, one in flight.
        Box::new(TransferPreviews::new(2, 3, 1)),
        Box::new(DescriptionInference::new(4, 2, 5)),
        Box::new(SyncOutbox::new(
            6,
            1,
            vec![exported(
                "history_snapshot",
                "archive:9f2c",
                TimestampMs::new(500),
            )],
        )),
        Box::new(BackupOutbox::new(
            2,
            1,
            vec![exported(
                "backup_generation",
                "backup:17",
                TimestampMs::new(600),
            )],
        )),
    ])
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.27: the generation, the prospective disables, the fence and the cancellation
// ---------------------------------------------------------------------------------------------

#[test]
fn enabling_privacy_records_a_generation_and_disables_the_four_prospectively() {
    let mut mode = busy_host();
    assert_eq!(mode.generation(), PrivacyGeneration::INITIAL);
    let enabling = mode.enable(TimestampMs::new(1_000));
    assert_eq!(enabling.generation, PrivacyGeneration::new(1));
    assert_eq!(enabling.at_ms.get(), 1_000);
    assert_eq!(
        enabling
            .disabled
            .iter()
            .map(|disabled| disabled.as_str())
            .collect::<Vec<_>>(),
        vec![
            "content_history_retention",
            "description_inference",
            "sync",
            "backup"
        ]
    );
    for capability in Disabled::ALL {
        assert!(mode.disables(*capability));
    }
}

#[test]
fn every_content_bearing_queue_and_capture_is_fenced_immediately() {
    let mut mode = busy_host();
    let enabling = mode.enable(TimestampMs::new(1_000));
    let fenced: std::collections::BTreeMap<&str, u64> = enabling
        .fenced
        .iter()
        .map(|(name, fenced)| (*name, fenced.queues))
        .collect();
    // The capture, the previews, the inference queue and both outboxes.
    assert_eq!(fenced["history"], 1);
    assert_eq!(fenced["transfer_previews"], 1);
    assert_eq!(fenced["description_inference"], 1);
    assert_eq!(fenced["sync"], 1);
    assert_eq!(fenced["backup"], 1);
    // Receipts are operation metadata, so there is nothing there to fence and it says so rather
    // than reporting a fence it did not need.
    assert_eq!(fenced["receipts"], 0);
}

#[test]
fn undispatched_backup_sync_and_description_work_is_cancelled() {
    let mut mode = busy_host();
    let enabling = mode.enable(TimestampMs::new(1_000));
    let cancelled: std::collections::BTreeMap<&str, u64> = enabling
        .cancelled
        .iter()
        .map(|(name, cancelled)| (*name, cancelled.undispatched))
        .collect();
    assert_eq!(cancelled["description_inference"], 4);
    assert_eq!(cancelled["sync"], 6);
    assert_eq!(cancelled["backup"], 2);
    assert_eq!(cancelled["transfer_previews"], 3);
    // And an admitted action is not cancelled by privacy mode: that is the dispatch barrier's,
    // and privacy mode deciding what a caller's action does is not one of the four things
    // section 24 asks for.
    assert_eq!(cancelled["receipts"], 0);
}

#[test]
fn retained_output_and_generated_descriptions_are_removed_and_the_removal_is_logical() {
    let mut mode = busy_host();
    let enabling = mode.enable(TimestampMs::new(1_000));
    let removed: std::collections::BTreeMap<&str, (u64, u64)> = enabling
        .removed
        .iter()
        .map(|(name, removed)| (*name, (removed.bytes, removed.records)))
        .collect();
    assert_eq!(removed["history"], (8 * 1024 * 1024, 0));
    assert_eq!(removed["description_inference"], (0, 5));
    assert_eq!(removed["transfer_previews"], (0, 2));
    // Receipts keep their metadata, which is what privacy mode explicitly retains.
    assert_eq!(removed["receipts"], (0, 0));
    // A second pass removes nothing, because the first one already did: this host does not keep
    // reporting a removal it has already made.
    let again = mode.enable(TimestampMs::new(2_000));
    let history = again
        .removed
        .iter()
        .find(|(name, _)| *name == "history")
        .expect("history is reached");
    assert_eq!(history.1.bytes, 0);
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.28: reconciliation, the late result, and what stays
// ---------------------------------------------------------------------------------------------

#[test]
fn privacy_is_enabled_with_upload_notification_and_inference_work_in_flight() {
    // Section 24 asks for exactly this case: *tests enable privacy while upload/notification and
    // inference work is in flight.* Cleanup of that work is reconciled before completion is
    // reported, and the report names which subsystem is still working.
    let mut mode = busy_host();
    let enabling = mode.enable(TimestampMs::new(1_000));
    assert_eq!(
        enabling.in_flight(),
        5,
        "two previews, two descriptions and one of each outbox"
    );
    let Completion::Reconciling { outstanding } = mode.reconcile() else {
        panic!("cleanup cannot be complete while work is in flight");
    };
    let names: Vec<&str> = outstanding.iter().map(|(name, _)| *name).collect();
    assert!(names.contains(&"transfer_previews"));
    assert!(names.contains(&"description_inference"));
    assert!(names.contains(&"sync"));
    assert!(names.contains(&"backup"));
}

#[test]
fn completion_is_reported_only_once_every_subsystem_has_reconciled() {
    let mut mode = PrivacyMode::new(vec![
        Box::new(Recording::new("quiet")),
        Box::new(Recording::with_in_flight("busy", 2)),
    ]);
    mode.enable(TimestampMs::new(1_000));
    assert!(!mode.reconcile().is_complete());

    // The subsystem itself reports each piece of cleanup as it finishes. Nothing else can say so
    // on its behalf, which is why the answer is asked of it rather than counted centrally.
    let mut busy = Recording::with_in_flight("busy", 2);
    busy.note_reconciled();
    assert_eq!(busy.outstanding(), 1);
    busy.note_reconciled();
    assert_eq!(busy.outstanding(), 0);
    let mut settled = PrivacyMode::new(vec![Box::new(Recording::new("quiet")), Box::new(busy)]);
    settled.enable(TimestampMs::new(2_000));
    assert!(settled.reconcile().is_complete());
}

#[test]
fn no_late_result_from_an_older_generation_is_published() {
    let mut mode = busy_host();
    mode.enable(TimestampMs::new(1_000));
    // The descriptions and uploads that were already in flight were admitted under the previous
    // generation. Their answers come back, and every subsystem refuses them.
    for subsystem in [
        "description_inference",
        "sync",
        "backup",
        "transfer_previews",
    ] {
        assert!(
            !mode.accepts_result(subsystem, PrivacyGeneration::INITIAL),
            "{subsystem} published a late result"
        );
        assert!(
            mode.accepts_result(subsystem, PrivacyGeneration::new(1)),
            "{subsystem} refused a result of its own generation"
        );
    }
}

#[test]
fn what_privacy_mode_keeps_is_named_rather_than_quietly_retained() {
    // Section 24: do not falsely promise that a functioning durable control system writes no
    // state at all. What it keeps is listed, with the reason each one is needed.
    let mut mode = busy_host();
    let enabling = mode.enable(TimestampMs::new(1_000));
    let kept: Vec<&str> = enabling.kept.iter().map(|kept| kept.what).collect();
    assert!(kept.contains(&"the receipt journal's operation metadata"));
    assert!(kept.contains(&"the minimal local authority this host holds"));
    assert!(kept.contains(&"live pending questions and approvals"));
    assert!(kept.contains(&"user-pinned labels"));
    for kept in &enabling.kept {
        assert!(
            !kept.why.is_empty(),
            "{} is kept for no stated reason",
            kept.what
        );
    }
}

#[test]
fn what_already_left_this_host_is_shown_rather_than_claimed_to_be_erased() {
    let mut mode = busy_host();
    let enabling = mode.enable(TimestampMs::new(1_000));
    assert_eq!(enabling.exported.len(), 2);
    let kinds: Vec<&str> = enabling
        .exported
        .iter()
        .map(|copy| copy.kind.as_str())
        .collect();
    assert!(kinds.contains(&"history_snapshot"));
    assert!(kinds.contains(&"backup_generation"));
    for copy in &enabling.exported {
        assert!(
            copy.deletable,
            "a copy this host knows about is one it can offer to delete"
        );
        assert!(copy.left_at_ms.get() > 0);
    }
    // And they are still there afterwards: privacy mode does not erase them.
    assert_eq!(mode.exported().len(), 2);
}

#[test]
fn disabling_privacy_starts_retention_again_and_still_refuses_the_private_intervals_results() {
    let mut mode = busy_host();
    mode.enable(TimestampMs::new(1_000));
    let resumed = mode.disable(TimestampMs::new(9_000));
    assert!(!mode.is_enabled());
    assert_eq!(resumed.retention_resumes_at_ms.get(), 9_000);
    for capability in Disabled::ALL {
        assert!(
            !mode.disables(*capability),
            "retention starts again from the moment privacy mode is turned off"
        );
    }
    assert!(
        !mode.accepts_result("sync", PrivacyGeneration::INITIAL),
        "a result from before the private interval is still refused"
    );
    assert_eq!(resumed.generation, PrivacyGeneration::new(1));
}

#[test]
fn a_restarted_host_reads_its_generation_back_and_keeps_refusing_what_it_refused() {
    let mut mode = busy_host();
    mode.enable(TimestampMs::new(1_000));
    let generation = mode.generation();
    // What a restart has is the recorded generation and whether privacy mode was on.
    let restored = PrivacyMode::restored(generation, true, vec![Box::new(Recording::new("sync"))]);
    assert!(restored.is_enabled());
    assert_eq!(restored.generation(), generation);
    assert!(!restored.accepts_result("sync", PrivacyGeneration::INITIAL));
    assert!(restored.accepts_result("sync", generation));
}
