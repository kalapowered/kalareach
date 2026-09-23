//! Section 24's privacy mode: the generation, what it disables, what it fences and cancels, what
//! it reconciles before it reports complete, and what it keeps and shows rather than erases.
//!
//! The contract is one trait, so the tests are about the trait as much as about any subsystem:
//! what matters is that every part of the host answers the same four questions, and that privacy
//! mode's answer to a person depends on all of them rather than on the first one that replied.
//!
//! Two of the subsystems act on stores this crate owns, and those are driven through a real
//! session with a real journal and a real spool. The other four are seams for work that lives
//! elsewhere, and what is tested of them is the contract they implement.
//!
//! The test that matters most is the one section 24 names by name: privacy is enabled while
//! upload, notification and inference work is in flight.

use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{ActorId, SessionEpoch, SessionId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{Digest256, TimestampMs};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::journal::Submission;
use kr_worker::privacy::subsystems::Recording;
use kr_worker::privacy::{
    BackupOutbox, Completion, DescriptionInference, Disabled, PrivacyGeneration, PrivacyMode,
    PrivacySubsystem, SyncOutbox, TransferPreviews, exported,
};
use kr_worker::pty::ShellCommand;
use kr_worker::session::{Session, SessionConfig};

/// A live session on the internal disk, with a journal and a spool of its own.
fn session_on_disk() -> (kr_ipc::testing::TempHost, Session) {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let journal = environment.journal_database(session_id);
    std::fs::create_dir_all(journal.parent().expect("a parent")).expect("the journal directory");
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: environment.environment_id(),
        display_number: DisplayNumber::new(1),
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), "sleep 30".to_owned()],
            cwd: "/".to_owned(),
            environment: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        worker_endpoint: None,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(journal),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
    };
    let session = Session::open(config).expect("opens the session");
    (temp, session)
}

fn actor() -> ActorId {
    ActorId::new("test:privacy").expect("an actor")
}

fn submission(byte: u8) -> Submission {
    Submission {
        actor_id: actor(),
        action_id: kr_worker::journal::action_id_from([byte; 16]),
        method: Method::AgentApprovalRespond.into(),
        method_version: MethodVersion::V1,
        payload_digest: Digest256::from_bytes([byte; 32]),
        subject_digest: Digest256::from_bytes([byte; 32]),
        // What a caller sent, which is the caller's own content rather than metadata.
        intent: b"the answer a person typed".to_vec(),
        accepted_deadline_ms: Some(TimestampMs::new(kr_ipc::now_ms().get() + 120_000)),
        now_ms: kr_ipc::now_ms(),
    }
}

/// The four seams a host holds beside the session's own two, each with work in it.
fn seams() -> (
    TransferPreviews,
    DescriptionInference,
    SyncOutbox,
    BackupOutbox,
) {
    (
        // Two decoded previews retained, three insertions admitted and not sent, one in flight.
        TransferPreviews::new(2, 3, 1),
        DescriptionInference::new(4, 2, 5),
        SyncOutbox::new(
            6,
            1,
            vec![exported(
                "history_snapshot",
                "archive:9f2c",
                TimestampMs::new(500),
            )],
        ),
        BackupOutbox::new(
            2,
            1,
            vec![exported(
                "backup_generation",
                "backup:17",
                TimestampMs::new(600),
            )],
        ),
    )
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.27: the generation, the prospective disables, the fence, the cancellation, the removal
// ---------------------------------------------------------------------------------------------

#[test]
fn enabling_privacy_records_a_generation_durably_before_anything_is_touched() {
    let (temp, mut session) = session_on_disk();
    let session_id = session.summary().session_id;
    assert_eq!(session.privacy().generation(), PrivacyGeneration::INITIAL);
    assert!(!session.privacy().is_enabled());

    let enabling = session.enable_privacy(&mut []).expect("enables");
    assert_eq!(enabling.generation, PrivacyGeneration::new(1));
    assert!(session.privacy().is_enabled());

    // The generation is on disk, which is what makes it a boundary a restart can see.
    let journal = kr_worker::journal::Journal::open_read_only(
        temp.environment().journal_database(session_id),
    )
    .expect("reads the journal");
    let recorded = journal
        .read_privacy()
        .expect("reads")
        .expect("the record is there");
    assert_eq!((recorded.generation, recorded.enabled), (1, true));
}

#[test]
fn the_four_capabilities_are_disabled_together_and_prospectively() {
    let (_temp, mut session) = session_on_disk();
    for capability in Disabled::ALL {
        assert!(!session.privacy().disables(*capability));
    }
    let enabling = session.enable_privacy(&mut []).expect("enables");
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
        assert!(session.privacy().disables(*capability));
    }
}

#[test]
fn retained_output_is_removed_and_nothing_is_retained_after_it() {
    let (_temp, mut session) = session_on_disk();
    for _ in 0..8 {
        session.ingest_output(&[b'x'; 8192]);
    }
    let before = session.retained_output_bytes();
    assert!(before > 0, "this session has retained output");

    let enabling = session.enable_privacy(&mut []).expect("enables");
    let removed = enabling
        .removed
        .iter()
        .find(|(name, _)| *name == "history")
        .expect("the history is reached")
        .1;
    assert!(removed.bytes > 0, "the retained output went: {removed:?}");
    assert_eq!(session.retained_output_bytes(), 0);
    let page = session.history_page(0, 4096).expect("a page");
    assert!(page.bytes.is_empty(), "nothing is served from before it");

    // And retention is disabled prospectively: what arrives now is not kept.
    session.ingest_output(&[b'y'; 4096]);
    assert_eq!(
        session.retained_output_bytes(),
        0,
        "output produced under privacy mode is not retained"
    );
}

#[test]
fn a_settled_receipts_content_is_removed_and_its_metadata_is_kept() {
    // Section 24 keeps minimal local authority and receipt metadata. A receipt's identity, state
    // and digests are metadata; the intent envelope and the result are the caller's content.
    let (_temp, mut session) = session_on_disk();
    {
        let journal = session.journal_mut().expect("a journal");
        journal.accept(&submission(1)).expect("a settled action");
        journal
            .mark_dispatching(
                actor(),
                kr_worker::journal::action_id_from([1; 16]),
                kr_ipc::now_ms(),
            )
            .expect("marks");
        journal
            .settle(
                actor(),
                kr_worker::journal::action_id_from([1; 16]),
                kr_protocol::receipt::ReceiptState::Applied,
                Some(b"what the action answered"),
                None,
                kr_ipc::now_ms(),
            )
            .expect("settles");
        // And one that has not settled, whose envelope recovery still needs.
        journal.accept(&submission(2)).expect("a pending action");
    }
    let enabling = session.enable_privacy(&mut []).expect("enables");
    let removed = enabling
        .removed
        .iter()
        .find(|(name, _)| *name == "receipts")
        .expect("the receipts are reached")
        .1;
    assert!(removed.records > 0, "the settled content went: {removed:?}");

    let journal = session.journal_mut().expect("a journal");
    let settled = journal
        .read(actor(), kr_worker::journal::action_id_from([1; 16]))
        .expect("reads")
        .expect("the receipt is still there");
    assert_eq!(
        settled.state,
        kr_protocol::receipt::ReceiptState::Applied,
        "the metadata is kept"
    );
    assert!(
        journal
            .read_result(&actor(), kr_worker::journal::action_id_from([1; 16]))
            .expect("reads")
            .is_none(),
        "the result the action produced is gone"
    );
    assert!(
        journal
            .read_intent(&actor(), kr_worker::journal::action_id_from([1; 16]))
            .expect("reads")
            .is_none(),
        "the envelope the caller sent is gone"
    );
    assert!(
        journal
            .read_intent(&actor(), kr_worker::journal::action_id_from([2; 16]))
            .expect("reads")
            .is_some(),
        "an action that has not settled keeps the envelope recovery reads"
    );
}

#[test]
fn a_privacy_generation_this_host_cannot_record_is_not_one_it_claims_to_be_in() {
    // The durable write comes first, so a store that refuses it leaves privacy mode off rather
    // than on with a boundary a restart cannot see.
    let (temp, mut session) = session_on_disk();
    let session_id = session.summary().session_id;
    rusqlite::Connection::open(temp.environment().journal_database(session_id))
        .expect("the same database")
        .execute_batch(
            "CREATE TRIGGER refuse_privacy BEFORE INSERT ON privacy
             BEGIN SELECT RAISE(ABORT, 'this store refused the generation'); END;",
        )
        .expect("the store will refuse it");
    for _ in 0..4 {
        session.ingest_output(&[b'x'; 4096]);
    }
    let retained = session.retained_output_bytes();
    assert!(session.enable_privacy(&mut []).is_err());
    assert!(!session.privacy().is_enabled());
    assert_eq!(
        session.retained_output_bytes(),
        retained,
        "nothing was removed for a privacy mode this host could not record"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.28: reconciliation, the late result, what stays and what is shown
// ---------------------------------------------------------------------------------------------

#[test]
fn privacy_is_enabled_with_upload_notification_and_inference_work_in_flight() {
    // Section 24 asks for exactly this case: *tests enable privacy while upload/notification and
    // inference work is in flight.* Cleanup of that work is reconciled before completion is
    // reported, and the report names which subsystem is still working.
    let (_temp, mut session) = session_on_disk();
    let (mut previews, mut descriptions, mut sync, mut backup) = seams();
    let enabling = {
        let mut seams: Vec<&mut dyn PrivacySubsystem> =
            vec![&mut previews, &mut descriptions, &mut sync, &mut backup];
        session.enable_privacy(&mut seams).expect("enables")
    };
    assert_eq!(
        enabling.in_flight(),
        5,
        "one preview, two descriptions and one of each outbox"
    );
    let cancelled: std::collections::BTreeMap<&str, u64> = enabling
        .cancelled
        .iter()
        .map(|(name, cancelled)| (*name, cancelled.undispatched))
        .collect();
    assert_eq!(cancelled["description_inference"], 4);
    assert_eq!(cancelled["sync"], 6);
    assert_eq!(cancelled["backup"], 2);
    assert_eq!(cancelled["transfer_previews"], 3);

    let seams: [&dyn PrivacySubsystem; 4] = [&previews, &descriptions, &sync, &backup];
    let Completion::Reconciling { outstanding } = session.reconcile_privacy(&seams) else {
        panic!("cleanup cannot be complete while work is in flight");
    };
    let names: Vec<&str> = outstanding.iter().map(|(name, _)| *name).collect();
    assert!(names.contains(&"transfer_previews"));
    assert!(names.contains(&"description_inference"));
    assert!(names.contains(&"sync"));
    assert!(names.contains(&"backup"));

    // Each subsystem reports its own cleanup as it finishes, and only when every one has is
    // completion reported. Nothing else can say so on its behalf, which is why the caller keeps
    // the subsystems it handed in.
    previews.note_reconciled();
    descriptions.note_reconciled();
    descriptions.note_reconciled();
    sync.note_reconciled();
    let seams: [&dyn PrivacySubsystem; 4] = [&previews, &descriptions, &sync, &backup];
    assert!(!session.reconcile_privacy(&seams).is_complete());
    backup.note_reconciled();
    let seams: [&dyn PrivacySubsystem; 4] = [&previews, &descriptions, &sync, &backup];
    assert!(session.reconcile_privacy(&seams).is_complete());
    assert!(session.privacy_cleanup_failure().is_none());
}

#[test]
fn every_content_bearing_queue_and_capture_is_fenced_immediately() {
    let (_temp, mut session) = session_on_disk();
    let (mut previews, mut descriptions, mut sync, mut backup) = seams();
    let enabling = {
        let mut seams: Vec<&mut dyn PrivacySubsystem> =
            vec![&mut previews, &mut descriptions, &mut sync, &mut backup];
        session.enable_privacy(&mut seams).expect("enables")
    };
    let fenced: std::collections::BTreeMap<&str, u64> = enabling
        .fenced
        .iter()
        .map(|(name, fenced)| (*name, fenced.queues))
        .collect();
    assert_eq!(fenced["history"], 1);
    assert_eq!(fenced["transfer_previews"], 1);
    assert_eq!(fenced["description_inference"], 1);
    assert_eq!(fenced["sync"], 1);
    assert_eq!(fenced["backup"], 1);
    // Receipts carry no queue of their own, and this says so rather than reporting a fence it did
    // not need.
    assert_eq!(fenced["receipts"], 0);
}

#[test]
fn no_late_result_is_published_and_only_the_generation_in_force_is() {
    let (_temp, mut session) = session_on_disk();
    session.enable_privacy(&mut []).expect("enables");
    let privacy = session.privacy();
    assert!(!privacy.accepts_result(PrivacyGeneration::INITIAL));
    assert!(privacy.accepts_result(PrivacyGeneration::new(1)));
    // A generation this host has never opened is not a licence either.
    assert!(!privacy.accepts_result(PrivacyGeneration::new(2)));
    session.enable_privacy(&mut []).expect("enables again");
    assert!(!session.privacy().accepts_result(PrivacyGeneration::new(1)));
}

#[test]
fn what_privacy_mode_keeps_is_named_rather_than_quietly_retained() {
    // Section 24: do not falsely promise that a functioning durable control system writes no
    // state at all. What it keeps is listed, with the reason each one is needed.
    let (_temp, mut session) = session_on_disk();
    let (mut previews, mut descriptions, mut sync, mut backup) = seams();
    let enabling = {
        let mut seams: Vec<&mut dyn PrivacySubsystem> =
            vec![&mut previews, &mut descriptions, &mut sync, &mut backup];
        session.enable_privacy(&mut seams).expect("enables")
    };
    let kept: Vec<&str> = enabling.kept.iter().map(|kept| kept.what).collect();
    assert!(kept.contains(&"the receipt journal's operation metadata"));
    assert!(kept.contains(&"the minimal local authority this host holds"));
    assert!(kept.contains(&"the intent envelope of an action that has not settled"));
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
    let (_temp, mut session) = session_on_disk();
    let (mut previews, mut descriptions, mut sync, mut backup) = seams();
    let enabling = {
        let mut seams: Vec<&mut dyn PrivacySubsystem> =
            vec![&mut previews, &mut descriptions, &mut sync, &mut backup];
        session.enable_privacy(&mut seams).expect("enables")
    };
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
            "a copy this host holds a reference to is one it can offer to delete"
        );
        assert!(copy.left_at_ms.get() > 0);
    }
    // And they are still there afterwards: privacy mode does not erase them.
    assert_eq!(sync.exported().len() + backup.exported().len(), 2);
}

#[test]
fn disabling_privacy_starts_retention_again_and_still_refuses_the_private_intervals_results() {
    let (_temp, mut session) = session_on_disk();
    session.enable_privacy(&mut []).expect("enables");
    session.ingest_output(&[b'x'; 4096]);
    assert_eq!(session.retained_output_bytes(), 0);

    let resumed = session.disable_privacy().expect("disables");
    assert!(!session.privacy().is_enabled());
    for capability in Disabled::ALL {
        assert!(!session.privacy().disables(*capability));
    }
    session.ingest_output(&[b'y'; 4096]);
    assert!(
        session.retained_output_bytes() > 0,
        "retention starts again from the moment privacy mode is turned off"
    );
    let page = session.history_page(0, 8192).expect("a page");
    assert!(
        page.gap.is_present(),
        "what was omitted while privacy mode was on is a gap rather than reconstructed"
    );
    // Turning privacy mode off opens a boundary of its own, so the private interval's own
    // generation is refused afterwards as well as during it.
    assert_eq!(resumed.generation, PrivacyGeneration::new(2));
    assert!(
        !session.privacy().accepts_result(PrivacyGeneration::new(1)),
        "a result admitted during the private interval is still refused"
    );
    assert!(
        !session.privacy().accepts_result(PrivacyGeneration::INITIAL),
        "and so is one from before it"
    );
    assert!(session.privacy().accepts_result(resumed.generation));
}

#[test]
fn a_restarted_session_reads_its_generation_back_and_keeps_refusing_what_it_refused() {
    let (temp, mut session) = session_on_disk();
    let session_id = session.summary().session_id;
    session.enable_privacy(&mut []).expect("enables");
    let generation = session.privacy().generation();
    drop(session);

    // The same session, opened again over the same stores.
    let environment = temp.environment();
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: environment.environment_id(),
        display_number: DisplayNumber::new(1),
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), "sleep 30".to_owned()],
            cwd: "/".to_owned(),
            environment: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        worker_endpoint: None,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
    };
    let restarted = Session::open(config).expect("opens the session again");
    assert!(restarted.privacy().is_enabled());
    assert_eq!(restarted.privacy().generation(), generation);
    assert!(
        !restarted
            .privacy()
            .accepts_result(PrivacyGeneration::INITIAL),
        "work admitted before the boundary is still refused after a restart"
    );
    assert!(restarted.privacy().accepts_result(generation));
}

#[test]
fn content_that_settles_while_privacy_is_on_is_taken_when_privacy_is_turned_off() {
    // Privacy mode is prospective: an action admitted after it was enabled settles later, and the
    // content its receipt carries is content this host was asked not to keep. Waiting for a
    // maintenance tick would leave it there for anybody who turned privacy mode off first.
    let (_temp, mut session) = session_on_disk();
    session.enable_privacy(&mut []).expect("enables");
    {
        let journal = session.journal_mut().expect("a journal");
        journal.accept(&submission(3)).expect("an action");
        journal
            .mark_dispatching(
                actor(),
                kr_worker::journal::action_id_from([3; 16]),
                kr_ipc::now_ms(),
            )
            .expect("marks");
        journal
            .settle(
                actor(),
                kr_worker::journal::action_id_from([3; 16]),
                kr_protocol::receipt::ReceiptState::Applied,
                Some(b"what the action answered"),
                None,
                kr_ipc::now_ms(),
            )
            .expect("settles");
        assert!(
            journal
                .read_result(&actor(), kr_worker::journal::action_id_from([3; 16]))
                .expect("reads")
                .is_some(),
            "it is there until something takes it"
        );
    }
    session.disable_privacy().expect("disables");
    let journal = session.journal_mut().expect("a journal");
    assert!(
        journal
            .read_result(&actor(), kr_worker::journal::action_id_from([3; 16]))
            .expect("reads")
            .is_none(),
        "the private interval's content is taken before privacy mode ends"
    );
    assert!(
        journal
            .read_intent(&actor(), kr_worker::journal::action_id_from([3; 16]))
            .expect("reads")
            .is_none()
    );
}

#[test]
fn a_cleanup_that_could_not_remove_the_output_is_not_settled_by_a_redaction_that_worked() {
    // Two obligations, cleared by different work. A spool this host could not empty is content
    // privacy mode was asked to remove and has not, and a redaction that succeeded says nothing
    // about it.
    let (temp, mut session) = session_on_disk();
    let session_id = session.summary().session_id;
    for _ in 0..4 {
        session.ingest_output(&[b'x'; 4096]);
    }
    // A directory of that name blocks the boundary file, so the spool cannot be emptied.
    let spool = temp.environment().session_spool(session_id);
    std::fs::create_dir(spool.join("boundary")).expect("blocks the boundary file");

    session.enable_privacy(&mut []).expect("enables");
    assert!(
        session.privacy_cleanup_failure().is_some(),
        "the removal that could not finish is owed"
    );
    assert!(!session.reconcile_privacy(&[]).is_complete());
    // A maintenance pass whose redaction succeeds does not settle the other obligation.
    session.collect_expired();
    assert!(
        !session.reconcile_privacy(&[]).is_complete(),
        "the output is still there, so the cleanup is not complete"
    );

    // Once the obstruction is gone the retry finishes it, and only then is it complete.
    std::fs::remove_dir(spool.join("boundary")).expect("unblocks it");
    session.collect_expired();
    assert!(session.reconcile_privacy(&[]).is_complete());
    assert_eq!(session.retained_output_bytes(), 0);
}

#[test]
fn a_session_whose_privacy_state_cannot_be_read_retains_nothing_and_owes_its_cleanup() {
    // Not knowing whether privacy mode is on is not a reason to keep output, and it is not a
    // reason to call the cleanup done either.
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    // A journal path that cannot be opened: a directory stands where the file belongs.
    let journal = environment.journal_database(session_id);
    std::fs::create_dir_all(&journal).expect("blocks the journal");
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: environment.environment_id(),
        display_number: DisplayNumber::new(1),
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), "sleep 30".to_owned()],
            cwd: "/".to_owned(),
            environment: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        worker_endpoint: None,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(journal),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
    };
    let mut session = Session::open(config).expect("opens the session");
    session.ingest_output(&[b'x'; 4096]);
    assert_eq!(
        session.retained_output_bytes(),
        0,
        "a host that cannot say whether privacy mode is on does not retain"
    );
    assert!(!session.reconcile_privacy(&[]).is_complete());
    assert!(session.privacy_cleanup_failure().is_some());

    // And a maintenance pass does not clear it: the journal is still unopenable, so nothing this
    // host owes has been done. Clearing one obligation on the strength of work it could not do is
    // what would make the cleanup report complete over content that is still there.
    session.collect_expired();
    assert!(!session.reconcile_privacy(&[]).is_complete());
    assert!(session.privacy_cleanup_failure().is_some());
    assert!(
        session.disable_privacy().is_err(),
        "privacy mode this host cannot see is not privacy mode it may turn off"
    );
}

#[test]
fn content_settled_under_privacy_is_taken_where_it_settles_rather_than_at_the_next_tick() {
    // A crash between a settlement and the next maintenance pass would leave the content for the
    // archive to serve, so it goes in the settlement's own wake rather than later.
    let (_temp, mut session) = session_on_disk();
    session.enable_privacy(&mut []).expect("enables");
    let action = kr_worker::journal::action_id_from([9; 16]);
    {
        let journal = session.journal_mut().expect("a journal");
        journal.accept(&submission(9)).expect("an action");
        journal
            .mark_dispatching(actor(), action, kr_ipc::now_ms())
            .expect("marks");
        journal
            .settle(
                actor(),
                action,
                kr_protocol::receipt::ReceiptState::Applied,
                Some(b"what the action answered"),
                None,
                kr_ipc::now_ms(),
            )
            .expect("settles");
    }
    // What the dispatch path does the moment the outcome is committed, with no tick in between.
    session.redact_settled_action(&actor(), action);
    let journal = session.journal_mut().expect("a journal");
    assert!(
        journal
            .read_result(&actor(), action)
            .expect("reads")
            .is_none(),
        "the content went where the action settled"
    );
    assert!(
        journal
            .read_intent(&actor(), action)
            .expect("reads")
            .is_none()
    );
    assert_eq!(
        journal
            .read(actor(), action)
            .expect("reads")
            .expect("the receipt is still there")
            .state,
        kr_protocol::receipt::ReceiptState::Applied,
        "the metadata is kept"
    );
}

#[test]
fn privacy_is_not_turned_off_while_its_own_cleanup_is_unfinished() {
    // Turning it off over an unfinished purge would resume retention beside it: output kept
    // afterwards would join the history the purge still owes, and a restart would lose the
    // obligation altogether.
    let (temp, mut session) = session_on_disk();
    let session_id = session.summary().session_id;
    for _ in 0..4 {
        session.ingest_output(&[b'x'; 4096]);
    }
    let spool = temp.environment().session_spool(session_id);
    std::fs::create_dir(spool.join("boundary")).expect("blocks the boundary file");
    session.enable_privacy(&mut []).expect("enables");
    assert!(session.privacy_cleanup_failure().is_some());

    let refused = session
        .disable_privacy()
        .expect_err("privacy mode is not turned off over an unfinished cleanup");
    assert!(refused.to_string().contains("unfinished"), "{refused}");
    assert!(session.privacy().is_enabled());

    // Once the obstruction is gone, the retry finishes it and the change is allowed.
    std::fs::remove_dir(spool.join("boundary")).expect("unblocks it");
    session.collect_expired();
    session.disable_privacy().expect("disables");
    assert!(!session.privacy().is_enabled());
}

// ---------------------------------------------------------------------------------------------
// The contract itself
// ---------------------------------------------------------------------------------------------

#[test]
fn a_subsystem_is_fenced_before_it_is_cancelled() {
    let mut mode = PrivacyMode::new();
    mode.open_generation(TimestampMs::new(1_000));
    let mut first = Recording::new("first");
    let mut second = Recording::new("second");
    let enabling = {
        let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![&mut first, &mut second];
        mode.apply(&mut subsystems, TimestampMs::new(1_000))
    };
    // The recording subsystem takes nothing back that it has not fenced first, so a cancellation
    // that had run early would be counted as taking nothing.
    assert!(
        enabling
            .cancelled
            .iter()
            .all(|(_, cancelled)| cancelled.undispatched > 0)
    );
    assert!(first.was_cancelled() && second.was_cancelled());
}

#[test]
fn a_shared_runtime_can_be_wrapped_once_and_driven_by_the_same_contract() {
    // The seams are adapters a host holds, not values privacy mode owns, so a subsystem whose
    // work lives in another service is reachable both before and after the enabling that started
    // its cleanup. That is what makes reconciliation something a host can actually reach.
    let mut mode = PrivacyMode::new();
    mode.open_generation(TimestampMs::new(1_000));
    let mut sync = SyncOutbox::new(3, 2, Vec::new());
    {
        let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![&mut sync];
        let enabling = mode.apply(&mut subsystems, TimestampMs::new(1_000));
        assert_eq!(enabling.in_flight(), 2);
    }
    assert_eq!(sync.outstanding(), 2);
    sync.note_reconciled();
    sync.note_reconciled();
    assert!(PrivacyMode::reconcile(&[&sync]).is_complete());
}
