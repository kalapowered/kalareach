//! Journals kept as fixtures, made with their faults and opened by the product: by a worker's
//! session, which recovers what it finds, and by the opener a recovery of a closed session's
//! journal uses, which creates nothing.
//!
//! Every fixture is also made as its control, the same file without its fault, and the control
//! must open cleanly at this build's schema version, so a fault is what the checks find and not
//! the SQL it was written into.

use std::path::{Path, PathBuf};

use kr_controller::archive::{Archive, ArchiveService, Incompleteness};
use kr_faults::journal::{self, Fault, JournalFixture, Made};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::SessionId;
use kr_protocol::receipt::{ReceiptState, RejectionReason};
use kr_protocol::scalars::TimestampMs;
use kr_worker::journal::{Journal, SCHEMA_VERSION};
use kr_worker::persistence::FaultKind;
use kr_worker::session::Session;

/// The kept fixtures, each with the test below that opens it.
const KEPT: [&str; 3] = [
    "damaged-receipts",
    "interrupted-accept",
    "unfinished-actions",
];

fn fixture(name: &str) -> JournalFixture {
    JournalFixture::load(&journal::directory().join(format!("{name}.json")))
        .unwrap_or_else(|error| panic!("{error}"))
}

/// The fixture made in a directory of its own on the internal disk, which goes with the handle.
fn made(name: &str, made: Made) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::Builder::new()
        .prefix("kr-faults-journal-")
        .tempdir()
        .expect("a directory for the journal");
    let path = directory.path().join("journal.sqlite3");
    fixture(name)
        .make(&path, made)
        .unwrap_or_else(|error| panic!("{name}: {error}"));
    (directory, path)
}

fn action(action: u8) -> kr_protocol::ids::ActionId {
    kr_worker::journal::action_id_from([action; 16])
}

fn state_of(journal: &Journal, which: u8) -> Option<ReceiptState> {
    journal
        .read(journal::actor().expect("the actor"), action(which))
        .unwrap_or_else(|error| panic!("action {which} could not be read: {error}"))
        .map(|receipt| receipt.state)
}

/// A worker's session with its journal at `path`, which recovers what it finds as it opens.
fn session_on(path: &Path) -> Session {
    Session::open(kr_faults::session::config(
        20,
        3,
        kr_worker::action::time::TimeSources::system(),
        Some(path.to_path_buf()),
    ))
    .unwrap_or_else(|error| panic!("the session did not open: {error}"))
}

/// KR-REQ-29.03: a stored journal holding an accepted intent with no dispatch marker, a dispatch
/// marker with no answer and an applied action, kept as SQL and opened by a worker's session: the
/// intent is rejected as expired, the marker becomes unknown and is never dispatched again, and the
/// applied action is left as it was.
#[test]
fn a_stored_intent_and_an_unanswered_marker_are_recovered_by_the_session_that_opens_them() {
    let (_directory, path) = made("unfinished-actions", Made::WithFault);
    // The fixture is a store from an older schema version, which the worker that owns it brings
    // forward when it opens it, and which a reader opens only after that.
    let stored = Journal::open(&path).expect("the stored journal opens and is brought forward");
    assert_eq!(
        [1, 2, 3].map(|which| state_of(&stored, which)),
        [
            Some(ReceiptState::Accepted),
            Some(ReceiptState::Dispatching),
            Some(ReceiptState::Applied)
        ],
        "the fixture holds the states a worker stopped in"
    );
    let applied_revision = stored
        .read(journal::actor().expect("the actor"), action(3))
        .expect("a read")
        .expect("action 3")
        .revision;
    drop(stored);

    let mut session = session_on(&path);
    let recovered = session.journal().expect("the session's journal");
    let actor = journal::actor().expect("the actor");
    let intent = recovered
        .read(actor.clone(), action(1))
        .expect("a read")
        .expect("action 1");
    assert_eq!(intent.state, ReceiptState::Rejected);
    assert_eq!(intent.reason.0, Some(RejectionReason::Expired));
    let marker = recovered
        .read(actor.clone(), action(2))
        .expect("a read")
        .expect("action 2");
    assert_eq!(marker.state, ReceiptState::Unknown);
    assert_eq!(
        marker.error.as_ref().map(|error| error.code),
        Some(ErrorCode::OutcomeUnknown)
    );
    let applied = recovered
        .read(actor, action(3))
        .expect("a read")
        .expect("action 3");
    assert_eq!(
        (applied.state, applied.revision),
        (ReceiptState::Applied, applied_revision)
    );

    let journal = session.journal_mut().expect("the session's journal");
    let again = journal
        .accept(&journal::submission(2).expect("a submission"))
        .expect("the retry is answered");
    assert!(
        again.deduplicated,
        "the marker's action is never admitted again"
    );
    assert_eq!(again.receipt.state, ReceiptState::Unknown);
    let fresh = journal
        .accept(&journal::submission(4).expect("a submission"))
        .expect("a new action is admitted");
    assert_eq!(
        (fresh.deduplicated, fresh.receipt.state),
        (false, ReceiptState::Accepted)
    );
}

/// KR-REQ-29.03: a journal whose receipts table has its root page overwritten, kept as SQL with
/// the damage applied as the file is made: every open finds it corrupt, a read fails rather than
/// finding nothing, recovery leaves the fault standing, and a session that opens it records the
/// failure; the control, the same file undamaged, reads every receipt.
#[test]
fn a_journal_with_a_damaged_page_is_corrupt_at_every_open_and_its_control_is_not() {
    let (_directory, path) = made("damaged-receipts", Made::WithFault);
    for open in 0..2 {
        let mut damaged = Journal::open_existing(&path)
            .unwrap_or_else(|error| panic!("open {open} refused the file itself: {error}"));
        let read = damaged.read(journal::actor().expect("the actor"), action(1));
        assert!(
            read.is_err(),
            "open {open} read {read:?} from a damaged table"
        );
        let fault = damaged.health().condition().fault().cloned();
        assert_eq!(
            fault.as_ref().map(|fault| fault.kind),
            Some(FaultKind::Corrupt),
            "open {open}: {fault:?}"
        );
        assert!(
            matches!(
                damaged.recover(TimestampMs::new(journal::SUBMITTED_AT_MS)),
                Ok(None)
            ),
            "open {open}: a damaged store is never recovered by a write"
        );
        assert!(
            damaged.health().condition().fault().is_some(),
            "open {open}: the fault stands"
        );
        assert_ne!(
            damaged.pragma_string("quick_check").ok().as_deref(),
            Some("ok"),
            "open {open}: the store's own check finds the damage"
        );
    }
    let session = session_on(&path);
    assert!(
        session.journal_failure().is_some(),
        "the session that opened the damaged journal records its failure"
    );

    let (_control_directory, control) = made("damaged-receipts", Made::AsControl);
    let undamaged = Journal::open_existing(&control).expect("the control opens");
    assert_eq!(
        [1, 2, 3].map(|which| state_of(&undamaged, which)),
        [Some(ReceiptState::Applied); 3]
    );
    assert!(undamaged.health().condition().fault().is_none());
    assert_eq!(
        undamaged.pragma_string("quick_check").ok().as_deref(),
        Some("ok")
    );
}

/// KR-REQ-29.03: an accept whose log was cut inside its last frame, as a crash inside the commit
/// leaves it, kept as a fixture: on recovery that action is gone, with no receipt and no event, the
/// rest of the store is as it was, and the store is sound rather than corrupt; the control, whose
/// log was copied whole, holds the accepted action.
#[test]
fn a_commit_cut_inside_its_last_log_frame_is_gone_and_the_store_is_not_corrupt() {
    let (_directory, path) = made("interrupted-accept", Made::WithFault);
    let recovered = Journal::open_existing(&path).expect("the journal opens");
    assert_eq!(state_of(&recovered, 9), None, "the cut commit is gone");
    assert_eq!(state_of(&recovered, 1), Some(ReceiptState::Applied));
    let events = recovered.events_after(0, 100).expect("the event record");
    assert!(
        events.iter().all(|event| event.action_id != action(9)),
        "no event of the cut commit: {events:?}"
    );
    assert!(recovered.health().condition().fault().is_none());
    assert_eq!(
        recovered.pragma_string("quick_check").ok().as_deref(),
        Some("ok")
    );
    drop(recovered);
    let session = session_on(&path);
    assert!(session.journal_failure().is_none());
    assert_eq!(
        state_of(session.journal().expect("the session's journal"), 9),
        None,
        "a session recovering the journal finds no trace of it either"
    );

    let (_control_directory, control) = made("interrupted-accept", Made::AsControl);
    let whole = Journal::open_existing(&control).expect("the control opens");
    assert_eq!(state_of(&whole, 9), Some(ReceiptState::Accepted));
}

/// A kept journal made where a host keeps a session's journal, for the archive to read, on a host
/// tree of its own that goes with the handle.
fn in_a_host(name: &str, made: Made) -> (kr_ipc::testing::TempHost, SessionId) {
    let host = kr_ipc::testing::TempHost::create();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let path = host.environment().journal_database(session_id);
    std::fs::create_dir_all(path.parent().expect("the session's directory"))
        .expect("creates the session's directory");
    fixture(name)
        .make(&path, made)
        .unwrap_or_else(|error| panic!("{name}: {error}"));
    (host, session_id)
}

fn archive_of(host: &kr_ipc::testing::TempHost, session_id: SessionId) -> Archive {
    ArchiveService::new(host.environment())
        .archive(session_id)
        .unwrap_or_else(|error| panic!("the archive answers: {error}"))
}

fn unreadable(archive: &Archive) -> bool {
    archive
        .incompleteness
        .iter()
        .any(|reason| matches!(reason, Incompleteness::JournalUnreadable { .. }))
}

/// The archive reads a crashed session's journal whose receipts table has its root page
/// overwritten as one it cannot read. SQLite answers a plain count of a table from the narrowest of
/// its indexes, so a count taken that way never meets the damaged page: it reports three receipts
/// for a store whose own check finds the damage and in which every receipt read fails. Section 24
/// asks for an explicit incomplete archive here, so the table is checked and counted from itself,
/// the archive names the receipts table, and it claims no count the table has not stood behind.
/// The same journal undamaged reads complete, with its three receipts.
#[test]
fn the_archive_reports_a_journal_whose_receipts_table_is_damaged_as_unreadable() {
    let (damaged, session_id) = in_a_host("damaged-receipts", Made::WithFault);
    let archive = archive_of(&damaged, session_id);
    assert!(
        archive.incompleteness.iter().any(|reason| matches!(
            reason,
            Incompleteness::JournalUnreadable { detail }
                if detail.contains("the receipts table cannot be read")
        )),
        "{:?}",
        archive.incompleteness
    );
    assert_eq!(
        archive.receipts, 0,
        "no count is claimed for a table that cannot be read"
    );
    let journal = Journal::open_read_only(damaged.environment().journal_database(session_id))
        .expect("the journal opens to be read");
    assert_ne!(
        journal.pragma_string("quick_check").ok().as_deref(),
        Some("ok"),
        "the store's own check finds the damage"
    );
    assert!(
        journal
            .read(journal::actor().expect("the actor"), action(1))
            .is_err(),
        "and a receipt cannot be read"
    );
    assert_eq!(
        journal.len().ok(),
        Some(3),
        "while the count from an index stays whole, which is why it is not the count reported"
    );

    let (control, session_id) = in_a_host("damaged-receipts", Made::AsControl);
    let archive = archive_of(&control, session_id);
    assert!(!unreadable(&archive), "{:?}", archive.incompleteness);
    assert_eq!(archive.receipts, 3);
}

/// KR-REQ-27.05: the archive reads a journal whose receipts table holds a state the contract does
/// not have, as a journal it cannot read, rather than as one with no unfinished work.
///
/// The count of unfinished actions used to come from the narrowest index that carries the state,
/// and counted the two states recovery resolves wherever they were. A receipt whose state is none
/// of the contract's, as text or as bytes, was counted as nothing, so the archive answered with
/// the recovery's unfinished actions and no sign that a receipt could not be read. Each receipt's
/// state is now read from the table and checked, and one that is not the contract's is the
/// archive's reason, reported to the journal's health as corruption. The same journal with every
/// state the contract's is the control, and still counts the unfinished actions.
#[test]
fn the_archive_reports_a_receipt_with_a_state_outside_the_contract_as_unreadable() {
    let unfinished = |archive: &Archive| {
        archive
            .incompleteness
            .iter()
            .find_map(|reason| match reason {
                Incompleteness::RecoveryUnfinished { unresolved } => Some(*unresolved),
                _ => None,
            })
    };
    let (control, session_id) = in_a_host("unfinished-actions", Made::AsControl);
    let archive = archive_of(&control, session_id);
    assert!(!unreadable(&archive), "{:?}", archive.incompleteness);
    assert_eq!(
        unfinished(&archive),
        Some(2),
        "the control's unfinished actions"
    );

    for (stored, what) in [("'settled'", "a text"), ("x'ff00'", "a bytes")] {
        let (host, session_id) = in_a_host("unfinished-actions", Made::AsControl);
        let path = host.environment().journal_database(session_id);
        rusqlite::Connection::open(&path)
            .expect("the journal opens to be changed")
            .execute(
                &format!(
                    "UPDATE receipts SET state = {stored} WHERE action_id = x'03030303030303030303030303030303'"
                ),
                [],
            )
            .expect("one receipt's state is changed");
        let archive = archive_of(&host, session_id);
        assert!(
            archive.incompleteness.iter().any(|reason| matches!(
                reason,
                Incompleteness::JournalUnreadable { detail }
                    if detail.contains("a stored receipt state is not in the contract")
            )),
            "{what} state outside the contract is the archive's reason: {:?}",
            archive.incompleteness
        );
        let journal = Journal::open_read_only(&path).expect("the journal opens to be read");
        assert!(
            journal.unresolved_work().is_err(),
            "{what} state outside the contract is not counted as nothing"
        );
        assert_eq!(
            journal.len().ok(),
            Some(3),
            "while the count from an index stays whole, which is why it is not what is asked"
        );
    }
}

/// KR-REQ-27.05, an interrupted transaction: the archive reads a crashed session's journal whose
/// last commit was cut inside its log, finds that action nowhere and the store readable; the same
/// journal with its log whole holds the action.
#[test]
fn the_archive_finds_no_trace_of_a_commit_cut_in_its_log_and_its_control_holds_it() {
    let (cut, session_id) = in_a_host("interrupted-accept", Made::WithFault);
    let archive = archive_of(&cut, session_id);
    assert!(!unreadable(&archive), "{:?}", archive.incompleteness);
    assert_eq!(
        archive.receipts, 1,
        "only the action committed before the cut"
    );

    let (whole, session_id) = in_a_host("interrupted-accept", Made::AsControl);
    assert_eq!(archive_of(&whole, session_id).receipts, 2);
}

/// KR-REQ-27.05, the recovery states: the archive counts the actions a crashed worker left
/// unfinished, an intent with no marker and a marker with no answer, as an incomplete record; once
/// it owns the dead worker's stores, recovery leaves the marker unknown and rejects the intent, and
/// the record is complete in that respect. A journal whose actions all ended has none to count.
#[cfg(unix)]
#[test]
fn the_archive_counts_what_a_worker_left_unfinished_and_recovery_settles_it() {
    let (host, session_id) = in_a_host("unfinished-actions", Made::WithFault);
    let unfinished = |archive: &Archive| {
        archive
            .incompleteness
            .iter()
            .find_map(|reason| match reason {
                Incompleteness::RecoveryUnfinished { unresolved } => Some(*unresolved),
                _ => None,
            })
    };
    assert_eq!(unfinished(&archive_of(&host, session_id)), Some(2));
    let service = ArchiveService::new(host.environment());
    let ownership = service
        .take_ownership(
            session_id,
            kr_protocol::session::DisplayNumber::new(1),
            &ended_process(),
        )
        .unwrap_or_else(|error| panic!("owns the dead worker's stores: {error}"));
    let recovered = service
        .recover_journal(&ownership)
        .unwrap_or_else(|error| panic!("recovers the journal: {error}"));
    assert_eq!((recovered.left_unknown, recovered.rejected), (1, 1));
    assert_eq!(unfinished(&archive_of(&host, session_id)), None);

    let (control, session_id) = in_a_host("damaged-receipts", Made::AsControl);
    assert_eq!(unfinished(&archive_of(&control, session_id)), None);
}

/// A child this test started, ended and collected however the test ends.
#[cfg(unix)]
struct Child(std::process::Child);

#[cfg(unix)]
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A process that has ended, as the kernel described it while it ran: the worker a recovery
/// takes ownership after.
#[cfg(unix)]
fn ended_process() -> kr_protocol::identity::ProcessStartIdentity {
    let mut child = Child(
        std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("starts a process"),
    );
    let identity =
        kr_ipc::identity::process_start_identity(child.0.id()).expect("the kernel describes it");
    child.0.kill().expect("ends it");
    child.0.wait().expect("collects it");
    identity
}

#[test]
fn every_fixture_is_made_from_exactly_its_sql_at_its_schema_version() {
    for fixture in JournalFixture::all().unwrap_or_else(|error| panic!("{error}")) {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("journal.sqlite3");
        journal::build(&path, &fixture.sql).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            journal::dump(&path).unwrap_or_else(|error| panic!("{error}")),
            fixture.sql,
            "{} reads back as other SQL",
            fixture.name
        );
        assert_eq!(
            Journal::recorded_schema_version(&path).expect("a version"),
            fixture.schema_version,
            "{}",
            fixture.name
        );
    }
}

#[test]
fn every_fixture_as_its_control_opens_cleanly_at_this_builds_schema_version() {
    for fixture in JournalFixture::all().unwrap_or_else(|error| panic!("{error}")) {
        let (_directory, path) = made(&fixture.name, Made::AsControl);
        let opened = Journal::open(&path)
            .unwrap_or_else(|error| panic!("{} did not open: {error}", fixture.name));
        assert_eq!(
            opened.schema_version().ok(),
            Some(SCHEMA_VERSION),
            "{}",
            fixture.name
        );
        assert!(
            opened.health().condition().fault().is_none(),
            "{}",
            fixture.name
        );
    }
}

#[test]
fn every_kept_journal_has_a_test_of_its_own() {
    let names: Vec<String> = JournalFixture::all()
        .unwrap_or_else(|error| panic!("{error}"))
        .into_iter()
        .map(|fixture| fixture.name)
        .collect();
    assert_eq!(
        names, KEPT,
        "a fixture without a test, or a test without a fixture"
    );
}

/// One write a new fixture's stored state is made with, through the product's journal.
enum Write {
    Accept(u8),
    Dispatch(u8),
    Apply(u8),
}

/// A fixture this build can write the stored state of.
struct Recipe {
    name: &'static str,
    about: &'static str,
    fault: Fault,
    writes: &'static [Write],
}

const RECIPES: [Recipe; 3] = [
    Recipe {
        name: "unfinished-actions",
        about: "a worker stopped with action 1's intent accepted and never dispatched, action 2's \
                dispatch marker committed and no answer, and action 3 applied",
        fault: Fault::None,
        writes: &[
            Write::Accept(1),
            Write::Accept(2),
            Write::Dispatch(2),
            Write::Accept(3),
            Write::Dispatch(3),
            Write::Apply(3),
        ],
    },
    Recipe {
        name: "damaged-receipts",
        about: "three applied actions, with the receipts table's root page overwritten",
        fault: Fault::RootPageOverwritten {
            table: String::new(),
        },
        writes: &[
            Write::Accept(1),
            Write::Dispatch(1),
            Write::Apply(1),
            Write::Accept(2),
            Write::Dispatch(2),
            Write::Apply(2),
            Write::Accept(3),
            Write::Dispatch(3),
            Write::Apply(3),
        ],
    },
    Recipe {
        name: "interrupted-accept",
        about: "action 1 applied, then the product's journal accepts action 9 and the log is cut \
                inside the last frame of that commit",
        fault: Fault::LogCutInLastFrame { accept: 9 },
        writes: &[Write::Accept(1), Write::Dispatch(1), Write::Apply(1)],
    },
];

/// Writes the stored state of every fixture above that is not kept yet, from this build.
///
/// A kept fixture is never written again: its SQL is what an earlier build wrote, and opening it
/// after the schema moves on is a test of the migration. The boot each record was written in is
/// replaced by one fixed value, so a fixture names no machine's boot.
#[test]
#[ignore = "writes a new fixture's stored state from this build; run it by hand to add one"]
fn write_the_stored_state_of_each_new_fixture() {
    for recipe in RECIPES {
        let file = journal::directory().join(format!("{}.json", recipe.name));
        if file.exists() {
            continue;
        }
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("journal.sqlite3");
        let mut journal = Journal::open(&path).expect("a journal");
        let actor = journal::actor().expect("the actor");
        for write in recipe.writes {
            match *write {
                Write::Accept(which) => {
                    journal
                        .accept(&journal::submission(which).expect("a submission"))
                        .expect("accepted");
                }
                Write::Dispatch(which) => {
                    journal
                        .mark_dispatching(actor.clone(), action(which), at(which, 1))
                        .expect("marked");
                }
                Write::Apply(which) => {
                    journal
                        .settle(
                            actor.clone(),
                            action(which),
                            ReceiptState::Applied,
                            Some(b"applied"),
                            None,
                            at(which, 2),
                        )
                        .expect("settled");
                }
            }
        }
        drop(journal);
        let connection = rusqlite::Connection::open(&path).expect("the store");
        connection
            .execute(
                "UPDATE receipts SET created_boot = ?1",
                [b"an earlier boot".as_slice()],
            )
            .expect("the boot replaced");
        connection.close().expect("closed");
        let fault = match recipe.fault {
            Fault::RootPageOverwritten { .. } => Fault::RootPageOverwritten {
                table: "receipts".to_owned(),
            },
            other => other,
        };
        let fixture = JournalFixture {
            format: journal::FORMAT.to_owned(),
            name: recipe.name.to_owned(),
            about: recipe.about.to_owned(),
            schema_version: SCHEMA_VERSION,
            sql: journal::dump(&path).expect("the store as SQL"),
            fault,
        };
        std::fs::write(&file, fixture.to_json()).expect("the fixture written");
    }
}

/// When a write to action `which` happened, `step` milliseconds after it was submitted.
fn at(which: u8, step: u64) -> TimestampMs {
    TimestampMs::new(journal::SUBMITTED_AT_MS + u64::from(which) * 1_000 + step)
}
