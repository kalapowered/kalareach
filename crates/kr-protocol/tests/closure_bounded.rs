//! A closure record's two lists are built by one bounded constructor.
//!
//! A worker, the host's own record of a closure and the reduction a paired device is given all
//! hold their lists to a number of bytes, charged as the device receives them, with one entry that
//! counts what is left out. These cases hold that constructor, the entry and its readers.

use kr_cbor::Limits;
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{SessionEpoch, SessionId};
use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};
use kr_protocol::session::{
    CLOSURE_BUDGET_BYTES, CLOSURE_TEXT_BYTES, ClosureOmission, ClosureReason, ClosureRecord,
    Durability, NOT_LISTED_KIND, OmissionReason, OwnershipCoverage, SurvivingResource,
    TerminatedProcess, WHY_NOT_SHOWN,
};

/// The frame bound a device is sent, which a closure's notice must stay under.
const FRAME_BOUND: usize = 262_144;

fn record(terminated: Vec<TerminatedProcess>, surviving: Vec<SurvivingResource>) -> ClosureRecord {
    ClosureRecord {
        session_id: SessionId::new(Uuid::from_bytes([7; 16])),
        session_epoch: SessionEpoch::V1,
        reason: ClosureReason::CloseRequested,
        root_exit_code: Nullable::null(),
        root_signal: Nullable::null(),
        terminated,
        surviving,
        ownership_coverage: OwnershipCoverage::Incomplete,
        durability: Durability::Durable,
        closed_at_ms: TimestampMs::new(9),
    }
}

fn survivor(kind: &str, detail: &str) -> SurvivingResource {
    SurvivingResource {
        kind: kind.to_owned(),
        detail: detail.to_owned(),
    }
}

fn ended(pid: u64, name: Option<&str>) -> TerminatedProcess {
    TerminatedProcess {
        identity: ProcessStartIdentity::new(pid, ProcessStartSource::LinuxProcStat, 7),
        name: Nullable(name.map(str::to_owned)),
        forced: false,
    }
}

fn size<T: serde::Serialize>(value: &T) -> usize {
    kr_cbor::to_canonical_vec(value)
        .expect("a closure record encodes")
        .len()
}

/// The record as a paired device is given it when every detail names the host: each `surviving`
/// entry but the one that counts what is left out has its detail replaced. The host's own rewrite
/// is held to the same words by the controller's cases, so this stands for it here.
fn as_shown(record: &ClosureRecord) -> ClosureRecord {
    let mut shown = record.clone();
    let counted = record.survivors().len();
    for entry in shown.surviving.iter_mut().take(counted) {
        entry.detail = format!("{}: {WHY_NOT_SHOWN}", entry.kind);
    }
    shown
}

fn the_words_of(entry: &SurvivingResource) -> &str {
    &entry.detail
}

/// KR-REQ-09.22: an entry whose detail names the host is charged for the words a device is given,
/// so 4,096 entries of one byte each, about 94,000 bytes as the worker builds them, are held to the
/// budget as they are shown (about 377,000 bytes before this cut, for a kind of `process`; the
/// longer the kind, the more the door adds).
#[test]
fn an_entry_that_names_the_host_is_charged_as_a_device_is_given_it() {
    let whole = record(
        Vec::new(),
        (0..4_096).map(|_| survivor("process", "/")).collect(),
    );
    let before = size(&as_shown(&whole));
    let bounded = whole.clone().bounded(CLOSURE_BUDGET_BYTES);
    let after = size(&as_shown(&bounded));
    println!(
        "4,096 one-byte details naming the host: as built {} bytes, as shown {before} bytes; \
         bounded: as built {} bytes, as shown {after} bytes, {} listed",
        size(&whole),
        size(&bounded),
        bounded.survivors().len()
    );
    assert!(before > 350_000, "the case's premise: {before}");
    assert!(
        after <= CLOSURE_BUDGET_BYTES + 512 + 1_536,
        "the record shown is {after} bytes"
    );
    assert!(
        after + 1_024 < FRAME_BOUND,
        "the record shown is {after} bytes"
    );
    let omitted = bounded.omitted().expect("the cut says what it left out");
    assert_eq!(omitted.ended, 0);
    assert_eq!(
        omitted.other,
        4_096 - u64::try_from(bounded.survivors().len()).expect("a count")
    );
    assert_eq!(omitted.reason, OmissionReason::Budget);
}

/// KR-REQ-09.22: a `terminated` entry is charged at its own encoding, because the host does not
/// rewrite it: a name that names the host costs what it is.
#[test]
fn a_terminated_entry_is_charged_at_its_own_encoding() {
    let one = ended(10, Some("/usr/lib/a-long-name-of-a-helper"));
    let each = size(&one);
    let whole = record(vec![one; 1_000], Vec::new());
    let bounded = whole.bounded(each * 10);
    assert_eq!(bounded.terminated.len(), 10);
    assert_eq!(bounded.omitted().expect("an entry").ended, 990);
}

/// KR-REQ-09.22: a free text member is cut to its limit on a character boundary and ends in
/// `...`, before it is charged, so one long note cannot push out the others.
#[test]
fn a_long_text_is_cut_on_a_character_boundary_and_does_not_push_out_the_rest() {
    let mebibyte = "e".repeat(1_048_576);
    let mut whole = record(Vec::new(), vec![survivor("process", &mebibyte)]);
    whole
        .surviving
        .extend((0..50).map(|_| survivor("process", "process 4521 is still running")));
    let bounded = whole.bounded(CLOSURE_BUDGET_BYTES);
    assert_eq!(bounded.surviving.len(), 51, "nothing is left out");
    assert!(bounded.omitted().is_none());
    let cut = the_words_of(&bounded.surviving[0]);
    assert_eq!(cut.len(), CLOSURE_TEXT_BYTES);
    assert!(cut.ends_with("..."));
    assert!(cut.starts_with(&mebibyte[..CLOSURE_TEXT_BYTES - 3]));

    // A multi-byte character that straddles the limit goes whole or not at all.
    let accents = "\u{e9}".repeat(600);
    let mut whole = record(
        vec![ended(1, Some(&accents))],
        vec![survivor(&accents, &accents)],
    );
    whole.root_signal = Nullable::some(accents.clone());
    let bounded = whole.bounded(CLOSURE_BUDGET_BYTES);
    for text in [
        bounded.surviving[0].kind.as_str(),
        bounded.surviving[0].detail.as_str(),
        bounded.terminated[0]
            .name
            .as_ref()
            .expect("a name")
            .as_str(),
        bounded.root_signal.as_ref().expect("a signal").as_str(),
    ] {
        assert_eq!(text.len(), 1_023, "1,020 bytes of text and the dots");
        assert!(text.ends_with("\u{e9}..."));
    }

    // At the limit a text is kept, and one byte over it is cut.
    let exact = "x".repeat(CLOSURE_TEXT_BYTES);
    let over = "x".repeat(CLOSURE_TEXT_BYTES + 1);
    let bounded = record(
        Vec::new(),
        vec![survivor("a", &exact), survivor("b", &over)],
    )
    .bounded(CLOSURE_BUDGET_BYTES);
    assert_eq!(bounded.surviving[0].detail, exact);
    assert_eq!(bounded.surviving[1].detail.len(), CLOSURE_TEXT_BYTES);
    assert!(bounded.surviving[1].detail.ends_with("..."));
}

/// KR-REQ-09.22: the codec refuses a list of more than 4,096 members. At the production budget the
/// cap is not reached and a record of two full lists encodes; at a budget of 4 MiB, 5,000 entries
/// of the smallest charge give a list of at most 4,096 members, the entry included, and the record
/// encodes. (Both lists at the cap would meet the codec's limit on all items in a record, which
/// the production budget keeps out of reach.)
#[test]
fn a_list_is_held_to_the_codecs_member_limit_with_the_entry_included() {
    let both = record(
        (0..5_000).map(|pid| ended(pid, None)).collect(),
        (0..5_000).map(|_| survivor("p", "/")).collect(),
    );
    let production = both.bounded(CLOSURE_BUDGET_BYTES);
    assert!(production.surviving.len() < 4_000, "the budget binds first");
    assert!(production.terminated.len() < 4_000);
    kr_cbor::to_canonical_vec_within(&production, &Limits::DEFAULT)
        .expect("a record at the production budget encodes");

    let survivors = record(Vec::new(), (0..5_000).map(|_| survivor("p", "/")).collect());
    assert!(
        kr_cbor::to_canonical_vec_within(&survivors, &Limits::DEFAULT).is_err(),
        "the codec refuses the whole record"
    );
    let large = survivors.bounded(4 * 1024 * 1024);
    assert_eq!(large.surviving.len(), 4_096, "4,095 entries and the entry");
    let omitted = large.omitted().expect("the entry is last");
    assert_eq!((omitted.ended, omitted.other), (0, 5_000 - 4_095));
    kr_cbor::to_canonical_vec_within(&large, &Limits::DEFAULT).expect("the bounded record encodes");

    let ended_processes = record((0..5_000).map(|pid| ended(pid, None)).collect(), Vec::new());
    assert!(
        kr_cbor::to_canonical_vec_within(&ended_processes, &Limits::DEFAULT).is_err(),
        "the codec refuses the whole record"
    );
    let large = ended_processes.bounded(4 * 1024 * 1024);
    assert_eq!(large.terminated.len(), 4_096);
    assert_eq!(large.surviving.len(), 1, "the entry alone");
    let omitted = large.omitted().expect("the entry");
    assert_eq!((omitted.ended, omitted.other), (5_000 - 4_096, 0));
    kr_cbor::to_canonical_vec_within(&large, &Limits::DEFAULT).expect("the bounded record encodes");
}

/// KR-REQ-09.22: `surviving` is listed first and in the order it was given (the worker gives the
/// `unestablished` entries, then the processes), each list is a prefix, and the first survivor is
/// never cut, whatever the budget.
#[test]
fn survivors_come_first_in_order_and_the_first_is_never_cut() {
    let mut given = vec![survivor("unestablished", "cannot read the boundary")];
    given.extend(
        (0..400).map(|pid| survivor("process", &format!("process {pid} is still running"))),
    );
    let whole = record(
        (0..400).map(|pid| ended(pid, None)).collect(),
        given.clone(),
    );

    let bounded = whole.clone().bounded(10_000);
    let listed = bounded.survivors().len();
    assert!(listed > 1 && listed < 400, "{listed}");
    assert_eq!(bounded.survivors(), &given[..listed], "a prefix, in order");
    assert!(
        bounded.terminated.is_empty(),
        "survivors took the budget first"
    );
    assert_eq!(bounded.omitted().expect("an entry").ended, 400);

    let none = whole.bounded(0);
    assert_eq!(
        none.survivors(),
        &given[..1],
        "the first survivor is listed"
    );
    assert_eq!(none.omitted().expect("an entry").other, 400);
}

/// KR-REQ-09.22: a record whose cut left out ended processes only says so and left nothing: a
/// reader that asks what the session left finds no survivor and no survivor left out.
#[test]
fn a_cut_that_leaves_out_ended_processes_only_left_nothing() {
    let whole = record((0..1_000).map(|_| ended(10, None)).collect(), Vec::new());
    let each = size(&ended(10, None));
    let bounded = whole.bounded(each * 100);
    assert_eq!(bounded.terminated.len(), 100);
    let omitted = bounded.omitted().expect("an entry");
    assert_eq!((omitted.ended, omitted.other), (900, 0));
    assert!(bounded.survivors().is_empty());
    assert!(!bounded.left_something());
}

/// KR-REQ-09.22: a cut that left out survivors, with or without ended processes, left something,
/// also when every survivor that was left out is one the record does not name.
#[test]
fn a_cut_that_leaves_out_survivors_left_something() {
    let survivors: Vec<_> = (0..20)
        .map(|pid| survivor("process", &format!("process {pid} is still running")))
        .collect();
    let both = record(
        (0..50).map(|pid| ended(pid, None)).collect(),
        survivors.clone(),
    );
    let bounded = both.bounded(0);
    let omitted = bounded.omitted().expect("an entry");
    assert_eq!((omitted.ended, omitted.other), (50, 19));
    assert!(bounded.left_something());

    let alone = record(Vec::new(), survivors).bounded(0);
    assert_eq!(alone.omitted().expect("an entry").other, 19);
    assert!(alone.left_something());

    // One listed survivor and nothing left out is something left too.
    let whole = record(
        Vec::new(),
        vec![survivor("process", "process 4 is still running")],
    );
    assert!(whole.bounded(CLOSURE_BUDGET_BYTES).left_something());

    // A record that counts survivors and lists none (the form a device is given) left something;
    // one that counts only ended processes did not.
    let counting = |ended, other| {
        record(
            Vec::new(),
            vec![
                ClosureOmission {
                    ended,
                    other,
                    reason: OmissionReason::Connection,
                }
                .entry(),
            ],
        )
    };
    assert!(counting(0, 3).survivors().is_empty());
    assert!(counting(0, 3).left_something());
    assert!(!counting(7, 0).left_something());
}

/// KR-REQ-09.22: the cut does not touch what the worker said about the whole: coverage, the
/// reason, the root's result and the times are what they were, and a record that fits is the
/// record it was.
#[test]
fn only_the_two_lists_change_and_a_record_that_fits_is_unchanged() {
    let mut whole = record(
        (0..50).map(|pid| ended(pid, None)).collect(),
        (0..50).map(|_| survivor("process", "/")).collect(),
    );
    whole.root_exit_code = Nullable::some(kr_protocol::scalars::U64::new(3));
    whole.ownership_coverage = OwnershipCoverage::Complete;
    whole.durability = Durability::Volatile;
    assert_eq!(whole.clone().bounded(CLOSURE_BUDGET_BYTES), whole);

    let cut = whole.clone().bounded(2_000);
    assert_ne!(cut.terminated, whole.terminated);
    assert_eq!(cut.ownership_coverage, OwnershipCoverage::Complete);
    assert_eq!(cut.durability, Durability::Volatile);
    assert_eq!(cut.root_exit_code, whole.root_exit_code);
    assert_eq!(cut.reason, whole.reason);
    assert_eq!(cut.session_id, whole.session_id);
    assert_eq!(cut.closed_at_ms, whole.closed_at_ms);
}

/// KR-REQ-09.22: the entry's words are the same for a count of none, one or two, and one function
/// reads them back.
#[test]
fn the_entry_reads_back_for_every_count_and_reason() {
    for (ended, other) in [(0, 1), (1, 1), (2, 0), (0, 0), (u64::MAX, u64::MAX)] {
        for (reason, why) in [
            (OmissionReason::Budget, "a closure record has a size limit"),
            (
                OmissionReason::Connection,
                "this connection cannot carry the whole record in one frame",
            ),
        ] {
            let omission = ClosureOmission {
                ended,
                other,
                reason,
            };
            let entry = omission.entry();
            assert_eq!(entry.kind, NOT_LISTED_KIND);
            assert_eq!(
                entry.detail,
                format!(
                    "not listed here: {ended} of the ended processes and {other} of the other \
                     entries, because {why}"
                )
            );
            assert_eq!(ClosureOmission::read(&entry), Some(omission));
        }
    }
    assert_eq!(
        ClosureOmission {
            ended: 1,
            other: 1,
            reason: OmissionReason::Budget
        }
        .entry()
        .detail,
        "not listed here: 1 of the ended processes and 1 of the other entries, because a closure \
         record has a size limit"
    );
}

/// KR-REQ-09.22: a `not_listed` entry that is not exactly what the type writes is an ordinary
/// entry: a survivor, and nothing it says is read as a count.
#[test]
fn a_not_listed_entry_that_does_not_match_is_an_ordinary_entry() {
    let reason = "because a closure record has a size limit";
    for detail in [
        "something the host wrote",
        &format!("not listed here: 01 of the ended processes and 1 of the other entries, {reason}"),
        &format!("not listed here: +1 of the ended processes and 1 of the other entries, {reason}"),
        &format!("not listed here: 1 of the ended processes and 1 of the other entries, {reason}."),
        &format!(
            "not listed here: 1 of the ended processes and 1 of the other entries, so {reason}"
        ),
        "not listed here: 18446744073709551616 of the ended processes and 1 of the other entries, because a closure record has a size limit",
    ] {
        let record = record(Vec::new(), vec![survivor(NOT_LISTED_KIND, detail)]);
        assert_eq!(record.omitted(), None, "{detail}");
        assert_eq!(record.survivors().len(), 1, "{detail}");
        assert!(record.left_something(), "{detail}");
    }
    // The words under another kind, and the entry anywhere but last, are ordinary entries.
    let entry = ClosureOmission {
        ended: 3,
        other: 4,
        reason: OmissionReason::Budget,
    }
    .entry();
    let other_kind = SurvivingResource {
        kind: "process".to_owned(),
        detail: entry.detail.clone(),
    };
    assert_eq!(ClosureOmission::read(&other_kind), None);
    let earlier = record(
        Vec::new(),
        vec![
            entry.clone(),
            survivor("process", "process 4 is still running"),
        ],
    );
    assert_eq!(earlier.omitted(), None);
    assert_eq!(earlier.survivors().len(), 2);
}

/// KR-REQ-09.22: the record a device is given in place of one that does not fit has one entry that
/// counts both lists, adds the counts of an entry already there, cuts the root's signal and keeps
/// every other member.
#[test]
fn the_reduction_for_a_device_counts_both_lists_and_fits_a_small_frame() {
    let mut whole = record(
        (0..5_000)
            .map(|pid| ended(pid, Some("/usr/bin/helper")))
            .collect(),
        (0..300).map(|_| survivor("process", "/")).collect(),
    );
    whole.root_signal = Nullable::some("S".repeat(300_000));
    whole.ownership_coverage = OwnershipCoverage::Complete;
    let reduced = whole.reduced_for_a_device();
    assert!(reduced.terminated.is_empty());
    assert_eq!(reduced.surviving.len(), 1);
    let omitted = reduced.omitted().expect("the entry");
    assert_eq!((omitted.ended, omitted.other), (5_000, 300));
    assert_eq!(omitted.reason, OmissionReason::Connection);
    assert!(!reduced.survivors().is_empty() || reduced.left_something());
    assert_eq!(
        reduced.root_signal.as_ref().expect("a signal").len(),
        CLOSURE_TEXT_BYTES
    );
    assert_eq!(reduced.ownership_coverage, OwnershipCoverage::Complete);
    assert_eq!(reduced.session_id, whole.session_id);
    assert!(size(&reduced) <= 1_536 + 512, "{}", size(&reduced));

    // The counts of a cut that was made before are added, whichever reason it gave.
    let cut = whole.bounded(20_000);
    let before = cut.omitted().expect("the worker's entry");
    let again = cut.reduced_for_a_device();
    let omitted = again.omitted().expect("the entry");
    assert_eq!(
        omitted.ended,
        before.ended + u64::try_from(cut.terminated.len()).expect("a count")
    );
    assert_eq!(
        omitted.other,
        before.other + u64::try_from(cut.survivors().len()).expect("a count")
    );
    assert_eq!(again.surviving.len(), 1);
}

/// KR-REQ-09.22: a record that nothing cut reads as it did before this entry, and a record that
/// holds the entry meets the hold rule of an older daemon, which keeps the writer registration for
/// any survivor of a kind it does not know.
#[test]
fn a_stored_record_reads_as_before_and_an_older_hold_rule_keeps_the_entry() {
    fn older_hold_rule_ends_the_registration(record: &ClosureRecord) -> bool {
        record.surviving.is_empty()
    }
    let uncut = record(
        vec![ended(1, None)],
        vec![survivor("process", "process 4521 is still running")],
    );
    assert_eq!(uncut.omitted(), None);
    assert_eq!(uncut.survivors(), uncut.surviving.as_slice());
    assert_eq!(uncut.left_something(), !uncut.surviving.is_empty());

    let cut = record((0..100).map(|pid| ended(pid, None)).collect(), Vec::new()).bounded(100);
    assert!(cut.omitted().is_some());
    assert!(!older_hold_rule_ends_the_registration(&cut));
}

/// KR-REQ-09.22: the allowance for an entry the host rewrites is the larger encoding less its own,
/// headers included, for a kind and a detail of any length.
#[test]
fn the_device_extra_of_a_record_is_what_its_entries_grow_by_as_shown() {
    assert_eq!(WHY_NOT_SHOWN.len(), 60);
    let mut expected = 0;
    let mut entries = Vec::new();
    for kind_len in [0, 1, 7, 14, 17, 23, 24, 100, 255, 256, 1_024] {
        for detail_len in [0, 1, 23, 24, 70, 255, 256, 1_024] {
            let entry = survivor(&"k".repeat(kind_len), &"d".repeat(detail_len));
            let shown = survivor(&entry.kind, &format!("{}: {WHY_NOT_SHOWN}", entry.kind));
            expected += size(&shown).saturating_sub(size(&entry));
            entries.push(entry);
        }
    }
    assert_eq!(record(Vec::new(), entries).device_extra(), expected);

    // One byte of detail under a kind of 14 bytes grows by 75 bytes of text and one of header.
    let one = record(Vec::new(), vec![survivor("abcdefghijklmn", "/")]);
    assert_eq!(one.device_extra(), 14 + 62 - 1 + 1);
    // An entry that already says more than the device is given grows by nothing.
    let long = record(Vec::new(), vec![survivor("p", &"d".repeat(500))]);
    assert_eq!(long.device_extra(), 0);
    // A terminated list is not rewritten, so it adds nothing.
    assert_eq!(
        record(vec![ended(1, Some("/usr/bin/x"))], Vec::new()).device_extra(),
        0
    );
}
