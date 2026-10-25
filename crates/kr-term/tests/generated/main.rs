//! Generated streams against the terminal engine's invariants (KR-ACC-024).
//!
//! The corpus tests feed the engine the streams someone thought of. These feed it streams nobody
//! did: C1 controls and malformed UTF-8 at every position, control strings ended every way and not
//! ended, tmux envelopes nested past their bound, control strings past theirs with queries in the
//! tail, and a flood of questions. Each stream is read whole and in three kinds of piece, and a run
//! is held to the invariants in `invariants.rs`.
//!
//! A failing stream is its seed. `KR_FUZZ_STREAMS` sets how many seeds a run takes, from zero; a
//! run takes 1,000 by default, so the test is deterministic and takes a few seconds.

mod generator;
mod invariants;
mod observe;

use generator::{End, Family, Mark, Shape, Stream, Tag, cuts, flood, oversized};
use invariants::{
    Framed, Invariant, Violation, a_flood_is_bounded_and_forwards_only_its_text, check_stream,
    events_cover_the_stream, forwarded_set_is_safe, nothing_past_the_bound_acts,
    read_split_changes_nothing, the_engine_is_in_its_bounds,
};
use kr_term::budget::GridSize;
use observe::{SIZES, feed_in, feed_whole, lex};

fn size_of(pair: (u32, u32)) -> GridSize {
    GridSize::new(pair.0, pair.1)
}

fn streams_per_run() -> u64 {
    std::env::var("KR_FUZZ_STREAMS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1000)
}

fn say(found: &[Violation]) -> String {
    found
        .iter()
        .take(4)
        .map(|violation| format!("{:?}: {}", violation.invariant, violation.detail))
        .collect::<Vec<_>>()
        .join("; ")
}

/// KR-ACC-024: a generated stream of hostile output, read whole and in pieces, never has a query, a
/// side effect, a graphics string, a C1 control or a control string with a control byte in it
/// forwarded to a physical terminal; the engine shows the same screen, side effects, replies and
/// forwarded bytes however the reads are cut; and it ends on ground.
#[test]
fn a_generated_stream_holds_every_invariant_however_it_is_read() {
    let count = streams_per_run();
    let mut report = Vec::new();
    let mut broken = std::collections::BTreeMap::new();
    let mut framed = Framed::default();
    let mut total = 0usize;
    for seed in 0..count {
        let stream = generator::stream(seed);
        total += stream.bytes.len();
        let size = size_of(SIZES[usize::from(seed % 3 == 0)]);
        let (found, here) = check_stream(&stream, size);
        framed.add(here);
        for violation in &found {
            *broken
                .entry(format!("{:?}", violation.invariant))
                .or_insert(0usize) += 1;
        }
        if !found.is_empty() {
            report.push(format!(
                "seed {seed}, {}x{}: {} (stream {:02x?})",
                size.cols,
                size.rows,
                say(&found),
                &stream.bytes[..stream.bytes.len().min(160)]
            ));
        }
    }
    println!("{count} streams, {total} bytes, framed tagged atoms {framed:?}");
    assert!(
        report.is_empty(),
        "{} of {count} streams break an invariant ({broken:?}), first:\n{}",
        report.len(),
        report
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    // The checks on tagged atoms only run on an atom that stands alone at ground, so a generator
    // that never produced one would pass for nothing.
    let count = usize::try_from(count).unwrap_or(usize::MAX);
    assert!(framed.queries >= count / 4, "{framed:?}");
    assert!(framed.side_effects >= count / 4, "{framed:?}");
    assert!(framed.graphics >= count / 20, "{framed:?}");
}

/// KR-ACC-024: a control string past its bound is discarded whole and nothing in it acts, whether
/// it is ended or not, and whatever is in its tail; what follows a string that ended is read as
/// ordinary output; a clipboard write happens only for a string that is whole and inside its bound.
#[test]
fn nothing_past_the_bound_of_a_control_string_acts() {
    let mut report = Vec::new();
    let mut seed = 0;
    for family in Family::ALL {
        for past_bound in [false, true] {
            for end in [End::St, End::Bel, End::Can, End::Open] {
                if (end == End::Bel && !family.is_osc()) || (!past_bound && end == End::Open) {
                    continue;
                }
                seed += 1;
                let shape = Shape {
                    family,
                    past_bound,
                    end,
                };
                let case = oversized(seed, shape);
                let size = size_of(SIZES[0]);
                let bytes = &case.stream.bytes;
                let events = lex(bytes);
                let whole = feed_whole(bytes, size);
                let mut found = forwarded_set_is_safe(&case.stream, &events, &whole, size).0;
                found.extend(events_cover_the_stream(bytes, &events));
                found.extend(the_engine_is_in_its_bounds(&whole));
                found.extend(nothing_past_the_bound_acts(&case, &whole));
                for how in 1..generator::SPLITS {
                    if how == 1 && bytes.len() > invariants::BYTE_AT_A_TIME_LIMIT {
                        continue;
                    }
                    let split = feed_in(bytes, &cuts(seed, bytes.len(), how), size);
                    found.extend(read_split_changes_nothing(&whole, &split, how));
                    found.extend(nothing_past_the_bound_acts(&case, &split));
                }
                if !found.is_empty() {
                    report.push(format!("{shape:?}, {} bytes: {}", bytes.len(), say(&found)));
                }
            }
        }
    }
    assert!(report.is_empty(), "{}", report.join("\n"));
}

/// KR-ACC-024: a flood of queries is reported, never grows the response lane past its bound, and
/// forwards none of its queries, only the text between them.
#[test]
fn a_flood_of_queries_stays_in_its_bound_and_forwards_only_its_text() {
    let flood = flood(77, 70_000);
    let size = size_of(SIZES[0]);
    let bytes = &flood.stream.bytes;
    let events = lex(bytes);
    let seen = feed_in(bytes, &cuts(1, bytes.len(), 3), size);
    let mut found = a_flood_is_bounded_and_forwards_only_its_text(&flood.text, &seen);
    found.extend(forwarded_set_is_safe(&flood.stream, &events, &seen, size).0);
    assert!(found.is_empty(), "{}", say(&found));
}

fn names(found: &[Violation], wanted: &[Invariant]) {
    for invariant in wanted {
        assert!(
            found
                .iter()
                .any(|violation| violation.invariant == *invariant),
            "{invariant:?} is not named in {found:?}"
        );
    }
}

/// A forwarded set the engine did not produce, checked after the engine's own set is.
fn forged(bytes: &[u8], marks: Vec<Mark>, spans: &[(u64, u64)]) -> Vec<Violation> {
    let size = size_of(SIZES[0]);
    let stream = Stream {
        seed: 0,
        bytes: bytes.to_vec(),
        marks,
    };
    let events = lex(bytes);
    let genuine = feed_whole(bytes, size);
    let control = forwarded_set_is_safe(&stream, &events, &genuine, size).0;
    assert!(
        control.is_empty(),
        "the engine's own run of the stream fails: {}",
        say(&control)
    );
    forwarded_set_is_safe(&stream, &events, &genuine.forging(bytes, spans), size).0
}

/// KR-ACC-024: the checks on the forwarded set fail on the defects they are there for. The engine's
/// own run of each stream passes them, and a forwarded set with a query, a clipboard write, a raw C1
/// control, an encoded C1 scalar or a control string with a control byte in it is named.
#[test]
fn the_checks_name_a_forwarded_set_that_carries_what_must_not_reach_a_terminal() {
    let query = b"ok\x1b[6n";
    names(
        &forged(
            query,
            vec![Mark {
                start: 2,
                end: 6,
                tag: Tag::Query,
            }],
            &[(0, query.len() as u64)],
        ),
        &[
            Invariant::Forwardable,
            Invariant::FixedPoint,
            Invariant::Tagged,
        ],
    );

    let write = b"a\x1b]52;c;aGk=\x07b";
    names(
        &forged(
            write,
            vec![Mark {
                start: 1,
                end: 13,
                tag: Tag::SideEffect,
            }],
            &[(0, write.len() as u64)],
        ),
        &[
            Invariant::Forwardable,
            Invariant::FixedPoint,
            Invariant::Tagged,
        ],
    );

    let ind = b"a\x84b";
    names(
        &forged(ind, Vec::new(), &[(0, ind.len() as u64)]),
        &[Invariant::Forwardable, Invariant::ByteSafety],
    );

    let scalar = "a\u{85}b".as_bytes();
    names(
        &forged(scalar, Vec::new(), &[(0, scalar.len() as u64)]),
        &[Invariant::Forwardable, Invariant::ByteSafety],
    );

    let embedded = b"a\x1b]2;ti\x08tle\x07b";
    names(
        &forged(embedded, Vec::new(), &[(0, embedded.len() as u64)]),
        &[Invariant::Forwardable, Invariant::ByteSafety],
    );
}

/// KR-ACC-024: the check on an oversized string names a query in its tail that was answered or
/// forwarded, and a clipboard write from a string past its bound.
#[test]
fn the_checks_name_a_query_in_the_tail_of_an_oversized_string_that_acts() {
    let shape = Shape {
        family: Family::Osc,
        past_bound: true,
        end: End::Open,
    };
    let case = oversized(5, shape);
    let size = size_of(SIZES[0]);
    let genuine = feed_whole(&case.stream.bytes, size);
    assert!(
        nothing_past_the_bound_acts(&case, &genuine).is_empty(),
        "the engine's own run of the string passes"
    );

    let mut answered = genuine.clone();
    answered.replies.push((case.inside[0], b"\x1b[0n".to_vec()));
    names(
        &nothing_past_the_bound_acts(&case, &answered),
        &[Invariant::Oversized],
    );

    let at = case.inside[0];
    let spans = [(at, at + 4)];
    let events = lex(&case.stream.bytes);
    let forwarded = genuine.forging(&case.stream.bytes, &spans);
    names(
        &forwarded_set_is_safe(&case.stream, &events, &forwarded, size).0,
        &[Invariant::Forwardable],
    );

    let mut written = genuine;
    written.side_effects.push((
        kr_term::sideeffect::SideEffectKind::ClipboardWrite {
            selection: kr_term::sideeffect::ClipboardSelection::Clipboard,
            content: b"x".to_vec(),
        },
        case.string_at,
    ));
    names(
        &nothing_past_the_bound_acts(&case, &written),
        &[Invariant::Oversized],
    );
}
