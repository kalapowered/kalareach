//! A session's screen restored at every point of its output, in a worker's own session.
//!
//! Each corpus under `fixtures/faults/restore/` is fed to a worker's session one byte at a time,
//! and at every point a terminal of the session's size and a terminal of another size attach, as a
//! person's clients attach, and are checked against the session's own screen until after the next
//! buffer switch. What is checked is written in `kr_faults::restore`.
//!
//! The last three tests plant a defect in the terminal of the session's size, and show that each
//! check fails on the defect it is there for: a check that could not fail would pass here for
//! nothing.

use kr_faults::corpus::{self, Corpus};
use kr_faults::restore::{Beforehand, Outcome, Property, Strategy, run, run_on};

fn corpus(name: &str) -> Corpus {
    Corpus::load(&corpus::directory().join(format!("{name}.json")))
        .unwrap_or_else(|error| panic!("{error}"))
}

fn restored(name: &str) -> Outcome {
    let corpus = corpus(name);
    let outcome = run(&corpus, Strategy::Product).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        outcome.points,
        corpus.bytes().len() + 1,
        "a pair of clients arrives at every point of {name}"
    );
    assert!(
        outcome.failures.is_empty(),
        "{name}, {} failure(s):\n{}",
        outcome.failures.len(),
        outcome
            .failures
            .iter()
            .take(40)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
    outcome
}

/// KR-REQ-27.06: a client that arrives anywhere in a command's ordinary output, between the bytes
/// of a colour change or a redrawn progress line, holds the session's screen and is handed the rest
/// of the output exactly once.
#[test]
fn a_client_arriving_anywhere_in_ordinary_output_holds_the_screen() {
    let outcome = restored("mid-output");
    assert!(
        outcome.restorations > 0,
        "some client was handed the stream"
    );
}

/// KR-REQ-27.06: a client that arrives inside any sequence (a title, a scalar of two to four
/// bytes, a broken one, a combining mark, a designation, a long link, a status query) holds the
/// session's screen once the sequence is done, and the stream never reaches it part way through
/// one.
#[test]
fn a_client_arriving_inside_any_sequence_holds_the_screen_once_it_is_done() {
    let outcome = restored("sequences");
    assert!(outcome.comparisons > 0);
}

/// KR-REQ-27.06: a client that arrives before, inside or after the switch into a full-screen
/// application's buffer, or its switch back, holds that buffer and the one beneath it: on the way
/// out it shows the shell's lines as the session does.
#[test]
fn a_client_arriving_at_a_switch_through_mode_1049_holds_both_buffers() {
    restored("alternate-1049");
}

/// KR-REQ-27.06: the same through mode 1047, with cursors saved around the switches by DECSC and
/// DECRC and through mode 1048, and a request for mode 47, which the profile does not include and
/// the session consumes without switching.
#[test]
fn a_client_arriving_at_a_switch_through_mode_1047_holds_both_buffers() {
    restored("alternate-47-1047");
}

/// KR-REQ-27.06: the same through a nested entry, a soft reset inside the alternate buffer and a
/// full reset of the screen.
#[test]
fn a_client_arriving_around_a_reset_of_the_alternate_buffer_holds_the_screen() {
    restored("alternate-resets");
}

/// KR-REQ-27.06: a clipboard write, a bell, a notification or a query that happened before a
/// client arrived never happens to that client, whatever point it arrived at; one that happens
/// after it arrived reaches the client holding the input lease once and no other client. That
/// includes an effect a client that joined inside its sequence is owed, when the byte that ends the
/// sequence is also the byte that lets the client take the stream.
#[test]
fn a_side_effect_from_before_a_client_arrived_never_reaches_it() {
    let outcome = restored("side-effects");
    assert!(
        outcome.live_effects >= 4,
        "the clipboard writes and bells after the first point were followed to their holders: {}",
        outcome.live_effects
    );
}

/// KR-REQ-08.83 and KR-REQ-27.06: a terminal an earlier application ran in holds the session's screen
/// after its restoration and through the output that follows, whatever that application left in
/// it, and whether or not the terminal acts on a soft reset.
///
/// The terminal is in origin mode inside a scroll region, has DEC line drawing in both character
/// sets, a pen and insert mode, holds a saved cursor in each buffer, and ignores the soft reset, as
/// Alacritty, Ghostty, tmux and GNU screen do. A restoration that relied on the soft reset to put
/// any of that right would draw into it. A soft reset the application sends is not forwarded to
/// such a terminal: the session tells it to begin again, which is why the corpus that has the
/// application send one is run too.
#[test]
fn a_terminal_an_earlier_application_left_in_a_state_holds_the_screen_after_its_restoration() {
    for corpus in Corpus::all().unwrap_or_else(|error| panic!("{error}")) {
        let outcome = run_on(&corpus, Strategy::Product, Beforehand::LeftByAnApplication)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            outcome.restorations > 0,
            "{}: some client was handed the stream",
            corpus.name
        );
        assert!(
            outcome.failures.is_empty(),
            "{}, {} failure(s):\n{}",
            corpus.name,
            outcome.failures.len(),
            outcome
                .failures
                .iter()
                .take(40)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

/// Every corpus kept for this suite is one a test above runs, so a corpus added without a test is
/// not silently left out.
#[test]
fn every_kept_corpus_is_run() {
    let named = [
        "alternate-1049",
        "alternate-47-1047",
        "alternate-resets",
        "mid-output",
        "sequences",
        "side-effects",
    ];
    let kept: Vec<String> = Corpus::all()
        .unwrap_or_else(|error| panic!("{error}"))
        .into_iter()
        .map(|corpus| corpus.name)
        .collect();
    assert_eq!(kept, named, "each corpus has its test");
}

/// A restoration that replays the retained output performs the clipboard write, the bell and the
/// notification the application made before the client arrived, and the check says so.
#[test]
fn a_restoration_that_replays_the_output_fails_the_check_it_is_there_for() {
    let outcome =
        run(&corpus("side-effects"), Strategy::Replay).unwrap_or_else(|error| panic!("{error}"));
    let caught = outcome.of(Property::NoReplay);
    assert!(
        caught
            .iter()
            .any(|failure| failure.what.contains("ClipboardWrite")),
        "the replayed clipboard write is caught: {caught:#?}"
    );
    assert!(
        caught.iter().any(|failure| failure.what.contains("OSC 52")),
        "and the sequence is named in the bytes: {caught:#?}"
    );
}

/// A restoration without the buffer that is not showing leaves the terminal of a client that
/// arrived while a full-screen application was running without the shell's lines, and the check
/// taken directly after the restoration says so.
#[test]
fn a_restoration_without_the_other_buffer_fails_the_check_it_is_there_for() {
    let outcome = run(&corpus("alternate-1049"), Strategy::WithoutInactive)
        .unwrap_or_else(|error| panic!("{error}"));
    let caught = outcome.of(Property::Restored);
    assert!(
        caught
            .iter()
            .any(|failure| failure.what.contains("other buffer's line")),
        "the missing buffer is caught when the screen is restored: {caught:#?}"
    );
}

/// A restoration whose switches into and out of the buffer that is not showing go the other way
/// puts the shell's lines where the application's belong and the other way round, and the check
/// taken directly after the restoration says so.
#[test]
fn a_restoration_with_its_switches_reversed_fails_the_check_it_is_there_for() {
    let outcome = run(&corpus("alternate-resets"), Strategy::ReversedSwitch)
        .unwrap_or_else(|error| panic!("{error}"));
    let caught = outcome.of(Property::Restored);
    assert!(
        caught
            .iter()
            .any(|failure| failure.what.contains("other buffer's line")),
        "the buffers painted the wrong way round are caught: {caught:#?}"
    );
}

/// A terminal drawn the screen where it arrived and handed the raw output from that point, rather
/// than from where the parser stands on ground, shows what nobody wrote once it arrives inside a
/// sequence, and the check says so.
#[test]
fn a_terminal_handed_the_output_from_where_it_arrived_fails_the_check_it_is_there_for() {
    let outcome = run(&corpus("sequences"), Strategy::RawFromOffset)
        .unwrap_or_else(|error| panic!("{error}"));
    let caught = outcome.of(Property::Continuity);
    assert!(
        caught.iter().any(|failure| failure.client == "direct"),
        "a direct client that arrived inside a sequence is caught; found instead:\n{}",
        outcome
            .failures
            .iter()
            .take(12)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
}
