//! What the host's grammar reads of what a person said, as a table of utterances.
//!
//! The grammar is closed, so the table is the specification: each line is something a person says,
//! written as a provider's transcript writes it, and what the host reads of it. A request is one of
//! the three the grammar holds; anything else is not a request, and a number that cannot be read
//! is its own answer.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-15.11 | `the_grammar_reads_the_requests_it_holds_and_nothing_else`, `a_mark_in_or_beside_a_number_leaves_no_number` |

use kr_protocol::ids::SessionId;
use kr_protocol::scalars::{U64, Uuid};
use kr_protocol::voice::{FragmentText, TranscriptFragment, VoiceAction};
use kr_voice::interpret::SpokenDestination;
use kr_voice::{DelegationInterpreter, GrammarInterpreter, Misread};

fn fragments(texts: &[&str]) -> Vec<TranscriptFragment> {
    texts
        .iter()
        .enumerate()
        .map(|(index, text)| TranscriptFragment {
            start_ms: U64::new(u64::try_from(index).expect("a small index") * 100),
            end_ms: U64::new(u64::try_from(index).expect("a small index") * 100 + 90),
            text: FragmentText::new(*text).expect("a fragment"),
        })
        .collect()
}

/// What the host read: the action and the number of the session it names, when it names one.
type Read = (VoiceAction, Option<u64>);

fn read(texts: &[&str]) -> Result<Read, Misread> {
    GrammarInterpreter.interpret(&fragments(texts)).map(|read| {
        assert!(read.spoken_destination.is_none() && read.approval.is_none());
        assert!(read.turn_id.is_none());
        (read.action, read.session_number)
    })
}

/// KR-REQ-15.11: the requests the grammar holds, in the forms a transcript writes them, and the
/// words it refuses.
#[test]
fn the_grammar_reads_the_requests_it_holds_and_nothing_else() {
    use VoiceAction::{Brief, Navigate, Status};

    let reads: &[(&[&str], Read)] = &[
        // Status, in each lead the grammar holds, with the session named in digits and in words.
        (&["status"], (Status, None)),
        (&["Status."], (Status, None)),
        (&["status session 3"], (Status, Some(3))),
        (&["Status of session three."], (Status, Some(3))),
        (&["status for the session three"], (Status, Some(3))),
        (&["What is the status of session 12?"], (Status, Some(12))),
        (
            &["What's the status of session twelve?"],
            (Status, Some(12)),
        ),
        (&["give me the status of session one"], (Status, Some(1))),
        (
            &["please tell me the status of session 4"],
            (Status, Some(4)),
        ),
        (
            &["Could you show me the status of session 4, please?"],
            (Status, Some(4)),
        ),
        // A briefing.
        (&["brief"], (Brief, None)),
        (&["brief me"], (Brief, None)),
        (&["Brief me on session 2."], (Brief, Some(2))),
        (&["briefing on session two"], (Brief, Some(2))),
        (&["Give me a briefing about session 7"], (Brief, Some(7))),
        // Going to a session.
        (&["go to session 5"], (Navigate, Some(5))),
        (&["Switch to session five."], (Navigate, Some(5))),
        (&["open session 6"], (Navigate, Some(6))),
        (&["show me session 6"], (Navigate, Some(6))),
        (&["take me to the session six"], (Navigate, Some(6))),
        // Numbers: digits, words, and a ten with a unit, however the hyphen was written.
        (&["status session 0"], (Status, Some(0))),
        (&["status session twenty"], (Status, Some(20))),
        (&["status session twenty-three"], (Status, Some(23))),
        (&["status session twenty three"], (Status, Some(23))),
        (&["status session ninety nine"], (Status, Some(99))),
        (&["status session 104"], (Status, Some(104))),
        (&["status session twenty\u{2011}three"], (Status, Some(23))),
        // Said in pieces: the fragments are one utterance, and a piece may end in the hyphen.
        (&["status of", "session", "three"], (Status, Some(3))),
        (&["Go to", "session 5."], (Navigate, Some(5))),
        (&["status of session twenty-", "three"], (Status, Some(23))),
        // Marks round the words: quotation marks, brackets, the stops of a sentence, an apostrophe
        // in a word written straight or curly, and a mark that closes the utterance on its own.
        (&["\u{201c}Status of session 3.\u{201d}"], (Status, Some(3))),
        (&["\"open session 6.\""], (Navigate, Some(6))),
        (
            &["What\u{2019}s the status of session 3"],
            (Status, Some(3)),
        ),
        (&["status of session twenty-three."], (Status, Some(23))),
        (&["status of session 3 ."], (Status, Some(3))),
        (&["status of session 3", "?"], (Status, Some(3))),
    ];
    for (texts, expected) in reads {
        assert_eq!(read(texts), Ok(*expected), "{texts:?}");
    }

    let refused: &[(&[&str], Misread)] = &[
        // Not a request at all.
        (&["hello"], Misread::NotARequest),
        (&["session three"], Misread::NotARequest),
        (&["go to"], Misread::NotARequest),
        (&["open"], Misread::NotARequest),
        (&["status please session three"], Misread::NotARequest),
        // A second request, or more than one: the whole utterance has to be the request.
        (&["status session three and close it"], Misread::NotARequest),
        (&["status session 3 4"], Misread::NotARequest),
        (
            &["brief me on session two then go to session three"],
            Misread::NotARequest,
        ),
        (&["status session twenty ten"], Misread::NotARequest),
        // Negation and every word the grammar does not hold.
        (
            &["do not give me the status of session three"],
            Misread::NotARequest,
        ),
        (&["don't brief me"], Misread::NotARequest),
        (&["never go to session 2"], Misread::NotARequest),
        (&["close session three"], Misread::NotARequest),
        (&["run the tests in session three"], Misread::NotARequest),
        (&["status of the other session"], Misread::NotARequest),
        // A sign or a point beside a number changes what it says, and is never dropped.
        (&["open session -3"], Misread::UnreadableNumber),
        (&["open session .3"], Misread::UnreadableNumber),
        (&["status session 3.5"], Misread::UnreadableNumber),
        (&["status session 1,000"], Misread::UnreadableNumber),
        (&["status session +3"], Misread::UnreadableNumber),
        (&["go to session 3/4"], Misread::UnreadableNumber),
        (&["status session - 3"], Misread::UnreadableNumber),
        (&["open session ."], Misread::UnreadableNumber),
        (&["open session .", "3"], Misread::UnreadableNumber),
        (&["open session (", "3)"], Misread::UnreadableNumber),
        (&["status session 3'4"], Misread::UnreadableNumber),
        (&["status session 1\u{2019}000"], Misread::UnreadableNumber),
        (&["status session #3"], Misread::UnreadableNumber),
        // A point or a comma with no space after it is how a decimal or a thousand is written, so
        // "3,please" is no number followed by a word.
        (&["status session 3,please"], Misread::UnreadableNumber),
        // A mark that is not a stop stays a word, wherever it stands.
        (&["status session 3 -"], Misread::NotARequest),
        (&["status \u{2014} session 3"], Misread::NotARequest),
        // A number that cannot be read.
        (&["status session"], Misread::UnreadableNumber),
        (&["status session banana"], Misread::UnreadableNumber),
        (&["go to session"], Misread::UnreadableNumber),
        (
            &["status session 99999999999999999999999"],
            Misread::UnreadableNumber,
        ),
        (&["status session thirty zero"], Misread::NotARequest),
        // A mark between a ten and its unit makes two numbers, never twenty-three.
        (&["open session twenty.", "Three."], Misread::NotARequest),
        (&["open session twenty, three"], Misread::NotARequest),
        (&["open session twenty (three)"], Misread::NotARequest),
        (&["open session twenty - three"], Misread::NotARequest),
        // A number said in words and left unfinished is no number: a hyphen that runs on to
        // nothing, or a trailing off.
        (&["open session twenty-"], Misread::UnreadableNumber),
        (&["go to session twenty- please"], Misread::UnreadableNumber),
        (&["open session twenty\u{2026}"], Misread::UnreadableNumber),
        // Several marks together are no stop, and a mark after a number that is not one stays in it.
        (&["status session 3.."], Misread::UnreadableNumber),
        (
            &["what's the status of session 3?!"],
            Misread::UnreadableNumber,
        ),
        (&["status of session 3\u{2026}"], Misread::UnreadableNumber),
        (&["status session 3-"], Misread::UnreadableNumber),
        (&["status session 3+"], Misread::UnreadableNumber),
        (&["status session 3%"], Misread::UnreadableNumber),
        // A bracket round a number sets it apart from the word before it.
        (&["\"Open session (6)\""], Misread::UnreadableNumber),
    ];
    for (texts, expected) in refused {
        assert_eq!(read(texts), Err(*expected), "{texts:?}");
    }
}

/// KR-REQ-15.11: no mark disappears from between the words that name a session, whatever the mark,
/// whatever number is said and however the transcript spaces it, so that the session read is never
/// one the person did not say. The only thing joined across a mark is the hyphen of a ten and its
/// unit.
#[test]
fn a_mark_in_or_beside_a_number_leaves_no_number() {
    const MARKS: &[&str] = &[
        "(", "\"", "'", "\u{201c}", "\u{2018}", "\u{201d}", "\u{2019}", ".", ",", ";", ":", "!",
        "?", "-", "+", "/", "\\", "*", "_", "~", "#", "%", "\u{2026}", "\u{2013}", "\u{2014}",
        "\u{2011}", ")",
    ];
    const HYPHENS: &[&str] = &["-", "\u{2011}"];
    for (first, second) in [("3", "3"), ("twenty", "three")] {
        for mark in MARKS {
            // "twenty-three" is the one number written across a mark.
            let one_number = first == "twenty" && HYPHENS.contains(mark);
            let mut utterances = vec![
                format!("open session {mark}{first}"),
                format!("open session {first} {mark} {second}"),
                format!("open session {first}{mark} {second}"),
                format!("open session {first} {mark}{second}"),
            ];
            if !one_number {
                utterances.push(format!("open session {first}{mark}{second}"));
            }
            for utterance in utterances {
                assert!(
                    read(&[&utterance]).is_err(),
                    "{utterance:?} names no session"
                );
            }
            // The same across the boundary of two fragments.
            if !one_number {
                assert!(
                    read(&[&format!("open session {first}{mark}"), second]).is_err(),
                    "{first}{mark} then {second} names no session"
                );
            }
            assert!(
                read(&[&format!("open session {mark}"), first]).is_err(),
                "{mark:?} then {first} names no session"
            );
        }
    }
}

/// What a person said is content, and a destination the host holds prints without it, so that a
/// log line or a panic message that shows one shows the session and not the words.
#[test]
fn a_spoken_destination_prints_without_the_words() {
    let destination = SpokenDestination {
        session_id: SessionId::new(Uuid::from_bytes([7; 16])),
        spoken_text: "the words nobody should log".to_owned(),
    };
    assert!(!format!("{destination:?}").contains("nobody"));
}
