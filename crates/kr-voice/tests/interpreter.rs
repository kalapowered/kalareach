//! What the host's grammar reads of what a person said, as a table of utterances.
//!
//! The grammar is closed, so the table is the specification: each line is something a person says,
//! written as a provider's transcript writes it, and what the host reads of it. A request is one of
//! the three the grammar holds; anything else is not a request, and a number that cannot be read
//! is its own answer.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-15.11 | `the_grammar_reads_the_requests_it_holds_and_nothing_else` |

use kr_protocol::scalars::U64;
use kr_protocol::voice::{FragmentText, TranscriptFragment, VoiceAction};
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
        // Said in pieces: the fragments are one utterance.
        (&["status of", "session", "three"], (Status, Some(3))),
        (&["Go to", "session 5."], (Navigate, Some(5))),
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
        // A number that cannot be read.
        (&["status session"], Misread::UnreadableNumber),
        (&["status session banana"], Misread::UnreadableNumber),
        (&["go to session"], Misread::UnreadableNumber),
        (
            &["status session 99999999999999999999999"],
            Misread::UnreadableNumber,
        ),
        (&["status session thirty zero"], Misread::NotARequest),
    ];
    for (texts, expected) in refused {
        assert_eq!(read(texts), Err(*expected), "{texts:?}");
    }
}
