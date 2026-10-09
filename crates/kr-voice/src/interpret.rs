//! What a person said, read by the host.
//!
//! Section 15 ¶1 and ¶7: the host coordinator interprets delegations. The paired device hands the
//! host the transcript fragments it vouches for ([`TranscriptFragment`]), and this module turns
//! them into the one thing the coordinator then checks: an [`Interpretation`] of what was asked for.
//! No model is called and nothing is guessed. The grammar is closed and says so: the **whole**
//! utterance has to be one of the requests below, and anything else is [`Misread`], with a
//! sentence that tells the person what the host does read.
//!
//! | Said | Becomes |
//! | --- | --- |
//! | "status", "what is the status of session 3" | read the status of the session |
//! | "brief me on session three" | read a briefing on the session |
//! | "go to session 3", "open session twenty one" | go to the session |
//!
//! A session is named by its display number, written as the provider's transcript writes it: in
//! digits (any number a 64-bit number holds), or in words from zero to ninety-nine ("twenty three" and "twenty-three"
//! alike). A request that names no session means the call's
//! one session, when the call reaches only one. A question is the same request. Negation, a
//! second request, a word the grammar does not hold, and a number that cannot be read are each
//! refused, because a host that acted on a guess about what a person meant would be acting on
//! content, and section 19 says content is never authority.

use std::fmt;

use kr_protocol::ids::{AgentTurnId, ApprovalRequestId, SessionId};
use kr_protocol::scalars::Digest256;
use kr_protocol::voice::{TranscriptFragment, VoiceAction};

/// The session a person named in a clear spoken confirmation, for an action that needs one.
///
/// Section 15 ¶13 requires the confirmation to name the destination, so the host checks the name
/// against the session it is about to submit to rather than accepting that one was given. Whether
/// the words were a clear confirmation is the interpreter's to decide, and it gives a destination
/// only for an utterance that is one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpokenDestination {
    /// The session the speaker named.
    pub session_id: SessionId,
}

/// An approval answer, with the details of the request it answers.
///
/// Section 15 ¶13: an approval decision requires the verified request's details and an explicit
/// answer. The host compares the details against the approval it holds, so a model that invented
/// them is refused rather than believed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedApprovalAnswer {
    /// The approval being answered.
    pub approval_request_id: ApprovalRequestId,
    /// The digest of the request's details as the host read them out.
    pub details_digest: Digest256,
    /// The explicit answer. Nothing is inferred from a transcript.
    pub approved: bool,
}

/// What a person asked for, as the host read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interpretation {
    /// What to do.
    pub action: VoiceAction,
    /// The display number of the session the words name, when they name one.
    pub session_number: Option<u64>,
    /// The spoken confirmation naming the destination, for an action that needs one.
    pub spoken_destination: Option<SpokenDestination>,
    /// The approval answer, for an action that answers one.
    pub approval: Option<VerifiedApprovalAnswer>,
    /// The turn to cancel, for an action that cancels one.
    pub turn_id: Option<AgentTurnId>,
}

impl Interpretation {
    /// A request for `action` on the session numbered `session_number`, naming nothing else.
    #[must_use]
    pub const fn of(action: VoiceAction, session_number: Option<u64>) -> Self {
        Self {
            action,
            session_number,
            spoken_destination: None,
            approval: None,
            turn_id: None,
        }
    }
}

/// Why the words were not read as a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Misread {
    /// The words are not one of the requests this host reads, said whole.
    NotARequest,
    /// The words ask about a session by a number that cannot be read.
    UnreadableNumber,
}

impl Misread {
    /// What a person is told. It never quotes what they said.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::NotARequest => {
                "this host reads a request for the status of a session, a briefing on one, or to \
                 go to one, said on its own. Say it again as one of those."
            }
            Self::UnreadableNumber => {
                "the session number could not be read. Say the number of the session, for \
                 example session 3."
            }
        }
    }
}

impl fmt::Display for Misread {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.detail())
    }
}

/// Reads what was said into what was asked for.
///
/// A seam so that the coordinator's own tests can script requests the product grammar does not
/// hold; the host builds the coordinator with [`GrammarInterpreter`] and nothing else.
pub trait DelegationInterpreter: Send + Sync + fmt::Debug {
    /// Reads the fragments of one delegation, in the order they were said.
    ///
    /// # Errors
    ///
    /// Returns why the words are not a request.
    fn interpret(&self, fragments: &[TranscriptFragment]) -> Result<Interpretation, Misread>;
}

/// The grammar of the table at the top of this module.
#[derive(Clone, Copy, Debug, Default)]
pub struct GrammarInterpreter;

/// Ways to begin a request for `action`, as words. Matching tries every one.
const LEADS: &[(VoiceAction, &[&str])] = &[
    (VoiceAction::Status, &["status"]),
    (VoiceAction::Status, &["what", "is", "the", "status"]),
    (VoiceAction::Status, &["what's", "the", "status"]),
    (VoiceAction::Status, &["whats", "the", "status"]),
    (VoiceAction::Status, &["give", "me", "the", "status"]),
    (VoiceAction::Status, &["show", "me", "the", "status"]),
    (VoiceAction::Status, &["tell", "me", "the", "status"]),
    (VoiceAction::Brief, &["brief"]),
    (VoiceAction::Brief, &["briefing"]),
    (VoiceAction::Brief, &["brief", "me"]),
    (VoiceAction::Brief, &["give", "me", "a", "briefing"]),
    (VoiceAction::Brief, &["give", "me", "a", "brief"]),
    (VoiceAction::Brief, &["give", "me", "the", "briefing"]),
    (VoiceAction::Navigate, &["go", "to"]),
    (VoiceAction::Navigate, &["switch", "to"]),
    (VoiceAction::Navigate, &["navigate", "to"]),
    (VoiceAction::Navigate, &["take", "me", "to"]),
    (VoiceAction::Navigate, &["show", "me"]),
    (VoiceAction::Navigate, &["open"]),
];

/// Words that join a status or a briefing to the session it is about.
const CONNECTORS: &[&str] = &["of", "on", "for", "about"];

impl DelegationInterpreter for GrammarInterpreter {
    fn interpret(&self, fragments: &[TranscriptFragment]) -> Result<Interpretation, Misread> {
        let words = words_of(&utterance(fragments));
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        let words = without_politeness(&words);

        let mut worst = Misread::NotARequest;
        for (action, lead) in LEADS {
            let Some(rest) = words.strip_prefix(*lead) else {
                continue;
            };
            match request(*action, rest) {
                Ok(session_number) => return Ok(Interpretation::of(*action, session_number)),
                Err(Misread::UnreadableNumber) => worst = Misread::UnreadableNumber,
                Err(Misread::NotARequest) => {}
            }
        }
        Err(worst)
    }
}

/// The fragments as one text, in the order they were said. A fragment that ends in the hyphen of
/// a word ("twenty-") runs on into the next with no space, so that a number the provider cut at its
/// hyphen is one word again. What follows the hyphen is not checked here: "twenty-" and "please"
/// make "twenty-please", which is no number word and is refused where numbers are read.
fn utterance(fragments: &[TranscriptFragment]) -> String {
    let mut spoken = String::new();
    for fragment in fragments {
        if !spoken.is_empty() && !ends_in_a_joining_hyphen(&spoken) {
            spoken.push(' ');
        }
        spoken.push_str(fragment.text.as_str());
    }
    spoken
}

/// Whether `text` ends in a hyphen that follows a letter.
fn ends_in_a_joining_hyphen(text: &str) -> bool {
    let mut backwards = text.chars().rev();
    matches!(backwards.next(), Some('-' | '\u{2010}' | '\u{2011}'))
        && backwards.next().is_some_and(char::is_alphabetic)
}

/// What stands between two words where a mark was set aside. It holds a space, which no word
/// split at whitespace can hold, so nothing a person says is ever equal to it.
const BOUNDARY: &str = " ";

/// Marks a token may begin with: an opening quotation mark or bracket.
const OPENING: &[char] = &['"', '(', '\''];

/// Marks a token may end with, before and after its stop: a closing quotation mark or bracket.
const CLOSING: &[char] = &[')', '"', '\''];

/// The stops of a sentence. One of them ends a token; several together ("..", "?!") do not, and
/// the token is then no word the grammar holds.
const STOPS: &[char] = &['.', ',', '!', '?', ';', ':'];

/// The words of `spoken`, lower-cased, and a [`BOUNDARY`] wherever a mark was set aside.
///
/// The rule that decides what a word is: **a mark never disappears from between two words.** A
/// mark at the front of a token (an opening quotation mark or bracket) or at its back (a closing
/// one, and one stop) is set aside, and puts a boundary there, so that what stood on either side of
/// it is not read as one thing ("twenty, three" is two words and a boundary, never twenty-three).
/// A boundary at the start or the end of the whole utterance is dropped before the words are read
/// ([`bare`]), so a stop that ends what was said, or a quotation round all of it, costs nothing.
/// **Nothing inside a token is ever removed, and nothing is changed but its case and the variant
/// forms of a mark ([`plain_marks`])**: "-3", ".3", "3.5", "1,000",
/// "3'4" and "3,please" are each one token that is no number, and "what's" is a word of its own,
/// which the leads hold as it is written and as it is written without its apostrophe. A hyphen
/// never stands for a space; the one hyphenated word the grammar holds is a ten and a unit
/// ("twenty-three"), which [`number_of`] reads as the word it is.
fn words_of(spoken: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let set_aside = |words: &mut Vec<String>| {
        if words.last().is_some_and(|last| last != BOUNDARY) {
            words.push(BOUNDARY.to_owned());
        }
    };
    for raw in plain_marks(spoken).split_whitespace() {
        let opened = raw.trim_start_matches(OPENING);
        if opened.len() != raw.len() {
            set_aside(&mut words);
        }
        let closed = opened.trim_end_matches(CLOSING);
        let stopped = closed.strip_suffix(STOPS).unwrap_or(closed);
        let core = stopped.trim_end_matches(CLOSING);
        if !core.is_empty() {
            words.push(core.to_lowercase());
        }
        if core.len() != opened.len() {
            set_aside(&mut words);
        }
    }
    words
}

/// Whether `character` is a mark a transcript writes for an apostrophe: the plain one, the single
/// quotation marks, the modifier letters, the grave and acute accents, the prime and the fullwidth
/// form. Some of them are letters to Unicode, so a rule about marks asks this first.
pub(crate) const fn is_apostrophe(character: char) -> bool {
    matches!(
        character,
        '\'' | '\u{2018}'
            | '\u{2019}'
            | '\u{201b}'
            | '\u{02bb}'
            | '\u{02bc}'
            | '`'
            | '\u{00b4}'
            | '\u{2032}'
            | '\u{ff07}'
            | '\u{a78c}'
    )
}

/// `spoken` with the variants of a quotation mark, an apostrophe and a hyphen that a transcript
/// writes put as the plain mark, so that one rule reads them all. A mark becomes a mark, never a
/// letter, a digit or a space.
fn plain_marks(spoken: &str) -> String {
    spoken
        .chars()
        .map(|each| match each {
            _ if is_apostrophe(each) => '\'',
            '\u{201c}' | '\u{201d}' | '\u{201e}' => '"',
            '\u{2010}' | '\u{2011}' => '-',
            other => other,
        })
        .collect()
}

/// `words` without a boundary at its start or its end.
fn bare<'a, 'b>(words: &'a [&'b str]) -> &'a [&'b str] {
    let mut words = words;
    while let [BOUNDARY, rest @ ..] = words {
        words = rest;
    }
    while let [rest @ .., BOUNDARY] = words {
        words = rest;
    }
    words
}

/// `words` without the courtesies a person puts round a request.
fn without_politeness<'a, 'b>(words: &'a [&'b str]) -> &'a [&'b str] {
    let mut words = bare(words);
    if let [rest @ .., "please"] = words {
        words = bare(rest);
    }
    loop {
        let before = words.len();
        for lead in [
            &["please"][..],
            &["can", "you"],
            &["could", "you"],
            &["would", "you"],
        ] {
            if let Some(rest) = words.strip_prefix(lead) {
                words = bare(rest);
            }
        }
        if words.len() == before {
            return words;
        }
    }
}

/// The rest of a request for `action` after its lead: an optional connector, and the session.
///
/// Returns the session's number, or nothing for a request that names none.
fn request(action: VoiceAction, rest: &[&str]) -> Result<Option<u64>, Misread> {
    let rest = if action == VoiceAction::Navigate {
        rest
    } else if let [first, tail @ ..] = rest {
        if CONNECTORS.contains(first) {
            tail
        } else {
            rest
        }
    } else {
        rest
    };
    if rest.is_empty() {
        // Going somewhere needs somewhere to go; a status or a briefing may mean the call's one
        // session, which the coordinator decides.
        return if action == VoiceAction::Navigate {
            Err(Misread::NotARequest)
        } else {
            Ok(None)
        };
    }
    let rest = rest.strip_prefix(&["the"]).unwrap_or(rest);
    let Some(number) = rest.strip_prefix(&["session"]) else {
        return Err(Misread::NotARequest);
    };
    match number_of(number) {
        Some((value, used)) if used == number.len() => Ok(Some(value)),
        // A number, and then more: a second request, or words the grammar does not hold.
        Some(_) => Err(Misread::NotARequest),
        None => Err(Misread::UnreadableNumber),
    }
}

/// The number the words begin with, and how many words it took, when they begin with one.
fn number_of(words: &[&str]) -> Option<(u64, usize)> {
    let first = *words.first()?;
    if first.bytes().all(|byte| byte.is_ascii_digit()) {
        return first.parse::<u64>().ok().map(|value| (value, 1));
    }
    if let Some(value) = small(first) {
        return Some((value, 1));
    }
    // "twenty-three": a ten and a unit, written as one word. A hyphen that joins anything else, or
    // joins nothing, makes no number.
    if let Some((ten, unit)) = first.split_once('-') {
        let unit = small(unit).filter(|unit| (1..10).contains(unit))?;
        return Some((tens(ten)? + unit, 1));
    }
    let tens = tens(first)?;
    // "twenty three": a ten and then a unit.
    match words.get(1).and_then(|next| small(next)) {
        Some(unit) if (1..10).contains(&unit) => Some((tens + unit, 2)),
        _ => Some((tens, 1)),
    }
}

/// Zero to nineteen, in words.
fn small(word: &str) -> Option<u64> {
    Some(match word {
        "zero" => 0,
        "one" => 1,
        "two" => 2,
        "three" => 3,
        "four" => 4,
        "five" => 5,
        "six" => 6,
        "seven" => 7,
        "eight" => 8,
        "nine" => 9,
        "ten" => 10,
        "eleven" => 11,
        "twelve" => 12,
        "thirteen" => 13,
        "fourteen" => 14,
        "fifteen" => 15,
        "sixteen" => 16,
        "seventeen" => 17,
        "eighteen" => 18,
        "nineteen" => 19,
        _ => return None,
    })
}

/// Twenty to ninety, in words.
fn tens(word: &str) -> Option<u64> {
    Some(match word {
        "twenty" => 20,
        "thirty" => 30,
        "forty" => 40,
        "fifty" => 50,
        "sixty" => 60,
        "seventy" => 70,
        "eighty" => 80,
        "ninety" => 90,
        _ => return None,
    })
}
