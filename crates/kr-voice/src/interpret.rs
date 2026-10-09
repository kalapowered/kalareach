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
//! digits or in words, from zero to ninety-nine. A request that names no session means the call's
//! one session, when the call reaches only one. A question is the same request. Negation, a
//! second request, a word the grammar does not hold, and a number that cannot be read are each
//! refused, because a host that acted on a guess about what a person meant would be acting on
//! content, and section 19 says content is never authority.

use std::fmt;

use kr_protocol::ids::{AgentTurnId, ApprovalRequestId, SessionId};
use kr_protocol::scalars::Digest256;
use kr_protocol::voice::{TranscriptFragment, VoiceAction};

/// A spoken confirmation that names the destination session.
///
/// Section 15 ¶13 requires the confirmation to name the destination, so the host checks the name
/// against the session it is about to submit to rather than accepting that one was given.
#[derive(Clone, PartialEq, Eq)]
pub struct SpokenDestination {
    /// The session the speaker named.
    pub session_id: SessionId,
    /// The words the speaker used, as the transcript recorded them. Data, never authority.
    pub spoken_text: String,
}

impl fmt::Debug for SpokenDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The words are what a person said, and print as nothing.
        formatter
            .debug_struct("SpokenDestination")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
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
        let spoken = fragments
            .iter()
            .map(|fragment| fragment.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let words = words_of(&spoken);
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

/// The words of `spoken`, lower-cased.
///
/// Sentence punctuation after a word ("three.", "three?") and quotation marks round it are not part
/// of it, a hyphen between two letters stands for the space it joins ("twenty-three"), and an
/// apostrophe inside a word is dropped ("what's" is "whats"). Anything else stays in the word, so
/// that a sign or a point beside a number leaves a token that is no number: "-3", ".3", "3.5" and
/// "1,000" are each refused as numbers and never read as the digits they hold.
fn words_of(spoken: &str) -> Vec<String> {
    let mut words = Vec::new();
    for raw in spoken.split_whitespace() {
        let trimmed = raw
            .trim_start_matches(['"', '\u{201c}', '\u{2018}', '(', '\''])
            .trim_end_matches([
                '.', ',', '!', '?', ';', ':', ')', '"', '\u{201d}', '\u{2019}', '\'',
            ]);
        let word: String = trimmed
            .chars()
            .filter(|character| !matches!(character, '\'' | '\u{2019}'))
            .flat_map(char::to_lowercase)
            .collect();
        if word.is_empty() {
            continue;
        }
        // A hyphen joins two letters, or it belongs to the token.
        let characters: Vec<char> = word.chars().collect();
        let joins_letters = characters.contains(&'-')
            && characters.iter().enumerate().all(|(index, each)| {
                *each != '-'
                    || (index > 0
                        && characters[index - 1].is_alphabetic()
                        && characters
                            .get(index + 1)
                            .is_some_and(|next| next.is_alphabetic()))
            });
        if joins_letters {
            words.extend(word.split('-').map(str::to_owned));
        } else {
            words.push(word);
        }
    }
    words
}

/// `words` without the courtesies a person puts round a request.
fn without_politeness<'a, 'b>(words: &'a [&'b str]) -> &'a [&'b str] {
    let mut words = words;
    if let [rest @ .., "please"] = words {
        words = rest;
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
                words = rest;
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
