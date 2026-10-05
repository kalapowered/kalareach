//! The grammar, the validated result, and every reason one is refused.
//!
//! Section 22 asks for *grammar-constrained JSON* with four fields, two codepoint limits, and a
//! list of things to reject. Both halves are here, and they are deliberately not the same
//! mechanism.
//!
//! The grammar is a constraint on generation: [`DESCRIPTION_GRAMMAR`] is given to the sampler, so
//! the only token sequences the model can produce are the ones that parse. It is what makes a
//! malicious project name unable to change the *shape* of the answer.
//!
//! The validation is a constraint on publication, and it does not trust the grammar. A runtime
//! that ignored its grammar, a build with the constraint misconfigured and a result that has been
//! sitting in a queue while the world moved on all reach [`validate`], and it refuses each of them.
//! Nothing here normalises a result into acceptability: section 22 says *reject*, and a title with
//! a control character in it is evidence that something upstream is wrong rather than something to
//! tidy up.
//!
//! # What a validated description cannot do
//!
//! [`GeneratedDescription`] has a title, an activity line, the cursor interval it covers and the
//! revision it was produced at. It has no status, no permission, no workflow transition and no
//! review outcome, and there is no function in this crate that turns one into any of those. That
//! is section 22's *contextual descriptions are labelled generated and never drive permission,
//! workflow or review-completion transitions*, expressed as a missing capability rather than as a
//! rule somebody enforces.

use kr_worker::privacy::PrivacyGeneration;
use serde::Deserialize;
use unicode_segmentation::UnicodeSegmentation;

use kr_protocol::ids::SessionEpoch;

use crate::context::{ContextBinding, ContextRevision, CursorInterval};
use crate::metadata::{
    ActivityText, MAX_ACTIVITY_CODEPOINTS, MAX_SUMMARY_CODEPOINTS, MAX_TITLE_CODEPOINTS,
    SummaryText, Title,
};
use crate::profile::ProfileRevision;
use crate::prompt::PromptKind;

/// The grammar every description is generated under.
///
/// It admits exactly one object, with exactly the four fields section 22 names, in one order. The
/// two string fields admit every character but the control ranges, the two delimiters, and the
/// bidirectional controls and line separators that [`validate`] refuses, so a title with a newline
/// or a right-to-left override in it is not merely rejected later: it cannot be sampled. What the
/// character class admits is everything but [`crate::metadata::is_forbidden_in_a_label`], the quote
/// and the backslash, and a test holds the two equal over every codepoint. The bounds are the
/// section's own, counted in codepoints, which is what a GBNF repetition over a character class
/// counts, and the numbers are JSON integers rather than digit runs, so a leading zero cannot be
/// produced either.
///
/// The class lists what is admitted and does not name what is left out, and that is deliberate.
/// A byte-level vocabulary has tokens that end inside a character, and llama.cpp admits one of
/// them when some character it could finish is in a listed class, and refuses it when some
/// character it could finish is in a negated class's excluded set. Left out by name, the
/// bidirectional controls would refuse every token that ends in the first byte of an Arabic or a
/// Persian letter or of the joiners, and the model could no longer copy the text it was given.
pub const DESCRIPTION_GRAMMAR: &str = r#"root ::= "{" ws "\"title\":" ws title "," ws "\"activity_text\":" ws activity "," ws "\"source_cursor\":" ws cursor "," ws "\"context_revision\":" ws number ws "}"
title ::= "\"" char{1,64} "\""
activity ::= "\"" char{1,160} "\""
cursor ::= "{" ws "\"from\":" ws number "," ws "\"to\":" ws number ws "}"
char ::= [\x20-\x21\x23-\x5B\x5D-\x7E\xA0-\u061B\u061D-\u200D\u2010-\u2027\u202F-\u2065\u206A-\uD7FF\uE000-\U0010FFFF]
number ::= "0" | [1-9] [0-9]{0,18}
ws ::= " "?
"#;

/// The grammar every summary is generated under.
///
/// It admits exactly one object, with the summary text and the interval it repeats, in one order.
/// The text admits what a description's strings admit and is bounded as section 18's summary is,
/// in codepoints; the interval is the grammar's own and is repeated from the prompt, so the object
/// has the shape of a description's and is held to the same rules by [`validate_summary`].
pub const SUMMARY_GRAMMAR: &str = r#"root ::= "{" ws "\"summary\":" ws summary "," ws "\"source_cursor\":" ws cursor ws "}"
summary ::= "\"" char{1,400} "\""
cursor ::= "{" ws "\"from\":" ws number "," ws "\"to\":" ws number ws "}"
char ::= [\x20-\x21\x23-\x5B\x5D-\x7E\xA0-\u061B\u061D-\u200D\u2010-\u2027\u202F-\u2065\u206A-\uD7FF\uE000-\U0010FFFF]
number ::= "0" | [1-9] [0-9]{0,18}
ws ::= " "?
"#;

/// What the model is asked to produce, as JSON, before any of it is trusted.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDescription {
    title: String,
    activity_text: String,
    source_cursor: CursorInterval,
    context_revision: u64,
}

/// What the model is asked to produce of a summary, as JSON, before any of it is trusted.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSummary {
    summary: String,
    source_cursor: CursorInterval,
}

/// Why a result was not published.
///
/// Every one of these is an ordinary outcome rather than an error: asking a model for something and
/// refusing what comes back is the design working. The session keeps the title it had.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The bytes are not the JSON object the grammar describes.
    Malformed {
        /// What the parser said.
        detail: String,
    },
    /// A field this product does not know, or a missing one.
    InvalidFields {
        /// What the parser said.
        detail: String,
    },
    /// A control character reached a field the grammar excludes them from.
    ControlCharacter {
        /// Which field.
        field: &'static str,
    },
    /// A field is empty, or longer than section 22's bound.
    OutOfBounds {
        /// Which field.
        field: &'static str,
        /// The bound.
        limit: usize,
        /// What arrived.
        found: usize,
    },
    /// The result names a different session epoch.
    WrongSessionEpoch {
        /// The epoch in force.
        expected: SessionEpoch,
        /// The epoch the result names.
        found: SessionEpoch,
    },
    /// The context moved while the job was running.
    ChangedContext {
        /// The revision in force.
        expected: ContextRevision,
        /// The revision the result was produced at.
        found: ContextRevision,
    },
    /// The session's binding changed while the job was running.
    ChangedBinding {
        /// The binding in force.
        expected: ContextBinding,
        /// The binding the job was admitted under.
        found: ContextBinding,
    },
    /// The model was remapped while the job was running.
    StaleProfileRevision {
        /// The profile in force, as identifier and revision.
        expected: (String, ProfileRevision),
        /// What the result was produced under.
        found: (String, ProfileRevision),
    },
    /// The result did not repeat the revision or the cursor interval its job was built from.
    ///
    /// It is a rejection rather than a correction: a runtime whose grammar let it invent a
    /// provenance field is a runtime whose other fields are worth no more.
    ProvenanceMismatch {
        /// Which field.
        field: &'static str,
    },
    /// Privacy mode's generation moved while the job was running.
    LateGeneration {
        /// The generation in force.
        expected: PrivacyGeneration,
        /// The generation the job was produced under.
        found: PrivacyGeneration,
    },
    /// Nothing admits a publication under the generation the job was produced under: privacy mode
    /// is on, or the generation moved on while the job ran.
    NotAdmitted {
        /// The generation the job was produced under.
        found: PrivacyGeneration,
    },
    /// The session's name is pinned. Generated text never overwrites one.
    NamePinned,
    /// The session closed while its job was running.
    SessionClosed,
}

impl Rejection {
    /// Returns the stable reason this rejection is reported under.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Malformed { .. } => "malformed",
            Self::InvalidFields { .. } => "invalid_fields",
            Self::ControlCharacter { .. } => "control_character",
            Self::OutOfBounds { .. } => "out_of_bounds",
            Self::WrongSessionEpoch { .. } => "wrong_session_epoch",
            Self::ChangedContext { .. } => "changed_context",
            Self::ChangedBinding { .. } => "changed_binding",
            Self::StaleProfileRevision { .. } => "stale_profile_revision",
            Self::ProvenanceMismatch { .. } => "provenance_mismatch",
            Self::LateGeneration { .. } => "late_generation",
            Self::NotAdmitted { .. } => "not_admitted",
            Self::NamePinned => "name_pinned",
            Self::SessionClosed => "session_closed",
        }
    }
}

/// What a result has to match to be published.
///
/// It is read at publication rather than at dispatch, because everything in it can move while a
/// job is running and the whole point is to notice when it did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expectation {
    /// The session epoch in force.
    pub session_epoch: SessionEpoch,
    /// The context revision in force.
    pub revision: ContextRevision,
    /// The binding in force.
    pub binding: ContextBinding,
    /// The profile in force.
    pub profile_id: String,
    /// The profile revision in force.
    pub profile_revision: ProfileRevision,
    /// Privacy mode's generation in force.
    pub generation: PrivacyGeneration,
    /// Whether this session's name is pinned.
    pub name_pinned: bool,
}

/// What a job carries with it, so a late result can be recognised as one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducedUnder {
    /// The session epoch the job was admitted under.
    pub session_epoch: SessionEpoch,
    /// The binding the job was admitted under.
    pub binding: ContextBinding,
    /// The context revision the job was built from.
    ///
    /// This is the trusted one. The result echoes a revision of its own, and the two are compared:
    /// a result that repeated the wrong number is refused rather than believed.
    pub context_revision: ContextRevision,
    /// The interval of the semantic stream the job was built from, which the result also echoes.
    pub cursor: CursorInterval,
    /// The profile the job ran on.
    pub profile_id: String,
    /// That profile's revision.
    pub profile_revision: ProfileRevision,
    /// Privacy mode's generation at admission.
    pub generation: PrivacyGeneration,
}

/// A description that has been validated and may be published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedDescription {
    /// The title.
    pub title: Title,
    /// The activity line.
    pub activity: ActivityText,
    /// The interval of the semantic stream it covers.
    pub cursor: CursorInterval,
    /// The context revision it was produced at.
    pub revision: ContextRevision,
    /// What it was produced under.
    pub produced_under: ProducedUnder,
}

/// A summary that has been validated and may be published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedSummary {
    /// The summary.
    pub text: SummaryText,
    /// The interval of the session's changes it covers, which is the one its job was built from.
    pub cursor: CursorInterval,
    /// What it was produced under.
    pub produced_under: ProducedUnder,
}

/// Validates a raw summary against what is in force now.
///
/// It is [`validate`] for the other object: the same refusals, in the same order, for what the two
/// have in common. A summary has no context revision, because what it covers is a frozen interval
/// of changes and a session that moves on does not make it describe something else, and no pin to
/// give way to, because it names nothing; [`Expectation::revision`] and
/// [`Expectation::name_pinned`] are not read.
///
/// # Errors
///
/// Returns the [`Rejection`] that applies. There is no partial success: a result is published
/// whole or not at all.
pub fn validate_summary(
    bytes: &[u8],
    produced_under: &ProducedUnder,
    expectation: &Expectation,
) -> std::result::Result<GeneratedSummary, Rejection> {
    let raw: RawSummary = serde_json::from_slice(bytes).map_err(|error| {
        let detail = error.to_string();
        if error.is_data() {
            Rejection::InvalidFields { detail }
        } else {
            Rejection::Malformed { detail }
        }
    })?;

    check_field("summary", &raw.summary, MAX_SUMMARY_CODEPOINTS)?;

    if produced_under.session_epoch != expectation.session_epoch {
        return Err(Rejection::WrongSessionEpoch {
            expected: expectation.session_epoch,
            found: produced_under.session_epoch,
        });
    }
    if produced_under.binding != expectation.binding {
        return Err(Rejection::ChangedBinding {
            expected: expectation.binding.clone(),
            found: produced_under.binding.clone(),
        });
    }
    if raw.source_cursor != produced_under.cursor {
        return Err(Rejection::ProvenanceMismatch {
            field: "source_cursor",
        });
    }
    if produced_under.profile_id != expectation.profile_id
        || produced_under.profile_revision != expectation.profile_revision
    {
        return Err(Rejection::StaleProfileRevision {
            expected: (expectation.profile_id.clone(), expectation.profile_revision),
            found: (
                produced_under.profile_id.clone(),
                produced_under.profile_revision,
            ),
        });
    }
    if produced_under.generation != expectation.generation {
        return Err(Rejection::LateGeneration {
            expected: expectation.generation,
            found: produced_under.generation,
        });
    }
    let text = SummaryText::new(&raw.summary).ok_or(Rejection::OutOfBounds {
        field: "summary",
        limit: MAX_SUMMARY_CODEPOINTS,
        found: 0,
    })?;
    Ok(GeneratedSummary {
        text,
        cursor: raw.source_cursor,
        produced_under: produced_under.clone(),
    })
}

/// Validates a raw result against what is in force now.
///
/// The order is chosen so the cheapest refusal that is also the most informative comes first. A
/// malformed result says the runtime is wrong; a stale one says the world moved; a pinned name says
/// a person has already decided. Each is reported as itself rather than as a generic failure,
/// because a host that saw only "rejected" could not tell a broken grammar from a busy session.
///
/// # Errors
///
/// Returns the [`Rejection`] that applies. There is no partial success: a result is published
/// whole or not at all.
pub fn validate(
    bytes: &[u8],
    produced_under: &ProducedUnder,
    expectation: &Expectation,
) -> std::result::Result<GeneratedDescription, Rejection> {
    let raw: RawDescription = serde_json::from_slice(bytes).map_err(|error| {
        let detail = error.to_string();
        if error.is_data() {
            Rejection::InvalidFields { detail }
        } else {
            Rejection::Malformed { detail }
        }
    })?;

    check_field("title", &raw.title, MAX_TITLE_CODEPOINTS)?;
    check_field("activity_text", &raw.activity_text, MAX_ACTIVITY_CODEPOINTS)?;

    if produced_under.session_epoch != expectation.session_epoch {
        return Err(Rejection::WrongSessionEpoch {
            expected: expectation.session_epoch,
            found: produced_under.session_epoch,
        });
    }
    if produced_under.binding != expectation.binding {
        return Err(Rejection::ChangedBinding {
            expected: expectation.binding.clone(),
            found: produced_under.binding.clone(),
        });
    }
    // The result echoes its own provenance, and the job carries the trusted copy. A result that
    // did not repeat what it was given is refused before either is compared with what is in force.
    if ContextRevision::new(raw.context_revision) != produced_under.context_revision {
        return Err(Rejection::ProvenanceMismatch {
            field: "context_revision",
        });
    }
    if raw.source_cursor != produced_under.cursor {
        return Err(Rejection::ProvenanceMismatch {
            field: "source_cursor",
        });
    }
    let revision = produced_under.context_revision;
    if revision != expectation.revision {
        return Err(Rejection::ChangedContext {
            expected: expectation.revision,
            found: revision,
        });
    }
    if produced_under.profile_id != expectation.profile_id
        || produced_under.profile_revision != expectation.profile_revision
    {
        return Err(Rejection::StaleProfileRevision {
            expected: (expectation.profile_id.clone(), expectation.profile_revision),
            found: (
                produced_under.profile_id.clone(),
                produced_under.profile_revision,
            ),
        });
    }
    if produced_under.generation != expectation.generation {
        return Err(Rejection::LateGeneration {
            expected: expectation.generation,
            found: produced_under.generation,
        });
    }
    if expectation.name_pinned {
        return Err(Rejection::NamePinned);
    }

    let title = Title::new(&raw.title).ok_or(Rejection::OutOfBounds {
        field: "title",
        limit: MAX_TITLE_CODEPOINTS,
        found: 0,
    })?;
    let activity = ActivityText::new(&raw.activity_text).ok_or(Rejection::OutOfBounds {
        field: "activity_text",
        limit: MAX_ACTIVITY_CODEPOINTS,
        found: 0,
    })?;
    Ok(GeneratedDescription {
        title,
        activity,
        cursor: raw.source_cursor,
        revision,
        produced_under: produced_under.clone(),
    })
}

/// Refuses a field that is empty, over its bound, or carrying a control character.
fn check_field(
    field: &'static str,
    value: &str,
    limit: usize,
) -> std::result::Result<(), Rejection> {
    // The same set the deterministic path removes, refused here instead of removed. Section 22
    // says *reject*, and a title with a right-to-left override in it is evidence that the grammar
    // did not hold rather than something to tidy up.
    if value.chars().any(crate::metadata::is_forbidden_in_a_label) {
        return Err(Rejection::ControlCharacter { field });
    }
    let codepoints = value.chars().count();
    if codepoints == 0 || codepoints > limit {
        return Err(Rejection::OutOfBounds {
            field,
            limit,
            found: codepoints,
        });
    }
    Ok(())
}

/// Ends an answer that ran out of output room, where it can be ended, so that the whole answer is
/// within `max_tokens` as `count` counts tokens.
///
/// The model writes the answer a token at a time under the grammar, and the output bound can stop
/// it before the object is closed. What it had written is a prefix of the grammar's object, and
/// the grammar fixes the order of the fields, so where the prefix stopped is known. Only the
/// activity text may end early. A summary's one string ends in the same way, and the interval it
/// repeats is written from the prompt after it, as the description's fields are:
///
/// - Stopped inside the activity text, or inside the fields that repeat the prompt after it, the
///   answer is the title as written, the activity text cut back to the longest run of whole
///   characters a person sees that leaves the answer within `max_tokens`, the closing quote, and
///   the two fields that repeat the revision and the cursor interval written from the prompt,
///   because they are the prompt's own values and no part of what the model chose to say. When it
///   stopped inside the activity text the last character it had written is not kept, because the
///   next token might have been part of it; and a run never ends in white space, which a published
///   text would lose from inside a character.
/// - Stopped inside the fields that repeat the prompt, what the model had written of them has to
///   be the start of what the prompt says, or the bytes come back as they are: a wrong number is
///   refused here as it is when the answer is whole.
/// - Already a whole object, or stopped before the activity text, or with no run of the activity
///   text that fits, or with bytes that are not text, the bytes come back as they are: a title is
///   never cut, and what [`validate`] refuses it still refuses.
#[must_use]
pub fn end_cut_answer(
    written: &[u8],
    prompt: &crate::prompt::Prompt,
    max_tokens: usize,
    mut count: impl FnMut(&str) -> usize,
) -> Vec<u8> {
    let unchanged = || written.to_vec();
    if serde_json::from_slice::<serde_json::Value>(written).is_ok() {
        return unchanged();
    }
    // Whole characters only: the last token can be half of one, and bytes that are not text in the
    // middle are not an answer to end.
    let text = match std::str::from_utf8(written) {
        Ok(text) => text,
        Err(error) if error.error_len().is_none() => {
            std::str::from_utf8(&written[..error.valid_up_to()]).unwrap_or_default()
        }
        Err(_) => return unchanged(),
    };
    // The strings of the object hold no quote, so the quotes are the fields' own: two around
    // `title`, two around its value, two around `activity_text`, and two around its value; a
    // summary's are the two around `summary` and the two around its value. `open` is the place of
    // the quote that opens the text that may end early.
    let quotes: Vec<usize> = text.match_indices('"').map(|(at, _)| at).collect();
    let (key, open, tail) = match prompt.kind {
        PromptKind::Description => (
            "\"activity_text\"",
            6,
            format!(
                ", \"source_cursor\": {{\"from\": {}, \"to\": {}}}, \"context_revision\": {}}}",
                prompt.cursor_from.get(),
                prompt.cursor_to.get(),
                prompt.revision.get()
            ),
        ),
        PromptKind::Summary => (
            "\"summary\"",
            2,
            format!(
                ", \"source_cursor\": {{\"from\": {}, \"to\": {}}}}}",
                prompt.cursor_from.get(),
                prompt.cursor_to.get()
            ),
        ),
    };
    if quotes.len() <= open || &text[quotes[open - 2]..=quotes[open - 1]] != key {
        return unchanged();
    }
    let (activity, whole) = if quotes.len() > open + 1 {
        // What the model wrote after the activity text has to be the start of the tail, and a
        // number it had finished, by a space or a comma after it, has to be the prompt's number.
        let written_tail = &text[quotes[open + 1] + 1..];
        let spaceless = |text: &str| text.replace(' ', "");
        let (expected, begun) = (spaceless(&tail), spaceless(written_tail));
        let continues = expected[begun.len().min(expected.len())..]
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_digit());
        let finished = written_tail.ends_with(' ') && begun.ends_with(|c: char| c.is_ascii_digit());
        if !expected.starts_with(&begun) || (finished && continues) {
            return unchanged();
        }
        (&text[quotes[open] + 1..quotes[open + 1]], true)
    } else {
        (&text[quotes[open] + 1..], false)
    };

    // The activity text in the characters a person sees, less the last when it may be unfinished,
    // and less any that would end the text in white space.
    let mut clusters: Vec<&str> = activity.graphemes(true).collect();
    if !whole {
        clusters.pop();
    }
    let ends_in_text = |kept: usize| {
        kept > 0
            && clusters[kept - 1]
                .chars()
                .next_back()
                .is_some_and(|character| !character.is_whitespace())
    };
    let answer = |kept: usize| {
        format!(
            "{}{}\"{tail}",
            &text[..=quotes[open]],
            clusters[..kept].concat()
        )
    };
    // The most clusters that leave the answer within the bound: the longest run first, so that a
    // tokenizer whose count of a longer text is smaller than a shorter one's still finds the one
    // that fits. The one kept is one that was counted and fit.
    (1..=clusters.len())
        .rev()
        .filter(|kept| ends_in_text(*kept))
        .map(answer)
        .find(|candidate| count(candidate) <= max_tokens)
        .map_or_else(unchanged, String::into_bytes)
}
