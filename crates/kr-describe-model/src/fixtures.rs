//! The sessions the benchmark and the tests describe: a context builder for a fixture session, and
//! the largest context the product admits in four scripts.
//!
//! What a prompt costs depends on how many tokens its text takes, and that depends on the script,
//! so the largest context is built in Latin, Arabic, Hebrew and emoji text: every field and every
//! recent event at the bound, with the longest numbers the answer repeats.

use kr_describe::context::{
    ContextBinding, ContextBuilder, ContextRevision, DescriptionContext,
    MAX_PROJECT_TEXT_CODEPOINTS, MAX_RECENT_EVENTS, SemanticEvent, SemanticEventKind,
};
use kr_describe::metadata::RepositoryFacts;
use kr_describe::output::{Expectation, GeneratedDescription, ProducedUnder, Rejection, validate};
use kr_describe::profile::ModelProfile;
use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::scalars::Uuid;
use kr_worker::privacy::PrivacyGeneration;

/// The environment every fixture session is in.
#[must_use]
pub fn environment() -> EnvironmentId {
    EnvironmentId::new(Uuid::from_bytes([7; 16]))
}

/// A session identifier a fixture can name twice.
#[must_use]
pub fn session(seed: u8) -> SessionId {
    SessionId::new(Uuid::from_bytes([seed; 16]))
}

/// A context builder for one fixture session at one revision.
#[must_use]
pub fn builder(seed: u8, revision: u64) -> ContextBuilder {
    ContextBuilder::new(
        environment(),
        session(seed),
        SessionEpoch::V1,
        ContextBinding::new("bench"),
        ContextRevision::new(revision),
    )
}

/// A repository and its branch.
#[must_use]
pub fn repository(name: &str, branch: &str) -> RepositoryFacts {
    RepositoryFacts {
        name: name.to_owned(),
        branch: Some(branch.to_owned()),
    }
}

/// An event whose summary is not empty once bounded, which is every summary the fixtures write.
#[must_use]
pub fn event(cursor: u64, kind: SemanticEventKind, summary: &str) -> SemanticEvent {
    SemanticEvent {
        cursor,
        kind,
        summary: kr_describe::context::ProjectText::new(summary)
            .unwrap_or_else(|| unreachable!("the fixtures' summaries are not empty")),
    }
}

/// Latin text, cycled to fill a field: the cheap case for a tokenizer.
pub const LATIN: &str = "crates/kr-describe/src/context/semantic_events/long_directory_name/file_with_a_long_name_for_this_event.rs and the pairing code entry screen ";
/// Arabic text, cycled to fill a field: about a token a codepoint.
pub const ARABIC: &str =
    "مراجعة شاشة موافقة المضيف وفحص مسار إدخال رمز الاقتران وتحديث ملف الإعدادات للمشروع ";
/// Hebrew text, cycled to fill a field: about a token a codepoint.
pub const HEBREW: &str =
    "בדיקת מסך אישור המארח ובדיקת מסלול הזנת קוד ההתאמה ועדכון קובץ ההגדרות של הפרויקט ";
/// Emoji, cycled to fill a field: several tokens a codepoint.
pub const EMOJI: &str = "🎂🎉🚀🔧🧪📦🛠🔍📝✅🌍🔑🧭🎯🪄🧵🎨📡🧱🔒";

/// A field of exactly the bound's length once the product has bounded and trimmed it, from `base`
/// repeated and started at or after `offset` codepoints in. The product removes controls and trims
/// a field after it bounds it, so a field that begins or ends with a space reaches it one codepoint
/// short; this asks the product's own constructor.
///
/// # Panics
///
/// Panics when no start of `base` gives such a field, which is a fault of the constant.
#[must_use]
pub fn field_of(base: &str, offset: usize) -> String {
    let period = base.chars().count();
    for start in offset..offset + period {
        let field: String = base
            .chars()
            .cycle()
            .skip(start)
            .take(MAX_PROJECT_TEXT_CODEPOINTS)
            .collect();
        if kr_describe::context::ProjectText::new(&field)
            .is_some_and(|text| text.as_str().chars().count() == MAX_PROJECT_TEXT_CODEPOINTS)
        {
            return field;
        }
    }
    panic!("no start of {base:?} gives a field of {MAX_PROJECT_TEXT_CODEPOINTS} codepoints")
}

/// A cursor and a revision of nineteen digits, the longest the grammar admits.
pub const LARGE_CURSOR: u64 = 4_000_000_000_000_000_100;

/// A context with every field and every recent event at the bound the product admits: six fields
/// and eight events of [`MAX_PROJECT_TEXT_CODEPOINTS`] codepoints each, in `base`'s script, with
/// the longest event label and numbers of nineteen digits.
#[must_use]
pub fn largest_context(seed: u8, base: &str) -> DescriptionContext {
    let mut context = builder(seed, LARGE_CURSOR + 50)
        .directory(&field_of(base, 0))
        .repository(&repository(&field_of(base, 7), &field_of(base, 13)))
        .application(&field_of(base, 19))
        .thread(&field_of(base, 29))
        .intent(&field_of(base, 37));
    for index in 0..MAX_RECENT_EVENTS {
        context = context.event(event(
            LARGE_CURSOR + index as u64,
            SemanticEventKind::ApprovalRequested,
            &field_of(base, 41 + 11 * index),
        ));
    }
    context.build()
}

/// The largest contexts, each named by the script its text is in.
#[must_use]
pub fn largest_contexts() -> Vec<(&'static str, DescriptionContext)> {
    [
        ("latin", LATIN),
        ("arabic", ARABIC),
        ("hebrew", HEBREW),
        ("emoji", EMOJI),
    ]
    .into_iter()
    .zip(1_u8..)
    .map(|((name, base), seed)| (name, largest_context(seed, base)))
    .collect()
}

/// Validates an answer to `context` as the service does: against the revision, the cursor interval,
/// the binding and the profile the job was built under, with nothing having moved since.
///
/// # Errors
///
/// Returns the rejection when the answer is not one that could be published.
pub fn validate_answer(
    context: &DescriptionContext,
    profile: &ModelProfile,
    bytes: &[u8],
) -> Result<GeneratedDescription, Rejection> {
    let produced_under = ProducedUnder {
        session_epoch: context.session_epoch(),
        binding: context.binding().clone(),
        context_revision: context.revision(),
        cursor: context.cursor(),
        profile_id: profile.profile_id().to_owned(),
        profile_revision: profile.revision(),
        generation: PrivacyGeneration::INITIAL,
    };
    let expectation = Expectation {
        session_epoch: produced_under.session_epoch,
        revision: produced_under.context_revision,
        binding: produced_under.binding.clone(),
        profile_id: produced_under.profile_id.clone(),
        profile_revision: produced_under.profile_revision,
        generation: produced_under.generation,
        name_pinned: false,
    };
    validate(bytes, &produced_under, &expectation)
}

/// Sessions whose names the model copies into its answer in their own script, so an answer to one
/// is text a cut can fall inside: an Arabic one, a Persian one with its zero-width non-joiner, and
/// one with a family of three people joined by zero-width joiners.
#[must_use]
pub fn copied_names() -> Vec<(&'static str, DescriptionContext)> {
    let text = |codepoints: &[u32]| -> String {
        codepoints
            .iter()
            .filter_map(|codepoint| char::from_u32(*codepoint))
            .collect()
    };
    let persian = text(&[
        0x645, 0x6CC, 0x200C, 0x62E, 0x648, 0x627, 0x647, 0x645, 0x20, 0x62E, 0x637, 0x627, 0x20,
        0x631, 0x627, 0x20, 0x631, 0x641, 0x639, 0x20, 0x6A9, 0x646, 0x645,
    ]);
    let family = text(&[0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467]);
    vec![
        (
            "copied arabic",
            builder(2, 12)
                .directory("المشروع")
                .intent("مراجعة شاشة موافقة المضيف")
                .build(),
        ),
        (
            "copied persian",
            builder(3, 13)
                .directory("پروژه")
                .intent(&format!("بررسی صفحه تأیید میزبان و {persian}"))
                .build(),
        ),
        (
            "copied emoji family",
            builder(4, 14)
                .directory("family")
                .intent(&format!("add the {family} emoji to the party planner"))
                .build(),
        ),
    ]
}
