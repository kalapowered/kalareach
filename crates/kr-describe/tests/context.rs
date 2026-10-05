//! What advances a context revision, what may be inside one, and what a result has to be before it
//! is published.
//!
//! These two modules are where section 22's rules about *input* and *output* live, and neither
//! needs a model: what may reach a prompt is decided by a type, and what may leave one is decided
//! by a grammar and a validation that does not trust it.

mod support;

use kr_describe::context::{
    Admits, Completion, ContextBinding, ContextBuilder, ContextRevision, ContextSignal,
    ContextTracker, CursorInterval, InputClass, Observed, ProjectText, SemanticEvent,
    SemanticEventKind, Settled, admits,
};
use kr_describe::metadata::{ActivityText, RepositoryFacts, Title};
use kr_describe::output::{
    DESCRIPTION_GRAMMAR, Expectation, ProducedUnder, Rejection, end_cut_answer, validate,
};
use kr_describe::profile::ProfileRevision;
use kr_describe::prompt::Prompt;
use kr_protocol::ids::SessionEpoch;
use kr_protocol::scalars::U64;
use kr_worker::privacy::{PrivacyGeneration, PrivacyMode};
use unicode_segmentation::UnicodeSegmentation;

use support::{at, binding, environment_id, session};

/// A well-formed result at one revision.
fn well_formed(revision: u64) -> Vec<u8> {
    format!(
        "{{\"title\":\"kalareach\",\"activity_text\":\"Checks the code-entry flow\",\
         \"source_cursor\":{{\"from\":3,\"to\":11}},\"context_revision\":{revision}}}"
    )
    .into_bytes()
}

/// What is in force when a result arrives.
fn expectation(revision: u64) -> Expectation {
    Expectation {
        session_epoch: SessionEpoch::V1,
        revision: ContextRevision::new(revision),
        binding: binding(),
        profile_id: "minicpm5-2b-q4-k-m".to_owned(),
        profile_revision: ProfileRevision::new(1),
        generation: PrivacyGeneration::INITIAL,
        name_pinned: false,
    }
}

/// What a job carried with it.
fn produced_under() -> ProducedUnder {
    produced_at(2)
}

/// What a job built at one revision carried with it.
fn produced_at(revision: u64) -> ProducedUnder {
    ProducedUnder {
        session_epoch: SessionEpoch::V1,
        binding: binding(),
        context_revision: ContextRevision::new(revision),
        cursor: CursorInterval::new(3, 11),
        profile_id: "minicpm5-2b-q4-k-m".to_owned(),
        profile_revision: ProfileRevision::new(1),
        generation: PrivacyGeneration::INITIAL,
    }
}

/// KR-REQ-01.14 and KR-REQ-22.05: the input, query and resize paths have no way in.
///
/// It is a proof by the path rather than by a timing figure. The only door into the queue is a
/// meaningful context change, and the five things that can be one do not include a keystroke, a
/// device query or a resize. The classes that describe those inputs are refused by the only
/// builder a context can be made with, so there is nothing for a hot path to call.
#[test]
fn nothing_on_the_input_query_or_resize_path_can_reach_a_description() {
    for class in [
        InputClass::RawKeystrokes,
        InputClass::HiddenInput,
        InputClass::EnvironmentValue,
        InputClass::FileBody,
        InputClass::FullHistory,
    ] {
        assert_eq!(
            admits(class),
            Admits::Never,
            "{} is excluded by section 22",
            class.as_str()
        );
    }

    let built = ContextBuilder::new(
        environment_id(1),
        session(1),
        SessionEpoch::V1,
        binding(),
        ContextRevision::new(1),
    )
    .offer(InputClass::RawKeystrokes, "ls -la\r")
    .offer(InputClass::HiddenInput, "hunter2")
    .offer(InputClass::EnvironmentValue, "AWS_SECRET_ACCESS_KEY=abc")
    .offer(InputClass::FileBody, "fn main() { todo!() }")
    .offer(InputClass::FullHistory, "the whole session");
    assert_eq!(built.refused().len(), 5);
    let context = built.build();
    let data = context.prompt().text();
    for secret in ["ls -la", "hunter2", "AWS_SECRET", "todo!", "whole session"] {
        assert!(
            !data.contains(secret),
            "an excluded class reached the prompt: {secret}"
        );
    }

    // And the tracker, which is the other half of the door, has nothing a keystroke could be.
    let mut tracker = ContextTracker::new(2_000);
    assert_eq!(tracker.settle(at(10_000)), Settled::NotYet);
    assert_eq!(tracker.revision(), ContextRevision::INITIAL);
}

/// KR-REQ-22.16: only the five meaningful changes advance the revision, and a repeat advances
/// nothing.
#[test]
fn only_a_meaningful_change_advances_the_revision() {
    let mut tracker = ContextTracker::new(2_000);
    let signals = [
        ContextSignal::WorkingDirectory {
            directory: "kalareach".to_owned(),
            repository: None,
        },
        ContextSignal::ForegroundApplication(Some("nvim".to_owned())),
        ContextSignal::SelectedThread(Some("review".to_owned())),
        ContextSignal::TaskIntent("check the pairing flow".to_owned()),
        ContextSignal::Completion(Some(Completion::Succeeded)),
    ];
    for signal in signals.clone() {
        assert_eq!(tracker.observe(signal, at(0)), Observed::Pending);
    }
    // Every one of them again, with nothing changed.
    for signal in signals {
        assert_eq!(tracker.observe(signal, at(10)), Observed::Unchanged);
    }
    assert_eq!(tracker.pending(), 5);
    assert_eq!(tracker.revision(), ContextRevision::INITIAL);
    assert_eq!(
        tracker.settle(at(2_000)),
        Settled::Advanced {
            revision: ContextRevision::new(1),
            coalesced: 5
        }
    );
    assert_eq!(tracker.settle(at(60_000)), Settled::NotYet);
}

/// KR-REQ-22.16: a fact the host no longer has is a change like any other. A completion cleared
/// when work begins, a thread cleared when it ends and an application that is gone each advance
/// the revision once and leave nothing of the old value; clearing what is already clear changes
/// nothing, and a new event is a change that needs no other fact to move with it.
#[test]
fn clearing_a_fact_is_a_change_and_so_is_a_new_event() {
    let mut tracker = ContextTracker::new(2_000);
    let set = [
        ContextSignal::ForegroundApplication(Some("cargo".to_owned())),
        ContextSignal::SelectedThread(Some("review".to_owned())),
        ContextSignal::Completion(Some(Completion::Failed)),
    ];
    for signal in set {
        assert_eq!(tracker.observe(signal, at(0)), Observed::Pending);
    }
    assert!(matches!(
        tracker.settle(at(2_000)),
        Settled::Advanced { .. }
    ));

    let cleared = [
        ContextSignal::ForegroundApplication(None),
        ContextSignal::SelectedThread(None),
        ContextSignal::Completion(None),
    ];
    for signal in cleared.clone() {
        assert_eq!(tracker.observe(signal, at(3_000)), Observed::Pending);
    }
    let facts = tracker.facts();
    assert_eq!(facts.application, None);
    assert_eq!(tracker.thread(), None);
    assert_eq!(tracker.completion(), None);
    for signal in cleared {
        assert_eq!(
            tracker.observe(signal, at(3_100)),
            Observed::Unchanged,
            "clearing what is clear"
        );
    }
    assert!(matches!(
        tracker.settle(at(5_000)),
        Settled::Advanced { .. }
    ));

    assert_eq!(tracker.settle(at(60_000)), Settled::NotYet);
    assert_eq!(tracker.note_event(at(60_000)), Observed::Pending);
    assert_eq!(tracker.settle(at(61_000)), Settled::NotYet, "debounced");
    assert!(matches!(
        tracker.settle(at(62_000)),
        Settled::Advanced { .. }
    ));
}

/// KR-REQ-22.16: rapid directory changes coalesce into one revision.
#[test]
fn rapid_directory_changes_coalesce_into_one_revision() {
    let mut tracker = ContextTracker::new(2_000);
    for step in 0..20_u64 {
        tracker.observe(
            ContextSignal::WorkingDirectory {
                directory: format!("crate-{step}"),
                repository: None,
            },
            at(step * 50),
        );
        assert_eq!(tracker.settle(at(step * 50)), Settled::NotYet);
    }
    let Settled::Advanced {
        revision,
        coalesced,
    } = tracker.settle(at(2_000))
    else {
        panic!("twenty changes settle into one revision")
    };
    assert_eq!(revision, ContextRevision::new(1));
    assert_eq!(coalesced, 20);
}

/// KR-REQ-22.16: a session changing continuously still settles every debounce.
///
/// The window starts at the first pending change and is never extended, so a long active turn
/// receives useful text instead of waiting for a quiet moment that never comes.
#[test]
fn a_session_changing_continuously_still_settles_every_debounce() {
    let mut tracker = ContextTracker::new(2_000);
    let mut settlements = 0;
    for step in 0..100_u64 {
        tracker.observe(
            ContextSignal::TaskIntent(format!("step {step}")),
            at(step * 100),
        );
        if matches!(tracker.settle(at(step * 100)), Settled::Advanced { .. }) {
            settlements += 1;
        }
    }
    assert!(
        settlements >= 4,
        "ten seconds of continuous change settled {settlements} times, and a two-second window \
         should settle about five"
    );
    assert_eq!(tracker.revision(), ContextRevision::new(settlements));
}

/// KR-REQ-22.16: a context carries bounded metadata and events, and project text is data.
#[test]
fn a_context_carries_bounded_metadata_and_treats_project_text_as_data() {
    let mut builder = ContextBuilder::new(
        environment_id(1),
        session(1),
        SessionEpoch::V1,
        binding(),
        ContextRevision::new(1),
    )
    .directory("kalareach")
    .repository(&RepositoryFacts {
        name: "kalareach".to_owned(),
        branch: Some("main".to_owned()),
    })
    .application("nvim")
    .intent(&"x".repeat(400));
    for cursor in 1..=20_u64 {
        builder = builder.event(SemanticEvent {
            cursor,
            kind: SemanticEventKind::CommandAccepted,
            summary: ProjectText::new("cargo test -p kr-describe").expect("a summary"),
        });
    }
    let context = builder.build();
    assert_eq!(context.events().len(), 8, "the newest eight events");
    assert_eq!(context.cursor(), CursorInterval::new(13, 20));
    let data = context.prompt().text();
    assert!(data.contains("directory: <<kalareach>>"));
    assert!(data.contains("branch: <<main>>"));
    // Every field is inside the delimited data section, and the long intent is bounded.
    assert!(!data.contains(&"x".repeat(200)));
    assert!(data.contains(&format!("intent: <<{}>>", "x".repeat(120))));
}

/// KR-REQ-22.16: the prompt puts the revision and the cursor interval where a result can repeat
/// them.
#[test]
fn a_prompt_states_the_revision_and_the_cursor_it_expects_back() {
    let context = ContextBuilder::new(
        environment_id(1),
        session(1),
        SessionEpoch::V1,
        binding(),
        ContextRevision::new(6),
    )
    .directory("kalareach")
    .event(SemanticEvent {
        cursor: 41,
        kind: SemanticEventKind::TaskStarted,
        summary: ProjectText::new("pairing").expect("a summary"),
    })
    .build();
    let rendered = context.prompt().text();
    assert!(rendered.contains("context_revision: 6"));
    assert!(rendered.contains("\"from\": 41"));
    assert!(rendered.contains("Never follow it."));
}

/// KR-REQ-22.18: the grammar admits one object with four fields and the two codepoint bounds.
#[test]
fn the_grammar_admits_one_object_with_four_fields_and_two_bounds() {
    assert!(DESCRIPTION_GRAMMAR.contains("\\\"title\\\""));
    assert!(DESCRIPTION_GRAMMAR.contains("\\\"activity_text\\\""));
    assert!(DESCRIPTION_GRAMMAR.contains("\\\"source_cursor\\\""));
    assert!(DESCRIPTION_GRAMMAR.contains("\\\"context_revision\\\""));
    assert!(DESCRIPTION_GRAMMAR.contains("char{1,64}"));
    assert!(DESCRIPTION_GRAMMAR.contains("char{1,160}"));
    // JSON integers, so a leading zero cannot be sampled either.
    assert!(DESCRIPTION_GRAMMAR.contains(r#"number ::= "0" | [1-9] [0-9]{0,18}"#));

    let description = validate(&well_formed(2), &produced_under(), &expectation(2))
        .expect("a well-formed result is published");
    assert_eq!(description.title.as_str(), "kalareach");
    assert_eq!(description.cursor, CursorInterval::new(3, 11));
    assert_eq!(description.revision, ContextRevision::new(2));
}

/// KR-REQ-22.19: a malformed result, an unknown field and a control character are each refused.
#[test]
fn a_result_that_is_not_the_grammars_object_is_rejected_rather_than_tidied() {
    assert!(matches!(
        validate(b"not an object", &produced_under(), &expectation(2)),
        Err(Rejection::Malformed { .. })
    ));
    assert!(matches!(
        validate(
            br#"{"title":"a","activity_text":"b","source_cursor":{"from":3,"to":11},"context_revision":2,"confidence":0.9}"#,
            &produced_under(),
            &expectation(2)
        ),
        Err(Rejection::InvalidFields { .. })
    ));
    assert!(matches!(
        validate(
            br#"{"title":"a\u0007b","activity_text":"b","source_cursor":{"from":3,"to":11},"context_revision":2}"#,
            &produced_under(),
            &expectation(2)
        ),
        Err(Rejection::ControlCharacter { field: "title" })
    ));
    let overlong = format!(
        "{{\"title\":\"{}\",\"activity_text\":\"b\",\"source_cursor\":{{\"from\":3,\"to\":11}},\"context_revision\":2}}",
        "t".repeat(65)
    );
    assert!(matches!(
        validate(overlong.as_bytes(), &produced_under(), &expectation(2)),
        Err(Rejection::OutOfBounds {
            field: "title",
            limit: 64,
            found: 65
        })
    ));
}

/// KR-REQ-22.19: a wrong epoch, a changed context and a changed binding are each refused.
#[test]
fn a_wrong_epoch_a_changed_context_and_a_changed_binding_are_each_refused() {
    let changed_context = validate(&well_formed(2), &produced_under(), &expectation(9));
    assert!(matches!(
        changed_context,
        Err(Rejection::ChangedContext { .. })
    ));

    let mut rebound = expectation(2);
    rebound.binding = ContextBinding::new("desktop-2/terminal/epoch-1");
    assert!(matches!(
        validate(&well_formed(2), &produced_under(), &rebound),
        Err(Rejection::ChangedBinding { .. })
    ));

    let mut produced = produced_under();
    produced.session_epoch = SessionEpoch::new(2);
    assert!(matches!(
        validate(&well_formed(2), &produced, &expectation(2)),
        Err(Rejection::WrongSessionEpoch { .. })
    ));
}

/// KR-REQ-22.19: a title is bounded in codepoints rather than bytes, so a name in any script fits.
#[test]
fn a_title_is_bounded_in_codepoints_rather_than_bytes() {
    let japanese = "セッションの名前".repeat(8);
    assert_eq!(japanese.chars().count(), 64);
    assert!(japanese.len() > 64, "it is far more than 64 bytes");
    let body = format!(
        "{{\"title\":\"{japanese}\",\"activity_text\":\"作業中\",\
         \"source_cursor\":{{\"from\":3,\"to\":11}},\"context_revision\":2}}"
    );
    let description = validate(body.as_bytes(), &produced_under(), &expectation(2))
        .expect("sixty-four codepoints fit");
    assert_eq!(description.title.codepoints(), 64);

    let too_long = format!("{japanese}あ");
    let over = format!(
        "{{\"title\":\"{too_long}\",\"activity_text\":\"作業中\",\
         \"source_cursor\":{{\"from\":3,\"to\":11}},\"context_revision\":2}}"
    );
    assert!(matches!(
        validate(over.as_bytes(), &produced_under(), &expectation(2)),
        Err(Rejection::OutOfBounds { found: 65, .. })
    ));

    // The deterministic path bounds the same way, and removes a directional override outright.
    let title = Title::new(&format!("{japanese}\u{202e}reversed")).expect("a title");
    assert_eq!(title.codepoints(), 64);
    assert!(!title.as_str().contains('\u{202e}'));
    assert_eq!(ActivityText::new("  ").map(|text| text.codepoints()), None);
}

/// KR-REQ-22.09 and KR-REQ-22.19: a result from a remapped profile is refused as stale.
#[test]
fn a_result_from_a_remapped_profile_is_refused_as_stale() {
    let produced_under = ProducedUnder {
        context_revision: ContextRevision::new(4),
        cursor: CursorInterval::new(1, 9),
        ..produced_at(4)
    };
    let expectation = Expectation {
        session_epoch: SessionEpoch::V1,
        revision: ContextRevision::new(4),
        binding: binding(),
        profile_id: "minicpm5-2b-q4-k-m".to_owned(),
        profile_revision: ProfileRevision::new(2),
        generation: PrivacyGeneration::INITIAL,
        name_pinned: false,
    };
    let bytes = br#"{"title":"kalareach","activity_text":"Builds the host","source_cursor":{"from":1,"to":9},"context_revision":4}"#;
    assert!(matches!(
        validate(bytes, &produced_under, &expectation),
        Err(Rejection::StaleProfileRevision { .. })
    ));
}

/// KR-REQ-22.17: a result produced under an old generation is refused rather than published.
#[test]
fn a_result_produced_under_an_old_generation_is_refused() {
    let produced_under = ProducedUnder {
        cursor: CursorInterval::new(1, 9),
        ..produced_at(2)
    };
    let expectation = Expectation {
        generation: PrivacyGeneration::new(1),
        ..expectation(2)
    };
    let bytes = br#"{"title":"kalareach","activity_text":"Builds the host","source_cursor":{"from":1,"to":9},"context_revision":2}"#;
    assert!(matches!(
        validate(bytes, &produced_under, &expectation),
        Err(Rejection::LateGeneration { .. })
    ));

    // And the rule itself lives on the mode, where there is one of it.
    let mut mode = PrivacyMode::new();
    mode.open_generation(kr_protocol::scalars::TimestampMs::new(1));
    assert!(!mode.accepts_result(PrivacyGeneration::INITIAL));
    assert!(mode.accepts_result(PrivacyGeneration::new(1)));
}

/// KR-REQ-22.19: a result that does not repeat the provenance it was given is refused.
///
/// The revision and the cursor interval in a result are the model's copy of what the job carried.
/// They are compared with the job's own, so a runtime that invented either is refused before
/// anything is compared with what is in force.
#[test]
fn a_result_that_rewrites_its_own_provenance_is_refused() {
    let rewritten_revision = br#"{"title":"kalareach","activity_text":"Builds","source_cursor":{"from":3,"to":11},"context_revision":9}"#;
    assert_eq!(
        validate(rewritten_revision, &produced_under(), &expectation(2)),
        Err(Rejection::ProvenanceMismatch {
            field: "context_revision"
        })
    );
    let rewritten_cursor = br#"{"title":"kalareach","activity_text":"Builds","source_cursor":{"from":0,"to":0},"context_revision":2}"#;
    assert_eq!(
        validate(rewritten_cursor, &produced_under(), &expectation(2)),
        Err(Rejection::ProvenanceMismatch {
            field: "source_cursor"
        })
    );
}

/// KR-REQ-22.09: a result from a different profile is refused even at the same revision number.
#[test]
fn a_result_from_a_different_profile_is_refused_at_the_same_revision() {
    let produced = ProducedUnder {
        profile_id: "smollm3-3b-q4-k-m".to_owned(),
        ..produced_under()
    };
    assert!(matches!(
        validate(&well_formed(2), &produced, &expectation(2)),
        Err(Rejection::StaleProfileRevision { .. })
    ));
}

/// KR-REQ-22.19: a generated field carrying a bidirectional control is refused, not tidied.
///
/// The deterministic path removes these, because the text came from a directory name nobody chose
/// to be shown. A generated field is different: the grammar excludes them, so one that arrives is
/// evidence the grammar did not hold, and section 22 says reject.
#[test]
fn a_generated_field_with_a_bidirectional_control_is_refused() {
    for control in ["\\u061c", "\\u202e", "\\u2066", "\\u2028"] {
        let body = format!(
            "{{\"title\":\"a{control}b\",\"activity_text\":\"Builds\",\
             \"source_cursor\":{{\"from\":3,\"to\":11}},\"context_revision\":2}}"
        );
        assert_eq!(
            validate(body.as_bytes(), &produced_under(), &expectation(2)),
            Err(Rejection::ControlCharacter { field: "title" }),
            "{control} was not refused"
        );
    }
    // And an ordinary Arabic letter, which is not a control, is carried.
    let arabic = "{\"title\":\"مرحبا\",\"activity_text\":\"Builds\",\
         \"source_cursor\":{\"from\":3,\"to\":11},\"context_revision\":2}";
    assert!(validate(arabic.as_bytes(), &produced_under(), &expectation(2)).is_ok());
}

/// KR-REQ-22.17: a closed session whose cleanup failed keeps its fence and its debt.
#[test]
fn a_closed_session_keeps_a_cleanup_it_could_not_finish() {
    let debt = kr_describe::privacy::CleanupDebt::new();
    debt.owe(
        kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
        "the store would not answer".to_owned(),
    );
    assert!(!debt.is_empty());
    debt.settle(&kr_protocol::ids::SessionId::new(
        kr_protocol::scalars::Uuid::from_bytes([1; 16]),
    ));
    assert!(debt.is_empty());
}

/// Reads one codepoint of a GBNF character class, which is a character or an escape: `\\`,
/// `\x`, `\u` or `\U` and its hexadecimal digits.
fn read_codepoint(chars: &[char], at: &mut usize) -> u32 {
    let first = chars[*at];
    *at += 1;
    if first != '\\' {
        return first as u32;
    }
    let kind = chars[*at];
    *at += 1;
    let digits = match kind {
        'x' => 2,
        'u' => 4,
        'U' => 8,
        other => return other as u32,
    };
    let hex: String = chars[*at..*at + digits].iter().collect();
    *at += digits;
    u32::from_str_radix(&hex, 16).expect("hexadecimal digits")
}

/// Reads the codepoints a GBNF character class names, as inclusive ranges: the text between `[` or
/// `[^` and `]`, whose ranges are `a-b`.
fn ranges_of(class: &str) -> Vec<(u32, u32)> {
    let chars: Vec<char> = class.chars().collect();
    let mut at = 0;
    let mut ranges = Vec::new();
    while at < chars.len() {
        let from = read_codepoint(&chars, &mut at);
        let to = if at < chars.len() && chars[at] == '-' {
            at += 1;
            read_codepoint(&chars, &mut at)
        } else {
            from
        };
        ranges.push((from, to));
    }
    ranges
}

/// KR-REQ-22.18: the grammar admits no character that validation refuses, and leaves out nothing
/// else but the quote and the backslash a string cannot hold bare. Held over every codepoint, so a
/// character added to one and not the other is a failure here.
#[test]
fn the_grammar_admits_exactly_the_characters_validation_accepts() {
    let class = DESCRIPTION_GRAMMAR
        .lines()
        .find_map(|line| line.strip_prefix("char ::= ["))
        .and_then(|class| class.strip_suffix(']'))
        .expect("the grammar names its character class");
    let (negated, listed) = class
        .strip_prefix('^')
        .map_or((false, class), |listed| (true, listed));
    let ranges = ranges_of(listed);
    for codepoint in 0..=0x0010_FFFF_u32 {
        let Some(character) = char::from_u32(codepoint) else {
            continue;
        };
        let named = ranges
            .iter()
            .any(|(from, to)| (*from..=*to).contains(&codepoint));
        let admitted = named != negated;
        let refused = kr_describe::metadata::is_forbidden_in_a_label(character);
        assert!(
            !(admitted && refused),
            "the grammar admits {codepoint:#06x}, which validation refuses"
        );
        assert!(
            admitted || refused || character == '"' || character == '\\',
            "the grammar leaves out {codepoint:#06x}, which validation accepts"
        );
        // The quote and the backslash are the two a JSON string cannot hold bare.
        assert!(
            !(admitted && (character == '"' || character == '\\')),
            "the grammar admits {codepoint:#06x}, which a string cannot hold"
        );
    }
    // No codepoint of the surrogate range, which no UTF-8 text holds.
    for surrogate in 0xD800..=0xDFFF_u32 {
        let named = ranges
            .iter()
            .any(|(from, to)| (*from..=*to).contains(&surrogate));
        assert!(
            named == negated,
            "the grammar admits the surrogate {surrogate:#06x}"
        );
    }
}

/// A text from codepoints, for the ones a source file cannot show: a combining mark and a joiner.
fn text_of(codepoints: &[u32]) -> String {
    codepoints
        .iter()
        .map(|codepoint| char::from_u32(*codepoint).expect("a character"))
        .collect()
}

/// One token for every four bytes, rounded up: the stand-in tokenizer.
fn stand_in(text: &str) -> usize {
    text.len().div_ceil(4)
}

/// The prompt of a job at revision 2 over the cursor interval 3 to 11.
fn prompt_at_two() -> Prompt {
    Prompt {
        kind: kr_describe::prompt::PromptKind::Description,
        revision: U64::new(2),
        cursor_from: U64::new(3),
        cursor_to: U64::new(11),
        earlier: U64::ZERO,
        facts: Vec::new(),
        events: Vec::new(),
    }
}

/// The answer whose activity text is `activity`.
fn answer_with(activity: &str) -> String {
    format!(
        "{{\"title\": \"kalareach\", \"activity_text\": \"{activity}\", \
         \"source_cursor\": {{\"from\": 3, \"to\": 11}}, \"context_revision\": 2}}"
    )
}

/// KR-REQ-22.18: an answer the output bound stopped is ended where it can be, at every place it
/// can stop. Inside the activity text it is ended on a boundary between characters a person sees
/// of the whole text, with the prompt's own revision and cursor interval written after it, and
/// passes validation; after the activity text it is the same with the text whole; before the
/// activity text, so inside the title, nothing is done and validation refuses it as it does today.
#[test]
fn an_answer_the_output_bound_stopped_is_ended_on_a_boundary_and_still_validates() {
    let prompt = prompt_at_two();
    // A combining mark after a letter, a family of three people joined by joiners, an Arabic
    // sentence, and plain text.
    let accented = text_of(&[
        0x63, 0x61, 0x66, 0x65, 0x301, 0x20, 0x6F, 0x75, 0x76, 0x65, 0x72, 0x74,
    ]);
    let family = text_of(&[
        0x68, 0x6F, 0x6D, 0x65, 0x20, 0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x20, 0x68, 0x65,
        0x72, 0x65,
    ]);
    let activities = [
        "Checks the code-entry flow and host approval screen".to_owned(),
        accented,
        family,
        "مراجعة شاشة موافقة المضيف".to_owned(),
    ];
    let mut ended_inside = 0;
    for activity in activities {
        let full = format!(
            "{{\"title\": \"kalareach\", \"activity_text\": \"{activity}\", \
             \"source_cursor\": {{\"from\": 3, \"to\": 11}}, \"context_revision\": 2}}"
        );
        let quotes: Vec<usize> = full.match_indices('"').map(|(at, _)| at).collect();
        let (opens, closes) = (quotes[6], quotes[7]);
        let boundaries: Vec<usize> = activity
            .grapheme_indices(true)
            .map(|(at, _)| at)
            .chain([activity.len()])
            .collect();
        for stopped_at in 0..=full.len() {
            let written = &full.as_bytes()[..stopped_at];
            let ended = end_cut_answer(written, &prompt, usize::MAX, stand_in);
            let validated = validate(&ended, &produced_under(), &expectation(2));
            if stopped_at == full.len() {
                assert_eq!(ended, written, "a whole answer is left as it is");
                assert!(validated.is_ok());
            } else if stopped_at <= opens {
                // Not into the activity text yet: the title is never cut, and nothing is done.
                assert_eq!(ended, written, "stopped at {stopped_at}");
                assert!(validated.is_err(), "stopped at {stopped_at}");
            } else if stopped_at <= closes {
                match validated {
                    Ok(description) => {
                        ended_inside += 1;
                        let kept = description.activity.as_str();
                        assert!(activity.starts_with(kept), "{kept:?} of {activity:?}");
                        assert!(
                            boundaries.contains(&kept.len()),
                            "{kept:?} of {activity:?} ends inside a character"
                        );
                        assert!(kept.len() < activity.len() || stopped_at > closes);
                        assert_eq!(description.cursor, CursorInterval::new(3, 11));
                        assert_eq!(description.revision, ContextRevision::new(2));
                    }
                    // Nothing of the activity text was left to end it with.
                    Err(_) => assert_eq!(ended, written, "stopped at {stopped_at}"),
                }
            } else {
                // After the activity text, in the fields that repeat the prompt: the text whole.
                let description = validated.expect("an answer stopped after its activity text");
                assert_eq!(description.activity.as_str(), activity);
                assert_eq!(description.cursor, CursorInterval::new(3, 11));
            }
        }
    }
    assert!(
        ended_inside > 100,
        "{ended_inside} cuts inside an activity text were ended"
    );
}

/// KR-REQ-22.18: the answer an output bound stopped is within the bound it was stopped at, as the
/// tokenizer counts, and a bigger bound never keeps less of the activity text. A bound with no room
/// for the title and the fields that repeat the prompt leaves the bytes as they are, so the answer
/// is refused and the session keeps its title.
#[test]
fn an_answer_the_output_bound_stopped_is_within_that_bound() {
    let prompt = prompt_at_two();
    let activity = "Checks the code-entry flow and host approval screen for the pairing work";
    let full = answer_with(activity);
    let written = &full.as_bytes()[..full.find("approval").expect("a word") + 3];
    let mut last = 0;
    let mut ended = 0;
    for bound in 0..=stand_in(&full) {
        let answer = end_cut_answer(written, &prompt, bound, stand_in);
        if answer == written {
            assert!(
                bound < stand_in(&answer_with("C")),
                "bound {bound} left room for the title and one character"
            );
            continue;
        }
        let answer = String::from_utf8(answer).expect("text");
        assert!(
            stand_in(&answer) <= bound,
            "{} > {bound}",
            stand_in(&answer)
        );
        let kept = validate(answer.as_bytes(), &produced_under(), &expectation(2))
            .expect("an answer within its bound")
            .activity;
        assert!(kept.as_str().len() >= last, "a bigger bound kept less");
        last = kept.as_str().len();
        ended += 1;
    }
    assert!(ended > 10, "{ended} bounds ended the answer");
}

/// KR-REQ-22.18: nothing the model wrote is corrected. A number it had begun to repeat that is not
/// the prompt's, bytes that are not text inside the answer, and a title that has not ended are each
/// left as they are, and refused as they would be whole.
#[test]
fn what_the_model_wrote_wrongly_is_left_as_it_is() {
    let prompt = prompt_at_two();
    let full = answer_with("Checks the flow");
    let wrong = full.replace("\"from\": 3", "\"from\": 7");
    let stopped = wrong.find("\"to\"").expect("a field");
    let written = &wrong.as_bytes()[..stopped];
    assert_eq!(
        end_cut_answer(written, &prompt, usize::MAX, stand_in),
        written,
        "a wrong echo of the interval"
    );

    // A number the model had finished, by the space after it, that is not the prompt's: `1` is the
    // start of the interval's end, 11, but not the whole of it.
    let finished = format!(
        "{}\"to\":1 ",
        wrong[..wrong.find("\"to\"").expect("a field")].replace("\"from\": 7", "\"from\": 3")
    );
    assert_eq!(
        end_cut_answer(finished.as_bytes(), &prompt, usize::MAX, stand_in),
        finished.as_bytes(),
        "a finished number that is not the prompt's"
    );
    // The same digit with nothing after it is only begun, and the prompt's number completes it.
    let begun = finished.trim_end();
    let ended = end_cut_answer(begun.as_bytes(), &prompt, usize::MAX, stand_in);
    assert!(
        validate(&ended, &produced_under(), &expectation(2)).is_ok(),
        "a number begun, as the prompt's number starts"
    );

    let mut broken = full.clone().into_bytes();
    let at = full.find("flow").expect("a word");
    broken[at] = 0xFF;
    let written = &broken[..at + 3];
    assert_eq!(
        end_cut_answer(written, &prompt, usize::MAX, stand_in),
        written,
        "bytes that are not text inside the activity text"
    );

    let written = &full.as_bytes()[..full.find("kalareach").expect("a title") + 4];
    assert_eq!(
        end_cut_answer(written, &prompt, usize::MAX, stand_in),
        written,
        "a title that has not ended"
    );
}

/// KR-REQ-22.18: white space is not trimmed from inside a character a person sees. A prepended mark
/// takes the space after it into its character, so the activity text stopped after it is ended
/// before that character and not between the mark and its space.
#[test]
fn white_space_inside_a_character_is_not_trimmed_from_the_end_of_a_cut_activity_text() {
    let prompt = prompt_at_two();
    let activity = text_of(&[0x41, 0x600, 0x20, 0x42, 0x20, 0x43]);
    let full = answer_with(&activity);
    let written = &full.as_bytes()[..=full.find('B').expect("a letter")];
    let ended = end_cut_answer(written, &prompt, usize::MAX, stand_in);
    let kept = validate(&ended, &produced_under(), &expectation(2))
        .expect("an answer that ends")
        .activity;
    assert_eq!(kept.as_str(), "A");
}

/// KR-REQ-22.18: a tokenizer whose count of a longer text is smaller than a shorter text's, as a
/// word becomes one token, still gets the longest run that fits: no run that was never counted is
/// passed over, and the answer is refused only when every run is over the bound.
#[test]
fn a_counter_that_is_not_steady_still_finds_the_run_that_fits() {
    let prompt = prompt_at_two();
    let full = answer_with("Checks the code entry flow");
    let written = &full.as_bytes()[..full.find("flow").expect("a word") + 2];
    let unsteady = |text: &str| -> usize {
        // Only the run of 14 characters counts within the bound, as a merge of its last letters
        // into one token would make it; the shorter and the longer runs count one over. The
        // shorter runs count over on purpose: a search that takes a shorter run to count less
        // stops at the first run over the bound it meets, and never reaches the 14.
        let activity = text
            .split("\"activity_text\": \"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default();
        if activity.chars().count() == 14 {
            128
        } else {
            129
        }
    };
    let ended = end_cut_answer(written, &prompt, 128, unsteady);
    let kept = validate(&ended, &produced_under(), &expectation(2))
        .expect("the run that fits is found")
        .activity;
    assert_eq!(kept.as_str(), "Checks the cod");
    // Every run over the bound: refused.
    assert_eq!(end_cut_answer(written, &prompt, 100, unsteady), written);
}
