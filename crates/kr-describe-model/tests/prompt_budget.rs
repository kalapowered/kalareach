//! The prompt's bound and the end of an answer, with the real weights where this host has them.
//!
//! The product's largest contexts, every field and event at the bound in Latin, Arabic, Hebrew and
//! emoji text, cost between 700 and 5,200 tokens, and only the model's own tokenizer says which. A
//! job's prompt is made to fit what the deadline leaves for reading it, and an answer the output
//! bound stops is ended where it can be. These tests ask the real tokenizer and the real model
//! whether both hold. A host without the weights says so and runs nothing.

use std::time::{Duration, Instant};

use kr_describe::budget::{Budgets, GIB};
use kr_describe::context::DescriptionContext;
use kr_describe::output::DESCRIPTION_GRAMMAR;
use kr_describe::priority::Cancellation;
use kr_describe::profile::ModelProfile;
use kr_describe::serve::{Generating, Job, Model};
use kr_describe::wire::LoadEnd;
use kr_describe_model::fixtures::{largest_contexts, validate_answer};
use kr_describe_model::llama::{Llama, LlamaRuntime};
use unicode_segmentation::UnicodeSegmentation;

mod support;

/// Says what a test measured, where the run's output shows it whether or not the test passes.
fn note(line: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{line}");
}

/// Runs one job for `context` as the service sends it, with `max_output_tokens` for the answer,
/// and returns what the model produced. The deadline is far off: what these tests decide is what
/// comes back, and how long it took is the benchmark's to say.
fn describe(
    model: &mut Llama,
    profile: &ModelProfile,
    context: &DescriptionContext,
    max_output_tokens: u32,
) -> Vec<u8> {
    let bounds = Budgets::DEFAULTS.bounds(profile.execution());
    let prompt = context.prompt();
    let job = Job {
        prompt: &prompt,
        grammar: DESCRIPTION_GRAMMAR,
        context_tokens: bounds.context_tokens,
        max_output_tokens,
        prompt_tokens: bounds.prompt_tokens,
        cpu_threads: bounds.cpu_threads,
        sampler: profile.sampler(),
        ceiling_bytes: 4 * GIB,
    };
    match model.generate(
        &job,
        &Cancellation::new(),
        Instant::now() + Duration::from_secs(1_800),
    ) {
        Generating::Produced { bytes, .. } => bytes,
        Generating::Ended { why, detail } => {
            panic!("the job ended {}: {detail:?}", why.as_str())
        }
    }
}

/// KR-REQ-22.10: the prompt of every largest context is made to fit what the deadline leaves for
/// reading it, counted by the model's own tokenizer, beside the answer's bound inside the window.
/// The control is the Latin context, which costs less than the bound and is left exactly as it is.
#[test]
fn the_largest_contexts_are_made_to_fit_the_prompt_bound() {
    let Some((profile, runtime)) =
        support::loaded("the_largest_contexts_are_made_to_fit_the_prompt_bound")
    else {
        return;
    };
    let bounds = Budgets::DEFAULTS.bounds(profile.execution());
    let budget = bounds.prompt_tokens as usize;
    let count = |text: &str| runtime.prompt_tokens(text).map(|read| read.tokens.len());

    for (script, context) in largest_contexts() {
        let prompt = context.prompt();
        let whole = count(&prompt.text()).expect("a count");
        let fitted = prompt.fit(budget, count).expect("a prompt that fits");
        note(&format!(
            "{script}: {whole} tokens whole, {} read of {budget}, {} events dropped, cut {}",
            fitted.tokens, fitted.events_dropped, fitted.cut
        ));
        assert!(fitted.tokens <= budget, "{script}");
        assert!(
            fitted.tokens + bounds.max_output_tokens as usize <= bounds.context_tokens as usize,
            "{script}"
        );
        assert_eq!(count(&fitted.text), Ok(fitted.tokens), "{script}");
        assert_eq!(
            prompt.fit(budget, count).expect("a prompt that fits"),
            fitted,
            "{script}: deterministic"
        );
        if script == "latin" {
            assert!(whole <= budget, "the control is under the bound");
            assert_eq!(fitted.text, prompt.text(), "and is left as it is");
        } else {
            assert!(
                whole > budget,
                "{script} is a context the bound has to trim"
            );
            assert_ne!(fitted.text, prompt.text(), "{script}");
            // What a session is for is kept before anything else.
            let intent = prompt.fact("intent").expect("an intent");
            assert!(
                fitted.text.contains(&format!("intent: <<{intent}>>")),
                "{script}: the intent"
            );
        }
    }
}

/// KR-REQ-22.18: a job for each largest context gives an answer that is published as it is, and the
/// output bound never leaves it cut. The Latin answer, which the model ends itself, is the same at
/// the bound and with room to spare: nothing in it is shortened. For the others, stopping the
/// model inside its activity text, at a bound it cannot finish in, gives an answer ended on a
/// boundary between characters a person sees, which is the start of the text it would have written.
#[test]
fn an_answer_the_output_bound_stops_is_ended_inside_its_activity_text() {
    let Some((profile, runtime)) =
        support::loaded("an_answer_the_output_bound_stops_is_ended_inside_its_activity_text")
    else {
        return;
    };
    assert!(
        profile.sampler().is_greedy(),
        "the same job writes the same answer"
    );
    let mut model = Llama::loaded(runtime);

    for (script, context) in largest_contexts() {
        let bounded = describe(&mut model, &profile, &context, 128);
        let reference = describe(&mut model, &profile, &context, 300);
        let runtime = model.runtime().expect("a loaded model");
        for bytes in [&bounded, &reference] {
            validate_answer(&context, &profile, bytes)
                .unwrap_or_else(|rejection| panic!("{script}: {}", rejection.as_str()));
            assert_eq!(
                runtime.grammar_takes(DESCRIPTION_GRAMMAR, bytes),
                Ok(true),
                "{script}"
            );
        }
        if script == "latin" {
            assert_eq!(bounded, reference, "the Latin answer is not shortened");
        }

        // Where the reference's activity text is, in the model's tokens.
        let text = String::from_utf8(reference.clone()).expect("text");
        let quotes: Vec<usize> = text.match_indices('"').map(|(at, _)| at).collect();
        let before = |end: usize| {
            runtime
                .prompt_tokens(&text[..end])
                .expect("tokens")
                .tokens
                .len()
        };
        let (starts, ends) = (before(quotes[6] + 1), before(quotes[7]));
        let full = validate_answer(&context, &profile, &reference)
            .expect("a published answer")
            .activity;
        let boundaries: Vec<usize> = full
            .as_str()
            .grapheme_indices(true)
            .map(|(at, _)| at)
            .chain([full.as_str().len()])
            .collect();

        let mut shortened = 0;
        for stop in [starts + 3, starts + (ends - starts) / 2, ends - 2] {
            let stop = u32::try_from(stop).expect("a count");
            let bytes = describe(&mut model, &profile, &context, stop);
            let Ok(description) = validate_answer(&context, &profile, &bytes) else {
                note(&format!("{script}: stopped at {stop}, refused"));
                continue;
            };
            let kept = description.activity.as_str();
            note(&format!("{script}: stopped at {stop}, kept {kept:?}"));
            assert!(full.as_str().starts_with(kept), "{script}: {kept:?}");
            assert!(
                boundaries.contains(&kept.len()),
                "{script}: {kept:?} ends inside a character of {:?}",
                full.as_str()
            );
            shortened += usize::from(kept.len() < full.as_str().len());
        }
        assert!(
            shortened >= 1,
            "{script}: no stop inside the activity text was ended"
        );
    }
}

/// KR-REQ-22.10: a profile whose window is too small to hold the instruction and the answer's bound
/// is refused when it loads, with a reason a person can read. A job for it could never be made to
/// fit, and refusing the profile once is what lets every job that is sent fit.
#[test]
fn a_profile_whose_window_cannot_hold_the_instruction_is_refused_at_load() {
    let Some(weights) =
        support::weights("a_profile_whose_window_cannot_hold_the_instruction_is_refused_at_load")
    else {
        return;
    };
    let small = kr_describe::testing::default_profile_with_window(200);
    let refused = LlamaRuntime::load(
        &small,
        &weights.path,
        &Cancellation::new(),
        Instant::now() + Duration::from_secs(300),
    );
    assert!(
        matches!(&refused, Err((LoadEnd::Refused, Some(detail))) if detail.contains("no room")),
        "{:?}",
        refused.map(|_| ())
    );
}
