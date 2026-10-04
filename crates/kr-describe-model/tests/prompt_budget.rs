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
use kr_describe_model::fixtures::{copied_names, largest_contexts, validate_answer};
use kr_describe_model::llama::Llama;
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
            // What a session is for is kept before anything else, and the newest event is kept
            // beside it, so the answer has what the session is doing now.
            let intent = prompt.fact("intent").expect("an intent");
            assert!(
                fitted.text.contains(&format!("intent: <<{intent}>>")),
                "{script}: the intent"
            );
            // Emoji cost about three tokens a codepoint, so the intent, the directory and the
            // repository alone take the whole bound; the others keep the newest event.
            if script != "emoji" {
                assert!(fitted.events_dropped < 8, "{script}: the newest event");
            }
        }
    }
}

/// KR-REQ-22.18: a job for each largest context, and for sessions whose names the model copies in
/// their own script, gives an answer that is published as it is, and the output bound never leaves
/// it cut. The Latin answer, which the model ends itself, is the same at the bound and with room to
/// spare: nothing in it is shortened. Stopping the model at a bound it cannot finish in gives an
/// answer within that bound, whole as JSON, with the activity text ended on a boundary between
/// characters a person sees of the text the model would have written, which for the sessions whose
/// names are copied is Arabic, Persian with its non-joiner, and a family of emoji with its joiners.
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

    let mut contexts = largest_contexts();
    contexts.extend(copied_names());
    for (name, context) in contexts {
        let bounded = describe(&mut model, &profile, &context, 128);
        let reference = describe(&mut model, &profile, &context, 300);
        let runtime = model.runtime().expect("a loaded model");
        for bytes in [&bounded, &reference] {
            validate_answer(&context, &profile, bytes)
                .unwrap_or_else(|rejection| panic!("{name}: {}", rejection.as_str()));
            assert_eq!(
                runtime.grammar_takes(DESCRIPTION_GRAMMAR, bytes),
                Ok(true),
                "{name}"
            );
        }
        if name == "latin" {
            assert_eq!(bounded, reference, "the Latin answer is not shortened");
        }

        // Where the reference's parts are, in the model's tokens.
        let text = String::from_utf8(reference.clone()).expect("text");
        note(&format!("{name}: the answer the model writes is {text}"));
        let quotes: Vec<usize> = text.match_indices('"').map(|(at, _)| at).collect();
        let tokens = |end: usize| runtime.answer_tokens(&text[..end]).expect("tokens");
        let (total, starts, closes) =
            (tokens(text.len()), tokens(quotes[6] + 1), tokens(quotes[7]));
        let tail = total - tokens(quotes[7] + 1);
        let full = validate_answer(&context, &profile, &reference)
            .expect("a published answer")
            .activity;
        let copied = !full.as_str().is_ascii();
        if name.starts_with("copied") {
            assert!(
                copied,
                "{name}: the model no longer writes its activity in the name's script"
            );
        }
        let boundaries: Vec<usize> = full
            .as_str()
            .grapheme_indices(true)
            .map(|(at, _)| at)
            .chain([full.as_str().len()])
            .collect();

        let mut stops = vec![
            starts + tail + 2,
            starts + tail + (closes - starts) / 2,
            total.saturating_sub(3),
            total.saturating_sub(1),
        ];
        stops.sort_unstable();
        stops.dedup();
        let (mut shortened, mut non_ascii) = (0, 0);
        for stop in stops {
            let bound = u32::try_from(stop).expect("a count");
            let bytes = describe(&mut model, &profile, &context, bound);
            let runtime = model.runtime().expect("a loaded model");
            let Ok(description) = validate_answer(&context, &profile, &bytes) else {
                note(&format!("{name}: bound {stop}, refused"));
                continue;
            };
            let kept = description.activity.as_str();
            note(&format!("{name}: bound {stop}, kept {kept:?}"));
            assert!(
                runtime
                    .answer_tokens(&String::from_utf8_lossy(&bytes))
                    .expect("tokens")
                    <= stop,
                "{name}: the answer is within its bound"
            );
            assert!(full.as_str().starts_with(kept), "{name}: {kept:?}");
            assert!(
                boundaries.contains(&kept.len()),
                "{name}: {kept:?} ends inside a character of {:?}",
                full.as_str()
            );
            shortened += usize::from(kept.len() < full.as_str().len());
            non_ascii += usize::from(kept.len() < full.as_str().len() && !kept.is_ascii());
        }
        assert!(
            shortened >= 1,
            "{name}: no bound inside the activity text was ended"
        );
        if copied {
            assert!(
                non_ascii >= 1,
                "{name}: no shortened answer holds the name's script"
            );
        }
    }
}
