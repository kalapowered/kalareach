//! The prompt's bound, with the real weights where this host has them.
//!
//! The product's largest contexts, every field and event at the bound in Latin, Arabic, Hebrew and
//! emoji text, cost between 700 and 5,200 tokens, and only the model's own tokenizer says which. A
//! job's prompt is made to fit what the deadline leaves for reading it. These tests ask the real
//! tokenizer whether it does. A host without the weights says so and runs nothing.

use std::time::{Duration, Instant};

use kr_describe::budget::Budgets;
use kr_describe::priority::Cancellation;
use kr_describe::wire::LoadEnd;
use kr_describe_model::fixtures::largest_contexts;
use kr_describe_model::llama::LlamaRuntime;

mod support;

/// Says what a test measured, where the run's output shows it whether or not the test passes.
fn note(line: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{line}");
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
