//! What the contact skill the host installs tells an agent.
//!
//! The skill text is compiled into the daemon, and an installation writes exactly these bytes, so
//! the text checked here is the text an agent reads.

/// Collapses the line wrapping of a Markdown document, so a sentence reads as one line.
fn prose(markdown: &str) -> String {
    markdown.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// KR-REQ-11.51: the skill the host installs tells the agent when and how to ask for missing
/// input, to give concise decision context, to wait on the question it already asked rather than
/// asking again, and to cancel a question that stopped mattering; it grants no authority, and it
/// says an unanswered question is never approval.
#[test]
fn the_skill_says_ask_wait_and_cancel_and_grants_no_authority() {
    let skill = prose(kr_controller::agent_tools::SKILL_MD);
    for (what, sentence) in [
        (
            "when to ask",
            "## When to ask Ask when the work genuinely stops without them",
        ),
        (
            "how to ask",
            "Put the decision in `question` and the background in `context`.",
        ),
        (
            "concise decision context",
            "Keep context to what turns on the answer",
        ),
        (
            "waiting on the question already asked",
            "call `wait_for_answer` when you have run out of useful work",
        ),
        (
            "a wait that runs out is not an answer",
            "`wait_for_answer` holds for up to ten minutes and returns the same question when the \
             wait runs out. That is not an answer.",
        ),
        (
            "cancelling a question that stopped mattering",
            "`cancel_question` when the question stops mattering",
        ),
        (
            "silence is not approval",
            "**An unanswered question is never approval.**",
        ),
        (
            "no authority granted",
            "it produces no approval inside any other tool and widens no permission you did not \
             already have",
        ),
    ] {
        assert!(
            skill.contains(sentence),
            "the skill does not say {what}: {sentence}"
        );
    }
    for forbidden in [
        "assume yes",
        "treat silence as",
        "proceed without an answer",
    ] {
        assert!(
            !skill.to_lowercase().contains(forbidden),
            "the skill says {forbidden}"
        );
    }
}
