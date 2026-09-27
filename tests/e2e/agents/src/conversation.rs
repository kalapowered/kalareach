//! What a part reads in an agent's own record of a conversation: a file of JSON lines, one per
//! prompt, reply, tool call or event, each told apart by a mark the build list names.

/// The identifier a conversation line gives the tool call it records or answers: its first string
/// member named `call_id`, at any depth.
#[must_use]
pub fn call_id_of(line: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let mut pending = vec![&value];
    while let Some(value) = pending.pop() {
        match value {
            serde_json::Value::Object(members) => {
                if let Some(id) = members.get("call_id").and_then(serde_json::Value::as_str) {
                    return Some(id.to_owned());
                }
                pending.extend(members.values());
            }
            serde_json::Value::Array(items) => pending.extend(items),
            _ => {}
        }
    }
    None
}

/// How many answers to tool approvals `text` records after the line `after`. Where `asking` is
/// empty, every line holding `answer` is one. Where it names what marks a call that asks for
/// approval, the records are read by kind: a call is a line holding one of `call` (and not
/// `answer`), an answer a line holding `answer`, each tied to its call by the call's identifier; the
/// count is how many calls holding one of `asking` have at least one answer, since an agent may
/// write several lines of output for one call, and an answer to a call that asked nobody, such as
/// the sandbox's own refusal, is not one. Anything that could make that count wrong leaves it
/// unknown: a call or an answer without an identifier, a call holding `asking` more than once,
/// which can ask more than once, or an answer tied to no call after `after`.
///
/// # Errors
///
/// Returns why the count cannot be established.
pub fn answers(
    text: &str,
    after: Option<usize>,
    (answer, call, asking): (&str, &[String], &[String]),
) -> Result<usize, String> {
    let lines: Vec<&str> = text
        .lines()
        .skip(after.map_or(0, |line| line + 1))
        .collect();
    if asking.is_empty() {
        return Ok(lines.iter().filter(|line| line.contains(answer)).count());
    }
    if call.is_empty() {
        return Err("nothing marks a call, so no answer can be tied to one".to_owned());
    }
    let mut calls = std::collections::BTreeMap::new();
    let mut answered = Vec::new();
    for line in &lines {
        if line.contains(answer) {
            answered.push(call_id_of(line).ok_or_else(|| "an answer has no call_id".to_owned())?);
        } else if call.iter().any(|kind| line.contains(kind.as_str())) {
            let id = call_id_of(line).ok_or_else(|| "a call has no call_id".to_owned())?;
            let asks: usize = asking
                .iter()
                .map(|text| line.matches(text.as_str()).count())
                .sum();
            if asks > 1 {
                return Err(format!(
                    "a call holds {asks} requests for approval, so its answers cannot be counted"
                ));
            }
            calls.insert(id, asks == 1);
        }
    }
    let mut counted = std::collections::BTreeSet::new();
    for id in answered {
        match calls.get(&id) {
            Some(true) => {
                counted.insert(id);
            }
            Some(false) => {}
            None => {
                return Err(format!(
                    "an answer is tied to no call recorded after the prompt ({id})"
                ));
            }
        }
    }
    Ok(counted.len())
}

/// Whether a line of `text` holding `marker` lies after the line `from` and before the line `to`:
/// a turn that started between them, where the agent marks each turn's start. `None` where `to`
/// does not come after `from`.
#[must_use]
pub fn turn_between(text: &str, from: usize, to: usize, marker: &str) -> Option<bool> {
    (to > from).then(|| {
        text.lines()
            .enumerate()
            .any(|(index, line)| index > from && index < to && line.contains(marker))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONVERSATION: &str = r#"{"type":"event_msg","payload":{"type":"task_started"}}
{"type":"response_item","payload":{"type":"message","role":"user","content":[{"text":"run it"}]}}
{"type":"response_item","payload":{"type":"function_call","call_id":"a","arguments":"{\"cmd\":\"echo\"}"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"a","output":"denied by the sandbox"}}
{"type":"response_item","payload":{"type":"function_call","call_id":"b","arguments":"{\"cmd\":\"echo\",\"sandbox_permissions\":\"require_escalated\"}"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"b","output":"exit 0"}}
{"type":"event_msg","payload":{"type":"task_started"}}
{"type":"response_item","payload":{"type":"message","role":"user","content":[{"text":"again"}]}}
"#;

    /// The marks Codex's conversations carry: an answer, the two kinds of call, what asks.
    fn marks() -> (String, Vec<String>, Vec<String>) {
        (
            "_call_output\"".to_owned(),
            vec![
                r#""type":"function_call""#.to_owned(),
                r#""type":"custom_tool_call""#.to_owned(),
            ],
            vec![
                "require_escalated".to_owned(),
                "with_additional_permissions".to_owned(),
            ],
        )
    }

    #[test]
    fn only_the_answers_to_calls_that_asked_count_where_the_calls_are_marked() {
        let (answer, call, asking) = marks();
        assert_eq!(answers(CONVERSATION, Some(1), (&answer, &call, &[])), Ok(2));
        assert_eq!(
            answers(CONVERSATION, Some(1), (&answer, &call, &asking)),
            Ok(1),
            "the sandbox's own refusal of a call that asked nobody is not an answer"
        );
        assert!(
            answers(CONVERSATION, Some(4), (&answer, &call, &asking)).is_err(),
            "an answer whose call came before `after` leaves the count unknown"
        );
        assert_eq!(call_id_of("not json"), None);
        let quoting = r#"{"type":"response_item","payload":{"type":"function_call","call_id":"c","arguments":"{\"cmd\":\"echo\",\"justification\":\"x\"}"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"c","output":"`justification` requires an explicit `sandbox_permissions`; use `sandbox_permissions: \"require_escalated\"`"}}
"#;
        assert_eq!(
            answers(quoting, None, (&answer, &call, &asking)),
            Ok(0),
            "an answer that only names the text ties to a call that asked nobody"
        );
        assert!(
            answers(CONVERSATION, Some(1), (&answer, &[], &asking)).is_err(),
            "without a mark for calls nothing can be tied"
        );
    }

    #[test]
    fn several_outputs_of_one_call_are_one_answer_and_a_count_that_could_be_wrong_is_unknown() {
        let (answer, call, asking) = marks();
        let notified = r#"{"type":"response_item","payload":{"type":"custom_tool_call","call_id":"x","input":"tools.exec_command({cmd: \"echo\", sandbox_permissions: \"require_escalated\"})"}}
{"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"x","output":"a notice"}}
{"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"x","output":"done"}}
"#;
        assert_eq!(answers(notified, None, (&answer, &call, &asking)), Ok(1));
        let twice = r#"{"type":"response_item","payload":{"type":"custom_tool_call","call_id":"y","input":"a(\"require_escalated\"); b(\"require_escalated\")"}}
{"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"y","output":"done"}}
"#;
        assert!(answers(twice, None, (&answer, &call, &asking)).is_err());
        let nameless = r#"{"type":"response_item","payload":{"type":"custom_tool_call","input":"require_escalated"}}
"#;
        assert!(answers(nameless, None, (&answer, &call, &asking)).is_err());
        let orphan = r#"{"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"z","output":"done"}}
"#;
        assert!(answers(orphan, None, (&answer, &call, &asking)).is_err());
        let quoted = r#"{"type":"event_msg","payload":{"type":"agent_message","message":"I will use require_escalated"}}
"#;
        assert_eq!(
            answers(quoted, None, (&answer, &call, &asking)),
            Ok(0),
            "a line that is no call record is not a call"
        );
    }

    #[test]
    fn a_turn_started_between_two_lines_only_where_its_mark_lies_between_them() {
        let marker = r#""type":"task_started""#;
        assert_eq!(turn_between(CONVERSATION, 1, 7, marker), Some(true));
        assert_eq!(turn_between(CONVERSATION, 1, 5, marker), Some(false));
        assert_eq!(turn_between(CONVERSATION, 5, 1, marker), None);
    }
}
