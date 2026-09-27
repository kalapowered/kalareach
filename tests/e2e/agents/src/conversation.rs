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

/// How many answers to tool approvals `text` records after the line `after`. Where `calls` is
/// empty, every line holding `marker` is one. Where `calls` names what marks a call that asks for
/// approval, a call is a line that holds one of them and is not itself an answer, and the count is
/// how many such calls after `after` have at least one answer tied to them by the call's identifier:
/// an agent may write several lines of output for one call, and a line that only quotes such a
/// text, an error naming it, is not a call. A call that holds those texts more than once can ask
/// more than once, and one without an identifier cannot be tied to its answers; either leaves the
/// count unknown.
///
/// # Errors
///
/// Returns why the count cannot be established.
pub fn answers(
    text: &str,
    after: Option<usize>,
    marker: &str,
    calls: &[String],
) -> Result<usize, String> {
    let lines: Vec<&str> = text
        .lines()
        .skip(after.map_or(0, |line| line + 1))
        .collect();
    if calls.is_empty() {
        return Ok(lines.iter().filter(|line| line.contains(marker)).count());
    }
    let mut asked = std::collections::BTreeSet::new();
    for line in lines.iter().filter(|line| !line.contains(marker)) {
        let asks: usize = calls
            .iter()
            .map(|call| line.matches(call.as_str()).count())
            .sum();
        if asks == 0 {
            continue;
        }
        if asks > 1 {
            return Err(format!(
                "a call holds {asks} requests for approval, so its answers cannot be counted"
            ));
        }
        let id = call_id_of(line)
            .ok_or_else(|| "a call that asks for approval has no call_id".to_owned())?;
        asked.insert(id);
    }
    let answered: std::collections::BTreeSet<String> = lines
        .iter()
        .filter(|line| line.contains(marker))
        .filter_map(|line| call_id_of(line))
        .filter(|id| asked.contains(id))
        .collect();
    Ok(answered.len())
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

    #[test]
    fn only_the_answers_to_calls_that_asked_count_where_the_calls_are_marked() {
        let marker = r#""type":"function_call_output""#;
        let asking = || {
            vec![
                "require_escalated".to_owned(),
                "with_additional_permissions".to_owned(),
            ]
        };
        assert_eq!(answers(CONVERSATION, Some(1), marker, &[]), Ok(2));
        assert_eq!(
            answers(CONVERSATION, Some(1), marker, &asking()),
            Ok(1),
            "the sandbox's own refusal of a call that asked nobody is not an answer"
        );
        assert_eq!(
            answers(CONVERSATION, Some(4), marker, &asking()),
            Ok(0),
            "an answer whose call came before `after` is not tied to one after it"
        );
        assert_eq!(call_id_of("not json"), None);
        let quoting = r#"{"type":"response_item","payload":{"type":"function_call","call_id":"c","arguments":"{\"cmd\":\"echo\",\"justification\":\"x\"}"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"c","output":"`justification` requires an explicit `sandbox_permissions`; use `sandbox_permissions: \"require_escalated\"`"}}
"#;
        assert_eq!(
            answers(quoting, None, marker, &asking()),
            Ok(0),
            "an answer that only names the text ties to no call that asked"
        );
    }

    #[test]
    fn several_outputs_of_one_call_are_one_answer_and_a_call_that_asks_twice_is_unknown() {
        let marker = "_call_output\"";
        let asking = vec!["require_escalated".to_owned()];
        let notified = r#"{"type":"response_item","payload":{"type":"custom_tool_call","call_id":"x","input":"tools.exec_command({cmd: \"echo\", sandbox_permissions: \"require_escalated\"})"}}
{"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"x","output":"a notice"}}
{"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"x","output":"done"}}
"#;
        assert_eq!(answers(notified, None, marker, &asking), Ok(1));
        let twice = r#"{"type":"response_item","payload":{"type":"custom_tool_call","call_id":"y","input":"a(\"require_escalated\"); b(\"require_escalated\")"}}
{"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"y","output":"done"}}
"#;
        assert!(answers(twice, None, marker, &asking).is_err());
        let nameless = r#"{"type":"response_item","payload":{"type":"custom_tool_call","input":"require_escalated"}}
"#;
        assert!(answers(nameless, None, marker, &asking).is_err());
    }

    #[test]
    fn a_turn_started_between_two_lines_only_where_its_mark_lies_between_them() {
        let marker = r#""type":"task_started""#;
        assert_eq!(turn_between(CONVERSATION, 1, 7, marker), Some(true));
        assert_eq!(turn_between(CONVERSATION, 1, 5, marker), Some(false));
        assert_eq!(turn_between(CONVERSATION, 5, 1, marker), None);
    }
}
