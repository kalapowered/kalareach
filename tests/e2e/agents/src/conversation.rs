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

/// How many lines of `text` after the line `after` hold `marker`, an answer to a tool approval.
/// Where `calls` names what marks a call that asks for approval, only the answers to such calls
/// after `after` count, each tied to its call by the call's identifier.
#[must_use]
pub fn answers(text: &str, after: Option<usize>, marker: &str, calls: &[String]) -> usize {
    let lines: Vec<&str> = text
        .lines()
        .skip(after.map_or(0, |line| line + 1))
        .collect();
    let asked: std::collections::BTreeSet<String> = lines
        .iter()
        .filter(|line| calls.iter().any(|call| line.contains(call.as_str())))
        .filter_map(|line| call_id_of(line))
        .collect();
    lines
        .iter()
        .filter(|line| line.contains(marker))
        .filter(|line| calls.is_empty() || call_id_of(line).is_some_and(|id| asked.contains(&id)))
        .count()
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
        assert_eq!(answers(CONVERSATION, Some(1), marker, &[]), 2);
        assert_eq!(
            answers(
                CONVERSATION,
                Some(1),
                marker,
                &[
                    "require_escalated".to_owned(),
                    "with_additional_permissions".to_owned()
                ]
            ),
            1,
            "the sandbox's own refusal of a call that asked nobody is not an answer"
        );
        assert_eq!(
            answers(
                CONVERSATION,
                Some(3),
                marker,
                &["require_escalated".to_owned()]
            ),
            1
        );
        assert_eq!(
            answers(
                CONVERSATION,
                Some(4),
                marker,
                &["require_escalated".to_owned()]
            ),
            0,
            "an answer whose call came before `after` is not tied to one after it"
        );
        assert_eq!(call_id_of("not json"), None);
    }

    #[test]
    fn a_turn_started_between_two_lines_only_where_its_mark_lies_between_them() {
        let marker = r#""type":"task_started""#;
        assert_eq!(turn_between(CONVERSATION, 1, 7, marker), Some(true));
        assert_eq!(turn_between(CONVERSATION, 1, 5, marker), Some(false));
        assert_eq!(turn_between(CONVERSATION, 5, 1, marker), None);
    }
}
