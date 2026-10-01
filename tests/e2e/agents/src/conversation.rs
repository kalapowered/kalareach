//! What a part reads in an agent's own record of a conversation: a file of JSON lines, one per
//! prompt, reply, tool call or event, each told apart by a mark the build list names.

use crate::build::RequestRecord;

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

/// Whether the agent's own record, after line `after` of `text`, holds exactly one request for
/// approval still pending, and it is one of the tool the part asked it to use, naming `command` and
/// the folder `cwd` it runs in. A request is a line holding `request.line` that is JSON with `kind`
/// `approval`, an `id` and a `toolCallId` that its `request` repeats, `request.toolName` the tool
/// named, `request.agentId` the main agent, `request.display.command` the command and
/// `request.display.cwd` the folder; it is pending while no later line holding
/// `request.resolved_line` names its `id`. The dialog on the screen shows the command alone, so
/// with two requests pending it could be either, and neither is answered.
///
/// # Errors
///
/// Returns what the record names in their place, that there is none pending, or that there are
/// several.
pub fn request_names(
    text: &str,
    after: Option<usize>,
    request: &RequestRecord,
    command: &str,
    cwd: &str,
) -> Result<(), String> {
    let words =
        |holder: &serde_json::Value, key: &str| holder[key].as_str().unwrap_or_default().to_owned();
    let lines: Vec<&str> = text.lines().collect();
    let answered = |from: usize, id: &str| {
        lines.iter().skip(from + 1).any(|later| {
            later.contains(request.resolved_line.as_str())
                && serde_json::from_str::<serde_json::Value>(later)
                    .is_ok_and(|answer| words(&answer, "id") == id)
        })
    };
    let mut pending: Vec<serde_json::Value> = Vec::new();
    let mut requests = 0;
    for (at, line) in lines.iter().enumerate() {
        if after.is_some_and(|from| at <= from) || !line.contains(request.line.as_str()) {
            continue;
        }
        requests += 1;
        let record: serde_json::Value = serde_json::from_str(line)
            .map_err(|error| format!("a request's record is not JSON: {error}"))?;
        if !answered(at, &words(&record, "id")) {
            pending.push(record);
        }
    }
    let record = match pending.as_slice() {
        [] if requests == 0 => {
            return Err("the conversation holds no record of a request for approval".to_owned());
        }
        [] => return Err("every request for approval in the record has been answered".to_owned()),
        [one] => one,
        several => {
            return Err(format!(
                "{} requests for approval are pending, and the dialog could be any of them",
                several.len()
            ));
        }
    };
    if words(record, "kind") != "approval" {
        return Err("the record is not a request for approval".to_owned());
    }
    let id = words(record, "id");
    let details = &record["request"];
    if id.is_empty() || words(details, "id") != id {
        return Err("the request's record has no identifier, or two".to_owned());
    }
    let call = words(record, "toolCallId");
    if call.is_empty() || words(details, "toolCallId") != call {
        return Err("the request's record names no tool call, or two".to_owned());
    }
    if words(details, "toolName") != request.tool {
        return Err("the request's record is for another tool".to_owned());
    }
    if words(record, "agentId") != "main" || words(details, "agentId") != "main" {
        return Err("the request's record is not the main agent's".to_owned());
    }
    let display = &details["display"];
    if words(display, "command") != command {
        return Err("the request's record names another command".to_owned());
    }
    if words(display, "cwd") != cwd {
        return Err("the request's record names another folder to run it in".to_owned());
    }
    Ok(())
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
    fn a_request_for_approval_is_the_one_pending_for_the_tool_with_the_command_and_the_folder() {
        let request = |id: &str, tool: &str, command: &str, cwd: &str| {
            format!(
                "{{\"type\":\"interaction.request\",\"agentId\":\"main\",\"id\":\"{id}\",\"kind\":\"approval\",\"toolCallId\":\"call-{id}\",\"request\":{{\"id\":\"{id}\",\"agentId\":\"main\",\"toolCallId\":\"call-{id}\",\"toolName\":\"{tool}\",\"display\":{{\"kind\":\"command\",\"command\":\"{command}\",\"cwd\":\"{cwd}\"}}}}}}\n"
            )
        };
        let resolved = |id: &str| {
            format!(
                "{{\"type\":\"interaction.resolved\",\"id\":\"{id}\",\"response\":{{\"decision\":\"approved\"}}}}\n"
            )
        };
        let record = RequestRecord {
            line: r#""type":"interaction.request""#.to_owned(),
            resolved_line: r#""type":"interaction.resolved""#.to_owned(),
            tool: "Bash".to_owned(),
        };
        let names = |text: &str, command: &str, cwd: &str| {
            request_names(text, Some(0), &record, command, cwd)
        };
        let prompt = "{\"type\":\"turn.prompt\"}\n";
        // An earlier request answered, and the one pending.
        let text = format!(
            "{prompt}{}{}{}",
            request("a", "Bash", "echo a >> a", "/r/w"),
            resolved("a"),
            request("b", "Bash", "echo kr1 >> a", "/r/w")
        );
        assert_eq!(names(&text, "echo kr1 >> a", "/r/w"), Ok(()));
        assert!(
            names(&text, "echo a >> a", "/r/w").is_err(),
            "the pending one is the one read"
        );
        assert!(names(&text, "echo kr1 >> a", "/elsewhere").is_err());
        assert!(
            request_names(&text, Some(3), &record, "echo kr1 >> a", "/r/w").is_err(),
            "nothing after that line"
        );
        // Two pending: the dialog could be either, and the same command in another folder is not told
        // apart on the screen.
        let two = format!(
            "{prompt}{}{}",
            request("a", "Bash", "echo kr1 >> a", "/other"),
            request("b", "Bash", "echo kr1 >> a", "/r/w")
        );
        assert!(names(&two, "echo kr1 >> a", "/r/w").is_err());
        // Another tool's request, an answered one, and the answer to another request.
        let other_tool = format!("{prompt}{}", request("c", "Write", "echo kr1 >> a", "/r/w"));
        assert!(names(&other_tool, "echo kr1 >> a", "/r/w").is_err());
        let answered = format!("{text}{}", resolved("b"));
        assert!(names(&answered, "echo kr1 >> a", "/r/w").is_err());
        let another_answered = format!("{text}{}", resolved("c"));
        assert_eq!(
            names(&another_answered, "echo kr1 >> a", "/r/w"),
            Ok(()),
            "the answer to another request does not answer this one"
        );
        // A record that contradicts itself, a subagent's, and one that is no JSON.
        let torn = text.replace("call-b\",\"request", "call-x\",\"request");
        assert!(names(&torn, "echo kr1 >> a", "/r/w").is_err());
        let subagent = text.replace("\"agentId\":\"main\"", "\"agentId\":\"agent-0\"");
        assert!(names(&subagent, "echo kr1 >> a", "/r/w").is_err());
        assert!(
            request_names(
                "not json with the mark \"type\":\"interaction.request\"\n",
                None,
                &record,
                "c",
                "d"
            )
            .is_err()
        );
        assert!(names(prompt, "c", "d").is_err(), "none at all");
    }

    #[test]
    fn a_turn_started_between_two_lines_only_where_its_mark_lies_between_them() {
        let marker = r#""type":"task_started""#;
        assert_eq!(turn_between(CONVERSATION, 1, 7, marker), Some(true));
        assert_eq!(turn_between(CONVERSATION, 1, 5, marker), Some(false));
        assert_eq!(turn_between(CONVERSATION, 5, 1, marker), None);
    }
}
