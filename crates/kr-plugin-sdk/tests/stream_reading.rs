//! What a table of an application server says the host reads and writes: how its approvals are
//! answered, which conversation and turn its stream names, and how its protocol spells the core's
//! own operations.
//!
//! A table of a server a native terminal speaks to answers an approval as the response to the
//! request itself, tells the host the places in its messages that name a thread, a turn and a
//! cleared request, and gives the request the host writes for a prompt, a steer and a
//! cancellation. The package validator every host, publisher and pipeline runs decides whether
//! a table says that completely and in a way the host can read. These cases build the example
//! connector package around each declaration and break it one way at a time.

use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::connector::{
    ConditionValue, ConnectorManifest, DecisionResponse, DecisionValue, FieldPath, FieldSegment,
    LeaveRoute, MAX_REQUEST_CONDITIONS, MessageMembers, MethodClass, MethodClassification,
    Observation, OperationRoute, Operations, RequestCondition, ResolvedRoute, ResponseCorrelation,
    Route, RouteDirection, SelectionRoute, TurnRoute,
};
use kr_plugin_sdk::example;
use kr_plugin_sdk::ids::{MethodName, ParameterName};
use kr_plugin_sdk::package::{CONNECTOR_FILE, MANIFEST_FILE, PRESENTATION_FILE};
use kr_plugin_sdk::plugin::{PayloadRole, PluginManifest};
use kr_plugin_sdk::text::Summary;
use kr_plugin_sdk::validate::{FindingCode, Report, validate_package_directory};
use kr_protocol::scalars::Nullable;

fn method(text: &str) -> MethodName {
    MethodName::new(text).expect("a valid method name")
}

fn decision(text: &str) -> ParameterName {
    ParameterName::new(text).expect("a valid decision")
}

fn path(names: &[&str]) -> FieldPath {
    FieldPath {
        segments: names
            .iter()
            .map(|name| FieldSegment::Member {
                name: (*name).to_owned(),
            })
            .collect(),
    }
}

fn route(name: &str, wire: &str, direction: RouteDirection) -> Route {
    Route {
        method: method(name),
        wire_name: wire.to_owned(),
        direction,
    }
}

fn classified(name: &str, class: MethodClass) -> MethodClassification {
    MethodClassification {
        method: method(name),
        class,
        evidence: Summary::new("Read from the application's own protocol").expect("a summary"),
    }
}

/// The example table, shaped like a server's: it names its message members, answers its approval
/// as the response to the request, and routes the methods an observation reads.
fn server_table() -> ConnectorManifest {
    let mut table = example::example_connector_table();
    table.messages = Some(MessageMembers {
        params: "params".to_owned(),
        result: "result".to_owned(),
        error: "error".to_owned(),
    });
    table.decision_destination = Nullable::null();
    // The answer is the response to the request, so the example's own answer method is not one.
    table
        .routes
        .retain(|route| route.method.as_str() != "approval.answer");
    table
        .methods
        .retain(|entry| entry.method.as_str() != "approval.answer");
    table.decision_response = Some(DecisionResponse {
        answers: vec![method("approval.request")],
        result_member: "decision".to_owned(),
        decisions: vec![
            DecisionValue {
                decision: decision("allow"),
                value: "accept".to_owned(),
            },
            DecisionValue {
                decision: decision("deny"),
                value: "decline".to_owned(),
            },
        ],
    });
    for (name, wire, direction, class) in [
        (
            "thread.start",
            "thread/start",
            RouteDirection::HostToUpstream,
            MethodClass::Mutation,
        ),
        (
            "thread.closed",
            "thread/closed",
            RouteDirection::UpstreamToHost,
            MethodClass::Observation,
        ),
        (
            "turn.started",
            "turn/started",
            RouteDirection::UpstreamToHost,
            MethodClass::Observation,
        ),
        (
            "turn.completed",
            "turn/completed",
            RouteDirection::UpstreamToHost,
            MethodClass::Observation,
        ),
        (
            "request.resolved",
            "serverRequest/resolved",
            RouteDirection::UpstreamToHost,
            MethodClass::Observation,
        ),
        (
            "turn.steer",
            "turn/steer",
            RouteDirection::HostToUpstream,
            MethodClass::Mutation,
        ),
    ] {
        table.routes.push(route(name, wire, direction));
        table.methods.push(classified(name, class));
    }
    table.observation = Some(Observation {
        selections: vec![SelectionRoute {
            method: method("thread.start"),
            thread: path(&["result", "thread", "id"]),
            hidden_when: Vec::new(),
        }],
        leaves: vec![LeaveRoute {
            method: method("thread.closed"),
            thread: path(&["params", "threadId"]),
        }],
        turn_started: Some(TurnRoute {
            method: method("turn.started"),
            thread: path(&["params", "threadId"]),
            turn: path(&["params", "turn", "id"]),
        }),
        turn_ended: Some(TurnRoute {
            method: method("turn.completed"),
            thread: path(&["params", "threadId"]),
            turn: path(&["params", "turn", "id"]),
        }),
        request_resolved: Some(ResolvedRoute {
            method: method("request.resolved"),
            request_id: path(&["params", "requestId"]),
        }),
    });
    table.operations = Some(Operations {
        prompt_submit: Some(OperationRoute {
            method: method("turn.start"),
            params: serde_json::json!({
                "threadId": { "$": "thread_id" },
                "input": [{ "type": "text", "text": { "$": "text" } }],
            }),
            reply_turn: Some(path(&["result", "turn", "id"])),
        }),
        prompt_queue: None,
        turn_steer: Some(OperationRoute {
            method: method("turn.steer"),
            params: serde_json::json!({
                "threadId": { "$": "thread_id" },
                "expectedTurnId": { "$": "turn_id" },
                "input": [{ "type": "text", "text": { "$": "text" } }],
            }),
            reply_turn: Some(path(&["result", "turnId"])),
        }),
        turn_cancel: Some(OperationRoute {
            method: method("turn.cancel"),
            params: serde_json::json!({
                "threadId": { "$": "thread_id" },
                "turnId": { "$": "turn_id" },
            }),
            reply_turn: None,
        }),
    });
    table
}

/// Writes the example connector package around `table`, edits its manifest, and validates it.
fn validate_with(table: &ConnectorManifest, edit: impl FnOnce(&mut PluginManifest)) -> Report {
    let connector = serde_json::to_vec_pretty(table).expect("the table serialises");
    let document = example::example_connector_presentation_json().into_bytes();
    let mut manifest = example::example_connector_manifest(&document, &connector);
    edit(&mut manifest);
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let package = temporary.path().join("package");
    std::fs::create_dir_all(&package).expect("the package directory");
    std::fs::write(
        package.join(MANIFEST_FILE),
        serde_json::to_vec_pretty(&manifest).expect("the manifest serialises"),
    )
    .expect("the manifest writes");
    std::fs::write(package.join(PRESENTATION_FILE), &document).expect("the document writes");
    if manifest.payload(PayloadRole::Connector).is_some() {
        std::fs::write(package.join(CONNECTOR_FILE), &connector).expect("the table writes");
    }
    validate_package_directory(&package).report
}

fn validated(table: &ConnectorManifest) -> Report {
    validate_with(table, |_| {})
}

/// Asserts a finding of `code` says `says`.
fn includes(report: &Report, code: FindingCode, says: &str) {
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == code && finding.detail.contains(says)),
        "no {} finding says {says:?}: {:?}",
        code.as_str(),
        report.findings
    );
}

fn refused(table: &ConnectorManifest, says: &str) {
    includes(&validated(table), FindingCode::ConnectorTableInvalid, says);
}

fn response(table: &mut ConnectorManifest) -> &mut DecisionResponse {
    table
        .decision_response
        .as_mut()
        .expect("the table declares a response")
}

fn operations(table: &mut ConnectorManifest) -> &mut Operations {
    table
        .operations
        .as_mut()
        .expect("the table declares operations")
}

fn observation(table: &mut ConnectorManifest) -> &mut Observation {
    table
        .observation
        .as_mut()
        .expect("the table declares an observation")
}

#[test]
fn a_table_that_answers_as_a_response_and_reads_the_stream_validates() {
    let report = validated(&server_table());
    assert!(report.is_valid(), "{:?}", report.findings);
    // And it is the bytes the package hash names: the members read back as written.
    let written = serde_json::to_value(server_table()).expect("the table serialises");
    let back: ConnectorManifest = serde_json::from_value(written).expect("it reads back");
    assert_eq!(back, server_table());
}

/// KR-REQ-11.33: the response a table answers with is read the way the application reads it, so
/// each decision has its own value, the requests it answers are ones the application asks, and the
/// package that declares it asks for both approval grants.
#[test]
fn kr_req_11_33_a_response_that_answers_an_approval_is_declared_completely() {
    // One way to answer, not two.
    let mut both = server_table();
    both.decision_destination = example::example_connector_table().decision_destination;
    refused(&both, "answers one way");

    let mut no_messages = server_table();
    no_messages.messages = None;
    no_messages.observation = None;
    refused(&no_messages, "names no message members");

    let mut by_order = server_table();
    by_order.response_correlation = ResponseCorrelation::Ordered {};
    refused(&by_order, "matches responses by order");

    let mut asked_by_the_host = server_table();
    response(&mut asked_by_the_host).answers = vec![method("turn.start")];
    refused(&asked_by_the_host, "the application never asks it");

    let mut unrouted = server_table();
    response(&mut unrouted).answers = vec![method("approval.unrouted")];
    refused(&unrouted, "which the table does not route");

    let mut unsupported = server_table();
    for entry in &mut unsupported.methods {
        if entry.method.as_str() == "approval.request" {
            entry.class = MethodClass::Unsupported;
        }
    }
    refused(&unsupported, "classifies as unsupported");

    let mut twice = server_table();
    response(&mut twice).answers = vec![method("approval.request"), method("approval.request")];
    refused(&twice, "more than once");

    let mut same_value = server_table();
    response(&mut same_value).decisions[1].value = "accept".to_owned();
    refused(&same_value, "cannot tell them apart");

    let mut reserved = server_table();
    response(&mut reserved).result_member = "result".to_owned();
    refused(&reserved, "is the table's result member");

    let mut nameless = server_table();
    response(&mut nameless).result_member = String::new();
    refused(&nameless, "result_member is empty");

    let mut none = server_table();
    response(&mut none).decisions.clear();
    refused(&none, "maps 0 decisions");

    // A choice the action offers that the table does not map is a decision a person could make
    // and the host could not send.
    let mut unmapped = server_table();
    response(&mut unmapped).decisions.pop();
    includes(
        &validated(&unmapped),
        FindingCode::ImplementationUnsatisfied,
        "which the decision response does not map",
    );

    // Interpreting a request and answering it are the two grants section 11 keeps apart.
    let without_grants = validate_with(&server_table(), |manifest| {
        manifest.capabilities.retain(|request| {
            !matches!(
                request.capability,
                PluginCapability::ApprovalDecode | PluginCapability::ApprovalRespond
            )
        });
    });
    includes(
        &without_grants,
        FindingCode::EffectWithoutCapability,
        "interprets approval requests and answers them",
    );
}

/// KR-REQ-12.06: the places the host reads a conversation and a turn out of a stream are checked
/// against the table that routes the messages.
#[test]
fn kr_req_12_06_an_observation_names_places_inside_messages_the_table_routes() {
    let mut no_messages = server_table();
    no_messages.messages = None;
    no_messages.decision_response = None;
    refused(&no_messages, "names no message members");

    let mut unrouted = server_table();
    observation(&mut unrouted).selections[0].method = method("thread.resume");
    refused(&unrouted, "which the table does not route");

    // A selection is a request of the terminal's, and a turn is a notification of the application's.
    let mut backwards = server_table();
    observation(&mut backwards).selections[0].method = method("turn.started");
    refused(&backwards, "the table routes it the other way");
    let mut also_backwards = server_table();
    observation(&mut also_backwards)
        .turn_started
        .as_mut()
        .expect("a start")
        .method = method("thread.start");
    refused(&also_backwards, "the table routes it the other way");

    // The reply is read inside the table's result member, a message's parameters inside its own.
    let mut reply_in_params = server_table();
    observation(&mut reply_in_params).selections[0].thread = path(&["params", "thread", "id"]);
    refused(&reply_in_params, "not inside the table's result member");
    let mut turn_in_result = server_table();
    observation(&mut turn_in_result)
        .turn_ended
        .as_mut()
        .expect("an end")
        .turn = path(&["result", "turn", "id"]);
    refused(&turn_in_result, "not inside the table's params member");

    // A method the table classifies as unsupported is one the host does not carry, so it cannot be
    // read as the place a conversation is named.
    let mut unsupported = server_table();
    for entry in &mut unsupported.methods {
        if entry.method.as_str() == "thread.start" {
            entry.class = MethodClass::Unsupported;
        }
    }
    refused(&unsupported, "classifies as unsupported");

    let mut two_roles = server_table();
    observation(&mut two_roles).leaves[0].method = method("turn.started");
    refused(&two_roles, "a method has one role");

    let mut one_place = server_table();
    observation(&mut one_place)
        .turn_started
        .as_mut()
        .expect("a start")
        .turn = path(&["params", "threadId"]);
    refused(&one_place, "overlapping places");

    let mut start_and_end = server_table();
    let ended = observation(&mut start_and_end)
        .turn_ended
        .as_mut()
        .expect("an end");
    ended.method = method("turn.started");
    refused(&start_and_end, "both the start and the end of a turn");
}

/// KR-REQ-12.06: the conditions under which a selection route's request starts a thread the
/// terminal never shows are checked when the table is read. A list of conditions, a place and a list
/// of values are bounded, and a table that breaks a bound is refused with a message of its own: it
/// is not read as one that states no condition, which would make every request of the route a
/// selection, and not as one whose condition can never be met.
#[test]
fn kr_req_12_06_the_conditions_of_a_hidden_request_are_checked_when_the_table_is_read() {
    let condition = |names: &[&str], values: Vec<ConditionValue>| RequestCondition {
        place: path(names),
        values,
    };
    let text = |value: &str| ConditionValue::Text(value.to_owned());
    let with = |conditions: Vec<RequestCondition>| {
        let mut table = server_table();
        observation(&mut table).selections[0].hidden_when = conditions;
        table
    };

    let fits = with(vec![
        condition(
            &["params", "ephemeral"],
            vec![ConditionValue::Boolean(true)],
        ),
        condition(&["params", "threadSource"], vec![text("system")]),
        condition(
            &["params", "depth"],
            vec![ConditionValue::Integer(
                kr_plugin_sdk::scalars::SafeInt::new(1).expect("an integer"),
            )],
        ),
    ]);
    let report = validated(&fits);
    assert!(report.is_valid(), "{:?}", report.findings);

    let many = with(
        (0..=MAX_REQUEST_CONDITIONS)
            .map(|n| condition(&["params", &format!("member{n}")], vec![text("x")]))
            .collect(),
    );
    refused(&many, "conditions for the requests of thread.start");

    let none = with(vec![condition(&["params", "threadSource"], Vec::new())]);
    refused(&none, "lists 0 values");

    let crowded = with(vec![condition(
        &["params", "threadSource"],
        (0..=MAX_REQUEST_CONDITIONS)
            .map(|n| text(&format!("source{n}")))
            .collect(),
    )]);
    refused(&crowded, "lists 9 values");

    // A place is read in the request's parameters: one in the reply never matches a request, and a
    // condition on the request's own method would hide every request of the route.
    let in_reply = with(vec![condition(
        &["result", "thread", "ephemeral"],
        vec![ConditionValue::Boolean(true)],
    )]);
    refused(
        &in_reply,
        "not inside the table's params member of the request",
    );
    let on_method = with(vec![condition(&["method"], vec![text("thread/start")])]);
    refused(
        &on_method,
        "not inside the table's params member of the request",
    );

    let nowhere = with(vec![condition(&[], vec![text("system")])]);
    refused(&nowhere, "a field path with 0 segments");

    let deep = with(vec![condition(
        &["params", "a", "b", "c", "d", "e", "f", "g", "h"],
        vec![text("system")],
    )]);
    refused(&deep, "a field path with 9 segments");
}

/// KR-REQ-12.12: the core's operations a table spells are the only requests the host writes of its
/// own, so each is a routed mutation to the application with a template that holds exactly the
/// values the core has for it.
#[test]
fn kr_req_12_12_an_operation_is_a_routed_mutation_with_a_template_that_fits_it() {
    let hole = |name: &str| serde_json::json!({ "$": name });

    let mut unrouted = server_table();
    operations(&mut unrouted)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .method = method("turn.unrouted");
    refused(&unrouted, "which the table does not route");

    let mut backwards = server_table();
    operations(&mut backwards)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .method = method("turn.started");
    refused(&backwards, "routes from the application to the host");

    let mut not_a_mutation = server_table();
    operations(&mut not_a_mutation)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .method = method("status.read");
    refused(&not_a_mutation, "does not classify as a mutation");

    let mut one_method = server_table();
    let submit = operations(&mut one_method)
        .prompt_submit
        .clone()
        .expect("a submit");
    operations(&mut one_method).prompt_queue = Some(submit);
    refused(&one_method, "could not tell which it sends");

    let mut none = server_table();
    *operations(&mut none) = Operations::default();
    refused(&none, "declares none");

    let mut not_an_object = server_table();
    operations(&mut not_an_object)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .params = serde_json::json!([]);
    refused(&not_an_object, "are not an object");

    // A hole is a whole value naming one of three things, and nothing else.
    let mut unknown_hole = server_table();
    operations(&mut unknown_hole)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .params = serde_json::json!({ "threadId": hole("thread_id"), "turnId": hole("turn") });
    refused(&unknown_hole, "is a hole");
    let mut hole_with_more = server_table();
    operations(&mut hole_with_more)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .params = serde_json::json!({
        "threadId": hole("thread_id"),
        "turnId": { "$": "turn_id", "extra": 1 },
    });
    refused(&hole_with_more, "is a hole");

    let mut no_thread = server_table();
    operations(&mut no_thread)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .params = serde_json::json!({ "turnId": hole("turn_id") });
    refused(&no_thread, "does not fill in thread_id");
    let mut no_turn = server_table();
    operations(&mut no_turn)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .params = serde_json::json!({ "threadId": hole("thread_id") });
    refused(&no_turn, "does not fill in turn_id");
    let mut no_text = server_table();
    operations(&mut no_text)
        .prompt_submit
        .as_mut()
        .expect("a submit")
        .params = serde_json::json!({ "threadId": hole("thread_id") });
    refused(&no_text, "does not fill in text");
    let mut surplus_text = server_table();
    operations(&mut surplus_text)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .params = serde_json::json!({
        "threadId": hole("thread_id"),
        "turnId": hole("turn_id"),
        "reason": hole("text"),
    });
    refused(&surplus_text, "fills in text, which it has no value for");
    let mut surplus_turn = server_table();
    operations(&mut surplus_turn)
        .prompt_submit
        .as_mut()
        .expect("a submit")
        .params = serde_json::json!({
        "threadId": hole("thread_id"),
        "turnId": hole("turn_id"),
        "text": hole("text"),
    });
    refused(&surplus_turn, "fills in turn_id, which it has no value for");

    // The template is bounded.
    let mut deep = server_table();
    let mut nested =
        serde_json::json!({ "threadId": hole("thread_id"), "turnId": hole("turn_id") });
    for _ in 0..9 {
        nested = serde_json::json!({ "inner": nested });
    }
    operations(&mut deep)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .params = nested;
    refused(&deep, "nests deeper than 8 levels");
    let mut wide = server_table();
    operations(&mut wide)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .params = serde_json::json!({
        "threadId": hole("thread_id"),
        "turnId": hole("turn_id"),
        "pad": vec![0_u8; 70],
    });
    refused(&wide, "the most is 64");
    let mut long = server_table();
    operations(&mut long)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .params = serde_json::json!({
        "threadId": hole("thread_id"),
        "turnId": hole("turn_id"),
        "pad": "x".repeat(300),
    });
    refused(&long, "over 256 bytes");
    let mut control = server_table();
    operations(&mut control)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .params = serde_json::json!({
        "threadId": hole("thread_id"),
        "turnId": hole("turn_id"),
        "pad": "a\nb",
    });
    refused(&control, "holds a control character");
    // The name of a member is a literal of the frame like any text in it.
    let mut long_name = server_table();
    operations(&mut long_name)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .params = serde_json::json!({
        "threadId": hole("thread_id"),
        "turnId": hole("turn_id"),
        "x".repeat(300): null,
    });
    refused(&long_name, "over 256 bytes");
    let mut control_name = server_table();
    operations(&mut control_name)
        .turn_cancel
        .as_mut()
        .expect("a cancel")
        .params = serde_json::json!({
        "threadId": hole("thread_id"),
        "turnId": hole("turn_id"),
        "a\nb": null,
    });
    refused(&control_name, "holds a control character");

    // A reply names its turn inside the result member the table names.
    let mut reply_in_params = server_table();
    operations(&mut reply_in_params)
        .prompt_submit
        .as_mut()
        .expect("a submit")
        .reply_turn = Some(path(&["params", "turn", "id"]));
    refused(&reply_in_params, "not inside the table's result member");

    // The members the template and the reply are read by come from the table.
    let mut no_messages = server_table();
    no_messages.messages = None;
    no_messages.decision_response = None;
    no_messages.observation = None;
    refused(&no_messages, "operations are written as requests");
}
