//! Answering a pending approval from a declarative package.
//!
//! A package answers an approval with three things: a connector table that says where an answer
//! goes, an action that answers through it, and an invocation that names the pending resource.
//! These tests build the example connector package with each part broken in one way and check that
//! the validator names the break, then follow a valid answer from the invocation to the bytes.

use std::collections::BTreeSet;

use kr_plugin_sdk::connector::{
    ConnectorManifest, DecisionValue, FieldPath, FieldSegment, MethodClass, RouteDirection,
};
use kr_plugin_sdk::effect::{
    ActionArgument, ActionImplementation, ActionInvocation, ArgumentValue, EffectClass,
    InvocationError, ParameterDeclaration, ParameterKind,
};
use kr_plugin_sdk::example;
use kr_plugin_sdk::ids::{ActionName, MethodName, ParameterName};
use kr_plugin_sdk::package::{CONNECTOR_FILE, MANIFEST_FILE, PRESENTATION_FILE};
use kr_plugin_sdk::plugin::{PayloadRole, PluginManifest};
use kr_plugin_sdk::validate::{FindingCode, Report, validate_package_directory};
use kr_protocol::ids::PendingResourceId;
use kr_protocol::scalars::{Nullable, Uuid};

fn name(text: &str) -> ParameterName {
    ParameterName::new(text).expect("a valid parameter name")
}

fn method(text: &str) -> MethodName {
    MethodName::new(text).expect("a valid method name")
}

fn members(names: &[&str]) -> FieldPath {
    FieldPath {
        segments: names
            .iter()
            .map(|name| FieldSegment::Member {
                name: (*name).to_owned(),
            })
            .collect(),
    }
}

/// Writes the example connector package with its table and manifest edited, and validates it.
fn validate_with(
    edit_table: impl FnOnce(&mut ConnectorManifest),
    edit_manifest: impl FnOnce(&mut PluginManifest),
) -> Report {
    let mut table = example::example_connector_table();
    edit_table(&mut table);
    let connector = serde_json::to_vec_pretty(&table).expect("the table serialises");
    let document = example::example_connector_presentation_json().into_bytes();
    let mut manifest = example::example_connector_manifest(&document, &connector);
    edit_manifest(&mut manifest);
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

fn table_only(edit: impl FnOnce(&mut ConnectorManifest)) -> Report {
    validate_with(edit, |_| {})
}

fn manifest_only(edit: impl FnOnce(&mut PluginManifest)) -> Report {
    validate_with(|_| {}, edit)
}

fn codes(report: &Report) -> BTreeSet<FindingCode> {
    report.codes().into_iter().collect()
}

/// Asserts the report holds exactly one kind of finding, and that one of them says `says`.
fn refused(report: &Report, code: FindingCode, says: &str) {
    assert_eq!(
        codes(report),
        BTreeSet::from([code]),
        "{:?}",
        report.findings
    );
    includes(report, code, says);
}

/// Asserts that one finding of `code` says `says`, whatever else the break also caused.
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

fn destination(
    table: &mut ConnectorManifest,
) -> &mut kr_plugin_sdk::connector::DecisionDestination {
    table
        .decision_destination
        .0
        .as_mut()
        .expect("the example declares a destination")
}

fn answer_action(manifest: &mut PluginManifest) -> &mut kr_plugin_sdk::effect::ActionDeclaration {
    manifest
        .actions
        .iter_mut()
        .find(|action| action.id.as_str() == "approval.answer")
        .expect("the example registers an answer")
}

#[test]
fn the_example_answers_through_its_table_and_validates() {
    let report = validate_with(|_| {}, |_| {});
    assert!(report.is_valid(), "{:?}", report.findings);
}

/// KR-REQ-12.18: the destination's method carries the answer from the host to the application
/// and is classified as a mutation; the method it answers comes the other way.
#[test]
fn kr_req_12_18_an_answer_travels_to_the_application_as_a_classified_mutation() {
    refused(
        &table_only(|table| destination(table).method = method("approval.unrouted")),
        FindingCode::ConnectorTableInvalid,
        "which the table does not route",
    );
    refused(
        &table_only(|table| {
            let route = table
                .routes
                .iter_mut()
                .find(|route| route.method.as_str() == "approval.answer")
                .expect("the answer is routed");
            route.direction = RouteDirection::UpstreamToHost;
        }),
        FindingCode::ConnectorTableInvalid,
        "routes from the application to the host",
    );
    refused(
        &table_only(|table| {
            let entry = table
                .methods
                .iter_mut()
                .find(|entry| entry.method.as_str() == "approval.answer")
                .expect("the answer is classified");
            entry.class = MethodClass::Observation;
        }),
        FindingCode::ConnectorTableInvalid,
        "does not classify as a mutation",
    );
    refused(
        &table_only(|table| destination(table).answers = method("status.read")),
        FindingCode::ConnectorTableInvalid,
        "the application never asks it",
    );
    refused(
        &table_only(|table| destination(table).answers = method("approval.unrouted")),
        FindingCode::ConnectorTableInvalid,
        "answers approval.unrouted, which the table does not route",
    );
    // A request classified as outside what the table can proxy is not one it answers.
    refused(
        &table_only(|table| {
            let entry = table
                .methods
                .iter_mut()
                .find(|entry| entry.method.as_str() == "approval.request")
                .expect("the request is classified");
            entry.class = MethodClass::Unsupported;
        }),
        FindingCode::ConnectorTableInvalid,
        "classifies as unsupported",
    );
}

/// KR-REQ-12.18: an answer's two paths are member names inside the depth bound, and neither
/// meets the other or the method name.
#[test]
fn kr_req_12_18_an_answer_is_written_to_fields_that_can_hold_it() {
    let nine: Vec<&str> = vec!["params"; 9];
    refused(
        &table_only(|table| destination(table).request_id_path = members(&nine)),
        FindingCode::ConnectorTableInvalid,
        "the decision destination's request_id_path has a field path with 9 segments",
    );
    refused(
        &table_only(|table| destination(table).decision_path = members(&[])),
        FindingCode::ConnectorTableInvalid,
        "the decision destination's decision_path has a field path with 0 segments",
    );
    refused(
        &table_only(|table| {
            destination(table).decision_path = FieldPath {
                segments: vec![
                    FieldSegment::Member {
                        name: "params".to_owned(),
                    },
                    FieldSegment::Index { index: 0 },
                ],
            };
        }),
        FindingCode::ConnectorTableInvalid,
        "names an array element",
    );
    refused(
        &table_only(|table| {
            destination(table).decision_path = members(&["params", "request_id"]);
        }),
        FindingCode::ConnectorTableInvalid,
        "overlapping fields",
    );
    refused(
        &table_only(|table| destination(table).decision_path = members(&["method"])),
        FindingCode::ConnectorTableInvalid,
        "meets the method path",
    );
}

/// KR-REQ-12.18: every decision maps to its own value, and the upstream can tell them apart.
#[test]
fn kr_req_12_18_every_decision_maps_to_its_own_value() {
    // An empty mapping also leaves every decision the example offers unmapped.
    let empty = table_only(|table| destination(table).decisions.clear());
    includes(
        &empty,
        FindingCode::ConnectorTableInvalid,
        "maps 0 decisions",
    );
    includes(
        &empty,
        FindingCode::ImplementationUnsatisfied,
        "offers the decision allow, which the decision destination does not map",
    );
    refused(
        &table_only(|table| {
            destination(table).decisions.push(DecisionValue {
                decision: name("allow"),
                value: "always".to_owned(),
            });
        }),
        FindingCode::ConnectorTableInvalid,
        "maps allow more than once",
    );
    refused(
        &table_only(|table| {
            destination(table).decisions[1].value = "approved".to_owned();
        }),
        FindingCode::ConnectorTableInvalid,
        "cannot tell them apart",
    );
    for value in [String::new(), "x".repeat(257), "allow\u{7}".to_owned()] {
        refused(
            &table_only(|table| destination(table).decisions[0].value = value.clone()),
            FindingCode::ConnectorTableInvalid,
            "maps allow to a value that is empty",
        );
    }
}

/// KR-REQ-11.47 and KR-REQ-12.18: an answer is implemented only through the destination, and a
/// routed method with free parameters can neither answer nor send what the destination keeps.
#[test]
fn kr_req_11_47_only_the_destination_answers() {
    // The answering form carries nothing but an answer.
    refused(
        &manifest_only(|manifest| answer_action(manifest).effect = EffectClass::UpstreamPrompt),
        FindingCode::ImplementationMismatch,
        "is implemented as decision_destination but declares the effect upstream.prompt",
    );
    // A routed method with parameters does not answer an approval.
    refused(
        &manifest_only(|manifest| {
            let prompt = manifest
                .actions
                .iter_mut()
                .find(|action| action.id.as_str() == "prompt.send")
                .expect("the example sends prompts");
            prompt.effect = EffectClass::ApprovalRespond;
        }),
        FindingCode::ImplementationMismatch,
        "is implemented as upstream_method but declares the effect approval.respond",
    );
    // Nor does it send the destination's method as some other effect.
    refused(
        &manifest_only(|manifest| {
            let prompt = manifest
                .actions
                .iter_mut()
                .find(|action| action.id.as_str() == "prompt.send")
                .expect("the example sends prompts");
            prompt.implementation = ActionImplementation::UpstreamMethod {
                method: method("approval.answer"),
                bindings: vec![
                    kr_plugin_sdk::effect::ParameterBinding {
                        parameter: name("text"),
                        field: members(&["params", "decision"]),
                    },
                    kr_plugin_sdk::effect::ParameterBinding {
                        parameter: name("queue"),
                        field: members(&["params", "queue"]),
                    },
                ],
            };
        }),
        FindingCode::ImplementationUnsatisfied,
        "keeps for answers",
    );
    // An answer needs the capability its class names.
    refused(
        &manifest_only(|manifest| {
            manifest
                .capabilities
                .retain(|request| request.capability.as_str() != "approval.respond");
        }),
        FindingCode::EffectWithoutCapability,
        "does not request approval.respond",
    );
}

/// KR-REQ-12.18: the answering action says which parameter carries the decision, and every
/// decision a person can pick is one the destination maps.
#[test]
fn kr_req_12_18_an_answer_offers_only_decisions_the_table_can_send() {
    refused(
        &manifest_only(|manifest| {
            let action = answer_action(manifest);
            if let ParameterKind::Choice { choices } = &mut action.parameters.parameters[0].kind {
                choices.push(kr_plugin_sdk::effect::ParameterChoice {
                    id: name("allow-always"),
                    label: kr_plugin_sdk::text::Label::new("Always allow").expect("a label"),
                });
            }
        }),
        FindingCode::ImplementationUnsatisfied,
        "offers the decision allow-always, which the decision destination does not map",
    );
    // The example's own controls offer choices, so they widen a text parameter as well.
    includes(
        &manifest_only(|manifest| {
            answer_action(manifest).parameters.parameters[0].kind = ParameterKind::Text {
                max_length: kr_plugin_sdk::scalars::Count::new(8),
                multiline: false,
            };
        }),
        FindingCode::ImplementationUnsatisfied,
        "which is not a choice",
    );
    refused(
        &manifest_only(|manifest| {
            answer_action(manifest).parameters.parameters[0].required = false;
        }),
        FindingCode::ImplementationUnsatisfied,
        "which it does not require",
    );
    refused(
        &manifest_only(|manifest| {
            answer_action(manifest)
                .parameters
                .parameters
                .push(ParameterDeclaration {
                    name: name("note"),
                    kind: ParameterKind::Text {
                        max_length: kr_plugin_sdk::scalars::Count::new(80),
                        multiline: false,
                    },
                    label: kr_plugin_sdk::text::Label::new("Note").expect("a label"),
                    required: false,
                });
        }),
        FindingCode::ImplementationUnsatisfied,
        "declares the parameter note, which an answer does not carry",
    );
    refused(
        &manifest_only(|manifest| {
            answer_action(manifest).implementation = ActionImplementation::DecisionDestination {
                decision: name("verdict"),
            };
        }),
        FindingCode::ImplementationUnsatisfied,
        "refers to the parameter verdict, which it does not declare",
    );
}

/// KR-REQ-12.18: a package that answers through a destination ships a table that declares one.
#[test]
fn kr_req_12_18_an_answer_needs_a_table_with_a_destination() {
    refused(
        &table_only(|table| table.decision_destination = Nullable::null()),
        FindingCode::ImplementationUnsatisfied,
        "the table declares none",
    );
    includes(
        &validate_with(
            |_| {},
            |manifest| {
                manifest
                    .payloads
                    .retain(|payload| payload.role != PayloadRole::Connector);
            },
        ),
        FindingCode::ImplementationUnsatisfied,
        "answers through the connector table's decision destination and the package ships no connector table",
    );
}

/// KR-REQ-12.18 and KR-REQ-11.34: the whole declarative path, with no component on it. An
/// invocation that names the pending resource and a decision is checked against the action, the
/// decision is read from it, and the table writes the answer from that decision and the pending
/// request's own identifier. Without the resource, or with a decision the action does not offer,
/// nothing is written.
#[test]
fn kr_req_12_18_an_invocation_becomes_the_answer_the_table_writes() {
    let document = example::example_connector_presentation_json().into_bytes();
    let connector_bytes = example::example_connector_table_json().into_bytes();
    let manifest = example::example_connector_manifest(&document, &connector_bytes);
    assert!(!manifest.has_component(), "no component is on the path");
    let table = example::example_connector_table();
    let action = manifest
        .actions
        .iter()
        .find(|action| action.id.as_str() == "approval.answer")
        .expect("the example registers an answer");
    let resource = PendingResourceId::new(Uuid::from_bytes([9; 16]));
    let invocation = |resource_id, decision: &str| ActionInvocation {
        action_id: ActionName::new("approval.answer").expect("valid"),
        resource_id,
        arguments: vec![ActionArgument {
            name: name("decision"),
            value: ArgumentValue::Choice {
                choice_id: name(decision),
            },
        }],
    };

    let allow = invocation(Nullable::some(resource), "allow");
    assert_eq!(action.check(&allow), Ok(()));
    let decision = action
        .decision(&allow)
        .expect("the answer carries a decision");
    assert_eq!(
        table
            .answer(&serde_json::json!(41), decision)
            .expect("the table writes the answer"),
        serde_json::json!({
            "method": "approval/answer",
            "params": {"request_id": 41, "decision": "approved"}
        })
    );

    assert_eq!(
        action.check(&invocation(Nullable::null(), "allow")),
        Err(InvocationError::ResourceMissing {
            action: ActionName::new("approval.answer").expect("valid"),
        })
    );
    let unmapped = invocation(Nullable::some(resource), "allow-always");
    assert!(matches!(
        action.check(&unmapped),
        Err(InvocationError::Arguments(_))
    ));
    assert!(
        table
            .answer(&serde_json::json!(41), &name("allow-always"))
            .is_err()
    );
}
