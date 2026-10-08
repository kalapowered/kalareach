//! A command integration's backend, as the package validator reads it.
//!
//! Section 12 has an opt-in command integration establish the worker-owned backend and gateway
//! before it launches the native terminal. A package that needs that says so in its manifest, and
//! the validator every host, publisher and pipeline runs decides whether the table it ships is one
//! the worker's gateway can read. These cases build the example connector package around a
//! backend declaration and break it one way at a time.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.07 | a backend with a table the gateway reads is accepted and round-trips; a table it cannot read, a missing `messages`, colliding member names, a declaration with no table, and a table with more methods than the gateway interprets are each named |

use std::path::Path;

use kr_plugin_sdk::capability::CapabilityRequest;
use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::connector::{
    BrokerTransport, ConnectorManifest, FieldPath, FieldSegment, Framing, MessageMembers,
    MethodClass, MethodClassification, ResponseCorrelation, Route, RouteDirection,
};
use kr_plugin_sdk::example;
use kr_plugin_sdk::ids::MethodName;
use kr_plugin_sdk::integration::{CommandIntegration, GATEWAY_PLACEHOLDER, IntegrationBackend};
use kr_plugin_sdk::package::{CONNECTOR_FILE, MANIFEST_FILE, PRESENTATION_FILE};
use kr_plugin_sdk::plugin::{PayloadRole, PluginManifest};
use kr_plugin_sdk::scalars::U64;
use kr_plugin_sdk::text::Summary;
use kr_plugin_sdk::validate::{FindingCode, Report, validate_package_directory};

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

/// The example table, edited to the shape the gateway reads: top-level members and the three names
/// a message is read by.
fn gateway_table() -> ConnectorManifest {
    let mut table = example::example_connector_table();
    table.messages = Some(MessageMembers {
        params: "params".to_owned(),
        result: "result".to_owned(),
        error: "error".to_owned(),
    });
    table
}

/// The declaration a package with a backend makes.
fn declaration() -> CommandIntegration {
    CommandIntegration {
        command: "example-agent".to_owned(),
        flags: vec!["--remote".to_owned(), GATEWAY_PLACEHOLDER.to_owned()],
        variables: Vec::new(),
        grant_statement: Summary::new("Starts the agent's server and points its terminal at it")
            .expect("a literal summary"),
        backend: Some(IntegrationBackend {
            arguments: vec!["serve".to_owned(), "--stdio".to_owned()],
            launching_words: vec!["resume".to_owned()],
        }),
    }
}

/// Writes the example connector package with `table`, a manifest declaring `integration`, and the
/// capability that applies it, and validates it. `ship_table` false leaves the table out.
fn validate_with(
    table: &ConnectorManifest,
    integration: Option<CommandIntegration>,
    ship_table: bool,
) -> Report {
    let connector = serde_json::to_vec_pretty(table).expect("the table serialises");
    let document = example::example_connector_presentation_json().into_bytes();
    let mut manifest: PluginManifest = example::example_connector_manifest(&document, &connector);
    if !ship_table {
        manifest
            .payloads
            .retain(|payload| payload.role != PayloadRole::Connector);
        // The example's actions send through the table; this package has none to send through.
        manifest.actions.clear();
    }
    manifest.sdk_range =
        kr_plugin_sdk::version::VersionRange::parse(">=0.1.5, <0.2.0").expect("a literal range");
    manifest.capabilities.push(CapabilityRequest {
        capability: PluginCapability::CommandIntegrationLaunch,
        reason: kr_plugin_sdk::text::Summary::new("Start the agent with its server")
            .expect("a literal reason"),
    });
    manifest.command_integration = integration;
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let package: &Path = &temporary.path().join("package");
    std::fs::create_dir_all(package).expect("the package directory");
    std::fs::write(
        package.join(MANIFEST_FILE),
        serde_json::to_vec_pretty(&manifest).expect("the manifest serialises"),
    )
    .expect("the manifest writes");
    std::fs::write(package.join(PRESENTATION_FILE), &document).expect("the document writes");
    if ship_table {
        std::fs::write(package.join(CONNECTOR_FILE), &connector).expect("the table writes");
    }
    validate_package_directory(package).report
}

fn detail_of(report: &Report, code: FindingCode) -> String {
    report
        .findings
        .iter()
        .filter(|finding| finding.code == code)
        .map(|finding| finding.detail.clone())
        .collect::<Vec<_>>()
        .join("; ")
}

fn refused(table: &ConnectorManifest, code: FindingCode, text: &str) {
    let report = validate_with(table, Some(declaration()), true);
    let detail = detail_of(&report, code);
    assert!(
        detail.contains(text),
        "expected {code:?} to say {text:?}: {:?}",
        report.findings
    );
}

/// KR-REQ-12.07: a backend whose table the gateway reads is accepted, and the declaration is the
/// bytes the package hash names, whole.
#[test]
fn kr_req_12_07_a_backend_with_a_table_the_gateway_reads_is_accepted() {
    let report = validate_with(&gateway_table(), Some(declaration()), true);
    assert!(report.is_valid(), "{:?}", report.findings);
    let written = serde_json::to_value(declaration()).expect("the declaration serialises");
    assert_eq!(written["backend"]["arguments"][0], "serve");
    assert_eq!(written["backend"]["launching_words"][0], "resume");
    let back: CommandIntegration = serde_json::from_value(written).expect("it reads back");
    assert_eq!(back, declaration());
}

/// KR-REQ-12.07: an integration with no backend writes none, so every package written before the
/// member existed reads and hashes as it did.
#[test]
fn kr_req_12_07_a_declaration_with_no_backend_does_not_write_the_member() {
    let mut plain = declaration();
    plain.backend = None;
    plain.flags = vec!["--flag".to_owned()];
    let written = serde_json::to_value(&plain).expect("the declaration serialises");
    assert!(written.get("backend").is_none(), "{written}");
    let mut table = example::example_connector_table();
    table.messages = None;
    assert!(
        serde_json::to_value(&table)
            .expect("the table serialises")
            .get("messages")
            .is_none(),
        "a table with no messages writes none"
    );
}

/// KR-REQ-12.07: each way the table is not one the gateway reads is named, in the table's file.
#[test]
fn kr_req_12_07_a_table_the_gateway_cannot_read_is_named_for_what_it_is() {
    let mut table = gateway_table();
    table.transport = BrokerTransport::LoopbackHttp;
    refused(
        &table,
        FindingCode::ConnectorTableInvalid,
        "standard streams",
    );

    let mut table = gateway_table();
    table.framing = Framing::ContentLength {
        length_header: "Content-Length".to_owned(),
        max_message_bytes: U64::new(1_048_576),
    };
    refused(
        &table,
        FindingCode::ConnectorTableInvalid,
        "one JSON document per line",
    );

    let mut table = gateway_table();
    table.response_correlation = ResponseCorrelation::Ordered {};
    refused(&table, FindingCode::ConnectorTableInvalid, "by order");

    let mut table = gateway_table();
    table.request_id_path = members(&["params", "id"]);
    refused(
        &table,
        FindingCode::ConnectorTableInvalid,
        "one top-level member",
    );

    let mut table = gateway_table();
    table.messages = None;
    refused(&table, FindingCode::ConnectorTableInvalid, "names none");

    let mut table = gateway_table();
    table.messages = Some(MessageMembers {
        params: "result".to_owned(),
        result: "result".to_owned(),
        error: "error".to_owned(),
    });
    refused(
        &table,
        FindingCode::ConnectorTableInvalid,
        "name the same member",
    );

    let mut table = gateway_table();
    table.messages = Some(MessageMembers {
        params: "method".to_owned(),
        result: "result".to_owned(),
        error: "error".to_owned(),
    });
    refused(
        &table,
        FindingCode::ConnectorTableInvalid,
        "name the same member",
    );

    let mut table = gateway_table();
    table.messages = Some(MessageMembers {
        params: "params".to_owned(),
        result: "id".to_owned(),
        error: "error".to_owned(),
    });
    refused(
        &table,
        FindingCode::ConnectorTableInvalid,
        "identifier member is also",
    );

    let mut table = gateway_table();
    table.messages = Some(MessageMembers {
        params: String::new(),
        result: "result".to_owned(),
        error: "error".to_owned(),
    });
    refused(
        &table,
        FindingCode::ConnectorTableInvalid,
        "names no member",
    );
}

/// KR-REQ-12.07: the gateway interprets at most as many methods as its table holds, and a package
/// with a backend that lists more says so before it is installed.
#[test]
fn kr_req_12_07_a_table_with_more_methods_than_the_gateway_interprets_is_named() {
    let mut table = gateway_table();
    let limit = kr_protocol::gateway::MAX_TABLE_METHODS;
    for index in 0..=limit {
        let method = MethodName::new(format!("extra.m{index}")).expect("a valid method name");
        table.routes.push(Route {
            method: method.clone(),
            wire_name: format!("extra/m{index}"),
            direction: RouteDirection::HostToUpstream,
        });
        table.methods.push(MethodClassification {
            method,
            class: MethodClass::Observation,
            evidence: Summary::new("Reports a counter").expect("a literal summary"),
        });
    }
    refused(
        &table,
        FindingCode::ConnectorTableInvalid,
        "interprets at most",
    );
    // Without a backend the same table is fine for the SDK.
    let mut plain = declaration();
    plain.backend = None;
    plain.flags = vec!["--flag".to_owned()];
    let report = validate_with(&table, Some(plain), true);
    assert!(
        !detail_of(&report, FindingCode::ConnectorTableInvalid).contains("interprets at most"),
        "{:?}",
        report.findings
    );
}

/// KR-REQ-12.07: a backend with no table to read is a finding on the integration, and the
/// placeholder without a backend, or twice with one, is too.
#[test]
fn kr_req_12_07_a_backend_needs_a_table_and_the_gateway_flag_goes_with_it() {
    let report = validate_with(&gateway_table(), Some(declaration()), false);
    assert!(
        detail_of(&report, FindingCode::IntegrationInvalid).contains("ships no connector table"),
        "{:?}",
        report.findings
    );

    let mut none = declaration();
    none.backend = None;
    let report = validate_with(&gateway_table(), Some(none), true);
    assert!(
        detail_of(&report, FindingCode::IntegrationInvalid).contains("declares no backend"),
        "{:?}",
        report.findings
    );

    let mut twice = declaration();
    twice.flags.push(GATEWAY_PLACEHOLDER.to_owned());
    let report = validate_with(&gateway_table(), Some(twice), true);
    assert!(
        detail_of(&report, FindingCode::IntegrationInvalid).contains("in 2 flags"),
        "{:?}",
        report.findings
    );
}

/// The package contract carries the bounds a publisher builds against.
#[test]
fn the_package_contract_publishes_the_backend_bounds() {
    let contract = kr_plugin_sdk::schema::package_contract();
    let integration = &contract["command_integration"];
    assert_eq!(integration["gateway_placeholder"], GATEWAY_PLACEHOLDER);
    assert_eq!(integration["max_backend_arguments"], 8);
    assert_eq!(integration["max_launching_words"], 8);
    assert_eq!(
        integration["max_backend_methods"],
        kr_protocol::gateway::MAX_TABLE_METHODS
    );
}
