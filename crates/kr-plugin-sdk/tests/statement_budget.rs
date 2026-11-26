//! The installation statement of a package that declares an ACP launch, and the room an owner's
//! device gives it.
//!
//! The host composes the statement from the publisher's words (the bridge's, the command
//! integration's and the ACP launch's, in that order), the host's reading of the placement and the
//! host's reading of the command integration, followed by the host's label and reading of the ACP
//! launch. The longest statement a device shows whole is `STATEMENT_CHARS`, set from the two
//! packages of this build that declare an ACP launch. These cases compose both packages' statements
//! from their bundled manifests with a launch declared as the design states it, and hold the budget
//! to what they need.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.26 | each package's statement lists the launch's words, then the host's label and reading of the launch after the integration's reading; the budget is the longest of the two plus a margin of 500, rounded up to the next 1,000; a package with no bridge that declares a launch is held to the budget as well |

use std::path::{Path, PathBuf};

use kr_plugin_sdk::acp_launch::AcpLaunch;
use kr_plugin_sdk::connector::ConnectorManifest;
use kr_plugin_sdk::example;
use kr_plugin_sdk::package::{MANIFEST_FILE, PRESENTATION_FILE};
use kr_plugin_sdk::plugin::PluginManifest;
use kr_plugin_sdk::validate::{FindingCode, validate_package_directory, whole_statement};
use kr_protocol::confirmation::{
    ACP_STATEMENT_LABEL, INTEGRATION_STATEMENT_LABEL, STATEMENT_CHARS,
};
use serde_json::{Value, json};

/// The margin the budget keeps above the longest statement, in characters.
const MARGIN: usize = 500;

/// The two bundled packages that declare an ACP launch, with the file of each launch's declaration.
const PACKAGES: [(&str, &str); 2] = [
    ("gemini-cli", "tests/fixtures/acp-launch-gemini-cli.json"),
    ("qoder-cli", "tests/fixtures/acp-launch-qoder-cli.json"),
];

fn bundled(package: &str, file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../bundled-plugins/targets/packages/kalareach")
        .join(package)
        .join("0.5.0")
        .join(file)
}

fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("the file reads")).expect("a JSON file")
}

/// A bundled package as it reads once it declares its launch and asks for the grants that go with
/// it, with its connector table.
fn package_with_launch(package: &str, declaration: &str) -> (PluginManifest, ConnectorManifest) {
    let mut manifest = read(&bundled(package, MANIFEST_FILE));
    for capability in ["approval.decode", "approval.respond"] {
        manifest["capabilities"]
            .as_array_mut()
            .expect("the manifest requests capabilities")
            .push(json!({
                "capability": capability,
                "reason": "Answer what the agent asks in ACP mode"
            }));
    }
    manifest["acp_launch"] = read(&Path::new(env!("CARGO_MANIFEST_DIR")).join(declaration));
    let manifest: PluginManifest = serde_json::from_value(manifest).expect("a manifest");
    let connector: ConnectorManifest =
        serde_json::from_value(read(&bundled(package, "connector.json"))).expect("a table");
    (manifest, connector)
}

/// Each package with its manifest and the statement the host composes for it, where it composes
/// one. Each case asserts on what it gets in its own body.
fn statements() -> Vec<(&'static str, PluginManifest, Option<String>)> {
    PACKAGES
        .iter()
        .map(|(package, declaration)| {
            let (manifest, connector) = package_with_launch(package, declaration);
            let statement = whole_statement(&manifest, Some(&connector));
            (*package, manifest, statement)
        })
        .collect()
}

/// KR-REQ-11.26: the launches the cases declare are launches the package check accepts, so what is
/// measured is a statement the host would show.
#[test]
fn kr_req_11_26_the_measured_launches_are_valid_declarations() {
    for (package, declaration) in PACKAGES {
        let (manifest, _) = package_with_launch(package, declaration);
        let launch = manifest.acp_launch.as_ref().expect("a launch");
        let supported: Vec<_> = manifest
            .platforms
            .iter()
            .map(|support| support.os)
            .collect();
        assert_eq!(
            launch.problems(&manifest.match_rules, &supported),
            Vec::<String>::new(),
            "{package}"
        );
    }
}

/// KR-REQ-11.26: the statement holds the publisher's words of the launch after the integration's
/// own, and the host's label and reading of the launch after its reading of the integration, once
/// each and in that order.
#[test]
fn kr_req_11_26_the_statement_states_the_launch_after_the_integration() {
    for (package, manifest, statement) in statements() {
        assert!(
            statement.is_some(),
            "{package} declares a launch, so the host composes a statement for it"
        );
        let statement = statement.unwrap_or_default();
        let launch: &AcpLaunch = manifest.acp_launch.as_ref().expect("a launch");
        let integration = manifest
            .command_integration
            .as_ref()
            .expect("a command integration");
        let words_at = statement.find(launch.grant_statement.as_str());
        let integration_words_at = statement.find(integration.grant_statement.as_str());
        let integration_label_at = statement.find(INTEGRATION_STATEMENT_LABEL);
        assert!(
            words_at.is_some() && integration_words_at.is_some() && integration_label_at.is_some(),
            "{package}: the publisher's words of the launch, the integration's own words and its \
             label are all shown"
        );
        assert!(
            matches!(
                (integration_words_at, words_at, integration_label_at),
                (Some(integration_words), Some(words), Some(label))
                    if integration_words < words && words < label
            ),
            "{package}: the launch's words follow the integration's, ahead of the host's labels"
        );
        assert_eq!(
            statement.matches(ACP_STATEMENT_LABEL).count(),
            1,
            "{package}: the host's label of the launch is written once"
        );
        assert!(
            statement.ends_with(&format!("{ACP_STATEMENT_LABEL} {}", launch.statement())),
            "{package}: the host's reading of the launch is last"
        );
        assert!(
            statement
                .find(ACP_STATEMENT_LABEL)
                .zip(integration_label_at)
                .is_some_and(|(label_at, integration_label)| integration_label < label_at),
            "{package}: the host's reading of the launch follows its reading of the integration"
        );
    }
}

/// KR-REQ-11.26: a device shows a statement of at most `STATEMENT_CHARS` whole, so the longest of
/// the two packages' statements is within it, and the figure is that length plus the margin,
/// rounded up to the next 1,000.
#[test]
fn kr_req_11_26_the_budget_holds_the_longer_of_the_two_statements_and_a_margin() {
    let lengths: Vec<(&str, Option<usize>)> = statements()
        .iter()
        .map(|(package, _, statement)| {
            (
                *package,
                statement.as_ref().map(|text| text.chars().count()),
            )
        })
        .collect();
    assert!(
        lengths.iter().all(|(_, length)| length.is_some()),
        "every package declares a launch, so the host composes a statement for each: {lengths:?}"
    );
    let longest = lengths
        .iter()
        .filter_map(|(_, length)| *length)
        .max()
        .expect("two packages");
    assert!(
        longest <= STATEMENT_CHARS,
        "the longer statement is {longest} characters and the budget is {STATEMENT_CHARS}: \
         {lengths:?}"
    );
    assert_eq!(
        STATEMENT_CHARS,
        (longest + MARGIN).div_ceil(1_000) * 1_000,
        "the longer statement is {longest} characters: the budget is that and {MARGIN}, rounded \
         up to the next 1,000"
    );
}

/// Writes the example package, which declares no bridge, with `launch` as its ACP launch and
/// validates it.
fn validate_example_with(launch: &Value) -> Vec<kr_plugin_sdk::validate::Finding> {
    let mut manifest: Value =
        serde_json::from_str(&example::example_manifest_json()).expect("the example manifest");
    for capability in [
        "command_integration.launch",
        "approval.decode",
        "approval.respond",
    ] {
        manifest["capabilities"]
            .as_array_mut()
            .expect("the manifest requests capabilities")
            .push(json!({
                "capability": capability,
                "reason": "Start the example agent in ACP mode and answer what it asks"
            }));
    }
    manifest["acp_launch"] = launch.clone();
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let package = temporary.path().join("package");
    std::fs::create_dir_all(&package).expect("the package directory");
    std::fs::write(
        package.join(PRESENTATION_FILE),
        example::example_presentation_json().as_bytes(),
    )
    .expect("the presentation writes");
    std::fs::write(
        package.join(MANIFEST_FILE),
        serde_json::to_string_pretty(&manifest)
            .expect("the manifest serialises")
            .as_bytes(),
    )
    .expect("the manifest writes");
    validate_package_directory(&package).report.findings
}

/// A launch of the example agent whose words and names are as long as the contract lets them be.
fn the_longest_launch() -> Value {
    let name = |index: usize| format!("{:_<64}", format!("EXAMPLE_NAME_{index:02}_"));
    let names: Vec<String> = (0..64).map(name).collect();
    json!({
        "command": "example-agent",
        "platforms": ["mac_os", "linux"],
        "required_names": [names[0]],
        "passed_names": names,
        "constants": (0..16)
            .map(|index| json!({"name": format!("EXAMPLE_SET_{index:02}"), "value": "v".repeat(256)}))
            .collect::<Vec<_>>(),
        "grant_statement": "w".repeat(6_000)
    })
}

/// KR-REQ-11.26: a package with no native bridge is held to the budget by its launch's words and
/// reading, so a launch that makes the whole statement longer than a device shows is refused for
/// its own reason, and a short launch of the same package is not.
#[test]
fn kr_req_11_26_a_package_with_no_bridge_is_held_to_the_budget_by_its_launch() {
    let refused = |findings: &[kr_plugin_sdk::validate::Finding]| {
        findings.iter().any(|finding| {
            finding.code == FindingCode::AcpLaunchInvalid
                && finding
                    .detail
                    .starts_with("the host's whole statement of this package")
                && finding.detail.contains("its reading of the ACP launch")
        })
    };
    let longest = validate_example_with(&the_longest_launch());
    assert!(
        refused(&longest),
        "a launch at the contract's longest does not fit the budget: {longest:?}"
    );
    let mut short = the_longest_launch();
    short["passed_names"] = json!(["EXAMPLE_ONE"]);
    short["required_names"] = json!(["EXAMPLE_ONE"]);
    short["constants"] = json!([]);
    short["grant_statement"] = json!("Starts the example agent in ACP mode.");
    let control = validate_example_with(&short);
    assert!(!refused(&control), "{control:?}");
}
