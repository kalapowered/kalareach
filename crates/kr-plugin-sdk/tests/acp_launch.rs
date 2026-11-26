//! A package's ACP launch, as the package validator reads it.
//!
//! ACP mode starts an agent that speaks the Agent Client Protocol with KalaReach as its only
//! client. The declaration says which variables of the person's shell the host copies into that
//! start and which it sets, and the validator every host, publisher and pipeline runs decides what
//! a declaration may say. These cases build a whole package directory around the example manifest
//! and run that validator on it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.26 | a declared launch is read from the verified manifest and its statement lists every variable; one that does not request the approval grants, `command_integration.launch`, a required name, a platform the package supports, or that declares an argument, is refused, each for its own reason |

use std::path::Path;

use kr_plugin_sdk::acp_launch::{AcpLaunch, AcpRefusal};
use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::example;
use kr_plugin_sdk::matching::OperatingSystem;
use kr_plugin_sdk::package::{MANIFEST_FILE, PRESENTATION_FILE};
use kr_plugin_sdk::validate::{Finding, FindingCode, Validated, validate_package_directory};
use serde_json::{Value, json};

/// Both approval grants and the launch grant, as a package that declares a launch requests them.
const GRANTS: [&str; 3] = [
    "command_integration.launch",
    "approval.decode",
    "approval.respond",
];

/// The example package with `launch` as its ACP launch and `requested` among its capabilities.
fn manifest_with(launch: &Value, requested: &[&str]) -> Value {
    let mut manifest: Value =
        serde_json::from_str(&example::example_manifest_json()).expect("the example manifest");
    for capability in requested {
        manifest["capabilities"]
            .as_array_mut()
            .expect("the manifest requests capabilities")
            .push(json!({
                "capability": capability,
                "reason": "Start the example agent in ACP mode and answer what it asks"
            }));
    }
    manifest["acp_launch"] = launch.clone();
    manifest
}

/// A launch of the example agent that passes the contract.
fn declaration() -> Value {
    json!({
        "command": "example-agent",
        "platforms": ["mac_os", "linux"],
        "required_names": ["PATH", "HOME", "EXAMPLE_API_KEY"],
        "passed_names": ["PATH", "HOME", "EXAMPLE_API_KEY", "HTTPS_PROXY", "https_proxy"],
        "constants": [
            {"name": "EXAMPLE_HOME", "value": "{private_home}"},
            {"name": "EXAMPLE_NO_RELAUNCH", "value": "true"}
        ],
        "grant_statement": "Starts the example agent in ACP mode, with no terminal of its own"
    })
}

/// Writes the example package with `manifest` and validates it.
fn validate(manifest: &Value) -> Validated {
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
        serde_json::to_string_pretty(manifest)
            .expect("the manifest serialises")
            .as_bytes(),
    )
    .expect("the manifest writes");
    validate_package_directory(Path::new(&package))
}

/// The findings the validator reports for `manifest`. Each case asserts on them in its own body.
fn findings_of(manifest: &Value) -> Vec<Finding> {
    validate(manifest).report.findings
}

/// Whether `findings` holds one with `code` and a detail that begins with `reason`.
fn has(findings: &[Finding], code: FindingCode, reason: &str) -> bool {
    findings
        .iter()
        .any(|finding| finding.code == code && finding.detail.starts_with(reason))
}

/// KR-REQ-11.26: a launch is read from the verified manifest whole, beside the grants it needs.
#[test]
fn kr_req_11_26_a_declared_launch_is_read_from_the_manifest() {
    let validated = validate(&manifest_with(&declaration(), &GRANTS));
    assert!(
        validated.report.is_valid(),
        "{:?}",
        validated.report.findings
    );
    let package = validated.package.expect("the package");
    let read = package
        .manifest
        .acp_launch
        .as_ref()
        .expect("the manifest declares the launch");
    assert_eq!(read.required_names, ["PATH", "HOME", "EXAMPLE_API_KEY"]);
    assert_eq!(read.constants.len(), 2);
    assert_eq!(
        serde_json::to_value(read).expect("the declaration serialises"),
        declaration()
    );
}

/// KR-REQ-11.26: the statement of the Gemini-shaped launch is exactly this text.
#[test]
fn kr_req_11_26_the_statement_of_a_launch_that_sets_a_private_folder_is_exact() {
    let launch: AcpLaunch = serde_json::from_value(json!({
        "command": "gemini",
        "platforms": ["mac_os", "linux"],
        "required_names": ["PATH", "HOME", "GEMINI_API_KEY"],
        "passed_names": [
            "PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "SHELL",
            "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
            "NODE_USE_ENV_PROXY", "grpc_proxy", "no_grpc_proxy",
            "NODE_EXTRA_CA_CERTS", "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
            "GEMINI_API_KEY", "GEMINI_MODEL"
        ],
        "constants": [
            {"name": "GEMINI_CLI_HOME", "value": "{private_home}"},
            {"name": "GEMINI_CLI_NO_RELAUNCH", "value": "true"},
            {"name": "GEMINI_CLI_TRUST_WORKSPACE", "value": "false"},
            {"name": "GEMINI_PTY_INFO", "value": "child_process"},
            {"name": "WS_NO_BUFFER_UTIL", "value": "1"},
            {"name": "WS_NO_UTF_8_VALIDATE", "value": "1"}
        ],
        "grant_statement": "Words of the publisher"
    }))
    .expect("a launch");
    assert_eq!(
        launch.statement(),
        "Adds an ACP button for \"gemini\", a second way to start it, on macOS and Linux. Only \
         that button starts it in ACP mode. KalaReach starts it with the one argument \"--acp\" \
         and adds no other. KalaReach builds the environment of that start from nothing: it \
         copies these variables from your shell, each only when it is set: PATH, HOME, USER, \
         LOGNAME, TMPDIR, SHELL, HTTPS_PROXY, HTTP_PROXY, NO_PROXY, https_proxy, http_proxy, \
         no_proxy, NODE_USE_ENV_PROXY, grpc_proxy, no_grpc_proxy, NODE_EXTRA_CA_CERTS, \
         GRPC_DEFAULT_SSL_ROOTS_FILE_PATH, GEMINI_API_KEY, GEMINI_MODEL. KalaReach sets these \
         variables itself: GEMINI_CLI_HOME=\"{private_home}\", \
         GEMINI_CLI_NO_RELAUNCH=\"true\", GEMINI_CLI_TRUST_WORKSPACE=\"false\", \
         GEMINI_PTY_INFO=\"child_process\", WS_NO_BUFFER_UTIL=\"1\", \
         WS_NO_UTF_8_VALIDATE=\"1\". {private_home} stands for a folder that KalaReach makes \
         new and empty for each start and deletes when the agent ends. The start is refused \
         when any of these variables is missing from your shell or empty: PATH, HOME, \
         GEMINI_API_KEY. Every other variable of your shell stays out of that start, whatever \
         its name. The agent and the programs it starts add variables of their own, and \
         KalaReach does not promise a fixed environment for them."
    );
}

/// KR-REQ-11.26: a launch that sets no variable says so, and a name that has not the shape the
/// contract allows is written as a JSON string.
#[test]
fn kr_req_11_26_the_statement_of_a_launch_with_no_constant_says_so() {
    let launch: AcpLaunch = serde_json::from_value(json!({
        "command": "qodercli",
        "platforms": ["linux"],
        "required_names": ["PATH", "HOME"],
        "passed_names": ["PATH", "HOME", "bad name"],
        "constants": [],
        "grant_statement": "Words of the publisher"
    }))
    .expect("a launch");
    let statement = launch.statement();
    assert!(
        statement.starts_with(
            "Adds an ACP button for \"qodercli\", a second way to start it, on Linux."
        ),
        "{statement}"
    );
    assert!(
        statement.contains("each only when it is set: PATH, HOME, \"bad name\". KalaReach sets no variables. The start is refused when any of these variables is missing from your shell or empty: PATH, HOME."),
        "{statement}"
    );
}

/// KR-REQ-11.26: a package that declares a launch without the approval grants is refused, because
/// an approval the agent asks for could not be answered.
#[test]
fn kr_req_11_26_a_launch_without_the_approval_grants_is_refused() {
    let reason = "grants missing:";
    let findings = findings_of(&manifest_with(
        &declaration(),
        &["command_integration.launch"],
    ));
    assert!(
        has(&findings, FindingCode::AcpLaunchWithoutCapability, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
    let validated = validate(&manifest_with(
        &declaration(),
        &["command_integration.launch", "approval.decode"],
    ));
    let finding = validated
        .report
        .findings
        .iter()
        .find(|finding| finding.code == FindingCode::AcpLaunchWithoutCapability)
        .expect("a finding for the missing grant");
    assert!(
        finding.detail.starts_with("grants missing:")
            && finding.detail.contains("approval.respond")
            && !finding.detail.contains("approval.decode"),
        "{}",
        finding.detail
    );
}

/// KR-REQ-11.26: a package that declares a launch without `command_integration.launch` is refused.
#[test]
fn kr_req_11_26_a_launch_without_the_launch_grant_is_refused() {
    let reason = "capability:";
    let findings = findings_of(&manifest_with(
        &declaration(),
        &["approval.decode", "approval.respond"],
    ));
    assert!(
        has(&findings, FindingCode::AcpLaunchWithoutCapability, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
}

/// KR-REQ-11.26: a launch with no required name is refused.
#[test]
fn kr_req_11_26_a_launch_with_no_required_name_is_refused() {
    let mut launch = declaration();
    launch["required_names"] = json!([]);
    let reason = "names missing: acp_launch lists no required name";
    let findings = findings_of(&manifest_with(&launch, &GRANTS));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
}

/// KR-REQ-11.26: a launch that requires a name it does not pass is refused.
#[test]
fn kr_req_11_26_a_required_name_that_is_not_passed_is_refused() {
    let mut launch = declaration();
    launch["required_names"] = json!(["PATH", "OTHER_KEY"]);
    let reason = "names missing: required name \"OTHER_KEY\" is not in passed_names";
    let findings = findings_of(&manifest_with(&launch, &GRANTS));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
}

/// KR-REQ-11.26: a launch with no platform is refused.
#[test]
fn kr_req_11_26_a_launch_with_no_platform_is_refused() {
    let mut launch = declaration();
    launch["platforms"] = json!([]);
    let reason = "platform: acp_launch lists no platform";
    let findings = findings_of(&manifest_with(&launch, &GRANTS));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
}

/// KR-REQ-11.26: a launch on Windows is refused, whatever the package supports.
#[test]
fn kr_req_11_26_a_launch_on_windows_is_refused() {
    let mut launch = declaration();
    launch["platforms"] = json!(["mac_os", "windows"]);
    let reason = "platform: acp_launch lists windows, which has no ACP launch";
    let findings = findings_of(&manifest_with(&launch, &GRANTS));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
}

/// KR-REQ-11.26: a launch on a platform the package does not support is refused.
#[test]
fn kr_req_11_26_a_launch_on_a_platform_the_package_does_not_list_is_refused() {
    let mut manifest = manifest_with(&declaration(), &GRANTS);
    manifest["platforms"] = json!([{"os": "linux", "architectures": ["x86_64"]}]);
    let reason = "platform: acp_launch lists mac_os, which the package's platforms do not support";
    let findings = findings_of(&manifest);
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
}

/// KR-REQ-11.26: a declared argument is an unknown member, which the manifest refuses before any
/// rule of the launch runs. This is the existing guard and no rule of the launch.
#[test]
fn kr_req_11_26_a_launch_cannot_declare_an_argument() {
    let mut launch = declaration();
    launch["arguments"] = json!(["--yolo"]);
    let validated = validate(&manifest_with(&launch, &GRANTS));
    assert!(
        validated.report.has(FindingCode::ManifestUnreadable),
        "{:?}",
        validated.report.findings
    );
}

/// KR-REQ-11.26: a command that is no executable of the package's match rules is refused.
#[test]
fn kr_req_11_26_a_command_that_the_package_does_not_match_is_refused() {
    let mut launch = declaration();
    launch["command"] = json!("other-agent");
    let reason = "the ACP launch's command \"other-agent\" is not the executable name";
    let findings = findings_of(&manifest_with(&launch, &GRANTS));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
}

/// KR-REQ-11.26: a name that is not a variable name, and a name only the worker sets, are refused.
#[test]
fn kr_req_11_26_a_name_outside_the_contract_is_refused() {
    let mut launch = declaration();
    launch["passed_names"] = json!(["PATH", "HOME", "EXAMPLE_API_KEY", "bad name"]);
    let reason = "name: \"bad name\" in passed_names is not a variable name";
    let findings = findings_of(&manifest_with(&launch, &GRANTS));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
    let mut launch = declaration();
    launch["passed_names"] = json!(["PATH", "HOME", "EXAMPLE_API_KEY", "KR_TOKEN"]);
    let reason = "name: \"KR_TOKEN\" in passed_names begins with KR_";
    let findings = findings_of(&manifest_with(&launch, &GRANTS));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
    let mut launch = declaration();
    launch["passed_names"] = json!(["PATH", "HOME", "EXAMPLE_API_KEY", "PATH"]);
    let reason = "name: \"PATH\" is listed more than once in passed_names";
    let findings = findings_of(&manifest_with(&launch, &GRANTS));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
}

/// KR-REQ-11.26: a list over the bound is refused.
#[test]
fn kr_req_11_26_a_list_over_the_bound_is_refused() {
    let mut launch = declaration();
    let names: Vec<String> = (0..65).map(|index| format!("NAME_{index}")).collect();
    launch["passed_names"] = json!(names);
    launch["required_names"] = json!(["NAME_0"]);
    let reason = "name: passed_names lists 65 names, over the 64 one list may";
    let findings = findings_of(&manifest_with(&launch, &GRANTS));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
}

/// KR-REQ-11.26: a constant that the shell also passes, one set twice, an empty value and a value
/// that holds a brace beside other text are refused.
#[test]
fn kr_req_11_26_a_constant_outside_the_contract_is_refused() {
    let with_constants = |constants: Value| {
        let mut launch = declaration();
        launch["constants"] = constants;
        manifest_with(&launch, &GRANTS)
    };
    let reason = "constant: \"HOME\" is both set by KalaReach and passed from the shell";
    let findings = findings_of(&with_constants(json!([{"name": "HOME", "value": "x"}])));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
    let reason = "constant: \"A_ONE\" is set more than once";
    let findings = findings_of(&with_constants(json!([
        {"name": "A_ONE", "value": "x"},
        {"name": "A_ONE", "value": "y"}
    ])));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
    let reason = "constant: the value of \"A_ONE\" is empty";
    let findings = findings_of(&with_constants(json!([{"name": "A_ONE", "value": ""}])));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
    let reason = "constant: the value of \"A_ONE\" holds a brace";
    let findings = findings_of(&with_constants(
        json!([{"name": "A_ONE", "value": "x{private_home}"}]),
    ));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
}

/// KR-REQ-11.26: the publisher's words for a launch cannot hold a label the host writes, alone or
/// where they join the words before them.
#[test]
fn kr_req_11_26_launch_words_that_hold_a_label_of_the_host_are_refused() {
    let mut launch = declaration();
    launch["grant_statement"] = json!(format!(
        "Starts the agent. {} nothing",
        kr_protocol::confirmation::INTEGRATION_STATEMENT_LABEL
    ));
    let reason = "the ACP launch's statement holds the words the host writes before its own reading of a \
         command integration";
    let findings = findings_of(&manifest_with(&launch, &GRANTS));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
    let label = kr_protocol::confirmation::PLACEMENT_STATEMENT_LABEL;
    let (start, rest) = label
        .split_once(' ')
        .expect("the label has more than one word");
    let mut manifest = manifest_with(&declaration(), &GRANTS);
    manifest["command_integration"] = json!({
        "command": "example-agent",
        "flags": ["--flag"],
        "variables": [],
        "grant_statement": format!("Adds a flag. {start}")
    });
    manifest["acp_launch"]["grant_statement"] = json!(format!("{rest} and starts the agent"));
    let reason = "the statements of the bridge, the command integration and the ACP launch, read \
         together, hold the words the host writes before its own reading of a placement";
    let findings = findings_of(&manifest);
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
}

/// The example manifest with a launch, a command integration whose words are `integration`, and a
/// native bridge whose words are `bridge`.
fn manifest_with_words(bridge: &str, integration: &str, launch_words: &str) -> Value {
    let mut manifest = manifest_with(&declaration(), &GRANTS);
    manifest["command_integration"] = json!({
        "command": "example-agent",
        "flags": ["--flag"],
        "variables": [],
        "grant_statement": integration
    });
    manifest["acp_launch"]["grant_statement"] = json!(launch_words);
    manifest["capabilities"]
        .as_array_mut()
        .expect("the manifest requests capabilities")
        .push(json!({
            "capability": "native_bridge.install",
            "reason": "Register the forwarder the example agent starts"
        }));
    manifest["native_bridge"] = json!({
        "application": "Example Agent",
        "application_range": ">=1.0.0, <2.0.0",
        "install": [{
            "type": "add_configuration_key",
            "file": "settings.json",
            "key": "enabled.example",
            "value": "true"
        }],
        "remove": [{
            "type": "remove_configuration_key",
            "file": "settings.json",
            "key": "enabled.example"
        }],
        "grant_statement": bridge
    });
    manifest
}

/// KR-REQ-11.26: the host writes its own label before its reading of the launch, so the words of
/// the bridge, of the command integration and of the launch cannot hold it, each in its own
/// sentence, and the three cannot form it where they join.
#[test]
fn kr_req_11_26_words_that_hold_the_launch_label_of_the_host_are_refused() {
    let label = kr_protocol::confirmation::ACP_STATEMENT_LABEL;
    let imitation = format!("Harmless. {label} Runs nothing.");
    let fine = "Adds a flag.";
    let reason = "the ACP launch's statement holds the words the host writes before its own reading of an \
         ACP launch";
    let findings = findings_of(&manifest_with_words(fine, fine, &imitation));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
    let reason = "the command integration's statement holds the words the host writes before its own \
         reading of an ACP launch";
    let findings = findings_of(&manifest_with_words(fine, &imitation, fine));
    assert!(
        has(&findings, FindingCode::IntegrationInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
    let reason = "the bridge's statement holds the words the host writes before its own reading of an ACP \
         launch";
    let findings = findings_of(&manifest_with_words(&imitation, fine, fine));
    assert!(
        has(&findings, FindingCode::BridgeRecipeInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );

    // Three statements that form the label only where they join: neither holds it.
    let (bridge, integration, launch) = (
        "Changes one setting. The host's exact reading of",
        "the ACP",
        "launch: Runs nothing.",
    );
    let joined = format!("{bridge} {integration} {launch}");
    assert!(joined.contains(label), "the three form the label");
    assert!(
        ![bridge, integration, launch]
            .iter()
            .any(|words| words.contains(label)),
        "and none holds it"
    );
    let reason = "the statements of the bridge, the command integration and the ACP launch, read \
         together, hold the words the host writes before its own reading of an ACP launch";
    let findings = findings_of(&manifest_with_words(bridge, integration, launch));
    assert!(
        has(&findings, FindingCode::AcpLaunchInvalid, reason),
        "a finding that begins {reason:?} is expected: {findings:?}"
    );
}

/// What an installation's grant holds when the owner has confirmed the launch and both approval
/// grants are held.
const HELD: [PluginCapability; 3] = [
    PluginCapability::CommandIntegrationLaunch,
    PluginCapability::ApprovalDecode,
    PluginCapability::ApprovalRespond,
];

/// The example agent's launch, as the declaration reads.
fn launch() -> AcpLaunch {
    serde_json::from_value(declaration()).expect("a launch")
}

/// KR-REQ-11.26: a launch with the switch on, the grants held and the host's platform listed is
/// admitted, and the declaration comes back whole.
#[test]
fn kr_req_11_26_a_granted_launch_is_admitted() {
    let launch = launch();
    let admitted = launch
        .admission(&HELD, true, OperatingSystem::Linux)
        .expect("the launch is admitted");
    assert_eq!(admitted, &launch);
    assert!(
        launch
            .admission(&HELD, true, OperatingSystem::MacOs)
            .is_ok()
    );
}

/// KR-REQ-11.26: each cause that forbids a launch is refused in its own sentence.
#[test]
fn kr_req_11_26_each_cause_that_forbids_a_launch_is_refused_in_its_own_words() {
    let launch = launch();
    let refused = |held: &[PluginCapability], switch_on: bool, host: OperatingSystem| {
        launch
            .admission(held, switch_on, host)
            .expect_err("the launch is refused")
            .to_string()
    };
    assert_eq!(
        refused(&HELD, false, OperatingSystem::Linux),
        "ACP mode is switched off for this agent on this host."
    );
    assert_eq!(
        refused(&HELD[1..], true, OperatingSystem::Linux),
        "The owner has not confirmed this release's launch grant, so ACP mode is not available."
    );
    assert_eq!(
        refused(&HELD[..2], true, OperatingSystem::Linux),
        "ACP mode needs the approval.decode and approval.respond grants, and this release does \
         not hold both."
    );
    assert_eq!(
        refused(&HELD, true, OperatingSystem::Windows),
        "This release does not offer ACP mode on this platform: it lists macOS and Linux."
    );
}

/// KR-REQ-11.26: where two causes apply, the first in the host's order is the one the person
/// reads: the switch, then the confirmation, then the approvals, then the platform.
#[test]
fn kr_req_11_26_the_first_cause_in_the_hosts_order_is_the_one_refused() {
    let launch = launch();
    assert_eq!(
        launch.admission(&[], false, OperatingSystem::Windows),
        Err(AcpRefusal::SwitchOff)
    );
    assert_eq!(
        launch.admission(&[], true, OperatingSystem::Windows),
        Err(AcpRefusal::NotConfirmed)
    );
    assert_eq!(
        launch.admission(&HELD[..1], true, OperatingSystem::Windows),
        Err(AcpRefusal::ApprovalsMissing)
    );
}
