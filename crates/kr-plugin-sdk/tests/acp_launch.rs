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

use kr_plugin_sdk::acp_launch::AcpLaunch;
use kr_plugin_sdk::example;
use kr_plugin_sdk::package::{MANIFEST_FILE, PRESENTATION_FILE};
use kr_plugin_sdk::validate::{FindingCode, Validated, validate_package_directory};
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

/// Asserts that the validator reports `code` with a detail that begins with `reason`.
fn assert_refused(manifest: &Value, code: FindingCode, reason: &str) {
    let validated = validate(manifest);
    assert!(
        validated
            .report
            .findings
            .iter()
            .any(|finding| finding.code == code && finding.detail.starts_with(reason)),
        "a finding {} that begins {reason:?} is expected: {:?}",
        code.as_str(),
        validated.report.findings
    );
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
    assert_refused(
        &manifest_with(&declaration(), &["command_integration.launch"]),
        FindingCode::AcpLaunchWithoutCapability,
        "grants missing:",
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
    assert_refused(
        &manifest_with(&declaration(), &["approval.decode", "approval.respond"]),
        FindingCode::AcpLaunchWithoutCapability,
        "capability:",
    );
}

/// KR-REQ-11.26: a launch with no required name, or one that requires a name it does not pass, is
/// refused.
#[test]
fn kr_req_11_26_a_launch_with_no_required_name_is_refused() {
    let mut launch = declaration();
    launch["required_names"] = json!([]);
    assert_refused(
        &manifest_with(&launch, &GRANTS),
        FindingCode::AcpLaunchInvalid,
        "names missing: acp_launch lists no required name",
    );
    let mut launch = declaration();
    launch["required_names"] = json!(["PATH", "OTHER_KEY"]);
    assert_refused(
        &manifest_with(&launch, &GRANTS),
        FindingCode::AcpLaunchInvalid,
        "names missing: required name \"OTHER_KEY\" is not in passed_names",
    );
}

/// KR-REQ-11.26: a launch with no platform, one the package does not support, or Windows, is
/// refused.
#[test]
fn kr_req_11_26_a_launch_on_a_platform_the_package_does_not_list_is_refused() {
    let mut launch = declaration();
    launch["platforms"] = json!([]);
    assert_refused(
        &manifest_with(&launch, &GRANTS),
        FindingCode::AcpLaunchInvalid,
        "platform: acp_launch lists no platform",
    );
    let mut launch = declaration();
    launch["platforms"] = json!(["mac_os", "windows"]);
    assert_refused(
        &manifest_with(&launch, &GRANTS),
        FindingCode::AcpLaunchInvalid,
        "platform: acp_launch lists windows, which has no ACP launch",
    );
    let mut manifest = manifest_with(&declaration(), &GRANTS);
    manifest["platforms"] = json!([{"os": "linux", "architectures": ["x86_64"]}]);
    assert_refused(
        &manifest,
        FindingCode::AcpLaunchInvalid,
        "platform: acp_launch lists mac_os, which the package's platforms do not support",
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
