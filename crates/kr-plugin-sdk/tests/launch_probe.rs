//! A package's launch probe, as the package validator reads it.
//!
//! Section 7 has a host refuse a launch whose application cannot run in the session it would start
//! in, and the host learns what mode an application runs in from the application itself, through
//! a diagnostic the package declares. The declaration runs the application's own executable with
//! arguments the package chose, so the validator every host, publisher and pipeline runs decides
//! what a declaration may say, and the capability that runs it is the owner's to confirm on every
//! release. These cases build a whole package directory around the example manifest and run that
//! validator on it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-07.64 | a declared probe is read from the verified manifest with its capability; one without it, with an empty argument list, an over-long list, an option that is not a name or a pointer that is not one is refused |

use std::path::Path;

use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::example;
use kr_plugin_sdk::launch_probe::{MAX_ARGUMENTS, MAX_CARRIED_OPTIONS};
use kr_plugin_sdk::package::{MANIFEST_FILE, PRESENTATION_FILE};
use kr_plugin_sdk::validate::{FindingCode, Validated, validate_package_directory};
use serde_json::{Value, json};

/// The example package with `probe` as its launch probe and the capability requested unless
/// `capability` is false.
fn manifest_with(probe: &Value, capability: bool) -> Value {
    let mut manifest: Value =
        serde_json::from_str(&example::example_manifest_json()).expect("the example manifest");
    manifest["sdk_range"] = json!(">=0.1.4, <0.2.0");
    if capability {
        manifest["capabilities"]
            .as_array_mut()
            .expect("the manifest requests capabilities")
            .push(json!({
                "capability": "launch.probe",
                "reason": "Read which sandbox the application will use before a launch"
            }));
    }
    manifest["launch_probe"] = probe.clone();
    manifest
}

fn declaration() -> Value {
    json!({
        "arguments": ["doctor", "--json"],
        "carried_options": ["-c", "--config"],
        "mode": "/checks/sandbox.helpers/details/sandbox backend",
        "refused_in_service_session": ["elevated"],
        "grant_statement": "Reads which sandbox the application will use before a launch"
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

fn assert_refused(manifest: &Value, code: FindingCode, what: &str) {
    let validated = validate(manifest);
    assert!(
        validated.report.has(code),
        "{what} is refused as {}: {:?}",
        code.as_str(),
        validated.report.findings
    );
}

/// KR-REQ-07.64: a package's launch probe is read from its verified manifest, whole, beside the
/// capability that runs it, and its statement lists every argument.
#[test]
fn kr_req_07_64_a_declared_probe_is_read_from_the_manifest() {
    let validated = validate(&manifest_with(&declaration(), true));
    assert!(
        validated.report.is_valid(),
        "{:?}",
        validated.report.findings
    );
    let package = validated.package.expect("the package");
    let read = package
        .manifest
        .launch_probe
        .as_ref()
        .expect("the manifest declares the probe");
    assert_eq!(read.arguments, ["doctor", "--json"]);
    assert_eq!(read.carried_options, ["-c", "--config"]);
    assert_eq!(read.refused_in_service_session, ["elevated"]);
    assert_eq!(
        serde_json::to_value(read).expect("the declaration serialises"),
        declaration()
    );
    let statement = read.statement();
    assert!(statement.contains("\"doctor\" \"--json\""), "{statement}");
}

/// KR-REQ-07.64: a package that declares a probe without requesting the capability that runs it is
/// refused, and the capability is one every release has to have confirmed again.
#[test]
fn kr_req_07_64_a_probe_without_its_capability_is_refused() {
    assert_refused(
        &manifest_with(&declaration(), false),
        FindingCode::LaunchProbeWithoutCapability,
        "a probe without launch.probe",
    );
    assert!(PluginCapability::LaunchProbe.confirmed_on_every_release());
    assert!(PluginCapability::LaunchProbe.requires_installation_grant());
}

/// KR-REQ-07.64: a probe that would start the application itself, passes more than the bound, or
/// names an option or a pointer the contract does not read is refused when the package is
/// validated.
#[test]
fn kr_req_07_64_a_probe_outside_the_contract_is_refused() {
    let changed = |change: &dyn Fn(&mut Value)| {
        let mut probe = declaration();
        change(&mut probe);
        manifest_with(&probe, true)
    };
    assert_refused(
        &changed(&|probe| probe["arguments"] = json!([])),
        FindingCode::LaunchProbeInvalid,
        "no argument, which starts the application bare",
    );
    assert_refused(
        &changed(&|probe| probe["arguments"] = json!(vec!["x"; MAX_ARGUMENTS + 1])),
        FindingCode::LaunchProbeInvalid,
        "an over-long list of arguments",
    );
    assert_refused(
        &changed(&|probe| probe["carried_options"] = json!(vec!["-c"; MAX_CARRIED_OPTIONS + 1])),
        FindingCode::LaunchProbeInvalid,
        "an over-long list of carried options",
    );
    assert_refused(
        &changed(&|probe| probe["carried_options"] = json!(["config"])),
        FindingCode::LaunchProbeInvalid,
        "an option that is not a name",
    );
    assert_refused(
        &changed(&|probe| probe["mode"] = json!("checks/sandbox")),
        FindingCode::LaunchProbeInvalid,
        "a mode that is not a pointer",
    );
    assert_refused(
        &changed(&|probe| probe["arguments"] = json!(["doctor", "--json\n--other"])),
        FindingCode::LaunchProbeInvalid,
        "an argument a person reading the declaration could not see whole",
    );
}
