//! A package's command integration, as the package validator reads it.
//!
//! Section 12 lets an explicitly enabled command integration add the flags an agent needs to an
//! interactive invocation, and section 7 keeps every reserved KR bootstrap value the worker's. A
//! package declares its integration in its manifest, beside its native bridge, and the validator
//! every host, publisher and pipeline runs decides what a declaration may say. These cases build a
//! whole package directory around the example manifest and run that validator on it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.07 | a declared integration is read from the verified manifest with its capability; one without it, or with a reserved, loader, search-path or startup variable, an empty flag or an over-long list, is refused |
//! | KR-REQ-12.20 | Gemini CLI's `GEMINI_CLI_NO_RELAUNCH=true` is a variable a package may set |
//! | KR-REQ-12.22 | Qoder CLI's two launch flags, as core pins them, are flags a package may add |

use std::path::{Path, PathBuf};

use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::example;
use kr_plugin_sdk::integration::{MAX_FLAGS, PERMITTED_VARIABLES};
use kr_plugin_sdk::package::{MANIFEST_FILE, PRESENTATION_FILE};
use kr_plugin_sdk::plugin::PluginManifest;
use kr_plugin_sdk::validate::{FindingCode, Validated, validate_package_directory};
use serde_json::{Value, json};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The example package with `integration` as its command integration, `command` as the executable
/// name of its one match rule, and the capability requested unless `capability` is false.
fn manifest_with(command: &str, integration: &Value, capability: bool) -> Value {
    let mut manifest: Value =
        serde_json::from_str(&example::example_manifest_json()).expect("the example manifest");
    manifest["sdk_range"] = json!(">=0.1.2, <0.2.0");
    manifest["match_rules"][0]["executable"]["file_stem"] = json!(command);
    if capability {
        manifest["capabilities"]
            .as_array_mut()
            .expect("the manifest requests capabilities")
            .push(json!({
                "capability": "command_integration.launch",
                "reason": "Start the agent with the flags its bridge needs"
            }));
    }
    manifest["command_integration"] = integration.clone();
    manifest
}

fn declaration(command: &str, flags: &[&str], variables: &[(&str, &str)]) -> Value {
    json!({
        "command": command,
        "flags": flags,
        "variables": variables
            .iter()
            .map(|(name, value)| json!({ "name": name, "value": value }))
            .collect::<Vec<_>>(),
        "grant_statement": "Starts the agent in KalaReach sessions with what its bridge needs"
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
    validate_package_directory(&package)
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

/// KR-REQ-12.07: a package's command integration is read from its verified manifest, whole and in
/// the declared order, beside the capability that applies it.
#[test]
fn kr_req_12_07_a_declared_integration_is_read_from_the_manifest() {
    let integration = declaration(
        "claude",
        &[
            "--dangerously-load-development-channels",
            "plugin:kalareach-channels@skills-dir",
        ],
        &[],
    );
    let validated = validate(&manifest_with("claude", &integration, true));
    assert!(
        validated.report.is_valid(),
        "{:?}",
        validated.report.findings
    );
    let package = validated.package.expect("the package");
    let read = package
        .manifest
        .command_integration
        .as_ref()
        .expect("the manifest declares the integration");
    assert_eq!(read.command, "claude");
    assert_eq!(
        read.flags,
        [
            "--dangerously-load-development-channels",
            "plugin:kalareach-channels@skills-dir"
        ]
    );
    assert!(read.variables.is_empty());
    assert_eq!(
        serde_json::to_value(read).expect("the declaration serialises"),
        integration
    );
}

/// KR-REQ-12.07: a declared integration without the capability that applies it is refused, as a
/// native bridge without `native_bridge.install` is.
#[test]
fn kr_req_12_07_an_integration_without_its_capability_is_refused() {
    assert_refused(
        &manifest_with("claude", &declaration("claude", &["--flag"], &[]), false),
        FindingCode::IntegrationWithoutCapability,
        "an integration without command_integration.launch",
    );
}

/// KR-REQ-12.07: a reserved or loader variable, an empty flag and an over-long list are refused
/// when the package is validated, and so are a search-path and a startup variable.
#[test]
fn kr_req_12_07_a_reserved_or_loader_variable_an_empty_flag_and_an_over_long_list_are_refused() {
    for (name, value) in [
        ("KR_REGISTRATION", "/tmp/registration.1.2"),
        ("LD_PRELOAD", "/tmp/preload.so"),
        ("DYLD_INSERT_LIBRARIES", "/tmp/insert.dylib"),
        ("PATH", "/tmp"),
        ("BASH_ENV", "/tmp/startup.sh"),
    ] {
        assert_refused(
            &manifest_with(
                "agent",
                &declaration("agent", &["--flag"], &[(name, value)]),
                true,
            ),
            FindingCode::IntegrationInvalid,
            name,
        );
    }
    assert_refused(
        &manifest_with("agent", &declaration("agent", &["--flag", ""], &[]), true),
        FindingCode::IntegrationInvalid,
        "an empty flag",
    );
    let too_many: Vec<&str> = std::iter::repeat_n("--flag", MAX_FLAGS + 1).collect();
    assert_refused(
        &manifest_with("agent", &declaration("agent", &too_many, &[]), true),
        FindingCode::IntegrationInvalid,
        "an over-long list",
    );
    assert_refused(
        &manifest_with("agent", &declaration("other-agent", &["--flag"], &[]), true),
        FindingCode::IntegrationInvalid,
        "a command none of the package's match rules names",
    );
}

/// KR-REQ-12.20: Gemini CLI's integration sets `GEMINI_CLI_NO_RELAUNCH=true` and adds no flag, and
/// that is a declaration a package may make.
#[test]
fn kr_req_12_20_gemini_cli_s_variable_validates() {
    assert!(
        PERMITTED_VARIABLES.iter().any(
            |permitted| permitted.name == "GEMINI_CLI_NO_RELAUNCH" && permitted.value == "true"
        )
    );
    let validated = validate(&manifest_with(
        "gemini",
        &declaration("gemini", &[], &[("GEMINI_CLI_NO_RELAUNCH", "true")]),
        true,
    ));
    assert!(
        validated.report.is_valid(),
        "{:?}",
        validated.report.findings
    );
}

/// KR-REQ-12.22: the two elements core pins for Qoder CLI's launch, `--settings` and the inline
/// hooks after it, are flags a package may add.
#[test]
fn kr_req_12_22_qoder_cli_s_launch_flags_validate() {
    let pinned: Vec<String> = serde_json::from_slice(
        &std::fs::read(repository_root().join("fixtures/bridges/qoder-cli/flags.json"))
            .expect("the pinned flags"),
    )
    .expect("a list of flags");
    let flags: Vec<&str> = pinned.iter().map(String::as_str).collect();
    let validated = validate(&manifest_with(
        "qodercli",
        &declaration("qodercli", &flags, &[]),
        true,
    ));
    assert!(
        validated.report.is_valid(),
        "{:?}",
        validated.report.findings
    );
}

/// A manifest written before the member existed declares no integration, and a manifest that
/// declares none is written without the member: every committed manifest, published packages and
/// examples alike, reads and is written again byte for byte, so its hash is the one it has now.
#[test]
fn a_manifest_without_an_integration_reads_and_writes_as_before() {
    let mut read = 0;
    for root in [
        repository_root().join("fixtures/plugins/valid"),
        repository_root().join("fixtures/plugins/catalogue/development/targets/packages"),
        repository_root()
            .join("crates/kr-controller/tests/fixtures/bridge-generation/targets/packages"),
    ] {
        for path in manifests_under(&root) {
            let bytes = std::fs::read(&path).expect("the manifest reads");
            let manifest: PluginManifest = serde_json::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            assert!(manifest.command_integration.is_none(), "{}", path.display());
            let mut written =
                serde_json::to_string_pretty(&manifest).expect("the manifest serialises");
            written.push('\n');
            assert_eq!(
                written.as_bytes(),
                bytes.as_slice(),
                "{} is written back byte for byte",
                path.display()
            );
            assert_eq!(
                PayloadDigest::of(written.as_bytes()),
                PayloadDigest::of(&bytes),
                "{}",
                path.display()
            );
            read += 1;
        }
    }
    assert!(read >= 10, "only {read} committed manifests were read");
    // The examples the generator writes are the committed bytes too.
    for (committed, rendered) in [
        (
            "fixtures/plugins/valid/example-declarative/plugin.json",
            example::example_manifest_json(),
        ),
        (
            "fixtures/plugins/valid/example-connector/plugin.json",
            example::example_connector_manifest_json(),
        ),
    ] {
        let bytes = std::fs::read(repository_root().join(committed)).expect("the committed file");
        assert_eq!(rendered.as_bytes(), bytes.as_slice(), "{committed}");
    }
}

fn manifests_under(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("the directory reads") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.file_name().is_some_and(|name| name == MANIFEST_FILE) {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}
