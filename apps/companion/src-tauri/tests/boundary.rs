//! The WebView boundary, read from the files that actually configure it.
//!
//! Section 13 states the boundary as a list of rules, and each one is a fact about a file in this
//! crate: the content-security policy in `tauri.conf.json`, the capability grants in
//! `capabilities/default.json`, the command list in the crate's own source. These tests read those
//! files rather than a copy of what they should say, so a change that widens the boundary fails
//! here instead of shipping.

use std::path::{Path, PathBuf};

use companion_tauri::commands::NAMED_COMMANDS;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} could not be read: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()))
}

fn configuration() -> serde_json::Value {
    read(&crate_root().join("tauri.conf.json"))
}

fn capabilities() -> serde_json::Value {
    read(&crate_root().join("capabilities/default.json"))
}

/// The policy, as a map from directive to its sources.
fn policy() -> std::collections::BTreeMap<String, Vec<String>> {
    let configuration = configuration();
    let csp = configuration["app"]["security"]["csp"]
        .as_str()
        .expect("the application declares a content-security policy");
    csp.split(';')
        .filter_map(|directive| {
            let mut words = directive.split_whitespace();
            let name = words.next()?;
            Some((
                name.to_owned(),
                words.map(std::borrow::ToOwned::to_owned).collect(),
            ))
        })
        .collect()
}

#[test]
fn the_interface_is_bundled_rather_than_fetched() {
    let configuration = configuration();
    let dist = configuration["build"]["frontendDist"]
        .as_str()
        .expect("the build names where the interface comes from");
    assert!(
        !dist.starts_with("http"),
        "a built application loads its interface from the bundle, not from a service"
    );
    assert_eq!(dist, "../dist");
}

#[test]
fn no_script_may_come_from_anywhere_but_the_bundle() {
    let policy = policy();
    let scripts = policy
        .get("script-src")
        .expect("the policy names where scripts may come from");
    assert_eq!(scripts, &vec!["'self'".to_owned()]);
}

#[test]
fn the_policy_permits_no_evaluation_and_no_default_source() {
    let policy = policy();
    assert_eq!(
        policy.get("default-src"),
        Some(&vec!["'none'".to_owned()]),
        "nothing is permitted unless a directive names it"
    );
    for (directive, sources) in &policy {
        assert!(
            !sources.iter().any(|source| source == "'unsafe-eval'"),
            "{directive} permits evaluation"
        );
        assert!(
            !sources.iter().any(|source| source == "*"),
            "{directive} permits anything"
        );
    }
}

#[test]
fn nothing_may_be_embedded_framed_or_navigated_away() {
    let policy = policy();
    for directive in ["object-src", "frame-src", "child-src", "form-action"] {
        assert_eq!(
            policy.get(directive),
            Some(&vec!["'none'".to_owned()]),
            "{directive} should permit nothing"
        );
    }
    assert_eq!(policy.get("base-uri"), Some(&vec!["'none'".to_owned()]));
    assert_eq!(
        policy.get("frame-ancestors"),
        Some(&vec!["'none'".to_owned()])
    );
}

#[test]
fn an_image_may_come_only_from_the_bundle_or_from_bytes_the_application_produced() {
    let policy = policy();
    let images = policy
        .get("img-src")
        .expect("the policy names where images may come from");
    for source in images {
        assert!(
            matches!(source.as_str(), "'self'" | "data:" | "blob:"),
            "img-src permits {source}, which is not the bundle or this application's own bytes"
        );
    }
    assert!(
        !images.iter().any(|source| source.starts_with("http")),
        "an image is never fetched from a remote origin by the page"
    );
}

#[test]
fn nothing_connects_anywhere_but_the_applications_own_channel() {
    let policy = policy();
    let connect = policy
        .get("connect-src")
        .expect("the policy names what the page may connect to");
    for source in connect {
        assert!(
            matches!(source.as_str(), "'self'" | "ipc:" | "http://ipc.localhost"),
            "connect-src permits {source}, which is not this application's own channel"
        );
    }
}

#[test]
fn the_capabilities_grant_no_shell_no_filesystem_and_no_general_http() {
    let capabilities = capabilities();
    let granted: Vec<String> = capabilities["permissions"]
        .as_array()
        .expect("the capability file lists its permissions")
        .iter()
        .map(|permission| match permission {
            serde_json::Value::String(name) => name.clone(),
            other => other["identifier"]
                .as_str()
                .expect("a permission names itself")
                .to_owned(),
        })
        .collect();

    for forbidden in ["shell:", "fs:", "http:", "process:", "os:"] {
        assert!(
            !granted.iter().any(|name| name.starts_with(forbidden)),
            "the interface is granted {forbidden}, which the boundary does not permit"
        );
    }
    assert!(
        granted.iter().any(|name| name == "dialog:allow-save"),
        "an export needs the platform's own save dialog"
    );
}

#[test]
fn an_external_link_is_permitted_only_for_the_approved_schemes() {
    let capabilities = capabilities();
    let opener = capabilities["permissions"]
        .as_array()
        .expect("the capability file lists its permissions")
        .iter()
        .find(|permission| permission["identifier"] == "opener:allow-open-url")
        .expect("opening a link is granted explicitly");
    let allowed: Vec<String> = opener["allow"]
        .as_array()
        .expect("the grant names what may be opened")
        .iter()
        .map(|entry| entry["url"].as_str().expect("a URL pattern").to_owned())
        .collect();
    assert_eq!(allowed, vec!["https://*".to_owned(), "mailto:*".to_owned()]);
    assert_eq!(
        allowed.len(),
        companion_tauri::links::APPROVED_SCHEMES.len(),
        "the platform grant and the application's own scheme list are the same list"
    );
}

#[test]
fn the_asset_protocol_is_off_and_the_prototype_is_frozen() {
    let configuration = configuration();
    assert_eq!(
        configuration["app"]["security"]["assetProtocol"]["enable"],
        serde_json::Value::Bool(false),
        "there is no protocol that turns a path into a readable URL"
    );
    assert_eq!(
        configuration["app"]["security"]["freezePrototype"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        configuration["app"]["withGlobalTauri"],
        serde_json::Value::Bool(false),
        "the command bridge is not a global the page can reach without importing it"
    );
}

#[test]
fn every_command_the_page_can_call_is_one_this_crate_names() {
    // The handler list is generated from the same names, so this is the list as data: a command
    // that exists without an entry here, or an entry without a command, is a boundary that two
    // files disagree about.
    let named: Vec<&str> = NAMED_COMMANDS.iter().map(|(command, _)| *command).collect();
    let source = std::fs::read_to_string(crate_root().join("src/commands.rs"))
        .expect("the command module is readable");
    let handlers = source
        .split("tauri::generate_handler![")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .expect("the handler list is generated in this module");
    let registered: Vec<String> = handlers
        .split(',')
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .collect();

    for command in &named {
        assert!(
            registered.iter().any(|name| name == command),
            "{command} is named but not registered"
        );
    }
    for command in &registered {
        assert!(
            named.iter().any(|name| name == command),
            "{command} is registered but not named"
        );
    }
}

#[test]
fn no_command_is_a_shell_a_path_or_a_method_the_page_chooses() {
    for (command, _) in NAMED_COMMANDS {
        let lowered = command.to_ascii_lowercase();
        // `shell_launch` is the specification's own name for installing a command at a verified
        // empty prompt, and it is a protocol method with its own preconditions rather than a
        // general shell. Every other shape of general execution is what this refuses.
        if *command == "shell_launch" {
            continue;
        }
        for forbidden in [
            "exec",
            "shell",
            "spawn",
            "eval",
            "read_file",
            "write_file",
            "invoke",
        ] {
            assert!(
                !lowered.contains(forbidden),
                "{command} reads as a general {forbidden}"
            );
        }
    }
}
