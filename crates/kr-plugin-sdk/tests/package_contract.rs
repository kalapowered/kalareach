//! The package contract: what a package directory holds and what its manifest declares.
//!
//! Section 11 fixes both halves. A package is `plugin.json`, an optional `connector.json`,
//! `presentation.json`, an optional `component.wasm`, assets, native hook bridge files, skill
//! packages and conformance fixtures; its manifest declares immutable plugin and publisher
//! identities, a version, SDK and WIT ranges, executable and distribution match rules, operating
//! system and architecture support, hashes, requested capabilities, actions and attachment modes.
//! These tests read a committed fixture package for the declarations and build a package with
//! every kind of file in it for the layout.

use std::path::{Path, PathBuf};

use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::example;
use kr_plugin_sdk::package::{MANIFEST_FILE, PRESENTATION_FILE};
use kr_plugin_sdk::validate::{FindingCode, validate_package_directory};
use serde_json::{Value, json};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins")
}

/// KR-REQ-11.19: a manifest declares its immutable publisher and plugin identities, a version,
/// bounded SDK and WIT ranges, executable and distribution match rules, the operating systems and
/// architectures it supports, the hash and exact size of every payload, the capabilities it
/// requests and the actions it registers, and the validated package carries each of them.
#[test]
fn a_manifest_declares_identity_ranges_match_rules_platforms_hashes_and_capabilities() {
    let directory = fixtures_root().join("valid/example-connector");
    let validated = validate_package_directory(&directory);
    assert!(
        validated.report.is_valid(),
        "{:?}",
        validated.report.findings
    );
    let package = validated.package.expect("the package");
    let manifest = serde_json::to_value(&package.manifest).expect("the manifest serialises");

    // Identity, version and the two ranges the host checks before it loads anything.
    assert_eq!(manifest["publisher_id"], "kalareach");
    assert_eq!(manifest["plugin_name"], "example-connector");
    assert_eq!(manifest["version"], "0.1.0");
    assert_eq!(manifest["sdk_range"], ">=0.1.1, <0.2.0");
    assert_eq!(manifest["wit_range"], ">=0.1.0, <0.2.0");

    // Match rules name both the executable and the distribution it came from.
    assert_eq!(
        manifest["match_rules"],
        json!([{
            "id": "example-agent",
            "executable": {
                "file_stem": "example-agent",
                "path_suffix": [],
                "version_range": ">=1.0.0, <2.0.0"
            },
            "distribution": {"registry": "npm", "package": "@kalareach/example-agent"},
            "confidence": "exact"
        }])
    );

    // Operating system and architecture support.
    assert_eq!(
        manifest["platforms"],
        json!([
            {"os": "linux", "architectures": ["x86_64", "aarch64"]},
            {"os": "mac_os", "architectures": ["aarch64"]}
        ])
    );

    // Every payload is declared with its hash and its exact size, and both are what the file on
    // disk is: the digest is recomputed here from the bytes rather than taken from the validator.
    assert!(!package.manifest.payloads.is_empty());
    for payload in &package.manifest.payloads {
        let bytes = std::fs::read(directory.join(payload.path.as_str()))
            .unwrap_or_else(|error| panic!("{}: {error}", payload.path));
        assert_eq!(
            PayloadDigest::of(&bytes),
            payload.digest,
            "{} is declared with its own hash",
            payload.path
        );
        assert_eq!(
            serde_json::to_value(payload.size_bytes).expect("a size"),
            json!(bytes.len().to_string()),
            "{} is declared with its exact size",
            payload.path
        );
        let found = package
            .file(&payload.path)
            .expect("the declared file is in the package");
        assert_eq!(found.digest, payload.digest);
    }
    let roles: Vec<Value> = package
        .manifest
        .payloads
        .iter()
        .map(|payload| serde_json::to_value(payload.role).expect("a role"))
        .collect();
    assert_eq!(roles, [json!("connector"), json!("presentation")]);

    // The capabilities it requests, each with the reason a person reviewing it reads.
    let requested: Vec<(String, String)> = manifest["capabilities"]
        .as_array()
        .expect("capabilities")
        .iter()
        .map(|entry| {
            (
                entry["capability"].as_str().expect("a name").to_owned(),
                entry["reason"].as_str().expect("a reason").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        requested
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        [
            "metadata.match",
            "presentation.declarative",
            "broker.semantic_events",
            "upstream.action",
            "approval.respond"
        ]
    );
    assert!(requested.iter().all(|(_, reason)| !reason.is_empty()));

    // The actions it registers, each with its effect class.
    assert_eq!(manifest["actions"][0]["id"], "prompt.send");
    assert_eq!(manifest["actions"][0]["effect"], "upstream.prompt");
    assert_eq!(manifest["actions"][1]["id"], "approval.answer");
    assert_eq!(manifest["actions"][1]["effect"], "approval.respond");
}

/// KR-REQ-11.19: an unbounded SDK range, a payload whose bytes do not match its hash and an effect
/// whose capability was never requested are each refused by the validator.
#[test]
fn a_declaration_the_package_does_not_honour_is_refused() {
    for (case, code) in [
        ("unbounded-sdk-range", FindingCode::UnboundedVersionRange),
        ("digest-mismatch", FindingCode::DigestMismatch),
        (
            "effect-without-capability",
            FindingCode::EffectWithoutCapability,
        ),
    ] {
        let validated =
            validate_package_directory(&fixtures_root().join("invalid").join(case).join("package"));
        assert!(
            validated.report.has(code),
            "{case} is refused as {}: {:?}",
            code.as_str(),
            validated.report.findings
        );
    }
}

/// Writes `bytes` at `path` inside `package`, creating its directories.
fn write(package: &Path, path: &str, bytes: &[u8]) {
    let target = package.join(path);
    std::fs::create_dir_all(target.parent().expect("a parent")).expect("the directory");
    std::fs::write(target, bytes).expect("the file writes");
}

/// KR-REQ-11.19: a package lays out its manifest, its presentation document, a component, an
/// asset, a native hook bridge file, a skill package and a conformance fixture, each declared as a
/// payload of its own role with its hash and size, and its manifest declares the attachment modes
/// it offers; the validator accepts it, and a changed byte, a file nobody declared or a size that
/// is not the file's own is a finding.
#[test]
fn every_part_of_the_layout_is_a_declared_payload_with_its_hash() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let package = temporary.path().join("package");
    std::fs::create_dir_all(&package).expect("the package directory");
    write(
        &package,
        PRESENTATION_FILE,
        example::example_presentation_json().as_bytes(),
    );

    // The parts the layout names beside the two documents, one of each role.
    let parts: [(&str, &str, &[u8]); 5] = [
        ("component", "component.wasm", b"\0asm\x01\0\0\0"),
        ("asset", "README.md", b"# Example package\n"),
        ("native_bridge", "bridge/hooks.json", b"{\"hooks\":[]}\n"),
        (
            "skill",
            "skills/example/SKILL.md",
            b"---\nname: example\n---\nAsk before acting.\n",
        ),
        ("fixture", "fixtures/conformance.json", b"{\"cases\":[]}\n"),
    ];
    let mut manifest: Value =
        serde_json::from_str(&example::example_manifest_json()).expect("the example manifest");
    // The attachment modes: what the upstream accepts, how much, and how it reaches the draft.
    // Contributing to the upstream draft is an upstream action, so the package requests that.
    manifest["capabilities"]
        .as_array_mut()
        .expect("the manifest requests capabilities")
        .push(json!({
            "capability": "upstream.action",
            "reason": "Hand a file the person chose to the application's own composer"
        }));
    manifest["attachments"] = json!({
        "accepted_media_types": ["image/png", "text/*"],
        "max_bytes": "10485760",
        "max_count": 4,
        "insertion": "native_composer",
        "external_destination": null
    });
    let payloads = manifest["payloads"]
        .as_array_mut()
        .expect("the manifest lists payloads");
    for (role, path, bytes) in parts {
        write(&package, path, bytes);
        payloads.push(json!({
            "role": role,
            "path": path,
            "digest": PayloadDigest::of(bytes).to_string(),
            "size_bytes": bytes.len().to_string(),
        }));
    }
    let manifest_text = serde_json::to_string_pretty(&manifest).expect("the manifest serialises");
    write(&package, MANIFEST_FILE, manifest_text.as_bytes());

    let validated = validate_package_directory(&package);
    assert!(
        validated.report.is_valid(),
        "{:?}",
        validated.report.findings
    );
    let found = validated.package.expect("the package");
    let attachments = found
        .manifest
        .attachments
        .0
        .as_ref()
        .expect("the manifest declares its attachment modes");
    assert_eq!(attachments.accepted_media_types, ["image/png", "text/*"]);
    assert_eq!(attachments.max_bytes.get(), 10_485_760);
    assert_eq!(attachments.max_count.get(), 4);
    assert_eq!(
        serde_json::to_value(attachments.insertion).expect("a mode"),
        json!("native_composer")
    );
    for (_, path, bytes) in parts {
        let file = found
            .files
            .iter()
            .find(|file| file.path.as_str() == path)
            .unwrap_or_else(|| panic!("{path} is in the package"));
        assert_eq!(file.digest, PayloadDigest::of(bytes), "{path}");
        assert_eq!(file.size_bytes, bytes.len() as u64, "{path}");
    }

    // A changed byte in a declared part is a hash that no longer matches.
    write(
        &package,
        "skills/example/SKILL.md",
        b"---\nname: example\n---\nAct before asking.\n",
    );
    let validated = validate_package_directory(&package);
    assert!(
        validated.report.has(FindingCode::DigestMismatch),
        "{:?}",
        validated.report.findings
    );

    // A file nobody declared is refused, whatever it is.
    write(
        &package,
        "skills/example/SKILL.md",
        b"---\nname: example\n---\nAsk before acting.\n",
    );
    write(&package, "fixtures/extra.json", b"{}\n");
    let validated = validate_package_directory(&package);
    assert!(
        validated.report.has(FindingCode::UndeclaredFile),
        "{:?}",
        validated.report.findings
    );
    std::fs::remove_file(package.join("fixtures/extra.json")).expect("removes the extra file");

    // A declared size that is not the file's own is refused too.
    let payloads = manifest["payloads"].as_array_mut().expect("payloads");
    let asset = payloads
        .iter_mut()
        .find(|payload| payload["path"] == "README.md")
        .expect("the asset");
    asset["size_bytes"] = json!("1");
    write(
        &package,
        MANIFEST_FILE,
        serde_json::to_string_pretty(&manifest)
            .expect("the manifest serialises")
            .as_bytes(),
    );
    let validated = validate_package_directory(&package);
    assert!(
        validated.report.has(FindingCode::SizeMismatch),
        "{:?}",
        validated.report.findings
    );
}
