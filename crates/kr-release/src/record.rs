//! The release record: what a release was qualified against, cited by digest.
//!
//! The specification keeps exact vendor routes, dependency and runtime revisions, model assets,
//! provider event schemas and service limits in immutable records, and asks every enabled
//! capability to cite its qualified implementation and evidence. A release carries
//! `share/release-record.json`, which lists those records with their digests, and the manifest
//! lists the file, so the signature covers it.
//!
//! What a release cites is written down in `docs/releases/records.json`, one entry per class.
//! A class is recorded (each record with its repository, revision, path and digest), unavailable
//! (the release leaves off the capability that needs it, and says which), or pending, which a run
//! that proves the pipeline may carry and a run that signs for release may not. A record in this
//! checkout is read here and digested; a record in another repository is checked against its
//! digest when that repository is at hand, and cited by it when it is not.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::agents;
use crate::refusal::{Refusal, Result, digest, digest_file, hex, read, read_json, refuse};

/// The classes a record keeps, in the order the specification names them.
pub const CLASSES: [&str; 5] = [
    "vendor_routes",
    "dependency_and_runtime_revisions",
    "model_assets",
    "provider_event_schemas",
    "service_limits",
];

/// Where the record's source is written down.
pub const LOCK: &str = "docs/releases/records.json";

/// Where a release keeps its record.
pub const FILE: &str = "share/release-record.json";

#[derive(Deserialize)]
struct Lock {
    format: u32,
    classes: BTreeMap<String, Class>,
}

#[derive(Deserialize)]
struct Class {
    state: String,
    #[serde(default)]
    records: Vec<Cited>,
    #[serde(default)]
    capability: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct Cited {
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    revision: Option<String>,
    path: String,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    covers: Option<String>,
}

/// The other repositories' checkouts at hand, by what they are.
#[derive(Default)]
pub struct Elsewhere {
    /// The plugins repository.
    pub plugins: Option<PathBuf>,
    /// The web repository.
    pub web: Option<PathBuf>,
}

/// Builds the record of a release for `target`.
///
/// `development` lets a class stay pending; a release that is signed for release does not.
///
/// # Errors
///
/// Returns a refusal for a class that is missing or malformed, a record that is missing or moved,
/// a pending class in a release, and an enabled capability that cites no qualified evidence.
pub fn build(
    checkout: &Path,
    target: &str,
    elsewhere: &Elsewhere,
    development: bool,
) -> Result<Value> {
    let lock: Lock = serde_json::from_value(read_json(&checkout.join(LOCK))?)
        .map_err(|error| Refusal(format!("{LOCK} is not a record lock: {error}")))?;
    if lock.format != 1 {
        refuse!(
            "{LOCK} is format {}, and this tool reads format 1",
            lock.format
        );
    }
    let named: Vec<&str> = lock.classes.keys().map(String::as_str).collect();
    let mut expected = CLASSES.to_vec();
    expected.sort_unstable();
    if named != expected {
        refuse!("{LOCK} keeps the classes {named:?}, and a release record keeps {CLASSES:?}");
    }
    let pinned_plugins = bundled_plugins_commit(checkout)?;
    let enabled = capabilities(checkout, target)?;

    let mut classes = Vec::new();
    for name in CLASSES {
        let class = &lock.classes[name];
        let entry = match class.state.as_str() {
            "recorded" => {
                if class.records.is_empty() {
                    refuse!("{name} is recorded and cites no record");
                }
                let mut records = Vec::new();
                for cited in &class.records {
                    records.extend(cite(checkout, name, cited, elsewhere, &pinned_plugins)?);
                }
                json!({ "class": name, "state": "recorded", "records": records })
            }
            "unavailable" => {
                let (Some(capability), Some(reason)) = (&class.capability, &class.reason) else {
                    refuse!(
                        "{name} is unavailable and does not say which capability the release leaves off, and why"
                    );
                };
                if enabled
                    .iter()
                    .any(|entry| entry["capability"] == capability.as_str())
                {
                    refuse!(
                        "{name} is unavailable because the release leaves off {capability}, and an \
                         agent build of this release enables it"
                    );
                }
                json!({ "class": name, "state": "unavailable", "capability": capability, "reason": reason })
            }
            "pending" => {
                let Some(reason) = &class.reason else {
                    refuse!("{name} is pending and does not say why");
                };
                if !development {
                    refuse!("{name} is pending, and a release is not signed with a record that is");
                }
                json!({ "class": name, "state": "pending", "reason": reason })
            }
            other => refuse!(
                "{name} is in the state `{other}`, which is none of recorded, unavailable and pending"
            ),
        };
        classes.push(entry);
    }
    Ok(json!({
        "format": 1,
        "classes": classes,
        "capabilities": enabled,
    }))
}

/// The commit of the plugins repository the bundled catalogue was taken from.
fn bundled_plugins_commit(checkout: &Path) -> Result<String> {
    let lock = read_json(&checkout.join("bundled-plugins.lock"))?;
    lock["source"]["commit"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Refusal("bundled-plugins.lock names no commit".to_owned()))
}

/// One citation, as the records it stands for.
fn cite(
    checkout: &Path,
    class: &str,
    cited: &Cited,
    elsewhere: &Elsewhere,
    pinned_plugins: &str,
) -> Result<Vec<Value>> {
    let Some(repository) = &cited.repository else {
        return in_checkout(checkout, class, cited);
    };
    let Some(revision) = &cited.revision else {
        refuse!(
            "{class}: {} in {repository} is cited with no revision",
            cited.path
        );
    };
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        refuse!(
            "{class}: the revision `{revision}` of {} is not a full commit",
            cited.path
        );
    }
    if repository.ends_with("/kalareach-plugins") && revision != pinned_plugins {
        refuse!(
            "{class}: {} is cited at {revision}, and the bundled catalogue was taken from \
             {pinned_plugins}",
            cited.path
        );
    }
    let directory = if repository.ends_with("/kalareach-plugins") {
        elsewhere.plugins.as_deref()
    } else if repository.ends_with("/kalareach-web") {
        elsewhere.web.as_deref()
    } else {
        None
    };
    let expected = match (&cited.sha256, &cited.text) {
        (Some(expected), None) | (None, Some(expected)) => expected,
        _ => refuse!(
            "{class}: {} states a digest or a text, and exactly one",
            cited.path
        ),
    };
    let read_here = match directory {
        Some(directory) => {
            let output = Command::new("git")
                .arg("-C")
                .arg(directory)
                .arg("show")
                .arg(format!("{revision}:{}", cited.path))
                .output()
                .map_err(|error| Refusal(format!("git cannot be run: {error}")))?;
            if !output.status.success() {
                refuse!(
                    "{class}: {} is missing from {repository} at {revision}",
                    cited.path
                );
            }
            let found = if cited.sha256.is_some() {
                hex(&digest(&output.stdout))
            } else {
                String::from_utf8_lossy(&output.stdout).trim().to_owned()
            };
            if found != *expected {
                refuse!(
                    "{class}: {} at {revision} in {repository} is not the record that was cited: \
                     it holds {found}, and the lock says {expected}",
                    cited.path
                );
            }
            true
        }
        None => false,
    };
    let mut record = json!({
        "repository": repository,
        "revision": revision,
        "path": cited.path,
        "read": read_here,
    });
    if let Some(sha256) = &cited.sha256 {
        record["sha256"] = json!(sha256);
    }
    if let Some(text) = &cited.text {
        record["text"] = json!(text);
    }
    if let Some(covers) = &cited.covers {
        record["covers"] = json!(covers);
    }
    Ok(vec![record])
}

/// A record in this checkout: a file, or every file of a directory that ends in `*.json`.
fn in_checkout(checkout: &Path, class: &str, cited: &Cited) -> Result<Vec<Value>> {
    let paths: Vec<String> = if let Some(directory) = cited.path.strip_suffix("/*.json") {
        let mut found: Vec<String> = std::fs::read_dir(checkout.join(directory))
            .map_err(|error| Refusal(format!("{class}: {directory} cannot be read: {error}")))?
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension == "json")
            })
            .map(|name| format!("{directory}/{name}"))
            .collect();
        found.sort();
        found
    } else {
        vec![cited.path.clone()]
    };
    if paths.is_empty() {
        refuse!("{class}: {} matches no file", cited.path);
    }
    let mut records = Vec::new();
    for path in paths {
        let file = checkout.join(&path);
        if !file.is_file() {
            refuse!("{class}: {path} is missing");
        }
        let mut record = json!({ "path": path, "sha256": hex(&digest_file(&file)?) });
        if class == "model_assets" {
            let profile = read_json(&file)?;
            record["details"] = json!({
                "profile_id": profile["profile_id"],
                "model_repository": profile["model"]["repository"],
                "model_revision": profile["model"]["revision"],
                "conversion_revision": profile["conversion"]["revision"],
                "runtime_revision": profile["runtime"]["llama_cpp_revision"],
                "assets": profile["assets"]
                    .as_array()
                    .map(|assets| assets.iter().map(|asset| json!({
                        "file_name": asset["file_name"],
                        "sha256": asset["sha256"],
                    })).collect::<Vec<_>>())
                    .unwrap_or_default(),
            });
        }
        records.push(record);
    }
    Ok(records)
}

/// The capabilities the release enables by evidence: those of the agent builds it lists, each with
/// the qualification records of its plugin.
///
/// # Errors
///
/// Returns a refusal for a build whose plugin cites no qualification.
fn capabilities(checkout: &Path, target: &str) -> Result<Vec<Value>> {
    let qualifications = agents::qualifications(checkout)?;
    let mut enabled = Vec::new();
    for agent in agents::agents(checkout, target)? {
        let cited = qualifications
            .get(&agent.plugin)
            .filter(|cited| !cited.is_empty());
        let Some(cited) = cited else {
            refuse!(
                "{} {} lists a build of {} and cites no qualification, so its capabilities have \
                 no evidence",
                agent.plugin,
                agent.plugin_version,
                agent.application
            );
        };
        for capability in &agent.capabilities {
            enabled.push(json!({
                "plugin": agent.plugin,
                "plugin_version": agent.plugin_version,
                "application": agent.application,
                "capability": capability,
                "qualification": cited,
            }));
        }
    }
    Ok(enabled)
}

/// Writes the record into a tree.
///
/// # Errors
///
/// Returns a refusal when the record cannot be built or written.
pub fn write(tree: &Path, record: &Value) -> Result<()> {
    let path = tree.join(FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| Refusal(format!("{} cannot be made: {error}", parent.display())))?;
    }
    let mut text = serde_json::to_string_pretty(record)
        .map_err(|error| Refusal(format!("the record is not JSON: {error}")))?;
    text.push('\n');
    std::fs::write(&path, text)
        .map_err(|error| Refusal(format!("{} cannot be written: {error}", path.display())))
}

/// Holds the record a tree carries to the one its checkout now makes, and refuses a pending class
/// unless this is a development run.
///
/// # Errors
///
/// Returns a refusal when the tree has no record, or its record is not the one now made.
pub fn held(
    tree: &Path,
    checkout: &Path,
    target: &str,
    elsewhere: &Elsewhere,
    development: bool,
) -> Result<()> {
    let carried =
        read(&tree.join(FILE)).map_err(|_| Refusal(format!("the tree carries no {FILE}")))?;
    let made = build(checkout, target, elsewhere, development)?;
    let carried: Value = serde_json::from_slice(&carried)
        .map_err(|error| Refusal(format!("{FILE} is not JSON: {error}")))?;
    if carried != made {
        refuse!("{FILE} is not the record this checkout makes: a record it cites moved or went");
    }
    Ok(())
}
