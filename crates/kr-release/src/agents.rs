//! The executable builds of the supported agents a release is qualified against.
//!
//! The signed plugin index at the pinned commit names, for an entry whose record passed every part
//! of the version qualification, each executable build by application, distribution, version,
//! operating system, architecture and digest. A release lists the builds for its own platform with
//! the capabilities the entry declares: a named build opens every capability its release declares.
//! The index names none today, and the release lists none.

use std::collections::BTreeMap;
use std::path::Path;

use kr_plugin_sdk::catalogue::CatalogueIndex;
use kr_plugin_sdk::matching::{Architecture, OperatingSystem};
use kr_protocol::update::ReleaseAgent;

use crate::refusal::{Refusal, Result, digest_file, hex, read_json, refuse, scalar};

/// The two files of the bundled catalogue the release reads, and the lock that pins them.
const INDEX: &str = "bundled-plugins/targets/index.json";
const TARGETS: &str = "bundled-plugins/metadata/targets.json";
const LOCK: &str = "bundled-plugins.lock";

/// The bundled index, read as the catalogue reads it, after it is held to what pins it: the lock
/// that the bundled catalogue is synchronised to names its digest and its targets metadata's, and
/// that metadata names the index's.
fn index(checkout: &Path) -> Result<CatalogueIndex> {
    let lock = read_json(&checkout.join(LOCK))?;
    let locked = |path: &str| -> Result<String> {
        lock["metadata"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|entry| entry["path"] == path)
            .and_then(|entry| entry["digest"].as_str())
            .map(str::to_owned)
            .ok_or_else(|| Refusal(format!("{LOCK} pins no {path}")))
    };
    let held = |file: &str, pinned: String| -> Result<()> {
        if hex(&digest_file(&checkout.join(file))?) != pinned {
            refuse!("{file} is not the file {LOCK} pins");
        }
        Ok(())
    };
    held(INDEX, locked("targets/index.json")?)?;
    held(TARGETS, locked("metadata/targets.json")?)?;
    let targets = read_json(&checkout.join(TARGETS))?;
    let pinned = targets["signed"]["targets"]["index.json"]["hashes"]["sha256"]
        .as_str()
        .ok_or_else(|| Refusal("the bundled targets metadata pins no index".to_owned()))?;
    held(INDEX, pinned.to_owned())?;
    let index: CatalogueIndex = serde_json::from_value(read_json(&checkout.join(INDEX))?)
        .map_err(|error| Refusal(format!("the bundled index is not an index: {error}")))?;
    for entry in &index.entries {
        entry
            .check_builds()
            .map_err(|error| Refusal(format!("{} {}: {error}", entry.plugin_id, entry.version)))?;
        for result in &entry.qualification {
            result.validate().map_err(|error| {
                Refusal(format!("{} {}: {error}", entry.plugin_id, entry.version))
            })?;
        }
    }
    Ok(index)
}

/// The builds the bundled index names for `target`, each with its entry's capabilities.
///
/// # Errors
///
/// Returns a refusal when the index is not the one the lock and the bundled metadata pin, or
/// breaks a rule a catalogue index keeps.
pub fn agents(checkout: &Path, target: &str) -> Result<Vec<ReleaseAgent>> {
    let (os, architecture) = platform(target)?;
    let mut agents = Vec::new();
    for entry in index(checkout)?.entries {
        let capabilities: Vec<String> = entry
            .capabilities
            .iter()
            .map(|request| request.capability.to_string())
            .collect();
        for build in entry.builds_for(os, architecture) {
            agents.push(ReleaseAgent {
                plugin: entry.plugin_id.to_string(),
                plugin_version: entry.version.to_string(),
                application: build.application.to_string(),
                distribution: build.distribution.to_string(),
                version: build.version.to_string(),
                os: build.os.as_str().to_owned(),
                architecture: build.architecture.as_str().to_owned(),
                sha256: scalar(*build.executable_digest.as_bytes()),
                schema_hash: None,
                capabilities: capabilities.clone(),
            });
        }
    }
    agents.sort_by(|first, second| {
        (&first.plugin, &first.application, &first.version).cmp(&(
            &second.plugin,
            &second.application,
            &second.version,
        ))
    });
    Ok(agents)
}

/// The qualification results each plugin of the bundled index cites, by plugin, as the index
/// states them.
///
/// # Errors
///
/// Returns a refusal when the index cannot be read as [`agents`] reads it.
pub fn qualifications(checkout: &Path) -> Result<BTreeMap<String, Vec<serde_json::Value>>> {
    let mut by_plugin = BTreeMap::new();
    for entry in index(checkout)?.entries {
        let results = entry
            .qualification
            .iter()
            .map(serde_json::to_value)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| Refusal(format!("a qualification result is not JSON: {error}")))?;
        by_plugin.insert(entry.plugin_id.to_string(), results);
    }
    Ok(by_plugin)
}

/// The operating system and architecture the index names a target's builds by.
fn platform(target: &str) -> Result<(OperatingSystem, Architecture)> {
    Ok(match target {
        "aarch64-apple-darwin" => (OperatingSystem::MacOs, Architecture::Aarch64),
        "x86_64-apple-darwin" => (OperatingSystem::MacOs, Architecture::X86_64),
        "aarch64-unknown-linux-gnu" => (OperatingSystem::Linux, Architecture::Aarch64),
        "x86_64-unknown-linux-gnu" => (OperatingSystem::Linux, Architecture::X86_64),
        "aarch64-pc-windows-msvc" => (OperatingSystem::Windows, Architecture::Aarch64),
        "x86_64-pc-windows-msvc" => (OperatingSystem::Windows, Architecture::X86_64),
        other => refuse!("{other} is not a release target"),
    })
}
