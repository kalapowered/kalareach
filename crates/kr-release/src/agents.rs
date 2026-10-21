//! The executable builds of the supported agents a release is qualified against.
//!
//! The signed plugin index at the pinned commit names, for an entry whose record passed every part
//! of the version qualification, each executable build by application, distribution, version,
//! operating system, architecture and digest. A release lists the builds for its own platform with
//! the capabilities the entry declares: a named build opens every capability its release declares.
//! The index names none today, and the release lists none.

use std::path::Path;

use kr_protocol::update::ReleaseAgent;
use serde::Deserialize;

use crate::refusal::{
    Refusal, Result, digest_file, digest_from_hex, hex, read_json, refuse, scalar,
};

#[derive(Deserialize)]
struct Index {
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    plugin_id: String,
    version: String,
    #[serde(default)]
    capabilities: Vec<Capability>,
    #[serde(default)]
    builds: Vec<Build>,
    #[serde(default)]
    qualification: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct Capability {
    capability: String,
}

#[derive(Deserialize)]
struct Build {
    application: String,
    distribution: String,
    version: String,
    os: String,
    architecture: String,
    executable_digest: String,
}

/// The builds the bundled index names for `target`, each with its entry's capabilities.
///
/// # Errors
///
/// Returns a refusal when the index is not the one the bundled metadata pins, or names a build
/// whose digest is not a SHA-256 digest.
pub fn agents(checkout: &Path, target: &str) -> Result<Vec<ReleaseAgent>> {
    let (os, architecture) = platform(target)?;
    let index_path = checkout.join("bundled-plugins/targets/index.json");
    let targets = read_json(&checkout.join("bundled-plugins/metadata/targets.json"))?;
    let pinned = targets["signed"]["targets"]["index.json"]["hashes"]["sha256"]
        .as_str()
        .ok_or_else(|| Refusal("the bundled targets metadata pins no index".to_owned()))?;
    if hex(&digest_file(&index_path)?) != pinned {
        refuse!("bundled-plugins/targets/index.json is not the index the bundled metadata pins");
    }
    let index: Index = serde_json::from_value(read_json(&index_path)?)
        .map_err(|error| Refusal(format!("the bundled index is not an index: {error}")))?;
    let mut agents = Vec::new();
    for entry in index.entries {
        let capabilities: Vec<String> = entry
            .capabilities
            .into_iter()
            .map(|capability| capability.capability)
            .collect();
        for build in entry.builds {
            if build.os != os || build.architecture != architecture {
                continue;
            }
            agents.push(ReleaseAgent {
                plugin: entry.plugin_id.clone(),
                plugin_version: entry.version.clone(),
                application: build.application,
                distribution: build.distribution,
                version: build.version,
                os: build.os,
                architecture: build.architecture,
                sha256: scalar(digest_from_hex(&build.executable_digest)?),
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

/// The qualification records each plugin of the bundled index cites, by plugin.
///
/// # Errors
///
/// Returns a refusal when the index cannot be read.
pub fn qualifications(
    checkout: &Path,
) -> Result<std::collections::BTreeMap<String, Vec<serde_json::Value>>> {
    let index: Index = serde_json::from_value(read_json(
        &checkout.join("bundled-plugins/targets/index.json"),
    )?)
    .map_err(|error| Refusal(format!("the bundled index is not an index: {error}")))?;
    Ok(index
        .entries
        .into_iter()
        .map(|entry| (entry.plugin_id, entry.qualification))
        .collect())
}

/// The operating system and architecture the index names a target's builds by.
fn platform(target: &str) -> Result<(&'static str, &'static str)> {
    Ok(match target {
        "aarch64-apple-darwin" => ("mac_os", "aarch64"),
        "x86_64-apple-darwin" => ("mac_os", "x86_64"),
        "aarch64-unknown-linux-gnu" => ("linux", "aarch64"),
        "x86_64-unknown-linux-gnu" => ("linux", "x86_64"),
        "aarch64-pc-windows-msvc" => ("windows", "aarch64"),
        "x86_64-pc-windows-msvc" => ("windows", "x86_64"),
        other => refuse!("{other} is not a release target"),
    })
}
