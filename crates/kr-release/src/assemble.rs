//! A release's manifest, assembled from its tree and the repository it was built from.
//!
//! Nothing here is typed in a second place. The protocol, the public majors and the compatibility
//! levels are the ones the tool was built with, which is the commit the release is made from; the
//! stores come from the lock that holds every store a program reads; the shell packages are read
//! from the tree and held to the repository's pins; the agent builds come from the bundled signed
//! index; the cryptographic pins come from the lock. A tree that disagrees with any of them is
//! refused here, before the manifest exists to be signed.

use std::path::{Path, PathBuf};

use kr_protocol::hello::{PACKAGE_VERSION, PUBLIC_MAJORS};
use kr_protocol::retained;
use kr_protocol::scalars::U64;
use kr_protocol::update::{
    CommitId, FileMode, ManifestKind, OsFloor, ReleaseFile, ReleaseManifest, ReleaseName,
    ReleasePath, ReleaseStore, required_programs,
};

use crate::refusal::{Refusal, Result, read_json, refuse, scalar};
use crate::{agents, pins, shells, tree};

/// Where a release keeps the update channel's root.
pub const CHANNEL_ROOT: &str = "share/update-root.json";

/// What a release is, apart from what its tree holds.
pub struct Inputs {
    /// The tree: `bin/`, `shells/` and `share/`.
    pub tree: PathBuf,
    /// The repository checkout the release is built from.
    pub checkout: PathBuf,
    /// The release.
    pub release: ReleaseName,
    /// Where it stands among releases.
    pub sequence: u64,
    /// The commit it was built from.
    pub commit: CommitId,
    /// The target it was built for.
    pub target: String,
    /// The oldest operating system it runs on.
    pub os_floor: OsFloor,
}

/// Assembles the manifest of a tree.
///
/// # Errors
///
/// Returns a refusal naming the first thing the tree disagrees with: a program it lacks, a file
/// that is not a regular file, a shell package that is not the repository's pins, or a pin that
/// the documents do not state.
pub fn assemble(inputs: &Inputs) -> Result<ReleaseManifest> {
    let listed = tree::files(&inputs.tree, &inputs.target)?;
    let mut files = Vec::with_capacity(listed.len());
    for file in &listed {
        files.push(ReleaseFile {
            path: ReleasePath::new(file.path.clone()).map_err(|error| {
                Refusal(format!("{} cannot be in a release: {error}", file.path))
            })?,
            length: U64::new(file.length),
            sha256: scalar(file.sha256),
            mode: if file.executable {
                FileMode::Executable
            } else {
                FileMode::Regular
            },
        });
    }
    let suffix = if inputs.target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let missing: Vec<String> = required_programs(&inputs.target)
        .map(|program| format!("bin/{program}{suffix}"))
        .filter(|path| {
            !listed
                .iter()
                .any(|file| file.path == *path && file.executable)
        })
        .collect();
    if !missing.is_empty() {
        refuse!("the tree lacks the programs {}", missing.join(", "));
    }
    for required in [CHANNEL_ROOT, crate::record::FILE] {
        if !listed.iter().any(|file| file.path == required) {
            refuse!("the tree carries no {required}");
        }
    }

    let manifest = ReleaseManifest {
        kind: ManifestKind::Release,
        release: inputs.release.clone(),
        sequence: U64::new(inputs.sequence),
        commit: inputs.commit.clone(),
        target: inputs.target.clone(),
        os_floor: inputs.os_floor,
        protocol_version: PACKAGE_VERSION,
        public_majors: PUBLIC_MAJORS
            .iter()
            .filter(|row| !row.retired)
            .map(|row| row.major)
            .collect(),
        retained_levels: retained::levels(),
        shells: shells::packages(&inputs.tree, &inputs.checkout, &inputs.target)?,
        agents: agents::agents(&inputs.checkout, &inputs.target)?,
        dependencies: Some(pins::dependencies(&inputs.checkout)?),
        stores: stores(&inputs.checkout)?,
        files,
    };
    manifest
        .check()
        .map_err(|error| Refusal(format!("the manifest cannot be a release's: {error}")))?;
    Ok(manifest)
}

/// Every store the programs read, from the lock that holds them.
fn stores(checkout: &Path) -> Result<Vec<ReleaseStore>> {
    let lock = read_json(&checkout.join("stored-formats.lock"))?;
    let Some(entries) = lock["stores"].as_array() else {
        refuse!("stored-formats.lock lists no stores");
    };
    entries
        .iter()
        .map(|store| {
            serde_json::from_value(store["entry"].clone())
                .map_err(|error| Refusal(format!("a store of stored-formats.lock: {error}")))
        })
        .collect()
}

/// Holds a tree to a manifest: every file it lists is there with its length and digest, and nothing
/// the manifest does not list is.
///
/// # Errors
///
/// Returns a refusal counting the files that differ, are missing or are not listed.
pub fn check_files(tree: &Path, manifest: &ReleaseManifest) -> Result<()> {
    let present = tree::files(tree, &manifest.target)?;
    let mut differing = 0_usize;
    let mut missing = 0_usize;
    for file in &manifest.files {
        match present
            .iter()
            .find(|found| found.path == file.path.as_str())
        {
            Some(found)
                if found.length == file.length.get()
                    && scalar(found.sha256) == file.sha256
                    && (found.executable == (file.mode == FileMode::Executable)) => {}
            Some(_) => differing += 1,
            None => missing += 1,
        }
    }
    let unlisted = present
        .iter()
        .filter(|found| {
            !manifest
                .files
                .iter()
                .any(|file| file.path.as_str() == found.path)
        })
        .count();
    if differing + missing + unlisted > 0 {
        refuse!(
            "the tree is not what its manifest says: {differing} of its files differ, {missing} \
             listed are missing and {unlisted} are not listed"
        );
    }
    Ok(())
}
