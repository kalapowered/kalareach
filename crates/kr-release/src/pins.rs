//! The cryptographic libraries a release is built with, as the lock resolved them.
//!
//! The release manifest pins eight libraries by exact version, with the graph each resolved to and
//! the vectors the pairing profile is held to. They are read from the workspace's own `Cargo.toml`
//! and `Cargo.lock`, never typed in a second place, and the documents that name them must say the
//! same versions: a pin that moves without its documents is refused.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use kr_protocol::update::{PinnedCrate, ReleaseDependencies, ReleaseSource, ResolvedCrate};
use toml_edit::{DocumentMut, Item};

use crate::refusal::{Refusal, Result, digest, digest_file, read, read_text, refuse, scalar};

/// The libraries a release pins: the crates that carry a key, a secret or a proof.
pub const PINNED: [&str; 8] = [
    "libsodium-sys-stable",
    "hkdf",
    "hmac",
    "sha2",
    "subtle",
    "zeroize",
    "keyring",
    "spake2",
];

/// One package of the lock.
struct Package {
    name: String,
    version: String,
    checksum: Option<String>,
    dependencies: Vec<String>,
}

/// The pins, their resolved graphs and the vectors, held to the documents that name them.
///
/// # Errors
///
/// Returns a refusal for a library that is not pinned to one exact version, that the lock resolves
/// to another version or without a checksum, or that a document names at another version.
pub fn dependencies(checkout: &Path) -> Result<ReleaseDependencies> {
    let manifest = read_text(&checkout.join("Cargo.toml"))?
        .parse::<DocumentMut>()
        .map_err(|error| Refusal(format!("Cargo.toml is not TOML: {error}")))?;
    let lock_bytes = read(&checkout.join("Cargo.lock"))?;
    let lock = String::from_utf8(lock_bytes.clone())
        .map_err(|_| Refusal("Cargo.lock is not text".to_owned()))?
        .parse::<DocumentMut>()
        .map_err(|error| Refusal(format!("Cargo.lock is not TOML: {error}")))?;
    let packages = packages(&lock)?;

    let mut documented = documented_versions(checkout)?;
    let mut pinned = Vec::new();
    for name in PINNED {
        let version = pinned_version(&manifest, name)?;
        match documented.remove(name) {
            Some(documents) if documents.iter().all(|stated| *stated == version) => {}
            Some(documents) => refuse!(
                "Cargo.toml pins {name} at {version}, and a document says {}",
                documents.join(", ")
            ),
            None => refuse!("no document says which version of {name} the release pins"),
        }
        let Some(package) = packages
            .iter()
            .find(|package| package.name == name && package.version == version)
        else {
            refuse!("Cargo.lock resolves {name} to no package at {version}");
        };
        let Some(checksum) = package.checksum.clone() else {
            refuse!("Cargo.lock holds no checksum for {name} {version}");
        };
        pinned.push(PinnedCrate {
            name: name.to_owned(),
            version,
            checksum,
            resolved: closure(&packages, package)?,
        });
    }

    let mut vectors = Vec::new();
    let directory = checkout.join("fixtures/pairing");
    let mut files: Vec<_> = std::fs::read_dir(&directory)
        .map_err(|error| crate::refusal::unreadable(&directory, &error))?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".json"))
        .collect();
    files.sort();
    for file in files {
        vectors.push(ReleaseSource {
            sha256: scalar(digest_file(&directory.join(&file))?),
            file: format!("fixtures/pairing/{file}"),
        });
    }
    if vectors.is_empty() {
        refuse!("fixtures/pairing holds no vectors");
    }
    Ok(ReleaseDependencies {
        lock_sha256: scalar(digest(&lock_bytes)),
        pinned,
        vectors,
    })
}

/// The exact version the workspace pins `name` to.
fn pinned_version(manifest: &DocumentMut, name: &str) -> Result<String> {
    let entry = manifest["workspace"]["dependencies"]
        .get(name)
        .ok_or_else(|| Refusal(format!("Cargo.toml has no workspace dependency {name}")))?;
    let requirement = match entry {
        Item::Value(toml_edit::Value::String(version)) => version.value().clone(),
        Item::Value(toml_edit::Value::InlineTable(table)) => table
            .get("version")
            .and_then(toml_edit::Value::as_str)
            .map(str::to_owned)
            .unwrap_or_default(),
        _ => String::new(),
    };
    match requirement.strip_prefix('=') {
        Some(version) if !version.is_empty() => Ok(version.to_owned()),
        _ => refuse!("{name} is not pinned to one exact version in Cargo.toml (`{requirement}`)"),
    }
}

/// The versions the documents name for each pinned library.
///
/// The cryptography reference lists them in a table under "Release manifest", and the pairing
/// reference names the PAKE's.
fn documented_versions(checkout: &Path) -> Result<BTreeMap<String, Vec<String>>> {
    let mut stated: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let crypto = read_text(&checkout.join("docs/crypto/README.md"))?;
    let mut inside = false;
    for line in crypto.lines() {
        if line.starts_with("## ") {
            inside = line == "## Release manifest";
            continue;
        }
        if !inside {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if let [_, name, version, _] = cells.as_slice()
            && let Some(name) = name
                .strip_prefix('`')
                .and_then(|rest| rest.strip_suffix('`'))
            && PINNED.contains(&name)
        {
            stated
                .entry(name.to_owned())
                .or_default()
                .push((*version).to_owned());
        }
    }
    let pairing = read_text(&checkout.join("docs/pairing/README.md"))?;
    for line in pairing.lines() {
        if let Some(rest) = line.strip_prefix("Pin `spake2` ") {
            let version: String = rest
                .chars()
                .take_while(|character| character.is_ascii_digit() || *character == '.')
                .collect();
            stated
                .entry("spake2".to_owned())
                .or_default()
                .push(version.trim_end_matches('.').to_owned());
        }
    }
    Ok(stated)
}

fn packages(lock: &DocumentMut) -> Result<Vec<Package>> {
    let Some(array) = lock.get("package").and_then(Item::as_array_of_tables) else {
        refuse!("Cargo.lock lists no packages");
    };
    let text = |table: &toml_edit::Table, key: &str| {
        table.get(key).and_then(Item::as_str).map(str::to_owned)
    };
    let mut found = Vec::new();
    for table in array {
        let (Some(name), Some(version)) = (text(table, "name"), text(table, "version")) else {
            refuse!("Cargo.lock holds a package with no name or version");
        };
        found.push(Package {
            name,
            version,
            checksum: text(table, "checksum"),
            dependencies: table
                .get("dependencies")
                .and_then(Item::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(toml_edit::Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    Ok(found)
}

/// Every crate a package resolves to, itself excluded, sorted.
fn closure(packages: &[Package], root: &Package) -> Result<Vec<ResolvedCrate>> {
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    seen.insert((root.name.clone(), root.version.clone()));
    let mut queue = VecDeque::from([root]);
    let mut resolved = Vec::new();
    while let Some(package) = queue.pop_front() {
        for dependency in &package.dependencies {
            let mut parts = dependency.split_whitespace();
            let (Some(name), version) = (parts.next(), parts.next()) else {
                continue;
            };
            let mut matches = packages.iter().filter(|candidate| {
                candidate.name == name && version.is_none_or(|v| candidate.version == v)
            });
            let (Some(found), None) = (matches.next(), matches.next()) else {
                refuse!("Cargo.lock names {dependency} and resolves it to no single package");
            };
            if seen.insert((found.name.clone(), found.version.clone())) {
                let Some(checksum) = found.checksum.clone() else {
                    refuse!(
                        "{} {} is in the graph of {} and has no registry checksum",
                        found.name,
                        found.version,
                        root.name
                    );
                };
                resolved.push(ResolvedCrate {
                    name: found.name.clone(),
                    version: found.version.clone(),
                    checksum,
                });
                queue.push_back(found);
            }
        }
    }
    resolved.sort_by(|first, second| {
        (&first.name, &first.version).cmp(&(&second.name, &second.version))
    });
    Ok(resolved)
}
