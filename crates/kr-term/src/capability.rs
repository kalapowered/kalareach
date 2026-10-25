//! The terminal's capability manifest: which fixtures fix what the terminal does.
//!
//! The specification gives the manifest six things to own: sequence classes, terminfo, worker
//! responses, width, wrap and geometry, input encodings and renderer fixtures. [`CATEGORIES`] is
//! that list, each with the fixture files that pin it, and [`manifest`] is the document that names
//! those files by their SHA-256 digests. It is committed as `fixtures/terminal/capabilities.json`,
//! written and checked by `kr-term-fixtures`, and carried in a release tree as
//! `share/terminal-capabilities.json`, which the release manifest lists and its signature covers.
//!
//! A fixture file that no category owns is an error, so a file added to the fixtures has to be given
//! to one of the six things before it is committed, and a fixture that changes moves its digest
//! here, which the check and the release both see.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::conformance::hex;

/// Where the manifest lives, in the directory of the fixtures it names.
pub const FILE: &str = "capabilities.json";

/// The document's format.
pub const FORMAT: &str = "kalareach.terminal-capabilities/1";

/// One of the things the manifest owns.
#[derive(Debug, Clone, Copy)]
pub struct Category {
    /// The category's name in the manifest.
    pub name: &'static str,
    /// What it owns, in words.
    pub owns: &'static str,
    /// The fixture files that pin it, relative to the fixtures directory. A name ending in `/`
    /// stands for every JSON file below that directory.
    pub fixtures: &'static [&'static str],
}

/// The six things the specification gives the manifest.
///
/// A fixture may pin more than one: the profile lists both the identity bytes a worker answers with
/// and the input protocols it advertises, so it is under both.
pub const CATEGORIES: [Category; 6] = [
    Category {
        name: "sequence-classes",
        owns: "The class of every sequence, and what the byte policy does with raw C1 bytes, \
               malformed UTF-8, nested passthrough and oversized strings.",
        fixtures: &["classes.json", "byte-policy.json"],
    },
    Category {
        name: "terminfo",
        owns: "The pinned xterm-256color database, its compiled bytes, and the class every \
               advertised output capability lands in.",
        fixtures: &["terminfo-xterm-256color.json"],
    },
    Category {
        name: "worker-responses",
        owns: "Every query and the exact bytes the worker answers with, and the identity and \
               limits the profile states.",
        fixtures: &["broker.json", "profile.json"],
    },
    Category {
        name: "width-wrap-geometry",
        owns: "The width model, delayed wrap, scrolling at the margins and the geometries a \
               session is admitted at.",
        fixtures: &["width.json", "admission.json"],
    },
    Category {
        name: "input-encodings",
        owns: "The input protocols the profile advertises and the bytes each encodes a key as: \
               the console's key records, what the legacy spelling of them is for a session whose \
               backend did not ask for records, and the client's ordinary, modifyOtherKeys and \
               Kitty encodings.",
        fixtures: &[
            "profile.json",
            "input-encodings.json",
            "console-legacy-input.json",
            "client-encodings.json",
        ],
    },
    Category {
        name: "renderer-fixtures",
        owns: "The snapshots a reconnection restores, what the client renders from a projection, \
               and what physical terminals measured.",
        fixtures: &["snapshot.json", "projection.json", "physical/"],
    },
];

/// The JSON files below `directory`, as paths relative to it with `/` between the parts, sorted.
fn files_below(directory: &Path, within: &Path) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    let entries =
        std::fs::read_dir(within).map_err(|error| format!("{}: {error}", within.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", within.display()))?;
        let path: PathBuf = entry.path();
        if path.is_dir() {
            found.extend(files_below(directory, &path)?);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let relative = path
                .strip_prefix(directory)
                .unwrap_or(&path)
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            found.push(relative);
        }
    }
    found.sort();
    Ok(found)
}

/// The files a category names, with a directory expanded to the JSON files it holds.
fn named(directory: &Path, category: &Category) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    for fixture in category.fixtures {
        if fixture.ends_with('/') {
            let within = directory.join(fixture.trim_end_matches('/'));
            let mut below = files_below(directory, &within)?;
            if below.is_empty() {
                return Err(format!("{}: holds no fixture", within.display()));
            }
            files.append(&mut below);
        } else {
            files.push((*fixture).to_owned());
        }
    }
    Ok(files)
}

/// The manifest of the fixtures in `directory`: each category with the digest of each fixture it
/// owns.
///
/// # Errors
///
/// Returns the reason when a fixture a category names cannot be read.
pub fn manifest(directory: &Path) -> Result<Value, String> {
    let mut categories = Vec::with_capacity(CATEGORIES.len());
    for category in &CATEGORIES {
        let mut fixtures = Vec::new();
        for name in named(directory, category)? {
            let path = directory.join(&name);
            let bytes =
                std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            fixtures.push(json!({
                "path": name,
                "sha256": hex(&Sha256::digest(&bytes)),
            }));
        }
        categories.push(json!({
            "name": category.name,
            "owns": category.owns,
            "fixtures": fixtures,
        }));
    }
    Ok(json!({
        "format": FORMAT,
        "profile": "kr-vt/1",
        "categories": categories,
    }))
}

/// The manifest as the text that is committed and carried in a release.
#[must_use]
pub fn render(manifest: &Value) -> String {
    let mut text = serde_json::to_string_pretty(manifest).unwrap_or_default();
    text.push('\n');
    text
}

/// The fixture files in `directory` that no category owns, other than the manifest itself.
///
/// # Errors
///
/// Returns the reason when the directory cannot be read.
pub fn unowned(directory: &Path) -> Result<Vec<String>, String> {
    let mut owned = Vec::new();
    for category in &CATEGORIES {
        owned.extend(named(directory, category)?);
    }
    Ok(files_below(directory, directory)?
        .into_iter()
        .filter(|file| file != FILE && !owned.contains(file))
        .collect())
}
