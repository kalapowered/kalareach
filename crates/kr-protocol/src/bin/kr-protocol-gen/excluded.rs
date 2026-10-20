//! The releases a level's contract does not cover: a closed record of two early 0.76.0 releases.
//!
//! A level is one surface, and the first release of a level fixes it. The level 0.76 was released
//! before every member it now has was in, so two of its releases speak a surface the level does not.
//! They stay published, since a published release stays where it is, and
//! `crates/kr-protocol/retained/EXCLUDED` names them, each with the commit, the level and the
//! digest of the surface its own schema has, and why. Release selection, the cut's comparison, the
//! in-level check and the upgrade suite skip a release the record names.
//!
//! The record is closed: it names the two tags in [`CLOSED`] and no other, so a later release
//! cannot be excluded by adding a block. Remove it, with this reader and everything that calls
//! it, at the 0.78 cut, which retains 0.77 and leaves nothing that talks to a 0.76 worker.
//!
//! This file is also read by the `kr-cli` upgrade suite, which chooses the release it updates from
//! the same selection, so it uses nothing but the standard library, `serde_json`, `kr_cbor` and
//! `kr_protocol`, and names its sibling modules as `crate::<module>`.

use std::path::Path;

use kr_protocol::retained::Surface;
use kr_protocol::update::CompatibilityLevel;

use crate::releases::{Release, git_in, is_ancestor, surface_roots_at};

/// Where the record is, from the root of the repository.
pub const RECORD: &str = "crates/kr-protocol/retained/EXCLUDED";

/// The releases the record names, and no others, in the order of their names.
pub const CLOSED: [&str; 2] = [
    "packages/v0.76.0+53a2e0be5111",
    "packages/v0.76.0+d3a552aa2ea6",
];

/// One excluded release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Excluded {
    /// The tag, `packages/v<version>+<commit>`.
    pub tag: String,
    /// The full commit the tag points at.
    pub commit: String,
    /// The level the release is at.
    pub level: CompatibilityLevel,
    /// The sha256, in lowercase hexadecimal, of the surface cut from the release's own schema with
    /// the roots its own source declares ([`surface_digest`]).
    pub surface: String,
    /// Why the release is excluded.
    pub why: String,
}

/// The excluded releases.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exclusions {
    entries: Vec<Excluded>,
}

impl Exclusions {
    /// No release excluded.
    #[cfg(test)]
    pub fn none() -> Self {
        Self::default()
    }

    /// Reads the record as a checkout has it, and holds it to [`CLOSED`].
    ///
    /// # Errors
    ///
    /// When the file cannot be read, is malformed, or does not name exactly the closed set.
    pub fn read(repository: &Path) -> Result<Self, String> {
        let path = repository.join(RECORD);
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let exclusions = Self::parse(&text).map_err(|error| format!("{RECORD}: {error}"))?;
        let mut named: Vec<&str> = exclusions.entries.iter().map(|e| e.tag.as_str()).collect();
        named.sort_unstable();
        if named != CLOSED {
            return Err(format!(
                "{RECORD} names {named:?}, and the record is closed to {CLOSED:?}"
            ));
        }
        Ok(exclusions)
    }

    /// Reads a record's text: `#` comments, and blocks of `name=value` lines (`tag`, `commit`,
    /// `level`, `surface`, `why`, each once) separated by blank lines.
    ///
    /// # Errors
    ///
    /// For a line that is neither, a field that is unknown, missing or twice, a value that is
    /// not what its field holds, and a tag named twice.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut blocks: Vec<Vec<(&str, &str)>> = vec![Vec::new()];
        for (number, line) in text.lines().enumerate() {
            let at = number + 1;
            if line.trim().is_empty() {
                if blocks.last().is_some_and(|block| !block.is_empty()) {
                    blocks.push(Vec::new());
                }
            } else if line.starts_with('#') {
            } else {
                let (name, value) = line
                    .split_once('=')
                    .ok_or_else(|| format!("line {at} is not `name=value`: {line}"))?;
                blocks
                    .last_mut()
                    .expect("a block is open")
                    .push((name, value.trim()));
            }
        }
        let mut entries: Vec<Excluded> = Vec::new();
        for block in blocks.iter().filter(|block| !block.is_empty()) {
            let entry = entry_of(block)?;
            if entries.iter().any(|kept| kept.tag == entry.tag) {
                return Err(format!("{} is named twice", entry.tag));
            }
            entries.push(entry);
        }
        if entries.is_empty() {
            return Err("the record names no release".to_owned());
        }
        Ok(Self { entries })
    }

    /// Whether the record names `tag`.
    pub fn contains(&self, tag: &str) -> bool {
        self.entries.iter().any(|entry| entry.tag == tag)
    }

    /// The excluded releases.
    pub fn entries(&self) -> &[Excluded] {
        &self.entries
    }

    /// Holds the record to the repository: each tag is a release this checkout has, at the commit
    /// and the level the record says, with the surface digest its own schema gives; the level has a
    /// release that is not excluded; and every such release is in the history of no excluded one.
    ///
    /// # Errors
    ///
    /// The first thing that does not hold.
    pub fn validate(&self, repository: &Path, inventory: &[Release]) -> Result<(), String> {
        for entry in &self.entries {
            let release = inventory
                .iter()
                .find(|release| release.tag == entry.tag)
                .ok_or_else(|| {
                    format!(
                        "{} names {}, which is not a release tag here",
                        RECORD, entry.tag
                    )
                })?;
            if release.commit != entry.commit {
                return Err(format!(
                    "{RECORD} says {} is at {}, and the tag points at {}",
                    entry.tag, entry.commit, release.commit
                ));
            }
            if release.level() != entry.level {
                return Err(format!(
                    "{RECORD} says {} is at level {}, and the tag is at level {}",
                    entry.tag,
                    entry.level,
                    release.level()
                ));
            }
            let digest = surface_digest(repository, &entry.commit)?;
            if digest != entry.surface {
                return Err(format!(
                    "{RECORD} gives {} the surface digest {}, and its own schema gives {digest}",
                    entry.tag, entry.surface
                ));
            }
            let kept: Vec<&Release> = inventory
                .iter()
                .filter(|other| other.level() == entry.level && !self.contains(&other.tag))
                .collect();
            if kept.is_empty() {
                return Err(format!(
                    "{RECORD} excludes {}, and level {} has no release that is not excluded",
                    entry.tag, entry.level
                ));
            }
            for other in kept {
                if !is_ancestor(repository, &entry.commit, &other.commit)? {
                    return Err(format!(
                        "{} is excluded and is not in the history of {}, a release of its level \
                         that is not: an excluded release is older than every kept one",
                        entry.tag, other.tag
                    ));
                }
            }
        }
        Ok(())
    }
}

fn entry_of(block: &[(&str, &str)]) -> Result<Excluded, String> {
    let mut tag = None;
    let mut commit = None;
    let mut level = None;
    let mut surface = None;
    let mut why = None;
    for (name, value) in block {
        let slot = match *name {
            "tag" => &mut tag,
            "commit" => &mut commit,
            "level" => &mut level,
            "surface" => &mut surface,
            "why" => &mut why,
            other => return Err(format!("a field the record does not have: {other}")),
        };
        if slot.replace((*value).to_owned()).is_some() {
            return Err(format!("the field {name} is given twice in one block"));
        }
    }
    let field = |name: &str, value: Option<String>| {
        value
            .filter(|text| !text.is_empty())
            .ok_or_else(|| format!("a block has no {name}"))
    };
    let tag = field("tag", tag)?;
    let commit = field("commit", commit)?;
    let level = field("level", level)?;
    let surface = field("surface", surface)?;
    let why = field("why", why)?;
    if !tag.starts_with("packages/v") {
        return Err(format!("{tag} is not a release tag"));
    }
    let hexadecimal = |text: &str, length: usize| {
        text.len() == length
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if !hexadecimal(&commit, 40) {
        return Err(format!(
            "{tag}: the commit is not 40 lowercase hexadecimal characters"
        ));
    }
    if !hexadecimal(&surface, 64) {
        return Err(format!(
            "{tag}: the surface is not 64 lowercase hexadecimal characters"
        ));
    }
    let level: CompatibilityLevel = level
        .parse()
        .map_err(|error| format!("{tag}: the level: {error}"))?;
    Ok(Excluded {
        tag,
        commit,
        level,
        surface,
        why,
    })
}

/// The digest of a release's surface: the sha256, in lowercase hexadecimal, of the surface cut from
/// the schema that release committed with the roots its own source declares, as it is rendered.
/// Taken over that release's own roots, it does not move when a later release changes the list.
///
/// # Errors
///
/// When the schema or the list of roots cannot be read at the commit.
pub fn surface_digest(repository: &Path, commit: &str) -> Result<String, String> {
    let text = git_in(
        repository,
        &[
            "show",
            &format!("{commit}:packages/protocol/schema/kalareach-protocol.schema.json"),
        ],
    )?;
    let schema: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| format!("the schema at {commit}: {error}"))?;
    let roots = surface_roots_at(repository, commit)?.ok_or_else(|| {
        format!("{commit} has no crates/kr-protocol/src/retained.rs to read SURFACE_ROOTS from")
    })?;
    let roots: Vec<&str> = roots.iter().map(String::as_str).collect();
    let surface = Surface::cut(&schema, &roots).map_err(|error| format!("{commit}: {error}"))?;
    Ok(kr_cbor::sha256(surface.render().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// The releases of `level` that are not excluded, leaving out the one at `except`, in the order of
/// their tags.
pub fn kept(
    inventory: &[Release],
    level: CompatibilityLevel,
    excluded: &Exclusions,
    except: &str,
) -> Vec<Release> {
    inventory
        .iter()
        .filter(|release| {
            release.level() == level && release.commit != except && !excluded.contains(&release.tag)
        })
        .cloned()
        .collect()
}
