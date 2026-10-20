//! The public contract: what a client of one release reads of a host of another.
//!
//! ```text
//! kr-protocol-gen --public-contract
//! ```
//!
//! The protocol package publishes every type of the schema, and a client built from one release of
//! it talks to a host of another across a level move: the public negotiation stays at major 1
//! while the package's minor number moves. So the commit being released is compared, over the whole
//! schema and with every definition a root, with the releases a client may have been built from,
//! and what an earlier reader could not read is reported:
//!
//! * a member that was added is not a difference where the earlier release's object carries the
//!   read-only metadata marker (`x-kalareach-read-only-metadata`), which makes its reader drop a
//!   member it does not know, and the member is optional;
//! * a definition that was added is not a difference;
//! * everything else is one: a member or a variant added to a closed object, a member, a variant
//!   or a definition removed, and anything that changed.
//!
//! Until public 1.0 freezes, which is the first client release (a host, command line, desktop or
//! mobile build published for people to install), the public contract may change with a level move,
//! and this reports and does not fail: the references are every release at the commit's level,
//! the excluded ones included. From the freeze, `crates/kr-protocol/retained/PUBLIC_FREEZE` names the
//! release the freeze was made at (`release=<tag>`), the references are that release and every
//! release after it that shares a public major that is not retired with the commit, and a
//! difference fails.
//!
//! It fails closed in both states when it cannot read what it compares: origin's tags, a release's
//! schema, the record of the freeze.

use std::collections::BTreeSet;
use std::path::Path;

use kr_protocol::retained::{Difference, DifferenceKind, differences};
use serde_json::Value;

use crate::excluded::Exclusions;
use crate::in_level::{Head, SCHEMA_PATH, cut_over};
use crate::releases::{
    Release, agree_with_origin, git_in, inventory, is_ancestor, package_version_at,
};
use crate::retained::expected_public_majors_in;

/// Where the freeze is recorded, from the root of the repository.
pub const FREEZE: &str = "crates/kr-protocol/retained/PUBLIC_FREEZE";

/// The keyword that makes an object's reader drop a member it does not know.
const READ_ONLY_METADATA: &str = "x-kalareach-read-only-metadata";

/// What the comparison found.
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    /// The release the freeze was made at, once public 1.0 is frozen.
    pub frozen_at: Option<String>,
    /// The releases compared.
    pub references: Vec<String>,
    /// For each release with a difference, the tag and each difference.
    pub differences: Vec<(String, Vec<String>)>,
}

/// Whether `difference` is one an earlier reader accepts: a definition that is new, or an optional
/// member that a read-only metadata object of the earlier release did not have.
fn accepted(old: &Value, new: &Value, difference: &Difference) -> bool {
    if difference.kind != DifferenceKind::Added {
        return false;
    }
    if difference.detail.starts_with("a root") {
        return true;
    }
    let Some((definition, member)) = difference.at.split_once('.') else {
        return false;
    };
    if member.contains(['.', '#', '[', '{']) {
        return false;
    }
    let marked = old["$defs"][definition]
        .get(READ_ONLY_METADATA)
        .and_then(Value::as_bool)
        == Some(true);
    let required = new["$defs"][definition]
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| required.iter().any(|name| name.as_str() == Some(member)));
    marked && !required
}

/// Compares the head's schema with one release's: each difference an earlier reader could not
/// read, as a line.
///
/// # Errors
///
/// When a schema cannot be cut.
pub fn compare(old: &Value, new: &Value) -> Result<Vec<String>, String> {
    let names = |schema: &Value| -> BTreeSet<String> {
        schema["$defs"]
            .as_object()
            .map(|definitions| definitions.keys().cloned().collect())
            .unwrap_or_default()
    };
    let roots: BTreeSet<String> = names(old).union(&names(new)).cloned().collect();
    let before = cut_over(old, &roots).map_err(|error| error.to_string())?;
    let after = cut_over(new, &roots).map_err(|error| error.to_string())?;
    Ok(differences(&before, &after)
        .iter()
        .filter(|difference| !accepted(old, new, difference))
        .map(ToString::to_string)
        .collect())
}

/// The non-retired public majors a record of the table lists.
fn live_majors(record: &str) -> BTreeSet<String> {
    record
        .lines()
        .filter(|line| line.starts_with("major=") && line.ends_with("retired=false"))
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// The release the freeze names, when there is a record of one.
///
/// # Errors
///
/// When the record is not `release=<tag>`, names a tag that is not a release here, or one that is
/// not in the history of `head`.
pub fn freeze(
    repository: &Path,
    head: &str,
    inventory: &[Release],
) -> Result<Option<Release>, String> {
    let path = repository.join(FREEZE);
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let tag = text
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| line.strip_prefix("release="))
        .collect::<Option<Vec<&str>>>()
        .filter(|lines| lines.len() == 1)
        .map(|lines| lines[0].trim())
        .ok_or_else(|| format!("{FREEZE} is not a single `release=<tag>` line"))?;
    let release = inventory
        .iter()
        .find(|release| release.tag == tag)
        .ok_or_else(|| format!("{FREEZE} names {tag}, which is not a release tag here"))?;
    if !is_ancestor(repository, &release.commit, head)? {
        return Err(format!(
            "{FREEZE} names {tag}, which is not in the history of {head}"
        ));
    }
    Ok(Some(release.clone()))
}

/// Compares `head` with the releases that make its public contract.
///
/// # Errors
///
/// When a record or a tree cannot be read.
pub fn report(
    repository: &Path,
    head: &Head,
    inventory: &[Release],
    frozen: Option<&Release>,
) -> Result<Report, String> {
    let head_majors = live_majors(&head.public_majors);
    let mut references = Vec::new();
    for release in inventory
        .iter()
        .filter(|release| release.commit != head.commit)
    {
        let referenced = match frozen {
            None => release.level() == head.level,
            Some(frozen) => {
                (release.commit == frozen.commit
                    || is_ancestor(repository, &frozen.commit, &release.commit)?)
                    && !live_majors(&expected_public_majors_in(repository, &release.commit)?)
                        .is_disjoint(&head_majors)
            }
        };
        if referenced {
            references.push(release);
        }
    }
    let mut found = Vec::new();
    for release in &references {
        let stated = package_version_at(repository, &release.commit)?;
        if stated != release.version {
            return Err(format!(
                "{} states {} and its commit's package is {stated}",
                release.tag, release.version
            ));
        }
        let text = git_in(
            repository,
            &["show", &format!("{}:{SCHEMA_PATH}", release.commit)],
        )
        .map_err(|error| format!("the schema of {} cannot be read: {error}", release.tag))?;
        let schema: Value = serde_json::from_str(&text)
            .map_err(|error| format!("the schema of {}: {error}", release.tag))?;
        let lines = compare(&schema, &head.schema)
            .map_err(|error| format!("the schema of {}: {error}", release.tag))?;
        if !lines.is_empty() {
            found.push((release.tag.clone(), lines));
        }
    }
    Ok(Report {
        frozen_at: frozen.map(|release| release.tag.clone()),
        references: references
            .iter()
            .map(|release| release.tag.clone())
            .collect(),
        differences: found,
    })
}

/// Runs the check for the commit at `HEAD` of the checkout at `repository`.
///
/// # Errors
///
/// When it cannot read what it compares, and, once public 1.0 is frozen, on a difference.
pub fn run(repository: &Path) -> Result<(), String> {
    let commit = git_in(repository, &["rev-parse", "--verify", "HEAD^{commit}"])?
        .trim()
        .to_owned();
    let releases = inventory(repository)?;
    agree_with_origin(repository, &releases, &commit)?;
    Exclusions::read(repository)?.validate(repository, &releases)?;
    let head = Head::of_this_build(repository, &commit)?;
    let frozen = freeze(repository, &commit, &releases)?;
    let report = report(repository, &head, &releases, frozen.as_ref())?;
    conclude(&report)
}

/// What the report comes to: printed, and a failure from the freeze on.
///
/// # Errors
///
/// When public 1.0 is frozen and a release's reader cannot read what the commit writes.
pub fn conclude(report: &Report) -> Result<(), String> {
    for (tag, lines) in &report.differences {
        println!(
            "{tag}: a client built from it cannot read what this commit writes:\n  {}",
            lines.join("\n  ")
        );
    }
    match (&report.frozen_at, report.differences.is_empty()) {
        (_, true) => {
            println!(
                "the public contract holds against {} release(s)",
                report.references.len()
            );
            Ok(())
        }
        (None, false) => {
            println!(
                "{} release(s) differ; public 1.0 is not frozen until the first client release, \
                 so this reports and does not fail",
                report.differences.len()
            );
            Ok(())
        }
        (Some(tag), false) => Err(format!(
            "public 1.0 is frozen at {tag} and {} release(s) differ",
            report.differences.len()
        )),
    }
}
