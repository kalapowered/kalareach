//! The third-party notice a release carries.
//!
//! A release carries `share/THIRD-PARTY-NOTICES.txt`, the licences of the crates its programs and
//! its fish package are built from, and the release manifest lists it, so its signature covers it.
//! The checkout commits the text in `docs/releases/third-party-notices.txt`, which
//! `scripts/generate-notices.py` makes from `cargo-about`; a tree whose copy differs is refused.
//!
//! The generator and a release check both read the lock, and the lock names crates that no release
//! platform builds, such as the ones a dependency uses only on an operating system a release does not
//! target. So the committed text ends with a list of the crates the lock reaches from the release
//! programs that no platform's build uses, which the generator writes from `gaps`, and a text that
//! leaves any crate of that closure out of both its entries and that list is refused. A dependency
//! added to the lock fails the check until the notice is made again.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use toml_edit::{DocumentMut, Item};

use crate::pins::{Package, packages};
use crate::refusal::{Refusal, Result, read, read_json, read_text, refuse};

/// Where a release keeps the notice.
pub const FILE: &str = "share/THIRD-PARTY-NOTICES.txt";

/// Where the checkout commits the notice.
pub const COMMITTED: &str = "docs/releases/third-party-notices.txt";

/// Holds what a tree carries of the notice to what its checkout commits, and the committed text to
/// the lock.
///
/// # Errors
///
/// Returns a refusal when the tree has no notice or a different one, or when the committed text has
/// no entry for a crate that the lock takes into the release programs.
pub fn held(tree: &Path, checkout: &Path) -> Result<()> {
    let committed = read(&checkout.join(COMMITTED))?;
    let carried =
        read(&tree.join(FILE)).map_err(|_| Refusal(format!("the tree carries no {FILE}")))?;
    if carried != committed {
        refuse!("{FILE} is not the notice this checkout commits in {COMMITTED}");
    }
    let text =
        String::from_utf8(committed).map_err(|_| Refusal(format!("{COMMITTED} is not text")))?;
    let lacking = gaps(checkout, &text)?;
    if let Some(first) = lacking.first() {
        refuse!(
            "{COMMITTED} has no entry for {} of the crates the lock takes into the release \
             programs, the first {first}: `python3 scripts/generate-notices.py write` makes it again",
            lacking.len()
        );
    }
    Ok(())
}

/// The crates the lock reaches from the release programs, without a crate that only a package's
/// tests use, that `notice` names in no entry, each as `name version`, in order.
///
/// # Errors
///
/// Returns a refusal when a file it reads is missing or is not what it expects.
pub fn gaps(checkout: &Path, notice: &str) -> Result<Vec<String>> {
    let named: BTreeSet<(String, String)> = notice
        .lines()
        .filter_map(|line| line.strip_prefix("  - "))
        .filter_map(|entry| {
            let mut words = entry.split(" | ").next()?.split_whitespace();
            Some((words.next()?.to_owned(), words.next()?.to_owned()))
        })
        .collect();
    Ok(reached(checkout)?
        .into_iter()
        .filter(|crate_version| !named.contains(crate_version))
        .map(|(name, version)| format!("{name} {version}"))
        .collect())
}

/// What a package of the workspace depends on, by the name of the package each dependency is.
struct Wants {
    /// The names it builds with: normal, build and target-specific ones.
    built: BTreeSet<String>,
    /// The names its tests use.
    tested: BTreeSet<String>,
}

/// The name of the package a dependency entry stands for.
fn real_name(key: &str, item: &Item, renamed: &BTreeMap<String, String>) -> String {
    let Some(table) = item.as_table_like() else {
        return key.to_owned();
    };
    if let Some(name) = table.get("package").and_then(Item::as_str) {
        return name.to_owned();
    }
    if table.get("workspace").and_then(Item::as_bool) == Some(true) {
        return renamed.get(key).cloned().unwrap_or_else(|| key.to_owned());
    }
    key.to_owned()
}

/// The names under one kind of dependency table, in the manifest's own and in each target's.
fn names_under(
    document: &DocumentMut,
    kind: &str,
    renamed: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut tables = vec![document.get(kind)];
    if let Some(targets) = document.get("target").and_then(Item::as_table_like) {
        tables.extend(targets.iter().map(|(_, target)| target.get(kind)));
    }
    tables
        .into_iter()
        .flatten()
        .filter_map(Item::as_table_like)
        .flat_map(|table| {
            table
                .iter()
                .map(|(key, item)| real_name(key, item, renamed))
        })
        .collect()
}

/// For each package of the workspace, what it builds with and what only its tests use.
fn workspace_wants(checkout: &Path) -> Result<BTreeMap<String, Wants>> {
    let root = read_text(&checkout.join("Cargo.toml"))?
        .parse::<DocumentMut>()
        .map_err(|error| Refusal(format!("Cargo.toml is not TOML: {error}")))?;
    let workspace = root.get("workspace");
    let renamed: BTreeMap<String, String> = workspace
        .and_then(|table| table.get("dependencies"))
        .and_then(Item::as_table_like)
        .map(|table| {
            table
                .iter()
                .filter_map(|(key, item)| {
                    let name = item.as_table_like()?.get("package")?.as_str()?;
                    Some((key.to_owned(), name.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default();
    let Some(members) = workspace
        .and_then(|table| table.get("members"))
        .and_then(Item::as_array)
    else {
        refuse!("Cargo.toml names no workspace members");
    };
    let mut found = BTreeMap::new();
    for member in members.iter().filter_map(toml_edit::Value::as_str) {
        let path = checkout.join(member).join("Cargo.toml");
        let document = read_text(&path)?
            .parse::<DocumentMut>()
            .map_err(|error| Refusal(format!("{member}/Cargo.toml is not TOML: {error}")))?;
        let Some(name) = document
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(Item::as_str)
        else {
            continue;
        };
        let mut built = names_under(&document, "dependencies", &renamed);
        built.extend(names_under(&document, "build-dependencies", &renamed));
        let tested = names_under(&document, "dev-dependencies", &renamed);
        found.insert(name.to_owned(), Wants { built, tested });
    }
    Ok(found)
}

/// Which packages of the lock a dependency entry of the lock names: `name`, `name version` or
/// `name version (source)`.
fn named_by<'a>(entry: &str, all: &'a [Package]) -> impl Iterator<Item = usize> + 'a {
    let mut words = entry.split_whitespace();
    let name = words.next().unwrap_or_default().to_owned();
    let version = words.next().map(str::to_owned);
    all.iter()
        .enumerate()
        .filter(move |(_, package)| {
            package.name == name
                && version
                    .as_ref()
                    .is_none_or(|wanted| package.version == *wanted)
        })
        .map(|(index, _)| index)
}

/// Every package the lock takes from a registry or a repository into the release programs, as
/// `(name, version)`.
fn reached(checkout: &Path) -> Result<BTreeSet<(String, String)>> {
    let lock = read_text(&checkout.join("Cargo.lock"))?
        .parse::<DocumentMut>()
        .map_err(|error| Refusal(format!("Cargo.lock is not TOML: {error}")))?;
    let all = packages(&lock)?;
    let wants = workspace_wants(checkout)?;
    let listed = read_json(&checkout.join("scripts/release-programs.json"))?;
    let Some(programs) = listed["programs"].as_array() else {
        refuse!("scripts/release-programs.json lists no programs");
    };
    let mut stack = Vec::new();
    for program in programs {
        let Some(name) = program["package"].as_str() else {
            refuse!("scripts/release-programs.json lists a program with no package");
        };
        let roots: Vec<usize> = all
            .iter()
            .enumerate()
            .filter(|(_, package)| package.name == name && package.source.is_none())
            .map(|(index, _)| index)
            .collect();
        if roots.is_empty() {
            refuse!("the lock holds no package {name}, which scripts/release-programs.json builds");
        }
        stack.extend(roots);
    }
    let mut seen = vec![false; all.len()];
    while let Some(index) = stack.pop() {
        if std::mem::replace(&mut seen[index], true) {
            continue;
        }
        let package = &all[index];
        // The lock holds a workspace package's test dependencies beside the ones it builds with.
        let tests_only = |name: &str| {
            package.source.is_none()
                && wants.get(&package.name).is_some_and(|wanted| {
                    wanted.tested.contains(name) && !wanted.built.contains(name)
                })
        };
        for entry in &package.dependencies {
            let name = entry.split_whitespace().next().unwrap_or_default();
            if !tests_only(name) {
                stack.extend(named_by(entry, &all));
            }
        }
    }
    Ok(all
        .iter()
        .zip(seen)
        .filter(|(package, reached)| *reached && package.source.is_some())
        .map(|(package, _)| (package.name.clone(), package.version.clone()))
        .collect())
}
