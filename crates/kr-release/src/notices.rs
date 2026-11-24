//! The third-party notice a release carries.
//!
//! A release carries `share/THIRD-PARTY-NOTICES.txt`, the licences of the crates its programs and
//! its fish package are built from, and the release manifest lists it, so its signature covers it.
//! The checkout commits the text in `docs/releases/third-party-notices.txt`, which
//! `scripts/generate-notices.py` makes from `cargo-about`; a tree whose copy differs is refused.
//!
//! The generator knows which crates a release build compiles in, because it asks `cargo tree` for
//! the packages and platforms a release is built for. This check reads only the lock, and the lock
//! names crates that no release build compiles, such as the ones a dependency uses only on an
//! operating system a release does not target, or only for its own tests. So the committed text
//! ends with a list of the crates the lock reaches from the release programs that no build
//! compiles, which the generator writes from `gaps`, and a text that leaves any crate of that
//! closure out of both its entries and that list is refused. A dependency added to the lock fails
//! the check until the notice is made again. A text that still holds the placeholder of a licence
//! template, where a crate's copyright line belongs, is refused too.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use toml_edit::{DocumentMut, Item};

use crate::pins::{Package, packages};
use crate::refusal::{Refusal, Result, read, read_json, read_text, refuse};

/// Where a release keeps the notice.
pub const FILE: &str = "share/THIRD-PARTY-NOTICES.txt";

/// Where the checkout commits the notice.
pub const COMMITTED: &str = "docs/releases/third-party-notices.txt";

/// Where the checkout commits the companion application's notice, which its installers and store
/// bundles carry.
pub const COMPANION_COMMITTED: &str = "docs/releases/companion-third-party-notices.txt";

/// What a notice covers, and so which packages the lock is read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Product {
    /// The release programs and the fish package, which a release archive carries.
    Programs,
    /// The companion application.
    Companion,
}

/// What the permissive licence templates of the SPDX list hold where the owner's copyright line
/// belongs, in lower case. The GPL's own text has `<year>` and `<name of author>` in the paragraph
/// that tells a program how to apply it, so those two are not in the list.
const PLACEHOLDERS: [&str; 9] = [
    "<owner>",
    "<copyright holder>",
    "<copyright holders>",
    "<organization>",
    "<organisation>",
    "<owner organization name>",
    "<owner organisation name>",
    "[year]",
    "[fullname]",
];

/// What a person does when the committed companion text is not the one the lock makes.
const COMPANION_REPAIR: &str = "install the production packages with `pnpm install --frozen-lockfile \
     --prod --filter \"@kalareach/companion...\"`, build kr-release with `cargo build -p kr-release`, \
     run `python3 scripts/generate-notices.py write --product companion --kr-release \
     target/debug/kr-release`, and commit the result";

/// What a person does when the committed text is not the one the lock makes.
const REPAIR: &str = "build kr-release with `cargo build -p kr-release`, fetch the crates with \
     `cargo fetch --locked`, put cargo-about 0.9.3 and askalono 0.5.0 on the PATH, run \
     `python3 scripts/generate-notices.py write --kr-release target/debug/kr-release`, and commit \
     the result";

/// What names a crate in the lock and in the notice: its name, its version and the Git repository
/// it comes from, which crates.io crates do not have. A repository and a registry can offer the
/// same name and version, and the notice has to carry the text of each.
type Identity = (String, String, Option<String>);

/// The address of the crates.io page an entry of a registry crate names as its source.
const REGISTRY_PAGE: &str = "https://crates.io/crates/";

/// Holds what a tree carries of the notice to what its checkout commits, and the committed text to
/// the lock.
///
/// # Errors
///
/// Returns a refusal when the tree has no notice or a different one, when the committed text holds
/// a licence template's placeholder, or when it has no entry for a crate that the lock takes into
/// the release programs.
pub fn held(tree: &Path, checkout: &Path) -> Result<()> {
    let committed = read(&checkout.join(COMMITTED))?;
    let carried =
        read(&tree.join(FILE)).map_err(|_| Refusal(format!("the tree carries no {FILE}")))?;
    if carried != committed {
        refuse!("{FILE} is not the notice this checkout commits in {COMMITTED}");
    }
    let text =
        String::from_utf8(committed).map_err(|_| Refusal(format!("{COMMITTED} is not text")))?;
    let lower = text.to_lowercase();
    if let Some(found) = PLACEHOLDERS.iter().find(|word| lower.contains(**word)) {
        refuse!(
            "{COMMITTED} holds {found}, the placeholder of a licence template, where the crate's \
             own copyright line belongs: {REPAIR}"
        );
    }
    let lacking = gaps(checkout, &text, Product::Programs)?;
    if let Some(first) = lacking.first() {
        refuse!(
            "{COMMITTED} has no entry for {} of the crates the lock takes into the release \
             programs, the first {first}: {REPAIR}",
            lacking.len()
        );
    }
    Ok(())
}

/// Holds the companion's committed notice to the lock: it holds no licence template's placeholder
/// and has an entry for every crate the lock takes into the companion application.
///
/// # Errors
///
/// Returns a refusal when the committed text is missing or is not text, holds a placeholder, or has
/// no entry for a crate that the lock takes into the companion.
pub fn held_companion(checkout: &Path) -> Result<()> {
    let text = String::from_utf8(read(&checkout.join(COMPANION_COMMITTED))?)
        .map_err(|_| Refusal(format!("{COMPANION_COMMITTED} is not text")))?;
    let lower = text.to_lowercase();
    if let Some(found) = PLACEHOLDERS.iter().find(|word| lower.contains(**word)) {
        refuse!(
            "{COMPANION_COMMITTED} holds {found}, the placeholder of a licence template, where \
             the crate's own copyright line belongs: {COMPANION_REPAIR}"
        );
    }
    let lacking = gaps(checkout, &text, Product::Companion)?;
    if let Some(first) = lacking.first() {
        refuse!(
            "{COMPANION_COMMITTED} has no entry for {} of the crates the lock takes into the \
             companion application, the first {first}: {COMPANION_REPAIR}",
            lacking.len()
        );
    }
    Ok(())
}

/// The crates the lock reaches from the packages of `product`, without a crate that only a
/// package's tests use, that `notice` names in no entry, each as `name version`, or `name version |
/// source ADDRESS` when a Git repository gives it, in order.
///
/// # Errors
///
/// Returns a refusal when a file it reads is missing or is not what it expects.
pub fn gaps(checkout: &Path, notice: &str, product: Product) -> Result<Vec<String>> {
    let named: BTreeSet<Identity> = entries(notice)
        .into_iter()
        .filter_map(|entry| {
            let mut fields = entry.split(" | ");
            let mut words = fields.next()?.split_whitespace();
            let (name, version) = (words.next()?.to_owned(), words.next()?.to_owned());
            let repository = fields
                .find_map(|field| field.strip_prefix("source "))
                .filter(|address| !address.starts_with(REGISTRY_PAGE))
                .map(str::to_owned);
            Some((name, version, repository))
        })
        .collect();
    Ok(reached(checkout, product)?
        .into_iter()
        .filter(|identity| !named.contains(identity))
        .map(|(name, version, repository)| match repository {
            Some(address) => format!("{name} {version} | source {address}"),
            None => format!("{name} {version}"),
        })
        .collect())
}

/// Where a line of the notice stands: in a licence text or a heading, under a heading `Used by:`
/// before its entries, among a block's entries, or among the closing list of crates.
#[derive(Clone, Copy)]
enum Part {
    Text,
    Heading,
    Entries,
    Closing,
}

/// The title of the closing list of crates that no release build compiles.
const CLOSING: &str = "Crates the lock reaches that no release build compiles";

/// The entries of the notice, without their leading marker: the lines under a `Used by:` heading, up
/// to the blank line that ends them, and the lines of the closing list. A line of a licence text that
/// starts with the same marker is not an entry.
fn entries(notice: &str) -> Vec<&str> {
    let mut part = Part::Text;
    let mut found = Vec::new();
    for line in notice.lines() {
        part = match (part, line) {
            (Part::Text, "Used by:") => Part::Heading,
            (Part::Text, CLOSING) => Part::Closing,
            (Part::Heading, _) => Part::Entries,
            (Part::Entries, "") => Part::Text,
            (same, entry) => {
                if let (Part::Entries | Part::Closing, Some(rest)) =
                    (same, entry.strip_prefix("  - "))
                {
                    found.push(rest);
                }
                same
            }
        };
    }
    found
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
    let source = words.next().map(|word| {
        word.trim_start_matches('(')
            .trim_end_matches(')')
            .to_owned()
    });
    all.iter()
        .enumerate()
        .filter(move |(_, package)| {
            package.name == name
                && version
                    .as_ref()
                    .is_none_or(|wanted| package.version == *wanted)
                && source
                    .as_ref()
                    .is_none_or(|wanted| package.source.as_ref() == Some(wanted))
        })
        .map(|(index, _)| index)
}

/// The packages a product is built from: the release programs of `scripts/release-programs.json`,
/// or the companion's package of `scripts/companion-notice.json`.
fn package_names(checkout: &Path, product: Product) -> Result<Vec<String>> {
    match product {
        Product::Programs => {
            let listed = read_json(&checkout.join("scripts/release-programs.json"))?;
            let Some(programs) = listed["programs"].as_array() else {
                refuse!("scripts/release-programs.json lists no programs");
            };
            programs
                .iter()
                .map(|program| {
                    program["package"]
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            Refusal(
                                "scripts/release-programs.json lists a program with no package"
                                    .into(),
                            )
                        })
                })
                .collect()
        }
        Product::Companion => {
            let listed = read_json(&checkout.join("scripts/companion-notice.json"))?;
            let Some(package) = listed["package"].as_str() else {
                refuse!("scripts/companion-notice.json names no package");
            };
            Ok(vec![package.to_owned()])
        }
    }
}

/// Every package the lock takes from a registry or a repository into the packages of `product`.
/// The lock holds the dependencies of a package under every feature of every package of the
/// workspace, so this is the crates a build can reach, which are more than the crates it compiles.
fn reached(checkout: &Path, product: Product) -> Result<BTreeSet<Identity>> {
    let lock = read_text(&checkout.join("Cargo.lock"))?
        .parse::<DocumentMut>()
        .map_err(|error| Refusal(format!("Cargo.lock is not TOML: {error}")))?;
    let all = packages(&lock)?;
    let wants = workspace_wants(checkout)?;
    let mut stack = Vec::new();
    for name in package_names(checkout, product)? {
        let roots: Vec<usize> = all
            .iter()
            .enumerate()
            .filter(|(_, package)| package.name == name && package.source.is_none())
            .map(|(index, _)| index)
            .collect();
        if roots.is_empty() {
            refuse!(
                "the lock holds no package {name}, which the notice of this product is made for"
            );
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
        .map(|(package, _)| {
            let repository = package
                .source
                .as_deref()
                .and_then(|source| source.strip_prefix("git+"))
                .map(str::to_owned);
            (package.name.clone(), package.version.clone(), repository)
        })
        .collect())
}
