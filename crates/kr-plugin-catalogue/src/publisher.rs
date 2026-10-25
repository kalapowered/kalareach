//! Which root holds a publisher's name.
//!
//! A plugin identifier is `publisher/name`, and an installation, an admission, a grant and a
//! binding are all found by it. Two repositories under different roots that list one publisher
//! would be two authorities for one name, and a package of the one could replace what the other
//! installed. So a publisher's name is held by the root that first lists it, and a repository
//! under another root is refused the name, when it synchronises and when it installs.
//!
//! The binding is read from what the catalogue keeps anyway and written nowhere: an enrolment
//! holds the publishers its active generation lists and the publishers of what it installed, and
//! an installation whose enrolment was removed holds its publisher by the root in the checkpoint
//! that enrolment left in its directory. "The same root" is the same set of keys the root names for
//! its own role: a mirror, and a vendor beneath the official root, share it, and a renewed root
//! keeps it. The enrolment the seed made is never refused, so a shipped name is the build's
//! whichever repository was enrolled first.

use std::collections::BTreeSet;
use std::path::Path;

use crate::db::Records;
use crate::error::{CatalogueError, CatalogueResult};
use crate::repository::EnrolmentKey;
use crate::seed;
use crate::store::Store;
use crate::trust;

/// The keys of a root's own role.
type RootKeys = BTreeSet<(&'static str, Vec<u8>)>;

/// Checks that none of `publishers`, which `candidate` lists, is held by a root other than the
/// candidate's.
///
/// `roots` are the roots that count as the candidate's own: the one it was enrolled on or has
/// kept, and, in a synchronisation, the one the load ended on, because the client verified the
/// chain between them. A holder whose keys for its own role match none of them is another root.
///
/// # Errors
///
/// Returns [`CatalogueError::Untrusted`] naming the publisher and the repository that holds it.
pub(crate) fn check(
    records: &Records<'_>,
    home: &Path,
    candidate: &EnrolmentKey,
    roots: &[&[u8]],
    publishers: &BTreeSet<String>,
) -> CatalogueResult<()> {
    if publishers.is_empty()
        || records
            .setting(&format!("{}{candidate}", seed::SEEDED))?
            .is_some()
    {
        return Ok(());
    }
    let own: Vec<RootKeys> = roots
        .iter()
        .filter_map(|root| trust::root_role_keys(root))
        .collect();
    let same = |theirs: Option<RootKeys>| theirs.is_some_and(|theirs| own.contains(&theirs));
    let enrolments = records.enrolments()?;
    let installations = records.installations()?;
    // Every repository that holds a publisher this one lists under another root, by publisher.
    let mut holders: std::collections::BTreeMap<String, BTreeSet<String>> =
        std::collections::BTreeMap::new();
    for held in enrolments.iter().filter(|held| held.key != *candidate) {
        let mut names = match &held.active {
            Some(active) => records.listed_publishers(&held.key, active.generation)?,
            None => BTreeSet::new(),
        };
        names.extend(
            installations
                .iter()
                .filter(|installation| installation.enrolment == held.key)
                .map(|installation| installation.publisher_id.to_string()),
        );
        let overlap: Vec<&String> = names.intersection(publishers).collect();
        if !overlap.is_empty() && !same(trust::root_role_keys(&held.enrolment.root)) {
            for name in overlap {
                holders
                    .entry(name.clone())
                    .or_default()
                    .insert(held.enrolment.id.to_string());
            }
        }
    }
    // A repository that was removed no longer has an enrolment to read a root from, and what it
    // installed stays installed. The checkpoint it left in its directory is the root it was on.
    for left in installations.iter().filter(|installation| {
        installation.enrolment != *candidate
            && !enrolments
                .iter()
                .any(|enrolled| enrolled.key == installation.enrolment)
    }) {
        let name = left.publisher_id.to_string();
        if !publishers.contains(&name) {
            continue;
        }
        let root = std::fs::read(
            Store::at(home, &left.enrolment)
                .datastore()
                .join("root.json"),
        )
        .ok()
        .and_then(|root| trust::root_role_keys(&root));
        if !same(root) {
            holders
                .entry(name)
                .or_default()
                .insert(left.repository.to_string());
        }
    }
    match holders.into_iter().next() {
        Some((publisher, holders)) => Err(held_by(&publisher, &holders)),
        None => Ok(()),
    }
}

fn held_by(publisher: &str, holders: &BTreeSet<String>) -> CatalogueError {
    let holders = holders.iter().cloned().collect::<Vec<_>>().join(", ");
    CatalogueError::Untrusted {
        detail: format!(
            "{publisher} is a publisher that {holders} hold under another root, and a package of \
             this repository under that name could replace what they installed; remove {holders} \
             and what was installed from them, or choose another publisher name"
        ),
    }
}
