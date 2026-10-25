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
//! keeps it. A holder whose root the candidate's root descends from, by the signatures the root
//! carries, is under the candidate's root too: it has not followed a rotation the candidate has.
//! The enrolment the seed made is never refused, so a shipped name is the build's whichever
//! repository was enrolled first.
//!
//! The check reads files and scans records, so it is made under the write lock of the change it
//! guards and before the admission is asked to hold the change's registration for the commit.

use std::collections::BTreeSet;
use std::path::Path;

use crate::db::Records;
use crate::error::{CatalogueError, CatalogueResult};
use crate::repository::EnrolmentKey;
use crate::seed;
use crate::store::Store;
use crate::trust;

/// What the candidate is doing when its publishers are checked, which decides what a person can do
/// about a refusal.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Doing {
    /// The candidate repository is synchronising a generation that lists the publishers.
    Synchronising,
    /// A package of the candidate repository is being installed.
    Installing,
}

/// Checks that none of `publishers`, which `candidate` lists, is held by a root other than the
/// candidate's.
///
/// `roots` are the roots that count as the candidate's own: the one it was enrolled on or has
/// kept, and, in a synchronisation, the one the load ended on, because the client verified the
/// chain between them. A holder whose keys for its own role match none of them, and whose root
/// none of them descends from, is another root.
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
    doing: Doing,
) -> CatalogueResult<()> {
    if publishers.is_empty()
        || records
            .setting(&format!("{}{candidate}", seed::SEEDED))?
            .is_some()
    {
        return Ok(());
    }
    let own: Vec<trust::RoleKeys> = roots
        .iter()
        .filter_map(|root| trust::root_role_keys(root))
        .collect();
    // A holder is under the candidate's root when it names the same keys for its own role, or when
    // the candidate's root descends from it: the holder's keys signed the candidate's root over,
    // as a client follows a rotation. The holder is then a repository that has not followed the
    // rotation yet, and it is recognised for as long as it has not, by the signatures the roots
    // carry, so no sync of the candidate waits for it to catch up.
    let same = |theirs: &[u8]| {
        trust::root_role_keys(theirs).is_some_and(|keys| own.contains(&keys))
            || roots
                .iter()
                .any(|root| trust::root_descends_from(theirs, root))
    };
    let enrolments = records.enrolments()?;
    let installations = records.installations()?;
    // Every repository that holds a publisher this one lists under another root, by publisher.
    let mut holders: std::collections::BTreeMap<String, Holders> =
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
        if !overlap.is_empty() && !same(&held.enrolment.root) {
            for name in overlap {
                holders
                    .entry(name.clone())
                    .or_default()
                    .enrolled
                    .insert(held.enrolment.id.to_string());
            }
        }
    }
    // A repository that was removed no longer has an enrolment to read a root from, and what it
    // installed stays installed. The checkpoint it left in its directory is the root it was on, and
    // a name whose checkpoint cannot be read is held against every root, the repository's own
    // included, rather than released for want of a record.
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
        );
        if !root.as_deref().is_ok_and(same) {
            holders
                .entry(name)
                .or_default()
                .removed
                .insert(left.repository.to_string());
        }
    }
    match holders.into_iter().next() {
        Some((publisher, holders)) => Err(held_by(&publisher, &holders, doing)),
        None => Ok(()),
    }
}

/// The repositories that hold one publisher's name under another root.
#[derive(Default)]
struct Holders {
    /// Repositories this host holds an enrolment of.
    enrolled: BTreeSet<String>,
    /// Repositories that were removed and left an installation behind.
    removed: BTreeSet<String>,
}

fn held_by(publisher: &str, holders: &Holders, doing: Doing) -> CatalogueError {
    let join = |names: &BTreeSet<String>| names.iter().cloned().collect::<Vec<_>>().join(", ");
    let all: BTreeSet<String> = holders.enrolled.union(&holders.removed).cloned().collect();
    // What a person can do differs by what holds the name: an enrolled repository is removed with
    // what was installed from it, and a repository that is already removed has only what it
    // installed left to remove.
    let mut steps = Vec::new();
    if !holders.enrolled.is_empty() {
        steps.push(format!(
            "remove {} and what was installed from it",
            join(&holders.enrolled)
        ));
    }
    if !holders.removed.is_empty() {
        steps.push(format!(
            "remove what was installed from {}",
            join(&holders.removed)
        ));
    }
    let again = match doing {
        Doing::Synchronising => "synchronise this repository again",
        Doing::Installing => "install this package again",
    };
    CatalogueError::Untrusted {
        detail: format!(
            "{publisher} is a publisher that {} hold under another root, and a package of this \
             repository under that name could replace what they installed; {}, then {again}",
            join(&all),
            steps.join(" and ")
        ),
    }
}
