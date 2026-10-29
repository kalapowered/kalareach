//! The page names a share by a role, and the rights each role carries there are a copy of the
//! host's.
//!
//! The host writes a grant's actions from its role once, when the grant is written, and decides every
//! request from the actions. The page keeps its own table of what each role carries, to name a share
//! by the widest role it holds in full and to say everything it allows beside that role. A role
//! that carried more on the page than at the host would name a share as less than it allows; one
//! that carried less would name it as more. Nothing but the two tables can notice that they differ,
//! so this reads the page's table out of its source and holds it to the host's.

use std::collections::{BTreeMap, BTreeSet};

use kr_protocol::sharing::SessionRole;

/// The page's table: for each role, the rights it names.
fn page_table() -> BTreeMap<String, BTreeSet<String>> {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../src/model/sharing.ts"),
    )
    .expect("the page's sharing model is readable");
    let start = source
        .find("const ROLE_RIGHTS")
        .expect("the page keeps a table of what each role carries");
    let body = &source[start..];
    let end = body
        .find("\n}\n")
        .expect("the table ends with a closing brace on a line of its own");
    let mut table: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in body[..end].lines().skip(1) {
        let line = line.trim();
        // A role opens on a line that names it, and its rights are the quoted words from there to
        // the bracket that closes the list.
        let rights = match line.split_once(": [") {
            Some((name, rest)) => {
                current = Some(name.to_owned());
                table.entry(name.to_owned()).or_default();
                rest
            }
            None => line,
        };
        if let Some(role) = &current {
            for right in rights.split('\'').skip(1).step_by(2) {
                let added = table
                    .get_mut(role)
                    .expect("the role was added when its line was read")
                    .insert(right.to_owned());
                assert!(added, "the page lists {right} twice for {role}");
            }
        }
        if line.contains(']') {
            current = None;
        }
    }
    table
}

/// KR-REQ-10.42: a share is named by what it allows, and the page names a role by the rights the
/// host writes for it. Every role the host has is in the page's table with exactly those rights, and
/// the page's table has no role the host does not.
#[test]
fn the_pages_table_of_what_each_role_carries_is_the_hosts() {
    let page = page_table();
    let host: BTreeMap<String, BTreeSet<String>> = SessionRole::ALL
        .into_iter()
        .map(|role| {
            (
                role.as_str().to_owned(),
                role.default_actions()
                    .iter()
                    .map(|right| right.as_str().to_owned())
                    .collect(),
            )
        })
        .collect();
    assert_eq!(page, host);
}
