//! The members that arrived in a definition of the schema inside a level.
//!
//! A release of one compatibility level reads and writes the frames of that level, and the check
//! of a level (`kr-protocol-gen --in-level`) holds the SDK's schema to every release of the level:
//! a member added to a definition is a difference. One kind of addition is not. A package carries
//! its own table and the host that reads it checks the package's `sdk_range` first, so a host that
//! predates a member refuses a package that holds it and misreads nothing. That holds for a member
//! only where absence keeps the earlier meaning, which no comparison of schemas can see, so the
//! members that qualify are listed here, one by one, each with the SDK version it arrived at.
//!
//! An entry is a promise about one member:
//!
//! * it is optional, and a table that does not state it means what a table meant before;
//! * it is left out when it holds nothing, so a table that does not use it is written with the
//!   same bytes as before;
//! * its definition belongs to the SDK alone, with no definition of that name in the protocol
//!   schema;
//! * its definition is reached only from documents a host reads after it has tested the package's
//!   `sdk_range`, which are the connector table and the presentation document, and never from the
//!   package manifest, the catalogue index or the publisher record, which an earlier host parses
//!   before it can refuse the package for its range and, for the index, whole;
//! * the SDK version rose in the release that added it, and a package that uses it states an
//!   `sdk_range` that starts at that version.
//!
//! The generator writes the table into the package contract, and the check of a level reads it
//! from the commit it checks and from every release it compares with: a member passes only where
//! the commit lists it at an SDK version above the earlier release's own, and the commit's own SDK
//! version is above that version too.

use serde_json::{Value, json};

/// One member that arrived in a definition of the schema inside a level.
#[derive(Clone, Copy, Debug)]
pub struct Arrival {
    /// The definition of the SDK's schema the member is in.
    pub definition: &'static str,
    /// The member's name.
    pub member: &'static str,
    /// The SDK version the member arrived at: the first release that has it.
    pub sdk_version: &'static str,
    /// Whether a connector table, as the JSON a package carries, holds the member anywhere. The
    /// package check uses it to refuse a package whose `sdk_range` admits an SDK that predates the
    /// member.
    pub carried_by: fn(&Value) -> bool,
}

/// Every member that arrived inside a level, in the order it did.
pub const ARRIVALS: &[Arrival] = &[Arrival {
    definition: "SelectionRoute",
    member: "hidden_when",
    sdk_version: "0.1.7",
    carried_by: |table| {
        table["observation"]["selections"]
            .as_array()
            .is_some_and(|routes| {
                routes
                    .iter()
                    .any(|route| route.get("hidden_when").is_some())
            })
    },
}];

/// The table as the package contract carries it.
#[must_use]
pub fn table() -> Value {
    Value::Array(
        ARRIVALS
            .iter()
            .map(|arrival| {
                json!({
                    "definition": arrival.definition,
                    "member": arrival.member,
                    "sdk_version": arrival.sdk_version,
                })
            })
            .collect(),
    )
}
