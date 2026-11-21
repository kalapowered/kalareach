//! The releases whose matrix readers the real cases build, and the matrices they read.
//!
//! Declared by `release_candidate.rs` alone, so no other test target compiles it.

use serde_json::{Value, json};

/// A host release whose reader a real case builds.
pub struct Known {
    /// The tag, `host/v<track>+<the first twelve digits of the commit>`.
    pub tag: &'static str,
    /// The tagged commit.
    pub commit: &'static str,
    /// The package version the release carries.
    pub version: &'static str,
    /// The first revision its reader reads, none for the reader that has no such floor.
    pub floor: Option<u64>,
}

/// The three host releases of core when the producer was written, and what each reader holds to.
pub const HOST_RELEASES: [Known; 3] = [
    Known {
        tag: "host/v0.1.0+7c68ef8cf3c0",
        commit: "7c68ef8cf3c0baa8586af42267583eb665e8dd26",
        version: "0.78.0",
        floor: Some(2),
    },
    Known {
        tag: "host/v0.1.0+8cd1adf5c8bf",
        commit: "8cd1adf5c8bf8f27149ae26a6b79a389853d13e2",
        version: "0.78.0",
        floor: None,
    },
    Known {
        tag: "host/v0.1.0+955f0efd7def",
        commit: "955f0efd7deff8a7d5b1935c22d683f07bd46f20",
        version: "0.78.0",
        floor: Some(2),
    },
];

/// A matrix of one compatible tier that serves the clients from `low` to `high`.
pub fn matrix(revision: &str, low: &str, high: &str) -> Value {
    json!({
        "schemaVersion": 1,
        "revision": revision,
        "issuedAt": "2026-10-26",
        "note": "",
        "installedClientWindowDays": 90,
        "alternatives": ["direct", "self-hosted-relay", "self-hosted-discovery"],
        "tiers": [{
            "id": "compatible",
            "compatible": true,
            "note": "",
            "client": { "minimum": low, "maximum": high },
            "relay": { "minimum": "1.2.0", "maximum": "1.2.99" },
            "discovery": { "minimum": "1.2.0", "maximum": "1.2.99" },
        }],
    })
}

/// Revision 1 as it was published: clients 0.1.0 to 0.4.99, which no host release is in.
pub fn first_revision() -> Value {
    matrix("1", "0.1.0", "0.4.99")
}

/// A revision that serves every host release and the release before them.
pub fn serving_every_release() -> Value {
    matrix("2", "0.77.0", "0.79.99")
}
