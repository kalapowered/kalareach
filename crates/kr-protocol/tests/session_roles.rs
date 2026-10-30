//! The session roles and the actions each carries by default.
//!
//! A grant keeps the actions its role carried when it was written and never the role. The
//! companion's page keeps its own table of what each role carries, to name a share by the widest
//! role it holds in full, and the page's test holds that table to the same fixture this file holds
//! the host to.

use std::path::PathBuf;

use kr_protocol::sharing::SessionRole;
use serde_json::Value;

fn fixture() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/protocol/session-roles.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

/// KR-REQ-10.42: the roles, in order, and what each carries by default, are what the page names a
/// share by. A role that carried more at the host than in the fixture would be named by the page as
/// less than it allows; one that carried less would be named as more.
#[test]
fn the_roles_and_their_default_actions_are_what_the_fixture_says() {
    let document = fixture();
    let roles = document["roles"].as_array().expect("a list of roles");
    let host: Vec<(String, Vec<String>)> = SessionRole::ALL
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
    let recorded: Vec<(String, Vec<String>)> = roles
        .iter()
        .map(|entry| {
            (
                entry["role"].as_str().expect("a role").to_owned(),
                entry["default_actions"]
                    .as_array()
                    .expect("a list of actions")
                    .iter()
                    .map(|right| right.as_str().expect("an action").to_owned())
                    .collect(),
            )
        })
        .collect();
    assert_eq!(recorded, host);
}
