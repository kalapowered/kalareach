//! The committed build list as the tests of this crate read it.

use crate::build::Build;

/// The committed list, in the fixture folder of this crate.
pub fn committed() -> serde_json::Value {
    serde_json::from_str(include_str!("../tests/fixtures/builds.json")).expect("the list")
}

/// The entry of `package` in the committed list, projected so that the driver gets every member it
/// reads: `missing` is `{}` where the list has none (the entries of kimi-cli and opencode-attach
/// have no such member), `actions` is not given, and `newer` is kept whatever `$installed` says.
pub fn build_of(package: &str) -> Build {
    let list = committed();
    let entry = list["builds"]
        .as_array()
        .and_then(|entries| entries.iter().find(|entry| entry["package"] == package))
        .unwrap_or_else(|| panic!("the committed list has no entry for {package}"));
    let mut out = serde_json::Map::new();
    for name in [
        "package",
        "application",
        "version",
        "prefix",
        "pinned",
        "sha256",
        "command",
        "launch",
        "arguments",
        "runtime",
        "environment",
        "home",
        "ready",
        "harmless",
        "composer",
        "server",
        "transcript",
        "no_account",
        "no_newer",
        "account",
        "isolation",
        "missing",
    ] {
        if let Some(value) = entry.get(name) {
            out.insert(name.to_owned(), value.clone());
        }
    }
    out.entry("missing")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(newer) = entry.get("newer").filter(|newer| !newer.is_null()) {
        let mut kept = serde_json::Map::new();
        for name in ["version", "prefix", "pinned", "sha256", "ready", "isolated"] {
            if let Some(value) = newer.get(name) {
                kept.insert(name.to_owned(), value.clone());
            }
        }
        out.insert("newer".to_owned(), serde_json::Value::Object(kept));
    }
    serde_json::from_value(serde_json::Value::Object(out)).expect("a build")
}
