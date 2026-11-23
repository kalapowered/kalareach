//! A configuration document one version ahead of the one this build writes, as the release after
//! this one writes it.
//!
//! This build reads the next version of the document without writing it, so that a host rolled
//! back to this build keeps working: a document at that version that holds nothing this build
//! lacks is the document this build writes, and one that holds a ceiling this build lacks is
//! refused whole. The golden files in `fixtures/configuration/` are the document as the later
//! release writes it, with each new ceiling set; they pin the names of the new ceilings, which the
//! stored-format lock does not (it holds the version number alone). The later release's writer
//! has to write them byte for byte.
//!
//! This build writes version 4, where the owner's description budgets arrived
//! (`version-4-description-budgets.json`, which this build writes byte for byte), and reads
//! through version 5 (`version-5.json`). `version-4-limits.json` pins a ceiling that this build
//! still lacks.

use std::path::PathBuf;

use kr_protocol::desktop::SleepInhibitionSetting;
use kr_protocol::hostinfo::configuration::{
    self, Change, ConfigurationDocument, DocumentState, Loaded,
};
use serde_json::Value;

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/configuration")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn load(text: &str) -> Loaded {
    configuration::load(Some(text.as_bytes()))
}

/// The golden file with one member of `ceilings` replaced.
fn with_ceiling(name: &str, member: &str, value: &Value) -> String {
    let mut document: Value = serde_json::from_str(&fixture(name)).expect("a JSON document");
    document["ceilings"][member] = value.clone();
    serde_json::to_string_pretty(&document).expect("a document")
}

/// KR-REQ-26.13: a document at the next version that holds no ceiling this build lacks is the
/// document this build writes: the same settings, read at the version this build writes, and the
/// next edit writes it at that version.
#[test]
fn a_document_one_version_ahead_with_no_new_ceiling_is_read_as_the_version_this_build_writes() {
    let ahead = load(&fixture("version-5.json"));
    assert_eq!(ahead.status.state, DocumentState::Loaded);
    assert!(!ahead.fails_closed());
    let document = ahead.document.clone().expect("the document is used");
    assert_eq!(document.version, configuration::VERSION);
    assert_eq!(document.ceilings.session_limit.as_ref(), Some(&16));
    assert_eq!(
        document.ceilings.grant_rights.as_ref(),
        Some(&vec!["session.view".to_owned()])
    );
    assert!(
        ahead
            .status
            .detail
            .as_str()
            .contains("version 5, read as version 4"),
        "{:?}",
        ahead.status
    );

    // The control: the same bytes at the version this build writes are the same document.
    let own = load(&fixture("version-5.json").replace("\"version\": 5", "\"version\": 4"));
    assert_eq!(own.status.state, DocumentState::Loaded);
    assert_eq!(own.document, ahead.document);

    let edited = configuration::edit(
        &ahead,
        &Change::SleepInhibition(SleepInhibitionSetting::Off),
    )
    .expect("a document this build reads is edited");
    let written: Value = serde_json::from_str(&edited.contents).expect("a JSON document");
    assert_eq!(
        written["version"], 4,
        "the edit writes the version this build writes"
    );
    assert_eq!(written["ceilings"]["session_limit"], 16);
    assert!(
        written["ceilings"].get("description_budgets").is_none(),
        "a document that does not use the ceiling writes no member for it"
    );
}

/// KR-REQ-26.13: a ceiling this build lacks, in any form, makes the document unusable whole, and
/// the file is left as it is: the host fails closed, the restrictions accepted before stay in
/// force, and nothing is read out of the document, since reading the rest would run the host
/// without the ceiling the owner wrote.
#[test]
fn a_ceiling_this_build_lacks_makes_the_document_unusable_in_every_form() {
    let empty = Value::Object(serde_json::Map::new());
    {
        let (name, member) = ("version-4-limits.json", "limits");
        let set = fixture(name);
        let forms = [
            ("set", set.clone()),
            ("null", with_ceiling(name, member, &Value::Null)),
            ("empty", with_ceiling(name, member, &empty)),
        ];
        for (form, text) in forms {
            let loaded = load(&text);
            assert_eq!(
                loaded.status.state,
                DocumentState::Invalid,
                "{member} {form}: {:?}",
                loaded.status
            );
            assert!(loaded.fails_closed(), "{member} {form}");
            assert!(
                loaded.document.is_none(),
                "{member} {form}: nothing is read out of a document with a ceiling this build lacks"
            );
        }
        // The same ceiling at the version before is refused alike: the version does not make a
        // name known.
        let at_three = set.replace("\"version\": 4", "\"version\": 3");
        assert_eq!(
            load(&at_three).status.state,
            DocumentState::Invalid,
            "{member}"
        );
    }
}

/// KR-REQ-26.13: the version after the one this build reads through is still one it does not know.
#[test]
fn a_document_two_versions_ahead_is_still_a_version_this_build_does_not_know() {
    let loaded = load(&fixture("version-5.json").replace("\"version\": 5", "\"version\": 6"));
    assert_eq!(loaded.status.state, DocumentState::UnknownVersion);
    assert!(loaded.fails_closed());
    assert!(loaded.document.is_none());
}

/// KR-REQ-26.13: what the later release writes with no ceiling set is what this build writes
/// with the version it reads it at, so a host moving between the two keeps one document.
#[test]
fn the_document_this_build_writes_is_the_golden_document_at_the_version_it_writes() {
    let loaded = load(&fixture("version-5.json"));
    let document: ConfigurationDocument = loaded.document.expect("the document is used");
    assert_eq!(
        configuration::contents(&document),
        fixture("version-5.json").replace("\"version\": 5", "\"version\": 4"),
    );
    // And the golden that is already at the version this build writes is read as it is and
    // written as it was.
    let own = load(&fixture("version-4.json"));
    assert_eq!(own.status.state, DocumentState::Loaded);
    assert!(
        !own.status.detail.as_str().contains("read as"),
        "{:?}",
        own.status
    );
    assert_eq!(
        configuration::contents(&own.document.expect("the document is used")),
        fixture("version-4.json"),
    );
}

/// KR-REQ-22.10: the owner's description budgets are a ceiling this build has, at the version it
/// writes: the golden document is read with both budgets set, and this build writes it back byte
/// for byte.
#[test]
fn this_build_writes_the_golden_document_with_the_description_budgets_byte_for_byte() {
    let golden = fixture("version-4-description-budgets.json");
    let loaded = load(&golden);
    assert_eq!(
        loaded.status.state,
        DocumentState::Loaded,
        "{:?}",
        loaded.status
    );
    assert!(!loaded.fails_closed());
    let document: ConfigurationDocument = loaded.document.expect("the document is used");
    assert_eq!(document.version, configuration::VERSION);
    let budgets = document
        .ceilings
        .description_budgets
        .expect("the document sets the budgets");
    assert_eq!(budgets.process_memory_bytes.as_ref(), Some(&(2 << 30)));
    assert_eq!(budgets.reserve_bytes.as_ref(), Some(&(2 << 30)));
    assert_eq!(configuration::contents(&document), golden);
}

/// KR-REQ-22.10: a document without the member reads as before, `null` reads as absent, one budget
/// alone is a document, and a member the budgets do not have, at any depth, makes the document
/// unusable whole.
#[test]
fn the_description_budgets_read_as_absent_as_one_budget_or_as_a_document_that_is_refused() {
    let name = "version-4-description-budgets.json";
    let member = "description_budgets";

    let absent = load(&fixture("version-4.json"));
    let document = absent.document.expect("the document is used");
    assert_eq!(document.ceilings.description_budgets, None);

    let null = load(&with_ceiling(name, member, &Value::Null));
    assert_eq!(
        null.status.state,
        DocumentState::Loaded,
        "{:?}",
        null.status
    );
    assert_eq!(
        null.document
            .expect("the document is used")
            .ceilings
            .description_budgets,
        None,
        "null is absent"
    );

    let one = load(&with_ceiling(
        name,
        member,
        &serde_json::json!({ "reserve_bytes": 3_221_225_472u64 }),
    ));
    assert_eq!(one.status.state, DocumentState::Loaded, "{:?}", one.status);
    let budgets = one
        .document
        .expect("the document is used")
        .ceilings
        .description_budgets
        .expect("the budgets are set");
    assert_eq!(budgets.process_memory_bytes.as_ref(), None);
    assert_eq!(budgets.reserve_bytes.as_ref(), Some(&3_221_225_472));

    for (what, value) in [
        (
            "a nested unknown member",
            serde_json::json!({ "process_memory_bytes": 1, "reserve_bytes": 2, "soft_bytes": 3 }),
        ),
        (
            "a budget that is not a number",
            serde_json::json!({ "reserve_bytes": "big" }),
        ),
        (
            "a budget below zero",
            serde_json::json!({ "process_memory_bytes": -1 }),
        ),
    ] {
        let loaded = load(&with_ceiling(name, member, &value));
        assert_eq!(
            loaded.status.state,
            DocumentState::Invalid,
            "{what}: {:?}",
            loaded.status
        );
        assert!(loaded.fails_closed(), "{what}");
        assert!(
            loaded.document.is_none(),
            "{what}: nothing is read out of it"
        );
    }
}

/// KR-REQ-22.10: a document that holds a description budget the host cannot honour is unusable
/// whole, as one with a session ceiling of 0 is, and says which rule it broke: the host fails
/// closed and nothing is read out of it.
#[test]
fn a_document_with_a_description_budget_the_host_cannot_honour_is_unusable() {
    let name = "version-4-description-budgets.json";
    let member = "description_budgets";
    for (what, value, rule) in [
        (
            "a ceiling of 0",
            serde_json::json!({ "process_memory_bytes": 0 }),
            "the description process's memory ceiling is more than 0 and at most 4 GiB",
        ),
        (
            "a ceiling above 4 GiB",
            serde_json::json!({ "process_memory_bytes": 4_294_967_297u64 }),
            "the description process's memory ceiling is more than 0 and at most 4 GiB",
        ),
        (
            "a reserve below 1 GiB",
            serde_json::json!({ "reserve_bytes": 1_073_741_823u64 }),
            "the description reserve is at least 1 GiB",
        ),
    ] {
        let loaded = load(&with_ceiling(name, member, &value));
        assert_eq!(
            loaded.status.state,
            DocumentState::Invalid,
            "{what}: {:?}",
            loaded.status
        );
        assert!(loaded.fails_closed(), "{what}");
        assert!(
            loaded.document.is_none(),
            "{what}: nothing is read out of it"
        );
        assert!(
            loaded.status.detail.as_str().contains(rule),
            "{what}: {:?}",
            loaded.status
        );
    }
    // The edges are the owner's: 4 GiB exactly, and a reserve of exactly 1 GiB.
    for value in [
        serde_json::json!({ "process_memory_bytes": 4_294_967_296u64 }),
        serde_json::json!({ "reserve_bytes": 1_073_741_824u64 }),
    ] {
        let loaded = load(&with_ceiling(name, member, &value));
        assert_eq!(
            loaded.status.state,
            DocumentState::Loaded,
            "{value}: {:?}",
            loaded.status
        );
    }
}
