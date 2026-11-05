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
    let ahead = load(&fixture("version-4.json"));
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
            .contains("version 4, read as version 3"),
        "{:?}",
        ahead.status
    );

    // The control: the same bytes at the version this build writes are the same document.
    let own = load(&fixture("version-4.json").replace("\"version\": 4", "\"version\": 3"));
    assert_eq!(own.status.state, DocumentState::Loaded);
    assert_eq!(own.document, ahead.document);

    let edited = configuration::edit(
        &ahead,
        &Change::SleepInhibition(SleepInhibitionSetting::Off),
    )
    .expect("a document this build reads is edited");
    let written: Value = serde_json::from_str(&edited.contents).expect("a JSON document");
    assert_eq!(
        written["version"], 3,
        "the edit writes the version this build writes"
    );
    assert_eq!(written["ceilings"]["session_limit"], 16);
}

/// KR-REQ-26.13: a ceiling this build lacks, in any form, makes the document unusable whole, and
/// the file is left as it is: the host fails closed, the restrictions accepted before stay in
/// force, and nothing is read out of the document, since reading the rest would run the host
/// without the ceiling the owner wrote.
#[test]
fn a_ceiling_this_build_lacks_makes_the_document_unusable_in_every_form() {
    let empty = Value::Object(serde_json::Map::new());
    for (name, member) in [
        ("version-4-limits.json", "limits"),
        ("version-4-description-budgets.json", "description_budgets"),
    ] {
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
        // The same ceiling at the version this build writes is refused alike: the version does
        // not make a name known.
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
    let loaded = load(&fixture("version-4.json").replace("\"version\": 4", "\"version\": 5"));
    assert_eq!(loaded.status.state, DocumentState::UnknownVersion);
    assert!(loaded.fails_closed());
    assert!(loaded.document.is_none());
}

/// KR-REQ-26.13: what the later release writes with no ceiling set is what this build writes
/// with the version it reads it at, so a host moving between the two keeps one document.
#[test]
fn the_document_this_build_writes_is_the_golden_document_at_the_version_it_writes() {
    let loaded = load(&fixture("version-4.json"));
    let document: ConfigurationDocument = loaded.document.expect("the document is used");
    assert_eq!(
        configuration::contents(&document),
        fixture("version-4.json").replace("\"version\": 4", "\"version\": 3"),
    );
}
