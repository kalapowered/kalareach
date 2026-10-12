//! The reader, the editor and the serializer of configuration levels, through the real functions.
//!
//! Three releases stand in for each other. `R1` is a release that reads level 1. `R1_LISTING` is
//! the same release with the existing `voice` section listed at level 2, so that it takes `voice`
//! for a section of a newer release. `R2` reads level 2 and knows `voice` as its level-2 section.
//! `voice` is always written, so it stands in for a levelled section when a test reads, ignores
//! and stamps one, and never when a test is about leaving an unused section out.

use serde_json::Value;

use super::{Levelled, Newer, Release, THIS_RELEASE};
use crate::hostinfo::configuration::{
    BASE_LEVEL, Change, ConfigurationDocument, DocumentState, EditRefused, VERSION, contents_in,
    edit_in, is_known_term, load_in, still_current,
};
use crate::hostinfo::export::Sentence;
use crate::scalars::Nullable;

const R1: Release = Release {
    level: 1,
    levelled: &[],
};

const R1_LISTING: Release = Release {
    level: 1,
    levelled: &[Levelled {
        member: "voice",
        level: 2,
    }],
};

const R2: Release = Release {
    level: 2,
    levelled: &[Levelled {
        member: "voice",
        level: 2,
    }],
};

/// A release that reads level 1 and predates the authority section: it takes the section for a
/// member of a newer release.
const BEFORE_AUTHORITY: Release = Release {
    level: 1,
    levelled: &[Levelled {
        member: "authority",
        level: 2,
    }],
};

const BROKER: &str = "https://broker.example.com";

const FEED: &str = "https://reach.example.com";

fn with_a_broker() -> ConfigurationDocument {
    let mut document = ConfigurationDocument::empty();
    document.voice.broker_origin = Nullable::some(BROKER.to_owned());
    document.ceilings.session_limit = Nullable::some(4);
    document
}

fn member_order(text: &str, members: &[&str]) -> Vec<usize> {
    members
        .iter()
        .map(|member| {
            text.find(&format!("\"{member}\""))
                .unwrap_or_else(|| panic!("{member} is written: {text}"))
        })
        .collect()
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).expect("JSON")
}

/// A document of level 2 as a release that holds `voice` writes it.
fn written_at_level_two() -> String {
    contents_in(&with_a_broker(), &R2)
}

/// KR-REQ-26.13: a writer stamps the highest level among the sections the document holds, in the
/// document's own member order, and a document that holds none of them is stamped with the base
/// level, so a release that reads less can still read and edit it.
#[test]
fn a_writer_stamps_the_level_of_the_sections_the_document_holds() {
    let held = written_at_level_two();
    let value = json(&held);
    assert_eq!(value["level"], 2, "{held}");
    assert_eq!(value["voice"]["broker_origin"], BROKER, "{held}");
    let order = member_order(
        &held,
        &["version", "level", "revision", "preferences", "voice"],
    );
    assert!(
        order.windows(2).all(|pair| pair[0] < pair[1]),
        "the file keeps the document's own member order: {held}"
    );

    let unused = contents_in(&ConfigurationDocument::empty(), &R2);
    assert_eq!(json(&unused)["level"], 1, "{unused}");

    // Through the editor too: an edit of a document that holds the section keeps it at level 2,
    // and an edit of one that does not writes level 1.
    let loaded = load_in(Some(held.as_bytes()), &R2);
    assert_eq!(loaded.status.state, DocumentState::Loaded);
    let edited = edit_in(&loaded, &Change::SessionLimit(Some(2)), &R2).expect("an edit");
    assert_eq!(json(&edited.contents)["level"], 2, "{}", edited.contents);
    assert_eq!(json(&edited.contents)["voice"]["broker_origin"], BROKER);
    assert_eq!(edited.document.level, 2);
    let first = edit_in(&load_in(None, &R2), &Change::SessionLimit(Some(2)), &R2).expect("an edit");
    assert_eq!(json(&first.contents)["level"], 1, "{}", first.contents);
    assert_eq!(first.document.level, 1);
}

/// KR-REQ-26.13: a section is held when one of its immediate fields is not null, and an empty list
/// is not null.
#[test]
fn a_section_is_held_when_one_of_its_fields_is_not_null() {
    let release = Release {
        level: 2,
        levelled: &[Levelled {
            member: "network",
            level: 2,
        }],
    };
    let mut document = ConfigurationDocument::empty();
    assert_eq!(json(&contents_in(&document, &release))["level"], 1);
    document.network.relay_urls = Nullable::some(Vec::new());
    assert_eq!(
        json(&contents_in(&document, &release))["level"],
        2,
        "an empty list can mean something"
    );
}

/// KR-REQ-26.13: a release that reads less takes a section of a newer one for what it is: it
/// applies every member it knows, leaves the section out, counts it and names it, and it does not
/// make the host fail closed.
#[test]
fn a_document_above_the_level_applies_its_known_members_and_reports_the_rest() {
    let held = written_at_level_two();
    let loaded = load_in(Some(held.as_bytes()), &R1_LISTING);
    assert_eq!(
        loaded.status.state,
        DocumentState::Loaded,
        "{:?}",
        loaded.status
    );
    assert!(!loaded.fails_closed());
    let document = loaded.document.expect("the document is used");
    assert_eq!(
        document.ceilings.session_limit.0,
        Some(4),
        "a known member applies"
    );
    assert_eq!(
        document.voice.broker_origin.0, None,
        "the newer section is left out"
    );
    assert_eq!(
        loaded.newer,
        Some(Newer {
            declared: 2,
            count: 1,
            names: vec!["voice".to_owned()]
        })
    );
    assert_eq!(
        document.level, 1,
        "the typed document states the level it applied"
    );
    assert!(
        loaded.status.detail.as_str().contains("level 2"),
        "{:?}",
        loaded.status
    );
    assert!(
        loaded.status.detail.as_str().contains("reads level 1"),
        "{:?}",
        loaded.status
    );
}

/// KR-REQ-26.13: an edit of a document above the level is refused, whether or not any member was
/// left out of it, so a whole-document rewrite never drops a member this release cannot see.
#[test]
fn an_edit_of_a_document_above_the_level_is_refused() {
    let held = written_at_level_two();
    let loaded = load_in(Some(held.as_bytes()), &R1_LISTING);
    assert!(loaded.newer.is_some());
    let change = Change::SessionLimit(Some(2));
    let refused = edit_in(&loaded, &change, &R1_LISTING).expect_err("refused");
    assert!(matches!(refused, EditRefused::NotOurs(_)), "{refused:?}");

    let only_known = br#"{"version": 3, "level": 2, "ceilings": {"session_limit": 4}}"#;
    let loaded = load_in(Some(only_known), &R1);
    assert_eq!(loaded.status.state, DocumentState::Loaded);
    assert_eq!(loaded.newer.as_ref().map(|newer| newer.count), Some(0));
    assert!(matches!(
        edit_in(&loaded, &change, &R1),
        Err(EditRefused::NotOurs(_))
    ));
}

/// KR-REQ-26.13: an edit prepared from a document at or below the level is not written over a file
/// that has since been changed to state a higher level and hold a member this release cannot see,
/// though the reader keeps only the members it knows and so sees an unchanged document.
#[test]
fn a_file_changed_to_a_higher_level_since_the_edit_was_prepared_is_not_overwritten() {
    let before = load_in(Some(br#"{"version": 3, "revision": 1}"#), &R1);
    assert_eq!(before.status.state, DocumentState::Loaded);
    let edited = edit_in(&before, &Change::SessionLimit(Some(2)), &R1).expect("an edit");
    let after = load_in(
        Some(br#"{"version": 3, "level": 2, "revision": 1, "telemetry_events": {}}"#),
        &R1,
    );
    assert_eq!(
        after.document, before.document,
        "the reader keeps only what it knows, so the document looks unchanged"
    );
    let refused = still_current(&edited, &after).expect_err("refused at the final check");
    assert!(matches!(refused, EditRefused::NotOurs(_)), "{refused:?}");
    still_current(&edited, &before).expect("a file that did not change");
}

/// KR-REQ-26.13: the level a document states is checked: a document at version 3 with no level is at
/// the base level; a level that is not a whole number of at least the base is refused; a level below
/// what the sections the document holds need is refused, as the release that wrote them refuses it;
/// and a document of an earlier version states no level.
#[test]
fn the_level_a_document_states_is_checked() {
    let plain = load_in(Some(br#"{"version": 3}"#), &R1);
    assert_eq!(plain.status.state, DocumentState::Loaded);
    assert_eq!(plain.document.expect("used").level, BASE_LEVEL);
    assert!(plain.newer.is_none());

    for refused in [
        r#"{"version": 3, "level": 0}"#,
        r#"{"version": 3, "level": "2"}"#,
        r#"{"version": 3, "level": -1}"#,
    ] {
        let loaded = load_in(Some(refused.as_bytes()), &R1);
        assert_eq!(loaded.status.state, DocumentState::Invalid, "{refused}");
    }

    let too_low =
        format!(r#"{{"version": 3, "level": 1, "voice": {{"broker_origin": "{BROKER}"}}}}"#);
    let loaded = load_in(Some(too_low.as_bytes()), &R2);
    assert_eq!(
        loaded.status.state,
        DocumentState::Invalid,
        "{:?}",
        loaded.status
    );

    // A guard: an earlier version states no level, and reads at the base level as before.
    for earlier in [r#"{"version": 1}"#, r#"{"version": 2}"#] {
        let loaded = load_in(Some(earlier.as_bytes()), &R1);
        assert_eq!(loaded.status.state, DocumentState::Loaded, "{earlier}");
        let document = loaded.document.expect("used");
        assert_eq!((document.version, document.level), (VERSION, BASE_LEVEL));
    }
    for stated in [
        r#"{"version": 1, "level": 1}"#,
        r#"{"version": 2, "level": 1}"#,
    ] {
        let loaded = load_in(Some(stated.as_bytes()), &R1);
        assert_eq!(loaded.status.state, DocumentState::Invalid, "{stated}");
    }
}

/// KR-REQ-26.13: the members a release knows stay strict at every depth in a document above its
/// level, a section the release lists above its level is refused whenever it is present, and a
/// misspelling of a known name is refused instead of being taken for a section of a newer release
/// (which would lift the restriction the owner wrote).
#[test]
fn a_document_above_the_level_stays_strict_about_what_it_knows() {
    for refused in [
        // An unknown field inside a known section.
        r#"{"version": 3, "level": 2, "ceilings": {"session_limt": 4}}"#,
        r#"{"version": 3, "level": 2, "voice": {"broker_origin": null, "x": 1}}"#,
        // A misspelling, a different case, a different separator, a transposition.
        r#"{"version": 3, "level": 2, "ceilngs": {"session_limit": 4}}"#,
        r#"{"version": 3, "level": 2, "Ceilings": {"session_limit": 4}}"#,
        r#"{"version": 3, "level": 2, "default-profile": "review"}"#,
        r#"{"version": 3, "level": 2, "descriptoins": {}}"#,
        // A field written at the top level instead of inside its section.
        r#"{"version": 3, "level": 2, "session_limit": 4}"#,
        r#"{"version": 3, "level": 2, "package_bytes": 1}"#,
    ] {
        let loaded = load_in(Some(refused.as_bytes()), &R1);
        assert_eq!(loaded.status.state, DocumentState::Invalid, "{refused}");
        assert!(loaded.fails_closed());
    }

    // The detail names the known name in this build's own word and the member only by its length.
    let loaded = load_in(
        Some(br#"{"version": 3, "level": 2, "ceilngs": {"session_limit": 4}}"#),
        &R1,
    );
    let said = loaded.status.detail.as_str();
    assert!(said.contains("ceilings"), "{said}");
    assert!(!said.contains("ceilngs"), "{said}");

    // A member that is not near any name is a section of a newer release.
    let newer = load_in(
        Some(br#"{"version": 3, "level": 2, "telemetry_events": {"enabled": true}}"#),
        &R1,
    );
    assert_eq!(
        newer.status.state,
        DocumentState::Loaded,
        "{:?}",
        newer.status
    );
    assert_eq!(
        newer.newer.expect("above the level").names,
        ["telemetry_events"]
    );

    // A near miss is found among many members, though it sorts after the sixteen names kept.
    let mut crowded = serde_json::json!({"version": 3, "level": 2});
    for index in 0..20 {
        crowded[format!("aa_telemetry_{index:02}")] = serde_json::json!({});
    }
    crowded["ceilngs"] = serde_json::json!({});
    let loaded = load_in(Some(crowded.to_string().as_bytes()), &R1);
    assert_eq!(loaded.status.state, DocumentState::Invalid);

    // A guard: below the level, a misspelt member is refused as it always was.
    let loaded = load_in(
        Some(br#"{"version": 3, "ceilngs": {"session_limit": 4}}"#),
        &R1,
    );
    assert_eq!(loaded.status.state, DocumentState::Invalid);

    // A section the release lists above its level is refused whenever it is present, held or not.
    let loaded = load_in(
        Some(br#"{"version": 3, "voice": {"broker_origin": null}}"#),
        &R1_LISTING,
    );
    assert_eq!(
        loaded.status.state,
        DocumentState::Invalid,
        "{:?}",
        loaded.status
    );
}

/// KR-REQ-26.13: a report keeps at most sixteen names, each of ASCII graphic characters and at most
/// sixty-four bytes, counts the rest, and never cuts a character.
#[test]
fn the_names_a_report_keeps_are_bounded_and_printable() {
    // The names that cannot be kept sort first, so a rule that kept them would put them among the
    // sixteen; the others sort after.
    let mut value = serde_json::json!({"version": 3, "level": 2});
    for index in 0..18 {
        value[format!("zq_telemetry_{index:02}")] = serde_json::json!({});
    }
    value[format!("aa_{}", "x".repeat(70))] = serde_json::json!({});
    value["aa_\u{202e}bidirectional"] = serde_json::json!({});
    value["aa_caf\u{e9}_telemetry"] = serde_json::json!({});
    value["aa_with space"] = serde_json::json!({});
    value["aa_escape\u{1b}[31m"] = serde_json::json!({});
    value["aa_line\nfeed"] = serde_json::json!({});
    let loaded = load_in(Some(value.to_string().as_bytes()), &R1);
    assert_eq!(
        loaded.status.state,
        DocumentState::Loaded,
        "{:?}",
        loaded.status
    );
    let newer = loaded.newer.expect("above the level");
    assert_eq!(newer.count, 24, "every member left out is counted");
    assert_eq!(newer.names.len(), 16);
    assert!(
        newer
            .names
            .iter()
            .all(|name| name.starts_with("zq_telemetry_")),
        "{:?}",
        newer.names
    );
    assert!(newer.names.iter().all(|name| {
        name.len() <= 64 && name.chars().all(|character| character.is_ascii_graphic())
    }));
}

/// The words of the document's own schema are this build's, and a sentence prints them as they are;
/// anything else is withheld.
#[test]
fn a_sentence_prints_the_names_of_the_documents_own_schema() {
    for name in [
        "ceilings",
        "default_profile",
        "broker_origin",
        "package_bytes",
        "store",
    ] {
        assert!(is_known_term(name), "{name}");
        assert_eq!(Sentence::new().term(name).as_str(), name);
    }
    assert!(!is_known_term("ceilngs"));
    assert!(!Sentence::new().term("ceilngs").as_str().contains("ceilngs"));
}

/// KR-REQ-26.13: the level of the typed document, and of the copy the registry records, is the level
/// of the members this release kept, so the two are equal and a restart over an unchanged document
/// of a higher level accepts nothing again.
#[test]
fn the_typed_document_and_the_copy_the_registry_records_state_what_was_applied() {
    let held = written_at_level_two();
    let loaded = load_in(Some(held.as_bytes()), &R1_LISTING);
    let document = loaded.document.expect("used");
    assert_eq!(document.level, 1);
    let recorded = contents_in(&document, &R1_LISTING);
    assert_eq!(json(&recorded)["level"], 1, "{recorded}");
    assert!(
        json(&recorded)["voice"]["broker_origin"].is_null(),
        "{recorded}"
    );
    // `voice` is always written, so the copy is read back by the release that knows it as its own.
    let reread = load_in(Some(recorded.as_bytes()), &R1);
    assert_eq!(
        reread.document,
        Some(document),
        "the record is the document applied"
    );

    let loaded = load_in(Some(held.as_bytes()), &R2);
    assert_eq!(loaded.document.expect("used").level, 2);
}

/// KR-REQ-26.13: the predicate that leaves an unused section out of the written document, which
/// every section of a level carries on its field, says a section is unused when every one of its
/// fields is null.
#[test]
fn a_section_is_unused_when_every_field_of_it_is_null() {
    use crate::hostinfo::configuration::{StorageSelection, is_unused};

    assert!(is_unused(&StorageSelection::default()));
    assert!(!is_unused(&StorageSelection {
        origin: Nullable::some("https://storage.example.com".to_owned()),
    }));
}

/// A document that selects an authority feed, as this build writes it.
fn with_a_feed() -> ConfigurationDocument {
    let mut document = ConfigurationDocument::empty();
    document.authority.origin = Nullable::some(FEED.to_owned());
    document.ceilings.session_limit = Nullable::some(4);
    document
}

/// KR-REQ-26.13: the authority feed's selection is a section of level 2. A document that selects
/// no feed is written without the section and at level 1, and a release that reads level 1 reads
/// that file strictly, as it read the file before the section existed.
#[test]
fn an_unused_authority_section_is_not_written_and_a_release_at_level_1_reads_the_file_strictly() {
    let mut document = ConfigurationDocument::empty();
    document.ceilings.session_limit = Nullable::some(4);
    let written = contents_in(&document, &THIS_RELEASE);
    let value = json(&written);
    assert!(value.get("authority").is_none(), "{written}");
    assert_eq!(value["level"], 1, "{written}");

    let read = load_in(Some(written.as_bytes()), &BEFORE_AUTHORITY);
    assert_eq!(
        read.status.state,
        DocumentState::Loaded,
        "{:?}",
        read.status
    );
    assert!(
        read.newer.is_none(),
        "a document at the level is read strictly"
    );
    assert_eq!(
        read.document.expect("used").ceilings.session_limit.0,
        Some(4)
    );

    // An edit of a document that selects no feed leaves the section out too.
    let edited = edit_in(
        &load_in(Some(written.as_bytes()), &THIS_RELEASE),
        &Change::SessionLimit(Some(2)),
        &THIS_RELEASE,
    )
    .expect("an edit");
    assert!(json(&edited.contents).get("authority").is_none());
    assert_eq!(json(&edited.contents)["level"], 1);
}

/// KR-REQ-26.13: a release that reads level 1 takes the authority section for a section of a newer
/// release: it applies every member it knows, leaves the section out, counts and names it, does not
/// fail closed, and does not edit the document. Without the section a host takes revocations only
/// from the owners who reach it directly.
#[test]
fn a_release_at_level_1_ignores_the_authority_section_and_applies_the_rest() {
    let written = contents_in(&with_a_feed(), &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 2, "{written}");
    assert_eq!(json(&written)["authority"]["origin"], FEED, "{written}");

    let loaded = load_in(Some(written.as_bytes()), &BEFORE_AUTHORITY);
    assert_eq!(
        loaded.status.state,
        DocumentState::Loaded,
        "{:?}",
        loaded.status
    );
    assert!(!loaded.fails_closed());
    assert_eq!(
        loaded.newer,
        Some(Newer {
            declared: 2,
            count: 1,
            names: vec!["authority".to_owned()]
        })
    );
    let document = loaded.document.as_ref().expect("the document is used");
    assert_eq!(document.ceilings.session_limit.0, Some(4));
    assert_eq!(document.authority.origin(), None, "the section is left out");
    assert!(matches!(
        edit_in(&loaded, &Change::SessionLimit(Some(2)), &BEFORE_AUTHORITY),
        Err(EditRefused::NotOurs(_))
    ));
}

/// KR-REQ-26.13: the upgrade half and the round trip of an active value. A document a release at
/// level 1 wrote is read by this build as it was; once the owner selects a feed the next write is at
/// level 2 and keeps every other member; the selection survives the file, the typed document and
/// the copy the registry keeps, which is the file's reading written again.
#[test]
fn a_selected_feed_survives_the_file_and_the_registrys_copy() {
    let mut earlier = ConfigurationDocument::empty();
    earlier.ceilings.session_limit = Nullable::some(4);
    let before = contents_in(&earlier, &R1);
    let loaded = load_in(Some(before.as_bytes()), &THIS_RELEASE);
    assert_eq!(loaded.status.state, DocumentState::Loaded);
    let mut document = loaded.document.expect("used");
    assert_eq!(document.authority.origin(), None);

    document.authority.origin = Nullable::some(FEED.to_owned());
    let written = contents_in(&document, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 2, "{written}");
    assert_eq!(json(&written)["ceilings"]["session_limit"], 4, "{written}");

    let read = load_in(Some(written.as_bytes()), &THIS_RELEASE);
    assert_eq!(
        read.status.state,
        DocumentState::Loaded,
        "{:?}",
        read.status
    );
    let typed = read.document.expect("used");
    assert_eq!(typed.authority.origin(), Some(FEED));
    assert_eq!(typed.level, 2);

    let copy = contents_in(&typed, &THIS_RELEASE);
    let from_the_copy = load_in(Some(copy.as_bytes()), &THIS_RELEASE);
    assert_eq!(from_the_copy.document.as_ref(), Some(&typed));
    assert_eq!(
        copy, written,
        "the copy is the file's reading written again"
    );

    // The section is as strict as any other: a field it does not declare refuses the document.
    let stray = br#"{"version": 3, "level": 2, "authority": {"origin": "https://reach.example.com", "relay": 1}}"#;
    assert_eq!(
        load_in(Some(stray), &THIS_RELEASE).status.state,
        DocumentState::Invalid
    );
}
