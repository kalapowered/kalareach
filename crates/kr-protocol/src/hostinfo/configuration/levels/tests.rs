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
    BASE_LEVEL, Change, ConfigurationDocument, DocumentState, EditRefused, TestSuite, VERSION,
    contents_in, edit_in, is_known_term, load_in, still_current,
};
use crate::hostinfo::export::Sentence;
use crate::scalars::Nullable;
use crate::session::ShellMode;

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

/// A release that reads level 2 and predates the mailbox section: it takes the section for a
/// member of a newer release.
const BEFORE_MAILBOX: Release = Release {
    level: 2,
    levelled: &[
        Levelled {
            member: "authority",
            level: 2,
        },
        Levelled {
            member: "mailbox",
            level: 3,
        },
    ],
};

/// A release that reads level 3 and predates the relay section: it takes the section for a member
/// of a newer release.
const BEFORE_RELAY: Release = Release {
    level: 3,
    levelled: &[
        Levelled {
            member: "authority",
            level: 2,
        },
        Levelled {
            member: "mailbox",
            level: 3,
        },
        Levelled {
            member: "relay",
            level: 4,
        },
    ],
};

/// A release that reads level 4 and predates the automation section: it takes the section for a
/// member of a newer release.
const BEFORE_AUTOMATION: Release = Release {
    level: 4,
    levelled: &[
        Levelled {
            member: "authority",
            level: 2,
        },
        Levelled {
            member: "mailbox",
            level: 3,
        },
        Levelled {
            member: "relay",
            level: 4,
        },
        Levelled {
            member: "automation",
            level: 5,
        },
    ],
};

/// A release that reads level 5 and predates the shell section: it takes the section for a member
/// of a newer release.
const BEFORE_SHELL: Release = Release {
    level: 5,
    levelled: &[
        Levelled {
            member: "authority",
            level: 2,
        },
        Levelled {
            member: "mailbox",
            level: 3,
        },
        Levelled {
            member: "relay",
            level: 4,
        },
        Levelled {
            member: "automation",
            level: 5,
        },
        Levelled {
            member: "shell",
            level: 6,
        },
    ],
};

/// A release that reads level 6 and predates the push section: it takes the section for a member
/// of a newer release.
const BEFORE_PUSH: Release = Release {
    level: 6,
    levelled: &[
        Levelled {
            member: "authority",
            level: 2,
        },
        Levelled {
            member: "mailbox",
            level: 3,
        },
        Levelled {
            member: "relay",
            level: 4,
        },
        Levelled {
            member: "automation",
            level: 5,
        },
        Levelled {
            member: "shell",
            level: 6,
        },
        Levelled {
            member: "push",
            level: 7,
        },
    ],
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
/// fail closed, and does not edit the document. Without the section a host takes a device's
/// revocation only from the owner at the machine.
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
/// level 1 wrote is read by this build as it was; once the owner selects a feed the next write is
/// at level 2 and keeps every other member; the selection survives the file, the typed document and
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

/// A document that selects a mailbox service, as this build writes it.
fn with_a_mailbox() -> ConfigurationDocument {
    let mut document = ConfigurationDocument::empty();
    document.mailbox.origin = Nullable::some(FEED.to_owned());
    document.ceilings.session_limit = Nullable::some(4);
    document
}

/// KR-REQ-26.13: the mailbox service's selection is a section of level 3, and a writer stamps the
/// highest level among the sections the document holds. A document that selects only an authority
/// feed stays at level 2, so a release that reads level 2 still reads and edits it; one that
/// selects no mailbox is written without the section.
#[test]
fn a_document_is_stamped_with_the_highest_level_among_the_sections_it_holds() {
    let mut feed_only = ConfigurationDocument::empty();
    feed_only.authority.origin = Nullable::some(FEED.to_owned());
    let written = contents_in(&feed_only, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 2, "{written}");
    assert!(json(&written).get("mailbox").is_none(), "{written}");

    let mut both = feed_only;
    both.mailbox.origin = Nullable::some(FEED.to_owned());
    let written = contents_in(&both, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 3, "{written}");
    assert_eq!(json(&written)["authority"]["origin"], FEED, "{written}");
    assert_eq!(json(&written)["mailbox"]["origin"], FEED, "{written}");
}

/// KR-REQ-26.13: a release that reads level 2 takes the mailbox section for a section of a newer
/// release: it applies every member it knows, the authority feed's section included, leaves the
/// mailbox section out, counts and names it, does not fail closed, and does not edit the document.
/// Without the section a host places no object in a device's mailbox, and presents its pushes as it
/// always did.
#[test]
fn a_release_at_level_2_ignores_the_mailbox_section_and_applies_the_rest() {
    let mut document = with_a_mailbox();
    document.authority.origin = Nullable::some(FEED.to_owned());
    let written = contents_in(&document, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 3, "{written}");

    let loaded = load_in(Some(written.as_bytes()), &BEFORE_MAILBOX);
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
            declared: 3,
            count: 1,
            names: vec!["mailbox".to_owned()]
        })
    );
    let used = loaded.document.as_ref().expect("the document is used");
    assert_eq!(used.ceilings.session_limit.0, Some(4));
    assert_eq!(used.authority.origin(), Some(FEED), "level 2 is still read");
    assert_eq!(used.mailbox.origin(), None, "the section is left out");
    assert!(matches!(
        edit_in(&loaded, &Change::SessionLimit(Some(2)), &BEFORE_MAILBOX),
        Err(EditRefused::NotOurs(_))
    ));
}

/// KR-REQ-26.13: the positive control of omission. A document with no mailbox section is written
/// without it and is read, and edited, by a release that reads level 2 as it was before the
/// section existed.
#[test]
fn an_unused_mailbox_section_is_not_written_and_a_release_at_level_2_reads_the_file_strictly() {
    let mut document = ConfigurationDocument::empty();
    document.authority.origin = Nullable::some(FEED.to_owned());
    let written = contents_in(&document, &THIS_RELEASE);
    assert!(json(&written).get("mailbox").is_none(), "{written}");

    let read = load_in(Some(written.as_bytes()), &BEFORE_MAILBOX);
    assert_eq!(read.status.state, DocumentState::Loaded);
    assert!(
        read.newer.is_none(),
        "a document at the level is read strictly"
    );
    let edited = edit_in(
        &load_in(Some(written.as_bytes()), &BEFORE_MAILBOX),
        &Change::SessionLimit(Some(2)),
        &BEFORE_MAILBOX,
    )
    .expect("a release at level 2 still edits it");
    assert!(json(&edited.contents).get("mailbox").is_none());
    assert_eq!(json(&edited.contents)["level"], 2);
    assert_eq!(json(&edited.contents)["authority"]["origin"], FEED);
}

/// KR-REQ-26.13: the upgrade half and the round trip of an active value. A document a release at
/// level 2 wrote is read by this build as it was; once the owner selects a mailbox service the next
/// write is at level 3 and keeps every other member; the selection survives the file, the typed
/// document and the copy the registry keeps, which is the file's reading written again.
#[test]
fn a_selected_mailbox_survives_the_file_and_the_registrys_copy() {
    let mut earlier = ConfigurationDocument::empty();
    earlier.authority.origin = Nullable::some(FEED.to_owned());
    earlier.ceilings.session_limit = Nullable::some(4);
    let before = contents_in(&earlier, &THIS_RELEASE);
    let loaded = load_in(Some(before.as_bytes()), &THIS_RELEASE);
    assert_eq!(loaded.status.state, DocumentState::Loaded);
    let mut document = loaded.document.expect("used");
    assert_eq!(document.mailbox.origin(), None);

    document.mailbox.origin = Nullable::some(FEED.to_owned());
    let written = contents_in(&document, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 3, "{written}");
    assert_eq!(json(&written)["ceilings"]["session_limit"], 4, "{written}");
    assert_eq!(json(&written)["authority"]["origin"], FEED, "{written}");

    let read = load_in(Some(written.as_bytes()), &THIS_RELEASE);
    assert_eq!(
        read.status.state,
        DocumentState::Loaded,
        "{:?}",
        read.status
    );
    let typed = read.document.expect("used");
    assert_eq!(typed.mailbox.origin(), Some(FEED));
    assert_eq!(typed.level, 3);

    let copy = contents_in(&typed, &THIS_RELEASE);
    let from_the_copy = load_in(Some(copy.as_bytes()), &THIS_RELEASE);
    assert_eq!(from_the_copy.document.as_ref(), Some(&typed));
    assert_eq!(
        copy, written,
        "the copy is the file's reading written again"
    );

    // The section is as strict as any other: a field it does not declare refuses the document.
    let stray = br#"{"version": 3, "level": 3, "mailbox": {"origin": "https://reach.example.com", "relay": 1}}"#;
    assert_eq!(
        load_in(Some(stray), &THIS_RELEASE).status.state,
        DocumentState::Invalid
    );
}

/// A document that selects a relay lease service, as this build writes it.
fn with_a_relay() -> ConfigurationDocument {
    let mut document = ConfigurationDocument::empty();
    document.relay.origin = Nullable::some(FEED.to_owned());
    document.ceilings.session_limit = Nullable::some(4);
    document
}

/// KR-REQ-26.13: the relay lease service's selection is a section of level 4, and a writer stamps
/// the highest level among the sections the document holds. A document that selects only a mailbox
/// service stays at level 3, so a release that reads level 3 still reads and edits it; one that
/// selects no relay is written without the section.
#[test]
fn a_document_with_no_relay_section_is_stamped_below_the_relays_level() {
    let mut mailbox_only = ConfigurationDocument::empty();
    mailbox_only.mailbox.origin = Nullable::some(FEED.to_owned());
    let written = contents_in(&mailbox_only, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 3, "{written}");
    assert!(json(&written).get("relay").is_none(), "{written}");

    let mut both = mailbox_only;
    both.relay.origin = Nullable::some(FEED.to_owned());
    let written = contents_in(&both, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 4, "{written}");
    assert_eq!(json(&written)["mailbox"]["origin"], FEED, "{written}");
    assert_eq!(json(&written)["relay"]["origin"], FEED, "{written}");
}

/// KR-REQ-26.13: a release that reads level 3 takes the relay section for a section of a newer
/// release: it applies every member it knows, the mailbox section included, leaves the relay
/// section out, counts and names it, does not fail closed, and does not edit the document. Without
/// the section a host asks for no relay lease, and a device reaches it directly or through a relay
/// its owner runs.
#[test]
fn a_release_at_level_3_ignores_the_relay_section_and_applies_the_rest() {
    let mut document = with_a_relay();
    document.mailbox.origin = Nullable::some(FEED.to_owned());
    let written = contents_in(&document, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 4, "{written}");

    let loaded = load_in(Some(written.as_bytes()), &BEFORE_RELAY);
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
            declared: 4,
            count: 1,
            names: vec!["relay".to_owned()]
        })
    );
    let used = loaded.document.as_ref().expect("the document is used");
    assert_eq!(used.ceilings.session_limit.0, Some(4));
    assert_eq!(used.mailbox.origin(), Some(FEED), "level 3 is still read");
    assert_eq!(used.relay.origin(), None, "the section is left out");
    assert!(matches!(
        edit_in(&loaded, &Change::SessionLimit(Some(2)), &BEFORE_RELAY),
        Err(EditRefused::NotOurs(_))
    ));
}

/// KR-REQ-26.13: the positive control of omission. A document with no relay section is written
/// without it and is read, and edited, by a release that reads level 3 as it was before the
/// section existed.
#[test]
fn an_unused_relay_section_is_not_written_and_a_release_at_level_3_reads_the_file_strictly() {
    let mut document = ConfigurationDocument::empty();
    document.mailbox.origin = Nullable::some(FEED.to_owned());
    let written = contents_in(&document, &THIS_RELEASE);
    assert!(json(&written).get("relay").is_none(), "{written}");

    let read = load_in(Some(written.as_bytes()), &BEFORE_RELAY);
    assert_eq!(read.status.state, DocumentState::Loaded);
    assert!(
        read.newer.is_none(),
        "a document at the level is read strictly"
    );
    let edited = edit_in(&read, &Change::SessionLimit(Some(2)), &BEFORE_RELAY).expect("an edit");
    assert!(json(&edited.contents).get("relay").is_none());
    assert_eq!(json(&edited.contents)["level"], 3);
}

/// KR-REQ-26.13: the upgrade half and the round trip of an active value. A document a release at
/// level 3 wrote is read by this build as it was; once the owner selects a relay lease service the
/// next write is at level 4 and keeps every other member; the selection survives the file, the
/// typed document and the copy the registry keeps, which is the file's reading written again.
#[test]
fn a_selected_relay_survives_the_file_and_the_registrys_copy() {
    let mut earlier = ConfigurationDocument::empty();
    earlier.mailbox.origin = Nullable::some(FEED.to_owned());
    earlier.ceilings.session_limit = Nullable::some(4);
    let before = contents_in(&earlier, &THIS_RELEASE);
    let loaded = load_in(Some(before.as_bytes()), &THIS_RELEASE);
    assert_eq!(loaded.status.state, DocumentState::Loaded);
    let mut document = loaded.document.expect("used");
    assert_eq!(document.relay.origin(), None);

    document.relay = with_a_relay().relay;
    let written = contents_in(&document, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 4, "{written}");
    assert_eq!(json(&written)["ceilings"]["session_limit"], 4, "{written}");
    assert_eq!(json(&written)["mailbox"]["origin"], FEED, "{written}");
    assert_eq!(json(&written)["relay"]["origin"], FEED, "{written}");

    let read = load_in(Some(written.as_bytes()), &THIS_RELEASE);
    assert_eq!(
        read.status.state,
        DocumentState::Loaded,
        "{:?}",
        read.status
    );
    let typed = read.document.expect("used");
    assert_eq!(typed.relay.origin(), Some(FEED));
    assert_eq!(typed.level, 4);

    let copy = contents_in(&typed, &THIS_RELEASE);
    let from_the_copy = load_in(Some(copy.as_bytes()), &THIS_RELEASE);
    assert_eq!(from_the_copy.document.as_ref(), Some(&typed));
    assert_eq!(
        copy, written,
        "the copy is the file's reading written again"
    );

    // The section is as strict as any other: a field it does not declare refuses the document.
    let stray = br#"{"version": 3, "level": 4, "relay": {"origin": "https://reach.example.com", "region": "eu"}}"#;
    assert_eq!(
        load_in(Some(stray), &THIS_RELEASE).status.state,
        DocumentState::Invalid
    );
    let stray = br#"{"version": 3, "level": 4, "relay": {"origin": "https://reach.example.com", "payer": {"account_id": "0b0c4a1e-2f6a-4a7c-9b7e-5d1f3c2a8e41", "authorisation_id": "7c1d9e52-3b4f-4d86-a0c2-91e5f6b73d08", "ceiling": 1}}}"#;
    assert_eq!(
        load_in(Some(stray), &THIS_RELEASE).status.state,
        DocumentState::Invalid
    );
}

/// A suite as an owner writes it.
fn a_suite() -> TestSuite {
    TestSuite {
        command: "cargo test --workspace".to_owned(),
        outputs: vec!["target".to_owned()],
    }
}

/// A document that names a test suite, as this build writes it.
fn with_a_suite() -> ConfigurationDocument {
    let mut document = ConfigurationDocument::empty();
    document.automation.test_suites =
        Nullable::some([("unit".to_owned(), a_suite())].into_iter().collect());
    document.ceilings.session_limit = Nullable::some(4);
    document
}

/// The automation section is a section of level 5, and a writer stamps the highest level among
/// the sections the document holds. A document that selects only a relay stays at level 4, so a
/// release that reads level 4 still reads and edits it; one that names no suite is written without
/// the section.
#[test]
fn a_document_with_no_automation_section_is_stamped_below_the_sections_level() {
    let mut relay_only = ConfigurationDocument::empty();
    relay_only.relay.origin = Nullable::some(FEED.to_owned());
    let written = contents_in(&relay_only, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 4, "{written}");
    assert!(json(&written).get("automation").is_none(), "{written}");

    let mut both = relay_only;
    both.automation.test_suites =
        Nullable::some([("unit".to_owned(), a_suite())].into_iter().collect());
    let written = contents_in(&both, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 5, "{written}");
    assert_eq!(json(&written)["relay"]["origin"], FEED, "{written}");
    assert_eq!(
        json(&written)["automation"]["test_suites"]["unit"]["command"],
        "cargo test --workspace",
        "{written}"
    );
}

/// A release that reads level 4 takes the automation section for a section of a newer release: it
/// applies every member it knows, leaves the section out, counts and names it, does not fail
/// closed, and does not edit the document. Without the section a host runs no suite for a
/// workflow.
#[test]
fn a_release_at_level_4_ignores_the_automation_section_and_applies_the_rest() {
    let mut document = with_a_suite();
    document.relay.origin = Nullable::some(FEED.to_owned());
    let written = contents_in(&document, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 5, "{written}");

    let loaded = load_in(Some(written.as_bytes()), &BEFORE_AUTOMATION);
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
            declared: 5,
            count: 1,
            names: vec!["automation".to_owned()]
        })
    );
    let used = loaded.document.as_ref().expect("the document is used");
    assert_eq!(used.ceilings.session_limit.0, Some(4));
    assert_eq!(used.relay.origin(), Some(FEED), "level 4 is still read");
    assert!(
        used.automation.suites().is_empty(),
        "the section is left out"
    );
    assert!(matches!(
        edit_in(&loaded, &Change::SessionLimit(Some(2)), &BEFORE_AUTOMATION),
        Err(EditRefused::NotOurs(_))
    ));
}

/// The positive control of omission, and the round trip of an active value: a document with no
/// suite is written without the section and is read, and edited, by a release at level 4 as it was
/// before the section existed; once a suite is named the next write is at level 5 and keeps every
/// other member, and the suite survives the file, the typed document and the registry's copy.
#[test]
fn a_named_suite_survives_the_file_and_the_registrys_copy() {
    let mut earlier = ConfigurationDocument::empty();
    earlier.relay.origin = Nullable::some(FEED.to_owned());
    earlier.ceilings.session_limit = Nullable::some(4);
    let before = contents_in(&earlier, &THIS_RELEASE);
    assert!(json(&before).get("automation").is_none(), "{before}");
    let read = load_in(Some(before.as_bytes()), &BEFORE_AUTOMATION);
    assert_eq!(read.status.state, DocumentState::Loaded);
    assert!(
        read.newer.is_none(),
        "a document at the level is read strictly"
    );

    let mut document = load_in(Some(before.as_bytes()), &THIS_RELEASE)
        .document
        .expect("used");
    document.automation = with_a_suite().automation;
    let written = contents_in(&document, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 5, "{written}");
    assert_eq!(json(&written)["ceilings"]["session_limit"], 4, "{written}");
    assert_eq!(json(&written)["relay"]["origin"], FEED, "{written}");

    let read = load_in(Some(written.as_bytes()), &THIS_RELEASE);
    assert_eq!(
        read.status.state,
        DocumentState::Loaded,
        "{:?}",
        read.status
    );
    let typed = read.document.expect("used");
    assert_eq!(typed.automation.suites().get("unit"), Some(&a_suite()));
    assert_eq!(typed.level, 5);
    let copy = contents_in(&typed, &THIS_RELEASE);
    assert_eq!(
        load_in(Some(copy.as_bytes()), &THIS_RELEASE)
            .document
            .as_ref(),
        Some(&typed)
    );
    assert_eq!(
        copy, written,
        "the copy is the file's reading written again"
    );

    // The section is as strict as any other: a member it does not declare refuses the document.
    for stray in [
        r#"{"version": 3, "level": 5, "automation": {"test_suites": {}, "region": "eu"}}"#,
        r#"{"version": 3, "level": 5, "automation": {"test_suites": {"unit": {"command": "true", "shell": "zsh"}}}}"#,
    ] {
        assert_eq!(
            load_in(Some(stray.as_bytes()), &THIS_RELEASE).status.state,
            DocumentState::Invalid,
            "{stray}"
        );
    }
}

/// A document that chooses a default shell mode, as this build writes it.
fn with_a_shell_mode() -> ConfigurationDocument {
    let mut document = ConfigurationDocument::empty();
    document.shell.mode = Nullable::some(ShellMode::NativeCompat);
    document.ceilings.session_limit = Nullable::some(4);
    document
}

/// The shell section is a section of level 6, and a writer stamps the highest level among the
/// sections the document holds. A document that holds only an automation suite stays at level 5,
/// so a release that reads level 5 still reads and edits it; one that chooses no mode is written
/// without the section.
#[test]
fn a_document_with_no_shell_section_is_stamped_below_the_sections_level() {
    let mut suite_only = ConfigurationDocument::empty();
    suite_only.automation.test_suites =
        Nullable::some([("unit".to_owned(), a_suite())].into_iter().collect());
    let written = contents_in(&suite_only, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 5, "{written}");
    assert!(json(&written).get("shell").is_none(), "{written}");

    let mut both = suite_only;
    both.shell.mode = Nullable::some(ShellMode::Managed);
    let written = contents_in(&both, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 6, "{written}");
    assert_eq!(json(&written)["shell"]["mode"], "managed", "{written}");
    assert_eq!(
        json(&written)["automation"]["test_suites"]["unit"]["command"],
        "cargo test --workspace",
        "{written}"
    );
}

/// A release that reads level 5 takes the shell section for a section of a newer release: it
/// applies every member it knows, leaves the section out, counts and names it, does not fail
/// closed, and does not edit the document. Without the section it creates a session in the mode
/// its own command names.
#[test]
fn a_release_at_level_5_ignores_the_shell_section_and_applies_the_rest() {
    let mut document = with_a_shell_mode();
    document.relay.origin = Nullable::some(FEED.to_owned());
    let written = contents_in(&document, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 6, "{written}");

    let loaded = load_in(Some(written.as_bytes()), &BEFORE_SHELL);
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
            declared: 6,
            count: 1,
            names: vec!["shell".to_owned()]
        })
    );
    let used = loaded.document.as_ref().expect("the document is used");
    assert_eq!(used.ceilings.session_limit.0, Some(4));
    assert_eq!(used.relay.origin(), Some(FEED), "level 4 is still read");
    assert_eq!(used.shell.mode(), None, "the section is left out");
    assert!(matches!(
        edit_in(&loaded, &Change::SessionLimit(Some(2)), &BEFORE_SHELL),
        Err(EditRefused::NotOurs(_))
    ));
}

/// The positive control of omission, and the round trip of an active value: a document that
/// chooses no mode is written without the section and is read, and edited, by a release at level
/// 5 as it was before the section existed; once a mode is chosen the next write is at level 6 and
/// keeps every other member, and the choice survives the file, the typed document and the
/// registry's copy.
#[test]
fn a_chosen_shell_mode_survives_the_file_and_the_registrys_copy() {
    let mut earlier = ConfigurationDocument::empty();
    earlier.relay.origin = Nullable::some(FEED.to_owned());
    earlier.ceilings.session_limit = Nullable::some(4);
    let before = contents_in(&earlier, &THIS_RELEASE);
    assert!(json(&before).get("shell").is_none(), "{before}");
    let read = load_in(Some(before.as_bytes()), &BEFORE_SHELL);
    assert_eq!(read.status.state, DocumentState::Loaded);
    assert!(
        read.newer.is_none(),
        "a document at the level is read strictly"
    );

    let mut document = load_in(Some(before.as_bytes()), &THIS_RELEASE)
        .document
        .expect("used");
    document.shell = with_a_shell_mode().shell;
    let written = contents_in(&document, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 6, "{written}");
    assert_eq!(json(&written)["ceilings"]["session_limit"], 4, "{written}");
    assert_eq!(json(&written)["relay"]["origin"], FEED, "{written}");

    let read = load_in(Some(written.as_bytes()), &THIS_RELEASE);
    assert_eq!(
        read.status.state,
        DocumentState::Loaded,
        "{:?}",
        read.status
    );
    let typed = read.document.expect("used");
    assert_eq!(typed.shell.mode(), Some(ShellMode::NativeCompat));
    assert_eq!(typed.level, 6);
    let copy = contents_in(&typed, &THIS_RELEASE);
    assert_eq!(
        load_in(Some(copy.as_bytes()), &THIS_RELEASE)
            .document
            .as_ref(),
        Some(&typed)
    );
    assert_eq!(
        copy, written,
        "the copy is the file's reading written again"
    );

    // The section is as strict as any other: a member it does not declare refuses the document.
    for stray in [
        r#"{"version": 3, "level": 6, "shell": {"mode": "managed", "fallback": true}}"#,
        r#"{"version": 3, "level": 6, "shell": {"mode": "stock"}}"#,
    ] {
        assert_eq!(
            load_in(Some(stray.as_bytes()), &THIS_RELEASE).status.state,
            DocumentState::Invalid,
            "{stray}"
        );
    }
}

/// Two gateways besides the official one, one of them on a loopback address.
const GATEWAYS: [&str; 2] = ["https://push.builder.example", "http://127.0.0.1:8788"];

/// A document that lists gateways, as this build writes it.
fn with_gateways() -> ConfigurationDocument {
    let mut document = ConfigurationDocument::empty();
    document.push.gateways =
        Nullable::some(GATEWAYS.iter().map(|&origin| origin.to_owned()).collect());
    document.ceilings.session_limit = Nullable::some(4);
    document
}

/// KR-REQ-16.04: the push section is a section of level 7, and a writer stamps the highest level
/// among the sections the document holds. A document that lists no gateway, or whose list is null,
/// is written without the section and below level 7; an empty list is held, because it says that
/// no gateway besides the official one is allowed.
#[test]
fn a_document_that_lists_no_gateway_is_stamped_below_the_sections_level() {
    let mut shell_only = ConfigurationDocument::empty();
    shell_only.shell.mode = Nullable::some(ShellMode::Managed);
    let written = contents_in(&shell_only, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 6, "{written}");
    assert!(json(&written).get("push").is_none(), "{written}");

    let mut both = shell_only;
    both.push.gateways = Nullable::some(vec![GATEWAYS[0].to_owned()]);
    let written = contents_in(&both, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 7, "{written}");
    assert_eq!(
        json(&written)["push"]["gateways"][0],
        GATEWAYS[0],
        "{written}"
    );
    assert_eq!(json(&written)["shell"]["mode"], "managed", "{written}");

    let mut empty_list = ConfigurationDocument::empty();
    empty_list.push.gateways = Nullable::some(Vec::new());
    let written = contents_in(&empty_list, &THIS_RELEASE);
    assert_eq!(
        json(&written)["level"],
        7,
        "an empty list is held: {written}"
    );
    assert_eq!(
        json(&written)["push"]["gateways"],
        serde_json::json!([]),
        "{written}"
    );
}

/// A release that reads level 6 takes the push section for a section of a newer release: it applies
/// every member it knows, leaves the section out, counts and names it, does not fail closed, and
/// does not edit the document.
#[test]
fn a_release_at_level_6_ignores_the_push_section_and_applies_the_rest() {
    let mut document = with_gateways();
    document.shell.mode = Nullable::some(ShellMode::NativeCompat);
    let written = contents_in(&document, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 7, "{written}");

    let loaded = load_in(Some(written.as_bytes()), &BEFORE_PUSH);
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
            declared: 7,
            count: 1,
            names: vec!["push".to_owned()]
        })
    );
    let used = loaded.document.as_ref().expect("the document is used");
    assert_eq!(used.ceilings.session_limit.0, Some(4));
    assert_eq!(
        used.shell.mode(),
        Some(ShellMode::NativeCompat),
        "level 6 is still read"
    );
    assert!(used.push.gateways().is_empty(), "the section is left out");
    assert!(matches!(
        edit_in(&loaded, &Change::SessionLimit(Some(2)), &BEFORE_PUSH),
        Err(EditRefused::NotOurs(_))
    ));
}

/// The positive control of omission, and the round trip of an active value: a document that lists
/// no gateway is read and edited by a release at level 6 as it was before the section existed; once
/// gateways are listed the next write is at level 7 and keeps every other member, and the list
/// survives the file, the typed document and the registry's copy.
#[test]
fn a_listed_gateway_survives_the_file_and_the_registrys_copy() {
    let mut earlier = ConfigurationDocument::empty();
    earlier.shell.mode = Nullable::some(ShellMode::Managed);
    earlier.ceilings.session_limit = Nullable::some(4);
    let before = contents_in(&earlier, &THIS_RELEASE);
    let read = load_in(Some(before.as_bytes()), &BEFORE_PUSH);
    assert_eq!(read.status.state, DocumentState::Loaded);
    assert!(
        read.newer.is_none(),
        "a document at the level is read strictly"
    );

    let mut document = load_in(Some(before.as_bytes()), &THIS_RELEASE)
        .document
        .expect("used");
    document.push = with_gateways().push;
    let written = contents_in(&document, &THIS_RELEASE);
    assert_eq!(json(&written)["level"], 7, "{written}");
    assert_eq!(json(&written)["ceilings"]["session_limit"], 4, "{written}");
    assert_eq!(json(&written)["shell"]["mode"], "managed", "{written}");

    let read = load_in(Some(written.as_bytes()), &THIS_RELEASE);
    assert_eq!(
        read.status.state,
        DocumentState::Loaded,
        "{:?}",
        read.status
    );
    let typed = read.document.expect("used");
    assert_eq!(typed.push.gateways(), GATEWAYS);
    assert_eq!(typed.level, 7);
    let copy = contents_in(&typed, &THIS_RELEASE);
    assert_eq!(
        load_in(Some(copy.as_bytes()), &THIS_RELEASE)
            .document
            .as_ref(),
        Some(&typed)
    );
    assert_eq!(
        copy, written,
        "the copy is the file's reading written again"
    );

    // The section is as strict as any other.
    for stray in [
        r#"{"version": 3, "level": 7, "push": {"gateways": [], "fallback": true}}"#,
        r#"{"version": 3, "level": 7, "push": {"gateways": "https://push.builder.example"}}"#,
    ] {
        assert_eq!(
            load_in(Some(stray.as_bytes()), &THIS_RELEASE).status.state,
            DocumentState::Invalid,
            "{stray}"
        );
    }
}

/// KR-REQ-16.04: an origin in the list is what a gateway origin is everywhere else, the official
/// gateway is never listed, no origin is listed twice and no more than sixteen are. Each refusal
/// names `push.gateways`, and a document that holds the section but states a level below 7 is
/// refused by name as well, so a hand-written document cannot slip a list past a release that
/// would ignore it.
#[test]
fn the_list_of_gateways_is_refused_by_name_when_an_entry_is_not_an_allowed_origin() {
    let long = format!("https://{}.example", "a".repeat(130));
    let many: Vec<String> = (0..17)
        .map(|n| format!("https://push{n}.example"))
        .collect();
    let refused: Vec<(&str, Vec<String>)> = vec![
        ("no scheme", vec!["push.builder.example".to_owned()]),
        (
            "plain http off loopback",
            vec!["http://push.builder.example".to_owned()],
        ),
        (
            "a path",
            vec!["https://push.builder.example/api".to_owned()],
        ),
        (
            "a trailing slash",
            vec!["https://push.builder.example/".to_owned()],
        ),
        (
            "upper case",
            vec!["https://PUSH.builder.example".to_owned()],
        ),
        (
            "the default port spelled out",
            vec!["https://push.builder.example:443".to_owned()],
        ),
        (
            "user information",
            vec!["https://user@push.builder.example".to_owned()],
        ),
        ("too long", vec![long]),
        ("empty", vec![String::new()]),
        (
            "the official gateway",
            vec![crate::service::OFFICIAL_GATEWAY_ORIGIN.to_owned()],
        ),
        (
            "a duplicate",
            vec![
                GATEWAYS[0].to_owned(),
                GATEWAYS[1].to_owned(),
                GATEWAYS[0].to_owned(),
            ],
        ),
        ("seventeen", many),
    ];
    for (why, list) in refused {
        let mut document = ConfigurationDocument::empty();
        document.push.gateways = Nullable::some(list.clone());
        document.level = 7;
        let text = serde_json::to_string(&document).expect("serialises");
        let loaded = load_in(Some(text.as_bytes()), &THIS_RELEASE);
        assert_eq!(
            loaded.status.state,
            DocumentState::Invalid,
            "{why}: {list:?}"
        );
        let said = loaded.status.detail.to_string();
        assert!(said.contains("push.gateways"), "{why}: {said}");
        // The edit refuses the same list, by the same name, and writes nothing.
        let refused = edit_in(
            &load_in(None, &THIS_RELEASE),
            &Change::PushGateways(Some(list.clone())),
            &THIS_RELEASE,
        );
        match refused {
            Err(EditRefused::Invalid(problems)) => assert!(
                problems
                    .iter()
                    .any(|problem| problem.to_string().contains("push.gateways")),
                "{why}: {problems:?}"
            ),
            other => panic!("{why}: the edit was not refused by name: {other:?}"),
        }
    }

    // The control: the same document with allowed origins is read.
    let accepted = r#"{"version": 3, "level": 7, "push": {"gateways": ["https://push.builder.example", "http://127.0.0.1:8788"]}}"#;
    assert_eq!(
        load_in(Some(accepted.as_bytes()), &THIS_RELEASE)
            .status
            .state,
        DocumentState::Loaded
    );
    // A level below the section's is refused by name, an empty list included.
    for low in [
        r#"{"version": 3, "level": 6, "push": {"gateways": ["https://push.builder.example"]}}"#,
        r#"{"version": 3, "push": {"gateways": []}}"#,
    ] {
        let loaded = load_in(Some(low.as_bytes()), &THIS_RELEASE);
        assert_eq!(loaded.status.state, DocumentState::Invalid, "{low}");
        assert!(
            loaded.status.detail.to_string().contains("push"),
            "{low}: {:?}",
            loaded.status
        );
    }
}

/// KR-REQ-16.04: the edit sets the whole list, stamps level 7 itself, takes effect at once, changes
/// no other member, and clearing it writes the document without the section at the level the rest
/// of it needs.
#[test]
fn the_edit_sets_the_list_of_gateways_and_clearing_it_leaves_no_section_behind() {
    let change = Change::PushGateways(Some(
        GATEWAYS.iter().map(|&origin| origin.to_owned()).collect(),
    ));
    assert_eq!(change.key(), "push.gateways");
    assert_eq!(
        change.effect(),
        crate::hostinfo::configuration::ValueEffect::Immediately
    );

    let power = Change::SessionLimit(Some(3));
    let base = edit_in(&load_in(None, &THIS_RELEASE), &power, &THIS_RELEASE).expect("an edit");
    let first = edit_in(
        &load_in(Some(base.contents.as_bytes()), &THIS_RELEASE),
        &change,
        &THIS_RELEASE,
    )
    .expect("an edit");
    assert_eq!(first.document.level, 7);
    assert_eq!(first.document.push.gateways(), GATEWAYS);
    assert_eq!(first.document.ceilings.session_limit.0, Some(3));
    assert_eq!(first.revision, 2);

    let cleared = edit_in(
        &load_in(Some(first.contents.as_bytes()), &THIS_RELEASE),
        &Change::PushGateways(None),
        &THIS_RELEASE,
    )
    .expect("an edit");
    assert!(cleared.document.push.gateways().is_empty());
    assert_eq!(cleared.document.level, 1, "nothing of level 7 is held");
    assert!(
        json(&cleared.contents).get("push").is_none(),
        "{}",
        cleared.contents
    );
    assert_eq!(cleared.document.ceilings.session_limit.0, Some(3));
}

/// The report lists the gateways in force, by location, or `none`, and says the list applies at
/// once. A document nobody can read decides nothing, so the report goes on saying what is in
/// force and not what the absent document would have said.
#[test]
fn the_report_lists_the_gateways_in_force_and_says_they_apply_at_once() {
    use crate::hostinfo::configuration::{PUSH_GATEWAYS_KEY, ValueEffect, ValueSource, push_row};

    let none = push_row(&[], None, "/state/configuration.json");
    assert_eq!(none.key, PUSH_GATEWAYS_KEY);
    assert!(
        crate::hostinfo::configuration::is_known_term(&none.key),
        "the report prints the name of the row as it is, not as its class and length"
    );
    assert_eq!(none.source, ValueSource::Default);
    assert_eq!(none.effect, ValueEffect::Immediately);
    assert_eq!(none.value(), "none");

    let document = with_gateways();
    let in_force = document.push.gateways().to_vec();
    let listed = push_row(&in_force, Some(&document), "/state/configuration.json");
    assert_eq!(listed.source, ValueSource::HostConfiguration);
    assert_eq!(listed.effect, ValueEffect::Immediately);
    let shown = listed.value();
    assert!(
        shown.contains(GATEWAYS[0]) && shown.contains(GATEWAYS[1]),
        "{shown}"
    );

    // The document is gone or unusable and the host still delivers through the list it had.
    let carried = push_row(&in_force, None, "/state/configuration.json");
    assert_eq!(carried.source, ValueSource::HostConfiguration);
    assert_eq!(carried.value(), listed.value());

    // The list is empty by the document's own word: held at level 7, and the row says it was
    // written.
    let mut cleared = ConfigurationDocument::empty();
    cleared.push.gateways = Nullable::some(Vec::new());
    let emptied = push_row(&[], Some(&cleared), "/state/configuration.json");
    assert_eq!(emptied.source, ValueSource::HostConfiguration);
    assert_eq!(emptied.value(), "none");
}
