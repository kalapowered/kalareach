//! The lock's rules for a document that has levels.
//!
//! The policy tests (the level window, the digests, the names and the shape) are driven over
//! values built from a document schema of the test's own, as the existing cases drive the lock over
//! stores of their own. The eligibility tests (what the real reader and writer say of a section)
//! go through `observe` over the real configuration document, with a release of the test's own.

use kr_protocol::hostinfo::configuration::{
    ConfigurationDocument, Levelled, NEAR_MISS, Release, VERSION,
};
use kr_protocol::update::{Recording, ReleaseStore, StoreScope};
use serde_json::{Value, json};

use super::{
    Claim, Kept, Levels, Lock, Observed, Store, Writers, at_base, digest, findings, levels_view,
    observe, table, write,
};

const TELEMETRY: Levelled = Levelled {
    member: "telemetry",
    level: 2,
};
const RELAYS: Levelled = Levelled {
    member: "relays",
    level: 3,
};

fn release(level: u64, levelled: &'static [Levelled]) -> Release {
    Release { level, levelled }
}

fn nullable(inner: Value) -> Value {
    json!({ "anyOf": [inner, { "type": "null" }], "default": null })
}

/// A document schema with two base sections and the definitions that two sections of a level
/// share.
fn document() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "version": { "type": "integer", "default": 3 },
            "level": { "type": "integer", "default": 1 },
            "preferences": { "$ref": "#/$defs/Preferences", "default": { "sleep": null } },
            "storage": { "$ref": "#/$defs/Storage", "default": { "origin": null } },
            "telemetry": { "$ref": "#/$defs/Telemetry", "default": { "origin": null, "limits": null } },
            "relays": { "$ref": "#/$defs/Relays", "default": { "urls": null, "limits": null } }
        },
        "$defs": {
            "Preferences": {
                "type": "object", "additionalProperties": false,
                "properties": { "sleep": nullable(json!({ "type": "string" })) }
            },
            "Storage": {
                "type": "object", "additionalProperties": false,
                "properties": { "origin": nullable(json!({ "type": "string" })) }
            },
            "Telemetry": {
                "type": "object", "additionalProperties": false,
                "properties": {
                    "origin": nullable(json!({ "type": "string" })),
                    "limits": nullable(json!({ "$ref": "#/$defs/Limits" }))
                }
            },
            "Relays": {
                "type": "object", "additionalProperties": false,
                "properties": {
                    "urls": nullable(json!({ "type": "array", "items": { "type": "string" } })),
                    "limits": nullable(json!({ "$ref": "#/$defs/Limits" }))
                }
            },
            "Limits": {
                "type": "object", "additionalProperties": false,
                "properties": { "bytes": nullable(json!({ "type": "integer" })) }
            }
        }
    })
}

fn entry(version: u32) -> ReleaseStore {
    ReleaseStore {
        store: "configuration".to_owned(),
        scope: StoreScope::Configuration,
        path: "config.json".to_owned(),
        recording: Recording::JsonMember {
            member: "version".to_owned(),
            absent: 1,
        },
        version,
        migrates_from: 1,
    }
}

/// What the code says of the synthetic store: its base digest, and its levels from the schema.
fn observed(version: u32, base: &str, document: &Value, release: &Release) -> Observed {
    Observed {
        entry: entry(version),
        digest: base.to_owned(),
        kept: vec!["ConfigurationDocument".to_owned()],
        levels: Some(levels_view(document, release)),
    }
}

fn messages(found: &[String]) -> String {
    found.join(" | ")
}

fn designs(document: &Value, release: &Release) -> Vec<String> {
    super::design_findings(&levels_view(document, release))
}

/// A section arrives with a level at the same version and the lock follows it; the section is held
/// to its level, its digest and the level it arrives at.
#[test]
fn a_section_arrives_with_a_level_without_a_version_and_is_held_to_it_afterwards() {
    let one = release(1, &[]);
    let two = release(2, &[TELEMETRY]);
    let schema = document();
    let lock = write(None, &[observed(VERSION as u32, "aa", &schema, &one)], &[])
        .expect("a first lock is written");

    // The code now has a section at level 2 and the version has not moved: the lock is behind, and
    // the writer brings it up.
    let now = [observed(VERSION as u32, "aa", &schema, &two)];
    let found = findings(&lock, &now, &[]);
    assert!(
        messages(&found).contains("telemetry") && messages(&found).contains("write the lock"),
        "{found:?}"
    );
    let lock2 =
        write(Some(&lock), &now, &[]).expect("a level is raised with a section, no version");
    assert!(
        findings(&lock2, &now, &[]).is_empty(),
        "the lock matches the code"
    );
    let stores = &lock2.stores[0];
    assert_eq!((stores.level, stores.members.len()), (Some(2), 1));

    // The section's digest moved with the version standing still: nothing is written, and the
    // check says to raise the version.
    let mut changed = schema.clone();
    changed["$defs"]["Telemetry"]["properties"]["origin"] = nullable(json!({ "type": "integer" }));
    let moved = [observed(VERSION as u32, "aa", &changed, &two)];
    let found = findings(&lock2, &moved, &[]);
    assert!(messages(&found).contains("raise the version"), "{found:?}");
    let refused = write(Some(&lock2), &moved, &[]).expect_err("is not written");
    assert!(messages(&refused).contains("raise it first"), "{refused:?}");
    // A raise of the version may change it, and the level stays.
    let raised = [observed(VERSION as u32 + 1, "bb", &changed, &two)];
    write(Some(&lock2), &raised, &[]).expect("a raised version may change a section");

    // The base digest moved at the same version: the store's own rule.
    let base_moved = [observed(VERSION as u32, "bb", &schema, &two)];
    assert!(write(Some(&lock2), &base_moved, &[]).is_err());

    // A section dropped with the version standing still is refused; with it raised it is not.
    let dropped = [observed(VERSION as u32, "aa", &schema, &one)];
    let refused = write(Some(&lock2), &dropped, &[]).expect_err("a section does not leave");
    assert!(
        messages(&refused).contains("raise the version first"),
        "{refused:?}"
    );
    // And a level never goes down, even with the version raised.
    let lowered = [observed(VERSION as u32 + 1, "cc", &schema, &one)];
    let refused = write(Some(&lock2), &lowered, &[]).expect_err("a level never goes down");
    assert!(messages(&refused).contains("would go down"), "{refused:?}");

    // A section's level never changes.
    let moved_level = [observed(
        VERSION as u32,
        "aa",
        &schema,
        &release(
            3,
            &[Levelled {
                member: "telemetry",
                level: 3,
            }],
        ),
    )];
    let refused = write(Some(&lock2), &moved_level, &[]).expect_err("a level does not change");
    assert!(messages(&refused).contains("would change"), "{refused:?}");

    // A second section must arrive above the level the store was at, and no higher than it is now.
    let three = release(3, &[TELEMETRY, RELAYS]);
    write(
        Some(&lock2),
        &[observed(VERSION as u32, "aa", &schema, &three)],
        &[],
    )
    .expect("a section above the level the store was at");
    let at_the_old_level = release(
        3,
        &[
            TELEMETRY,
            Levelled {
                member: "relays",
                level: 2,
            },
        ],
    );
    let refused = write(
        Some(&lock2),
        &[observed(VERSION as u32, "aa", &schema, &at_the_old_level)],
        &[],
    )
    .expect_err("a section cannot claim a level an earlier release already had");
    assert!(
        messages(&refused).contains("above the level"),
        "{refused:?}"
    );
}

/// The level and the distance never go down, with no section at all, and at a raised version.
#[test]
fn the_level_and_the_distance_never_go_down_even_with_no_sections() {
    let schema = document();
    let two = release(2, &[]);
    let lock = write(None, &[observed(VERSION as u32, "aa", &schema, &two)], &[]).expect("a lock");
    let mut lowered = observed(VERSION as u32 + 1, "aa", &schema, &release(1, &[]));
    assert!(
        write(Some(&lock), &[lowered], &[]).is_err(),
        "a level goes down"
    );
    lowered = observed(VERSION as u32 + 1, "aa", &schema, &two);
    lowered.levels.as_mut().expect("levels").near_miss =
        u32::try_from(NEAR_MISS).expect("small") - 1;
    let refused = write(Some(&lock), &[lowered], &[]).expect_err("the distance goes down");
    assert!(messages(&refused).contains("misspelling"), "{refused:?}");
}

/// A change to a document schema that a rule must refuse.
type Mutation = fn(&mut Value);

/// What a section may be: an object that cannot be null and is closed, whose fields are nullable
/// with a null default, whose own default is none or all null, and that refers to nothing the
/// document's definitions do not hold. Each refusal holds at a raised version too.
#[test]
fn the_shape_of_a_section_is_held_to_the_rule_at_every_version() {
    let two = release(2, &[TELEMETRY]);
    assert!(
        designs(&document(), &two).is_empty(),
        "{:?}",
        designs(&document(), &two)
    );

    let mutations: [(&str, Mutation); 7] = [
        ("cannot be null", |schema| {
            schema["properties"]["telemetry"] = nullable(json!({ "$ref": "#/$defs/Telemetry" }));
        }),
        ("cannot be null, so absent", |schema| {
            schema["$defs"]["Telemetry"]["properties"]["origin"] =
                json!({ "type": "string", "default": null });
        }),
        ("whose default is not null", |schema| {
            schema["$defs"]["Telemetry"]["properties"]["origin"]["default"] = json!("x");
        }),
        ("not closed", |schema| {
            schema["$defs"]["Telemetry"]["additionalProperties"] = json!(true);
        }),
        ("not closed", |schema| {
            schema["$defs"]["Limits"]["additionalProperties"] = json!(true);
        }),
        ("do not hold", |schema| {
            schema["$defs"]["Telemetry"]["properties"]["limits"] =
                nullable(json!({ "$ref": "#/$defs/Elsewhere" }));
        }),
        ("not the all-null value", |schema| {
            schema["properties"]["telemetry"]["default"] = json!({ "origin": "x", "limits": null });
        }),
    ];
    for (needle, mutate) in mutations {
        let mut schema = document();
        mutate(&mut schema);
        let found = designs(&schema, &two);
        assert!(messages(&found).contains(needle), "{needle}: {found:?}");
        let lock = write(
            None,
            &[observed(
                VERSION as u32,
                "aa",
                &document(),
                &release(1, &[]),
            )],
            &[],
        )
        .expect("a lock");
        let refused = write(
            Some(&lock),
            &[observed(VERSION as u32 + 1, "aa", &schema, &two)],
            &[],
        )
        .expect_err("a version raise does not waive the shape");
        assert!(messages(&refused).contains(needle), "{needle}: {refused:?}");
    }

    // A map inside the section is not an object that declares properties, and is allowed.
    let mut schema = document();
    schema["$defs"]["Telemetry"]["properties"]["origin"] =
        nullable(json!({ "type": "object", "additionalProperties": { "type": "string" } }));
    assert!(
        designs(&schema, &two).is_empty(),
        "{:?}",
        designs(&schema, &two)
    );
}

/// The names of a section are held to the rules every release in the field applies to them: it is
/// declared once, names a property, is ASCII snake case, and is not within the distance of any
/// other property or of any name below one.
#[test]
fn the_name_of_a_section_is_held_to_what_a_release_in_the_field_applies() {
    let schema = document();
    let twice = designs(&schema, &release(2, &[TELEMETRY, TELEMETRY]));
    assert!(messages(&twice).contains("more than once"), "{twice:?}");
    let missing = designs(
        &schema,
        &release(
            2,
            &[Levelled {
                member: "telemtry",
                level: 2,
            }],
        ),
    );
    assert!(
        messages(&missing).contains("names no property"),
        "{missing:?}"
    );

    let mut odd = document();
    odd["properties"]["Odd-Name"] = odd["properties"]["telemetry"].clone();
    let found = designs(
        &odd,
        &release(
            2,
            &[Levelled {
                member: "Odd-Name",
                level: 2,
            }],
        ),
    );
    assert!(messages(&found).contains("snake case"), "{found:?}");

    // Within two edits of a base property, of a name below one, and of another section.
    const NEAR_STORAGE: &[Levelled] = &[Levelled {
        member: "storege",
        level: 2,
    }];
    const NEAR_A_LIMIT: &[Levelled] = &[Levelled {
        member: "limit",
        level: 2,
    }];
    const NEAR_RELAYS: &[Levelled] = &[Levelled {
        member: "relay",
        level: 2,
    }];
    for (levelled, near) in [
        (NEAR_STORAGE, "storage"),
        (NEAR_A_LIMIT, "limits"),
        (NEAR_RELAYS, "relays"),
    ] {
        let name = levelled[0].member;
        let mut schema = document();
        schema["properties"][name] = schema["properties"]["telemetry"].clone();
        let found = designs(&schema, &release(2, levelled));
        assert!(messages(&found).contains(near), "{name}: {found:?}");
    }
}

/// Two sections that arrive in one write are held to each other's names as well as to the base's: a
/// release that knows the first and not the second takes the second for a misspelling of the first.
#[test]
fn two_sections_arriving_together_are_held_to_each_others_names() {
    const BOTH: &[Levelled] = &[
        Levelled {
            member: "relays",
            level: 2,
        },
        Levelled {
            member: "relay",
            level: 3,
        },
    ];
    let mut schema = document();
    schema["properties"]["relay"] = schema["properties"]["relays"].clone();
    let found = designs(&schema, &release(3, BOTH));
    assert!(
        messages(&found).contains("the section relay is within 2 edits of the name relays"),
        "{found:?}"
    );
}

/// The folding and the metric are the ones every release in the field applies, so they are pinned
/// beside the distance: a change to either changes which names such a release takes for a
/// misspelling, and so needs a version raise like the distance does.
#[test]
fn the_folding_and_the_metric_of_the_near_miss_rule_are_pinned() {
    use kr_protocol::hostinfo::configuration::near_miss;

    assert_eq!(NEAR_MISS, 2);
    for (a, b) in [
        ("ceilings", "ceilings"),
        ("ceilngs", "ceilings"),
        ("CEILINGS", "ceilings"),
        ("default-profile", "default_profile"),
        ("defaultprofile", "default_profile"),
        ("ceilnigs", "ceilings"),
        ("ceiling", "ceilings"),
        ("sessionlimit", "session_limit"),
        // Six separators fold away; with none folded this is six edits.
        ("c_e-i_l-i_n-g_s", "ceilings"),
        // Two accents are two edits of characters, and four of bytes.
        ("c\u{e9}il\u{ef}ngs", "ceilings"),
    ] {
        assert!(near_miss(a, b), "{a} and {b} are taken for each other");
    }
    for (a, b) in [
        ("telemetry", "ceilings"),
        ("authority", "agents"),
        ("sync", "startup"),
        ("ceil", "ceilings"),
        // A transposition costs two edits and a substitution one: three in all. A metric that
        // counted a transposition as one would take these for each other.
        ("ceilnigz", "ceilings"),
    ] {
        assert!(!near_miss(a, b), "{a} and {b} are not");
    }
}

/// A definition that two sections share and no base section uses is in both sections' digests and
/// in neither base digest, so a change to it moves both sections and leaves the base alone.
#[test]
fn a_definition_two_sections_share_is_in_both_digests_and_not_in_the_base() {
    let three = release(3, &[TELEMETRY, RELAYS]);
    let before = levels_view(&document(), &three);
    let mut changed = document();
    changed["$defs"]["Limits"]["properties"]["bytes"] = nullable(json!({ "type": "string" }));
    let after = levels_view(&changed, &three);
    for (was, now) in before.members.iter().zip(&after.members) {
        assert_ne!(
            was.digest, now.digest,
            "{} moves with a shared definition",
            was.member
        );
    }
    let base = |schema: &Value| {
        digest(
            &Store {
                writers: Writers::Daemon,
                entry: entry(3),
                owned: Vec::<Claim>::new(),
                kept: vec![Kept::Protocol(
                    "Doc",
                    at_base(schema, three.levelled),
                    "Doc",
                )],
                levels: None,
            },
            &[],
        )
        .expect("a digest")
    };
    assert_eq!(
        base(&document()),
        base(&changed),
        "the base digest does not hold the definition"
    );

    // The registry holds the document without the sections, so adding a section moves nothing of it.
    let mut with_more = document();
    with_more["properties"]["telemetry"]["default"]["extra"] = Value::Null;
    with_more["$defs"]["Telemetry"]["properties"]["extra"] = nullable(json!({ "type": "string" }));
    assert_eq!(base(&document()), base(&with_more));
}

/// A guard: a raise of the version moves the registry's digest, because the document's `version`
/// default is in what the registry keeps; and the schema's default is the version the code writes.
#[test]
fn the_registry_digest_moves_when_only_the_version_default_moves() {
    let schema = kr_protocol::schema::schema_for::<ConfigurationDocument>();
    assert_eq!(
        schema["properties"]["version"]["default"], VERSION,
        "the schema states what the code writes"
    );
    let digest_of = |schema: &Value| {
        digest(
            &Store {
                writers: Writers::Daemon,
                entry: entry(1),
                owned: Vec::<Claim>::new(),
                kept: vec![Kept::Protocol(
                    "ConfigurationDocument",
                    at_base(schema, &[]),
                    "ConfigurationDocument",
                )],
                levels: None,
            },
            &[],
        )
        .expect("a digest")
    };
    let mut raised = schema.clone();
    raised["properties"]["version"]["default"] = json!(VERSION + 1);
    assert_ne!(digest_of(&schema), digest_of(&raised));
}

/// The names the lock compares are the ones the reader compares: the views `observe` builds from the
/// real document hold the names below each section, the budgets under the ceilings included, and
/// nothing in them is unresolved.
#[test]
fn the_views_observe_builds_hold_the_names_the_reader_compares() {
    let production = table::table()
        .into_iter()
        .find(|store| store.levels.is_some())
        .expect("the store whose document has levels");
    let observed = observe(&production, &[]).expect("observed");
    let levels = observed.levels.expect("levels");
    let ceilings = levels
        .properties
        .iter()
        .find(|property| property.name == "ceilings")
        .expect("the ceilings");
    assert!(
        ceilings.names.contains("package_bytes"),
        "a name below a nullable alternative"
    );
    assert!(
        levels
            .properties
            .iter()
            .all(|property| property.unresolved.is_empty())
    );
    let reader = kr_protocol::hostinfo::configuration::names_by_member_of(
        &kr_protocol::schema::schema_for::<ConfigurationDocument>(),
    );
    for property in &levels.properties {
        assert_eq!(
            Some(&property.names),
            reader.get(&property.name),
            "{}",
            property.name
        );
    }
    assert!(
        levels.members.is_empty(),
        "no section has arrived with a level yet"
    );
    assert!(levels.eligibility.is_empty() && super::design_findings(&levels).is_empty());
}

/// A section the real reader and writer do not treat as a section of a level is found by `observe`
/// and refused by the check and the writer: `voice` is always written, and `profiles` is an open
/// map. Each finding is the check's own, so removing the check removes it.
#[test]
fn what_the_real_reader_and_writer_say_of_a_section_is_found_through_observe() {
    let stand_in = |member: &'static str| {
        let levelled: &'static [Levelled] =
            Box::leak(vec![Levelled { member, level: 2 }].into_boxed_slice());
        Store {
            writers: Writers::Daemon,
            entry: entry(3),
            owned: Vec::<Claim>::new(),
            kept: Vec::new(),
            levels: Some(Levels {
                release: release(2, levelled),
                document: kr_protocol::schema::schema_for::<ConfigurationDocument>(),
            }),
        }
    };

    let voice = observe(&stand_in("voice"), &[]).expect("observed");
    let found = voice.levels.as_ref().expect("levels").eligibility.clone();
    assert!(
        found.iter().any(|(member, finding)| member == "voice" && finding.contains("is written when it is")),
        "a section that is always written is found: {found:?}"
    );
    let refused = write(None, &[voice], &[]).expect_err("is not written");
    assert!(
        messages(&refused).contains("is written when it is"),
        "{refused:?}"
    );
    let lock = Lock {
        format: 1,
        stores: Vec::new(),
        named: Vec::new(),
    };
    let again = observe(&stand_in("voice"), &[]).expect("observed");
    assert!(
        messages(&findings(&lock, &[again], &[])).contains("is written when it is"),
        "the check reports it too"
    );

    let profiles = observe(&stand_in("profiles"), &[]).expect("observed");
    let found = profiles
        .levels
        .as_ref()
        .expect("levels")
        .eligibility
        .clone();
    assert!(
        found
            .iter()
            .any(|(member, finding)| member == "profiles" && finding.contains("is not closed")),
        "an open map reads a field it does not declare: {found:?}"
    );
}

/// A section whose own schema is a map, which accepts any key and reads back differently from the
/// copy the registry keeps once it is unused, is refused at the same version and at a raised one.
#[test]
fn a_section_that_is_a_map_is_refused() {
    let two = release(2, &[TELEMETRY]);
    let mut schema = document();
    schema["properties"]["telemetry"] = json!({
        "type": "object",
        "additionalProperties": nullable(json!({ "type": "string" })),
        "default": {}
    });
    let found = designs(&schema, &two);
    assert!(
        messages(&found).contains("does not declare its fields"),
        "{found:?}"
    );
    let lock = write(
        None,
        &[observed(
            VERSION as u32,
            "aa",
            &document(),
            &release(1, &[]),
        )],
        &[],
    )
    .expect("a lock");
    for version in [VERSION as u32, VERSION as u32 + 1] {
        let refused = write(Some(&lock), &[observed(version, "aa", &schema, &two)], &[])
            .expect_err("a map is not a section");
        assert!(
            messages(&refused).contains("does not declare its fields"),
            "{refused:?}"
        );
    }
}

/// A change that does not state the levels of a store that has them cannot remove them from the
/// lock, even with the version and the digest unchanged and no section in the table.
#[test]
fn the_levels_of_a_store_are_not_removed_from_the_lock() {
    let schema = document();
    let one = release(1, &[]);
    let lock = write(None, &[observed(VERSION as u32, "aa", &schema, &one)], &[]).expect("a lock");
    assert_eq!(lock.stores[0].level, Some(1));
    let mut without = observed(VERSION as u32, "aa", &schema, &one);
    without.levels = None;
    let refused = write(Some(&lock), &[without], &[]).expect_err("the levels are kept");
    assert!(
        messages(&refused).contains("would leave the lock"),
        "{refused:?}"
    );
    let mut without = observed(VERSION as u32, "aa", &schema, &one);
    without.levels = None;
    let found = findings(&lock, &[without], &[]);
    assert!(
        messages(&found).contains("the levels of a store are kept"),
        "{found:?}"
    );
}

/// The check reports each way the levels of a store differ from the lock's: a section's level, the
/// level of the store alone, and the distance; and the window refuses a new section that claims a
/// level above the store's, which is a section without a level raise.
#[test]
fn the_check_reports_each_way_the_levels_differ_and_the_window_has_an_upper_bound() {
    let schema = document();
    let two = release(2, &[TELEMETRY]);
    let lock = write(None, &[observed(VERSION as u32, "aa", &schema, &two)], &[]).expect("a lock");

    let moved_level = observed(
        VERSION as u32,
        "aa",
        &schema,
        &release(
            3,
            &[Levelled {
                member: "telemetry",
                level: 3,
            }],
        ),
    );
    let found = findings(&lock, &[moved_level], &[]);
    assert!(
        messages(&found).contains("a section's level never changes"),
        "{found:?}"
    );

    let store_alone = observed(VERSION as u32, "aa", &schema, &release(3, &[TELEMETRY]));
    let found = findings(&lock, &[store_alone], &[]);
    assert!(
        messages(&found).contains("is read at level 3 in the code and 2 in the lock"),
        "{found:?}"
    );

    let mut distance = observed(VERSION as u32, "aa", &schema, &two);
    distance.levels.as_mut().expect("levels").near_miss = 3;
    let found = findings(&lock, &[distance], &[]);
    assert!(
        messages(&found).contains("misspelling in the code"),
        "{found:?}"
    );

    // A new section above the level the store is read at: no level was raised for it.
    let above = release(2, &[TELEMETRY, RELAYS]);
    let refused = write(
        Some(&lock),
        &[observed(VERSION as u32, "aa", &schema, &above)],
        &[],
    )
    .expect_err("a section cannot claim a level the store is not at");
    assert!(
        messages(&refused).contains("no higher than the level 2"),
        "{refused:?}"
    );
}

/// A definition that a base section reaches stays in the base digest, whichever sections of a level
/// share it, so a change to it needs the version raised.
#[test]
fn a_definition_a_base_section_shares_stays_in_the_base_digest() {
    let two = release(2, &[TELEMETRY]);
    let mut schema = document();
    schema["$defs"]["Storage"]["properties"]["origin"] =
        nullable(json!({ "$ref": "#/$defs/Limits" }));
    let mut changed = schema.clone();
    changed["$defs"]["Limits"]["properties"]["bytes"] = nullable(json!({ "type": "string" }));
    let base = |schema: &Value| {
        digest(
            &Store {
                writers: Writers::Daemon,
                entry: entry(3),
                owned: Vec::<Claim>::new(),
                kept: vec![Kept::Protocol("Doc", at_base(schema, two.levelled))],
                levels: None,
            },
            &[],
        )
        .expect("a digest")
    };
    assert_ne!(base(&schema), base(&changed));
}
