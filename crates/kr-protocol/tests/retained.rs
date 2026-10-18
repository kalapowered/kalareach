//! What a release keeps of the release before it, tried on the surfaces of two real releases.
//!
//! The product keeps one retained level, and between it and this build nothing differs, so the
//! tables of entries are empty. The difference these tests work from is a real one: the surface of
//! the 0.73.0 release (`tests/retained/0.73`, cut from its tag) and of this build differ by one
//! variant of the attention source, which a record of the attention text request carries. The
//! other differences are made by editing that real surface: a required member dropped, a variant
//! removed, a definition renamed, something frozen changed.

use kr_cbor::{CanonicalMap, CanonicalValue, Limits};
use kr_protocol::attention::{AttentionRecordRef, AttentionSource, AttentionTextRequest};
use kr_protocol::envelope::ControlFrame;
use kr_protocol::hello::PackageVersion;
use kr_protocol::ids::BuildId;
use kr_protocol::local::LocalBuild;
use kr_protocol::retained::surface::Refusal;
use kr_protocol::retained::{
    CodecError, Compatible, Declared, Difference, DifferenceKind, Level, RetainedLevel, Surface,
    assess, current, differences,
};
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::update::CompatibilityLevel;
use serde_json::Value;

const SURFACE_073: &str = include_str!("retained/0.73/surface.schema.json");

fn old_surface() -> Surface {
    Surface::parse(SURFACE_073).expect("the 0.73 surface")
}

fn limits() -> Limits {
    Limits::DEFAULT
}

fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

fn at_attention_source(source: AttentionSource) -> ControlFrame {
    ControlFrame::AttentionText(AttentionTextRequest {
        request_id: kr_protocol::ids::RequestId::new(7),
        records: vec![AttentionRecordRef {
            source,
            sequence: U64::new(3),
        }],
        recorded_generation: Nullable::null(),
    })
}

/// A surface edited as JSON: the text of the real surface changed by `edit`.
fn edited(surface: &Surface, edit: impl FnOnce(&mut serde_json::Map<String, Value>)) -> Surface {
    let mut document: Value = serde_json::from_str(&surface.render()).expect("a document");
    let definitions = document
        .get_mut("$defs")
        .and_then(Value::as_object_mut)
        .expect("definitions");
    edit(definitions);
    Surface::parse(&serde_json::to_string(&document).expect("text")).expect("an edited surface")
}

fn level_of(
    surface: &Surface,
    declared: &'static [Declared],
    compatible: &'static [Compatible],
) -> Level {
    Level::retained(leak(RetainedLevel::new(
        CompatibilityLevel::of(PackageVersion::new(0, 73, 0)),
        leak(surface.render()),
        "",
        "",
        declared,
        compatible,
    )))
}

fn refuse_authority(value: &mut CanonicalValue) -> Result<(), String> {
    match value {
        CanonicalValue::Text(text) if text == "authority" => {
            Err("the level has no source named authority".to_owned())
        }
        _ => Ok(()),
    }
}

fn keep(_value: &mut CanonicalValue) -> Result<(), String> {
    Ok(())
}

static AUTHORITY: Declared = Declared {
    at: "AttentionSource#const:authority",
    write: refuse_authority,
    read: keep,
    golden: &[],
};

/// The surface this build keeps for the release before it is covered: nothing differs from it.
#[test]
fn the_surface_kept_for_the_previous_release_is_the_one_this_build_has() {
    if let Err(problems) = kr_protocol::retained::check() {
        panic!("{}", problems.join("\n"));
    }
}

/// Two real releases: one variant, found at the place that carries it.
#[test]
fn two_real_releases_differ_by_the_attention_source_authority() {
    let found = differences(&old_surface(), current());
    assert_eq!(
        found,
        vec![Difference {
            at: "AttentionSource#const:authority".to_owned(),
            kind: DifferenceKind::Added,
            detail: "a variant".to_owned(),
        }]
    );
}

/// Every difference needs an entry, and every entry needs a difference.
#[test]
fn every_difference_needs_an_entry_and_every_entry_needs_a_difference() {
    let old = old_surface();
    let bare = assess(&old, current(), &[], &[]);
    assert_eq!(bare.uncovered.len(), 1, "{bare}");
    assert!(!bare.is_clean());

    let covered = assess(
        &old,
        current(),
        &[],
        &[Compatible {
            at: "AttentionSource#const:authority",
            reason: "the control daemon never asks a worker for this source",
        }],
    );
    assert!(covered.is_clean(), "{covered}");

    let stale = assess(
        &old,
        current(),
        &[],
        &[
            Compatible {
                at: "AttentionSource#const:authority",
                reason: "covered",
            },
            Compatible {
                at: "AttentionSource#const:gone",
                reason: "nothing differs there",
            },
        ],
    );
    assert_eq!(stale.stale, vec!["AttentionSource#const:gone"], "{stale}");

    // The same releases, compared with the difference gone: the entry is stale.
    let same = assess(
        current(),
        current(),
        &[],
        &[Compatible {
            at: "AttentionSource#const:authority",
            reason: "covered",
        }],
    );
    assert_eq!(
        same.stale,
        vec!["AttentionSource#const:authority"],
        "{same}"
    );
}

/// The kinds of difference a schema has, made on the real surface.
#[test]
fn a_changed_requirement_variant_or_keyword_is_a_difference_and_a_rename_is_not() {
    let new = old_surface();

    let loosened = edited(&new, |definitions| {
        let required = definitions["AttentionRecordRef"]["required"]
            .as_array_mut()
            .expect("required");
        required.retain(|name| name != "sequence");
    });
    assert!(
        differences(&new, &loosened)
            .iter()
            .any(|found| found.at == "AttentionRecordRef.sequence"
                && found.kind == DifferenceKind::Changed),
        "{:?}",
        differences(&new, &loosened)
    );

    let fewer = edited(&new, |definitions| {
        let branches = definitions["AttentionSource"]["oneOf"]
            .as_array_mut()
            .expect("variants");
        branches.retain(|branch| branch["const"] != "receipts");
    });
    assert_eq!(
        differences(&new, &fewer)
            .iter()
            .map(|found| (found.at.as_str(), found.kind))
            .collect::<Vec<_>>(),
        vec![("AttentionSource#const:receipts", DifferenceKind::Removed)]
    );

    let keyword = edited(&new, |definitions| {
        definitions["AttentionTextRequest"]["properties"]["records"]["uniqueItems"] =
            Value::Bool(true);
    });
    assert!(
        differences(&new, &keyword).iter().any(
            |found| found.at == "AttentionTextRequest.records" && found.detail == "uniqueItems"
        ),
        "{:?}",
        differences(&new, &keyword)
    );

    // A definition under another name, used in the same places: nothing differs.
    let renamed = Surface::parse(
        &new.render()
            .replace("\"AttentionRecordRef\"", "\"AttentionRecordRefs\"")
            .replace(
                "#/$defs/AttentionRecordRef\"",
                "#/$defs/AttentionRecordRefs\"",
            ),
    )
    .expect("a renamed surface");
    assert_eq!(differences(&new, &renamed), Vec::<Difference>::new());
}

/// What is frozen takes a compatibility entry and never a rewrite.
#[test]
fn a_difference_in_what_is_frozen_takes_a_compatible_entry_and_never_a_rewrite() {
    let old = old_surface();
    let frozen = edited(&old, |definitions| {
        definitions["LocalHelloAck"]["properties"]["peer_note"] =
            serde_json::json!({"type": "string"});
    });
    let place = "LocalHelloAck.peer_note";
    let nothing = assess(&old, &frozen, &[], &[]);
    assert!(
        nothing.uncovered.iter().any(|found| found.at == place),
        "{nothing}"
    );

    let rewritten = assess(
        &old,
        &frozen,
        &[Declared {
            at: "LocalHelloAck.peer_note",
            write: keep,
            read: keep,
            golden: &[],
        }],
        &[],
    );
    assert!(
        rewritten
            .rewritten_but_frozen
            .iter()
            .any(|found| found.at == place),
        "{rewritten}"
    );

    let compatible = assess(
        &old,
        &frozen,
        &[],
        &[Compatible {
            at: "LocalHelloAck.peer_note",
            reason: "every reader ignores it",
        }],
    );
    assert!(
        !compatible.uncovered.iter().any(|found| found.at == place)
            && compatible.rewritten_but_frozen.is_empty(),
        "{compatible}"
    );
}

/// What is written beside a reference is part of the place: a bound added beside an unchanged
/// reference is a difference.
#[test]
fn a_keyword_beside_a_reference_is_compared() {
    let old = old_surface();
    let bounded = edited(&old, |definitions| {
        definitions["ReceiptResponse"]["properties"]["receipt"]["maxLength"] = serde_json::json!(4);
    });
    let found = differences(&old, &bounded);
    assert!(
        found
            .iter()
            .any(|difference| difference.at == "ReceiptResponse.receipt"),
        "{found:?}"
    );
    assert_eq!(differences(&old, &old), Vec::<Difference>::new());
}

/// The session a running worker's first question names is read before the daemon knows the level
/// the rest is read under, so a change to it takes a compatibility entry and never a rewrite, as
/// the keys of the frames do.
#[test]
fn the_session_a_running_workers_question_names_is_frozen() {
    let old = old_surface();
    for question in ["PluginRuntimeWanted", "DraftWanted"] {
        let changed = edited(&old, |definitions| {
            definitions[question]["properties"]["session_id"] =
                serde_json::json!({"type": "string"});
        });
        let place: &'static str = if question == "DraftWanted" {
            "DraftWanted.session_id"
        } else {
            "PluginRuntimeWanted.session_id"
        };
        let rewritten = assess(
            &old,
            &changed,
            &[Declared {
                at: place,
                write: keep,
                read: keep,
                golden: &[],
            }],
            &[],
        );
        assert!(
            rewritten
                .rewritten_but_frozen
                .iter()
                .any(|found| found.at == place),
            "{question}: {rewritten}"
        );
    }
}

/// A frozen definition that a surface lacks is a change that could not be seen, and is reported.
#[test]
fn a_frozen_definition_a_surface_lacks_is_reported() {
    let without: Vec<&str> = kr_protocol::retained::SURFACE_ROOTS
        .iter()
        .copied()
        .filter(|root| *root != "QuestionReadOwnParams")
        .collect();
    let lacking = Surface::cut(&kr_protocol::schema::protocol_schema(), &without)
        .expect("the surface without the membership probe");
    let found = assess(&lacking, current(), &[], &[]);
    assert!(
        found
            .absent
            .iter()
            .any(|name| name == "QuestionReadOwnParams"),
        "{found}"
    );
    assert!(assess(current(), current(), &[], &[]).is_clean());
}

fn stated(minor: u16, patch: u16) -> LocalBuild {
    LocalBuild {
        build_id: BuildId::new("kr-worker/0.1.0").expect("a build identifier"),
        protocol_version: PackageVersion::new(0, minor, patch),
    }
}

/// A worker is at this level, at a retained one, or at none this release speaks.
#[test]
fn a_worker_is_at_this_level_at_a_retained_one_or_at_none() {
    let this = kr_protocol::hello::PACKAGE_VERSION;
    assert!(
        Level::of(Some(&stated(this.minor, 0)))
            .expect("this level")
            .is_this()
    );
    assert!(
        Level::of(Some(&stated(this.minor, 9)))
            .expect("a patch apart")
            .is_this()
    );
    let previous = Level::of(Some(&stated(74, 0))).expect("the retained level");
    assert!(!previous.is_this());
    assert_eq!(
        previous.level(),
        kr_protocol::retained::RETAINED_WORKER_LEVELS[0]
    );
    for minor in [this.minor - 2, this.minor + 1] {
        assert!(Level::of(Some(&stated(minor, 0))).is_err(), "level {minor}");
    }
    assert!(Level::of(None).is_err());
}

/// A frame written for a level that has what it carries is the frame this build writes; one that
/// carries what the level lacks is refused by name and not written.
#[test]
fn a_frame_the_level_has_is_written_as_it_is_and_one_it_lacks_is_refused_by_name() {
    let level = level_of(&old_surface(), std::slice::from_ref(&AUTHORITY), &[]);
    let known = at_attention_source(AttentionSource::Questions);
    assert_eq!(
        level
            .encode(&known, &limits())
            .expect("written for the level"),
        Level::this().encode(&known, &limits()).expect("written"),
    );
    let lacking = at_attention_source(AttentionSource::Authority);
    match level.encode(&lacking, &limits()) {
        Err(CodecError::NotInLevel { refusal, .. }) => {
            assert!(refusal.to_string().contains("authority"), "{refusal}");
        }
        other => panic!("expected a refusal by name, got {other:?}"),
    }
}

/// A frame the level wrote is read as the frame it is; one its surface does not admit is refused.
#[test]
fn a_frame_of_the_level_is_read_and_one_outside_its_surface_is_refused() {
    let level = level_of(&old_surface(), std::slice::from_ref(&AUTHORITY), &[]);
    let known = at_attention_source(AttentionSource::Questions);
    let payload = Level::this().encode(&known, &limits()).expect("written");
    assert_eq!(level.decode(&payload, &limits()).expect("read"), known);

    // What the 0.73 surface does not have: a source it never sent.
    let outside = Level::this()
        .encode(&at_attention_source(AttentionSource::Authority), &limits())
        .expect("this build writes it");
    match level.decode(&outside, &limits()) {
        Err(CodecError::OutsideLevel { refusal, .. }) => {
            assert!(
                matches!(refusal, Refusal::UnknownVariant { ref found, .. } if found == "authority"),
                "{refusal}"
            );
        }
        other => panic!("expected the level's surface to refuse it, got {other:?}"),
    }

    // A member that is not in the surface, and a required member the frame lacks.
    let value = kr_cbor::decode(&payload, &limits()).expect("canonical");
    let value = change(
        value,
        &["attention_text", "records", "[0]"],
        &with("extra", CanonicalValue::Null),
    );
    let unknown = kr_cbor::encode(&value);
    assert!(
        matches!(
            level.decode(&unknown, &limits()),
            Err(CodecError::OutsideLevel {
                refusal: Refusal::UnknownMember { ref member, .. },
                ..
            }) if member == "extra"
        ),
        "{:?}",
        level.decode(&unknown, &limits())
    );
}

/// A rewrite is applied to each instance of its definition, going out and coming in, and the golden
/// pair of its entry comes out both ways.
#[test]
fn rewrites_are_applied_to_each_instance_both_ways() {
    // A level before the request carried the generation the daemon recorded.
    let without = edited(&old_surface(), |definitions| {
        let request = &mut definitions["AttentionTextRequest"];
        request["properties"]
            .as_object_mut()
            .expect("members")
            .remove("recorded_generation");
        request["required"]
            .as_array_mut()
            .expect("required")
            .retain(|name| name != "recorded_generation");
    });
    fn leave_out(value: &mut CanonicalValue) -> Result<(), String> {
        kr_protocol::retained::remove_member(value, "recorded_generation");
        Ok(())
    }
    fn say_none(value: &mut CanonicalValue) -> Result<(), String> {
        let CanonicalValue::Map(map) = value else {
            return Err("not a map".to_owned());
        };
        let mut entries = std::mem::take(map).into_entries();
        entries.push(("recorded_generation".to_owned(), CanonicalValue::Null));
        *map = CanonicalMap::from_entries(entries).map_err(|error| error.to_string())?;
        Ok(())
    }
    let frame = at_attention_source(AttentionSource::Questions);
    let current_bytes = Level::this().encode(&frame, &limits()).expect("written");
    let as_the_level_has_it = change(
        kr_cbor::decode(&current_bytes, &limits()).expect("canonical"),
        &["attention_text"],
        &dropping("recorded_generation"),
    );
    let retained_bytes = kr_cbor::encode(&as_the_level_has_it);
    let golden = leak([kr_protocol::retained::Golden {
        current: leak(current_bytes.clone()),
        retained: leak(retained_bytes.clone()),
    }]);
    let entry = leak([Declared {
        at: "AttentionTextRequest.recorded_generation",
        write: leave_out,
        read: say_none,
        golden,
    }]);
    let level = level_of(&without, entry, &[]);
    assert_eq!(
        level.encode(&frame, &limits()).expect("written"),
        retained_bytes
    );
    assert_eq!(
        level.decode(&retained_bytes, &limits()).expect("read"),
        frame
    );
    assert_eq!(level.golden_problems(&limits()), Vec::<String>::new());

    // A pair that is not what the rewrites make of the frame is reported.
    let wrong = leak([Declared {
        at: "AttentionTextRequest.recorded_generation",
        write: leave_out,
        read: say_none,
        golden: leak([kr_protocol::retained::Golden {
            current: leak(current_bytes.clone()),
            retained: leak(current_bytes),
        }]),
    }]);
    assert!(
        !level_of(&without, wrong, &[])
            .golden_problems(&limits())
            .is_empty()
    );

    // The member's absence is two differences at one place (it is not a member, and it is not
    // required), which one entry covers.
    assert_eq!(
        differences(&without, current())
            .iter()
            .map(|found| found.at.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "AttentionSource#const:authority",
            "AttentionTextRequest.recorded_generation"
        ]
        .into_iter()
        .collect()
    );
}

type Entries = Vec<(String, CanonicalValue)>;

/// Changes the entries of the map `path` leads to: the keys of maps, and `[0]` for the first item of
/// an array. A value the path does not reach is returned as it was.
fn change(
    value: CanonicalValue,
    path: &[&str],
    edit: &dyn Fn(Entries) -> Entries,
) -> CanonicalValue {
    match (path.split_first(), value) {
        (None, CanonicalValue::Map(map)) => CanonicalValue::Map(
            CanonicalMap::from_entries(edit(map.into_entries())).expect("a map"),
        ),
        (Some((&"[0]", rest)), CanonicalValue::Array(mut items)) => {
            if !items.is_empty() {
                let first = items.remove(0);
                items.insert(0, change(first, rest, edit));
            }
            CanonicalValue::Array(items)
        }
        (Some((key, rest)), CanonicalValue::Map(map)) => {
            let entries = map
                .into_entries()
                .into_iter()
                .map(|(name, member)| {
                    if name == *key {
                        (name, change(member, rest, edit))
                    } else {
                        (name, member)
                    }
                })
                .collect();
            CanonicalValue::Map(CanonicalMap::from_sorted_entries(entries).expect("sorted"))
        }
        (_, other) => other,
    }
}

fn with(member: &'static str, value: CanonicalValue) -> impl Fn(Entries) -> Entries {
    move |mut entries| {
        entries.push((member.to_owned(), value.clone()));
        entries
    }
}

fn dropping(member: &'static str) -> impl Fn(Entries) -> Entries {
    move |entries| {
        entries
            .into_iter()
            .filter(|(name, _)| name != member)
            .collect()
    }
}

/// A receipt as a worker keeps it.
fn a_kept_receipt() -> kr_protocol::receipt::Receipt {
    kr_protocol::receipt::Receipt {
        action_id: kr_protocol::ids::ActionId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16])),
        actor_id: kr_protocol::ids::ActorId::new("device:test").expect("a principal"),
        method: kr_protocol::method::Method::SessionClose.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        revision: U64::new(2),
        state: kr_protocol::receipt::ReceiptState::Applied,
        reason: Nullable::null(),
        payload_digest: kr_protocol::scalars::Digest256::from_bytes([0; 32]),
        accepted_deadline_ms: Nullable::null(),
        error: Nullable::null(),
        error_withheld: false,
        updated_at_ms: kr_protocol::scalars::TimestampMs::new(1),
    }
}

/// What a worker answers `action.read` with reads under the level it retains whatever the result it
/// kept looks like: none, a map, an array, a text. The surface says the result is opaque, so the
/// walk leaves it to the typed layer; a level that refused a kept result would fail a device's
/// retry across an update. While the retained surface and this build's are the same, each answer
/// reads the same under both.
#[test]
fn a_kept_answer_reads_under_the_retained_level_as_it_reads_under_this_one() {
    use kr_protocol::envelope::ParamsValue;
    use kr_protocol::receipt::ActionReadResult;

    let retained = Level::retained(&kr_protocol::retained::RETAINED[0]);
    let map = CanonicalValue::Map(
        CanonicalMap::from_entries([("state".to_owned(), CanonicalValue::text("closing"))])
            .expect("a map"),
    );
    for result in [
        Nullable::null(),
        Nullable::some(ParamsValue::new(map)),
        Nullable::some(ParamsValue::new(CanonicalValue::Array(vec![
            CanonicalValue::text("a"),
        ]))),
        Nullable::some(ParamsValue::new(CanonicalValue::text("done"))),
    ] {
        let answer = ActionReadResult {
            receipt: a_kept_receipt(),
            result,
        };
        let value = ParamsValue::from_typed(&answer).expect("encodes");
        let this = Level::this()
            .decode_value::<ActionReadResult>(&value)
            .expect("read under this level");
        let kept = retained
            .decode_value::<ActionReadResult>(&value)
            .unwrap_or_else(|error| panic!("{error}: {answer:?}"));
        assert_eq!(kept, this);
        assert_eq!(kept, answer);
    }
}

/// KR-REQ-26.06, KR-ACC-035: the exchange a control daemon had with a real worker of the release
/// before (`retained/0.74/frames.json`: the payload of every frame either way, as they went over
/// the wire in the upgrade suite) reads under the level that release stated, and reads the same
/// under this build's own level while the two do not differ. What the daemon wrote reads back as
/// the bytes it wrote.
///
/// The record is made by `KR_RECORD_FRAMES=1 cargo test -p kr-cli --features upgrade-suite --test
/// upgrade the_frames_ -- --nocapture`, which prints it.
#[test]
fn the_exchange_recorded_with_a_real_worker_of_the_release_before_reads_under_its_level() {
    let record: Vec<Value> = serde_json::from_str(include_str!("../retained/0.74/frames.json"))
        .expect("the record is a list");
    assert!(
        !record.is_empty(),
        "the retained level records no exchange with a worker of its release"
    );
    // The record is of the 0.74 release, and is read under that level whatever else is retained.
    let wanted = CompatibilityLevel::of(PackageVersion::new(0, 74, 0));
    let retained = kr_protocol::retained::RETAINED
        .iter()
        .find(|retained| retained.level == wanted)
        .expect("the 0.74 level is retained");
    let level = Level::retained(retained);
    // While this build's surface is the one the level kept, a frame reads the same under both.
    let alike = differences(retained.surface(), current()).is_empty();
    let mut both_ways = [false; 2];
    for entry in &record {
        let payload = hex::decode(entry["payload"].as_str().expect("a payload")).expect("hex");
        let written = entry["direction"] == "controller_to_worker";
        both_ways[usize::from(written)] = true;
        let frame = level
            .decode(&payload, &limits())
            .unwrap_or_else(|error| panic!("{entry} reads under the level: {error:?}"));
        if alike {
            assert_eq!(
                Level::this()
                    .decode(&payload, &limits())
                    .expect("it reads under this build's level too"),
                frame
            );
        }
        if written {
            assert_eq!(
                level.encode(&frame, &limits()).expect("it writes again"),
                payload,
                "{entry}"
            );
        }
    }
    assert_eq!(both_ways, [true, true], "frames went both ways");
    // The exchange is the one the upgrade suite makes, frame by frame.
    let kinds: Vec<String> = record
        .iter()
        .map(|entry| {
            let payload = hex::decode(entry["payload"].as_str().expect("a payload")).expect("hex");
            let frame = level.decode(&payload, &limits()).expect("it reads");
            let document = serde_json::to_value(&frame).expect("a frame is a document");
            document
                .as_object()
                .and_then(|object| object.keys().next().cloned())
                .expect("a frame names its kind")
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "verify_challenge",
            "verify_proof",
            "generation_token",
            "generation_accepted",
            "local_access",
            "local_access_ack",
            "authority_revision",
            "authority_revision_ack",
            "authority_revision",
            "authority_revision_ack",
            "privacy_generation",
            "privacy_generation_ack",
            "plugin_admissions",
            "plugin_admissions_ack",
            "request",
            "response",
        ]
    );
}
