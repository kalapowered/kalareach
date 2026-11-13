//! What a release keeps of the release before it, tried on the surfaces of two real releases.
//!
//! The product keeps one retained level. The difference these tests work from is a real one: the
//! surface of the 0.73.0 release (`tests/retained/0.73`, cut from its tag) and of the 0.75.0
//! release (`tests/retained/0.75`, the surface the level of that release was cut with), a later
//! release, differ by one variant of the attention source, which a record of the attention text
//! request carries. Two real surfaces are what they compare, and not this build's, because the
//! retained level and this build move with every cut and every change to a frame, and these cases
//! are about how differences are found and covered, not about what this build differs by. The other
//! differences are made by editing that real surface: a required member dropped, a variant
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
    SurfaceError, assess, current, differences,
};
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::update::CompatibilityLevel;
use serde_json::{Value, json};

const SURFACE_073: &str = include_str!("retained/0.73/surface.schema.json");
const SURFACE_075: &str = include_str!("retained/0.75/surface.schema.json");

fn old_surface() -> Surface {
    Surface::parse(SURFACE_073).expect("the 0.73 surface")
}

/// The surface of the 0.75.0 release, a later release than 0.73.0.
fn newer_surface() -> &'static Surface {
    static SURFACE: std::sync::OnceLock<Surface> = std::sync::OnceLock::new();
    SURFACE.get_or_init(|| Surface::parse(SURFACE_075).expect("the 0.75 surface"))
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

/// The surface this build keeps for the release before it is covered: it differs from it only
/// where an entry says why the difference is safe.
#[test]
fn the_surface_kept_for_the_previous_release_is_the_one_this_build_has() {
    if let Err(problems) = kr_protocol::retained::check() {
        panic!("{}", problems.join("\n"));
    }
}

/// Two real releases: one variant, found at the place that carries it.
#[test]
fn two_real_releases_differ_by_the_attention_source_authority() {
    let found = differences(&old_surface(), newer_surface());
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
    let bare = assess(&old, newer_surface(), &[], &[]);
    assert_eq!(bare.uncovered.len(), 1, "{bare}");
    assert!(!bare.is_clean());

    let covered = assess(
        &old,
        newer_surface(),
        &[],
        &[Compatible {
            at: "AttentionSource#const:authority",
            reason: "the control daemon never asks a worker for this source",
        }],
    );
    assert!(covered.is_clean(), "{covered}");

    let stale = assess(
        &old,
        newer_surface(),
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
    let previous = Level::of(Some(&stated(77, 0))).expect("the retained level");
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
        differences(&without, newer_surface())
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
/// before (`retained/0.77/frames.json`: the payload of every frame either way, as they went over
/// the wire in the upgrade suite) reads under the level that release stated, and reads the same
/// under this build's own level while the two do not differ. What the daemon wrote reads back as
/// the bytes it wrote.
///
/// The record is made by `KR_RECORD_FRAMES=1 cargo test -p kr-cli --features upgrade-suite --test
/// upgrade the_frames_ -- --nocapture`, which prints it.
#[test]
fn the_exchange_recorded_with_a_real_worker_of_the_release_before_reads_under_its_level() {
    let record: Vec<Value> = serde_json::from_str(include_str!("../retained/0.77/frames.json"))
        .expect("the record is a list");
    assert!(
        !record.is_empty(),
        "the retained level records no exchange with a worker of its release"
    );
    // The record is of the 0.77 release, and is read under that level whatever else is retained.
    let wanted = CompatibilityLevel::of(PackageVersion::new(0, 77, 0));
    let retained = kr_protocol::retained::RETAINED
        .iter()
        .find(|retained| retained.level == wanted)
        .expect("the 0.77 level is retained");
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

/// The recordings of the release before that sit beside the tests that read them, outside
/// `retained/` (the registration a worker of that release publishes for a launch, the first frame
/// its forwarder writes, and the Channels frames of its forwarder and its worker), are of the
/// newest retained level: each file is named for that level, and the registration names the
/// release the level was cut from. A cut that retains a newer level and leaves a recording of the
/// older one in place fails here, naming the file.
#[test]
fn the_recordings_beside_the_tests_are_of_the_release_before() {
    let before = kr_protocol::retained::RETAINED
        .iter()
        .max_by_key(|level| level.level)
        .expect("a level is retained");
    let level = before.level.to_string();
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for (directory, stem, extension) in [
        ("kr-worker/tests/fixtures", "channel-frames", "json"),
        ("kr-worker/tests/fixtures", "bridge-hello", "json"),
        ("kr-hook/tests/fixtures", "registration", "txt"),
    ] {
        let mut recordings: Vec<String> = std::fs::read_dir(crates.join(directory))
            .expect("the fixtures directory")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.starts_with(&format!("{stem}-")))
            .collect();
        recordings.sort();
        assert_eq!(
            recordings,
            [format!("{stem}-{level}.{extension}")],
            "{directory} holds the recording of the release before, named for its level {level}, \
             and no other"
        );
    }
    let registration = std::fs::read_to_string(
        crates.join(format!("kr-hook/tests/fixtures/registration-{level}.txt")),
    )
    .expect("the recorded registration");
    assert_eq!(
        registration
            .lines()
            .find_map(|line| line.strip_prefix("release=")),
        before.record("release"),
        "the recorded registration names the release level {level} was cut from"
    );
}

/// A surface cut from a schema holds the keywords of the schema's own root, beside its
/// definitions, and a difference in one is a difference of the surface: a validator applies them to
/// every document, so a root whose `type` changes accepts other values. Its annotations are left
/// out, as everywhere. Its `properties`, the bundle's entries, are compared by member (see
/// `a_change_of_a_member_of_the_schemas_own_root_is_a_difference`). A surface read from a recorded
/// document holds none, and compares none.
#[test]
fn a_difference_in_the_keywords_of_the_schemas_own_root_is_a_difference() {
    let dialect = "https://json-schema.org/draft/2020-12/schema";
    let root = || {
        json!({
            "$schema": dialect,
            "type": "object",
            "title": "Bundle",
            "description": "What the bundle holds",
            "properties": { "a": { "$ref": "#/$defs/A" } },
            "allOf": [{ "type": "object", "description": "A part of the root" }],
        })
    };
    let cut = |root: &Value, defined: Value| {
        let mut schema = root.clone();
        schema["$defs"] = defined;
        Surface::cut(&schema, &["A"]).expect("a surface")
    };
    let definitions = || json!({ "A": { "type": "string" }, "B": { "type": "string" } });
    let found = |old: &Surface, new: &Surface| {
        differences(old, new)
            .iter()
            .map(|found| (found.at.clone(), found.kind, found.detail.clone()))
            .collect::<Vec<_>>()
    };
    let base = cut(&root(), definitions());
    assert_eq!(found(&base, &cut(&root(), definitions())), vec![]);
    let changed = |keyword: &str, value: Value| {
        let mut other = root();
        other[keyword] = value;
        other
    };
    for (new_root, keyword) in [
        // A root that is a string accepts only texts; one that is an object, only objects.
        (changed("type", json!("string")), "type"),
        // The dialect decides what the keywords of the schema mean.
        (
            changed("$schema", json!("http://json-schema.org/draft-07/schema#")),
            "$schema",
        ),
        // A keyword that the earlier root did not have.
        (changed("not", json!({ "type": "null" })), "not"),
    ] {
        assert_eq!(
            found(&base, &cut(&new_root, definitions())),
            vec![(
                "$root".to_owned(),
                DifferenceKind::Changed,
                keyword.to_owned()
            )],
            "{keyword}"
        );
    }
    let mut without = root();
    without
        .as_object_mut()
        .expect("an object")
        .remove("$schema");
    assert_eq!(
        found(&base, &cut(&without, definitions())),
        vec![(
            "$root".to_owned(),
            DifferenceKind::Changed,
            "$schema".to_owned()
        )],
        "a root that names no dialect"
    );
    // Annotations, in the root, inside a keyword of it and on a member, are no difference.
    let mut quiet = root();
    quiet["title"] = json!("Another title");
    quiet["description"] = json!("Another description");
    quiet["properties"]["a"]["description"] = json!("Another member");
    quiet["allOf"][0]["description"] = json!("Another part of the root");
    assert_eq!(found(&base, &cut(&quiet, definitions())), vec![]);
    // A reference of the root is compared where its target is in the surface, and a cut that does
    // not hold the target is refused: the roots of the cut are all that a recorded document lists,
    // and an absent target would make a changed reference no difference. The cut stays one that
    // `parse` reads back.
    let mut composed = root();
    composed["allOf"] = json!([{ "$ref": "#/$defs/B" }]);
    let with_roots = |roots: &[&str]| {
        let mut schema = composed.clone();
        schema["$defs"] = definitions();
        Surface::cut(&schema, roots)
    };
    assert_eq!(
        with_roots(&["A"]),
        Err(SurfaceError::RootReference("B".to_owned()))
    );
    let referring = with_roots(&["A", "B"]).expect("a cut that holds the target");
    assert_eq!(referring.names().collect::<Vec<_>>(), ["A", "B"]);
    assert!(Surface::parse(&referring.render()).is_ok());
    // A reference of the root that is not to `$defs` by its plain name cannot be told from one that
    // is, by a reader that decodes the fragment or reads an address: the cut refuses it.
    for reference in [
        "#/%24defs/B",
        "https://example.test/x#/$defs/B",
        "#/properties/a",
    ] {
        let mut schema = root();
        schema["oneOf"] = json!([{ "$ref": reference }]);
        schema["$defs"] = definitions();
        assert_eq!(
            Surface::cut(&schema, &["A", "B"]),
            Err(SurfaceError::BadReference(reference.to_owned())),
            "{reference}"
        );
    }
    // A recorded document holds no root keywords, so the surface read from one compares none.
    let recorded = Surface::parse(&base.render()).expect("the recorded surface");
    assert_eq!(
        found(
            &recorded,
            &cut(&changed("type", json!("string")), definitions())
        ),
        vec![]
    );
}

/// A surface cut from a schema holds the members of the schema's own root, the bundle's entries,
/// and compares them by name: a consumer reads a member by its name (the plugin SDK's reader
/// compiles a validator from each), so an entry that moves to another definition, one that gains
/// a keyword and an inline entry that changes are differences, and so is a member that is gone,
/// each at `$root.<member>`. An entry that is a reference is compared by its text and not
/// followed, so a renamed definition that its entry follows is a line at the member. A member that
/// only the new root has is an arrival: an earlier reader never named it, so it is no difference.
/// An entry that is not an object of members is refused by the cut, and a recorded document holds
/// no root, so it compares none.
#[test]
fn a_change_of_a_member_of_the_schemas_own_root_is_a_difference() {
    let bundle = || {
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "properties": {
                "a": { "$ref": "#/$defs/A" },
                "b": { "$ref": "#/$defs/B" },
                "identifiers": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": { "a_id": { "$ref": "#/$defs/A" } },
                },
            },
            "$defs": {
                "A": { "type": "string" },
                "B": { "type": "string" },
                "Holder": { "type": "object", "properties": { "a": { "$ref": "#/$defs/A" } } },
            },
        })
    };
    let cut = |schema: &Value| Surface::cut(schema, &["B", "Holder"]).expect("a surface");
    let lines = |old: &Value, new: &Value| -> Vec<String> {
        differences(&cut(old), &cut(new))
            .iter()
            .map(ToString::to_string)
            .collect()
    };
    let edited = |edit: &dyn Fn(&mut Value)| {
        let mut schema = bundle();
        edit(&mut schema);
        schema
    };
    assert_eq!(lines(&bundle(), &bundle()), Vec::<String>::new());
    // A member that moves to another definition, though both definitions are alike.
    assert_eq!(
        lines(
            &bundle(),
            &edited(&|schema| schema["properties"]["a"] = json!({ "$ref": "#/$defs/B" }))
        ),
        ["$root.a changed: $ref"]
    );
    // A member that gains a keyword beside its reference, and one that stops being a reference.
    assert_eq!(
        lines(
            &bundle(),
            &edited(&|schema| schema["properties"]["a"]["default"] = json!("x"))
        ),
        ["$root.a changed: default"]
    );
    assert_eq!(
        lines(
            &bundle(),
            &edited(&|schema| schema["properties"]["a"] = json!({ "type": "string" }))
        ),
        ["$root.a changed: a reference against an inline schema"]
    );
    // The inline member: a member it gains, one it loses, and a keyword of its own.
    assert_eq!(
        lines(
            &bundle(),
            &edited(
                &|schema| schema["properties"]["identifiers"]["properties"]["extra"] =
                    json!({ "type": "string" })
            )
        ),
        ["$root.identifiers.extra added: a member"]
    );
    assert_eq!(
        lines(
            &bundle(),
            &edited(&|schema| {
                schema["properties"]["identifiers"]["properties"] = json!({});
            })
        ),
        ["$root.identifiers.a_id removed: a member"]
    );
    assert_eq!(
        lines(
            &bundle(),
            &edited(
                &|schema| schema["properties"]["identifiers"]["additionalProperties"] = json!(true)
            )
        ),
        ["$root.identifiers changed: additionalProperties"]
    );
    // A member that is gone; a member that arrives is no difference, beside a removal too.
    let without_b = edited(&|schema| {
        schema["properties"]
            .as_object_mut()
            .expect("members")
            .remove("b");
    });
    assert_eq!(lines(&bundle(), &without_b), ["$root.b removed: a member"]);
    let with_c = edited(&|schema| schema["properties"]["c"] = json!({ "$ref": "#/$defs/A" }));
    assert_eq!(lines(&bundle(), &with_c), Vec::<String>::new());
    let swapped = edited(&|schema| {
        schema["properties"]
            .as_object_mut()
            .expect("members")
            .remove("b");
        schema["properties"]["c"] = json!({ "$ref": "#/$defs/A" });
    });
    assert_eq!(lines(&bundle(), &swapped), ["$root.b removed: a member"]);
    // Annotations of a member decide nothing.
    assert_eq!(
        lines(
            &bundle(),
            &edited(&|schema| schema["properties"]["a"]["description"] = json!("About a"))
        ),
        Vec::<String>::new()
    );
    // A definition that is renamed, with its member following it: the definitions are alike, so
    // the line is the member's, the accepted cost of comparing an entry by its name.
    let renamed = edited(&|schema| {
        let body = schema["$defs"]
            .as_object_mut()
            .expect("definitions")
            .remove("A");
        schema["$defs"]["Renamed"] = body.expect("A");
        schema["$defs"]["Holder"]["properties"]["a"] = json!({ "$ref": "#/$defs/Renamed" });
        schema["properties"]["a"] = json!({ "$ref": "#/$defs/Renamed" });
        schema["properties"]["identifiers"]["properties"]["a_id"] =
            json!({ "$ref": "#/$defs/Renamed" });
    });
    assert_eq!(lines(&bundle(), &renamed), ["$root.a changed: $ref"]);
    // An inline member that is a nullable pair stays one when its null branch has a description, so
    // a reference that becomes an inline schema is a line at the member.
    let nullable = |first: Value| {
        edited(&|schema| {
            schema["properties"]["n"] =
                json!({ "anyOf": [first.clone(), { "type": "null", "description": "none" }] });
        })
    };
    assert_eq!(
        lines(
            &nullable(json!({ "$ref": "#/$defs/A" })),
            &nullable(json!({ "type": "integer" }))
        ),
        ["$root.n changed: a reference against an inline schema"]
    );
    // Members that are not an object of members cannot be read by name, so the cut refuses them.
    for members in [json!(["a"]), json!("a"), json!(null)] {
        let schema = edited(&|schema| schema["properties"] = members.clone());
        assert!(
            matches!(
                Surface::cut(&schema, &["B", "Holder"]),
                Err(SurfaceError::NotASurface(_))
            ),
            "{members}"
        );
    }
    // A recorded document holds no root, so the surface read from one compares no member.
    let recorded = Surface::parse(&cut(&bundle()).render()).expect("the recorded surface");
    assert_eq!(
        differences(&recorded, &cut(&without_b)),
        Vec::<Difference>::new()
    );
}

/// A reference inside a member of the schema's own root, nested or beside the entry's own, has to
/// be `#/$defs/NAME` with a NAME of ASCII letters, digits and `_` that the schema defines. The
/// comparison of an inline member follows a nested reference only to a definition that the surface
/// holds and passes over any other, so a reference that moves from one pointer into a definition
/// (`#/$defs/Pair/properties/text`) to another, or to a name that the schema lacks, would be no
/// difference though a validator that reads the member accepts other values. The cut refuses such
/// a reference, as it does in a definition and in a keyword of the root. A definition that the
/// surface does not hold is not refused: the cut does not follow the entries.
#[test]
fn a_reference_inside_a_member_of_the_schemas_own_root_has_to_name_a_definition() {
    let schema = |entry: &Value| {
        json!({
            "$defs": {
                "A": { "type": "string" },
                "Outside": { "type": "string" },
                "Pair": { "type": "object", "properties": {
                    "text": { "type": "string" }, "number": { "type": "number" } } },
            },
            "properties": { "a": entry },
        })
    };
    for (entry, wanted) in [
        (
            json!({ "$ref": "#/$defs/Pair/properties/text" }),
            SurfaceError::BadReference("#/$defs/Pair/properties/text".to_owned()),
        ),
        (
            json!({ "type": "array", "items": { "$ref": "#/$defs/Pair/properties/number" } }),
            SurfaceError::BadReference("#/$defs/Pair/properties/number".to_owned()),
        ),
        (
            json!({ "$ref": "#/%24defs/A" }),
            SurfaceError::BadReference("#/%24defs/A".to_owned()),
        ),
        (
            json!({ "anyOf": [{ "$ref": "#/$defs/A" }, { "$ref": "https://example.test/#/$defs/A" }] }),
            SurfaceError::BadReference("https://example.test/#/$defs/A".to_owned()),
        ),
        (
            json!({ "$ref": "#/$defs/Missing" }),
            SurfaceError::UnknownRoot("Missing".to_owned()),
        ),
        (
            json!({ "$ref": "#/$defs/A", "properties": { "x": { "$ref": "#/$defs/Missing" } } }),
            SurfaceError::UnknownRoot("Missing".to_owned()),
        ),
    ] {
        assert_eq!(
            Surface::cut(&schema(&entry), &["A"]),
            Err(wanted),
            "{entry}"
        );
    }
    let outside = Surface::cut(&schema(&json!({ "$ref": "#/$defs/Outside" })), &["A"])
        .expect("a definition outside the surface");
    assert_eq!(outside.names().collect::<Vec<_>>(), ["A"]);
}

/// A reference of the schema's own root is followed only where its name is ASCII letters, digits
/// and `_`. A validator reads the fragment as a JSON pointer (`~1` is `/`, `%2F` is `/`, a trailing
/// `/` starts another segment), so a reference whose text is another definition's literal name may
/// point elsewhere for it: a cut that took the text for the name would compare the wrong target (a
/// root whose reference goes from `#/$defs/A~1B`, which is `A/B`, to `C` would be no difference
/// where the definition `A~1B` and `C` are alike). The names of every committed schema are plain, so
/// the strict form refuses none of them; it also refuses an empty name, which is a valid pointer.
#[test]
fn a_root_reference_whose_name_is_not_plain_is_refused_by_the_cut() {
    for (reference, literal) in [
        ("#/$defs/A~1B", "A~1B"),
        ("#/$defs/A%2FB", "A%2FB"),
        ("#/$defs/B/", "B/"),
        ("#/$defs/B#", "B#"),
        ("#/$defs/B ", "B "),
        ("#/$defs/", ""),
    ] {
        let schema = json!({ "$ref": reference, "$defs": {
            literal: { "type": "number" }, "C": { "type": "number" } } });
        assert_eq!(
            Surface::cut(&schema, &["C", literal]),
            Err(SurfaceError::BadReference(reference.to_owned())),
            "{reference}"
        );
    }
}

/// A definition with a name that begins with `$` is refused by the cut, where it is reached: the
/// place of the schema's own root is `$root`, and a difference of a definition of that name could
/// not be told from one of the root.
#[test]
fn a_definition_named_like_the_roots_place_is_refused() {
    let schema = json!({ "$defs": { "A": { "$ref": "#/$defs/$root" },
        "$root": { "type": "string" } } });
    for roots in [&["$root"][..], &["A"][..]] {
        assert_eq!(
            Surface::cut(&schema, roots),
            Err(SurfaceError::ReservedName("$root".to_owned())),
            "{roots:?}"
        );
    }
}
