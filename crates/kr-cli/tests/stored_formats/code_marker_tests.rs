//! The marker that stands for the protocol's error code in a digest's input, and the table's
//! refusal of every other form of the code.
//!
//! A store keeps an error code as its wire word, so a code that the protocol gains or drops moves
//! no store's digest. The cases drive the normaliser over schemas of this module's own, built from
//! what the protocol generates, as the cases of the levels drive it over documents of their own.
//! None starts a daemon, reads a path or depends on the platform.

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::update::{Recording, ReleaseStore, StoreScope};
use serde_json::{Value, json};

use super::{
    Kept, Known, KnownIs, Store, Writers, canonical, code_forms_in, code_marker, code_type, hex,
    normalise_schema, normalise_with_code, table,
};

/// The schema the protocol generates for its error code.
fn code() -> Value {
    kr_protocol::schema::schema_for::<ErrorCode>()
}

/// `code` with one more word.
fn gained(mut code: Value) -> Value {
    code["oneOf"]
        .as_array_mut()
        .expect("the code is a list of variants")
        .push(json!({
            "const": "A_CODE_THE_PROTOCOL_GAINED",
            "description": "A code that a later release defines.",
            "type": "string"
        }));
    code
}

/// `code` without its last word.
fn dropped(mut code: Value) -> Value {
    code["oneOf"]
        .as_array_mut()
        .expect("the code is a list of variants")
        .pop();
    code
}

/// The protocol's error object as it generates it, with `code` as the definition of the code.
fn error_object(code: &Value) -> Value {
    let mut object = kr_protocol::schema::schema_for::<ProtocolError>();
    object["$defs"]["ErrorCode"] = code.clone();
    object
}

/// What the digest's input holds for `object`, a type that is no code, read as a build whose own
/// schema of the code is `own` reads it.
fn input(object: &Value, own: &Value) -> Value {
    normalise_with_code(object, own, None).expect("the schema is read")
}

/// What the digest's input holds for `root`, the schema of the type that the build declares to be
/// the code.
fn code_root_input(root: &Value, own: &Value) -> Value {
    normalise_with_code(root, own, Some(code_type())).expect("the schema is read")
}

/// The digest of an input.
fn digest(input: &Value) -> String {
    hex(&kr_cbor::sha256(canonical(input).as_bytes()))
}

fn definitions_of(object: &mut Value) -> &mut Value {
    &mut object["$defs"]
}

/// A code the protocol gains, or one it drops, is not a change of what a store keeps: the digest's
/// input is the same where a type refers to the code.
#[test]
fn a_code_gained_or_dropped_moves_no_digest_where_a_type_refers_to_the_code() {
    let own = code();
    let before = input(&error_object(&own), &own);
    let more = gained(own.clone());
    assert_eq!(
        digest(&before),
        digest(&input(&error_object(&more), &more)),
        "one more code moves the digest of a type that refers to the code"
    );
    let fewer = dropped(own.clone());
    assert_eq!(
        digest(&before),
        digest(&input(&error_object(&fewer), &fewer)),
        "one code fewer moves the digest of a type that refers to the code"
    );
    assert!(
        canonical(&before).contains(&canonical(&code_marker())),
        "the code is in the input as the marker"
    );
}

/// The same where the code is the root of what a store keeps: the registry's line and the known
/// lines.
#[test]
fn a_code_gained_or_dropped_moves_no_digest_where_the_code_is_the_root() {
    let own = code();
    assert_eq!(
        code_root_input(&own, &own),
        code_marker(),
        "the root that is the code is the marker"
    );
    let more = gained(own.clone());
    assert_eq!(
        code_root_input(&more, &more),
        code_marker(),
        "one more code moves the digest of the root"
    );
    let fewer = dropped(own);
    assert_eq!(
        code_root_input(&fewer, &fewer),
        code_marker(),
        "one code fewer moves the digest of the root"
    );
}

/// A code that is any other form than a list of strings fails the check, at a reference and at
/// the root, and so does a list that a keyword narrows: a store keeps the wire word, and a form
/// that changes what a word is makes a stored word mean something else.
#[test]
fn the_code_in_another_form_fails_the_check() {
    let own = code();
    // An integer for a word.
    let integers = json!({ "oneOf": [
        { "const": 1, "type": "integer" }, { "const": 2, "type": "integer" } ] });
    // An enumeration of integers.
    let integer_enum = json!({ "type": "integer", "enum": [1, 2] });
    // An object.
    let object = json!({ "type": "object", "properties": { "word": { "type": "string" } } });
    // A variant that carries a value.
    let mut payload = own.clone();
    payload["oneOf"]
        .as_array_mut()
        .expect("variants")
        .push(json!({
            "type": "object",
            "properties": { "A_CODE": { "type": "string" } },
            "required": ["A_CODE"],
            "additionalProperties": false
        }));
    // A validation keyword that a variant gains.
    let mut keyword = own.clone();
    keyword["oneOf"][0]["pattern"] = json!("^[A-Z_]+$");
    // A keyword on the list.
    let mut listed = own.clone();
    listed["maxLength"] = json!(40);
    // A word twice.
    let mut twice = own;
    let first = twice["oneOf"][0].clone();
    twice["oneOf"].as_array_mut().expect("variants").push(first);
    // No word.
    let empty = json!({ "oneOf": [] });
    let forms = [
        integers,
        integer_enum,
        object,
        payload,
        keyword,
        listed,
        twice,
        empty,
    ];
    for (index, form) in forms.iter().enumerate() {
        let mut form = form.clone();
        form["title"] = json!("ErrorCode");
        let reference = normalise_with_code(&error_object(&form), &form, None);
        assert!(
            reference.is_err_and(|error| error.contains("plain list of strings")),
            "form {index} of the code passes at a reference"
        );
        let root = normalise_with_code(&form, &form, Some(code_type()));
        assert!(
            root.is_err_and(|error| error.contains("plain list of strings")),
            "form {index} of the code passes at the root"
        );
    }
}

/// A change to another enumeration moves the digest: the retry class that the error object keeps
/// is the one that stays closed.
#[test]
fn a_change_of_another_enumeration_moves_the_digest() {
    let own = code();
    let before = digest(&input(&error_object(&own), &own));
    let mut gained_class = error_object(&own);
    definitions_of(&mut gained_class)["RetryCategory"]["oneOf"]
        .as_array_mut()
        .expect("the retry class is a list of variants")
        .push(json!({ "const": "a_new_class", "type": "string" }));
    assert_ne!(
        before,
        digest(&input(&gained_class, &own)),
        "a retry class gained moves no digest"
    );
    let mut renamed_class = error_object(&own);
    renamed_class["$defs"]["RetryCategory"]["oneOf"][0]["const"] = json!("a_class_renamed");
    assert_ne!(
        before,
        digest(&input(&renamed_class, &own)),
        "a retry class renamed moves no digest"
    );
}

/// A change to the error object's other members moves the digest: a member, the nullability of a
/// member, the nullability of the code, and the `required` list.
#[test]
fn a_change_of_the_error_objects_other_members_moves_the_digest() {
    let own = code();
    let before = digest(&input(&error_object(&own), &own));
    let mut member = error_object(&own);
    member["properties"]["extra"] = json!({ "type": "string" });
    assert_ne!(before, digest(&input(&member, &own)), "a member added");
    let mut nullability = error_object(&own);
    nullability["properties"]["diagnostic_id"] =
        json!({ "$ref": "#/$defs/DiagnosticId", "description": "An identifier." });
    assert_ne!(
        before,
        digest(&input(&nullability, &own)),
        "a member made not nullable"
    );
    let mut nullable_code = error_object(&own);
    nullable_code["properties"]["code"] =
        json!({ "anyOf": [{ "$ref": "#/$defs/ErrorCode" }, { "type": "null" }] });
    assert_ne!(
        before,
        digest(&input(&nullable_code, &own)),
        "the code made nullable"
    );
    let mut required = error_object(&own);
    required["required"]
        .as_array_mut()
        .expect("the required list")
        .retain(|name| name != "message");
    assert_ne!(
        before,
        digest(&input(&required, &own)),
        "a member made optional"
    );
}

/// A type that only has the code's name is not the code and fails, at a reference and at the
/// root: an identity that is not certain is never guessed.
#[test]
fn a_type_that_only_has_the_codes_name_is_not_the_code_and_fails() {
    let own = code();
    let mut impostor = error_object(&own);
    definitions_of(&mut impostor)["ErrorCode"] = json!({ "type": "integer" });
    assert!(
        normalise_with_code(&impostor, &own, None)
            .is_err_and(|error| error.contains("only has the name")),
        "a definition of the code's name that is an integer is taken for the code"
    );
    let mut other_words = error_object(&own);
    definitions_of(&mut other_words)["ErrorCode"] = dropped(own.clone());
    assert!(
        normalise_with_code(&other_words, &own, None)
            .is_err_and(|error| error.contains("only has the name")),
        "a definition of the code's name with other words is taken for the code"
    );
    let mut root = json!({ "title": "ErrorCode", "type": "object", "properties": {} });
    assert!(
        normalise_with_code(&root, &own, None)
            .is_err_and(|error| error.contains("only has the name")),
        "a root of the code's name that is an object is taken for the code"
    );
    assert!(
        normalise_with_code(&root, &own, Some(code_type()))
            .is_err_and(|error| error.contains("is declared as the protocol's error code")),
        "a root declared as the code that is an object is taken for the code"
    );
    root["title"] = json!("Another");
    assert!(
        normalise_with_code(&root, &own, None).is_ok(),
        "a root with no relation to the code is refused"
    );
}

/// A definition is the code by its name and by its words together: one that is equal to the code
/// under any other name is not the code and fails the check. A second enumeration with the same
/// words would otherwise take the marker, and a word added to both lists would move no digest.
#[test]
fn a_definition_equal_to_the_code_under_another_name_is_not_the_code_and_fails() {
    let own = code();
    // A second enumeration, referred to by a member of its own, beside the code.
    let mut beside = error_object(&own);
    definitions_of(&mut beside)["OtherWords"] = own.clone();
    beside["properties"]["other"] = json!({ "$ref": "#/$defs/OtherWords" });
    assert!(
        normalise_with_code(&beside, &own, None)
            .is_err_and(|error| error.contains("equal to the protocol's error code")),
        "an enumeration with the code's words under another name beside the code is taken for it"
    );
    // The code itself under another name.
    let mut renamed = error_object(&own);
    let definition = definitions_of(&mut renamed)
        .as_object_mut()
        .expect("definitions")
        .remove("ErrorCode")
        .expect("the code's definition");
    definitions_of(&mut renamed)["StoredWord"] = definition;
    renamed["properties"]["code"]["$ref"] = json!("#/$defs/StoredWord");
    assert!(
        normalise_with_code(&renamed, &own, None)
            .is_err_and(|error| error.contains("equal to the protocol's error code")),
        "the code under another definition's name is taken for the code"
    );
    // A word that both enumerations gain together.
    let both = gained(own);
    let mut gained_by_both = error_object(&both);
    definitions_of(&mut gained_by_both)["OtherWords"] = both.clone();
    gained_by_both["properties"]["other"] = json!({ "$ref": "#/$defs/OtherWords" });
    assert!(
        normalise_with_code(&gained_by_both, &both, None)
            .is_err_and(|error| error.contains("equal to the protocol's error code")),
        "a word that is added to both enumerations moves no digest"
    );
}

/// Two definitions that are both equal to the code are not told apart: which one a type refers
/// to is not certain, so the check fails.
#[test]
fn two_definitions_equal_to_the_code_in_one_schema_fail() {
    let own = code();
    let mut twice = error_object(&own);
    definitions_of(&mut twice)["ErrorCode2"] = own.clone();
    assert!(
        normalise_with_code(&twice, &own, None)
            .is_err_and(|error| error.contains("two definitions")),
        "two equal definitions of the code are taken for the code"
    );
}

/// The schema library gives the second type of a name the name and a number. The code under that
/// name, with the name it would have had, is the code.
#[test]
fn the_schema_librarys_rename_of_the_code_on_a_clash_is_the_code() {
    let own = code();
    let before = input(&error_object(&own), &own);
    let mut clash = error_object(&own);
    let definition = definitions_of(&mut clash)
        .as_object_mut()
        .expect("definitions")
        .remove("ErrorCode")
        .expect("the code's definition");
    definitions_of(&mut clash)["ErrorCode2"] = definition;
    clash["properties"]["code"]["$ref"] = json!("#/$defs/ErrorCode2");
    assert_eq!(
        before,
        input(&clash, &own),
        "the code under the schema library's rename on a clash is not the code"
    );
}

/// The root is the code by the Rust type that a kept schema declares for it. A root equal to the
/// code and declared as another type, or declared as nothing, is not the code and fails; a root
/// declared as the code that is not what this build generates for it fails too.
#[test]
fn a_root_equal_to_the_code_is_the_code_only_where_it_is_declared_as_the_code() {
    let own = code();
    assert_eq!(
        code_root_input(&own, &own),
        code_marker(),
        "the root declared as the code is not the marker"
    );
    let mut other = own.clone();
    other["title"] = json!("OtherWords");
    for declared in [Some("kr_worker::OtherWords"), None] {
        assert!(
            normalise_with_code(&other, &own, declared)
                .is_err_and(|error| error.contains("not declared as the code")),
            "a root with the code's words that is declared as {declared:?} is taken for the code"
        );
    }
    assert!(
        normalise_with_code(&dropped(own.clone()), &own, Some(code_type()))
            .is_err_and(|error| error.contains("is declared as the protocol's error code")),
        "a root declared as the code that is not the build's code is taken for it"
    );
}

/// What the real error object and the real code are in the input: the marker and the retry class,
/// and none of the code's words. The protocol's own schema holds no marker.
#[test]
fn the_real_error_object_holds_the_marker_and_the_retry_class_and_no_word_of_the_code() {
    let object = normalise_schema(
        &kr_protocol::schema::schema_for::<ProtocolError>(),
        Some(std::any::type_name::<ProtocolError>()),
    )
    .expect("the error object is read");
    let text = canonical(&object);
    assert!(
        text.contains("protocol-error-code"),
        "the marker is not in the input"
    );
    assert!(
        text.contains("outcome_unknown"),
        "the retry class is not in the input"
    );
    for word in ErrorCode::ALL {
        assert!(
            !text.contains(word.as_str()),
            "the word {} of the code is in the input",
            word.as_str()
        );
    }
    assert_eq!(
        normalise_schema(&code(), Some(code_type())).expect("the code is read"),
        code_marker(),
        "the real code is not the marker"
    );
    assert!(
        !serde_json::to_string(&code())
            .expect("the schema")
            .contains("x-kr-stored-word"),
        "the protocol's own schema holds the marker"
    );
}

fn store_keeping(kept: Vec<Kept>) -> Store {
    Store {
        writers: Writers::Daemon,
        entry: ReleaseStore {
            store: "synthetic".to_owned(),
            scope: StoreScope::Environment,
            path: "synthetic.sqlite".to_owned(),
            recording: Recording::SqliteUserVersion,
            version: 1,
            migrates_from: 0,
            reads_through: None,
        },
        owned: Vec::new(),
        kept,
        levels: None,
    }
}

fn known_line(name: &'static str, is: KnownIs) -> Known {
    Known {
        store: "synthetic",
        name,
        is,
        pinned: "",
    }
}

const ERROR_SOURCE: &str = "crates/kr-protocol/src/error.rs";

/// No store keeps the error code in any form but its schema: a pin of its source hashes the macro
/// that lists the codes and not the codes, and a set of words that holds a code's word fixes the
/// set at the codes of the day. The table has none, and a planted one of each form is found.
#[test]
fn no_store_keeps_the_error_code_in_a_form_the_marker_does_not_see() {
    let found = code_forms_in(&table::table(), &table::known());
    assert!(
        found.is_empty(),
        "the table keeps the code in a form the digest does not hold as a word:\n{}",
        found.join("\n")
    );
    let word = ErrorCode::PermissionDenied.as_str().to_owned();
    let planted = store_keeping(vec![
        Kept::Source(ERROR_SOURCE, &["ErrorCode"]),
        Kept::Words("words of a column", vec!["quiet".to_owned(), word.clone()]),
    ]);
    let found = code_forms_in(&[planted], &[]);
    assert_eq!(found.len(), 2, "a source pin and a words set: {found:?}");
    let known = [
        known_line("ErrorCode", KnownIs::Source(ERROR_SOURCE)),
        known_line("words", KnownIs::Words(vec![word], None, &[])),
        known_line(
            "words of enums",
            KnownIs::Words(Vec::new(), None, &[(ERROR_SOURCE, "ErrorCode")]),
        ),
    ];
    let found = code_forms_in(&[], &known);
    assert_eq!(
        found.len(),
        3,
        "a known source pin, a known set of words and a known enumeration: {found:?}"
    );
    let harmless = store_keeping(vec![
        Kept::Source(ERROR_SOURCE, &["RetryCategory"]),
        Kept::Words("words of a column", vec!["quiet".to_owned()]),
    ]);
    assert!(
        code_forms_in(&[harmless], &[]).is_empty(),
        "a source pin and a set of words with no relation to the code are found"
    );
}
