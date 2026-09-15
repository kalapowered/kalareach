//! Deterministic JSON Schema and method-table generation.
//!
//! Rust is canonical. The TypeScript package is generated from the schema this module produces, so
//! a change to a Rust type flows to the schema, and from the schema to TypeScript. Both steps have
//! a `--check` mode that fails when the committed output no longer matches, which is what keeps
//! the two languages from drifting.
//!
//! The output is byte stable: every object is a sorted map, the indentation is fixed and each file
//! ends with one newline.

use schemars::{JsonSchema, SchemaGenerator, generate::SchemaSettings};
use serde_json::{Map, Value, json};

use crate::actor::ActorEnvelope;
use crate::authority::MethodEntry;
use crate::envelope::{MutationRequest, Notification, Request, Response};
use crate::error::ProtocolError;
use crate::frame::StreamHeader;
use crate::grant::Grant;
use crate::hello::{ClientOffer, HostSelection};
use crate::ids::SessionRef;
use crate::method::{Method, REGISTRY};
use crate::receipt::{Receipt, ReceiptResponse};

/// The generated JSON Schema bundle.
pub const SCHEMA_FILE_NAME: &str = "kalareach-protocol.schema.json";

/// The generated method and authority table.
pub const METHOD_AUTHORITY_FILE_NAME: &str = "method-authority.json";

/// Adds one root type to the bundle.
macro_rules! roots {
    ($generator:ident, $properties:ident, $($name:literal => $type:ty),+ $(,)?) => {
        $(
            let schema = $generator.subschema_for::<$type>();
            $properties.insert($name.to_owned(), schema.to_value());
        )+
    };
}

/// Builds the JSON Schema bundle for every root protocol message.
///
/// The bundle is one document: a root object whose properties name the root messages and whose
/// `$defs` hold every referenced type exactly once. One document means the generated TypeScript is
/// one module with no duplicated interfaces.
#[must_use]
pub fn protocol_schema() -> Value {
    let mut generator: SchemaGenerator = SchemaSettings::draft2020_12().into_generator();
    let mut properties = Map::new();
    roots! {
        generator, properties,
        "actor_envelope" => ActorEnvelope,
        "client_offer" => ClientOffer,
        "grant" => Grant,
        "host_selection" => HostSelection,
        "method_entry" => MethodEntry,
        "mutation_request" => MutationRequest,
        "notification" => Notification,
        "protocol_error" => ProtocolError,
        "receipt" => Receipt,
        "receipt_response" => ReceiptResponse,
        "request" => Request,
        "response" => Response,
        "session_ref" => SessionRef,
        "stream_header" => StreamHeader,
    }
    let definitions = generator.take_definitions(true);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "KalaReach protocol",
        "description": "Generated from the Rust wire types in crates/kr-protocol. Rust is canonical: edit the Rust types and regenerate. Every property below names one root message; $defs holds the referenced types.",
        "type": "object",
        "properties": Value::Object(properties),
        "$defs": Value::Object(definitions.into_iter().collect()),
    })
}

/// Builds the method and authority table as data.
///
/// Consumers that are not written in Rust read this file instead of re-deriving the table. Any
/// method that is not listed here is denied.
#[must_use]
pub fn method_authority_table() -> Value {
    json!({
        "description": "One exhaustive authority entry per method. Anything not listed is denied. Generated from crates/kr-protocol; do not edit by hand.",
        "method_count": REGISTRY.len(),
        "unlisted_methods_are_denied": true,
        "methods": REGISTRY,
    })
}

/// Returns every generated file as a name and its exact contents.
///
/// # Panics
///
/// Panics when a generated document cannot be serialised, which would mean a schema type is
/// malformed rather than a runtime condition.
#[must_use]
pub fn generated_files() -> Vec<(&'static str, String)> {
    vec![
        (SCHEMA_FILE_NAME, render(&protocol_schema())),
        (
            METHOD_AUTHORITY_FILE_NAME,
            render(&method_authority_table()),
        ),
    ]
}

fn render(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("generated JSON is serialisable");
    text.push('\n');
    text
}

/// Returns the schema name every method uses, for cross-checking the table against the enum.
#[must_use]
pub fn method_names() -> Vec<&'static str> {
    Method::ALL.iter().map(|method| method.as_str()).collect()
}

/// Returns the schema of one type, for tests that assert a single shape.
#[must_use]
pub fn schema_for<T: JsonSchema>() -> Value {
    SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<T>()
        .to_value()
}
