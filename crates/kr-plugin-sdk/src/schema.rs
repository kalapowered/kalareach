//! Deterministic JSON Schema generation.
//!
//! Rust is canonical. The schema in `packages/plugin-sdk/schema/` comes from these types, the
//! TypeScript types come from that schema, and the WIT package is copied beside them so a
//! JavaScript build reads the same interface a Rust host does. Every step has a `--check` mode
//! that fails when the committed output no longer matches, which is what keeps the languages from
//! drifting.
//!
//! The output is byte stable: sorted objects, fixed indentation and one trailing newline.

use schemars::{JsonSchema, Schema, SchemaGenerator, generate::SchemaSettings, json_schema};
use serde_json::{Map, Value, json};

use crate::capability::{CapabilityEvidence, PluginCapability};
use crate::catalogue::{CatalogueIndex, INDEX_VERSION, IndexEntry, PublisherRecord};
use crate::connector::ConnectorManifest;
use crate::effect::{ActionInvocation, EffectClass};
use crate::limits::{InstanceLimits, RepositoryBudgets};
use crate::plugin::PluginManifest;
use crate::predicate::Predicate;
use crate::presentation::{DocumentNode, PresentationManifest, UnsupportedNode};
use crate::validate::{FindingCode, Report};
use crate::wit;

/// The generated JSON Schema bundle.
pub const SCHEMA_FILE_NAME: &str = "kalareach-plugin-sdk.schema.json";

/// The generated effect class and capability table.
pub const CONTRACT_FILE_NAME: &str = "package-contract.json";

/// Builds the JSON Schema bundle for every root document in the package contract.
///
/// The bundle is one document: a root object whose properties name the root documents and whose
/// `$defs` hold every referenced type exactly once, so the generated TypeScript is one module
/// with no duplicated interfaces.
#[must_use]
pub fn sdk_schema() -> Value {
    let mut generator: SchemaGenerator = SchemaSettings::draft2020_12().into_generator();
    let mut properties = Map::new();
    macro_rules! roots {
        ($($name:literal => $type:ty),+ $(,)?) => {
            $(properties.insert(
                $name.to_owned(),
                generator.subschema_for::<$type>().to_value(),
            );)+
        };
    }
    roots! {
        "plugin_manifest" => PluginManifest,
        "connector_manifest" => ConnectorManifest,
        "presentation_manifest" => PresentationManifest,
        "catalogue_index" => CatalogueIndex,
        "index_entry" => IndexEntry,
        "publisher_record" => PublisherRecord,
        "capability_evidence" => CapabilityEvidence,
        "document_node" => DocumentNode,
        "unsupported_node" => UnsupportedNode,
        "visibility_predicate" => Predicate,
        "action_invocation" => ActionInvocation,
        "instance_limits" => InstanceLimits,
        "repository_budgets" => RepositoryBudgets,
        "validation_report" => Report,
    }
    properties.insert(
        "vocabulary".to_owned(),
        vocabulary(&mut generator).to_value(),
    );
    let definitions = generator.take_definitions(true);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "KalaReach plugin SDK",
        "description": "Generated from the Rust types in crates/kr-plugin-sdk. Rust is canonical: edit the Rust types and regenerate. Every property below names one root document; $defs holds the referenced types.",
        "type": "object",
        "properties": Value::Object(properties),
        "$defs": Value::Object(definitions.into_iter().collect()),
    })
}

/// Registers the closed vocabularies so every consumer gets a named type for each one.
fn vocabulary(generator: &mut SchemaGenerator) -> Schema {
    let mut properties = Map::new();
    macro_rules! entries {
        ($($name:literal => $type:ty),+ $(,)?) => {
            $(properties.insert(
                $name.to_owned(),
                generator.subschema_for::<$type>().to_value(),
            );)+
        };
    }
    entries! {
        "effect_class" => EffectClass,
        "plugin_capability" => PluginCapability,
        "capability_state" => crate::capability::CapabilityState,
        "evidence_source" => crate::capability::EvidenceSource,
        "invalidation_trigger" => crate::capability::InvalidationTrigger,
        "method_class" => crate::connector::MethodClass,
        "broker_transport" => crate::connector::BrokerTransport,
        "framing" => crate::connector::Framing,
        "standard_icon" => crate::presentation::StandardIcon,
        "semantic_priority" => crate::presentation::SemanticPriority,
        "binding_state" => crate::predicate::BindingState,
        "presentation_flag" => crate::predicate::PresentationFlag,
        "operating_system" => crate::matching::OperatingSystem,
        "architecture" => crate::matching::Architecture,
        "payload_role" => crate::plugin::PayloadRole,
        "revocation_reason" => crate::catalogue::RevocationReason,
        "finding_code" => FindingCode,
        "package_path" => crate::paths::PackagePath,
        "payload_digest" => crate::digest::PayloadDigest,
        "package_version" => crate::version::PackageVersion,
        "version_range" => crate::version::VersionRange,
    }
    json_schema!({
        "type": "object",
        "description": "Every closed vocabulary in the package contract. This is a vocabulary rather than a document: it exists so each enumeration has one named type.",
        "properties": Value::Object(properties)
    })
}

/// Builds the package contract as data.
///
/// Consumers that are not written in Rust read this file instead of re-deriving the tables. It
/// carries the effect classes with the rights each one needs, the capabilities with their default
/// ceiling, the node union, the execution limits and the repository budgets.
#[must_use]
pub fn package_contract() -> Value {
    let effects: Vec<Value> = EffectClass::ALL
        .iter()
        .map(|class| {
            json!({
                "effect": class.as_str(),
                "mutation": class.is_mutation(),
                "required_rights": class
                    .required_rights()
                    .iter()
                    .map(|right| right.as_str())
                    .collect::<Vec<_>>(),
                "required_capability": class.required_capability().as_str(),
            })
        })
        .collect();
    let capabilities: Vec<Value> = PluginCapability::ALL
        .iter()
        .map(|capability| {
            json!({
                "capability": capability.as_str(),
                "within_default_ceiling": capability.within_default_ceiling(),
                "requires_installation_grant": capability.requires_installation_grant(),
                "required_right": capability.required_right().map(|right| right.as_str()),
            })
        })
        .collect();
    json!({
        "description": "The KalaReach package contract as data. Generated from crates/kr-plugin-sdk; do not edit by hand.",
        "sdk_version": crate::version::SDK_VERSION,
        "wit_version": crate::version::WIT_VERSION,
        "index_version": INDEX_VERSION,
        "manifest_version": PluginManifest::CURRENT_VERSION,
        "wit_package": {
            "name": wit::PACKAGE_NAME,
            "world": wit::WORLD,
            "export_interface": wit::EXPORT_INTERFACE,
            "exports": wit::EXPORTS,
            "imports": wit::IMPORT_PURPOSES
                .iter()
                .map(|(name, purpose)| json!({"interface": name, "purpose": purpose}))
                .collect::<Vec<_>>(),
        },
        "effect_classes": effects,
        "capabilities": capabilities,
        "default_repository_ceiling": PluginCapability::DEFAULT_REPOSITORY_CEILING
            .iter()
            .map(|capability| capability.as_str())
            .collect::<Vec<_>>(),
        "document_node_kinds": crate::presentation::NodeBody::KINDS,
        "finding_codes": FindingCode::ALL
            .iter()
            .map(|code| code.as_str())
            .collect::<Vec<_>>(),
        "instance_limits": InstanceLimits::defaults(),
        "repository_budgets": RepositoryBudgets::defaults(),
        "predicate_bounds": {
            "max_depth": crate::predicate::MAX_PREDICATE_DEPTH,
            "max_terms": crate::predicate::MAX_PREDICATE_TERMS,
        },
        "package_bounds": {
            "max_files": crate::package::MAX_PACKAGE_FILES,
            "max_bytes": crate::package::MAX_PACKAGE_BYTES,
            "max_document_nodes": crate::presentation::MAX_DOCUMENT_NODES,
            "max_controls": crate::presentation::MAX_CONTROLS,
            "max_parameters": crate::effect::MAX_PARAMETERS,
            "max_classified_methods": crate::connector::MAX_CLASSIFIED_METHODS,
        },
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
        (SCHEMA_FILE_NAME, render(&sdk_schema())),
        (CONTRACT_FILE_NAME, render(&package_contract())),
    ]
}

fn render(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("generated JSON is serialisable");
    text.push('\n');
    text
}

/// Returns the schema of one type, for tests that assert a single shape.
#[must_use]
pub fn schema_for<T: JsonSchema>() -> Value {
    SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<T>()
        .to_value()
}
