//! The KalaReach plugin package contract.
//!
//! A plugin is an installable package; an adapter is its active binding to an application. This
//! crate defines what a package is: the manifests it carries, the component interface it may
//! implement, the effect classes its actions declare, the catalogue index it appears in, and the
//! validation every host, publisher and pipeline runs before trusting any of it.
//!
//! Rust is canonical. The JSON Schema in `packages/plugin-sdk/schema/`, the TypeScript types and
//! the published WIT package are all generated from these types and checked in continuous
//! integration.
//!
//! # What a package is
//!
//! A directory with `plugin.json`, `presentation.json`, an optional `connector.json`, an optional
//! `component.wasm`, and whatever assets, bridge files, skills and fixtures the manifest declares.
//! Nothing undeclared is permitted, and every declared byte is named by its digest and its exact
//! length.
//!
//! A simple definition needs no Wasm at all. Match rules, a document and declarative controls are
//! a complete package, which is why a vendor can add detection, presentation and commands without
//! a core or companion-app release.
//!
//! # What a package cannot do
//!
//! The boundaries are in the types rather than in prose:
//!
//! * [`connector`] has no field for a command line, an executable or an address. A transport
//!   handle binds the executable, launch, upstream identity and environment the host chose.
//! * [`presentation`] is a closed node union rendered by standard client components. There is no
//!   variant that carries markup, styles or script.
//! * [`predicate`] is a bounded boolean grammar over closed vocabularies with no expression form.
//! * [`effect`] resolves each class to the rights the broker intersects, so a label cannot buy an
//!   effect the class does not carry.
//! * [`capability`] separates what a package requests from what a host has evidence for, and
//!   rejects a signed record that claims a host result it cannot establish.
//! * [`paths`] admits only paths that mean one unambiguous file on Linux, macOS and Windows.
//! * [`integration`] adds only whole flags a person confirmed to the command it names, and sets
//!   only environment variables the contract permits by exact name and value.
//!
//! # Modules
//!
//! | Module | What it holds |
//! | --- | --- |
//! | [`ids`] | Publisher, plugin, node, control, action and method identifiers |
//! | [`text`] | Bounded label, description and reason text |
//! | [`version`] | Package versions and the ranges a package accepts |
//! | [`digest`] | Payload digests and declared sizes |
//! | [`identity`] | What binds executable plugin semantics to a verified package |
//! | [`paths`] | Safe package paths and case-collision detection |
//! | [`limits`] | The execution limits and repository budgets a package runs under |
//! | [`capability`] | Requested capabilities and capability evidence |
//! | [`effect`] | Effect classes, actions, parameters and attachment contributions |
//! | [`matching`] | Declarative executable and distribution match rules |
//! | [`predicate`] | The bounded visibility predicate grammar |
//! | [`presentation`] | The document node union and declarative controls |
//! | [`connector`] | The declarative native-proxy table |
//! | [`plugin`] | The `plugin.json` manifest |
//! | [`integration`] | A package's command integration: its command, flags and variables |
//! | [`catalogue`] | The signed catalogue index |
//! | [`package`] | The on-disk package layout |
//! | [`validate`] | Package validation and its stable finding codes |
//! | [`wit`] | The `kalareach:plugin` WIT package |
//! | [`example`] | A complete example package |
//! | [`scalars`] | The scalars these types are built from |
//! | [`schema`] | Deterministic JSON Schema generation |
//!
//! # Example
//!
//! ```
//! use kr_plugin_sdk::connector::MethodClass;
//! use kr_plugin_sdk::effect::EffectClass;
//! use kr_plugin_sdk::capability::PluginCapability;
//!
//! // An effect class resolves to the rights the broker intersects at dispatch.
//! assert!(EffectClass::TerminalInput.is_mutation());
//! assert_eq!(
//!     EffectClass::TerminalInput.required_rights(),
//!     &[kr_protocol::rights::ActionRight::TerminalInput]
//! );
//!
//! // Observation carries no input right, whatever an action calls itself.
//! assert!(!EffectClass::Observe.is_mutation());
//!
//! // A native method nobody classified is a mutation.
//! assert_eq!(MethodClass::UNCLASSIFIED, MethodClass::Mutation);
//!
//! // Enrolling a repository permits metadata, presentation and authorised events, nothing else.
//! assert!(PluginCapability::MetadataMatch.within_default_ceiling());
//! assert!(!PluginCapability::TerminalInput.within_default_ceiling());
//! ```

pub mod bundle;
pub mod capability;
pub mod catalogue;
pub mod connector;
pub mod digest;
pub mod effect;
pub mod example;
pub mod identity;
pub mod ids;
pub mod integration;
pub mod limits;
pub mod matching;
pub mod package;
pub mod paths;
pub mod plugin;
pub mod predicate;
pub mod presentation;
pub mod scalars;
pub mod schema;
pub mod text;
pub mod validate;
pub mod version;
pub mod wit;
