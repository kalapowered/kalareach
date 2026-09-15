//! The declarative native-proxy table.
//!
//! A native terminal application uses the KalaReach gateway only when its connector supplies a
//! qualified declarative table for framing, request identifiers, response correlation, routing
//! and method classification. Core code interprets that table directly. No Wasm runs on the
//! forwarding path, so a component fault disables rich meaning without stalling or discarding
//! otherwise valid native traffic.
//!
//! Two rules in this module are not configurable, because making them configurable would make
//! them defeatable.
//!
//! * An unclassified method is a mutation. [`ConnectorManifest::classify`] returns
//!   [`MethodClass::Mutation`] for anything the table does not list, so a method a publisher
//!   forgot is treated as capable of changing something.
//! * A transport handle binds the selected executable, launch, upstream identity and environment.
//!   The manifest names a transport kind and its bounded parameters; it never names a URL, a
//!   process or a filesystem path the broker would then open.

use kr_protocol::scalars::Nullable;

use crate::scalars::U64;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{MethodName, PluginId};
use crate::text::Summary;
use crate::version::{PackageVersion, VersionRange};

/// Maximum number of methods one classification table may list.
pub const MAX_CLASSIFIED_METHODS: usize = 512;

/// Maximum number of segments in a field path.
pub const MAX_FIELD_PATH_DEPTH: usize = 8;

/// What a native method does to the upstream.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MethodClass {
    /// Reports state without changing it.
    Observation,
    /// Changes something.
    Mutation,
    /// Carries a credential. The broker keeps it and never passes it to a component.
    Credential,
    /// The connector states that this method is outside what it can proxy safely.
    Unsupported,
}

impl MethodClass {
    /// The class the broker assumes for a method the table does not list.
    ///
    /// Section 11 makes any unclassified native request presumed mutation-capable for
    /// rich-state safety, so the default is the conservative one and nothing can change it.
    pub const UNCLASSIFIED: Self = Self::Mutation;
}

/// A bounded path into a decoded native message.
///
/// The grammar is member names and array indices only, with no wildcard, no filter and no
/// recursive descent. The broker evaluates it against every framed message on the forwarding
/// path, so it must cost a fixed number of lookups.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FieldPath {
    /// The path segments, from the root of the message.
    pub segments: Vec<FieldSegment>,
}

/// One segment of a [`FieldPath`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldSegment {
    /// A member of an object.
    Member {
        /// The member name.
        name: String,
    },
    /// An element of an array.
    Index {
        /// The zero-based index.
        index: u32,
    },
}

/// How messages are separated on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Framing {
    /// One JSON document per line.
    LineDelimitedJson {
        /// Maximum bytes in one line.
        max_message_bytes: U64,
    },
    /// A header block with a content length, then the body.
    ContentLength {
        /// The header that carries the length.
        length_header: String,
        /// Maximum bytes in one body.
        max_message_bytes: U64,
    },
    /// A big-endian length prefix, then the body.
    LengthPrefixed {
        /// Width of the length prefix in bytes.
        prefix_bytes: u8,
        /// Maximum bytes in one body.
        max_message_bytes: U64,
    },
    /// Server-sent events.
    ServerSentEvents {
        /// Maximum bytes in one event.
        max_message_bytes: U64,
    },
}

impl Framing {
    /// The smallest and largest message size a framing may declare.
    ///
    /// A framing that accepts nothing cannot carry a message, and one that accepts more than the
    /// control frame limit describes a stream the broker would not read anyway.
    pub const MESSAGE_BYTES_RANGE: std::ops::RangeInclusive<u64> = 1..=(16 * 1024 * 1024);

    /// The prefix widths a length-prefixed framing may declare.
    pub const PREFIX_WIDTHS: &'static [u8] = &[1, 2, 4, 8];

    /// Returns the maximum bytes one framed message may carry.
    #[must_use]
    pub const fn max_message_bytes(&self) -> u64 {
        match self {
            Self::LineDelimitedJson { max_message_bytes }
            | Self::ContentLength {
                max_message_bytes, ..
            }
            | Self::LengthPrefixed {
                max_message_bytes, ..
            }
            | Self::ServerSentEvents { max_message_bytes } => max_message_bytes.get(),
        }
    }
}

/// How the broker reaches the upstream.
///
/// The broker owns the handle. A connector names the kind and its bounded parameters; the
/// executable, launch, upstream identity and environment come from the binding the host made, so
/// a package cannot substitute an arbitrary URL, process or path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BrokerTransport {
    /// JSON-RPC or JSON lines over the bound process's standard streams.
    Stdio,
    /// A private Unix socket or named pipe the broker created.
    PrivateSocket,
    /// Loopback HTTP to the bound process's advertised port.
    LoopbackHttp,
    /// A WebSocket to the bound process.
    WebSocket,
    /// Server-sent events from the bound process.
    ServerSentEvents,
    /// A bounded byte stream with the connector's own framing.
    ByteStream,
}

/// How a response is matched to its request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseCorrelation {
    /// The response repeats the request identifier at a known path.
    MatchingId {
        /// Where the identifier is in a response.
        id_path: FieldPath,
    },
    /// Responses arrive in request order on a single ordered channel.
    ///
    /// The broker still records each opaque request before forwarding it, so ordering is how a
    /// reply is matched, not a reason to skip the ledger.
    Ordered {},
}

/// One route from a native method to the stream that carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Route {
    /// The method as the table names it.
    pub method: MethodName,
    /// The method name exactly as it appears on the wire.
    pub wire_name: String,
    /// The direction the method travels.
    pub direction: RouteDirection,
}

/// Which way a native method travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RouteDirection {
    /// The application asks KalaReach.
    UpstreamToHost,
    /// KalaReach asks the application.
    HostToUpstream,
    /// Either side may send it.
    Bidirectional,
}

/// One entry in the method classification table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct MethodClassification {
    /// The method.
    pub method: MethodName,
    /// What it does.
    pub class: MethodClass,
    /// What the publisher qualified this classification against.
    pub evidence: Summary,
}

/// The upstream protocol a table is pinned to.
///
/// A table is qualified against one installed protocol version. It is not carried forward to a
/// version nobody tested, because the classification of a method is exactly the kind of thing a
/// protocol revision changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProtocolPin {
    /// The protocol name as the vendor publishes it.
    pub name: String,
    /// The versions this table was qualified against.
    pub qualified_range: VersionRange,
    /// The exact version the publisher tested.
    pub tested_version: PackageVersion,
}

/// The connector manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ConnectorManifest {
    /// The manifest format version.
    pub manifest_version: u32,
    /// The package this table belongs to.
    pub plugin_id: PluginId,
    /// The upstream protocol this table is qualified against.
    pub protocol: ProtocolPin,
    /// How the broker reaches the upstream.
    pub transport: BrokerTransport,
    /// How messages are separated.
    pub framing: Framing,
    /// Where a request carries its identifier.
    pub request_id_path: FieldPath,
    /// Where a message names its method.
    pub method_path: FieldPath,
    /// How a response is matched to its request.
    pub response_correlation: ResponseCorrelation,
    /// The routes.
    pub routes: Vec<Route>,
    /// What each method does.
    pub methods: Vec<MethodClassification>,
    /// Whether the connector has a tested volatile forwarding mode.
    ///
    /// Without one it is not a resilient managed gateway: on receipt-storage failure its
    /// unchanged terminal integration is the supported path, and the manifest says so rather than
    /// letting a reader assume otherwise.
    pub volatile_forwarding: bool,
    /// What the publisher says about the qualification behind this table.
    pub qualification_note: Nullable<Summary>,
}

impl ConnectorManifest {
    /// The manifest format version this crate reads and writes.
    pub const CURRENT_VERSION: u32 = 1;

    /// Returns what the table says a method does.
    ///
    /// A method the table does not list is [`MethodClass::UNCLASSIFIED`], which is
    /// [`MethodClass::Mutation`]. There is no manifest field that changes this.
    #[must_use]
    pub fn classify(&self, method: &MethodName) -> MethodClass {
        self.methods
            .iter()
            .find(|entry| &entry.method == method)
            .map_or(MethodClass::UNCLASSIFIED, |entry| entry.class)
    }

    /// Returns the route for a wire method name.
    #[must_use]
    pub fn route_for_wire_name(&self, wire_name: &str) -> Option<&Route> {
        self.routes
            .iter()
            .find(|route| route.wire_name == wire_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method(name: &str) -> MethodName {
        MethodName::new(name).expect("valid method name")
    }

    fn manifest() -> ConnectorManifest {
        ConnectorManifest {
            manifest_version: 1,
            plugin_id: PluginId::new("kalareach/example").expect("valid plugin id"),
            protocol: ProtocolPin {
                name: "example-rpc".to_owned(),
                qualified_range: VersionRange::parse(">=1.0, <2.0").expect("valid range"),
                tested_version: PackageVersion::parse("1.3.0").expect("valid version"),
            },
            transport: BrokerTransport::Stdio,
            framing: Framing::LineDelimitedJson {
                max_message_bytes: U64::new(1_048_576),
            },
            request_id_path: FieldPath {
                segments: vec![FieldSegment::Member {
                    name: "id".to_owned(),
                }],
            },
            method_path: FieldPath {
                segments: vec![FieldSegment::Member {
                    name: "method".to_owned(),
                }],
            },
            response_correlation: ResponseCorrelation::MatchingId {
                id_path: FieldPath {
                    segments: vec![FieldSegment::Member {
                        name: "id".to_owned(),
                    }],
                },
            },
            routes: vec![Route {
                method: method("status.read"),
                wire_name: "status/read".to_owned(),
                direction: RouteDirection::HostToUpstream,
            }],
            methods: vec![
                MethodClassification {
                    method: method("status.read"),
                    class: MethodClass::Observation,
                    evidence: Summary::new("Returns the current turn state and nothing else")
                        .expect("valid summary"),
                },
                MethodClassification {
                    method: method("file.write"),
                    class: MethodClass::Mutation,
                    evidence: Summary::new("Writes to the workspace").expect("valid summary"),
                },
            ],
            volatile_forwarding: false,
            qualification_note: Nullable(None),
        }
    }

    #[test]
    fn an_unclassified_method_is_a_mutation() {
        let manifest = manifest();
        assert_eq!(
            manifest.classify(&method("never.listed")),
            MethodClass::Mutation
        );
        assert_eq!(MethodClass::UNCLASSIFIED, MethodClass::Mutation);
    }

    #[test]
    fn the_table_answers_for_the_methods_it_lists() {
        let manifest = manifest();
        assert_eq!(
            manifest.classify(&method("status.read")),
            MethodClass::Observation
        );
        assert_eq!(
            manifest.classify(&method("file.write")),
            MethodClass::Mutation
        );
    }

    #[test]
    fn a_route_is_found_by_its_wire_spelling() {
        let manifest = manifest();
        let route = manifest
            .route_for_wire_name("status/read")
            .expect("the route is listed");
        assert_eq!(route.direction, RouteDirection::HostToUpstream);
        assert!(manifest.route_for_wire_name("status.read").is_none());
    }

    #[test]
    fn the_manifest_cannot_name_a_process_or_a_url() {
        // A transport is a kind, not a target. There is no field for a command line, an
        // executable path or an address, so a connector cannot describe one.
        let value = serde_json::to_value(manifest()).expect("serialisable");
        let text = value.to_string();
        for forbidden in ["command", "argv", "url", "endpoint", "executable", "path"] {
            assert!(
                !text.contains(&format!("\"{forbidden}\"")),
                "the manifest carries a {forbidden} field"
            );
        }
        let with_url = serde_json::json!({
            "manifest_version": 1,
            "plugin_id": "kalareach/example",
            "url": "https://example.test"
        });
        assert!(serde_json::from_value::<ConnectorManifest>(with_url).is_err());
    }
}
