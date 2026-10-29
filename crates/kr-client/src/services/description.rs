//! The description a service publishes of itself: which relays, discovery servers and service
//! origins a host that joins it should select.
//!
//! A service publishes the description at [`PATH`] on its own origin, with no credential. It is the
//! part of a host's configuration document that a service can speak for: the relay map, the Pkarr
//! publisher and resolver, the DNS origin, and the origins of the authority feed, the mailbox and
//! the relay lease service, under the names the document gives them. This module reads it and
//! turns it into a [`ServiceSelection`], which `kr host network` writes through the configuration
//! document's own writer. It decides nothing else: no host fetches a description by itself, and
//! what a host selects is only ever what its document says.
//!
//! # What vouches for it
//!
//! The description decides where a host sends its traffic and the choice stays in the document
//! until the person joins again, so a forged one would outlast the connection it was forged on. The
//! managed service signs it, with the key that signs its release matrix and that every build pins
//! ([`Pins`]), under a context of its own, [`DOMAIN`], which is part of the signed bytes: a matrix
//! signature is never a description's, and a description's is never a matrix's. [`Trust::Pinned`]
//! requires that signature. A service a person runs names its own public key, and a description
//! signed by it is read the same way. [`Trust::TlsOnly`] takes the description on the connection
//! alone, for a person who has said so.
//!
//! The key the service publishes beside a signature proves nothing, since whoever forged the
//! description would publish a key of their own, so this module never reads one.
//!
//! # What is accepted
//!
//! The published reply is `{ "description": { ... }, "signature": "..." }`. The description is
//! read when all of these hold, and each is its own [`Refusal`]:
//!
//! 1. its `schema_version` is 1, so a later description is one this build does not read;
//! 2. every member this build reads has the type it declares: lists of text, text, or null for a
//!    service the description does not name;
//! 3. no member it does not know is within two edits of a name it does know, since a misspelling
//!    would otherwise drop a service without a word. Other unknown members are ignored, counted and
//!    named in [`Ignored`], and the signature does not cover them;
//! 4. when a key is pinned, the signature verifies over the bytes this module rebuilds from the
//!    members it read, field by field, with an absent service signed as null;
//! 5. no relay, discovery or service address is plain `http` unless the description itself was read
//!    from a plain `http` loopback origin and the address is on loopback too;
//! 6. it names a relay or a discovery server, since a host that joined one that names neither would
//!    have the network on and nothing to reach it by.
//!
//! Whether each value is one the document accepts is the document's validator's decision, and it
//! makes it when the selection is written.

use std::collections::BTreeSet;
use std::time::Duration;

use base64::Engine as _;
use kr_crypto::sign::SigningTranscript;
use kr_protocol::hostinfo::configuration::{ServiceSelection, near_miss};
use kr_protocol::scalars::Signature64;
use kr_protocol::service::GatewayOrigin;
use kr_transport::config::ProxyUrl;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::ServiceHttp;
use super::http::{HttpDeadlines, HttpService};
use super::matrix::Pins;

/// Where a service publishes its description.
pub const PATH: &str = "/.well-known/kalareach-service.json";

/// The most of an answer the transport reads on this path, which `managed_response_limits` sets.
pub const MAX_ANSWER_BYTES: u64 = 16 * 1024;

/// The context the service signs the description under, as the one key of the map it signs. It is
/// not the matrix's, so a signature made for one never verifies as the other.
pub const DOMAIN: &str = "kalareach-service-description-v1";

/// The only schema this build reads.
const SCHEMA_VERSION: u64 = 1;

/// The most ignored names that are kept for the report.
const NAMES_KEPT: usize = 16;

/// The longest ignored name that is kept for the report.
const NAME_BYTES: usize = 64;

/// The members of the description this build reads, and the members of each section.
const MEMBERS: [&str; 5] = ["schema_version", "network", "authority", "mailbox", "relay"];
const NETWORK_MEMBERS: [&str; 4] = [
    "relay_urls",
    "pkarr_publisher_url",
    "pkarr_resolver_url",
    "dns_origin",
];
const ORIGIN_MEMBERS: [&str; 1] = ["origin"];

/// What vouches for a description.
#[derive(Clone)]
pub enum Trust {
    /// A signature that verifies under one of these keys is required, and a description that has
    /// none, or whose signature does not verify, is refused.
    Pinned(Pins),
    /// The connection alone: the description is read as it came, and a signature on it is ignored.
    TlsOnly,
}

crate::debug_as_name!(Trust);

/// What a description names that this build does not read.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Ignored {
    count: usize,
    names: Vec<String>,
}

crate::debug_fields!(Ignored { count });

impl Ignored {
    /// How many members were left out.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// The names of some of them, at most sixteen: each at most 64 bytes of printable ASCII, so
    /// that a terminal prints one as it is. A longer name, or one with any other character, is
    /// counted and not kept.
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    fn note(&mut self, name: &str) {
        self.count += 1;
        if self.names.len() < NAMES_KEPT
            && !name.is_empty()
            && name.len() <= NAME_BYTES
            && name.chars().all(|character| character.is_ascii_graphic())
        {
            self.names.push(name.to_owned());
        }
    }
}

/// A description that passed every rule.
#[derive(Clone, PartialEq, Eq)]
pub struct Description {
    selection: ServiceSelection,
    signed: bool,
    ignored: Ignored,
}

crate::debug_fields!(Description { signed });

impl Description {
    /// What the service describes, as the document names it.
    #[must_use]
    pub const fn selection(&self) -> &ServiceSelection {
        &self.selection
    }

    /// Whether the description was verified under a pinned key.
    #[must_use]
    pub const fn signed(&self) -> bool {
        self.signed
    }

    /// The members this build left out.
    #[must_use]
    pub const fn ignored(&self) -> &Ignored {
        &self.ignored
    }
}

/// Why a published reply was not accepted. None of these says anything the service wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The reply is not JSON, or not the shape of a published description.
    Unreadable,
    /// Its `schema_version` is not 1.
    Version,
    /// A member has the wrong type.
    Malformed,
    /// A member is within two edits of a name this build reads.
    Misspelt,
    /// A signature was required and is absent, is not 64 bytes, or does not verify.
    Signature,
    /// A value is plain `http` where only `https` is read.
    Insecure,
    /// It names no relay and no discovery server.
    Empty,
}

impl Refusal {
    /// What a person is told, in this client's own words.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::Unreadable => "the service's description is not in a form this build reads",
            Self::Version => {
                "the service describes itself in a later form than this build reads; update \
                 KalaReach on this host"
            }
            Self::Malformed => "the service's description has a member of the wrong type",
            Self::Misspelt => {
                "the service's description has a member that resembles one this build reads and is \
                 not; the service should correct it"
            }
            Self::Signature => {
                "the service's description is not signed by the key this host expects of it"
            }
            Self::Insecure => {
                "the service's description names a plain http address, which a host joins only \
                 from a service on this machine"
            }
            Self::Empty => "the service's description names no relay and no discovery server",
        }
    }
}

/// Why the description was not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unread {
    /// The service did not answer, answered with a fault that passes (408, 429, 5xx), or answered
    /// past the bound the transport reads the description under.
    Unreachable,
    /// The service answered 404 or 501: it publishes no description.
    NotPublished,
    /// The service refused with another status.
    Refused(u16),
    /// This host could not set up a connection to the service: the proxy its document names is not
    /// one the transport can use, or the platform's certificate verification could not be set up.
    NoTransport,
    /// The service is addressed over plain `http` and the document names a proxy, which would
    /// carry the exchange in clear text to its own loopback.
    ClearTextViaProxy,
}

impl Unread {
    /// What a person is told, in this client's own words.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::Unreachable => {
                "the service could not be reached, or its answer was past the bound this host reads"
            }
            Self::NotPublished => "the service publishes no description of itself",
            Self::Refused(_) => "the service refused to give its description",
            Self::NoTransport => {
                "this host could not set up a connection to the service; check the proxy its \
                 configuration names"
            }
            Self::ClearTextViaProxy => {
                "the service is addressed over plain http, which a proxy would carry in clear \
                 text; a proxy is used with an https service only"
            }
        }
    }
}

/// How long the exchange may take: the deadlines the release matrix is read under.
const DEADLINES: HttpDeadlines = HttpDeadlines {
    connect: Duration::from_secs(5),
    read: Duration::from_secs(10),
    total: Duration::from_secs(20),
};

/// The transport that reads a description from `origin`: through `proxy`, the proxy the host's
/// document names, and directly when it names none. Nothing is read from the environment, and a
/// proxy that cannot be reached is not gone around.
///
/// # Errors
///
/// Returns [`Unread::NoTransport`] when the proxy or the platform's certificate verification
/// cannot be used, and [`Unread::ClearTextViaProxy`] for a plain `http` origin with a proxy.
pub fn connect(origin: &GatewayOrigin, proxy: Option<&str>) -> Result<HttpService, Unread> {
    let proxy = proxy
        .map(|text| text.parse::<ProxyUrl>())
        .transpose()
        .map_err(|_| Unread::NoTransport)?;
    if proxy.is_some() && origin.as_str().starts_with("http://") {
        return Err(Unread::ClearTextViaProxy);
    }
    HttpService::through(
        origin.clone(),
        DEADLINES,
        super::managed_response_limits(),
        proxy.as_ref(),
    )
    .map_err(|_| Unread::NoTransport)
}

/// Reads the published reply from `origin`.
///
/// # Errors
///
/// Returns why the reply was not read.
pub async fn fetch(http: &dyn ServiceHttp, origin: &GatewayOrigin) -> Result<Vec<u8>, Unread> {
    let url = format!("{}{PATH}", origin.as_str());
    let answer = http
        .get_json(&url, &[])
        .await
        .map_err(|_| Unread::Unreachable)?;
    match answer.status {
        200 => Ok(answer.body),
        404 | 501 => Err(Unread::NotPublished),
        408 | 429 | 500..=599 => Err(Unread::Unreachable),
        status => Err(Unread::Refused(status)),
    }
}

/// Whether `origin` is the managed service, whose description is read under the pinned key.
#[must_use]
pub fn is_managed(origin: &GatewayOrigin) -> bool {
    GatewayOrigin::new(super::account::ACCOUNT_ORIGIN)
        .is_ok_and(|managed| managed.as_str() == origin.as_str())
}

/// The reply as the service writes it. Members it does not name are data this module never reads.
#[derive(Deserialize)]
struct Published {
    description: Value,
    #[serde(default)]
    signature: Option<String>,
}

/// The bytes the service signs, field by field, in a fixed order: what is signed is what the
/// service means and not whatever shape the reply had. A service the description does not name is
/// null, and an unnamed list is empty.
#[derive(Serialize)]
struct Signed<'a> {
    schema_version: u64,
    network: SignedNetwork<'a>,
    authority: SignedOrigin<'a>,
    mailbox: SignedOrigin<'a>,
    relay: SignedOrigin<'a>,
}

#[derive(Serialize)]
struct SignedNetwork<'a> {
    relay_urls: &'a [String],
    pkarr_publisher_url: Option<&'a str>,
    pkarr_resolver_url: Option<&'a str>,
    dns_origin: Option<&'a str>,
}

#[derive(Serialize)]
struct SignedOrigin<'a> {
    origin: Option<&'a str>,
}

/// Accepts a published reply read from `origin`, or says which rule it broke.
///
/// # Errors
///
/// Returns the [`Refusal`] naming the first rule the reply breaks.
pub fn read(body: &[u8], origin: &GatewayOrigin, trust: &Trust) -> Result<Description, Refusal> {
    let published = super::json::read::<Published>(body).map_err(|_| Refusal::Unreadable)?;
    let Value::Object(members) = &published.description else {
        return Err(Refusal::Unreadable);
    };
    match members.get("schema_version").and_then(Value::as_u64) {
        Some(SCHEMA_VERSION) => {}
        Some(_) => return Err(Refusal::Version),
        None => return Err(Refusal::Malformed),
    }

    let mut ignored = Ignored::default();
    look_for_misspellings(members, &MEMBERS, &mut ignored)?;
    let network = section(members, "network", &NETWORK_MEMBERS, &mut ignored)?;
    let authority = section(members, "authority", &ORIGIN_MEMBERS, &mut ignored)?;
    let mailbox = section(members, "mailbox", &ORIGIN_MEMBERS, &mut ignored)?;
    let relay = section(members, "relay", &ORIGIN_MEMBERS, &mut ignored)?;

    let selection = ServiceSelection {
        relay_urls: texts(network.get("relay_urls"))?,
        pkarr_publisher_url: text(network.get("pkarr_publisher_url"))?,
        pkarr_resolver_url: text(network.get("pkarr_resolver_url"))?,
        dns_origin: text(network.get("dns_origin"))?,
        authority_origin: text(authority.get("origin"))?,
        mailbox_origin: text(mailbox.get("origin"))?,
        relay_origin: text(relay.get("origin"))?,
    };

    // The signature comes before anything is concluded from what was signed, so that a description
    // that is not the service's is refused as that and for no other reason.
    let signed = match trust {
        Trust::Pinned(pins) => {
            verify(&selection, published.signature.as_deref(), pins)?;
            true
        }
        Trust::TlsOnly => false,
    };

    if !addresses_are_secure(&selection, origin) {
        return Err(Refusal::Insecure);
    }
    if selection.selects_nothing() {
        return Err(Refusal::Empty);
    }
    Ok(Description {
        selection,
        signed,
        ignored,
    })
}

/// The section `name` of the description: its members, or none when it is absent or null.
fn section(
    members: &Map<String, Value>,
    name: &str,
    known: &[&str],
    ignored: &mut Ignored,
) -> Result<Map<String, Value>, Refusal> {
    match members.get(name) {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(section)) => {
            look_for_misspellings(section, known, ignored)?;
            Ok(section.clone())
        }
        Some(_) => Err(Refusal::Malformed),
    }
}

/// Refuses a member that is within two edits of a name `known` lists and is not that name, and
/// notes every other member `known` does not list.
fn look_for_misspellings(
    members: &Map<String, Value>,
    known: &[&str],
    ignored: &mut Ignored,
) -> Result<(), Refusal> {
    for name in members.keys() {
        if known.contains(&name.as_str()) {
            continue;
        }
        if known.iter().any(|known| near_miss(name, known)) {
            return Err(Refusal::Misspelt);
        }
        ignored.note(name);
    }
    Ok(())
}

/// A text member: absent and null are no value.
fn text(value: Option<&Value>) -> Result<Option<String>, Refusal> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(Refusal::Malformed),
    }
}

/// A list of text: absent and null are an empty list.
fn texts(value: Option<&Value>) -> Result<Vec<String>, Refusal> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => Ok(text.clone()),
                _ => Err(Refusal::Malformed),
            })
            .collect(),
        Some(_) => Err(Refusal::Malformed),
    }
}

/// Checks the signature over what was read.
fn verify(
    selection: &ServiceSelection,
    signature: Option<&str>,
    pins: &Pins,
) -> Result<(), Refusal> {
    let transcript = SigningTranscript::keyed(
        DOMAIN,
        &Signed {
            schema_version: SCHEMA_VERSION,
            network: SignedNetwork {
                relay_urls: &selection.relay_urls,
                pkarr_publisher_url: selection.pkarr_publisher_url.as_deref(),
                pkarr_resolver_url: selection.pkarr_resolver_url.as_deref(),
                dns_origin: selection.dns_origin.as_deref(),
            },
            authority: SignedOrigin {
                origin: selection.authority_origin.as_deref(),
            },
            mailbox: SignedOrigin {
                origin: selection.mailbox_origin.as_deref(),
            },
            relay: SignedOrigin {
                origin: selection.relay_origin.as_deref(),
            },
        },
    )
    .map_err(|_| Refusal::Malformed)?;
    let signature = signature
        .and_then(|text| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(text)
                .ok()
        })
        .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
        .map(Signature64::from_bytes)
        .ok_or(Refusal::Signature)?;
    if pins.vouches_for(&transcript, &signature) {
        Ok(())
    } else {
        Err(Refusal::Signature)
    }
}

/// Whether every address the description names may be joined from `origin`: `https` anywhere, and
/// plain `http` only on loopback and only when the description was itself read over plain `http`
/// from loopback.
fn addresses_are_secure(selection: &ServiceSelection, origin: &GatewayOrigin) -> bool {
    let local = url::Url::parse(origin.as_str())
        .ok()
        .is_some_and(|origin| origin.scheme() == "http" && is_loopback(&origin));
    let addresses: BTreeSet<&str> = selection
        .relay_urls
        .iter()
        .map(String::as_str)
        .chain(selection.pkarr_publisher_url.as_deref())
        .chain(selection.pkarr_resolver_url.as_deref())
        .chain(selection.authority_origin.as_deref())
        .chain(selection.mailbox_origin.as_deref())
        .chain(selection.relay_origin.as_deref())
        .collect();
    addresses.into_iter().all(|address| {
        match url::Url::parse(address) {
            Ok(address) if address.scheme() == "http" => local && is_loopback(&address),
            // `https` is fine, and what is neither is the document validator's to refuse.
            _ => true,
        }
    })
}

/// Whether this address names the loopback interface.
fn is_loopback(address: &url::Url) -> bool {
    match address.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}
