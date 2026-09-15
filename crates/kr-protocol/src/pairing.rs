//! Pairing wire objects: the contexts, bundles, transcripts and QR payloads of section 10.
//!
//! This module holds the shapes and their exact canonical encodings. It performs no cryptography:
//! `kr-crypto` signs and encrypts, and `kr-pairing` owns the state machines, budgets and the
//! order in which the objects below are produced.
//!
//! # The contracts that must not drift
//!
//! Section 23 states that pairing array order, HKDF labels and envelope additional authenticated
//! data are exact contracts. Three of them are arrays rather than maps, because the specification
//! writes them as arrays:
//!
//! | Object | Encoding |
//! | --- | --- |
//! | [`PairingContext`] (`C`) | `[domain, rendezvous_origin, locator, invitation_id, attempt_id, host_nonce, client_nonce]` |
//! | Role identities | `CBOR(["kr-pair/host", CH])` and `CBOR(["kr-pair/client", CH])` |
//! | Bundle AAD | `[domain, T, direction, sequence, message_type]` |
//! | [`DirectTranscript`] (`D`) | `[domain, invitation_id, host_endpoint_id, client_endpoint_id, host_keys, client_keys, proposed_grant_digest, host_nonce, client_nonce, expires_at_ms]` |
//!
//! Everything else is a closed map type whose canonical encoding follows from its field names.
//!
//! # Profile decisions
//!
//! Section 10 fixes some of this exactly and leaves the rest to the implementation. What it fixes
//! is above. What it does not fix is decided here, once, and frozen by the vectors under
//! `fixtures/pairing/`:
//!
//! | Decision | Choice | Why |
//! | --- | --- | --- |
//! | The bundle signature domains | `kr-pair/host-bundle/1`, `kr-pair/client-bundle/1` | Section 10 says each device signs its bundle and `T`; it names no domain, and a shared one would let a host bundle verify as a client bundle |
//! | The `pair.finish` tag domain | `kr-pair/finish/1` | Section 10 fixes the tag's key and its inputs, not its encoding |
//! | The owner-confirmation domain | `kr-pair/owner-confirm/1` | Section 10 fixes the fields, not the encoding |
//! | The key identifier domain | `kr-key-id/1` | Section 10 requires purposes to stay separate; putting the purpose inside the identifier is how that is enforced |
//! | The revocation and authority domains | `kr-revocation/1`, `kr-authority/1` | Section 10 requires signed revocation requests and host-issued revision records, and names no domain |
//! | The bundle AAD's "protocol domain" | `kr-pair/spake2-ed25519/1`, the same literal as `C` | Section 10 says the additional data carries "the protocol domain"; reusing the one already defined avoids inventing a second |
//! | The element order inside the AAD, the finish tag and `D` | The order section 10 lists them in, host before client wherever it writes "both" | Section 10 lists the members but not an encoding |
//! | Key bundles inside `D` | A positional array in [`KeyPurpose::ALL`] order | `D` is an array, so its members are positional; a map inside it would encode the field names for no gain |
//! | The QR code member | [`ShortCode`], the canonical `XXXX-XXX-XXX` form | Section 10 gives the display form; a payload that carried another spelling of the same code would produce another transcript |

use core::fmt;
use core::str::FromStr;

use kr_cbor::{CanonicalValue, CborError, sha256, signing_value};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize};

use crate::grant::{
    EnvironmentSelector, Grant, GrantExpiry, HistoryScope, OrganisationRequirement, SessionSelector,
};
use crate::ids::{
    ArchiveId, AttemptId, AuthorityRevision, BackupGeneration, ConfirmationId, DeviceId,
    DeviceKeyRevision, GrantId, InvitationId, PairingSequence, RevocationRequestId,
};
use crate::rights::ActionRight;
use crate::scalars::{
    AuthorisationKey, Bytes, CanonicalSet, Digest256, EndpointKey, KeyId, Mac256, Nonce256,
    NotificationPreviewKey, Nullable, SecretBytes32, Signature64, StoredEnvelopeKey, TimestampMs,
};

/// The Bitcoin Base58 alphabet the ten-character code is drawn from.
pub const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Characters in the locator half of a short code.
pub const LOCATOR_LEN: usize = 4;

/// Characters in the secret half of a short code.
pub const CODE_SECRET_LEN: usize = 6;

/// Characters in a complete short code.
pub const CODE_LEN: usize = LOCATOR_LEN + CODE_SECRET_LEN;

/// The domain that separates the short-code pairing transcript.
///
/// It names the exact PAKE profile in use: the RustCrypto `spake2` crate's `Spake2<Ed25519Group>`,
/// which is not the RFC 9382 P-256 ciphersuite.
pub const PAIRING_DOMAIN: &str = "kr-pair/spake2-ed25519/1";

/// The domain of the host's PAKE identity, `CBOR(["kr-pair/host", CH])`.
pub const HOST_IDENTITY_DOMAIN: &str = "kr-pair/host";

/// The domain of the client's PAKE identity, `CBOR(["kr-pair/client", CH])`.
pub const CLIENT_IDENTITY_DOMAIN: &str = "kr-pair/client";

/// The HKDF-SHA256 information string of the client confirmation key.
pub const INFO_CLIENT_CONFIRM: &str = "kr-pair/1/client-confirm";

/// The HKDF-SHA256 information string of the host confirmation key.
pub const INFO_HOST_CONFIRM: &str = "kr-pair/1/host-confirm";

/// The HKDF-SHA256 information string of the client-to-host bundle key.
pub const INFO_CLIENT_TO_HOST: &str = "kr-pair/1/client-to-host";

/// The HKDF-SHA256 information string of the host-to-client bundle key.
pub const INFO_HOST_TO_CLIENT: &str = "kr-pair/1/host-to-client";

/// The HKDF-SHA256 information string of the iroh binding key.
pub const INFO_IROH_BIND: &str = "kr-pair/1/iroh-bind";

/// Every HKDF information string, in the order section 10 lists them.
pub const HKDF_INFO_STRINGS: [&str; 5] = [
    INFO_CLIENT_CONFIRM,
    INFO_HOST_CONFIRM,
    INFO_CLIENT_TO_HOST,
    INFO_HOST_TO_CLIENT,
    INFO_IROH_BIND,
];

/// The domain of the short-code verification value.
pub const VERIFY_DOMAIN: &str = "kr-pair/verify/1";

/// The domain of the direct-mode transcript `D`.
pub const DIRECT_DOMAIN: &str = "kr-pair/direct/1";

/// The domain of the direct-mode verification value.
pub const DIRECT_VERIFY_DOMAIN: &str = "kr-pair/direct-verify/1";

/// The domain the host bundle signature covers.
pub const HOST_BUNDLE_DOMAIN: &str = "kr-pair/host-bundle/1";

/// The domain the client bundle signature covers.
pub const CLIENT_BUNDLE_DOMAIN: &str = "kr-pair/client-bundle/1";

/// The domain the `pair.finish` binding tag covers.
pub const FINISH_DOMAIN: &str = "kr-pair/finish/1";

/// The domain an owner-confirmation proof covers.
pub const OWNER_CONFIRM_DOMAIN: &str = "kr-pair/owner-confirm/1";

/// The domain a key identifier is derived under.
pub const KEY_ID_DOMAIN: &str = "kr-key-id/1";

/// Characters in a verification value.
pub const VERIFICATION_VALUE_LEN: usize = 8;

/// The lifetime of a pairing invitation, in milliseconds.
pub const INVITATION_LIFETIME_MS: u64 = 5 * 60 * 1000;

/// Failed client-confirmation tags the host permits per invitation.
pub const MAX_CONFIRMATION_FAILURES: u32 = 5;

/// Attempts a client permits per entered code.
pub const MAX_CLIENT_ATTEMPTS: u32 = 5;

/// How long a client keeps an exhausted or expired entry tombstone, in milliseconds.
pub const CLIENT_TOMBSTONE_MS: u64 = 24 * 60 * 60 * 1000;

/// Maximum size of one encrypted pairing frame, in bytes.
pub const MAX_PAIRING_FRAME_LEN: usize = 64 * 1024;

/// Maximum size of a complete pairing bundle exchange, in bytes.
pub const MAX_PAIRING_EXCHANGE_LEN: usize = 256 * 1024;

/// Maximum display length of a device name, in bytes.
pub const MAX_DEVICE_NAME_LEN: usize = 128;

/// Maximum number of relay URLs, discovery origins or direct-address hints in a network
/// configuration.
pub const MAX_NETWORK_HINTS: usize = 32;

/// Returns true when `character` is in the Bitcoin Base58 alphabet.
#[must_use]
pub fn is_base58(character: char) -> bool {
    BASE58_ALPHABET.contains(character)
}

/// A text value that failed a pairing schema rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingTextError(&'static str);

impl fmt::Display for PairingTextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for PairingTextError {}

/// Declares a validated text newtype with one canonical form.
macro_rules! validated_text {
    ($(#[$meta:meta])* $name:ident, $validate:ident, $description:literal, $pattern:expr) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wraps text after validating it.
            ///
            /// # Errors
            ///
            /// Returns [`PairingTextError`] naming the rule the text broke.
            pub fn new(value: impl Into<String>) -> Result<Self, PairingTextError> {
                let value = value.into();
                $validate(&value)?;
                Ok(Self(value))
            }

            /// Returns the text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = PairingTextError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::new(text)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Self::new(text).map_err(serde::de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> std::borrow::Cow<'static, str> {
                concat!("kalareach::", stringify!($name)).into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "pattern": $pattern,
                    "description": $description
                })
            }
        }
    };
}

/// Emits the ordinary `Debug` of a validated text newtype.
///
/// It is separate from [`validated_text`] because one of those types, [`ShortCode`], carries the
/// six secret characters and redacts itself instead.
macro_rules! text_debug {
    ($name:ident) => {
        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, concat!(stringify!($name), "({:?})"), self.0)
            }
        }
    };
}

fn validate_locator(value: &str) -> Result<(), PairingTextError> {
    if value.chars().count() != LOCATOR_LEN {
        return Err(PairingTextError("a locator is exactly four characters"));
    }
    if !value.chars().all(is_base58) {
        return Err(PairingTextError(
            "a locator uses only the Bitcoin Base58 alphabet",
        ));
    }
    Ok(())
}

validated_text!(
    /// The four-character Base58 locator of a rendezvous record.
    ///
    /// The locator is not secret. It names a temporary record; the six secret characters never
    /// leave the two devices.
    Locator,
    validate_locator,
    "The four-character Base58 locator of a rendezvous record. It carries no secret entropy.",
    "^[1-9A-HJ-NP-Za-km-z]{4}$"
);
text_debug!(Locator);

fn validate_rendezvous_origin(value: &str) -> Result<(), PairingTextError> {
    let Some(authority) = value.strip_prefix("https://") else {
        return Err(PairingTextError("a rendezvous origin starts with https://"));
    };
    if authority.is_empty() || authority.len() > 255 {
        return Err(PairingTextError("a rendezvous origin has a host"));
    }
    if authority.bytes().any(|byte| !(b'!'..=b'~').contains(&byte)) {
        return Err(PairingTextError(
            "a rendezvous origin is printable ASCII without spaces",
        ));
    }
    if authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
    {
        return Err(PairingTextError(
            "a rendezvous origin carries no path, query, fragment or user information",
        ));
    }

    let (host, port, bracketed) = split_authority(authority)?;
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(PairingTextError("a rendezvous origin port is decimal"));
        }
        if port.len() > 1 && port.starts_with('0') {
            return Err(PairingTextError(
                "a rendezvous origin port has no leading zero",
            ));
        }
        match port.parse::<u16>() {
            Ok(443) => {
                return Err(PairingTextError(
                    "a canonical https origin omits the default port 443",
                ));
            }
            Ok(0) => return Err(PairingTextError("a rendezvous origin port is not zero")),
            Ok(_) => {}
            Err(_) => {
                return Err(PairingTextError(
                    "a rendezvous origin port is a 16-bit port",
                ));
            }
        }
    }
    validate_origin_host(host, bracketed)
}

/// Splits `host[:port]`, keeping an IPv6 literal inside its brackets.
///
/// The third element says whether the host arrived bracketed, so an unbracketed IPv6 literal is
/// rejected rather than read as a host and a port.
fn split_authority(authority: &str) -> Result<(&str, Option<&str>, bool), PairingTextError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(PairingTextError("an IPv6 origin closes its bracket"));
        };
        let host = &rest[..end];
        return match &rest[end + 1..] {
            "" => Ok((host, None, true)),
            tail => match tail.strip_prefix(':') {
                Some(port) => Ok((host, Some(port), true)),
                None => Err(PairingTextError(
                    "an IPv6 origin has nothing but a port after its bracket",
                )),
            },
        };
    }
    if authority.contains('[') || authority.contains(']') {
        return Err(PairingTextError(
            "only an IPv6 literal uses brackets, and it starts with one",
        ));
    }
    Ok(match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port), false),
        None => (authority, None, false),
    })
}

/// Validates the host half of an origin: a bracketed IPv6 literal, or lower-case DNS labels.
fn validate_origin_host(host: &str, bracketed: bool) -> Result<(), PairingTextError> {
    if host.is_empty() {
        return Err(PairingTextError("a rendezvous origin has a host"));
    }
    if bracketed {
        // One address has many spellings. The canonical one is what the standard library writes,
        // so an origin that spells it differently is rejected rather than producing a second
        // transcript for the same service.
        let parsed: std::net::Ipv6Addr = host
            .parse()
            .map_err(|_| PairingTextError("a bracketed origin host is an IPv6 literal"))?;
        if parsed.to_string() != host {
            return Err(PairingTextError(
                "an IPv6 origin uses the canonical spelling of its address",
            ));
        }
        if parsed.to_ipv4_mapped().is_some()
            || (parsed.to_ipv4().is_some() && !parsed.is_loopback() && !parsed.is_unspecified())
        {
            // An IPv4-mapped or IPv4-compatible address is one host with two spellings, and URL
            // parsers do not agree on which to write. An IPv4 service is named by its IPv4
            // literal. The loopback and unspecified addresses are not IPv4 addresses in disguise.
            return Err(PairingTextError(
                "an IPv4 address is written as an IPv4 origin, not as a mapped IPv6 literal",
            ));
        }
        return Ok(());
    }
    if host.contains(':') {
        return Err(PairingTextError("an IPv6 origin host is bracketed"));
    }
    if host.ends_with('.') {
        return Err(PairingTextError(
            "a rendezvous origin host has no trailing dot",
        ));
    }
    // An IPv4 literal is a host as well, and it too has one canonical spelling.
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        let parsed: std::net::Ipv4Addr = host
            .parse()
            .map_err(|_| PairingTextError("a numeric origin host is an IPv4 literal"))?;
        if parsed.to_string() != host {
            return Err(PairingTextError(
                "an IPv4 origin uses the canonical spelling of its address",
            ));
        }
        return Ok(());
    }
    // A host whose last label is a number is an address, not a name: a URL parser reads
    // `0xc0000201` as 192.0.2.1. An origin that two parsers read differently is two origins, so
    // the last label must be a name.
    let last = host.rsplit('.').next().unwrap_or(host);
    if last.starts_with(|character: char| character.is_ascii_digit())
        || !last.bytes().any(|byte| byte.is_ascii_lowercase())
    {
        return Err(PairingTextError(
            "a rendezvous origin host ends in a name, not a number",
        ));
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(PairingTextError(
                "a rendezvous origin host label is 1 to 63 characters",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(PairingTextError(
                "a rendezvous origin host label does not start or end with a hyphen",
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(PairingTextError(
                "a rendezvous origin host is lower-case ASCII; encode an international name as A-label punycode",
            ));
        }
    }
    Ok(())
}

validated_text!(
    /// The locally configured canonical HTTPS origin of a rendezvous service.
    ///
    /// Both devices build `C` from their own configured origin and reject an inconsistent value,
    /// so the canonical form has to be exact: scheme, lower-case host, optional port, nothing else.
    /// A typed code never selects a service URL.
    RendezvousOrigin,
    validate_rendezvous_origin,
    "A canonical HTTPS origin: https:// followed by a lower-case host or a bracketed IPv6 literal and an optional non-default port, with no path, query, fragment or user information.",
    "^https://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*|\\[[0-9a-f:]+\\])(:[1-9][0-9]{0,4})?$"
);
text_debug!(RendezvousOrigin);

fn validate_short_code(value: &str) -> Result<(), PairingTextError> {
    // The canonical display form is `XXXX-XXX-XXX`. A parser accepts a code with spaces or other
    // hyphenation, but what travels in a QR payload or a transcript is this one form.
    let bytes = value.as_bytes();
    if bytes.len() != CODE_LEN + 2 {
        return Err(PairingTextError(
            "a short code is ten characters written XXXX-XXX-XXX",
        ));
    }
    if bytes[LOCATOR_LEN] != b'-' || bytes[LOCATOR_LEN + 4] != b'-' {
        return Err(PairingTextError("a short code is grouped XXXX-XXX-XXX"));
    }
    let digits = value.chars().filter(|character| *character != '-');
    if digits.clone().count() != CODE_LEN || !digits.clone().all(is_base58) {
        return Err(PairingTextError(
            "a short code is ten characters from the Bitcoin Base58 alphabet",
        ));
    }
    Ok(())
}

validated_text!(
    /// A ten-character short code in its canonical `XXXX-XXX-XXX` display form.
    ///
    /// The six secret characters are in here, so this type redacts itself in debug output and
    /// never reaches a log or an analytics event.
    ShortCode,
    validate_short_code,
    "A ten-character Base58 pairing code in its canonical XXXX-XXX-XXX form.",
    "^[1-9A-HJ-NP-Za-km-z]{4}-[1-9A-HJ-NP-Za-km-z]{3}-[1-9A-HJ-NP-Za-km-z]{3}$"
);

impl ShortCode {
    /// Returns the locator half, which is not secret.
    #[must_use]
    pub fn locator(&self) -> Locator {
        Locator::new(&self.as_str()[..LOCATOR_LEN]).expect("a validated code starts with a locator")
    }
}

impl fmt::Debug for ShortCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Section 10: the six secret characters never enter a log or an analytics event.
        write!(formatter, "ShortCode({}-...-...)", self.locator())
    }
}

impl Drop for ShortCode {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;

        self.0.zeroize();
    }
}

impl ShortCode {
    /// Returns the canonical text, cleared when the caller drops it.
    ///
    /// A caller that needs the code as text, to render a QR payload or to display it, gets a
    /// buffer that clears itself. [`Self::as_str`] borrows instead and copies nothing.
    #[must_use]
    pub fn to_secret_text(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(self.0.clone())
    }
}

fn validate_device_name(value: &str) -> Result<(), PairingTextError> {
    if value.is_empty() {
        return Err(PairingTextError("a device name is not empty"));
    }
    if value.len() > MAX_DEVICE_NAME_LEN {
        return Err(PairingTextError("a device name is at most 128 bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err(PairingTextError(
            "a device name carries no control characters",
        ));
    }
    Ok(())
}

validated_text!(
    /// A device's display name. Display text, never authority.
    DeviceName,
    validate_device_name,
    "A device display name of at most 128 bytes and no control characters. Display text, never authority.",
    "^[^\\u0000-\\u001f\\u007f]{1,128}$"
);
text_debug!(DeviceName);

fn validate_network_hint(value: &str) -> Result<(), PairingTextError> {
    if value.is_empty() || value.len() > 253 {
        return Err(PairingTextError("a network hint is 1 to 253 bytes"));
    }
    if value.chars().any(|character| {
        character.is_control() || character.is_whitespace() || !character.is_ascii()
    }) {
        return Err(PairingTextError(
            "a network hint is printable ASCII without spaces",
        ));
    }
    Ok(())
}

validated_text!(
    /// One relay URL, discovery origin or direct-address hint.
    ///
    /// The transport crate parses these into iroh's own types. They are configuration the
    /// authenticated bundle carries, never authority.
    NetworkHint,
    validate_network_hint,
    "One relay URL, discovery origin or direct-address hint: printable ASCII without spaces, 1 to 253 bytes.",
    "^[!-~]{1,253}$"
);
text_debug!(NetworkHint);

/// The purpose a device key is declared for.
///
/// Section 10 keeps the four purposes independent and forbids converting or reusing one private
/// key across them. The purpose is part of the key identifier and of the signed bundle, so a
/// receiver cannot silently accept a key under a purpose its owner never declared.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyPurpose {
    /// The iroh transport identity.
    Transport,
    /// Ed25519 authorisation signatures.
    Authorisation,
    /// X25519 stored-envelope encryption.
    StoredEnvelope,
    /// X25519 notification-preview encryption.
    NotificationPreview,
}

impl KeyPurpose {
    /// Every purpose, in declaration order.
    pub const ALL: [Self; 4] = [
        Self::Transport,
        Self::Authorisation,
        Self::StoredEnvelope,
        Self::NotificationPreview,
    ];

    /// Returns the schema name of the purpose.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Authorisation => "authorisation",
            Self::StoredEnvelope => "stored_envelope",
            Self::NotificationPreview => "notification_preview",
        }
    }
}

/// One device's four purpose-separated public keys.
///
/// An authenticated pairing exchange binds these public keys and their explicit purposes to one
/// device record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DevicePublicKeys {
    /// The iroh transport identity.
    pub transport: EndpointKey,
    /// The Ed25519 authorisation key.
    pub authorisation: AuthorisationKey,
    /// The X25519 stored-envelope key.
    pub stored_envelope: StoredEnvelopeKey,
    /// The X25519 notification-preview key.
    pub notification_preview: NotificationPreviewKey,
}

impl DevicePublicKeys {
    /// Returns the raw bytes declared for `purpose`.
    #[must_use]
    pub const fn raw(&self, purpose: KeyPurpose) -> &[u8; 32] {
        match purpose {
            KeyPurpose::Transport => self.transport.as_bytes(),
            KeyPurpose::Authorisation => self.authorisation.as_bytes(),
            KeyPurpose::StoredEnvelope => self.stored_envelope.as_bytes(),
            KeyPurpose::NotificationPreview => self.notification_preview.as_bytes(),
        }
    }

    /// Returns true when no two purposes declare the same public key.
    ///
    /// Section 10 forbids converting or reusing one private key across purposes. Two equal public
    /// keys prove a reused private key, which this check rejects before the keys reach a device
    /// record.
    #[must_use]
    pub fn purposes_are_distinct(&self) -> bool {
        let keys = [
            self.transport.as_bytes(),
            self.authorisation.as_bytes(),
            self.stored_envelope.as_bytes(),
            self.notification_preview.as_bytes(),
        ];
        for (index, left) in keys.iter().enumerate() {
            if keys[index + 1..].iter().any(|right| right == left) {
                return false;
            }
        }
        true
    }
}

/// The selected discovery and relay configuration a pairing invitation carries.
///
/// Discovery and relay selection are separate configuration choices, and a self-hosted deployment
/// replaces each service independently, so each list stands on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// The selected relay configuration, as relay URLs.
    pub relay_urls: Vec<NetworkHint>,
    /// The selected discovery configuration, as Pkarr or DNS origins.
    pub discovery_origins: Vec<NetworkHint>,
    /// Current direct-address hints. Hints only: the endpoint identity is what authenticates.
    pub direct_addresses: Vec<NetworkHint>,
}

impl NetworkConfig {
    /// Returns true when every list is inside [`MAX_NETWORK_HINTS`].
    #[must_use]
    pub fn is_bounded(&self) -> bool {
        self.relay_urls.len() <= MAX_NETWORK_HINTS
            && self.discovery_origins.len() <= MAX_NETWORK_HINTS
            && self.direct_addresses.len() <= MAX_NETWORK_HINTS
    }
}

/// The rights an invitation proposes, before the host issues a grant.
///
/// The client cannot enlarge the grant through its bundle: the host commits the grant it proposed,
/// and the proposal is covered by the transcript both devices confirmed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposedGrant {
    /// The grant this one will be delegated from, when it is a delegation.
    pub parent_grant_id: Nullable<GrantId>,
    /// Which environments it covers.
    pub environment_selector: EnvironmentSelector,
    /// Which sessions it covers.
    pub session_selector: SessionSelector,
    /// The actions it permits.
    pub actions: CanonicalSet<ActionRight>,
    /// How far back it may see.
    pub history: HistoryScope,
    /// When it stops being valid.
    pub expiry: GrantExpiry,
    /// An optional organisation membership requirement.
    pub organisation: Nullable<OrganisationRequirement>,
}

impl ProposedGrant {
    /// Builds the grant the host commits, filling in the identities only the host can assign.
    #[must_use]
    pub fn into_grant(
        self,
        grant_id: GrantId,
        issuer_device_id: DeviceId,
        recipient_device_id: DeviceId,
        authority_revision: AuthorityRevision,
    ) -> Grant {
        Grant {
            grant_id,
            parent_grant_id: self.parent_grant_id,
            issuer_device_id,
            recipient_device_id,
            authority_revision,
            environment_selector: self.environment_selector,
            session_selector: self.session_selector,
            actions: self.actions,
            history: self.history,
            expiry: self.expiry,
            organisation: self.organisation,
        }
    }
}

/// The deterministic-CBOR context `C` of one short-code pairing attempt.
///
/// Both devices construct `C` themselves from their own configured origin and their own random
/// values, and reject an inconsistent one. Its encoding is an array, not a map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingContext {
    /// The locally configured canonical HTTPS origin of the rendezvous service.
    pub rendezvous_origin: RendezvousOrigin,
    /// The four-character locator of the rendezvous record.
    pub locator: Locator,
    /// The invitation this attempt belongs to.
    pub invitation_id: InvitationId,
    /// This candidate's attempt.
    pub attempt_id: AttemptId,
    /// The host's fresh 256-bit nonce.
    pub host_nonce: Nonce256,
    /// The candidate's fresh 256-bit nonce.
    pub client_nonce: Nonce256,
}

impl PairingContext {
    /// Builds `C` as a canonical value.
    #[must_use]
    pub fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Array(vec![
            CanonicalValue::text(PAIRING_DOMAIN),
            CanonicalValue::text(self.rendezvous_origin.as_str()),
            CanonicalValue::text(self.locator.as_str()),
            CanonicalValue::bytes(self.invitation_id.get().as_bytes().as_slice()),
            CanonicalValue::bytes(self.attempt_id.get().as_bytes().as_slice()),
            CanonicalValue::bytes(self.host_nonce.as_bytes().as_slice()),
            CanonicalValue::bytes(self.client_nonce.as_bytes().as_slice()),
        ])
    }

    /// Returns the canonical encoding of `C`.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        kr_cbor::encode(&self.to_canonical_value())
    }

    /// Returns `CH = SHA256(C)`.
    #[must_use]
    pub fn context_hash(&self) -> Digest256 {
        Digest256::from_bytes(sha256(&self.to_canonical_bytes()))
    }

    /// Returns the host's PAKE identity, `CBOR(["kr-pair/host", CH])`.
    #[must_use]
    pub fn host_identity(&self) -> Vec<u8> {
        role_identity(HOST_IDENTITY_DOMAIN, self.context_hash())
    }

    /// Returns the client's PAKE identity, `CBOR(["kr-pair/client", CH])`.
    #[must_use]
    pub fn client_identity(&self) -> Vec<u8> {
        role_identity(CLIENT_IDENTITY_DOMAIN, self.context_hash())
    }

    /// Returns `T = SHA256(CBOR([C, message_A, message_B]))`.
    ///
    /// `message_A` is the host's library-produced message and `message_B` the client's, in that
    /// order, whichever side computes the transcript.
    #[must_use]
    pub fn transcript(&self, message_a: &[u8], message_b: &[u8]) -> Digest256 {
        let value = CanonicalValue::Array(vec![
            self.to_canonical_value(),
            CanonicalValue::bytes(message_a),
            CanonicalValue::bytes(message_b),
        ]);
        Digest256::from_bytes(sha256(&kr_cbor::encode(&value)))
    }
}

/// Builds one role identity, `CBOR([domain, CH])`.
#[must_use]
pub fn role_identity(domain: &str, context_hash: Digest256) -> Vec<u8> {
    kr_cbor::encode(&signing_value(
        domain,
        vec![CanonicalValue::bytes(context_hash.as_bytes().as_slice())],
    ))
}

/// Which direction a pairing bundle message travels.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BundleDirection {
    /// From the candidate to the host, under the `client-to-host` key.
    ClientToHost,
    /// From the host to the candidate, under the `host-to-client` key.
    HostToClient,
}

impl BundleDirection {
    /// Returns the schema name of the direction.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientToHost => "client_to_host",
            Self::HostToClient => "host_to_client",
        }
    }

    /// Returns the HKDF information string of the key that protects this direction.
    #[must_use]
    pub const fn info(self) -> &'static str {
        match self {
            Self::ClientToHost => INFO_CLIENT_TO_HOST,
            Self::HostToClient => INFO_HOST_TO_CLIENT,
        }
    }
}

/// What one encrypted pairing message carries.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BundleMessageType {
    /// The signed host bundle.
    HostBundle,
    /// The signed client bundle.
    ClientBundle,
}

impl BundleMessageType {
    /// Returns the schema name of the message type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostBundle => "host_bundle",
            Self::ClientBundle => "client_bundle",
        }
    }

    /// Returns the direction this message type always travels in.
    #[must_use]
    pub const fn direction(self) -> BundleDirection {
        match self {
            Self::HostBundle => BundleDirection::HostToClient,
            Self::ClientBundle => BundleDirection::ClientToHost,
        }
    }
}

/// Builds the additional authenticated data of one encrypted pairing message.
///
/// The encoding is `CBOR([domain, T, direction, sequence, message_type])`. Binding the direction
/// and the sequence stops a message being replayed back at its sender or reordered inside the
/// exchange, and binding `T` stops it being replayed into another attempt.
#[must_use]
pub fn bundle_aad(
    transcript: Digest256,
    direction: BundleDirection,
    sequence: PairingSequence,
    message_type: BundleMessageType,
) -> Vec<u8> {
    let value = CanonicalValue::Array(vec![
        CanonicalValue::text(PAIRING_DOMAIN),
        CanonicalValue::bytes(transcript.as_bytes().as_slice()),
        CanonicalValue::text(direction.as_str()),
        CanonicalValue::Integer(sequence.get().into()),
        CanonicalValue::text(message_type.as_str()),
    ]);
    kr_cbor::encode(&value)
}

/// The host's key bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostBundle {
    /// The invitation this bundle answers.
    pub invitation_id: InvitationId,
    /// The host's device identity.
    pub device_id: DeviceId,
    /// The revision of the host's purpose-separated keys.
    pub device_key_revision: DeviceKeyRevision,
    /// The host's iroh endpoint identity.
    pub endpoint_id: EndpointKey,
    /// The host's purpose-separated public keys.
    pub keys: DevicePublicKeys,
    /// The selected discovery and relay configuration, with current hints.
    pub network_config: NetworkConfig,
    /// The rights the invitation proposes.
    pub proposed_grant: ProposedGrant,
}

/// The candidate's key bundle.
///
/// It carries no device identity: the host assigns one when it commits the device record, so a
/// candidate cannot choose or reuse an identity the host already knows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientBundle {
    /// The candidate's iroh endpoint identity.
    pub endpoint_id: EndpointKey,
    /// The candidate's purpose-separated public keys.
    pub keys: DevicePublicKeys,
    /// The revision of those keys.
    pub device_key_revision: DeviceKeyRevision,
    /// The candidate's display name. Display text, never authority.
    pub device_name: DeviceName,
    /// The candidate's platform.
    pub platform: DevicePlatform,
}

/// The platform a device runs on.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DevicePlatform {
    /// macOS.
    Macos,
    /// Windows.
    Windows,
    /// Linux, including a WSL2 distribution.
    Linux,
    /// iOS or iPadOS.
    Ios,
    /// Android.
    Android,
}

/// A bundle and the authorisation signature that binds its key purposes.
///
/// The encryption authenticates the initial bundle; this signature binds the key-purpose
/// declarations to the authorisation key, and covers `T`, so it cannot be replayed from another
/// transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedHostBundle {
    /// The bundle.
    pub bundle: HostBundle,
    /// The transcript the signature covers.
    pub transcript: Digest256,
    /// The Ed25519 signature over `CBOR(["kr-pair/host-bundle/1", bundle, T])`.
    pub signature: Signature64,
}

/// A candidate bundle and the authorisation signature that binds its key purposes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedClientBundle {
    /// The bundle.
    pub bundle: ClientBundle,
    /// The transcript the signature covers.
    pub transcript: Digest256,
    /// The Ed25519 signature over `CBOR(["kr-pair/client-bundle/1", bundle, T])`.
    pub signature: Signature64,
}

/// The `pair.finish` request, which binds the pairing transcript to the live iroh identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairFinishRequest {
    /// The invitation.
    pub invitation_id: InvitationId,
    /// The attempt.
    pub attempt_id: AttemptId,
    /// The transcript both devices confirmed.
    pub transcript: Digest256,
    /// The SHA-256 of the canonical host bundle.
    pub host_bundle_hash: Digest256,
    /// The SHA-256 of the canonical client bundle.
    pub client_bundle_hash: Digest256,
    /// The tag under the `iroh-bind` key.
    pub binding_tag: Mac256,
}

/// Builds the message the `pair.finish` binding tag is computed over.
///
/// The input includes both endpoint identities and both bundle hashes, so the tag proves the same
/// two devices that ran the PAKE are the two endpoints now talking over iroh.
#[must_use]
pub fn finish_mac_input(
    invitation_id: InvitationId,
    attempt_id: AttemptId,
    transcript: Digest256,
    host_endpoint_id: &EndpointKey,
    client_endpoint_id: &EndpointKey,
    host_bundle_hash: Digest256,
    client_bundle_hash: Digest256,
) -> Vec<u8> {
    kr_cbor::encode(&signing_value(
        FINISH_DOMAIN,
        vec![
            CanonicalValue::bytes(invitation_id.get().as_bytes().as_slice()),
            CanonicalValue::bytes(attempt_id.get().as_bytes().as_slice()),
            CanonicalValue::bytes(transcript.as_bytes().as_slice()),
            CanonicalValue::bytes(host_endpoint_id.as_bytes().as_slice()),
            CanonicalValue::bytes(client_endpoint_id.as_bytes().as_slice()),
            CanonicalValue::bytes(host_bundle_hash.as_bytes().as_slice()),
            CanonicalValue::bytes(client_bundle_hash.as_bytes().as_slice()),
        ],
    ))
}

/// Returns the eight-hexadecimal-character verification value of a short-code pairing.
///
/// It is the first eight hexadecimal characters of
/// `SHA256(CBOR(["kr-pair/verify/1", T, host_bundle_hash, client_bundle_hash]))`. It helps the
/// owner identify the request; the PAKE authentication and the endpoint binding do not depend on
/// those eight characters alone.
#[must_use]
pub fn verification_value(
    transcript: Digest256,
    host_bundle_hash: Digest256,
    client_bundle_hash: Digest256,
) -> String {
    let input = signing_value(
        VERIFY_DOMAIN,
        vec![
            CanonicalValue::bytes(transcript.as_bytes().as_slice()),
            CanonicalValue::bytes(host_bundle_hash.as_bytes().as_slice()),
            CanonicalValue::bytes(client_bundle_hash.as_bytes().as_slice()),
        ],
    );
    hex_prefix(&sha256(&kr_cbor::encode(&input)))
}

/// Returns the eight-hexadecimal-character verification value of a direct pairing.
#[must_use]
pub fn direct_verification_value(transcript: &DirectTranscript) -> String {
    let input = signing_value(DIRECT_VERIFY_DOMAIN, vec![transcript.to_canonical_value()]);
    hex_prefix(&sha256(&kr_cbor::encode(&input)))
}

fn hex_prefix(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(VERIFICATION_VALUE_LEN);
    for byte in &digest[..VERIFICATION_VALUE_LEN / 2] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The direct-mode transcript `D`.
///
/// Its encoding is an array: `[domain, invitation_id, host_endpoint_id, client_endpoint_id,
/// host_keys, client_keys, proposed_grant_digest, host_nonce, client_nonce, expires_at_ms]`.
/// The expiry is the invitation's original one, so a service that advertises a later deadline
/// cannot extend the window the two devices authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectTranscript {
    /// The invitation being redeemed.
    pub invitation_id: InvitationId,
    /// The host's iroh endpoint identity, pinned by the QR.
    pub host_endpoint_id: EndpointKey,
    /// The candidate's iroh endpoint identity.
    pub client_endpoint_id: EndpointKey,
    /// The host's complete purpose-key bundle.
    pub host_keys: DevicePublicKeys,
    /// The candidate's complete purpose-key bundle.
    pub client_keys: DevicePublicKeys,
    /// The SHA-256 of the canonical proposed grant.
    pub proposed_grant_digest: Digest256,
    /// The host's fresh challenge nonce.
    pub host_nonce: Nonce256,
    /// The candidate's fresh nonce.
    pub client_nonce: Nonce256,
    /// The invitation's original expiry, in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
}

impl DirectTranscript {
    /// Builds `D` as a canonical value.
    ///
    /// # Panics
    ///
    /// Panics only if a 64-bit timestamp falls outside CBOR's 64-bit argument range, which it
    /// cannot.
    #[must_use]
    pub fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Array(vec![
            CanonicalValue::text(DIRECT_DOMAIN),
            CanonicalValue::bytes(self.invitation_id.get().as_bytes().as_slice()),
            CanonicalValue::bytes(self.host_endpoint_id.as_bytes().as_slice()),
            CanonicalValue::bytes(self.client_endpoint_id.as_bytes().as_slice()),
            keys_value(&self.host_keys),
            keys_value(&self.client_keys),
            CanonicalValue::bytes(self.proposed_grant_digest.as_bytes().as_slice()),
            CanonicalValue::bytes(self.host_nonce.as_bytes().as_slice()),
            CanonicalValue::bytes(self.client_nonce.as_bytes().as_slice()),
            CanonicalValue::Integer(self.expires_at_ms.get().into()),
        ])
    }

    /// Returns the canonical encoding of `D`.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        kr_cbor::encode(&self.to_canonical_value())
    }
}

/// Encodes a key bundle as the array `D` embeds, in [`KeyPurpose::ALL`] order.
fn keys_value(keys: &DevicePublicKeys) -> CanonicalValue {
    CanonicalValue::Array(
        KeyPurpose::ALL
            .iter()
            .map(|purpose| CanonicalValue::bytes(keys.raw(*purpose).as_slice()))
            .collect(),
    )
}

/// The proof a candidate submits in direct mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectRedeemProof {
    /// The invitation being redeemed.
    pub invitation_id: InvitationId,
    /// The candidate's complete purpose-key bundle.
    pub client_keys: DevicePublicKeys,
    /// The revision of those keys.
    pub device_key_revision: DeviceKeyRevision,
    /// The candidate's display name.
    pub device_name: DeviceName,
    /// The candidate's platform.
    pub platform: DevicePlatform,
    /// The host challenge this redemption answers.
    pub host_nonce: Nonce256,
    /// The candidate's fresh nonce.
    pub client_nonce: Nonce256,
    /// `HMAC-SHA256(invitation_secret, D)`.
    pub secret_proof: Mac256,
    /// The candidate's Ed25519 signature over `D`.
    pub signature: Signature64,
}

/// The host challenge a direct redemption starts from. Single use, and it expires with the
/// invitation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectChallenge {
    /// The invitation.
    pub invitation_id: InvitationId,
    /// The fresh host nonce.
    pub host_nonce: Nonce256,
    /// The host's complete purpose-key bundle.
    pub host_keys: DevicePublicKeys,
    /// The revision of those keys.
    pub device_key_revision: DeviceKeyRevision,
    /// The host's iroh endpoint identity.
    pub endpoint_id: EndpointKey,
    /// The invitation's original expiry.
    pub expires_at_ms: TimestampMs,
}

/// A QR payload. The parser requires an explicit supported mode.
///
/// A code-mode QR is not an offline invitation: it names a rendezvous origin and a code, and the
/// short-code flow still runs. A direct-mode QR is self-contained and carries the full secret.
///
/// The encoding is written out by hand rather than derived. The payload is a mode-tagged map, and
/// the fields that follow the tag depend on it; a derived internally tagged enum would buffer the
/// value through serde's content representation, which does not preserve the binary
/// representation of a 16-byte identifier or a byte string. Writing the map directly also keeps
/// the QR bytes the exact contract section 10 asks for.
#[derive(Clone, PartialEq, Eq)]
pub enum QrPayload {
    /// The short-code payload: `{version, mode: "code", rendezvous_origin, code}`.
    Code(CodeQrPayload),
    /// The self-contained payload: `{version, mode: "direct", invitation_id, endpoint_id,
    /// network_config, secret, proposed_grant, expires_at}`.
    ///
    /// It is boxed because it carries a complete proposed grant and network configuration, which
    /// would otherwise make every code payload as large as a direct one.
    Direct(Box<DirectQrPayload>),
}

/// The members of a short-code QR payload.
///
/// `Debug` redacts the code: six of its ten characters are the PAKE secret, and section 10 keeps
/// them out of every service request, URL, log and analytics event.
#[derive(Clone, PartialEq, Eq)]
pub struct CodeQrPayload {
    /// The rendezvous origin to contact. Naming another origin requires explicit native
    /// confirmation before contact.
    pub rendezvous_origin: RendezvousOrigin,
    /// The ten-character code, in its canonical `XXXX-XXX-XXX` display form.
    pub code: ShortCode,
}

impl fmt::Debug for CodeQrPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodeQrPayload")
            .field("rendezvous_origin", &self.rendezvous_origin)
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Debug for QrPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code(payload) => formatter.debug_tuple("Code").field(payload).finish(),
            Self::Direct(payload) => formatter.debug_tuple("Direct").field(payload).finish(),
        }
    }
}

/// The members of a self-contained QR payload.
///
/// `Debug` redacts the invitation secret, which is the whole of the invitation's authority until
/// the owner approves.
#[derive(Clone, PartialEq, Eq)]
pub struct DirectQrPayload {
    /// The invitation.
    pub invitation_id: InvitationId,
    /// The host's pinned iroh endpoint identity.
    pub endpoint_id: EndpointKey,
    /// The selected discovery and relay configuration.
    pub network_config: NetworkConfig,
    /// The random 256-bit invitation secret. It is the whole of the invitation's authority until
    /// the owner approves, so it zeroises when it is dropped and never appears in debug output.
    pub secret: SecretBytes32,
    /// The rights the invitation proposes.
    pub proposed_grant: ProposedGrant,
    /// The invitation's expiry in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
}

impl fmt::Debug for DirectQrPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectQrPayload")
            .field("invitation_id", &self.invitation_id)
            .field("endpoint_id", &self.endpoint_id)
            .field("network_config", &self.network_config)
            .field("secret", &"redacted")
            .field("proposed_grant", &self.proposed_grant)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// The largest QR payload this build encodes or accepts, in bytes.
///
/// A QR code in byte mode holds at most 2,953 bytes at version 40 with the lowest error
/// correction, so anything larger was never a scannable code. The bound is applied to the text
/// form before it is decoded, so an oversized payload costs no allocation.
pub const MAX_QR_PAYLOAD_LEN: usize = 2953;

/// The QR payload version this build produces and accepts.
pub const QR_PAYLOAD_VERSION: u64 = 1;

/// The mode name of a short-code QR payload.
pub const QR_MODE_CODE: &str = "code";

/// The mode name of a self-contained QR payload.
pub const QR_MODE_DIRECT: &str = "direct";

/// A QR payload that could not be read.
#[derive(Debug, thiserror::Error)]
pub enum QrPayloadError {
    /// The bytes were not canonical KR-CBOR-1.
    #[error("the QR payload is not canonical KR-CBOR-1: {0}")]
    Encoding(#[from] CborError),
    /// The payload was not a map with the expected members.
    #[error("the QR payload is malformed: {0}")]
    Malformed(&'static str),
    /// The payload named a mode this build does not support.
    #[error("unsupported QR payload mode {mode:?}; a parser requires an explicit supported mode")]
    UnsupportedMode {
        /// The mode the payload named.
        mode: String,
    },
    /// The payload declared a version this build does not read.
    #[error("unsupported QR payload version {version}; this build reads version 1")]
    UnsupportedVersion {
        /// The version the payload declared.
        version: i128,
    },
    /// The payload was larger than a scannable QR code can hold.
    #[error("the QR payload is {len} bytes, over the {limit}-byte limit")]
    TooLarge {
        /// The size of the payload.
        len: usize,
        /// The limit.
        limit: usize,
    },
    /// A member failed its own schema rule.
    #[error("the QR payload carries an invalid {member}: {reason}")]
    InvalidMember {
        /// Which member failed.
        member: &'static str,
        /// Why it failed.
        reason: String,
    },
}

impl QrPayload {
    /// Returns the mode name this payload declares.
    #[must_use]
    pub const fn mode(&self) -> &'static str {
        match self {
            Self::Code { .. } => QR_MODE_CODE,
            Self::Direct { .. } => QR_MODE_DIRECT,
        }
    }

    /// Builds the payload as a canonical value.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when an embedded object is outside KR-CBOR-1.
    pub fn to_canonical_value(&self) -> Result<CanonicalValue, CborError> {
        let mut map = kr_cbor::CanonicalMap::new();
        map.insert(
            "version".to_owned(),
            CanonicalValue::Integer(QR_PAYLOAD_VERSION.into()),
        )?;
        map.insert("mode".to_owned(), CanonicalValue::text(self.mode()))?;
        match self {
            Self::Code(payload) => {
                map.insert(
                    "rendezvous_origin".to_owned(),
                    CanonicalValue::text(payload.rendezvous_origin.as_str()),
                )?;
                map.insert(
                    "code".to_owned(),
                    CanonicalValue::text(payload.code.as_str()),
                )?;
            }
            Self::Direct(payload) => {
                let DirectQrPayload {
                    invitation_id,
                    endpoint_id,
                    network_config,
                    secret,
                    proposed_grant,
                    expires_at_ms,
                } = payload.as_ref();
                map.insert(
                    "invitation_id".to_owned(),
                    CanonicalValue::bytes(invitation_id.get().as_bytes().as_slice()),
                )?;
                map.insert(
                    "endpoint_id".to_owned(),
                    CanonicalValue::bytes(endpoint_id.as_bytes().as_slice()),
                )?;
                map.insert(
                    "network_config".to_owned(),
                    kr_cbor::to_canonical_value(network_config)?,
                )?;
                map.insert(
                    "secret".to_owned(),
                    CanonicalValue::bytes(secret.expose().as_slice()),
                )?;
                map.insert(
                    "proposed_grant".to_owned(),
                    kr_cbor::to_canonical_value(proposed_grant)?,
                )?;
                map.insert(
                    "expires_at".to_owned(),
                    CanonicalValue::Integer(expires_at_ms.get().into()),
                )?;
            }
        }
        Ok(CanonicalValue::Map(map))
    }

    /// Encodes the payload as canonical KR-CBOR-1 bytes.
    ///
    /// A QR code carries these bytes directly in byte mode. An encoder restricted to text uses
    /// [`Self::to_text`].
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn to_canonical_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, CborError> {
        // A direct payload's bytes carry the invitation secret, so the caller is handed a buffer
        // that clears itself, and the value tree this built is cleared before it is dropped.
        let mut value = self.to_canonical_value()?;
        let bytes = kr_cbor::encode(&value);
        zeroise_value(&mut value);
        Ok(zeroize::Zeroizing::new(bytes))
    }

    /// Decodes and validates a payload from canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`QrPayloadError`] when the bytes are not canonical, when the payload names no
    /// supported mode, when it declares an unsupported version or when a member breaks its own
    /// schema rule.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, QrPayloadError> {
        if bytes.len() > MAX_QR_PAYLOAD_LEN {
            return Err(QrPayloadError::TooLarge {
                len: bytes.len(),
                limit: MAX_QR_PAYLOAD_LEN,
            });
        }
        let mut value = kr_cbor::decode(bytes, &kr_cbor::Limits::DEFAULT)?;
        let payload = Self::from_canonical_value(&value);
        zeroise_value(&mut value);
        payload
    }

    /// Reads a payload from a decoded canonical value.
    ///
    /// # Errors
    ///
    /// See [`Self::from_canonical_bytes`].
    pub fn from_canonical_value(value: &CanonicalValue) -> Result<Self, QrPayloadError> {
        let map = value
            .as_map()
            .ok_or(QrPayloadError::Malformed("a QR payload is a map"))?;
        let version = map
            .get("version")
            .and_then(CanonicalValue::as_integer)
            .ok_or(QrPayloadError::Malformed("a QR payload declares a version"))?;
        if version.get() != i128::from(QR_PAYLOAD_VERSION) {
            return Err(QrPayloadError::UnsupportedVersion {
                version: version.get(),
            });
        }
        let mode = map
            .get("mode")
            .and_then(CanonicalValue::as_text)
            .ok_or(QrPayloadError::Malformed("a QR payload declares a mode"))?;
        match mode {
            QR_MODE_CODE => {
                if map.len() != 4 {
                    return Err(QrPayloadError::Malformed(
                        "a code payload has exactly version, mode, rendezvous_origin and code",
                    ));
                }
                let origin = map
                    .get("rendezvous_origin")
                    .and_then(CanonicalValue::as_text)
                    .ok_or(QrPayloadError::Malformed("a code payload names an origin"))?;
                let code = map
                    .get("code")
                    .and_then(CanonicalValue::as_text)
                    .ok_or(QrPayloadError::Malformed("a code payload carries a code"))?;
                Ok(Self::Code(CodeQrPayload {
                    rendezvous_origin: RendezvousOrigin::new(origin).map_err(|error| {
                        QrPayloadError::InvalidMember {
                            member: "rendezvous_origin",
                            reason: error.to_string(),
                        }
                    })?,
                    code: ShortCode::new(code).map_err(|error| QrPayloadError::InvalidMember {
                        member: "code",
                        reason: error.to_string(),
                    })?,
                }))
            }
            QR_MODE_DIRECT => {
                if map.len() != 8 {
                    return Err(QrPayloadError::Malformed(
                        "a direct payload has exactly version, mode, invitation_id, endpoint_id, network_config, secret, proposed_grant and expires_at",
                    ));
                }
                let network_config: NetworkConfig = typed_member(map, "network_config")?;
                if !network_config.is_bounded() {
                    return Err(QrPayloadError::InvalidMember {
                        member: "network_config",
                        reason: format!("each list holds at most {MAX_NETWORK_HINTS} hints"),
                    });
                }
                Ok(Self::Direct(Box::new(DirectQrPayload {
                    invitation_id: InvitationId::new(crate::scalars::Uuid::from_bytes(
                        fixed_member(map, "invitation_id")?,
                    )),
                    endpoint_id: EndpointKey::from_bytes(fixed_member(map, "endpoint_id")?),
                    network_config,
                    secret: SecretBytes32::from_bytes(fixed_member(map, "secret")?),
                    proposed_grant: typed_member(map, "proposed_grant")?,
                    expires_at_ms: TimestampMs::new(
                        map.get("expires_at")
                            .and_then(CanonicalValue::as_integer)
                            .and_then(kr_cbor::Integer::as_u64)
                            .ok_or(QrPayloadError::Malformed(
                                "a direct payload carries an unsigned expiry in UTC milliseconds",
                            ))?,
                    ),
                })))
            }
            other => Err(QrPayloadError::UnsupportedMode {
                mode: other.to_owned(),
            }),
        }
    }

    /// Returns the unpadded base64url text of the canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn to_text(&self) -> Result<zeroize::Zeroizing<String>, CborError> {
        Ok(zeroize::Zeroizing::new(crate::scalars::to_base64url(
            &self.to_canonical_bytes()?,
        )))
    }

    /// Reads a payload from its unpadded base64url text.
    ///
    /// # Errors
    ///
    /// Returns [`QrPayloadError`] when the text is not base64url or the bytes are not a valid
    /// payload.
    pub fn from_text(text: &str) -> Result<Self, QrPayloadError> {
        // Four base64url characters carry three bytes, so the text is bounded before it is
        // decoded and an oversized input never reaches an allocation.
        let limit = MAX_QR_PAYLOAD_LEN.div_ceil(3) * 4;
        if text.len() > limit {
            return Err(QrPayloadError::TooLarge {
                len: text.len(),
                limit,
            });
        }
        // The buffer is under `Zeroizing` before the decode starts, so a decode that fails part
        // way through does not leave the prefix it read behind.
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(text.len() / 4 * 3));
        crate::scalars::from_base64url_into(text, &mut bytes).map_err(|reason| {
            QrPayloadError::InvalidMember {
                member: "payload text",
                reason,
            }
        })?;
        Self::from_canonical_bytes(&bytes)
    }
}

/// Clears every byte string and text buffer in a value tree that carried a secret.
///
/// `CanonicalValue` is an ordinary wire value and does not clear itself, so a tree built around a
/// pairing secret is wiped here before it is dropped.
fn zeroise_value(value: &mut CanonicalValue) {
    use zeroize::Zeroize as _;

    match value {
        CanonicalValue::Bytes(bytes) => bytes.zeroize(),
        CanonicalValue::Text(text) => text.zeroize(),
        CanonicalValue::Array(items) => items.iter_mut().for_each(zeroise_value),
        CanonicalValue::Map(map) => {
            let mut entries = std::mem::take(map).into_entries();
            for (key, value) in &mut entries {
                key.zeroize();
                zeroise_value(value);
            }
        }
        CanonicalValue::Null | CanonicalValue::Bool(_) | CanonicalValue::Integer(_) => {}
    }
}

fn fixed_member<const N: usize>(
    map: &kr_cbor::CanonicalMap,
    member: &'static str,
) -> Result<[u8; N], QrPayloadError> {
    let CanonicalValue::Bytes(bytes) = map
        .get(member)
        .ok_or(QrPayloadError::Malformed("a member is missing"))?
    else {
        return Err(QrPayloadError::InvalidMember {
            member,
            reason: "expected a byte string".to_owned(),
        });
    };
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| QrPayloadError::InvalidMember {
        member,
        reason: format!("expected {N} bytes, got {}", bytes.len()),
    })
}

fn typed_member<T: serde::de::DeserializeOwned + Serialize>(
    map: &kr_cbor::CanonicalMap,
    member: &'static str,
) -> Result<T, QrPayloadError> {
    let value = map
        .get(member)
        .ok_or(QrPayloadError::Malformed("a member is missing"))?;
    kr_cbor::from_canonical_value(value).map_err(|error| QrPayloadError::InvalidMember {
        member,
        reason: error.to_string(),
    })
}

/// How an owner confirmation reached the host.
///
/// Noninteractive confirmation from a session, plugin or contact-tool channel is rejected: an
/// agent's process label, operating-system peer credentials, terminal output or a newly created
/// invitation context is not a confirmation.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConfirmationChannel {
    /// A protected native user-verification ceremony on the unlocked owner device.
    OwnerDevicePresence,
    /// Approval from a separately paired owner device.
    PairedOwnerDevice,
    /// An explicitly enrolled user-presence-capable owner signer, for a headless host.
    EnrolledPresenceSigner,
    /// The initial local bootstrap on an interactive controlling terminal outside a KR session.
    ///
    /// This protects against accidental agent initiation. It is not isolation from other code
    /// running under the same operating-system identity.
    LocalBootstrapTerminal,
    /// A KalaReach session channel. Never a confirmation.
    Session,
    /// A plugin channel. Never a confirmation.
    Plugin,
    /// A contact-tool channel. Never a confirmation.
    ContactTool,
}

impl ConfirmationChannel {
    /// Returns the schema name of the channel.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerDevicePresence => "owner_device_presence",
            Self::PairedOwnerDevice => "paired_owner_device",
            Self::EnrolledPresenceSigner => "enrolled_presence_signer",
            Self::LocalBootstrapTerminal => "local_bootstrap_terminal",
            Self::Session => "session",
            Self::Plugin => "plugin",
            Self::ContactTool => "contact_tool",
        }
    }

    /// Returns true when a confirmation arriving through this channel may be accepted.
    ///
    /// `initial_bootstrap` is true only while the host has no owner yet. The controlling-terminal
    /// channel exists to protect that one moment against accidental agent initiation; afterwards a
    /// host with no user-presence-capable signer and no separately paired owner refuses the
    /// confirmation rather than downgrading it.
    #[must_use]
    pub const fn is_acceptable(self, initial_bootstrap: bool) -> bool {
        match self {
            Self::OwnerDevicePresence | Self::PairedOwnerDevice | Self::EnrolledPresenceSigner => {
                true
            }
            Self::LocalBootstrapTerminal => initial_bootstrap,
            Self::Session | Self::Plugin | Self::ContactTool => false,
        }
    }
}

/// What a sensitive action is being confirmed for.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SensitiveAction {
    /// Issuing a persistent pairing invitation.
    IssueInvitation,
    /// Confirming a new device.
    ConfirmDevice,
    /// Enlarging a persistent grant.
    EnlargeGrant,
    /// Trusting a new repository root.
    TrustRepositoryRoot,
    /// Granting executable or native-bridge capabilities.
    GrantExecutableCapability,
    /// Changing host-management authority.
    ChangeHostAuthority,
}

/// A host-issued owner-confirmation challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerConfirmationRequest {
    /// The challenge identity. Single use.
    pub confirmation_id: ConfirmationId,
    /// What is being confirmed.
    pub action: SensitiveAction,
    /// The digest of the exact action. One confirmation authorises one digest.
    pub action_digest: Digest256,
    /// The keys the action sends authority to. Null when the action has no destination device.
    pub destination_keys: Nullable<DevicePublicKeys>,
    /// The rights the action would grant.
    pub destination_rights: CanonicalSet<ActionRight>,
    /// The host this confirmation is for.
    pub host_device_id: DeviceId,
    /// The host's iroh endpoint identity.
    pub host_endpoint_id: EndpointKey,
    /// The host's fresh challenge nonce.
    pub nonce: Nonce256,
    /// The short expiry, in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
}

impl OwnerConfirmationRequest {
    /// Builds the canonical bytes an owner-confirmation proof signs.
    ///
    /// The channel is inside the signed material. A channel field beside an unsigned signature
    /// would be the signer's unauthenticated claim about how the confirmation was obtained, and a
    /// host that recorded it would be recording an attacker's word.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the request cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self, channel: ConfirmationChannel) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            OWNER_CONFIRM_DOMAIN,
            vec![
                kr_cbor::to_canonical_value(self)?,
                CanonicalValue::text(channel.as_str()),
            ],
        )))
    }
}

/// An owner's answer to a confirmation challenge.
///
/// The verification ceremony itself is platform code; this object records its result and binds it
/// to the exact challenge. The host's acceptance record keeps the user-presence evidence and the
/// challenge-consumption transition together.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerConfirmationProof {
    /// The challenge this proof answers.
    pub request: OwnerConfirmationRequest,
    /// How the confirmation reached the host.
    pub channel: ConfirmationChannel,
    /// The key identifier of the signer that produced the proof.
    pub signer_key_id: KeyId,
    /// The Ed25519 signature over `CBOR(["kr-pair/owner-confirm/1", request, channel])`.
    pub signature: Signature64,
}

/// A remote owner's signed revocation request.
///
/// A device cannot assign a higher host revision to its own request: the record carries no host
/// revision, because only the target host issues ordered authority revisions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationRequest {
    /// The request identity. Unique per request.
    pub request_id: RevocationRequestId,
    /// The device that published it.
    pub issuer_device_id: DeviceId,
    /// The host it is addressed to.
    pub host_device_id: DeviceId,
    /// What it revokes.
    pub target: RevocationTarget,
    /// When the issuer published it, in UTC milliseconds.
    pub issued_at_ms: TimestampMs,
    /// The key identifier of the issuer's authorisation key.
    pub issuer_key_id: KeyId,
    /// The Ed25519 signature over `CBOR(["kr-revocation/1", request without this field])`.
    pub signature: Signature64,
}

/// What a revocation removes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RevocationTarget {
    /// Named grants, and every grant delegated from them.
    Grants {
        /// The grants to revoke.
        grant_ids: CanonicalSet<GrantId>,
    },
    /// Named devices, and every grant issued to them.
    Devices {
        /// The devices to revoke.
        device_ids: CanonicalSet<DeviceId>,
    },
}

/// The domain a revocation request signature covers.
pub const REVOCATION_DOMAIN: &str = "kr-revocation/1";

/// The domain a host authority revision record signature covers.
pub const AUTHORITY_REVISION_DOMAIN: &str = "kr-authority/1";

/// One ordered authority revision, issued by the host and by nobody else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRevisionRecord {
    /// The host that issued it.
    pub host_device_id: DeviceId,
    /// The revision this record establishes.
    pub authority_revision: AuthorityRevision,
    /// The revision it follows. A host rejects a record that does not follow its latest accepted
    /// revision.
    pub previous_revision: AuthorityRevision,
    /// The revocation requests this revision applied, in ascending order.
    pub applied_requests: CanonicalSet<RevocationRequestId>,
    /// When the host issued it, in UTC milliseconds.
    pub issued_at_ms: TimestampMs,
    /// The key identifier of the host's authorisation key.
    pub host_key_id: KeyId,
    /// The Ed25519 signature over `CBOR(["kr-authority/1", record without this field])`.
    pub signature: Signature64,
}

/// Whether a revocation has reached every affected worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RevocationCompletion {
    /// Every affected worker acknowledged the fence or was confirmed to have ended.
    Complete,
    /// Some workers have not acknowledged yet. The controller has already stopped forwarding.
    Pending {
        /// How many workers are still outstanding.
        pending_workers: crate::scalars::U64,
    },
}

/// The host's acknowledgement of one revocation request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationAcknowledgement {
    /// The request acknowledged.
    pub request_id: RevocationRequestId,
    /// The host that acknowledged it.
    pub host_device_id: DeviceId,
    /// The revision the host issued for it.
    pub authority_revision: AuthorityRevision,
    /// Whether the dispatch barrier has completed.
    pub completion: RevocationCompletion,
    /// When the host acknowledged it, in UTC milliseconds.
    pub acknowledged_at_ms: TimestampMs,
}

/// What `pair.status` reports.
///
/// It never reveals secret material, and the host returns it only to the candidate's authenticated
/// endpoint or to the issuing owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PairStatus {
    /// The invitation is open and no candidate holds it.
    Open {
        /// Remaining failed-confirmation allowance on the host.
        remaining_confirmations: u32,
        /// When the invitation expires, in UTC milliseconds.
        expires_at_ms: TimestampMs,
    },
    /// A candidate holds the invitation and owner approval is pending.
    AwaitingApproval {
        /// The candidate's attempt.
        attempt_id: AttemptId,
        /// The verification value shown on both devices.
        verification_value: String,
        /// When the invitation expires, in UTC milliseconds.
        expires_at_ms: TimestampMs,
    },
    /// The owner approved and the host committed the device record and grant.
    Committed {
        /// The device the host created.
        device_id: DeviceId,
        /// The grant it issued.
        grant_id: GrantId,
    },
    /// The invitation was consumed without a grant.
    Consumed {
        /// Why it was consumed.
        reason: PairingConsumedReason,
    },
}

/// Why an invitation was consumed without issuing a grant.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PairingConsumedReason {
    /// The owner denied the request.
    Denied,
    /// The invitation reached its deadline.
    Expired,
    /// The owner cancelled it.
    Cancelled,
    /// The failed-confirmation allowance ran out.
    AttemptsExhausted,
    /// The host restarted while the invitation was unfinished.
    HostRestarted,
}

/// A stored backup checkpoint a pairing transfers.
///
/// A fresh client needs a trusted latest-generation checkpoint to detect a service replaying an
/// older valid backup. Pairing is where that checkpoint moves between devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GenerationCheckpoint {
    /// The archive the checkpoint describes.
    pub archive_id: ArchiveId,
    /// The latest generation the sending device has seen.
    pub backup_generation: BackupGeneration,
    /// The hash of that generation's encrypted manifest.
    pub encrypted_manifest_hash: Digest256,
    /// When the sending device observed it, in UTC milliseconds.
    pub observed_at_ms: TimestampMs,
}

/// Opaque bytes carried inside a pairing message, bounded by the pairing frame limit.
pub type PairingPayload = Bytes;

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> RendezvousOrigin {
        RendezvousOrigin::new("https://reach.kala.to").expect("a canonical origin")
    }

    #[test]
    fn a_locator_is_four_base58_characters() {
        assert!(Locator::new("aB3x").is_ok());
        assert!(Locator::new("aB3").is_err());
        assert!(Locator::new("aB3xy").is_err());
        // 0, O, I and l are outside the Bitcoin alphabet.
        assert!(Locator::new("0B3x").is_err());
        assert!(Locator::new("OB3x").is_err());
        assert!(Locator::new("IB3x").is_err());
        assert!(Locator::new("lB3x").is_err());
    }

    #[test]
    fn an_origin_is_a_canonical_https_origin() {
        assert!(RendezvousOrigin::new("https://reach.kala.to").is_ok());
        assert!(RendezvousOrigin::new("https://reach.kala.to:8443").is_ok());
        assert!(RendezvousOrigin::new("http://reach.kala.to").is_err());
        assert!(RendezvousOrigin::new("https://reach.kala.to/").is_err());
        assert!(RendezvousOrigin::new("https://REACH.kala.to").is_err());
        assert!(RendezvousOrigin::new("https://user@reach.kala.to").is_err());
        assert!(RendezvousOrigin::new("https://reach.kala.to:99999").is_err());
    }

    #[test]
    fn the_context_encodes_as_an_array_in_the_specified_order() {
        let context = PairingContext {
            rendezvous_origin: origin(),
            locator: Locator::new("aB3x").expect("a locator"),
            invitation_id: InvitationId::new(crate::scalars::Uuid::from_bytes([1; 16])),
            attempt_id: AttemptId::new(crate::scalars::Uuid::from_bytes([2; 16])),
            host_nonce: Nonce256::from_bytes([3; 32]),
            client_nonce: Nonce256::from_bytes([4; 32]),
        };
        let CanonicalValue::Array(items) = context.to_canonical_value() else {
            panic!("C is an array");
        };
        assert_eq!(items.len(), 7);
        assert_eq!(items[0].as_text(), Some(PAIRING_DOMAIN));
        assert_eq!(items[1].as_text(), Some("https://reach.kala.to"));
        assert_eq!(items[2].as_text(), Some("aB3x"));
    }

    #[test]
    fn the_role_identities_differ() {
        let context = PairingContext {
            rendezvous_origin: origin(),
            locator: Locator::new("aB3x").expect("a locator"),
            invitation_id: InvitationId::new(crate::scalars::Uuid::from_bytes([1; 16])),
            attempt_id: AttemptId::new(crate::scalars::Uuid::from_bytes([2; 16])),
            host_nonce: Nonce256::from_bytes([3; 32]),
            client_nonce: Nonce256::from_bytes([4; 32]),
        };
        assert_ne!(context.host_identity(), context.client_identity());
    }

    #[test]
    fn distinct_purposes_reject_a_reused_key() {
        let keys = DevicePublicKeys {
            transport: EndpointKey::from_bytes([1; 32]),
            authorisation: AuthorisationKey::from_bytes([2; 32]),
            stored_envelope: StoredEnvelopeKey::from_bytes([3; 32]),
            notification_preview: NotificationPreviewKey::from_bytes([4; 32]),
        };
        assert!(keys.purposes_are_distinct());
        let reused = DevicePublicKeys {
            notification_preview: NotificationPreviewKey::from_bytes([2; 32]),
            ..keys
        };
        assert!(!reused.purposes_are_distinct());
    }

    #[test]
    fn a_verification_value_is_eight_hexadecimal_characters() {
        let value = verification_value(
            Digest256::from_bytes([1; 32]),
            Digest256::from_bytes([2; 32]),
            Digest256::from_bytes([3; 32]),
        );
        assert_eq!(value.len(), VERIFICATION_VALUE_LEN);
        assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    fn sample_direct_payload() -> DirectQrPayload {
        DirectQrPayload {
            invitation_id: InvitationId::new(crate::scalars::Uuid::from_bytes([1; 16])),
            endpoint_id: EndpointKey::from_bytes([2; 32]),
            network_config: NetworkConfig {
                relay_urls: vec![NetworkHint::new("https://relay.kala.to").expect("a hint")],
                discovery_origins: Vec::new(),
                direct_addresses: vec![NetworkHint::new("192.0.2.1:41234").expect("a hint")],
            },
            secret: SecretBytes32::from_bytes([3; 32]),
            proposed_grant: ProposedGrant {
                parent_grant_id: Nullable::null(),
                environment_selector: EnvironmentSelector::Any,
                session_selector: SessionSelector::None,
                actions: CanonicalSet::new(),
                history: HistoryScope {
                    lower_bound_ms: Nullable::null(),
                    include_live_screen: false,
                    named_questions: CanonicalSet::new(),
                    named_approvals: CanonicalSet::new(),
                },
                expiry: GrantExpiry::Never,
                organisation: Nullable::null(),
            },
            expires_at_ms: TimestampMs::new(1_764_000_600_000),
        }
    }

    #[test]
    fn the_hand_assembled_encoding_matches_the_value_tree() {
        // The encoder writes the map head and the two secret-carrying heads itself. This is the
        // check that it writes what the canonical encoder would have written.
        for payload in [
            QrPayload::Code(CodeQrPayload {
                rendezvous_origin: origin(),
                code: ShortCode::new("aB3x-Yz7-9Qw").expect("a code"),
            }),
            QrPayload::Direct(Box::new(sample_direct_payload())),
        ] {
            let assembled = payload.to_canonical_bytes().expect("canonical bytes");
            let through_the_tree =
                kr_cbor::encode(&payload.to_canonical_value().expect("a value tree"));
            assert_eq!(
                assembled.as_slice(),
                through_the_tree.as_slice(),
                "{} payload",
                payload.mode()
            );
            // And it round trips, so the members are in the order the decoder expects.
            assert_eq!(
                QrPayload::from_canonical_bytes(&assembled).expect("a payload"),
                payload
            );
        }
    }

    #[test]
    fn a_qr_payload_round_trips_and_requires_a_supported_mode_and_version() {
        let payload = QrPayload::Code(CodeQrPayload {
            rendezvous_origin: origin(),
            code: ShortCode::new("aB3x-Yz7-9Qw").expect("a code"),
        });
        let bytes = payload.to_canonical_bytes().expect("canonical bytes");
        assert_eq!(
            QrPayload::from_canonical_bytes(&bytes).expect("a payload"),
            payload
        );
        let text = payload.to_text().expect("text");
        assert_eq!(QrPayload::from_text(&text).expect("a payload"), payload);

        let mut map = kr_cbor::CanonicalMap::new();
        map.insert("version".to_owned(), CanonicalValue::Integer(2u64.into()))
            .expect("a fresh key");
        map.insert("mode".to_owned(), CanonicalValue::text(QR_MODE_CODE))
            .expect("a fresh key");
        map.insert(
            "rendezvous_origin".to_owned(),
            CanonicalValue::text(origin().as_str()),
        )
        .expect("a fresh key");
        map.insert("code".to_owned(), CanonicalValue::text("aB3x-Yz7-9Qw"))
            .expect("a fresh key");
        let future = kr_cbor::encode(&CanonicalValue::Map(map));
        assert!(matches!(
            QrPayload::from_canonical_bytes(&future),
            Err(QrPayloadError::UnsupportedVersion { version: 2 })
        ));

        let mut map = kr_cbor::CanonicalMap::new();
        map.insert("version".to_owned(), CanonicalValue::Integer(1u64.into()))
            .expect("a fresh key");
        map.insert("mode".to_owned(), CanonicalValue::text("offline"))
            .expect("a fresh key");
        let unknown = kr_cbor::encode(&CanonicalValue::Map(map));
        assert!(matches!(
            QrPayload::from_canonical_bytes(&unknown),
            Err(QrPayloadError::UnsupportedMode { .. })
        ));
    }

    #[test]
    fn only_interactive_channels_may_confirm() {
        for bootstrap in [false, true] {
            assert!(ConfirmationChannel::OwnerDevicePresence.is_acceptable(bootstrap));
            assert!(ConfirmationChannel::PairedOwnerDevice.is_acceptable(bootstrap));
            assert!(ConfirmationChannel::EnrolledPresenceSigner.is_acceptable(bootstrap));
            assert!(!ConfirmationChannel::Session.is_acceptable(bootstrap));
            assert!(!ConfirmationChannel::Plugin.is_acceptable(bootstrap));
            assert!(!ConfirmationChannel::ContactTool.is_acceptable(bootstrap));
        }
        // The controlling terminal is the initial bootstrap exception and nothing more.
        assert!(ConfirmationChannel::LocalBootstrapTerminal.is_acceptable(true));
        assert!(!ConfirmationChannel::LocalBootstrapTerminal.is_acceptable(false));
    }

    #[test]
    fn the_confirmation_signature_covers_the_channel() {
        let request = OwnerConfirmationRequest {
            confirmation_id: ConfirmationId::new(crate::scalars::Uuid::from_bytes([1; 16])),
            action: SensitiveAction::ConfirmDevice,
            action_digest: Digest256::from_bytes([2; 32]),
            destination_keys: Nullable::null(),
            destination_rights: CanonicalSet::new(),
            host_device_id: DeviceId::new(crate::scalars::Uuid::from_bytes([3; 16])),
            host_endpoint_id: EndpointKey::from_bytes([4; 32]),
            nonce: Nonce256::from_bytes([5; 32]),
            expires_at_ms: TimestampMs::new(1_000),
        };
        assert_ne!(
            request
                .signing_input(ConfirmationChannel::OwnerDevicePresence)
                .expect("bytes"),
            request
                .signing_input(ConfirmationChannel::LocalBootstrapTerminal)
                .expect("bytes")
        );
    }

    #[test]
    fn a_short_code_redacts_its_secret_half() {
        let code = ShortCode::new("aB3x-Yz7-9Qw").expect("a code");
        let rendered = format!("{code:?}");
        assert_eq!(rendered, "ShortCode(aB3x-...-...)");
        assert!(!rendered.contains("Yz7"));
        assert!(!rendered.contains("9Qw"));
        assert_eq!(code.locator().as_str(), "aB3x");
        assert!(ShortCode::new("aB3xYz79Qw").is_err());
        assert!(ShortCode::new("aB3x-Yz7-9Q0").is_err());
    }

    #[test]
    fn a_direct_payload_redacts_its_secret() {
        let payload = DirectQrPayload {
            invitation_id: InvitationId::new(crate::scalars::Uuid::from_bytes([1; 16])),
            endpoint_id: EndpointKey::from_bytes([2; 32]),
            network_config: NetworkConfig {
                relay_urls: Vec::new(),
                discovery_origins: Vec::new(),
                direct_addresses: Vec::new(),
            },
            secret: SecretBytes32::from_bytes([3; 32]),
            proposed_grant: ProposedGrant {
                parent_grant_id: Nullable::null(),
                environment_selector: EnvironmentSelector::Any,
                session_selector: SessionSelector::None,
                actions: CanonicalSet::new(),
                history: HistoryScope {
                    lower_bound_ms: Nullable::null(),
                    include_live_screen: false,
                    named_questions: CanonicalSet::new(),
                    named_approvals: CanonicalSet::new(),
                },
                expiry: GrantExpiry::Never,
                organisation: Nullable::null(),
            },
            expires_at_ms: TimestampMs::new(1),
        };
        let rendered = format!("{payload:?}");
        assert!(rendered.contains("secret: \"redacted\""));
        assert!(!rendered.contains(&crate::scalars::to_base64url(&[3u8; 32])));
    }

    #[test]
    fn an_origin_has_one_canonical_form() {
        assert!(RendezvousOrigin::new("https://reach.kala.to:443").is_err());
        assert!(RendezvousOrigin::new("https://reach.kala.to:00443").is_err());
        assert!(RendezvousOrigin::new("https://reach.kala.to:0").is_err());
        assert!(RendezvousOrigin::new("https://reach.kala.to.").is_err());
        assert!(RendezvousOrigin::new("https://-reach.kala.to").is_err());
        assert!(RendezvousOrigin::new("https://reach..kala.to").is_err());
        assert!(RendezvousOrigin::new("https://[2001:db8::1]").is_ok());
        assert!(RendezvousOrigin::new("https://[2001:db8::1]:8443").is_ok());
        assert!(RendezvousOrigin::new("https://[2001:DB8::1]").is_err());
        assert!(RendezvousOrigin::new("https://2001:db8::1").is_err());
        // One address, one spelling.
        assert!(RendezvousOrigin::new("https://[:::]").is_err());
        assert!(RendezvousOrigin::new("https://[2001:0db8::1]").is_err());
        assert!(RendezvousOrigin::new("https://[2001:db8:0:0:0:0:0:1]").is_err());
        assert!(RendezvousOrigin::new("https://[::1]").is_ok());
        assert!(RendezvousOrigin::new("https://192.0.2.1").is_ok());
        assert!(RendezvousOrigin::new("https://192.0.02.1").is_err());
        assert!(RendezvousOrigin::new("https://192.0.2.1.5").is_err());
        // One host, one spelling: a mapped address and a numeric last label are both refused.
        assert!(RendezvousOrigin::new("https://[::ffff:192.0.2.1]").is_err());
        assert!(RendezvousOrigin::new("https://[::ffff:c000:201]").is_err());
        assert!(RendezvousOrigin::new("https://[::192.0.2.1]").is_err());
        assert!(RendezvousOrigin::new("https://0xc0000201").is_err());
        assert!(RendezvousOrigin::new("https://3221225985").is_err());
        assert!(RendezvousOrigin::new("https://reach.kala.to").is_ok());
        assert!(RendezvousOrigin::new("https://1password.example").is_ok());
        // A punycode A-label is a name: it starts with a letter and carries one.
        assert!(RendezvousOrigin::new("https://xn--p1ai.xn--p1ai").is_ok());
        assert!(RendezvousOrigin::new("https://reach.kala.to:8443").is_ok());
    }

    #[test]
    fn the_five_information_strings_are_the_specified_literals() {
        assert_eq!(
            HKDF_INFO_STRINGS,
            [
                "kr-pair/1/client-confirm",
                "kr-pair/1/host-confirm",
                "kr-pair/1/client-to-host",
                "kr-pair/1/host-to-client",
                "kr-pair/1/iroh-bind",
            ]
        );
    }

    #[test]
    fn the_bundle_aad_binds_direction_sequence_and_type() {
        let transcript = Digest256::from_bytes([7; 32]);
        let base = bundle_aad(
            transcript,
            BundleDirection::ClientToHost,
            PairingSequence::new(1),
            BundleMessageType::ClientBundle,
        );
        assert_ne!(
            base,
            bundle_aad(
                transcript,
                BundleDirection::HostToClient,
                PairingSequence::new(1),
                BundleMessageType::ClientBundle,
            )
        );
        assert_ne!(
            base,
            bundle_aad(
                transcript,
                BundleDirection::ClientToHost,
                PairingSequence::new(2),
                BundleMessageType::ClientBundle,
            )
        );
        assert_ne!(
            base,
            bundle_aad(
                transcript,
                BundleDirection::ClientToHost,
                PairingSequence::new(1),
                BundleMessageType::HostBundle,
            )
        );
    }
}
