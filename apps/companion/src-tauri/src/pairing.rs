//! The rendezvous origin, and what a scanned code is allowed to change about it.
//!
//! Section 10 is explicit about two things a companion application owns. The chosen rendezvous
//! origin is always visible, on manual entry and on the issuing screen, with a change action
//! before an attempt starts. And a scanned code-mode QR that names another origin needs an explicit
//! native confirmation that shows the full HTTPS hostname, because a typed code must never select
//! a service for the person.

use serde::{Deserialize, Serialize};

use crate::error::{CommandError, Result};

/// The origin KalaReach's own rendezvous service runs on.
pub const DEFAULT_RENDEZVOUS_ORIGIN: &str = "https://rendezvous.kala.to";

/// The canonical form of one rendezvous origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    /// The canonical `https://host[:port]` form.
    pub origin: String,
    /// The hostname on its own, which is what a confirmation shows.
    pub host: String,
    /// True when this is the origin KalaReach ships with.
    pub is_default: bool,
}

/// Parses and canonicalises a rendezvous origin.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` for anything that is not a plain `https` origin: a path, a query, a
/// fragment, credentials or another scheme all make the string something other than an origin.
pub fn parse_origin(value: &str) -> Result<Origin> {
    let trimmed = value.trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("https://")
        .ok_or_else(|| CommandError::invalid("a rendezvous origin is an https origin"))?;
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ']) {
        return Err(CommandError::invalid(
            "a rendezvous origin carries a host and an optional port, and nothing else",
        ));
    }
    let host = rest.rsplit_once(':').map_or(rest, |(host, port)| {
        if !port.is_empty() && port.chars().all(|character| character.is_ascii_digit()) {
            host
        } else {
            rest
        }
    });
    // A host is compared case-insensitively, so the canonical form is the lowercase one.
    let host = host.to_ascii_lowercase();
    if host.is_empty() {
        return Err(CommandError::invalid(
            "a rendezvous origin must name a host",
        ));
    }
    let origin = format!("https://{}", rest.to_ascii_lowercase());
    Ok(Origin {
        is_default: origin == DEFAULT_RENDEZVOUS_ORIGIN,
        origin,
        host,
    })
}

/// What a scanned QR payload turned out to be.
///
/// Section 10 gives the two typed payloads exactly. A parser that accepted an untyped one would be
/// guessing which pairing mode the person is in, so an unknown mode is a refusal rather than a
/// default.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Scanned {
    /// A short-code QR: a rendezvous origin and a ten-character code.
    Code {
        /// The origin the QR names.
        origin: Origin,
        /// The code, as typed into the field.
        code: String,
        /// True when the QR names an origin other than the one this device is configured with.
        /// The interface must obtain an explicit confirmation showing `origin.host` first.
        needs_origin_confirmation: bool,
    },
    /// A self-contained direct QR, which does not use the short-code service at all.
    Direct {
        /// The invitation this QR carries.
        invitation_id: String,
        /// The host endpoint the client pins.
        endpoint_id: String,
        /// When the invitation expires.
        expires_at_ms: String,
    },
}

#[derive(Deserialize)]
struct RawPayload {
    version: u32,
    mode: String,
    rendezvous_origin: Option<String>,
    code: Option<String>,
    invitation_id: Option<String>,
    endpoint_id: Option<String>,
    expires_at_ms: Option<String>,
}

/// The most a QR payload may weigh before it is parsed.
const MAX_PAYLOAD_BYTES: usize = 8 * 1024;

/// Parses a scanned QR payload against the configured origin.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` for a payload that is not one of the two typed formats, and for a
/// code that is not ten valid characters.
pub fn scan(payload: &str, configured: &Origin) -> Result<Scanned> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(CommandError::invalid("that is not a pairing code"));
    }
    let raw: RawPayload = serde_json::from_str(payload)
        .map_err(|_| CommandError::invalid("that is not a pairing code"))?;
    if raw.version != 1 {
        return Err(CommandError::invalid(
            "this application does not read that pairing code version",
        ));
    }
    match raw.mode.as_str() {
        "code" => {
            let origin = parse_origin(raw.rendezvous_origin.as_deref().ok_or_else(|| {
                CommandError::invalid("a code QR names the rendezvous origin it belongs to")
            })?)?;
            let code = normalise_code(
                raw.code
                    .as_deref()
                    .ok_or_else(|| CommandError::invalid("a code QR carries a code"))?,
            )?;
            Ok(Scanned::Code {
                needs_origin_confirmation: origin.origin != configured.origin,
                origin,
                code,
            })
        }
        "direct" => Ok(Scanned::Direct {
            invitation_id: raw.invitation_id.ok_or_else(|| {
                CommandError::invalid("a direct QR carries an invitation identifier")
            })?,
            endpoint_id: raw.endpoint_id.ok_or_else(|| {
                CommandError::invalid("a direct QR carries the host endpoint it pins")
            })?,
            expires_at_ms: raw
                .expires_at_ms
                .ok_or_else(|| CommandError::invalid("a direct QR carries its expiry"))?,
        }),
        _ => Err(CommandError::invalid(
            "a QR without a supported pairing mode is not an invitation",
        )),
    }
}

/// The Bitcoin Base58 alphabet, which is what a short code is drawn from.
const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Normalises a typed or scanned short code.
///
/// Spaces and hyphens are removed, case is preserved, and exactly ten valid characters are
/// required. Section 10 fixes all three.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` when the result is not ten characters of the alphabet.
pub fn normalise_code(value: &str) -> Result<String> {
    let code: String = value
        .chars()
        .filter(|character| !matches!(character, ' ' | '-'))
        .collect();
    if code.chars().count() != 10 || !code.chars().all(|character| BASE58.contains(character)) {
        return Err(CommandError::invalid(
            "a pairing code is ten characters of the pairing alphabet",
        ));
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_origin() -> Origin {
        parse_origin(DEFAULT_RENDEZVOUS_ORIGIN).expect("the shipped origin parses")
    }

    #[test]
    fn the_shipped_origin_is_marked_as_the_default() {
        let origin = default_origin();
        assert!(origin.is_default);
        assert_eq!(origin.host, "rendezvous.kala.to");
    }

    #[test]
    fn a_self_hosted_origin_is_accepted_and_is_not_the_default() {
        let origin = parse_origin("https://pair.example.org:8443/").expect("a valid origin");
        assert_eq!(origin.origin, "https://pair.example.org:8443");
        assert_eq!(origin.host, "pair.example.org");
        assert!(!origin.is_default);
    }

    #[test]
    fn an_origin_with_a_path_or_another_scheme_is_refused() {
        for value in [
            "https://pair.example.org/path",
            "http://pair.example.org",
            "https://user@pair.example.org",
            "pair.example.org",
        ] {
            assert!(parse_origin(value).is_err(), "{value} is not an origin");
        }
    }

    #[test]
    fn a_code_qr_naming_another_origin_is_marked_as_needing_confirmation() {
        let payload = r#"{"version":1,"mode":"code","rendezvous_origin":"https://pair.example.org","code":"KALA4821xy"}"#;
        let scanned = scan(payload, &default_origin()).expect("a code QR");
        let Scanned::Code {
            origin,
            needs_origin_confirmation,
            ..
        } = scanned
        else {
            panic!("that payload is a code QR");
        };
        assert!(needs_origin_confirmation);
        assert_eq!(
            origin.host, "pair.example.org",
            "the confirmation shows the full hostname"
        );
    }

    #[test]
    fn a_code_qr_naming_the_configured_origin_needs_no_confirmation() {
        let payload = format!(
            r#"{{"version":1,"mode":"code","rendezvous_origin":"{DEFAULT_RENDEZVOUS_ORIGIN}","code":"KALA-4821-xy"}}"#
        );
        let scanned = scan(&payload, &default_origin()).expect("a code QR");
        let Scanned::Code {
            needs_origin_confirmation,
            code,
            ..
        } = scanned
        else {
            panic!("that payload is a code QR");
        };
        assert!(!needs_origin_confirmation);
        assert_eq!(
            code, "KALA4821xy",
            "separators are removed and case is kept"
        );
    }

    #[test]
    fn a_direct_qr_is_read_as_a_self_contained_invitation() {
        let payload = r#"{"version":1,"mode":"direct","invitation_id":"i-1","endpoint_id":"e-1","expires_at_ms":"1700000000000"}"#;
        let scanned = scan(payload, &default_origin()).expect("a direct QR");
        assert!(matches!(scanned, Scanned::Direct { .. }));
    }

    #[test]
    fn a_qr_without_a_supported_mode_is_refused() {
        let payload = r#"{"version":1,"mode":"guess","code":"KALA4821xy"}"#;
        let error =
            scan(payload, &default_origin()).expect_err("an untyped QR is not an invitation");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_code_of_the_wrong_length_or_alphabet_is_refused() {
        for value in ["KALA4821x", "KALA4821xyz", "KALA48210y", "KALA4821xI"] {
            assert!(normalise_code(value).is_err(), "{value} is not a code");
        }
    }
}
