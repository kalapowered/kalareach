//! The one invitation reader a device has.
//!
//! A host issues its QR payload as base64url canonical KR-CBOR-1 (`QrPayload::to_text`), and the
//! device reads it with the host's own reader, `QrPayload::from_text`: it bounds the text before
//! decoding, requires canonical bytes, an explicit supported mode and version 1, and zeroises what
//! it decoded. Nothing else reads an invitation, so a payload in any other form is not one.
//!
//! A code payload becomes the code a person would have typed and the origin it names. Section 10
//! requires an explicit native confirmation, showing the full hostname, before a device contacts an
//! origin a scanned code names in place of the one it is set to use; [`CodeInvitation`] says when
//! that is the case and leaves the confirmation to the application that owns the dialogs.

use kr_pairing::code::EnteredCode;
use kr_protocol::grant::GrantExpiry;
use kr_protocol::pairing::{DirectQrPayload, QrPayload, QrPayloadError, RendezvousOrigin};
use kr_protocol::rights::ActionRight;
use serde::Serialize;

use super::failure::{FailureKind, PairingFailure};

/// What a scanned or pasted payload turned out to be.
pub enum Invitation {
    /// A short code, through the rendezvous room at the origin the payload names.
    Code(CodeInvitation),
    /// A self-contained invitation, redeemed directly with the host it pins.
    Direct(Box<DirectQrPayload>),
}

impl std::fmt::Debug for Invitation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Code(code) => formatter.debug_tuple("Code").field(code).finish(),
            Self::Direct(payload) => formatter.debug_tuple("Direct").field(payload).finish(),
        }
    }
}

/// A code payload, read.
///
/// `Debug` shows the locator and never the six secret characters.
#[derive(Debug)]
pub struct CodeInvitation {
    /// The origin the payload names.
    pub origin: RendezvousOrigin,
    /// The code, as a person would have entered it.
    pub code: EnteredCode,
    /// True when `origin` is not the origin this device is set to use, so contacting it needs the
    /// person's explicit confirmation first.
    pub names_another_origin: bool,
}

/// What a person is shown about an invitation before they pair with it. Nothing in it is secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InvitationSummary {
    /// `code` or `direct`.
    pub mode: &'static str,
    /// The host name of the origin a code goes through.
    pub origin_host: Option<String>,
    /// True when that origin is not the one this device is set to use.
    pub names_another_origin: bool,
    /// The rights a direct invitation proposes. A code's proposal arrives only once the host has
    /// proved the code.
    pub rights: Option<Vec<ActionRight>>,
    /// When the grant a direct invitation proposes would end, if it would.
    pub grant_expires_at_ms: Option<u64>,
    /// When a direct invitation expires.
    pub expires_at_ms: Option<u64>,
}

impl Invitation {
    /// What a person is shown about this invitation.
    #[must_use]
    pub fn summary(&self) -> InvitationSummary {
        match self {
            Self::Code(code) => InvitationSummary {
                mode: "code",
                origin_host: Some(origin_host(&code.origin).to_owned()),
                names_another_origin: code.names_another_origin,
                rights: None,
                grant_expires_at_ms: None,
                expires_at_ms: None,
            },
            Self::Direct(payload) => InvitationSummary {
                mode: "direct",
                origin_host: None,
                names_another_origin: false,
                rights: Some(payload.proposed_grant.actions.iter().copied().collect()),
                grant_expires_at_ms: match payload.proposed_grant.expiry {
                    GrantExpiry::Never => None,
                    GrantExpiry::At { expires_at_ms } => Some(expires_at_ms.get()),
                },
                expires_at_ms: Some(payload.expires_at_ms.get()),
            },
        }
    }
}

/// Returns the host name of an origin, which is what a confirmation shows a person.
#[must_use]
pub fn origin_host(origin: &RendezvousOrigin) -> &str {
    let authority = origin
        .as_str()
        .strip_prefix("https://")
        .unwrap_or(origin.as_str());
    match authority.strip_prefix('[') {
        Some(bracketed) => bracketed
            .split_once(']')
            .map_or(authority, |(host, _)| host),
        None => authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host),
    }
}

/// Reads a scanned or pasted invitation, against the origin this device is set to use.
///
/// Whitespace around the text is ignored, because a copied line carries it; nothing else is.
///
/// # Errors
///
/// Returns [`FailureKind::NotAnInvitation`] for anything that is not a canonical payload of a
/// supported mode, and [`FailureKind::NewerInvitation`] for a payload of a later version.
pub fn read_invitation(
    text: &str,
    configured: &RendezvousOrigin,
) -> Result<Invitation, PairingFailure> {
    let payload = QrPayload::from_text(text.trim()).map_err(|error| {
        let kind = match error {
            QrPayloadError::UnsupportedVersion { version } if version > 1 => {
                FailureKind::NewerInvitation
            }
            _ => FailureKind::NotAnInvitation,
        };
        PairingFailure::new(kind, error.to_string())
    })?;
    match payload {
        QrPayload::Code(code) => {
            let entered = EnteredCode::parse(&code.code.to_secret_text()).map_err(|_| {
                PairingFailure::new(
                    FailureKind::NotAnInvitation,
                    "the payload's code is not ten characters of the pairing alphabet",
                )
            })?;
            Ok(Invitation::Code(CodeInvitation {
                names_another_origin: &code.rendezvous_origin != configured,
                origin: code.rendezvous_origin.clone(),
                code: entered,
            }))
        }
        QrPayload::Direct(payload) => Ok(Invitation::Direct(payload)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A confirmation shows the host name of an origin, with no scheme, port or brackets.
    #[test]
    fn an_origins_host_is_what_a_confirmation_shows() {
        for (origin, host) in [
            ("https://reach.kala.to", "reach.kala.to"),
            ("https://pair.example.org:8443", "pair.example.org"),
            ("https://[::1]:8443", "::1"),
        ] {
            assert_eq!(
                origin_host(&RendezvousOrigin::new(origin).expect("an origin")),
                host
            );
        }
    }
}
