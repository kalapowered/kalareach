//! The issuing owner's pairing methods, the rendezvous relay payload and the security event.
//!
//! `pair.invite`, `pair.confirm`, `pair.cancel` and the owner's form of `pair.status` are local
//! IPC methods of the owner that issued an invitation. The candidate's three methods are in
//! [`crate::preauth`]. What passes between the two devices during a short-code exchange never
//! touches the host's own endpoint: it travels as opaque payloads through the rendezvous room, and
//! [`RendezvousMessage`] is that payload.
//!
//! Secret material is in two of these types and in no log. The ten-character code and the direct
//! QR text are returned to the issuing owner only, and both redact themselves in debug output.

use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::ErrorCode;
use crate::ids::{
    ConfirmationId, DeviceId, GrantId, InvitationId, PairingEventSequence, PairingSequence,
};
use crate::pairing::{
    ConfirmationChannel, DeviceName, DevicePlatform, DevicePublicKeys, MAX_QR_PAYLOAD_LEN,
    ProposedGrant, RendezvousOrigin, ShortCode,
};
use crate::scalars::{Bytes, Digest256, KeyId, Mac256, Nonce192, Nonce256, Nullable, TimestampMs};

/// How an invitation is offered, without its parameters.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InviteModeKind {
    /// A ten-character code through a rendezvous service.
    Code,
    /// A self-contained QR carrying the endpoint and a 256-bit secret.
    Direct,
}

/// How an invitation is offered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum InviteMode {
    /// A ten-character code through a rendezvous service.
    Code {
        /// The rendezvous origin to reserve the locator at. Null takes this host's default, which
        /// the answer names so the issuing screen can show it.
        rendezvous_origin: Nullable<RendezvousOrigin>,
    },
    /// A self-contained QR.
    Direct,
}

impl InviteMode {
    /// Returns the mode without its parameters.
    #[must_use]
    pub const fn kind(&self) -> InviteModeKind {
        match self {
            Self::Code { .. } => InviteModeKind::Code,
            Self::Direct => InviteModeKind::Direct,
        }
    }
}

/// Which rules a proposed grant is checked against.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InviteGrantKind {
    /// A personal owner grant, valid until revoked.
    PersonalOwner,
    /// A session invitation, view-only for an hour unless the issuer chose otherwise.
    SessionInvitation,
}

/// The rendezvous origin a host reserves a code at when its owner names none.
///
/// Section 10 has the origin always shown on the issuing screen, the default included, with a way
/// to change it before an attempt starts. This is that default: the service KalaReach runs.
pub const DEFAULT_RENDEZVOUS_ORIGIN: &str = "https://reach.kala.to";

/// Returns the default rendezvous origin.
///
/// # Panics
///
/// Never: the constant is a valid origin, and a test holds it to that.
#[must_use]
pub fn default_rendezvous_origin() -> RendezvousOrigin {
    RendezvousOrigin::new(DEFAULT_RENDEZVOUS_ORIGIN).expect("the default origin is an origin")
}

/// The domain an owner's confirmation to issue an invitation is computed under.
pub const ISSUE_INVITATION_DOMAIN: &str = "kr-pair/issue-invitation/1";

/// Returns the digest an owner confirms when it approves issuing one invitation.
///
/// It covers everything the owner is shown about the invitation: how it will be offered, the
/// origin a code invitation reserves its locator at, the rules its grant is checked against, and
/// the exact proposed grant. A confirmation for a code invitation therefore cannot issue a direct
/// one, and one for one origin cannot reserve at another.
///
/// # Errors
///
/// Returns a CBOR error when the grant is outside KR-CBOR-1.
pub fn issuance_digest(
    mode: InviteModeKind,
    rendezvous_origin: Option<&RendezvousOrigin>,
    grant_kind: InviteGrantKind,
    proposed_grant: &ProposedGrant,
) -> Result<Digest256, kr_cbor::CborError> {
    let origin: Nullable<RendezvousOrigin> =
        rendezvous_origin.map_or_else(Nullable::null, |origin| Nullable::some(origin.clone()));
    Ok(Digest256::from_bytes(kr_cbor::sha256(
        &kr_cbor::to_canonical_vec(&(
            ISSUE_INVITATION_DOMAIN,
            mode,
            origin,
            grant_kind,
            proposed_grant,
        ))?,
    )))
}

/// The parameters of `pair.invite`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairInviteParams {
    /// How the invitation is offered.
    pub mode: InviteMode,
    /// Which rules the proposed grant is checked against.
    pub grant_kind: InviteGrantKind,
    /// The exact rights the invitation proposes. The owner's confirmation names them.
    pub proposed_grant: ProposedGrant,
}

/// The unpadded base64url text a QR code encodes.
///
/// A direct payload carries the invitation's whole secret and a code payload carries the code,
/// so this redacts itself in debug output and clears its buffer when it is dropped.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct QrText(String);

impl QrText {
    /// Wraps QR payload text after checking its alphabet and its length.
    ///
    /// # Errors
    ///
    /// Returns a message when the text is not unpadded base64url or is longer than a QR code can
    /// hold.
    pub fn new(text: impl Into<String>) -> Result<Self, &'static str> {
        let text = text.into();
        if text.is_empty() {
            return Err("a QR payload is not empty");
        }
        if text.len() > MAX_QR_PAYLOAD_LEN.div_ceil(3) * 4 {
            return Err("a QR payload fits in one QR code");
        }
        if !text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err("a QR payload is unpadded base64url");
        }
        Ok(Self(text))
    }

    /// Returns the text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for QrText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "QrText({} characters)", self.0.len())
    }
}

impl Drop for QrText {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;

        self.0.zeroize();
    }
}

impl<'de> Deserialize<'de> for QrText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for QrText {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "QrText".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::QrText".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^[A-Za-z0-9_-]+$",
            "maxLength": MAX_QR_PAYLOAD_LEN.div_ceil(3) * 4,
            "description": "The unpadded base64url text of a QR payload. It carries secret material and is returned to the issuing owner only."
        })
    }
}

/// How the issuing owner offers an invitation it has just issued.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum InviteEntry {
    /// The code, the origin a candidate must use, and the code-mode QR.
    Code {
        /// The origin the locator was reserved at. Always shown, the default included.
        rendezvous_origin: RendezvousOrigin,
        /// The ten characters, displayed `XXXX-XXX-XXX`.
        code: ShortCode,
        /// The code-mode QR payload, `{version, mode: "code", rendezvous_origin, code}`.
        qr_text: QrText,
    },
    /// The self-contained QR payload.
    Direct {
        /// `{version, mode: "direct", invitation_id, endpoint_id, network_config, secret,
        /// proposed_grant, expires_at}`.
        qr_text: QrText,
    },
}

/// The result of `pair.invite`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairInviteResult {
    /// The invitation.
    pub invitation_id: InvitationId,
    /// When the invitation expires, in UTC milliseconds. The host's own monotonic deadline is the
    /// authoritative one; this is the same five minutes on the wall clock.
    pub expires_at_ms: TimestampMs,
    /// How to offer it.
    pub entry: InviteEntry,
}

/// Exactly what the owner approves, by mode.
///
/// The host reports this once the candidate has bound its transcript to its live endpoint, and
/// `pair.confirm` names it back. An approval that named less would not say which candidate the
/// owner was shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PairingApproval {
    /// A short-code candidate: the transcript both devices confirmed and both bundle hashes.
    Code {
        /// `T`.
        transcript: Digest256,
        /// The host bundle's hash.
        host_bundle_hash: Digest256,
        /// The candidate bundle's hash.
        client_bundle_hash: Digest256,
    },
    /// A direct candidate: the digest of `D` and of its complete key bundle.
    Direct {
        /// The digest of `D`.
        transcript_digest: Digest256,
        /// The digest of the candidate's complete key bundle.
        client_key_digest: Digest256,
    },
}

/// The parameters of `pair.confirm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairConfirmParams {
    /// The invitation.
    pub invitation_id: InvitationId,
    /// Exactly what the owner approves.
    pub approval: PairingApproval,
}

/// The result of `pair.confirm`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairConfirmResult {
    /// The device the host created.
    pub device_id: DeviceId,
    /// The grant it issued.
    pub grant_id: GrantId,
    /// The security event this pairing wrote.
    pub event: PairingSecurityEvent,
}

/// The parameters of `pair.cancel`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairCancelParams {
    /// The invitation.
    pub invitation_id: InvitationId,
    /// True when the owner is refusing the candidate it was shown, rather than withdrawing the
    /// invitation. Both consume the invitation without a grant; the reason is recorded.
    pub deny: bool,
}

/// The candidate the issuing owner is shown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairCandidateView {
    /// What the candidate calls itself. Display text, never authority.
    pub device_name: DeviceName,
    /// What it says it runs on. Display text, never authority.
    pub platform: DevicePlatform,
    /// Its complete purpose-key bundle, which the grant will be bound to.
    pub keys: DevicePublicKeys,
    /// The eight hexadecimal characters both devices display.
    pub verification_value: String,
}

/// What the issuing owner sees of its own invitation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairOwnerView {
    /// How it is offered.
    pub mode: InviteModeKind,
    /// The rendezvous origin, for a code invitation.
    pub rendezvous_origin: Nullable<RendezvousOrigin>,
    /// Failed confirmations the invitation still allows.
    pub remaining_confirmations: u32,
    /// Which rules the proposed grant was checked against.
    pub grant_kind: InviteGrantKind,
    /// The complete proposed grant.
    pub proposed_grant: ProposedGrant,
    /// The candidate awaiting approval, once it has bound its transcript to its endpoint.
    pub candidate: Nullable<PairCandidateView>,
    /// Exactly what `pair.confirm` names, once there is a candidate to approve.
    pub approval: Nullable<PairingApproval>,
    /// The security event, once the pairing committed.
    pub event: Nullable<PairingSecurityEvent>,
}

/// One completed pairing, as the host's retained security outbox holds it.
///
/// Rows are immutable and ordered by [`Self::sequence`], which is the outbox's stable cursor.
/// Every completed pairing writes exactly one, in the transaction that commits the device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairingSecurityEvent {
    /// The row's position in the outbox.
    pub sequence: PairingEventSequence,
    /// The invitation the device paired through.
    pub invitation_id: InvitationId,
    /// How it was offered.
    pub mode: InviteModeKind,
    /// The device the host created.
    pub device_id: DeviceId,
    /// The grant it issued.
    pub grant_id: GrantId,
    /// The rules that grant was checked against.
    pub grant_kind: InviteGrantKind,
    /// What the device calls itself. Display text, never authority.
    pub device_name: DeviceName,
    /// What it says it runs on. Display text, never authority.
    pub platform: DevicePlatform,
    /// The value both devices displayed.
    pub verification_value: String,
    /// The owner confirmation the device was accepted under.
    pub confirmation_id: ConfirmationId,
    /// How that confirmation reached the host.
    pub channel: ConfirmationChannel,
    /// The key identifier of the signer that produced it.
    pub signer_key_id: KeyId,
    /// True when this pairing established the host's first owner.
    pub first_owner: bool,
    /// When the host committed it, in UTC milliseconds.
    pub committed_at_ms: TimestampMs,
}

/// One opaque payload of a short-code exchange, as it travels through the rendezvous room.
///
/// The room checks the attempt identity and the length and forwards the bytes unread. The order is
/// section 10's: the candidate is admitted with its nonce, the host answers with its own nonce and
/// its PAKE message, the candidate sends its PAKE message and then its confirmation tag, the host
/// verifies it and answers with its own tag and its sealed bundle, and the candidate sends its
/// sealed bundle, which the host acknowledges once it has opened and verified it. Everything after
/// that is `pair.finish` over iroh, which the candidate sends only after the acknowledgement: the
/// room and the iroh path are two routes, and a finish that overtook the bundle would name a
/// transcript the host has not bound to a candidate yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RendezvousMessage {
    /// The candidate asks to be admitted under its attempt, with its fresh nonce.
    Admit {
        /// The candidate's 256-bit nonce.
        client_nonce: Nonce256,
    },
    /// The host's nonce and its SPAKE2 message, role A.
    HostPake {
        /// The host's 256-bit nonce.
        host_nonce: Nonce256,
        /// The library's message, unchanged.
        message: Bytes,
    },
    /// The candidate's SPAKE2 message, role B.
    ClientPake {
        /// The library's message, unchanged.
        message: Bytes,
    },
    /// The candidate's confirmation tag, `HMAC-SHA256(client-confirm-key, T)`.
    ClientConfirmation {
        /// The tag.
        tag: Mac256,
    },
    /// The host's confirmation tag, `HMAC-SHA256(host-confirm-key, T)`.
    HostConfirmation {
        /// The tag.
        tag: Mac256,
    },
    /// One sealed bundle message. Its direction and type are authenticated, not sent: each side
    /// knows which phase it is in.
    Bundle {
        /// Its position in the exchange.
        sequence: PairingSequence,
        /// The fresh 24-byte nonce.
        nonce: Nonce192,
        /// The XChaCha20-Poly1305 ciphertext.
        ciphertext: Bytes,
    },
    /// The host opened and verified the candidate's bundle; the candidate may finish over iroh.
    BundleAccepted,
    /// The host ends the attempt, with the stable code it would report anywhere else.
    ///
    /// An authentication failure is `PAIRING_AUTH_FAILED` and says nothing more, whether the code,
    /// the origin or the peer was wrong.
    Refused {
        /// The code.
        code: ErrorCode,
        /// Failed confirmations the invitation still allows, when the host can say.
        remaining_confirmations: Nullable<u32>,
    },
}

/// The largest encoded [`RendezvousMessage`] a host or a candidate accepts, in bytes.
///
/// The room forwards payloads of up to 64 KiB, and a bundle message is the largest thing either
/// side sends. The bound is checked before the payload is decoded.
pub const MAX_RENDEZVOUS_MESSAGE_LEN: usize = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalars::Uuid;

    #[test]
    fn qr_text_redacts_itself_and_refuses_what_is_not_base64url() {
        let text = QrText::new("abc-_XYZ019").expect("valid text");
        let rendered = format!("{text:?}");
        assert!(!rendered.contains("abc"), "{rendered}");
        assert!(QrText::new("").is_err());
        assert!(QrText::new("has space").is_err());
        assert!(QrText::new("padded==").is_err());
        assert!(QrText::new("a".repeat(MAX_QR_PAYLOAD_LEN.div_ceil(3) * 4 + 1)).is_err());
    }

    /// KR-REQ-10.05: the confirmation to issue an invitation names how it is offered, where a code
    /// is reserved, the kind of its grant and the grant itself; changing any one of them is
    /// another digest, so one approval issues exactly one kind of invitation.
    #[test]
    fn the_issuing_digest_names_the_mode_the_origin_the_kind_and_the_grant() {
        let grant = crate::pairing::ProposedGrant {
            parent_grant_id: Nullable::null(),
            environment_selector: crate::grant::EnvironmentSelector::Any,
            session_selector: crate::grant::SessionSelector::Any,
            actions: [crate::rights::ActionRight::SessionView]
                .into_iter()
                .collect(),
            history: crate::grant::HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: false,
                named_questions: crate::scalars::CanonicalSet::new(),
                named_approvals: crate::scalars::CanonicalSet::new(),
            },
            expiry: crate::grant::GrantExpiry::Never,
            organisation: Nullable::null(),
        };
        let origin = default_rendezvous_origin();
        let other_origin = RendezvousOrigin::new("https://pair.example.org").expect("an origin");
        let code = issuance_digest(
            InviteModeKind::Code,
            Some(&origin),
            InviteGrantKind::PersonalOwner,
            &grant,
        )
        .expect("a digest");
        let mut wider = grant.clone();
        wider
            .actions
            .insert(crate::rights::ActionRight::TerminalInput);
        for other in [
            issuance_digest(
                InviteModeKind::Direct,
                None,
                InviteGrantKind::PersonalOwner,
                &grant,
            ),
            issuance_digest(
                InviteModeKind::Code,
                Some(&other_origin),
                InviteGrantKind::PersonalOwner,
                &grant,
            ),
            issuance_digest(
                InviteModeKind::Code,
                Some(&origin),
                InviteGrantKind::SessionInvitation,
                &grant,
            ),
            issuance_digest(
                InviteModeKind::Code,
                Some(&origin),
                InviteGrantKind::PersonalOwner,
                &wider,
            ),
        ] {
            assert_ne!(other.expect("a digest"), code);
        }
        assert_eq!(
            issuance_digest(
                InviteModeKind::Code,
                Some(&origin),
                InviteGrantKind::PersonalOwner,
                &grant,
            )
            .expect("a digest"),
            code,
            "the same terms are the same digest"
        );
    }

    #[test]
    fn every_relayed_message_round_trips_through_the_canonical_encoding() {
        for message in [
            RendezvousMessage::Admit {
                client_nonce: Nonce256::from_bytes([1; 32]),
            },
            RendezvousMessage::HostPake {
                host_nonce: Nonce256::from_bytes([2; 32]),
                message: Bytes::new(vec![3; 33]),
            },
            RendezvousMessage::ClientPake {
                message: Bytes::new(vec![4; 33]),
            },
            RendezvousMessage::ClientConfirmation {
                tag: Mac256::from_bytes([5; 32]),
            },
            RendezvousMessage::HostConfirmation {
                tag: Mac256::from_bytes([6; 32]),
            },
            RendezvousMessage::Bundle {
                sequence: PairingSequence::new(0),
                nonce: Nonce192::from_bytes([7; 24]),
                ciphertext: Bytes::new(vec![8; 64]),
            },
            RendezvousMessage::BundleAccepted,
            RendezvousMessage::Refused {
                code: ErrorCode::PairingAuthFailed,
                remaining_confirmations: Nullable::some(4),
            },
        ] {
            let bytes = kr_cbor::to_canonical_vec(&message).expect("encodes");
            let decoded: RendezvousMessage =
                kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
            assert_eq!(decoded, message);
        }
    }

    #[test]
    fn an_approval_names_every_digest_of_its_mode() {
        let approval = PairConfirmParams {
            invitation_id: InvitationId::new(Uuid::from_bytes([9; 16])),
            approval: PairingApproval::Code {
                transcript: Digest256::from_bytes([1; 32]),
                host_bundle_hash: Digest256::from_bytes([2; 32]),
                client_bundle_hash: Digest256::from_bytes([3; 32]),
            },
        };
        let bytes = kr_cbor::to_canonical_vec(&approval).expect("encodes");
        let decoded: PairConfirmParams =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(decoded, approval);
    }
}
