//! What can go wrong on a KalaReach connection.

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::FrameError;

/// A transport failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The configuration names a service the endpoint cannot be built from.
    #[error("{what} is not a usable {kind}: {reason}")]
    Configuration {
        /// The configured value.
        what: String,
        /// What it was meant to be.
        kind: &'static str,
        /// Why it was refused.
        reason: String,
    },
    /// The endpoint could not be bound.
    #[error("the iroh endpoint could not be bound: {0}")]
    Bind(String),
    /// A connection could not be established.
    ///
    /// That includes a relay the network would not let this endpoint upgrade to, which the message
    /// names with the HTTP status the upgrade was refused with. The relay itself never answered, so
    /// that is not a [`Self::RelayRefused`].
    #[error("the connection could not be established: {0}")]
    Connect(String),
    /// A relay on the route had turned this endpoint away when the attempt to reach the peer timed
    /// out without a connection, or when it had nothing but refusing relays to try.
    ///
    /// Section 17: an exhausted bootstrap route is reported as what it is, with what may still
    /// work, and never as a peer that went away.
    #[error("{0}")]
    RelayRefused(RelayRefusal),
    /// A stream could not be opened or accepted.
    #[error("the stream failed: {0}")]
    Stream(String),
    /// The peer closed the connection.
    #[error("the peer closed the connection: {0}")]
    Closed(String),
    /// A frame was malformed or exceeded its stream kind's bound.
    #[error("the frame was refused: {0}")]
    Frame(#[from] FrameError),
    /// A value could not be encoded or decoded as KR-CBOR-1.
    #[error("the message was not canonical: {0}")]
    Cbor(#[from] kr_cbor::CborError),
    /// The handshake failed. The peer receives the protocol error; this side keeps the detail.
    #[error("the handshake failed: {0}")]
    Handshake(ProtocolError),
    /// A cryptographic check failed.
    #[error("the connection proof failed: {0}")]
    Crypto(#[from] kr_crypto::CryptoError),
    /// The peer did not answer inside the inactivity threshold.
    #[error("the peer was silent for longer than the inactivity threshold")]
    Inactive,
    /// A limit this connection agreed to was exceeded.
    #[error("{what} exceeds its limit of {limit}")]
    LimitExceeded {
        /// The limit that was hit.
        what: &'static str,
        /// The configured bound.
        limit: usize,
    },
    /// The control stream ended, so every stream it authorised is revoked.
    #[error("the control stream ended, revoking every associated data stream")]
    ControlLost,
}

impl TransportError {
    /// Builds the handshake failure a peer is told about.
    #[must_use]
    pub fn handshake(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Handshake(ProtocolError::new(code, message))
    }

    /// Returns the protocol error to send to the peer.
    ///
    /// Every failure maps to a stable code, so a peer never has to read a message to decide what
    /// to do. Detail that would only help an attacker stays on this side of the connection.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        match self {
            Self::Handshake(error) => error.clone(),
            Self::Configuration { .. } | Self::Bind(_) => {
                ProtocolError::new(ErrorCode::HostNotConfigured, "the host is not configured")
            }
            Self::Connect(_) | Self::Closed(_) | Self::Stream(_) | Self::ControlLost => {
                ProtocolError::new(ErrorCode::ResourceUnavailable, "the connection ended")
            }
            Self::RelayRefused(refusal) => match refusal.kind {
                RelayRefusalKind::AllowanceSpent => ProtocolError::new(
                    ErrorCode::QuotaExceeded,
                    "the relay allowance the connection needed is spent",
                ),
                RelayRefusalKind::Stopping => ProtocolError::new(
                    ErrorCode::ServiceCapacity,
                    "a relay the connection needed is stopping",
                ),
                // A refusal this build cannot classify says nothing about when it ends, so it is
                // the code of any other connection that could not be established.
                RelayRefusalKind::Unknown => {
                    ProtocolError::new(ErrorCode::ResourceUnavailable, "the connection ended")
                }
            },
            Self::Frame(error) => ProtocolError::new(error.code(), "the message was refused"),
            Self::Cbor(error) => ProtocolError::new(
                kr_protocol::wire::refusal_code(error),
                "the message was refused",
            ),
            Self::Crypto(_) => ProtocolError::new(
                ErrorCode::PermissionDenied,
                "the connection proof was refused",
            ),
            Self::Inactive => ProtocolError::new(
                ErrorCode::ResourceUnavailable,
                "the transport is unavailable",
            ),
            Self::LimitExceeded { .. } => {
                ProtocolError::new(ErrorCode::ResourceUnavailable, "a connection limit was hit")
            }
        }
    }
}

/// What kind of refusal a relay gave, as the relay states it.
///
/// A KalaReach relay starts the reason it gives with a kind token, then a colon and one space,
/// then text for a person: `allowance_spent: the reserved bytes for this endpoint are spent`. The
/// token is the contract and the text is not. A reason whose start is not a token this build
/// knows is [`Self::Unknown`] and is kept whole: that is what an older relay, another operator's
/// relay and a kind added after this build all send.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RelayRefusalKind {
    /// The relay allowance this endpoint's traffic is paid from is spent, or is in its bounded
    /// grace, so the relay opens no new session for it until the allowance changes.
    AllowanceSpent,
    /// The relay is stopping and admits nothing new. Another relay, or the same one once it is
    /// back, can admit the endpoint.
    Stopping,
    /// The reason carries no kind this build knows.
    Unknown,
}

impl RelayRefusalKind {
    /// Every kind a relay can name, with the token it names it by.
    const TOKENS: [(Self, &'static str); 2] = [
        (Self::AllowanceSpent, "allowance_spent"),
        (Self::Stopping, "stopping"),
    ];

    /// Returns the token a relay starts its reason with for this kind, or `None` for
    /// [`Self::Unknown`], which has none.
    #[must_use]
    pub fn token(self) -> Option<&'static str> {
        Self::TOKENS
            .iter()
            .find(|(kind, _)| *kind == self)
            .map(|(_, token)| *token)
    }

    /// Splits a relay's reason into its kind and the text for a person.
    ///
    /// The text is what follows the token and its separator. A reason with no token this build
    /// knows is returned whole as the text of [`Self::Unknown`].
    #[must_use]
    pub fn parse(reason: &str) -> (Self, &str) {
        reason
            .split_once(": ")
            .and_then(|(token, text)| {
                Self::TOKENS
                    .iter()
                    .find(|(_, known)| *known == token)
                    .map(|(kind, _)| (*kind, text))
            })
            .unwrap_or((Self::Unknown, reason))
    }
}

/// Something that may still reach a peer when a relay turned this endpoint away.
///
/// Section 17: new connectivity may need valid protected address hints, local network discovery
/// the person selects, another configured relay or a restored allowance. These are kinds of path,
/// not addresses: which of them a person can use depends on configuration this error does not
/// carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RouteAlternative {
    /// A direct path to the peer's current addresses, as the protected pairing exchange or an
    /// authenticated update gives them.
    AddressHints,
    /// Local network discovery, which the person selects.
    LocalDiscovery,
    /// Another relay, configured on both sides.
    AnotherRelay,
    /// The relay allowance, restored.
    RestoredAllowance,
}

impl RouteAlternative {
    /// Returns what may still work after a refusal of `kind`, for an endpoint that has a direct
    /// transport of its own when `direct` is true.
    ///
    /// A relay-only endpoint has no socket to take a direct path from, so the two direct
    /// alternatives are not offered to it. A restored allowance is offered only when the relay
    /// said the allowance is what it refused for.
    #[must_use]
    pub fn after(kind: RelayRefusalKind, direct: bool) -> Vec<Self> {
        let mut alternatives = Vec::with_capacity(4);
        if direct {
            alternatives.extend([Self::AddressHints, Self::LocalDiscovery]);
        }
        alternatives.push(Self::AnotherRelay);
        if kind == RelayRefusalKind::AllowanceSpent {
            alternatives.push(Self::RestoredAllowance);
        }
        alternatives
    }

    /// Returns the alternative in words, as the refusal's message names it.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::AddressHints => {
                "the peer's current direct addresses from pairing or an authenticated update"
            }
            Self::LocalDiscovery => "local network discovery the person selects",
            Self::AnotherRelay => "another configured relay",
            Self::RestoredAllowance => "a restored relay allowance",
        }
    }
}

/// A relay on a connection's route turned this endpoint away.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayRefusal {
    /// The relay that refused.
    pub relay: iroh::RelayUrl,
    /// The kind of refusal, from the token the relay's reason started with.
    pub kind: RelayRefusalKind,
    /// What the relay said, for a person: the text after its token, or the whole reason when it
    /// carried no token this build knows.
    pub reason: String,
    /// What may still reach the peer, in the order a person would try them.
    pub alternatives: Vec<RouteAlternative>,
}

impl RelayRefusal {
    /// Builds the refusal of `relay` from the reason it gave, for an endpoint that has a direct
    /// transport of its own when `direct` is true.
    #[must_use]
    pub fn from_reason(relay: iroh::RelayUrl, reason: &str, direct: bool) -> Self {
        let (kind, text) = RelayRefusalKind::parse(reason);
        Self {
            relay,
            kind,
            reason: text.to_owned(),
            alternatives: RouteAlternative::after(kind, direct),
        }
    }
}

impl std::fmt::Display for RelayRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let because = match self.kind {
            RelayRefusalKind::AllowanceSpent => " because the relay allowance is spent",
            RelayRefusalKind::Stopping => " because it is stopping",
            RelayRefusalKind::Unknown => "",
        };
        write!(
            formatter,
            "the relay {} refused this endpoint{because}: {}",
            self.relay, self.reason
        )?;
        let mut alternatives = self
            .alternatives
            .iter()
            .map(|alternative| alternative.describe());
        if let Some(first) = alternatives.next() {
            write!(formatter, "; a new connection may need {first}")?;
            let rest: Vec<&str> = alternatives.collect();
            if let Some((last, middle)) = rest.split_last() {
                for alternative in middle {
                    write!(formatter, ", {alternative}")?;
                }
                write!(formatter, " or {last}")?;
            }
        }
        Ok(())
    }
}

/// The result of a transport operation.
pub type Result<T> = std::result::Result<T, TransportError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn relay() -> iroh::RelayUrl {
        "https://relay-1.reach.kala.to"
            .parse()
            .expect("a relay URL")
    }

    /// KR-REQ-17.40: a relay's refusal is classified by the token its reason starts with and by
    /// nothing else. Each kind a relay names is read with the text after it, and a reason with no
    /// known token, whatever its words, is kept whole as a refusal of no known kind.
    #[test]
    fn a_refusal_is_classified_by_its_token_alone() {
        assert_eq!(
            RelayRefusalKind::parse(
                "allowance_spent: the reserved bytes for this endpoint are spent; 5000 ms of grace \
                 remain for connections already open"
            ),
            (
                RelayRefusalKind::AllowanceSpent,
                "the reserved bytes for this endpoint are spent; 5000 ms of grace remain for \
                 connections already open"
            )
        );
        assert_eq!(
            RelayRefusalKind::parse("stopping: this relay is stopping"),
            (RelayRefusalKind::Stopping, "this relay is stopping")
        );
        for unknown in [
            // What a relay deployed before the tokens says, and what another operator's relay says
            // when its access policy turns an endpoint away.
            "the reserved bytes for this endpoint are spent; 0 ms of grace remain",
            "not authorized",
            // A token this build does not know, which a later relay may add.
            "maintenance: back soon",
            // A known token without its separator, in the wrong case, after other text, or
            // separated by anything but a colon and one space.
            "stopping",
            "Stopping: this relay is stopping",
            "relay stopping: soon",
            "allowance_spent:spent",
            "allowance_spent : spent",
            "",
        ] {
            assert_eq!(
                RelayRefusalKind::parse(unknown),
                (RelayRefusalKind::Unknown, unknown),
                "{unknown:?} is a reason of no known kind, kept whole"
            );
        }
    }

    /// KR-REQ-17.40: every kind a relay names has one token, and the token parses back to it.
    #[test]
    fn every_kind_a_relay_names_round_trips_through_its_token() {
        for (kind, token) in RelayRefusalKind::TOKENS {
            assert_eq!(kind.token(), Some(token));
            assert_eq!(
                RelayRefusalKind::parse(&format!("{token}: some text")),
                (kind, "some text")
            );
        }
        assert_eq!(RelayRefusalKind::Unknown.token(), None);
    }

    /// KR-REQ-17.40: a spent allowance is an exhausted allowance, which no retry fixes until it
    /// changes; a stopping relay is capacity that another relay or a later attempt can supply; a
    /// refusal of no known kind is any other connection that could not be established. None of the
    /// three looks like a peer that went away.
    #[test]
    fn each_kind_of_refusal_carries_its_own_code() {
        let code = |reason: &str| {
            TransportError::RelayRefused(RelayRefusal::from_reason(relay(), reason, false))
                .to_protocol_error()
        };
        let spent = code("allowance_spent: spent");
        assert_eq!(spent.code, ErrorCode::QuotaExceeded);
        assert_eq!(
            spent.retry,
            kr_protocol::error::RetryCategory::NoRetry,
            "a spent allowance is not retried"
        );
        let stopping = code("stopping: this relay is stopping");
        assert_eq!(stopping.code, ErrorCode::ServiceCapacity);
        assert_eq!(stopping.retry, kr_protocol::error::RetryCategory::Transient);
        assert_eq!(
            code("not authorized").code,
            TransportError::Connect("timed out".to_owned())
                .to_protocol_error()
                .code,
            "a refusal of no known kind has the code of any other connection that failed"
        );
    }

    /// KR-REQ-17.40: what may still work is named by kind. A relay-only endpoint is offered no
    /// direct path, and a restored allowance is offered only for a refusal that was about the
    /// allowance.
    #[test]
    fn the_alternatives_are_the_ones_this_endpoint_and_this_refusal_leave() {
        use RouteAlternative::{AddressHints, AnotherRelay, LocalDiscovery, RestoredAllowance};
        let spent = RelayRefusalKind::AllowanceSpent;
        assert_eq!(
            RouteAlternative::after(spent, true),
            vec![
                AddressHints,
                LocalDiscovery,
                AnotherRelay,
                RestoredAllowance
            ]
        );
        assert_eq!(
            RouteAlternative::after(spent, false),
            vec![AnotherRelay, RestoredAllowance]
        );
        for other in [RelayRefusalKind::Stopping, RelayRefusalKind::Unknown] {
            assert_eq!(
                RouteAlternative::after(other, true),
                vec![AddressHints, LocalDiscovery, AnotherRelay]
            );
            assert_eq!(RouteAlternative::after(other, false), vec![AnotherRelay]);
        }
    }

    /// KR-REQ-17.40: the message names the relay, says why it refused in words, carries what the
    /// relay said, and lists what may still work.
    #[test]
    fn the_message_names_the_relay_its_reason_and_what_may_still_work() {
        let message = TransportError::RelayRefused(RelayRefusal::from_reason(
            relay(),
            "allowance_spent: the reserved bytes for this endpoint are spent",
            false,
        ))
        .to_string();
        assert_eq!(
            message,
            "the relay https://relay-1.reach.kala.to/ refused this endpoint because the relay \
             allowance is spent: the reserved bytes for this endpoint are spent; a new connection \
             may need another configured relay or a restored relay allowance"
        );
        let unknown = TransportError::RelayRefused(RelayRefusal::from_reason(
            relay(),
            "not authorized",
            true,
        ))
        .to_string();
        assert_eq!(
            unknown,
            "the relay https://relay-1.reach.kala.to/ refused this endpoint: not authorized; a new \
             connection may need the peer's current direct addresses from pairing or an \
             authenticated update, local network discovery the person selects or another \
             configured relay"
        );
    }
}
