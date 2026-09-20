//! Where a notification goes, and what has to be true before content may leave for it.
//!
//! Two kinds, and the difference between them is not a detail of transport. A **push**
//! destination is a paired device: the preview is sealed to a key only that device holds, and the
//! gateway and the provider forward bytes they cannot read. An **external** destination is a
//! webhook, Slack, email, Discord or Telegram: the service and its recipients read what arrives.
//! Section 19 says so in one sentence, that external delivery sends content to the named service
//! and its recipients and cannot inherit a claim that only encrypted KalaReach endpoints can read
//! it, and this module is built so that the sentence cannot be forgotten: every external message
//! carries it, and there is no constructor that omits it.
//!
//! Both kinds need the same two things before anything leaves, and section 25 names them
//! together: a **configured destination** and an **explicit rule or grant**. They are separate
//! fields here because they are separate facts. Configuring where to send is not a decision about
//! what may be sent, and an installation that conflated them would treat the act of writing down
//! an address as authority over session content.

use std::fmt;

use kr_protocol::ids::{GrantId, InstallationId, PushSenderRecordId};
use kr_protocol::scalars::{NotificationPreviewKey, StoredEnvelopeKey, TimestampMs};

use crate::error::{DeliveryError, Result};

/// The longest a destination identifier may be, in bytes.
pub const MAX_DESTINATION_ID_LEN: usize = 128;

/// One configured destination, as this environment names it.
///
/// It is chosen by whoever configured the destination, so it is bounded and printable and nothing
/// else: this crate compares it and derives nothing from it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DestinationId(String);

impl DestinationId {
    /// Builds a destination identifier.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::NoDestination`] when the value is empty, longer than
    /// [`MAX_DESTINATION_ID_LEN`] or carries a control character.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_DESTINATION_ID_LEN
            || value.chars().any(char::is_control)
        {
            return Err(DeliveryError::NoDestination(
                "a destination identifier is 1 to 128 printable bytes".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    /// Returns the identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DestinationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Which kind of destination a record is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DestinationKind {
    /// A paired device, reached through the push gateway.
    Push,
    /// An HTTP endpoint the owner configured.
    Webhook,
    /// A Slack channel or conversation.
    Slack,
    /// An email recipient.
    Email,
    /// A Discord channel.
    Discord,
    /// A Telegram chat.
    Telegram,
}

impl DestinationKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::Push,
        Self::Webhook,
        Self::Slack,
        Self::Email,
        Self::Discord,
        Self::Telegram,
    ];

    /// The five external kinds section 25 documents.
    pub const EXTERNAL: [Self; 5] = [
        Self::Webhook,
        Self::Slack,
        Self::Email,
        Self::Discord,
        Self::Telegram,
    ];

    /// Returns the stable name this kind is stored and reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Webhook => "webhook",
            Self::Slack => "slack",
            Self::Email => "email",
            Self::Discord => "discord",
            Self::Telegram => "telegram",
        }
    }

    /// Reads a stored name back.
    #[must_use]
    pub fn from_stored(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }

    /// Returns true when the recipients of this kind read the content that arrives.
    ///
    /// Every kind but push. It is a property of the destination rather than of the message, so it
    /// is answered here and carried into the message rather than decided at each call site.
    #[must_use]
    pub const fn recipients_read_the_content(self) -> bool {
        !matches!(self, Self::Push)
    }
}

impl fmt::Display for DestinationKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The destination's `notification_preview` key, and the one rotation keeps for a while.
///
/// Section 16 registers this key through the paired device's authenticated channel with purpose
/// `notification_preview` and a revision, and uses it for preview envelopes **only**: not for a
/// mailbox record, not for an archive key wrap, not for a recovery bundle. The type is
/// [`NotificationPreviewKey`], which is a different type from a stored-envelope key, so the
/// compiler refuses the mistake rather than a reviewer catching it.
///
/// Rotation keeps the previous key until the notifications that were sealed to it have expired,
/// and no longer: `retired_until_ms` is that instant, and a key past it is dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewKeys {
    /// The key in force.
    pub current: NotificationPreviewKey,
    /// Its revision, as the paired device declared it.
    pub revision: u64,
    /// The key rotation replaced, kept only while notifications sealed to it can still arrive.
    pub previous: Option<RetiredPreviewKey>,
}

/// A preview key rotation replaced, and when it stops being kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetiredPreviewKey {
    /// The key.
    pub key: NotificationPreviewKey,
    /// Its revision.
    pub revision: u64,
    /// The last outstanding notification's expiry. Past this the key is dropped.
    pub retired_until_ms: TimestampMs,
}

impl PreviewKeys {
    /// Builds a key ring holding one key and no retired one.
    #[must_use]
    pub const fn only(current: NotificationPreviewKey, revision: u64) -> Self {
        Self {
            current,
            revision,
            previous: None,
        }
    }

    /// Rotates to a new key, keeping the old one until `outstanding_until_ms`.
    ///
    /// The bound is the caller's: it is the furthest expiry among the notifications already sealed
    /// to the key being replaced. A rotation with nothing outstanding keeps nothing, which is the
    /// ordinary case and the one that leaves the least behind.
    ///
    /// Section 16 keeps **a** previous key, singular, so a second rotation while the first
    /// replacement still has notifications outstanding keeps the key being replaced now and drops
    /// the older one. The deadline is the later of the two, because the older key's outstanding
    /// notifications are the ones that would otherwise be unopenable, and the newer key is the one
    /// a device has just stopped using. Dropping the older key is what makes *bounded* mean one.
    #[must_use]
    pub fn rotated(
        &self,
        current: NotificationPreviewKey,
        revision: u64,
        outstanding_until_ms: Option<TimestampMs>,
    ) -> Self {
        let carried = self
            .previous
            .as_ref()
            .map(|previous| previous.retired_until_ms);
        let retired_until_ms = match (outstanding_until_ms, carried) {
            (Some(now), Some(before)) => Some(TimestampMs::new(now.get().max(before.get()))),
            (Some(now), None) => Some(now),
            (None, _) => None,
        };
        Self {
            current,
            revision,
            previous: retired_until_ms.map(|retired_until_ms| RetiredPreviewKey {
                key: self.current,
                revision: self.revision,
                retired_until_ms,
            }),
        }
    }

    /// Drops a retired key whose outstanding notifications have all expired.
    pub fn forget_expired(&mut self, now_ms: u64) {
        if self
            .previous
            .as_ref()
            .is_some_and(|previous| now_ms >= previous.retired_until_ms.get())
        {
            self.previous = None;
        }
    }

    /// Returns the retired key, when one is still being kept at `now_ms`.
    #[must_use]
    pub fn retained_previous(&self, now_ms: u64) -> Option<&RetiredPreviewKey> {
        self.previous
            .as_ref()
            .filter(|previous| now_ms < previous.retired_until_ms.get())
    }
}

/// A paired device this host may send notifications to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushDestination {
    /// The installation the gateway knows the device by.
    pub installation_id: InstallationId,
    /// The authorisation this host delivers under.
    pub sender_record_id: PushSenderRecordId,
    /// The device's preview keys.
    pub preview_keys: PreviewKeys,
    /// Whether the device wants previews at all.
    ///
    /// Section 16: disabling previews removes the recipient key from future notifications while
    /// the generic alert remains. It is not a field a producer may override, and the producer asks
    /// this rather than deciding for itself.
    pub previews_enabled: bool,
    /// The device's stored-envelope key, which an encrypted object is sealed to.
    ///
    /// Section 16 moves the excess detail of a preview that does not fit into a referenced
    /// encrypted object, and an encrypted object for a device is a mailbox object: it is sealed to
    /// the stored-envelope key, never to the preview key, because the preview key is for preview
    /// envelopes only. A destination with no stored-envelope key has nowhere to move the excess
    /// to, so an oversized notification for it is refused rather than trimmed.
    pub mailbox_key: Option<StoredEnvelopeKey>,
}

/// How a destination lets a sender name a delivery so that a repeat is not a second message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Idempotency {
    /// The destination accepts a delivery identifier and ignores a repeat of one it has seen.
    ///
    /// The field name is the destination's own: a webhook header, a Slack client message
    /// identifier, an email `Message-ID`. It is carried rather than assumed because the five
    /// services do not agree on one.
    Supported {
        /// What the destination calls the identifier it deduplicates by.
        field: String,
    },
    /// The destination has no such identifier.
    ///
    /// Section 25 then forbids the retry rather than allowing a guess: a repeat may be a second
    /// message to a human being, and *marked duplicate-delivery uncertainty* is the honest answer
    /// to a send whose outcome is unknown.
    Unsupported,
}

impl Idempotency {
    /// Returns true when a repeat of one delivery identifier is not a second message.
    #[must_use]
    pub const fn supports_retry(&self) -> bool {
        matches!(self, Self::Supported { .. })
    }
}

/// The explicit rule or grant that admits content to one destination.
///
/// Section 25 requires it before anything is sent, and section 19's external rule means the check
/// cannot stop at the destination's own configuration: the content policy is intersected with the
/// recipient's own authority, which is the grant. So both are here, and a record that names a
/// grant is checked against that grant rather than against the fact that somebody configured an
/// address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryRule {
    /// The rule's own name, as the person who wrote it named it.
    pub name: String,
    /// The grant whose authority the content is intersected with.
    ///
    /// `None` is a rule with no grant behind it, which admits nothing that carries session
    /// content: the producer refuses rather than falling back to the destination's configuration.
    pub grant_id: Option<GrantId>,
}

/// A service or address outside KalaReach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalDestination {
    /// Which service.
    pub kind: DestinationKind,
    /// The opaque reference the adapter resolves.
    ///
    /// It is never a credential. A token, a webhook secret or a password belongs in the host's
    /// secret store and is fetched by the adapter that sends; storing one here would put it in
    /// this journal, in its backups and in anything that reads a destination record.
    pub endpoint: String,
    /// Whether the destination deduplicates by a delivery identifier this host can choose.
    pub idempotency: Idempotency,
}

/// What a destination record holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    /// A paired device, through the push gateway.
    Push(Box<PushDestination>),
    /// A service outside KalaReach.
    External(ExternalDestination),
}

impl Destination {
    /// Which kind this is.
    #[must_use]
    pub const fn kind(&self) -> DestinationKind {
        match self {
            Self::Push(_) => DestinationKind::Push,
            Self::External(external) => external.kind,
        }
    }
}

/// One configured destination, with the rule that admits content to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationRecord {
    /// What this environment calls it.
    pub id: DestinationId,
    /// Where it goes.
    pub destination: Destination,
    /// The explicit rule or grant, when one has been written.
    pub rule: Option<DeliveryRule>,
    /// Whether the destination is in service.
    pub enabled: bool,
    /// When it was configured, in UTC milliseconds.
    pub configured_at_ms: TimestampMs,
}

impl DestinationRecord {
    /// A digest of everything about this destination that decides where content goes.
    ///
    /// It is bound to every notification admitted for the destination and compared again when the
    /// notification is claimed. Section 25 needs a configured destination *and* an explicit rule
    /// before content leaves, and both can change after a notification has been built: an endpoint
    /// edited to another address would otherwise receive content authorised for the first one, and
    /// a rule removed after admission would not stop the send it authorised. A digest rather than
    /// a counter, so the binding changes exactly when the destination does and survives a restart
    /// without anything having to remember a number.
    ///
    /// `configured_at_ms` is left out: re-writing an unchanged record is not a change of
    /// destination.
    ///
    /// The notification-preview keys are left out too, and that is the point of section 16's
    /// retention: a rotation keeps the previous key until the notifications sealed to it expire,
    /// so those notifications are still the device's to read and still go where they were
    /// admitted to go. A key says what the recipient can read, not who the recipient is. Binding
    /// to it would revoke every outstanding notification the moment the device rotated, and would
    /// revoke them a second time when the retained key was forgotten. What previews are allowed to
    /// carry at all is a policy rather than a key, so `previews_enabled` stays.
    #[must_use]
    pub fn binding_digest(&self) -> String {
        let mut input = String::new();
        // Every field is written with its own length in front of it, so no value can spell out
        // the separator and the field after it. An endpoint and an idempotency header are both
        // text somebody configured, and without the lengths one destination could be written to
        // look exactly like another.
        let mut field = |value: &str| {
            use std::fmt::Write as _;
            let _ = write!(input, "{}:{value};", value.len());
        };
        field(self.id.as_str());
        field(if self.enabled { "enabled" } else { "disabled" });
        match &self.rule {
            Some(rule) => {
                field("rule");
                field(&rule.name);
                match rule.grant_id {
                    Some(grant) => field(&grant.to_string()),
                    None => field("-"),
                }
            }
            None => field("no rule"),
        }
        match &self.destination {
            Destination::Push(push) => {
                field("push");
                field(&push.installation_id.to_string());
                field(&push.sender_record_id.to_string());
                field(if push.previews_enabled {
                    "previews"
                } else {
                    "no previews"
                });
                field(
                    &push
                        .mailbox_key
                        .as_ref()
                        .map_or_else(|| "-".to_owned(), |key| hex(key.as_bytes())),
                );
            }
            Destination::External(external) => {
                field("external");
                field(external.kind.as_str());
                field(&external.endpoint);
                match &external.idempotency {
                    Idempotency::Supported { field: header } => field(header),
                    Idempotency::Unsupported => field("-"),
                }
            }
        }
        hex(&kr_cbor::sha256(input.as_bytes()))
    }

    /// Returns the rule, or the refusal section 25 requires when there is none.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::NotAuthorised`] when no rule has been written for this
    /// destination.
    pub fn require_rule(&self) -> Result<&DeliveryRule> {
        self.rule
            .as_ref()
            .ok_or_else(|| DeliveryError::NotAuthorised(self.id.to_string()))
    }

    /// Returns the push destination, when this is one.
    #[must_use]
    pub fn as_push(&self) -> Option<&PushDestination> {
        match &self.destination {
            Destination::Push(push) => Some(push),
            Destination::External(_) => None,
        }
    }

    /// Returns the external destination, when this is one.
    #[must_use]
    pub const fn as_external(&self) -> Option<&ExternalDestination> {
        match &self.destination {
            Destination::External(external) => Some(external),
            Destination::Push(_) => None,
        }
    }
}

/// Renders bytes as lowercase hexadecimal, for a digest input that has to be unambiguous.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> NotificationPreviewKey {
        NotificationPreviewKey::from_bytes([byte; 32])
    }

    #[test]
    fn a_destination_identifier_is_bounded_and_printable() {
        assert!(DestinationId::new("desk-phone").is_ok());
        assert!(DestinationId::new("").is_err());
        assert!(DestinationId::new("a\u{7}b").is_err());
        assert!(DestinationId::new("x".repeat(MAX_DESTINATION_ID_LEN + 1)).is_err());
    }

    #[test]
    fn every_kind_but_push_has_recipients_that_read_the_content() {
        assert!(!DestinationKind::Push.recipients_read_the_content());
        for kind in DestinationKind::EXTERNAL {
            assert!(
                kind.recipients_read_the_content(),
                "{kind} delivers to recipients that read it"
            );
        }
    }

    #[test]
    fn a_rotation_with_nothing_outstanding_keeps_no_previous_key() {
        let keys = PreviewKeys::only(key(1), 1);
        let rotated = keys.rotated(key(2), 2, None);
        assert_eq!(rotated.current, key(2));
        assert_eq!(rotated.previous, None);
    }

    #[test]
    fn a_retired_preview_key_is_kept_only_until_outstanding_expiry() {
        let keys = PreviewKeys::only(key(1), 1);
        let mut rotated = keys.rotated(key(2), 2, Some(TimestampMs::new(5_000)));
        assert_eq!(
            rotated
                .retained_previous(4_999)
                .map(|previous| previous.key),
            Some(key(1))
        );
        assert_eq!(rotated.retained_previous(5_000), None);
        rotated.forget_expired(5_000);
        assert_eq!(
            rotated.previous, None,
            "the key is dropped, not just hidden"
        );
    }

    #[test]
    fn a_second_rotation_keeps_one_previous_key_and_the_later_deadline() {
        let first = PreviewKeys::only(key(1), 1);
        let second = first.rotated(key(2), 2, Some(TimestampMs::new(5_000)));
        let third = second.rotated(key(3), 3, Some(TimestampMs::new(3_000)));
        let previous = third.previous.as_ref().expect("one previous key");
        assert_eq!(
            previous.key,
            key(2),
            "the key being replaced now is the one kept"
        );
        assert_eq!(
            previous.retired_until_ms.get(),
            5_000,
            "the later of the two deadlines, because the older key's notifications outlast it"
        );
        assert_eq!(
            third.retained_previous(5_000),
            None,
            "and it is still bounded"
        );
    }

    fn push_record(keys: PreviewKeys) -> DestinationRecord {
        DestinationRecord {
            id: DestinationId::new("desk-phone").expect("an identifier"),
            destination: Destination::Push(Box::new(PushDestination {
                installation_id: InstallationId::new(kr_protocol::scalars::Uuid::from_bytes(
                    [7_u8; 16],
                )),
                sender_record_id: PushSenderRecordId::new(kr_protocol::scalars::Uuid::from_bytes(
                    [9_u8; 16],
                )),
                preview_keys: keys,
                previews_enabled: true,
                mailbox_key: None,
            })),
            rule: Some(DeliveryRule {
                name: "mentions".to_owned(),
                grant_id: None,
            }),
            enabled: true,
            configured_at_ms: TimestampMs::new(1),
        }
    }

    #[test]
    fn rotating_and_forgetting_a_preview_key_leaves_the_dispatch_binding_alone() {
        let rotated =
            PreviewKeys::only(key(1), 1).rotated(key(2), 2, Some(TimestampMs::new(5_000)));
        let mut forgotten = rotated.clone();
        forgotten.forget_expired(5_000);
        let before = push_record(PreviewKeys::only(key(1), 1)).binding_digest();
        assert_eq!(
            push_record(rotated).binding_digest(),
            before,
            "a device that rotated its preview key is the same device, and section 16 keeps the \
             replaced key so the notifications sealed to it still arrive"
        );
        assert_eq!(
            push_record(forgotten).binding_digest(),
            before,
            "and forgetting the retired key is housekeeping, not a change of recipient"
        );
    }

    #[test]
    fn what_decides_where_a_notification_goes_changes_the_binding() {
        let keys = PreviewKeys::only(key(1), 1);
        let before = push_record(keys.clone()).binding_digest();
        let mut disabled = push_record(keys.clone());
        disabled.enabled = false;
        assert_ne!(disabled.binding_digest(), before);
        let mut unruled = push_record(keys.clone());
        unruled.rule = None;
        assert_ne!(unruled.binding_digest(), before);
        let mut elsewhere = push_record(keys);
        if let Destination::Push(push) = &mut elsewhere.destination {
            push.installation_id =
                InstallationId::new(kr_protocol::scalars::Uuid::from_bytes([8_u8; 16]));
        }
        assert_ne!(
            elsewhere.binding_digest(),
            before,
            "another installation is another device"
        );
    }

    /// Two destinations somebody could configure, whose fields spell each other out when they are
    /// run together. The binding has to tell them apart, because one of them is another address.
    #[test]
    fn two_destinations_that_read_alike_do_not_share_a_binding() {
        let hook = |endpoint: &str, header: &str| DestinationRecord {
            id: DestinationId::new("hook").expect("an identifier"),
            destination: Destination::External(ExternalDestination {
                kind: DestinationKind::Webhook,
                endpoint: endpoint.to_owned(),
                idempotency: Idempotency::Supported {
                    field: header.to_owned(),
                },
            }),
            rule: Some(DeliveryRule {
                name: "on failure".to_owned(),
                grant_id: None,
            }),
            enabled: true,
            configured_at_ms: TimestampMs::new(1),
        };
        assert_ne!(
            hook("https://example.invalid/hook", "x;idempotency=y").binding_digest(),
            hook("https://example.invalid/hook;idempotency=x", "y").binding_digest(),
            "the second is another address, and a claim has to refuse it"
        );
    }

    #[test]
    fn a_destination_with_no_rule_admits_nothing() {
        let record = DestinationRecord {
            id: DestinationId::new("hook").expect("an identifier"),
            destination: Destination::External(ExternalDestination {
                kind: DestinationKind::Webhook,
                endpoint: "https://example.invalid/hook".to_owned(),
                idempotency: Idempotency::Unsupported,
            }),
            rule: None,
            enabled: true,
            configured_at_ms: TimestampMs::new(1),
        };
        assert!(
            matches!(record.require_rule(), Err(DeliveryError::NotAuthorised(name)) if name == "hook"),
            "configuring an address is not authority over content"
        );
    }
}
