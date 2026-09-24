//! External notification destinations: the credential one of them sends with.
//!
//! Section 25 documents Slack, Discord, Telegram and email delivery beside webhooks, and each of
//! those four sends through a credential. A Slack or Discord incoming-webhook address is itself a
//! bearer secret, Telegram sends through a bot token, and email through a mail submission account.
//! A destination's endpoint is never a credential, so the credential travels on its own, once, in
//! `delivery.destination.secret.set`, and the host keeps it in its secret store under the
//! destination's identifier. No method answers with it afterwards, and no field of any answer has
//! room for it.
//!
//! [`SecretText`] is the type every part of a credential is carried in. It redacts itself in debug
//! output and clears its bytes when it is dropped, so a credential that passes through a log line or
//! a panic message by mistake says that it was there and nothing more.

use core::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize as _;

use crate::scalars::U64;

/// The longest part of a credential, in bytes.
pub const MAX_SECRET_TEXT_LEN: usize = 4096;

/// Text that is a credential or part of one.
///
/// One to [`MAX_SECRET_TEXT_LEN`] bytes with no control character. It is deliberately not `Copy`
/// and not `Display`: every read of it goes through [`Self::expose`], so each place that uses a
/// credential is one a reviewer can find.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretText(String);

impl SecretText {
    /// Wraps text after checking it.
    ///
    /// # Errors
    ///
    /// Returns the rule the text broke. The text itself is never part of the answer.
    pub fn new(text: impl Into<String>) -> Result<Self, SecretTextError> {
        let secret = Self(text.into());
        if secret.0.is_empty() || secret.0.len() > MAX_SECRET_TEXT_LEN {
            return Err(SecretTextError(
                "a credential is between 1 and 4096 bytes long",
            ));
        }
        if secret.0.chars().any(char::is_control) {
            return Err(SecretTextError(
                "a credential carries no control characters",
            ));
        }
        Ok(secret)
    }

    /// Returns the credential.
    ///
    /// The name is deliberate: every call site that reads the secret is one a reviewer can find.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretText(redacted)")
    }
}

impl Serialize for SecretText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        // The refusal names the rule and never the text, so a malformed credential is not
        // repeated back in the answer that refuses it.
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for SecretText {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SecretText".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::SecretText".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_SECRET_TEXT_LEN,
            "pattern": "^[^\\u0000-\\u001f\\u007f-\\u009f]+$",
            "description": "A credential or part of one: 1 to 4096 bytes, no control characters. \
                            The host keeps it in its secret store and never answers with it."
        })
    }
}

/// Why a credential's text was refused. It names the rule and never the text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretTextError(&'static str);

impl fmt::Display for SecretTextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for SecretTextError {}

/// How a mail submission connection is protected before anything is sent over it.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MailSecurity {
    /// TLS from the first byte, the way submission on port 465 works.
    ImplicitTls,
    /// A plain connection that is upgraded with STARTTLS before anything else is sent, the way
    /// submission on port 587 works. A server that does not offer the upgrade is not sent to.
    Starttls,
}

/// A mail submission account: the server a message is handed to and the account it is sent from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailAccount {
    /// The submission server's host name or IP address.
    pub server: String,
    /// Its port.
    pub port: U64,
    /// How the connection is protected.
    pub security: MailSecurity,
    /// The account name the server authenticates.
    pub username: SecretText,
    /// Its password.
    pub password: SecretText,
    /// The address the message is sent from.
    pub from_address: String,
}

/// The kinds of external destination that send with a credential.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DestinationSecretKind {
    /// A Slack incoming webhook.
    Slack,
    /// A Discord webhook.
    Discord,
    /// A Telegram bot.
    Telegram,
    /// A mail submission account.
    Email,
}

impl DestinationSecretKind {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Slack => "slack",
            Self::Discord => "discord",
            Self::Telegram => "telegram",
            Self::Email => "email",
        }
    }
}

impl fmt::Display for DestinationSecretKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The credential one external destination sends with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DestinationSecret {
    /// A Slack incoming webhook. Its address is the credential: whoever holds it can post to the
    /// channel it was made for.
    Slack {
        /// The webhook's address, as Slack issued it.
        webhook_url: SecretText,
    },
    /// A Discord webhook. Its address carries the webhook's token, so the address is the
    /// credential.
    Discord {
        /// The webhook's address, as Discord issued it.
        webhook_url: SecretText,
    },
    /// A Telegram bot, which sends through its token.
    Telegram {
        /// The bot's token, as Telegram issued it.
        bot_token: SecretText,
    },
    /// A mail submission account.
    Email {
        /// The account.
        account: MailAccount,
    },
}

impl DestinationSecret {
    /// Which kind of destination this credential is for.
    #[must_use]
    pub const fn kind(&self) -> DestinationSecretKind {
        match self {
            Self::Slack { .. } => DestinationSecretKind::Slack,
            Self::Discord { .. } => DestinationSecretKind::Discord,
            Self::Telegram { .. } => DestinationSecretKind::Telegram,
            Self::Email { .. } => DestinationSecretKind::Email,
        }
    }
}

/// Parameters of `delivery.destination.secret.set`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryDestinationSecretSetParams {
    /// The identifier the destination is configured under, or will be.
    pub destination_id: String,
    /// The credential it sends with.
    pub secret: DestinationSecret,
}

/// The result of `delivery.destination.secret.set`. It never carries the credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryDestinationSecretSetResult {
    /// The identifier the credential is kept under.
    pub destination_id: String,
    /// Which kind of destination the credential is for.
    pub kind: DestinationSecretKind,
    /// Whether a destination of this kind is configured under the identifier now, and so sends
    /// with this credential from here on.
    ///
    /// Notifications admitted while the destination sent with the credential this one replaced
    /// are not sent with this one: they were admitted for wherever that credential reached.
    pub in_force: bool,
    /// Who can read what this destination delivers, in a sentence a person is shown.
    ///
    /// Section 25: the recipients of an external destination read what it delivers, and
    /// KalaReach's encrypted routing does not make those messages private.
    pub recipients_can_read: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_is_redacted_in_debug_output() {
        let secret = DestinationSecret::Telegram {
            bot_token: SecretText::new("123456:very-secret-token").expect("a token"),
        };
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("very-secret-token"), "{rendered}");
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn a_refused_credential_is_not_repeated_in_the_refusal() {
        let refused = SecretText::new("secret\npart").expect_err("a control character");
        assert!(!refused.to_string().contains("secret"));
        let refused = serde_json::from_str::<SecretText>("\"\"").expect_err("empty");
        assert!(refused.to_string().contains("between 1 and 4096"));
        let long = format!("\"{}\"", "x".repeat(MAX_SECRET_TEXT_LEN + 1));
        let refused = serde_json::from_str::<SecretText>(&long).expect_err("too long");
        assert!(!refused.to_string().contains("xxxx"));
    }

    #[test]
    fn a_credential_names_its_kind_on_the_wire() {
        let secret = DestinationSecret::Slack {
            webhook_url: SecretText::new("https://hooks.slack.com/services/T0/B0/x")
                .expect("an address"),
        };
        let json = serde_json::to_value(&secret).expect("encodes");
        assert_eq!(json["kind"], "slack");
        assert_eq!(secret.kind(), DestinationSecretKind::Slack);
        let back: DestinationSecret = serde_json::from_value(json).expect("decodes");
        assert_eq!(back, secret);
        assert!(
            serde_json::from_value::<DestinationSecret>(serde_json::json!({
                "kind": "slack",
                "bot_token": "123:abc"
            }))
            .is_err(),
            "a field of another kind is refused"
        );
    }
}
