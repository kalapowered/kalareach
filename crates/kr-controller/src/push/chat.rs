//! Slack, Discord and Telegram: three chat services, each reached by one HTTPS request.
//!
//! Each of them sends through a credential from the host's secret store. A Slack incoming webhook
//! and a Discord webhook are addresses that are themselves bearer secrets: whoever holds one can
//! post to the channel it was made for. A Telegram bot sends through its token, which the Bot API
//! takes in the request's path. So a credential is checked here for the shape its service issues,
//! and it is refused rather than kept when it has another: a Slack credential that pointed anywhere
//! but Slack's webhook host would send session content to wherever it pointed.
//!
//! # The requests
//!
//! | Service | Request | Body |
//! | --- | --- | --- |
//! | Slack | `POST` to the incoming webhook's address | `text`, with `mrkdwn`, link unfurling and media unfurling off |
//! | Discord | `POST` to the webhook's address with `?wait=true`, so a message that is not saved is an error rather than silence | `content`, with no mention allowed and link embeds suppressed |
//! | Telegram | `POST https://api.telegram.org/bot<token>/sendMessage` | `chat_id`, `text`, with link previews off and no parse mode |
//!
//! Session text reaches these services as text, never as markup: Slack's control characters are
//! escaped, Discord is told to ping nobody, and Telegram parses no entities. So a line of session
//! output cannot mention a channel, ping everyone or become a link a service fetches. A message
//! longer than its service takes is shortened before it is sent, and still ends with the sentence
//! that says who can read it.
//!
//! # Which answer is which
//!
//! | Answer | Outcome |
//! | --- | --- |
//! | A 2xx, and for Telegram `"ok": true` | Delivered |
//! | 429 | Nothing was taken: the service asked for later |
//! | Any other 4xx | Refused, and a retry cannot change that |
//! | A 5xx, a 2xx Telegram answer that is not `"ok": true`, a failure after the request left | Nobody knows |
//! | A failure before a byte was written | Nothing was sent |
//!
//! None of these services takes an identifier it would recognise a repeat by, so each is
//! configured without one, and [`kr_delivery::external::decide_external`] marks an unknown outcome
//! as duplicate-delivery uncertainty rather than sending it again. The request's address can hold
//! the credential, so a failure is reported by its class and phase and never with the transport's
//! own message, which names the address.

use std::sync::Arc;

use kr_client::services::http::ExchangePhase;
use kr_delivery::destination::{DestinationKind, ExternalDestination};
use kr_delivery::external::{ExternalMessage, ExternalOutcome, RECIPIENTS_CAN_READ};
use kr_protocol::delivery::{DestinationSecret, SecretText};
use kr_protocol::service::GatewayOrigin;
use url::Url;

use super::transport::{DeliveryTransports, nothing_was_sent};

/// The hosts Slack issues incoming webhooks on: Slack's own, and GovSlack's.
pub const SLACK_WEBHOOK_HOSTS: [&str; 2] = ["hooks.slack.com", "hooks.slack-gov.com"];

/// The hosts Discord issues webhook addresses on.
pub const DISCORD_WEBHOOK_HOSTS: [&str; 4] = [
    "discord.com",
    "discordapp.com",
    "canary.discord.com",
    "ptb.discord.com",
];

/// The longest Telegram chat username, after its `@`.
const MAX_TELEGRAM_USERNAME_LEN: usize = 32;

/// The longest name a person may give the channel a Slack or Discord webhook posts to.
pub const MAX_CHANNEL_LABEL_LEN: usize = 200;

/// Reads an address that is a credential, refusing anything but plain HTTPS to one of `hosts`.
///
/// Every refusal names the rule the address broke and never the address.
fn webhook_address(text: &str, service: &str, hosts: &[&str]) -> Result<Url, String> {
    let refused = |rule: &str| format!("a {service} webhook address {rule}");
    let address = Url::parse(text).map_err(|_| refused("is an absolute address"))?;
    if address.scheme() != "https" {
        return Err(refused("uses https"));
    }
    if !address.username().is_empty() || address.password().is_some() {
        return Err(refused("carries no user name or password"));
    }
    if address.port().is_some() {
        return Err(refused("uses the default https port"));
    }
    if address.query().is_some() || address.fragment().is_some() {
        return Err(refused("carries no query and no fragment"));
    }
    match address.host_str() {
        Some(host) if hosts.iter().any(|known| host.eq_ignore_ascii_case(known)) => Ok(address),
        _ => Err(refused(&format!("is on {}", hosts.join(" or ")))),
    }
}

/// The path segments of an address, when every one of them is present.
fn segments(address: &Url) -> Vec<&str> {
    address
        .path_segments()
        .map(Iterator::collect)
        .unwrap_or_default()
}

fn is_token_text(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Checks a Slack incoming webhook's address: `https://hooks.slack.com/services/…`, as Slack
/// issues it.
///
/// # Errors
///
/// Returns the rule the address broke, never the address.
pub fn check_slack_webhook(text: &str) -> Result<Url, String> {
    let address = webhook_address(text, "Slack", &SLACK_WEBHOOK_HOSTS)?;
    let path = segments(&address);
    match path.as_slice() {
        ["services", rest @ ..]
            if rest.len() >= 3 && rest.iter().all(|part| is_token_text(part)) =>
        {
            Ok(address)
        }
        _ => Err(
            "a Slack webhook address is the /services/ address Slack issued for one channel"
                .to_owned(),
        ),
    }
}

/// Checks a Discord webhook's address: `https://discord.com/api/webhooks/<id>/<token>`, with or
/// without an API version, as Discord issues it.
///
/// # Errors
///
/// Returns the rule the address broke, never the address.
pub fn check_discord_webhook(text: &str) -> Result<Url, String> {
    let address = webhook_address(text, "Discord", &DISCORD_WEBHOOK_HOSTS)?;
    let path = segments(&address);
    let webhook = match path.as_slice() {
        ["api", "webhooks", id, token] => Some((*id, *token)),
        ["api", version, "webhooks", id, token]
            if version.len() > 1
                && version.starts_with('v')
                && version[1..].bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            Some((*id, *token))
        }
        _ => None,
    };
    match webhook {
        Some((id, token))
            if !id.is_empty()
                && id.len() <= 20
                && id.bytes().all(|byte| byte.is_ascii_digit())
                && is_token_text(token) =>
        {
            Ok(address)
        }
        _ => Err(
            "a Discord webhook address is the /api/webhooks/<id>/<token> address Discord issued"
                .to_owned(),
        ),
    }
}

/// Checks a Telegram bot token: the bot's number, a colon, and the secret part, as `@BotFather`
/// issues it.
///
/// # Errors
///
/// Returns the rule the token broke, never the token.
pub fn check_telegram_token(text: &str) -> Result<(), String> {
    let refused = || {
        "a Telegram bot token is the bot's number, a colon and the token Telegram issued".to_owned()
    };
    let (bot, secret) = text.split_once(':').ok_or_else(refused)?;
    if bot.is_empty()
        || bot.len() > 20
        || !bot.bytes().all(|byte| byte.is_ascii_digit())
        || secret.len() < 20
        || secret.len() > 128
        || !is_token_text(secret)
    {
        return Err(refused());
    }
    Ok(())
}

/// Checks the name a person gave the channel a Slack or Discord webhook posts to.
///
/// It is the destination's endpoint, and the endpoint is never the credential: for these two
/// services the address is the credential, so what is left to name the destination by is what the
/// person calls the channel.
///
/// # Errors
///
/// Returns the rule the name broke.
pub fn check_channel_label(text: &str) -> Result<(), String> {
    if text.is_empty() || text.len() > MAX_CHANNEL_LABEL_LEN || text.chars().any(char::is_control) {
        return Err(format!(
            "the channel a webhook posts to is named in 1 to {MAX_CHANNEL_LABEL_LEN} bytes with \
             no control characters"
        ));
    }
    if text.contains("://") {
        return Err(
            "the channel a webhook posts to is named, not addressed: the webhook's address is its \
             credential and is kept in this host's secret store"
                .to_owned(),
        );
    }
    Ok(())
}

/// Checks a Telegram chat: a chat's number, or a public chat's `@username`.
///
/// # Errors
///
/// Returns the rule the chat broke.
pub fn check_telegram_chat(text: &str) -> Result<(), String> {
    let refused = || "a Telegram chat is its number or a public chat's @username".to_owned();
    if let Some(name) = text.strip_prefix('@') {
        let valid = (4..=MAX_TELEGRAM_USERNAME_LEN).contains(&name.len())
            && name
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        return if valid { Ok(()) } else { Err(refused()) };
    }
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty()
        || digits.len() > 19
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || text.parse::<i64>().is_err()
    {
        return Err(refused());
    }
    Ok(())
}

/// The origin the Telegram Bot API is served from.
pub const TELEGRAM_API: &str = "https://api.telegram.org";

/// The longest Slack message this host sends, before escaping, in UTF-16 code units: escaping can
/// make it five times longer, and Slack takes 40,000.
pub const SLACK_LIMIT: usize = 8_000;

/// The longest Discord message, in the units Discord counts.
pub const DISCORD_LIMIT: usize = 2_000;

/// The longest Telegram message, in the units Telegram counts.
pub const TELEGRAM_LIMIT: usize = 4_096;

/// Discord's message flag that stops the links in a message from being fetched and embedded.
const SUPPRESS_EMBEDS: u64 = 1 << 2;

/// The longest part of a service's own answer this host repeats.
const MAX_SERVICE_WORDS: usize = 120;

/// The chat services' adapter: one HTTPS request per attempt, through the managed transport of
/// the service's own origin.
#[derive(Clone, Debug)]
pub struct ChatSender {
    transports: Arc<dyn DeliveryTransports>,
    runtime: tokio::runtime::Handle,
}

/// One request, built and ready to send.
struct ChatRequest {
    service: &'static str,
    origin: GatewayOrigin,
    /// The address, which can hold the credential, in text that clears itself.
    url: SecretText,
    body: Vec<u8>,
}

impl ChatSender {
    /// Builds the adapter over the transports this host reaches the services through.
    #[must_use]
    pub fn new(transports: Arc<dyn DeliveryTransports>, runtime: tokio::runtime::Handle) -> Self {
        Self {
            transports,
            runtime,
        }
    }

    /// Sends one message to one Slack, Discord or Telegram destination with its credential.
    pub fn send(
        &self,
        destination: &ExternalDestination,
        secret: &DestinationSecret,
        message: &ExternalMessage,
    ) -> ExternalOutcome {
        let request = match request(destination, secret, message) {
            Ok(request) => request,
            Err(outcome) => return outcome,
        };
        let service = request.service;
        let Ok(transport) = self.transports.to(&request.origin) else {
            return ExternalOutcome::NotDispatched {
                detail: format!("no transport reaches {service}"),
            };
        };
        let answer = self.runtime.block_on(async {
            transport
                .post_json(request.url.expose(), &request.body, &[])
                .await
        });
        match answer {
            // The transport's own message names the address, and the address can be the
            // credential, so a failure is told by its class and its phase alone.
            Err(error) if nothing_was_sent(&error) => ExternalOutcome::NotDispatched {
                detail: format!("{service} could not be reached{}", phase(&error)),
            },
            Err(error) => ExternalOutcome::Unknown {
                detail: format!("{service} did not answer{}", phase(&error)),
            },
            Ok(answer) => read_answer(service, secret, answer.status, &answer.body),
        }
    }
}

/// The phase a failure happened in, as the clause that says so.
fn phase(error: &kr_client::ClientError) -> String {
    ExchangePhase::of(error).map_or_else(String::new, |phase| format!(" {}", phase.as_str()))
}

/// Builds the request one destination takes, or the outcome of a destination that cannot take one.
fn request(
    destination: &ExternalDestination,
    secret: &DestinationSecret,
    message: &ExternalMessage,
) -> Result<ChatRequest, ExternalOutcome> {
    let unsendable = |detail: String| ExternalOutcome::Unsendable { detail };
    let origin_of = |address: &Url| {
        GatewayOrigin::new(address.origin().ascii_serialization()).map_err(|_| {
            unsendable("the service's address is not one this host reaches".to_owned())
        })
    };
    let secret_url = |text: String| {
        SecretText::new(text)
            .map_err(|_| unsendable("the service's address could not be held".to_owned()))
    };
    let body = |value: serde_json::Value| {
        serde_json::to_vec(&value)
            .map_err(|_| unsendable("the message could not be encoded".to_owned()))
    };
    match (destination.kind, secret) {
        (DestinationKind::Slack, DestinationSecret::Slack { webhook_url }) => {
            let address = check_slack_webhook(webhook_url.expose()).map_err(unsendable)?;
            Ok(ChatRequest {
                service: "Slack",
                origin: origin_of(&address)?,
                url: secret_url(address.to_string())?,
                body: body(serde_json::json!({
                    "text": slack_escape(&fit(&message.body, SLACK_LIMIT, "Slack")),
                    "mrkdwn": false,
                    "unfurl_links": false,
                    "unfurl_media": false,
                }))?,
            })
        }
        (DestinationKind::Discord, DestinationSecret::Discord { webhook_url }) => {
            let mut address = check_discord_webhook(webhook_url.expose()).map_err(unsendable)?;
            // Without it Discord answers before it has saved the message, and a message it then
            // fails to save is not reported at all.
            address.set_query(Some("wait=true"));
            Ok(ChatRequest {
                service: "Discord",
                origin: origin_of(&address)?,
                url: secret_url(address.to_string())?,
                body: body(serde_json::json!({
                    "content": fit(&message.body, DISCORD_LIMIT, "Discord"),
                    "allowed_mentions": { "parse": [] },
                    "flags": SUPPRESS_EMBEDS,
                }))?,
            })
        }
        (DestinationKind::Telegram, DestinationSecret::Telegram { bot_token }) => {
            check_telegram_token(bot_token.expose()).map_err(unsendable)?;
            check_telegram_chat(&destination.endpoint).map_err(unsendable)?;
            let chat = destination.endpoint.parse::<i64>().map_or_else(
                |_| serde_json::Value::from(destination.endpoint.clone()),
                serde_json::Value::from,
            );
            Ok(ChatRequest {
                service: "Telegram",
                origin: GatewayOrigin::new(TELEGRAM_API).map_err(|_| {
                    unsendable("the Telegram Bot API is not an origin this host reaches".to_owned())
                })?,
                url: secret_url(format!(
                    "{TELEGRAM_API}/bot{}/sendMessage",
                    bot_token.expose()
                ))?,
                body: body(serde_json::json!({
                    "chat_id": chat,
                    "text": fit(&message.body, TELEGRAM_LIMIT, "Telegram"),
                    "link_preview_options": { "is_disabled": true },
                }))?,
            })
        }
        (kind, _) => Err(unsendable(format!(
            "a {kind} destination is not sent through a chat service with a {} credential",
            secret.kind()
        ))),
    }
}

/// Reads one service's answer as what it says.
fn read_answer(
    service: &'static str,
    secret: &DestinationSecret,
    status: u16,
    body: &[u8],
) -> ExternalOutcome {
    let said = service_words(service, secret, body);
    match status {
        200..=299 if service == "Telegram" => {
            let sent = serde_json::from_slice::<serde_json::Value>(body)
                .ok()
                .and_then(|value| value.get("ok").and_then(serde_json::Value::as_bool))
                == Some(true);
            if sent {
                ExternalOutcome::Delivered
            } else {
                ExternalOutcome::Unknown {
                    detail: format!(
                        "Telegram answered {status} without saying the message was sent"
                    ),
                }
            }
        }
        200..=299 => ExternalOutcome::Delivered,
        429 => ExternalOutcome::NotDispatched {
            detail: format!("{service} asked for later (429) without taking the message"),
        },
        400..=499 => ExternalOutcome::Refused {
            detail: format!("{service} answered {status}{said}"),
        },
        _ => ExternalOutcome::Unknown {
            detail: format!("{service} answered {status}{said}"),
        },
    }
}

/// What a service said about a refusal, in words this host can repeat, or nothing.
///
/// Slack answers with a short code (`channel_not_found`), Discord with a numbered error and
/// Telegram with a description. Each is kept only when it is short, printable and holds no piece
/// of the credential: a service's own words are the service's, and this host does not write down
/// what it cannot vouch for.
fn service_words(service: &str, secret: &DestinationSecret, body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let words = match service {
        "Slack" => Some(text.trim().to_owned()).filter(|code| {
            !code.is_empty()
                && code.len() <= 64
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        }),
        "Discord" => serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|value| value.get("code").and_then(serde_json::Value::as_u64))
            .map(|code| format!("error {code}")),
        _ => serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|value| {
                value
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .map(|description| {
                description
                    .chars()
                    .filter(|character| character.is_ascii_graphic() || *character == ' ')
                    .take(MAX_SERVICE_WORDS)
                    .collect::<String>()
            }),
    };
    words
        .filter(|words| !words.is_empty() && !holds_a_piece_of(words, secret))
        .map_or_else(String::new, |words| format!(": {words}"))
}

/// Whether text holds any part of a credential long enough to matter.
fn holds_a_piece_of(text: &str, secret: &DestinationSecret) -> bool {
    let credential = match secret {
        DestinationSecret::Slack { webhook_url } | DestinationSecret::Discord { webhook_url } => {
            webhook_url.expose()
        }
        DestinationSecret::Telegram { bot_token } => bot_token.expose(),
        DestinationSecret::Email { account } => account.password.expose(),
    };
    credential
        .split(['/', ':', '?', '=', '&'])
        .filter(|piece| piece.len() >= 8)
        .any(|piece| text.contains(piece))
}

/// The length of text in UTF-16 code units, the unit Discord and Telegram measure a message in.
fn units(text: &str) -> usize {
    text.encode_utf16().count()
}

/// Fits a message inside a service's limit.
///
/// A message that fits is sent as it is. One that does not keeps as much of its beginning as fits,
/// says it was shortened, and still ends with [`RECIPIENTS_CAN_READ`]: the sentence that says who
/// can read a message is the last thing to go, and it never goes.
#[must_use]
pub fn fit(body: &str, limit: usize, service: &str) -> String {
    if units(body) <= limit {
        return body.to_owned();
    }
    let marker = format!("\n\n[Shortened to fit what {service} takes.]\n\n");
    let room = limit.saturating_sub(units(RECIPIENTS_CAN_READ) + units(&marker));
    let content = body
        .strip_suffix(RECIPIENTS_CAN_READ)
        .unwrap_or(body)
        .trim_end();
    let mut kept = String::new();
    let mut used = 0;
    for character in content.chars() {
        let width = character.len_utf16();
        if used + width > room {
            break;
        }
        kept.push(character);
        used += width;
    }
    format!("{kept}{marker}{RECIPIENTS_CAN_READ}")
}

/// Escapes the three characters Slack reads as markup, so session text reaches a channel as text:
/// no mention, no channel link, no link of its own.
#[must_use]
pub fn slack_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slack_credential_is_the_address_slack_issues_and_nothing_else() {
        assert!(check_slack_webhook("https://hooks.slack.com/services/T00/B00/XXXX").is_ok());
        assert!(check_slack_webhook("https://hooks.slack-gov.com/services/T00/B00/XXXX").is_ok());
        for refused in [
            "http://hooks.slack.com/services/T00/B00/XXXX",
            "https://hooks.slack.com.example.net/services/T00/B00/XXXX",
            "https://example.net/services/T00/B00/XXXX",
            "https://user:pass@hooks.slack.com/services/T00/B00/XXXX",
            "https://hooks.slack.com:8443/services/T00/B00/XXXX",
            "https://hooks.slack.com/services/T00/B00",
            "https://hooks.slack.com/services/T00/B00/XXXX?channel=general",
            "https://hooks.slack.com/triggers/T00/B00/XXXX",
            "not an address",
        ] {
            let refusal = check_slack_webhook(refused).expect_err(refused);
            assert!(
                !refusal.contains("T00") && !refusal.contains("XXXX"),
                "the refusal of {refused} repeats it: {refusal}"
            );
        }
    }

    #[test]
    fn a_discord_credential_is_the_address_discord_issues_and_nothing_else() {
        assert!(
            check_discord_webhook("https://discord.com/api/webhooks/123456/abc-DEF_ghi").is_ok()
        );
        assert!(
            check_discord_webhook("https://discord.com/api/v10/webhooks/123456/abc-DEF_ghi")
                .is_ok()
        );
        for refused in [
            "https://discord.com/api/webhooks/123456",
            "https://discord.com/api/webhooks/abc/token",
            "https://discord.com/api/webhooks/123456/token?wait=true",
            "https://discord.example.com/api/webhooks/123456/token",
            "http://discord.com/api/webhooks/123456/token",
            "https://discord.com/api/vx/webhooks/123456/token",
        ] {
            let refusal = check_discord_webhook(refused).expect_err(refused);
            assert!(!refusal.contains("123456"), "{refusal}");
        }
    }

    #[test]
    fn a_telegram_token_is_the_shape_telegram_issues() {
        assert!(check_telegram_token("123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11").is_ok());
        for refused in [
            "ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
            "123456:short",
            "12a456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
            "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/getMe",
            ":ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        ] {
            let refusal = check_telegram_token(refused).expect_err(refused);
            assert!(!refusal.contains("DEF1234"), "{refusal}");
        }
    }

    #[test]
    fn a_telegram_chat_is_a_number_or_a_public_username() {
        for accepted in ["123456789", "-1001234567890", "@team_alerts"] {
            assert!(check_telegram_chat(accepted).is_ok(), "{accepted}");
        }
        for refused in [
            "",
            "@",
            "@a1",
            "@1team",
            "12 34",
            "-",
            "99999999999999999999",
        ] {
            assert!(check_telegram_chat(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn a_message_is_shortened_keeping_its_start_and_the_sentence_about_its_readers() {
        let body = format!(
            "{}\n{}\n\n{RECIPIENTS_CAN_READ}",
            "A KalaReach session is waiting for an approval.",
            "\u{1f600}".repeat(3_000)
        );
        let fitted = fit(&body, 2_000, "Discord");
        assert!(fitted.encode_utf16().count() <= 2_000);
        assert!(fitted.starts_with("A KalaReach session is waiting for an approval."));
        assert!(fitted.ends_with(RECIPIENTS_CAN_READ));
        assert!(fitted.contains("Shortened to fit what Discord takes"));
        let short = format!("fits\n\n{RECIPIENTS_CAN_READ}");
        assert_eq!(
            fit(&short, 2_000, "Discord"),
            short,
            "a message that fits is as it was"
        );
    }

    #[test]
    fn slack_reads_session_text_as_text() {
        assert_eq!(
            slack_escape("<!channel> & <@U1> <https://example.net|x>"),
            "&lt;!channel&gt; &amp; &lt;@U1&gt; &lt;https://example.net|x&gt;"
        );
    }

    #[test]
    fn a_channel_is_named_and_never_addressed() {
        assert!(check_channel_label("#alerts in Engineering").is_ok());
        assert!(check_channel_label("").is_err());
        assert!(check_channel_label("line\nbreak").is_err());
        assert!(check_channel_label("https://hooks.slack.com/services/T/B/X").is_err());
    }
}
