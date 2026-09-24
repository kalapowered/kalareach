//! Slack, Discord and Telegram: three chat services, each reached by one HTTPS request.
//!
//! Each of them sends through a credential from the host's secret store. A Slack incoming webhook
//! and a Discord webhook are addresses that are themselves bearer secrets: whoever holds one can
//! post to the channel it was made for. A Telegram bot sends through its token, which the Bot API
//! takes in the request's path. So a credential is checked here for the shape its service issues,
//! and it is refused rather than kept when it has another: a Slack credential that pointed anywhere
//! but Slack's webhook host would send session content to wherever it pointed.

use url::Url;

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
    fn a_channel_is_named_and_never_addressed() {
        assert!(check_channel_label("#alerts in Engineering").is_ok());
        assert!(check_channel_label("").is_err());
        assert!(check_channel_label("line\nbreak").is_err());
        assert!(check_channel_label("https://hooks.slack.com/services/T/B/X").is_err());
    }
}
