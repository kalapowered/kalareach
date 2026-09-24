//! Email: a message handed to a mail submission server under the owner's account.
//!
//! Everything a destination or an event supplies that ends up in a mail command or a header is
//! checked here before it is used, and none of it may carry a line break: an address is a plain
//! `local@domain` in ASCII, so a recipient, a sender or a subject can never add a header of its own
//! or a command to the conversation with the server.

use kr_protocol::delivery::MailAccount;

/// The longest address this host sends to or from.
pub const MAX_ADDRESS_LEN: usize = 254;

/// The longest host name a submission server may have.
const MAX_HOST_LEN: usize = 253;

/// Checks one mail address: `local@domain`, ASCII, with nothing a header or a mail command could
/// read as anything but the address.
///
/// # Errors
///
/// Returns the rule the address broke.
pub fn check_address(text: &str) -> Result<(), String> {
    let refused = || {
        "a mail address is local@domain in ASCII letters, digits and the punctuation an address \
         allows, with no spaces, quotes, brackets or line breaks"
            .to_owned()
    };
    if text.len() > MAX_ADDRESS_LEN || text.bytes().filter(|byte| *byte == b'@').count() != 1 {
        return Err(refused());
    }
    let (local, domain) = text.split_once('@').ok_or_else(refused)?;
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'.' | b'!'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                )
        });
    if !local_ok || check_host_name(domain).is_err() || !domain.contains('.') {
        return Err(refused());
    }
    Ok(())
}

/// Checks a host name: dot-separated labels of ASCII letters, digits and hyphens.
fn check_host_name(text: &str) -> Result<(), String> {
    let refused =
        || "a host name is dot-separated labels of ASCII letters, digits and hyphens".to_owned();
    if text.is_empty() || text.len() > MAX_HOST_LEN {
        return Err(refused());
    }
    for label in text.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(refused());
        }
    }
    Ok(())
}

/// Checks a submission server: a host name or an IP address.
///
/// # Errors
///
/// Returns the rule the server broke.
pub fn check_server(text: &str) -> Result<(), String> {
    if text.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    check_host_name(text).map_err(|_| {
        "a mail submission server is a host name or an IP address, with no scheme and no port"
            .to_owned()
    })
}

/// Checks a mail submission account, everything but the password's value.
///
/// The user name and the password are credentials already checked for length and control
/// characters where they were read; a NUL, which the PLAIN mechanism would read as a separator, is
/// one of those.
///
/// # Errors
///
/// Returns the rule the account broke, never the credential.
pub fn check_account(account: &MailAccount) -> Result<(), String> {
    check_server(&account.server)?;
    if account.port.get() == 0 || account.port.get() > u64::from(u16::MAX) {
        return Err("a mail submission port is between 1 and 65535".to_owned());
    }
    check_address(&account.from_address)
        .map_err(|rule| format!("the address mail is sent from: {rule}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::delivery::{MailSecurity, SecretText};
    use kr_protocol::scalars::U64;

    #[test]
    fn an_address_is_plain_and_can_add_nothing_to_a_header_or_a_command() {
        for accepted in [
            "person@example.com",
            "first.last+alerts@mail.example.co.uk",
            "o'brien@example.org",
        ] {
            assert!(check_address(accepted).is_ok(), "{accepted}");
        }
        for refused in [
            "person@example.com\r\nBcc: someone@example.net",
            "person@example.com>\r\nRCPT TO:<someone@example.net",
            "Person <person@example.com>",
            "person@example.com, someone@example.net",
            "\"quoted\"@example.com",
            "person@@example.com",
            "person@localhost",
            ".person@example.com",
            "person@-example.com",
            "pérson@example.com",
            "",
        ] {
            assert!(check_address(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn a_server_is_a_host_or_an_address_and_nothing_else() {
        for accepted in ["smtp.example.com", "localhost", "127.0.0.1", "::1"] {
            assert!(check_server(accepted).is_ok(), "{accepted}");
        }
        for refused in [
            "smtps://smtp.example.com",
            "smtp.example.com:465",
            "smtp example com",
            "",
        ] {
            assert!(check_server(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn an_account_is_refused_without_repeating_its_credential() {
        let account = MailAccount {
            server: "smtp.example.com".to_owned(),
            port: U64::new(0),
            security: MailSecurity::ImplicitTls,
            username: SecretText::new("person@example.com").expect("a name"),
            password: SecretText::new("correct horse").expect("a password"),
            from_address: "person@example.com".to_owned(),
        };
        let refusal = check_account(&account).expect_err("port zero");
        assert!(!refusal.contains("correct horse"));
        assert!(
            check_account(&MailAccount {
                port: U64::new(465),
                ..account
            })
            .is_ok()
        );
    }
}
