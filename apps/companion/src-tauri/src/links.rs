//! Which links this application will hand to the operating system, and which it will not.
//!
//! Section 13 allows an external link only on a user action and only with an approved scheme.
//! Terminal output and agent text are the least trustworthy strings the application handles, and a
//! renderer that turns any of them into an openable link would give a package a way to run a
//! handler the person never chose. The rule here is a closed list of schemes, applied to a URL this
//! backend parses itself rather than to the text the page displayed.

use serde::Serialize;

use crate::error::{CommandError, Result};

/// The schemes this application will open.
///
/// `https` is the web. `mailto` is a message the person composes and sends themselves. Everything
/// else, including `file`, `javascript`, `data` and every custom application scheme, is refused:
/// those either reach a local handler chosen by the content or put content itself in the URL.
pub const APPROVED_SCHEMES: &[&str] = &["https", "mailto"];

/// A link the application is willing to open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Approved {
    /// The scheme, lowercased.
    pub scheme: String,
    /// The full URL, exactly as it will be handed to the platform.
    pub url: String,
    /// The host, for the confirmation the interface shows before opening.
    pub host: Option<String>,
}

/// Checks a link against the approved schemes.
///
/// # Errors
///
/// Returns `PERMISSION_DENIED` for a scheme that is not approved and `INVALID_ARGUMENT` for a
/// string that is not a URL at all.
pub fn approve(url: &str) -> Result<Approved> {
    let trimmed = url.trim();
    if trimmed.len() != url.len() {
        return Err(CommandError::invalid(
            "a link with surrounding whitespace is not opened; the text around it is not the link",
        ));
    }
    if trimmed.is_empty() || trimmed.len() > MAX_URL_LEN {
        return Err(CommandError::invalid(
            "a link must be between one and two thousand characters",
        ));
    }
    if trimmed.chars().any(|character| {
        character.is_control() || character == '\u{2028}' || character == '\u{2029}'
    }) {
        return Err(CommandError::invalid(
            "a link containing a control character is not opened",
        ));
    }

    let (scheme, rest) = trimmed.split_once(':').ok_or_else(|| {
        CommandError::invalid("a link without a scheme is not opened")
    })?;
    let scheme = scheme.to_ascii_lowercase();
    if !scheme
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.'))
        || !scheme.starts_with(|character: char| character.is_ascii_alphabetic())
    {
        return Err(CommandError::invalid("that is not a URL scheme"));
    }
    if !APPROVED_SCHEMES.contains(&scheme.as_str()) {
        return Err(CommandError::refused(format!(
            "the {scheme} scheme is not one this application opens"
        )));
    }

    let host = if scheme == "https" {
        Some(https_host(rest)?)
    } else {
        None
    };

    Ok(Approved {
        scheme,
        url: trimmed.to_owned(),
        host,
    })
}

/// The longest link this application will consider.
const MAX_URL_LEN: usize = 2048;

/// Pulls the host out of an `https` URL, refusing the shapes that hide one.
///
/// A URL with credentials in its authority is refused outright: the part a person reads is not the
/// part the browser connects to, which is the whole of that trick.
fn https_host(rest: &str) -> Result<String> {
    let authority = rest.strip_prefix("//").ok_or_else(|| {
        CommandError::invalid("an https link must name a host")
    })?;
    let authority = authority
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.contains('@') {
        return Err(CommandError::refused(
            "a link that carries credentials in front of its host is not opened",
        ));
    }
    let host = authority.rsplit_once(':').map_or(authority, |(host, port)| {
        if port.chars().all(|character| character.is_ascii_digit()) {
            host
        } else {
            authority
        }
    });
    if host.is_empty() {
        return Err(CommandError::invalid("an https link must name a host"));
    }
    Ok(host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_https_link_is_approved_and_names_its_host() {
        let approved = approve("https://docs.example.org/guide#top").expect("https is approved");
        assert_eq!(approved.scheme, "https");
        assert_eq!(approved.host.as_deref(), Some("docs.example.org"));
    }

    #[test]
    fn a_mailto_link_is_approved_without_a_host() {
        let approved = approve("mailto:someone@example.org").expect("mailto is approved");
        assert_eq!(approved.scheme, "mailto");
        assert_eq!(approved.host, None);
    }

    #[test]
    fn plain_http_is_refused() {
        let error = approve("http://example.org").expect_err("http is not approved");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::PermissionDenied);
    }

    #[test]
    fn a_script_url_is_refused() {
        for url in [
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox",
        ] {
            let error = approve(url).expect_err("a script URL is never opened");
            assert_eq!(error.code, kr_protocol::error::ErrorCode::PermissionDenied);
        }
    }

    #[test]
    fn a_file_url_is_refused() {
        let error = approve("file:///etc/passwd").expect_err("file is not approved");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::PermissionDenied);
    }

    #[test]
    fn a_custom_application_scheme_is_refused() {
        let error = approve("kalareach-internal://run").expect_err("no custom scheme is approved");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::PermissionDenied);
    }

    #[test]
    fn a_link_that_hides_its_host_behind_credentials_is_refused() {
        let error = approve("https://docs.example.org@evil.test/path")
            .expect_err("the authority is not what it reads as");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::PermissionDenied);
    }

    #[test]
    fn a_link_with_a_control_character_is_refused() {
        let error = approve("https://example.org/\u{0}x").expect_err("control characters are out");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_link_with_a_port_still_names_its_host() {
        let approved = approve("https://example.org:8443/x").expect("a port is allowed");
        assert_eq!(approved.host.as_deref(), Some("example.org"));
    }

    #[test]
    fn a_string_that_is_not_a_url_is_refused() {
        let error = approve("example.org").expect_err("no scheme, no link");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::InvalidArgument);
    }
}
