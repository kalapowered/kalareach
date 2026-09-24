//! What the main window may navigate to: the bundled interface and nothing else.
//!
//! The sign-in's pages open in the system browser, never in this window. The content policy stops
//! the page from framing or fetching another origin, but it does not stop a top-level navigation,
//! so the window refuses one away from the bundled interface, and on a desktop it refuses to open
//! a new window at all. On iOS the web view opens no window for `window.open`; on Android it turns
//! `window.open` into a navigation of the same view, which this refuses.

use tauri::{Runtime, Url, WebviewWindowBuilder};

/// Whether the main window may navigate to `url`.
///
/// The bundled interface is served from the application's own origin, which the platforms spell
/// as `tauri://localhost` or `http(s)://tauri.localhost`. A development build also serves it from
/// the development server its configuration names.
#[must_use]
pub fn allowed(url: &Url, development: Option<&Url>) -> bool {
    let bundled = matches!(
        (url.scheme(), url.host_str()),
        ("tauri", Some("localhost")) | ("http" | "https", Some("tauri.localhost"))
    );
    bundled || development.is_some_and(|served| served.origin() == url.origin())
}

/// Adds the navigation and new-window handlers to the main window's builder.
#[must_use]
pub fn guard<'a, R: Runtime, M: tauri::Manager<R>>(
    builder: WebviewWindowBuilder<'a, R, M>,
    development: Option<Url>,
) -> WebviewWindowBuilder<'a, R, M> {
    let builder = builder.on_navigation(move |url| {
        let allowed = allowed(url, development.as_ref());
        if !allowed {
            tracing::warn!(origin = %url.origin().ascii_serialization(), "a navigation away from the interface was refused");
        }
        allowed
    });
    #[cfg(desktop)]
    let builder = builder.on_new_window(|url, _| {
        tracing::warn!(origin = %url.origin().ascii_serialization(), "a new window was refused");
        tauri::webview::NewWindowResponse::Deny
    });
    builder
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).expect("an address")
    }

    /// Section 13: the bundled interface, and never the website's pages, in the window.
    #[test]
    fn the_window_goes_only_to_the_bundled_interface() {
        for bundled in [
            "tauri://localhost/index.html",
            "http://tauri.localhost/index.html",
            "https://tauri.localhost/",
        ] {
            assert!(allowed(&url(bundled), None), "{bundled}");
        }
        for elsewhere in [
            "https://reach.kala.to/account/sign-in",
            "https://reach.kala.to/auth/oauth2/authorize?client_id=kalareach-desktop",
            "http://127.0.0.1:8765/oauth/callback",
            "https://tauri.localhost.evil.example/",
            "tauri://elsewhere/index.html",
            "data:text/html,<p>hello</p>",
            "about:blank",
        ] {
            assert!(!allowed(&url(elsewhere), None), "{elsewhere}");
        }
        let development = url("http://localhost:4187");
        assert!(allowed(
            &url("http://localhost:4187/index.html"),
            Some(&development)
        ));
        assert!(!allowed(&url("http://localhost:4188/"), Some(&development)));
        assert!(!allowed(&url("https://reach.kala.to/"), Some(&development)));
    }
}
