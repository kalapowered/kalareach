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

/// Decides a navigation the main window was asked to make, and writes down one it refuses.
fn decide(url: &Url, development: Option<&Url>) -> bool {
    let allowed = allowed(url, development);
    if !allowed {
        tracing::warn!(origin = %url.origin().ascii_serialization(), "a navigation away from the interface was refused");
    }
    allowed
}

/// Writes down a new window the page asked for and the application refused.
#[cfg(desktop)]
fn note_refused_window(url: &Url) {
    tracing::warn!(origin = %url.origin().ascii_serialization(), "a new window was refused");
}

/// Adds the navigation and new-window handlers to the main window's builder.
#[must_use]
pub fn guard<'a, R: Runtime, M: tauri::Manager<R>>(
    builder: WebviewWindowBuilder<'a, R, M>,
    development: Option<Url>,
) -> WebviewWindowBuilder<'a, R, M> {
    let builder = builder.on_navigation(move |url| decide(url, development.as_ref()));
    #[cfg(desktop)]
    let builder = builder.on_new_window(|url, _| {
        note_refused_window(&url);
        tauri::webview::NewWindowResponse::Deny
    });
    builder
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    /// The fields of each record written through `tracing` while it is in place.
    #[derive(Clone, Default)]
    struct Written(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

    struct Fields<'a>(&'a mut BTreeMap<String, String>);

    impl tracing::field::Visit for Fields<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    impl tracing::Subscriber for Written {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut fields = BTreeMap::new();
            event.record(&mut Fields(&mut fields));
            self.0.lock().expect("the record").push(fields);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// One written record, as its message and the origin it names.
    fn said(message: &str, origin: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("message".to_owned(), message.to_owned()),
            ("origin".to_owned(), origin.to_owned()),
        ])
    }

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

    /// How many `blob:` prefixes the nested address holds. A `url` release before 2.5.9
    /// (RUSTSEC-2026-0592) took the origin of such an address by calling itself once for each
    /// prefix, so a deep one overflows the stack, which ends the whole process and which no handler
    /// catches. A test thread has the 2 MiB of stack a spawned thread has by default, and at that
    /// size the recursion overflowed from 6,227 prefixes in an unoptimised build and from 8,227 in
    /// an optimised one; 10,000 prefixes, an address of 50,020 bytes, are past both.
    const NESTED_BLOBS: usize = 10_000;

    fn nested_blobs() -> Url {
        url(&format!(
            "{}https://example.com/",
            "blob:".repeat(NESTED_BLOBS)
        ))
    }

    /// An address nested this deep is refused, and the warning names it by an opaque origin, which
    /// is written as `null`: the check returns, so the process goes on.
    #[test]
    fn a_navigation_to_a_deeply_nested_blob_address_is_refused_and_named_by_a_null_origin() {
        let written = Written::default();
        let allowed =
            tracing::subscriber::with_default(written.clone(), || decide(&nested_blobs(), None));
        assert!(!allowed);
        assert_eq!(
            written.0.lock().expect("the record").clone(),
            [said(
                "a navigation away from the interface was refused",
                "null"
            )]
        );
    }

    /// A development build compares the origin of the address with the development server's, and
    /// a deeply nested address is not that origin.
    #[test]
    fn a_deeply_nested_blob_address_is_not_the_development_servers_origin() {
        let development = url("http://localhost:4187");
        assert!(!allowed(&nested_blobs(), Some(&development)));
    }

    /// A page that asks for a new window with such an address is refused, and the warning names it
    /// by a null origin.
    #[cfg(desktop)]
    #[test]
    fn a_new_window_for_a_deeply_nested_blob_address_is_refused_and_named_by_a_null_origin() {
        let written = Written::default();
        tracing::subscriber::with_default(written.clone(), || {
            note_refused_window(&nested_blobs());
        });
        assert_eq!(
            written.0.lock().expect("the record").clone(),
            [said("a new window was refused", "null")]
        );
    }
}
