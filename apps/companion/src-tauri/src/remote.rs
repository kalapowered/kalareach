//! Importing one remote image, only when a person asks for it.
//!
//! Section 13 forbids fetching a remote image from terminal or agent text automatically, and allows
//! an explicit open or import through the authorised host or client path with a size limit. The
//! difference between the two is not a setting: an automatic fetch would leak the reader's address
//! to whoever printed the URL, and an agent can print a URL at any time.
//!
//! So there is no automatic path here at all. There is one command, it takes a URL a person
//! activated, it refuses anything that is not `https`, it declares a byte limit before it reads,
//! and it stops reading at that limit rather than after it.

use crate::error::{CommandError, Result};
use crate::links;

/// The most one explicitly imported image may weigh.
///
/// Large enough for a screenshot from any current display, small enough that a hostile server
/// cannot make the application hold an arbitrary buffer. It is enforced while reading, one byte
/// past the limit, so a response that exceeds it is refused rather than truncated into half an
/// image. A declared length is a claim and is not what this rests on.
pub const MAX_IMPORT_BYTES: u64 = 16 * 1024 * 1024;

/// What an import asked for and what it got.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imported {
    /// The URL that was fetched.
    pub url: String,
    /// The media type the server declared.
    pub media_type: String,
    /// The bytes.
    pub bytes: Vec<u8>,
}

/// What a fetch of one URL looks like, so the policy can be tested without a network.
pub trait Fetcher: Send + Sync {
    /// Reads at most `limit` bytes of `url`, and says what media type the server declared.
    ///
    /// # Errors
    ///
    /// Returns the transport failure, or the refusal when the response exceeds `limit`.
    fn fetch(&self, url: &str, limit: u64) -> Result<(String, Vec<u8>)>;
}

/// The media types an import may produce.
///
/// The decoder the host uses accepts these, and an import that is not an image has no reason to
/// come through an image import.
pub const IMPORTABLE_MEDIA_TYPES: &[&str] = &["image/png", "image/jpeg", "image/gif"];

/// Imports one image, after checking everything that can be checked before the request.
///
/// # Errors
///
/// Returns `PERMISSION_DENIED` for a scheme that is not approved, `RESOURCE_LIMIT` when the
/// response exceeds [`MAX_IMPORT_BYTES`], and `INVALID_ARGUMENT` when the server returns something
/// that is not an importable image.
pub fn import(url: &str, fetcher: &dyn Fetcher) -> Result<Imported> {
    let approved = links::approve(url)?;
    if approved.scheme != "https" {
        return Err(CommandError::refused(
            "an image is imported over https and nothing else",
        ));
    }

    let (media_type, bytes) = fetcher.fetch(&approved.url, MAX_IMPORT_BYTES)?;
    if bytes.len() as u64 > MAX_IMPORT_BYTES {
        return Err(CommandError::too_large(format!(
            "the image exceeds the {MAX_IMPORT_BYTES}-byte import limit"
        )));
    }

    let declared = media_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !IMPORTABLE_MEDIA_TYPES.contains(&declared.as_str()) {
        return Err(CommandError::invalid(format!(
            "{declared} is not a media type this application imports"
        )));
    }

    Ok(Imported {
        url: approved.url,
        media_type: declared,
        bytes,
    })
}

/// The fetcher this application actually uses.
///
/// One request, no redirects it did not check, no cookies, no cache and a hard read limit. A
/// redirect is followed only while it stays on `https`, because a redirect to another scheme is
/// the same escape the approved-scheme list exists to prevent.
#[derive(Debug)]
pub struct HttpsFetcher {
    agent: ureq::Agent,
}

impl HttpsFetcher {
    /// Builds the fetcher.
    #[must_use]
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(20)))
            .max_redirects(3)
            // Every request in the chain, not just the first: a redirect to http is refused before
            // it is made rather than noticed after the bytes have already gone somewhere.
            .https_only(true)
            .redirect_auth_headers(ureq::config::RedirectAuthHeaders::Never)
            .user_agent("KalaReach")
            .build();
        Self {
            agent: config.into(),
        }
    }
}

impl Default for HttpsFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Fetcher for HttpsFetcher {
    fn fetch(&self, url: &str, limit: u64) -> Result<(String, Vec<u8>)> {
        let mut response = self.agent.get(url).call().map_err(|error| {
            CommandError::unavailable(format!("the image could not be fetched: {error}"))
        })?;
        // The agent refuses a request that is not https, so a chain that left it never happened.
        // This is the second check on the same fact, on the URL the response actually came from.
        if !crate::links::approve(&ureq::ResponseExt::get_uri(&response).to_string())
            .is_ok_and(|approved| approved.scheme == "https")
        {
            return Err(CommandError::refused(
                "that response did not come from an https address",
            ));
        }
        let media_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        // One byte over the limit is read deliberately, so a response that exceeds it is refused
        // rather than silently truncated into a half image.
        let bytes = response
            .body_mut()
            .with_config()
            .limit(limit + 1)
            .read_to_vec()
            .map_err(|error| {
                CommandError::too_large(format!(
                    "the image exceeds the {limit}-byte import limit: {error}"
                ))
            })?;
        Ok((media_type, bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Recorded {
        calls: Mutex<Vec<(String, u64)>>,
        answer: Option<(String, Vec<u8>)>,
    }

    impl Fetcher for Recorded {
        fn fetch(&self, url: &str, limit: u64) -> Result<(String, Vec<u8>)> {
            self.calls
                .lock()
                .expect("the recorder is not poisoned")
                .push((url.to_owned(), limit));
            self.answer.clone().ok_or_else(CommandError::not_connected)
        }
    }

    fn answering(media_type: &str, bytes: Vec<u8>) -> Recorded {
        Recorded {
            calls: Mutex::new(Vec::new()),
            answer: Some((media_type.to_owned(), bytes)),
        }
    }

    /// KR-REQ-13.23: an explicit import fetches the image once, with its size limit declared.
    #[test]
    fn an_explicit_import_fetches_once_and_declares_the_limit() {
        let fetcher = answering("image/png", vec![1, 2, 3]);
        let imported = import("https://example.org/a.png", &fetcher).expect("an image");
        assert_eq!(imported.media_type, "image/png");
        let calls = fetcher.calls.lock().expect("the recorder is not poisoned");
        assert_eq!(calls.len(), 1, "an import fetches once");
        assert_eq!(
            calls[0].1, MAX_IMPORT_BYTES,
            "the limit is declared up front"
        );
    }

    /// KR-REQ-13.23: an image over the size limit is refused rather than kept.
    #[test]
    fn a_response_over_the_limit_is_refused_as_a_resource_limit() {
        let fetcher = answering("image/png", vec![0; MAX_IMPORT_BYTES as usize + 1]);
        let error = import("https://example.org/a.png", &fetcher).expect_err("too large");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::QuotaExceeded);
    }

    /// KR-REQ-13.23: an import is only ever an authorised https fetch; anything else is refused
    /// before the network is touched.
    #[test]
    fn a_non_https_url_is_refused_before_anything_is_fetched() {
        let fetcher = answering("image/png", vec![1]);
        let error = import("http://example.org/a.png", &fetcher).expect_err("https only");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::PermissionDenied);
        assert!(
            fetcher
                .calls
                .lock()
                .expect("the recorder is not poisoned")
                .is_empty(),
            "a refused scheme never reaches the network"
        );
    }

    #[test]
    fn a_response_that_is_not_an_image_is_refused() {
        let fetcher = answering("text/html", b"<script>".to_vec());
        let error = import("https://example.org/a.png", &fetcher).expect_err("not an image");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_media_type_with_parameters_is_read_by_its_type_alone() {
        let fetcher = answering("image/jpeg; charset=binary", vec![9]);
        let imported = import("https://example.org/a.jpg", &fetcher).expect("an image");
        assert_eq!(imported.media_type, "image/jpeg");
    }

    /// Where the child finds the image address its parent listens at.
    const IMAGE: &str = "IMAGE_PROXY_TEST_ADDRESS";

    /// A loopback listener that counts the connections it takes, and drops each one.
    struct Counting {
        port: u16,
        taken: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Counting {
        fn start() -> Self {
            use std::sync::atomic::Ordering;

            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
            listener
                .set_nonblocking(true)
                .expect("a listener that polls");
            let port = listener.local_addr().expect("an address").port();
            let taken = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (counted, stopped) = (taken.clone(), stop.clone());
            let thread = std::thread::spawn(move || {
                while !stopped.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok(_) => {
                            counted.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
                    }
                }
            });
            Self {
                port,
                taken,
                stop,
                thread: Some(thread),
            }
        }

        fn taken(&mut self) -> usize {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            self.taken.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// The child half of [`no_proxy_variable_moves_an_image_import`].
    ///
    /// It is ignored in an ordinary run because it means nothing without the environment the
    /// other test builds around it, and that test runs it by name.
    #[test]
    #[ignore = "no_proxy_variable_moves_an_image_import runs this one"]
    fn the_child_of_the_image_proxy_test() {
        let address = std::env::var(IMAGE).expect("the parent names its address");
        // Nothing answers TLS at the address, so the import fails either way. Where it went is
        // what the parent reads.
        let fetched = HttpsFetcher::new().fetch(&address, MAX_IMPORT_BYTES);
        assert!(fetched.is_err(), "nothing answers at the image's address");
    }

    /// KR-REQ-26.14: no proxy variable moves an image a person imports. In a process whose
    /// `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY` name a listener that counts connections, the
    /// fetch goes to the image's own address and the listener is never reached.
    #[test]
    fn no_proxy_variable_moves_an_image_import() {
        let mut proxy = Counting::start();
        let mut image = Counting::start();
        let variables = format!("http://127.0.0.1:{}", proxy.port);
        let ran = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([
                "--exact",
                "--ignored",
                "--nocapture",
                "remote::tests::the_child_of_the_image_proxy_test",
            ])
            .env(IMAGE, format!("https://127.0.0.1:{}/image.png", image.port))
            .env("HTTPS_PROXY", &variables)
            .env("HTTP_PROXY", &variables)
            .env("ALL_PROXY", &variables)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .current_dir(std::env::temp_dir())
            .output()
            .expect("the child");
        assert!(
            ran.status.success() && String::from_utf8_lossy(&ran.stdout).contains("1 passed"),
            "{}{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
        assert_eq!(
            proxy.taken(),
            0,
            "the import went to the proxy the environment names"
        );
        assert!(
            image.taken() > 0,
            "the import went to the image's own address"
        );
    }
}
