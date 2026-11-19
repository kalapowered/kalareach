//! The redirect loop of a client whose proxy holds a login: it follows by the library's own rules,
//! gates each hop, keeps the address of the hop that failed, stops at the limit, and holds every hop
//! and the final body to one deadline. The origins are stand-ins on the loopback.

// Only the client configuration of this module is used; other suites that share it use the rest.
#[path = "support/tls.rs"]
#[allow(dead_code)]
mod tls;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_transport::proxy::{FollowFailure, Following, ProxyLoginKind, follow, proxy_login_kind};
use reqwest::{Method, Url};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// How long a test waits for something before it fails as stuck.
const WATCHDOG: Duration = Duration::from_secs(30);

/// What an origin saw of one request.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

/// What an origin answers.
#[derive(Clone, Default)]
struct Reply {
    status: u16,
    location: Option<String>,
    /// Waits this long before it answers.
    delay: Option<Duration>,
    /// Never answers.
    hold: bool,
}

type Script = Box<dyn Fn(&Seen) -> Reply + Send + Sync>;

struct Origin {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    script: Arc<Mutex<Script>>,
    task: tokio::task::JoinHandle<()>,
}

impl Origin {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a listener");
        let port = listener.local_addr().expect("an address").port();
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let script: Arc<Mutex<Script>> = Arc::new(Mutex::new(Box::new(|_| Reply {
            status: 200,
            ..Reply::default()
        })));
        let task = tokio::spawn({
            let seen = Arc::clone(&seen);
            let script = Arc::clone(&script);
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(serve(stream, Arc::clone(&seen), Arc::clone(&script)));
                }
            }
        });
        Self {
            port,
            seen,
            script,
            task,
        }
    }

    fn url(&self, path: &str) -> Url {
        format!("http://127.0.0.1:{}{path}", self.port)
            .parse()
            .expect("a URL")
    }

    fn answer(&self, script: impl Fn(&Seen) -> Reply + Send + Sync + 'static) {
        *self.script.lock().unwrap_or_else(PoisonError::into_inner) = Box::new(script);
    }

    fn take(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.seen.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn count(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    mut stream: tokio::net::TcpStream,
    seen: Arc<Mutex<Vec<Seen>>>,
    script: Arc<Mutex<Script>>,
) {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    let end = loop {
        if let Some(at) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break at + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => bytes.extend_from_slice(&chunk[..read]),
        }
    };
    let head = String::from_utf8_lossy(&bytes[..end]).into_owned();
    let mut lines = head.lines();
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_owned();
    let target = first.next().unwrap_or_default().to_owned();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let mut body = bytes[end..].to_vec();
    while body.len() < length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => body.extend_from_slice(&chunk[..read]),
        }
    }
    let request = Seen {
        method,
        target,
        headers,
        body,
    };
    let reply = (script.lock().unwrap_or_else(PoisonError::into_inner))(&request);
    seen.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(request);
    if reply.hold {
        std::future::pending::<()>().await;
    }
    if let Some(delay) = reply.delay {
        tokio::time::sleep(delay).await;
    }
    let location = reply
        .location
        .map(|location| format!("location: {location}\r\n"))
        .unwrap_or_default();
    let _ = stream
        .write_all(
            format!(
                "HTTP/1.1 {} Answer\r\n{location}content-length: 0\r\nconnection: close\r\n\r\n",
                reply.status
            )
            .as_bytes(),
        )
        .await;
    let _ = stream.shutdown().await;
}

fn builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .tls_backend_preconfigured((*tls::client_config(&[])).clone())
}

/// A client that follows nothing by itself, as one whose proxy holds a login.
fn following_client() -> reqwest::Client {
    builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("a client")
}

/// The library's own client, whose policy `follow` copies.
fn library_client() -> reqwest::Client {
    builder().build().expect("a client")
}

fn free(_: &Url) -> Result<(), ProxyLoginKind> {
    Ok(())
}

fn following(limit: usize, deadline: Duration) -> Following {
    Following {
        limit,
        deadline: Some(deadline),
    }
}

fn request(client: &reqwest::Client, method: &Method, url: &Url) -> reqwest::Request {
    let mut request = client
        .request(method.clone(), url.clone())
        .header("authorization", "Bearer secret")
        .header("x-kept", "yes")
        .header("content-type", "text/plain");
    if method == Method::POST || method == Method::PUT {
        request = request.body("the body");
    }
    request.build().expect("a request")
}

/// For `GET`, `HEAD`, `POST` and `PUT` and for each of `301`, `302`, `303`, `307` and `308`, to an
/// address on the same origin and to another origin, the request that the origin records after
/// `follow` equals the one it records after the library's own policy: the method, the body, the
/// headers a followed request keeps or loses, and the `Referer`.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_followed_request_is_the_one_the_librarys_own_policy_sends() {
    let first = Origin::start().await;
    let second = Origin::start().await;
    let (follows, library) = (following_client(), library_client());
    for cross in [false, true] {
        for method in [Method::GET, Method::HEAD, Method::POST, Method::PUT] {
            for status in [301_u16, 302, 303, 307, 308] {
                let location = if cross {
                    second.url("/b").to_string()
                } else {
                    "/b".to_owned()
                };
                first.answer(move |seen| {
                    if seen.target == "/a" {
                        Reply {
                            status,
                            location: Some(location.clone()),
                            ..Reply::default()
                        }
                    } else {
                        Reply {
                            status: 200,
                            ..Reply::default()
                        }
                    }
                });
                let url = first.url("/a");

                let done = follow(
                    &follows,
                    request(&follows, &method, &url),
                    following(10, WATCHDOG),
                    free,
                )
                .await
                .expect("a followed request");
                assert_eq!(done.status(), 200);
                let mut ours = first.take();
                ours.extend(second.take());
                ours.retain(|seen| seen.target == "/b");

                let done = library
                    .execute(request(&library, &method, &url))
                    .await
                    .expect("the library's own request");
                assert_eq!(done.status(), 200);
                let mut theirs = first.take();
                theirs.extend(second.take());
                theirs.retain(|seen| seen.target == "/b");

                assert_eq!(
                    ours.len(),
                    1,
                    "{method} {status} cross {cross}: followed once"
                );
                assert_eq!(
                    ours, theirs,
                    "{method} {status} cross {cross}: the request after the redirect"
                );
            }
        }
    }
}

/// The one place `follow` differs from the library's own policy: in a chain from one host to a
/// second and then to the second again, a header that holds a login is removed at the change of
/// host and stays removed. The library, as locked in this build, sends it again on the second
/// request to the second host; `follow` does not, and every other header is the library's.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_login_header_removed_at_a_change_of_host_stays_removed_in_a_chain_to_the_same_host_twice()
 {
    let first = Origin::start().await;
    let second = Origin::start().await;
    let to_second = second.url("/b").to_string();
    first.answer(move |_| Reply {
        status: 307,
        location: Some(to_second.clone()),
        ..Reply::default()
    });
    second.answer(|seen| match seen.target.as_str() {
        "/b" => Reply {
            status: 307,
            location: Some("/c".to_owned()),
            ..Reply::default()
        },
        _ => Reply {
            status: 200,
            ..Reply::default()
        },
    });
    let (follows, library) = (following_client(), library_client());
    let url = first.url("/a");

    let done = follow(
        &follows,
        request(&follows, &Method::GET, &url),
        following(10, WATCHDOG),
        free,
    )
    .await
    .expect("a followed request");
    assert_eq!(done.status(), 200);
    let ours: Vec<Seen> = second.take();
    first.take();
    let done = library
        .execute(request(&library, &Method::GET, &url))
        .await
        .expect("the library's own request");
    assert_eq!(done.status(), 200);
    let theirs: Vec<Seen> = second.take();

    let reach = |seen: &[Seen], target: &str| {
        seen.iter()
            .find(|seen| seen.target == target)
            .unwrap_or_else(|| panic!("{target} was requested"))
            .clone()
    };
    for (who, seen) in [("follow", &ours), ("the library", &theirs)] {
        assert_eq!(
            reach(seen, "/b").headers.get("authorization"),
            None,
            "{who}: the login goes no further than the host that received it"
        );
        assert_eq!(
            reach(seen, "/b").headers.get("x-kept").map(String::as_str),
            Some("yes"),
            "{who}: the other headers follow"
        );
    }
    assert_eq!(
        reach(&ours, "/c").headers.get("authorization"),
        None,
        "follow: the login stays removed on the second request to the same host"
    );
    assert_eq!(
        reach(&ours, "/c").headers.get("x-kept").map(String::as_str),
        Some("yes")
    );
    assert_eq!(
        reach(&theirs, "/c")
            .headers
            .get("authorization")
            .map(String::as_str),
        Some("Bearer secret"),
        "the library restores it on that request: the exception to equivalence"
    );
}

/// Ten redirects are followed and the eleventh is refused, with the address that answered it, and
/// the library's policy makes the same eleven requests.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ten_redirects_are_followed_and_the_eleventh_is_refused() {
    let origin = Origin::start().await;
    origin.answer(|seen| {
        let step: usize = seen
            .target
            .trim_start_matches("/n")
            .parse()
            .unwrap_or_default();
        Reply {
            status: 302,
            location: Some(format!("/n{}", step + 1)),
            ..Reply::default()
        }
    });
    let client = following_client();
    let error = follow(
        &client,
        client.get(origin.url("/n0")).build().expect("a request"),
        following(10, WATCHDOG),
        free,
    )
    .await
    .expect_err("an eleventh redirect");
    assert!(matches!(error.failure, FollowFailure::TooManyRedirects));
    assert_eq!(
        error.url,
        origin.url("/n10"),
        "the hop that was answered by the eleventh"
    );
    assert_eq!(
        origin.take().len(),
        11,
        "the first request and ten redirects"
    );

    let library = library_client()
        .get(origin.url("/n0"))
        .send()
        .await
        .expect_err("the library's limit");
    assert!(library.is_redirect());
    assert_eq!(
        origin.take().len(),
        11,
        "the library makes the same eleven requests"
    );
}

/// A hop that fails is named by its own address and not the first request's, and the gate runs
/// before every send: a hop it refuses is never sent and carries its kind.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_hop_is_named_by_its_own_address_and_each_hop_is_gated() {
    let origin = Origin::start().await;
    // Nothing listens at this port, so the second hop's connect is refused.
    let nowhere: Url = "http://127.0.0.1:1/b".parse().expect("a URL");
    origin.answer({
        let nowhere = nowhere.to_string();
        move |_| Reply {
            status: 302,
            location: Some(nowhere.clone()),
            ..Reply::default()
        }
    });
    let client = following_client();
    let error = follow(
        &client,
        client.get(origin.url("/a")).build().expect("a request"),
        following(10, WATCHDOG),
        free,
    )
    .await
    .expect_err("the second hop fails");
    assert!(matches!(error.failure, FollowFailure::Send(_)));
    assert_eq!(error.url, nowhere);

    let gated = Mutex::new(Vec::new());
    let error = follow(
        &client,
        client.get(origin.url("/a")).build().expect("a request"),
        following(10, WATCHDOG),
        |url| {
            gated
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(url.clone());
            if url.port() == Some(1) {
                Err(ProxyLoginKind::ClearTextTarget)
            } else {
                Ok(())
            }
        },
    )
    .await
    .expect_err("the gate refuses the second hop");
    assert_eq!(error.url, nowhere);
    assert_eq!(
        proxy_login_kind(&error),
        Some(ProxyLoginKind::ClearTextTarget)
    );
    assert_eq!(
        *gated.lock().unwrap_or_else(PoisonError::into_inner),
        vec![origin.url("/a"), nowhere],
        "the gate ran for the first request and for the hop"
    );
    assert_eq!(origin.count(), 2, "the refused hop was not sent");
}

/// Two requests that follow at once keep their own addresses: a failure names the hop of its own
/// request, whichever answered last.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_that_follow_at_once_keep_their_own_addresses() {
    let origin = Origin::start().await;
    origin.answer(|seen| {
        let tag = seen.target.trim_start_matches("/a-").to_owned();
        Reply {
            status: 302,
            location: Some(format!("http://127.0.0.1:1/{tag}")),
            // The first request answers last.
            delay: (tag == "one").then_some(Duration::from_millis(300)),
            ..Reply::default()
        }
    });
    let client = following_client();
    let send = |tag: &'static str| {
        let client = client.clone();
        let url = origin.url(&format!("/a-{tag}"));
        async move {
            follow(
                &client,
                client.get(url).build().expect("a request"),
                following(10, WATCHDOG),
                free,
            )
            .await
        }
    };
    let (one, two) = tokio::join!(send("one"), send("two"));
    assert_eq!(one.expect_err("fails").url.path(), "/one");
    assert_eq!(two.expect_err("fails").url.path(), "/two");
}

/// Every hop and the final body are held to one deadline: the hops that came before use up time
/// that the next one does not get back, so a chain of slow hops ends at the deadline with a
/// timeout, and the hop after the one that ran out is never sent.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_hops_end_at_one_deadline() {
    let origin = Origin::start().await;
    origin.answer(|seen| {
        let step: usize = seen
            .target
            .trim_start_matches("/n")
            .parse()
            .unwrap_or_default();
        Reply {
            status: 302,
            location: Some(format!("/n{}", step + 1)),
            delay: Some(Duration::from_secs(1)),
            ..Reply::default()
        }
    });
    let client = following_client();
    let started = Instant::now();
    let error = follow(
        &client,
        client.get(origin.url("/n0")).build().expect("a request"),
        following(10, Duration::from_millis(1500)),
        free,
    )
    .await
    .expect_err("the deadline runs out");
    match &error.failure {
        FollowFailure::Send(source) => assert!(source.is_timeout(), "{source}"),
        other => panic!("a timeout was expected: {other}"),
    }
    assert!(
        origin.count() <= 2,
        "the third hop was sent although the deadline of the whole chain had passed"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}
