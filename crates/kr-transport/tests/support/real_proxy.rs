//! A real proxy a case names, and what the proxy's own access log says of the traffic.
//!
//! `scripts/real-proxy.sh` runs a squid on the loopback and writes the three names the cases read:
//! `KR_REAL_PROXY` (its origin), `KR_REAL_PROXY_CREDENTIAL_FILE` (one `user:password` line made for
//! the run) and `KR_REAL_PROXY_ACCESS_LOG` (the proxy's access log). A second proxy that offers
//! Digest only is named the same way by `KR_REAL_PROXY_DIGEST`, `KR_REAL_PROXY_DIGEST_CREDENTIAL_FILE`
//! and `KR_REAL_PROXY_DIGEST_ACCESS_LOG`.
//!
//! The log is the proxy's record of what reached it. A line is
//! `<time> <client> <method> <target> <status> <result> <user>`, written when the request ends: a
//! `CONNECT` that was let through is written when its tunnel closes.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kr_crypto::secret::SecretVec;
use kr_transport::config::ProxyUrl;
use kr_transport::proxy::ProxyCredential;

/// How long a case waits for the proxy to write a line.
const LOG_PATIENCE: Duration = Duration::from_secs(20);

/// The login a case presents.
#[derive(Clone, Copy, Debug)]
pub enum Login {
    /// The user and password the proxy was started with.
    Right,
    /// The right user with a password the proxy does not hold.
    Wrong,
    /// No login.
    None,
}

/// One line of the proxy's access log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Logged {
    pub method: String,
    pub target: String,
    pub status: u16,
    pub result: String,
    pub user: String,
}

/// The proxy the environment names.
pub struct RealProxy {
    pub origin: String,
    user: String,
    password: String,
    log: PathBuf,
}

fn named(origin: &str, suffix: &str) -> String {
    let name = format!("{origin}{suffix}");
    std::env::var(&name).unwrap_or_else(|_| {
        panic!("{name} is not set: the environment names the proxy this case runs against, as scripts/real-proxy.sh writes the names")
    })
}

impl RealProxy {
    /// The proxy that asks for a login by HTTP Basic.
    pub fn basic() -> Self {
        Self::read("KR_REAL_PROXY")
    }

    /// The proxy that offers Digest only.
    pub fn digest() -> Self {
        Self::read("KR_REAL_PROXY_DIGEST")
    }

    /// The proxy that intercepts TLS and asks for no login: the proxy at the port that passes a
    /// WebSocket upgrade, the origin of the port that refuses it, and the DER form of the
    /// authority whose certificates it presents.
    pub fn bump() -> (Self, String, Vec<u8>) {
        let name = "KR_REAL_PROXY_BUMP";
        let authority =
            std::fs::read(named(name, "_CA_FILE")).expect("the authority file is readable");
        let proxy = Self {
            origin: named(name, ""),
            user: String::new(),
            password: String::new(),
            log: PathBuf::from(named(name, "_ACCESS_LOG")),
        };
        (proxy, named(name, "_BLOCKING"), authority)
    }

    fn read(origin: &str) -> Self {
        let credential = std::fs::read_to_string(named(origin, "_CREDENTIAL_FILE"))
            .expect("the credential file is readable");
        let (user, password) = credential
            .trim_end_matches(['\r', '\n'])
            .split_once(':')
            .expect("the credential file holds one user:password line");
        Self {
            origin: named(origin, ""),
            user: user.to_owned(),
            password: password.to_owned(),
            log: PathBuf::from(named(origin, "_ACCESS_LOG")),
        }
    }

    /// The login line, `user:password`, as the owner stores it.
    pub fn login_line(&self) -> String {
        format!("{}:{}", self.user, self.password)
    }

    /// The name the proxy was started with, and what its log says for that user.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The proxy's address with `login` as the login this host holds for it.
    pub fn url(&self, login: Login) -> ProxyUrl {
        let proxy: ProxyUrl = self.origin.parse().expect("the proxy's origin");
        let password = match login {
            Login::Right => self.password.clone(),
            Login::Wrong => "not-this-password".to_owned(),
            Login::None => return proxy,
        };
        proxy.with_login(
            ProxyCredential::new(
                SecretVec::new(self.user.clone().into_bytes()),
                SecretVec::new(password.into_bytes()),
            )
            .expect("a login"),
        )
    }

    /// Every line of the log that names `target`, in the order they were written.
    pub fn lines_to(&self, target: &str) -> Vec<Logged> {
        self.lines_matching(|line_target| line_target == target)
    }

    /// Every line of the log whose target holds `text`, in the order they were written. A request
    /// the proxy read inside a tunnel it intercepted is named by its whole address.
    pub fn lines_naming(&self, text: &str) -> Vec<Logged> {
        self.lines_matching(|line_target| line_target.contains(text))
    }

    fn lines_matching(&self, keep: impl Fn(&str) -> bool) -> Vec<Logged> {
        let log = std::fs::read_to_string(&self.log).unwrap_or_default();
        log.lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                let [_, _, method, line_target, status, result, user] = fields[..] else {
                    return None;
                };
                if !keep(line_target) {
                    return None;
                }
                Some(Logged {
                    method: method.to_owned(),
                    target: line_target.to_owned(),
                    status: status.parse().ok()?,
                    result: result.to_owned(),
                    user: user.to_owned(),
                })
            })
            .collect()
    }

    /// Waits until the lines that name `target` number `count`, and returns them.
    pub async fn wait_for(&self, target: &str, count: usize) -> Vec<Logged> {
        self.wait_until(target, &format!("{count} line(s)"), |lines| {
            lines.len() >= count
        })
        .await
    }

    /// Waits until the lines that name `target` satisfy `enough`, and returns them.
    pub async fn wait_until(
        &self,
        target: &str,
        wanted: &str,
        enough: impl Fn(&[Logged]) -> bool,
    ) -> Vec<Logged> {
        let deadline = Instant::now() + LOG_PATIENCE;
        loop {
            let lines = self.lines_to(target);
            if enough(&lines) {
                return lines;
            }
            assert!(
                Instant::now() < deadline,
                "the proxy's log never held {wanted} for {target}: {lines:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Waits until the lines whose target holds `text` satisfy `enough`, and returns them.
    pub async fn wait_until_naming(
        &self,
        text: &str,
        wanted: &str,
        enough: impl Fn(&[Logged]) -> bool,
    ) -> Vec<Logged> {
        let deadline = Instant::now() + LOG_PATIENCE;
        loop {
            let lines = self.lines_naming(text);
            if enough(&lines) {
                return lines;
            }
            assert!(
                Instant::now() < deadline,
                "the proxy's log never held {wanted} for {text}: {lines:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
