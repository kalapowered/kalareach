//! A real proxy a case names, and what the proxy's own access log says of the traffic.
//!
//! `scripts/real-proxy.sh` runs a squid on the loopback and writes the three names the cases read:
//! `KR_REAL_PROXY` (its origin), `KR_REAL_PROXY_CREDENTIAL_FILE` (one `user:password` line made for
//! the run) and `KR_REAL_PROXY_ACCESS_LOG` (the proxy's access log). A proxy that offers Digest
//! only also sets `KR_REAL_PROXY_DIGEST`, so a case written for the other kind refuses it.
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

fn named(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("KR_REAL_PROXY, KR_REAL_PROXY_CREDENTIAL_FILE and KR_REAL_PROXY_ACCESS_LOG name the proxy to run against, and {name} is not set")
    })
}

impl RealProxy {
    /// The proxy that asks for a login by HTTP Basic.
    pub fn basic() -> Self {
        assert!(
            std::env::var_os("KR_REAL_PROXY_DIGEST").is_none(),
            "KR_REAL_PROXY_DIGEST is set: the proxy named offers Digest only, and this case needs one that asks for Basic"
        );
        Self::read()
    }

    /// The proxy that offers Digest only.
    pub fn digest() -> Self {
        assert!(
            std::env::var_os("KR_REAL_PROXY_DIGEST").is_some(),
            "KR_REAL_PROXY_DIGEST is not set: this case needs the proxy that offers Digest only"
        );
        Self::read()
    }

    fn read() -> Self {
        let origin = named("KR_REAL_PROXY");
        let credential = std::fs::read_to_string(named("KR_REAL_PROXY_CREDENTIAL_FILE"))
            .expect("the credential file is readable");
        let (user, password) = credential
            .trim_end_matches(['\r', '\n'])
            .split_once(':')
            .expect("the credential file holds one user:password line");
        Self {
            origin,
            user: user.to_owned(),
            password: password.to_owned(),
            log: PathBuf::from(named("KR_REAL_PROXY_ACCESS_LOG")),
        }
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
        let log = std::fs::read_to_string(&self.log).unwrap_or_default();
        log.lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                let [_, _, method, line_target, status, result, user] = fields[..] else {
                    return None;
                };
                if line_target != target {
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
        let deadline = Instant::now() + LOG_PATIENCE;
        loop {
            let lines = self.lines_to(target);
            if lines.len() >= count {
                return lines;
            }
            assert!(
                Instant::now() < deadline,
                "the proxy's log never held {count} line(s) for {target}: {lines:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
