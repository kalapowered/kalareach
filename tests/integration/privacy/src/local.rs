//! A local deployment of the web service, as a person and a device meet it.
//!
//! A person signs in through a browser and deletes a backup collection from the account console; a
//! device receives a sign-in code by mail and a push registration's challenge through the provider.
//! None of that is a managed-service call, so none of it goes through the client's transport. This
//! module is that browser: plain requests to the deployment's account routes, with the session
//! cookie a browser would hold.
//!
//! # What is read beside the running service
//!
//! A local deployment sends no mail and reaches no provider, so the two things a device receives
//! from outside are read where the deployment keeps them, read-only, in the persistence directory
//! `wrangler dev` writes: the sign-in code from the account database's mail sink, which is the read
//! the web repository's development guide makes with `wrangler d1 execute --local`, and the
//! challenge from the installation's own object, which the web's push suite reads through its test
//! runtime. Each read is for the one address, installation and registration the leg asked about.
//! They stand in for a mailbox and a device, so they prove nothing about delivery by mail or by the
//! provider.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use kr_client::services::ServiceFuture;
use kr_client::services::account::{AccountToken, AccountTokenSource};
use kr_protocol::ids::{ArchiveId, InstallationId, PushRegistrationId};
use kr_protocol::service::GatewayOrigin;

use crate::{Deployment, ORIGIN_VARIABLE, STATE_VARIABLE, fresh_uuid, variable};

/// The desktop application as the authorisation server registers it: a public client whose
/// redirect is loopback on a fixed port.
const DESKTOP_CLIENT: &str = "kalareach-desktop";
const DESKTOP_REDIRECT: &str = "http://127.0.0.1:8765/oauth/callback";

/// The scopes the leg's account token carries: the identity claims and backup storage.
const TOKEN_SCOPES: &str = "openid profile email backup.write";

/// Another loopback origin, for the refusal a signed-in change from another site meets.
pub const ANOTHER_SITE: &str = "http://127.0.0.1:9";

/// One local deployment, reached as a device and as a browser reach it.
pub struct LocalStack {
    deployment: Deployment,
    origin: GatewayOrigin,
    state: PathBuf,
    http: reqwest::Client,
}

impl fmt::Debug for LocalStack {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalStack")
            .field("origin", &self.origin.as_str())
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// One answer from an account route: the status and the envelope.
#[derive(Clone, Debug, PartialEq)]
pub struct Answer {
    /// The HTTP status.
    pub status: u16,
    /// The envelope, or null when the body was not JSON.
    pub body: serde_json::Value,
}

impl Answer {
    /// The refusal's code, when the envelope is a refusal.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.body["error"]["code"].as_str()
    }
}

/// Where a signed-in change says it comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Site {
    /// The deployment's own site, as the console sends it.
    This,
    /// Another site, which the account routes refuse a change from.
    Another,
}

/// One account signed in on the deployment: its session, as a browser holds it, and an access token
/// for backup storage, as the desktop application holds it.
pub struct Account {
    address: String,
    session: String,
    token: AccountToken,
}

impl fmt::Debug for Account {
    /// The address. Never the session or the token.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Account")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl Account {
    /// The account's token, as the storage client asks for one.
    #[must_use]
    pub fn tokens(&self) -> Arc<dyn AccountTokenSource> {
        Arc::new(Given(self.token.clone()))
    }
}

/// A token the leg holds, handed out for whatever scope is asked: the service checks the scope it
/// was issued with.
#[derive(Debug)]
struct Given(AccountToken);

impl AccountTokenSource for Given {
    fn token<'a>(&'a self, _scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        let token = self.0.clone();
        Box::pin(async move { Ok(token) })
    }
}

impl LocalStack {
    /// The local deployment this run was given, or nothing when it was given none.
    ///
    /// # Panics
    ///
    /// Panics when the run was promised its services and a variable is missing, when the origin is
    /// not a loopback one (a deployment over HTTPS has no persistence directory to read beside it),
    /// and when the HTTP client cannot be built.
    #[must_use]
    pub fn from_environment() -> Option<Self> {
        let origin = variable(ORIGIN_VARIABLE)?;
        let state = variable(STATE_VARIABLE)?;
        assert!(
            origin.starts_with("http://127.0.0.1:"),
            "this leg reads beside a local deployment, and {ORIGIN_VARIABLE} does not name one"
        );
        let origin = GatewayOrigin::new(origin).expect("a loopback origin");
        // The device's transport first: building it installs the TLS provider this process uses,
        // which the browser's client needs installed before it is built.
        let deployment = Deployment::at(origin.clone());
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // Loopback, always, whatever proxy this machine's environment names.
            .no_proxy()
            .build()
            .expect("an HTTP client");
        Some(Self {
            deployment,
            origin,
            state: PathBuf::from(state),
            http,
        })
    }

    /// The deployment, as a device's managed-service clients reach it.
    #[must_use]
    pub const fn deployment(&self) -> &Deployment {
        &self.deployment
    }

    /// The deployment's origin.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        &self.origin
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin.as_str())
    }

    /// Signs a fresh account in as the desktop application does, through a code the mail sink kept.
    ///
    /// The code is sent to an address made for the call and read beside the deployment; the session
    /// the sign-in sets is the browser's; the desktop application is then authorised with a proof
    /// key, and the code it is given is exchanged for a token carrying backup storage's scope.
    ///
    /// # Panics
    ///
    /// Panics when any step is refused, and when the sink kept no code for the address.
    pub async fn sign_in(&self) -> Account {
        let address = format!("privacy-{}@example.test", fresh_uuid());
        let sent = self
            .http
            .post(self.url("/auth/email-otp/send-verification-otp"))
            .header("content-type", "application/json")
            .header("origin", self.origin.as_str())
            .body(serde_json::json!({ "email": address, "type": "sign-in" }).to_string())
            .send()
            .await
            .expect("the code was asked for");
        assert!(
            sent.status().is_success(),
            "sending a sign-in code: {}",
            sent.status()
        );
        let code = self
            .captured_code(&address)
            .expect("the deployment's mail sink kept a code for the address");

        let verified = self
            .http
            .post(self.url("/auth/sign-in/email-otp"))
            .header("content-type", "application/json")
            .header("origin", self.origin.as_str())
            .body(serde_json::json!({ "email": address, "otp": code }).to_string())
            .send()
            .await
            .expect("the code was presented");
        assert!(
            verified.status().is_success(),
            "signing in: {}",
            verified.status()
        );
        let session = verified
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| value.split(';').next())
            .collect::<Vec<_>>()
            .join("; ");
        assert!(!session.is_empty(), "the sign-in set no session");

        let mut secret = [0_u8; 32];
        kr_crypto::random_bytes(&mut secret).expect("a verifier");
        let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(kr_cbor::sha256(verifier.as_bytes()));
        let state = fresh_uuid().to_string();
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", DESKTOP_CLIENT),
                ("redirect_uri", DESKTOP_REDIRECT),
                ("scope", TOKEN_SCOPES),
                ("state", state.as_str()),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
            ])
            .finish();
        let authorised = self
            .http
            .get(self.url(&format!("/auth/oauth2/authorize?{query}")))
            .header("cookie", &session)
            .send()
            .await
            .expect("the application was authorised");
        let location = authorised
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let redirect = url::Url::parse(location).expect("the authorisation redirected");
        let pairs: Vec<(String, String)> = redirect.query_pairs().into_owned().collect();
        let named = |key: &str| {
            pairs
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(named("state").as_deref(), Some(state.as_str()));
        let granted = named("code").expect("the redirect carries a code");

        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("code", granted.as_str()),
                ("redirect_uri", DESKTOP_REDIRECT),
                ("client_id", DESKTOP_CLIENT),
                ("code_verifier", verifier.as_str()),
            ])
            .finish();
        let exchanged = self
            .http
            .post(self.url("/auth/oauth2/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .expect("the code was exchanged");
        assert!(
            exchanged.status().is_success(),
            "the token exchange: {}",
            exchanged.status()
        );
        let issued: serde_json::Value =
            serde_json::from_slice(&exchanged.bytes().await.expect("the token answer"))
                .expect("the token answer is JSON");
        let scopes = issued["scope"].as_str().unwrap_or_default();
        assert!(
            scopes.split(' ').any(|scope| scope == "backup.write"),
            "the token carries backup storage's scope"
        );
        let token = issued["access_token"]
            .as_str()
            .expect("the answer carries a token");
        Account {
            address,
            session,
            token: AccountToken::new(token).expect("a token a header can carry"),
        }
    }

    /// The backup collections the account's console lists, as `session` asks for them.
    ///
    /// # Panics
    ///
    /// Panics when the deployment cannot be reached.
    pub async fn collections(&self, session: Option<&Account>) -> Answer {
        let mut request = self
            .http
            .get(self.url("/api/account/backups"))
            .header("origin", self.origin.as_str());
        if let Some(account) = session {
            request = request.header("cookie", &account.session);
        }
        answer(request.send().await.expect("the listing was asked for")).await
    }

    /// The console's deletion of one backup collection.
    ///
    /// # Panics
    ///
    /// Panics when the deployment cannot be reached.
    pub async fn delete_collection(
        &self,
        session: Option<&Account>,
        from: Site,
        archive: ArchiveId,
    ) -> Answer {
        let origin = match from {
            Site::This => self.origin.as_str(),
            Site::Another => ANOTHER_SITE,
        };
        let mut request = self
            .http
            .post(self.url("/api/account/backups/delete"))
            .header("content-type", "application/json")
            .header("origin", origin)
            .body(serde_json::json!({ "archiveId": archive.to_string() }).to_string());
        if let Some(account) = session {
            request = request.header("cookie", &account.session);
        }
        answer(request.send().await.expect("the deletion was asked for")).await
    }

    /// The newest sign-in code the deployment's mail sink holds for `address`.
    fn captured_code(&self, address: &str) -> Option<String> {
        let root = self
            .state
            .join("v3")
            .join("d1")
            .join("miniflare-D1DatabaseObject");
        for file in databases(&root) {
            let Ok(connection) = read_only(&file) else {
                continue;
            };
            // Only the account database has the sink; any other answers with an error here.
            let body: Result<String, _> = connection.query_row(
                "SELECT body FROM auth_email_capture WHERE recipient = ?1 \
                 ORDER BY created_at DESC LIMIT 1",
                [address],
                |row| row.get(0),
            );
            if let Ok(body) = body {
                return body
                    .split(|character: char| !character.is_ascii_digit())
                    .find(|run| run.len() == 8)
                    .map(str::to_owned);
            }
        }
        None
    }

    /// The challenge the push gateway is waiting for, for one installation's one registration.
    ///
    /// The gateway keeps it in the installation's own object and sends it through the provider,
    /// which a local deployment never reaches. The object is found by the name it was addressed by,
    /// which is the installation's identifier.
    #[must_use]
    pub fn pending_challenge(
        &self,
        installation: InstallationId,
        registration: PushRegistrationId,
    ) -> Option<String> {
        let objects = self.state.join("v3").join("do");
        let class = std::fs::read_dir(&objects)
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with("-InstallationPush"))
            })?;
        let installation = installation.to_string();
        let registration = registration.to_string();
        for file in databases(&class) {
            let Ok(connection) = read_only(&file) else {
                continue;
            };
            let named: Result<i64, _> = connection.query_row(
                "SELECT count(*) FROM __miniflare_do_name WHERE name = ?1",
                [&installation],
                |row| row.get(0),
            );
            if named.ok() != Some(1) {
                continue;
            }
            return connection
                .query_row(
                    "SELECT challenge FROM pending_registration WHERE registration_id = ?1",
                    [&registration],
                    |row| row.get(0),
                )
                .ok();
        }
        None
    }
}

/// Every database file in one of the deployment's storage directories.
fn databases(directory: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(directory)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "sqlite")
                        && path
                            .file_name()
                            .is_some_and(|name| name != "metadata.sqlite")
                })
                .collect()
        })
        .unwrap_or_default()
}

/// One database, opened so that nothing this leg does can write to it.
fn read_only(file: &Path) -> rusqlite::Result<rusqlite::Connection> {
    rusqlite::Connection::open_with_flags(
        file,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

async fn answer(response: reqwest::Response) -> Answer {
    let status = response.status().as_u16();
    let bytes = response.bytes().await.unwrap_or_default();
    Answer {
        status,
        body: serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    }
}
