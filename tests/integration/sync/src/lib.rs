//! What a device and a deployment prove to each other.
//!
//! The mailbox, the durable authority feed and settings sync are reached over one signed HTTP
//! call each, and every other suite in this repository checks that call against something this
//! repository wrote: a mock, a loopback server, a runtime the service half runs inside. This one
//! checks it against a deployment. It seals a real envelope, signs a real credential, sends it to
//! the origin it is given and holds the answer to the rules sections 9, 10 and 20 state.
//!
//! # What it runs against, and what it leaves behind
//!
//! One environment variable names the origin: [`ORIGIN_VARIABLE`]. Without it every leg prints why
//! it did nothing and returns, so an ordinary test run of this workspace stays offline and green.
//! [`REQUIRE_VARIABLE`] set to `1` turns that absence into a failure, which is how a run that
//! promised a deployment finds out that it did not get one.
//!
//! Every principal is made for the run and held in memory: a fresh key signs, and the identifiers
//! the legs publish are drawn fresh as well, so a leg touches nothing that was not made for it. A
//! leg finishes by removing what the service lets it remove.

use std::sync::Arc;

use kr_client::services::authority::{AuthorityFeedClient, AuthorityFeedState};
use kr_client::services::mailbox::MailboxClient;
use kr_client::services::relay::{ServiceHttp, ServiceSigner};
use kr_client::services::{HttpDeadlines, HttpService, managed_response_limits};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::ids::DeviceId;
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{AuthorisationKey, KeyId, Signature64, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};

/// The variable naming the origin these legs run against.
pub const ORIGIN_VARIABLE: &str = "KR_DEPLOYED_ORIGIN";

/// The variable that turns a missing origin into a failure rather than a skip.
pub const REQUIRE_VARIABLE: &str = "KR_REQUIRE_DEPLOYED_ORIGIN";

/// The deployment one leg runs against.
#[derive(Debug, Clone)]
pub struct Deployment {
    origin: GatewayOrigin,
    transport: Arc<HttpService>,
}

impl Deployment {
    /// The deployment this run was given, or nothing when it was given none.
    ///
    /// # Panics
    ///
    /// Panics when [`REQUIRE_VARIABLE`] says this run was promised a deployment and
    /// [`ORIGIN_VARIABLE`] names none, and when the origin it names is not one a managed-service
    /// credential may travel to.
    #[must_use]
    pub fn from_environment() -> Option<Self> {
        let named = std::env::var(ORIGIN_VARIABLE).unwrap_or_default();
        if named.is_empty() {
            let required = std::env::var(REQUIRE_VARIABLE).is_ok_and(|value| value == "1");
            assert!(
                !required,
                "{REQUIRE_VARIABLE}=1 and {ORIGIN_VARIABLE} names no deployment, so this leg could not run"
            );
            eprintln!(
                "skipping: {ORIGIN_VARIABLE} names no deployment, so nothing was sent anywhere"
            );
            return None;
        }

        // The value is not in the message. An address may carry a user name and a password in
        // front of the host, and a variable that was set wrongly is exactly when one does.
        let origin = GatewayOrigin::new(named).unwrap_or_else(|error| {
            panic!("what {ORIGIN_VARIABLE} names is not an origin a credential travels to: {error}")
        });
        Some(Self::at(origin))
    }

    /// A deployment at one origin, with the bounds this client's operations are read under.
    ///
    /// # Panics
    ///
    /// Panics when the transport cannot be built, which is a fault in this machine's TLS
    /// configuration rather than in the deployment.
    #[must_use]
    pub fn at(origin: GatewayOrigin) -> Self {
        let transport = HttpService::with(
            origin.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .expect("a transport for the origin this run was given");
        Self {
            origin,
            transport: Arc::new(transport),
        }
    }

    /// The origin these legs address.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        &self.origin
    }

    /// The transport every client of this deployment shares.
    ///
    /// One transport, so a leg that speaks as an owner and as a host uses one set of connections
    /// rather than one each. A leg that sends a request no client of this crate will build takes
    /// this and its own signer.
    #[must_use]
    pub fn transport(&self) -> Arc<dyn ServiceHttp> {
        Arc::clone(&self.transport) as Arc<_>
    }

    /// An authority-feed client signing as `who`.
    #[must_use]
    pub fn authority_feed(&self, who: &Arc<RunKey>) -> AuthorityFeedClient {
        AuthorityFeedClient::new(
            self.origin.clone(),
            self.transport(),
            Arc::clone(who) as Arc<_>,
        )
    }

    /// A mailbox client signing as `who`.
    #[must_use]
    pub fn mailbox(&self, who: &Arc<RunKey>) -> MailboxClient {
        MailboxClient::new(
            self.origin.clone(),
            self.transport(),
            Arc::clone(who) as Arc<_>,
        )
    }
}

/// One principal, made for this run and held in memory.
///
/// The key is generated when the leg starts and discarded when it ends, so nothing a leg signs
/// outlives it and no key of a real device is ever used.
#[derive(Debug)]
pub struct RunKey {
    pair: AuthorisationKeyPair,
    kind: ServiceRequestSigner,
    device_id: DeviceId,
}

impl RunKey {
    /// A device signing as an installation: a remote owner publishing to somebody's feed.
    ///
    /// # Panics
    ///
    /// Panics when a key cannot be generated.
    #[must_use]
    pub fn installation() -> Arc<Self> {
        Self::of(ServiceRequestSigner::Installation)
    }

    /// A device signing as a host: the owner of the feed it addresses.
    ///
    /// # Panics
    ///
    /// Panics when a key cannot be generated.
    #[must_use]
    pub fn host() -> Arc<Self> {
        Self::of(ServiceRequestSigner::Host)
    }

    fn of(kind: ServiceRequestSigner) -> Arc<Self> {
        Arc::new(Self {
            pair: AuthorisationKeyPair::generate().expect("a fresh authorisation key"),
            kind,
            device_id: DeviceId::new(fresh_uuid()),
        })
    }

    /// The signing key itself, for the records this device signs rather than the credential.
    #[must_use]
    pub const fn pair(&self) -> &AuthorisationKeyPair {
        &self.pair
    }

    /// The identifier this device's authorisation key derives, which is the feed it addresses.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        kr_crypto::keys::key_id(KeyPurpose::Authorisation, self.pair.public().as_bytes())
    }

    /// The device identifier this run gave it.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }
}

impl ServiceSigner for RunKey {
    fn signer(&self) -> ServiceRequestSigner {
        self.kind
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.pair.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        // The transcript refuses bytes that are not a domain-tagged array, so a signer cannot be
        // handed arbitrary bytes to sign under a domain it holds a key for.
        let transcript =
            SigningTranscript::from_canonical_bytes(self.kind.domain(), message.to_vec())
                .expect("a domain-tagged credential");
        Ok(sign(&self.pair, &transcript).expect("a signature"))
    }
}

/// A fresh identifier, drawn for this run alone.
///
/// # Panics
///
/// Panics when the operating system's generator cannot be read.
#[must_use]
pub fn fresh_uuid() -> Uuid {
    let mut bytes = [0u8; 16];
    kr_crypto::random_bytes(&mut bytes).expect("an identifier for this run");
    Uuid::from_bytes(bytes)
}

/// This machine's clock, in UTC milliseconds.
///
/// # Panics
///
/// Panics when the clock is before the epoch.
#[must_use]
pub fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock at or after the epoch")
            .as_millis(),
    )
    .expect("a clock this century")
}

/// Says what one leg proved, in the words the report uses.
///
/// A leg that ran prints one line naming the deployment it ran against and the rule it held that
/// deployment to, so the output reads as a report rather than as test output.
pub fn proved(leg: &str, deployment: &Deployment, what: &str) {
    println!("{leg}: {what} ({})", deployment.origin().as_str());
}

/// The words the deployment checkpoint finds a leg's leftovers by.
///
/// `scripts/e2e-deployment.sh` collects every line of a leg's output that holds them and names what
/// follows as something the leg left on the deployment.
pub const GIVE_BACK: &str = "give back what it took";

/// What one authority-feed leg's cleanup left, one line for each part that did not finish.
///
/// The cleanup removes the leg's host from the feed, which ends the retention of every record the
/// host had not applied, and acknowledges any announcement the leg placed in the host's mailbox.
/// The removal has finished only when the feed says the host is removed and retains nothing for it.
/// Every part that did not finish is its own line, in [`GIVE_BACK`]'s words, so the checkpoint names
/// each of them and a second failure is never hidden behind the first. Nothing is left when the
/// list is empty. A leg reports these lines whether its own work passed or failed.
#[must_use]
pub fn authority_feed_left(
    removed: &kr_client::Result<AuthorityFeedState>,
    emptied: &Result<(), String>,
) -> Vec<String> {
    let mut left = Vec::new();
    match removed {
        Ok(state) => {
            if !state.summary.removed {
                left.push(not_given_back("the feed does not report the host removed"));
            }
            let outstanding = state.summary.outstanding.get();
            if outstanding != 0 {
                left.push(not_given_back(&format!(
                    "the feed still retains {outstanding} records the host had not applied"
                )));
            }
        }
        Err(error) => left.push(not_given_back(&format!(
            "the host could not remove itself from the feed: {error}"
        ))),
    }
    if let Err(what) = emptied {
        left.push(not_given_back(what));
    }
    left
}

/// One line of what a leg left, as the checkpoint reads it.
///
/// One line whatever the failure said: the checkpoint reads a leg's output line by line, so a line
/// break inside a failure would cut what follows it out of the report. Every control character is
/// written as its escape instead.
fn not_given_back(what: &str) -> String {
    let mut line = format!("this leg could not {GIVE_BACK}: ");
    for character in what.chars() {
        match character {
            '\n' => line.push_str("\\n"),
            '\r' => line.push_str("\\r"),
            '\t' => line.push_str("\\t"),
            control if control.is_control() => {
                line.push_str(&format!("\\u{{{:x}}}", u32::from(control)));
            }
            other => line.push(other),
        }
    }
    line
}

/// A service that answers nothing, for the legs that prove what an unavailable feed means.
///
/// It holds a loopback port of its own for as long as the leg holds this, so nothing else can be
/// listening on the address a leg is calling: a port that was probed and released could be taken
/// between the probe and the request. Every connection it accepts it closes at once, so an exchange
/// against it ends where the bytes are, immediately and without a deadline or an interval anywhere
/// in it.
pub struct SilentService {
    origin: GatewayOrigin,
    accepting: tokio::task::JoinHandle<()>,
}

impl SilentService {
    /// Starts one on a loopback port the operating system chooses.
    ///
    /// # Panics
    ///
    /// Panics when a loopback port cannot be taken.
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("the port it took").port();
        let accepting = tokio::spawn(async move {
            // Accepted and dropped. The caller's request reaches a socket and the socket closes,
            // which is a service that answered nothing rather than a connection left hanging.
            while let Ok((connection, _)) = listener.accept().await {
                drop(connection);
            }
        });

        Self {
            origin: GatewayOrigin::new(format!("http://127.0.0.1:{port}"))
                .expect("a loopback origin"),
            accepting,
        }
    }

    /// The origin it answers nothing on.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        &self.origin
    }

    /// A deployment pointed at it.
    #[must_use]
    pub fn deployment(&self) -> Deployment {
        Deployment::at(self.origin.clone())
    }
}

impl Drop for SilentService {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

#[cfg(test)]
mod tests {
    use kr_client::services::authority::AuthorityFeedSummary;
    use kr_protocol::error::{ErrorCode, ProtocolError};
    use kr_protocol::scalars::{Nullable, U64};

    use super::*;

    /// What a feed answers a removal with.
    fn answered(removed: bool, outstanding: u64) -> kr_client::Result<AuthorityFeedState> {
        Ok(AuthorityFeedState {
            host_key_id: KeyId::from_bytes([1; 32]),
            host_device_id: Nullable::null(),
            records: Vec::new(),
            next_after_sequence: U64::new(0),
            more: false,
            summary: AuthorityFeedSummary {
                authority_revision: Nullable::null(),
                revised_at: Nullable::null(),
                last_acknowledgement: Nullable::null(),
                acknowledged_at: Nullable::null(),
                outstanding: U64::new(outstanding),
                removed,
                removal_keys: Vec::new(),
                poll_interval_seconds: 60,
            },
            announced: None,
        })
    }

    /// A removal the feed never answered.
    fn unanswered() -> kr_client::Result<AuthorityFeedState> {
        Err(kr_client::ClientError::Host(ProtocolError::new(
            ErrorCode::UpstreamUnavailable,
            "the feed could not be reached",
        )))
    }

    /// Every line reads the way the checkpoint collects it: its words, then what was left.
    fn what_the_checkpoint_names(left: &[String]) -> Vec<String> {
        left.iter()
            .map(|line| {
                let (_, what) = line
                    .split_once(&format!("{GIVE_BACK}: "))
                    .expect("the line holds the checkpoint's words");
                what.to_owned()
            })
            .collect()
    }

    #[test]
    fn a_cleanup_that_finished_leaves_nothing_to_name() {
        assert!(authority_feed_left(&answered(true, 0), &Ok(())).is_empty());
    }

    #[test]
    fn a_removal_that_did_not_finish_is_named_on_its_own() {
        let unreached = authority_feed_left(&unanswered(), &Ok(()));
        assert_eq!(unreached.len(), 1, "{unreached:?}");
        assert!(
            what_the_checkpoint_names(&unreached)[0]
                .starts_with("the host could not remove itself from the feed: "),
            "{unreached:?}"
        );

        let kept = authority_feed_left(&answered(false, 0), &Ok(()));
        assert_eq!(
            what_the_checkpoint_names(&kept),
            vec!["the feed does not report the host removed".to_owned()]
        );

        let retained = authority_feed_left(&answered(true, 2), &Ok(()));
        assert_eq!(
            what_the_checkpoint_names(&retained),
            vec!["the feed still retains 2 records the host had not applied".to_owned()]
        );
    }

    #[test]
    fn a_mailbox_that_was_not_emptied_is_named_on_its_own() {
        let left = authority_feed_left(
            &answered(true, 0),
            &Err("the announcement mailbox could not be read: refused".to_owned()),
        );
        assert_eq!(
            what_the_checkpoint_names(&left),
            vec!["the announcement mailbox could not be read: refused".to_owned()]
        );
    }

    /// A failure whose text runs over several lines is still one line of the report, so the
    /// checkpoint, which reads line by line, names all of it.
    #[test]
    fn a_failure_over_several_lines_is_reported_on_one() {
        let left = authority_feed_left(
            &answered(true, 0),
            &Err("the mailbox refused:\nfirst line\r\nsecond line\u{7}".to_owned()),
        );
        assert_eq!(left.len(), 1, "{left:?}");
        assert_eq!(left[0].lines().count(), 1, "{left:?}");
        assert!(!left[0].contains(['\n', '\r', '\u{7}']), "{left:?}");
        assert_eq!(
            what_the_checkpoint_names(&left),
            vec!["the mailbox refused:\\nfirst line\\r\\nsecond line\\u{7}".to_owned()]
        );
    }

    /// The case the report exists for: two parts failed, and the second is not hidden behind the
    /// first.
    #[test]
    fn two_parts_that_did_not_finish_are_both_named() {
        let left = authority_feed_left(
            &answered(false, 3),
            &Err("the announcement mailbox could not be acknowledged: refused".to_owned()),
        );
        assert_eq!(
            what_the_checkpoint_names(&left),
            vec![
                "the feed does not report the host removed".to_owned(),
                "the feed still retains 3 records the host had not applied".to_owned(),
                "the announcement mailbox could not be acknowledged: refused".to_owned(),
            ]
        );

        let left = authority_feed_left(
            &unanswered(),
            &Err("the announcement mailbox could not be read: refused".to_owned()),
        );
        assert_eq!(left.len(), 2, "{left:?}");
        assert!(left.iter().all(|line| line.contains(GIVE_BACK)), "{left:?}");
    }
}
