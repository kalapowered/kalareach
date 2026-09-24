//! Signing in through the system browser: the request, the checks on its answer, the exchange, the
//! refresh, the one lock, sign-out and recovery.
//!
//! Section 17: native applications are registered public OAuth clients using the system browser,
//! the authorisation-code flow with S256 PKCE, exact registered redirects, state and issuer and
//! audience checks, rotating refresh tokens whose replay revokes the family, and native secure
//! storage. Each test names the rule it holds; where a rule is a check, the accepted answer sits
//! beside the refused one so that removing the check fails the test.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use kr_client::error::{ClientError, Result};
use kr_client::services::account::{
    ACCOUNT_ORIGIN, AUTHORIZE_PATH, AccountHttp, AccountIdentity, AccountService, AccountStatus,
    AccountToken, AccountTokenSource, AccountUsage, Answer, AnswerFault, AuthorisationGrant,
    AuthorisationRequest, Carrier, Client, Exchanged, ISSUER, IdentityRead, IssuedGrant,
    LEASE_SCOPE, ManagedAccountService, PendingAuthorisation, RELYING_PARTY_ID, REQUESTED_SCOPES,
    Redirect, RefreshToken, Refreshed, SignedInAccount, StoredGrant, TOKEN_PATH, USAGE_SCOPE,
    code_challenge,
};
use kr_client::services::{ServiceFuture, ServiceHttpAnswer};
use kr_crypto::store::{MemoryStore, SecretName, SecretStore};
use kr_protocol::error::{ErrorCode, ProtocolError};
use url::Url;

/* ---- The request --------------------------------------------------------------------------- */

/// RFC 7636 appendix B: this verifier gives this challenge under S256.
#[test]
fn the_s256_challenge_is_the_one_rfc_7636_gives() {
    assert_eq!(
        code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

fn parameters(url: &Url) -> BTreeMap<String, Vec<String>> {
    let mut all: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in url.query_pairs() {
        all.entry(name.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    all
}

fn base64url_43(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// KR-REQ-17.19: the hand-off goes to the fixed origin, whose host is the relying party, with
/// exactly the parameters the registered public client sends, for every client and redirect.
#[test]
fn a_request_names_the_fixed_origin_and_exactly_its_parameters() {
    for (client, redirect) in [
        (Client::Mobile, Redirect::AppLink),
        (Client::Mobile, Redirect::PrivateUse),
        (Client::Desktop, Redirect::Loopback),
    ] {
        let request = AuthorisationRequest::new(client, redirect).expect("a request");
        let url = Url::parse(&request.url()).expect("an address");
        assert_eq!(url.origin().ascii_serialization(), ACCOUNT_ORIGIN);
        assert_eq!(url.host_str(), Some(RELYING_PARTY_ID));
        assert_eq!(url.path(), AUTHORIZE_PATH);
        let parameters = parameters(&url);
        let names: Vec<&str> = parameters.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "client_id",
                "code_challenge",
                "code_challenge_method",
                "nonce",
                "prompt",
                "redirect_uri",
                "response_type",
                "scope",
                "state"
            ],
            "{client:?} {redirect:?}"
        );
        assert!(parameters.values().all(|values| values.len() == 1));
        let one = |name: &str| parameters[name][0].as_str();
        assert_eq!(one("response_type"), "code");
        assert_eq!(one("client_id"), client.id());
        assert_eq!(one("redirect_uri"), redirect.uri());
        assert_eq!(one("scope"), REQUESTED_SCOPES.join(" "));
        assert_eq!(one("code_challenge_method"), "S256");
        assert_eq!(one("prompt"), "login");
        for secret in ["state", "nonce", "code_challenge"] {
            assert!(base64url_43(one(secret)), "{secret}");
        }
        assert!(!url.as_str().contains("client_secret"));
        assert!(!url.as_str().contains("resource"));
    }
    assert_eq!(
        Redirect::PrivateUse.uri(),
        "to.kala.reach:/oauth/callback",
        "the private-use form: a reverse domain, one slash, no authority"
    );
}

/// A request's state, verifier, nonce and attempt are fresh every time.
#[test]
fn two_requests_share_no_state_verifier_nonce_or_attempt() {
    let first = AuthorisationRequest::new(Client::Desktop, Redirect::Loopback).expect("a request");
    let second = AuthorisationRequest::new(Client::Desktop, Redirect::Loopback).expect("a request");
    let (a, b) = (
        parameters(&Url::parse(&first.url()).expect("an address")),
        parameters(&Url::parse(&second.url()).expect("an address")),
    );
    for secret in ["state", "nonce", "code_challenge"] {
        assert_ne!(a[secret], b[secret], "{secret}");
    }
    assert_ne!(first.attempt(), second.attempt());
}

#[test]
fn a_redirect_another_client_registered_is_refused() {
    assert!(AuthorisationRequest::new(Client::Mobile, Redirect::Loopback).is_err());
    assert!(AuthorisationRequest::new(Client::Desktop, Redirect::AppLink).is_err());
    assert!(AuthorisationRequest::new(Client::Desktop, Redirect::PrivateUse).is_err());
}

/* ---- The answer ---------------------------------------------------------------------------- */

/// A request, the pending attempt holding it, and the state and challenge it sent.
fn attempt(client: Client, redirect: Redirect) -> (PendingAuthorisation, String, String) {
    let request = AuthorisationRequest::new(client, redirect).expect("a request");
    let sent = parameters(&Url::parse(&request.url()).expect("an address"));
    let state = sent["state"][0].clone();
    let challenge = sent["code_challenge"][0].clone();
    (PendingAuthorisation::new(request), state, challenge)
}

/// The redirect with `pairs` as its query, each encoded once.
fn callback(base: &str, pairs: &[(&str, &str)]) -> String {
    let mut url = Url::parse(base).expect("an address");
    {
        let mut query = url.query_pairs_mut();
        for (name, value) in pairs {
            query.append_pair(name, value);
        }
    }
    url.into()
}

fn good(redirect: Redirect, state: &str) -> String {
    callback(
        redirect.uri(),
        &[("code", "a-code"), ("state", state), ("iss", ISSUER)],
    )
}

/// KR-REQ-17.19: an answer on the attempt's own redirect with its state and the issuer becomes a
/// grant whose verifier is the one the challenge was made from.
#[test]
fn a_matching_answer_becomes_a_grant_bound_to_the_request() {
    for (client, redirect) in [
        (Client::Mobile, Redirect::AppLink),
        (Client::Mobile, Redirect::PrivateUse),
        (Client::Desktop, Redirect::Loopback),
    ] {
        let (mut pending, state, challenge) = attempt(client, redirect);
        let attempt = pending.attempt().expect("waiting");
        let Answer::Granted(grant) = pending.answer(&good(redirect, &state), Carrier::Terminal)
        else {
            panic!("{redirect:?}: a matching answer is a grant");
        };
        assert_eq!(grant.code(), "a-code");
        assert_eq!(grant.redirect(), redirect);
        assert_eq!(grant.client(), client);
        assert_eq!(grant.attempt(), attempt);
        assert_eq!(code_challenge(grant.verifier()), challenge);
        assert!(!pending.is_waiting(), "the request is consumed");
    }
}

#[test]
fn a_wrong_state_is_dropped_by_a_continuing_carrier_which_then_takes_the_right_answer() {
    let (mut pending, state, _) = attempt(Client::Desktop, Redirect::Loopback);
    let forged = callback(
        Redirect::Loopback.uri(),
        &[
            ("code", "a-code"),
            ("state", "not-the-state"),
            ("iss", ISSUER),
        ],
    );
    assert!(matches!(
        pending.answer(&forged, Carrier::Continuing),
        Answer::Dropped(AnswerFault::WrongState)
    ));
    assert!(pending.is_waiting());
    assert!(matches!(
        pending.answer(&good(Redirect::Loopback, &state), Carrier::Continuing),
        Answer::Granted(_)
    ));
}

#[test]
fn a_wrong_state_ends_a_terminal_carriers_attempt() {
    let (mut pending, state, _) = attempt(Client::Mobile, Redirect::AppLink);
    let forged = callback(
        Redirect::AppLink.uri(),
        &[
            ("code", "a-code"),
            ("state", "not-the-state"),
            ("iss", ISSUER),
        ],
    );
    assert!(matches!(
        pending.answer(&forged, Carrier::Terminal),
        Answer::Failed(AnswerFault::WrongState)
    ));
    assert!(!pending.is_waiting(), "no other answer can arrive");
    assert!(matches!(
        pending.answer(&good(Redirect::AppLink, &state), Carrier::Terminal),
        Answer::Failed(AnswerFault::WrongState)
    ));
}

/// Section 17: issuer checks. A mix-up answer is refused and nothing is exchanged.
#[test]
fn another_issuer_or_none_fails_and_grants_nothing() {
    for carrier in [Carrier::Terminal, Carrier::Continuing] {
        for issuer in [Some("https://evil.example/auth"), None] {
            let (mut pending, state, _) = attempt(Client::Mobile, Redirect::AppLink);
            let mut pairs = vec![("code", "a-code"), ("state", state.as_str())];
            if let Some(issuer) = issuer {
                pairs.push(("iss", issuer));
            }
            assert!(
                matches!(
                    pending.answer(&callback(Redirect::AppLink.uri(), &pairs), carrier),
                    Answer::Failed(AnswerFault::OtherIssuer)
                ),
                "{carrier:?} {issuer:?}"
            );
            assert!(!pending.is_waiting());
        }
    }
}

/// Section 17: exact registered redirects. Anything else is another address.
#[test]
fn an_answer_on_another_address_is_refused() {
    let cases: [(Redirect, &[&str]); 3] = [
        (
            Redirect::AppLink,
            &[
                "https://reach.kala.to.evil.example/app/oauth/callback",
                "http://reach.kala.to/app/oauth/callback",
                "https://reach.kala.to/app/oauth/callback/x",
                "https://reach.kala.to:8443/app/oauth/callback",
                "https://someone@reach.kala.to/app/oauth/callback",
                "to.kala.reach:/oauth/callback",
            ],
        ),
        (
            Redirect::PrivateUse,
            &[
                "to.kala.reach://oauth/callback",
                "to.kala.reach:/oauth/callback/x",
                "to.kala.reachx:/oauth/callback",
                "https://reach.kala.to/app/oauth/callback",
            ],
        ),
        (
            Redirect::Loopback,
            &[
                "http://127.0.0.1:8766/oauth/callback",
                "http://localhost:8765/oauth/callback",
                "https://127.0.0.1:8765/oauth/callback",
                "http://127.0.0.1:8765/oauth/callback/x",
            ],
        ),
    ];
    for (redirect, others) in cases {
        let client = if redirect == Redirect::Loopback {
            Client::Desktop
        } else {
            Client::Mobile
        };
        for other in others {
            let (mut pending, state, _) = attempt(client, redirect);
            let answer = callback(
                other,
                &[("code", "a-code"), ("state", &state), ("iss", ISSUER)],
            );
            assert!(
                matches!(
                    pending.answer(&answer, Carrier::Continuing),
                    Answer::Dropped(AnswerFault::OtherAddress)
                ),
                "{redirect:?} accepted {other}"
            );
            assert!(matches!(
                pending.answer(&good(redirect, &state), Carrier::Continuing),
                Answer::Granted(_)
            ));
        }
        // A fragment is another address as well.
        let (mut pending, state, _) = attempt(client, redirect);
        let fragment = format!("{}#x", good(redirect, &state));
        assert!(matches!(
            pending.answer(&fragment, Carrier::Terminal),
            Answer::Failed(AnswerFault::OtherAddress)
        ));
    }
}

/// A code is used once: the same answer delivered again finds no attempt waiting.
#[test]
fn a_repeated_answer_is_refused_the_second_time() {
    for carrier in [Carrier::Terminal, Carrier::Continuing] {
        let (mut pending, state, _) = attempt(Client::Desktop, Redirect::Loopback);
        let answer = good(Redirect::Loopback, &state);
        assert!(matches!(
            pending.answer(&answer, carrier),
            Answer::Granted(_)
        ));
        let again = pending.answer(&answer, carrier);
        assert!(
            matches!(
                again,
                Answer::Failed(AnswerFault::WrongState) | Answer::Dropped(AnswerFault::WrongState)
            ),
            "{carrier:?}: {again:?}"
        );
    }
}

#[test]
fn a_duplicated_parameter_is_refused() {
    for name in ["state", "code", "iss", "error"] {
        for carrier in [Carrier::Terminal, Carrier::Continuing] {
            let (mut pending, state, _) = attempt(Client::Desktop, Redirect::Loopback);
            let mut pairs = vec![
                ("code", "a-code"),
                ("state", state.as_str()),
                ("iss", ISSUER),
            ];
            let value = match name {
                "state" => state.as_str(),
                "iss" => ISSUER,
                "error" => "access_denied",
                _ => "a-code",
            };
            pairs.push((name, value));
            if name == "error" {
                pairs.push(("error", "access_denied"));
            }
            let answer = pending.answer(&callback(Redirect::Loopback.uri(), &pairs), carrier);
            match carrier {
                Carrier::Terminal => {
                    assert!(
                        matches!(answer, Answer::Failed(AnswerFault::Repeated)),
                        "{name}"
                    );
                    assert!(!pending.is_waiting(), "{name}");
                }
                Carrier::Continuing => {
                    assert!(
                        matches!(answer, Answer::Dropped(AnswerFault::Repeated)),
                        "{name}"
                    );
                    assert!(pending.is_waiting(), "{name}");
                }
            }
        }
    }
}

#[test]
fn access_denied_is_a_refusal_and_another_error_a_failure() {
    let (mut pending, state, _) = attempt(Client::Mobile, Redirect::AppLink);
    let refused = callback(
        Redirect::AppLink.uri(),
        &[
            ("error", "access_denied"),
            ("state", &state),
            ("iss", ISSUER),
        ],
    );
    assert!(matches!(
        pending.answer(&refused, Carrier::Terminal),
        Answer::Refused
    ));
    let (mut pending, state, _) = attempt(Client::Mobile, Redirect::AppLink);
    let failed = callback(
        Redirect::AppLink.uri(),
        &[
            ("error", "invalid_scope"),
            ("state", &state),
            ("iss", ISSUER),
        ],
    );
    assert!(matches!(
        pending.answer(&failed, Carrier::Terminal),
        Answer::Failed(AnswerFault::ServiceFailure)
    ));
    let (mut pending, state, _) = attempt(Client::Mobile, Redirect::AppLink);
    let empty = callback(
        Redirect::AppLink.uri(),
        &[("state", &state), ("iss", ISSUER)],
    );
    assert!(matches!(
        pending.answer(&empty, Carrier::Terminal),
        Answer::Failed(AnswerFault::NoCode)
    ));
}

/* ---- The service ----------------------------------------------------------------------------- */

/// What a scripted exchange saw, and what it answers next.
#[derive(Debug, Default)]
struct Scripted {
    answers: Mutex<VecDeque<ServiceHttpAnswer>>,
    seen: Mutex<Vec<(String, String, Vec<u8>)>>,
}

impl Scripted {
    fn answering(answers: Vec<(u16, serde_json::Value)>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(
                answers
                    .into_iter()
                    .map(|(status, body)| ServiceHttpAnswer {
                        status,
                        body: serde_json::to_vec(&body).expect("json"),
                    })
                    .collect(),
            ),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn next(&self) -> ServiceHttpAnswer {
        self.answers
            .lock()
            .expect("the script")
            .pop_front()
            .expect("the script has an answer for every request")
    }

    fn seen(&self) -> Vec<(String, String, Vec<u8>)> {
        self.seen.lock().expect("the record").clone()
    }
}

impl AccountHttp for Scripted {
    fn post_form<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        self.seen.lock().expect("the record").push((
            "POST".to_owned(),
            url.to_owned(),
            body.to_vec(),
        ));
        let answer = self.next();
        Box::pin(async move { Ok(answer) })
    }

    fn get<'a>(
        &'a self,
        url: &'a str,
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        self.seen
            .lock()
            .expect("the record")
            .push(("GET".to_owned(), url.to_owned(), Vec::new()));
        let answer = self.next();
        Box::pin(async move { Ok(answer) })
    }
}

/// The test clock: 2026-09-24 at noon, in seconds.
const NOW: u64 = 1_790_251_200;

fn now() -> u64 {
    NOW
}

/// An unsigned compact token with these claims; the signature is not what is checked.
fn id_token(claims: &serde_json::Value) -> String {
    let encode = |value: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(value).expect("json"))
    };
    format!(
        "{}.{}.signature",
        encode(&serde_json::json!({"alg": "RS256", "typ": "JWT"})),
        encode(claims)
    )
}

fn claims(client: Client, nonce: &str) -> serde_json::Value {
    serde_json::json!({
        "iss": ISSUER,
        "sub": "account-1",
        "aud": client.id(),
        "nonce": nonce,
        "iat": NOW - 5,
        "exp": NOW + 3600,
    })
}

fn token_answer(claims: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "access_token": "an-access-token",
        "token_type": "Bearer",
        "expires_in": 600,
        "refresh_token": "a-refresh-token",
        "scope": "openid profile email offline_access organisation.lease voice reasoning billing.read",
        "id_token": id_token(claims),
    })
}

/// A grant from a real answer to a real request, as the coordinator gets one.
fn granted(client: Client, redirect: Redirect) -> AuthorisationGrant {
    let (mut pending, state, _) = attempt(client, redirect);
    match pending.answer(&good(redirect, &state), Carrier::Terminal) {
        Answer::Granted(grant) => grant,
        other => panic!("a grant: {other:?}"),
    }
}

fn service(http: &Arc<Scripted>, client: Client) -> ManagedAccountService {
    ManagedAccountService::new(Arc::clone(http) as Arc<dyn AccountHttp>, client).with_clock(now)
}

fn form_fields(body: &[u8]) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

/// KR-REQ-17.23: the exchange is the form the service redeems, with the attempt's redirect and
/// verifier, and a good answer is issued.
#[tokio::test]
async fn a_good_exchange_is_issued_and_sends_the_form_the_service_redeems() {
    for (client, redirect) in [
        (Client::Mobile, Redirect::PrivateUse),
        (Client::Desktop, Redirect::Loopback),
    ] {
        let grant = granted(client, redirect);
        let http = Scripted::answering(vec![(200, token_answer(&claims(client, grant.nonce())))]);
        let Exchanged::Issued(issued) = service(&http, client)
            .exchange(&grant)
            .await
            .expect("an answer")
        else {
            panic!("a good answer is issued");
        };
        assert_eq!(issued.subject, "account-1");
        assert_eq!(issued.expires_in_seconds, 600);
        assert!(issued.scopes.iter().any(|scope| scope == USAGE_SCOPE));
        let seen = http.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "POST");
        assert_eq!(seen[0].1, format!("{ACCOUNT_ORIGIN}{TOKEN_PATH}"));
        let fields = form_fields(&seen[0].2);
        assert_eq!(fields["grant_type"], "authorization_code");
        assert_eq!(fields["code"], "a-code");
        assert_eq!(fields["redirect_uri"], redirect.uri());
        assert_eq!(fields["client_id"], client.id());
        assert_eq!(fields["code_verifier"], grant.verifier());
        assert_eq!(fields.len(), 5, "no secret and nothing else");
    }
}

/// Section 17: audience checks, and every other check on an exchange's answer. A failed answer
/// keeps nothing and hands back its refresh token to be revoked.
#[tokio::test]
async fn an_exchange_answer_failing_a_check_is_refused_and_hands_back_its_refresh_token() {
    let client = Client::Mobile;
    type Mutation = fn(&mut serde_json::Value, &mut serde_json::Value);
    let mutations: [(&str, Mutation, bool); 12] = [
        (
            "no refresh token",
            |answer, _| {
                answer
                    .as_object_mut()
                    .expect("an object")
                    .remove("refresh_token");
            },
            false,
        ),
        (
            "another token type",
            |answer, _| answer["token_type"] = serde_json::json!("mac"),
            true,
        ),
        (
            "no access token",
            |answer, _| {
                answer
                    .as_object_mut()
                    .expect("an object")
                    .remove("access_token");
            },
            true,
        ),
        (
            "no lifetime",
            |answer, _| answer["expires_in"] = serde_json::json!(0),
            true,
        ),
        (
            "no ID token",
            |answer, _| {
                answer
                    .as_object_mut()
                    .expect("an object")
                    .remove("id_token");
            },
            true,
        ),
        (
            "another issuer",
            |_, claims| claims["iss"] = serde_json::json!("https://evil.example/auth"),
            true,
        ),
        (
            "another audience",
            |_, claims| claims["aud"] = serde_json::json!("kalareach-desktop"),
            true,
        ),
        (
            "another nonce",
            |_, claims| claims["nonce"] = serde_json::json!("another"),
            true,
        ),
        (
            "no nonce",
            |_, claims| {
                claims.as_object_mut().expect("an object").remove("nonce");
            },
            true,
        ),
        (
            "another authorised party",
            |_, claims| claims["azp"] = serde_json::json!("kalareach-desktop"),
            true,
        ),
        (
            "expired",
            |_, claims| claims["exp"] = serde_json::json!(NOW - 3600),
            true,
        ),
        (
            "issued in the future",
            |_, claims| claims["iat"] = serde_json::json!(NOW + 3600),
            true,
        ),
    ];
    for (what, mutate, carries_refresh) in mutations {
        let grant = granted(client, Redirect::AppLink);
        let mut claims = claims(client, grant.nonce());
        let mut answer = token_answer(&claims);
        mutate(&mut answer, &mut claims);
        if answer.get("id_token").is_some() {
            answer["id_token"] = serde_json::json!(id_token(&claims));
        }
        let http = Scripted::answering(vec![(200, answer)]);
        let outcome = service(&http, client)
            .exchange(&grant)
            .await
            .expect("an answer");
        let Exchanged::Refused { leftover } = outcome else {
            panic!("{what}: refused");
        };
        assert_eq!(
            leftover.map(|token| token.expose().to_owned()),
            carries_refresh.then(|| "a-refresh-token".to_owned()),
            "{what}"
        );
    }
    // The control: an audience list naming the client, with the client as the authorised party,
    // is accepted.
    let grant = granted(client, Redirect::AppLink);
    let mut claims = claims(client, grant.nonce());
    claims["aud"] = serde_json::json!(["another-audience", client.id()]);
    claims["azp"] = serde_json::json!(client.id());
    let http = Scripted::answering(vec![(200, token_answer(&claims))]);
    assert!(matches!(
        service(&http, client)
            .exchange(&grant)
            .await
            .expect("an answer"),
        Exchanged::Issued(_)
    ));
}

#[tokio::test]
async fn a_refused_code_is_refused_and_a_failing_service_is_an_error() {
    let grant = granted(Client::Desktop, Redirect::Loopback);
    let http = Scripted::answering(vec![(400, serde_json::json!({"error": "invalid_grant"}))]);
    assert!(matches!(
        service(&http, Client::Desktop)
            .exchange(&grant)
            .await
            .expect("an answer"),
        Exchanged::Refused { leftover: None }
    ));
    let http = Scripted::answering(vec![(503, serde_json::json!({}))]);
    assert!(
        service(&http, Client::Desktop)
            .exchange(&grant)
            .await
            .is_err()
    );
}

fn stored(client: Client) -> StoredGrant {
    StoredGrant::new(
        IssuedGrant {
            access_token: AccountToken::new("an-access-token").expect("a token"),
            expires_in_seconds: 600,
            refresh_token: RefreshToken::new("a-refresh-token").expect("a token"),
            scopes: vec!["openid".to_owned(), "voice".to_owned()],
            subject: "account-1".to_owned(),
        },
        client,
        "the-sign-in-nonce",
        NOW * 1000,
    )
    .expect("a grant")
}

fn refresh_answer(claims: Option<serde_json::Value>) -> serde_json::Value {
    let mut answer = serde_json::json!({
        "access_token": "a-new-access-token",
        "token_type": "Bearer",
        "expires_in": 600,
        "refresh_token": "a-new-refresh-token",
        "scope": "openid voice",
    });
    if let Some(claims) = claims {
        answer["id_token"] = serde_json::json!(id_token(&claims));
    }
    answer
}

/// Section 17: rotating refresh tokens. A refresh answer is checked on its own terms against what
/// is stored, and asks nothing but the token endpoint.
#[tokio::test]
async fn a_refresh_answer_is_checked_against_the_stored_grant() {
    let client = Client::Desktop;
    let base = || {
        let mut claims = claims(client, "the-sign-in-nonce");
        claims.as_object_mut().expect("an object").remove("nonce");
        claims
    };
    let good: [(&str, serde_json::Value); 3] = [
        ("an ID token without a nonce", refresh_answer(Some(base()))),
        (
            "an ID token with the stored nonce",
            refresh_answer(Some(claims(client, "the-sign-in-nonce"))),
        ),
        ("no ID token", refresh_answer(None)),
    ];
    for (what, answer) in good {
        let http = Scripted::answering(vec![(200, answer)]);
        let outcome = service(&http, client)
            .refresh(&stored(client))
            .await
            .expect("an answer");
        let Refreshed::Rotated(issued) = outcome else {
            panic!("{what}: rotated");
        };
        assert_eq!(issued.refresh_token.expose(), "a-new-refresh-token");
        assert_eq!(
            http.seen().len(),
            1,
            "{what}: no identity read on a refresh"
        );
    }
    let mut other_subject = base();
    other_subject["sub"] = serde_json::json!("account-2");
    let other_nonce = claims(client, "another-nonce");
    let mut wider = refresh_answer(None);
    wider["scope"] = serde_json::json!("openid voice billing.read");
    let mut no_refresh = refresh_answer(None);
    no_refresh
        .as_object_mut()
        .expect("an object")
        .remove("refresh_token");
    let refused: [(&str, serde_json::Value, bool); 4] = [
        ("another subject", refresh_answer(Some(other_subject)), true),
        ("another nonce", refresh_answer(Some(other_nonce)), true),
        ("wider scopes", wider, true),
        ("no refresh token", no_refresh, false),
    ];
    for (what, answer, carries_refresh) in refused {
        let http = Scripted::answering(vec![(200, answer)]);
        let outcome = service(&http, client)
            .refresh(&stored(client))
            .await
            .expect("an answer");
        let Refreshed::Refused { leftover } = outcome else {
            panic!("{what}: refused");
        };
        assert_eq!(leftover.is_some(), carries_refresh, "{what}");
    }
    let http = Scripted::answering(vec![(400, serde_json::json!({"error": "invalid_grant"}))]);
    assert!(matches!(
        service(&http, client)
            .refresh(&stored(client))
            .await
            .expect("an answer"),
        Refreshed::Ended
    ));
    let http = Scripted::answering(vec![(503, serde_json::json!({}))]);
    assert!(
        service(&http, client)
            .refresh(&stored(client))
            .await
            .is_err()
    );
    let seen = Scripted::answering(vec![(200, refresh_answer(None))]);
    let _ = service(&seen, client).refresh(&stored(client)).await;
    let fields = form_fields(&seen.seen()[0].2);
    assert_eq!(fields["grant_type"], "refresh_token");
    assert_eq!(fields["refresh_token"], "a-refresh-token");
    assert_eq!(fields["client_id"], client.id());
}

/* ---- The signed-in account ------------------------------------------------------------------- */

/// A service whose answers the test decides, and which records what it was asked.
#[derive(Debug, Default)]
struct Stub {
    refreshes: AtomicUsize,
    /// When set, a refresh waits for a permit before it answers.
    held: Option<tokio::sync::Semaphore>,
    refresh_answer: Mutex<Option<RefreshAnswer>>,
    identity: Mutex<Option<std::result::Result<AccountIdentity, ErrorCode>>>,
    revoke_works: std::sync::atomic::AtomicBool,
    revoked: Mutex<Vec<String>>,
}

/// What the stub's next refresh answers, given how many refreshes it has seen.
struct RefreshAnswer(Box<dyn Fn(usize) -> Result<Refreshed> + Send + Sync>);

impl std::fmt::Debug for RefreshAnswer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RefreshAnswer")
    }
}

fn issued_for(subject: &str, refresh: &str, scopes: &[&str]) -> IssuedGrant {
    IssuedGrant {
        access_token: AccountToken::new(format!("{refresh}-access")).expect("a token"),
        expires_in_seconds: 600,
        refresh_token: RefreshToken::new(refresh).expect("a token"),
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        subject: subject.to_owned(),
    }
}

impl Stub {
    fn new() -> Self {
        let stub = Self::default();
        stub.revoke_works.store(true, Ordering::SeqCst);
        *stub.refresh_answer.lock().expect("the answer") = Some(RefreshAnswer(Box::new(|count| {
            Ok(Refreshed::Rotated(issued_for(
                "account-1",
                &format!("rotated-{count}"),
                &["openid", "voice", LEASE_SCOPE],
            )))
        })));
        stub
    }

    fn holding() -> Self {
        Self {
            held: Some(tokio::sync::Semaphore::new(0)),
            ..Self::new()
        }
    }

    fn answer_refresh(&self, answer: impl Fn(usize) -> Result<Refreshed> + Send + Sync + 'static) {
        *self.refresh_answer.lock().expect("the answer") = Some(RefreshAnswer(Box::new(answer)));
    }

    fn release(&self) {
        if let Some(held) = &self.held {
            held.add_permits(1);
        }
    }

    fn revoked(&self) -> Vec<String> {
        self.revoked.lock().expect("the record").clone()
    }
}

impl AccountService for Stub {
    fn exchange<'a>(&'a self, _grant: &'a AuthorisationGrant) -> ServiceFuture<'a, Exchanged> {
        Box::pin(async { panic!("these tests commit what an exchange issued") })
    }

    fn refresh<'a>(&'a self, _stored: &'a StoredGrant) -> ServiceFuture<'a, Refreshed> {
        Box::pin(async move {
            let count = self.refreshes.fetch_add(1, Ordering::SeqCst) + 1;
            if let Some(held) = &self.held {
                held.acquire().await.expect("a permit").forget();
            }
            let answer = self.refresh_answer.lock().expect("the answer");
            (answer.as_ref().expect("a refresh answer").0)(count)
        })
    }

    fn revoke<'a>(&'a self, refresh: &'a RefreshToken) -> ServiceFuture<'a, ()> {
        Box::pin(async move {
            if !self.revoke_works.load(Ordering::SeqCst) {
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::UpstreamUnavailable,
                    "the service cannot be reached".to_owned(),
                )));
            }
            self.revoked
                .lock()
                .expect("the record")
                .push(refresh.expose().to_owned());
            Ok(())
        })
    }

    fn identity<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, AccountIdentity> {
        let answer = self.identity.lock().expect("the identity").clone();
        Box::pin(async move {
            match answer.expect("an identity answer") {
                Ok(identity) => Ok(identity),
                Err(code) => Err(ClientError::Host(ProtocolError::new(
                    code,
                    "the identity could not be read".to_owned(),
                ))),
            }
        })
    }

    fn usage<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, AccountUsage> {
        Box::pin(async { Ok(AccountUsage::default()) })
    }
}

/// The test clock for the account, in milliseconds: set per test.
static CLOCK_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NOW * 1000);

fn clock_ms() -> u64 {
    CLOCK_MS.load(Ordering::SeqCst)
}

fn account(stub: &Arc<Stub>, store: &Arc<MemoryStore>) -> Arc<SignedInAccount> {
    Arc::new(
        SignedInAccount::new(
            Arc::clone(stub) as Arc<dyn AccountService>,
            Arc::clone(store) as Arc<dyn SecretStore>,
            Client::Desktop,
        )
        .with_clock(clock_ms),
    )
}

/// The stored grant's refresh token, read from the store itself.
fn stored_refresh(store: &MemoryStore) -> Option<String> {
    let bytes = store
        .get(&SecretName::new("account/session").expect("a name"))
        .expect("a read")?;
    let document: serde_json::Value = serde_json::from_slice(bytes.expose()).expect("json");
    document["refreshToken"].as_str().map(str::to_owned)
}

/// Serialises the tests that move the shared clock.
static CLOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Past the stored token's life, so the next `token()` refreshes.
fn expire() {
    CLOCK_MS.store(NOW * 1000 + 600_000, Ordering::SeqCst);
}

fn rewind() {
    CLOCK_MS.store(NOW * 1000, Ordering::SeqCst);
}

/// An expired token is refreshed once, and the rotation is kept before the token is handed out.
#[tokio::test]
async fn an_expired_token_is_refreshed_once_and_kept_before_it_is_handed_out() {
    let _clock = CLOCK.lock().await;
    rewind();
    let stub = Arc::new(Stub::new());
    let store = Arc::new(MemoryStore::new());
    let signed_in = account(&stub, &store);
    signed_in
        .commit(
            issued_for("account-1", "first", &["openid", "voice"]),
            "a-nonce",
        )
        .await
        .expect("a sign-in");
    let token = signed_in.token("voice").await.expect("a token");
    assert_eq!(
        token.expose(),
        "first-access",
        "a live token is not refreshed"
    );
    assert_eq!(stub.refreshes.load(Ordering::SeqCst), 0);
    expire();
    let token = signed_in.token("voice").await.expect("a token");
    assert_eq!(token.expose(), "rotated-1-access");
    assert_eq!(stub.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(stored_refresh(&store).as_deref(), Some("rotated-1"));
    rewind();
}

/// One lock: two callers at once cause one refresh.
#[tokio::test]
async fn two_callers_at_once_cause_one_refresh() {
    let _clock = CLOCK.lock().await;
    rewind();
    let stub = Arc::new(Stub::holding());
    let store = Arc::new(MemoryStore::new());
    let signed_in = account(&stub, &store);
    signed_in
        .commit(
            issued_for("account-1", "first", &["openid", "voice"]),
            "a-nonce",
        )
        .await
        .expect("a sign-in");
    expire();
    let (a, b) = (Arc::clone(&signed_in), Arc::clone(&signed_in));
    let first = tokio::spawn(async move { a.token("voice").await });
    let second = tokio::spawn(async move { b.token("voice").await });
    while stub.refreshes.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    stub.release();
    stub.release();
    let first = first.await.expect("a task").expect("a token");
    let second = second.await.expect("a task").expect("a token");
    assert_eq!(first, second);
    assert_eq!(stub.refreshes.load(Ordering::SeqCst), 1);
    rewind();
}

/// One lock: a sign-out that arrives during a refresh waits for it, then queues the rotated token,
/// and nothing can hand out a token afterwards.
#[tokio::test]
async fn a_sign_out_during_a_refresh_waits_and_revokes_the_rotated_token() {
    let _clock = CLOCK.lock().await;
    rewind();
    let stub = Arc::new(Stub::holding());
    let store = Arc::new(MemoryStore::new());
    let signed_in = account(&stub, &store);
    signed_in
        .commit(
            issued_for("account-1", "first", &["openid", "voice"]),
            "a-nonce",
        )
        .await
        .expect("a sign-in");
    expire();
    let refreshing = {
        let signed_in = Arc::clone(&signed_in);
        tokio::spawn(async move { signed_in.token("voice").await })
    };
    while stub.refreshes.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    let signing_out = {
        let signed_in = Arc::clone(&signed_in);
        tokio::spawn(async move { signed_in.sign_out().await })
    };
    tokio::task::yield_now().await;
    assert!(
        !signing_out.is_finished(),
        "the sign-out waits for the refresh"
    );
    stub.release();
    refreshing
        .await
        .expect("a task")
        .expect("the refresh finished first");
    let signed_out = signing_out.await.expect("a task").expect("a sign-out");
    assert!(signed_out.was_signed_in);
    assert!(signed_out.service_told);
    assert_eq!(
        stub.revoked(),
        ["rotated-1"],
        "the rotated token is the one revoked"
    );
    assert!(signed_in.token("voice").await.is_err());
    assert_eq!(stored_refresh(&store), None);
    rewind();
}

/// One lock: a sign-in committed during a refresh of an older grant leaves the new grant, and the
/// older one's rotated token is revoked.
#[tokio::test]
async fn a_sign_in_during_a_refresh_of_an_older_grant_keeps_the_new_grant() {
    let _clock = CLOCK.lock().await;
    rewind();
    let stub = Arc::new(Stub::holding());
    let store = Arc::new(MemoryStore::new());
    let signed_in = account(&stub, &store);
    signed_in
        .commit(
            issued_for("account-1", "first", &["openid", "voice"]),
            "a-nonce",
        )
        .await
        .expect("a sign-in");
    expire();
    let refreshing = {
        let signed_in = Arc::clone(&signed_in);
        tokio::spawn(async move { signed_in.token("voice").await })
    };
    while stub.refreshes.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    let committing = {
        let signed_in = Arc::clone(&signed_in);
        tokio::spawn(async move {
            signed_in
                .commit(
                    issued_for("account-2", "second", &["openid", "voice"]),
                    "b-nonce",
                )
                .await
        })
    };
    stub.release();
    refreshing.await.expect("a task").expect("a token");
    committing.await.expect("a task").expect("a sign-in");
    assert_eq!(stored_refresh(&store).as_deref(), Some("second"));
    assert_eq!(stub.revoked(), ["rotated-1"]);
    rewind();
}

/// Recovery: A's revocation pending and B signed in after it; at the next start B stays and A is
/// revoked.
#[tokio::test]
async fn recovery_keeps_a_later_sign_in_while_an_earlier_revocation_is_pending() {
    let _clock = CLOCK.lock().await;
    rewind();
    let stub = Arc::new(Stub::new());
    let store = Arc::new(MemoryStore::new());
    let signed_in = account(&stub, &store);
    signed_in
        .commit(issued_for("account-1", "grant-a", &["openid"]), "a-nonce")
        .await
        .expect("A");
    stub.revoke_works.store(false, Ordering::SeqCst);
    let out = signed_in.sign_out().await.expect("a sign-out");
    assert!(out.was_signed_in && !out.service_told);
    signed_in
        .commit(issued_for("account-1", "grant-b", &["openid"]), "b-nonce")
        .await
        .expect("B");
    stub.revoke_works.store(true, Ordering::SeqCst);
    let restarted = account(&stub, &store);
    assert_eq!(restarted.recover().await.expect("a recovery"), 0);
    assert_eq!(stored_refresh(&store).as_deref(), Some("grant-b"));
    assert_eq!(stub.revoked(), ["grant-a"]);
    assert!(matches!(
        restarted.status().expect("a status"),
        AccountStatus::SignedIn { .. }
    ));
}

/// Recovery: a grant whose own revocation is pending was being signed out when the last run
/// stopped, so it is removed.
#[tokio::test]
async fn a_grant_whose_own_revocation_is_pending_is_removed_at_start() {
    let _clock = CLOCK.lock().await;
    rewind();
    let stub = Arc::new(Stub::new());
    let store = Arc::new(MemoryStore::new());
    let signed_in = account(&stub, &store);
    signed_in
        .commit(issued_for("account-1", "grant-a", &["openid"]), "a-nonce")
        .await
        .expect("A");
    // The last run queued A's revocation and stopped before removing A.
    let session = store
        .get(&SecretName::new("account/session").expect("a name"))
        .expect("a read")
        .expect("A is stored");
    let grant_id =
        serde_json::from_slice::<serde_json::Value>(session.expose()).expect("json")["grantId"]
            .as_str()
            .expect("an identifier")
            .to_owned();
    let pending = serde_json::json!({"entries": [
        {"grantId": grant_id, "refreshToken": "grant-a", "queuedAtMs": NOW * 1000}
    ]});
    store
        .set(
            &SecretName::new("account/revoke").expect("a name"),
            &serde_json::to_vec(&pending).expect("json"),
        )
        .expect("a write");
    let restarted = account(&stub, &store);
    assert_eq!(restarted.recover().await.expect("a recovery"), 0);
    assert_eq!(stored_refresh(&store), None);
    assert_eq!(stub.revoked(), ["grant-a"]);
    assert_eq!(
        restarted.status().expect("a status"),
        AccountStatus::SignedOut
    );
}

/// A grant the service no longer honours ends; an unknown outcome keeps it for the next ask.
#[tokio::test]
async fn invalid_grant_ends_the_sign_in_and_an_unknown_outcome_keeps_it() {
    let _clock = CLOCK.lock().await;
    rewind();
    let stub = Arc::new(Stub::new());
    let store = Arc::new(MemoryStore::new());
    let signed_in = account(&stub, &store);
    signed_in
        .commit(
            issued_for("account-1", "first", &["openid", "voice"]),
            "a-nonce",
        )
        .await
        .expect("a sign-in");
    expire();
    stub.answer_refresh(|_| {
        Err(ClientError::Host(ProtocolError::new(
            ErrorCode::OutcomeUnknown,
            "the answer did not arrive".to_owned(),
        )))
    });
    let error = signed_in
        .token("voice")
        .await
        .expect_err("an unknown outcome");
    assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
    assert_eq!(stored_refresh(&store).as_deref(), Some("first"));
    stub.answer_refresh(|_| Ok(Refreshed::Ended));
    let error = signed_in.token("voice").await.expect_err("ended");
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(stored_refresh(&store), None);
    assert_eq!(signed_in.status().expect("a status"), AccountStatus::Ended);
    assert!(
        stub.revoked().is_empty(),
        "an ended grant has nothing to revoke"
    );
    rewind();
}

/// A refresh answer that failed a check ends the grant and revokes the token it carried.
#[tokio::test]
async fn a_refused_refresh_answer_ends_the_grant_and_revokes_its_token() {
    let _clock = CLOCK.lock().await;
    rewind();
    let stub = Arc::new(Stub::new());
    let store = Arc::new(MemoryStore::new());
    let signed_in = account(&stub, &store);
    signed_in
        .commit(
            issued_for("account-1", "first", &["openid", "voice"]),
            "a-nonce",
        )
        .await
        .expect("a sign-in");
    expire();
    stub.answer_refresh(|_| {
        Ok(Refreshed::Refused {
            leftover: Some(RefreshToken::new("leftover").expect("a token")),
        })
    });
    assert!(signed_in.token("voice").await.is_err());
    assert_eq!(stored_refresh(&store), None);
    assert_eq!(stub.revoked(), ["leftover"]);
    rewind();
}

/// A sign-out with the service out of reach signs this device out at once, and tells the service
/// at the next start.
#[tokio::test]
async fn a_sign_out_with_the_service_unreachable_signs_out_here_and_sends_later() {
    let _clock = CLOCK.lock().await;
    rewind();
    let stub = Arc::new(Stub::new());
    let store = Arc::new(MemoryStore::new());
    let signed_in = account(&stub, &store);
    signed_in
        .commit(issued_for("account-1", "grant-a", &["openid"]), "a-nonce")
        .await
        .expect("a sign-in");
    stub.revoke_works.store(false, Ordering::SeqCst);
    let out = signed_in.sign_out().await.expect("a sign-out");
    assert!(out.was_signed_in);
    assert!(!out.service_told);
    assert_eq!(
        signed_in.status().expect("a status"),
        AccountStatus::SignedOut
    );
    stub.revoke_works.store(true, Ordering::SeqCst);
    assert_eq!(
        account(&stub, &store).recover().await.expect("a recovery"),
        0
    );
    assert_eq!(stub.revoked(), ["grant-a"]);
}

/// The scoped source: a grant without a scope is never presented for it.
#[tokio::test]
async fn a_token_for_a_scope_the_grant_lacks_is_refused() {
    let _clock = CLOCK.lock().await;
    rewind();
    let stub = Arc::new(Stub::new());
    let store = Arc::new(MemoryStore::new());
    let signed_in = account(&stub, &store);
    assert_eq!(
        signed_in
            .token("openid")
            .await
            .expect_err("signed out")
            .code(),
        ErrorCode::HostNotConfigured
    );
    signed_in
        .commit(
            issued_for("account-1", "first", &["openid", "voice"]),
            "a-nonce",
        )
        .await
        .expect("a sign-in");
    let refused = signed_in
        .token(LEASE_SCOPE)
        .await
        .expect_err("no lease scope");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    assert!(signed_in.token("voice").await.is_ok());
    assert_eq!(
        signed_in.usage().await.expect("usage"),
        None,
        "no usage scope"
    );
}

/// After an exchange, userinfo naming another account undoes the sign-in; a userinfo failure keeps
/// it with the address unread; a good answer keeps the address.
#[tokio::test]
async fn the_identity_read_after_a_sign_in_is_held_to_the_sign_ins_subject() {
    let _clock = CLOCK.lock().await;
    rewind();
    let stub = Arc::new(Stub::new());
    let store = Arc::new(MemoryStore::new());
    let signed_in = account(&stub, &store);
    let sign_in = || issued_for("account-1", "grant", &["openid", "email", USAGE_SCOPE]);

    signed_in
        .commit(sign_in(), "a-nonce")
        .await
        .expect("a sign-in");
    *stub.identity.lock().expect("the identity") = Some(Err(ErrorCode::UpstreamUnavailable));
    assert_eq!(
        signed_in.complete_identity().await.expect("a read"),
        IdentityRead::Unread
    );
    assert!(matches!(
        signed_in.status().expect("a status"),
        AccountStatus::SignedIn { email: None, .. }
    ));

    *stub.identity.lock().expect("the identity") = Some(Ok(AccountIdentity {
        subject: "account-1".to_owned(),
        email: Some("sam@example.com".to_owned()),
        name: None,
    }));
    assert_eq!(
        signed_in.complete_identity().await.expect("a read"),
        IdentityRead::Read
    );
    assert!(matches!(
        signed_in.status().expect("a status"),
        AccountStatus::SignedIn { email: Some(ref email), .. } if email == "sam@example.com"
    ));

    *stub.identity.lock().expect("the identity") = Some(Ok(AccountIdentity {
        subject: "account-2".to_owned(),
        email: Some("someone@example.com".to_owned()),
        name: None,
    }));
    assert_eq!(
        signed_in.complete_identity().await.expect("a read"),
        IdentityRead::Disagreed
    );
    assert_eq!(
        signed_in.status().expect("a status"),
        AccountStatus::SignedOut
    );
    assert_eq!(stub.revoked(), ["grant"]);
}

/// The scoped source on a host: an imported token is refused for a scope it was not issued with,
/// and handed out for one it was.
#[tokio::test]
async fn an_imported_token_is_refused_for_a_scope_it_was_not_issued_with() {
    use kr_client::services::voice::{AccountTokenFile, StoredAccountToken, account_token_path};

    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let path = account_token_path(directory.path());
    let stored = StoredAccountToken::read(
        br#"{"origin":"https://reach.example","accessToken":"an-imported-token","scopes":["voice"]}"#,
    )
    .expect("a token document");
    kr_ipc::paths::write_owner_only_file(&path, &stored.write().expect("bytes"))
        .expect("the stored token");
    let source = AccountTokenFile::at(path).for_origin("https://reach.example");
    let refused = source.token(LEASE_SCOPE).await.expect_err("no lease scope");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    assert!(!refused.to_string().contains("an-imported-token"));
    assert_eq!(
        source
            .token("voice")
            .await
            .expect("the voice scope")
            .expose(),
        "an-imported-token"
    );
}
