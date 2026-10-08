//! What a recording of a local Worker's answers is made of, shared by the suites that hold a
//! stand-in to one: the transport that keeps every answer, the one that gives them back, the
//! journal of what the clients decoded, and the shapes the stand-in is compared by.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use kr_client::error::ClientError;
use kr_client::services::{ServiceFuture, ServiceHttp, ServiceHttpAnswer, ServiceSigner};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::scalars::{AuthorisationKey, Signature64};
use kr_protocol::service::ServiceRequestSigner;

/// The words of an answer that decide what a caller does with it, which a shape keeps verbatim.
pub const DECISIVE: [&str; 7] = [
    "code", "state", "backup", "reason", "ok", "removed", "mailbox",
];

/* -------------------------------------------------------------------------- */
/* What a run keeps                                                            */
/* -------------------------------------------------------------------------- */

/// One answer, as it came back.
#[derive(Clone, Debug)]
pub struct Exchange {
    step: String,
    path: String,
    status: u16,
    body: Vec<u8>,
}

/// What the script did, step by step.
#[derive(Debug, Default)]
pub struct Journal {
    pub step: Mutex<String>,
    pub exchanges: Mutex<Vec<Exchange>>,
    pub outcomes: Mutex<Vec<(String, String)>>,
    /// What this run made afresh that an answer repeats, in the order it was made: the identifiers
    /// of the keys it signed with, and the hash of each manifest it sealed, as an answer writes
    /// them.
    pub names: Mutex<Vec<String>>,
}

impl Journal {
    /// Keeps something this run made afresh that an answer may repeat.
    pub fn name(&self, text: String) {
        self.names.lock().expect("the names").push(text);
    }

    /// Names what the requests that follow are for.
    pub fn step(&self, name: &str) {
        *self.step.lock().expect("the step") = name.to_owned();
    }

    /// Keeps what the client made of the answers to the step in hand.
    pub fn decoded(&self, outcome: String) {
        let step = self.step.lock().expect("the step").clone();
        self.outcomes
            .lock()
            .expect("the outcomes")
            .push((step, outcome));
    }

    pub fn exchanges(&self) -> Vec<Exchange> {
        self.exchanges.lock().expect("the exchanges").clone()
    }

    pub fn outcomes(&self) -> Vec<(String, String)> {
        self.outcomes.lock().expect("the outcomes").clone()
    }
}

/// A transport that passes every request on and keeps every answer.
#[derive(Debug)]
pub struct Recording {
    pub inner: Arc<dyn ServiceHttp>,
    pub origin: String,
    pub journal: Arc<Journal>,
}

impl Recording {
    fn keep(&self, url: &str, answer: &ServiceHttpAnswer) {
        self.journal
            .exchanges
            .lock()
            .expect("the exchanges")
            .push(Exchange {
                step: self.journal.step.lock().expect("the step").clone(),
                path: url.strip_prefix(&self.origin).unwrap_or(url).to_owned(),
                status: answer.status,
                body: answer.body.clone(),
            });
    }
}

impl ServiceHttp for Recording {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            let answer = self.inner.post_json(url, body, headers).await?;
            self.keep(url, &answer);
            Ok(answer)
        })
    }

    fn post_bytes<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move {
            let answer = self.inner.post_bytes(url, body, headers).await?;
            self.keep(url, &answer);
            Ok(answer)
        })
    }
}

/// A transport that answers each request with the next answer the recording holds, whatever the
/// request said, once it has checked that the request is to the path the recording expects.
///
/// A key and an encrypted manifest are made afresh for each run, so an answer that names what the
/// recording made is given back naming what this run made in its place, and nothing else of it is
/// changed.
#[derive(Debug)]
pub struct Replaying {
    pub answers: Mutex<VecDeque<Exchange>>,
    pub recorded_names: Vec<String>,
    pub journal: Arc<Journal>,
}

impl Replaying {
    fn answer(&self, url: &str) -> ServiceHttpAnswer {
        let next = self
            .answers
            .lock()
            .expect("the answers")
            .pop_front()
            .unwrap_or_else(|| panic!("the client made a request to {url} the recording lacks"));
        assert!(
            url.ends_with(&next.path),
            "the client asked {url} where the recording expects {} for {}",
            next.path,
            next.step
        );
        let mut body = String::from_utf8_lossy(&next.body).into_owned();
        for (recorded, now) in self
            .recorded_names
            .iter()
            .zip(self.journal.names.lock().expect("the names").iter())
        {
            body = body.replace(recorded, now);
        }
        ServiceHttpAnswer {
            status: next.status,
            body: if next.body.is_ascii() {
                body.into_bytes()
            } else {
                next.body
            },
        }
    }
}

impl ServiceHttp for Replaying {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        _body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move { Ok(self.answer(url)) })
    }

    fn post_bytes<'a>(
        &'a self,
        url: &'a str,
        _body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        Box::pin(async move { Ok(self.answer(url)) })
    }
}

/* -------------------------------------------------------------------------- */
/* The keys, and the account                                                   */
/* -------------------------------------------------------------------------- */

/// An installation's key, or a host's, signing as it is.
#[derive(Debug)]
pub struct Keyed {
    pub key: AuthorisationKeyPair,
    pub signer: ServiceRequestSigner,
}

impl ServiceSigner for Keyed {
    fn signer(&self) -> ServiceRequestSigner {
        self.signer
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.key.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let transcript =
            SigningTranscript::from_canonical_bytes(self.signer.domain(), message.to_vec())
                .expect("a transcript");
        Ok(sign(&self.key, &transcript).expect("a signature"))
    }
}

/// An account token, as a source hands it over.
pub fn keyed(signer: ServiceRequestSigner) -> Arc<Keyed> {
    Arc::new(Keyed {
        key: AuthorisationKeyPair::generate().expect("a key"),
        signer,
    })
}

/// How a key identifier is written in an answer.
pub fn written(key: &Keyed) -> String {
    serde_json::to_value(key.key.key_id())
        .expect("a key identifier")
        .as_str()
        .expect("text")
        .to_owned()
}

/* -------------------------------------------------------------------------- */
/* What the client made of an answer                                           */
/* -------------------------------------------------------------------------- */

/// What a refusal or a failure is to a caller: the code, what a person does, and the delay named.
pub fn refused(error: &ClientError) -> String {
    let delay = match error {
        ClientError::Refused {
            retry_after_seconds,
            ..
        } => *retry_after_seconds,
        _ => None,
    };
    format!(
        "refused {:?}, {:?}, after {delay:?}",
        error.code(),
        error.user_action()
    )
}

/// What a decoded answer is, in the words of the values the caller acts on.
pub fn decoded<T>(answer: &Result<T, ClientError>, show: impl FnOnce(&T) -> String) -> String {
    match answer {
        Ok(answer) => show(answer),
        Err(error) => refused(error),
    }
}

pub fn debug<T: std::fmt::Debug>(value: &T) -> String {
    format!("{value:?}")
}

/* -------------------------------------------------------------------------- */
/* Shapes, and the record                                                      */
/* -------------------------------------------------------------------------- */

/// The shape of one JSON value: members and types, with the decisive words kept.
pub fn shape(key: &str, value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(members) => Value::Object(
            members
                .iter()
                .map(|(name, member)| (name.clone(), shape(name, member)))
                .collect(),
        ),
        Value::Array(items) => serde_json::json!({
            "array": items.first().map_or(Value::Null, |first| shape(key, first)),
        }),
        Value::String(text) if DECISIVE.contains(&key) => Value::String(text.clone()),
        Value::Bool(flag) if DECISIVE.contains(&key) => Value::Bool(*flag),
        Value::String(_) => Value::String("string".to_owned()),
        Value::Number(_) => Value::String("number".to_owned()),
        Value::Bool(_) => Value::String("boolean".to_owned()),
        Value::Null => Value::String("null".to_owned()),
    }
}

/// An answer's shape, or the word for an answer that is content and not a document.
pub fn shape_of(exchange: &Exchange) -> serde_json::Value {
    serde_json::from_slice::<serde_json::Value>(&exchange.body).map_or_else(
        |_| serde_json::json!("content"),
        |document| shape("", &document),
    )
}

/// An answer's body for the record: the document, or the content's bytes in base64.
pub fn body_of(exchange: &Exchange) -> serde_json::Value {
    serde_json::from_slice::<serde_json::Value>(&exchange.body).unwrap_or_else(|_| {
        serde_json::json!({
            "content_base64": base64::engine::general_purpose::STANDARD.encode(&exchange.body),
        })
    })
}

pub fn recorded(journal: &Journal, web_commit: &str) -> serde_json::Value {
    serde_json::json!({
        "recorded_from": "a Worker on this machine, started by infra/scripts/testing/local-restore.mjs",
        "web_commit": web_commit,
        "names": journal.names.lock().expect("the names").clone(),
        "exchanges": journal.exchanges().iter().map(|exchange| serde_json::json!({
            "step": exchange.step,
            "path": exchange.path,
            "status": exchange.status,
            "shape": shape_of(exchange),
            "body": body_of(exchange),
        })).collect::<Vec<_>>(),
        "decoded": journal.outcomes().iter().map(|(step, outcome)| serde_json::json!({
            "step": step,
            "outcome": outcome,
        })).collect::<Vec<_>>(),
    })
}

/// The recorded answers as exchanges a transport can give back.
pub fn held_exchanges(held: &serde_json::Value) -> Vec<Exchange> {
    held["exchanges"]
        .as_array()
        .expect("recorded exchanges")
        .iter()
        .map(|exchange| Exchange {
            step: exchange["step"].as_str().expect("a step").to_owned(),
            path: exchange["path"].as_str().expect("a path").to_owned(),
            status: u16::try_from(exchange["status"].as_u64().expect("a status"))
                .expect("a status"),
            body: match exchange["body"]["content_base64"].as_str() {
                Some(content) => base64::engine::general_purpose::STANDARD
                    .decode(content)
                    .expect("content"),
                None => serde_json::to_vec(&exchange["body"]).expect("a body"),
            },
        })
        .collect()
}

/// What the recording says each step decoded to.
pub fn held_outcomes(held: &serde_json::Value) -> Vec<(String, String)> {
    held["decoded"]
        .as_array()
        .expect("recorded outcomes")
        .iter()
        .map(|outcome| {
            (
                outcome["step"].as_str().expect("a step").to_owned(),
                outcome["outcome"].as_str().expect("an outcome").to_owned(),
            )
        })
        .collect()
}

/// The steps at which `ran` differs from `held`, in words.
pub fn differences(held: &[(String, String)], ran: &[(String, String)]) -> Vec<String> {
    let mut differing = Vec::new();
    for (index, (step, outcome)) in held.iter().enumerate() {
        match ran.get(index) {
            Some((ran_step, ran_outcome)) if ran_step == step && ran_outcome == outcome => {}
            Some((ran_step, ran_outcome)) => differing.push(format!(
                "{step}: the client decoded\n    {ran_outcome}\n  at {ran_step}, and the recording \
                 holds\n    {outcome}"
            )),
            None => differing.push(format!("{step}: this run made no such step")),
        }
    }
    if ran.len() > held.len() {
        differing.push(format!(
            "this run made {} steps and the recording holds {}",
            ran.len(),
            held.len()
        ));
    }
    differing
}
