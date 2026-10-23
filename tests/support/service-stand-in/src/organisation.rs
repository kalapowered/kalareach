//! An organisation's membership lease and policy-authority routes, answering as the Worker's do.
//!
//! A member's device asks the service for the lease its organisation signed for it, and for the
//! chain of keys that signs the organisation's leases. Both routes are proven by an account's
//! bearer token carrying the `organisation.lease` scope, and neither is a signed managed-service
//! request. The signing is the suite's: the keys belong to an organisation the suite holds, and the
//! stand-in asks the [`OrganisationAuthority`] it is given for what is signed.
//!
//! The source is the web repository's `workers/api/src/auth/routes.ts` (the lease route at about
//! :1480 and the policy-authority route at about :1750), `workers/api/src/auth/organisation.ts` and
//! the contract in `packages/service-contracts/src/auth.ts` (`MembershipLeaseRequest`,
//! `readMembershipLeaseRequest`, `MembershipLeaseResponse`). No answer of the Worker's has been
//! recorded for these routes: a local Worker issues the account system's tokens for backup only. So
//! every row about them is read from the source and held to nothing else.

use std::collections::BTreeMap;
use std::sync::Arc;

use kr_client::services::ServiceHttpAnswer;
use kr_protocol::account::{MembershipLease, PolicyAuthority};
use kr_protocol::scalars::AuthorisationKey;
use serde_json::Value;

use crate::web::{Token, refusal};

/// The scope the account's token carries to ask for a lease.
pub const LEASE_SCOPE: &str = "organisation.lease";

/// How long after a lease the Worker advises asking for the next, in seconds
/// (`MEMBERSHIP_LEASE_REFRESH_INTERVAL_MS`, `auth/durable/organisation-authority.ts:393`).
pub const REFRESH_AFTER_SECONDS: u64 = 300;

/// What an organisation signs, held by the suite that stands the organisation up.
pub trait OrganisationAuthority: Send + Sync + std::fmt::Debug {
    /// The lease the organisation signs for `account` and the device `device_key`, or none where
    /// the account is not a member of the organisation: a directory that deactivated the person
    /// removed the membership, so there is nothing to lease.
    fn lease(&self, account: &str, device_key: &AuthorisationKey) -> Option<MembershipLease>;

    /// The chain of keys that signs the organisation's leases, as it stands.
    fn authority(&self) -> PolicyAuthority;

    /// Whether `account` is a member, which reading the chain needs.
    fn is_member(&self, account: &str) -> bool;
}

/// The organisations the service signs for, by the identifier a route names.
#[derive(Debug, Default)]
pub(crate) struct Organisations {
    held: BTreeMap<String, Arc<dyn OrganisationAuthority>>,
}

impl Organisations {
    pub(crate) fn serve(&mut self, organisation: &str, authority: Arc<dyn OrganisationAuthority>) {
        self.held.insert(organisation.to_owned(), authority);
    }
}

/// Whether `path` is one of the organisation routes.
pub(crate) fn is_organisation_route(path: &str) -> bool {
    path.starts_with("/api/account/organisations/")
}

/// The success envelope.
fn ok(data: &Value) -> ServiceHttpAnswer {
    ServiceHttpAnswer {
        status: 200,
        body: serde_json::to_vec(&serde_json::json!({ "ok": true, "data": data }))
            .expect("an answer"),
    }
}

/// Answers one request on an organisation route.
///
/// `body` is the request's body as the service parsed it, or null when it carried none.
pub(crate) fn answer(
    organisations: &Organisations,
    tokens: &BTreeMap<String, Token>,
    path: &str,
    body: &Value,
    bearer: Option<&str>,
) -> ServiceHttpAnswer {
    let Some(rest) = path.strip_prefix("/api/account/organisations/") else {
        return refusal(404, "NOT_FOUND", "There is nothing at that address.");
    };
    let Some((organisation, tail)) = rest.split_once('/') else {
        return refusal(404, "NOT_FOUND", "There is nothing at that address.");
    };
    // A native application holds an account token, not a cookie. A token that is missing, one the
    // account system did not issue, one that has ended and one issued without the scope are one
    // answer: the caller is not signed in as far as this route can tell.
    let Some(account) = bearer
        .and_then(|bearer| tokens.get(bearer))
        .filter(|token| token.live && token.scopes.contains(LEASE_SCOPE))
        .map(|token| token.account.as_str())
    else {
        return refusal(401, "UNAUTHENTICATED", "Sign in to continue.");
    };
    // The Worker reads a lease request's body before it asks whether the account is a member, so a
    // request that is both malformed and from a stranger is answered as malformed.
    let requested = match tail {
        "lease" => match read_request(body) {
            Some(device_key) => Some(device_key),
            None => {
                return refusal(
                    400,
                    "INVALID_REQUEST",
                    "A lease request names the device it is for as device_key: the unpadded \
                     base64url of its 32-byte authorisation key.",
                );
            }
        },
        _ => None,
    };
    let not_a_member = || {
        refusal(
            403,
            "FORBIDDEN",
            "This account is not a member of that organisation.",
        )
    };
    let Some(authority) = organisations.held.get(organisation) else {
        return not_a_member();
    };
    match (tail, requested) {
        ("lease", Some(device_key)) => {
            authority
                .lease(account, &device_key)
                .map_or_else(not_a_member, |lease| {
                    ok(&serde_json::json!({
                        "lease": lease,
                        "refreshAfterSeconds": REFRESH_AFTER_SECONDS,
                    }))
                })
        }
        ("policy-authority", _) => {
            if authority.is_member(account) {
                ok(&serde_json::to_value(authority.authority()).expect("a chain"))
            } else {
                not_a_member()
            }
        }
        _ => refusal(404, "NOT_FOUND", "There is nothing at that address."),
    }
}

/// A lease request read against its closed shape (`readMembershipLeaseRequest`): an object that
/// carries a `device_key` that is the canonical unpadded base64url of exactly 32 bytes, and nothing
/// else.
fn read_request(body: &Value) -> Option<AuthorisationKey> {
    let object = body.as_object()?;
    if object.len() != 1 {
        return None;
    }
    let text = object.get("device_key")?.as_str()?;
    let key: AuthorisationKey = serde_json::from_value(Value::String(text.to_owned())).ok()?;
    // One spelling of one key: the text must be the canonical spelling of the bytes it decodes to.
    (kr_protocol::scalars::to_base64url(key.as_bytes()) == text).then_some(key)
}
