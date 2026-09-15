//! The mutation payload digest.
//!
//! Section 23 requires a mutation digest to cover the method and version, the actor and grant, the
//! complete target, the preconditions, the action identifier, the freshness window and time to
//! live, and the parameters. Nothing is ever signed from parameters alone or from the diagnostic
//! JSON.
//!
//! `request_id` is deliberately **not** covered. It correlates a response on one connection, while
//! the durable identity is `action_id`. An exact retry over a new connection carries a new
//! `request_id` and must still produce the same digest, otherwise a legitimate retry would look
//! like a reused identifier with a different payload and be rejected as `ID_CONFLICT`.
//!
//! `action_window_id` **is** covered. Replacing an expired window therefore changes the payload,
//! which is what makes it a new first admission rather than an automatic retry.

use kr_cbor::{CanonicalMap, CanonicalValue, CborError, sha256, signing_value};

use crate::envelope::MutationRequest;
use crate::ids::ActorId;
use crate::scalars::Digest256;

/// The domain the mutation digest is separated by.
pub const MUTATION_DOMAIN: &str = "kr-mutation/1";

/// Builds the canonical signing input for a mutation.
///
/// # Errors
///
/// Returns a CBOR error when any covered field cannot be represented in KR-CBOR-1.
pub fn mutation_signing_input(
    request: &MutationRequest,
    actor_id: &ActorId,
) -> Result<Vec<u8>, CborError> {
    Ok(kr_cbor::encode(&mutation_signing_value(request, actor_id)?))
}

/// Builds the mutation signing input and returns its SHA-256 digest.
///
/// # Errors
///
/// Returns a CBOR error when any covered field cannot be represented in KR-CBOR-1.
pub fn mutation_digest(
    request: &MutationRequest,
    actor_id: &ActorId,
) -> Result<Digest256, CborError> {
    Ok(Digest256::from_bytes(sha256(&mutation_signing_input(
        request, actor_id,
    )?)))
}

/// Builds the mutation signing input as a canonical value.
///
/// # Errors
///
/// Returns a CBOR error when any covered field cannot be represented in KR-CBOR-1.
pub fn mutation_signing_value(
    request: &MutationRequest,
    actor_id: &ActorId,
) -> Result<CanonicalValue, CborError> {
    let mut covered = CanonicalMap::new();
    covered.insert(
        "action_id".to_owned(),
        kr_cbor::to_canonical_value(&request.action_id)?,
    )?;
    covered.insert(
        "action_window_id".to_owned(),
        kr_cbor::to_canonical_value(&request.action_window_id)?,
    )?;
    covered.insert(
        "actor_id".to_owned(),
        kr_cbor::to_canonical_value(actor_id)?,
    )?;
    covered.insert("expected".to_owned(), request.expected.as_value().clone())?;
    covered.insert(
        "grant_id".to_owned(),
        kr_cbor::to_canonical_value(&request.grant_id)?,
    )?;
    covered.insert(
        "method".to_owned(),
        kr_cbor::to_canonical_value(&request.method)?,
    )?;
    covered.insert(
        "method_version".to_owned(),
        kr_cbor::to_canonical_value(&request.method_version)?,
    )?;
    covered.insert("params".to_owned(), request.params.as_value().clone())?;
    covered.insert(
        "requested_ttl_ms".to_owned(),
        kr_cbor::to_canonical_value(&request.requested_ttl_ms)?,
    )?;
    covered.insert(
        "target".to_owned(),
        kr_cbor::to_canonical_value(&request.target)?,
    )?;
    Ok(signing_value(
        MUTATION_DOMAIN,
        vec![CanonicalValue::Map(covered)],
    ))
}
