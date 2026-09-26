//! Giving back what a leg's sync work took from a deployment.
//!
//! Every request identity the leg presented is fenced first, so a write whose answer the leg never
//! saw either has already run, and is removed below, or never will. Then every copy the service
//! kept is resolved and every object is removed under comparison, until a comparison finds the
//! collection empty. What the service keeps by its own rules stays, and no client may remove it: the
//! receipt of each identity for thirty days, a content-free record of each removed object's place
//! in the order, spent nonces, and the ledger's record of the installation.

use std::sync::Arc;

use kr_client::services::relay::ServiceSigner;
use kr_client::services::signed::SignedService;
use kr_client::services::sync::{MAX_SYNC_REQUEST_BYTES, SYNC_EXCHANGE_PATH};
use kr_protocol::method::Method;
use kr_sync_integration::{Deployment, RunKey};

use crate::held::Reached;

/// Gives back what `reached` names, and says what the service would not take back.
///
/// Every identity first, then every collection, and each is attempted whatever happened to the one
/// before it: a failure with one must not be why another keeps its content. Nothing is left when the
/// list is empty.
pub async fn give_back(
    deployment: &Deployment,
    key: &Arc<RunKey>,
    reached: &Reached,
) -> Vec<String> {
    let signed = SignedService::new(
        deployment.origin().clone(),
        deployment.transport(),
        Arc::clone(key) as Arc<dyn ServiceSigner>,
    );
    let mut left = Vec::new();
    for (identity, (collection, first, last)) in &reached.identities {
        // A fence answers a request that has run with its receipt and changes nothing, and it ends
        // one that has not, so after this no write of the leg's can still arrive.
        let fence = serde_json::json!({
            "fence": {
                "collection_id": collection,
                "request_id": identity,
                "first_signed_at_ms": first.to_string(),
                "last_signed_at_ms": last.to_string(),
            },
        });
        match sync_call(&signed, &fence).await {
            Ok(answer) => {
                if let Err(what) = ended(&answer, identity) {
                    left.push(what);
                }
            }
            Err(error) => left.push(format!("a request identity could not be ended: {error}")),
        }
    }
    for collection in &reached.collections {
        if let Err(what) = empty(&signed, collection).await {
            left.push(what);
        }
    }
    left
}

/// Holds a fence's answer to having ended the identity it named.
///
/// Only three answers end a request: the receipt of one that ran, applied or refused, and the fence
/// itself. Anything else leaves an upload that may still arrive, so a leg that took it for an end
/// could report a collection empty just before a delayed write filled it again.
fn ended(answer: &serde_json::Value, identity: &str) -> Result<(), String> {
    if answer["request_id"] != identity {
        return Err("a fence was answered about another request identity".to_owned());
    }
    if !answer["never_ran"].is_boolean() {
        return Err("a fence answer did not say whether the request ran".to_owned());
    }
    match answer["state"].as_str() {
        Some("applied" | "refused" | "fenced") => Ok(()),
        _ => Err("a fence answer did not end the request it named".to_owned()),
    }
}

/// Sends one settings-sync request as it is written.
async fn sync_call(
    signed: &SignedService,
    body: &serde_json::Value,
) -> kr_client::Result<serde_json::Value> {
    signed
        .call(
            SYNC_EXCHANGE_PATH,
            Method::SyncCompareExchange,
            body,
            MAX_SYNC_REQUEST_BYTES,
        )
        .await
}

/// Empties one collection, or says why it is not empty.
///
/// A bounded number of passes rather than a loop: a collection that always had more ends the leg
/// rather than holding it, and running out is a failure, because the collection still holds
/// something. A removal compares like any other write, so one that meets a write it did not expect
/// loses and the next pass reads the collection again.
async fn empty(signed: &SignedService, collection: &str) -> Result<(), String> {
    for _ in 0..4_u32 {
        let held = sync_call(
            signed,
            &serde_json::json!({ "compare": { "collection_id": collection, "with_conflicts": true } }),
        )
        .await
        .map_err(|error| format!("a collection could not be read: {error}"))?;
        let copies: Vec<serde_json::Value> = held["conflicts"]
            .as_array()
            .map(|copies| {
                copies
                    .iter()
                    .map(|copy| copy["conflict_id"].clone())
                    .collect()
            })
            .unwrap_or_default();
        let objects = held["changed"].as_array().cloned().unwrap_or_default();
        if copies.is_empty() && objects.is_empty() {
            let stored = &held["stored"];
            if stored["objects"] == "0" && stored["conflicts"] == "0" && stored["bytes"] == "0" {
                return Ok(());
            }
            return Err(format!(
                "a collection with nothing left to remove still counts {stored}"
            ));
        }
        if !copies.is_empty() {
            sync_call(
                signed,
                &serde_json::json!({
                    "resolve": { "collection_id": collection, "conflict_ids": copies },
                }),
            )
            .await
            .map_err(|error| format!("a collection's copies could not be dropped: {error}"))?;
        }
        for object in objects {
            // No request identity: a removal made to give back what a leg took leaves no receipt
            // of its own behind.
            sync_call(
                signed,
                &serde_json::json!({
                    "exchange": {
                        "collection_id": collection,
                        "kind": object["kind"],
                        "object_id": object["object_id"],
                        "expected_revision": object["revision"],
                        "object": null,
                    },
                }),
            )
            .await
            .map_err(|error| format!("an object could not be removed: {error}"))?;
        }
    }
    Err("a collection still held something after every pass this leg is allowed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_answer_that_ends_the_named_request_counts_as_ended() {
        for state in ["applied", "refused", "fenced"] {
            let answer =
                serde_json::json!({ "request_id": "a", "never_ran": false, "state": state });
            assert_eq!(ended(&answer, "a"), Ok(()), "{state}");
        }
        let about_another =
            serde_json::json!({ "request_id": "b", "never_ran": true, "state": "fenced" });
        assert!(ended(&about_another, "a").is_err());
        let silent = serde_json::json!({ "request_id": "a", "state": "fenced" });
        assert!(ended(&silent, "a").is_err());
        let open = serde_json::json!({ "request_id": "a", "never_ran": false, "state": "pending" });
        assert!(ended(&open, "a").is_err());
    }
}
