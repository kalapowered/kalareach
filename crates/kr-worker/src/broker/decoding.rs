//! What the worker takes of a component's decoding of a native request.
//!
//! A component that decodes a request proposes how it reads: the request it read, a one-line summary
//! of what answering yes would do, and the decisions it finds offered. The worker believes none of
//! it as it stands. The request a person will answer is the one the broker holds, the answers that
//! can be given are the ones the connector's table maps, and the words that name them are the
//! table's. So the proposal is turned into a [`DecodedProjection`] by [`project`], which refuses
//! anything the broker did not already know:
//!
//! * a request other than the one the component was handed;
//! * a decision the connector's table does not map to an answer, or one offered twice.
//!
//! The summary is carried whole. A summary longer than the decoder's trust allows is refused by the
//! trust's own check when the broker interprets the projection, and is never cut to fit, since a
//! shortened sentence can say something the component did not. The component's own class for the
//! method and the document nodes it proposes to present the request with are not part of the
//! proposal: the connector's table classifies a method, and a person answers an approval, not a
//! component's drawing of one.

use kr_protocol::broker::{DecodedProjection, OfferedDecision};

use crate::broker::connectors::component_schema;

/// What a component proposed when it decoded a native request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentDecoded {
    /// The identifier the upstream gave the request, as the component read it.
    pub request_id: String,
    /// A one-line summary of what answering yes would do.
    pub summary: String,
    /// The decisions the component finds offered, as the identifiers the table maps.
    pub decisions: Vec<String>,
}

/// A proposal the worker will not turn into an approval.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeRefusal {
    /// The component decoded some other request than the one it was handed.
    #[error("the component read request {read:?}, and the request it was handed is {pending:?}")]
    OtherRequest {
        /// The identifier the component named.
        read: String,
        /// The identifier of the request that is waiting.
        pending: String,
    },
    /// A decision the connector's table does not map to an answer.
    #[error("the component offered {id:?}, which the connector's table does not map to an answer")]
    UnmappedDecision {
        /// The identifier the component offered.
        id: String,
    },
    /// A decision offered more than once.
    #[error("the component offered {id:?} more than once")]
    DuplicateDecision {
        /// The identifier it repeated.
        id: String,
    },
}

/// Turns a component's proposal into the projection the broker interprets, or refuses it.
///
/// `pending` is the identifier the upstream gave the request that is waiting, and `table` is the
/// decisions the connector's table maps for it, labelled as the package's answer action labels
/// them. The projection offers the decisions the component named, in the order it named them, each
/// under the table's label and none under the component's.
///
/// # Errors
///
/// Returns the first thing the worker will not believe: another request, a decision the table does
/// not map, or a decision offered twice.
pub fn project(
    decoded: &ComponentDecoded,
    pending: &str,
    table: &[OfferedDecision],
) -> Result<DecodedProjection, DecodeRefusal> {
    if decoded.request_id != pending {
        return Err(DecodeRefusal::OtherRequest {
            read: decoded.request_id.clone(),
            pending: pending.to_owned(),
        });
    }
    let mut decisions: Vec<OfferedDecision> = Vec::with_capacity(decoded.decisions.len());
    for id in &decoded.decisions {
        let Some(mapped) = table.iter().find(|mapped| mapped.option_id == *id) else {
            return Err(DecodeRefusal::UnmappedDecision { id: id.clone() });
        };
        if decisions.iter().any(|offered| offered.option_id == *id) {
            return Err(DecodeRefusal::DuplicateDecision { id: id.clone() });
        }
        decisions.push(mapped.clone());
    }
    Ok(DecodedProjection {
        schema_version: component_schema(),
        summary: decoded.summary.clone(),
        decisions,
    })
}
