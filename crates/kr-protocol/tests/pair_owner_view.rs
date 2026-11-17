//! What a reader of an earlier shape of the issuing owner's view reads.
//!
//! A host that is newer than the reader sends the same bytes for every invitation that did not end
//! because the device is still listed, so the reader's strict decoder does not meet a member it
//! does not know.

use kr_cbor::{CanonicalValue, Limits};
use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::invitation::{
    ExistingPairing, InviteGrantKind, InviteModeKind, PairCandidateView, PairOwnerView,
    PairingApproval, PairingSecurityEvent,
};
use kr_protocol::pairing::{DeviceName, ProposedGrant, RendezvousOrigin};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The issuing owner's view as the earlier shape defines it: the same members and no `existing`,
/// read as strictly as the current one reads its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EarlierOwnerView {
    mode: InviteModeKind,
    rendezvous_origin: Nullable<RendezvousOrigin>,
    remaining_confirmations: u32,
    grant_kind: InviteGrantKind,
    proposed_grant: ProposedGrant,
    candidate: Nullable<PairCandidateView>,
    approval: Nullable<PairingApproval>,
    event: Nullable<PairingSecurityEvent>,
}

fn proposed_grant() -> ProposedGrant {
    ProposedGrant {
        parent_grant_id: Nullable::null(),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: [ActionRight::SessionView].into_iter().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: true,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::At {
            expires_at_ms: TimestampMs::new(1_800_000_000_000),
        },
        organisation: Nullable::null(),
    }
}

/// An open invitation's view, with no pairing the host lists.
fn view(existing: Option<ExistingPairing>) -> PairOwnerView {
    PairOwnerView {
        mode: InviteModeKind::Direct,
        rendezvous_origin: Nullable::null(),
        remaining_confirmations: 5,
        grant_kind: InviteGrantKind::SessionInvitation,
        proposed_grant: proposed_grant(),
        candidate: Nullable::null(),
        approval: Nullable::null(),
        event: Nullable::null(),
        existing,
    }
}

fn encoded(view: &PairOwnerView) -> Vec<u8> {
    let value = kr_cbor::to_canonical_value(view).expect("the view is a value");
    kr_cbor::encode(&value)
}

/// Whether the map `value` holds a member named `name`.
fn has_member(value: &CanonicalValue, name: &str) -> bool {
    let Some(map) = value.as_map() else {
        panic!("a view encodes as a map");
    };
    map.get(name).is_some()
}

/// KR-REQ-10.08: the view of an invitation that did not end because the device is still listed
/// carries no `existing` member, so a reader of the earlier shape, which refuses any member it does
/// not know, reads it and finds what the host's view said.
#[test]
fn a_view_with_no_listed_pairing_is_read_by_a_decoder_of_the_earlier_shape() {
    let current = view(None);
    let bytes = encoded(&current);
    let decoded = kr_cbor::decode(&bytes, &Limits::DEFAULT).expect("the bytes decode");
    assert!(
        !has_member(&decoded, "existing"),
        "the encoded view carries no existing member"
    );

    let earlier = kr_protocol::wire::decode::<EarlierOwnerView>(&bytes, &Limits::DEFAULT);
    assert!(
        earlier.is_ok(),
        "a decoder of the earlier shape reads the view: {earlier:?}"
    );
    let earlier = earlier.expect("read above");
    assert_eq!(earlier.mode, current.mode);
    assert_eq!(
        earlier.remaining_confirmations,
        current.remaining_confirmations
    );
    assert_eq!(earlier.proposed_grant, current.proposed_grant);

    // The earlier bytes are read by the current decoder as a view with no listed pairing.
    let reread = kr_protocol::wire::decode::<PairOwnerView>(
        &kr_cbor::encode(&kr_cbor::to_canonical_value(&earlier).expect("a value")),
        &Limits::DEFAULT,
    );
    assert_eq!(reread.ok(), Some(current), "the current decoder reads them");
}

/// KR-REQ-10.08: the view of an invitation that ended for a listed device carries the host's own
/// record of the device in its `existing` member, and a decoder of the current shape reads it back.
#[test]
fn a_view_with_a_listed_pairing_carries_it_and_reads_back() {
    let existing = ExistingPairing {
        device_name: DeviceName::new("Kitchen tablet").expect("a name"),
        paired_at_ms: TimestampMs::new(1_700_000_000_000),
    };
    let current = view(Some(existing));
    let bytes = encoded(&current);
    let decoded = kr_cbor::decode(&bytes, &Limits::DEFAULT).expect("the bytes decode");
    assert!(
        has_member(&decoded, "existing"),
        "the encoded view carries the listed pairing"
    );
    let reread = kr_protocol::wire::decode::<PairOwnerView>(&bytes, &Limits::DEFAULT);
    assert_eq!(reread.ok(), Some(current), "it reads back");
}
