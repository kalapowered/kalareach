//! Inputs the rules of the surface's types are tried on, and whether each is accepted.
//!
//! A retained level records what its release's code made of each input. The rules are found
//! through their source as well (the walker); these are the cases a reader can see.

use kr_cbor::CanonicalValue;
use kr_protocol::ids::{ActorId, CapabilityId};
use kr_protocol::local::may_travel_to_a_worker;
use kr_protocol::question::{CALLER_TOKEN_BYTES, CallerToken};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, U64, Uuid};
use kr_protocol::session::Dimensions;
use kr_protocol::worker::RevisionReach;

fn text(value: &str) -> CanonicalValue {
    CanonicalValue::text(value)
}

/// Each probe with whether this build's code accepts it.
pub fn probes() -> Vec<(&'static str, bool)> {
    let long = "x".repeat(4096);
    let set_of = |items: &[&str]| -> bool {
        let value = CanonicalValue::Array(items.iter().map(|item| text(item)).collect());
        kr_cbor::from_canonical_value::<CanonicalSet<CapabilityId>>(&value).is_ok()
    };
    let mut with_voice = CanonicalSet::new();
    with_voice.insert(ActionRight::VoiceUse);
    vec![
        (
            "an identifier of plain text",
            ActorId::new("an-actor").is_ok(),
        ),
        ("an empty identifier", ActorId::new("").is_ok()),
        (
            "an identifier with a control character",
            ActorId::new("an\u{7}actor").is_ok(),
        ),
        (
            "an identifier with a newline",
            ActorId::new("an\nactor").is_ok(),
        ),
        ("an identifier past every limit", ActorId::new(long).is_ok()),
        ("a set in ascending order", set_of(&["a", "b"])),
        ("a set out of order", set_of(&["b", "a"])),
        ("a set with a repeated item", set_of(&["a", "a"])),
        (
            "a caller token of the right length",
            CallerToken::new(vec![0; CALLER_TOKEN_BYTES]).is_well_formed(),
        ),
        (
            "a caller token one byte short",
            CallerToken::new(vec![0; CALLER_TOKEN_BYTES - 1]).is_well_formed(),
        ),
        (
            "a set of rights that holds voice.use travels to a worker",
            may_travel_to_a_worker(&with_voice),
        ),
        (
            "an empty set of rights travels to a worker",
            may_travel_to_a_worker(&CanonicalSet::new()),
        ),
        (
            "a reach of the host is the host's",
            RevisionReach::Host.is_host(),
        ),
        (
            "a window of 80 by 24",
            Dimensions::new(80, 24).validate().is_ok(),
        ),
        ("a window of none", Dimensions::new(0, 0).validate().is_ok()),
        (
            "a number as an integer",
            kr_protocol::wire::from_value::<U64>(&CanonicalValue::Integer(7_u64.into())).is_ok(),
        ),
        (
            "a number as text",
            kr_protocol::wire::from_value::<U64>(&text("7")).is_ok(),
        ),
        (
            "a unique identifier of sixteen bytes",
            kr_protocol::wire::from_value::<Uuid>(&CanonicalValue::bytes(vec![1; 16])).is_ok(),
        ),
        (
            "a unique identifier of fifteen bytes",
            kr_protocol::wire::from_value::<Uuid>(&CanonicalValue::bytes(vec![1; 15])).is_ok(),
        ),
    ]
}
