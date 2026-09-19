//! The method-to-right mapping of section 23, read out of the registry.
//!
//! Section 10 declares the action vocabulary and then says "Exact method-to-right mappings are
//! required in section 23." [`kr_protocol::method::REGISTRY`] is that table, with one exhaustive
//! entry per method and a required-rights column on each. This module reads it; it does not
//! restate it. A second copy of a table like this drifts, and the copy that drifts is always the
//! one an authorisation check happens to read.
//!
//! What is here instead is the two questions a caller of the table asks that the table does not
//! answer in that shape: which rights a method needs, and which methods a right reaches.

use kr_protocol::authority::{RequiredAuthority, RightCondition};
use kr_protocol::method::{Method, REGISTRY};
use kr_protocol::rights::ActionRight;

/// Every right one method can require, including the ones required only under a condition.
///
/// A caller that wants to know what a method might ask for uses this. A caller deciding one actual
/// request uses [`super::decide`], which evaluates the conditions against that request.
#[must_use]
pub fn rights_for(method: Method) -> Vec<ActionRight> {
    let mut rights: Vec<ActionRight> = entry(method)
        .required_rights
        .iter()
        .filter_map(|required| match required.authority {
            RequiredAuthority::Right { right } => Some(right),
            _ => None,
        })
        .collect();
    rights.sort_unstable();
    rights.dedup();
    rights
}

/// The rights one method requires of every caller, whatever the request says.
#[must_use]
pub fn unconditional_rights_for(method: Method) -> Vec<ActionRight> {
    let mut rights: Vec<ActionRight> = entry(method)
        .required_rights
        .iter()
        .filter(|required| required.when == RightCondition::Always)
        .filter_map(|required| match required.authority {
            RequiredAuthority::Right { right } => Some(right),
            _ => None,
        })
        .collect();
    rights.sort_unstable();
    rights.dedup();
    rights
}

/// Every method one right reaches, in registry order.
///
/// This is how a person reading a grant finds out what it lets somebody do. A right that reaches
/// nothing is a right no method asks for, which the vocabulary test checks.
#[must_use]
pub fn methods_for(right: ActionRight) -> Vec<Method> {
    REGISTRY
        .iter()
        .filter(|entry| {
            entry
                .required_rights
                .iter()
                .any(|required| required.authority == RequiredAuthority::Right { right })
        })
        .map(|entry| entry.method)
        .collect()
}

fn entry(method: Method) -> &'static kr_protocol::authority::MethodEntry {
    REGISTRY
        .iter()
        .find(|entry| entry.method == method)
        .expect("every method has exactly one registry entry")
}
