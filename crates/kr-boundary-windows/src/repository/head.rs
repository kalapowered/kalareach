//! The grammar of a repository's `HEAD`: a symbolic reference to a branch, or an object
//! identifier. Anything else is refused by name before Git reads it.

use crate::frame::invocation::RefusedKind;
use crate::names::{BRANCH_PREFIX, is_branch_name, is_oid};
use crate::refusal::Refusal;

/// What `HEAD` holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeadKind {
    /// A symbolic reference to `refs/heads/<name>`, which may not exist yet.
    Branch {
        /// The branch's name.
        name: String,
    },
    /// An object identifier: a detached `HEAD`.
    Detached {
        /// The identifier, in lowercase hexadecimal.
        oid: String,
    },
}

/// Reads the bytes of `HEAD`: `ref: refs/heads/<name>` or an object identifier, with the single
/// newline Git writes after it or none.
///
/// A refusal names its rule and never what the file held: `head-form` for bytes that are neither,
/// `head-reference` for a symbolic reference to anything but `refs/heads/`, and `head-name` for a
/// branch name outside the grammar of [`crate::names::is_branch_name`].
///
/// # Errors
///
/// Returns a refusal of kind `repository` for any other form.
pub fn check_head(bytes: &[u8]) -> Result<HeadKind, Refusal> {
    let text = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if let Some(target) = text.strip_prefix(b"ref: ") {
        let Some(name) = target.strip_prefix(BRANCH_PREFIX.as_bytes()) else {
            return Err(refusal(
                "head-reference",
                "HEAD refers to something other than a branch",
            ));
        };
        return match std::str::from_utf8(name) {
            Ok(name) if is_branch_name(name) => Ok(HeadKind::Branch {
                name: name.to_owned(),
            }),
            _ => Err(refusal(
                "head-name",
                "HEAD refers to a branch whose name this release does not admit",
            )),
        };
    }
    match std::str::from_utf8(text) {
        Ok(oid) if is_oid(oid) => Ok(HeadKind::Detached {
            oid: oid.to_owned(),
        }),
        _ => Err(refusal(
            "head-form",
            "HEAD is neither a branch reference nor an object identifier",
        )),
    }
}

fn refusal(rule: &'static str, detail: &str) -> Refusal {
    Refusal::new(RefusedKind::Repository, rule, detail)
}
