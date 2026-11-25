//! A project's tree by what it is on the volume, never by how a path spells it.
//!
//! The chain holds the volume serial and the 128-bit identifier of every directory from the
//! volume's root down to the tree's root, taken from the handles the hold keeps open. A short name,
//! a `\\?\` form, a volume-GUID name or a substituted drive all lead to the same chain, and a
//! directory that differs by case only is the same directory on a volume that folds case.

use crate::filekey::FileKey;

/// The identity of a tree: the chain of its directories' keys, root of the volume first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeIdentity {
    /// The key of each directory from the volume's root to the tree's root.
    pub chain: Vec<FileKey>,
}
