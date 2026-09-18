//! A platform with no boundary of its own.
//!
//! macOS, Linux and Windows each have a mechanism this service can enclose an invocation with.
//! Anywhere else there is nothing to build one out of, so Git is not run at all. That is the whole
//! rule stated once: where a guarantee cannot be enforced from outside Git, the operation that
//! needs it is refused rather than run under checks that notice afterwards.

use std::ffi::OsString;
use std::path::PathBuf;

use super::{Confinement, Invocation};
use crate::error::{ProjectError, Result};

/// What the boundary is, for a person reading a record.
pub const MECHANISM: &str = "none: this platform has no boundary this service can build";

/// The boundary as the parent built it, which on this platform is never built at all.
#[derive(Debug)]
pub struct Prepared {
    never: std::convert::Infallible,
}

impl Prepared {
    /// Returns the program the child executes and the arguments it runs with.
    ///
    /// # Panics
    ///
    /// Never: no value of this type exists.
    pub fn command(&self, _invocation: &Invocation<'_>) -> (PathBuf, Vec<OsString>) {
        match self.never {}
    }

    /// Applies the boundary to this process.
    ///
    /// # Errors
    ///
    /// Never returns: no value of this type exists.
    pub fn apply(&mut self) -> std::io::Result<()> {
        match self.never {}
    }
}

/// Builds the boundary one invocation runs under.
///
/// # Errors
///
/// Always returns [`ProjectError::GitFailed`]: this platform has no mechanism to build one from.
pub fn prepare(_confinement: &Confinement) -> Result<Prepared> {
    Err(ProjectError::GitFailed {
        detail: "this platform has no boundary a Git invocation can be enclosed in, so none is \
                 run"
        .into(),
    })
}

/// Starts one Git invocation inside its boundary.
pub use super::unix::start;
