//! What this crate refuses, and why.
//!
//! Two kinds of thing live here and they are deliberately not mixed. An error is a request this
//! crate would not carry out: a profile it will not run, an asset that is not the one that was
//! qualified, a store it cannot open. A *rejection* is not an error at all: a model result that
//! fails validation is an ordinary outcome of asking a model for something, and it is reported as
//! [`crate::output::Rejection`] beside the deterministic title that is shown instead.

/// The result of an operation that can be refused.
pub type Result<T> = std::result::Result<T, DescribeError>;

/// What this crate refuses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DescribeError {
    /// The environment runs no model.
    #[error("{environment} runs no model here: {reason}")]
    PlacementRefused {
        /// The environment kind.
        environment: &'static str,
        /// The stable refusal reason.
        reason: &'static str,
    },

    /// The profile was not qualified on this target.
    #[error("profile {profile} was not qualified on {target}")]
    IncompatibleTarget {
        /// The profile asked for.
        profile: String,
        /// The target this host runs.
        target: String,
    },

    /// A profile document did not parse.
    #[error("a profile document did not parse: {detail}")]
    ProfileMalformed {
        /// What the parser said.
        detail: String,
    },

    /// A profile parsed and states something this product will not run.
    #[error("profile {profile} states {why}")]
    ProfileRefused {
        /// The profile.
        profile: String,
        /// What it states.
        why: &'static str,
    },

    /// A profile signature is from a key this host does not accept.
    #[error("a profile was signed by a key this host does not accept")]
    ProfileUntrustedKey,

    /// A profile signature does not verify over its document.
    #[error("a profile signature does not verify over its document")]
    ProfileSignatureInvalid,

    /// A set of profiles breaks one of section 22's rules about the set.
    #[error("a profile catalogue was refused: {why}")]
    CatalogueRefused {
        /// What the set does.
        why: &'static str,
    },

    /// An asset file could not be read.
    #[error("asset {file} could not be read: {detail}")]
    AssetUnreadable {
        /// The asset's file name.
        file: String,
        /// What the filesystem said.
        detail: String,
    },

    /// An asset file is not the recorded size.
    #[error("asset {file} is {found} bytes, and the profile records {expected}")]
    AssetSizeMismatch {
        /// The asset's file name.
        file: String,
        /// The recorded size.
        expected: u64,
        /// The size found.
        found: u64,
    },

    /// An asset file is not the recorded file.
    #[error("asset {file} hashes to {found}, and the profile records {expected}")]
    AssetDigestMismatch {
        /// The asset's file name.
        file: String,
        /// The recorded digest.
        expected: String,
        /// The digest found.
        found: String,
    },

    /// A download was asked for a profile this environment did not select.
    #[error("this environment selected {selected}, and a download of {asked_for} was refused")]
    DownloadNotSelected {
        /// The selected profile.
        selected: String,
        /// The profile the download was asked for.
        asked_for: String,
    },

    /// The names, pins and provenance store could not be opened or written.
    #[error("the description store could not be used: {detail}")]
    Store {
        /// What the store said.
        detail: String,
    },

    /// A runtime could not load a model, or could not run one.
    #[error("the inference runtime failed: {detail}")]
    Runtime {
        /// What the runtime said.
        detail: String,
    },
}
