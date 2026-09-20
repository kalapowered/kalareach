//! Enrolling a repository.
//!
//! Enrolment is where every later decision is bounded: the trust root this repository's metadata
//! is verified against, the budgets a sync runs inside, the capability ceiling its packages cannot
//! exceed without an explicit grant, and whether the host keeps a full offline mirror of it.
//!
//! Three rules live here rather than further down, because they decide whether a repository is
//! enrolled at all.
//!
//! * **Every repository keeps its own root.** An enterprise or vendor repository that adopted its
//!   own root out of band is not verified against the official one, and adopting a second root
//!   never widens the first. The roots are held per enrolment and never merged.
//! * **A Git branch is not update authority.** A branch moves, and a repository whose "current
//!   revision" decides what a host installs has no signed statement of what it published. A
//!   version-control location is refused at enrolment, by name, rather than fetched and found
//!   unsigned later.
//! * **A new root, or trust wider than what was already accepted, is the owner's decision.** The
//!   enrolment records which trust the owner confirmed, so a later change can be compared against
//!   it instead of being accepted because the caller had `host.manage`.

use std::collections::BTreeSet;

use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::limits::RepositoryBudgets;
use kr_protocol::ids::RepositoryGeneration;
use url::Url;

use crate::catalogue::error::{CatalogueError, CatalogueResult};

/// How much a repository is trusted before any package asks for anything.
///
/// The default permits metadata matching, declarative presentation and already-authorised broker
/// semantic events. That is what stops thousands of passive downloads from becoming thousands of
/// permission prompts: everything in the default ceiling is something the host was already doing
/// with data the actor may already see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityCeiling {
    permitted: BTreeSet<PluginCapability>,
}

impl CapabilityCeiling {
    /// The ceiling a newly enrolled repository gets.
    #[must_use]
    pub fn default_ceiling() -> Self {
        Self {
            permitted: PluginCapability::DEFAULT_REPOSITORY_CEILING
                .iter()
                .copied()
                .collect(),
        }
    }

    /// Builds a ceiling from an explicit repository grant.
    #[must_use]
    pub fn with(capabilities: impl IntoIterator<Item = PluginCapability>) -> Self {
        let mut permitted: BTreeSet<PluginCapability> =
            PluginCapability::DEFAULT_REPOSITORY_CEILING
                .iter()
                .copied()
                .collect();
        permitted.extend(capabilities);
        Self { permitted }
    }

    /// Returns true when the ceiling permits a capability without a per-package grant.
    #[must_use]
    pub fn permits(&self, capability: PluginCapability) -> bool {
        self.permitted.contains(&capability)
    }

    /// Returns the permitted capabilities in a stable order.
    #[must_use]
    pub fn capabilities(&self) -> Vec<PluginCapability> {
        self.permitted.iter().copied().collect()
    }

    /// Returns true when `other` permits something this ceiling does not.
    ///
    /// Widening trust is the owner's decision, so the comparison is part of the enrolment rather
    /// than of the caller's argument list.
    #[must_use]
    pub fn widens(&self, other: &Self) -> bool {
        other.permitted.difference(&self.permitted).next().is_some()
    }
}

impl Default for CapabilityCeiling {
    fn default() -> Self {
        Self::default_ceiling()
    }
}

/// What kind of repository this is.
///
/// The kind is descriptive. It changes nothing about verification: an official repository is
/// verified exactly as a community one is, against the root this host holds for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RepositoryKind {
    /// The repository KalaReach ships the root for.
    Official,
    /// A vendor's own repository, delegated beneath the official root or with its own.
    Vendor,
    /// A community repository with its own root.
    Community,
    /// A directory on this machine.
    Local,
    /// A mirror of another repository, with that repository's root.
    Mirror,
}

impl RepositoryKind {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Official => "official",
            Self::Vendor => "vendor",
            Self::Community => "community",
            Self::Local => "local",
            Self::Mirror => "mirror",
        }
    }
}

/// A repository identifier inside this host.
///
/// It is the host's own name for an enrolment, not anything the repository asserts. Two
/// repositories that both call themselves "stable" are two enrolments here.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepositoryId(String);

impl RepositoryId {
    /// The characters an identifier may use.
    ///
    /// The identifier becomes a directory name, so it uses the portable alphabet for the same
    /// reason package paths do: a name two filesystems disagree about is a name that finds a
    /// different repository on a different machine.
    fn is_permitted(character: char) -> bool {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
    }

    /// Parses a repository identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::InvalidArgument`] when the text is empty, too long, made only of
    /// dots or carries a character outside the portable alphabet.
    pub fn new(text: impl Into<String>) -> CatalogueResult<Self> {
        let text = text.into();
        if text.is_empty() || text.len() > 64 {
            return Err(CatalogueError::InvalidArgument {
                detail: format!(
                    "a repository identifier is between one and sixty-four bytes, not {}",
                    text.len()
                ),
            });
        }
        if text.chars().all(|character| character == '.') {
            return Err(CatalogueError::InvalidArgument {
                detail: "a repository identifier made only of dots names a directory".to_owned(),
            });
        }
        if let Some(character) = text.chars().find(|c| !Self::is_permitted(*c)) {
            return Err(CatalogueError::InvalidArgument {
                detail: format!(
                    "a repository identifier uses A-Z, a-z, 0-9, '-', '_' and '.', not {character:?}"
                ),
            });
        }
        Ok(Self(text))
    }

    /// Returns the identifier's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for RepositoryId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The version-control schemes a repository location may not use.
///
/// A branch is a moving name. Installing what it points at today means installing something else
/// tomorrow with no signed statement that either was published, which is the thing TUF metadata
/// exists to replace.
const VERSION_CONTROL_SCHEMES: &[&str] = &[
    "git",
    "git+file",
    "git+http",
    "git+https",
    "git+ssh",
    "hg",
    "ssh",
    "svn",
];

/// Query keys that name a moving version-control reference rather than a published generation.
const BRANCH_KEYS: &[&str] = &["branch", "ref", "rev", "revision", "tag"];

/// Checks that a repository location can carry signed generations.
///
/// # Errors
///
/// Returns [`CatalogueError::Untrusted`] for a version-control location, a scheme this host does
/// not fetch from, or a location that names a branch.
pub fn check_location(url: &Url) -> CatalogueResult<()> {
    let scheme = url.scheme();
    if VERSION_CONTROL_SCHEMES.contains(&scheme) {
        return Err(CatalogueError::Untrusted {
            detail: format!(
                "{scheme} names a version-control location; a branch moves and states nothing \
                 about what was published, so it is never update authority. Enrol a signed \
                 catalogue generation instead"
            ),
        });
    }
    if !matches!(scheme, "file" | "https") {
        return Err(CatalogueError::Untrusted {
            detail: format!(
                "a repository is fetched over https or read from a local directory, not over \
                 {scheme}"
            ),
        });
    }
    if let Some((key, value)) = url
        .query_pairs()
        .find(|(key, _)| BRANCH_KEYS.contains(&key.as_ref()))
    {
        return Err(CatalogueError::Untrusted {
            detail: format!(
                "the location selects {key}={value}; a version-control reference moves and is \
                 never update authority"
            ),
        });
    }
    if url.cannot_be_a_base() {
        return Err(CatalogueError::Untrusted {
            detail: "a repository location is a directory, so it has a path to resolve metadata \
                     and targets against"
                .to_owned(),
        });
    }
    Ok(())
}

/// A repository this host has enrolled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrolment {
    /// This host's name for the repository.
    pub id: RepositoryId,
    /// What kind of repository it is.
    pub kind: RepositoryKind,
    /// Where its metadata lives.
    pub metadata_url: Url,
    /// Where its targets live.
    pub targets_url: Url,
    /// The trust root adopted for this repository, and no other.
    pub root: Vec<u8>,
    /// The budgets a sync runs inside.
    pub budgets: RepositoryBudgets,
    /// What its packages may do without a further grant.
    pub ceiling: CapabilityCeiling,
    /// The generation this repository is held at, where the owner pinned one.
    pub pinned_generation: Option<RepositoryGeneration>,
}

impl Enrolment {
    /// Enrols a repository after checking its location and its root.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::Untrusted`] when the location cannot carry signed generations or
    /// the root is empty, and [`CatalogueError::ResourceLimit`] when the root is larger than the
    /// metadata budget.
    pub fn new(
        id: RepositoryId,
        kind: RepositoryKind,
        metadata_url: Url,
        targets_url: Url,
        root: Vec<u8>,
        budgets: RepositoryBudgets,
        ceiling: CapabilityCeiling,
    ) -> CatalogueResult<Self> {
        check_location(&metadata_url)?;
        check_location(&targets_url)?;
        if root.is_empty() {
            return Err(CatalogueError::Untrusted {
                detail: "a repository is enrolled with the trust root its metadata is verified \
                         against; there is no unverified enrolment"
                    .to_owned(),
            });
        }
        crate::catalogue::budget::BudgetLedger::new(budgets).check_metadata_bytes(
            root.len() as u64,
            crate::catalogue::budget::Stage::Actual,
            "root.json",
        )?;
        Ok(Self {
            id,
            kind,
            metadata_url,
            targets_url,
            root,
            budgets,
            ceiling,
            pinned_generation: None,
        })
    }

    /// Returns the digest of the adopted root.
    ///
    /// Two enrolments that adopted the same root have the same digest; an enrolment whose root
    /// changed has a different one, which is what makes "a new root" a thing a host can see.
    #[must_use]
    pub fn root_digest(&self) -> PayloadDigest {
        PayloadDigest::of(&self.root)
    }

    /// Decides whether a proposed change needs the owner to confirm it.
    ///
    /// A different root is a different trust anchor, whatever it is called. A wider ceiling is
    /// more than the owner accepted. Either one is the owner's decision and not the caller's.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::OwnerConfirmationRequired`] naming exactly what changed.
    pub fn check_change(&self, proposed: &Self, confirmed: bool) -> CatalogueResult<()> {
        if confirmed {
            return Ok(());
        }
        if proposed.root_digest() != self.root_digest() {
            return Err(CatalogueError::OwnerConfirmationRequired {
                detail: format!(
                    "{} would be verified against a different trust root; adopting a root is the \
                     owner's decision",
                    self.id
                ),
            });
        }
        if self.ceiling.widens(&proposed.ceiling) {
            let added: Vec<&'static str> = proposed
                .ceiling
                .capabilities()
                .into_iter()
                .filter(|capability| !self.ceiling.permits(*capability))
                .map(PluginCapability::as_str)
                .collect();
            return Err(CatalogueError::OwnerConfirmationRequired {
                detail: format!(
                    "{} would be permitted {} without a further grant; enlarging a repository's \
                     trust is the owner's decision",
                    self.id,
                    added.join(", ")
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).expect("a parsable location")
    }

    fn enrolment() -> Enrolment {
        Enrolment::new(
            RepositoryId::new("official").expect("a valid identifier"),
            RepositoryKind::Official,
            url("https://plugins.example/metadata/"),
            url("https://plugins.example/targets/"),
            b"root".to_vec(),
            RepositoryBudgets::defaults(),
            CapabilityCeiling::default_ceiling(),
        )
        .expect("an enrollable repository")
    }

    #[test]
    fn a_git_location_is_never_update_authority() {
        for location in [
            "git+https://example.invalid/plugins.git",
            "git://example.invalid/plugins",
            "ssh://example.invalid/plugins",
        ] {
            let refusal = check_location(&url(location)).expect_err("refused");
            assert!(
                refusal.to_string().contains("never update authority"),
                "{location}: {refusal}"
            );
        }
        let branch = check_location(&url("https://example.invalid/plugins?branch=main"))
            .expect_err("refused");
        assert!(branch.to_string().contains("never update authority"));
    }

    #[test]
    fn a_location_is_https_or_a_local_directory() {
        assert!(check_location(&url("https://plugins.example/metadata/")).is_ok());
        assert!(check_location(&url("file:///var/lib/kalareach/mirror/")).is_ok());
        assert!(check_location(&url("http://plugins.example/metadata/")).is_err());
        assert!(check_location(&url("data:text/plain,nothing")).is_err());
    }

    #[test]
    fn the_default_ceiling_is_the_three_passive_capabilities() {
        let ceiling = CapabilityCeiling::default_ceiling();
        assert!(ceiling.permits(PluginCapability::MetadataMatch));
        assert!(ceiling.permits(PluginCapability::DeclarativePresentation));
        assert!(ceiling.permits(PluginCapability::BrokerSemanticEvents));
        assert!(!ceiling.permits(PluginCapability::TerminalStream));
        assert!(!ceiling.permits(PluginCapability::NativeBridgeInstall));
        assert_eq!(ceiling.capabilities().len(), 3);
    }

    #[test]
    fn a_new_root_or_a_wider_ceiling_is_the_owners_decision() {
        let current = enrolment();

        let mut rerooted = current.clone();
        rerooted.root = b"another root".to_vec();
        let refusal = current
            .check_change(&rerooted, false)
            .expect_err("a different root");
        assert!(matches!(
            refusal,
            CatalogueError::OwnerConfirmationRequired { .. }
        ));
        assert!(current.check_change(&rerooted, true).is_ok());

        let mut wider = current.clone();
        wider.ceiling = CapabilityCeiling::with([PluginCapability::TerminalStream]);
        let refusal = current
            .check_change(&wider, false)
            .expect_err("a wider ceiling");
        assert!(refusal.to_string().contains("terminal.stream"), "{refusal}");

        // Narrowing is not enlarging, so it needs no confirmation.
        let narrower = current.clone();
        assert!(wider.check_change(&narrower, false).is_ok());
    }

    #[test]
    fn an_identifier_is_a_portable_directory_name() {
        assert!(RepositoryId::new("kalareach-official").is_ok());
        assert!(RepositoryId::new("").is_err());
        assert!(RepositoryId::new("..").is_err());
        assert!(RepositoryId::new("a/b").is_err());
        assert!(RepositoryId::new("caf\u{e9}").is_err());
        assert!(RepositoryId::new("x".repeat(65)).is_err());
    }

    #[test]
    fn an_enrolment_holds_its_own_root() {
        let official = enrolment();
        let mut vendor = enrolment();
        vendor.id = RepositoryId::new("vendor").expect("a valid identifier");
        vendor.kind = RepositoryKind::Vendor;
        vendor.root = b"vendor root".to_vec();
        assert_ne!(official.root_digest(), vendor.root_digest());
        // Enrolling the vendor never changes what the official repository is verified against.
        assert_eq!(official.root, b"root".to_vec());
    }
}
