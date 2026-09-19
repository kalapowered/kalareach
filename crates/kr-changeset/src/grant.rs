//! What a capture may read, decided before it reads anything.
//!
//! Section 14: "User-selected inclusion rules and file grants apply before capture; secret or
//! excluded files do not become automatic attachment material." Three rules decide it, in this
//! order, and a path that any of them removes is **never opened**:
//!
//! 1. This host's own secret rules, which no wire field turns off.
//! 2. The caller's exclusions.
//! 3. The caller's selection, when it made one.
//!
//! The inclusion policy then decides the classes, which is the project service's
//! [`kr_protocol::project::InclusionPolicy`]. A path this module removes is recorded in the
//! version's exclusions with its reason, so a reader sees what was left out rather than a tree
//! that is quietly short.

use kr_protocol::changeset::{ExclusionReason, FileGrant};

/// The file names this host never captures, whatever a policy or a grant says.
///
/// Each is a credential, a private key or an authentication file that tools put in a working tree.
/// The match is on the **last component**, so `config/.env` is covered as surely as `.env`, and it
/// is case-insensitive for the ASCII letters because the platforms this runs on differ about that.
const SECRET_NAMES: &[&str] = &[
    ".env",
    ".envrc",
    ".git-credentials",
    ".htpasswd",
    ".netrc",
    "_netrc",
    ".npmrc",
    ".pgpass",
    ".pypirc",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "service-account.json",
];

/// The file-name prefixes this host never captures.
const SECRET_PREFIXES: &[&str] = &[".env."];

/// The file-name suffixes this host never captures.
const SECRET_SUFFIXES: &[&str] = &[".jks", ".key", ".keystore", ".p12", ".pem", ".pfx", ".ppk"];

/// The directory names whose whole contents this host never captures.
///
/// A key inside one of these is a key whatever it is called, so the rule is the directory rather
/// than a list of the names people give keys.
const SECRET_DIRECTORIES: &[&str] = &[".aws", ".gnupg", ".ssh"];

/// The directory name whose contents are a repository's own administrative data.
///
/// Git reports an untracked nested repository as one directory, and a walk that descended into it
/// would reach that repository's configuration, which holds its remotes and can hold a credential,
/// and its object database, which holds every version of every file in it. None of that is the
/// content of the tree this host was asked to capture.
const ADMINISTRATIVE_DIRECTORY: &str = ".git";

/// What the grant decided about one path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantDecision {
    /// The capture may read it.
    Permitted,
    /// It is not captured, for this reason.
    Refused(ExclusionReason),
}

/// Returns true when one path is a repository's own administrative data.
///
/// The match is on any component, so `nested/.git/config` is covered as surely as `.git/config`.
#[must_use]
pub fn is_administrative(path: &str) -> bool {
    path.split('/')
        .any(|component| component == ADMINISTRATIVE_DIRECTORY)
}

/// Returns true when a secret rule covers one path.
///
/// The path is the repository-relative one the status reported, with `/` separators.
#[must_use]
pub fn is_secret(path: &str) -> bool {
    let lowered = path.to_ascii_lowercase();
    for component in lowered.split('/') {
        if SECRET_DIRECTORIES.contains(&component) {
            return true;
        }
    }
    let Some(name) = lowered.rsplit('/').next() else {
        return false;
    };
    SECRET_NAMES.contains(&name)
        || SECRET_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        || SECRET_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

/// Returns true when one path lies under one of the grant's prefixes.
///
/// A prefix matches a whole path or a whole path component boundary: `src` covers `src/main.rs`
/// and does not cover `srcs/main.rs`. A prefix that ends in `/` is read the same way as one that
/// does not, so a caller cannot make one mean something else by adding a separator.
#[must_use]
pub fn under(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    path == prefix
        || (path.len() > prefix.len()
            && path.starts_with(prefix)
            && path.as_bytes()[prefix.len()] == b'/')
}

/// Decides whether a capture may read one path.
///
/// The order is the one the module documentation states: the secret rules first, because a caller
/// cannot select its way past them; then the caller's exclusions; then its selection.
#[must_use]
pub fn decide(grant: &FileGrant, path: &str) -> GrantDecision {
    if is_administrative(path) {
        return GrantDecision::Refused(ExclusionReason::Unsupported);
    }
    if is_secret(path) {
        return GrantDecision::Refused(ExclusionReason::SecretRule);
    }
    if grant
        .excluded_paths
        .iter()
        .any(|prefix| under(path, prefix))
    {
        return GrantDecision::Refused(ExclusionReason::Grant);
    }
    if !grant.included_paths.is_empty()
        && !grant
            .included_paths
            .iter()
            .any(|prefix| under(path, prefix))
    {
        return GrantDecision::Refused(ExclusionReason::Grant);
    }
    GrantDecision::Permitted
}

/// Returns the grant as it is recorded on a version.
///
/// The recorded form always says the secret rules were applied, because there is no way to ask for
/// a capture without them.
#[must_use]
pub fn recorded(grant: &FileGrant) -> FileGrant {
    FileGrant {
        included_paths: grant.included_paths.clone(),
        excluded_paths: grant.excluded_paths.clone(),
        secret_rules_applied: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_is_refused_wherever_it_is_and_whatever_a_grant_says() {
        // The rule a caller cannot select its way past. A selection of the whole tree still leaves
        // every one of these out.
        let everything = FileGrant {
            included_paths: vec![String::new()],
            excluded_paths: Vec::new(),
            secret_rules_applied: true,
        };
        for path in [
            ".env",
            ".env.production",
            "services/api/.env",
            "deploy/server.pem",
            "deploy/SERVER.PEM",
            "keys/id_rsa",
            "config/credentials.json",
            "home/.ssh/authorized_keys",
            "vendor/.aws/config",
            "certs/bundle.p12",
            ".netrc",
        ] {
            assert!(is_secret(path), "{path} is a secret");
            assert_eq!(
                decide(&everything, path),
                GrantDecision::Refused(ExclusionReason::SecretRule),
                "{path} is refused whatever the grant selects"
            );
        }
    }

    #[test]
    fn a_repository_s_own_administrative_data_is_never_content() {
        // Git reports an untracked nested repository as one directory. Descending into it would
        // reach its configuration, which holds its remotes and can hold a credential, and its
        // object database, which holds every version of every file in it.
        let everything = FileGrant {
            included_paths: vec![String::new()],
            excluded_paths: Vec::new(),
            secret_rules_applied: true,
        };
        for path in [
            ".git/config",
            ".git",
            "nested/.git/config",
            "nested/.git/objects/ab/cdef",
            "vendor/thing/.git/HEAD",
        ] {
            assert!(is_administrative(path), "{path} is administrative data");
            assert_eq!(
                decide(&everything, path),
                GrantDecision::Refused(ExclusionReason::Unsupported),
                "{path} is refused whatever the grant selects"
            );
        }
        // A path that merely starts with the same letters is content.
        assert!(!is_administrative(".gitignore"));
        assert!(!is_administrative("src/.gitattributes"));
        assert_eq!(decide(&everything, ".gitignore"), GrantDecision::Permitted);
    }

    #[test]
    fn an_ordinary_file_is_not_mistaken_for_a_secret() {
        for path in [
            "README.md",
            "src/main.rs",
            "environment.md",
            "docs/keyboard.md",
            "assets/key-art.png",
            "src/credentials_test_helper.rs",
        ] {
            assert!(!is_secret(path), "{path} is not a secret");
        }
    }

    #[test]
    fn a_prefix_matches_a_whole_component_rather_than_a_string() {
        assert!(under("src/main.rs", "src"));
        assert!(under("src/main.rs", "src/"));
        assert!(under("src", "src"));
        assert!(!under("srcs/main.rs", "src"));
        assert!(!under("other/src/main.rs", "src"));
        // An empty prefix is the whole tree.
        assert!(under("anything/at/all", ""));
    }

    #[test]
    fn an_exclusion_beats_a_selection() {
        let grant = FileGrant {
            included_paths: vec!["src".to_owned()],
            excluded_paths: vec!["src/generated".to_owned()],
            secret_rules_applied: true,
        };
        assert_eq!(decide(&grant, "src/main.rs"), GrantDecision::Permitted);
        assert_eq!(
            decide(&grant, "src/generated/table.rs"),
            GrantDecision::Refused(ExclusionReason::Grant)
        );
        // Outside the selection entirely.
        assert_eq!(
            decide(&grant, "docs/README.md"),
            GrantDecision::Refused(ExclusionReason::Grant)
        );
    }

    #[test]
    fn an_empty_selection_means_the_policy_decides_alone() {
        let grant = FileGrant::default();
        assert_eq!(decide(&grant, "anything"), GrantDecision::Permitted);
        assert_eq!(decide(&grant, "src/main.rs"), GrantDecision::Permitted);
    }

    #[test]
    fn the_recorded_grant_always_says_the_secret_rules_were_applied() {
        // There is no wire field that turns them off, so a record that said otherwise would be
        // describing something this host does not do.
        let asked = FileGrant {
            included_paths: Vec::new(),
            excluded_paths: Vec::new(),
            secret_rules_applied: false,
        };
        assert!(recorded(&asked).secret_rules_applied);
    }
}
