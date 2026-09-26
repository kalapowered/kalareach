//! `kr account token import`: putting a managed-service account token where this host reads it.
//!
//! Managed voice spends an account's balance, so a host that brokers a call presents an account
//! token. The document holds an access token the service issued, which the service accepts for as
//! long as it said when it issued it (ten minutes for the managed service), and this host does not
//! refresh it. The companion's own sign-in keeps its tokens in the device's secure storage and
//! exports none: its refresh token rotates on every use, so a second holder would end the grant.
//! This command is how an operator puts a token on a host, and it is deliberately the whole of what
//! this command does.
//!
//! Two rules shape it.
//!
//! **The value is never printed.** Not on success, not in a refusal, not in a diagnostic. What is
//! printed is where the file went, the origin it belongs to, the scopes it carries and when it
//! stops. Everything that could carry the value is held in
//! [`AccountToken`](kr_client::services::AccountToken), which has no display and prints a
//! placeholder.
//!
//! **The destination is this host's runtime root and nothing else.** The path is derived from the
//! runtime root the host already owns; the operator names the file to read, not the file to write.

use kr_client::shown;
use kr_client::shown::Shown;
use std::path::{Path, PathBuf};

use kr_client::services::account::{scope_names, scope_words};
use kr_client::services::voice::{
    ACCOUNT_TOKEN_FILE_LIMIT, StoredAccountToken, VOICE_SCOPE, account_token_path,
};
use kr_ipc::paths::HostPaths;

use crate::error::{CliError, Result};
use crate::shown::named;

/// What an import did, for a person and for `--json`.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct Imported {
    /// Where the token was written.
    pub path: String,
    /// The origin it belongs to, as a diagnostic names one: the scheme, the host and the port.
    pub origin: String,
    /// The scopes it carries that this build knows, by name.
    pub scopes: Vec<&'static str>,
    /// How many scopes it carries that this build does not know. They are counted, not repeated:
    /// a scope is whatever the file said.
    pub unknown_scopes: usize,
    /// When it stops being accepted, in UTC milliseconds, or null when the issuer did not say.
    pub expires_at_ms: Option<u64>,
    /// True when it carries the scope managed voice needs.
    pub carries_voice_scope: bool,
}

kr_client::debug_fields!(Imported {
    scopes,
    unknown_scopes,
    expires_at_ms,
    carries_voice_scope
});

impl Imported {
    /// The lines a person reads.
    ///
    /// Deliberately free of anything derived from the token. A length or a digest would be one
    /// more thing that leaks a little about a secret, for no benefit an operator has asked for.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("Wrote the account token to {}.", self.path),
            format!("It belongs to {}.", self.origin),
        ];
        lines.push(format!(
            "It carries {}.",
            scope_words(&self.scopes, self.unknown_scopes)
        ));
        if let Some(expires_at_ms) = self.expires_at_ms {
            lines.push(format!(
                "It stops being accepted at {expires_at_ms} in UTC milliseconds."
            ));
        }
        if !self.carries_voice_scope {
            lines.push(format!(
                "Managed voice needs the {VOICE_SCOPE} scope, which this token does not carry."
            ));
        }
        lines
    }
}

/// What `kr account token show` says of the token this host reads, for a person and for `--json`.
///
/// The origin and the scopes are said as a diagnostic says them: the scheme, the host and the
/// port, and the scopes this build knows by name with the others counted. A stored origin can carry
/// a user name and a password in front of the host, and a scope is whatever the file said.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct Held {
    /// Where this host reads its account token.
    pub path: String,
    /// True when a token is imported there.
    pub imported: bool,
    /// The origin it belongs to, when one is imported.
    pub origin: Option<String>,
    /// The scopes it carries that this build knows, by name.
    pub scopes: Vec<&'static str>,
    /// How many scopes it carries that this build does not know.
    pub unknown_scopes: usize,
    /// The token's description, for a person.
    #[serde(skip)]
    description: Option<String>,
}

kr_client::debug_fields!(Held {
    imported,
    scopes,
    unknown_scopes
});

impl Held {
    /// What `path` holds, as `stored` read it.
    #[must_use]
    pub fn of(path: &Path, stored: Option<&StoredAccountToken>) -> Self {
        let (scopes, unknown_scopes) =
            stored.map_or_else(|| (Vec::new(), 0), |stored| scope_names(&stored.scopes));
        Self {
            path: path.display().to_string(),
            imported: stored.is_some(),
            origin: stored.map(|stored| Shown::address(&stored.origin).into_string()),
            scopes,
            unknown_scopes,
            description: stored.map(|stored| stored.description().into_string()),
        }
    }

    /// The lines a person reads. The token itself is never in them.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("This host reads its account token from {}.", self.path),
            self.description.as_ref().map_or_else(
                || {
                    "No account token has been imported. Write one with `kr account token import \
                     <path>`."
                        .to_owned()
                },
                |description| format!("It holds {description}."),
            ),
        ]
    }
}

/// Reads a token from `source` and writes it where this host reads it.
///
/// # Errors
///
/// Returns an error when the file cannot be read, when it is not an account token document, or
/// when the runtime root cannot be created. No error carries the token.
pub fn import(source: &Path) -> Result<Imported> {
    let paths = HostPaths::discover().map_err(CliError::from)?;
    import_into(source, paths.runtime_root())
}

/// The same, into a stated runtime root.
///
/// Separate so a test can drive the whole command against a directory on the internal disk.
///
/// # Errors
///
/// Returns an error when the file cannot be read, when it is not an account token document, or
/// when the destination cannot be written.
pub fn import_into(source: &Path, runtime_root: &Path) -> Result<Imported> {
    let destination = account_token_path(runtime_root);
    // The operator names the file to read. The file to write is derived from the runtime root this
    // host already owns, so there is no argument that could put a token somewhere else.
    if !destination.starts_with(runtime_root) {
        return Err(CliError::Usage(Shown::said(
            "an account token is written inside this host's runtime directory",
        )));
    }
    let bytes = read_source(source)?;
    let stored = StoredAccountToken::read(&bytes).map_err(|error| {
        // The refusal from the reader names the shape, never the value.
        CliError::Usage(shown!("{} could not be read: {}", named(source), error))
    })?;

    std::fs::create_dir_all(runtime_root).map_err(|error| {
        CliError::Usage(shown!(
            "{}: {}",
            Shown::root(runtime_root),
            Shown::io(&error)
        ))
    })?;
    kr_ipc::paths::write_owner_only_file(
        &destination,
        &stored.write().map_err(|error| {
            CliError::Usage(shown!("the token could not be written: {}", error))
        })?,
    )
    .map_err(CliError::from)?;

    let (scopes, unknown_scopes) = scope_names(&stored.scopes);
    Ok(Imported {
        path: destination.display().to_string(),
        origin: Shown::address(&stored.origin).into_string(),
        scopes,
        unknown_scopes,
        expires_at_ms: stored.expires_at_ms,
        carries_voice_scope: stored.carries(VOICE_SCOPE),
    })
}

/// Where this host reads its account token, for a person asking.
///
/// # Errors
///
/// Returns an error when the runtime root cannot be discovered.
pub fn token_path() -> Result<PathBuf> {
    let paths = HostPaths::discover().map_err(CliError::from)?;
    Ok(account_token_path(paths.runtime_root()))
}

/// Reads the operator's file, bounded.
fn read_source(source: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(source)
        .map_err(|error| CliError::Usage(shown!("{}: {}", named(source), Shown::io(&error))))?;
    if metadata.len() > ACCOUNT_TOKEN_FILE_LIMIT {
        return Err(CliError::Usage(shown!(
            "{} is larger than an account token document",
            named(source)
        )));
    }
    std::fs::read(source)
        .map_err(|error| CliError::Usage(shown!("{}: {}", named(source), Shown::io(&error))))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A disposable runtime root on the internal disk, never on the workspace volume.
    fn runtime_root() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("kr-account-")
            .tempdir_in(std::env::temp_dir())
            .expect("a runtime root on the internal disk")
    }

    fn document(scopes: &str) -> String {
        format!(
            r#"{{"origin":"https://reach.example","accessToken":"a-secret-value",
                "scopes":[{scopes}],"expiresAtMs":1700000000000}}"#
        )
    }

    #[test]
    fn an_imported_token_is_written_owner_only_and_never_printed() {
        let root = runtime_root();
        let source = root.path().join("from-the-operator.json");
        std::fs::write(&source, document(r#""voice""#)).expect("the operator's file");

        let imported = import_into(&source, root.path()).expect("the token is imported");
        assert!(imported.carries_voice_scope);
        assert_eq!(imported.origin, "https://reach.example");

        // Nothing a person or a script reads carries the value.
        let rendered = imported.lines().join("\n");
        assert!(!rendered.contains("a-secret-value"), "{rendered}");
        let json = serde_json::to_string(&imported).expect("the machine-readable answer");
        assert!(!json.contains("a-secret-value"), "{json}");
        assert!(!format!("{imported:?}").contains("a-secret-value"));

        // The file is this host's, owner-only, and holds what was imported.
        let written = std::path::PathBuf::from(&imported.path);
        assert_eq!(written, account_token_path(root.path()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&written)
                .expect("the written token")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the token is owner-only");
        }
        let stored = kr_client::services::voice::AccountTokenFile::at(written)
            .stored()
            .expect("the host reads it back");
        assert_eq!(stored.origin, "https://reach.example");
        assert!(stored.carries(VOICE_SCOPE));
    }

    #[test]
    fn a_token_without_the_voice_scope_is_written_and_reported_as_such() {
        let root = runtime_root();
        let source = root.path().join("no-scope.json");
        std::fs::write(&source, document(r#""reasoning""#)).expect("the operator's file");
        let imported = import_into(&source, root.path()).expect("the token is imported");
        assert!(!imported.carries_voice_scope);
        assert!(
            imported
                .lines()
                .iter()
                .any(|line| line.contains("does not carry"))
        );
    }

    #[test]
    fn a_document_this_command_cannot_parse_is_refused_without_quoting_it() {
        let root = runtime_root();
        let source = root.path().join("broken.json");
        std::fs::write(
            &source,
            r#"{"origin":"https://reach.example","accessToken":"a-secret"#,
        )
        .expect("the operator's file");
        let error = import_into(&source, root.path()).expect_err("it is refused");
        assert!(!error.to_string().contains("a-secret"), "{error}");
        assert!(
            !account_token_path(root.path()).exists(),
            "a refused import writes nothing"
        );
    }

    #[test]
    fn a_file_that_is_not_there_is_refused() {
        let root = runtime_root();
        let error =
            import_into(&root.path().join("absent.json"), root.path()).expect_err("it is refused");
        assert!(matches!(error, CliError::Usage(_)));
    }

    /// A stored document with the marker in the path, the query and the fragment of its origin,
    /// and in its user information when `credentials` is set, in a scope, and as the token.
    fn marked_document(credentials: bool) -> String {
        let marker = crate::shown::marker::MARKER;
        let user = if credentials {
            format!("{marker}:{marker}@")
        } else {
            String::new()
        };
        format!(
            r#"{{"origin":"https://{user}reach.example/{marker}?{marker}#{marker}",
                "accessToken":"{marker}","scopes":["voice","{marker}"],"expiresAtMs":1700000000000}}"#
        )
    }

    /// `kr account token import` says the origin as a diagnostic names one and the scopes this
    /// build knows, and counts the others: a stored origin can carry a user name and a password,
    /// and a scope is whatever the file said.
    #[test]
    fn an_import_says_the_origin_and_scopes_without_what_the_file_put_in_them() {
        use crate::shown::marker::{MARKER, assert_unmarked};

        // An origin with credentials in it is not printed at all; one without is its scheme and
        // host.
        for (credentials, origin, places) in [
            (true, "<not printed>", 5),
            (false, "https://reach.example", 3),
        ] {
            let root = runtime_root();
            let source = root.path().join("from-the-operator.json");
            std::fs::write(&source, marked_document(credentials)).expect("the operator's file");
            let imported = import_into(&source, root.path()).expect("the token is imported");
            // The negative control: the stored record holds the marker in the origin's user
            // information, path, query and fragment and in the second scope, where the import
            // reported them whole.
            let stored =
                kr_client::services::voice::AccountTokenFile::at(PathBuf::from(&imported.path))
                    .stored()
                    .expect("the host reads it back");
            assert_eq!(
                stored.origin.matches(MARKER).count(),
                places,
                "{}",
                stored.origin
            );
            assert!(stored.scopes.iter().any(|scope| scope == MARKER));

            assert_eq!(imported.origin, origin);
            assert_eq!(imported.scopes, ["voice"]);
            assert_eq!(imported.unknown_scopes, 1);
            assert_unmarked(
                "an import",
                &[
                    imported.lines().join("\n"),
                    serde_json::to_string(&imported).expect("the machine-readable answer"),
                    format!("{imported:?}"),
                    format!("{imported:#?}"),
                ],
            );
        }
    }

    /// `kr account token show` says the same of the token this host reads, for a person and for a
    /// script.
    #[test]
    fn a_shown_token_says_the_origin_and_scopes_without_what_the_file_put_in_them() {
        use crate::shown::marker::{MARKER, assert_unmarked};

        let root = runtime_root();
        let path = account_token_path(root.path());
        kr_ipc::paths::write_owner_only_file(&path, marked_document(false).as_bytes())
            .expect("the stored token");
        let stored = kr_client::services::voice::AccountTokenFile::at(path.clone())
            .stored()
            .expect("the host reads it");
        // The negative control: what the command printed at `origin` and `scopes`.
        assert!(
            stored.origin.contains(MARKER) && stored.scopes.iter().any(|scope| scope == MARKER)
        );

        let held = Held::of(&path, Some(&stored));
        assert_eq!(held.origin.as_deref(), Some("https://reach.example"));
        assert_eq!(held.scopes, ["voice"]);
        assert_eq!(held.unknown_scopes, 1);
        assert_unmarked(
            "a shown token",
            &[
                held.lines().join("\n"),
                serde_json::to_string(&held).expect("the machine-readable answer"),
                format!("{held:?}"),
                format!("{held:#?}"),
            ],
        );

        let nothing = Held::of(&path, None);
        assert!(!nothing.imported);
        assert!(nothing.lines()[1].starts_with("No account token has been imported."));
    }
}
