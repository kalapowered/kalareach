//! `kr account token import`: putting a managed-service account token where this host reads it.
//!
//! Managed voice spends an account's balance, so the host presents an account token when it brokers
//! a call. Obtaining that token is the companion application's sign-in; this command is how an
//! operator puts one on a host that has no browser, and it is deliberately the whole of what this
//! command does.
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

use std::path::{Path, PathBuf};

use kr_client::services::voice::{
    ACCOUNT_TOKEN_FILE_LIMIT, StoredAccountToken, VOICE_SCOPE, account_token_path,
};
use kr_ipc::paths::HostPaths;

use crate::error::{CliError, Result};

/// What an import did, for a person and for `--json`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Imported {
    /// Where the token was written.
    pub path: String,
    /// The origin it belongs to.
    pub origin: String,
    /// The scopes it carries.
    pub scopes: Vec<String>,
    /// When it stops being accepted, in UTC milliseconds, or null when the issuer did not say.
    pub expires_at_ms: Option<u64>,
    /// True when it carries the scope managed voice needs.
    pub carries_voice_scope: bool,
}

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
        lines.push(if self.scopes.is_empty() {
            "It carries no scopes.".to_owned()
        } else {
            format!("It carries {}.", self.scopes.join(", "))
        });
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
        return Err(CliError::Usage(
            "an account token is written inside this host's runtime directory".to_owned(),
        ));
    }
    let bytes = read_source(source)?;
    let stored = StoredAccountToken::read(&bytes).map_err(|error| {
        // The refusal from the reader names the shape, never the value.
        CliError::Usage(format!("{} could not be read: {error}", source.display()))
    })?;

    std::fs::create_dir_all(runtime_root)
        .map_err(|error| CliError::Usage(format!("{}: {error}", runtime_root.display())))?;
    kr_ipc::paths::write_owner_only_file(
        &destination,
        &stored
            .write()
            .map_err(|error| CliError::Usage(format!("the token could not be written: {error}")))?,
    )
    .map_err(CliError::from)?;

    Ok(Imported {
        path: destination.display().to_string(),
        origin: stored.origin.clone(),
        scopes: stored.scopes.clone(),
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
        .map_err(|error| CliError::Usage(format!("{}: {error}", source.display())))?;
    if metadata.len() > ACCOUNT_TOKEN_FILE_LIMIT {
        return Err(CliError::Usage(format!(
            "{} is larger than an account token document",
            source.display()
        )));
    }
    std::fs::read(source).map_err(|error| CliError::Usage(format!("{}: {error}", source.display())))
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
}
