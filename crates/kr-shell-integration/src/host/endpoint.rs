//! The worker's own bridge endpoint, and the bootstrap values it hands the root shell.
//!
//! One endpoint per session, inside a directory that admits the owning user alone. Three
//! independent things keep an unrelated process off it: the directory's permissions, the peer
//! credentials the listener checks before a frame is read, and the proof over the one-time secret
//! that only the shell the worker launched was given.
//!
//! The secret is generated here and never leaves the worker except through the environment of the
//! process the worker starts. It is not written to the journal, not put in a diagnostic and not
//! copied into a descriptor.

use std::path::{Path, PathBuf};

use kr_crypto::secret::{Secret, SymmetricKey};
use kr_ipc::endpoint::Listener;
use kr_ipc::paths::{Endpoint, OWNER_ONLY_DIRECTORY_MODE};
use kr_protocol::ids::SessionId;
use kr_protocol::scalars::Bytes;

use crate::contract::transport::{Bootstrap, BridgeEndpoint, ENDPOINT_BASENAME, EndpointKind};
use crate::host::error::{HostError, Result};

/// The session's bridge endpoint, bound and ready to accept the root shell.
///
/// It owns the listener, the address in the form the bootstrap variable carries, and the secret
/// the proof is taken over. Dropping it removes the socket file, so a session that ends leaves no
/// address behind for a later process to connect to.
#[derive(Debug)]
pub struct HostEndpoint {
    session_id: SessionId,
    listener: Listener,
    address: BridgeEndpoint,
    path: Option<PathBuf>,
    secret: SymmetricKey,
}

impl HostEndpoint {
    /// Creates the endpoint inside a directory this user alone can open.
    ///
    /// The directory is checked rather than repaired: one that is group-readable, owned by
    /// somebody else or reached through a symbolic link cannot be made trustworthy by changing its
    /// mode, because the host cannot tell who looked inside it first.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Directory`] when the directory is not owner-only, [`HostError::Endpoint`]
    /// when the resulting path does not fit a socket address, [`HostError::Crypto`] when the
    /// secret cannot be generated, and [`HostError::Ipc`] when the endpoint cannot be bound.
    pub fn open(session_id: SessionId, directory: &Path) -> Result<Self> {
        check_owner_only(directory)?;
        let path = directory.join(ENDPOINT_BASENAME);
        let address = BridgeEndpoint {
            kind: native_kind(),
            path: path
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| HostError::Directory {
                    path: directory.display().to_string(),
                    detail: "a bridge endpoint path must be valid UTF-8".to_owned(),
                })?,
        };
        address.validate()?;
        // The listener replaces a socket file a dead process left behind and sets the file to 0600
        // as it binds, so the address the shell is given is owner-only from the moment it exists.
        let endpoint = Endpoint::from_path(&path)?;
        let listener = Listener::bind(&endpoint)?;
        Ok(Self {
            session_id,
            listener,
            address,
            path: (native_kind() == EndpointKind::UnixSocket).then_some(path),
            secret: Secret::random()?,
        })
    }

    /// Returns the session this endpoint belongs to.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the address, in the form the bootstrap variable carries.
    #[must_use]
    pub const fn address(&self) -> &BridgeEndpoint {
        &self.address
    }

    /// Returns the listener, for accepting the root shell's connection.
    #[must_use]
    pub const fn listener(&self) -> &Listener {
        &self.listener
    }

    /// Returns the secret the proof is taken over.
    ///
    /// It stays inside the worker. The only copy that leaves is the one the launched shell reads
    /// out of its own environment, and that copy is removed from the exported environment as soon
    /// as the handshake succeeds.
    #[must_use]
    pub const fn secret(&self) -> &SymmetricKey {
        &self.secret
    }

    /// Returns the two variables the worker exports when it launches the root shell.
    #[must_use]
    pub fn bootstrap(&self) -> Bootstrap {
        Bootstrap {
            endpoint: self.address.clone(),
            secret: Bytes::new(self.secret.expose().to_vec()),
        }
    }
}

impl Drop for HostEndpoint {
    fn drop(&mut self) {
        if let Some(path) = self.path.as_ref() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Returns the kind of endpoint this platform listens on.
#[must_use]
pub const fn native_kind() -> EndpointKind {
    if cfg!(windows) {
        EndpointKind::WindowsNamedPipe
    } else {
        EndpointKind::UnixSocket
    }
}

/// Checks that a directory admits the owning user alone.
///
/// # Errors
///
/// Returns [`HostError::Directory`] when it is missing, is not a directory, is a symbolic link, is
/// owned by another user, or carries permissions wider than `0700`.
pub fn check_owner_only(directory: &Path) -> Result<()> {
    let fault = |detail: &str| HostError::Directory {
        path: directory.display().to_string(),
        detail: detail.to_owned(),
    };
    let metadata =
        std::fs::symlink_metadata(directory).map_err(|error| fault(&error.to_string()))?;
    if metadata.file_type().is_symlink() {
        return Err(fault("it is a symbolic link"));
    }
    if !metadata.is_dir() {
        return Err(fault("it is not a directory"));
    }
    owner_only_mode(&metadata, &fault)
}

#[cfg(unix)]
fn owner_only_mode(metadata: &std::fs::Metadata, fault: &dyn Fn(&str) -> HostError) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.uid() != kr_ipc::paths::current_uid() {
        return Err(fault("it belongs to another user"));
    }
    let mode = metadata.mode() & 0o777;
    if mode & !OWNER_ONLY_DIRECTORY_MODE != 0 {
        return Err(fault(&format!(
            "its mode is {mode:04o} and a bridge directory is {OWNER_ONLY_DIRECTORY_MODE:04o}"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn owner_only_mode(
    _metadata: &std::fs::Metadata,
    _fault: &dyn Fn(&str) -> HostError,
) -> Result<()> {
    // Windows has no mode bits to read. The pipe carries an owner-only access-control list of its
    // own, which is what the endpoint is protected by there.
    Ok(())
}

#[cfg(test)]
mod tests {
    use kr_protocol::scalars::Uuid;

    use crate::contract::transport::BOOTSTRAP_SECRET_LEN;

    use super::*;

    fn session() -> SessionId {
        SessionId::new(Uuid::from_bytes([0x5a; 16]))
    }

    fn owner_only_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("a temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(
                directory.path(),
                std::fs::Permissions::from_mode(OWNER_ONLY_DIRECTORY_MODE),
            )
            .expect("owner-only");
        }
        directory
    }

    #[tokio::test]
    async fn the_endpoint_is_owner_only_inside_an_owner_only_directory() {
        let directory = owner_only_directory();
        let endpoint = HostEndpoint::open(session(), directory.path()).expect("binds");
        assert_eq!(endpoint.session_id(), session());
        assert_eq!(endpoint.address().kind, native_kind());
        assert_eq!(endpoint.address().validate(), Ok(()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let socket = std::fs::symlink_metadata(&endpoint.address().path).expect("the socket");
            assert_eq!(
                socket.permissions().mode() & 0o777,
                kr_ipc::paths::OWNER_ONLY_FILE_MODE,
                "the endpoint file admits the owning user alone"
            );
        }
        let bootstrap = endpoint.bootstrap();
        assert_eq!(bootstrap.secret.as_slice().len(), BOOTSTRAP_SECRET_LEN);
        let exported = bootstrap.exported_variables();
        assert_eq!(exported.len(), 2);
        assert_eq!(exported[0].1, endpoint.address().path);
        // Two endpoints of the same session never share a secret: a proof taken against one is
        // worthless against the other.
        let elsewhere = owner_only_directory();
        let second = HostEndpoint::open(session(), elsewhere.path()).expect("binds again");
        assert_ne!(
            second.bootstrap().secret.as_slice(),
            bootstrap.secret.as_slice()
        );
    }

    #[tokio::test]
    async fn the_socket_goes_when_the_session_does() {
        let directory = owner_only_directory();
        let path = {
            let endpoint = HostEndpoint::open(session(), directory.path()).expect("binds");
            endpoint.address().path.clone()
        };
        assert!(
            !std::path::Path::new(&path).exists(),
            "a closed session leaves no address behind"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_directory_anybody_can_read_is_refused_rather_than_repaired() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a temporary directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))
            .expect("group and world readable");
        let error = HostEndpoint::open(session(), directory.path()).expect_err("refused");
        assert!(matches!(error, HostError::Directory { .. }), "{error}");
    }

    #[tokio::test]
    async fn a_missing_directory_is_a_named_failure() {
        let directory = owner_only_directory();
        let missing = directory.path().join("not-there");
        let error = HostEndpoint::open(session(), &missing).expect_err("refused");
        assert!(matches!(error, HostError::Directory { .. }), "{error}");
    }
}
