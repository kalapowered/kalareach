//! Publishing, reading and retiring worker descriptors.
//!
//! A descriptor is how the `kr` command line reaches a worker while the control daemon is
//! restarting. It is published atomically, owner-only, and carries no secret. What it carries is
//! the worker's public key, which is the only part a reader may act on before a challenge: the
//! filename, the endpoint path and the process identifier inside it are hints, and a client that
//! trusted them could be sent anywhere by a file someone else wrote.
//!
//! Retirement removes the file. A closed session's descriptor is gone, so a reader gets the
//! closure record from the registry rather than an endpoint that might start something.

use std::path::Path;

use kr_protocol::ids::SessionId;
use kr_protocol::worker::WorkerDescriptor;

use crate::error::{IpcError, Result};
use crate::paths::{EnvironmentPaths, write_owner_only_file};

/// Writes a descriptor into the runtime directory, replacing any previous version atomically.
///
/// # Errors
///
/// Returns an error when the descriptor cannot be encoded or the file cannot be published.
pub fn publish(paths: &EnvironmentPaths, descriptor: &WorkerDescriptor) -> Result<()> {
    let bytes = kr_cbor::to_canonical_vec(descriptor)
        .map_err(|error| IpcError::Frame(kr_protocol::frame::FrameError::Cbor(error)))?;
    let path = paths.descriptor_file(descriptor.session_id);
    write_owner_only_file(&path, &bytes)
}

/// Reads one session's descriptor, or `None` when there is none.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be read or is not a canonical descriptor.
pub fn read(paths: &EnvironmentPaths, session_id: SessionId) -> Result<Option<WorkerDescriptor>> {
    read_file(&paths.descriptor_file(session_id))
}

/// Reads every descriptor currently published for an environment.
///
/// A file that cannot be parsed is reported rather than skipped silently: a descriptor directory
/// the host cannot read completely is a fact the caller has to act on.
///
/// # Errors
///
/// Returns an error when the directory cannot be listed.
pub fn read_all(paths: &EnvironmentPaths) -> Result<Vec<DescriptorEntry>> {
    let directory = paths.descriptors_dir();
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(IpcError::io("list", directory, error)),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| IpcError::io("list", &directory, error))?;
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "kr") {
            continue;
        }
        match read_file(&path) {
            Ok(Some(descriptor)) => found.push(DescriptorEntry {
                path: path.clone(),
                descriptor: Ok(descriptor),
            }),
            Ok(None) => {}
            Err(error) => found.push(DescriptorEntry {
                path: path.clone(),
                descriptor: Err(error.to_string()),
            }),
        }
    }
    found.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(found)
}

/// One descriptor file and what reading it produced.
#[derive(Debug)]
pub struct DescriptorEntry {
    /// The file.
    pub path: std::path::PathBuf,
    /// The descriptor, or why the file could not be read.
    pub descriptor: std::result::Result<WorkerDescriptor, String>,
}

/// Removes a session's descriptor.
///
/// Removing one that is already gone succeeds: retirement is idempotent, and a controller that
/// crashed part way through should be able to finish.
///
/// # Errors
///
/// Returns an error when the file exists and cannot be removed.
pub fn retire(paths: &EnvironmentPaths, session_id: SessionId) -> Result<()> {
    let path = paths.descriptor_file(session_id);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(IpcError::io("retire", path, error)),
    }
}

fn read_file(path: &Path) -> Result<Option<WorkerDescriptor>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(IpcError::io("read", path, error)),
    };
    kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
        .map(Some)
        .map_err(|error| IpcError::Frame(kr_protocol::frame::FrameError::Cbor(error)))
}

#[cfg(test)]
mod tests {
    use kr_protocol::hello::PROTOCOL_VERSION;
    use kr_protocol::identity::{
        BootIdentity, BootIdentitySource, ProcessStartIdentity, ProcessStartSource, WorkerProfile,
    };
    use kr_protocol::ids::SessionEpoch;
    use kr_protocol::scalars::{AuthorisationKey, Bytes, TimestampMs};
    use kr_protocol::session::DisplayNumber;

    use super::*;
    use crate::testing::TempHost;

    fn descriptor(host: &TempHost, session: u8) -> WorkerDescriptor {
        WorkerDescriptor {
            session_id: SessionId::new(kr_protocol::scalars::Uuid::from_bytes([session; 16])),
            session_epoch: SessionEpoch::V1,
            environment_id: host.environment_id(),
            display_number: DisplayNumber::new(u64::from(session)),
            boot_identity: BootIdentity {
                source: BootIdentitySource::LinuxBootId,
                value: Bytes::new(b"boot".to_vec()),
            },
            process_start_identity: ProcessStartIdentity::new(
                42,
                ProcessStartSource::LinuxProcStat,
                99,
            ),
            protocol_version: PROTOCOL_VERSION,
            endpoint: "/run/w1.sock".to_owned(),
            worker_public_key: AuthorisationKey::from_bytes([session; 32]),
            worker_profile: WorkerProfile::HeadlessUser,
            published_at_ms: TimestampMs::new(1),
        }
    }

    #[test]
    fn a_descriptor_round_trips_and_is_owner_only() {
        let host = TempHost::create();
        let paths = host.environment();
        let published = descriptor(&host, 1);
        publish(&paths, &published).expect("publishes");
        let read_back = read(&paths, published.session_id)
            .expect("reads")
            .expect("present");
        assert_eq!(read_back, published);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let mode = std::fs::metadata(paths.descriptor_file(published.session_id))
                .expect("metadata")
                .mode()
                & 0o777;
            assert_eq!(mode, crate::paths::OWNER_ONLY_FILE_MODE);
        }
    }

    #[test]
    fn republishing_replaces_the_previous_version() {
        let host = TempHost::create();
        let paths = host.environment();
        let mut published = descriptor(&host, 2);
        publish(&paths, &published).expect("publishes");
        published.endpoint = "/run/w2.sock".to_owned();
        publish(&paths, &published).expect("republishes");
        let read_back = read(&paths, published.session_id)
            .expect("reads")
            .expect("present");
        assert_eq!(read_back.endpoint, "/run/w2.sock");
        assert_eq!(read_all(&paths).expect("lists").len(), 1);
    }

    #[test]
    fn a_retired_descriptor_is_gone_and_retiring_again_succeeds() {
        let host = TempHost::create();
        let paths = host.environment();
        let published = descriptor(&host, 3);
        publish(&paths, &published).expect("publishes");
        retire(&paths, published.session_id).expect("retires");
        assert!(read(&paths, published.session_id).expect("reads").is_none());
        retire(&paths, published.session_id).expect("retiring again succeeds");
    }

    #[test]
    fn an_unreadable_descriptor_is_reported_rather_than_skipped() {
        let host = TempHost::create();
        let paths = host.environment();
        publish(&paths, &descriptor(&host, 4)).expect("publishes");
        let broken = paths.descriptors_dir().join("broken.kr");
        crate::paths::write_owner_only_file(&broken, b"not canonical cbor").expect("writes");
        let entries = read_all(&paths).expect("lists");
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries.iter().filter(|e| e.descriptor.is_err()).count(),
            1,
            "the unreadable file is listed with its failure"
        );
    }
}
