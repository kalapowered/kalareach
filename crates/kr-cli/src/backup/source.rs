//! Where `kr backup restore` reads ciphertext from: the control daemon's relay.
//!
//! The daemon holds the account this host is signed in with, so it is the one that reaches the
//! storage service, and it does so as a relay of ciphertext and public records (`backup.read`).
//! This process holds the kit and opens the archive; the daemon never sees the seed or a plaintext.
//!
//! When the service asks to be left alone the daemon sends nothing and answers how long is left of
//! the delay. This source waits that long, says so on the error stream, and asks the same question
//! again, at most [`MAX_WAITS`] times for one read. After the last it gives up with the time to
//! try again, and the restore removes what it wrote.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use kr_client::error::ClientError;
use kr_client::recovery::{
    BundleWrite, BundleWriter, BundleWritten, RestoreSource, SignInCause, SourceService,
    SourceSignIn,
};
use kr_client::services::{ServiceFuture, SyncFetched, SyncPosition, SyncRecoveryId, SyncRevision};
use kr_client::shown;
use kr_client::shown::{Said as _, Shown};
use kr_protocol::archive::{ArchiveCheckpoint, BackupGenerationPublication};
use kr_protocol::backup_bundle::{
    BackupBundlePlace, BackupBundleWriteParams, BackupBundleWriteResult,
};
use kr_protocol::backup_read::{BackupBundle, BackupReadParams, BackupReadResult, BackupSignIn};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ArchiveId, BackupObjectId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64, Uuid};

use crate::daemon::Daemon;
use crate::error::CliError;

/// How many times one read is repeated after the service asked for quiet.
pub const MAX_WAITS: usize = 5;

/// How a wait is spent.
pub type Pause = Arc<dyn Fn(Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// A wait that takes the time it names.
#[must_use]
pub fn real_pause() -> Pause {
    Arc::new(|time| Box::pin(tokio::time::sleep(time)))
}

/// The control daemon's relay, as a [`RestoreSource`].
pub struct DaemonSource {
    daemon: tokio::sync::Mutex<Daemon>,
    pause: Pause,
}

kr_client::debug_as_name!(DaemonSource);

impl DaemonSource {
    /// A source that reads through `daemon` and spends the waits it is told to with `pause`.
    #[must_use]
    pub fn new(daemon: Daemon, pause: Pause) -> Self {
        Self {
            daemon: tokio::sync::Mutex::new(daemon),
            pause,
        }
    }

    /// Asks one read, repeating it after each wait the daemon names, at most [`MAX_WAITS`] times.
    async fn ask(&self, params: BackupReadParams) -> kr_client::Result<BackupReadResult> {
        let mut waited = 0;
        loop {
            let answer = {
                let mut daemon = self.daemon.lock().await;
                daemon
                    .read::<_, BackupReadResult>(Method::BackupRead, &params)
                    .await
                    .map_err(from_command)?
            };
            let BackupReadResult::Wait {
                retry_after_seconds,
            } = answer
            else {
                return Ok(answer);
            };
            let seconds = retry_after_seconds.get();
            if waited == MAX_WAITS {
                return Err(ClientError::Host(kr_client::error::refusal(
                    ErrorCode::RateLimited,
                    shown!(
                        "the storage service still asks this host to wait about {} more seconds \
                         after {} waits; try again after that, and nothing was kept",
                        seconds,
                        MAX_WAITS
                    ),
                )));
            }
            waited += 1;
            crate::report::say(&shown!(
                "The storage service asked to be left alone. Waiting {} s, wait {} of {}.",
                seconds,
                waited,
                MAX_WAITS
            ));
            (self.pause)(Duration::from_secs(seconds)).await;
        }
    }
}

/// What the daemon's refusal or a failure of the connection is, as the client library carries it.
fn from_command(error: CliError) -> ClientError {
    match error {
        CliError::Refused(refusal) => ClientError::Host(refusal),
        CliError::Ipc(failure) => ClientError::Ipc(failure),
        other => ClientError::Host(kr_client::error::refusal(
            ErrorCode::ResourceUnavailable,
            other.said(),
        )),
    }
}

fn contrary() -> ClientError {
    ClientError::Host(kr_client::error::refusal(
        ErrorCode::ResourceUnavailable,
        Shown::said("the daemon answered a read with another read's answer"),
    ))
}

impl RestoreSource for DaemonSource {
    fn service(&self) -> ServiceFuture<'_, SourceService> {
        Box::pin(async move {
            match self.ask(BackupReadParams::Service {}).await? {
                BackupReadResult::Service { origin, sign_in } => Ok(SourceService {
                    origin,
                    sign_in: match sign_in {
                        BackupSignIn::Usable => SourceSignIn::Usable,
                        BackupSignIn::SignedOut => SourceSignIn::Unusable(SignInCause::SignedOut),
                        BackupSignIn::Waiting => SourceSignIn::Unusable(SignInCause::Waiting),
                        BackupSignIn::Ended => SourceSignIn::Unusable(SignInCause::Ended),
                        BackupSignIn::WithoutScope => {
                            SourceSignIn::Unusable(SignInCause::WithoutScope)
                        }
                        BackupSignIn::NotRenewed => SourceSignIn::Unusable(SignInCause::NotRenewed),
                    },
                }),
                _ => Err(contrary()),
            }
        })
    }

    fn bundle<'a>(&'a self, locator: &'a str) -> ServiceFuture<'a, SyncFetched> {
        Box::pin(async move {
            let locator: Uuid = locator.parse().map_err(|_| {
                ClientError::Host(kr_client::error::refusal(
                    ErrorCode::InvalidArgument,
                    Shown::said("the bundle locator is not an identifier"),
                ))
            })?;
            match self.ask(BackupReadParams::Bundle { locator }).await? {
                BackupReadResult::Bundle {
                    bundle:
                        BackupBundle::Held {
                            write_sequence,
                            revision,
                            recovery,
                            ciphertext,
                        },
                } => {
                    let recovery = recovery.0.map(SyncRecoveryId::new);
                    let position = match revision.0 {
                        Some(revision) => SyncPosition::at(
                            write_sequence.get(),
                            SyncRevision::new(revision),
                            recovery,
                        ),
                        None => SyncPosition::removed_at(write_sequence.get(), recovery),
                    };
                    Ok(SyncFetched::Held {
                        position,
                        ciphertext: ciphertext.as_slice().to_vec(),
                    })
                }
                BackupReadResult::Bundle {
                    bundle: BackupBundle::Absent { recovery },
                } => Ok(SyncFetched::Absent {
                    recovery: recovery.0.map(SyncRecoveryId::new),
                }),
                _ => Err(contrary()),
            }
        })
    }

    fn generation<'a>(
        &'a self,
        archive: ArchiveId,
        checkpoint: Option<&'a ArchiveCheckpoint>,
    ) -> ServiceFuture<'a, Option<BackupGenerationPublication>> {
        Box::pin(async move {
            let params = BackupReadParams::Generation {
                archive_id: archive,
                checkpoint: Nullable(checkpoint.cloned()),
            };
            match self.ask(params).await? {
                BackupReadResult::Generation { publication } => Ok(publication.0),
                _ => Err(contrary()),
            }
        })
    }

    fn object(
        &self,
        archive: ArchiveId,
        object: BackupObjectId,
        offset: u64,
        length: u64,
    ) -> ServiceFuture<'_, Vec<u8>> {
        Box::pin(async move {
            let params = BackupReadParams::Object {
                archive_id: archive,
                object_id: object,
                offset: U64::new(offset),
                length: U64::new(length),
            };
            match self.ask(params).await? {
                BackupReadResult::Object { bytes } => Ok(bytes.as_slice().to_vec()),
                _ => Err(contrary()),
            }
        })
    }
}

/// The control daemon's relay, as the place a restore records the checkpoint it verified.
///
/// Each write opens a connection of its own: the connections of a restore have waited for as long
/// as the files took to write, and the daemon ends one that stops reading.
pub struct DaemonBundleWriter {
    paths: kr_ipc::paths::HostPaths,
    selector: crate::cli::EnvironmentSelector,
}

kr_client::debug_as_name!(DaemonBundleWriter);

impl DaemonBundleWriter {
    /// A writer that reaches the environment `environment` names under `paths`, or this
    /// installation's own.
    #[must_use]
    pub const fn new(paths: kr_ipc::paths::HostPaths, environment: Option<String>) -> Self {
        Self {
            paths,
            selector: crate::cli::EnvironmentSelector { environment },
        }
    }
}

impl BundleWriter for DaemonBundleWriter {
    fn write<'a>(&'a self, write: BundleWrite<'a>) -> ServiceFuture<'a, BundleWritten> {
        Box::pin(async move {
            let locator: Uuid = write.locator.parse().map_err(|_| {
                ClientError::Host(kr_client::error::refusal(
                    ErrorCode::InvalidArgument,
                    Shown::said("the bundle locator is not an identifier"),
                ))
            })?;
            let place = |position: SyncPosition| BackupBundlePlace {
                write_sequence: U64::new(position.write_sequence),
                revision: Nullable(position.revision.0.map(|revision| revision.get())),
                recovery: Nullable(position.recovery().map(|recovery| recovery.get())),
            };
            let params = BackupBundleWriteParams {
                locator,
                expected: place(write.expected),
                request_id: write.request_id,
                signed_at_ms: kr_protocol::scalars::TimestampMs::new(write.signed_at_ms),
                sealed_bundle: kr_protocol::scalars::Bytes::new(write.sealed.to_vec()),
            };
            let mut daemon = Daemon::open(&self.paths, &self.selector)
                .await
                .map_err(from_command)?;
            let answer = daemon
                .mutate::<_, BackupBundleWriteResult>(Method::BackupBundleWrite, &params)
                .await
                .map_err(from_command)?;
            Ok(match answer {
                BackupBundleWriteResult::Written { place } => {
                    BundleWritten::Written(position(place))
                }
                BackupBundleWriteResult::Conflict { .. } => BundleWritten::Conflict,
                BackupBundleWriteResult::Wait {
                    retry_after_seconds,
                } => BundleWritten::Wait {
                    seconds: retry_after_seconds.get(),
                },
            })
        })
    }
}

/// Where the daemon says a write left the bundle, as the client library names a place.
fn position(place: BackupBundlePlace) -> SyncPosition {
    let recovery = place.recovery.0.map(SyncRecoveryId::new);
    match place.revision.0 {
        Some(revision) => SyncPosition::at(
            place.write_sequence.get(),
            SyncRevision::new(revision),
            recovery,
        ),
        None => SyncPosition::removed_at(place.write_sequence.get(), recovery),
    }
}
