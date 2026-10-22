//! A host's backups under this computer's recovery.
//!
//! The recovery recipient is registered for a backup collection, and every new archive wraps its
//! manifest key for it, so a kit opens the archives a host makes only if the host was set up under
//! that kit's recipient. Naming the host's writer in a bundle does not do that: a restore would
//! trust the writer and still be unable to open what the writer signed. [`cover_host_archive`]
//! does both, in this order:
//!
//! 1. It reads what the host says of its backups, and declines, with nothing sent to the service,
//!    when the host cannot be covered as it stands: it selects no service or another than the
//!    bundle's, it has no usable sign-in, a setup of it is under way, or it was set up under
//!    another kit and a replacement was not asked for.
//! 2. It commits the bundle naming the archive, the host's producer and the host's writer, by
//!    compare-and-swap, as [`SettingsArchive::enable`](crate::recovery::SettingsArchive::enable)
//!    does, through the one composition [`ArchiveEntries`] holds.
//! 3. It reads the sealed bytes as the service now holds them and sends them to the host with this
//!    computer's recipient: the host writes nothing of the bundle that is already there, and goes
//!    on only if what is there is these bytes.
//! 4. It says the host is covered only after the host answered that it is set up.
//!
//! A host keeps one setup. One set up under another recipient keeps its archive and its recipient,
//! so the only way to put it under this computer's recovery is a replacement: a new archive under
//! the new recipient. The earlier archive keeps what the host published to it and stays readable
//! with its own kit; the host stops adding to it. That is never done unless asked for by name.

use std::fmt;
use std::sync::Arc;

use kr_crypto::kdf::RecoverySeed;
use kr_protocol::archive::{CollectionLocator, RecoveryBundle, TrustedProducer, TrustedWriter};
use kr_protocol::backup_read::BackupSignIn;
use kr_protocol::backup_setup::{
    BackupEnableCause, BackupEnableParams, BackupEnableResult, BackupHostKeys, BackupSetupState,
    BackupStatusParams, BackupStatusResult, BackupUnusable,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{ArchiveId, EnvironmentId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Bytes, DurationMs, StoredEnvelopeKey, TimestampMs, Uuid};

use crate::error::ClientError;
use crate::recovery::files::is_a_lost_answer;
use crate::recovery::{BundleStore, RecoveryError, Result, WriterEnabled, kit_fingerprint};
use crate::services::ServiceFuture;
use crate::session::{Session, Settled};

/// How long an enrolment of the host's backups stays acceptable to the host once sent.
const ENABLE_TTL: DurationMs = DurationMs::new(60_000);

/// The entries one archive needs in a recovery bundle so that a restore can find it and verify
/// what the host made of it.
#[derive(Clone, PartialEq, Eq)]
pub struct ArchiveEntries {
    /// Where the archive is.
    pub collection: CollectionLocator,
    /// The writer a restore trusts to have signed its generations.
    pub writer: TrustedWriter,
    /// The producer whose wraps a restore opens.
    pub producer: TrustedProducer,
}

impl ArchiveEntries {
    /// Puts the archive's collection and producer in `bundle`, once each. The writer goes in
    /// through [`BundleStore::enable_writer`], which is what declares it.
    pub fn enter(&self, bundle: &mut RecoveryBundle) {
        if !bundle.collections.contains(&self.collection) {
            bundle.collections.push(self.collection.clone());
        }
        let mut producers: Vec<TrustedProducer> = bundle
            .trusted_producers
            .iter()
            .filter(|held| held.sender_key_id != self.producer.sender_key_id)
            .cloned()
            .collect();
        producers.push(self.producer.clone());
        bundle.trusted_producers = producers.into_iter().collect();
    }

    /// Commits `bundle` naming the archive, its producer and its writer, in one write, and returns
    /// the evidence that the writer is named only once that write has landed.
    ///
    /// # Errors
    ///
    /// Returns whatever [`BundleStore::enable_writer`] returns.
    pub async fn commit(
        &self,
        bundles: &mut BundleStore,
        seed: &RecoverySeed,
        bundle: &mut RecoveryBundle,
        now: TimestampMs,
    ) -> Result<WriterEnabled> {
        self.enter(bundle);
        bundles
            .enable_writer(seed, bundle, self.writer.clone(), now)
            .await
    }

    /// Takes the archive's collection out of the bundle at the service, for an archive the host
    /// declined to make. The writer and the producer stay: they are the host's own keys, which
    /// name no archive, and a restore lists archives by their collections.
    ///
    /// # Errors
    ///
    /// Returns whatever [`BundleStore::fetch`] and [`BundleStore::commit`] return.
    pub async fn withdraw(
        &self,
        bundles: &mut BundleStore,
        seed: &RecoverySeed,
        now: TimestampMs,
    ) -> Result<()> {
        let mut bundle = bundles.fetch(seed).await?;
        let named = bundle.collections.len();
        bundle.collections.retain(|held| held != &self.collection);
        if bundle.collections.len() == named {
            return Ok(());
        }
        bundles.commit(seed, &mut bundle, now).await.map(|_| ())
    }

    /// Whether `bundle` already names the archive, its producer and its writer.
    #[must_use]
    pub fn carried_by(&self, bundle: &RecoveryBundle) -> bool {
        bundle.collections.contains(&self.collection)
            && bundle.trusted_producers.iter().any(|held| {
                held.sender_key_id == self.producer.sender_key_id
                    && held.stored_envelope_key == self.producer.stored_envelope_key
            })
            && bundle.trusted_writers.iter().any(|held| {
                held.writer_key_id == self.writer.writer_key_id
                    && held.signing_key == self.writer.signing_key
            })
    }
}

/// The host's backups, as its daemon on this machine answers for them.
pub trait HostBackups: Send + Sync + fmt::Debug {
    /// What `backup.status` says.
    fn status(&self) -> ServiceFuture<'_, BackupStatusResult>;

    /// What `backup.enable` says to these parameters. A failure here means the call may have been
    /// carried out.
    fn enable<'a>(
        &'a self,
        params: &'a BackupEnableParams,
    ) -> ServiceFuture<'a, BackupEnableResult>;
}

/// The host on this machine, reached over a session the owner's application holds.
pub struct SessionHost {
    session: Arc<Session>,
    environment_id: EnvironmentId,
}

impl SessionHost {
    /// The host the session is open to, in the environment it stamped on the connection.
    #[must_use]
    pub const fn new(session: Arc<Session>, environment_id: EnvironmentId) -> Self {
        Self {
            session,
            environment_id,
        }
    }
}

impl fmt::Debug for SessionHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionHost")
            .finish_non_exhaustive()
    }
}

/// The preconditions of a call that has none, in the shape the host reads.
#[derive(serde::Serialize)]
struct NoPreconditions {}

impl HostBackups for SessionHost {
    fn status(&self) -> ServiceFuture<'_, BackupStatusResult> {
        Box::pin(async move {
            self.session
                .read(Method::BackupStatus, &BackupStatusParams {})
                .await
        })
    }

    fn enable<'a>(
        &'a self,
        params: &'a BackupEnableParams,
    ) -> ServiceFuture<'a, BackupEnableResult> {
        Box::pin(async move {
            let settled = self
                .session
                .mutate(
                    Method::BackupEnable,
                    ActionTarget::environment(self.environment_id),
                    None,
                    &NoPreconditions {},
                    params,
                    ENABLE_TTL,
                )
                .await?;
            match settled {
                Settled::Result(value) => Ok(value.to_typed()?),
                // The host settled the action with a receipt and not with the setup's own
                // answer: it is not known how the setup ended.
                Settled::Receipt(_) => Err(ClientError::refusal(
                    kr_protocol::error::ErrorCode::OutcomeUnknown,
                    crate::shown::Shown::said(
                        "the host answered with a receipt and not with how the setup ended",
                    ),
                )),
            }
        })
    }
}

/// How a host's backups stand against this computer's recovery.
#[derive(Clone, PartialEq, Eq)]
pub enum HostCover {
    /// The host's backups are set up under this computer's recovery, and the bundle names them.
    Covered(HostCovered),
    /// Nothing was declared: the host's backups are as they were, and this is why.
    Left(Left),
}

/// A host whose archives this computer's kit opens.
#[derive(Clone, PartialEq, Eq)]
pub struct HostCovered {
    /// The archive the host makes its backups in.
    pub archive_id: ArchiveId,
    /// The fingerprint of this computer's kit.
    pub kit_fingerprint: String,
    /// The fingerprint of the kit the host was set up under before, when this replaced a setup.
    pub replaced: Option<String>,
    /// Whether the host was already set up under this computer's recovery, so that nothing was
    /// sent to it.
    pub already: bool,
    /// The bundle's revision once it names the archive.
    pub bundle_revision: u64,
}

/// Why a host was left as it was.
#[derive(Clone, PartialEq, Eq)]
pub enum Left {
    /// The host's configuration selects no storage service.
    NoService,
    /// The host selects another service than the one the bundle is kept at.
    OtherService {
        /// The service the host selects.
        host: String,
    },
    /// The host holds no account token a request may carry, for this reason.
    SignIn(BackupSignIn),
    /// A setup of the host's backups has not ended, under kits with these fingerprints.
    SetupUnderWay {
        /// The fingerprints, oldest first.
        kit_fingerprints: Vec<String>,
    },
    /// The host was set up under another kit. This computer's kit does not open its backups.
    OtherKit {
        /// The fingerprint of the kit the host was set up under.
        host_fingerprint: String,
    },
    /// The host was set up under this computer's kit and cannot make backups now.
    Unusable {
        /// Why.
        why: BackupUnusable,
    },
    /// The host declined, after the bundle was written, for this cause.
    Declined(BackupEnableCause),
}

// What these hold is a service's origin and kit fingerprints, text a diagnostic does not repeat.
crate::debug_as_name!(ArchiveEntries, HostCover, HostCovered, Left);

/// Covers the host's backups with this computer's recovery, where that can be done, and says so
/// only when it has been.
///
/// `replace` asks for a new archive under this computer's recovery over a setup under another kit;
/// without it such a host is left as it is.
///
/// # Errors
///
/// Returns [`RecoveryError::Service`] when the host cannot be asked or refuses the call, whatever
/// [`BundleStore::enable_writer`] returns when the bundle cannot be written, and
/// [`RecoveryError::HostOutcomeUnknown`] when the host's answer to the setup did not come back: a
/// repeat reads the host's status again and finds the setup if it landed. A host that declines or
/// refuses has recorded nothing, and the archive the bundle was made to name is taken out of it
/// again.
pub async fn cover_host_archive(
    host: &dyn HostBackups,
    bundles: &mut BundleStore,
    seed: &RecoverySeed,
    replace: bool,
    now: TimestampMs,
) -> Result<HostCover> {
    let status = host.status().await.map_err(RecoveryError::Service)?;
    let origin = bundles.context().service_origin.clone();
    let (Some(service), Some(keys)) = (status.service.as_ref(), status.keys.as_ref()) else {
        return Ok(HostCover::Left(Left::NoService));
    };
    if service != &origin {
        return Ok(HostCover::Left(Left::OtherService {
            host: service.clone(),
        }));
    }
    let recipient = *seed.recipient()?.public();
    let ours = kit_fingerprint(&recipient);
    let entries = |archive_id: ArchiveId| ArchiveEntries {
        collection: CollectionLocator {
            service_origin: origin.clone(),
            locator: archive_id.to_string(),
            archive_id,
        },
        writer: TrustedWriter {
            writer_key_id: keys.writer_key_id,
            signing_key: keys.writer_public_key,
            enrolled_at_ms: now,
        },
        producer: TrustedProducer {
            sender_key_id: keys.producer_key_id,
            stored_envelope_key: keys.producer_public_key,
            enrolled_at_ms: now,
        },
    };

    let replaced = match &status.setup {
        BackupSetupState::InProgress { kit_fingerprints } => {
            return Ok(HostCover::Left(Left::SetupUnderWay {
                kit_fingerprints: kit_fingerprints.clone(),
            }));
        }
        BackupSetupState::Committed {
            archive_id,
            kit_fingerprint,
            recovery_public_key,
            unusable,
            ..
        } if *recovery_public_key == recipient => {
            if let Some(why) = unusable.0
                && !replace
            {
                return Ok(HostCover::Left(Left::Unusable { why }));
            }
            if unusable.0.is_none() {
                // Set up under this computer's recovery already. The bundle is made to name it if
                // it does not, and the host is sent nothing. Writing the bundle needs the host's
                // sign-in as a setup does, and a host that has none is left as it is.
                if status.sign_in != BackupSignIn::Usable {
                    return Ok(HostCover::Left(Left::SignIn(status.sign_in)));
                }
                let entries = entries(*archive_id);
                let mut bundle = bundles.fetch(seed).await?;
                if !entries.carried_by(&bundle) {
                    entries.commit(bundles, seed, &mut bundle, now).await?;
                }
                return Ok(HostCover::Covered(HostCovered {
                    archive_id: *archive_id,
                    kit_fingerprint: ours,
                    replaced: None,
                    already: true,
                    bundle_revision: bundle.revision.get(),
                }));
            }
            Some(kit_fingerprint.clone())
        }
        BackupSetupState::Committed {
            kit_fingerprint, ..
        } => {
            if !replace {
                return Ok(HostCover::Left(Left::OtherKit {
                    host_fingerprint: kit_fingerprint.clone(),
                }));
            }
            Some(kit_fingerprint.clone())
        }
        BackupSetupState::None {} => None,
    };
    if status.sign_in != BackupSignIn::Usable {
        return Ok(HostCover::Left(Left::SignIn(status.sign_in)));
    }

    // The bundle first, then the host, with the bytes that are at the service.
    let archive_id =
        ArchiveId::new(kr_transport::random::fresh_uuid_v4().map_err(ClientError::from)?);
    let entries = entries(archive_id);
    let mut bundle = bundles.fetch(seed).await?;
    let enabled = entries.commit(bundles, seed, &mut bundle, now).await?;
    // The host is not asked until the call is ready to send, and a failure before that leaves the
    // bundle naming an archive the host never heard of: it is taken out again.
    let params = match setup_for(
        bundles,
        &recipient,
        &ours,
        archive_id,
        keys,
        replaced.is_some(),
        now,
    )
    .await
    {
        Ok(params) => params,
        Err(error) => {
            let _ = entries.withdraw(bundles, seed, now).await;
            return Err(error);
        }
    };
    match host.enable(&params).await {
        Ok(BackupEnableResult::Enabled {
            archive_id: set_up,
            kit_fingerprint,
            ..
        }) if set_up == archive_id && kit_fingerprint == ours => {
            Ok(HostCover::Covered(HostCovered {
                archive_id,
                kit_fingerprint: ours,
                replaced,
                already: false,
                bundle_revision: enabled.bundle_revision(),
            }))
        }
        // An answer for another archive or kit than the one sent says nothing of this one.
        Ok(BackupEnableResult::Enabled { .. }) => Err(RecoveryError::HostOutcomeUnknown {
            retry_after_seconds: None,
        }),
        // A decline says that nothing was recorded, so the bundle must not go on naming an archive
        // the host never made: a restore would list it, and ask which archive to open. Taking it
        // out is one more write, and if it cannot be made the entry stays and the decline is
        // reported all the same.
        Ok(BackupEnableResult::Declined { cause }) => {
            let _ = entries.withdraw(bundles, seed, now).await;
            Ok(HostCover::Left(Left::Declined(cause)))
        }
        // The host may have carried the setup out, so the entry stays: the repeat finds the setup
        // by its status, or the host never made it and the entry is the one left to take out.
        Ok(BackupEnableResult::Unknown {
            retry_after_seconds,
        }) => Err(RecoveryError::HostOutcomeUnknown {
            retry_after_seconds: retry_after_seconds.0.map(|seconds| seconds.get()),
        }),
        // The host answered with a refusal of its own, which it gives before it does anything, so
        // nothing was recorded.
        Err(error) if is_a_definite_refusal(&error) => {
            let _ = entries.withdraw(bundles, seed, now).await;
            Err(RecoveryError::Service(error))
        }
        // Anything else may have followed a call that was carried out: a lost answer, a broken
        // connection, a reply that could not be read. The entry stays, and the repeat finds the
        // setup if it landed.
        Err(_) => Err(RecoveryError::HostOutcomeUnknown {
            retry_after_seconds: None,
        }),
    }
}

/// Whether a failed call to the host is the host refusing it in its own words: an answer that
/// carries an error and is not one of the codes for an answer that was lost.
fn is_a_definite_refusal(error: &ClientError) -> bool {
    matches!(error, ClientError::Host(_)) && !is_a_lost_answer(error)
}

/// The call that sets the host up under this computer's recovery, made from the bundle as the
/// service holds it now.
///
/// # Errors
///
/// Returns whatever [`BundleStore::sealed_as_committed`] returns, and a malformed kit when the
/// bundle's locator is not an identifier.
async fn setup_for(
    bundles: &BundleStore,
    recipient: &StoredEnvelopeKey,
    kit_fingerprint: &str,
    archive_id: ArchiveId,
    keys: &BackupHostKeys,
    replace: bool,
    now: TimestampMs,
) -> Result<BackupEnableParams> {
    let sealed = bundles.sealed_as_committed().await?;
    let bundle_locator = bundles
        .context()
        .bundle_locator
        .parse::<Uuid>()
        .map_err(|_| RecoveryError::MalformedKit {
            what: "a bundle locator that is not an identifier",
        })?;
    Ok(BackupEnableParams {
        archive_id,
        recovery_public_key: *recipient,
        kit_fingerprint: kit_fingerprint.to_owned(),
        bundle_locator,
        sealed_bundle: Bytes::new(sealed),
        request_id: kr_transport::random::fresh_uuid_v4().map_err(ClientError::from)?,
        enabled_at_ms: now,
        writer_key_id: keys.writer_key_id,
        producer_key_id: keys.producer_key_id,
        replace,
    })
}
