//! The methods that serve this host's backups to the command line: a restore's reads of the managed
//! storage service, and the owner's setup of what the host backs up.

use kr_protocol::backup_bundle::BackupBundleWriteParams;
use kr_protocol::backup_read::{BackupReadParams, BackupReadResult};
use kr_protocol::backup_setup::{BackupEnableParams, BackupEnableResult, BackupStatusParams};
use kr_protocol::envelope::{MutationRequest, ParamsValue};

use crate::error::{ControllerError, Result};

use super::{Controller, parse};

impl Controller {
    /// Answers `backup.read`.
    ///
    /// Everything but the question of which service this host is configured for reads content that
    /// a restore writes outside the host's retention, so it follows privacy mode as `kr export`
    /// does. It is refused while privacy mode is on. The state is read as the read begins, checked
    /// again where the request leaves the host (after the wait for an account token, which can be
    /// long), and read once more when the service has answered: an answer whose read ended under
    /// another state than it began under is not given. A request already on its way when privacy
    /// mode is turned on cannot be recalled; what it returns is dropped here, and the command
    /// reads privacy mode again after the last answer.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] when the host selects no storage service,
    /// [`ControllerError::PermissionDenied`] while privacy mode is on or when it changed during the
    /// read, and the relay's own refusals otherwise.
    pub(super) async fn backup_read(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let read: BackupReadParams = parse(params)?;
        let Some(relay) = &self.backup_relay else {
            return Err(ControllerError::NotConfigured(format!(
                "{} in this host's configuration document ({}) selects no storage service, so there \
                 is nothing to read a backup from",
                kr_protocol::hostinfo::configuration::STORAGE_ORIGIN.key,
                kr_protocol::hostinfo::configuration::FILE_NAME,
            )));
        };
        let held = !matches!(read, BackupReadParams::Service {});
        let before = self.privacy.state().now();
        if held && before.private {
            return Err(ControllerError::PermissionDenied {
                detail: "privacy mode is on, and a restore reads nothing while it is".to_owned(),
            });
        }
        let answer: BackupReadResult = relay.read(read, before).await?;
        if held && self.privacy.state().now() != before {
            return Err(ControllerError::PermissionDenied {
                detail: "privacy mode changed while that was read, so the answer is not given"
                    .to_owned(),
            });
        }
        ParamsValue::from_typed(&answer)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Answers `backup.bundle.write`: moves the recovery bundle on by one compare-and-swap, for a
    /// restore that has verified a generation and records it.
    ///
    /// The call is refused while privacy mode is on, as `backup.read` is, and when it changed while
    /// the call waited for a token; a write that has been sent is answered as it ended, because a
    /// restore that is told nothing about a bundle that was in fact written would write it again.
    /// The daemon keeps no record of the write.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] when the host selects no storage service,
    /// [`ControllerError::PermissionDenied`] while privacy mode is on, and the relay's own
    /// refusals otherwise.
    pub(super) async fn backup_bundle_write(
        &self,
        mutation: &MutationRequest,
    ) -> Result<ParamsValue> {
        let write: BackupBundleWriteParams = parse(&mutation.params)?;
        let Some(relay) = &self.backup_relay else {
            return Err(ControllerError::NotConfigured(format!(
                "{} in this host's configuration document ({}) selects no storage service, so there \
                 is no bundle to write",
                kr_protocol::hostinfo::configuration::STORAGE_ORIGIN.key,
                kr_protocol::hostinfo::configuration::FILE_NAME,
            )));
        };
        let before = self.privacy.state().now();
        if before.private {
            return Err(ControllerError::PermissionDenied {
                detail: "privacy mode is on, and nothing is written to the recovery bundle while \
                         it is"
                    .to_owned(),
            });
        }
        let answer = relay.write_bundle(write, before).await?;
        ParamsValue::from_typed(&answer)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Answers `backup.status`: where this host's backups stand, for the owner who is setting them
    /// up.
    ///
    /// The service is read live, bounded, and not at all while the service has asked to be left
    /// alone.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] when the host selects no storage service,
    /// [`ControllerError::InvalidArgument`] for parameters that are not empty, and
    /// [`ControllerError::RegistryUnavailable`] when the record of the setup cannot be read: a
    /// store that could not be read does not say that the host is not set up.
    pub(super) async fn backup_status(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let _: BackupStatusParams = parse(params)?;
        let setup = self.backup_setup_of()?;
        let answer = setup.status(self.privacy.state().now().private).await?;
        ParamsValue::from_typed(&answer)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Answers `backup.enable`: sets this host's backups up, as the command asked.
    ///
    /// Setting up moves no content: the bundle is key material, so privacy mode neither stops it
    /// nor is stopped by it. What the call writes to the service is the sealed bundle, a writer's
    /// enrolment and the account's retention switch.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] when the host selects no storage service, and
    /// [`ControllerError::InvalidArgument`] for a call that is not well formed.
    pub(super) async fn backup_enable(
        self: &std::sync::Arc<Self>,
        mutation: &MutationRequest,
    ) -> Result<ParamsValue> {
        #[cfg(any(test, feature = "testing"))]
        crate::testing::note_backup_enable(self.paths.environment_id(), &mutation.params);
        let params: BackupEnableParams = parse(&mutation.params)?;
        let answer = self.enable_backups(params).await?;
        ParamsValue::from_typed(&answer)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    async fn enable_backups(
        self: &std::sync::Arc<Self>,
        params: BackupEnableParams,
    ) -> Result<BackupEnableResult> {
        let setup = self.backup_setup_of()?;
        // The setup is committed on a thread that this call can stop waiting for. The thread keeps
        // the daemon, and with it the environment's lock, until the commit has ended: a commit that
        // went on after the lock was let go could land beside the next daemon's start.
        let daemon = std::sync::Arc::clone(self) as std::sync::Arc<dyn std::any::Any + Send + Sync>;
        setup.enable(params, daemon).await
    }

    /// Sets this host's backups up as `backup.enable` does, for a suite that stops waiting for the
    /// call while its commit is still to be made.
    ///
    /// # Errors
    ///
    /// As `backup.enable`.
    #[cfg(feature = "testing")]
    pub async fn enable_backups_for_a_test(
        self: &std::sync::Arc<Self>,
        params: BackupEnableParams,
    ) -> Result<BackupEnableResult> {
        self.enable_backups(params).await
    }

    /// Stops the next `backup.status` between its two reads, for a suite that holds a call before
    /// its commit and lets it end in the gap. Returns the end that says the status has arrived and
    /// the end that lets it go.
    #[cfg(feature = "testing")]
    pub fn pause_the_next_status_between_its_reads(
        &self,
    ) -> Option<(
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    )> {
        self.backup_setup
            .as_ref()
            .map(|setup| setup.pause_the_next_status_between_its_reads())
    }

    fn backup_setup_of(&self) -> Result<&std::sync::Arc<crate::backup::setup::BackupSetup>> {
        self.backup_setup.as_ref().ok_or_else(|| {
            ControllerError::NotConfigured(format!(
                "{} in this host's configuration document ({}) selects no storage service, so \
                 there is nothing to set backups up at",
                kr_protocol::hostinfo::configuration::STORAGE_ORIGIN.key,
                kr_protocol::hostinfo::configuration::FILE_NAME,
            ))
        })
    }
}
