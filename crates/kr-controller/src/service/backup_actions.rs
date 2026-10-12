//! A restore's reads of the managed storage service: the one method that serves them.

use kr_protocol::backup_read::{BackupReadParams, BackupReadResult};
use kr_protocol::envelope::ParamsValue;

use crate::error::{ControllerError, Result};

use super::{Controller, parse};

impl Controller {
    /// Answers `backup.read`.
    ///
    /// Everything but the question of which service this host is configured for reads content that
    /// a restore writes outside the host's retention, so it follows privacy mode as `kr export`
    /// does: it is refused while privacy mode is on, and an answer read under a state that has
    /// changed by the time it would be given is not given. The decision is the published state
    /// before the read and the published state after it; the answer is held, not delivered, when
    /// they differ.
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
        let answer: BackupReadResult = relay.read(read).await?;
        if held && self.privacy.state().now() != before {
            return Err(ControllerError::PermissionDenied {
                detail: "privacy mode changed while that was read, so the answer is not given"
                    .to_owned(),
            });
        }
        ParamsValue::from_typed(&answer)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }
}
