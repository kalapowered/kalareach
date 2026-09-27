//! The command integrations a session is launched with.
//!
//! Section 12's opt-in is the environment's configuration: `command_integrations` names the
//! packages whose integration a new session applies. What an integration adds is the release's
//! own, read from its verified manifest, and applies only while the installation holds the
//! owner-confirmed `command_integration.launch` grant. This daemon reads the admitted packages by
//! the same rules a worker reads them, from the admissions the worker is handed first, so a
//! session's entries name exactly the connectors its worker holds: one entry per connector whose
//! integration applies, on where the configuration names its package and off where it does not,
//! so an invocation of an integration left off is answered as a disabled one.
//!
//! The entries are fixed when the session is launched. A later release, grant or configuration
//! reaches the sessions created after it; the worker establishes a backend only while the package
//! an entry names still integrates its command with the entry's flags.

use std::sync::Arc;

use kr_protocol::admission::AdmittedPackage;
use kr_protocol::session::CommandIntegration;
use kr_worker::broker::catalogue::{CheckedPackages, ReadPackage, Reading};

/// This daemon's reader of the packages its admissions carry, each package checked once.
#[derive(Debug, Default)]
pub struct Integrations {
    checked: CheckedPackages,
}

impl Integrations {
    /// A reader that has checked nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads `packages` by a worker's rules. It reads files, so it belongs on a thread that may
    /// block.
    #[must_use]
    pub fn read(&self, packages: &[AdmittedPackage]) -> Reading {
        self.checked.read(packages)
    }
}

/// The entries a session launched with `reading`'s admissions gets: one for each connector whose
/// integration applies, in command order, on where `enabled` names its package.
#[must_use]
pub fn entries(reading: &Reading, enabled: &[String]) -> Vec<CommandIntegration> {
    let mut entries: Vec<CommandIntegration> = reading
        .packages
        .iter()
        .filter_map(|(_, read)| {
            let Ok(ReadPackage::Connector(connector)) = read else {
                return None;
            };
            let integration = connector.integration()?;
            // The connector the command resolves to, which two packages integrating one command
            // leave none of.
            let resolved = reading.sources.for_command(&integration.command)?;
            if !Arc::ptr_eq(&resolved, connector) {
                return None;
            }
            let plugin_id = connector.plugin_id();
            Some(CommandIntegration {
                enabled: enabled.iter().any(|named| named == plugin_id.as_str()),
                plugin_id,
                command: integration.command.clone(),
                flags: integration.flags.clone(),
            })
        })
        .collect();
    entries.sort_by(|left, right| left.command.cmp(&right.command));
    entries
}

#[cfg(test)]
mod tests;
