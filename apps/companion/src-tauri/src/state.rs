//! What the backend holds between commands.
//!
//! One host link, one rendezvous origin and one draft store. Nothing here is reachable from the
//! WebView except through the commands, and the commands never hand out a handle: a command
//! returns protocol values, never a capability the page could keep.

use std::sync::{Arc, Mutex, RwLock};

use crate::error::{CommandError, Result};
use crate::link::{HostLink, Unconnected};
use crate::pairing::{self, Origin};

/// The backend's long-lived state.
#[derive(Debug)]
pub struct AppState {
    link: RwLock<Arc<dyn HostLink>>,
    origin: Mutex<Origin>,
    drafts: Mutex<Option<Arc<kr_client::drafts::DraftStore>>>,
}

impl AppState {
    /// Builds the state of an application that has not connected to anything yet.
    ///
    /// # Panics
    ///
    /// Panics when the shipped rendezvous origin does not parse, which is a build-time mistake
    /// rather than a runtime condition.
    #[must_use]
    pub fn new() -> Self {
        Self {
            link: RwLock::new(Arc::new(Unconnected)),
            origin: Mutex::new(
                pairing::parse_origin(pairing::DEFAULT_RENDEZVOUS_ORIGIN)
                    .expect("the shipped rendezvous origin parses"),
            ),
            drafts: Mutex::new(None),
        }
    }

    /// Replaces the host link.
    pub fn connect(&self, link: Arc<dyn HostLink>) {
        *self.link.write().expect("the link lock is not poisoned") = link;
    }

    /// The current host link.
    #[must_use]
    pub fn link(&self) -> Arc<dyn HostLink> {
        Arc::clone(&self.link.read().expect("the link lock is not poisoned"))
    }

    /// The rendezvous origin this device is configured with.
    #[must_use]
    pub fn origin(&self) -> Origin {
        self.origin
            .lock()
            .expect("the origin lock is not poisoned")
            .clone()
    }

    /// Changes the rendezvous origin.
    ///
    /// # Errors
    ///
    /// Returns `INVALID_ARGUMENT` when the value is not an https origin.
    pub fn set_origin(&self, value: &str) -> Result<Origin> {
        let parsed = pairing::parse_origin(value)?;
        *self.origin.lock().expect("the origin lock is not poisoned") = parsed.clone();
        Ok(parsed)
    }

    /// Opens, or reuses, this device's draft store.
    ///
    /// A draft belongs to the device, so the store lives under this application's own per-user
    /// directory and never under a session's working directory.
    ///
    /// # Errors
    ///
    /// Returns the store's own failure when the directory cannot be made durable.
    pub fn drafts(
        &self,
        directory: &std::path::Path,
        device_id: kr_protocol::ids::DeviceId,
    ) -> Result<Arc<kr_client::drafts::DraftStore>> {
        let mut held = self.drafts.lock().expect("the draft lock is not poisoned");
        if let Some(store) = held.as_ref() {
            return Ok(Arc::clone(store));
        }
        let store = kr_client::drafts::DraftStore::open(directory, device_id)
            .map_err(CommandError::from)?;
        let store = Arc::new(store);
        *held = Some(Arc::clone(&store));
        Ok(store)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_application_is_unconnected_and_carries_the_shipped_origin() {
        let state = AppState::new();
        assert!(!state.link().connected());
        assert!(state.origin().is_default);
    }

    #[test]
    fn the_origin_can_be_changed_before_an_attempt_and_the_change_is_what_is_read_back() {
        let state = AppState::new();
        let changed = state
            .set_origin("https://pair.example.org")
            .expect("a valid origin");
        assert!(!changed.is_default);
        assert_eq!(state.origin().origin, "https://pair.example.org");
    }

    #[test]
    fn an_origin_that_is_not_an_https_origin_leaves_the_configured_one_alone() {
        let state = AppState::new();
        assert!(state.set_origin("http://pair.example.org").is_err());
        assert!(state.origin().is_default);
    }
}
