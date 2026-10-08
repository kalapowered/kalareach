//! The components this broker's bindings ship, and where each stands in the plugin runtime.
//!
//! A binding is made from a package the control daemon admitted, and a package may ship a
//! component. The broker does not run it, and does not talk to the plugin runtime: it keeps what
//! the runtime link needs in order to, and what the link learned. Both are small.
//!
//! * **What is wanted.** Each live binding whose package ships a component, with the location,
//!   digest and size the admissions named when the binding was made. They are pinned there: a
//!   binding stays on the release it was made on after an upgrade, and the component it registers
//!   is that release's, not the installed one's. A binding whose rich capabilities are disabled, or
//!   which is due to end, is not wanted, so the link unbinds it and the runtime's instance goes.
//! * **Where each stands.** The state the link last reported for a binding. It is not the
//!   binding's: it says nothing about its grants, its trust or its faults, and a runtime that is
//!   lost changes it for every binding at once without touching anything the broker decides.
//!
//! The link reads the first with [`Broker::component_wants`], reports the second with
//! [`Broker::set_component_state`], and waits on [`Broker::component_changes`] for the set to move.
//! It holds nothing of the broker's across a call to the runtime.

use std::sync::Arc;

use kr_plugin_sdk::plugin::{PayloadRole, PluginManifest};
use kr_protocol::admission::{AdmittedComponent, ComponentReport, ComponentState};
use kr_protocol::ids::{BrokerBindingId, PluginId};
use kr_protocol::limits::MAX_REPORT_DETAIL_BYTES;
use kr_protocol::scalars::{Digest256, Nullable};

use super::{Binding, Broker};

/// The component a binding's package ships, as the admissions named it when the binding was made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundComponent {
    /// Where the component is, below the directory that holds every repository's store, with `/`
    /// between its parts.
    pub path: String,
    /// The component's digest.
    pub digest: Digest256,
    /// Its exact size.
    pub bytes: u64,
    /// Why this broker will not register it, where the admissions and the package's own manifest
    /// do not name the same component.
    pub refusal: Option<String>,
}

/// One binding whose component the plugin runtime is wanted for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentWant {
    /// The binding.
    pub binding_id: BrokerBindingId,
    /// The package.
    pub plugin_id: PluginId,
    /// The release's version.
    pub version: String,
    /// The exact package hash the binding holds.
    pub package_digest: Digest256,
    /// The admission revision the binding was decided at.
    pub revision: u64,
    /// The program the binding recognises.
    pub executable: String,
    /// The component, as pinned.
    pub component: BoundComponent,
}

/// Reads the component a package ships from the admission and from the package's own manifest, and
/// keeps it only where they agree.
///
/// The admission names where the component is; the manifest, which this worker read and checked
/// itself, names what it is. A binding whose two disagree is bound with a refusal rather than
/// without a component, so the disagreement is reported and not silent.
pub(super) fn bound_component(
    admitted: Option<&AdmittedComponent>,
    manifest: &PluginManifest,
) -> Option<BoundComponent> {
    let declared = manifest.payload(PayloadRole::Component);
    match (admitted, declared) {
        (None, None) => None,
        (Some(admitted), Some(declared))
            if admitted.digest == Digest256::from_bytes(*declared.digest.as_bytes())
                && admitted.bytes.get() == declared.size_bytes.get() =>
        {
            Some(BoundComponent {
                path: admitted.path.clone(),
                digest: admitted.digest,
                bytes: admitted.bytes.get(),
                refusal: None,
            })
        }
        (Some(admitted), _) => Some(BoundComponent {
            path: admitted.path.clone(),
            digest: admitted.digest,
            bytes: admitted.bytes.get(),
            refusal: Some(
                "the admissions name a component that is not the one the package's own manifest \
                 declares"
                    .to_owned(),
            ),
        }),
        (None, Some(declared)) => Some(BoundComponent {
            path: String::new(),
            digest: Digest256::from_bytes(*declared.digest.as_bytes()),
            bytes: declared.size_bytes.get(),
            refusal: Some(
                "the package's manifest declares a component and the admissions name none"
                    .to_owned(),
            ),
        }),
    }
}

/// Cuts `text` to the bound a report carries, at a character boundary.
fn cut(text: &str) -> (String, bool) {
    if text.len() <= MAX_REPORT_DETAIL_BYTES {
        return (text.to_owned(), false);
    }
    let mut end = MAX_REPORT_DETAIL_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), true)
}

/// What the report of a binding's component says, from what the broker holds of it.
pub(super) fn report_of(
    binding: &Binding,
    reported: Option<&(ComponentState, Option<String>)>,
) -> Option<ComponentReport> {
    let component = binding.component.as_ref()?;
    let (state, reason) = if let Some(refusal) = component.refusal.as_ref() {
        (ComponentState::Unavailable, Some(refusal.as_str()))
    } else if let Some(why) = binding.rich_disabled.as_ref() {
        (ComponentState::Disabled, Some(why.as_str()))
    } else {
        match reported {
            Some((state, reason)) => (*state, reason.as_deref()),
            None => (ComponentState::Pending, None),
        }
    };
    let (reason, reason_cut) = match reason.map(cut) {
        Some((text, was_cut)) => (Nullable::some(text), was_cut),
        None => (Nullable::null(), false),
    };
    Some(ComponentReport {
        state,
        reason,
        reason_cut,
    })
}

impl Broker {
    /// Returns what is woken whenever the set of bindings the plugin runtime is wanted for may
    /// have changed: a binding made, forgotten, disabled or due to end.
    ///
    /// A wake that finds nothing changed costs a look at [`Self::component_wants`], and a change
    /// is never missed: the wake is kept until it is waited for.
    #[must_use]
    pub fn component_changes(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.state().component_changes)
    }

    /// Returns every live binding whose component the plugin runtime is wanted for, with the
    /// component as the binding pinned it.
    ///
    /// A binding with its rich capabilities disabled, or due to end, is not here, and neither is one
    /// whose component could not be established.
    #[must_use]
    pub fn component_wants(&self) -> Vec<ComponentWant> {
        self.state()
            .bindings
            .values()
            .filter(|binding| binding.rich_disabled.is_none() && !binding.ending)
            .filter_map(|binding| {
                let component = binding.component.as_ref()?;
                if component.refusal.is_some() {
                    return None;
                }
                let release = binding.release.as_ref()?;
                Some(ComponentWant {
                    binding_id: binding.binding_id,
                    plugin_id: binding.plugin_id.clone(),
                    version: release.version.clone(),
                    package_digest: binding.package_digest,
                    revision: binding.frame.map_or(0, |frame| frame.revision.get()),
                    executable: binding
                        .executable
                        .as_ref()
                        .map_or_else(String::new, |executable| executable.path.clone()),
                    component: component.clone(),
                })
            })
            .collect()
    }

    /// Records where the plugin runtime has the component of one binding.
    ///
    /// A binding the broker no longer holds is ignored: the link learns of it with the next set it
    /// reads, and a report that arrives after the binding went is about nothing.
    pub fn set_component_state(
        &self,
        binding_id: BrokerBindingId,
        state: ComponentState,
        reason: Option<&str>,
    ) {
        let mut held = self.state();
        if held.bindings.contains_key(&binding_id) {
            held.component_states
                .insert(binding_id, (state, reason.map(str::to_owned)));
        }
    }
}

#[cfg(feature = "testing")]
impl Broker {
    /// Gives a binding made from a test's own descriptor the release, the program and the component
    /// that a binding made from admissions has, so that the plugin runtime is wanted for it and the
    /// link registers it.
    ///
    /// # Errors
    ///
    /// Returns [`super::BrokerError::UnknownSubject`] when this broker holds no such binding.
    pub fn ship_component(
        &self,
        binding_id: BrokerBindingId,
        release: kr_protocol::admission::LiveRelease,
        executable: crate::broker::ledger::BoundExecutable,
        component: BoundComponent,
    ) -> super::Result<()> {
        let mut state = self.state();
        let binding = state
            .bindings
            .get_mut(&binding_id)
            .ok_or_else(|| super::unknown_binding(binding_id))?;
        binding.release = Some(release);
        binding.executable = Some(executable);
        binding.component = Some(component);
        state.component_states.remove(&binding_id);
        state.component_changes.notify_one();
        Ok(())
    }
}
