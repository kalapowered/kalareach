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
use kr_protocol::metrics::{Adapter, MetricOutcome};
use kr_protocol::scalars::{Digest256, Nullable};

use super::decoding::NotDecoded;
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
    /// The generation of the package's repository the admissions carried when the binding was made.
    pub repository_generation: kr_protocol::ids::RepositoryGeneration,
    /// The program the binding recognises.
    pub executable: String,
    /// The component, as pinned.
    pub component: BoundComponent,
    /// Which streams the binding's installation lets its component be offered.
    pub streams: super::binder::Streams,
    /// Whether the binding holds the `Observation` grant, without which it is offered nothing.
    pub observing: bool,
    /// The generation of the instance's source: a new execution of the instance advances it.
    pub generation: u64,
    /// What the instance's bound execution is, as a component is told it.
    pub execution: Execution,
}

/// What a component is told about the execution its binding is bound to: the instance's binding
/// revision, the conversation it has selected, and the turn it is running.
///
/// The broker knows no more than this of what the execution is doing, so a component is told it is
/// running while a turn is and idle otherwise, and is never told it awaits a person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Execution {
    /// The instance's binding revision.
    pub revision: u64,
    /// The conversation the instance has selected, where it has one.
    pub thread_id: Option<String>,
    /// The turn the instance is running, where it is running one.
    pub turn_id: Option<String>,
}

/// What a person is told about a binding's component beyond where it stands.
///
/// Each is the latest of its kind, set by the link or the pump, and a `Registered` binding's report
/// carries them as its reason: how its component was obtained, what its view has missed, and the
/// last time it faulted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ComponentNotes {
    /// How the registration obtained the component and how long that took.
    pub registration: Option<String>,
    /// What the component has missed.
    pub loss: Option<String>,
    /// The last time a call into it faulted.
    pub fault: Option<FaultNote>,
    /// The requests it was not asked to decode, or whose decoding was not taken.
    pub decoding: Option<DecodingNote>,
}

/// The requests a binding's component did not turn into approvals, as a person is told of them:
/// how many, and why the last was not. Never a word the component chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodingNote {
    /// How many requests were not decoded since the binding was registered.
    pub count: u64,
    /// Why the last was not.
    pub last: NotDecoded,
}

impl DecodingNote {
    fn text(self) -> String {
        format!(
            "{} request{} not decoded; the last: {}",
            self.count,
            if self.count == 1 { " was" } else { "s were" },
            self.last.words()
        )
    }
}

/// A fault in a call into a component, as the runtime reported it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultNote {
    /// Which call faulted.
    pub call: String,
    /// The runtime's words, which the component chose in part. None where the fault came to the
    /// worker in or after privacy mode: those words are never kept.
    pub detail: Option<String>,
    /// How many faults the binding has had in the last minute.
    pub faults_in_window: u32,
}

impl FaultNote {
    fn text(&self, private: bool) -> String {
        let detail = self.detail.as_deref().filter(|_| !private);
        match detail {
            // What a component says in a fault can be made of what it was offered, so while privacy
            // mode is on, and for a fault that may have happened in it, only the metadata is told.
            None => format!(
                "last fault, in {} ({} in the last minute); the runtime's words are withheld for \
                 privacy mode",
                self.call, self.faults_in_window
            ),
            Some(detail) => format!(
                "last fault, in {}: {} ({} in the last minute)",
                self.call, detail, self.faults_in_window
            ),
        }
    }
}

impl ComponentNotes {
    fn text(&self, private: bool) -> Option<String> {
        let fault = self.fault.as_ref().map(|fault| fault.text(private));
        let decoding = self.decoding.map(DecodingNote::text);
        let parts: Vec<&str> = [
            self.registration.as_deref(),
            self.loss.as_deref(),
            fault.as_deref(),
            decoding.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect();
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

/// Which of a binding's notes is being set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComponentNote {
    /// How the registration obtained the component.
    Registration(String),
    /// What the component has missed.
    Loss(String),
    /// A fault in a call into the component.
    Fault(FaultNote),
    /// A request that was not decoded.
    Decoding(NotDecoded),
    /// None of them: the binding is registered again, or gone.
    Clear,
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
    notes: Option<&ComponentNotes>,
    private: bool,
) -> Option<ComponentReport> {
    let component = binding.component.as_ref()?;
    let noted = notes.and_then(|notes| notes.text(private));
    let (state, reason) = if let Some(refusal) = component.refusal.as_ref() {
        (ComponentState::Unavailable, Some(refusal.clone()))
    } else if let Some(why) = binding.rich_disabled.as_ref() {
        (ComponentState::Disabled, Some(why.clone()))
    } else {
        match reported {
            // A registered component has no reason of its own; what a person is told is what the
            // worker has noted of it.
            Some((ComponentState::Registered, reason)) => (
                ComponentState::Registered,
                [reason.clone(), noted]
                    .into_iter()
                    .flatten()
                    .reduce(|first, second| format!("{first}; {second}")),
            ),
            Some((state, reason)) => (*state, reason.clone()),
            None => (ComponentState::Pending, None),
        }
    };
    let (reason, reason_cut) = match reason.as_deref().map(cut) {
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
        let state = self.state();
        state
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
                    repository_generation: binding.repository_generation?,
                    executable: binding
                        .executable
                        .as_ref()
                        .map_or_else(String::new, |executable| executable.path.clone()),
                    component: component.clone(),
                    streams: binding.streams,
                    observing: binding
                        .grants
                        .holds(kr_protocol::broker::BrokerGrant::Observation),
                    generation: state
                        .instances
                        .get(&binding.application_instance_id)
                        .map_or(0, |instance| instance.source_generation.get()),
                    execution: state
                        .instances
                        .get(&binding.application_instance_id)
                        .map_or_else(
                            || Execution {
                                revision: 1,
                                thread_id: None,
                                turn_id: None,
                            },
                            |instance| Execution {
                                revision: instance.binding_revision.get(),
                                thread_id: instance
                                    .thread_id
                                    .as_ref()
                                    .map(|thread| thread.as_str().to_owned()),
                                turn_id: instance
                                    .turn_id
                                    .as_ref()
                                    .map(|turn| turn.as_str().to_owned()),
                            },
                        ),
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
        let Some(binding) = held.bindings.get(&binding_id) else {
            return;
        };
        let package = binding.plugin_id.clone();
        let before = held
            .component_states
            .insert(binding_id, (state, reason.map(str::to_owned)));
        drop(held);
        // The runtime says again and again that a component it cannot run is unavailable; the
        // failure is the step into that state, not each saying of it.
        if state == ComponentState::Unavailable
            && before.is_none_or(|(was, _)| was != ComponentState::Unavailable)
            && let Some(adapter) = Adapter::of_package(package.as_str())
        {
            self.adapter_failed(adapter, MetricOutcome::Unavailable);
        }
        drop(held);
        // A request waiting for this component's registration may now be asked, or given up on.
        self.decoding.wake();
    }

    /// Returns the source generation the binding's instance has reached now, where the broker holds
    /// the binding.
    #[must_use]
    pub fn component_generation(&self, binding_id: BrokerBindingId) -> Option<u64> {
        let state = self.state();
        let binding = state.bindings.get(&binding_id)?;
        state
            .instances
            .get(&binding.application_instance_id)
            .map(|instance| instance.source_generation.get())
    }

    /// Records one thing a person is told about a binding's component. A binding the broker no
    /// longer holds is ignored, as in [`Self::set_component_state`].
    pub fn note_component(&self, binding_id: BrokerBindingId, note: ComponentNote) {
        let mut held = self.state();
        if !held.bindings.contains_key(&binding_id) {
            return;
        }
        let notes = held.component_notes.entry(binding_id).or_default();
        match note {
            ComponentNote::Registration(text) => notes.registration = Some(text),
            ComponentNote::Loss(text) => notes.loss = Some(text),
            ComponentNote::Fault(text) => notes.fault = Some(text),
            ComponentNote::Decoding(last) => {
                let count = notes
                    .decoding
                    .map_or(0, |held| held.count)
                    .saturating_add(1);
                notes.decoding = Some(DecodingNote { count, last });
            }
            ComponentNote::Clear => {
                held.component_notes.remove(&binding_id);
            }
        }
    }

    /// Counts one failure of a bundled adapter, for the metrics this host reports about itself.
    pub(crate) fn adapter_failed(&self, adapter: Adapter, outcome: MetricOutcome) {
        self.adapter_failures.adapter_failed(adapter, outcome);
    }

    /// Returns what this broker has counted of the host's own metrics.
    #[must_use]
    pub fn metrics(&self) -> kr_protocol::metrics::Report {
        self.adapter_failures.report()
    }
}

#[cfg(feature = "testing")]
impl Broker {
    /// Gives a binding made from a test's own descriptor the release, the repository generation,
    /// the program and the component that a binding made from admissions has, so that the plugin
    /// runtime is wanted for it and the link registers it.
    ///
    /// # Errors
    ///
    /// Returns [`super::BrokerError::UnknownSubject`] when this broker holds no such binding.
    pub fn ship_component(
        &self,
        binding_id: BrokerBindingId,
        release: kr_protocol::admission::LiveRelease,
        repository_generation: kr_protocol::ids::RepositoryGeneration,
        executable: crate::broker::ledger::BoundExecutable,
        component: BoundComponent,
    ) -> super::Result<()> {
        let mut state = self.state();
        let binding = state
            .bindings
            .get_mut(&binding_id)
            .ok_or_else(|| super::unknown_binding(binding_id))?;
        binding.release = Some(release);
        binding.repository_generation = Some(repository_generation);
        binding.executable = Some(executable);
        binding.component = Some(component);
        state.component_states.remove(&binding_id);
        state.component_notes.remove(&binding_id);
        state.component_changes.notify_one();
        Ok(())
    }

    /// Gives a binding made from a test's own descriptor the streams an installation's capabilities
    /// give a binding made from admissions.
    ///
    /// # Errors
    ///
    /// Returns [`super::BrokerError::UnknownSubject`] when this broker holds no such binding.
    pub fn grant_streams(
        &self,
        binding_id: BrokerBindingId,
        streams: super::binder::Streams,
    ) -> super::Result<()> {
        let mut state = self.state();
        state
            .bindings
            .get_mut(&binding_id)
            .ok_or_else(|| super::unknown_binding(binding_id))?
            .streams = streams;
        state.component_changes.notify_one();
        Ok(())
    }
}
