//! The worker's link to the plugin runtime.
//!
//! A binding whose package ships a component is registered with the plugin runtime, the process of
//! the worker's own protocol and environment that hosts component instances. The runtime is
//! started when a worker first needs it, by the control daemon; this link asks the daemon for it,
//! connects to it directly and registers the bindings, and the daemon is not in that path
//! afterwards. A daemon that restarts leaves every registration where it is.
//!
//! # What the link holds
//!
//! Nothing the broker decides. Which bindings want a component, and which component, is the
//! broker's ([`Broker::component_wants`]); where each stands is reported back
//! ([`Broker::set_component_state`]). The link keeps the connection and the set of registrations it
//! made on it, and it reads the broker's set fresh each time round, so a binding that was forgotten,
//! disabled or made while a registration was under way is brought into line by the next pass
//! rather than by a case of its own: a registration that finished for a binding that has gone is
//! unbound by the pass that finds it registered and not wanted.
//!
//! It holds no lock of the broker across a call to the runtime, and the broker never waits for it.
//! A runtime that is slow, silent or gone changes what the link reports, and nothing else: the
//! terminal, the native gateway and every request in the broker's ledger go on as they were.
//!
//! # When it asks
//!
//! Only while some binding wants a component. A session that never runs a program whose package
//! ships one asks for nothing, and neither does one whose last such binding has ended: it unbinds,
//! drops its connection, and the runtime holds nothing of it.
//!
//! # What the link does once a component is registered
//!
//! A binding is reported `Registered` as soon as the runtime has its component, and is offered
//! observations (`crate::plugin_observation`) only once the link has made it ready: its held
//! checkpoint restored where there was one. What was observed between the checkpoint and the
//! registration is not replayed, so a restore is a loss, and the pump takes the snapshot it owes
//! before it offers the binding anything. The link takes a checkpoint of a ready binding when it
//! has been offered events and has been quiet for two seconds (or its last attempt is a minute old,
//! or it has never been asked), holds it in memory under the source generation the component was
//! registered in, and restores it when the binding is registered again after the runtime was lost.
//! Held checkpoints are never persisted, and privacy mode drops them. Every thirty seconds it asks
//! the runtime what it is doing; a runtime that does not answer twice running is treated as lost.
//!
//! # When the runtime is lost
//!
//! The connection ends when the runtime does. Every registration on it is gone, and each binding
//! is reported unavailable with the reason. The link asks the daemon again at once for the first
//! loss of a run, and after a wait that doubles from half a second to thirty for the ones after,
//! or when the daemon asked it to wait, whatever else wakes it meanwhile; a link that nothing wants
//! the runtime of any more forgets the wait, and the next binding that wants a component asks at
//! once. The daemon starts a replacement under its own bound, and the link registers every wanted
//! binding again.
//! A binding whose component the runtime disabled after its faults stays disabled: the broker holds
//! that, and does not want it again.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use kr_ipc::paths::EnvironmentPaths;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::identity::PluginIdentity;
use kr_plugin_sdk::ids::RepositoryGeneration;
use kr_plugin_sdk::version::PackageVersion;
use kr_plugin_service::client::PluginClient;
use kr_plugin_service::error::ServiceError;
use kr_plugin_service::protocol::{ComponentSource, Notice};
use kr_plugin_service::vocabulary::{BindingActivity, BindingFacts};
use kr_protocol::admission::{
    ComponentState, PluginRuntimeState, PluginRuntimeUnavailable, PluginRuntimeWanted,
};
use kr_protocol::envelope::ControlFrame;
use kr_protocol::ids::{BrokerBindingId, SessionId};

use crate::broker::Broker;
use crate::broker::component::{ComponentNote, ComponentWant, FaultNote};
use crate::broker::observation::{Held, ObservationLane};
use crate::plugin_observation::{CALL_WAIT, service_id};

/// How long a request to the control daemon is given.
///
/// The daemon answers once the runtime is running, which can mean starting it, and it gives that
/// the runtime's own wait for its acceptance; this is longer, so the answer is the daemon's own.
const ASK_DEADLINE: Duration = Duration::from_secs(45);

/// The longest the link leaves between two attempts to reach the runtime.
const LONGEST_DELAY: Duration = Duration::from_secs(10 * 60);

/// How long a connection must have lasted before a loss of it is the first of a run again.
const STEADY: Duration = Duration::from_secs(60);

/// How long a binding the runtime refused is left before it is offered again, the first time; each
/// refusal after doubles it, up to [`LONGEST_DELAY`].
///
/// A refusal can be the runtime's own and pass: its registration deadline, a full queue of reads,
/// the limit on what one connection holds. A component it cannot take at all is refused again at a
/// cost of one registration each time, which this spaces out.
const REFUSAL_DELAY: Duration = Duration::from_secs(30);

/// How often the runtime is asked what it is doing while a binding is registered.
const HEALTH_EVERY: Duration = Duration::from_secs(30);

/// How many answers to the health question in a row may fail to come before the runtime is taken
/// to be lost.
const HEALTH_FAILURES: u32 = 2;

/// What a binding that is waiting for the runtime is reported as doing, in turn.
const ASKING: &str = "asking the control daemon for the plugin runtime";
const CONNECTING: &str = "connecting to the plugin runtime";
const REGISTERING: &str = "registering with the plugin runtime";

/// What the link needs to reach the control daemon and the runtime.
#[derive(Clone, Debug)]
pub struct RuntimeRequest {
    /// The session this worker serves, which the daemon checks against the process that asks.
    pub session_id: SessionId,
    /// The control daemon's owner-only rendezvous endpoint.
    pub rendezvous: PathBuf,
    /// The environment, whose runtime directory publishes where the runtime is.
    pub environment: EnvironmentPaths,
}

/// Registers the bindings that want a component with the plugin runtime, for as long as the broker
/// lives.
pub async fn link(request: RuntimeRequest, broker: Weak<Broker>) {
    let Some((changes, lane)) = broker
        .upgrade()
        .map(|broker| (broker.component_changes(), broker.observation()))
    else {
        return;
    };
    // The task that offers observations to the registered components lives as long as the link.
    let _pump = AbortOnDrop(tokio::spawn(crate::plugin_observation::pump(Weak::clone(
        &broker,
    ))));
    // The task that asks components to decode the requests they are trusted to decode likewise.
    let _decoder = AbortOnDrop(tokio::spawn(crate::plugin_decoding::decoder(Weak::clone(
        &broker,
    ))));
    let mut link = Link {
        request,
        client: None,
        registered: BTreeMap::new(),
        refused: BTreeMap::new(),
        pace: Pacing::default(),
        last_reason: None,
        lane,
        health_due: None,
        health_failures: 0,
    };
    loop {
        let Some(wants) = broker.upgrade().map(|broker| broker.component_wants()) else {
            return;
        };
        let delay = link.settle(&broker, wants).await;
        link.wait(&broker, &changes, delay).await;
    }
}

/// Ends a task when it is dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Link {
    request: RuntimeRequest,
    client: Option<Arc<PluginClient>>,
    /// The bindings registered on `client`, each with the source generation of its instance when it
    /// was registered: the component holds what it was offered since, whichever generation the
    /// instance has reached.
    registered: BTreeMap<BrokerBindingId, u64>,
    /// The bindings the runtime refused on `client`, and when each may be offered again.
    refused: BTreeMap<BrokerBindingId, Refusal>,
    /// When the runtime may next be reached for.
    pace: Pacing,
    /// Why the runtime was last not reachable, which a binding made while the link waits is told.
    last_reason: Option<String>,
    /// What the worker has to offer the components, what each has missed, and the state held for
    /// each.
    lane: Arc<ObservationLane>,
    /// When the runtime is next asked what it is doing.
    health_due: Option<tokio::time::Instant>,
    /// How many times in a row the runtime did not answer.
    health_failures: u32,
}

/// One binding's refusal by the runtime.
#[derive(Clone, Copy)]
struct Refusal {
    again_at: tokio::time::Instant,
    times: u32,
}

/// When the runtime may next be reached for.
///
/// Every failure to reach it, and every loss of it, fixes a time before which it is not tried
/// again, and a wake for any other reason (a binding made or ended) does not skip that time. After
/// the first loss of a run the next try is at once, because a runtime that ended is replaced by the
/// daemon on the next request; after that the wait doubles from half a second to thirty, and a
/// wait the daemon asked for is that wait.
#[derive(Debug, Default)]
struct Pacing {
    /// How many attempts in a row have ended without the runtime holding the bindings.
    failures: u32,
    connected_at: Option<tokio::time::Instant>,
    not_before: Option<tokio::time::Instant>,
}

impl Pacing {
    /// How much longer to wait before the runtime is reached for, where it is too soon.
    fn held(&self, now: tokio::time::Instant) -> Option<Duration> {
        self.not_before
            .filter(|at| now < *at)
            .map(|at| at.duration_since(now))
    }

    /// How much longer to wait, none where it is not too soon.
    fn remaining(&self, now: tokio::time::Instant) -> Duration {
        self.held(now).unwrap_or(Duration::ZERO)
    }

    /// Notes that the runtime was reached.
    fn connected(&mut self, now: tokio::time::Instant) {
        self.connected_at = Some(now);
        self.not_before = None;
    }

    /// Notes that nothing wants the runtime any more. A wait the daemon asked for is forgotten with
    /// the rest: the next binding that wants a component asks again at once, and the daemon's own
    /// bound on starts is what holds a runtime that keeps ending.
    fn idle(&mut self) {
        *self = Self::default();
    }

    /// Notes that the runtime could not be reached, and that the daemon asked for `asked` before
    /// the next request, where it did.
    fn failed(&mut self, now: tokio::time::Instant, asked: Option<Duration>) {
        self.failures = self.failures.saturating_add(1);
        self.not_before = Some(now + asked.unwrap_or_else(|| self.backoff()));
    }

    /// Notes that a connection to the runtime ended. One that had lasted is the start of a new run
    /// of losses and not a continuation of the last.
    fn lost(&mut self, now: tokio::time::Instant) {
        let steady = self
            .connected_at
            .take()
            .is_some_and(|at| now.duration_since(at) >= STEADY);
        self.failures = if steady {
            1
        } else {
            self.failures.saturating_add(1)
        };
        self.not_before = Some(now + self.backoff());
    }

    /// The wait the failures so far call for: none after the first, then doubling from half a
    /// second.
    fn backoff(&self) -> Duration {
        match self.failures {
            0 | 1 => Duration::ZERO,
            failures => Duration::from_millis(500)
                .saturating_mul(1 << (failures - 2).min(10))
                .min(Duration::from_secs(30)),
        }
    }
}

/// What ended a wait.
enum Event {
    Changed,
    Timer,
    /// A notice from the runtime, or `None` when its connection ended.
    Notice(Option<Notice>),
}

impl Link {
    /// Brings the runtime to what the broker wants of it, keeps up what a registered component
    /// needs, and says how long to leave before the next attempt where this one did not get there.
    async fn settle(
        &mut self,
        broker: &Weak<Broker>,
        wants: Vec<ComponentWant>,
    ) -> Option<Duration> {
        // The streams producers push at all are the streams some binding takes.
        self.lane.set_wanted(
            wants
                .iter()
                .any(|want| want.observing && want.streams.semantic),
            wants
                .iter()
                .any(|want| want.observing && want.streams.terminal),
        );
        let registering = self.register_wanted(broker, &wants).await;
        let keeping = self.keep_up(broker, &wants).await;
        match (registering, keeping) {
            (Some(first), Some(second)) => Some(first.min(second)),
            (delay, None) | (None, delay) => delay,
        }
    }

    /// Brings the runtime's registrations to what the broker wants of it.
    async fn register_wanted(
        &mut self,
        broker: &Weak<Broker>,
        wants: &[ComponentWant],
    ) -> Option<Duration> {
        let wanted: BTreeSet<BrokerBindingId> = wants.iter().map(|want| want.binding_id).collect();

        // What is registered and no longer wanted is unbound: its binding ended, was forgotten or
        // lost its rich capabilities, and the instance it holds in the runtime goes with it.
        let gone: Vec<BrokerBindingId> = self
            .registered
            .keys()
            .filter(|binding| !wanted.contains(binding))
            .copied()
            .collect();
        // A binding that ended while the runtime was lost has no registration to unbind, and its
        // view and held state are forgotten here.
        self.lane.forget_unwanted(&wanted);
        for binding_id in gone {
            let Some(client) = self.client.as_ref() else {
                self.registered.clear();
                break;
            };
            match client.unbind(service_id(binding_id)).await {
                Ok(_) | Err(ServiceError::Protocol { .. } | ServiceError::Disabled { .. }) => {
                    self.registered.remove(&binding_id);
                    self.lane.forget(binding_id);
                    if let Some(broker) = broker.upgrade() {
                        broker.note_component(binding_id, ComponentNote::Clear);
                    }
                }
                Err(error) => {
                    self.lose(broker, &error.to_string());
                    break;
                }
            }
        }
        self.refused
            .retain(|binding_id, _| wanted.contains(binding_id));

        // Nothing wanted, nothing registered: the runtime is not asked for, and a connection to it
        // is not kept.
        if wants.is_empty() {
            if self.registered.is_empty() {
                self.hold(broker, None);
                self.last_reason = None;
                self.pace.idle();
            }
            return None;
        }
        let now = tokio::time::Instant::now();
        let pending: Vec<&ComponentWant> = wants
            .iter()
            .filter(|want| {
                !self.registered.contains_key(&want.binding_id)
                    && self
                        .refused
                        .get(&want.binding_id)
                        .is_none_or(|refusal| refusal.again_at <= now)
            })
            .collect();
        if pending.is_empty() {
            return self.until_a_refusal_is_over(now);
        }
        // A wait the daemon asked for, or a backoff, holds against a wake for any other reason. A
        // binding that came meanwhile is told why the runtime is not being reached for.
        if let Some(wait) = self.pace.held(now) {
            if let Some(reason) = self.last_reason.clone() {
                for want in &pending {
                    report(
                        broker,
                        want.binding_id,
                        ComponentState::Unavailable,
                        Some(&reason),
                    );
                }
            }
            return Some(wait);
        }

        if self.client.is_none() {
            let Some(client) = self.reach(broker, &pending, wants).await else {
                return Some(self.pace.remaining(tokio::time::Instant::now()));
            };
            self.hold(broker, Some(Arc::new(client)));
            self.last_reason = None;
            self.pace.connected(tokio::time::Instant::now());
        }

        for want in pending {
            let Some(client) = self.client.as_ref() else {
                return Some(self.pace.remaining(tokio::time::Instant::now()));
            };
            // A release whose version the runtime cannot be told is this binding's problem and no
            // other's: it is reported, and offered again with the rest that are refused.
            let identity = match identity_of(want) {
                Ok(identity) => identity,
                Err(reason) => {
                    self.refuse(broker, want.binding_id, &reason);
                    continue;
                }
            };
            report(
                broker,
                want.binding_id,
                ComponentState::Pending,
                Some(REGISTERING),
            );
            let registered = client
                .register(
                    service_id(want.binding_id),
                    &identity,
                    &facts_of(want),
                    &want.executable,
                    &ComponentSource {
                        path: want.component.path.clone(),
                        digest: PayloadDigest::from_bytes(*want.component.digest.as_bytes()),
                        bytes: want.component.bytes,
                    },
                )
                .await;
            match registered {
                Ok(registration) => {
                    self.registered.insert(want.binding_id, want.generation);
                    self.refused.remove(&want.binding_id);
                    if let Some(strong) = broker.upgrade() {
                        strong.note_component(
                            want.binding_id,
                            ComponentNote::Registration(if registration.cached {
                                format!(
                                    "loaded from the compiled-code cache in {} ms",
                                    registration.elapsed_ms
                                )
                            } else {
                                format!("compiled in {} ms", registration.elapsed_ms)
                            }),
                        );
                    }
                    report(broker, want.binding_id, ComponentState::Registered, None);
                    if let Err(error) = self.make_ready(broker, want).await {
                        let reason = error.to_string();
                        self.lose(broker, &reason);
                        for want in wants {
                            report(
                                broker,
                                want.binding_id,
                                ComponentState::Unavailable,
                                Some(&reason),
                            );
                        }
                        return Some(self.pace.remaining(tokio::time::Instant::now()));
                    }
                }
                // The runtime answered and said no: this component, not the runtime. The reason is
                // the binding's, and it is offered again after a wait that grows.
                Err(
                    ServiceError::Protocol { detail: reason } | ServiceError::Disabled { reason },
                ) => {
                    self.refuse(broker, want.binding_id, &reason);
                }
                Err(error) => {
                    let reason = error.to_string();
                    self.lose(broker, &reason);
                    // The binding being registered and those behind it were told a step of the
                    // way; every one that wants a component is told what stopped it.
                    for want in wants {
                        report(
                            broker,
                            want.binding_id,
                            ComponentState::Unavailable,
                            Some(&reason),
                        );
                    }
                    return Some(self.pace.remaining(tokio::time::Instant::now()));
                }
            }
        }
        self.until_a_refusal_is_over(tokio::time::Instant::now())
    }

    /// How long until the soonest binding the runtime refused may be offered again, where any is.
    fn until_a_refusal_is_over(&self, now: tokio::time::Instant) -> Option<Duration> {
        self.refused
            .values()
            .map(|refusal| refusal.again_at.saturating_duration_since(now))
            .min()
    }

    /// Records that the runtime refused one binding's component, and when to offer it again.
    fn refuse(&mut self, broker: &Weak<Broker>, binding_id: BrokerBindingId, reason: &str) {
        let times = self
            .refused
            .get(&binding_id)
            .map_or(1, |refusal| refusal.times.saturating_add(1));
        let wait = REFUSAL_DELAY
            .saturating_mul(1 << (times - 1).min(10))
            .min(LONGEST_DELAY);
        self.refused.insert(
            binding_id,
            Refusal {
                again_at: tokio::time::Instant::now() + wait,
                times,
            },
        );
        report(
            broker,
            binding_id,
            ComponentState::Unavailable,
            Some(reason),
        );
    }

    /// Asks the daemon for the runtime and connects to it, reporting each step of it to the
    /// bindings that wait, and what stopped it to every binding that wants a component.
    async fn reach(
        &mut self,
        broker: &Weak<Broker>,
        waiting: &[&ComponentWant],
        wants: &[ComponentWant],
    ) -> Option<PluginClient> {
        for want in waiting {
            report(
                broker,
                want.binding_id,
                ComponentState::Pending,
                Some(ASKING),
            );
        }
        let told = match self.ask().await {
            Ok(PluginRuntimeState::Running) => None,
            Ok(PluginRuntimeState::Unavailable(PluginRuntimeUnavailable {
                reason,
                retry_after_ms,
            })) => {
                // Never sooner than a second, so an answer that names no wait is not a loop.
                let told = Duration::from_millis(retry_after_ms.get())
                    .clamp(Duration::from_secs(1), LONGEST_DELAY);
                Some((reason, Some(told)))
            }
            Err(reason) => Some((reason, None)),
        };
        if told.is_none() {
            for want in waiting {
                report(
                    broker,
                    want.binding_id,
                    ComponentState::Pending,
                    Some(CONNECTING),
                );
            }
            match PluginClient::connect(&self.request.environment).await {
                Ok(client) => return Some(client),
                Err(error) => {
                    self.stopped(
                        broker,
                        wants,
                        &format!("the plugin runtime could not be reached: {error}"),
                        None,
                    );
                    return None;
                }
            }
        }
        if let Some((reason, asked)) = told {
            self.stopped(broker, wants, &reason, asked);
        }
        None
    }

    /// Records that an attempt to reach the runtime failed: why, to every binding that wants a
    /// component, and how long to leave before the next, which is the daemon's figure where it
    /// gave one.
    fn stopped(
        &mut self,
        broker: &Weak<Broker>,
        wants: &[ComponentWant],
        reason: &str,
        asked: Option<Duration>,
    ) {
        for want in wants {
            report(
                broker,
                want.binding_id,
                ComponentState::Unavailable,
                Some(reason),
            );
        }
        self.last_reason = Some(reason.to_owned());
        self.pace.failed(tokio::time::Instant::now(), asked);
    }

    /// Waits until something may have changed: the broker's set, a notice from the runtime, the
    /// end of its connection, or the time the last attempt asked to wait.
    async fn wait(
        &mut self,
        broker: &Weak<Broker>,
        changes: &tokio::sync::Notify,
        delay: Option<Duration>,
    ) {
        // Held for the wait by a reference of its own, so the notice that ends it can be handled
        // with `self` free while another task makes calls on the same connection.
        let client = self.client.clone();
        let event = {
            let timer = async {
                match delay {
                    Some(delay) => tokio::time::sleep(delay).await,
                    None => std::future::pending().await,
                }
            };
            let notice = async {
                match client.as_ref() {
                    // A document is read and dropped here, since nothing in the worker presents
                    // one, so the many a busy component draws do not each cost a pass of the link.
                    Some(client) => loop {
                        match client.notice().await {
                            Some(Notice::Document { .. }) => {}
                            other => break other,
                        }
                    },
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = changes.notified() => Event::Changed,
                () = self.lane.until_state_is_owed() => Event::Changed,
                () = timer => Event::Timer,
                notice = notice => Event::Notice(notice),
            }
        };
        match event {
            Event::Changed | Event::Timer => {}
            Event::Notice(None) => self.lose(broker, "the plugin runtime ended its connection"),
            Event::Notice(Some(Notice::Disabled { binding_id, reason })) => {
                // The runtime has stopped running this component for good. The broker holds that
                // for the binding's life; the next pass sees it no longer wanted and unbinds it.
                // Its reason carries the last fault's words, which are withheld as a fault's are.
                let reason = if self.lane.words_withheld() {
                    "the plugin runtime disabled the component after repeated faults; its words \
                     are withheld for privacy mode"
                        .to_owned()
                } else {
                    reason
                };
                if let Some(broker) = broker.upgrade() {
                    broker.disable_rich(BrokerBindingId::new(binding_id), reason);
                }
            }
            // A call into the component faulted and the binding survived it: a person is told
            // which call and in whose words, and the third fault in a minute disables the binding.
            Event::Notice(Some(Notice::Fault {
                binding_id,
                call,
                detail,
                faults_in_window,
            })) => {
                // Decided by the connection the notice came on and never by when it was read: the
                // words may come from anything a component was handed, however long ago and
                // however many notices are waiting behind this one.
                let withheld = self.lane.words_withheld();
                if let Some(broker) = broker.upgrade() {
                    broker.note_component(
                        BrokerBindingId::new(binding_id),
                        ComponentNote::Fault(FaultNote {
                            call: call.to_string(),
                            detail: (!withheld).then_some(detail),
                            faults_in_window,
                        }),
                    );
                }
            }
            // The runtime's own queue lost observations and asked its component for a fresh
            // snapshot. A document gap concerns a presentation nothing here reads.
            Event::Notice(Some(Notice::Gap {
                binding_id,
                events,
                bytes,
                ..
            })) if events > 0 => {
                if let Some(broker) = broker.upgrade() {
                    broker.note_component(
                        BrokerBindingId::new(binding_id),
                        ComponentNote::Loss(format!(
                            "the plugin runtime's queue dropped {events} observations ({bytes} \
                             bytes) and asked the component for a fresh snapshot"
                        )),
                    );
                }
            }
            // A document nothing here reads.
            Event::Notice(Some(_)) => {}
        }
    }

    /// Makes a binding ready to be offered observations: its held checkpoint restored where it has
    /// one.
    ///
    /// The observations between the checkpoint and this registration were not replayed, so a
    /// restore is a loss: it is numbered, and the pump takes the snapshot it owes before it offers
    /// the component anything. A restore the component does not answer is a loss too, since the
    /// component may hold some of the state it was given, and the snapshot rebuilds its view from
    /// whatever it holds.
    ///
    /// # Errors
    ///
    /// Returns the failure when the runtime cannot be reached.
    async fn make_ready(
        &mut self,
        broker: &Weak<Broker>,
        want: &ComponentWant,
    ) -> Result<(), ServiceError> {
        let Some(client) = self.client.clone() else {
            return Ok(());
        };
        let binding = want.binding_id;
        // The generation the source has reached now, not the one the registration began under: it
        // may have moved while the registration was under way.
        let generation = broker
            .upgrade()
            .and_then(|broker| broker.component_generation(binding))
            .unwrap_or(want.generation);
        let held = self
            .lane
            .take_held(binding, want.package_digest, generation);
        if let Some(held) = held {
            // The component is given state that belongs to this generation.
            self.registered.insert(binding, generation);
            let restored = client
                .restore(service_id(binding), held.state, CALL_WAIT)
                .await;
            let note = match restored {
                Ok(called) if called.answered() => {
                    "the component's state was restored from a checkpoint, and the observations \
                     since it was taken were not replayed"
                }
                Err(ServiceError::Unavailable { detail }) => {
                    return Err(ServiceError::Unavailable { detail });
                }
                Ok(_) | Err(_) => {
                    "the component's state could not be restored from a checkpoint, and the \
                     observations since it was taken were not replayed"
                }
            };
            self.lane.lose_unready(binding, note.to_owned());
            if let Some(strong) = broker.upgrade() {
                strong.note_component(
                    binding,
                    ComponentNote::Loss(format!("{note}; a fresh snapshot is owed")),
                );
            }
        }
        self.lane.set_ready(binding, true);
        Ok(())
    }

    /// Takes the state of the bindings that are due it, and asks the runtime what it is doing when
    /// it is time. Says how long to leave before either is due again.
    async fn keep_up(
        &mut self,
        broker: &Weak<Broker>,
        wants: &[ComponentWant],
    ) -> Option<Duration> {
        let client = self.client.clone()?;
        if self.registered.is_empty() {
            self.health_due = None;
            return None;
        }
        let now = tokio::time::Instant::now();
        let due = *self.health_due.get_or_insert(now + HEALTH_EVERY);
        if now >= due {
            self.health_due = Some(now + HEALTH_EVERY);
            match client.health().await {
                Ok(_) => self.health_failures = 0,
                Err(ServiceError::Unavailable { detail }) => {
                    self.lose(broker, &detail);
                    return Some(self.pace.remaining(tokio::time::Instant::now()));
                }
                Err(_) => {
                    self.health_failures = self.health_failures.saturating_add(1);
                    if self.health_failures >= HEALTH_FAILURES {
                        self.lose(broker, "the plugin runtime stopped answering");
                        return Some(self.pace.remaining(tokio::time::Instant::now()));
                    }
                }
            }
        }
        // One binding's state at a time; the next is taken on the next pass.
        let now = tokio::time::Instant::now();
        let epoch = self.lane.privacy_epoch();
        let due = self.lane.checkpoint_due(now).into_iter().next();
        // Privacy mode may have come on between the choice and the call, and then nothing is asked.
        if let Some(binding) =
            due.filter(|_| !self.lane.is_private() && self.lane.privacy_epoch() == epoch)
        {
            self.lane.checkpoint_attempted(binding, now);
            let want = wants.iter().find(|want| want.binding_id == binding);
            let generation = self.registered.get(&binding).copied();
            match client.checkpoint(service_id(binding), CALL_WAIT).await {
                Ok(called) => {
                    if let (Some(state), Some(want), Some(generation)) =
                        (called.state, want, generation)
                    {
                        self.lane.hold(
                            binding,
                            Held {
                                package_digest: want.package_digest,
                                generation,
                                state,
                            },
                            epoch,
                        );
                    }
                }
                Err(ServiceError::Unavailable { detail }) => {
                    self.lose(broker, &detail);
                    return Some(self.pace.remaining(tokio::time::Instant::now()));
                }
                Err(_) => {}
            }
        }
        let now = tokio::time::Instant::now();
        let health = self
            .health_due
            .map_or(HEALTH_EVERY, |due| due.saturating_duration_since(now));
        Some(
            self.lane
                .next_checkpoint(now)
                .map_or(health, |checkpoint| checkpoint.min(health)),
        )
    }

    /// Records that the runtime is gone: every registration on it with it.
    fn lose(&mut self, broker: &Weak<Broker>, reason: &str) {
        // Nothing is offered to a binding the runtime no longer holds, and what it held of the
        // component's state stays, for the registration that follows.
        self.lane.all_not_ready();
        self.health_due = None;
        self.health_failures = 0;
        for binding_id in std::mem::take(&mut self.registered).into_keys() {
            report(
                broker,
                binding_id,
                ComponentState::Unavailable,
                Some(reason),
            );
            if let Some(strong) = broker.upgrade() {
                strong.note_component(binding_id, ComponentNote::Clear);
            }
        }
        self.refused.clear();
        self.hold(broker, None);
        self.last_reason = Some(reason.to_owned());
        self.pace.lost(tokio::time::Instant::now());
    }

    /// Keeps the connection to the runtime, or lets it go, and tells the broker, which asks
    /// components to prepare actions over it.
    fn hold(&mut self, broker: &Weak<Broker>, client: Option<Arc<PluginClient>>) {
        if client.is_some() {
            // Before anything is registered on it, so that its notices are judged by privacy mode
            // from the start of the connection.
            self.lane.began_connection();
        }
        if let Some(broker) = broker.upgrade() {
            broker.component_calls().set(client.clone());
        }
        self.client = client;
    }

    /// One request to the control daemon's rendezvous endpoint, and its answer.
    async fn ask(&self) -> Result<PluginRuntimeState, String> {
        let wanted = ControlFrame::PluginRuntimeWanted(PluginRuntimeWanted {
            session_id: self.request.session_id,
        });
        match crate::daemon_link::exchange(&self.request.rendezvous, wanted, ASK_DEADLINE).await {
            Ok(ControlFrame::PluginRuntimeState(state)) => Ok(state),
            Ok(_) => Err(
                "the control daemon could not be asked: the control daemon answered with \
                 something else"
                    .to_owned(),
            ),
            Err(why) => Err(format!("the control daemon could not be asked: {why}")),
        }
    }
}

/// Tells the broker where one binding's component stands, if the broker is still there.
fn report(
    broker: &Weak<Broker>,
    binding_id: BrokerBindingId,
    state: ComponentState,
    reason: Option<&str>,
) {
    if let Some(broker) = broker.upgrade() {
        broker.set_component_state(binding_id, state, reason);
    }
}

/// Which code the runtime is asked to run: the package, its release, the generation of its
/// repository the admissions carried and its exact bytes.
fn identity_of(want: &ComponentWant) -> Result<PluginIdentity, String> {
    let version = PackageVersion::parse(&want.version).map_err(|error| {
        format!(
            "the release's version {:?} is not one the plugin runtime is told: {error}",
            want.version
        )
    })?;
    Ok(PluginIdentity::new(
        want.plugin_id.clone(),
        version,
        PayloadDigest::from_bytes(*want.package_digest.as_bytes()),
        RepositoryGeneration::new(want.repository_generation.get()),
    ))
}

/// What the component may read about its binding when it is bound.
fn facts_of(want: &ComponentWant) -> BindingFacts {
    BindingFacts {
        plugin_id: want.plugin_id.to_string(),
        binding_revision: 1,
        activity: BindingActivity::Idle,
        thread_id: None,
        turn_id: None,
        updated_at_ms: kr_ipc::now_ms().get(),
        held_rights: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: tokio::time::Instant, millis: u64) -> tokio::time::Instant {
        base + Duration::from_millis(millis)
    }

    #[test]
    fn the_first_loss_of_a_run_is_tried_again_at_once_and_the_next_ones_wait_longer() {
        let base = tokio::time::Instant::now();
        let mut pace = Pacing::default();
        pace.connected(base);
        pace.lost(at(base, 10));
        assert_eq!(pace.held(at(base, 10)), None);
        // A second loss soon after the first is not the first of a run.
        pace.connected(at(base, 20));
        pace.lost(at(base, 30));
        assert_eq!(pace.held(at(base, 30)), Some(Duration::from_millis(500)));
        pace.connected(at(base, 40));
        pace.lost(at(base, 50));
        assert_eq!(pace.held(at(base, 50)), Some(Duration::from_millis(1_000)));
    }

    #[test]
    fn a_connection_that_lasted_makes_its_loss_the_first_of_a_new_run() {
        let base = tokio::time::Instant::now();
        let mut pace = Pacing::default();
        for step in 0..4 {
            pace.connected(at(base, step));
            pace.lost(at(base, step));
        }
        assert!(pace.held(at(base, 3)).is_some());
        pace.connected(at(base, 10));
        pace.lost(at(base, 10) + STEADY);
        assert_eq!(pace.held(at(base, 10) + STEADY), None);
    }

    #[test]
    fn a_wait_the_daemon_asked_for_holds_however_often_the_link_is_woken() {
        let base = tokio::time::Instant::now();
        let mut pace = Pacing::default();
        pace.failed(base, Some(Duration::from_secs(300)));
        // Woken for another reason a minute later, or four minutes, it is still held, for what is
        // left of the daemon's figure.
        assert_eq!(
            pace.held(base + Duration::from_secs(60)),
            Some(Duration::from_secs(240))
        );
        assert_eq!(
            pace.held(base + Duration::from_secs(240)),
            Some(Duration::from_secs(60))
        );
        assert_eq!(pace.held(base + Duration::from_secs(300)), None);
    }

    #[test]
    fn a_runtime_nothing_wants_any_more_is_forgotten_with_its_failures() {
        let base = tokio::time::Instant::now();
        let mut pace = Pacing::default();
        pace.failed(base, Some(Duration::from_secs(300)));
        pace.idle();
        assert_eq!(pace.held(base), None);
        // And the first failure after is the first of a new run, tried again at once.
        pace.failed(base, None);
        assert_eq!(pace.held(base), None);
    }
}
