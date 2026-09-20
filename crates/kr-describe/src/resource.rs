//! The memory reserve, power and pressure, and `resource_paused`.
//!
//! Section 22's resource paragraph is the one that decides whether this feature is usable on the
//! 8 GiB laptop it is supposed to be usable on. It asks for four things and this module is each of
//! them:
//!
//! 1. Before loading, the target's measured peak estimate **plus a reserve of at least the larger
//!    of 1 GiB or 20% of physical RAM**, read from the qualified available-memory signal.
//! 2. When the reserve cannot be maintained: pause or unload, keep the metadata titles, report
//!    `resource_paused`. An owner may configure a *stricter* reserve.
//! 3. Battery paused by default unless explicitly enabled; thermal or memory pressure pauses even
//!    on mains.
//! 4. Re-evaluate after pressure clears, **without restarting a worker**.
//!
//! # Why a signal says whether it is qualified
//!
//! Section 22 says *using the qualified available-memory/pressure signal*, and a host that cannot
//! read one has to say so rather than assume. [`Signal`] carries that: a reading is either
//! qualified or it names why this build cannot take it on this platform. The policy then treats an
//! unqualified memory signal as a refusal to load, because the reserve is a promise and a promise
//! nobody measured is not one. It treats an unqualified *power* signal as battery, for the same
//! reason in the other direction: section 22 defaults battery to paused, and a host that cannot
//! tell has not been told it is on mains.
//!
//! # What "pause" means here, exactly
//!
//! Pausing stops admitting and dispatching inference. It does not remove a title, it does not
//! close a session, it does not end a worker and it does not forget the queue's aging positions.
//! [`ResourceState::ResourcePaused`] is a reportable state with a reason in it, and
//! [`ResourcePolicy::evaluate`] moves out of it on the next tick that finds the pressure gone. A
//! worker restart is not part of any path through this module.

use crate::budget::{Budgets, GIB, ResidentCost};

/// A reading this host either has or explicitly does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal<T> {
    /// The host read it.
    Qualified(T),
    /// This build cannot read it on this platform, and here is why.
    Unqualified {
        /// Why not, in words a report can carry.
        why: &'static str,
    },
}

impl<T: Copy> Signal<T> {
    /// Returns the reading, when there is one.
    #[must_use]
    pub const fn value(self) -> Option<T> {
        match self {
            Self::Qualified(value) => Some(value),
            Self::Unqualified { .. } => None,
        }
    }

    /// Returns whether this host reads this signal.
    #[must_use]
    pub const fn is_qualified(self) -> bool {
        matches!(self, Self::Qualified(_))
    }
}

/// Where the host's power comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerSource {
    /// Mains.
    Mains,
    /// A battery.
    Battery,
}

/// What the host says about its temperature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThermalState {
    /// Nothing is being held back.
    Nominal,
    /// The host is limiting something.
    Elevated,
    /// The host is limiting a great deal.
    Critical,
}

/// One reading of everything the resource policy depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostConditions {
    /// Physical RAM.
    pub physical_memory_bytes: Signal<u64>,
    /// Memory available right now.
    pub available_memory_bytes: Signal<u64>,
    /// Where power comes from.
    pub power: Signal<PowerSource>,
    /// What the host says about its temperature.
    pub thermal: Signal<ThermalState>,
}

impl HostConditions {
    /// Builds a reading in which every signal is qualified, which is what a test drives.
    #[must_use]
    pub const fn measured(
        physical_memory_bytes: u64,
        available_memory_bytes: u64,
        power: PowerSource,
        thermal: ThermalState,
    ) -> Self {
        Self {
            physical_memory_bytes: Signal::Qualified(physical_memory_bytes),
            available_memory_bytes: Signal::Qualified(available_memory_bytes),
            power: Signal::Qualified(power),
            thermal: Signal::Qualified(thermal),
        }
    }
}

/// Why inference is not running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauseReason {
    /// Loading would leave less than the reserve.
    MemoryReserve,
    /// The reserve stopped holding while the model was resident.
    MemoryPressure,
    /// The host is thermally limited.
    Thermal,
    /// The host is on battery and inference on battery has not been enabled.
    Battery,
    /// This host cannot read a signal the decision needs.
    SignalUnqualified {
        /// Which signal.
        signal: &'static str,
    },
    /// An owner turned inference off.
    Disabled,
}

impl PauseReason {
    /// Returns the stable reason this pause is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemoryReserve => "memory_reserve",
            Self::MemoryPressure => "memory_pressure",
            Self::Thermal => "thermal",
            Self::Battery => "battery",
            Self::SignalUnqualified { .. } => "signal_unqualified",
            Self::Disabled => "disabled",
        }
    }
}

/// What state inference is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceState {
    /// Nothing is loaded and nothing is stopping a load.
    Ready,
    /// Inference is admitted: nothing in the resource or power policy is stopping a job.
    ///
    /// It does not say a model is mapped. Whether weights are resident is the service's own fact,
    /// and it is the service that tells [`ResourcePolicy::evaluate`] so.
    Admitted,
    /// Inference is paused. Metadata titles are unaffected and the queue keeps its positions.
    ResourcePaused {
        /// Why.
        reason: PauseReason,
        /// Whether a model was unloaded to reach this state.
        unloaded: bool,
    },
}

impl ResourceState {
    /// Returns the stable name this state is reported under.
    ///
    /// `resource_paused` is section 22's own word, and it is what a client sees.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Admitted => "admitted",
            Self::ResourcePaused { .. } => "resource_paused",
        }
    }

    /// Returns whether a job may be dispatched in this state.
    #[must_use]
    pub const fn dispatches(self) -> bool {
        matches!(self, Self::Admitted)
    }
}

/// The owner's settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceSettings {
    /// Whether descriptions are enabled at all.
    pub enabled: bool,
    /// Whether inference may run on battery. Section 22 defaults this off.
    pub on_battery: bool,
    /// A reserve the owner has asked for. It applies only when it is stricter than section 22's.
    pub owner_reserve_bytes: Option<u64>,
    /// A process ceiling the owner has asked for. It applies only when it is stricter.
    pub owner_ceiling_bytes: Option<u64>,
}

impl Default for ResourceSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            on_battery: false,
            owner_reserve_bytes: None,
            owner_ceiling_bytes: None,
        }
    }
}

/// The resource and power policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourcePolicy {
    settings: ResourceSettings,
    budgets: Budgets,
    state: ResourceState,
}

impl ResourcePolicy {
    /// Builds the policy.
    #[must_use]
    pub const fn new(settings: ResourceSettings, budgets: Budgets) -> Self {
        Self {
            settings,
            budgets,
            state: ResourceState::Ready,
        }
    }

    /// Returns the state.
    #[must_use]
    pub const fn state(&self) -> ResourceState {
        self.state
    }

    /// Returns the budgets, with any stricter owner ceiling applied.
    #[must_use]
    pub const fn budgets(&self) -> Budgets {
        match self.settings.owner_ceiling_bytes {
            Some(ceiling) => self.budgets.with_owner_ceiling(ceiling),
            None => self.budgets,
        }
    }

    /// Returns the reserve this host must keep free.
    ///
    /// Section 22 fixes the floor at *the larger of 1 GiB or 20% of physical RAM*. An owner's
    /// figure only ever raises it: a configured reserve below the floor is the owner asking for
    /// less safety than the product was qualified with, and it is ignored.
    #[must_use]
    pub fn required_reserve_bytes(&self, physical_memory_bytes: u64) -> u64 {
        let floor = GIB.max(physical_memory_bytes / 5);
        match self.settings.owner_reserve_bytes {
            Some(owner) if owner > floor => owner,
            _ => floor,
        }
    }

    /// Decides what to do now, from one reading.
    ///
    /// The decision is made afresh every time rather than remembered, which is what makes "the
    /// pressure cleared" an ordinary outcome instead of a recovery path. The previous state is
    /// used for exactly one thing: knowing whether moving to a pause means unloading something.
    pub fn evaluate(
        &mut self,
        conditions: &HostConditions,
        cost: &ResidentCost,
        resident: bool,
    ) -> Transition {
        let next = self.decide(conditions, cost, resident);
        let transition = Transition {
            from: self.state,
            to: next,
            restarted_worker: false,
        };
        self.state = next;
        transition
    }

    fn decide(
        &self,
        conditions: &HostConditions,
        cost: &ResidentCost,
        resident: bool,
    ) -> ResourceState {
        let pause = |reason: PauseReason| ResourceState::ResourcePaused {
            reason,
            unloaded: resident,
        };
        if !self.settings.enabled {
            return pause(PauseReason::Disabled);
        }
        // Power first. Section 22 defaults battery to paused, and a host that cannot read its own
        // power source has not been told it is on mains.
        match conditions.power {
            Signal::Qualified(PowerSource::Battery) if !self.settings.on_battery => {
                return pause(PauseReason::Battery);
            }
            Signal::Unqualified { .. } if !self.settings.on_battery => {
                return pause(PauseReason::Battery);
            }
            _ => {}
        }
        // Thermal pressure pauses even on mains. An unqualified thermal signal does not pause on
        // its own: unlike memory, there is no promise being made about it, and a host that cannot
        // read a temperature is not thereby hot.
        if matches!(
            conditions.thermal,
            Signal::Qualified(ThermalState::Elevated | ThermalState::Critical)
        ) {
            return pause(PauseReason::Thermal);
        }
        let Signal::Qualified(physical) = conditions.physical_memory_bytes else {
            return pause(PauseReason::SignalUnqualified {
                signal: "physical_memory",
            });
        };
        let Signal::Qualified(available) = conditions.available_memory_bytes else {
            return pause(PauseReason::SignalUnqualified {
                signal: "available_memory",
            });
        };
        if !self.budgets().admits(cost) {
            return pause(PauseReason::MemoryReserve);
        }
        let reserve = self.required_reserve_bytes(physical);
        // While a model is resident its cost is already inside `available`, so the question is
        // whether the reserve still holds; before a load it is not, so the cost has to come out of
        // `available` first. Which world this is comes from the caller, which holds the runtime:
        // inferring it from the previous state is how a host comes to refuse a load and then admit
        // the same load a tick later.
        let headroom = if resident {
            available
        } else {
            available.saturating_sub(cost.total())
        };
        if headroom < reserve {
            return pause(if resident {
                PauseReason::MemoryPressure
            } else {
                PauseReason::MemoryReserve
            });
        }
        ResourceState::Admitted
    }
}

/// One move of the resource state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transition {
    /// The state before.
    pub from: ResourceState,
    /// The state after.
    pub to: ResourceState,
    /// Whether reaching the new state restarted a worker.
    ///
    /// It never does. The field is here so a test can assert it rather than take it on trust, and
    /// so the one path that would have to change to break section 22's rule is visible.
    pub restarted_worker: bool,
}

impl Transition {
    /// Returns whether inference resumed on this move.
    #[must_use]
    pub const fn resumed(&self) -> bool {
        matches!(self.from, ResourceState::ResourcePaused { .. })
            && matches!(self.to, ResourceState::Admitted)
    }

    /// Returns whether inference paused on this move.
    #[must_use]
    pub const fn paused(&self) -> bool {
        !matches!(self.from, ResourceState::ResourcePaused { .. })
            && matches!(self.to, ResourceState::ResourcePaused { .. })
    }
}

/// Reading this host's own conditions.
///
/// Everything here is best effort by design: the point is not to read every signal on every
/// platform, it is to say which ones this build actually reads and to mark the rest unqualified so
/// the policy can be conservative about them. A signal that is added later changes this module and
/// nothing else.
pub mod platform {
    use super::{HostConditions, PowerSource, Signal, ThermalState};

    /// Reads what this host will tell this build.
    ///
    /// Memory is read on every platform. Power and thermal state are read on macOS and Linux, each
    /// through the mechanism that platform documents, and are unqualified on Windows in this
    /// build.
    #[must_use]
    pub fn read_conditions() -> HostConditions {
        let (physical, available) = memory();
        HostConditions {
            physical_memory_bytes: physical,
            available_memory_bytes: available,
            power: power(),
            thermal: thermal(),
        }
    }

    fn memory() -> (Signal<u64>, Signal<u64>) {
        let mut system = sysinfo::System::new_with_specifics(
            sysinfo::RefreshKind::nothing().with_memory(sysinfo::MemoryRefreshKind::everything()),
        );
        system.refresh_memory();
        let total = system.total_memory();
        let available = system.available_memory();
        if total == 0 {
            return (
                Signal::Unqualified {
                    why: "this host reports no physical memory",
                },
                Signal::Unqualified {
                    why: "this host reports no physical memory",
                },
            );
        }
        (Signal::Qualified(total), Signal::Qualified(available))
    }

    #[cfg(target_os = "macos")]
    fn power() -> Signal<PowerSource> {
        // `pmset -g ps` is the documented way to ask this platform where its power comes from
        // without linking against IOKit. The answer is read once per evaluation tick rather than
        // per job, and a command that does not run leaves the signal unqualified, which the policy
        // treats as battery.
        match run("/usr/bin/pmset", &["-g", "ps"]) {
            Some(text) if text.contains("'AC Power'") => Signal::Qualified(PowerSource::Mains),
            Some(text) if text.contains("'Battery Power'") => {
                Signal::Qualified(PowerSource::Battery)
            }
            _ => Signal::Unqualified {
                why: "this host did not report a power source",
            },
        }
    }

    #[cfg(target_os = "linux")]
    fn power() -> Signal<PowerSource> {
        // The kernel's own power-supply class. A mains supply that is online is mains; a host with
        // no battery at all is mains, because there is nothing for it to be running from.
        let Ok(entries) = std::fs::read_dir("/sys/class/power_supply") else {
            return Signal::Unqualified {
                why: "this host has no power-supply class",
            };
        };
        let mut saw_battery = false;
        let mut mains_online = false;
        let mut saw_mains = false;
        for entry in entries.flatten() {
            let kind = std::fs::read_to_string(entry.path().join("type")).unwrap_or_default();
            match kind.trim() {
                "Battery" => saw_battery = true,
                "Mains" | "USB" => {
                    saw_mains = true;
                    let online =
                        std::fs::read_to_string(entry.path().join("online")).unwrap_or_default();
                    if online.trim() == "1" {
                        mains_online = true;
                    }
                }
                _ => {}
            }
        }
        if !saw_battery {
            return Signal::Qualified(PowerSource::Mains);
        }
        if !saw_mains {
            return Signal::Unqualified {
                why: "this host reports a battery and no mains supply",
            };
        }
        Signal::Qualified(if mains_online {
            PowerSource::Mains
        } else {
            PowerSource::Battery
        })
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn power() -> Signal<PowerSource> {
        Signal::Unqualified {
            why: "this build does not read a power source on this platform",
        }
    }

    #[cfg(target_os = "macos")]
    fn thermal() -> Signal<ThermalState> {
        // `pmset -g therm` reports the limits this platform is applying. A scheduler limit below
        // 100 is the host saying it is holding something back, which is exactly the signal section
        // 22 asks for.
        let Some(text) = run("/usr/bin/pmset", &["-g", "therm"]) else {
            return Signal::Unqualified {
                why: "this host did not report a thermal state",
            };
        };
        let Some(limit) = text
            .lines()
            .find_map(|line| line.trim().strip_prefix("CPU_Speed_Limit"))
            .and_then(|rest| rest.trim().strip_prefix('='))
            .and_then(|value| value.trim().parse::<u32>().ok())
        else {
            return Signal::Unqualified {
                why: "this host did not report a processor speed limit",
            };
        };
        Signal::Qualified(match limit {
            100 => ThermalState::Nominal,
            50..=99 => ThermalState::Elevated,
            _ => ThermalState::Critical,
        })
    }

    #[cfg(target_os = "linux")]
    fn thermal() -> Signal<ThermalState> {
        // The kernel's thermal zones, against each zone's own first trip point. Comparing a
        // temperature with a fixed number would be meaningless across machines; comparing it with
        // the trip point the platform itself declared is the platform's own judgement.
        let Ok(entries) = std::fs::read_dir("/sys/class/thermal") else {
            return Signal::Unqualified {
                why: "this host has no thermal class",
            };
        };
        let mut worst: Option<ThermalState> = None;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("thermal_zone"))
            {
                continue;
            }
            let Some(temperature) = read_number(&path.join("temp")) else {
                continue;
            };
            let Some(trip) = (0..8)
                .filter_map(|index| read_number(&path.join(format!("trip_point_{index}_temp"))))
                .filter(|trip| *trip > 0)
                .min()
            else {
                continue;
            };
            let state = if temperature >= trip {
                ThermalState::Critical
            } else if temperature * 100 >= trip * 90 {
                ThermalState::Elevated
            } else {
                ThermalState::Nominal
            };
            worst = Some(worst.map_or(state, |held| held.max(state)));
        }
        worst.map_or(
            Signal::Unqualified {
                why: "this host reported no thermal zone with a trip point",
            },
            Signal::Qualified,
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn thermal() -> Signal<ThermalState> {
        Signal::Unqualified {
            why: "this build does not read a thermal state on this platform",
        }
    }

    #[cfg(target_os = "linux")]
    fn read_number(path: &std::path::Path) -> Option<i64> {
        std::fs::read_to_string(path)
            .ok()?
            .trim()
            .parse::<i64>()
            .ok()
    }

    #[cfg(target_os = "macos")]
    fn run(program: &str, arguments: &[&str]) -> Option<String> {
        let output = std::process::Command::new(program)
            .args(arguments)
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    }
}
