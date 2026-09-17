//! The host power setting, and the assertion that holds automatic sleep off.
//!
//! Sleep is the host's own policy. KalaReach changes it only when the owner has said so, only
//! while work it has actually admitted is outstanding, and only on the power source the owner
//! chose. Three rules follow from that, and every one of them is visible in this module.
//!
//! * **Off until chosen.** [`read`] returns [`SleepInhibitionSetting::Off`] for a host with no
//!   setting file, for a file it cannot read and for a file whose contents it does not recognise.
//!   Nothing here turns the setting on, and setup offers it rather than applying it.
//! * **Mains is not battery.** `mains_only` holds nothing on battery *and nothing on a host that
//!   will not say what it is running on*: a setting that means "only on mains" must not become
//!   "always" because the platform declined to answer. Using battery power as well is a separate
//!   choice the owner makes on purpose.
//! * **Held for a reason, released with it.** [`Inhibitor::evaluate`] takes the assertion when
//!   verified foreground work or pending requests exist and releases it the moment they do not.
//!   The reason is reported beside the assertion, so a person can see what the host is keeping the
//!   machine awake for.
//!
//! # How the assertion is held
//!
//! Each platform has a facility for this and each ties the assertion to the life of a process.
//! This host runs that facility as a child with a pipe on its input and holds the other end: the
//! assertion lasts exactly as long as the pipe.
//!
//! | Platform | The facility | What it asserts |
//! | --- | --- | --- |
//! | macOS | `caffeinate -i`, which takes a power-management assertion | the system does not sleep because nobody is using it |
//! | Linux | `systemd-inhibit --what=sleep:idle --mode=block`, which holds the login manager's own inhibitor descriptor | the same, through the login manager |
//! | Windows | the per-user host agent's execution-state request | the same, for the calling session |
//!
//! Releasing is closing the pipe, so nothing is ever signalled: the facility sees its input end,
//! exits, and the assertion goes with it. That also means a control daemon that dies releases
//! everything it held, because the pipe dies with the process. An assertion that could outlive the
//! daemon holding it would be a machine that never sleeps again.
//!
//! # What an assertion does not promise
//!
//! It asks the operating system not to sleep on its own. It does not stop a person closing the
//! lid, an administrator forcing sleep, or a platform policy overriding the request. Section 3
//! treats every one of those as a possible loss of reachability rather than as something to
//! prevent: the host may be suspended at any moment, and what protects correctness is that every
//! deadline is measured on the suspend-aware continuous clock. Time spent suspended is time spent,
//! so waking up never brings an expired action window, lease or grant back.

use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use kr_protocol::desktop::{
    InhibitionMechanism, InhibitionReason, PowerSource, SleepInhibitionSetting,
    SleepInhibitionState, setting,
};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};
use kr_transport::clock::{ContinuousClock, ContinuousInstant};

use crate::error::{ControllerError, Result};

/// How long a facility is given to exit after its input ends.
pub const RELEASE_PATIENCE: std::time::Duration = std::time::Duration::from_secs(2);

/// How often the releasing facility is asked whether it has exited.
const RELEASE_POLL: std::time::Duration = std::time::Duration::from_millis(20);

/// How long a platform query is given to answer.
///
/// Every query this module makes is a subprocess, and a subprocess that never returns would be a
/// host that never released its assertion. Nothing here waits longer than this, and a query that
/// reaches it is ended and reads as no answer.
pub const QUERY_PATIENCE: std::time::Duration = std::time::Duration::from_secs(2);

/// How often a bounded query is asked whether it has finished.
const QUERY_POLL: std::time::Duration = std::time::Duration::from_millis(20);

/// How long a facility is given to hold its assertion before it is believed.
///
/// A process that exits immediately did not take an assertion, whatever it was asked for. This is
/// the only wait on the acquisition path, and it happens once per assertion rather than once per
/// query.
const ACQUIRE_SETTLE: std::time::Duration = std::time::Duration::from_millis(100);

/// What the host currently has outstanding.
///
/// Both counts are of work the host has admitted rather than of activity it has guessed at. An
/// idle shell is not work, and output on a terminal is not work: what counts is an agent the host
/// has admitted a turn for, and a request it has accepted and not yet answered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Demand {
    /// Live sessions with verified foreground work.
    pub sessions_with_work: u64,
    /// Accepted requests the host has not answered.
    pub pending_requests: u64,
}

impl Demand {
    /// Returns the reason an assertion would be held, or none when nothing justifies one.
    #[must_use]
    pub const fn reason(self) -> Option<InhibitionReason> {
        InhibitionReason::of(self.sessions_with_work > 0, self.pending_requests > 0)
    }
}

/// Reads this environment's power setting.
///
/// An absent file, an unreadable file and a file this build does not understand all read as off.
/// The setting is the owner's explicit choice, so the absence of one is never taken for consent.
#[must_use]
pub fn read(paths: &kr_ipc::paths::EnvironmentPaths) -> SleepInhibitionSetting {
    let path = paths.state_dir().join(setting::FILE_NAME);
    match kr_ipc::paths::read_owner_only_file(&path, setting::MAX_LEN) {
        Ok(Some(bytes)) => setting::parse(&bytes),
        _ => SleepInhibitionSetting::Off,
    }
}

/// Writes this environment's power setting.
///
/// # Errors
///
/// Returns an error when the state directory cannot be written.
pub fn write(
    paths: &kr_ipc::paths::EnvironmentPaths,
    chosen: SleepInhibitionSetting,
) -> Result<()> {
    let path = paths.state_dir().join(setting::FILE_NAME);
    kr_ipc::paths::write_owner_only_file(&path, setting::document(chosen).as_bytes())
        .map_err(ControllerError::Ipc)
}

/// Returns which facility this host holds a sleep assertion with.
#[must_use]
pub const fn mechanism() -> InhibitionMechanism {
    #[cfg(target_os = "macos")]
    {
        InhibitionMechanism::MacosPowerAssertion
    }
    #[cfg(target_os = "linux")]
    {
        InhibitionMechanism::LinuxLogindInhibitor
    }
    #[cfg(windows)]
    {
        InhibitionMechanism::WindowsExecutionState
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        InhibitionMechanism::None
    }
}

/// Reads what this host is running on.
///
/// A host that does not answer is unknown rather than mains. That is what makes a `mains_only`
/// setting mean what it says on a platform this host cannot read the power source of.
#[must_use]
pub fn power_source() -> PowerSource {
    platform::power_source()
}

/// The assertion this daemon holds, and what it is holding it for.
#[derive(Debug)]
pub struct Inhibitor {
    held: Option<Held>,
    /// Why no assertion is held although the setting is on, when that is the case.
    withheld: Option<String>,
    /// Whether something is already looking at this setting on a cadence.
    ///
    /// It lives here rather than beside the daemon's other state so that taking an assertion and
    /// taking responsibility for reviewing it happen inside one lock. A mark kept outside this
    /// lock could be cleared by a review that had just finished while another caller was taking
    /// an assertion, leaving that assertion with nothing watching it.
    reviewing: bool,
}

/// One held assertion.
#[derive(Debug)]
struct Held {
    /// The facility holding it. Dropping its input releases the assertion.
    facility: Child,
    /// What it is held for.
    reason: InhibitionReason,
    /// When it was taken.
    since_ms: TimestampMs,
    /// What the platform's own listing shows for it.
    holder: String,
}

impl Default for Inhibitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Inhibitor {
    /// Builds an inhibitor that holds nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            held: None,
            withheld: None,
            reviewing: false,
        }
    }

    /// Returns whether something is already reviewing this setting.
    #[must_use]
    pub const fn reviewing(&self) -> bool {
        self.reviewing
    }

    /// Records whether something is reviewing this setting.
    pub const fn set_reviewing(&mut self, reviewing: bool) {
        self.reviewing = reviewing;
    }

    /// Takes or releases the assertion for what the host currently has outstanding.
    ///
    /// Called whenever either input can have changed: the setting, the power source, or the work.
    /// It is the only place an assertion is taken or released, so the reported state is always the
    /// state of this process's own child.
    pub fn evaluate(
        &mut self,
        setting: SleepInhibitionSetting,
        demand: Demand,
        power: PowerSource,
    ) -> SleepInhibitionState {
        // A facility that has exited on its own — because the platform refused, or because
        // something ended it — is not held any more, whatever this side remembers.
        if self
            .held
            .as_mut()
            .is_some_and(|held| matches!(held.facility.try_wait(), Ok(Some(_)) | Err(_)))
        {
            self.held = None;
        }
        let wanted = setting.permits(power).then(|| demand.reason()).flatten();
        match wanted {
            Some(reason) => self.hold(reason, setting, power),
            None => {
                self.release();
                self.withheld = withheld_reason(setting, demand, power);
                self.state(setting, demand, power)
            }
        }
    }

    /// Releases the assertion, if one is held.
    ///
    /// The facility's input is dropped, which is what it waits on, and the child is then reaped.
    /// Nothing is signalled: the only process involved is this daemon's own child, and closing a
    /// pipe is how it was designed to be told.
    pub fn release(&mut self) {
        let Some(mut held) = self.held.take() else {
            return;
        };
        drop(held.facility.stdin.take());
        // The facility exits as soon as it sees the end of its input, and waiting for it is what
        // turns "the assertion is released" from a hope into a fact. The wait is bounded: a
        // facility that does not exit when its input ends is ended, because an assertion that
        // stayed held because its holder hung would be a machine that stopped sleeping for good.
        // The process being ended is this daemon's own child and nothing else.
        let deadline = std::time::Instant::now() + RELEASE_PATIENCE;
        loop {
            match held.facility.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => {}
            }
            if std::time::Instant::now() >= deadline {
                let _ = held.facility.kill();
                let _ = held.facility.wait();
                return;
            }
            std::thread::sleep(RELEASE_POLL);
        }
    }

    /// Returns what this inhibitor is currently doing.
    #[must_use]
    pub fn state(
        &self,
        setting: SleepInhibitionSetting,
        demand: Demand,
        power: PowerSource,
    ) -> SleepInhibitionState {
        SleepInhibitionState {
            setting,
            active: self.held.is_some(),
            reason: Nullable(self.held.as_ref().map(|held| held.reason)),
            mechanism: mechanism(),
            power_source: power,
            sessions_with_work: U64::new(demand.sessions_with_work),
            pending_requests: U64::new(demand.pending_requests),
            since_ms: Nullable(self.held.as_ref().map(|held| held.since_ms)),
            holder: Nullable(self.held.as_ref().map(|held| held.holder.clone())),
            withheld_reason: Nullable(self.held.is_none().then(|| self.withheld.clone()).flatten()),
        }
    }

    /// Takes the assertion, or keeps the one that is already held.
    fn hold(
        &mut self,
        reason: InhibitionReason,
        setting: SleepInhibitionSetting,
        power: PowerSource,
    ) -> SleepInhibitionState {
        if let Some(held) = self.held.as_mut() {
            // The assertion is the same assertion; only what it is held for can have changed.
            held.reason = reason;
            self.withheld = None;
            return self.state(setting, self.demand_of(reason), power);
        }
        match platform::hold() {
            Some((mut facility, holder)) => {
                // A facility that has already exited holds nothing. Its assertion lasts exactly as
                // long as the process does, so a process that is gone is an assertion that was
                // never taken, and reporting one would be reporting a machine that will not sleep
                // when it will.
                std::thread::sleep(ACQUIRE_SETTLE);
                match facility.try_wait() {
                    Ok(None) => {
                        // A running facility is not an assertion. Where the platform lists what it
                        // is holding, that listing is what settles it, and a facility the platform
                        // does not name holds nothing whatever it is doing.
                        match platform::acknowledged(facility.id()) {
                            Some(false) => {
                                let _ = facility.kill();
                                let _ = facility.wait();
                                self.withheld = Some(
                                    "this host asked for a sleep assertion and the operating \
                                     system does not list one, so its sleep policy is unchanged"
                                        .to_owned(),
                                );
                            }
                            acknowledged => {
                                self.held = Some(Held {
                                    facility,
                                    reason,
                                    since_ms: kr_ipc::now_ms(),
                                    holder: match acknowledged {
                                        Some(true) => format!(
                                            "{holder}, which the operating system's own listing \
                                             names"
                                        ),
                                        // A platform that publishes no listing an ordinary user
                                        // can read leaves the facility's own life as the evidence,
                                        // and the record says which it is.
                                        _ => format!(
                                            "{holder}, which this platform publishes no listing of"
                                        ),
                                    },
                                });
                                self.withheld = None;
                            }
                        }
                    }
                    Ok(Some(status)) => {
                        self.withheld = Some(format!(
                            "this host's sleep-assertion facility ended at once ({status}), so \
                             its sleep policy is unchanged"
                        ));
                    }
                    Err(error) => {
                        let _ = facility.kill();
                        let _ = facility.wait();
                        self.withheld = Some(format!(
                            "this host could not tell whether its sleep-assertion facility \
                             started ({error}), so its sleep policy is unchanged"
                        ));
                    }
                }
            }
            None => {
                self.withheld = Some(
                    "this host's sleep-assertion facility is not available, so its sleep policy \
                     is unchanged"
                        .to_owned(),
                );
            }
        }
        self.state(setting, self.demand_of(reason), power)
    }

    /// Returns the demand one reason describes, for reporting.
    const fn demand_of(&self, reason: InhibitionReason) -> Demand {
        match reason {
            InhibitionReason::ForegroundWork => Demand {
                sessions_with_work: 1,
                pending_requests: 0,
            },
            InhibitionReason::PendingRequests => Demand {
                sessions_with_work: 0,
                pending_requests: 1,
            },
            InhibitionReason::ForegroundWorkAndPendingRequests => Demand {
                sessions_with_work: 1,
                pending_requests: 1,
            },
        }
    }
}

impl Drop for Inhibitor {
    fn drop(&mut self) {
        self.release();
    }
}

/// Returns why the setting is on and no assertion is held.
fn withheld_reason(
    setting: SleepInhibitionSetting,
    demand: Demand,
    power: PowerSource,
) -> Option<String> {
    if setting == SleepInhibitionSetting::Off {
        return None;
    }
    if !setting.permits(power) {
        return Some(format!(
            "this setting inhibits sleep on mains power and this host is running on {}",
            power.as_str()
        ));
    }
    if demand.reason().is_none() {
        return Some(
            "no session has verified foreground work and no accepted request is outstanding"
                .to_owned(),
        );
    }
    None
}

/// Returns whether a deadline taken before a suspension has expired by the time of waking.
///
/// This is the whole of what an assertion does not promise. The host may be suspended at any
/// moment — a closed lid, a forced sleep, a platform policy that overrides the request — and every
/// deadline is measured on the suspend-aware continuous clock, so time spent suspended is time
/// spent. Waking up therefore never brings an expired action window, lease or grant back, and this
/// function is the comparison that says so.
#[must_use]
pub fn expired_at_wake(clock: &Arc<dyn ContinuousClock>, deadline: ContinuousInstant) -> bool {
    clock.now() >= deadline
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{Child, Command, Stdio};
    use kr_protocol::desktop::PowerSource;

    /// The facility macOS holds a power-management assertion with.
    const FACILITY: &str = "/usr/bin/caffeinate";

    /// Takes a power-management assertion against automatic system sleep.
    ///
    /// `-i` asks for the one assertion this is about: the system does not sleep because nobody is
    /// using it. Nothing here keeps the display awake, which is the person's business rather than
    /// the host's. The assertion lasts as long as the command that is run under it, so the command
    /// is one that waits on its input and the input is a pipe this daemon holds.
    pub(super) fn hold() -> Option<(Child, String)> {
        let facility = Command::new(FACILITY)
            .args(["-i", "cat"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let holder = format!(
            "a power-management assertion against idle system sleep, held on behalf of process {}",
            facility.id()
        );
        Some((facility, holder))
    }

    /// Asks the platform whether it has the assertion this host asked for.
    ///
    /// The operating system's own listing is the only thing that settles it, and it names the
    /// process the assertion is held on behalf of, which is the facility this host started.
    pub(super) fn acknowledged(facility: u32) -> Option<bool> {
        let printed = super::bounded_output("/usr/bin/pmset", &["-g", "assertions"])?;
        Some(printed.contains(&format!("(pid {facility})")))
    }

    /// Reads whether this host is running on mains power.
    pub(super) fn power_source() -> PowerSource {
        let Some(printed) = super::bounded_output("/usr/bin/pmset", &["-g", "batt"]) else {
            return PowerSource::Unknown;
        };
        super::power_source_of(&printed, "ac power", "battery")
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{Child, Command, Stdio};
    use kr_protocol::desktop::PowerSource;

    /// The facility the login manager holds a sleep inhibitor with.
    const FACILITY: &str = "systemd-inhibit";

    /// Takes the login manager's own sleep inhibitor.
    ///
    /// `--mode=block` is the inhibitor that refuses automatic sleep rather than merely asking to be
    /// told about it, and the descriptor it holds lives exactly as long as the command run under
    /// it. So the command waits on its input and this daemon holds the other end of that pipe.
    pub(super) fn hold() -> Option<(Child, String)> {
        let facility = Command::new(FACILITY)
            .args([
                "--what=sleep:idle",
                "--who=KalaReach",
                "--why=KalaReach has admitted work that is still running",
                "--mode=block",
                "cat",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let holder = format!(
            "a login-manager sleep inhibitor named KalaReach, held on behalf of process {}",
            facility.id()
        );
        Some((facility, holder))
    }

    /// Asks the login manager whether it has the inhibitor this host asked for.
    ///
    /// The manager lists what it is holding and who asked for it, and this host asks under its own
    /// name.
    pub(super) fn acknowledged(_facility: u32) -> Option<bool> {
        let printed = super::bounded_output(FACILITY, &["--list", "--no-legend"])?;
        Some(printed.contains("KalaReach"))
    }

    /// Reads whether this host is running on mains power.
    ///
    /// The kernel publishes one file per power supply. A supply of type `Mains` that is online is
    /// the answer; a host with no mains supply at all is a host running on battery. A host with no
    /// power supplies published is a desktop machine or a virtual one, and neither answers this.
    pub(super) fn power_source() -> PowerSource {
        let Ok(entries) = std::fs::read_dir("/sys/class/power_supply") else {
            return PowerSource::Unknown;
        };
        let mut mains = None;
        let mut battery = false;
        for entry in entries.flatten() {
            let kind = std::fs::read_to_string(entry.path().join("type")).unwrap_or_default();
            match kind.trim() {
                "Mains" => {
                    let online =
                        std::fs::read_to_string(entry.path().join("online")).unwrap_or_default();
                    mains = Some(mains.unwrap_or(false) || online.trim() == "1");
                }
                "Battery" => battery = true,
                _ => {}
            }
        }
        match (mains, battery) {
            (Some(true), _) => PowerSource::Mains,
            (Some(false), true) => PowerSource::Battery,
            (Some(false), false) => PowerSource::Unknown,
            (None, true) => PowerSource::Battery,
            (None, false) => PowerSource::Unknown,
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{Child, Command, Stdio};
    use kr_protocol::desktop::PowerSource;

    /// The per-user host agent's execution-state request, held for as long as its input is open.
    ///
    /// Every value is an explicit unsigned 32-bit one. The continuous flag is `0x80000000`, which
    /// a signed literal cannot carry, and a conversion that failed would leave a process waiting
    /// on its input with no assertion behind it. The request stops on any error, and treats a zero
    /// result from the call as the failure it is.
    const REQUEST: &str = "\
        $ErrorActionPreference = 'Stop'; \
        $signature = '[DllImport(\"kernel32.dll\", SetLastError=true)] public static extern uint \
        SetThreadExecutionState(uint flags);'; \
        $api = Add-Type -MemberDefinition $signature -Name Power -Namespace KalaReach -PassThru; \
        $continuous = [uint32]2147483648; \
        $system = [uint32]1; \
        $flags = [uint32]($continuous -bor $system); \
        if ($api::SetThreadExecutionState($flags) -eq 0) { exit 1 }; \
        while ($null -ne [Console]::In.ReadLine()) { }; \
        [void]$api::SetThreadExecutionState($continuous)";

    /// Asks this session not to be slept while the request is held.
    pub(super) fn hold() -> Option<(Child, String)> {
        let facility = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", REQUEST])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let holder = format!(
            "an execution-state request against automatic sleep, held on behalf of process {}",
            facility.id()
        );
        Some((facility, holder))
    }

    /// This platform publishes no listing of execution-state requests an ordinary user can read.
    pub(super) const fn acknowledged(_facility: u32) -> Option<bool> {
        None
    }

    /// Reads whether this host is running on mains power.
    ///
    /// A machine that has no battery is on mains, and a query that failed says nothing at all.
    /// Those are different answers: collapsing them would let a `mains_only` setting hold an
    /// assertion on a laptop whose battery this host could not read.
    pub(super) fn power_source() -> PowerSource {
        let Ok(output) = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "try { \
                   $status = Get-CimInstance -ClassName BatteryStatus -Namespace root\\wmi \
                     -ErrorAction Stop; \
                   if ($null -eq $status) { 'ac power' } \
                   elseif ($status.PowerOnline) { 'ac power' } else { 'battery' } \
                 } catch { 'unknown' }",
            ])
            .stdin(Stdio::null())
            .output()
        else {
            return PowerSource::Unknown;
        };
        if !output.status.success() {
            return PowerSource::Unknown;
        }
        super::power_source_of(
            &String::from_utf8_lossy(&output.stdout),
            "ac power",
            "battery",
        )
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod platform {
    use super::Child;
    use kr_protocol::desktop::PowerSource;

    /// A platform with no facility this host knows holds nothing.
    pub(super) const fn hold() -> Option<(Child, String)> {
        None
    }

    /// A platform with no facility has nothing to acknowledge.
    pub(super) const fn acknowledged(_facility: u32) -> Option<bool> {
        None
    }

    /// A platform this host cannot read the power source of answers so.
    pub(super) const fn power_source() -> PowerSource {
        PowerSource::Unknown
    }
}

/// Runs a platform query with a bound and returns what it printed.
///
/// The output is read after the query has finished, so a query that filled its pipe would stall;
/// every query here prints a few kilobytes at most, and one that stalls is ended at the deadline
/// like any other that does not answer.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn bounded_output(program: &str, arguments: &[&str]) -> Option<String> {
    use std::io::Read as _;

    let mut query = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + QUERY_PATIENCE;
    loop {
        match query.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => return None,
            Ok(None) => {}
        }
        if std::time::Instant::now() >= deadline {
            let _ = query.kill();
            let _ = query.wait();
            return None;
        }
        std::thread::sleep(QUERY_POLL);
    }
    let mut printed = String::new();
    query
        .stdout
        .take()?
        .read_to_string(&mut printed)
        .ok()
        .map(|_| printed)
}

/// Returns the power source a platform's own wording describes.
#[cfg(any(target_os = "macos", windows))]
fn power_source_of(printed: &str, mains: &str, battery: &str) -> PowerSource {
    let printed = printed.to_ascii_lowercase();
    if printed.contains(mains) {
        PowerSource::Mains
    } else if printed.contains(battery) {
        PowerSource::Battery
    } else {
        PowerSource::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_transport::clock::ManualClock;
    use std::time::Duration;

    fn temporary_environment() -> kr_ipc::testing::TempHost {
        kr_ipc::testing::TempHost::create()
    }

    #[test]
    fn a_host_with_no_setting_file_changes_nothing() {
        let host = temporary_environment();
        assert_eq!(
            read(&host.environment()),
            SleepInhibitionSetting::Off,
            "the setting is off until the owner chooses otherwise"
        );
    }

    #[test]
    fn the_setting_is_read_back_as_it_was_written_and_a_damaged_file_reads_as_off() {
        let host = temporary_environment();
        let paths = host.environment();
        for setting in [
            SleepInhibitionSetting::MainsOnly,
            SleepInhibitionSetting::BatteryToo,
            SleepInhibitionSetting::Off,
        ] {
            write(&paths, setting).expect("the setting is written");
            assert_eq!(read(&paths), setting);
        }
        kr_ipc::paths::write_owner_only_file(
            &paths.state_dir().join(setting::FILE_NAME),
            b"{\"sleep_inhibition\": \"always\"}",
        )
        .expect("writes");
        assert_eq!(
            read(&paths),
            SleepInhibitionSetting::Off,
            "a setting this build does not understand is not consent to anything"
        );
        kr_ipc::paths::write_owner_only_file(
            &paths.state_dir().join(setting::FILE_NAME),
            b"not a document",
        )
        .expect("writes");
        assert_eq!(read(&paths), SleepInhibitionSetting::Off);
    }

    #[test]
    fn nothing_is_held_while_the_setting_is_off() {
        let mut inhibitor = Inhibitor::new();
        let state = inhibitor.evaluate(
            SleepInhibitionSetting::Off,
            Demand {
                sessions_with_work: 3,
                pending_requests: 2,
            },
            PowerSource::Mains,
        );
        assert!(
            !state.active,
            "work alone never changes a host's sleep policy"
        );
        assert!(!state.reason.is_present());
        assert!(
            !state.withheld_reason.is_present(),
            "an off setting withholds nothing; it is off"
        );
        assert!(state.describe().contains("unchanged"));
    }

    #[test]
    fn a_mains_only_setting_says_why_it_holds_nothing_on_battery() {
        let mut inhibitor = Inhibitor::new();
        let state = inhibitor.evaluate(
            SleepInhibitionSetting::MainsOnly,
            Demand {
                sessions_with_work: 1,
                pending_requests: 0,
            },
            PowerSource::Battery,
        );
        assert!(!state.active);
        let reason = state.withheld_reason.as_ref().expect("a reason").clone();
        assert!(reason.contains("battery"), "{reason}");
    }

    #[test]
    fn an_enabled_setting_with_no_work_says_so() {
        let mut inhibitor = Inhibitor::new();
        let state = inhibitor.evaluate(
            SleepInhibitionSetting::BatteryToo,
            Demand::default(),
            PowerSource::Battery,
        );
        assert!(!state.active);
        assert!(
            state
                .withheld_reason
                .as_ref()
                .is_some_and(|reason| reason.contains("no accepted request is outstanding")),
            "{state:?}"
        );
    }

    #[test]
    fn the_assertion_is_taken_for_work_and_released_when_the_work_ends() {
        let mut inhibitor = Inhibitor::new();
        let held = inhibitor.evaluate(
            SleepInhibitionSetting::BatteryToo,
            Demand {
                sessions_with_work: 1,
                pending_requests: 0,
            },
            PowerSource::Mains,
        );
        // A platform without the facility reports that rather than claiming an assertion.
        if !held.active {
            assert!(held.withheld_reason.is_present());
            return;
        }
        assert_eq!(
            held.reason.as_ref().copied(),
            Some(InhibitionReason::ForegroundWork)
        );
        assert!(
            held.since_ms.is_present(),
            "a held assertion says when it was taken"
        );
        assert!(
            held.holder
                .as_ref()
                .is_some_and(|holder| holder.contains("process")),
            "the assertion names itself so a person can find it: {held:?}"
        );
        assert!(held.describe().contains("sleep inhibited"));

        // Both conditions at once are one assertion, not two.
        let both = inhibitor.evaluate(
            SleepInhibitionSetting::BatteryToo,
            Demand {
                sessions_with_work: 1,
                pending_requests: 1,
            },
            PowerSource::Mains,
        );
        assert!(both.active);
        assert_eq!(
            both.reason.as_ref().copied(),
            Some(InhibitionReason::ForegroundWorkAndPendingRequests)
        );
        assert_eq!(
            both.since_ms.as_ref().map(|since| since.get()),
            held.since_ms.as_ref().map(|since| since.get()),
            "the assertion was kept rather than retaken"
        );

        let released = inhibitor.evaluate(
            SleepInhibitionSetting::BatteryToo,
            Demand::default(),
            PowerSource::Mains,
        );
        assert!(
            !released.active,
            "the assertion goes when its condition does"
        );
        assert!(!released.since_ms.is_present());
    }

    #[test]
    fn waking_up_does_not_bring_an_expired_deadline_back() {
        let clock = ManualClock::new();
        let shared: Arc<dyn ContinuousClock> = Arc::new(clock.clone());
        let deadline = shared
            .now()
            .checked_add(Duration::from_secs(5))
            .expect("a deadline");
        assert!(!expired_at_wake(&shared, deadline));
        // The machine sleeps for an hour: a closed lid, a forced sleep, a platform override. The
        // continuous clock counts it, because time spent suspended is time spent.
        clock.advance(Duration::from_secs(3_600));
        assert!(
            expired_at_wake(&shared, deadline),
            "an authority deadline taken before a suspension is expired on waking"
        );
    }
}
