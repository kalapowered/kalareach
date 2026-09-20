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
//! | Windows | an execution-state request, made by the command this host runs | the same, for the session that command runs in |
//!
//! An assertion is reported only once the platform has confirmed this acquisition: macOS and Linux
//! both publish a listing that names the holding process, and where a platform publishes none the
//! request itself reports that its call succeeded. A facility that is merely running holds
//! nothing, and a host that reported one would be promising a machine that stays awake when it
//! does not.
//!
//! Releasing is closing the pipe: the facility sees its input end, exits, and the assertion goes
//! with it. That also means a control daemon that dies releases everything it held, because the
//! pipe dies with the process. An assertion that could outlive the daemon holding it would be a
//! machine that never sleeps again.
//!
//! Two endings are not that graceful one, and both are bounded on purpose. A facility whose
//! acquisition the platform did not confirm is stopped rather than left running, and a facility
//! that has not exited two seconds after its input ended is stopped too, because an assertion that
//! stayed held because its holder hung would be a machine that stopped sleeping for good. The only
//! process either of those ends is this daemon's own child.
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
    SleepInhibitionState,
};
use kr_protocol::hostinfo::configuration::Change;
use kr_protocol::scalars::{Nullable, TimestampMs, U64};
use kr_transport::clock::{ContinuousClock, ContinuousInstant};

use crate::error::Result;

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

/// How long an acquisition is given to be confirmed.
///
/// A running facility is not an assertion: the platform has to say it holds one. This is the whole
/// of the acquisition wait, it happens once per assertion rather than once per query, and a
/// confirmation that arrives sooner ends it sooner.
pub const ACQUIRE_PATIENCE: std::time::Duration = std::time::Duration::from_secs(2);

/// How often an acquisition is asked whether it has been confirmed.
///
/// Only a platform that publishes a listing is asked more than once; where the facility reports
/// its own acquisition there is one answer to wait for.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const ACQUIRE_POLL: std::time::Duration = std::time::Duration::from_millis(20);

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
/// One section of the versioned per-user host configuration document, resolved through the same
/// precedence function as every other ordinary preference. An absent document, an unreadable one
/// and one at a version this build does not know all read as off: the setting is the owner's
/// explicit choice, so the absence of one is never taken for consent.
#[must_use]
pub fn read(paths: &kr_ipc::paths::EnvironmentPaths) -> SleepInhibitionSetting {
    crate::config::sleep_inhibition(paths)
}

/// Writes this environment's power setting.
///
/// Through the validated edit, so the choice is checked against the schema before a revision is
/// applied and a document this build must not rewrite is refused rather than replaced.
///
/// # Errors
///
/// Returns an error when the edit is refused or the state directory cannot be written.
pub fn write(
    paths: &kr_ipc::paths::EnvironmentPaths,
    chosen: SleepInhibitionSetting,
) -> Result<()> {
    crate::config::apply(
        paths,
        &Change::SleepInhibition(chosen),
        crate::config::HardLimits::default(),
    )
    .map(|_| ())
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
            Some(reason) => self.hold(reason, setting, demand, power),
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
    /// Closing a pipe is how the facility was designed to be told, so that is how it is told; the
    /// one that has not exited by its deadline is ended, and the only process either way is this
    /// daemon's own child.
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
    ///
    /// The demand is carried through rather than reconstructed from the reason it produced. The
    /// reported counts are counts: two accepted requests are two, and a reason says only that
    /// there was at least one of each kind.
    fn hold(
        &mut self,
        reason: InhibitionReason,
        setting: SleepInhibitionSetting,
        demand: Demand,
        power: PowerSource,
    ) -> SleepInhibitionState {
        if let Some(held) = self.held.as_mut() {
            // The assertion is the same assertion; only what it is held for can have changed.
            held.reason = reason;
            self.withheld = None;
            return self.state(setting, demand, power);
        }
        match platform::hold() {
            Some((mut facility, holder)) => {
                // A running facility is not an assertion, and neither is a facility that has
                // already exited: its assertion lasts exactly as long as the process does. What
                // settles it is the platform confirming this acquisition, either by naming it in
                // its own listing or by the facility reporting that the call succeeded. Nothing
                // else is reported as an assertion, because a host that claimed one it does not
                // hold would be a host that says the machine will stay awake when it will not.
                match platform::acknowledged(&mut facility) {
                    Some(confirmation) => {
                        self.held = Some(Held {
                            facility,
                            reason,
                            since_ms: kr_ipc::now_ms(),
                            holder: format!("{holder}, {confirmation}"),
                        });
                        self.withheld = None;
                    }
                    None => {
                        self.withheld = Some(match facility.try_wait() {
                            Ok(Some(status)) => format!(
                                "this host's sleep-assertion facility ended at once ({status}), \
                                 so its sleep policy is unchanged"
                            ),
                            _ => "this host asked for a sleep assertion and the operating system \
                                  did not confirm one, so its sleep policy is unchanged"
                                .to_owned(),
                        });
                        let _ = facility.kill();
                        let _ = facility.wait();
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
        self.state(setting, demand, power)
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

    /// Waits for the platform to name this acquisition's assertion in its own listing.
    ///
    /// The listing names the process each assertion is held on behalf of, and the process this
    /// host compares it with is the facility it just started. An assertion under another
    /// process, including another environment's, is not this one.
    pub(super) fn acknowledged(facility: &mut Child) -> Option<String> {
        let wanted = format!("(pid {})", facility.id());
        super::confirmed_within(facility, |patience| {
            super::bounded_output("/usr/bin/pmset", &["-g", "assertions"], patience)
                .is_some_and(|printed| printed.contains(&wanted))
        })
        .then(|| "which the operating system's own assertion listing names".to_owned())
    }

    /// Reads whether this host is running on mains power.
    pub(super) fn power_source() -> PowerSource {
        let Some(printed) =
            super::bounded_output("/usr/bin/pmset", &["-g", "batt"], super::QUERY_PATIENCE)
        else {
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

    /// The name this host asks for its inhibitor under.
    const WHO: &str = "KalaReach";

    /// Which whitespace-separated field of an inhibitor listing holds the asking process.
    ///
    /// The listing is one inhibitor per line: who asked, its user identifier, that user's name,
    /// the process, the process's command, what it holds, why, and its mode. The reason is the
    /// only field with spaces in it and it comes after the process, so counting from the left is
    /// exact.
    const PROCESS_FIELD: usize = 3;

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

    /// Waits for the login manager to name this acquisition's inhibitor in its own listing.
    ///
    /// The manager lists what it is holding, who asked for it and which process asked. Both the
    /// name and the process must match: every environment asks under the same name, so the name
    /// alone would let one host's inhibitor acknowledge another's.
    pub(super) fn acknowledged(facility: &mut Child) -> Option<String> {
        let process = facility.id().to_string();
        super::confirmed_within(facility, |patience| {
            super::bounded_output(FACILITY, &["--list", "--no-legend"], patience)
                .is_some_and(|printed| names(&printed, &process))
        })
        .then(|| "which the login manager's own inhibitor listing names".to_owned())
    }

    /// Returns whether an inhibitor listing names this host's inhibitor, held by this process.
    fn names(printed: &str, process: &str) -> bool {
        printed.lines().any(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            fields.first() == Some(&WHO) && fields.get(PROCESS_FIELD) == Some(&process)
        })
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

    #[cfg(test)]
    mod tests {
        use super::names;

        #[test]
        fn only_this_process_s_own_inhibitor_acknowledges_it() {
            let printed = "KalaReach 1000 someone 4242 systemd-inhibit sleep:idle KalaReach has \
                           admitted work that is still running block\n\
                           KalaReach 1000 someone 99 systemd-inhibit sleep:idle KalaReach has \
                           admitted work that is still running block\n";
            assert!(names(printed, "4242"));
            assert!(names(printed, "99"));
            assert!(
                !names(printed, "4243"),
                "another environment's inhibitor is not this one"
            );
            assert!(
                !names("PowerDevil 1000 someone 4242 kded5 sleep block\n", "4242"),
                "another program's inhibitor is not this one"
            );
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{Child, Command, Stdio};
    use kr_protocol::desktop::PowerSource;

    /// What the request prints once the platform has accepted it.
    ///
    /// This platform publishes no listing of execution-state requests an ordinary user can read,
    /// so the request itself is what says the call succeeded. It prints this after the call and
    /// before it waits, which is the acknowledgement this acquisition is believed on.
    const ACCEPTED: &str = "kalareach-execution-state-held";

    /// The execution-state request, held for as long as its input is open.
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
        [Console]::Out.WriteLine('kalareach-execution-state-held'); \
        [Console]::Out.Flush(); \
        while ($null -ne [Console]::In.ReadLine()) { }; \
        [void]$api::SetThreadExecutionState($continuous)";

    /// Asks this session not to be slept while the request is held.
    pub(super) fn hold() -> Option<(Child, String)> {
        let facility = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", REQUEST])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let holder = format!(
            "an execution-state request against automatic sleep, held on behalf of process {}",
            facility.id()
        );
        Some((facility, holder))
    }

    /// Waits for the request to report that the platform accepted it.
    ///
    /// The read is on a thread of its own, and the wait on it is bounded: a request that never
    /// answers must not stall the daemon that asked for it. The thread ends with the pipe, which
    /// the caller closes when it stops a request it could not believe.
    pub(super) fn acknowledged(facility: &mut Child) -> Option<String> {
        use std::io::{BufRead as _, BufReader};

        let printed = facility.stdout.take()?;
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(printed).read_line(&mut line);
            let _ = sender.send(line);
        });
        let line = receiver.recv_timeout(super::ACQUIRE_PATIENCE).ok()?;
        (line.trim() == ACCEPTED).then(|| "which the request itself reports taking".to_owned())
    }

    /// Reads whether this host is running on mains power.
    ///
    /// A machine that has no battery is on mains, and a query that failed says nothing at all.
    /// Those are different answers: collapsing them would let a `mains_only` setting hold an
    /// assertion on a laptop whose battery this host could not read.
    pub(super) fn power_source() -> PowerSource {
        let Some(printed) = super::bounded_output(
            "powershell.exe",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "try { \
                   $status = Get-CimInstance -ClassName BatteryStatus -Namespace root\\wmi \
                     -ErrorAction Stop; \
                   if ($null -eq $status) { 'ac power' } \
                   elseif ($status.PowerOnline) { 'ac power' } else { 'battery' } \
                 } catch { 'unknown' }",
            ],
            super::QUERY_PATIENCE,
        ) else {
            return PowerSource::Unknown;
        };
        super::power_source_of(&printed, "ac power", "battery")
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
    pub(super) const fn acknowledged(_facility: &mut Child) -> Option<String> {
        None
    }

    /// A platform this host cannot read the power source of answers so.
    pub(super) const fn power_source() -> PowerSource {
        PowerSource::Unknown
    }
}

/// Asks a platform for the confirmation that an acquisition holds an assertion, until it arrives
/// or the acquisition's deadline passes.
///
/// A facility that exits while this waits took nothing, so the wait ends with it. Each ask is
/// given what is left of the deadline rather than a bound of its own, so the whole acquisition
/// costs at most [`ACQUIRE_PATIENCE`] however many times the platform is asked.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn confirmed_within(
    facility: &mut Child,
    mut ask: impl FnMut(std::time::Duration) -> bool,
) -> bool {
    let deadline = std::time::Instant::now() + ACQUIRE_PATIENCE;
    loop {
        if matches!(facility.try_wait(), Ok(Some(_)) | Err(_)) {
            return false;
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        if ask(left) {
            return true;
        }
        std::thread::sleep(ACQUIRE_POLL);
    }
}

/// Runs a platform query with a bound and returns what it printed.
///
/// The output is read after the query has finished, so a query that filled its pipe would stall;
/// every query here prints a few kilobytes at most, and one that stalls is ended at the deadline
/// like any other that does not answer.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn bounded_output(
    program: &str,
    arguments: &[&str],
    patience: std::time::Duration,
) -> Option<String> {
    use std::io::Read as _;

    let mut query = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + patience;
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
        let document = kr_worker::config::document_path(&paths);
        kr_ipc::paths::write_owner_only_file(
            &document,
            br#"{"version": 1, "preferences": {"sleep_inhibition": "always"}}"#,
        )
        .expect("writes");
        assert_eq!(
            read(&paths),
            SleepInhibitionSetting::Off,
            "a setting this build does not understand is not consent to anything"
        );
        kr_ipc::paths::write_owner_only_file(&document, b"not a document").expect("writes");
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
        assert!(
            held.holder.as_ref().is_some_and(|holder| {
                holder.contains("listing names") || holder.contains("reports taking")
            }),
            "an assertion is reported only once the platform has confirmed it: {held:?}"
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
