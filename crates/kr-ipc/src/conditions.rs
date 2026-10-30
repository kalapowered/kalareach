//! What the host's own facilities say about where its power comes from and how hot it is, on the
//! platform whose facility is a system call.
//!
//! Linux answers through files that need no system call of this crate's, and its reader stays with
//! the code that uses it. macOS answers its power through a program, which stays there too, and its
//! heat through the system's notification state: the thermal pressure level, which says how far the
//! platform is holding the machine back to keep it cool, on Intel and on Apple silicon alike.
//! Windows answers through two facilities: the power-status call, which says whether the machine is
//! on the mains or on a battery, and the performance counters of its thermal zones, whose passive
//! limit says how far the platform is holding the processors back to keep the machine cool.
//!
//! A reading says what the facility said and nothing about what to do with it. A facility that does
//! not answer is an absent reading, never a guess: [`supply`] returns nothing when the system would
//! not say, and [`thermal_zones`] lists nothing when the machine has no zone to read.
//!
//! The decision from the power-status call's two bytes is [`PowerStatus::supply`], which takes no
//! system call, so it is tested on every platform against the bytes a machine returned.

/// Where the machine's power comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Supply {
    /// The machine is plugged in, or has no battery to run from.
    Mains,
    /// The machine is running from its battery.
    Battery,
}

/// What Windows' power-status call returned in the two fields that say where power comes from.
///
/// The call's other fields (the battery's charge and its remaining time) say nothing about the
/// source, and a machine that has no battery fills them with a value that means unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerStatus {
    /// `ACLineStatus`: 0 when the machine is not plugged in, 1 when it is, 255 when the system
    /// does not know.
    pub ac_line_status: u8,
    /// `BatteryFlag`: a set of flags (1 high, 2 low, 4 critical, 8 charging), 128 when the
    /// machine has no battery, and 255 when the system does not know.
    pub battery_flag: u8,
}

impl PowerStatus {
    /// The flag value of a machine that has no battery.
    const NO_BATTERY: u8 = 128;

    /// Returns where the power comes from, or nothing when the system did not say.
    ///
    /// A machine that has no battery has no other source than the mains, even when it does not say
    /// whether it is plugged in. A machine that has a battery and does not say whether it is
    /// plugged in has not said, and the reading is absent rather than the answer that is safer for
    /// whoever asks.
    #[must_use]
    pub const fn supply(self) -> Option<Supply> {
        match (self.ac_line_status, self.battery_flag) {
            (1, _) => Some(Supply::Mains),
            (0, _) => Some(Supply::Battery),
            (_, Self::NO_BATTERY) => Some(Supply::Mains),
            _ => None,
        }
    }
}

/// One thermal zone, as the platform's performance counters report it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThermalZone {
    /// The zone's name, as the platform names it.
    pub name: String,
    /// The share of the processors' top speed the platform is allowing because of heat, in percent:
    /// 100 when it holds nothing back. Nothing when the platform listed the zone and gave no usable
    /// reading of it: a counter that held no data, or a value below nought.
    pub passive_limit_percent: Option<u32>,
}

/// The status of a counter whose value is a reading, and the status of the first reading after a
/// change, which is a reading too. The Windows module holds these equal to the system's own.
#[cfg(any(windows, test))]
const STATUS_VALID_DATA: u32 = 0;
#[cfg(any(windows, test))]
const STATUS_NEW_DATA: u32 = 1;

impl ThermalZone {
    /// A zone as a counter reported it: `status` is the counter's status and `value` the number it
    /// formatted. A reading counts when the status says the counter holds data and the number is
    /// not below nought; any other zone is listed with no limit, so that a zone the platform could
    /// not read is never taken for one that holds nothing back.
    #[cfg(any(windows, test))]
    fn counted(name: String, status: u32, value: i32) -> Self {
        let held = status == STATUS_VALID_DATA || status == STATUS_NEW_DATA;
        Self {
            name,
            passive_limit_percent: held.then(|| u32::try_from(value).ok()).flatten(),
        }
    }
}

/// Reads where the machine's power comes from.
///
/// Nothing when the system would not say, and nothing on a platform whose facility this crate does
/// not call.
#[must_use]
pub fn supply() -> Option<Supply> {
    power_status().and_then(PowerStatus::supply)
}

/// Reads what the system returns for the power-status call.
#[cfg(windows)]
#[must_use]
pub fn power_status() -> Option<PowerStatus> {
    windows::power_status()
}

/// Reads what the system returns for the power-status call: nothing on a platform that has no such
/// call.
#[cfg(not(windows))]
#[must_use]
pub const fn power_status() -> Option<PowerStatus> {
    None
}

/// Reads the passive limit of every thermal zone the platform reports, each zone in the list
/// whether or not it could be read.
///
/// An empty list means the machine has no zone to read, or the platform would not read them.
#[cfg(windows)]
#[must_use]
pub fn thermal_zones() -> Vec<ThermalZone> {
    windows::thermal_zones()
}

/// Reads the passive limit of every thermal zone the platform reports: none on a platform whose
/// zones this crate does not read.
#[cfg(not(windows))]
#[must_use]
pub const fn thermal_zones() -> Vec<ThermalZone> {
    Vec::new()
}

/// Reads the thermal pressure level macOS reports: 0 is nominal, 1 moderate, 2 heavy, 3 trapping and
/// 4 sleeping, the levels the system's `OSThermalNotification.h` names for macOS.
///
/// Nothing when the system would not say, and nothing on a platform whose facility this crate does
/// not call.
#[cfg(target_os = "macos")]
#[must_use]
pub fn thermal_pressure_level() -> Option<u64> {
    macos::thermal_pressure_level()
}

/// Reads the thermal pressure level macOS reports: nothing on a platform that has no such level.
#[cfg(not(target_os = "macos"))]
#[must_use]
pub const fn thermal_pressure_level() -> Option<u64> {
    None
}

/// The one place in this crate that asks the system's notification state for the thermal pressure
/// level.
///
/// The workspace forbids unsafe code; this crate denies it and relaxes the rule for this module,
/// because the notification state has no safe interface.
#[cfg(target_os = "macos")]
mod macos {
    #![expect(
        unsafe_code,
        reason = "the system's notification state has no safe interface"
    )]

    use std::ffi::{CStr, c_char, c_int};

    /// The status the notification calls return when they did what was asked.
    const NOTIFY_STATUS_OK: u32 = 0;

    /// The notification the system posts the thermal pressure level under, which the SDK names
    /// `kOSThermalNotificationPressureLevelName`.
    const PRESSURE_LEVEL: &CStr = c"com.apple.system.thermalpressurelevel";

    unsafe extern "C" {
        /// `notify_register_check`, which registers a name to be read with `notify_get_state` and
        /// posts nothing.
        fn notify_register_check(name: *const c_char, out_token: *mut c_int) -> u32;
        /// `notify_get_state`, which reads the 64-bit state last posted under a registered name.
        fn notify_get_state(token: c_int, state: *mut u64) -> u32;
        /// `notify_cancel`, which releases a registration.
        fn notify_cancel(token: c_int) -> u32;
    }

    pub(super) fn thermal_pressure_level() -> Option<u64> {
        let mut token: c_int = 0;
        // SAFETY: the call reads a NUL-terminated name that outlives it and writes one 32-bit value
        // through a pointer to a live local of that size.
        let registered = unsafe { notify_register_check(PRESSURE_LEVEL.as_ptr(), &raw mut token) };
        if registered != NOTIFY_STATUS_OK {
            return None;
        }
        let mut state = 0_u64;
        // SAFETY: the call takes the token registered above and writes one 64-bit value through a
        // pointer to a live local of that size.
        let read = unsafe { notify_get_state(token, &raw mut state) };
        // SAFETY: the call takes the token registered above, once, and reads no memory of this
        // process. A registration that cannot be released is left to the process's end.
        let _ = unsafe { notify_cancel(token) };
        (read == NOTIFY_STATUS_OK).then_some(state)
    }
}

/// The two places in this crate that call the performance counters and the power status.
///
/// The workspace forbids unsafe code; this crate denies it and relaxes the rule for this module,
/// because neither facility has a safe interface.
#[cfg(windows)]
mod windows {
    #![expect(
        unsafe_code,
        reason = "the power-status call and the performance counters have no safe interface"
    )]

    use super::{PowerStatus, ThermalZone};
    use windows_sys::Win32::System::Performance::{
        PDH_CSTATUS_NEW_DATA, PDH_CSTATUS_VALID_DATA, PDH_FMT_COUNTERVALUE_ITEM_W, PDH_FMT_LONG,
        PDH_HCOUNTER, PDH_HQUERY, PDH_MORE_DATA, PdhAddEnglishCounterW, PdhCloseQuery,
        PdhCollectQueryData, PdhGetFormattedCounterArrayW, PdhOpenQueryW,
    };
    use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};

    /// The counter whose instances are the machine's thermal zones, by the name the counters have
    /// in every language.
    const PASSIVE_LIMIT: &str = r"\Thermal Zone Information(*)\% Passive Limit";

    // The statuses the pure reading of a zone counts are the system's own.
    const _: () = assert!(
        super::STATUS_VALID_DATA == PDH_CSTATUS_VALID_DATA
            && super::STATUS_NEW_DATA == PDH_CSTATUS_NEW_DATA
    );

    pub(super) fn power_status() -> Option<PowerStatus> {
        let mut status = SYSTEM_POWER_STATUS {
            ACLineStatus: 0,
            BatteryFlag: 0,
            BatteryLifePercent: 0,
            SystemStatusFlag: 0,
            BatteryLifeTime: 0,
            BatteryFullLifeTime: 0,
        };
        // SAFETY: the call writes one `SYSTEM_POWER_STATUS` through the pointer it is given and has
        // no other effect. The pointer is to a live local of exactly that type.
        let read = unsafe { GetSystemPowerStatus(&raw mut status) };
        (read != 0).then_some(PowerStatus {
            ac_line_status: status.ACLineStatus,
            battery_flag: status.BatteryFlag,
        })
    }

    /// A query that is closed when it goes out of scope.
    struct Query(PDH_HQUERY);

    impl Drop for Query {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful `PdhOpenQueryW` and is closed once, here.
            unsafe {
                PdhCloseQuery(self.0);
            }
        }
    }

    pub(super) fn thermal_zones() -> Vec<ThermalZone> {
        read_zones().unwrap_or_default()
    }

    fn read_zones() -> Option<Vec<ThermalZone>> {
        let mut handle: PDH_HQUERY = std::ptr::null_mut();
        // SAFETY: a null data source means the live counters, and the call writes one handle
        // through the pointer it is given, which is to a live local.
        let opened = unsafe { PdhOpenQueryW(std::ptr::null(), 0, &raw mut handle) };
        if opened != 0 {
            return None;
        }
        let query = Query(handle);

        let path: Vec<u16> = PASSIVE_LIMIT
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut counter: PDH_HCOUNTER = std::ptr::null_mut();
        // SAFETY: the path is a null-terminated wide string that outlives the call, the query is
        // open, and the call writes one handle through a pointer to a live local. A machine with no
        // thermal zone refuses here, and that is no reading.
        let added = unsafe { PdhAddEnglishCounterW(query.0, path.as_ptr(), 0, &raw mut counter) };
        if added != 0 {
            return None;
        }
        // SAFETY: the query is open and holds the counter added above.
        if unsafe { PdhCollectQueryData(query.0) } != 0 {
            return None;
        }

        // The first call says how much room the instances need, and the second fills it. The
        // buffer is made of 64-bit words, which is the alignment an item needs.
        let mut bytes = 0_u32;
        let mut count = 0_u32;
        // SAFETY: with a null buffer the call writes only the two sizes, through pointers to live
        // locals.
        let sized = unsafe {
            PdhGetFormattedCounterArrayW(
                counter,
                PDH_FMT_LONG,
                &raw mut bytes,
                &raw mut count,
                std::ptr::null_mut(),
            )
        };
        if sized != PDH_MORE_DATA {
            return None;
        }
        let mut buffer = vec![0_u64; (bytes as usize).div_ceil(8)];
        // SAFETY: the buffer holds at least `bytes` bytes, as the first call asked, is aligned for
        // an item, and outlives the call; the sizes are written through pointers to live locals.
        let filled = unsafe {
            PdhGetFormattedCounterArrayW(
                counter,
                PDH_FMT_LONG,
                &raw mut bytes,
                &raw mut count,
                buffer.as_mut_ptr().cast::<PDH_FMT_COUNTERVALUE_ITEM_W>(),
            )
        };
        if filled != 0 {
            return None;
        }

        // SAFETY: the call filled `count` items at the start of the buffer, which is aligned for
        // them, and the buffer is not touched while the slice is read.
        let items = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr().cast::<PDH_FMT_COUNTERVALUE_ITEM_W>(),
                count as usize,
            )
        };
        let mut zones = Vec::new();
        for item in items {
            // SAFETY: the format asked for a long, so the value is the union's 32-bit member when
            // the counter was formatted. For an item whose status is a failure the bytes are still
            // initialised (the buffer was zeroed and the call wrote into it) and every bit pattern
            // is an `i32`; `counted` gives no limit for such an item and ignores this number.
            let limit = unsafe { item.FmtValue.Anonymous.longValue };
            // SAFETY: the name is a null-terminated wide string the call placed in the buffer,
            // which is still held.
            let name = unsafe { wide_string(item.szName) };
            zones.push(ThermalZone::counted(name, item.FmtValue.CStatus, limit));
        }
        Some(zones)
    }

    /// Reads a null-terminated wide string.
    ///
    /// # Safety
    ///
    /// `name` is null or points to a null-terminated sequence of 16-bit units that is readable to
    /// its end.
    unsafe fn wide_string(name: *const u16) -> String {
        if name.is_null() {
            return String::new();
        }
        let mut length = 0;
        // SAFETY: the caller promised the sequence is readable to its terminator, and the loop
        // stops there.
        while unsafe { *name.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: the `length` units before the terminator are readable.
        let units = unsafe { std::slice::from_raw_parts(name, length) };
        String::from_utf16_lossy(units)
    }
}

#[cfg(test)]
mod tests {
    use super::{PowerStatus, Supply, ThermalZone};

    /// A Mac answers with one of the levels the SDK names for macOS, 0 to 4. A reading outside them
    /// would mean the call was made wrongly, and the host would then be paused for heat it does not
    /// have.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_thermal_pressure_level_a_mac_reports_is_one_the_system_names() {
        let level = super::thermal_pressure_level().expect("the system answers");
        assert!(level <= 4, "the level {level}");
    }

    /// Windows' power-status call, answered with the bytes machines returned: a desktop with no
    /// battery that is plugged in (recorded on the Windows test machine, whose class has no
    /// battery), the encodings the call documents for a laptop on its charger, on its battery and
    /// with a low battery, and the two answers that say nothing about the source.
    #[test]
    fn the_power_status_a_machine_returned_says_where_its_power_comes_from() {
        let mains = |ac_line_status, battery_flag| {
            PowerStatus {
                ac_line_status,
                battery_flag,
            }
            .supply()
        };
        assert_eq!(mains(1, 128), Some(Supply::Mains), "a desktop, plugged in");
        assert_eq!(mains(1, 9), Some(Supply::Mains), "high and charging");
        assert_eq!(mains(0, 1), Some(Supply::Battery), "high, unplugged");
        assert_eq!(mains(0, 2), Some(Supply::Battery), "low, unplugged");
        assert_eq!(mains(0, 4), Some(Supply::Battery), "critical, unplugged");
        assert_eq!(
            mains(255, 128),
            Some(Supply::Mains),
            "no battery to run from, whatever the line says"
        );
        assert_eq!(mains(255, 255), None, "nothing known");
        assert_eq!(
            mains(255, 1),
            None,
            "a battery and no word on the plug has not said"
        );
    }

    /// A zone as a counter reported it: a status that holds data gives its number, the first
    /// reading after a change included, and a counter that held no data, or a number below nought,
    /// gives a listed zone with no limit. Statuses are the system's: 0 valid data, 1 new data, and
    /// three of the failures Performance Data Helper returns for a counter that cannot be read.
    #[test]
    fn a_zone_the_counters_gave_no_reading_of_is_listed_with_no_limit() {
        let zone = |status, value| ThermalZone::counted("zone".to_owned(), status, value);
        let limit = |status, value| zone(status, value).passive_limit_percent;

        assert_eq!(limit(0, 100), Some(100), "valid data");
        assert_eq!(limit(1, 61), Some(61), "the first reading after a change");
        assert_eq!(
            limit(0, 0),
            Some(0),
            "a platform holding the processors still"
        );
        assert_eq!(
            limit(0x8000_07D5_u32, 100),
            None,
            "a counter with no data (PDH_NO_DATA)"
        );
        assert_eq!(
            limit(0xC000_0BB8_u32, 100),
            None,
            "a counter that is not there"
        );
        assert_eq!(
            limit(0xC000_0BBA_u32, 100),
            None,
            "a counter with invalid data (PDH_CSTATUS_INVALID_DATA)"
        );
        assert_eq!(limit(0, -1), None, "a number below nought");
        assert_eq!(
            zone(0xC000_0BBA_u32, 100).name,
            "zone",
            "and the name is kept"
        );
    }

    /// The machine's own management data, asked through PowerShell, and what this module reads
    /// through the performance counters: the thermal zones are the ones the management data lists,
    /// each with the limit it lists, and a machine that lists none has none.
    #[cfg(windows)]
    #[test]
    fn the_thermal_zones_agree_with_the_platforms_management_data() {
        use super::thermal_zones;
        use std::process::Command;

        let script = "Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation | \
            ForEach-Object { '{0}={1}' -f $_.Name, $_.PercentPassiveLimit }";
        let printed = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .expect("PowerShell runs");
        assert!(printed.status.success(), "{printed:?}");
        let text = String::from_utf8_lossy(&printed.stdout).into_owned();
        let mut listed: Vec<(String, Option<u32>)> = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (name, limit) = line.rsplit_once('=').expect("a name and a limit");
                (name.to_lowercase(), Some(limit.parse().expect("a limit")))
            })
            .collect();
        listed.sort();

        let mut read: Vec<(String, Option<u32>)> = thermal_zones()
            .into_iter()
            .map(|zone| (zone.name.to_lowercase(), zone.passive_limit_percent))
            .collect();
        read.sort();
        assert_eq!(read, listed);
    }
}
