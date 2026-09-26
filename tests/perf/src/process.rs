//! What a measurement reads about the processes it measures.
//!
//! A reading this host could not take is an error, never a zero. A process the kernel will not
//! name, or a column it does not print the way this reads it, would otherwise count as having used
//! nothing, which is the one direction a resource measurement must never be wrong in.

use std::collections::BTreeMap;
use std::process::Command;

/// Runs `ps` for `pids` with one output column after the identifier, and returns that column by
/// process, refusing a process `ps` did not report.
fn ps_column(pids: &[u32], column: &str) -> Result<BTreeMap<u32, String>, String> {
    if pids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let list = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let output = Command::new("ps")
        .args(["-o", &format!("pid=,{column}="), "-p", &list])
        .output()
        .map_err(|error| format!("read the process table: {error}"))?;
    let mut found = BTreeMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut fields = line.split_whitespace();
        let (Some(pid), Some(value)) = (fields.next(), fields.next()) else {
            continue;
        };
        if let Ok(pid) = pid.parse::<u32>() {
            found.insert(pid, value.to_owned());
        }
    }
    if let Some(missing) = pids.iter().find(|pid| !found.contains_key(pid)) {
        return Err(format!(
            "the process table has no process {missing}, so its reading cannot be taken"
        ));
    }
    Ok(found)
}

/// Each process's resident size, in kibibytes, read in one pass over the process table.
///
/// # Errors
///
/// A process that is not running, or a size the table does not give as a number.
pub fn resident_kib(pids: &[u32]) -> Result<BTreeMap<u32, u64>, String> {
    ps_column(pids, "rss")?
        .into_iter()
        .map(|(pid, value)| {
            value
                .parse()
                .map(|kib| (pid, kib))
                .map_err(|_| format!("process {pid}'s resident size reads `{value}`"))
        })
        .collect()
}

/// Each process's processor time, user and system together, in seconds.
///
/// Linux keeps the count in clock ticks, in `/proc/<pid>/stat`, and that is what is read there: its
/// `ps` prints processor time in whole seconds. Elsewhere `ps` prints it to a hundredth of a second.
///
/// # Errors
///
/// A process that is not running, or a reading that is not in the form this reads.
pub fn processor_seconds(pids: &[u32]) -> Result<BTreeMap<u32, f64>, String> {
    #[cfg(target_os = "linux")]
    {
        pids.iter()
            .map(|&pid| linux_processor_seconds(pid).map(|seconds| (pid, seconds)))
            .collect()
    }
    #[cfg(not(target_os = "linux"))]
    {
        ps_column(pids, "time")?
            .into_iter()
            .map(|(pid, value)| {
                processor_time(&value)
                    .map(|seconds| (pid, seconds))
                    .ok_or_else(|| format!("process {pid}'s processor time reads `{value}`"))
            })
            .collect()
    }
}

#[cfg(target_os = "linux")]
fn linux_processor_seconds(pid: u32) -> Result<f64, String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|error| format!("read process {pid}'s status: {error}"))?;
    // The second field is the command name in parentheses, and a name can hold spaces and
    // parentheses of its own, so the fields are counted from after the last parenthesis. The first
    // of them is the line's third field.
    let fields: Vec<&str> = status
        .rsplit_once(')')
        .map(|(_, rest)| rest.split_whitespace().collect())
        .ok_or_else(|| format!("process {pid}'s status names no command: `{status}`"))?;
    let ticks = |field: usize| -> Result<u64, String> {
        fields
            .get(field - 3)
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| format!("process {pid}'s status has no field {field}: `{status}`"))
    };
    let used = ticks(14)? + ticks(15)?;
    #[expect(
        clippy::cast_precision_loss,
        reason = "a tick count over one measurement is far inside f64's exact range"
    )]
    let seconds = used as f64 / rustix::param::clock_ticks_per_second() as f64;
    Ok(seconds)
}

/// Reads `ps`'s processor time, `[[dd-]hh:]mm:ss[.cc]`, as seconds.
#[cfg_attr(
    target_os = "linux",
    allow(dead_code, reason = "Linux reads /proc instead")
)]
fn processor_time(text: &str) -> Option<f64> {
    let (days, clock) = match text.split_once('-') {
        Some((days, clock)) => (days.parse::<f64>().ok()?, clock),
        None => (0.0, text),
    };
    let mut seconds = 0.0;
    for part in clock.split(':') {
        seconds = seconds * 60.0 + part.parse::<f64>().ok()?;
    }
    Some(days * 86_400.0 + seconds)
}

/// A process's parent, where the process table names one other than the system's first process.
#[must_use]
pub fn parent_of(pid: u32) -> Option<u32> {
    ps_column(&[pid], "ppid")
        .ok()?
        .remove(&pid)?
        .parse::<u32>()
        .ok()
        .filter(|parent| *parent > 1)
}

/// How many processes the host is running.
///
/// # Errors
///
/// When the process table cannot be read.
pub fn count() -> Result<usize, String> {
    let output = Command::new("ps")
        .args(["-A", "-o", "pid="])
        .output()
        .map_err(|error| format!("read the process table: {error}"))?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count())
}

/// The processes whose parent is `pid`.
#[must_use]
pub fn children_of(pid: u32) -> Vec<u32> {
    let Ok(output) = Command::new("pgrep")
        .args(["-P", &pid.to_string()])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::processor_time;

    #[test]
    fn processor_time_is_read_in_every_form_ps_prints_it() {
        assert_eq!(processor_time("0:00.12"), Some(0.12));
        assert_eq!(processor_time("1:02.50"), Some(62.5));
        assert_eq!(processor_time("01:02:03"), Some(3723.0));
        assert_eq!(processor_time("2-01:00:00"), Some(2.0 * 86_400.0 + 3600.0));
        assert_eq!(processor_time(""), None);
        assert_eq!(processor_time("soon"), None);
    }
}
