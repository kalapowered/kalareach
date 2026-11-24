//! The text a launch case ends with when its launch did not go through the integration: what the
//! terminal showed after the typing, when each step of the launch was first seen, what the host's
//! list of instances held, and what the daemon wrote.
//!
//! A launch the host does not admit and commit runs as typed, and the host then adopts the process
//! without a registration. A refusal, a deadline that passed and a start that failed leave the
//! same instance behind, so the failure has to say which it was. The launcher repeats what the
//! backend told it on the terminal, and the case sees the order and the spacing of the steps, so
//! both go into the text. The host keeps its own reason for a refused launch in the worker's
//! memory only, so it is in the report only where the launcher repeated it.
//!
//! Everything here is a plain function of text and times, so that what a case reports is tested
//! without a host.

use std::fmt::Write as _;
use std::time::Duration;

/// The words the launcher ends its report with when it runs the program as typed: it says so when
/// the backend refused the launch, did not answer within the launcher's deadline, or did not
/// commit the launch within it.
pub const RUNS_AS_TYPED: &str = "so the program runs as typed";

/// The most bytes of the terminal's text the report repeats, counted after control characters are
/// written as escapes.
pub const TERMINAL_AT_MOST: usize = 4096;

/// When, counted from the typing, a case first saw each step of one launch. A step that was never
/// seen is `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    /// The forging helper's line on the terminal.
    pub helper_line: Option<Duration>,
    /// The launcher's report that it runs the program as typed ([`RUNS_AS_TYPED`]).
    pub launcher_report: Option<Duration>,
    /// The first instance the host listed for the session, of whatever kind.
    pub first_instance: Option<Duration>,
    /// The first instance the host listed as served through its gateway.
    pub served: Option<Duration>,
}

impl Seen {
    /// Notes that `step` was seen at `at`, unless it was seen before: the first sighting is the
    /// one that counts.
    fn first(step: &mut Option<Duration>, at: Duration) {
        if step.is_none() {
            *step = Some(at);
        }
    }

    /// Notes what a look at the terminal's text since the typing shows at `at`: the forging
    /// helper's line, which `helper_line` is a part of, and the launcher's report that it runs the
    /// program as typed.
    pub fn observe_terminal(&mut self, at: Duration, terminal: &str, helper_line: &str) {
        if terminal.contains(helper_line) {
            Self::first(&mut self.helper_line, at);
        }
        if terminal.contains(RUNS_AS_TYPED) {
            Self::first(&mut self.launcher_report, at);
        }
    }

    /// Notes what a read of the host's list of instances shows at `at`: how many instances it
    /// listed, where the read succeeded, and whether one of them is served through the gateway.
    pub fn observe_instances(&mut self, at: Duration, listed: Option<usize>, served: bool) {
        if listed.is_some_and(|count| count > 0) {
            Self::first(&mut self.first_instance, at);
        }
        if served {
            Self::first(&mut self.served, at);
        }
    }
}

/// What a launch case that found no instance served through the gateway says about the launch:
/// the steps and when each was first seen, the host's reads of its instances, the terminal's text
/// since the typing, what the daemon wrote and what the session worker said to its diagnostics.
///
/// `reads` is the case's own text of the host's reads, each with the time it was made; `worker` is
/// the host's text of the worker's diagnostics lines.
#[must_use]
pub fn launch_report(
    terminal: &str,
    seen: &Seen,
    reads: &str,
    daemon: &str,
    worker: &str,
) -> String {
    format!(
        "the launch's steps, as first seen from the typing:\n{}\n\
         the host's list of application instances as the device read it, each read with its time \
         after the case began:\n{reads}\n\
         the terminal's text since the typing, control characters as escapes:\n{}\n\
         what the daemon wrote:\n{daemon}\n\
         the worker's diagnostics (a refusal before the credential leaves only its line here):\n\
         {worker}",
        steps(seen),
        terminal_text(terminal, TERMINAL_AT_MOST),
    )
}

/// The steps of a launch, one to a line, each with the time it was first seen or that it was not.
fn steps(seen: &Seen) -> String {
    let mut text = String::new();
    for (name, at) in [
        ("the forging helper's line", seen.helper_line),
        (
            "the launcher's report that it runs the program as typed",
            seen.launcher_report,
        ),
        ("the first instance the host listed", seen.first_instance),
        ("the first instance served through the gateway", seen.served),
    ] {
        if !text.is_empty() {
            text.push('\n');
        }
        let _ = match at {
            Some(at) => write!(text, "  {name}: +{} ms", at.as_millis()),
            None => write!(text, "  {name}: not seen"),
        };
    }
    text
}

/// The first `at_most` bytes of `text` as a person reads them in a log: a line end as a line end,
/// every other control character as the escape that names it, and a note of how much was cut where
/// the text is longer.
fn terminal_text(text: &str, at_most: usize) -> String {
    let mut shown = String::new();
    for character in text.replace("\r\n", "\n").chars() {
        let piece = if character == '\n' || !character.is_control() {
            character.to_string()
        } else {
            character.escape_default().to_string()
        };
        if shown.len() + piece.len() > at_most {
            let _ = write!(
                shown,
                "\n(cut at {at_most} bytes of the {} bytes the terminal gave)",
                text.len()
            );
            break;
        }
        shown.push_str(&piece);
    }
    shown
}

#[cfg(test)]
mod tests {
    use super::*;

    const REFUSAL: &str = "the backend did not admit this launch (the executable presented is not \
                           the file this backend was established for), so the program runs as typed";

    fn all_seen() -> Seen {
        Seen {
            helper_line: Some(Duration::from_millis(250)),
            launcher_report: Some(Duration::from_millis(2310)),
            first_instance: Some(Duration::from_millis(2400)),
            served: None,
        }
    }

    #[test]
    fn the_report_repeats_the_launchers_own_line_from_the_terminal() {
        let terminal =
            format!("kr-e2e-forge: pid 7 start 9 forged presentation refused\r\n{REFUSAL}\r\n");
        let report = launch_report(&terminal, &all_seen(), "(no read)", "(daemon)", "(worker)");
        assert!(report.contains(REFUSAL), "the launcher's line: {report}");
        assert!(
            report.contains("forged presentation refused\n"),
            "a line end is a line end: {report}"
        );
        assert!(!report.contains('\r'), "no carriage return: {report:?}");
    }

    #[test]
    fn the_report_gives_the_time_each_step_was_first_seen_and_says_which_was_not_seen() {
        let report = launch_report("", &all_seen(), "(no read)", "(daemon)", "(worker)");
        assert!(
            report.contains("the forging helper's line: +250 ms"),
            "{report}"
        );
        assert!(
            report.contains("the launcher's report that it runs the program as typed: +2310 ms"),
            "{report}"
        );
        assert!(
            report.contains("the first instance the host listed: +2400 ms"),
            "{report}"
        );
        assert!(
            report.contains("the first instance served through the gateway: not seen"),
            "{report}"
        );
        let nothing = launch_report("", &Seen::default(), "(no read)", "(daemon)", "(worker)");
        assert_eq!(nothing.matches(": not seen").count(), 4, "{nothing}");
    }

    #[test]
    fn the_report_holds_the_hosts_reads_of_its_instances_with_their_times() {
        let reads = "+14210 ms AgentInstanceList { sequence: U64(1) }\n+14240 ms AgentInstanceList { sequence: U64(1) }";
        let report = launch_report("", &all_seen(), reads, "(daemon)", "(worker)");
        assert!(report.contains(reads), "the reads: {report}");
    }

    #[test]
    fn the_report_holds_what_the_daemon_wrote() {
        let report = launch_report(
            "",
            &all_seen(),
            "(no read)",
            "the daemon's last line",
            "(worker)",
        );
        assert!(
            report.contains("the daemon's last line"),
            "the daemon's text: {report}"
        );
    }

    #[test]
    fn the_report_holds_the_workers_diagnostics_line_of_a_forged_presentation() {
        let line = "a launch was not admitted: this connection did not present this backend's \
                    credential";
        let report = launch_report("", &all_seen(), "(no read)", "(daemon)", line);
        assert!(
            report.contains(&format!(
                "the worker's diagnostics (a refusal before the credential leaves only its line \
                 here):\n{line}"
            )),
            "the worker's line: {report}"
        );
    }

    #[test]
    fn the_terminals_text_is_cut_at_the_bound_and_its_control_characters_are_escapes() {
        let long = format!("\u{1b}[31m{}", "é".repeat(TERMINAL_AT_MOST));
        let report = launch_report(&long, &Seen::default(), "(no read)", "(daemon)", "(worker)");
        assert!(
            report.contains("\\u{1b}[31m"),
            "the escape is named: {report}"
        );
        assert!(!report.contains('\u{1b}'), "no raw escape: {report:?}");
        assert!(
            report.contains("(cut at 4096 bytes of the "),
            "the cut is said: {report}"
        );
        let shown = terminal_text(&long, TERMINAL_AT_MOST);
        let kept = shown.split("\n(cut").next().unwrap_or_default();
        assert!(
            kept.len() <= TERMINAL_AT_MOST,
            "the bound holds, to the byte: {}",
            kept.len()
        );
        assert_eq!(
            terminal_text("short\ttext", TERMINAL_AT_MOST),
            "short\\ttext",
            "a text inside the bound is kept whole"
        );
    }

    const HELPER: &str = "forged presentation";
    const HELPER_LINE: &str = "kr-e2e-forge: pid 7 start 9 forged presentation refused";

    fn ms(count: u64) -> Duration {
        Duration::from_millis(count)
    }

    #[test]
    fn a_look_at_the_terminal_notes_each_line_at_its_first_sight_and_a_later_look_moves_none() {
        let mut seen = Seen::default();
        seen.observe_terminal(ms(10), "$ codex\r\n", HELPER);
        assert_eq!(seen, Seen::default(), "nothing to see yet");
        seen.observe_terminal(ms(40), &format!("$ codex\r\n{HELPER_LINE}\r\n"), HELPER);
        assert_eq!(seen.helper_line, Some(ms(40)), "the helper's line");
        assert_eq!(seen.launcher_report, None, "the launcher has not reported");
        seen.observe_terminal(ms(2300), &format!("{HELPER_LINE}\r\n{REFUSAL}\r\n"), HELPER);
        assert_eq!(seen.helper_line, Some(ms(40)), "the first sight stays");
        assert_eq!(
            seen.launcher_report,
            Some(ms(2300)),
            "the launcher's report"
        );
        seen.observe_terminal(ms(2900), &format!("{HELPER_LINE}\r\n{REFUSAL}\r\n"), HELPER);
        assert_eq!(
            seen.launcher_report,
            Some(ms(2300)),
            "the first sight stays"
        );
        assert_eq!(seen.first_instance, None, "no list was read");
        assert_eq!(seen.served, None, "no list was read");
    }

    #[test]
    fn a_read_of_the_hosts_list_notes_the_first_instance_and_the_first_served_one_apart() {
        let mut seen = Seen::default();
        seen.observe_instances(ms(5), None, false);
        seen.observe_instances(ms(30), Some(0), false);
        assert_eq!(
            seen,
            Seen::default(),
            "a failed read and an empty list show nothing"
        );
        seen.observe_instances(ms(60), Some(1), false);
        assert_eq!(seen.first_instance, Some(ms(60)), "the first instance");
        assert_eq!(seen.served, None, "none is served through the gateway");
        seen.observe_instances(ms(90), Some(2), true);
        assert_eq!(seen.first_instance, Some(ms(60)), "the first sight stays");
        assert_eq!(seen.served, Some(ms(90)), "the first served instance");
        seen.observe_instances(ms(120), Some(2), true);
        assert_eq!(seen.served, Some(ms(90)), "the first sight stays");
        assert_eq!(seen.helper_line, None, "no terminal was looked at");
        assert_eq!(seen.launcher_report, None, "no terminal was looked at");
    }
}
