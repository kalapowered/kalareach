//! One Claude Code lifecycle or tool hook.
//!
//! A hook here observes. Whatever happens, the forwarder writes exactly `{}` to standard output and
//! exits 0, promptly: a JSON object with no fields is the neutral answer on every event, and exit 0
//! is the code that neither blocks nor reports an error. It never answers `{"continue": false}`,
//! never prints anything a hook's output could be read as, and never waits for a person.
//!
//! Every run is bounded by [`HOOK_DEADLINE`], well inside the shortest timeout the package
//! registers (one second, for `SessionEnd`). When the deadline passes, the answer is written and
//! the process ends, whatever is still in flight.

use std::io::Read as _;
use std::time::Duration;

use crate::exchange::Exchange;
use crate::registration::{Bridge, Paths, Registration};

/// What a hook declares itself to the worker as.
const BRIDGE: Bridge = Bridge {
    application: super::APPLICATION,
    surface: "hook",
};

/// How long one hook run may take, from start to answer.
///
/// The package registers a one-second timeout for `SessionEnd` and five seconds for the other four
/// events. Claude Code cancels a hook that reaches its timeout and discards its output, so the
/// deadline sits well inside the shorter one.
pub const HOOK_DEADLINE: Duration = Duration::from_millis(500);

/// The most of a hook's input this forwarder reads.
///
/// A `PostToolUse` event carries the tool's whole response, which can be large. It is read to its
/// end so the application's write completes, and past this bound it is left unread.
pub const MAX_HOOK_INPUT_BYTES: u64 = 64 * 1024 * 1024;

/// The answer every hook run writes: a JSON object that sets nothing.
pub const NEUTRAL_ANSWER: &str = "{}";

/// Runs one hook and answers neutrally.
#[must_use]
pub fn run() -> std::process::ExitCode {
    let (finished, outcome) = std::sync::mpsc::channel();
    // The work runs on its own thread so the deadline is kept whatever it is waiting on. When the
    // deadline passes, the answer is written and the process ends, which ends that thread too.
    std::thread::spawn(move || {
        let _ = finished.send(observe());
    });
    match outcome.recv_timeout(HOOK_DEADLINE) {
        Ok(Ok(())) => {}
        Ok(Err(failure)) => crate::report(&failure),
        Err(_) => crate::report(&format!(
            "the hook did not finish within {} ms, and answered anyway",
            HOOK_DEADLINE.as_millis()
        )),
    }
    answer()
}

/// How long a hook waits for the worker to finish publishing its launch.
///
/// The worker writes the registration as soon as it knows which process it started, long before
/// the application runs its first hook, so this only covers a hook that races the launch itself.
pub const REGISTRATION_WAIT: Duration = Duration::from_millis(250);

/// Reads the event Claude Code wrote and, inside a launch, reaches the worker with it.
fn observe() -> Result<(), String> {
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_HOOK_INPUT_BYTES)
        .read_to_end(&mut input)
        .map_err(|error| format!("the hook's input could not be read: {error}"))?;
    // Outside a launch there is nobody to tell, and the answer is the same neutral one.
    let Some(paths) = Paths::from_environment().map_err(|error| error.to_string())? else {
        return Ok(());
    };
    let registration =
        Registration::read(&paths, REGISTRATION_WAIT).map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("the hook could not start: {error}"))?;
    runtime
        .block_on(async {
            let mut exchange = Exchange::open(&registration, BRIDGE).await?;
            exchange.admitted(HOOK_DEADLINE).await
        })
        .map_err(|error| error.to_string())
}

/// Writes the neutral answer and ends with the code that blocks nothing.
fn answer() -> std::process::ExitCode {
    use std::io::Write as _;
    let mut output = std::io::stdout().lock();
    let _ = writeln!(output, "{NEUTRAL_ANSWER}");
    let _ = output.flush();
    std::process::ExitCode::SUCCESS
}
