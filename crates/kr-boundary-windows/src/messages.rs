//! Messages of the product whose exact words are fixed: what the installer says while Windows
//! starts application control, and what the broker answers while its proof has not passed.

/// Said by the installer after it starts the Application Identity service, before it waits for the
/// platform's first "policy applied" event.
// text: APPLICATION_CONTROL_STARTING
pub const APPLICATION_CONTROL_STARTING: &str = "Windows starts application control after the service starts, and the installation waits for it.";

/// The broker's answer to every request while its proof of the boundary has not passed.
// text: STILL_STARTING
pub const STILL_STARTING: &str =
    "Windows is still starting application control after the restart; try again in a few minutes.";
