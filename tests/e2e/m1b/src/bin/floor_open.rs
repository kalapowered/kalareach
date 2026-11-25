//! The product's open of a clock floor's file, run as a program of its own, so that an agent that
//! cuts or replaces the file while the product maps it ends this program and not the test program
//! that asked. It takes the file's path and the environment's id, opens the floor as the daemon
//! does for this boot, and exits 0 when the floor opens. It exits 2, with why on standard error,
//! when it does not. Its only argument may be `--version`, which ends it at once with exit 0 and
//! touches nothing: the host starts it once in this way, where nothing is timed, when it places the
//! program in the run. It runs on Unix only, as the floor does.

use std::process::ExitCode;

#[cfg(unix)]
fn open_floor(path: &std::ffi::OsStr, environment: &std::ffi::OsStr) -> Result<(), String> {
    let environment = environment
        .to_str()
        .and_then(|text| text.parse::<kr_protocol::ids::EnvironmentId>().ok())
        .ok_or_else(|| "the environment's id is not an identifier".to_owned())?;
    let boot = kr_ipc::identity::boot_identity()
        .and_then(|identity| kr_ipc::identity::boot_epoch(&identity))
        .map_err(|why| format!("the boot epoch cannot be read: {why}"))?;
    kr_ipc::floor::SharedFloor::open(std::path::Path::new(path), environment, boot)
        .map(drop)
        .map_err(|why| why.to_string())
}

#[cfg(not(unix))]
fn open_floor(_: &std::ffi::OsStr, _: &std::ffi::OsStr) -> Result<(), String> {
    Err("the floor is opened on Unix only".to_owned())
}

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match arguments.as_slice() {
        [version] if version == "--version" => ExitCode::SUCCESS,
        [path, environment] => match open_floor(path, environment) {
            Ok(()) => ExitCode::SUCCESS,
            Err(why) => {
                eprintln!("{why}");
                ExitCode::from(2)
            }
        },
        _ => {
            eprintln!("the floor opener takes the floor's path and the environment's id");
            ExitCode::from(2)
        }
    }
}
