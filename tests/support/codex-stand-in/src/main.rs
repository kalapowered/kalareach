//! A stand-in for `codex`, the pinned release's command: its application server and its native
//! terminal, each speaking the protocol that release speaks.
//!
//! * `codex app-server --listen stdio://` is the server, on standard input and output.
//! * `codex --remote unix:///path [words]` and `codex words --remote unix:///path` are the
//!   terminal, connecting to a gateway's socket: a host that integrates the command puts its flags
//!   after the words that were typed.
//! * `codex --exec-in-new-session PROGRAM [arguments]` is how the server starts a command in a
//!   session of its own, as the pinned release's server does.
//! * `codex --rewrite-config` appends a line to the configuration file `CODEX_HOME` names, as an
//!   agent that rewrites its configuration at a start does.
//! * `codex --move-work` moves the directory it runs in to a place beside the directory that
//!   holds it and makes an empty directory of the same name in its place, as an agent that moves
//!   its working directory away at a start does.
//!
//! Every frame either side writes or reads is checked against the schemas that release publishes
//! (see `contract`), so a gateway that makes a frame the pinned release would not write is caught.
//! A test makes a run misbehave by naming variants in `STAND_IN` (see `variants`).
//!
//! The release's terminal reaches a gateway over a socket in a file. On Unix its server starts
//! commands in process groups; on Windows it starts them in jobs.

/// The release the newer program of this source is.
const NEWER_RELEASE: &str = "0.156.1";

/// Whether this program is the newer build of the source: the second `[[bin]]` of the package.
fn newer() -> bool {
    option_env!("CARGO_BIN_NAME") == Some("codex-stand-in-newer")
}

mod contract;
#[cfg(windows)]
mod job;
#[cfg(unix)]
mod keyboard;
#[cfg(unix)]
mod record;
mod server;
#[cfg(unix)]
mod terminal;
mod variants;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let variants = variants::Variants::from_env();
    match arguments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--version"] => println!(
            "codex-cli {}",
            if newer() {
                NEWER_RELEASE
            } else {
                contract::RELEASE
            }
        ),
        // The pinned build, started by hand where no gateway serves it: a composer, and nothing to
        // serve.
        #[cfg(unix)]
        [] if variants.by_hand && !newer() => by_hand(None),
        // The pinned build, started by hand on a saved conversation: its own `resume` or `fork` and
        // the conversation's identifier. The stand-in saves none, so it only says what it was asked.
        // As with a start by hand on nothing, the case says so in `STAND_IN`: a start that does not
        // is one no gateway served, and ends on the last arm.
        #[cfg(unix)]
        [word @ ("resume" | "fork"), id] if variants.by_hand && !newer() => {
            by_hand(Some(format!("{word} {id}")))
        }
        // The newer build, started as typed (a build outside the package's range is served no
        // gateway, so the shell runs it with nothing after its name): it says so and stays until
        // it is ended, which keeps its image and its place in the process table for a case to look
        // at.
        [] if newer() => run_as_typed(),
        // What an agent that rewrites its own configuration at a start does: a line is added to the
        // `config.toml` that `CODEX_HOME` names.
        ["--rewrite-config"] => rewrite_config(),
        // What an agent that moves its working directory out from under its caller does. A
        // Windows process holds its working directory open, so nothing can move it away.
        #[cfg(unix)]
        ["--move-work"] => move_work(),
        ["app-server", "--listen", "stdio://"] => server::run(variants).await,
        #[cfg(unix)]
        ["--remote", remote, words @ ..] | [words @ .., "--remote", remote]
            if remote.starts_with("unix://") =>
        {
            let socket = &remote["unix://".len()..];
            let prompt = words.join(" ");
            if variants.leave_a_host {
                variants::Variants::leave();
            }
            let status =
                terminal::run(contract::Contract::pinned(), variants, socket, &prompt).await;
            std::process::exit(status);
        }
        #[cfg(unix)]
        [server::EXEC_IN_NEW_SESSION, _, ..] => server::exec_in_new_session(&arguments[1..]),
        _ => {
            eprintln!(
                "codex-stand-in: serves `app-server --listen stdio://` and `--remote unix://PATH \
                 [words]` only"
            );
            std::process::exit(2);
        }
    }
}

/// What the line says when a program started by hand is up: the screen shows it before any key.
#[cfg(unix)]
const BY_HAND: &str = "codex-stand-in: by hand";

/// What the program does when a person starts it by hand: draws a composer, shows what is typed at
/// it, says what a typed line or command comes to, and goes on until its input ends or it is ended.
/// `on` is the saved-conversation command it was started with, where it was.
#[cfg(unix)]
fn by_hand(on: Option<String>) -> ! {
    use std::io::Read as _;
    let mut screen = keyboard::Screen::open();
    screen.begins();
    match on {
        Some(on) => screen.say(format!("{BY_HAND} ({on})")),
        None => screen.say(BY_HAND),
    }
    let mut decoder = keyboard::Decoder::default();
    let mut input = std::io::stdin().lock();
    let mut bytes = [0_u8; 256];
    loop {
        match input.read(&mut bytes) {
            Ok(count) if count > 0 => {
                for key in decoder.keys(&bytes[..count]) {
                    if let Some(typed) = screen.key(key) {
                        screen.say(format!("by hand: took {typed:?}"));
                    }
                }
                screen.redraw();
            }
            _ => std::process::exit(0),
        }
    }
}

/// What the newer build does when it runs as typed: says so on its terminal and waits to be ended.
/// The wait is a bound and not a decision: the program ends by itself after an hour.
fn run_as_typed() -> ! {
    eprintln!(
        "codex-stand-in: serves nothing as typed (newer build {NEWER_RELEASE}, {})",
        option_env!("CARGO_BIN_NAME").unwrap_or("")
    );
    std::thread::sleep(std::time::Duration::from_secs(3600));
    std::process::exit(2);
}

/// Appends a line to the `config.toml` in the directory `CODEX_HOME` names, and says so.
///
/// # Panics
///
/// Panics when the directory is not named or the file cannot be appended to.
fn rewrite_config() {
    use std::io::Write as _;
    let directory = std::env::var_os("CODEX_HOME").expect("CODEX_HOME names the configuration");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(std::path::Path::new(&directory).join("config.toml"))
        .expect("the configuration file");
    writeln!(file, "# rewritten by a start of the agent").expect("appends to it");
    println!("codex-cli rewrote its configuration");
}

/// Moves the directory it runs in to a sibling of the directory that holds it, named after that
/// directory with `-moved` added, makes an empty directory at the old place, and says so.
///
/// # Panics
///
/// Panics when the directory has no parent or cannot be moved or made again.
#[cfg(unix)]
fn move_work() {
    let work = std::env::current_dir().expect("the working directory");
    let holder = work
        .parent()
        .expect("a directory that holds the working directory");
    let mut name = holder
        .file_name()
        .expect("a name for the directory that holds it")
        .to_os_string();
    name.push("-moved");
    std::fs::rename(&work, holder.with_file_name(name)).expect("moves the directory away");
    std::fs::create_dir(&work).expect("makes another directory at the old place");
    println!("codex-cli moved its working directory");
}
