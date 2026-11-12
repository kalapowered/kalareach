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
//! The release's terminal reaches a gateway over a socket in a file and its server starts commands
//! in process groups, so the program is built for Unix; elsewhere it only says so.

#[cfg(unix)]
mod contract;
#[cfg(unix)]
mod keyboard;
#[cfg(unix)]
mod record;
#[cfg(unix)]
mod server;
#[cfg(unix)]
mod terminal;
#[cfg(unix)]
mod variants;

#[cfg(unix)]
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
        ["--version"] => println!("codex-cli {}", contract::RELEASE),
        // What an agent that rewrites its own configuration at a start does: a line is added to the
        // `config.toml` that `CODEX_HOME` names.
        ["--rewrite-config"] => rewrite_config(),
        // What an agent that moves its working directory out from under its caller does.
        ["--move-work"] => move_work(),
        ["app-server", "--listen", "stdio://"] => server::run(variants).await,
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

/// Appends a line to the `config.toml` in the directory `CODEX_HOME` names, and says so.
///
/// # Panics
///
/// Panics when the directory is not named or the file cannot be appended to.
#[cfg(unix)]
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

#[cfg(not(unix))]
fn main() {
    eprintln!("codex-stand-in: built for Unix only");
    std::process::exit(2);
}
