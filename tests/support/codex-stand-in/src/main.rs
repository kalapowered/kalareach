//! A stand-in for `codex`, the pinned release's command: its application server and its native
//! terminal, each speaking the protocol that release speaks.
//!
//! * `codex app-server --listen stdio://` is the server, on standard input and output.
//! * `codex --remote unix:///path [words]` and `codex words --remote unix:///path` are the
//!   terminal, connecting to a gateway's socket: a host that integrates the command puts its flags
//!   after the words that were typed.
//! * `codex --exec-in-new-session PROGRAM [arguments]` is how the server starts a command in a
//!   session of its own, as the pinned release's server does.
//!
//! Every frame either side writes or reads is checked against the schemas that release publishes
//! (see `contract`), so a gateway that makes a frame the pinned release would not write is caught.
//! A test makes a run misbehave by naming variants in `KR_STAND_IN` (see `variants`).
//!
//! The release's terminal reaches a gateway over a socket in a file and its server starts commands
//! in process groups, so the program is built for Unix; elsewhere it only says so.

#[cfg(unix)]
mod contract;
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
        ["app-server", "--listen", "stdio://"] => server::run(variants).await,
        ["--remote", remote, words @ ..] | [words @ .., "--remote", remote]
            if remote.starts_with("unix://") =>
        {
            let socket = &remote["unix://".len()..];
            let prompt = words.join(" ");
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

#[cfg(not(unix))]
fn main() {
    eprintln!("codex-stand-in: built for Unix only");
    std::process::exit(2);
}
