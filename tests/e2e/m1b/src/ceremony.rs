//! The owner's side of pairing, as `kr pair` runs it.
//!
//! A host with no owner yet has its first owner confirmed at an interactive terminal outside every
//! session: the person types `pair` to issue the invitation and, to approve the device that answers
//! it, the verification value that device shows. So those two run on a terminal window of their
//! own. On a host that has an owner, the same commands wait for an owner device to confirm and ask
//! nothing of the terminal, so they run as plain commands while the device answers.

use std::process::Output;
use std::thread::JoinHandle;

use serde_json::Value;

use crate::LIVENESS;
use crate::host::{Host, output_within};
use crate::window::Window;

/// What the person types to issue a host's first owner invitation.
const ISSUE_WORD: &[u8] = b"pair";

/// The prompt the issuing ceremony asks at.
const ISSUE_PROMPT: &[u8] = b"Type pair to issue the invitation: ";

/// The prompt the approving ceremony asks at.
const APPROVE_PROMPT: &[u8] = b"Type the verification value the new device shows: ";

/// How one `kr pair` ended: its status and the document it printed.
#[derive(Clone, Debug)]
pub struct Answered {
    /// The command's exit status.
    pub exit: u32,
    /// What it printed with `--json`.
    pub document: Value,
}

impl Answered {
    /// The code a refusal carries, when this is one.
    #[must_use]
    pub fn refusal(&self) -> Option<&str> {
        if self.document["ok"] == false {
            self.document["code"].as_str()
        } else {
            None
        }
    }
}

/// Issues an invitation at a terminal on a host with no owner, typing `pair` at the ceremony.
///
/// `arguments` follow `kr pair invite`.
///
/// # Panics
///
/// Panics when the ceremony never asks, the command does not end within [`LIVENESS`], or it prints
/// no document.
#[must_use]
pub fn issue_first(host: &Host<'_>, arguments: &[&str]) -> Answered {
    let mut command = vec!["pair", "invite"];
    command.extend_from_slice(arguments);
    command.push("--json");
    at_terminal(host, "kr pair invite", &command, ISSUE_PROMPT, ISSUE_WORD)
}

/// Approves the device that answered `invitation_id` at a terminal on a host with no owner,
/// typing the verification value that device shows.
///
/// # Panics
///
/// As [`issue_first`].
#[must_use]
pub fn approve_first(host: &Host<'_>, invitation_id: &str, verification_value: &str) -> Answered {
    at_terminal(
        host,
        "kr pair confirm",
        &["pair", "confirm", invitation_id, "--json"],
        APPROVE_PROMPT,
        verification_value.as_bytes(),
    )
}

/// Starts `kr pair invite` on a host that has an owner. It waits for an owner device to confirm;
/// [`finished`] collects it.
#[must_use]
pub fn issue_waiting(host: &Host<'_>, arguments: &[&str]) -> JoinHandle<Result<Output, String>> {
    let mut command = vec!["pair", "invite"];
    command.extend_from_slice(arguments);
    command.push("--json");
    let command = host.command(&command);
    std::thread::spawn(move || output_within(command, LIVENESS))
}

/// Starts `kr pair confirm` on a host that has an owner. It waits for an owner device to confirm;
/// [`finished`] collects it.
#[must_use]
pub fn approve_waiting(host: &Host<'_>, invitation_id: &str) -> JoinHandle<Result<Output, String>> {
    let command = host.command(&["pair", "confirm", invitation_id, "--json"]);
    std::thread::spawn(move || output_within(command, LIVENESS))
}

/// Collects a command started by [`issue_waiting`] or [`approve_waiting`].
///
/// # Panics
///
/// Panics when it did not end or printed no document.
#[must_use]
pub fn finished(waiting: JoinHandle<Result<Output, String>>, what: &str) -> Answered {
    let output = waiting
        .join()
        .unwrap_or_else(|_| panic!("{what}: the thread running it failed"))
        .unwrap_or_else(|error| panic!("{what}: {error}"));
    let document = first_document(&output.stdout).unwrap_or_else(|| {
        panic!(
            "{what} printed no document: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    Answered {
        exit: output
            .status
            .code()
            .and_then(|code| u32::try_from(code).ok())
            .unwrap_or(u32::MAX),
        document,
    }
}

fn at_terminal(
    host: &Host<'_>,
    what: &str,
    arguments: &[&str],
    prompt: &[u8],
    typed: &[u8],
) -> Answered {
    let run = host.run();
    let mut window = Window::open(
        run,
        what,
        &run.binary("kr"),
        arguments,
        run.root(),
        &host.variables(),
    );
    let _ = window.wait_for(0, prompt, "the owner's ceremony asks at the terminal");
    let mark = window.mark();
    let mut line = typed.to_vec();
    line.push(b'\r');
    window.type_text(&line);
    let exit = window.exit_code(LIVENESS);
    let printed = window.collected().since(mark);
    let document = first_document(&printed).unwrap_or_else(|| {
        panic!(
            "{what} printed no document after the ceremony: {}",
            String::from_utf8_lossy(&printed).escape_debug()
        )
    });
    Answered { exit, document }
}

/// The first JSON document in what a command printed, wherever it starts.
///
/// A terminal carries the ceremony's own lines and the echo of what was typed before the
/// document, and turns every line ending into a carriage return and a line feed.
#[must_use]
pub fn first_document(printed: &[u8]) -> Option<Value> {
    let text = String::from_utf8_lossy(printed).replace('\r', "");
    let start = text.find('{')?;
    serde_json::Deserializer::from_str(&text[start..])
        .into_iter::<Value>()
        .next()?
        .ok()
}

/// Pairs `device` as the first owner of a host that has none, by direct QR over loopback: the
/// person issues the invitation and approves the device at the terminal, and the device redeems it
/// and connects with its paired proof.
///
/// # Panics
///
/// Panics when any step fails, naming it.
#[must_use]
pub fn pair_first_owner(
    host: &Host<'_>,
    device: &crate::device::Device,
    runtime: &tokio::runtime::Runtime,
) -> (crate::device::PairedHost, crate::device::Remote) {
    let invited = issue_first(host, &["--owner", "--direct"]);
    assert_eq!(
        invited.exit, 0,
        "the owner invitation: {}",
        invited.document
    );
    let candidate = runtime
        .block_on(device.redeem(invited.document["qr_text"].as_str().expect("a QR text")))
        .unwrap_or_else(|why| panic!("the redemption: {why}"));
    let approved = approve_first(
        host,
        invited.document["invitation_id"]
            .as_str()
            .expect("an invitation"),
        &candidate.verification_value,
    );
    assert_eq!(
        approved.exit, 0,
        "the owner approves: {}",
        approved.document
    );
    let paired = runtime
        .block_on(candidate.committed(LIVENESS))
        .unwrap_or_else(|why| panic!("the pairing: {why}"));
    let remote = runtime
        .block_on(device.connect(&paired))
        .unwrap_or_else(|why| panic!("the paired connection: {why}"));
    (paired, remote)
}
