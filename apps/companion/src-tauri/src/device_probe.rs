//! The checks a debug build runs on a phone for what the device keeps for itself.
//!
//! A script puts a request in the application's data directory (`kr-probe/device-request.json`),
//! starts the application on a simulator, and reads the lines the application writes beside it
//! (`kr-probe/device-result-<run>-<launch>.txt`, one `check=<name> ok=<0 or 1> detail=<text>` per
//! check and `done=1` last). It runs the same device three times, which is the point: what a phone
//! keeps is what survives the application ending.
//!
//! * the pairing records opened, with the reason when they did not;
//! * the secure store keeps an item across launches: written in the first, read and deleted in the
//!   second, absent in the third;
//! * the device's own budget is charged for a code at an origin nothing answers for
//!   (`probe.invalid`), so the tries left after each launch show whether the count and the boot
//!   identity survive a relaunch, and that a deleted boot record is a tombstone;
//! * the boot identity's digest, which the script compares across launches;
//! * the directories of the pairing records are excluded from the device's backup.
//!
//! Compiled into debug builds only. A release build has no request to read.

use std::path::Path;

use tauri::Manager as _;

use crate::probe::Check;

/// What a script asks a launch for.
#[derive(serde::Deserialize)]
struct Request {
    /// Names the run, which the result file's name repeats.
    run: String,
    /// Which launch of the run this is: the first, the second or the third.
    launch: u32,
    /// The value the secure store keeps across the first two launches.
    item: String,
    /// What the launch does with the item: `write`, `read_and_delete` or `absent`.
    secret: String,
    /// The tries the budget has left after this launch's charge, or none when it refuses the code.
    tries_left: Option<u32>,
}

fn is_a_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn check(name: &'static str, ok: bool, detail: impl std::fmt::Display) -> Check {
    Check {
        name,
        ok,
        detail: detail.to_string().replace(['\n', '\r'], " "),
    }
}

/// Runs the checks a script asked for, if it asked: the request is read once and taken away.
pub fn start<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let Ok(data) = app.path().app_data_dir() else {
        return;
    };
    let directory = data.join("kr-probe");
    let Ok(text) = std::fs::read_to_string(directory.join("device-request.json")) else {
        return;
    };
    let _ = std::fs::remove_file(directory.join("device-request.json"));
    let Ok(request) = serde_json::from_str::<Request>(&text) else {
        return;
    };
    if !is_a_name(&request.run) {
        return;
    }
    let app = app.clone();
    std::thread::spawn(move || {
        let file = directory.join(format!(
            "device-result-{}-{}.txt",
            request.run, request.launch
        ));
        let append = |text: &str| {
            use std::io::Write as _;
            if let Ok(mut open) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file)
            {
                let _ = open.write_all(text.as_bytes());
            }
        };
        append(&format!("run={}\nlaunch={}\n", request.run, request.launch));
        for found in checks(&app, &data, &request) {
            append(&format!("{}\n", found.line()));
        }
        append("done=1\n");
    });
}

fn checks<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    data: &Path,
    request: &Request,
) -> Vec<Check> {
    let mut found = Vec::new();
    let state = app.state::<crate::AppState>();
    let device = match state.device() {
        Ok(device) => {
            found.push(check("the pairing records open", true, "open"));
            device
        }
        Err(error) => {
            found.push(check("the pairing records open", false, error.message));
            return found;
        }
    };
    found.push(secret_item(app, request));

    let pairing = device.pairing();
    let digest: String = pairing
        .clock
        .boot_identity()
        .0
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    found.push(check("the boot identity", true, format!("digest {digest}")));
    found.push(charge(pairing, request.tries_left));
    found.extend(backup(app, data));
    found
}

/// The secure store keeps an item from one launch to the next.
fn secret_item<R: tauri::Runtime>(app: &tauri::AppHandle<R>, request: &Request) -> Check {
    use kr_crypto::store::SecretName;

    let name = "secret store";
    let store = match companion_platform::secrets::open(app) {
        Ok(store) => store,
        Err(error) => return check(name, false, format!("not opened: {error}")),
    };
    let Ok(item) = SecretName::new("kr-probe-item") else {
        return check(name, false, "the probe's item has no valid name");
    };
    let wanted = request.item.as_bytes();
    let held = match store.get(&item) {
        Ok(held) => held,
        Err(error) => return check(name, false, format!("read failed: {error}")),
    };
    let held = held.as_ref().map(|bytes| bytes.expose().to_vec());
    match request.secret.as_str() {
        "write" => {
            if held.is_some() {
                return check(name, false, "an item of an earlier run was still there");
            }
            match store.set(&item, wanted) {
                Ok(()) => check(name, true, format!("written to {}", store.describe())),
                Err(error) => check(name, false, format!("write failed: {error}")),
            }
        }
        "read_and_delete" => {
            if held.as_deref() != Some(wanted) {
                return check(name, false, "the item of the earlier launch is not there");
            }
            match store.delete(&item).and_then(|()| store.get(&item)) {
                Ok(None) => check(name, true, "the item survived the relaunch and was deleted"),
                Ok(Some(_)) => check(name, false, "the item was still there after its deletion"),
                Err(error) => check(name, false, format!("delete failed: {error}")),
            }
        }
        _ => check(
            name,
            held.is_none(),
            if held.is_none() {
                "absent"
            } else {
                "an item was left behind"
            },
        ),
    }
}

/// One try is charged against the device's own budget for a code nothing answers for.
fn charge(pairing: &kr_client::pairing::candidate::Pairing, wanted: Option<u32>) -> Check {
    use kr_pairing::PairingError;
    use kr_pairing::client::charge_attempt;
    use kr_pairing::code::EnteredCode;
    use kr_protocol::pairing::RendezvousOrigin;

    let name = "budget";
    let (Ok(origin), Ok(code)) = (
        RendezvousOrigin::new("https://probe.invalid"),
        EnteredCode::parse("aB3x-Yz7-9Qw"),
    ) else {
        return check(name, false, "the probe's origin or code does not parse");
    };
    match (
        charge_attempt(&*pairing.budget, &*pairing.clock, &origin, &code),
        wanted,
    ) {
        (Ok(left), Some(wanted)) => check(
            name,
            left == wanted,
            format!("{left} tries left, expected {wanted}"),
        ),
        (Err(PairingError::ClientAttemptsExhausted), None) => {
            check(name, true, "the code is refused as spent")
        }
        (Ok(left), None) => check(
            name,
            false,
            format!("{left} tries left, expected a refusal"),
        ),
        (Err(error), _) => check(name, false, format!("not charged: {error}")),
    }
}

/// The directories of the pairing records are excluded from the device's backup.
#[cfg(target_os = "ios")]
fn backup<R: tauri::Runtime>(app: &tauri::AppHandle<R>, data: &Path) -> Vec<Check> {
    [
        (
            "the paired hosts are out of the backup",
            crate::device::HOSTS_DIRECTORY,
        ),
        (
            "the budget is out of the backup",
            crate::device::BUDGET_DIRECTORY,
        ),
    ]
    .into_iter()
    .map(|(name, directory)| {
        match companion_platform::backup::is_kept_out(app, &data.join(directory)) {
            Ok(excluded) => check(name, excluded, format!("{directory} excluded: {excluded}")),
            Err(error) => check(name, false, format!("not read: {error}")),
        }
    })
    .collect()
}

#[cfg(not(target_os = "ios"))]
const fn backup<R: tauri::Runtime>(_app: &tauri::AppHandle<R>, _data: &Path) -> Vec<Check> {
    Vec::new()
}
