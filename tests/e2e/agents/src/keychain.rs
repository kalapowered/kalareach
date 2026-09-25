//! A keychain of the run's own, made the default inside the run's home.
//!
//! macOS reads a user's keychain search list and default keychain from the home directory a
//! process names. An agent started with a home that holds no keychain, and that writes a secret, as
//! some do when they start to test their store, finds no default keychain, and the system then asks
//! the person at the screen to create one. So each run's home gets a keychain of its own, with a
//! random password, unlocked, searched and made the default there before any session starts in
//! it: a write stays inside the home, nobody is asked anything, and the keychain is deleted with the
//! run. Every step runs with the run's home as the only home it names, so the person's own search
//! list and default keychain are never read or written.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use kr_e2e_m1b::LIVENESS;
use kr_e2e_m1b::run::output_within;

/// The run's keychain, deleted when this is dropped.
pub struct RunKeychain {
    home: PathBuf,
    path: PathBuf,
}

impl RunKeychain {
    /// Creates the keychain in `home` and makes it the home's only searched and default keychain,
    /// on macOS; elsewhere there is nothing to create.
    ///
    /// # Panics
    ///
    /// Panics when a step fails, or when the home's default keychain is not this one afterwards.
    #[must_use]
    pub fn create(home: &Path) -> Option<Self> {
        if !cfg!(target_os = "macos") {
            return None;
        }
        let keychains = home.join("Library").join("Keychains");
        // The search list and the default are written to the home's own preferences file, and
        // silently not written when its folder is missing.
        let preferences = home.join("Library").join("Preferences");
        for directory in [&keychains, &preferences] {
            std::fs::create_dir_all(directory)
                .unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
        }
        let path = keychains.join("kr-agents.keychain-db");
        let keychain = path.display().to_string();
        let password = random_password();
        security(home, &["create-keychain", "-p", &password, &keychain]);
        // No lock after a timeout or on sleep: a locked default keychain would ask for its password.
        security(home, &["set-keychain-settings", &keychain]);
        security(home, &["unlock-keychain", "-p", &password, &keychain]);
        security(home, &["list-keychains", "-d", "user", "-s", &keychain]);
        security(home, &["default-keychain", "-d", "user", "-s", &keychain]);
        let named = security(home, &["default-keychain", "-d", "user"]);
        let resolved = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        assert!(
            named.contains(&resolved.display().to_string()) || named.contains(&keychain),
            "the run's home names {keychain} as its default keychain, not {named}"
        );
        Some(Self {
            home: home.to_path_buf(),
            path,
        })
    }
}

impl Drop for RunKeychain {
    fn drop(&mut self) {
        // Removes it from the home's search list and deletes its file.
        let mut command = security_command(&self.home);
        command.args(["delete-keychain", &self.path.display().to_string()]);
        let _ = output_within(command, LIVENESS);
    }
}

/// `security` with `home` as the only home it names.
fn security_command(home: &Path) -> Command {
    let mut command = Command::new("/usr/bin/security");
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin");
    command
}

/// Runs one `security` step and returns what it printed.
fn security(home: &Path, arguments: &[&str]) -> String {
    let mut command = security_command(home);
    command.args(arguments);
    let output = output_within(command, LIVENESS)
        .unwrap_or_else(|why| panic!("security {}: {why}", arguments[0]));
    assert!(
        output.status.success(),
        "security {}: {}{}",
        arguments[0],
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Thirty-two hexadecimal digits from the system's random source.
fn random_password() -> String {
    let mut bytes = [0_u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .expect("reads the system's random source");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
