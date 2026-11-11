//! The installation, its repair and its removal.
//!
//! The installation lays down, in this order and recording each object in the manifest before the
//! step that makes it: the data directory and the earlier-state record, the program directory and
//! the broker and credential helper in it, the two accounts with their rights, the service, the
//! Application Identity service, started and awaited until the platform reports its first policy
//! applied, the application-control policy, awaited the same way, and then the proof that the
//! policy refuses what it must. A failure at any step undoes what was done by the removal
//! sequence and then checks the machine against the earlier-state record.
//!
//! The removal puts back only what the installation changed. Another rule that an administrator
//! added to the executable collection is left in force, with the allow-all rule beside it, since
//! taking the allow-all rule away would make that rule a block for every account it does not name.
//! The broker stays up in a maintenance state until the release has been shown, because only the
//! broker can make the token that shows it.

#![allow(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead as _, Read as _, Write as _};
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use crate::frame::{self, Class, Request, Response};
use crate::manifest::{
    GitSet, Image, InstallState, Manifest, ObjectKind, Prior, STORE_VERSION, StoreError,
};
use crate::messages;
use crate::notice::NOTICE;
use crate::policy::{self, Policy};

use super::acl;
use super::applocker::{self, Channel};
use super::ffi::{self, Sid};
use super::proof;
use super::registry;
use super::sd::{self, Principals, SdKind};
use super::service;
use super::{account, boot, pipe, token, verify};

/// The broker's service name.
pub const SERVICE: &str = "KalaReachBoundary";
/// The checkout and apply account.
pub const CHECKOUT: &str = "krb-checkout";
/// The connection account.
pub const CONNECT: &str = "krb-connect";

const DISPLAY: &str = "KalaReach repository boundary";
const BROKER: &str = "kr-boundary-broker.exe";
const CREDENTIAL: &str = "kr-boundary-credential.exe";
/// The privileges the broker uses and no others.
const BROKER_PRIVILEGES: [&str; 7] = [
    "SeTcbPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeImpersonatePrivilege",
    "SeChangeNotifyPrivilege",
    // Held disabled, and enabled only on the token of the thread that walks a tree (privilege.rs).
    "SeBackupPrivilege",
    "SeRestorePrivilege",
];
const APPID: &str = "AppIDSvc";
const APPID_KEY: &str = r"SYSTEM\CurrentControlSet\Services\AppIDSvc";
const AUTOMATIC: u32 = 2;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// A failure of the installation, its repair or its removal.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The installation refuses to go on, for a reason the person can act on.
    #[error("{0}")]
    Refused(String),
    /// A call into the platform failed.
    #[error(transparent)]
    Win(#[from] ffi::Error),
    /// A record could not be read or written.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Application control could not be read or written.
    #[error(transparent)]
    Applocker(#[from] applocker::Error),
    /// A file operation failed.
    #[error("{what}: {source}")]
    Io {
        /// What was being done.
        what: String,
        /// The reason.
        source: io::Error,
    },
    /// A step failed in a way that is not one of the above.
    #[error("{0}")]
    Failed(String),
}

/// The steps of an installation, named so that a test can make any one of them fail.
pub const STEPS: [&str; 7] = [
    "directories",
    "payload",
    "accounts",
    "service",
    "appid",
    "policy",
    "broker",
];

/// Fails the step named in the environment, for the test build only. A build that ships has no
/// such seam.
#[cfg(feature = "testing")]
fn inject(step: &str) -> Result<(), Error> {
    if std::env::var("KR_BOUNDARY_FAIL_AFTER").as_deref() == Ok(step) {
        return Err(Error::Failed(format!(
            "a failure was injected after the {step} step"
        )));
    }
    Ok(())
}

#[cfg(not(feature = "testing"))]
#[allow(clippy::unnecessary_wraps)]
fn inject(_step: &str) -> Result<(), Error> {
    Ok(())
}

fn io_error(what: impl Into<String>) -> impl FnOnce(io::Error) -> Error {
    let what = what.into();
    move |source| Error::Io { what, source }
}

/// Where the installation lives.
#[derive(Clone, Debug)]
pub struct Paths {
    /// The program directory: the broker and the credential helper.
    pub program: PathBuf,
    /// The data directory: the manifest, the earlier-state record, the journal and the staging
    /// directories.
    pub data: PathBuf,
    /// The journal's directory, one file for each invocation. Only administrators and the system
    /// can reach it.
    pub journal: PathBuf,
    /// The directory every invocation's private root is made under. No boundary account can list,
    /// create in or delete from it.
    pub run: PathBuf,
    /// What the broker points Git's global file, hooks path and template directory at: an empty
    /// `config`, an empty `hooks` and an empty `template`, which every account may read.
    pub git: PathBuf,
    /// The directory a run stages in, only administrators and the system can write.
    pub staging: PathBuf,
    /// The manifest.
    pub manifest: PathBuf,
    /// The earlier-state record.
    pub prior: PathBuf,
}

impl Paths {
    /// The installation's places on this computer.
    #[must_use]
    pub fn system() -> Paths {
        let program_files =
            std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into());
        let program_data =
            std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
        let data = PathBuf::from(program_data)
            .join("KalaReach")
            .join("Boundary");
        let program = PathBuf::from(program_files)
            .join("KalaReach")
            .join("Boundary");
        Paths {
            git: program.join("git"),
            program,
            staging: data.join("staging"),
            journal: data.join("journal"),
            run: data.join("run"),
            manifest: data.join("manifest.json"),
            prior: data.join("prior.json"),
            data,
        }
    }
}

fn git_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into()))
        .join("Git")
}

/// How the installation was found.
pub enum Entry {
    /// Nothing of the installation exists.
    Fresh,
    /// The manifest says the installation finished.
    Installed(Manifest),
    /// The manifest says an installation began and did not finish.
    Partial(Manifest),
}

fn say(line: &str) {
    println!("{line}");
}

/// Finds what state the computer is in, and refuses when an object of the installation's names
/// exists that the manifest does not list.
///
/// # Errors
///
/// Returns [`Error::Refused`] naming the foreign object, or the failure of the call that looked.
pub fn entry(paths: &Paths) -> Result<Entry, Error> {
    if paths.manifest.exists() {
        let manifest = Manifest::load(&paths.manifest)?;
        return Ok(match manifest.state {
            InstallState::Installed => Entry::Installed(manifest),
            InstallState::InProgress => Entry::Partial(manifest),
        });
    }
    for name in [CHECKOUT, CONNECT] {
        if account::find(name).is_some() {
            return Err(Error::Refused(format!(
                "an account named {name} exists and this installation did not make it"
            )));
        }
    }
    if service::manager()?.open(SERVICE)?.is_some() {
        return Err(Error::Refused(format!(
            "a service named {SERVICE} exists and this installation did not make it"
        )));
    }
    for directory in [&paths.program, &paths.data] {
        if directory.exists() {
            return Err(Error::Refused(format!(
                "{} exists and this installation did not make it",
                directory.display()
            )));
        }
    }
    Ok(Entry::Fresh)
}

/// Reads the state of every kind of application control and refuses when any is in force. Anything
/// that cannot be read refuses too.
fn refuse_when_controlled(channel: &Channel) -> Result<(String, Policy), Error> {
    let (xml, effective) = channel.effective()?;
    let ours: Vec<&str> = [
        policy::RULE_ALLOW_ALL,
        policy::RULE_CHECKOUT,
        policy::RULE_CONNECT,
    ]
    .into_iter()
    .filter(|id| {
        effective
            .collections
            .get(policy::EXE)
            .is_some_and(|collection| collection.rules.contains_key(*id))
    })
    .collect();
    if !ours.is_empty() {
        return Err(Error::Refused(format!(
            "application control already holds rule(s) of this installation's names: {}",
            ours.join(", ")
        )));
    }
    if !effective.is_unconfigured() {
        return Err(Error::Refused(
            "this computer already enforces application control, so the installation stops and changes nothing"
                .to_owned(),
        ));
    }
    refuse_software_restriction()?;
    refuse_smart_app_control()?;
    refuse_code_integrity()?;
    Ok((xml, effective))
}

fn refuse_software_restriction() -> Result<(), Error> {
    let Some(key) = registry::open(r"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers")?
    else {
        return Ok(());
    };
    if key.dword("DefaultLevel")?.is_some() {
        return Err(Error::Refused(
            "a software restriction policy is set on this computer".to_owned(),
        ));
    }
    for level in key.subkey_names()? {
        if !level.chars().all(|character| character.is_ascii_digit()) {
            continue;
        }
        for kind in ["Paths", "Hashes", "UrlZones"] {
            if let Some(rules) = registry::open(&format!(
                r"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\{level}\{kind}"
            ))? && !rules.subkey_names()?.is_empty()
            {
                return Err(Error::Refused(
                    "a software restriction policy holds rules on this computer".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn refuse_smart_app_control() -> Result<(), Error> {
    let state = registry::open(r"SYSTEM\CurrentControlSet\Control\CI\Policy")?
        .map(|key| key.dword("VerifiedAndReputablePolicyState"))
        .transpose()?
        .flatten();
    match state {
        Some(0) => Ok(()),
        Some(other) => Err(Error::Refused(format!(
            "Smart App Control is on or evaluating on this computer (state {other})"
        ))),
        None => Err(Error::Refused(
            "Smart App Control's state could not be read".to_owned(),
        )),
    }
}

fn refuse_code_integrity() -> Result<(), Error> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    let tool = Path::new(&root).join("System32").join("CiTool.exe");
    let output = Command::new(&tool)
        .args(["--list-policies", "--json"])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            Error::Refused(format!(
                "the code-integrity policies could not be listed: {error}"
            ))
        })?;
    if !output.status.success() {
        return Err(Error::Refused(format!(
            "the code-integrity policies could not be listed: {}",
            output.status
        )));
    }
    let listing: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        Error::Refused(format!(
            "the code-integrity policies could not be read: {error}"
        ))
    })?;
    let policies = listing["Policies"].as_array().ok_or_else(|| {
        Error::Refused("the code-integrity policies could not be read".to_owned())
    })?;
    for entry in policies {
        let system = entry["IsSystemPolicy"].as_bool().unwrap_or(false);
        let enforced = entry["IsEnforced"].as_bool().unwrap_or(true);
        let name = entry["FriendlyName"].as_str().unwrap_or("");
        if !system {
            return Err(Error::Refused(format!(
                "a code-integrity policy beyond the system's is present: {name}"
            )));
        }
        if enforced && name.starts_with("VerifiedAndReputable") {
            return Err(Error::Refused("Smart App Control is enforcing".to_owned()));
        }
    }
    Ok(())
}

/// Finds Git where it installs for every account, refuses when anyone but the system's own class
/// could change it, and records what the policy will name.
fn qualify_git() -> Result<GitSet, Error> {
    let dir = git_dir();
    let mut images = Vec::new();
    for relative in policy::git_images() {
        let path = dir.join(relative);
        let bytes = fs::read(&path).map_err(|_| {
            Error::Refused(format!(
                "Git's program {} is not where the policy expects it",
                path.display()
            ))
        })?;
        if let Some(finding) = acl::changeable_by_others(&path, false)? {
            return Err(Error::Refused(format!(
                "{} can be changed by others: {finding}",
                path.display()
            )));
        }
        let mut ancestor = path.parent();
        while let Some(parent) = ancestor {
            if parent.parent().is_none() {
                break;
            }
            if let Some(finding) = acl::changeable_by_others(parent, true)? {
                return Err(Error::Refused(format!(
                    "{} can be replaced by others: {finding}",
                    parent.display()
                )));
            }
            ancestor = parent.parent();
        }
        images.push(Image {
            path: (*relative).to_owned(),
            sha256: hex::encode(Sha256::digest(&bytes)),
        });
    }
    let output = Command::new(dir.join("mingw64").join("bin").join("git.exe"))
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Error::Refused(format!("Git could not be run: {error}")))?;
    Ok(GitSet {
        dir: dir.display().to_string(),
        version: String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        images,
    })
}

/// One payload file, staged and checked.
struct Staged {
    name: &'static str,
    path: PathBuf,
    sha256: String,
}

/// Copies each payload file into the staging directory through one open handle, checks its
/// signature there and records its digest.
fn stage_payload(payload: &Path, staging: &Path) -> Result<Vec<Staged>, Error> {
    let mut staged = Vec::new();
    for name in [BROKER, CREDENTIAL] {
        let source = payload.join(name);
        let metadata = fs::symlink_metadata(&source).map_err(|_| {
            Error::Refused(format!(
                "{} is not in the payload directory",
                source.display()
            ))
        })?;
        if metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(Error::Refused(format!(
                "{} is a link, not a file",
                source.display()
            )));
        }
        let mut handle = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&source)
            .map_err(io_error(format!("opening {}", source.display())))?;
        let mut bytes = Vec::new();
        handle
            .read_to_end(&mut bytes)
            .map_err(io_error(format!("reading {}", source.display())))?;
        drop(handle);
        let path = staging.join(name);
        fs::write(&path, &bytes).map_err(io_error(format!("staging {}", path.display())))?;
        let checked = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .map_err(io_error(format!("opening {}", path.display())))?;
        let subject = verify::signer(&checked, &path)?;
        if subject != verify::PUBLISHER {
            return Err(Error::Refused(format!(
                "{name} is signed by {subject}, not by {}",
                verify::PUBLISHER
            )));
        }
        drop(checked);
        staged.push(Staged {
            name,
            path,
            sha256: hex::encode(Sha256::digest(&bytes)),
        });
    }
    Ok(staged)
}

fn sha256_of(path: &Path) -> Result<String, Error> {
    let bytes = fs::read(path).map_err(io_error(format!("reading {}", path.display())))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// The state of a run: where it works and what it has recorded.
struct Run {
    paths: Paths,
    manifest: Manifest,
}

impl Run {
    /// Records an object and writes the manifest, before the step that makes the object.
    fn record(&mut self, kind: ObjectKind, id: &str, detail: Option<&str>) -> Result<(), Error> {
        self.manifest.record(kind, id, detail);
        self.manifest.save(&self.paths.manifest)?;
        Ok(())
    }
}

/// The permission list of the service: the system and administrators in full, and each enrolled
/// person only to see whether the service runs and how it is set up.
fn service_security(persons: &[String]) -> Result<String, Error> {
    let persons = persons
        .iter()
        .map(|person| Sid::parse(person))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(sd::descriptor_text(
        SdKind::Service,
        &Principals {
            persons,
            ..Principals::default()
        },
    )?)
}

/// Records a failed step and goes on to the next, so that one failure does not leave the rest of
/// the removal undone.
fn keep(result: Result<(), Error>, what: &str, failures: &mut Vec<String>) {
    if let Err(error) = result {
        say(&format!("{what} failed: {error}"));
        failures.push(format!("{what}: {error}"));
    }
}

/// What `install` and `repair` are asked.
pub struct Options {
    /// The directory the setup program's signed payload is in.
    pub payload: PathBuf,
    /// The person the broker serves, as an identifier, or `None` for the account running setup.
    pub person: Option<String>,
}

/// Asks the person to type yes after showing the notice.
///
/// # Errors
///
/// Returns [`Error::Refused`] for any answer but yes.
pub fn confirm(person: &str, action: &str) -> Result<(), Error> {
    say(NOTICE);
    say("");
    say(&format!("The broker will serve the account {person}."));
    print!("Type yes to {action}: ");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(io_error("reading the answer"))?;
    if answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err(Error::Refused(
            "the answer was not yes, so nothing was changed".to_owned(),
        ))
    }
}

fn person_of(options: &Options) -> Result<String, Error> {
    match &options.person {
        Some(text) => Ok(Sid::parse(text)?.to_text()),
        None => Ok(token::current_user()?.to_text()),
    }
}

/// Installs the boundary, or repairs an installation, and proves it in force.
///
/// # Errors
///
/// Returns the reason the installation stopped. When it stops after a change was made, the
/// removal sequence has run and the machine has been checked against the earlier-state record.
pub fn install(paths: &Paths, options: &Options, repair: bool) -> Result<(), Error> {
    if !token::current_is_administrator()? {
        return Err(Error::Refused(
            "run the setup program as an administrator".to_owned(),
        ));
    }
    let person = person_of(options)?;
    let state = entry(paths)?;
    let (manifest, existing) = match (state, repair) {
        (Entry::Fresh, false) => (Manifest::begin(), false),
        (Entry::Fresh, true) => {
            return Err(Error::Refused(
                "nothing is installed, so there is nothing to repair".to_owned(),
            ));
        }
        (Entry::Installed(_) | Entry::Partial(_), false) => {
            return Err(Error::Refused(
                "the boundary is already installed or half installed: use repair or remove"
                    .to_owned(),
            ));
        }
        (Entry::Installed(manifest) | Entry::Partial(manifest), true) => (manifest, true),
    };
    let mut run = Run {
        paths: paths.clone(),
        manifest,
    };
    if !run.manifest.persons.contains(&person) {
        run.manifest.persons.push(person);
    }
    let outcome = lay_down(&mut run, options, existing);
    if let Err(failure) = outcome {
        say(&format!("the installation stopped: {failure}"));
        if existing {
            return Err(failure);
        }
        say("undoing what was done");
        match remove(paths, true) {
            Ok(()) => say("the earlier state is back"),
            Err(error) => say(&format!(
                "the removal after the failure also failed: {error}"
            )),
        }
        return Err(failure);
    }
    Ok(())
}

fn lay_down(run: &mut Run, options: &Options, existing: bool) -> Result<(), Error> {
    let paths = run.paths.clone();
    fs::create_dir_all(&paths.data).map_err(io_error("making the data directory"))?;
    acl::set_protected(
        &paths.data,
        &sd::descriptor(SdKind::AdminDir, &Principals::default())?,
    )?;
    fs::create_dir_all(&paths.staging).map_err(io_error("making the staging directory"))?;
    acl::set_protected(
        &paths.staging,
        &sd::descriptor(SdKind::AdminDir, &Principals::default())?,
    )?;
    // The journal and the parent of the private roots: administrators and the system only, so no
    // boundary token can list, create in or delete from either.
    for (directory, what) in [
        (&paths.journal, "the journal directory"),
        (&paths.run, "the directory of the private roots"),
    ] {
        run.record(
            ObjectKind::Directory,
            &directory.display().to_string(),
            None,
        )?;
        fs::create_dir_all(directory).map_err(io_error(format!("making {what}")))?;
        acl::set_protected(
            directory,
            &sd::descriptor(SdKind::AdminDir, &Principals::default())?,
        )?;
    }
    let channel = Channel::new(&paths.staging);
    let sweep = |staging: &Path| {
        if let Ok(entries) = fs::read_dir(staging) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with("proof-") {
                    let _ = fs::remove_dir_all(entry.path());
                }
            }
        }
    };
    sweep(&paths.staging);

    say("reading what is on this computer");
    if !existing {
        run.record(
            ObjectKind::Directory,
            &paths.data.display().to_string(),
            None,
        )?;
    }
    let (baseline_xml, effective) = if existing {
        let (xml, effective) = channel.effective()?;
        let foreign = effective.foreign_exe_rules();
        if !foreign.is_empty() {
            return Err(Error::Refused(
                "an administrator has added a rule to the executable collection since the installation, so a repair would change what that rule means"
                    .to_owned(),
            ));
        }
        (xml, effective)
    } else {
        refuse_when_controlled(&channel)?
    };
    let _ = effective;
    let git = qualify_git()?;
    say(&format!("Git: {} at {}", git.version, git.dir));
    let staged = stage_payload(&options.payload, &paths.staging)?;
    for file in &staged {
        say(&format!(
            "{} verified: signed by {}, sha256 {}",
            file.name,
            verify::PUBLISHER,
            file.sha256
        ));
    }
    run.manifest.git = Some(git);
    run.manifest.save(&paths.manifest)?;

    let appid = service::manager()?.open(APPID)?.ok_or_else(|| {
        Error::Refused(
            "the Application Identity service does not exist on this computer".to_owned(),
        )
    })?;
    let (appid_start, _) = appid.configuration()?;
    let appid_running = appid.status()?.running();
    let prior = Prior {
        store: STORE_VERSION,
        appid_start_type: appid_start,
        appid_running,
        policy_xml: baseline_xml,
    };
    if prior.write_once(&paths.prior)? {
        say("the earlier state is recorded");
    }
    inject("directories")?;

    // The program directory and its files.
    let manager = service::manager()?;
    let broker_service = manager.open(SERVICE)?;
    if let Some(service) = &broker_service
        && service.status()?.running()
    {
        service.stop()?;
        service.wait_for(true, Duration::from_secs(60))?;
    }
    run.record(
        ObjectKind::Directory,
        &paths.program.display().to_string(),
        None,
    )?;
    fs::create_dir_all(&paths.program).map_err(io_error("making the program directory"))?;
    acl::set_protected(
        &paths.program,
        &sd::descriptor(
            SdKind::AdminDir,
            &Principals {
                users_may_read: true,
                ..Principals::default()
            },
        )?,
    )?;
    // What the broker points Git's global file, hooks path and template directory at: empty, and
    // readable by every account, never writable by one.
    run.record(
        ObjectKind::Directory,
        &paths.git.display().to_string(),
        None,
    )?;
    fs::create_dir_all(&paths.git)
        .map_err(io_error("making the directory of Git's empty settings"))?;
    for part in ["hooks", "template"] {
        fs::create_dir_all(paths.git.join(part))
            .map_err(io_error(format!("making the empty {part} directory")))?;
    }
    let empty_config = paths.git.join("config");
    run.record(
        ObjectKind::File,
        &empty_config.display().to_string(),
        Some(&hex::encode(Sha256::digest(b""))),
    )?;
    fs::write(&empty_config, b"").map_err(io_error("making the empty global configuration"))?;
    for file in &staged {
        let target = paths.program.join(file.name);
        run.record(
            ObjectKind::File,
            &target.display().to_string(),
            Some(&file.sha256),
        )?;
        fs::copy(&file.path, &target).map_err(io_error(format!("installing {}", file.name)))?;
        if sha256_of(&target)? != file.sha256 {
            return Err(Error::Failed(format!(
                "{} changed while it was installed",
                file.name
            )));
        }
    }

    inject("payload")?;

    // The accounts.
    let mut sids = Vec::new();
    for name in [CHECKOUT, CONNECT] {
        let sid = match account::find(name) {
            Some(sid) if existing => sid,
            _ => {
                run.record(ObjectKind::Account, name, None)?;
                account::create(name)?
            }
        };
        run.record(ObjectKind::Account, name, Some(&sid.to_text()))?;
        run.record(ObjectKind::Right, &format!("{name}:deny-sign-in"), None)?;
        account::grant_rights(&sid, &account::DENY_RIGHTS)?;
        run.record(
            ObjectKind::RegistryValue,
            &format!("SpecialAccounts\\{name}"),
            None,
        )?;
        account::hide_from_sign_in(name)?;
        say(&format!(
            "account {name} ({}) refused sign-in and hidden from the sign-in screen",
            sid.to_text()
        ));
        sids.push(sid);
    }

    inject("accounts")?;

    // The service.
    run.record(ObjectKind::Service, SERVICE, None)?;
    let broker_service = match manager.open(SERVICE)? {
        Some(service) => service,
        None => manager.create(
            SERVICE,
            DISPLAY,
            &paths.program.join(BROKER).display().to_string(),
        )?,
    };
    broker_service.configure(
        "Starts Git for KalaReach as its two repository boundary accounts, on behalf of the people it serves.",
        &BROKER_PRIVILEGES,
    )?;
    broker_service.set_security(&service_security(&run.manifest.persons)?)?;
    run.manifest.save(&paths.manifest)?;

    inject("service")?;

    // The Application Identity service first. A policy written before the service has applied one is
    // not enforced, and the service applies its first about two minutes after it starts.
    run.record(
        ObjectKind::AppIdentity,
        APPID,
        Some(&format!("start={AUTOMATIC}")),
    )?;
    if appid_start != AUTOMATIC {
        appid.set_automatic()?;
    }
    let git = run
        .manifest
        .git
        .clone()
        .ok_or_else(|| Error::Failed("no Git installation is recorded".to_owned()))?;
    let log_env = proof::proof_environment(&git, &paths.staging).map_err(Error::Failed)?;
    let before_start = applocker::newest_record(&paths.staging, &log_env)?;
    let was_running = appid.status()?.running();
    if !was_running {
        appid.start()?;
        appid.wait_for(false, Duration::from_secs(60))?;
    }
    inject("appid")?;
    say(messages::APPLICATION_CONTROL_STARTING);
    let waited = wait_for_applied(
        if was_running {
            Applied::ThisStart
        } else {
            Applied::After(before_start)
        },
        FIRST_APPLIED_BOUND,
        "the Application Identity service's first \"policy applied\" event",
        &paths.staging,
        &log_env,
    )?;
    say(&format!(
        "application control has started, {:.0} s after the service",
        waited.as_secs_f32()
    ));

    // The policy, and the platform's next event that says it applied it.
    let wanted = Policy::installed(&sids[0].to_text(), &sids[1].to_text());
    for id in [
        policy::RULE_ALLOW_ALL,
        policy::RULE_CHECKOUT,
        policy::RULE_CONNECT,
    ] {
        run.record(ObjectKind::PolicyRule, id, None)?;
    }
    let before_write = applocker::newest_record(&paths.staging, &log_env)?;
    channel.set(&wanted.render())?;
    say("the policy is written");
    inject("policy")?;
    wait_for_applied(
        Applied::After(before_write),
        NEXT_APPLIED_BOUND,
        "the \"policy applied\" event after the policy was written",
        &paths.staging,
        &log_env,
    )?;
    say("the platform has applied the policy");
    let (after_xml, after) = channel.effective()?;
    let _ = after_xml;
    let differences = after.differences(&wanted);
    if !differences.is_empty() {
        return Err(Error::Failed(format!(
            "the platform reports a different policy from the one written: {}",
            differences.join("; ")
        )));
    }

    // The broker, and the proof through it.
    broker_service.start()?;
    broker_service.wait_for(false, Duration::from_secs(60))?;
    say("the broker is running");
    inject("broker")?;
    let mut session = open_session()?;
    for class in [Class::Checkout, Class::Connect] {
        match ask(&mut session, &Request::Prove { class })? {
            Response::Proof {
                ready: true,
                detail,
            } => say(&detail),
            Response::Proof {
                ready: false,
                detail,
            } => {
                return Err(Error::Failed(format!("the proof failed: {detail}")));
            }
            other => {
                return Err(Error::Failed(format!(
                    "the broker answered a proof with {other:?}"
                )));
            }
        }
    }
    run.manifest.state = InstallState::Installed;
    run.manifest.save(&paths.manifest)?;
    say("the boundary is installed and in force");
    Ok(())
}

/// How long the installation waits for the platform's first "policy applied" event after it starts
/// the Application Identity service: the service applies its first policy about two minutes after
/// it starts.
const FIRST_APPLIED_BOUND: Duration = Duration::from_secs(300);
/// How long it waits for the next such event after it has written the policy: the platform applied
/// the policy within a second of the write in every run of the guest.
const NEXT_APPLIED_BOUND: Duration = Duration::from_secs(60);

/// What a "policy applied" event has to come after.
enum Applied {
    /// A record number in the application-control log: the log's newest before the step.
    After(u64),
    /// The start of Windows: the service was already running, so it applied its first policy
    /// before this installation began, or has not yet since the machine started.
    ThisStart,
}

/// Waits for the platform's "policy applied" event, and returns how long it took.
fn wait_for_applied(
    since: Applied,
    bound: Duration,
    what: &str,
    scratch: &Path,
    env: &crate::env::EnvBlock,
) -> Result<Duration, Error> {
    let begun = Instant::now();
    loop {
        let seen = match since {
            Applied::After(record) => applocker::policy_applied_after(record, scratch, env)?,
            Applied::ThisStart => {
                applocker::policy_applied_within(ffi::uptime_millis(), scratch, env)?
            }
        };
        if seen {
            return Ok(begun.elapsed());
        }
        if begun.elapsed() >= bound {
            return Err(Error::Failed(format!(
                "Windows did not report {what} within {} seconds",
                bound.as_secs()
            )));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Connects to the broker's pipe, checking that the process serving it is the service's.
///
/// # Errors
///
/// Returns an error when the service is not running, the pipe is served by another process, or the
/// versions differ.
pub fn open_session() -> Result<pipe::Connection, Error> {
    let manager = service::manager()?;
    let service = manager
        .open(SERVICE)?
        .ok_or_else(|| Error::Failed("the broker's service does not exist".to_owned()))?;
    let status = service.status()?;
    if !status.running() {
        return Err(Error::Failed(
            "the broker's service is not running".to_owned(),
        ));
    }
    let mut connection = pipe::connect(status.pid)?;
    match ask(
        &mut connection,
        &Request::Hello {
            version: frame::VERSION,
        },
    )? {
        Response::Hello { .. } => Ok(connection),
        other => Err(Error::Failed(format!(
            "the broker answered hello with {other:?}"
        ))),
    }
}

/// Sends one request and reads the answer.
///
/// # Errors
///
/// Returns an error when the connection fails.
pub fn ask(connection: &mut pipe::Connection, request: &Request) -> Result<Response, Error> {
    frame::write(connection, request).map_err(|error| Error::Failed(error.to_string()))?;
    frame::read(connection).map_err(|error| Error::Failed(error.to_string()))
}

/// Removes the installation and checks the computer against the earlier-state record.
///
/// With `quiet_when_empty`, an installation that has nothing recorded is not an error. The broker
/// is left in a maintenance state first, the policy is put back, the release is proved through the
/// broker, and only then is the broker, with the accounts and the files, taken away.
///
/// # Errors
///
/// Returns the reason a step failed, after trying every later step it could.
pub fn remove(paths: &Paths, quiet_when_empty: bool) -> Result<(), Error> {
    if !token::current_is_administrator()? {
        return Err(Error::Refused(
            "run the setup program as an administrator".to_owned(),
        ));
    }
    let manifest = match fs::read(&paths.manifest) {
        Ok(bytes) => Manifest::parse(&bytes)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if quiet_when_empty {
                return Ok(());
            }
            return Err(Error::Refused("nothing is installed".to_owned()));
        }
        Err(error) => return Err(io_error("reading the manifest")(error)),
    };
    let prior = Prior::load(&paths.prior).ok();
    let channel = Channel::new(&paths.staging);
    let manager = service::manager()?;
    let mut failures: Vec<String> = Vec::new();
    // (1) the broker stays up and refuses new invocations.
    let mut session = None;
    if manifest.find(ObjectKind::Service, SERVICE).is_some()
        && let Some(service) = manager.open(SERVICE)?
    {
        if !service.status()?.running() {
            let _ = service.start();
            let _ = service.wait_for(false, Duration::from_secs(60));
        }
        match open_session().and_then(|mut connection| {
            ask(&mut connection, &Request::Maintenance { on: true })?;
            Ok(connection)
        }) {
            Ok(connection) => {
                say("the broker is in its maintenance state");
                session = Some(connection);
            }
            Err(error) => say(&format!(
                "the broker could not be reached, so the release will be read from the policy alone: {error}"
            )),
        }
    }

    // (2) the policy: our rules go; an administrator's rule keeps the allow-all rule beside it.
    let has_rules = manifest.of_kind(ObjectKind::PolicyRule).next().is_some();
    if has_rules {
        keep(
            (|| -> Result<(), Error> {
                let (xml, effective) = channel.effective()?;
                let (_, kept) = effective.without_ours();
                if kept {
                    say(
                        "an administrator's rule shares the executable collection, so the allow-all rule and the collection's mode stay in force beside it",
                    );
                }
                let drop: &[&str] = if kept {
                    &[policy::RULE_CHECKOUT, policy::RULE_CONNECT]
                } else {
                    &[
                        policy::RULE_ALLOW_ALL,
                        policy::RULE_CHECKOUT,
                        policy::RULE_CONNECT,
                    ]
                };
                channel.set(
                    &policy::strip(&xml, drop).map_err(|error| Error::Failed(error.to_string()))?,
                )?;
                say("the policy is put back");
                Ok(())
            })(),
            "putting the policy back",
            &mut failures,
        );
    }

    // (3) the Application Identity service's start type goes back only where it is still ours.
    if let (Some(object), Some(prior)) = (manifest.find(ObjectKind::AppIdentity, APPID), &prior) {
        keep(
            (|| -> Result<(), Error> {
                let appid = manager.open(APPID)?.ok_or_else(|| {
                    Error::Failed("the Application Identity service is missing".to_owned())
                })?;
                let (current, _) = appid.configuration()?;
                let set_by_us = object.detail.as_deref() == Some(&format!("start={current}"));
                if set_by_us && current != prior.appid_start_type {
                    if let Some(key) = registry::open(APPID_KEY)? {
                        key.set_dword("Start", prior.appid_start_type)?;
                        say(&format!(
                            "the Application Identity service's start type is back to {}",
                            prior.appid_start_type
                        ));
                    }
                } else {
                    say(
                        "the Application Identity service's start type was changed by someone else and is left alone",
                    );
                }
                Ok(())
            })(),
            "restoring the Application Identity service's start type",
            &mut failures,
        );
    }

    // (4) the release, proved through the broker.
    if let Some(connection) = session.as_mut() {
        for class in [Class::Checkout, Class::Connect] {
            match ask(connection, &Request::Release { class }) {
                Ok(Response::Proof {
                    ready: true,
                    detail,
                }) => say(&detail),
                Ok(Response::Proof {
                    ready: false,
                    detail,
                }) => {
                    keep(
                        Err(Error::Failed(detail)),
                        "proving the release",
                        &mut failures,
                    );
                }
                Ok(other) => keep(
                    Err(Error::Failed(format!("{other:?}"))),
                    "proving the release",
                    &mut failures,
                ),
                Err(error) => keep(Err(error), "proving the release", &mut failures),
            }
        }
    }
    drop(session);

    // (5) the Application Identity service stops if the installation started it and no rule is left,
    // and the broker's service goes.
    if let Some(prior) = &prior {
        keep(
            (|| -> Result<(), Error> {
                let (_, effective) = channel.effective()?;
                let no_rules = effective
                    .collections
                    .values()
                    .all(|collection| collection.rules.is_empty());
                if !prior.appid_running
                    && no_rules
                    && let Some(appid) = manager.open(APPID)?
                    && appid.status()?.running()
                {
                    appid.stop()?;
                    appid.wait_for(true, Duration::from_secs(60))?;
                    say("the Application Identity service is stopped as it was");
                }
                Ok(())
            })(),
            "stopping the Application Identity service",
            &mut failures,
        );
    }
    keep(
        (|| -> Result<(), Error> {
            if let Some(service) = manager.open(SERVICE)? {
                if service.status()?.running() {
                    service.stop()?;
                    service.wait_for(true, Duration::from_secs(60))?;
                }
                // The marker is a volatile key under the service's own key: it goes first.
                boot::remove()?;
                if service.marked_for_deletion()? {
                    say(
                        "the broker's service is already deleted and goes when the last program that holds it lets go",
                    );
                } else {
                    service.delete()?;
                    say("the broker's service is deleted");
                }
            }
            Ok(())
        })(),
        "deleting the broker's service",
        &mut failures,
    );

    // (6) the accounts, their rights and the files.
    for object in manifest.of_kind(ObjectKind::Account) {
        let name = object.id.clone();
        keep(
            (|| -> Result<(), Error> {
                if let Some(sid) = account::find(&name) {
                    account::revoke_all_rights(&sid)?;
                    account::delete_profile(&sid)?;
                }
                account::unhide_from_sign_in(&name)?;
                account::delete(&name)?;
                say(&format!("account {name} is removed with its rights"));
                Ok(())
            })(),
            "removing an account",
            &mut failures,
        );
    }
    if paths.program.exists() {
        keep(
            fs::remove_dir_all(&paths.program).map_err(io_error("removing the program directory")),
            "removing the program directory",
            &mut failures,
        );
        if let Some(parent) = paths.program.parent() {
            let _ = fs::remove_dir(parent);
        }
    }
    // The journal and the private roots' parent go only when empty: a journal row or a root that
    // is still there means a release is not finished, and the records that describe it stay.
    for directory in [&paths.run, &paths.journal] {
        if directory.exists() {
            keep(
                fs::remove_dir(directory).map_err(io_error(format!(
                    "removing {}, which still holds an unfinished invocation",
                    directory.display()
                ))),
                "removing the journal or the private roots",
                &mut failures,
            );
        }
    }
    if let Some(prior) = &prior {
        match residue(prior, paths) {
            Ok(left) if left.is_empty() => say("the machine matches the earlier-state record"),
            Ok(left) => {
                for line in &left {
                    say(&format!("not put back: {line}"));
                }
                failures.push(format!(
                    "the earlier state is not back: {}",
                    left.join("; ")
                ));
            }
            Err(error) => failures.push(format!("checking the earlier state: {error}")),
        }
    }
    if failures.is_empty() {
        // The records go last: a failed removal can be run again from them.
        let _ = fs::remove_dir_all(&paths.staging);
        let _ = fs::remove_file(&paths.manifest);
        let _ = fs::remove_file(&paths.prior);
        let _ = fs::remove_dir(&paths.data);
        if let Some(parent) = paths.data.parent() {
            let _ = fs::remove_dir(parent);
        }
        say("the installation is removed");
        Ok(())
    } else {
        Err(Error::Failed(format!(
            "the removal did not finish and its records are kept: {}",
            failures.join("; ")
        )))
    }
}

/// What the installation changed that has not been put back, read from the machine against the
/// earlier-state record. An empty list means the baseline holds. The data directory is not
/// counted: it holds the records this check reads, and goes last.
///
/// # Errors
///
/// Returns the failure of a call that could not look.
pub fn residue(prior: &Prior, paths: &Paths) -> Result<Vec<String>, Error> {
    let mut left = Vec::new();
    let (_, effective) = Channel::new(&paths.staging).effective()?;
    let baseline =
        Policy::parse(&prior.policy_xml).map_err(|error| Error::Failed(error.to_string()))?;
    // Where an administrator's rule has since joined the executable collection, the removal keeps the
    // allow-all rule and the collection's mode beside it on purpose; everything else of ours is gone.
    let expected = if effective.foreign_exe_rules().is_empty() {
        baseline
    } else {
        effective.without_ours().0
    };
    left.extend(effective.differences(&expected));
    for name in [CHECKOUT, CONNECT] {
        if account::find(name).is_some() {
            left.push(format!("the account {name} is still there"));
        }
        if account::hidden_from_sign_in(name)? {
            left.push(format!("{name} is still hidden from the sign-in screen"));
        }
    }
    if let Some(service) = service::manager()?.open(SERVICE)?
        && !service.marked_for_deletion()?
    {
        left.push("the broker's service is still there".to_owned());
    }
    if paths.program.exists() {
        left.push(format!("{} is still there", paths.program.display()));
    }
    Ok(left)
}
