//! What the project tests build their repositories out of.
//!
//! Everything here lives on the internal disk: the host tree, the repositories, the journal and
//! the sentinel directory. A repository is built with plain installed Git, deliberately *not*
//! through the restricted profile, because the profile refuses the subcommands a fixture needs
//! (`add`, `commit`) and that refusal is itself one of the things under test.

// Each test binary compiles this module on its own and uses the part of it that it needs, so a
// helper another binary uses is dead code from this one's point of view.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use kr_ipc::testing::TempHost;
use kr_project::ProjectService;
use kr_project::credential::{BrokerRegistry, OS_SECRET_STORE};

/// Fails the test unless nothing at all is at the path, and says what it found instead.
///
/// `Path::exists` answers false when the platform would not say — a permission failure anywhere
/// along the path reads exactly like an absence — and it follows a link, so a name whose target is
/// gone reads as absent although the name is still there. An assertion that something was removed
/// has to distinguish those, so this asks about the name itself and accepts only its plain absence.
///
/// # Panics
///
/// Panics when something is at the path, and when the platform will not say whether anything is.
pub fn assert_absent(path: &Path, what: &str) {
    match std::fs::symlink_metadata(path) {
        Ok(found) => panic!(
            "{what}: {} still holds {:?}",
            path.display(),
            found.file_type()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!(
            "{what}: whether {} is there could not be established: {error}",
            path.display()
        ),
    }
}

/// Returns the names one directory holds, sorted, and fails the test on anything it could not read.
///
/// A listing that turns a failure into an empty list is a listing that says "there is nothing here"
/// when it means "I could not look", and an assertion built on it then passes for the wrong reason.
/// Every error is the test's answer: the directory could not be opened, or one entry could not be
/// read, and either way what is in there is not established.
///
/// # Panics
///
/// Panics when the directory or any entry in it cannot be read.
#[must_use]
pub fn names_in(directory: &Path) -> Vec<String> {
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{} could not be read: {error}", directory.display()));
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!(
                "an entry of {} could not be read: {error}",
                directory.display()
            )
        });
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    names
}

/// The same, where an absent directory is a valid answer and nothing else is.
///
/// The name is asked about before the directory is read, because reading one follows a link: a
/// link whose target is gone answers "not found", and a listing built on that reports an empty
/// directory although the name is there and something may well have written through it.
///
/// # Panics
///
/// Panics when the name holds anything other than a directory, and when the directory or any entry
/// in it cannot be read.
#[must_use]
pub fn names_in_if_any(directory: &Path) -> Vec<String> {
    match std::fs::symlink_metadata(directory) {
        Ok(found) if found.is_dir() => names_in(directory),
        Ok(found) => panic!(
            "{} is {:?} rather than a directory",
            directory.display(),
            found.file_type()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!(
            "whether {} is there could not be established: {error}",
            directory.display()
        ),
    }
}

/// The fixture document the restricted-profile tests are built from.
#[must_use]
pub fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/project")
        .canonicalize()
        .expect("the fixture directory is beside the crate")
}

/// Reads `fixtures/project/restricted-profile.json`.
#[must_use]
pub fn restricted_profile_fixture() -> serde_json::Value {
    let path = fixture_path().join("restricted-profile.json");
    let text = std::fs::read_to_string(&path).expect("the restricted-profile fixture is readable");
    serde_json::from_str(&text).expect("the restricted-profile fixture is one JSON document")
}

/// A host tree with the project service open on it.
///
/// Its directories are under the platform's temporary directory, which is on the internal disk, so
/// nothing a test starts reaches the workspace.
pub struct Fixture {
    host: TempHost,
    service: ProjectService,
    work: tempfile::TempDir,
}

impl Fixture {
    /// Opens a fresh host and service.
    #[must_use]
    pub fn create() -> Self {
        let host = TempHost::create();
        let service = ProjectService::open(&host.environment()).expect("the project service opens");
        let work = tempfile::TempDir::new().expect("a working directory on the internal disk");
        Self {
            host,
            service,
            work,
        }
    }

    /// Opens a fresh host whose credential brokers are the ones a test supplies.
    #[must_use]
    pub fn with_brokers(brokers: BrokerRegistry) -> Self {
        let mut fixture = Self::create();
        fixture.service.set_brokers(brokers);
        fixture
    }

    /// Runs something between the reading of a repository's configuration and each Git child.
    pub fn interpose(&mut self, interposition: kr_project::git::Interposition) {
        self.service.interpose(interposition);
    }

    /// Returns the service.
    #[must_use]
    pub const fn service(&self) -> &ProjectService {
        &self.service
    }

    /// Returns the host tree, so a test can reopen the service on the same environment.
    #[must_use]
    pub const fn host(&self) -> &TempHost {
        &self.host
    }

    /// Reopens the service on the same environment, the way a replacement daemon does.
    #[must_use]
    pub fn reopen(&self) -> ProjectService {
        ProjectService::open(&self.host.environment()).expect("a replacement service opens")
    }

    /// Returns the directory repositories are built in.
    #[must_use]
    pub fn work(&self) -> &Path {
        self.work.path()
    }

    /// Returns the environment this host owns.
    #[must_use]
    pub fn environment_id(&self) -> kr_protocol::ids::EnvironmentId {
        self.host.environment_id()
    }
}

/// A broker whose programs are the ones installed Git ships with.
///
/// The tests that clone over a network transport need a broker, and what makes one approved is
/// that its programs are in Git's own helper directory. A host without them says so rather than
/// failing a test for the wrong reason.
#[must_use]
pub fn installed_broker() -> BrokerRegistry {
    let git = kr_project::git::GitProgram::discover().expect("installed Git");
    BrokerRegistry::discover(&git)
}

/// A broker with both programs named, for a test that never reaches either.
#[must_use]
pub fn named_broker() -> BrokerRegistry {
    let git = kr_project::git::GitProgram::discover().expect("installed Git");
    BrokerRegistry::from_brokers(vec![BrokerRegistry::broker(
        OS_SECRET_STORE,
        Some(git.exec_path().join("git-credential-cache")),
        Some(std::path::PathBuf::from("/usr/bin/ssh")),
    )])
}

/// A broker that lends an ssh program and no credential helper, which is the ordinary Linux host.
///
/// Git ships `git-credential-osxkeychain` on Apple platforms and `git-credential-libsecret` is a
/// separate package on most Linux distributions, so a host that has ssh and no credential helper is
/// the common case rather than a contrived one.
#[must_use]
pub fn broker_without_a_credential_helper() -> BrokerRegistry {
    BrokerRegistry::from_brokers(vec![BrokerRegistry::broker(
        OS_SECRET_STORE,
        None,
        Some(std::path::PathBuf::from("/usr/bin/ssh")),
    )])
}

/// Runs installed Git directly, for building a fixture.
///
/// No user or system configuration is read, so a signing key or a template directory in the
/// operator's own files cannot change what a fixture is.
///
/// # Panics
///
/// Panics when the invocation fails, which in a test means the fixture could not be built.
pub fn git_raw<I, S>(directory: &Path, arguments: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let arguments: Vec<std::ffi::OsString> = arguments
        .into_iter()
        .map(|argument| argument.as_ref().to_owned())
        .collect();
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .arg("-c")
        .arg("user.name=KalaReach Fixture")
        .arg("-c")
        .arg("user.email=fixture@example.invalid")
        .arg("-c")
        .arg("commit.gpgSign=false")
        .arg("-c")
        .arg("init.defaultBranch=main")
        // A fixture builds a submodule from a path on this machine, which is the transport Git
        // refuses by default. Nothing here reaches a network.
        .arg("-c")
        .arg("protocol.file.allow=always")
        .args(&arguments)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .env("LC_ALL", "C")
        .output()
        .expect("installed Git runs");
    assert!(
        output.status.success(),
        "git {arguments:?} in {} failed: {}",
        directory.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Builds an ordinary repository with one commit.
///
/// # Panics
///
/// Panics when the repository cannot be built.
pub fn ordinary_repository(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    std::fs::create_dir_all(&path).expect("a directory for the repository");
    git_raw(&path, ["init", "--initial-branch=main"]);
    write(&path, "README.md", "a repository\n");
    write(&path, "src/lib.rs", "pub fn answer() -> u32 { 42 }\n");
    git_raw(&path, ["add", "-A"]);
    git_raw(&path, ["commit", "-m", "the first commit"]);
    path
}

/// Creates a named pipe nothing ever writes to, and returns its path.
///
/// Opening one for reading blocks until a writer arrives, so a child pointed at one cannot finish
/// on its own. That is what a test of the host's deadline needs: a child whose only way out is the
/// host ending it, rather than a real command racing a bound it might beat on a fast machine.
///
/// # Panics
///
/// Panics when the pipe cannot be created, and when what was created is not one.
#[cfg(unix)]
#[must_use]
pub fn pipe_nothing_writes_to(parent: &Path, name: &str) -> PathBuf {
    use std::os::unix::fs::FileTypeExt;

    let path = parent.join(name);
    let made = Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo runs on this host");
    assert!(made.success(), "a named pipe at {}", path.display());
    let kind = std::fs::symlink_metadata(&path)
        .expect("the pipe this test just made")
        .file_type();
    assert!(
        kind.is_fifo(),
        "{} is a named pipe rather than {kind:?}",
        path.display()
    );
    path
}

/// Writes one file, creating the directories above it.
///
/// # Panics
///
/// Panics when the file cannot be written.
pub fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("the directories above the file");
    }
    std::fs::write(&path, contents).expect("the file is written");
}

/// Writes one file of bytes, creating the directories above it.
///
/// # Panics
///
/// Panics when the file cannot be written.
pub fn write_bytes(root: &Path, relative: &str, contents: &[u8]) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("the directories above the file");
    }
    std::fs::write(&path, contents).expect("the file is written");
}

/// A repository with every execution-capable thing the fixture names planted in it.
pub struct Planted {
    /// Where the repository is.
    pub path: PathBuf,
    /// Where a helper that ran would write.
    pub sentinels: PathBuf,
    /// The configuration keys that were planted and must be neutralised.
    pub neutralised: Vec<String>,
}

impl Planted {
    /// Returns the names of every sentinel that exists, which must be none.
    ///
    /// # Panics
    ///
    /// Panics when the sentinel directory cannot be read for a reason other than its absence.
    #[must_use]
    pub fn escaped(&self) -> Vec<String> {
        // The directory itself is required, not merely its emptiness: the fixture leaves it there
        // because a marker cannot create it, and a directory that has gone is a fixture whose
        // evidence has gone with it.
        names_in(&self.sentinels)
    }
}

/// Builds a repository with every neutralised entry of the fixture planted in it.
///
/// The marker program is copied in with its sentinel directory substituted, each configuration key
/// is set to invoke it with the name of its entry, every hook the fixture lists is written twice
/// (in the repository's own hook directory and in the one its `core.hooksPath` names), and the
/// attributes that name the drivers are committed.
///
/// # Panics
///
/// Panics when the repository cannot be built.
pub fn planted_repository(parent: &Path, name: &str, include_refused: bool) -> Planted {
    let fixture = restricted_profile_fixture();
    let path = ordinary_repository(parent, name);
    let sentinels = parent.join(format!("{name}-sentinels"));
    let marker = plant_marker(parent, name, &sentinels);
    // The attributes that name the drivers are committed *before* the configuration is planted,
    // because the fixture builder runs ordinary Git: a filter or a hook the builder triggered
    // would be a sentinel the service never asked for.
    let attributes: Vec<&str> = fixture["attributes"]
        .as_array()
        .expect("the fixture lists attributes")
        .iter()
        .map(|line| line.as_str().expect("each attribute is a line"))
        .collect();
    write(
        &path,
        ".gitattributes",
        &format!("{}\n", attributes.join("\n")),
    );
    git_raw(&path, ["add", "-A"]);
    git_raw(
        &path,
        ["commit", "-m", "the attributes that name the drivers"],
    );
    let mut neutralised = Vec::new();
    for entry in fixture["neutralised"]
        .as_array()
        .expect("the fixture lists its neutralised entries")
    {
        let key = entry["key"].as_str().expect("each entry names its key");
        let sentinel = entry["sentinel"]
            .as_str()
            .expect("each entry names its sentinel");
        neutralised.push(key.to_owned());
        let value = match key {
            // A hook directory and a template directory are directories rather than programs, so
            // they are planted as directories whose hooks are the marker.
            "core.hooksPath" => {
                let hooks = plant_hooks(parent, &format!("{name}-hooks-path"), &marker, &fixture);
                hooks.display().to_string()
            }
            "init.templateDir" => {
                let template = parent.join(format!("{name}-template"));
                let hooks = template.join("hooks");
                std::fs::create_dir_all(&hooks).expect("a template hook directory");
                for hook in fixture["hooks"]
                    .as_array()
                    .expect("the fixture lists hooks")
                {
                    let hook = hook.as_str().expect("each hook is a name");
                    copy_marker(&marker, &hooks.join(hook), &format!("template-hook-{hook}"));
                }
                template.display().to_string()
            }
            _ => format!("{} {sentinel}", marker.display()),
        };
        git_raw(&path, ["config", "--local", "--", key, &value]);
    }
    if include_refused {
        for entry in fixture["refused"]
            .as_array()
            .expect("the fixture lists its refused entries")
        {
            let key = entry["key"].as_str().expect("each entry names its key");
            let value = entry["value"].as_str().expect("each entry names its value");
            git_raw(&path, ["config", "--local", "--", key, value]);
        }
    }
    // The repository's own hook directory, which `core.hooksPath` above already replaces; both are
    // planted so the test proves neither is reached.
    let own_hooks = path.join(".git/hooks");
    std::fs::create_dir_all(&own_hooks).expect("the repository's own hook directory");
    for hook in fixture["hooks"]
        .as_array()
        .expect("the fixture lists hooks")
    {
        let hook = hook.as_str().expect("each hook is a name");
        copy_marker(&marker, &own_hooks.join(hook), &format!("own-hook-{hook}"));
    }
    // Nothing the fixture builder did counts: the sentinel directory starts empty at the moment
    // the service is first asked to do anything, and it stays there, because a marker that has to
    // create it cannot.
    empty_the_sentinels(&sentinels);
    Planted {
        path,
        sentinels,
        neutralised,
    }
}

/// A parent repository holding a submodule whose own configuration plants a filter.
///
/// The submodule's configuration lives in the parent's modules directory, which the parent's own
/// configuration listing does not read: a driver defined there is one the audit cannot see. So the
/// host must never enter a submodule, and this is the fixture that proves it does not.
pub struct PlantedSubmodule {
    /// The parent repository.
    pub parent: PathBuf,
    /// The submodule's path inside it.
    pub submodule_path: String,
    /// Where the submodule's filter would write if it ran.
    pub sentinels: PathBuf,
}

impl PlantedSubmodule {
    /// Returns the names of every sentinel that exists, which must be none.
    ///
    /// # Panics
    ///
    /// Panics when the sentinel directory cannot be read for a reason other than its absence.
    #[must_use]
    pub fn escaped(&self) -> Vec<String> {
        // The directory itself is required, not merely its emptiness: the fixture leaves it there
        // because a marker cannot create it, and a directory that has gone is a fixture whose
        // evidence has gone with it.
        names_in(&self.sentinels)
    }
}

/// Builds a parent repository with a submodule whose own configuration plants a filter.
///
/// The submodule sits at `submodule_path` inside the parent, so a test can choose a path of its
/// own and look for it in what the host says afterwards.
///
/// # Panics
///
/// Panics when the repositories cannot be built.
pub fn planted_submodule(
    parent_directory: &Path,
    name: &str,
    submodule_path: &str,
) -> PlantedSubmodule {
    let sentinels = parent_directory.join(format!("{name}-submodule-sentinels"));
    let marker = plant_marker(parent_directory, &format!("{name}-submodule"), &sentinels);
    // The child, with an attribute that names a filter.
    let child = parent_directory.join(format!("{name}-child"));
    std::fs::create_dir_all(&child).expect("a directory for the child");
    git_raw(&child, ["init", "--initial-branch=main"]);
    write(
        &child, "a.txt", "a
",
    );
    write(
        &child,
        ".gitattributes",
        "* filter=child
",
    );
    git_raw(&child, ["add", "-A"]);
    git_raw(&child, ["commit", "-m", "the child"]);
    // The parent, with the child added as a submodule.
    let parent = ordinary_repository(parent_directory, name);
    git_raw(
        &parent,
        [
            OsStr::new("submodule"),
            OsStr::new("add"),
            OsStr::new("--quiet"),
            child.as_os_str(),
            OsStr::new(submodule_path),
        ],
    );
    git_raw(&parent, ["commit", "-m", "the submodule"]);
    // The filter is configured where the submodule's own repository is, which is inside the
    // parent's modules directory rather than anywhere the parent's configuration names.
    let inside = parent.join(submodule_path);
    git_raw(
        &inside,
        [
            OsStr::new("config"),
            OsStr::new("--local"),
            OsStr::new("--"),
            OsStr::new("filter.child.clean"),
            marker.as_os_str(),
        ],
    );
    git_raw(
        &inside,
        [
            OsStr::new("config"),
            OsStr::new("--local"),
            OsStr::new("--"),
            OsStr::new("filter.child.smudge"),
            marker.as_os_str(),
        ],
    );
    // Something inside the submodule for the filter to be invoked on.
    write(
        &inside,
        "a.txt",
        "changed inside the submodule
",
    );
    empty_the_sentinels(&sentinels);
    PlantedSubmodule {
        parent,
        submodule_path: submodule_path.to_owned(),
        sentinels,
    }
}

/// Plants one execution-capable configuration key on a repository, with a name of this host's
/// choosing rather than one the audit's own spelling would match.
///
/// # Panics
///
/// Panics when the configuration cannot be written.
pub fn plant_named_driver(parent: &Path, repository: &Path, name: &str, key: &str) -> PathBuf {
    let sentinels = parent.join(format!("{name}-sentinels"));
    let marker = plant_marker(parent, name, &sentinels);
    for leaf in ["clean", "smudge"] {
        git_raw(
            repository,
            [
                OsStr::new("config"),
                OsStr::new("--local"),
                OsStr::new("--"),
                OsStr::new(&format!("filter.{key}.{leaf}")),
                marker.as_os_str(),
            ],
        );
    }
    write(
        repository,
        ".gitattributes",
        &format!(
            "* filter={key}
"
        ),
    );
    git_raw(repository, ["add", "-A"]);
    git_raw(repository, ["commit", "-m", "the attribute"]);
    write(
        repository,
        "a.txt",
        "changed after the commit
",
    );
    empty_the_sentinels(&sentinels);
    sentinels
}

/// Copies the marker program out of the fixture with its sentinel directory substituted.
/// Empties the sentinel directory without taking it away.
///
/// The marker records with a shell redirection, which needs no program, but it can only create the
/// directory with `mkdir`, and the restricted profile's `PATH` is `/usr/bin` and Git's own helper
/// directory: on this platform `mkdir` is in `/bin` and is not found there. A fixture that removed
/// the directory would therefore leave a marker that cannot record, and every "no sentinel
/// appeared" assertion would pass whether a helper ran or not. So the directory stays and only what
/// is in it goes.
///
/// # Panics
///
/// Panics when the directory cannot be emptied or read.
pub fn empty_the_sentinels(sentinels: &Path) {
    std::fs::create_dir_all(sentinels).expect("the sentinel directory");
    for name in names_in(sentinels) {
        let path = sentinels.join(&name);
        let found = std::fs::symlink_metadata(&path).expect("what the sentinel directory holds");
        if found.is_dir() {
            std::fs::remove_dir_all(&path).expect("a directory inside the sentinel directory goes");
        } else {
            std::fs::remove_file(&path).expect("a sentinel goes");
        }
    }
    assert_eq!(
        names_in(sentinels),
        Vec::<String>::new(),
        "the sentinel directory starts empty and stays where a marker can write into it"
    );
}

/// Plants the marker program and proves it can record a run into the sentinel directory it is
/// given.
///
/// # Panics
///
/// Panics when the program cannot be written, run, or does not record its own run.
pub fn plant_marker(parent: &Path, name: &str, sentinels: &Path) -> PathBuf {
    let fixture = restricted_profile_fixture();
    let source = fixture["marker_program"][if cfg!(windows) { "windows" } else { "unix" }]
        .as_str()
        .expect("the fixture names its marker program");
    let body = std::fs::read_to_string(fixture_path().join(source))
        .expect("the marker program is readable");
    let body = body.replace("@SENTINELS@", &sentinels.display().to_string());
    let marker = parent.join(format!(
        "{name}-marker{}",
        if cfg!(windows) { ".cmd" } else { ".sh" }
    ));
    std::fs::write(&marker, body).expect("the marker program is written");
    make_executable(&marker);
    prove_the_marker_records(&marker, sentinels);
    marker
}

/// Runs the planted marker once and requires it to leave its evidence.
///
/// Every restricted-profile assertion is "no sentinel appeared", and that is only evidence when a
/// helper which ran *would* have left one. The marker records what it can and exits zero, because a
/// helper that failed the command would hide itself behind an ordinary error; the cost of that is
/// that a marker which could not write looks exactly like a marker that never ran. So the recorder
/// is proved here, in the environment the test will run it in, before any of those assertions means
/// anything: the program is invoked with a name of this helper's own, the file it should have
/// written is required, and it is taken away again so the test starts with nothing.
///
/// # Panics
///
/// Panics when the marker does not record its own run.
fn prove_the_marker_records(marker: &Path, sentinels: &Path) {
    const CONTROL: &str = "the-recorder-itself";

    std::fs::create_dir_all(sentinels).expect("the sentinel directory");
    // A bounded retry, for one race and nothing else. This binary's tests run in threads of one
    // process, and another test's child can be forked while the descriptor this helper wrote the
    // marker through is still open: the child inherits a copy and holds it until its own exec
    // closes it, and Linux refuses to exec a file any process still holds open for writing with
    // ETXTBSY. Nothing about the marker or the product is wrong when that happens, and the window
    // closes as soon as that child execs, so the control run is attempted again for about a second
    // before the error stands. Keeping the retry is what keeps these tests parallel: the
    // alternative is coordinating every write against every child launch in the binary, which
    // costs far more than waiting out a window that closes in milliseconds.
    const ATTEMPTS: usize = 100;
    const BETWEEN: std::time::Duration = std::time::Duration::from_millis(10);

    // With nothing in its environment, which is at least as bare as the one the restricted profile
    // gives a Git child: a marker that records under this records under that.
    let mut attempted = 0;
    let status = loop {
        attempted += 1;
        match Command::new(marker)
            .arg(CONTROL)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .status()
        {
            Ok(status) => break status,
            Err(error)
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy
                    && attempted < ATTEMPTS =>
            {
                std::thread::sleep(BETWEEN);
            }
            Err(error) => {
                panic!("the planted marker runs, after {attempted} attempts: {error:?}");
            }
        }
    };
    assert!(status.success(), "the planted marker exits zero: {status}");
    let recorded = sentinels.join(CONTROL);
    assert!(
        std::fs::symlink_metadata(&recorded).is_ok(),
        "the planted marker records its own run at {}, so that finding no sentinel later is \
         evidence that nothing ran rather than evidence that nothing could be written",
        recorded.display()
    );
    std::fs::remove_file(&recorded).expect("the control the recorder left is taken away again");
}

fn plant_hooks(parent: &Path, name: &str, marker: &Path, fixture: &serde_json::Value) -> PathBuf {
    let hooks = parent.join(name);
    std::fs::create_dir_all(&hooks).expect("a hook directory");
    for hook in fixture["hooks"]
        .as_array()
        .expect("the fixture lists hooks")
    {
        let hook = hook.as_str().expect("each hook is a name");
        copy_marker(marker, &hooks.join(hook), &format!("hooks-path-{hook}"));
    }
    hooks
}

/// Writes one hook that invokes the marker with a name of its own.
fn copy_marker(marker: &Path, destination: &Path, sentinel: &str) {
    let body = if cfg!(windows) {
        format!("@echo off\r\ncall \"{}\" {sentinel}\r\n", marker.display())
    } else {
        format!("#!/bin/sh\nexec \"{}\" {sentinel}\n", marker.display())
    };
    std::fs::write(destination, body).expect("the hook is written");
    make_executable(destination);
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = std::fs::metadata(path)
        .expect("the program's metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).expect("the program is executable");
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

/// A destination request for one name inside a directory.
#[must_use]
pub fn destination(
    environment_id: kr_protocol::ids::EnvironmentId,
    parent: &Path,
    name: &str,
) -> kr_protocol::project::DestinationRequest {
    kr_protocol::project::DestinationRequest {
        environment_id,
        parent_path: parent.display().to_string(),
        name: name.to_owned(),
    }
}

/// The action one test submits its mutation under.
#[must_use]
pub fn action(method: &str, seed: u8) -> kr_project::store::Action {
    kr_project::store::Action {
        actor_id: kr_protocol::ids::ActorId::new("local:test").expect("a valid principal"),
        action_id: kr_protocol::scalars::Uuid::from_bytes([seed; 16]),
        method: method.to_owned(),
        payload_digest: kr_protocol::scalars::Digest256::from_bytes([seed; 32]),
    }
}

/// The principal every test acts as.
#[must_use]
pub fn actor() -> kr_protocol::ids::ActorId {
    kr_protocol::ids::ActorId::new("local:test").expect("a valid principal")
}

/// The policy that copies everything uncommitted into a new workspace.
#[must_use]
pub const fn include_everything() -> kr_protocol::project::InclusionPolicy {
    use kr_protocol::project::InclusionChoice::Include;

    kr_protocol::project::InclusionPolicy {
        dirty_files: Include,
        untracked_files: Include,
        submodules: Include,
        binary_files: Include,
        generated_artefacts: Include,
    }
}

/// The daemon's owner, as the location tests stand it in.
///
/// It issues challenges the way the daemon's ceremony does, keeps them outstanding, and accepts a
/// proof only when it answers a challenge it issued for exactly the enlargement the service
/// presents, carrying the signature [`sign`] makes. Each challenge is consumed once. Grants are the
/// ones a test gives it, and a grant a test revokes is refused as the daemon would refuse it.
#[derive(Debug, Default)]
pub struct TestOwner {
    outstanding: std::sync::Mutex<
        Vec<(
            kr_protocol::pairing::OwnerConfirmationRequest,
            kr_project::policy::Enlargement,
        )>,
    >,
    grants: std::sync::Mutex<
        std::collections::BTreeMap<kr_protocol::ids::GrantId, kr_project::policy::GrantReach>,
    >,
    issued: std::sync::atomic::AtomicU64,
}

/// The signature a test owner's proof carries.
const TEST_SIGNATURE: [u8; 64] = [0x5a; 64];

impl TestOwner {
    /// Adds a grant this owner will say stands.
    pub fn grant_to(
        &self,
        grant_id: kr_protocol::ids::GrantId,
        actions: &[kr_protocol::rights::ActionRight],
    ) {
        self.grants.lock().expect("the grants").insert(
            grant_id,
            kr_project::policy::GrantReach {
                recipient_device_id: kr_protocol::ids::DeviceId::new(grant_id.get()),
                actions: actions.iter().copied().collect(),
            },
        );
    }

    /// Takes a grant away, as a revocation does.
    pub fn revoke(&self, grant_id: kr_protocol::ids::GrantId) {
        self.grants.lock().expect("the grants").remove(&grant_id);
    }

    /// Returns how many challenges this owner has issued.
    #[must_use]
    pub fn issued(&self) -> u64 {
        self.issued.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Returns how many challenges are still outstanding.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.outstanding.lock().expect("the challenges").len()
    }
}

impl kr_project::policy::OwnerAuthority for TestOwner {
    fn challenge(
        &self,
        enlargement: &kr_project::policy::Enlargement,
    ) -> Result<kr_protocol::pairing::OwnerConfirmationRequest, kr_protocol::error::ProtocolError>
    {
        let number = self
            .issued
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .wrapping_add(1);
        let mut identity = [0_u8; 16];
        identity[..8].copy_from_slice(&number.to_be_bytes());
        let request = kr_protocol::pairing::OwnerConfirmationRequest {
            confirmation_id: kr_protocol::ids::ConfirmationId::new(
                kr_protocol::scalars::Uuid::from_bytes(identity),
            ),
            action: kr_protocol::pairing::SensitiveAction::EnlargeGrant,
            action_digest: enlargement.action_digest,
            destination_keys: kr_protocol::scalars::Nullable(None),
            destination_rights: enlargement.rights.clone(),
            host_device_id: kr_protocol::ids::DeviceId::new(
                kr_protocol::scalars::Uuid::from_bytes([0x11; 16]),
            ),
            host_endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes([0x22; 32]),
            nonce: kr_protocol::scalars::Nonce256::from_bytes([0x33; 32]),
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(kr_ipc::now_ms().get() + 120_000),
        };
        self.outstanding
            .lock()
            .expect("the challenges")
            .push((request.clone(), enlargement.clone()));
        Ok(request)
    }

    fn accept(
        &self,
        enlargement: &kr_project::policy::Enlargement,
        proof: &kr_protocol::pairing::OwnerConfirmationProof,
    ) -> Result<(), kr_protocol::error::ProtocolError> {
        let refused = |why: &str| {
            kr_protocol::error::ProtocolError::new(
                kr_protocol::error::ErrorCode::OwnerConfirmationRequired,
                format!("the owner's confirmation does not authorise this: {why}"),
            )
        };
        if proof.signature != kr_protocol::scalars::Signature64::from_bytes(TEST_SIGNATURE) {
            return Err(refused("the signature is not the owner's"));
        }
        let mut outstanding = self.outstanding.lock().expect("the challenges");
        let Some(position) = outstanding
            .iter()
            .position(|(request, _)| request == &proof.request)
        else {
            return Err(refused("no such challenge is outstanding"));
        };
        if &outstanding[position].1 != enlargement
            || proof.request.action_digest != enlargement.action_digest
            || proof.request.destination_rights != enlargement.rights
        {
            return Err(refused("the challenge was issued for something else"));
        }
        outstanding.remove(position);
        Ok(())
    }

    fn grant(
        &self,
        grant_id: kr_protocol::ids::GrantId,
    ) -> Result<kr_project::policy::GrantReach, kr_protocol::error::ProtocolError> {
        self.grants
            .lock()
            .expect("the grants")
            .get(&grant_id)
            .cloned()
            .ok_or_else(|| {
                kr_protocol::error::ProtocolError::new(
                    kr_protocol::error::ErrorCode::PermissionDenied,
                    format!("grant {grant_id} was revoked or has expired"),
                )
            })
    }
}

/// The owner's proof for one challenge.
#[must_use]
pub fn sign(
    request: &kr_protocol::pairing::OwnerConfirmationRequest,
) -> kr_protocol::pairing::OwnerConfirmationProof {
    kr_protocol::pairing::OwnerConfirmationProof {
        request: request.clone(),
        channel: kr_protocol::pairing::ConfirmationChannel::EnrolledPresenceSigner,
        signer_key_id: kr_protocol::scalars::KeyId::from_bytes([0x44; 32]),
        signature: kr_protocol::scalars::Signature64::from_bytes(TEST_SIGNATURE),
    }
}

/// One submission of an action. The same action identifier carries a different payload digest
/// once its proof is added, as a real submission's does.
#[must_use]
pub fn submission(method: &str, seed: u8, proven: bool) -> kr_project::store::Action {
    let mut digest = [seed; 32];
    if proven {
        digest[0] ^= 0x80;
    }
    kr_project::store::Action {
        actor_id: actor(),
        action_id: kr_protocol::scalars::Uuid::from_bytes([seed; 16]),
        method: method.to_owned(),
        payload_digest: kr_protocol::scalars::Digest256::from_bytes(digest),
    }
}

/// Returns the kinds of every event the outbox of one environment's journal holds, in order.
///
/// Read from the file rather than through the service, because what is being established is what
/// a consumer of the outbox would read.
#[must_use]
pub fn outbox(host: &TempHost) -> Vec<(String, String)> {
    let journal = ProjectService::root_of(&host.environment()).join("projects.sqlite");
    let connection = rusqlite::Connection::open(&journal).expect("the journal opens");
    let mut statement = connection
        .prepare("SELECT kind, subject FROM events ORDER BY sequence")
        .expect("the outbox reads");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("the outbox reads")
        .map(|row| row.expect("an event"))
        .collect()
}
