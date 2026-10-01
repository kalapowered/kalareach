//! A native module of the person's own, loaded into the managed Zsh package.
//!
//! Section 7 asks that loading ordinary startup files is not taken for proof that a native module
//! fits the editor, and that an explicitly incompatible module produces a named error and never a
//! false ready state. Both halves are driven here with real modules: two are compiled, as a person
//! compiles one, against the headers of this repository's own Zsh package
//! (`tests/shells/zsh/native-module-abi/`), and each is loaded by a startup file into the packaged
//! shell.
//!
//! The bridge makes its handshake when the editor module is set up, which a shell does on demand:
//! before a startup file that loads the editor first, after one that does not. A module a startup
//! file loads may therefore not be there yet to be judged when the declaration is made. It is judged
//! where qualification completes, after every startup file: the report that the hooks are live lists each dynamic module
//! the shell holds and says whether the running shell provides every name it imports, and the
//! worker's contract decision refuses the session on the first that does not. A module built
//! against a newer editor calls a function this one does not have; the shell loads it without
//! complaint, since it binds lazily, and it would end the shell at the first call that needs the
//! function. A module built against another layout of the same names binds every symbol it
//! imports, and no import check tells it from one built for this editor: that is the limit of the
//! diagnosis, and it is not tested for, because a check of what the diagnosis cannot see would be a
//! claim about it. These cases drive the bridge and the contract decision; the create answer the
//! worker gives is driven by the worker's own suite.
//!
//! The cases drive this tree's built package, which an ordinary run does not have, so they are
//! left out of one. A run that built the packages runs them with `--include-ignored`. Building the
//! modules needs the pinned Zsh archive that `scripts/build-shells.sh` fetched into the package
//! cache, and is done once per package build.

#![cfg(unix)]

mod shellpkg;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kr_shell_integration::contract::events::{BridgeEvent, LoadedModule, ModuleImports};
use kr_shell_integration::contract::qualification::{QualificationReason, ShellKind};
use kr_shell_integration::contract::transport::decide_activated_modules;
use shellpkg::{
    CaseSetup, Package, QualificationCase, Session, StackIndex, package_root, repository_root,
};

/// Where the modules' source, the person's startup file and the build script are.
fn fixture() -> PathBuf {
    repository_root().join("tests/shells/zsh/native-module-abi")
}

/// The one case these tests run, described here rather than in the corpus: it has two outcomes,
/// and the corpus runner asks every case for one.
fn case() -> QualificationCase {
    let mut case: QualificationCase = serde_json::from_value(serde_json::json!({
        "id": "zsh-native-module-abi",
        "shell": "zsh",
        "stack": "native-module-abi",
        "title": "a native module built as a person builds one, against the package's headers",
        "supported": true,
        "requires": [],
        "order": ["user-top", "kr-module-loaded", "user-bottom"],
        "binding": "none",
        "checks": ["identity"],
        "covers": ["KR-REQ-07.87", "KR-REQ-07.88"],
        "home": [{"file": "zshrc", "path": ".zshrc"}]
    }))
    .expect("the case decodes");
    case.directory = fixture();
    case
}

/// The two modules, built once per package build and kept beside the package cache.
///
/// # Panics
///
/// Panics when the modules cannot be built, which is a fault of the fixture or of the machine and
/// not a verdict on the package.
fn built_modules(package: &Package) -> PathBuf {
    static BUILDING: Mutex<()> = Mutex::new(());
    let _one_at_a_time = BUILDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let archive = package.record["build"]["upstream"]["archive"]
        .as_str()
        .expect("the package's record names the archive it was built from");
    let archive = package_root().join("sources").join(archive);
    assert!(
        archive.is_file(),
        "{} is not here; the package build fetches it (scripts/build-shells.sh --zsh)",
        archive.display()
    );
    // Named by the package build and by the fixture that builds the modules, so a change to
    // either builds them again.
    let fixture_digest = {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        for file in ["build-modules.sh", "kr_user.c"] {
            digest.update(std::fs::read(fixture().join(file)).expect("the fixture reads"));
        }
        digest
            .finalize()
            .iter()
            .take(6)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let output = package_root()
        .join("module-abi")
        .join(format!("{}-{fixture_digest}", package.identity));
    let built = std::process::Command::new("bash")
        .arg(fixture().join("build-modules.sh"))
        .arg("--archive")
        .arg(&archive)
        .arg("--output")
        .arg(&output)
        .output()
        .expect("bash runs the build script");
    assert!(
        built.status.success(),
        "the modules did not build:\n{}{}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );
    output
}

/// A home whose startup file loads `module`, with that module in the directory it searches.
fn home_loading(package: &Package, modules: &Path, module: &str) -> CaseSetup {
    let setup = home_with_modules(package, &[module]);
    std::fs::copy(
        modules.join(format!("{module}.so")),
        setup.home.join("modules").join(format!("{module}.so")),
    )
    .expect("the module goes where the shell searches");
    setup
}

/// A home whose startup file loads each of `names`, from the directory the person's module path
/// puts ahead of the shell's own.
fn home_with_modules(package: &Package, names: &[&str]) -> CaseSetup {
    let stacks = StackIndex {
        platform: String::new(),
        lock_sha256: String::new(),
        stacks: Vec::new(),
    };
    let mut setup = CaseSetup::prepare(&case(), package, &stacks);
    std::fs::create_dir_all(setup.home.join("modules")).expect("a module directory in the home");
    setup
        .environment
        .push(("KR_TEST_USER_MODULES".to_owned(), names.join(" ")));
    setup
}

/// The dynamic modules a session's report of its hooks lists, or why it does not.
///
/// # Panics
///
/// Panics when the shell reports neither, which is a fault of the package under test.
fn activation_report(session: &mut Session) -> Vec<LoadedModule> {
    let (_, event) = session.expect_event("the report that the hooks are live", |event| {
        matches!(event, BridgeEvent::HooksActivated(_))
    });
    let BridgeEvent::HooksActivated(activated) = event else {
        unreachable!("the wait accepts nothing else")
    };
    activated.modules
}

/// What the shell said when a module the home's startup file loaded was refused, for a failure that
/// needs to say why.
fn refusals(setup: &CaseSetup) -> String {
    std::fs::read_to_string(setup.home.join("module-error")).unwrap_or_default()
}

fn module<'a>(modules: &'a [LoadedModule], name: &str) -> &'a LoadedModule {
    modules
        .iter()
        .find(|module| module.name == name)
        .unwrap_or_else(|| panic!("the report lists no module {name}: {modules:?}"))
}

/// KR-REQ-07.87, KR-REQ-07.88: the control. A module built for the package's editor loads, the
/// report says it binds, and the contract lets the session qualify.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built"]
fn a_module_built_for_the_packages_editor_binds_and_the_session_may_qualify() {
    let package = Package::built(ShellKind::Zsh);
    let modules = built_modules(&package);
    let setup = home_loading(&package, &modules, "kr_user_compatible");

    let mut session = Session::start_for(&package, &case(), &setup);
    let listed = activation_report(&mut session);
    assert_eq!(
        setup.recorded_order(),
        ["user-top", "kr-module-loaded", "user-bottom"],
        "the shell loaded the person's module before the integration went live: {}",
        refusals(&setup)
    );
    let ours = module(&listed, "kr_user_compatible");
    assert_eq!(ours.imports, ModuleImports::Bound);
    assert!(
        Path::new(&ours.path).starts_with(setup.home.join("modules").canonicalize().unwrap()),
        "the report says where the shell found it: {}",
        ours.path
    );
    assert_eq!(decide_activated_modules("zle-5.9", &listed), Ok(()));
}

/// KR-REQ-07.87, KR-REQ-07.88: a module built against a newer editor calls a function this one
/// does not have. The shell loads it, the report names what is missing, and the contract refuses
/// the session with the named reason.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built"]
fn a_module_that_needs_what_the_editor_lacks_is_named_in_the_report_and_refused() {
    let package = Package::built(ShellKind::Zsh);
    let modules = built_modules(&package);
    let setup = home_loading(&package, &modules, "kr_user_newer");

    let mut session = Session::start_for(&package, &case(), &setup);
    let listed = activation_report(&mut session);
    // The shell loaded it: the loader had nothing to object to, which is the false ready state the
    // diagnosis exists to prevent.
    assert_eq!(
        setup.recorded_order(),
        ["user-top", "kr-module-loaded", "user-bottom"],
        "the module loaded, since the loader binds lazily: {}",
        refusals(&setup)
    );
    assert_eq!(
        module(&listed, "kr_user_newer").imports,
        ModuleImports::Missing("zle_abi_newer_entry".to_owned())
    );
    let refused = decide_activated_modules("zle-5.9", &listed)
        .expect_err("a session with a module that cannot bind is not qualified");
    assert_eq!(refused.reason, QualificationReason::ModuleTreeUnsupported);
    assert_eq!(
        refused.error.message,
        "module kr_user_newer imports zle_abi_newer_entry, which this reader (zle-5.9) does not \
         provide"
    );
}

/// A module that imports from a package module is judged by whether that module is loaded when the
/// hooks go live: the shell does not load a module because another imports a name from it, so a
/// call into a module that is not there ends the shell, and the session is refused by name. Loaded
/// first, as a startup file that needs it loads it, the same module binds.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built"]
fn a_module_that_imports_from_a_package_module_is_judged_by_whether_that_module_is_loaded() {
    let package = Package::built(ShellKind::Zsh);
    let modules = built_modules(&package);

    let setup = home_loading(&package, &modules, "kr_user_lazy");
    let mut session = Session::start_for(&package, &case(), &setup);
    let listed = activation_report(&mut session);
    assert_eq!(
        module(&listed, "kr_user_lazy").imports,
        ModuleImports::Missing("asklist".to_owned()),
        "the provider is not loaded, and the module would end the shell at its first call"
    );
    let refused = decide_activated_modules("zle-5.9", &listed)
        .expect_err("a module that imports what is not there is not qualified");
    assert_eq!(refused.reason, QualificationReason::ModuleTreeUnsupported);
    drop(session);

    let setup = home_with_modules(&package, &["zsh/complist", "kr_user_lazy"]);
    std::fs::copy(
        modules.join("kr_user_lazy.so"),
        setup.home.join("modules/kr_user_lazy.so"),
    )
    .expect("the module goes where the shell searches");
    let mut session = Session::start_for(&package, &case(), &setup);
    let listed = activation_report(&mut session);
    assert_eq!(
        module(&listed, "kr_user_lazy").imports,
        ModuleImports::Bound,
        "the provider is loaded: {}",
        refusals(&setup)
    );
    assert_eq!(decide_activated_modules("zle-5.9", &listed), Ok(()));
}

/// A name a module imports weakly is one it is content to lose, and is not judged.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built"]
fn a_module_that_only_weakly_imports_a_missing_name_binds() {
    let package = Package::built(ShellKind::Zsh);
    let modules = built_modules(&package);
    let setup = home_loading(&package, &modules, "kr_user_weak");

    let mut session = Session::start_for(&package, &case(), &setup);
    let listed = activation_report(&mut session);
    assert_eq!(
        module(&listed, "kr_user_weak").imports,
        ModuleImports::Bound
    );
    assert_eq!(decide_activated_modules("zle-5.9", &listed), Ok(()));
}

/// A file the loader refuses is the loader's to report: the shell does not hold it, so the report
/// has no entry for it, and the session is not refused for a module that never loaded.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built"]
fn a_file_the_loader_refuses_is_the_loaders_to_report_and_is_not_listed() {
    let package = Package::built(ShellKind::Zsh);
    let setup = home_with_modules(&package, &["kr_wrong_abi"]);
    // A file named like a module, whose contents are not a module in any format the shell loads.
    std::fs::write(setup.home.join("modules/kr_wrong_abi.so"), b"not a module")
        .expect("writes the file");
    let mut session = Session::start_for(&package, &case(), &setup);
    let listed = activation_report(&mut session);
    assert_eq!(
        setup.recorded_order(),
        ["user-top", "kr-module-refused", "user-bottom"]
    );
    assert!(
        listed.iter().all(|module| module.name != "kr_wrong_abi"),
        "a module the loader refused is the loader's to diagnose: {listed:?}"
    );
    assert_eq!(decide_activated_modules("zle-5.9", &listed), Ok(()));
}

/// The shell runs the image it loaded, so that image is what is judged: a configuration that removes
/// the module's file after loading it, or puts another file in its place as an update does, changes
/// nothing about what the shell holds. Loading a module that needs what the editor lacks and then
/// replacing its file with one that does not leaves a shell that will end at the first call, and
/// reading the name again would call it a module that binds.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built"]
fn a_module_is_judged_as_the_shell_loaded_it_and_not_as_its_file_is_now() {
    let package = Package::built(ShellKind::Zsh);
    let modules = built_modules(&package);

    // Removed after it loaded: the module that needs what the editor lacks is still refused.
    let mut setup = home_loading(&package, &modules, "kr_user_newer");
    setup.environment.push((
        "KR_TEST_REMOVE_AFTER_LOAD".to_owned(),
        "kr_user_newer".to_owned(),
    ));
    let mut session = Session::start_for(&package, &case(), &setup);
    let listed = activation_report(&mut session);
    assert_eq!(
        setup.recorded_order(),
        ["user-top", "kr-module-loaded", "user-bottom"],
        "the module loaded before its file was removed: {}",
        refusals(&setup)
    );
    assert!(
        !setup.home.join("modules/kr_user_newer.so").exists(),
        "the startup file removed the module's file"
    );
    assert_eq!(
        module(&listed, "kr_user_newer").imports,
        ModuleImports::Missing("zle_abi_newer_entry".to_owned())
    );
    drop(session);

    // Replaced after it loaded by a module that binds: the one that loaded is the one judged.
    let mut setup = home_loading(&package, &modules, "kr_user_newer");
    std::fs::copy(
        modules.join("kr_user_compatible.so"),
        setup.home.join("replacement.so"),
    )
    .expect("the replacement is in the home");
    setup.environment.push((
        "KR_TEST_REPLACE_AFTER_LOAD".to_owned(),
        "kr_user_newer".to_owned(),
    ));
    let mut session = Session::start_for(&package, &case(), &setup);
    let listed = activation_report(&mut session);
    assert!(
        !setup.home.join("replacement.so").exists(),
        "the startup file put the replacement where the module was: {}",
        refusals(&setup)
    );
    assert_eq!(
        module(&listed, "kr_user_newer").imports,
        ModuleImports::Missing("zle_abi_newer_entry".to_owned()),
        "a replacement that binds was taken for the module that loaded"
    );
    let refused = decide_activated_modules("zle-5.9", &listed)
        .expect_err("the shell holds a module that cannot bind");
    assert_eq!(refused.reason, QualificationReason::ModuleTreeUnsupported);
    drop(session);

    // Replaced by a link into the package's own tree, which is where the package's modules are: the
    // name now finds a module of the package, and the module that loaded is still the one judged.
    let package_tree = PathBuf::from(
        package.record["shell"]["modules"][0]["search_path"]
            .as_str()
            .expect("the record names the package's module directory"),
    );
    let mut setup = home_loading(&package, &modules, "kr_user_newer");
    setup.environment.push((
        "KR_TEST_LINK_AFTER_LOAD".to_owned(),
        "kr_user_newer".to_owned(),
    ));
    setup.environment.push((
        "KR_TEST_LINK_TARGET".to_owned(),
        package_tree
            .join("zsh/complist.so")
            .to_str()
            .expect("a path that is text")
            .to_owned(),
    ));
    let mut session = Session::start_for(&package, &case(), &setup);
    let listed = activation_report(&mut session);
    assert!(
        std::fs::symlink_metadata(setup.home.join("modules/kr_user_newer.so"))
            .is_ok_and(|about| about.file_type().is_symlink()),
        "the startup file put a link where the module was: {}",
        refusals(&setup)
    );
    assert_eq!(
        module(&listed, "kr_user_newer").imports,
        ModuleImports::Missing("zle_abi_newer_entry".to_owned()),
        "a link into the package's tree made the module the package's"
    );
    let refused = decide_activated_modules("zle-5.9", &listed)
        .expect_err("the shell holds a module that cannot bind");
    assert_eq!(refused.reason, QualificationReason::ModuleTreeUnsupported);
    drop(session);

    // The other way, the control: a module that binds is not refused for what replaces its file.
    let mut setup = home_loading(&package, &modules, "kr_user_compatible");
    std::fs::copy(
        modules.join("kr_user_newer.so"),
        setup.home.join("replacement.so"),
    )
    .expect("the replacement is in the home");
    setup.environment.push((
        "KR_TEST_REPLACE_AFTER_LOAD".to_owned(),
        "kr_user_compatible".to_owned(),
    ));
    let mut session = Session::start_for(&package, &case(), &setup);
    let listed = activation_report(&mut session);
    assert_eq!(
        module(&listed, "kr_user_compatible").imports,
        ModuleImports::Bound
    );
    assert_eq!(decide_activated_modules("zle-5.9", &listed), Ok(()));
}

/// A copy of the editor that a person puts first on their module path is not the package's: where
/// the shell sets the editor up only when a startup file asks, that copy is the editor, and a module
/// beside it is not the package's for being there.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built"]
fn a_copy_of_the_editor_does_not_make_the_modules_beside_it_the_packages() {
    let package = Package::built(ShellKind::Zsh);
    let modules = built_modules(&package);
    let package_tree = PathBuf::from(
        package.record["shell"]["modules"][0]["search_path"]
            .as_str()
            .expect("the record names the package's module directory"),
    );
    let setup = home_loading(&package, &modules, "kr_user_newer");
    std::fs::create_dir_all(setup.home.join("modules/zsh")).expect("a directory");
    std::fs::copy(
        package_tree.join("zsh/zle.so"),
        setup.home.join("modules/zsh/zle.so"),
    )
    .expect("the editor is copied beside the module");

    let mut session = Session::start_for(&package, &case(), &setup);
    let listed = activation_report(&mut session);
    assert_eq!(
        module(&listed, "kr_user_newer").imports,
        ModuleImports::Missing("zle_abi_newer_entry".to_owned()),
        "a module beside a copy of the editor was taken for the package's"
    );
    assert_eq!(
        decide_activated_modules("zle-5.9", &listed)
            .expect_err("the shell holds a module that cannot bind")
            .reason,
        QualificationReason::ModuleTreeUnsupported
    );
}

/// Every module of the package's own tree binds when it is the only one loaded. A module that
/// imported a name from one that was not loaded would be refused with the session, since every
/// module the shell holds is judged: the package's own are not exempt, and this holds them to it.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built"]
fn each_of_the_packages_own_modules_binds_when_it_is_the_only_one_loaded() {
    let package = Package::built(ShellKind::Zsh);
    let tree = PathBuf::from(
        package.record["shell"]["modules"][0]["search_path"]
            .as_str()
            .expect("the record names the package's module directory"),
    );
    let mut names = Vec::new();
    collect_modules(&tree, &tree, &mut names);
    names.retain(|name| name != "zsh/zle");
    assert!(
        names.len() >= 20,
        "the package's module tree holds {names:?}"
    );
    for name in &names {
        let setup = home_with_modules(&package, &[name.as_str()]);
        let mut session = Session::start_for(&package, &case(), &setup);
        let listed = activation_report(&mut session);
        assert_eq!(
            setup.recorded_order(),
            ["user-top", "kr-module-loaded", "user-bottom"],
            "{name} did not load: {}",
            refusals(&setup)
        );
        for held in &listed {
            assert_eq!(
                held.imports,
                ModuleImports::Bound,
                "with {name} loaded, {} was not judged to bind",
                held.name
            );
        }
        assert_eq!(
            decide_activated_modules("zle-5.9", &listed),
            Ok(()),
            "{name}"
        );
    }
}

/// Every module of the package's own tree, loaded from a directory the person's module path puts
/// ahead of it, is judged as the person's own would be, and every one of them binds. This is the
/// control that the diagnosis does not refuse what is built for the editor: the modules are real,
/// dozens of them, and they import all that a module of the shell's own kind imports.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built"]
fn the_packages_own_modules_loaded_from_elsewhere_all_bind() {
    let package = Package::built(ShellKind::Zsh);
    let tree = PathBuf::from(
        package.record["shell"]["modules"][0]["search_path"]
            .as_str()
            .expect("the record names the package's module directory"),
    );
    let mut names = Vec::new();
    collect_modules(&tree, &tree, &mut names);
    // The editor itself is already loaded, and what is loaded from the shell's own directory is
    // not what this is about.
    names.retain(|name| name != "zsh/zle");
    assert!(
        names.len() >= 20,
        "the package's module tree holds {names:?}"
    );
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let setup = home_with_modules(&package, &names);
    copy_tree(&tree, &setup.home.join("modules"));
    // The editor the shell runs is the one its module path finds first. Where the shell sets it up
    // only when a startup file asks, after that file has put the home's directory first, a copy of
    // it here would be the editor the shell runs; a copy of the editor has a test of its own, and
    // this one keeps the package's.
    std::fs::remove_file(setup.home.join("modules/zsh/zle.so"))
        .expect("the copy of the editor goes, so the package's own is loaded");
    warm(&package, &setup, &names);

    let mut session = Session::start_for(&package, &case(), &setup);
    let listed = activation_report(&mut session);
    let loaded = setup
        .recorded_order()
        .iter()
        .filter(|line| *line == "kr-module-loaded")
        .count();
    assert!(
        loaded >= 20,
        "only {loaded} of {} modules loaded, so the control judged too few: {:?} {}",
        names.len(),
        setup.recorded_order(),
        refusals(&setup)
    );
    // Each module that loaded is in the report, from the home's own directory, and binds. A
    // control that passed with an empty list would prove nothing.
    let home_modules = setup
        .home
        .join("modules")
        .canonicalize()
        .expect("the directory is there");
    let judged = listed
        .iter()
        .filter(|module| Path::new(&module.path).starts_with(&home_modules))
        .count();
    // What the shell held before the startup file ran came from the package's own directory, and a
    // `zmodload` of it changed nothing, so it is not the person's and is not in the report.
    let preloaded: Vec<String> = std::fs::read_to_string(setup.home.join("preloaded"))
        .expect("the startup file recorded what the shell already held")
        .lines()
        .filter_map(|line| line.strip_prefix("zmodload ").map(str::to_owned))
        .collect();
    let expected = names
        .iter()
        .filter(|name| !preloaded.iter().any(|held| held == *name))
        .count();
    assert!(
        judged == expected,
        "the report judged {judged} of the {expected} modules that loaded from the home \
         (already held: {preloaded:?}): {listed:?}"
    );
    for module in &listed {
        assert_eq!(
            module.imports,
            ModuleImports::Bound,
            "a module of the package's own tree was not judged to bind: {module:?}"
        );
    }
    assert_eq!(decide_activated_modules("zle-5.9", &listed), Ok(()));
}

/// Loads each of `names` once in a shell of its own, where nothing is timed. The operating system
/// checks every newly written executable the first time it is loaded, and that takes seconds for
/// each of the dozens of copies here, which a session's own deadline is no place to spend.
fn warm(package: &Package, setup: &CaseSetup, names: &[&str]) {
    let script = format!(
        "module_path=({}/modules $module_path); for module in {}; do zmodload $module; done",
        setup.home.display(),
        names.join(" ")
    );
    let warmed = std::process::Command::new(&package.executable)
        .args(["-f", "-c", &script])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("the shell starts");
    assert!(
        warmed.status.success() || !warmed.stderr.is_empty(),
        "the shell that warms the copies did not run"
    );
}

/// The names, as `zmodload` takes them, of every module under `directory`.
fn collect_modules(root: &Path, directory: &Path, names: &mut Vec<String>) {
    let mut entries: Vec<_> = std::fs::read_dir(directory)
        .expect("the module directory reads")
        .map(|entry| entry.expect("an entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_modules(root, &path, names);
        } else if path.extension().is_some_and(|extension| extension == "so") {
            let relative = path.strip_prefix(root).expect("under the root");
            names.push(relative.with_extension("").to_string_lossy().into_owned());
        }
    }
}

/// Copies `from` to `to`, directories and files.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("the directory reads") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("the file copies");
        }
    }
}
