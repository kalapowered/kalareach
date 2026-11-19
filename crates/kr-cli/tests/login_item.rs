//! `kr host login-item status`, `install` and `remove`, run as the commands a person types.
//!
//! Every run gets a home, the installation's two roots, a temporary directory and a layout of its
//! own on the internal disk: a copy of `kr` beside a stand-in `kr-controller` that only appends a
//! line to a file, so nothing here starts a daemon. The environment is cleared and holds exactly
//! `HOME`, a `PATH` of the system's directories (a stand-in folder first on Linux), both roots,
//! `TMPDIR` and, on Linux, `XDG_CONFIG_HOME` inside the home. No case touches a real home, a
//! launch agent, a login item or a service manager.

mod support;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod written {
    use super::support;

    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const MARKER: &str = "login item: ";

    /// One lock for every copy of a program and every start of a process in this test program. A
    /// process started while another thread holds a copy of `kr` open for writing keeps that
    /// descriptor until it runs its own program, and running the copy then fails with "text file
    /// busy".
    static STARTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn spawn_lock() -> std::sync::MutexGuard<'static, ()> {
        STARTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    trait Started {
        fn output_locked(&mut self) -> std::io::Result<std::process::Output>;
        fn spawn_locked(&mut self) -> std::io::Result<std::process::Child>;
    }

    impl Started for Command {
        fn output_locked(&mut self) -> std::io::Result<std::process::Output> {
            let _held = spawn_lock();
            self.output()
        }

        fn spawn_locked(&mut self) -> std::io::Result<std::process::Child> {
            let _held = spawn_lock();
            self.spawn()
        }
    }

    struct Setup {
        _root: tempfile::TempDir,
        root: PathBuf,
        home: PathBuf,
        state: PathBuf,
        runtime: PathBuf,
        bin: PathBuf,
        stub_log: PathBuf,
    }

    impl Setup {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("a directory on the internal disk");
            let base = std::fs::canonicalize(root.path()).expect("the directory resolves");
            let home = base.join("home");
            let bin = base.join("bin");
            for directory in [&home, &bin, &base.join("tmp")] {
                std::fs::create_dir_all(directory).expect("a directory");
            }
            let layout = Self {
                _root: root,
                root: base.clone(),
                home,
                state: base.join("s"),
                runtime: base.join("r"),
                stub_log: base.join("stub-ran"),
                bin,
            };
            layout.layout(&layout.bin);
            layout
        }

        /// A `kr` copy and a stand-in `kr-controller` beside it in `directory`.
        fn layout(&self, directory: &Path) {
            std::fs::create_dir_all(directory).expect("a directory");
            let target = directory.join("kr");
            {
                let _held = spawn_lock();
                std::fs::copy(support::kr(), &target).expect("a copy of kr");
            }
            std::fs::write(
                directory.join("kr-controller"),
                format!("#!/bin/sh\necho started >> '{}'\n", self.stub_log.display()),
            )
            .expect("the stand-in");
            std::fs::set_permissions(
                directory.join("kr-controller"),
                std::fs::Permissions::from_mode(0o755),
            )
            .expect("a mode");
        }

        fn command_in(&self, kr: &Path, home: &Path, arguments: &[&str]) -> Command {
            let mut command = Command::new(kr);
            command
                .args(arguments)
                .env_clear()
                .env("HOME", home)
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .env("KR_STATE_DIR", &self.state)
                .env("KR_RUNTIME_DIR", &self.runtime)
                .env("TMPDIR", self.root.join("tmp"))
                .current_dir(&self.root)
                .stdin(std::process::Stdio::null());
            #[cfg(target_os = "linux")]
            command.env("XDG_CONFIG_HOME", home.join(".config"));
            command
        }

        fn run_with(&self, kr: &Path, home: &Path, arguments: &[&str]) -> std::process::Output {
            self.command_in(kr, home, arguments)
                .output_locked()
                .expect("kr runs")
        }

        fn run(&self, arguments: &[&str]) -> std::process::Output {
            self.run_with(&self.bin.join("kr"), &self.home, arguments)
        }

        /// Runs `kr host login-item <argument>` and requires success; returns what it printed.
        fn ok(&self, argument: &str) -> String {
            let output = self.run(&["host", "login-item", argument]);
            assert!(
                output.status.success(),
                "kr host login-item {argument} succeeds: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).into_owned()
        }

        /// Runs `kr host login-item <argument>`, requires failure, and returns what it said.
        fn refused(&self, argument: &str) -> String {
            let output = self.run(&["host", "login-item", argument]);
            assert!(
                !output.status.success(),
                "kr host login-item {argument} is refused"
            );
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        }

        fn directory(&self, home: &Path) -> PathBuf {
            if cfg!(target_os = "macos") {
                home.join("Library/LaunchAgents")
            } else {
                home.join(".config/autostart")
            }
        }

        /// The login item's file in `home`, when there is one.
        fn item_in(&self, home: &Path) -> Option<PathBuf> {
            std::fs::read_dir(self.directory(home))
                .ok()?
                .flatten()
                .map(|entry| entry.path())
                .find(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("kr-desktop-host-"))
                })
        }

        fn item(&self) -> PathBuf {
            self.item_in(&self.home)
                .expect("the login item's file is there")
        }

        fn state_dir(&self) -> Option<PathBuf> {
            let environments = std::fs::read_dir(self.state.join("environments")).ok()?;
            environments.flatten().map(|entry| entry.path()).next()
        }

        fn record_path(&self) -> Option<PathBuf> {
            self.state_dir()
                .map(|directory| directory.join("desktop-host-login.json"))
        }

        fn record(&self) -> serde_json::Value {
            let path = self.record_path().expect("a state directory");
            serde_json::from_slice(&std::fs::read(path).expect("a record"))
                .expect("a record in JSON")
        }

        fn record_bytes(&self) -> Option<Vec<u8>> {
            self.record_path().and_then(|path| std::fs::read(path).ok())
        }

        fn stub_ran(&self) -> bool {
            self.stub_log.exists()
        }

        /// Every file under the home, the roots and the layout's temporary directory, by path.
        fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
            self.snapshot_with(&[])
        }

        /// The same, and every file under each of `homes` as well.
        fn snapshot_with(&self, homes: &[&Path]) -> BTreeMap<PathBuf, Vec<u8>> {
            let mut found = BTreeMap::new();
            for root in [&self.home, &self.state, &self.runtime] {
                collect(root, &mut found);
            }
            for root in homes {
                collect(root, &mut found);
            }
            found
        }
    }

    fn collect(directory: &Path, found: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).expect("metadata");
            if metadata.is_dir() {
                found.insert(path.clone(), b"<directory>".to_vec());
                collect(&path, found);
            } else if metadata.file_type().is_symlink() {
                found.insert(path, b"<link>".to_vec());
            } else {
                found.insert(path, std::fs::read(entry.path()).unwrap_or_default());
            }
        }
    }

    fn last_line(text: &str) -> &str {
        text.lines().last().unwrap_or_default()
    }

    fn status_word(setup: &Setup) -> String {
        let output = setup.run(&["--json", "host", "login-item", "status"]);
        assert!(output.status.success(), "status succeeds");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        value["state"].as_str().expect("a state").to_owned()
    }

    #[cfg(target_os = "macos")]
    fn read_vector(file: &Path) -> Vec<String> {
        let output = Command::new("/usr/bin/plutil")
            .args(["-convert", "json", "-o", "-"])
            .arg(file)
            .output_locked()
            .expect("plutil reads a file of the test's own tree");
        assert!(output.status.success(), "plutil reads the file");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        value["ProgramArguments"]
            .as_array()
            .expect("ProgramArguments")
            .iter()
            .map(|item| item.as_str().expect("a string").to_owned())
            .collect()
    }

    #[cfg(target_os = "linux")]
    fn read_vector(file: &Path) -> Vec<String> {
        let script = "import json, sys\nimport gi\ngi.require_version('GLib', '2.0')\nfrom gi.repository import GLib\nfor line in open(sys.argv[1], encoding='utf-8').read().split('\\n'):\n    if line.startswith('Exec='):\n        print(json.dumps(GLib.shell_parse_argv(line[5:])[1], ensure_ascii=False))\n";
        let output = Command::new("python3")
            .args(["-c", script])
            .arg(file)
            .output_locked()
            .expect(
                "python3 with GLib is installed: this case reads the entry with GLib's own parser",
            );
        assert!(
            output.status.success(),
            "GLib's parser reads the Exec line: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("a JSON vector")
    }

    /// Where a distribution puts the generator that turns autostart entries into user units.
    #[cfg(target_os = "linux")]
    const GENERATORS: [&str; 3] = [
        "/usr/lib/systemd/user-generators/systemd-xdg-autostart-generator",
        "/lib/systemd/user-generators/systemd-xdg-autostart-generator",
        "/usr/libexec/systemd/user-generators/systemd-xdg-autostart-generator",
    ];

    #[cfg(target_os = "linux")]
    fn generator() -> Option<PathBuf> {
        GENERATORS
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
    }

    /// Whether `desktop-file-validate` can be started from `PATH`.
    #[cfg(target_os = "linux")]
    fn validator_is_installed() -> bool {
        Command::new("desktop-file-validate")
            .arg("--help")
            .output_locked()
            .is_ok()
    }

    /// A path as the generator writes it in `WorkingDirectory=`: a single quote after a backslash
    /// and every byte of a non-ASCII letter as a three-digit octal escape; every other character
    /// as it is.
    #[cfg(target_os = "linux")]
    fn escaped_by_the_generator(path: &str) -> String {
        path.bytes()
            .map(|byte| match byte {
                b'\'' => "\\'".to_owned(),
                0x80.. => format!("\\{byte:03o}"),
                _ => char::from(byte).to_string(),
            })
            .collect()
    }

    /// The unit the autostart generator makes from the entries under the setup's own
    /// `XDG_CONFIG_HOME`, or nothing when it makes none. The generator runs by hand, writes only
    /// under the setup's temporary folder and reads no configuration directory but an empty one.
    /// `tag` keeps the output of two runs in one setup apart.
    #[cfg(target_os = "linux")]
    fn generated_unit(setup: &Setup, generator: &Path, tag: &str) -> Option<String> {
        let output_root = setup.root.join("generated").join(tag);
        let empty = setup.root.join("no-config-directories");
        let directories = ["normal", "early", "late"].map(|name| output_root.join(name));
        std::fs::create_dir_all(&empty).expect("a directory");
        for directory in &directories {
            std::fs::create_dir_all(directory).expect("a directory");
        }
        let output = Command::new(generator)
            .args(&directories)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &setup.home)
            .env("XDG_CONFIG_HOME", setup.home.join(".config"))
            .env("XDG_CONFIG_DIRS", &empty)
            .output_locked()
            .expect("the autostart generator starts");
        assert!(
            output.status.success(),
            "the autostart generator exits 0: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // A user generator writes its units to the last of its three directories.
        std::fs::read_dir(&directories[2])
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "service")
            })
            .map(|path| std::fs::read_to_string(path).expect("the unit's text"))
    }

    #[test]
    fn the_login_item_is_written_for_this_platform_and_recorded_exactly() {
        let setup = Setup::new();
        let text = setup.ok("install");
        assert!(
            last_line(&text).starts_with("login item: installed: "),
            "{text}"
        );
        assert!(
            setup.item_in(&setup.home).is_some(),
            "the login item's file is there with the login item's own name: {text}"
        );
        let item = setup.item();
        let name = item
            .file_name()
            .and_then(|n| n.to_str())
            .expect("a name")
            .to_owned();
        let extension = if cfg!(target_os = "macos") {
            ".plist"
        } else {
            ".desktop"
        };
        assert!(
            name.starts_with("kr-desktop-host-") && name.ends_with(extension),
            "{name}"
        );
        assert!(
            !name.starts_with("kr-controller-"),
            "not the service start's label"
        );
        let mode = std::fs::metadata(&item)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the file is owner-only");
        let contents = std::fs::read_to_string(&item).expect("text");
        let record = setup.record();
        assert_eq!(record["version"], 1);
        assert_eq!(record["label"], name.trim_end_matches(extension));
        assert_eq!(record["path"], item.to_string_lossy().as_ref());
        assert_eq!(record["contents"], contents.as_str());
        assert!(record["pending"].is_null(), "nothing is under way");
        assert!(record.get("made").is_none(), "no directory is recorded");
        assert_eq!(
            record["kind"],
            if cfg!(target_os = "macos") {
                "launch_agent"
            } else {
                "autostart_entry"
            }
        );
        #[cfg(target_os = "macos")]
        for key in [
            "RunAtLoad",
            "LimitLoadToSessionType",
            "Aqua",
            "KeepAlive",
            "Umask",
        ] {
            assert!(contents.contains(key), "the property list holds {key}");
        }
        #[cfg(target_os = "linux")]
        for line in ["Type=Application", "Terminal=false", "TryExec="] {
            assert!(contents.contains(line), "the entry holds {line}");
        }
        let directory = setup.state_dir().expect("the state directory");
        let mut inside: Vec<String> = std::fs::read_dir(&directory)
            .expect("the state directory")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        inside.sort();
        assert!(
            inside.contains(&"desktop-host-login.lock".to_owned()),
            "{inside:?}"
        );
        assert!(
            !inside.contains(&"controller-service.lock".to_owned()),
            "{inside:?}"
        );
        assert_eq!(
            inside.len(),
            3,
            "the marker, the record and the lock only: {inside:?}"
        );
        assert!(!setup.runtime.exists(), "no runtime directory was made");
        assert!(!setup.stub_ran(), "nothing was started");
    }

    #[test]
    fn the_command_the_login_item_stores_is_the_one_kr_gives_the_daemon_and_nothing_runs_it() {
        let setup = Setup::new();
        assert!(setup.ok("install").contains(MARKER));
        let vector = read_vector(&setup.item());
        let controller = std::fs::canonicalize(setup.bin.join("kr-controller")).expect("resolves");
        assert_eq!(
            vector,
            vec![
                controller.to_string_lossy().into_owned(),
                "--runtime-dir".to_owned(),
                setup.runtime.to_string_lossy().into_owned(),
                "--state-dir".to_owned(),
                setup.state.to_string_lossy().into_owned(),
            ]
        );
        assert!(!setup.stub_ran(), "the stand-in stays untouched");
    }

    #[test]
    fn a_second_install_changes_nothing() {
        let setup = Setup::new();
        setup.ok("install");
        let before = setup.snapshot();
        let text = setup.ok("install");
        assert!(text.contains("already installed"), "{text}");
        assert!(
            before == setup.snapshot(),
            "every byte of the tree is equal"
        );
    }

    #[test]
    fn removing_takes_out_the_file_and_the_record_and_no_directory_and_nothing_else() {
        let setup = Setup::new();
        let directory = setup.directory(&setup.home);
        std::fs::create_dir_all(&directory).expect("the person's own directory");
        let theirs = [
            ("foo.desktop", "[Desktop Entry]\nName=Foo\n"),
            ("kr-desktop-host-other.plist", "other\n"),
            ("another-program.plist", "<plist/>\n"),
        ];
        for (name, contents) in theirs {
            std::fs::write(directory.join(name), contents).expect("a seeded file");
        }
        let seeded = setup.snapshot();
        setup.ok("install");
        let text = setup.ok("remove");
        assert!(text.contains("removed "), "{text}");
        assert!(
            text.contains("does not end a daemon that is running"),
            "{text}"
        );
        assert!(
            setup
                .item_in(&setup.home)
                .is_none_or(|p| p.ends_with("kr-desktop-host-other.plist"))
        );
        assert!(setup.record_bytes().is_none(), "the record is gone");
        let after = setup.snapshot();
        for (name, contents) in theirs {
            assert_eq!(
                after.get(&directory.join(name)).map(Vec::as_slice),
                Some(contents.as_bytes()),
                "{name} is as seeded"
            );
        }
        assert!(directory.is_dir(), "no directory is removed");
        let extra: Vec<_> = after
            .keys()
            .filter(|path| !seeded.contains_key(*path))
            .collect();
        assert!(
            extra.iter().all(|path| path.starts_with(&setup.state)),
            "only kr's own state is left: {extra:?}"
        );
    }

    #[test]
    fn a_login_item_changed_since_kr_wrote_it_is_named_and_left() {
        for change in ["append", "replace", "directory", "link"] {
            let setup = Setup::new();
            setup.ok("install");
            let item = setup.item();
            match change {
                "append" => {
                    let mut text = std::fs::read(&item).expect("bytes");
                    text.extend_from_slice(b"X-Mine=1\n");
                    std::fs::write(&item, text).expect("a change");
                }
                "replace" => std::fs::write(&item, b"mine\n").expect("a change"),
                "directory" => {
                    std::fs::remove_file(&item).expect("goes");
                    std::fs::create_dir(&item).expect("a directory");
                }
                _ => {
                    std::fs::remove_file(&item).expect("goes");
                    std::os::unix::fs::symlink(&setup.home, &item).expect("a link");
                }
            }
            let refusal = setup.refused("install");
            assert!(
                refusal.contains("was changed after kr wrote it, so kr does not replace it"),
                "{change}: {refusal}"
            );
            let before = std::fs::symlink_metadata(&item).is_ok();
            let text = setup.ok("remove");
            assert!(
                before && std::fs::symlink_metadata(&item).is_ok(),
                "{change}: left"
            );
            assert!(
                text.contains(&format!(
                    "left {}: it was changed after kr wrote it",
                    item.display()
                )),
                "{change}: {text}"
            );
            assert!(
                last_line(&text).starts_with(MARKER),
                "{change}: ends with the status line"
            );
            assert!(
                setup.record_bytes().is_none(),
                "{change}: the record is dropped"
            );
            assert!(setup.item_in(&setup.home).is_some_and(|p| p == item));
            let leftovers = std::fs::read_dir(setup.directory(&setup.home))
                .expect("dir")
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
                .count();
            assert_eq!(leftovers, 0, "{change}: no aside is left");
        }
    }

    #[test]
    fn a_file_kr_did_not_write_at_the_login_items_place_is_refused_and_left() {
        let setup = Setup::new();
        setup.ok("install");
        let other_home = setup.root.join("home2");
        std::fs::create_dir_all(setup.directory(&other_home)).expect("a directory");
        let item = setup.item();
        let name = item.file_name().expect("a name").to_owned();
        let place = setup.directory(&other_home).join(name);
        std::fs::write(&place, b"somebody's own file\n").expect("a foreign file");
        // The record of the first home is dropped, so the second has none and a file at its place.
        setup.ok("remove");
        let output = |argument: &str| {
            setup.run_with(
                &setup.bin.join("kr"),
                &other_home,
                &["host", "login-item", argument],
            )
        };
        let before = setup.snapshot_with(&[&other_home]);
        let install = output("install");
        assert!(!install.status.success(), "install is refused");
        let said = String::from_utf8_lossy(&install.stderr).into_owned();
        assert!(said.contains("is not what this installation of kr writes, and kr has no record of writing it, so kr does not replace it"), "{said}");
        assert!(
            setup.snapshot_with(&[&other_home]) == before,
            "nothing was written, in the second home or anywhere else"
        );
        let remove = output("remove");
        let text = String::from_utf8_lossy(&remove.stdout).into_owned();
        assert!(remove.status.success(), "remove succeeds");
        assert!(
            text.contains("nothing of the login item's to remove"),
            "{text}"
        );
        assert!(
            last_line(&text).contains("login item: ")
                && last_line(&text).contains("kr leaves it as it is"),
            "{text}"
        );
        assert_eq!(
            std::fs::read(&place).expect("left"),
            b"somebody's own file\n"
        );
    }

    #[test]
    fn a_login_item_that_has_gone_is_said_to_be_gone_and_its_record_dropped() {
        let setup = Setup::new();
        setup.ok("install");
        std::fs::remove_file(setup.item()).expect("the file goes");
        assert_eq!(status_word(&setup), "gone");
        let text = setup.ok("remove");
        assert!(setup.record_bytes().is_none(), "{text}");
        setup.ok("install");
        assert!(
            setup.item_in(&setup.home).is_some(),
            "install writes the file again"
        );
        std::fs::remove_file(setup.item()).expect("goes again");
        let text = setup.ok("install");
        assert!(
            last_line(&text).starts_with("login item: installed: "),
            "{text}"
        );
        assert!(setup.item_in(&setup.home).is_some());
    }

    #[test]
    fn no_program_is_started_by_any_login_item_command() {
        let setup = Setup::new();
        for argument in ["install", "status", "remove"] {
            setup.ok(argument);
            assert!(
                !setup.stub_ran(),
                "{argument} started the stand-in controller"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn no_manager_is_asked_by_any_login_item_command() {
        let setup = Setup::new();
        let stand_ins = setup.root.join("stand-ins");
        std::fs::create_dir(&stand_ins).expect("a directory");
        let calls = setup.root.join("manager-calls");
        for program in ["systemctl", "loginctl", "gsettings", "dbus-send"] {
            let path = stand_ins.join(program);
            std::fs::write(
                &path,
                format!("#!/bin/sh\necho {program} >> '{}'\n", calls.display()),
            )
            .expect("a stand-in");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("a mode");
        }
        for argument in ["install", "status", "remove"] {
            let mut command = setup.command_in(
                &setup.bin.join("kr"),
                &setup.home,
                &["host", "login-item", argument],
            );
            command.env("PATH", format!("{}:/usr/bin:/bin", stand_ins.display()));
            let output = command.output_locked().expect("kr runs");
            assert!(output.status.success(), "{argument} succeeds");
        }
        assert!(!calls.exists(), "no manager was asked");
    }

    /// Runs `kr shell install --shell zsh` in `setup`'s private home, with a zsh package of the
    /// test's own as a build installs one (its identity record and the file naming the identity in
    /// use; nothing starts it) and a package root and preferences folder of the test's own.
    fn shell_install_in(setup: &Setup) -> std::process::Output {
        use kr_shell_integration::contract::qualification::ShellKind;
        use kr_shell_integration::host::package::{
            CURRENT_BASENAME, MANIFEST_BASENAME, PACKAGE_ROOT_VARIABLE, PackageManifest,
            PackageShell, PackageStartupEntry,
        };

        let packages = setup.root.join("packages");
        let programs = setup.root.join("programs");
        let package = packages.join("zsh").join("test-1");
        std::fs::create_dir_all(&package).expect("the package's directory");
        std::fs::create_dir_all(&programs).expect("a directory");
        std::fs::write(programs.join("konsole"), b"#!/bin/sh\n").expect("Konsole stands in");
        let manifest = PackageManifest {
            identity: "test-1".to_owned(),
            shell: PackageShell {
                kind: ShellKind::Zsh,
                executable: package.join("bin/zsh"),
                upstream_version: "5.9".to_owned(),
                editor_abi: "zle-5.9".to_owned(),
                integration_version: "1".to_owned(),
                patches: Vec::new(),
                modules: Vec::new(),
            },
            startup_entry: PackageStartupEntry {
                file: package
                    .join("startup/entry.zsh")
                    .to_str()
                    .expect("the package root is text")
                    .to_owned(),
            },
            launch: kr_shell_integration::host::package::PackageLaunch::default(),
        };
        std::fs::write(
            package.join(MANIFEST_BASENAME),
            serde_json::to_string(&manifest).expect("the record encodes"),
        )
        .expect("writes the identity record");
        std::fs::write(packages.join("zsh").join(CURRENT_BASENAME), "test-1\n")
            .expect("names the identity in use");
        let mut command = setup.command_in(
            &setup.bin.join("kr"),
            &setup.home,
            &["shell", "install", "--shell", "zsh"],
        );
        command
            .env("PATH", format!("{}:/usr/bin:/bin", programs.display()))
            .env(PACKAGE_ROOT_VARIABLE, &packages);
        #[cfg(target_os = "macos")]
        {
            // `defaults` ignores HOME: the terminal preferences are files of this test's own.
            std::fs::create_dir_all(setup.home.join("domains")).expect("a directory");
            for domain in ["com.googlecode.iterm2", "com.apple.Terminal"] {
                std::fs::write(
                    setup.home.join("domains").join(format!("{domain}.plist")),
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict/></plist>\n",
                )
                .expect("preferences");
            }
            command.env(
                kr_shell_integration::host::terminal_profile::PREFERENCES_DIRECTORY_VARIABLE,
                setup.home.join("domains"),
            );
        }
        command.output_locked().expect("kr runs")
    }

    #[test]
    fn the_login_item_and_the_other_offers_are_separate_and_neither_touches_the_others_files() {
        let setup = Setup::new();
        setup.ok("install");
        let directory = setup.state_dir().expect("a state directory");
        for name in [
            "controller-service.json",
            "shell-entries.json",
            "terminal-profiles.json",
        ] {
            assert!(
                !directory.join(name).exists() && !setup.state.join(name).exists(),
                "{name}"
            );
        }
        // A seeded service record and definition are as seeded across all three commands.
        let seeded = [
            (
                directory.join("controller-service.json"),
                b"{\"seeded\":true}\n".to_vec(),
            ),
            (
                setup
                    .directory(&setup.home)
                    .join("kr-controller-seeded.plist"),
                b"seeded\n".to_vec(),
            ),
        ];
        for (path, contents) in &seeded {
            std::fs::write(path, contents).expect("a seeded file");
        }
        for argument in ["install", "status", "remove"] {
            setup.ok(argument);
            for (path, contents) in &seeded {
                assert_eq!(
                    std::fs::read(path).ok().as_ref(),
                    Some(contents),
                    "{argument}"
                );
            }
        }
        // In a tree of its own with no service record, `kr host startup --set standalone` and
        // `kr shell install` write no login item and no record.
        let second = Setup::new();
        let output = second.run(&["host", "startup", "--set", "standalone"]);
        assert!(
            output.status.success(),
            "kr host startup --set standalone succeeds: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(second.item_in(&second.home).is_none());
        assert!(second.record_bytes().is_none());
        let shell = shell_install_in(&second);
        assert!(
            shell.status.success(),
            "kr shell install succeeds in the private home: {}{}",
            String::from_utf8_lossy(&shell.stdout),
            String::from_utf8_lossy(&shell.stderr)
        );
        assert!(second.item_in(&second.home).is_none());
        assert!(second.record_bytes().is_none());
        // What those two commands wrote is as they wrote it across all three login item commands:
        // the configuration document that holds `startup.controller`, and the shell's startup file.
        let written: BTreeMap<PathBuf, Vec<u8>> = second
            .snapshot()
            .into_iter()
            .filter(|(path, contents)| {
                contents.as_slice() != b"<directory>".as_slice()
                    && !path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("desktop-host-login"))
            })
            .collect();
        assert!(
            written
                .keys()
                .any(|path| path.extension().is_some_and(|e| e == "json"))
                && written.keys().any(|path| path.starts_with(&second.home)),
            "the configuration document and a startup file in the home were written: {:?}",
            written.keys().collect::<Vec<_>>()
        );
        for argument in ["install", "status", "remove"] {
            second.ok(argument);
            for (path, contents) in &written {
                assert_eq!(
                    std::fs::read(path).ok().as_ref(),
                    Some(contents),
                    "{argument} leaves {} as it was",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn status_says_each_state_in_words_and_in_json() {
        let setup = Setup::new();
        let json = |setup: &Setup| -> serde_json::Value {
            let output = setup.run(&["--json", "host", "login-item", "status"]);
            assert_eq!(output.status.code(), Some(0));
            serde_json::from_slice(&output.stdout).expect("JSON")
        };
        let words = |setup: &Setup| {
            let output = setup.run(&["host", "login-item", "status"]);
            assert_eq!(output.status.code(), Some(0));
            String::from_utf8_lossy(&output.stdout).into_owned()
        };
        // none, with no identity yet and with one
        let fresh = words(&setup);
        assert!(
            fresh.contains("this environment has no identity yet"),
            "{fresh}"
        );
        assert!(json(&setup)["file"].is_null());
        assert!(setup.state_dir().is_none(), "status wrote nothing");
        setup.ok("install");
        // installed
        let installed = words(&setup);
        assert!(
            installed.starts_with("login item: installed: ")
                && installed.contains("is there as kr wrote it"),
            "{installed}"
        );
        let document = json(&setup);
        assert_eq!(document["state"], "installed");
        assert_eq!(document["recorded"], true);
        assert!(document["pending"].is_null());
        // changed
        let item = setup.item();
        let original = std::fs::read(&item).expect("bytes");
        std::fs::write(&item, b"edited\n").expect("a change");
        assert!(words(&setup).contains(
            "was changed after kr wrote it, so it is no longer kr's to replace or remove"
        ));
        assert_eq!(json(&setup)["state"], "changed");
        // gone
        std::fs::remove_file(&item).expect("goes");
        assert!(
            words(&setup)
                .contains(", and the file is gone; kr host login-item remove drops the record")
        );
        assert_eq!(json(&setup)["state"], "gone");
        // unrecorded: exactly kr's bytes and no record
        std::fs::write(&item, &original).expect("restored");
        std::fs::set_permissions(&item, std::fs::Permissions::from_mode(0o600)).expect("a mode");
        let record = setup.record_path().expect("a path");
        let kept = std::fs::read(&record).expect("a record");
        std::fs::remove_file(&record).expect("the record goes");
        assert!(words(&setup).contains(
            "is exactly what this installation of kr writes, and kr has no record of writing it"
        ));
        assert_eq!(json(&setup)["state"], "unrecorded");
        // foreign: other bytes and no record
        std::fs::write(&item, b"foreign\n").expect("a change");
        assert!(words(&setup).contains("kr leaves it as it is and does not write over it"));
        assert_eq!(json(&setup)["state"], "foreign");
        // outdated: a second layout writes other bytes
        std::fs::write(&item, &original).expect("restored");
        std::fs::write(&record, &kept).expect("the record is back");
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).expect("a mode");
        let layout = setup.root.join("bin2");
        setup.layout(&layout);
        let other = setup.run_with(
            &layout.join("kr"),
            &setup.home,
            &["--json", "host", "login-item", "status"],
        );
        let other: serde_json::Value = serde_json::from_slice(&other.stdout).expect("JSON");
        assert_eq!(other["state"], "outdated");
        // The whole sentence, the refusal that follows from it, and the clause of a pending install.
        let outdated = format!(
            "login item: {} is as kr wrote it, but this installation of kr writes it differently \
             now; kr host login-item remove takes it out, and kr host login-item install then \
             writes this installation's",
            item.display()
        );
        let there = |arguments: &[&str]| setup.run_with(&layout.join("kr"), &setup.home, arguments);
        let text =
            String::from_utf8_lossy(&there(&["host", "login-item", "status"]).stdout).into_owned();
        assert_eq!(text.trim_end(), outdated);
        let before = setup.snapshot();
        let refused = there(&["host", "login-item", "install"]);
        assert_eq!(
            refused.status.code(),
            Some(2),
            "install is refused as a usage error"
        );
        let said = String::from_utf8_lossy(&refused.stderr).into_owned();
        assert!(
            said.contains(&format!(
                "the login item file {} is as kr wrote it, but this installation of kr writes it \
                 differently now; run kr host login-item remove first, then run kr host \
                 login-item install again",
                item.display()
            )),
            "{said}"
        );
        assert!(
            setup.snapshot() == before,
            "a refused install changes nothing"
        );
        leave_pending(
            &setup,
            serde_json::json!({"operation": "publish", "staging": beside(&item, "kr-staging")}),
        );
        let text =
            String::from_utf8_lossy(&there(&["host", "login-item", "status"]).stdout).into_owned();
        assert_eq!(
            text.trim_end(),
            format!(
                "{outdated}; an earlier kr host login-item install did not finish: kr host \
                 login-item remove takes out what it left"
            )
        );
        std::fs::write(&record, &kept).expect("the record is as it was");
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).expect("a mode");
        // elsewhere: another home
        let second = setup.root.join("home2");
        std::fs::create_dir_all(&second).expect("a home");
        let elsewhere = setup.run_with(
            &setup.bin.join("kr"),
            &second,
            &["host", "login-item", "status"],
        );
        let text = String::from_utf8_lossy(&elsewhere.stdout).into_owned();
        assert!(
            text.contains("login item: the file the record ") && text.contains(" names is not "),
            "{text}"
        );
        // an unusable record gives its sentence and a non-zero exit
        std::fs::write(&record, b"not json").expect("a bad record");
        let bad = setup.run(&["host", "login-item", "status"]);
        assert!(!bad.status.success());
        assert!(String::from_utf8_lossy(&bad.stderr).contains("cannot be used"));
    }

    /// The name a path left beside the login item's file has, as a record names it.
    fn beside(item: &Path, extension: &str) -> PathBuf {
        let name = item.file_name().and_then(|n| n.to_str()).expect("a name");
        item.with_file_name(format!(
            ".{name}.0d15ea5e-0000-4000-8000-000000000001.{extension}"
        ))
    }

    /// Writes into the record what an earlier command that stopped would have left: `pending`.
    fn leave_pending(setup: &Setup, pending: serde_json::Value) {
        let mut record = setup.record();
        record["pending"] = pending;
        std::fs::write(
            setup.record_path().expect("a record"),
            serde_json::to_vec_pretty(&record).expect("encodes"),
        )
        .expect("the record is written");
    }

    /// A second home beside the first, which the first one's record does not name.
    fn other_home(setup: &Setup) -> PathBuf {
        let second = setup.root.join("home2");
        std::fs::create_dir_all(&second).expect("a home");
        second
    }

    fn run_in(setup: &Setup, home: &Path, arguments: &[&str]) -> (bool, String, String) {
        let output = setup.run_with(&setup.bin.join("kr"), home, arguments);
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    #[test]
    fn a_home_that_is_not_text_is_refused_before_anything_is_made() {
        use std::os::unix::ffi::OsStrExt as _;
        let setup = Setup::new();
        let before = setup.snapshot();
        let bad = setup.root.join(std::ffi::OsStr::from_bytes(b"home-\xff"));
        let mut homes = vec![(bad.clone(), None)];
        if cfg!(target_os = "linux") {
            homes.push((
                setup.home.clone(),
                Some(setup.root.join(std::ffi::OsStr::from_bytes(b"cfg-\xff"))),
            ));
        }
        for (home, config) in homes {
            for argument in ["install", "remove", "status"] {
                let mut command = setup.command_in(
                    &setup.bin.join("kr"),
                    &home,
                    &["host", "login-item", argument],
                );
                if let Some(config) = &config {
                    command.env("XDG_CONFIG_HOME", config);
                }
                let output = command.output_locked().expect("kr runs");
                let said = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                if argument == "install" {
                    assert!(!output.status.success(), "install is refused: {said}");
                    assert!(
                        said.contains(
                            "is not text, so the login item's record cannot hold it exactly; \
                             nothing was written"
                        ),
                        "{said}"
                    );
                }
                assert!(
                    before == setup.snapshot(),
                    "{argument}: no identity, state directory, record or file was made"
                );
            }
        }
    }

    #[test]
    fn what_a_settling_did_is_told_though_a_refusal_follows_it() {
        let setup = Setup::new();
        setup.ok("install");
        let first = setup.item();
        // An earlier install stopped after it staged: its staging file holds other bytes.
        let staging = beside(&first, "kr-staging");
        std::fs::write(&staging, b"somebody else's bytes\n").expect("a staging file");
        leave_pending(
            &setup,
            serde_json::json!({"operation": "publish", "staging": staging}),
        );
        let second = other_home(&setup);
        let (ok, said, refused) = run_in(&setup, &second, &["host", "login-item", "install"]);
        assert!(!ok, "install from another home is refused: {said}{refused}");
        assert!(
            refused.contains("kr wrote this environment's login item at the file the record "),
            "{refused}"
        );
        assert!(
            said.contains("under a name that ends in .kr-staging")
                && said.contains("it does not hold what kr wrote"),
            "the leftover the settling kept is named though the record no longer names it: {said}"
        );
        assert!(
            setup.record()["pending"].is_null(),
            "the record drops what it named"
        );
        assert!(staging.exists(), "the leftover is left");
        // The same in the document.
        std::fs::write(&staging, b"somebody else's bytes\n").expect("a staging file");
        leave_pending(
            &setup,
            serde_json::json!({"operation": "publish", "staging": staging}),
        );
        let (ok, said, _) = run_in(
            &setup,
            &second,
            &["host", "login-item", "install", "--json"],
        );
        assert!(!ok, "install from another home is refused: {said}");
        // One document holds what the settling did and the refusal that followed it.
        let parsed = serde_json::from_str::<serde_json::Value>(&said);
        assert!(parsed.is_ok(), "the output is one document: {said}");
        let document = parsed.unwrap_or_default();
        assert_eq!(document["ok"], false, "{said}");
        assert!(
            document["message"]
                .as_str()
                .is_some_and(|message| message.contains("the file the record ")),
            "{said}"
        );
        assert!(
            document["actions"]
                .as_array()
                .is_some_and(|actions| actions.iter().any(|a| a == "left_leftover")),
            "{said}"
        );
    }

    #[test]
    fn each_stopped_state_says_what_the_next_command_does_about_it() {
        let setup = Setup::new();
        setup.ok("install");
        let first = setup.item();
        let staging = beside(&first, "kr-staging");
        let install_stopped = serde_json::json!({"operation": "publish", "staging": staging});
        let aside = beside(&first, "kr-moving");
        let remove_stopped = serde_json::json!({"operation": "remove", "aside": aside});

        // The file is as kr wrote it: install finishes an install, remove finishes a remove.
        leave_pending(&setup, install_stopped.clone());
        let (ok, said, _) = run_in(&setup, &setup.home, &["host", "login-item", "status"]);
        assert!(ok);
        assert!(
            said.contains(
                "an earlier kr host login-item install did not finish: kr host login-item install \
                 finishes it, or kr host login-item remove takes out what it left"
            ),
            "{said}"
        );
        // Where the control daemon is gone, install refuses before it settles anything, so status
        // does not say that install finishes it.
        let controller = setup.bin.join("kr-controller");
        let away = setup.bin.join("kr-controller.away");
        std::fs::rename(&controller, &away).expect("the control daemon goes");
        let (ok, said, _) = run_in(&setup, &setup.home, &["host", "login-item", "status"]);
        std::fs::rename(&away, &controller).expect("the control daemon is back");
        assert!(ok);
        assert!(
            said.contains(
                "an earlier kr host login-item install did not finish: kr host login-item remove \
                 takes out what it left"
            ) && !said.contains("install finishes it"),
            "{said}"
        );
        leave_pending(&setup, remove_stopped.clone());
        let (_, said, _) = run_in(&setup, &setup.home, &["host", "login-item", "status"]);
        assert!(
            said.contains(
                "an earlier kr host login-item remove did not finish: kr host login-item remove \
                 finishes it"
            ),
            "{said}"
        );
        let (_, said, _) = run_in(
            &setup,
            &setup.home,
            &["host", "login-item", "status", "--json"],
        );
        let document: serde_json::Value = serde_json::from_str(&said).unwrap_or_default();
        assert_eq!(document["pending"], "remove", "{said}");

        // An install takes back a removal that stopped, and says so, and the item is as it was.
        let (ok, said, _) = run_in(&setup, &setup.home, &["host", "login-item", "install"]);
        assert!(ok, "{said}");
        assert!(
            said.contains("took back what an earlier kr host login-item remove began"),
            "{said}"
        );
        assert!(!said.contains("finished what"), "{said}");
        assert!(setup.record()["pending"].is_null());

        // A removal takes out what an install left, and says so.
        leave_pending(&setup, install_stopped.clone());
        let (ok, said, _) = run_in(&setup, &setup.home, &["host", "login-item", "remove"]);
        assert!(ok, "{said}");
        assert!(
            said.contains("took out what an earlier kr host login-item install began"),
            "{said}"
        );
        assert!(setup.item_in(&setup.home).is_none());

        // From another home, an install that stopped is settled by remove, and status says that
        // install would only refuse.
        setup.ok("install");
        let first = setup.item();
        let staging = beside(&first, "kr-staging");
        leave_pending(
            &setup,
            serde_json::json!({"operation": "publish", "staging": staging}),
        );
        let second = other_home(&setup);
        let (_, said, _) = run_in(&setup, &second, &["host", "login-item", "status"]);
        assert!(
            said.contains(
                "an earlier kr host login-item install did not finish: kr host login-item remove \
                 takes out what it left"
            ) && !said.contains("install finishes it"),
            "{said}"
        );

        // The file changed after kr wrote it: the refusal names the file the record names, not the
        // place under the home that the command was run from.
        let mut changed = std::fs::read(&first).expect("the file");
        changed.extend_from_slice(b"\n");
        std::fs::write(&first, changed).expect("a changed file");
        let (ok, _, refused) = run_in(&setup, &second, &["host", "login-item", "install"]);
        assert!(!ok, "{refused}");
        assert!(
            refused.contains("the file the record ")
                && refused.contains(
                    " names was changed after kr wrote it, so kr does not replace it; run kr host \
                 login-item remove, which leaves it, then run kr host login-item install again"
                ),
            "the refusal names the file by the record that names it: {refused}"
        );
        assert!(
            !refused.contains(&first.display().to_string()),
            "the first home's path is not printed whole: {refused}"
        );
        assert!(
            !refused.contains(&second.display().to_string()),
            "a file under the other home is not said to be changed: {refused}"
        );
    }

    /// A removal that stopped after it took the file out and flushed: nothing is left to take
    /// back, and an install says so before it writes the file again.
    #[test]
    fn an_install_does_not_say_it_took_back_a_removal_that_had_taken_the_file_out() {
        let setup = Setup::new();
        setup.ok("install");
        let first = setup.item();
        let aside = beside(&first, "kr-moving");
        leave_pending(
            &setup,
            serde_json::json!({"operation": "remove", "aside": aside}),
        );
        std::fs::remove_file(&first).expect("the removal had taken the file out");
        assert!(!aside.exists());
        let (ok, said, refused) = run_in(&setup, &setup.home, &["host", "login-item", "install"]);
        assert!(ok, "{said}{refused}");
        assert!(
            said.contains(
                "an earlier kr host login-item remove had already taken out the file, so kr had \
                 nothing to take back"
            ),
            "{said}"
        );
        assert!(!said.contains("took back what"), "{said}");
        assert!(
            setup.item_in(&setup.home).is_some(),
            "install wrote the file again"
        );
        assert!(setup.record()["pending"].is_null());
        // An install that stopped before it put the file in place is not said to have finished.
        let item = setup.item();
        std::fs::remove_file(&item).expect("the file goes");
        let staging = beside(&item, "kr-staging");
        leave_pending(
            &setup,
            serde_json::json!({"operation": "publish", "staging": staging}),
        );
        let (ok, said, refused) = run_in(&setup, &setup.home, &["host", "login-item", "install"]);
        assert!(ok, "{said}{refused}");
        assert!(
            said.contains(
                "an earlier kr host login-item install stopped before it put the file in place, \
                 so kr had no file to finish"
            ),
            "{said}"
        );
        assert!(!said.contains("finished what"), "{said}");
    }

    /// A removal whose own removal fails after the settling did its part does not say it took
    /// out what an earlier install began: the file is still there.
    #[test]
    fn a_removal_that_fails_after_its_settling_does_not_say_it_took_out_the_install() {
        let setup = Setup::new();
        setup.ok("install");
        let item = setup.item();
        let staging = beside(&item, "kr-staging");
        leave_pending(
            &setup,
            serde_json::json!({"operation": "publish", "staging": staging}),
        );
        let directory = item.parent().expect("a directory").to_owned();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
            .expect("a read-only directory");
        let (ok, said, refused) = run_in(&setup, &setup.home, &["host", "login-item", "remove"]);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
            .expect("the directory is writable again");
        assert!(!ok, "the removal fails: {said}{refused}");
        assert!(
            refused.contains("kr stopped while it was moving the file aside"),
            "{said}{refused}"
        );
        assert!(
            !said.contains("took out what an earlier")
                && !refused.contains("took out what an earlier"),
            "{said}{refused}"
        );
        assert!(item.exists(), "the file is still there");
    }

    #[test]
    fn a_path_the_record_names_that_is_not_the_homes_is_never_printed() {
        let setup = Setup::new();
        let marked = setup.root.join("home-MARKER-9f3a");
        std::fs::create_dir_all(&marked).expect("a home");
        let (ok, said, _) = run_in(&setup, &marked, &["host", "login-item", "install"]);
        assert!(ok, "{said}");
        let item = setup
            .item_in(&marked)
            .expect("the item is in the marked home");
        let staging = beside(&item, "kr-staging");
        leave_pending(
            &setup,
            serde_json::json!({"operation": "publish", "staging": staging}),
        );
        std::fs::write(&staging, b"somebody else's bytes\n").expect("a staging file");
        let second = other_home(&setup);
        for argument in [
            &["status"][..],
            &["install"],
            &["status", "--json"],
            &["remove"],
        ] {
            let mut arguments = vec!["host", "login-item"];
            arguments.extend_from_slice(argument);
            let (_, said, refused) = run_in(&setup, &second, &arguments);
            assert!(
                !said.contains("MARKER-9f3a") && !refused.contains("MARKER-9f3a"),
                "{argument:?} prints text of a path that is not this home's: {said}{refused}"
            );
        }
    }

    #[test]
    fn a_changed_file_a_record_names_that_is_not_the_homes_is_never_printed_whole() {
        let setup = Setup::new();
        let marked = setup.root.join("home-MARKER-9f3a");
        std::fs::create_dir_all(&marked).expect("a home");
        let (ok, said, _) = run_in(&setup, &marked, &["host", "login-item", "install"]);
        assert!(ok, "{said}");
        let item = setup
            .item_in(&marked)
            .expect("the item is in the marked home");
        let staging = beside(&item, "kr-staging");
        leave_pending(
            &setup,
            serde_json::json!({"operation": "publish", "staging": staging}),
        );
        let mut changed = std::fs::read(&item).expect("the file");
        changed.extend_from_slice(b"\n");
        std::fs::write(&item, changed).expect("a changed file");
        let second = other_home(&setup);
        let said_by = |arguments: &[&str]| {
            let mut full = vec!["host", "login-item"];
            full.extend_from_slice(arguments);
            let (ok, said, refused) = run_in(&setup, &second, &full);
            assert!(
                !said.contains("MARKER-9f3a") && !refused.contains("MARKER-9f3a"),
                "{arguments:?} prints text of a path that is not this home's: {said}{refused}"
            );
            (ok, said, refused)
        };
        let (ok, _, _) = said_by(&["status"]);
        assert!(ok);
        let (ok, _, _) = said_by(&["status", "--json"]);
        assert!(ok);
        let (ok, said, refused) = said_by(&["install"]);
        assert!(!ok, "{said}{refused}");
        assert!(
            refused.contains(" names was changed after kr wrote it, so kr does not replace it"),
            "{refused}"
        );
        let (ok, said, _) = said_by(&["install", "--json"]);
        assert!(!ok);
        let parsed = serde_json::from_str::<serde_json::Value>(&said);
        assert!(parsed.is_ok(), "the output is one document: {said}");
        let document = parsed.unwrap_or_default();
        assert!(
            document["message"].as_str().is_some_and(|message| {
                message.contains(" names was changed after kr wrote it, so kr does not replace it")
            }),
            "{said}"
        );
        let (ok, said, refused) = said_by(&["remove"]);
        assert!(ok, "{said}{refused}");
        assert!(item.exists(), "the changed file is left");
        assert!(setup.record_path().is_some_and(|path| !path.exists()));
    }

    #[test]
    fn a_file_that_is_exactly_what_kr_writes_is_adopted_and_no_byte_of_it_changes() {
        let setup = Setup::new();
        setup.ok("install");
        let item = setup.item();
        let original = std::fs::read(&item).expect("bytes");
        setup.ok("remove");
        // An identity and no record, and no file: the state is none, with the file it would write.
        let text = setup.ok("status");
        assert_eq!(
            text.trim_end(),
            format!(
                "login item: none: kr has no record of a login item for this environment, and \
                 there is no file at {}; kr host login-item install writes one",
                item.display()
            )
        );
        std::fs::write(&item, &original).expect("the file is there as kr writes it");
        std::fs::set_permissions(&item, std::fs::Permissions::from_mode(0o600)).expect("a mode");
        assert_eq!(status_word(&setup), "unrecorded");
        let said = setup.ok("install");
        assert!(
            said.contains(&format!(
                "recorded {}, which is what this installation writes; no byte of it changed",
                item.display()
            )),
            "{said}"
        );
        assert!(
            last_line(&said).starts_with("login item: installed: "),
            "{said}"
        );
        assert_eq!(std::fs::read(&item).expect("bytes"), original);
        assert!(
            setup.record_bytes().is_some(),
            "the file is recorded: {said}"
        );
        assert_eq!(setup.record()["path"], item.to_string_lossy().as_ref());
        assert!(setup.record()["pending"].is_null());
        assert_eq!(status_word(&setup), "installed");
        let again = setup.ok("install");
        assert!(again.contains("login item: already installed: "), "{again}");
    }

    /// One state of an install or a removal that stopped, built by hand from the record and the
    /// files each step leaves.
    struct Stopped {
        name: &'static str,
        operation: &'static str,
        file_is_there: bool,
        leftover: Option<&'static str>,
    }

    const STOPPED: [Stopped; 8] = [
        Stopped {
            name: "publish 1",
            operation: "publish",
            file_is_there: false,
            leftover: None,
        },
        Stopped {
            name: "publish 3",
            operation: "publish",
            file_is_there: false,
            leftover: Some("staged"),
        },
        Stopped {
            name: "publish 4",
            operation: "publish",
            file_is_there: true,
            leftover: Some("linked"),
        },
        Stopped {
            name: "publish 5",
            operation: "publish",
            file_is_there: true,
            leftover: None,
        },
        Stopped {
            name: "remove 1",
            operation: "remove",
            file_is_there: true,
            leftover: None,
        },
        Stopped {
            name: "remove 2",
            operation: "remove",
            file_is_there: false,
            leftover: Some("moved"),
        },
        Stopped {
            name: "remove 3",
            operation: "remove",
            file_is_there: false,
            leftover: None,
        },
        Stopped {
            name: "put back 1",
            operation: "remove",
            file_is_there: true,
            leftover: Some("linked"),
        },
    ];

    /// An installed login item turned into `state`, and the bytes it holds.
    fn stopped_in(setup: &Setup, state: &Stopped) -> (PathBuf, Vec<u8>) {
        setup.ok("install");
        let item = setup.item();
        let original = std::fs::read(&item).expect("bytes");
        let name = if state.operation == "publish" {
            "kr-staging"
        } else {
            "kr-moving"
        };
        let leftover = beside(&item, name);
        match state.leftover {
            Some("linked") => std::fs::hard_link(&item, &leftover).expect("two names"),
            Some("moved") => std::fs::rename(&item, &leftover).expect("moved aside"),
            Some(_) => {
                std::fs::write(&leftover, &original).expect("a staged file");
                std::fs::set_permissions(&leftover, std::fs::Permissions::from_mode(0o600))
                    .expect("a mode");
            }
            None => {}
        }
        if !state.file_is_there && state.leftover != Some("moved") {
            std::fs::remove_file(&item).expect("the file is not there");
        }
        let key = if state.operation == "publish" {
            "staging"
        } else {
            "aside"
        };
        leave_pending(
            setup,
            serde_json::json!({"operation": state.operation, key: leftover}),
        );
        (item, original)
    }

    fn leftovers_in(setup: &Setup) -> Vec<String> {
        std::fs::read_dir(setup.directory(&setup.home))
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .filter(|name| name.starts_with('.'))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn every_stopped_state_is_read_by_status_and_finished_by_install_and_by_remove() {
        for state in &STOPPED {
            let name = state.name;
            // status reads the state and changes nothing.
            let setup = Setup::new();
            let (item, original) = stopped_in(&setup, state);
            let before = setup.snapshot();
            let said = setup.ok("status");
            assert!(
                said.contains(&format!(
                    "an earlier kr host login-item {} did not finish: ",
                    if state.operation == "publish" {
                        "install"
                    } else {
                        "remove"
                    }
                )),
                "{name}: {said}"
            );
            assert!(setup.snapshot() == before, "{name}: status changes nothing");
            // install finishes it, whole, and says what it did from what it found.
            let said = setup.ok("install");
            assert!(setup.record()["pending"].is_null(), "{name}: {said}");
            assert_eq!(leftovers_in(&setup), Vec::<String>::new(), "{name}: {said}");
            assert_eq!(
                std::fs::read(&item).ok().as_deref(),
                Some(original.as_slice()),
                "{name}"
            );
            let sentence = match (
                state.operation,
                state.file_is_there || state.leftover == Some("moved"),
            ) {
                ("publish", true) => "finished what an earlier kr host login-item install began",
                ("publish", false) => {
                    "an earlier kr host login-item install stopped before it put the file in place, \
                     so kr had no file to finish"
                }
                (_, true) => "took back what an earlier kr host login-item remove began",
                (_, false) => {
                    "an earlier kr host login-item remove had already taken out the file, so kr \
                     had nothing to take back"
                }
            };
            assert!(said.contains(sentence), "{name}: {said}");
            // remove finishes it too: no file, no record, no leftover.
            let setup = Setup::new();
            let (item, _) = stopped_in(&setup, state);
            let said = setup.ok("remove");
            assert!(setup.record_bytes().is_none(), "{name}: {said}");
            assert!(!item.exists(), "{name}: {said}");
            assert_eq!(leftovers_in(&setup), Vec::<String>::new(), "{name}: {said}");
            let sentence = if state.operation == "publish" {
                "took out what an earlier kr host login-item install began"
            } else {
                "finished what an earlier kr host login-item remove began"
            };
            assert!(said.contains(sentence), "{name}: {said}");
        }
    }

    /// When the directory the item was written into has become a file, status says the file is
    /// gone and a removal drops the record, as it does for a file that is gone.
    #[test]
    fn a_login_item_whose_directory_became_a_file_is_gone_and_its_removal_finishes() {
        let setup = Setup::new();
        setup.ok("install");
        let item = setup.item();
        let directory = item.parent().expect("a directory").to_owned();
        std::fs::remove_file(&item).expect("the file goes");
        std::fs::remove_dir(&directory).expect("the directory goes");
        std::fs::write(&directory, b"a file now\n").expect("a file in its place");
        assert_eq!(status_word(&setup), "gone");
        let (ok, said, refused) = run_in(&setup, &setup.home, &["host", "login-item", "remove"]);
        assert!(ok, "the removal finishes: {said}{refused}");
        assert!(setup.record_bytes().is_none(), "{said}");
        assert_eq!(
            std::fs::read(&directory).ok().as_deref(),
            Some(&b"a file now\n"[..]),
            "the file that stands where the directory was is left"
        );
    }

    #[test]
    fn a_removal_with_no_record_makes_no_identity_no_lock_and_no_file() {
        let setup = Setup::new();
        let before = setup.snapshot();
        let (ok, said, _) = run_in(&setup, &setup.home, &["host", "login-item", "remove"]);
        assert!(ok, "{said}");
        assert!(
            said.contains("nothing of the login item's to remove"),
            "{said}"
        );
        assert!(before == setup.snapshot(), "nothing was made: {said}");
        // With an identity but no record and no lock, nothing is made either.
        setup.ok("install");
        setup.ok("remove");
        let directory = setup.state_dir().expect("a state directory");
        let lock = directory.join("desktop-host-login.lock");
        let _ = std::fs::remove_file(&lock);
        let before = setup.snapshot();
        let (ok, said, _) = run_in(&setup, &setup.home, &["host", "login-item", "remove"]);
        assert!(ok, "{said}");
        assert!(!lock.exists(), "no lock file was made: {said}");
        assert!(before == setup.snapshot(), "nothing was made: {said}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_path_a_property_list_must_escape_reads_back_whole() {
        for name in ["a&b", "a<b>", "a'b", "a\"b"] {
            let setup = Setup::new();
            let layout = setup.root.join(name).join("bin");
            setup.layout(&layout);
            let output = setup.run_with(
                &layout.join("kr"),
                &setup.home,
                &["host", "login-item", "install"],
            );
            assert!(
                output.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let controller = std::fs::canonicalize(layout.join("kr-controller")).expect("resolves");
            assert_eq!(
                read_vector(&setup.item())[0],
                controller.to_string_lossy(),
                "{name}"
            );
            // The runtime and state directories read back whole as well.
            let mut setup = Setup::new();
            setup.state = setup.root.join(name).join("s");
            setup.runtime = setup.root.join(name).join("r");
            setup.ok("install");
            let words = read_vector(&setup.item());
            for root in [&setup.state, &setup.runtime] {
                let root = root.to_string_lossy();
                assert!(
                    words.iter().any(|word| word.contains(root.as_ref())),
                    "{name}: {root} reads back whole from {words:?}"
                );
            }
        }
        // A path with a control character cannot be written exactly, and nothing is written.
        let setup = Setup::new();
        let layout = setup.root.join("a\nb").join("bin");
        setup.layout(&layout);
        let before = setup.snapshot();
        let output = setup.run_with(
            &layout.join("kr"),
            &setup.home,
            &["host", "login-item", "install"],
        );
        assert!(!output.status.success(), "a control character is refused");
        let said = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            said.contains("cannot be written into a property list exactly")
                && said.contains("; nothing was written"),
            "{said}"
        );
        assert!(setup.snapshot() == before, "nothing was written");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_path_a_desktop_entry_cannot_hold_exactly_is_refused_and_every_other_path_reads_back_whole()
    {
        assert!(
            validator_is_installed(),
            "desktop-file-validate is not installed (the desktop-file-utils package): this case \
             validates every entry it writes with it"
        );
        let generator = generator();
        assert!(
            generator.is_some(),
            "the autostart generator is not installed (the systemd package; looked in \
             {GENERATORS:?}): this case converts every entry it writes with it"
        );
        let generator = generator.expect("checked above");
        // The second field is whether the generator double-quotes the word in its `ExecStart=`
        // line; it leaves the others bare. The entry's own words are all quoted.
        let accepted = [
            ("a b", true),
            ("a'b", true),
            ("a#b", false),
            ("a;b", true),
            ("a(b", true),
            ("a&b", true),
            ("a<b>", true),
            ("a~b", false),
            ("a*b", true),
            ("a?b", true),
            ("a|b", true),
            (".dot", false),
            ("zoë", false),
            // A space at the end of a name in the middle of a path is a space like any other.
            (" a", true),
            ("a ", true),
        ];
        let refused = ["a\"b", "a`b", "a$b", "a\\b", "a%b", "a\tb", "a\nb"];
        let mut cases: Vec<(&str, &str, Option<bool>)> = Vec::new();
        for position in ["daemon", "runtime", "state"] {
            for (name, quoted) in accepted {
                cases.push((name, position, Some(quoted)));
            }
            for name in refused {
                cases.push((name, position, None));
            }
            // An equals sign is refused in the daemon's path and read back in a root.
            cases.push(("a=b", position, (position != "daemon").then_some(false)));
        }
        for (name, position, quoted) in cases {
            let setup = Setup::new();
            let mut kr = setup.bin.join("kr");
            let mut runtime = setup.runtime.clone();
            let mut state = setup.state.clone();
            match position {
                "daemon" => {
                    let layout = setup.root.join(name).join("bin");
                    setup.layout(&layout);
                    kr = layout.join("kr");
                }
                "runtime" => runtime = setup.root.join(name).join("run"),
                _ => state = setup.root.join(name).join("state"),
            }
            let before = setup.snapshot();
            let mut command =
                setup.command_in(&kr, &setup.home, &["host", "login-item", "install"]);
            command.env("KR_RUNTIME_DIR", &runtime);
            command.env("KR_STATE_DIR", &state);
            let output = command.output_locked().expect("kr runs");
            let said = String::from_utf8_lossy(&output.stderr).into_owned();
            let Some(quoted) = quoted else {
                assert!(
                    !output.status.success(),
                    "the {position} path {name:?} is refused"
                );
                assert!(
                    said.contains("cannot be written into a desktop entry exactly"),
                    "{position} {name:?}: {said}"
                );
                assert!(
                    setup.snapshot() == before && !runtime.exists() && !state.exists(),
                    "{position} {name:?}: nothing was written"
                );
                continue;
            };
            assert!(
                output.status.success(),
                "the {position} path {name:?} is written: {said}"
            );
            let entry = setup.item_in(&setup.home).expect("the entry is written");
            let controller =
                std::fs::canonicalize(kr.with_file_name("kr-controller")).expect("resolves");
            // GLib's shell parser: the quoting subset of `Exec`, word by word.
            assert_eq!(
                read_vector(&entry),
                vec![
                    controller.to_string_lossy().into_owned(),
                    "--runtime-dir".to_owned(),
                    runtime.to_string_lossy().into_owned(),
                    "--state-dir".to_owned(),
                    state.to_string_lossy().into_owned(),
                ],
                "GLib reads the {position} path {name:?} back to the vector kr was given"
            );
            // The validator: the entry is valid, `TryExec` and `Path` included.
            let validated = Command::new("desktop-file-validate")
                .arg(&entry)
                .output_locked()
                .expect("desktop-file-validate starts");
            assert!(
                validated.status.success(),
                "desktop-file-validate refuses the entry for the {position} path {name:?}: {}{}",
                String::from_utf8_lossy(&validated.stdout),
                String::from_utf8_lossy(&validated.stderr)
            );
            // The generator: the unit it makes, `ExecStart=` and the working directory read back
            // from `Path`.
            let unit = generated_unit(&setup, &generator, "entry");
            assert!(
                unit.is_some(),
                "the autostart generator makes no unit from the entry for the {position} path {name:?}"
            );
            let unit = unit.expect("checked above");
            let word = |path: &Path, tested: bool| {
                let text = path.to_string_lossy();
                if tested && quoted {
                    format!("\"{text}\"")
                } else {
                    text.into_owned()
                }
            };
            let exec_start = format!(
                "ExecStart=:{} --runtime-dir {} --state-dir {}",
                word(&controller, position == "daemon"),
                word(&runtime, position == "runtime"),
                word(&state, position == "state"),
            );
            assert!(
                unit.lines().any(|line| line == exec_start),
                "the generator's ExecStart for the {position} path {name:?} is not {exec_start:?}: {unit}"
            );
            let environment = std::fs::read_dir(state.join("environments"))
                .expect("the state root holds the environment")
                .flatten()
                .map(|entry| entry.path())
                .next()
                .expect("an environment directory");
            let working_directory = format!(
                "WorkingDirectory=-{}",
                escaped_by_the_generator(&environment.to_string_lossy())
            );
            assert!(
                unit.lines().any(|line| line == working_directory),
                "the generator's working directory for the {position} path {name:?} is not {working_directory:?}: {unit}"
            );
        }
        // A path that itself ends in a space cannot be written exactly either.
        for input in ["runtime", "state"] {
            let setup = Setup::new();
            let root = setup.root.join(input).join("a ");
            let before = setup.snapshot();
            let mut command = setup.command_in(
                &setup.bin.join("kr"),
                &setup.home,
                &["host", "login-item", "install"],
            );
            command.env(
                if input == "runtime" {
                    "KR_RUNTIME_DIR"
                } else {
                    "KR_STATE_DIR"
                },
                &root,
            );
            let output = command.output_locked().expect("kr runs");
            let said = String::from_utf8_lossy(&output.stderr).into_owned();
            assert!(
                !output.status.success(),
                "the {input} root {root:?} is refused"
            );
            assert!(
                said.contains("cannot be written into a desktop entry exactly"),
                "{input} {root:?}: {said}"
            );
            assert!(
                setup.snapshot() == before && !root.exists(),
                "{input} {root:?}: nothing was written"
            );
        }
        // `TryExec` is read by the generator too: it makes no unit once the program is not
        // executable.
        let setup = Setup::new();
        setup.ok("install");
        assert!(
            generated_unit(&setup, &generator, "executable").is_some(),
            "the generator makes a unit while the program is executable"
        );
        std::fs::set_permissions(
            setup.bin.join("kr-controller"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("a mode");
        assert!(
            generated_unit(&setup, &generator, "not-executable").is_none(),
            "the generator makes no unit once TryExec names a program that cannot be run"
        );
    }

    #[test]
    fn an_install_and_a_removal_at_once_leave_no_file_the_record_does_not_name() {
        let setup = Setup::new();
        setup.ok("install");
        setup.ok("remove");
        for _ in 0..4 {
            let install = setup
                .command_in(
                    &setup.bin.join("kr"),
                    &setup.home,
                    &["host", "login-item", "install"],
                )
                .spawn_locked()
                .expect("starts");
            let remove = setup
                .command_in(
                    &setup.bin.join("kr"),
                    &setup.home,
                    &["host", "login-item", "remove"],
                )
                .spawn_locked()
                .expect("starts");
            for mut child in [install, remove] {
                let _ = child.wait();
            }
            let file = setup.item_in(&setup.home);
            let record = setup.record_bytes();
            match (&file, &record) {
                (Some(file), Some(record)) => {
                    let record: serde_json::Value = serde_json::from_slice(record).expect("JSON");
                    assert_eq!(
                        record["contents"],
                        std::fs::read_to_string(file).expect("text").as_str()
                    );
                    assert!(record["pending"].is_null());
                }
                (None, None) => {}
                other => panic!(
                    "the file and the record are both there or both gone: {:?}",
                    (other.0.is_some(), other.1.is_some())
                ),
            }
            let leftovers = std::fs::read_dir(setup.directory(&setup.home)).map_or(0, |entries| {
                entries
                    .flatten()
                    .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
                    .count()
            });
            assert_eq!(leftovers, 0, "no aside and no staging file");
        }
    }

    #[test]
    fn a_record_this_build_does_not_read_is_refused_and_left() {
        let setup = Setup::new();
        setup.ok("install");
        let item = setup.item();
        let good = setup.record();
        let mutate = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut value = good.clone();
            change(&mut value);
            value.to_string().into_bytes()
        };
        let outside = setup.root.join("outside");
        std::fs::write(&outside, b"not kr's\n").expect("an outside file");
        let records = [
            mutate(&|v| v["version"] = 2.into()),
            mutate(&|v| v["extra"] = 1.into()),
            b"not json".to_vec(),
            mutate(&|v| {
                v["pending"] = serde_json::json!({"operation": "remove", "aside": outside})
            }),
            mutate(&|v| {
                v["pending"] =
                    serde_json::json!({"operation": "publish", "staging": "/x/.y.kr-staging"})
            }),
        ];
        let path = setup.record_path().expect("a path");
        for record in records {
            std::fs::write(&path, &record).expect("a record");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("a mode");
            let file = std::fs::read(&item).expect("the file");
            for argument in ["install", "status", "remove"] {
                let said = setup.refused(argument);
                assert!(said.contains("cannot be used"), "{argument}: {said}");
            }
            assert_eq!(
                std::fs::read(&path).expect("kept"),
                record,
                "the record is as it was"
            );
            assert_eq!(
                std::fs::read(&item).expect("kept"),
                file,
                "the file is as it was"
            );
            assert_eq!(std::fs::read(&outside).expect("kept"), b"not kr's\n");
        }
    }

    #[test]
    fn a_failed_install_takes_its_record_back_and_leaves_no_file() {
        let setup = Setup::new();
        let directory = setup.directory(&setup.home);
        std::fs::create_dir_all(directory.parent().expect("a parent")).expect("a parent");
        std::fs::write(&directory, b"a file where the directory belongs\n").expect("a file");
        let said = setup.refused("install");
        assert!(
            said.contains("kr stopped while it was making the directory for the file"),
            "{said}"
        );
        assert!(
            said.contains("kr took back its record and wrote no file"),
            "{said}"
        );
        assert!(setup.record_bytes().is_none(), "no record");
        assert_eq!(
            std::fs::read(&directory).expect("left"),
            b"a file where the directory belongs\n"
        );
    }

    #[test]
    fn a_login_item_written_from_another_home_is_not_overwritten_and_removal_goes_through_the_record()
     {
        let setup = Setup::new();
        setup.ok("install");
        let first = setup.item();
        let recorded = setup.record_bytes().expect("a record");
        let second = setup.root.join("home2");
        std::fs::create_dir_all(&second).expect("a home");
        let run = |argument: &str| {
            setup.run_with(
                &setup.bin.join("kr"),
                &second,
                &["host", "login-item", argument],
            )
        };
        let install = run("install");
        assert!(!install.status.success());
        let said = String::from_utf8_lossy(&install.stderr).into_owned();
        assert!(
            said.contains("kr wrote this environment's login item at the file the record "),
            "{said}"
        );
        assert_eq!(setup.record_bytes(), Some(recorded));
        let status = run("status");
        assert!(String::from_utf8_lossy(&status.stdout).contains(" names is not "));
        let remove = run("remove");
        assert!(
            remove.status.success(),
            "{}",
            String::from_utf8_lossy(&remove.stderr)
        );
        let text = String::from_utf8_lossy(&remove.stdout).into_owned();
        assert!(text.contains("removed the file the record "), "{text}");
        assert!(!first.exists(), "the first home's file is taken out");
        assert!(setup.record_bytes().is_none());
        assert!(
            setup.item_in(&second).is_none(),
            "the second home is untouched"
        );
    }

    #[test]
    fn a_missing_or_non_executable_controller_is_refused_at_install_and_removal_works_without_it() {
        let layouts = ["none", "directory", "mode"];
        for layout in layouts {
            let setup = Setup::new();
            let directory = setup.root.join("layout").join(layout);
            setup.layout(&directory);
            let controller = directory.join("kr-controller");
            std::fs::remove_file(&controller).expect("goes");
            match layout {
                "directory" => std::fs::create_dir(&controller).expect("a directory"),
                "mode" => {
                    std::fs::write(&controller, b"#!/bin/sh\n").expect("a file");
                    std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o644))
                        .expect("a mode");
                }
                _ => {}
            }
            let output = setup.run_with(
                &directory.join("kr"),
                &setup.home,
                &["host", "login-item", "install"],
            );
            assert!(!output.status.success(), "{layout}");
            let said = String::from_utf8_lossy(&output.stderr).into_owned();
            assert!(
                said.contains("the control daemon is not at ")
                    || said.contains("is not executable"),
                "{layout}: {said}"
            );
            assert!(
                !setup.state.exists() && !setup.home.join(".config").exists(),
                "{layout}: nothing was written"
            );
        }
        let setup = Setup::new();
        setup.ok("install");
        std::fs::remove_file(setup.bin.join("kr-controller")).expect("the controller goes");
        assert!(setup.ok("status").contains(MARKER));
        setup.ok("remove");
        assert!(setup.record_bytes().is_none());
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod unwritten {
    use std::process::Command;

    use super::support;

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn a_login_item_is_refused_on_a_system_with_no_writer() {
        let root = tempfile::tempdir().expect("a directory");
        for argument in ["status", "install", "remove"] {
            let output = Command::new(support::kr())
                .args(["host", "login-item", argument])
                .env_clear()
                .env(
                    "SystemRoot",
                    std::env::var_os("SystemRoot").unwrap_or_default(),
                )
                .env("LOCALAPPDATA", root.path().join("local"))
                .env("USERPROFILE", root.path().join("home"))
                .env("KR_STATE_DIR", "")
                .output()
                .expect("kr runs");
            assert!(!output.status.success());
            let said = String::from_utf8_lossy(&output.stderr).into_owned();
            assert!(
                said.contains(
                    "the login item is written on macOS and Linux; this system has no writer for it"
                ),
                "{said}"
            );
        }
        assert!(
            !root.path().join("local").exists(),
            "nothing was made under LOCALAPPDATA"
        );
    }
}
